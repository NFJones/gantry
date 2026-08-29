//! Public-facade conformance for nondurable activity event delivery.

use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::event::{EventDraft, EventEnvelope, EventPayload, ProtectedReference};
use gantry::host::contracts::{
    FreshIdentityAllocator, HostError, HostFuture, IdentitySource, UtcClock,
};
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, ProtectedPayload,
    RedactionCapabilities, SinkDeliveryPolicy, SinkId,
};
use gantry::identity::ProtocolIdentity;
use gantry::observe::{
    ActivityBarrier, DeliveryKernel, EventCompleter, SinkPlan, SinkRegistration, project_payloads,
};
use gantry::portable::{
    DeliveryOutcome, EventKind, IdentityKind, JitterMode, ProtectedReferenceClass, SinkClass,
};
use gantry::timestamp::UtcTimestamp;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ObservationVectors {
    format: String,
    event_completion: EventCompletionVector,
    projection_cases: Vec<ProjectionVector>,
    retry_cases: Vec<RetryVector>,
    barrier_cases: Vec<BarrierVector>,
}

#[derive(Debug, Deserialize)]
struct EventCompletionVector {
    kind: String,
    layer: String,
    activity_material: String,
    event_material: String,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct ProjectionVector {
    class: String,
    raw_output: bool,
    operation_request_content: bool,
    operation_result_content: bool,
    integration_diagnostics: bool,
    source_snippets: bool,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RetryVector {
    initial_delay_us: u64,
    cap_us: u64,
    retry_number: u64,
    expected_ceiling_us: u64,
}

#[derive(Debug, Deserialize)]
struct BarrierVector {
    class: String,
    outcome: String,
    expected_barrier: String,
}

struct ScriptedIdentitySource(Mutex<VecDeque<Result<[u8; 32], HostError>>>);

impl ScriptedIdentitySource {
    fn new(responses: impl IntoIterator<Item = Result<[u8; 32], HostError>>) -> Self {
        Self(Mutex::new(responses.into_iter().collect()))
    }
}

impl IdentitySource for ScriptedIdentitySource {
    fn fresh_material(&self, _kind: IdentityKind) -> Result<[u8; 32], HostError> {
        self.0
            .lock()
            .map_err(|_| failure("identity-state"))?
            .pop_front()
            .unwrap_or_else(|| Err(failure("identity-exhausted")))
    }
}

struct FixedClock(UtcTimestamp);

impl UtcClock for FixedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

struct FixedSink(DeliveryOutcome);

impl EventSink for FixedSink {
    fn deliver<'a>(
        &'a self,
        _request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move { Ok(self.0) })
    }
}

struct ImmediateRuntime;

impl EventDeliveryRuntime for ImmediateRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        _timeout_us: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        sink.deliver(request)
    }

    fn sleep<'a>(&'a self, _delay_us: u64) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_full_jitter(&self, ceiling_us: u64) -> Result<u64, HostError> {
        Ok(ceiling_us)
    }
}

#[test]
fn canonical_event_completion_uses_public_occurrence_contracts() {
    let vectors = vectors();
    assert_eq!(vectors.format, "gantry.activity-observation-vectors/v1");
    let schema: serde_json::Value =
        read_json(&protocol_root().join("schemas/activity-observation-v1.schema.json"));
    assert_eq!(
        schema["$id"],
        "https://gantry.invalid/protocol/activity-observation/v1/schema.json"
    );

    let vector = vectors.event_completion;
    let kind = EventKind::from_wire_name(&vector.kind);
    assert!(kind.is_some());
    let kind = kind.unwrap_or_else(|| unreachable!("checked above"));
    assert_eq!(kind.layer().wire_name(), vector.layer);
    let timestamp = UtcTimestamp::from_unix_seconds(0, 42);
    assert!(timestamp.is_ok());
    let timestamp = timestamp.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(timestamp.to_string(), vector.timestamp);

    let source = ScriptedIdentitySource::new([decode_material(&vector.event_material)]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(timestamp.clone());
    let completer = EventCompleter::new(&allocator, &source, &clock);
    let activity = fresh(IdentityKind::Activity, &vector.activity_material);
    let completed = block_on(completer.complete(activity, EventDraft::new(kind, payload(b"{}"))));
    assert!(completed.is_ok());
    let completed = completed.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(completed.activity_id(), activity);
    assert_eq!(
        completed.event_id().to_string(),
        format!("event:{}", vector.event_material)
    );
    assert_eq!(completed.timestamp(), &timestamp);
}

#[test]
fn canonical_projection_and_retry_vectors_match_the_public_kernel() {
    let vectors = vectors();
    for (index, vector) in vectors.projection_cases.into_iter().enumerate() {
        let class = ProtectedReferenceClass::from_wire_name(&vector.class);
        assert!(class.is_some());
        let class = class.unwrap_or_else(|| unreachable!("checked above"));
        let reference = ProtectedReference::new(format!("payload-{index}"), class);
        assert!(reference.is_ok());
        let reference = reference.unwrap_or_else(|_| unreachable!("checked above"));
        let draft = EventDraft::new(EventKind::OperationCompletion, payload(b"{}"))
            .with_protected_references(vec![reference.clone()]);
        assert!(draft.is_ok());
        let event = complete(draft.unwrap_or_else(|_| unreachable!("checked above")));
        let policy = policy(
            SinkClass::Required,
            vector.raw_output,
            RedactionCapabilities {
                operation_request_content: vector.operation_request_content,
                operation_result_content: vector.operation_result_content,
                integration_diagnostics: vector.integration_diagnostics,
                source_snippets: vector.source_snippets,
            },
        );
        let projected = project_payloads(
            &event,
            &[ProtectedPayload {
                reference,
                bytes: Arc::from(&b"protected"[..]),
            }],
            &policy,
        );
        assert!(projected.is_ok());
        let projected = projected.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(projected.payloads().len(), 1);
        assert_eq!(
            projected.payloads()[0].projection.wire_name(),
            vector.expected
        );
        assert_eq!(
            projected.payloads()[0].bytes.is_some(),
            vector.expected == "available"
        );
    }

    for vector in vectors.retry_cases {
        let retry = EventRetryPolicy::new(
            "fixture",
            i64::MAX as u64,
            vector.initial_delay_us,
            vector.cap_us,
            JitterMode::None,
        );
        assert!(retry.is_ok());
        assert_eq!(
            gantry::observe::retry::delay_ceiling(
                &retry.unwrap_or_else(|_| unreachable!("checked above")),
                vector.retry_number,
            ),
            Some(vector.expected_ceiling_us)
        );
    }
}

#[test]
fn canonical_barrier_vectors_keep_required_failure_activity_scoped() {
    let vectors = vectors();
    for (index, vector) in vectors.barrier_cases.into_iter().enumerate() {
        let class = SinkClass::from_wire_name(&vector.class);
        let outcome = DeliveryOutcome::from_wire_name(&vector.outcome);
        assert!(class.is_some() && outcome.is_some());
        let class = class.unwrap_or_else(|| unreachable!("checked above"));
        let sink = Arc::new(FixedSink(
            outcome.unwrap_or_else(|| unreachable!("checked above")),
        ));
        let plan = SinkPlan::new(vec![SinkRegistration::new(
            sink_id(&format!("sink-{index}")),
            policy(class, false, RedactionCapabilities::default()),
            sink,
        )]);
        assert!(plan.is_ok());
        let allocator = FreshIdentityAllocator::default();
        let source = ScriptedIdentitySource::new([Ok([index as u8 + 30; 32])]);
        let kernel = DeliveryKernel::new(&allocator, &source, &ImmediateRuntime);
        let result = block_on(kernel.deliver(
            complete(EventDraft::new(EventKind::Parse, payload(b"{}"))),
            &[],
            &plan.unwrap_or_else(|_| unreachable!("checked above")),
        ));
        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!("checked above"));
        let actual = match result.barrier {
            ActivityBarrier::Delivered => "delivered",
            ActivityBarrier::RequiredExhausted { .. } => "required-exhausted",
        };
        assert_eq!(actual, vector.expected_barrier);
    }
}

fn policy(
    class: SinkClass,
    raw_output: bool,
    capabilities: RedactionCapabilities,
) -> SinkDeliveryPolicy {
    let retry = EventRetryPolicy::new("retry-v1", 0, 0, 0, JitterMode::None);
    assert!(retry.is_ok());
    let policy = SinkDeliveryPolicy::new(
        class,
        raw_output,
        "redaction-v1",
        capabilities,
        retry.unwrap_or_else(|_| unreachable!("checked above")),
        30,
    );
    assert!(policy.is_ok());
    policy.unwrap_or_else(|_| unreachable!("checked above"))
}

fn complete(draft: EventDraft) -> EventEnvelope {
    let event = EventEnvelope::complete(
        fresh(IdentityKind::Event, &"11".repeat(32)),
        fresh(IdentityKind::Activity, &"22".repeat(32)),
        UtcTimestamp::from_unix_seconds(0, 42)
            .unwrap_or_else(|_| unreachable!("fixture timestamp is valid")),
        draft,
    );
    assert!(event.is_ok());
    event.unwrap_or_else(|_| unreachable!("checked above"))
}

fn payload(bytes: &[u8]) -> EventPayload {
    EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(bytes))
        .unwrap_or_else(|_| unreachable!("fixture payload is nonempty"))
}

fn sink_id(value: &str) -> SinkId {
    SinkId::new(value).unwrap_or_else(|_| unreachable!("fixture sink ID is nonempty"))
}

fn fresh(kind: IdentityKind, hexadecimal: &str) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(
        kind,
        decode_material(hexadecimal).unwrap_or_else(|_| unreachable!("fixture material is valid")),
    )
    .unwrap_or_else(|_| unreachable!("fixture kind accepts fresh material"))
}

fn decode_material(value: &str) -> Result<[u8; 32], HostError> {
    if value.len() != 64 {
        return Err(failure("invalid-material"));
    }
    let mut material = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| failure("invalid-material"))?;
        material[index] = u8::from_str_radix(text, 16).map_err(|_| failure("invalid-material"))?;
    }
    Ok(material)
}

fn failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn vectors() -> ObservationVectors {
    read_json(&protocol_root().join("goldens/activity-observation-vectors-v1.json"))
}

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("deterministic observation future unexpectedly remained pending"),
    }
}
