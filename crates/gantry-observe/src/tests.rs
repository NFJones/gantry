use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry_core::event::{EventDraft, EventEnvelope, EventPayload, ProtectedReference};
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    DeliveryOutcome, DeliveryProjection, EventKind, EventLayer, IdentityKind, JitterMode,
    ProtectedReferenceClass, SinkClass,
};
use gantry_core::timestamp::UtcTimestamp;
use gantry_host::contracts::{
    FreshIdentityAllocator, HostError, HostFuture, IdentitySource, UtcClock,
};
use gantry_host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, ProtectedPayload,
    RedactionCapabilities, SinkDeliveryPolicy, SinkId,
};

use crate::barrier::ActivityBarrier;
use crate::delivery::{DeliveryKernel, SinkSettlementStatus};
use crate::draft::{EventCompleter, EventCompletionError};
use crate::plan::{SinkPlan, SinkPlanError, SinkRegistration};
use crate::projection::project_payloads;
use crate::retry::{RetrySelectionError, delay_ceiling, select_delay};

#[derive(Default)]
struct ScriptedIdentitySource {
    responses: Mutex<VecDeque<Result<[u8; 32], HostError>>>,
    calls: Mutex<Vec<IdentityKind>>,
}

impl ScriptedIdentitySource {
    fn new(responses: impl IntoIterator<Item = Result<[u8; 32], HostError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<IdentityKind> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl IdentitySource for ScriptedIdentitySource {
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError> {
        self.calls
            .lock()
            .map_err(|_| failure("identity-calls"))?
            .push(kind);
        self.responses
            .lock()
            .map_err(|_| failure("identity-responses"))?
            .pop_front()
            .unwrap_or_else(|| Err(failure("identity-exhausted")))
    }
}

struct ScriptedClock {
    responses: Mutex<VecDeque<Result<UtcTimestamp, HostError>>>,
    calls: AtomicUsize,
}

impl ScriptedClock {
    fn new(responses: impl IntoIterator<Item = Result<UtcTimestamp, HostError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }
}

impl UtcClock for ScriptedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.responses
                .lock()
                .map_err(|_| failure("clock-responses"))?
                .pop_front()
                .unwrap_or_else(|| Err(failure("clock-exhausted")))
        })
    }
}

struct ScriptedSink {
    outcomes: Mutex<VecDeque<Result<DeliveryOutcome, HostError>>>,
    calls: Mutex<Vec<EventDeliveryRequest>>,
}

impl ScriptedSink {
    fn new(outcomes: impl IntoIterator<Item = Result<DeliveryOutcome, HostError>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<EventDeliveryRequest> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl EventSink for ScriptedSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move {
            self.calls
                .lock()
                .map_err(|_| failure("sink-calls"))?
                .push(request);
            self.outcomes
                .lock()
                .map_err(|_| failure("sink-outcomes"))?
                .pop_front()
                .unwrap_or(Ok(DeliveryOutcome::Terminal))
        })
    }
}

#[derive(Default)]
struct ScriptedRuntime {
    timeouts: Mutex<Vec<u64>>,
    sleeps: Mutex<Vec<u64>>,
    jitter: Mutex<VecDeque<Result<u64, HostError>>>,
}

impl ScriptedRuntime {
    fn with_jitter(responses: impl IntoIterator<Item = Result<u64, HostError>>) -> Self {
        Self {
            timeouts: Mutex::new(Vec::new()),
            sleeps: Mutex::new(Vec::new()),
            jitter: Mutex::new(responses.into_iter().collect()),
        }
    }

    fn timeouts(&self) -> Vec<u64> {
        self.timeouts
            .lock()
            .map(|values| values.clone())
            .unwrap_or_default()
    }

    fn sleeps(&self) -> Vec<u64> {
        self.sleeps
            .lock()
            .map(|values| values.clone())
            .unwrap_or_default()
    }
}

impl EventDeliveryRuntime for ScriptedRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        timeout_us: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move {
            self.timeouts
                .lock()
                .map_err(|_| failure("runtime-timeouts"))?
                .push(timeout_us);
            sink.deliver(request).await
        })
    }

    fn sleep<'a>(&'a self, delay_us: u64) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async move {
            self.sleeps
                .lock()
                .map_err(|_| failure("runtime-sleeps"))?
                .push(delay_us);
            Ok(())
        })
    }

    fn sample_full_jitter(&self, ceiling_us: u64) -> Result<u64, HostError> {
        self.jitter
            .lock()
            .map_err(|_| failure("runtime-jitter"))?
            .pop_front()
            .unwrap_or(Ok(ceiling_us))
    }
}

#[test]
fn event_completion_uses_caller_activity_and_fresh_occurrence_metadata() {
    let allocator = FreshIdentityAllocator::default();
    let identities = ScriptedIdentitySource::new([Ok([2; 32])]);
    let timestamp = timestamp();
    let clock = ScriptedClock::new([Ok(timestamp.clone())]);
    let completer = EventCompleter::new(&allocator, &identities, &clock);
    let draft = EventDraft::new(EventKind::Parse, payload(b"{\"phase\":\"parse\"}"));

    let completed = block_on(completer.complete(fresh(IdentityKind::Activity, 1), draft));
    assert!(completed.is_ok());
    let completed = completed.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(completed.activity_id(), fresh(IdentityKind::Activity, 1));
    assert_eq!(completed.event_id(), fresh(IdentityKind::Event, 2));
    assert_eq!(completed.kind(), EventKind::Parse);
    assert_eq!(completed.layer(), EventLayer::Physical);
    assert_eq!(completed.timestamp(), &timestamp);
    assert_eq!(identities.calls(), vec![IdentityKind::Event]);
    assert_eq!(clock.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn event_completion_rejects_activity_identity_and_preserves_service_failures() {
    let allocator = FreshIdentityAllocator::default();
    let identities = ScriptedIdentitySource::new([Ok([3; 32])]);
    let clock = ScriptedClock::new([Ok(timestamp())]);
    let completer = EventCompleter::new(&allocator, &identities, &clock);
    let invalid = block_on(completer.complete(
        fresh(IdentityKind::Execution, 1),
        EventDraft::new(EventKind::Parse, payload(b"{}")),
    ));
    assert_eq!(invalid, Err(EventCompletionError::InvalidActivityIdentity));
    assert!(identities.calls().is_empty());
    assert_eq!(clock.calls.load(Ordering::Relaxed), 0);

    let failed_clock = ScriptedClock::new([Err(failure("clock-failed"))]);
    let completer = EventCompleter::new(&allocator, &identities, &failed_clock);
    let failed = block_on(completer.complete(
        fresh(IdentityKind::Activity, 4),
        EventDraft::new(EventKind::Analysis, payload(b"{}")),
    ));
    assert!(matches!(
        failed,
        Err(EventCompletionError::Clock(HostError { ref code, .. })) if code.as_ref() == "clock-failed"
    ));
}

#[test]
fn protected_projection_applies_each_frozen_capability_without_envelope_bytes() {
    let references = all_references();
    let event = event_with_references(references.clone());
    let payloads = references
        .iter()
        .enumerate()
        .map(|(index, reference)| ProtectedPayload {
            reference: reference.clone(),
            bytes: Arc::from(vec![index as u8 + 1]),
        })
        .collect::<Vec<_>>();
    let policy = policy(
        SinkClass::Required,
        true,
        RedactionCapabilities {
            operation_request_content: false,
            operation_result_content: true,
            integration_diagnostics: false,
            source_snippets: true,
        },
        0,
        JitterMode::None,
    );

    let projected = project_payloads(&event, &payloads, &policy);
    assert!(projected.is_ok());
    let projected = projected.unwrap_or_else(|_| unreachable!("checked above"));
    let states = projected
        .payloads()
        .iter()
        .map(|payload| {
            (
                payload.reference.class(),
                payload.projection,
                payload.bytes.is_some(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        vec![
            (
                ProtectedReferenceClass::RawOutput,
                DeliveryProjection::Available,
                true
            ),
            (
                ProtectedReferenceClass::OperationRequest,
                DeliveryProjection::Redacted,
                false
            ),
            (
                ProtectedReferenceClass::NormalizedValue,
                DeliveryProjection::Available,
                true
            ),
            (
                ProtectedReferenceClass::NormalizedDecision,
                DeliveryProjection::Available,
                true
            ),
            (
                ProtectedReferenceClass::NormalizedOperationError,
                DeliveryProjection::Available,
                true,
            ),
            (
                ProtectedReferenceClass::IntegrationDiagnostic,
                DeliveryProjection::Redacted,
                false,
            ),
            (
                ProtectedReferenceClass::SourceSnippet,
                DeliveryProjection::Available,
                true
            ),
        ]
    );
    assert_eq!(event.protected_references(), references.as_slice());
}

#[test]
fn sink_plans_are_canonical_unique_and_policy_snapshots_are_immutable() {
    let sink_a = Arc::new(ScriptedSink::new([]));
    let sink_b = Arc::new(ScriptedSink::new([]));
    let mut original = policy(
        SinkClass::Required,
        false,
        RedactionCapabilities::default(),
        1,
        JitterMode::None,
    );
    let plan = SinkPlan::new(vec![
        SinkRegistration::new(sink_id("z"), original.clone(), sink_b),
        SinkRegistration::new(sink_id("a"), original.clone(), sink_a),
    ]);
    assert!(plan.is_ok());
    original.retry.retry_limit = 9;
    let plan = plan.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(
        plan.registrations()
            .iter()
            .map(|registration| registration.id().as_str())
            .collect::<Vec<_>>(),
        vec!["a", "z"]
    );
    assert!(
        plan.registrations()
            .iter()
            .all(|registration| registration.policy().retry.retry_limit == 1)
    );

    let duplicate = SinkPlan::new(vec![
        SinkRegistration::new(
            sink_id("same"),
            original.clone(),
            Arc::new(ScriptedSink::new([])),
        ),
        SinkRegistration::new(sink_id("same"), original, Arc::new(ScriptedSink::new([]))),
    ]);
    assert!(matches!(duplicate, Err(SinkPlanError::DuplicateSinkId)));
}

#[test]
fn delivery_retries_finitely_and_best_effort_exhaustion_does_not_fail_barrier() {
    let required = Arc::new(ScriptedSink::new([
        Ok(DeliveryOutcome::Retriable),
        Ok(DeliveryOutcome::Success),
    ]));
    let best_effort = Arc::new(ScriptedSink::new([Ok(DeliveryOutcome::Terminal)]));
    let plan = SinkPlan::new(vec![
        SinkRegistration::new(
            sink_id("required"),
            policy(
                SinkClass::Required,
                false,
                RedactionCapabilities::default(),
                2,
                JitterMode::None,
            ),
            required.clone(),
        ),
        SinkRegistration::new(
            sink_id("best"),
            policy(
                SinkClass::BestEffort,
                false,
                RedactionCapabilities::default(),
                0,
                JitterMode::None,
            ),
            best_effort.clone(),
        ),
    ]);
    assert!(plan.is_ok());
    let plan = plan.unwrap_or_else(|_| unreachable!("checked above"));
    let allocator = FreshIdentityAllocator::default();
    let identities = ScriptedIdentitySource::new([Ok([10; 32]), Ok([11; 32]), Ok([12; 32])]);
    let runtime = ScriptedRuntime::default();
    let kernel = DeliveryKernel::new(&allocator, &identities, &runtime);

    let result = block_on(kernel.deliver(event(), &[], &plan));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.barrier, ActivityBarrier::Delivered);
    assert_eq!(
        result
            .settlements
            .iter()
            .map(|settlement| (settlement.sink_id.as_str(), settlement.status))
            .collect::<Vec<_>>(),
        vec![
            ("best", SinkSettlementStatus::Exhausted),
            ("required", SinkSettlementStatus::Success),
        ]
    );
    assert_eq!(runtime.timeouts(), vec![30, 30, 30]);
    assert_eq!(runtime.sleeps(), vec![10]);
    assert_eq!(best_effort.calls().len(), 1);
    let required_calls = required.calls();
    assert_eq!(required_calls.len(), 2);
    assert_eq!(required_calls[0].retry_number, 0);
    assert_eq!(required_calls[1].retry_number, 1);
    assert_eq!(
        required_calls[0].event.event_id(),
        required_calls[1].event.event_id()
    );
    assert_ne!(required_calls[0].attempt_id, required_calls[1].attempt_id);
}

#[test]
fn required_exhaustion_is_reported_only_for_its_activity() {
    let failed_sink = Arc::new(ScriptedSink::new([Ok(DeliveryOutcome::Terminal)]));
    let successful_sink = Arc::new(ScriptedSink::new([Ok(DeliveryOutcome::Success)]));
    let failed_plan = required_plan("shared", failed_sink);
    let successful_plan = required_plan("shared", successful_sink);
    let allocator = FreshIdentityAllocator::default();
    let identities = ScriptedIdentitySource::new([Ok([20; 32]), Ok([21; 32])]);
    let runtime = ScriptedRuntime::default();
    let kernel = DeliveryKernel::new(&allocator, &identities, &runtime);
    let failed_event = event_for_activity(31);
    let successful_event = event_for_activity(32);

    let failed = block_on(kernel.deliver(failed_event.clone(), &[], &failed_plan));
    assert!(failed.is_ok());
    let failed = failed.unwrap_or_else(|_| unreachable!("checked above"));
    assert!(matches!(
        failed.barrier,
        ActivityBarrier::RequiredExhausted { event_id, .. } if event_id == failed_event.event_id()
    ));

    let successful = block_on(kernel.deliver(successful_event, &[], &successful_plan));
    assert!(successful.is_ok());
    assert_eq!(
        successful
            .unwrap_or_else(|_| unreachable!("checked above"))
            .barrier,
        ActivityBarrier::Delivered
    );
}

#[test]
fn retry_selection_saturates_and_enforces_inclusive_jitter_bounds() {
    let none = EventRetryPolicy::new("none", i64::MAX as u64, 10, 40, JitterMode::None);
    assert!(none.is_ok());
    let none = none.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(delay_ceiling(&none, 0), None);
    assert_eq!(delay_ceiling(&none, 1), Some(10));
    assert_eq!(delay_ceiling(&none, 2), Some(20));
    assert_eq!(delay_ceiling(&none, 3), Some(40));
    assert_eq!(delay_ceiling(&none, u64::MAX), Some(40));

    let full = EventRetryPolicy::new("full", 1, 10, 40, JitterMode::Full);
    assert!(full.is_ok());
    let full = full.unwrap_or_else(|_| unreachable!("checked above"));
    let endpoints = ScriptedRuntime::with_jitter([Ok(0), Ok(10)]);
    assert_eq!(select_delay(&full, 1, &endpoints), Ok(0));
    assert_eq!(select_delay(&full, 1, &endpoints), Ok(10));
    let invalid = ScriptedRuntime::with_jitter([Ok(11)]);
    assert_eq!(
        select_delay(&full, 1, &invalid),
        Err(RetrySelectionError::OutOfRangeJitter)
    );
}

fn required_plan(id: &str, sink: Arc<ScriptedSink>) -> SinkPlan {
    let plan = SinkPlan::new(vec![SinkRegistration::new(
        sink_id(id),
        policy(
            SinkClass::Required,
            false,
            RedactionCapabilities::default(),
            0,
            JitterMode::None,
        ),
        sink,
    )]);
    assert!(plan.is_ok());
    plan.unwrap_or_else(|_| unreachable!("checked above"))
}

fn policy(
    class: SinkClass,
    raw_output: bool,
    capabilities: RedactionCapabilities,
    retry_limit: u64,
    jitter: JitterMode,
) -> SinkDeliveryPolicy {
    let retry = EventRetryPolicy::new("retry-v1", retry_limit, 10, 40, jitter);
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

fn all_references() -> Vec<ProtectedReference> {
    [
        ProtectedReferenceClass::RawOutput,
        ProtectedReferenceClass::OperationRequest,
        ProtectedReferenceClass::NormalizedValue,
        ProtectedReferenceClass::NormalizedDecision,
        ProtectedReferenceClass::NormalizedOperationError,
        ProtectedReferenceClass::IntegrationDiagnostic,
        ProtectedReferenceClass::SourceSnippet,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, class)| {
        let reference = ProtectedReference::new(format!("ref-{index}"), class);
        assert!(reference.is_ok());
        reference.unwrap_or_else(|_| unreachable!("checked above"))
    })
    .collect()
}

fn event_with_references(references: Vec<ProtectedReference>) -> EventEnvelope {
    let draft = EventDraft::new(EventKind::OperationCompletion, payload(b"{}"))
        .with_protected_references(references);
    assert!(draft.is_ok());
    complete(
        40,
        41,
        draft.unwrap_or_else(|_| unreachable!("checked above")),
    )
}

fn event() -> EventEnvelope {
    event_for_activity(51)
}

fn event_for_activity(activity: u8) -> EventEnvelope {
    complete(
        activity.wrapping_add(1),
        activity,
        EventDraft::new(EventKind::Parse, payload(b"{}")),
    )
}

fn complete(event: u8, activity: u8, draft: EventDraft) -> EventEnvelope {
    let completed = EventEnvelope::complete(
        fresh(IdentityKind::Event, event),
        fresh(IdentityKind::Activity, activity),
        timestamp(),
        draft,
    );
    assert!(completed.is_ok());
    completed.unwrap_or_else(|_| unreachable!("checked above"))
}

fn payload(bytes: &[u8]) -> EventPayload {
    let payload = EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(bytes));
    assert!(payload.is_ok());
    payload.unwrap_or_else(|_| unreachable!("checked above"))
}

fn sink_id(value: &str) -> SinkId {
    let id = SinkId::new(value);
    assert!(id.is_ok());
    id.unwrap_or_else(|_| unreachable!("checked above"))
}

fn timestamp() -> UtcTimestamp {
    let timestamp = UtcTimestamp::from_unix_seconds(0, 42);
    assert!(timestamp.is_ok());
    timestamp.unwrap_or_else(|_| unreachable!("checked above"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    let identity = ProtocolIdentity::from_fresh_material(kind, [byte; 32]);
    assert!(identity.is_ok());
    identity.unwrap_or_else(|_| unreachable!("checked above"))
}

fn failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
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
