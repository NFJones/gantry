//! External `ValidatePackage` coverage through the public Gantry facade.

use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::frontend::PackageSyntaxStatus;
use gantry::host::contracts::{
    FreshIdentityAllocator, HostError, HostFuture, IdentitySource, UtcClock,
};
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, RedactionCapabilities,
    SinkDeliveryPolicy, SinkId,
};
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    DeliveryOutcome, EventKind, EventLayer, FrontendResourceCode, IdentityKind, JitterMode,
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, SinkClass,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::{ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &[u8]) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-validate-conformance-{}-{suffix}",
            std::process::id()
        ));
        assert!(fs::create_dir(&path).is_ok());
        assert!(fs::write(path.join("main.gnt"), source).is_ok());
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ScriptedIdentities {
    responses: Mutex<VecDeque<Result<[u8; 32], HostError>>>,
    calls: Mutex<Vec<IdentityKind>>,
}

impl ScriptedIdentities {
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

impl IdentitySource for ScriptedIdentities {
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError> {
        self.calls
            .lock()
            .map_err(|_| failure("identity-state"))?
            .push(kind);
        self.responses
            .lock()
            .map_err(|_| failure("identity-state"))?
            .pop_front()
            .unwrap_or_else(|| Err(failure("identity-exhausted")))
    }
}

struct FixedClock(Result<UtcTimestamp, HostError>);

impl UtcClock for FixedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async move { self.0.clone() })
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
fn valid_and_invalid_packages_each_expose_one_parse_occurrence() {
    for (source, expected, payload) in [
        (
            &b"fn main() {}"[..],
            PackageSyntaxStatus::Valid,
            "{\"diagnostics\":[],\"phase\":\"parse\",\"status\":\"syntax-valid\"}",
        ),
        (
            &b"fn main( {"[..],
            PackageSyntaxStatus::Invalid,
            "\"status\":\"syntax-invalid\"",
        ),
    ] {
        let root = TempDirectory::new(source);
        let identities = ScriptedIdentities::new([Ok([1; 32]), Ok([2; 32])]);
        let allocator = FreshIdentityAllocator::default();
        let clock = FixedClock(Ok(timestamp()));
        let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
        let selection = selection();
        let result = block_on(coordinator.validate(request(&root.0, &selection, None)));
        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(result.phase.status(), expected);
        assert_eq!(result.event.kind(), EventKind::Parse);
        assert_eq!(result.event.layer(), EventLayer::Physical);
        assert_eq!(result.event.activity_id(), result.activity_id);
        assert!(result.event.execution_id().is_none());
        let event_payload = std::str::from_utf8(result.event.payload().canonical_bytes());
        assert!(event_payload.is_ok_and(|actual| {
            if expected == PackageSyntaxStatus::Valid {
                actual == payload
            } else {
                actual.contains(payload) && actual.contains("\"phase\":\"parse\"")
            }
        }));
        assert_eq!(
            identities.calls(),
            vec![IdentityKind::Activity, IdentityKind::Event]
        );
    }
}

#[test]
fn semantic_errors_remain_outside_syntax_only_validation() {
    let root = TempDirectory::new(
        b"mod child;\nmod child;\nmod nested_scope { mod nested; }\nuse child::thing;\nstruct Duplicate { value: Int, value: Int }\nfn recursive() { recursive(); }\nfn main() { missing_name; child::thing(); }",
    );
    assert!(fs::write(root.0.join("child.gnt"), b"fn thing() {}").is_ok());
    assert!(fs::create_dir(root.0.join("nested_scope")).is_ok());
    assert!(fs::write(root.0.join("nested_scope/nested.gnt"), b"fn nested() {}").is_ok());
    let identities = ScriptedIdentities::new([Ok([8; 32]), Ok([9; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();

    let result = block_on(coordinator.validate(request(&root.0, &selection, None)));
    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(result.phase.status(), PackageSyntaxStatus::Valid);
    assert!(result.phase.diagnostics().is_empty());
    assert_eq!(result.phase.snapshot().records().len(), 3);
    assert!(result.event.execution_id().is_none());
}

#[test]
fn complete_frontend_limit_policy_is_public_and_finite() {
    const MAXIMUM: u64 = i64::MAX as u64;

    assert!(
        FrontendLimits::new(
            MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM, MAXIMUM
        )
        .is_ok()
    );
    for index in 0..9 {
        let mut zero = [1; 9];
        zero[index] = 0;
        assert!(
            FrontendLimits::new(
                zero[0], zero[1], zero[2], zero[3], zero[4], zero[5], zero[6], zero[7], zero[8]
            )
            .is_err()
        );

        let mut oversized = [1; 9];
        oversized[index] = MAXIMUM + 1;
        assert!(
            FrontendLimits::new(
                oversized[0],
                oversized[1],
                oversized[2],
                oversized[3],
                oversized[4],
                oversized[5],
                oversized[6],
                oversized[7],
                oversized[8]
            )
            .is_err()
        );
    }
}

#[test]
fn frontend_limit_failure_is_separate_and_retains_diagnostics() {
    let root = TempDirectory::new(
        b"struct Broken { value Int; }\naction read_only missing( -> String;\nfn good() {}",
    );
    let identities = ScriptedIdentities::new([Ok([10; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();
    let limits = FrontendLimits::new(1, 4_096, 4_096, 128, 1, 4_096, 4_096, 4_096, 4_096)
        .unwrap_or_else(|_| unreachable!("positive limits"));

    let result =
        block_on(coordinator.validate(request_with_limits(&root.0, &selection, limits, None)));
    let error = match result {
        Err(ValidatePackageError::Package(error)) => error,
        other => panic!("expected package resource limit, got {other:?}"),
    };
    assert_eq!(error.code(), "frontend-resource-limit");
    assert!(matches!(
        error.frontend_resource_limit(),
        Some(limit)
            if limit.code == FrontendResourceCode::DiagnosticCountLimit
                && limit.limit == 1
                && limit.observed == Some(2)
    ));
    assert_eq!(error.retained_diagnostics().len(), 1);
    assert_eq!(identities.calls(), vec![IdentityKind::Activity]);
}

#[test]
fn identity_source_and_clock_failures_preserve_phase_ordering() {
    let missing = std::env::temp_dir().join("gantry-conformance-missing-package");
    let identities = ScriptedIdentities::new([Err(failure("identity-failed"))]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let selection = selection();
    let result = block_on(coordinator.validate(request(&missing, &selection, None)));
    assert!(matches!(
        result,
        Err(ValidatePackageError::ActivityIdentity(_))
    ));
    assert_eq!(identities.calls(), vec![IdentityKind::Activity]);

    let root = TempDirectory::new(b"fn main() {}");
    let identities = ScriptedIdentities::new([Ok([3; 32]), Ok([4; 32])]);
    let clock = FixedClock(Err(failure("clock-failed")));
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock);
    let result = block_on(coordinator.validate(request(&root.0, &selection, None)));
    assert!(matches!(result, Err(ValidatePackageError::Event(_))));
    assert_eq!(
        identities.calls(),
        vec![IdentityKind::Activity, IdentityKind::Event]
    );
}

#[test]
fn required_sink_exhaustion_is_an_operational_failure_after_parse() {
    let root = TempDirectory::new(b"fn main() {}");
    let identities = ScriptedIdentities::new([Ok([5; 32]), Ok([6; 32]), Ok([7; 32])]);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock(Ok(timestamp()));
    let runtime = ImmediateRuntime;
    let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &clock)
        .with_delivery_runtime(&runtime);
    let selection = selection();
    let plan = required_plan(DeliveryOutcome::Terminal);
    let result = block_on(coordinator.validate(request(&root.0, &selection, Some(&plan))));
    assert_eq!(result, Err(ValidatePackageError::RequiredEventDelivery));
    assert_eq!(
        identities.calls(),
        vec![
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::DeliveryAttempt,
        ]
    );
}

fn request<'a>(
    root: &'a std::path::Path,
    selection: &'a ProtocolSelection,
    event_delivery: Option<&'a SinkPlan>,
) -> ValidatePackageRequest<'a> {
    let limits = FrontendLimits::new(
        32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
    )
    .unwrap_or_else(|_| unreachable!("positive limits"));
    request_with_limits(root, selection, limits, event_delivery)
}

fn request_with_limits<'a>(
    root: &'a std::path::Path,
    selection: &'a ProtocolSelection,
    frontend_limits: FrontendLimits,
    event_delivery: Option<&'a SinkPlan>,
) -> ValidatePackageRequest<'a> {
    ValidatePackageRequest {
        package_root: root,
        protocol_selection: selection,
        frontend_limits,
        event_delivery,
    }
}

fn selection() -> ProtocolSelection {
    ProtocolSelection::new(
        PORTABLE_SPECIFICATION_REVISION,
        PROTOCOL_FAMILY_DEFINITIONS
            .iter()
            .map(|definition| SelectedProtocol {
                family: definition.family,
                version: ProtocolVersion {
                    major: definition.major,
                    minor: definition.minor,
                },
            })
            .collect(),
    )
    .unwrap_or_else(|_| unreachable!("published selection"))
}

fn required_plan(outcome: DeliveryOutcome) -> SinkPlan {
    let retry = EventRetryPolicy::new("retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|_| unreachable!("valid retry policy"));
    let policy = SinkDeliveryPolicy::new(
        SinkClass::Required,
        false,
        "redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|_| unreachable!("valid sink policy"));
    SinkPlan::new(vec![SinkRegistration::new(
        SinkId::new("required").unwrap_or_else(|_| unreachable!("valid sink ID")),
        policy,
        Arc::new(FixedSink(outcome)),
    )])
    .unwrap_or_else(|_| unreachable!("valid sink plan"))
}

fn timestamp() -> UtcTimestamp {
    UtcTimestamp::from_unix_seconds(0, 42).unwrap_or_else(|_| unreachable!("valid timestamp"))
}

fn failure(code: &str) -> HostError {
    HostError {
        code: code.into(),
        protected_diagnostic: None,
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
