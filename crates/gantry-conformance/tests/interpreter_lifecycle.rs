//! Public-facade conformance for interpreter lifecycle, configuration, and panic containment.

use std::fs;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use gantry::host::contracts::{
    CancellationToken, DurationMicros, ExecutorAdapter, HostError, HostFuture, IdentitySource,
    InclusiveJitterRange,
};
use gantry::identity::ProtocolIdentity;
use gantry::portable::{
    CONFIGURATION_FIELDS, CancellationReasonCategory, ConfigurationClass, ConfigurationField,
    IdentityKind, InterpreterState, JitterMode, ShutdownCause,
};
use gantry::runtime::{
    AdapterPoison, AdmissionKind, BoundaryFailure, CancellationReason, CancellationRecord,
    ConfigurationErrorKind, FinalShutdownEventSettlement, InterpreterConfiguration,
    InterpreterLifecycle, LifecycleCode, MachineOutcome, PanicOrigin, RequiredConfiguration,
    RetryDefaults, drop_integration,
};
use gantry::source::FrontendLimits;
use gantry::value::{LogicalValue, ValueLimits};
use serde::Deserialize;

const CONFIGURATION_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_lifecycle.rs#public_configuration_defaults_bounds_and_classes_are_exact";
const LIFECYCLE_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_lifecycle.rs#shutdown_races_transfer_admission_and_snapshot_first_durations";
const PANIC_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_lifecycle.rs#panic_boundaries_preserve_origin_and_apply_exact_poisoning";
const REENTRY_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_lifecycle.rs#reentry_is_chain_local_and_pending_adapters_hold_no_lifecycle_lock";
const UNCLEAN_EVIDENCE: &str = "crates/gantry-conformance/tests/interpreter_lifecycle.rs#unclean_drop_signals_work_without_standard_event_claim";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

#[derive(Debug)]
struct FixedServices;

impl ExecutorAdapter for FixedServices {
    fn sleep<'a>(&'a self, _: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

impl IdentitySource for FixedServices {
    fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
        Ok([0x5a; 32])
    }
}

#[derive(Debug, Default)]
struct WakeCounter {
    wakes: AtomicUsize,
}

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
    }
}

struct PanicOnDrop;

impl Future for PanicOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("protected integration destructor payload");
    }
}

#[test]
fn checked_in_lifecycle_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/interpreter-lifecycle-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.interpreter-lifecycle-evidence/v1");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert_eq!(manifest.issue, "GNT-EMB-002");
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(|entry| entry.evidence.as_str())
            .collect::<Vec<_>>(),
        [
            CONFIGURATION_EVIDENCE,
            LIFECYCLE_EVIDENCE,
            PANIC_EVIDENCE,
            REENTRY_EVIDENCE,
            UNCLEAN_EVIDENCE,
        ]
    );
    assert_eq!(manifest.exclusions.len(), 4);
    assert!(manifest.profiles.is_empty());
}

#[test]
fn public_configuration_defaults_bounds_and_classes_are_exact() {
    let configuration = configuration();
    let retry = configuration.retry_defaults();
    assert_eq!(retry.model_retry_limit, 2);
    assert_eq!(retry.action_retry_limit, 0);
    assert_eq!(retry.backoff_initial.get(), 100_000);
    assert_eq!(retry.backoff_cap.get(), 2_000_000);
    assert_eq!(retry.jitter, JitterMode::Full);
    assert_eq!(retry.event_delivery_retry_limit, 3);
    assert_eq!(retry.event_delivery_attempt_timeout.get(), 30_000_000);
    assert_eq!(configuration.graceful_shutdown_timeout().get(), 30_000_000);
    assert_eq!(configuration.post_cancellation_drain().get(), 5_000_000);
    assert_eq!(configuration.maximum_tasks_per_execution(), 65_536);

    let machine = configuration.machine_limits();
    assert_eq!(machine.maximum_deterministic_transitions, 10_000_000);
    assert_eq!(machine.maximum_operations, 100_000);
    assert_eq!(machine.maximum_loop_iterations, 1_000_000);
    assert_eq!(machine.maximum_workflow_call_depth, 1_024);
    assert_eq!(machine.deterministic_transition_yield_quantum, 1_000);

    assert_eq!(
        configuration_class(ConfigurationField::MaximumPackageFiles),
        ConfigurationClass::ActivityPolicy
    );
    assert_eq!(
        configuration_class(ConfigurationField::GracefulShutdownTimeoutUs),
        ConfigurationClass::DurablyMutable
    );
    assert_eq!(
        configuration_class(ConfigurationField::MaximumEntryInputBytes),
        ConfigurationClass::IdentityBound
    );
    assert_eq!(
        configuration_class(ConfigurationField::ExecutorAdapter),
        ConfigurationClass::IntegrationOwned
    );
    assert_eq!(
        configuration_class(ConfigurationField::DeterministicTransitionYieldQuantum),
        ConfigurationClass::SchedulingOnly
    );

    let too_large =
        RetryDefaults::new(0, 0, 0, 0, JitterMode::None, 0, DurationMicros::MAXIMUM + 1);
    assert!(matches!(
        too_large,
        Err(error)
            if error.field == ConfigurationField::EventDeliveryAttemptTimeoutUs
                && error.kind == ConfigurationErrorKind::TooLarge
    ));
    assert!(matches!(
        RetryDefaults::new(0, 0, 0, 0, JitterMode::None, 0, 0),
        Err(error)
            if error.field == ConfigurationField::EventDeliveryAttemptTimeoutUs
                && error.kind == ConfigurationErrorKind::Zero
    ));

    let oversized_lengths = ValueLimits::new(1, 1, 1, 9_007_199_254_740_992)
        .unwrap_or_else(|| unreachable!("value limits require only positivity"));
    let required =
        RequiredConfiguration::new(frontend_limits(), 1, 1, oversized_lengths, 1, 1, 1, 1);
    assert!(matches!(
        required,
        Err(error)
            if error.field == ConfigurationField::MaximumListItems
                && error.kind == ConfigurationErrorKind::TooLarge
    ));
}

#[test]
fn shutdown_races_transfer_admission_and_snapshot_first_durations() {
    let lifecycle = InterpreterLifecycle::new(&configuration());
    assert_eq!(lifecycle.snapshot().state, InterpreterState::Running);

    let mut start = lifecycle
        .admit(AdmissionKind::NewWork)
        .unwrap_or_else(|error| panic!("new work was rejected: {error}"));
    let graceful = duration(17);
    let drain = duration(23);
    let mut first = lifecycle
        .begin_shutdown(Some(graceful), Some(drain))
        .unwrap_or_else(|error| panic!("shutdown was rejected: {error}"));
    let coordinator = first
        .coordinator
        .take()
        .unwrap_or_else(|| panic!("first caller did not receive coordination authority"));

    let execution_id = execution(1);
    let handle = start
        .accept_execution(execution_id)
        .unwrap_or_else(|error| panic!("admitted execution was not transferred: {error:?}"));
    assert_eq!(lifecycle.snapshot().admitted_calls, 0);
    assert_eq!(lifecycle.snapshot().cohort.as_ref(), [execution_id]);
    assert!(matches!(
        lifecycle.admit(AdmissionKind::NewWork),
        Err(error) if error.code == LifecycleCode::InterpreterShuttingDown
    ));
    assert!(
        lifecycle
            .query_execution(execution_id)
            .unwrap_or_else(|error| panic!("cohort query was rejected: {error}"))
            .is_some()
    );

    let repeated = lifecycle
        .begin_shutdown(Some(duration(99)), Some(duration(101)))
        .unwrap_or_else(|error| panic!("repeated shutdown was rejected: {error}"));
    assert!(repeated.coordinator.is_none());
    assert_eq!(repeated.durations.graceful, graceful);
    assert_eq!(repeated.durations.drain, drain);

    let first_reason = CancellationReason::new(
        CancellationReasonCategory::Caller,
        Some(Arc::from("first")),
        None,
        32,
    )
    .unwrap_or_else(|error| panic!("cancellation fixture failed: {error:?}"));
    let second_reason = CancellationReason::new(
        CancellationReasonCategory::Deadline,
        Some(Arc::from("second")),
        None,
        32,
    )
    .unwrap_or_else(|error| panic!("cancellation fixture failed: {error:?}"));
    let first_record = lifecycle
        .cancel_execution(execution_id, first_reason.clone())
        .unwrap_or_else(|error| panic!("cancellation was rejected: {error}"));
    assert!(matches!(
        first_record,
        CancellationRecord::Accepted { ref reason, ref signal }
            if reason == &first_reason && signal.is_cancelled()
    ));
    let repeated_record = lifecycle
        .cancel_execution(execution_id, second_reason)
        .unwrap_or_else(|error| panic!("repeated cancellation was rejected: {error}"));
    assert!(matches!(
        repeated_record,
        CancellationRecord::Existing { ref reason, ref signal }
            if reason == &first_reason && signal.is_cancelled()
    ));

    let dropped_counter = Arc::new(WakeCounter::default());
    let retained_counter = Arc::new(WakeCounter::default());
    let dropped_waker = Waker::from(Arc::clone(&dropped_counter));
    let retained_waker = Waker::from(Arc::clone(&retained_counter));
    let mut dropped_wait = lifecycle
        .await_terminal(execution_id)
        .unwrap_or_else(|error| panic!("terminal wait was rejected: {error}"));
    let mut retained_wait = lifecycle
        .await_terminal(execution_id)
        .unwrap_or_else(|error| panic!("terminal wait was rejected: {error}"));
    assert!(poll_once(&mut dropped_wait, &dropped_waker).is_pending());
    assert!(poll_once(&mut retained_wait, &retained_waker).is_pending());
    drop(dropped_wait);

    let outcome = MachineOutcome::Succeeded(LogicalValue::unit());
    lifecycle
        .complete_foreground(&handle, outcome.clone())
        .unwrap_or_else(|error| panic!("foreground completion failed: {error:?}"));
    assert_eq!(dropped_counter.wakes.load(Ordering::Acquire), 0);
    assert_eq!(retained_counter.wakes.load(Ordering::Acquire), 1);
    assert!(poll_once(&mut retained_wait, &retained_waker).is_pending());
    lifecycle
        .complete_terminal(&handle, outcome.clone())
        .unwrap_or_else(|error| panic!("terminal completion failed: {error:?}"));
    assert_eq!(retained_counter.wakes.load(Ordering::Acquire), 2);
    let Poll::Ready(Some(snapshot)) = poll_once(&mut retained_wait, &retained_waker) else {
        panic!("terminal waiter did not resolve")
    };
    assert_eq!(snapshot.foreground, Some(outcome.clone()));
    assert_eq!(snapshot.terminal, Some(outcome));
    assert_eq!(snapshot.cancellation, Some(first_reason));

    let report = coordinator
        .complete(true, FinalShutdownEventSettlement::Settled)
        .unwrap_or_else(|error| panic!("shutdown completion failed: {error:?}"));
    assert_eq!(report.cause, ShutdownCause::Requested);
    assert!(report.orderly);
    assert!(!report.unclean);
    assert_eq!(report.durations.graceful, graceful);
    assert_eq!(report.durations.drain, drain);
    assert_eq!(report.cohort.len(), 1);
    assert_eq!(lifecycle.snapshot().state, InterpreterState::Terminated);
    assert!(matches!(
        lifecycle.query_execution(execution_id),
        Err(error) if error.code == LifecycleCode::InterpreterTerminated
    ));

    let first_report = poll_ready(&mut first.wait, &retained_waker);
    assert!(Arc::ptr_eq(&report, &first_report));
    let mut after_termination = lifecycle
        .begin_shutdown(None, None)
        .unwrap_or_else(|error| panic!("post-termination shutdown failed: {error}"));
    assert!(after_termination.coordinator.is_none());
    let repeated_report = poll_ready(&mut after_termination.wait, &retained_waker);
    assert!(Arc::ptr_eq(&report, &repeated_report));
}

#[test]
fn reentry_is_chain_local_and_pending_adapters_hold_no_lifecycle_lock() {
    let lifecycle = InterpreterLifecycle::new(&configuration());
    let poison = AdapterPoison::default();
    let rejection = lifecycle
        .catch_adapter(&poison, || {
            lifecycle
                .admit(AdmissionKind::NewWork)
                .err()
                .unwrap_or_else(|| panic!("same-chain reentry was admitted"))
        })
        .unwrap_or_else(|failure| panic!("adapter boundary failed: {failure:?}"));
    assert_eq!(rejection.code, LifecycleCode::ReentrantInterpreterCall);
    assert!(!poison.is_poisoned());

    let mut pending = lifecycle.contain_adapter_future(
        Box::pin(std::future::pending::<()>()),
        AdapterPoison::default(),
    );
    let waker = Waker::from(Arc::new(WakeCounter::default()));
    assert!(poll_host(&mut pending, &waker).is_pending());

    let independent = lifecycle.clone();
    let thread = std::thread::spawn(move || independent.admit(AdmissionKind::NewWork));
    let admission = thread
        .join()
        .unwrap_or_else(|_| panic!("independent admission thread panicked"))
        .unwrap_or_else(|error| panic!("pending adapter blocked independent admission: {error}"));
    drop(admission);
    assert_eq!(lifecycle.snapshot().state, InterpreterState::Running);
}

#[test]
fn panic_boundaries_preserve_origin_and_apply_exact_poisoning() {
    let lifecycle = InterpreterLifecycle::new(&configuration());
    let synchronous_poison = AdapterPoison::default();
    let failure = lifecycle
        .catch_adapter(&synchronous_poison, || panic!("protected adapter payload"))
        .expect_err("integration panic escaped classification");
    assert_eq!(failure.origin, PanicOrigin::Integration);
    assert_eq!(failure.code(), "integration-panic");
    assert!(synchronous_poison.is_poisoned());
    assert_eq!(lifecycle.snapshot().state, InterpreterState::Running);

    let future_poison = AdapterPoison::default();
    let future: HostFuture<'static, ()> = Box::pin(std::future::poll_fn(|_| {
        panic!("protected adapter-future payload")
    }));
    let mut contained = lifecycle.contain_adapter_future(future, future_poison.clone());
    let waker = Waker::from(Arc::new(WakeCounter::default()));
    assert!(matches!(
        poll_host(&mut contained, &waker),
        Poll::Ready(Err(BoundaryFailure {
            origin: PanicOrigin::Integration
        }))
    ));
    assert!(future_poison.is_poisoned());

    let drop_poison = AdapterPoison::default();
    let contained = lifecycle.contain_adapter_future(Box::pin(PanicOnDrop), drop_poison.clone());
    assert!(catch_unwind(AssertUnwindSafe(|| drop(contained))).is_ok());
    assert!(drop_poison.is_poisoned());

    let value_poison = AdapterPoison::default();
    let mut value = Some(PanicOnDrop);
    assert!(matches!(
        drop_integration(&value_poison, &mut value),
        Err(BoundaryFailure {
            origin: PanicOrigin::Integration
        })
    ));
    assert!(value.is_none());
    assert!(value_poison.is_poisoned());

    let public = InterpreterLifecycle::new(&configuration());
    let invariant = public
        .catch_public(|| panic!("protected Gantry invariant payload"))
        .expect_err("invariant panic escaped classification");
    assert_eq!(invariant.origin, PanicOrigin::GantryInvariant);
    assert_eq!(invariant.code(), "internal-invariant-failure");
    assert_eq!(public.snapshot().cause, Some(ShutdownCause::Poisoned));
    assert!(matches!(
        public.admit(AdmissionKind::NewWork),
        Err(error) if error.code == LifecycleCode::InterpreterPoisoned
    ));

    let asynchronous = InterpreterLifecycle::new(&configuration());
    let future: HostFuture<'static, ()> = Box::pin(std::future::poll_fn(|_| {
        panic!("protected public-future payload")
    }));
    let mut contained = asynchronous.contain_public_future(future);
    assert!(matches!(
        poll_host(&mut contained, &waker),
        Poll::Ready(Err(BoundaryFailure {
            origin: PanicOrigin::GantryInvariant
        }))
    ));
    assert_eq!(asynchronous.snapshot().cause, Some(ShutdownCause::Poisoned));
}

#[test]
fn unclean_drop_signals_work_without_standard_event_claim() {
    let lifecycle = InterpreterLifecycle::new(&configuration());
    let mut admission = lifecycle
        .admit(AdmissionKind::NewWork)
        .unwrap_or_else(|error| panic!("new work was rejected: {error}"));
    let handle = admission
        .accept_execution(execution(9))
        .unwrap_or_else(|error| panic!("execution acceptance failed: {error:?}"));
    let cancellation = handle
        .cancellation_signal()
        .unwrap_or_else(|error| panic!("cancellation signal was unavailable: {error:?}"));

    assert!(!cancellation.is_cancelled());
    drop(lifecycle);
    assert!(cancellation.is_cancelled());
}

fn configuration() -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        frontend_limits(),
        16 * 1_024 * 1_024,
        16 * 1_024 * 1_024,
        ValueLimits::new(256, 1_048_576, 1_048_576, 65_536)
            .unwrap_or_else(|| unreachable!("fixture value limits are positive")),
        10_000_000,
        100_000,
        1_000_000,
        1_000,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(Arc::new(FixedServices), Arc::new(FixedServices), required)
}

fn frontend_limits() -> FrontendLimits {
    FrontendLimits::new(
        128, 1_048_576, 16_777_216, 1_000_000, 1_000, 1_048_576, 16_777_216, 16_777_216, 16_777_216,
    )
    .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}"))
}

fn configuration_class(field: ConfigurationField) -> ConfigurationClass {
    CONFIGURATION_FIELDS
        .iter()
        .find(|definition| definition.field == field)
        .map(|definition| definition.class)
        .unwrap_or_else(|| panic!("configuration field is absent: {}", field.wire_name()))
}

fn execution(byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [byte; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"))
}

fn duration(value: u64) -> DurationMicros {
    DurationMicros::new(value).unwrap_or_else(|| panic!("duration is out of range: {value}"))
}

fn poll_once<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    let mut context = Context::from_waker(waker);
    Pin::new(future).poll(&mut context)
}

fn poll_host<T>(future: &mut HostFuture<'_, T>, waker: &Waker) -> Poll<T> {
    let mut context = Context::from_waker(waker);
    future.as_mut().poll(&mut context)
}

fn poll_ready<F: Future + Unpin>(future: &mut F, waker: &Waker) -> F::Output {
    match poll_once(future, waker) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future remained pending"),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
