//! Public conformance for caller-independent must-settle activities.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use gantry::host::contracts::{
    EmbeddingVersion, ExecutorAdapter, HostError, HostFuture, HostRequest, HostResponse,
    IdentitySource, IntegrationPreflight,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::portable::IdentityKind;
use gantry::runtime::{
    AdapterPoison, AdmissionClass, AdmissionResourceClass, AsyncCapacityLimits,
    FinalShutdownEventSettlement, InterpreterConfiguration, InterpreterLifecycle, LifecycleCode,
    OwnedActivityError, RequiredConfiguration,
};
use gantry::source::FrontendLimits;
use gantry::value::ValueLimits;
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use serde::Deserialize;

const OWNERSHIP_EVIDENCE: &str = "crates/gantry-conformance/tests/owned_activities.rs#dropped_waiter_retains_dependencies_and_must_settle_progress";
const SATURATION_EVIDENCE: &str = "crates/gantry-conformance/tests/owned_activities.rs#public_activity_saturation_is_pre_invocation_and_releases_once";
const SHUTDOWN_EVIDENCE: &str = "crates/gantry-conformance/tests/owned_activities.rs#shutdown_waits_for_caller_independent_activity_settlement";
const CONTAINMENT_EVIDENCE: &str = "crates/gantry-conformance/tests/owned_activities.rs#owned_activity_contains_panics_and_rejects_reentrant_callbacks";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
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

#[derive(Default)]
struct PendingControl {
    result: Mutex<Option<Result<HostResponse, HostError>>>,
    waiter: Mutex<Option<Waker>>,
}

impl PendingControl {
    fn complete(&self, result: Result<HostResponse, HostError>) {
        lock(&self.result).replace(result);
        if let Some(waiter) = lock(&self.waiter).take() {
            waiter.wake();
        }
    }
}

struct PendingPreflight {
    control: Arc<PendingControl>,
    calls: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl Drop for PendingPreflight {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

impl IntegrationPreflight for PendingPreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::ResolveMappings);
        self.calls.fetch_add(1, Ordering::AcqRel);
        Box::pin(std::future::poll_fn(move |context| {
            if let Some(result) = lock(&self.control.result).take() {
                return Poll::Ready(result);
            }
            *lock(&self.control.waiter) = Some(context.waker().clone());
            Poll::Pending
        }))
    }
}

struct ImmediatePreflight {
    calls: Arc<AtomicUsize>,
}

impl IntegrationPreflight for ImmediatePreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move { response(request.operation()) })
    }
}

struct PanickingPreflight;

impl IntegrationPreflight for PanickingPreflight {
    fn call<'a>(&'a self, _: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(std::future::poll_fn(|_| {
            panic!("protected preflight panic fixture")
        }))
    }
}

struct ReentrantPreflight {
    lifecycle: InterpreterLifecycle,
    observed: Arc<Mutex<Option<LifecycleCode>>>,
}

impl IntegrationPreflight for ReentrantPreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let code = self
            .lifecycle
            .admit(gantry::runtime::AdmissionKind::NewWork)
            .err()
            .map(|error| error.code);
        *lock(&self.observed) = code;
        Box::pin(async move { response(request.operation()) })
    }
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn checked_in_owned_activity_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/owned-activities-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.owned-activity-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-ACT-001");
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
            OWNERSHIP_EVIDENCE,
            CONTAINMENT_EVIDENCE,
            SATURATION_EVIDENCE,
            SHUTDOWN_EVIDENCE,
        ]
    );
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn dropped_waiter_retains_dependencies_and_must_settle_progress() {
    let (configuration, executor) = configuration(2);
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let control = Arc::new(PendingControl::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let service = Arc::new(PendingPreflight {
        control: Arc::clone(&control),
        calls: Arc::clone(&calls),
        dropped: Arc::clone(&dropped),
    });
    let weak = Arc::downgrade(&service);
    let mut waiter =
        lifecycle.call_owned_preflight(service.clone(), AdapterPoison::default(), request());

    assert!(poll_once(&mut waiter, Waker::noop()).is_pending());
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(lifecycle.snapshot().owned_activities, 1);
    assert_eq!(executor.task_ids(), [0]);
    drop(service);
    drop(waiter);
    assert!(weak.upgrade().is_some());
    assert!(!dropped.load(Ordering::Acquire));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));

    control.complete(response(EmbeddingOperation::ResolveMappings));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert!(weak.upgrade().is_none());
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(lifecycle.snapshot().owned_activities, 0);
    assert_eq!(public_activity_in_use(&configuration), 0);
    assert_eq!(lifecycle.owned_activity_submitted_task_count(), 1);
}

#[test]
fn public_activity_saturation_is_pre_invocation_and_releases_once() {
    let (configuration, executor) = configuration(1);
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let control = Arc::new(PendingControl::default());
    let first_calls = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(PendingPreflight {
        control: Arc::clone(&control),
        calls: Arc::clone(&first_calls),
        dropped: Arc::new(AtomicBool::new(false)),
    });
    let mut first_wait = lifecycle.call_owned_preflight(first, AdapterPoison::default(), request());
    assert!(poll_once(&mut first_wait, Waker::noop()).is_pending());

    let refused_calls = Arc::new(AtomicUsize::new(0));
    let refused = lifecycle.call_owned_preflight(
        Arc::new(ImmediatePreflight {
            calls: Arc::clone(&refused_calls),
        }),
        AdapterPoison::default(),
        request(),
    );
    assert!(matches!(
        block_on(refused),
        Err(OwnedActivityError::Admission(error))
            if error.resource
                == AdmissionResourceClass::Ordinary(AdmissionClass::PublicActivity)
    ));
    assert_eq!(refused_calls.load(Ordering::Acquire), 0);
    assert_eq!(public_activity_in_use(&configuration), 1);

    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    control.complete(response(EmbeddingOperation::ResolveMappings));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert!(matches!(
        poll_once(&mut first_wait, Waker::noop()),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(public_activity_in_use(&configuration), 0);
}

#[test]
fn shutdown_waits_for_caller_independent_activity_settlement() {
    let (configuration, executor) = configuration(1);
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let control = Arc::new(PendingControl::default());
    let waiter = lifecycle.call_owned_preflight(
        Arc::new(PendingPreflight {
            control: Arc::clone(&control),
            calls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicBool::new(false)),
        }),
        AdapterPoison::default(),
        request(),
    );
    drop(waiter);

    let mut shutdown = lifecycle
        .begin_shutdown(None, None)
        .unwrap_or_else(|error| panic!("shutdown admission failed: {error}"));
    let coordinator = shutdown
        .coordinator
        .take()
        .unwrap_or_else(|| panic!("first shutdown caller did not own coordination"));
    let mut progress = coordinator.wait_for_quiescence();
    let wakes = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wakes));
    assert!(poll_once(&mut progress, &waker).is_pending());
    assert_eq!(lifecycle.snapshot().owned_activities, 1);
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));

    control.complete(response(EmbeddingOperation::ResolveMappings));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert!(wakes.0.load(Ordering::Acquire) > 0);
    assert!(poll_once(&mut progress, &waker).is_ready());
    let report = coordinator
        .complete(true, FinalShutdownEventSettlement::Settled)
        .unwrap_or_else(|error| panic!("shutdown completion failed: {error:?}"));
    assert!(report.orderly);
}

#[test]
fn owned_activity_contains_panics_and_rejects_reentrant_callbacks() {
    let (configuration, _) = configuration(2);
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let poison = AdapterPoison::default();
    let panicked =
        lifecycle.call_owned_preflight(Arc::new(PanickingPreflight), poison.clone(), request());
    assert!(matches!(
        block_on(panicked),
        Err(OwnedActivityError::Boundary(failure))
            if failure.origin == gantry::runtime::PanicOrigin::Integration
    ));
    assert!(poison.is_poisoned());
    assert_eq!(lifecycle.snapshot().owned_activities, 0);

    let observed = Arc::new(Mutex::new(None));
    let reentrant = lifecycle.call_owned_preflight(
        Arc::new(ReentrantPreflight {
            lifecycle: lifecycle.clone(),
            observed: Arc::clone(&observed),
        }),
        AdapterPoison::default(),
        request(),
    );
    assert!(block_on(reentrant).is_ok());
    assert_eq!(
        *lock(&observed),
        Some(LifecycleCode::ReentrantInterpreterCall)
    );
}

fn configuration(
    public_activity_capacity: u64,
) -> (
    InterpreterConfiguration,
    Arc<DeterministicConcurrentExecutor>,
) {
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor.clone();
    let required = RequiredConfiguration::new(
        FrontendLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
            .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1,
        1,
        ValueLimits::new(1, 1, 1, 1).unwrap_or_else(|| panic!("value limits failed")),
        1,
        1,
        1,
        1,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    let capacities = AsyncCapacityLimits::new(1, 1, 1, public_activity_capacity, 1, 1, 1, 1, 1)
        .unwrap_or_else(|error| panic!("capacity configuration failed: {error}"));
    (
        InterpreterConfiguration::new(
            executor_adapter,
            Arc::new(FixedIdentitySource),
            required,
            capacities,
        ),
        executor,
    )
}

struct FixedIdentitySource;

impl IdentitySource for FixedIdentitySource {
    fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
        Ok([7; 32])
    }
}

fn request() -> HostRequest {
    HostRequest::new(
        EmbeddingVersion::V1,
        EmbeddingOperation::ResolveMappings,
        Arc::from(&b"{}"[..]),
    )
    .unwrap_or_else(|error| panic!("request failed: {error:?}"))
}

fn response(operation: EmbeddingOperation) -> Result<HostResponse, HostError> {
    HostResponse::new(
        EmbeddingVersion::V1,
        operation,
        Arc::from(&b"{\"result\":\"resolved\"}"[..]),
    )
    .map_err(|_| host_error("response-invariant"))
}

fn public_activity_in_use(configuration: &InterpreterConfiguration) -> u64 {
    configuration
        .async_admission()
        .snapshot()
        .in_use(AdmissionResourceClass::Ordinary(
            AdmissionClass::PublicActivity,
        ))
}

fn host_error(code: &str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn poll_once<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
