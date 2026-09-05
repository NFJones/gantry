//! Public conformance for bounded package blocking-work ownership.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use gantry::host::contracts::{
    BlockingJobCancellation, BlockingJobCompletion, BlockingWorkCapacities, BlockingWorkService,
    BlockingWorkSubmitError, ExecutorAdapter, HostError, HostFuture, IdentitySource,
    OwnedBlockingJob, SubmittedBlockingJob,
};
use gantry::host::journal::{JournalId, JournalStorage, ReadJournalPrefixV1};
use gantry::portable::{
    PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS, StartFailureCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, BlockingWorkConfigurationError, BoundedBlockingWorkService,
    InterpreterConfiguration, RequiredConfiguration,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{
    AnalyzePackageCoordinator, AnalyzePackageError, AnalyzePackageRequest, Interpreter,
    PackageBlockingWorkError, StartExecutionRequest, StartExecutionResult,
    ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest,
};
use gantry_conformance::scripted::ScriptedIntegration;
use gantry_conformance::services::{
    DeterministicExecutor, DeterministicIdentitySource, DeterministicUtcClock,
};
use gantry_storage_sqlite::{SqliteJournalStore, SqliteJournalStoreConfig};
use serde::Deserialize;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct PanickingCapture;

impl Drop for PanickingCapture {
    fn drop(&mut self) {
        panic!("queued capture destructor must remain contained");
    }
}

struct PanickingPayload;

impl Drop for PanickingPayload {
    fn drop(&mut self) {
        panic!("blocking panic payload destructor must remain contained");
    }
}

struct PanickingWake;

impl Wake for PanickingWake {
    fn wake(self: Arc<Self>) {
        panic!("completion wake must remain contained");
    }
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn package(source: &[u8]) -> Self {
        let directory = Self::new("package");
        std::fs::write(directory.0.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("package fixture write failed: {error}"));
        directory
    }

    fn new(label: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-blocking-work-{label}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
        Self(path)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bounded_blocking_work_is_nonblocking_cancellable_and_retained_to_settlement() {
    assert_send_sync::<BoundedBlockingWorkService>();
    let service = BoundedBlockingWorkService::new(1, 1)
        .unwrap_or_else(|error| panic!("blocking service construction failed: {error}"));
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let active = service
        .submit(Box::new(move || {
            let _ = started_sender.send(());
            let _ = release_receiver.recv();
        }))
        .unwrap_or_else(|error| panic!("active job submission failed: {error:?}"));
    started_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("active job did not start: {error}"));

    let queued_ran = Arc::new(AtomicBool::new(false));
    let queued_marker = Arc::clone(&queued_ran);
    let panicking_capture = PanickingCapture;
    let queued = service
        .submit(Box::new(move || {
            drop(panicking_capture);
            queued_marker.store(true, Ordering::Release);
        }))
        .unwrap_or_else(|error| panic!("queued job submission failed: {error:?}"));
    let refusal = service.submit(Box::new(|| {}));
    assert!(matches!(
        refusal,
        Err(BlockingWorkSubmitError::CapacityExhausted)
    ));
    assert_eq!(
        queued.cancel_before_start(),
        BlockingJobCancellation::Cancelled
    );
    assert_eq!(
        block_on(queued.completion()),
        BlockingJobCompletion::CancelledBeforeStart
    );
    assert_eq!(
        active.cancel_before_start(),
        BlockingJobCancellation::AlreadyStarted
    );
    let mut active_wait = active.completion();
    let panicking_waker = Waker::from(Arc::new(PanickingWake));
    let mut panicking_context = Context::from_waker(&panicking_waker);
    assert!(
        active_wait
            .as_mut()
            .poll(&mut panicking_context)
            .is_pending()
    );
    release_sender
        .send(())
        .unwrap_or_else(|error| panic!("active job release failed: {error}"));
    assert_eq!(block_on(active_wait), BlockingJobCompletion::Completed);
    assert_eq!(
        block_on(active.completion()),
        BlockingJobCompletion::Completed
    );
    assert!(!queued_ran.load(Ordering::Acquire));

    let panicked = service
        .submit(Box::new(|| std::panic::panic_any(PanickingPayload)))
        .unwrap_or_else(|error| panic!("panicking job submission failed: {error:?}"));
    assert_eq!(
        block_on(panicked.completion()),
        BlockingJobCompletion::Panicked
    );

    let retained_finished = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&retained_finished);
    let (retained_started_sender, retained_started_receiver) = mpsc::sync_channel(1);
    let (retained_release_sender, retained_release_receiver) = mpsc::sync_channel(1);
    let retained = service
        .submit(Box::new(move || {
            let _ = retained_started_sender.send(());
            let _ = retained_release_receiver.recv();
            finished.store(true, Ordering::Release);
        }))
        .unwrap_or_else(|error| panic!("retained job submission failed: {error:?}"));
    retained_started_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("retained job did not start: {error}"));
    drop(retained);
    let mut shutdown = Box::pin(service.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    retained_release_sender
        .send(())
        .unwrap_or_else(|error| panic!("retained job release failed: {error}"));
    assert_eq!(block_on(shutdown), Ok(()));
    assert!(retained_finished.load(Ordering::Acquire));
    assert!(matches!(
        service.submit(Box::new(|| {})),
        Err(BlockingWorkSubmitError::Failed(_))
    ));
}

#[test]
fn package_waiter_drop_cancels_queued_work_and_discards_started_results() {
    let root = TemporaryDirectory::package(b"fn main() {}");
    let selection = selection();

    let queued_service = BoundedBlockingWorkService::new(1, 1)
        .unwrap_or_else(|error| panic!("queued service construction failed: {error}"));
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let blocker = queued_service
        .submit(Box::new(move || {
            let _ = started_sender.send(());
            let _ = release_receiver.recv();
        }))
        .unwrap_or_else(|error| panic!("blocking fixture submission failed: {error:?}"));
    started_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("blocking fixture did not start: {error}"));
    let queued_identities = DeterministicIdentitySource::new([Ok([1; 32])]);
    let queued_clock = clock(1);
    let queued_allocator = gantry::host::contracts::FreshIdentityAllocator::default();
    let queued_coordinator = ValidatePackageCoordinator::new(
        &queued_allocator,
        &queued_identities,
        &queued_clock,
        &queued_service,
    );
    let mut queued_wait =
        Box::pin(queued_coordinator.validate(validate_request(&root.0, &selection)));
    assert!(poll_once(queued_wait.as_mut()).is_pending());
    drop(queued_wait);
    let replacement = queued_service
        .submit(Box::new(|| {}))
        .unwrap_or_else(|error| panic!("queued cancellation did not release capacity: {error:?}"));
    assert_eq!(
        replacement.cancel_before_start(),
        BlockingJobCancellation::Cancelled
    );
    release_sender
        .send(())
        .unwrap_or_else(|error| panic!("blocking fixture release failed: {error}"));
    assert_eq!(
        block_on(blocker.completion()),
        BlockingJobCompletion::Completed
    );
    assert_eq!(block_on(queued_service.shutdown()), Ok(()));
    assert_eq!(queued_identities.calls().len(), 1);

    let started_service = GatedBlockingService::new();
    let started_identities = DeterministicIdentitySource::new([Ok([2; 32])]);
    let started_clock = clock(2);
    let started_allocator = gantry::host::contracts::FreshIdentityAllocator::default();
    let started_coordinator = ValidatePackageCoordinator::new(
        &started_allocator,
        &started_identities,
        &started_clock,
        &started_service,
    );
    let mut started_wait =
        Box::pin(started_coordinator.validate(validate_request(&root.0, &selection)));
    assert!(poll_once(started_wait.as_mut()).is_pending());
    wait_until(
        || started_service.started() == 1,
        "package job did not start",
    );
    drop(started_wait);
    let mut shutdown = Box::pin(started_service.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    started_service.release();
    assert_eq!(block_on(shutdown), Ok(()));
    assert_eq!(started_identities.calls().len(), 1);
}

#[test]
fn blocking_failures_map_without_fabricating_package_or_execution_state() {
    let root = TemporaryDirectory::package(b"fn main() {}");
    let selection = selection();
    let allocator = gantry::host::contracts::FreshIdentityAllocator::default();
    let validate_identities = DeterministicIdentitySource::new([Ok([3; 32])]);
    let validate_clock = clock(3);
    let refusing = RefusingBlockingService;
    let validate = ValidatePackageCoordinator::new(
        &allocator,
        &validate_identities,
        &validate_clock,
        &refusing,
    );
    assert!(matches!(
        block_on(validate.validate(validate_request(&root.0, &selection))),
        Err(ValidatePackageError::BlockingWork(
            PackageBlockingWorkError::CapacityExhausted
        ))
    ));

    let analyze_identities = DeterministicIdentitySource::new([Ok([4; 32])]);
    let analyze_clock = clock(4);
    let analyze =
        AnalyzePackageCoordinator::new(&allocator, &analyze_identities, &analyze_clock, &refusing);
    assert!(matches!(
        block_on(analyze.analyze(analyze_request(&root.0, &selection))),
        Err(AnalyzePackageError::BlockingWork(
            PackageBlockingWorkError::CapacityExhausted
        ))
    ));

    let panicking = PanickingBlockingService::default();
    let panic_identities = DeterministicIdentitySource::new([Ok([5; 32]), Ok([6; 32])]);
    let panic_clock = clock(5);
    let panic_coordinator =
        ValidatePackageCoordinator::new(&allocator, &panic_identities, &panic_clock, &panicking);
    for _ in 0..2 {
        assert!(matches!(
            block_on(panic_coordinator.validate(validate_request(&root.0, &selection))),
            Err(ValidatePackageError::BlockingWork(
                PackageBlockingWorkError::Internal
            ))
        ));
    }
    assert_eq!(panicking.calls.load(Ordering::Acquire), 1);

    let handle_panicking = PanickingHandleService;
    let handle_identities = DeterministicIdentitySource::new([Ok([7; 32])]);
    let handle_clock = clock(6);
    let handle_coordinator = ValidatePackageCoordinator::new(
        &allocator,
        &handle_identities,
        &handle_clock,
        &handle_panicking,
    );
    assert!(matches!(
        block_on(handle_coordinator.validate(validate_request(&root.0, &selection))),
        Err(ValidatePackageError::BlockingWork(
            PackageBlockingWorkError::Internal
        ))
    ));

    let executor = Arc::new(DeterministicExecutor::new([], []));
    let identities = Arc::new(DeterministicIdentitySource::new([Ok([8; 32])]));
    let interpreter_configuration = configuration(executor, identities)
        .with_blocking_work_service(Box::new(RefusingBlockingService))
        .unwrap_or_else(|error| panic!("matching blocking service was rejected: {error}"));
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        interpreter_configuration,
        Arc::new(clock(7)),
        integration.clone(),
        integration.clone(),
        integration,
    );
    let result = block_on(interpreter.start_execution(StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    }));
    assert!(matches!(
        result,
        StartExecutionResult::Rejected(failure)
            if failure.category == StartFailureCategory::ImplementationResourceExhaustion
                && failure.code.as_ref() == "implementation-resource-exhaustion"
                && failure.package_activity.is_none()
    ));

    let executor = Arc::new(DeterministicExecutor::new([], []));
    let identities = Arc::new(DeterministicIdentitySource::new([]));
    assert!(matches!(
        configuration(executor, identities)
            .with_blocking_work_service(Box::new(RecordingBlockingService::new(2))),
        Err(BlockingWorkConfigurationError::CapacityMismatch { .. })
    ));

    let executor = Arc::new(DeterministicExecutor::new([], []));
    let identities = Arc::new(DeterministicIdentitySource::new([Err(host_failure(
        "provider-specific-text",
    ))]));
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new(
        configuration(executor, identities),
        Arc::new(clock(8)),
        integration.clone(),
        integration.clone(),
        integration,
    );
    assert!(matches!(
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        })),
        StartExecutionResult::Rejected(failure)
            if failure.category == StartFailureCategory::IntegrationPreflight
                && failure.code.as_ref() == "identity-source-failure"
                && failure.package_activity.is_none()
    ));
}

#[test]
fn package_jobs_are_owned_separate_deterministic_and_do_not_starve_timers() {
    let root = TemporaryDirectory::package(b"mod child;\nfn main() {}");
    std::fs::write(root.0.join("child.gnt"), b"fn child() {}")
        .unwrap_or_else(|error| panic!("child fixture write failed: {error}"));
    let selection = selection();
    let one = analyze_with_workers(&root.0, &selection, 1, 10);
    let four = analyze_with_workers(&root.0, &selection, 4, 10);
    assert_eq!(one.result, four.result);
    assert!(one.thread_names.len() >= 6);
    assert!(four.thread_names.len() >= 6);
    assert!(
        one.thread_names
            .iter()
            .chain(&four.thread_names)
            .all(|name| name == "gantry-blocking-work")
    );

    let service = BoundedBlockingWorkService::new(1, 1)
        .unwrap_or_else(|error| panic!("timer service construction failed: {error}"));
    let finished = Arc::new(AtomicBool::new(false));
    let finished_job = Arc::clone(&finished);
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let job = service
        .submit(Box::new(move || {
            let _ = started_sender.send(());
            std::thread::sleep(Duration::from_millis(100));
            finished_job.store(true, Ordering::Release);
        }))
        .unwrap_or_else(|error| panic!("timer-load job submission failed: {error:?}"));
    started_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("timer-load job did not start: {error}"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("Tokio timer runtime failed: {error}"));
    runtime.block_on(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
    });
    assert!(!finished.load(Ordering::Acquire));
    assert_eq!(block_on(job.completion()), BlockingJobCompletion::Completed);
    assert_eq!(block_on(service.shutdown()), Ok(()));
}

#[test]
fn sqlite_worker_remains_isolated_under_generic_blocking_saturation() {
    let directory = TemporaryDirectory::new("sqlite");
    let store = SqliteJournalStore::open(
        directory.0.join("journal.sqlite3"),
        SqliteJournalStoreConfig::default(),
    )
    .unwrap_or_else(|error| panic!("SQLite store open failed: {error:?}"));
    let service = BoundedBlockingWorkService::new(1, 1)
        .unwrap_or_else(|error| panic!("blocking service construction failed: {error}"));
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let blocker = service
        .submit(Box::new(move || {
            let _ = started_sender.send(());
            let _ = release_receiver.recv();
        }))
        .unwrap_or_else(|error| panic!("generic blocker submission failed: {error:?}"));
    started_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("generic blocker did not start: {error}"));

    let before = store.worker_snapshot();
    let prefix = block_on(
        store.read_prefix(ReadJournalPrefixV1 {
            journal_id: JournalId::new("blocking-isolation")
                .unwrap_or_else(|error| panic!("journal id failed: {error:?}")),
        }),
    );
    assert!(prefix.is_ok());
    let after = store.worker_snapshot();
    assert_eq!(after.queued, before.queued.saturating_add(1));
    assert_eq!(after.executing, before.executing.saturating_add(1));

    release_sender
        .send(())
        .unwrap_or_else(|error| panic!("generic blocker release failed: {error}"));
    assert_eq!(
        block_on(blocker.completion()),
        BlockingJobCompletion::Completed
    );
    assert_eq!(block_on(service.shutdown()), Ok(()));
    store
        .close()
        .unwrap_or_else(|error| panic!("SQLite store close failed: {error:?}"));
}

#[test]
fn checked_in_blocking_work_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: BlockingWorkEvidence =
        read_json(&root.join("protocol/conformance/blocking-work-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    assert_eq!(manifest.format, "gantry.blocking-work-evidence/v1");
    assert_eq!(manifest.issue, "GNT-ASYNC-BLOCK-001");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.requirements, expected_requirements());
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(!manifest.exclusions.is_empty());

    for requirement in &manifest.requirements {
        let clause = review
            .requirements
            .iter()
            .find(|candidate| candidate.id == requirement.requirement)
            .and_then(|candidate| {
                candidate
                    .clauses
                    .iter()
                    .find(|clause| clause.key == requirement.clause)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing reviewed row {}/{}",
                    requirement.requirement, requirement.clause
                )
            });
        for profile in &requirement.profiles {
            let profile = clause
                .profile_reviews
                .iter()
                .find(|candidate| candidate.profile == *profile)
                .unwrap_or_else(|| panic!("missing reviewed profile {profile}"));
            assert_eq!(profile.state, "covered");
            assert!(profile.evidence.iter().any(|evidence| {
                evidence.starts_with("crates/gantry-conformance/tests/blocking_work.rs#")
                    || evidence
                        == "crates/gantry-conformance/tests/durable_start.rs#durable_start_and_resume_preserve_acceptance_and_nonmutation_boundaries"
            }));
        }
    }
}

struct GatedBlockingService {
    inner: BoundedBlockingWorkService,
    gate: Arc<(Mutex<bool>, Condvar)>,
    started: Arc<AtomicU64>,
}

impl GatedBlockingService {
    fn new() -> Self {
        Self {
            inner: BoundedBlockingWorkService::new(1, 1)
                .unwrap_or_else(|_| unreachable!("positive gate capacities")),
            gate: Arc::new((Mutex::new(false), Condvar::new())),
            started: Arc::new(AtomicU64::new(0)),
        }
    }

    fn started(&self) -> u64 {
        self.started.load(Ordering::Acquire)
    }

    fn release(&self) {
        let (lock, wake) = &*self.gate;
        *lock_state(lock) = true;
        wake.notify_all();
    }
}

impl BlockingWorkService for GatedBlockingService {
    fn capacities(&self) -> BlockingWorkCapacities {
        self.inner.capacities()
    }

    fn submit(
        &self,
        job: OwnedBlockingJob,
    ) -> Result<Arc<dyn SubmittedBlockingJob>, BlockingWorkSubmitError> {
        let gate = Arc::clone(&self.gate);
        let started = Arc::clone(&self.started);
        self.inner.submit(Box::new(move || {
            started.fetch_add(1, Ordering::AcqRel);
            let (lock, wake) = &*gate;
            let mut released = lock_state(lock);
            while !*released {
                released = wake
                    .wait(released)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            job();
        }))
    }

    fn shutdown<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        self.inner.shutdown()
    }
}

struct RefusingBlockingService;

impl BlockingWorkService for RefusingBlockingService {
    fn capacities(&self) -> BlockingWorkCapacities {
        BlockingWorkCapacities::new(1, 1)
            .unwrap_or_else(|| unreachable!("positive refusing capacities"))
    }

    fn submit(
        &self,
        _job: OwnedBlockingJob,
    ) -> Result<Arc<dyn SubmittedBlockingJob>, BlockingWorkSubmitError> {
        Err(BlockingWorkSubmitError::CapacityExhausted)
    }

    fn shutdown<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
struct PanickingBlockingService {
    calls: AtomicU64,
}

impl BlockingWorkService for PanickingBlockingService {
    fn capacities(&self) -> BlockingWorkCapacities {
        BlockingWorkCapacities::new(1, 1)
            .unwrap_or_else(|| unreachable!("positive panicking capacities"))
    }

    fn submit(
        &self,
        _job: OwnedBlockingJob,
    ) -> Result<Arc<dyn SubmittedBlockingJob>, BlockingWorkSubmitError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        panic!("protected blocking-service panic")
    }

    fn shutdown<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }
}

struct PanickingHandleService;

impl BlockingWorkService for PanickingHandleService {
    fn capacities(&self) -> BlockingWorkCapacities {
        BlockingWorkCapacities::new(1, 1)
            .unwrap_or_else(|| unreachable!("positive handle-test capacities"))
    }

    fn submit(
        &self,
        job: OwnedBlockingJob,
    ) -> Result<Arc<dyn SubmittedBlockingJob>, BlockingWorkSubmitError> {
        job();
        Ok(Arc::new(PanickingHandle))
    }

    fn shutdown<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }
}

struct PanickingHandle;

impl SubmittedBlockingJob for PanickingHandle {
    fn cancel_before_start(&self) -> BlockingJobCancellation {
        BlockingJobCancellation::AlreadySettled
    }

    fn completion<'a>(&'a self) -> HostFuture<'a, BlockingJobCompletion> {
        Box::pin(async { BlockingJobCompletion::Completed })
    }
}

impl Drop for PanickingHandle {
    fn drop(&mut self) {
        panic!("blocking handle destructor must remain contained");
    }
}

struct RecordingBlockingService {
    inner: BoundedBlockingWorkService,
    thread_names: Arc<Mutex<Vec<String>>>,
}

impl RecordingBlockingService {
    fn new(workers: u64) -> Self {
        Self {
            inner: BoundedBlockingWorkService::new(8, workers)
                .unwrap_or_else(|_| unreachable!("positive recording capacities")),
            thread_names: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn thread_names(&self) -> Vec<String> {
        lock_state(&self.thread_names).clone()
    }
}

impl BlockingWorkService for RecordingBlockingService {
    fn capacities(&self) -> BlockingWorkCapacities {
        self.inner.capacities()
    }

    fn submit(
        &self,
        job: OwnedBlockingJob,
    ) -> Result<Arc<dyn SubmittedBlockingJob>, BlockingWorkSubmitError> {
        let names = Arc::clone(&self.thread_names);
        self.inner.submit(Box::new(move || {
            let name = std::thread::current()
                .name()
                .unwrap_or("unnamed")
                .to_owned();
            lock_state(&names).push(name);
            job();
        }))
    }

    fn shutdown<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        self.inner.shutdown()
    }
}

struct AnalysisRun {
    result: gantry::AnalyzePackageResult,
    thread_names: Vec<String>,
}

fn analyze_with_workers(
    root: &Path,
    selection: &ProtocolSelection,
    workers: u64,
    identity_seed: u8,
) -> AnalysisRun {
    let service = RecordingBlockingService::new(workers);
    let identities = DeterministicIdentitySource::new([
        Ok([identity_seed; 32]),
        Ok([identity_seed.saturating_add(1); 32]),
        Ok([identity_seed.saturating_add(2); 32]),
    ]);
    let clock = clock(u32::from(identity_seed));
    let allocator = gantry::host::contracts::FreshIdentityAllocator::default();
    let coordinator = AnalyzePackageCoordinator::new(&allocator, &identities, &clock, &service);
    let result = block_on(coordinator.analyze(analyze_request(root, selection)))
        .unwrap_or_else(|error| panic!("package analysis failed: {error:?}"));
    let thread_names = service.thread_names();
    assert_eq!(block_on(service.shutdown()), Ok(()));
    AnalysisRun {
        result,
        thread_names,
    }
}

fn configuration(
    executor: Arc<DeterministicExecutor>,
    identities: Arc<DeterministicIdentitySource>,
) -> InterpreterConfiguration {
    let executor: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = identities;
    let capacities = AsyncCapacityLimits::new(8, 8, 8, 8, 8, 1, 1, 8, 8)
        .unwrap_or_else(|error| panic!("async capacities failed: {error}"));
    InterpreterConfiguration::new(executor, identities, required(), capacities)
}

fn required() -> RequiredConfiguration {
    RequiredConfiguration::new(
        frontend_limits(),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"))
}

fn frontend_limits() -> FrontendLimits {
    FrontendLimits::new(
        32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304, 256,
        65_536, 1_000_000,
    )
    .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}"))
}

fn validate_request<'a>(
    root: &'a Path,
    selection: &'a ProtocolSelection,
) -> ValidatePackageRequest<'a> {
    ValidatePackageRequest {
        package_root: root,
        protocol_selection: selection,
        frontend_limits: frontend_limits(),
        event_delivery: None,
    }
}

fn analyze_request<'a>(
    root: &'a Path,
    selection: &'a ProtocolSelection,
) -> AnalyzePackageRequest<'a> {
    AnalyzePackageRequest {
        package_root: root,
        protocol_selection: selection,
        frontend_limits: frontend_limits(),
        event_delivery: None,
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
    .unwrap_or_else(|error| panic!("protocol selection failed: {error:?}"))
}

fn clock(microsecond: u32) -> DeterministicUtcClock {
    DeterministicUtcClock::new([
        UtcTimestamp::from_unix_seconds(0, microsecond).map_err(|_| host_failure("timestamp")),
        UtcTimestamp::from_unix_seconds(0, microsecond.saturating_add(1))
            .map_err(|_| host_failure("timestamp")),
    ])
}

fn host_failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn assert_send_sync<T: Send + Sync>() {}

fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    future.poll(&mut context)
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    loop {
        match poll_once(future.as_mut()) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline, "{message}");
        std::thread::yield_now();
    }
}

fn lock_state<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Deserialize)]
struct BlockingWorkEvidence {
    format: String,
    specification_sha256: String,
    issue: String,
    requirements: Vec<RequirementAssignment>,
    capabilities: Vec<Capability>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RequirementAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct Capability {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewedRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewedRequirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

fn expected_requirements() -> Vec<RequirementAssignment> {
    vec![
        assignment(
            "GNT-7.17",
            "clause-001",
            &[
                "concurrent-evaluator",
                "durable-runtime",
                "embedding",
                "evaluator",
            ],
        ),
        assignment("GNT-15.0", "clause-005", &["embedding"]),
        assignment("GNT-15.1", "clause-001", &["embedding"]),
        assignment("GNT-15.4-owned-work", "clause-001", &["embedding"]),
        assignment("GNT-15.7", "clause-001", &["embedding"]),
        assignment("GNT-15.9", "clause-001", &["embedding"]),
    ]
}

fn assignment(requirement: &str, clause: &str, profiles: &[&str]) -> RequirementAssignment {
    RequirementAssignment {
        requirement: requirement.to_owned(),
        clause: clause.to_owned(),
        profiles: profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
