//! Tokio-specific qualification of Gantry's executor-neutral task contract.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::ThreadId;
use std::time::Duration;

use gantry::host::contracts::{
    DeadlineOutcome, DurationMicros, ExecutorAdapter, HostError, InclusiveJitterRange,
    JitterSource, OwnedTaskAbort, OwnedTaskCompletion, OwnedTaskPanic, OwnedTaskPanicOrigin,
    OwnedTaskResult, deadline_race,
};
use gantry_adapter_tokio::TokioExecutor;
use serde::Deserialize;
use tokio::runtime::{Builder, Runtime};

const RUNTIME_EVIDENCE: &str = "crates/gantry-conformance/tests/tokio_executor.rs#caller_owned_runtime_matrix_keeps_runnable_work_making_progress";
const OVERLAP_EVIDENCE: &str = "crates/gantry-conformance/tests/tokio_executor.rs#multithread_runtime_polls_owned_send_tasks_concurrently";
const MIGRATION_EVIDENCE: &str = "crates/gantry-conformance/tests/tokio_executor.rs#multithread_runtime_preserves_owned_tasks_across_worker_migration";
const SHUTDOWN_EVIDENCE: &str = "crates/gantry-conformance/tests/tokio_executor.rs#runtime_shutdown_reports_structured_task_and_service_failures";
const CONTROL_EVIDENCE: &str = "crates/gantry-conformance/tests/tokio_executor.rs#abort_drop_panic_and_stale_wakes_settle_once";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    requirements: Vec<RequirementEvidence>,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RequirementEvidence {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ContractGate {
    requirement_assignments: Vec<RequirementAssignment>,
}

#[derive(Debug, Deserialize)]
struct RequirementAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

#[derive(Debug)]
struct FixedJitter;

impl JitterSource for FixedJitter {
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

#[derive(Default)]
struct ControlledState {
    ready: AtomicBool,
    dropped: AtomicBool,
    polls: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

impl ControlledState {
    fn complete(&self) {
        self.ready.store(true, Ordering::Release);
        if let Some(waker) = lock(&self.waker).take() {
            waker.wake();
        }
    }
}

struct ControlledTask {
    state: Arc<ControlledState>,
}

impl Future for ControlledTask {
    type Output = OwnedTaskResult;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.state.polls.fetch_add(1, Ordering::AcqRel);
        if self.state.ready.load(Ordering::Acquire) {
            return Poll::Ready(OwnedTaskResult::new());
        }
        *lock(&self.state.waker) = Some(context.waker().clone());
        if self.state.ready.load(Ordering::Acquire) {
            Poll::Ready(OwnedTaskResult::new())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for ControlledTask {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::Release);
    }
}

struct BlockingPollTask {
    entered: Sender<ThreadId>,
    release: Receiver<()>,
}

impl Future for BlockingPollTask {
    type Output = OwnedTaskResult;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.entered
            .send(std::thread::current().id())
            .unwrap_or_else(|error| panic!("overlap observation failed: {error}"));
        self.release
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("overlap release failed: {error}"));
        Poll::Ready(OwnedTaskResult::new())
    }
}

struct MigrationTask {
    observed: Sender<ThreadId>,
    resume: Arc<Mutex<Option<Waker>>>,
    polls: usize,
}

impl Future for MigrationTask {
    type Output = OwnedTaskResult;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.observed
            .send(std::thread::current().id())
            .unwrap_or_else(|error| panic!("migration observation failed: {error}"));
        self.polls = self.polls.saturating_add(1);
        if self.polls > 1 {
            return Poll::Ready(OwnedTaskResult::new());
        }
        *lock(&self.resume) = Some(context.waker().clone());
        Poll::Pending
    }
}

struct PanicOnDropTask {
    polled: Arc<AtomicBool>,
}

impl Future for PanicOnDropTask {
    type Output = OwnedTaskResult;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polled.store(true, Ordering::Release);
        Poll::Pending
    }
}

impl Drop for PanicOnDropTask {
    fn drop(&mut self) {
        std::panic::resume_unwind(Box::new(OwnedTaskPanic::new(
            OwnedTaskPanicOrigin::Integration,
            Some(Arc::from("protected-drop-panic")),
        )));
    }
}

#[test]
fn checked_in_tokio_executor_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/tokio-executor-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.tokio-executor-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-TOKIO-001");
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
            RUNTIME_EVIDENCE,
            OVERLAP_EVIDENCE,
            MIGRATION_EVIDENCE,
            SHUTDOWN_EVIDENCE,
            CONTROL_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-TOKIO-001")
        })
        .map(|assignment| RequirementEvidence {
            requirement: assignment.requirement,
            clause: assignment.clause,
            profiles: assignment.profiles,
        })
        .collect::<Vec<_>>();
    assigned.sort();
    let mut declared = manifest.requirements;
    declared.sort();
    assert_eq!(declared, assigned);
    assert_eq!(declared.len(), 7);
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn caller_owned_runtime_matrix_keeps_runnable_work_making_progress() {
    for runtime in [current_thread_runtime(), multithread_runtime()] {
        let adapter = Arc::new(TokioExecutor::new(
            runtime.handle().clone(),
            Arc::new(FixedJitter),
        ));
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let zero = DurationMicros::new(0)
                    .unwrap_or_else(|| unreachable!("zero duration is admitted"));
                let immediate = deadline_race(
                    adapter.as_ref(),
                    Box::pin(std::future::ready(17_u64)),
                    zero,
                    None,
                )
                .await;
                assert_eq!(immediate, DeadlineOutcome::Completed(17));

                let completed = Arc::new(AtomicUsize::new(0));
                let mut handles = Vec::new();
                for _ in 0..16 {
                    let task_adapter = Arc::clone(&adapter);
                    let task_completed = Arc::clone(&completed);
                    handles.push(
                        adapter
                            .spawn(Box::pin(async move {
                                for _ in 0..16 {
                                    task_adapter
                                        .yield_now()
                                        .await
                                        .unwrap_or_else(|error| panic!("yield failed: {error:?}"));
                                }
                                task_adapter
                                    .sleep(zero)
                                    .await
                                    .unwrap_or_else(|error| panic!("timer failed: {error:?}"));
                                task_completed.fetch_add(1, Ordering::AcqRel);
                                OwnedTaskResult::new()
                            }))
                            .unwrap_or_else(|error| panic!("task submission failed: {error:?}")),
                    );
                }
                for handle in handles {
                    assert_eq!(
                        handle.completion().await,
                        OwnedTaskCompletion::Completed(OwnedTaskResult::new())
                    );
                }
                assert_eq!(completed.load(Ordering::Acquire), 16);
            })
            .await
            .unwrap_or_else(|_| panic!("runtime progress exceeded the qualification deadline"));
        });
    }
}

#[test]
fn multithread_runtime_polls_owned_send_tasks_concurrently() {
    let runtime = multithread_runtime();
    let adapter = TokioExecutor::new(runtime.handle().clone(), Arc::new(FixedJitter));
    let (entered_sender, entered_receiver) = channel();
    let (first_release, first_receiver) = channel();
    let (second_release, second_receiver) = channel();

    let first = adapter
        .spawn(Box::pin(BlockingPollTask {
            entered: entered_sender.clone(),
            release: first_receiver,
        }))
        .unwrap_or_else(|error| panic!("first overlap submission failed: {error:?}"));
    let second = adapter
        .spawn(Box::pin(BlockingPollTask {
            entered: entered_sender,
            release: second_receiver,
        }))
        .unwrap_or_else(|error| panic!("second overlap submission failed: {error:?}"));

    let first_worker = entered_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("first task was not polled: {error}"));
    let second_worker = entered_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("second task did not overlap: {error}"));
    assert_ne!(first_worker, second_worker);
    first_release
        .send(())
        .unwrap_or_else(|error| panic!("first overlap release failed: {error}"));
    second_release
        .send(())
        .unwrap_or_else(|error| panic!("second overlap release failed: {error}"));

    runtime.block_on(async {
        assert_eq!(
            first.completion().await,
            OwnedTaskCompletion::Completed(OwnedTaskResult::new())
        );
        assert_eq!(
            second.completion().await,
            OwnedTaskCompletion::Completed(OwnedTaskResult::new())
        );
    });
}

#[test]
fn multithread_runtime_preserves_owned_tasks_across_worker_migration() {
    let runtime = multithread_runtime();
    let adapter = TokioExecutor::new(runtime.handle().clone(), Arc::new(FixedJitter));
    let (migration_sender, migration_receiver) = channel();
    let resume = Arc::new(Mutex::new(None));
    let migrated = adapter
        .spawn(Box::pin(MigrationTask {
            observed: migration_sender,
            resume: Arc::clone(&resume),
            polls: 0,
        }))
        .unwrap_or_else(|error| panic!("migration submission failed: {error:?}"));
    let first_worker = migration_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("migration task was not initially polled: {error}"));

    let (first_entered_sender, first_entered_receiver) = channel();
    let (first_release, first_receiver) = channel();
    let first_blocker = adapter
        .spawn(Box::pin(BlockingPollTask {
            entered: first_entered_sender,
            release: first_receiver,
        }))
        .unwrap_or_else(|error| panic!("first migration blocker failed: {error:?}"));
    let (second_entered_sender, second_entered_receiver) = channel();
    let (second_release, second_receiver) = channel();
    let second_blocker = adapter
        .spawn(Box::pin(BlockingPollTask {
            entered: second_entered_sender,
            release: second_receiver,
        }))
        .unwrap_or_else(|error| panic!("second migration blocker failed: {error:?}"));
    let first_blocker_worker = first_entered_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("first migration blocker was not polled: {error}"));
    let second_blocker_worker = second_entered_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("second migration blocker was not polled: {error}"));
    assert_ne!(first_blocker_worker, second_blocker_worker);

    let (release_other_worker, release_original_worker) = if first_blocker_worker == first_worker {
        (second_release, first_release)
    } else if second_blocker_worker == first_worker {
        (first_release, second_release)
    } else {
        panic!("migration task ran outside the runtime worker set")
    };
    lock(&resume)
        .take()
        .unwrap_or_else(|| panic!("migration task did not retain its executor waker"))
        .wake();
    release_other_worker
        .send(())
        .unwrap_or_else(|error| panic!("other worker release failed: {error}"));
    let second_worker = migration_receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("migration task was not resumed: {error}"));
    assert_ne!(first_worker, second_worker);
    release_original_worker
        .send(())
        .unwrap_or_else(|error| panic!("original worker release failed: {error}"));

    runtime.block_on(async {
        for handle in [migrated, first_blocker, second_blocker] {
            assert_eq!(
                handle.completion().await,
                OwnedTaskCompletion::Completed(OwnedTaskResult::new())
            );
        }
    });
}

#[test]
fn runtime_shutdown_reports_structured_task_and_service_failures() {
    let runtime = multithread_runtime();
    let adapter = TokioExecutor::new(runtime.handle().clone(), Arc::new(FixedJitter));
    let state = Arc::new(ControlledState::default());
    let pending = adapter
        .spawn(Box::pin(ControlledTask {
            state: Arc::clone(&state),
        }))
        .unwrap_or_else(|error| panic!("pending task submission failed: {error:?}"));
    runtime.block_on(wait_for_count(&state.polls, 1));
    drop(runtime);

    assert!(state.dropped.load(Ordering::Acquire));
    assert_executor_failure(block_on(pending.completion()));

    let rejected_state = Arc::new(ControlledState::default());
    let rejected = adapter
        .spawn(Box::pin(ControlledTask {
            state: Arc::clone(&rejected_state),
        }))
        .unwrap_or_else(|error| panic!("shutdown task handoff failed: {error:?}"));
    assert_executor_failure(block_on(rejected.completion()));
    assert!(rejected_state.dropped.load(Ordering::Acquire));
    assert!(matches!(
        block_on(adapter.yield_now()),
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
    assert!(matches!(
        block_on(adapter.sleep(
            DurationMicros::new(0).unwrap_or_else(|| unreachable!("zero duration is admitted"))
        )),
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
}

#[test]
fn abort_drop_panic_and_stale_wakes_settle_once() {
    let runtime = current_thread_runtime();
    let adapter = TokioExecutor::new(runtime.handle().clone(), Arc::new(FixedJitter));
    runtime.block_on(async {
        let controlled_state = Arc::new(ControlledState::default());
        let controlled = adapter
            .spawn(Box::pin(ControlledTask {
                state: Arc::clone(&controlled_state),
            }))
            .unwrap_or_else(|error| panic!("controlled task submission failed: {error:?}"));
        wait_for_count(&controlled_state.polls, 1).await;
        let stale_waker = lock(&controlled_state.waker)
            .as_ref()
            .cloned()
            .unwrap_or_else(|| panic!("controlled task did not retain its executor waker"));
        let mut abandoned_observer = controlled.completion();
        assert!(matches!(poll_once(&mut abandoned_observer), Poll::Pending));
        drop(abandoned_observer);
        assert!(!controlled_state.dropped.load(Ordering::Acquire));
        controlled_state.complete();
        let completion = controlled.completion().await;
        assert_eq!(
            completion,
            OwnedTaskCompletion::Completed(OwnedTaskResult::new())
        );
        assert_eq!(controlled.completion().await, completion);
        assert_eq!(controlled.abort().await, OwnedTaskAbort::AlreadySettled);
        let polls_after_completion = controlled_state.polls.load(Ordering::Acquire);
        stale_waker.wake_by_ref();
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            controlled_state.polls.load(Ordering::Acquire),
            polls_after_completion
        );

        let stopped_state = Arc::new(ControlledState::default());
        let stopped = adapter
            .spawn(Box::pin(ControlledTask {
                state: Arc::clone(&stopped_state),
            }))
            .unwrap_or_else(|error| panic!("stopped task submission failed: {error:?}"));
        wait_for_count(&stopped_state.polls, 1).await;
        let first_abort = stopped.abort();
        let second_abort = stopped.abort();
        assert_eq!(first_abort.await, OwnedTaskAbort::Stopped);
        assert_eq!(second_abort.await, OwnedTaskAbort::Stopped);
        assert_eq!(stopped.abort().await, OwnedTaskAbort::AlreadySettled);
        assert_eq!(stopped.completion().await, OwnedTaskCompletion::Stopped);
        assert!(stopped_state.dropped.load(Ordering::Acquire));

        let panic_polled = Arc::new(AtomicBool::new(false));
        let panicked = adapter
            .spawn(Box::pin(PanicOnDropTask {
                polled: Arc::clone(&panic_polled),
            }))
            .unwrap_or_else(|error| panic!("panic task submission failed: {error:?}"));
        wait_for_bool(&panic_polled).await;
        assert_eq!(panicked.abort().await, OwnedTaskAbort::AlreadySettled);
        assert_eq!(
            panicked.completion().await,
            OwnedTaskCompletion::Panicked {
                origin: OwnedTaskPanicOrigin::Integration,
                protected_diagnostic: Some(Arc::from("protected-drop-panic")),
            }
        );

        let final_state = Arc::new(ControlledState::default());
        let final_handle = adapter
            .spawn(Box::pin(ControlledTask {
                state: Arc::clone(&final_state),
            }))
            .unwrap_or_else(|error| panic!("final-handle submission failed: {error:?}"));
        wait_for_count(&final_state.polls, 1).await;
        let final_stale_waker = lock(&final_state.waker)
            .as_ref()
            .cloned()
            .unwrap_or_else(|| panic!("final task did not retain its executor waker"));
        drop(final_handle);
        wait_for_bool(&final_state.dropped).await;
        let polls_after_drop = final_state.polls.load(Ordering::Acquire);
        final_stale_waker.wake_by_ref();
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(final_state.polls.load(Ordering::Acquire), polls_after_drop);
    });
}

async fn wait_for_count(counter: &AtomicUsize, minimum: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while counter.load(Ordering::Acquire) < minimum {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("counter did not reach {minimum}"));
}

async fn wait_for_bool(value: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !value.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("boolean observation did not become true"));
}

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    Pin::new(future).poll(&mut context)
}

fn assert_executor_failure(completion: OwnedTaskCompletion) {
    assert!(matches!(
        completion,
        OwnedTaskCompletion::Failed(HostError { ref code, .. })
            if code.as_ref() == "executor-failure"
    ));
}

fn current_thread_runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("current-thread runtime construction failed: {error}"))
}

fn multithread_runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("multithread runtime construction failed: {error}"))
}

fn block_on<F: Future>(future: F) -> F::Output {
    current_thread_runtime().block_on(future)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
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
