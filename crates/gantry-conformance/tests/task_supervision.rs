//! Public conformance for bounded executor-task supervision.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use gantry::host::contracts::{
    DurationMicros, ExecutorAdapter, HostError, HostFuture, InclusiveJitterRange, OwnedTaskAbort,
    OwnedTaskCompletion, OwnedTaskFuture, OwnedTaskPanic, OwnedTaskPanicOrigin, OwnedTaskResult,
    SubmittedTask,
};
use gantry::runtime::{
    AbnormalCompletionHandler, AdmissionClass, AdmissionResourceClass, AsyncAdmission,
    AsyncCapacityLimits, SupervisedTaskDomain, SupervisionSignal, TaskSupervisor,
};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use serde::Deserialize;

const ABNORMAL_EVIDENCE: &str = "crates/gantry-conformance/tests/task_supervision.rs#abnormal_completion_before_semantic_settlement_is_classified_once";
const ABORT_EVIDENCE: &str = "crates/gantry-conformance/tests/task_supervision.rs#abort_results_remain_distinct_from_physical_completion";
const OWNERSHIP_EVIDENCE: &str = "crates/gantry-conformance/tests/task_supervision.rs#control_shares_are_bounded_and_unclean_relinquish_is_nonsemantic";
const CONTROL_PLANE_EVIDENCE: &str = "crates/gantry-conformance/tests/task_supervision.rs#control_plane_capacity_remains_available_under_ordinary_saturation";
const SETTLEMENT_EVIDENCE: &str = "crates/gantry-conformance/tests/task_supervision.rs#semantic_settlement_retains_capacity_until_physical_reaping";

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

#[derive(Default)]
struct TaskControl {
    ready: AtomicBool,
    dropped: AtomicBool,
    polls: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

impl TaskControl {
    fn complete(&self) {
        self.ready.store(true, Ordering::Release);
        if let Some(waker) = lock(&self.waker).take() {
            waker.wake();
        }
    }
}

struct SignallingTask {
    control: Arc<TaskControl>,
    signal: Option<SupervisionSignal>,
}

impl Future for SignallingTask {
    type Output = OwnedTaskResult;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.control.polls.fetch_add(1, Ordering::AcqRel);
        if let Some(signal) = self.signal.take() {
            assert!(signal.settle());
        }
        if self.control.ready.load(Ordering::Acquire) {
            return Poll::Ready(OwnedTaskResult::new());
        }
        *lock(&self.control.waker) = Some(context.waker().clone());
        if self.control.ready.load(Ordering::Acquire) {
            Poll::Ready(OwnedTaskResult::new())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for SignallingTask {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::Release);
    }
}

struct ReentrantCloseTask {
    supervisor: TaskSupervisor,
}

impl Future for ReentrantCloseTask {
    type Output = OwnedTaskResult;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.supervisor.abort_and_relinquish_all();
        Poll::Ready(OwnedTaskResult::new())
    }
}

struct ImmediateExecutor;

impl ExecutorAdapter for ImmediateExecutor {
    fn spawn(&self, mut task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
        let mut context = Context::from_waker(Waker::noop());
        let Poll::Ready(result) = task.as_mut().poll(&mut context) else {
            panic!("immediate executor received a pending fixture")
        };
        Ok(Box::new(ImmediateSubmittedTask {
            completion: OwnedTaskCompletion::Completed(result),
        }))
    }

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

struct ImmediateSubmittedTask {
    completion: OwnedTaskCompletion,
}

impl SubmittedTask for ImmediateSubmittedTask {
    fn completion<'a>(&'a self) -> HostFuture<'a, OwnedTaskCompletion> {
        Box::pin(std::future::ready(self.completion.clone()))
    }

    fn abort<'a>(&'a self) -> HostFuture<'a, OwnedTaskAbort> {
        Box::pin(std::future::ready(OwnedTaskAbort::AlreadySettled))
    }
}

#[derive(Default)]
struct BlockingSpawnExecutor {
    state: Arc<BlockingSpawnState>,
}

#[derive(Default)]
struct BlockingSpawnState {
    task: Mutex<Option<OwnedTaskFuture>>,
    spawn_entered: Mutex<bool>,
    spawn_entered_wake: Condvar,
    spawn_released: Mutex<bool>,
    spawn_released_wake: Condvar,
    completion: Mutex<Option<OwnedTaskCompletion>>,
    completion_waiters: Mutex<Vec<Waker>>,
    abort_waiters: Mutex<Vec<Waker>>,
    abort_settled: AtomicBool,
    aborts: AtomicUsize,
}

impl BlockingSpawnExecutor {
    fn wait_until_spawn_entered(&self) {
        let mut entered = lock(&self.state.spawn_entered);
        while !*entered {
            entered = wait(&self.state.spawn_entered_wake, entered);
        }
    }

    fn release_spawn(&self) {
        *lock(&self.state.spawn_released) = true;
        self.state.spawn_released_wake.notify_all();
    }

    fn settle_abort(&self) {
        let task = lock(&self.state.task).take();
        drop(task);
        *lock(&self.state.completion) = Some(OwnedTaskCompletion::Stopped);
        self.state.abort_settled.store(true, Ordering::Release);
        for waiter in std::mem::take(&mut *lock(&self.state.abort_waiters)) {
            waiter.wake();
        }
        for waiter in std::mem::take(&mut *lock(&self.state.completion_waiters)) {
            waiter.wake();
        }
    }
}

impl ExecutorAdapter for BlockingSpawnExecutor {
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
        *lock(&self.state.task) = Some(task);
        *lock(&self.state.spawn_entered) = true;
        self.state.spawn_entered_wake.notify_all();
        let mut released = lock(&self.state.spawn_released);
        while !*released {
            released = wait(&self.state.spawn_released_wake, released);
        }
        Ok(Box::new(BlockingSubmittedTask {
            state: Arc::clone(&self.state),
        }))
    }

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

struct BlockingSubmittedTask {
    state: Arc<BlockingSpawnState>,
}

impl SubmittedTask for BlockingSubmittedTask {
    fn completion<'a>(&'a self) -> HostFuture<'a, OwnedTaskCompletion> {
        Box::pin(std::future::poll_fn(move |context| {
            if let Some(completion) = lock(&self.state.completion).clone() {
                Poll::Ready(completion)
            } else {
                let mut waiters = lock(&self.state.completion_waiters);
                if !waiters
                    .iter()
                    .any(|candidate| candidate.will_wake(context.waker()))
                {
                    waiters.push(context.waker().clone());
                }
                Poll::Pending
            }
        }))
    }

    fn abort<'a>(&'a self) -> HostFuture<'a, OwnedTaskAbort> {
        Box::pin(std::future::poll_fn(move |context| {
            if self.state.abort_settled.load(Ordering::Acquire) {
                return Poll::Ready(OwnedTaskAbort::Stopped);
            }
            if self
                .state
                .aborts
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let mut waiters = lock(&self.state.abort_waiters);
                if !waiters
                    .iter()
                    .any(|candidate| candidate.will_wake(context.waker()))
                {
                    waiters.push(context.waker().clone());
                }
            }
            Poll::Pending
        }))
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
fn checked_in_task_supervision_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/task-supervision-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.task-supervision-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-SUP-001");
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
            ABNORMAL_EVIDENCE,
            ABORT_EVIDENCE,
            OWNERSHIP_EVIDENCE,
            CONTROL_PLANE_EVIDENCE,
            SETTLEMENT_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-SUP-001")
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
    assert_eq!(declared.len(), 9);
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn semantic_settlement_retains_capacity_until_physical_reaping() {
    let (supervisor, executor, admission) = supervisor();
    let reservation = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("root reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
    let signal = registration.signal();
    let control = Arc::new(TaskControl::default());
    let task = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control: Arc::clone(&control),
                signal: Some(signal.clone()),
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("root submission failed: {error:?}"));

    let wakes = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wakes));
    assert!(
        supervisor
            .poll_quiescence(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(signal.is_settled());
    assert!(task.snapshot().semantic_settled);
    assert_eq!(task.snapshot().completion, None);
    assert_eq!(root_capacity_in_use(&admission), 1);

    control.complete();
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert_eq!(supervisor.active_count(SupervisedTaskDomain::Root), 0);
    assert_eq!(root_capacity_in_use(&admission), 0);
    assert_eq!(wakes.0.load(Ordering::Acquire), 1);
    assert_eq!(
        ready(task.completion()),
        OwnedTaskCompletion::Completed(OwnedTaskResult::new())
    );
    assert_eq!(
        ready(task.completion()),
        OwnedTaskCompletion::Completed(OwnedTaskResult::new())
    );
}

#[test]
fn immediate_completion_is_registered_and_reaped_once() {
    let executor: Arc<dyn ExecutorAdapter> = Arc::new(ImmediateExecutor);
    let limits = capacities();
    let admission = AsyncAdmission::new(limits);
    let supervisor = TaskSupervisor::new(executor, admission.clone());
    let reservation = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("root reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
    let signal = registration.signal();
    let control = Arc::new(TaskControl::default());
    control.complete();
    let task = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control,
                signal: Some(signal),
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("immediate submission failed: {error:?}"));

    assert_eq!(supervisor.active_count(SupervisedTaskDomain::Root), 0);
    assert_eq!(root_capacity_in_use(&admission), 0);
    assert!(task.snapshot().semantic_settled);
    assert_eq!(
        ready(task.completion()),
        OwnedTaskCompletion::Completed(OwnedTaskResult::new())
    );
}

#[test]
fn abnormal_completion_before_semantic_settlement_is_classified_once() {
    let (supervisor, executor, admission) = supervisor();
    let reservation = supervisor
        .try_reserve(AdmissionClass::SourceChildTask)
        .unwrap_or_else(|error| panic!("child reservation failed: {error}"));
    let completions = Arc::new(Mutex::new(Vec::new()));
    let callback_completions = Arc::clone(&completions);
    let abnormal: AbnormalCompletionHandler = Arc::new(move |completion| {
        lock(&callback_completions).push(completion);
    });
    let registration = supervisor.prepare(SupervisedTaskDomain::SourceChild, Some(abnormal));
    let control = Arc::new(TaskControl::default());
    let task = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control: Arc::clone(&control),
                signal: None,
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("child submission failed: {error:?}"));

    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    let stale_waker = lock(&control.waker)
        .as_ref()
        .cloned()
        .unwrap_or_else(|| panic!("pending child omitted its executor waker"));
    executor
        .fail_task(0)
        .unwrap_or_else(|error| panic!("executor failure injection failed: {error:?}"));

    let snapshot = task.snapshot();
    assert!(snapshot.abnormal_before_semantic);
    assert!(!snapshot.semantic_settled);
    assert_executor_failure(
        snapshot
            .completion
            .unwrap_or_else(|| panic!("physical completion was not retained")),
    );
    assert_eq!(lock(&completions).len(), 1);
    assert_eq!(child_capacity_in_use(&admission), 0);
    assert_eq!(
        supervisor.active_count(SupervisedTaskDomain::SourceChild),
        0
    );

    stale_waker.wake();
    assert_eq!(lock(&completions).len(), 1);
    assert_executor_failure(ready(task.completion()));

    let reservation = supervisor
        .try_reserve(AdmissionClass::SourceChildTask)
        .unwrap_or_else(|error| panic!("panic-child reservation failed: {error}"));
    let panic_completions = Arc::clone(&completions);
    let abnormal: AbnormalCompletionHandler = Arc::new(move |completion| {
        lock(&panic_completions).push(completion);
    });
    let registration = supervisor.prepare(SupervisedTaskDomain::SourceChild, Some(abnormal));
    let panicked = supervisor
        .submit(
            registration,
            Box::pin(async {
                std::panic::resume_unwind(Box::new(OwnedTaskPanic::new(
                    OwnedTaskPanicOrigin::Integration,
                    Some(Arc::from("protected-supervision-panic")),
                )))
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("panic-child submission failed: {error:?}"));
    assert!(matches!(
        executor.poll_task(1),
        Ok(DeterministicTaskPoll::Panicked {
            origin: OwnedTaskPanicOrigin::Integration,
            protected_diagnostic: Some(ref diagnostic),
        }) if diagnostic.as_ref() == "protected-supervision-panic"
    ));
    assert_eq!(lock(&completions).len(), 2);
    assert_eq!(
        ready(panicked.completion()),
        OwnedTaskCompletion::Panicked {
            origin: OwnedTaskPanicOrigin::Integration,
            protected_diagnostic: Some(Arc::from("protected-supervision-panic")),
        }
    );
    assert_eq!(child_capacity_in_use(&admission), 0);
}

#[test]
fn abort_results_remain_distinct_from_physical_completion() {
    let (supervisor, executor, admission) = supervisor();
    let reservation = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("root reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
    let signal = registration.signal();
    let control = Arc::new(TaskControl::default());
    let task = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control: Arc::clone(&control),
                signal: None,
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("root submission failed: {error:?}"));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    executor
        .fail_abort(0)
        .unwrap_or_else(|error| panic!("abort failure injection failed: {error:?}"));

    assert!(task.request_abort());
    let snapshot = task.snapshot();
    assert!(snapshot.abort_requested);
    assert!(matches!(
        snapshot.abort_result,
        Some(OwnedTaskAbort::Failed(HostError { ref code, .. }))
            if code.as_ref() == "executor-failure"
    ));
    assert_eq!(snapshot.completion, None);
    assert_eq!(root_capacity_in_use(&admission), 1);

    assert!(signal.settle());
    control.complete();
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let snapshot = task.snapshot();
    assert!(matches!(
        snapshot.abort_result,
        Some(OwnedTaskAbort::Failed(_))
    ));
    assert_eq!(
        snapshot.completion,
        Some(OwnedTaskCompletion::Completed(OwnedTaskResult::new()))
    );
    assert!(!snapshot.abnormal_before_semantic);
    assert_eq!(root_capacity_in_use(&admission), 0);
    assert!(!task.request_abort());

    let reservation = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("stopped-root reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
    let signal = registration.signal();
    let stopped = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control: Arc::new(TaskControl::default()),
                signal: None,
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("stopped-root submission failed: {error:?}"));
    assert_eq!(executor.poll_task(1), Ok(DeterministicTaskPoll::Pending));
    assert!(signal.settle());
    assert!(stopped.request_abort());
    let snapshot = stopped.snapshot();
    assert_eq!(snapshot.abort_result, Some(OwnedTaskAbort::Stopped));
    assert_eq!(snapshot.completion, Some(OwnedTaskCompletion::Stopped));
    assert!(!snapshot.abnormal_before_semantic);
    assert_eq!(root_capacity_in_use(&admission), 0);
    assert_eq!(executor.poll_task(1), Ok(DeterministicTaskPoll::Stopped));
}

#[test]
fn control_plane_capacity_remains_available_under_ordinary_saturation() {
    let (supervisor, executor, admission) = supervisor();
    let ordinary = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("ordinary reservation failed: {error}"));
    assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_err());

    let control_plane = supervisor
        .try_reserve_control_plane()
        .unwrap_or_else(|error| panic!("control-plane reservation failed: {error}"));
    assert!(supervisor.try_reserve_control_plane().is_err());
    let registration = supervisor.prepare(SupervisedTaskDomain::ControlPlane, None);
    let signal = registration.signal();
    let control = Arc::new(TaskControl::default());
    let cleanup = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control: Arc::clone(&control),
                signal: Some(signal),
            }),
            control_plane.transfer(),
        )
        .unwrap_or_else(|error| panic!("control-plane submission failed: {error:?}"));

    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert_eq!(root_capacity_in_use(&admission), 1);
    assert_eq!(control_plane_capacity_in_use(&admission), 1);
    control.complete();
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert_eq!(
        ready(cleanup.completion()),
        OwnedTaskCompletion::Completed(OwnedTaskResult::new())
    );
    assert_eq!(control_plane_capacity_in_use(&admission), 0);
    assert_eq!(root_capacity_in_use(&admission), 1);
    ordinary.rollback();
    assert_eq!(root_capacity_in_use(&admission), 0);
}

#[test]
fn close_racing_accepted_spawn_registers_and_aborts_before_releasing_capacity() {
    let executor = Arc::new(BlockingSpawnExecutor::default());
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor.clone();
    let admission = AsyncAdmission::new(capacities());
    let supervisor = TaskSupervisor::new(executor_adapter, admission.clone());
    let reservation = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("root reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
    let control = Arc::new(TaskControl::default());
    let submit_supervisor = supervisor.clone();
    let submit_control = Arc::clone(&control);
    let submission = thread::spawn(move || {
        submit_supervisor.submit(
            registration,
            Box::pin(SignallingTask {
                control: submit_control,
                signal: None,
            }),
            reservation.transfer(),
        )
    });

    executor.wait_until_spawn_entered();
    let close_finished = Arc::new(AtomicBool::new(false));
    let close_supervisor = supervisor.clone();
    let close_finished_signal = Arc::clone(&close_finished);
    let close = thread::spawn(move || {
        close_supervisor.abort_and_relinquish_all();
        close_finished_signal.store(true, Ordering::Release);
    });
    while !supervisor.snapshot().closed {
        thread::yield_now();
    }
    assert!(supervisor.snapshot().closed);
    close
        .join()
        .unwrap_or_else(|_| panic!("close thread panicked"));
    assert!(close_finished.load(Ordering::Acquire));
    assert_eq!(root_capacity_in_use(&admission), 1);
    assert!(!control.dropped.load(Ordering::Acquire));
    assert_eq!(executor.state.aborts.load(Ordering::Acquire), 0);

    executor.release_spawn();
    let result = submission
        .join()
        .unwrap_or_else(|_| panic!("submission thread panicked"));
    assert!(matches!(
        result,
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
    assert_eq!(executor.state.aborts.load(Ordering::Acquire), 1);
    assert!(!control.dropped.load(Ordering::Acquire));
    assert_eq!(root_capacity_in_use(&admission), 1);
    assert_eq!(supervisor.active_count(SupervisedTaskDomain::Root), 1);

    executor.settle_abort();
    assert!(control.dropped.load(Ordering::Acquire));
    assert_eq!(root_capacity_in_use(&admission), 0);
    assert_eq!(supervisor.active_count(SupervisedTaskDomain::Root), 0);
}

#[test]
fn immediate_executor_poll_can_reenter_close_during_spawn() {
    let executor: Arc<dyn ExecutorAdapter> = Arc::new(ImmediateExecutor);
    let admission = AsyncAdmission::new(capacities());
    let supervisor = TaskSupervisor::new(executor, admission.clone());
    let reservation = supervisor
        .try_reserve(AdmissionClass::RootTask)
        .unwrap_or_else(|error| panic!("root reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
    let submit_supervisor = supervisor.clone();
    let task_supervisor = supervisor.clone();
    let (finished, completion) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = submit_supervisor.submit(
            registration,
            Box::pin(ReentrantCloseTask {
                supervisor: task_supervisor,
            }),
            reservation.transfer(),
        );
        let _ = finished.send(result);
    });

    let result = completion
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("reentrant close deadlocked submission: {error}"));
    assert!(matches!(
        result,
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
    assert!(supervisor.snapshot().closed);
    assert_eq!(root_capacity_in_use(&admission), 0);
    assert_eq!(supervisor.active_count(SupervisedTaskDomain::Root), 0);
}

#[test]
fn control_shares_are_bounded_and_unclean_relinquish_is_nonsemantic() {
    let (supervisor, executor, admission) = supervisor();
    let reservation = supervisor
        .try_reserve(AdmissionClass::InterpreterBackgroundTask)
        .unwrap_or_else(|error| panic!("background reservation failed: {error}"));
    let callback_count = Arc::new(AtomicUsize::new(0));
    let abnormal_count = Arc::clone(&callback_count);
    let abnormal: AbnormalCompletionHandler = Arc::new(move |_| {
        abnormal_count.fetch_add(1, Ordering::AcqRel);
    });
    let registration =
        supervisor.prepare(SupervisedTaskDomain::InterpreterBackground, Some(abnormal));
    let control = Arc::new(TaskControl::default());
    let task = supervisor
        .submit(
            registration,
            Box::pin(SignallingTask {
                control: Arc::clone(&control),
                signal: None,
            }),
            reservation.transfer(),
        )
        .unwrap_or_else(|error| panic!("background submission failed: {error:?}"));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(!supervisor.snapshot().tasks[0].control_relinquished);

    let mut completion = Box::pin(task.completion());
    assert!(poll_once(completion.as_mut(), Waker::noop()).is_pending());
    drop(task);
    assert!(supervisor.snapshot().tasks[0].control_relinquished);
    supervisor.abort_and_relinquish_all();

    assert!(supervisor.snapshot().closed);
    assert!(supervisor.snapshot().tasks.is_empty());
    assert_eq!(background_capacity_in_use(&admission), 0);
    assert!(control.dropped.load(Ordering::Acquire));
    assert_eq!(callback_count.load(Ordering::Acquire), 0);
    assert_eq!(
        poll_once(completion.as_mut(), Waker::noop()),
        Poll::Ready(OwnedTaskCompletion::Stopped)
    );
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Stopped));

    let rejected = Arc::new(TaskControl::default());
    let control_plane = supervisor
        .try_reserve_control_plane()
        .unwrap_or_else(|error| panic!("control-plane reservation failed: {error}"));
    let registration = supervisor.prepare(SupervisedTaskDomain::ControlPlane, None);
    let result = supervisor.submit(
        registration,
        Box::pin(SignallingTask {
            control: Arc::clone(&rejected),
            signal: None,
        }),
        control_plane.transfer(),
    );
    assert!(matches!(
        result,
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
    assert!(rejected.dropped.load(Ordering::Acquire));
}

fn supervisor() -> (
    TaskSupervisor,
    Arc<DeterministicConcurrentExecutor>,
    AsyncAdmission,
) {
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor.clone();
    let limits = capacities();
    let admission = AsyncAdmission::new(limits);
    (
        TaskSupervisor::new(executor_adapter, admission.clone()),
        executor,
        admission,
    )
}

fn root_capacity_in_use(admission: &AsyncAdmission) -> u64 {
    in_use(admission, AdmissionClass::RootTask)
}

fn child_capacity_in_use(admission: &AsyncAdmission) -> u64 {
    in_use(admission, AdmissionClass::SourceChildTask)
}

fn background_capacity_in_use(admission: &AsyncAdmission) -> u64 {
    in_use(admission, AdmissionClass::InterpreterBackgroundTask)
}

fn control_plane_capacity_in_use(admission: &AsyncAdmission) -> u64 {
    admission
        .snapshot()
        .in_use(AdmissionResourceClass::ControlPlaneTask)
}

fn in_use(admission: &AsyncAdmission, class: AdmissionClass) -> u64 {
    admission
        .snapshot()
        .in_use(AdmissionResourceClass::Ordinary(class))
}

fn capacities() -> AsyncCapacityLimits {
    AsyncCapacityLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1)
        .unwrap_or_else(|error| panic!("capacity fixture failed: {error}"))
}

fn assert_executor_failure(completion: OwnedTaskCompletion) {
    assert!(matches!(
        completion,
        OwnedTaskCompletion::Failed(HostError { ref code, .. })
            if code.as_ref() == "executor-failure"
    ));
}

fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match poll_once(future.as_mut(), Waker::noop()) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future unexpectedly remained pending"),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait<'a, T>(condition: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condition
        .wait(guard)
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
