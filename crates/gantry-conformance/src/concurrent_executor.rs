//! Deterministic executor-neutral task scheduling for bounded conformance exploration.
//!
//! The harness polls only explicitly selected runnable tasks. It supports
//! repeatable joins, idempotent abort, injected submission failure, and stale
//! wake observation without defining Gantry's portable scheduling order.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Wake, Waker};

use gantry::host::contracts::{
    ConcurrentExecutorAdapter, DurationMicros, EmbeddingVersion, ExecutorAdapter, HostError,
    HostFuture, HostResponse, InclusiveJitterRange, OwnedTaskFuture, OwnedTaskResult,
    SubmittedTask,
};
use gantry::host::embedding::EmbeddingOperation;

/// Result of one explicit deterministic task poll.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeterministicTaskPoll {
    /// The task remained pending and must wake itself before another legal poll.
    Pending,
    /// The task is pending but has not made itself runnable.
    NotRunnable,
    /// The task completed with its exact executor-neutral result.
    Settled(OwnedTaskResult),
    /// A confirmed abort removed the task future.
    Stopped,
    /// Task polling or destruction failed at the executor boundary.
    Failed(HostError),
}

/// Explicitly driven concurrent executor for deterministic schedule replay.
#[derive(Default)]
pub struct DeterministicConcurrentExecutor {
    tasks: Mutex<Vec<Arc<Mutex<DeterministicTaskState>>>>,
    fail_next_spawn: AtomicBool,
    yields: AtomicU64,
}

impl std::fmt::Debug for DeterministicConcurrentExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeterministicConcurrentExecutor")
            .field("task_count", &self.task_ids().len())
            .finish_non_exhaustive()
    }
}

impl DeterministicConcurrentExecutor {
    /// Makes the next submission fail with `executor-failure`.
    pub fn fail_next_spawn(&self) {
        self.fail_next_spawn.store(true, Ordering::Release);
    }

    /// Returns all zero-based harness task identities in creation order.
    #[must_use]
    pub fn task_ids(&self) -> Vec<u64> {
        let tasks = lock(&self.tasks);
        (0..tasks.len())
            .filter_map(|index| u64::try_from(index).ok())
            .collect()
    }

    /// Returns the number of polls performed for one task.
    #[must_use]
    pub fn poll_count(&self, task_id: u64) -> Option<u64> {
        self.task(task_id).map(|task| lock(&task).polls)
    }

    /// Returns the number of wakes observed for one task, including stale wakes.
    #[must_use]
    pub fn wake_count(&self, task_id: u64) -> Option<u64> {
        self.task(task_id).map(|task| lock(&task).wakes)
    }

    /// Returns whether one unsettled task is currently eligible for polling.
    #[must_use]
    pub fn is_runnable(&self, task_id: u64) -> bool {
        self.task(task_id).is_some_and(|task| {
            let task = lock(&task);
            matches!(task.settlement, DeterministicSettlement::Running) && task.runnable
        })
    }

    /// Polls exactly one selected runnable task once.
    pub fn poll_task(&self, task_id: u64) -> Result<DeterministicTaskPoll, HostError> {
        let task = self.task(task_id).ok_or_else(executor_failure)?;
        let mut future = Some({
            let mut state = lock(&task);
            match &state.settlement {
                DeterministicSettlement::Completed(Ok(result)) => {
                    return Ok(DeterministicTaskPoll::Settled(result.clone()));
                }
                DeterministicSettlement::Completed(Err(error)) => {
                    return Ok(DeterministicTaskPoll::Failed(error.clone()));
                }
                DeterministicSettlement::Stopped => return Ok(DeterministicTaskPoll::Stopped),
                DeterministicSettlement::Running if !state.runnable => {
                    return Ok(DeterministicTaskPoll::NotRunnable);
                }
                DeterministicSettlement::Running => {}
            }
            state.runnable = false;
            state.polls = state.polls.saturating_add(1);
            state.future.take().ok_or_else(executor_failure)?
        });

        let waker = Waker::from(Arc::new(DeterministicWake {
            task: Arc::downgrade(&task),
        }));
        let mut context = Context::from_waker(&waker);
        let polled = catch_unwind(AssertUnwindSafe(|| {
            future
                .as_mut()
                .unwrap_or_else(|| unreachable!("task future is present while polling"))
                .as_mut()
                .poll(&mut context)
        }));
        let polled = match polled {
            Ok(Poll::Ready(result)) => {
                if catch_unwind(AssertUnwindSafe(|| drop(future.take()))).is_err() {
                    Err(())
                } else {
                    Ok(Poll::Ready(result))
                }
            }
            Ok(Poll::Pending) => Ok(Poll::Pending),
            Err(_) => {
                let _ = catch_unwind(AssertUnwindSafe(|| drop(future.take())));
                Err(())
            }
        };
        let (poll, waiters) = {
            let mut state = lock(&task);
            if !matches!(state.settlement, DeterministicSettlement::Running) {
                (poll_from_settlement(&state.settlement), Vec::new())
            } else {
                match polled {
                    Ok(Poll::Pending) => {
                        state.future = future.take();
                        (DeterministicTaskPoll::Pending, Vec::new())
                    }
                    Ok(Poll::Ready(result)) => {
                        state.settlement = DeterministicSettlement::Completed(Ok(result.clone()));
                        let waiters = std::mem::take(&mut state.waiters);
                        (DeterministicTaskPoll::Settled(result), waiters)
                    }
                    Err(_) => {
                        let error = executor_failure();
                        state.settlement = DeterministicSettlement::Completed(Err(error.clone()));
                        let waiters = std::mem::take(&mut state.waiters);
                        (DeterministicTaskPoll::Failed(error), waiters)
                    }
                }
            }
        };
        wake_all(waiters);
        Ok(poll)
    }

    fn task(&self, task_id: u64) -> Option<Arc<Mutex<DeterministicTaskState>>> {
        usize::try_from(task_id)
            .ok()
            .and_then(|index| lock(&self.tasks).get(index).cloned())
    }
}

impl ExecutorAdapter for DeterministicConcurrentExecutor {
    fn sleep<'a>(&'a self, _duration: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        self.yields.fetch_add(1, Ordering::AcqRel);
        Box::pin(async { Ok(()) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

impl ConcurrentExecutorAdapter for DeterministicConcurrentExecutor {
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
        if self.fail_next_spawn.swap(false, Ordering::AcqRel) {
            return Err(executor_failure());
        }
        let state = Arc::new(Mutex::new(DeterministicTaskState {
            future: Some(task),
            settlement: DeterministicSettlement::Running,
            runnable: true,
            polls: 0,
            wakes: 0,
            waiters: Vec::new(),
        }));
        lock(&self.tasks).push(Arc::clone(&state));
        Ok(Box::new(DeterministicSubmittedTask { state }))
    }
}

struct DeterministicSubmittedTask {
    state: Arc<Mutex<DeterministicTaskState>>,
}

impl SubmittedTask for DeterministicSubmittedTask {
    fn join<'a>(&'a self) -> HostFuture<'a, Result<OwnedTaskResult, HostError>> {
        Box::pin(std::future::poll_fn(move |context| {
            let mut state = lock(&self.state);
            match &state.settlement {
                DeterministicSettlement::Running => {
                    register_waker(&mut state.waiters, context.waker());
                    Poll::Pending
                }
                DeterministicSettlement::Completed(result) => Poll::Ready(result.clone()),
                DeterministicSettlement::Stopped => Poll::Ready(Err(executor_failure())),
            }
        }))
    }

    fn abort<'a>(&'a self) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let (result, future, waiters) = {
            let mut state = lock(&self.state);
            match state.settlement {
                DeterministicSettlement::Running => {
                    state.settlement = DeterministicSettlement::Stopped;
                    state.runnable = false;
                    (
                        "stopped",
                        state.future.take(),
                        std::mem::take(&mut state.waiters),
                    )
                }
                DeterministicSettlement::Completed(_) | DeterministicSettlement::Stopped => {
                    ("already-settled", None, Vec::new())
                }
            }
        };
        if catch_unwind(AssertUnwindSafe(|| drop(future))).is_err() {
            return Box::pin(async { Err(executor_failure()) });
        }
        wake_all(waiters);
        Box::pin(async move { abort_response(result) })
    }
}

impl Drop for DeterministicSubmittedTask {
    fn drop(&mut self) {
        let (future, waiters) = {
            let mut state = lock(&self.state);
            if !matches!(state.settlement, DeterministicSettlement::Running) {
                return;
            }
            state.settlement = DeterministicSettlement::Stopped;
            state.runnable = false;
            (state.future.take(), std::mem::take(&mut state.waiters))
        };
        let _ = catch_unwind(AssertUnwindSafe(|| drop(future)));
        wake_all(waiters);
    }
}

struct DeterministicTaskState {
    future: Option<OwnedTaskFuture>,
    settlement: DeterministicSettlement,
    runnable: bool,
    polls: u64,
    wakes: u64,
    waiters: Vec<Waker>,
}

enum DeterministicSettlement {
    Running,
    Completed(Result<OwnedTaskResult, HostError>),
    Stopped,
}

struct DeterministicWake {
    task: Weak<Mutex<DeterministicTaskState>>,
}

impl Wake for DeterministicWake {
    fn wake(self: Arc<Self>) {
        self.mark_runnable();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.mark_runnable();
    }
}

impl DeterministicWake {
    fn mark_runnable(&self) {
        if let Some(task) = self.task.upgrade() {
            let mut task = lock(&task);
            if matches!(task.settlement, DeterministicSettlement::Running) {
                task.wakes = task.wakes.saturating_add(1);
                task.runnable = true;
            }
        }
    }
}

fn poll_from_settlement(settlement: &DeterministicSettlement) -> DeterministicTaskPoll {
    match settlement {
        DeterministicSettlement::Running => DeterministicTaskPoll::Pending,
        DeterministicSettlement::Completed(Ok(result)) => {
            DeterministicTaskPoll::Settled(result.clone())
        }
        DeterministicSettlement::Completed(Err(error)) => {
            DeterministicTaskPoll::Failed(error.clone())
        }
        DeterministicSettlement::Stopped => DeterministicTaskPoll::Stopped,
    }
}

fn register_waker(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|candidate| candidate.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

fn wake_all(waiters: Vec<Waker>) {
    for waiter in waiters {
        waiter.wake();
    }
}

fn abort_response(result: &str) -> Result<HostResponse, HostError> {
    HostResponse::new(
        EmbeddingVersion::V1,
        EmbeddingOperation::AbortTask,
        Arc::from(format!("{{\"result\":\"{result}\"}}").into_bytes()),
    )
    .map_err(|_| executor_failure())
}

fn executor_failure() -> HostError {
    HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
