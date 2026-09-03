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
    DurationMicros, ExecutorAdapter, HostError, HostFuture, InclusiveJitterRange, OwnedTaskAbort,
    OwnedTaskCompletion, OwnedTaskFuture, OwnedTaskPanic, OwnedTaskPanicOrigin, OwnedTaskResult,
    SubmittedTask,
};

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
    /// Task polling or destruction panicked at a classified boundary.
    Panicked {
        /// Boundary that originated the panic.
        origin: OwnedTaskPanicOrigin,
        /// Optional stable key for protected diagnostic bytes.
        protected_diagnostic: Option<Arc<str>>,
    },
    /// Task polling or destruction failed at the executor boundary.
    Failed(HostError),
}

/// Explicitly driven concurrent executor for deterministic schedule replay.
#[derive(Default)]
pub struct DeterministicConcurrentExecutor {
    tasks: Mutex<Vec<Arc<Mutex<DeterministicTaskState>>>>,
    fail_next_spawn: AtomicBool,
    yields: AtomicU64,
    next_yield_failure: Mutex<Option<HostError>>,
    next_yield_cancellation: Mutex<Option<gantry::host::contracts::CancellationSignal>>,
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

    /// Makes the next cooperative yield fail with the supplied executor error.
    pub fn fail_next_yield(&self, error: HostError) {
        *lock(&self.next_yield_failure) = Some(error);
    }

    /// Makes the next cooperative yield publish one Gantry cancellation signal.
    pub fn cancel_on_next_yield(&self, signal: gantry::host::contracts::CancellationSignal) {
        *lock(&self.next_yield_cancellation) = Some(signal);
    }

    /// Makes the next abort request for one running task fail immutably.
    pub fn fail_abort(&self, task_id: u64) -> Result<(), HostError> {
        let task = self.task(task_id).ok_or_else(executor_failure)?;
        let mut task = lock(&task);
        if !matches!(task.settlement, DeterministicSettlement::Running)
            || task.abort_result.is_some()
        {
            return Err(executor_failure());
        }
        task.fail_abort = true;
        Ok(())
    }

    /// Settles one running task with an injected executor-internal failure.
    pub fn fail_task(&self, task_id: u64) -> Result<(), HostError> {
        let task = self.task(task_id).ok_or_else(executor_failure)?;
        let (future, waiters) = {
            let mut state = lock(&task);
            if !matches!(state.settlement, DeterministicSettlement::Running) {
                return Err(executor_failure());
            }
            state.runnable = false;
            (state.future.take(), std::mem::take(&mut state.waiters))
        };
        let completion = match catch_unwind(AssertUnwindSafe(|| drop(future))) {
            Ok(()) => OwnedTaskCompletion::Failed(executor_failure()),
            Err(payload) => completion_from_panic(payload),
        };
        lock(&task).settlement = DeterministicSettlement::Settled(completion);
        wake_all(waiters);
        Ok(())
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

    /// Returns the number of cooperative executor yields requested by tasks.
    #[must_use]
    pub fn yields(&self) -> u64 {
        self.yields.load(Ordering::Acquire)
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
                DeterministicSettlement::Settled(completion) => {
                    return Ok(poll_from_completion(completion));
                }
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
                match catch_unwind(AssertUnwindSafe(|| drop(future.take()))) {
                    Ok(()) => Ok(Poll::Ready(result)),
                    Err(payload) => Err(payload),
                }
            }
            Ok(Poll::Pending) => Ok(Poll::Pending),
            Err(payload) => {
                let _ = catch_unwind(AssertUnwindSafe(|| drop(future.take())));
                Err(payload)
            }
        };
        let (poll, waiters) = {
            let mut state = lock(&task);
            if !matches!(state.settlement, DeterministicSettlement::Running) {
                let DeterministicSettlement::Settled(completion) = &state.settlement else {
                    unreachable!("checked above")
                };
                (poll_from_completion(completion), Vec::new())
            } else {
                match polled {
                    Ok(Poll::Pending) => {
                        state.future = future.take();
                        (DeterministicTaskPoll::Pending, Vec::new())
                    }
                    Ok(Poll::Ready(result)) => {
                        state.settlement = DeterministicSettlement::Settled(
                            OwnedTaskCompletion::Completed(result),
                        );
                        let waiters = std::mem::take(&mut state.waiters);
                        (DeterministicTaskPoll::Settled(result), waiters)
                    }
                    Err(payload) => {
                        let completion = completion_from_panic(payload);
                        let poll = poll_from_completion(&completion);
                        state.settlement = DeterministicSettlement::Settled(completion);
                        let waiters = std::mem::take(&mut state.waiters);
                        (poll, waiters)
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
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
        if self.fail_next_spawn.swap(false, Ordering::AcqRel) {
            let _ = catch_unwind(AssertUnwindSafe(|| drop(task)));
            return Err(executor_failure());
        }
        let state = Arc::new(Mutex::new(DeterministicTaskState {
            future: Some(task),
            settlement: DeterministicSettlement::Running,
            abort_result: None,
            fail_abort: false,
            runnable: true,
            polls: 0,
            wakes: 0,
            waiters: Vec::new(),
        }));
        lock(&self.tasks).push(Arc::clone(&state));
        Ok(Box::new(DeterministicSubmittedTask { state }))
    }

    fn sleep<'a>(&'a self, _duration: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        self.yields.fetch_add(1, Ordering::AcqRel);
        if let Some(signal) = lock(&self.next_yield_cancellation).take() {
            signal.cancel();
        }
        let result = lock(&self.next_yield_failure).take().map_or(Ok(()), Err);
        Box::pin(async move { result })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

struct DeterministicSubmittedTask {
    state: Arc<Mutex<DeterministicTaskState>>,
}

impl SubmittedTask for DeterministicSubmittedTask {
    fn completion<'a>(&'a self) -> HostFuture<'a, OwnedTaskCompletion> {
        Box::pin(std::future::poll_fn(move |context| {
            let mut state = lock(&self.state);
            match &state.settlement {
                DeterministicSettlement::Running => {
                    register_waker(&mut state.waiters, context.waker());
                    Poll::Pending
                }
                DeterministicSettlement::Settled(completion) => Poll::Ready(completion.clone()),
            }
        }))
    }

    fn abort<'a>(&'a self) -> HostFuture<'a, OwnedTaskAbort> {
        let (result, future, waiters) = {
            let mut state = lock(&self.state);
            match state.settlement {
                DeterministicSettlement::Running => {
                    if let Some(result) = &state.abort_result {
                        return Box::pin(std::future::ready(result.clone()));
                    }
                    if state.fail_abort {
                        let result = OwnedTaskAbort::Failed(executor_failure());
                        state.abort_result = Some(result.clone());
                        return Box::pin(std::future::ready(result));
                    }
                    state.runnable = false;
                    (
                        OwnedTaskAbort::Stopped,
                        state.future.take(),
                        std::mem::take(&mut state.waiters),
                    )
                }
                DeterministicSettlement::Settled(_) => {
                    (OwnedTaskAbort::AlreadySettled, None, Vec::new())
                }
            }
        };
        let (completion, result) = match catch_unwind(AssertUnwindSafe(|| drop(future))) {
            Ok(()) if result == OwnedTaskAbort::Stopped => {
                (Some(OwnedTaskCompletion::Stopped), result)
            }
            Ok(()) => (None, result),
            Err(payload) => (
                Some(completion_from_panic(payload)),
                OwnedTaskAbort::Failed(executor_failure()),
            ),
        };
        {
            let mut state = lock(&self.state);
            if let Some(completion) = completion {
                state.settlement = DeterministicSettlement::Settled(completion);
            }
            state.abort_result = Some(result.clone());
        }
        wake_all(waiters);
        Box::pin(std::future::ready(result))
    }
}

impl Drop for DeterministicSubmittedTask {
    fn drop(&mut self) {
        let (future, waiters) = {
            let mut state = lock(&self.state);
            if !matches!(state.settlement, DeterministicSettlement::Running) {
                return;
            }
            state.runnable = false;
            (state.future.take(), std::mem::take(&mut state.waiters))
        };
        let completion = match catch_unwind(AssertUnwindSafe(|| drop(future))) {
            Ok(()) => OwnedTaskCompletion::Stopped,
            Err(payload) => completion_from_panic(payload),
        };
        lock(&self.state).settlement = DeterministicSettlement::Settled(completion);
        wake_all(waiters);
    }
}

struct DeterministicTaskState {
    future: Option<OwnedTaskFuture>,
    settlement: DeterministicSettlement,
    abort_result: Option<OwnedTaskAbort>,
    fail_abort: bool,
    runnable: bool,
    polls: u64,
    wakes: u64,
    waiters: Vec<Waker>,
}

enum DeterministicSettlement {
    Running,
    Settled(OwnedTaskCompletion),
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

fn poll_from_completion(completion: &OwnedTaskCompletion) -> DeterministicTaskPoll {
    match completion {
        OwnedTaskCompletion::Completed(result) => DeterministicTaskPoll::Settled(*result),
        OwnedTaskCompletion::Stopped => DeterministicTaskPoll::Stopped,
        OwnedTaskCompletion::Panicked {
            origin,
            protected_diagnostic,
        } => DeterministicTaskPoll::Panicked {
            origin: *origin,
            protected_diagnostic: protected_diagnostic.clone(),
        },
        OwnedTaskCompletion::Failed(error) => DeterministicTaskPoll::Failed(error.clone()),
    }
}

fn completion_from_panic(payload: Box<dyn std::any::Any + Send>) -> OwnedTaskCompletion {
    if let Some(panic) = payload.downcast_ref::<OwnedTaskPanic>() {
        return OwnedTaskCompletion::Panicked {
            origin: panic.origin(),
            protected_diagnostic: panic.protected_diagnostic().cloned(),
        };
    }
    OwnedTaskCompletion::Panicked {
        origin: OwnedTaskPanicOrigin::GantryInvariant,
        protected_diagnostic: None,
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
