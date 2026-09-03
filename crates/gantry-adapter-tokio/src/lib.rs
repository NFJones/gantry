//! Tokio implementation of Gantry's base executor-neutral services.
//!
//! The adapter retains a caller-owned runtime handle and never constructs or
//! shuts down a Tokio runtime. Tokio types remain confined to this leaf crate.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};
use std::task::Waker;
use std::task::{Context, Poll};
use std::time::Duration;

use gantry_host::contracts::{
    DurationMicros, ExecutorAdapter, HostError, HostFuture, InclusiveJitterRange, JitterSource,
    OwnedTaskAbort, OwnedTaskCompletion, OwnedTaskFuture, OwnedTaskPanic, OwnedTaskPanicOrigin,
    SubmittedTask,
};
use tokio::runtime::Handle;
use tokio::task::{JoinError, JoinHandle};

/// Base Tokio services over one caller-owned runtime handle.
pub struct TokioExecutor {
    handle: Handle,
    jitter: Arc<dyn JitterSource>,
}

impl std::fmt::Debug for TokioExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokioExecutor")
            .finish_non_exhaustive()
    }
}

impl TokioExecutor {
    /// Binds the adapter to an existing runtime and injected jitter source.
    #[must_use]
    pub fn new(handle: Handle, jitter: Arc<dyn JitterSource>) -> Self {
        Self { handle, jitter }
    }
}

impl ExecutorAdapter for TokioExecutor {
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
        let state = Arc::new(Mutex::new(SubmittedTaskState::default()));
        let managed = ManagedTaskFuture {
            task: Some(task),
            state: Arc::clone(&state),
        };
        catch_unwind(AssertUnwindSafe(|| self.handle.spawn(managed)))
            .map_err(|_| executor_failure_code())?;
        Ok(Box::new(TokioSubmittedTask { state }))
    }

    fn sleep<'a>(&'a self, duration: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        let task = self.handle.spawn(async move {
            tokio::time::sleep(Duration::from_micros(duration.get())).await;
        });
        Box::pin(async move { AbortOnDrop::new(task).await.map_err(executor_failure) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        let task = self.handle.spawn(async move {
            tokio::task::yield_now().await;
        });
        Box::pin(async move { AbortOnDrop::new(task).await.map_err(executor_failure) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        let sample = self.jitter.sample_inclusive(range)?;
        if sample < range.minimum() || sample > range.maximum() {
            return Err(executor_failure_code());
        }
        Ok(sample)
    }
}

struct TokioSubmittedTask {
    state: Arc<Mutex<SubmittedTaskState>>,
}

impl SubmittedTask for TokioSubmittedTask {
    fn completion<'a>(&'a self) -> HostFuture<'a, OwnedTaskCompletion> {
        Box::pin(std::future::poll_fn(move |context| {
            let mut state = lock_submitted(&self.state);
            match &state.settlement {
                SubmittedTaskSettlement::Running => {
                    register_waker(&mut state.waiters, context.waker());
                    Poll::Pending
                }
                SubmittedTaskSettlement::Settled(result) => Poll::Ready(result.clone()),
            }
        }))
    }

    fn abort<'a>(&'a self) -> HostFuture<'a, OwnedTaskAbort> {
        let executor_waker = {
            let mut state = lock_submitted(&self.state);
            if !matches!(state.settlement, SubmittedTaskSettlement::Running) {
                return Box::pin(std::future::ready(OwnedTaskAbort::AlreadySettled));
            }
            state.stop_requested = true;
            state.executor_waker.take()
        };
        if let Some(waker) = executor_waker {
            waker.wake();
        }
        Box::pin(std::future::poll_fn(move |context| {
            let mut state = lock_submitted(&self.state);
            if let Some(result) = &state.abort_result {
                return Poll::Ready(result.clone());
            }
            register_waker(&mut state.waiters, context.waker());
            Poll::Pending
        }))
    }
}

impl Drop for TokioSubmittedTask {
    fn drop(&mut self) {
        let executor_waker = {
            let mut state = lock_submitted(&self.state);
            if !matches!(state.settlement, SubmittedTaskSettlement::Running) {
                return;
            }
            state.stop_requested = true;
            state.executor_waker.take()
        };
        if let Some(waker) = executor_waker {
            waker.wake();
        }
    }
}

struct ManagedTaskFuture {
    task: Option<OwnedTaskFuture>,
    state: Arc<Mutex<SubmittedTaskState>>,
}

impl Future for ManagedTaskFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        {
            let mut state = lock_submitted(&self.state);
            if state.stop_requested {
                drop(state);
                let task = self.task.take();
                let completion = match catch_unwind(AssertUnwindSafe(|| drop(task))) {
                    Ok(()) => OwnedTaskCompletion::Stopped,
                    Err(payload) => completion_from_panic(payload),
                };
                complete_submitted(&self.state, SubmittedTaskSettlement::Settled(completion));
                return Poll::Ready(());
            }
            state.executor_waker = Some(context.waker().clone());
        }

        let Some(task) = self.task.as_mut() else {
            complete_submitted(
                &self.state,
                SubmittedTaskSettlement::Settled(OwnedTaskCompletion::Failed(
                    executor_failure_code(),
                )),
            );
            return Poll::Ready(());
        };
        match catch_unwind(AssertUnwindSafe(|| task.as_mut().poll(context))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(result)) => {
                let task = self.task.take();
                if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(task))) {
                    complete_submitted(
                        &self.state,
                        SubmittedTaskSettlement::Settled(completion_from_panic(payload)),
                    );
                    return Poll::Ready(());
                }
                complete_submitted(
                    &self.state,
                    SubmittedTaskSettlement::Settled(OwnedTaskCompletion::Completed(result)),
                );
                Poll::Ready(())
            }
            Err(payload) => {
                let task = self.task.take();
                let _ = catch_unwind(AssertUnwindSafe(|| drop(task)));
                complete_submitted(
                    &self.state,
                    SubmittedTaskSettlement::Settled(completion_from_panic(payload)),
                );
                Poll::Ready(())
            }
        }
    }
}

impl Drop for ManagedTaskFuture {
    fn drop(&mut self) {
        let running = matches!(
            lock_submitted(&self.state).settlement,
            SubmittedTaskSettlement::Running
        );
        if running {
            let task = self.task.take();
            let completion = match catch_unwind(AssertUnwindSafe(|| drop(task))) {
                Ok(()) => OwnedTaskCompletion::Failed(executor_failure_code()),
                Err(payload) => completion_from_panic(payload),
            };
            complete_submitted(&self.state, SubmittedTaskSettlement::Settled(completion));
        }
    }
}

#[derive(Default)]
struct SubmittedTaskState {
    settlement: SubmittedTaskSettlement,
    stop_requested: bool,
    abort_result: Option<OwnedTaskAbort>,
    executor_waker: Option<Waker>,
    waiters: Vec<Waker>,
}

#[derive(Default)]
enum SubmittedTaskSettlement {
    #[default]
    Running,
    Settled(OwnedTaskCompletion),
}

fn complete_submitted(state: &Mutex<SubmittedTaskState>, settlement: SubmittedTaskSettlement) {
    let waiters = {
        let mut state = lock_submitted(state);
        if !matches!(state.settlement, SubmittedTaskSettlement::Running) {
            return;
        }
        if state.stop_requested && state.abort_result.is_none() {
            let result = match &settlement {
                SubmittedTaskSettlement::Running => unreachable!("completion is terminal"),
                SubmittedTaskSettlement::Settled(OwnedTaskCompletion::Stopped) => {
                    OwnedTaskAbort::Stopped
                }
                SubmittedTaskSettlement::Settled(OwnedTaskCompletion::Failed(error)) => {
                    OwnedTaskAbort::Failed(error.clone())
                }
                SubmittedTaskSettlement::Settled(
                    OwnedTaskCompletion::Completed(_) | OwnedTaskCompletion::Panicked { .. },
                ) => OwnedTaskAbort::AlreadySettled,
            };
            state.abort_result = Some(result);
        }
        state.settlement = settlement;
        state.executor_waker = None;
        std::mem::take(&mut state.waiters)
    };
    for waiter in waiters {
        waiter.wake();
    }
}

fn lock_submitted(state: &Mutex<SubmittedTaskState>) -> MutexGuard<'_, SubmittedTaskState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn register_waker(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|candidate| candidate.will_wake(waker)) {
        waiters.push(waker.clone());
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

struct AbortOnDrop<T> {
    task: JoinHandle<T>,
}

impl<T> AbortOnDrop<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task }
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(context)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn executor_failure(_: JoinError) -> HostError {
    executor_failure_code()
}

fn executor_failure_code() -> HostError {
    HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use gantry_host::contracts::{
        CancellationSignal, DeadlineOutcome, DurationMicros, ExecutorAdapter, HostError,
        InclusiveJitterRange, JitterSource, deadline_race,
    };
    use gantry_host::contracts::{
        OwnedTaskAbort, OwnedTaskCompletion, OwnedTaskPanicOrigin, OwnedTaskResult,
    };
    use tokio::runtime::Builder;

    use super::TokioExecutor;

    #[derive(Debug)]
    struct FixedJitter;

    impl JitterSource for FixedJitter {
        fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
            Ok(range.maximum())
        }
    }

    struct PendingUntilDrop {
        dropped: Arc<AtomicBool>,
    }

    impl Future for PendingUntilDrop {
        type Output = u64;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingUntilDrop {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct SubmittedUntilDrop {
        dropped: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
    }

    impl Future for SubmittedUntilDrop {
        type Output = OwnedTaskResult;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            Poll::Pending
        }
    }

    impl Drop for SubmittedUntilDrop {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    fn exercise(runtime: tokio::runtime::Runtime) {
        let adapter = TokioExecutor::new(runtime.handle().clone(), Arc::new(FixedJitter));
        runtime.block_on(async {
            let zero =
                DurationMicros::new(0).unwrap_or_else(|| unreachable!("zero duration is admitted"));
            assert_eq!(adapter.sleep(zero).await, Ok(()));
            assert_eq!(adapter.yield_now().await, Ok(()));
            let range = InclusiveJitterRange::new(2, 7)
                .unwrap_or_else(|| unreachable!("fixture range is valid"));
            assert_eq!(adapter.sample_inclusive(range), Ok(7));

            let completed = deadline_race(&adapter, Box::pin(async { 7_u64 }), zero, None).await;
            assert_eq!(completed, DeadlineOutcome::Completed(7));

            let dropped = Arc::new(AtomicBool::new(false));
            let pending = PendingUntilDrop {
                dropped: Arc::clone(&dropped),
            };
            let timed_out = deadline_race(&adapter, Box::pin(pending), zero, None).await;
            assert_eq!(timed_out, DeadlineOutcome::TimedOut);
            assert!(dropped.load(Ordering::Acquire));

            let cancellation = CancellationSignal::default();
            assert!(cancellation.cancel());
            let cancelled = deadline_race(
                &adapter,
                Box::pin(std::future::pending::<u64>()),
                DurationMicros::new(1_000_000)
                    .unwrap_or_else(|| unreachable!("fixture duration is admitted")),
                Some(&cancellation),
            )
            .await;
            assert_eq!(cancelled, DeadlineOutcome::Cancelled);

            exercise_task_services(&adapter).await;
        });
    }

    async fn exercise_task_services(adapter: &TokioExecutor) {
        let expected = OwnedTaskResult::new();
        let settled = adapter
            .spawn(Box::pin(async move { expected }))
            .unwrap_or_else(|error| panic!("task submission failed: {error:?}"));
        assert_eq!(
            settled.completion().await,
            OwnedTaskCompletion::Completed(expected)
        );
        assert_eq!(
            settled.completion().await,
            OwnedTaskCompletion::Completed(expected)
        );
        assert_eq!(settled.abort().await, OwnedTaskAbort::AlreadySettled);

        let dropped = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let pending = adapter
            .spawn(Box::pin(SubmittedUntilDrop {
                dropped: Arc::clone(&dropped),
                polls: Arc::clone(&polls),
            }))
            .unwrap_or_else(|error| panic!("pending task submission failed: {error:?}"));
        let first_poll = tokio::time::timeout(Duration::from_secs(5), async {
            while polls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            first_poll.is_ok(),
            "spawned task was not polled before deadline"
        );
        assert_eq!(pending.abort().await, OwnedTaskAbort::Stopped);
        assert!(dropped.load(Ordering::Acquire));
        let polls_after_stop = polls.load(Ordering::Acquire);
        tokio::task::yield_now().await;
        assert_eq!(polls.load(Ordering::Acquire), polls_after_stop);
        assert_eq!(pending.abort().await, OwnedTaskAbort::AlreadySettled);
        assert_eq!(pending.completion().await, OwnedTaskCompletion::Stopped);

        let panicked = adapter
            .spawn(Box::pin(async {
                panic!("task panic fixture");
            }))
            .unwrap_or_else(|error| panic!("panic task submission failed: {error:?}"));
        assert_eq!(
            panicked.completion().await,
            OwnedTaskCompletion::Panicked {
                origin: OwnedTaskPanicOrigin::GantryInvariant,
                protected_diagnostic: None,
            }
        );
    }

    #[test]
    fn caller_owned_current_thread_runtime_substitutes() {
        let runtime = Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
        exercise(runtime);
    }

    #[test]
    fn caller_owned_multithread_runtime_substitutes() {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
        exercise(runtime);
    }
}
