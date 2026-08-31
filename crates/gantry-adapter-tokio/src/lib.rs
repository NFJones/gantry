//! Tokio implementation of Gantry's base executor-neutral services.
//!
//! The adapter retains a caller-owned runtime handle and never constructs or
//! shuts down a Tokio runtime. Tokio types remain confined to this leaf crate.

use std::future::Future;
#[cfg(feature = "concurrent")]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "concurrent")]
use std::sync::{Mutex, MutexGuard};
#[cfg(feature = "concurrent")]
use std::task::Waker;
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(feature = "concurrent")]
use gantry_host::contracts::{
    ConcurrentExecutorAdapter, EmbeddingVersion, HostResponse, OwnedTaskFuture, OwnedTaskResult,
    SubmittedTask,
};
use gantry_host::contracts::{
    DurationMicros, ExecutorAdapter, HostError, HostFuture, InclusiveJitterRange, JitterSource,
};
#[cfg(feature = "concurrent")]
use gantry_host::embedding::EmbeddingOperation;
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

#[cfg(feature = "concurrent")]
impl ConcurrentExecutorAdapter for TokioExecutor {
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
}

#[cfg(feature = "concurrent")]
struct TokioSubmittedTask {
    state: Arc<Mutex<SubmittedTaskState>>,
}

#[cfg(feature = "concurrent")]
impl SubmittedTask for TokioSubmittedTask {
    fn join<'a>(&'a self) -> HostFuture<'a, Result<OwnedTaskResult, HostError>> {
        Box::pin(std::future::poll_fn(move |context| {
            let mut state = lock_submitted(&self.state);
            match &state.settlement {
                SubmittedTaskSettlement::Running => {
                    register_waker(&mut state.waiters, context.waker());
                    Poll::Pending
                }
                SubmittedTaskSettlement::Completed(result) => Poll::Ready(result.clone()),
                SubmittedTaskSettlement::Stopped => Poll::Ready(Err(executor_failure_code())),
            }
        }))
    }

    fn abort<'a>(&'a self) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(std::future::poll_fn(move |context| {
            let executor_waker = {
                let mut state = lock_submitted(&self.state);
                match &state.settlement {
                    SubmittedTaskSettlement::Running => {
                        state.stop_requested = true;
                        register_waker(&mut state.waiters, context.waker());
                        state.executor_waker.take()
                    }
                    SubmittedTaskSettlement::Completed(_) => {
                        return Poll::Ready(abort_response("already-settled"));
                    }
                    SubmittedTaskSettlement::Stopped => {
                        let result = if state.stop_reported {
                            "already-settled"
                        } else {
                            state.stop_reported = true;
                            "stopped"
                        };
                        return Poll::Ready(abort_response(result));
                    }
                }
            };
            if let Some(waker) = executor_waker {
                waker.wake();
            }
            Poll::Pending
        }))
    }
}

#[cfg(feature = "concurrent")]
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

#[cfg(feature = "concurrent")]
struct ManagedTaskFuture {
    task: Option<OwnedTaskFuture>,
    state: Arc<Mutex<SubmittedTaskState>>,
}

#[cfg(feature = "concurrent")]
impl Future for ManagedTaskFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        {
            let mut state = lock_submitted(&self.state);
            if state.stop_requested {
                drop(state);
                let task = self.task.take();
                let _ = catch_unwind(AssertUnwindSafe(|| drop(task)));
                complete_submitted(&self.state, SubmittedTaskSettlement::Stopped);
                return Poll::Ready(());
            }
            state.executor_waker = Some(context.waker().clone());
        }

        let Some(task) = self.task.as_mut() else {
            complete_submitted(
                &self.state,
                SubmittedTaskSettlement::Completed(Err(executor_failure_code())),
            );
            return Poll::Ready(());
        };
        match catch_unwind(AssertUnwindSafe(|| task.as_mut().poll(context))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(result)) => {
                let task = self.task.take();
                if catch_unwind(AssertUnwindSafe(|| drop(task))).is_err() {
                    complete_submitted(
                        &self.state,
                        SubmittedTaskSettlement::Completed(Err(executor_failure_code())),
                    );
                    return Poll::Ready(());
                }
                complete_submitted(&self.state, SubmittedTaskSettlement::Completed(Ok(result)));
                Poll::Ready(())
            }
            Err(_) => {
                let task = self.task.take();
                let _ = catch_unwind(AssertUnwindSafe(|| drop(task)));
                complete_submitted(
                    &self.state,
                    SubmittedTaskSettlement::Completed(Err(executor_failure_code())),
                );
                Poll::Ready(())
            }
        }
    }
}

#[cfg(feature = "concurrent")]
impl Drop for ManagedTaskFuture {
    fn drop(&mut self) {
        let running = matches!(
            lock_submitted(&self.state).settlement,
            SubmittedTaskSettlement::Running
        );
        if running {
            let task = self.task.take();
            let _ = catch_unwind(AssertUnwindSafe(|| drop(task)));
            complete_submitted(
                &self.state,
                SubmittedTaskSettlement::Completed(Err(executor_failure_code())),
            );
        }
    }
}

#[cfg(feature = "concurrent")]
#[derive(Default)]
struct SubmittedTaskState {
    settlement: SubmittedTaskSettlement,
    stop_requested: bool,
    stop_reported: bool,
    executor_waker: Option<Waker>,
    waiters: Vec<Waker>,
}

#[cfg(feature = "concurrent")]
#[derive(Default)]
enum SubmittedTaskSettlement {
    #[default]
    Running,
    Completed(Result<OwnedTaskResult, HostError>),
    Stopped,
}

#[cfg(feature = "concurrent")]
fn complete_submitted(state: &Mutex<SubmittedTaskState>, settlement: SubmittedTaskSettlement) {
    let waiters = {
        let mut state = lock_submitted(state);
        if !matches!(state.settlement, SubmittedTaskSettlement::Running) {
            return;
        }
        state.settlement = settlement;
        state.executor_waker = None;
        std::mem::take(&mut state.waiters)
    };
    for waiter in waiters {
        waiter.wake();
    }
}

#[cfg(feature = "concurrent")]
fn lock_submitted(state: &Mutex<SubmittedTaskState>) -> MutexGuard<'_, SubmittedTaskState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(feature = "concurrent")]
fn register_waker(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|candidate| candidate.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

#[cfg(feature = "concurrent")]
fn abort_response(result: &str) -> Result<HostResponse, HostError> {
    HostResponse::new(
        EmbeddingVersion::V1,
        EmbeddingOperation::AbortTask,
        Arc::from(format!("{{\"result\":\"{result}\"}}").into_bytes()),
    )
    .map_err(|_| executor_failure_code())
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

    use gantry_host::contracts::{
        CancellationSignal, DeadlineOutcome, DurationMicros, ExecutorAdapter, HostError,
        InclusiveJitterRange, JitterSource, deadline_race,
    };
    #[cfg(feature = "concurrent")]
    use gantry_host::contracts::{ConcurrentExecutorAdapter, OwnedTaskResult};
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

    #[cfg(feature = "concurrent")]
    struct SubmittedUntilDrop {
        dropped: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
    }

    #[cfg(feature = "concurrent")]
    impl Future for SubmittedUntilDrop {
        type Output = OwnedTaskResult;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            Poll::Pending
        }
    }

    #[cfg(feature = "concurrent")]
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

            #[cfg(feature = "concurrent")]
            exercise_task_services(&adapter).await;
        });
    }

    #[cfg(feature = "concurrent")]
    async fn exercise_task_services(adapter: &TokioExecutor) {
        let expected = OwnedTaskResult {
            canonical_bytes: Arc::from(b"{\"result\":\"settled\"}".as_slice()),
        };
        let settled = adapter
            .spawn(Box::pin({
                let expected = expected.clone();
                async move { expected }
            }))
            .unwrap_or_else(|error| panic!("task submission failed: {error:?}"));
        assert_eq!(settled.join().await, Ok(expected.clone()));
        assert_eq!(settled.join().await, Ok(expected));
        let after_settlement = settled
            .abort()
            .await
            .unwrap_or_else(|error| panic!("settled abort failed: {error:?}"));
        assert_eq!(
            after_settlement.canonical_bytes(),
            b"{\"result\":\"already-settled\"}"
        );

        let dropped = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let pending = adapter
            .spawn(Box::pin(SubmittedUntilDrop {
                dropped: Arc::clone(&dropped),
                polls: Arc::clone(&polls),
            }))
            .unwrap_or_else(|error| panic!("pending task submission failed: {error:?}"));
        for _ in 0..1_000 {
            if polls.load(Ordering::Acquire) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(polls.load(Ordering::Acquire) > 0);
        let stopped = pending
            .abort()
            .await
            .unwrap_or_else(|error| panic!("pending task abort failed: {error:?}"));
        assert_eq!(stopped.canonical_bytes(), b"{\"result\":\"stopped\"}");
        assert!(dropped.load(Ordering::Acquire));
        let polls_after_stop = polls.load(Ordering::Acquire);
        tokio::task::yield_now().await;
        assert_eq!(polls.load(Ordering::Acquire), polls_after_stop);
        let repeated = pending
            .abort()
            .await
            .unwrap_or_else(|error| panic!("repeated abort failed: {error:?}"));
        assert_eq!(
            repeated.canonical_bytes(),
            b"{\"result\":\"already-settled\"}"
        );
        assert!(matches!(
            pending.join().await,
            Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
        ));

        let panicked = adapter
            .spawn(Box::pin(async {
                panic!("task panic fixture");
            }))
            .unwrap_or_else(|error| panic!("panic task submission failed: {error:?}"));
        assert!(matches!(
            panicked.join().await,
            Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
        ));
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
