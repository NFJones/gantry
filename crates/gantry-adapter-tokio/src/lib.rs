//! Tokio implementation of Gantry's base executor-neutral services.
//!
//! The adapter retains a caller-owned runtime handle and never constructs or
//! shuts down a Tokio runtime. Tokio types remain confined to this leaf crate.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use gantry_host::contracts::{
    DurationMicros, ExecutorAdapter, HostError, HostFuture, InclusiveJitterRange, JitterSource,
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use gantry_host::contracts::{
        CancellationSignal, DeadlineOutcome, DurationMicros, ExecutorAdapter, HostError,
        InclusiveJitterRange, JitterSource, deadline_race,
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
        });
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
