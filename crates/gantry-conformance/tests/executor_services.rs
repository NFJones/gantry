//! Public contract coverage for executor-neutral services and the Tokio adapter.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use gantry::host::contracts::{
    CancellationSignal, DeadlineOutcome, DurationMicros, ExecutorAdapter, HostError, HostFuture,
    InclusiveJitterRange, JitterSource, OwnedTaskAbort, OwnedTaskCompletion, OwnedTaskPanic,
    OwnedTaskPanicOrigin, OwnedTaskResult, deadline_race,
};
use gantry_adapter_tokio::TokioExecutor;
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::services::DeterministicExecutor;
use serde::Deserialize;
use tokio::runtime::Builder;

const CONTRACT_EVIDENCE: &str = "crates/gantry-conformance/tests/executor_services.rs#executor_contract_bounds_and_failures_are_exact";
const ADAPTER_EVIDENCE: &str = "crates/gantry-conformance/tests/executor_services.rs#caller_owned_tokio_runtimes_preserve_completion_first_and_drop_losers";
const TASK_EVIDENCE: &str = "crates/gantry-conformance/tests/executor_services.rs#deterministic_task_service_preserves_every_physical_outcome";

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
struct ExecutorVectors {
    format: String,
    duration_minimum_micros: u64,
    duration_maximum_micros: u64,
    inclusive_jitter_range: [u64; 2],
    deadline_outcomes: Vec<String>,
    task_abort_outcomes: Vec<String>,
    task_completion_outcomes: Vec<String>,
    executor_failure_code: String,
    caller_owned_runtime_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

#[derive(Debug)]
struct FixedJitter {
    sample: u64,
}

impl JitterSource for FixedJitter {
    fn sample_inclusive(&self, _: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(self.sample)
    }
}

#[derive(Debug)]
struct FailingTimer;

impl ExecutorAdapter for FailingTimer {
    fn spawn(
        &self,
        task: gantry::host::contracts::OwnedTaskFuture,
    ) -> Result<Box<dyn gantry::host::contracts::SubmittedTask>, HostError> {
        gantry::host::contracts::reject_task_submission(task)
    }

    fn sleep<'a>(&'a self, _: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async {
            Err(HostError {
                code: Arc::from("executor-failure"),
                protected_diagnostic: None,
            })
        })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

struct PendingUntilDrop {
    dropped: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
}

impl Future for PendingUntilDrop {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::AcqRel);
        Poll::Pending
    }
}

impl Drop for PendingUntilDrop {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

struct PendingOwnedTask {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingOwnedTask {
    type Output = OwnedTaskResult;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingOwnedTask {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
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

#[test]
fn checked_in_executor_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/executor-services-v1.json"));
    let vectors: ExecutorVectors =
        read_json(&root.join("protocol/goldens/executor-services-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/executor-services-v1.schema.json"));

    assert_eq!(manifest.format, "gantry.executor-services-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-EXEC-001");
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
        vec![CONTRACT_EVIDENCE, ADAPTER_EVIDENCE, TASK_EVIDENCE]
    );
    assert_eq!(manifest.exclusions.len(), 4);

    assert_eq!(vectors.format, "gantry.executor-service-vectors/v1");
    assert_eq!(vectors.duration_minimum_micros, 0);
    assert_eq!(vectors.duration_maximum_micros, DurationMicros::MAXIMUM);
    assert_eq!(vectors.inclusive_jitter_range, [2, 7]);
    assert_eq!(
        vectors.deadline_outcomes,
        ["completed", "cancelled", "timed-out", "failed"]
    );
    assert_eq!(
        vectors.task_abort_outcomes,
        ["already-settled", "failed", "stopped"]
    );
    assert_eq!(
        vectors.task_completion_outcomes,
        ["completed", "failed", "panicked", "stopped"]
    );
    assert_eq!(vectors.executor_failure_code, "executor-failure");
    assert_eq!(
        vectors.caller_owned_runtime_kinds,
        ["current-thread", "multi-thread"]
    );
    assert_eq!(
        schema["$id"],
        "https://gantry.invalid/protocol/executor-services/v1/schema.json"
    );
    assert_eq!(
        schema["properties"]["duration_maximum_micros"]["maximum"],
        DurationMicros::MAXIMUM
    );
}

#[test]
fn executor_contract_bounds_and_failures_are_exact() {
    assert_eq!(DurationMicros::new(0).map(DurationMicros::get), Some(0));
    assert_eq!(
        DurationMicros::new(DurationMicros::MAXIMUM).map(DurationMicros::get),
        Some(DurationMicros::MAXIMUM)
    );
    assert_eq!(DurationMicros::new(DurationMicros::MAXIMUM + 1), None);
    assert!(InclusiveJitterRange::new(7, 2).is_none());
    assert!(InclusiveJitterRange::new(0, DurationMicros::MAXIMUM + 1).is_none());

    let zero = DurationMicros::new(0).unwrap_or_else(|| unreachable!("zero is admitted"));
    let outcome = block_on(deadline_race(
        &FailingTimer,
        Box::pin(std::future::pending::<u64>()),
        zero,
        None,
    ));
    assert!(matches!(
        outcome,
        DeadlineOutcome::Failed(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));

    let scripted = DeterministicExecutor::new([Ok(())], [Ok(7)]);
    assert_eq!(block_on(scripted.sleep(zero)), Ok(()));
    assert_eq!(block_on(scripted.yield_now()), Ok(()));
    let range =
        InclusiveJitterRange::new(2, 7).unwrap_or_else(|| unreachable!("fixture range is valid"));
    assert_eq!(scripted.sample_inclusive(range), Ok(7));
    assert_eq!(scripted.sleeps(), [zero]);
    assert_eq!(scripted.yields(), 1);

    let cancellation = CancellationSignal::default();
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    let mut waiter = cancellation.cancelled();
    assert!(matches!(waiter.as_mut().poll(&mut context), Poll::Pending));
    assert!(cancellation.cancel());
    assert_eq!(counter.wakes.load(Ordering::Acquire), 1);
    assert!(matches!(
        waiter.as_mut().poll(&mut context),
        Poll::Ready(())
    ));
    assert!(!cancellation.cancel());
}

#[test]
fn deterministic_task_service_preserves_every_physical_outcome() {
    let executor = DeterministicConcurrentExecutor::default();
    let acknowledgement = OwnedTaskResult::new();

    let completed = executor
        .spawn(Box::pin(async move { acknowledgement }))
        .unwrap_or_else(|error| panic!("completion submission failed: {error:?}"));
    assert_eq!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(acknowledgement))
    );
    assert_eq!(
        block_on(completed.completion()),
        OwnedTaskCompletion::Completed(acknowledgement)
    );
    assert_eq!(
        block_on(completed.completion()),
        OwnedTaskCompletion::Completed(acknowledgement)
    );
    assert_eq!(block_on(completed.abort()), OwnedTaskAbort::AlreadySettled);

    let stopped_drop = Arc::new(AtomicBool::new(false));
    let stopped = executor
        .spawn(Box::pin(PendingOwnedTask {
            dropped: Arc::clone(&stopped_drop),
        }))
        .unwrap_or_else(|error| panic!("stop submission failed: {error:?}"));
    assert_eq!(executor.poll_task(1), Ok(DeterministicTaskPoll::Pending));
    assert_eq!(block_on(stopped.abort()), OwnedTaskAbort::Stopped);
    assert!(stopped_drop.load(Ordering::Acquire));
    assert_eq!(block_on(stopped.completion()), OwnedTaskCompletion::Stopped);
    assert_eq!(block_on(stopped.abort()), OwnedTaskAbort::AlreadySettled);

    let integration_panic = executor
        .spawn(Box::pin(async {
            std::panic::resume_unwind(Box::new(OwnedTaskPanic::new(
                OwnedTaskPanicOrigin::Integration,
                Some(Arc::from("protected-panic")),
            )))
        }))
        .unwrap_or_else(|error| panic!("panic submission failed: {error:?}"));
    let expected_panic = OwnedTaskCompletion::Panicked {
        origin: OwnedTaskPanicOrigin::Integration,
        protected_diagnostic: Some(Arc::from("protected-panic")),
    };
    assert_eq!(
        executor.poll_task(2),
        Ok(DeterministicTaskPoll::Panicked {
            origin: OwnedTaskPanicOrigin::Integration,
            protected_diagnostic: Some(Arc::from("protected-panic")),
        })
    );
    assert_eq!(block_on(integration_panic.completion()), expected_panic);

    let failed_drop = Arc::new(AtomicBool::new(false));
    let failed = executor
        .spawn(Box::pin(PendingOwnedTask {
            dropped: Arc::clone(&failed_drop),
        }))
        .unwrap_or_else(|error| panic!("failure submission failed: {error:?}"));
    assert_eq!(executor.fail_task(3), Ok(()));
    assert!(failed_drop.load(Ordering::Acquire));
    assert!(matches!(
        block_on(failed.completion()),
        OwnedTaskCompletion::Failed(HostError { ref code, .. })
            if code.as_ref() == "executor-failure"
    ));

    let abort_failed = executor
        .spawn(Box::pin(std::future::pending::<OwnedTaskResult>()))
        .unwrap_or_else(|error| panic!("abort-failure submission failed: {error:?}"));
    assert_eq!(executor.fail_abort(4), Ok(()));
    for result in [
        block_on(abort_failed.abort()),
        block_on(abort_failed.abort()),
    ] {
        assert!(matches!(
            result,
            OwnedTaskAbort::Failed(HostError { ref code, .. })
                if code.as_ref() == "executor-failure"
        ));
    }
    drop(abort_failed);

    let rejected_drop = Arc::new(AtomicBool::new(false));
    executor.fail_next_spawn();
    assert!(
        executor
            .spawn(Box::pin(PendingOwnedTask {
                dropped: Arc::clone(&rejected_drop),
            }))
            .is_err()
    );
    assert!(rejected_drop.load(Ordering::Acquire));

    let final_drop = Arc::new(AtomicBool::new(false));
    let final_handle = executor
        .spawn(Box::pin(PendingOwnedTask {
            dropped: Arc::clone(&final_drop),
        }))
        .unwrap_or_else(|error| panic!("final-handle submission failed: {error:?}"));
    drop(final_handle);
    assert!(final_drop.load(Ordering::Acquire));
    assert_eq!(executor.poll_task(5), Ok(DeterministicTaskPoll::Stopped));
}

#[test]
fn caller_owned_tokio_runtimes_preserve_completion_first_and_drop_losers() {
    for runtime in [
        Builder::new_current_thread().enable_time().build(),
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build(),
    ] {
        let runtime =
            runtime.unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
        exercise_runtime(runtime);
    }
}

fn exercise_runtime(runtime: tokio::runtime::Runtime) {
    let range =
        InclusiveJitterRange::new(2, 7).unwrap_or_else(|| unreachable!("fixture range is valid"));
    let adapter = TokioExecutor::new(
        runtime.handle().clone(),
        Arc::new(FixedJitter { sample: 7 }),
    );
    runtime.block_on(async {
        let zero = DurationMicros::new(0).unwrap_or_else(|| unreachable!("zero is admitted"));
        assert_eq!(adapter.sleep(zero).await, Ok(()));
        assert_eq!(adapter.yield_now().await, Ok(()));
        assert_eq!(adapter.sample_inclusive(range), Ok(7));

        let cancellation = CancellationSignal::default();
        assert!(cancellation.cancel());
        assert!(!cancellation.cancel());
        let completed = deadline_race(
            &adapter,
            Box::pin(async { 42_u64 }),
            zero,
            Some(&cancellation),
        )
        .await;
        assert_eq!(completed, DeadlineOutcome::Completed(42));

        let dropped = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let timed_out = deadline_race(
            &adapter,
            Box::pin(PendingUntilDrop {
                dropped: Arc::clone(&dropped),
                polls: Arc::clone(&polls),
            }),
            zero,
            None,
        )
        .await;
        assert_eq!(timed_out, DeadlineOutcome::TimedOut);
        assert!(dropped.load(Ordering::Acquire));
        let polls_after_timeout = polls.load(Ordering::Acquire);
        tokio::task::yield_now().await;
        assert_eq!(polls.load(Ordering::Acquire), polls_after_timeout);

        let dropped = Arc::new(AtomicBool::new(false));
        let cancelled = deadline_race(
            &adapter,
            Box::pin(PendingUntilDrop {
                dropped: Arc::clone(&dropped),
                polls: Arc::new(AtomicUsize::new(0)),
            }),
            DurationMicros::new(1_000_000)
                .unwrap_or_else(|| unreachable!("fixture duration is admitted")),
            Some(&cancellation),
        )
        .await;
        assert_eq!(cancelled, DeadlineOutcome::Cancelled);
        assert!(dropped.load(Ordering::Acquire));
    });

    let invalid = TokioExecutor::new(
        runtime.handle().clone(),
        Arc::new(FixedJitter { sample: 8 }),
    );
    assert!(matches!(
        invalid.sample_inclusive(range),
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
}

fn block_on<F: Future>(future: F) -> F::Output {
    let runtime = Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
    runtime.block_on(future)
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
