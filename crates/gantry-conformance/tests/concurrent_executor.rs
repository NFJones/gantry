//! Public adapter and bounded deterministic-schedule evidence for concurrent execution.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use gantry::host::contracts::{
    ConcurrentExecutorAdapter, HostError, JitterSource, OwnedTaskResult,
};
use gantry::portable::ExecutorAbortResultKind;
use gantry_adapter_tokio::TokioExecutor;
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use serde::Deserialize;
use tokio::runtime::Builder;

const MODEL_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_executor.rs#bounded_schedules_and_failure_replays_are_deterministic";
const ADAPTER_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_executor.rs#caller_owned_tokio_task_services_are_executor_neutral_and_terminal";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    model: String,
    model_evidence: String,
    adapter_evidence: String,
    reviewed_clauses: Vec<ReviewedClauseLink>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct ReviewedClauseLink {
    requirement: String,
    clause: String,
    profile: String,
    evidence: Vec<String>,
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

#[derive(Debug, Deserialize)]
struct ConcurrentExecutorModel {
    format: String,
    maximum_tasks: usize,
    polls_per_task: usize,
    maximum_consecutive_polls: usize,
    explored_schedule_count: usize,
    assumptions: Vec<String>,
    schedules: Vec<Vec<String>>,
    replay_cases: Vec<ReplayCase>,
}

#[derive(Debug, Deserialize)]
struct ReplayCase {
    id: String,
    actions: Vec<String>,
    invariant: String,
}

#[derive(Debug)]
struct FixedJitter;

impl JitterSource for FixedJitter {
    fn sample_inclusive(
        &self,
        range: gantry::host::contracts::InclusiveJitterRange,
    ) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

struct YieldingTask {
    remaining_yields: usize,
    result: &'static [u8],
}

impl Future for YieldingTask {
    type Output = OwnedTaskResult;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.remaining_yields == 0 {
            return Poll::Ready(task_result(self.result));
        }
        self.remaining_yields -= 1;
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

struct LateWakeTask {
    polls: Arc<AtomicU64>,
    retained_waker: Arc<Mutex<Option<Waker>>>,
}

impl Future for LateWakeTask {
    type Output = OwnedTaskResult;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::AcqRel);
        *self
            .retained_waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(context.waker().clone());
        Poll::Pending
    }
}

#[test]
fn reviewed_concurrent_executor_evidence_is_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/concurrent-executor-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.concurrent-executor-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-CON-004");
    assert_eq!(manifest.model_evidence, MODEL_EVIDENCE);
    assert_eq!(manifest.adapter_evidence, ADAPTER_EVIDENCE);
    assert!(root.join(&manifest.model).is_file());
    assert!(
        manifest
            .reviewed_clauses
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(manifest.exclusions.len() >= 3);

    for link in &manifest.reviewed_clauses {
        let profile = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == link.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == link.clause)
            })
            .and_then(|clause| {
                clause
                    .profile_reviews
                    .iter()
                    .find(|profile| profile.profile == link.profile)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing {}:{} {} review",
                    link.requirement, link.clause, link.profile
                )
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, link.evidence);
    }
}

#[test]
fn caller_owned_tokio_task_services_are_executor_neutral_and_terminal() {
    for runtime in [
        Builder::new_current_thread().enable_time().build(),
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build(),
    ] {
        let runtime =
            runtime.unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
        let adapter = TokioExecutor::new(runtime.handle().clone(), Arc::new(FixedJitter));
        runtime.block_on(async {
            let completed = adapter
                .spawn(Box::pin(async { task_result(b"completed") }))
                .unwrap_or_else(|error| panic!("task submission failed: {error:?}"));
            assert_eq!(completed.join().await, Ok(task_result(b"completed")));
            assert_eq!(completed.join().await, Ok(task_result(b"completed")));
            assert_eq!(
                abort_kind(completed.abort().await),
                ExecutorAbortResultKind::AlreadySettled
            );

            let polls = Arc::new(AtomicU64::new(0));
            let retained_waker = Arc::new(Mutex::new(None));
            let pending = adapter
                .spawn(Box::pin(LateWakeTask {
                    polls: Arc::clone(&polls),
                    retained_waker: Arc::clone(&retained_waker),
                }))
                .unwrap_or_else(|error| panic!("pending submission failed: {error:?}"));
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
            assert_eq!(
                abort_kind(pending.abort().await),
                ExecutorAbortResultKind::Stopped
            );
            let polls_after_abort = polls.load(Ordering::Acquire);
            retained_waker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_else(|| panic!("pending task retained no waker"))
                .wake();
            tokio::task::yield_now().await;
            assert_eq!(polls.load(Ordering::Acquire), polls_after_abort);
            assert_eq!(
                abort_kind(pending.abort().await),
                ExecutorAbortResultKind::AlreadySettled
            );
            assert!(matches!(
                pending.join().await,
                Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
            ));
        });
    }
}

#[test]
fn bounded_schedules_and_failure_replays_are_deterministic() {
    let root = workspace_root();
    let model: ConcurrentExecutorModel =
        read_json(&root.join("protocol/goldens/concurrent-executor-model-v1.json"));
    assert_eq!(model.format, "gantry.concurrent-executor-model/v1");
    assert_eq!(model.maximum_tasks, 2);
    assert_eq!(model.polls_per_task, 3);
    assert_eq!(model.maximum_consecutive_polls, 2);
    assert!(!model.assumptions.is_empty());
    assert!(
        model
            .assumptions
            .iter()
            .any(|value| value.contains("not an unbounded proof"))
    );

    let generated = fair_schedules(model.polls_per_task, model.maximum_consecutive_polls);
    assert_eq!(model.schedules, generated);
    assert_eq!(model.explored_schedule_count, generated.len());
    assert_eq!(generated.len(), 14);
    for schedule in &generated {
        replay_fair_schedule(schedule);
    }

    let ids = model
        .replay_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    for case in &model.replay_cases {
        assert!(!case.actions.is_empty());
        assert!(!case.invariant.is_empty());
        match case.id.as_str() {
            "abort-late-wake" => replay_abort_late_wake(),
            "sibling-failure-isolation" => replay_sibling_failure(),
            "submission-failure" => replay_submission_failure(),
            other => panic!("unknown replay case {other}"),
        }
    }
}

fn replay_fair_schedule(schedule: &[String]) {
    let executor = DeterministicConcurrentExecutor::default();
    let first = executor
        .spawn(Box::pin(YieldingTask {
            remaining_yields: 2,
            result: b"first",
        }))
        .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
    let second = executor
        .spawn(Box::pin(YieldingTask {
            remaining_yields: 2,
            result: b"second",
        }))
        .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));

    for task in schedule {
        let task_id = match task.as_str() {
            "a" => 0,
            "b" => 1,
            other => panic!("unknown schedule task {other}"),
        };
        assert!(executor.is_runnable(task_id));
        let poll = executor
            .poll_task(task_id)
            .unwrap_or_else(|error| panic!("scheduled poll failed: {error:?}"));
        assert!(matches!(
            poll,
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::Settled(_)
        ));
    }
    assert_eq!(executor.poll_count(0), Some(3));
    assert_eq!(executor.poll_count(1), Some(3));
    assert_eq!(executor.wake_count(0), Some(2));
    assert_eq!(executor.wake_count(1), Some(2));
    assert_eq!(ready(first.join()), Ok(task_result(b"first")));
    assert_eq!(ready(second.join()), Ok(task_result(b"second")));
}

fn replay_abort_late_wake() {
    let executor = DeterministicConcurrentExecutor::default();
    let polls = Arc::new(AtomicU64::new(0));
    let retained_waker = Arc::new(Mutex::new(None));
    let handle = executor
        .spawn(Box::pin(LateWakeTask {
            polls: Arc::clone(&polls),
            retained_waker: Arc::clone(&retained_waker),
        }))
        .unwrap_or_else(|error| panic!("late-wake submission failed: {error:?}"));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    assert!(!executor.is_runnable(0));
    assert_eq!(
        abort_kind(ready(handle.abort())),
        ExecutorAbortResultKind::Stopped
    );
    retained_waker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .unwrap_or_else(|| panic!("late-wake task retained no waker"))
        .wake();
    assert!(!executor.is_runnable(0));
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Stopped));
    assert_eq!(polls.load(Ordering::Acquire), 1);
    assert_eq!(executor.poll_count(0), Some(1));
    assert_eq!(
        abort_kind(ready(handle.abort())),
        ExecutorAbortResultKind::AlreadySettled
    );
}

fn replay_sibling_failure() {
    let executor = DeterministicConcurrentExecutor::default();
    let failed = executor
        .spawn(Box::pin(async { panic!("deterministic sibling failure") }))
        .unwrap_or_else(|error| panic!("failing sibling submission failed: {error:?}"));
    let healthy = executor
        .spawn(Box::pin(async { task_result(b"healthy") }))
        .unwrap_or_else(|error| panic!("healthy sibling submission failed: {error:?}"));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Failed(HostError { ref code, .. }))
            if code.as_ref() == "executor-failure"
    ));
    assert_eq!(
        executor.poll_task(1),
        Ok(DeterministicTaskPoll::Settled(task_result(b"healthy")))
    );
    assert!(matches!(
        ready(failed.join()),
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
    assert_eq!(ready(healthy.join()), Ok(task_result(b"healthy")));
}

fn replay_submission_failure() {
    let executor = DeterministicConcurrentExecutor::default();
    executor.fail_next_spawn();
    assert!(matches!(
        executor.spawn(Box::pin(async { task_result(b"unsubmitted") })),
        Err(HostError { ref code, .. }) if code.as_ref() == "executor-failure"
    ));
    assert!(executor.task_ids().is_empty());
}

fn fair_schedules(polls_per_task: usize, maximum_consecutive: usize) -> Vec<Vec<String>> {
    fn visit(
        first: usize,
        second: usize,
        maximum_consecutive: usize,
        current: &mut Vec<String>,
        output: &mut Vec<Vec<String>>,
    ) {
        if first == 0 && second == 0 {
            output.push(current.clone());
            return;
        }
        for (name, remaining) in [("a", first), ("b", second)] {
            if remaining == 0 {
                continue;
            }
            let consecutive = current
                .iter()
                .rev()
                .take_while(|value| value.as_str() == name)
                .count();
            if consecutive == maximum_consecutive {
                continue;
            }
            current.push(name.to_owned());
            visit(
                first - usize::from(name == "a"),
                second - usize::from(name == "b"),
                maximum_consecutive,
                current,
                output,
            );
            current.pop();
        }
    }

    let mut output = Vec::new();
    visit(
        polls_per_task,
        polls_per_task,
        maximum_consecutive,
        &mut Vec::new(),
        &mut output,
    );
    output
}

fn abort_kind(
    response: Result<gantry::host::contracts::HostResponse, HostError>,
) -> ExecutorAbortResultKind {
    match response {
        Ok(response) if response.canonical_bytes() == b"{\"result\":\"stopped\"}" => {
            ExecutorAbortResultKind::Stopped
        }
        Ok(response) if response.canonical_bytes() == b"{\"result\":\"already-settled\"}" => {
            ExecutorAbortResultKind::AlreadySettled
        }
        Ok(response) => panic!(
            "unexpected abort response: {:?}",
            response.canonical_bytes()
        ),
        Err(_) => ExecutorAbortResultKind::Failed,
    }
}

fn ready<T>(mut future: gantry::host::contracts::HostFuture<'_, T>) -> T {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("settled contract future remained pending"),
    }
}

fn task_result(bytes: &'static [u8]) -> OwnedTaskResult {
    OwnedTaskResult {
        canonical_bytes: Arc::from(bytes),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
