//! Public conformance for nondurable root-event delivery and ownership.

use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use gantry::event::EventEnvelope;
use gantry::host::contracts::{ExecutorAdapter, HostError, HostFuture, IdentitySource};
use gantry::host::event::{
    EventDeliveryRequest, EventDeliveryRuntime, EventRetryPolicy, EventSink, RedactionCapabilities,
    SinkDeliveryPolicy, SinkId,
};
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{
    DeliveryOutcome, EventKind, JitterMode, PORTABLE_SPECIFICATION_REVISION,
    PROTOCOL_FAMILY_DEFINITIONS, RuntimeErrorCategory, SinkClass, StartFailureCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, FinalShutdownEventFailure, FinalShutdownEventSettlement,
    InterpreterConfiguration, MachineOutcome, RequiredConfiguration, RuntimeCode,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use gantry::{Interpreter, StartExecutionRequest, StartExecutionResult};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::ScriptedIntegration;
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;

const DURABLE_BARRIER_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_event_dispatch_and_settlement_precede_callback_and_terminal_observation";
const DURABLE_BEST_EFFORT_PROGRESS_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#committed_best_effort_operation_dispatch_delivery_settles_while_child_hook_is_pending";
const DURABLE_CANCELLATION_DRAIN_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#facade_cancellation_drains_finite_events_before_releasing_durable_owner";
const DURABLE_DELIVERY_CAPACITY_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_graph_sink_delivery_obeys_maximum_active_event_deliveries";
const NONDURABLE_BEST_EFFORT_REJECTION_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#best_effort_delivery_submission_rejection_preserves_language_result";
const NONDURABLE_CANCELLED_FIRST_ADMISSION_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#aborted_producer_does_not_drop_completed_event_waiting_for_first_sink_admission";
const NONDURABLE_CANCELLED_SECOND_SINK_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#aborted_producer_does_not_drop_second_sink_from_admitted_mixed_plan";
const NONDURABLE_CAPACITY_ORDER_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#capacity_one_reverse_polling_preserves_nondurable_per_sink_task_order";
const NONDURABLE_ORDER_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#nondurable_root_events_keep_semantic_order_after_start_and_await_observers_drop";
const OWNED_DELIVERY_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#dropped_start_waiter_does_not_abandon_required_default_plan_delivery";
const PRETERMINAL_EXHAUSTION_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#preterminal_required_delivery_exhaustion_commits_runtime_failure_precedence";
const REQUIRED_FAILURE_RECOVERY_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#resume_reconstructs_committed_required_delivery_failure_before_source_progress";
const SHUTDOWN_EVIDENCE: &str = "crates/gantry-conformance/tests/revent_ownership.rs#shutdown_emits_one_final_event_and_reports_its_actual_settlement";
const TASK_SEQUENCE_CLOCK_EVIDENCE: &str = "crates/gantry-runtime/src/event.rs#shared_task_pipelines_serialize_sequence_across_delayed_clock_completion";
const TERMINAL_RESUME_EVIDENCE: &str = "crates/gantry-conformance/tests/automatic_durable_root.rs#terminal_delivery_only_resume_submits_no_root_or_hook_and_releases_owner";
const OBS_CONCURRENT_EVIDENCE: &str = "crates/gantry-conformance/tests/source_spawn.rs#native_child_submission_keeps_the_gate_closed_and_establishes_session_before_hook";
const OBS_DURABLE_EVIDENCE: &str = "crates/gantry-conformance/tests/source_spawn.rs#durable_spawn_event_commits_before_child_dependence_and_settles_by_foreground";
const OBS_EXHAUSTION_EVIDENCE: &str = "crates/gantry-conformance/tests/source_spawn.rs#public_durable_query_retains_required_spawn_delivery_failure";

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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn checked_in_revent_ownership_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/revent-ownership-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.revent-ownership-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-REVENT-001");
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
            DURABLE_BEST_EFFORT_PROGRESS_EVIDENCE,
            DURABLE_CANCELLATION_DRAIN_EVIDENCE,
            DURABLE_DELIVERY_CAPACITY_EVIDENCE,
            DURABLE_BARRIER_EVIDENCE,
            NONDURABLE_BEST_EFFORT_REJECTION_EVIDENCE,
            NONDURABLE_CANCELLED_FIRST_ADMISSION_EVIDENCE,
            NONDURABLE_CANCELLED_SECOND_SINK_EVIDENCE,
            NONDURABLE_CAPACITY_ORDER_EVIDENCE,
            NONDURABLE_ORDER_EVIDENCE,
            OWNED_DELIVERY_EVIDENCE,
            PRETERMINAL_EXHAUSTION_EVIDENCE,
            REQUIRED_FAILURE_RECOVERY_EVIDENCE,
            SHUTDOWN_EVIDENCE,
            TASK_SEQUENCE_CLOCK_EVIDENCE,
            TERMINAL_RESUME_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-REVENT-001")
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
    assert_eq!(declared.len(), 3);
    assert_eq!(manifest.exclusions.len(), 1);
}

#[test]
fn checked_in_async_execution_observation_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/async-execution-observation-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(
        manifest.format,
        "gantry.async-execution-observation-evidence/v1"
    );
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-OBS-001");
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
            OBS_CONCURRENT_EVIDENCE,
            OBS_DURABLE_EVIDENCE,
            NONDURABLE_ORDER_EVIDENCE,
            OBS_EXHAUSTION_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-OBS-001")
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
    assert_eq!(declared.len(), 3);
    assert_eq!(manifest.exclusions.len(), 4);
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-revent-ownership-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write root-event fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct RecordingSink {
    outcomes: Mutex<VecDeque<(Option<EventKind>, DeliveryOutcome)>>,
    events: Mutex<Vec<EventEnvelope>>,
}

impl RecordingSink {
    fn new(outcomes: impl IntoIterator<Item = (Option<EventKind>, DeliveryOutcome)>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<EventEnvelope> {
        lock(&self.events).clone()
    }
}

impl EventSink for RecordingSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move {
            let kind = request.event.kind();
            lock(&self.events).push(request.event);
            let mut outcomes = lock(&self.outcomes);
            let outcome = outcomes
                .iter()
                .position(|(selected, _)| selected.is_none_or(|selected| selected == kind))
                .and_then(|index| outcomes.remove(index))
                .map_or(DeliveryOutcome::Success, |(_, outcome)| outcome);
            Ok(outcome)
        })
    }
}

#[derive(Default)]
struct ImmediateDeliveryRuntime {
    attempts: AtomicU64,
}

impl ImmediateDeliveryRuntime {
    fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Acquire)
    }
}

impl EventDeliveryRuntime for ImmediateDeliveryRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        _: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        sink.deliver(request)
    }

    fn sleep<'a>(&'a self, _: u64) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_full_jitter(&self, _: u64) -> Result<u64, HostError> {
        Ok(0)
    }
}

struct PendingDelivery {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingDelivery {
    type Output = Result<DeliveryOutcome, HostError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingDelivery {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

struct PendingSink {
    calls: Arc<AtomicU64>,
    dropped: Arc<AtomicBool>,
}

impl EventSink for PendingSink {
    fn deliver<'a>(
        &'a self,
        _: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Box::pin(PendingDelivery {
            dropped: Arc::clone(&self.dropped),
        })
    }
}

#[derive(Default)]
struct DeliveryGate {
    calls: AtomicU64,
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl DeliveryGate {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        if let Some(waker) = lock(&self.waker).take() {
            waker.wake();
        }
    }
}

struct GatedDelivery {
    gate: Arc<DeliveryGate>,
}

impl Future for GatedDelivery {
    type Output = Result<DeliveryOutcome, HostError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.gate.released.load(Ordering::Acquire) {
            Poll::Ready(Ok(DeliveryOutcome::Success))
        } else {
            *lock(&self.gate.waker) = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

struct GatedRecordingSink {
    gated_kind: EventKind,
    gate: Arc<DeliveryGate>,
    events: Mutex<Vec<EventEnvelope>>,
}

impl GatedRecordingSink {
    fn new(gated_kind: EventKind, gate: Arc<DeliveryGate>) -> Self {
        Self {
            gated_kind,
            gate,
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<EventEnvelope> {
        lock(&self.events).clone()
    }
}

impl EventSink for GatedRecordingSink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        let gated = request.event.kind() == self.gated_kind;
        lock(&self.events).push(request.event);
        if gated {
            self.gate.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(GatedDelivery {
                gate: Arc::clone(&self.gate),
            })
        } else {
            Box::pin(async { Ok(DeliveryOutcome::Success) })
        }
    }
}

#[test]
fn dropped_start_waiter_does_not_abandon_required_default_plan_delivery() {
    let root = TempDirectory::new("fn main() -> Int { 3 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let calls = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(PendingSink {
        calls: Arc::clone(&calls),
        dropped: Arc::clone(&dropped),
    });
    let interpreter = interpreter_with_delivery(
        executor,
        Arc::new(ImmediateDeliveryRuntime::default()),
        plan(SinkClass::Required, sink),
    );
    let selection = selection();
    let mut start = Box::pin(interpreter.start_execution(request(&root, &selection, None)));

    let deadline = Instant::now() + Duration::from_secs(2);
    while calls.load(Ordering::Acquire) == 0 {
        assert!(
            poll_once(start.as_mut()).is_pending(),
            "required default-plan delivery did not remain an admitted start activity"
        );
        assert!(
            Instant::now() < deadline,
            "start did not reach required default-plan delivery"
        );
        std::thread::yield_now();
    }
    assert_eq!(calls.load(Ordering::Acquire), 1);
    drop(start);
    assert!(
        !dropped.load(Ordering::Acquire),
        "dropping the start waiter abandoned its must-settle delivery"
    );
}

#[test]
fn executor_rejection_does_not_start_or_abandon_event_delivery() {
    let root = TempDirectory::new("fn main() -> Int { 5 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    executor.fail_next_spawn();
    let calls = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(PendingSink {
        calls: Arc::clone(&calls),
        dropped: Arc::clone(&dropped),
    });
    let interpreter = interpreter_with_delivery(
        executor,
        Arc::new(ImmediateDeliveryRuntime::default()),
        plan(SinkClass::Required, sink),
    );
    let selection = selection();

    let StartExecutionResult::Rejected(failure) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("event-delivery executor rejection accepted an execution")
    };
    assert_eq!(
        failure.category,
        StartFailureCategory::ImplementationResourceExhaustion
    );
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(
        !dropped.load(Ordering::Acquire),
        "executor rejection abandoned an already-started sink future"
    );
}

#[test]
fn nondurable_root_events_keep_semantic_order_after_start_and_await_observers_drop() {
    let root = TempDirectory::new("fn main() -> Int { 40 + 2 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let sink = Arc::new(RecordingSink::new([]));
    let runtime = Arc::new(ImmediateDeliveryRuntime::default());
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        runtime.clone(),
        plan(SinkClass::Required, sink.clone()),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("valid root-event fixture was rejected")
    };
    let execution_id = accepted.execution_id();
    let handle = accepted.handle().clone();
    drop(accepted);
    let root_task_id = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted execution submitted no root task"));

    let mut terminal_wait = Box::pin(interpreter.await_terminal(&handle));
    assert!(poll_once(terminal_wait.as_mut()).is_pending());
    drop(terminal_wait);
    drive_execution_tasks(&executor, &interpreter, &handle);
    assert!(matches!(
        executor.poll_task(root_task_id),
        Ok(DeterministicTaskPoll::Settled(_))
    ));

    let snapshot = interpreter
        .query_execution(execution_id)
        .unwrap_or_else(|error| panic!("execution query failed: {error:?}"))
        .unwrap_or_else(|| panic!("accepted execution disappeared with its observers"));
    assert!(matches!(
        snapshot.terminal.as_ref().map(|terminal| &terminal.foreground),
        Some(MachineOutcome::Succeeded(value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 42)
    ));

    let events = sink.events();
    assert_eq!(
        events.iter().map(EventEnvelope::kind).collect::<Vec<_>>(),
        [
            EventKind::Parse,
            EventKind::Analysis,
            EventKind::TaskCompletion,
            EventKind::ForegroundCompletion,
            EventKind::TerminalExecution,
        ]
    );
    let lifecycle = &events[2..];
    assert!(
        lifecycle
            .iter()
            .all(|event| event.execution_id() == Some(execution_id))
    );
    assert_eq!(
        lifecycle
            .iter()
            .map(EventEnvelope::per_task_sequence)
            .collect::<Vec<_>>(),
        [Some(0), Some(1), Some(2)]
    );
    assert!(
        lifecycle
            .windows(2)
            .all(|pair| pair[0].event_id() != pair[1].event_id())
    );
    assert_eq!(runtime.attempts(), 5);
}

#[test]
fn reverse_polling_preserves_nondurable_per_sink_task_order() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let required = Arc::new(RecordingSink::new([]));
    let best_effort = Arc::new(RecordingSink::new([]));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::new(vec![
            registration("required", SinkClass::Required, required.clone()),
            registration("best-effort", SinkClass::BestEffort, best_effort.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}")),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("reverse-poll fixture was rejected")
    };
    let handle = accepted.handle().clone();
    drop(accepted);

    drive_execution_tasks_in_reverse(&executor, &interpreter, &handle);

    let expected = [
        EventKind::Parse,
        EventKind::Analysis,
        EventKind::TaskCompletion,
        EventKind::ForegroundCompletion,
        EventKind::TerminalExecution,
    ];
    assert_eq!(
        required
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        best_effort
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn one_active_delivery_backpressures_without_dropping_accepted_obligations() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let required = Arc::new(RecordingSink::new([]));
    let best_effort = Arc::new(RecordingSink::new([]));
    let interpreter = interpreter_with_delivery_capacity(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::new(vec![
            registration("required", SinkClass::Required, required.clone()),
            registration("best-effort", SinkClass::BestEffort, best_effort.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}")),
        1,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("capacity-one fixture was rejected")
    };
    let handle = accepted.handle().clone();
    drop(accepted);

    drive_execution_tasks(&executor, &interpreter, &handle);
    drive_runnable_tasks(&executor, false);

    let expected = [
        EventKind::Parse,
        EventKind::Analysis,
        EventKind::TaskCompletion,
        EventKind::ForegroundCompletion,
        EventKind::TerminalExecution,
    ];
    assert_eq!(
        required
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        best_effort
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn aborted_producer_does_not_drop_completed_event_waiting_for_first_sink_admission() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let required = Arc::new(RecordingSink::new([]));
    let gate = Arc::new(DeliveryGate::default());
    let best_effort = Arc::new(GatedRecordingSink::new(
        EventKind::TaskCompletion,
        Arc::clone(&gate),
    ));
    let interpreter = interpreter_with_delivery_capacity(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::new(vec![
            registration("required", SinkClass::Required, required.clone()),
            registration("best-effort", SinkClass::BestEffort, best_effort.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}")),
        1,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("first-admission cancellation fixture was rejected")
    };
    let execution_id = accepted.execution_id();
    drop(accepted);
    let root_task = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted execution submitted no root task"));

    assert_eq!(
        executor
            .poll_task(root_task)
            .unwrap_or_else(|error| panic!("root poll failed: {error:?}")),
        DeterministicTaskPoll::Pending
    );
    let first_delivery = *executor
        .task_ids()
        .last()
        .filter(|task| **task != root_task)
        .unwrap_or_else(|| panic!("task completion did not submit a delivery worker"));
    assert_eq!(
        executor
            .poll_task(first_delivery)
            .unwrap_or_else(|error| panic!("first delivery poll failed: {error:?}")),
        DeterministicTaskPoll::Pending
    );
    assert_eq!(gate.calls.load(Ordering::Acquire), 1);
    assert!(executor.is_runnable(root_task));
    assert_eq!(
        executor
            .poll_task(root_task)
            .unwrap_or_else(|error| panic!("foreground handoff poll failed: {error:?}")),
        DeterministicTaskPoll::Pending
    );
    assert!(
        !required
            .events()
            .iter()
            .any(|event| event.kind() == EventKind::ForegroundCompletion)
    );

    let aborted = interpreter.test_abort_nondurable_execution_tasks(execution_id);
    assert_eq!(aborted.len(), 1);
    assert!(executor.abort_result(root_task).is_some());
    gate.release();
    assert!(matches!(
        executor.poll_task(first_delivery),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    for _ in 0..16 {
        if !drive_runnable_tasks(&executor, false) {
            break;
        }
    }

    assert!(
        required
            .events()
            .iter()
            .any(|event| event.kind() == EventKind::ForegroundCompletion),
        "the completed event was lost with its aborted producer"
    );
    assert!(
        best_effort
            .events()
            .iter()
            .any(|event| event.kind() == EventKind::ForegroundCompletion),
        "the completed event's best-effort obligation was not retained"
    );
}

#[test]
fn aborted_producer_does_not_drop_second_sink_from_admitted_mixed_plan() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let required = Arc::new(RecordingSink::new([]));
    let best_effort = Arc::new(RecordingSink::new([]));
    let interpreter = interpreter_with_delivery_capacity(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::new(vec![
            registration("required", SinkClass::Required, required.clone()),
            registration("best-effort", SinkClass::BestEffort, best_effort.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}")),
        1,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("second-admission cancellation fixture was rejected")
    };
    let execution_id = accepted.execution_id();
    drop(accepted);
    let root_task = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted execution submitted no root task"));

    assert_eq!(
        executor
            .poll_task(root_task)
            .unwrap_or_else(|error| panic!("root poll failed: {error:?}")),
        DeterministicTaskPoll::Pending
    );
    let delivery = *executor
        .task_ids()
        .last()
        .filter(|task| **task != root_task)
        .unwrap_or_else(|| panic!("task completion did not submit a delivery worker"));
    let aborted = interpreter.test_abort_nondurable_execution_tasks(execution_id);
    assert_eq!(aborted.len(), 1);
    assert!(executor.abort_result(root_task).is_some());
    assert!(matches!(
        executor.poll_task(delivery),
        Ok(DeterministicTaskPoll::Settled(_))
    ));

    assert!(
        required
            .events()
            .iter()
            .any(|event| event.kind() == EventKind::TaskCompletion)
    );
    assert!(
        best_effort
            .events()
            .iter()
            .any(|event| event.kind() == EventKind::TaskCompletion),
        "producer abort dropped the mixed plan before its second sink"
    );
}

#[test]
fn best_effort_delivery_submission_rejection_preserves_language_result() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let sink = Arc::new(RecordingSink::new([]));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        plan(SinkClass::BestEffort, sink.clone()),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("best-effort rejection fixture was rejected")
    };
    let execution_id = accepted.execution_id();
    let handle = accepted.handle().clone();
    drop(accepted);

    executor.fail_next_spawn();
    drive_execution_tasks(&executor, &interpreter, &handle);
    for _ in 0..16 {
        if !drive_runnable_tasks(&executor, false) {
            break;
        }
    }
    let snapshot = interpreter
        .query_execution(execution_id)
        .unwrap_or_else(|error| panic!("execution query failed: {error:?}"))
        .unwrap_or_else(|| panic!("accepted execution disappeared"));
    assert!(snapshot.cancellation.is_none());
    assert!(matches!(
        snapshot.terminal.as_ref().map(|terminal| &terminal.foreground),
        Some(MachineOutcome::Succeeded(value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 42)
    ));
    assert!(
        !sink
            .events()
            .iter()
            .any(|event| event.kind() == EventKind::TaskCompletion),
        "the executor-rejected best-effort operation unexpectedly reached its sink"
    );
    assert!(
        sink.events()
            .iter()
            .any(|event| event.kind() == EventKind::TerminalExecution)
    );
}

#[test]
fn capacity_one_reverse_polling_preserves_nondurable_per_sink_task_order() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let required = Arc::new(RecordingSink::new([]));
    let best_effort = Arc::new(RecordingSink::new([]));
    let interpreter = interpreter_with_delivery_capacity(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::new(vec![
            registration("required", SinkClass::Required, required.clone()),
            registration("best-effort", SinkClass::BestEffort, best_effort.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}")),
        1,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("capacity-one reverse-poll fixture was rejected")
    };
    let handle = accepted.handle().clone();
    drop(accepted);

    drive_execution_tasks_in_reverse(&executor, &interpreter, &handle);

    let expected = [
        EventKind::Parse,
        EventKind::Analysis,
        EventKind::TaskCompletion,
        EventKind::ForegroundCompletion,
        EventKind::TerminalExecution,
    ];
    assert_eq!(
        required
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        best_effort
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn foreground_event_agrees_with_rewritten_public_failure_after_required_delivery_failure() {
    let root = TempDirectory::new("fn main() -> Int { 42 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let failed = Arc::new(RecordingSink::new([(
        Some(EventKind::TaskCompletion),
        DeliveryOutcome::Terminal,
    )]));
    let observer = Arc::new(RecordingSink::new([]));
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::new(vec![
            registration("failed", SinkClass::Required, failed.clone()),
            registration("observer", SinkClass::Required, observer.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}")),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, None)))
    else {
        panic!("required-delivery-failure fixture was rejected")
    };
    let handle = accepted.handle().clone();
    drop(accepted);

    drive_execution_tasks(&executor, &interpreter, &handle);
    let snapshot = block_on(interpreter.await_terminal(&handle))
        .unwrap_or_else(|error| panic!("terminal observation failed: {error:?}"))
        .unwrap_or_else(|| panic!("accepted execution disappeared"));
    let foreground = &snapshot
        .terminal
        .as_ref()
        .unwrap_or_else(|| panic!("execution had no terminal outcome"))
        .foreground;
    assert!(matches!(
        foreground,
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Operation(RuntimeErrorCategory::RequiredEventDeliveryFailure)
    ));
    assert_eq!(snapshot.required_delivery_failures.len(), 1);

    let foreground_event = observer
        .events()
        .into_iter()
        .find(|event| event.kind() == EventKind::ForegroundCompletion)
        .unwrap_or_else(|| panic!("observer did not receive foreground completion"));
    let payload: serde_json::Value =
        serde_json::from_slice(foreground_event.payload().canonical_bytes())
            .unwrap_or_else(|error| panic!("foreground payload was not JSON: {error}"));
    assert_eq!(
        payload["completion_category"],
        RuntimeErrorCategory::RequiredEventDeliveryFailure.wire_name()
    );
    assert!(
        payload["failure_reference"]
            .as_str()
            .is_some_and(|reference| reference.ends_with(":required-event-delivery-failure")),
        "foreground payload: {payload}"
    );
}

#[test]
fn explicit_start_plan_overrides_the_constructor_default_plan() {
    let root = TempDirectory::new("fn main() -> Int { 7 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let sink = Arc::new(RecordingSink::new([]));
    let runtime = Arc::new(ImmediateDeliveryRuntime::default());
    let interpreter = interpreter_with_delivery(
        Arc::clone(&executor),
        runtime.clone(),
        plan(SinkClass::Required, sink.clone()),
    );
    let selection = selection();
    let no_delivery = SinkPlan::default();
    let StartExecutionResult::Accepted(_accepted) =
        block_on(interpreter.start_execution(request(&root, &selection, Some(&no_delivery))))
    else {
        panic!("explicit-plan fixture was rejected")
    };

    assert!(sink.events().is_empty());
    assert_eq!(runtime.attempts(), 0);
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert!(sink.events().is_empty());
    assert_eq!(runtime.attempts(), 0);
}

#[test]
fn required_exhaustion_drives_preacceptance_rejection() {
    let rejected_root = TempDirectory::new("fn main() -> Int { 1 }");
    let rejected_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let rejected_sink = Arc::new(RecordingSink::new([(
        Some(EventKind::Analysis),
        DeliveryOutcome::Terminal,
    )]));
    let rejected = interpreter_with_delivery(
        Arc::clone(&rejected_executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        plan(SinkClass::Required, rejected_sink.clone()),
    );
    let selection = selection();
    let StartExecutionResult::Rejected(failure) =
        block_on(rejected.start_execution(request(&rejected_root, &selection, None)))
    else {
        panic!("required preacceptance exhaustion accepted an execution")
    };
    assert_eq!(
        failure.category,
        StartFailureCategory::RequiredEventDelivery
    );
    for task_id in rejected_executor.task_ids() {
        assert!(matches!(
            rejected_executor.poll_task(task_id),
            Ok(DeterministicTaskPoll::Settled(_))
        ));
    }
    assert_eq!(
        rejected_sink
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        [EventKind::Parse, EventKind::Analysis]
    );
}

#[test]
fn required_exhaustion_after_terminal_preserves_the_fixed_root_outcome() {
    let terminal_root = TempDirectory::new("fn main() -> Int { 9 }");
    let terminal_executor = Arc::new(DeterministicConcurrentExecutor::default());
    let terminal_sink = Arc::new(RecordingSink::new([(
        Some(EventKind::TerminalExecution),
        DeliveryOutcome::Terminal,
    )]));
    let terminal = interpreter_with_delivery(
        Arc::clone(&terminal_executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        plan(SinkClass::Required, terminal_sink.clone()),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(terminal.start_execution(request(&terminal_root, &selection, None)))
    else {
        panic!("terminal-exhaustion fixture was rejected")
    };
    let execution_id = accepted.execution_id();
    let handle = accepted.handle().clone();
    drop(accepted);
    let root_task_id = *terminal_executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("accepted execution submitted no root task"));
    drive_execution_tasks(&terminal_executor, &terminal, &handle);
    assert!(matches!(
        terminal_executor.poll_task(root_task_id),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let snapshot = block_on(terminal.await_terminal(&handle))
        .unwrap_or_else(|error| panic!("terminal-exhaustion observation failed: {error:?}"))
        .unwrap_or_else(|| panic!("terminal-exhaustion execution disappeared"));
    assert_eq!(snapshot.execution_id, execution_id);
    assert!(matches!(
        snapshot.terminal.as_ref().map(|terminal| &terminal.foreground),
        Some(MachineOutcome::Succeeded(value))
            if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 9)
    ));
    assert_eq!(snapshot.required_delivery_failures.len(), 1);
    assert_eq!(
        terminal_sink
            .events()
            .iter()
            .map(EventEnvelope::kind)
            .collect::<Vec<_>>(),
        [
            EventKind::Parse,
            EventKind::Analysis,
            EventKind::TaskCompletion,
            EventKind::ForegroundCompletion,
            EventKind::TerminalExecution,
        ]
    );
}

#[test]
fn shutdown_emits_one_final_event_and_reports_its_actual_settlement() {
    for (class, outcome, expected, orderly) in [
        (
            SinkClass::Required,
            DeliveryOutcome::Success,
            FinalShutdownEventSettlement::Settled,
            true,
        ),
        (
            SinkClass::Required,
            DeliveryOutcome::Terminal,
            FinalShutdownEventSettlement::Exhausted,
            false,
        ),
        (
            SinkClass::BestEffort,
            DeliveryOutcome::Terminal,
            FinalShutdownEventSettlement::Exhausted,
            true,
        ),
    ] {
        let executor = Arc::new(DeterministicConcurrentExecutor::default());
        let sink = Arc::new(RecordingSink::new([(Some(EventKind::Shutdown), outcome)]));
        let interpreter = interpreter_with_delivery_polling(
            Arc::clone(&executor),
            Arc::new(ImmediateDeliveryRuntime::default()),
            plan(class, sink.clone()),
            false,
        );
        let observer = interpreter.clone();

        let mut dropped_waiter = Box::pin(interpreter.shutdown());
        assert!(poll_once(dropped_waiter.as_mut()).is_pending());
        drop(dropped_waiter);
        assert_eq!(executor.task_ids(), [0]);
        assert!(matches!(
            executor.poll_task(0),
            Ok(DeterministicTaskPoll::Settled(_))
        ));

        let report = block_on(observer.shutdown())
            .unwrap_or_else(|error| panic!("shutdown report failed: {error:?}"));
        let repeated = block_on(interpreter.shutdown())
            .unwrap_or_else(|error| panic!("repeated shutdown failed: {error:?}"));
        assert!(Arc::ptr_eq(&report, &repeated));
        assert_eq!(report.final_event, expected);
        assert_eq!(report.orderly, orderly);
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind(), EventKind::Shutdown);
        assert!(events[0].execution_id().is_none());
    }
}

#[test]
fn shutdown_event_reports_confirmed_executor_aborts() {
    let root = TempDirectory::new("fn main() -> Int { 17 }");
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    executor.control_sleeps();
    let sink = Arc::new(RecordingSink::new([(
        Some(EventKind::Shutdown),
        DeliveryOutcome::Success,
    )]));
    let interpreter = interpreter_with_delivery_polling(
        Arc::clone(&executor),
        Arc::new(ImmediateDeliveryRuntime::default()),
        plan(SinkClass::Required, sink.clone()),
        false,
    );
    let selection = selection();
    let mut start = Box::pin(interpreter.start_execution(request(&root, &selection, None)));
    let accepted = loop {
        match poll_once(start.as_mut()) {
            Poll::Ready(StartExecutionResult::Accepted(accepted)) => break accepted,
            Poll::Ready(StartExecutionResult::Rejected(failure)) => {
                panic!("valid shutdown-abort fixture was rejected: {failure:?}")
            }
            Poll::Pending => {
                for task_id in executor.task_ids() {
                    if executor.is_runnable(task_id) {
                        let _ = executor.poll_task(task_id);
                    }
                }
            }
        }
    };
    drop(accepted);

    let mut shutdown = Box::pin(interpreter.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    assert_eq!(executor.task_ids(), [0, 1, 2]);
    assert_eq!(executor.poll_task(2), Ok(DeterministicTaskPoll::Pending));
    executor
        .release_sleep(0)
        .unwrap_or_else(|error| panic!("grace timer release failed: {error:?}"));
    assert_eq!(executor.poll_task(2), Ok(DeterministicTaskPoll::Pending));
    executor
        .release_sleep(2)
        .unwrap_or_else(|error| panic!("drain timer release failed: {error:?}"));
    assert!(matches!(
        executor.poll_task(2),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let report = match poll_once(shutdown.as_mut()) {
        Poll::Ready(Ok(report)) => report,
        Poll::Ready(Err(error)) => panic!("shutdown abort fixture failed: {error:?}"),
        Poll::Pending => panic!("shutdown abort fixture did not publish its report"),
    };
    assert!(report.orderly);
    let events = sink.events();
    let shutdown_event = events
        .iter()
        .find(|event| event.kind() == EventKind::Shutdown)
        .unwrap_or_else(|| panic!("shutdown event was not delivered: {events:?}"));
    let payload = std::str::from_utf8(shutdown_event.payload().canonical_bytes())
        .unwrap_or_else(|error| panic!("shutdown payload was not UTF-8: {error}"));
    assert!(
        payload.contains("\"aborted_count\":1"),
        "payload: {payload}"
    );
}

#[test]
fn shutdown_identity_failure_is_not_reported_as_sink_exhaustion() {
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor.clone();
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new([
        Ok([1_u8; 32]),
        Err(HostError {
            code: Arc::from("identity-source-failure"),
            protected_diagnostic: None,
        }),
    ]));
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let interpreter = Interpreter::new_with_event_delivery(
        configuration(executor_adapter, identities),
        Arc::new(DeterministicUtcClock::new([timestamp(1)])),
        integration.clone(),
        integration.clone(),
        integration,
        Arc::new(ImmediateDeliveryRuntime::default()),
        SinkPlan::default(),
    );

    let mut shutdown = Box::pin(interpreter.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    assert_eq!(executor.task_ids(), [0]);
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    let report = match poll_once(shutdown.as_mut()) {
        Poll::Ready(Ok(report)) => report,
        Poll::Ready(Err(error)) => panic!("shutdown failed outside its report: {error:?}"),
        Poll::Pending => panic!("shutdown identity failure did not publish its report"),
    };
    assert_eq!(
        report.final_event,
        FinalShutdownEventSettlement::Failed(FinalShutdownEventFailure::IdentityGeneration)
    );
    assert!(!report.orderly);
}

fn interpreter_with_delivery(
    executor: Arc<DeterministicConcurrentExecutor>,
    runtime: Arc<ImmediateDeliveryRuntime>,
    event_delivery: SinkPlan,
) -> Interpreter {
    interpreter_with_delivery_polling(executor, runtime, event_delivery, true)
}

fn drive_execution_tasks(
    executor: &DeterministicConcurrentExecutor,
    interpreter: &Interpreter,
    handle: &gantry::runtime::ExecutionHandle,
) {
    for _ in 0..1_000 {
        if interpreter
            .query_execution(handle.execution_id())
            .unwrap_or_else(|error| panic!("execution query failed: {error:?}"))
            .is_some_and(|snapshot| snapshot.terminal.is_some())
        {
            return;
        }
        let mut progressed = false;
        for task_id in executor.task_ids() {
            if executor.is_runnable(task_id) {
                progressed = true;
                let _ = executor
                    .poll_task(task_id)
                    .unwrap_or_else(|error| panic!("task {task_id} poll failed: {error:?}"));
            }
        }
        if !progressed {
            std::thread::yield_now();
        }
    }
    panic!("execution did not reach terminal state");
}

fn drive_execution_tasks_in_reverse(
    executor: &DeterministicConcurrentExecutor,
    interpreter: &Interpreter,
    handle: &gantry::runtime::ExecutionHandle,
) {
    for _ in 0..1_000 {
        let terminal = interpreter
            .query_execution(handle.execution_id())
            .unwrap_or_else(|error| panic!("execution query failed: {error:?}"))
            .is_some_and(|snapshot| snapshot.terminal.is_some());
        let progressed = drive_runnable_tasks(executor, true);
        if terminal && !progressed {
            return;
        }
        if !progressed {
            std::thread::yield_now();
        }
    }
    panic!("reverse-polled execution did not settle all delivery tasks");
}

fn drive_runnable_tasks(executor: &DeterministicConcurrentExecutor, reverse: bool) -> bool {
    let mut task_ids = executor.task_ids();
    if reverse {
        task_ids.reverse();
    }
    let mut progressed = false;
    for task_id in task_ids {
        if executor.is_runnable(task_id) {
            progressed = true;
            let _ = executor
                .poll_task(task_id)
                .unwrap_or_else(|error| panic!("task {task_id} poll failed: {error:?}"));
        }
    }
    progressed
}

fn interpreter_with_delivery_polling(
    executor: Arc<DeterministicConcurrentExecutor>,
    runtime: Arc<ImmediateDeliveryRuntime>,
    event_delivery: SinkPlan,
    poll_next_spawn_immediately: bool,
) -> Interpreter {
    interpreter_with_delivery_capacity_and_polling(
        executor,
        runtime,
        event_delivery,
        8,
        poll_next_spawn_immediately,
    )
}

fn interpreter_with_delivery_capacity(
    executor: Arc<DeterministicConcurrentExecutor>,
    runtime: Arc<ImmediateDeliveryRuntime>,
    event_delivery: SinkPlan,
    maximum_active_event_deliveries: u64,
) -> Interpreter {
    interpreter_with_delivery_capacity_and_polling(
        executor,
        runtime,
        event_delivery,
        maximum_active_event_deliveries,
        true,
    )
}

fn interpreter_with_delivery_capacity_and_polling(
    executor: Arc<DeterministicConcurrentExecutor>,
    runtime: Arc<ImmediateDeliveryRuntime>,
    event_delivery: SinkPlan,
    maximum_active_event_deliveries: u64,
    poll_next_spawn_immediately: bool,
) -> Interpreter {
    if poll_next_spawn_immediately {
        executor.poll_next_spawn_immediately();
    }
    let executor_adapter: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=192).map(|byte| Ok([byte; 32])),
    ));
    let integration = Arc::new(ScriptedIntegration::new([], []));
    Interpreter::new_with_event_delivery(
        configuration_with_event_delivery_capacity(
            executor_adapter,
            identities,
            maximum_active_event_deliveries,
        ),
        Arc::new(DeterministicUtcClock::new((1_u32..=192).map(timestamp))),
        integration.clone(),
        integration.clone(),
        integration,
        runtime,
        event_delivery,
    )
}

fn request<'a>(
    root: &'a TempDirectory,
    selection: &'a ProtocolSelection,
    event_delivery: Option<&'a SinkPlan>,
) -> StartExecutionRequest<'a> {
    StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery,
    }
}

fn configuration(
    executor: Arc<dyn ExecutorAdapter>,
    identities: Arc<dyn IdentitySource>,
) -> InterpreterConfiguration {
    configuration_with_event_delivery_capacity(executor, identities, 8)
}

fn configuration_with_event_delivery_capacity(
    executor: Arc<dyn ExecutorAdapter>,
    identities: Arc<dyn IdentitySource>,
    maximum_active_event_deliveries: u64,
) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            256, 65_536, 1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(
        executor,
        identities,
        required,
        AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, maximum_active_event_deliveries, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    )
}

fn plan(class: SinkClass, sink: Arc<dyn EventSink>) -> SinkPlan {
    SinkPlan::new(vec![registration("revent-sink", class, sink)])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"))
}

fn registration(id: &str, class: SinkClass, sink: Arc<dyn EventSink>) -> SinkRegistration {
    let retry = EventRetryPolicy::new("revent-retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
    let policy = SinkDeliveryPolicy::new(
        class,
        false,
        "revent-redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"));
    SinkRegistration::new(
        SinkId::new(id).unwrap_or_else(|error| panic!("sink identity failed: {error:?}")),
        policy,
        sink,
    )
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
    .unwrap_or_else(|error| panic!("selection failed: {error}"))
}

fn timestamp(microseconds: u32) -> Result<UtcTimestamp, HostError> {
    UtcTimestamp::from_unix_seconds(0, microseconds).map_err(|_| HostError {
        code: Arc::from("clock-invariant"),
        protected_diagnostic: None,
    })
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match poll_once(future.as_mut()) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
