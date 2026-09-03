//! Public conformance coverage for unified root and child execution coordination.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Wake, Waker};

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::TaskControlSiteKind;
use gantry::ir::{
    CanonicalPath, StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor,
};
use gantry::portable::{IdentityKind, TaskHandleState, TaskStatusKind};
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentTaskStateV1, ExecutionCoordinator, LogicalSessionRegistryV1,
    MachineOutcome, SessionCreationModeV1, TaskCreationRequestV1, TaskDriverOwnershipV1,
    TaskOriginV1, TaskRecoveryStateV1, TaskStateError,
};
use gantry::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use serde::Deserialize;

const FIRST_CLASS_ROOT_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_coordinator.rs#root_is_one_first_class_task_without_child_only_state";
const JOIN_SESSION_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_coordinator.rs#join_waits_on_publication_and_sessions_share_the_same_coordinator_cut";
const RACE_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_coordinator.rs#settlement_and_cancellation_race_has_one_consistent_winner";
const PUBLICATION_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_coordinator.rs#task_settlement_and_completion_publish_before_waiter_notification";
const SHUTDOWN_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_coordinator.rs#shutdown_quiescence_wakes_when_semantic_settlement_follows_physical_completion";

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

#[test]
fn checked_in_execution_coordinator_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/execution-coordinator-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.execution-coordinator-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-COORD-001");
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
            FIRST_CLASS_ROOT_EVIDENCE,
            JOIN_SESSION_EVIDENCE,
            RACE_EVIDENCE,
            PUBLICATION_EVIDENCE,
            SHUTDOWN_EVIDENCE,
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-COORD-001")
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
    assert_eq!(declared.len(), 5);
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn root_is_one_first_class_task_without_child_only_state() {
    let (coordinator, root, _) = fixture(3);
    let snapshot = coordinator.snapshot();
    let root_record = snapshot
        .state()
        .task_record(root)
        .unwrap_or_else(|| panic!("root task record missing"));

    assert_eq!(snapshot.state().created_task_count(), 1);
    assert_eq!(snapshot.state().task_record_count(), 1);
    assert_eq!(root_record.origin(), TaskOriginV1::Root);
    assert!(root_record.task_path().is_empty());
    assert_eq!(root_record.status().kind(), TaskStatusKind::Running);
    assert_eq!(
        root_record.driver_ownership(),
        TaskDriverOwnershipV1::Supervised
    );
    assert_eq!(root_record.recovery_state(), TaskRecoveryStateV1::Original);
    assert_eq!(root_record.source_handle_state(), None);
    assert_eq!(root_record.pending_outcome(), None);
    assert!(snapshot.state().task(root).is_none());
}

#[test]
fn task_settlement_and_completion_publish_before_waiter_notification() {
    let (coordinator, root, _) = fixture(1);
    let mut task_wait = Box::pin(
        coordinator
            .wait_for_task_settlement(root)
            .unwrap_or_else(|error| panic!("task wait failed: {error:?}")),
    );
    let probe = Arc::new(PublicationProbe::new(coordinator.clone()));
    let waker = Waker::from(Arc::clone(&probe));
    assert!(poll_once(task_wait.as_mut(), &waker).is_pending());

    let outcome = MachineOutcome::Succeeded(LogicalValue::unit());
    coordinator
        .stage_task_outcome(root, outcome.clone())
        .unwrap_or_else(|error| panic!("outcome staging failed: {error:?}"));
    assert_eq!(probe.wakes.load(Ordering::Acquire), 0);
    assert_eq!(
        coordinator
            .snapshot()
            .state()
            .task_record(root)
            .and_then(|task| task.pending_outcome()),
        Some(&outcome)
    );

    coordinator
        .settle_staged_task(root)
        .unwrap_or_else(|error| panic!("settlement failed: {error:?}"));
    assert_eq!(probe.wakes.load(Ordering::Acquire), 1);
    assert!(probe.observed_unlocked.load(Ordering::Acquire));
    assert!(matches!(
        poll_once(task_wait.as_mut(), Waker::noop()),
        Poll::Ready(status) if status.kind() == TaskStatusKind::Succeeded
    ));

    let mut foreground_wait = Box::pin(coordinator.wait_for_foreground());
    assert!(poll_once(foreground_wait.as_mut(), Waker::noop()).is_pending());
    assert_eq!(
        coordinator
            .complete_foreground()
            .unwrap_or_else(|error| panic!("foreground completion failed: {error:?}")),
        outcome
    );
    assert_eq!(
        poll_once(foreground_wait.as_mut(), Waker::noop()),
        Poll::Ready(outcome.clone())
    );

    let mut terminal_wait = Box::pin(coordinator.wait_for_terminal());
    assert!(poll_once(terminal_wait.as_mut(), Waker::noop()).is_pending());
    coordinator
        .complete_terminal()
        .unwrap_or_else(|error| panic!("terminal completion failed: {error:?}"));
    assert!(poll_once(terminal_wait.as_mut(), Waker::noop()).is_ready());
    assert_eq!(
        coordinator.stage_task_outcome(root, outcome),
        Err(TaskStateError::InvalidTransition)
    );
}

#[test]
fn join_waits_on_publication_and_sessions_share_the_same_coordinator_cut() {
    let (coordinator, root, root_session) = fixture(2);
    let child = coordinator
        .create_child(
            request(root, root_session, "child", 0),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    coordinator
        .resolve_submission(child.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("submission failed: {error:?}"));

    let snapshot = coordinator.snapshot();
    assert_eq!(snapshot.sessions().len(), 2);
    assert!(snapshot.sessions().iter().any(|session| {
        session.id == child.base_session_id
            && session.parent == Some(root_session)
            && session.creator_task == Some(child.task_id)
    }));

    let join = task_control(TaskControlSiteKind::Join, 1, "child");
    let ownership = match coordinator
        .begin_join(root, &join, &[child.handle_id])
        .unwrap_or_else(|error| panic!("join start failed: {error:?}"))
    {
        gantry::runtime::JoinStartV1::Started(ownership) => ownership,
        gantry::runtime::JoinStartV1::Empty => panic!("nonempty join was empty"),
    };
    let mut wait = Box::pin(
        coordinator
            .wait_for_join(ownership, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("join wait failed: {error:?}")),
    );
    assert!(poll_once(wait.as_mut(), Waker::noop()).is_pending());

    coordinator
        .settle_task(
            child.task_id,
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("child settlement failed: {error:?}"));
    assert!(matches!(
        poll_once(wait.as_mut(), Waker::noop()),
        Poll::Ready(Ok(gantry::runtime::JoinResolutionV1::Succeeded(value)))
            if value == LogicalValue::unit()
    ));
}

#[test]
fn shutdown_quiescence_requires_physical_driver_completion() {
    let (coordinator, root, _) = fixture(1);
    let outcome = MachineOutcome::Succeeded(LogicalValue::unit());
    coordinator
        .settle_task(root, outcome)
        .unwrap_or_else(|error| panic!("root settlement failed: {error:?}"));
    assert_eq!(
        coordinator
            .snapshot()
            .state()
            .task_record(root)
            .map(|task| task.driver_ownership()),
        Some(TaskDriverOwnershipV1::Supervised)
    );

    let mut wait = Box::pin(coordinator.wait_for_shutdown_quiescence());
    let probe = Arc::new(PublicationProbe::new(coordinator.clone()));
    let waker = Waker::from(Arc::clone(&probe));
    assert!(poll_once(wait.as_mut(), &waker).is_pending());
    assert!(
        coordinator
            .mark_driver_physically_settled(root)
            .unwrap_or_else(|error| panic!("physical settlement failed: {error:?}"))
    );
    assert_eq!(probe.wakes.load(Ordering::Acquire), 1);
    assert!(probe.observed_unlocked.load(Ordering::Acquire));
    assert!(poll_once(wait.as_mut(), Waker::noop()).is_ready());
    assert!(
        !coordinator
            .mark_driver_physically_settled(root)
            .unwrap_or_else(|error| panic!("repeat physical settlement failed: {error:?}"))
    );
}

#[test]
fn shutdown_quiescence_wakes_when_semantic_settlement_follows_physical_completion() {
    let (coordinator, root, _) = fixture(1);
    assert!(
        coordinator
            .mark_driver_physically_settled(root)
            .unwrap_or_else(|error| panic!("physical settlement failed: {error:?}"))
    );

    let mut wait = Box::pin(coordinator.wait_for_shutdown_quiescence());
    let probe = Arc::new(PublicationProbe::new(coordinator.clone()));
    let waker = Waker::from(Arc::clone(&probe));
    assert!(poll_once(wait.as_mut(), &waker).is_pending());

    coordinator
        .settle_task(root, MachineOutcome::Succeeded(LogicalValue::unit()))
        .unwrap_or_else(|error| panic!("semantic settlement failed: {error:?}"));
    assert_eq!(probe.wakes.load(Ordering::Acquire), 1);
    assert!(probe.observed_unlocked.load(Ordering::Acquire));
    assert!(poll_once(wait.as_mut(), Waker::noop()).is_ready());
}

#[test]
fn join_and_detach_race_has_one_linearized_winner() {
    for occurrence in 0..64 {
        let (coordinator, root, root_session) = fixture(2);
        let child = coordinator
            .create_child(
                request(root, root_session, "child", occurrence),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
        coordinator
            .resolve_submission(child.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));

        let barrier = Arc::new(Barrier::new(3));
        let join_coordinator = coordinator.clone();
        let join_barrier = Arc::clone(&barrier);
        let join = task_control(TaskControlSiteKind::Join, 1, "child");
        let handle = child.handle_id;
        let join_thread = std::thread::spawn(move || {
            join_barrier.wait();
            join_coordinator.begin_join(root, &join, &[handle])
        });

        let detach_coordinator = coordinator.clone();
        let detach_barrier = Arc::clone(&barrier);
        let detach = task_control(TaskControlSiteKind::Detach, 2, "child");
        let detach_thread = std::thread::spawn(move || {
            detach_barrier.wait();
            detach_coordinator.detach(root, &detach, handle)
        });

        barrier.wait();
        let join_result = join_thread
            .join()
            .unwrap_or_else(|_| panic!("join race thread panicked"));
        let detach_result = detach_thread
            .join()
            .unwrap_or_else(|_| panic!("detach race thread panicked"));
        assert_ne!(join_result.is_ok(), detach_result.is_ok());
        assert!(
            matches!(join_result, Err(TaskStateError::ConsumedHandle))
                || matches!(detach_result, Err(TaskStateError::ConsumedHandle))
        );

        let state = coordinator.snapshot();
        let disposition = state
            .state()
            .task(child.task_id)
            .map(|task| task.handle_state())
            .unwrap_or_else(|| panic!("child task missing"));
        assert!(matches!(
            disposition,
            TaskHandleState::Joined | TaskHandleState::Detached
        ));
    }
}

#[test]
fn registration_and_settlement_interleavings_do_not_lose_wakeups() {
    for byte in 1..=64 {
        let execution = fresh(IdentityKind::Execution, byte);
        let root = ProtocolIdentity::derive(IdentityKind::Task, &[byte])
            .unwrap_or_else(|error| panic!("root identity failed: {error}"));
        let session = fresh(IdentityKind::Session, byte.saturating_add(64));
        let state = ConcurrentTaskStateV1::new(execution, root, 1)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let coordinator = ExecutionCoordinator::new(state, sessions)
            .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
        let barrier = Arc::new(Barrier::new(2));
        let publisher = coordinator.clone();
        let publisher_barrier = Arc::clone(&barrier);
        let thread = std::thread::spawn(move || {
            publisher_barrier.wait();
            publisher
                .settle_task(root, MachineOutcome::Succeeded(LogicalValue::unit()))
                .unwrap_or_else(|error| panic!("root settlement failed: {error:?}"));
        });

        let mut wait = Box::pin(
            coordinator
                .wait_for_task_settlement(root)
                .unwrap_or_else(|error| panic!("task wait failed: {error:?}")),
        );
        barrier.wait();
        let first = poll_once(wait.as_mut(), Waker::noop());
        thread
            .join()
            .unwrap_or_else(|_| panic!("settlement thread panicked"));
        if first.is_pending() {
            assert!(poll_once(wait.as_mut(), Waker::noop()).is_ready());
        }
    }
}

#[test]
fn settlement_and_cancellation_race_has_one_consistent_winner() {
    for byte in 1..=64 {
        let execution = fresh(IdentityKind::Execution, byte);
        let root = ProtocolIdentity::derive(IdentityKind::Task, &[byte, 1])
            .unwrap_or_else(|error| panic!("root identity failed: {error}"));
        let session = fresh(IdentityKind::Session, byte.saturating_add(64));
        let state = ConcurrentTaskStateV1::new(execution, root, 1)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let coordinator = ExecutionCoordinator::new(state, sessions)
            .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
        let barrier = Arc::new(Barrier::new(3));

        let settlement_coordinator = coordinator.clone();
        let settlement_barrier = Arc::clone(&barrier);
        let settlement = std::thread::spawn(move || {
            settlement_barrier.wait();
            settlement_coordinator
                .settle_task(root, MachineOutcome::Succeeded(LogicalValue::unit()))
        });

        let cancellation_coordinator = coordinator.clone();
        let cancellation_barrier = Arc::clone(&barrier);
        let cancellation = std::thread::spawn(move || {
            cancellation_barrier.wait();
            cancellation_coordinator.cancel_task_tree(root, "race-cancelled")
        });

        barrier.wait();
        settlement
            .join()
            .unwrap_or_else(|_| panic!("settlement race thread panicked"))
            .unwrap_or_else(|error| panic!("settlement race failed: {error:?}"));
        let cancelled = cancellation
            .join()
            .unwrap_or_else(|_| panic!("cancellation race thread panicked"))
            .unwrap_or_else(|error| panic!("cancellation race failed: {error:?}"));

        let snapshot = coordinator.snapshot();
        let status = snapshot
            .state()
            .task_record(root)
            .map(|task| task.status())
            .unwrap_or_else(|| panic!("root task disappeared"));
        match status {
            gantry::runtime::ConcurrentTaskStatusV1::Succeeded(_) => {
                assert!(cancelled.is_empty());
                assert_eq!(snapshot.state().task_cancellation_reason(root), None);
            }
            gantry::runtime::ConcurrentTaskStatusV1::Cancelled(reason) => {
                assert_eq!(cancelled, [root]);
                assert_eq!(reason.as_ref(), "race-cancelled");
                assert_eq!(
                    snapshot.state().task_cancellation_reason(root),
                    Some("race-cancelled")
                );
            }
            other => panic!("race left unexpected root status {other:?}"),
        }
    }
}

struct PublicationProbe {
    coordinator: ExecutionCoordinator,
    wakes: AtomicUsize,
    observed_unlocked: AtomicBool,
}

impl PublicationProbe {
    fn new(coordinator: ExecutionCoordinator) -> Self {
        Self {
            coordinator,
            wakes: AtomicUsize::new(0),
            observed_unlocked: AtomicBool::new(false),
        }
    }
}

impl Wake for PublicationProbe {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
        self.observed_unlocked
            .store(self.coordinator.try_snapshot().is_some(), Ordering::Release);
    }
}

fn fixture(maximum_tasks: u64) -> (ExecutionCoordinator, ProtocolIdentity, ProtocolIdentity) {
    let execution = fresh(IdentityKind::Execution, 1);
    let root = ProtocolIdentity::derive(IdentityKind::Task, b"coordinator-root")
        .unwrap_or_else(|error| panic!("root identity failed: {error}"));
    let root_session = fresh(IdentityKind::Session, 2);
    let state = ConcurrentTaskStateV1::new(execution, root, maximum_tasks)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let coordinator = ExecutionCoordinator::new(state, sessions)
        .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
    (coordinator, root, root_session)
}

fn request(
    parent_task_id: ProtocolIdentity,
    parent_session_id: ProtocolIdentity,
    handle: &str,
    occurrence: u64,
) -> TaskCreationRequestV1 {
    TaskCreationRequestV1 {
        parent_task_id,
        handle_name: Arc::from(handle),
        workflow: CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("workflow path failed: {error}")),
        spawn_site: StructuralPosition::new(vec![0])
            .unwrap_or_else(|error| panic!("spawn site failed: {error}")),
        spawn_occurrence: occurrence,
        result_type: TypeDescriptor::UNIT,
        captures: Vec::new(),
        inherited_agent: None,
        parent_session_id,
    }
}

fn task_control(kind: TaskControlSiteKind, position: u64, handle: &str) -> TaskControlSite {
    let workflow = CanonicalPath::new("crate::main")
        .unwrap_or_else(|error| panic!("workflow path failed: {error}"));
    let position = StructuralPosition::new(vec![position])
        .unwrap_or_else(|error| panic!("control site failed: {error}"));
    TaskControlSite {
        id: StaticSiteId::new(workflow, position),
        kind,
        handles: vec![Arc::from(handle)],
        source: source_span(),
    }
}

fn source_span() -> SourceSpan {
    let limits = SourceLimits::new(1, 64, 64, 1, 1)
        .unwrap_or_else(|error| panic!("source limits failed: {error:?}"));
    let mut builder = SourceSnapshotBuilder::new(limits);
    let id = builder
        .add_file("main.gnt", b"join(child)")
        .unwrap_or_else(|error| panic!("source fixture failed: {error:?}"));
    let snapshot = builder.finish();
    let record = snapshot
        .get(&id)
        .unwrap_or_else(|| panic!("source record missing"));
    SourceSpan::new(
        record,
        ByteSpan::new(0, 1).unwrap_or_else(|error| panic!("byte span failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("source span failed: {error:?}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"))
}

fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
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
