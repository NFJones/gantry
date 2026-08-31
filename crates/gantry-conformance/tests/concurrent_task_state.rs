//! Public conformance coverage for concurrent task creation and scheduler state.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::{CanonicalPath, EffectSet, StructuralPosition, TypeDescriptor};
use gantry::portable::{IdentityKind, RuntimeErrorCategory, TaskHandleState, TaskStatusKind};
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
    Instruction, InstructionKind, LogicalSessionRegistryV1, Machine, MachineLabel, MachineLimits,
    MachineProgram, MachineStep, Parameter, SessionCreationModeV1, TaskCaptureV1,
    TaskCreationRequestV1, TaskStateError, Workflow,
};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};
use serde::Deserialize;

const CREATION_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_task_state.rs#public_task_creation_is_bounded_stable_and_snapshot_isolated";
const SCHEDULER_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_task_state.rs#public_submission_and_scheduler_preserve_one_shared_machine_path";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
    profile: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
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

#[test]
fn reviewed_concurrent_task_state_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/concurrent-task-state-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.concurrent-task-state-evidence/v1");
    assert_eq!(manifest.issue, "GNT-CON-001");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(manifest.exclusions.len(), 5);

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            CREATION_EVIDENCE | SCHEDULER_EVIDENCE
        ));
        entries
            .entry((entry.requirement, entry.clause, entry.profile))
            .or_default()
            .push(entry.evidence);
    }

    for ((requirement, clause_key, profile_name), evidence) in entries {
        let profile = review
            .requirements
            .iter()
            .find(|candidate| candidate.id == requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == clause_key)
            })
            .and_then(|clause| {
                clause
                    .profile_reviews
                    .iter()
                    .find(|profile| profile.profile == profile_name)
            })
            .unwrap_or_else(|| {
                panic!("missing {profile_name} review for {requirement}:{clause_key}")
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, evidence);
    }
}

#[test]
fn public_task_creation_is_bounded_stable_and_snapshot_isolated() {
    let execution = fresh(IdentityKind::Execution, 1);
    let root_task = derived_task(b"{\"root\":true}");
    let root_session = fresh(IdentityKind::Session, 2);
    let mut state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let parent_value = LogicalValue::boolean(false);
    let capture = TaskCaptureV1::new(
        Arc::from("flag"),
        TypeDescriptor::BOOL,
        true,
        &parent_value,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("capture failed: {error:?}"));

    let created = state
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 0, vec![capture]),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
    let task = state
        .task(created.task_id)
        .unwrap_or_else(|| panic!("created task missing"));
    assert_eq!(state.created_task_count(), 2);
    assert_eq!(state.maximum_task_count(), 2);
    assert_eq!(task.parent_task_id(), root_task);
    assert_eq!(task.handle_name(), "child");
    assert_eq!(task.handle_id(), created.handle_id);
    assert_eq!(task.handle_id().owner(), root_task);
    assert_eq!(task.handle_id().child(), created.task_id);
    assert_eq!(task.handle_state(), TaskHandleState::Attached);
    assert_eq!(task.status().kind(), TaskStatusKind::Submitting);
    assert!(!task.handle_is_visible());
    assert!(state.parent_is_suspended(root_task));
    assert_eq!(created.transition.task_id, created.task_id);
    assert_eq!(created.transition.parent_task_id, root_task);
    assert_eq!(created.transition.workflow, path("crate::main"));
    assert_eq!(created.transition.spawn_site, site(0));
    assert_eq!(created.transition.spawn_occurrence, 0);
    assert_eq!(created.transition.result_type, TypeDescriptor::UNIT);
    assert_eq!(created.transition.attachment, TaskHandleState::Attached);
    assert_eq!(task.task_path(), [Arc::from("spawn:crate::main:0:0")]);
    assert_eq!(task.base_session_id(), created.base_session_id);
    assert_eq!(
        sessions
            .get(created.base_session_id)
            .and_then(|session| session.parent),
        Some(root_session)
    );

    state
        .replace_capture(
            created.task_id,
            "flag",
            &[],
            &LogicalValue::boolean(true),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("capture replacement failed: {error:?}"));
    assert!(matches!(parent_value.view(), LogicalValueView::Bool(false)));
    assert!(matches!(
        state
            .task(created.task_id)
            .and_then(|record| record.captures().get("flag"))
            .map(TaskCaptureV1::value)
            .map(LogicalValue::view),
        Some(LogicalValueView::Bool(true))
    ));

    state
        .resolve_submission(created.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("submission resolution failed: {error:?}"));
    assert!(!state.parent_is_suspended(root_task));

    assert_eq!(
        state.create_child(
            &mut sessions,
            creation_request(root_task, root_session, 1, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        ),
        Err(TaskStateError::TaskCountLimit)
    );
    assert_eq!(state.created_task_count(), 2);
}

#[test]
fn public_submission_and_scheduler_preserve_one_shared_machine_path() {
    let execution = fresh(IdentityKind::Execution, 3);
    let root_task = derived_task(b"{\"root\":true}");
    let root_session = fresh(IdentityKind::Session, 4);
    let state = ConcurrentTaskStateV1::new(execution, root_task, 3)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let mut scheduler = ConcurrentSchedulerV1::new(state);
    let first = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 0, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
    scheduler
        .resolve_submission(first.task_id, Ok(child_machine(execution, root_session)))
        .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
    let second = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 1, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
    scheduler
        .resolve_submission(
            second.task_id,
            Err(gantry::host::contracts::HostError {
                code: Arc::from("queue-closed"),
                protected_diagnostic: Some(Arc::from("executor-1")),
            }),
        )
        .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));

    let failed = scheduler
        .state()
        .task(second.task_id)
        .unwrap_or_else(|| panic!("failed task missing"));
    assert!(failed.handle_is_visible());
    assert_eq!(failed.handle_id(), second.handle_id);
    assert!(matches!(
        failed.status(),
        ConcurrentTaskStatusV1::Failed(failure)
            if failure.category == RuntimeErrorCategory::ExecutorFailure
                && failure.code.as_ref() == "queue-closed"
    ));

    let deterministic = scheduler
        .step_next()
        .unwrap_or_else(|error| panic!("scheduler step failed: {error:?}"))
        .unwrap_or_else(|| panic!("submitted task was not runnable"));
    assert_eq!(deterministic.task_id, first.task_id);
    assert!(matches!(
        deterministic.step,
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let settlement = scheduler
        .step_next()
        .unwrap_or_else(|error| panic!("scheduler settlement failed: {error:?}"))
        .unwrap_or_else(|| panic!("submitted task did not settle"));
    assert_eq!(settlement.task_id, first.task_id);
    assert!(matches!(
        settlement.step,
        MachineStep::Transition(MachineLabel::TaskSettled(_))
    ));
    assert!(matches!(
        scheduler
            .state()
            .task(first.task_id)
            .map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Succeeded(_))
    ));
    assert_eq!(scheduler.step_next(), Ok(None));
}

fn creation_request(
    parent_task_id: ProtocolIdentity,
    parent_session_id: ProtocolIdentity,
    spawn_occurrence: u64,
    captures: Vec<TaskCaptureV1>,
) -> TaskCreationRequestV1 {
    TaskCreationRequestV1 {
        parent_task_id,
        handle_name: Arc::from("child"),
        workflow: path("crate::main"),
        spawn_site: site(0),
        spawn_occurrence,
        result_type: TypeDescriptor::UNIT,
        captures,
        inherited_agent: Some(Arc::from("writer")),
        parent_session_id,
    }
}

fn child_machine(execution: ProtocolIdentity, session: ProtocolIdentity) -> Machine {
    let root = path("crate::child");
    let program = MachineProgram::new(vec![Workflow {
        path: root.clone(),
        parameters: Vec::<Parameter>::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: site(0),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: site(1),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("child program failed: {error:?}"));
    Machine::new_concurrent_task_with_context(
        Arc::new(program),
        &root,
        Vec::new(),
        execution,
        MachineLimits::new(16, 1, 1, 4, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive child limits")),
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("child machine failed: {error:?}"))
}

fn session_registry(
    execution: ProtocolIdentity,
    root_session: ProtocolIdentity,
) -> LogicalSessionRegistryV1 {
    LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"))
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn site(value: u64) -> StructuralPosition {
    StructuralPosition::new(vec![value]).unwrap_or_else(|error| panic!("site failed: {error}"))
}

fn derived_task(key: &[u8]) -> ProtocolIdentity {
    ProtocolIdentity::derive(IdentityKind::Task, key)
        .unwrap_or_else(|error| panic!("task identity failed: {error}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
