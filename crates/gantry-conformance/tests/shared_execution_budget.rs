//! Narrow public conformance evidence for execution-wide and task-local budgets.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::host::journal::{
    FullJournalPrefixV1, JournalEvidenceEnvelopeV1, JournalId, JournalPrefixV1,
    SnapshotJournalPrefixV1,
};
use gantry::identity::ProtocolIdentity;
use gantry::ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
    StructuralPosition, TypeDescriptor, Workflow,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentDurableCheckpointError, ConcurrentDurableCheckpointV3,
    ConcurrentSchedulerV1, ConcurrentTaskStateV1, DurableCommitCutV1, DurableLogicalEvidenceV3,
    ExecutionBudget, ExecutionBudgetSnapshot, ExecutionCoordinator, LogicalSessionRegistryV1,
    Machine, MachineLabel, MachineLimits, MachineOutcome, MachineStep, RuntimeCode,
    SessionCreationModeV1, TaskCreationRequestV1, TaskStateError, recover_authoritative_prefix,
};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use serde::Deserialize;

const MANIFEST_PATH: &str = "protocol/conformance/shared-execution-budget-v1.json";
const CANONICAL_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#canonical_budget_and_task_checkpoints_preserve_continuation";
const COMPACTION_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#full_and_compacted_prefixes_restore_the_same_budget_frontier";
const OWNERSHIP_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#coordinator_and_scheduler_retain_the_exact_execution_budget_owner";
const OPERATION_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#root_and_child_share_one_logical_operation_limit";
const TRANSITION_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#root_and_child_share_one_deterministic_transition_limit";
const LOCAL_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#loop_and_yield_limits_remain_task_local";
const TORN_EVIDENCE: &str = "crates/gantry-conformance/tests/shared_execution_budget.rs#continuously_torn_combined_capture_is_rejected";

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
fn checked_in_shared_execution_budget_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest = read_json(&root.join(MANIFEST_PATH));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(
        manifest.format,
        "gantry.shared-execution-budget-evidence/v1"
    );
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-BUD-001");
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
            CANONICAL_EVIDENCE,
            COMPACTION_EVIDENCE,
            OWNERSHIP_EVIDENCE,
            OPERATION_EVIDENCE,
            TRANSITION_EVIDENCE,
            LOCAL_EVIDENCE,
            TORN_EVIDENCE,
        ]
    );
    assert_eq!(manifest.exclusions.len(), 6);

    let state_clause = review
        .requirements
        .iter()
        .find(|requirement| requirement.id == "GNT-3-M-STATE")
        .and_then(|requirement| {
            requirement
                .clauses
                .iter()
                .find(|clause| clause.key == "clause-002")
        })
        .unwrap_or_else(|| panic!("missing GNT-3-M-STATE clause-002 review"));
    assert_eq!(
        state_clause
            .profile_reviews
            .iter()
            .map(|review| (review.profile.as_str(), review.state.as_str()))
            .collect::<Vec<_>>(),
        [
            ("concurrent-evaluator", "planned"),
            ("durable-runtime", "planned"),
            ("evaluator", "planned"),
        ]
    );
    assert!(
        state_clause
            .profile_reviews
            .iter()
            .all(|review| review.evidence.is_empty())
    );
}

#[test]
fn root_and_child_share_one_deterministic_transition_limit() {
    let program = single_instruction_program(InstructionKind::Push(LogicalValue::unit()));
    let machine_limits = limits(1, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut root = root_machine(Arc::clone(&program), machine_limits, budget.clone());
    let (task_id, task_path) = standalone_child_coordinate();
    let mut child = child_machine(
        program,
        task_id,
        task_path,
        machine_limits,
        budget.clone(),
        None,
    );

    assert!(matches!(
        root.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        child.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::DeterministicTransitionBudget
    ));
    assert_eq!(budget.snapshot().remaining_transitions, 0);
    assert_eq!(budget.snapshot().revision, 1);
    assert_eq!(child.remaining_budgets(), (0, 1, 1));
}

#[test]
fn root_and_child_share_one_logical_operation_limit() {
    let program = single_instruction_program(InstructionKind::Operation);
    let machine_limits = limits(1, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut root = root_machine(Arc::clone(&program), machine_limits, budget.clone());
    let (task_id, task_path) = standalone_child_coordinate();
    let mut child = child_machine(
        program,
        task_id,
        task_path,
        machine_limits,
        budget.clone(),
        None,
    );

    assert!(matches!(
        root.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    assert!(matches!(
        child.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::OperationBudget
    ));
    assert_eq!(budget.snapshot().remaining_operations, 0);
    assert_eq!(budget.snapshot().revision, 1);
    assert_eq!(child.status(), gantry::runtime::MachineStatus::Failed);
}

#[test]
fn loop_and_yield_limits_remain_task_local() {
    let program = Arc::new(
        MachineProgram::new(vec![Workflow {
            path: path("crate::main"),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                instruction(
                    0,
                    InstructionKind::EnterLoop {
                        phase: gantry::runtime::LoopPhase::Body,
                        source_limit: None,
                    },
                ),
                instruction(1, InstructionKind::LeaveOccurrence),
                instruction(2, InstructionKind::Jump(0)),
            ],
        }])
        .unwrap_or_else(|error| panic!("program failed: {error:?}")),
    );
    let machine_limits = limits(16, 1, 1, 1, 1);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut root = root_machine(Arc::clone(&program), machine_limits, budget.clone());
    let (task_id, task_path) = standalone_child_coordinate();
    let mut child = child_machine(program, task_id, task_path, machine_limits, budget, None);

    assert!(matches!(root.step(), MachineStep::Transition(_)));
    assert!(matches!(child.step(), MachineStep::Transition(_)));
    assert_eq!(root.remaining_budgets().2, 0);
    assert_eq!(child.remaining_budgets().2, 0);
    assert!(root.resume_after_yield());
    for _ in 0..2 {
        assert!(matches!(root.step(), MachineStep::Transition(_)));
        assert!(root.resume_after_yield());
    }
    assert!(matches!(
        root.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::LoopIterationBudget
    ));
    assert!(child.resume_after_yield());
}

#[test]
fn coordinator_and_scheduler_retain_the_exact_execution_budget_owner() {
    let machine_limits = limits(8, 2, 2, 2, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let state = ConcurrentTaskStateV1::new(execution(), root_task(), 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = sessions();
    let coordinator =
        ExecutionCoordinator::new_with_budget(state.clone(), sessions.clone(), budget.clone())
            .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
    let program = single_instruction_program(InstructionKind::Push(LogicalValue::unit()));
    let mut root = root_machine(Arc::clone(&program), machine_limits, budget.clone());
    assert!(matches!(root.step(), MachineStep::Transition(_)));
    assert_eq!(
        coordinator.snapshot().execution_budget(),
        Some(budget.snapshot())
    );

    let mut scheduler = ConcurrentSchedulerV1::new(state, budget.clone())
        .unwrap_or_else(|error| panic!("scheduler failed: {error:?}"));
    let created = scheduler
        .create_child(&mut sessions, child_request(), DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    let task_path = Arc::from(
        scheduler
            .state()
            .task(created.task_id)
            .unwrap_or_else(|| panic!("created task missing"))
            .task_path(),
    );
    let independent = ExecutionBudget::new(execution(), machine_limits);
    assert_eq!(
        scheduler.resolve_submission(
            created.task_id,
            Ok(child_machine(
                Arc::clone(&program),
                created.task_id,
                Arc::clone(&task_path),
                machine_limits,
                independent,
                Some(created.base_session_id),
            )),
        ),
        Err(TaskStateError::InvalidTaskMachine)
    );
    scheduler
        .resolve_submission(
            created.task_id,
            Ok(child_machine(
                program,
                created.task_id,
                task_path,
                machine_limits,
                budget.clone(),
                Some(created.base_session_id),
            )),
        )
        .unwrap_or_else(|error| panic!("shared child submission failed: {error:?}"));
    assert_eq!(scheduler.execution_budget(), budget.snapshot());
}

#[test]
fn canonical_budget_and_task_checkpoints_preserve_continuation() {
    let program = return_program();
    let machine_limits = limits(8, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut original = root_machine(Arc::clone(&program), machine_limits, budget);
    assert!(matches!(original.step(), MachineStep::Transition(_)));

    let task_checkpoint = original.checkpoint();
    let budget_checkpoint = original.budget_checkpoint();
    let task_bytes = task_checkpoint.canonical_bytes();
    let budget_bytes = budget_checkpoint.canonical_bytes();
    let decoded_task = gantry::runtime::MachineCheckpointV3::decode(&program, &task_bytes)
        .unwrap_or_else(|error| panic!("task checkpoint decode failed: {error:?}"));
    let decoded_budget = ExecutionBudgetSnapshot::decode(&budget_bytes)
        .unwrap_or_else(|error| panic!("budget checkpoint decode failed: {error:?}"));
    assert_eq!(decoded_task.canonical_bytes(), task_bytes);
    assert_eq!(decoded_budget.canonical_bytes(), budget_bytes);

    let recovered_budget = ExecutionBudget::recover_from_checkpoint(decoded_budget)
        .unwrap_or_else(|error| panic!("budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, decoded_task, recovered_budget)
        .unwrap_or_else(|error| panic!("machine recovery failed: {error:?}"));
    assert_eq!(drive(&mut original), drive(&mut recovered));
    assert_eq!(original.budget_checkpoint(), recovered.budget_checkpoint());
}

#[test]
fn full_and_compacted_prefixes_restore_the_same_budget_frontier() {
    let program = return_program();
    let machine_limits = limits(8, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut machine = root_machine(Arc::clone(&program), machine_limits, budget);
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let evidence = DurableLogicalEvidenceV3::new(
        execution(),
        root_task(),
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
    )
    .unwrap_or_else(|error| panic!("logical evidence failed: {error:?}"));
    let evidence_id = ProtocolIdentity::from_storage_material([9; 32]);
    let envelope = JournalEvidenceEnvelopeV1 {
        journal_id: journal_id(),
        sequence: 1,
        evidence_id,
        kind: Arc::from("gantry.logical-evidence/v3"),
        canonical_body: Arc::from(evidence.canonical_body()),
        references: Arc::from([]),
        protected_payloads: Arc::from([]),
    };
    let full = JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: journal_id(),
        evidence: Arc::from([envelope]),
        committed_through: 1,
    });
    let compacted = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: journal_id(),
        snapshot_version: 5,
        frontier: 1,
        canonical_snapshot: Arc::from(evidence.canonical_body()),
        retained_evidence: BTreeMap::from([(evidence_id, 1)]),
        suffix: Arc::from([]),
        committed_through: 1,
    });

    let full_recovery = recover_authoritative_prefix(Arc::clone(&program), &full)
        .unwrap_or_else(|error| panic!("full recovery failed: {error:?}"));
    let compacted_recovery = recover_authoritative_prefix(program, &compacted)
        .unwrap_or_else(|error| panic!("compacted recovery failed: {error:?}"));
    assert_eq!(
        full_recovery.machine().budget_checkpoint(),
        compacted_recovery.machine().budget_checkpoint()
    );
    assert_eq!(
        drive(&mut full_recovery.into_machine()),
        drive(&mut compacted_recovery.into_machine())
    );
}

#[test]
fn continuously_torn_combined_capture_is_rejected() {
    let program = single_instruction_program(InstructionKind::Push(LogicalValue::unit()));
    let machine_limits = limits(16, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let foreground = root_machine(Arc::clone(&program), machine_limits, budget.clone());
    let scheduler = ConcurrentSchedulerV1::new(
        ConcurrentTaskStateV1::new(execution(), root_task(), 1)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}")),
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("scheduler failed: {error:?}"));
    let sessions = sessions();
    let (task_id, task_path) = standalone_child_coordinate();
    let mut racers = (0..8)
        .map(|_| {
            child_machine(
                Arc::clone(&program),
                task_id,
                Arc::clone(&task_path),
                machine_limits,
                budget.clone(),
                None,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        ConcurrentDurableCheckpointV3::capture_with_test_interleaving(
            &foreground,
            &scheduler,
            &sessions,
            |attempt| {
                assert!(matches!(racers[attempt].step(), MachineStep::Transition(_)));
            },
        ),
        Err(ConcurrentDurableCheckpointError::CaptureRace)
    );
}

fn root_machine(
    program: Arc<MachineProgram>,
    machine_limits: MachineLimits,
    budget: ExecutionBudget,
) -> Machine {
    Machine::new_with_budget(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget,
    )
    .unwrap_or_else(|error| panic!("root machine failed: {error:?}"))
}

fn child_machine(
    program: Arc<MachineProgram>,
    task_id: ProtocolIdentity,
    task_path: Arc<[Arc<str>]>,
    machine_limits: MachineLimits,
    budget: ExecutionBudget,
    session: Option<ProtocolIdentity>,
) -> Machine {
    Machine::new_concurrent_task_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        task_id,
        task_path,
        machine_limits,
        budget,
        None,
        session,
    )
    .unwrap_or_else(|error| panic!("child machine failed: {error:?}"))
}

fn standalone_child_coordinate() -> (ProtocolIdentity, Arc<[Arc<str>]>) {
    let execution = execution();
    let task_path = Arc::from([Arc::from("spawn:crate::main:0:0")]);
    let key = format!("{{\"execution\":\"{execution}\",\"path\":[\"spawn:crate::main:0:0\"]}}");
    let task_id = ProtocolIdentity::derive(IdentityKind::Task, key.as_bytes())
        .unwrap_or_else(|error| panic!("child task identity failed: {error}"));
    (task_id, task_path)
}

fn single_instruction_program(kind: InstructionKind) -> Arc<MachineProgram> {
    program(vec![instruction(0, kind)])
}

fn return_program() -> Arc<MachineProgram> {
    program(vec![
        instruction(0, InstructionKind::Push(LogicalValue::unit())),
        instruction(1, InstructionKind::Return),
    ])
}

fn program(instructions: Vec<Instruction>) -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(vec![Workflow {
            path: path("crate::main"),
            parameters: Vec::<Parameter>::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions,
        }])
        .unwrap_or_else(|error| panic!("program failed: {error:?}")),
    )
}

fn instruction(index: u64, kind: InstructionKind) -> Instruction {
    Instruction {
        site: StructuralPosition::new(vec![index])
            .unwrap_or_else(|error| panic!("site failed: {error}")),
        ty: TypeDescriptor::UNIT,
        kind,
    }
}

fn limits(
    transitions: u64,
    operations: u64,
    loops: u64,
    depth: u64,
    quantum: u64,
) -> MachineLimits {
    MachineLimits::new(
        transitions,
        operations,
        loops,
        depth,
        quantum,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|| panic!("positive machine limits failed"))
}

fn sessions() -> LogicalSessionRegistryV1 {
    LogicalSessionRegistryV1::new(
        execution(),
        root_session(),
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"))
}

fn child_request() -> TaskCreationRequestV1 {
    TaskCreationRequestV1 {
        parent_task_id: root_task(),
        handle_name: Arc::from("child"),
        workflow: path("crate::main"),
        spawn_site: StructuralPosition::new(vec![0])
            .unwrap_or_else(|error| panic!("spawn site failed: {error}")),
        spawn_occurrence: 0,
        result_type: TypeDescriptor::UNIT,
        captures: Vec::new(),
        inherited_agent: None,
        parent_session_id: root_session(),
    }
}

fn drive(machine: &mut Machine) -> MachineOutcome {
    for _ in 0..16 {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::Complete(outcome) => return outcome,
            other => panic!("machine remained blocked: {other:?}"),
        }
    }
    panic!("machine did not terminate within the fixture bound")
}

fn execution() -> ProtocolIdentity {
    fresh(IdentityKind::Execution, 1)
}

fn root_task() -> ProtocolIdentity {
    ProtocolIdentity::derive(IdentityKind::Task, b"shared-budget-root")
        .unwrap_or_else(|error| panic!("root task identity failed: {error}"))
}

fn root_session() -> ProtocolIdentity {
    fresh(IdentityKind::Session, 2)
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"))
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn journal_id() -> JournalId {
    JournalId::new("shared-execution-budget")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"))
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
