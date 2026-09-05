//! Committed sequential-root publication and rejected-cut atomicity.

use super::*;
use crate::{
    CanonicalTranscriptV1, DurableCommitCutV1, DurableLogicalEvidenceV3, Machine, MachineLabel,
    MachineLimits, MachineStep, recover_authoritative_prefix,
};
use gantry_core::portable::IdentityKind;
use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use gantry_host::journal::{
    FullJournalPrefixV1, JournalEvidenceEnvelopeV1, JournalId, JournalPrefixV1,
};
use gantry_ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, TypeDescriptor,
    Workflow,
};

#[test]
fn committed_root_publication_is_atomic_and_rejects_repeated_cuts() {
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [31; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [32; 32])
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let path = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path: {error}"));
    let program = Arc::new(
        MachineProgram::new(vec![Workflow {
            path: path.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let limits = MachineLimits::new(100, 10, 10, 10, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program.clone(), &path, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let task = machine.task_id();
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("sessions: {error:?}"));
    let coordinator = ExecutionCoordinator::new_with_budget(
        ConcurrentTaskStateV1::new(execution, task, 10)
            .unwrap_or_else(|error| panic!("tasks: {error:?}")),
        sessions.clone(),
        machine.execution_budget(),
    )
    .unwrap_or_else(|error| panic!("coordinator: {error:?}"));
    for _ in 0..10 {
        if matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::TaskSettled(_))
        ) {
            break;
        }
    }
    let evidence = DurableLogicalEvidenceV3::new_with_sessions(
        execution,
        task,
        DurableCommitCutV1::TaskSettlement,
        None,
        &machine,
        Some(sessions.checkpoint()),
    )
    .unwrap_or_else(|error| panic!("evidence: {error:?}"));
    let journal =
        JournalId::new("root-publication").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: journal.clone(),
        committed_through: 1,
        evidence: Arc::from([JournalEvidenceEnvelopeV1 {
            journal_id: journal,
            sequence: 1,
            evidence_id: ProtocolIdentity::from_storage_material([1; 32]),
            kind: Arc::from("gantry.logical-evidence/v3"),
            canonical_body: Arc::from(evidence.canonical_body()),
            references: Arc::from([]),
            protected_payloads: Arc::from([]),
        }]),
    });
    let recovered = recover_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    coordinator
        .publish_committed_root(&recovered)
        .unwrap_or_else(|error| panic!("publish: {error:?}"));
    let snapshot = coordinator.snapshot();
    assert_eq!(snapshot.state().root_settled_outcome(), machine.outcome());
    assert_eq!(
        snapshot.execution_budget(),
        Some(machine.budget_checkpoint())
    );
    let retained = coordinator
        .committed_root()
        .unwrap_or_else(|| panic!("missing committed root"));
    assert_eq!(
        retained.machine().checkpoint(),
        recovered.machine().checkpoint()
    );
    assert_eq!(retained.events(), recovered.events());
    assert!(coordinator.publish_committed_root(&recovered).is_err());
    assert_eq!(coordinator.snapshot(), snapshot);
}
