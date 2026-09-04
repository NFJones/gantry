//! Public conformance coverage for durable logical evidence and recovery projection.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{HookOutcomeV1, JournalStorage};
use gantry::host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, FullJournalPrefixV1, JournalCommitRequestV1,
    JournalEvidenceEnvelopeV1, JournalId, JournalOwnerOperationV1, JournalPrefixV1,
    ReadJournalPrefixV1, SnapshotJournalPrefixV1,
};
use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, StructuralPosition,
    TypeDescriptor, Workflow,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    CanonicalTranscriptV1, DurableCommitCoordinatorV1, DurableCommitCutV1, DurableEvidenceError,
    DurableLogicalEvidenceV2, DurableOperationEvidenceV1, DurableOperationRecoveryV1,
    DurableTransitionSink, InMemoryJournalStore, LogicalSessionRegistryV1, Machine, MachineLimits,
    MachineOutcome, MachineStep, SessionCreationModeV1, SessionEstablishmentV1,
    ValidationErrorCategoryV1, ValidationErrorV1, recover_authoritative_prefix,
};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use serde::Deserialize;

const PREFIX_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_committed_and_compacted_prefixes_restore_the_same_machine_and_sessions";
const OPERATION_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_operation_cuts_reuse_committed_payloads_and_classify_indeterminate_dispatch";
const CORRUPTION_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_recovery_rejects_corruption_invalid_causality_and_operation_order";
const CUT_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_non_operation_commit_cuts_recover_without_reapplying_fixed_state";
const COMMIT_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_commit_coordinator_awaits_contiguous_causal_cuts";
const EVENT_COMPACTION_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_events.rs#public_full_and_compacted_event_prefixes_project_equivalently";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    reviewed_clauses: Vec<ReviewedClauseLink>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
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

#[derive(Debug, Deserialize)]
struct RecoveryVectors {
    format: String,
    checkpoint_formats: Vec<String>,
    commit_cuts: Vec<String>,
    operation_recovery: Vec<String>,
    prefix_forms: Vec<String>,
    cases: Vec<String>,
}

#[test]
fn checked_in_durable_recovery_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/durable-recovery-v1.json"));
    let vectors: RecoveryVectors =
        read_json(&root.join("protocol/goldens/durable-recovery-v1.json"));
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/durable-recovery-v1.schema.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.durable-recovery-evidence/v1");
    assert_eq!(manifest.issue, "GNT-DUR-002");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(
        manifest
            .reviewed_clauses
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(manifest.exclusions.len(), 4);
    for capability in &manifest.capabilities {
        assert!(matches!(
            capability.evidence.as_str(),
            PREFIX_EVIDENCE
                | OPERATION_EVIDENCE
                | CORRUPTION_EVIDENCE
                | CUT_EVIDENCE
                | COMMIT_EVIDENCE
                | EVENT_COMPACTION_EVIDENCE
        ));
    }

    for link in manifest.reviewed_clauses {
        if !evidence_is_current {
            continue;
        }
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

    assert_eq!(vectors.format, "gantry.durable-recovery-vectors/v1");
    assert_eq!(vectors.checkpoint_formats.len(), 4);
    assert_eq!(vectors.commit_cuts.len(), 9);
    assert_eq!(vectors.operation_recovery.len(), 5);
    assert_eq!(vectors.prefix_forms, ["full-prefix", "snapshot-prefix"]);
    assert_eq!(vectors.cases.len(), 5);
    assert_eq!(schema["properties"]["format"]["const"], vectors.format);
}

#[test]
fn public_committed_and_compacted_prefixes_restore_the_same_machine_and_sessions() {
    let program = value_program();
    let mut machine = machine(Arc::clone(&program));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));

    let root_session = fresh(IdentityKind::Session, 3);
    let mut sessions = LogicalSessionRegistryV1::new(
        execution(),
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let fork = sessions
        .create(
            root_session,
            root_task(),
            StructuralPosition::new(vec![9])
                .unwrap_or_else(|error| panic!("session site failed: {error}")),
            0,
            SessionCreationModeV1::Fork,
            SessionEstablishmentV1::Separate,
        )
        .unwrap_or_else(|error| panic!("fork session failed: {error:?}"))
        .id;
    let evidence = DurableLogicalEvidenceV2::new_with_sessions(
        execution(),
        root_task(),
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
        Some(sessions.checkpoint()),
    )
    .unwrap_or_else(|error| panic!("logical evidence failed: {error:?}"));

    let store = InMemoryJournalStore::new();
    let journal_id = journal_id();
    let owner = block_on(store.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
    let local = BatchLocalEvidenceId::new("checkpoint")
        .unwrap_or_else(|error| panic!("local id failed: {error:?}"));
    let batch = gantry::host::journal::JournalBatchV1::new(
        vec![
            evidence
                .unfinalized(local, Vec::new())
                .unwrap_or_else(|error| panic!("evidence body failed: {error:?}")),
        ],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("journal batch failed: {error:?}"));
    let receipt = block_on(store.commit(JournalCommitRequestV1 {
        journal_id: journal_id.clone(),
        ownership_token: owner.token,
        batch,
    }))
    .unwrap_or_else(|error| panic!("commit failed: {error:?}"));
    let full = block_on(store.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"));
    let full_recovery = recover_authoritative_prefix(Arc::clone(&program), &full)
        .unwrap_or_else(|error| panic!("full-prefix recovery failed: {error:?}"));
    assert_eq!(full_recovery.latest_sequence(), 1);
    assert_eq!(
        full_recovery.latest_evidence_id(),
        receipt.entries[0].evidence_id
    );
    assert_eq!(full_recovery.latest_cut(), DurableCommitCutV1::Checkpoint);
    assert_eq!(
        full_recovery
            .sessions()
            .and_then(|sessions| sessions.get(root_session))
            .map(|session| session.transcript.bytes()),
        Some(CanonicalTranscriptV1::empty().bytes())
    );
    assert_eq!(
        full_recovery
            .sessions()
            .and_then(|sessions| sessions.get(fork))
            .and_then(|session| session.parent),
        Some(root_session)
    );

    let snapshot = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id,
        snapshot_version: 3,
        frontier: 1,
        canonical_snapshot: Arc::from(evidence.canonical_body()),
        retained_evidence: std::collections::BTreeMap::from([(receipt.entries[0].evidence_id, 1)]),
        suffix: Arc::from([]),
        committed_through: 1,
    });
    let mut stale_selector_snapshot = snapshot.clone();
    let JournalPrefixV1::Snapshot(stale_selector) = &mut stale_selector_snapshot else {
        unreachable!("cloned compacted prefix changed form");
    };
    stale_selector.snapshot_version = 1;
    assert_eq!(
        recover_authoritative_prefix(Arc::clone(&program), &stale_selector_snapshot).map(|_| ()),
        Err(DurableEvidenceError::Encoding)
    );
    let compacted = recover_authoritative_prefix(program, &snapshot)
        .unwrap_or_else(|error| panic!("snapshot recovery failed: {error:?}"));
    assert_eq!(compacted.latest_sequence(), full_recovery.latest_sequence());
    assert_eq!(compacted.latest_cut(), full_recovery.latest_cut());
    assert_eq!(
        drive(compacted.into_machine()),
        drive(full_recovery.into_machine())
    );
}

#[test]
fn public_operation_cuts_reuse_committed_payloads_and_classify_indeterminate_dispatch() {
    let program = operation_program();
    let mut machine = machine(Arc::clone(&program));
    let occurrence = match machine.step() {
        MachineStep::Transition(gantry::runtime::MachineLabel::OperationPrepared(occurrence)) => {
            occurrence
        }
        other => panic!("operation was not prepared: {other:?}"),
    };
    let dispatch = fresh(IdentityKind::Dispatch, 4);
    let request = request_bytes(occurrence.identity, dispatch);

    let prepared = operation_evidence(
        &machine,
        occurrence.identity,
        Some(dispatch),
        DurableCommitCutV1::OperationPrepared,
        Some(RecoveryClass::ReadOnly),
        Some(Arc::clone(&request)),
        None,
        Arc::from([]),
        None,
        None,
        None,
    );
    let prepared_envelope = envelope(1, 1, &prepared, &[]);
    let recovered = recover_authoritative_prefix(
        Arc::clone(&program),
        &full_prefix(vec![prepared_envelope.clone()]),
    )
    .unwrap_or_else(|error| panic!("prepared recovery failed: {error:?}"));
    assert_eq!(
        recovered.operation_recovery(),
        &DurableOperationRecoveryV1::Redispatch {
            operation_id: occurrence.identity,
            previous_dispatch_id: dispatch,
            validation_attempt: 0,
            next_recovery_dispatch: 1,
            action_recovery: Some(RecoveryClass::ReadOnly),
            request_bytes: Arc::clone(&request),
        }
    );

    let non_idempotent = operation_evidence(
        &machine,
        occurrence.identity,
        Some(dispatch),
        DurableCommitCutV1::OperationPrepared,
        Some(RecoveryClass::NonIdempotent),
        Some(Arc::clone(&request)),
        None,
        Arc::from([]),
        None,
        None,
        None,
    );
    let recovered = recover_authoritative_prefix(
        Arc::clone(&program),
        &full_prefix(vec![envelope(1, 1, &non_idempotent, &[])]),
    )
    .unwrap_or_else(|error| panic!("non-idempotent recovery failed: {error:?}"));
    assert_eq!(
        recovered.operation_recovery(),
        &DurableOperationRecoveryV1::UnknownOutcome {
            operation_id: occurrence.identity,
            dispatch_id: dispatch,
            request_bytes: Arc::clone(&request),
        }
    );

    let outcome_value = HookOutcomeV1::Completed(Arc::from(&b"invalid"[..]));
    let outcome = operation_evidence(
        &machine,
        occurrence.identity,
        Some(dispatch),
        DurableCommitCutV1::OperationOutcome,
        Some(RecoveryClass::ReadOnly),
        Some(Arc::clone(&request)),
        Some(outcome_value.clone()),
        Arc::from([]),
        None,
        None,
        None,
    );
    let outcome_envelope = envelope(2, 2, &outcome, &[prepared_envelope.evidence_id]);
    let retry_errors = Arc::from([ValidationErrorV1 {
        category: ValidationErrorCategoryV1::Schema,
        instance_location: Some(Arc::from("/value")),
        message: Arc::from("invalid value"),
        schema_location: Some(Arc::from("/type")),
    }]);
    let retry = operation_evidence(
        &machine,
        occurrence.identity,
        Some(dispatch),
        DurableCommitCutV1::RetryWaiting,
        Some(RecoveryClass::ReadOnly),
        Some(Arc::clone(&request)),
        Some(outcome_value.clone()),
        Arc::clone(&retry_errors),
        None,
        None,
        Some(17),
    );
    let recovered = recover_authoritative_prefix(
        Arc::clone(&program),
        &full_prefix(vec![
            prepared_envelope.clone(),
            outcome_envelope.clone(),
            envelope(3, 3, &retry, &[outcome_envelope.evidence_id]),
        ]),
    )
    .unwrap_or_else(|error| panic!("retry recovery failed: {error:?}"));
    assert_eq!(
        recovered.operation_recovery(),
        &DurableOperationRecoveryV1::RetryDelay {
            operation_id: occurrence.identity,
            delay_us: 17,
            validation_attempt: 0,
            recovery_dispatch: 0,
            retries_left: Some(2),
            request_bytes: Arc::clone(&request),
            outcome: outcome_value,
            errors: retry_errors,
        }
    );

    machine
        .complete_operation(occurrence.identity, LogicalValue::unit())
        .unwrap_or_else(|error| panic!("operation completion failed: {error:?}"));
    let result = operation_evidence(
        &machine,
        occurrence.identity,
        None,
        DurableCommitCutV1::OperationResult,
        Some(RecoveryClass::ReadOnly),
        None,
        None,
        Arc::from([]),
        Some(TypeDescriptor::UNIT),
        Some(Arc::from(&b"null"[..])),
        None,
    );
    let recovered = recover_authoritative_prefix(
        program,
        &full_prefix(vec![
            prepared_envelope,
            outcome_envelope.clone(),
            envelope(3, 4, &result, &[outcome_envelope.evidence_id]),
        ]),
    )
    .unwrap_or_else(|error| panic!("result recovery failed: {error:?}"));
    assert_eq!(
        recovered.operation_recovery(),
        &DurableOperationRecoveryV1::ReuseResult {
            operation_id: occurrence.identity,
            result_type: TypeDescriptor::UNIT,
            result_bytes: Arc::from(&b"null"[..]),
        }
    );
    assert_eq!(
        drive(recovered.into_machine()),
        MachineOutcome::Succeeded(LogicalValue::unit())
    );
}

#[test]
fn public_recovery_rejects_corruption_invalid_causality_and_operation_order() {
    let program = operation_program();
    let mut machine = machine(Arc::clone(&program));
    let occurrence = match machine.step() {
        MachineStep::Transition(gantry::runtime::MachineLabel::OperationPrepared(occurrence)) => {
            occurrence
        }
        other => panic!("operation was not prepared: {other:?}"),
    };
    let dispatch = fresh(IdentityKind::Dispatch, 5);
    let request = request_bytes(occurrence.identity, dispatch);
    let outcome = operation_evidence(
        &machine,
        occurrence.identity,
        Some(dispatch),
        DurableCommitCutV1::OperationOutcome,
        Some(RecoveryClass::ReadOnly),
        Some(request),
        Some(HookOutcomeV1::Completed(Arc::from(&b"null"[..]))),
        Arc::from([]),
        None,
        None,
        None,
    );
    assert_eq!(
        recover_authoritative_prefix(
            Arc::clone(&program),
            &full_prefix(vec![envelope(1, 1, &outcome, &[])])
        )
        .map(|_| ()),
        Err(DurableEvidenceError::InvalidOperationTransition)
    );

    let checkpoint = DurableLogicalEvidenceV2::new(
        execution(),
        root_task(),
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
    )
    .unwrap_or_else(|error| panic!("checkpoint evidence failed: {error:?}"));
    let first = envelope(1, 1, &checkpoint, &[]);
    let second = envelope(2, 2, &checkpoint, &[]);
    let invalid_causality = JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: journal_id(),
        evidence: Arc::from([first, second]),
        committed_through: 2,
    });
    assert_eq!(
        recover_authoritative_prefix(Arc::clone(&program), &invalid_causality).map(|_| ()),
        Err(DurableEvidenceError::InvalidCausalOrder)
    );

    let mut corrupt = checkpoint.canonical_body();
    let marker = b"\"checkpoint\":\"";
    let index = corrupt
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|index| index + marker.len())
        .unwrap_or_else(|| panic!("checkpoint field missing"));
    corrupt[index] = if corrupt[index] == b'0' { b'1' } else { b'0' };
    let corrupt_prefix = JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: journal_id(),
        evidence: Arc::from([JournalEvidenceEnvelopeV1 {
            journal_id: journal_id(),
            sequence: 1,
            evidence_id: evidence_id(1),
            kind: Arc::from("gantry.logical-evidence/v2"),
            canonical_body: Arc::from(corrupt),
            references: Arc::from([]),
            protected_payloads: Arc::from([]),
        }]),
        committed_through: 1,
    });
    assert!(matches!(
        recover_authoritative_prefix(program, &corrupt_prefix),
        Err(DurableEvidenceError::Encoding | DurableEvidenceError::Checkpoint(_))
    ));
}

#[test]
fn public_non_operation_commit_cuts_recover_without_reapplying_fixed_state() {
    let program = value_program();

    let mut cancelled = machine(Arc::clone(&program));
    assert!(cancelled.cancel("caller").is_some());
    let cancellation = DurableLogicalEvidenceV2::new(
        execution(),
        root_task(),
        DurableCommitCutV1::Cancellation,
        None,
        &cancelled,
    )
    .unwrap_or_else(|error| panic!("cancellation evidence failed: {error:?}"));
    let body = cancellation.canonical_body();
    assert_eq!(
        DurableLogicalEvidenceV2::decode(&program, &body),
        Ok(cancellation.clone())
    );
    let recovered = recover_authoritative_prefix(
        Arc::clone(&program),
        &full_prefix(vec![envelope(1, 1, &cancellation, &[])]),
    )
    .unwrap_or_else(|error| panic!("cancellation recovery failed: {error:?}"));
    assert_eq!(
        drive(recovered.into_machine()),
        MachineOutcome::Cancelled(Arc::from("caller"))
    );

    let mut terminal = machine(Arc::clone(&program));
    let terminal_outcome = loop {
        match terminal.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(terminal.resume_after_yield()),
            MachineStep::Complete(outcome) => break outcome,
            other => panic!("terminal fixture blocked unexpectedly: {other:?}"),
        }
    };
    for (index, cut) in [
        DurableCommitCutV1::TaskSettlement,
        DurableCommitCutV1::ForegroundCompletion,
        DurableCommitCutV1::TerminalCompletion,
    ]
    .into_iter()
    .enumerate()
    {
        let evidence =
            DurableLogicalEvidenceV2::new(execution(), root_task(), cut, None, &terminal)
                .unwrap_or_else(|error| panic!("{cut:?} evidence failed: {error:?}"));
        let material = u8::try_from(index + 2)
            .unwrap_or_else(|_| panic!("commit-cut fixture material overflowed"));
        let recovered = recover_authoritative_prefix(
            Arc::clone(&program),
            &full_prefix(vec![envelope(1, material, &evidence, &[])]),
        )
        .unwrap_or_else(|error| panic!("{cut:?} recovery failed: {error:?}"));
        assert_eq!(recovered.latest_cut(), cut);
        assert_eq!(
            recovered.into_machine().step(),
            MachineStep::Complete(terminal_outcome.clone())
        );
    }
}

#[test]
fn public_commit_coordinator_awaits_contiguous_causal_cuts() {
    let program = value_program();
    let mut machine = machine(Arc::clone(&program));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));

    let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("coordinated-recovery-journal")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
    let sink = DurableTransitionSink::new(Arc::clone(&storage), journal_id.clone(), owner.token);
    let mut coordinator = DurableCommitCoordinatorV1::new(&sink, execution(), root_task(), None)
        .unwrap_or_else(|error| panic!("coordinator construction failed: {error:?}"));

    let checkpoint =
        block_on(coordinator.commit_cut(DurableCommitCutV1::Checkpoint, None, &machine, None))
            .unwrap_or_else(|error| panic!("checkpoint commit failed: {error:?}"));
    assert!(machine.cancel("caller").is_some());
    let cancellation =
        block_on(coordinator.commit_cut(DurableCommitCutV1::Cancellation, None, &machine, None))
            .unwrap_or_else(|error| panic!("cancellation commit failed: {error:?}"));
    assert_eq!((checkpoint.sequence, cancellation.sequence), (1, 2));

    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("coordinator store returned a snapshot")
    };
    assert_eq!(full.evidence.len(), 2);
    assert_eq!(
        full.evidence[1].references.as_ref(),
        [checkpoint.evidence_id]
    );
    let recovered = recover_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("coordinated recovery failed: {error:?}"));
    assert_eq!(recovered.latest_sequence(), cancellation.sequence);
    assert_eq!(recovered.latest_cut(), DurableCommitCutV1::Cancellation);
    assert_eq!(
        drive(recovered.into_machine()),
        MachineOutcome::Cancelled(Arc::from("caller"))
    );
}

#[allow(clippy::too_many_arguments)]
fn operation_evidence(
    machine: &Machine,
    operation_id: ProtocolIdentity,
    dispatch_id: Option<ProtocolIdentity>,
    cut: DurableCommitCutV1,
    action_recovery: Option<RecoveryClass>,
    request_bytes: Option<Arc<[u8]>>,
    outcome: Option<HookOutcomeV1>,
    retry_errors: Arc<[ValidationErrorV1]>,
    result_type: Option<TypeDescriptor>,
    result_bytes: Option<Arc<[u8]>>,
    retry_delay_us: Option<u64>,
) -> DurableLogicalEvidenceV2 {
    DurableLogicalEvidenceV2::new(
        execution(),
        root_task(),
        cut,
        Some(DurableOperationEvidenceV1 {
            operation_id,
            dispatch_id,
            validation_attempt: 0,
            recovery_dispatch: 0,
            retry_delay_us,
            retries_left: Some(2),
            action_recovery,
            request_bytes,
            outcome,
            retry_errors,
            result_type,
            result_bytes,
        }),
        machine,
    )
    .unwrap_or_else(|error| panic!("operation evidence failed: {error:?}"))
}

fn full_prefix(evidence: Vec<JournalEvidenceEnvelopeV1>) -> JournalPrefixV1 {
    let committed_through =
        u64::try_from(evidence.len()).unwrap_or_else(|_| panic!("fixture prefix is too large"));
    JournalPrefixV1::Full(FullJournalPrefixV1 {
        journal_id: journal_id(),
        evidence: Arc::from(evidence),
        committed_through,
    })
}

fn envelope(
    sequence: u64,
    material: u8,
    evidence: &DurableLogicalEvidenceV2,
    references: &[ProtocolIdentity],
) -> JournalEvidenceEnvelopeV1 {
    JournalEvidenceEnvelopeV1 {
        journal_id: journal_id(),
        sequence,
        evidence_id: evidence_id(material),
        kind: Arc::from("gantry.logical-evidence/v2"),
        canonical_body: Arc::from(evidence.canonical_body()),
        references: Arc::from(references),
        protected_payloads: Arc::from([]),
    }
}

fn request_bytes(operation: ProtocolIdentity, dispatch: ProtocolIdentity) -> Arc<[u8]> {
    Arc::from(
        format!("{{\"dispatch_id\":\"{dispatch}\",\"operation_id\":\"{operation}\"}}").into_bytes(),
    )
}

fn value_program() -> Arc<MachineProgram> {
    program(
        TypeDescriptor::BOOL,
        vec![
            instruction(
                0,
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            ),
            instruction(1, TypeDescriptor::BOOL, InstructionKind::Return),
        ],
    )
}

fn operation_program() -> Arc<MachineProgram> {
    program(
        TypeDescriptor::UNIT,
        vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    )
}

fn program(result: TypeDescriptor, instructions: Vec<Instruction>) -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(vec![Workflow {
            path: path("crate::main"),
            parameters: Vec::new(),
            result,
            effects: EffectSet::default(),
            instructions,
        }])
        .unwrap_or_else(|error| panic!("program failed: {error:?}")),
    )
}

fn machine(program: Arc<MachineProgram>) -> Machine {
    Machine::new(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        MachineLimits::new(16, 4, 4, 4, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("machine limits failed")),
    )
    .unwrap_or_else(|error| panic!("machine failed: {error:?}"))
}

fn drive(mut machine: Machine) -> MachineOutcome {
    loop {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::Complete(outcome) => return outcome,
            other => panic!("machine remained externally blocked: {other:?}"),
        }
    }
}

fn instruction(index: u64, ty: TypeDescriptor, kind: InstructionKind) -> Instruction {
    Instruction {
        site: StructuralPosition::new(vec![index])
            .unwrap_or_else(|error| panic!("site failed: {error}")),
        ty,
        kind,
    }
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn execution() -> ProtocolIdentity {
    fresh(IdentityKind::Execution, 1)
}

fn root_task() -> ProtocolIdentity {
    ProtocolIdentity::derive(IdentityKind::Task, b"public-durable-root")
        .unwrap_or_else(|error| panic!("task identity failed: {error}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"))
}

fn evidence_id(byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_storage_material([byte; 32])
}

fn journal_id() -> JournalId {
    JournalId::new("public-recovery-journal")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
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
