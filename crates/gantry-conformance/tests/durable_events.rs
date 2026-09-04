//! Public conformance coverage for journal-first events and delivery recovery.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use gantry::event::{EventDraft, EventEnvelope, EventPayload, ProtectedReference};
use gantry::host::event::{
    EventRetryPolicy, ProtectedPayload, RedactionCapabilities, SinkDeliveryPolicy, SinkId,
};
use gantry::host::journal::{
    AcquireJournalOwnerV1, JournalId, JournalOwnerOperationV1, JournalPayloadKey, JournalPrefixV1,
    JournalStorage, ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1,
    SnapshotJournalPrefixV1,
};
use gantry::identity::ProtocolIdentity;
use gantry::ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, StructuralPosition,
    TypeDescriptor, Workflow,
};
use gantry::portable::{
    DeliveryOutcome, EventKind, IdentityKind, JitterMode, ProtectedReferenceClass, SinkClass,
};
use gantry::runtime::{
    DurableCommitCoordinatorV1, DurableCommitCutV1, DurableDeliveryRecoveryV1,
    DurableEventBarrierV1, DurableEventCommitCoordinatorV1, DurableEventCommitError,
    DurableEventDispatchedV1, DurableEventEvidenceError, DurableEventOccurrenceV1,
    DurableEventPlanV1, DurableEventSettledV1, DurableSinkObligationV1, DurableTransitionSink,
    InMemoryJournalStore, Machine, MachineLimits, RecoveredDurableStateV1,
    recover_authoritative_prefix,
};
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use serde::Deserialize;

const JOURNAL_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_events.rs#public_journal_first_occurrence_plan_and_payloads_precede_delivery";
const CRASH_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_events.rs#public_delivery_crash_cuts_preserve_retry_budget_and_terminal_settlement";
const BARRIER_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_events.rs#public_replacement_barrier_exclusion_and_compaction_guards_are_exact";
const COMPACTION_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_events.rs#public_full_and_compacted_event_prefixes_project_equivalently";
const FAILURE_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_events.rs#public_journal_failure_ends_the_standard_event_stream";
const CATALOG_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_observation.rs#public_execution_event_catalog_is_typed_canonical_and_protected";
const CONSEQUENCE_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_observation.rs#public_required_delivery_failure_is_isolated_nonrecursive_and_post_terminal_safe";
const RECOVERY_COMPACTION_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_committed_and_compacted_prefixes_restore_the_same_machine_and_sessions";
const RECOVERY_CORRUPTION_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_recovery.rs#public_recovery_rejects_corruption_invalid_causality_and_operation_order";
const RETRY_EVIDENCE: &str = "crates/gantry-conformance/tests/activity_observation.rs#canonical_projection_and_retry_vectors_match_the_public_kernel";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
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
struct DurableEventVectors {
    format: String,
    barriers: Vec<String>,
    cases: Vec<String>,
    evidence_kinds: Vec<String>,
    recovery_states: Vec<String>,
    retention: Vec<String>,
    standard_event_catalog_closed: bool,
}

#[test]
fn reviewed_durable_event_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/durable-events-v1.json"));
    let vectors: DurableEventVectors =
        read_json(&root.join("protocol/goldens/durable-events-v1.json"));
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/durable-events-v1.schema.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.durable-event-evidence/v1");
    assert_eq!(manifest.issue, "GNT-DUR-005");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    let allowed = BTreeSet::from([
        BARRIER_EVIDENCE,
        CATALOG_EVIDENCE,
        COMPACTION_EVIDENCE,
        CONSEQUENCE_EVIDENCE,
        CRASH_EVIDENCE,
        FAILURE_EVIDENCE,
        JOURNAL_EVIDENCE,
        RECOVERY_COMPACTION_EVIDENCE,
        RECOVERY_CORRUPTION_EVIDENCE,
        RETRY_EVIDENCE,
    ]);
    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(
            allowed.contains(entry.evidence.as_str()),
            "{}",
            entry.evidence
        );
        validate_test_anchor(&root, &entry.evidence);
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

    assert_eq!(vectors.format, "gantry.durable-event-vectors/v1");
    assert_eq!(vectors.evidence_kinds.len(), 3);
    assert_eq!(vectors.recovery_states.len(), 5);
    assert_eq!(vectors.barriers.len(), 3);
    assert_eq!(vectors.retention.len(), 3);
    assert_eq!(vectors.cases.len(), 8);
    assert!(vectors.standard_event_catalog_closed);
    assert_eq!(schema["properties"]["format"]["const"], vectors.format);
}

#[test]
fn public_journal_first_occurrence_plan_and_payloads_precede_delivery() {
    let fixture = fixture("public-durable-event-order");
    let reference = protected_reference();
    let event = event(reference.clone());
    let event_id = event.event_id();
    let sink_id = sink_id("required-sink");
    let occurrence = occurrence(
        fixture.cause.evidence_id,
        event,
        vec![DurableSinkObligationV1::new(
            sink_id.clone(),
            policy(SinkClass::Required, true),
        )],
    );
    let mut coordinator = DurableEventCommitCoordinatorV1::new(
        &fixture.sink,
        (fixture.cause.evidence_id, fixture.cause.sequence),
    )
    .unwrap_or_else(|error| panic!("event coordinator failed: {error:?}"));
    let payload = ProtectedPayload {
        reference,
        bytes: Arc::from(&b"sensitive-secret-bytes"[..]),
    };
    let occurrence_commit = block_on(coordinator.commit_occurrence(&occurrence, &[payload]))
        .unwrap_or_else(|error| panic!("occurrence commit failed: {error:?}"));
    let attempt_id = fresh(IdentityKind::DeliveryAttempt, 30);
    let dispatched = DurableEventDispatchedV1::new(event_id, sink_id.clone(), attempt_id, 0)
        .unwrap_or_else(|error| panic!("dispatch construction failed: {error:?}"));
    let dispatch_commit =
        block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &dispatched))
            .unwrap_or_else(|error| panic!("dispatch commit failed: {error:?}"));
    let settled = DurableEventSettledV1::new(
        event_id,
        sink_id,
        attempt_id,
        0,
        DeliveryOutcome::Success,
        2,
        None,
    )
    .unwrap_or_else(|error| panic!("settlement construction failed: {error:?}"));
    let settlement_commit = block_on(coordinator.commit_settled(
        occurrence_commit.evidence_id,
        dispatch_commit.evidence_id,
        &settled,
    ))
    .unwrap_or_else(|error| panic!("settlement commit failed: {error:?}"));
    assert_eq!(
        (
            occurrence_commit.sequence,
            dispatch_commit.sequence,
            settlement_commit.sequence,
        ),
        (2, 3, 4)
    );

    let prefix = read_prefix(fixture.storage.as_ref(), &fixture.journal_id);
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("in-memory event journal returned a snapshot")
    };
    assert_eq!(
        full.evidence
            .iter()
            .map(|envelope| envelope.kind.as_ref())
            .collect::<Vec<_>>(),
        [
            "gantry.logical-evidence/v2",
            "gantry.event-occurrence/v1",
            "gantry.event-delivery-dispatched/v1",
            "gantry.event-delivery-settled/v1",
        ]
    );
    assert!(
        full.evidence[1]
            .references
            .contains(&fixture.cause.evidence_id)
    );
    assert!(
        full.evidence[2]
            .references
            .contains(&occurrence_commit.evidence_id)
    );
    assert!(
        full.evidence[3]
            .references
            .contains(&dispatch_commit.evidence_id)
    );
    assert!(
        !String::from_utf8_lossy(&full.evidence[1].canonical_body)
            .contains("sensitive-secret-bytes")
    );
    let resolved = block_on(
        fixture.storage.resolve_payload(ResolveJournalPayloadV1 {
            journal_id: fixture.journal_id,
            key: JournalPayloadKey::new("event:raw-output")
                .unwrap_or_else(|error| panic!("payload key failed: {error:?}")),
        }),
    )
    .unwrap_or_else(|error| panic!("payload resolution failed: {error:?}"));
    assert_eq!(resolved.bytes.as_ref(), b"sensitive-secret-bytes");

    let recovered = recover_authoritative_prefix(Arc::clone(&fixture.program), &prefix)
        .unwrap_or_else(|error| panic!("event recovery failed: {error:?}"));
    assert_eq!(recovered.latest_sequence(), 4);
    assert!(matches!(
        delivery(&recovered, event_id, "required-sink"),
        DurableDeliveryRecoveryV1::Success { attempt_id: recovered_attempt }
            if *recovered_attempt == attempt_id
    ));
    assert_eq!(
        recovered
            .events()
            .event_for_cause(fixture.cause.evidence_id)
            .map(|event| event.occurrence().event().event_id()),
        Some(event_id)
    );
    let duplicate = DurableEventCommitCoordinatorV1::from_recovered(
        &fixture.sink,
        (recovered.latest_evidence_id(), recovered.latest_sequence()),
        recovered.events(),
    )
    .and_then(|mut coordinator| block_on(coordinator.commit_occurrence(&occurrence, &[])));
    assert_eq!(duplicate, Err(DurableEventCommitError::DuplicateOccurrence));
}

#[test]
fn public_full_and_compacted_event_prefixes_project_equivalently() {
    let fixture = fixture("public-durable-event-compaction");
    let reference = protected_reference();
    let event = event(reference.clone());
    let event_id = event.event_id();
    let sink_id = sink_id("required-sink");
    let occurrence = occurrence(
        fixture.cause.evidence_id,
        event,
        vec![DurableSinkObligationV1::new(
            sink_id.clone(),
            policy(SinkClass::Required, true),
        )],
    );
    let mut coordinator = DurableEventCommitCoordinatorV1::new(
        &fixture.sink,
        (fixture.cause.evidence_id, fixture.cause.sequence),
    )
    .unwrap_or_else(|error| panic!("event coordinator failed: {error:?}"));
    let occurrence_commit = block_on(coordinator.commit_occurrence(
        &occurrence,
        &[ProtectedPayload {
            reference,
            bytes: Arc::from(&b"raw"[..]),
        }],
    ))
    .unwrap_or_else(|error| panic!("occurrence commit failed: {error:?}"));
    let attempt_id = fresh(IdentityKind::DeliveryAttempt, 35);
    let dispatched = DurableEventDispatchedV1::new(event_id, sink_id.clone(), attempt_id, 0)
        .unwrap_or_else(|error| panic!("dispatch failed: {error:?}"));
    let dispatch_commit =
        block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &dispatched))
            .unwrap_or_else(|error| panic!("dispatch commit failed: {error:?}"));
    let settled = DurableEventSettledV1::new(
        event_id,
        sink_id,
        attempt_id,
        0,
        DeliveryOutcome::Success,
        2,
        None,
    )
    .unwrap_or_else(|error| panic!("settlement failed: {error:?}"));
    block_on(coordinator.commit_settled(
        occurrence_commit.evidence_id,
        dispatch_commit.evidence_id,
        &settled,
    ))
    .unwrap_or_else(|error| panic!("settlement commit failed: {error:?}"));

    let full = read_prefix(fixture.storage.as_ref(), &fixture.journal_id);
    let JournalPrefixV1::Full(full_prefix) = &full else {
        panic!("in-memory event journal returned a snapshot")
    };
    let compacted = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: fixture.journal_id.clone(),
        snapshot_version: 3,
        frontier: fixture.cause.sequence,
        canonical_snapshot: Arc::clone(&full_prefix.evidence[0].canonical_body),
        retained_evidence: BTreeMap::from([(fixture.cause.evidence_id, fixture.cause.sequence)]),
        suffix: Arc::from(full_prefix.evidence[1..].to_vec()),
        committed_through: full_prefix.committed_through,
    });
    let full_recovery = recover_authoritative_prefix(Arc::clone(&fixture.program), &full)
        .unwrap_or_else(|error| panic!("full event recovery failed: {error:?}"));
    let compacted_recovery = recover_authoritative_prefix(Arc::clone(&fixture.program), &compacted)
        .unwrap_or_else(|error| panic!("compacted event recovery failed: {error:?}"));

    assert_eq!(
        compacted_recovery.latest_sequence(),
        full_recovery.latest_sequence()
    );
    assert_eq!(
        compacted_recovery.latest_evidence_id(),
        full_recovery.latest_evidence_id()
    );
    assert_eq!(compacted_recovery.events(), full_recovery.events());
    assert!(matches!(
        delivery(&compacted_recovery, event_id, "required-sink"),
        DurableDeliveryRecoveryV1::Success { attempt_id: recovered_attempt }
            if *recovered_attempt == attempt_id
    ));
}

#[test]
fn public_delivery_crash_cuts_preserve_retry_budget_and_terminal_settlement() {
    let fixture = fixture("public-durable-event-crash-cuts");
    let reference = protected_reference();
    let event = event(reference.clone());
    let event_id = event.event_id();
    let sink_id = sink_id("required-sink");
    let occurrence = occurrence(
        fixture.cause.evidence_id,
        event,
        vec![DurableSinkObligationV1::new(
            sink_id.clone(),
            policy(SinkClass::Required, true),
        )],
    );
    let mut coordinator = DurableEventCommitCoordinatorV1::new(
        &fixture.sink,
        (fixture.cause.evidence_id, fixture.cause.sequence),
    )
    .unwrap_or_else(|error| panic!("event coordinator failed: {error:?}"));
    let occurrence_commit = block_on(coordinator.commit_occurrence(
        &occurrence,
        &[ProtectedPayload {
            reference,
            bytes: Arc::from(&b"raw"[..]),
        }],
    ))
    .unwrap_or_else(|error| panic!("occurrence commit failed: {error:?}"));

    let first_attempt = fresh(IdentityKind::DeliveryAttempt, 31);
    let first = DurableEventDispatchedV1::new(event_id, sink_id.clone(), first_attempt, 0)
        .unwrap_or_else(|error| panic!("first dispatch failed: {error:?}"));
    let first_commit =
        block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &first))
            .unwrap_or_else(|error| panic!("first dispatch commit failed: {error:?}"));
    let recovered = recover(&fixture);
    assert!(matches!(
        delivery(&recovered, event_id, "required-sink"),
        DurableDeliveryRecoveryV1::Indeterminate { previous_attempt_id, retry_number: 0 }
            if *previous_attempt_id == first_attempt
    ));

    let redelivery_attempt = fresh(IdentityKind::DeliveryAttempt, 32);
    let redelivery =
        DurableEventDispatchedV1::new(event_id, sink_id.clone(), redelivery_attempt, 0)
            .unwrap_or_else(|error| panic!("redelivery failed: {error:?}"));
    let redelivery_commit =
        block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &redelivery))
            .unwrap_or_else(|error| panic!("redelivery commit failed: {error:?}"));
    assert!(redelivery_commit.sequence > first_commit.sequence);
    let retriable = DurableEventSettledV1::new(
        event_id,
        sink_id.clone(),
        redelivery_attempt,
        0,
        DeliveryOutcome::Retriable,
        2,
        Some(17),
    )
    .unwrap_or_else(|error| panic!("retriable settlement failed: {error:?}"));
    block_on(coordinator.commit_settled(
        occurrence_commit.evidence_id,
        redelivery_commit.evidence_id,
        &retriable,
    ))
    .unwrap_or_else(|error| panic!("retriable commit failed: {error:?}"));
    let recovered = recover(&fixture);
    assert_eq!(
        delivery(&recovered, event_id, "required-sink"),
        &DurableDeliveryRecoveryV1::RetryDelay {
            retry_number: 1,
            delay_us: 17,
            remaining_retries: 2,
        }
    );

    let final_attempt = fresh(IdentityKind::DeliveryAttempt, 33);
    let final_dispatch = DurableEventDispatchedV1::new(event_id, sink_id.clone(), final_attempt, 1)
        .unwrap_or_else(|error| panic!("final dispatch failed: {error:?}"));
    let final_dispatch_commit =
        block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &final_dispatch))
            .unwrap_or_else(|error| panic!("final dispatch commit failed: {error:?}"));
    let terminal = DurableEventSettledV1::new(
        event_id,
        sink_id,
        final_attempt,
        1,
        DeliveryOutcome::Terminal,
        1,
        None,
    )
    .unwrap_or_else(|error| panic!("terminal settlement failed: {error:?}"));
    block_on(coordinator.commit_settled(
        occurrence_commit.evidence_id,
        final_dispatch_commit.evidence_id,
        &terminal,
    ))
    .unwrap_or_else(|error| panic!("terminal commit failed: {error:?}"));
    let recovered = recover(&fixture);
    assert!(matches!(
        delivery(&recovered, event_id, "required-sink"),
        DurableDeliveryRecoveryV1::Terminal { attempt_id } if *attempt_id == final_attempt
    ));
}

#[test]
fn public_replacement_barrier_exclusion_and_compaction_guards_are_exact() {
    let fixture = fixture("public-durable-event-retention");
    let reference = protected_reference();
    let event = event(reference.clone());
    let event_id = event.event_id();
    let required = sink_id("required-sink");
    let best_effort = sink_id("best-effort-sink");
    let plan = DurableEventPlanV1::new(vec![
        DurableSinkObligationV1::new(required.clone(), policy(SinkClass::Required, true)),
        DurableSinkObligationV1::new(best_effort.clone(), policy(SinkClass::BestEffort, false)),
    ])
    .unwrap_or_else(|error| panic!("durable plan failed: {error:?}"));
    let occurrence = DurableEventOccurrenceV1::new(fixture.cause.evidence_id, event, plan.clone())
        .unwrap_or_else(|error| panic!("occurrence failed: {error:?}"));
    let mut coordinator = DurableEventCommitCoordinatorV1::new(
        &fixture.sink,
        (fixture.cause.evidence_id, fixture.cause.sequence),
    )
    .unwrap_or_else(|error| panic!("event coordinator failed: {error:?}"));
    let occurrence_commit = block_on(coordinator.commit_occurrence(
        &occurrence,
        &[ProtectedPayload {
            reference,
            bytes: Arc::from(&b"raw"[..]),
        }],
    ))
    .unwrap_or_else(|error| panic!("occurrence commit failed: {error:?}"));
    let recovered = recover(&fixture);
    assert!(
        !recovered
            .events()
            .requires_replacement(fixture.cause.evidence_id)
    );
    assert!(recovered.events().requires_replacement(fresh_evidence(90)));
    assert_eq!(
        recovered
            .events()
            .required_barrier_through(occurrence_commit.sequence),
        DurableEventBarrierV1::Pending {
            event_id,
            sink_id: required.clone(),
        }
    );
    let consequence_plan = plan.without_sink(&required);
    assert!(consequence_plan.obligation(&required).is_none());
    assert!(consequence_plan.obligation(&best_effort).is_some());

    let retention = recovered.events().retention();
    assert!(
        retention
            .evidence_ids()
            .contains(&occurrence_commit.evidence_id)
    );
    let payload_key = JournalPayloadKey::new("event:raw-output")
        .unwrap_or_else(|error| panic!("payload key failed: {error:?}"));
    assert!(retention.payload_keys().contains(&payload_key));
    assert_eq!(
        retention.validate_retained(&BTreeSet::new(), &BTreeSet::new()),
        Err(DurableEventEvidenceError::CompactionWouldDangle)
    );
    assert_eq!(
        retention.validate_retained(retention.evidence_ids(), retention.payload_keys(),),
        Ok(())
    );

    let attempt_id = fresh(IdentityKind::DeliveryAttempt, 34);
    let dispatched = DurableEventDispatchedV1::new(event_id, required.clone(), attempt_id, 0)
        .unwrap_or_else(|error| panic!("dispatch failed: {error:?}"));
    let dispatch_commit =
        block_on(coordinator.commit_dispatched(occurrence_commit.evidence_id, &dispatched))
            .unwrap_or_else(|error| panic!("dispatch commit failed: {error:?}"));
    let terminal = DurableEventSettledV1::new(
        event_id,
        required.clone(),
        attempt_id,
        0,
        DeliveryOutcome::Terminal,
        2,
        None,
    )
    .unwrap_or_else(|error| panic!("terminal settlement failed: {error:?}"));
    let settlement = block_on(coordinator.commit_settled(
        occurrence_commit.evidence_id,
        dispatch_commit.evidence_id,
        &terminal,
    ))
    .unwrap_or_else(|error| panic!("terminal commit failed: {error:?}"));
    let recovered = recover(&fixture);
    assert!(matches!(
        recovered.events().required_barrier_through(settlement.sequence),
        DurableEventBarrierV1::RequiredExhausted(failure)
            if failure.sink_id == required
                && failure.event_id == event_id
                && failure.attempt_id == attempt_id
    ));
}

#[test]
fn public_journal_failure_ends_the_standard_event_stream() {
    let fixture = fixture("public-durable-event-journal-failure");
    let reference = protected_reference();
    let occurrence = occurrence(
        fixture.cause.evidence_id,
        event(reference.clone()),
        vec![DurableSinkObligationV1::new(
            sink_id("required-sink"),
            policy(SinkClass::Required, true),
        )],
    );
    block_on(fixture.storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: fixture.journal_id,
        ownership_token: fixture.token,
    }))
    .unwrap_or_else(|error| panic!("owner release failed: {error:?}"));
    let mut coordinator = DurableEventCommitCoordinatorV1::new(
        &fixture.sink,
        (fixture.cause.evidence_id, fixture.cause.sequence),
    )
    .unwrap_or_else(|error| panic!("event coordinator failed: {error:?}"));
    let payload = ProtectedPayload {
        reference,
        bytes: Arc::from(&b"raw"[..]),
    };
    let first =
        block_on(coordinator.commit_occurrence(&occurrence, std::slice::from_ref(&payload)));
    let Err(DurableEventCommitError::Journal(error)) = first else {
        panic!("first failed event commit did not return the journal error")
    };
    assert_eq!(
        block_on(coordinator.commit_occurrence(&occurrence, &[payload])),
        Err(DurableEventCommitError::StreamTerminated(error))
    );
}

struct Fixture {
    storage: Arc<dyn JournalStorage>,
    journal_id: JournalId,
    token: gantry::host::journal::JournalOwnershipToken,
    sink: DurableTransitionSink,
    program: Arc<MachineProgram>,
    cause: gantry::runtime::DurableEvidenceCommitV1,
}

fn fixture(name: &str) -> Fixture {
    let storage: Arc<dyn JournalStorage> = Arc::new(InMemoryJournalStore::new());
    let journal_id =
        JournalId::new(name).unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("owner acquisition failed: {error:?}"));
    let token = owner.token.clone();
    let sink = DurableTransitionSink::new(Arc::clone(&storage), journal_id.clone(), owner.token);
    let program = program();
    let machine = machine(Arc::clone(&program));
    let mut coordinator = DurableCommitCoordinatorV1::new(&sink, execution(), root_task(), None)
        .unwrap_or_else(|error| panic!("logical coordinator failed: {error:?}"));
    let cause =
        block_on(coordinator.commit_cut(DurableCommitCutV1::Checkpoint, None, &machine, None))
            .unwrap_or_else(|error| panic!("logical cause commit failed: {error:?}"));
    Fixture {
        storage,
        journal_id,
        token,
        sink,
        program,
        cause,
    }
}

fn recover(fixture: &Fixture) -> RecoveredDurableStateV1 {
    let prefix = read_prefix(fixture.storage.as_ref(), &fixture.journal_id);
    recover_authoritative_prefix(Arc::clone(&fixture.program), &prefix)
        .unwrap_or_else(|error| panic!("event recovery failed: {error:?}"))
}

fn read_prefix(storage: &dyn JournalStorage, journal_id: &JournalId) -> JournalPrefixV1 {
    block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix read failed: {error:?}"))
}

fn delivery<'a>(
    recovered: &'a RecoveredDurableStateV1,
    event_id: ProtocolIdentity,
    sink: &str,
) -> &'a DurableDeliveryRecoveryV1 {
    let sink = sink_id(sink);
    recovered
        .events()
        .events()
        .get(&event_id)
        .and_then(|event| event.deliveries().get(&sink))
        .unwrap_or_else(|| panic!("recovered delivery is absent"))
}

fn occurrence(
    cause: ProtocolIdentity,
    event: EventEnvelope,
    obligations: Vec<DurableSinkObligationV1>,
) -> DurableEventOccurrenceV1 {
    DurableEventOccurrenceV1::new(
        cause,
        event,
        DurableEventPlanV1::new(obligations)
            .unwrap_or_else(|error| panic!("durable plan failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("durable occurrence failed: {error:?}"))
}

fn event(reference: ProtectedReference) -> EventEnvelope {
    let draft = EventDraft::new(EventKind::OperationCompletion, payload())
        .with_execution_id(execution())
        .and_then(|draft| draft.with_protected_references(vec![reference]))
        .unwrap_or_else(|error| panic!("event draft failed: {error:?}"));
    EventEnvelope::complete(
        fresh(IdentityKind::Event, 6),
        fresh(IdentityKind::Activity, 7),
        UtcTimestamp::from_unix_seconds(0, 42)
            .unwrap_or_else(|error| panic!("timestamp failed: {error:?}")),
        draft,
    )
    .unwrap_or_else(|error| panic!("event completion failed: {error:?}"))
}

fn protected_reference() -> ProtectedReference {
    ProtectedReference::new("event:raw-output", ProtectedReferenceClass::RawOutput)
        .unwrap_or_else(|error| panic!("protected reference failed: {error:?}"))
}

fn policy(class: SinkClass, raw_output: bool) -> SinkDeliveryPolicy {
    SinkDeliveryPolicy::new(
        class,
        raw_output,
        "redaction-v1",
        RedactionCapabilities {
            operation_request_content: true,
            operation_result_content: false,
            integration_diagnostics: true,
            source_snippets: false,
        },
        EventRetryPolicy::new("retry-v1", 2, 10, 40, JitterMode::None)
            .unwrap_or_else(|error| panic!("retry policy failed: {error:?}")),
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"))
}

fn payload() -> EventPayload {
    EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(&b"{}"[..]))
        .unwrap_or_else(|error| panic!("event payload failed: {error:?}"))
}

fn program() -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(vec![Workflow {
            path: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("path failed: {error}")),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![Instruction {
                site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("site failed: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            }],
        }])
        .unwrap_or_else(|error| panic!("program failed: {error:?}")),
    )
}

fn machine(program: Arc<MachineProgram>) -> Machine {
    Machine::new(
        program,
        &CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path failed: {error}")),
        Vec::new(),
        execution(),
        MachineLimits::new(16, 4, 4, 4, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("machine limits failed")),
    )
    .unwrap_or_else(|error| panic!("machine failed: {error:?}"))
}

fn execution() -> ProtocolIdentity {
    fresh(IdentityKind::Execution, 5)
}

fn root_task() -> ProtocolIdentity {
    ProtocolIdentity::derive(IdentityKind::Task, b"public-durable-event-root")
        .unwrap_or_else(|error| panic!("task identity failed: {error}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error:?}"))
}

fn fresh_evidence(byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_storage_material([byte; 32])
}

fn sink_id(value: &str) -> SinkId {
    SinkId::new(value).unwrap_or_else(|error| panic!("sink id failed: {error:?}"))
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

fn validate_test_anchor(root: &Path, evidence: &str) {
    let (path, test) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("evidence anchor has no test: {evidence}"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read {path}: {error}"));
    assert!(source.contains(&format!("fn {test}(")), "{evidence}");
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
