//! Public contract coverage for typed journal storage and transition sinks.

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};

use gantry::host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, JournalBatchV1, JournalContractError,
    JournalEvidenceEnvelopeV1, JournalId, JournalOwnerOperationV1, JournalPrefixV1,
    JournalProtectedPayloadV1, JournalStorage, ReleaseJournalOwnerV1, SnapshotJournalPrefixV1,
    UnfinalizedEvidenceV1, validate_journal_prefix,
};
use gantry::identity::ProtocolIdentity;
use gantry::portable::IdentityKind;
use gantry::runtime::{
    DurableTransitionSink, InMemoryJournalStore, TransitionReceiptV1, TransitionSink,
    VolatileTransitionSink,
};
use gantry_conformance::journal::run_journal_storage_contract;
use serde::Deserialize;

const STORE_EVIDENCE: &str = "crates/gantry-conformance/tests/journal_storage.rs#public_in_memory_store_passes_the_common_atomic_fenced_contract";
const SINK_EVIDENCE: &str = "crates/gantry-conformance/tests/journal_storage.rs#public_transition_sinks_separate_volatile_and_fenced_durable_records";
const RACE_EVIDENCE: &str = "crates/gantry-conformance/tests/journal_storage.rs#public_owner_and_commit_races_are_linearizable";
const PREFIX_EVIDENCE: &str = "crates/gantry-conformance/tests/journal_storage.rs#public_snapshot_prefix_validation_enforces_frontier_watermark_and_references";

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
struct JournalVectors {
    format: String,
    first_sequence: u64,
    prefix_forms: Vec<String>,
    contract_cases: Vec<String>,
    error_codes: Vec<String>,
    in_memory_persistence_claim: String,
}

#[test]
fn checked_in_journal_contract_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/journal-storage-v1.json"));
    let vectors: JournalVectors = read_json(&root.join("protocol/goldens/journal-storage-v1.json"));
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/journal-storage-v1.schema.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.journal-storage-evidence/v1");
    assert_eq!(manifest.issue, "GNT-DUR-001");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
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
            STORE_EVIDENCE | SINK_EVIDENCE | RACE_EVIDENCE | PREFIX_EVIDENCE
        ));
    }

    for link in manifest.reviewed_clauses {
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
            .unwrap_or_else(|| panic!("missing reviewed journal clause"));
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, link.evidence);
    }

    assert_eq!(vectors.format, "gantry.journal-storage-vectors/v1");
    assert_eq!(vectors.first_sequence, 1);
    assert_eq!(vectors.prefix_forms, ["full-prefix", "snapshot-prefix"]);
    assert_eq!(vectors.in_memory_persistence_claim, "none");
    assert!(
        vectors
            .contract_cases
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(vectors.error_codes.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        schema["$id"],
        "https://gantry.invalid/protocol/journal-storage/v1/schema.json"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["first_sequence"]["const"], 1);

    let capabilities = manifest
        .capabilities
        .into_iter()
        .map(|capability| (capability.id, capability.evidence))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(capabilities.len(), 4);
}

#[test]
fn public_in_memory_store_passes_the_common_atomic_fenced_contract() {
    let store = InMemoryJournalStore::new();
    assert_eq!(block_on(run_journal_storage_contract(&store)), Ok(()));
}

#[test]
fn public_transition_sinks_separate_volatile_and_fenced_durable_records() {
    let volatile = VolatileTransitionSink::default();
    assert_eq!(
        block_on(volatile.record(batch("volatile"))),
        Ok(TransitionReceiptV1::Volatile)
    );
    assert_eq!(volatile.batches().len(), 1);

    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("sink-journal")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let ownership = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: JournalOwnerOperationV1::Start,
    }))
    .unwrap_or_else(|error| panic!("ownership failed: {error:?}"));
    let sink = DurableTransitionSink::new(
        Arc::clone(&storage) as Arc<dyn JournalStorage>,
        journal_id.clone(),
        ownership.token.clone(),
    );
    assert!(matches!(
        block_on(sink.record(batch("durable"))),
        Ok(TransitionReceiptV1::Durable(receipt))
            if receipt.first_sequence == 1 && receipt.last_sequence == 1
    ));
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id,
        ownership_token: ownership.token,
    }))
    .unwrap_or_else(|error| panic!("release failed: {error:?}"));
    assert!(block_on(sink.record(batch("stale"))).is_err());
}

#[test]
fn public_owner_and_commit_races_are_linearizable() {
    let storage = Arc::new(InMemoryJournalStore::new());
    let journal_id = JournalId::new("race-journal")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let barrier = Arc::new(Barrier::new(3));
    let mut owners = Vec::new();
    for operation in [
        JournalOwnerOperationV1::Start,
        JournalOwnerOperationV1::Resume,
    ] {
        let storage = Arc::clone(&storage);
        let journal_id = journal_id.clone();
        let barrier = Arc::clone(&barrier);
        owners.push(std::thread::spawn(move || {
            barrier.wait();
            block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
                journal_id,
                operation,
            }))
        }));
    }
    barrier.wait();
    let results = owners
        .into_iter()
        .map(|owner| {
            owner
                .join()
                .unwrap_or_else(|_| panic!("owner thread panicked"))
        })
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let ownership = results
        .into_iter()
        .find_map(Result::ok)
        .unwrap_or_else(|| panic!("owner race had no winner"));

    let barrier = Arc::new(Barrier::new(3));
    let mut commits = Vec::new();
    for id in ["left", "right"] {
        let storage = Arc::clone(&storage);
        let journal_id = journal_id.clone();
        let token = ownership.token.clone();
        let barrier = Arc::clone(&barrier);
        commits.push(std::thread::spawn(move || {
            barrier.wait();
            block_on(
                storage.commit(gantry::host::journal::JournalCommitRequestV1 {
                    journal_id,
                    ownership_token: token,
                    batch: batch(id),
                }),
            )
        }));
    }
    barrier.wait();
    let mut sequences = commits
        .into_iter()
        .map(|commit| {
            commit
                .join()
                .unwrap_or_else(|_| panic!("commit thread panicked"))
                .unwrap_or_else(|error| panic!("commit failed: {error:?}"))
                .first_sequence
        })
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, [1, 2]);
}

#[test]
fn public_snapshot_prefix_validation_enforces_frontier_watermark_and_references() {
    let journal_id = JournalId::new("snapshot-journal")
        .unwrap_or_else(|error| panic!("journal id failed: {error:?}"));
    let retained = ProtocolIdentity::from_storage_material([1; 32]);
    let suffix_id = ProtocolIdentity::from_storage_material([2; 32]);
    let envelope = JournalEvidenceEnvelopeV1 {
        journal_id: journal_id.clone(),
        sequence: 2,
        evidence_id: suffix_id,
        kind: Arc::from("transition"),
        canonical_body: Arc::from(&b"{}"[..]),
        references: Arc::from([retained]),
        protected_payloads: Arc::from([]),
    };
    let valid = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id,
        snapshot_version: 1,
        frontier: 1,
        canonical_snapshot: Arc::from(&b"{}"[..]),
        retained_evidence: std::collections::BTreeMap::from([(retained, 1)]),
        suffix: Arc::from([envelope.clone()]),
        committed_through: 2,
    });
    assert_eq!(validate_journal_prefix(&valid), Ok(()));

    let JournalPrefixV1::Snapshot(mut invalid) = valid else {
        unreachable!("fixture is a snapshot")
    };
    invalid.suffix = Arc::from([JournalEvidenceEnvelopeV1 {
        sequence: 3,
        ..envelope
    }]);
    assert_eq!(
        validate_journal_prefix(&JournalPrefixV1::Snapshot(invalid)),
        Err(JournalContractError::InvalidPrefix)
    );
    assert_eq!(suffix_id.kind(), IdentityKind::Evidence);
}

fn batch(id: &str) -> JournalBatchV1 {
    let local = BatchLocalEvidenceId::new(id.to_owned())
        .unwrap_or_else(|error| panic!("local id failed: {error:?}"));
    let body = UnfinalizedEvidenceV1::new(
        local,
        "transition",
        format!("{{\"id\":\"{id}\"}}").into_bytes(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("evidence body failed: {error:?}"));
    JournalBatchV1::new(vec![body], Vec::<JournalProtectedPayloadV1>::new())
        .unwrap_or_else(|error| panic!("batch failed: {error:?}"))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
