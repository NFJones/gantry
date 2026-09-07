//! Frozen conformance evidence for owner-scoped async cancellation and draining.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/async-cancellation-v1.json";
const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
const OWNER: &str = "GNT-ASYNC-CANCEL-001";
const ARTIFACTS: [(&str, &str); 4] = [
    (
        "crates/gantry-conformance/tests/automatic_durable_root.rs",
        "af6eb95d0e7e752f475fbde43b6fb9cea141dbb024b76e0b823b72650ed4810c",
    ),
    (
        "crates/gantry-conformance/tests/interpreter_ownership.rs",
        "c732ccab5dc58768243bf2b0eb1ca630b47f1153e8ceef984b1fd153793f5a13",
    ),
    (
        "crates/gantry-conformance/tests/source_spawn.rs",
        "85cd772a6fce8d79c15b8fa46ec07b33803aa6988f424b8cb99a6f4a7d873ed0",
    ),
    (
        "crates/gantry-conformance/tests/source_spawn_tokio.rs",
        "d07c3c7c8ea16515bb3e69404eb55ca9eef2c2c2ffc203b0d2c76c3c48f325d3",
    ),
];
const CAPABILITIES: [(&str, &str); 12] = [
    (
        "dropped-cancellation-owner",
        "crates/gantry-conformance/tests/interpreter_ownership.rs#dropped_cancellation_waiter_does_not_abandon_nondurable_cleanup",
    ),
    (
        "durable-descendant-drain",
        "crates/gantry-conformance/tests/source_spawn.rs#durable_parent_failure_cancels_only_attached_descendants_before_settlement",
    ),
    (
        "durable-resistant-dispatch-abort",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#graph_cancellation_aborts_resistant_dispatch_after_bounded_drain",
    ),
    (
        "durable-sibling-detached-isolation",
        "crates/gantry-conformance/tests/source_spawn.rs#durable_nested_parent_failure_retains_outcome_and_does_not_cancel_siblings",
    ),
    (
        "failed-abort-classification",
        "crates/gantry-conformance/tests/interpreter_ownership.rs#public_cancellation_classifies_abort_failure_without_false_physical_settlement",
    ),
    (
        "nondurable-current-thread-descendant-drain",
        "crates/gantry-conformance/tests/source_spawn_tokio.rs#current_thread_tokio_parent_failure_waits_for_attached_descendant_drain",
    ),
    (
        "nondurable-multithread-descendant-drain",
        "crates/gantry-conformance/tests/source_spawn_tokio.rs#multithread_tokio_parent_failure_waits_for_attached_descendant_drain",
    ),
    (
        "shutdown-joins-cancellation-owner",
        "crates/gantry-conformance/tests/interpreter_ownership.rs#shutdown_reuses_active_nondurable_cancellation_control_reserve",
    ),
    (
        "shutdown-owner-serves-cancellation",
        "crates/gantry-conformance/tests/interpreter_ownership.rs#cancellation_during_shutdown_joins_the_existing_control_owner",
    ),
    (
        "shutdown-release-report",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#shutdown_report_preserves_exact_owner_release_failure_and_repeat_identity",
    ),
    (
        "shutdown-retains-live-durable-owner",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#cancellation_resistant_durable_work_does_not_fake_shutdown_completion",
    ),
    (
        "submitted-unpolled-abort",
        "crates/gantry-conformance/tests/interpreter_ownership.rs#public_cancellation_aborts_a_submitted_unpolled_driver",
    ),
];
const EXCLUSIONS: [&str; 3] = [
    "Source spawn construction, publication gates, and child-session ordering remain owned by GNT-ASYNC-SPAWN-001 and protocol/conformance/source-spawn-v1.json.",
    "Source JOIN, JOINALL, DETACH, and all-settled result ordering remain owned by GNT-ASYNC-JOIN-001 and protocol/conformance/source-join-v1.json.",
    "Recovered runnable-graph reconstruction, fencing, and replacement submission remain owned by GNT-ASYNC-REC-001.",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    artifacts: Vec<FileDigest>,
    requirements: Vec<RequirementEvidence>,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct RequirementEvidence {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
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
fn checked_in_async_cancellation_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest = read_json(&root.join(MANIFEST_PATH));
    let contract: ContractGate = read_json(&root.join(CONTRACT_PATH));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.async-cancellation-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, OWNER);
    assert_eq!(
        manifest
            .artifacts
            .iter()
            .map(|artifact| (artifact.path.as_str(), artifact.sha256.as_str()))
            .collect::<Vec<_>>(),
        ARTIFACTS
    );
    for artifact in &manifest.artifacts {
        assert_eq!(
            artifact.sha256,
            sha256(
                &fs::read(root.join(&artifact.path)).unwrap_or_else(|error| {
                    panic!(
                        "could not read cancellation artifact {}: {error}",
                        artifact.path
                    )
                })
            ),
            "stale cancellation artifact: {}",
            artifact.path
        );
    }

    let mut assigned = contract
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == OWNER)
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
    assert_eq!(declared.len(), 7);

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
            .map(|entry| (entry.id.as_str(), entry.evidence.as_str()))
            .collect::<Vec<_>>(),
        CAPABILITIES
    );
    for capability in &manifest.capabilities {
        assert_anchor_exists(&root, &capability.evidence);
    }
    assert_eq!(
        manifest
            .exclusions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        EXCLUSIONS
    );
}

fn assert_anchor_exists(root: &Path, evidence: &str) {
    let (path, anchor) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("evidence has no anchor: {evidence}"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read evidence {path}: {error}"));
    assert!(
        source.contains(&format!("fn {anchor}(")),
        "evidence anchor is absent: {evidence}"
    );
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(
        &fs::read(path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
