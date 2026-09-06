//! Current-contract evidence validation for executable source-task lowering.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/async-source-lowering-v1.json";
const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
const ISSUE: &str = "GNT-ASYNC-LOWER-001";
const FORMAT: &str = "gantry.async-source-lowering-evidence/v1";

const CAPABILITIES: &[(&str, &str)] = &[
    (
        "closed-generic-task-body-identity",
        "crates/gantry-conformance/tests/executable_bridge.rs#generic_task_bodies_have_closed_distinct_identities",
    ),
    (
        "independent-nested-task-bodies",
        "crates/gantry-conformance/tests/executable_bridge.rs#nested_task_bodies_preserve_captures_and_joinall_order",
    ),
    (
        "join-expression-lowering",
        "crates/gantry-conformance/tests/executable_bridge.rs#join_operand_preserves_surrounding_expression",
    ),
    (
        "retained-task-program-codec",
        "crates/gantry-conformance/tests/executable_bridge.rs#analyzed_task_program_round_trips_through_retained_codec",
    ),
    (
        "runtime-profile-rejection",
        "crates/gantry-conformance/tests/executable_bridge.rs#analyzed_concurrent_entry_reaches_the_existing_profile_rejection",
    ),
    (
        "typed-spawn-join-captures",
        "crates/gantry-conformance/tests/executable_bridge.rs#concurrent_source_lowers_spawn_join_and_typed_captures",
    ),
];

#[derive(Clone, Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    implementation: Implementation,
    requirements: Vec<RequirementEvidence>,
    artifacts: Vec<Artifact>,
    capabilities: Vec<Capability>,
    claim: Claim,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Implementation {
    commit: String,
    subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RequirementEvidence {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Artifact {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Capability {
    id: String,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Claim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    assignment_scope: String,
    full_clause_coverage: bool,
}

#[derive(Debug, Deserialize)]
struct Contract {
    requirement_assignments: Vec<RequirementAssignment>,
}

#[derive(Debug, Deserialize)]
struct RequirementAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[test]
fn checked_in_async_source_lowering_evidence_is_current_and_narrow() {
    let root = workspace_root();
    let manifest: EvidenceManifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn async_source_lowering_evidence_rejects_tampering_and_overclaiming() {
    let root = workspace_root();
    let manifest: EvidenceManifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut incomplete = manifest.clone();
    incomplete.capabilities.pop();
    assert!(validate_manifest(&root, &incomplete).is_err());

    let mut reassigned = manifest.clone();
    reassigned.requirements.pop();
    assert!(validate_manifest(&root, &reassigned).is_err());

    let mut overclaimed = manifest.clone();
    overclaimed
        .claim
        .advertises_profiles
        .push("concurrent-evaluator".to_owned());
    assert!(validate_manifest(&root, &overclaimed).is_err());

    let mut runtime_claim = manifest;
    runtime_claim.exclusions.remove(0);
    assert!(validate_manifest(&root, &runtime_claim).is_err());
}

fn validate_manifest(root: &Path, manifest: &EvidenceManifest) -> Result<(), String> {
    if manifest.format != FORMAT || manifest.issue != ISSUE {
        return Err("source lowering evidence identity differs".to_owned());
    }
    if manifest.specification_sha256 != sha256(&read(root.join("SPEC.md"))?) {
        return Err("source lowering evidence uses another specification".to_owned());
    }
    if manifest.implementation.commit != "b91ac8143ecf9847d927126e6ea05b03426bfb9c"
        || manifest.implementation.subject
            != "Lower concurrent source into independent executable task bodies."
    {
        return Err("source lowering implementation provenance differs".to_owned());
    }

    validate_requirements(root, &manifest.requirements)?;
    validate_artifacts(root, &manifest.artifacts)?;
    validate_capabilities(root, &manifest.capabilities, &manifest.artifacts)?;
    validate_claim(&manifest.claim, &manifest.exclusions)
}

fn validate_requirements(root: &Path, declared: &[RequirementEvidence]) -> Result<(), String> {
    let contract: Contract = read_json(&root.join(CONTRACT_PATH));
    let mut assigned = contract
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == ISSUE)
        })
        .map(|assignment| RequirementEvidence {
            requirement: assignment.requirement,
            clause: assignment.clause,
            profiles: assignment.profiles,
        })
        .collect::<Vec<_>>();
    assigned.sort();
    let mut declared = declared.to_vec();
    declared.sort();
    if declared != assigned
        || declared
            != [
                RequirementEvidence {
                    requirement: "GNT-15.8".to_owned(),
                    clause: "clause-001".to_owned(),
                    profiles: vec!["embedding".to_owned()],
                },
                RequirementEvidence {
                    requirement: "GNT-3-M-SPAWN".to_owned(),
                    clause: "clause-001".to_owned(),
                    profiles: vec!["concurrent-evaluator".to_owned()],
                },
            ]
    {
        return Err("source lowering frozen requirement assignments differ".to_owned());
    }
    Ok(())
}

fn validate_artifacts(root: &Path, artifacts: &[Artifact]) -> Result<(), String> {
    let expected = [
        "crates/gantry-analysis/src/bodies.rs",
        "crates/gantry-analysis/src/executable.rs",
        "crates/gantry-conformance/tests/executable_bridge.rs",
        CONTRACT_PATH,
    ];
    if artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .ne(expected)
    {
        return Err("source lowering artifact inventory differs".to_owned());
    }
    for artifact in artifacts {
        if artifact.sha256 != sha256(&read(root.join(&artifact.path))?) {
            return Err(format!(
                "source lowering artifact is stale: {}",
                artifact.path
            ));
        }
    }
    Ok(())
}

fn validate_capabilities(
    root: &Path,
    capabilities: &[Capability],
    artifacts: &[Artifact],
) -> Result<(), String> {
    if capabilities
        .iter()
        .map(|capability| (capability.id.as_str(), capability.evidence.as_str()))
        .ne(CAPABILITIES.iter().copied())
    {
        return Err("source lowering capability evidence differs".to_owned());
    }
    for capability in capabilities {
        let (path, anchor) = capability
            .evidence
            .split_once('#')
            .ok_or_else(|| format!("evidence has no anchor: {}", capability.evidence))?;
        if !artifacts.iter().any(|artifact| artifact.path == path) {
            return Err(format!("evidence path is not authenticated: {path}"));
        }
        let source = String::from_utf8(read(root.join(path))?)
            .map_err(|error| format!("evidence source is not UTF-8: {error}"))?;
        if !source.contains(&format!("fn {anchor}")) {
            return Err(format!(
                "evidence anchor is absent: {}",
                capability.evidence
            ));
        }
    }
    Ok(())
}

fn validate_claim(claim: &Claim, exclusions: &[String]) -> Result<(), String> {
    let expected_exclusions = [
        "This evidence does not claim runtime coordinator behavior, executor submission, native child scheduling, join settlement, detachment, or cancellation.",
        "The assigned GNT-3-M-SPAWN clause includes downstream runtime obligations that this lowering evidence does not cover.",
        "The assigned GNT-15.8 clause includes publication-set and full conformance-corpus obligations that this lowering evidence does not cover.",
        "This evidence publishes no analyzer, concurrent-evaluator, embedding, evaluator, or durable-runtime profile claim.",
    ];
    if !claim.profiles.is_empty()
        || !claim.advertises_profiles.is_empty()
        || claim.assignment_scope
            != "lowering-relevant slices of the exact frozen GNT-ASYNC-LOWER-001 assignments"
        || claim.full_clause_coverage
        || exclusions != expected_exclusions
    {
        return Err("source lowering evidence overclaims its scope".to_owned());
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read(path: PathBuf) -> Result<Vec<u8>, String> {
    fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
