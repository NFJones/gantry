//! Independent validation of the combined concurrent-durable profile gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry::ConformanceProfile;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/combined-gate-v1.json";
const CRASH_EVIDENCE: &str = "crates/gantry-conformance/tests/combined_refinement.rs#public_combined_crash_cuts_recover_without_repeating_task_transitions";
const JOIN_EVIDENCE: &str = "crates/gantry-conformance/tests/combined_refinement.rs#public_combined_join_ownership_and_settlement_recover_once";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    composed_obligations: Vec<ComposedObligation>,
    required_evidence: Vec<String>,
    composition: Composition,
    claim: Claim,
    validation_commands: Vec<String>,
    environment_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prerequisite {
    issue: String,
    commit: String,
    subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ComposedObligation {
    requirement: String,
    clause: String,
    excluded_profile: String,
    complementary_profile: String,
    combined_evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Composition {
    evaluator: String,
    checkpoint: String,
    journal_evidence: String,
    graph_recovery: String,
    event_recovery: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    excludes_profiles: Vec<String>,
    excludes_capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<Clause>,
}

#[derive(Debug, Deserialize)]
struct Clause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StandaloneGate {
    status: String,
    artifacts: Vec<FileDigest>,
}

#[test]
fn checked_in_combined_profile_gate_is_current() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert!(gantry::advertised_profiles().is_empty());
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification.sha256,
        gantry::PROFILE_SPECIFICATION_REVISION,
    ));
    assert!(validate_manifest(&root, &manifest).is_err());
}

#[test]
fn combined_gate_rejects_stale_overclaimed_and_incomplete_evidence() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut overclaimed = manifest.clone();
    overclaimed
        .claim
        .excludes_capabilities
        .push("unverified-capability".to_owned());
    assert!(validate_manifest(&root, &overclaimed).is_err());

    let mut missing = manifest;
    missing.composed_obligations.pop();
    assert!(validate_manifest(&root, &missing).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.combined-gate-evidence/v1"
        || manifest.gate != "GNT-COMB-001"
        || manifest.status != "verified"
    {
        return Err("combined gate identity or status is invalid".to_owned());
    }
    let claimed = [
        "analyzer",
        "concurrent-evaluator",
        "durable-runtime",
        "embedding",
        "evaluator",
        "frontend",
    ];
    if manifest.claim.profiles != claimed
        || manifest.claim.advertises_profiles != claimed
        || !manifest.claim.excludes_profiles.is_empty()
        || !manifest.claim.excludes_capabilities.is_empty()
        || !gantry::compiled_features().concurrent
        || !gantry::compiled_features().durable
        || !gantry::PROFILE_CLAIMS_ENABLED
        || gantry::advertised_profiles()
            != [
                ConformanceProfile::Analyzer,
                ConformanceProfile::ConcurrentEvaluator,
                ConformanceProfile::DurableRuntime,
                ConformanceProfile::Embedding,
                ConformanceProfile::Evaluator,
                ConformanceProfile::Frontend,
            ]
    {
        return Err("combined claim is invalid or incomplete".to_owned());
    }

    validate_file_digest(root, &manifest.specification, "specification")?;
    validate_sorted_unique(
        "prerequisite issues",
        manifest
            .prerequisites
            .iter()
            .map(|prerequisite| prerequisite.issue.as_str()),
    )?;
    for prerequisite in &manifest.prerequisites {
        validate_commit(root, prerequisite)?;
    }

    validate_sorted_unique(
        "artifact paths",
        manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str()),
    )?;
    for artifact in &manifest.artifacts {
        validate_file_digest(root, artifact, "artifact")?;
    }
    let artifact_paths = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    for required in required_artifact_paths() {
        if !artifact_paths.contains(required) {
            return Err(format!("required combined artifact is missing: {required}"));
        }
    }

    let concurrent: StandaloneGate =
        read_json(&root.join("protocol/conformance/concurrent-gate-v1.json"));
    let durable: StandaloneGate =
        read_json(&root.join("protocol/conformance/durable-gate-v1.json"));
    if concurrent.status != "verified" || durable.status != "verified" {
        return Err("standalone prerequisite gate is not verified".to_owned());
    }
    for artifact in concurrent.artifacts.iter().chain(&durable.artifacts) {
        validate_file_digest(root, artifact, "delegated standalone artifact")?;
    }

    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    if review.specification_sha256 != manifest.specification.sha256 {
        return Err("combined evidence uses another specification revision".to_owned());
    }
    validate_composed_obligations(root, manifest, &review, &artifact_paths)?;

    if manifest.required_evidence != [CRASH_EVIDENCE, JOIN_EVIDENCE] {
        return Err("required combined evidence is incomplete".to_owned());
    }
    for evidence in &manifest.required_evidence {
        validate_public_test_anchor(root, evidence)?;
        require_anchor_artifact(evidence, &artifact_paths)?;
    }

    if manifest.composition.evaluator != "gantry-runtime::Machine"
        || manifest.composition.checkpoint != "gantry-runtime::ConcurrentDurableCheckpointV1"
        || manifest.composition.journal_evidence != "gantry-runtime::ConcurrentDurableEvidenceV1"
        || manifest.composition.graph_recovery
            != "gantry-runtime::recover_concurrent_authoritative_prefix"
        || manifest.composition.event_recovery != "gantry-runtime::RecoveredDurableEventsV1"
    {
        return Err("combined composition does not identify the existing runtime path".to_owned());
    }

    validate_sorted_unique(
        "validation commands",
        manifest.validation_commands.iter().map(String::as_str),
    )?;
    if manifest.validation_commands.is_empty()
        || manifest.environment_gaps
            != [
                "The exact Rust 1.97.1 and rolling stable macOS product lanes execute in hosted CI; this Linux gate run does not claim a local macOS result or a qualified stable-media power-loss environment.",
            ]
    {
        return Err("validation commands or environment gaps are incomplete".to_owned());
    }
    Ok(())
}

fn validate_composed_obligations(
    root: &Path,
    manifest: &Manifest,
    review: &RequirementReview,
    artifact_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    if manifest.composed_obligations.len() != 14
        || !manifest
            .composed_obligations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err("combined obligation set differs from reviewed exclusions".to_owned());
    }
    let declared = manifest
        .composed_obligations
        .iter()
        .map(|obligation| {
            (
                obligation.requirement.as_str(),
                obligation.clause.as_str(),
                obligation.excluded_profile.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeSet::new();
    let mut clause_index = BTreeMap::new();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            clause_index.insert((requirement.id.as_str(), clause.key.as_str()), clause);
            for profile_review in &clause.profile_reviews {
                let rationale = profile_review.rationale.as_deref().unwrap_or_default();
                if rationale.contains("GNT-COMB-001")
                    || rationale.contains("combined concurrent-durable")
                {
                    if profile_review.state != "not-applicable"
                        || !profile_review.evidence.is_empty()
                    {
                        return Err("combined-owned standalone exclusion is not narrow".to_owned());
                    }
                    expected.insert((
                        requirement.id.as_str(),
                        clause.key.as_str(),
                        profile_review.profile.as_str(),
                    ));
                }
            }
        }
    }
    if declared != expected {
        return Err("combined obligation set differs from reviewed exclusions".to_owned());
    }

    for obligation in &manifest.composed_obligations {
        let clause = clause_index
            .get(&(obligation.requirement.as_str(), obligation.clause.as_str()))
            .ok_or_else(|| "combined obligation names an unknown clause".to_owned())?;
        if obligation.complementary_profile == "combined-only" {
            if obligation.requirement != "GNT-11.8"
                || clause
                    .profile_reviews
                    .iter()
                    .any(|review| review.state == "covered")
            {
                return Err("combined-only obligation is not narrowly classified".to_owned());
            }
        } else {
            let complementary = clause
                .profile_reviews
                .iter()
                .find(|review| review.profile == obligation.complementary_profile)
                .ok_or_else(|| "combined obligation lacks complementary review".to_owned())?;
            if complementary.state != "covered" || complementary.evidence.is_empty() {
                return Err("combined obligation lacks covered standalone evidence".to_owned());
            }
        }
        if !matches!(
            obligation.combined_evidence.as_str(),
            CRASH_EVIDENCE | JOIN_EVIDENCE
        ) {
            return Err("combined obligation uses unknown all-features evidence".to_owned());
        }
        validate_public_test_anchor(root, &obligation.combined_evidence)?;
        require_anchor_artifact(&obligation.combined_evidence, artifact_paths)?;
    }
    Ok(())
}

fn required_artifact_paths() -> [&'static str; 11] {
    [
        "SPEC.md",
        "crates/gantry-conformance/tests/combined_gate.rs",
        "crates/gantry-conformance/tests/combined_refinement.rs",
        "crates/gantry-runtime/src/recovery/concurrent.rs",
        "crates/gantry-runtime/src/task.rs",
        "crates/gantry-runtime/src/task/combined_checkpoint.rs",
        "crates/gantry/src/lib.rs",
        "protocol/conformance/concurrent-gate-v1.json",
        "protocol/conformance/durable-gate-v1.json",
        "protocol/requirements/generated/requirements-v1.json",
        "protocol/requirements/reviewed-v1.json",
    ]
}

fn validate_public_test_anchor(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, test) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence anchor has no test: {evidence}"))?;
    if !path.starts_with("crates/gantry-conformance/tests/") || !path.ends_with(".rs") {
        return Err(format!(
            "evidence is not a public conformance test: {evidence}"
        ));
    }
    let source = fs::read_to_string(root.join(path))
        .map_err(|error| format!("could not read evidence {path}: {error}"))?;
    if !source.contains(&format!("fn {test}(")) {
        return Err(format!("evidence test is missing: {evidence}"));
    }
    Ok(())
}

fn require_anchor_artifact(evidence: &str, artifact_paths: &BTreeSet<&str>) -> Result<(), String> {
    let (path, _) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence anchor has no test: {evidence}"))?;
    if !artifact_paths.contains(path) {
        return Err(format!("evidence file has no authenticated digest: {path}"));
    }
    Ok(())
}

fn validate_file_digest(root: &Path, file: &FileDigest, kind: &str) -> Result<(), String> {
    let bytes = fs::read(root.join(&file.path))
        .map_err(|error| format!("could not read {kind} {}: {error}", file.path))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if file.sha256.len() != 64 || actual != file.sha256 {
        return Err(format!("{kind} digest differs: {}", file.path));
    }
    Ok(())
}

fn validate_commit(root: &Path, prerequisite: &Prerequisite) -> Result<(), String> {
    if prerequisite.commit.len() != 40
        || !prerequisite
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || prerequisite.subject.trim().is_empty()
    {
        return Err(format!(
            "invalid prerequisite record: {}",
            prerequisite.issue
        ));
    }
    let ancestor = Command::new("git")
        .current_dir(root)
        .args(["merge-base", "--is-ancestor", &prerequisite.commit, "HEAD"])
        .status()
        .map_err(|error| format!("could not inspect prerequisite commit: {error}"))?;
    if !ancestor.success() {
        return Err(format!(
            "prerequisite commit is not an ancestor: {}",
            prerequisite.issue
        ));
    }
    let subject = Command::new("git")
        .current_dir(root)
        .args(["show", "-s", "--format=%s", &prerequisite.commit])
        .output()
        .map_err(|error| format!("could not inspect prerequisite subject: {error}"))?;
    if !subject.status.success()
        || String::from_utf8_lossy(&subject.stdout).trim() != prerequisite.subject
    {
        return Err(format!(
            "prerequisite subject differs: {}",
            prerequisite.issue
        ));
    }
    Ok(())
}

fn validate_sorted_unique<'a>(
    kind: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.is_empty() || !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(format!("{kind} are empty, duplicated, or unsorted"));
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

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
