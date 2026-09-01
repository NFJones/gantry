//! Independent validation of the Phase 1 source-substrate evidence index.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry_conformance::{
    EvidenceKind, EvidenceRecord, EvidenceState, EvidenceVisibility, validate_gate_evidence,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/source-substrate-gate-v1.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    evidence_suites: Vec<EvidenceSuite>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSuite {
    id: String,
    kind: String,
    visibility: String,
    state: String,
    revision: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    phase: String,
    profiles: Vec<String>,
    advertises_profile: bool,
}

#[test]
fn checked_in_source_substrate_gate_is_current_and_claims_no_profile() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert!(manifest.claim.profiles.is_empty());
    assert!(!manifest.claim.advertises_profile);
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification.sha256,
        gantry::PROFILE_SPECIFICATION_REVISION,
    ));
    assert!(validate_manifest(&root, &manifest).is_err());
}

#[test]
fn source_substrate_gate_rejects_stale_artifacts_and_profile_overclaiming() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut overclaim = manifest;
    overclaim.claim.profiles.push("frontend".to_owned());
    overclaim.claim.advertises_profile = true;
    assert!(validate_manifest(&root, &overclaim).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.source-substrate-gate-evidence/v1"
        || manifest.gate != "GNT-GATE-100"
        || manifest.status != "verified"
    {
        return Err("source-substrate gate identity or status is invalid".to_owned());
    }
    if manifest.claim.phase != "phase-1-source-substrate"
        || manifest.claim.advertises_profile
        || !manifest.claim.profiles.is_empty()
    {
        return Err("source-substrate gate must not claim a profile".to_owned());
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

    validate_sorted_unique(
        "evidence suite ids",
        manifest
            .evidence_suites
            .iter()
            .map(|suite| suite.id.as_str()),
    )?;
    let required = [
        "diagnostic-presentation",
        "requirement-ledger",
        "source-provider",
        "source-substrate",
    ];
    let mut records = Vec::new();
    for suite in &manifest.evidence_suites {
        if !root.join(&suite.path).is_file() {
            return Err(format!("evidence suite path is missing: {}", suite.path));
        }
        records.push(EvidenceRecord {
            id: &suite.id,
            kind: evidence_kind(&suite.kind)?,
            visibility: evidence_visibility(&suite.visibility)?,
            state: evidence_state(&suite.state)?,
            revision: &suite.revision,
        });
    }
    validate_gate_evidence(&manifest.specification.sha256, &required, &records)
        .map_err(|errors| format!("gate evidence is invalid: {errors:?}"))?;

    if manifest.validation_commands.is_empty() || manifest.environment_gaps.len() != 1 {
        return Err("validation commands or environment gaps are incomplete".to_owned());
    }
    Ok(())
}

fn evidence_kind(value: &str) -> Result<EvidenceKind, String> {
    match value {
        "fixture" => Ok(EvidenceKind::Fixture),
        "golden" => Ok(EvidenceKind::Golden),
        "public-api" => Ok(EvidenceKind::PublicApi),
        "requirement" => Ok(EvidenceKind::Requirement),
        _ => Err(format!("unknown evidence kind: {value}")),
    }
}

fn evidence_visibility(value: &str) -> Result<EvidenceVisibility, String> {
    match value {
        "public-facade" => Ok(EvidenceVisibility::PublicFacade),
        _ => Err(format!("unknown evidence visibility: {value}")),
    }
}

fn evidence_state(value: &str) -> Result<EvidenceState, String> {
    match value {
        "verified" => Ok(EvidenceState::Verified),
        _ => Err(format!("unknown evidence state: {value}")),
    }
}

fn validate_file_digest(root: &Path, file: &FileDigest, kind: &str) -> Result<(), String> {
    let bytes = fs::read(root.join(&file.path))
        .map_err(|error| format!("could not read {kind} {}: {error}", file.path))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != file.sha256 {
        return Err(format!("{kind} digest differs: {}", file.path));
    }
    Ok(())
}

fn validate_commit(root: &Path, prerequisite: &Prerequisite) -> Result<(), String> {
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
        .map_err(|error| format!("could not read prerequisite subject: {error}"))?;
    let actual = String::from_utf8(subject.stdout)
        .map_err(|error| format!("prerequisite subject is not UTF-8: {error}"))?;
    if actual.trim_end() != prerequisite.subject {
        return Err(format!(
            "prerequisite subject differs: {}",
            prerequisite.issue
        ));
    }
    Ok(())
}

fn validate_sorted_unique<'a>(
    name: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let values = values.into_iter().collect::<Vec<_>>();
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) || unique.len() != values.len() {
        return Err(format!("{name} are not sorted and unique"));
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
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
