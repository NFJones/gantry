//! Independent validation of the general-purpose semantic foundation gate.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const RECORD_PATH: &str = "protocol/conformance/general-purpose-foundation-gate-v1.json";

const EXPECTED_PREREQUISITES: &[&str] = &[
    "015994ca-a48c-418f-94ef-ff6754cf60c7",
    "0e28f3d7-12d6-4f5b-bbaf-1fb058cf1153",
    "156160ed-c436-471f-b465-c64e497270f1",
    "21fa527c-7af4-42d8-aeec-73778f8db706",
    "2696ec5d-1862-4351-a6a8-9634dc5d39c6",
    "2fa9f962-c114-4426-9563-0f9d3afbb092",
    "317a9fac-1547-4201-8068-ba99ead94cc7",
    "479f93b3-e5fe-428b-ac14-2a327fd9a291",
    "49bd7879-3cbb-4f44-9a53-f5a95ae32383",
    "55242960-678c-4e1d-85eb-d853c6d0ffcf",
    "5d2b7af2-6f39-435f-9574-aa4b1bb470dc",
    "60864b0a-bab4-4969-bf5d-5e8d47004d0c",
    "7695985d-73aa-45df-8a43-3db90f89030c",
    "8ca9ca59-e5f4-4a67-b02c-fd72e3cfa907",
    "9bb85d44-61fe-49a1-bc3c-cc40154e60b0",
    "aaebf76e-884d-465a-9070-179f4fed597a",
    "b0533834-73f4-431f-aeb4-1120b118525f",
    "b120e06d-c596-4c39-801c-9ec2fc7ee451",
    "b8c4c779-6458-4118-8933-4014356d7cf8",
    "bdad65ae-0213-4474-b182-b0b40792b817",
    "bebfddf1-3303-4611-b7a6-a4216dc0aa42",
    "dc3bd12e-9173-4378-a4cd-e120b05c1ad4",
    "ddc2962d-c7b6-49b5-9a8f-a3a4756395b2",
    "f3f9766b-b9a5-4517-946d-077863d1bda5",
    "fb4e67ad-f653-43ed-a2ea-f874a1ea1837",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    prerequisite_source: FileDigest,
    verifies: Vec<String>,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    evidence: Vec<Evidence>,
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
struct Evidence {
    id: String,
    state: String,
    visibility: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    phase: String,
    profiles: Vec<String>,
    advertises_general_purpose: bool,
    advertises_production_strategy: bool,
    advertises_stable_edition: bool,
    advertises_stable_standard_library: bool,
}

#[test]
fn foundation_gate_is_current_and_makes_no_completion_claim() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(RECORD_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn foundation_gate_rejects_malformed_missing_cyclic_stale_and_overclaiming_records() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(RECORD_PATH));

    let mut malformed = manifest.clone();
    malformed.prerequisites[0].commit = "not-a-commit".to_owned();
    assert!(validate_manifest(&root, &malformed).is_err());

    let mut missing = manifest.clone();
    missing.prerequisites.pop();
    assert!(validate_manifest(&root, &missing).is_err());

    let mut cyclic = manifest.clone();
    cyclic.prerequisites.push(cyclic.prerequisites[0].clone());
    assert!(validate_manifest(&root, &cyclic).is_err());

    let mut self_referential = manifest.clone();
    self_referential.prerequisites[0].issue = self_referential.gate.clone();
    assert!(validate_manifest(&root, &self_referential).is_err());

    let mut fabricated = manifest.clone();
    fabricated.prerequisites[0].commit = "0badc0d".to_owned();
    assert!(validate_manifest(&root, &fabricated).is_err());

    let mut relabelled = manifest.clone();
    relabelled.prerequisites[0].subject = "Unrelated work".to_owned();
    assert!(validate_manifest(&root, &relabelled).is_err());

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut overclaim = manifest.clone();
    overclaim.claim.advertises_general_purpose = true;
    assert!(validate_manifest(&root, &overclaim).is_err());

    let mut profiled = manifest.clone();
    profiled.claim.profiles.push("frontend".to_owned());
    assert!(validate_manifest(&root, &profiled).is_err());

    let mut unqualified = manifest;
    unqualified.environment_gaps.clear();
    assert!(validate_manifest(&root, &unqualified).is_err());
}

#[test]
fn foundation_gate_refuses_a_bound_source_that_is_not_committed() {
    let root = workspace_root();
    let untracked = FileDigest {
        path: "docs/reference/general-purpose-refactor-issue-plan.md".to_owned(),
        sha256: "0".repeat(64),
    };
    assert!(
        validate_tracked_source(&root, &untracked).is_err(),
        "a source under the ignored directory is refused even when a local copy exists"
    );
    let specification =
        fs::read(root.join("SPEC.md")).unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    let tracked = FileDigest {
        path: "SPEC.md".to_owned(),
        sha256: format!("{:x}", Sha256::digest(specification)),
    };
    assert!(
        validate_tracked_source(&root, &tracked).is_ok(),
        "a committed source whose bytes match is admitted"
    );
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.general-purpose-foundation-gate-evidence/v1"
        || manifest.gate != "GNT-GP-GATE-100"
        || manifest.status != "verified"
    {
        return Err("foundation gate identity or status is invalid".to_owned());
    }
    validate_digest(root, &manifest.specification)?;
    if manifest.specification.path != "SPEC.md"
        || manifest.specification.sha256 != gantry::PROFILE_SPECIFICATION_REVISION
    {
        return Err("foundation gate does not bind the active specification".to_owned());
    }
    validate_tracked_source(root, &manifest.prerequisite_source)?;

    ordered_unique(manifest.verifies.iter().map(String::as_str), "verifies")?;
    if manifest.verifies.len() < EXPECTED_VERIFIES_FLOOR {
        return Err("foundation gate does not declare what it verifies".to_owned());
    }
    ordered_unique(
        manifest
            .prerequisites
            .iter()
            .map(|prerequisite| prerequisite.issue.as_str()),
        "prerequisites",
    )?;
    let expected = EXPECTED_PREREQUISITES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual = manifest
        .prerequisites
        .iter()
        .map(|prerequisite| prerequisite.issue.as_str())
        .collect::<BTreeSet<_>>();
    if actual != expected || manifest.prerequisites.len() != expected.len() {
        return Err("foundation gate prerequisite closure differs".to_owned());
    }
    if manifest.prerequisites.iter().any(|prerequisite| {
        prerequisite.issue == manifest.gate
            || !is_commit(prerequisite.commit.as_str())
            || prerequisite.subject.trim().is_empty()
    }) {
        return Err("foundation gate prerequisite provenance is malformed".to_owned());
    }
    for prerequisite in &manifest.prerequisites {
        validate_commit(root, prerequisite)?;
    }

    ordered_unique(
        manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str()),
        "artifacts",
    )?;
    if manifest.artifacts.is_empty() {
        return Err("foundation gate binds no artifacts".to_owned());
    }
    for artifact in &manifest.artifacts {
        validate_digest(root, artifact)?;
    }

    ordered_unique(
        manifest
            .evidence
            .iter()
            .map(|evidence| evidence.id.as_str()),
        "evidence",
    )?;
    if manifest.evidence.len() < EXPECTED_EVIDENCE_FLOOR
        || manifest.evidence.iter().any(|evidence| {
            evidence.state != "verified"
                || evidence.visibility != "public-repository"
                || !root.join(&evidence.path).is_file()
        })
    {
        return Err("foundation gate evidence is incomplete".to_owned());
    }
    if manifest.claim.phase != "phase-0-foundation"
        || !manifest.claim.profiles.is_empty()
        || manifest.claim.advertises_general_purpose
        || manifest.claim.advertises_production_strategy
        || manifest.claim.advertises_stable_edition
        || manifest.claim.advertises_stable_standard_library
    {
        return Err("foundation gate overclaims completion".to_owned());
    }
    if manifest.validation_commands.len() < 6 || manifest.environment_gaps.len() < 3 {
        return Err("validation or qualification record is incomplete".to_owned());
    }
    Ok(())
}

const EXPECTED_EVIDENCE_FLOOR: usize = 4;

const EXPECTED_VERIFIES_FLOOR: usize = 5;

fn validate_commit(root: &Path, prerequisite: &Prerequisite) -> Result<(), String> {
    let ancestor = Command::new("git")
        .current_dir(root)
        .args(["merge-base", "--is-ancestor", &prerequisite.commit, "HEAD"])
        .stderr(std::process::Stdio::null())
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

fn is_commit(value: &str) -> bool {
    (7..=40).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validates one bound gate source: it must be committed in `git` and its bytes must match.
///
/// A source that is not tracked — for example a path under an ignored directory that merely
/// happens to exist in this workspace — is refused, because the record could not then be
/// reproduced from repository bytes.
fn validate_tracked_source(root: &Path, artifact: &FileDigest) -> Result<(), String> {
    let tracked = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--error-unmatch", &artifact.path])
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("could not inspect tracked gate sources: {error}"))?;
    if !tracked.success() {
        return Err(format!("gate source is not committed: {}", artifact.path));
    }
    validate_digest(root, artifact)
}

fn validate_digest(root: &Path, artifact: &FileDigest) -> Result<(), String> {
    let bytes = fs::read(root.join(&artifact.path))
        .map_err(|error| format!("could not read {}: {error}", artifact.path))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != artifact.sha256 {
        return Err(format!(
            "artifact digest differs (refresh this gate record and regenerate the publication set): {}",
            artifact.path
        ));
    }
    Ok(())
}

fn ordered_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<(), String> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} must be strictly ordered and unique"));
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate must be in the workspace"))
        .to_path_buf()
}
