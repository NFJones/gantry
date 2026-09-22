//! Independent validation of the deterministic-language milestone gate (`GNT-GP-GATE-200`).
//!
//! The gate record authenticates every Phase-1 prerequisite by issue id, ancestor commit, and exact
//! commit subject, binds the active specification and prerequisite-source digests, refreshes every
//! artifact digest it cites, requires the public evidence entries it names to exist, and refuses
//! every completion overclaim. This lane re-derives all of it from repository bytes.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const RECORD_PATH: &str = "protocol/conformance/general-purpose-milestone-gate-v1.json";

const EXPECTED_PREREQUISITES: &[&str] = &[
    "0113b3f5-9177-4870-849a-8d72b8af2dec",
    "015b197c-b484-4e04-a22c-4a180de447e3",
    "062b99fd-c642-4a71-84f8-ac19904b7b38",
    "152c8944-f974-4901-b7ce-dc0d7e46eecd",
    "181cb89d-1d1e-4643-a6fb-210b8c4c267a",
    "38ca21fb-8ab8-4a74-92a7-7f961bbf2929",
    "4f129e96-9fe0-444b-88ba-023824530b6b",
    "4fc80378-f38b-4c49-9f29-c024c7d47df2",
    "4ff620d7-48e3-4302-8c99-191a79614a65",
    "5789eddc-1dfa-4e8d-b28a-68b8e456d328",
    "59b613ff-fd89-44a2-bf95-895d887569ac",
    "6700f5ee-e62a-4652-8ae3-0cdb76c0dadf",
    "6c821d63-37f7-45a3-91a8-d9a85e8b81a0",
    "82d06478-08da-4eed-a870-4401b17ddf6f",
    "8516ff7e-feef-4a1b-a69c-b33bc73e9af0",
    "adfa200b-cdb1-4860-a60c-37338ffd0704",
    "c484efec-aec7-459b-a743-94f7a37df8b9",
    "d4aaa6ea-3f9f-44b3-bf27-fa8ad49598ea",
    "ebd70791-8676-424c-95d8-4f2e52371745",
    "f3908168-98c6-4286-8b12-6864285dbc0c",
];

const EXPECTED_VERIFIES_FLOOR: usize = 5;

const EXPECTED_EVIDENCE_FLOOR: usize = 4;

const EXPECTED_ACCEPTANCE_FLOOR: usize = 10;

const EXPECTED_PHASE: &str = "phase-1-deterministic-language";

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
    acceptance: Vec<Acceptance>,
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
struct Acceptance {
    item: String,
    disposition: String,
    evidence: String,
    owner: Option<String>,
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
fn milestone_gate_is_current_and_makes_no_completion_claim() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(RECORD_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn milestone_gate_rejects_malformed_missing_cyclic_stale_and_overclaiming_records() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(RECORD_PATH));

    let mut malformed = manifest.clone();
    malformed.prerequisites[0].commit = "not-a-commit".to_owned();
    assert!(validate_manifest(&root, &malformed).is_err());

    let mut missing = manifest.clone();
    missing.prerequisites.pop();
    assert!(validate_manifest(&root, &missing).is_err());

    let mut duplicated = manifest.clone();
    duplicated
        .prerequisites
        .push(duplicated.prerequisites[0].clone());
    assert!(validate_manifest(&root, &duplicated).is_err());

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

    let mut missing_evidence = manifest.clone();
    missing_evidence
        .evidence
        .truncate(EXPECTED_EVIDENCE_FLOOR - 1);
    assert!(validate_manifest(&root, &missing_evidence).is_err());

    let mut unknown_disposition = manifest.clone();
    unknown_disposition.acceptance[0].disposition = "assumed".to_owned();
    assert!(validate_manifest(&root, &unknown_disposition).is_err());

    let mut unowned = manifest.clone();
    unowned.acceptance[4].owner = None;
    assert!(validate_manifest(&root, &unowned).is_err());

    let mut owned_pass = manifest.clone();
    owned_pass.acceptance[0].owner = Some("ownerless".to_owned());
    assert!(validate_manifest(&root, &owned_pass).is_err());

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

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.general-purpose-milestone-gate-evidence/v1"
        || manifest.gate != "GNT-GP-GATE-200"
        || manifest.status != "verified"
    {
        return Err("milestone gate identity or status is invalid".to_owned());
    }
    validate_digest(root, &manifest.specification)?;
    if manifest.specification.path != "SPEC.md"
        || manifest.specification.sha256 != gantry::PROFILE_SPECIFICATION_REVISION
    {
        return Err("milestone gate does not bind the active specification".to_owned());
    }
    validate_digest(root, &manifest.prerequisite_source)?;

    ordered_unique(manifest.verifies.iter().map(String::as_str), "verifies")?;
    if manifest.verifies.len() < EXPECTED_VERIFIES_FLOOR {
        return Err("milestone gate does not declare what it verifies".to_owned());
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
        return Err("milestone gate prerequisite closure differs".to_owned());
    }
    if manifest.prerequisites.iter().any(|prerequisite| {
        prerequisite.issue == manifest.gate
            || !is_commit(prerequisite.commit.as_str())
            || prerequisite.subject.trim().is_empty()
    }) {
        return Err("milestone gate prerequisite provenance is malformed".to_owned());
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
        return Err("milestone gate binds no artifacts".to_owned());
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
        return Err("milestone gate evidence is incomplete".to_owned());
    }
    ordered_unique(
        manifest
            .acceptance
            .iter()
            .map(|acceptance| acceptance.item.as_str()),
        "acceptance",
    )?;
    if manifest.acceptance.len() < EXPECTED_ACCEPTANCE_FLOOR {
        return Err("milestone gate records too few acceptance items".to_owned());
    }
    for acceptance in &manifest.acceptance {
        if !root.join(&acceptance.evidence).is_file() {
            return Err(format!(
                "acceptance evidence is missing: {}",
                acceptance.item
            ));
        }
        match (acceptance.disposition.as_str(), acceptance.owner.as_deref()) {
            ("passed", None) => {}
            ("qualified", Some(owner)) if !owner.trim().is_empty() => {}
            _ => {
                return Err(format!(
                    "acceptance disposition or owner is invalid: {}",
                    acceptance.item
                ));
            }
        }
    }
    if manifest.claim.phase != EXPECTED_PHASE
        || !manifest.claim.profiles.is_empty()
        || manifest.claim.advertises_general_purpose
        || manifest.claim.advertises_production_strategy
        || manifest.claim.advertises_stable_edition
        || manifest.claim.advertises_stable_standard_library
    {
        return Err("milestone gate overclaims completion".to_owned());
    }
    if manifest.validation_commands.len() < 6 || manifest.environment_gaps.len() < 3 {
        return Err("validation or qualification record is incomplete".to_owned());
    }
    Ok(())
}

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
