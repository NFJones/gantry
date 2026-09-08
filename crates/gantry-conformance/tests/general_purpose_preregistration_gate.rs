//! Independent validation of the general-purpose preregistration evidence gate.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/general-purpose-preregistration-gate-v1.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
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
fn preregistration_gate_is_current_and_makes_no_completion_claim() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn preregistration_gate_rejects_stale_evidence_and_overclaims() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut profile = manifest.clone();
    profile.claim.profiles.push("frontend".to_owned());
    assert!(validate_manifest(&root, &profile).is_err());

    let mut stable = manifest;
    stable.claim.advertises_stable_edition = true;
    assert!(validate_manifest(&root, &stable).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.general-purpose-preregistration-gate-evidence/v1"
        || manifest.gate != "GNT-GP-GATE-000"
        || manifest.status != "verified"
    {
        return Err("preregistration gate identity or status is invalid".to_owned());
    }
    validate_digest(root, &manifest.specification)?;
    if manifest.specification.path != "SPEC.md"
        || manifest.specification.sha256 != gantry::PROFILE_SPECIFICATION_REVISION
    {
        return Err("preregistration gate does not bind the active specification".to_owned());
    }
    if !manifest.prerequisites.is_empty()
        || manifest
            .prerequisites
            .iter()
            .any(|prerequisite| prerequisite.issue == manifest.gate)
    {
        return Err("root preregistration gate must have no prerequisites".to_owned());
    }

    ordered_unique(
        manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str()),
        "artifacts",
    )?;
    let required_artifacts = BTreeSet::from([
        "crates/gantry-conformance/tests/general_purpose_preregistration.rs",
        "docs/general-purpose-preregistration.md",
        "protocol/catalogs/general-purpose-preregistration-v1.json",
        "protocol/goldens/general-purpose-preregistration-v1.canonical.json",
        "protocol/schemas/general-purpose-preregistration-v1.schema.json",
    ]);
    let actual_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    if actual_artifacts != required_artifacts {
        return Err("preregistration gate artifact membership differs".to_owned());
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
    if manifest.evidence.len() != 2
        || manifest.evidence.iter().any(|evidence| {
            evidence.state != "verified"
                || evidence.visibility != "public-repository"
                || !root.join(&evidence.path).is_file()
        })
    {
        return Err("preregistration evidence is incomplete".to_owned());
    }
    if manifest.claim.phase != "phase-0-preregistration"
        || !manifest.claim.profiles.is_empty()
        || manifest.claim.advertises_general_purpose
        || manifest.claim.advertises_production_strategy
        || manifest.claim.advertises_stable_edition
        || manifest.claim.advertises_stable_standard_library
    {
        return Err("preregistration gate overclaims completion".to_owned());
    }
    if manifest.validation_commands.len() < 6 || manifest.environment_gaps.len() != 3 {
        return Err("validation or qualification record is incomplete".to_owned());
    }
    Ok(())
}

fn validate_digest(root: &Path, artifact: &FileDigest) -> Result<(), String> {
    let bytes = fs::read(root.join(&artifact.path))
        .map_err(|error| format!("could not read {}: {error}", artifact.path))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != artifact.sha256 {
        return Err(format!("artifact digest differs: {}", artifact.path));
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
