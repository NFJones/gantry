//! Independent validation of the analyzer profile evidence index.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/generics-traits-analyzer-gate-v1.json";
const PREREQUISITES: [&str; 6] = [
    "GNT-GEN-AN-001",
    "GNT-GEN-AN-002",
    "GNT-GEN-AN-003",
    "GNT-GEN-AN-004",
    "GNT-GEN-API-001",
    "GNT-GEN-PROOF-001",
];
const REQUIRED_ARTIFACTS: [&str; 33] = [
    "crates/gantry-analysis/src/bodies.rs",
    "crates/gantry-analysis/src/effects.rs",
    "crates/gantry-analysis/src/generics.rs",
    "crates/gantry-analysis/src/lowering.rs",
    "crates/gantry-analysis/src/schemas.rs",
    "crates/gantry-analysis/src/types.rs",
    "crates/gantry-conformance/tests/analyzer_gate.rs",
    "crates/gantry-conformance/tests/analyzer_lowering.rs",
    "crates/gantry-conformance/tests/analyzer_types.rs",
    "crates/gantry-conformance/tests/analyzer_validity_model.rs",
    "crates/gantry-conformance/tests/external_facade_matrix.rs",
    "crates/gantry-conformance/tests/frontend_lexical_evidence.rs",
    "crates/gantry-conformance/tests/frontend_parser_evidence.rs",
    "crates/gantry-conformance/tests/ir_contracts.rs",
    "crates/gantry-conformance/tests/requirements_ledger.rs",
    "crates/gantry-conformance/tests/validate_package.rs",
    "crates/gantry/src/lib.rs",
    "crates/gantry/src/validate.rs",
    "docs/analyzer-generics-and-traits.md",
    "docs/analyzer-package-validity.md",
    "protocol/catalogs/ir-contracts-v1.json",
    "protocol/catalogs/profiles-v1.json",
    "protocol/conformance/analyzer-validity-v1.json",
    "protocol/conformance/generics-traits-frontend-v1.json",
    "protocol/conformance/generics-traits-ir-v1.json",
    "protocol/goldens/analyzer-validity-model-v1.json",
    "protocol/requirements/generated/requirements-v1.json",
    "protocol/requirements/reviewed-v1.json",
    "protocol/requirements/section14-v1.json",
    "protocol/schemas/canonical-ir-v1.schema.json",
    "protocol/schemas/generated-schema-object-v1.schema.json",
    "protocol/schemas/package-source-manifest-v1.schema.json",
    "protocol/schemas/source-map-v1.schema.json",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    profile: String,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    review_summary: ReviewSummary,
    section14_excerpt_count: usize,
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
struct ReviewSummary {
    applicable_clause_count: usize,
    covered_count: usize,
    not_applicable_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    excludes_profiles: Vec<String>,
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
    profiles: Vec<String>,
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
struct Section14Review {
    specification_sha256: String,
    excerpts: Vec<Section14Excerpt>,
}

#[derive(Debug, Deserialize)]
struct Section14Excerpt {
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ValidityManifest {
    specification_sha256: String,
    issue: String,
    profile: String,
    argument: String,
    model: String,
    evidence_manifests: Vec<String>,
    lemmas: Vec<serde_json::Value>,
}

#[test]
fn checked_in_analyzer_profile_gate_is_current() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert!(gantry::advertised_profiles().is_empty());
    assert_eq!(
        manifest.specification.sha256,
        gantry::PROFILE_SPECIFICATION_REVISION
    );
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn analyzer_profile_gate_rejects_stale_artifacts_and_overclaiming() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut overclaim = manifest.clone();
    overclaim
        .claim
        .advertises_profiles
        .push("analyzer".to_owned());
    assert!(validate_manifest(&root, &overclaim).is_err());

    let mut incomplete = manifest;
    incomplete.prerequisites.pop();
    assert!(validate_manifest(&root, &incomplete).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.analyzer-gate-evidence/v1"
        || manifest.gate != "GNT-GEN-GATE-300"
        || manifest.status != "verified"
        || manifest.profile != "analyzer"
    {
        return Err("analyzer gate identity or status is invalid".to_owned());
    }
    if manifest.claim.profiles != ["analyzer", "frontend"]
        || !manifest.claim.advertises_profiles.is_empty()
        || manifest.claim.excludes_profiles
            != [
                "concurrent-evaluator",
                "durable-runtime",
                "embedding",
                "evaluator",
            ]
        || gantry::PROFILE_CLAIMS_ENABLED
        || !gantry::advertised_profiles().is_empty()
    {
        return Err("analyzer claim is invalid or overstates a later profile".to_owned());
    }

    validate_file_digest(root, &manifest.specification, "specification")?;
    if manifest
        .prerequisites
        .iter()
        .map(|prerequisite| prerequisite.issue.as_str())
        .collect::<Vec<_>>()
        != PREREQUISITES
    {
        return Err("analyzer amendment prerequisites are incomplete".to_owned());
    }
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
    if manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<Vec<_>>()
        != REQUIRED_ARTIFACTS
    {
        return Err("analyzer amendment artifact set is incomplete".to_owned());
    }
    for artifact in &manifest.artifacts {
        validate_file_digest(root, artifact, "artifact")?;
    }

    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let section14: Section14Review =
        read_json(&root.join("protocol/requirements/section14-v1.json"));
    if review.specification_sha256 != manifest.specification.sha256
        || section14.specification_sha256 != manifest.specification.sha256
    {
        return Err("analyzer evidence uses another specification revision".to_owned());
    }

    let mut applicable_clause_count = 0_usize;
    let mut covered_count = 0_usize;
    let mut not_applicable_count = 0_usize;
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            if !clause.profiles.iter().any(|profile| profile == "analyzer") {
                continue;
            }
            applicable_clause_count += 1;
            let profile_review = clause
                .profile_reviews
                .iter()
                .find(|profile_review| profile_review.profile == "analyzer")
                .ok_or_else(|| {
                    format!(
                        "analyzer review is missing: {}:{}",
                        requirement.id, clause.key
                    )
                })?;
            match profile_review.state.as_str() {
                "covered" if !profile_review.evidence.is_empty() => {
                    covered_count += 1;
                    for evidence in &profile_review.evidence {
                        validate_evidence_anchor(root, evidence)?;
                    }
                }
                "not-applicable"
                    if profile_review.evidence.is_empty()
                        && profile_review
                            .rationale
                            .as_deref()
                            .is_some_and(|rationale| !rationale.is_empty()) =>
                {
                    not_applicable_count += 1;
                }
                _ => {
                    return Err(format!(
                        "analyzer review is not closed: {}:{}",
                        requirement.id, clause.key
                    ));
                }
            }
        }
    }
    if manifest.review_summary.applicable_clause_count != applicable_clause_count
        || manifest.review_summary.covered_count != covered_count
        || manifest.review_summary.not_applicable_count != not_applicable_count
        || applicable_clause_count != covered_count + not_applicable_count
    {
        return Err("analyzer review summary differs from reviewed applicability".to_owned());
    }

    if manifest.section14_excerpt_count != section14.excerpts.len()
        || section14
            .excerpts
            .iter()
            .any(|excerpt| excerpt.state != "covered" || excerpt.evidence.is_empty())
    {
        return Err("Section 14 authoring evidence is incomplete".to_owned());
    }

    let validity: ValidityManifest =
        read_json(&root.join("protocol/conformance/analyzer-validity-v1.json"));
    if validity.specification_sha256 != manifest.specification.sha256
        || validity.issue != "GNT-GEN-PROOF-001"
        || validity.profile != "analyzer"
        || !root.join(&validity.argument).is_file()
        || !root.join(&validity.model).is_file()
        || validity.evidence_manifests.len() != 6
        || validity.lemmas.len() != 9
        || validity
            .evidence_manifests
            .iter()
            .any(|path| !root.join(path).is_file())
    {
        return Err("analyzer validity evidence is incomplete".to_owned());
    }
    validate_sorted_unique(
        "validation commands",
        manifest.validation_commands.iter().map(String::as_str),
    )?;
    if manifest.environment_gaps
        != [
            "Global profile advertisement remains withheld until the complete generics-and-traits adoption gate closes; hosted macOS qualification is owned by GNT-GEN-REL-001 and is not claimed by this Linux evidence gate.",
        ]
    {
        return Err("validation commands or environment gaps are incomplete".to_owned());
    }
    Ok(())
}

fn validate_evidence_anchor(root: &Path, evidence: &str) -> Result<(), String> {
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
