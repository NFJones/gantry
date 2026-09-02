//! Independent validation of the frontend profile evidence index.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry::ConformanceProfile;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/frontend-gate-v1.json";

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

#[test]
fn checked_in_frontend_profile_gate_is_current() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert!(gantry::advertised_profiles().contains(&ConformanceProfile::Frontend));
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification.sha256,
        gantry::PROFILE_SPECIFICATION_REVISION,
    ));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn frontend_profile_gate_rejects_stale_artifacts_and_overclaiming() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut overclaim = manifest;
    overclaim.claim.profiles.push("analyzer".to_owned());
    assert!(validate_manifest(&root, &overclaim).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.frontend-gate-evidence/v1"
        || manifest.gate != "GNT-GATE-200"
        || manifest.status != "verified"
        || manifest.profile != "frontend"
    {
        return Err("frontend gate identity or status is invalid".to_owned());
    }
    if manifest.claim.profiles != ["frontend"]
        || manifest.claim.advertises_profiles != manifest.claim.profiles
        || manifest.claim.excludes_profiles
            != [
                "analyzer",
                "concurrent-evaluator",
                "durable-runtime",
                "embedding",
                "evaluator",
            ]
        || !gantry::PROFILE_CLAIMS_ENABLED
        || !gantry::advertised_profiles().contains(&ConformanceProfile::Frontend)
    {
        return Err("frontend claim is invalid or overstates another profile".to_owned());
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

    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let section14: Section14Review =
        read_json(&root.join("protocol/requirements/section14-v1.json"));
    if review.specification_sha256 != manifest.specification.sha256
        || section14.specification_sha256 != manifest.specification.sha256
    {
        return Err("frontend evidence uses another specification revision".to_owned());
    }

    let mut applicable_clause_count = 0_usize;
    let mut covered_count = 0_usize;
    let mut not_applicable_count = 0_usize;
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            if !clause.profiles.iter().any(|profile| profile == "frontend") {
                continue;
            }
            applicable_clause_count += 1;
            let profile_review = clause
                .profile_reviews
                .iter()
                .find(|profile_review| profile_review.profile == "frontend")
                .ok_or_else(|| {
                    format!(
                        "frontend review is missing: {}:{}",
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
                        "frontend review is not closed: {}:{}",
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
        return Err("frontend review summary differs from reviewed applicability".to_owned());
    }

    if manifest.section14_excerpt_count != section14.excerpts.len()
        || section14
            .excerpts
            .iter()
            .any(|excerpt| excerpt.state != "covered" || excerpt.evidence.is_empty())
    {
        return Err("Section 14 authoring evidence is incomplete".to_owned());
    }
    if manifest.validation_commands.is_empty() || manifest.environment_gaps.len() != 1 {
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
