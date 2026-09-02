//! Cross-profile proof linkage for generics and static-trait refinement.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const MANIFEST_PATH: &str = "protocol/conformance/generics-traits-refinements-v1.json";
const PROFILES: [&str; 3] = ["concurrent-evaluator", "durable-runtime", "evaluator"];
const STATIC_PREREQUISITES: [&str; 14] = [
    "GNT-1.0#clause-001",
    "GNT-12.11-generic-diagnostics#clause-001",
    "GNT-12.9#clause-001",
    "GNT-13.2#clause-001",
    "GNT-13.3#clause-001",
    "GNT-13.4#clause-001",
    "GNT-13.6#clause-001",
    "GNT-13.7#clause-001",
    "GNT-4.14#clause-001",
    "GNT-4.15#clause-001",
    "GNT-4.16#clause-001",
    "GNT-4.17-generic-analysis-limits#clause-001",
    "GNT-4.4#clause-001",
    "GNT-4.9#clause-001",
];

#[derive(Clone, Debug, Deserialize)]
struct ProofManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profiles: Vec<String>,
    static_prerequisite_requirements: Vec<String>,
    profile_arguments: Vec<ProfileArgument>,
    assumptions: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProfileArgument {
    profile: String,
    argument: String,
    model: String,
    model_evidence: String,
    implementation_evidence_manifest: String,
    preservation_requirements: Vec<String>,
    obligations: Vec<String>,
    positive_evidence: Vec<String>,
    negative_evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ImplementationEvidence {
    specification_sha256: String,
    profile: String,
    entries: Vec<EvidenceEntry>,
}

#[derive(Debug, Deserialize)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
}

#[derive(Debug, Deserialize)]
struct Model {
    obligations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewedRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewedRequirement {
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

#[test]
fn generic_refinement_arguments_cover_every_profile_requirement() {
    let root = workspace_root();
    let manifest: ProofManifest = read_json(&root.join(MANIFEST_PATH));
    validate_manifest(&root, &manifest).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn generic_refinement_evidence_rejects_incomplete_profile_arguments() {
    let root = workspace_root();
    let manifest: ProofManifest = read_json(&root.join(MANIFEST_PATH));

    let mut missing_negative = manifest.clone();
    missing_negative.profile_arguments[0]
        .negative_evidence
        .clear();
    assert!(matches!(
        validate_manifest(&root, &missing_negative),
        Err(message) if message.contains("positive and negative")
    ));

    let mut missing_requirement = manifest;
    missing_requirement.profile_arguments[0]
        .preservation_requirements
        .pop();
    assert!(matches!(
        validate_manifest(&root, &missing_requirement),
        Err(message) if message.contains("does not classify every reviewed requirement")
    ));
}

fn validate_manifest(root: &Path, manifest: &ProofManifest) -> Result<(), String> {
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    if manifest.format != "gantry.generics-traits-refinement-evidence/v1"
        || manifest.issue != "GNT-GEN-PROOF-002"
        || manifest.profiles != PROFILES
        || manifest.static_prerequisite_requirements != STATIC_PREREQUISITES
        || manifest.specification_sha256 != review.specification_sha256
        || manifest.specification_sha256 != gantry::PROFILE_SPECIFICATION_REVISION
    {
        return Err("generic refinement proof identity or revision is invalid".to_owned());
    }
    if manifest.assumptions.len() < 3
        || manifest.exclusions.len() < 3
        || manifest
            .assumptions
            .iter()
            .chain(&manifest.exclusions)
            .any(String::is_empty)
    {
        return Err("generic refinement assumptions or exclusions are incomplete".to_owned());
    }
    if manifest
        .profile_arguments
        .iter()
        .map(|argument| argument.profile.as_str())
        .ne(PROFILES)
    {
        return Err("generic refinement profile arguments are incomplete or unordered".to_owned());
    }

    for argument in &manifest.profile_arguments {
        validate_profile_argument(root, &review, manifest, argument)?;
    }
    Ok(())
}

fn validate_profile_argument(
    root: &Path,
    review: &RequirementReview,
    manifest: &ProofManifest,
    argument: &ProfileArgument,
) -> Result<(), String> {
    if argument.obligations != expected_obligations(&argument.profile)
        || !sorted_unique(&argument.preservation_requirements)
        || !sorted_unique(&argument.positive_evidence)
        || !sorted_unique(&argument.negative_evidence)
    {
        return Err(format!(
            "{} proof obligations are incomplete",
            argument.profile
        ));
    }
    if argument.positive_evidence.is_empty() || argument.negative_evidence.is_empty() {
        return Err(format!(
            "{} proof requires positive and negative public evidence",
            argument.profile
        ));
    }

    let written = fs::read_to_string(root.join(&argument.argument))
        .map_err(|error| format!("could not read {}: {error}", argument.argument))?;
    if !written.contains("## Generics and static-trait refinement")
        || !written.contains(MANIFEST_PATH)
    {
        return Err(format!(
            "{} written argument is incomplete",
            argument.profile
        ));
    }
    let model: Model = read_json(&root.join(&argument.model));
    if !argument
        .obligations
        .iter()
        .all(|obligation| model.obligations.contains(obligation))
    {
        return Err(format!(
            "{} model omits a proof obligation",
            argument.profile
        ));
    }
    validate_evidence_anchor(root, &argument.model_evidence)?;
    for evidence in argument
        .positive_evidence
        .iter()
        .chain(&argument.negative_evidence)
    {
        validate_evidence_anchor(root, evidence)?;
    }

    let implementation: ImplementationEvidence =
        read_json(&root.join(&argument.implementation_evidence_manifest));
    if implementation.profile != argument.profile
        || implementation.specification_sha256 != manifest.specification_sha256
    {
        return Err(format!(
            "{} implementation evidence has the wrong identity",
            argument.profile
        ));
    }
    let implementation_requirements = implementation
        .entries
        .iter()
        .map(|entry| format!("{}#{}", entry.requirement, entry.clause))
        .collect::<BTreeSet<_>>();
    let classified = manifest
        .static_prerequisite_requirements
        .iter()
        .chain(&argument.preservation_requirements)
        .cloned()
        .collect::<BTreeSet<_>>();
    if implementation_requirements != classified {
        return Err(format!(
            "{} proof does not classify every reviewed requirement",
            argument.profile
        ));
    }
    for key in classified {
        let (requirement, clause) = key
            .split_once('#')
            .ok_or_else(|| format!("invalid requirement key {key}"))?;
        let profile = reviewed_profile(review, requirement, clause, &argument.profile)?;
        if profile.state != "covered" || profile.evidence.is_empty() {
            return Err(format!("uncovered reviewed requirement {key}"));
        }
    }
    let proof = reviewed_profile(
        review,
        "GNT-3-D-PROPERTIES",
        "clause-001",
        &argument.profile,
    )?;
    if !proof.evidence.contains(&argument.model_evidence) {
        return Err(format!(
            "{} bounded model is not linked to the formal property",
            argument.profile
        ));
    }
    Ok(())
}

fn reviewed_profile<'a>(
    review: &'a RequirementReview,
    requirement: &str,
    clause: &str,
    profile: &str,
) -> Result<&'a ProfileReview, String> {
    review
        .requirements
        .iter()
        .find(|candidate| candidate.id == requirement)
        .and_then(|candidate| {
            candidate
                .clauses
                .iter()
                .find(|candidate| candidate.key == clause)
        })
        .and_then(|candidate| {
            candidate
                .profile_reviews
                .iter()
                .find(|candidate| candidate.profile == profile)
        })
        .ok_or_else(|| format!("missing reviewed profile {requirement}#{clause}#{profile}"))
}

fn expected_obligations(profile: &str) -> &'static [&'static str] {
    match profile {
        "concurrent-evaluator" => &[
            "closed-generic-task-transfer",
            "no-concurrent-generic-analysis",
            "schedule-independent-static-selection",
        ],
        "durable-runtime" => &[
            "fail-closed-generic-artifacts",
            "no-recovery-generic-analysis",
            "retained-generic-projection-equivalence",
            "selected-target-preservation",
            "source-free-generic-recovery",
        ],
        "evaluator" => &[
            "closed-generic-descriptor-preservation",
            "concrete-effect-and-schema-preservation",
            "direct-call-target-preservation",
            "no-runtime-generic-analysis",
        ],
        _ => &[],
    }
}

fn validate_evidence_anchor(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, test) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence anchor has no test: {evidence}"))?;
    if !path.starts_with("crates/gantry-conformance/tests/") || !path.ends_with(".rs") {
        return Err(format!(
            "evidence is not public conformance coverage: {evidence}"
        ));
    }
    let source = fs::read_to_string(root.join(path))
        .map_err(|error| format!("could not read evidence {path}: {error}"))?;
    if !source.contains(&format!("fn {test}(")) {
        return Err(format!("missing evidence symbol {evidence}"));
    }
    Ok(())
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
