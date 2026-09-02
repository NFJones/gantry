//! Aggregate evidence validation for generics and static-trait conformance.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/generics-traits-conformance-v1.json";
const ADOPTION_PATH: &str = "protocol/conformance/generics-traits-adoption-v1.json";
const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";
const PROFILES: [&str; 6] = [
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];
const PREREQUISITES: [(&str, &str); 4] = [
    ("GNT-GEN-API-001", "b5fffb5"),
    ("GNT-GEN-CON-001", "1140efb"),
    ("GNT-GEN-DUR-001", "5910167"),
    ("GNT-GEN-RUN-001", "60be080"),
];
const ARTIFACTS: [&str; 20] = [
    ".github/workflows/ci.yml",
    "crates/gantry-conformance/tests/fuzz_regressions.rs",
    "crates/gantry-conformance/tests/generics_conformance.rs",
    "crates/gantry-conformance/tests/generics_conformance_gate.rs",
    "fuzz/Cargo.lock",
    "fuzz/Cargo.toml",
    "fuzz/README.md",
    "fuzz/corpus/generic_ir/closed-callable",
    "fuzz/corpus/generic_ir/nested-type",
    "fuzz/corpus/generic_ir/open-template",
    "fuzz/corpus/generic_package/contextual-self",
    "fuzz/corpus/generic_package/nested-applications",
    "fuzz/corpus/generic_package/recursive-obligation",
    "fuzz/corpus/parser/generic-angle-ambiguity",
    "fuzz/corpus/parser/generic-qualified-call",
    "fuzz/fuzz_targets/generic_ir.rs",
    "fuzz/fuzz_targets/generic_package.rs",
    "protocol/README.md",
    "protocol/conformance/generics-traits-adoption-v1.json",
    "protocol/requirements/reviewed-v1.json",
];
const FUZZ_TARGETS: [&str; 3] = ["generic_ir", "generic_package", "parser"];
const FUZZ_CORPORA: [&str; 8] = [
    "fuzz/corpus/generic_ir/closed-callable",
    "fuzz/corpus/generic_ir/nested-type",
    "fuzz/corpus/generic_ir/open-template",
    "fuzz/corpus/generic_package/contextual-self",
    "fuzz/corpus/generic_package/nested-applications",
    "fuzz/corpus/generic_package/recursive-obligation",
    "fuzz/corpus/parser/generic-angle-ambiguity",
    "fuzz/corpus/parser/generic-qualified-call",
];
const PROPERTY_EVIDENCE: [&str; 1] = [
    "crates/gantry-conformance/tests/generics_conformance.rs#generic_canonicalization_properties_are_deterministic",
];
const SCALE_EVIDENCE: [&str; 1] = [
    "crates/gantry-conformance/tests/generics_conformance.rs#generic_scale_envelopes_are_charged_and_deduplicated",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profiles: Vec<String>,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    property_evidence: Vec<String>,
    scale_evidence: Vec<String>,
    fuzz: FuzzEvidence,
    profile_review_summary: Vec<ProfileSummary>,
    advertises_profiles: Vec<String>,
    environment_gaps: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prerequisite {
    issue: String,
    commit: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FuzzEvidence {
    workflow: String,
    smoke_runs: u64,
    scheduled_runs: u64,
    targets: Vec<String>,
    corpora: Vec<String>,
    deterministic_replay: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileSummary {
    profile: String,
    covered_count: usize,
    not_applicable_count: usize,
    planned_count: usize,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    clauses: Vec<Clause>,
}

#[derive(Debug, Deserialize)]
struct Clause {
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
    rationale: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdoptionGate {
    status: String,
    advertises_profiles: Vec<String>,
    blocked_by: Vec<String>,
}

#[test]
fn reviewed_generics_conformance_evidence_is_closed() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    let review: RequirementReview = read_json(&root.join(REVIEW_PATH));
    let adoption: AdoptionGate = read_json(&root.join(ADOPTION_PATH));

    assert_eq!(
        validate_manifest(&root, &manifest, &review, &adoption),
        Ok(())
    );
}

#[test]
fn generics_conformance_gate_rejects_stale_incomplete_or_overclaimed_evidence() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    let review: RequirementReview = read_json(&root.join(REVIEW_PATH));
    let adoption: AdoptionGate = read_json(&root.join(ADOPTION_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale, &review, &adoption).is_err());

    let mut incomplete = manifest.clone();
    incomplete.artifacts.pop();
    assert!(validate_manifest(&root, &incomplete, &review, &adoption).is_err());

    let mut overclaimed = manifest;
    overclaimed.advertises_profiles.push("embedding".to_owned());
    assert!(validate_manifest(&root, &overclaimed, &review, &adoption).is_err());
}

fn validate_manifest(
    root: &Path,
    manifest: &Manifest,
    review: &RequirementReview,
    adoption: &AdoptionGate,
) -> Result<(), String> {
    if manifest.format != "gantry.generics-traits-conformance-evidence/v1"
        || manifest.issue != "GNT-GEN-CONF-001"
        || manifest.profiles != PROFILES
        || manifest.advertises_profiles != PROFILES
    {
        return Err("generic conformance identity or profile claim is invalid".to_owned());
    }
    let specification_sha256 = sha256(&fs::read(root.join("SPEC.md")).map_err(io_error)?);
    if manifest.specification_sha256 != specification_sha256
        || review.specification_sha256 != specification_sha256
    {
        return Err("generic conformance evidence uses another specification".to_owned());
    }
    if manifest
        .prerequisites
        .iter()
        .map(|entry| (entry.issue.as_str(), entry.commit.as_str()))
        .collect::<Vec<_>>()
        != PREREQUISITES
    {
        return Err("generic conformance prerequisites are incomplete".to_owned());
    }
    for prerequisite in &manifest.prerequisites {
        let status = Command::new("git")
            .args([
                "cat-file",
                "-e",
                &format!("{}^{{commit}}", prerequisite.commit),
            ])
            .current_dir(root)
            .status()
            .map_err(io_error)?;
        if !status.success() {
            return Err(format!(
                "generic conformance prerequisite commit is missing: {}",
                prerequisite.commit
            ));
        }
    }
    if manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<Vec<_>>()
        != ARTIFACTS
    {
        return Err("generic conformance artifact set is incomplete".to_owned());
    }
    for artifact in &manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).map_err(io_error)?;
        if artifact.sha256 != sha256(&bytes) {
            return Err(format!(
                "stale generic conformance artifact {}",
                artifact.path
            ));
        }
    }
    if manifest.property_evidence != PROPERTY_EVIDENCE || manifest.scale_evidence != SCALE_EVIDENCE
    {
        return Err("generic conformance property or scale evidence is empty".to_owned());
    }
    for evidence in manifest
        .property_evidence
        .iter()
        .chain(&manifest.scale_evidence)
        .chain([&manifest.fuzz.deterministic_replay])
    {
        assert_anchor_exists(root, evidence)?;
    }
    if manifest.fuzz.workflow != ".github/workflows/ci.yml"
        || manifest.fuzz.smoke_runs != 2_000
        || manifest.fuzz.scheduled_runs != 100_000
        || manifest.fuzz.targets != FUZZ_TARGETS
        || manifest.fuzz.corpora != FUZZ_CORPORA
    {
        return Err("generic conformance fuzz evidence is incomplete".to_owned());
    }
    let workflow = fs::read_to_string(root.join(&manifest.fuzz.workflow)).map_err(io_error)?;
    for target in &manifest.fuzz.targets {
        if !workflow.contains(&format!("cargo fuzz run {target} --")) {
            return Err(format!("fuzz workflow omits {target}"));
        }
    }
    if !workflow.contains("'100000'") || !workflow.contains("'2000'") {
        return Err("fuzz workflow omits bounded or scheduled run counts".to_owned());
    }

    let summary = review_summary(review)?;
    if manifest.profile_review_summary != summary
        || summary.iter().any(|profile| profile.planned_count != 0)
    {
        return Err("generic conformance profile reviews remain open".to_owned());
    }
    if manifest.advertises_profiles != PROFILES
        || adoption.status != "verified"
        || adoption.advertises_profiles != PROFILES
        || adoption
            .blocked_by
            .iter()
            .any(|issue| issue == "GNT-GEN-CONF-001")
        || !adoption.blocked_by.is_empty()
    {
        return Err("generic conformance gate overclaims publication or release".to_owned());
    }
    if manifest.environment_gaps.is_empty() || manifest.exclusions.len() < 2 {
        return Err("generic conformance qualifications are incomplete".to_owned());
    }
    Ok(())
}

fn review_summary(review: &RequirementReview) -> Result<Vec<ProfileSummary>, String> {
    let mut counts = PROFILES
        .into_iter()
        .map(|profile| (profile.to_owned(), (0_usize, 0_usize, 0_usize)))
        .collect::<BTreeMap<_, _>>();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile_review in &clause.profile_reviews {
                let profile = counts
                    .get_mut(&profile_review.profile)
                    .ok_or_else(|| format!("unknown profile {}", profile_review.profile))?;
                match profile_review.state.as_str() {
                    "covered" if !profile_review.evidence.is_empty() => profile.0 += 1,
                    "not-applicable"
                        if profile_review.evidence.is_empty()
                            && profile_review
                                .rationale
                                .as_deref()
                                .is_some_and(|value| !value.is_empty()) =>
                    {
                        profile.1 += 1;
                    }
                    "planned" | "in-progress" | "unresolved"
                        if profile_review.evidence.is_empty() =>
                    {
                        profile.2 += 1;
                    }
                    state => {
                        return Err(format!(
                            "invalid profile review state or evidence shape {state}"
                        ));
                    }
                }
            }
        }
    }
    Ok(counts
        .into_iter()
        .map(
            |(profile, (covered_count, not_applicable_count, planned_count))| ProfileSummary {
                profile,
                covered_count,
                not_applicable_count,
                planned_count,
            },
        )
        .collect())
}

fn assert_anchor_exists(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, anchor) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence has no anchor: {evidence}"))?;
    let source = fs::read_to_string(root.join(path)).map_err(io_error)?;
    if !source.contains(&format!("fn {anchor}")) {
        return Err(format!("evidence anchor does not exist: {evidence}"));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn io_error(error: std::io::Error) -> String {
    error.to_string()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
        .to_path_buf()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
