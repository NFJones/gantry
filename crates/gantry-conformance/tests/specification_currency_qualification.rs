//! Validation of the retained specification-currency qualification record.
//!
//! The record freezes the bounded candidate, the accumulated drift reviewed for
//! profile applicability and Section 14 coverage, the executed qualification
//! evidence, and the residual gaps. Every identity is recomputed from current
//! bytes so the record cannot silently go stale.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const RECORD_PATH: &str = "protocol/conformance/specification-currency-qualification-v1.json";
const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";
const SECTION14_PATH: &str = "protocol/requirements/section14-v1.json";
const INVENTORY_PATH: &str = "protocol/requirements/generated/requirements-v1.json";
const VERIFICATION_PATH: &str = "protocol/publication/verification-v1.json";
const PROFILES: [&str; 6] = [
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: String,
    issue: String,
    status: String,
    specification_sha256: String,
    superseded_specification_sha256: String,
    candidate: Candidate,
    drift_review: DriftReview,
    section14_review: Section14Review,
    qualification: Qualification,
    gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    base_commit: String,
    currency_repair_parent_commit: String,
    reviewed_through_commit: String,
    since_commit: String,
    identity_note: String,
    toolchain: String,
    inputs: Vec<FileDigest>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriftReview {
    specification_commits_reviewed: usize,
    requirements_before: InventorySummary,
    requirements_after: InventorySummary,
    added_requirements: Vec<AddedRequirement>,
    changed_requirement_bodies: Vec<String>,
    removed_requirements: Vec<String>,
    profile_applicability: Vec<ProfileApplicability>,
    reviewed_categories: Vec<String>,
    outcome: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventorySummary {
    count: usize,
    clauses: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddedRequirement {
    id: String,
    clauses: usize,
    profile_reviews: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileApplicability {
    profile: String,
    before_covered: usize,
    before_not_applicable: usize,
    after_covered: usize,
    after_not_applicable: usize,
    after_planned: usize,
    outcome: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section14Review {
    excerpt_count_before: usize,
    excerpt_count_after: usize,
    states: Vec<String>,
    every_excerpt_has_evidence: bool,
    outcome: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    scope: String,
    lanes: Vec<LaneResult>,
    commands: Vec<CommandResult>,
    publication: PublicationSummary,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneResult {
    lane: String,
    result: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandResult {
    command: String,
    result: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationSummary {
    member_count: usize,
    identity_at_currency_repair_parent: String,
    identity_note: String,
    verification: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewRequirement {
    clauses: Vec<ReviewClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewClause {
    profile_reviews: Vec<ReviewProfile>,
}

#[derive(Debug, Deserialize)]
struct ReviewProfile {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Inventory {
    specification_sha256: String,
    requirements: Vec<InventoryRequirement>,
}

#[derive(Debug, Deserialize)]
struct InventoryRequirement {
    id: String,
    body_sha256: String,
    clauses: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Section14File {
    specification_sha256: String,
    excerpts: Vec<Excerpt>,
}

#[derive(Debug, Deserialize)]
struct Excerpt {
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Adoption {
    status: String,
    specification_sha256: String,
}

#[test]
fn retained_qualification_identifies_the_current_candidate() {
    let root = workspace_root();
    let record: Record = read_json(&root.join(RECORD_PATH));
    assert_eq!(validate(&root, &record), Ok(()));
}

#[test]
fn qualification_validator_rejects_stale_or_unqualified_records() {
    let root = workspace_root();
    let record: Record = read_json(&root.join(RECORD_PATH));

    let mut stale = record.clone();
    stale.specification_sha256 = "0".repeat(64);
    assert!(validate(&root, &stale).is_err());

    let mut open = record.clone();
    open.qualification.lanes[0].result = "planned".to_owned();
    assert!(validate(&root, &open).is_err());

    let mut missing_gap = record;
    missing_gap.gaps.clear();
    assert!(validate(&root, &missing_gap).is_err());
}

fn validate(root: &Path, record: &Record) -> Result<(), String> {
    let specification = fs::read(root.join("SPEC.md")).map_err(io_error)?;
    let specification_sha256 = sha256(&specification);
    if record.format != "gantry.specification-currency-qualification/v1"
        || record.issue != "be47045e-93fb-473b-af7a-2d459aae091c"
        || record.status != "verified"
        || record.specification_sha256 != specification_sha256
        || record.superseded_specification_sha256 == specification_sha256
    {
        return Err("qualification record identity or revision differs".to_owned());
    }
    validate_commit(root, &record.candidate.base_commit, "base")?;
    validate_commit(
        root,
        &record.candidate.currency_repair_parent_commit,
        "currency repair parent",
    )?;
    validate_commit(
        root,
        &record.candidate.reviewed_through_commit,
        "reviewed through",
    )?;
    validate_commit(root, &record.candidate.since_commit, "since")?;
    if record.candidate.identity_note.trim().is_empty()
        || record.candidate.toolchain.trim().is_empty()
    {
        return Err("candidate identity note or toolchain is empty".to_owned());
    }
    let mut inputs = BTreeMap::new();
    for input in &record.candidate.inputs {
        let bytes = fs::read(root.join(&input.path)).map_err(io_error)?;
        if input.sha256 != sha256(&bytes) {
            return Err(format!("candidate input digest differs: {}", input.path));
        }
        inputs.insert(input.path.as_str(), input.sha256.as_str());
    }
    for required in [
        "SPEC.md",
        "protocol/requirements/reviewed-v1.json",
        "protocol/requirements/section14-v1.json",
        "protocol/requirements/generated/requirements-v1.json",
        "Cargo.lock",
        "fuzz/Cargo.lock",
    ] {
        if !inputs.contains_key(required) {
            return Err(format!("candidate input is missing: {required}"));
        }
    }
    validate_drift(root, &record.drift_review, &specification_sha256)?;
    validate_section14(root, &record.section14_review, &specification_sha256)?;
    validate_adoptions(root, &specification_sha256)?;
    validate_qualification(root, &record.qualification)?;
    if record.gaps.is_empty() || record.gaps.iter().any(|gap| gap.trim().is_empty()) {
        return Err("qualification gaps are missing or empty".to_owned());
    }
    Ok(())
}

fn validate_commit(root: &Path, commit: &str, role: &str) -> Result<(), String> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("candidate {role} commit is invalid: {commit}"));
    }
    let ancestor = Command::new("git")
        .current_dir(root)
        .args(["merge-base", "--is-ancestor", commit, "HEAD"])
        .status()
        .map_err(io_error)?;
    if !ancestor.success() {
        return Err(format!(
            "candidate {role} commit is not an ancestor: {commit}"
        ));
    }
    Ok(())
}

fn validate_drift(
    root: &Path,
    drift: &DriftReview,
    specification_sha256: &str,
) -> Result<(), String> {
    let inventory: Inventory = read_json(&root.join(INVENTORY_PATH));
    if inventory.specification_sha256 != specification_sha256 {
        return Err("requirement inventory uses another specification".to_owned());
    }
    let requirement_count = inventory.requirements.len();
    let clause_count = inventory
        .requirements
        .iter()
        .map(|requirement| requirement.clauses.len())
        .sum::<usize>();
    if drift.specification_commits_reviewed == 0
        || drift.requirements_after.count != requirement_count
        || drift.requirements_after.clauses != clause_count
        || drift.requirements_before.count >= drift.requirements_after.count
        || drift.requirements_before.clauses >= drift.requirements_after.clauses
        || drift.added_requirements.len()
            != drift.requirements_after.count - drift.requirements_before.count
    {
        return Err("drift inventory totals differ".to_owned());
    }
    let bodies = inventory
        .requirements
        .iter()
        .map(|requirement| (requirement.id.as_str(), requirement.body_sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for added in &drift.added_requirements {
        let requirement = inventory
            .requirements
            .iter()
            .find(|requirement| requirement.id == added.id)
            .ok_or_else(|| format!("added requirement is absent: {}", added.id))?;
        if requirement.clauses.len() != added.clauses
            || added
                .profile_reviews
                .iter()
                .any(|review| review.trim().is_empty())
        {
            return Err(format!("added requirement shape differs: {}", added.id));
        }
    }
    for changed in &drift.changed_requirement_bodies {
        if !bodies.contains_key(changed.as_str()) {
            return Err(format!("changed requirement is absent: {changed}"));
        }
    }
    for removed in &drift.removed_requirements {
        if bodies.contains_key(removed.as_str()) {
            return Err(format!("removed requirement is still present: {removed}"));
        }
    }
    let review: RequirementReview = read_json(&root.join(REVIEW_PATH));
    if review.specification_sha256 != specification_sha256 {
        return Err("reviewed requirements use another specification".to_owned());
    }
    let mut derived = PROFILES
        .into_iter()
        .map(|profile| (profile.to_owned(), (0_usize, 0_usize, 0_usize)))
        .collect::<BTreeMap<_, _>>();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile_review in &clause.profile_reviews {
                let counts = derived
                    .get_mut(&profile_review.profile)
                    .ok_or_else(|| format!("unknown profile {}", profile_review.profile))?;
                match profile_review.state.as_str() {
                    "covered" if !profile_review.evidence.is_empty() => counts.0 += 1,
                    "not-applicable" if profile_review.evidence.is_empty() => counts.1 += 1,
                    "covered" | "not-applicable" => {
                        return Err("profile review evidence shape is invalid".to_owned());
                    }
                    _ => counts.2 += 1,
                }
            }
        }
    }
    if drift.profile_applicability.len() != PROFILES.len() {
        return Err("profile applicability rows are incomplete".to_owned());
    }
    for (index, row) in drift.profile_applicability.iter().enumerate() {
        if row.profile != PROFILES[index] {
            return Err("profile applicability order differs".to_owned());
        }
        let (covered, not_applicable, planned) = derived
            .get(&row.profile)
            .ok_or_else(|| format!("unknown profile {}", row.profile))?;
        if row.after_covered != *covered
            || row.after_not_applicable != *not_applicable
            || row.after_planned != *planned
            || row.after_planned != 0
            || row.before_covered > row.after_covered
            || row.before_not_applicable > row.after_not_applicable
            || row.outcome.trim().is_empty()
        {
            return Err(format!("profile applicability differs: {}", row.profile));
        }
    }
    if drift.reviewed_categories.is_empty()
        || drift
            .reviewed_categories
            .iter()
            .any(|category| category.trim().is_empty())
        || drift.outcome.trim().is_empty()
    {
        return Err("drift review qualifications are incomplete".to_owned());
    }
    Ok(())
}

fn validate_section14(
    root: &Path,
    review: &Section14Review,
    specification_sha256: &str,
) -> Result<(), String> {
    let section14: Section14File = read_json(&root.join(SECTION14_PATH));
    if section14.specification_sha256 != specification_sha256
        || section14.excerpts.len() != review.excerpt_count_after
        || review.excerpt_count_before != review.excerpt_count_after
        || section14
            .excerpts
            .iter()
            .any(|excerpt| excerpt.state != "covered" || excerpt.evidence.is_empty())
        || !review.every_excerpt_has_evidence
        || review.states != vec!["covered".to_owned()]
        || review.outcome.trim().is_empty()
    {
        return Err("Section 14 review differs from the reviewed excerpts".to_owned());
    }
    Ok(())
}

fn validate_adoptions(root: &Path, specification_sha256: &str) -> Result<(), String> {
    for path in [
        "protocol/conformance/async-execution-adoption-v1.json",
        "protocol/conformance/generics-traits-adoption-v1.json",
    ] {
        let adoption: Adoption = read_json(&root.join(path));
        if adoption.status != "verified" || adoption.specification_sha256 != specification_sha256 {
            return Err(format!("adoption does not identify the candidate: {path}"));
        }
    }
    Ok(())
}

fn validate_qualification(root: &Path, qualification: &Qualification) -> Result<(), String> {
    if qualification.scope.trim().is_empty()
        || qualification.lanes.is_empty()
        || qualification
            .lanes
            .iter()
            .any(|lane| lane.lane.trim().is_empty() || lane.result != "pass")
    {
        return Err("qualification lanes are incomplete or not all passing".to_owned());
    }
    let mut lanes = BTreeSet::new();
    for lane in &qualification.lanes {
        if !lanes.insert(lane.lane.as_str()) {
            return Err(format!("duplicate qualification lane: {}", lane.lane));
        }
    }
    if qualification.commands.is_empty()
        || qualification
            .commands
            .iter()
            .any(|command| command.command.trim().is_empty() || command.result.trim().is_empty())
    {
        return Err("qualification commands are incomplete".to_owned());
    }
    let verification: serde_json::Value = read_json(&root.join(VERIFICATION_PATH));
    let identity = verification["publication_set_identity"]
        .as_str()
        .ok_or_else(|| "verification report has no identity".to_owned())?;
    if identity.len() != 64 {
        return Err("publication identity is not a digest".to_owned());
    }
    let members = verification["artifacts"]
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| "verification report has no artifacts".to_owned())?;
    if qualification.publication.member_count != members
        || qualification.publication.member_count != 7
        || qualification
            .publication
            .identity_at_currency_repair_parent
            .len()
            != 64
        || !qualification
            .publication
            .identity_at_currency_repair_parent
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || qualification.publication.identity_note.trim().is_empty()
        || qualification.publication.verification.trim().is_empty()
    {
        return Err("publication summary differs from the verification report".to_owned());
    }
    Ok(())
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
