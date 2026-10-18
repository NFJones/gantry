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
    successors: Vec<Successor>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    base_commit: String,
    currency_repair_parent_commit: String,
    reviewed_through_commit: String,
    since_commit: String,
    tree_sha: String,
    identity_note: String,
    toolchain: String,
    inputs: Vec<FileDigest>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Successor {
    path: String,
    sha256: String,
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
    clauses: Vec<InventoryClause>,
}

#[derive(Debug, Deserialize)]
struct InventoryClause {
    profile_reviews: Vec<InventoryReview>,
}

#[derive(Debug, Deserialize)]
struct InventoryReview {
    profile: String,
    state: String,
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

    let mut tree = record.clone();
    tree.candidate.tree_sha = "0".repeat(40);
    assert!(validate(&root, &tree).is_err());

    let mut history = record.clone();
    history.drift_review.changed_requirement_bodies.clear();
    assert!(validate(&root, &history).is_err());

    let mut commits = record.clone();
    commits.drift_review.specification_commits_reviewed += 1;
    assert!(validate(&root, &commits).is_err());

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
    validate_drift(
        root,
        &record.drift_review,
        &specification_sha256,
        &record.candidate.since_commit,
        &record.candidate.reviewed_through_commit,
        &record.superseded_specification_sha256,
    )?;
    let tree = git_rev_parse(
        root,
        &format!("{}^{{tree}}", record.candidate.reviewed_through_commit),
    )?;
    if record.candidate.tree_sha != tree {
        return Err("candidate tree digest differs from the reviewed commit".to_owned());
    }
    validate_successors(root, record)?;
    reject_uncommitted_inputs(root)?;
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
    since_commit: &str,
    reviewed_through_commit: &str,
    superseded_specification_sha256: &str,
) -> Result<(), String> {
    let inventory: Inventory = read_json(&root.join(INVENTORY_PATH));
    if inventory.specification_sha256 != specification_sha256 {
        return Err("requirement inventory uses another specification".to_owned());
    }
    let review: RequirementReview = read_json(&root.join(REVIEW_PATH));
    if review.specification_sha256 != specification_sha256 {
        return Err("reviewed requirements use another specification".to_owned());
    }
    let old_specification = git_show(root, since_commit, "SPEC.md")?;
    if sha256(&old_specification) != superseded_specification_sha256 {
        return Err("superseded specification digest differs from the since commit".to_owned());
    }
    let old_inventory: Inventory = decode(
        &git_show(root, since_commit, INVENTORY_PATH)?,
        "historical inventory",
    )?;
    let old_review: RequirementReview = decode(
        &git_show(root, since_commit, REVIEW_PATH)?,
        "historical reviewed ledger",
    )?;
    if drift.specification_commits_reviewed
        != git_count(root, since_commit, reviewed_through_commit)?
    {
        return Err("reviewed specification commit count differs from git history".to_owned());
    }
    let before_clauses = old_inventory
        .requirements
        .iter()
        .map(|requirement| requirement.clauses.len())
        .sum::<usize>();
    let after_clauses = inventory
        .requirements
        .iter()
        .map(|requirement| requirement.clauses.len())
        .sum::<usize>();
    if drift.requirements_before.count != old_inventory.requirements.len()
        || drift.requirements_before.clauses != before_clauses
        || drift.requirements_after.count != inventory.requirements.len()
        || drift.requirements_after.clauses != after_clauses
    {
        return Err("recorded inventory totals differ from history".to_owned());
    }
    let old_bodies = old_inventory
        .requirements
        .iter()
        .map(|requirement| (requirement.id.clone(), requirement.body_sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    let new_bodies = inventory
        .requirements
        .iter()
        .map(|requirement| (requirement.id.clone(), requirement.body_sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_added = new_bodies
        .keys()
        .filter(|id| !old_bodies.contains_key(*id))
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_removed = old_bodies
        .keys()
        .filter(|id| !new_bodies.contains_key(*id))
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_changed = new_bodies
        .iter()
        .filter(|(id, body)| old_bodies.get(*id).is_some_and(|old| old != *body))
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let recorded_added = drift
        .added_requirements
        .iter()
        .map(|added| added.id.clone())
        .collect::<BTreeSet<_>>();
    if recorded_added != expected_added
        || drift
            .changed_requirement_bodies
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_changed
        || drift
            .removed_requirements
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_removed
    {
        return Err("recorded drift identities differ from history".to_owned());
    }
    for added in &drift.added_requirements {
        let requirement = inventory
            .requirements
            .iter()
            .find(|requirement| requirement.id == added.id)
            .ok_or_else(|| format!("added requirement is absent: {}", added.id))?;
        let expected_states = requirement
            .clauses
            .iter()
            .flat_map(|clause| clause.profile_reviews.iter())
            .map(|review| format!("{}:{}", review.profile, review.state))
            .collect::<BTreeSet<_>>();
        if requirement.clauses.len() != added.clauses
            || added
                .profile_reviews
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                != expected_states
        {
            return Err(format!("added requirement shape differs: {}", added.id));
        }
    }
    let derived_before = profile_counts(&old_review)?;
    let derived_after = profile_counts(&review)?;
    if drift.profile_applicability.len() != PROFILES.len() {
        return Err("profile applicability rows are incomplete".to_owned());
    }
    for (index, row) in drift.profile_applicability.iter().enumerate() {
        if row.profile != PROFILES[index] {
            return Err("profile applicability order differs".to_owned());
        }
        let before = derived_before
            .get(&row.profile)
            .ok_or_else(|| format!("unknown profile {}", row.profile))?;
        let after = derived_after
            .get(&row.profile)
            .ok_or_else(|| format!("unknown profile {}", row.profile))?;
        if row.before_covered != before.0
            || row.before_not_applicable != before.1
            || row.after_covered != after.0
            || row.after_not_applicable != after.1
            || row.after_planned != after.2
            || row.after_planned != 0
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

fn profile_counts(
    review: &RequirementReview,
) -> Result<BTreeMap<String, (usize, usize, usize)>, String> {
    let mut counts = PROFILES
        .into_iter()
        .map(|profile| (profile.to_owned(), (0_usize, 0_usize, 0_usize)))
        .collect::<BTreeMap<_, _>>();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile_review in &clause.profile_reviews {
                let entry = counts
                    .get_mut(&profile_review.profile)
                    .ok_or_else(|| format!("unknown profile {}", profile_review.profile))?;
                match profile_review.state.as_str() {
                    "covered" if !profile_review.evidence.is_empty() => entry.0 += 1,
                    "not-applicable" if profile_review.evidence.is_empty() => entry.1 += 1,
                    "covered" | "not-applicable" => {
                        return Err("profile review evidence shape is invalid".to_owned());
                    }
                    _ => entry.2 += 1,
                }
            }
        }
    }
    Ok(counts)
}

fn git_show(root: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["show", &format!("{commit}:{path}")])
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err(format!(
            "could not read historical input {path} at {commit}"
        ));
    }
    Ok(output.stdout)
}

fn git_count(root: &Path, since: &str, through: &str) -> Result<usize, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "rev-list",
            "--count",
            &format!("{since}..{through}"),
            "--",
            "SPEC.md",
        ])
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err("could not count reviewed specification commits".to_owned());
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<usize>()
        .map_err(|error| format!("invalid specification commit count: {error}"))
}

fn git_rev_parse(root: &Path, argument: &str) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--verify", argument])
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err(format!("could not resolve {argument}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_changed_paths(root: &Path, commit: &str) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["diff", "--name-only", commit, "HEAD"])
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err("could not inspect the candidate descendant changes".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect())
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("could not decode {label}: {error}"))
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

fn validate_successors(root: &Path, record: &Record) -> Result<(), String> {
    let changed = git_changed_paths(root, &record.candidate.reviewed_through_commit)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let recorded = record
        .successors
        .iter()
        .map(|successor| successor.path.clone())
        .collect::<BTreeSet<_>>();
    if changed != recorded || recorded.len() != record.successors.len() {
        return Err("recorded successor set differs from the candidate descendants".to_owned());
    }
    for successor in &record.successors {
        verify_successor_digest(root, successor)?;
    }
    Ok(())
}

/// Verifies one recorded successor digest against the bytes it currently pins.
///
/// Self-referential records cannot pin their own digest, so an empty digest is
/// accepted only for those paths. Every other successor must pin a digest that
/// matches its committed bytes.
fn verify_successor_digest(root: &Path, successor: &Successor) -> Result<(), String> {
    if successor.sha256.is_empty() {
        if !self_referential(&successor.path) {
            return Err(format!(
                "successor has no pinned digest: {}",
                successor.path
            ));
        }
        return Ok(());
    }
    let bytes = fs::read(root.join(&successor.path))
        .map_err(|error| format!("could not read successor {}: {error}", successor.path))?;
    if successor.sha256 != sha256(&bytes) {
        return Err(format!("successor digest differs: {}", successor.path));
    }
    Ok(())
}

fn self_referential(path: &str) -> bool {
    path == RECORD_PATH
        || path == "protocol/conformance/manifest-v1.json"
        || path == "protocol/publication/v1/gantry.conformance.json"
        || path == "protocol/publication/index-v1.json"
        || path == "protocol/publication/verification-v1.json"
}

fn reject_uncommitted_inputs(root: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err("could not inspect uncommitted inputs".to_owned());
    }
    for path in dirty_paths(&output.stdout)? {
        if dirty_path_is_applicable(&path) {
            return Err(format!("applicable input is not committed: {path}"));
        }
    }
    Ok(())
}

fn dirty_paths(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut fields = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    let mut paths = Vec::new();
    while let Some(entry) = fields.next() {
        if entry.len() < 3 {
            return Err("unrecognized worktree status entry".to_owned());
        }
        let status = &entry[..2];
        paths.push(String::from_utf8_lossy(&entry[3..]).into_owned());
        if status.contains(&b'R') || status.contains(&b'C') {
            let source = fields
                .next()
                .ok_or_else(|| "rename entry has no source path".to_owned())?;
            paths.push(String::from_utf8_lossy(source).into_owned());
        }
    }
    Ok(paths)
}

fn dirty_path_is_applicable(path: &str) -> bool {
    !path.starts_with("target/") && !path.starts_with("docs/reference/")
}

#[test]
fn qualification_validator_rejects_successor_and_dirty_input_counterexamples() {
    let root = workspace_root();
    let record: Record = read_json(&root.join(RECORD_PATH));
    // The recorded successor set is the candidate-descendant diff at the current
    // head, so dropping a recorded successor must be refused. This holds even
    // when every remaining successor is self-referential and therefore carries
    // no digest, which is the shape of a record-only recut.
    let mut missing_successor = record.clone();
    assert!(
        !missing_successor.successors.is_empty(),
        "the record is always its own recorded successor"
    );
    missing_successor.successors.pop();
    assert!(validate(&root, &missing_successor).is_err());

    // Only self-referential successors may omit a digest, and every one of them
    // must omit it. A legitimate record-only recut therefore proves the
    // invariant without requiring a pinned successor to exist.
    for entry in &record.successors {
        assert_eq!(
            entry.sha256.is_empty(),
            self_referential(&entry.path),
            "successor pin state differs from its self-referential status: {}",
            entry.path
        );
    }

    // The per-successor digest branch runs against an explicitly test-local tree
    // so its counterexamples never depend on which successors the live record
    // happens to carry.
    let fixture_root = successor_fixture_root();
    let pinned_path = "protocol/publication/v1/qualification-fixture.json";
    let pinned_bytes = b"pinned successor bytes";
    let pinned_digest = sha256(pinned_bytes);
    let self_bytes = b"self-referential record bytes";
    let self_digest = sha256(self_bytes);
    write_successor_fixture(&fixture_root, pinned_path, pinned_bytes);
    write_successor_fixture(&fixture_root, RECORD_PATH, self_bytes);

    // A matching pin is accepted for both pinned and self-referential entries.
    assert_eq!(
        verify_successor_digest(
            &fixture_root,
            &successor_fixture(pinned_path, &pinned_digest)
        ),
        Ok(())
    );
    assert_eq!(
        verify_successor_digest(&fixture_root, &successor_fixture(RECORD_PATH, &self_digest)),
        Ok(())
    );
    // A wrong digest must fail even though the pinned file exists.
    assert_eq!(
        verify_successor_digest(
            &fixture_root,
            &successor_fixture(pinned_path, &"0".repeat(64))
        ),
        Err(format!("successor digest differs: {pinned_path}"))
    );
    // A pinned successor whose file is absent must fail.
    let absent_path = "protocol/publication/v1/absent-successor.json";
    match verify_successor_digest(
        &fixture_root,
        &successor_fixture(absent_path, &pinned_digest),
    ) {
        Ok(()) => panic!("an absent successor file must not verify"),
        Err(error) => assert!(
            error.starts_with(&format!("could not read successor {absent_path}: ")),
            "unexpected absent-successor error: {error}"
        ),
    }
    // A non-self-referential entry with no pin must fail, and a self-referential
    // entry with no pin must pass; a self-referential entry that pins a wrong
    // digest must still fail.
    assert_eq!(
        verify_successor_digest(&fixture_root, &successor_fixture(pinned_path, "")),
        Err(format!("successor has no pinned digest: {pinned_path}"))
    );
    assert_eq!(
        verify_successor_digest(&fixture_root, &successor_fixture(RECORD_PATH, "")),
        Ok(())
    );
    assert_eq!(
        verify_successor_digest(
            &fixture_root,
            &successor_fixture(RECORD_PATH, &"0".repeat(64))
        ),
        Err(format!("successor digest differs: {RECORD_PATH}"))
    );

    let applicable_to_excluded =
        dirty_paths(b"R  docs/reference/task.rs\0crates/gantry-runtime/src/task.rs\0")
            .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        applicable_to_excluded
            .iter()
            .any(|path| dirty_path_is_applicable(path))
    );
    let excluded_to_applicable =
        dirty_paths(b"R  crates/gantry-runtime/src/task.rs\0docs/reference/task.rs\0")
            .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        excluded_to_applicable
            .iter()
            .any(|path| dirty_path_is_applicable(path))
    );
    let harmless =
        dirty_paths(b"R  target/a\0target/b\0").unwrap_or_else(|error| panic!("{error}"));
    assert!(harmless.iter().all(|path| !dirty_path_is_applicable(path)));
    let literal =
        dirty_paths(b"?? arrows  ->  in names.rs\0").unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(literal, vec!["arrows  ->  in names.rs".to_owned()]);
    assert!(dirty_path_is_applicable(
        "crates/gantry-runtime/src/task.rs"
    ));
    assert!(!dirty_path_is_applicable("target/debug/xtask"));
    assert!(!dirty_path_is_applicable("docs/reference/note.md"));
}

/// Returns a clean scratch tree for successor digest fixtures under the test
/// target directory.
fn successor_fixture_root() -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("successor-digest-fixture");
    if root.exists() {
        fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("could not clear {}: {error}", root.display()));
    }
    fs::create_dir_all(&root)
        .unwrap_or_else(|error| panic!("could not create {}: {error}", root.display()));
    root
}

/// Writes one successor fixture file, creating its parent directories.
fn write_successor_fixture(root: &Path, path: &str, bytes: &[u8]) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", parent.display()));
    }
    fs::write(&target, bytes)
        .unwrap_or_else(|error| panic!("could not write {}: {error}", target.display()));
}

/// Builds one successor entry for a digest fixture call.
fn successor_fixture(path: &str, digest: &str) -> Successor {
    Successor {
        path: path.to_owned(),
        sha256: digest.to_owned(),
    }
}
