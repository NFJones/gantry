//! Contract-gate validation for the executor-backed execution amendment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";
const ASYNC_EVIDENCE_GATE_PATH: &str = "protocol/conformance/async-execution-gate-v1.json";
const INVENTORY_PATH: &str = "protocol/conformance/manifest-v1.json";
const SOURCE_SPAWN_ISSUE: &str = "GNT-ASYNC-SPAWN-001";
const SOURCE_SPAWN_PATH: &str = "protocol/conformance/source-spawn-v1.json";
const PROFILES: [&str; 6] = [
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
];
const ASSIGNMENT_MATRIX_SHA256: &str =
    "d5f62a1af89feded6523b71efc615b9c7d295c9b5e8a099d2f26033c34fa33a4";
const SOURCE_SPAWN_EXCLUSIONS: [&str; 4] = [
    "Source JOIN, JOINALL, DETACH, descendant draining, and their complete concurrent-evaluator behavior remain owned by GNT-ASYNC-JOIN-001 and GNT-ASYNC-CANCEL-001.",
    "The linked source fixtures do not claim successful source JOIN execution; after the child behavior under test, their join site may terminate with the current unsupported task-control invariant.",
    "Complete concurrent-evaluator graph cancellation is not inferred from the focused durable cancellation ordering case.",
    "Recovered child reconstruction and fenced executor resubmission remain owned by GNT-ASYNC-REC-001; mixed-prefix resume is only classified as runnable replacement unavailable.",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractGate {
    format: String,
    issue: String,
    status: String,
    specification_sha256: String,
    adoption_gate: String,
    profile_claims: String,
    amended_profiles: Vec<String>,
    prerequisites: Vec<Prerequisite>,
    contract_artifacts: Vec<FileDigest>,
    decisions: Vec<Decision>,
    requirement_assignments: Vec<Assignment>,
    compatibility_impacts: Vec<String>,
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
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: String,
    status: String,
    resolution: String,
    normative_requirements: Vec<String>,
    generated_artifacts: Vec<String>,
    implementation_owners: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SourceSpawnManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    requirements: Vec<SourceSpawnRequirement>,
    capabilities: Vec<SourceSpawnCapability>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SourceSpawnRequirement {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SourceSpawnCapability {
    id: String,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AsyncEvidenceGateInventory {
    format: String,
    gate: String,
    status: String,
    specification_sha256: String,
    artifacts: Vec<FileDigest>,
}

#[derive(Clone, Debug, Deserialize)]
struct ConformanceInventory {
    format: String,
    specification_sha256: String,
    manifests: Vec<ManifestInventoryEntry>,
    gates: Vec<GateInventoryEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestInventoryEntry {
    format: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GateInventoryEntry {
    gate: String,
    path: String,
    sha256: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionGate {
    format: String,
    gate: String,
    status: String,
    specification_sha256: String,
    amended_profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    blocked_by: Vec<String>,
    superseded_publication_revision: String,
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
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
}

#[test]
fn verified_async_contract_gate_freezes_every_decision_and_requirement_assignment() {
    let root = workspace_root();
    let contract: ContractGate = read_json(&root.join(CONTRACT_PATH));
    assert_eq!(validate_contract(&root, &contract), Ok(()));
}

#[test]
fn async_contract_gate_rejects_stale_incomplete_duplicate_or_overclaimed_records() {
    let root = workspace_root();
    let contract: ContractGate = read_json(&root.join(CONTRACT_PATH));

    let mut stale = contract.clone();
    stale.contract_artifacts[0].sha256 = "0".repeat(64);
    assert!(matches!(
        validate_contract(&root, &stale),
        Err(message) if message.contains("artifact digest differs")
    ));

    let mut missing_decision = contract.clone();
    missing_decision.decisions.pop();
    assert!(matches!(
        validate_contract(&root, &missing_decision),
        Err(message) if message.contains("fourteen resolved decisions")
    ));

    let mut unresolved = contract.clone();
    unresolved.decisions[0].status = "open".to_owned();
    assert!(matches!(
        validate_contract(&root, &unresolved),
        Err(message) if message.contains("unresolved decision")
    ));

    let mut duplicate = contract.clone();
    duplicate
        .requirement_assignments
        .push(duplicate.requirement_assignments[0].clone());
    assert!(matches!(
        validate_contract(&root, &duplicate),
        Err(message) if message.contains("duplicate requirement assignment")
    ));

    let mut incomplete = contract.clone();
    incomplete.requirement_assignments[0].profiles.pop();
    assert!(matches!(
        validate_contract(&root, &incomplete),
        Err(message) if message.contains("requirement assignment matrix differs")
    ));

    let mut unrelated_covered = contract.clone();
    unrelated_covered.requirement_assignments.push(Assignment {
        requirement: "GNT-12.6".to_owned(),
        clause: "clause-001".to_owned(),
        profiles: vec!["durable-runtime".to_owned()],
        evidence_owners: unrelated_covered.requirement_assignments[0]
            .evidence_owners
            .clone(),
    });
    assert!(matches!(
        validate_contract(&root, &unrelated_covered),
        Err(message) if message.contains("requirement assignment matrix differs")
    ));

    let mut overclaimed = contract;
    overclaimed.profile_claims = "enabled".to_owned();
    assert!(matches!(
        validate_contract(&root, &overclaimed),
        Err(message) if message.contains("profile claims")
    ));
}

#[test]
fn source_spawn_closure_rejects_structural_content_anchor_and_digest_mutations() {
    let root = workspace_root();
    let contract: ContractGate = read_json(&root.join(CONTRACT_PATH));
    let source: SourceSpawnManifest = read_json(&root.join(SOURCE_SPAWN_PATH));
    let gate: AsyncEvidenceGateInventory = read_json(&root.join(ASYNC_EVIDENCE_GATE_PATH));
    let inventory: ConformanceInventory = read_json(&root.join(INVENTORY_PATH));
    let specification_sha256 = sha256(&read(&root.join("SPEC.md")).unwrap_or_else(|error| {
        panic!("could not read specification for source-spawn regression: {error}")
    }));

    assert_eq!(
        validate_source_spawn_closure(
            &root,
            &contract,
            &specification_sha256,
            &source,
            &gate,
            &inventory,
        ),
        Ok(())
    );

    let mut unknown: serde_json::Value = read_json(&root.join(SOURCE_SPAWN_PATH));
    unknown
        .as_object_mut()
        .unwrap_or_else(|| panic!("source-spawn manifest is not an object"))
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    let error = match serde_json::from_value::<SourceSpawnManifest>(unknown) {
        Ok(_) => panic!("source-spawn manifest accepted an unknown field"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("unknown field `unexpected`"));

    let mut reordered_requirement = source.clone();
    reordered_requirement.requirements.swap(0, 1);
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &reordered_requirement,
        &gate,
        &inventory,
        "requirements differ",
    );

    let mut changed_requirement = source.clone();
    changed_requirement.requirements[0].profiles.pop();
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &changed_requirement,
        &gate,
        &inventory,
        "requirements differ",
    );

    let mut reordered_capability = source.clone();
    reordered_capability.capabilities.swap(0, 1);
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &reordered_capability,
        &gate,
        &inventory,
        "capabilities differ",
    );

    let mut changed_capability = source.clone();
    changed_capability.capabilities[0].id = "changed-capability".to_owned();
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &changed_capability,
        &gate,
        &inventory,
        "capabilities differ",
    );

    let mut reordered_exclusion = source.clone();
    reordered_exclusion.exclusions.swap(0, 1);
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &reordered_exclusion,
        &gate,
        &inventory,
        "exclusions differ",
    );

    let mut changed_exclusion = source.clone();
    changed_exclusion.exclusions[0].push_str(" changed");
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &changed_exclusion,
        &gate,
        &inventory,
        "exclusions differ",
    );

    let mut dangling_anchor = source.clone();
    dangling_anchor.capabilities[0].evidence =
        "crates/gantry-conformance/tests/source_spawn.rs#missing_source_spawn_symbol".to_owned();
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &dangling_anchor,
        &gate,
        &inventory,
        "evidence symbol does not exist",
    );

    let mut stale_specification = source.clone();
    stale_specification.specification_sha256 = "0".repeat(64);
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &stale_specification,
        &gate,
        &inventory,
        "specification digest differs",
    );

    let mut stale_inventory = inventory.clone();
    stale_inventory
        .manifests
        .iter_mut()
        .find(|entry| entry.path == SOURCE_SPAWN_PATH)
        .unwrap_or_else(|| panic!("source-spawn inventory entry is absent"))
        .sha256 = "0".repeat(64);
    assert_source_spawn_error(
        &root,
        &contract,
        &specification_sha256,
        &source,
        &gate,
        &stale_inventory,
        "aggregate manifest digest differs",
    );
}

fn validate_contract(root: &Path, contract: &ContractGate) -> Result<(), String> {
    if contract.format != "gantry.async-execution-contract-gate/v1"
        || contract.issue != "GNT-ASYNC-GATE-000"
        || contract.status != "verified"
    {
        return Err("contract gate identity or status is invalid".to_owned());
    }
    if contract.profile_claims != "blocked" || gantry::PROFILE_CLAIMS_ENABLED {
        return Err("contract gate profile claims are not blocked".to_owned());
    }
    if contract
        .amended_profiles
        .iter()
        .map(String::as_str)
        .ne(PROFILES)
    {
        return Err("contract gate profile set is incomplete or unordered".to_owned());
    }

    let specification = read(&root.join("SPEC.md"))?;
    let specification_sha256 = sha256(&specification);
    if contract.specification_sha256 != specification_sha256 {
        return Err("contract gate uses another specification revision".to_owned());
    }
    let review: RequirementReview = read_json_result(&root.join(REVIEW_PATH))?;
    if review.specification_sha256 != specification_sha256 {
        return Err("reviewed requirements use another specification revision".to_owned());
    }
    let adoption: AdoptionGate = read_json_result(&root.join(&contract.adoption_gate))?;
    if adoption.format != "gantry.async-execution-adoption/v1"
        || adoption.gate != contract.issue
        || adoption.status != "blocked"
        || adoption.specification_sha256 != specification_sha256
        || adoption.amended_profiles != contract.amended_profiles
        || !adoption.advertises_profiles.is_empty()
        || adoption.superseded_publication_revision.is_empty()
    {
        return Err("staged adoption gate is inconsistent with the contract gate".to_owned());
    }
    let downstream = adoption.blocked_by.into_iter().collect::<BTreeSet<_>>();
    if downstream.is_empty() || downstream.contains(&contract.issue) {
        return Err("staged adoption downstream issue set is invalid".to_owned());
    }
    let mut evidence_owners = downstream.clone();
    let source_spawn: SourceSpawnManifest = read_json_result(&root.join(SOURCE_SPAWN_PATH))?;
    let async_gate: AsyncEvidenceGateInventory =
        read_json_result(&root.join(ASYNC_EVIDENCE_GATE_PATH))?;
    let inventory: ConformanceInventory = read_json_result(&root.join(INVENTORY_PATH))?;
    validate_source_spawn_closure(
        root,
        contract,
        &specification_sha256,
        &source_spawn,
        &async_gate,
        &inventory,
    )?;
    if !evidence_owners.insert(SOURCE_SPAWN_ISSUE.to_owned()) {
        return Err(format!(
            "closed evidence owner {SOURCE_SPAWN_ISSUE} is duplicated"
        ));
    }

    validate_prerequisites(root, &contract.prerequisites)?;
    let artifact_paths = validate_artifacts(root, &contract.contract_artifacts)?;
    let requirement_ids = review
        .requirements
        .iter()
        .map(|requirement| requirement.id.clone())
        .collect::<BTreeSet<_>>();
    validate_decisions(
        &contract.decisions,
        &requirement_ids,
        &artifact_paths,
        &evidence_owners,
    )?;
    validate_assignments(&contract.requirement_assignments, &review, &evidence_owners)?;

    if contract.compatibility_impacts.len() < 8
        || !sorted_unique(&contract.compatibility_impacts)
        || contract
            .compatibility_impacts
            .iter()
            .any(|impact| impact.is_empty() || contains_placeholder(impact))
    {
        return Err("compatibility impacts are incomplete or provisional".to_owned());
    }
    Ok(())
}

fn validate_prerequisites(root: &Path, prerequisites: &[Prerequisite]) -> Result<(), String> {
    const EXPECTED: [(&str, &str, &str); 4] = [
        (
            "GNT-ASYNC-SPEC-001",
            "b076f1adf2b0128a579a3743e36588de2862e8c8",
            "Define executor-backed execution semantics.",
        ),
        (
            "GNT-ASYNC-CONTRACT-001",
            "1da9cb5036c21fc48bafd6d240447a72d6a1bf27",
            "Amend generated async execution contracts.",
        ),
        (
            "GNT-ASYNC-CONTRACT-001",
            "ef45c97154093183acf880feba47fe9b98607e97",
            "Correct preflight trait contract.",
        ),
        (
            "GNT-ASYNC-CONTRACT-001",
            "58c88d66ca7926515edaf0892bcf39fdc6d897b3",
            "Correct executor completion contract.",
        ),
    ];
    if prerequisites
        .iter()
        .map(|entry| {
            (
                entry.issue.as_str(),
                entry.commit.as_str(),
                entry.subject.as_str(),
            )
        })
        .ne(EXPECTED)
    {
        return Err("contract gate prerequisites are incomplete".to_owned());
    }
    for prerequisite in prerequisites {
        let status = Command::new("git")
            .current_dir(root)
            .args(["merge-base", "--is-ancestor", &prerequisite.commit, "HEAD"])
            .status()
            .map_err(|error| format!("could not inspect prerequisite commit: {error}"))?;
        if !status.success() {
            return Err(format!(
                "prerequisite commit is not an ancestor: {}",
                prerequisite.commit
            ));
        }
    }
    Ok(())
}

fn validate_artifacts(root: &Path, artifacts: &[FileDigest]) -> Result<BTreeSet<String>, String> {
    if artifacts.is_empty() || !artifacts.windows(2).all(|pair| pair[0].path < pair[1].path) {
        return Err("contract artifact set is empty, duplicate, or unordered".to_owned());
    }
    let mut paths = BTreeSet::new();
    for artifact in artifacts {
        let bytes = read(&root.join(&artifact.path))?;
        if artifact.sha256 != sha256(&bytes) {
            return Err(format!("artifact digest differs: {}", artifact.path));
        }
        paths.insert(artifact.path.clone());
    }
    Ok(paths)
}

fn validate_source_spawn_closure(
    root: &Path,
    contract: &ContractGate,
    specification_sha256: &str,
    source: &SourceSpawnManifest,
    gate: &AsyncEvidenceGateInventory,
    inventory: &ConformanceInventory,
) -> Result<(), String> {
    if source.format != "gantry.source-spawn-evidence/v1" || source.issue != SOURCE_SPAWN_ISSUE {
        return Err("source-spawn manifest identity differs".to_owned());
    }
    if source.specification_sha256 != specification_sha256 {
        return Err("source-spawn specification digest differs".to_owned());
    }

    let expected_requirements = expected_source_spawn_requirements();
    if source.requirements != expected_requirements {
        return Err("source-spawn requirements differ from the exact contract".to_owned());
    }
    let owned_requirements = contract
        .requirement_assignments
        .iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == SOURCE_SPAWN_ISSUE)
        })
        .map(|assignment| SourceSpawnRequirement {
            requirement: assignment.requirement.clone(),
            clause: assignment.clause.clone(),
            profiles: assignment.profiles.clone(),
        })
        .collect::<Vec<_>>();
    if owned_requirements != source.requirements {
        return Err("source-spawn evidence ownership differs from the async contract".to_owned());
    }

    for capability in &source.capabilities {
        validate_evidence_anchor(root, &capability.evidence)?;
    }
    if source.capabilities != expected_source_spawn_capabilities() {
        return Err("source-spawn capabilities differ from the exact contract".to_owned());
    }
    if source.exclusions
        != SOURCE_SPAWN_EXCLUSIONS
            .iter()
            .map(|exclusion| (*exclusion).to_owned())
            .collect::<Vec<_>>()
    {
        return Err("source-spawn exclusions differ from the exact contract".to_owned());
    }

    let source_digest = sha256(&read(&root.join(SOURCE_SPAWN_PATH))?);
    if gate.format != "gantry.async-execution-evidence-gate/v1"
        || gate.gate != "GNT-ASYNC-GATE-100"
        || gate.status != "verified"
        || gate.specification_sha256 != specification_sha256
    {
        return Err("source-spawn authentication gate identity differs".to_owned());
    }
    validate_digest_entry(
        gate.artifacts
            .iter()
            .map(|entry| (entry.path.as_str(), entry.sha256.as_str())),
        SOURCE_SPAWN_PATH,
        &source_digest,
        "async evidence gate",
    )?;

    if inventory.format != "gantry.conformance-manifest/v1"
        || inventory.specification_sha256 != specification_sha256
    {
        return Err("source-spawn aggregate manifest identity differs".to_owned());
    }
    let source_inventory = inventory
        .manifests
        .iter()
        .filter(|entry| entry.path == SOURCE_SPAWN_PATH)
        .collect::<Vec<_>>();
    if source_inventory.len() != 1
        || source_inventory[0].format != source.format
        || source_inventory[0].sha256 != source_digest
    {
        return Err("source-spawn aggregate manifest digest differs".to_owned());
    }

    let gate_digest = sha256(&read(&root.join(ASYNC_EVIDENCE_GATE_PATH))?);
    validate_digest_entry(
        inventory
            .manifests
            .iter()
            .filter(|entry| entry.format == gate.format)
            .map(|entry| (entry.path.as_str(), entry.sha256.as_str())),
        ASYNC_EVIDENCE_GATE_PATH,
        &gate_digest,
        "aggregate manifest gate inventory",
    )?;
    let gate_inventory = inventory
        .gates
        .iter()
        .filter(|entry| entry.gate == gate.gate)
        .collect::<Vec<_>>();
    if gate_inventory.len() != 1
        || gate_inventory[0].path != ASYNC_EVIDENCE_GATE_PATH
        || gate_inventory[0].sha256 != gate_digest
        || gate_inventory[0].status != gate.status
    {
        return Err("source-spawn aggregate gate digest differs".to_owned());
    }
    Ok(())
}

fn validate_digest_entry<'a>(
    entries: impl Iterator<Item = (&'a str, &'a str)>,
    expected_path: &str,
    expected_digest: &str,
    owner: &str,
) -> Result<(), String> {
    let matching = entries
        .filter(|(path, _)| *path == expected_path)
        .collect::<Vec<_>>();
    if matching.len() != 1 || matching[0].1 != expected_digest {
        return Err(format!("source-spawn {owner} digest differs"));
    }
    Ok(())
}

fn validate_evidence_anchor(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, symbol) = evidence
        .split_once('#')
        .ok_or_else(|| format!("source-spawn evidence anchor is malformed: {evidence}"))?;
    if path.is_empty() || symbol.is_empty() || symbol.contains('#') {
        return Err(format!(
            "source-spawn evidence anchor is malformed: {evidence}"
        ));
    }
    let source = String::from_utf8(read(&root.join(path))?)
        .map_err(|_| format!("source-spawn evidence file is not UTF-8: {path}"))?;
    let declaration = format!("fn {symbol}(");
    if !source
        .lines()
        .any(|line| line.trim_start().starts_with(&declaration))
    {
        return Err(format!(
            "source-spawn evidence symbol does not exist: {evidence}"
        ));
    }
    Ok(())
}

fn expected_source_spawn_requirements() -> Vec<SourceSpawnRequirement> {
    [
        (
            "GNT-3.6",
            "clause-001",
            &[
                "concurrent-evaluator",
                "durable-runtime",
                "embedding",
                "evaluator",
            ][..],
        ),
        ("GNT-3-M-SPAWN", "clause-001", &["concurrent-evaluator"][..]),
        (
            "GNT-3-D-COMMIT-ORDER",
            "clause-001",
            &["durable-runtime"][..],
        ),
        (
            "GNT-7.17",
            "clause-003",
            &[
                "concurrent-evaluator",
                "durable-runtime",
                "embedding",
                "evaluator",
            ][..],
        ),
        (
            "GNT-15.2-runtime-sessions",
            "clause-001",
            &["embedding"][..],
        ),
        ("GNT-15.4", "clause-001", &["embedding"][..]),
        ("GNT-15.4-owned-work", "clause-001", &["embedding"][..]),
    ]
    .into_iter()
    .map(|(requirement, clause, profiles)| SourceSpawnRequirement {
        requirement: requirement.to_owned(),
        clause: clause.to_owned(),
        profiles: profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    })
    .collect()
}

fn expected_source_spawn_capabilities() -> Vec<SourceSpawnCapability> {
    [
        (
            "child-session-before-hook",
            "native_child_submission_keeps_the_gate_closed_and_establishes_session_before_hook",
        ),
        (
            "durable-child-creation-order",
            "durable_child_creation_and_success_publish_before_immediate_child_polling",
        ),
        (
            "durable-child-operation-order",
            "durable_child_action_commits_ordered_operation_cuts",
        ),
        (
            "durable-child-submission-failure-order",
            "durable_child_submission_failure_settles_the_created_identity_before_parent_progress",
        ),
        (
            "native-executor-child-submission",
            "native_child_submission_keeps_the_gate_closed_and_establishes_session_before_hook",
        ),
        (
            "parent-session-precheck",
            "durable_parent_session_failure_is_task_local_and_creates_no_child",
        ),
        (
            "required-spawn-event-barrier",
            "durable_required_spawn_event_settles_before_child_submission",
        ),
        (
            "submission-rejection-settlement",
            "child_executor_rejection_settles_without_submitting_another_driver",
        ),
        (
            "task-limit-precheck",
            "durable_task_limit_precheck_skips_parent_session_and_child_creation",
        ),
    ]
    .into_iter()
    .map(|(id, symbol)| SourceSpawnCapability {
        id: id.to_owned(),
        evidence: format!("crates/gantry-conformance/tests/source_spawn.rs#{symbol}"),
    })
    .collect()
}

fn assert_source_spawn_error(
    root: &Path,
    contract: &ContractGate,
    specification_sha256: &str,
    source: &SourceSpawnManifest,
    gate: &AsyncEvidenceGateInventory,
    inventory: &ConformanceInventory,
    expected: &str,
) {
    assert!(matches!(
        validate_source_spawn_closure(
            root,
            contract,
            specification_sha256,
            source,
            gate,
            inventory,
        ),
        Err(message) if message.contains(expected)
    ));
}

fn validate_decisions(
    decisions: &[Decision],
    requirement_ids: &BTreeSet<String>,
    artifact_paths: &BTreeSet<String>,
    downstream: &BTreeSet<String>,
) -> Result<(), String> {
    let expected_ids = (1..=14)
        .map(|index| format!("decision-{index:02}"))
        .collect::<Vec<_>>();
    if decisions
        .iter()
        .map(|decision| &decision.id)
        .ne(&expected_ids)
    {
        return Err("contract gate must contain fourteen resolved decisions".to_owned());
    }
    for decision in decisions {
        if decision.status != "resolved" {
            return Err(format!("unresolved decision: {}", decision.id));
        }
        if decision.resolution.is_empty() || contains_placeholder(&decision.resolution) {
            return Err(format!("decision {} remains provisional", decision.id));
        }
        if decision.normative_requirements.is_empty()
            || !sorted_unique(&decision.normative_requirements)
            || decision
                .normative_requirements
                .iter()
                .any(|requirement| !requirement_ids.contains(requirement))
        {
            return Err(format!("decision {} has invalid requirements", decision.id));
        }
        if decision.generated_artifacts.is_empty()
            || !sorted_unique(&decision.generated_artifacts)
            || decision
                .generated_artifacts
                .iter()
                .any(|artifact| !artifact_paths.contains(artifact))
        {
            return Err(format!("decision {} has invalid artifacts", decision.id));
        }
        if decision.implementation_owners.is_empty()
            || !sorted_unique(&decision.implementation_owners)
            || decision
                .implementation_owners
                .iter()
                .any(|owner| !downstream.contains(owner))
        {
            return Err(format!("decision {} has invalid owners", decision.id));
        }
    }
    Ok(())
}

fn validate_assignments(
    assignments: &[Assignment],
    review: &RequirementReview,
    downstream: &BTreeSet<String>,
) -> Result<(), String> {
    let mut reviewed = BTreeMap::<(String, String, String), String>::new();
    let mut remaining_planned = BTreeSet::new();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            for profile in &clause.profile_reviews {
                let key = (
                    requirement.id.clone(),
                    clause.key.clone(),
                    profile.profile.clone(),
                );
                reviewed.insert(key.clone(), profile.state.clone());
                if profile.state == "planned" {
                    remaining_planned.insert(key);
                }
            }
        }
    }

    let mut assigned = BTreeSet::new();
    let mut assignment_rows = Vec::new();
    let mut owners = BTreeSet::new();
    for assignment in assignments {
        if assignment.profiles.is_empty()
            || !sorted_unique(&assignment.profiles)
            || assignment.evidence_owners.is_empty()
            || !sorted_unique(&assignment.evidence_owners)
        {
            return Err(format!(
                "assignment {}#{} is empty, duplicate, or unordered",
                assignment.requirement, assignment.clause
            ));
        }
        for owner in &assignment.evidence_owners {
            if !downstream.contains(owner) {
                return Err(format!("unknown evidence owner {owner}"));
            }
            owners.insert(owner.clone());
        }
        for profile in &assignment.profiles {
            assignment_rows.push(format!(
                "{}#{}#{}#{}\n",
                assignment.requirement,
                assignment.clause,
                profile,
                assignment.evidence_owners.join(",")
            ));
            let key = (
                assignment.requirement.clone(),
                assignment.clause.clone(),
                profile.clone(),
            );
            if !assigned.insert(key.clone()) {
                return Err(format!(
                    "duplicate requirement assignment {}#{}#{profile}",
                    assignment.requirement, assignment.clause
                ));
            }
            if !matches!(
                reviewed.get(&key).map(String::as_str),
                Some("planned" | "covered")
            ) {
                return Err(format!(
                    "assignment is not a planned or covered review {}#{}#{profile}",
                    assignment.requirement, assignment.clause
                ));
            }
        }
    }
    assignment_rows.sort();
    if sha256(assignment_rows.concat().as_bytes()) != ASSIGNMENT_MATRIX_SHA256 {
        return Err("requirement assignment matrix differs from the frozen contract".to_owned());
    }
    if !remaining_planned.is_subset(&assigned) {
        return Err("planned requirement coverage differs from the frozen matrix".to_owned());
    }
    if owners != *downstream {
        return Err("downstream issue ownership differs from the frozen matrix".to_owned());
    }
    Ok(())
}

fn contains_placeholder(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    ["todo", "tbd", "reverify later", "unresolved choice"]
        .iter()
        .any(|placeholder| value.contains(placeholder))
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    read_json_result(path).unwrap_or_else(|error| panic!("{error}"))
}

fn read_json_result<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not decode {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
