//! Contract-gate validation for the executor-backed execution amendment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
const REVIEW_PATH: &str = "protocol/requirements/reviewed-v1.json";
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
fn verified_async_contract_gate_freezes_every_decision_and_planned_requirement() {
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
        Err(message) if message.contains("planned requirement coverage differs")
    ));

    let mut overclaimed = contract;
    overclaimed.profile_claims = "enabled".to_owned();
    assert!(matches!(
        validate_contract(&root, &overclaimed),
        Err(message) if message.contains("profile claims")
    ));
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
        &downstream,
    )?;
    validate_assignments(&contract.requirement_assignments, &review, &downstream)?;

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
    let mut planned = BTreeSet::new();
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
                    planned.insert(key);
                }
            }
        }
    }

    let mut assigned = BTreeSet::new();
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
            if reviewed.get(&key).map(String::as_str) != Some("planned") {
                return Err(format!(
                    "assignment is not a planned review {}#{}#{profile}",
                    assignment.requirement, assignment.clause
                ));
            }
        }
    }
    if assigned != planned {
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
