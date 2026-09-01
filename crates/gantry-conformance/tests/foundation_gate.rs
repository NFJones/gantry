//! Independent validation of the Phase 0 foundation evidence index.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/foundation-v1.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    prerequisites: Vec<Prerequisite>,
    lifecycle_resolution: LifecycleResolution,
    requirements: RequirementSummary,
    next_profile: NextProfile,
    publication_skeleton: PublicationSummary,
    dependencies: DependencySummary,
    artifacts: Vec<FileDigest>,
    evidence_suites: Vec<EvidenceSuite>,
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
struct LifecycleResolution {
    requirement: String,
    status: String,
    body_sha256: String,
    clause_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementSummary {
    path: String,
    sha256: String,
    requirement_count: usize,
    clause_count: usize,
    section14_excerpt_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NextProfile {
    name: String,
    applicable_clause_count: usize,
    review_states: Vec<String>,
    implementation_complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationSummary {
    path: String,
    sha256: String,
    required_artifact_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencySummary {
    ledger_path: String,
    ledger_sha256: String,
    product_lockfile_sha256: String,
    fuzz_lockfile_sha256: String,
    decision_count: usize,
    selected_count: usize,
    rejected_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSuite {
    id: String,
    kind: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    phase: String,
    profiles: Vec<String>,
    permits_profile_implementation: bool,
    advertises_profile: bool,
}

#[derive(Debug, Deserialize)]
struct RequirementInventory {
    specification_sha256: String,
    requirements: Vec<Requirement>,
    section14_excerpts: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    body_sha256: String,
    clauses: Vec<Clause>,
}

#[derive(Debug, Deserialize)]
struct Clause {
    profiles: Vec<String>,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct PublicationSkeleton {
    required_artifact_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DependencyLedger {
    decisions: Vec<DependencyDecision>,
}

#[derive(Debug, Deserialize)]
struct DependencyDecision {
    status: String,
}

#[test]
fn checked_in_foundation_evidence_is_current_and_makes_no_profile_claim() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn foundation_validator_rejects_stale_artifacts_and_profile_overclaiming() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    let result = validate_manifest(&root, &stale);
    assert!(matches!(result, Err(message) if message.contains("artifact digest differs")));

    let mut overclaim = manifest;
    overclaim.claim.profiles.push("frontend".to_owned());
    overclaim.claim.advertises_profile = true;
    let result = validate_manifest(&root, &overclaim);
    assert!(matches!(result, Err(message) if message.contains("must not claim a profile")));
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.foundation-evidence/v1"
        || manifest.gate != "GNT-GATE-000"
        || manifest.status != "verified"
    {
        return Err("foundation manifest identity or status is invalid".to_owned());
    }
    if manifest.claim.phase != "phase-0-contract-foundation"
        || !manifest.claim.permits_profile_implementation
        || manifest.claim.advertises_profile
        || !manifest.claim.profiles.is_empty()
    {
        return Err("foundation gate must not claim a profile".to_owned());
    }
    if manifest.next_profile.name != "frontend" || !manifest.next_profile.implementation_complete {
        return Err("next-profile classification overstates implementation".to_owned());
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
    let expected_artifacts = expected_artifacts();
    let actual_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<Vec<_>>();
    if actual_artifacts != expected_artifacts {
        return Err("foundation artifact set is incomplete or unexpected".to_owned());
    }
    for artifact in &manifest.artifacts {
        validate_file_digest(root, artifact, "artifact")?;
    }
    validate_file_digest(root, &manifest.specification, "specification")?;

    validate_requirements(root, manifest)?;
    validate_publication(root, manifest)?;
    validate_dependencies(root, manifest)?;

    validate_sorted_unique(
        "evidence suite ids",
        manifest
            .evidence_suites
            .iter()
            .map(|suite| suite.id.as_str()),
    )?;
    for suite in &manifest.evidence_suites {
        if suite.kind.trim().is_empty() || !root.join(&suite.path).is_file() {
            return Err(format!("evidence suite is invalid: {}", suite.id));
        }
    }
    validate_sorted_unique(
        "validation commands",
        manifest.validation_commands.iter().map(String::as_str),
    )?;
    if manifest
        .validation_commands
        .iter()
        .any(|command| command.trim().is_empty())
    {
        return Err("validation commands contain an empty entry".to_owned());
    }
    if manifest.environment_gaps
        != [
            "The exact Rust 1.97.1 and rolling stable macOS product lanes are declared in CI and require a hosted macOS runner.",
        ]
    {
        return Err("environment gaps are stale or overbroad".to_owned());
    }
    Ok(())
}

fn validate_commit(root: &Path, prerequisite: &Prerequisite) -> Result<(), String> {
    if prerequisite.commit.len() != 40
        || !prerequisite
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || prerequisite.subject.trim().is_empty()
    {
        return Err(format!(
            "invalid prerequisite record: {}",
            prerequisite.issue
        ));
    }
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
    if !subject.status.success()
        || String::from_utf8_lossy(&subject.stdout).trim_end() != prerequisite.subject
    {
        return Err(format!(
            "prerequisite subject differs: {}",
            prerequisite.issue
        ));
    }
    Ok(())
}

fn validate_requirements(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.requirements.path != "protocol/requirements/generated/requirements-v1.json" {
        return Err("requirement inventory path is invalid".to_owned());
    }
    validate_file_digest(
        root,
        &FileDigest {
            path: manifest.requirements.path.clone(),
            sha256: manifest.requirements.sha256.clone(),
        },
        "requirement inventory",
    )?;
    let inventory: RequirementInventory = read_json(&root.join(&manifest.requirements.path));
    let clause_count = inventory
        .requirements
        .iter()
        .map(|requirement| requirement.clauses.len())
        .sum::<usize>();
    if inventory.specification_sha256 != manifest.specification.sha256
        || inventory.requirements.len() != manifest.requirements.requirement_count
        || clause_count != manifest.requirements.clause_count
        || inventory.section14_excerpts.len() != manifest.requirements.section14_excerpt_count
    {
        return Err("requirement inventory summary differs".to_owned());
    }

    let lifecycle = inventory
        .requirements
        .iter()
        .find(|requirement| requirement.id == manifest.lifecycle_resolution.requirement)
        .ok_or_else(|| "resolved lifecycle requirement is absent".to_owned())?;
    if manifest.lifecycle_resolution.requirement != "GNT-3-M-LIFECYCLES"
        || manifest.lifecycle_resolution.status != "resolved"
        || lifecycle.body_sha256 != manifest.lifecycle_resolution.body_sha256
        || lifecycle.clauses.len() != manifest.lifecycle_resolution.clause_count
        || lifecycle.clauses.is_empty()
    {
        return Err("lifecycle resolution evidence differs".to_owned());
    }

    let frontend = inventory
        .requirements
        .iter()
        .flat_map(|requirement| &requirement.clauses)
        .filter(|clause| clause.profiles.iter().any(|profile| profile == "frontend"))
        .collect::<Vec<_>>();
    let states = frontend
        .iter()
        .filter_map(|clause| {
            clause
                .profile_reviews
                .iter()
                .find(|review| review.profile == "frontend")
                .map(|review| review.state.as_str())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if frontend.len() != manifest.next_profile.applicable_clause_count
        || states != manifest.next_profile.review_states
    {
        return Err("next-profile clause classification differs".to_owned());
    }
    Ok(())
}

fn validate_publication(root: &Path, manifest: &Manifest) -> Result<(), String> {
    validate_file_digest(
        root,
        &FileDigest {
            path: manifest.publication_skeleton.path.clone(),
            sha256: manifest.publication_skeleton.sha256.clone(),
        },
        "publication skeleton",
    )?;
    let publication: PublicationSkeleton =
        read_json(&root.join(&manifest.publication_skeleton.path));
    if publication.required_artifact_ids != manifest.publication_skeleton.required_artifact_ids {
        return Err("publication skeleton artifact ids differ".to_owned());
    }
    validate_sorted_unique(
        "publication artifact ids",
        manifest
            .publication_skeleton
            .required_artifact_ids
            .iter()
            .map(String::as_str),
    )
}

fn validate_dependencies(root: &Path, manifest: &Manifest) -> Result<(), String> {
    validate_file_digest(
        root,
        &FileDigest {
            path: manifest.dependencies.ledger_path.clone(),
            sha256: manifest.dependencies.ledger_sha256.clone(),
        },
        "dependency ledger",
    )?;
    if sha256_file(&root.join("Cargo.lock"))? != manifest.dependencies.product_lockfile_sha256
        || sha256_file(&root.join("fuzz/Cargo.lock"))? != manifest.dependencies.fuzz_lockfile_sha256
    {
        return Err("dependency lockfile digest differs".to_owned());
    }
    let ledger: DependencyLedger = read_json(&root.join(&manifest.dependencies.ledger_path));
    let selected = ledger
        .decisions
        .iter()
        .filter(|decision| decision.status == "selected")
        .count();
    let rejected = ledger
        .decisions
        .iter()
        .filter(|decision| decision.status == "rejected")
        .count();
    if ledger.decisions.len() != manifest.dependencies.decision_count
        || selected != manifest.dependencies.selected_count
        || rejected != manifest.dependencies.rejected_count
        || selected + rejected != ledger.decisions.len()
    {
        return Err("dependency decision summary differs".to_owned());
    }
    Ok(())
}

fn validate_file_digest(root: &Path, file: &FileDigest, label: &str) -> Result<(), String> {
    if file.sha256.len() != 64 || sha256_file(&root.join(&file.path))? != file.sha256 {
        return Err(format!("{label} digest differs: {}", file.path));
    }
    Ok(())
}

fn validate_sorted_unique<'a>(
    name: &str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), String> {
    let values = values.collect::<Vec<_>>();
    let ordered = values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if values != ordered {
        return Err(format!("{name} must be sorted and unique"));
    }
    Ok(())
}

fn expected_artifacts() -> Vec<&'static str> {
    vec![
        ".github/workflows/ci.yml",
        "Cargo.lock",
        "Cargo.toml",
        "Justfile",
        "SPEC.md",
        "crates/gantry-adapter-tokio/Cargo.toml",
        "crates/gantry-analysis/Cargo.toml",
        "crates/gantry-conformance/tests/analyzer_gate.rs",
        "crates/gantry-conformance/tests/analyzer_lowering.rs",
        "crates/gantry-conformance/tests/analyzer_symbols.rs",
        "crates/gantry-conformance/tests/analyzer_types.rs",
        "crates/gantry-conformance/tests/analyzer_validity_model.rs",
        "crates/gantry-conformance/tests/analyzer_workflow_facts.rs",
        "crates/gantry-conformance/tests/combined_gate.rs",
        "crates/gantry-conformance/tests/combined_refinement.rs",
        "crates/gantry-conformance/tests/concurrent_executor.rs",
        "crates/gantry-conformance/tests/concurrent_gate.rs",
        "crates/gantry-conformance/tests/concurrent_handle_ownership.rs",
        "crates/gantry-conformance/tests/concurrent_lifecycle.rs",
        "crates/gantry-conformance/tests/concurrent_refinement_model.rs",
        "crates/gantry-conformance/tests/concurrent_task_state.rs",
        "crates/gantry-conformance/tests/durable_events.rs",
        "crates/gantry-conformance/tests/durable_gate.rs",
        "crates/gantry-conformance/tests/durable_recovery.rs",
        "crates/gantry-conformance/tests/durable_start.rs",
        "crates/gantry-conformance/tests/executor_services.rs",
        "crates/gantry-conformance/tests/interpreter_lifecycle.rs",
        "crates/gantry-conformance/tests/ir_contracts.rs",
        "crates/gantry-conformance/tests/journal_storage.rs",
        "crates/gantry-conformance/tests/persistent_values.rs",
        "crates/gantry-conformance/tests/sequential_gate.rs",
        "crates/gantry-conformance/tests/sequential_machine.rs",
        "crates/gantry-conformance/tests/sequential_refinement_model.rs",
        "crates/gantry-conformance/tests/validate_package.rs",
        "crates/gantry-conformance/tests/value_kernel.rs",
        "crates/gantry-core/src/generated/portable.rs",
        "crates/gantry-core/src/generated/profiles.rs",
        "crates/gantry-core/src/generated/unicode.rs",
        "crates/gantry-host/src/generated/embedding.rs",
        "crates/gantry-ir/Cargo.toml",
        "crates/gantry-ir/src/generated/contracts.rs",
        "crates/gantry-runtime/Cargo.toml",
        "deny.toml",
        "docs/analyzer-package-validity.md",
        "docs/concurrent-evaluator-refinement.md",
        "docs/sequential-evaluator-refinement.md",
        "fuzz/Cargo.lock",
        "governance/dependency-ledger-v1.json",
        "governance/fixtures/negative-policy-v1.json",
        "protocol/catalogs/embedding-contracts-v1.json",
        "protocol/catalogs/ir-contracts-v1.json",
        "protocol/catalogs/portable-contracts-v1.json",
        "protocol/catalogs/profiles-v1.json",
        "protocol/conformance/analyzer-gate-v1.json",
        "protocol/conformance/analyzer-ir-v1.json",
        "protocol/conformance/analyzer-lowering-v1.json",
        "protocol/conformance/analyzer-package-v1.json",
        "protocol/conformance/analyzer-symbols-v1.json",
        "protocol/conformance/analyzer-types-v1.json",
        "protocol/conformance/analyzer-validity-v1.json",
        "protocol/conformance/analyzer-workflows-v1.json",
        "protocol/conformance/combined-gate-v1.json",
        "protocol/conformance/concurrent-executor-v1.json",
        "protocol/conformance/concurrent-gate-v1.json",
        "protocol/conformance/concurrent-handle-ownership-v1.json",
        "protocol/conformance/concurrent-lifecycle-v1.json",
        "protocol/conformance/concurrent-refinement-v1.json",
        "protocol/conformance/concurrent-task-state-v1.json",
        "protocol/conformance/durable-events-v1.json",
        "protocol/conformance/durable-gate-v1.json",
        "protocol/conformance/durable-recovery-v1.json",
        "protocol/conformance/durable-start-v1.json",
        "protocol/conformance/executor-services-v1.json",
        "protocol/conformance/interpreter-lifecycle-v1.json",
        "protocol/conformance/journal-storage-v1.json",
        "protocol/conformance/persistent-values-v1.json",
        "protocol/conformance/sequential-evaluator-refinement-v1.json",
        "protocol/conformance/sequential-gate-v1.json",
        "protocol/conformance/sequential-machine-v1.json",
        "protocol/conformance/value-kernel-v1.json",
        "protocol/goldens/activity-observation-vectors-v1.json",
        "protocol/goldens/analyzer-validity-model-v1.json",
        "protocol/goldens/concurrent-executor-model-v1.json",
        "protocol/goldens/concurrent-lifecycle-v1.json",
        "protocol/goldens/concurrent-refinement-model-v1.json",
        "protocol/goldens/diagnostic-machine-v1.json",
        "protocol/goldens/diagnostic-presentation-v1.json",
        "protocol/goldens/durable-events-v1.json",
        "protocol/goldens/durable-recovery-v1.json",
        "protocol/goldens/durable-start-v1.json",
        "protocol/goldens/embedding-contracts-v1.canonical.json",
        "protocol/goldens/embedding-envelope-negatives-v1.json",
        "protocol/goldens/executor-services-v1.json",
        "protocol/goldens/ir-artifact-vectors-v1.json",
        "protocol/goldens/ir-contracts-v1.canonical.json",
        "protocol/goldens/journal-storage-v1.json",
        "protocol/goldens/package-service-vectors-v1.json",
        "protocol/goldens/persistent-values-v1.json",
        "protocol/goldens/portable-contract-vectors-v1.json",
        "protocol/goldens/portable-contracts-v1.canonical.json",
        "protocol/goldens/profiles-v1.canonical.json",
        "protocol/goldens/sequential-evaluator-model-v1.json",
        "protocol/goldens/sequential-machine-v1.json",
        "protocol/goldens/source-substrate-vectors-v1.json",
        "protocol/goldens/unicode-version-vectors-v1.json",
        "protocol/goldens/value-kernel-v1.json",
        "protocol/publication/artifacts-v1.json",
        "protocol/requirements/generated/requirements-v1.json",
        "protocol/requirements/reviewed-v1.json",
        "protocol/requirements/section14-v1.json",
        "protocol/schemas/activity-observation-v1.schema.json",
        "protocol/schemas/canonical-ir-v1.schema.json",
        "protocol/schemas/concurrent-executor-model-v1.schema.json",
        "protocol/schemas/concurrent-lifecycle-v1.schema.json",
        "protocol/schemas/concurrent-refinement-model-v1.schema.json",
        "protocol/schemas/durable-events-v1.schema.json",
        "protocol/schemas/durable-recovery-v1.schema.json",
        "protocol/schemas/durable-start-v1.schema.json",
        "protocol/schemas/embedding-contracts-v1.schema.json",
        "protocol/schemas/executor-services-v1.schema.json",
        "protocol/schemas/generated-schema-object-v1.schema.json",
        "protocol/schemas/journal-storage-v1.schema.json",
        "protocol/schemas/package-services-v1.schema.json",
        "protocol/schemas/package-source-manifest-v1.schema.json",
        "protocol/schemas/persistent-values-v1.schema.json",
        "protocol/schemas/portable-contracts-v1.schema.json",
        "protocol/schemas/profile-catalog-v1.schema.json",
        "protocol/schemas/sequential-machine-v1.schema.json",
        "protocol/schemas/source-map-v1.schema.json",
        "protocol/schemas/source-substrate-v1.schema.json",
        "protocol/schemas/value-kernel-v1.schema.json",
        "rust-toolchain.toml",
        "third_party/unicode/16.0.0/LICENSE",
        "third_party/unicode/16.0.0/SHA256SUMS",
        "third_party/unicode/16.0.0/SOURCES",
    ]
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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
