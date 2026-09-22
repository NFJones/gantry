//! Independent aggregate validation for executor-backed async conformance evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/async-execution-conformance-v1.json";
const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
/// Digest of the derived assignment rows of `CONTRACT_PATH`, not of its bytes.
const ASSIGNMENT_SHA256: &str = "878398b1881eaa6ace6e8e9ab9d07775557a3e3202c5e5e52167c1d68c6bf347";
const PREREQUISITES: [(&str, &str, &str, &str, &str); 5] = [
    (
        "GNT-ASYNC-BLOCK-001",
        "3892895c41d1f8290e97da09ce32260c51a1d74d",
        "Isolate package work behind bounded blocking admission.",
        "protocol/conformance/blocking-work-v1.json",
        "cdd0df384eaf3c1cafc01ff3169b553ec6f66820f854a2c07e9bd4cbfeb1c1b9",
    ),
    (
        "GNT-ASYNC-CLI-001",
        "98d91f33e6206688a5354dc7d5260dbc1afaf5d6",
        "Adopt multithread CLI runtime policy",
        "protocol/conformance/cli-runtime-policy-v1.json",
        "22655383cf5e40aa2acfdb695b391591e015217c8fedeb55e7c31df584992470",
    ),
    (
        "GNT-ASYNC-GATE-200",
        "a6915ef212b9e245da00fd383f79bc81f05c3556",
        "Close the native source concurrency evidence gate.",
        "protocol/conformance/native-source-concurrency-gate-v1.json",
        "f2e8f6b0ad3eeaa5212f5bacfe1a2f5210fc3a7160b78447f3caa0a1d5d38810",
    ),
    (
        "GNT-ASYNC-PROOF-001",
        "ca413e8e23f714e33d72511a74f02a2eeccc4032",
        "Compose async execution refinements",
        "protocol/conformance/async-execution-refinement-v1.json",
        "8dec394c7b2ccd30967c6596bad2c788766030dc7156616395dad2a5761c21c5",
    ),
    (
        "GNT-ASYNC-REC-001",
        "d5d34c22107d8f16739b21baf6a0f6f773de276a",
        "Qualify executor-backed recovery",
        "protocol/conformance/async-recovery-v1.json",
        "a0f41c210dbf4f18e87409febc33cc3827dd2c27ab740f551cd660bcf791e62e",
    ),
];
const ARTIFACTS: [(&str, &str); 8] = [
    (
        ".github/workflows/ci.yml",
        "21db3502f3ed0da4dad7211f4af3dbeb5b7bfaa29e55be1c6f9493e4bd6aa1d8",
    ),
    (
        "protocol/catalogs/profiles-v1.json",
        "d36e7ddbc6c82701395809a0dd80196d0bfa789576d66d28e9ab4ac79446231f",
    ),
    (
        "protocol/conformance/async-execution-adoption-v1.json",
        "a494b37dcc5473784960032d369b0850d33c68839121f270b44d5da6a5e91527",
    ),
    (
        "protocol/conformance/async-execution-contract-v1.json",
        "0688a94e5de87f79e01ae8510d3e785e9c1a2e00dae43d39404199469fbc86dc",
    ),
    (
        "protocol/conformance/async-execution-gate-v1.json",
        "4492adb187323b77a06f2b0270bdb7c01a8a1aafef3e35fffec249da1693f0b2",
    ),
    (
        "protocol/goldens/concurrent-refinement-model-v1.json",
        "b1dece7db1454e50db4ac3f55ed770c2ff511b4ed5a66f31f96c190d5c6adb27",
    ),
    (
        "protocol/goldens/durable-refinement-model-v1.json",
        "621d7c89e236fde9c7353e40750e848f4899d1e86cad15c2f493e90730efb966",
    ),
    (
        "protocol/goldens/sequential-evaluator-model-v1.json",
        "c461c9eeb0883fe746d9405faae9ca6cf07eefa26c0c506a82d593a0fc9de7f4",
    ),
];
const EVIDENCE: [(&str, &str); 17] = [
    (
        "admission-async-atomic",
        "crates/gantry-conformance/tests/async_admission.rs#public_admission_batches_are_atomic_nonblocking_and_boundary_typed",
    ),
    (
        "admission-async-policy",
        "crates/gantry-conformance/tests/async_admission.rs#public_async_capacities_are_explicit_positive_operational_policy",
    ),
    (
        "admission-control-reserve",
        "crates/gantry-conformance/tests/async_admission.rs#public_cleanup_reserve_survives_ordinary_saturation",
    ),
    (
        "blocking-admission",
        "crates/gantry-conformance/tests/blocking_work.rs#bounded_blocking_work_is_nonblocking_cancellable_and_retained_to_settlement",
    ),
    (
        "blocking-worker-isolation",
        "crates/gantry-conformance/tests/blocking_work.rs#package_jobs_are_owned_separate_deterministic_and_do_not_starve_timers",
    ),
    (
        "cancellation",
        "crates/gantry-conformance/tests/concurrent_lifecycle.rs#public_cancellation_abort_terminal_and_shutdown_cohorts_are_exact",
    ),
    (
        "event-fault",
        "crates/gantry-conformance/tests/durable_events.rs#public_delivery_crash_cuts_preserve_retry_budget_and_terminal_settlement",
    ),
    (
        "event-order",
        "crates/gantry-conformance/tests/concurrent_lifecycle.rs#public_concurrent_events_are_canonical_typed_and_causal",
    ),
    (
        "facade-feature-matrix",
        "crates/gantry-conformance/tests/external_facade_matrix.rs#every_supported_feature_combination_builds_for_an_external_consumer",
    ),
    (
        "lifecycle",
        "crates/gantry-conformance/tests/task_supervision.rs#semantic_settlement_retains_capacity_until_physical_reaping",
    ),
    (
        "portable-root-outcomes",
        "crates/gantry-conformance/tests/async_execution_gate.rs#deterministic_and_tokio_runtimes_produce_the_same_portable_root_outcome",
    ),
    (
        "recovery-fault",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#resume_revision_commit_failure_times_out_abort_resistant_rollback",
    ),
    (
        "recovery-fencing",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#fenced_resume_rejects_a_live_superseded_root_publish",
    ),
    (
        "shutdown-fault",
        "crates/gantry-conformance/tests/tokio_executor.rs#runtime_shutdown_reports_structured_task_and_service_failures",
    ),
    (
        "tokio-fault",
        "crates/gantry-conformance/tests/tokio_executor.rs#abort_drop_panic_and_stale_wakes_settle_once",
    ),
    (
        "tokio-runtime-matrix",
        "crates/gantry-conformance/tests/tokio_executor.rs#caller_owned_runtime_matrix_keeps_runnable_work_making_progress",
    ),
    (
        "worker-count-independent-recovery",
        "crates/gantry-conformance/tests/source_spawn_tokio.rs#durable_resume_preserves_identities_and_budgets_across_worker_count_changes",
    ),
];
const MODEL_EVIDENCE: [&str; 3] = [
    "crates/gantry-conformance/tests/concurrent_refinement_model.rs#bounded_concurrent_refinement_model_and_counterexamples_replay",
    "crates/gantry-conformance/tests/durable_refinement_model.rs#bounded_durable_refinement_model_and_counterexamples_replay",
    "crates/gantry-conformance/tests/sequential_refinement_model.rs#bounded_sequential_refinement_model_and_counterexamples_replay",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    issue: String,
    status: String,
    specification_sha256: String,
    prerequisites: Vec<Prerequisite>,
    assignment_authentication: AssignmentAuthentication,
    artifacts: Vec<FileDigest>,
    evidence: Vec<Evidence>,
    portable_outcomes: PortableOutcomes,
    worker_policy: WorkerPolicy,
    bounded_validation: BoundedValidation,
    ci: CiEvidence,
    adoption: AdoptionEvidence,
    environment_gaps: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prerequisite {
    issue: String,
    commit: String,
    subject: String,
    artifact: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentAuthentication {
    contract: String,
    owner: String,
    assignment_count: usize,
    profile_row_count: usize,
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
struct Evidence {
    category: String,
    anchor: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableOutcomes {
    executors: Vec<String>,
    compares_only: String,
    scheduler_claims: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerPolicy {
    cli_runtime: String,
    worker_counts: Vec<String>,
    semantic_identity: bool,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedValidation {
    models: Vec<String>,
    stress: StressEvidence,
    limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StressEvidence {
    iterations: usize,
    base_seed: String,
    selector: String,
    current_thread: String,
    multi_thread: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiEvidence {
    workflow: String,
    linux_rust: Vec<String>,
    macos_rust: Vec<String>,
    scope: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionEvidence {
    path: String,
    status: String,
    required_blockers: Vec<String>,
    claims_enabled: bool,
    advertises_profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Contract {
    requirement_assignments: Vec<Assignment>,
}

#[derive(Debug, Deserialize)]
struct Assignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AdoptionGate {
    status: String,
    advertises_profiles: Vec<String>,
    blocked_by: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProfileCatalog {
    claims_enabled: bool,
}

#[test]
fn checked_in_async_execution_conformance_is_current_and_narrow() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn async_execution_conformance_rejects_assignment_prerequisite_digest_anchor_and_claim_mutations() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut assignment = manifest.clone();
    assignment.assignment_authentication.assignment_count -= 1;
    assert!(validate_manifest(&root, &assignment).is_err());

    let mut prerequisite = manifest.clone();
    prerequisite.prerequisites[0].commit = "0".repeat(40);
    assert!(validate_manifest(&root, &prerequisite).is_err());

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut anchor = manifest.clone();
    anchor.evidence[0].anchor.push_str("_missing");
    assert!(validate_manifest(&root, &anchor).is_err());

    let mut unbounded = manifest.clone();
    unbounded.portable_outcomes.scheduler_claims = true;
    assert!(validate_manifest(&root, &unbounded).is_err());

    let mut withdrawn = manifest;
    withdrawn.adoption.claims_enabled = false;
    withdrawn.adoption.advertises_profiles.clear();
    assert!(validate_manifest(&root, &withdrawn).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.async-execution-conformance-evidence/v1"
        || manifest.issue != "GNT-ASYNC-CONF-001"
        || manifest.status != "verified"
        || manifest.specification_sha256 != sha256(&read(root.join("SPEC.md"))?)
    {
        return Err("aggregate identity, status, or specification differs".to_owned());
    }
    validate_prerequisites(root, &manifest.prerequisites)?;
    validate_assignments(root, &manifest.assignment_authentication)?;
    validate_artifacts(root, &manifest.artifacts)?;
    validate_evidence(root, manifest)?;
    validate_adoption(root, &manifest.adoption)?;
    validate_ci(root, &manifest.ci)?;
    if manifest.environment_gaps.len() != 3
        || !manifest
            .environment_gaps
            .iter()
            .any(|gap| gap.contains("macOS"))
        || !manifest
            .environment_gaps
            .iter()
            .any(|gap| gap.contains("not exhaustive"))
        || manifest.exclusions.len() != 3
        || !manifest
            .exclusions
            .iter()
            .any(|gap| gap.contains("GNT-ASYNC-REL-001") && gap.contains("qualified Linux"))
        || !manifest
            .exclusions
            .iter()
            .any(|gap| gap.contains("macOS") && gap.contains("stable-media"))
    {
        return Err("aggregate qualifications are incomplete".to_owned());
    }
    Ok(())
}

fn validate_prerequisites(root: &Path, prerequisites: &[Prerequisite]) -> Result<(), String> {
    if prerequisites
        .iter()
        .map(|entry| {
            (
                entry.issue.as_str(),
                entry.commit.as_str(),
                entry.subject.as_str(),
                entry.artifact.as_str(),
                entry.sha256.as_str(),
            )
        })
        .ne(PREREQUISITES)
    {
        return Err("aggregate prerequisites differ".to_owned());
    }
    for prerequisite in prerequisites {
        let ancestor = Command::new("git")
            .current_dir(root)
            .args(["merge-base", "--is-ancestor", &prerequisite.commit, "HEAD"])
            .status()
            .map_err(|error| error.to_string())?;
        if !ancestor.success() {
            return Err(format!(
                "prerequisite is not an ancestor: {}",
                prerequisite.issue
            ));
        }
        let subject = Command::new("git")
            .current_dir(root)
            .args(["show", "-s", "--format=%s", &prerequisite.commit])
            .output()
            .map_err(|error| error.to_string())?;
        if String::from_utf8(subject.stdout)
            .map_err(|error| error.to_string())?
            .trim_end()
            != prerequisite.subject
        {
            return Err(format!(
                "prerequisite subject differs: {}",
                prerequisite.issue
            ));
        }
        validate_digest(root, &prerequisite.artifact, &prerequisite.sha256)?;
        let value: serde_json::Value = read_json(&root.join(&prerequisite.artifact));
        if value["issue"] != prerequisite.issue && value["gate"] != prerequisite.issue {
            return Err(format!(
                "prerequisite artifact owner differs: {}",
                prerequisite.issue
            ));
        }
        if value["specification_sha256"] != manifest_specification(root)? {
            return Err(format!(
                "prerequisite specification differs: {}",
                prerequisite.issue
            ));
        }
    }
    Ok(())
}

fn validate_assignments(
    root: &Path,
    authentication: &AssignmentAuthentication,
) -> Result<(), String> {
    if authentication.contract != CONTRACT_PATH
        || authentication.owner != "GNT-ASYNC-CONF-001"
        || authentication.assignment_count != 28
        || authentication.profile_row_count != 65
        || authentication.sha256 != ASSIGNMENT_SHA256
    {
        return Err("assignment authentication record differs".to_owned());
    }
    let contract: Contract = read_json(&root.join(CONTRACT_PATH));
    let assignments = contract
        .requirement_assignments
        .iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == &authentication.owner)
        })
        .collect::<Vec<_>>();
    let mut rows = assignments
        .iter()
        .flat_map(|assignment| {
            assignment.profiles.iter().map(move |profile| {
                format!(
                    "{}#{}#{}#{}\n",
                    assignment.requirement,
                    assignment.clause,
                    profile,
                    assignment.evidence_owners.join(",")
                )
            })
        })
        .collect::<Vec<_>>();
    rows.sort();
    if assignments.len() != authentication.assignment_count
        || rows.len() != authentication.profile_row_count
        || sha256(rows.concat().as_bytes()) != authentication.sha256
    {
        return Err("GNT-ASYNC-CONF-001 assignment rows differ".to_owned());
    }
    Ok(())
}

fn validate_artifacts(root: &Path, artifacts: &[FileDigest]) -> Result<(), String> {
    if artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.sha256.as_str()))
        .ne(ARTIFACTS)
    {
        return Err("selected aggregate artifact set differs".to_owned());
    }
    for artifact in artifacts {
        validate_digest(root, &artifact.path, &artifact.sha256)?;
    }
    Ok(())
}

fn validate_evidence(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest
        .evidence
        .iter()
        .map(|entry| (entry.category.as_str(), entry.anchor.as_str()))
        .ne(EVIDENCE)
    {
        return Err("aggregate evidence matrix differs".to_owned());
    }
    for anchor in manifest
        .evidence
        .iter()
        .map(|entry| entry.anchor.as_str())
        .chain(
            manifest
                .bounded_validation
                .models
                .iter()
                .map(String::as_str),
        )
        .chain([
            manifest.worker_policy.evidence.as_str(),
            manifest.bounded_validation.stress.current_thread.as_str(),
            manifest.bounded_validation.stress.multi_thread.as_str(),
        ])
    {
        validate_anchor(root, anchor)?;
    }
    if manifest.portable_outcomes.executors
        != [
            "deterministic",
            "tokio-current-thread",
            "tokio-multi-thread",
        ]
        || manifest.portable_outcomes.compares_only != "portable foreground and terminal outcomes"
        || manifest.portable_outcomes.scheduler_claims
        || manifest.worker_policy.cli_runtime != "tokio-multi-thread"
        || manifest.worker_policy.worker_counts != ["default", "1", "2", "4"]
        || manifest.worker_policy.semantic_identity
        || manifest.bounded_validation.models != MODEL_EVIDENCE
        || manifest.bounded_validation.stress.iterations != 32
        || manifest.bounded_validation.stress.base_seed != "0x6a09e667f3bcc909"
        || manifest.bounded_validation.stress.selector != "GANTRY_SOURCE_STRESS_ITERATION"
        || manifest.bounded_validation.limitations.len() != 2
        || !manifest
            .bounded_validation
            .limitations
            .iter()
            .any(|limit| limit.contains("not an unbounded proof"))
        || !manifest
            .bounded_validation
            .limitations
            .iter()
            .any(|limit| limit.contains("not schedule replay"))
    {
        return Err("portable, worker, model, or stress evidence differs".to_owned());
    }
    Ok(())
}

fn validate_adoption(root: &Path, evidence: &AdoptionEvidence) -> Result<(), String> {
    let adoption: AdoptionGate = read_json(&root.join(&evidence.path));
    let profiles: ProfileCatalog = read_json(&root.join("protocol/catalogs/profiles-v1.json"));
    if evidence.path != "protocol/conformance/async-execution-adoption-v1.json"
        || evidence.status != "verified"
        || !evidence.required_blockers.is_empty()
        || !evidence.claims_enabled
        || evidence.advertises_profiles
            != [
                "analyzer",
                "concurrent-evaluator",
                "durable-runtime",
                "embedding",
                "evaluator",
                "frontend",
            ]
        || adoption.status != evidence.status
        || adoption.advertises_profiles != evidence.advertises_profiles
        || adoption.blocked_by != evidence.required_blockers
        || !profiles.claims_enabled
        || !gantry::PROFILE_CLAIMS_ENABLED
        || !gantry::advertises_any_profile()
    {
        return Err("aggregate adoption is incomplete or overstates profiles".to_owned());
    }
    Ok(())
}

fn validate_ci(root: &Path, ci: &CiEvidence) -> Result<(), String> {
    if ci.workflow != ".github/workflows/ci.yml"
        || ci.linux_rust != ["1.91.0", "1.97.1", "stable"]
        || ci.macos_rust != ["1.97.1", "stable"]
        || ci.scope
            != "shared product matrix with workspace all-target all-feature build, lint, and tests"
    {
        return Err("CI evidence matrix differs".to_owned());
    }
    let workflow =
        fs::read_to_string(root.join(&ci.workflow)).map_err(|error| error.to_string())?;
    for needle in [
        "os: ubuntu-latest",
        "os: macos-latest",
        "cargo build --locked --workspace --all-targets --all-features",
        "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
        "cargo test --locked --workspace --all-targets --all-features --no-fail-fast",
    ] {
        if !workflow.contains(needle) {
            return Err(format!("CI workflow omits {needle}"));
        }
    }
    Ok(())
}

fn validate_anchor(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, anchor) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence has no anchor: {evidence}"))?;
    let source = fs::read_to_string(root.join(path)).map_err(|error| error.to_string())?;
    if !source.contains(&format!("fn {anchor}(")) {
        return Err(format!("evidence anchor is missing: {evidence}"));
    }
    Ok(())
}

fn validate_digest(root: &Path, path: &str, expected: &str) -> Result<(), String> {
    let actual = sha256(&read(root.join(path))?);
    if actual != expected {
        return Err(format!("artifact digest differs: {path}"));
    }
    Ok(())
}

fn manifest_specification(root: &Path) -> Result<String, String> {
    Ok(sha256(&read(root.join("SPEC.md"))?))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read(path: PathBuf) -> Result<Vec<u8>, String> {
    fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))
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
