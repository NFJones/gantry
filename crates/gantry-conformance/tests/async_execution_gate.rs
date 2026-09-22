//! Narrow evidence gate for portable executor-backed root execution.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use gantry::host::contracts::{
    ExecutorAdapter, HookOutcomeV1, HostError, IdentitySource, InclusiveJitterRange, JitterSource,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::portable::{PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, ExecutionSnapshot, InterpreterConfiguration, MachineOutcome,
    RequiredConfiguration,
};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{Interpreter, StartExecutionRequest, StartExecutionResult};
use gantry_adapter_tokio::TokioExecutor;
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use gantry_conformance::scripted::{ScriptedHook, ScriptedIntegration, ScriptedPreflight};
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::runtime::{Builder, Runtime};

const MANIFEST_PATH: &str = "protocol/conformance/async-execution-gate-v1.json";
const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
/// Digest of the derived frozen assignment rows of `CONTRACT_PATH`, not of its bytes.
const ASSIGNMENT_SHA256: &str = "23ee16c35e5981c680c97d8a8fa0d7ce33485f90bb7da49c9f3c0f0d6d889102";
const ARTIFACTS: [(&str, &str); 19] = [
    (
        "crates/gantry-conformance/tests/source_spawn.rs",
        "85cd772a6fce8d79c15b8fa46ec07b33803aa6988f424b8cb99a6f4a7d873ed0",
    ),
    (
        "protocol/conformance/async-cancellation-v1.json",
        "bbc4c0ff1ce986b2f331249f1917a86292c77533aa5c7e44142816e11080012e",
    ),
    (
        "protocol/conformance/async-execution-contract-v1.json",
        "0a419ac6fa3e54f4337992c25c398e0c0b532df0b8f12d30497c5530a0bd7364",
    ),
    (
        "protocol/conformance/async-execution-observation-v1.json",
        "3098518562abc8288d22691711d3ca786147f6ec808c8d63ddf5d1bf2fc997ee",
    ),
    (
        "protocol/conformance/automatic-durable-root-v1.json",
        "b5ca66a48d87adb4fa4c9d24e3d482125e67edfbdd8b8b2cd5876bf9edfed334",
    ),
    (
        "protocol/conformance/automatic-root-start-v1.json",
        "80c36c5b53c437e3deb239118dd2d5e95b856c6850a8e436b8c65d800e66db61",
    ),
    (
        "protocol/conformance/durable-recovery-v1.json",
        "9c0f58f40f7747361216c44c7fd8b60a3f6ba206fc56ead33b4e0d9fb30fe904",
    ),
    (
        "protocol/conformance/durable-start-v1.json",
        "1a5c8b7bbf92ec6799bf1bec91b07f806d6e4ba2f85f12e080eb4547f0369398",
    ),
    (
        "protocol/conformance/execution-api-v1.json",
        "4e7e20a9b239bbb58732705b6d2a13bba886a7bb54066a048b6cfcecada5abcd",
    ),
    (
        "protocol/conformance/execution-coordinator-v1.json",
        "5e4c5cafe0ed5fecbc5ea280e3eff7687a79b66984b67d08671187e64eaacaf3",
    ),
    (
        "protocol/conformance/executor-services-v1.json",
        "d95c70c0d11464bcecc4d121700ba90fbe72293fe41c55b73ea33655c81a25ef",
    ),
    (
        "protocol/conformance/interpreter-lifecycle-v1.json",
        "fdda39d8ccf697ca3f07b9631cf2eabccf9cf86d431f9a295b4611188a46d569",
    ),
    (
        "protocol/conformance/interpreter-ownership-v1.json",
        "f4a210e1773406d603e6e3849116976214e12f1d4f81ae9c1c1b5297480983fb",
    ),
    (
        "protocol/conformance/revent-ownership-v1.json",
        "433767f101846e1c7e15efea13f753bfa9fa5cef71c7b4488c8f0dcc2cd9653c",
    ),
    (
        "protocol/conformance/runtime-sessions-v1.json",
        "9fbebf120016a9e66cfb558c0001999317285e6261685b08a8438537a68001c4",
    ),
    (
        "protocol/conformance/source-spawn-v1.json",
        "9c8d63ba152968d33f2f804df02529297c3b69b6edf66c678504e0ba2982eed4",
    ),
    (
        "protocol/conformance/task-driver-v1.json",
        "bc31b707465b1e961857209c837c519391322aeb871367653cddf15a27b54856",
    ),
    (
        "protocol/conformance/task-supervision-v1.json",
        "f64c5ac95fe13819dd538f9939faa6c685368c5699ed77a8d0b146dc579ba083",
    ),
    (
        "protocol/conformance/tokio-executor-v1.json",
        "5dd4bf36301b67799e92d5fed61070bd31eccdfeb9d09acc12098f135fe9eb29",
    ),
];
const EVIDENCE: [(&str, &str); 21] = [
    (
        "adapter-behavior",
        "crates/gantry-conformance/tests/scripted_integration.rs#scripted_adapter_exercises_preflight_hook_and_cancellation_contracts",
    ),
    (
        "api-privacy",
        "crates/gantry-conformance/tests/external_facade_matrix.rs#legacy_execution_surface_is_unavailable_to_external_consumers",
    ),
    (
        "automatic-durable-root",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#resumed_root_stays_gated_until_atomic_acceptance_then_completes_automatically",
    ),
    (
        "automatic-root",
        "crates/gantry-conformance/tests/automatic_root_start.rs#independently_accepted_roots_make_executor_owned_progress",
    ),
    (
        "cancellation",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#facade_cancellation_of_a_running_durable_root_commits_before_signalling",
    ),
    (
        "coordinator",
        "crates/gantry-conformance/tests/execution_coordinator.rs#task_settlement_and_completion_publish_before_waiter_notification",
    ),
    (
        "driver",
        "crates/gantry-conformance/tests/task_driver.rs#driver_yields_and_supervision_observes_physical_completion_after_semantic_settlement",
    ),
    (
        "durable-commit",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#accepted_durable_root_runs_on_the_executor_and_commits_before_observation",
    ),
    (
        "durable-failure",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#durable_commit_failure_reports_run_failure_and_preserves_sequence_one",
    ),
    (
        "event-barrier",
        "crates/gantry-conformance/tests/revent_ownership.rs#nondurable_root_events_keep_semantic_order_after_start_and_await_observers_drop",
    ),
    (
        "executor-services",
        "crates/gantry-conformance/tests/executor_services.rs#checked_in_executor_evidence_is_narrow_and_current",
    ),
    (
        "immediate-poll",
        "crates/gantry-conformance/tests/automatic_root_start.rs#immediate_executor_poll_cannot_cross_the_accepted_root_gate",
    ),
    (
        "lifecycle",
        "crates/gantry-conformance/tests/interpreter_lifecycle.rs#shutdown_races_transfer_admission_and_snapshot_first_durations",
    ),
    (
        "ownership",
        "crates/gantry-conformance/tests/interpreter_ownership.rs#dropped_shutdown_waiter_does_not_abandon_the_unique_coordinator",
    ),
    (
        "resume-rollback",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#resume_executor_rejection_rolls_back_and_releases_the_owner_once",
    ),
    (
        "resume-terminal",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#terminal_resume_accepts_without_submitting_a_root_driver",
    ),
    (
        "runtime-portability",
        "crates/gantry-conformance/tests/tokio_executor.rs#caller_owned_runtime_matrix_keeps_runnable_work_making_progress",
    ),
    (
        "session",
        "crates/gantry-conformance/tests/runtime_sessions.rs#concurrent_runtime_session_waiters_share_one_must_settle_success",
    ),
    (
        "shutdown",
        "crates/gantry-conformance/tests/automatic_durable_root.rs#facade_shutdown_cancels_a_running_durable_root_only_after_commit",
    ),
    (
        "start-failure",
        "crates/gantry-conformance/tests/automatic_root_start.rs#post_acceptance_submission_failure_returns_accepted_and_settles_the_root",
    ),
    (
        "supervision",
        "crates/gantry-conformance/tests/task_supervision.rs#semantic_settlement_retains_capacity_until_physical_reaping",
    ),
];
const EXCLUSIONS: [&str; 5] = [
    "blocking-isolation",
    "cli-policy",
    "full-task-graph-recovery",
    "profile-publication",
    "source-child-concurrency",
];
const VALIDATION_COMMANDS: [&str; 33] = [
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test async_cancellation",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test async_contract_gate",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test async_execution_gate",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test automatic_durable_root",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test automatic_root_start",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test conformance_publication",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test durable_events",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test durable_recovery",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test durable_start",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test execution_coordinator",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test executor_services",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test external_facade_matrix",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test interpreter_lifecycle",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test interpreter_ownership",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test logical_sessions",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test revent_ownership",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test runtime_sessions",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test scripted_integration",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test source_spawn",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test source_spawn_tokio",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test task_driver",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test task_supervision",
    "timeout 120s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test tokio_executor",
    "timeout 120s rustup run 1.97.1 cargo fmt --all --check",
    "timeout 300s rustup run 1.97.1 cargo check --locked --workspace --all-targets --all-features",
    "timeout 300s rustup run 1.97.1 cargo clippy --locked -p gantry-conformance --test async_execution_gate -- -D warnings",
    "timeout 600s rustup run 1.97.1 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
    "timeout 900s rustup run 1.97.1 cargo test --locked --workspace --all-targets --all-features --no-fail-fast",
    "timeout 120s rustup run 1.97.1 cargo run --locked -p xtask -- check governance",
    "timeout 900s python3 release/verify-package-set.py",
    "timeout 120s rustup run 1.97.1 cargo run --locked -p xtask -- check generated",
    "timeout 120s rustup run 1.97.1 cargo run --locked -p xtask -- check workspace",
    "timeout 120s git diff --check",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification_sha256: String,
    prerequisites: Vec<Prerequisite>,
    assignment_authentication: AssignmentAuthentication,
    artifacts: Vec<FileDigest>,
    required_evidence: Vec<Evidence>,
    portable_root_outcomes: PortableRootOutcomes,
    claim: Claim,
    validation_commands: Vec<String>,
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
    evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableRootOutcomes {
    executors: Vec<String>,
    crosses: Vec<String>,
    compares_only: String,
    equivalence: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    excludes_capabilities: Vec<String>,
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

#[derive(Debug)]
struct FixedJitter;

impl JitterSource for FixedJitter {
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-async-execution-gate-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(
            path.join("main.gnt"),
            "agents { worker }\ndefault agent = worker;\nfn main() { session(fork) { discard prompt \"First\" -> String; discard prompt \"Second\" -> String; } }",
        )
            .unwrap_or_else(|error| panic!("could not write root fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn checked_in_async_execution_gate_authenticates_only_frozen_narrow_evidence() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn async_execution_gate_rejects_mutated_prerequisites_assignments_evidence_and_claims() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut prerequisite = manifest.clone();
    prerequisite.prerequisites[0].commit = "0".repeat(40);
    assert!(validate_manifest(&root, &prerequisite).is_err());

    let mut assignment = manifest.clone();
    assignment.assignment_authentication.profile_row_count -= 1;
    assert!(validate_manifest(&root, &assignment).is_err());

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut missing_surface = manifest.clone();
    missing_surface.artifacts.pop();
    assert!(validate_manifest(&root, &missing_surface).is_err());

    let mut incomplete = manifest.clone();
    incomplete.required_evidence.pop();
    assert!(validate_manifest(&root, &incomplete).is_err());

    let mut unbounded_validation = manifest.clone();
    unbounded_validation.validation_commands.pop();
    assert!(validate_manifest(&root, &unbounded_validation).is_err());

    let mut broadened_portability = manifest.clone();
    broadened_portability
        .portable_root_outcomes
        .executors
        .push("unsupported-runtime".to_owned());
    assert!(validate_manifest(&root, &broadened_portability).is_err());

    let mut overclaimed_portability = manifest.clone();
    overclaimed_portability.portable_root_outcomes.compares_only =
        "all scheduler and graph behavior".to_owned();
    assert!(validate_manifest(&root, &overclaimed_portability).is_err());

    let mut overclaimed = manifest.clone();
    overclaimed.claim.profiles.push("embedding".to_owned());
    assert!(validate_manifest(&root, &overclaimed).is_err());

    let mut broadened = manifest;
    broadened.claim.excludes_capabilities.pop();
    assert!(validate_manifest(&root, &broadened).is_err());
}

#[test]
fn deterministic_and_tokio_runtimes_produce_the_same_portable_root_outcome() {
    let deterministic = deterministic_outcome();
    let current_thread = tokio_outcome(current_thread_runtime());
    let multi_thread = tokio_outcome(multithread_runtime());

    assert_eq!(current_thread.foreground, deterministic.foreground);
    assert_eq!(current_thread.terminal, deterministic.terminal);
    assert_eq!(multi_thread.foreground, deterministic.foreground);
    assert_eq!(multi_thread.terminal, deterministic.terminal);
    assert_eq!(
        deterministic.foreground.as_ref(),
        deterministic
            .terminal
            .as_ref()
            .map(|terminal| &terminal.foreground)
    );
    assert!(matches!(
        deterministic
            .terminal
            .as_ref()
            .map(|terminal| &terminal.foreground),
        Some(MachineOutcome::Succeeded(_))
    ));
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.async-execution-evidence-gate/v1"
        || manifest.gate != "GNT-ASYNC-GATE-100"
        || manifest.status != "verified"
    {
        return Err("async execution gate identity or status is invalid".to_owned());
    }
    if manifest.specification_sha256 != sha256(&read(root.join("SPEC.md"))?) {
        return Err("async execution gate uses another specification".to_owned());
    }
    validate_prerequisites(root, &manifest.prerequisites)?;
    validate_artifacts(root, &manifest.artifacts)?;
    validate_assignments(root, &manifest.assignment_authentication)?;

    let evidence = manifest
        .required_evidence
        .iter()
        .map(|record| (record.category.as_str(), record.evidence.as_str()))
        .collect::<Vec<_>>();
    if evidence != EVIDENCE {
        return Err("required root evidence is incomplete or broadened".to_owned());
    }
    for record in &manifest.required_evidence {
        assert_anchor_exists(root, &record.evidence)?;
    }

    if manifest.portable_root_outcomes.executors
        != [
            "deterministic",
            "tokio-current-thread",
            "tokio-multi-thread",
        ]
        || manifest.portable_root_outcomes.crosses
            != [
                "executor-yield",
                "runtime-session-establishment",
                "host-operation-dispatch",
            ]
        || manifest.portable_root_outcomes.compares_only
            != "portable foreground and terminal outcomes"
        || manifest.portable_root_outcomes.equivalence
            != "crates/gantry-conformance/tests/async_execution_gate.rs#deterministic_and_tokio_runtimes_produce_the_same_portable_root_outcome"
    {
        return Err("portable root outcome matrix is incomplete".to_owned());
    }
    assert_anchor_exists(root, &manifest.portable_root_outcomes.equivalence)?;

    if !manifest.claim.profiles.is_empty()
        || !manifest.claim.advertises_profiles.is_empty()
        || manifest.claim.excludes_capabilities != EXCLUSIONS
    {
        return Err("narrow gate overclaims capabilities or profile publication".to_owned());
    }
    if manifest
        .validation_commands
        .iter()
        .map(String::as_str)
        .ne(VALIDATION_COMMANDS)
    {
        return Err("focused validation commands are incomplete".to_owned());
    }
    Ok(())
}

fn validate_prerequisites(root: &Path, prerequisites: &[Prerequisite]) -> Result<(), String> {
    const EXPECTED: [(&str, &str, &str); 3] = [
        (
            "GNT-ASYNC-API-001",
            "b5b7ec5832e10698d01ff21dd20de540ba446d3f",
            "Replace manual driving with observation APIs",
        ),
        (
            "GNT-ASYNC-REVENT-001",
            "199d8f0d76a1ee2d1082325ae5ab7dae4cc6ab5a",
            "Own sequential event delivery barriers",
        ),
        (
            "GNT-ASYNC-TOKIO-001",
            "6eeba18a52e7df31599996acf433d4575100961a",
            "Qualify Tokio executor semantics.",
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
        return Err("async execution prerequisites differ".to_owned());
    }
    for prerequisite in prerequisites {
        let ancestor = Command::new("git")
            .current_dir(root)
            .args(["merge-base", "--is-ancestor", &prerequisite.commit, "HEAD"])
            .status()
            .map_err(|error| format!("could not inspect prerequisite ancestry: {error}"))?;
        if !ancestor.success() {
            return Err(format!(
                "prerequisite is not resolved: {}",
                prerequisite.issue
            ));
        }
        let output = Command::new("git")
            .current_dir(root)
            .args(["show", "-s", "--format=%s", &prerequisite.commit])
            .output()
            .map_err(|error| format!("could not inspect prerequisite subject: {error}"))?;
        let subject = String::from_utf8(output.stdout)
            .map_err(|error| format!("prerequisite subject is not UTF-8: {error}"))?;
        if subject.trim_end() != prerequisite.subject {
            return Err(format!(
                "prerequisite subject differs: {}",
                prerequisite.issue
            ));
        }
    }
    Ok(())
}

fn validate_artifacts(root: &Path, artifacts: &[FileDigest]) -> Result<(), String> {
    if artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.sha256.as_str()))
        .ne(ARTIFACTS)
    {
        return Err("async execution artifact set differs".to_owned());
    }
    for artifact in artifacts {
        if artifact.sha256 != sha256(&read(root.join(&artifact.path))?) {
            return Err(format!("stale async execution artifact: {}", artifact.path));
        }
    }
    Ok(())
}

fn validate_assignments(
    root: &Path,
    authentication: &AssignmentAuthentication,
) -> Result<(), String> {
    if authentication.contract != CONTRACT_PATH
        || authentication.owner != "GNT-ASYNC-GATE-100"
        || authentication.assignment_count != 18
        || authentication.profile_row_count != 48
        || authentication.sha256 != ASSIGNMENT_SHA256
    {
        return Err("assignment authentication record differs".to_owned());
    }
    let contract: Contract = read_json_result(&root.join(&authentication.contract))?;
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
    let mut rows = Vec::new();
    for assignment in &assignments {
        for profile in &assignment.profiles {
            rows.push(format!(
                "{}#{}#{}#{}\n",
                assignment.requirement,
                assignment.clause,
                profile,
                assignment.evidence_owners.join(",")
            ));
        }
    }
    rows.sort();
    if assignments.len() != authentication.assignment_count
        || rows.len() != authentication.profile_row_count
        || sha256(rows.concat().as_bytes()) != authentication.sha256
    {
        return Err("GNT-ASYNC-GATE-100 frozen assignment rows differ".to_owned());
    }
    Ok(())
}

fn deterministic_outcome() -> ExecutionSnapshot {
    let root = TempDirectory::new();
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let adapter: Arc<dyn ExecutorAdapter> = executor.clone();
    let (interpreter, integration) = interpreter(adapter);
    let accepted = block_on("deterministic root start", start_root(&interpreter, &root));
    let handle = accepted.handle().clone();
    drop(accepted);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut polls = 0_u64;
    while Instant::now() < deadline {
        polls = polls.saturating_add(1);
        match executor
            .poll_task(0)
            .unwrap_or_else(|error| panic!("deterministic root poll failed: {error:?}"))
        {
            DeterministicTaskPoll::Pending | DeterministicTaskPoll::NotRunnable => {
                std::thread::yield_now();
            }
            DeterministicTaskPoll::Settled(_) => {
                assert!(
                    executor.yields() > 0,
                    "portable root crossed no executor yield"
                );
                assert_portable_boundaries(&integration);
                return block_on(
                    "deterministic terminal observation",
                    interpreter.await_terminal(&handle),
                )
                .unwrap_or_else(|error| panic!("deterministic observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("deterministic root disappeared"));
            }
            other => panic!("deterministic root settled abnormally: {other:?}"),
        }
    }
    panic!(
        "deterministic root exceeded the 5s gate deadline after {polls} polls and {} yields",
        executor.yields()
    )
}

fn tokio_outcome(runtime: Runtime) -> ExecutionSnapshot {
    let root = TempDirectory::new();
    let adapter: Arc<dyn ExecutorAdapter> = Arc::new(TokioExecutor::new(
        runtime.handle().clone(),
        Arc::new(FixedJitter),
    ));
    let (interpreter, integration) = interpreter(adapter);
    runtime.block_on(async {
        let snapshot = tokio::time::timeout(Duration::from_secs(5), async {
            let accepted = start_root(&interpreter, &root).await;
            let handle = accepted.handle().clone();
            drop(accepted);
            interpreter
                .await_terminal(&handle)
                .await
                .unwrap_or_else(|error| panic!("Tokio observation failed: {error:?}"))
                .unwrap_or_else(|| panic!("Tokio root disappeared"))
        })
        .await
        .unwrap_or_else(|_| panic!("Tokio root exceeded the 5s gate deadline"));
        assert_portable_boundaries(&integration);
        snapshot
    })
}

async fn start_root(
    interpreter: &Interpreter,
    root: &TempDirectory,
) -> gantry::StartExecutionAccepted {
    let selection = selection();
    let request = StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    };
    let StartExecutionResult::Accepted(accepted) = interpreter.start_execution(request).await
    else {
        panic!("portable root fixture was rejected")
    };
    *accepted
}

fn interpreter(executor: Arc<dyn ExecutorAdapter>) -> (Interpreter, Arc<ScriptedIntegration>) {
    let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=96).map(|byte| Ok([byte; 32])),
    ));
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            256, 65_536, 1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    let configuration = InterpreterConfiguration::new(
        executor,
        identities,
        required,
        AsyncCapacityLimits::new(1, 8, 8, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    );
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([
            Ok(HookOutcomeV1::Completed(Arc::from(&br#""one""#[..]))),
            Ok(HookOutcomeV1::Completed(Arc::from(&br#""two""#[..]))),
        ])],
    ));
    let interpreter = Interpreter::new(
        configuration,
        Arc::new(DeterministicUtcClock::new((1_u32..=96).map(timestamp))),
        integration.clone(),
        integration.clone(),
        integration.clone(),
    );
    (interpreter, integration)
}

fn assert_portable_boundaries(integration: &ScriptedIntegration) {
    let operations = integration
        .calls()
        .iter()
        .map(|call| call.operation)
        .collect::<Vec<_>>();
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == EmbeddingOperation::ResolveMappings)
            .count(),
        1
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == EmbeddingOperation::EstablishSession)
            .count(),
        2
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == EmbeddingOperation::CreateHook)
            .count(),
        1
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == EmbeddingOperation::DispatchOperation)
            .count(),
        2
    );
}

fn selection() -> ProtocolSelection {
    ProtocolSelection::new(
        PORTABLE_SPECIFICATION_REVISION,
        PROTOCOL_FAMILY_DEFINITIONS
            .iter()
            .map(|definition| SelectedProtocol {
                family: definition.family,
                version: ProtocolVersion {
                    major: definition.major,
                    minor: definition.minor,
                },
            })
            .collect(),
    )
    .unwrap_or_else(|error| panic!("selection failed: {error}"))
}

fn timestamp(microseconds: u32) -> Result<UtcTimestamp, HostError> {
    UtcTimestamp::from_unix_seconds(0, microseconds).map_err(|_| HostError {
        code: Arc::from("clock-invariant"),
        protected_diagnostic: None,
    })
}

fn current_thread_runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("current-thread runtime construction failed: {error}"))
}

fn multithread_runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap_or_else(|error| panic!("multi-thread runtime construction failed: {error}"))
}

fn assert_anchor_exists(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, anchor) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence has no anchor: {evidence}"))?;
    let source = fs::read_to_string(root.join(path))
        .map_err(|error| format!("could not read evidence {path}: {error}"))?;
    if !source.contains(&format!("fn {anchor}(")) {
        return Err(format!("evidence anchor is missing: {evidence}"));
    }
    Ok(())
}

fn block_on<F: Future>(operation: &str, future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut polls = 0_u64;
    while Instant::now() < deadline {
        polls = polls.saturating_add(1);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    panic!("{operation} exceeded the 5s gate deadline after {polls} polls")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
    let path = path.as_ref();
    fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    read_json_result(path).unwrap_or_else(|error| panic!("{error}"))
}

fn read_json_result<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&read(path)?)
        .map_err(|error| format!("could not decode {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
