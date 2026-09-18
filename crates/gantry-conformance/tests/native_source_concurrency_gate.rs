//! Independent evidence-only closeout for native executor-backed source tasks.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/native-source-concurrency-gate-v1.json";
const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
const JOIN_MANIFEST_PATH: &str = "protocol/conformance/source-join-v1.json";
const LOWER_MANIFEST_PATH: &str = "protocol/conformance/async-source-lowering-v1.json";
/// Digest of the derived frozen assignment rows of `CONTRACT_PATH`, not of its bytes.
const ASSIGNMENT_SHA256: &str = "74faddf1d9144d541328a5393dc8d96016a9c91b6240d3fcef4c194b46e4e17e";
const EXCLUSIONS: [&str; 5] = [
    "adapter-owned-runtime",
    "cli-multithread-default",
    "full-frozen-clause-coverage",
    "profile-publication",
    "recovered-runnable-task-graph-replacement",
];
const PREREQUISITES: [(&str, &str, &str); 9] = [
    (
        "GNT-ASYNC-IR-001",
        "5f27fec62e18d2286a01c7b50620b14dc5c7c11c",
        "Define executable task-control IR.",
    ),
    (
        "GNT-ASYNC-LOWER-001",
        "b91ac8143ecf9847d927126e6ea05b03426bfb9c",
        "Lower concurrent source into independent executable task bodies.",
    ),
    (
        "GNT-ASYNC-DUR-001",
        "2797f52467ac839c74b0048c0d530de156d4902d",
        "Record durable coordination requirements and verification.",
    ),
    (
        "GNT-ASYNC-SPAWN-001",
        "828f07df6e8c201a315f35acbf159af50669750b",
        "Schedule native source child tasks.",
    ),
    (
        "GNT-ASYNC-JOIN-001",
        "3e8937fc15c9ec11eefb305cf92acce310b469ff",
        "Implement all-settled source joins and detach.",
    ),
    (
        "GNT-ASYNC-CANCEL-001",
        "cb92fd5069615bec6709551dc7627dc736c39ddc",
        "Complete source task cancellation and shutdown.",
    ),
    (
        "GNT-ASYNC-OBS-001",
        "d189345ec35a41d0461cdad2e51ec0e5d106e5a8",
        "Linearize parallel event delivery and barriers.",
    ),
    (
        "GNT-ASYNC-MODEL-001",
        "a06785fc970dff378cfe214068941b8f8e45c51f",
        "Model and stress native coordinator semantics.",
    ),
    (
        "GNT-ASYNC-TOKIO-001",
        "6eeba18a52e7df31599996acf433d4575100961a",
        "Qualify Tokio executor semantics.",
    ),
];
const ARTIFACTS: [(&str, &str); 14] = [
    (
        "crates/gantry-conformance/tests/async_source_lowering.rs",
        "c1cdb2d90a8ee4f2377e3fd3505dfa7af03d5b410961baafc5f4659fadbbd73c",
    ),
    (
        "crates/gantry-conformance/tests/executable_bridge.rs",
        "78cb612b3f389a07663eda682c3cae0a30aa6e4fc282f1e021f86cabe4921e0d",
    ),
    (
        "crates/gantry-conformance/tests/source_spawn.rs",
        "85cd772a6fce8d79c15b8fa46ec07b33803aa6988f424b8cb99a6f4a7d873ed0",
    ),
    (
        "crates/gantry-conformance/tests/source_spawn_tokio.rs",
        "d07c3c7c8ea16515bb3e69404eb55ca9eef2c2c2ffc203b0d2c76c3c48f325d3",
    ),
    (
        "protocol/conformance/async-cancellation-v1.json",
        "86764b641e321834e54a90462a1d0c1cb9ef8e149c9a5915d8287fcc36be7249",
    ),
    (
        "protocol/conformance/async-coordinator-model-v1.json",
        "e1e60f7617a01f5416b7563bc28c3f352057cfdb3e5ead0e34fc2efdd1e0451d",
    ),
    (
        "protocol/conformance/async-execution-contract-v1.json",
        "c9c81f9cfdd5c1cc52afb29c8f46b6fdb0d81cd00eb833b43e4b8e12cffe8601",
    ),
    (
        "protocol/conformance/async-execution-observation-v1.json",
        "d788df2084c6477d44d0a1a42cb86ad516b30298962c15511330cdbe0c629603",
    ),
    (
        "protocol/conformance/async-source-lowering-v1.json",
        "3b83bb90a9a07f3501fcc6a9f150d67663eebd335ed249fed8f13c3c950340bb",
    ),
    (
        "protocol/conformance/durable-coordination-v1.json",
        "92ceb453abb8fc63f825cdf4c9163244c0ca91114825e958c71af8ced2401106",
    ),
    (
        "protocol/conformance/executable-task-ir-v1.json",
        "85c911fde17b45dee5854283518ec1d48e1d518d0bc9609388dde60af1334053",
    ),
    (
        "protocol/conformance/source-join-v1.json",
        "c30e4b6f20e53948a64c2c5419ac920e06b4ac2c9c85e4d7a1f809b1084348ea",
    ),
    (
        "protocol/conformance/source-spawn-v1.json",
        "f8699e3718a4d45c24dd352a864ec991f4d6ebaa2c8214d0e269913ee1dcb62e",
    ),
    (
        "protocol/conformance/tokio-executor-v1.json",
        "f917b09613a69ffe6ad33ec178cf46fdaf118ff187fa53fe2f36d73b27f83063",
    ),
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
    native_source_matrix: NativeSourceMatrix,
    production_audit: ProductionAudit,
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
struct NativeSourceMatrix {
    executors: Vec<String>,
    behaviors: Vec<String>,
    compares_only: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionAudit {
    round_robin_role: String,
    production_child_polling: String,
    owned_future_markers: Vec<SourceMarker>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMarker {
    path: String,
    needle: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    #[serde(default)]
    implementation: Option<Implementation>,
    requirements: Vec<NestedRequirement>,
    artifacts: Vec<FileDigest>,
    capabilities: Vec<NestedCapability>,
    #[serde(default)]
    claim: Option<NestedClaim>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Implementation {
    commit: String,
    subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct NestedRequirement {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedCapability {
    id: String,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedClaim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    assignment_scope: String,
    full_clause_coverage: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    assignment_scope: String,
    full_clause_coverage: bool,
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

#[test]
fn checked_in_native_source_concurrency_gate_authenticates_nested_evidence() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(validate_manifest(&root, &manifest), Ok(()));
}

#[test]
fn native_source_concurrency_gate_rejects_tampering_and_overclaiming() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut blocked = manifest.clone();
    blocked.status = "blocked".to_owned();
    assert!(validate_manifest(&root, &blocked).is_err());

    let mut prerequisite = manifest.clone();
    prerequisite.prerequisites[0].commit = "0".repeat(40);
    assert!(validate_manifest(&root, &prerequisite).is_err());

    let mut assignment = manifest.clone();
    assignment.assignment_authentication.assignment_count -= 1;
    assert!(validate_manifest(&root, &assignment).is_err());

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut missing_evidence = manifest.clone();
    missing_evidence.required_evidence.pop();
    assert!(validate_manifest(&root, &missing_evidence).is_err());

    let mut broadened_matrix = manifest.clone();
    broadened_matrix
        .native_source_matrix
        .executors
        .push("adapter-owned-runtime".to_owned());
    assert!(validate_manifest(&root, &broadened_matrix).is_err());

    let join: NestedManifest = read_json(&root.join(JOIN_MANIFEST_PATH));
    let mut stale_join = join.clone();
    stale_join.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_join_manifest(&root, &stale_join).is_err());

    let mut incomplete_join = join;
    incomplete_join.capabilities.pop();
    assert!(validate_join_manifest(&root, &incomplete_join).is_err());

    let lowering: NestedManifest = read_json(&root.join(LOWER_MANIFEST_PATH));
    let mut reassigned_lowering = lowering.clone();
    reassigned_lowering.requirements.pop();
    assert!(validate_lowering_manifest(&root, &reassigned_lowering).is_err());

    let mut overclaimed_lowering = lowering;
    if let Some(claim) = overclaimed_lowering.claim.as_mut() {
        claim
            .advertises_profiles
            .push("concurrent-evaluator".to_owned());
    }
    assert!(validate_lowering_manifest(&root, &overclaimed_lowering).is_err());

    let mut weakened_lowering: NestedManifest = read_json(&root.join(LOWER_MANIFEST_PATH));
    weakened_lowering.exclusions.pop();
    assert!(validate_lowering_manifest(&root, &weakened_lowering).is_err());

    let mut profile_overclaim = manifest.clone();
    profile_overclaim
        .claim
        .advertises_profiles
        .push("concurrent-evaluator".to_owned());
    assert!(validate_manifest(&root, &profile_overclaim).is_err());

    let mut clause_overclaim = manifest.clone();
    clause_overclaim.claim.full_clause_coverage = true;
    assert!(validate_manifest(&root, &clause_overclaim).is_err());

    let mut recovery_overclaim = manifest;
    recovery_overclaim.claim.excludes_capabilities.pop();
    assert!(validate_manifest(&root, &recovery_overclaim).is_err());
}

#[test]
fn production_source_tasks_use_owned_futures_without_round_robin_child_polling() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert_eq!(
        validate_production_audit(&root, &manifest.production_audit),
        Ok(())
    );
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.native-source-concurrency-gate-evidence/v1"
        || manifest.gate != "GNT-ASYNC-GATE-200"
        || manifest.status != "verified"
    {
        return Err("native source concurrency gate identity or status differs".to_owned());
    }
    if manifest.specification_sha256 != sha256(&read(root.join("SPEC.md"))?) {
        return Err("native source concurrency gate uses another specification".to_owned());
    }
    validate_prerequisites(root, &manifest.prerequisites)?;
    validate_assignments(root, &manifest.assignment_authentication)?;
    validate_artifacts(root, &manifest.artifacts)?;
    validate_evidence(root, &manifest.required_evidence)?;
    validate_matrix(&manifest.native_source_matrix)?;
    validate_production_audit(root, &manifest.production_audit)?;
    let join = read_json_result(&root.join(JOIN_MANIFEST_PATH))?;
    validate_join_manifest(root, &join)?;
    let lowering = read_json_result(&root.join(LOWER_MANIFEST_PATH))?;
    validate_lowering_manifest(root, &lowering)?;
    validate_claim(&manifest.claim)?;
    validate_commands(&manifest.validation_commands)?;
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
            )
        })
        .ne(PREREQUISITES)
    {
        return Err("native source prerequisite provenance differs".to_owned());
    }
    for prerequisite in prerequisites {
        let ancestor = Command::new("git")
            .current_dir(root)
            .args(["merge-base", "--is-ancestor", &prerequisite.commit, "HEAD"])
            .status()
            .map_err(|error| format!("could not inspect prerequisite ancestry: {error}"))?;
        if !ancestor.success() {
            return Err(format!(
                "prerequisite is not an ancestor: {}",
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

fn validate_assignments(
    root: &Path,
    authentication: &AssignmentAuthentication,
) -> Result<(), String> {
    if authentication.contract != CONTRACT_PATH
        || authentication.owner != "GNT-ASYNC-GATE-200"
        || authentication.assignment_count != 13
        || authentication.profile_row_count != 30
        || authentication.sha256 != ASSIGNMENT_SHA256
    {
        return Err("frozen assignment authentication differs".to_owned());
    }
    let contract: Contract = read_json_result(&root.join(&authentication.contract))?;
    let assignments = contract
        .requirement_assignments
        .iter()
        .filter(|assignment| assignment.evidence_owners.contains(&authentication.owner))
        .collect::<Vec<_>>();
    let mut rows = assignments
        .iter()
        .flat_map(|assignment| {
            assignment.profiles.iter().map(|profile| {
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
        return Err("GNT-ASYNC-GATE-200 frozen assignment rows differ".to_owned());
    }
    Ok(())
}

fn validate_artifacts(root: &Path, artifacts: &[FileDigest]) -> Result<(), String> {
    if artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.sha256.as_str()))
        .ne(ARTIFACTS)
    {
        return Err("native source artifact set differs".to_owned());
    }
    for artifact in artifacts {
        if artifact.sha256 != sha256(&read(root.join(&artifact.path))?) {
            return Err(format!("stale native source artifact: {}", artifact.path));
        }
    }
    Ok(())
}

fn validate_evidence(root: &Path, evidence: &[Evidence]) -> Result<(), String> {
    const CATEGORIES: [&str; 23] = [
        "adapter-current-thread",
        "adapter-multithread",
        "adapter-owned-task-progress",
        "adapter-worker-migration",
        "cancellation-current-thread",
        "cancellation-multithread",
        "detach-observation",
        "durable-commit-order",
        "durable-spawn-publication",
        "empty-joinall",
        "ir-negative",
        "ir-task-bodies",
        "lowering-captures",
        "lowering-expression",
        "lowering-nested-bodies",
        "model",
        "native-owned-child",
        "observation-barrier",
        "shared-operation-budget",
        "stress-current-thread",
        "stress-multithread",
        "task-qualified-identity",
        "wake-driven-join",
    ];
    if evidence
        .iter()
        .map(|record| record.category.as_str())
        .ne(CATEGORIES)
    {
        return Err("native source evidence categories differ".to_owned());
    }
    let unique = evidence
        .iter()
        .map(|record| record.evidence.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() != evidence.len() {
        return Err("native source evidence anchors are duplicated".to_owned());
    }
    for record in evidence {
        assert_anchor_exists(root, &record.evidence)?;
    }
    Ok(())
}

fn validate_matrix(matrix: &NativeSourceMatrix) -> Result<(), String> {
    if matrix.executors
        != [
            "deterministic-reference",
            "tokio-current-thread",
            "tokio-multi-thread",
        ]
        || matrix.behaviors
            != [
                "typed-capture-isolation",
                "one-owned-future-per-source-task",
                "all-settled-join-order",
                "detach-foreground-terminal-split",
                "attached-descendant-drain",
                "event-delivery-barriers",
                "shared-budget-and-task-identity",
            ]
        || matrix.compares_only
            != "portable source-task outcomes and owned-task lifecycle boundaries"
    {
        return Err("native source executor and behavior matrix differs".to_owned());
    }
    Ok(())
}

fn validate_production_audit(root: &Path, audit: &ProductionAudit) -> Result<(), String> {
    const MARKERS: [(&str, &str); 5] = [
        ("crates/gantry/src/interpreter.rs", "fn from_child("),
        (
            "crates/gantry/src/interpreter.rs",
            "fn into_gated_owned_task(",
        ),
        (
            "crates/gantry-adapter-tokio/src/lib.rs",
            "fn spawn(&self, task: OwnedTaskFuture)",
        ),
        (
            "crates/gantry-runtime/src/coordinator.rs",
            "pub struct JoinSettlementWait",
        ),
        (
            "crates/gantry-runtime/src/supervision.rs",
            "fn enqueue(this: &Arc<Self>, id: u64)",
        ),
    ];
    if audit.round_robin_role != "deterministic/reference compatibility mechanism only"
        || audit.production_child_polling != "absent"
        || audit
            .owned_future_markers
            .iter()
            .map(|marker| (marker.path.as_str(), marker.needle.as_str()))
            .ne(MARKERS)
    {
        return Err("production source-task audit claim differs".to_owned());
    }
    for marker in &audit.owned_future_markers {
        let source = fs::read_to_string(root.join(&marker.path))
            .map_err(|error| format!("could not read {}: {error}", marker.path))?;
        if !source.contains(&marker.needle) {
            return Err(format!(
                "owned-future source marker is missing: {}",
                marker.path
            ));
        }
    }

    for directory in [
        "crates/gantry/src",
        "crates/gantry-runtime/src",
        "crates/gantry-adapter-tokio/src",
    ] {
        let mut files = Vec::new();
        collect_rust_files(&root.join(directory), &mut files)?;
        for path in files {
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            let test_module = source.find("mod tests {");
            let production = test_module.map_or(source.as_str(), |boundary| &source[..boundary]);
            if production.contains(".step_next(") {
                return Err(format!(
                    "production round-robin scheduler call found in {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn validate_join_manifest(root: &Path, manifest: &NestedManifest) -> Result<(), String> {
    const CAPABILITIES: [(&str, &str); 9] = [
        (
            "source-child-join-completion",
            "crates/gantry-conformance/tests/source_spawn.rs#native_child_submission_keeps_the_gate_closed_and_establishes_session_before_hook",
        ),
        (
            "source-child-join-rejection-failure",
            "crates/gantry-conformance/tests/source_spawn.rs#child_executor_rejection_settles_without_submitting_another_driver",
        ),
        (
            "source-named-join-all-settled-order",
            "crates/gantry-conformance/tests/source_spawn_tokio.rs#current_thread_tokio_named_join_preserves_selection_order_after_reverse_completion",
        ),
        (
            "source-joinall-all-settled-order",
            "crates/gantry-conformance/tests/source_spawn_tokio.rs#multithread_tokio_joinall_preserves_declaration_order_after_reverse_completion",
        ),
        (
            "source-empty-joinall-event",
            "crates/gantry-conformance/tests/source_spawn_tokio.rs#current_thread_tokio_empty_joinall_emits_memberless_join_event",
        ),
        (
            "source-aggregate-join-failure",
            "crates/gantry-conformance/tests/source_spawn_tokio.rs#multithread_tokio_join_failure_waits_for_all_selected_children",
        ),
        (
            "source-detach-foreground-terminal-split",
            "crates/gantry-conformance/tests/source_spawn_tokio.rs#current_thread_tokio_detach_separates_foreground_success_from_terminal_failure",
        ),
        (
            "durable-source-join-operation-cuts",
            "crates/gantry-conformance/tests/source_spawn.rs#durable_child_action_commits_ordered_operation_cuts",
        ),
        (
            "durable-detached-terminal-recovery",
            "crates/gantry-conformance/tests/source_spawn.rs#durable_detached_failures_survive_full_and_compacted_public_recovery",
        ),
    ];
    let expected_requirements = [
        nested_requirement("GNT-3-D-COMMIT-ORDER", &["durable-runtime"]),
        nested_requirement(
            "GNT-3-M-TASK-SETTLE",
            &["concurrent-evaluator", "durable-runtime", "evaluator"],
        ),
        nested_requirement("GNT-15.4-owned-work", &["embedding"]),
    ];
    let expected_exclusions = [
        "Cancellation or failure of an owner and the resulting descendant cancellation and draining remain owned by GNT-ASYNC-CANCEL-001.",
        "Recovered task-graph reconstruction, fencing, and runnable child resubmission remain owned by GNT-ASYNC-REC-001.",
        "The evidence does not broaden the sequential evaluator profile with spawned-task execution; source task control requires the concurrent evaluator and is combined with durability only when both refinements are enabled.",
    ];
    if manifest.format != "gantry.source-join-evidence/v1"
        || manifest.issue != "GNT-ASYNC-JOIN-001"
        || manifest.implementation.is_some()
        || manifest.claim.is_some()
        || manifest.exclusions != expected_exclusions
    {
        return Err("source JOIN evidence identity or scope differs".to_owned());
    }
    validate_nested_manifest(
        root,
        manifest,
        &expected_requirements,
        &[
            "crates/gantry-conformance/tests/source_spawn.rs",
            "crates/gantry-conformance/tests/source_spawn_tokio.rs",
        ],
        &CAPABILITIES,
    )
}

fn validate_lowering_manifest(root: &Path, manifest: &NestedManifest) -> Result<(), String> {
    const CAPABILITIES: [(&str, &str); 6] = [
        (
            "closed-generic-task-body-identity",
            "crates/gantry-conformance/tests/executable_bridge.rs#generic_task_bodies_have_closed_distinct_identities",
        ),
        (
            "independent-nested-task-bodies",
            "crates/gantry-conformance/tests/executable_bridge.rs#nested_task_bodies_preserve_captures_and_joinall_order",
        ),
        (
            "join-expression-lowering",
            "crates/gantry-conformance/tests/executable_bridge.rs#join_operand_preserves_surrounding_expression",
        ),
        (
            "retained-task-program-codec",
            "crates/gantry-conformance/tests/executable_bridge.rs#analyzed_task_program_round_trips_through_retained_codec",
        ),
        (
            "runtime-profile-rejection",
            "crates/gantry-conformance/tests/executable_bridge.rs#analyzed_concurrent_entry_reaches_the_existing_profile_rejection",
        ),
        (
            "typed-spawn-join-captures",
            "crates/gantry-conformance/tests/executable_bridge.rs#concurrent_source_lowers_spawn_join_and_typed_captures",
        ),
    ];
    let expected_requirements = [
        nested_requirement("GNT-3-M-SPAWN", &["concurrent-evaluator"]),
        nested_requirement("GNT-15.8", &["embedding"]),
    ];
    let expected_exclusions = [
        "This evidence does not claim runtime coordinator behavior, executor submission, native child scheduling, join settlement, detachment, or cancellation.",
        "The assigned GNT-3-M-SPAWN clause includes downstream runtime obligations that this lowering evidence does not cover.",
        "The assigned GNT-15.8 clause includes publication-set and full conformance-corpus obligations that this lowering evidence does not cover.",
        "This evidence publishes no analyzer, concurrent-evaluator, embedding, evaluator, or durable-runtime profile claim.",
    ];
    let implementation = manifest.implementation.as_ref();
    let claim = manifest.claim.as_ref();
    if manifest.format != "gantry.async-source-lowering-evidence/v1"
        || manifest.issue != "GNT-ASYNC-LOWER-001"
        || implementation.map(|value| value.commit.as_str()) != Some("b91ac8143ecf9847d927126e6ea05b03426bfb9c")
        || implementation.map(|value| value.subject.as_str()) != Some("Lower concurrent source into independent executable task bodies.")
        || claim.is_none_or(|value| !value.profiles.is_empty() || !value.advertises_profiles.is_empty() || value.full_clause_coverage || value.assignment_scope != "lowering-relevant slices of the exact frozen GNT-ASYNC-LOWER-001 assignments")
        || manifest.exclusions != expected_exclusions
    {
        return Err("source LOWER evidence identity or scope differs".to_owned());
    }
    validate_nested_manifest(
        root,
        manifest,
        &expected_requirements,
        &[
            "crates/gantry-analysis/src/bodies.rs",
            "crates/gantry-analysis/src/executable.rs",
            "crates/gantry-conformance/tests/executable_bridge.rs",
            CONTRACT_PATH,
        ],
        &CAPABILITIES,
    )
}

fn nested_requirement(requirement: &str, profiles: &[&str]) -> NestedRequirement {
    NestedRequirement {
        requirement: requirement.to_owned(),
        clause: "clause-001".to_owned(),
        profiles: profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    }
}

fn validate_nested_manifest(
    root: &Path,
    manifest: &NestedManifest,
    expected_requirements: &[NestedRequirement],
    expected_artifacts: &[&str],
    expected_capabilities: &[(&str, &str)],
) -> Result<(), String> {
    if manifest.specification_sha256 != sha256(&read(root.join("SPEC.md"))?) {
        return Err("nested evidence uses another specification".to_owned());
    }
    let contract: Contract = read_json_result(&root.join(CONTRACT_PATH))?;
    let mut assigned = contract
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == &manifest.issue)
        })
        .map(|assignment| NestedRequirement {
            requirement: assignment.requirement,
            clause: assignment.clause,
            profiles: assignment.profiles,
        })
        .collect::<Vec<_>>();
    assigned.sort();
    let mut declared = manifest.requirements.clone();
    declared.sort();
    let mut expected = expected_requirements.to_vec();
    expected.sort();
    if declared != assigned || declared != expected {
        return Err("nested evidence assignments differ".to_owned());
    }
    if manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .ne(expected_artifacts.iter().copied())
    {
        return Err("nested evidence artifact inventory differs".to_owned());
    }
    for artifact in &manifest.artifacts {
        if artifact.sha256 != sha256(&read(root.join(&artifact.path))?) {
            return Err(format!(
                "nested evidence artifact is stale: {}",
                artifact.path
            ));
        }
    }
    if manifest
        .capabilities
        .iter()
        .map(|capability| (capability.id.as_str(), capability.evidence.as_str()))
        .ne(expected_capabilities.iter().copied())
    {
        return Err("nested capability evidence differs".to_owned());
    }
    for capability in &manifest.capabilities {
        let (path, _) = capability
            .evidence
            .split_once('#')
            .ok_or_else(|| format!("evidence has no anchor: {}", capability.evidence))?;
        if !manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.path == path)
        {
            return Err(format!("nested evidence path is not authenticated: {path}"));
        }
        assert_anchor_exists(root, &capability.evidence)?;
    }
    Ok(())
}

fn validate_claim(claim: &Claim) -> Result<(), String> {
    if !claim.profiles.is_empty()
        || !claim.advertises_profiles.is_empty()
        || claim.assignment_scope
            != "only GNT-ASYNC-GATE-200-relevant slices of the 13 frozen assignments"
        || claim.full_clause_coverage
        || claim.excludes_capabilities != EXCLUSIONS
    {
        return Err(
            "verified evidence-only gate overclaims clauses, capabilities, or profiles".to_owned(),
        );
    }
    Ok(())
}

fn validate_commands(commands: &[String]) -> Result<(), String> {
    if commands.len() != 14
        || commands
            .iter()
            .any(|command| !command.starts_with("timeout "))
        || !commands
            .iter()
            .any(|command| command.contains("--test async_source_lowering"))
        || !commands.iter().any(|command| command.contains("cargo fmt"))
        || !commands
            .iter()
            .any(|command| command.contains("cargo check"))
        || !commands
            .iter()
            .any(|command| command.contains("cargo clippy"))
        || !commands
            .iter()
            .any(|command| command.contains("cargo test --locked --workspace"))
        || !commands
            .iter()
            .any(|command| command.contains("xtask -- check generated"))
    {
        return Err("bounded validation command set is incomplete".to_owned());
    }
    Ok(())
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?
    {
        let path = entry
            .map_err(|error| format!("could not inspect {}: {error}", directory.display()))?
            .path();
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
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
