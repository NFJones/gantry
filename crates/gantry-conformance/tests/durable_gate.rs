//! Independent validation of the standalone durable-runtime profile gate.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry::ConformanceProfile;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/durable-gate-v1.json";
const PROFILE: &str = "durable-runtime";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    review_summary: ReviewSummary,
    evidence_anchor_count: usize,
    section14_excerpt_count: usize,
    semantic_evidence: SemanticEvidence,
    required_evidence: Vec<String>,
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
struct ReviewSummary {
    profile: String,
    applicable_clause_count: usize,
    covered_count: usize,
    not_applicable_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticEvidence {
    manifest: String,
    argument: String,
    model: String,
    maximum_depth: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    counterexample_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    profiles: Vec<String>,
    advertises_profiles: Vec<String>,
    excludes_profiles: Vec<String>,
    excludes_capabilities: Vec<String>,
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
    profiles: Vec<String>,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Section14Review {
    specification_sha256: String,
    excerpts: Vec<Section14Excerpt>,
}

#[derive(Debug, Deserialize)]
struct Section14Excerpt {
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SequentialGate {
    artifacts: Vec<FileDigest>,
}

#[derive(Debug, Deserialize)]
struct RefinementManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profile: String,
    argument: String,
    model: String,
    model_evidence: String,
    trace_evidence: Vec<String>,
    evidence_manifests: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DurableModel {
    format: String,
    maximum_depth: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    obligations: Vec<String>,
    assumptions: Vec<String>,
    counterexamples: Vec<Counterexample>,
}

#[derive(Debug, Deserialize)]
struct Counterexample {
    id: String,
    trace: Vec<String>,
    rejected_action: String,
    invariant: String,
}

#[derive(Debug, Deserialize)]
struct SqliteEvidence {
    format: String,
    issue: String,
    physical_fault_matrix: PhysicalFaultMatrix,
}

#[derive(Debug, Deserialize)]
struct PhysicalFaultMatrix {
    status: String,
    cases: Vec<String>,
    power_loss_claim: bool,
}

#[test]
fn checked_in_durable_profile_gate_is_current() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));
    assert!(gantry::advertised_profiles().is_empty());
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification.sha256,
        gantry::PROFILE_SPECIFICATION_REVISION,
    ));
    assert!(validate_manifest(&root, &manifest).is_err());
}

#[test]
fn durable_gate_rejects_stale_overclaimed_and_incomplete_evidence() {
    let root = workspace_root();
    let manifest: Manifest = read_json(&root.join(MANIFEST_PATH));

    let mut stale = manifest.clone();
    stale.artifacts[0].sha256 = "0".repeat(64);
    assert!(validate_manifest(&root, &stale).is_err());

    let mut overclaimed = manifest.clone();
    overclaimed
        .claim
        .profiles
        .push("concurrent-evaluator".to_owned());
    assert!(validate_manifest(&root, &overclaimed).is_err());

    let mut missing = manifest.clone();
    missing.required_evidence.pop();
    assert!(validate_manifest(&root, &missing).is_err());

    let mut inconsistent = manifest;
    inconsistent.review_summary.covered_count += 1;
    assert!(validate_manifest(&root, &inconsistent).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.durable-gate-evidence/v1"
        || manifest.gate != "GNT-GATE-600"
        || manifest.status != "verified"
    {
        return Err("durable gate identity or status is invalid".to_owned());
    }
    let claimed = [
        "analyzer",
        "durable-runtime",
        "embedding",
        "evaluator",
        "frontend",
    ];
    if manifest.claim.profiles != claimed
        || manifest.claim.advertises_profiles != claimed
        || manifest.claim.excludes_profiles != ["concurrent-evaluator"]
        || manifest.claim.excludes_capabilities != ["combined-concurrent-durable"]
        || !gantry::compiled_features().durable
        || !gantry::PROFILE_CLAIMS_ENABLED
        || !gantry::advertised_profiles().contains(&ConformanceProfile::DurableRuntime)
    {
        return Err("durable claim is invalid or overstates combined behavior".to_owned());
    }

    validate_file_digest(root, &manifest.specification, "specification")?;
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
    for artifact in &manifest.artifacts {
        validate_file_digest(root, artifact, "artifact")?;
    }
    let artifact_paths = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    for required in required_artifact_paths() {
        if !artifact_paths.contains(required) {
            return Err(format!("required artifact is missing: {required}"));
        }
    }

    let sequential: SequentialGate =
        read_json(&root.join("protocol/conformance/sequential-gate-v1.json"));
    for artifact in &sequential.artifacts {
        validate_file_digest(root, artifact, "delegated sequential artifact")?;
    }
    let authenticated_paths = artifact_paths
        .iter()
        .copied()
        .chain(
            sequential
                .artifacts
                .iter()
                .map(|artifact| artifact.path.as_str()),
        )
        .collect::<BTreeSet<_>>();

    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let section14: Section14Review =
        read_json(&root.join("protocol/requirements/section14-v1.json"));
    if review.specification_sha256 != manifest.specification.sha256
        || section14.specification_sha256 != manifest.specification.sha256
    {
        return Err("durable evidence uses another specification revision".to_owned());
    }
    validate_reviews(root, manifest, &review, &authenticated_paths)?;
    validate_section14(root, manifest, &section14, &authenticated_paths)?;
    validate_semantic_evidence(root, manifest, &authenticated_paths)?;
    validate_storage_evidence(root, &artifact_paths)?;
    validate_required_evidence(root, manifest, &authenticated_paths)?;

    validate_sorted_unique(
        "validation commands",
        manifest.validation_commands.iter().map(String::as_str),
    )?;
    if manifest.validation_commands.is_empty()
        || manifest.environment_gaps
            != [
                "The exact Rust 1.97.1 and rolling stable macOS product lanes execute in hosted CI; this Linux gate run does not claim a local macOS result or a qualified stable-media power-loss environment.",
            ]
    {
        return Err("validation commands or environment gaps are incomplete".to_owned());
    }
    Ok(())
}

fn validate_reviews(
    root: &Path,
    manifest: &Manifest,
    review: &RequirementReview,
    artifact_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    let mut applicable = 0_usize;
    let mut covered = 0_usize;
    let mut not_applicable = 0_usize;
    let mut anchors = BTreeSet::new();
    for requirement in &review.requirements {
        for clause in &requirement.clauses {
            if !clause.profiles.iter().any(|candidate| candidate == PROFILE) {
                continue;
            }
            applicable += 1;
            let profile_review = clause
                .profile_reviews
                .iter()
                .find(|profile_review| profile_review.profile == PROFILE)
                .ok_or_else(|| {
                    format!(
                        "durable review is missing: {}:{}",
                        requirement.id, clause.key
                    )
                })?;
            match profile_review.state.as_str() {
                "covered" if !profile_review.evidence.is_empty() => {
                    covered += 1;
                    for evidence in &profile_review.evidence {
                        anchors.insert(evidence.as_str());
                        validate_public_test_anchor(root, evidence)?;
                        require_anchor_artifact(evidence, artifact_paths)?;
                    }
                }
                "not-applicable"
                    if profile_review.evidence.is_empty()
                        && profile_review
                            .rationale
                            .as_deref()
                            .is_some_and(|rationale| !rationale.trim().is_empty()) =>
                {
                    not_applicable += 1;
                }
                _ => {
                    return Err(format!(
                        "durable review is not closed: {}:{}",
                        requirement.id, clause.key
                    ));
                }
            }
        }
    }
    let summary = &manifest.review_summary;
    if summary.profile != PROFILE
        || (applicable, covered, not_applicable)
            != (
                summary.applicable_clause_count,
                summary.covered_count,
                summary.not_applicable_count,
            )
        || applicable != covered + not_applicable
        || manifest.evidence_anchor_count != anchors.len()
    {
        return Err("durable review summary differs from reviewed applicability".to_owned());
    }
    Ok(())
}

fn validate_section14(
    root: &Path,
    manifest: &Manifest,
    section14: &Section14Review,
    artifact_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    if manifest.section14_excerpt_count != section14.excerpts.len()
        || section14
            .excerpts
            .iter()
            .any(|excerpt| excerpt.state != "covered" || excerpt.evidence.is_empty())
    {
        return Err("Section 14 authoring evidence is incomplete".to_owned());
    }
    for evidence in section14
        .excerpts
        .iter()
        .flat_map(|excerpt| &excerpt.evidence)
    {
        validate_public_test_anchor(root, evidence)?;
        require_anchor_artifact(evidence, artifact_paths)?;
    }
    Ok(())
}

fn validate_semantic_evidence(
    root: &Path,
    manifest: &Manifest,
    artifact_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    let summary = &manifest.semantic_evidence;
    if summary.manifest != "protocol/conformance/durable-refinement-v1.json"
        || summary.argument != "docs/durable-runtime-refinement.md"
        || summary.model != "protocol/goldens/durable-refinement-model-v1.json"
        || summary.maximum_depth != 15
        || summary.explored_state_count != 3_724
        || summary.terminal_state_count != 2_772
        || summary.counterexample_count != 15
    {
        return Err("durable semantic evidence summary is invalid".to_owned());
    }
    for path in [&summary.manifest, &summary.argument, &summary.model] {
        if !artifact_paths.contains(path.as_str()) {
            return Err(format!("semantic evidence artifact is missing: {path}"));
        }
    }

    let refinement: RefinementManifest = read_json(&root.join(&summary.manifest));
    if refinement.format != "gantry.durable-refinement-evidence/v1"
        || refinement.specification_sha256 != manifest.specification.sha256
        || refinement.issue != "GNT-DUR-006"
        || refinement.profile != PROFILE
        || refinement.argument != summary.argument
        || refinement.model != summary.model
        || refinement.trace_evidence.len() != 11
        || refinement.evidence_manifests.len() != 3
        || refinement.exclusions.len() != 4
    {
        return Err("durable refinement manifest is incomplete".to_owned());
    }
    validate_public_test_anchor(root, &refinement.model_evidence)?;
    require_anchor_artifact(&refinement.model_evidence, artifact_paths)?;
    for evidence in &refinement.trace_evidence {
        validate_public_test_anchor(root, evidence)?;
        require_anchor_artifact(evidence, artifact_paths)?;
    }
    for evidence_manifest in &refinement.evidence_manifests {
        if !artifact_paths.contains(evidence_manifest.as_str()) {
            return Err(format!(
                "refinement evidence manifest is missing: {evidence_manifest}"
            ));
        }
    }
    if !refinement
        .exclusions
        .iter()
        .any(|exclusion| exclusion.contains("Concurrent"))
        || !refinement
            .exclusions
            .iter()
            .any(|exclusion| exclusion.contains("not an unbounded proof"))
    {
        return Err("durable refinement exclusions are incomplete".to_owned());
    }

    let model: DurableModel = read_json(&root.join(&summary.model));
    let expected_obligations = [
        "cancellation-nonconsumption",
        "causally-closed-prefix-recovery",
        "commit-before-observation",
        "compaction-equivalent-projection",
        "fail-closed-generic-artifacts",
        "fixed-outcome-status-isolation",
        "indeterminate-delivery-classification",
        "indeterminate-operation-classification",
        "no-recovery-generic-analysis",
        "recorded-delay-reuse",
        "retained-generic-projection-equivalence",
        "selected-target-preservation",
        "single-result-consumption",
        "source-free-generic-recovery",
        "terminal-completion-uniqueness",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual_obligations = model
        .obligations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if model.format != "gantry.durable-refinement-model/v1"
        || model.maximum_depth != summary.maximum_depth
        || model.explored_state_count != summary.explored_state_count
        || model.terminal_state_count != summary.terminal_state_count
        || model.counterexamples.len() != summary.counterexample_count
        || actual_obligations != expected_obligations
        || model.assumptions.len() != 4
    {
        return Err("durable bounded model summary differs".to_owned());
    }
    validate_sorted_unique(
        "counterexample ids",
        model
            .counterexamples
            .iter()
            .map(|counterexample| counterexample.id.as_str()),
    )?;
    if model.counterexamples.iter().any(|counterexample| {
        counterexample.trace.len() > model.maximum_depth
            || counterexample.rejected_action.trim().is_empty()
            || counterexample.invariant.trim().is_empty()
    }) {
        return Err("durable counterexample replay is incomplete".to_owned());
    }
    Ok(())
}

fn validate_storage_evidence(root: &Path, artifact_paths: &BTreeSet<&str>) -> Result<(), String> {
    for path in [
        "protocol/conformance/journal-storage-v1.json",
        "protocol/conformance/sqlite-storage-v1.json",
        "docs/sqlite-journal-storage.md",
    ] {
        if !artifact_paths.contains(path) {
            return Err(format!("storage evidence artifact is missing: {path}"));
        }
    }
    let sqlite: SqliteEvidence =
        read_json(&root.join("protocol/conformance/sqlite-storage-v1.json"));
    if sqlite.format != "gantry.sqlite-storage-evidence/v1"
        || sqlite.issue != "GNT-SQL-002"
        || sqlite.physical_fault_matrix.status != "synthetic-bundled-unix-vfs-covered"
        || sqlite.physical_fault_matrix.cases
            != [
                "database-sync-failure",
                "directory-sync-failure",
                "short-write",
                "torn-write",
            ]
        || sqlite.physical_fault_matrix.power_loss_claim
    {
        return Err("SQLite durability evidence overclaims its environment".to_owned());
    }
    Ok(())
}

fn validate_required_evidence(
    root: &Path,
    manifest: &Manifest,
    artifact_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    let expected = required_evidence();
    if manifest.required_evidence != expected {
        return Err("required durable evidence is incomplete".to_owned());
    }
    for evidence in &manifest.required_evidence {
        validate_public_test_anchor(root, evidence)?;
        require_anchor_artifact(evidence, artifact_paths)?;
    }
    Ok(())
}

fn required_evidence() -> Vec<String> {
    [
        "crates/gantry-conformance/tests/durable_events.rs#public_delivery_crash_cuts_preserve_retry_budget_and_terminal_settlement",
        "crates/gantry-conformance/tests/durable_events.rs#public_journal_first_occurrence_plan_and_payloads_precede_delivery",
        "crates/gantry-conformance/tests/durable_recovery.rs#public_committed_and_compacted_prefixes_restore_the_same_machine_and_sessions",
        "crates/gantry-conformance/tests/durable_recovery.rs#public_operation_cuts_reuse_committed_payloads_and_classify_indeterminate_dispatch",
        "crates/gantry-conformance/tests/durable_refinement_model.rs#bounded_durable_refinement_model_and_counterexamples_replay",
        "crates/gantry-conformance/tests/durable_start.rs#durable_cancellation_commits_once_before_terminal_observation_and_release",
        "crates/gantry-conformance/tests/durable_start.rs#durable_shutdown_cancels_sequential_work_releases_once_and_is_idempotent",
        "crates/gantry-conformance/tests/durable_start.rs#durable_start_and_resume_preserve_acceptance_and_nonmutation_boundaries",
        "crates/gantry-conformance/tests/journal_storage.rs#public_in_memory_store_passes_the_common_atomic_fenced_contract",
        "crates/gantry-conformance/tests/sqlite_storage.rs#bundled_sqlite_fault_matrix_preserves_atomic_sequence_and_payload_prefixes",
        "crates/gantry-conformance/tests/sqlite_storage.rs#public_sqlite_cross_process_owner_exclusion_and_crash_reclamation",
        "crates/gantry-conformance/tests/sqlite_storage.rs#public_sqlite_strict_power_loss_policy_matches_environment_qualification",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_artifact_paths() -> [&'static str; 27] {
    [
        "SPEC.md",
        "crates/gantry-conformance/tests/durable_events.rs",
        "crates/gantry-conformance/tests/durable_gate.rs",
        "crates/gantry-conformance/tests/durable_recovery.rs",
        "crates/gantry-conformance/tests/durable_refinement_model.rs",
        "crates/gantry-conformance/tests/durable_start.rs",
        "crates/gantry-conformance/tests/journal_storage.rs",
        "crates/gantry-conformance/tests/sqlite_storage.rs",
        "crates/gantry/src/lib.rs",
        "docs/durable-runtime-refinement.md",
        "docs/sqlite-journal-storage.md",
        "protocol/conformance/durable-events-v1.json",
        "protocol/conformance/durable-recovery-v1.json",
        "protocol/conformance/durable-refinement-v1.json",
        "protocol/conformance/durable-start-v1.json",
        "protocol/conformance/journal-storage-v1.json",
        "protocol/conformance/sequential-gate-v1.json",
        "protocol/conformance/sqlite-storage-v1.json",
        "protocol/goldens/durable-events-v1.json",
        "protocol/goldens/durable-recovery-v1.json",
        "protocol/goldens/durable-refinement-model-v1.json",
        "protocol/goldens/durable-start-v1.json",
        "protocol/goldens/journal-storage-v1.json",
        "protocol/publication/artifacts-v1.json",
        "protocol/requirements/generated/requirements-v1.json",
        "protocol/requirements/reviewed-v1.json",
        "protocol/requirements/section14-v1.json",
    ]
}

fn validate_public_test_anchor(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, _) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence anchor has no test: {evidence}"))?;
    if !path.starts_with("crates/gantry-conformance/tests/") || !path.ends_with(".rs") {
        return Err(format!(
            "evidence is not a public conformance test: {evidence}"
        ));
    }
    validate_source_test_anchor(root, evidence)
}

fn validate_source_test_anchor(root: &Path, evidence: &str) -> Result<(), String> {
    let (path, test) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence anchor has no test: {evidence}"))?;
    let source = fs::read_to_string(root.join(path))
        .map_err(|error| format!("could not read evidence {path}: {error}"))?;
    if !source.contains(&format!("fn {test}(")) {
        return Err(format!("evidence test is missing: {evidence}"));
    }
    Ok(())
}

fn require_anchor_artifact(evidence: &str, artifact_paths: &BTreeSet<&str>) -> Result<(), String> {
    let (path, _) = evidence
        .split_once('#')
        .ok_or_else(|| format!("evidence anchor has no test: {evidence}"))?;
    if !artifact_paths.contains(path) {
        return Err(format!("evidence file has no authenticated digest: {path}"));
    }
    Ok(())
}

fn validate_file_digest(root: &Path, file: &FileDigest, kind: &str) -> Result<(), String> {
    let bytes = fs::read(root.join(&file.path))
        .map_err(|error| format!("could not read {kind} {}: {error}", file.path))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if file.sha256.len() != 64 || actual != file.sha256 {
        return Err(format!("{kind} digest differs: {}", file.path));
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

fn validate_sorted_unique<'a>(
    name: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let values = values.into_iter().collect::<Vec<_>>();
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
