//! Independent validation of the sequential evaluator and embedding gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry::ConformanceProfile;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "protocol/conformance/sequential-gate-v1.json";
const REVIEW_PROFILES: [&str; 2] = ["embedding", "evaluator"];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    gate: String,
    status: String,
    specification: FileDigest,
    prerequisites: Vec<Prerequisite>,
    artifacts: Vec<FileDigest>,
    review_summaries: Vec<ReviewSummary>,
    evidence_anchor_count: usize,
    section14_excerpt_count: usize,
    semantic_evidence: SemanticEvidence,
    unsupported_concurrency_evidence: String,
    cli_evidence: String,
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
struct RefinementManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profiles: Vec<String>,
    argument: String,
    model: String,
    model_evidence: String,
    trace_evidence: Vec<String>,
    evidence_manifests: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SequentialModel {
    format: String,
    maximum_depth: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    obligations: Vec<String>,
    assumptions: Vec<String>,
    host_wait_states: Vec<String>,
    counterexamples: Vec<Counterexample>,
}

#[derive(Debug, Deserialize)]
struct Counterexample {
    id: String,
    trace: Vec<String>,
    rejected_action: String,
    invariant: String,
}

#[test]
fn checked_in_sequential_profile_gate_is_current() {
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
fn sequential_profile_gate_rejects_stale_overclaimed_and_incomplete_evidence() {
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
    inconsistent.review_summaries[0].covered_count += 1;
    assert!(validate_manifest(&root, &inconsistent).is_err());
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if manifest.format != "gantry.sequential-gate-evidence/v1"
        || manifest.gate != "GNT-GATE-400"
        || manifest.status != "verified"
    {
        return Err("sequential gate identity or status is invalid".to_owned());
    }
    let advertised_profiles_are_valid =
        if gantry::compiled_features().concurrent && gantry::compiled_features().durable {
            gantry::advertised_profiles()
                == [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::ConcurrentEvaluator,
                    ConformanceProfile::DurableRuntime,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
        } else if gantry::compiled_features().concurrent {
            gantry::advertised_profiles()
                == [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::ConcurrentEvaluator,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
        } else {
            gantry::advertised_profiles()
                == [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
        };
    if manifest.claim.profiles != ["analyzer", "embedding", "evaluator", "frontend"]
        || manifest.claim.advertises_profiles != manifest.claim.profiles
        || manifest.claim.excludes_profiles != ["concurrent-evaluator", "durable-runtime"]
        || manifest.claim.excludes_capabilities != ["journal", "resume"]
        || !advertised_profiles_are_valid
    {
        return Err("sequential claim is invalid or overstates a later profile".to_owned());
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

    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let section14: Section14Review =
        read_json(&root.join("protocol/requirements/section14-v1.json"));
    if review.specification_sha256 != manifest.specification.sha256
        || section14.specification_sha256 != manifest.specification.sha256
    {
        return Err("sequential evidence uses another specification revision".to_owned());
    }

    let summaries = validate_reviews(root, &review, &artifact_paths)?;
    if manifest.review_summaries.len() != REVIEW_PROFILES.len() {
        return Err("sequential review summary differs from reviewed applicability".to_owned());
    }
    for summary in &manifest.review_summaries {
        let actual = summaries
            .get(summary.profile.as_str())
            .ok_or_else(|| "sequential review summary has an unknown profile".to_owned())?;
        if *actual
            != (
                summary.applicable_clause_count,
                summary.covered_count,
                summary.not_applicable_count,
            )
            || summary.applicable_clause_count
                != summary.covered_count + summary.not_applicable_count
        {
            return Err("sequential review summary differs from reviewed applicability".to_owned());
        }
    }
    validate_sorted_unique(
        "review summary profiles",
        manifest
            .review_summaries
            .iter()
            .map(|summary| summary.profile.as_str()),
    )?;

    let evidence_anchors = review
        .requirements
        .iter()
        .flat_map(|requirement| &requirement.clauses)
        .flat_map(|clause| &clause.profile_reviews)
        .filter(|profile_review| REVIEW_PROFILES.contains(&profile_review.profile.as_str()))
        .flat_map(|profile_review| profile_review.evidence.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    if manifest.evidence_anchor_count != evidence_anchors.len() {
        return Err("sequential evidence anchor count differs".to_owned());
    }

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
        require_anchor_artifact(evidence, &artifact_paths)?;
    }

    validate_semantic_evidence(root, manifest, &artifact_paths)?;
    validate_required_evidence(root, manifest, &artifact_paths)?;
    validate_source_test_anchor(root, &manifest.unsupported_concurrency_evidence)?;
    validate_source_test_anchor(root, &manifest.cli_evidence)?;
    require_anchor_artifact(&manifest.unsupported_concurrency_evidence, &artifact_paths)?;
    require_anchor_artifact(&manifest.cli_evidence, &artifact_paths)?;

    validate_sorted_unique(
        "validation commands",
        manifest.validation_commands.iter().map(String::as_str),
    )?;
    if manifest.validation_commands.is_empty()
        || manifest.environment_gaps
            != [
                "The stable macOS product lane executes in hosted CI; this Linux gate run does not claim a local macOS result.",
            ]
    {
        return Err("validation commands or environment gaps are incomplete".to_owned());
    }
    Ok(())
}

fn validate_reviews(
    root: &Path,
    review: &RequirementReview,
    artifact_paths: &BTreeSet<&str>,
) -> Result<BTreeMap<&'static str, (usize, usize, usize)>, String> {
    let mut summaries = BTreeMap::new();
    for profile in REVIEW_PROFILES {
        let mut applicable = 0_usize;
        let mut covered = 0_usize;
        let mut not_applicable = 0_usize;
        for requirement in &review.requirements {
            for clause in &requirement.clauses {
                if !clause.profiles.iter().any(|candidate| candidate == profile) {
                    continue;
                }
                applicable += 1;
                let profile_review = clause
                    .profile_reviews
                    .iter()
                    .find(|profile_review| profile_review.profile == profile)
                    .ok_or_else(|| {
                        format!(
                            "{profile} review is missing: {}:{}",
                            requirement.id, clause.key
                        )
                    })?;
                match profile_review.state.as_str() {
                    "covered" if !profile_review.evidence.is_empty() => {
                        covered += 1;
                        for evidence in &profile_review.evidence {
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
                            "{profile} review is not closed: {}:{}",
                            requirement.id, clause.key
                        ));
                    }
                }
            }
        }
        summaries.insert(profile, (applicable, covered, not_applicable));
    }
    Ok(summaries)
}

fn validate_semantic_evidence(
    root: &Path,
    manifest: &Manifest,
    artifact_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    let summary = &manifest.semantic_evidence;
    if summary.manifest != "protocol/conformance/sequential-evaluator-refinement-v1.json"
        || summary.argument != "docs/sequential-evaluator-refinement.md"
        || summary.model != "protocol/goldens/sequential-evaluator-model-v1.json"
        || summary.maximum_depth != 12
        || summary.explored_state_count != 836
        || summary.terminal_state_count != 276
        || summary.counterexample_count != 9
    {
        return Err("sequential semantic evidence summary is invalid".to_owned());
    }
    for path in [&summary.manifest, &summary.argument, &summary.model] {
        if !artifact_paths.contains(path.as_str()) {
            return Err(format!("semantic evidence artifact is missing: {path}"));
        }
    }

    let refinement: RefinementManifest = read_json(&root.join(&summary.manifest));
    if refinement.format != "gantry.sequential-evaluator-refinement-evidence/v1"
        || refinement.specification_sha256 != manifest.specification.sha256
        || refinement.issue != "GNT-RUN-002"
        || refinement.profiles != ["embedding", "evaluator"]
        || refinement.argument != summary.argument
        || refinement.model != summary.model
        || refinement.trace_evidence.is_empty()
        || refinement.evidence_manifests.len() != 3
        || refinement.exclusions.len() != 4
    {
        return Err("sequential refinement manifest is incomplete".to_owned());
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
            .any(|exclusion| exclusion.contains("Durable"))
    {
        return Err("sequential refinement exclusions are incomplete".to_owned());
    }

    let model: SequentialModel = read_json(&root.join(&summary.model));
    let obligation_set = model
        .obligations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_obligations = [
        "base-handle-ownership-vacuous",
        "cancellation-nonconsumption",
        "enabled-machine-progress",
        "fixed-outcome-observation-isolation",
        "lifecycle-linearization",
        "operation-single-consumption",
        "terminal-completion-uniqueness",
        "type-and-store-preservation",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if model.format != "gantry.sequential-evaluator-model/v1"
        || model.maximum_depth != summary.maximum_depth
        || model.explored_state_count != summary.explored_state_count
        || model.terminal_state_count != summary.terminal_state_count
        || model.counterexamples.len() != summary.counterexample_count
        || obligation_set != expected_obligations
        || model.assumptions.len() != 4
        || model.host_wait_states != ["prepared-integration-result", "retry-waiting-timer"]
    {
        return Err("sequential bounded model summary differs".to_owned());
    }
    validate_sorted_unique(
        "counterexample ids",
        model
            .counterexamples
            .iter()
            .map(|counterexample| counterexample.id.as_str()),
    )?;
    if model.counterexamples.iter().any(|counterexample| {
        counterexample.trace.is_empty()
            || counterexample.rejected_action.trim().is_empty()
            || counterexample.invariant.trim().is_empty()
    }) {
        return Err("sequential counterexample replay is incomplete".to_owned());
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
        return Err("required sequential evidence is incomplete".to_owned());
    }
    for evidence in &manifest.required_evidence {
        validate_public_test_anchor(root, evidence)?;
        require_anchor_artifact(evidence, artifact_paths)?;
    }
    Ok(())
}

fn required_evidence() -> Vec<String> {
    [
        "crates/gantry-conformance/tests/activity_observation.rs#canonical_barrier_vectors_keep_required_failure_activity_scoped",
        "crates/gantry-conformance/tests/execution_observation.rs#public_execution_event_catalog_is_typed_canonical_and_protected",
        "crates/gantry-conformance/tests/execution_observation.rs#public_required_delivery_failure_is_isolated_nonrecursive_and_post_terminal_safe",
        "crates/gantry-conformance/tests/executor_services.rs#caller_owned_tokio_runtimes_preserve_completion_first_and_drop_losers",
        "crates/gantry-conformance/tests/harness.rs#contract_runner_uses_substitutable_adapters_and_aggregates_failures",
        "crates/gantry-conformance/tests/interpreter_facade.rs#public_interpreter_drives_and_observes_one_sequential_execution",
        "crates/gantry-conformance/tests/interpreter_lifecycle.rs#panic_boundaries_preserve_origin_and_apply_exact_poisoning",
        "crates/gantry-conformance/tests/logical_sessions.rs#public_session_establishment_is_idempotent_and_precedes_hook_creation",
        "crates/gantry-conformance/tests/operation_boundaries.rs#public_operation_lifecycle_is_lazy_serial_and_single_consumption",
        "crates/gantry-conformance/tests/scripted_integration.rs#scripted_adapter_exercises_preflight_hook_and_cancellation_contracts",
        "crates/gantry-conformance/tests/sequential_machine.rs#public_budgets_cancellation_and_dynamic_identities_are_exact",
        "crates/gantry-conformance/tests/sequential_refinement_model.rs#bounded_sequential_refinement_model_and_counterexamples_replay",
        "crates/gantry-conformance/tests/start_execution.rs#mapping_and_root_preflight_precede_identity_and_accept_normalized_entry",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn required_artifact_paths() -> [&'static str; 17] {
    [
        "SPEC.md",
        "crates/gantry-cli/src/main.rs",
        "crates/gantry/src/lib.rs",
        "docs/sequential-evaluator-refinement.md",
        "protocol/catalogs/embedding-contracts-v1.json",
        "protocol/catalogs/profiles-v1.json",
        "protocol/conformance/analyzer-gate-v1.json",
        "protocol/conformance/execution-observation-v1.json",
        "protocol/conformance/executor-services-v1.json",
        "protocol/conformance/interpreter-lifecycle-v1.json",
        "protocol/conformance/sequential-evaluator-refinement-v1.json",
        "protocol/goldens/embedding-contracts-v1.canonical.json",
        "protocol/goldens/sequential-evaluator-model-v1.json",
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
