//! Bounded model and written-argument checks for analyzer package validity.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisError, AnalysisStatus, TypedPackage, analyze_package_types};
use gantry::frontend::{CompletedSyntaxPhase, validate_package_syntax};
use gantry::ir::ArtifactLimits;
use gantry::portable::FrontendResourceCode;
use gantry::source::SourceLimits;
use serde::Deserialize;

const MODEL_EVIDENCE: &str = "crates/gantry-conformance/tests/analyzer_validity_model.rs#bounded_analyzer_validity_model_and_counterexamples_replay";
const OBLIGATIONS: [&str; 6] = [
    "module-resolution-security",
    "types-patterns-completion-schemas",
    "linear-task-ownership",
    "effects-and-purity",
    "canonical-lowering",
    "bounded-artifact-admission",
];

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct ValidityManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profile: String,
    argument: String,
    model: String,
    model_evidence: String,
    evidence_manifests: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ValidityModel {
    format: String,
    maximum_depth: usize,
    explored_state_count: usize,
    expected_conforming_states: usize,
    obligations: Vec<String>,
    assumptions: Vec<String>,
    counterexamples: Vec<Counterexample>,
    canonicalization: CanonicalizationCases,
}

#[derive(Debug, Deserialize)]
struct Counterexample {
    id: String,
    source: String,
    outcome: String,
    expected_code: String,
}

#[derive(Debug, Deserialize)]
struct CanonicalizationCases {
    compact: String,
    cosmetic: String,
    semantic: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewedRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewedRequirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-analyzer-validity-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bounded_analyzer_validity_model_and_counterexamples_replay() {
    let root = workspace_root();
    let model: ValidityModel =
        read_json(&root.join("protocol/goldens/analyzer-validity-model-v1.json"));
    assert_eq!(model.format, "gantry.analyzer-validity-model/v1");
    assert_eq!(model.maximum_depth, OBLIGATIONS.len());
    assert_eq!(model.explored_state_count, 1 << OBLIGATIONS.len());
    assert_eq!(model.obligations, OBLIGATIONS);
    assert!(!model.assumptions.is_empty());

    let mut conforming = 0_usize;
    for state in 0..model.explored_state_count {
        let trace = (0..OBLIGATIONS.len())
            .map(|index| state & (1 << index) != 0)
            .collect::<Vec<_>>();
        let accepted = trace.iter().all(|passed| *passed);
        if accepted {
            conforming = conforming.saturating_add(1);
        }
        assert_eq!(accepted, state == model.explored_state_count - 1);
        if let Some(first_failure) = trace.iter().position(|passed| !passed) {
            assert!(trace[..first_failure].iter().all(|passed| *passed));
            assert!(!accepted);
        }
    }
    assert_eq!(conforming, model.expected_conforming_states);

    let ids = model
        .counterexamples
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    for case in &model.counterexamples {
        let phase = syntax(&case.source);
        match case.outcome.as_str() {
            "source-invalid" => {
                let package = analyze_package_types(&phase)
                    .unwrap_or_else(|error| panic!("analysis failed operationally: {error:?}"));
                assert_eq!(package.status(), AnalysisStatus::Invalid, "{}", case.id);
                assert!(
                    package
                        .diagnostics()
                        .iter()
                        .any(|diagnostic| diagnostic.code.as_str() == case.expected_code),
                    "{}: {:?}",
                    case.id,
                    package.diagnostics()
                );
                assert!(package.canonical_ir().is_none());
            }
            "operational-failure" => {
                let result = gantry::analysis::analyze_package_types_with_artifact_limits(
                    &phase,
                    ArtifactLimits {
                        canonical_ir_bytes: 1,
                        ..ArtifactLimits::MAXIMUM
                    },
                );
                assert!(matches!(
                    result,
                    Err(AnalysisError::ResourceLimit { error, .. })
                        if error.code == FrontendResourceCode::CanonicalIrByteLimit
                            && error.code.wire_name() == case.expected_code
                ));
            }
            other => panic!("unknown modeled outcome {other}"),
        }
    }

    let compact = analyze(&model.canonicalization.compact);
    let cosmetic = analyze(&model.canonicalization.cosmetic);
    let semantic = analyze(&model.canonicalization.semantic);
    assert_eq!(ir_bytes(&compact), ir_bytes(&cosmetic));
    assert_ne!(manifest_bytes(&compact), manifest_bytes(&cosmetic));
    assert_ne!(ir_bytes(&compact), ir_bytes(&semantic));
}

#[test]
fn written_validity_argument_links_current_public_evidence_and_no_integration_graph() {
    let root = workspace_root();
    let manifest: ValidityManifest =
        read_json(&root.join("protocol/conformance/analyzer-validity-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    assert_eq!(manifest.format, "gantry.analyzer-validity-evidence/v1");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert_eq!(manifest.issue, "GNT-AN-007");
    assert_eq!(manifest.profile, "analyzer");
    assert_eq!(manifest.model_evidence, MODEL_EVIDENCE);
    assert!(
        manifest
            .evidence_manifests
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(manifest.evidence_manifests.len(), 6);
    assert_eq!(manifest.exclusions.len(), 3);

    let argument = fs::read_to_string(root.join(&manifest.argument))
        .unwrap_or_else(|error| panic!("could not read validity argument: {error}"));
    for heading in [
        "## Scope and claim",
        "## Assumptions and abstraction boundary",
        "## Argument",
        "## Requirement and trace links",
        "## Counterexample replay",
    ] {
        assert!(argument.contains(heading));
    }
    assert!(argument.contains("not an unbounded proof"));
    assert!(root.join(&manifest.model).is_file());

    for path in &manifest.evidence_manifests {
        let value: serde_json::Value = read_json(&root.join(path));
        assert!(gantry_conformance::evidence_revision_is_expected(
            value["specification_sha256"].as_str().unwrap_or_default(),
            &review.specification_sha256,
        ));
        assert!(
            value["entries"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
        );
    }

    let proof = review
        .requirements
        .iter()
        .find(|requirement| requirement.id == "GNT-3-D-PROPERTIES")
        .and_then(|requirement| {
            requirement
                .clauses
                .iter()
                .find(|clause| clause.key == "clause-001")
        })
        .and_then(|clause| {
            clause
                .profile_reviews
                .iter()
                .find(|profile| profile.profile == "analyzer")
        })
        .unwrap_or_else(|| panic!("missing analyzer proof review"));
    assert_eq!(proof.state, "covered");
    assert_eq!(proof.evidence, [MODEL_EVIDENCE]);

    let metadata = Command::new("cargo")
        .current_dir(&root)
        .args(["metadata", "--locked", "--format-version", "1", "--no-deps"])
        .output()
        .unwrap_or_else(|error| panic!("cargo metadata failed: {error}"));
    assert!(metadata.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)
        .unwrap_or_else(|error| panic!("metadata JSON failed: {error}"));
    let dependencies = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package["name"] == "gantry-analysis")
        })
        .and_then(|package| package["dependencies"].as_array())
        .unwrap_or_else(|| panic!("gantry-analysis metadata is missing"))
        .iter()
        .filter_map(|dependency| dependency["name"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dependencies,
        BTreeSet::from(["gantry-core", "gantry-frontend", "gantry-ir", "sha2"])
    );
}

fn analyze(source: &str) -> TypedPackage {
    let phase = syntax(source);
    let package = analyze_package_types(&phase)
        .unwrap_or_else(|error| panic!("analysis failed operationally: {error:?}"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    package
}

fn syntax(source: &str) -> CompletedSyntaxPhase {
    let root = TempDirectory::new(source);
    validate_package_syntax(&root.0, limits())
        .unwrap_or_else(|error| panic!("syntax failed: {error:?}"))
}

fn ir_bytes(package: &TypedPackage) -> &[u8] {
    package
        .canonical_ir()
        .unwrap_or_else(|| unreachable!("valid package has canonical IR"))
        .artifact()
        .canonical_bytes()
}

fn manifest_bytes(package: &TypedPackage) -> &[u8] {
    package
        .manifest()
        .unwrap_or_else(|| unreachable!("valid package has a manifest"))
        .artifact()
        .canonical_bytes()
}

fn limits() -> SourceLimits {
    SourceLimits::new(8, 65_536, 262_144, 65_536, 128)
        .unwrap_or_else(|_| unreachable!("positive limits"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
