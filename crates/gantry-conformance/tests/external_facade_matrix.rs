//! Isolated external-consumer checks for every supported facade feature set.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry_conformance::{FacadeFeatureSelection, validate_facade_features};
use serde::Deserialize;

const API_MANIFEST_PATH: &str = "protocol/conformance/execution-api-v1.json";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    requirements: Vec<RequirementEvidence>,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RequirementEvidence {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ContractGate {
    requirement_assignments: Vec<RequirementAssignment>,
}

#[derive(Debug, Deserialize)]
struct RequirementAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

#[test]
fn checked_in_execution_api_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest = read_json(&root.join(API_MANIFEST_PATH));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    let gate: ContractGate =
        read_json(&root.join("protocol/conformance/async-execution-contract-v1.json"));

    assert_eq!(manifest.format, "gantry.execution-api-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-API-001");
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(|entry| entry.evidence.as_str())
            .collect::<Vec<_>>(),
        [
            "crates/gantry-conformance/tests/external_facade_matrix.rs#every_supported_feature_combination_builds_for_an_external_consumer",
            "crates/gantry-conformance/tests/external_facade_matrix.rs#legacy_execution_surface_is_unavailable_to_external_consumers",
        ]
    );

    let mut assigned = gate
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-API-001")
        })
        .map(|assignment| RequirementEvidence {
            requirement: assignment.requirement,
            clause: assignment.clause,
            profiles: assignment.profiles,
        })
        .collect::<Vec<_>>();
    assigned.sort();
    let mut declared = manifest.requirements;
    declared.sort();
    assert_eq!(declared, assigned);
    assert_eq!(declared.len(), 7);
    assert_eq!(manifest.exclusions.len(), 2);
}

#[test]
fn every_supported_feature_combination_builds_for_an_external_consumer() {
    let combinations = [
        ("none", &[][..], [false, false, false, false, false]),
        (
            "frontend",
            &["frontend"][..],
            [true, false, false, false, false],
        ),
        (
            "analyzer",
            &["analyzer"][..],
            [true, true, false, false, false],
        ),
        (
            "evaluator",
            &["evaluator"][..],
            [true, true, true, false, false],
        ),
        (
            "concurrent",
            &["concurrent"][..],
            [true, true, true, true, false],
        ),
        ("durable", &["durable"][..], [true, true, true, false, true]),
        (
            "combined",
            &["concurrent", "durable"][..],
            [true, true, true, true, true],
        ),
    ];

    for (name, features, expected) in combinations {
        let observed = FacadeFeatureSelection {
            frontend: expected[0],
            analyzer: expected[1],
            evaluator: expected[2],
            concurrent: expected[3],
            durable: expected[4],
        };
        assert_eq!(validate_facade_features(observed), Ok(()));
        run_external_consumer(name, features, expected);
    }
}

#[test]
fn legacy_execution_surface_is_unavailable_to_external_consumers() {
    reject_legacy_execution_surface();
}

fn run_external_consumer(name: &str, features: &[&str], expected: [bool; 5]) {
    let root = workspace_root();
    let fixture = root.join("target/conformance-external").join(name);
    let _ = fs::remove_dir_all(&fixture);
    assert!(fs::create_dir_all(fixture.join("src")).is_ok());
    let feature_list = features
        .iter()
        .map(|feature| format!("\"{feature}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest = format!(
        "[package]\nname = \"gantry-external-{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\ngantry = {{ path = {:?}, default-features = false, features = [{}] }}\n",
        root.join("crates/gantry"),
        feature_list
    );
    assert!(fs::write(fixture.join("Cargo.toml"), manifest).is_ok());
    let frontend_contract = if expected[0] {
        "    let _ = gantry::event::EventVersion::V1;\n    let _ = gantry::observe::SinkPlan::default();\n"
    } else {
        ""
    };
    let analyzer_contract = if expected[1] {
        "    let _ = std::mem::size_of::<gantry::AnalyzePackageRequest<'static>>();\n    let _ = std::mem::size_of::<gantry::AnalyzePackageArtifacts<'static>>();\n    let _ = std::mem::size_of::<gantry::AnalyzePackageGenericFacts<'static>>();\n    let _: Option<gantry::AnalyzePackageCoordinator<'static>> = None;\n    let _inspect = |result: &gantry::AnalyzePackageResult| {\n        let _: Option<gantry::AnalyzePackageArtifacts<'_>> = result.artifacts();\n        let _: Option<gantry::AnalyzePackageGenericFacts<'_>> = result.generic_facts();\n        let _ = result.diagnostics();\n    };\n"
    } else {
        ""
    };
    let evaluator_contract = if expected[2] {
        "    let _ = std::mem::size_of::<gantry::StartExecutionAccepted>();\n    let _inspect_start = |accepted: &gantry::StartExecutionAccepted| {\n        let _: gantry::identity::ProtocolIdentity = accepted.execution_id();\n        let _: &gantry::runtime::ExecutionHandle = accepted.handle();\n    };\n    let _await_foreground = gantry::Interpreter::await_foreground;\n    let _await_terminal = gantry::Interpreter::await_terminal;\n    let _query = gantry::Interpreter::query_execution;\n"
    } else {
        ""
    };
    let durable_contract = if expected[4] {
        "    let _inspect_durable_start = |accepted: &gantry::DurableStartExecutionAccepted| {\n        let _: &gantry::host::journal::JournalId = accepted.journal_id();\n        let _: gantry::identity::ProtocolIdentity = accepted.execution_id();\n        let _: &gantry::runtime::ExecutionHandle = accepted.handle();\n    };\n    let _inspect_durable_resume = |accepted: &gantry::DurableResumeExecutionAccepted| {\n        let _: gantry::identity::ProtocolIdentity = accepted.execution_id();\n        let _: &gantry::runtime::ExecutionHandle = accepted.handle();\n        let _: &gantry::host::journal::JournalId = accepted.journal_id();\n        let _ = accepted.source_comparison();\n        let _ = accepted.retained_artifacts();\n    };\n"
    } else {
        ""
    };
    let source = format!(
        "fn main() {{\n    let actual = gantry::compiled_features();\n    assert_eq!([actual.frontend, actual.analyzer, actual.evaluator, actual.concurrent, actual.durable], {:?});\n    let advertised = gantry::advertised_profiles();\n    if !gantry::PROFILE_CLAIMS_ENABLED {{\n        assert!(advertised.is_empty());\n        assert!(!gantry::advertises_any_profile());\n    }} else if actual.concurrent && actual.durable {{\n        assert_eq!(advertised, [gantry::ConformanceProfile::Analyzer, gantry::ConformanceProfile::ConcurrentEvaluator, gantry::ConformanceProfile::DurableRuntime, gantry::ConformanceProfile::Embedding, gantry::ConformanceProfile::Evaluator, gantry::ConformanceProfile::Frontend]);\n        assert!(gantry::advertises_any_profile());\n    }} else if actual.concurrent {{\n        assert_eq!(advertised, [gantry::ConformanceProfile::Analyzer, gantry::ConformanceProfile::ConcurrentEvaluator, gantry::ConformanceProfile::Embedding, gantry::ConformanceProfile::Evaluator, gantry::ConformanceProfile::Frontend]);\n        assert!(gantry::advertises_any_profile());\n    }} else if actual.durable {{\n        assert_eq!(advertised, [gantry::ConformanceProfile::Analyzer, gantry::ConformanceProfile::DurableRuntime, gantry::ConformanceProfile::Embedding, gantry::ConformanceProfile::Evaluator, gantry::ConformanceProfile::Frontend]);\n        assert!(gantry::advertises_any_profile());\n    }} else if actual.evaluator {{\n        assert_eq!(advertised, [gantry::ConformanceProfile::Analyzer, gantry::ConformanceProfile::Embedding, gantry::ConformanceProfile::Evaluator, gantry::ConformanceProfile::Frontend]);\n        assert!(gantry::advertises_any_profile());\n    }} else if actual.analyzer {{\n        assert_eq!(advertised, [gantry::ConformanceProfile::Analyzer, gantry::ConformanceProfile::Frontend]);\n        assert!(gantry::advertises_any_profile());\n    }} else if actual.frontend {{\n        assert_eq!(advertised, [gantry::ConformanceProfile::Frontend]);\n        assert!(gantry::advertises_any_profile());\n    }} else {{\n        assert!(advertised.is_empty());\n        assert!(!gantry::advertises_any_profile());\n    }}\n    let _ = gantry::PROFILE_DEFINITIONS.len();\n    let _ = gantry::host::embedding::EMBEDDING_OPERATIONS.len();\n    let _ = gantry::diagnostic::DiagnosticRenderOptions::default();\n{frontend_contract}{analyzer_contract}{evaluator_contract}{durable_contract}}}\n",
        expected,
    );
    assert!(fs::write(fixture.join("src/main.rs"), source).is_ok());

    let status = Command::new("cargo")
        .current_dir(&fixture)
        .env(
            "CARGO_TARGET_DIR",
            root.join("target/conformance-external-target"),
        )
        .args(["run", "--offline", "--quiet"])
        .status();
    assert!(status.is_ok(), "could not run external fixture {name}");
    assert!(
        status
            .unwrap_or_else(|_| unreachable!("checked above"))
            .success(),
        "external fixture {name} failed"
    );
}

fn reject_legacy_execution_surface() {
    let root = workspace_root();
    let fixture = root.join("target/conformance-external/legacy-execution-surface");
    let _ = fs::remove_dir_all(&fixture);
    assert!(fs::create_dir_all(fixture.join("src")).is_ok());
    let manifest = format!(
        "[package]\nname = \"gantry-external-legacy-execution-surface\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\ngantry = {{ path = {:?}, default-features = false, features = [\"durable\"] }}\n",
        root.join("crates/gantry")
    );
    assert!(fs::write(fixture.join("Cargo.toml"), manifest).is_ok());
    let source = r#"
use gantry::{
    DurableResumeExecutionAccepted, DurableStartExecutionAccepted,
    DurableStartExecutionCoordinator, Interpreter, StartExecutionAccepted,
    StartExecutionCoordinator, TaskDriver,
};

async fn drive(interpreter: &Interpreter, accepted: StartExecutionAccepted) {
    let _ = interpreter.run_execution(accepted).await;
}

fn expose(
    accepted: &StartExecutionAccepted,
    durable: &DurableStartExecutionAccepted,
    resumed: &DurableResumeExecutionAccepted,
) {
    let _ = &accepted.package_activity;
    let _ = &durable.owned;
    let _ = &durable.ownership_token;
    let _ = &resumed.recovered;
}

fn main() {}
"#;
    assert!(fs::write(fixture.join("src/main.rs"), source).is_ok());
    let output = Command::new("cargo")
        .current_dir(&fixture)
        .env(
            "CARGO_TARGET_DIR",
            root.join("target/conformance-external-target"),
        )
        .args(["check", "--offline", "--quiet"])
        .output()
        .unwrap_or_else(|error| panic!("could not check legacy execution fixture: {error}"));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    for rejected in [
        "DurableStartExecutionCoordinator",
        "StartExecutionCoordinator",
        "TaskDriver",
        "run_execution",
        "package_activity",
        "ownership_token",
        "recovered",
    ] {
        assert!(
            stderr.contains(rejected),
            "legacy surface `{rejected}` was not rejected:\n{stderr}"
        );
    }
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
