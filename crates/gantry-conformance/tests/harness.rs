//! Self-tests for the reusable external conformance harness.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry_conformance::{
    ContractCase, EvidenceKind, EvidenceRecord, EvidenceState, EvidenceVisibility,
    FacadeFeatureSelection, GateEvidenceError, PublicationSkeletonError, run_contract_cases,
    validate_facade_features, validate_gate_evidence, validate_publication_skeleton,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    dependencies: Vec<CargoDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    name: String,
}

#[test]
fn gate_evidence_rejects_missing_placeholder_stale_and_private_records() {
    let revision = "revision-a";
    let records = [
        EvidenceRecord {
            id: "duplicate",
            kind: EvidenceKind::Fixture,
            visibility: EvidenceVisibility::PublicFacade,
            state: EvidenceState::Verified,
            revision,
        },
        EvidenceRecord {
            id: "duplicate",
            kind: EvidenceKind::Golden,
            visibility: EvidenceVisibility::PublicFacade,
            state: EvidenceState::Verified,
            revision,
        },
        EvidenceRecord {
            id: "placeholder",
            kind: EvidenceKind::Protocol,
            visibility: EvidenceVisibility::PublicFacade,
            state: EvidenceState::Placeholder,
            revision,
        },
        EvidenceRecord {
            id: "stale",
            kind: EvidenceKind::Requirement,
            visibility: EvidenceVisibility::PublicFacade,
            state: EvidenceState::Verified,
            revision: "revision-old",
        },
        EvidenceRecord {
            id: "private",
            kind: EvidenceKind::PublicApi,
            visibility: EvidenceVisibility::PrivateOnly,
            state: EvidenceState::Verified,
            revision,
        },
    ];

    let result = validate_gate_evidence(
        revision,
        &["duplicate", "placeholder", "stale", "private", "missing"],
        &records,
    );
    assert!(result.is_err());
    let errors = result
        .err()
        .unwrap_or_else(|| unreachable!("checked above"));
    assert!(errors.contains(&GateEvidenceError::DuplicateId("duplicate".to_owned())));
    assert!(errors.contains(&GateEvidenceError::Placeholder("placeholder".to_owned())));
    assert!(errors.contains(&GateEvidenceError::Stale("stale".to_owned())));
    assert!(errors.contains(&GateEvidenceError::PrivateOnly("private".to_owned())));
    assert!(errors.contains(&GateEvidenceError::Missing("missing".to_owned())));
}

#[test]
fn gate_evidence_accepts_current_supported_surfaces_in_stable_order() {
    let records = [
        EvidenceRecord {
            id: "public",
            kind: EvidenceKind::PublicApi,
            visibility: EvidenceVisibility::PublicFacade,
            state: EvidenceState::Verified,
            revision: "revision-a",
        },
        EvidenceRecord {
            id: "adapter",
            kind: EvidenceKind::AdapterContract,
            visibility: EvidenceVisibility::AdapterContract,
            state: EvidenceState::Verified,
            revision: "revision-a",
        },
    ];
    let index = validate_gate_evidence("revision-a", &["adapter", "public"], &records);
    assert!(index.is_ok());
    let index = index.unwrap_or_else(|_| unreachable!("checked above"));
    assert_eq!(
        index
            .records
            .iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        ["adapter", "public"]
    );
}

#[test]
fn contract_runner_uses_substitutable_adapters_and_aggregates_failures() {
    struct Adapter {
        value: u8,
    }
    fn passes(adapter: &Adapter) -> Result<(), String> {
        (adapter.value == 7)
            .then_some(())
            .ok_or_else(|| "wrong value".to_owned())
    }
    fn fails(_: &Adapter) -> Result<(), String> {
        Err("observed failure".to_owned())
    }
    let cases = [
        ContractCase {
            id: "passes",
            run: passes,
        },
        ContractCase {
            id: "fails",
            run: fails,
        },
    ];
    let result = run_contract_cases(&Adapter { value: 7 }, &cases);
    assert!(result.is_err());
    let failures = result
        .err()
        .unwrap_or_else(|| unreachable!("checked above"));
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].id, "fails");
    assert_eq!(failures[0].detail, "observed failure");
}

#[test]
fn publication_skeleton_rejects_missing_duplicate_and_unknown_members() {
    let invalid = [
        "gantry.authoring",
        "gantry.authoring",
        "gantry.conformance",
        "gantry.embedding",
        "gantry.ir",
        "gantry.journal",
        "gantry.spec",
        "unexpected",
    ];
    let result = validate_publication_skeleton(2, 0, &invalid);
    assert!(result.is_err());
    let errors = result
        .err()
        .unwrap_or_else(|| unreachable!("checked above"));
    assert!(errors.contains(&PublicationSkeletonError::UnsupportedVersion));
    assert!(
        errors.contains(&PublicationSkeletonError::DuplicateArtifact(
            "gantry.authoring".to_owned()
        ))
    );
    assert!(errors.contains(&PublicationSkeletonError::MissingArtifact(
        "gantry.values".to_owned()
    )));
    assert!(
        errors.contains(&PublicationSkeletonError::UnexpectedArtifact(
            "unexpected".to_owned()
        ))
    );
}

#[test]
fn checked_in_publication_skeleton_is_accepted_without_claiming_completeness() {
    let value: serde_json::Value =
        read_json(&workspace_root().join("protocol/publication/artifacts-v1.json"));
    let major = value["publication_index"]["major"].as_u64();
    let minor = value["publication_index"]["minor"].as_u64();
    let ids = value["required_artifact_ids"].as_array().map(|values| {
        values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
    });
    assert!(major.is_some() && minor.is_some() && ids.is_some());
    assert_eq!(
        validate_publication_skeleton(
            major.unwrap_or_default(),
            minor.unwrap_or_default(),
            &ids.unwrap_or_default(),
        ),
        Ok(())
    );
}

#[test]
fn external_dependency_graph_has_no_private_generator_or_harness_edges() {
    let output = Command::new("cargo")
        .current_dir(workspace_root())
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output();
    assert!(output.is_ok());
    let output = output.unwrap_or_else(|_| unreachable!("checked above"));
    assert!(output.status.success());
    let metadata: Result<CargoMetadata, _> = serde_json::from_slice(&output.stdout);
    assert!(metadata.is_ok());
    let metadata = metadata.unwrap_or_else(|_| unreachable!("checked above"));
    let workspace = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();
    let workspace_names = metadata
        .packages
        .iter()
        .filter(|package| workspace.contains(&package.id))
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    for package in &metadata.packages {
        if !workspace.contains(&package.id) {
            continue;
        }
        for dependency in &package.dependencies {
            if !workspace_names.contains(dependency.name.as_str()) {
                continue;
            }
            if package.name != "gantry-conformance" {
                assert_ne!(dependency.name, "gantry-conformance");
            }
            if package.name != "xtask" {
                assert_ne!(dependency.name, "xtask");
            }
        }
    }
}

#[test]
fn feature_validator_rejects_nonadditive_combinations() {
    assert_eq!(
        validate_facade_features(FacadeFeatureSelection {
            frontend: false,
            analyzer: true,
            evaluator: false,
            concurrent: false,
            durable: false,
        }),
        Err("analyzer requires frontend")
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
