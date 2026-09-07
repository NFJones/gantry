//! Frozen requirement assignments and executable evidence for CLI runtime policy.

use std::fs;
use std::path::Path;

use serde_json::Value;

/// Verifies CLI-001's exact frozen rows and linked worker-policy evidence.
#[test]
fn cli_runtime_policy_evidence_matches_frozen_assignments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |path: &str| -> Value {
        serde_json::from_slice(
            &fs::read(root.join(path)).unwrap_or_else(|error| panic!("read {path}: {error}")),
        )
        .unwrap_or_else(|error| panic!("decode {path}: {error}"))
    };
    let manifest = read("protocol/conformance/cli-runtime-policy-v1.json");
    let gate = read("protocol/conformance/async-execution-contract-v1.json");
    let review = read("protocol/requirements/reviewed-v1.json");
    assert_eq!(manifest["format"], "gantry.cli-runtime-policy-evidence/v1");
    assert_eq!(manifest["issue"], "GNT-ASYNC-CLI-001");
    assert_eq!(
        manifest["specification_sha256"],
        review["specification_sha256"]
    );
    let expected = gate["requirement_assignments"]
        .as_array()
        .unwrap_or_else(|| panic!("missing frozen assignments"))
        .iter()
        .filter(|row| {
            row["evidence_owners"]
                .as_array()
                .is_some_and(|owners| owners.iter().any(|owner| owner == "GNT-ASYNC-CLI-001"))
        })
        .map(|row| {
            serde_json::json!({
                "requirement": row["requirement"],
                "clause": row["clause"],
                "profiles": row["profiles"]
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 5);
    assert_eq!(manifest["requirements"], Value::Array(expected));

    let capabilities = manifest["capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("missing capabilities"));
    assert_eq!(capabilities.len(), 3);
    let mut previous = "";
    for capability in capabilities {
        let id = capability["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing capability id"));
        assert!(id > previous, "noncanonical capability order: {id}");
        previous = id;
        let evidence = capability["evidence"]
            .as_str()
            .unwrap_or_else(|| panic!("missing evidence"));
        let (path, anchor) = evidence
            .split_once('#')
            .unwrap_or_else(|| panic!("missing anchor: {evidence}"));
        let source = fs::read_to_string(root.join(path))
            .unwrap_or_else(|error| panic!("read {path}: {error}"));
        assert!(
            source.contains(&format!("fn {anchor}(")),
            "missing regression: {evidence}"
        );
    }
    assert_eq!(manifest["exclusions"].as_array().map(Vec::len), Some(3));
}
