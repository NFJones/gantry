//! Frozen requirement assignments and evidence for composed async refinement.

use std::fs;
use std::path::Path;

use serde_json::Value;

#[test]
fn async_execution_refinement_matches_frozen_assignments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |path: &str| -> Value {
        serde_json::from_slice(
            &fs::read(root.join(path)).unwrap_or_else(|error| panic!("read {path}: {error}")),
        )
        .unwrap_or_else(|error| panic!("decode {path}: {error}"))
    };
    let manifest = read("protocol/conformance/async-execution-refinement-v1.json");
    let gate = read("protocol/conformance/async-execution-contract-v1.json");
    let review = read("protocol/requirements/reviewed-v1.json");

    assert_eq!(
        manifest["format"],
        "gantry.async-execution-refinement-evidence/v1"
    );
    assert_eq!(manifest["issue"], "GNT-ASYNC-PROOF-001");
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
                .is_some_and(|owners| owners.iter().any(|owner| owner == "GNT-ASYNC-PROOF-001"))
        })
        .map(|row| {
            serde_json::json!({
                "requirement": row["requirement"],
                "clause": row["clause"],
                "profiles": row["profiles"]
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 7);
    assert_eq!(manifest["requirements"], Value::Array(expected));

    let argument = fs::read_to_string(
        root.join(
            manifest["argument"]
                .as_str()
                .unwrap_or_else(|| panic!("missing argument")),
        ),
    )
    .unwrap_or_else(|error| panic!("read argument: {error}"));
    for heading in [
        "## Scope and claim",
        "## Assumptions and proof boundaries",
        "## Composed refinement",
        "## Requirement and evidence mapping",
        "## Counterexample classes",
    ] {
        assert!(argument.contains(heading));
    }
    assert!(argument.contains("not unbounded proofs"));
    assert!(argument.contains("exactly-once physical"));

    let models = manifest["models"]
        .as_array()
        .unwrap_or_else(|| panic!("missing models"));
    assert_eq!(models.len(), 3);
    for model in models {
        let path = model.as_str().unwrap_or_else(|| panic!("invalid model"));
        assert!(root.join(path).is_file(), "missing model: {path}");
    }

    let capabilities = manifest["capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("missing capabilities"));
    assert_eq!(capabilities.len(), 10);
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
