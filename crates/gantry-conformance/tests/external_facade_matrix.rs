//! Isolated external-consumer checks for every supported facade feature set.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gantry_conformance::{FacadeFeatureSelection, validate_facade_features};

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
    let source = format!(
        "fn main() {{\n    let actual = gantry::compiled_features();\n    assert_eq!([actual.frontend, actual.analyzer, actual.evaluator, actual.concurrent, actual.durable], {:?});\n    assert!(!gantry::advertises_any_profile());\n    let _ = gantry::PROFILE_DEFINITIONS.len();\n    let _ = gantry::host::embedding::EMBEDDING_OPERATIONS.len();\n}}\n",
        expected
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
