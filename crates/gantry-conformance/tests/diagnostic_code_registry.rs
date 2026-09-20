//! Coupling lane: every diagnostic code the analyzer emits is registered.
//!
//! The source-substrate registry (`crates/gantry-core/src/source.rs`) is the vocabulary tooling
//! reads, but `DiagnosticCode::new` validates only the kebab-case shape, so an emitted code could
//! stay unregistered indefinitely. This lane scans the analyzer's string-code emission sites —
//! calls into the `*diagnostic(` helpers and direct `DiagnosticCode::new("...")` constructions —
//! and requires each observed code to appear in `DIAGNOSTIC_CODE_REGISTRY`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::source::DIAGNOSTIC_CODE_REGISTRY;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

/// Returns the code literals passed to the analyzer's diagnostic constructors.
///
/// A candidate is the first string literal after a `diagnostic(` call or a
/// `DiagnosticCode::new(` construction, and it counts only when every character is a lowercase
/// letter, a digit, or a hyphen with at least one hyphen, which excludes messages and prose.
fn emitted_codes(source: &str) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    for marker in ["diagnostic(", "DiagnosticCode::new("] {
        for (index, _) in source.match_indices(marker) {
            let rest = &source[index + marker.len()..];
            let Some(candidate) = rest.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some(end) = candidate.find('"') else {
                continue;
            };
            let literal = &candidate[..end];
            if !literal.is_empty()
                && literal.contains('-')
                && literal.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
            {
                codes.insert(literal.to_owned());
            }
        }
    }
    codes
}

#[test]
fn analyzer_emitted_codes_are_registered() {
    let root = workspace_root();
    let registered: BTreeSet<String> = DIAGNOSTIC_CODE_REGISTRY
        .iter()
        .map(|definition| definition.code.to_owned())
        .collect();

    let mut observed = BTreeSet::new();
    let directory = root.join("crates/gantry-analysis/src");
    for entry in fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("the analyzer source directory is readable: {error}"))
    {
        let path = entry
            .unwrap_or_else(|error| panic!("the analyzer source entry is readable: {error}"))
            .path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("the analyzer source is readable: {error}"));
        observed.extend(emitted_codes(&source));
    }

    assert!(
        observed.len() >= 80,
        "the scan observed {} analyzer codes; a refactor that breaks the scanner must fail here",
        observed.len()
    );
    let missing = observed
        .difference(&registered)
        .cloned()
        .collect::<Vec<String>>();
    assert!(
        missing.is_empty(),
        "analyzer-emitted codes are missing from DIAGNOSTIC_CODE_REGISTRY: {missing:?}"
    );
}
