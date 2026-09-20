//! Coupling lane: every diagnostic code in the analyzer sources is registered.
//!
//! The source-substrate registry (`crates/gantry-core/src/source.rs`) is the vocabulary tooling
//! reads, but `DiagnosticCode::new` validates only the kebab-case shape, so an emitted code could
//! stay unregistered indefinitely. This lane scans every code-shaped string literal in
//! `crates/gantry-analysis/src` — whether it is passed to a diagnostic constructor, asserted in a
//! test, or compared against an emitted code — and requires each one to appear in
//! `DIAGNOSTIC_CODE_REGISTRY`, except for the field-value spellings listed below, which are
//! structured-diagnostic field values and wire names rather than diagnostic codes.

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

/// Code-shaped analyzer literals that are structured-diagnostic field values or wire names rather
/// than diagnostic codes: the occurrence and access kinds, classifier values, namespace
/// comparisons, binding positions, and expression forms the analyzer reports inside a diagnostic's
/// `fields` map.
const FIELD_VALUE_SPELLINGS: [&str; 12] = [
    "action-result",
    "binding-annotation",
    "boundary-position",
    "cross-namespace",
    "declared-type",
    "instantiation-argument",
    "nested-component",
    "non-signature",
    "open-member",
    "operand-type",
    "prompt-result",
    "same-namespace",
];

/// Returns the code-shaped string literals in one analyzer source file.
///
/// A candidate is a lowercase kebab-case literal with at least one hyphen, which excludes prose,
/// schema names, paths, and wire spellings outside this vocabulary.
fn code_shaped_literals(source: &str) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    for (index, _) in source.match_indices('"') {
        let rest = &source[index + 1..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        let literal = &rest[..end];
        if !literal.contains('-')
            || !literal
                .chars()
                .any(|character| character.is_ascii_lowercase())
            || !literal.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
        {
            continue;
        }
        codes.insert(literal.to_owned());
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
    let mut pending = vec![root.join("crates/gantry-analysis/src")];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("the analyzer source directory is readable: {error}"))
        {
            let path = entry
                .unwrap_or_else(|error| panic!("the analyzer source entry is readable: {error}"))
                .path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("the analyzer source is readable: {error}"));
            observed.extend(code_shaped_literals(&source));
        }
    }

    for spelling in FIELD_VALUE_SPELLINGS {
        assert!(
            observed.remove(spelling),
            "`{spelling}` is a field value, not a diagnostic code, so the scan must observe it"
        );
    }

    assert!(
        observed.len() >= 100,
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
