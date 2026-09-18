//! Section 38 evidence for the typed error, assertion, panic, and divergence contract.
//!
//! Each test is a pure function of the published specification and the public `gantry::ir`
//! surface: no test reads host state, a clock, a process identity, or an environment fact, and
//! the section anchors, the closed failure-channel vocabulary, and the frozen diagnostics are
//! asserted together.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{ERROR_SEMANTICS_CLAUSES, ErrorSemanticsDiagnosticCode, FailureChannel};

/// Asserts one closed vocabulary is sorted by wire name and strictly decodes.
fn assert_vocabulary_closed<T>(
    members: &[T],
    wire_name: fn(T) -> &'static str,
    from_wire_name: fn(&str) -> Option<T>,
) where
    T: Copy + std::fmt::Debug + PartialEq,
{
    let mut prior: Option<&'static str> = None;
    for member in members {
        let wire = wire_name(*member);
        if let Some(previous) = prior {
            assert!(
                previous < wire,
                "the vocabulary must be sorted by wire name: {previous} then {wire}"
            );
        }
        assert_eq!(
            from_wire_name(wire),
            Some(*member),
            "the wire spelling `{wire}` must strictly decode"
        );
        prior = Some(wire);
    }
    assert_eq!(from_wire_name("not-a-member"), None);
}

/// The workspace root of this test crate.
fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crates/gantry-conformance must live under the workspace root"),
    }
}

/// Reads one required fixture file.
fn read(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("could not read {}: {error}", path.display()),
    }
}

#[test]
fn section_38_anchors_and_nonclaims_are_published() {
    let specification = read(&workspace_root().join("SPEC.md"));
    assert_eq!(
        ERROR_SEMANTICS_CLAUSES.len(),
        5,
        "Section 38 publishes five clause anchors"
    );
    let mut prior = 0_usize;
    for clause in ERROR_SEMANTICS_CLAUSES {
        let marker = format!("<a id=\"{clause}\"></a>");
        let position = match specification.find(&marker) {
            Some(position) => position,
            None => panic!("SPEC.md must publish the anchor {clause}"),
        };
        assert!(
            position > prior,
            "the anchors of Section 38 appear in clause order"
        );
        prior = position;
        assert!(
            specification.contains(&format!("**[{clause}] ")),
            "the clause {clause} carries no clause text"
        );
    }
    assert!(
        specification.contains("## 38. Typed Errors, Assertions, Panic, and Divergence"),
        "SPEC.md must publish the Section 38 heading"
    );
    assert!(
        specification.contains("no implicit `Never` subtyping"),
        "the section must publish its non-claims"
    );
    for clause in ERROR_SEMANTICS_CLAUSES {
        assert!(
            ErrorSemanticsDiagnosticCode::ALL
                .iter()
                .any(|code| code.requirement() == clause),
            "the clause {clause} owns no frozen diagnostic"
        );
    }
    let start = match specification.find("<a id=\"GNT-38.0-error-and-divergence-scope\"></a>") {
        Some(position) => position,
        None => panic!("Section 38.0 must be published"),
    };
    let end = match specification[start..].find("<a id=\"GNT-38.1-typed-error-propagation\"></a>") {
        Some(offset) => start + offset,
        None => panic!("Section 38.1 must be published"),
    };
    let scope = &specification[start..end];
    for code in ErrorSemanticsDiagnosticCode::ALL {
        assert!(
            scope.contains(&format!("`{}`", code.as_str())),
            "the scope clause does not list the frozen diagnostic {}",
            code.as_str()
        );
    }
}

#[test]
fn failure_channels_are_closed_and_keep_the_domain_error_apart() {
    assert_vocabulary_closed(
        &FailureChannel::ALL,
        FailureChannel::wire_name,
        FailureChannel::from_wire_name,
    );
    assert!(FailureChannel::DomainError.is_domain_error());
    for channel in FailureChannel::ALL {
        assert_eq!(
            channel.is_domain_error(),
            channel == FailureChannel::DomainError,
            "only the domain-error channel is a typed domain error"
        );
    }
}

#[test]
fn error_semantics_diagnostics_are_frozen_and_single_owner() {
    let mut spellings = BTreeSet::new();
    let mut prior: Option<&str> = None;
    for code in ErrorSemanticsDiagnosticCode::ALL {
        let spelling = code.as_str();
        if let Some(previous) = prior {
            assert!(
                previous < spelling,
                "the diagnostic registry is sorted: {previous} then {spelling}"
            );
        }
        assert!(
            spellings.insert(spelling),
            "one distinct diagnostic per refusal condition"
        );
        assert!(!code.meaning().is_empty(), "every code publishes a meaning");
        assert!(
            ERROR_SEMANTICS_CLAUSES.contains(&code.requirement()),
            "{} names a clause Section 38 does not publish",
            code.as_str()
        );
        prior = Some(spelling);
    }
    assert_eq!(spellings.len(), ErrorSemanticsDiagnosticCode::ALL.len());
    for code in ErrorSemanticsDiagnosticCode::ALL {
        assert_eq!(
            ErrorSemanticsDiagnosticCode::from_wire_name(code.as_str()),
            Some(code)
        );
    }
    assert_eq!(
        ErrorSemanticsDiagnosticCode::from_wire_name("not-a-code"),
        None
    );
    assert_eq!(
        ErrorSemanticsDiagnosticCode::NeverBoundaryRefused.requirement(),
        "GNT-38.4-boundaries-durability-and-non-claims"
    );
}
