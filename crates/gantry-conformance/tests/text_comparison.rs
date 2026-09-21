//! Public conformance for the canonical scalar comparison of
//! `GNT-41.6-canonical-text-comparison`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{TEXT_CLAUSES, TextOrdering, TextValue};

/// The declared clauses of Section 41, written out independently of the model.
const EXPECTED_CLAUSES: [&str; 12] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
    "GNT-41.3-canonical-text-case-mapping",
    "GNT-41.4-canonical-text-builders",
    "GNT-41.5-canonical-text-traversal",
    "GNT-41.6-canonical-text-comparison",
    "GNT-41.7-canonical-grapheme-clusters",
    "GNT-41.8-bounded-text-matching",
    "GNT-41.9-canonical-text-conversions",
    "GNT-41.10-canonical-text-admission-bound",
    "GNT-41.11-canonical-text-value-bound",
];
const COMPARISON_CLAUSE: &str = "GNT-41.6-canonical-text-comparison";

#[test]
fn comparison_clause_publishes_the_three_results() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    assert_eq!(
        TextOrdering::ALL.map(TextOrdering::spelling),
        ["less", "equal", "greater"]
    );
    let body = clause_body(&specification, COMPARISON_CLAUSE);
    for declaration in [
        "`compare` publishes `less`, `equal`, or `greater`",
        "it publishes `equal` exactly when the two values are equal",
        "a proper prefix of a longer sequence is `less` than that longer sequence",
        "a comparison only observes the two scalar sequences it compares and never modifies",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    for citation in [
        "`GNT-41.1-canonical-text-values`",
        "`GNT-41.2-canonical-text-normalization`",
        "`GNT-41.3-canonical-text-case-mapping`",
    ] {
        assert!(body.contains(citation), "the clause cites {citation}");
    }
}

#[test]
fn comparison_orders_by_scalar_sequence() {
    assert_eq!(ordering("", "a"), TextOrdering::Less);
    assert_eq!(ordering("a", "ab"), TextOrdering::Less);
    assert_eq!(ordering("ab", "a"), TextOrdering::Greater);
    // Scalar value decides, not octet length: 'z' U+007A precedes 'é' U+00E9, which precedes the
    // astral U+1F600.
    assert_eq!(ordering("z", "\u{e9}"), TextOrdering::Less);
    assert_eq!(ordering("\u{e9}", "\u{1f600}"), TextOrdering::Less);
    assert_eq!(ordering("a\u{e9}", "a\u{e9}"), TextOrdering::Equal);
}

#[test]
fn comparison_is_total_lawful_and_consistent_with_equality() {
    let sample = ["", "a", "ab", "b", "\u{e9}", "\u{1f600}", "abc"];
    for left in sample {
        for right in sample {
            let first = admitted(left.as_bytes());
            let second = admitted(right.as_bytes());
            assert_eq!(
                first.compare(&second) == TextOrdering::Equal,
                first == second,
                "`equal` is exactly equality"
            );
            assert_eq!(
                first.compare(&second),
                reverse(second.compare(&first)),
                "comparison is antisymmetric"
            );
            assert_eq!(first.compare(&first), TextOrdering::Equal);
        }
    }
    for a in sample {
        for b in sample {
            for c in sample {
                let first = admitted(a.as_bytes());
                let second = admitted(b.as_bytes());
                let third = admitted(c.as_bytes());
                if first.compare(&second) == TextOrdering::Less
                    && second.compare(&third) == TextOrdering::Less
                {
                    assert_eq!(
                        first.compare(&third),
                        TextOrdering::Less,
                        "comparison is transitive"
                    );
                }
            }
        }
    }
}

#[test]
fn comparison_is_case_sensitive_and_never_normalizes() {
    let composed = admitted("\u{e9}".as_bytes());
    let decomposed = admitted("e\u{301}".as_bytes());
    assert_ne!(composed, decomposed);
    assert_eq!(composed.compare(&decomposed), TextOrdering::Greater);
    let sharp = admitted("\u{df}".as_bytes());
    let doubled = admitted(b"SS");
    assert_ne!(sharp.compare(&doubled), TextOrdering::Equal);
    assert_eq!(doubled.compare(&sharp), TextOrdering::Less);
}

#[test]
fn comparison_is_observation_only() {
    let left = admitted("a\u{e9}".as_bytes());
    let right = admitted(b"ab");
    let recorded_left = left.clone();
    let recorded_right = right.clone();
    // The second scalar decides: 'b' U+0062 precedes 'é' U+00E9, so `right` orders first even
    // though `left` carries more octets.
    assert_eq!(left.compare(&right), TextOrdering::Greater);
    assert_eq!(right.compare(&left), TextOrdering::Less);
    assert_eq!(
        left, recorded_left,
        "comparison does not modify either value"
    );
    assert_eq!(right, recorded_right);
    assert_eq!(left.canonical_octets(), recorded_left.canonical_octets());
    assert_eq!(right.canonical_octets(), recorded_right.canonical_octets());
    assert!(
        right < left,
        "comparison agrees with the canonical ordering"
    );
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn ordering(left: &str, right: &str) -> TextOrdering {
    admitted(left.as_bytes()).compare(&admitted(right.as_bytes()))
}

fn reverse(ordering: TextOrdering) -> TextOrdering {
    match ordering {
        TextOrdering::Less => TextOrdering::Greater,
        TextOrdering::Equal => TextOrdering::Equal,
        TextOrdering::Greater => TextOrdering::Less,
    }
}

/// Returns the body of one clause: the text between its anchor and the next anchor, or to the end
/// of the specification when the clause is the final one.
fn clause_body<'a>(specification: &'a str, anchor: &str) -> &'a str {
    let declaration = format!("<a id=\"{anchor}\"></a>");
    let start = specification
        .find(&declaration)
        .unwrap_or_else(|| panic!("the specification anchors `{anchor}`"))
        + declaration.len();
    let rest = &specification[start..];
    match rest.find("<a id=") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}
