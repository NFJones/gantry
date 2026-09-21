//! Public conformance for the forward scalar traversal of
//! `GNT-41.5-canonical-text-traversal`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{CharValue, TEXT_CLAUSES, TextValue};

/// The declared clauses of Section 41, written out independently of the model.
const EXPECTED_CLAUSES: [&str; 11] = [
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
    "GNT-41.10-text-work-limits",
];
const TRAVERSAL_CLAUSE: &str = "GNT-41.5-canonical-text-traversal";

#[test]
fn traversal_clause_publishes_the_forward_cursor() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    let body = clause_body(&specification, TRAVERSAL_CLAUSE);
    for declaration in [
        "`scalars` publishes a cursor over a text value",
        "`next_scalar` publishes the next scalar as a `Char` value",
        "`remaining` publishes the number of scalars the cursor has not yet published",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    assert!(
        body.contains("`GNT-41.1-canonical-text-values`"),
        "the clause cites `GNT-41.1-canonical-text-values`"
    );
}

#[test]
fn traversal_publishes_exactly_the_scalar_sequence() {
    let value = admitted("a\u{e9}\u{1f600}\u{301}".as_bytes());
    assert_eq!(value.scalar_count(), 4);
    let mut cursor = value.scalars();
    assert_eq!(cursor.remaining(), 4);
    let mut published = Vec::new();
    while let Some(scalar) = cursor.next_scalar() {
        published.push(scalar);
        assert_eq!(cursor.remaining(), 4 - published.len());
    }
    assert_eq!(cursor.remaining(), 0);
    assert_eq!(cursor.next_scalar(), None);
    let expected = [
        scalar("a"),
        scalar("\u{e9}"),
        scalar("\u{1f600}"),
        scalar("\u{301}"),
    ];
    assert_eq!(published, expected);
    assert_eq!(
        TextValue::from_scalars(&published)
            .unwrap_or_else(|error| panic!("the scalar sequence is admitted: {error}")),
        value
    );
}

#[test]
fn traversal_over_the_empty_value_publishes_nothing() {
    let value = TextValue::empty();
    let mut cursor = value.scalars();
    assert_eq!(cursor.remaining(), 0);
    assert_eq!(cursor.next_scalar(), None);
    assert_eq!(TextValue::empty().scalars().next_scalar(), None);
}

#[test]
fn traversal_is_observation_only_and_cursors_are_independent() {
    let value = admitted("\u{ac01}bc".as_bytes());
    let recorded = value.clone();
    assert_eq!(value.scalar_count(), 3);
    let mut first = value.scalars();
    let mut second = value.scalars();
    assert_eq!(first.next_scalar(), second.next_scalar());
    assert_eq!(first.remaining(), 2);
    // Draining one cursor leaves the other's progress untouched.
    assert_eq!(second.next_scalar(), Some(scalar("b")));
    assert_eq!(second.next_scalar(), Some(scalar("c")));
    assert_eq!(second.remaining(), 0);
    assert_eq!(second.next_scalar(), None);
    assert_eq!(
        first.remaining(),
        2,
        "draining one cursor leaves the other where it was"
    );
    assert_eq!(first.next_scalar(), Some(scalar("b")));
    assert_eq!(first.next_scalar(), Some(scalar("c")));
    assert_eq!(first.next_scalar(), None);
    assert_eq!(first.remaining(), 0);
    assert_eq!(value, recorded, "traversal never modifies the value");
    assert_eq!(value.canonical_octets(), recorded.canonical_octets());
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn scalar(text: &str) -> CharValue {
    let mut scalars = text.chars();
    let (Some(value), None) = (scalars.next(), scalars.next()) else {
        panic!("`{text}` is exactly one scalar value");
    };
    CharValue::new(u32::from(value)).unwrap_or_else(|error| panic!("`{text}` is admitted: {error}"))
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
