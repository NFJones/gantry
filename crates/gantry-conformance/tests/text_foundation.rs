//! Public conformance for the text foundation of `GNT-41.0-text-foundation-scope` and
//! `GNT-41.1-canonical-text-values`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{CharValue, TEXT_CLAUSES, TextDiagnosticCode, TextValue};

/// The text surface this slice publishes, written out independently of the model and the note: the
/// clause anchors in specification order and the one registered refusal spelling.
const EXPECTED_CLAUSES: [&str; 3] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
];
const EXPECTED_DIAGNOSTIC: &str = "text-invalid-utf8";

#[test]
fn text_clauses_and_the_diagnostic_are_published() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(
        TEXT_CLAUSES, EXPECTED_CLAUSES,
        "the model publishes the expected clauses in specification order"
    );
    assert_eq!(
        specification.matches("<a id=\"GNT-41.").count(),
        EXPECTED_CLAUSES.len(),
        "the section declares one anchor per published clause"
    );
    let mut previous = 0_usize;
    for clause in EXPECTED_CLAUSES {
        let declaration = format!("<a id=\"{clause}\"");
        let position = specification
            .find(&declaration)
            .unwrap_or_else(|| panic!("the specification declares `{clause}`"));
        assert!(
            position > previous,
            "`{clause}` is declared after the clause before it"
        );
        previous = position;
    }
    assert!(
        specification.contains(EXPECTED_DIAGNOSTIC),
        "the section declares the registered diagnostic"
    );
    assert_eq!(
        TextDiagnosticCode::ALL.len(),
        1,
        "the section declares exactly one diagnostic"
    );
    for code in TextDiagnosticCode::ALL {
        assert_eq!(code.spelling(), EXPECTED_DIAGNOSTIC);
        assert!(EXPECTED_CLAUSES.contains(&code.owning_clause()));
    }
}

#[test]
fn text_values_admit_exactly_well_formed_utf8() {
    let empty = admitted(b"");
    assert!(empty.is_empty());
    assert_eq!(empty.scalar_count(), 0);
    assert_eq!(empty.canonical_octets(), b"");

    let text = "a\u{e9}\u{1f600}b";
    let value = admitted(text.as_bytes());
    assert_eq!(value.scalar_count(), 4);
    assert_eq!(
        value.canonical_octets(),
        text.as_bytes(),
        "admission keeps exactly the admitted octets"
    );
    assert!(!value.is_empty());

    let mark = admitted("\u{feff}".as_bytes());
    assert_eq!(
        mark.scalar_count(),
        1,
        "a byte-order mark is admitted as its scalar rather than stripped"
    );
    assert_eq!(mark.canonical_octets(), "\u{feff}".as_bytes());

    for (octets, index) in [
        (b"\xFF".as_slice(), 0_usize),
        (b"\xE2\x82".as_slice(), 0),
        (b"a\x80".as_slice(), 1),
        (b"\xC0\xAF".as_slice(), 0),
        (b"\xED\xA0\x80".as_slice(), 0),
    ] {
        let refusal = TextValue::from_octets(octets)
            .err()
            .unwrap_or_else(|| panic!("`{octets:?}` is ill-formed UTF-8"));
        assert_eq!(refusal.code(), TextDiagnosticCode::InvalidUtf8);
        assert!(
            refusal.detail().contains(&format!("octet {index}")),
            "the refusal names the failing octet index: {}",
            refusal.detail()
        );
    }
}

#[test]
fn text_slicing_publishes_only_scalars_the_value_holds() {
    // An empty value holds no scalar, so no range with a positive end may publish anything, while
    // the empty range at position zero still publishes the empty value.
    let empty = TextValue::empty();
    assert_eq!(rendered(&slice(&empty, 0, 0)), "");
    assert!(
        empty.slice_scalars(0, 1).is_none(),
        "a range whose end exceeds the empty value's scalar count publishes nothing"
    );
    assert!(
        empty.slice_scalars(1, 1).is_none(),
        "a range beyond the empty value publishes nothing"
    );
    assert_eq!(empty.scalar_at(0), None);

    let value = admitted("a\u{e9}\u{1f600}b".as_bytes());
    assert_eq!(value.scalar_count(), 4);
    assert_eq!(rendered(&slice(&value, 0, 0)), "");
    assert_eq!(rendered(&slice(&value, 0, 4)), "a\u{e9}\u{1f600}b");
    assert_eq!(rendered(&slice(&value, 1, 3)), "\u{e9}\u{1f600}");
    assert_eq!(rendered(&slice(&value, 4, 4)), "");
    assert!(
        value.slice_scalars(3, 5).is_none(),
        "an end beyond the scalar count publishes nothing"
    );
    assert!(
        value.slice_scalars(2, 1).is_none(),
        "a start after the end publishes nothing"
    );
    assert_eq!(value.scalar_at(0), Some(scalar("a")));
    assert_eq!(value.scalar_at(2), Some(scalar("\u{1f600}")));
    assert_eq!(value.scalar_at(3), Some(scalar("b")));
    assert_eq!(value.scalar_at(4), None);
    assert_eq!(
        value.scalar_count(),
        4,
        "slicing does not modify the value it reads"
    );
    assert_eq!(
        value.canonical_octets(),
        "a\u{e9}\u{1f600}b".as_bytes(),
        "slicing does not re-encode the value it reads"
    );
}

#[test]
fn text_identity_is_the_scalar_sequence() {
    let from_octets = admitted("a\u{e9}".as_bytes());
    let scalars = [scalar("a"), scalar("\u{e9}")];
    let from_scalars = TextValue::from_scalars(&scalars);
    assert_eq!(from_scalars, from_octets);
    assert_eq!(
        from_scalars.canonical_octets(),
        from_octets.canonical_octets()
    );
    assert!(admitted(b"a") < admitted(b"b"));
    assert!(admitted(b"b") < admitted("\u{e9}".as_bytes()));
    assert!(admitted("\u{e9}".as_bytes()) < admitted("\u{1f600}".as_bytes()));
    assert_eq!(TextValue::empty(), TextValue::from_scalars(&[]));
}

#[test]
fn text_note_names_every_declared_clause_and_the_diagnostic() {
    let note = read_workspace_file("docs/text-foundation.md");
    for clause in TEXT_CLAUSES {
        assert!(note.contains(clause), "the note names `{clause}`");
    }
    assert!(
        note.contains(EXPECTED_DIAGNOSTIC),
        "the note names the registered diagnostic"
    );
    // Prose assertions read the note with its whitespace flattened, so re-wrapping a paragraph
    // cannot change whether the note declares a non-claim.
    let flat = note.split_whitespace().collect::<Vec<_>>().join(" ");
    for phrase in [
        "no grapheme-cluster segmentation",
        "no case mapping",
        "no regular expression",
        "no locale",
        "no compatibility form",
        "no `String` method",
    ] {
        assert!(flat.contains(phrase), "the note declares `{phrase}`");
    }
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn slice(value: &TextValue, start: usize, end: usize) -> TextValue {
    value
        .slice_scalars(start, end)
        .unwrap_or_else(|| panic!("`{start}..{end}` is a scalar-boundary slice"))
}

fn scalar(text: &str) -> CharValue {
    let mut scalars = text.chars();
    let (Some(value), None) = (scalars.next(), scalars.next()) else {
        panic!("`{text}` is exactly one scalar value");
    };
    CharValue::new(u32::from(value))
        .unwrap_or_else(|error| panic!("`{text}` is an admitted scalar: {error}"))
}

fn rendered(value: &TextValue) -> String {
    String::from_utf8(value.canonical_octets().to_vec())
        .unwrap_or_else(|error| panic!("the canonical octets are UTF-8: {error}"))
}

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}
