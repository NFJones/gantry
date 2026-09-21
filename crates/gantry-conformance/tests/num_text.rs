//! Conformance for the canonical numeric text of `GNT-40.6`.
//!
//! The lane requires the specification and the note to publish the clause and the model to format
//! exactly the canonical spelling of a value and to parse exactly that spelling: a non-canonical
//! spelling of the same value, a bare `+`, `-0`, a separator, or a magnitude outside the domain is
//! refused rather than normalized, and the two directions round-trip exactly.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    NUM_CLAUSES, format_canonical_float, format_canonical_int, parse_canonical_float,
    parse_canonical_int,
};
use gantry::numeric::{GANTRY_INT_MAXIMUM, GANTRY_INT_MINIMUM, GantryFloat, GantryInt};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
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

fn element(value: i64) -> GantryInt {
    GantryInt::new(value).unwrap_or_else(|| panic!("`{value}` is inside the canonical Int range"))
}

fn float(value: f64) -> GantryFloat {
    GantryFloat::new(value).unwrap_or_else(|| panic!("`{value}` is a finite binary64 value"))
}

#[test]
fn canonical_numeric_text_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    let anchor = "GNT-40.6-canonical-numeric-text";
    assert!(
        NUM_CLAUSES.contains(&anchor),
        "the numeric-text clause is declared by the numeric clause vocabulary"
    );
    assert!(note.contains(anchor), "the note names `{anchor}`");
    let clause = clause_body(&specification, anchor);
    assert!(
        !specification.trim_end().ends_with(clause.trim_end()),
        "the numeric-text clause is no longer the specification's final clause"
    );
    for surface in [
        "`format_canonical_int`",
        "`parse_canonical_int`",
        "`format_canonical_float`",
        "`parse_canonical_float`",
    ] {
        assert!(
            clause.contains(surface),
            "the clause names the model helper {surface}"
        );
        assert!(
            note.contains(surface),
            "the note names the model helper {surface}"
        );
    }
    for citation in [
        "`GNT-35.2-literal-formation-and-canonical-text`",
        "`GNT-8.5`",
        "`GNT-5.1`",
    ] {
        assert!(clause.contains(citation), "the clause cites {citation}");
    }
}

#[test]
fn canonical_numeric_text_round_trips_exactly() {
    for value in [
        GANTRY_INT_MINIMUM,
        GANTRY_INT_MINIMUM + 1,
        -1,
        0,
        1,
        GANTRY_INT_MAXIMUM - 1,
        GANTRY_INT_MAXIMUM,
    ] {
        let element = element(value);
        let text = format_canonical_int(element);
        assert_eq!(
            parse_canonical_int(&text),
            Some(element),
            "`{text}` round-trips"
        );
        assert!(
            !text.starts_with('+') && !(text.len() > 1 && text.starts_with('0')),
            "`{text}` is canonical"
        );
    }
    assert_eq!(format_canonical_int(element(0)), "0");
    assert_eq!(format_canonical_int(element(-7)), "-7");
    for refused in [
        "+1",
        "01",
        "-0",
        "1_0",
        "1.0",
        "1e0",
        " 1",
        "1 ",
        "9007199254740992",
    ] {
        assert_eq!(
            parse_canonical_int(refused),
            None,
            "the non-canonical text `{refused}` is refused"
        );
    }
    assert_eq!(
        parse_canonical_int("9007199254740991"),
        Some(element(GANTRY_INT_MAXIMUM)),
        "the canonical text of the maximum is admitted"
    );

    for value in [
        -f64::MAX,
        -1.0,
        -0.5,
        -f64::MIN_POSITIVE,
        0.0,
        0.5,
        1.0,
        f64::MIN_POSITIVE,
        f64::MAX,
    ] {
        let element = float(value);
        let text = format_canonical_float(element);
        assert_eq!(
            parse_canonical_float(&text),
            Some(element),
            "`{text}` round-trips"
        );
        assert!(!text.starts_with('+'), "`{text}` carries no bare plus");
        if !text.contains('.') && !text.contains('e') && !text.contains('E') {
            let alternate = format!("{text}.0");
            assert_eq!(
                parse_canonical_float(&alternate),
                None,
                "`{alternate}` spells the same value non-canonically"
            );
        }
    }
    assert_eq!(format_canonical_float(float(0.0)), "0");
    for refused in ["+1", "-0", "NaN", "inf", "-inf", "1 "] {
        assert_eq!(
            parse_canonical_float(refused),
            None,
            "the non-canonical text `{refused}` is refused"
        );
    }
    assert_eq!(parse_canonical_float("0.5"), Some(float(0.5)));
}
