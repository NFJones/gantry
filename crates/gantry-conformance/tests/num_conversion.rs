//! Conformance for the numeric conversions of `GNT-40.3`.
//!
//! The lanes require the specification and the note to publish the clause, the `Int`-to-`Float`
//! conversion to be total and exact, and the `Float`-to-`Int` conversion to yield exactly one
//! canonical value or nothing, with no truncation, rounding, saturation, wrapping, or coercion.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{NUM_CLAUSES, NumericConversion, float_to_int, int_to_float};
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

fn integer(value: i64) -> GantryInt {
    GantryInt::new(value).unwrap_or_else(|| panic!("`{value}` is inside the canonical Int range"))
}

fn float(value: f64) -> GantryFloat {
    GantryFloat::new(value).unwrap_or_else(|| panic!("`{value}` is a finite binary64 value"))
}

#[test]
fn numeric_conversion_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    let anchor = "GNT-40.3-numeric-conversions";
    assert!(NUM_CLAUSES.contains(&anchor));
    assert!(specification.contains(&format!("<a id=\"{anchor}\"></a>")));
    assert!(note.contains(anchor), "the note names `{anchor}`");
    assert_eq!(
        NumericConversion::ALL.map(NumericConversion::wire_name),
        ["int-to-float", "float-to-int"]
    );
    for spelling in [
        "int-to-float",
        "float-to-int",
        "`int_to_float`",
        "`float_to_int`",
    ] {
        let published = if spelling.starts_with('`') {
            note.contains(spelling)
        } else {
            clause_body(&specification, anchor).contains(spelling)
        };
        assert!(published, "the clause and note publish `{spelling}`");
    }
}

#[test]
fn numeric_conversions_are_exact_and_refuse_outside_the_domain() {
    // The `Int`-to-`Float` conversion is total and exact at every boundary.
    for value in [
        GANTRY_INT_MAXIMUM,
        GANTRY_INT_MINIMUM,
        GANTRY_INT_MAXIMUM - 1,
        GANTRY_INT_MINIMUM + 1,
        0,
        1,
        -1,
    ] {
        let converted = int_to_float(integer(value));
        assert_eq!(converted, float(value as f64), "`{value}` converts exactly");
        assert_eq!(
            float_to_int(converted),
            Some(integer(value)),
            "`{value}` round-trips"
        );
    }

    // The `Float`-to-`Int` conversion refuses a fractional operand rather than truncating.
    for fractional in [0.5, -0.5, 1.5, -1.5, 4503599627370495.5] {
        assert_eq!(
            float_to_int(float(fractional)),
            None,
            "`{fractional}` is not integral"
        );
    }
    // It refuses an operand outside the canonical domain rather than saturating or wrapping.
    for outside in [
        (GANTRY_INT_MAXIMUM as f64) + 1.0,
        (GANTRY_INT_MINIMUM as f64) - 1.0,
        1e300,
        -1e300,
    ] {
        assert_eq!(
            float_to_int(float(outside)),
            None,
            "`{outside}` is outside the canonical Int domain"
        );
    }
    // Both boundaries convert exactly and are in range.
    assert_eq!(
        float_to_int(float(GANTRY_INT_MAXIMUM as f64)),
        Some(integer(GANTRY_INT_MAXIMUM))
    );
    assert_eq!(
        float_to_int(float(GANTRY_INT_MINIMUM as f64)),
        Some(integer(GANTRY_INT_MINIMUM))
    );
}

/// `GNT-40.3` is the specification's final clause, so extracting its body takes `clause_body`'s
/// no-next-anchor path: the body must run to the end of the specification and publish both
/// conversion spellings, which is the tail branch this lane owns.
#[test]
fn numeric_conversions_clause_body_exercises_the_final_clause_tail() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let clause = clause_body(&specification, "GNT-40.3-numeric-conversions");

    assert_eq!(
        NUM_CLAUSES.last(),
        Some(&"GNT-40.3-numeric-conversions"),
        "the conversions clause is the specification's final clause"
    );
    assert!(
        specification.trim_end().ends_with(clause.trim_end()),
        "the final clause body runs to the end of the specification"
    );
    for spelling in [
        NumericConversion::IntToFloat.wire_name(),
        NumericConversion::FloatToInt.wire_name(),
    ] {
        assert!(
            clause.contains(&format!("`{spelling}`")),
            "the final clause publishes the backticked spelling `{spelling}`"
        );
    }
}
