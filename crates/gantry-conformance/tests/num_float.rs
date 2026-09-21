//! Conformance for the finite float algorithms of `GNT-40.5`.
//!
//! The lane requires the specification and the note to publish the clause and the model to be exact
//! and total over the canonical `Float` domain: `negate` and `abs` take one operand, `minimum` and
//! `maximum` two, none refuses, rounds, or consults a host math library or ambient rounding mode,
//! and either signed zero is the canonical zero.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{BinaryFloatAlgorithm, NUM_CLAUSES, UnaryFloatAlgorithm};
use gantry::numeric::GantryFloat;

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

fn float(value: f64) -> GantryFloat {
    GantryFloat::new(value).unwrap_or_else(|| panic!("`{value}` is a finite binary64 value"))
}

#[test]
fn finite_float_algorithms_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    let anchor = "GNT-40.5-finite-float-algorithms";
    assert_eq!(
        NUM_CLAUSES.last(),
        Some(&anchor),
        "the finite-float clause is the specification's final clause"
    );
    assert!(note.contains(anchor), "the note names `{anchor}`");
    let clause = clause_body(&specification, anchor);
    assert!(
        specification.trim_end().ends_with(clause.trim_end()),
        "the final clause body runs to the end of the specification"
    );
    assert_eq!(
        UnaryFloatAlgorithm::ALL.map(UnaryFloatAlgorithm::wire_name),
        ["negate", "abs"]
    );
    assert_eq!(
        BinaryFloatAlgorithm::ALL.map(BinaryFloatAlgorithm::wire_name),
        ["minimum", "maximum"]
    );
    for spelling in [
        UnaryFloatAlgorithm::Negate.wire_name(),
        UnaryFloatAlgorithm::Abs.wire_name(),
        BinaryFloatAlgorithm::Minimum.wire_name(),
        BinaryFloatAlgorithm::Maximum.wire_name(),
    ] {
        assert!(
            clause.contains(&format!("`{spelling}`")),
            "the clause publishes the backticked spelling `{spelling}`"
        );
    }
    for surface in ["`UnaryFloatAlgorithm`", "`BinaryFloatAlgorithm`"] {
        assert!(
            clause.contains(surface),
            "the clause names the model surface {surface}"
        );
    }
    for application in [
        "`UnaryFloatAlgorithm::apply`",
        "`BinaryFloatAlgorithm::apply`",
    ] {
        assert!(
            note.contains(application),
            "the note names the model application {application}"
        );
    }
}

#[test]
fn finite_float_algorithms_are_exact_and_total() {
    let operands = [
        -f64::MAX,
        -1.0,
        -f64::MIN_POSITIVE,
        f64::from_bits(1),
        0.0,
        1.0,
        f64::MIN_POSITIVE,
        f64::MAX,
    ];
    assert_eq!(float(-0.0), float(0.0), "either signed zero is canonical");
    for left in operands {
        let value = float(left);
        assert_eq!(UnaryFloatAlgorithm::Negate.apply(value), float(-left));
        assert_eq!(
            UnaryFloatAlgorithm::Negate.apply(UnaryFloatAlgorithm::Negate.apply(value)),
            value,
            "`negate` is its own inverse"
        );
        assert_eq!(UnaryFloatAlgorithm::Abs.apply(value), float(left.abs()));
        assert_eq!(
            UnaryFloatAlgorithm::Abs.apply(UnaryFloatAlgorithm::Negate.apply(value)),
            UnaryFloatAlgorithm::Abs.apply(value),
            "`abs` ignores the sign"
        );
        assert_eq!(
            BinaryFloatAlgorithm::Maximum.apply(value, UnaryFloatAlgorithm::Negate.apply(value)),
            UnaryFloatAlgorithm::Abs.apply(value),
            "`maximum` of a value and its negation is its magnitude"
        );
        for right in operands {
            let other = float(right);
            let lesser = if left <= right { float(left) } else { other };
            let greater = if left >= right { float(left) } else { other };
            assert_eq!(BinaryFloatAlgorithm::Minimum.apply(value, other), lesser);
            assert_eq!(BinaryFloatAlgorithm::Maximum.apply(value, other), greater);
            assert_eq!(
                BinaryFloatAlgorithm::Minimum.apply(value, other),
                BinaryFloatAlgorithm::Minimum.apply(other, value),
                "`minimum` is commutative"
            );
            assert_eq!(
                BinaryFloatAlgorithm::Maximum.apply(value, other),
                BinaryFloatAlgorithm::Maximum.apply(other, value),
                "`maximum` is commutative"
            );
        }
        assert_eq!(
            BinaryFloatAlgorithm::Minimum.apply(value, value),
            value,
            "`minimum` is idempotent"
        );
        assert_eq!(
            BinaryFloatAlgorithm::Maximum.apply(value, value),
            value,
            "`maximum` is idempotent"
        );
    }
    assert_eq!(
        UnaryFloatAlgorithm::Negate.apply(float(0.0)),
        float(0.0),
        "negating the canonical zero publishes the canonical zero"
    );
    assert_eq!(
        UnaryFloatAlgorithm::Abs.apply(float(-0.0)),
        float(0.0),
        "the magnitude of either zero is the canonical zero"
    );
}
