//! Conformance for the canonical integer overflow modes of `GNT-40.7`.
//!
//! The lane requires the specification and the note to publish the clause and the model to be exact
//! in every declared mode over the canonical `Int` domain: `refuse` publishes the exact result or
//! refuses under `integer-overflow`, `saturating` publishes the exact result or the domain's nearer
//! bound, and `wrapping` publishes the exact result reduced modulo the domain's span — never the
//! declared-width behaviour of a fixed-width scalar — while a zero divisor refuses in every mode.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{CheckedIntegerAlgorithm, NUM_CLAUSES, OverflowMode, apply_in_mode};
use gantry::numeric::{GANTRY_INT_MAXIMUM, GANTRY_INT_MINIMUM, GantryInt};
use gantry::portable::DeterministicEvaluationCode;

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

fn exact(algorithm: CheckedIntegerAlgorithm, left: i64, right: i64) -> Option<i128> {
    let dividend = i128::from(left);
    let divisor = i128::from(right);
    match algorithm {
        CheckedIntegerAlgorithm::Add => Some(dividend + divisor),
        CheckedIntegerAlgorithm::Subtract => Some(dividend - divisor),
        CheckedIntegerAlgorithm::Multiply => Some(dividend * divisor),
        CheckedIntegerAlgorithm::Divide => (divisor != 0).then(|| dividend / divisor),
        CheckedIntegerAlgorithm::Remainder => (divisor != 0).then(|| dividend % divisor),
    }
}

#[test]
fn canonical_modes_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    let anchor = "GNT-40.7-canonical-integer-overflow-modes";
    assert_eq!(
        NUM_CLAUSES.last(),
        Some(&anchor),
        "the overflow-mode clause is the specification's final clause"
    );
    assert!(note.contains(anchor), "the note names `{anchor}`");
    let clause = clause_body(&specification, anchor);
    assert!(
        specification.trim_end().ends_with(clause.trim_end()),
        "the final clause body runs to the end of the specification"
    );
    assert_eq!(
        OverflowMode::ALL.map(OverflowMode::as_str),
        ["refuse", "wrapping", "saturating"]
    );
    for spelling in OverflowMode::ALL.map(OverflowMode::as_str) {
        assert!(
            clause.contains(&format!("`{spelling}`")),
            "the clause publishes the backticked spelling `{spelling}`"
        );
    }
    for citation in [
        "`GNT-35.3-checked-arithmetic-and-overflow-modes`",
        "`GNT-5.1`",
    ] {
        assert!(clause.contains(citation), "the clause cites {citation}");
    }
    let application = "`apply_in_mode`";
    assert!(
        clause.contains(application),
        "the clause names the model application {application}"
    );
    assert!(
        note.contains(application),
        "the note names the model application {application}"
    );
}

#[test]
fn canonical_modes_are_exact_in_every_mode() {
    let operands = [
        GANTRY_INT_MINIMUM,
        GANTRY_INT_MINIMUM + 1,
        -2,
        -1,
        0,
        1,
        2,
        GANTRY_INT_MAXIMUM - 1,
        GANTRY_INT_MAXIMUM,
    ];
    let minimum = i128::from(GANTRY_INT_MINIMUM);
    let maximum = i128::from(GANTRY_INT_MAXIMUM);
    let span = maximum - minimum + 1;
    for algorithm in CheckedIntegerAlgorithm::ALL {
        for left in operands {
            for right in operands {
                let refused = apply_in_mode(
                    OverflowMode::Refuse,
                    algorithm,
                    element(left),
                    element(right),
                );
                assert_eq!(
                    refused,
                    algorithm.apply(element(left), element(right)),
                    "`refuse` delegates to the algorithm of `GNT-40.2`"
                );
                match exact(algorithm, left, right) {
                    None => {
                        for mode in OverflowMode::ALL {
                            assert!(
                                apply_in_mode(mode, algorithm, element(left), element(right))
                                    .is_err(),
                                "`{}` with a zero divisor refuses in `{}` mode",
                                algorithm.wire_name(),
                                mode.as_str()
                            );
                        }
                    }
                    Some(value) => {
                        let in_domain = (minimum..=maximum).contains(&value);
                        let saturated = apply_in_mode(
                            OverflowMode::Saturating,
                            algorithm,
                            element(left),
                            element(right),
                        );
                        let wrapped = apply_in_mode(
                            OverflowMode::Wrapping,
                            algorithm,
                            element(left),
                            element(right),
                        );
                        if in_domain {
                            let published =
                                element(i64::try_from(value).expect("inside the domain"));
                            assert_eq!(
                                refused,
                                Ok(published),
                                "`refuse` publishes the exact result"
                            );
                            assert_eq!(
                                saturated,
                                Ok(published),
                                "`saturating` publishes the exact result when it is canonical"
                            );
                            assert_eq!(
                                wrapped,
                                Ok(published),
                                "`wrapping` publishes the exact result when it is canonical"
                            );
                        } else {
                            assert_eq!(
                                refused,
                                Err(DeterministicEvaluationCode::IntegerOverflow),
                                "`refuse` refuses outside the domain"
                            );
                            assert_eq!(
                                saturated,
                                Ok(element(
                                    i64::try_from(value.clamp(minimum, maximum))
                                        .expect("inside the domain")
                                )),
                                "`saturating` publishes the nearer domain bound"
                            );
                            assert_eq!(
                                wrapped,
                                Ok(element(
                                    i64::try_from(minimum + (value - minimum).rem_euclid(span))
                                        .expect("inside the domain")
                                )),
                                "`wrapping` publishes the canonical-domain reduction"
                            );
                        }
                    }
                }
            }
        }
    }
    // The two discriminating cases: the canonical-domain reduction is not the declared-width one.
    assert_eq!(
        apply_in_mode(
            OverflowMode::Wrapping,
            CheckedIntegerAlgorithm::Add,
            element(GANTRY_INT_MAXIMUM),
            element(1)
        ),
        Ok(element(GANTRY_INT_MINIMUM)),
        "`{}` + 1 wraps to the domain minimum, not to `2^53`",
        GANTRY_INT_MAXIMUM
    );
    assert_eq!(
        apply_in_mode(
            OverflowMode::Wrapping,
            CheckedIntegerAlgorithm::Subtract,
            element(GANTRY_INT_MINIMUM),
            element(1)
        ),
        Ok(element(GANTRY_INT_MAXIMUM)),
        "the domain minimum minus one wraps to the domain maximum"
    );
    assert_eq!(
        apply_in_mode(
            OverflowMode::Wrapping,
            CheckedIntegerAlgorithm::Multiply,
            element(GANTRY_INT_MINIMUM),
            element(2)
        ),
        Ok(element(1)),
        "twice the domain minimum wraps to one"
    );
}
