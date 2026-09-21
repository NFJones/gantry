//! Conformance for the integer bit operations of `GNT-40.4`.
//!
//! The lane requires the specification and the note to publish the clause and the model to be exact:
//! every admitted operation publishes exactly one canonical `Int` value when its exact result lies
//! inside the canonical domain and refuses under `integer-overflow` when it does not, the two counts
//! are total, and nothing depends on a host facility, timing, prior calls, or global state.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{BinaryBitOperation, NUM_CLAUSES, UnaryBitOperation};
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

#[test]
fn integer_bit_operations_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    let anchor = "GNT-40.4-integer-bit-operations";
    assert!(
        NUM_CLAUSES.contains(&anchor),
        "the bit operations clause is declared by the numeric clause vocabulary"
    );
    assert!(note.contains(anchor), "the note names `{anchor}`");
    let clause = clause_body(&specification, anchor);
    assert!(
        !specification.trim_end().ends_with(clause.trim_end()),
        "the bit operations clause is no longer the specification's final clause"
    );
    assert_eq!(
        BinaryBitOperation::ALL.map(BinaryBitOperation::wire_name),
        ["and", "or", "xor"]
    );
    assert_eq!(
        UnaryBitOperation::ALL.map(UnaryBitOperation::wire_name),
        ["not", "leading-zeros", "trailing-zeros"]
    );
    for spelling in [
        BinaryBitOperation::And.wire_name(),
        BinaryBitOperation::Or.wire_name(),
        BinaryBitOperation::Xor.wire_name(),
        UnaryBitOperation::Not.wire_name(),
        UnaryBitOperation::LeadingZeros.wire_name(),
        UnaryBitOperation::TrailingZeros.wire_name(),
    ] {
        assert!(
            clause.contains(&format!("`{spelling}`")),
            "the clause publishes the backticked spelling `{spelling}`"
        );
    }
    for surface in ["`BinaryBitOperation`", "`UnaryBitOperation`"] {
        assert!(
            clause.contains(surface),
            "the clause names the model surface {surface}"
        );
    }
    for application in ["`BinaryBitOperation::apply`", "`UnaryBitOperation::apply`"] {
        assert!(
            note.contains(application),
            "the note names the model application {application}"
        );
    }
}

fn expect(value: i64) -> Result<GantryInt, DeterministicEvaluationCode> {
    GantryInt::new(value).ok_or(DeterministicEvaluationCode::IntegerOverflow)
}

/// A combination or complement is exact where its result is canonical and refuses under
/// `integer-overflow` where it is not; the two counts are total over the domain.
#[test]
fn integer_bit_operations_are_exact_and_refuse_out_of_domain() {
    let operands = [
        GANTRY_INT_MINIMUM,
        GANTRY_INT_MINIMUM + 1,
        GANTRY_INT_MINIMUM / 2,
        -1,
        0,
        1,
        GANTRY_INT_MAXIMUM / 2,
        GANTRY_INT_MAXIMUM - 1,
        GANTRY_INT_MAXIMUM,
    ];
    for left in operands {
        for right in operands {
            assert_eq!(
                BinaryBitOperation::And.apply(element(left), element(right)),
                expect(left & right)
            );
            assert_eq!(
                BinaryBitOperation::Or.apply(element(left), element(right)),
                expect(left | right)
            );
            assert_eq!(
                BinaryBitOperation::Xor.apply(element(left), element(right)),
                expect(left ^ right)
            );
            for operation in [BinaryBitOperation::And, BinaryBitOperation::Or] {
                assert_eq!(
                    operation.apply(element(left), element(right)),
                    operation.apply(element(right), element(left)),
                    "`{}` is commutative",
                    operation.wire_name()
                );
            }
            assert_eq!(
                BinaryBitOperation::Xor.apply(element(left), element(right)),
                BinaryBitOperation::Xor.apply(element(right), element(left)),
                "`xor` is commutative"
            );
        }
        let value = element(left);
        assert_eq!(
            BinaryBitOperation::And.apply(value, value),
            Ok(value),
            "`and` is idempotent"
        );
        assert_eq!(
            BinaryBitOperation::Or.apply(value, value),
            Ok(value),
            "`or` is idempotent"
        );
        assert_eq!(
            UnaryBitOperation::LeadingZeros.apply(value),
            Ok(element(i64::from(left.leading_zeros())))
        );
        assert_eq!(
            UnaryBitOperation::TrailingZeros.apply(value),
            Ok(element(i64::from(left.trailing_zeros())))
        );
        match UnaryBitOperation::Not.apply(value) {
            Ok(complement) => {
                assert_eq!(Some(complement), GantryInt::new(!left));
                assert_eq!(
                    UnaryBitOperation::Not.apply(complement),
                    Ok(value),
                    "`not` is its own inverse wherever it publishes"
                );
                assert_eq!(
                    BinaryBitOperation::And.apply(value, complement),
                    Ok(element(0)),
                    "a value and its complement publish zero"
                );
            }
            Err(code) => assert_eq!(code, DeterministicEvaluationCode::IntegerOverflow),
        }
    }
    let mut associative_triples = [0usize; 2];
    let mut and_grouping_differentials = 0usize;
    for first in operands {
        for second in operands {
            for third in operands {
                for (index, operation) in [BinaryBitOperation::And, BinaryBitOperation::Or]
                    .into_iter()
                    .enumerate()
                {
                    let grouped_left = operation
                        .apply(element(first), element(second))
                        .and_then(|partial| operation.apply(partial, element(third)));
                    let grouped_right = operation
                        .apply(element(second), element(third))
                        .and_then(|partial| operation.apply(element(first), partial));
                    if let (Ok(left_value), Ok(right_value)) = (&grouped_left, &grouped_right) {
                        assert_eq!(
                            left_value,
                            right_value,
                            "`{}` is associative wherever both groupings publish",
                            operation.wire_name()
                        );
                        associative_triples[index] += 1;
                    } else if operation == BinaryBitOperation::And
                        && grouped_left.is_ok() != grouped_right.is_ok()
                    {
                        and_grouping_differentials += 1;
                    }
                }
            }
        }
    }
    assert!(
        associative_triples[0] > 0 && associative_triples[1] > 0,
        "each binary bit operation publishes at least one associative triple"
    );
    assert!(
        and_grouping_differentials > 0,
        "`and` has a grouping-differential triple, which is why its associative claim is conditional"
    );
    assert_eq!(
        UnaryBitOperation::LeadingZeros.apply(element(0)),
        Ok(element(64))
    );
    assert_eq!(
        UnaryBitOperation::TrailingZeros.apply(element(0)),
        Ok(element(64))
    );
}
