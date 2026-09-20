//! Conformance for the checked integer algorithms of `GNT-40.2`.
//!
//! The lanes require the specification and the note to publish the clause, and the model to return
//! exactly one canonical `Int` value or exactly one declared failure for every operand boundary:
//! no wrapping, saturation, coercion, implicit widening, or host dependence.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{CheckedIntegerAlgorithm, NUM_CLAUSES, negate};
use gantry::numeric::{GANTRY_INT_MAXIMUM, GANTRY_INT_MINIMUM, GantryInt};
use gantry::portable::DeterministicEvaluationCode;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn element(value: i64) -> GantryInt {
    GantryInt::new(value).unwrap_or_else(|| panic!("`{value}` is inside the canonical Int range"))
}

#[test]
fn checked_integer_algorithm_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    let anchor = "GNT-40.2-checked-integer-algorithms";
    assert!(NUM_CLAUSES.contains(&anchor));
    assert!(specification.contains(&format!("<a id=\"{anchor}\"></a>")));
    assert!(note.contains(anchor), "the note names `{anchor}`");
    assert_eq!(
        CheckedIntegerAlgorithm::ALL.map(CheckedIntegerAlgorithm::wire_name),
        ["add", "subtract", "multiply", "divide", "remainder"]
    );
    for spelling in [
        "add",
        "subtract",
        "multiply",
        "divide",
        "remainder",
        "negate",
        "integer-overflow",
        "integer-division-by-zero",
        "integer-remainder-by-zero",
    ] {
        assert!(
            specification.contains(spelling),
            "the specification publishes `{spelling}`"
        );
    }
}

#[test]
fn checked_integer_algorithms_are_exact_and_refuse_only_declared_failures() {
    let maximum = element(GANTRY_INT_MAXIMUM);
    let minimum = element(GANTRY_INT_MINIMUM);

    assert_eq!(
        CheckedIntegerAlgorithm::Add.apply(element(GANTRY_INT_MAXIMUM - 1), element(1)),
        Ok(maximum)
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Add.apply(maximum, element(1)),
        Err(DeterministicEvaluationCode::IntegerOverflow)
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Subtract.apply(minimum, element(1)),
        Err(DeterministicEvaluationCode::IntegerOverflow)
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Subtract.apply(maximum, maximum),
        Ok(element(0))
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Multiply.apply(maximum, element(2)),
        Err(DeterministicEvaluationCode::IntegerOverflow)
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Multiply.apply(minimum, element(1)),
        Ok(minimum)
    );

    // Division truncates toward zero and the remainder carries the dividend's sign.
    for (left, right, quotient, remainder) in [
        (7, 2, 3, 1),
        (-7, 2, -3, -1),
        (7, -2, -3, 1),
        (-7, -2, 3, -1),
        (0, 5, 0, 0),
    ] {
        assert_eq!(
            CheckedIntegerAlgorithm::Divide.apply(element(left), element(right)),
            Ok(element(quotient)),
            "{left} / {right}"
        );
        assert_eq!(
            CheckedIntegerAlgorithm::Remainder.apply(element(left), element(right)),
            Ok(element(remainder)),
            "{left} % {right}"
        );
        // The canonical law holds exactly in the canonical domain.
        let reconstructed = CheckedIntegerAlgorithm::Multiply
            .apply(element(quotient), element(right))
            .and_then(|product| CheckedIntegerAlgorithm::Add.apply(product, element(remainder)))
            .unwrap_or_else(|error| panic!("the law reconstructs in range: {error:?}"));
        assert_eq!(reconstructed, element(left), "{left} == q * b + r");
    }
    assert_eq!(
        CheckedIntegerAlgorithm::Divide.apply(element(1), element(0)),
        Err(DeterministicEvaluationCode::IntegerDivisionByZero)
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Remainder.apply(element(1), element(0)),
        Err(DeterministicEvaluationCode::IntegerRemainderByZero)
    );
    // The canonical `Int` domain is symmetric, so the extreme quotient is representable exactly
    // rather than overflowing as the two's complement minimum would.
    assert_eq!(
        CheckedIntegerAlgorithm::Divide.apply(minimum, element(-1)),
        Ok(maximum)
    );
    assert_eq!(
        CheckedIntegerAlgorithm::Remainder.apply(minimum, element(-1)),
        Ok(element(0))
    );

    // The canonical `Int` domain is symmetric, so negating its minimum is exact.
    assert_eq!(negate(minimum), Ok(maximum));
    assert_eq!(negate(maximum), Ok(minimum));
    assert_eq!(negate(element(-5)), Ok(element(5)));
    assert_eq!(negate(element(5)), Ok(element(-5)));
    assert_eq!(negate(element(0)), Ok(element(0)));
}
