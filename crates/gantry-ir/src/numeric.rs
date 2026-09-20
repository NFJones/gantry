//! The admitted deterministic integer algorithms of `GNT-40.2`.
//!
//! Every algorithm is pure: it consumes canonical `Int` operands and returns exactly one canonical
//! `Int` value or exactly one declared deterministic failure. Nothing here wraps, saturates, widens
//! implicitly, coerces across numeric types, or consults a host facility, timing, prior calls, or
//! global state. This module publishes no float algorithm, bit operation, conversion, parsing,
//! formatting, work limit, cancellation safe point, quota, schema, recovery, durability, boundary
//! encoding, lowering, machine representation, or family behavior.

use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::DeterministicEvaluationCode;

/// One admitted binary checked integer algorithm of `GNT-40.2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckedIntegerAlgorithm {
    /// Checked addition of the two operands.
    Add,
    /// Checked subtraction of the second operand from the first.
    Subtract,
    /// Checked multiplication of the two operands.
    Multiply,
    /// Truncating division of the first operand by the second.
    Divide,
    /// Remainder of the first operand by the second, carrying the dividend's sign.
    Remainder,
}

impl CheckedIntegerAlgorithm {
    /// Every admitted binary algorithm, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Add,
        Self::Subtract,
        Self::Multiply,
        Self::Divide,
        Self::Remainder,
    ];

    /// Returns the canonical wire spelling of this algorithm.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Subtract => "subtract",
            Self::Multiply => "multiply",
            Self::Divide => "divide",
            Self::Remainder => "remainder",
        }
    }

    /// Applies the algorithm to exactly two canonical operands.
    ///
    /// The result is exactly one canonical `Int` value or exactly one declared failure: a result
    /// outside the canonical domain is refused under `integer-overflow`, a division by zero under
    /// `integer-division-by-zero`, and a remainder by zero under `integer-remainder-by-zero`.
    /// Division truncates toward zero and the remainder carries the dividend's sign, preserving
    /// `a == (a / b) * b + (a % b)`. No algorithm wraps, saturates, coerces, widens implicitly,
    /// refuses under any other code, or depends on a host facility, timing, prior calls, or global
    /// state.
    pub fn apply(
        self,
        left: GantryInt,
        right: GantryInt,
    ) -> Result<GantryInt, DeterministicEvaluationCode> {
        match self {
            Self::Add => left.checked_add(right),
            Self::Subtract => left.checked_sub(right),
            Self::Multiply => left.checked_mul(right),
            Self::Divide => left.checked_div(right),
            Self::Remainder => left.checked_rem(right),
        }
    }
}

/// Negates one canonical `Int` operand (`GNT-40.2`).
///
/// The negation is total over the canonical domain: the domain is symmetric, so the negation of its
/// minimum is its maximum and the delegated range check cannot fire for any admitted operand.
pub fn negate(value: GantryInt) -> Result<GantryInt, DeterministicEvaluationCode> {
    value.checked_neg()
}

/// The canonical wire spelling of the unary negation of `GNT-40.2`.
pub const NEGATE_WIRE_NAME: &str = "negate";

/// One admitted numeric conversion of `GNT-40.3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumericConversion {
    /// Converts one canonical `Int` to its exact binary64 `Float`.
    IntToFloat,
    /// Converts one finite `Float` to its canonical `Int` when it is integral and in range.
    FloatToInt,
}

impl NumericConversion {
    /// Every admitted conversion, in declaration order.
    pub const ALL: [Self; 2] = [Self::IntToFloat, Self::FloatToInt];

    /// Returns the canonical wire spelling of this conversion.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::IntToFloat => "int-to-float",
            Self::FloatToInt => "float-to-int",
        }
    }
}

/// Converts one canonical `Int` to its exact binary64 `Float` (`GNT-40.3`).
///
/// The conversion is total and exact: every canonical `Int` value is representable in binary64, so
/// nothing rounds, widens implicitly, or consults a host facility.
#[must_use]
pub fn int_to_float(value: GantryInt) -> GantryFloat {
    value.to_float()
}

/// Converts one finite `Float` to its canonical `Int` (`GNT-40.3`).
///
/// The conversion returns exactly one canonical `Int` value only when the operand is integral and
/// inside the canonical `Int` domain, and returns nothing otherwise; a fractional operand and an
/// out-of-domain operand both refuse rather than truncating, rounding, saturating, wrapping, or
/// coercing.
#[must_use]
pub fn float_to_int(value: GantryFloat) -> Option<GantryInt> {
    value.to_int()
}
