//! The admitted deterministic integer algorithms of `GNT-40.2`.
//!
//! Every algorithm is pure: it consumes canonical `Int` operands and returns exactly one canonical
//! `Int` value or exactly one declared deterministic failure. Nothing here wraps, saturates, widens
//! implicitly, coerces across numeric types, or consults a host facility, timing, prior calls, or
//! global state. This module publishes no float algorithm, bit operation, conversion, parsing,
//! formatting, work limit, cancellation safe point, quota, schema, recovery, durability, boundary
//! encoding, lowering, machine representation, or family behavior.

use gantry_core::numeric::GantryInt;
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

/// Negates one canonical `Int` operand, returning the exact result or `integer-overflow` at the
/// element's minimum (`GNT-40.2`).
pub fn negate(value: GantryInt) -> Result<GantryInt, DeterministicEvaluationCode> {
    value.checked_neg()
}
