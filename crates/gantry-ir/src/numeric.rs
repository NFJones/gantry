//! The admitted deterministic numeric algorithms of `GNT-40.2` through `GNT-40.5`.
//!
//! Every operation is pure and exact: it consumes canonical operands and publishes exactly one
//! canonical value, exactly one declared deterministic failure, or nothing where the clause
//! declares a partial form. Nothing here wraps, saturates, masks a result into range, widens
//! implicitly, coerces across numeric types, or consults a host facility, an ambient rounding mode,
//! timing, prior calls, or global state. This module publishes the checked integer algorithms and
//! the unary negation (`GNT-40.2`), the two numeric conversions (`GNT-40.3`), the checked bit
//! operations (`GNT-40.4`), and the finite-float algorithms (`GNT-40.5`) only: it publishes no
//! parsing, formatting, work limit, cancellation safe point, quota, schema, recovery, durability,
//! boundary encoding, lowering, machine representation, or family behavior.

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

/// One admitted binary bit operation of `GNT-40.4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryBitOperation {
    /// Bitwise conjunction of the two operands.
    And,
    /// Bitwise disjunction of the two operands.
    Or,
    /// Bitwise exclusive disjunction of the two operands.
    Xor,
}

impl BinaryBitOperation {
    /// Every admitted binary bit operation, in declaration order.
    pub const ALL: [Self; 3] = [Self::And, Self::Or, Self::Xor];

    /// Returns the canonical wire spelling of this operation.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
        }
    }

    /// Applies the operation to exactly two canonical operands (`GNT-40.4`).
    ///
    /// The combination is exact over the two's-complement representation: it publishes exactly one
    /// canonical `Int` value when that exact result lies inside the canonical domain and refuses
    /// under `integer-overflow` when it does not. No result wraps, saturates, or is masked into
    /// range, and nothing here coerces, widens implicitly, refuses under any other code, or depends
    /// on a host facility, ambient width, timing, prior calls, or global state.
    #[must_use]
    pub fn apply(
        self,
        left: GantryInt,
        right: GantryInt,
    ) -> Result<GantryInt, DeterministicEvaluationCode> {
        let value = match self {
            Self::And => left.get() & right.get(),
            Self::Or => left.get() | right.get(),
            Self::Xor => left.get() ^ right.get(),
        };
        GantryInt::new(value).ok_or(DeterministicEvaluationCode::IntegerOverflow)
    }
}

/// One admitted unary bit operation of `GNT-40.4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryBitOperation {
    /// Bitwise complement of the operand.
    Not,
    /// Count of the unset high-order bits of the operand's representation.
    LeadingZeros,
    /// Count of the unset low-order bits of the operand's representation.
    TrailingZeros,
}

impl UnaryBitOperation {
    /// Every admitted unary bit operation, in declaration order.
    pub const ALL: [Self; 3] = [Self::Not, Self::LeadingZeros, Self::TrailingZeros];

    /// Returns the canonical wire spelling of this operation.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Not => "not",
            Self::LeadingZeros => "leading-zeros",
            Self::TrailingZeros => "trailing-zeros",
        }
    }

    /// Applies the operation to exactly one canonical operand (`GNT-40.4`).
    ///
    /// The complement is exact and publishes exactly one canonical `Int` value when its result lies
    /// inside the canonical domain, refusing under `integer-overflow` when it does not; each count
    /// is total because it publishes a canonical `Int` value of at most 64. Nothing here wraps,
    /// saturates, or is masked into range, and nothing coerces, widens implicitly, refuses under any
    /// other code, or depends on a host facility, ambient width, timing, prior calls, or global
    /// state.
    #[must_use]
    pub fn apply(self, value: GantryInt) -> Result<GantryInt, DeterministicEvaluationCode> {
        let result = match self {
            Self::Not => !value.get(),
            Self::LeadingZeros => i64::from(value.get().leading_zeros()),
            Self::TrailingZeros => i64::from(value.get().trailing_zeros()),
        };
        GantryInt::new(result).ok_or(DeterministicEvaluationCode::IntegerOverflow)
    }
}

/// One admitted unary finite-float algorithm of `GNT-40.5`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryFloatAlgorithm {
    /// Sign-flipped operand.
    Negate,
    /// Magnitude of the operand.
    Abs,
}

impl UnaryFloatAlgorithm {
    /// Every admitted unary finite-float algorithm, in declaration order.
    pub const ALL: [Self; 2] = [Self::Negate, Self::Abs];

    /// Returns the canonical wire spelling of this algorithm.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Negate => "negate",
            Self::Abs => "abs",
        }
    }

    /// Applies the algorithm to exactly one canonical operand (`GNT-40.5`).
    ///
    /// Both algorithms are exact over the canonical `Float` domain and total: the sign flip and the
    /// magnitude neither round nor refuse an operand, and nothing here consults a host math library,
    /// an ambient rounding mode, timing, prior calls, or global state.
    #[must_use]
    pub fn apply(self, value: GantryFloat) -> GantryFloat {
        match self {
            Self::Negate => value.negated(),
            Self::Abs => GantryFloat::new(value.get().abs())
                .unwrap_or_else(|| unreachable!("a magnitude of a finite value is finite")),
        }
    }
}

/// One admitted binary finite-float algorithm of `GNT-40.5`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryFloatAlgorithm {
    /// Lesser of the two operands under the canonical total order.
    Minimum,
    /// Greater of the two operands under the canonical total order.
    Maximum,
}

impl BinaryFloatAlgorithm {
    /// Every admitted binary finite-float algorithm, in declaration order.
    pub const ALL: [Self; 2] = [Self::Minimum, Self::Maximum];

    /// Returns the canonical wire spelling of this algorithm.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Minimum => "minimum",
            Self::Maximum => "maximum",
        }
    }

    /// Applies the algorithm to exactly two canonical operands (`GNT-40.5`).
    ///
    /// The comparison uses the canonical `Float` value's own total order, so an equal pair publishes
    /// that equal value and neither algorithm rounds, refuses an operand, or consults a host math
    /// library, an ambient rounding mode, timing, prior calls, or global state.
    #[must_use]
    pub fn apply(self, left: GantryFloat, right: GantryFloat) -> GantryFloat {
        match self {
            Self::Minimum => left.min(right),
            Self::Maximum => left.max(right),
        }
    }
}

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
