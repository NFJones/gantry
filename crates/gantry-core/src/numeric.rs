//! Exact Gantry integer bounds, finite binary64 values, and checked primitives.

use crate::portable::DeterministicEvaluationCode;

/// Inclusive minimum Gantry `Int` value.
pub const GANTRY_INT_MINIMUM: i64 = -9_007_199_254_740_991;
/// Inclusive maximum Gantry `Int` value.
pub const GANTRY_INT_MAXIMUM: i64 = 9_007_199_254_740_991;

/// One exact Gantry `Int` in the portable `±(2^53 - 1)` range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GantryInt(i64);

impl GantryInt {
    /// Admits one integer only when it is inside the portable Gantry range.
    #[must_use]
    pub const fn new(value: i64) -> Option<Self> {
        if value < GANTRY_INT_MINIMUM || value > GANTRY_INT_MAXIMUM {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Returns the exact integer value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Checked unary negation.
    pub fn checked_neg(self) -> Result<Self, DeterministicEvaluationCode> {
        admit_int(
            self.0
                .checked_neg()
                .ok_or(DeterministicEvaluationCode::IntegerOverflow)?,
        )
    }

    /// Checked addition.
    pub fn checked_add(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        admit_int(
            self.0
                .checked_add(right.0)
                .ok_or(DeterministicEvaluationCode::IntegerOverflow)?,
        )
    }

    /// Checked subtraction.
    pub fn checked_sub(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        admit_int(
            self.0
                .checked_sub(right.0)
                .ok_or(DeterministicEvaluationCode::IntegerOverflow)?,
        )
    }

    /// Checked multiplication.
    pub fn checked_mul(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        admit_int(
            self.0
                .checked_mul(right.0)
                .ok_or(DeterministicEvaluationCode::IntegerOverflow)?,
        )
    }

    /// Checked division truncating toward zero.
    pub fn checked_div(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        if right.0 == 0 {
            return Err(DeterministicEvaluationCode::IntegerDivisionByZero);
        }
        admit_int(
            self.0
                .checked_div(right.0)
                .ok_or(DeterministicEvaluationCode::IntegerOverflow)?,
        )
    }

    /// Checked remainder retaining the dividend's sign.
    pub fn checked_rem(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        if right.0 == 0 {
            return Err(DeterministicEvaluationCode::IntegerRemainderByZero);
        }
        admit_int(
            self.0
                .checked_rem(right.0)
                .ok_or(DeterministicEvaluationCode::IntegerOverflow)?,
        )
    }

    /// Converts exactly to binary64; every admitted `Int` is representable.
    #[must_use]
    pub fn to_float(self) -> GantryFloat {
        GantryFloat(self.0 as f64)
    }
}

fn admit_int(value: i64) -> Result<GantryInt, DeterministicEvaluationCode> {
    GantryInt::new(value).ok_or(DeterministicEvaluationCode::IntegerOverflow)
}

/// One finite Gantry `Float` with negative zero normalized to positive zero.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct GantryFloat(f64);

impl Eq for GantryFloat {}

impl GantryFloat {
    /// Admits one finite binary64 value and normalizes either signed zero.
    #[must_use]
    pub fn new(value: f64) -> Option<Self> {
        value
            .is_finite()
            .then_some(Self(if value == 0.0 { 0.0 } else { value }))
    }

    /// Returns the normalized finite binary64 value.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// Returns an exact `Int` only for integral in-range values.
    #[must_use]
    pub fn to_int(self) -> Option<GantryInt> {
        if self.0.fract() != 0.0
            || self.0 < GANTRY_INT_MINIMUM as f64
            || self.0 > GANTRY_INT_MAXIMUM as f64
        {
            return None;
        }
        GantryInt::new(self.0 as i64)
    }

    /// Unary negation with signed-zero normalization.
    #[must_use]
    pub fn negated(self) -> Self {
        Self::new(-self.0).unwrap_or_else(|| unreachable!("negation preserves finiteness"))
    }

    /// Binary64 addition with finite-result enforcement.
    pub fn checked_add(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        admit_float(self.0 + right.0)
    }

    /// Binary64 subtraction with finite-result enforcement.
    pub fn checked_sub(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        admit_float(self.0 - right.0)
    }

    /// Binary64 multiplication with finite-result enforcement.
    pub fn checked_mul(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        admit_float(self.0 * right.0)
    }

    /// Binary64 division with explicit signed-zero rejection.
    pub fn checked_div(self, right: Self) -> Result<Self, DeterministicEvaluationCode> {
        if right.0 == 0.0 {
            return Err(DeterministicEvaluationCode::FloatDivisionByZero);
        }
        admit_float(self.0 / right.0)
    }

    /// Returns the RFC 8785 / ECMAScript canonical number spelling.
    #[must_use]
    pub fn canonical_string(self) -> String {
        canonical_binary64(self.0)
    }
}

fn admit_float(value: f64) -> Result<GantryFloat, DeterministicEvaluationCode> {
    GantryFloat::new(value).ok_or(DeterministicEvaluationCode::FloatNonFiniteResult)
}

/// Formats one finite binary64 value using RFC 8785's ECMAScript thresholds.
#[must_use]
pub fn canonical_binary64(value: f64) -> String {
    let value = if value == 0.0 { 0.0 } else { value };
    debug_assert!(value.is_finite());
    if value == 0.0 {
        return "0".to_owned();
    }

    let shortest = format!("{value:?}");
    let (negative, unsigned) = shortest
        .strip_prefix('-')
        .map_or((false, shortest.as_str()), |value| (true, value));
    let (mantissa, exponent) =
        unsigned
            .split_once(['e', 'E'])
            .map_or((unsigned, 0_i32), |(mantissa, exponent)| {
                (
                    mantissa,
                    exponent
                        .parse::<i32>()
                        .unwrap_or_else(|_| unreachable!("Rust float exponent is bounded")),
                )
            });
    let decimal = mantissa.find('.').unwrap_or(mantissa.len());
    let mut digits = mantissa
        .bytes()
        .filter(|byte| *byte != b'.')
        .collect::<Vec<_>>();
    let leading = digits
        .iter()
        .position(|digit| *digit != b'0')
        .unwrap_or(digits.len());
    digits.drain(..leading);
    while digits.last() == Some(&b'0') {
        digits.pop();
    }
    let decimal =
        i32::try_from(decimal).unwrap_or_else(|_| unreachable!("binary64 rendering is bounded"));
    let leading =
        i32::try_from(leading).unwrap_or_else(|_| unreachable!("binary64 rendering is bounded"));
    let decimal_position = decimal + exponent - leading;
    let digits = std::str::from_utf8(&digits)
        .unwrap_or_else(|_| unreachable!("shortest binary64 spelling is ASCII"));
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    let digit_count = i32::try_from(digits.len())
        .unwrap_or_else(|_| unreachable!("binary64 rendering is bounded"));
    if decimal_position > 0 && decimal_position <= 21 {
        if digit_count <= decimal_position {
            output.push_str(digits);
            for _ in 0..decimal_position - digit_count {
                output.push('0');
            }
        } else {
            let split = usize::try_from(decimal_position)
                .unwrap_or_else(|_| unreachable!("positive decimal position fits"));
            output.push_str(&digits[..split]);
            output.push('.');
            output.push_str(&digits[split..]);
        }
    } else if decimal_position <= 0 && decimal_position > -6 {
        output.push_str("0.");
        for _ in 0..-decimal_position {
            output.push('0');
        }
        output.push_str(digits);
    } else {
        output.push_str(&digits[..1]);
        if digits.len() > 1 {
            output.push('.');
            output.push_str(&digits[1..]);
        }
        let exponent = decimal_position - 1;
        output.push('e');
        if exponent >= 0 {
            output.push('+');
        }
        output.push_str(&exponent.to_string());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        GANTRY_INT_MAXIMUM, GANTRY_INT_MINIMUM, GantryFloat, GantryInt, canonical_binary64,
    };
    use crate::portable::DeterministicEvaluationCode;

    #[test]
    fn integer_primitives_enforce_the_portable_range_and_exact_codes() {
        let maximum = GantryInt::new(GANTRY_INT_MAXIMUM)
            .unwrap_or_else(|| unreachable!("maximum is admitted"));
        let minimum = GantryInt::new(GANTRY_INT_MINIMUM)
            .unwrap_or_else(|| unreachable!("minimum is admitted"));
        let one = GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted"));
        let zero = GantryInt::new(0).unwrap_or_else(|| unreachable!("zero is admitted"));
        assert_eq!(
            maximum.checked_add(one),
            Err(DeterministicEvaluationCode::IntegerOverflow)
        );
        assert_eq!(
            minimum.checked_sub(one),
            Err(DeterministicEvaluationCode::IntegerOverflow)
        );
        assert_eq!(
            one.checked_div(zero),
            Err(DeterministicEvaluationCode::IntegerDivisionByZero)
        );
        assert_eq!(
            one.checked_rem(zero),
            Err(DeterministicEvaluationCode::IntegerRemainderByZero)
        );
        let seven = GantryInt::new(7).unwrap_or_else(|| unreachable!("seven is admitted"));
        let negative_three =
            GantryInt::new(-3).unwrap_or_else(|| unreachable!("negative three is admitted"));
        assert_eq!(
            seven.checked_div(negative_three).map(GantryInt::get),
            Ok(-2)
        );
        assert_eq!(seven.checked_rem(negative_three).map(GantryInt::get), Ok(1));
    }

    #[test]
    fn float_primitives_normalize_zero_and_reject_nonfinite_results() {
        let zero = GantryFloat::new(-0.0).unwrap_or_else(|| unreachable!("zero is finite"));
        assert_eq!(zero.get().to_bits(), 0.0_f64.to_bits());
        let one = GantryFloat::new(1.0).unwrap_or_else(|| unreachable!("one is finite"));
        assert_eq!(
            one.checked_div(zero),
            Err(DeterministicEvaluationCode::FloatDivisionByZero)
        );
        let maximum =
            GantryFloat::new(f64::MAX).unwrap_or_else(|| unreachable!("maximum is finite"));
        assert_eq!(
            maximum.checked_mul(maximum),
            Err(DeterministicEvaluationCode::FloatNonFiniteResult)
        );
        let underflow = GantryFloat::new(f64::MIN_POSITIVE)
            .unwrap_or_else(|| unreachable!("minimum normal is finite"))
            .checked_mul(GantryFloat::new(f64::MIN_POSITIVE).unwrap_or_else(|| unreachable!()));
        assert_eq!(underflow.map(GantryFloat::get), Ok(0.0));
    }

    #[test]
    fn binary64_formatting_matches_rfc_8785_thresholds_and_vectors() {
        for (value, expected) in [
            (-0.0, "0"),
            (333_333_333.333_333_3, "333333333.3333333"),
            (1e30, "1e+30"),
            (4.5, "4.5"),
            (2e-3, "0.002"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(canonical_binary64(value), expected, "{value:?}");
        }
    }
}
