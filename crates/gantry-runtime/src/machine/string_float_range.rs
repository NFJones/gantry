//! Private incremental magnitude preflight for an already grammar-admitted JSON number.
//!
//! The unchanged conversion owner revalidates admitted results. These recomputable facts
//! authorize no publication and bound scanning only, not final rounding or allocation.

use std::cmp::Ordering;

/// Constant-size decimal facts accumulated over unchanged grammar-admitted input.
#[derive(Clone, Debug, Default)]
pub(super) struct StringFloatRangeWork {
    cursor: usize,
    fractional: bool,
    fraction_digits: i128,
    significant_digits: usize,
    prefix: [u8; 17],
    nonzero_tail: bool,
    exponent: bool,
    negative_exponent: bool,
    exponent_magnitude: i128,
    exponent_overflow: bool,
    result: Option<bool>,
}

impl StringFloatRangeWork {
    /// Inspects at most `quantum` octets, then compares at most seventeen prefix digits.
    /// Returns `None` while unfinished. Callers must independently validate JSON grammar.
    pub(super) fn advance(&mut self, source: &str, quantum: usize) -> Option<bool> {
        if self.result.is_some() {
            return self.result;
        }
        let end = self.cursor.saturating_add(quantum).min(source.len());
        for byte in &source.as_bytes()[self.cursor..end] {
            if self.exponent {
                match byte {
                    b'-' => self.negative_exponent = true,
                    b'+' => {}
                    b'0'..=b'9' if !self.exponent_overflow => {
                        if let Some(next) = self
                            .exponent_magnitude
                            .checked_mul(10)
                            .and_then(|value| value.checked_add(i128::from(*byte - b'0')))
                        {
                            self.exponent_magnitude = next;
                        } else {
                            self.exponent_overflow = true;
                        }
                    }
                    _ => {}
                }
            } else {
                match byte {
                    b'e' | b'E' => self.exponent = true,
                    b'.' => self.fractional = true,
                    b'0'..=b'9' => {
                        if self.fractional {
                            self.fraction_digits = self.fraction_digits.saturating_add(1);
                        }
                        if self.significant_digits != 0 || *byte != b'0' {
                            if let Some(slot) = self.prefix.get_mut(self.significant_digits) {
                                *slot = *byte;
                            } else {
                                self.nonzero_tail |= *byte != b'0';
                            }
                            self.significant_digits += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        self.cursor = end;
        if end != source.len() {
            return None;
        }
        let exponent = match (self.exponent_overflow, self.negative_exponent) {
            (true, true) => i128::MIN,
            (true, false) => i128::MAX,
            (false, true) => -self.exponent_magnitude,
            (false, false) => self.exponent_magnitude,
        };
        let order = exponent
            .saturating_sub(self.fraction_digits)
            .saturating_add(
                i128::try_from(self.significant_digits.saturating_sub(1)).unwrap_or(i128::MAX),
            );
        let admitted = self.significant_digits == 0
            || match order.cmp(&308) {
                Ordering::Less => true,
                Ordering::Greater => false,
                Ordering::Equal => {
                    let mut prefix = self.prefix;
                    prefix[self.significant_digits.min(17)..].fill(b'0');
                    match prefix.cmp(b"17976931348623157") {
                        Ordering::Less => true,
                        Ordering::Greater => false,
                        Ordering::Equal => !self.nonzero_tail,
                    }
                }
            };
        self.result = Some(admitted);
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::StringFloatRangeWork;
    use gantry_core::strict_json::{JsonNumberScanner, parse_json_float};

    /// Independent conversion controls pin exact range boundaries across tiny scan quanta.
    #[test]
    fn incremental_range_matches_authoritative_conversion() {
        let mut sources = vec![
            "0".to_owned(),
            "-0.000e99999999999999999999999999999999999999999".to_owned(),
            "1.7976931348623157e308".to_owned(),
            "1.797693134862315700000e308".to_owned(),
            "1.797693134862315700001e308".to_owned(),
            "1.7976931348623158e308".to_owned(),
            "1.7976931348623156e308".to_owned(),
            "17976931348623157e292".to_owned(),
            "1e99999999999999999999999999999999999999999".to_owned(),
            "1e-99999999999999999999999999999999999999999".to_owned(),
            format!("1{}e-20000", "0".repeat(20_000)),
            format!("1.7976931348623157{}1e308", "0".repeat(20_000)),
            format!("0.{}1e20309", "0".repeat(20_000)),
        ];
        for integer in [0, 1, 9, 10, 17976931348623157_u64] {
            for fraction in ["", ".0", ".001", ".10200"] {
                for exponent in ["", "e+3", "e-3", "e292", "e308", "e309", "e-324"] {
                    for sign in ["", "-"] {
                        sources.push(format!("{sign}{integer}{fraction}{exponent}"));
                    }
                }
            }
        }
        for source in sources {
            let mut grammar = JsonNumberScanner::new(0);
            assert_eq!(
                grammar.advance(source.as_bytes(), source.len() + 8),
                Some(Ok(source.len())),
                "range fixtures must have independently admitted grammar"
            );
            let expected = parse_json_float(&source).is_some();
            for quantum in [1, 7, 4096] {
                let mut work = StringFloatRangeWork::default();
                assert_eq!(work.advance(&source, 0), None);
                let mut calls = 0;
                let actual = loop {
                    calls += 1;
                    assert!(calls <= source.len().div_ceil(quantum), "finite progress");
                    if let Some(result) = work.advance(&source, quantum) {
                        break result;
                    }
                };
                assert_eq!(actual, expected, "{source:.80}, quantum={quantum}");
                assert_eq!(work.advance(&source, quantum), Some(expected));
            }
        }
    }
}
