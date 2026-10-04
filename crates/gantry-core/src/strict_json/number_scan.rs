//! Incremental RFC 8259 number grammar scanning over one unchanged byte slice.
//!
//! This scanner reports a token endpoint or syntax offset only. It grants no numeric
//! conversion or admission authority; callers still validate whole-token consumption.

use super::JsonError;

/// One constant-work grammar state.
#[derive(Clone, Copy, Debug)]
enum State {
    Start,
    IntegerStart,
    Zero,
    Integer,
    FractionStart,
    Fraction,
    ExponentSign,
    ExponentStart,
    Exponent,
}

/// Recomputable grammar progress for a single token in immutable input.
#[derive(Clone, Debug)]
pub struct JsonNumberScanner {
    cursor: usize,
    state: State,
    outcome: Option<Result<usize, JsonError>>,
}

impl JsonNumberScanner {
    /// Starts a token at `offset`; invalid offsets refuse on the first grammar step.
    #[must_use]
    pub fn new(offset: usize) -> Self {
        Self {
            cursor: offset,
            state: State::Start,
            outcome: None,
        }
    }

    /// Returns the current absolute byte offset, including on syntax refusal.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Performs at most `quantum` constant-work grammar steps over the same unchanged input.
    /// `None` means more work remains (also for a zero quantum). A successful endpoint may
    /// precede delimiters or trailing data; it is not proof that the entire slice is a number.
    /// Repeated calls after completion return the retained endpoint/refusal without scanning.
    pub fn advance(&mut self, bytes: &[u8], quantum: usize) -> Option<Result<usize, JsonError>> {
        if let Some(outcome) = &self.outcome {
            return Some(outcome.clone());
        }
        for _ in 0..quantum {
            let byte = bytes.get(self.cursor).copied();
            match self.state {
                State::Start => {
                    if byte == Some(b'-') {
                        self.cursor += 1;
                    }
                    self.state = State::IntegerStart;
                }
                State::IntegerStart => match byte {
                    Some(b'0') => {
                        self.cursor += 1;
                        self.state = State::Zero;
                    }
                    Some(b'1'..=b'9') => {
                        self.cursor += 1;
                        self.state = State::Integer;
                    }
                    _ => return self.refuse(),
                },
                State::Zero | State::Integer => {
                    if byte.is_some_and(|byte| byte.is_ascii_digit()) {
                        if matches!(self.state, State::Zero) {
                            return self.refuse();
                        }
                        self.cursor += 1;
                    } else if byte == Some(b'.') {
                        self.cursor += 1;
                        self.state = State::FractionStart;
                    } else if matches!(byte, Some(b'e' | b'E')) {
                        self.cursor += 1;
                        self.state = State::ExponentSign;
                    } else {
                        return self.complete();
                    }
                }
                State::FractionStart | State::ExponentStart => {
                    if byte.is_some_and(|byte| byte.is_ascii_digit()) {
                        self.cursor += 1;
                        self.state = if matches!(self.state, State::FractionStart) {
                            State::Fraction
                        } else {
                            State::Exponent
                        };
                    } else {
                        return self.refuse();
                    }
                }
                State::Fraction => {
                    if byte.is_some_and(|byte| byte.is_ascii_digit()) {
                        self.cursor += 1;
                    } else if matches!(byte, Some(b'e' | b'E')) {
                        self.cursor += 1;
                        self.state = State::ExponentSign;
                    } else {
                        return self.complete();
                    }
                }
                State::ExponentSign => {
                    if matches!(byte, Some(b'+' | b'-')) {
                        self.cursor += 1;
                    }
                    self.state = State::ExponentStart;
                }
                State::Exponent => {
                    if byte.is_some_and(|byte| byte.is_ascii_digit()) {
                        self.cursor += 1;
                    } else {
                        return self.complete();
                    }
                }
            }
        }
        None
    }

    /// Retains a successful token endpoint without interpreting trailing bytes.
    fn complete(&mut self) -> Option<Result<usize, JsonError>> {
        self.outcome = Some(Ok(self.cursor));
        self.outcome.clone()
    }

    /// Retains the exact first syntax-refusal offset.
    fn refuse(&mut self) -> Option<Result<usize, JsonError>> {
        self.outcome = Some(Err(JsonError::Syntax {
            offset: self.cursor,
        }));
        self.outcome.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::JsonNumberScanner;
    use crate::strict_json::{JsonError, JsonLimits, StrictJsonDocument};

    /// Independent endpoints and refusal offsets pin grammar semantics across tiny quanta.
    #[test]
    fn incremental_number_scanning_preserves_endpoints_and_syntax_offsets() {
        for (token, expected) in [
            ("0", Ok(1)),
            ("-0", Ok(2)),
            ("12.3e+4", Ok(7)),
            ("1,", Ok(1)),
            ("0x", Ok(1)),
            ("1 ", Ok(1)),
            ("", Err(0)),
            ("-", Err(1)),
            ("+1", Err(0)),
            ("01", Err(1)),
            ("-01", Err(2)),
            (".1", Err(0)),
            ("1.", Err(2)),
            ("1e", Err(2)),
            ("1e+", Err(3)),
            ("1e-", Err(3)),
            ("1.e2", Err(2)),
            ("1e.x", Err(2)),
        ] {
            for quantum in [1, 2, 4096] {
                let input = format!("[{token}");
                let mut scanner = JsonNumberScanner::new(1);
                assert_eq!(scanner.advance(input.as_bytes(), 0), None);
                assert_eq!(scanner.cursor(), 1);
                let mut calls = 0;
                let outcome = loop {
                    calls += 1;
                    assert!(calls <= token.len() + 8, "scanner must progress: {token:?}");
                    if let Some(outcome) = scanner.advance(input.as_bytes(), quantum) {
                        break outcome;
                    }
                };
                let expected = expected
                    .map(|end| end + 1)
                    .map_err(|offset| JsonError::Syntax { offset: offset + 1 });
                assert_eq!(outcome, expected, "{token:?}, {quantum}");
                assert_eq!(scanner.advance(input.as_bytes(), quantum), Some(expected));
            }
        }
        let limits = JsonLimits {
            maximum_bytes: 100,
            maximum_nesting_depth: 4,
            maximum_nodes: 4,
            maximum_string_scalars: 100,
            maximum_list_items: 4,
        };
        for (input, offset) in [("[01]", 2), ("[1.]", 3), ("[1e+]", 4), ("[-]", 2)] {
            assert_eq!(
                StrictJsonDocument::decode(input.as_bytes(), limits),
                Err(JsonError::Syntax { offset })
            );
        }
        let mut invalid = JsonNumberScanner::new(usize::MAX);
        assert_eq!(
            invalid.advance(b"1", 2),
            Some(Err(JsonError::Syntax { offset: usize::MAX }))
        );
    }
}
