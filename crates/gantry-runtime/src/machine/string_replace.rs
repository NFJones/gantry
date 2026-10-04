//! Recomputable cooperative nonoverlapping String replacement over immutable operands.
//!
//! Search never examines inserted text. Each complete unmatched/replacement piece is counted
//! before copying; all progress stays private until ordinary atomic primitive publication.

use gantry_core::portable::DeterministicEvaluationCode;

use super::{RuntimeCode, string_search::StringSearchWork};

/// One finite-work phase; boundaries and output are private, not logical checkpoint facts.
#[derive(Clone, Debug, Default)]
enum Phase {
    #[default]
    Search,
    CountSource,
    CopySource,
    CountReplacement,
    CopyReplacement,
}

/// Private exact-match, whole-piece admission and copy progress.
#[derive(Clone, Debug, Default)]
pub(super) struct StringReplaceWork {
    search: StringSearchWork,
    phase: Phase,
    emitted: usize,
    match_end: usize,
    piece_end: usize,
    cursor: usize,
    next_scalars: u64,
    scalars: u64,
    tail: bool,
    pub(super) output: String,
    pub(super) complete: bool,
    pub(super) error: Option<RuntimeCode>,
}

impl StringReplaceWork {
    /// Performs at most `quantum` search, scalar admission/copy or phase-boundary units.
    /// Refuses empty patterns and complete-piece overflow without publishing accumulated output.
    /// Prefix-table/output allocation and final logical construction are outside this work bound.
    pub(super) fn advance(
        &mut self,
        source: &str,
        pattern: &str,
        replacement: &str,
        maximum: u64,
        quantum: usize,
    ) -> bool {
        if self.complete || self.error.is_some() {
            return false;
        }
        if pattern.is_empty() {
            self.error = Some(RuntimeCode::Deterministic(
                DeterministicEvaluationCode::StringEmptyPattern,
            ));
            return false;
        }
        for _ in 0..quantum {
            match self.phase {
                Phase::Search => {
                    if self
                        .search
                        .advance(source.as_bytes(), pattern.as_bytes(), 1)
                    {
                        continue;
                    }
                    if let Some(range) = self.search.match_range(pattern.len()) {
                        self.piece_end = range.start;
                        self.match_end = range.end;
                        self.tail = false;
                    } else {
                        self.piece_end = source.len();
                        self.tail = true;
                    }
                    self.cursor = self.emitted;
                    self.next_scalars = self.scalars;
                    self.phase = Phase::CountSource;
                }
                Phase::CountSource | Phase::CountReplacement => {
                    let (piece, end) = if matches!(self.phase, Phase::CountSource) {
                        (source, self.piece_end)
                    } else {
                        (replacement, replacement.len())
                    };
                    if let Some(scalar) = piece[self.cursor..end].chars().next() {
                        let Some(next) = self
                            .next_scalars
                            .checked_add(1)
                            .filter(|count| *count <= maximum)
                        else {
                            self.error = Some(RuntimeCode::Deterministic(
                                DeterministicEvaluationCode::StringSizeLimit,
                            ));
                            return false;
                        };
                        self.next_scalars = next;
                        self.cursor += scalar.len_utf8();
                    } else {
                        self.scalars = self.next_scalars;
                        if matches!(self.phase, Phase::CountSource) {
                            self.cursor = self.emitted;
                            self.phase = Phase::CopySource;
                        } else {
                            self.cursor = 0;
                            self.phase = Phase::CopyReplacement;
                        }
                    }
                }
                Phase::CopySource | Phase::CopyReplacement => {
                    let (piece, end) = if matches!(self.phase, Phase::CopySource) {
                        (source, self.piece_end)
                    } else {
                        (replacement, replacement.len())
                    };
                    if let Some(scalar) = piece[self.cursor..end].chars().next() {
                        self.output.push(scalar);
                        self.cursor += scalar.len_utf8();
                    } else if matches!(self.phase, Phase::CopySource) {
                        if self.tail {
                            self.complete = true;
                            return false;
                        }
                        self.cursor = 0;
                        self.next_scalars = self.scalars;
                        self.phase = Phase::CountReplacement;
                    } else {
                        self.emitted = self.match_end;
                        self.search.resume_nonoverlapping();
                        self.phase = Phase::Search;
                    }
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::StringReplaceWork;
    use crate::machine::evaluate_primitive;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValueLimits};
    use gantry_ir::Primitive;

    /// Tiny quanta preserve nonoverlapping UTF-8 matches and whole-piece refusal order.
    #[test]
    fn incremental_replacement_preserves_exact_results_and_piece_admission() {
        for source in ["", "a", "aaa", "abababa", "éé😀", "no match"] {
            for pattern in ["", "a", "aa", "aba", "é", "😀", "longer than input"] {
                for replacement in ["", "a", "aa", "éx"] {
                    for maximum in 1..=12 {
                        let limits = ValueLimits::new(8, 100, maximum, 100)
                            .unwrap_or_else(|| panic!("limits"));
                        let operands = [source, pattern, replacement].map(|text| {
                            LogicalValue::string(text, DEFAULT_VALUE_LIMITS)
                                .unwrap_or_else(|error| panic!("operand: {error:?}"))
                        });
                        let expected =
                            evaluate_primitive(Primitive::StringReplace, &operands, limits);
                        let mut work = StringReplaceWork::default();
                        let mut calls = 0;
                        while work.advance(source, pattern, replacement, maximum, 1) {
                            calls += 1;
                            assert!(calls < 1000, "replacement must make finite progress");
                            assert!(work.scalars <= maximum);
                        }
                        let actual = work.error.map_or_else(
                            || {
                                LogicalValue::string(work.output.as_str(), limits)
                                    .map_err(crate::machine::map_string_value_error)
                            },
                            Err,
                        );
                        assert_eq!(
                            actual, expected,
                            "{source:?}, {pattern:?}, {replacement:?}, {maximum}"
                        );
                        assert!(!work.advance(source, pattern, replacement, maximum, 1));
                    }
                }
            }
        }
        let mut work = StringReplaceWork::default();
        while work.advance("abcX", "X", "yyyy", 5, 1) {}
        assert_eq!(
            work.output, "abc",
            "an over-limit replacement must append none of its piece"
        );
        assert_eq!(
            work.error,
            Some(super::RuntimeCode::Deterministic(
                gantry_core::portable::DeterministicEvaluationCode::StringSizeLimit
            ))
        );
    }
}
