//! Recomputable cooperative String splitting over immutable logical operands.
//!
//! Search remains nonoverlapping. Each next List place is admitted before a segment's
//! scalar admission and private copying; empty segments are preserved. Final value
//! construction is synchronous and is not part of the finite search/copy-work bound.

use gantry_core::portable::DeterministicEvaluationCode;
use gantry_core::value::{LogicalValue, ValueLimits};

use super::{RuntimeCode, map_string_value_error, string_search::StringSearchWork};

/// One private phase; no segment or partial List is source-visible.
#[derive(Clone, Debug, Default)]
enum Phase {
    #[default]
    Search,
    Count,
    Copy,
    Construct,
}

/// Private segment facts, discarded on recovery or terminal settlement.
#[derive(Clone, Debug, Default)]
pub(super) struct StringSplitWork {
    search: StringSearchWork,
    phase: Phase,
    start: usize,
    end: usize,
    match_end: usize,
    cursor: usize,
    scalars: u64,
    tail: bool,
    piece: String,
    pub(super) items: Vec<LogicalValue>,
    pub(super) complete: bool,
    pub(super) error: Option<RuntimeCode>,
}

impl StringSplitWork {
    /// Performs at most `quantum` search, scalar admission/copy or phase-boundary units.
    /// Refusal exposes no partial List. Segment construction, allocation and destruction
    /// are explicitly outside the work bound and retain ordinary value-limit checking.
    pub(super) fn advance(
        &mut self,
        source: &str,
        separator: &str,
        limits: ValueLimits,
        quantum: usize,
    ) -> bool {
        if self.complete || self.error.is_some() {
            return false;
        }
        if separator.is_empty() {
            self.error = Some(RuntimeCode::Deterministic(
                DeterministicEvaluationCode::StringEmptySeparator,
            ));
            return false;
        }
        for _ in 0..quantum {
            match self.phase {
                Phase::Search => {
                    if self
                        .search
                        .advance(source.as_bytes(), separator.as_bytes(), 1)
                    {
                        continue;
                    }
                    if let Some(range) = self.search.match_range(separator.len()) {
                        self.end = range.start;
                        self.match_end = range.end;
                        self.tail = false;
                    } else {
                        self.end = source.len();
                        self.tail = true;
                    }
                    let next = u64::try_from(self.items.len())
                        .ok()
                        .and_then(|count| count.checked_add(1));
                    if next.is_none_or(|count| count > limits.maximum_list_items()) {
                        self.error = Some(RuntimeCode::Deterministic(
                            DeterministicEvaluationCode::ListSizeLimit,
                        ));
                        return false;
                    }
                    self.cursor = self.start;
                    self.scalars = 0;
                    self.phase = Phase::Count;
                }
                Phase::Count => {
                    if let Some(scalar) = source[self.cursor..self.end].chars().next() {
                        let Some(next) = self
                            .scalars
                            .checked_add(1)
                            .filter(|count| *count <= limits.maximum_string_scalars())
                        else {
                            self.error = Some(RuntimeCode::Deterministic(
                                DeterministicEvaluationCode::StringSizeLimit,
                            ));
                            return false;
                        };
                        self.scalars = next;
                        self.cursor += scalar.len_utf8();
                    } else {
                        self.cursor = self.start;
                        self.phase = Phase::Copy;
                    }
                }
                Phase::Copy => {
                    if let Some(scalar) = source[self.cursor..self.end].chars().next() {
                        self.piece.push(scalar);
                        self.cursor += scalar.len_utf8();
                    } else {
                        self.phase = Phase::Construct;
                    }
                }
                Phase::Construct => {
                    let piece = std::mem::take(&mut self.piece);
                    match LogicalValue::string(piece, limits) {
                        Ok(value) => self.items.push(value),
                        Err(error) => {
                            self.error = Some(map_string_value_error(error));
                            return false;
                        }
                    }
                    if self.tail {
                        self.complete = true;
                        return false;
                    }
                    self.start = self.match_end;
                    self.search.resume_nonoverlapping();
                    self.phase = Phase::Search;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::StringSplitWork;
    use crate::machine::{evaluate_primitive, map_list_value_error};
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValueLimits};
    use gantry_ir::Primitive;

    /// Tiny quanta preserve empty segments, nonoverlapping separators and legacy refusal order.
    #[test]
    fn incremental_split_preserves_segments_and_admission_order() {
        for source in ["", "a", ",a,,", "aaaaa", "é😀é😀", "no match"] {
            for separator in ["", ",", "aa", "é", "😀", "longer than input"] {
                for maximum in 1..=6 {
                    for items in 1..=6 {
                        let limits = ValueLimits::new(8, 100, maximum, items)
                            .unwrap_or_else(|| panic!("limits"));
                        let operands = [source, separator].map(|text| {
                            LogicalValue::string(text, DEFAULT_VALUE_LIMITS)
                                .unwrap_or_else(|error| panic!("operand: {error:?}"))
                        });
                        let expected =
                            evaluate_primitive(Primitive::StringSplit, &operands, limits);
                        let mut work = StringSplitWork::default();
                        let mut calls = 0;
                        while work.advance(source, separator, limits, 1) {
                            calls += 1;
                            assert!(calls < 1000, "split must make finite progress");
                            assert!(work.items.len() as u64 <= items);
                        }
                        let actual = work.error.map_or_else(
                            || {
                                LogicalValue::list(work.items.clone(), limits)
                                    .map_err(map_list_value_error)
                            },
                            Err,
                        );
                        assert_eq!(
                            actual, expected,
                            "{source:?}, {separator:?}, {maximum}, {items}"
                        );
                        assert!(!work.advance(source, separator, limits, 1));
                    }
                }
            }
        }
        let limits = ValueLimits::new(8, 100, 1, 1).unwrap_or_else(|| panic!("limits"));
        let mut work = StringSplitWork::default();
        while work.advance(",long", ",", limits, 1) {}
        assert_eq!(
            work.error,
            Some(super::RuntimeCode::Deterministic(
                gantry_core::portable::DeterministicEvaluationCode::ListSizeLimit
            ))
        );
        assert_eq!(
            work.items.len(),
            1,
            "List place refusal precedes the next String limit"
        );
    }
}
