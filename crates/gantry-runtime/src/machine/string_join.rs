//! Recomputable cooperative List<String> joining over immutable logical operands.
//!
//! Each separator/item is admitted in existing evaluation order before copying it. Only
//! private output advances; publication and the single transition charge remain machine-owned.

use gantry_core::portable::DeterministicEvaluationCode;
use gantry_core::value::{LogicalValue, LogicalValueView};

use super::RuntimeCode;

/// Private piece-admission and copy progress, omitted from checkpoints.
#[derive(Clone, Debug, Default)]
pub(super) struct StringJoinWork {
    index: usize,
    separator: bool,
    admitted: bool,
    offset: usize,
    scalars: u64,
    pub(super) output: String,
    pub(super) complete: bool,
    pub(super) error: Option<RuntimeCode>,
}

impl StringJoinWork {
    /// Advances at most `quantum` piece admissions or scalar copies.
    /// Empty pieces consume admission work too, so an empty-item list cannot monopolize a call.
    /// Complete piece metrics are checked before copying, with separator-before-item precedence.
    pub(super) fn advance(
        &mut self,
        list: &LogicalValue,
        separator: &LogicalValue,
        maximum: u64,
        quantum: usize,
    ) -> bool {
        if self.complete || self.error.is_some() {
            return false;
        }
        let LogicalValueView::List(length) = list.view() else {
            self.error = Some(RuntimeCode::InternalInvariant);
            return false;
        };
        let mut remaining = quantum;
        while remaining != 0 {
            if self.index == length {
                self.complete = true;
                return false;
            }
            let piece = if self.separator {
                separator.clone()
            } else {
                let Some(item) = list.member(self.index) else {
                    self.error = Some(RuntimeCode::InternalInvariant);
                    return false;
                };
                item
            };
            let Some(text) = piece.as_string() else {
                self.error = Some(RuntimeCode::InternalInvariant);
                return false;
            };
            if !self.admitted {
                let next = self
                    .scalars
                    .checked_add(piece.metrics().maximum_string_scalars);
                let Some(next) = next.filter(|count| *count <= maximum) else {
                    self.error = Some(RuntimeCode::Deterministic(
                        DeterministicEvaluationCode::StringSizeLimit,
                    ));
                    return false;
                };
                self.scalars = next;
                self.admitted = true;
                remaining -= 1;
            }
            let mut end = self.offset;
            for scalar in text[self.offset..].chars().take(remaining) {
                end += scalar.len_utf8();
                remaining -= 1;
            }
            self.output.push_str(&text[self.offset..end]);
            self.offset = end;
            if end == text.len() {
                if self.separator {
                    self.separator = false;
                } else {
                    self.index += 1;
                    self.separator = true;
                }
                self.offset = 0;
                self.admitted = false;
            }
        }
        self.complete = self.index == length;
        !self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::StringJoinWork;
    use crate::machine::evaluate_primitive;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValueLimits};
    use gantry_ir::Primitive;

    /// Small quanta preserve legacy piece order and whole-piece admission, including empty items.
    #[test]
    fn incremental_join_preserves_piece_admission_and_refusal_order() {
        for items in [
            vec![],
            vec![""],
            vec!["é"],
            vec!["", "", ""],
            vec!["é", "😀", "a"],
        ] {
            for separator in ["", "😀"] {
                let list = LogicalValue::list(
                    items
                        .iter()
                        .map(|item| {
                            LogicalValue::string(*item, DEFAULT_VALUE_LIMITS)
                                .unwrap_or_else(|error| panic!("item: {error:?}"))
                        })
                        .collect(),
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("list: {error:?}"));
                let separator = LogicalValue::string(separator, DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("separator: {error:?}"));
                for maximum in 1..=8 {
                    let limits =
                        ValueLimits::new(8, 100, maximum, 100).unwrap_or_else(|| panic!("limits"));
                    let expected = evaluate_primitive(
                        Primitive::StringListJoin,
                        &[list.clone(), separator.clone()],
                        limits,
                    );
                    let mut work = StringJoinWork::default();
                    let mut calls = 0;
                    while work.advance(&list, &separator, maximum, 1) {
                        calls += 1;
                        assert!(calls < 100, "empty pieces must still make finite progress");
                        assert!(work.scalars <= maximum);
                    }
                    let actual = work.error.map_or_else(
                        || {
                            LogicalValue::string(work.output, limits)
                                .map_err(crate::machine::map_string_value_error)
                        },
                        Err,
                    );
                    assert_eq!(actual, expected);
                }
            }
        }
        let list = LogicalValue::list(
            vec![
                LogicalValue::string("a", DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("item: {error:?}")),
                LogicalValue::unit(),
            ],
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("list: {error:?}"));
        let separator = LogicalValue::string("xx", DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("separator: {error:?}"));
        let mut work = StringJoinWork::default();
        while work.advance(&list, &separator, 2, 1) {}
        assert_eq!(
            work.error,
            Some(super::RuntimeCode::Deterministic(
                gantry_core::portable::DeterministicEvaluationCode::StringSizeLimit
            ))
        );
        assert_eq!(
            work.output, "a",
            "separator admission precedes the invalid next item"
        );
    }
}
