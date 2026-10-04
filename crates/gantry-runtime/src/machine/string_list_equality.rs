//! Recomputable bounded member/octet comparison for flat logical String lists.
//!
//! No operands or result are published here. Non-String members retain the general
//! equality owner's semantics; allocation and logical-value disposal are not latency bounds.

use gantry_core::value::LogicalValue;

/// Offsets only; checkpoint recovery restarts from retained immutable operands.
#[derive(Clone, Debug, Default)]
pub(super) struct StringListEqualityWork {
    member: usize,
    offset: usize,
    admitted: bool,
    pub(super) result: Option<bool>,
    pub(super) unsupported: bool,
}

impl StringListEqualityWork {
    /// Shares one finite allowance across member admission and compared octets.
    /// Empty members spend admission work, so large empty lists cannot bypass yielding.
    pub(super) fn advance(
        &mut self,
        left: &LogicalValue,
        right: &LogicalValue,
        quantum: usize,
    ) -> bool {
        if self.result.is_some() || self.unsupported {
            return false;
        }
        let (Some(length), Some(other_length)) = (left.aggregate_len(), right.aggregate_len())
        else {
            self.unsupported = true;
            return false;
        };
        if length != other_length {
            self.result = Some(false);
            return false;
        }
        let mut remaining = quantum;
        while self.member < length && remaining != 0 {
            let (Some(left), Some(right)) = (left.member(self.member), right.member(self.member))
            else {
                self.unsupported = true;
                return false;
            };
            let (Some(left), Some(right)) = (left.as_string(), right.as_string()) else {
                self.unsupported = true;
                return false;
            };
            if !self.admitted {
                remaining -= 1;
                self.admitted = true;
                if left.len() != right.len() {
                    self.result = Some(false);
                    return false;
                }
            }
            let end = self.offset.saturating_add(remaining).min(left.len());
            if left.as_bytes()[self.offset..end] != right.as_bytes()[self.offset..end] {
                self.result = Some(false);
                return false;
            }
            remaining -= end - self.offset;
            self.offset = end;
            if end == left.len() {
                self.member += 1;
                self.offset = 0;
                self.admitted = false;
            }
        }
        if self.member == length {
            self.result = Some(true);
        }
        self.result.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::StringListEqualityWork;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};

    /// Tiny quanta preserve exact results across empty and multibyte members.
    #[test]
    fn incremental_lists_match_general_equality() {
        let lists = [
            vec![],
            vec![""],
            vec!["", ""],
            vec!["é", "😀"],
            vec!["é", "x"],
        ];
        for left in &lists {
            for right in &lists {
                let make = |pieces: &Vec<&str>| {
                    LogicalValue::list(
                        pieces
                            .iter()
                            .map(|piece| {
                                LogicalValue::string(*piece, DEFAULT_VALUE_LIMITS)
                                    .unwrap_or_else(|error| panic!("String: {error:?}"))
                            })
                            .collect(),
                        DEFAULT_VALUE_LIMITS,
                    )
                    .unwrap_or_else(|error| panic!("List: {error:?}"))
                };
                let left = make(left);
                let right = make(right);
                let mut work = StringListEqualityWork::default();
                let mut calls = 0;
                while work.advance(&left, &right, 1) {
                    calls += 1;
                    assert!(calls < 64, "finite fixture must complete");
                }
                assert_eq!(work.result, Some(left == right));
                assert!(!work.advance(&left, &right, 1));
            }
        }
    }
}
