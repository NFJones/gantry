//! Recomputable grammar and magnitude preflight over unchanged String operands.
//!
//! Exact range conversion and binary64 rounding remain synchronous under the existing owner.
//! A grammar endpoint is not conversion authority; private preparation revalidates the complete
//! token before caching its numeric result, outside the shared execution-budget mutex.

use gantry_core::numeric::GantryFloat;
use gantry_core::strict_json::{JsonNumberScanner, parse_json_float};

use super::string_float_range::StringFloatRangeWork;

/// Private grammar/range progress, omitted from logical checkpoints.
#[derive(Clone, Debug)]
pub(super) struct StringFloatWork {
    scanner: JsonNumberScanner,
    range: StringFloatRangeWork,
    /// Absent while pending; completed parsing retains either no value or one finite Float.
    pub(super) result: Option<Option<GantryFloat>>,
}

impl Default for StringFloatWork {
    fn default() -> Self {
        Self {
            scanner: JsonNumberScanner::new(0),
            range: StringFloatRangeWork::default(),
            result: None,
        }
    }
}

impl StringFloatWork {
    /// Runs finite grammar and range quanta, requiring whole-input consumption.
    /// Refusal is an ordinary absent parse result, never a task failure or partial number.
    /// Each scanner admits at most `quantum` units per call. In-range input is revalidated by
    /// the synchronous conversion owner; exact out-of-range input refuses without conversion.
    /// Neither grammar, range inspection nor conversion holds the machine's budget lock.
    pub(super) fn advance(&mut self, source: &str, quantum: usize) -> bool {
        if self.result.is_some() {
            return false;
        }
        if let Some(outcome) = self.scanner.advance(source.as_bytes(), quantum) {
            if !outcome.is_ok_and(|end| end == source.len()) {
                self.result = Some(None);
                return false;
            }
            let Some(in_range) = self.range.advance(source, quantum) else {
                return true;
            };
            self.result = Some(
                in_range
                    .then(|| parse_json_float(source).and_then(GantryFloat::new))
                    .flatten(),
            );
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StringFloatWork;

    /// Exact range inspection must not monopolize the grammar-completion call.
    #[test]
    fn range_preparation_yields_after_grammar_completion() {
        let source = format!("1{}e-10000", "0".repeat(10_000));
        let mut work = StringFloatWork::default();
        assert!(
            work.scanner
                .advance(source.as_bytes(), source.len() + 8)
                .is_some_and(|result| result == Ok(source.len()))
        );
        assert!(
            work.advance(&source, 4096),
            "range facts require separate bounded work"
        );
        assert!(work.result.is_none());
        let mut calls = 0;
        while work.advance(&source, 4096) {
            calls += 1;
            assert!(calls < 16, "finite fixture must finish");
        }
        assert_eq!(work.result.flatten().map(|value| value.get()), Some(1.0));
    }
}
