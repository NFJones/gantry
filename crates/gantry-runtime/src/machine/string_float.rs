//! Recomputable grammar-only Float token admission over unchanged String operands.
//!
//! Exact range conversion and binary64 rounding remain synchronous under the existing owner.
//! A grammar endpoint is not conversion authority; private preparation revalidates the complete
//! token before caching its numeric result, outside the shared execution-budget mutex.

use gantry_core::numeric::GantryFloat;
use gantry_core::strict_json::{JsonNumberScanner, parse_json_float};

/// Private grammar progress, omitted from logical checkpoints.
#[derive(Clone, Debug)]
pub(super) struct StringFloatWork {
    scanner: JsonNumberScanner,
    /// Absent while pending; completed parsing retains either no value or one finite Float.
    pub(super) result: Option<Option<GantryFloat>>,
}

impl Default for StringFloatWork {
    fn default() -> Self {
        Self {
            scanner: JsonNumberScanner::new(0),
            result: None,
        }
    }
}

impl StringFloatWork {
    /// Runs a finite grammar quantum, requiring whole-input consumption on completion.
    /// Refusal is an ordinary absent parse result, never a task failure or partial number.
    /// Successful grammar is revalidated by the existing synchronous conversion owner before
    /// caching the result. Neither grammar nor conversion holds the machine's budget lock.
    pub(super) fn advance(&mut self, source: &str, quantum: usize) -> bool {
        if self.result.is_some() {
            return false;
        }
        if let Some(outcome) = self.scanner.advance(source.as_bytes(), quantum) {
            self.result = Some(if outcome.is_ok_and(|end| end == source.len()) {
                parse_json_float(source).and_then(GantryFloat::new)
            } else {
                None
            });
            false
        } else {
            true
        }
    }
}
