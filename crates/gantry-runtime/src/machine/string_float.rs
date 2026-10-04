//! Recomputable grammar-only Float token admission over unchanged String operands.
//!
//! Exact range conversion and binary64 rounding remain synchronous under the existing owner.
//! A grammar endpoint is not conversion authority; final parsing revalidates the complete token.

use gantry_core::strict_json::JsonNumberScanner;

/// Private grammar progress, omitted from logical checkpoints.
#[derive(Clone, Debug)]
pub(super) struct StringFloatWork {
    scanner: JsonNumberScanner,
    pub(super) valid: Option<bool>,
}

impl Default for StringFloatWork {
    fn default() -> Self {
        Self {
            scanner: JsonNumberScanner::new(0),
            valid: None,
        }
    }
}

impl StringFloatWork {
    /// Runs a finite grammar quantum, requiring whole-input consumption on completion.
    /// Refusal is an ordinary absent parse result, never a task failure or partial number.
    pub(super) fn advance(&mut self, source: &str, quantum: usize) -> bool {
        if self.valid.is_some() {
            return false;
        }
        if let Some(outcome) = self.scanner.advance(source.as_bytes(), quantum) {
            self.valid = Some(outcome.is_ok_and(|end| end == source.len()));
            false
        } else {
            true
        }
    }
}
