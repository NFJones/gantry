//! Recomputable bounded uppercase construction over unchanged logical String input.
//!
//! Each complete pinned mapping is checked before private accumulation. No partial output
//! enters machine state; final logical construction and charging belong to primitive publication.

use gantry_core::unicode::push_full_uppercase;

/// Private mapping progress, omitted from logical checkpoints and rebuilt on recovery.
#[derive(Clone, Debug, Default)]
pub(super) struct StringUppercaseWork {
    offset: usize,
    scalars: u64,
    pub(super) output: String,
    pub(super) complete: bool,
    pub(super) failed: bool,
}

impl StringUppercaseWork {
    /// Maps at most `quantum` input scalars, admitting each whole expansion before appending.
    /// Exhaustion retains no publishable result; allocations are not a latency guarantee.
    pub(super) fn advance(&mut self, source: &str, maximum: u64, quantum: usize) -> bool {
        if self.complete || self.failed {
            return false;
        }
        let mut piece = String::new();
        for scalar in source[self.offset..].chars().take(quantum) {
            piece.clear();
            push_full_uppercase(scalar, &mut piece);
            let next = self.scalars.checked_add(piece.chars().count() as u64);
            let Some(next) = next.filter(|next| *next <= maximum) else {
                self.failed = true;
                return false;
            };
            self.output.push_str(&piece);
            self.scalars = next;
            self.offset += scalar.len_utf8();
        }
        self.complete = self.offset == source.len();
        !self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::StringUppercaseWork;
    use gantry_core::unicode::to_full_uppercase_bounded;

    /// Small chunks preserve pinned expansions and refuse a whole mapping before appending it.
    #[test]
    fn incremental_uppercase_preserves_mapping_and_output_admission() {
        for source in ["", "abc", "ßé", "ﬃ", "ΟΣ", "😀a"] {
            for maximum in 0..=8 {
                let expected = to_full_uppercase_bounded(source, maximum);
                let mut work = StringUppercaseWork::default();
                let mut calls = 0;
                while work.advance(source, maximum, 1) {
                    calls += 1;
                    assert!(calls <= source.chars().count());
                    assert!(work.scalars <= maximum);
                    assert!(!work.complete);
                }
                assert_eq!(!work.failed, expected.is_some());
                if let Some(expected) = expected {
                    assert!(work.complete);
                    assert_eq!(work.output, expected);
                }
                assert!(!work.advance(source, maximum, 1));
            }
        }
        let mut work = StringUppercaseWork::default();
        assert!(work.advance("aß", 2, 1));
        assert!(!work.advance("aß", 2, 1));
        assert!(work.failed);
        assert_eq!(
            work.output, "A",
            "refused expansion must not append a prefix"
        );
        assert_eq!(work.scalars, 1);
    }
}
