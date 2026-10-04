//! Recomputable bounded concatenation copying over immutable logical String operands.
//!
//! Complete scalar-size admission belongs to the machine before copying starts. Only private
//! output advances here; final logical construction and transition charging remain atomic.

/// Private copy progress, omitted from checkpoints and rebuilt after recovery.
#[derive(Clone, Debug, Default)]
pub(super) struct StringConcatWork {
    side: usize,
    offset: usize,
    pub(super) output: String,
    pub(super) complete: bool,
    pub(super) failed: bool,
}

impl StringConcatWork {
    /// Copies at most `quantum` scalars from the two already admitted pieces.
    /// Scalar-aligned offsets preserve UTF-8; allocation and final construction are not
    /// covered by the finite copy-work bound.
    pub(super) fn advance(&mut self, pieces: [&str; 2], quantum: usize) -> bool {
        if self.complete || self.failed {
            return false;
        }
        let mut remaining = quantum;
        while self.side < pieces.len() && remaining != 0 {
            let piece = pieces[self.side];
            let mut end = self.offset;
            for scalar in piece[self.offset..].chars().take(remaining) {
                end += scalar.len_utf8();
                remaining -= 1;
            }
            self.output.push_str(&piece[self.offset..end]);
            self.offset = end;
            if end == piece.len() {
                self.side += 1;
                self.offset = 0;
            }
        }
        self.complete = self.side == pieces.len();
        !self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::StringConcatWork;

    /// Small quanta retain exact concatenation and scalar-aligned boundaries across pieces.
    #[test]
    fn incremental_copy_preserves_empty_and_unicode_pieces() {
        for pieces in [["", ""], ["", "é"], ["😀", ""], ["éa", "😀b"]] {
            let mut work = StringConcatWork::default();
            let mut calls = 0;
            while work.advance(pieces, 1) {
                calls += 1;
                assert!(
                    calls
                        <= pieces
                            .iter()
                            .map(|piece| piece.chars().count())
                            .sum::<usize>()
                            + 1
                );
                assert!(!work.complete);
            }
            assert_eq!(work.output, pieces.concat());
            assert!(!work.advance(pieces, 1));
        }
    }
}
