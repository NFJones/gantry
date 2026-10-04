//! Recomputable Unicode whitespace boundary scans over unchanged logical String operands.
//!
//! Only scalar-boundary offsets are retained. Scanning yields without publishing a substring;
//! final logical-value construction remains owned by ordinary atomic primitive publication.

use gantry_core::unicode::is_white_space;

/// Private boundary progress; never a logical checkpoint fact.
#[derive(Clone, Debug)]
pub(super) struct StringTrimWork {
    pub(super) start: usize,
    pub(super) end: usize,
    front: bool,
    back: bool,
    pub(super) complete: bool,
}

impl StringTrimWork {
    /// Initializes exactly the selected leading/trailing scans without touching input.
    pub(super) fn new(length: usize, front: bool, back: bool) -> Self {
        Self {
            start: 0,
            end: length,
            front,
            back,
            complete: false,
        }
    }

    /// Classifies at most `quantum` scalars, preserving exact pinned Unicode whitespace rules.
    /// Returns true only when another scan chunk is required before result construction.
    pub(super) fn advance(&mut self, source: &str, quantum: usize) -> bool {
        if self.complete {
            return false;
        }
        for _ in 0..quantum {
            if self.start == self.end {
                self.complete = true;
                return false;
            }
            if self.front {
                let scalar = source[self.start..self.end]
                    .chars()
                    .next()
                    .unwrap_or_else(|| unreachable!("nonempty scalar-boundary span"));
                if is_white_space(scalar) {
                    self.start += scalar.len_utf8();
                } else {
                    self.front = false;
                }
            } else if self.back {
                let scalar = source[self.start..self.end]
                    .chars()
                    .next_back()
                    .unwrap_or_else(|| unreachable!("nonempty scalar-boundary span"));
                if is_white_space(scalar) {
                    self.end -= scalar.len_utf8();
                } else {
                    self.back = false;
                }
            } else {
                self.complete = true;
                return false;
            }
        }
        self.complete = self.start == self.end || (!self.front && !self.back);
        !self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::StringTrimWork;
    use gantry_core::unicode::is_white_space;

    /// Small chunks retain scalar boundaries and the pinned leading/trailing trim semantics.
    #[test]
    fn incremental_trimming_preserves_unicode_boundaries() {
        for source in [
            "",
            "abc",
            " \t\n",
            "\u{2003}é\u{a0}",
            "\u{200b}é\u{200b}",
            " é x ",
        ] {
            for (front, back) in [(true, true), (true, false), (false, true)] {
                let expected = match (front, back) {
                    (true, true) => source.trim_matches(is_white_space),
                    (true, false) => source.trim_start_matches(is_white_space),
                    (false, true) => source.trim_end_matches(is_white_space),
                    _ => unreachable!("closed trim fixture"),
                };
                let mut work = StringTrimWork::new(source.len(), front, back);
                let mut calls = 0;
                while work.advance(source, 1) {
                    calls += 1;
                    assert!(calls <= source.chars().count() + 2);
                    assert!(source.is_char_boundary(work.start));
                    assert!(source.is_char_boundary(work.end));
                    assert!(!work.complete);
                }
                assert_eq!(&source[work.start..work.end], expected);
                assert!(!work.advance(source, 1));
            }
        }
    }
}
