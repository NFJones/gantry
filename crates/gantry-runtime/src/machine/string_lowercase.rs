//! Recomputable contextual lowercase work over immutable logical String operands.
//!
//! Scalar collection, backward Final_Sigma context and forward mapping share one finite
//! work quantum. Scratch and accumulated output stay private until primitive publication.

use gantry_core::unicode::{is_case_ignorable, is_cased, push_full_lowercase};

/// Exactly one pass of the private contextual mapping algorithm.
#[derive(Clone, Debug, Default)]
enum Phase {
    #[default]
    Collect,
    Context,
    Map,
}

/// Private mapping state, discarded on recovery or terminal settlement.
#[derive(Clone, Debug, Default)]
pub(super) struct StringLowercaseWork {
    phase: Phase,
    offset: usize,
    characters: Vec<(char, bool)>,
    index: usize,
    next_cased: bool,
    before_cased: bool,
    scalars: u64,
    pub(super) output: String,
    pub(super) complete: bool,
    pub(super) failed: bool,
}

impl StringLowercaseWork {
    /// Performs at most `quantum` scalar collection, context or mapping steps.
    /// Each whole pinned expansion must fit before accumulation. Allocation and final
    /// logical construction are outside this work bound; no partial output is published.
    pub(super) fn advance(&mut self, source: &str, maximum: u64, quantum: usize) -> bool {
        if self.complete || self.failed {
            return false;
        }
        let mut piece = String::new();
        for _ in 0..quantum {
            match self.phase {
                Phase::Collect => {
                    if let Some(scalar) = source[self.offset..].chars().next() {
                        self.characters.push((scalar, false));
                        self.offset += scalar.len_utf8();
                    }
                    if self.offset == source.len() {
                        self.index = self.characters.len();
                        self.phase = Phase::Context;
                    }
                }
                Phase::Context => {
                    if self.index != 0 {
                        self.index -= 1;
                        let (scalar, after_cased) = &mut self.characters[self.index];
                        *after_cased = self.next_cased;
                        if !is_case_ignorable(*scalar) {
                            self.next_cased = is_cased(*scalar);
                        }
                    }
                    if self.index == 0 {
                        self.phase = Phase::Map;
                    }
                }
                Phase::Map => {
                    let Some(&(scalar, after_cased)) = self.characters.get(self.index) else {
                        self.complete = true;
                        return false;
                    };
                    piece.clear();
                    if scalar == '\u{03A3}' && self.before_cased && !after_cased {
                        piece.push('\u{03C2}');
                    } else {
                        push_full_lowercase(scalar, &mut piece);
                    }
                    let next = self.scalars.checked_add(piece.chars().count() as u64);
                    let Some(next) = next.filter(|next| *next <= maximum) else {
                        self.failed = true;
                        return false;
                    };
                    self.output.push_str(&piece);
                    self.scalars = next;
                    if !is_case_ignorable(scalar) {
                        self.before_cased = is_cased(scalar);
                    }
                    self.index += 1;
                    if self.index == self.characters.len() {
                        self.complete = true;
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::StringLowercaseWork;
    use gantry_core::unicode::to_full_lowercase_bounded;

    /// Chunk boundaries must preserve contextual sigma and whole-expansion admission.
    #[test]
    fn incremental_lowercase_preserves_context_and_output_admission() {
        for source in [
            "",
            "ABC",
            "İ",
            "ΟΣ",
            "ΟΣΑ",
            "ΟΣ\u{301}Α",
            "ΟΣ\u{301}",
            "Σ",
            "AΣ AΣA",
            "😀A",
        ] {
            for maximum in 0..=12 {
                let expected = to_full_lowercase_bounded(source, maximum);
                let mut work = StringLowercaseWork::default();
                let mut calls = 0;
                while work.advance(source, maximum, 1) {
                    calls += 1;
                    assert!(calls <= 3 * source.chars().count() + 2);
                    assert!(work.characters.len() <= source.chars().count());
                    assert!(work.scalars <= maximum);
                    assert!(!work.complete);
                }
                assert_eq!(!work.failed, expected.is_some(), "{source:?}, {maximum}");
                if let Some(expected) = expected {
                    assert!(work.complete);
                    assert_eq!(work.output, expected);
                }
                assert!(!work.advance(source, maximum, 1));
            }
        }
        let mut work = StringLowercaseWork::default();
        while work.advance("Aİ", 2, 1) {}
        assert!(work.failed);
        assert_eq!(
            work.output, "a",
            "refused full expansion must not append its prefix"
        );
        assert_eq!(work.scalars, 1);
    }
}
