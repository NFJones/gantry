//! Recomputable bounded substring-search scratch, never a logical checkpoint fact.
//!
//! Incremental prefix-table construction and matching use the same finite work quantum.
//! Immutable UTF-8 operands remain machine-owned; byte matching gives exact String containment.

/// One private linear-time search over unchanged source and pattern operands.
#[derive(Clone, Debug, Default)]
pub(super) struct StringSearchWork {
    /// Prefix lengths for the processed pattern, built incrementally rather than eagerly.
    prefix: Vec<usize>,
    /// Pattern index currently being admitted to the prefix table.
    build: usize,
    /// Current prefix length during table construction or matching.
    matched: usize,
    /// Source position, retained across scheduling-only yields.
    offset: usize,
    /// Complete Boolean result, kept private until ordinary primitive publication.
    pub(super) result: Option<bool>,
}

impl StringSearchWork {
    /// Performs at most `quantum` prefix/search comparisons, returning true if work remains.
    /// Fallback consumes a work unit without advancing input, preventing repeated-prefix
    /// adversaries from monopolizing a call. No prefix state or provisional result is exposed.
    pub(super) fn advance(&mut self, source: &[u8], pattern: &[u8], quantum: usize) -> bool {
        if self.result.is_some() {
            return false;
        }
        if pattern.is_empty() || pattern.len() > source.len() {
            self.result = Some(pattern.is_empty());
            return false;
        }
        if self.prefix.is_empty() {
            self.prefix.push(0);
            self.build = 1;
        }
        for _ in 0..quantum {
            if self.build < pattern.len() {
                if pattern[self.build] == pattern[self.matched] {
                    self.matched += 1;
                    self.prefix.push(self.matched);
                    self.build += 1;
                } else if self.matched != 0 {
                    self.matched = self.prefix[self.matched - 1];
                } else {
                    self.prefix.push(0);
                    self.build += 1;
                }
                if self.build == pattern.len() {
                    self.matched = 0;
                }
                continue;
            }
            if self.offset == source.len() {
                self.result = Some(false);
                return false;
            }
            if source[self.offset] == pattern[self.matched] {
                self.offset += 1;
                self.matched += 1;
                if self.matched == pattern.len() {
                    self.result = Some(true);
                    return false;
                }
            } else if self.matched != 0 {
                self.matched = self.prefix[self.matched - 1];
            } else {
                self.offset += 1;
            }
        }
        if self.build == pattern.len() && self.offset == source.len() {
            self.result = Some(false);
            return false;
        }
        true
    }

    /// Returns the completed match's source range without exposing partial search progress.
    pub(super) fn match_range(&self, pattern_length: usize) -> Option<std::ops::Range<usize>> {
        (self.result == Some(true)).then(|| self.offset - pattern_length..self.offset)
    }

    /// Continues after a complete nonempty match, retaining the table but excluding overlap.
    pub(super) fn resume_nonoverlapping(&mut self) {
        debug_assert_eq!(self.result, Some(true));
        self.result = None;
        self.matched = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::StringSearchWork;

    /// Small work quanta must preserve exact matching while avoiding repeated-prefix rescans.
    #[test]
    fn incremental_search_matches_exact_contains_with_linear_work() {
        let mut texts = vec![String::new(), "é😀é".to_owned()];
        for length in 1..=7 {
            for bits in 0..(1_usize << length) {
                texts.push(
                    (0..length)
                        .map(|index| if bits & (1 << index) == 0 { 'a' } else { 'b' })
                        .collect(),
                );
            }
        }
        for source in &texts {
            for pattern in &texts {
                let mut work = StringSearchWork::default();
                let bound = 2 * (source.len() + pattern.len()) + 2;
                let mut calls = 0;
                while work.advance(source.as_bytes(), pattern.as_bytes(), 1) {
                    calls += 1;
                    assert!(
                        calls <= bound,
                        "search must remain linear: {source:?}, {pattern:?}"
                    );
                    assert!(work.prefix.len() <= pattern.len());
                    assert!(work.result.is_none());
                }
                assert_eq!(work.result, Some(source.contains(pattern.as_str())));
                assert!(!work.advance(source.as_bytes(), pattern.as_bytes(), 1));
            }
        }
    }
}
