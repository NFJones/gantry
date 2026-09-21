//! The pure text foundation of `GNT-41.0-text-foundation-scope`,
//! `GNT-41.1-canonical-text-values`, `GNT-41.2-canonical-text-normalization`,
//! `GNT-41.3-canonical-text-case-mapping`, `GNT-41.4-canonical-text-builders`,
//! `GNT-41.5-canonical-text-traversal`, `GNT-41.6-canonical-text-comparison`,
//! `GNT-41.7-canonical-grapheme-clusters`, `GNT-41.8-bounded-text-matching`, and
//! `GNT-41.9-canonical-text-conversions`: canonical text values as finite sequences of Unicode
//! scalar values over the Section 35 scalar and octet contracts, their exact admission from octets
//! and UTF-16 code units, their scalar count and canonical UTF-8 octets, their scalar-boundary
//! slicing, their two canonical normalization forms, their two full default case mappings over the
//! pinned Unicode 16.0.0 data, an explicitly bounded builder that publishes one text value, a
//! forward cursor that publishes the scalars of a value one at a time, the canonical three-way
//! comparison their identity already decides, a forward cursor that publishes their extended
//! grapheme clusters, an explicitly bounded matcher over admitted patterns, and the declared
//! lossless octet-text mapping.
//!
//! The model is pure: it consumes no host locale, host encoding, ambient text facility, timing, or
//! global mutable state, and it declares no word, sentence, or line segmentation, no case folding,
//! no formatting, parsing, or interpolation beyond the declared pattern syntax, no host
//! regular-expression semantics, captures, or backtracking, no locale value or catalog, no
//! compatibility normalization form, and no boundary schema, recovery, or durable behavior.

use std::cmp::Ordering;
use std::fmt;

use gantry_core::unicode::{
    grapheme_cluster_boundaries, normalize_nfc, normalize_nfd, to_full_lowercase, to_full_uppercase,
};

use crate::scalar::CharValue;

/// The declared clauses of Section 41, in specification order
/// (`GNT-41.0` through `GNT-41.9`).
pub const TEXT_CLAUSES: [&str; 10] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
    "GNT-41.3-canonical-text-case-mapping",
    "GNT-41.4-canonical-text-builders",
    "GNT-41.5-canonical-text-traversal",
    "GNT-41.6-canonical-text-comparison",
    "GNT-41.7-canonical-grapheme-clusters",
    "GNT-41.8-bounded-text-matching",
    "GNT-41.9-canonical-text-conversions",
];

/// One frozen text-foundation diagnostic of `GNT-41.0-text-foundation-scope`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextDiagnosticCode {
    /// `GNT-41.1`: an octet sequence is not well-formed UTF-8.
    InvalidUtf8,
    /// `GNT-41.4`: appending to a builder would exceed its declared octet bound.
    BuilderBound,
    /// `GNT-41.8`: a pattern is not well formed under the declared pattern syntax.
    PatternSyntax,
    /// `GNT-41.8`: a pattern exceeds a declared pattern bound.
    PatternBound,
    /// `GNT-41.8`: a match exhausted the caller-declared step budget.
    MatchBudget,
    /// `GNT-41.9`: a UTF-16 code-unit sequence is not a well-formed encoding.
    InvalidUtf16,
}

impl TextDiagnosticCode {
    /// Every declared diagnostic, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::InvalidUtf8,
        Self::BuilderBound,
        Self::PatternSyntax,
        Self::PatternBound,
        Self::MatchBudget,
        Self::InvalidUtf16,
    ];

    /// Returns the registered refusal spelling.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "text-invalid-utf8",
            Self::BuilderBound => "text-builder-bound",
            Self::PatternSyntax => "text-pattern-syntax",
            Self::PatternBound => "text-pattern-bound",
            Self::MatchBudget => "text-match-budget",
            Self::InvalidUtf16 => "text-invalid-utf16",
        }
    }

    /// Returns the one clause that owns this refusal condition.
    #[must_use]
    pub fn owning_clause(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "GNT-41.1-canonical-text-values",
            Self::BuilderBound => "GNT-41.4-canonical-text-builders",
            Self::PatternSyntax => "GNT-41.8-bounded-text-matching",
            Self::PatternBound => "GNT-41.8-bounded-text-matching",
            Self::MatchBudget => "GNT-41.8-bounded-text-matching",
            Self::InvalidUtf16 => "GNT-41.9-canonical-text-conversions",
        }
    }
}

/// One published canonical normalization form of `GNT-41.2-canonical-text-normalization`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NormalizationForm {
    /// Normalization Form D, the canonical decomposition, spelled `nfd`.
    Nfd,
    /// Normalization Form C, the canonical composition, spelled `nfc`.
    Nfc,
}

impl NormalizationForm {
    /// Every declared form, in declaration order.
    pub const ALL: [Self; 2] = [Self::Nfd, Self::Nfc];

    /// Returns the registered spelling of the form.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::Nfd => "nfd",
            Self::Nfc => "nfc",
        }
    }
}

/// One published full default case mapping of `GNT-41.3-canonical-text-case-mapping`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaseMapping {
    /// The lowercase mapping, spelled `lower`.
    Lower,
    /// The uppercase mapping, spelled `upper`.
    Upper,
}

impl CaseMapping {
    /// Every declared mapping, in declaration order.
    pub const ALL: [Self; 2] = [Self::Lower, Self::Upper];

    /// Returns the registered spelling of the mapping.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::Lower => "lower",
            Self::Upper => "upper",
        }
    }
}

/// One published canonical comparison result of `GNT-41.6-canonical-text-comparison`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TextOrdering {
    /// The first value's scalar sequence orders before the second's.
    Less,
    /// The two scalar sequences are equal.
    Equal,
    /// The first value's scalar sequence orders after the second's.
    Greater,
}

impl TextOrdering {
    /// Every declared result, in declaration order.
    pub const ALL: [Self; 3] = [Self::Less, Self::Equal, Self::Greater];

    /// Returns the registered spelling of the result.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::Less => "less",
            Self::Equal => "equal",
            Self::Greater => "greater",
        }
    }
}

/// One published bounded text builder of `GNT-41.4-canonical-text-builders`.
///
/// A builder accumulates the canonical octets of text values up to a declared bound and publishes
/// exactly one text value: appending is explicit, ordered, and atomic, a refused append leaves the
/// builder exactly as it was, and `build` publishes a new value that shares no mutable storage with
/// the builder.
#[derive(Clone, Debug)]
pub struct TextBuilder {
    text: String,
    octet_bound: usize,
}

impl TextBuilder {
    /// Publishes a builder whose accumulated canonical octets may never exceed `octet_bound`.
    #[must_use]
    pub fn with_octet_bound(octet_bound: usize) -> Self {
        Self {
            text: String::new(),
            octet_bound,
        }
    }

    /// Returns the declared octet bound of the builder.
    #[must_use]
    pub fn octet_bound(&self) -> usize {
        self.octet_bound
    }

    /// Returns the number of canonical octets the builder has accumulated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns whether the builder has accumulated no octet at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Appends one text value, refusing under `text-builder-bound` when the declared bound would be
    /// exceeded; a refused append leaves the builder exactly as it was.
    pub fn append(&mut self, value: &TextValue) -> Result<(), TextError> {
        let appended = value.canonical_octets().len();
        let accumulated = self.text.len();
        if accumulated.saturating_add(appended) > self.octet_bound {
            return Err(TextError::new(
                TextDiagnosticCode::BuilderBound,
                format!(
                    "appending {appended} octet(s) to {accumulated} accumulated octet(s) exceeds the declared bound of {}",
                    self.octet_bound
                ),
            ));
        }
        self.text.push_str(&value.text);
        Ok(())
    }

    /// Publishes the text value whose canonical octets are exactly the accumulated sequence.
    #[must_use]
    pub fn build(&self) -> TextValue {
        TextValue {
            text: self.text.clone(),
        }
    }
}

/// One published forward scalar cursor of `GNT-41.5-canonical-text-traversal`.
///
/// A cursor publishes the scalars of the text value it traverses one at a time in sequence order,
/// never modifies that value, and holds no identity: it is not a text value, it is never serialized,
/// and no cursor position or progress is durable or recoverable.
#[derive(Clone, Debug)]
pub struct TextScalars<'a> {
    text: &'a str,
    remaining: usize,
}

impl TextScalars<'_> {
    /// Returns the number of scalars the cursor has not yet published.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Publishes the next scalar in sequence order, or none when every scalar has been published.
    pub fn next_scalar(&mut self) -> Option<CharValue> {
        let mut characters = self.text.chars();
        let character = characters.next()?;
        let scalar = CharValue::new(u32::from(character)).ok();
        self.text = characters.as_str();
        self.remaining -= 1;
        scalar
    }
}

/// One published forward extended grapheme cluster cursor of
/// `GNT-41.7-canonical-grapheme-clusters`.
///
/// The cursor publishes the value's extended grapheme clusters one at a time in sequence order and
/// never modifies the value; `remaining` starts at the value's cluster count.
pub struct TextGraphemes<'a> {
    text: &'a str,
    boundaries: Vec<usize>,
    published: usize,
}

impl TextGraphemes<'_> {
    /// Returns the number of clusters the cursor has not yet published.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.boundaries.len() - 1 - self.published
    }

    /// Publishes the next extended grapheme cluster in sequence order, or none when every cluster
    /// has been published.
    pub fn next_cluster(&mut self) -> Option<TextValue> {
        if self.published + 1 >= self.boundaries.len() {
            return None;
        }
        let from = self.boundaries[self.published];
        let to = self.boundaries[self.published + 1];
        self.published += 1;
        self.text.get(from..to).map(|slice| TextValue {
            text: slice.to_owned(),
        })
    }
}

/// One refused text-foundation decision of `GNT-41.0-text-foundation-scope`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextError {
    code: TextDiagnosticCode,
    detail: String,
}

impl TextError {
    /// Declares one refusal under its owning diagnostic.
    pub fn new(code: TextDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the owning diagnostic.
    #[must_use]
    pub fn code(&self) -> TextDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail, which names the failing octet index for `text-invalid-utf8`.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for TextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.spelling(), self.detail)
    }
}

/// One canonical text value of `GNT-41.1-canonical-text-values`: a finite sequence of Unicode
/// scalar values whose canonical encoding is UTF-8.
///
/// The identity of a value is exactly its scalar sequence, so equality and ordering are decided on
/// the scalars rather than on the octets that carry them, and a value is immutable: every
/// operation publishes a new value or an observation and never modifies the value it was given.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TextValue {
    text: String,
}

impl TextValue {
    /// Publishes the empty text value of `GNT-41.1-canonical-text-values`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            text: String::new(),
        }
    }

    /// Admits one octet sequence as a text value (`GNT-41.1-canonical-text-values`).
    ///
    /// The sequence is admitted exactly when it is well-formed UTF-8, and the admitted value keeps
    /// exactly the octets it was admitted from, so nothing is normalized, re-encoded, or stripped.
    /// An ill-formed, truncated, over-long, or surrogate encoding is refused under
    /// `text-invalid-utf8`, naming the zero-based octet index at which well-formed decoding fails.
    pub fn from_octets(octets: &[u8]) -> Result<Self, TextError> {
        match std::str::from_utf8(octets) {
            Ok(text) => Ok(Self {
                text: text.to_owned(),
            }),
            Err(error) => Err(TextError::new(
                TextDiagnosticCode::InvalidUtf8,
                format!(
                    "octet {} does not begin a well-formed UTF-8 scalar sequence",
                    error.valid_up_to()
                ),
            )),
        }
    }

    /// Publishes the text value holding the given scalar values in order
    /// (`GNT-41.1-canonical-text-values`).
    #[must_use]
    pub fn from_scalars(scalars: &[CharValue]) -> Self {
        let mut text = String::new();
        for scalar in scalars {
            text.push_str(&scalar.to_canonical_string());
        }
        Self { text }
    }

    /// Returns the number of scalar values the value holds (`GNT-41.1-canonical-text-values`).
    #[must_use]
    pub fn scalar_count(&self) -> usize {
        self.text.chars().count()
    }

    /// Returns the canonical UTF-8 octets of the value (`GNT-41.1-canonical-text-values`).
    #[must_use]
    pub fn canonical_octets(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// Admits one UTF-16 code-unit sequence as a text value
    /// (`GNT-41.9-canonical-text-conversions`).
    ///
    /// The sequence is admitted exactly when every code unit is either a scalar value's own code
    /// unit or one half of a well-formed surrogate pair, so a lone or unpaired surrogate is refused
    /// under `text-invalid-utf16`, naming the zero-based code-unit index of the offending unit, and
    /// nothing is replaced, dropped, reversed, or normalized.
    pub fn from_utf16_code_units(code_units: &[u16]) -> Result<Self, TextError> {
        let mut text = String::new();
        let mut index = 0_usize;
        while index < code_units.len() {
            let unit = code_units[index];
            if (0xD800..0xDC00).contains(&unit) {
                let low = code_units.get(index + 1).copied().ok_or_else(|| {
                    TextError::new(
                        TextDiagnosticCode::InvalidUtf16,
                        format!("code unit {index} is a high surrogate with no low surrogate"),
                    )
                })?;
                if !(0xDC00..0xE000).contains(&low) {
                    return Err(TextError::new(
                        TextDiagnosticCode::InvalidUtf16,
                        format!(
                            "code unit {index} is a high surrogate not followed by a low surrogate"
                        ),
                    ));
                }
                let value =
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                text.push(char::from_u32(value).ok_or_else(|| {
                    TextError::new(
                        TextDiagnosticCode::InvalidUtf16,
                        format!("code unit {index} does not encode a scalar value"),
                    )
                })?);
                index += 2;
            } else if (0xDC00..0xE000).contains(&unit) {
                return Err(TextError::new(
                    TextDiagnosticCode::InvalidUtf16,
                    format!("code unit {index} is a low surrogate with no high surrogate"),
                ));
            } else {
                text.push(char::from_u32(u32::from(unit)).ok_or_else(|| {
                    TextError::new(
                        TextDiagnosticCode::InvalidUtf16,
                        format!("code unit {index} does not encode a scalar value"),
                    )
                })?);
                index += 1;
            }
        }
        Ok(Self { text })
    }

    /// Publishes the canonical UTF-16 code units of the value
    /// (`GNT-41.9-canonical-text-conversions`): the code units of the value's scalar sequence in
    /// scalar order, with every scalar outside the basic multilingual plane encoded as one
    /// surrogate pair, and with no byte-order mark, padding, or reversal.
    #[must_use]
    pub fn utf16_code_units(&self) -> Vec<u16> {
        self.text.encode_utf16().collect()
    }

    /// Publishes one text value from an octet sequence under the declared lossless octet-text
    /// mapping (`GNT-41.9-canonical-text-conversions`): every octet maps to the scalar value with
    /// the same numeric value, so the conversion is total, admits every octet sequence, and keeps
    /// every octet it was given.
    #[must_use]
    pub fn from_lossless_octets(octets: &[u8]) -> Self {
        Self {
            text: octets.iter().map(|octet| char::from(*octet)).collect(),
        }
    }

    /// Publishes the octets of the value under the declared lossless octet-text mapping, or nothing
    /// when some scalar of the value has no octet under that mapping
    /// (`GNT-41.9-canonical-text-conversions`).
    #[must_use]
    pub fn lossless_octets(&self) -> Option<Vec<u8>> {
        self.text
            .chars()
            .map(|scalar| u8::try_from(u32::from(scalar)).ok())
            .collect()
    }

    /// Returns whether the value holds no scalar at all (`GNT-41.1-canonical-text-values`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Returns the scalar value at one zero-based scalar position, or none
    /// (`GNT-41.1-canonical-text-values`).
    #[must_use]
    pub fn scalar_at(&self, position: usize) -> Option<CharValue> {
        self.text
            .chars()
            .nth(position)
            .and_then(|scalar| CharValue::new(u32::from(scalar)).ok())
    }

    /// Publishes the scalar-boundary slice holding the scalars whose positions lie in the half-open
    /// range `start..end` (`GNT-41.1-canonical-text-values`).
    ///
    /// A position of this contract is a scalar position, so `start > end` or `end` beyond the
    /// scalar count publishes nothing rather than clamping, extending, re-encoding, or filling with
    /// a replacement scalar, and no slice can publish a partial scalar or an ill-formed sequence.
    #[must_use]
    pub fn slice_scalars(&self, start: usize, end: usize) -> Option<Self> {
        if start > end {
            return None;
        }
        let boundaries = self.boundaries();
        let (Some(&from), Some(&to)) = (boundaries.get(start), boundaries.get(end)) else {
            return None;
        };
        self.text.get(from..to).map(|slice| Self {
            text: slice.to_owned(),
        })
    }

    /// Publishes the named canonical normalization form of the value
    /// (`GNT-41.2-canonical-text-normalization`).
    ///
    /// Normalization is total and deterministic over the pinned Unicode 16.0.0 data: it publishes a
    /// new value whose identity is the normalized scalar sequence, never modifies the value it was
    /// given, and is idempotent in each published form.
    #[must_use]
    pub fn normalize(&self, form: NormalizationForm) -> Self {
        let text = match form {
            NormalizationForm::Nfd => normalize_nfd(&self.text),
            NormalizationForm::Nfc => normalize_nfc(&self.text),
        };
        Self { text }
    }

    /// Publishes the named full default case mapping of the value
    /// (`GNT-41.3-canonical-text-case-mapping`).
    ///
    /// The mapping is total and deterministic over the pinned Unicode 16.0.0 data, locale-neutral,
    /// and applied to each scalar in sequence order, so the result may hold a different number of
    /// scalars than the value it was mapped from; the value it was given is never modified.
    #[must_use]
    pub fn map_case(&self, mapping: CaseMapping) -> Self {
        let text = match mapping {
            CaseMapping::Lower => to_full_lowercase(&self.text),
            CaseMapping::Upper => to_full_uppercase(&self.text),
        };
        Self { text }
    }

    /// Publishes a forward scalar cursor over the value
    /// (`GNT-41.5-canonical-text-traversal`).
    ///
    /// The cursor publishes the value's scalars one at a time in sequence order and never modifies
    /// the value; `remaining` starts at the value's scalar count.
    #[must_use]
    pub fn scalars(&self) -> TextScalars<'_> {
        TextScalars {
            text: &self.text,
            remaining: self.scalar_count(),
        }
    }

    /// Publishes the canonical three-way comparison of the value with another value
    /// (`GNT-41.6-canonical-text-comparison`).
    ///
    /// The result is decided by the two scalar sequences: `equal` exactly when the values are
    /// equal, and otherwise by the first differing scalar, so a proper prefix orders before the
    /// value it prefixes. Comparison never normalizes, case-maps, or modifies its operands.
    #[must_use]
    pub fn compare(&self, other: &TextValue) -> TextOrdering {
        match self.text.cmp(&other.text) {
            Ordering::Less => TextOrdering::Less,
            Ordering::Equal => TextOrdering::Equal,
            Ordering::Greater => TextOrdering::Greater,
        }
    }

    /// Publishes a forward extended grapheme cluster cursor over the value
    /// (`GNT-41.7-canonical-grapheme-clusters`).
    ///
    /// The clusters are the extended grapheme clusters of the pinned Unicode 16.0.0 data, decided
    /// on the value's own scalar sequence: segmentation never normalizes, case-maps, or modifies
    /// the value, and `remaining` starts at the value's cluster count.
    #[must_use]
    pub fn graphemes(&self) -> TextGraphemes<'_> {
        TextGraphemes {
            text: &self.text,
            boundaries: grapheme_cluster_boundaries(&self.text),
            published: 0,
        }
    }

    /// Returns every scalar boundary of the value: the octet offset of each scalar and the end of
    /// the value, so a value holding no scalar exposes exactly one boundary at zero and no range
    /// with a positive end is a boundary pair.
    fn boundaries(&self) -> Vec<usize> {
        let mut offsets = Vec::with_capacity(self.scalar_count() + 1);
        offsets.extend(self.text.char_indices().map(|(offset, _)| offset));
        offsets.push(self.text.len());
        offsets
    }
}

/// The declared maximum number of scalar values an admitted pattern may hold
/// (`GNT-41.8-bounded-text-matching`).
pub const PATTERN_SCALAR_BOUND: usize = 4096;

/// The declared maximum number of instructions an admitted pattern's program may hold
/// (`GNT-41.8-bounded-text-matching`).
pub const PATTERN_INSTRUCTION_BOUND: usize = 16_384;

/// The declared maximum repetition count a bounded repetition may state
/// (`GNT-41.8-bounded-text-matching`).
pub const PATTERN_REPEAT_BOUND: u32 = 255;

/// The declared maximum step budget a pattern may be admitted with
/// (`GNT-41.8-bounded-text-matching`): every admitted pattern's matching work is bounded by
/// one declared maximum as well as by its own budget.
pub const PATTERN_STEP_BOUND: u32 = 524_288;

/// One published scalar match span of `GNT-41.8-bounded-text-matching`: a half-open range of scalar
/// positions whose start is inclusive and whose end is exclusive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TextRange {
    start: usize,
    end: usize,
}

impl TextRange {
    /// Returns the inclusive scalar position at which the span starts.
    #[must_use]
    pub fn start(self) -> usize {
        self.start
    }

    /// Returns the exclusive scalar position at which the span ends.
    #[must_use]
    pub fn end(self) -> usize {
        self.end
    }

    /// Returns whether the span holds no scalar.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Publishes the spanned scalars as a text value of `GNT-41.1-canonical-text-values`, or
    /// nothing when the span is not a scalar-boundary range of `value`.
    #[must_use]
    pub fn slice(self, value: &TextValue) -> Option<TextValue> {
        value.slice_scalars(self.start, self.end)
    }
}

/// One admitted bounded pattern of `GNT-41.8-bounded-text-matching`.
///
/// A pattern holds a compiled program over a finite state machine and the caller-declared step
/// budget its matches may spend, so matching is decided by the pattern and the text alone and never
/// consults a locale, a host regular-expression engine, or global mutable state.
#[derive(Clone, Debug)]
pub struct Pattern {
    program: Vec<Instruction>,
    steps: u32,
}

#[derive(Clone, Debug)]
enum Instruction {
    Scalar(char),
    AnyScalar,
    Class {
        ranges: Vec<(char, char)>,
        negated: bool,
    },
    Split(usize, usize),
    Jump(usize),
    Match,
}

#[derive(Clone, Debug)]
enum Node {
    Empty,
    Atom(Instruction),
    Concat(Vec<Node>),
    Alternate(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
}

impl Pattern {
    /// Admits one pattern of `GNT-41.8-bounded-text-matching` under a caller-declared step budget.
    ///
    /// A pattern is admitted exactly when it is well formed under the declared pattern syntax and
    /// within every declared pattern bound and the declared budget is not zero; an ill-formed
    /// construct is refused under `text-pattern-syntax` naming the scalar position at which
    /// admission failed, and a pattern beyond a declared bound or a zero budget is refused under
    /// `text-pattern-bound`. Admission compiles the pattern once and never matches it.
    pub fn admit(pattern: &TextValue, steps: u32) -> Result<Self, TextError> {
        if steps == 0 {
            return Err(TextError::new(
                TextDiagnosticCode::PatternBound,
                "the declared step budget is zero",
            ));
        }
        if steps > PATTERN_STEP_BOUND {
            return Err(TextError::new(
                TextDiagnosticCode::PatternBound,
                format!(
                    "the declared step budget {steps} is beyond the declared maximum budget {PATTERN_STEP_BOUND}"
                ),
            ));
        }
        let count = pattern.scalar_count();
        if count > PATTERN_SCALAR_BOUND {
            return Err(TextError::new(
                TextDiagnosticCode::PatternBound,
                format!(
                    "the pattern holds {count} scalars, beyond the declared bound {PATTERN_SCALAR_BOUND}"
                ),
            ));
        }
        let mut parser = PatternParser {
            scalars: pattern.text.chars().collect(),
            index: 0,
        };
        let node = parser.parse_alternation()?;
        if parser.index != parser.scalars.len() {
            return Err(parser.syntax_error(parser.index, "unmatched closing construct"));
        }
        let projected = projected_instructions(&node)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                TextError::new(
                    TextDiagnosticCode::PatternBound,
                    format!(
                        "the compiled program would exceed the declared bound {PATTERN_INSTRUCTION_BOUND}"
                    ),
                )
            })?;
        if projected > PATTERN_INSTRUCTION_BOUND {
            return Err(TextError::new(
                TextDiagnosticCode::PatternBound,
                format!(
                    "the compiled program would hold {projected} instructions, beyond the declared bound {PATTERN_INSTRUCTION_BOUND}"
                ),
            ));
        }
        let mut program = Vec::new();
        compile_node(&node, &mut program);
        program.push(Instruction::Match);
        Ok(Self { program, steps })
    }

    /// Returns the caller-declared step budget of the pattern.
    #[must_use]
    pub fn steps(&self) -> u32 {
        self.steps
    }

    /// Returns whether some scalar span of `text` matches the pattern
    /// (`GNT-41.8-bounded-text-matching`).
    pub fn is_match(&self, text: &TextValue) -> Result<bool, TextError> {
        Ok(self.find_first(text)?.is_some())
    }

    /// Publishes the leftmost-longest match span of `text`, or nothing when no span matches
    /// (`GNT-41.8-bounded-text-matching`).
    ///
    /// The span is the one whose start is the smallest scalar position at which any match begins
    /// and, among the matches at that position, whose end is the largest; a match that spends more
    /// steps than the declared budget is refused under `text-match-budget` rather than published
    /// partially, so every call either publishes one exact span or one refusal.
    pub fn find_first(&self, text: &TextValue) -> Result<Option<TextRange>, TextError> {
        let scalars: Vec<char> = text.text.chars().collect();
        let mut simulator = Simulator::new(self.program.len(), self.steps);
        for start in 0..=scalars.len() {
            if let Some(end) = self.match_from(&scalars, start, &mut simulator)? {
                return Ok(Some(TextRange { start, end }));
            }
        }
        Ok(None)
    }

    fn match_from(
        &self,
        scalars: &[char],
        start: usize,
        simulator: &mut Simulator,
    ) -> Result<Option<usize>, TextError> {
        let mut current = Vec::new();
        simulator.generation()?;
        simulator.closure(&self.program, &mut current, 0)?;
        let mut best = match_position(&self.program, &current, start);
        let mut position = start;
        while position < scalars.len() && !current.is_empty() {
            let mut next = Vec::new();
            simulator.generation()?;
            for state in &current {
                let advances = match &self.program[*state] {
                    Instruction::Scalar(scalar) => *scalar == scalars[position],
                    Instruction::AnyScalar => true,
                    Instruction::Class { ranges, negated } => {
                        let inside = ranges.iter().any(|(low, high)| {
                            scalars[position] >= *low && scalars[position] <= *high
                        });
                        inside != *negated
                    }
                    Instruction::Split(_, _) | Instruction::Jump(_) | Instruction::Match => false,
                };
                if advances {
                    simulator.closure(&self.program, &mut next, *state + 1)?;
                }
            }
            position += 1;
            current = next;
            if let Some(end) = match_position(&self.program, &current, position) {
                best = Some(end);
            }
        }
        Ok(best)
    }
}

fn match_position(program: &[Instruction], states: &[usize], position: usize) -> Option<usize> {
    states
        .iter()
        .any(|state| matches!(program[*state], Instruction::Match))
        .then_some(position)
}

struct Simulator {
    stamps: Vec<u32>,
    generation: u32,
    budget: u32,
}

impl Simulator {
    fn new(states: usize, budget: u32) -> Self {
        Self {
            stamps: vec![0; states],
            generation: 0,
            budget,
        }
    }

    fn generation(&mut self) -> Result<(), TextError> {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.stamps.fill(0);
            self.generation = 1;
        }
        Ok(())
    }

    fn closure(
        &mut self,
        program: &[Instruction],
        list: &mut Vec<usize>,
        start: usize,
    ) -> Result<(), TextError> {
        let mut stack = vec![start];
        while let Some(state) = stack.pop() {
            if self.stamps[state] == self.generation {
                continue;
            }
            self.stamps[state] = self.generation;
            self.budget = self.budget.checked_sub(1).ok_or_else(|| {
                TextError::new(
                    TextDiagnosticCode::MatchBudget,
                    "the match exhausted its declared step budget",
                )
            })?;
            match &program[state] {
                Instruction::Jump(target) => stack.push(*target),
                Instruction::Split(first, second) => {
                    stack.push(*first);
                    stack.push(*second);
                }
                Instruction::Scalar(_) | Instruction::AnyScalar | Instruction::Class { .. } => {
                    list.push(state);
                }
                Instruction::Match => list.push(state),
            }
        }
        Ok(())
    }
}

struct PatternParser {
    scalars: Vec<char>,
    index: usize,
}

impl PatternParser {
    fn syntax_error(&self, index: usize, detail: &str) -> TextError {
        TextError::new(
            TextDiagnosticCode::PatternSyntax,
            format!("scalar position {index} is not admitted: {detail}"),
        )
    }

    fn bound_error(&self, index: usize, detail: &str) -> TextError {
        TextError::new(
            TextDiagnosticCode::PatternBound,
            format!("scalar position {index} exceeds a declared bound: {detail}"),
        )
    }

    fn peek(&self) -> Option<char> {
        self.scalars.get(self.index).copied()
    }

    fn parse_alternation(&mut self) -> Result<Node, TextError> {
        let mut branches = vec![self.parse_concat()?];
        while self.peek() == Some('|') {
            self.index += 1;
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap_or(Node::Empty))
        } else {
            Ok(Node::Alternate(branches))
        }
    }

    fn parse_concat(&mut self) -> Result<Node, TextError> {
        let mut items = Vec::new();
        while let Some(scalar) = self.peek() {
            if scalar == '|' || scalar == ')' {
                break;
            }
            items.push(self.parse_repeat()?);
        }
        if items.is_empty() {
            Ok(Node::Empty)
        } else if items.len() == 1 {
            Ok(items.pop().unwrap_or(Node::Empty))
        } else {
            Ok(Node::Concat(items))
        }
    }

    fn parse_repeat(&mut self) -> Result<Node, TextError> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.index += 1;
                (0, None)
            }
            Some('+') => {
                self.index += 1;
                (1, None)
            }
            Some('?') => {
                self.index += 1;
                (0, Some(1))
            }
            Some('{') => self.parse_bounded_repeat()?,
            _ => return Ok(atom),
        };
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    fn parse_bounded_repeat(&mut self) -> Result<(u32, Option<u32>), TextError> {
        let open = self.index;
        self.index += 1;
        let min = self.parse_repeat_count(open)?;
        let max = if self.peek() == Some(',') {
            self.index += 1;
            if self.peek() == Some('}') {
                None
            } else {
                Some(self.parse_repeat_count(open)?)
            }
        } else {
            Some(min)
        };
        if self.peek() != Some('}') {
            return Err(self.syntax_error(self.index, "a bounded repetition needs a closing brace"));
        }
        self.index += 1;
        if let Some(maximum) = max {
            if maximum < min {
                return Err(self.syntax_error(
                    open,
                    "a bounded repetition needs a maximum no smaller than its minimum",
                ));
            }
            if maximum > PATTERN_REPEAT_BOUND {
                return Err(self.bound_error(
                    open,
                    &format!("a repetition of {maximum} exceeds the declared bound {PATTERN_REPEAT_BOUND}"),
                ));
            }
        }
        if min > PATTERN_REPEAT_BOUND {
            return Err(self.bound_error(
                open,
                &format!("a repetition of {min} exceeds the declared bound {PATTERN_REPEAT_BOUND}"),
            ));
        }
        Ok((min, max))
    }

    fn parse_repeat_count(&mut self, open: usize) -> Result<u32, TextError> {
        let start = self.index;
        let mut value: u32 = 0;
        while let Some(scalar) = self.peek() {
            let Some(digit) = scalar.to_digit(10) else {
                break;
            };
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .unwrap_or(u32::MAX);
            self.index += 1;
        }
        if start == self.index {
            return Err(self.syntax_error(open, "a bounded repetition needs a decimal count"));
        }
        Ok(value)
    }

    fn parse_atom(&mut self) -> Result<Node, TextError> {
        let Some(scalar) = self.peek() else {
            return Err(self.syntax_error(self.index, "the pattern ends where an atom is required"));
        };
        match scalar {
            '(' => {
                self.index += 1;
                let node = self.parse_alternation()?;
                if self.peek() != Some(')') {
                    return Err(
                        self.syntax_error(self.index, "an open group needs a closing parenthesis")
                    );
                }
                self.index += 1;
                Ok(node)
            }
            '[' => self.parse_class(),
            '.' => {
                self.index += 1;
                Ok(Node::Atom(Instruction::AnyScalar))
            }
            '\\' => {
                let start = self.index;
                self.index += 1;
                let Some(escaped) = self.peek() else {
                    return Err(self.syntax_error(start, "an escape needs an escaped scalar"));
                };
                if !matches!(
                    escaped,
                    '.' | '*'
                        | '+'
                        | '?'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '|'
                        | '\\'
                        | '{'
                        | '}'
                        | '^'
                        | '$'
                ) {
                    return Err(
                        self.syntax_error(start, "only a pattern metacharacter may be escaped")
                    );
                }
                self.index += 1;
                Ok(Node::Atom(Instruction::Scalar(escaped)))
            }
            '*' | '+' | '?' | '{' => {
                Err(self.syntax_error(self.index, "a quantifier needs a preceding atom"))
            }
            '^' | '$' => Err(self.syntax_error(
                self.index,
                "an anchor is not admitted by the declared pattern syntax",
            )),
            ')' => Err(self.syntax_error(self.index, "an unmatched closing parenthesis")),
            _ => {
                self.index += 1;
                Ok(Node::Atom(Instruction::Scalar(scalar)))
            }
        }
    }

    fn parse_class(&mut self) -> Result<Node, TextError> {
        let open = self.index;
        self.index += 1;
        let negated = self.peek() == Some('^');
        if negated {
            self.index += 1;
        }
        let mut ranges = Vec::new();
        while let Some(scalar) = self.peek() {
            if scalar == ']' {
                break;
            }
            let low = self.parse_class_scalar(open)?;
            if self.peek() == Some('-') && self.scalars.get(self.index + 1).copied() != Some(']') {
                self.index += 1;
                let high = self.parse_class_scalar(open)?;
                if high < low {
                    return Err(self.syntax_error(open, "a class range needs an ascending order"));
                }
                ranges.push((low, high));
            } else {
                ranges.push((low, low));
            }
        }
        if self.peek() != Some(']') {
            return Err(self.syntax_error(open, "an open class needs a closing bracket"));
        }
        self.index += 1;
        if ranges.is_empty() {
            return Err(self.syntax_error(open, "a class needs at least one scalar"));
        }
        Ok(Node::Atom(Instruction::Class { ranges, negated }))
    }

    fn parse_class_scalar(&mut self, open: usize) -> Result<char, TextError> {
        let Some(scalar) = self.peek() else {
            return Err(self.syntax_error(open, "an open class needs a closing bracket"));
        };
        if scalar == '\\' {
            self.index += 1;
            let Some(escaped) = self.peek() else {
                return Err(self.syntax_error(open, "an escape needs an escaped scalar"));
            };
            if !matches!(escaped, ']' | '-' | '\\' | '^') {
                return Err(self.syntax_error(
                    self.index - 1,
                    "only a class metacharacter may be escaped in a class",
                ));
            }
            self.index += 1;
            return Ok(escaped);
        }
        self.index += 1;
        Ok(scalar)
    }
}

fn compile_node(node: &Node, program: &mut Vec<Instruction>) {
    match node {
        Node::Empty => {}
        Node::Atom(instruction) => program.push(instruction.clone()),
        Node::Concat(items) => {
            for item in items {
                compile_node(item, program);
            }
        }
        Node::Alternate(branches) => {
            let mut jumps = Vec::new();
            for (index, branch) in branches.iter().enumerate() {
                if index + 1 == branches.len() {
                    compile_node(branch, program);
                } else {
                    let split = program.len();
                    program.push(Instruction::Split(0, 0));
                    let body = program.len();
                    compile_node(branch, program);
                    let jump = program.len();
                    program.push(Instruction::Jump(0));
                    jumps.push(jump);
                    program[split] = Instruction::Split(body, jump + 1);
                }
            }
            let after = program.len();
            for jump in jumps {
                program[jump] = Instruction::Jump(after);
            }
        }
        Node::Repeat { node, min, max } => {
            for _ in 0..*min {
                compile_node(node, program);
            }
            match max {
                None => {
                    let split = program.len();
                    program.push(Instruction::Split(0, 0));
                    let body = program.len();
                    compile_node(node, program);
                    program.push(Instruction::Jump(split));
                    let after = program.len();
                    program[split] = Instruction::Split(body, after);
                }
                Some(maximum) => {
                    let mut splits = Vec::new();
                    for _ in *min..*maximum {
                        let split = program.len();
                        program.push(Instruction::Split(0, 0));
                        splits.push(split);
                        compile_node(node, program);
                    }
                    let after = program.len();
                    for split in splits {
                        program[split] = Instruction::Split(split + 1, after);
                    }
                }
            }
        }
    }
}

/// Returns the exact number of instructions compiling `node` emits, or nothing when that count
/// overflows; the count is computed without compiling, so admission can refuse an over-bound
/// pattern before any expansion happens.
fn projected_instructions(node: &Node) -> Option<usize> {
    match node {
        Node::Empty => Some(0),
        Node::Atom(_) => Some(1),
        Node::Concat(items) => {
            let mut total = 0_usize;
            for item in items {
                total = total.checked_add(projected_instructions(item)?)?;
            }
            Some(total)
        }
        Node::Alternate(branches) => {
            let mut total = 0_usize;
            for branch in branches {
                total = total.checked_add(projected_instructions(branch)?)?;
            }
            total.checked_add(2 * branches.len().saturating_sub(1))
        }
        Node::Repeat { node, min, max } => {
            let inner = projected_instructions(node)?;
            let minimum = *min as usize;
            match max {
                None => {
                    let copies = minimum.checked_add(1)?;
                    inner.checked_mul(copies)?.checked_add(2)
                }
                Some(maximum) => inner
                    .checked_mul(*maximum as usize)?
                    .checked_add((*maximum as usize).saturating_sub(minimum)),
            }
        }
    }
}
