//! The pure text foundation of `GNT-41.0-text-foundation-scope`,
//! `GNT-41.1-canonical-text-values`, `GNT-41.2-canonical-text-normalization`,
//! `GNT-41.3-canonical-text-case-mapping`, `GNT-41.4-canonical-text-builders`,
//! `GNT-41.5-canonical-text-traversal`, and `GNT-41.6-canonical-text-comparison`: canonical text
//! values as finite sequences of Unicode scalar values over the Section 35 scalar and octet
//! contracts, their exact admission from octets, their scalar count and canonical UTF-8 octets,
//! their scalar-boundary slicing, their two canonical normalization forms, their two full default
//! case mappings over the pinned Unicode 16.0.0 data, an explicitly bounded builder that publishes
//! one text value, a forward cursor that publishes the scalars of a value one at a time, and the
//! canonical three-way comparison their identity already decides.
//!
//! The model is pure: it consumes no host locale, host encoding, ambient text facility, timing, or
//! global mutable state, and it declares no grapheme-cluster segmentation, no case folding, no
//! formatting, parsing, or interpolation, no regular expression, no locale value or catalog, no
//! compatibility normalization form, and no boundary schema, recovery, or durable behavior.

use std::cmp::Ordering;
use std::fmt;

use gantry_core::unicode::{normalize_nfc, normalize_nfd, to_full_lowercase, to_full_uppercase};

use crate::scalar::CharValue;

/// The declared clauses of Section 41, in specification order
/// (`GNT-41.0` through `GNT-41.6`).
pub const TEXT_CLAUSES: [&str; 7] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
    "GNT-41.3-canonical-text-case-mapping",
    "GNT-41.4-canonical-text-builders",
    "GNT-41.5-canonical-text-traversal",
    "GNT-41.6-canonical-text-comparison",
];

/// One frozen text-foundation diagnostic of `GNT-41.0-text-foundation-scope`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextDiagnosticCode {
    /// `GNT-41.1`: an octet sequence is not well-formed UTF-8.
    InvalidUtf8,
    /// `GNT-41.4`: appending to a builder would exceed its declared octet bound.
    BuilderBound,
}

impl TextDiagnosticCode {
    /// Every declared diagnostic, in declaration order.
    pub const ALL: [Self; 2] = [Self::InvalidUtf8, Self::BuilderBound];

    /// Returns the registered refusal spelling.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "text-invalid-utf8",
            Self::BuilderBound => "text-builder-bound",
        }
    }

    /// Returns the one clause that owns this refusal condition.
    #[must_use]
    pub fn owning_clause(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "GNT-41.1-canonical-text-values",
            Self::BuilderBound => "GNT-41.4-canonical-text-builders",
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
