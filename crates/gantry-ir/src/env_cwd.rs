//! Pure portable logical working-directory value model for `std.env::working_directory`.
//!
//! This module models the data-only logical working-directory values of
//! `GNT-30.3-arguments-environment-and-logical-cwd` within the intended domain of
//! `GNT-49.0-environment-foundation-scope`, together with the bounded launch-snapshot rules of
//! `GNT-30.2-bounded-launch-snapshot-and-capability-closure`.
//!
//! The model is deliberately not a directory handle, capability, adapter, launcher, or host path.
//! It reads no ambient process state, performs no host I/O, and carries no authority: a path value
//! is exact rooted data and nothing more. There is no implicit native or text conversion. A native
//! separator, drive marker, or stream marker is refused rather than translated, a non-UTF-8
//! presentation is refused rather than reinterpreted, and no operation consults the host's current
//! directory, environment, locale, case rules, or filesystem namespace.
//!
//! Target encoding and case behavior is an explicit declared value policy. A value is always exact
//! UTF-8 data and is never folded during admission or equality; a caller that wants an ASCII-only
//! representation or an ASCII case-insensitive comparison selects that policy explicitly through
//! [`LogicalWorkingDirectory::admit_under`] or [`LogicalWorkingDirectory::compare_under`].

use std::fmt;

/// The declared version of the portable logical working-directory value contract.
pub const CWD_VALUE_CONTRACT_VERSION: u64 = 1;

/// The declared default bound, in bytes, on one canonical logical path text.
pub const CWD_DEFAULT_MAX_PATH_BYTES: usize = 4_096;

/// The declared default bound on the number of retained path segments.
pub const CWD_DEFAULT_MAX_SEGMENTS: usize = 256;

/// The declared default bound, in bytes, on one logical root or segment.
pub const CWD_DEFAULT_MAX_SEGMENT_BYTES: usize = 255;

/// The closed refusal set of the portable logical working-directory value contract.
///
/// Each code names exactly one refusal condition, and no code is shared by two conditions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CwdDiagnosticCode {
    /// A relative path component would leave the declared logical root.
    Escape,
    /// A presented byte sequence is not valid UTF-8.
    InvalidEncoding,
    /// A declared logical root is not a portable root name.
    InvalidRoot,
    /// One logical segment is empty, dot-named, or carries a refused scalar.
    InvalidSegment,
    /// A declared path, segment, or segment count exceeds its finite bound.
    LimitExceeded,
    /// A native separator, drive marker, stream marker, or doubled leading separator was presented.
    NativeForm,
    /// A value cannot be represented under the selected target encoding policy.
    UnsupportedEncoding,
}

impl CwdDiagnosticCode {
    /// Every declared code, in canonical order.
    pub const ALL: [Self; 7] = [
        Self::Escape,
        Self::InvalidEncoding,
        Self::InvalidRoot,
        Self::InvalidSegment,
        Self::LimitExceeded,
        Self::NativeForm,
        Self::UnsupportedEncoding,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Escape => "cwd-escape",
            Self::InvalidEncoding => "cwd-invalid-encoding",
            Self::InvalidRoot => "cwd-invalid-root",
            Self::InvalidSegment => "cwd-invalid-segment",
            Self::LimitExceeded => "cwd-limit-exceeded",
            Self::NativeForm => "cwd-native-form",
            Self::UnsupportedEncoding => "cwd-unsupported-encoding",
        }
    }
}

/// One typed refusal of the portable logical working-directory value contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CwdError {
    code: CwdDiagnosticCode,
    detail: String,
}

impl CwdError {
    /// Builds one refusal from its declared code and an explanation.
    fn new(code: CwdDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the one declared code that owns this refusal.
    #[must_use]
    pub const fn code(&self) -> CwdDiagnosticCode {
        self.code
    }

    /// Returns the explanation of the refused condition.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CwdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for CwdError {}

/// The exact finite bounds of one logical working-directory value.
///
/// Every bound is nonzero. The path bound applies to the canonical rooted text, which is the root
/// bytes plus one separator and the bytes of every retained segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CwdLimits {
    max_path_bytes: usize,
    max_segments: usize,
    max_segment_bytes: usize,
}

impl CwdLimits {
    /// Declares one exact bound set, refusing any zero bound.
    ///
    /// # Errors
    ///
    /// Returns [`CwdDiagnosticCode::LimitExceeded`] when any bound is zero, because a zero bound
    /// admits no exact domain.
    pub fn new(
        max_path_bytes: usize,
        max_segments: usize,
        max_segment_bytes: usize,
    ) -> Result<Self, CwdError> {
        if max_path_bytes == 0 || max_segments == 0 || max_segment_bytes == 0 {
            return Err(CwdError::new(
                CwdDiagnosticCode::LimitExceeded,
                "every logical working-directory bound must be nonzero",
            ));
        }
        Ok(Self {
            max_path_bytes,
            max_segments,
            max_segment_bytes,
        })
    }

    /// Returns the declared default bound set.
    #[must_use]
    pub const fn declared() -> Self {
        Self {
            max_path_bytes: CWD_DEFAULT_MAX_PATH_BYTES,
            max_segments: CWD_DEFAULT_MAX_SEGMENTS,
            max_segment_bytes: CWD_DEFAULT_MAX_SEGMENT_BYTES,
        }
    }

    /// Returns the maximum admitted canonical path length in bytes.
    #[must_use]
    pub const fn max_path_bytes(self) -> usize {
        self.max_path_bytes
    }

    /// Returns the maximum admitted retained-segment count.
    #[must_use]
    pub const fn max_segments(self) -> usize {
        self.max_segments
    }

    /// Returns the maximum admitted root or segment length in bytes.
    #[must_use]
    pub const fn max_segment_bytes(self) -> usize {
        self.max_segment_bytes
    }
}

/// The closed declared text-encoding policy of one target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CwdEncodingPolicy {
    /// Only ASCII scalars are representable.
    Ascii,
    /// Every valid UTF-8 scalar is representable.
    Utf8,
}

impl CwdEncodingPolicy {
    /// Every declared encoding policy, in canonical wire-name order.
    pub const ALL: [Self; 2] = [Self::Ascii, Self::Utf8];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.wire_name() == value)
    }
}

/// The closed declared case policy of one target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CwdCasePolicy {
    /// Uppercase ASCII scalars fold to their lowercase ASCII scalar; no other scalar folds.
    AsciiInsensitive,
    /// Scalars compare exactly and never fold.
    Sensitive,
}

impl CwdCasePolicy {
    /// Every declared case policy, in canonical wire-name order.
    pub const ALL: [Self; 2] = [Self::AsciiInsensitive, Self::Sensitive];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AsciiInsensitive => "ascii-insensitive",
            Self::Sensitive => "sensitive",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.wire_name() == value)
    }
}

/// One explicit target encoding and case policy for logical working-directory values.
///
/// A policy is declared data. It is never inferred from a host filesystem, locale, or target
/// inspection, and it never changes an admitted value; it only bounds representability and case
/// comparison when a caller selects it explicitly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CwdTargetPolicy {
    encoding: CwdEncodingPolicy,
    case: CwdCasePolicy,
}

impl CwdTargetPolicy {
    /// The portable policy: exact UTF-8 text with case-sensitive comparison.
    pub const PORTABLE: Self = Self::new(CwdEncodingPolicy::Utf8, CwdCasePolicy::Sensitive);

    /// Declares one target policy from its two closed components.
    #[must_use]
    pub const fn new(encoding: CwdEncodingPolicy, case: CwdCasePolicy) -> Self {
        Self { encoding, case }
    }

    /// Returns the declared text-encoding policy.
    #[must_use]
    pub const fn encoding(self) -> CwdEncodingPolicy {
        self.encoding
    }

    /// Returns the declared case policy.
    #[must_use]
    pub const fn case(self) -> CwdCasePolicy {
        self.case
    }

    /// Returns the exact portable spelling as `encoding/case`.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match (self.encoding, self.case) {
            (CwdEncodingPolicy::Ascii, CwdCasePolicy::AsciiInsensitive) => {
                "ascii/ascii-insensitive"
            }
            (CwdEncodingPolicy::Ascii, CwdCasePolicy::Sensitive) => "ascii/sensitive",
            (CwdEncodingPolicy::Utf8, CwdCasePolicy::AsciiInsensitive) => "utf8/ascii-insensitive",
            (CwdEncodingPolicy::Utf8, CwdCasePolicy::Sensitive) => "utf8/sensitive",
        }
    }
}

/// Every declared target policy, in canonical wire-name order.
pub const CWD_TARGET_POLICIES: [CwdTargetPolicy; 4] = [
    CwdTargetPolicy::new(CwdEncodingPolicy::Ascii, CwdCasePolicy::AsciiInsensitive),
    CwdTargetPolicy::new(CwdEncodingPolicy::Ascii, CwdCasePolicy::Sensitive),
    CwdTargetPolicy::new(CwdEncodingPolicy::Utf8, CwdCasePolicy::AsciiInsensitive),
    CwdTargetPolicy::PORTABLE,
];

/// The exact relation of two logical working-directory values under one target policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CwdComparison {
    /// The rooted values differ in at least one exact segment.
    Different,
    /// The declared logical roots differ.
    DifferentRoot,
    /// Every root and segment matches exactly.
    Equal,
    /// Every root and segment matches only after declared ASCII case folding.
    EqualUnderCaseFolding,
}

impl CwdComparison {
    /// Every declared comparison result, in canonical wire-name order.
    pub const ALL: [Self; 4] = [
        Self::Different,
        Self::DifferentRoot,
        Self::Equal,
        Self::EqualUnderCaseFolding,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Different => "different",
            Self::DifferentRoot => "different-root",
            Self::Equal => "equal",
            Self::EqualUnderCaseFolding => "equal-under-case-folding",
        }
    }
}

/// One admitted logical root identity.
///
/// A root is a portable name: an ASCII lowercase letter followed by ASCII lowercase letters,
/// digits, or `_`. It names a logical root, never a host filesystem root, drive, share, or home
/// directory.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalCwdRoot(String);

impl LogicalCwdRoot {
    /// Admits one logical root identity against the declared segment byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`CwdDiagnosticCode::InvalidRoot`] when the root is empty or is not a portable
    /// root name, and [`CwdDiagnosticCode::LimitExceeded`] beyond the declared byte bound.
    pub fn new(value: &str, limits: &CwdLimits) -> Result<Self, CwdError> {
        if value.is_empty() {
            return Err(CwdError::new(
                CwdDiagnosticCode::InvalidRoot,
                "a logical working-directory root must be nonempty",
            ));
        }
        if value.len() > limits.max_segment_bytes() {
            return Err(CwdError::new(
                CwdDiagnosticCode::LimitExceeded,
                format!(
                    "a logical root declares {} bytes, beyond the {} byte bound",
                    value.len(),
                    limits.max_segment_bytes()
                ),
            ));
        }
        let mut scalars = value.chars();
        let portable = scalars
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
            && scalars.all(|scalar| {
                scalar.is_ascii_lowercase() || scalar.is_ascii_digit() || scalar == '_'
            });
        if !portable {
            return Err(CwdError::new(
                CwdDiagnosticCode::InvalidRoot,
                format!("the logical root `{value}` is not a portable root name"),
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact admitted root spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One admitted logical path segment.
///
/// A segment is nonempty exact UTF-8 data without a separator, drive or stream marker, NUL, or
/// control scalar, and it is never `.` or `..`. Non-ASCII scalars are admitted here and become
/// representable or unrepresentable only when a target encoding policy is selected explicitly.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalCwdSegment(String);

impl LogicalCwdSegment {
    /// Admits one logical segment against the declared segment byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`CwdDiagnosticCode::InvalidSegment`] for an empty, dot-named, or malformed
    /// segment, and [`CwdDiagnosticCode::LimitExceeded`] beyond the declared byte bound.
    pub fn new(value: &str, limits: &CwdLimits) -> Result<Self, CwdError> {
        if value.is_empty() {
            return Err(CwdError::new(
                CwdDiagnosticCode::InvalidSegment,
                "a logical path segment must be nonempty",
            ));
        }
        if value.len() > limits.max_segment_bytes() {
            return Err(CwdError::new(
                CwdDiagnosticCode::LimitExceeded,
                format!(
                    "a logical path segment declares {} bytes, beyond the {} byte bound",
                    value.len(),
                    limits.max_segment_bytes()
                ),
            ));
        }
        if value == "." || value == ".." {
            return Err(CwdError::new(
                CwdDiagnosticCode::InvalidSegment,
                "a logical path segment is never `.` or `..`",
            ));
        }
        if value.chars().any(|scalar| {
            scalar == '/'
                || scalar == '\\'
                || scalar == ':'
                || scalar == '\0'
                || scalar.is_control()
        }) {
            return Err(CwdError::new(
                CwdDiagnosticCode::InvalidSegment,
                "a logical path segment carries a separator, marker, NUL, or control scalar",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact admitted segment spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One immutable rooted portable logical working-directory value.
///
/// A value is an exact logical root plus ordered retained segments. Every admitted value is already
/// normalized: empty and `.` components are dropped during explicit composition, every `..`
/// component removes one retained segment, and a `..` at the root is refused instead of escaping.
/// The text spelling is data only and carries no directory authority. Equality is exact over the
/// root and segments; admission bounds are not part of the value identity.
#[derive(Clone, Debug, Eq)]
pub struct LogicalWorkingDirectory {
    root: LogicalCwdRoot,
    segments: Vec<LogicalCwdSegment>,
    limits: CwdLimits,
}

impl PartialEq for LogicalWorkingDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.segments == other.segments
    }
}

impl LogicalWorkingDirectory {
    /// Admits a root-only logical working directory.
    ///
    /// # Errors
    ///
    /// Returns the root admission refusal of [`LogicalCwdRoot::new`].
    pub fn rooted(root: &str, limits: &CwdLimits) -> Result<Self, CwdError> {
        let root = LogicalCwdRoot::new(root, limits)?;
        assemble(root, Vec::new(), limits)
    }

    /// Admits one logical working directory from a presented portable path text.
    ///
    /// The declared separator is `/`. A leading `/` composes from the declared root; otherwise the
    /// text composes from that root as well, because this constructor starts with no segments.
    /// Empty and `.` components are dropped, every `..` removes one retained segment, and a `..` at
    /// the root is refused. Native separators, drive or stream markers, and a doubled leading
    /// separator are refused rather than translated.
    ///
    /// # Errors
    ///
    /// Returns the root refusal of [`LogicalCwdRoot::new`], the segment refusal of
    /// [`LogicalCwdSegment::new`], [`CwdDiagnosticCode::Escape`] for a `..` at the root,
    /// [`CwdDiagnosticCode::NativeForm`] for a native or doubled-leading form, and
    /// [`CwdDiagnosticCode::LimitExceeded`] beyond the declared bounds.
    pub fn from_text(root: &str, text: &str, limits: &CwdLimits) -> Result<Self, CwdError> {
        let root = LogicalCwdRoot::new(root, limits)?;
        let segments = parse_segments(text, Vec::new(), limits)?;
        assemble(root, segments, limits)
    }

    /// Admits one logical working directory from presented bytes, refusing invalid UTF-8.
    ///
    /// # Errors
    ///
    /// Returns [`CwdDiagnosticCode::InvalidEncoding`] when the bytes are not UTF-8, and otherwise
    /// the refusals of [`LogicalWorkingDirectory::from_text`].
    pub fn from_bytes(root: &str, bytes: &[u8], limits: &CwdLimits) -> Result<Self, CwdError> {
        let text = std::str::from_utf8(bytes).map_err(|_| {
            CwdError::new(
                CwdDiagnosticCode::InvalidEncoding,
                "a presented logical path is not valid UTF-8",
            )
        })?;
        Self::from_text(root, text, limits)
    }

    /// Composes one presented relative or root-relative path text onto this exact value.
    ///
    /// A text beginning with `/` replaces every retained segment and composes from the same
    /// declared root. Any other text composes from the current retained segments. The receiver is
    /// never mutated; composition returns a new value.
    ///
    /// # Errors
    ///
    /// Returns the segment refusal of [`LogicalCwdSegment::new`],
    /// [`CwdDiagnosticCode::Escape`] when a `..` would leave the declared root,
    /// [`CwdDiagnosticCode::NativeForm`] for a native or doubled-leading form, and
    /// [`CwdDiagnosticCode::LimitExceeded`] beyond the declared bounds.
    pub fn compose(&self, text: &str) -> Result<Self, CwdError> {
        if text.starts_with('/') {
            return Self::from_text(self.root.as_str(), text, &self.limits);
        }
        let segments = parse_segments(text, self.segments.clone(), &self.limits)?;
        assemble(self.root.clone(), segments, &self.limits)
    }

    /// Returns the exact declared logical root.
    #[must_use]
    pub const fn root(&self) -> &LogicalCwdRoot {
        &self.root
    }

    /// Returns the exact retained segments in canonical order.
    #[must_use]
    pub fn segments(&self) -> &[LogicalCwdSegment] {
        &self.segments
    }

    /// Returns the admitted segment count.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns whether this value is the declared root with no retained segment.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the exact bounds this value was admitted under.
    #[must_use]
    pub const fn limits(&self) -> CwdLimits {
        self.limits
    }

    /// Returns the canonical data spelling `root/segment/...`.
    ///
    /// The spelling is portable data only. It is not a host path and grants no authority.
    #[must_use]
    pub fn as_text(&self) -> String {
        let mut text = self.root.as_str().to_owned();
        for segment in &self.segments {
            text.push('/');
            text.push_str(segment.as_str());
        }
        text
    }

    /// Returns the canonical root-relative data spelling `/segment/...`.
    ///
    /// The root-only value spells `/`.
    #[must_use]
    pub fn relative_text(&self) -> String {
        if self.segments.is_empty() {
            return "/".to_owned();
        }
        let mut text = String::new();
        for segment in &self.segments {
            text.push('/');
            text.push_str(segment.as_str());
        }
        text
    }

    /// Admits this exact value under one explicit target encoding policy.
    ///
    /// # Errors
    ///
    /// Returns [`CwdDiagnosticCode::UnsupportedEncoding`] when the policy declares the ASCII
    /// encoding and any root or segment scalar is non-ASCII. Case policy never changes a value and
    /// is not consulted here.
    pub fn admit_under(&self, policy: CwdTargetPolicy) -> Result<(), CwdError> {
        if policy.encoding() == CwdEncodingPolicy::Ascii
            && (!self.root.as_str().is_ascii()
                || self
                    .segments
                    .iter()
                    .any(|segment| !segment.as_str().is_ascii()))
        {
            return Err(CwdError::new(
                CwdDiagnosticCode::UnsupportedEncoding,
                "a logical path scalar is not representable under the declared ASCII encoding policy",
            ));
        }
        Ok(())
    }

    /// Compares this exact value with another under one explicit target policy.
    ///
    /// Case folding is the declared ASCII fold only: uppercase ASCII scalars map to their
    /// lowercase ASCII scalar and no other scalar folds. The declared root participates in the
    /// comparison. Neither value is changed by the comparison.
    ///
    /// # Errors
    ///
    /// Returns [`CwdDiagnosticCode::UnsupportedEncoding`] when either value is not representable
    /// under the policy's encoding.
    pub fn compare_under(
        &self,
        other: &Self,
        policy: CwdTargetPolicy,
    ) -> Result<CwdComparison, CwdError> {
        self.admit_under(policy)?;
        other.admit_under(policy)?;
        let case = policy.case();
        if fold_ascii(self.root.as_str(), case) != fold_ascii(other.root.as_str(), case) {
            return Ok(CwdComparison::DifferentRoot);
        }
        if self.segments.len() != other.segments.len() {
            return Ok(CwdComparison::Different);
        }
        let mut folded = false;
        for (left, right) in self.segments.iter().zip(other.segments.iter()) {
            if fold_ascii(left.as_str(), case) != fold_ascii(right.as_str(), case) {
                return Ok(CwdComparison::Different);
            }
            if left.as_str() != right.as_str() {
                folded = true;
            }
        }
        Ok(if folded {
            CwdComparison::EqualUnderCaseFolding
        } else {
            CwdComparison::Equal
        })
    }
}

/// Refuses a presented form that would require implicit native or doubled-leading interpretation.
fn reject_native_text(text: &str) -> Result<(), CwdError> {
    if text.contains('\\') || text.contains(':') {
        return Err(CwdError::new(
            CwdDiagnosticCode::NativeForm,
            "a native separator, drive marker, or stream marker is refused rather than translated",
        ));
    }
    if text.contains('\0') || text.chars().any(char::is_control) {
        return Err(CwdError::new(
            CwdDiagnosticCode::InvalidSegment,
            "a presented logical path carries a NUL or control scalar",
        ));
    }
    if text.starts_with("//") {
        return Err(CwdError::new(
            CwdDiagnosticCode::NativeForm,
            "a doubled leading separator is not a portable logical path",
        ));
    }
    Ok(())
}

/// Parses one presented portable text onto an initial retained-segment sequence.
///
/// The presented text byte bound is checked before it is split, so an oversized presentation is
/// refused before any component work. Empty and `.` components are dropped, each `..` removes one
/// retained segment, and a `..` with no retained segment is refused.
fn parse_segments(
    text: &str,
    mut segments: Vec<LogicalCwdSegment>,
    limits: &CwdLimits,
) -> Result<Vec<LogicalCwdSegment>, CwdError> {
    if text.len() > limits.max_path_bytes() {
        return Err(CwdError::new(
            CwdDiagnosticCode::LimitExceeded,
            format!(
                "a presented logical path declares {} bytes, beyond the {} byte bound",
                text.len(),
                limits.max_path_bytes()
            ),
        ));
    }
    reject_native_text(text)?;
    if text.starts_with('/') {
        segments.clear();
    }
    for component in text.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(CwdError::new(
                        CwdDiagnosticCode::Escape,
                        "a relative component would leave the declared logical root",
                    ));
                }
            }
            _ => segments.push(LogicalCwdSegment::new(component, limits)?),
        }
    }
    if segments.len() > limits.max_segments() {
        return Err(CwdError::new(
            CwdDiagnosticCode::LimitExceeded,
            format!(
                "{} segments are retained, beyond the {} segment bound",
                segments.len(),
                limits.max_segments()
            ),
        ));
    }
    Ok(segments)
}

/// Assembles one admitted value, checking the canonical path and segment-count bounds.
fn assemble(
    root: LogicalCwdRoot,
    segments: Vec<LogicalCwdSegment>,
    limits: &CwdLimits,
) -> Result<LogicalWorkingDirectory, CwdError> {
    if segments.len() > limits.max_segments() {
        return Err(CwdError::new(
            CwdDiagnosticCode::LimitExceeded,
            format!(
                "{} segments are retained, beyond the {} segment bound",
                segments.len(),
                limits.max_segments()
            ),
        ));
    }
    let mut total = root.as_str().len();
    for segment in &segments {
        total = total
            .checked_add(1)
            .and_then(|value| value.checked_add(segment.as_str().len()))
            .ok_or_else(|| {
                CwdError::new(
                    CwdDiagnosticCode::LimitExceeded,
                    "the canonical logical path exceeds the addressable total",
                )
            })?;
    }
    if total > limits.max_path_bytes() {
        return Err(CwdError::new(
            CwdDiagnosticCode::LimitExceeded,
            format!(
                "the canonical logical path declares {total} bytes, beyond the {} byte bound",
                limits.max_path_bytes()
            ),
        ));
    }
    Ok(LogicalWorkingDirectory {
        root,
        segments,
        limits: *limits,
    })
}

/// Folds uppercase ASCII scalars under the declared case policy, leaving every other scalar exact.
fn fold_ascii(text: &str, case: CwdCasePolicy) -> String {
    match case {
        CwdCasePolicy::Sensitive => text.to_owned(),
        CwdCasePolicy::AsciiInsensitive => text
            .chars()
            .map(|scalar| {
                if scalar.is_ascii_uppercase() {
                    scalar.to_ascii_lowercase()
                } else {
                    scalar
                }
            })
            .collect(),
    }
}
