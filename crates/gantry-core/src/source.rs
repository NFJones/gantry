//! Portable immutable source records, byte spans, diagnostics, and counters.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::portable::{DiagnosticCategory, DiagnosticSeverity, FrontendResourceCode};
use crate::unicode;

const MAXIMUM_FRONTEND_LIMIT: u64 = i64::MAX as u64;

/// One normalized package-relative source path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackagePath(Arc<str>);

impl PackagePath {
    /// Validates one slash-separated path relative to the package root.
    pub fn new(value: &str) -> Result<Self, PackagePathError> {
        if value.is_empty() {
            return Err(PackagePathError::Empty);
        }
        if value.starts_with('/') || value.contains('\\') || value.contains(':') {
            return Err(PackagePathError::NotRelative);
        }
        if value.contains('\0') {
            return Err(PackagePathError::InvalidCharacter);
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(PackagePathError::InvalidComponent);
        }
        if !unicode::is_nfc(value) {
            return Err(PackagePathError::NotNfc);
        }
        if !value.ends_with(".gnt") {
            return Err(PackagePathError::NotSourceFile);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact slash-separated package path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackagePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection of a package-relative source path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackagePathError {
    /// The path has no components.
    Empty,
    /// The path is absolute, drive-relative, or uses host separators.
    NotRelative,
    /// A component is empty, `.` or `..`.
    InvalidComponent,
    /// The path contains a forbidden scalar such as NUL.
    InvalidCharacter,
    /// The path is not already in Unicode 16 NFC.
    NotNfc,
    /// The final component is not a Gantry source filename.
    NotSourceFile,
}

impl fmt::Display for PackagePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "package path is empty",
            Self::NotRelative => "package path is not slash-separated and relative",
            Self::InvalidComponent => "package path contains an empty, dot, or parent component",
            Self::InvalidCharacter => "package path contains a forbidden character",
            Self::NotNfc => "package path is not Unicode 16 NFC",
            Self::NotSourceFile => "package path does not end in .gnt",
        })
    }
}

impl std::error::Error for PackagePathError {}

/// Snapshot-local source identity represented by its exact package path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceId(PackagePath);

impl SourceId {
    /// Reconstructs one snapshot-local identity from its portable package path.
    ///
    /// This is used by versioned source maps and durable event records whose
    /// source bytes were validated before the record became authoritative.
    pub fn from_package_path(value: &str) -> Result<Self, PackagePathError> {
        PackagePath::new(value).map(Self)
    }

    /// Returns the exact package-relative identity.
    #[must_use]
    pub fn package_path(&self) -> &PackagePath {
        &self.0
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Zero-based, end-exclusive byte offsets.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteSpan {
    start: u64,
    end: u64,
}

impl ByteSpan {
    /// Constructs an ordered byte span.
    pub const fn new(start: u64, end: u64) -> Result<Self, SpanError> {
        if start > end {
            return Err(SpanError::Reversed);
        }
        Ok(Self { start, end })
    }

    /// Returns the inclusive start byte offset.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the exclusive end byte offset.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }
}

/// One package-relative source span.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceSpan {
    source: SourceId,
    bytes: ByteSpan,
}

impl SourceSpan {
    /// Constructs a span proven to lie inside one immutable source record.
    pub fn new(record: &SourceRecord, bytes: ByteSpan) -> Result<Self, SpanError> {
        if bytes.end > record.byte_len() {
            return Err(SpanError::OutOfBounds);
        }
        Ok(Self {
            source: record.id.clone(),
            bytes,
        })
    }

    /// Reconstructs a previously validated portable source span.
    ///
    /// The caller must obtain the path and offsets from an authenticated
    /// source map or another versioned record that validated the bounds before
    /// publication. This constructor still validates path shape and byte order.
    pub fn from_portable_parts(
        path: &str,
        start: u64,
        end: u64,
    ) -> Result<Self, PortableSpanError> {
        let source = SourceId::from_package_path(path).map_err(PortableSpanError::Path)?;
        let bytes = ByteSpan::new(start, end).map_err(PortableSpanError::Span)?;
        Ok(Self { source, bytes })
    }

    /// Returns the source identity.
    #[must_use]
    pub fn source(&self) -> &SourceId {
        &self.source
    }

    /// Returns the byte offsets.
    #[must_use]
    pub const fn bytes(&self) -> ByteSpan {
        self.bytes
    }
}

/// Rejection of a byte span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanError {
    /// The start offset follows the end offset.
    Reversed,
    /// The end offset exceeds the immutable source bytes.
    OutOfBounds,
    /// A text slice splits a UTF-8 scalar.
    NotCharacterBoundary,
}

impl fmt::Display for SpanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reversed => "source span is reversed",
            Self::OutOfBounds => "source span exceeds the immutable source",
            Self::NotCharacterBoundary => "source span splits a UTF-8 scalar",
        })
    }
}

impl std::error::Error for SpanError {}

/// Failure to reconstruct a source span from portable path and offset fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableSpanError {
    /// The package-relative source path is invalid.
    Path(PackagePathError),
    /// The byte offsets are reversed.
    Span(SpanError),
}

impl fmt::Display for PortableSpanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => error.fmt(formatter),
            Self::Span(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PortableSpanError {}

/// Immutable bytes and identity for one selected source file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRecord {
    id: SourceId,
    bytes: Arc<[u8]>,
    sha256: [u8; 32],
}

impl SourceRecord {
    fn new(path: PackagePath, bytes: &[u8]) -> Self {
        let sha256 = Sha256::digest(bytes).into();
        Self {
            id: SourceId(path),
            bytes: Arc::from(bytes),
            sha256,
        }
    }

    /// Returns the snapshot-local source identity.
    #[must_use]
    pub fn id(&self) -> &SourceId {
        &self.id
    }

    /// Returns the exact immutable source bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact byte length.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Returns SHA-256 over the exact immutable bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Decodes the admitted bytes as UTF-8 without replacing invalid input.
    pub fn text(&self) -> Result<&str, Utf8SourceError> {
        std::str::from_utf8(&self.bytes).map_err(|error| Utf8SourceError {
            source: self.id.clone(),
            valid_up_to: error.valid_up_to() as u64,
            error_len: error.error_len().map(|length| length as u64),
        })
    }

    /// Returns a UTF-8 text slice when both offsets are scalar boundaries.
    pub fn text_slice(&self, span: ByteSpan) -> Result<&str, TextSliceError> {
        if span.end > self.byte_len() {
            return Err(TextSliceError::Span(SpanError::OutOfBounds));
        }
        let text = self.text().map_err(TextSliceError::Utf8)?;
        let start = usize::try_from(span.start)
            .map_err(|_| TextSliceError::Span(SpanError::OutOfBounds))?;
        let end =
            usize::try_from(span.end).map_err(|_| TextSliceError::Span(SpanError::OutOfBounds))?;
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            return Err(TextSliceError::Span(SpanError::NotCharacterBoundary));
        }
        text.get(start..end)
            .ok_or(TextSliceError::Span(SpanError::OutOfBounds))
    }
}

/// Exact invalid-UTF-8 location in one source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Utf8SourceError {
    /// Source containing the invalid byte sequence.
    pub source: SourceId,
    /// Bytes valid before the first decoding error.
    pub valid_up_to: u64,
    /// Invalid sequence length, or `None` for incomplete trailing input.
    pub error_len: Option<u64>,
}

/// Failure to obtain a text slice from immutable source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TextSliceError {
    /// The complete source is not UTF-8.
    Utf8(Utf8SourceError),
    /// The requested byte span is invalid for text slicing.
    Span(SpanError),
}

impl fmt::Display for TextSliceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(_) => formatter.write_str("source is not valid UTF-8"),
            Self::Span(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TextSliceError {}

/// Positive source-ingress and diagnostic limits for one package activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLimits {
    maximum_package_files: u64,
    maximum_source_file_bytes: u64,
    maximum_package_source_bytes: u64,
    maximum_source_tokens: u64,
    maximum_diagnostics_per_activity: u64,
}

impl SourceLimits {
    /// Constructs the finite positive source-substrate limits.
    pub fn new(
        maximum_package_files: u64,
        maximum_source_file_bytes: u64,
        maximum_package_source_bytes: u64,
        maximum_source_tokens: u64,
        maximum_diagnostics_per_activity: u64,
    ) -> Result<Self, SourceLimitConfigurationError> {
        let values = [
            maximum_package_files,
            maximum_source_file_bytes,
            maximum_package_source_bytes,
            maximum_source_tokens,
            maximum_diagnostics_per_activity,
        ];
        if values.contains(&0) {
            return Err(SourceLimitConfigurationError::Zero);
        }
        if values.iter().any(|value| *value > MAXIMUM_FRONTEND_LIMIT) {
            return Err(SourceLimitConfigurationError::TooLarge);
        }
        Ok(Self {
            maximum_package_files,
            maximum_source_file_bytes,
            maximum_package_source_bytes,
            maximum_source_tokens,
            maximum_diagnostics_per_activity,
        })
    }

    /// Returns the maximum exact bytes admitted for one selected source file.
    #[must_use]
    pub const fn maximum_source_file_bytes(self) -> u64 {
        self.maximum_source_file_bytes
    }

    /// Returns the maximum selected source files admitted for one activity.
    #[must_use]
    pub const fn maximum_package_files(self) -> u64 {
        self.maximum_package_files
    }

    /// Returns the maximum cumulative source bytes admitted for one activity.
    #[must_use]
    pub const fn maximum_package_source_bytes(self) -> u64 {
        self.maximum_package_source_bytes
    }

    /// Returns the maximum nontrivia tokens admitted for one activity.
    #[must_use]
    pub const fn maximum_source_tokens(self) -> u64 {
        self.maximum_source_tokens
    }

    /// Returns the maximum retained diagnostics admitted for one activity.
    #[must_use]
    pub const fn maximum_diagnostics_per_activity(self) -> u64 {
        self.maximum_diagnostics_per_activity
    }
}

/// Complete finite frontend policy accepted by package operations.
///
/// Syntax-only validation enforces the embedded source and constructed-type
/// limits. Semantic analysis additionally consumes the generic-instantiation
/// and trait-resolution budgets and enforces the artifact limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontendLimits {
    source: SourceLimits,
    maximum_package_source_manifest_bytes: u64,
    maximum_canonical_ir_bytes: u64,
    maximum_source_map_bytes: u64,
    maximum_generated_schema_bytes: u64,
    maximum_constructed_type_depth: u64,
    maximum_generic_instantiations_per_activity: u64,
    maximum_trait_resolution_steps_per_activity: u64,
}

impl FrontendLimits {
    /// Constructs the complete positive frontend policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maximum_package_files: u64,
        maximum_source_file_bytes: u64,
        maximum_package_source_bytes: u64,
        maximum_source_tokens: u64,
        maximum_diagnostics_per_activity: u64,
        maximum_package_source_manifest_bytes: u64,
        maximum_canonical_ir_bytes: u64,
        maximum_source_map_bytes: u64,
        maximum_generated_schema_bytes: u64,
        maximum_constructed_type_depth: u64,
        maximum_generic_instantiations_per_activity: u64,
        maximum_trait_resolution_steps_per_activity: u64,
    ) -> Result<Self, SourceLimitConfigurationError> {
        let source = SourceLimits::new(
            maximum_package_files,
            maximum_source_file_bytes,
            maximum_package_source_bytes,
            maximum_source_tokens,
            maximum_diagnostics_per_activity,
        )?;
        let artifact_limits = [
            maximum_package_source_manifest_bytes,
            maximum_canonical_ir_bytes,
            maximum_source_map_bytes,
            maximum_generated_schema_bytes,
            maximum_constructed_type_depth,
            maximum_generic_instantiations_per_activity,
            maximum_trait_resolution_steps_per_activity,
        ];
        if artifact_limits.contains(&0) {
            return Err(SourceLimitConfigurationError::Zero);
        }
        if artifact_limits
            .iter()
            .any(|value| *value > MAXIMUM_FRONTEND_LIMIT)
        {
            return Err(SourceLimitConfigurationError::TooLarge);
        }
        Ok(Self {
            source,
            maximum_package_source_manifest_bytes,
            maximum_canonical_ir_bytes,
            maximum_source_map_bytes,
            maximum_generated_schema_bytes,
            maximum_constructed_type_depth,
            maximum_generic_instantiations_per_activity,
            maximum_trait_resolution_steps_per_activity,
        })
    }

    /// Returns the source, token, and diagnostic limits used by validation.
    #[must_use]
    pub const fn source_limits(self) -> SourceLimits {
        self.source
    }

    /// Returns the maximum selected source files admitted for one activity.
    #[must_use]
    pub const fn maximum_package_files(self) -> u64 {
        self.source.maximum_package_files()
    }

    /// Returns the maximum exact bytes admitted for one selected source file.
    #[must_use]
    pub const fn maximum_source_file_bytes(self) -> u64 {
        self.source.maximum_source_file_bytes()
    }

    /// Returns the maximum cumulative source bytes admitted for one activity.
    #[must_use]
    pub const fn maximum_package_source_bytes(self) -> u64 {
        self.source.maximum_package_source_bytes()
    }

    /// Returns the maximum nontrivia source tokens admitted for one activity.
    #[must_use]
    pub const fn maximum_source_tokens(self) -> u64 {
        self.source.maximum_source_tokens()
    }

    /// Returns the maximum retained diagnostics admitted for one activity.
    #[must_use]
    pub const fn maximum_diagnostics_per_activity(self) -> u64 {
        self.source.maximum_diagnostics_per_activity()
    }

    /// Returns the package-source-manifest byte limit for later phases.
    #[must_use]
    pub const fn maximum_package_source_manifest_bytes(self) -> u64 {
        self.maximum_package_source_manifest_bytes
    }

    /// Returns the canonical-IR byte limit for later phases.
    #[must_use]
    pub const fn maximum_canonical_ir_bytes(self) -> u64 {
        self.maximum_canonical_ir_bytes
    }

    /// Returns the source-map byte limit for later phases.
    #[must_use]
    pub const fn maximum_source_map_bytes(self) -> u64 {
        self.maximum_source_map_bytes
    }

    /// Returns the generated-schema object byte limit for later phases.
    #[must_use]
    pub const fn maximum_generated_schema_bytes(self) -> u64 {
        self.maximum_generated_schema_bytes
    }

    /// Returns the maximum retained constructed-type depth for one activity.
    #[must_use]
    pub const fn maximum_constructed_type_depth(self) -> u64 {
        self.maximum_constructed_type_depth
    }

    /// Returns the maximum new canonical generic instantiations for one activity.
    #[must_use]
    pub const fn maximum_generic_instantiations_per_activity(self) -> u64 {
        self.maximum_generic_instantiations_per_activity
    }

    /// Returns the maximum trait-resolution work units for one activity.
    #[must_use]
    pub const fn maximum_trait_resolution_steps_per_activity(self) -> u64 {
        self.maximum_trait_resolution_steps_per_activity
    }
}

/// Invalid source-limit configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceLimitConfigurationError {
    /// A required frontend limit is zero.
    Zero,
    /// A limit exceeds `2^63 - 1`.
    TooLarge,
}

/// One exact frontend resource-limit outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontendResourceLimit {
    /// Exact portable limit code.
    pub code: FrontendResourceCode,
    /// Configured positive limit.
    pub limit: u64,
    /// Observed count, or `None` when checked arithmetic overflowed.
    pub observed: Option<u64>,
}

impl fmt::Display for FrontendResourceLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.wire_name())
    }
}

impl std::error::Error for FrontendResourceLimit {}

/// Checked source-ingress counters for one package activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCounters {
    limits: SourceLimits,
    package_files: u64,
    package_source_bytes: u64,
    source_tokens: u64,
    diagnostics: u64,
}

impl SourceCounters {
    /// Starts zeroed counters under the supplied limits.
    #[must_use]
    pub const fn new(limits: SourceLimits) -> Self {
        Self {
            limits,
            package_files: 0,
            package_source_bytes: 0,
            source_tokens: 0,
            diagnostics: 0,
        }
    }

    /// Atomically admits one selected file before its bytes are copied or decoded.
    pub fn admit_file(&mut self, byte_len: u64) -> Result<(), FrontendResourceLimit> {
        check_limit(
            FrontendResourceCode::SourceFileByteLimit,
            self.limits.maximum_source_file_bytes,
            Some(byte_len),
        )?;
        let next_files = checked_count(
            FrontendResourceCode::PackageFileCountLimit,
            self.package_files,
            1,
            self.limits.maximum_package_files,
        )?;
        let next_bytes = checked_count(
            FrontendResourceCode::PackageSourceByteLimit,
            self.package_source_bytes,
            byte_len,
            self.limits.maximum_package_source_bytes,
        )?;
        self.package_files = next_files;
        self.package_source_bytes = next_bytes;
        Ok(())
    }

    /// Charges nontrivia source tokens while scanning.
    pub fn charge_tokens(&mut self, amount: u64) -> Result<(), FrontendResourceLimit> {
        self.source_tokens = checked_count(
            FrontendResourceCode::SourceTokenLimit,
            self.source_tokens,
            amount,
            self.limits.maximum_source_tokens,
        )?;
        Ok(())
    }

    /// Charges one retained error or warning diagnostic.
    pub fn charge_diagnostic(&mut self) -> Result<(), FrontendResourceLimit> {
        self.diagnostics = checked_count(
            FrontendResourceCode::DiagnosticCountLimit,
            self.diagnostics,
            1,
            self.limits.maximum_diagnostics_per_activity,
        )?;
        Ok(())
    }

    /// Returns `(files, bytes, tokens, diagnostics)`.
    #[must_use]
    pub const fn counts(&self) -> (u64, u64, u64, u64) {
        (
            self.package_files,
            self.package_source_bytes,
            self.source_tokens,
            self.diagnostics,
        )
    }
}

/// Checked generic-analysis counters for one admitted package activity.
///
/// Construct a fresh value at each public package-activity boundary. Charges
/// are committed only after their checked next value is within the configured
/// limit, so rejected work cannot alter the retained prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericAnalysisCounters {
    limits: FrontendLimits,
    generic_instantiations: u64,
    trait_resolution_steps: u64,
}

impl GenericAnalysisCounters {
    /// Starts zeroed generic-analysis counters under the supplied activity policy.
    #[must_use]
    pub const fn new(limits: FrontendLimits) -> Self {
        Self {
            limits,
            generic_instantiations: 0,
            trait_resolution_steps: 0,
        }
    }

    /// Checks one constructed type before it is retained.
    pub fn check_constructed_type_depth(&self, depth: u64) -> Result<(), FrontendResourceLimit> {
        check_limit(
            FrontendResourceCode::ConstructedTypeDepthLimit,
            self.limits.maximum_constructed_type_depth,
            Some(depth),
        )
    }

    /// Charges one new canonical generic-instantiation key before retaining it.
    pub fn charge_generic_instantiation(&mut self) -> Result<(), FrontendResourceLimit> {
        let next = checked_count(
            FrontendResourceCode::GenericInstantiationLimit,
            self.generic_instantiations,
            1,
            self.limits.maximum_generic_instantiations_per_activity,
        )?;
        self.generic_instantiations = next;
        Ok(())
    }

    /// Charges canonical trait-resolution work before retaining its result.
    pub fn charge_trait_resolution_steps(
        &mut self,
        amount: u64,
    ) -> Result<(), FrontendResourceLimit> {
        let next = checked_count(
            FrontendResourceCode::TraitResolutionStepLimit,
            self.trait_resolution_steps,
            amount,
            self.limits.maximum_trait_resolution_steps_per_activity,
        )?;
        self.trait_resolution_steps = next;
        Ok(())
    }

    /// Returns `(generic instantiations, trait-resolution steps)`.
    #[must_use]
    pub const fn counts(&self) -> (u64, u64) {
        (self.generic_instantiations, self.trait_resolution_steps)
    }
}

fn checked_count(
    code: FrontendResourceCode,
    current: u64,
    amount: u64,
    limit: u64,
) -> Result<u64, FrontendResourceLimit> {
    let observed = current.checked_add(amount);
    check_limit(code, limit, observed)?;
    observed.ok_or(FrontendResourceLimit {
        code,
        limit,
        observed: None,
    })
}

fn check_limit(
    code: FrontendResourceCode,
    limit: u64,
    observed: Option<u64>,
) -> Result<(), FrontendResourceLimit> {
    match observed {
        Some(value) if value <= limit => Ok(()),
        _ => Err(FrontendResourceLimit {
            code,
            limit,
            observed,
        }),
    }
}

/// Incremental immutable-snapshot builder with pre-copy limit enforcement.
#[derive(Debug)]
pub struct SourceSnapshotBuilder {
    counters: SourceCounters,
    records: BTreeMap<PackagePath, SourceRecord>,
}

impl SourceSnapshotBuilder {
    /// Starts one package activity's snapshot.
    #[must_use]
    pub fn new(limits: SourceLimits) -> Self {
        Self {
            counters: SourceCounters::new(limits),
            records: BTreeMap::new(),
        }
    }

    /// Validates and copies one complete source observation exactly once.
    pub fn add_file(&mut self, path: &str, bytes: &[u8]) -> Result<SourceId, SourceError> {
        let path = PackagePath::new(path).map_err(SourceError::Path)?;
        if self.records.contains_key(&path) {
            return Err(SourceError::DuplicatePath(path));
        }
        let byte_len = u64::try_from(bytes.len()).map_err(|_| {
            SourceError::ResourceLimit(FrontendResourceLimit {
                code: FrontendResourceCode::SourceFileByteLimit,
                limit: self.counters.limits.maximum_source_file_bytes,
                observed: None,
            })
        })?;
        self.counters
            .admit_file(byte_len)
            .map_err(SourceError::ResourceLimit)?;
        let record = SourceRecord::new(path.clone(), bytes);
        let id = record.id.clone();
        self.records.insert(path, record);
        Ok(id)
    }

    /// Returns mutable checked counters for lexer and diagnostic charging.
    pub fn counters_mut(&mut self) -> &mut SourceCounters {
        &mut self.counters
    }

    /// Borrows one already admitted immutable record together with the shared
    /// activity counters used by later frontend phases.
    pub fn record_and_counters_mut(
        &mut self,
        id: &SourceId,
    ) -> (Option<&SourceRecord>, &mut SourceCounters) {
        (self.records.get(&id.0), &mut self.counters)
    }

    /// Returns the current checked counters without permitting mutation.
    #[must_use]
    pub const fn counters(&self) -> &SourceCounters {
        &self.counters
    }

    /// Freezes records in unsigned UTF-8 package-path order.
    #[must_use]
    pub fn finish(self) -> SourceSnapshot {
        SourceSnapshot {
            records: self.records.into_values().collect(),
            counters: self.counters,
        }
    }
}

/// One immutable, canonically ordered source snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSnapshot {
    records: Vec<SourceRecord>,
    counters: SourceCounters,
}

impl SourceSnapshot {
    /// Returns records in unsigned UTF-8 package-path order.
    #[must_use]
    pub fn records(&self) -> &[SourceRecord] {
        &self.records
    }

    /// Splits immutable records from the mutable activity counters used by
    /// later frontend phases.
    ///
    /// Lexing and analysis consume the already-frozen source records while
    /// charging their shared package-activity limits incrementally.
    pub fn records_and_counters_mut(&mut self) -> (&[SourceRecord], &mut SourceCounters) {
        (&self.records, &mut self.counters)
    }

    /// Finds a record by its source identity.
    #[must_use]
    pub fn get(&self, id: &SourceId) -> Option<&SourceRecord> {
        self.records
            .binary_search_by(|record| record.id.cmp(id))
            .ok()
            .and_then(|index| self.records.get(index))
    }

    /// Returns the final checked activity counters.
    #[must_use]
    pub const fn counters(&self) -> &SourceCounters {
        &self.counters
    }
}

/// Failure while constructing one immutable source snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// Invalid package-relative path.
    Path(PackagePathError),
    /// One package path was selected more than once.
    DuplicatePath(PackagePath),
    /// A configured source counter was exceeded.
    ResourceLimit(FrontendResourceLimit),
}

/// Canonical package diagnostic phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticPhase {
    /// Package discovery and immutable snapshot construction.
    Package,
    /// Lexical scanning.
    Lexical,
    /// Surface syntax parsing.
    Syntax,
    /// Static semantic analysis.
    Analysis,
}

impl DiagnosticPhase {
    /// Returns the stable phase spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Lexical => "lexical",
            Self::Syntax => "syntax",
            Self::Analysis => "analysis",
        }
    }
}

/// Stable implementation diagnostic code within one protocol major version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticCode(Arc<str>);

impl DiagnosticCode {
    /// Validates one lowercase kebab-case diagnostic code.
    pub fn new(value: &str) -> Result<Self, DiagnosticCodeError> {
        if value.is_empty()
            || value.starts_with('-')
            || value.ends_with('-')
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-')
            || value.as_bytes().windows(2).any(|pair| pair == b"--")
        {
            return Err(DiagnosticCodeError);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the stable code spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invalid implementation diagnostic code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticCodeError;

/// One labeled related source span.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelatedSpan {
    /// Stable relationship label.
    pub label: Arc<str>,
    /// Related source location.
    pub span: SourceSpan,
}

/// Stable machine-facing classification for one diagnostic.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticMetadata {
    /// Canonical production phase.
    pub phase: DiagnosticPhase,
    /// Exact portable severity.
    pub severity: DiagnosticSeverity,
    /// Exact portable category.
    pub category: DiagnosticCategory,
    /// Stable implementation or specification-assigned code.
    pub code: DiagnosticCode,
}

/// Disclosure-neutral machine diagnostic.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StructuredDiagnostic {
    /// Canonical production phase.
    pub phase: DiagnosticPhase,
    /// Exact portable severity.
    pub severity: DiagnosticSeverity,
    /// Exact portable category.
    pub category: DiagnosticCategory,
    /// Stable implementation or specification-assigned code.
    pub code: DiagnosticCode,
    /// Human-readable message not used for machine decisions.
    pub message: Arc<str>,
    /// Primary source location when source-backed.
    pub primary: Option<SourceSpan>,
    /// Canonically ordered labeled related locations.
    pub related: Vec<RelatedSpan>,
    /// Structured repair fields in unsigned UTF-8 key order.
    pub fields: BTreeMap<Arc<str>, Arc<str>>,
}

impl StructuredDiagnostic {
    /// Constructs a diagnostic and canonicalizes related-span ordering.
    pub fn new(
        metadata: DiagnosticMetadata,
        message: impl Into<Arc<str>>,
        primary: Option<SourceSpan>,
        mut related: Vec<RelatedSpan>,
        fields: BTreeMap<Arc<str>, Arc<str>>,
    ) -> Result<Self, DiagnosticError> {
        let message = message.into();
        if message.trim().is_empty() {
            return Err(DiagnosticError::EmptyMessage);
        }
        related.sort();
        if related.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DiagnosticError::DuplicateRelatedSpan);
        }
        Ok(Self {
            phase: metadata.phase,
            severity: metadata.severity,
            category: metadata.category,
            code: metadata.code,
            message,
            primary,
            related,
            fields,
        })
    }
}

/// Invalid structured diagnostic construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticError {
    /// Human-readable text is required but is not machine-parsed.
    EmptyMessage,
    /// One related label/span pair appears more than once.
    DuplicateRelatedSpan,
}

/// Bounded collector for diagnostics already produced in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticBuffer {
    limit: u64,
    diagnostics: Vec<StructuredDiagnostic>,
}

impl DiagnosticBuffer {
    /// Creates a collector under a finite positive diagnostic cap.
    pub fn new(limit: u64) -> Result<Self, SourceLimitConfigurationError> {
        SourceLimits::new(1, 1, 1, 1, limit)?;
        Ok(Self {
            limit,
            diagnostics: Vec::new(),
        })
    }

    /// Retains one diagnostic when it is the next canonical item and fits.
    pub fn push(&mut self, diagnostic: StructuredDiagnostic) -> Result<(), DiagnosticBufferError> {
        if self
            .diagnostics
            .last()
            .is_some_and(|last| last > &diagnostic)
        {
            return Err(DiagnosticBufferError::OutOfOrder);
        }
        let observed = (self.diagnostics.len() as u64).checked_add(1);
        check_limit(
            FrontendResourceCode::DiagnosticCountLimit,
            self.limit,
            observed,
        )
        .map_err(DiagnosticBufferError::ResourceLimit)?;
        self.diagnostics.push(diagnostic);
        Ok(())
    }

    /// Returns the retained canonical prefix.
    #[must_use]
    pub fn diagnostics(&self) -> &[StructuredDiagnostic] {
        &self.diagnostics
    }
}

/// Diagnostic buffer rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticBufferError {
    /// The next diagnostic does not follow canonical order.
    OutOfOrder,
    /// The exact retained prefix has reached its configured cap.
    ResourceLimit(FrontendResourceLimit),
}

/// One published implementation diagnostic code definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticCodeDefinition {
    /// Stable code.
    pub code: &'static str,
    /// Canonical phase.
    pub phase: DiagnosticPhase,
    /// Portable category.
    pub category: DiagnosticCategory,
    /// Meaning retained for this protocol major.
    pub meaning: &'static str,
}

/// Initial Gantry source-substrate diagnostic code registry.
pub const DIAGNOSTIC_CODE_REGISTRY: &[DiagnosticCodeDefinition] = &[
    DiagnosticCodeDefinition {
        code: "aggregate-member-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An aggregate member differs from its exact expected type.",
    },
    DiagnosticCodeDefinition {
        code: "ambiguous-constructor-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A tagged constructor has no compatible expected type.",
    },
    DiagnosticCodeDefinition {
        code: "ambiguous-module-resolution",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "Both permitted file-module candidates exist, so neither is selected.",
    },
    DiagnosticCodeDefinition {
        code: "call-argument-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A workflow argument differs from its exact parameter type.",
    },
    DiagnosticCodeDefinition {
        code: "call-arity",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A workflow call has the wrong number of arguments.",
    },
    DiagnosticCodeDefinition {
        code: "condition-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A control-flow condition is neither Bool nor Decision.",
    },
    DiagnosticCodeDefinition {
        code: "consumed-task-handle",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::TaskOwnership,
        meaning: "A task handle is consumed more than once.",
    },
    DiagnosticCodeDefinition {
        code: "default-agent-outside-root",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "A default agent declaration occurs outside the package root module.",
    },
    DiagnosticCodeDefinition {
        code: "discard-required",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A non-Unit expression statement requires explicit discard.",
    },
    DiagnosticCodeDefinition {
        code: "duplicate-default-agent",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "The package contains more than one default agent declaration.",
    },
    DiagnosticCodeDefinition {
        code: "duplicate-item",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "One module declares the same ordinary item name more than once.",
    },
    DiagnosticCodeDefinition {
        code: "duplicate-member",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "One receiver declares a duplicate field or inherent method name.",
    },
    DiagnosticCodeDefinition {
        code: "duplicate-module-resolution",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "More than one declaration resolves to the same canonical module path.",
    },
    DiagnosticCodeDefinition {
        code: "duplicate-struct-field",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A struct constructor supplies one field more than once.",
    },
    DiagnosticCodeDefinition {
        code: "duplicate-task-handle",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::TaskOwnership,
        meaning: "A task handle appears more than once in one consumption.",
    },
    DiagnosticCodeDefinition {
        code: "expected-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A type annotation resolves to an item that is not a declared type.",
    },
    DiagnosticCodeDefinition {
        code: "for-source-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A for source is not a List value.",
    },
    DiagnosticCodeDefinition {
        code: "foreign-task-handle",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::TaskOwnership,
        meaning: "A spawned task references a handle owned by another task.",
    },
    DiagnosticCodeDefinition {
        code: "identifier-confusable-collision",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::IdentifierSecurity,
        meaning: "Distinct identifier spellings share one Unicode 16 confusable skeleton.",
    },
    DiagnosticCodeDefinition {
        code: "identifier-not-nfc",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::IdentifierSecurity,
        meaning: "An identifier spelling is not already Unicode 16 NFC.",
    },
    DiagnosticCodeDefinition {
        code: "identifier-script-warning",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::IdentifierSecurity,
        meaning: "An identifier is outside one Recommended single-script set.",
    },
    DiagnosticCodeDefinition {
        code: "identifier-security",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::IdentifierSecurity,
        meaning: "An identifier contains a Unicode scalar excluded by Gantry security rules.",
    },
    DiagnosticCodeDefinition {
        code: "immutable-assignment",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An assignment target is rooted in an immutable binding or receiver.",
    },
    DiagnosticCodeDefinition {
        code: "import-name-collision",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "An imported final name collides with another visible item or import.",
    },
    DiagnosticCodeDefinition {
        code: "impure-workflow",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A pure workflow has a nonempty transitive inferred effect set.",
    },
    DiagnosticCodeDefinition {
        code: "incompatible-pattern",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A pattern constructor is incompatible with its scrutinee type.",
    },
    DiagnosticCodeDefinition {
        code: "inconsistent-task-ownership",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::TaskOwnership,
        meaning: "A task handle is attached on some control-flow paths and consumed on others.",
    },
    DiagnosticCodeDefinition {
        code: "integer-literal-out-of-range",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An integer literal exceeds the inclusive Gantry Int range.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-action-target",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An action invocation resolves to an ordinary workflow.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-block-prompt",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A block prompt violates its structural delimiter rules.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-block-prompt-indentation",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A nonblank block-prompt line does not have the closing indentation prefix.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-call-target",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An ordinary call resolves to a declared action.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-character",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A source scalar cannot begin a Gantry token.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-control-transfer",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::ControlFlow,
        meaning: "A break or continue statement has no valid enclosing loop target.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-entry-point",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "The package root does not declare exactly one function named main.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-enum-constructor",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An enum constructor does not match its variant payload shape.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-field-default",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A field default differs from its exact declared scalar or optional-member type.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-impl-target",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An inherent implementation target is not a package struct.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-loop-limit",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::ControlFlow,
        meaning: "A numeric loop limit is outside the inclusive range 1 through 2^63-1.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-number",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A numeric token violates the Gantry lexical grammar.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-option-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An Option has Unit or another Option as its immediate member.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-package-path",
        phase: DiagnosticPhase::Package,
        category: DiagnosticCategory::Package,
        meaning: "A selected path is not a canonical package-relative path.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-primitive",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A deterministic primitive has no signature for its operand types.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-source-span",
        phase: DiagnosticPhase::Package,
        category: DiagnosticCategory::Package,
        meaning: "A source-backed location is outside its immutable source bytes.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-source-utf8",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "An admitted source file is not valid UTF-8.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-string-escape",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A quoted string contains an incomplete or unsupported escape.",
    },
    DiagnosticCodeDefinition {
        code: "invalid-unicode-escape",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A Unicode escape is malformed or does not identify a scalar value.",
    },
    DiagnosticCodeDefinition {
        code: "literal-line-terminator",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A quoted string contains an unescaped line terminator.",
    },
    DiagnosticCodeDefinition {
        code: "mismatched-interpolation-delimiter",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A prompt interpolation closes nested delimiters out of order.",
    },
    DiagnosticCodeDefinition {
        code: "missing-module-source",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "A module declaration has no discovered source or inline body.",
    },
    DiagnosticCodeDefinition {
        code: "missing-parent-module",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "A discovered module has no containing module in the canonical graph.",
    },
    DiagnosticCodeDefinition {
        code: "missing-result",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::ControlFlow,
        meaning: "A value-returning callable has a reachable normal path without a result.",
    },
    DiagnosticCodeDefinition {
        code: "missing-struct-field",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A struct constructor omits a required field.",
    },
    DiagnosticCodeDefinition {
        code: "mixed-task-results",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::TaskOwnership,
        meaning: "A join mixes Unit and value-producing task results.",
    },
    DiagnosticCodeDefinition {
        code: "module-cycle",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "The canonical module graph contains a parent cycle.",
    },
    DiagnosticCodeDefinition {
        code: "nonexhaustive-match",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::ControlFlow,
        meaning: "A structural match does not cover every value of its scrutinee type.",
    },
    DiagnosticCodeDefinition {
        code: "projection-index-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A list projection index is not Int.",
    },
    DiagnosticCodeDefinition {
        code: "receiver-scope",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "The self receiver is referenced outside an inherent method body.",
    },
    DiagnosticCodeDefinition {
        code: "recursive-enum",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An enum payload recursively contains its declaring enum.",
    },
    DiagnosticCodeDefinition {
        code: "recursive-type-cycle",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A declared-type cycle contains more than one type.",
    },
    DiagnosticCodeDefinition {
        code: "redundant-pattern",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::ControlFlow,
        meaning: "A match arm is unreachable after preceding ordered patterns.",
    },
    DiagnosticCodeDefinition {
        code: "sealed-type-boundary",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A prompt, action, or entry type contains Decision or OperationError.",
    },
    DiagnosticCodeDefinition {
        code: "sealed-value-operation",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A sealed Decision value is used by a prohibited source operation.",
    },
    DiagnosticCodeDefinition {
        code: "shadowed-name",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "A lexical declaration duplicates or shadows a visible name.",
    },
    DiagnosticCodeDefinition {
        code: "tuple-index-out-of-range",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A tuple projection index exceeds its static arity.",
    },
    DiagnosticCodeDefinition {
        code: "type-mismatch",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "An expression type differs from the exact type required by its context.",
    },
    DiagnosticCodeDefinition {
        code: "unclosed-interpolation",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A prompt interpolation has no closing brace.",
    },
    DiagnosticCodeDefinition {
        code: "unconsumed-task-handle",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::TaskOwnership,
        meaning: "An attached task handle reaches lexical scope exit.",
    },
    DiagnosticCodeDefinition {
        code: "unexpected-byte-order-mark",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A byte-order mark occurs outside the permitted initial source position.",
    },
    DiagnosticCodeDefinition {
        code: "unexpected-token",
        phase: DiagnosticPhase::Syntax,
        category: DiagnosticCategory::Syntax,
        meaning: "A source token does not satisfy the Gantry surface grammar.",
    },
    DiagnosticCodeDefinition {
        code: "unguarded-recursive-type",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A self-recursive struct field is not guarded by Option or List.",
    },
    DiagnosticCodeDefinition {
        code: "unknown-member",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A receiver type has no field or inherent method with the selected name.",
    },
    DiagnosticCodeDefinition {
        code: "unknown-struct-field",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::Type,
        meaning: "A struct constructor supplies an unknown field.",
    },
    DiagnosticCodeDefinition {
        code: "unreachable-source",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::ControlFlow,
        meaning: "Source follows a command with no reachable normal completion.",
    },
    DiagnosticCodeDefinition {
        code: "unresolved-agent",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "An agent selection does not name a package-wide declared agent.",
    },
    DiagnosticCodeDefinition {
        code: "unresolved-import",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "A use declaration does not resolve to one importable package item.",
    },
    DiagnosticCodeDefinition {
        code: "unresolved-reference",
        phase: DiagnosticPhase::Analysis,
        category: DiagnosticCategory::NameResolution,
        meaning: "A required package-item path does not resolve uniquely.",
    },
    DiagnosticCodeDefinition {
        code: "unterminated-block-comment",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A nested block comment has no closing delimiter.",
    },
    DiagnosticCodeDefinition {
        code: "unterminated-prompt-template",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A contextual prompt template has no matching closing delimiter.",
    },
    DiagnosticCodeDefinition {
        code: "unterminated-raw-string",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A raw string has no matching closing delimiter.",
    },
    DiagnosticCodeDefinition {
        code: "unterminated-string",
        phase: DiagnosticPhase::Lexical,
        category: DiagnosticCategory::Lexical,
        meaning: "A quoted string has no closing delimiter.",
    },
];

/// Verifies code uniqueness and stable canonical ordering.
pub fn validate_diagnostic_code_registry() -> Result<(), DiagnosticCodeRegistryError> {
    let mut previous = None;
    let mut codes = BTreeSet::new();
    for definition in DIAGNOSTIC_CODE_REGISTRY {
        DiagnosticCode::new(definition.code).map_err(|_| DiagnosticCodeRegistryError)?;
        if !codes.insert(definition.code) || previous.is_some_and(|value| value >= definition.code)
        {
            return Err(DiagnosticCodeRegistryError);
        }
        if definition.meaning.is_empty() {
            return Err(DiagnosticCodeRegistryError);
        }
        previous = Some(definition.code);
    }
    Ok(())
}

/// Invalid or unstable diagnostic code registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticCodeRegistryError;

#[cfg(test)]
mod tests {
    use super::{
        ByteSpan, DiagnosticBuffer, DiagnosticBufferError, DiagnosticCode, DiagnosticPhase,
        FrontendLimits, GenericAnalysisCounters, PackagePath, SourceLimitConfigurationError,
        SourceLimits, SourceSnapshotBuilder, SourceSpan, TextSliceError,
        validate_diagnostic_code_registry,
    };
    use crate::portable::{DiagnosticCategory, DiagnosticSeverity, FrontendResourceCode};
    use std::collections::BTreeMap;

    #[test]
    fn complete_frontend_limits_enforce_every_finite_boundary() {
        const MAXIMUM: u64 = i64::MAX as u64;

        for accepted in [MAXIMUM - 1, MAXIMUM] {
            let limits = FrontendLimits::new(
                accepted, accepted, accepted, accepted, accepted, accepted, accepted, accepted,
                accepted, accepted, accepted, accepted,
            );
            assert!(limits.is_ok());
            let limits = limits.unwrap_or_else(|_| unreachable!("accepted finite limits"));
            assert_eq!(
                limits.source_limits(),
                SourceLimits::new(accepted, accepted, accepted, accepted, accepted)
                    .unwrap_or_else(|_| unreachable!("accepted source limits"))
            );
            assert_eq!(limits.maximum_package_source_manifest_bytes(), accepted);
            assert_eq!(limits.maximum_canonical_ir_bytes(), accepted);
            assert_eq!(limits.maximum_source_map_bytes(), accepted);
            assert_eq!(limits.maximum_generated_schema_bytes(), accepted);
            assert_eq!(limits.maximum_constructed_type_depth(), accepted);
            assert_eq!(
                limits.maximum_generic_instantiations_per_activity(),
                accepted
            );
            assert_eq!(
                limits.maximum_trait_resolution_steps_per_activity(),
                accepted
            );
        }

        for rejected in [0, MAXIMUM + 1] {
            let expected = if rejected == 0 {
                SourceLimitConfigurationError::Zero
            } else {
                SourceLimitConfigurationError::TooLarge
            };
            for index in 0..12 {
                let mut values = [1; 12];
                values[index] = rejected;
                assert_eq!(
                    FrontendLimits::new(
                        values[0], values[1], values[2], values[3], values[4], values[5],
                        values[6], values[7], values[8], values[9], values[10], values[11],
                    ),
                    Err(expected),
                    "limit index {index}"
                );
            }
        }
    }

    #[test]
    fn generic_analysis_charges_are_activity_scoped_and_failure_atomic() {
        let limits = FrontendLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 2, 4)
            .unwrap_or_else(|_| unreachable!("positive limits"));
        let mut first = GenericAnalysisCounters::new(limits);

        assert_eq!(first.check_constructed_type_depth(3), Ok(()));
        assert_eq!(
            first.check_constructed_type_depth(4),
            Err(super::FrontendResourceLimit {
                code: FrontendResourceCode::ConstructedTypeDepthLimit,
                limit: 3,
                observed: Some(4),
            })
        );
        assert_eq!(first.charge_generic_instantiation(), Ok(()));
        assert_eq!(first.charge_generic_instantiation(), Ok(()));
        assert!(matches!(
            first.charge_generic_instantiation(),
            Err(error)
                if error.code == FrontendResourceCode::GenericInstantiationLimit
                    && error.observed == Some(3)
        ));
        assert_eq!(first.charge_trait_resolution_steps(1), Ok(()));
        assert_eq!(first.charge_trait_resolution_steps(3), Ok(()));
        assert!(matches!(
            first.charge_trait_resolution_steps(u64::MAX),
            Err(error)
                if error.code == FrontendResourceCode::TraitResolutionStepLimit
                    && error.observed.is_none()
        ));
        assert_eq!(first.counts(), (2, 4));

        let reset = GenericAnalysisCounters::new(limits);
        assert_eq!(reset.counts(), (0, 0));
    }

    #[test]
    fn package_paths_and_snapshots_are_canonical_and_immutable() {
        assert!(PackagePath::new("main.gnt").is_ok());
        assert!(PackagePath::new("nested/module.gnt").is_ok());
        for invalid in [
            "",
            "/main.gnt",
            "../main.gnt",
            "a//b.gnt",
            "a\\b.gnt",
            "main.txt",
        ] {
            assert!(PackagePath::new(invalid).is_err(), "{invalid}");
        }

        let limits = SourceLimits::new(2, 8, 16, 4, 2);
        assert!(limits.is_ok());
        let mut builder =
            SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
        let mut bytes = b"second".to_vec();
        let nested = builder.add_file("z.gnt", &bytes);
        assert!(nested.is_ok());
        bytes[0] = b'X';
        let root = builder.add_file("main.gnt", b"root");
        assert!(root.is_ok());
        let snapshot = builder.finish();
        assert_eq!(snapshot.records()[0].id().to_string(), "main.gnt");
        assert_eq!(snapshot.records()[1].bytes(), b"second");
    }

    #[test]
    fn byte_spans_preserve_multibyte_coordinates() {
        let limits = SourceLimits::new(1, 16, 16, 1, 1);
        assert!(limits.is_ok());
        let mut builder =
            SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
        let source = builder.add_file("main.gnt", "aéz".as_bytes());
        assert!(source.is_ok());
        let snapshot = builder.finish();
        let record = snapshot.get(&source.unwrap_or_else(|_| unreachable!("checked above")));
        assert!(record.is_some());
        let record = record.unwrap_or_else(|| unreachable!("checked above"));
        let scalar = ByteSpan::new(1, 3);
        assert!(scalar.is_ok());
        assert_eq!(
            record.text_slice(scalar.unwrap_or_else(|_| unreachable!("checked above"))),
            Ok("é")
        );
        let split = ByteSpan::new(1, 2);
        assert!(split.is_ok());
        assert!(matches!(
            record.text_slice(split.unwrap_or_else(|_| unreachable!("checked above"))),
            Err(TextSliceError::Span(_))
        ));
    }

    #[test]
    fn diagnostic_registry_and_order_are_stable() {
        assert_eq!(validate_diagnostic_code_registry(), Ok(()));
        let limits = SourceLimits::new(1, 8, 8, 1, 1);
        assert!(limits.is_ok());
        let mut builder =
            SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
        let source = builder.add_file("main.gnt", b"bad");
        assert!(source.is_ok());
        let snapshot = builder.finish();
        let record = snapshot.get(&source.unwrap_or_else(|_| unreachable!("checked above")));
        assert!(record.is_some());
        let record = record.unwrap_or_else(|| unreachable!("checked above"));
        let bytes = ByteSpan::new(0, 1);
        assert!(bytes.is_ok());
        let span = SourceSpan::new(
            record,
            bytes.unwrap_or_else(|_| unreachable!("checked above")),
        );
        assert!(span.is_ok());
        let diagnostic = super::StructuredDiagnostic::new(
            super::DiagnosticMetadata {
                phase: DiagnosticPhase::Lexical,
                severity: DiagnosticSeverity::Error,
                category: DiagnosticCategory::Lexical,
                code: DiagnosticCode::new("invalid-source-utf8")
                    .unwrap_or_else(|_| unreachable!("constant is valid")),
            },
            "invalid UTF-8",
            Some(span.unwrap_or_else(|_| unreachable!("checked above"))),
            Vec::new(),
            BTreeMap::new(),
        );
        assert!(diagnostic.is_ok());
        let mut buffer =
            DiagnosticBuffer::new(1).unwrap_or_else(|_| unreachable!("positive limit"));
        assert!(
            buffer
                .push(diagnostic.clone().unwrap_or_else(|_| unreachable!()))
                .is_ok()
        );
        let limit = buffer.push(diagnostic.unwrap_or_else(|_| unreachable!()));
        assert!(matches!(
            limit,
            Err(DiagnosticBufferError::ResourceLimit(error))
                if error.code == FrontendResourceCode::DiagnosticCountLimit
        ));
        assert_eq!(buffer.diagnostics().len(), 1);
    }
}
