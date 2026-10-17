//! Declared `std.env` surface and bounded launch-value model for `SPEC.md` Sections 49 and 30.
//!
//! The module publishes the canonical `std.env` module rows and their applicability, and it
//! models the bounded immutable argument and environment snapshots whose exact values and
//! attenuation rules `GNT-30.2-bounded-launch-snapshot-and-capability-closure` and
//! `GNT-30.3-arguments-environment-and-logical-cwd` require.
//!
//! The value model is deliberately not an environment provider or a launcher. It reads no
//! ambient process state, performs no host I/O, infers no credential from a name or value, and
//! grants no environment, directory, or durable authority. Every operation is a deterministic
//! function of explicit inputs: admission, lookup, enumeration, update, child attenuation,
//! launch injection, and durable snapshot recovery. Protected entries remain present across all
//! of those operations and are redacted from ordinary formatting so a diagnostic, log line, or
//! debug rendering cannot disclose them. Native process handles, paths, and digests are refused
//! rather than resurrected or treated as authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::application::LaunchArrangement;
use crate::package::TargetKind;
use crate::resource::ResourceCarrier;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 49 clauses implemented by this pure model, in declaration order.
pub const ENV_CLAUSES: [&str; 2] = [
    "GNT-49.0-environment-foundation-scope",
    "GNT-49.1-environment-modules-and-item-rows",
];

/// The declared semantic mode of every `std.env` item row.
pub const ENV_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.env` item row.
pub const ENV_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// One declared public module of `std.env` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvItemRow {
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public modules of `std.env`, in canonical name order.
pub const ENV_ITEMS: [EnvItemRow; 3] = [
    EnvItemRow {
        name: "std.env::arguments",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ],
    },
    EnvItemRow {
        name: "std.env::environment",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ],
    },
    EnvItemRow {
        name: "std.env::working_directory",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-49.0-environment-foundation-scope",
            "GNT-49.1-environment-modules-and-item-rows",
        ],
    },
];

/// Declares the canonical pure hierarchy plus the `std.env` declaration surface.
pub fn canonical_env_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_env_package(&mut graph)?;
    Ok(graph)
}

/// Adds the capability-backed `std.env` package and its closed module surface to a graph.
pub fn declare_env_package(graph: &mut StdGraph) -> Result<(), StdlibError> {
    graph.declare(StdPackage::new(
        PackageFamily::Env,
        NameClass::Package,
        StabilityTier::Stable,
        &ENV_SURFACE_MODES,
        &ENV_SURFACE_TARGETS,
        &[],
        &[],
    )?)?;
    declare_env_surface(graph)
}

/// Declares the published item surface of `std.env` over one standard-library graph.
pub fn declare_env_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Env.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_env_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            ENV_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == ENV_ITEMS.len() {
        let row = ENV_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in ENV_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.env` surface as exactly its three module rows.
pub fn admit_env_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Env.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_env_surface_package(graph, package)?;
    if ENV_ITEMS.iter().any(|row| package.item(row.name).is_none()) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.env item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_env_surface_package(graph: &StdGraph, package: &StdPackage) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(ENV_SURFACE_MODES)
        || package.targets().iter().copied().ne(ENV_SURFACE_TARGETS)
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::UnsupportedApplicability,
            format!(
                "`{}` must declare exactly the application mode over the library and binary targets",
                package.name()
            ),
        ));
    }
    if package.exports().iter().any(|export| {
        !ENV_ITEMS
            .iter()
            .any(|row| export == &row.name.replace("::", "."))
    }) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a package export outside the three std.env modules is refused".to_owned(),
        ));
    }
    let owner = package.name();
    if graph.names().iter().any(|name| name.owner() == owner) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            format!("`{owner}` declares a name outside its three declared modules"),
        ));
    }
    let present = ENV_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the three std.env modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != ENV_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.env item surface is partially declared".to_owned(),
        ));
    }
    for row in ENV_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(ENV_SURFACE_MODES)
            || item.targets().iter().copied().ne(ENV_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}

/// The launch-contract clauses this value model implements, in specification order.
///
/// The anchors already exist in `SPEC.md`; this constant publishes no new requirement row.
pub const ENV_VALUE_CLAUSES: [&str; 3] = [
    "GNT-30.2-bounded-launch-snapshot-and-capability-closure",
    "GNT-30.3-arguments-environment-and-logical-cwd",
    "GNT-49.0-environment-foundation-scope",
];

/// The declared version of the bounded launch-value contract.
///
/// A durable record that declares another version is refused rather than reinterpreted.
pub const ENV_VALUE_CONTRACT_VERSION: u64 = 1;

/// The declared default bound on the number of arguments in one snapshot.
pub const ENV_DEFAULT_MAX_ARGUMENTS: usize = 4_096;

/// The declared default bound on the number of environment entries in one snapshot.
pub const ENV_DEFAULT_MAX_ENTRIES: usize = 4_096;

/// The declared default bound, in bytes, on one environment name.
pub const ENV_DEFAULT_MAX_NAME_BYTES: usize = 256;

/// The declared default bound, in bytes, on one environment value or argument.
pub const ENV_DEFAULT_MAX_VALUE_BYTES: usize = 65_536;

/// The declared default bound, in bytes, on one snapshot's names, values, or arguments.
pub const ENV_DEFAULT_MAX_TOTAL_BYTES: usize = 1_048_576;

/// The closed refusal set of the bounded launch-value contract.
///
/// Each code names exactly one refusal condition, and no code is shared by two conditions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnvDiagnosticCode {
    /// One argument or value exceeds the declared per-item byte bound.
    ArgumentByteBound,
    /// The argument count exceeds the declared count bound.
    ArgumentCountBound,
    /// An environment name is declared more than once in one snapshot or grant.
    DuplicateEntry,
    /// One environment name or value exceeds its declared byte bound.
    EntryByteBound,
    /// The environment entry count exceeds the declared count bound.
    EntryCountBound,
    /// A durable record is not an eligible committed snapshot of the declared version.
    IneligibleSnapshot,
    /// Two launch arrangements present different arguments or environment entries.
    InjectionMismatch,
    /// A presented byte sequence is not valid UTF-8.
    InvalidEncoding,
    /// An environment name is empty or contains a refused character.
    InvalidEntryName,
    /// A declared limit is zero and therefore admits no exact domain.
    InvalidLimits,
    /// An environment value contains a refused character.
    InvalidValue,
    /// A process-local native environment handle can never be resurrected.
    NativeHandleRefused,
    /// A path or digest is not committed authority to recover a snapshot.
    PathDigestNoAuthority,
    /// A snapshot's total declared bytes exceed the declared total bound.
    TotalByteBound,
}

impl EnvDiagnosticCode {
    /// Every declared code, in canonical order.
    pub const ALL: [Self; 14] = [
        Self::ArgumentByteBound,
        Self::ArgumentCountBound,
        Self::DuplicateEntry,
        Self::EntryByteBound,
        Self::EntryCountBound,
        Self::IneligibleSnapshot,
        Self::InjectionMismatch,
        Self::InvalidEncoding,
        Self::InvalidEntryName,
        Self::InvalidLimits,
        Self::InvalidValue,
        Self::NativeHandleRefused,
        Self::PathDigestNoAuthority,
        Self::TotalByteBound,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArgumentByteBound => "env-argument-byte-bound",
            Self::ArgumentCountBound => "env-argument-count-bound",
            Self::DuplicateEntry => "env-duplicate-entry",
            Self::EntryByteBound => "env-entry-byte-bound",
            Self::EntryCountBound => "env-entry-count-bound",
            Self::IneligibleSnapshot => "env-ineligible-snapshot",
            Self::InjectionMismatch => "env-injection-mismatch",
            Self::InvalidEncoding => "env-invalid-encoding",
            Self::InvalidEntryName => "env-invalid-entry-name",
            Self::InvalidLimits => "env-invalid-limits",
            Self::InvalidValue => "env-invalid-value",
            Self::NativeHandleRefused => "env-native-handle-refused",
            Self::PathDigestNoAuthority => "env-path-digest-no-authority",
            Self::TotalByteBound => "env-total-byte-bound",
        }
    }
}

/// One typed refusal of the bounded launch-value contract.
///
/// The detail names the refused condition without echoing a protected value: a protected byte
/// sequence can never reach ordinary diagnostics through this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvError {
    code: EnvDiagnosticCode,
    detail: String,
}

impl EnvError {
    /// Builds one refusal from its declared code and a non-protected explanation.
    fn new(code: EnvDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the one declared code that owns this refusal.
    #[must_use]
    pub const fn code(&self) -> EnvDiagnosticCode {
        self.code
    }

    /// Returns the non-protected explanation of the refused condition.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for EnvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

/// The exact finite bounds of one argument or environment snapshot.
///
/// Every bound is nonzero: a zero bound admits no exact domain, so it is refused rather than
/// interpreted as "unbounded" or "empty". The total bound is the sum of every entry's name and
/// value bytes, or of every argument's bytes, within one snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvLimits {
    max_arguments: usize,
    max_entries: usize,
    max_name_bytes: usize,
    max_value_bytes: usize,
    max_total_bytes: usize,
}

impl EnvLimits {
    /// Declares one exact bound set, refusing a zero bound.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::InvalidLimits`] when any bound is zero.
    pub fn new(
        max_arguments: usize,
        max_entries: usize,
        max_name_bytes: usize,
        max_value_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, EnvError> {
        if [
            max_arguments,
            max_entries,
            max_name_bytes,
            max_value_bytes,
            max_total_bytes,
        ]
        .contains(&0)
        {
            return Err(EnvError::new(
                EnvDiagnosticCode::InvalidLimits,
                "every launch-value bound must be nonzero",
            ));
        }
        Ok(Self {
            max_arguments,
            max_entries,
            max_name_bytes,
            max_value_bytes,
            max_total_bytes,
        })
    }

    /// Returns the declared default bound set.
    #[must_use]
    pub const fn declared() -> Self {
        Self {
            max_arguments: ENV_DEFAULT_MAX_ARGUMENTS,
            max_entries: ENV_DEFAULT_MAX_ENTRIES,
            max_name_bytes: ENV_DEFAULT_MAX_NAME_BYTES,
            max_value_bytes: ENV_DEFAULT_MAX_VALUE_BYTES,
            max_total_bytes: ENV_DEFAULT_MAX_TOTAL_BYTES,
        }
    }

    /// Returns the maximum admitted argument count.
    #[must_use]
    pub const fn max_arguments(self) -> usize {
        self.max_arguments
    }

    /// Returns the maximum admitted environment entry count.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum admitted environment name length in bytes.
    #[must_use]
    pub const fn max_name_bytes(self) -> usize {
        self.max_name_bytes
    }

    /// Returns the maximum admitted environment value or argument length in bytes.
    #[must_use]
    pub const fn max_value_bytes(self) -> usize {
        self.max_value_bytes
    }

    /// Returns the maximum admitted total name, value, or argument bytes in one snapshot.
    #[must_use]
    pub const fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }
}

/// The closed protection classification of one environment value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnvProtection {
    /// The value may appear in ordinary formatting.
    Ordinary,
    /// The value is present in every snapshot but redacted from ordinary formatting.
    Protected,
}

impl EnvProtection {
    /// Every classification, in canonical wire-name order.
    pub const ALL: [Self; 2] = [Self::Ordinary, Self::Protected];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Protected => "protected",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protection| protection.wire_name() == value)
    }
}

/// One admitted environment name.
///
/// A name is nonempty UTF-8 text without a NUL octet, an `=` octet, or a control character. Names
/// are compared byte for byte and are never case-folded or normalized, because an ambient host
/// case or encoding policy is not part of the portable value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentEntryName(String);

impl EnvironmentEntryName {
    /// Admits one name against the declared name bound.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::InvalidEntryName`] for an empty name or one containing a NUL
    /// octet, an `=` octet, or a control character, and
    /// [`EnvDiagnosticCode::EntryByteBound`] when the name exceeds the declared byte bound.
    pub fn new(value: impl Into<String>, limits: &EnvLimits) -> Result<Self, EnvError> {
        let value = value.into();
        validate_name_text(&value, limits)?;
        Ok(Self(value))
    }

    /// Admits one name from presented bytes, refusing invalid UTF-8.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::InvalidEncoding`] when the bytes are not UTF-8, and otherwise
    /// the same refusals as [`EnvironmentEntryName::new`].
    pub fn from_bytes(bytes: &[u8], limits: &EnvLimits) -> Result<Self, EnvError> {
        let value = std::str::from_utf8(bytes).map_err(|_| {
            EnvError::new(
                EnvDiagnosticCode::InvalidEncoding,
                "an environment name is not valid UTF-8",
            )
        })?;
        Self::new(value, limits)
    }

    /// Returns the exact admitted spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One admitted environment value with its declared protection.
///
/// The value bytes are present in the snapshot; only their rendering is classified. Ordinary
/// formatting of a protected value prints a fixed redaction marker, and the explicit
/// [`EnvironmentValue::expose`] accessor is the only non-ordinary read. Protection is always
/// declared by the construction call and is never inferred from a name or a value's shape.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentValue {
    kind: ValueKind,
}

/// The private value payload, so neither variant can bypass admission.
#[derive(Clone, Eq, PartialEq)]
enum ValueKind {
    /// An ordinary value.
    Ordinary(String),
    /// A protected value.
    Protected(String),
}

impl EnvironmentValue {
    /// Admits one ordinary value against the declared value bound.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::InvalidValue`] for a NUL octet and
    /// [`EnvDiagnosticCode::EntryByteBound`] beyond the declared value byte bound.
    pub fn ordinary(value: impl Into<String>, limits: &EnvLimits) -> Result<Self, EnvError> {
        Self::admit(value.into(), EnvProtection::Ordinary, limits)
    }

    /// Admits one protected value against the declared value bound.
    ///
    /// # Errors
    ///
    /// Returns the same refusals as [`EnvironmentValue::ordinary`].
    pub fn protected(value: impl Into<String>, limits: &EnvLimits) -> Result<Self, EnvError> {
        Self::admit(value.into(), EnvProtection::Protected, limits)
    }

    /// Admits one value from presented bytes with an explicit protection classification.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::InvalidEncoding`] when the bytes are not UTF-8, and otherwise
    /// the same refusals as [`EnvironmentValue::ordinary`].
    pub fn from_bytes(
        bytes: &[u8],
        protection: EnvProtection,
        limits: &EnvLimits,
    ) -> Result<Self, EnvError> {
        let value = std::str::from_utf8(bytes).map_err(|_| {
            EnvError::new(
                EnvDiagnosticCode::InvalidEncoding,
                "an environment value is not valid UTF-8",
            )
        })?;
        Self::admit(value.to_owned(), protection, limits)
    }

    /// Admits one value with an explicit protection classification.
    fn admit(
        value: String,
        protection: EnvProtection,
        limits: &EnvLimits,
    ) -> Result<Self, EnvError> {
        validate_value_text(&value, limits)?;
        let kind = match protection {
            EnvProtection::Ordinary => ValueKind::Ordinary(value),
            EnvProtection::Protected => ValueKind::Protected(value),
        };
        Ok(Self { kind })
    }

    /// Returns the declared protection classification.
    #[must_use]
    pub const fn protection(&self) -> EnvProtection {
        match self.kind {
            ValueKind::Ordinary(_) => EnvProtection::Ordinary,
            ValueKind::Protected(_) => EnvProtection::Protected,
        }
    }

    /// Returns whether the value is protected.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        matches!(self.kind, ValueKind::Protected(_))
    }

    /// Returns the exact value bytes for an explicit non-ordinary consumer.
    ///
    /// Ordinary formatting never calls this accessor. A launcher injection or child projection
    /// path consumes it deliberately; a diagnostic or debug rendering must not.
    #[must_use]
    pub fn expose(&self) -> &str {
        match &self.kind {
            ValueKind::Ordinary(value) | ValueKind::Protected(value) => value,
        }
    }

    /// Returns the exact value length in bytes.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.expose().len()
    }
}

impl fmt::Debug for EnvironmentValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ValueKind::Ordinary(value) => formatter.debug_tuple("Ordinary").field(value).finish(),
            ValueKind::Protected(_) => formatter.write_str("Protected(<protected>)"),
        }
    }
}

impl fmt::Display for EnvironmentValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ValueKind::Ordinary(value) => formatter.write_str(value),
            ValueKind::Protected(_) => formatter.write_str("<protected>"),
        }
    }
}

/// One admitted environment entry: an exact name and an exact value.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentEntry {
    name: EnvironmentEntryName,
    value: EnvironmentValue,
}

impl EnvironmentEntry {
    /// Admits one entry, revalidating its name and value against `limits`.
    ///
    /// # Errors
    ///
    /// Returns the name or value refusal of the presented components.
    pub fn new(
        name: EnvironmentEntryName,
        value: EnvironmentValue,
        limits: &EnvLimits,
    ) -> Result<Self, EnvError> {
        validate_name_text(name.as_str(), limits)?;
        validate_value_text(value.expose(), limits)?;
        Ok(Self { name, value })
    }

    /// Admits one ordinary entry.
    ///
    /// # Errors
    ///
    /// Returns the name or value refusal of the presented components.
    pub fn ordinary(
        name: EnvironmentEntryName,
        value: impl Into<String>,
        limits: &EnvLimits,
    ) -> Result<Self, EnvError> {
        Self::new(name, EnvironmentValue::ordinary(value, limits)?, limits)
    }

    /// Admits one protected entry.
    ///
    /// # Errors
    ///
    /// Returns the name or value refusal of the presented components.
    pub fn protected(
        name: EnvironmentEntryName,
        value: impl Into<String>,
        limits: &EnvLimits,
    ) -> Result<Self, EnvError> {
        Self::new(name, EnvironmentValue::protected(value, limits)?, limits)
    }

    /// Returns the exact admitted name.
    #[must_use]
    pub const fn name(&self) -> &EnvironmentEntryName {
        &self.name
    }

    /// Returns the exact admitted value.
    #[must_use]
    pub const fn value(&self) -> &EnvironmentValue {
        &self.value
    }

    /// Returns the exact name and value bytes this entry contributes to a snapshot total.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.name.as_str().len() + self.value.byte_len()
    }
}

impl fmt::Debug for EnvironmentEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentEntry")
            .field("name", &self.name.as_str())
            .field("value", &self.value)
            .finish()
    }
}

impl fmt::Display for EnvironmentEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}", self.name.as_str(), self.value)
    }
}

/// Validates one environment name against the declared name domain and byte bound.
fn validate_name_text(name: &str, limits: &EnvLimits) -> Result<(), EnvError> {
    if name.is_empty() {
        return Err(EnvError::new(
            EnvDiagnosticCode::InvalidEntryName,
            "an environment name must be nonempty",
        ));
    }
    if name.len() > limits.max_name_bytes {
        return Err(EnvError::new(
            EnvDiagnosticCode::EntryByteBound,
            format!(
                "an environment name declares {} bytes, beyond the {} byte bound",
                name.len(),
                limits.max_name_bytes
            ),
        ));
    }
    if name
        .chars()
        .any(|character| character == '\0' || character == '=' || character.is_control())
    {
        return Err(EnvError::new(
            EnvDiagnosticCode::InvalidEntryName,
            "an environment name contains a NUL, `=`, or control character",
        ));
    }
    Ok(())
}

/// Validates one environment value against the declared byte bound.
fn validate_value_text(value: &str, limits: &EnvLimits) -> Result<(), EnvError> {
    if value.len() > limits.max_value_bytes {
        return Err(EnvError::new(
            EnvDiagnosticCode::EntryByteBound,
            format!(
                "a launch value declares {} bytes, beyond the {} byte bound",
                value.len(),
                limits.max_value_bytes
            ),
        ));
    }
    if value.contains('\0') {
        return Err(EnvError::new(
            EnvDiagnosticCode::InvalidValue,
            "a launch value contains a NUL octet",
        ));
    }
    Ok(())
}

/// Validates one argument against the declared per-argument byte bound.
fn validate_argument_text(value: &str, limits: &EnvLimits) -> Result<(), EnvError> {
    if value.len() > limits.max_value_bytes {
        return Err(EnvError::new(
            EnvDiagnosticCode::ArgumentByteBound,
            format!(
                "an argument declares {} bytes, beyond the {} byte bound",
                value.len(),
                limits.max_value_bytes
            ),
        ));
    }
    if value.contains('\0') {
        return Err(EnvError::new(
            EnvDiagnosticCode::InvalidValue,
            "an argument contains a NUL octet",
        ));
    }
    Ok(())
}

/// One immutable, bounded, ordered argument snapshot.
///
/// Argument order is meaningful and preserved exactly. The snapshot is admitted once and never
/// mutated; a later argument change is a new snapshot. No operation reads an ambient process
/// argument list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentSnapshot {
    arguments: Vec<String>,
    limits: EnvLimits,
}

impl ArgumentSnapshot {
    /// Admits one exact argument sequence against `limits`.
    ///
    /// Arguments are validated in presented order, then the count bound is checked, then the
    /// total byte bound. Content is never rewritten, trimmed, or reordered.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::ArgumentByteBound`] or
    /// [`EnvDiagnosticCode::InvalidValue`] for a refused argument,
    /// [`EnvDiagnosticCode::ArgumentCountBound`] beyond the count bound, and
    /// [`EnvDiagnosticCode::TotalByteBound`] beyond the total byte bound.
    pub fn new(arguments: Vec<String>, limits: &EnvLimits) -> Result<Self, EnvError> {
        let mut total = 0usize;
        for argument in &arguments {
            validate_argument_text(argument, limits)?;
            total = total.checked_add(argument.len()).ok_or_else(|| {
                EnvError::new(
                    EnvDiagnosticCode::TotalByteBound,
                    "the declared argument bytes exceed the addressable total",
                )
            })?;
        }
        if arguments.len() > limits.max_arguments {
            return Err(EnvError::new(
                EnvDiagnosticCode::ArgumentCountBound,
                format!(
                    "{} arguments are declared, beyond the {} argument bound",
                    arguments.len(),
                    limits.max_arguments
                ),
            ));
        }
        if total > limits.max_total_bytes {
            return Err(EnvError::new(
                EnvDiagnosticCode::TotalByteBound,
                format!(
                    "the arguments declare {total} bytes, beyond the {} byte bound",
                    limits.max_total_bytes
                ),
            ));
        }
        Ok(Self {
            arguments,
            limits: *limits,
        })
    }

    /// Returns the exact argument sequence in its admitted order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.arguments
    }

    /// Returns one argument by zero-based position.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&str> {
        self.arguments.get(index).map(String::as_str)
    }

    /// Enumerates every argument in exact admitted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.arguments.iter().map(String::as_str)
    }

    /// Returns the admitted argument count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.arguments.len()
    }

    /// Returns whether no argument is admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.arguments.is_empty()
    }

    /// Returns the exact bounds this snapshot was admitted under.
    #[must_use]
    pub const fn limits(&self) -> EnvLimits {
        self.limits
    }
}

/// One immutable, bounded environment snapshot in canonical name order.
///
/// Names are nonempty and unique. Entry count, per-entry bytes, and total bytes are bounded at
/// admission. Lookup and enumeration are explicit operations over the admitted entries; there is
/// no ambient read. An update always returns a new snapshot and never mutates the original or
/// another snapshot, so a prior snapshot keeps its exact values for as long as it is held.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSnapshot {
    entries: BTreeMap<String, EnvironmentEntry>,
    total_bytes: usize,
    limits: EnvLimits,
}

impl EnvironmentSnapshot {
    /// Admits one exact entry set against `limits`.
    ///
    /// The entry count bound is checked before any entry content. Entries are then validated in
    /// presented order and the running total byte bound is checked after every entry, so an
    /// out-of-bound presentation is refused before the canonical map is built. Duplicate names
    /// are refused while that canonical ascending-name map is constructed, and no entry payload
    /// is copied in order to refuse a presentation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::EntryCountBound`] before any entry is inspected,
    /// [`EnvDiagnosticCode::InvalidEntryName`], [`EnvDiagnosticCode::InvalidValue`], or
    /// [`EnvDiagnosticCode::EntryByteBound`] for a refused entry,
    /// [`EnvDiagnosticCode::TotalByteBound`] once the running total exceeds its bound, and
    /// [`EnvDiagnosticCode::DuplicateEntry`] for a repeated name.
    pub fn new(entries: Vec<EnvironmentEntry>, limits: &EnvLimits) -> Result<Self, EnvError> {
        if entries.len() > limits.max_entries {
            return Err(EnvError::new(
                EnvDiagnosticCode::EntryCountBound,
                format!(
                    "{} entries are declared, beyond the {} entry bound",
                    entries.len(),
                    limits.max_entries
                ),
            ));
        }
        let mut total_bytes = 0usize;
        for entry in &entries {
            validate_name_text(entry.name().as_str(), limits)?;
            validate_value_text(entry.value().expose(), limits)?;
            total_bytes = total_bytes.checked_add(entry.byte_len()).ok_or_else(|| {
                EnvError::new(
                    EnvDiagnosticCode::TotalByteBound,
                    "the declared environment bytes exceed the addressable total",
                )
            })?;
            if total_bytes > limits.max_total_bytes {
                return Err(EnvError::new(
                    EnvDiagnosticCode::TotalByteBound,
                    format!(
                        "the environment declares {total_bytes} bytes, beyond the {} byte bound",
                        limits.max_total_bytes
                    ),
                ));
            }
        }
        let mut frozen = BTreeMap::new();
        for entry in entries {
            let name = entry.name().as_str().to_owned();
            if frozen.contains_key(&name) {
                return Err(EnvError::new(
                    EnvDiagnosticCode::DuplicateEntry,
                    format!("environment name `{name}` is declared more than once"),
                ));
            }
            frozen.insert(name, entry);
        }
        Ok(Self {
            entries: frozen,
            total_bytes,
            limits: *limits,
        })
    }

    /// Looks up one entry by its exact name.
    ///
    /// The lookup is case-sensitive and consults only this snapshot.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&EnvironmentEntry> {
        self.entries.get(name)
    }

    /// Returns whether one exact name is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Enumerates every entry in canonical ascending name order.
    pub fn iter(&self) -> impl Iterator<Item = &EnvironmentEntry> {
        self.entries.values()
    }

    /// Returns the admitted entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the snapshot admits no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the exact total name and value bytes of this snapshot.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the exact bounds this snapshot was admitted under.
    #[must_use]
    pub const fn limits(&self) -> EnvLimits {
        self.limits
    }

    /// Returns a new snapshot that adds or replaces one entry.
    ///
    /// The original snapshot and every other held snapshot keep their exact values. A replacement
    /// keeps the entry count unchanged and re-counts the entry's bytes; an addition must fit both
    /// the count and total byte bounds.
    ///
    /// # Errors
    ///
    /// Returns the entry refusal of the presented entry,
    /// [`EnvDiagnosticCode::EntryCountBound`] for an addition beyond the count bound, or
    /// [`EnvDiagnosticCode::TotalByteBound`] beyond the total byte bound. Refusal checks run
    /// before the new map is built, so a refused update copies no entry payload and leaves every
    /// snapshot unchanged.
    pub fn with_entry(&self, entry: EnvironmentEntry) -> Result<Self, EnvError> {
        validate_name_text(entry.name().as_str(), &self.limits)?;
        validate_value_text(entry.value().expose(), &self.limits)?;
        let name = entry.name().as_str().to_owned();
        let replaced = self.entries.get(&name).map(EnvironmentEntry::byte_len);
        if replaced.is_none() && self.entries.len() >= self.limits.max_entries {
            return Err(EnvError::new(
                EnvDiagnosticCode::EntryCountBound,
                format!(
                    "adding `{name}` would exceed the {} entry bound",
                    self.limits.max_entries
                ),
            ));
        }
        let total_bytes = self.total_bytes - replaced.unwrap_or_default() + entry.byte_len();
        if total_bytes > self.limits.max_total_bytes {
            return Err(EnvError::new(
                EnvDiagnosticCode::TotalByteBound,
                format!(
                    "adding `{name}` would declare {total_bytes} bytes, beyond the {} byte bound",
                    self.limits.max_total_bytes
                ),
            ));
        }
        let mut entries = self.entries.clone();
        entries.insert(name, entry);
        Ok(Self {
            entries,
            total_bytes,
            limits: self.limits,
        })
    }

    /// Returns a new snapshot that omits one exact name.
    ///
    /// The original snapshot is unchanged. Removing an absent name returns an equal snapshot.
    #[must_use]
    pub fn without_entry(&self, name: &str) -> Self {
        let mut entries = self.entries.clone();
        let mut total_bytes = self.total_bytes;
        if let Some(removed) = entries.remove(name) {
            total_bytes -= removed.byte_len();
        }
        Self {
            entries,
            total_bytes,
            limits: self.limits,
        }
    }

    /// Returns the exact attenuated child projection for one explicit grant.
    ///
    /// The projection contains exactly the granted names that this snapshot holds, byte for byte.
    /// It cannot add an entry, cannot widen a value, and cannot convert a protected value to an
    /// ordinary one. There is no ambient inheritance path: a grant is the only input.
    #[must_use]
    pub fn project_child(&self, grant: &ChildEnvironmentGrant) -> ChildEnvironmentProjection {
        let entries = grant
            .names()
            .iter()
            .filter_map(|name| self.entries.get(name.as_str()).cloned())
            .collect();
        ChildEnvironmentProjection { entries }
    }

    /// Builds the exact launch injection for one arrangement.
    ///
    /// Arguments are preserved in their admitted order and the environment is the attenuated
    /// projection. The arrangement never changes either payload, so a standalone and an embedded
    /// launch present identical values; [`admit_injection_parity`] verifies that fact.
    #[must_use]
    pub fn injection_plan(
        &self,
        arguments: &ArgumentSnapshot,
        grant: &ChildEnvironmentGrant,
        arrangement: LaunchArrangement,
    ) -> InjectionPlan {
        InjectionPlan {
            arrangement,
            arguments: arguments.as_slice().to_vec(),
            environment: self.project_child(grant).entries,
        }
    }

    /// Returns the committed durable record of this exact snapshot.
    #[must_use]
    pub fn durable_record(&self) -> DurableEnvironmentRecord {
        DurableEnvironmentRecord {
            version: ENV_VALUE_CONTRACT_VERSION,
            entries: self.entries.values().cloned().collect(),
            limits: self.limits,
        }
    }
}

/// One explicit child environment grant.
///
/// A grant names exactly the entries a child may receive. It is the only input to child
/// projection, so inheritance is never ambient: an empty grant inherits nothing, a grant cannot
/// name a value the parent does not hold, and duplicate names are refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildEnvironmentGrant {
    names: BTreeSet<EnvironmentEntryName>,
}

impl ChildEnvironmentGrant {
    /// Returns the empty grant, which inherits no environment entry.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            names: BTreeSet::new(),
        }
    }

    /// Declares one explicit grant over exactly the presented names.
    ///
    /// # Errors
    ///
    /// Returns the name refusal of the first refused name and
    /// [`EnvDiagnosticCode::DuplicateEntry`] for a repeated name.
    pub fn selecting(names: &[&str], limits: &EnvLimits) -> Result<Self, EnvError> {
        let mut selected = BTreeSet::new();
        for name in names {
            let name = EnvironmentEntryName::new(*name, limits)?;
            if !selected.insert(name.clone()) {
                return Err(EnvError::new(
                    EnvDiagnosticCode::DuplicateEntry,
                    format!(
                        "environment name `{}` is granted more than once",
                        name.as_str()
                    ),
                ));
            }
        }
        Ok(Self { names: selected })
    }

    /// Returns the exact granted names in canonical order.
    #[must_use]
    pub fn names(&self) -> &BTreeSet<EnvironmentEntryName> {
        &self.names
    }

    /// Returns whether no name is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// The exact attenuated child environment projection.
///
/// Every contained entry is byte-identical to the parent entry of the same name, including its
/// protection, so the projection is provably a subset and never a widening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildEnvironmentProjection {
    entries: Vec<EnvironmentEntry>,
}

impl ChildEnvironmentProjection {
    /// Returns the projected entries in canonical ascending name order.
    #[must_use]
    pub fn entries(&self) -> &[EnvironmentEntry] {
        &self.entries
    }

    /// Returns the projected entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the projection inherits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns whether every projected entry is exactly its parent entry.
    #[must_use]
    pub fn is_subset_of(&self, parent: &EnvironmentSnapshot) -> bool {
        self.entries
            .iter()
            .all(|entry| parent.get(entry.name().as_str()) == Some(entry))
    }
}

/// The exact launch injection presented to a child process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectionPlan {
    arrangement: LaunchArrangement,
    arguments: Vec<String>,
    environment: Vec<EnvironmentEntry>,
}

impl InjectionPlan {
    /// Returns the launch arrangement this plan was built for.
    #[must_use]
    pub const fn arrangement(&self) -> LaunchArrangement {
        self.arrangement
    }

    /// Returns the exact injected arguments in launch order.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the exact injected environment entries in canonical order.
    #[must_use]
    pub fn environment(&self) -> &[EnvironmentEntry] {
        &self.environment
    }
}

/// Admits standalone and embedded injection as one identical presentation.
///
/// Standalone and embedded launch arrangements normalize to the same launch values, so an
/// arrangement label may never change an argument or an environment byte, and a protected value
/// stays protected in both.
///
/// # Errors
///
/// Returns [`EnvDiagnosticCode::InjectionMismatch`] when either plan names the other arrangement,
/// when their argument sequences differ, or when their environment entries differ.
pub fn admit_injection_parity(
    standalone: &InjectionPlan,
    embedded: &InjectionPlan,
) -> Result<(), EnvError> {
    if standalone.arrangement != LaunchArrangement::Standalone
        || embedded.arrangement != LaunchArrangement::Embedded
    {
        return Err(EnvError::new(
            EnvDiagnosticCode::InjectionMismatch,
            "injection parity requires one standalone plan and one embedded plan",
        ));
    }
    if standalone.arguments != embedded.arguments {
        return Err(EnvError::new(
            EnvDiagnosticCode::InjectionMismatch,
            "standalone and embedded launches present different arguments",
        ));
    }
    if standalone.environment != embedded.environment {
        return Err(EnvError::new(
            EnvDiagnosticCode::InjectionMismatch,
            "standalone and embedded launches present different environment entries",
        ));
    }
    Ok(())
}

/// One committed durable environment record.
///
/// The record is the exact value form of an eligible committed snapshot. It holds no native
/// handle, path, digest, or process-local identity, so recovery can only reproduce the exact
/// values it carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEnvironmentRecord {
    version: u64,
    entries: Vec<EnvironmentEntry>,
    limits: EnvLimits,
}

impl DurableEnvironmentRecord {
    /// Returns the committed record of one admitted snapshot.
    #[must_use]
    pub fn committed(snapshot: &EnvironmentSnapshot) -> Self {
        snapshot.durable_record()
    }

    /// Decodes one durable record from its declared fields.
    ///
    /// The version is authenticated before any entry is inspected, and the admitted snapshot is
    /// then stored in canonical ascending name order, so a decoded record equals the committed
    /// record of the snapshot it recovers. Refusal copies no entry payload.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDiagnosticCode::IneligibleSnapshot`] for a version other than the declared
    /// contract version, and otherwise the entry refusals of [`EnvironmentSnapshot::new`]. A
    /// refused record recovers nothing.
    pub fn decode(
        version: u64,
        entries: Vec<EnvironmentEntry>,
        limits: &EnvLimits,
    ) -> Result<Self, EnvError> {
        if version != ENV_VALUE_CONTRACT_VERSION {
            return Err(EnvError::new(
                EnvDiagnosticCode::IneligibleSnapshot,
                format!(
                    "durable snapshot version {version} is not the declared version {ENV_VALUE_CONTRACT_VERSION}"
                ),
            ));
        }
        let snapshot = EnvironmentSnapshot::new(entries, limits)?;
        Ok(Self {
            version,
            entries: snapshot.entries.into_values().collect(),
            limits: *limits,
        })
    }

    /// Returns the declared durable contract version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the exact recorded entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[EnvironmentEntry] {
        &self.entries
    }

    /// Returns the exact bounds the recorded snapshot was admitted under.
    #[must_use]
    pub const fn limits(&self) -> EnvLimits {
        self.limits
    }

    /// Recovers the exact committed snapshot values.
    ///
    /// # Errors
    ///
    /// Returns the entry refusals of [`EnvironmentSnapshot::new`] when the recorded fields no
    /// longer form an eligible snapshot.
    pub fn recover(&self) -> Result<EnvironmentSnapshot, EnvError> {
        EnvironmentSnapshot::new(self.entries.clone(), &self.limits)
    }
}

/// One presented durable carrier for environment values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvDurableCarrier {
    /// An eligible committed snapshot record.
    CommittedSnapshot(Box<DurableEnvironmentRecord>),
    /// A process-local native handle, which never resurrects.
    NativeHandle,
    /// A path or digest reference, which grants nothing.
    PathOrDigest(String),
}

impl EnvDurableCarrier {
    /// Returns the exact carrier spelling.
    #[must_use]
    pub const fn carrier_name(&self) -> &'static str {
        match self {
            Self::CommittedSnapshot(_) => "committed-snapshot",
            Self::NativeHandle => "native-handle",
            Self::PathOrDigest(_) => "path-or-digest",
        }
    }
}

/// The one durable carrier admissible for an environment value snapshot.
///
/// The exact committed-snapshot form is the declared durable reconstruction record of
/// `GNT-28.7-durable-resource-reconstruction`; ordinary serialization and ordinary durable state
/// carry no reconstruction contract and are inadmissible.
pub const ENV_DURABLE_CARRIER: ResourceCarrier = ResourceCarrier::ReconstructionRecord;

/// Returns whether `carrier` may carry a durable environment value snapshot.
#[must_use]
pub const fn env_durable_carrier_is_admissible(carrier: ResourceCarrier) -> bool {
    matches!(carrier, ResourceCarrier::ReconstructionRecord)
}

/// Admits one declared resource carrier for environment value facts, or refuses it.
///
/// # Errors
///
/// Returns [`EnvDiagnosticCode::IneligibleSnapshot`] for ordinary serialization or ordinary
/// durable state.
pub fn admit_env_durable_carrier(carrier: ResourceCarrier) -> Result<(), EnvError> {
    if env_durable_carrier_is_admissible(carrier) {
        return Ok(());
    }
    Err(EnvError::new(
        EnvDiagnosticCode::IneligibleSnapshot,
        format!(
            "`{}` carries no durable environment reconstruction contract",
            carrier.wire_name()
        ),
    ))
}

/// Recovers the exact environment snapshot a durable carrier admits.
///
/// Only a committed eligible snapshot recovers its exact values, including protected values. A
/// native handle never resurrects, and a path or digest grants no authority to recover anything.
///
/// # Errors
///
/// Returns [`EnvDiagnosticCode::NativeHandleRefused`] for a native handle,
/// [`EnvDiagnosticCode::PathDigestNoAuthority`] for a path or digest, and the entry refusals of
/// [`EnvironmentSnapshot::new`] when a committed record is not an eligible snapshot.
pub fn admit_durable_environment(
    carrier: &EnvDurableCarrier,
) -> Result<EnvironmentSnapshot, EnvError> {
    match carrier {
        EnvDurableCarrier::CommittedSnapshot(record) => record.recover(),
        EnvDurableCarrier::NativeHandle => Err(EnvError::new(
            EnvDiagnosticCode::NativeHandleRefused,
            "a process-local native environment handle never resurrects",
        )),
        EnvDurableCarrier::PathOrDigest(reference) => Err(EnvError::new(
            EnvDiagnosticCode::PathDigestNoAuthority,
            format!("`{reference}` is a path or digest, not committed environment authority"),
        )),
    }
}
