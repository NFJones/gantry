//! Pure standard-library logical package architecture model for `SPEC.md` Section 34.
//!
//! The model records declared logical packages, name classifications, the internal
//! dependency DAG, the edition prelude, facade re-exports, stability tiers,
//! applicability, relocations, and the aggregate manifest. It is deliberately not a
//! package downloader, a generator, a linker, a repository layout, or a publication
//! mechanism: every decision below is a deterministic function of declared facts,
//! and physical Rust crate layout never enters an identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gantry_core::mode::SemanticMode;

use crate::TargetKind;
use crate::authority::digest_fields;
use crate::manifest::encode_hex;

/// The Section 34 clauses implemented by this pure model, in declaration order.
pub const STDLIB_CLAUSES: [&str; 13] = [
    "GNT-34.0-standard-library-package-architecture",
    "GNT-34.1-canonical-hierarchy-and-package-names",
    "GNT-34.2-name-classification",
    "GNT-34.3-acyclic-internal-dependency-dag",
    "GNT-34.4-edition-prelude-and-explicit-imports",
    "GNT-34.5-facade-and-reexport-identity",
    "GNT-34.6-stability-tiers",
    "GNT-34.7-applicability-and-feature-granularity",
    "GNT-34.8-defining-identity-and-interface-digest",
    "GNT-34.9-standard-library-contract-versioning",
    "GNT-34.10-relocation-and-deprecation",
    "GNT-34.11-aggregate-manifests-and-publication-inputs",
    "GNT-34.12-standard-library-architecture-non-claims",
];

/// The maximum admitted logical package or item name length in bytes.
pub const MAX_STD_NAME_BYTES: usize = 128;

/// The maximum admitted declared package count.
pub const MAX_STD_PACKAGES: usize = 128;

/// One closed standard-library family of `GNT-34.1-canonical-hierarchy-and-package-names`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PackageFamily {
    /// `std.agent`.
    Agent,
    /// `std.artifact`.
    Artifact,
    /// `std.codec`.
    Codec,
    /// `std.collections`.
    Collections,
    /// `std.console`.
    Console,
    /// `std.core`.
    Core,
    /// `std.crypto`.
    Crypto,
    /// `std.data`.
    Data,
    /// `std.env`.
    Env,
    /// `std.fs`.
    Fs,
    /// `std.io`.
    Io,
    /// `std.net`.
    Net,
    /// `std.num`.
    Num,
    /// `std.observe`.
    Observe,
    /// `std.process`.
    Process,
    /// `std.random`.
    Random,
    /// `std.secret`.
    Secret,
    /// `std.test`.
    Test,
    /// `std.text`.
    Text,
    /// `std.time`.
    Time,
}

impl PackageFamily {
    /// Every family in exact wire-name order.
    pub const ALL: [Self; 20] = [
        Self::Agent,
        Self::Artifact,
        Self::Codec,
        Self::Collections,
        Self::Console,
        Self::Core,
        Self::Crypto,
        Self::Data,
        Self::Env,
        Self::Fs,
        Self::Io,
        Self::Net,
        Self::Num,
        Self::Observe,
        Self::Process,
        Self::Random,
        Self::Secret,
        Self::Test,
        Self::Text,
        Self::Time,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Artifact => "artifact",
            Self::Codec => "codec",
            Self::Collections => "collections",
            Self::Console => "console",
            Self::Core => "core",
            Self::Crypto => "crypto",
            Self::Data => "data",
            Self::Env => "env",
            Self::Fs => "fs",
            Self::Io => "io",
            Self::Net => "net",
            Self::Num => "num",
            Self::Observe => "observe",
            Self::Process => "process",
            Self::Random => "random",
            Self::Secret => "secret",
            Self::Test => "test",
            Self::Text => "text",
            Self::Time => "time",
        }
    }

    /// Returns the canonical logical package name.
    #[must_use]
    pub fn package_name(self) -> String {
        format!("std.{}", self.wire_name())
    }

    /// Returns whether this family is pure rather than capability-backed.
    #[must_use]
    pub const fn is_pure(self) -> bool {
        matches!(
            self,
            Self::Codec
                | Self::Collections
                | Self::Core
                | Self::Crypto
                | Self::Data
                | Self::Num
                | Self::Text
        )
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|family| family.wire_name() == value)
    }
}

/// One closed name classification of `GNT-34.2-name-classification`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NameClass {
    /// A facade that re-exports public items.
    Facade,
    /// A generated declaration.
    GeneratedDeclaration,
    /// An implementation-only intrinsic.
    ImplementationIntrinsic,
    /// A module belonging to exactly one package.
    Module,
    /// A logical package.
    Package,
}

impl NameClass {
    /// Every classification in exact wire-name order.
    pub const ALL: [Self; 5] = [
        Self::Facade,
        Self::GeneratedDeclaration,
        Self::ImplementationIntrinsic,
        Self::Module,
        Self::Package,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Facade => "facade",
            Self::GeneratedDeclaration => "generated-declaration",
            Self::ImplementationIntrinsic => "implementation-intrinsic",
            Self::Module => "module",
            Self::Package => "package",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|class| class.wire_name() == value)
    }
}

/// One closed stability tier of `GNT-34.6-stability-tiers`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StabilityTier {
    /// Experimental: no compatibility promise.
    Experimental,
    /// Foundational: never entered or left by a transition.
    Foundational,
    /// Stable: the compatibility promise applies.
    Stable,
    /// Target-specific: qualified per target.
    TargetSpecific,
}

impl StabilityTier {
    /// Every tier in exact wire-name order.
    pub const ALL: [Self; 4] = [
        Self::Experimental,
        Self::Foundational,
        Self::Stable,
        Self::TargetSpecific,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::Foundational => "foundational",
            Self::Stable => "stable",
            Self::TargetSpecific => "target-specific",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tier| tier.wire_name() == value)
    }

    /// Returns whether this tier is presented as stable.
    #[must_use]
    pub const fn is_stable(self) -> bool {
        matches!(self, Self::Stable | Self::Foundational)
    }

    /// Returns the declared stability rank; a higher rank is wider stability.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Experimental => 0,
            Self::TargetSpecific => 1,
            Self::Stable => 2,
            Self::Foundational => 3,
        }
    }
}

/// One frozen architecture diagnostic of `GNT-34.0`-`GNT-34.12`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StdlibDiagnosticCode {
    /// `std-contract-version-mismatch`
    ContractVersionMismatch,
    /// `std-dependency-cycle`
    DependencyCycle,
    /// `std-duplicate-package`
    DuplicatePackage,
    /// `std-facade-identity-loss`
    FacadeIdentityLoss,
    /// `std-feature-mutates-instance`
    FeatureMutatesInstance,
    /// `std-invalid-name-classification`
    InvalidNameClassification,
    /// `std-invalid-package-name`
    InvalidPackageName,
    /// `std-invalid-relocation`
    InvalidRelocation,
    /// `std-invalid-stability-transition`
    InvalidStabilityTransition,
    /// `std-layout-derived-identity`
    LayoutDerivedIdentity,
    /// `std-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `std-package-to-adapter-edge`
    PackageToAdapterEdge,
    /// `std-publication-drift`
    PublicationDrift,
    /// `std-pure-to-capability-edge`
    PureToCapabilityEdge,
    /// `std-unenumerated-prelude-member`
    UnenumeratedPreludeMember,
    /// `std-unknown-edge`
    UnknownEdge,
    /// `std-unsupported-applicability`
    UnsupportedApplicability,
    /// `std-wildcard-prelude-refused`
    WildcardPreludeRefused,
}

impl StdlibDiagnosticCode {
    /// Every diagnostic in canonical spelling order.
    pub const ALL: [Self; 18] = [
        Self::ContractVersionMismatch,
        Self::DependencyCycle,
        Self::DuplicatePackage,
        Self::FacadeIdentityLoss,
        Self::FeatureMutatesInstance,
        Self::InvalidNameClassification,
        Self::InvalidPackageName,
        Self::InvalidRelocation,
        Self::InvalidStabilityTransition,
        Self::LayoutDerivedIdentity,
        Self::NonClaimAsGuarantee,
        Self::PackageToAdapterEdge,
        Self::PublicationDrift,
        Self::PureToCapabilityEdge,
        Self::UnenumeratedPreludeMember,
        Self::UnknownEdge,
        Self::UnsupportedApplicability,
        Self::WildcardPreludeRefused,
    ];

    /// Returns the frozen diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractVersionMismatch => "std-contract-version-mismatch",
            Self::DependencyCycle => "std-dependency-cycle",
            Self::DuplicatePackage => "std-duplicate-package",
            Self::FacadeIdentityLoss => "std-facade-identity-loss",
            Self::FeatureMutatesInstance => "std-feature-mutates-instance",
            Self::InvalidNameClassification => "std-invalid-name-classification",
            Self::InvalidPackageName => "std-invalid-package-name",
            Self::InvalidRelocation => "std-invalid-relocation",
            Self::InvalidStabilityTransition => "std-invalid-stability-transition",
            Self::LayoutDerivedIdentity => "std-layout-derived-identity",
            Self::NonClaimAsGuarantee => "std-non-claim-as-guarantee",
            Self::PackageToAdapterEdge => "std-package-to-adapter-edge",
            Self::PublicationDrift => "std-publication-drift",
            Self::PureToCapabilityEdge => "std-pure-to-capability-edge",
            Self::UnenumeratedPreludeMember => "std-unenumerated-prelude-member",
            Self::UnknownEdge => "std-unknown-edge",
            Self::UnsupportedApplicability => "std-unsupported-applicability",
            Self::WildcardPreludeRefused => "std-wildcard-prelude-refused",
        }
    }

    /// Strictly decodes one frozen diagnostic spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }

    /// Returns the sole owning requirement clause.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::InvalidPackageName | Self::DuplicatePackage => STDLIB_CLAUSES[1],
            Self::InvalidNameClassification => STDLIB_CLAUSES[2],
            Self::UnknownEdge
            | Self::DependencyCycle
            | Self::PureToCapabilityEdge
            | Self::PackageToAdapterEdge => STDLIB_CLAUSES[3],
            Self::UnenumeratedPreludeMember | Self::WildcardPreludeRefused => STDLIB_CLAUSES[4],
            Self::FacadeIdentityLoss => STDLIB_CLAUSES[5],
            Self::InvalidStabilityTransition => STDLIB_CLAUSES[6],
            Self::UnsupportedApplicability | Self::FeatureMutatesInstance => STDLIB_CLAUSES[7],
            Self::LayoutDerivedIdentity => STDLIB_CLAUSES[8],
            Self::ContractVersionMismatch => STDLIB_CLAUSES[9],
            Self::InvalidRelocation => STDLIB_CLAUSES[10],
            Self::PublicationDrift => STDLIB_CLAUSES[11],
            Self::NonClaimAsGuarantee => STDLIB_CLAUSES[12],
        }
    }
}

impl fmt::Display for StdlibDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One typed refusal from the pure standard-library architecture model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdlibError {
    code: StdlibDiagnosticCode,
    detail: String,
}

impl StdlibError {
    /// Builds one refusal with its frozen diagnostic and a bounded detail message.
    #[must_use]
    pub fn new(code: StdlibDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen diagnostic code.
    #[must_use]
    pub const fn code(&self) -> StdlibDiagnosticCode {
        self.code
    }

    /// Returns the owning clause of the frozen diagnostic code.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.code.requirement()
    }

    /// Returns the bounded detail message.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for StdlibError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for StdlibError {}

/// Validates one canonical logical name rooted at `std`.
fn validate_std_name(value: &str) -> Result<(), StdlibError> {
    let invalid = || {
        StdlibError::new(
            StdlibDiagnosticCode::InvalidPackageName,
            format!("`{value}` is not a canonical logical `std` name"),
        )
    };
    if value.len() > MAX_STD_NAME_BYTES || !value.starts_with("std.") {
        return Err(invalid());
    }
    let normalized = value.replace("::", ".");
    if normalized.ends_with('.') || normalized.contains("..") {
        return Err(invalid());
    }
    let mut segments = normalized.split('.');
    if segments.next() != Some("std") {
        return Err(invalid());
    }
    let mut count = 0;
    for segment in segments {
        count += 1;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !segment.starts_with(|scalar: char| scalar.is_ascii_lowercase())
        {
            return Err(invalid());
        }
    }
    if count == 0 {
        return Err(invalid());
    }
    Ok(())
}

/// Returns the canonical spelling of one logical `std` path: `::` and `.` separators
/// name the same logical path, so every registry, dedup check, and identity fold uses
/// this form.
fn canonical_std_path(value: &str) -> String {
    value.replace("::", ".")
}

/// One typed package interface identity of `GNT-34.8-defining-identity-and-interface-digest`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StdInterfaceIdentity(Arc<str>);

impl StdInterfaceIdentity {
    /// Returns the exact lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One typed aggregate graph identity of `GNT-34.11-aggregate-manifests-and-publication-inputs`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StdGraphIdentity(Arc<str>);

impl StdGraphIdentity {
    /// Returns the exact lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One declared public standard-library item of `GNT-34.5`-`GNT-34.8`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdItem {
    name: String,
    owner: String,
    class: NameClass,
    tier: StabilityTier,
    modes: BTreeSet<SemanticMode>,
    targets: BTreeSet<TargetKind>,
}

impl StdItem {
    /// Declares one public item; a package classification and an empty applicability
    /// are refused here.
    pub fn new(
        name: &str,
        class: NameClass,
        tier: StabilityTier,
        modes: &[SemanticMode],
        targets: &[TargetKind],
    ) -> Result<Self, StdlibError> {
        validate_std_name(name)?;
        if class == NameClass::Package {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{name}` declares the package classification inside a package"),
            ));
        }
        if modes.is_empty() || targets.is_empty() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{name}` declares no applicability"),
            ));
        }
        let canonical = canonical_std_path(name);
        let owner = canonical
            .split('.')
            .take(2)
            .collect::<Vec<&str>>()
            .join(".");
        Ok(Self {
            name: canonical,
            owner,
            class,
            tier,
            modes: modes.iter().copied().collect(),
            targets: targets.iter().copied().collect(),
        })
    }

    /// Returns the canonical item name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the defining logical package of this item.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the declared classification.
    #[must_use]
    pub const fn class(&self) -> NameClass {
        self.class
    }

    /// Returns the one declared tier.
    #[must_use]
    pub const fn tier(&self) -> StabilityTier {
        self.tier
    }

    /// Returns the declared semantic modes.
    #[must_use]
    pub fn modes(&self) -> &BTreeSet<SemanticMode> {
        &self.modes
    }

    /// Returns the declared targets.
    #[must_use]
    pub fn targets(&self) -> &BTreeSet<TargetKind> {
        &self.targets
    }
}

/// One declared logical standard-library package of `GNT-34.1`-`GNT-34.8`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdPackage {
    name: String,
    family: PackageFamily,
    class: NameClass,
    tier: StabilityTier,
    modes: BTreeSet<SemanticMode>,
    targets: BTreeSet<TargetKind>,
    dependencies: BTreeSet<String>,
    exports: BTreeSet<String>,
    items: BTreeMap<String, StdItem>,
}

impl StdPackage {
    /// Declares one logical package; a non-package classification, an empty
    /// applicability set, and malformed dependencies are refused. The `exports`
    /// parameter declares the exported reach of the package in canonical form; a public
    /// item's stability tier is declared by its `StdItem`.
    pub fn new(
        family: PackageFamily,
        class: NameClass,
        tier: StabilityTier,
        modes: &[SemanticMode],
        targets: &[TargetKind],
        dependencies: &[&str],
        exports: &[&str],
    ) -> Result<Self, StdlibError> {
        if class != NameClass::Package {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!(
                    "`{}` is declared with the non-package class `{}`",
                    family.package_name(),
                    class.wire_name()
                ),
            ));
        }
        if modes.is_empty() || targets.is_empty() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` declares no applicability", family.package_name()),
            ));
        }
        let mut declared = BTreeSet::new();
        for dependency in dependencies {
            if dependency.len() > MAX_STD_NAME_BYTES || dependency.trim().is_empty() {
                return Err(StdlibError::new(
                    StdlibDiagnosticCode::InvalidPackageName,
                    format!("`{dependency}` is not a well-formed dependency name"),
                ));
            }
            declared.insert((*dependency).to_owned());
        }
        if declared.contains(&family.package_name()) {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::DependencyCycle,
                format!(
                    "`{}` declares a dependency on itself",
                    family.package_name()
                ),
            ));
        }
        let mut exported = BTreeSet::new();
        for item in exports {
            validate_std_name(item)?;
            let canonical = canonical_std_path(item);
            if !canonical.starts_with(&format!("{}.", family.package_name())) {
                return Err(StdlibError::new(
                    StdlibDiagnosticCode::FacadeIdentityLoss,
                    format!("`{item}` is not owned by `{}`", family.package_name()),
                ));
            }
            exported.insert(canonical);
        }
        Ok(Self {
            name: family.package_name(),
            family,
            class,
            tier,
            modes: modes.iter().copied().collect(),
            targets: targets.iter().copied().collect(),
            dependencies: declared,
            exports: exported,
            items: BTreeMap::new(),
        })
    }

    /// Returns the canonical logical package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared family.
    #[must_use]
    pub const fn family(&self) -> PackageFamily {
        self.family
    }

    /// Returns the declared name classification.
    #[must_use]
    pub const fn class(&self) -> NameClass {
        self.class
    }

    /// Returns the declared stability tier.
    #[must_use]
    pub const fn tier(&self) -> StabilityTier {
        self.tier
    }

    /// Returns the declared semantic modes.
    #[must_use]
    pub fn modes(&self) -> &BTreeSet<SemanticMode> {
        &self.modes
    }

    /// Returns the declared targets.
    #[must_use]
    pub fn targets(&self) -> &BTreeSet<TargetKind> {
        &self.targets
    }

    /// Returns the declared dependency edges.
    #[must_use]
    pub fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }

    /// Returns the declared exported items.
    #[must_use]
    pub fn exports(&self) -> &BTreeSet<String> {
        &self.exports
    }

    /// Returns whether this package exports one item.
    #[must_use]
    pub fn exports_item(&self, item: &str) -> bool {
        let canonical = canonical_std_path(item);
        self.exports.contains(&canonical) || self.items.contains_key(&canonical)
    }

    /// Returns the interface identity over every declared interface fact.
    #[must_use]
    pub fn identity(&self) -> StdInterfaceIdentity {
        let mut fields: Vec<Vec<u8>> = vec![
            self.name.as_bytes().to_vec(),
            self.family.wire_name().as_bytes().to_vec(),
            self.class.wire_name().as_bytes().to_vec(),
            self.tier.wire_name().as_bytes().to_vec(),
        ];
        for mode in &self.modes {
            fields.push(mode.wire_name().as_bytes().to_vec());
        }
        for target in &self.targets {
            fields.push(target.wire_name().as_bytes().to_vec());
        }
        for dependency in &self.dependencies {
            fields.push(dependency.as_bytes().to_vec());
        }
        for item in &self.exports {
            fields.push(item.as_bytes().to_vec());
        }
        for item in self.items.values() {
            fields.push(item.name().as_bytes().to_vec());
            fields.push(item.class().wire_name().as_bytes().to_vec());
            fields.push(item.tier().wire_name().as_bytes().to_vec());
            for mode in item.modes() {
                fields.push(mode.wire_name().as_bytes().to_vec());
            }
            for target in item.targets() {
                fields.push(target.wire_name().as_bytes().to_vec());
            }
        }
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
        StdInterfaceIdentity(Arc::from(encode_hex(&digest_fields(
            "gantry.std.interface.v1",
            &borrowed,
        ))))
    }

    /// Declares one public item of this package; a foreign item, a class contradiction,
    /// and a second tier for one item are refused.
    pub fn declare_item(&mut self, item: StdItem) -> Result<(), StdlibError> {
        if item.owner() != self.name {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::FacadeIdentityLoss,
                format!("`{}` is not owned by `{}`", item.name(), self.name),
            ));
        }
        if let Some(existing) = self.items.get(item.name()) {
            let code = if existing.tier() == item.tier() {
                StdlibDiagnosticCode::DuplicatePackage
            } else {
                StdlibDiagnosticCode::InvalidStabilityTransition
            };
            return Err(StdlibError::new(
                code,
                format!(
                    "`{}` already declares the tier `{}`",
                    item.name(),
                    existing.tier().wire_name()
                ),
            ));
        }
        self.items.insert(item.name().to_owned(), item);
        Ok(())
    }

    /// Returns the declared public items in canonical name order.
    #[must_use]
    pub fn items(&self) -> &BTreeMap<String, StdItem> {
        &self.items
    }

    /// Returns one declared public item.
    #[must_use]
    pub fn item(&self, name: &str) -> Option<&StdItem> {
        self.items.get(&canonical_std_path(name))
    }
}

/// One declared non-package name of `GNT-34.2-name-classification`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdName {
    path: String,
    class: NameClass,
    owner: String,
}

impl StdName {
    /// Declares one module, facade, generated declaration, or implementation-only
    /// intrinsic; a package classification is refused here.
    pub fn new(path: &str, class: NameClass, owner: &str) -> Result<Self, StdlibError> {
        validate_std_name(path)?;
        if class == NameClass::Package {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{path}` declares the package classification inside a package"),
            ));
        }
        if owner.trim().is_empty() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{path}` declares no owning package"),
            ));
        }
        validate_std_name(owner)?;
        if path != owner
            && !path.starts_with(&format!("{owner}."))
            && !path.starts_with(&format!("{owner}::"))
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{path}` is not rooted under its owning package `{owner}`"),
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            class,
            owner: owner.to_owned(),
        })
    }

    /// Returns the declared path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the declared classification.
    #[must_use]
    pub const fn class(&self) -> NameClass {
        self.class
    }

    /// Returns the owning package.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

/// One enumerated edition-prelude member and the automatic source spellings it owns
/// (`GNT-34.4-edition-prelude-and-explicit-imports`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreludeBinding {
    member: &'static str,
    spellings: &'static [&'static str],
}

impl PreludeBinding {
    /// Returns the canonical member path this binding enumerates.
    #[must_use]
    pub fn member(&self) -> &'static str {
        self.member
    }

    /// Returns the automatic source spellings the member owns.
    #[must_use]
    pub fn spellings(&self) -> &'static [&'static str] {
        self.spellings
    }
}

/// The edition the canonical hierarchy declares (`GNT-34.4`).
pub const CANONICAL_PRELUDE_EDITION: &str = "2026";

/// The canonical edition's enumerated prelude members (`GNT-34.4`).
pub const CANONICAL_PRELUDE_MEMBERS: [&str; 2] = ["std.core::option", "std.core::result"];

/// The closed correspondence between enumerated edition-prelude members and the automatic
/// source names they make available (`GNT-34.4`). A member outside this correspondence
/// enumerates no source name, so declaring such a member is refused; the compiler-owned type
/// words that are not prelude members stay compiler-owned.
pub const PRELUDE_BINDINGS: [PreludeBinding; 2] = [
    PreludeBinding {
        member: "std.core.option",
        spellings: &["Option", "Some", "None"],
    },
    PreludeBinding {
        member: "std.core.result",
        spellings: &["Result", "Ok", "Err"],
    },
];

/// One closed edition prelude of `GNT-34.4-edition-prelude-and-explicit-imports`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prelude {
    edition: String,
    members: BTreeSet<String>,
}

impl Prelude {
    /// Declares one edition-versioned enumerated prelude; a wildcard member and an
    /// undeclared edition are refused.
    pub fn new(edition: &str, members: &[&str]) -> Result<Self, StdlibError> {
        if edition.trim().is_empty()
            || edition.len() > MAX_STD_NAME_BYTES
            || !edition.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
            })
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnenumeratedPreludeMember,
                format!("`{edition}` is not a declared prelude edition"),
            ));
        }
        let mut declared = BTreeSet::new();
        for member in members {
            if member.contains('*') {
                return Err(StdlibError::new(
                    StdlibDiagnosticCode::WildcardPreludeRefused,
                    format!("`{member}` is a wildcard prelude member"),
                ));
            }
            validate_std_name(member)?;
            let canonical = canonical_std_path(member);
            if !PRELUDE_BINDINGS
                .iter()
                .any(|binding| binding.member == canonical.as_str())
            {
                return Err(StdlibError::new(
                    StdlibDiagnosticCode::UnenumeratedPreludeMember,
                    format!("`{member}` enumerates no automatic source name"),
                ));
            }
            declared.insert(canonical);
        }
        Ok(Self {
            edition: edition.to_owned(),
            members: declared,
        })
    }

    /// Returns the canonical edition's declared prelude (`GNT-34.4`); this is the prelude
    /// `canonical_pure_hierarchy` declares.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            edition: CANONICAL_PRELUDE_EDITION.to_owned(),
            members: CANONICAL_PRELUDE_MEMBERS
                .iter()
                .map(|member| canonical_std_path(member))
                .collect(),
        }
    }

    /// Returns every automatic source spelling this prelude makes available (`GNT-34.4`): the
    /// union of the declared spellings of its enumerated members. Declaring a member outside
    /// the closed correspondence is refused, so this set is total.
    #[must_use]
    pub fn automatic_spellings(&self) -> BTreeSet<&'static str> {
        PRELUDE_BINDINGS
            .iter()
            .filter(|binding| self.members.contains(binding.member))
            .flat_map(|binding| binding.spellings.iter().copied())
            .collect()
    }

    /// Returns the declared edition.
    #[must_use]
    pub fn edition(&self) -> &str {
        &self.edition
    }

    /// Returns one declared edition prelude; presenting a different member set under an
    /// already declared edition is refused rather than admitted as a silent extension.
    pub fn for_edition(&self, edition: &str, members: &[&str]) -> Result<Self, StdlibError> {
        let declared = Self::new(edition, members)?;
        if declared.edition == self.edition && declared.members != self.members {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnenumeratedPreludeMember,
                format!(
                    "edition `{edition}` admits another member set only through an explicit edition change"
                ),
            ));
        }
        Ok(declared)
    }

    /// Returns the enumerated members.
    #[must_use]
    pub fn members(&self) -> &BTreeSet<String> {
        &self.members
    }

    /// Admits one automatic name; a name outside the enumeration is refused.
    pub fn admit(&self, path: &str) -> Result<(), StdlibError> {
        if !self.members.contains(&canonical_std_path(path)) {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnenumeratedPreludeMember,
                format!("`{path}` is not an enumerated prelude member"),
            ));
        }
        Ok(())
    }
}

/// How one presented path names a standard-library identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdPresentation {
    /// The presentation names a declared package itself.
    Defining,
    /// The presentation names a declared convenience facade re-export.
    Facade,
}

impl StdPresentation {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Defining => "defining",
            Self::Facade => "facade",
        }
    }
}

/// The declared identity one presented path carries, as tooling reports it.
///
/// A facade presentation never erases the defining package: `defining_identity` always names the
/// defining side, so a tool can show the convenience path and the defining identity side by side,
/// and physical repository layout is never reported as an identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdPathInspection {
    presented: String,
    presentation: StdPresentation,
    defining_package: String,
    facade_item: Option<String>,
}

impl StdPathInspection {
    /// Returns the presentation that was inspected.
    #[must_use]
    pub fn presented(&self) -> &str {
        &self.presented
    }

    /// Returns how the presentation names its identity.
    #[must_use]
    pub const fn presentation(&self) -> StdPresentation {
        self.presentation
    }

    /// Returns the defining package identity, never a facade path.
    #[must_use]
    pub fn defining_package(&self) -> &str {
        &self.defining_package
    }

    /// Returns the re-exported item a facade presentation names, if it names one.
    #[must_use]
    pub fn facade_item(&self) -> Option<&str> {
        self.facade_item.as_deref()
    }

    /// Returns the preserved defining identity of the presentation.
    #[must_use]
    pub fn defining_identity(&self) -> String {
        match &self.facade_item {
            Some(item) => format!("{}#{item}", self.defining_package),
            None => self.defining_package.clone(),
        }
    }
}

/// Inspects one presented path against the declared hierarchy.
///
/// A presentation may be a declared package name (`std.core`) or a declared convenience facade
/// path (`std.io::option`); `::` and `.` are the same separator, as everywhere else in this
/// module. A facade presentation is reported with the defining package and re-exported item it
/// carries and is never reported as an identity of its own, and its defining side must be declared
/// and exported by the graph. Physical repository layout — a presentation containing a path
/// separator or ending in `.rs` — is refused rather than reinterpreted as an identity, because
/// layout is nonsemantic; an empty presentation and a presentation that names nothing declared are
/// refused too.
pub fn inspect_presentation(
    graph: &StdGraph,
    facades: &[FacadeReexport],
    presented: &str,
) -> Result<StdPathInspection, StdlibError> {
    let named = presented.trim();
    if named.is_empty() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidPackageName,
            "an empty presentation names no standard identity",
        ));
    }
    if named.contains('/') || named.contains('\\') || named.ends_with(".rs") {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::LayoutDerivedIdentity,
            format!("`{presented}` names physical repository layout, not a standard identity"),
        ));
    }
    let canonical = canonical_std_path(named);
    if let Some(facade) = facades
        .iter()
        .find(|facade| canonical_std_path(facade.path()) == canonical)
    {
        facade.admit(graph, &facade.defining_identity())?;
        return Ok(StdPathInspection {
            presented: named.to_owned(),
            presentation: StdPresentation::Facade,
            defining_package: facade.defining_package().to_owned(),
            facade_item: Some(facade.item().to_owned()),
        });
    }
    if graph.package(&canonical).is_some() {
        return Ok(StdPathInspection {
            presented: named.to_owned(),
            presentation: StdPresentation::Defining,
            defining_package: canonical,
            facade_item: None,
        });
    }
    Err(StdlibError::new(
        StdlibDiagnosticCode::UnknownEdge,
        format!("`{presented}` names no declared standard package or facade"),
    ))
}

/// One declared facade re-export of `GNT-34.5-facade-and-reexport-identity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FacadeReexport {
    path: String,
    defining_package: String,
    item: String,
}

impl FacadeReexport {
    /// Declares one facade re-export over a defining package and item.
    pub fn new(path: &str, defining_package: &str, item: &str) -> Result<Self, StdlibError> {
        validate_std_name(path)?;
        validate_std_name(defining_package)?;
        validate_std_name(item)?;
        Ok(Self {
            path: path.to_owned(),
            defining_package: defining_package.to_owned(),
            item: item.to_owned(),
        })
    }

    /// Returns the declared facade path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the defining package.
    #[must_use]
    pub fn defining_package(&self) -> &str {
        &self.defining_package
    }

    /// Returns the re-exported item.
    #[must_use]
    pub fn item(&self) -> &str {
        &self.item
    }

    /// Returns the preserved defining identity of the re-exported item.
    #[must_use]
    pub fn defining_identity(&self) -> String {
        format!("{}#{}", self.defining_package, self.item)
    }

    /// Admits the re-export against one graph; a missing defining package, an
    /// unexported item, and a substituted identity are refused.
    pub fn admit(&self, graph: &StdGraph, presented_identity: &str) -> Result<(), StdlibError> {
        let Some(package) = graph.package(&self.defining_package) else {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!(
                    "`{}` names no declared standard package",
                    self.defining_package
                ),
            ));
        };
        if !package.exports_item(&self.item) {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::FacadeIdentityLoss,
                format!(
                    "`{}` does not export `{}`",
                    self.defining_package, self.item
                ),
            ));
        }
        if presented_identity != self.defining_identity() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::FacadeIdentityLoss,
                format!(
                    "the facade presents `{presented_identity}` instead of `{}`",
                    self.defining_identity()
                ),
            ));
        }
        Ok(())
    }
}

/// One declared stability-tier transition of `GNT-34.6-stability-tiers`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StabilityTransition {
    from: StabilityTier,
    to: StabilityTier,
}

impl StabilityTransition {
    /// Declares one transition; a no-op, backwards, or foundational transition is refused.
    pub fn new(from: StabilityTier, to: StabilityTier) -> Result<Self, StdlibError> {
        let allowed = matches!(
            (from, to),
            (StabilityTier::Experimental, StabilityTier::TargetSpecific)
                | (StabilityTier::Experimental, StabilityTier::Stable)
                | (StabilityTier::TargetSpecific, StabilityTier::Stable)
        );
        if !allowed {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidStabilityTransition,
                format!(
                    "`{}` to `{}` is not a permitted stability transition",
                    from.wire_name(),
                    to.wire_name()
                ),
            ));
        }
        Ok(Self { from, to })
    }

    /// Returns the superseded tier.
    #[must_use]
    pub const fn from(self) -> StabilityTier {
        self.from
    }

    /// Returns the target tier.
    #[must_use]
    pub const fn to(self) -> StabilityTier {
        self.to
    }
}

/// One declared relocation of `GNT-34.10-relocation-and-deprecation`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relocation {
    from: String,
    to: String,
    preserved_identity: String,
}

impl Relocation {
    /// Declares one relocation; a no-op move or a missing preserved identity is refused.
    pub fn new(from: &str, to: &str, preserved_identity: &str) -> Result<Self, StdlibError> {
        validate_std_name(from)?;
        validate_std_name(to)?;
        if from == to || preserved_identity.trim().is_empty() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!("`{from}` to `{to}` is not a declared relocation"),
            ));
        }
        Ok(Self {
            from: from.to_owned(),
            to: to.to_owned(),
            preserved_identity: preserved_identity.to_owned(),
        })
    }

    /// Returns the old path.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    /// Returns the new path.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// Returns the preserved defining identity.
    #[must_use]
    pub fn preserved_identity(&self) -> &str {
        &self.preserved_identity
    }

    /// Admits one relocated item identity; an identity change is refused.
    pub fn admit(&self, presented_identity: &str) -> Result<(), StdlibError> {
        if presented_identity != self.preserved_identity {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!(
                    "the relocation changes `{}` to `{presented_identity}`",
                    self.preserved_identity
                ),
            ));
        }
        Ok(())
    }
}

/// One declared deprecation of `GNT-34.10-relocation-and-deprecation`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdDeprecation {
    item: String,
    tier: StabilityTier,
    target: StabilityTier,
    replacement: Option<String>,
}

impl StdDeprecation {
    /// Declares one deprecation of an item from its declared tier to a narrower tier;
    /// a widening or unchanged target tier is refused.
    pub fn new(
        item: &str,
        tier: StabilityTier,
        target: StabilityTier,
        replacement: Option<&str>,
    ) -> Result<Self, StdlibError> {
        validate_std_name(item)?;
        if tier == StabilityTier::Foundational {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!("the deprecation of `{item}` would leave the foundational tier"),
            ));
        }
        if target.rank() >= tier.rank() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!(
                    "the deprecation of `{item}` does not narrow `{}`",
                    tier.wire_name()
                ),
            ));
        }
        if let Some(replacement) = replacement {
            validate_std_name(replacement)?;
        }
        Ok(Self {
            item: item.to_owned(),
            tier,
            target,
            replacement: replacement.map(str::to_owned),
        })
    }

    /// Returns the deprecated item.
    #[must_use]
    pub fn item(&self) -> &str {
        &self.item
    }

    /// Returns the tier the item is deprecated from.
    #[must_use]
    pub const fn tier(&self) -> StabilityTier {
        self.tier
    }

    /// Returns the tier the item moves to.
    #[must_use]
    pub const fn target_tier(&self) -> StabilityTier {
        self.target
    }

    /// Returns the declared replacement, when one is named.
    #[must_use]
    pub fn replacement(&self) -> Option<&str> {
        self.replacement.as_deref()
    }

    /// Admits the deprecation against its declaring package; an item without a declared
    /// tier, a contradicting from-tier, and an undeclared replacement are refused.
    pub fn admit(&self, package: &StdPackage) -> Result<(), StdlibError> {
        if package.item(&self.item).is_none() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!(
                    "the deprecation of `{}` names an item without a declared tier",
                    self.item
                ),
            ));
        }
        if let Some(item) = package.item(&self.item)
            && item.tier() != self.tier
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!(
                    "the deprecation of `{}` states the tier `{}` while the item declares `{}`",
                    self.item,
                    self.tier.wire_name(),
                    item.tier().wire_name()
                ),
            ));
        }
        if let Some(replacement) = &self.replacement
            && package.item(replacement).is_none()
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidRelocation,
                format!(
                    "the deprecation of `{}` names the undeclared replacement `{replacement}`",
                    self.item
                ),
            ));
        }
        Ok(())
    }
}

/// One already selected package instance of `GNT-34.7-applicability-and-feature-granularity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedInstance {
    name: String,
    interface: StdInterfaceIdentity,
    requirements: BTreeSet<String>,
}

impl SelectedInstance {
    /// Declares one selected instance from its declared facts.
    pub fn new(
        name: &str,
        interface: StdInterfaceIdentity,
        requirements: &[&str],
    ) -> Result<Self, StdlibError> {
        validate_std_name(name)?;
        Ok(Self {
            name: name.to_owned(),
            interface,
            requirements: requirements
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        })
    }

    /// Derives one selected instance from its declared package.
    #[must_use]
    pub fn from_package(package: &StdPackage) -> Self {
        Self {
            name: package.name().to_owned(),
            interface: package.identity(),
            requirements: package.dependencies().clone(),
        }
    }

    /// Returns the selected package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the selected interface identity.
    #[must_use]
    pub fn interface(&self) -> &StdInterfaceIdentity {
        &self.interface
    }

    /// Returns the selected package requirements.
    #[must_use]
    pub fn requirements(&self) -> &BTreeSet<String> {
        &self.requirements
    }
}

/// One declared feature selection of `GNT-34.7-applicability-and-feature-granularity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureSelection {
    feature: String,
    packages: BTreeSet<String>,
}

impl FeatureSelection {
    /// Declares one feature and the exact package set it enables.
    pub fn new(feature: &str, packages: &[&str]) -> Result<Self, StdlibError> {
        if feature.trim().is_empty() || feature.len() > MAX_STD_NAME_BYTES {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidPackageName,
                "a feature name must be nonempty and bounded",
            ));
        }
        let mut selected = BTreeSet::new();
        for package in packages {
            validate_std_name(package)?;
            selected.insert((*package).to_owned());
        }
        Ok(Self {
            feature: feature.to_owned(),
            packages: selected,
        })
    }

    /// Returns the declared feature name.
    #[must_use]
    pub fn feature(&self) -> &str {
        &self.feature
    }

    /// Returns the exact package set the feature enables.
    #[must_use]
    pub fn packages(&self) -> &BTreeSet<String> {
        &self.packages
    }

    /// Applies this selection against the declared graph and the already selected
    /// instances; an undeclared package, and a selection that would change an existing
    /// instance's identity or requirements, are refused.
    pub fn apply(
        &self,
        graph: &StdGraph,
        selected: &BTreeMap<String, SelectedInstance>,
    ) -> Result<BTreeMap<String, SelectedInstance>, StdlibError> {
        let mut declared = Vec::new();
        for name in &self.packages {
            let Some(package) = graph.package(name) else {
                return Err(StdlibError::new(
                    StdlibDiagnosticCode::UnknownEdge,
                    format!(
                        "the feature `{}` enables the undeclared package `{name}`",
                        self.feature
                    ),
                ));
            };
            if let Some(instance) = selected.get(name)
                && (instance.interface() != &package.identity()
                    || instance.requirements() != package.dependencies())
            {
                return Err(StdlibError::new(
                    StdlibDiagnosticCode::FeatureMutatesInstance,
                    format!(
                        "the feature `{}` would change the selected instance `{name}`",
                        self.feature
                    ),
                ));
            }
            declared.push(package);
        }
        let mut applied = selected.clone();
        for package in declared {
            applied
                .entry(package.name().to_owned())
                .or_insert_with(|| SelectedInstance::from_package(package));
        }
        Ok(applied)
    }
}

/// Requires one package's declared applicability for one mode and target.
pub fn require_applicable(
    package: &StdPackage,
    mode: SemanticMode,
    target: TargetKind,
) -> Result<(), StdlibError> {
    if !package.modes().contains(&mode) || !package.targets().contains(&target) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::UnsupportedApplicability,
            format!(
                "`{}` is not available for mode `{}` on target `{}`",
                package.name(),
                mode.wire_name(),
                target.wire_name()
            ),
        ));
    }
    Ok(())
}

/// Refuses any identity fact that names a physical repository path or file. A fact is
/// path-shaped when it carries a path separator and a lowercase layout segment
/// (`src`, `target`, `crates`, `tests`, `benches`, `examples`), or when it names a file.
pub fn check_layout_identity(facts: &[&str]) -> Result<(), StdlibError> {
    for fact in facts {
        let path_like = fact.contains('/') || fact.contains('\\');
        let layout_segment = fact.split(['/', '\\']).any(|segment| {
            matches!(
                segment.to_ascii_lowercase().as_str(),
                "src" | "target" | "crates" | "tests" | "benches" | "examples"
            )
        });
        let file_like = fact.ends_with(".rs") || fact.ends_with(".toml");
        if fact.is_empty() || (path_like && layout_segment) || file_like {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::LayoutDerivedIdentity,
                format!("`{fact}` is a physical layout fact, not a declared identity fact"),
            ));
        }
    }
    Ok(())
}

/// One versioned standard-library contract of `GNT-34.9-standard-library-contract-versioning`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdContractVersion {
    major: u32,
    minor: u32,
}

impl StdContractVersion {
    /// Declares one contract version; a zero major version is refused.
    pub fn new(major: u32, minor: u32) -> Result<Self, StdlibError> {
        if major == 0 {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::ContractVersionMismatch,
                "a standard-library contract version needs a nonzero major version",
            ));
        }
        Ok(Self { major, minor })
    }

    /// Returns the major version.
    #[must_use]
    pub const fn major(self) -> u32 {
        self.major
    }

    /// Returns the minor version.
    #[must_use]
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// Refuses a presented contract version that differs from the published one.
    pub fn admit_consumer(&self, presented: Self) -> Result<(), StdlibError> {
        if presented != *self {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::ContractVersionMismatch,
                format!(
                    "presented contract {}.{} differs from the published {}.{}",
                    presented.major, presented.minor, self.major, self.minor
                ),
            ));
        }
        Ok(())
    }
}

/// One aggregate manifest entry of `GNT-34.11-aggregate-manifests-and-publication-inputs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdManifestEntry {
    name: String,
    class: NameClass,
    tier: StabilityTier,
    modes: BTreeSet<SemanticMode>,
    targets: BTreeSet<TargetKind>,
    dependencies: BTreeSet<String>,
    identity: StdInterfaceIdentity,
}

impl StdManifestEntry {
    /// Returns the recorded applicability modes.
    #[must_use]
    pub fn modes(&self) -> &BTreeSet<SemanticMode> {
        &self.modes
    }

    /// Returns the recorded applicability targets.
    #[must_use]
    pub fn targets(&self) -> &BTreeSet<TargetKind> {
        &self.targets
    }

    /// Returns the recorded dependencies.
    #[must_use]
    pub fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }
}

impl StdManifestEntry {
    /// Returns the recorded package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the recorded classification.
    #[must_use]
    pub const fn class(&self) -> NameClass {
        self.class
    }

    /// Returns the recorded stability tier.
    #[must_use]
    pub const fn tier(&self) -> StabilityTier {
        self.tier
    }

    /// Returns the recorded interface identity.
    #[must_use]
    pub const fn identity(&self) -> &StdInterfaceIdentity {
        &self.identity
    }
}

/// One aggregate standard-library manifest of `GNT-34.11-aggregate-manifests-and-publication-inputs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdManifest {
    contract: StdContractVersion,
    entries: Vec<StdManifestEntry>,
    prelude_edition: String,
    identity: StdGraphIdentity,
}

impl StdManifest {
    /// Returns the published contract version.
    #[must_use]
    pub const fn contract(&self) -> StdContractVersion {
        self.contract
    }

    /// Returns the manifest entries in canonical name order.
    #[must_use]
    pub fn entries(&self) -> &[StdManifestEntry] {
        &self.entries
    }

    /// Returns the aggregate graph identity.
    #[must_use]
    pub const fn identity(&self) -> &StdGraphIdentity {
        &self.identity
    }

    /// Returns the prelude edition the manifest was built under.
    #[must_use]
    pub fn prelude_edition(&self) -> &str {
        &self.prelude_edition
    }

    /// Refuses a manifest that omits a declared package or records another identity.
    pub fn verify_against(&self, graph: &StdGraph) -> Result<(), StdlibError> {
        let recomputed = graph.manifest(self.contract)?;
        if self.entries != recomputed.entries || self.identity != recomputed.identity {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::PublicationDrift,
                "the aggregate manifest is stale against the declared hierarchy",
            ));
        }
        Ok(())
    }

    /// Admits one consumer over the published contract; a presented contract version,
    /// graph identity, or package interface digest that differs from the published one
    /// is refused rather than repaired.
    pub fn admit_consumer(
        &self,
        version: StdContractVersion,
        graph_identity: &str,
        interfaces: &BTreeMap<String, String>,
    ) -> Result<(), StdlibError> {
        let refuse = |detail: String| {
            Err(StdlibError::new(
                StdlibDiagnosticCode::ContractVersionMismatch,
                detail,
            ))
        };
        self.contract.admit_consumer(version)?;
        if graph_identity != self.identity.as_str() {
            return refuse(
                "the presented graph identity differs from the published one".to_owned(),
            );
        }
        for entry in &self.entries {
            match interfaces.get(entry.name()) {
                Some(interface) if interface == entry.identity().as_str() => {}
                Some(_) => {
                    return refuse(format!(
                        "the presented interface digest for `{}` differs from the published one",
                        entry.name()
                    ));
                }
                None => {
                    return refuse(format!(
                        "the consumer presents no interface digest for `{}`",
                        entry.name()
                    ));
                }
            }
        }
        if interfaces.len() != self.entries.len() {
            return refuse(
                "the consumer presents interface digests for undeclared packages".to_owned(),
            );
        }
        Ok(())
    }
}

/// Declares the canonical pure standard-library hierarchy of
/// `GNT-34.1-canonical-hierarchy-and-package-names`: the root `std.core` and the six pure families
/// that build on it, with the dependency direction frozen by the reviewed roadmap
/// (`std.collections` and `std.num` depend only on `std.core`; `std.text` may add `std.collections`;
/// `std.codec` may add core, collections, and text; `std.crypto` may add core, num, and codec;
/// `std.data` may add core, collections, text, and codec).
///
/// The declaration carries package identities, applicability, and edges only. `GNT-34.6` and
/// `GNT-34.8` give every public item its own tier and defining identity, so an item belongs to the
/// family that owns its API surface (`GNT-GP-COLL-001` for `std.collections`) rather than to this
/// constructor. The one exception is the enumerated edition prelude of `GNT-34.4`: its members are
/// foundational items of `std.core`, so they are declared here because that clause fixes the exact
/// set.
pub fn canonical_pure_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = StdGraph::new(Prelude::canonical());
    let core = PackageFamily::Core.package_name();
    let collections = PackageFamily::Collections.package_name();
    let text = PackageFamily::Text.package_name();
    let num = PackageFamily::Num.package_name();
    let codec = PackageFamily::Codec.package_name();
    for (family, tier, dependencies) in [
        (PackageFamily::Core, StabilityTier::Foundational, Vec::new()),
        (
            PackageFamily::Collections,
            StabilityTier::Stable,
            vec![core.clone()],
        ),
        (
            PackageFamily::Text,
            StabilityTier::Stable,
            vec![core.clone(), collections.clone()],
        ),
        (
            PackageFamily::Num,
            StabilityTier::Stable,
            vec![core.clone()],
        ),
        (
            PackageFamily::Codec,
            StabilityTier::Stable,
            vec![core.clone(), collections.clone(), text.clone()],
        ),
        (
            PackageFamily::Crypto,
            StabilityTier::Stable,
            vec![core.clone(), num.clone(), codec.clone()],
        ),
        (
            PackageFamily::Data,
            StabilityTier::Stable,
            vec![
                core.clone(),
                collections.clone(),
                text.clone(),
                codec.clone(),
            ],
        ),
    ] {
        let declared: Vec<&str> = dependencies.iter().map(String::as_str).collect();
        graph.declare(StdPackage::new(
            family,
            NameClass::Package,
            tier,
            &[SemanticMode::Portable, SemanticMode::Application],
            &[TargetKind::Library, TargetKind::Binary],
            &declared,
            &[],
        )?)?;
    }
    let core_package = graph
        .package(&core)
        .ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::InvalidPackageName,
                "`std.core` is not declared before its prelude items".to_owned(),
            )
        })?
        .clone();
    let modes = core_package.modes().iter().copied().collect::<Vec<_>>();
    let targets = core_package.targets().iter().copied().collect::<Vec<_>>();
    for member in CANONICAL_PRELUDE_MEMBERS {
        graph.declare_item(StdItem::new(
            member,
            NameClass::Module,
            StabilityTier::Foundational,
            &modes,
            &targets,
        )?)?;
    }
    Ok(graph)
}

/// One declared standard-library package graph of `GNT-34.3`-`GNT-34.11`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdGraph {
    packages: BTreeMap<String, StdPackage>,
    names: Vec<StdName>,
    prelude: Prelude,
}

impl StdGraph {
    /// Creates one graph over its declared edition prelude.
    #[must_use]
    pub fn new(prelude: Prelude) -> Self {
        Self {
            packages: BTreeMap::new(),
            names: Vec::new(),
            prelude,
        }
    }

    /// Returns the declared prelude.
    #[must_use]
    pub const fn prelude(&self) -> &Prelude {
        &self.prelude
    }

    /// Declares one package; a duplicate name and an over-large graph are refused.
    pub fn declare(&mut self, package: StdPackage) -> Result<(), StdlibError> {
        if self.packages.len() >= MAX_STD_PACKAGES {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::DuplicatePackage,
                "the declared hierarchy exceeds the package bound",
            ));
        }
        let name = package.name().to_owned();
        if self.packages.contains_key(&name) {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::DuplicatePackage,
                format!("`{name}` is declared twice"),
            ));
        }
        self.packages.insert(name, package);
        Ok(())
    }

    /// Declares one non-package name; a duplicate path is refused.
    pub fn declare_name(&mut self, name: StdName) -> Result<(), StdlibError> {
        if self
            .names
            .iter()
            .any(|existing| canonical_std_path(existing.path()) == canonical_std_path(name.path()))
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::DuplicatePackage,
                format!("`{}` is declared twice", name.path()),
            ));
        }
        if !self.packages.contains_key(name.owner()) {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{}` names no declared owning package", name.owner()),
            ));
        }
        if self
            .packages
            .values()
            .any(|package| package.item(name.path()).is_some())
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` already carries one classification", name.path()),
            ));
        }
        self.names.push(name);
        Ok(())
    }

    /// Declares one public item inside its owning package; an undeclared owner and a
    /// second tier for one item are refused.
    pub fn declare_item(&mut self, item: StdItem) -> Result<(), StdlibError> {
        if self
            .names
            .iter()
            .any(|existing| canonical_std_path(existing.path()) == item.name())
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` already carries one classification", item.name()),
            ));
        }
        let owner = item.owner().to_owned();
        let Some(package) = self.packages.get_mut(&owner) else {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!(
                    "`{}` is declared inside the undeclared package `{owner}`",
                    item.name()
                ),
            ));
        };
        package.declare_item(item)
    }

    /// Returns one declared package.
    #[must_use]
    pub fn package(&self, name: &str) -> Option<&StdPackage> {
        self.packages.get(name)
    }

    /// Returns every declared package name in canonical order.
    #[must_use]
    pub fn package_names(&self) -> Vec<&str> {
        self.packages.keys().map(String::as_str).collect()
    }

    /// Returns every declared non-package name.
    #[must_use]
    pub fn names(&self) -> &[StdName] {
        &self.names
    }

    /// Validates every declared edge: unknown targets, host adapters, pure-to-capability
    /// edges, and cycles are refused.
    pub fn validate(&self) -> Result<(), StdlibError> {
        for package in self.packages.values() {
            for dependency in package.dependencies() {
                let lowered = dependency.to_ascii_lowercase();
                if dependency == "std" || lowered.starts_with("std.") {
                    validate_std_name(dependency)?;
                } else {
                    return Err(StdlibError::new(
                        StdlibDiagnosticCode::PackageToAdapterEdge,
                        format!(
                            "`{}` depends on the host adapter `{dependency}`",
                            package.name()
                        ),
                    ));
                }
                let Some(target) = self.packages.get(dependency) else {
                    return Err(StdlibError::new(
                        StdlibDiagnosticCode::UnknownEdge,
                        format!(
                            "`{}` depends on the undeclared `{dependency}`",
                            package.name()
                        ),
                    ));
                };
                if package.family().is_pure() && !target.family().is_pure() {
                    return Err(StdlibError::new(
                        StdlibDiagnosticCode::PureToCapabilityEdge,
                        format!(
                            "the pure package `{}` depends on the capability package `{dependency}`",
                            package.name()
                        ),
                    ));
                }
            }
        }
        // The topological order refuses any cycle, naming one member that lies on it.
        self.topological_order().map(|_| ())
    }

    /// Returns one deterministic topological order over the declared packages.
    pub fn topological_order(&self) -> Result<Vec<String>, StdlibError> {
        let mut emitted: BTreeSet<String> = BTreeSet::new();
        let mut order: Vec<String> = Vec::with_capacity(self.packages.len());
        loop {
            let ready = self
                .packages
                .iter()
                .filter(|(name, _)| !emitted.contains(*name))
                .find(|(_, package)| {
                    package.dependencies().iter().all(|dependency| {
                        !self.packages.contains_key(dependency) || emitted.contains(dependency)
                    })
                })
                .map(|(name, _)| name.clone());
            match ready {
                Some(name) => {
                    emitted.insert(name.clone());
                    order.push(name);
                }
                None => break,
            }
        }
        if order.len() != self.packages.len() {
            let remaining: BTreeSet<String> = self
                .packages
                .keys()
                .filter(|name| !emitted.contains(*name))
                .cloned()
                .collect();
            let member = remaining
                .iter()
                .find(|name| self.reaches_itself(name, &remaining))
                .cloned()
                .unwrap_or_else(|| remaining.iter().next().cloned().unwrap_or_default());
            return Err(StdlibError::new(
                StdlibDiagnosticCode::DependencyCycle,
                format!("the dependency cycle includes `{member}`"),
            ));
        }
        Ok(order)
    }

    /// Returns whether one package reaches itself through unemitted dependencies.
    fn reaches_itself(&self, start: &str, pending: &BTreeSet<String>) -> bool {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<String> = vec![start.to_owned()];
        while let Some(node) = stack.pop() {
            let Some(package) = self.packages.get(&node) else {
                continue;
            };
            for dependency in package.dependencies() {
                if !pending.contains(dependency) {
                    continue;
                }
                if dependency == start {
                    return true;
                }
                if seen.insert(dependency.clone()) {
                    stack.push(dependency.clone());
                }
            }
        }
        false
    }

    /// Returns the aggregate manifest over every declared package.
    pub fn manifest(&self, contract: StdContractVersion) -> Result<StdManifest, StdlibError> {
        self.validate()?;
        let entries = self
            .packages
            .values()
            .map(|package| StdManifestEntry {
                name: package.name().to_owned(),
                class: package.class(),
                tier: package.tier(),
                modes: package.modes().clone(),
                targets: package.targets().clone(),
                dependencies: package.dependencies().clone(),
                identity: package.identity(),
            })
            .collect::<Vec<StdManifestEntry>>();
        let mut fields: Vec<Vec<u8>> =
            vec![format!("{}.{}", contract.major(), contract.minor()).into_bytes()];
        fields.push(self.prelude.edition().as_bytes().to_vec());
        for entry in &entries {
            fields.push(entry.name().as_bytes().to_vec());
            fields.push(entry.class().wire_name().as_bytes().to_vec());
            fields.push(entry.tier().wire_name().as_bytes().to_vec());
            fields.push(entry.identity().as_str().as_bytes().to_vec());
        }
        for member in self.prelude.members() {
            fields.push(member.as_bytes().to_vec());
        }
        for entry in &entries {
            for mode in &entry.modes {
                fields.push(mode.wire_name().as_bytes().to_vec());
            }
            for target in &entry.targets {
                fields.push(target.wire_name().as_bytes().to_vec());
            }
            for dependency in &entry.dependencies {
                fields.push(dependency.as_bytes().to_vec());
            }
        }
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
        Ok(StdManifest {
            contract,
            entries,
            prelude_edition: self.prelude.edition().to_owned(),
            identity: StdGraphIdentity(Arc::from(encode_hex(&digest_fields(
                "gantry.std.graph.v1",
                &borrowed,
            )))),
        })
    }
}

/// The closed standard-library architecture non-claim vocabulary of `GNT-34.12`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StdlibNonClaim {
    /// Whether any adapter exists.
    AdapterPresence,
    /// Whether any capability or provider exists.
    CapabilityAndProviderExistence,
    /// Documentation rendering.
    DocumentationRendering,
    /// Durable execution.
    DurableExecution,
    /// Family behavior.
    FamilyBehavior,
    /// A permanently frozen prelude.
    FrozenPreludeForever,
    /// Host behavior.
    HostBehavior,
    /// Repository layout as identity.
    LayoutAsIdentity,
    /// Package acquisition and registry trust.
    PackageAcquisitionAndRegistryTrust,
    /// Parser, formatter, linker, or tooling behavior.
    ParserFormatterLinkerTooling,
    /// Performance and cost.
    PerformanceAndCost,
    /// Release policy.
    ReleasePolicy,
}

impl StdlibNonClaim {
    /// Every non-claim in exact wire-name order.
    pub const ALL: [Self; 12] = [
        Self::AdapterPresence,
        Self::CapabilityAndProviderExistence,
        Self::DocumentationRendering,
        Self::DurableExecution,
        Self::FamilyBehavior,
        Self::FrozenPreludeForever,
        Self::HostBehavior,
        Self::LayoutAsIdentity,
        Self::PackageAcquisitionAndRegistryTrust,
        Self::ParserFormatterLinkerTooling,
        Self::PerformanceAndCost,
        Self::ReleasePolicy,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AdapterPresence => "adapter-presence",
            Self::CapabilityAndProviderExistence => "capability-and-provider-existence",
            Self::DocumentationRendering => "documentation-rendering",
            Self::DurableExecution => "durable-execution",
            Self::FamilyBehavior => "family-behavior",
            Self::FrozenPreludeForever => "frozen-prelude-forever",
            Self::HostBehavior => "host-behavior",
            Self::LayoutAsIdentity => "layout-as-identity",
            Self::PackageAcquisitionAndRegistryTrust => "package-acquisition-and-registry-trust",
            Self::ParserFormatterLinkerTooling => "parser-formatter-linker-tooling",
            Self::PerformanceAndCost => "performance-and-cost",
            Self::ReleasePolicy => "release-policy",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|claim| claim.wire_name() == value)
    }
}

/// The declared standard-library architecture non-claims of `GNT-34.12`.
pub const STDLIB_NON_CLAIMS: [&str; 12] = [
    "No adapter presence: the model declares packages and claims nothing about the existence of any adapter.",
    "No capability or provider existence: declaration of a capability package promises no implementation.",
    "No documentation rendering: documentation generation and publication are downstream owners.",
    "No durable execution: durability contracts remain owned by other sections.",
    "No family behavior: this section declares architecture and implements none of the families it names.",
    "No permanently frozen prelude: the prelude is closed per edition and may change with an edition transition.",
    "No host behavior: nothing about host services, adapters, or platform behavior is promised.",
    "No layout as identity: repository layout, crate names, and file paths are never source identity.",
    "No package acquisition or registry trust: acquisition, resolution, and trust are owned by other issues.",
    "No parser, formatter, linker, or tooling behavior: this section defines architecture only.",
    "No performance or cost promise: semantic cost and performance remain owned by other sections.",
    "No release policy: publication, qualification, and claims are owned by release issues.",
];

/// The declared order of the standard-library non-claims (`GNT-34.12`).
pub const STDLIB_NON_CLAIM_ORDER: [StdlibNonClaim; 12] = StdlibNonClaim::ALL;

/// One presented non-claim assertion (`GNT-34.12`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdlibNonClaimAssertion {
    claim: StdlibNonClaim,
    presented_as_guarantee: bool,
}

impl StdlibNonClaimAssertion {
    /// Records whether one non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: StdlibNonClaim, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(self) -> StdlibNonClaim {
        self.claim
    }

    /// Returns whether the non-claim was presented as a guarantee.
    #[must_use]
    pub const fn presented_as_guarantee(self) -> bool {
        self.presented_as_guarantee
    }
}

/// Refuses any standard-library non-claim presented as a guarantee.
pub fn check_stdlib_non_claims(assertions: &[StdlibNonClaimAssertion]) -> Result<(), StdlibError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee() {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::NonClaimAsGuarantee,
                format!(
                    "the non-claim `{}` was presented as a guarantee",
                    assertion.claim().wire_name()
                ),
            ));
        }
    }
    Ok(())
}
