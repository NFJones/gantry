//! Pure package, manifest, and public-interface identity model.
//!
//! This module is the machine-checked identity, alias, visibility, re-export,
//! target-kind, interface, compatibility-axis, and resolution-order model for
//! `GNT-16.0` through `GNT-16.9-resolution-order-independence`, refining the
//! landed `GNT-11.6-package-source-manifest` and
//! `GNT-11.6-compatibility-classes` relations.
//!
//! Scope is deliberately narrow: this module decides identity, resolution, and
//! comparison over explicitly supplied inputs. It never reads a host path, a
//! registry, or a discovery response, never loads or runs package source, and
//! holds no package-wide state that is created by linking a package. Every rule
//! it states is reproducible from its own arguments, which is what
//! `GNT-16.9-resolution-order-independence` requires of resolution: the same
//! unordered manifests and sources produce the same instances, identities,
//! interface digests, and diagnostics under every permutation.
//!
//! The three identity layers stay distinct here: the package-source identity of
//! `GNT-11.6-package-source-manifest` is [`PackageSourceIdentity`] and retains
//! both labeled digests, the canonical package identity of
//! `GNT-16.1-package-identity` is [`PackageIdentity`], and the resolved package
//! instance of `GNT-16.2-package-instances` is [`PackageInstance`], whose
//! identity *is* its package identity.
//!
//! Canonical identity text is explicit and stable; Rust `Debug` and `Display`
//! renderings are presentation only and are never protocol identities.

// The diagnostic variants deliberately carry full package identities so a
// rejected manifest, alias, interface, or instance reports the exact identity
// it disagreed with. Boxing those fields would hide identity behind an
// allocation at every construction and match site, so this module answers the
// size lint explicitly instead of weakening its own diagnostics.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use gantry_core::protocol::ProtocolVersion;
use gantry_core::unicode::{is_nfc, is_xid_continue, is_xid_start, to_full_lowercase};

use crate::authority::digest_fields;
use crate::generated::RecoveryClass;
use crate::manifest::encode_hex;
use crate::target::TargetFactsRecord;
use crate::{CanonicalPath, CanonicalSignature, EffectSet};

/// Domain separator for canonical package-identity derivation.
const IDENTITY_DOMAIN: &str = "gantry.package-identity/v1";

/// Domain separator for canonical public-interface digests.
const INTERFACE_DOMAIN: &str = "gantry.public-interface/v1";

/// Domain separator for canonical alias maps.
const ALIAS_MAP_DOMAIN: &str = "gantry.package-alias-map/v1";

/// One frozen published diagnostic identity of this model.
///
/// The codes are frozen: a consumer matches on [`Self::as_str`], and the
/// meanings are the ones registered for the package category. The variant order
/// is the sorted code order, so [`Self::ALL`] is already in the order the
/// registry requires.
///
/// A condition this module can decide but that has no published code is a typed
/// [`PackageError`] variant whose [`PackageError::code`] is `None`; such a
/// condition MUST NOT be reported under another condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PackageDiagnosticCode {
    /// `package-alias-collision`
    AliasCollision,
    /// `package-alias-unresolved`
    AliasUnresolved,
    /// `package-instance-interface-mismatch`
    InstanceInterfaceMismatch,
    /// `package-item-not-exported`
    ItemNotExported,
    /// `package-reexport-cycle`
    ReexportCycle,
    /// `package-target-kind-invalid`
    TargetKindInvalid,
    /// `package-transitive-undeclared`
    TransitiveUndeclared,
}

impl PackageDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 7] = [
        Self::AliasCollision,
        Self::AliasUnresolved,
        Self::InstanceInterfaceMismatch,
        Self::ItemNotExported,
        Self::ReexportCycle,
        Self::TargetKindInvalid,
        Self::TransitiveUndeclared,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AliasCollision => "package-alias-collision",
            Self::AliasUnresolved => "package-alias-unresolved",
            Self::InstanceInterfaceMismatch => "package-instance-interface-mismatch",
            Self::ItemNotExported => "package-item-not-exported",
            Self::ReexportCycle => "package-reexport-cycle",
            Self::TargetKindInvalid => "package-target-kind-invalid",
            Self::TransitiveUndeclared => "package-transitive-undeclared",
        }
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::AliasCollision => {
                "A dependency alias collides with another name in its declaring package instance."
            }
            Self::AliasUnresolved => {
                "A qualified path names a dependency alias that its declaring package instance does not declare."
            }
            Self::InstanceInterfaceMismatch => {
                "A package interface does not match the interface identity bound by its package instance or pinned dependency artifact."
            }
            Self::ItemNotExported => {
                "A name is not exported by the frozen public interface manifest that governs it."
            }
            Self::ReexportCycle => {
                "A re-export chain never terminates in a defining exported item."
            }
            Self::TargetKindInvalid => {
                "A target violates the closed target-kind vocabulary or the rules of its kind."
            }
            Self::TransitiveUndeclared => {
                "A package names an item reachable only through a dependency it does not declare."
            }
        }
    }

    /// Returns the clause that owns this condition.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        match self {
            Self::AliasCollision | Self::AliasUnresolved | Self::TransitiveUndeclared => {
                "GNT-16.3-dependency-aliases"
            }
            Self::InstanceInterfaceMismatch => "GNT-16.7-public-interface-manifest",
            Self::ItemNotExported => "GNT-16.4-visibility",
            Self::ReexportCycle => "GNT-16.5-reexports",
            Self::TargetKindInvalid => "GNT-16.6-target-kinds",
        }
    }
}

/// One namespace a dependency alias can collide with.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AliasNamespace {
    /// A local module name of the declaring package instance.
    Module,
    /// An ordinary item of the declaring package instance.
    Item,
    /// An agent name of the declaring package instance.
    Agent,
    /// A capability slot of the declaring package instance.
    CapabilitySlot,
    /// Another dependency alias of the declaring package instance.
    DependencyAlias,
    /// A reserved word of the selected edition.
    ReservedWord,
}

impl AliasNamespace {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Item => "item",
            Self::Agent => "agent",
            Self::CapabilitySlot => "capability-slot",
            Self::DependencyAlias => "dependency-alias",
            Self::ReservedWord => "reserved-word",
        }
    }
}

/// The relation that makes one alias spelling collide.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CollisionCondition {
    /// The two spellings are byte-identical.
    Exact,
    /// The two spellings are equal after Unicode case folding.
    Case,
    /// The candidate spelling is a truncation of a declared name.
    Truncation,
    /// The candidate spelling is not canonically normalized.
    Normalization,
    /// The candidate spelling is a reserved word of the selected edition.
    ReservedWord,
}

impl CollisionCondition {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Case => "case",
            Self::Truncation => "truncation",
            Self::Normalization => "normalization",
            Self::ReservedWord => "reserved-word",
        }
    }
}

/// The rule one target violates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetCondition {
    /// The declared kind is outside the closed five-kind vocabulary.
    UnsupportedKind,
    /// A `binary` target declares no entry point.
    MissingEntryPoint,
    /// A `binary` target declares more than one entry point.
    MultipleEntryPoints,
    /// A `library` target declares an entry point.
    LibraryDeclaresEntryPoint,
    /// A non-shipping target's item appears in another target's public interface.
    NonShippingItemInPublicInterface,
    /// A non-shipping target's re-export appears in another target's public interface.
    NonShippingExportInPublicInterface,
}

impl TargetCondition {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UnsupportedKind => "unsupported-kind",
            Self::MissingEntryPoint => "missing-entry-point",
            Self::MultipleEntryPoints => "multiple-entry-points",
            Self::LibraryDeclaresEntryPoint => "library-declares-entry-point",
            Self::NonShippingItemInPublicInterface => "non-shipping-item-in-public-interface",
            Self::NonShippingExportInPublicInterface => "non-shipping-export-in-public-interface",
        }
    }
}

/// Why one identity could not be established.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UnprovenReason {
    /// A required identity input is absent. An absent input is never empty.
    MissingInput(&'static str),
    /// A supplied identity input is malformed.
    InvalidInput(&'static str),
    /// The identity record version is unsupported.
    UnsupportedRecordVersion(u32),
    /// The interface manifest version is unsupported.
    UnsupportedInterfaceVersion(u32),
}

impl UnprovenReason {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::MissingInput(_) => "missing-input",
            Self::InvalidInput(_) => "invalid-input",
            Self::UnsupportedRecordVersion(_) => "unsupported-identity-record-version",
            Self::UnsupportedInterfaceVersion(_) => "unsupported-interface-version",
        }
    }

    /// Returns the named input when this reason identifies one.
    #[must_use]
    pub const fn input(self) -> Option<&'static str> {
        match self {
            Self::MissingInput(name) | Self::InvalidInput(name) => Some(name),
            Self::UnsupportedRecordVersion(_) | Self::UnsupportedInterfaceVersion(_) => None,
        }
    }
}

/// One rejected package-model condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageError {
    /// A dependency alias collides inside its declaring package instance.
    AliasCollision {
        /// The collided namespace.
        namespace: AliasNamespace,
        /// One spelling of the colliding pair, in canonical order.
        alias: Arc<str>,
        /// The other spelling of the colliding pair, never smaller than `alias`.
        conflicting: Arc<str>,
        /// The collision relation.
        condition: CollisionCondition,
    },
    /// A qualified path names an alias the declaring package does not declare.
    AliasUnresolved {
        /// The unresolved first-segment spelling.
        spelling: Arc<str>,
    },
    /// A path names an item reachable only through an undeclared dependency.
    TransitiveUndeclared {
        /// The dependency package name that is not declared.
        package: Arc<str>,
        /// The rejected path spelling.
        accessed: Arc<str>,
    },
    /// A name the frozen interface does not export.
    ItemNotExported {
        /// The package instance whose frozen interface governs the lookup.
        package: PackageIdentity,
        /// The unexported name.
        name: Arc<str>,
    },
    /// A re-export whose defining instance the manifest does not pin.
    UnpinnedExport {
        /// The exported spelling of the re-export.
        exported_name: Arc<str>,
        /// The defining instance identity without a matching dependency pin.
        defining: PackageIdentity,
    },
    /// A re-export chain that never terminates in a defining exported item.
    ReexportCycle {
        /// The instance at which the walk revisited a name.
        package: PackageIdentity,
        /// The name that closed the cycle.
        name: Arc<str>,
    },
    /// An interface identity that does not match the interface it must bind.
    InterfaceMismatch {
        /// The expected interface identity.
        expected: InterfaceDigest,
        /// The observed interface identity.
        observed: InterfaceDigest,
    },
    /// A target that violates the closed vocabulary or its kind's rules.
    TargetKindInvalid {
        /// The declared kind spelling.
        kind: Arc<str>,
        /// The violated rule.
        condition: TargetCondition,
    },
    /// An alias spelling that is not a legal alias identifier.
    InvalidAlias {
        /// The rejected spelling.
        spelling: Arc<str>,
    },
    /// One alias declared twice by one declaring package instance.
    DuplicateAlias {
        /// The duplicated alias spelling.
        alias: Arc<str>,
    },
    /// A dependency cycle among resolved package instances.
    DependencyCycle {
        /// One deterministic rotation of the cycle, in instance order.
        cycle: Vec<PackageIdentity>,
    },
    /// A referenced package instance that the resolved graph does not contain.
    UnknownInstance {
        /// The missing instance identity.
        package: PackageIdentity,
    },
    /// An identity record that carries a property this version does not define.
    UnknownIdentityProperty {
        /// The unknown property name.
        property: Arc<str>,
    },
    /// An identity record whose version is unsupported.
    UnsupportedIdentityVersion {
        /// The unsupported version.
        version: u32,
    },
    /// An interface manifest whose version is unsupported.
    UnsupportedInterfaceVersion {
        /// The unsupported version.
        version: u32,
    },
    /// A digest that is not 64 lowercase hexadecimal digits.
    InvalidDigest {
        /// The rejected digest text.
        value: Arc<str>,
    },
    /// A declared package fact that is malformed or outside its vocabulary.
    InvalidDeclaration {
        /// The named field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
    /// One named declaration supplied twice where exactly one is admitted.
    DuplicateDeclaration {
        /// The named field.
        field: &'static str,
        /// The duplicated value.
        value: Arc<str>,
    },
    /// An interface that omits a member its package declares.
    OmittedDeclaredMember {
        /// The omitted declared name.
        name: Arc<str>,
    },
    /// An interface that records a member its package does not declare.
    UndeclaredInterfaceMember {
        /// The undeclared recorded name.
        name: Arc<str>,
    },
    /// One interface member name recorded twice.
    DuplicateInterfaceMember {
        /// The duplicated name.
        name: Arc<str>,
    },
    /// Content that the recorded item kind does not admit.
    ItemContentMismatch {
        /// The item name.
        name: Arc<str>,
        /// The item kind.
        kind: ItemKind,
    },
    /// An unqualified name that is neither local nor explicitly imported.
    UnqualifiedNameNotLocal {
        /// The unresolved unqualified name.
        name: Arc<str>,
    },
    /// An unqualified name that is local and explicitly imported at once.
    UnqualifiedNameAmbiguous {
        /// The ambiguous name.
        name: Arc<str>,
    },
    /// A resolved requirement that exceeds a declared capability ceiling.
    RequirementExceedsCeiling {
        /// The requirement subject.
        subject: Arc<str>,
    },
    /// An unchecked axis reported as compatible.
    UncheckedAxisReportedAsCompatible {
        /// The axis.
        axis: CompatibilityAxis,
    },
    /// A not-checked axis marked machine-checked.
    NotCheckedAxisMarkedChecked {
        /// The axis.
        axis: CompatibilityAxis,
    },
    /// A report that omits a required per-axis sub-report.
    IncompleteCompatibilityReport {
        /// The axis whose sub-reports are incomplete.
        axis: CompatibilityAxis,
    },
    /// A resolved dependency carries no pinned interface digest.
    UnpinnedDependency {
        /// The dependency that resolved without a pin.
        dependency: PackageIdentity,
    },
    /// One dependency identity carries two distinct pinned interface digests.
    ConflictingDependencyPin {
        /// The dependency with conflicting pins.
        dependency: PackageIdentity,
    },
    /// The supplied dependency count exceeds the fingerprint's declared bound.
    ExceedsMaximumDependencies {
        /// The number of supplied dependencies when the bound was crossed.
        observed: usize,
        /// The declared bound.
        maximum: usize,
    },
}

impl PackageError {
    /// Returns the frozen published diagnostic identity of this condition.
    ///
    /// `None` means the condition has no published code and MUST NOT be
    /// reported under another condition's code.
    #[must_use]
    pub fn code(&self) -> Option<PackageDiagnosticCode> {
        match self {
            Self::AliasCollision { .. } => Some(PackageDiagnosticCode::AliasCollision),
            Self::AliasUnresolved { .. } => Some(PackageDiagnosticCode::AliasUnresolved),
            Self::TransitiveUndeclared { .. } => Some(PackageDiagnosticCode::TransitiveUndeclared),
            Self::ItemNotExported { .. } => Some(PackageDiagnosticCode::ItemNotExported),
            Self::ReexportCycle { .. } => Some(PackageDiagnosticCode::ReexportCycle),
            Self::InterfaceMismatch { .. } => {
                Some(PackageDiagnosticCode::InstanceInterfaceMismatch)
            }
            Self::TargetKindInvalid { .. } => Some(PackageDiagnosticCode::TargetKindInvalid),
            Self::UnpinnedExport { .. }
            | Self::InvalidAlias { .. }
            | Self::DuplicateAlias { .. }
            | Self::DependencyCycle { .. }
            | Self::UnknownInstance { .. }
            | Self::UnknownIdentityProperty { .. }
            | Self::UnsupportedIdentityVersion { .. }
            | Self::UnsupportedInterfaceVersion { .. }
            | Self::InvalidDigest { .. }
            | Self::InvalidDeclaration { .. }
            | Self::DuplicateDeclaration { .. }
            | Self::OmittedDeclaredMember { .. }
            | Self::UndeclaredInterfaceMember { .. }
            | Self::DuplicateInterfaceMember { .. }
            | Self::ItemContentMismatch { .. }
            | Self::UnqualifiedNameNotLocal { .. }
            | Self::UnqualifiedNameAmbiguous { .. }
            | Self::RequirementExceedsCeiling { .. }
            | Self::UncheckedAxisReportedAsCompatible { .. }
            | Self::NotCheckedAxisMarkedChecked { .. }
            | Self::IncompleteCompatibilityReport { .. }
            | Self::UnpinnedDependency { .. }
            | Self::ConflictingDependencyPin { .. }
            | Self::ExceedsMaximumDependencies { .. } => None,
        }
    }

    /// Returns the clause that owns this condition.
    #[must_use]
    pub const fn clause(&self) -> &'static str {
        match self {
            Self::UnpinnedDependency { .. }
            | Self::ConflictingDependencyPin { .. }
            | Self::ExceedsMaximumDependencies { .. } => "GNT-16.9-resolution-order-independence",
            Self::AliasCollision { .. }
            | Self::AliasUnresolved { .. }
            | Self::TransitiveUndeclared { .. }
            | Self::InvalidAlias { .. }
            | Self::DuplicateAlias { .. }
            | Self::UnqualifiedNameNotLocal { .. }
            | Self::UnqualifiedNameAmbiguous { .. } => "GNT-16.3-dependency-aliases",
            Self::ItemNotExported { .. } => "GNT-16.4-visibility",
            Self::ReexportCycle { .. } | Self::DependencyCycle { .. } => "GNT-16.5-reexports",
            Self::TargetKindInvalid { .. } | Self::RequirementExceedsCeiling { .. } => {
                "GNT-16.6-target-kinds"
            }
            Self::InterfaceMismatch { .. }
            | Self::UnsupportedInterfaceVersion { .. }
            | Self::UnpinnedExport { .. }
            | Self::OmittedDeclaredMember { .. }
            | Self::UndeclaredInterfaceMember { .. }
            | Self::DuplicateInterfaceMember { .. }
            | Self::ItemContentMismatch { .. } => "GNT-16.7-public-interface-manifest",
            Self::UnknownInstance { .. } => "GNT-16.2-package-instances",
            Self::UncheckedAxisReportedAsCompatible { .. }
            | Self::NotCheckedAxisMarkedChecked { .. }
            | Self::IncompleteCompatibilityReport { .. } => "GNT-16.8-compatibility-axes",
            Self::UnknownIdentityProperty { .. }
            | Self::UnsupportedIdentityVersion { .. }
            | Self::InvalidDigest { .. }
            | Self::InvalidDeclaration { .. }
            | Self::DuplicateDeclaration { .. } => "GNT-16.1-package-identity",
        }
    }
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AliasCollision {
                namespace,
                alias,
                conflicting,
                condition,
            } => write!(
                formatter,
                "alias `{alias}` collides with `{conflicting}` in the {} namespace ({})",
                namespace.wire_name(),
                condition.wire_name()
            ),
            Self::AliasUnresolved { spelling } => {
                write!(formatter, "alias `{spelling}` is not declared")
            }
            Self::TransitiveUndeclared { package, accessed } => write!(
                formatter,
                "`{accessed}` names an item of undeclared dependency `{package}`"
            ),
            Self::ItemNotExported { package, name } => {
                write!(formatter, "`{name}` is not exported by {package}")
            }
            Self::UnpinnedExport {
                exported_name,
                defining,
            } => write!(
                formatter,
                "re-export `{exported_name}` names {defining}, which the manifest does not pin"
            ),
            Self::ReexportCycle { package, name } => write!(
                formatter,
                "re-export chain for `{name}` in {package} never terminates"
            ),
            Self::InterfaceMismatch { expected, observed } => write!(
                formatter,
                "interface identity mismatch: expected {}, observed {}",
                expected.as_str(),
                observed.as_str()
            ),
            Self::TargetKindInvalid { kind, condition } => write!(
                formatter,
                "target kind `{kind}` is invalid ({})",
                condition.wire_name()
            ),
            Self::UnpinnedDependency { dependency } => write!(
                formatter,
                "dependency {} resolved without a pinned interface",
                dependency.as_str()
            ),
            Self::ConflictingDependencyPin { dependency } => write!(
                formatter,
                "dependency {} carries two distinct interface pins",
                dependency.as_str()
            ),
            Self::ExceedsMaximumDependencies { observed, maximum } => write!(
                formatter,
                "{observed} supplied dependencies exceed the declared maximum of {maximum}"
            ),
            Self::InvalidAlias { spelling } => {
                write!(formatter, "`{spelling}` is not a legal dependency alias")
            }
            Self::DuplicateAlias { alias } => {
                write!(formatter, "alias `{alias}` is declared twice")
            }
            Self::DependencyCycle { cycle } => {
                write!(formatter, "dependency cycle of {} instances", cycle.len())
            }
            Self::UnknownInstance { package } => {
                write!(formatter, "instance {package} is not resolved")
            }
            Self::UnknownIdentityProperty { property } => {
                write!(formatter, "unknown identity property `{property}`")
            }
            Self::UnsupportedIdentityVersion { version } => {
                write!(formatter, "unsupported identity record version {version}")
            }
            Self::UnsupportedInterfaceVersion { version } => {
                write!(formatter, "unsupported interface version {version}")
            }
            Self::InvalidDigest { value } => {
                write!(formatter, "`{value}` is not a lowercase hex SHA-256 digest")
            }
            Self::InvalidDeclaration { field, value } => {
                write!(formatter, "invalid {field} `{value}`")
            }
            Self::DuplicateDeclaration { field, value } => {
                write!(formatter, "{field} `{value}` is declared twice")
            }
            Self::OmittedDeclaredMember { name } => {
                write!(formatter, "interface omits declared member `{name}`")
            }
            Self::UndeclaredInterfaceMember { name } => {
                write!(formatter, "interface records undeclared member `{name}`")
            }
            Self::DuplicateInterfaceMember { name } => {
                write!(formatter, "interface member `{name}` is recorded twice")
            }
            Self::ItemContentMismatch { name, kind } => write!(
                formatter,
                "`{name}` carries content that kind {} does not admit",
                kind.wire_name()
            ),
            Self::UnqualifiedNameNotLocal { name } => {
                write!(formatter, "unqualified name `{name}` is not local")
            }
            Self::UnqualifiedNameAmbiguous { name } => write!(
                formatter,
                "unqualified name `{name}` is both local and explicitly imported"
            ),
            Self::RequirementExceedsCeiling { subject } => write!(
                formatter,
                "resolved requirement `{subject}` exceeds its declared ceiling"
            ),
            Self::UncheckedAxisReportedAsCompatible { axis } => write!(
                formatter,
                "unchecked axis {} is reported as compatible",
                axis.wire_name()
            ),
            Self::NotCheckedAxisMarkedChecked { axis } => write!(
                formatter,
                "not-checked axis {} is marked machine-checked",
                axis.wire_name()
            ),
            Self::IncompleteCompatibilityReport { axis } => write!(
                formatter,
                "compatibility report omits axis {} sub-reports",
                axis.wire_name()
            ),
        }
    }
}

impl std::error::Error for PackageError {}

/// Validates one lowercase hexadecimal SHA-256 digest spelling.
fn validate_digest(value: &str) -> Result<(), PackageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PackageError::InvalidDigest {
            value: Arc::from(value),
        });
    }
    Ok(())
}

/// Validates one identifier spelling under the landed identifier rules.
fn validate_identifier(field: &'static str, value: &str) -> Result<(), PackageError> {
    if !is_nfc(value) {
        return Err(PackageError::InvalidDeclaration {
            field,
            value: Arc::from(value),
        });
    }
    let mut scalars = value.chars();
    if !scalars
        .next()
        .is_some_and(|scalar| scalar == '_' || is_xid_start(scalar))
        || !scalars.all(is_xid_continue)
    {
        return Err(PackageError::InvalidDeclaration {
            field,
            value: Arc::from(value),
        });
    }
    Ok(())
}

/// Returns the case-folded comparison skeleton of one spelling.
///
/// The fold uses the workspace's pinned full case mappings
/// (`gantry_core::unicode::to_full_lowercase`) rather than the toolchain's
/// `str::to_lowercase`, so alias collisions follow the pinned Unicode version and
/// its context-sensitive final-sigma rule exactly as the identifier model of
/// `GNT-18.7-case-behaviour` does.
fn case_fold(value: &str) -> String {
    to_full_lowercase(value)
}

/// Returns whether two identities name the same package name and version.
///
/// The identity binds the interface digest, so this comparison identifies the
/// package one identity was resolved from without treating a name or version as
/// a proxy for the interface that identity binds.
fn same_package(left: &PackageIdentity, right: &PackageIdentity) -> bool {
    left.inputs().name() == right.inputs().name()
        && left.inputs().version() == right.inputs().version()
}

macro_rules! digest_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Decodes one exact lowercase hexadecimal digest.
            pub fn from_hex(value: &str) -> Result<Self, PackageError> {
                validate_digest(value)?;
                Ok(Self(Arc::from(value)))
            }

            /// Encodes one accepted digest.
            #[must_use]
            pub fn from_digest(digest: [u8; 32]) -> Self {
                Self(Arc::from(encode_hex(&digest)))
            }

            /// Returns the exact lowercase hexadecimal digest.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

digest_type!(
    SourceManifestDigest,
    "One labeled package-source-manifest entity (GNT-11.6-package-source-manifest)."
);
digest_type!(
    CanonicalIrDigest,
    "One labeled canonical-core-IR identity (GNT-11.6-package-source-manifest item 6)."
);
digest_type!(
    InterfaceDigest,
    "One canonical public-interface-manifest digest (GNT-16.7-public-interface-manifest)."
);

/// One exact package-source identity.
///
/// The record retains both labeled digests rather than substituting one for the
/// other, so source bytes that differ only in a comment keep one canonical IR
/// identity and a different source-manifest identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSourceIdentity {
    manifest: SourceManifestDigest,
    canonical_ir: CanonicalIrDigest,
}

impl PackageSourceIdentity {
    /// Constructs one labeled source identity.
    #[must_use]
    pub const fn new(manifest: SourceManifestDigest, canonical_ir: CanonicalIrDigest) -> Self {
        Self {
            manifest,
            canonical_ir,
        }
    }

    /// Returns the labeled package-source-manifest digest.
    #[must_use]
    pub const fn manifest(&self) -> &SourceManifestDigest {
        &self.manifest
    }

    /// Returns the labeled canonical-core-IR digest.
    #[must_use]
    pub const fn canonical_ir(&self) -> &CanonicalIrDigest {
        &self.canonical_ir
    }
}

/// One resolved package name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageName(Arc<str>);

impl PackageName {
    /// Validates one resolved package name.
    pub fn new(value: &str) -> Result<Self, PackageError> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(PackageError::InvalidDeclaration {
                field: "package name",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact resolved name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One exact package version value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageVersion(Arc<str>);

impl PackageVersion {
    /// Validates one exact version value, which is never a range or comparison.
    pub fn new(value: &str) -> Result<Self, PackageError> {
        if value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_')
            })
        {
            return Err(PackageError::InvalidDeclaration {
                field: "version",
                value: Arc::from(value),
            });
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact version text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One selected feature name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FeatureName(Arc<str>);

impl FeatureName {
    /// Validates one selected feature name.
    pub fn new(value: &str) -> Result<Self, PackageError> {
        validate_identifier("feature", value)?;
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact feature name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One canonically ordered set of selected features.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelectedFeatureSet(Vec<FeatureName>);

impl SelectedFeatureSet {
    /// Builds one canonical feature set from names in any order.
    pub fn new(names: &[&str]) -> Result<Self, PackageError> {
        let mut features = Vec::with_capacity(names.len());
        for name in names {
            features.push(FeatureName::new(name)?);
        }
        features.sort();
        if features.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PackageError::DuplicateDeclaration {
                field: "feature",
                value: features[0].0.clone(),
            });
        }
        Ok(Self(features))
    }

    /// Returns the empty selected feature set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the selected features in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[FeatureName] {
        &self.0
    }

    /// Returns whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of selected features.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterates the selected feature names in canonical order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(FeatureName::as_str)
    }
}

/// Whether one declared generator input is an input or an output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GeneratorInputRole {
    /// A declared generator input.
    Input,
    /// A declared generator output.
    Output,
}

impl GeneratorInputRole {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "input" => Some(Self::Input),
            "output" => Some(Self::Output),
            _ => None,
        }
    }
}

/// One declared generator input, output, or hash.
///
/// Declared inputs, outputs, and hashes are part of the artifact identity, so
/// changing one changes the identity that is derived from this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratorInput {
    /// The declared name.
    pub name: Arc<str>,
    /// Whether the declaration is an input or an output.
    pub role: GeneratorInputRole,
    /// The declared lowercase hexadecimal SHA-256 hash.
    pub digest: Arc<str>,
}

impl GeneratorInput {
    /// Validates one declared generator input, output, or hash.
    pub fn new(name: &str, role: GeneratorInputRole, digest: &str) -> Result<Self, PackageError> {
        validate_identifier("generator input", name)?;
        validate_digest(digest)?;
        Ok(Self {
            name: Arc::from(name),
            role,
            digest: Arc::from(digest),
        })
    }
}

/// The canonically ordered declared generator inputs of one instance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneratorInputs(Vec<GeneratorInput>);

impl GeneratorInputs {
    /// Builds one canonical generator record from declarations in any order.
    pub fn new(entries: &[GeneratorInput]) -> Result<Self, PackageError> {
        let mut entries = entries.to_vec();
        for entry in &entries {
            validate_identifier("generator input", &entry.name)?;
            validate_digest(&entry.digest)?;
        }
        entries.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.role.cmp(&right.role))
        });
        if entries
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name && pair[0].role == pair[1].role)
        {
            return Err(PackageError::DuplicateDeclaration {
                field: "generator input",
                value: entries[0].name.clone(),
            });
        }
        Ok(Self(entries))
    }

    /// Returns the empty generator record of one instance that declares none.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the declared entries in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[GeneratorInput] {
        &self.0
    }

    /// Returns whether no generator input is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The closed target-kind vocabulary of `GNT-16.6-target-kinds`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetKind {
    /// A `library` target: no entry point, and its exported items are the public interface.
    Library,
    /// A `binary` target: exactly one entry point.
    Binary,
    /// A non-shipping `test` target.
    Test,
    /// A non-shipping `example` target.
    Example,
    /// A non-shipping `benchmark` target.
    Benchmark,
}

impl TargetKind {
    /// Every kind of the closed vocabulary.
    pub const ALL: [Self; 5] = [
        Self::Library,
        Self::Binary,
        Self::Test,
        Self::Example,
        Self::Benchmark,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Binary => "binary",
            Self::Test => "test",
            Self::Example => "example",
            Self::Benchmark => "benchmark",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }

    /// Returns whether this kind is shipping.
    ///
    /// A `test`, `example`, or `benchmark` target is non-shipping and
    /// bounded-authority, so it MUST NOT be represented as shipping authority.
    #[must_use]
    pub const fn is_shipping(self) -> bool {
        matches!(self, Self::Library | Self::Binary)
    }
}

/// The resolved target facts that participate in package identity.
///
/// One recorded fact is the declared target kind together with the declared
/// entry point of that kind. Physical directory structure, file names, host
/// paths, target roots, and the target's display name are deliberately absent,
/// because they MUST NOT affect package identity or target identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetFacts {
    kind: TargetKind,
    entry_point: Option<CanonicalPath>,
}

impl TargetFacts {
    /// Constructs target facts under the per-kind entry-point rules.
    pub fn new(kind: TargetKind, entry_point: Option<CanonicalPath>) -> Result<Self, PackageError> {
        match (kind, entry_point.is_some()) {
            (TargetKind::Library, true) => {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(kind.wire_name()),
                    condition: TargetCondition::LibraryDeclaresEntryPoint,
                });
            }
            (TargetKind::Binary, false) => {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(kind.wire_name()),
                    condition: TargetCondition::MissingEntryPoint,
                });
            }
            _ => {}
        }
        Ok(Self { kind, entry_point })
    }

    /// Returns the resolved target kind.
    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    /// Returns the declared entry point of the instance, when it has one.
    #[must_use]
    pub const fn entry_point(&self) -> Option<&CanonicalPath> {
        self.entry_point.as_ref()
    }
}

/// The declared target facts of one package instance.
///
/// The facts are exactly the declared pairs of target kind and declared entry
/// point. Target names, target roots, host paths, and physical layout are
/// deliberately absent, so an instance that adds an example target is a
/// different instance while an instance that changes only a target name or root
/// is not. The set is canonically ordered and records each distinct fact once,
/// so the same declaration set produces the same identity in every enumeration
/// order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetFactSet(Vec<TargetFacts>);

impl TargetFactSet {
    /// Builds one canonical target-fact set from declarations in any order.
    ///
    /// The declared set, not its enumeration, is the identity input: a fact
    /// declared twice is one fact.
    #[must_use]
    pub fn new(facts: &[TargetFacts]) -> Self {
        let mut facts = facts.to_vec();
        facts.sort_by(compare_target_facts);
        facts.dedup();
        Self(facts)
    }

    /// Returns the empty set of one instance that declares no target fact.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the declared facts in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[TargetFacts] {
        &self.0
    }

    /// Returns whether the set declares no fact.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of distinct declared facts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the set declares one fact equal to the supplied fact.
    #[must_use]
    pub fn contains(&self, facts: &TargetFacts) -> bool {
        self.0.contains(facts)
    }
}

/// Orders two declared target facts by kind and then by declared entry point.
fn compare_target_facts(left: &TargetFacts, right: &TargetFacts) -> std::cmp::Ordering {
    left.kind.cmp(&right.kind).then_with(|| {
        left.entry_point()
            .map(CanonicalPath::as_str)
            .cmp(&right.entry_point().map(CanonicalPath::as_str))
    })
}

/// The closed inputs of one package identity.
///
/// Every input is domain-separated and independently recorded, and none of them
/// is a module graph path, a filesystem layout, a discovery order, a registry
/// display name, a dependency alias spelling, a target name, or a target root.
/// The target input is the declared set of target kinds and entry points.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageIdentityInputs {
    name: PackageName,
    version: PackageVersion,
    source: PackageSourceIdentity,
    features: SelectedFeatureSet,
    targets: TargetFactSet,
    selection: TargetFactsRecord,
    interface: InterfaceDigest,
    generators: GeneratorInputs,
}

impl PackageIdentityInputs {
    /// Constructs one complete, fully established input record.
    #[must_use]
    // The inputs are the closed identity vocabulary of `GNT-16.1`, so the
    // constructor is kept explicit rather than collapsed into a builder that
    // could omit an input.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        name: PackageName,
        version: PackageVersion,
        source: PackageSourceIdentity,
        features: SelectedFeatureSet,
        targets: TargetFactSet,
        selection: TargetFactsRecord,
        interface: InterfaceDigest,
        generators: GeneratorInputs,
    ) -> Self {
        Self {
            name,
            version,
            source,
            features,
            targets,
            selection,
            interface,
            generators,
        }
    }

    /// Returns the resolved package name.
    #[must_use]
    pub const fn name(&self) -> &PackageName {
        &self.name
    }

    /// Returns the exact package version.
    #[must_use]
    pub const fn version(&self) -> &PackageVersion {
        &self.version
    }

    /// Returns both labeled source-identity digests.
    #[must_use]
    pub const fn source(&self) -> &PackageSourceIdentity {
        &self.source
    }

    /// Returns the selected features of the instance.
    #[must_use]
    pub const fn features(&self) -> &SelectedFeatureSet {
        &self.features
    }

    /// Returns the declared target facts of the instance.
    #[must_use]
    pub const fn targets(&self) -> &TargetFactSet {
        &self.targets
    }

    /// Returns the selected target and feature-solution facts of the instance.
    ///
    /// These are the `GNT-17.2-descriptor-normalization-and-target-facts` facts
    /// named by `GNT-16.1-package-identity`: the descriptor version, the
    /// normalized descriptor digest, and the selected feature-solution digest.
    #[must_use]
    pub const fn selection(&self) -> &TargetFactsRecord {
        &self.selection
    }

    /// Returns the public-interface digest of the instance.
    #[must_use]
    pub const fn interface_digest(&self) -> &InterfaceDigest {
        &self.interface
    }

    /// Returns the declared generator inputs of the instance.
    #[must_use]
    pub const fn generator_inputs(&self) -> &GeneratorInputs {
        &self.generators
    }
}

/// One canonical package identity.
///
/// The identity has exactly one canonical byte representation, and two packages
/// have the same identity if and only if those canonical bytes are identical.
/// Comparison is exact: equality is canonical-byte equality, never a text
/// substring, display name, version string, or prefix comparison.
#[derive(Clone, Debug)]
pub struct PackageIdentity {
    inputs: PackageIdentityInputs,
    canonical: Arc<[u8]>,
    digest: [u8; 32],
}

impl PackageIdentity {
    /// Derives the one canonical identity of one complete input record.
    #[must_use]
    pub fn derive(inputs: PackageIdentityInputs) -> Self {
        let canonical = encode_identity(&inputs);
        let digest = digest_fields(IDENTITY_DOMAIN, &[&canonical]);
        Self {
            inputs,
            canonical: Arc::from(canonical),
            digest,
        }
    }

    /// Returns the closed input record of this identity.
    #[must_use]
    pub const fn inputs(&self) -> &PackageIdentityInputs {
        &self.inputs
    }

    /// Returns the one canonical byte representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the identity digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal identity digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        encode_hex(&self.digest)
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("package:{}", encode_hex(&self.digest))
    }

    /// Returns the public-interface digest bound by this identity.
    #[must_use]
    pub const fn interface_digest(&self) -> &InterfaceDigest {
        self.inputs.interface_digest()
    }
}

impl PartialEq for PackageIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for PackageIdentity {}

/// Domain separator for canonical dependency fingerprints.
const DEPENDENCY_FINGERPRINT_DOMAIN: &str = "gantry.package-dependency-fingerprint/v1";

/// One pinned dependency entry of a [`DependencyFingerprint`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyPin {
    identity: PackageIdentity,
    interface: InterfaceDigest,
}

impl DependencyPin {
    /// Returns the resolved dependency package identity.
    #[must_use]
    pub const fn identity(&self) -> &PackageIdentity {
        &self.identity
    }

    /// Returns the interface digest this resolution pinned for the dependency.
    #[must_use]
    pub const fn interface(&self) -> &InterfaceDigest {
        &self.interface
    }
}

/// One canonical fingerprint of a package instance and its pinned dependencies.
///
/// The fingerprint composes the resolved package identity digest with the pinned
/// interface digest of every dependency it resolved, so two resolutions whose
/// dependency sets differ in any identity or pin cannot share a fingerprint, and
/// two resolutions over the same set share one whatever the declaration order.
///
/// Dependency identity is the resolved package identity alone: an alias is local
/// source spelling and is never an input, so reaching one dependency under two
/// different aliases in two declaring packages yields the same fingerprint, and
/// renaming an alias changes no fingerprint. A dependency that resolved without a
/// pinned interface digest is refused rather than fingerprinted, so an open
/// dependency cannot be reported as a resolved one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyFingerprint {
    package: PackageIdentity,
    pins: Vec<DependencyPin>,
    digest: [u8; 32],
}

impl DependencyFingerprint {
    /// The largest number of supplied dependencies one derivation admits.
    ///
    /// The bound is measured over the supplied pairs before deduplication, so
    /// duplicates count toward it, and a larger input is refused with
    /// [`PackageError::ExceedsMaximumDependencies`] instead of
    /// being truncated.
    pub const MAXIMUM_DEPENDENCIES: usize = 4096;

    /// Derives one fingerprint from a resolved package and its dependencies.
    ///
    /// A dependency whose interface digest is absent resolved without a pin and
    /// is refused with [`PackageError::UnpinnedDependency`]; one
    /// dependency identity carrying two distinct pins is refused with
    /// [`PackageError::ConflictingDependencyPin`]. Identical
    /// repeats collapse.
    ///
    /// # Errors
    ///
    /// Returns the two refusals above, plus
    /// [`PackageError::ExceedsMaximumDependencies`] when the supplied
    /// dependencies exceed [`Self::MAXIMUM_DEPENDENCIES`].
    pub fn derive(
        package: PackageIdentity,
        dependencies: impl IntoIterator<Item = (PackageIdentity, Option<InterfaceDigest>)>,
    ) -> Result<Self, PackageError> {
        let mut supplied = Vec::new();
        for pair in dependencies {
            supplied.push(pair);
            if supplied.len() > Self::MAXIMUM_DEPENDENCIES {
                return Err(PackageError::ExceedsMaximumDependencies {
                    observed: supplied.len(),
                    maximum: Self::MAXIMUM_DEPENDENCIES,
                });
            }
        }
        supplied.sort_by_key(|pin| pin.0.as_str());
        let mut pins = Vec::with_capacity(supplied.len());
        for (identity, interface) in supplied {
            let interface = interface.ok_or_else(|| PackageError::UnpinnedDependency {
                dependency: identity.clone(),
            })?;
            pins.push(DependencyPin {
                identity,
                interface,
            });
        }
        // Supplied pairs are already in canonical identity order, so a missing
        // pin refuses the canonically smallest unpinned dependency whatever the
        // caller's order, as this module's diagnostic ordering requires.
        let mut deduped: Vec<DependencyPin> = Vec::with_capacity(pins.len());
        for pin in pins {
            match deduped.last() {
                Some(last) if last.identity == pin.identity => {
                    if last.interface != pin.interface {
                        return Err(PackageError::ConflictingDependencyPin {
                            dependency: pin.identity,
                        });
                    }
                }
                _ => deduped.push(pin),
            }
        }
        let canonical = encode_dependency_fingerprint(&package, &deduped);
        let digest = digest_fields(DEPENDENCY_FINGERPRINT_DOMAIN, &[&canonical]);
        Ok(Self {
            package,
            pins: deduped,
            digest,
        })
    }

    /// Returns the fingerprinted package identity.
    #[must_use]
    pub const fn package(&self) -> &PackageIdentity {
        &self.package
    }

    /// Returns the pinned dependencies in canonical identity order.
    #[must_use]
    pub fn pins(&self) -> &[DependencyPin] {
        &self.pins
    }

    /// Returns the number of distinct pinned dependencies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Returns whether the package resolved no dependency.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Returns the pin of one dependency identity, when it is pinned.
    #[must_use]
    pub fn pin_for(&self, dependency: &PackageIdentity) -> Option<&InterfaceDigest> {
        self.pins
            .iter()
            .find(|pin| &pin.identity == dependency)
            .map(|pin| &pin.interface)
    }

    /// Returns the fingerprint digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the lowercase hexadecimal fingerprint digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        encode_hex(&self.digest)
    }

    /// Returns the exact portable fingerprint spelling.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("dependency-fingerprint:{}", self.digest_hex())
    }
}

/// Encodes the canonical fingerprint material.
///
/// Every field is a fixed-length hexadecimal digest or a separator, so the
/// encoding is unambiguous without length prefixes.
fn encode_dependency_fingerprint(package: &PackageIdentity, pins: &[DependencyPin]) -> Vec<u8> {
    let mut text = String::new();
    text.push_str(&package.digest_hex());
    text.push('\n');
    for pin in pins {
        text.push_str(&pin.identity.digest_hex());
        text.push(':');
        text.push_str(pin.interface.as_str());
        text.push('\n');
    }
    text.into_bytes()
}

impl PartialOrd for PackageIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageIdentity {
    /// Orders identities by canonical bytes, which is a deterministic iteration
    /// order and never an identity comparison.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for PackageIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl fmt::Display for PackageIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_str())
    }
}

/// One decoded, versioned, closed identity record.
///
/// An identity record that carries a property this version does not define, or
/// an unsupported version, is rejected rather than repaired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageIdentityRecord {
    version: u32,
    properties: BTreeMap<Arc<str>, Arc<str>>,
}

impl PackageIdentityRecord {
    /// The only supported identity-record version.
    pub const VERSION: u32 = 1;

    /// The closed property vocabulary of an identity record.
    pub const PROPERTIES: [&'static str; 9] = [
        "name",
        "version",
        "source_manifest_sha256",
        "canonical_ir_sha256",
        "features",
        "target_facts",
        "target_selection",
        "interface_sha256",
        "generator_inputs",
    ];

    /// Decodes one closed identity record, rejecting unknown properties.
    pub fn new(version: u32, properties: &[(&str, &str)]) -> Result<Self, PackageError> {
        if version != Self::VERSION {
            return Err(PackageError::UnsupportedIdentityVersion { version });
        }
        let mut decoded = BTreeMap::new();
        for (key, value) in properties {
            if !Self::PROPERTIES.contains(key) {
                return Err(PackageError::UnknownIdentityProperty {
                    property: Arc::from(*key),
                });
            }
            if decoded.insert(Arc::from(*key), Arc::from(*value)).is_some() {
                return Err(PackageError::DuplicateDeclaration {
                    field: "identity property",
                    value: Arc::from(*key),
                });
            }
        }
        Ok(Self {
            version,
            properties: decoded,
        })
    }

    /// Returns the record version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns one recorded property value.
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(AsRef::as_ref)
    }

    /// Proves the identity of this record, or reports it unproven.
    ///
    /// A missing property is never treated as an empty property, and a record
    /// that cannot establish every input is reported unproven rather than
    /// asserted equal.
    #[must_use]
    pub fn prove(&self) -> IdentityProof {
        match self.try_prove() {
            Ok(identity) => IdentityProof::Proven(Box::new(identity)),
            Err(reason) => IdentityProof::Unproven(reason),
        }
    }

    fn required(&self, key: &'static str) -> Result<&str, UnprovenReason> {
        self.property(key).ok_or(UnprovenReason::MissingInput(key))
    }

    fn try_prove(&self) -> Result<PackageIdentity, UnprovenReason> {
        let name = PackageName::new(self.required("name")?)
            .map_err(|_| UnprovenReason::InvalidInput("name"))?;
        let version = PackageVersion::new(self.required("version")?)
            .map_err(|_| UnprovenReason::InvalidInput("version"))?;
        let manifest = SourceManifestDigest::from_hex(self.required("source_manifest_sha256")?)
            .map_err(|_| UnprovenReason::InvalidInput("source_manifest_sha256"))?;
        let canonical_ir = CanonicalIrDigest::from_hex(self.required("canonical_ir_sha256")?)
            .map_err(|_| UnprovenReason::InvalidInput("canonical_ir_sha256"))?;
        let interface = InterfaceDigest::from_hex(self.required("interface_sha256")?)
            .map_err(|_| UnprovenReason::InvalidInput("interface_sha256"))?;

        let feature_text = self.required("features")?;
        let feature_names = if feature_text.is_empty() {
            Vec::new()
        } else {
            feature_text.split(',').collect::<Vec<_>>()
        };
        let features = SelectedFeatureSet::new(&feature_names)
            .map_err(|_| UnprovenReason::InvalidInput("features"))?;

        // The declared target facts are recorded as `;`-separated entries of
        // `kind` or `kind=entry`; the canonical set orders them, so the recorded
        // text and the derived identity never depend on declaration order.
        let target_text = self.required("target_facts")?;
        let mut declared = Vec::new();
        if !target_text.is_empty() {
            for fact in target_text.split(';') {
                let (kind_text, entry_text) = match fact.split_once('=') {
                    Some((kind, entry)) => (kind, Some(entry)),
                    None => (fact, None),
                };
                let kind = TargetKind::from_wire_name(kind_text)
                    .ok_or(UnprovenReason::InvalidInput("target_facts"))?;
                let entry_point = match entry_text {
                    None | Some("") => None,
                    Some(text) => Some(
                        CanonicalPath::new(text)
                            .map_err(|_| UnprovenReason::InvalidInput("target_facts"))?,
                    ),
                };
                declared.push(
                    TargetFacts::new(kind, entry_point)
                        .map_err(|_| UnprovenReason::InvalidInput("target_facts"))?,
                );
            }
        }
        let targets = TargetFactSet::new(&declared);

        // The selected target and feature-solution facts are recorded as the
        // canonical `version:descriptor:features` text of
        // `GNT-17.2-descriptor-normalization-and-target-facts`; a record that
        // cannot name them is unproven rather than assumed.
        let selection = TargetFactsRecord::from_text(self.required("target_selection")?)
            .map_err(|_| UnprovenReason::InvalidInput("target_selection"))?;

        let generator_text = self.required("generator_inputs")?;
        let mut generator_entries = Vec::new();
        if !generator_text.is_empty() {
            for entry in generator_text.split(';') {
                let mut parts = entry.split('=');
                let (Some(name), Some(role), Some(digest)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    return Err(UnprovenReason::InvalidInput("generator_inputs"));
                };
                if parts.next().is_some() {
                    return Err(UnprovenReason::InvalidInput("generator_inputs"));
                }
                let role = GeneratorInputRole::from_wire_name(role)
                    .ok_or(UnprovenReason::InvalidInput("generator_inputs"))?;
                generator_entries.push(GeneratorInput {
                    name: Arc::from(name),
                    role,
                    digest: Arc::from(digest),
                });
            }
        }
        let generators = GeneratorInputs::new(&generator_entries)
            .map_err(|_| UnprovenReason::InvalidInput("generator_inputs"))?;

        Ok(PackageIdentity::derive(PackageIdentityInputs::new(
            name,
            version,
            PackageSourceIdentity::new(manifest, canonical_ir),
            features,
            targets,
            selection,
            interface,
            generators,
        )))
    }
}

/// The outcome of an attempt to prove one package identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityProof {
    /// The identity is proven and carries its canonical bytes.
    Proven(Box<PackageIdentity>),
    /// The identity is unproven and MUST NOT be asserted equal to any other.
    Unproven(UnprovenReason),
}

impl IdentityProof {
    /// Returns the proven identity when the proof succeeded.
    #[must_use]
    pub fn proven(&self) -> Option<&PackageIdentity> {
        match self {
            Self::Proven(identity) => Some(identity),
            Self::Unproven(_) => None,
        }
    }

    /// Returns the reason an identity is unproven.
    #[must_use]
    pub const fn reason(&self) -> Option<UnprovenReason> {
        match self {
            Self::Proven(_) => None,
            Self::Unproven(reason) => Some(*reason),
        }
    }
}

/// Whether one item is nameable outside its defining package.
///
/// The vocabulary is binary because `GNT-16.4-visibility` defines no visibility
/// keyword, modifier, or partial-visibility form.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Visibility {
    /// The item is exported by the frozen public interface manifest.
    Exported,
    /// The item is package-wide addressable inside its package and not exported.
    PackageLocal,
}

impl Visibility {
    /// Returns whether the item is exported.
    #[must_use]
    pub const fn is_exported(self) -> bool {
        matches!(self, Self::Exported)
    }

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exported => "exported",
            Self::PackageLocal => "package-local",
        }
    }
}

/// The item kinds a re-export must preserve.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ItemKind {
    /// A nominal type identity.
    Nominal,
    /// An ordinary workflow or function item.
    Function,
    /// An action declaration with its recovery class.
    Action,
    /// A capability requirement.
    Capability,
    /// An agent slot.
    Agent,
    /// A trait identity.
    Trait,
    /// An operation identity.
    Operation,
}

impl ItemKind {
    /// Every kind, in the fixed reporting order of this module.
    pub const ALL: [Self; 7] = [
        Self::Nominal,
        Self::Function,
        Self::Action,
        Self::Capability,
        Self::Agent,
        Self::Trait,
        Self::Operation,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Function => "function",
            Self::Action => "action",
            Self::Capability => "capability",
            Self::Agent => "agent",
            Self::Trait => "trait",
            Self::Operation => "operation",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }
}

/// The construction policy of one exported nominal item.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstructionPolicy {
    /// Every public field or variant is constructible by a consumer.
    Exhaustive,
    /// Construction is reserved and only the recorded paths construct it.
    Sealed,
}

impl ConstructionPolicy {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::Sealed => "sealed",
        }
    }
}

/// The exhaustiveness policy of one exported nominal item.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExhaustivenessPolicy {
    /// A consumer match must cover every recorded variant.
    Exhaustive,
    /// A consumer match needs no arm for unrecorded variants.
    NonExhaustive,
}

impl ExhaustivenessPolicy {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::NonExhaustive => "non-exhaustive",
        }
    }
}

/// The nominal facts of one exported item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NominalFacts {
    /// Public field names.
    pub fields: Vec<Arc<str>>,
    /// Public variant names.
    pub variants: Vec<Arc<str>>,
    /// Construction policy.
    pub construction: ConstructionPolicy,
    /// Exhaustiveness policy.
    pub exhaustiveness: ExhaustivenessPolicy,
    /// The exported canonical schema of this nominal identity, when it has one.
    pub schema: Option<InterfaceDigest>,
}

/// The trait facts of one exported item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraitFacts {
    /// The defining owner of the trait identity, when it is owned.
    pub owner: Option<Arc<str>>,
    /// Method names that participate in the exported interface.
    pub methods: Vec<Arc<str>>,
    /// Coherence-affecting implementations recorded for this trait.
    pub coherence_impls: Vec<Arc<str>>,
}

/// One recorded member of a frozen public interface manifest.
///
/// The groups are the closed content of `GNT-16.7-public-interface-manifest`:
/// names, kinds, visibility, normalized signatures, bounds, receiver modes,
/// effect rows, mode restrictions, and public constants; nominal identities,
/// fields, variants, construction and exhaustiveness policy, and exported
/// schemas; trait ownership and coherence-affecting implementations; capability
/// and agent requirements, action declarations with recovery classes,
/// fulfilment descriptors, tool contracts, data-release projections, and
/// protected-value transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceItem {
    /// The name this item is declared and exported under.
    pub name: Arc<str>,
    /// The item kind.
    pub kind: ItemKind,
    /// Whether the item is nameable outside its defining package.
    pub visibility: Visibility,
    /// The target kind whose source declares the item.
    pub target: TargetKind,
    /// The normalized signature, for callable and action kinds.
    pub signature: Option<CanonicalSignature>,
    /// Generic and trait bounds.
    pub bounds: Vec<Arc<str>>,
    /// The receiver mode spelling, when the item is a method.
    pub receiver_mode: Option<Arc<str>>,
    /// The effect row.
    pub effect_row: EffectSet,
    /// Mode restrictions that constrain call sites.
    pub mode_restrictions: Vec<Arc<str>>,
    /// Semantics-relevant public constants.
    pub constants: Vec<(Arc<str>, Arc<str>)>,
    /// Nominal facts, for a nominal kind.
    pub nominal: Option<NominalFacts>,
    /// Trait facts, for a trait kind.
    pub trait_facts: Option<TraitFacts>,
    /// Package-qualified capability requirements.
    pub requirements: Vec<Arc<str>>,
    /// Package-qualified agent requirements.
    pub agents: Vec<Arc<str>>,
    /// The action recovery class, for an action kind.
    pub recovery: Option<RecoveryClass>,
    /// The fulfilment descriptor, when the item declares one.
    pub fulfilment: Option<Arc<str>>,
    /// The model-visible tool contract, when the item declares one.
    pub tool_contract: Option<Arc<str>>,
    /// The data-release projection, when the item declares one.
    pub data_release: Option<Arc<str>>,
    /// The protected-value transition, when the item declares one.
    pub protected_transition: Option<Arc<str>>,
}

impl InterfaceItem {
    /// Constructs one item record with every group empty.
    pub fn new(
        name: &str,
        kind: ItemKind,
        visibility: Visibility,
        target: TargetKind,
    ) -> Result<Self, PackageError> {
        validate_identifier("interface item", name)?;
        Ok(Self {
            name: Arc::from(name),
            kind,
            visibility,
            target,
            signature: None,
            bounds: Vec::new(),
            receiver_mode: None,
            effect_row: EffectSet::default(),
            mode_restrictions: Vec::new(),
            constants: Vec::new(),
            nominal: None,
            trait_facts: None,
            requirements: Vec::new(),
            agents: Vec::new(),
            recovery: None,
            fulfilment: None,
            tool_contract: None,
            data_release: None,
            protected_transition: None,
        })
    }

    /// Returns the item name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the item kind.
    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        self.kind
    }

    /// Returns the item visibility.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns the declaring target kind.
    #[must_use]
    pub const fn target(&self) -> TargetKind {
        self.target
    }

    /// Returns whether this item declares one recorded member name.
    #[must_use]
    pub fn declares_member(&self, member: &str) -> bool {
        self.nominal.as_ref().is_some_and(|nominal| {
            nominal.fields.iter().any(|field| field.as_ref() == member)
                || nominal
                    .variants
                    .iter()
                    .any(|variant| variant.as_ref() == member)
        }) || self.trait_facts.as_ref().is_some_and(|trait_facts| {
            trait_facts
                .methods
                .iter()
                .any(|method| method.as_ref() == member)
        })
    }

    /// Canonicalizes group order and rejects content the kind does not admit.
    fn canonicalize(&mut self) -> Result<(), PackageError> {
        sort_unique(&mut self.bounds);
        sort_unique(&mut self.mode_restrictions);
        sort_unique(&mut self.requirements);
        sort_unique(&mut self.agents);
        self.constants.sort();
        if self.constants.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(PackageError::DuplicateDeclaration {
                field: "public constant",
                value: self.name.clone(),
            });
        }
        if let Some(nominal) = self.nominal.as_mut() {
            sort_unique(&mut nominal.fields);
            sort_unique(&mut nominal.variants);
        }
        if let Some(trait_facts) = self.trait_facts.as_mut() {
            sort_unique(&mut trait_facts.methods);
            sort_unique(&mut trait_facts.coherence_impls);
        }
        self.check_content()
    }

    fn check_content(&self) -> Result<(), PackageError> {
        let coherent = match self.kind {
            ItemKind::Nominal => {
                self.nominal.is_some() && self.signature.is_none() && self.trait_facts.is_none()
            }
            ItemKind::Trait => {
                self.trait_facts.is_some() && self.signature.is_none() && self.nominal.is_none()
            }
            ItemKind::Function | ItemKind::Action | ItemKind::Operation => {
                self.signature.is_some() && self.nominal.is_none() && self.trait_facts.is_none()
            }
            ItemKind::Capability | ItemKind::Agent => {
                self.signature.is_none() && self.nominal.is_none() && self.trait_facts.is_none()
            }
        };
        if !coherent || self.recovery.is_some() != (self.kind == ItemKind::Action) {
            return Err(PackageError::ItemContentMismatch {
                name: self.name.clone(),
                kind: self.kind,
            });
        }
        Ok(())
    }
}

/// The closed declared surface of one package instance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeclaredSurface(BTreeSet<Arc<str>>);

impl DeclaredSurface {
    /// Builds one declared surface from names in any order.
    pub fn from_names(names: &[&str]) -> Result<Self, PackageError> {
        let mut surface = BTreeSet::new();
        for name in names {
            validate_identifier("declared member", name)?;
            if !surface.insert(Arc::from(*name)) {
                return Err(PackageError::DuplicateInterfaceMember {
                    name: Arc::from(*name),
                });
            }
        }
        Ok(Self(surface))
    }

    /// Returns whether the surface declares one name.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains(name)
    }

    /// Iterates the declared names in canonical order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(AsRef::as_ref)
    }

    /// Returns the number of declared names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the surface declares no name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One pinned dependency interface, keyed by identity and never by alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyInterfacePin {
    /// The dependency package-instance identity.
    pub package: PackageIdentity,
    /// The dependency interface digest this instance was resolved against.
    pub interface: InterfaceDigest,
}

/// One exported name and the defining identity it reaches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportEntry {
    /// The exported spelling in the re-exporting package.
    pub exported_name: Arc<str>,
    /// The defining name in the defining package.
    pub defining_name: Arc<str>,
    /// The preserved item kind.
    pub kind: ItemKind,
    /// The target kind whose source declares the re-export.
    pub target: TargetKind,
    /// The defining package-instance identity, which a facade cannot erase.
    pub defining: PackageIdentity,
}

/// The non-member metadata of one public interface manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceMetadata {
    /// The selected source-language edition.
    pub edition: Arc<str>,
    /// The standard-library contract version.
    pub stdlib_contract: ProtocolVersion,
    /// The protocol versions this interface binds, by name.
    pub protocol_versions: Vec<(Arc<str>, ProtocolVersion)>,
    /// The target predicates this interface was resolved under.
    pub target_predicates: Vec<Arc<str>>,
    /// The selected public features of the instance.
    pub public_features: SelectedFeatureSet,
}

/// The complete input of one interface sealing operation.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceSeal<'a> {
    /// The interface version.
    pub version: u32,
    /// The non-member metadata.
    pub metadata: &'a InterfaceMetadata,
    /// The complete declared surface the manifest must record.
    pub surface: &'a DeclaredSurface,
    /// The recorded items.
    pub items: &'a [InterfaceItem],
    /// The pinned dependency interfaces.
    pub dependencies: &'a [DependencyInterfacePin],
    /// The re-exports of this package.
    pub exports: &'a [ExportEntry],
}

/// One frozen public interface manifest over one canonical encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicInterfaceManifest {
    version: u32,
    metadata: InterfaceMetadata,
    dependencies: Vec<DependencyInterfacePin>,
    exports: Vec<ExportEntry>,
    items: Vec<InterfaceItem>,
    canonical: Arc<[u8]>,
    digest: InterfaceDigest,
}

impl PublicInterfaceManifest {
    /// The only supported interface-manifest version.
    pub const VERSION: u32 = 1;

    /// Seals one manifest, rejecting any interface that is not closed.
    pub fn seal(seal: InterfaceSeal<'_>) -> Result<Self, PackageError> {
        if seal.version != Self::VERSION {
            return Err(PackageError::UnsupportedInterfaceVersion {
                version: seal.version,
            });
        }
        if seal.metadata.edition.is_empty() {
            return Err(PackageError::InvalidDeclaration {
                field: "edition",
                value: seal.metadata.edition.clone(),
            });
        }
        let mut items = seal.items.to_vec();
        for item in &mut items {
            item.canonicalize()?;
        }
        items.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.kind.cmp(&right.kind))
        });
        if items.windows(2).any(|pair| pair[0].name == pair[1].name) {
            let duplicated = items[1].name.clone();
            return Err(PackageError::DuplicateInterfaceMember { name: duplicated });
        }
        let mut exports = seal.exports.to_vec();
        for export in &exports {
            validate_identifier("exported name", &export.exported_name)?;
            validate_identifier("defining name", &export.defining_name)?;
        }
        exports.sort_by(|left, right| left.exported_name.cmp(&right.exported_name));
        if exports
            .windows(2)
            .any(|pair| pair[0].exported_name == pair[1].exported_name)
        {
            let duplicated = exports[1].exported_name.clone();
            return Err(PackageError::DuplicateInterfaceMember { name: duplicated });
        }
        if let Some(item) = items.iter().find(|item| {
            exports
                .binary_search_by(|export| export.exported_name.as_ref().cmp(item.name.as_ref()))
                .is_ok()
        }) {
            // One spelling has one meaning: a name recorded as both a local item
            // and a re-export is rejected here rather than resolved by whichever
            // table a consumer happens to consult first.
            return Err(PackageError::DuplicateInterfaceMember {
                name: item.name.clone(),
            });
        }
        for name in seal.surface.names() {
            if !items.iter().any(|item| item.name.as_ref() == name)
                && !exports
                    .iter()
                    .any(|export| export.exported_name.as_ref() == name)
            {
                return Err(PackageError::OmittedDeclaredMember {
                    name: Arc::from(name),
                });
            }
        }
        for name in items
            .iter()
            .map(|item| item.name.as_ref())
            .chain(exports.iter().map(|export| export.exported_name.as_ref()))
        {
            if !seal.surface.contains(name) {
                return Err(PackageError::UndeclaredInterfaceMember {
                    name: Arc::from(name),
                });
            }
        }

        let mut metadata = seal.metadata.clone();
        metadata.protocol_versions.sort();
        if metadata
            .protocol_versions
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        {
            let duplicated = metadata.protocol_versions[1].0.clone();
            return Err(PackageError::DuplicateDeclaration {
                field: "protocol version",
                value: duplicated,
            });
        }
        sort_unique(&mut metadata.target_predicates);

        let mut dependencies = seal.dependencies.to_vec();
        dependencies.sort_by(|left, right| {
            left.package
                .cmp(&right.package)
                .then_with(|| left.interface.cmp(&right.interface))
        });
        if dependencies
            .windows(2)
            .any(|pair| pair[0].package == pair[1].package)
        {
            return Err(PackageError::DuplicateDeclaration {
                field: "dependency interface pin",
                value: Arc::from(dependencies[1].package.inputs().name().as_str()),
            });
        }

        // A re-export names one defining package-instance identity, and an
        // identity is reachable only through an interface the manifest pinned.
        // An export whose defining instance has no pin is therefore an unclosed
        // interface rather than a name to resolve through whatever the graph
        // happens to hold.
        for export in &exports {
            if !dependencies
                .iter()
                .any(|pin| pin.package == export.defining)
            {
                return Err(PackageError::UnpinnedExport {
                    exported_name: export.exported_name.clone(),
                    defining: export.defining.clone(),
                });
            }
        }

        let canonical = encode_interface(seal.version, &metadata, &dependencies, &exports, &items);
        let digest = InterfaceDigest::from_digest(digest_fields(INTERFACE_DOMAIN, &[&canonical]));
        Ok(Self {
            version: seal.version,
            metadata,
            dependencies,
            exports,
            items,
            canonical: Arc::from(canonical),
            digest,
        })
    }

    /// Seals one manifest, reporting an unsupported version as unproven.
    #[must_use]
    pub fn seal_versioned(seal: InterfaceSeal<'_>) -> InterfaceProof {
        if seal.version != Self::VERSION {
            return InterfaceProof::Unproven(UnprovenReason::UnsupportedInterfaceVersion(
                seal.version,
            ));
        }
        match Self::seal(seal) {
            Ok(manifest) => InterfaceProof::Proved(Box::new(manifest)),
            Err(PackageError::UnsupportedInterfaceVersion { version }) => {
                InterfaceProof::Unproven(UnprovenReason::UnsupportedInterfaceVersion(version))
            }
            Err(error) => InterfaceProof::Invalid(error),
        }
    }

    /// Returns the interface version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the selected edition.
    #[must_use]
    pub fn edition(&self) -> &str {
        &self.metadata.edition
    }

    /// Returns the standard-library contract version.
    #[must_use]
    pub const fn stdlib_contract(&self) -> ProtocolVersion {
        self.metadata.stdlib_contract
    }

    /// Returns the bound protocol versions in canonical order.
    #[must_use]
    pub fn protocol_versions(&self) -> &[(Arc<str>, ProtocolVersion)] {
        &self.metadata.protocol_versions
    }

    /// Returns the target predicates in canonical order.
    #[must_use]
    pub fn target_predicates(&self) -> &[Arc<str>] {
        &self.metadata.target_predicates
    }

    /// Returns the selected public features.
    #[must_use]
    pub const fn public_features(&self) -> &SelectedFeatureSet {
        &self.metadata.public_features
    }

    /// Returns the pinned dependency interfaces.
    #[must_use]
    pub fn dependency_interfaces(&self) -> &[DependencyInterfacePin] {
        &self.dependencies
    }

    /// Returns the recorded items in canonical order.
    #[must_use]
    pub fn items(&self) -> &[InterfaceItem] {
        &self.items
    }

    /// Returns the recorded re-exports in canonical order.
    #[must_use]
    pub fn exports(&self) -> &[ExportEntry] {
        &self.exports
    }

    /// Returns the one canonical encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the interface digest over the canonical encoding.
    #[must_use]
    pub const fn digest(&self) -> &InterfaceDigest {
        &self.digest
    }

    /// Returns one recorded item by name.
    #[must_use]
    pub fn item(&self, name: &str) -> Option<&InterfaceItem> {
        self.items.iter().find(|item| item.name.as_ref() == name)
    }

    /// Returns one recorded re-export by exported name.
    #[must_use]
    pub fn export(&self, name: &str) -> Option<&ExportEntry> {
        self.exports
            .iter()
            .find(|export| export.exported_name.as_ref() == name)
    }

    /// Returns whether the frozen interface exports one name.
    #[must_use]
    pub fn is_exported(&self, name: &str) -> bool {
        self.item(name)
            .is_some_and(|item| item.visibility.is_exported())
            || self.export(name).is_some()
    }

    /// Returns whether the frozen interface records one name at all.
    #[must_use]
    pub fn is_recorded(&self, name: &str) -> bool {
        self.item(name).is_some() || self.export(name).is_some()
    }

    /// Returns the pinned interface digest of one dependency identity.
    #[must_use]
    pub fn dependency_digest(&self, package: &PackageIdentity) -> Option<&InterfaceDigest> {
        self.dependencies
            .iter()
            .find(|pin| &pin.package == package)
            .map(|pin| &pin.interface)
    }

    /// Rejects a manifest whose identity does not match the pinned artifact.
    ///
    /// The mismatch names the expected and observed interface identities and is
    /// never repaired from a recomputed interface, from source available at the
    /// time, or from a display name.
    pub fn check_pinned(&self, pinned: &InterfaceDigest) -> Result<(), PackageError> {
        if &self.digest != pinned {
            return Err(PackageError::InterfaceMismatch {
                expected: pinned.clone(),
                observed: self.digest.clone(),
            });
        }
        Ok(())
    }

    /// Rejects non-shipping items and re-exports in a shipping interface.
    pub fn check_shipping_surface(&self, kind: TargetKind) -> Result<(), PackageError> {
        if !kind.is_shipping() {
            return Ok(());
        }
        for item in &self.items {
            if !item.target.is_shipping() {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(item.target.wire_name()),
                    condition: TargetCondition::NonShippingItemInPublicInterface,
                });
            }
        }
        for export in &self.exports {
            if !export.target.is_shipping() {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(export.target.wire_name()),
                    condition: TargetCondition::NonShippingExportInPublicInterface,
                });
            }
        }
        Ok(())
    }
}

/// The outcome of a versioned interface seal.
#[derive(Clone, Debug, Eq, PartialEq)]
// Each variant carries the full outcome: the proved manifest, the unproven
// reason, or the rejecting diagnostic. Boxing the diagnostic would hide the
// exact package error a caller matches on.
#[allow(clippy::large_enum_variant)]
pub enum InterfaceProof {
    /// The manifest is proved and carries its canonical encoding.
    Proved(Box<PublicInterfaceManifest>),
    /// The version is unsupported, so the manifest is unproven rather than accepted.
    Unproven(UnprovenReason),
    /// The manifest is a closed-interface violation.
    Invalid(PackageError),
}

impl InterfaceProof {
    /// Returns the proved manifest.
    #[must_use]
    pub fn proved(&self) -> Option<&PublicInterfaceManifest> {
        match self {
            Self::Proved(manifest) => Some(manifest),
            Self::Unproven(_) | Self::Invalid(_) => None,
        }
    }
}

/// One resolved package instance.
///
/// Two instances are distinct nominal universes exactly when their identities
/// differ, and a type declared by one is a different nominal type from a
/// structurally identical type declared by another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInstance {
    identity: PackageIdentity,
    interface: PublicInterfaceManifest,
}

impl PackageInstance {
    /// Binds one identity to the one interface it was resolved against.
    ///
    /// The identity binds the interface digest, so an interface that does not
    /// match the identity is rejected rather than relinked. A shipping
    /// instance also never binds a public interface that carries a
    /// non-shipping target's item or re-export, while a package that declares
    /// no shipping target is unaffected.
    pub fn new(
        identity: PackageIdentity,
        interface: PublicInterfaceManifest,
    ) -> Result<Self, PackageError> {
        interface.check_pinned(identity.interface_digest())?;
        for facts in identity.inputs().targets().as_slice() {
            if facts.kind().is_shipping() {
                interface.check_shipping_surface(facts.kind())?;
            }
        }
        Ok(Self {
            identity,
            interface,
        })
    }

    /// Returns the package-instance identity, which is the package identity.
    #[must_use]
    pub const fn identity(&self) -> &PackageIdentity {
        &self.identity
    }

    /// Returns the frozen public interface of this instance.
    #[must_use]
    pub const fn interface(&self) -> &PublicInterfaceManifest {
        &self.interface
    }
}

/// One name resolved to the package instance that defines it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedName {
    /// The spelling that was queried.
    exported_name: Arc<str>,
    /// The defining package instance, which is never a re-exporting facade.
    defining_instance: PackageIdentity,
    /// The defining name inside the defining package.
    defining_name: Arc<str>,
    /// The preserved item kind.
    kind: ItemKind,
    /// Every re-export hop, in traversal order, as (instance, exported name).
    chain: Vec<(PackageIdentity, Arc<str>)>,
}

impl ResolvedName {
    /// Returns the queried spelling.
    #[must_use]
    pub fn exported_name(&self) -> &str {
        &self.exported_name
    }

    /// Returns the defining package instance.
    #[must_use]
    pub const fn defining_instance(&self) -> &PackageIdentity {
        &self.defining_instance
    }

    /// Returns the defining name inside the defining package.
    #[must_use]
    pub fn defining_name(&self) -> &str {
        &self.defining_name
    }

    /// Returns the preserved item kind.
    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        self.kind
    }

    /// Returns whether the name was reached through a re-export chain.
    #[must_use]
    pub fn is_reexported(&self) -> bool {
        !self.chain.is_empty()
    }

    /// Returns every re-export hop as (instance, exported name).
    #[must_use]
    pub fn chain(&self) -> &[(PackageIdentity, Arc<str>)] {
        &self.chain
    }
}

/// One resolved graph of package instances and dependency edges.
///
/// The graph is one node per package-instance identity, so an instance reached
/// through several graph paths has exactly one identity and one node, while two
/// identities that differ in any input never merge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackageGraph {
    instances: BTreeMap<PackageIdentity, PackageInstance>,
    edges: BTreeSet<(PackageIdentity, PackageIdentity)>,
}

impl PackageGraph {
    /// Constructs one empty resolved graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one instance, returning whether a new node was created.
    ///
    /// Identical instances deduplicate to exactly one identity. An identity that
    /// is already registered is retained only when the recorded interface bytes
    /// and digest agree; a disagreement is an interface mismatch rather than a
    /// silent replacement of the interface the node was resolved against.
    pub fn register(&mut self, instance: PackageInstance) -> Result<bool, PackageError> {
        if let Some(existing) = self.instances.get(instance.identity()) {
            if existing.interface().canonical_bytes() != instance.interface().canonical_bytes()
                || existing.interface().digest() != instance.interface().digest()
            {
                return Err(PackageError::InterfaceMismatch {
                    expected: existing.interface().digest().clone(),
                    observed: instance.interface().digest().clone(),
                });
            }
            return Ok(false);
        }
        self.instances.insert(instance.identity().clone(), instance);
        Ok(true)
    }

    /// Adds one dependency edge between two resolved instances.
    pub fn link(
        &mut self,
        from: &PackageIdentity,
        to: &PackageIdentity,
    ) -> Result<bool, PackageError> {
        for endpoint in [from, to] {
            if !self.instances.contains_key(endpoint) {
                return Err(PackageError::UnknownInstance {
                    package: endpoint.clone(),
                });
            }
        }
        self.check_edge_pins(from, to)?;
        Ok(self.edges.insert((from.clone(), to.clone())))
    }

    /// Registers one unordered discovery result and its dependency edges.
    ///
    /// The outcome depends only on the supplied multiset, never on the order in
    /// which instances and edges are enumerated.
    pub fn register_discovered(
        &mut self,
        discovered: &[PackageInstance],
        edges: &[(PackageIdentity, PackageIdentity)],
    ) -> Result<(), PackageError> {
        for instance in discovered {
            self.register(instance.clone())?;
        }
        for (from, to) in edges {
            self.link(from, to)?;
        }
        // The discovery outcome depends only on the supplied multiset, so the
        // recorded pins are verified over the complete resolved graph rather than
        // against whichever instances happened to be registered first.
        self.check_pins()?;
        Ok(())
    }

    /// Verifies every recorded dependency pin against the registered instances.
    ///
    /// A pin is satisfied only by the registered instance with the pinned
    /// package-instance identity carrying exactly the pinned interface digest. An
    /// instance that pins a package the graph holds at another interface digest
    /// is rejected as `package-instance-interface-mismatch`, and a pin that names
    /// no registered package at all is rejected as an unresolved instance, so an
    /// interface is never reached through whatever the graph happens to hold.
    pub fn check_pins(&self) -> Result<(), PackageError> {
        for instance in self.instances.values() {
            for pin in instance.interface().dependency_interfaces() {
                self.check_registered_interface(&pin.package, &pin.interface)?;
            }
        }
        Ok(())
    }

    /// Rejects one registered interface that disagrees with one pinned digest.
    fn check_registered_interface(
        &self,
        identity: &PackageIdentity,
        pinned: &InterfaceDigest,
    ) -> Result<(), PackageError> {
        match self.instances.get(identity) {
            Some(instance) if instance.interface().digest() != pinned => {
                Err(PackageError::InterfaceMismatch {
                    expected: pinned.clone(),
                    observed: instance.interface().digest().clone(),
                })
            }
            Some(_) => Ok(()),
            None => Err(self.absent_interface_error(identity, pinned)),
        }
    }

    /// Returns the diagnosed condition of one pin that no registered node satisfies.
    ///
    /// The same package name and version registered at another interface digest is
    /// a stale pin, and the reported failure names both interface identities.
    fn absent_interface_error(
        &self,
        identity: &PackageIdentity,
        pinned: &InterfaceDigest,
    ) -> PackageError {
        match self
            .instances
            .values()
            .find(|instance| same_package(instance.identity(), identity))
        {
            Some(instance) => PackageError::InterfaceMismatch {
                expected: pinned.clone(),
                observed: instance.interface().digest().clone(),
            },
            None => PackageError::UnknownInstance {
                package: identity.clone(),
            },
        }
    }

    /// Rejects one edge whose endpoints disagree about the reached interface.
    ///
    /// Every pin is compared by exact package-instance identity, never by
    /// package name and version: two instances of one name and version are
    /// distinct universes, so a pin that addresses a sibling instance is not a
    /// disagreement about this edge and MUST NOT be read as one.
    fn check_edge_pins(
        &self,
        from: &PackageIdentity,
        to: &PackageIdentity,
    ) -> Result<(), PackageError> {
        let (Some(manifest), Some(instance)) = (self.interface(from), self.instances.get(to))
        else {
            return Ok(());
        };
        for pin in manifest.dependency_interfaces() {
            if pin.package == *to && pin.interface != *instance.interface().digest() {
                return Err(PackageError::InterfaceMismatch {
                    expected: pin.interface.clone(),
                    observed: instance.interface().digest().clone(),
                });
            }
        }
        Ok(())
    }

    /// Iterates every instance in canonical identity order.
    pub fn instances(&self) -> impl Iterator<Item = &PackageInstance> {
        self.instances.values()
    }

    /// Returns one resolved instance.
    #[must_use]
    pub fn instance(&self, identity: &PackageIdentity) -> Option<&PackageInstance> {
        self.instances.get(identity)
    }

    /// Returns the frozen interface of one resolved instance.
    #[must_use]
    pub fn interface(&self, identity: &PackageIdentity) -> Option<&PublicInterfaceManifest> {
        self.instances.get(identity).map(PackageInstance::interface)
    }

    /// Returns the number of resolved nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Returns whether no instance is resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Returns the number of dependency edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns the one canonical encoding of the resolved graph.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = String::from("{\"edges\":[");
        for (index, (from, to)) in self.edges.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('[');
            push_json_string(&mut output, &from.as_str());
            output.push(',');
            push_json_string(&mut output, &to.as_str());
            output.push(']');
        }
        output.push_str("],\"instances\":[");
        for (index, instance) in self.instances.values().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str("{\"identity\":");
            push_json_string(&mut output, &instance.identity().as_str());
            output.push_str(",\"interface\":");
            push_json_string(&mut output, instance.interface().digest().as_str());
            output.push('}');
        }
        output.push_str("]}");
        output.into_bytes()
    }

    /// Rejects a dependency cycle among package instances.
    ///
    /// The walk starts from the smallest identity and visits successors in
    /// identity order, so the reported cycle does not depend on traversal order.
    pub fn validate_acyclic(&self) -> Result<(), PackageError> {
        let mut state: BTreeMap<&PackageIdentity, u8> = BTreeMap::new();
        let mut path: Vec<&PackageIdentity> = Vec::new();
        for node in self.instances.keys() {
            if state.get(node).copied().unwrap_or(0) == 0 {
                self.visit(node, &mut state, &mut path)?;
            }
        }
        Ok(())
    }

    fn visit<'a>(
        &'a self,
        node: &'a PackageIdentity,
        state: &mut BTreeMap<&'a PackageIdentity, u8>,
        path: &mut Vec<&'a PackageIdentity>,
    ) -> Result<(), PackageError> {
        state.insert(node, 1);
        path.push(node);
        for successor in self.successors(node) {
            match state.get(successor).copied().unwrap_or(0) {
                1 => {
                    let start = path
                        .iter()
                        .position(|candidate| *candidate == successor)
                        .unwrap_or(0);
                    return Err(PackageError::DependencyCycle {
                        cycle: path[start..]
                            .iter()
                            .map(|candidate| (*candidate).clone())
                            .collect(),
                    });
                }
                0 => self.visit(successor, state, path)?,
                _ => {}
            }
        }
        path.pop();
        state.insert(node, 2);
        Ok(())
    }

    fn successors<'a>(&'a self, node: &'a PackageIdentity) -> Vec<&'a PackageIdentity> {
        self.edges
            .iter()
            .filter(|(from, _)| from == node)
            .map(|(_, to)| to)
            .collect()
    }

    /// Returns whether one resolved instance has a dependency with this name.
    fn has_dependency_named(&self, from: &PackageIdentity, name: &str) -> bool {
        self.successors(from)
            .into_iter()
            .any(|successor| successor.inputs().name().as_str() == name)
    }

    /// Returns whether one resolved instance records one name at all.
    fn records_name(&self, from: &PackageIdentity, name: &str) -> bool {
        self.interface(from)
            .is_some_and(|manifest| manifest.is_recorded(name))
    }

    /// Resolves one name in one instance, following re-export chains.
    ///
    /// Reachability is decided against the frozen interfaces, so a re-export
    /// preserves the defining package identity and kind, a chain is accepted
    /// only when every link is exported, and a chain that never terminates in a
    /// defining exported item is reported as a cycle rather than as an
    /// unresolved name. Every link MUST also be pinned by the re-exporting
    /// manifest at exactly the interface digest the graph holds for the defining
    /// instance, so a re-export never reaches whatever interface the graph
    /// happens to contain. A name resolved from an instance that declares a
    /// shipping target MUST terminate in an item that target kinds can ship, so
    /// a re-export never routes a non-shipping target's item into a shipping
    /// public interface.
    pub fn resolve_name(
        &self,
        from: &PackageIdentity,
        name: &str,
    ) -> Result<ResolvedName, PackageError> {
        self.check_pins()?;
        // Binding covers the manifest's own records; this covers names reached
        // across dependency edges, however many re-export hops they take.
        let origin_is_shipping = self.instances.get(from).is_some_and(|instance| {
            instance
                .identity()
                .inputs()
                .targets()
                .as_slice()
                .iter()
                .any(|facts| facts.kind().is_shipping())
        });
        let mut current = from.clone();
        let mut lookup: Arc<str> = Arc::from(name);
        let mut chain: Vec<(PackageIdentity, Arc<str>)> = Vec::new();
        let mut visited: BTreeSet<(PackageIdentity, Arc<str>)> = BTreeSet::new();
        loop {
            if !visited.insert((current.clone(), lookup.clone())) {
                return Err(PackageError::ReexportCycle {
                    package: current,
                    name: lookup,
                });
            }
            let manifest =
                self.interface(&current)
                    .ok_or_else(|| PackageError::UnknownInstance {
                        package: current.clone(),
                    })?;
            if let Some(item) = manifest.item(&lookup) {
                if !item.visibility.is_exported() {
                    return Err(PackageError::ItemNotExported {
                        package: current,
                        name: lookup,
                    });
                }
                if origin_is_shipping && !item.target.is_shipping() {
                    return Err(PackageError::TargetKindInvalid {
                        kind: Arc::from(item.target.wire_name()),
                        condition: TargetCondition::NonShippingItemInPublicInterface,
                    });
                }
                return Ok(ResolvedName {
                    exported_name: Arc::from(name),
                    defining_instance: current,
                    defining_name: item.name.clone(),
                    kind: item.kind,
                    chain,
                });
            }
            let export = manifest
                .export(&lookup)
                .ok_or_else(|| PackageError::ItemNotExported {
                    package: current.clone(),
                    name: lookup.clone(),
                })?;
            let target = export.defining.clone();
            let pinned = manifest
                .dependency_digest(&target)
                .cloned()
                .ok_or_else(|| PackageError::UnpinnedExport {
                    exported_name: export.exported_name.clone(),
                    defining: target.clone(),
                })?;
            self.check_registered_interface(&target, &pinned)?;
            let next_name = export.defining_name.clone();
            chain.push((current, lookup));
            current = target;
            lookup = next_name;
        }
    }

    /// Returns the item one resolution terminates in.
    ///
    /// Every requirement, recovery class, mode restriction, and provenance fact
    /// is read from the defining package instance, so a facade cannot erase
    /// them.
    pub fn defined_item(&self, resolved: &ResolvedName) -> Result<&InterfaceItem, PackageError> {
        let manifest = self
            .interface(resolved.defining_instance())
            .ok_or_else(|| PackageError::UnknownInstance {
                package: resolved.defining_instance().clone(),
            })?;
        manifest
            .item(resolved.defining_name())
            .ok_or_else(|| PackageError::ItemNotExported {
                package: resolved.defining_instance().clone(),
                name: Arc::from(resolved.defining_name()),
            })
    }
}

/// One exact dependency alias.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DependencyAlias(Arc<str>);

impl DependencyAlias {
    /// Validates one alias spelling under the landed identifier rules.
    pub fn new(value: &str) -> Result<Self, PackageError> {
        validate_identifier("alias", value).map_err(|_| PackageError::InvalidAlias {
            spelling: Arc::from(value),
        })?;
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact alias spelling, which is local source spelling only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One direct dependency and the one instance its alias binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyDeclaration {
    alias: DependencyAlias,
    instance: PackageIdentity,
}

impl DependencyDeclaration {
    /// Returns the local alias spelling.
    #[must_use]
    pub const fn alias(&self) -> &DependencyAlias {
        &self.alias
    }

    /// Returns the one instance this alias binds.
    #[must_use]
    pub const fn instance(&self) -> &PackageIdentity {
        &self.instance
    }
}

/// The local names one declaring package instance already occupies.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeclaredNamespaces {
    /// Local module names.
    pub modules: BTreeSet<Arc<str>>,
    /// Ordinary item names.
    pub items: BTreeSet<Arc<str>>,
    /// Agent names.
    pub agents: BTreeSet<Arc<str>>,
    /// Capability slots.
    pub capability_slots: BTreeSet<Arc<str>>,
    /// Reserved words of the selected edition.
    pub reserved_words: BTreeSet<Arc<str>>,
}

impl DeclaredNamespaces {
    /// Constructs one empty namespace record.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts one module name.
    pub fn with_module(mut self, name: &str) -> Self {
        self.modules.insert(Arc::from(name));
        self
    }

    /// Inserts one ordinary item name.
    pub fn with_item(mut self, name: &str) -> Self {
        self.items.insert(Arc::from(name));
        self
    }

    /// Inserts one agent name.
    pub fn with_agent(mut self, name: &str) -> Self {
        self.agents.insert(Arc::from(name));
        self
    }

    /// Inserts one capability slot.
    pub fn with_capability_slot(mut self, name: &str) -> Self {
        self.capability_slots.insert(Arc::from(name));
        self
    }

    /// Inserts one reserved word of the selected edition.
    pub fn with_reserved_word(mut self, name: &str) -> Self {
        self.reserved_words.insert(Arc::from(name));
        self
    }
}

/// The dependency namespace of one declaring package instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaringPackageScope {
    instance: PackageIdentity,
    namespaces: DeclaredNamespaces,
    dependencies: Vec<DependencyDeclaration>,
}

impl DeclaringPackageScope {
    /// Constructs one declaring scope over the names the instance occupies.
    #[must_use]
    pub const fn new(instance: PackageIdentity, namespaces: DeclaredNamespaces) -> Self {
        Self {
            instance,
            namespaces,
            dependencies: Vec::new(),
        }
    }

    /// Returns the declaring package instance.
    #[must_use]
    pub const fn instance(&self) -> &PackageIdentity {
        &self.instance
    }

    /// Returns the declared direct dependencies in declaration order.
    #[must_use]
    pub fn dependencies(&self) -> &[DependencyDeclaration] {
        &self.dependencies
    }

    /// Declares one direct dependency under exactly one explicit alias.
    ///
    /// A collision is a static error rather than a resolution preference, so no
    /// alias is ever silently shadowed.
    pub fn declare_dependency(
        &mut self,
        alias: &str,
        instance: PackageIdentity,
    ) -> Result<DependencyAlias, PackageError> {
        let alias = DependencyAlias::new(alias)?;
        self.check_alias_collisions(&alias, false)?;
        self.dependencies.push(DependencyDeclaration {
            alias: alias.clone(),
            instance,
        });
        Ok(alias)
    }

    /// Declares one synthesized alias for one external package identity.
    ///
    /// The synthesized spelling MUST be rejected on reserved-word status,
    /// canonical normalization, case, or truncation collision with a name
    /// already in the declaring package's dependency or item namespace. The
    /// same inputs produce the same alias and the same alias map independently
    /// of discovery or enumeration order.
    pub fn declare_synthesized_dependency(
        &mut self,
        package_name: &str,
        instance: PackageIdentity,
    ) -> Result<DependencyAlias, PackageError> {
        let synthesized = synthesize_alias(package_name);
        if !is_nfc(&synthesized) {
            return Err(PackageError::AliasCollision {
                namespace: AliasNamespace::DependencyAlias,
                alias: Arc::from(synthesized.as_str()),
                conflicting: Arc::from(package_name),
                condition: CollisionCondition::Normalization,
            });
        }
        let alias = DependencyAlias::new(synthesized.as_str())?;
        self.check_alias_collisions(&alias, true)?;
        self.dependencies.push(DependencyDeclaration {
            alias: alias.clone(),
            instance,
        });
        Ok(alias)
    }

    /// Rejects one alias that collides with a name its declaring package occupies.
    ///
    /// An explicit alias is compared exactly and case-sensitively in every
    /// namespace, because `GNT-4.12` requires identifier equality to compare the
    /// exact NFC scalar sequence without case folding. A synthesized alias is
    /// additionally rejected under the one symmetric collision relation of
    /// `GNT-16.3-dependency-aliases`, which admits reserved-word status,
    /// canonical normalization, case, truncation, and confusable similarity. All
    /// six namespaces of the declaring package are checked by that one relation,
    /// and the reported pair is ordered, so the diagnostic depends only on the two
    /// colliding spellings and not on which of them was declared second.
    fn check_alias_collisions(
        &self,
        alias: &DependencyAlias,
        synthesized: bool,
    ) -> Result<(), PackageError> {
        if self.namespaces.reserved_words.contains(alias.as_str()) {
            return Err(alias_collision(
                AliasNamespace::ReservedWord,
                alias.as_str(),
                alias.as_str(),
                CollisionCondition::ReservedWord,
            ));
        }
        let mut occupied = Vec::new();
        for (namespace, names) in [
            (AliasNamespace::Module, &self.namespaces.modules),
            (AliasNamespace::Item, &self.namespaces.items),
            (AliasNamespace::Agent, &self.namespaces.agents),
            (
                AliasNamespace::CapabilitySlot,
                &self.namespaces.capability_slots,
            ),
        ] {
            for name in names.iter() {
                occupied.push((namespace, name.as_ref()));
            }
        }
        for declaration in &self.dependencies {
            if declaration.alias == *alias {
                return Err(PackageError::DuplicateAlias {
                    alias: Arc::from(alias.as_str()),
                });
            }
            occupied.push((AliasNamespace::DependencyAlias, declaration.alias.as_str()));
        }
        for (namespace, name) in occupied {
            let condition = if synthesized {
                collision_condition(alias.as_str(), name)
            } else if name == alias.as_str() {
                Some(CollisionCondition::Exact)
            } else {
                None
            };
            if let Some(condition) = condition {
                return Err(alias_collision(namespace, alias.as_str(), name, condition));
            }
        }
        Ok(())
    }

    /// Resolves one alias to the one instance it binds.
    ///
    /// Resolution searches the declared dependency namespace only, so it never
    /// falls back to filesystem layout, a host name, a registry display name, a
    /// transitive graph path, or discovery order.
    pub fn resolve_alias(&self, alias: &str) -> Result<&PackageIdentity, PackageError> {
        self.dependencies
            .iter()
            .find(|declaration| declaration.alias.as_str() == alias)
            .map(|declaration| &declaration.instance)
            .ok_or_else(|| PackageError::AliasUnresolved {
                spelling: Arc::from(alias),
            })
    }

    /// Returns the machine-readable alias-to-identity map.
    #[must_use]
    pub fn alias_map(&self) -> AliasMap {
        let mut entries = self
            .dependencies
            .iter()
            .map(|declaration| (declaration.alias.clone(), declaration.instance.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut canonical = String::from("{\"dependencies\":[");
        for (index, (alias, instance)) in entries.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str("{\"alias\":");
            push_json_string(&mut canonical, alias.as_str());
            canonical.push_str(",\"package\":");
            push_json_string(&mut canonical, &instance.as_str());
            canonical.push('}');
        }
        canonical.push_str("]}");
        let digest = digest_fields(ALIAS_MAP_DOMAIN, &[canonical.as_bytes()]);
        AliasMap {
            entries,
            canonical: Arc::from(canonical.into_bytes()),
            digest,
        }
    }

    /// Returns whether one unqualified name is local to the declaring package.
    #[must_use]
    pub fn is_local_name(&self, name: &str) -> bool {
        self.namespaces.items.contains(name) || self.namespaces.modules.contains(name)
    }

    /// Resolves one unqualified name, which stays lexical and package-local.
    ///
    /// An unqualified name never resolves into a dependency; the only way an
    /// external item becomes nameable through an unqualified name is an explicit
    /// import that names the item through the alias. An imported name is resolved
    /// through the resolved graph rather than from the import declaration alone,
    /// so a target that is absent from the graph or not exported by its frozen
    /// interface is reported instead of accepted.
    pub fn resolve_unqualified(
        &self,
        graph: &PackageGraph,
        imports: &ImportSet,
        name: &str,
    ) -> Result<UnqualifiedResolution, PackageError> {
        match (self.is_local_name(name), imports.get(name)) {
            (true, None) => Ok(UnqualifiedResolution::LexicalLocal {
                name: Arc::from(name),
            }),
            (true, Some(_)) => Err(PackageError::UnqualifiedNameAmbiguous {
                name: Arc::from(name),
            }),
            (false, Some(import)) => {
                let resolved = self.resolve_qualified(graph, import.path())?;
                Ok(UnqualifiedResolution::Imported {
                    local_name: Arc::from(name),
                    alias: Arc::from(import.path().alias()),
                    item: Arc::from(import.path().item()),
                    defining_instance: Box::new(resolved.defining_instance().clone()),
                })
            }
            (false, None) => Err(PackageError::UnqualifiedNameNotLocal {
                name: Arc::from(name),
            }),
        }
    }

    /// Resolves one alias-qualified path against one resolved graph.
    ///
    /// The first segment is the alias; the second segment MUST be an exported
    /// item of the bound instance, and every further segment MUST be a recorded
    /// member of that item. A segment that names a dependency of the bound
    /// instance is reported as an undeclared transitive access; the name is used
    /// only to select that diagnostic and never resolves through it.
    pub fn resolve_qualified(
        &self,
        graph: &PackageGraph,
        path: &QualifiedPath,
    ) -> Result<ResolvedName, PackageError> {
        let instance = self.resolve_alias(path.alias())?.clone();
        let resolved = match graph.resolve_name(&instance, path.item()) {
            Ok(resolved) => resolved,
            // A name the bound instance records is a visibility or termination
            // failure of that instance, even when one of its dependencies happens
            // to share the name. Only a name that instance does not record at all
            // can be a name reachable solely through an undeclared transitive
            // edge.
            Err(PackageError::ItemNotExported { .. })
                if !graph.records_name(&instance, path.item())
                    && graph.has_dependency_named(&instance, path.item()) =>
            {
                return Err(PackageError::TransitiveUndeclared {
                    package: Arc::from(path.item()),
                    accessed: Arc::from(path.as_string()),
                });
            }
            Err(error) => return Err(error),
        };
        for member in path.members() {
            let item = graph.defined_item(&resolved)?;
            if !item.declares_member(member) {
                return Err(PackageError::ItemNotExported {
                    package: resolved.defining_instance().clone(),
                    name: member.clone(),
                });
            }
        }
        Ok(resolved)
    }
}

/// Returns one collision error with its colliding pair in canonical order.
///
/// The pair is ordered by exact spelling, so the same two colliding names produce
/// the same diagnostic under either declaration order, which is what
/// `GNT-16.9-resolution-order-independence` requires of a diagnostic.
fn alias_collision(
    namespace: AliasNamespace,
    left: &str,
    right: &str,
    condition: CollisionCondition,
) -> PackageError {
    let (alias, conflicting) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    PackageError::AliasCollision {
        namespace,
        alias: Arc::from(alias),
        conflicting: Arc::from(conflicting),
        condition,
    }
}

/// Returns the symmetric collision relation between two alias spellings.
///
/// The relation is symmetric, so the same pair returns the same condition in
/// either order and no declaration order can decide whether a pair collides. It
/// is applied to a synthesized alias, where `GNT-16.3-dependency-aliases` admits
/// rejection by reserved-word status, canonical normalization, case, truncation,
/// or confusable similarity; an explicit alias is compared exactly under
/// `GNT-4.12`.
fn collision_condition(candidate: &str, existing: &str) -> Option<CollisionCondition> {
    if candidate == existing {
        return Some(CollisionCondition::Exact);
    }
    if case_fold(candidate) == case_fold(existing) {
        return Some(CollisionCondition::Case);
    }
    if candidate.starts_with(existing) || existing.starts_with(candidate) {
        return Some(CollisionCondition::Truncation);
    }
    None
}

/// Returns the deterministic alias spelling for one external package name.
///
/// Identifier security algorithms, including confusable and mixed-script
/// policy, are owned by IDENT-001; this derivation only replaces the separator
/// characters that a package name admits and an alias identifier does not, and
/// leaves every collision rejection to the declaring scope.
fn synthesize_alias(package_name: &str) -> String {
    package_name
        .chars()
        .map(|scalar| match scalar {
            '-' | '.' | '/' => '_',
            scalar => scalar,
        })
        .collect()
}

/// One deterministic machine-readable alias-to-identity map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasMap {
    entries: Vec<(DependencyAlias, PackageIdentity)>,
    canonical: Arc<[u8]>,
    digest: [u8; 32],
}

impl AliasMap {
    /// Returns the alias-to-identity entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[(DependencyAlias, PackageIdentity)] {
        &self.entries
    }

    /// Returns the one canonical encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the lowercase hexadecimal map digest.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        encode_hex(&self.digest)
    }
}

/// One alias-qualified source path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedPath {
    segments: Vec<Arc<str>>,
}

impl QualifiedPath {
    /// Validates one alias-qualified path of at least two segments.
    pub fn new(value: &str) -> Result<Self, PackageError> {
        let segments = value.split("::").collect::<Vec<_>>();
        if segments.len() < 2 {
            return Err(PackageError::InvalidDeclaration {
                field: "qualified path",
                value: Arc::from(value),
            });
        }
        for segment in &segments {
            validate_identifier("qualified path segment", segment)?;
        }
        Ok(Self {
            segments: segments.into_iter().map(Arc::from).collect(),
        })
    }

    /// Returns the first segment, which is the alias spelling.
    #[must_use]
    pub fn alias(&self) -> &str {
        self.segments.first().map(AsRef::as_ref).unwrap_or("")
    }

    /// Returns the second segment, which is the item name inside the instance.
    #[must_use]
    pub fn item(&self) -> &str {
        self.segments.get(1).map(AsRef::as_ref).unwrap_or("")
    }

    /// Returns every segment after the item name.
    #[must_use]
    pub fn members(&self) -> &[Arc<str>] {
        self.segments.get(2..).unwrap_or(&[])
    }

    /// Returns every segment in order.
    #[must_use]
    pub fn segments(&self) -> &[Arc<str>] {
        &self.segments
    }

    /// Returns the exact path spelling.
    #[must_use]
    pub fn as_string(&self) -> String {
        self.segments
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>()
            .join("::")
    }
}

/// One explicit import that names an external item through an alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Import {
    local_name: Arc<str>,
    path: QualifiedPath,
}

impl Import {
    /// Constructs one explicit import of one alias-qualified path.
    ///
    /// An import introduces the item under the item's own name: the landed `use`
    /// declaration of `GNT-13.3` admits no alias and no rename, so a local name
    /// that differs from the path item is invalid rather than a second binding.
    pub fn new(local_name: &str, path: QualifiedPath) -> Result<Self, PackageError> {
        validate_identifier("import name", local_name)?;
        if local_name != path.item() {
            return Err(PackageError::InvalidDeclaration {
                field: "import name",
                value: Arc::from(local_name),
            });
        }
        Ok(Self {
            local_name: Arc::from(local_name),
            path,
        })
    }

    /// Returns the local spelling the import introduces.
    #[must_use]
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Returns the alias-qualified path the import names.
    #[must_use]
    pub const fn path(&self) -> &QualifiedPath {
        &self.path
    }
}

/// One set of explicit imports of one declaring package instance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportSet(Vec<Import>);

impl ImportSet {
    /// Builds one import set, rejecting a duplicated local name.
    pub fn new(imports: &[Import]) -> Result<Self, PackageError> {
        let mut imports = imports.to_vec();
        imports.sort_by(|left, right| left.local_name.cmp(&right.local_name));
        if imports
            .windows(2)
            .any(|pair| pair[0].local_name == pair[1].local_name)
        {
            return Err(PackageError::DuplicateDeclaration {
                field: "import",
                value: imports[1].local_name.clone(),
            });
        }
        Ok(Self(imports))
    }

    /// Returns one import by its local name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Import> {
        self.0
            .iter()
            .find(|import| import.local_name.as_ref() == name)
    }

    /// Returns every import in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[Import] {
        &self.0
    }
}

/// The outcome of one unqualified lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnqualifiedResolution {
    /// The name is lexical and package-local.
    LexicalLocal {
        /// The resolved local name.
        name: Arc<str>,
    },
    /// The name is reachable only through one explicit import.
    Imported {
        /// The local spelling the import introduces.
        local_name: Arc<str>,
        /// The alias the import names the item through.
        alias: Arc<str>,
        /// The item name inside the bound instance.
        item: Arc<str>,
        /// The defining package instance the resolved import reaches.
        ///
        /// The identity is boxed so that one unqualified resolution stays small
        /// while still naming the package the import was resolved against.
        defining_instance: Box<PackageIdentity>,
    },
}

/// One declared target of one package manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDescriptor {
    kind: TargetKind,
    name: Arc<str>,
    root: Option<Arc<str>>,
    entry_points: Vec<CanonicalPath>,
}

impl TargetDescriptor {
    /// Constructs one target under the per-kind entry-point rules.
    ///
    /// The host root spelling is recorded for manifest completeness but never
    /// enters package, target, or interface identity.
    pub fn new(
        kind: TargetKind,
        name: &str,
        entry_points: &[CanonicalPath],
    ) -> Result<Self, PackageError> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(PackageError::InvalidDeclaration {
                field: "target name",
                value: Arc::from(name),
            });
        }
        match (kind, entry_points.len()) {
            (TargetKind::Library, 1..) => {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(kind.wire_name()),
                    condition: TargetCondition::LibraryDeclaresEntryPoint,
                });
            }
            (TargetKind::Binary, 0) => {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(kind.wire_name()),
                    condition: TargetCondition::MissingEntryPoint,
                });
            }
            (TargetKind::Binary, 2..) => {
                return Err(PackageError::TargetKindInvalid {
                    kind: Arc::from(kind.wire_name()),
                    condition: TargetCondition::MultipleEntryPoints,
                });
            }
            _ => {}
        }
        let mut entry_points = entry_points.to_vec();
        entry_points.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(Self {
            kind,
            name: Arc::from(name),
            root: None,
            entry_points,
        })
    }

    /// Returns the target kind.
    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    /// Returns the target name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the recorded host root spelling, when one was recorded.
    #[must_use]
    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }

    /// Records one host root spelling for manifest completeness only.
    ///
    /// Physical crate layout is nonsemantic: the recorded spelling is never an
    /// input of package, target, or interface identity, and two hosts with
    /// different physical layouts derive the same identities for the same
    /// declaration set.
    #[must_use]
    pub fn with_root(mut self, root: &str) -> Self {
        self.root = Some(Arc::from(root));
        self
    }

    /// Returns the declared entry points in canonical order.
    #[must_use]
    pub fn entry_points(&self) -> &[CanonicalPath] {
        &self.entry_points
    }
}

/// The `targets[]` collection of one package manifest.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetSet(Vec<TargetDescriptor>);

impl TargetSet {
    /// Builds one target set, rejecting a duplicated target name.
    pub fn new(targets: &[TargetDescriptor]) -> Result<Self, PackageError> {
        let mut targets = targets.to_vec();
        targets.sort_by(|left, right| left.name.cmp(&right.name));
        if targets.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(PackageError::DuplicateDeclaration {
                field: "target",
                value: targets[1].name.clone(),
            });
        }
        Ok(Self(targets))
    }

    /// Returns every target in canonical order.
    #[must_use]
    pub fn targets(&self) -> &[TargetDescriptor] {
        &self.0
    }

    /// Returns whether the set declares one shipping target.
    #[must_use]
    pub fn has_shipping_target(&self) -> bool {
        self.0.iter().any(|target| target.kind.is_shipping())
    }
}

/// One declarative capability ceiling.
///
/// A ceiling bounds and never grants: it is not the semantic source of truth for
/// preflight, and it cannot admit an operation, substitute for a resolved
/// requirement, or relax a recovery class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredCeiling {
    subject: Arc<str>,
    strength: u8,
}

impl DeclaredCeiling {
    /// Declares one ceiling over one requirement subject.
    pub fn new(subject: &str, strength: u8) -> Result<Self, PackageError> {
        validate_identifier("ceiling subject", subject)?;
        Ok(Self {
            subject: Arc::from(subject),
            strength,
        })
    }

    /// Returns the ceiling subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the declared strength bound.
    #[must_use]
    pub const fn strength(&self) -> u8 {
        self.strength
    }
}

/// One resolved requirement demand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequirementDemand {
    subject: Arc<str>,
    strength: u8,
}

impl RequirementDemand {
    /// Constructs one resolved requirement demand.
    pub fn new(subject: &str, strength: u8) -> Result<Self, PackageError> {
        validate_identifier("requirement subject", subject)?;
        Ok(Self {
            subject: Arc::from(subject),
            strength,
        })
    }

    /// Returns the requirement subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the resolved strength.
    #[must_use]
    pub const fn strength(&self) -> u8 {
        self.strength
    }
}

/// Rejects one resolved requirement that exceeds a declared ceiling.
///
/// The check is one-directional: a ceiling that covers a demand admits the
/// demand for preflight comparison only and grants nothing.
pub fn check_ceiling(
    ceiling: &DeclaredCeiling,
    demand: &RequirementDemand,
) -> Result<(), PackageError> {
    if ceiling.subject != demand.subject || demand.strength > ceiling.strength {
        return Err(PackageError::RequirementExceedsCeiling {
            subject: demand.subject.clone(),
        });
    }
    Ok(())
}

/// The five reportable compatibility axes of `GNT-16.8-compatibility-axes`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompatibilityAxis {
    /// Whether downstream source still analyzes against the replacement.
    Source,
    /// Whether the versioned boundary schemas accept and produce the same values.
    BoundarySchema,
    /// Whether exported calls can reach effects or requirements absent before.
    Authority,
    /// Whether documented guarantees remain valid.
    DeclaredBehaviour,
    /// Whether a linked executable may be replaced and a durable run may resume.
    DurableArtifact,
}

impl CompatibilityAxis {
    /// Every axis, in the reporting order of this module.
    pub const ALL: [Self; 5] = [
        Self::Source,
        Self::BoundarySchema,
        Self::Authority,
        Self::DeclaredBehaviour,
        Self::DurableArtifact,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::BoundarySchema => "boundary-schema",
            Self::Authority => "authority",
            Self::DeclaredBehaviour => "declared-behaviour",
            Self::DurableArtifact => "durable-artifact",
        }
    }

    /// Returns the landed compatibility class this axis refines.
    #[must_use]
    pub const fn landed_class(self) -> u8 {
        match self {
            Self::Source | Self::BoundarySchema => 1,
            Self::Authority => 2,
            Self::DeclaredBehaviour => 3,
            Self::DurableArtifact => 4,
        }
    }
}

/// One boundary surface whose acceptance is compared on the boundary-schema axis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BoundarySchemaSurface {
    /// The versioned entry schema.
    Entry,
    /// The action schema.
    Action,
    /// The model schema.
    Model,
    /// The tool schema.
    Tool,
    /// The artifact schema.
    Artifact,
    /// The protected-reference schema.
    ProtectedReference,
}

impl BoundarySchemaSurface {
    /// Every surface, in the reporting order of this module.
    pub const ALL: [Self; 6] = [
        Self::Entry,
        Self::Action,
        Self::Model,
        Self::Tool,
        Self::Artifact,
        Self::ProtectedReference,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Action => "action",
            Self::Model => "model",
            Self::Tool => "tool",
            Self::Artifact => "artifact",
            Self::ProtectedReference => "protected-reference",
        }
    }
}

/// One distinct durable-artifact sub-relation of the durable-artifact axis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DurableArtifactRelation {
    /// Whether an already linked executable may be replaced by the candidate.
    LinkedReplacement,
    /// Whether an existing durable run may resume on the candidate.
    DurableResume,
}

impl DurableArtifactRelation {
    /// Every sub-relation, which MUST NOT be merged into one verdict.
    pub const ALL: [Self; 2] = [Self::LinkedReplacement, Self::DurableResume];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::LinkedReplacement => "linked-replacement",
            Self::DurableResume => "durable-resume",
        }
    }
}

/// The reported verdict of one compared axis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AxisVerdict {
    /// The axis changed.
    Changed,
    /// The axis is compatible.
    Unchanged,
    /// The axis was not checked, which is never a compatibility claim.
    NotChecked,
}

impl AxisVerdict {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::NotChecked => "not-checked",
        }
    }
}

/// One reported axis verdict and its machine-checked flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AxisReport {
    axis: CompatibilityAxis,
    machine_checked: bool,
    verdict: AxisVerdict,
}

impl AxisReport {
    /// Constructs one axis report, rejecting a self-contradicting flag.
    pub fn new(
        axis: CompatibilityAxis,
        machine_checked: bool,
        verdict: AxisVerdict,
    ) -> Result<Self, PackageError> {
        if verdict == AxisVerdict::NotChecked && machine_checked {
            return Err(PackageError::NotCheckedAxisMarkedChecked { axis });
        }
        if verdict == AxisVerdict::Unchanged && !machine_checked {
            return Err(PackageError::UncheckedAxisReportedAsCompatible { axis });
        }
        Ok(Self {
            axis,
            machine_checked,
            verdict,
        })
    }

    /// Returns the axis.
    #[must_use]
    pub const fn axis(&self) -> CompatibilityAxis {
        self.axis
    }

    /// Returns whether the axis was machine-checked.
    #[must_use]
    pub const fn machine_checked(&self) -> bool {
        self.machine_checked
    }

    /// Returns the reported verdict.
    #[must_use]
    pub const fn verdict(&self) -> AxisVerdict {
        self.verdict
    }
}

/// One reported boundary-schema sub-surface verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundarySchemaSubReport {
    surface: BoundarySchemaSurface,
    machine_checked: bool,
    verdict: AxisVerdict,
}

impl BoundarySchemaSubReport {
    /// Constructs one sub-surface report, rejecting a self-contradicting flag.
    pub fn new(
        surface: BoundarySchemaSurface,
        machine_checked: bool,
        verdict: AxisVerdict,
    ) -> Result<Self, PackageError> {
        if verdict == AxisVerdict::NotChecked && machine_checked {
            return Err(PackageError::NotCheckedAxisMarkedChecked {
                axis: CompatibilityAxis::BoundarySchema,
            });
        }
        if verdict == AxisVerdict::Unchanged && !machine_checked {
            return Err(PackageError::UncheckedAxisReportedAsCompatible {
                axis: CompatibilityAxis::BoundarySchema,
            });
        }
        Ok(Self {
            surface,
            machine_checked,
            verdict,
        })
    }

    /// Returns the compared boundary surface.
    #[must_use]
    pub const fn surface(&self) -> BoundarySchemaSurface {
        self.surface
    }

    /// Returns whether the surface was machine-checked.
    #[must_use]
    pub const fn machine_checked(&self) -> bool {
        self.machine_checked
    }

    /// Returns the reported verdict.
    #[must_use]
    pub const fn verdict(&self) -> AxisVerdict {
        self.verdict
    }
}

/// The boundary-schema axis, reported per surface and never collapsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundarySchemaReport(Vec<BoundarySchemaSubReport>);

impl BoundarySchemaReport {
    /// Constructs one complete per-surface report.
    ///
    /// Every surface of the axis MUST be reported exactly once; the axis has no
    /// single collapsed verdict.
    pub fn new(reports: &[BoundarySchemaSubReport]) -> Result<Self, PackageError> {
        if reports.len() != BoundarySchemaSurface::ALL.len()
            || BoundarySchemaSurface::ALL
                .iter()
                .any(|surface| !reports.iter().any(|report| report.surface == *surface))
        {
            return Err(PackageError::IncompleteCompatibilityReport {
                axis: CompatibilityAxis::BoundarySchema,
            });
        }
        let mut reports = reports.to_vec();
        reports.sort_by_key(|left| left.surface);
        Ok(Self(reports))
    }

    /// Returns every sub-surface report in canonical order.
    #[must_use]
    pub fn reports(&self) -> &[BoundarySchemaSubReport] {
        &self.0
    }

    /// Returns the verdict of one boundary surface.
    #[must_use]
    pub fn verdict(&self, surface: BoundarySchemaSurface) -> Option<AxisVerdict> {
        self.0
            .iter()
            .find(|report| report.surface == surface)
            .map(BoundarySchemaSubReport::verdict)
    }

    /// Returns whether every surface was machine-checked.
    #[must_use]
    pub fn is_fully_machine_checked(&self) -> bool {
        self.0.iter().all(BoundarySchemaSubReport::machine_checked)
    }
}

/// One reported durable-artifact sub-relation verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableArtifactSubReport {
    relation: DurableArtifactRelation,
    machine_checked: bool,
    verdict: AxisVerdict,
}

impl DurableArtifactSubReport {
    /// Constructs one sub-relation report, rejecting a self-contradicting flag.
    pub fn new(
        relation: DurableArtifactRelation,
        machine_checked: bool,
        verdict: AxisVerdict,
    ) -> Result<Self, PackageError> {
        if verdict == AxisVerdict::NotChecked && machine_checked {
            return Err(PackageError::NotCheckedAxisMarkedChecked {
                axis: CompatibilityAxis::DurableArtifact,
            });
        }
        if verdict == AxisVerdict::Unchanged && !machine_checked {
            return Err(PackageError::UncheckedAxisReportedAsCompatible {
                axis: CompatibilityAxis::DurableArtifact,
            });
        }
        Ok(Self {
            relation,
            machine_checked,
            verdict,
        })
    }

    /// Returns the compared sub-relation.
    #[must_use]
    pub const fn relation(&self) -> DurableArtifactRelation {
        self.relation
    }

    /// Returns whether the sub-relation was machine-checked.
    #[must_use]
    pub const fn machine_checked(&self) -> bool {
        self.machine_checked
    }

    /// Returns the reported verdict.
    #[must_use]
    pub const fn verdict(&self) -> AxisVerdict {
        self.verdict
    }
}

/// The durable-artifact axis, reported per sub-relation and never merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableArtifactReport(Vec<DurableArtifactSubReport>);

impl DurableArtifactReport {
    /// Constructs one complete sub-relation report.
    ///
    /// The linked-replacement relation and the durable-resume relation MUST both
    /// be reported and MUST NOT be merged into one verdict.
    pub fn new(reports: &[DurableArtifactSubReport]) -> Result<Self, PackageError> {
        if reports.len() != DurableArtifactRelation::ALL.len()
            || DurableArtifactRelation::ALL
                .iter()
                .any(|relation| !reports.iter().any(|report| report.relation == *relation))
        {
            return Err(PackageError::IncompleteCompatibilityReport {
                axis: CompatibilityAxis::DurableArtifact,
            });
        }
        let mut reports = reports.to_vec();
        reports.sort_by_key(|left| left.relation);
        Ok(Self(reports))
    }

    /// Returns every sub-relation report in canonical order.
    #[must_use]
    pub fn reports(&self) -> &[DurableArtifactSubReport] {
        &self.0
    }

    /// Returns the verdict of one durable-artifact sub-relation.
    #[must_use]
    pub fn verdict(&self, relation: DurableArtifactRelation) -> Option<AxisVerdict> {
        self.0
            .iter()
            .find(|report| report.relation == relation)
            .map(DurableArtifactSubReport::verdict)
    }
}

/// One named compared input of a compatibility comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparedInput {
    /// The exact compared input name.
    pub name: Arc<str>,
    /// The package identity of the compared input.
    pub identity: PackageIdentity,
    /// The public-interface digest of the compared input.
    pub interface: InterfaceDigest,
}

impl ComparedInput {
    /// Constructs one named compared input.
    pub fn new(
        name: &str,
        identity: PackageIdentity,
        interface: InterfaceDigest,
    ) -> Result<Self, PackageError> {
        if name.is_empty() {
            return Err(PackageError::InvalidDeclaration {
                field: "compared input",
                value: Arc::from(name),
            });
        }
        Ok(Self {
            name: Arc::from(name),
            identity,
            interface,
        })
    }
}

/// The two named inputs of one compatibility comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparedInputs {
    /// The previous package or artifact.
    pub previous: ComparedInput,
    /// The candidate replacement.
    pub candidate: ComparedInput,
}

/// One compatibility comparison, reported on exactly five axes.
///
/// The report names its compared inputs, marks each axis machine-checked or not,
/// keeps the two boundary-schema sub-reports and the two durable-artifact
/// sub-relations distinct, and offers no aggregate verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityReport {
    compared: ComparedInputs,
    source: AxisReport,
    boundary_schema: BoundarySchemaReport,
    authority: AxisReport,
    declared_behaviour: AxisReport,
    durable_artifact: DurableArtifactReport,
}

impl CompatibilityReport {
    /// Assembles one report from five distinctly reported axes.
    pub fn new(
        compared: ComparedInputs,
        source: AxisReport,
        boundary_schema: BoundarySchemaReport,
        authority: AxisReport,
        declared_behaviour: AxisReport,
        durable_artifact: DurableArtifactReport,
    ) -> Result<Self, PackageError> {
        for (report, axis) in [
            (&source, CompatibilityAxis::Source),
            (&authority, CompatibilityAxis::Authority),
            (&declared_behaviour, CompatibilityAxis::DeclaredBehaviour),
        ] {
            if report.axis != axis {
                return Err(PackageError::IncompleteCompatibilityReport { axis });
            }
        }
        Ok(Self {
            compared,
            source,
            boundary_schema,
            authority,
            declared_behaviour,
            durable_artifact,
        })
    }

    /// Reports the comparison the recorded interface encoding establishes.
    ///
    /// Comparing the two interface digests decides the source axis: equal
    /// declarations are unchanged, and an observed difference is reported as
    /// changed with the two compared interface digests named by
    /// [`ComparedInputs`]. The encoding records no per-surface boundary-schema
    /// fact, so no boundary surface is reported as machine-checked here: a
    /// different interface does not tell this model which surface accepts or
    /// produces different values, and reporting that as checked would claim
    /// evidence the model does not record. Declared behaviour, authority, and the
    /// durable-artifact relations are reported as not checked rather than as
    /// compatible, because interface, signature, or schema equality is never
    /// behavioural compatibility.
    #[must_use]
    pub fn for_interface_equality(
        compared: ComparedInputs,
        previous: &PublicInterfaceManifest,
        candidate: &PublicInterfaceManifest,
    ) -> Self {
        let equal = previous.digest() == candidate.digest();
        let source = equal_axis(CompatibilityAxis::Source, equal);
        let surfaces = BoundarySchemaSurface::ALL
            .into_iter()
            .map(|surface| {
                BoundarySchemaSubReport::new(surface, false, AxisVerdict::NotChecked)
                    .unwrap_or_else(|_| {
                        unreachable!("an unchecked surface is never marked checked")
                    })
            })
            .collect::<Vec<_>>();
        let relations = DurableArtifactRelation::ALL
            .into_iter()
            .map(|relation| {
                DurableArtifactSubReport::new(relation, false, AxisVerdict::NotChecked)
                    .unwrap_or_else(|_| unreachable!("fixture verdict is self-consistent"))
            })
            .collect::<Vec<_>>();
        Self {
            compared,
            source,
            boundary_schema: BoundarySchemaReport::new(&surfaces)
                .unwrap_or_else(|_| unreachable!("every surface is reported")),
            authority: unchecked_axis(CompatibilityAxis::Authority),
            declared_behaviour: unchecked_axis(CompatibilityAxis::DeclaredBehaviour),
            durable_artifact: DurableArtifactReport::new(&relations)
                .unwrap_or_else(|_| unreachable!("every relation is reported")),
        }
    }

    /// Returns the named compared inputs.
    #[must_use]
    pub const fn compared(&self) -> &ComparedInputs {
        &self.compared
    }

    /// Returns the source axis report.
    #[must_use]
    pub const fn source(&self) -> &AxisReport {
        &self.source
    }

    /// Returns the boundary-schema axis, per surface.
    #[must_use]
    pub const fn boundary_schema(&self) -> &BoundarySchemaReport {
        &self.boundary_schema
    }

    /// Returns the authority axis report.
    #[must_use]
    pub const fn authority(&self) -> &AxisReport {
        &self.authority
    }

    /// Returns the declared-behaviour axis report.
    #[must_use]
    pub const fn declared_behaviour(&self) -> &AxisReport {
        &self.declared_behaviour
    }

    /// Returns the durable-artifact axis, per sub-relation.
    #[must_use]
    pub const fn durable_artifact(&self) -> &DurableArtifactReport {
        &self.durable_artifact
    }

    /// Returns the five axis identities in reporting order.
    #[must_use]
    pub const fn axes(&self) -> [CompatibilityAxis; 5] {
        CompatibilityAxis::ALL
    }
}

/// Returns the verdict one machine-checked digest comparison produces.
///
/// A differing digest is an observed difference, so it is reported as changed
/// rather than as never checked: `NotChecked` would claim the comparison never
/// happened when the compared digests are exactly what was compared.
const fn verdict_for(equal: bool) -> AxisVerdict {
    if equal {
        AxisVerdict::Unchanged
    } else {
        AxisVerdict::Changed
    }
}

/// Returns the axis report of one machine-checked digest comparison.
fn equal_axis(axis: CompatibilityAxis, equal: bool) -> AxisReport {
    AxisReport::new(axis, true, verdict_for(equal))
        .unwrap_or_else(|_| unreachable!("a compared digest yields a checked verdict"))
}

/// Returns the axis report of one axis that was not checked.
fn unchecked_axis(axis: CompatibilityAxis) -> AxisReport {
    AxisReport::new(axis, false, AxisVerdict::NotChecked)
        .unwrap_or_else(|_| unreachable!("an unchecked axis is never marked checked"))
}

/// Orders one list of canonical names and removes exact duplicates.
fn sort_unique(values: &mut Vec<Arc<str>>) {
    values.sort();
    values.dedup();
}

/// Appends one JSON string literal with the canonical escapes.
fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            scalar if scalar <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", scalar as u32));
            }
            scalar => output.push(scalar),
        }
    }
    output.push('"');
}

/// Appends the body of one JSON string array.
fn push_string_array(output: &mut String, values: &[Arc<str>]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, value);
    }
}

/// Appends one optional JSON string literal.
fn push_optional_string(output: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_json_string(output, value),
        None => output.push_str("null"),
    }
}

/// Returns the one canonical encoding of one identity input record.
fn encode_identity(inputs: &PackageIdentityInputs) -> Vec<u8> {
    let mut output = String::from("{\"canonical_ir_sha256\":");
    push_json_string(&mut output, inputs.source.canonical_ir().as_str());
    output.push_str(",\"features\":[");
    for (index, feature) in inputs.features.as_slice().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, feature.as_str());
    }
    output.push_str("],\"generator_inputs\":[");
    for (index, entry) in inputs.generators.as_slice().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"digest\":");
        push_json_string(&mut output, &entry.digest);
        output.push_str(",\"name\":");
        push_json_string(&mut output, &entry.name);
        output.push_str(",\"role\":");
        push_json_string(&mut output, entry.role.wire_name());
        output.push('}');
    }
    output.push_str("],\"interface_sha256\":");
    push_json_string(&mut output, inputs.interface.as_str());
    output.push_str(",\"name\":");
    push_json_string(&mut output, inputs.name.as_str());
    output.push_str(",\"source_manifest_sha256\":");
    push_json_string(&mut output, inputs.source.manifest().as_str());
    output.push_str(",\"target_facts\":[");
    for (index, facts) in inputs.targets.as_slice().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"entry\":");
        push_optional_string(&mut output, facts.entry_point().map(CanonicalPath::as_str));
        output.push_str(",\"kind\":");
        push_json_string(&mut output, facts.kind().wire_name());
        output.push('}');
    }
    output.push(']');
    output.push_str(",\"target_selection\":");
    push_json_string(&mut output, &inputs.selection.text());
    output.push_str(",\"version\":");
    push_json_string(&mut output, inputs.version.as_str());
    output.push_str(",\"version_of_record\":1}");
    output.into_bytes()
}

/// Returns the one canonical encoding of one public interface manifest.
fn encode_interface(
    version: u32,
    metadata: &InterfaceMetadata,
    dependencies: &[DependencyInterfacePin],
    exports: &[ExportEntry],
    items: &[InterfaceItem],
) -> Vec<u8> {
    let mut output = String::from("{\"dependency_interfaces\":[");
    for (index, pin) in dependencies.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"interface\":");
        push_json_string(&mut output, pin.interface.as_str());
        output.push_str(",\"package\":");
        push_json_string(&mut output, &pin.package.as_str());
        output.push('}');
    }
    output.push_str("],\"edition\":");
    push_json_string(&mut output, &metadata.edition);
    output.push_str(",\"exports\":[");
    for (index, export) in exports.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"defining\":");
        push_json_string(&mut output, &export.defining.as_str());
        output.push_str(",\"defining_name\":");
        push_json_string(&mut output, &export.defining_name);
        output.push_str(",\"exported_name\":");
        push_json_string(&mut output, &export.exported_name);
        output.push_str(",\"kind\":");
        push_json_string(&mut output, export.kind.wire_name());
        output.push_str(",\"target\":");
        push_json_string(&mut output, export.target.wire_name());
        output.push('}');
    }
    output.push_str("],\"items\":[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        encode_item(&mut output, item);
    }
    output.push_str("],\"protocol_versions\":[");
    for (index, (name, role)) in metadata.protocol_versions.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"major\":");
        output.push_str(&role.major.to_string());
        output.push_str(",\"minor\":");
        output.push_str(&role.minor.to_string());
        output.push_str(",\"name\":");
        push_json_string(&mut output, name);
        output.push('}');
    }
    output.push_str("],\"public_features\":[");
    for (index, feature) in metadata.public_features.as_slice().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, feature.as_str());
    }
    output.push_str("],\"stdlib_contract\":{\"major\":");
    output.push_str(&metadata.stdlib_contract.major.to_string());
    output.push_str(",\"minor\":");
    output.push_str(&metadata.stdlib_contract.minor.to_string());
    output.push_str("},\"target_predicates\":[");
    push_string_array(&mut output, &metadata.target_predicates);
    output.push_str("],\"version\":");
    output.push_str(&version.to_string());
    output.push('}');
    output.into_bytes()
}

/// Appends the canonical encoding of one recorded interface item.
fn encode_item(output: &mut String, item: &InterfaceItem) {
    output.push_str("{\"agents\":[");
    push_string_array(output, &item.agents);
    output.push_str("],\"bounds\":[");
    push_string_array(output, &item.bounds);
    output.push_str("],\"constants\":[");
    for (index, (name, value)) in item.constants.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('[');
        push_json_string(output, name);
        output.push(',');
        push_json_string(output, value);
        output.push(']');
    }
    output.push_str("],\"data_release\":");
    push_optional_string(output, item.data_release.as_deref());
    output.push_str(",\"effect_row\":[");
    for (index, effect) in item.effect_row.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, effect.wire_name());
    }
    output.push_str("],\"fulfilment\":");
    push_optional_string(output, item.fulfilment.as_deref());
    output.push_str(",\"kind\":");
    push_json_string(output, item.kind.wire_name());
    output.push_str(",\"mode_restrictions\":[");
    push_string_array(output, &item.mode_restrictions);
    output.push_str("],\"name\":");
    push_json_string(output, &item.name);
    output.push_str(",\"nominal\":");
    match item.nominal.as_ref() {
        None => output.push_str("null"),
        Some(nominal) => {
            output.push_str("{\"construction\":");
            push_json_string(output, nominal.construction.wire_name());
            output.push_str(",\"exhaustiveness\":");
            push_json_string(output, nominal.exhaustiveness.wire_name());
            output.push_str(",\"fields\":[");
            push_string_array(output, &nominal.fields);
            output.push_str("],\"schema\":");
            push_optional_string(output, nominal.schema.as_ref().map(InterfaceDigest::as_str));
            output.push_str(",\"variants\":[");
            push_string_array(output, &nominal.variants);
            output.push_str("]}");
        }
    }
    output.push_str(",\"protected_transition\":");
    push_optional_string(output, item.protected_transition.as_deref());
    output.push_str(",\"receiver_mode\":");
    push_optional_string(output, item.receiver_mode.as_deref());
    output.push_str(",\"recovery\":");
    push_optional_string(output, item.recovery.map(RecoveryClass::wire_name));
    output.push_str(",\"requirements\":[");
    push_string_array(output, &item.requirements);
    output.push_str("],\"signature\":");
    push_optional_string(
        output,
        item.signature.as_ref().map(CanonicalSignature::as_str),
    );
    output.push_str(",\"target\":");
    push_json_string(output, item.target.wire_name());
    output.push_str(",\"tool_contract\":");
    push_optional_string(output, item.tool_contract.as_deref());
    output.push_str(",\"trait\":");
    match item.trait_facts.as_ref() {
        None => output.push_str("null"),
        Some(trait_facts) => {
            output.push_str("{\"coherence_impls\":[");
            push_string_array(output, &trait_facts.coherence_impls);
            output.push_str("],\"methods\":[");
            push_string_array(output, &trait_facts.methods);
            output.push_str("],\"owner\":");
            push_optional_string(output, trait_facts.owner.as_deref());
            output.push('}');
        }
    }
    output.push_str(",\"visibility\":");
    push_json_string(output, item.visibility.wire_name());
    output.push('}');
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalIrDigest, CanonicalPath, CollisionCondition, DependencyFingerprint, DependencyPin,
        GeneratorInputs, IDENTITY_DOMAIN, InterfaceDigest, PackageError, PackageIdentity,
        PackageIdentityInputs, PackageName, PackageSourceIdentity, PackageVersion,
        SelectedFeatureSet, SourceManifestDigest, TargetFactSet, TargetFacts, TargetKind,
        collision_condition, digest_fields, push_json_string, synthesize_alias,
    };
    use crate::target::{FeatureSolutionDigest, TargetDescriptorDigest, TargetFactsRecord};

    /// Returns one dependency identity over one declared target fact.
    fn dependency_identity(kind: TargetKind, entry: Option<&str>) -> PackageIdentity {
        identity_with_targets(&[fact(kind, entry)])
    }

    #[test]
    fn dependency_fingerprint_is_order_and_repeat_independent() {
        let package = dependency_identity(TargetKind::Library, None);
        let first = dependency_identity(TargetKind::Binary, Some("crate::main"));
        let second = dependency_identity(TargetKind::Example, Some("crate::demo"));
        let first_pin = InterfaceDigest::from_digest(fixture("dep-first"));
        let second_pin = InterfaceDigest::from_digest(fixture("dep-second"));
        let forward = DependencyFingerprint::derive(
            package.clone(),
            [
                (first.clone(), Some(first_pin.clone())),
                (second.clone(), Some(second_pin.clone())),
            ],
        )
        .unwrap_or_else(|error| panic!("the declared dependencies are pinned: {error}"));
        let reversed = DependencyFingerprint::derive(
            package.clone(),
            [
                (second.clone(), Some(second_pin.clone())),
                (first.clone(), Some(first_pin.clone())),
                (first.clone(), Some(first_pin.clone())),
            ],
        )
        .unwrap_or_else(|error| panic!("the declared dependencies are pinned: {error}"));
        assert_eq!(forward, reversed, "order and repeats change nothing");
        assert_eq!(forward.len(), 2, "identical repeats collapse");
        assert_eq!(forward.package(), &package);
        assert_eq!(forward.pin_for(&first), Some(&first_pin));
        assert_eq!(forward.pin_for(&second), Some(&second_pin));
        assert!(!forward.is_empty());
        assert!(forward.as_str().starts_with("dependency-fingerprint:"));
        assert_eq!(forward.digest_hex().len(), 64);
        assert_eq!(forward.digest(), forward.digest());
        let pinned: Vec<&InterfaceDigest> = forward
            .pins()
            .iter()
            .map(DependencyPin::interface)
            .collect();
        assert_eq!(pinned.len(), 2);
        assert!(pinned.contains(&&first_pin));
        assert!(pinned.contains(&&second_pin));
        let pinned_identities: Vec<&PackageIdentity> =
            forward.pins().iter().map(DependencyPin::identity).collect();
        assert_eq!(pinned_identities.len(), 2);
        assert!(pinned_identities.contains(&&first));
        assert!(pinned_identities.contains(&&second));
        // Guards the lookup rather than the pair values: `pin_for` must resolve a
        // pin's own identity to that pin's interface. The pair values themselves
        // are pinned by the `pin_for` assertions above and the digest inequality
        // below.
        for pin in forward.pins() {
            assert_eq!(
                forward.pin_for(pin.identity()),
                Some(pin.interface()),
                "each pin keeps its own identity and interface paired"
            );
        }
        let other_package = dependency_identity(TargetKind::Benchmark, None);
        let other = DependencyFingerprint::derive(
            other_package,
            [
                (first.clone(), Some(first_pin.clone())),
                (second.clone(), Some(second_pin.clone())),
            ],
        )
        .unwrap_or_else(|error| panic!("the declared dependencies are pinned: {error}"));
        assert_ne!(
            forward.digest(),
            other.digest(),
            "the fingerprinted package identity is part of the fingerprint"
        );
        let repinned = DependencyFingerprint::derive(
            package.clone(),
            [
                (first.clone(), Some(second_pin.clone())),
                (second.clone(), Some(first_pin.clone())),
            ],
        )
        .unwrap_or_else(|error| panic!("the declared dependencies are pinned: {error}"));
        assert_ne!(
            forward.digest(),
            repinned.digest(),
            "a dependency's pin is part of the fingerprint"
        );
        let empty = DependencyFingerprint::derive(package, [])
            .unwrap_or_else(|error| panic!("an empty dependency set is pinned: {error}"));
        assert!(empty.is_empty());
        assert_ne!(
            empty.as_str(),
            forward.as_str(),
            "a dependency set is part of the fingerprint"
        );
    }

    #[test]
    fn dependency_fingerprint_refuses_open_and_conflicting_dependencies() {
        let package = dependency_identity(TargetKind::Library, None);
        let open = dependency_identity(TargetKind::Test, None);
        let error = DependencyFingerprint::derive(package.clone(), [(open.clone(), None)])
            .err()
            .unwrap_or_else(|| panic!("an open dependency is refused"));
        assert!(matches!(
            &error,
            PackageError::UnpinnedDependency { dependency }
                if dependency == &open
        ));
        assert!(
            error
                .to_string()
                .contains("resolved without a pinned interface")
        );
        let second_open = dependency_identity(TargetKind::Example, Some("crate::demo"));
        let forward_open = DependencyFingerprint::derive(
            package.clone(),
            [(open.clone(), None), (second_open.clone(), None)],
        )
        .err()
        .unwrap_or_else(|| panic!("an open dependency is refused"));
        let reversed_open = DependencyFingerprint::derive(
            package.clone(),
            [(second_open, None), (open.clone(), None)],
        )
        .err()
        .unwrap_or_else(|| panic!("an open dependency is refused"));
        assert_eq!(
            forward_open.to_string(),
            reversed_open.to_string(),
            "two unpinned dependencies refuse the canonically smallest identity"
        );
        let conflicting = dependency_identity(TargetKind::Benchmark, None);
        let error = DependencyFingerprint::derive(
            package,
            [
                (
                    conflicting.clone(),
                    Some(InterfaceDigest::from_digest(fixture("pin-one"))),
                ),
                (
                    conflicting.clone(),
                    Some(InterfaceDigest::from_digest(fixture("pin-two"))),
                ),
            ],
        )
        .err()
        .unwrap_or_else(|| panic!("two pins for one dependency are refused"));
        assert!(matches!(
            &error,
            PackageError::ConflictingDependencyPin { dependency }
                if dependency == &conflicting
        ));
        assert!(
            error
                .to_string()
                .contains("carries two distinct interface pins")
        );
    }

    #[test]
    fn dependency_fingerprint_bound_is_pre_dedup_and_refuses_one_more() {
        let package = dependency_identity(TargetKind::Library, None);
        let dependency = dependency_identity(TargetKind::Binary, Some("crate::main"));
        let pin = InterfaceDigest::from_digest(fixture("bound-pin"));
        let at_bound = DependencyFingerprint::derive(
            package.clone(),
            vec![
                (dependency.clone(), Some(pin.clone()));
                DependencyFingerprint::MAXIMUM_DEPENDENCIES
            ],
        )
        .unwrap_or_else(|error| panic!("the declared bound is inclusive: {error}"));
        assert_eq!(
            at_bound.len(),
            1,
            "duplicate dependencies collapse after the bound check"
        );
        let error = DependencyFingerprint::derive(
            package,
            vec![(dependency, Some(pin)); DependencyFingerprint::MAXIMUM_DEPENDENCIES + 1],
        )
        .err()
        .unwrap_or_else(|| panic!("one dependency past the bound is refused"));
        assert!(matches!(
            &error,
            PackageError::ExceedsMaximumDependencies { observed, maximum }
                if *maximum == DependencyFingerprint::MAXIMUM_DEPENDENCIES
                    && *observed == DependencyFingerprint::MAXIMUM_DEPENDENCIES + 1
        ));
        assert_eq!(
            error.to_string(),
            format!(
                "{} supplied dependencies exceed the declared maximum of {}",
                DependencyFingerprint::MAXIMUM_DEPENDENCIES + 1,
                DependencyFingerprint::MAXIMUM_DEPENDENCIES
            )
        );
    }

    /// Returns one deterministic fixture digest.
    fn fixture(seed: &str) -> [u8; 32] {
        digest_fields("gantry.package-test-fixture/v1", &[seed.as_bytes()])
    }

    /// Returns one declared target fact under the per-kind entry-point rules.
    fn fact(kind: TargetKind, entry: Option<&str>) -> TargetFacts {
        let entry_point = entry.map(|text| {
            CanonicalPath::new(text).unwrap_or_else(|_| unreachable!("fixture path is canonical"))
        });
        TargetFacts::new(kind, entry_point)
            .unwrap_or_else(|_| unreachable!("fixture fact satisfies its kind rules"))
    }

    /// Returns one identity over the supplied declared target facts.
    fn identity_with_targets(facts: &[TargetFacts]) -> PackageIdentity {
        PackageIdentity::derive(PackageIdentityInputs::new(
            PackageName::new("app").unwrap_or_else(|_| unreachable!("fixture name is valid")),
            PackageVersion::new("1.0.0")
                .unwrap_or_else(|_| unreachable!("fixture version is valid")),
            PackageSourceIdentity::new(
                SourceManifestDigest::from_digest(fixture("manifest")),
                CanonicalIrDigest::from_digest(fixture("ir")),
            ),
            SelectedFeatureSet::empty(),
            TargetFactSet::new(facts),
            TargetFactsRecord::new(
                1,
                TargetDescriptorDigest::from_digest(fixture("descriptor")),
                FeatureSolutionDigest::from_digest(fixture("solution")),
            )
            .unwrap_or_else(|_| unreachable!("fixture selection names its version")),
            InterfaceDigest::from_digest(fixture("interface")),
            GeneratorInputs::empty(),
        ))
    }

    #[test]
    fn canonical_identity_encoding_carries_the_declared_fact_set_and_its_domain_digest() {
        let declared = identity_with_targets(&[
            fact(TargetKind::Example, Some("crate::demo")),
            fact(TargetKind::Library, None),
        ]);
        let reordered = identity_with_targets(&[
            fact(TargetKind::Library, None),
            fact(TargetKind::Example, Some("crate::demo")),
        ]);
        assert_eq!(declared.canonical_bytes(), reordered.canonical_bytes());
        // The identity digest is the domain-separated digest of exactly the
        // canonical bytes, which only this module can recompute.
        assert_eq!(
            declared.digest(),
            digest_fields(IDENTITY_DOMAIN, &[declared.canonical_bytes()])
        );
        let text = std::str::from_utf8(declared.canonical_bytes())
            .unwrap_or_else(|_| unreachable!("the canonical encoding is UTF-8 text"));
        // Each fact is one canonical pair of the declared entry point and kind, in
        // canonical kind order.
        assert!(text.contains("\"target_facts\":[{\"entry\":null,\"kind\":\"library\"},"));
        assert!(text.contains("{\"entry\":\"crate::demo\",\"kind\":\"example\"}"));
        // The declared set, not its enumeration, is the input: a fact recorded
        // twice is one fact, and adding one declared target is a new identity.
        assert_eq!(
            declared,
            identity_with_targets(&[
                fact(TargetKind::Library, None),
                fact(TargetKind::Library, None),
                fact(TargetKind::Example, Some("crate::demo")),
            ])
        );
        assert_ne!(
            declared,
            identity_with_targets(&[fact(TargetKind::Library, None)])
        );
    }

    #[test]
    fn canonical_json_string_escaping_covers_the_recorded_groups() {
        let mut escaped = String::new();
        push_json_string(&mut escaped, "a\"b\\c\nd\te\u{1}f");
        assert_eq!(escaped, "\"a\\\"b\\\\c\\nd\\te\\u0001f\"");
        // A scalar outside the escaped set is written as itself, so a recorded
        // name keeps its exact NFC spelling rather than an escaped approximation.
        let mut unicode = String::new();
        push_json_string(&mut unicode, "\u{e9}\u{4e2d}");
        assert_eq!(unicode, "\"\u{e9}\u{4e2d}\"");
    }

    #[test]
    fn collision_relation_is_symmetric_and_ordered_by_specificity() {
        for (left, right, expected) in [
            ("serde", "serde", CollisionCondition::Exact),
            ("serde", "Serde", CollisionCondition::Case),
            ("serde", "serde_json", CollisionCondition::Truncation),
            ("serde_json", "serde", CollisionCondition::Truncation),
        ] {
            assert_eq!(collision_condition(left, right), Some(expected));
            assert_eq!(collision_condition(right, left), Some(expected));
        }
        assert_eq!(collision_condition("serde", "other"), None);
        assert_eq!(collision_condition("other", "serde"), None);
    }

    /// The case condition folds with the pinned full case mapping, not the
    /// toolchain's mapping: `ΑΣ` (U+0391 U+03A3) and `Ας` (U+0391 U+03C2) are one
    /// spelling under the pinned context-sensitive final-sigma rule but two under
    /// `str::to_lowercase`, so this pair collides only when the pinned mapping is
    /// used.
    #[test]
    fn case_collision_uses_the_pinned_full_case_mapping() {
        assert_eq!(
            collision_condition("\u{391}\u{3a3}", "\u{391}\u{3c2}"),
            Some(CollisionCondition::Case)
        );
        assert_eq!(
            collision_condition("\u{391}\u{3c2}", "\u{391}\u{3a3}"),
            Some(CollisionCondition::Case)
        );
    }

    #[test]
    fn synthesized_alias_replaces_only_separator_scalars() {
        assert_eq!(synthesize_alias("serde-json"), "serde_json");
        assert_eq!(synthesize_alias("core.io/util"), "core_io_util");
        // Case and every other scalar are preserved, so the synthesized alias
        // depends only on the package name it derives from.
        assert_eq!(synthesize_alias("Serde"), "Serde");
        // Two distinct package names can synthesize one alias, which the declaring
        // scope rejects rather than silently shadowing one of them.
        assert_eq!(
            synthesize_alias("serde.json"),
            synthesize_alias("serde-json")
        );
    }
}
