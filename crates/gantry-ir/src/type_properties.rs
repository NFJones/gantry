//! Independent properties of the existing primitive value domain.
//!
//! These facts describe v1 values, not admission of an operation or execution.
//! Declared and aggregate types require a declaration-aware structural proof;
//! a nominal descriptor alone cannot establish their properties.

use crate::generated::TypeKind;

/// Ownership obligation of a value, independent of encoding and authority.
///
/// Classification does not admit a source type or define its transfer or cleanup
/// operations. Primitives and ordinary aggregates are [`Self::Copyable`]; an
/// `affine struct` inhabits [`Self::AffineDroppable`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OwnershipClass {
    /// Independent logical copies and ordinary discard are permitted.
    Copyable,
    /// Copying is prohibited; discard requires the type's defined disposition.
    AffineDroppable,
    /// Copying and silent discard are prohibited; consumption must be accounted for.
    MustConsume,
}

impl OwnershipClass {
    /// Returns whether the class requires the move ledger to account for every use.
    ///
    /// `MustConsume` requires each reachable place to be consumed or explicitly
    /// discarded through a declared disposition; `AffineDroppable` requires the
    /// same accounting while an ordinary discard remains a permitted use.
    #[must_use]
    pub const fn requires_consumption(self) -> bool {
        match self {
            Self::MustConsume | Self::AffineDroppable => true,
            Self::Copyable => false,
        }
    }

    /// Combines reachable member obligations without weakening either member.
    ///
    /// `MustConsume` dominates `AffineDroppable`, which dominates `Copyable`.
    /// This operation is associative, commutative, and idempotent. Fold from
    /// `Copyable` for an empty aggregate; an enum includes every variant payload.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::MustConsume, _) | (_, Self::MustConsume) => Self::MustConsume,
            (Self::AffineDroppable, _) | (_, Self::AffineDroppable) => Self::AffineDroppable,
            (Self::Copyable, Self::Copyable) => Self::Copyable,
        }
    }
}

/// Eligibility for moving a value between source-task ownership domains.
///
/// This classification grants neither task creation nor authority delegation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferEligibility {
    /// A spawned source task may receive an independent logical copy.
    IsolatedTaskCapture,
    /// No transfer contract has been established for the value.
    Ineligible,
}

impl TransferEligibility {
    /// Conservatively combines stored-member transfer eligibility.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Ineligible, _) | (_, Self::Ineligible) => Self::Ineligible,
            (Self::IsolatedTaskCapture, Self::IsolatedTaskCapture) => Self::IsolatedTaskCapture,
        }
    }
}

/// Whether a value contains a live source resource.
///
/// Classification alone defines no cleanup operation or release authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ValueResourceClass {
    /// The value contains no live source resource.
    NonLiveResource,
    /// The value contains a live source resource requiring a separate contract.
    LiveResource,
}

impl ValueResourceClass {
    /// Conservatively combines stored-member resource classification.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::LiveResource, _) | (_, Self::LiveResource) => Self::LiveResource,
            (Self::NonLiveResource, Self::NonLiveResource) => Self::NonLiveResource,
        }
    }
}

/// Source-language protection of a value type.
///
/// This is distinct from the potentially sensitive integration data carried by
/// any value at a transport, journal, diagnostic, or event boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProtectionClass {
    /// Source may use the type without a sealed-type restriction.
    Unsealed,
    /// Source operations are restricted by a sealed-type contract.
    Sealed,
}

impl SourceProtectionClass {
    /// Conservatively combines stored-member source protection.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Sealed, _) | (_, Self::Sealed) => Self::Sealed,
            (Self::Unsealed, Self::Unsealed) => Self::Unsealed,
        }
    }
}

/// Availability of a canonical sealed-value recovery projection.
///
/// This classifies value evidence only; it does not implement runtime recovery
/// or establish durable execution admission.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecoveryProjectionClass {
    /// Canonical sealed value evidence can reconstruct the logical value.
    SealedValue,
    /// No value recovery projection is available.
    Unavailable,
}

impl RecoveryProjectionClass {
    /// Conservatively combines stored-member recovery projection availability.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unavailable, _) | (_, Self::Unavailable) => Self::Unavailable,
            (Self::SealedValue, Self::SealedValue) => Self::SealedValue,
        }
    }
}

/// Independent structural properties folded over stored members.
///
/// Each axis combines conservatively and remains independent of external-value
/// eligibility, operation admission, authority, and runtime implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndependentTypeProperties {
    ownership: OwnershipClass,
    transfer: TransferEligibility,
    resource: ValueResourceClass,
    source_protection: SourceProtectionClass,
    recovery_projection: RecoveryProjectionClass,
}

impl IndependentTypeProperties {
    /// Identity used for an aggregate with no stored members.
    #[must_use]
    pub const fn empty_aggregate() -> Self {
        Self {
            ownership: OwnershipClass::Copyable,
            transfer: TransferEligibility::IsolatedTaskCapture,
            resource: ValueResourceClass::NonLiveResource,
            source_protection: SourceProtectionClass::Unsealed,
            recovery_projection: RecoveryProjectionClass::SealedValue,
        }
    }

    /// Constructs one property tuple for a primitive leaf.
    const fn primitive(source_protection: SourceProtectionClass) -> Self {
        Self {
            source_protection,
            ..Self::empty_aggregate()
        }
    }

    /// Seed contributed by an `affine struct` declaration independent of its members.
    #[must_use]
    pub const fn affine() -> Self {
        Self::ownership_seed(OwnershipClass::AffineDroppable)
    }

    /// Seed contributed by a `must_consume struct` declaration independent of its members.
    #[must_use]
    pub const fn must_consume() -> Self {
        Self::ownership_seed(OwnershipClass::MustConsume)
    }

    /// Seed contributed by an ownership-modifier declaration independent of its members.
    #[must_use]
    pub const fn ownership_seed(ownership: OwnershipClass) -> Self {
        Self {
            ownership,
            ..Self::empty_aggregate()
        }
    }

    /// Combines every axis conservatively for aggregate storage.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        Self {
            ownership: self.ownership.combine(other.ownership),
            transfer: self.transfer.combine(other.transfer),
            resource: self.resource.combine(other.resource),
            source_protection: self.source_protection.combine(other.source_protection),
            recovery_projection: self.recovery_projection.combine(other.recovery_projection),
        }
    }

    /// Returns the value ownership obligation.
    #[must_use]
    pub const fn ownership_class(self) -> OwnershipClass {
        self.ownership
    }

    /// Returns source-task transfer eligibility.
    #[must_use]
    pub const fn transfer_eligibility(self) -> TransferEligibility {
        self.transfer
    }

    /// Returns the live source-resource classification.
    #[must_use]
    pub const fn resource_class(self) -> ValueResourceClass {
        self.resource
    }

    /// Returns source-language protection independently of transport sensitivity.
    #[must_use]
    pub const fn source_protection_class(self) -> SourceProtectionClass {
        self.source_protection
    }

    /// Returns sealed-value recovery projection availability.
    #[must_use]
    pub const fn recovery_projection_class(self) -> RecoveryProjectionClass {
        self.recovery_projection
    }
}

/// Compiler-owned facts about one existing primitive value type.
///
/// Copyability, equality, external encoding, interpolation, and recovery are
/// separate predicates. In particular, recovery does not imply external
/// eligibility. No fact grants authority or bypasses contextual boundary rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimitiveTypeProperties {
    canonical_scalar_key: bool,
    equatable: bool,
    external: bool,
    hashable: bool,
    orderable: bool,
    source_protection: SourceProtectionClass,
}

impl PrimitiveTypeProperties {
    /// Classifies primitive kinds; returns `None` for structural type kinds.
    pub(crate) const fn for_kind(kind: TypeKind) -> Option<Self> {
        match kind {
            TypeKind::Unit | TypeKind::Bool | TypeKind::String => Some(Self {
                canonical_scalar_key: true,
                equatable: true,
                external: true,
                hashable: true,
                orderable: false,
                source_protection: SourceProtectionClass::Unsealed,
            }),
            TypeKind::Int | TypeKind::Float => Some(Self {
                canonical_scalar_key: true,
                equatable: true,
                external: true,
                hashable: true,
                orderable: true,
                source_protection: SourceProtectionClass::Unsealed,
            }),
            TypeKind::Decision | TypeKind::OperationError => Some(Self {
                canonical_scalar_key: false,
                equatable: false,
                external: false,
                hashable: false,
                orderable: false,
                source_protection: SourceProtectionClass::Sealed,
            }),
            TypeKind::Declared
            | TypeKind::Option
            | TypeKind::Result
            | TypeKind::List
            | TypeKind::Tuple => None,
        }
    }

    /// Whether v1 permits an independent logical copy of this primitive.
    #[must_use]
    pub const fn is_copyable(self) -> bool {
        matches!(self.ownership_class(), OwnershipClass::Copyable)
    }

    /// Returns the ownership class of an existing v1 primitive value.
    #[must_use]
    pub const fn ownership_class(self) -> OwnershipClass {
        self.independent_properties().ownership_class()
    }

    /// Returns source-task transfer eligibility for this primitive.
    #[must_use]
    pub const fn transfer_eligibility(self) -> TransferEligibility {
        self.independent_properties().transfer_eligibility()
    }

    /// Returns the live source-resource classification for this primitive.
    #[must_use]
    pub const fn resource_class(self) -> ValueResourceClass {
        self.independent_properties().resource_class()
    }

    /// Returns source-language protection independently of transport sensitivity.
    #[must_use]
    pub const fn source_protection_class(self) -> SourceProtectionClass {
        self.independent_properties().source_protection_class()
    }

    /// Returns sealed-value recovery projection availability for this primitive.
    #[must_use]
    pub const fn recovery_projection_class(self) -> RecoveryProjectionClass {
        self.independent_properties().recovery_projection_class()
    }

    /// Returns the complete independent property tuple for this primitive.
    #[must_use]
    pub const fn independent_properties(self) -> IndependentTypeProperties {
        IndependentTypeProperties::primitive(self.source_protection)
    }

    /// Whether this primitive satisfies the compiler-owned `Equatable` bound.
    #[must_use]
    pub const fn is_equatable(self) -> bool {
        self.equatable
    }

    /// Whether this primitive has the stable canonical scalar-key hash contract.
    ///
    /// Hashability is intentionally narrower than `ExternalValue`: only the
    /// primitive domain with a versioned scalar-key frame and SHA-256 content
    /// hash may report this property.
    #[must_use]
    pub const fn is_hashable(self) -> bool {
        self.hashable
    }

    /// Whether numeric ordering primitives admit this type.
    #[must_use]
    pub const fn is_orderable(self) -> bool {
        self.orderable
    }

    /// Whether this primitive is admitted to the canonical scalar-key domain.
    ///
    /// This is independent of numeric source ordering: Unit, Bool, and String
    /// are eligible, while sealed primitives are not. Structural types have no
    /// primitive properties and therefore cannot be admitted by this predicate.
    #[must_use]
    pub const fn is_canonical_scalar_key(self) -> bool {
        self.canonical_scalar_key
    }

    /// Whether this primitive satisfies `ExternalValue`, before contextual checks.
    #[must_use]
    pub const fn is_external(self) -> bool {
        self.external
    }

    /// Whether the sealed interpolation encoding admits this primitive.
    #[must_use]
    pub const fn is_interpolatable(self) -> bool {
        true
    }

    /// Whether v1 has a sealed recovery projection for this primitive value.
    ///
    /// This does not establish that a containing execution is durably admissible.
    #[must_use]
    pub const fn has_recovery_projection(self) -> bool {
        matches!(
            self.recovery_projection_class(),
            RecoveryProjectionClass::SealedValue
        )
    }
}
