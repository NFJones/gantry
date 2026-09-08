//! Independent properties of the existing primitive value domain.
//!
//! These facts describe v1 values, not admission of an operation or execution.
//! Declared and aggregate types require a declaration-aware structural proof;
//! a nominal descriptor alone cannot establish their properties.

use crate::generated::TypeKind;

/// Ownership obligation of a value, independent of encoding and authority.
///
/// Classification does not admit a source type or define its transfer or cleanup
/// operations. Existing v1 first-class values are all [`Self::Copyable`].
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

/// Compiler-owned facts about one existing primitive value type.
///
/// Copyability, equality, external encoding, interpolation, and recovery are
/// separate predicates. In particular, recovery does not imply external
/// eligibility. No fact grants authority or bypasses contextual boundary rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimitiveTypeProperties {
    equatable: bool,
    external: bool,
    orderable: bool,
}

impl PrimitiveTypeProperties {
    /// Classifies primitive kinds; returns `None` for structural type kinds.
    pub(crate) const fn for_kind(kind: TypeKind) -> Option<Self> {
        match kind {
            TypeKind::Unit | TypeKind::Bool | TypeKind::String => Some(Self {
                equatable: true,
                external: true,
                orderable: false,
            }),
            TypeKind::Int | TypeKind::Float => Some(Self {
                equatable: true,
                external: true,
                orderable: true,
            }),
            TypeKind::Decision | TypeKind::OperationError => Some(Self {
                equatable: false,
                external: false,
                orderable: false,
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
        OwnershipClass::Copyable
    }

    /// Whether this primitive satisfies the compiler-owned `Equatable` bound.
    #[must_use]
    pub const fn is_equatable(self) -> bool {
        self.equatable
    }

    /// Whether numeric ordering primitives admit this type.
    #[must_use]
    pub const fn is_orderable(self) -> bool {
        self.orderable
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
        true
    }
}
