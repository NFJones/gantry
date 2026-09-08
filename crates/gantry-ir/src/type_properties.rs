//! Independent properties of the existing primitive value domain.
//!
//! These facts describe v1 values, not admission of an operation or execution.
//! Declared and aggregate types require a declaration-aware structural proof;
//! a nominal descriptor alone cannot establish their properties.

use crate::generated::TypeKind;

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
        true
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
