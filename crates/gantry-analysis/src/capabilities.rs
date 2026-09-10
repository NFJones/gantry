//! Bounded inspection of capabilities in an already validated package.
//!
//! Queries share the analyzer's structural prover, but never its mutable cache
//! or activity budget. No query admits a new source type or executable artifact.

use std::collections::BTreeMap;

use gantry_core::source::{FrontendLimits, FrontendResourceLimit, GenericAnalysisCounters};
use gantry_ir::{
    IndependentTypeProperties, OwnershipClass, RecoveryProjectionClass, SourceProtectionClass,
    TransferEligibility, TypeDescriptor, TypeExpression, ValueResourceClass,
};

use crate::generics::{
    SealedCapability, prove_independent_type_properties, prove_sealed_capability,
};
use crate::{AnalysisError, AnalysisStatus, TypedPackage};

/// Independent compiler-owned capability results, not execution admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeCapabilities {
    canonical_scalar_key: bool,
    hashable: bool,
    independent: IndependentTypeProperties,
    equatable: bool,
    external: bool,
    interpolatable: bool,
    orderable: bool,
}

impl TypeCapabilities {
    /// Whether the validated v1 value permits independent logical copies.
    ///
    /// Only [`OwnershipClass::Copyable`] values permit independent copies. An
    /// `affine struct` is [`OwnershipClass::AffineDroppable`] and cannot be
    /// copied. Task handles are not values.
    #[must_use]
    pub const fn is_copyable(self) -> bool {
        matches!(self.ownership_class(), gantry_ir::OwnershipClass::Copyable)
    }

    /// Returns the ownership class of this validated v1 value.
    ///
    /// An `affine struct` produces [`OwnershipClass::AffineDroppable`].
    #[must_use]
    pub const fn ownership_class(self) -> OwnershipClass {
        self.independent.ownership_class()
    }

    /// Whether a v1 task may capture an independent copy of this value.
    ///
    /// This is source-task capture eligibility, not shared identity, host-thread
    /// safety, authority delegation, or permission to spawn a task.
    #[must_use]
    pub const fn is_task_capturable(self) -> bool {
        matches!(
            self.transfer_eligibility(),
            TransferEligibility::IsolatedTaskCapture
        )
    }

    /// Returns eligibility for transfer between source-task ownership domains.
    #[must_use]
    pub const fn transfer_eligibility(self) -> TransferEligibility {
        self.independent.transfer_eligibility()
    }

    /// Whether this type contains a live source resource.
    #[must_use]
    pub const fn is_live_resource(self) -> bool {
        matches!(self.resource_class(), ValueResourceClass::LiveResource)
    }

    /// Returns the live source-resource classification.
    #[must_use]
    pub const fn resource_class(self) -> ValueResourceClass {
        self.independent.resource_class()
    }

    /// Whether source operations are restricted by a sealed type boundary.
    #[must_use]
    pub const fn is_source_protected(self) -> bool {
        matches!(
            self.source_protection_class(),
            SourceProtectionClass::Sealed
        )
    }

    /// Returns source-language protection, independently of transport sensitivity.
    #[must_use]
    pub const fn source_protection_class(self) -> SourceProtectionClass {
        self.independent.source_protection_class()
    }

    /// Whether canonical sealed value evidence can reconstruct this value.
    #[must_use]
    pub const fn has_sealed_recovery_projection(self) -> bool {
        matches!(
            self.recovery_projection_class(),
            RecoveryProjectionClass::SealedValue
        )
    }

    /// Returns the value recovery-projection classification.
    #[must_use]
    pub const fn recovery_projection_class(self) -> RecoveryProjectionClass {
        self.independent.recovery_projection_class()
    }

    /// Whether the stored value satisfies `Equatable`.
    #[must_use]
    pub const fn is_equatable(self) -> bool {
        self.equatable
    }

    /// Whether this exact type is admitted to the canonical scalar-key domain.
    ///
    /// Only the five unsealed scalar primitives qualify. This report does not
    /// grant a source capability, add structural keys, or admit collections.
    #[must_use]
    pub const fn is_canonical_scalar_key(self) -> bool {
        self.canonical_scalar_key
    }

    /// Whether this exact type has the stable canonical scalar-key hash contract.
    ///
    /// Hashability is limited to the five versioned scalar-key primitives. It
    /// does not follow from external eligibility, equality, or a source codec.
    #[must_use]
    pub const fn is_hashable(self) -> bool {
        self.hashable
    }

    /// Whether this exact type supports the existing numeric ordering operators.
    ///
    /// Ordering is limited to `Int` and finite `Float`; it does not follow from
    /// equality, hashability, external eligibility, or canonical-key admission.
    #[must_use]
    pub const fn is_orderable(self) -> bool {
        self.orderable
    }

    /// Whether the stored value satisfies `ExternalValue`, before contextual checks.
    #[must_use]
    pub const fn is_external(self) -> bool {
        self.external
    }

    /// Whether the stored value satisfies `Interpolatable`.
    #[must_use]
    pub const fn is_interpolatable(self) -> bool {
        self.interpolatable
    }
}

/// Failure of a bounded capability query; no partial report is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeCapabilityQueryError {
    /// The package did not pass source validation.
    InvalidPackage,
    /// The descriptor is neither primitive nor retained by this package.
    TypeNotRetained,
    /// The fresh query budget was exhausted.
    ResourceLimit(FrontendResourceLimit),
    /// Retained analyzer state violates its internal contract.
    Invariant,
}

impl std::fmt::Display for TypeCapabilityQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPackage => "capability query requires a valid package",
            Self::TypeNotRetained => "type was not retained by this package",
            Self::ResourceLimit(_) => "capability query limit exceeded",
            Self::Invariant => "retained capability state is inconsistent",
        })
    }
}

impl std::error::Error for TypeCapabilityQueryError {}

impl TypedPackage {
    /// Proves capabilities for a primitive or an exact retained closed type.
    ///
    /// Uses fresh constructed-depth and trait-resolution limits for each call.
    /// Unknown descriptors and invalid packages are rejected before proof. The
    /// result neither grants authority nor establishes durable admission.
    pub fn type_capabilities(
        &self,
        descriptor: &TypeDescriptor,
        limits: FrontendLimits,
    ) -> Result<TypeCapabilities, TypeCapabilityQueryError> {
        if self.status() != AnalysisStatus::Valid {
            return Err(TypeCapabilityQueryError::InvalidPackage);
        }
        let retained = descriptor.primitive_properties().is_some()
            || self
                .types()
                .iter()
                .any(|fact| &fact.descriptor == descriptor)
            || self
                .generic_types()
                .iter()
                .any(|fact| fact.descriptor.as_ref() == Some(descriptor))
            || self
                .declared_value_shapes()
                .is_some_and(|shapes| shapes.get(descriptor).is_some());
        if !retained {
            return Err(TypeCapabilityQueryError::TypeNotRetained);
        }
        let declarations = self
            .capability_declarations
            .as_ref()
            .ok_or(TypeCapabilityQueryError::Invariant)?;
        let counters = GenericAnalysisCounters::new(limits);
        let expression = TypeExpression::closed(descriptor, u64::MAX)
            .map_err(|_| TypeCapabilityQueryError::Invariant)?;
        counters
            .check_constructed_type_depth(expression.depth())
            .map_err(TypeCapabilityQueryError::ResourceLimit)?;
        let mut counters = Some(counters);
        let mut memo = BTreeMap::new();
        let mut prove = |capability| {
            prove_sealed_capability(
                capability,
                descriptor,
                declarations,
                &mut counters,
                &mut memo,
            )
            .map_err(|error| match error {
                AnalysisError::ResourceLimit { error, .. } => {
                    TypeCapabilityQueryError::ResourceLimit(error)
                }
                _ => TypeCapabilityQueryError::Invariant,
            })
        };
        let equatable = prove(SealedCapability::Equatable)?;
        let external = prove(SealedCapability::ExternalValue)?;
        let interpolatable = prove(SealedCapability::Interpolatable)?;
        let mut independent_memo = BTreeMap::new();
        let independent = prove_independent_type_properties(
            descriptor,
            declarations,
            &mut counters,
            &mut independent_memo,
        )
        .map_err(|error| match error {
            AnalysisError::ResourceLimit { error, .. } => {
                TypeCapabilityQueryError::ResourceLimit(error)
            }
            _ => TypeCapabilityQueryError::Invariant,
        })?;
        Ok(TypeCapabilities {
            canonical_scalar_key: descriptor
                .primitive_properties()
                .is_some_and(|properties| properties.is_canonical_scalar_key()),
            hashable: descriptor
                .primitive_properties()
                .is_some_and(|properties| properties.is_hashable()),
            independent,
            equatable,
            external,
            interpolatable,
            orderable: descriptor
                .primitive_properties()
                .is_some_and(|properties| properties.is_orderable()),
        })
    }
}
