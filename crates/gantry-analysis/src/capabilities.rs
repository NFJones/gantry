//! Bounded inspection of capabilities in an already validated package.
//!
//! Queries share the analyzer's structural prover, but never its mutable cache
//! or activity budget. No query admits a new source type or executable artifact.

use std::collections::BTreeMap;

use gantry_core::source::{FrontendLimits, FrontendResourceLimit, GenericAnalysisCounters};
use gantry_ir::{OwnershipClass, TypeDescriptor, TypeExpression};

use crate::generics::{SealedCapability, prove_ownership_class, prove_sealed_capability};
use crate::{AnalysisError, AnalysisStatus, TypedPackage};

/// Independent compiler-owned capability results, not execution admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeCapabilities {
    ownership_class: OwnershipClass,
    equatable: bool,
    external: bool,
    interpolatable: bool,
}

impl TypeCapabilities {
    /// Whether the validated v1 value permits independent logical copies.
    ///
    /// Every currently admitted first-class value is copyable, including sealed
    /// values that cannot cross an external boundary. Task handles are not values.
    #[must_use]
    pub const fn is_copyable(self) -> bool {
        matches!(self.ownership_class(), gantry_ir::OwnershipClass::Copyable)
    }

    /// Returns the ownership class of this validated v1 value.
    ///
    /// Noncopyable classifications do not yet have source inhabitants in v1.
    #[must_use]
    pub const fn ownership_class(self) -> OwnershipClass {
        self.ownership_class
    }

    /// Whether a v1 task may capture an independent copy of this value.
    ///
    /// This is source-task capture eligibility, not shared identity, host-thread
    /// safety, authority delegation, or permission to spawn a task.
    #[must_use]
    pub const fn is_task_capturable(self) -> bool {
        matches!(self.ownership_class, OwnershipClass::Copyable)
    }

    /// Whether the stored value satisfies `Equatable`.
    #[must_use]
    pub const fn is_equatable(self) -> bool {
        self.equatable
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
        let mut ownership_memo = BTreeMap::new();
        let ownership_class =
            prove_ownership_class(descriptor, declarations, &mut counters, &mut ownership_memo)
                .map_err(|error| match error {
                    AnalysisError::ResourceLimit { error, .. } => {
                        TypeCapabilityQueryError::ResourceLimit(error)
                    }
                    _ => TypeCapabilityQueryError::Invariant,
                })?;
        Ok(TypeCapabilities {
            ownership_class,
            equatable,
            external,
            interpolatable,
        })
    }
}
