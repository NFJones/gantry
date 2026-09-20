//! The collection key and canonical order foundation of `GNT-39.0` through `GNT-39.3`.
//!
//! This module declares the key contract a source collection consumes: admission of the
//! canonical scalar-key domain, the canonical order, and duplicate-key identity. It defines no
//! collection type, no traversal, no family behavior, and no storage fact.

use std::cmp::Ordering;

use gantry_core::canonical_key::{CanonicalKey, CanonicalKeyError, CanonicalKeyLimits};
use gantry_core::value::LogicalValue;

/// The declared clauses of `GNT-39.0` through `GNT-39.3`, in specification order.
pub const COLLECTION_CLAUSES: [&str; 4] = [
    "GNT-39.0-collection-key-and-order-scope",
    "GNT-39.1-admitted-collection-keys",
    "GNT-39.2-canonical-collection-order-and-duplicate-identity",
    "GNT-39.3-collection-foundation-non-claims",
];

/// One frozen collection-foundation diagnostic of `GNT-39.0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionDiagnosticCode {
    /// `GNT-39.1`: the candidate kind is not an admitted collection key.
    InvalidKey,
    /// `GNT-39.2`: two admitted keys share one identity.
    DuplicateKey,
    /// `GNT-39.3`: a declared non-claim is presented as a guarantee it does not make.
    NonClaimAsGuarantee,
}

impl CollectionDiagnosticCode {
    /// Every declared diagnostic, in declaration order.
    pub const ALL: [Self; 3] = [
        Self::InvalidKey,
        Self::DuplicateKey,
        Self::NonClaimAsGuarantee,
    ];

    /// Returns the registered refusal spelling.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::InvalidKey => "collection-invalid-key",
            Self::DuplicateKey => "collection-duplicate-key",
            Self::NonClaimAsGuarantee => "collection-non-claim-as-guarantee",
        }
    }

    /// Returns the one clause that owns this refusal condition.
    #[must_use]
    pub fn owning_clause(self) -> &'static str {
        match self {
            Self::InvalidKey => "GNT-39.1-admitted-collection-keys",
            Self::DuplicateKey => "GNT-39.2-canonical-collection-order-and-duplicate-identity",
            Self::NonClaimAsGuarantee => "GNT-39.3-collection-foundation-non-claims",
        }
    }
}

/// One refused collection-foundation decision of `GNT-39.0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionError {
    code: CollectionDiagnosticCode,
    detail: String,
}

impl CollectionError {
    /// Declares one refusal under its owning diagnostic.
    pub fn new(code: CollectionDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the owning diagnostic.
    #[must_use]
    pub fn code(&self) -> CollectionDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// One refused key admission or identity decision of `GNT-39.1` and `GNT-39.2`: the collection
/// contract's own refusal, or the canonical scalar-key contract's refusal passed through
/// unchanged so no refusal spelling is shared between the two contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionKeyRefusal {
    /// `GNT-39.1`: the candidate kind is not an admitted collection key.
    InvalidKey(CollectionError),
    /// `GNT-39.2`: two admitted keys share one identity.
    DuplicateKey(CollectionError),
    /// `GNT-5.15`: the canonical scalar-key contract refused the candidate.
    Canonical(CanonicalKeyError),
}

/// The collection key policy of `GNT-39.1` and `GNT-39.2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectionKeyPolicy {
    limits: CanonicalKeyLimits,
}

impl CollectionKeyPolicy {
    /// Declares one key policy over the canonical key contract's frame limits.
    #[must_use]
    pub const fn new(limits: CanonicalKeyLimits) -> Self {
        Self { limits }
    }

    /// Returns the canonical-frame limits this policy admits under.
    #[must_use]
    pub const fn limits(self) -> CanonicalKeyLimits {
        self.limits
    }

    /// Admits one candidate key of `GNT-39.1`.
    ///
    /// A candidate outside the admitted canonical scalar-key domain is refused under
    /// `collection-invalid-key`, naming the refused kind; the framing, length, scalar-range, and
    /// UTF-8 refusals of the canonical scalar-key contract are passed through unchanged.
    pub fn admit(&self, value: &LogicalValue) -> Result<CanonicalKey, CollectionKeyRefusal> {
        value
            .canonical_key(self.limits)
            .map_err(|error| match error {
                CanonicalKeyError::IneligibleKind(kind) => {
                    CollectionKeyRefusal::InvalidKey(CollectionError::new(
                        CollectionDiagnosticCode::InvalidKey,
                        format!("`{kind:?}` is not an admitted collection key"),
                    ))
                }
                other => CollectionKeyRefusal::Canonical(other),
            })
    }

    /// Admits one batch of candidate keys of `GNT-39.2`.
    ///
    /// Every candidate is admitted in input order, and a batch whose admitted keys do not have
    /// unique identity is refused under `collection-duplicate-key`, reporting the zero-based first
    /// and first-repeated input indices. No output is published unless every key is admitted and
    /// every identity is unique.
    pub fn admit_batch(
        &self,
        values: &[LogicalValue],
    ) -> Result<Vec<CanonicalKey>, CollectionKeyRefusal> {
        let mut admitted = Vec::with_capacity(values.len());
        for value in values {
            admitted.push(self.admit(value)?);
        }
        for (index, key) in admitted.iter().enumerate() {
            let repeated = admitted[..index]
                .iter()
                .position(|earlier| earlier.cmp(key) == Ordering::Equal);
            if let Some(first) = repeated {
                return Err(CollectionKeyRefusal::DuplicateKey(CollectionError::new(
                    CollectionDiagnosticCode::DuplicateKey,
                    format!("keys at input indices {first} and {index} share one identity"),
                )));
            }
        }
        Ok(admitted)
    }
}

/// Returns the canonical collection order of two admitted keys (`GNT-39.2`).
///
/// The order is the canonical scalar-key order: `Unit < Bool < Int < Float < String`, with `Int`
/// and `Float` numerically and independently and `String` in lexicographic Unicode-scalar order.
/// Equality is value equality, so normalized signed zeros compare equal and no comparison is made
/// over frame bytes or content hashes.
#[must_use]
pub fn canonical_order(left: &CanonicalKey, right: &CanonicalKey) -> Ordering {
    left.cmp(right)
}

/// One declared non-claim of `GNT-39.3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionNonClaimName {
    /// No source collection type and no collection API.
    SourceCollectionType,
    /// No range stepping, iterator ownership or invalidation, traversal, mutation, exhaustion,
    /// suspension, quota, schema, recovery, or durable behavior.
    RangeIteratorAndDurability,
    /// No family behavior.
    FamilyBehavior,
    /// No storage layout or physical representation.
    StorageLayout,
    /// No performance claim.
    Performance,
    /// No boundary encoding beyond the consumed canonical key frame.
    BoundaryEncoding,
}

impl CollectionNonClaimName {
    /// Every declared non-claim, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::SourceCollectionType,
        Self::RangeIteratorAndDurability,
        Self::FamilyBehavior,
        Self::StorageLayout,
        Self::Performance,
        Self::BoundaryEncoding,
    ];

    /// Returns the declared label of this non-claim.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceCollectionType => "no source collection type or collection API",
            Self::RangeIteratorAndDurability => {
                "no range, iterator, traversal, quota, schema, recovery, or durable behavior"
            }
            Self::FamilyBehavior => "no family behavior",
            Self::StorageLayout => "no storage layout or physical representation",
            Self::Performance => "no performance claim",
            Self::BoundaryEncoding => "no boundary encoding beyond the canonical key frame",
        }
    }
}

/// One assertion about a declared non-claim of `GNT-39.3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectionNonClaimAssertion {
    /// Non-claim being asserted.
    pub name: CollectionNonClaimName,
    /// Whether the assertion presents the non-claim as a guarantee.
    pub claims_as_guarantee: bool,
}

/// Verifies that every declared non-claim is asserted and none is presented as a guarantee.
pub fn check_collection_non_claims(
    assertions: &[CollectionNonClaimAssertion],
) -> Result<(), CollectionError> {
    for name in CollectionNonClaimName::ALL {
        let asserted = assertions.iter().find(|entry| entry.name == name);
        match asserted {
            None => {
                return Err(CollectionError::new(
                    CollectionDiagnosticCode::NonClaimAsGuarantee,
                    format!("non-claim {} is not asserted", name.as_str()),
                ));
            }
            Some(entry) if entry.claims_as_guarantee => {
                return Err(CollectionError::new(
                    CollectionDiagnosticCode::NonClaimAsGuarantee,
                    format!("non-claim {} is presented as a guarantee", name.as_str()),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}
