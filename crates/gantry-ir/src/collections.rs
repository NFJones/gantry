//! The collection key, canonical order, and `Map` type-identity foundation of `GNT-39.0` through
//! `GNT-39.5`.
//!
//! This module declares the key contract a source collection consumes: admission of the
//! canonical scalar-key domain, the canonical order, duplicate-key identity, and the identity of
//! the one recognised `Map<K, V>` type form. It admits no collection type as a value type, and
//! defines no traversal, no family behavior, and no storage fact.

use std::cmp::Ordering;

use gantry_core::canonical_key::{CanonicalKey, CanonicalKeyError, CanonicalKeyLimits};
use gantry_core::value::LogicalValue;

use crate::types::TypeDescriptor;

/// The declared clauses of `GNT-39.0` through `GNT-39.5`, in specification order.
pub const COLLECTION_CLAUSES: [&str; 6] = [
    "GNT-39.0-collection-key-and-order-scope",
    "GNT-39.1-admitted-collection-keys",
    "GNT-39.2-canonical-collection-order-and-duplicate-identity",
    "GNT-39.3-collection-foundation-non-claims",
    "GNT-39.4-map-type-form-recognition",
    "GNT-39.5-map-type-identity",
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
    /// `GNT-39.4`: a recognised `Map<K, V>` occurrence is not admitted as a type.
    UnadmittedType,
}

impl CollectionDiagnosticCode {
    /// Every declared diagnostic, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::InvalidKey,
        Self::DuplicateKey,
        Self::NonClaimAsGuarantee,
        Self::UnadmittedType,
    ];

    /// Returns the registered refusal spelling.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        match self {
            Self::InvalidKey => "collection-invalid-key",
            Self::DuplicateKey => "collection-duplicate-key",
            Self::NonClaimAsGuarantee => "collection-non-claim-as-guarantee",
            Self::UnadmittedType => "collection-type-unadmitted",
        }
    }

    /// Returns the one clause that owns this refusal condition.
    #[must_use]
    pub fn owning_clause(self) -> &'static str {
        match self {
            Self::InvalidKey => "GNT-39.1-admitted-collection-keys",
            Self::DuplicateKey => "GNT-39.2-canonical-collection-order-and-duplicate-identity",
            Self::NonClaimAsGuarantee => "GNT-39.3-collection-foundation-non-claims",
            Self::UnadmittedType => "GNT-39.4-map-type-form-recognition",
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

/// One admitted collection key type of a `Map<K, V>` type identity (`GNT-39.5`).
///
/// The five variants are exactly the admitted collection key types of `GNT-39.1`: the scalar key
/// types whose canonical scalar-key format version 1.0 admits values into a collection key. The
/// order is the canonical scalar-key order of `GNT-39.2`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MapKeyType {
    /// `Unit`.
    Unit,
    /// `Bool`.
    Bool,
    /// `Int`.
    Int,
    /// `Float`.
    Float,
    /// `String`.
    String,
}

impl MapKeyType {
    /// Every admitted key type, in canonical scalar-key order.
    pub const ALL: [Self; 5] = [Self::Unit, Self::Bool, Self::Int, Self::Float, Self::String];

    /// Returns the canonical type text of this key type.
    #[must_use]
    pub fn canonical_text(self) -> &'static str {
        match self {
            Self::Unit => "Unit",
            Self::Bool => "Bool",
            Self::Int => "Int",
            Self::Float => "Float",
            Self::String => "String",
        }
    }

    /// Classifies one canonical type text as an admitted collection key type.
    ///
    /// An argument of any other type — including `Decision`, `OperationError`, an option, result,
    /// list, tuple, callable, or declared type, and a type parameter — is refused under
    /// `collection-invalid-key`, naming the refused argument, rather than coerced, structurally
    /// encoded, or admitted through ordinary equality.
    pub fn classify(canonical_text: &str) -> Result<Self, CollectionError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.canonical_text() == canonical_text)
            .ok_or_else(|| {
                CollectionError::new(
                    CollectionDiagnosticCode::InvalidKey,
                    format!("`{canonical_text}` is not an admitted collection key type"),
                )
            })
    }
}

/// One admitted `Map<K, V>` type identity of `GNT-39.5`.
///
/// The identity is the pair of its resolved argument descriptors: an admitted key type and the
/// value argument carried unchanged. Admitting an identity decides no type admission, and publishes
/// no construction, projection, iteration, traversal, mutation, quota, schema, recovery,
/// durability, boundary encoding, lowering, or machine representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapTypeIdentity {
    key: MapKeyType,
    value: TypeDescriptor,
}

impl MapTypeIdentity {
    /// Admits one `Map<K, V>` type identity from its two resolved argument descriptors.
    ///
    /// The key argument is admitted exactly when its canonical descriptor text names one of the
    /// five admitted collection key types; any other key argument is refused under
    /// `collection-invalid-key` naming the refused argument. The value argument is any constructed
    /// type descriptor and is carried unchanged.
    pub fn admit(key: &TypeDescriptor, value: &TypeDescriptor) -> Result<Self, CollectionError> {
        Ok(Self {
            key: MapKeyType::classify(&key.canonical_string())?,
            value: value.clone(),
        })
    }

    /// Returns the admitted key type.
    #[must_use]
    pub fn key(&self) -> MapKeyType {
        self.key
    }

    /// Returns the value argument descriptor.
    #[must_use]
    pub fn value(&self) -> &TypeDescriptor {
        &self.value
    }

    /// Returns the canonical constructed-type text, for example `Map<Int,String>`.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!(
            "Map<{},{}>",
            self.key.canonical_text(),
            self.value.canonical_string()
        )
    }
}

/// One declared non-claim of `GNT-39.3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionNonClaimName {
    /// No source collection value, operation, or collection API.
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
            Self::SourceCollectionType => {
                "no source collection value, operation, or collection API"
            }
            Self::RangeIteratorAndDurability => {
                "no range stepping, iterator ownership or invalidation, traversal, mutation, exhaustion, suspension, quotas, schemas, recovery, or durable behavior"
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
