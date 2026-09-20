//! The collection key, canonical order, and `Map` type-identity foundation of `GNT-39.0` through
//! `GNT-39.5`.
//!
//! This module declares the key contract a source collection consumes: admission of the
//! canonical scalar-key domain, the canonical order, duplicate-key identity, and the identity of
//! the one recognised `Map<K, V>` type form. It admits no collection type as a value type, and
//! defines no traversal, no family behavior, and no storage fact.

use std::cmp::Ordering;

use gantry_core::canonical_key::{CanonicalKey, CanonicalKeyError, CanonicalKeyLimits};
use gantry_core::numeric::GantryInt;
use gantry_core::value::LogicalValue;

use crate::generated::TypeKind;
use crate::types::TypeDescriptor;

/// The declared clauses of `GNT-39.0` through `GNT-39.8`, in specification order.
pub const COLLECTION_CLAUSES: [&str; 9] = [
    "GNT-39.0-collection-key-and-order-scope",
    "GNT-39.1-admitted-collection-keys",
    "GNT-39.2-canonical-collection-order-and-duplicate-identity",
    "GNT-39.3-collection-foundation-non-claims",
    "GNT-39.4-map-type-form-recognition",
    "GNT-39.5-map-type-identity",
    "GNT-39.6-set-and-range-type-identities",
    "GNT-39.7-range-step-contract",
    "GNT-39.8-collection-value-model",
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

/// One admitted collection key type of a `Map<K, V>` or `Set<K>` type identity (`GNT-39.5`,
/// `GNT-39.6`).
///
/// The five variants are exactly the admitted collection key types of `GNT-39.1`: the scalar key
/// types whose canonical scalar-key format version 1.0 admits values into a collection key. The
/// order is the canonical scalar-key order of `GNT-39.2`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CollectionKeyType {
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

impl CollectionKeyType {
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

    /// Classifies one resolved descriptor as an admitted collection key type by its own kind.
    ///
    /// Classification reads the descriptor's closed type kind rather than comparing canonical
    /// text, so a descriptor whose kind is one of the five admitted keys is admitted and every
    /// other kind — a `Decision`, `OperationError`, `Never`, option, result, list, tuple, callable,
    /// `Map`, `Set`, `Range`, or declared type — is refused under `collection-invalid-key`, naming
    /// the refused argument. The refusal is the only outcome for an admitted-key text that denotes
    /// another type, so no argument is coerced, structurally encoded, or admitted through ordinary
    /// equality.
    pub fn from_descriptor(descriptor: &TypeDescriptor) -> Result<Self, CollectionError> {
        match descriptor.kind() {
            TypeKind::Unit => Ok(Self::Unit),
            TypeKind::Bool => Ok(Self::Bool),
            TypeKind::Int => Ok(Self::Int),
            TypeKind::Float => Ok(Self::Float),
            TypeKind::String => Ok(Self::String),
            TypeKind::Declared
            | TypeKind::Option
            | TypeKind::Result
            | TypeKind::List
            | TypeKind::Map
            | TypeKind::Set
            | TypeKind::Range
            | TypeKind::Tuple
            | TypeKind::Decision
            | TypeKind::OperationError
            | TypeKind::Callable
            | TypeKind::Never => Err(Self::refuse(&descriptor.canonical_string())),
        }
    }

    fn refuse(canonical_text: &str) -> CollectionError {
        CollectionError::new(
            CollectionDiagnosticCode::InvalidKey,
            format!("`{canonical_text}` is not an admitted collection key type"),
        )
    }
}

/// Reports whether one descriptor names a collection type kind anywhere inside it.
///
/// No collection type is admitted as a value type in this edition
/// (`GNT-39.4-map-type-form-recognition`), so a member that names one at any depth — the member
/// itself, or a collection inside a member of any other kind, or inside a declared type's arguments
/// — is one of the unadmitted members `GNT-39.5` and `GNT-39.6` refuse. The rule is the descriptor
/// algebra's own fail-closed predicate (`TypeDescriptor::contains_collection_type`), so the model
/// and the other callers of that predicate cannot drift apart.
fn contains_collection_kind(descriptor: &TypeDescriptor) -> bool {
    descriptor.contains_collection_type()
}

/// One admitted `Map<K, V>` type identity of `GNT-39.5`.
///
/// The identity is the pair of its resolved argument descriptors: an admitted key type and the
/// value argument carried unchanged. Admitting an identity decides no type admission, and publishes
/// no construction, projection, iteration, traversal, mutation, quota, schema, recovery,
/// durability, boundary encoding, lowering, or machine representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapTypeIdentity {
    key: CollectionKeyType,
    value: TypeDescriptor,
}

impl MapTypeIdentity {
    /// Admits one `Map<K, V>` type identity from its two resolved argument descriptors.
    ///
    /// The key argument is admitted exactly when its canonical descriptor text names one of the
    /// five admitted collection key types; any other key argument is refused under
    /// `collection-invalid-key` naming the refused argument. The value argument is any constructed
    /// type descriptor that names no collection type anywhere inside it: no collection type is
    /// admitted as a value type in this edition, so a value argument carrying one is refused under
    /// `collection-type-unadmitted`, exactly as the text decoder refuses the same identity text.
    pub fn admit(key: &TypeDescriptor, value: &TypeDescriptor) -> Result<Self, CollectionError> {
        let key = CollectionKeyType::from_descriptor(key)?;
        Self::admitted(key, value).ok_or_else(|| {
            CollectionError::new(
                CollectionDiagnosticCode::UnadmittedType,
                format!(
                    "`Map<{},{}>` carries a member this edition does not admit as a value type",
                    key.canonical_text(),
                    value.canonical_string()
                ),
            )
        })
    }

    /// The one construction rule both the argument path and the text decoder apply.
    ///
    /// `None` reports a value member that names a collection type this edition does not admit as a
    /// value type; each caller reports its own refused text, so an admitted identity and a refused
    /// one are the same decision on both paths.
    fn admitted(key: CollectionKeyType, value: &TypeDescriptor) -> Option<Self> {
        if contains_collection_kind(value) {
            return None;
        }
        Some(Self {
            key,
            value: value.clone(),
        })
    }

    /// Returns the admitted key type.
    #[must_use]
    pub fn key(&self) -> CollectionKeyType {
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

    /// Decodes one exact canonical `Map<K,V>` identity text.
    ///
    /// The text must be the canonical rendering of the identity: `Map<` then the key member text,
    /// one comma, the value member text, and `>`. A key member text that is not one of the five
    /// admitted key types is refused under `collection-invalid-key`, naming the refused member, so
    /// decoding admits no key the key domain refuses; any other text that is not the canonical
    /// rendering of one identity is refused under `collection-type-unadmitted`, so decoding admits
    /// no member kind this edition does not admit and no non-canonical spelling. No collection type
    /// is admitted as a value type in this edition (`GNT-39.4-map-type-form-recognition`), so a
    /// collection value member — a nested `Map`, `Set`, or `Range` — is one of the unadmitted
    /// members this decoder refuses, whether or not the descriptor algebra carries its structure.
    /// Decoding publishes the identity and nothing more: no descriptor kind, type admission, value, construction,
    /// projection, iteration, traversal, lowering, or machine representation.
    pub fn from_canonical_text(text: &str) -> Result<Self, CollectionError> {
        let inner = text
            .strip_prefix("Map<")
            .and_then(|rest| rest.strip_suffix('>'))
            .ok_or_else(|| Self::not_an_identity(text))?;
        let mut depth = 0u64;
        let mut separator = None;
        for (index, character) in inner.char_indices() {
            match character {
                '<' => depth += 1,
                '>' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| Self::not_an_identity(text))?;
                }
                ',' if depth == 0 => {
                    separator = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let separator = separator.ok_or_else(|| Self::not_an_identity(text))?;
        let (key_text, value_text) = (&inner[..separator], &inner[separator + 1..]);
        let key = CollectionKeyType::classify(key_text)?;
        let value = TypeDescriptor::from_canonical_string(value_text)
            .map_err(|_| Self::not_an_identity(text))?;
        let identity = Self::admitted(key, &value).ok_or_else(|| Self::not_an_identity(text))?;
        if identity.canonical_text() == text {
            Ok(identity)
        } else {
            Err(Self::not_an_identity(text))
        }
    }

    fn not_an_identity(text: &str) -> CollectionError {
        CollectionError::new(
            CollectionDiagnosticCode::UnadmittedType,
            format!("`{text}` is not the canonical text of one admitted Map identity"),
        )
    }
}

/// One admitted `Set<K>` type identity of `GNT-39.6`.
///
/// The identity is its admitted element key type, which is exactly one admitted collection key type
/// of `GNT-39.1` because a set element is a collection key. Admitting an identity decides no type
/// admission, and publishes no value, construction, traversal, mutation, quota, schema, recovery,
/// durability, boundary encoding, lowering, or machine representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetTypeIdentity {
    element: CollectionKeyType,
}

impl SetTypeIdentity {
    /// Admits one `Set<K>` type identity from its resolved argument descriptor.
    ///
    /// The element argument is admitted exactly when its canonical descriptor text names one of the
    /// five admitted collection key types; any other element argument is refused under
    /// `collection-invalid-key` naming the refused argument.
    pub fn admit(element: &TypeDescriptor) -> Result<Self, CollectionError> {
        Ok(Self {
            element: CollectionKeyType::from_descriptor(element)?,
        })
    }

    /// Returns the admitted element key type.
    #[must_use]
    pub fn element(&self) -> CollectionKeyType {
        self.element
    }

    /// Returns the canonical constructed-type text, for example `Set<Int>`.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!("Set<{}>", self.element.canonical_text())
    }

    /// Decodes one exact canonical `Set<K>` identity text.
    ///
    /// The element member text must name one of the five admitted key types (refused under
    /// `collection-invalid-key` naming the whole refused member, even when the text is also
    /// non-canonical or carries a member this edition does not admit), and any other input that is
    /// not the canonical rendering of one identity is refused under `collection-type-unadmitted`.
    /// The key rule applies first, exactly as it does for a `Map` key member.
    pub fn from_canonical_text(text: &str) -> Result<Self, CollectionError> {
        let element_text = text
            .strip_prefix("Set<")
            .and_then(|rest| rest.strip_suffix('>'))
            .ok_or_else(|| Self::not_an_identity(text))?;
        let identity = Self {
            element: CollectionKeyType::classify(element_text)?,
        };
        if identity.canonical_text() == text {
            Ok(identity)
        } else {
            Err(Self::not_an_identity(text))
        }
    }

    fn not_an_identity(text: &str) -> CollectionError {
        CollectionError::new(
            CollectionDiagnosticCode::UnadmittedType,
            format!("`{text}` is not the canonical text of one admitted Set identity"),
        )
    }
}

/// One admitted `Map` value of `GNT-39.8-collection-value-model`.
///
/// The value is its finite entries in the canonical collection order of `GNT-39.2`: each entry is
/// one admitted canonical key of `GNT-39.1-admitted-collection-keys` and the value member that key
/// resolves to. Admitting a value refuses a repeated key under `collection-duplicate-key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapValue {
    entries: Vec<(CanonicalKey, LogicalValue)>,
}

impl MapValue {
    /// Admits one `Map` value from its candidate entries in input order.
    ///
    /// Every key is admitted under the key contract of `GNT-39.1-admitted-collection-keys` and a
    /// repeated key is refused under `collection-duplicate-key` before anything is published; the
    /// admitted entries are then published in the canonical collection order of `GNT-39.2`.
    pub fn admit(
        policy: CollectionKeyPolicy,
        pairs: &[(LogicalValue, LogicalValue)],
    ) -> Result<Self, CollectionKeyRefusal> {
        let keys = pairs.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        let admitted = policy.admit_batch(&keys)?;
        let mut entries = admitted
            .into_iter()
            .zip(pairs.iter().map(|(_, value)| value.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| canonical_order(&left.0, &right.0));
        Ok(Self { entries })
    }

    /// Returns the admitted entries in canonical collection order.
    #[must_use]
    pub fn entries(&self) -> &[(CanonicalKey, LogicalValue)] {
        &self.entries
    }

    /// Returns the value member one admitted key resolves to, or `None`.
    #[must_use]
    pub fn get(&self, key: &CanonicalKey) -> Option<&LogicalValue> {
        self.entries
            .iter()
            .find(|(candidate, _)| canonical_order(candidate, key) == Ordering::Equal)
            .map(|(_, value)| value)
    }

    /// Returns the number of admitted entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the value has no admitted entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the value-layer nodes this value's content contributes (`GNT-39.8`).
    ///
    /// The value is one aggregate node and each entry adds one node for its admitted key plus the
    /// nodes of the value that key resolves to, read from the value layer's own metrics. The count
    /// saturates rather than wrapping.
    #[must_use]
    pub fn accounted_nodes(&self) -> u64 {
        self.entries.iter().fold(1_u64, |total, (_, value)| {
            total
                .saturating_add(1)
                .saturating_add(value.metrics().nodes)
        })
    }
}

/// One admitted `Set` value of `GNT-39.8-collection-value-model`.
///
/// The value is its finite elements in the canonical collection order of `GNT-39.2`: each element
/// is one admitted canonical key of `GNT-39.1-admitted-collection-keys`, because a set element is a
/// collection key. Admitting a value refuses a repeated element under `collection-duplicate-key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetValue {
    elements: Vec<CanonicalKey>,
}

impl SetValue {
    /// Admits one `Set` value from its candidate elements in input order.
    pub fn admit(
        policy: CollectionKeyPolicy,
        elements: &[LogicalValue],
    ) -> Result<Self, CollectionKeyRefusal> {
        let mut admitted = policy.admit_batch(elements)?;
        admitted.sort_by(canonical_order);
        Ok(Self { elements: admitted })
    }

    /// Returns the admitted elements in canonical collection order.
    #[must_use]
    pub fn elements(&self) -> &[CanonicalKey] {
        &self.elements
    }

    /// Reports whether one admitted key is an element of the value.
    #[must_use]
    pub fn contains(&self, key: &CanonicalKey) -> bool {
        self.elements
            .iter()
            .any(|candidate| canonical_order(candidate, key) == Ordering::Equal)
    }

    /// Returns the number of admitted elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Reports whether the value has no admitted element.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns the value-layer nodes this value's content contributes (`GNT-39.8`).
    ///
    /// The value is one aggregate node and each element is one admitted canonical key, so the count
    /// is one plus the number of elements. The count saturates rather than wrapping.
    #[must_use]
    pub fn accounted_nodes(&self) -> u64 {
        1_u64.saturating_add(u64::try_from(self.elements.len()).unwrap_or(u64::MAX))
    }
}

/// One admitted `Range` value of `GNT-39.8-collection-value-model`.
///
/// The value is its two bound positions over one admitted element type, ordered by the canonical
/// collection order of `GNT-39.2`: the start bound is inclusive, the end bound is exclusive, and an
/// unbounded side has no bound value there. The admissible step is exactly the sealed step contract
/// of `GNT-39.7-range-step-contract`, so a step whose result would leave its bound or the element's
/// canonical value range is exhaustion rather than a refusal, and this model publishes no traversal,
/// iteration, mutation, ownership, invalidation, or exhaustion reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeValue {
    start: Option<GantryInt>,
    end: Option<GantryInt>,
}

impl RangeValue {
    /// Publishes one `Range` value over its two bound positions.
    #[must_use]
    pub const fn new(start: Option<GantryInt>, end: Option<GantryInt>) -> Self {
        Self { start, end }
    }

    /// Returns the inclusive start bound, or `None` for an unbounded start.
    #[must_use]
    pub const fn start(self) -> Option<GantryInt> {
        self.start
    }

    /// Returns the exclusive end bound, or `None` for an unbounded end.
    #[must_use]
    pub const fn end(self) -> Option<GantryInt> {
        self.end
    }

    /// Reports whether one position is admitted: at or above the inclusive start bound and strictly
    /// below the exclusive end bound.
    #[must_use]
    pub fn admits(self, value: GantryInt) -> bool {
        self.start.is_none_or(|start| value >= start) && self.end.is_none_or(|end| value < end)
    }

    /// Returns the next admitted forward step, or `None` when the step is exhaustion.
    #[must_use]
    pub fn forward(self, value: GantryInt) -> Option<GantryInt> {
        let contract = RangeStepContract::Int;
        if contract.forward_within(value, self.end) {
            contract.successor(value)
        } else {
            None
        }
    }

    /// Returns the next admitted backward step, or `None` when the step is exhaustion.
    #[must_use]
    pub fn backward(self, value: GantryInt) -> Option<GantryInt> {
        let contract = RangeStepContract::Int;
        if contract.backward_within(value, self.start) {
            contract.predecessor(value)
        } else {
            None
        }
    }

    /// Returns the value-layer nodes this value's content contributes (`GNT-39.8`).
    ///
    /// The value is one aggregate node and each present bound position is one node, so an unbounded
    /// side contributes nothing.
    #[must_use]
    pub const fn accounted_nodes(self) -> u64 {
        1_u64
            .saturating_add(if self.start.is_some() { 1 } else { 0 })
            .saturating_add(if self.end.is_some() { 1 } else { 0 })
    }
}

/// One `Range<T>` type identity of `GNT-39.6`.
///
/// The identity is its element descriptor, which is any admitted value type: this clause publishes
/// the element argument, which names no collection type anywhere inside it, and no stepping
/// contract, so admitting an identity decides no type
/// admission and publishes no value, bounds, step, traversal, iteration, mutation, quota, schema,
/// recovery, durability, boundary encoding, lowering, or machine representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeTypeIdentity {
    element: TypeDescriptor,
}

impl RangeTypeIdentity {
    /// Publishes one `Range<T>` type identity over its resolved element descriptor.
    ///
    /// The element argument is any constructed type descriptor that names no collection type
    /// anywhere inside it: no collection type is admitted as a value type in this edition, so an
    /// element carrying one is refused under `collection-type-unadmitted`, exactly as the text
    /// decoder refuses the same identity text.
    pub fn new(element: TypeDescriptor) -> Result<Self, CollectionError> {
        if contains_collection_kind(&element) {
            return Err(CollectionError::new(
                CollectionDiagnosticCode::UnadmittedType,
                format!(
                    "`Range<{}>` carries a member this edition does not admit as a value type",
                    element.canonical_string()
                ),
            ));
        }
        Ok(Self { element })
    }

    /// Returns the element argument descriptor.
    #[must_use]
    pub fn element(&self) -> &TypeDescriptor {
        &self.element
    }

    /// Returns the canonical constructed-type text, for example `Range<Int>`.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        format!("Range<{}>", self.element.canonical_string())
    }

    /// Decodes one exact canonical `Range<T>` identity text.
    ///
    /// The element member text must be the canonical text of one admitted value type, and any input
    /// that is not the canonical rendering of one identity is refused under
    /// `collection-type-unadmitted`; no stepping, bounds, or iteration rule is decoded or admitted.
    /// No collection type is admitted as a value type in this edition
    /// (`GNT-39.4-map-type-form-recognition`), so an element member that names a collection type at
    /// any depth is one of the unadmitted members this decoder refuses through the identity's own
    /// construction rule.
    pub fn from_canonical_text(text: &str) -> Result<Self, CollectionError> {
        let element = text
            .strip_prefix("Range<")
            .and_then(|rest| rest.strip_suffix('>'))
            .ok_or_else(|| Self::not_an_identity(text))?;
        let element = TypeDescriptor::from_canonical_string(element)
            .map_err(|_| Self::not_an_identity(text))?;
        let identity = Self::new(element).map_err(|_| Self::not_an_identity(text))?;
        if identity.canonical_text() == text {
            Ok(identity)
        } else {
            Err(Self::not_an_identity(text))
        }
    }

    fn not_an_identity(text: &str) -> CollectionError {
        CollectionError::new(
            CollectionDiagnosticCode::UnadmittedType,
            format!("`{text}` is not the canonical text of one admitted Range identity"),
        )
    }
}

/// The sealed deterministic step contract of one `Range<T>` element type (`GNT-39.7`).
///
/// The contract is sealed: this clause declares every element type that admits stepping, and no
/// package, adapter, or host may define one. Exactly one element type is admitted in this edition —
/// `Int` — and its step is exactly one value toward the bound, taken with the element type's checked
/// arithmetic. The contract publishes no traversal, iteration, `for` integration, mutation,
/// ownership or invalidation, quota or suspension, schema, recovery, durability, boundary encoding,
/// lowering, machine representation, performance, or family behavior, and admits no `Range` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeStepContract {
    /// The `Int` element type.
    Int,
}

impl RangeStepContract {
    /// Every admitted element type, in canonical order.
    pub const ALL: [Self; 1] = [Self::Int];

    /// Returns the canonical element text of this contract.
    #[must_use]
    pub fn element_text(self) -> &'static str {
        match self {
            Self::Int => "Int",
        }
    }

    /// Returns the sealed contract of one element text, or nothing when the type admits none.
    #[must_use]
    pub fn sealed(element_text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|contract| contract.element_text() == element_text)
    }

    /// Returns the checked successor of one element value in the element's own domain, or nothing
    /// when the successor would leave the canonical `Int` value range.
    #[must_use]
    pub fn successor(self, value: GantryInt) -> Option<GantryInt> {
        match self {
            Self::Int => GantryInt::new(value.get().checked_add(1)?),
        }
    }

    /// Returns the checked predecessor of one element value in the element's own domain, or nothing
    /// when the predecessor would leave the canonical `Int` value range.
    #[must_use]
    pub fn predecessor(self, value: GantryInt) -> Option<GantryInt> {
        match self {
            Self::Int => GantryInt::new(value.get().checked_sub(1)?),
        }
    }

    /// Returns whether the forward step from `value` lands strictly below the exclusive end bound.
    ///
    /// The step is the successor of `value`, so a value whose successor is the end bound, or whose
    /// successor does not exist, is exhausted rather than inside the bound; an absent bound is
    /// unbounded on that side.
    #[must_use]
    pub fn forward_within(self, value: GantryInt, end: Option<GantryInt>) -> bool {
        match (self.successor(value), end) {
            (Some(next), Some(end)) => next < end,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Returns whether the backward step from `value` lands at or above the inclusive start bound.
    ///
    /// The step is the predecessor of `value`, so a value whose predecessor is the start bound is
    /// still inside it and a value whose predecessor would cross it, or does not exist, is
    /// exhausted; an absent bound is unbounded on that side.
    #[must_use]
    pub fn backward_within(self, value: GantryInt, start: Option<GantryInt>) -> bool {
        match (self.predecessor(value), start) {
            (Some(previous), Some(start)) => previous >= start,
            (Some(_), None) => true,
            (None, _) => false,
        }
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
