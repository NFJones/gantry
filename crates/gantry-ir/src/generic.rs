//! Validated generic analysis facts and closed executable projection contracts.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use gantry_core::source::SourceSpan;

use crate::generated::TemplateKind;
use crate::{
    CanonicalCallableIdentity, CanonicalPath, CanonicalSignature, CanonicalTemplateIdentity,
    EffectSet, StaticSiteId, TypeDescriptor, TypeExpression,
};

/// One canonical trait reference with ordered template arguments.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TraitReference {
    path: CanonicalPath,
    arguments: Vec<TypeExpression>,
}

impl TraitReference {
    /// Constructs one canonical trait reference.
    #[must_use]
    pub const fn new(path: CanonicalPath, arguments: Vec<TypeExpression>) -> Self {
        Self { path, arguments }
    }

    /// Returns the canonical trait path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns declaration-order trait arguments.
    #[must_use]
    pub fn arguments(&self) -> &[TypeExpression] {
        &self.arguments
    }

    /// Returns the exact canonical trait-reference spelling.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        let mut output = self.path.as_str().to_owned();
        if !self.arguments.is_empty() {
            output.push('<');
            for (index, argument) in self.arguments.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(argument.as_str());
            }
            output.push('>');
        }
        output
    }
}

/// One canonical `Trait<...> for Receiver` predicate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Predicate {
    trait_reference: TraitReference,
    receiver: TypeExpression,
}

impl Predicate {
    /// Constructs one canonical predicate.
    #[must_use]
    pub const fn new(trait_reference: TraitReference, receiver: TypeExpression) -> Self {
        Self {
            trait_reference,
            receiver,
        }
    }

    /// Returns the required trait.
    #[must_use]
    pub const fn trait_reference(&self) -> &TraitReference {
        &self.trait_reference
    }

    /// Returns the receiver expression.
    #[must_use]
    pub const fn receiver(&self) -> &TypeExpression {
        &self.receiver
    }

    /// Returns canonical bytes used to order predicate sets.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        format!(
            "{} for {}",
            self.trait_reference.canonical_string(),
            self.receiver.as_str()
        )
    }
}

/// One trait method signature and conservative effect contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraitMethodContract {
    name: Arc<str>,
    parameter_count: u64,
    mutable_receiver: bool,
    parameters: Vec<TypeExpression>,
    result: TypeExpression,
    predicates: Vec<Predicate>,
    effects: EffectSet,
}

impl TraitMethodContract {
    /// Constructs one method contract with a canonical predicate set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        parameter_count: u64,
        mutable_receiver: bool,
        parameters: Vec<TypeExpression>,
        result: TypeExpression,
        predicates: Vec<Predicate>,
        effects: EffectSet,
    ) -> Result<Self, GenericContractError> {
        validate_identifier(name)?;
        validate_predicates(&predicates)?;
        Ok(Self {
            name: Arc::from(name),
            parameter_count,
            mutable_receiver,
            parameters,
            result,
            predicates,
            effects,
        })
    }

    /// Returns the canonical method name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the method binder size.
    #[must_use]
    pub const fn parameter_count(&self) -> u64 {
        self.parameter_count
    }

    /// Returns whether the receiver is `mut self`.
    #[must_use]
    pub const fn mutable_receiver(&self) -> bool {
        self.mutable_receiver
    }

    /// Returns non-receiver parameter types in declaration order.
    #[must_use]
    pub fn parameters(&self) -> &[TypeExpression] {
        &self.parameters
    }

    /// Returns the declared result type.
    #[must_use]
    pub const fn result(&self) -> &TypeExpression {
        &self.result
    }

    /// Returns predicates in unsigned canonical-byte order.
    #[must_use]
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }

    /// Returns the conservative declared effects.
    #[must_use]
    pub const fn effects(&self) -> &EffectSet {
        &self.effects
    }
}

/// One canonical source trait declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraitContract {
    path: CanonicalPath,
    parameter_count: u64,
    predicates: Vec<Predicate>,
    methods: Vec<TraitMethodContract>,
}

impl TraitContract {
    /// Constructs one trait whose predicates and methods are canonically ordered.
    pub fn new(
        path: CanonicalPath,
        parameter_count: u64,
        predicates: Vec<Predicate>,
        methods: Vec<TraitMethodContract>,
    ) -> Result<Self, GenericContractError> {
        validate_predicates(&predicates)?;
        if methods
            .windows(2)
            .any(|pair| pair[0].name() >= pair[1].name())
        {
            return Err(GenericContractError::NoncanonicalOrder);
        }
        Ok(Self {
            path,
            parameter_count,
            predicates,
            methods,
        })
    }

    /// Returns the canonical trait path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns the trait binder size.
    #[must_use]
    pub const fn parameter_count(&self) -> u64 {
        self.parameter_count
    }

    /// Returns canonical declaration predicates.
    #[must_use]
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }

    /// Returns methods in canonical name order.
    #[must_use]
    pub fn methods(&self) -> &[TraitMethodContract] {
        &self.methods
    }
}

/// One canonical inherent or trait implementation identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalImplementationIdentity(Arc<str>);

impl CanonicalImplementationIdentity {
    /// Constructs an inherent implementation identity from its receiver head.
    #[must_use]
    pub fn inherent(receiver: &TypeExpression) -> Self {
        Self(Arc::from(format!("<{}>", receiver.as_str())))
    }

    /// Constructs a trait implementation identity from receiver and trait heads.
    #[must_use]
    pub fn trait_implementation(
        receiver: &TypeExpression,
        trait_reference: &TraitReference,
    ) -> Self {
        Self(Arc::from(format!(
            "<{} as {}>",
            receiver.as_str(),
            trait_reference.canonical_string()
        )))
    }

    /// Returns the exact canonical identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalImplementationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One implementation head retained before coherence checking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationHead {
    identity: CanonicalImplementationIdentity,
    parameter_count: u64,
    receiver: TypeExpression,
    trait_reference: Option<TraitReference>,
    predicates: Vec<Predicate>,
}

impl ImplementationHead {
    /// Constructs one canonically ordered implementation head.
    pub fn new(
        parameter_count: u64,
        receiver: TypeExpression,
        trait_reference: Option<TraitReference>,
        predicates: Vec<Predicate>,
    ) -> Result<Self, GenericContractError> {
        validate_predicates(&predicates)?;
        let identity = trait_reference.as_ref().map_or_else(
            || CanonicalImplementationIdentity::inherent(&receiver),
            |trait_reference| {
                CanonicalImplementationIdentity::trait_implementation(&receiver, trait_reference)
            },
        );
        Ok(Self {
            identity,
            parameter_count,
            receiver,
            trait_reference,
            predicates,
        })
    }

    /// Returns the canonical implementation identity.
    #[must_use]
    pub const fn identity(&self) -> &CanonicalImplementationIdentity {
        &self.identity
    }

    /// Returns the implementation binder size.
    #[must_use]
    pub const fn parameter_count(&self) -> u64 {
        self.parameter_count
    }

    /// Returns the implementation receiver head.
    #[must_use]
    pub const fn receiver(&self) -> &TypeExpression {
        &self.receiver
    }

    /// Returns the implemented trait, or `None` for an inherent block.
    #[must_use]
    pub const fn trait_reference(&self) -> Option<&TraitReference> {
        self.trait_reference.as_ref()
    }

    /// Returns canonical implementation predicates.
    #[must_use]
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }
}

/// One generic declared-type or callable template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericTemplate {
    kind: TemplateKind,
    identity: CanonicalTemplateIdentity,
    parameter_count: u64,
    predicates: Vec<Predicate>,
    conservative_effects: EffectSet,
}

impl GenericTemplate {
    /// Constructs one template with canonical predicates.
    pub fn new(
        kind: TemplateKind,
        identity: CanonicalTemplateIdentity,
        parameter_count: u64,
        predicates: Vec<Predicate>,
        conservative_effects: EffectSet,
    ) -> Result<Self, GenericContractError> {
        validate_predicates(&predicates)?;
        Ok(Self {
            kind,
            identity,
            parameter_count,
            predicates,
            conservative_effects,
        })
    }

    /// Returns the closed template category.
    #[must_use]
    pub const fn kind(&self) -> TemplateKind {
        self.kind
    }

    /// Returns the canonical template identity.
    #[must_use]
    pub const fn identity(&self) -> &CanonicalTemplateIdentity {
        &self.identity
    }

    /// Returns the total declaration binder size.
    #[must_use]
    pub const fn parameter_count(&self) -> u64 {
        self.parameter_count
    }

    /// Returns canonical declaration predicates.
    #[must_use]
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }

    /// Returns the conservative parametric effect contract.
    #[must_use]
    pub const fn conservative_effects(&self) -> &EffectSet {
        &self.conservative_effects
    }
}

/// Closed identity emitted for one retained instantiation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConcreteIdentity {
    /// One closed declared-type application.
    DeclaredType(TypeDescriptor),
    /// One direct concrete callable.
    Callable(CanonicalCallableIdentity),
}

impl ConcreteIdentity {
    /// Returns the exact canonical identity spelling used for ordering and source maps.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        match self {
            Self::DeclaredType(descriptor) => descriptor.canonical_string(),
            Self::Callable(callable) => callable.as_str().to_owned(),
        }
    }
}

/// One retained canonical instantiation key and its closed identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcreteInstantiation {
    kind: TemplateKind,
    template: CanonicalTemplateIdentity,
    arguments: Vec<TypeDescriptor>,
    concrete: ConcreteIdentity,
}

impl ConcreteInstantiation {
    /// Constructs one retained instantiation, rejecting mismatched identity categories.
    pub fn new(
        kind: TemplateKind,
        template: CanonicalTemplateIdentity,
        arguments: Vec<TypeDescriptor>,
        concrete: ConcreteIdentity,
    ) -> Result<Self, GenericContractError> {
        if matches!(kind, TemplateKind::DeclaredType)
            != matches!(concrete, ConcreteIdentity::DeclaredType(_))
        {
            return Err(GenericContractError::IdentityKindMismatch);
        }
        Ok(Self {
            kind,
            template,
            arguments,
            concrete,
        })
    }

    /// Returns the instantiation template kind.
    #[must_use]
    pub const fn kind(&self) -> TemplateKind {
        self.kind
    }

    /// Returns the template identity.
    #[must_use]
    pub const fn template(&self) -> &CanonicalTemplateIdentity {
        &self.template
    }

    /// Returns complete ordered closed arguments.
    #[must_use]
    pub fn arguments(&self) -> &[TypeDescriptor] {
        &self.arguments
    }

    /// Returns the emitted closed identity.
    #[must_use]
    pub const fn concrete(&self) -> &ConcreteIdentity {
        &self.concrete
    }
}

/// One statically resolved generic or trait call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCall {
    /// Canonical structural call site.
    pub site: StaticSiteId,
    /// Exact direct concrete target.
    pub callee: CanonicalCallableIdentity,
    /// Selected implementation when dispatch originated from a trait call.
    pub selected_implementation: Option<CanonicalImplementationIdentity>,
}

/// One exact concrete callable effect summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcreteEffect {
    /// Exact concrete callable.
    pub callable: CanonicalCallableIdentity,
    /// Least-fixed-point concrete effects.
    pub effects: EffectSet,
}

/// Multi-origin source mapping for one interned concrete type or callable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcreteSourceMapEntry {
    node: ConcreteIdentity,
    declaration: SourceSpan,
    origins: SourceOriginSet,
}

impl ConcreteSourceMapEntry {
    /// Binds one concrete node to its declaration and canonical origin set.
    #[must_use]
    pub const fn new(
        node: ConcreteIdentity,
        declaration: SourceSpan,
        origins: SourceOriginSet,
    ) -> Self {
        Self {
            node,
            declaration,
            origins,
        }
    }

    /// Returns the interned concrete node identity.
    #[must_use]
    pub const fn node(&self) -> &ConcreteIdentity {
        &self.node
    }

    /// Returns the authored generic declaration span.
    #[must_use]
    pub const fn declaration(&self) -> &SourceSpan {
        &self.declaration
    }

    /// Returns every concrete call or instantiation origin in canonical order.
    #[must_use]
    pub const fn origins(&self) -> &SourceOriginSet {
        &self.origins
    }
}

/// Canonical authored origins for one interned concrete node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceOriginSet(Arc<[SourceSpan]>);

impl SourceOriginSet {
    /// Sorts and deduplicates origins into canonical path/offset order.
    #[must_use]
    pub fn canonicalize(mut origins: Vec<SourceSpan>) -> Self {
        origins.sort();
        origins.dedup();
        Self(Arc::from(origins))
    }

    /// Admits already canonical origins, rejecting duplicates and disorder.
    pub fn from_canonical_origins(origins: Vec<SourceSpan>) -> Result<Self, GenericContractError> {
        if origins.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(GenericContractError::NoncanonicalOrigins);
        }
        Ok(Self(Arc::from(origins)))
    }

    /// Returns sorted, deduplicated authored origins.
    #[must_use]
    pub fn origins(&self) -> &[SourceSpan] {
        &self.0
    }
}

/// One monomorphized callable in the closed executable projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedCallable {
    identity: CanonicalCallableIdentity,
    signature: CanonicalSignature,
    effects: EffectSet,
    direct_calls: Vec<CanonicalCallableIdentity>,
}

impl ClosedCallable {
    /// Constructs one callable with sorted, deduplicated direct targets.
    pub fn new(
        identity: CanonicalCallableIdentity,
        signature: CanonicalSignature,
        effects: EffectSet,
        direct_calls: Vec<CanonicalCallableIdentity>,
    ) -> Result<Self, GenericContractError> {
        if direct_calls.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(GenericContractError::NoncanonicalOrder);
        }
        Ok(Self {
            identity,
            signature,
            effects,
            direct_calls,
        })
    }

    /// Returns the concrete callable identity.
    #[must_use]
    pub const fn identity(&self) -> &CanonicalCallableIdentity {
        &self.identity
    }

    /// Returns the closed callable signature.
    #[must_use]
    pub const fn signature(&self) -> &CanonicalSignature {
        &self.signature
    }

    /// Returns exact concrete effects.
    #[must_use]
    pub const fn effects(&self) -> &EffectSet {
        &self.effects
    }

    /// Returns direct targets in canonical identity order.
    #[must_use]
    pub fn direct_calls(&self) -> &[CanonicalCallableIdentity] {
        &self.direct_calls
    }
}

/// Distinct runtime projection containing only closed types and direct calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableProjection {
    types: Vec<TypeDescriptor>,
    callables: Vec<ClosedCallable>,
}

impl ExecutableProjection {
    /// Returns the empty closed projection used before analyzer lowering supplies records.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            types: Vec::new(),
            callables: Vec::new(),
        }
    }

    /// Constructs a projection only when records are canonical and call targets are closed.
    pub fn new(
        types: Vec<TypeDescriptor>,
        callables: Vec<ClosedCallable>,
    ) -> Result<Self, GenericContractError> {
        if types.windows(2).any(|pair| {
            pair[0].canonical_string().as_bytes() >= pair[1].canonical_string().as_bytes()
        }) || callables
            .windows(2)
            .any(|pair| pair[0].identity() >= pair[1].identity())
        {
            return Err(GenericContractError::NoncanonicalOrder);
        }
        let identities = callables
            .iter()
            .map(ClosedCallable::identity)
            .collect::<BTreeSet<_>>();
        if callables
            .iter()
            .flat_map(ClosedCallable::direct_calls)
            .any(|callee| !identities.contains(callee))
        {
            return Err(GenericContractError::MissingDirectTarget);
        }
        Ok(Self { types, callables })
    }

    /// Returns canonical closed descriptors.
    #[must_use]
    pub fn types(&self) -> &[TypeDescriptor] {
        &self.types
    }

    /// Returns concrete callables in identity order.
    #[must_use]
    pub fn callables(&self) -> &[ClosedCallable] {
        &self.callables
    }
}

/// Complete canonically ordered generic analysis facts and closed projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericAnalysisFacts {
    traits: Vec<TraitContract>,
    implementations: Vec<ImplementationHead>,
    templates: Vec<GenericTemplate>,
    instantiations: Vec<ConcreteInstantiation>,
    resolved_calls: Vec<ResolvedCall>,
    concrete_effects: Vec<ConcreteEffect>,
    source_map: Vec<ConcreteSourceMapEntry>,
    executable: ExecutableProjection,
}

impl GenericAnalysisFacts {
    /// Returns an empty fact set with a distinct empty closed projection.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            traits: Vec::new(),
            implementations: Vec::new(),
            templates: Vec::new(),
            instantiations: Vec::new(),
            resolved_calls: Vec::new(),
            concrete_effects: Vec::new(),
            source_map: Vec::new(),
            executable: ExecutableProjection::empty(),
        }
    }

    /// Constructs one complete generic fact set in canonical identity order.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        traits: Vec<TraitContract>,
        implementations: Vec<ImplementationHead>,
        templates: Vec<GenericTemplate>,
        instantiations: Vec<ConcreteInstantiation>,
        resolved_calls: Vec<ResolvedCall>,
        concrete_effects: Vec<ConcreteEffect>,
        source_map: Vec<ConcreteSourceMapEntry>,
        executable: ExecutableProjection,
    ) -> Result<Self, GenericContractError> {
        if traits
            .windows(2)
            .any(|pair| pair[0].path() >= pair[1].path())
            || implementations
                .windows(2)
                .any(|pair| pair[0].identity() >= pair[1].identity())
            || templates.windows(2).any(|pair| {
                (pair[0].kind(), pair[0].identity()) >= (pair[1].kind(), pair[1].identity())
            })
            || instantiations.windows(2).any(|pair| {
                (pair[0].kind(), pair[0].template(), pair[0].arguments())
                    >= (pair[1].kind(), pair[1].template(), pair[1].arguments())
            })
            || resolved_calls
                .windows(2)
                .any(|pair| pair[0].site >= pair[1].site)
            || concrete_effects
                .windows(2)
                .any(|pair| pair[0].callable >= pair[1].callable)
            || source_map
                .windows(2)
                .any(|pair| pair[0].node() >= pair[1].node())
        {
            return Err(GenericContractError::NoncanonicalOrder);
        }

        let implementation_ids = implementations
            .iter()
            .map(ImplementationHead::identity)
            .collect::<BTreeSet<_>>();
        if resolved_calls.iter().any(|call| {
            call.selected_implementation
                .as_ref()
                .is_some_and(|identity| !implementation_ids.contains(identity))
        }) {
            return Err(GenericContractError::MissingImplementation);
        }

        let template_ids = templates
            .iter()
            .map(GenericTemplate::identity)
            .collect::<BTreeSet<_>>();
        if instantiations
            .iter()
            .any(|instantiation| !template_ids.contains(instantiation.template()))
        {
            return Err(GenericContractError::MissingTemplate);
        }

        let callable_ids = executable
            .callables()
            .iter()
            .map(ClosedCallable::identity)
            .collect::<BTreeSet<_>>();
        if resolved_calls
            .iter()
            .any(|call| !callable_ids.contains(&call.callee))
            || concrete_effects
                .iter()
                .any(|effect| !callable_ids.contains(&effect.callable))
        {
            return Err(GenericContractError::MissingDirectTarget);
        }

        Ok(Self {
            traits,
            implementations,
            templates,
            instantiations,
            resolved_calls,
            concrete_effects,
            source_map,
            executable,
        })
    }

    /// Returns trait contracts in canonical path order.
    #[must_use]
    pub fn traits(&self) -> &[TraitContract] {
        &self.traits
    }

    /// Returns implementation heads in canonical identity order.
    #[must_use]
    pub fn implementations(&self) -> &[ImplementationHead] {
        &self.implementations
    }

    /// Returns generic templates in canonical key order.
    #[must_use]
    pub fn templates(&self) -> &[GenericTemplate] {
        &self.templates
    }

    /// Returns retained concrete instantiations in canonical key order.
    #[must_use]
    pub fn instantiations(&self) -> &[ConcreteInstantiation] {
        &self.instantiations
    }

    /// Returns resolved calls in structural-site order.
    #[must_use]
    pub fn resolved_calls(&self) -> &[ResolvedCall] {
        &self.resolved_calls
    }

    /// Returns exact concrete effects in callable-identity order.
    #[must_use]
    pub fn concrete_effects(&self) -> &[ConcreteEffect] {
        &self.concrete_effects
    }

    /// Returns multi-origin mappings in concrete-node order.
    #[must_use]
    pub fn source_map(&self) -> &[ConcreteSourceMapEntry] {
        &self.source_map
    }

    /// Returns the distinct closed executable projection.
    #[must_use]
    pub const fn executable(&self) -> &ExecutableProjection {
        &self.executable
    }
}

/// Rejection of malformed generic analysis or executable facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericContractError {
    /// A canonical identifier component is invalid.
    InvalidIdentifier,
    /// Canonical records are duplicated or out of order.
    NoncanonicalOrder,
    /// Source origins are duplicated or out of canonical order.
    NoncanonicalOrigins,
    /// A declared-type key names a callable, or the reverse.
    IdentityKindMismatch,
    /// A direct call names no callable in the executable projection.
    MissingDirectTarget,
    /// A retained instantiation names no declared template.
    MissingTemplate,
    /// A resolved trait call names no implementation head.
    MissingImplementation,
}

impl fmt::Display for GenericContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "generic contract identifier is not canonical",
            Self::NoncanonicalOrder => "generic contract records are not canonically ordered",
            Self::NoncanonicalOrigins => "source origins are not canonical",
            Self::IdentityKindMismatch => "template and concrete identity kinds do not match",
            Self::MissingDirectTarget => "executable projection has a missing direct target",
            Self::MissingTemplate => "generic instantiation has a missing template",
            Self::MissingImplementation => "resolved call has a missing implementation",
        })
    }
}

impl std::error::Error for GenericContractError {}

fn validate_predicates(predicates: &[Predicate]) -> Result<(), GenericContractError> {
    if predicates
        .windows(2)
        .any(|pair| pair[0].canonical_string().as_bytes() >= pair[1].canonical_string().as_bytes())
    {
        return Err(GenericContractError::NoncanonicalOrder);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), GenericContractError> {
    CanonicalPath::new(&format!("crate::{value}"))
        .map(|_| ())
        .map_err(|_| GenericContractError::InvalidIdentifier)
}

#[cfg(test)]
mod tests {
    use gantry_core::source::SourceSpan;

    use super::{
        ClosedCallable, ExecutableProjection, GenericContractError, Predicate, SourceOriginSet,
        TraitReference,
    };
    use crate::{
        CanonicalCallableIdentity, CanonicalPath, CanonicalSignature, EffectSet, TypeDescriptor,
        TypeExpression,
    };

    #[test]
    fn predicates_use_ordinals_and_require_canonical_order() {
        let parameter = TypeExpression::parameter(0, 0, 8)
            .unwrap_or_else(|_| unreachable!("bounded parameter is valid"));
        let first = Predicate::new(
            TraitReference::new(
                CanonicalPath::new("crate::Display")
                    .unwrap_or_else(|_| unreachable!("constant path is canonical")),
                Vec::new(),
            ),
            parameter.clone(),
        );
        let second = Predicate::new(
            TraitReference::new(
                CanonicalPath::new("crate::Label")
                    .unwrap_or_else(|_| unreachable!("constant path is canonical")),
                Vec::new(),
            ),
            parameter,
        );
        assert_eq!(first.canonical_string(), "crate::Display for ^0.0");
        assert!(super::validate_predicates(&[first.clone(), second.clone()]).is_ok());
        assert_eq!(
            super::validate_predicates(&[second, first]),
            Err(GenericContractError::NoncanonicalOrder)
        );
    }

    #[test]
    fn source_origin_canonicalization_is_permutation_independent() {
        let first = SourceSpan::from_portable_parts("main.gnt", 1, 2)
            .unwrap_or_else(|_| unreachable!("constant span is portable"));
        let second = SourceSpan::from_portable_parts("main.gnt", 3, 4)
            .unwrap_or_else(|_| unreachable!("constant span is portable"));
        let left =
            SourceOriginSet::canonicalize(vec![second.clone(), first.clone(), first.clone()]);
        let right = SourceOriginSet::canonicalize(vec![first.clone(), second.clone()]);
        assert_eq!(left, right);
        assert_eq!(left.origins(), [first.clone(), second.clone()]);
        assert_eq!(
            SourceOriginSet::from_canonical_origins(vec![first.clone(), first]),
            Err(GenericContractError::NoncanonicalOrigins)
        );
    }

    #[test]
    fn executable_projection_rejects_missing_direct_targets() {
        let main_path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let helper_path = CanonicalPath::new("crate::helper")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let main = CanonicalCallableIdentity::free(&main_path, &[]);
        let helper = CanonicalCallableIdentity::free(&helper_path, &[]);
        let callable = ClosedCallable::new(
            main,
            CanonicalSignature::function(&main_path, &[], &TypeDescriptor::UNIT),
            EffectSet::default(),
            vec![helper],
        )
        .unwrap_or_else(|_| unreachable!("direct targets are ordered"));
        assert_eq!(
            ExecutableProjection::new(vec![TypeDescriptor::UNIT], vec![callable]),
            Err(GenericContractError::MissingDirectTarget)
        );
    }
}
