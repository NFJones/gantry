//! Body typing, static trait selection, and completion validation.
//!
//! This pass intentionally uses explicit syntax-node work collections. It
//! validates deterministic value flow, module-visible trait lookup, concrete
//! obligation proof, pattern coverage, parametric generic bodies, and the
//! canonical reachable instantiation closure. Exact effect inference and final
//! executable-artifact lowering remain owned by later analyzer passes.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::portable::{
    DiagnosticCategory, DiagnosticSeverity, FrontendResourceCode, GenericAnalysisCode,
};
use gantry_core::source::{
    DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, FrontendResourceLimit,
    GenericAnalysisCounters, SourceSpan, StructuredDiagnostic,
};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::{Effect, TemplateKind, TypeKind};
use gantry_ir::{
    CanonicalCallableIdentity, CanonicalImplementationIdentity, CanonicalPath,
    CanonicalTemplateIdentity, ConcreteIdentity, ConcreteInstantiation, EffectSet, GenericTemplate,
    ImplementationHead, OwnershipClass, Predicate, ReceiverMode, TraitContract,
    TraitMethodContract, TraitReference, TransferEligibility, TypeDescriptor, TypeDescriptorError,
    TypeExpression, WorkflowParameter,
};

use crate::generics::{
    CapabilityPredicate, ExactTypeSubstitution, GenericDeclarationShape, SealedCapability,
    TypeInferenceFailure, TypeParameterKey, collect_capability_predicates,
    collect_type_parameter_keys, collect_where_predicates,
    invalid_generic_option_member_declaration, prove_ownership_class, prove_sealed_capability,
    prove_transfer_eligibility, substitute_self_type,
};
use crate::{
    AnalysisError, GenericTypeFact, PackageStructure, Symbol, SymbolId, SymbolKind, TypeBinder,
    TypeFact,
};

#[derive(Clone, Debug)]
struct BlockResult {
    falls_through: bool,
    trailing: Option<TypeDescriptor>,
    breaks_loop: bool,
    continues_loop: bool,
    /// The block left through a construct with no normal completion rather than an explicit
    /// `return`/`break`/`continue` transfer, so an obligation it still owes surfaces at the
    /// enclosing scope exit instead of being settled by the transfer.
    diverges: bool,
}

/// Completion of one statement `match`: `GNT-3-T-BRANCH` merges every feasible
/// arm's completion map, so a normal exit is reachable only when some arm falls
/// through and each loop transfer is reachable from some arm.
struct StatementCompletion {
    falls_through: bool,
    breaks_loop: bool,
    continues_loop: bool,
    diverges: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoolFact {
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug)]
struct CallableSignature {
    parameters: Vec<TypeDescriptor>,
    result: TypeDescriptor,
}

#[derive(Clone, Debug)]
struct InherentMethodMetadata {
    declaration: SourceSpan,
    receiver_mode: ReceiverMode,
}

#[derive(Clone, Debug)]
struct GenericCallableSignature {
    kind: TemplateKind,
    path: CanonicalPath,
    template: CanonicalTemplateIdentity,
    receiver: Option<TypeExpression>,
    trait_reference: Option<TraitReference>,
    method_name: Option<Arc<str>>,
    implementation: Option<CanonicalImplementationIdentity>,
    implementation_parameter_count: usize,
    source_index: usize,
    declaration: NodeId,
    required: Vec<TypeParameterKey>,
    predicates: Vec<Predicate>,
    sealed_predicates: Vec<CapabilityPredicate>,
    parameters: Vec<TypeExpression>,
    parameter_mutability: Vec<bool>,
    result: TypeExpression,
}

pub(crate) type InstantiationKey = (CanonicalTemplateIdentity, Vec<TypeDescriptor>);

type PostfixFieldSequence = (Arc<str>, Vec<(Arc<str>, NodeId)>);

/// One addressable place in the affine move ledger: a binding root plus projected struct fields.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AffinePlace {
    root: Arc<str>,
    path: Vec<Arc<str>>,
}

impl AffinePlace {
    fn root_only(root: Arc<str>) -> Self {
        Self {
            root,
            path: Vec::new(),
        }
    }

    fn projected(root: Arc<str>, path: Vec<Arc<str>>) -> Self {
        Self { root, path }
    }

    /// Returns whether one place is an ancestor-or-equal projection of the other.
    fn intersects(&self, other: &Self) -> bool {
        self.root == other.root
            && (self.path.starts_with(&other.path) || other.path.starts_with(&self.path))
    }
}

type EffectSummaries = (
    BTreeMap<CanonicalTemplateIdentity, EffectSet>,
    BTreeMap<InstantiationKey, EffectSet>,
    BTreeMap<SourceSpan, EffectSet>,
);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EffectNode {
    Source(SourceSpan),
    Template(CanonicalTemplateIdentity),
    Concrete(InstantiationKey),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EffectDraft {
    pub(crate) direct: EffectSet,
    pub(crate) calls: BTreeSet<EffectNode>,
    pub(crate) pure: bool,
    pub(crate) source: Option<SourceSpan>,
    pub(crate) contributors: BTreeMap<Effect, SourceSpan>,
    pub(crate) call_sites: BTreeMap<EffectNode, SourceSpan>,
}

pub(crate) struct BodyAnalysis {
    pub(crate) expression_types: Vec<BTreeMap<NodeId, TypeDescriptor>>,
    pub(crate) struct_fields: BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, TypeDescriptor>>,
    /// Typed outer binding candidates indexed by closed owner and authored spawn.
    pub(crate) spawn_captures:
        BTreeMap<EffectNode, BTreeMap<SourceSpan, Vec<SpawnCaptureMetadata>>>,
    pub(crate) generic_templates: Vec<GenericTemplate>,
    pub(crate) generic_instantiations: Vec<ConcreteInstantiation>,
    pub(crate) concrete_callables: Vec<ConcreteCallableMetadata>,
    pub(crate) resolved_calls: Vec<ResolvedCallMetadata>,
    pub(crate) source_callables: Vec<SourceCallableMetadata>,
    pub(crate) closed_enums: BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, Option<TypeDescriptor>>>,
    pub(crate) generic_declarations: BTreeSet<SourceSpan>,
    pub(crate) generic_template_effects: BTreeMap<CanonicalTemplateIdentity, EffectSet>,
    pub(crate) generic_concrete_effects: BTreeMap<InstantiationKey, EffectSet>,
}

/// A visible value binding from which lowering selects the exact free captures.
#[derive(Clone, Debug)]
pub(crate) struct SpawnCaptureMetadata {
    /// Analyzer-resolved lexical name; never a task-handle name.
    pub(crate) name: Arc<str>,
    /// Binding type after substitution for a concrete callable.
    pub(crate) ty: TypeDescriptor,
    /// Whether the copied child-local binding permits assignment.
    pub(crate) mutable: bool,
}

pub(crate) struct ConcreteCallableMetadata {
    pub(crate) key: InstantiationKey,
    pub(crate) receiver: Option<TypeDescriptor>,
    pub(crate) mutable_receiver: bool,
    pub(crate) parameters: Vec<WorkflowParameter>,
    pub(crate) result: TypeDescriptor,
    pub(crate) declaration: SourceSpan,
    pub(crate) declaration_types: BTreeMap<NodeId, TypeFact>,
    pub(crate) expression_types: BTreeMap<NodeId, TypeDescriptor>,
    pub(crate) origins: Vec<SourceSpan>,
    pub(crate) direct_calls: Vec<EffectNode>,
    pub(crate) operation_results: BTreeMap<SourceSpan, TypeDescriptor>,
}

pub(crate) struct ResolvedCallMetadata {
    pub(crate) caller: EffectNode,
    pub(crate) callee: EffectNode,
    pub(crate) source: SourceSpan,
    pub(crate) selected_implementation: Option<CanonicalImplementationIdentity>,
}

pub(crate) struct SourceCallableMetadata {
    pub(crate) identity: CanonicalCallableIdentity,
    pub(crate) receiver: Option<TypeDescriptor>,
    pub(crate) receiver_mode: Option<ReceiverMode>,
    pub(crate) parameters: Vec<WorkflowParameter>,
    pub(crate) result: TypeDescriptor,
    pub(crate) effects: EffectSet,
    pub(crate) declaration: SourceSpan,
    pub(crate) direct_calls: Vec<EffectNode>,
}

#[derive(Clone, Debug)]
struct GenericMethodResolution {
    signature: GenericCallableSignature,
    concrete_arguments: Vec<TypeDescriptor>,
    callable: CallableSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeclaredTraitObligation {
    trait_path: CanonicalPath,
    trait_arguments: Vec<TypeDescriptor>,
    receiver: TypeDescriptor,
}

#[derive(Clone, Debug)]
struct StructFieldShape {
    ty: TypeDescriptor,
    required: bool,
}

#[derive(Clone, Debug)]
struct StructShape {
    descriptor: TypeDescriptor,
    fields: BTreeMap<Arc<str>, StructFieldShape>,
}

#[derive(Clone, Debug)]
struct GenericStructFieldShape {
    ty: TypeExpression,
    required: bool,
}

#[derive(Clone, Debug)]
struct GenericStructShape {
    path: CanonicalPath,
    required: Vec<TypeParameterKey>,
    fields: BTreeMap<Arc<str>, GenericStructFieldShape>,
}

#[derive(Clone, Debug)]
struct EnumShape {
    descriptor: TypeDescriptor,
    variants: BTreeMap<Arc<str>, Option<TypeDescriptor>>,
}

#[derive(Clone, Debug)]
struct GenericEnumShape {
    path: CanonicalPath,
    required: Vec<TypeParameterKey>,
    variants: BTreeMap<Arc<str>, Option<TypeExpression>>,
}

#[derive(Clone, Debug)]
struct BodyContext {
    callables: BTreeMap<SymbolId, CallableSignature>,
    capability_declarations: BTreeMap<String, GenericDeclarationShape>,
    capability_proofs: RefCell<BTreeMap<(SealedCapability, String), bool>>,
    invalid_option_members: RefCell<BTreeMap<String, Option<SourceSpan>>>,
    generic_callables: BTreeMap<SymbolId, GenericCallableSignature>,
    generic_methods: Vec<GenericCallableSignature>,
    generic_types: BTreeMap<SourceSpan, TypeExpression>,
    maximum_constructed_type_depth: Option<u64>,
    actions: BTreeMap<SymbolId, CallableSignature>,
    methods: BTreeMap<(TypeDescriptor, Arc<str>), CallableSignature>,
    references: BTreeMap<SourceSpan, SymbolId>,
    structs: BTreeMap<SymbolId, StructShape>,
    generic_structs: BTreeMap<SymbolId, GenericStructShape>,
    enums: BTreeMap<SymbolId, EnumShape>,
    generic_enums: BTreeMap<SymbolId, GenericEnumShape>,
    trait_symbols: BTreeMap<SymbolId, CanonicalPath>,
    trait_contracts: Vec<TraitContract>,
    implementation_heads: Vec<ImplementationHead>,
    implementation_candidates: BTreeMap<(CanonicalPath, Arc<str>), Vec<usize>>,
    callable_visible_traits: BTreeMap<SourceSpan, BTreeSet<CanonicalPath>>,
    current_visible_traits: RefCell<BTreeSet<CanonicalPath>>,
    generic_templates: Vec<GenericTemplate>,
    generic_instantiations: RefCell<BTreeMap<InstantiationKey, ConcreteInstantiation>>,
    generic_instantiation_origins: RefCell<BTreeMap<InstantiationKey, BTreeSet<SourceSpan>>>,
    resolved_calls: RefCell<
        BTreeMap<(EffectNode, SourceSpan, EffectNode), Option<CanonicalImplementationIdentity>>,
    >,
    generic_instantiation_witnesses: RefCell<BTreeMap<InstantiationKey, Vec<InstantiationKey>>>,
    current_instantiation: RefCell<Option<(InstantiationKey, Vec<InstantiationKey>)>>,
    current_type_substitution: RefCell<Option<ExactTypeSubstitution>>,
    current_declared_obligations: RefCell<Vec<DeclaredTraitObligation>>,
    current_effect_owner: RefCell<Option<EffectNode>>,
    effect_drafts: RefCell<BTreeMap<EffectNode, EffectDraft>>,
    callable_sources: BTreeMap<SymbolId, SourceSpan>,
    method_sources: BTreeMap<(CanonicalImplementationIdentity, Arc<str>), SourceSpan>,
    inherent_method_sources: BTreeMap<(TypeDescriptor, Arc<str>), InherentMethodMetadata>,
    action_effects: BTreeMap<SymbolId, Effect>,
    parametric_validation: Cell<bool>,
    generic_analysis_counters: RefCell<Option<GenericAnalysisCounters>>,
    trait_obligations: RefCell<BTreeMap<String, ObligationProof>>,
    expression_types: RefCell<BTreeMap<NodeId, TypeDescriptor>>,
    shared_receiver_value_roots: RefCell<BTreeSet<Arc<str>>>,
    affine_consumed: RefCell<BTreeSet<AffinePlace>>,
    affine_loop_entry_roots: RefCell<Vec<BTreeSet<Arc<str>>>>,
    must_consume_obligations: RefCell<BTreeMap<Arc<str>, MustConsumeBinding>>,
    must_consume_discharged: RefCell<BTreeSet<AffinePlace>>,
    must_consume_partial: RefCell<BTreeSet<AffinePlace>>,
    must_consume_fresh: RefCell<BTreeSet<AffinePlace>>,
    must_consume_fresh_all: RefCell<BTreeSet<AffinePlace>>,
    must_consume_scopes: RefCell<Vec<MustConsumeScope>>,
    must_consume_loop_depths: RefCell<Vec<usize>>,
    must_consume_receiver: Cell<bool>,
    must_consume_consuming: Cell<bool>,
    must_consume_discarding: Cell<bool>,
    resolved_struct_fields: RefCell<BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, TypeDescriptor>>>,
    spawn_captures: RefCell<BTreeMap<EffectNode, BTreeMap<SourceSpan, Vec<SpawnCaptureMetadata>>>>,
    concrete_declaration_types: RefCell<BTreeMap<InstantiationKey, BTreeMap<NodeId, TypeFact>>>,
    concrete_expression_types:
        RefCell<BTreeMap<InstantiationKey, BTreeMap<NodeId, TypeDescriptor>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObligationResult {
    Proven,
    Unsatisfied,
    Cyclic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObligationProof {
    result: ObligationResult,
    chain: Vec<String>,
    selected_implementation: Option<usize>,
}

type PatternAnalysis = (BTreeSet<String>, BTreeMap<Arc<str>, TypeDescriptor>);

#[allow(clippy::too_many_arguments)]
fn build_body_context(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    generic_facts: &[GenericTypeFact],
    binders: &[TypeBinder],
    structure: &PackageStructure,
    capability_declarations: &BTreeMap<String, GenericDeclarationShape>,
    trait_contracts: &[TraitContract],
    implementation_heads: &[ImplementationHead],
    maximum_constructed_type_depth: Option<u64>,
    generic_analysis_counters: Option<GenericAnalysisCounters>,
) -> Result<BodyContext, AnalysisError> {
    let symbols_by_span = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol))
        .collect::<BTreeMap<_, _>>();
    let symbols_by_id = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let trait_symbols = structure
        .symbols()
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Trait)
        .map(|symbol| (symbol.id, symbol.path.clone()))
        .collect::<BTreeMap<_, _>>();
    let visible_traits_by_module = structure
        .visible_items()
        .iter()
        .map(|(module, items)| {
            let traits = items
                .values()
                .filter_map(|symbol| trait_symbols.get(symbol).cloned())
                .collect::<BTreeSet<_>>();
            (*module, traits)
        })
        .collect::<BTreeMap<_, _>>();
    let mut callable_visible_traits = BTreeMap::new();
    for source in sources {
        for node in source.tree().nodes().iter().filter(|node| {
            matches!(
                node.form(),
                SyntaxForm::FunctionDeclaration | SyntaxForm::MethodDeclaration
            )
        }) {
            let visible = structure
                .modules()
                .iter()
                .filter(|module| span_contains(&module.span, node.span()))
                .min_by_key(|module| span_width(&module.span))
                .and_then(|module| visible_traits_by_module.get(&module.id))
                .cloned()
                .unwrap_or_default();
            callable_visible_traits.insert(node.span().clone(), visible);
        }
    }
    let mut implementation_candidates = BTreeMap::<(CanonicalPath, Arc<str>), Vec<usize>>::new();
    for (index, implementation) in implementation_heads.iter().enumerate() {
        let Some(reference) = implementation.trait_reference() else {
            continue;
        };
        implementation_candidates
            .entry((
                reference.path().clone(),
                outer_type_constructor(implementation.receiver().as_str()),
            ))
            .or_default()
            .push(index);
    }
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let generic_by_span = generic_facts
        .iter()
        .map(|fact| (fact.span.clone(), fact))
        .collect::<BTreeMap<_, _>>();
    let generic_types = generic_facts
        .iter()
        .map(|fact| (fact.span.clone(), fact.expression.clone()))
        .collect::<BTreeMap<_, _>>();
    let generic_type_references = generic_facts
        .iter()
        .map(|fact| (fact.span.clone(), &fact.expression))
        .collect::<BTreeMap<_, _>>();
    let binders_by_declaration = binders
        .iter()
        .map(|binder| (binder.declaration.clone(), binder))
        .collect::<BTreeMap<_, _>>();
    let mut callables = BTreeMap::new();
    let mut generic_callables = BTreeMap::new();
    let mut generic_templates = Vec::new();
    let mut callable_sources = BTreeMap::new();
    let mut actions = BTreeMap::new();
    let mut action_effects = BTreeMap::new();
    let mut methods = BTreeMap::new();
    let mut method_sources = BTreeMap::new();
    let mut inherent_method_sources = BTreeMap::new();
    let mut structs = BTreeMap::new();
    let mut generic_structs = BTreeMap::new();
    let mut enums = BTreeMap::new();
    let mut generic_enums = BTreeMap::new();
    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for node in source.tree().nodes() {
            let Some(name_span) = direct_identifier_span(source.tree(), node) else {
                continue;
            };
            let Some(symbol) = symbols_by_span.get(&name_span).copied() else {
                continue;
            };
            match node.form() {
                SyntaxForm::FunctionDeclaration => {
                    callable_sources.insert(symbol.id, node.span().clone());
                    if let Some(binder) = binders_by_declaration.get(node.span()).copied() {
                        let required = binder
                            .parameters
                            .iter()
                            .map(|parameter| TypeParameterKey {
                                binder_depth: binder.depth,
                                ordinal: parameter.ordinal,
                            })
                            .collect::<Vec<_>>();
                        let template_arguments = required
                            .iter()
                            .map(|parameter| {
                                TypeExpression::parameter(
                                    parameter.binder_depth,
                                    parameter.ordinal,
                                    u64::MAX,
                                )
                                .map_err(|_| AnalysisError::Invariant)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        let template =
                            CanonicalTemplateIdentity::free(&symbol.path, &template_arguments);
                        let declaration = source
                            .tree()
                            .nodes()
                            .iter()
                            .position(|candidate| std::ptr::eq(candidate, node))
                            .map(NodeId::from_index)
                            .ok_or(AnalysisError::Invariant)?;
                        let predicates = collect_where_predicates(
                            source.tree(),
                            declaration,
                            Some(binder),
                            &generic_type_references,
                            &references,
                            &symbols_by_id,
                        )?;
                        let sealed_predicates = collect_capability_predicates(
                            source.tree(),
                            declaration,
                            Some(binder),
                        )?;
                        let parameters = node
                            .children()
                            .iter()
                            .copied()
                            .filter_map(|child| {
                                let parameter = source.tree().node(child)?;
                                matches!(parameter.form(), SyntaxForm::Parameter)
                                    .then_some(parameter)
                            })
                            .filter_map(|parameter| {
                                direct_child_form(source.tree(), parameter, SyntaxForm::ValueType)
                            })
                            .filter_map(|type_node| source.tree().node(type_node))
                            .filter_map(|type_node| generic_by_span.get(type_node.span()))
                            .map(|fact| fact.expression.clone())
                            .collect::<Vec<_>>();
                        let parameter_mutability = node
                            .children()
                            .iter()
                            .filter_map(|child| source.tree().node(*child))
                            .filter(|parameter| {
                                matches!(parameter.form(), SyntaxForm::Parameter)
                                    && direct_child_form(
                                        source.tree(),
                                        parameter,
                                        SyntaxForm::ValueType,
                                    )
                                    .is_some()
                            })
                            .map(|parameter| {
                                node_has_reserved_word(source.tree(), parameter, "mut")
                            })
                            .collect::<Vec<_>>();
                        let result = node
                            .children()
                            .iter()
                            .copied()
                            .rfind(|child| {
                                source.tree().node(*child).is_some_and(|node| {
                                    matches!(node.form(), SyntaxForm::ValueType)
                                })
                            })
                            .and_then(|type_node| source.tree().node(type_node))
                            .and_then(|type_node| generic_by_span.get(type_node.span()))
                            .map(|fact| fact.expression.clone())
                            .unwrap_or(
                                TypeExpression::closed(&TypeDescriptor::UNIT, u64::MAX)
                                    .map_err(|_| AnalysisError::Invariant)?,
                            );
                        generic_callables.insert(
                            symbol.id,
                            GenericCallableSignature {
                                kind: TemplateKind::FreeWorkflow,
                                path: symbol.path.clone(),
                                template: template.clone(),
                                receiver: None,
                                trait_reference: None,
                                method_name: None,
                                implementation: None,
                                implementation_parameter_count: 0,
                                source_index,
                                declaration,
                                required,
                                predicates: predicates.clone(),
                                sealed_predicates,
                                parameters,
                                parameter_mutability,
                                result,
                            },
                        );
                        generic_templates.push(
                            GenericTemplate::new(
                                TemplateKind::FreeWorkflow,
                                template,
                                u64::try_from(binder.parameters.len())
                                    .map_err(|_| AnalysisError::Invariant)?,
                                predicates,
                                gantry_ir::EffectSet::default(),
                            )
                            .map_err(|_| AnalysisError::Invariant)?,
                        );
                        continue;
                    }
                    let parameters = node
                        .children()
                        .iter()
                        .copied()
                        .filter_map(|child| {
                            let parameter = source.tree().node(child)?;
                            matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
                        })
                        .filter_map(|parameter| {
                            direct_child_form(source.tree(), parameter, SyntaxForm::ValueType)
                        })
                        .filter_map(|type_node| resolved.get(&type_node))
                        .map(|fact| fact.descriptor.clone())
                        .collect::<Vec<_>>();
                    let result =
                        node.children()
                            .iter()
                            .copied()
                            .rfind(|child| {
                                source.tree().node(*child).is_some_and(|node| {
                                    matches!(node.form(), SyntaxForm::ValueType)
                                })
                            })
                            .and_then(|type_node| resolved.get(&type_node))
                            .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
                    callables.insert(symbol.id, CallableSignature { parameters, result });
                }
                SyntaxForm::ActionDeclaration => {
                    let effect = if node_has_reserved_word(source.tree(), node, "read_only") {
                        Effect::ActionReadOnly
                    } else if node_has_reserved_word(source.tree(), node, "idempotent") {
                        Effect::ActionIdempotent
                    } else if node_has_reserved_word(source.tree(), node, "non_idempotent") {
                        Effect::ActionNonIdempotent
                    } else {
                        return Err(AnalysisError::Invariant);
                    };
                    action_effects.insert(symbol.id, effect);
                    let parameters = node
                        .children()
                        .iter()
                        .copied()
                        .filter_map(|child| {
                            let parameter = source.tree().node(child)?;
                            matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
                        })
                        .filter_map(|parameter| {
                            direct_child_form(source.tree(), parameter, SyntaxForm::ValueType)
                        })
                        .filter_map(|type_node| resolved.get(&type_node))
                        .map(|fact| fact.descriptor.clone())
                        .collect::<Vec<_>>();
                    let result =
                        node.children()
                            .iter()
                            .copied()
                            .rfind(|child| {
                                source.tree().node(*child).is_some_and(|node| {
                                    matches!(node.form(), SyntaxForm::ValueType)
                                })
                            })
                            .and_then(|type_node| resolved.get(&type_node))
                            .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
                    actions.insert(symbol.id, CallableSignature { parameters, result });
                }
                SyntaxForm::StructDeclaration => {
                    if !capability_declarations
                        .get(symbol.path.as_str())
                        .is_some_and(GenericDeclarationShape::is_expandable)
                    {
                        continue;
                    }
                    if let Some(binder) = binders_by_declaration.get(node.span()).copied() {
                        let mut fields = BTreeMap::new();
                        for child in node.children().iter().copied() {
                            let field =
                                source.tree().node(child).ok_or(AnalysisError::Invariant)?;
                            if !matches!(field.form(), SyntaxForm::StructField) {
                                continue;
                            }
                            let Some(name) = direct_identifier(source.tree(), child)? else {
                                return Err(AnalysisError::Invariant);
                            };
                            let type_node =
                                direct_child_form(source.tree(), field, SyntaxForm::ValueType)
                                    .and_then(|type_node| source.tree().node(type_node))
                                    .ok_or(AnalysisError::Invariant)?;
                            let ty = generic_by_span
                                .get(type_node.span())
                                .map(|fact| fact.expression.clone())
                                .ok_or(AnalysisError::Invariant)?;
                            let has_default = field.children().iter().copied().any(|part| {
                                node_contains_punctuation(source.tree(), part, Punctuation::Equal)
                            });
                            fields.insert(
                                name,
                                GenericStructFieldShape {
                                    required: !has_default && !ty.as_str().starts_with("Option<"),
                                    ty,
                                },
                            );
                        }
                        generic_structs.insert(
                            symbol.id,
                            GenericStructShape {
                                path: symbol.path.clone(),
                                required: binder
                                    .parameters
                                    .iter()
                                    .map(|parameter| TypeParameterKey {
                                        binder_depth: binder.depth,
                                        ordinal: parameter.ordinal,
                                    })
                                    .collect(),
                                fields,
                            },
                        );
                        continue;
                    }
                    let mut fields = BTreeMap::new();
                    for child in node.children().iter().copied() {
                        let field = source.tree().node(child).ok_or(AnalysisError::Invariant)?;
                        if !matches!(field.form(), SyntaxForm::StructField) {
                            continue;
                        }
                        let Some(name) = direct_identifier(source.tree(), child)? else {
                            return Err(AnalysisError::Invariant);
                        };
                        let Some(type_node) =
                            direct_child_form(source.tree(), field, SyntaxForm::ValueType)
                        else {
                            return Err(AnalysisError::Invariant);
                        };
                        let Some(fact) = resolved.get(&type_node) else {
                            continue;
                        };
                        let has_default = field.children().iter().copied().any(|part| {
                            node_contains_punctuation(source.tree(), part, Punctuation::Equal)
                        });
                        fields.insert(
                            name,
                            StructFieldShape {
                                ty: fact.descriptor.clone(),
                                required: !has_default
                                    && fact.descriptor.kind() != TypeKind::Option,
                            },
                        );
                    }
                    structs.insert(
                        symbol.id,
                        StructShape {
                            descriptor: TypeDescriptor::declared(symbol.path.clone()),
                            fields,
                        },
                    );
                }
                SyntaxForm::EnumDeclaration => {
                    if !capability_declarations
                        .get(symbol.path.as_str())
                        .is_some_and(GenericDeclarationShape::is_expandable)
                    {
                        continue;
                    }
                    if let Some(binder) = binders_by_declaration.get(node.span()).copied() {
                        let mut variants = BTreeMap::new();
                        for child in node.children().iter().copied() {
                            let variant =
                                source.tree().node(child).ok_or(AnalysisError::Invariant)?;
                            if !matches!(variant.form(), SyntaxForm::EnumVariant) {
                                continue;
                            }
                            let Some(name) = direct_identifier(source.tree(), child)? else {
                                return Err(AnalysisError::Invariant);
                            };
                            let payload =
                                direct_child_form(source.tree(), variant, SyntaxForm::ValueType)
                                    .and_then(|type_node| source.tree().node(type_node))
                                    .and_then(|type_node| generic_by_span.get(type_node.span()))
                                    .map(|fact| fact.expression.clone());
                            variants.insert(name, payload);
                        }
                        generic_enums.insert(
                            symbol.id,
                            GenericEnumShape {
                                path: symbol.path.clone(),
                                required: binder
                                    .parameters
                                    .iter()
                                    .map(|parameter| TypeParameterKey {
                                        binder_depth: binder.depth,
                                        ordinal: parameter.ordinal,
                                    })
                                    .collect(),
                                variants,
                            },
                        );
                        continue;
                    }
                    let mut variants = BTreeMap::new();
                    for child in node.children().iter().copied() {
                        let variant = source.tree().node(child).ok_or(AnalysisError::Invariant)?;
                        if !matches!(variant.form(), SyntaxForm::EnumVariant) {
                            continue;
                        }
                        let Some(name) = direct_identifier(source.tree(), child)? else {
                            return Err(AnalysisError::Invariant);
                        };
                        let payload =
                            direct_child_form(source.tree(), variant, SyntaxForm::ValueType)
                                .and_then(|type_node| resolved.get(&type_node))
                                .map(|fact| fact.descriptor.clone());
                        variants.insert(name, payload);
                    }
                    enums.insert(
                        symbol.id,
                        EnumShape {
                            descriptor: TypeDescriptor::declared(symbol.path.clone()),
                            variants,
                        },
                    );
                }
                _ => {}
            }
        }
    }
    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for node in source
            .tree()
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::ImplDeclaration))
        {
            if direct_child_form(source.tree(), node, SyntaxForm::TraitReference).is_some() {
                continue;
            }
            let Some(receiver) = implementation_receiver_descriptor(
                source.tree(),
                node,
                &generic_types,
                &references,
                &structs,
            )?
            else {
                continue;
            };
            for method in node.children().iter().copied().filter(|child| {
                source
                    .tree()
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MethodDeclaration))
            }) {
                let method_node = source.tree().node(method).ok_or(AnalysisError::Invariant)?;
                if direct_child_form(source.tree(), method_node, SyntaxForm::TypeParameterList)
                    .is_some()
                {
                    continue;
                }
                let Some(name) = direct_identifier(source.tree(), method)? else {
                    return Err(AnalysisError::Invariant);
                };
                let parameters = method_node
                    .children()
                    .iter()
                    .copied()
                    .filter_map(|child| {
                        let parameter = source.tree().node(child)?;
                        matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
                    })
                    .filter_map(|parameter| {
                        direct_child_form(source.tree(), parameter, SyntaxForm::ValueType)
                    })
                    .filter_map(|type_node| resolved.get(&type_node))
                    .map(|fact| fact.descriptor.clone())
                    .collect::<Vec<_>>();
                let result = method_node
                    .children()
                    .iter()
                    .copied()
                    .rfind(|child| {
                        source
                            .tree()
                            .node(*child)
                            .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                    })
                    .and_then(|type_node| resolved.get(&type_node))
                    .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
                methods.insert(
                    (receiver.clone(), name),
                    CallableSignature { parameters, result },
                );
                inherent_method_sources.insert(
                    (
                        receiver.clone(),
                        direct_identifier(source.tree(), method)?
                            .ok_or(AnalysisError::Invariant)?,
                    ),
                    InherentMethodMetadata {
                        declaration: method_node.span().clone(),
                        receiver_mode: method_receiver_mode(source.tree(), method)?,
                    },
                );
            }
        }
    }
    let generic_methods = collect_generic_method_signatures(
        sources,
        &generic_types,
        &binders_by_declaration,
        &references,
        &trait_symbols,
        &symbols_by_id,
        implementation_heads,
        &mut method_sources,
        &mut generic_templates,
    )?;
    generic_templates.sort_by(|left, right| {
        (left.kind(), left.identity()).cmp(&(right.kind(), right.identity()))
    });
    Ok(BodyContext {
        callables,
        capability_declarations: capability_declarations.clone(),
        capability_proofs: RefCell::new(BTreeMap::new()),
        invalid_option_members: RefCell::new(BTreeMap::new()),
        generic_callables,
        generic_methods,
        generic_types,
        maximum_constructed_type_depth,
        actions,
        methods,
        references,
        structs,
        generic_structs,
        enums,
        generic_enums,
        trait_symbols,
        trait_contracts: trait_contracts.to_vec(),
        implementation_heads: implementation_heads.to_vec(),
        implementation_candidates,
        callable_visible_traits,
        current_visible_traits: RefCell::new(BTreeSet::new()),
        generic_templates,
        generic_instantiations: RefCell::new(BTreeMap::new()),
        generic_instantiation_origins: RefCell::new(BTreeMap::new()),
        resolved_calls: RefCell::new(BTreeMap::new()),
        generic_instantiation_witnesses: RefCell::new(BTreeMap::new()),
        current_instantiation: RefCell::new(None),
        current_type_substitution: RefCell::new(None),
        current_declared_obligations: RefCell::new(Vec::new()),
        current_effect_owner: RefCell::new(None),
        effect_drafts: RefCell::new(BTreeMap::new()),
        callable_sources,
        method_sources,
        inherent_method_sources,
        action_effects,
        parametric_validation: Cell::new(false),
        generic_analysis_counters: RefCell::new(generic_analysis_counters),
        trait_obligations: RefCell::new(BTreeMap::new()),
        expression_types: RefCell::new(BTreeMap::new()),
        shared_receiver_value_roots: RefCell::new(BTreeSet::new()),
        affine_consumed: RefCell::new(BTreeSet::new()),
        affine_loop_entry_roots: RefCell::new(Vec::new()),
        must_consume_obligations: RefCell::new(BTreeMap::new()),
        must_consume_discharged: RefCell::new(BTreeSet::new()),
        must_consume_partial: RefCell::new(BTreeSet::new()),
        must_consume_fresh: RefCell::new(BTreeSet::new()),
        must_consume_fresh_all: RefCell::new(BTreeSet::new()),
        must_consume_scopes: RefCell::new(Vec::new()),
        must_consume_loop_depths: RefCell::new(Vec::new()),
        must_consume_receiver: Cell::new(false),
        must_consume_consuming: Cell::new(false),
        must_consume_discarding: Cell::new(false),
        resolved_struct_fields: RefCell::new(BTreeMap::new()),
        spawn_captures: RefCell::new(BTreeMap::new()),
        concrete_declaration_types: RefCell::new(BTreeMap::new()),
        concrete_expression_types: RefCell::new(BTreeMap::new()),
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_generic_method_signatures(
    sources: &[ParsedSource],
    generic_types: &BTreeMap<SourceSpan, TypeExpression>,
    binders: &BTreeMap<SourceSpan, &TypeBinder>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    trait_symbols: &BTreeMap<SymbolId, CanonicalPath>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
    implementation_heads: &[ImplementationHead],
    method_sources: &mut BTreeMap<(CanonicalImplementationIdentity, Arc<str>), SourceSpan>,
    templates: &mut Vec<GenericTemplate>,
) -> Result<Vec<GenericCallableSignature>, AnalysisError> {
    let mut methods = Vec::new();
    let generic_type_references = generic_types
        .iter()
        .map(|(span, expression)| (span.clone(), expression))
        .collect::<BTreeMap<_, _>>();
    for (source_index, source) in sources.iter().enumerate() {
        let tree = source.tree();
        for (implementation_index, implementation) in tree.nodes().iter().enumerate() {
            if !matches!(implementation.form(), SyntaxForm::ImplDeclaration) {
                continue;
            }
            let receiver = crate::generics::implementation_receiver_expression(
                tree,
                NodeId::from_index(implementation_index),
                &generic_type_references,
                references,
                symbols,
            )?;
            let implementation_binder = binders.get(implementation.span()).copied();
            let implementation_required = implementation_binder
                .into_iter()
                .flat_map(|binder| {
                    binder
                        .parameters
                        .iter()
                        .map(move |parameter| TypeParameterKey {
                            binder_depth: binder.depth,
                            ordinal: parameter.ordinal,
                        })
                })
                .collect::<Vec<_>>();
            let trait_reference =
                direct_child_form(tree, implementation, SyntaxForm::TraitReference)
                    .map(|reference| {
                        let reference_node =
                            tree.node(reference).ok_or(AnalysisError::Invariant)?;
                        let path = direct_child_form(tree, reference_node, SyntaxForm::Path)
                            .ok_or(AnalysisError::Invariant)?;
                        let target = references
                            .get(tree.node(path).ok_or(AnalysisError::Invariant)?.span())
                            .copied()
                            .ok_or(AnalysisError::Invariant)?;
                        let trait_path = trait_symbols
                            .get(&target)
                            .cloned()
                            .ok_or(AnalysisError::Invariant)?;
                        let arguments =
                            direct_child_form(tree, reference_node, SyntaxForm::TypeArgumentList)
                                .map(|list| {
                                    tree.node(list)
                                        .ok_or(AnalysisError::Invariant)?
                                        .children()
                                        .iter()
                                        .filter_map(|child| tree.node(*child))
                                        .filter(|node| matches!(node.form(), SyntaxForm::ValueType))
                                        .map(|node| {
                                            generic_types
                                                .get(node.span())
                                                .cloned()
                                                .ok_or(AnalysisError::Invariant)
                                        })
                                        .collect::<Result<Vec<_>, _>>()
                                })
                                .transpose()?
                                .unwrap_or_default();
                        Ok(TraitReference::new(trait_path, arguments))
                    })
                    .transpose()?;
            let implementation_identity = trait_reference.as_ref().map_or_else(
                || CanonicalImplementationIdentity::inherent(&receiver),
                |reference| {
                    CanonicalImplementationIdentity::trait_implementation(&receiver, reference)
                },
            );
            let Some(implementation_head) = implementation_heads
                .iter()
                .find(|head| head.identity() == &implementation_identity)
            else {
                continue;
            };
            for method in implementation.children().iter().copied().filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MethodDeclaration))
            }) {
                let method_node = tree.node(method).ok_or(AnalysisError::Invariant)?;
                let method_binder = binders.get(method_node.span()).copied();
                let method_name =
                    direct_identifier(tree, method)?.ok_or(AnalysisError::Invariant)?;
                method_sources.insert(
                    (implementation_identity.clone(), method_name.clone()),
                    method_node.span().clone(),
                );
                if implementation_required.is_empty() && method_binder.is_none() {
                    continue;
                }
                let method_required = method_binder
                    .into_iter()
                    .flat_map(|binder| {
                        binder
                            .parameters
                            .iter()
                            .map(move |parameter| TypeParameterKey {
                                binder_depth: binder.depth,
                                ordinal: parameter.ordinal,
                            })
                    })
                    .collect::<Vec<_>>();
                let mut required = implementation_required.clone();
                required.extend(method_required.iter().copied());
                let mut predicates = implementation_head.predicates().to_vec();
                predicates.extend(collect_where_predicates(
                    tree,
                    method,
                    method_binder,
                    &generic_type_references,
                    references,
                    symbols,
                )?);
                predicates.sort_by(|left, right| {
                    left.canonical_string()
                        .as_bytes()
                        .cmp(right.canonical_string().as_bytes())
                });
                predicates.dedup();
                let mut sealed_predicates = collect_capability_predicates(
                    tree,
                    NodeId::from_index(implementation_index),
                    implementation_binder,
                )?;
                sealed_predicates.extend(collect_capability_predicates(
                    tree,
                    method,
                    method_binder,
                )?);
                sealed_predicates.sort_by(|left, right| {
                    left.capability
                        .cmp(&right.capability)
                        .then_with(|| left.parameter.cmp(&right.parameter))
                });
                sealed_predicates.dedup_by(|left, right| {
                    left.capability == right.capability && left.parameter == right.parameter
                });
                let method_arguments = method_required
                    .iter()
                    .map(|parameter| {
                        TypeExpression::parameter(
                            parameter.binder_depth,
                            parameter.ordinal,
                            u64::MAX,
                        )
                        .map_err(|_| AnalysisError::Invariant)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let (kind, template) = if let Some(reference) = &trait_reference {
                    (
                        TemplateKind::TraitMethod,
                        CanonicalTemplateIdentity::trait_method(
                            &receiver,
                            reference.path(),
                            reference.arguments(),
                            &method_name,
                            &method_arguments,
                        )
                        .map_err(|_| AnalysisError::Invariant)?,
                    )
                } else {
                    (
                        TemplateKind::InherentMethod,
                        CanonicalTemplateIdentity::inherent(
                            &receiver,
                            &method_name,
                            &method_arguments,
                        )
                        .map_err(|_| AnalysisError::Invariant)?,
                    )
                };
                let parameters = method_node
                    .children()
                    .iter()
                    .filter_map(|child| tree.node(*child))
                    .filter(|node| {
                        matches!(node.form(), SyntaxForm::Parameter)
                            && !node_has_reserved_word(tree, node, "self")
                    })
                    .filter_map(|parameter| {
                        direct_child_form(tree, parameter, SyntaxForm::ValueType)
                    })
                    .map(|type_node| {
                        generic_types
                            .get(tree.node(type_node).ok_or(AnalysisError::Invariant)?.span())
                            .cloned()
                            .ok_or(AnalysisError::Invariant)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let parameter_mutability = method_node
                    .children()
                    .iter()
                    .filter_map(|child| tree.node(*child))
                    .filter(|parameter| {
                        matches!(parameter.form(), SyntaxForm::Parameter)
                            && !node_has_reserved_word(tree, parameter, "self")
                    })
                    .map(|parameter| node_has_reserved_word(tree, parameter, "mut"))
                    .collect::<Vec<_>>();
                let result = method_node
                    .children()
                    .iter()
                    .copied()
                    .rfind(|child| {
                        tree.node(*child)
                            .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                    })
                    .map(|type_node| {
                        generic_types
                            .get(tree.node(type_node).ok_or(AnalysisError::Invariant)?.span())
                            .cloned()
                            .ok_or(AnalysisError::Invariant)
                    })
                    .transpose()?
                    .unwrap_or(
                        TypeExpression::closed(&TypeDescriptor::UNIT, u64::MAX)
                            .map_err(|_| AnalysisError::Invariant)?,
                    );
                let Ok(outer) =
                    CanonicalPath::new(outer_type_constructor(receiver.as_str()).as_ref())
                else {
                    continue;
                };
                let path = CanonicalPath::method(&outer, &method_name)
                    .map_err(|_| AnalysisError::Invariant)?;
                templates.push(
                    GenericTemplate::new(
                        kind,
                        template.clone(),
                        u64::try_from(required.len()).map_err(|_| AnalysisError::Invariant)?,
                        predicates.clone(),
                        gantry_ir::EffectSet::default(),
                    )
                    .map_err(|_| AnalysisError::Invariant)?,
                );
                methods.push(GenericCallableSignature {
                    kind,
                    path,
                    template,
                    receiver: Some(receiver.clone()),
                    trait_reference: trait_reference.clone(),
                    method_name: Some(method_name),
                    implementation: Some(implementation_identity.clone()),
                    implementation_parameter_count: implementation_required.len(),
                    source_index,
                    declaration: method,
                    required,
                    predicates,
                    sealed_predicates,
                    parameters,
                    parameter_mutability,
                    result,
                });
            }
        }
    }
    methods.sort_by(|left, right| (left.kind, &left.template).cmp(&(right.kind, &right.template)));
    Ok(methods)
}

/// Checks every free-function and method body against its declared signature.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_package_bodies(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    generic_facts: &[GenericTypeFact],
    binders: &[TypeBinder],
    structure: &PackageStructure,
    capability_declarations: &BTreeMap<String, GenericDeclarationShape>,
    trait_contracts: &[TraitContract],
    implementation_heads: &[ImplementationHead],
    maximum_constructed_type_depth: Option<u64>,
    generic_analysis_counters: &mut Option<GenericAnalysisCounters>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<BodyAnalysis, AnalysisError> {
    validate_shared_receiver_declarations(sources, diagnostics)?;
    let context = build_body_context(
        sources,
        facts,
        generic_facts,
        binders,
        structure,
        capability_declarations,
        trait_contracts,
        implementation_heads,
        maximum_constructed_type_depth,
        generic_analysis_counters.take(),
    )?;
    let result = (|| {
        let mut expression_types = Vec::with_capacity(sources.len());
        for (source_index, source) in sources.iter().enumerate() {
            let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
            for (index, node) in source.tree().nodes().iter().enumerate() {
                if !matches!(
                    node.form(),
                    SyntaxForm::FunctionDeclaration | SyntaxForm::MethodDeclaration
                ) {
                    continue;
                }
                if matches!(node.form(), SyntaxForm::MethodDeclaration)
                    && context.generic_methods.iter().any(|method| {
                        method.source_index == source_index
                            && method.declaration == NodeId::from_index(index)
                    })
                {
                    continue;
                }
                if direct_child_form(source.tree(), node, SyntaxForm::TypeParameterList).is_some() {
                    continue;
                }
                *context.current_effect_owner.borrow_mut() =
                    Some(EffectNode::Source(node.span().clone()));
                let check = check_callable(
                    source.tree(),
                    NodeId::from_index(index),
                    resolved,
                    &context,
                    diagnostics,
                );
                *context.current_effect_owner.borrow_mut() = None;
                check?;
            }
            expression_types.push(context.expression_types.take());
        }
        check_parametric_generic_bodies(sources, facts, &context, diagnostics)?;
        check_instantiated_generic_bodies(sources, facts, &context, diagnostics)?;
        let (generic_template_effects, generic_concrete_effects, source_effects) =
            finish_effect_graph(&context, diagnostics)?;
        let concrete_callables = collect_concrete_callable_metadata(sources, &context)?;
        let source_callables =
            collect_source_callable_metadata(sources, facts, structure, &context, &source_effects)?;
        let resolved_calls = context
            .resolved_calls
            .take()
            .into_iter()
            .map(
                |((caller, source, callee), selected_implementation)| ResolvedCallMetadata {
                    caller,
                    callee,
                    source,
                    selected_implementation,
                },
            )
            .collect();
        let mut closed_types = expression_types
            .iter()
            .flat_map(BTreeMap::values)
            .cloned()
            .collect::<BTreeSet<_>>();
        closed_types.extend(
            context
                .concrete_expression_types
                .borrow()
                .values()
                .flat_map(BTreeMap::values)
                .cloned(),
        );
        let mut struct_fields = context
            .structs
            .values()
            .map(|shape| {
                (
                    shape.descriptor.clone(),
                    shape
                        .fields
                        .iter()
                        .map(|(name, field)| (name.clone(), field.ty.clone()))
                        .collect(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        struct_fields.extend(context.resolved_struct_fields.take());
        let mut closed_enums = BTreeMap::new();
        for descriptor in &closed_types {
            if let Some(shape) = enum_shape_for_descriptor(&context, descriptor)? {
                closed_enums.insert(descriptor.clone(), shape.variants);
            }
        }
        let generic_declarations = context
            .generic_callables
            .values()
            .chain(context.generic_methods.iter())
            .map(|signature| {
                sources
                    .get(signature.source_index)
                    .and_then(|source| source.tree().node(signature.declaration))
                    .map(|node| node.span().clone())
                    .ok_or(AnalysisError::Invariant)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut generic_declarations = generic_declarations;
        generic_declarations.extend(
            context
                .method_sources
                .values()
                .filter(|declaration| {
                    !context.inherent_method_sources.values().any(|metadata| {
                        metadata.declaration == **declaration
                            && metadata.receiver_mode == ReceiverMode::SharedPlace
                    })
                })
                .cloned(),
        );
        context.expression_types.borrow_mut().clear();
        Ok(BodyAnalysis {
            expression_types,
            struct_fields,
            spawn_captures: context.spawn_captures.take(),
            generic_templates: context.generic_templates.clone(),
            generic_instantiations: context
                .generic_instantiations
                .take()
                .into_values()
                .collect(),
            concrete_callables,
            resolved_calls,
            source_callables,
            closed_enums,
            generic_declarations,
            generic_template_effects,
            generic_concrete_effects,
        })
    })();
    *generic_analysis_counters = context.generic_analysis_counters.take();
    result
}

fn collect_concrete_callable_metadata(
    sources: &[ParsedSource],
    context: &BodyContext,
) -> Result<Vec<ConcreteCallableMetadata>, AnalysisError> {
    context
        .generic_instantiations
        .borrow()
        .keys()
        .map(|key| {
            let signature = context
                .generic_callables
                .values()
                .chain(context.generic_methods.iter())
                .find(|signature| signature.template == key.0)
                .ok_or(AnalysisError::Invariant)?;
            let substitution = ExactTypeSubstitution::explicit(&signature.required, &key.1)
                .map_err(|_| AnalysisError::Invariant)?;
            let receiver = signature
                .receiver
                .as_ref()
                .map(|receiver| {
                    substitution
                        .apply(receiver)
                        .map_err(|_| AnalysisError::Invariant)
                })
                .transpose()?;
            let parameters = signature
                .parameters
                .iter()
                .zip(&signature.parameter_mutability)
                .map(|(parameter, mutable)| {
                    Ok(WorkflowParameter {
                        mutable: *mutable,
                        ty: substitution
                            .apply_with_receiver(parameter, receiver.as_ref())
                            .map_err(|_| AnalysisError::Invariant)?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let result = substitution
                .apply_with_receiver(&signature.result, receiver.as_ref())
                .map_err(|_| AnalysisError::Invariant)?;
            let declaration = sources
                .get(signature.source_index)
                .and_then(|source| source.tree().node(signature.declaration))
                .map(|node| node.span().clone())
                .ok_or(AnalysisError::Invariant)?;
            let origins = context
                .generic_instantiation_origins
                .borrow()
                .get(key)
                .map(|origins| origins.iter().cloned().collect())
                .unwrap_or_default();
            let direct_calls = context
                .effect_drafts
                .borrow()
                .get(&EffectNode::Concrete(key.clone()))
                .into_iter()
                .flat_map(|draft| &draft.calls)
                .filter(|callee| !matches!(callee, EffectNode::Template(_)))
                .cloned()
                .collect();
            let mutable_receiver = sources
                .get(signature.source_index)
                .and_then(|source| source.tree().node(signature.declaration))
                .is_some_and(|node| {
                    node_has_reserved_word(sources[signature.source_index].tree(), node, "mut")
                });
            let operation_results = concrete_operation_results(
                sources[signature.source_index].tree(),
                signature.declaration,
                &substitution,
                receiver.as_ref(),
                context,
            )?;
            let declaration_types = context
                .concrete_declaration_types
                .borrow()
                .get(key)
                .cloned()
                .ok_or(AnalysisError::Invariant)?;
            let expression_types = context
                .concrete_expression_types
                .borrow()
                .get(key)
                .cloned()
                .ok_or(AnalysisError::Invariant)?;
            Ok(ConcreteCallableMetadata {
                key: key.clone(),
                receiver,
                mutable_receiver,
                parameters,
                result,
                declaration,
                declaration_types,
                expression_types,
                origins,
                direct_calls,
                operation_results,
            })
        })
        .collect()
}

fn concrete_operation_results(
    tree: &SyntaxTree,
    callable: NodeId,
    substitution: &ExactTypeSubstitution,
    receiver: Option<&TypeDescriptor>,
    context: &BodyContext,
) -> Result<BTreeMap<SourceSpan, TypeDescriptor>, AnalysisError> {
    let declaration = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    let mut results = BTreeMap::new();
    for operation in tree.nodes().iter().filter(|node| {
        span_contains(declaration.span(), node.span())
            && matches!(
                node.form(),
                SyntaxForm::PromptExpression
                    | SyntaxForm::DecideExpression
                    | SyntaxForm::ActionExpression
            )
    }) {
        let result = match operation.form() {
            SyntaxForm::PromptExpression => {
                if let Some(type_node) = direct_child_form(tree, operation, SyntaxForm::ValueType) {
                    let expression = tree
                        .node(type_node)
                        .and_then(|node| context.generic_types.get(node.span()))
                        .ok_or(AnalysisError::Invariant)?;
                    substitution
                        .apply_with_receiver(expression, receiver)
                        .map_err(|_| AnalysisError::Invariant)?
                } else {
                    TypeDescriptor::UNIT
                }
            }
            SyntaxForm::DecideExpression => TypeDescriptor::DECISION,
            SyntaxForm::ActionExpression => {
                let path = direct_child_form(tree, operation, SyntaxForm::Path)
                    .ok_or(AnalysisError::Invariant)?;
                let target = tree
                    .node(path)
                    .and_then(|path| context.references.get(path.span()))
                    .ok_or(AnalysisError::Invariant)?;
                context
                    .actions
                    .get(target)
                    .map(|signature| signature.result.clone())
                    .ok_or(AnalysisError::Invariant)?
            }
            _ => return Err(AnalysisError::Invariant),
        };
        results.insert(operation.span().clone(), result);
    }
    Ok(results)
}

fn collect_source_callable_metadata(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    structure: &PackageStructure,
    context: &BodyContext,
    effects: &BTreeMap<SourceSpan, EffectSet>,
) -> Result<Vec<SourceCallableMetadata>, AnalysisError> {
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let mut callables = Vec::new();
    for (symbol_id, signature) in &context.callables {
        let symbol = symbols.get(symbol_id).ok_or(AnalysisError::Invariant)?;
        let declaration = context
            .callable_sources
            .get(symbol_id)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        let (source_index, tree, callable) = find_source_callable(sources, &declaration)?;
        let parameters = source_callable_parameters(
            tree,
            callable,
            facts.get(source_index).ok_or(AnalysisError::Invariant)?,
            None,
        )?;
        callables.push(SourceCallableMetadata {
            identity: CanonicalCallableIdentity::free(&symbol.path, &[]),
            receiver: None,
            receiver_mode: None,
            parameters,
            result: signature.result.clone(),
            effects: effects.get(&declaration).copied().unwrap_or_default(),
            declaration: declaration.clone(),
            direct_calls: source_direct_calls(context, &declaration),
        });
    }
    for ((receiver, method), metadata) in &context.inherent_method_sources {
        let (source_index, tree, callable) = find_source_callable(sources, &metadata.declaration)?;
        let parameters = source_callable_parameters(
            tree,
            callable,
            facts.get(source_index).ok_or(AnalysisError::Invariant)?,
            Some(receiver),
        )?;
        let result = callable_result(
            tree,
            callable,
            facts.get(source_index).ok_or(AnalysisError::Invariant)?,
        );
        callables.push(SourceCallableMetadata {
            identity: CanonicalCallableIdentity::inherent(receiver, method, &[])
                .map_err(|_| AnalysisError::Invariant)?,
            receiver: Some(receiver.clone()),
            receiver_mode: Some(metadata.receiver_mode),
            parameters,
            result,
            effects: effects
                .get(&metadata.declaration)
                .copied()
                .unwrap_or_default(),
            declaration: metadata.declaration.clone(),
            direct_calls: source_direct_calls(context, &metadata.declaration),
        });
    }
    for ((implementation, method), declaration) in &context.method_sources {
        if context.generic_methods.iter().any(|signature| {
            sources
                .get(signature.source_index)
                .and_then(|source| source.tree().node(signature.declaration))
                .is_some_and(|node| node.span() == declaration)
        }) {
            continue;
        }
        let head = context
            .implementation_heads
            .iter()
            .find(|head| head.identity() == implementation)
            .ok_or(AnalysisError::Invariant)?;
        if !head.receiver().is_closed()
            || head.trait_reference().is_some_and(|reference| {
                reference
                    .arguments()
                    .iter()
                    .any(|argument| !argument.is_closed())
            })
        {
            continue;
        }
        let receiver = head
            .receiver()
            .to_descriptor(u64::MAX)
            .map_err(|_| AnalysisError::Invariant)?;
        let method_arguments = Vec::new();
        let identity = if let Some(reference) = head.trait_reference() {
            let trait_arguments = reference
                .arguments()
                .iter()
                .map(|argument| {
                    argument
                        .to_descriptor(u64::MAX)
                        .map_err(|_| AnalysisError::Invariant)
                })
                .collect::<Result<Vec<_>, _>>()?;
            CanonicalCallableIdentity::trait_method(
                &receiver,
                reference.path(),
                &trait_arguments,
                method,
                &method_arguments,
            )
            .map_err(|_| AnalysisError::Invariant)?
        } else {
            CanonicalCallableIdentity::inherent(&receiver, method, &method_arguments)
                .map_err(|_| AnalysisError::Invariant)?
        };
        let (source_index, tree, callable) = find_source_callable(sources, declaration)?;
        let parameters = source_callable_parameters(
            tree,
            callable,
            facts.get(source_index).ok_or(AnalysisError::Invariant)?,
            Some(&receiver),
        )?;
        let result = callable_result(
            tree,
            callable,
            facts.get(source_index).ok_or(AnalysisError::Invariant)?,
        );
        callables.push(SourceCallableMetadata {
            identity,
            receiver: Some(receiver),
            receiver_mode: Some(method_receiver_mode(tree, callable)?),
            parameters,
            result,
            effects: effects.get(declaration).copied().unwrap_or_default(),
            declaration: declaration.clone(),
            direct_calls: source_direct_calls(context, declaration),
        });
    }
    callables.sort_by(|left, right| left.identity.cmp(&right.identity));
    callables.dedup_by(|left, right| left.identity == right.identity);
    Ok(callables)
}

fn find_source_callable<'a>(
    sources: &'a [ParsedSource],
    declaration: &SourceSpan,
) -> Result<(usize, &'a SyntaxTree, NodeId), AnalysisError> {
    sources
        .iter()
        .enumerate()
        .find_map(|(source_index, source)| {
            source
                .tree()
                .nodes()
                .iter()
                .enumerate()
                .find(|(_, node)| {
                    matches!(
                        node.form(),
                        SyntaxForm::FunctionDeclaration | SyntaxForm::MethodDeclaration
                    ) && node.span() == declaration
                })
                .map(|(index, _)| (source_index, source.tree(), NodeId::from_index(index)))
        })
        .ok_or(AnalysisError::Invariant)
}

fn source_callable_parameters(
    tree: &SyntaxTree,
    callable: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    receiver: Option<&TypeDescriptor>,
) -> Result<Vec<WorkflowParameter>, AnalysisError> {
    let node = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    let mut parameters = Vec::new();
    if let Some(receiver) = receiver {
        let receiver_mutable = node
            .children()
            .iter()
            .copied()
            .find(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Parameter))
            })
            .and_then(|child| tree.node(child))
            .is_some_and(|parameter| {
                node_has_reserved_word(tree, parameter, "mut")
                    || node_has_identifier(tree, parameter, "exclusive")
                    || node_has_identifier(tree, parameter, "owned")
            });
        parameters.push(WorkflowParameter {
            mutable: receiver_mutable,
            ty: receiver.clone(),
        });
    }
    for parameter in node.children().iter().copied().filter_map(|child| {
        let parameter = tree.node(child)?;
        matches!(parameter.form(), SyntaxForm::Parameter).then_some((child, parameter))
    }) {
        if node_has_reserved_word(tree, parameter.1, "self") {
            continue;
        }
        let type_node = direct_child_form(tree, parameter.1, SyntaxForm::ValueType)
            .ok_or(AnalysisError::Invariant)?;
        let ty = facts
            .get(&type_node)
            .map(|fact| fact.descriptor.clone())
            .ok_or(AnalysisError::Invariant)?;
        parameters.push(WorkflowParameter {
            mutable: node_has_reserved_word(tree, parameter.1, "mut"),
            ty,
        });
    }
    Ok(parameters)
}

fn validate_shared_receiver_declarations(
    sources: &[ParsedSource],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for source in sources {
        for method in source.tree().nodes().iter().filter(|node| {
            matches!(
                node.form(),
                SyntaxForm::MethodDeclaration | SyntaxForm::TraitMethodDeclaration
            )
        }) {
            let Some(receiver) = method.children().iter().copied().find_map(|child| {
                let parameter = source.tree().node(child)?;
                matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
            }) else {
                continue;
            };
            let receiver_kind = if node_has_identifier(source.tree(), receiver, "shared") {
                Some((
                    "shared",
                    "shared-receiver-scope",
                    "`shared self` is limited to zero-argument monomorphic inherent methods",
                ))
            } else if node_has_identifier(source.tree(), receiver, "exclusive") {
                Some((
                    "exclusive",
                    "exclusive-receiver-scope",
                    "`exclusive self` is limited to zero-argument monomorphic inherent methods",
                ))
            } else if node_has_identifier(source.tree(), receiver, "owned") {
                Some((
                    "owned",
                    "owned-receiver-scope",
                    "`owned self` is limited to zero-argument monomorphic inherent methods",
                ))
            } else {
                None
            };
            let Some((_kind, diagnostic_code, diagnostic_message)) = receiver_kind else {
                continue;
            };
            let inherent = matches!(method.form(), SyntaxForm::MethodDeclaration)
                && source.tree().nodes().iter().any(|implementation| {
                    matches!(implementation.form(), SyntaxForm::ImplDeclaration)
                        && span_contains(implementation.span(), method.span())
                        && direct_child_form(
                            source.tree(),
                            implementation,
                            SyntaxForm::TraitReference,
                        )
                        .is_none()
                        && direct_child_form(
                            source.tree(),
                            implementation,
                            SyntaxForm::TypeParameterList,
                        )
                        .is_none()
                        && direct_child_form(source.tree(), implementation, SyntaxForm::ValueType)
                            .and_then(|receiver| source.tree().node(receiver))
                            .is_none_or(|receiver| {
                                direct_child_form(
                                    source.tree(),
                                    receiver,
                                    SyntaxForm::TypeArgumentList,
                                )
                                .is_none()
                            })
                });
            let method_is_monomorphic =
                direct_child_form(source.tree(), method, SyntaxForm::TypeParameterList).is_none();
            let argument_count = method
                .children()
                .iter()
                .filter_map(|child| source.tree().node(*child))
                .filter(|parameter| matches!(parameter.form(), SyntaxForm::Parameter))
                .filter(|parameter| !node_has_reserved_word(source.tree(), parameter, "self"))
                .count();
            if !inherent || !method_is_monomorphic || argument_count != 0 {
                diagnostics.push(body_diagnostic(
                    diagnostic_code,
                    DiagnosticCategory::Type,
                    diagnostic_message,
                    receiver.span().clone(),
                    [] as [(&str, &str); 0],
                )?);
            }
        }
    }
    Ok(())
}

fn method_receiver_mode(
    tree: &SyntaxTree,
    callable: NodeId,
) -> Result<ReceiverMode, AnalysisError> {
    let callable = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    let receiver = callable.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Parameter))
    });
    let Some(receiver) = receiver.and_then(|receiver| tree.node(receiver)) else {
        return Err(AnalysisError::Invariant);
    };
    if node_has_identifier(tree, receiver, "shared") {
        Ok(ReceiverMode::SharedPlace)
    } else if node_has_identifier(tree, receiver, "exclusive") {
        Ok(ReceiverMode::ExclusivePlace)
    } else if node_has_identifier(tree, receiver, "owned") {
        Ok(ReceiverMode::Owned)
    } else {
        Ok(ReceiverMode::from_v1_mutability(node_has_reserved_word(
            tree, receiver, "mut",
        )))
    }
}

/// Returns the receiver mode of the innermost callable containing `span`.
///
/// The enclosing callable's mode decides whether `self` names an admitted caller
/// place, so a nested `exclusive self` reborrow can tell the enclosing admitted
/// place from a callee-local receiver binding.
fn enclosing_callable_receiver_mode(
    tree: &SyntaxTree,
    span: &SourceSpan,
) -> Result<Option<ReceiverMode>, AnalysisError> {
    let Some(callable) = enclosing_callable_node(tree, span) else {
        return Ok(None);
    };
    method_receiver_mode(tree, callable).map(Some)
}

fn callable_result(
    tree: &SyntaxTree,
    callable: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
) -> TypeDescriptor {
    tree.node(callable)
        .into_iter()
        .flat_map(|node| node.children().iter().copied())
        .rfind(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
        })
        .and_then(|type_node| facts.get(&type_node))
        .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone())
}

fn source_direct_calls(context: &BodyContext, declaration: &SourceSpan) -> Vec<EffectNode> {
    context
        .effect_drafts
        .borrow()
        .get(&EffectNode::Source(declaration.clone()))
        .into_iter()
        .flat_map(|draft| &draft.calls)
        .filter(|callee| !matches!(callee, EffectNode::Template(_)))
        .cloned()
        .collect()
}

fn check_parametric_generic_bodies(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    context.parametric_validation.set(true);
    for (signature_index, signature) in context
        .generic_callables
        .values()
        .chain(context.generic_methods.iter())
        .enumerate()
    {
        let rigid_arguments = signature
            .required
            .iter()
            .enumerate()
            .map(|(parameter_index, _)| {
                let mut name =
                    format!("crate::__gantry_parametric_{signature_index}_{parameter_index}");
                // Authored nominal types must never stand in for a rigid parameter.
                while context.capability_declarations.contains_key(&name) {
                    name.push('_');
                }
                CanonicalPath::new(&name)
                    .map(TypeDescriptor::declared)
                    .map_err(|_| AnalysisError::Invariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let substitution = ExactTypeSubstitution::explicit(&signature.required, &rigid_arguments)
            .map_err(|_| AnalysisError::Invariant)?;
        // Rigid representatives prove only capabilities promised by this binder.
        for predicate in &signature.sealed_predicates {
            let index = signature
                .required
                .iter()
                .position(|parameter| parameter == &predicate.parameter)
                .ok_or(AnalysisError::Invariant)?;
            context.capability_proofs.borrow_mut().insert(
                (
                    predicate.capability,
                    rigid_arguments[index].canonical_string(),
                ),
                true,
            );
        }
        let receiver = signature
            .receiver
            .as_ref()
            .map(|receiver| {
                substitution
                    .apply(receiver)
                    .map_err(|_| AnalysisError::Invariant)
            })
            .transpose()?;
        let declared_obligations = signature
            .predicates
            .iter()
            .map(|predicate| {
                let predicate_receiver = if let Some(receiver) = &receiver {
                    substitute_self_type(predicate.receiver(), receiver)?
                } else {
                    predicate.receiver().clone()
                };
                let predicate_receiver = substitution
                    .apply(&predicate_receiver)
                    .map_err(|_| AnalysisError::Invariant)?;
                let trait_arguments = predicate
                    .trait_reference()
                    .arguments()
                    .iter()
                    .map(|argument| {
                        let argument = if let Some(receiver) = &receiver {
                            substitute_self_type(argument, receiver)?
                        } else {
                            argument.clone()
                        };
                        substitution
                            .apply(&argument)
                            .map_err(|_| AnalysisError::Invariant)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(DeclaredTraitObligation {
                    trait_path: predicate.trait_reference().path().clone(),
                    trait_arguments,
                    receiver: predicate_receiver,
                })
            })
            .collect::<Result<Vec<_>, AnalysisError>>()?;
        let source = sources
            .get(signature.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let declaration = source
            .tree()
            .node(signature.declaration)
            .ok_or(AnalysisError::Invariant)?;
        let mut substituted_facts = facts
            .get(signature.source_index)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        for (index, node) in source.tree().nodes().iter().enumerate() {
            if !matches!(node.form(), SyntaxForm::ValueType)
                || !span_contains(declaration.span(), node.span())
            {
                continue;
            }
            let Some(expression) = context.generic_types.get(node.span()) else {
                continue;
            };
            let descriptor = substitution
                .apply_with_receiver(expression, receiver.as_ref())
                .map_err(|_| AnalysisError::Invariant)?;
            substituted_facts.insert(
                NodeId::from_index(index),
                TypeFact {
                    span: node.span().clone(),
                    descriptor,
                },
            );
        }
        *context.current_type_substitution.borrow_mut() = Some(substitution);
        *context.current_declared_obligations.borrow_mut() = declared_obligations;
        *context.current_effect_owner.borrow_mut() =
            Some(EffectNode::Template(signature.template.clone()));
        let check = check_callable(
            source.tree(),
            signature.declaration,
            &substituted_facts,
            context,
            diagnostics,
        );
        *context.current_type_substitution.borrow_mut() = None;
        context.current_declared_obligations.borrow_mut().clear();
        *context.current_effect_owner.borrow_mut() = None;
        check?;
    }
    context.parametric_validation.set(false);
    Ok(())
}

fn check_instantiated_generic_bodies(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut checked = BTreeSet::<InstantiationKey>::new();
    loop {
        let next = context
            .generic_instantiations
            .borrow()
            .keys()
            .find(|key| !checked.contains(*key))
            .cloned();
        let Some(key) = next else {
            break;
        };
        let signature = context
            .generic_callables
            .values()
            .chain(context.generic_methods.iter())
            .find(|signature| signature.template == key.0)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        let substitution = ExactTypeSubstitution::explicit(&signature.required, &key.1)
            .map_err(|_| AnalysisError::Invariant)?;
        let receiver = signature
            .receiver
            .as_ref()
            .map(|receiver| {
                substitution
                    .apply(receiver)
                    .map_err(|_| AnalysisError::Invariant)
            })
            .transpose()?;
        let source = sources
            .get(signature.source_index)
            .ok_or(AnalysisError::Invariant)?;
        let declaration = source
            .tree()
            .node(signature.declaration)
            .ok_or(AnalysisError::Invariant)?;
        let mut substituted_facts = facts
            .get(signature.source_index)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        for (index, node) in source.tree().nodes().iter().enumerate() {
            if !matches!(node.form(), SyntaxForm::ValueType)
                || !span_contains(declaration.span(), node.span())
            {
                continue;
            }
            let Some(expression) = context.generic_types.get(node.span()) else {
                continue;
            };
            let descriptor = substitution
                .apply_with_receiver(expression, receiver.as_ref())
                .map_err(|_| AnalysisError::Invariant)?;
            substituted_facts.insert(
                NodeId::from_index(index),
                TypeFact {
                    span: node.span().clone(),
                    descriptor,
                },
            );
        }
        let witness = context
            .generic_instantiation_witnesses
            .borrow()
            .get(&key)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        *context.current_instantiation.borrow_mut() = Some((key.clone(), witness));
        *context.current_type_substitution.borrow_mut() = Some(substitution);
        *context.current_effect_owner.borrow_mut() = Some(EffectNode::Concrete(key.clone()));
        context.expression_types.borrow_mut().clear();
        let check = check_callable(
            source.tree(),
            signature.declaration,
            &substituted_facts,
            context,
            diagnostics,
        );
        let expression_types = context.expression_types.take();
        *context.current_type_substitution.borrow_mut() = None;
        *context.current_instantiation.borrow_mut() = None;
        *context.current_effect_owner.borrow_mut() = None;
        check?;
        context
            .concrete_declaration_types
            .borrow_mut()
            .insert(key.clone(), substituted_facts);
        context
            .concrete_expression_types
            .borrow_mut()
            .insert(key.clone(), expression_types);
        checked.insert(key);
    }
    Ok(())
}

fn initialize_effect_draft(
    tree: &SyntaxTree,
    callable: &gantry_frontend::SyntaxNode,
    context: &BodyContext,
) -> Result<(), AnalysisError> {
    let Some(owner) = context.current_effect_owner.borrow().clone() else {
        return Ok(());
    };
    let block =
        direct_child_form(tree, callable, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
    let mut direct = EffectSet::default();
    let mut contributors = BTreeMap::new();
    let mut work = vec![block];
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        let before = direct;
        match node.form() {
            SyntaxForm::PromptExpression => {
                direct.insert(Effect::Prompt);
                if subtree_has_reserved_word(tree, node, "fork")
                    || subtree_has_reserved_word(tree, node, "new")
                {
                    direct.insert(Effect::Session);
                }
            }
            SyntaxForm::DecideExpression => {
                direct.insert(Effect::Decide);
                if subtree_has_reserved_word(tree, node, "fork")
                    || subtree_has_reserved_word(tree, node, "new")
                {
                    direct.insert(Effect::Session);
                }
            }
            SyntaxForm::ActionExpression => {
                if let Some(path) = direct_child_form(tree, node, SyntaxForm::Path)
                    && let Some(target) = tree
                        .node(path)
                        .and_then(|path| context.references.get(path.span()))
                    && let Some(effect) = context.action_effects.get(target)
                {
                    direct.insert(*effect);
                }
            }
            SyntaxForm::AttemptExpression => {
                direct.insert(Effect::Attempt);
            }
            SyntaxForm::SpawnStatement => {
                direct.insert(Effect::Spawn);
            }
            SyntaxForm::JoinExpression | SyntaxForm::JoinAllExpression => {
                direct.insert(Effect::Join);
            }
            SyntaxForm::DetachStatement => {
                direct.insert(Effect::Background);
            }
            SyntaxForm::SessionStatement | SyntaxForm::SessionExpression
                if subtree_has_reserved_word(tree, node, "fork")
                    || subtree_has_reserved_word(tree, node, "new") =>
            {
                direct.insert(Effect::Session);
            }
            SyntaxForm::LoopStatement | SyntaxForm::WhileStatement | SyntaxForm::UntilStatement
                if subtree_has_reserved_word(tree, node, "fork")
                    || subtree_has_reserved_word(tree, node, "new") =>
            {
                direct.insert(Effect::Session);
            }
            _ => {}
        }
        for effect in direct.iter() {
            if !before.contains(effect) {
                contributors
                    .entry(effect)
                    .or_insert_with(|| node.span().clone());
            }
        }
        work.extend(node.children().iter().rev().copied());
    }
    let mut drafts = context.effect_drafts.borrow_mut();
    let draft = drafts.entry(owner).or_default();
    draft.direct = draft.direct.union(direct);
    draft.pure = node_has_reserved_word(tree, callable, "pure");
    draft.source = Some(callable.span().clone());
    for (effect, span) in contributors {
        draft.contributors.entry(effect).or_insert(span);
    }
    Ok(())
}

fn subtree_has_reserved_word(
    tree: &SyntaxTree,
    root: &gantry_frontend::SyntaxNode,
    expected: &str,
) -> bool {
    let mut work = root.children().to_vec();
    while let Some(id) = work.pop() {
        let Some(node) = tree.node(id) else {
            return false;
        };
        if matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == expected)
        {
            return true;
        }
        work.extend(node.children().iter().copied());
    }
    false
}

fn finish_effect_graph(
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<EffectSummaries, AnalysisError> {
    let drafts = context.effect_drafts.borrow().clone();
    let mut summaries = drafts
        .iter()
        .map(|(node, draft)| (node.clone(), draft.direct))
        .collect::<BTreeMap<_, _>>();
    loop {
        let mut changed = false;
        for (node, draft) in &drafts {
            let mut summary = draft.direct;
            for callee in &draft.calls {
                if let Some(effects) = summaries.get(callee) {
                    summary = summary.union(*effects);
                }
            }
            let current = summaries.get_mut(node).ok_or(AnalysisError::Invariant)?;
            if *current != summary {
                *current = summary;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (node, draft) in &drafts {
        let effects = summaries.get(node).copied().unwrap_or_default();
        // A trait implementation method is valid only under the contract its trait method
        // declares: the exact inferred effect set must stay within that contract, because
        // parametric callers use the declared set as their conservative summary
        // (`GNT-3-T-PARAMETRIC-PACKAGE`, `GNT-6.12-static-traits`). This report names the
        // contract, so a violating declaration reports it instead of the generic purity report
        // below, which would describe a method as a workflow and duplicate the finding.
        let contract = trait_contract_effects(context, node);
        if let Some((declared, callable, implementation)) = &contract
            && let Some(offending) = effects.iter().find(|effect| !declared.contains(*effect))
            && let Some(span) = draft
                .contributors
                .get(&offending)
                .cloned()
                .or_else(|| {
                    // A purely transitive effect has no contributor in this body, so the call that
                    // can reach it is the closest available location.
                    draft
                        .calls
                        .iter()
                        .find(|callee| {
                            summaries
                                .get(*callee)
                                .is_some_and(|callee_effects| callee_effects.contains(offending))
                        })
                        .and_then(|callee| draft.call_sites.get(callee))
                        .cloned()
                })
                .or_else(|| draft.source.clone())
        {
            diagnostics.push(body_diagnostic(
                "effect-contract-violation",
                DiagnosticCategory::Type,
                "an implementation method infers effects outside its trait method contract",
                span,
                [
                    ("callable", callable.clone()),
                    ("implementation", implementation.clone()),
                    ("inferred", effect_names(effects)),
                    ("declared", effect_names(*declared)),
                ],
            )?);
            continue;
        }
        // The workflow walker already reports the purity violation of a trait implementation
        // declaration, so this report covers callables that declare no contract at all.
        if draft.pure && !effects.is_empty() && contract.is_none() {
            diagnostics.push(body_diagnostic(
                "impure-workflow",
                DiagnosticCategory::Type,
                "a pure workflow has a nonempty transitive inferred effect set",
                draft.source.clone().ok_or(AnalysisError::Invariant)?,
                [("effects", effect_names(effects))],
            )?);
        }
    }
    let templates = summaries
        .iter()
        .filter_map(|(node, effects)| match node {
            EffectNode::Template(template) => Some((template.clone(), *effects)),
            EffectNode::Source(_) | EffectNode::Concrete(_) => None,
        })
        .collect();
    let concrete = summaries
        .iter()
        .filter_map(|(node, effects)| match node {
            EffectNode::Concrete(key) => Some((key.clone(), *effects)),
            EffectNode::Source(_) | EffectNode::Template(_) => None,
        })
        .collect();
    let source = summaries
        .into_iter()
        .filter_map(|(node, effects)| match node {
            EffectNode::Source(source) => Some((source, effects)),
            EffectNode::Template(_) | EffectNode::Concrete(_) => None,
        })
        .collect();
    Ok((templates, concrete, source))
}

fn effect_names(effects: EffectSet) -> String {
    effects
        .iter()
        .map(Effect::wire_name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Returns the declared trait-method effect contract one drafted callable must stay within, with
/// the canonical callable name and implementing identity for diagnostics.
///
/// Inherent methods, concrete instantiations, and implementations whose trait or method has no
/// retained contract have no declared contract to check (`GNT-3-T-PARAMETRIC-PACKAGE`).
fn trait_contract_effects(
    context: &BodyContext,
    node: &EffectNode,
) -> Option<(EffectSet, String, String)> {
    let (trait_path, method_name, implementation) = match node {
        EffectNode::Source(span) => {
            let ((identity, name), _) = context
                .method_sources
                .iter()
                .find(|(_, source)| *source == span)?;
            let head = context
                .implementation_heads
                .iter()
                .find(|head| head.identity() == identity)?;
            let trait_reference = head.trait_reference()?;
            (
                trait_reference.path().clone(),
                name.clone(),
                identity.as_str().to_owned(),
            )
        }
        EffectNode::Template(template) => {
            let signature = context.generic_methods.iter().find(|signature| {
                signature.kind == TemplateKind::TraitMethod && signature.template == *template
            })?;
            (
                signature.trait_reference.as_ref()?.path().clone(),
                signature.method_name.clone()?,
                signature
                    .implementation
                    .as_ref()
                    .map(|identity| identity.as_str().to_owned())
                    .unwrap_or_default(),
            )
        }
        EffectNode::Concrete(_) => return None,
    };
    let contract = context
        .trait_contracts
        .iter()
        .find(|contract| contract.path() == &trait_path)?;
    let method = contract
        .methods()
        .iter()
        .find(|method| method.name() == method_name.as_ref())?;
    Some((
        *method.effects(),
        format!("{}::{}", trait_path.as_str(), method_name),
        implementation,
    ))
}

fn record_effect_call(context: &BodyContext, callee: EffectNode, call_site: SourceSpan) {
    let Some(owner) = context.current_effect_owner.borrow().clone() else {
        return;
    };
    let mut drafts = context.effect_drafts.borrow_mut();
    let draft = drafts.entry(owner).or_default();
    draft.calls.insert(callee.clone());
    draft.call_sites.entry(callee).or_insert(call_site);
}

fn record_direct_effects(context: &BodyContext, effects: EffectSet) {
    let Some(owner) = context.current_effect_owner.borrow().clone() else {
        return;
    };
    let mut drafts = context.effect_drafts.borrow_mut();
    let draft = drafts.entry(owner).or_default();
    draft.direct = draft.direct.union(effects);
}

fn check_callable(
    tree: &SyntaxTree,
    callable: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let node = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    initialize_effect_draft(tree, node, context)?;
    context.shared_receiver_value_roots.borrow_mut().clear();
    context.affine_consumed.borrow_mut().clear();
    context.affine_loop_entry_roots.borrow_mut().clear();
    context.must_consume_obligations.borrow_mut().clear();
    context.must_consume_discharged.borrow_mut().clear();
    context.must_consume_partial.borrow_mut().clear();
    context.must_consume_fresh.borrow_mut().clear();
    context.must_consume_fresh_all.borrow_mut().clear();
    context.must_consume_scopes.borrow_mut().clear();
    context.must_consume_loop_depths.borrow_mut().clear();
    context.must_consume_receiver.set(false);
    context.must_consume_consuming.set(false);
    context.must_consume_discarding.set(false);
    *context.current_visible_traits.borrow_mut() = context
        .callable_visible_traits
        .get(node.span())
        .cloned()
        .unwrap_or_default();
    let mut environment = BTreeMap::<Arc<str>, TypeDescriptor>::new();
    for parameter in node.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Parameter))
    }) {
        let parameter_node = tree.node(parameter).ok_or(AnalysisError::Invariant)?;
        if node_has_reserved_word(tree, parameter_node, "self") {
            if let Some(receiver) = method_receiver_type(tree, node, context)? {
                environment.insert(Arc::from("self"), receiver);
            }
            continue;
        }
        let Some(name) = direct_identifier(tree, parameter)? else {
            continue;
        };
        let Some(type_node) = direct_child_form(tree, parameter_node, SyntaxForm::ValueType) else {
            continue;
        };
        if let Some(fact) = facts.get(&type_node) {
            environment.insert(name.clone(), fact.descriptor.clone());
            register_must_consume_binding(
                name,
                &fact.descriptor,
                parameter_node.span().clone(),
                context,
            );
        }
    }
    // The `owned self` admission already consumed the caller place, so the callee-local receiver
    // starts discharged rather than owing a further consumption.
    if let Some(receiver) = environment.get("self").cloned()
        && method_receiver_mode(tree, callable).is_ok_and(|mode| mode == ReceiverMode::Owned)
        && is_must_consume_type(&receiver, context)
    {
        context.must_consume_receiver.set(true);
        context
            .must_consume_discharged
            .borrow_mut()
            .insert(AffinePlace::root_only(Arc::from("self")));
    }

    let result = node
        .children()
        .iter()
        .copied()
        .rfind(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
        })
        .and_then(|type_node| facts.get(&type_node))
        .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
    let block = node
        .children()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
        })
        .ok_or(AnalysisError::Invariant)?;
    let completion = check_block(
        tree,
        block,
        facts,
        &environment,
        &result,
        context,
        diagnostics,
    )?;

    if let Some(actual) = completion.trailing {
        require_type(
            &result,
            &actual,
            tree.node(block)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone(),
            diagnostics,
        )?;
    } else if result != TypeDescriptor::UNIT && completion.falls_through {
        diagnostics.push(body_diagnostic(
            "missing-result",
            DiagnosticCategory::ControlFlow,
            "a value-returning callable has a reachable normal path without a result",
            tree.node(block)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone(),
            [("expected", result.canonical_string())],
        )?);
    }
    report_open_obligations(
        &ObligationSnapshot::capture(context),
        "a MustConsume value is not consumed before the callable returns",
        context,
        diagnostics,
    )?;
    Ok(())
}

fn check_block(
    tree: &SyntaxTree,
    block: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    inherited: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected_result: &TypeDescriptor,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<BlockResult, AnalysisError> {
    let node = tree.node(block).ok_or(AnalysisError::Invariant)?;
    enter_obligation_scope(context);
    let mut environment = inherited.clone();
    let mut reachable = true;
    let mut trailing = None;
    let mut breaks_loop = false;
    let mut continues_loop = false;
    let mut diverges = false;
    for (child_index, child) in node.children().iter().copied().enumerate() {
        let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
        if is_token(child_node.form()) {
            continue;
        }
        if !reachable {
            diagnostics.push(body_diagnostic(
                "unreachable-source",
                DiagnosticCategory::ControlFlow,
                "source follows a command with no reachable normal completion",
                child_node.span().clone(),
                [] as [(&str, &str); 0],
            )?);
            continue;
        }
        match child_node.form() {
            SyntaxForm::LetStatement => {
                check_let(tree, child, facts, &mut environment, context, diagnostics)?;
            }
            SyntaxForm::AssignmentStatement => {
                check_assignment(tree, child, facts, &environment, context, diagnostics)?;
            }
            SyntaxForm::DiscardStatement => {
                let expression = direct_child_form(tree, child_node, SyntaxForm::Expression)
                    .ok_or(AnalysisError::Invariant)?;
                let recorded = diagnostics.len();
                context.must_consume_discarding.set(true);
                let discarded = infer_expression(
                    tree,
                    expression,
                    facts,
                    &environment,
                    None,
                    context,
                    diagnostics,
                );
                context.must_consume_discarding.set(false);
                let discarded = discarded?;
                // A discarded place already records one class-aware diagnostic; a discarded
                // `MustConsume` value is still a silent discard of the obligation.
                let reported = diagnostics[recorded..].iter().any(|diagnostic| {
                    matches!(
                        diagnostic.code.as_str(),
                        "must-consume-discard" | "must-consume-copy"
                    )
                });
                if !reported
                    && let Some(ty) = discarded
                    && is_must_consume_type(&ty, context)
                {
                    diagnostics.push(body_diagnostic(
                        "must-consume-discard",
                        DiagnosticCategory::Type,
                        "a MustConsume value requires consumption rather than discard",
                        tree.node(expression)
                            .ok_or(AnalysisError::Invariant)?
                            .span()
                            .clone(),
                        [] as [(&str, &str); 0],
                    )?);
                }
            }
            SyntaxForm::SpawnStatement => {
                check_spawned_block(tree, child_node, facts, &environment, context, diagnostics)?;
            }
            SyntaxForm::ReturnStatement => {
                let expression = direct_child_form(tree, child_node, SyntaxForm::Expression);
                // An `owned self` receiver that is handed back to the caller escapes the callable
                // that owes its consumption.
                if context.must_consume_receiver.get()
                    && let Some(id) = expression
                    && expression_is_receiver_root(tree, id)
                {
                    diagnostics.push(body_diagnostic(
                        "must-consume-escape",
                        DiagnosticCategory::Type,
                        "an `owned self` MustConsume receiver is returned by the consuming callable",
                        child_node.span().clone(),
                        [] as [(&str, &str); 0],
                    )?);
                }
                // Returning a place transfers it to the caller, which discharges the obligation;
                // a produced value or a nested read is a copy rather than the returned place.
                context
                    .must_consume_consuming
                    .set(expression.is_some_and(|id| expression_names_a_place(tree, id)));
                let actual = expression
                    .map(|id| {
                        infer_expression(
                            tree,
                            id,
                            facts,
                            &environment,
                            Some(expected_result),
                            context,
                            diagnostics,
                        )
                    })
                    .transpose()?
                    .flatten()
                    .unwrap_or(TypeDescriptor::UNIT);
                context.must_consume_consuming.set(false);
                require_type(
                    expected_result,
                    &actual,
                    child_node.span().clone(),
                    diagnostics,
                )?;
                // A return exits the callable, so a value this path still owes is unconsumed on an
                // exit unless the returned place transferred it to the caller.
                report_open_obligations(
                    &ObligationSnapshot::capture(context),
                    "a MustConsume value is not consumed before the callable returns",
                    context,
                    diagnostics,
                )?;
                reachable = false;
            }
            SyntaxForm::BreakStatement | SyntaxForm::ContinueStatement => {
                if !has_valid_loop_target(tree, child_node) {
                    diagnostics.push(body_diagnostic(
                        "invalid-control-transfer",
                        DiagnosticCategory::ControlFlow,
                        "a break or continue statement has no valid enclosing loop target",
                        child_node.span().clone(),
                        [] as [(&str, &str); 0],
                    )?);
                }
                // A break or continue leaves every block opened inside the loop, so an obligation
                // those blocks introduced is unconsumed on this exit.
                leave_loop_obligation_scopes(context, diagnostics)?;
                breaks_loop |= matches!(child_node.form(), SyntaxForm::BreakStatement);
                continues_loop |= matches!(child_node.form(), SyntaxForm::ContinueStatement);
                reachable = false;
            }
            SyntaxForm::WithStatement | SyntaxForm::SessionStatement => {
                let body = direct_child_form(tree, child_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                let result = check_block(
                    tree,
                    body,
                    facts,
                    &environment,
                    expected_result,
                    context,
                    diagnostics,
                )?;
                reachable = result.falls_through;
                breaks_loop |= result.breaks_loop;
                continues_loop |= result.continues_loop;
                diverges |= !result.falls_through && result.diverges;
            }
            SyntaxForm::MatchStatement => {
                let completion = check_match_statement(
                    tree,
                    child_node,
                    facts,
                    &environment,
                    expected_result,
                    context,
                    diagnostics,
                )?;
                reachable = completion.falls_through;
                breaks_loop |= completion.breaks_loop;
                continues_loop |= completion.continues_loop;
                diverges |= completion.diverges;
            }
            SyntaxForm::IfStatement => {
                let has_pattern = child_node.children().iter().copied().any(|nested| {
                    tree.node(nested)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
                });
                let mut pattern_environment = environment.clone();
                let mut pattern_payload_roots = BTreeSet::new();
                let mut pattern_bindings = BTreeMap::new();
                let mut pattern_span = None;
                if has_pattern {
                    let pattern = direct_child_form(tree, child_node, SyntaxForm::Pattern)
                        .ok_or(AnalysisError::Invariant)?;
                    pattern_span = Some(
                        tree.node(pattern)
                            .ok_or(AnalysisError::Invariant)?
                            .span()
                            .clone(),
                    );
                    let scrutinee = direct_child_form(tree, child_node, SyntaxForm::Expression)
                        .ok_or(AnalysisError::Invariant)?;
                    if let Some(scrutinee_type) = infer_expression(
                        tree,
                        scrutinee,
                        facts,
                        &environment,
                        None,
                        context,
                        diagnostics,
                    )? && validate_pattern_shape(
                        tree,
                        pattern,
                        &scrutinee_type,
                        true,
                        context,
                        diagnostics,
                    )? {
                        let (_, bindings) = pattern_coverage(
                            tree,
                            pattern,
                            &scrutinee_type,
                            &BTreeSet::new(),
                            context,
                            diagnostics,
                        )?;
                        pattern_payload_roots = bindings.keys().cloned().collect();
                        pattern_environment.extend(bindings.clone());
                        pattern_bindings = bindings;
                    }
                }
                let conditions = child_node
                    .children()
                    .iter()
                    .copied()
                    .filter(|nested| {
                        tree.node(*nested)
                            .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
                    })
                    .collect::<Vec<_>>();
                if !has_pattern {
                    for condition in conditions.iter().copied() {
                        if let Some(actual) = infer_expression(
                            tree,
                            condition,
                            facts,
                            &environment,
                            None,
                            context,
                            diagnostics,
                        )? && !matches!(actual.kind(), TypeKind::Bool | TypeKind::Decision)
                        {
                            diagnostics.push(body_diagnostic(
                                "condition-type",
                                DiagnosticCategory::Type,
                                "a condition is neither Bool nor Decision",
                                tree.node(condition)
                                    .ok_or(AnalysisError::Invariant)?
                                    .span()
                                    .clone(),
                                [("actual", actual.canonical_string())],
                            )?);
                        }
                    }
                }
                let saved = ObligationSnapshot::capture(context);
                let mut branch_states = Vec::new();
                let mut branch_results = Vec::new();
                let mut blocks = 0_usize;
                for nested in child_node.children().iter().copied().filter(|nested| {
                    tree.node(*nested)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
                }) {
                    let branch_environment = if has_pattern && blocks == 0 {
                        &pattern_environment
                    } else {
                        &environment
                    };
                    blocks = blocks.saturating_add(1);
                    saved.restore(context);
                    let result = if has_pattern && blocks == 1 {
                        let pattern_span = pattern_span.clone().ok_or(AnalysisError::Invariant)?;
                        enter_obligation_bindings(context, &pattern_bindings, &pattern_span);
                        let checked = with_shared_receiver_payload_roots(
                            context,
                            pattern_payload_roots.clone(),
                            || {
                                check_block(
                                    tree,
                                    nested,
                                    facts,
                                    branch_environment,
                                    expected_result,
                                    context,
                                    diagnostics,
                                )
                            },
                        );
                        let checked = checked?;
                        leave_obligation_scope(context, diagnostics)?;
                        checked
                    } else {
                        check_block(
                            tree,
                            nested,
                            facts,
                            branch_environment,
                            expected_result,
                            context,
                            diagnostics,
                        )?
                    };
                    branch_results.push(result);
                    // A branch that left the region without a normal completion never reaches the
                    // join. A settled transfer already reported what it owed, so it contributes no
                    // join state; a branch that diverged owes at the enclosing scope exit, so its
                    // final state keeps the obligation visible there.
                    if branch_results
                        .last()
                        .is_some_and(|result| result.falls_through || result.diverges)
                    {
                        branch_states.push((
                            blocks.saturating_sub(1),
                            ObligationSnapshot::capture(context),
                        ));
                    }
                }
                // A consuming admission on only some paths leaves the obligation live: a discharge
                // survives the fold only when every reaching path discharges it, and the report is
                // deferred to the region exit that a path still leaves without the discharge. The
                // same constant facts the reachability analysis uses select the reaching paths: a
                // branch guarded by a statically false condition never runs, a branch after a
                // statically true condition is unreachable, and the pre-conditional state is a
                // reaching path exactly when the chain can fall through without taking a branch.
                let has_final_else = blocks > conditions.len();
                // The first expression of a pattern chain is the scrutinee rather than a
                // condition, and a pattern can always fail to select its branch.
                let first_condition = usize::from(has_pattern);
                let mut reaching_states = Vec::new();
                let mut no_branch_possible = true;
                if has_pattern
                    && let Some((_, state)) = branch_states.iter().find(|(branch, _)| *branch == 0)
                {
                    reaching_states.push(state.clone());
                }
                for (index, condition) in
                    conditions.iter().copied().enumerate().skip(first_condition)
                {
                    match bool_fact(tree, condition)? {
                        BoolFact::True => {
                            if let Some((_, state)) =
                                branch_states.iter().find(|(branch, _)| *branch == index)
                            {
                                reaching_states.push(state.clone());
                            }
                            no_branch_possible = false;
                            break;
                        }
                        BoolFact::False => {}
                        BoolFact::Unknown => {
                            if let Some((_, state)) =
                                branch_states.iter().find(|(branch, _)| *branch == index)
                            {
                                reaching_states.push(state.clone());
                            }
                        }
                    }
                }
                // A final else block covers the not-taken path whenever no condition is statically
                // true.
                if no_branch_possible
                    && let Some((_, state)) = branch_states
                        .iter()
                        .find(|(branch, _)| *branch == conditions.len())
                {
                    reaching_states.push(state.clone());
                }
                let include_fallthrough = !has_final_else && no_branch_possible;
                merge_obligation_states(&saved, &reaching_states, include_fallthrough, context);
                if has_pattern {
                    let has_else = child_node.children().iter().any(|nested| {
                        tree.node(*nested).is_some_and(|node| {
                            matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "else")
                        })
                    });
                    reachable = !has_else
                        || blocks == 0
                        || branch_results.iter().any(|result| result.falls_through);
                    breaks_loop |= branch_results.iter().any(|result| result.breaks_loop);
                    continues_loop |= branch_results.iter().any(|result| result.continues_loop);
                    diverges |= !reachable && branch_results.iter().any(|result| result.diverges);
                } else {
                    let has_final_else = branch_results.len() > conditions.len();
                    let mut selected_fallthrough = !has_final_else;
                    let mut selected_breaks = false;
                    let mut selected_continues = false;
                    if has_final_else && let Some(otherwise) = branch_results.last() {
                        selected_fallthrough = otherwise.falls_through;
                        selected_breaks = otherwise.breaks_loop;
                        selected_continues = otherwise.continues_loop;
                    }
                    for (index, condition) in conditions.iter().copied().enumerate().rev() {
                        let Some(branch) = branch_results.get(index) else {
                            continue;
                        };
                        match bool_fact(tree, condition)? {
                            BoolFact::True => {
                                selected_fallthrough = branch.falls_through;
                                selected_breaks = branch.breaks_loop;
                                selected_continues = branch.continues_loop;
                            }
                            BoolFact::False => {}
                            BoolFact::Unknown => {
                                selected_fallthrough |= branch.falls_through;
                                selected_breaks |= branch.breaks_loop;
                                selected_continues |= branch.continues_loop;
                            }
                        }
                    }
                    reachable = selected_fallthrough;
                    breaks_loop |= selected_breaks;
                    continues_loop |= selected_continues;
                    diverges |= !selected_fallthrough
                        && branch_results.iter().any(|result| result.diverges);
                }
            }
            SyntaxForm::ForStatement => {
                let source = direct_child_form(tree, child_node, SyntaxForm::Expression)
                    .ok_or(AnalysisError::Invariant)?;
                let body = direct_child_form(tree, child_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                let source_type = infer_expression(
                    tree,
                    source,
                    facts,
                    &environment,
                    None,
                    context,
                    diagnostics,
                )?;
                let mut body_environment = environment.clone();
                if let Some(source_type) = source_type {
                    if source_type.kind() == TypeKind::List {
                        if let Some(name) = direct_identifier(tree, child)?
                            && let Some(member) = source_type.immediate_members().into_iter().next()
                        {
                            body_environment.insert(name, member);
                        }
                    } else {
                        diagnostics.push(body_diagnostic(
                            "for-source-type",
                            DiagnosticCategory::Type,
                            "a for source is not a List value",
                            tree.node(source)
                                .ok_or(AnalysisError::Invariant)?
                                .span()
                                .clone(),
                            [("actual", source_type.canonical_string())],
                        )?);
                    }
                }
                let loop_entry = ObligationSnapshot::capture(context);
                let loop_depth = context.must_consume_scopes.borrow().len();
                context
                    .must_consume_loop_depths
                    .borrow_mut()
                    .push(loop_depth);
                let checked = with_affine_loop_scope(context, &environment, || {
                    check_block(
                        tree,
                        body,
                        facts,
                        &body_environment,
                        expected_result,
                        context,
                        diagnostics,
                    )
                });
                context.must_consume_loop_depths.borrow_mut().pop();
                let _ = checked?;
                report_loop_consumption(&loop_entry, context, diagnostics)?;
            }
            SyntaxForm::LoopStatement | SyntaxForm::WhileStatement | SyntaxForm::UntilStatement => {
                check_loop_limit(tree, child_node, diagnostics)?;
                let condition = direct_child_form(tree, child_node, SyntaxForm::Expression);
                let body = direct_child_form(tree, child_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                let loop_entry = ObligationSnapshot::capture(context);
                let loop_depth = context.must_consume_scopes.borrow().len();
                context
                    .must_consume_loop_depths
                    .borrow_mut()
                    .push(loop_depth);
                let checked = with_affine_loop_scope(context, &environment, || {
                    for condition in condition.iter().copied() {
                        if let Some(actual) = infer_expression(
                            tree,
                            condition,
                            facts,
                            &environment,
                            None,
                            context,
                            diagnostics,
                        )? && !matches!(actual.kind(), TypeKind::Bool | TypeKind::Decision)
                        {
                            diagnostics.push(body_diagnostic(
                                "condition-type",
                                DiagnosticCategory::Type,
                                "a condition is neither Bool nor Decision",
                                tree.node(condition)
                                    .ok_or(AnalysisError::Invariant)?
                                    .span()
                                    .clone(),
                                [("actual", actual.canonical_string())],
                            )?);
                        }
                    }
                    check_block(
                        tree,
                        body,
                        facts,
                        &environment,
                        expected_result,
                        context,
                        diagnostics,
                    )
                });
                context.must_consume_loop_depths.borrow_mut().pop();
                let body_result = checked?;
                report_loop_consumption(&loop_entry, context, diagnostics)?;
                let fact = condition
                    .map(|condition| bool_fact(tree, condition))
                    .transpose()?
                    .unwrap_or(BoolFact::Unknown);
                reachable = match child_node.form() {
                    SyntaxForm::LoopStatement => body_result.breaks_loop,
                    SyntaxForm::WhileStatement => fact != BoolFact::True || body_result.breaks_loop,
                    SyntaxForm::UntilStatement => {
                        body_result.breaks_loop
                            || ((body_result.falls_through || body_result.continues_loop)
                                && fact != BoolFact::False)
                    }
                    _ => return Err(AnalysisError::Invariant),
                };
                diverges |= !reachable;
            }
            SyntaxForm::Expression => {
                let terminated = node
                    .children()
                    .get(child_index.saturating_add(1))
                    .and_then(|next| tree.node(*next))
                    .is_some_and(|next| matches!(next.form(), SyntaxForm::ExpressionStatement));
                // A trailing expression is the callable result: a returned `MustConsume` place is
                // handed to the caller rather than copied, and a returned `owned self` receiver
                // escapes the consuming callable.
                if !terminated
                    && context.must_consume_receiver.get()
                    && expression_is_receiver_root(tree, child)
                {
                    diagnostics.push(body_diagnostic(
                        "must-consume-escape",
                        DiagnosticCategory::Type,
                        "an `owned self` MustConsume receiver is returned by the consuming callable",
                        child_node.span().clone(),
                        [] as [(&str, &str); 0],
                    )?);
                }
                if !terminated {
                    // Only a whole place transfers its obligation to the caller: a projection or a
                    // produced value is a copy rather than the returned place itself.
                    context
                        .must_consume_consuming
                        .set(expression_is_whole_place(tree, child));
                }
                let actual = infer_expression(
                    tree,
                    child,
                    facts,
                    &environment,
                    Some(expected_result),
                    context,
                    diagnostics,
                )?;
                context.must_consume_consuming.set(false);
                if terminated {
                    if let Some(actual) = actual
                        && actual != TypeDescriptor::UNIT
                    {
                        diagnostics.push(body_diagnostic(
                            "discard-required",
                            DiagnosticCategory::Type,
                            "a non-Unit expression statement requires explicit discard",
                            child_node.span().clone(),
                            [("actual", actual.canonical_string())],
                        )?);
                    }
                } else {
                    trailing = actual;
                    reachable = false;
                }
            }
            _ => {}
        }
    }
    leave_obligation_scope(context, diagnostics)?;
    Ok(BlockResult {
        falls_through: reachable,
        trailing,
        breaks_loop,
        continues_loop,
        diverges,
    })
}

/// Rejects a spawned block's reference to an outer binding that admits no task transfer.
///
/// A spawned block captures the outer bindings it references, and that capture is an independent
/// copy, so a value of an ownership class that prohibits copying has no task-transfer contract and
/// the reference is rejected where it appears. Declaration names, type syntax, and patterns name
/// bindings or types rather than reading a captured value, and a nested spawned block reports its
/// own captures.
fn check_spawn_capture_eligibility(
    tree: &SyntaxTree,
    block: NodeId,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut reported = BTreeSet::new();
    let mut work = vec![block];
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        if id != block
            && matches!(
                node.form(),
                SyntaxForm::SpawnStatement
                    | SyntaxForm::Parameter
                    | SyntaxForm::StructField
                    | SyntaxForm::Pattern
                    | SyntaxForm::ValueType
                    | SyntaxForm::TypeParameterList
                    | SyntaxForm::TypeArgumentList
                    | SyntaxForm::TraitReference
            )
        {
            continue;
        }
        let declares = matches!(
            node.form(),
            SyntaxForm::LetStatement | SyntaxForm::ForStatement
        );
        let mut identifiers = 0;
        for child in node.children() {
            let Some(child_node) = tree.node(*child) else {
                continue;
            };
            let SyntaxForm::Token(TokenKind::Identifier(name)) = child_node.form() else {
                continue;
            };
            let declared = identifiers == 0;
            identifiers += 1;
            if declares && declared {
                continue;
            }
            let Some(ty) = environment.get(name) else {
                continue;
            };
            if task_capture_eligible(ty, context) || !reported.insert(name.clone()) {
                continue;
            }
            diagnostics.push(body_diagnostic(
                "task-capture-ineligible",
                DiagnosticCategory::Type,
                "a spawned block cannot capture a value with no task-transfer contract",
                child_node.span().clone(),
                [("binding", name.as_ref())],
            )?);
        }
        work.extend(node.children().iter().rev().copied());
    }
    Ok(())
}

fn check_spawned_block(
    tree: &SyntaxTree,
    statement: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let result = direct_child_form(tree, statement, SyntaxForm::ValueType)
        .and_then(|type_node| facts.get(&type_node))
        .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
    let block =
        direct_child_form(tree, statement, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
    check_spawn_capture_eligibility(tree, block, environment, context, diagnostics)?;
    let captures = environment
        .iter()
        .map(|(name, ty)| {
            Ok(SpawnCaptureMetadata {
                name: name.clone(),
                ty: ty.clone(),
                mutable: assignment_root_is_mutable(
                    tree,
                    statement.span(),
                    name,
                    name.as_ref() == "self",
                )?,
            })
        })
        .collect::<Result<Vec<_>, AnalysisError>>()?;
    let owner = context
        .current_effect_owner
        .borrow()
        .clone()
        .ok_or(AnalysisError::Invariant)?;
    context
        .spawn_captures
        .borrow_mut()
        .entry(owner)
        .or_default()
        .insert(statement.span().clone(), captures);
    let completion = check_block(
        tree,
        block,
        facts,
        environment,
        &result,
        context,
        diagnostics,
    )?;
    if let Some(actual) = completion.trailing {
        require_type(
            &result,
            &actual,
            tree.node(block)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone(),
            diagnostics,
        )?;
    } else if result != TypeDescriptor::UNIT && completion.falls_through {
        diagnostics.push(body_diagnostic(
            "missing-result",
            DiagnosticCategory::ControlFlow,
            "a value-returning spawned block has a reachable normal path without a result",
            tree.node(block)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone(),
            [("expected", result.canonical_string())],
        )?);
    }
    Ok(())
}

fn check_match_statement(
    tree: &SyntaxTree,
    statement: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected_result: &TypeDescriptor,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<StatementCompletion, AnalysisError> {
    let scrutinee = direct_child_form(tree, statement, SyntaxForm::Expression)
        .ok_or(AnalysisError::Invariant)?;
    let Some(scrutinee_type) = infer_expression(
        tree,
        scrutinee,
        facts,
        environment,
        None,
        context,
        diagnostics,
    )?
    else {
        return Ok(StatementCompletion {
            falls_through: true,
            breaks_loop: false,
            continues_loop: false,
            diverges: false,
        });
    };
    if scrutinee_type == TypeDescriptor::DECISION {
        diagnostics.push(body_diagnostic(
            "sealed-value-operation",
            DiagnosticCategory::Type,
            "Decision values cannot be pattern-matched",
            statement.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    let universe = coverage_universe(&scrutinee_type, context)?;
    let saved = ObligationSnapshot::capture(context);
    let mut covered = BTreeSet::new();
    let mut any_fallthrough = false;
    let mut any_break = false;
    let mut any_continue = false;
    let mut any_diverges = false;
    let mut branch_states = Vec::new();
    for arm in statement.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
    }) {
        let arm_node = tree.node(arm).ok_or(AnalysisError::Invariant)?;
        let pattern = direct_child_form(tree, arm_node, SyntaxForm::Pattern)
            .ok_or(AnalysisError::Invariant)?;
        let (keys, bindings) = pattern_coverage(
            tree,
            pattern,
            &scrutinee_type,
            &universe,
            context,
            diagnostics,
        )?;
        if !keys.is_empty() && keys.iter().all(|key| covered.contains(key)) {
            diagnostics.push(body_diagnostic(
                "redundant-pattern",
                DiagnosticCategory::ControlFlow,
                "a match arm is unreachable after preceding ordered patterns",
                tree.node(pattern)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [] as [(&str, &str); 0],
            )?);
        }
        covered.extend(keys);
        let mut arm_environment = environment.clone();
        let payload_roots = pattern_payload_binding_names(tree, pattern, &bindings)?;
        arm_environment.extend(bindings.clone());
        let body =
            direct_child_form(tree, arm_node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
        let pattern_span = tree
            .node(pattern)
            .ok_or(AnalysisError::Invariant)?
            .span()
            .clone();
        saved.restore(context);
        enter_obligation_bindings(context, &bindings, &pattern_span);
        let checked = with_shared_receiver_payload_roots(context, payload_roots, || {
            check_block(
                tree,
                body,
                facts,
                &arm_environment,
                expected_result,
                context,
                diagnostics,
            )
        });
        let result = checked?;
        leave_obligation_scope(context, diagnostics)?;
        // A diverging arm never reaches the join and never settles through a transfer, so its
        // final state keeps the obligation visible at the enclosing scope exit.
        if result.falls_through || result.diverges {
            branch_states.push(ObligationSnapshot::capture(context));
        }
        any_fallthrough |= result.falls_through;
        any_break |= result.breaks_loop;
        any_continue |= result.continues_loop;
        any_diverges |= result.diverges;
    }
    let exhaustive = !universe.is_empty() && universe.is_subset(&covered);
    merge_obligation_states(&saved, &branch_states, !exhaustive, context);
    if !universe.is_empty() && !exhaustive {
        diagnostics.push(body_diagnostic(
            "nonexhaustive-match",
            DiagnosticCategory::ControlFlow,
            "a structural match does not cover every value of its scrutinee type",
            statement.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    let falls_through = !exhaustive || any_fallthrough;
    Ok(StatementCompletion {
        falls_through,
        breaks_loop: any_break,
        continues_loop: any_continue,
        diverges: !falls_through && any_diverges,
    })
}

fn check_let(
    tree: &SyntaxTree,
    statement: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &mut BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
    let type_node =
        direct_child_form(tree, node, SyntaxForm::ValueType).ok_or(AnalysisError::Invariant)?;
    let Some(expected) = facts.get(&type_node).map(|fact| fact.descriptor.clone()) else {
        return Ok(());
    };
    if let Some(expression) = direct_child_form(tree, node, SyntaxForm::Expression)
        && let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            Some(&expected),
            context,
            diagnostics,
        )?
    {
        require_type(&expected, &actual, node.span().clone(), diagnostics)?;
    }
    if let Some(pattern) = direct_child_form(tree, node, SyntaxForm::Pattern) {
        if validate_pattern_shape(tree, pattern, &expected, false, context, diagnostics)? {
            let bindings = pattern_type_bindings(tree, pattern, &expected)?;
            // A pattern that binds a name to a `MustConsume` value owes that payload's
            // consumption like any other binding introduction.
            for (name, ty) in &bindings {
                register_must_consume_binding(name.clone(), ty, node.span().clone(), context);
            }
            environment.extend(bindings);
        }
    } else if let Some(name) = direct_identifier(tree, statement)? {
        // A declaration of a `MustConsume` value owes its consumption before the binding's scope
        // ends, whether the value came from a struct literal, a call result, or a projection.
        register_must_consume_binding(name.clone(), &expected, node.span().clone(), context);
        environment.insert(name, expected);
    }
    Ok(())
}

fn check_assignment(
    tree: &SyntaxTree,
    statement: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
    let receiver = node_has_reserved_word(tree, node, "self");
    let identifiers = direct_identifiers(tree, statement)?;
    let root = if receiver {
        Arc::from("self")
    } else {
        identifiers
            .first()
            .cloned()
            .ok_or(AnalysisError::Invariant)?
    };
    if receiver && !environment.contains_key(&root) {
        diagnostics.push(body_diagnostic(
            "receiver-scope",
            DiagnosticCategory::Type,
            "self is available only inside an inherent method body",
            node.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    if assignment_targets_sealed_member(&root, &identifiers, environment) {
        diagnostics.push(body_diagnostic(
            "sealed-value-operation",
            DiagnosticCategory::Type,
            "a sealed Decision field cannot be mutated",
            node.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    if !assignment_root_is_mutable(tree, node.span(), &root, receiver)? {
        diagnostics.push(body_diagnostic(
            "immutable-assignment",
            DiagnosticCategory::Type,
            "an assignment target is rooted in an immutable binding or receiver",
            node.span().clone(),
            [("binding", root.as_ref())],
        )?);
    }

    let expected = assignment_target_type(&root, receiver, &identifiers, environment, context);
    let expression =
        direct_child_form(tree, node, SyntaxForm::Expression).ok_or(AnalysisError::Invariant)?;
    let operator = direct_assignment_operator(tree, node).ok_or(AnalysisError::Invariant)?;
    let actual = infer_expression(
        tree,
        expression,
        facts,
        environment,
        (operator == Punctuation::Equal)
            .then_some(expected.as_ref())
            .flatten(),
        context,
        diagnostics,
    )?;
    if let (Some(expected), Some(actual)) = (expected, actual) {
        if operator == Punctuation::Equal {
            require_type(&expected, &actual, node.span().clone(), diagnostics)?;
        } else if let Some(primitive) = assignment_primitive(operator) {
            let result = infer_binary_operator(
                primitive,
                expected.clone(),
                actual,
                node.span().clone(),
                context,
                diagnostics,
            )?;
            require_type(&expected, &result, node.span().clone(), diagnostics)?;
        }
    }
    // Replacing a place that still owes consumption would silently discard an initialized
    // `MustConsume` value, which `GNT-6.2d` forbids: the place must be consumed first. A projected
    // struct field of a live root that owns such a value discards it in exactly the same way, so
    // the rule covers a binding root and every struct-field projection of one. The answer is judged
    // per obligation place rather than per root, so consuming one projected field never licenses
    // replacing a sibling. A place whose value is already gone may be reassigned: a binding root
    // binds a fresh obligation, and a projection re-initializes exactly its own subtree - even
    // inside a containing place that was already consumed - so the fresh value owes its
    // consumption like any other.
    if operator == Punctuation::Equal
        && !receiver
        && let Some(target) =
            assignment_target_type(&root, receiver, &identifiers, environment, context)
        && is_must_consume_type(&target, context)
    {
        let place = AffinePlace::projected(
            root.clone(),
            identifiers.get(1..).unwrap_or_default().to_vec(),
        );
        if obligation_place_is_live(&place, context) {
            diagnostics.push(body_diagnostic(
                "must-consume-replaced",
                DiagnosticCategory::Type,
                "an initialized MustConsume place cannot be replaced without consuming it",
                node.span().clone(),
                [] as [(&str, &str); 0],
            )?);
        } else if identifiers.len() == 1 {
            rebind_must_consume(
                &root,
                MustConsumeBinding {
                    span: node.span().clone(),
                    ty: target,
                },
                context,
            );
        } else {
            reinitialize_must_consume_place(&place, context);
        }
    }
    Ok(())
}

fn assignment_target_type(
    root: &Arc<str>,
    receiver: bool,
    identifiers: &[Arc<str>],
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
) -> Option<TypeDescriptor> {
    let mut current = environment.get(root)?.clone();
    let fields = if receiver {
        identifiers
    } else {
        identifiers.get(1..).unwrap_or_default()
    };
    for field in fields {
        let shape = context
            .structs
            .values()
            .find(|shape| shape.descriptor == current)?;
        current = shape.fields.get(field)?.ty.clone();
    }
    Some(current)
}

fn assignment_targets_sealed_member(
    root: &Arc<str>,
    identifiers: &[Arc<str>],
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
) -> bool {
    identifiers.len() > 1 && environment.get(root) == Some(&TypeDescriptor::DECISION)
}

/// Returns the innermost function or method declaration containing `span`.
fn enclosing_callable_node(tree: &SyntaxTree, span: &SourceSpan) -> Option<NodeId> {
    tree.nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            matches!(
                node.form(),
                SyntaxForm::FunctionDeclaration | SyntaxForm::MethodDeclaration
            ) && span_contains(node.span(), span)
        })
        .min_by_key(|(_, node)| span_width(node.span()))
        .map(|(index, _)| NodeId::from_index(index))
}

fn assignment_root_is_mutable(
    tree: &SyntaxTree,
    assignment: &SourceSpan,
    root: &Arc<str>,
    receiver: bool,
) -> Result<bool, AnalysisError> {
    let Some(callable) =
        enclosing_callable_node(tree, assignment).and_then(|callable| tree.node(callable))
    else {
        return Ok(false);
    };

    if receiver {
        return Ok(callable.children().iter().copied().any(|child| {
            tree.node(child).is_some_and(|parameter| {
                matches!(parameter.form(), SyntaxForm::Parameter)
                    && node_has_reserved_word(tree, parameter, "self")
                    && (node_has_reserved_word(tree, parameter, "mut")
                        || node_has_identifier(tree, parameter, "exclusive")
                        || node_has_identifier(tree, parameter, "owned"))
            })
        }));
    }

    let declaration = tree
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node.form(),
                SyntaxForm::Parameter | SyntaxForm::LetStatement
            ) && span_contains(callable.span(), node.span())
                && node.span().bytes().start() <= assignment.bytes().start()
        })
        .filter_map(|node| {
            let id = tree
                .nodes()
                .iter()
                .position(|candidate| std::ptr::eq(candidate, node))
                .map(NodeId::from_index)?;
            (direct_identifier(tree, id).ok().flatten().as_ref() == Some(root)).then_some(node)
        })
        .filter(|declaration| {
            matches!(declaration.form(), SyntaxForm::Parameter)
                || tree.nodes().iter().any(|block| {
                    matches!(block.form(), SyntaxForm::Block)
                        && span_contains(block.span(), assignment)
                        && span_contains(block.span(), declaration.span())
                })
        })
        .max_by_key(|node| node.span().bytes().start());
    Ok(declaration.is_some_and(|node| node_has_reserved_word(tree, node, "mut")))
}

fn direct_assignment_operator(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<Punctuation> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Punctuation(operator))
                if matches!(
                    operator,
                    Punctuation::Equal
                        | Punctuation::PlusEqual
                        | Punctuation::MinusEqual
                        | Punctuation::StarEqual
                        | Punctuation::SlashEqual
                        | Punctuation::PercentEqual
                ) =>
            {
                Some(*operator)
            }
            _ => None,
        })
}

fn assignment_primitive(operator: Punctuation) -> Option<Punctuation> {
    match operator {
        Punctuation::PlusEqual => Some(Punctuation::Plus),
        Punctuation::MinusEqual => Some(Punctuation::Minus),
        Punctuation::StarEqual => Some(Punctuation::Star),
        Punctuation::SlashEqual => Some(Punctuation::Slash),
        Punctuation::PercentEqual => Some(Punctuation::Percent),
        _ => None,
    }
}

fn has_valid_loop_target(tree: &SyntaxTree, transfer: &gantry_frontend::SyntaxNode) -> bool {
    let Some(loop_node) = tree
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node.form(),
                SyntaxForm::LoopStatement
                    | SyntaxForm::WhileStatement
                    | SyntaxForm::UntilStatement
                    | SyntaxForm::ForStatement
            ) && span_contains(node.span(), transfer.span())
        })
        .min_by_key(|node| span_width(node.span()))
    else {
        return false;
    };
    !tree.nodes().iter().any(|node| {
        matches!(node.form(), SyntaxForm::SpawnStatement)
            && span_contains(node.span(), transfer.span())
            && span_contains(loop_node.span(), node.span())
    })
}

fn check_loop_limit(
    tree: &SyntaxTree,
    statement: &gantry_frontend::SyntaxNode,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for modifier in statement
        .children()
        .iter()
        .copied()
        .filter_map(|child| {
            let list = tree.node(child)?;
            matches!(list.form(), SyntaxForm::ModifierList).then_some(list)
        })
        .flat_map(|list| list.children().iter().copied())
    {
        let Some(node) = tree.node(modifier) else {
            return Err(AnalysisError::Invariant);
        };
        if !matches!(node.form(), SyntaxForm::Modifier)
            || !node_has_reserved_word(tree, node, "limit")
        {
            continue;
        }
        let invalid = node
            .children()
            .iter()
            .filter_map(|child| tree.node(*child))
            .find_map(|token| match token.form() {
                SyntaxForm::Token(TokenKind::DirectiveInteger(value)) => Some(
                    value
                        .parse::<u64>()
                        .map_or(true, |limit| limit == 0 || limit > i64::MAX as u64),
                ),
                _ => None,
            });
        if invalid == Some(true) {
            diagnostics.push(body_diagnostic(
                "invalid-loop-limit",
                DiagnosticCategory::ControlFlow,
                "a numeric loop limit is outside the inclusive range 1 through 2^63-1",
                node.span().clone(),
                [] as [(&str, &str); 0],
            )?);
        }
    }
    Ok(())
}

fn pattern_type_bindings(
    tree: &SyntaxTree,
    pattern: NodeId,
    ty: &TypeDescriptor,
) -> Result<BTreeMap<Arc<str>, TypeDescriptor>, AnalysisError> {
    let mut bindings = BTreeMap::new();
    let mut work = vec![(pattern, ty.clone())];
    while let Some((pattern, current_type)) = work.pop() {
        let node = tree.node(pattern).ok_or(AnalysisError::Invariant)?;
        let nested = node
            .children()
            .iter()
            .copied()
            .filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
            })
            .collect::<Vec<_>>();
        let word = direct_reserved_word(tree, node);
        if word.as_deref() == Some("Some") {
            if let (Some(member), Some(nested)) = (
                current_type.immediate_members().into_iter().next(),
                nested.first().copied(),
            ) {
                work.push((nested, member));
            }
            continue;
        }
        if !nested.is_empty() {
            let members = current_type.immediate_members();
            for (nested, member) in nested.into_iter().zip(members).rev() {
                work.push((nested, member));
            }
            continue;
        }
        if let Some(name) = direct_identifier(tree, pattern)? {
            bindings.insert(name, current_type);
        }
    }
    Ok(bindings)
}

fn pattern_payload_binding_names(
    tree: &SyntaxTree,
    pattern: NodeId,
    bindings: &BTreeMap<Arc<str>, TypeDescriptor>,
) -> Result<BTreeSet<Arc<str>>, AnalysisError> {
    if node_contains_punctuation(tree, pattern, Punctuation::PathSeparator) {
        return Ok(bindings.keys().cloned().collect());
    }
    let mut payload_bindings = BTreeSet::new();
    let mut work = vec![(pattern, false)];
    while let Some((pattern, inherited_payload)) = work.pop() {
        let node = tree.node(pattern).ok_or(AnalysisError::Invariant)?;
        let nested = node
            .children()
            .iter()
            .copied()
            .filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
            })
            .collect::<Vec<_>>();
        let payload =
            inherited_payload
                || matches!(
                    direct_reserved_word(tree, node).as_deref(),
                    Some("Some" | "Ok" | "Err")
                )
                || node.children().iter().copied().any(|child| {
                    node_contains_punctuation(tree, child, Punctuation::PathSeparator)
                });
        if nested.is_empty() {
            if payload
                && let Some(name) = direct_identifier(tree, pattern)?
                && bindings.contains_key(&name)
            {
                payload_bindings.insert(name);
            }
        } else {
            work.extend(nested.into_iter().map(|nested| (nested, payload)));
        }
    }
    Ok(payload_bindings)
}

fn with_shared_receiver_payload_roots<T>(
    context: &BodyContext,
    payload_roots: BTreeSet<Arc<str>>,
    check: impl FnOnce() -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    let previous = context.shared_receiver_value_roots.replace(BTreeSet::new());
    let mut scoped = previous.clone();
    scoped.extend(payload_roots);
    context.shared_receiver_value_roots.replace(scoped);
    let result = check();
    context.shared_receiver_value_roots.replace(previous);
    result
}

/// Returns the proved ownership class of one analysed type.
fn ownership_class(ty: &TypeDescriptor, context: &BodyContext) -> Option<OwnershipClass> {
    prove_ownership_class(ty, &context.capability_declarations).ok()
}

/// Returns whether a spawned block may capture an independent copy of one analysed type.
///
/// A type whose eligibility cannot be proven here is an open generic parameter or an unproven
/// declaration shape, so the reference stays admitted: the same conservative reading the
/// ownership predicate uses, and the instantiated body is checked again for its concrete types.
fn task_capture_eligible(ty: &TypeDescriptor, context: &BodyContext) -> bool {
    match prove_transfer_eligibility(ty, &context.capability_declarations) {
        Ok(eligibility) => eligibility == TransferEligibility::IsolatedTaskCapture,
        Err(_) => true,
    }
}

/// Returns whether the type's ownership class requires the move ledger to account for uses.
fn requires_consumption(ty: &TypeDescriptor, context: &BodyContext) -> bool {
    ownership_class(ty, context).is_some_and(OwnershipClass::requires_consumption)
}

/// Returns whether the type's ownership class prohibits silent copying and discard.
fn is_must_consume_type(ty: &TypeDescriptor, context: &BodyContext) -> bool {
    ownership_class(ty, context) == Some(OwnershipClass::MustConsume)
}

/// Returns the atomic `MustConsume` places one binding value holds.
///
/// A `must_consume struct` declaration is atomic: its whole value is the obligation, so consuming
/// one of its stored values does not discharge it. An aggregate that only inherits the class from a
/// stored member decomposes into that member's places, so consuming every part discharges it while
/// consuming one part leaves the rest owing. A type whose members cannot be enumerated stays
/// atomic, which is the conservative reading.
fn obligation_places(ty: &TypeDescriptor, context: &BodyContext) -> BTreeSet<Vec<Arc<str>>> {
    let mut places = BTreeSet::new();
    collect_obligation_places(ty, &mut Vec::new(), context, &mut places);
    if places.is_empty() {
        places.insert(Vec::new());
    }
    places
}

fn collect_obligation_places(
    ty: &TypeDescriptor,
    path: &mut Vec<Arc<str>>,
    context: &BodyContext,
    places: &mut BTreeSet<Vec<Arc<str>>>,
) {
    if !is_must_consume_type(ty, context) {
        return;
    }
    if is_declared_must_consume(ty, context) {
        places.insert(path.clone());
        return;
    }
    let Some(fields) = struct_fields_for_descriptor(context, ty).ok().flatten() else {
        places.insert(path.clone());
        return;
    };
    let mut decomposed = false;
    for (name, field) in fields {
        if !is_must_consume_type(&field, context) {
            continue;
        }
        decomposed = true;
        path.push(name);
        collect_obligation_places(&field, path, context, places);
        path.pop();
    }
    if !decomposed {
        places.insert(path.clone());
    }
}

/// Returns whether one type declares the `must_consume` modifier itself.
fn is_declared_must_consume(ty: &TypeDescriptor, context: &BodyContext) -> bool {
    ty.declared_path()
        .and_then(|path| context.capability_declarations.get(path.as_str()))
        .is_some_and(|declaration| declaration.is_must_consume())
}

/// Returns whether one obligation leaf is covered by a place of a marked set.
///
/// A leaf is covered when the set holds a place that contains it: transferring a place moves every
/// place inside it, so the leaf's value is gone with the containing place.
fn obligation_leaf_marked(
    marked: &BTreeSet<AffinePlace>,
    root: &Arc<str>,
    leaf: &[Arc<str>],
) -> bool {
    marked
        .iter()
        .any(|place| place.root == *root && leaf.starts_with(&place.path))
}

/// Returns whether one obligation leaf holds a value an admitted assignment re-initialized.
///
/// The leaf is fresh for the place the assignment named, for every place inside it, and for the
/// place that contains it: a declared aggregate stays one atomic obligation, so re-initializing a
/// stored value inside it leaves a value that owes its own consumption.
fn obligation_leaf_refreshed(
    refreshed: &BTreeSet<AffinePlace>,
    root: &Arc<str>,
    leaf: &[Arc<str>],
) -> bool {
    refreshed.iter().any(|place| {
        place.root == *root && (leaf.starts_with(&place.path) || place.path.starts_with(leaf))
    })
}

/// Returns whether one assignment target still holds an initialized `MustConsume` value.
///
/// The answer is judged per obligation place: a target that contains, or is contained in, a place
/// that still holds a value would discard it, while a sibling place that owes nothing stays
/// replaceable. Coverage by a consumed place is the proof that the value is already gone, unless an
/// earlier admitted assignment re-initialized the place on a reaching path.
fn obligation_place_is_live(place: &AffinePlace, context: &BodyContext) -> bool {
    let Some(binding) = context
        .must_consume_obligations
        .borrow()
        .get(&place.root)
        .cloned()
    else {
        return false;
    };
    let places = obligation_places(&binding.ty, context);
    let discharged = context.must_consume_discharged.borrow();
    let fresh = context.must_consume_fresh.borrow();
    places.iter().any(|leaf| {
        let leaf = AffinePlace::projected(place.root.clone(), leaf.clone());
        leaf.intersects(place)
            && (!obligation_leaf_marked(&discharged, &place.root, &leaf.path)
                || obligation_leaf_refreshed(&fresh, &place.root, &leaf.path))
    })
}

/// Returns the places of one root inside a consumed-place set.
fn obligation_places_for_root(
    root: &Arc<str>,
    places: &BTreeSet<AffinePlace>,
) -> BTreeSet<AffinePlace> {
    places
        .iter()
        .filter(|place| place.root == *root)
        .cloned()
        .collect()
}

/// Access kind recorded for one non-copyable place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AffineAccess {
    /// The place is read rather than moved.
    ///
    /// `AffineDroppable` admits one read; `MustConsume` records it as an unaccounted copy.
    Read,
    /// The place is moved out by an `owned self` admission.
    Consume,
}

/// Proved consumption state of one `MustConsume` obligation root.
///
/// The analyzer folds the state of every reaching path into one of three states, so a guard clause
/// may discharge a value on an early exit and a joining statement may still consume it without a
/// false path-dependence report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObligationState {
    /// No reaching path consumed the place.
    Live,
    /// Some reaching paths consumed the place and some did not.
    Partial,
    /// Every reaching path consumed the place.
    Discharged,
}

/// One binding root's obligation: where the value was bound and the type whose `MustConsume`
/// places it holds.
#[derive(Clone, Debug)]
struct MustConsumeBinding {
    span: SourceSpan,
    ty: TypeDescriptor,
}

/// The obligation state one root had before a block rebound its name.
#[derive(Clone, Debug)]
struct MustConsumePrior {
    binding: MustConsumeBinding,
    discharged: BTreeSet<AffinePlace>,
    partial: BTreeSet<AffinePlace>,
    fresh: BTreeSet<AffinePlace>,
    fresh_all: BTreeSet<AffinePlace>,
}

/// The consumption state of every obligation place at one region boundary.
#[derive(Clone, Debug, Default)]
struct ObligationSnapshot {
    /// Binding of every obligation root in scope at the boundary.
    obligations: BTreeMap<Arc<str>, MustConsumeBinding>,
    /// Places consumed on some but not all reaching paths.
    partial: BTreeSet<AffinePlace>,
    /// Places consumed on every reaching path.
    discharged: BTreeSet<AffinePlace>,
    /// Places an admitted assignment re-initialized on some reaching path.
    fresh: BTreeSet<AffinePlace>,
    /// Places an admitted assignment re-initialized on every reaching path.
    fresh_all: BTreeSet<AffinePlace>,
}

impl ObligationSnapshot {
    /// Captures the current consumption state of every obligation root.
    fn capture(context: &BodyContext) -> Self {
        Self {
            obligations: context.must_consume_obligations.borrow().clone(),
            partial: context.must_consume_partial.borrow().clone(),
            discharged: context.must_consume_discharged.borrow().clone(),
            fresh: context.must_consume_fresh.borrow().clone(),
            fresh_all: context.must_consume_fresh_all.borrow().clone(),
        }
    }

    /// Makes this captured state the current consumption state.
    fn restore(&self, context: &BodyContext) {
        context
            .must_consume_obligations
            .borrow_mut()
            .clone_from(&self.obligations);
        context
            .must_consume_partial
            .borrow_mut()
            .clone_from(&self.partial);
        context
            .must_consume_discharged
            .borrow_mut()
            .clone_from(&self.discharged);
        context
            .must_consume_fresh
            .borrow_mut()
            .clone_from(&self.fresh);
        context
            .must_consume_fresh_all
            .borrow_mut()
            .clone_from(&self.fresh_all);
    }

    /// Returns the proved state of one root, or `None` when the root owes nothing.
    ///
    /// The state folds every `MustConsume` place the binding holds: the root is discharged only
    /// when every place is consumed on every reaching path and no admitted assignment re-initialized
    /// one, live when some place holds a value on every reaching path, and path-dependent otherwise.
    fn state(&self, root: &Arc<str>, context: &BodyContext) -> Option<ObligationState> {
        let binding = self.obligations.get(root)?;
        let places = obligation_places(&binding.ty, context);
        if places.iter().all(|leaf| {
            obligation_leaf_marked(&self.discharged, root, leaf)
                && !obligation_leaf_refreshed(&self.fresh, root, leaf)
        }) {
            return Some(ObligationState::Discharged);
        }
        Some(
            if places.iter().any(|leaf| {
                (!obligation_leaf_marked(&self.discharged, root, leaf)
                    && !obligation_leaf_marked(&self.partial, root, leaf))
                    || obligation_leaf_refreshed(&self.fresh_all, root, leaf)
            }) {
                ObligationState::Live
            } else {
                ObligationState::Partial
            },
        )
    }
}

/// One lexical block's `MustConsume` binding bookkeeping.
///
/// Obligations are keyed by binding root, so a block that rebinds an outer root has to remember the
/// outer state and restore it when the block ends.
#[derive(Clone, Debug, Default)]
struct MustConsumeScope {
    /// Roots whose binding was introduced inside this block.
    introduced: BTreeSet<Arc<str>>,
    /// The state each root had before this block first rebound its name.
    shadowed: BTreeMap<Arc<str>, Option<MustConsumePrior>>,
}

/// Records that one root owes a fresh consumption of a `MustConsume` value.
///
/// Every binding introduction of a `MustConsume` value owes consumption: parameters, `let`
/// declarations including pattern bindings, and pattern payloads. Rebinding a root drops any stale
/// discharge and starts a fresh obligation, so a reassigned or shadowed value is never silently
/// accounted for by an earlier consumption.
fn register_must_consume_binding(
    name: Arc<str>,
    ty: &TypeDescriptor,
    span: SourceSpan,
    context: &BodyContext,
) {
    if !is_must_consume_type(ty, context) {
        return;
    }
    record_shadowed_binding(name.clone(), context);
    rebind_must_consume(
        &name,
        MustConsumeBinding {
            span,
            ty: ty.clone(),
        },
        context,
    );
}

/// Remembers the obligation state one root had before the current block rebound its name.
fn record_shadowed_binding(name: Arc<str>, context: &BodyContext) {
    let binding = context
        .must_consume_obligations
        .borrow()
        .get(&name)
        .cloned();
    let previous = binding.map(|binding| MustConsumePrior {
        binding,
        discharged: obligation_places_for_root(&name, &context.must_consume_discharged.borrow()),
        partial: obligation_places_for_root(&name, &context.must_consume_partial.borrow()),
        fresh: obligation_places_for_root(&name, &context.must_consume_fresh.borrow()),
        fresh_all: obligation_places_for_root(&name, &context.must_consume_fresh_all.borrow()),
    });
    let mut scopes = context.must_consume_scopes.borrow_mut();
    let Some(scope) = scopes.last_mut() else {
        return;
    };
    if !scope.introduced.insert(name.clone()) {
        return;
    }
    scope.shadowed.insert(name, previous);
}

/// Marks one place as consumed on this reaching path.
fn discharge_must_consume(place: &AffinePlace, context: &BodyContext) {
    let contained = |candidate: &AffinePlace| {
        candidate.root == place.root && candidate.path.starts_with(&place.path)
    };
    context
        .must_consume_fresh
        .borrow_mut()
        .retain(|candidate| !contained(candidate));
    context
        .must_consume_fresh_all
        .borrow_mut()
        .retain(|candidate| !contained(candidate));
    context
        .must_consume_discharged
        .borrow_mut()
        .insert(place.clone());
}

/// Binds a fresh obligation for one root, dropping every stale discharge.
fn rebind_must_consume(root: &Arc<str>, binding: MustConsumeBinding, context: &BodyContext) {
    context
        .must_consume_obligations
        .borrow_mut()
        .insert(root.clone(), binding);
    context
        .must_consume_discharged
        .borrow_mut()
        .retain(|place| place.root != *root);
    context
        .must_consume_partial
        .borrow_mut()
        .retain(|place| place.root != *root);
    context
        .must_consume_fresh
        .borrow_mut()
        .retain(|place| place.root != *root);
    context
        .must_consume_fresh_all
        .borrow_mut()
        .retain(|place| place.root != *root);
}

/// Records that one admitted assignment re-initialized its target place.
///
/// Assignment to a place whose value is already gone re-initializes exactly that place and the
/// places contained in it, so the fresh value owes its own consumption under `GNT-6.2d`, while a
/// containing place that was already consumed stays gone. The stored place is the target itself:
/// every place inside it holds a fresh value, a read of the containing place stays a read of what
/// the containing transfer moved, and a later assignment inside the target is judged against the
/// fresh value it would discard.
fn reinitialize_must_consume_place(place: &AffinePlace, context: &BodyContext) {
    let contained = |candidate: &AffinePlace| {
        candidate.root == place.root && candidate.path.starts_with(&place.path)
    };
    context
        .must_consume_discharged
        .borrow_mut()
        .retain(|candidate| !contained(candidate));
    context
        .must_consume_partial
        .borrow_mut()
        .retain(|candidate| !contained(candidate));
    context
        .must_consume_fresh
        .borrow_mut()
        .retain(|candidate| !contained(candidate));
    context
        .must_consume_fresh_all
        .borrow_mut()
        .retain(|candidate| !contained(candidate));
    context
        .must_consume_fresh
        .borrow_mut()
        .insert(place.clone());
    context
        .must_consume_fresh_all
        .borrow_mut()
        .insert(place.clone());
}

/// Enters one lexical block for `MustConsume` binding bookkeeping.
fn enter_obligation_scope(context: &BodyContext) {
    context
        .must_consume_scopes
        .borrow_mut()
        .push(MustConsumeScope::default());
}

/// Binds pattern payload obligations inside one lexical scope, so the scope exit retires them.
fn enter_obligation_bindings(
    context: &BodyContext,
    bindings: &BTreeMap<Arc<str>, TypeDescriptor>,
    span: &SourceSpan,
) {
    enter_obligation_scope(context);
    for (name, ty) in bindings {
        register_must_consume_binding(name.clone(), ty, span.clone(), context);
    }
}

/// Reports and retires the obligations one block introduced, restoring any shadowed outer state.
fn leave_obligation_scope(
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let Some(scope) = context.must_consume_scopes.borrow_mut().pop() else {
        return Ok(());
    };
    let current = ObligationSnapshot::capture(context);
    for root in &scope.introduced {
        let Some(binding) = current.obligations.get(root) else {
            continue;
        };
        report_open_obligation(
            root,
            &binding.span,
            current.state(root, context),
            "a MustConsume value is not consumed before its scope ends",
            diagnostics,
        )?;
    }
    for (root, previous) in &scope.shadowed {
        context.must_consume_obligations.borrow_mut().remove(root);
        context
            .must_consume_discharged
            .borrow_mut()
            .retain(|place| place.root != *root);
        context
            .must_consume_partial
            .borrow_mut()
            .retain(|place| place.root != *root);
        context
            .must_consume_fresh
            .borrow_mut()
            .retain(|place| place.root != *root);
        context
            .must_consume_fresh_all
            .borrow_mut()
            .retain(|place| place.root != *root);
        let Some(previous) = previous else {
            continue;
        };
        context
            .must_consume_obligations
            .borrow_mut()
            .insert(root.clone(), previous.binding.clone());
        context
            .must_consume_discharged
            .borrow_mut()
            .extend(previous.discharged.iter().cloned());
        context
            .must_consume_partial
            .borrow_mut()
            .extend(previous.partial.iter().cloned());
        context
            .must_consume_fresh
            .borrow_mut()
            .extend(previous.fresh.iter().cloned());
        context
            .must_consume_fresh_all
            .borrow_mut()
            .extend(previous.fresh_all.iter().cloned());
    }
    Ok(())
}

/// Leaves every block scope opened inside the innermost loop, as `break` and `continue` do.
fn leave_loop_obligation_scopes(
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let Some(depth) = context.must_consume_loop_depths.borrow().last().copied() else {
        return Ok(());
    };
    while context.must_consume_scopes.borrow().len() > depth {
        leave_obligation_scope(context, diagnostics)?;
    }
    Ok(())
}

/// Reports one obligation that still owes consumption at a region exit.
fn report_open_obligation(
    root: &Arc<str>,
    span: &SourceSpan,
    state: Option<ObligationState>,
    reason: &'static str,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    match state {
        Some(ObligationState::Live) => diagnostics.push(body_diagnostic(
            "must-consume-unconsumed",
            DiagnosticCategory::Type,
            reason,
            span.clone(),
            [("binding", root.as_ref())],
        )?),
        Some(ObligationState::Partial) => diagnostics.push(body_diagnostic(
            "must-consume-path-dependent",
            DiagnosticCategory::Type,
            "a MustConsume value is consumed on only some paths",
            span.clone(),
            [("binding", root.as_ref())],
        )?),
        Some(ObligationState::Discharged) | None => {}
    }
    Ok(())
}

/// Reports every obligation that still owes consumption at a region exit.
fn report_open_obligations(
    snapshot: &ObligationSnapshot,
    reason: &'static str,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for (root, binding) in &snapshot.obligations {
        report_open_obligation(
            root,
            &binding.span,
            snapshot.state(root, context),
            reason,
            diagnostics,
        )?;
    }
    Ok(())
}

/// Folds the consumption states of every analysed path into one state and installs it.
///
/// A root stays discharged only when every reaching path discharged it, becomes partial when some
/// paths discharged it and some did not, and stays live when none did. A root that one path never
/// bound counts as live, which keeps the fold conservative and defers the report to a region exit
/// where a path still lacks the discharge.
fn merge_obligation_states(
    saved: &ObligationSnapshot,
    branches: &[ObligationSnapshot],
    include_fallthrough: bool,
    context: &BodyContext,
) {
    let reaching = branches
        .iter()
        .chain(include_fallthrough.then_some(saved))
        .cloned()
        .collect::<Vec<_>>();
    let mut merged = saved.clone();
    merged.partial.clear();
    merged.discharged.clear();
    merged.fresh.clear();
    merged.fresh_all.clear();
    // A place one reaching path re-initialized is fresh at the join, and a place every reaching
    // path re-initialized is fresh on every path; the pre-conditional state contributes only as a
    // reaching path.
    merged.fresh.extend(
        reaching
            .iter()
            .flat_map(|branch| branch.fresh.iter().cloned()),
    );
    if let Some((first, rest)) = reaching.split_first() {
        merged.fresh_all = first.fresh_all.clone();
        for branch in rest {
            merged
                .fresh_all
                .retain(|place| branch.fresh_all.contains(place));
        }
    }
    for root in saved.obligations.keys() {
        let Some(binding) = saved.obligations.get(root) else {
            continue;
        };
        for leaf in obligation_places(&binding.ty, context) {
            let place = AffinePlace::projected(root.clone(), leaf);
            let mut discharged_everywhere = true;
            let mut consumed_somewhere = false;
            let mut reaching_count = 0_usize;
            for branch in &reaching {
                reaching_count = reaching_count.saturating_add(1);
                if branch
                    .discharged
                    .iter()
                    .any(|marked| marked.root == *root && place.path.starts_with(&marked.path))
                {
                    consumed_somewhere = true;
                    continue;
                }
                discharged_everywhere = false;
                if branch
                    .partial
                    .iter()
                    .any(|marked| marked.root == *root && place.path.starts_with(&marked.path))
                {
                    consumed_somewhere = true;
                }
            }
            // No path reaches this join, so nothing can be left owing on one: every exiting
            // branch reported its own obligation, and the fold is vacuous rather than live.
            if reaching_count == 0 {
                merged
                    .discharged
                    .insert(AffinePlace::root_only(root.clone()));
                continue;
            }
            if discharged_everywhere {
                merged.discharged.insert(place);
            } else if consumed_somewhere {
                merged.partial.insert(place);
            }
        }
    }
    merged.restore(context);
}

/// Runs one loop body with the outer binding roots visible for repeated-execution checks.
fn with_affine_loop_scope<T>(
    context: &BodyContext,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    check: impl FnOnce() -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    let entry_roots = environment.keys().cloned().collect::<BTreeSet<_>>();
    context
        .affine_loop_entry_roots
        .borrow_mut()
        .push(entry_roots);
    let result = check();
    context.affine_loop_entry_roots.borrow_mut().pop();
    result
}

/// Reports consumption and re-initialization that only a loop iteration could perform and restores
/// the outer state.
///
/// A loop body may execute zero or many times, so a discharge recorded inside it is never a
/// callable-wide discharge: the obligation stays live and the consumption is path-dependent. A
/// place an iteration re-initialized is path-dependent in the same way, because the fresh value may
/// never be consumed when the body does not run.
fn report_loop_consumption(
    entry: &ObligationSnapshot,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let after = context.must_consume_discharged.borrow().clone();
    let after_fresh = context.must_consume_fresh.borrow().clone();
    let mut reported = BTreeSet::new();
    for place in after.difference(&entry.discharged) {
        // A place the entry already left gone belongs to a value an iteration re-initialized, not
        // to an outer obligation the loop consumed.
        if entry
            .discharged
            .iter()
            .any(|marked| marked.root == place.root && place.path.starts_with(&marked.path))
        {
            continue;
        }
        if !reported.insert(place.root.clone()) {
            continue;
        }
        let Some(binding) = entry.obligations.get(&place.root) else {
            continue;
        };
        diagnostics.push(body_diagnostic(
            "must-consume-path-dependent",
            DiagnosticCategory::Type,
            "a MustConsume value is consumed inside a loop that may not execute",
            binding.span.clone(),
            [("binding", place.root.as_ref())],
        )?);
    }
    for place in after_fresh.difference(&entry.fresh) {
        if !reported.insert(place.root.clone()) {
            continue;
        }
        let Some(binding) = entry.obligations.get(&place.root) else {
            continue;
        };
        diagnostics.push(body_diagnostic(
            "must-consume-path-dependent",
            DiagnosticCategory::Type,
            "a MustConsume value is re-initialized inside a loop that may not execute",
            binding.span.clone(),
            [("binding", place.root.as_ref())],
        )?);
    }
    // A loop body may run zero times, so nothing inside it settles an outer obligation.
    let mut restored = entry.clone();
    restored.obligations = context.must_consume_obligations.borrow().clone();
    restored.restore(context);
    Ok(())
}

/// Records one affine read or move place, rejecting any intersecting or repeated use.
fn record_affine_place(
    place: AffinePlace,
    root_type: Option<&TypeDescriptor>,
    place_type: &TypeDescriptor,
    span: SourceSpan,
    access: AffineAccess,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let place_class = ownership_class(place_type, context);
    let root_class = root_type.and_then(|root| ownership_class(root, context));
    let tracked = place_class.is_some_and(OwnershipClass::requires_consumption)
        || root_class.is_some_and(OwnershipClass::requires_consumption);
    if !tracked {
        return Ok(());
    }
    let must_consume = place_class == Some(OwnershipClass::MustConsume)
        || root_class == Some(OwnershipClass::MustConsume);
    // A `return` hands one `MustConsume` place back to the caller rather than copying it. Only a
    // read of the value itself is that transfer: reading a `Copyable` member inside such a value
    // stays a copy, which item 2d rejects.
    let access = match access {
        AffineAccess::Read
            if place_class == Some(OwnershipClass::MustConsume)
                && context.must_consume_consuming.take() =>
        {
            AffineAccess::Consume
        }
        access => access,
    };
    let repeats_in_loop = context
        .affine_loop_entry_roots
        .borrow()
        .last()
        .is_some_and(|roots| roots.contains(&place.root));
    // A `MustConsume` discharge is root-scoped and branch-scoped, so consuming one place in two
    // exclusive branches is not a reuse. The `AffineDroppable` ledger stays path-insensitive. A
    // place every reaching path re-initialized holds a fresh value, so an earlier discharge does
    // not make a use of it repeated.
    let intersects = if must_consume {
        let discharged = context.must_consume_discharged.borrow();
        let partial = context.must_consume_partial.borrow();
        let fresh = context.must_consume_fresh_all.borrow();
        discharged.iter().chain(partial.iter()).any(|consumed| {
            consumed.intersects(&place)
                && !fresh.iter().any(|refreshed| {
                    refreshed.root == place.root && place.path.starts_with(&refreshed.path)
                })
        })
    } else {
        context
            .affine_consumed
            .borrow()
            .iter()
            .any(|consumed| consumed.intersects(&place))
    };
    // The receiver of one consuming callable is the value this admission already consumed, so
    // reading it inside that callable is neither an unaccounted copy nor a reuse.
    let receiver_read =
        must_consume && context.must_consume_receiver.get() && place.root.as_ref() == "self";
    if !receiver_read && (repeats_in_loop || intersects) {
        diagnostics.push(body_diagnostic(
            "affine-value-reuse",
            DiagnosticCategory::Type,
            if must_consume {
                "a MustConsume value is used more than once"
            } else {
                "an AffineDroppable value is used more than once"
            },
            span.clone(),
            [] as [(&str, &str); 0],
        )?);
    } else if must_consume && access == AffineAccess::Read && !receiver_read {
        let discarding = context.must_consume_discarding.get();
        diagnostics.push(body_diagnostic(
            if discarding {
                "must-consume-discard"
            } else {
                "must-consume-copy"
            },
            DiagnosticCategory::Type,
            if discarding {
                "a MustConsume value requires consumption rather than discard"
            } else {
                "a MustConsume place is copied; only an `owned self` admission consumes it"
            },
            span,
            [] as [(&str, &str); 0],
        )?);
    }
    if must_consume && access == AffineAccess::Consume {
        discharge_must_consume(&place, context);
    }
    context.affine_consumed.borrow_mut().insert(place);
    Ok(())
}

fn record_affine_read(
    name: Arc<str>,
    ty: &TypeDescriptor,
    span: SourceSpan,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    record_affine_place(
        AffinePlace::root_only(name),
        Some(ty),
        ty,
        span,
        AffineAccess::Read,
        context,
        diagnostics,
    )
}

fn owned_receiver_place(
    tree: &SyntaxTree,
    receiver_children: &[NodeId],
) -> Option<(Arc<str>, Vec<Arc<str>>)> {
    if let Some((root, fields)) = postfix_field_sequence(tree, receiver_children) {
        return Some((root, fields.into_iter().map(|(field, _)| field).collect()));
    }
    for child in receiver_children {
        let node = tree.node(*child)?;
        if matches!(node.form(), SyntaxForm::Path)
            && let Ok(Some(name)) = direct_identifier(tree, *child)
        {
            return Some((name, Vec::new()));
        }
    }
    None
}

fn check_owned_move_receiver(
    tree: &SyntaxTree,
    receiver_children: &[NodeId],
    receiver_type: &TypeDescriptor,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    span: SourceSpan,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if !requires_consumption(receiver_type, context) {
        return Ok(());
    }
    let Some((root, fields)) = owned_receiver_place(tree, receiver_children) else {
        // A bare `self` receiver arrives as a reserved word rather than a path node, and re-admitting
        // it inside the consuming callable still escapes the obligation this frame owes.
        if is_must_consume_type(receiver_type, context)
            && context.must_consume_receiver.get()
            && receiver_children
                .iter()
                .any(|child| expression_is_receiver_root(tree, *child))
        {
            diagnostics.push(body_diagnostic(
                "must-consume-escape",
                DiagnosticCategory::Type,
                "an `owned self` MustConsume receiver is re-admitted inside the consuming callable",
                span,
                [] as [(&str, &str); 0],
            )?);
        }
        return Ok(());
    };
    if is_must_consume_type(receiver_type, context)
        && context.must_consume_receiver.get()
        && root.as_ref() == "self"
        && fields.is_empty()
    {
        diagnostics.push(body_diagnostic(
            "must-consume-escape",
            DiagnosticCategory::Type,
            "an `owned self` MustConsume receiver is re-admitted inside the consuming callable",
            span.clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    record_affine_place(
        AffinePlace::projected(root.clone(), fields),
        environment.get(&root),
        receiver_type,
        span,
        AffineAccess::Consume,
        context,
        diagnostics,
    )
}

fn validate_pattern_shape(
    tree: &SyntaxTree,
    pattern: NodeId,
    ty: &TypeDescriptor,
    allow_refutable: bool,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<bool, AnalysisError> {
    let mut compatible = true;
    let mut work = vec![(pattern, ty.clone())];
    while let Some((pattern, current_type)) = work.pop() {
        let node = tree.node(pattern).ok_or(AnalysisError::Invariant)?;
        let nested = node
            .children()
            .iter()
            .copied()
            .filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
            })
            .collect::<Vec<_>>();
        let word = direct_reserved_word(tree, node);
        let members = current_type.immediate_members();
        let valid = match word.as_deref() {
            Some("Some") if allow_refutable && current_type.kind() == TypeKind::Option => {
                if let (Some(nested), Some(member)) = (nested.first(), members.first()) {
                    work.push((*nested, member.clone()));
                }
                true
            }
            Some("None") => allow_refutable && current_type.kind() == TypeKind::Option,
            Some("Ok" | "Err") if allow_refutable && current_type.kind() == TypeKind::Result => {
                let member = if word.as_deref() == Some("Ok") {
                    members.first()
                } else {
                    members.get(1)
                };
                if let (Some(nested), Some(member)) = (nested.first(), member) {
                    work.push((*nested, member.clone()));
                }
                true
            }
            Some("OperationError") => {
                allow_refutable && current_type.kind() == TypeKind::OperationError
            }
            Some(_) => false,
            None if !nested.is_empty() => {
                if current_type.kind() == TypeKind::Tuple && nested.len() == members.len() {
                    work.extend(nested.into_iter().zip(members).rev());
                    true
                } else if allow_refutable
                    && current_type.kind() == TypeKind::Declared
                    && let Some(shape) = enum_shape_for_descriptor(context, &current_type)?
                    && let Some(variant) = direct_identifiers(tree, pattern)?.last()
                    && let Some(Some(payload)) = shape.variants.get(variant)
                    && let Some(nested) = nested.first()
                {
                    work.push((*nested, payload.clone()));
                    true
                } else {
                    false
                }
            }
            None => {
                let qualified = node.children().iter().copied().any(|child| {
                    node_contains_punctuation(tree, child, Punctuation::PathSeparator)
                });
                !qualified
                    || (allow_refutable
                        && current_type.kind() == TypeKind::Declared
                        && enum_shape_for_descriptor(context, &current_type)?.is_some())
            }
        };
        if !valid {
            compatible = false;
            diagnostics.push(body_diagnostic(
                "incompatible-pattern",
                DiagnosticCategory::Type,
                "a pattern shape is incompatible with its matched type",
                node.span().clone(),
                [("type", current_type.canonical_string())],
            )?);
        }
    }
    Ok(compatible)
}

fn direct_reserved_word(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<String> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => Some(word.spelling().to_owned()),
            _ => None,
        })
}

fn node_has_reserved_word(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    expected: &str,
) -> bool {
    node.children().iter().filter_map(|child| tree.node(*child)).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == expected)
    })
}

/// Returns whether one expression is exactly the reserved receiver word `self`.
///
/// A projected receiver (`self.field`) is a member read rather than the owned place itself, so any
/// field access inside the expression disqualifies it.
fn expression_is_receiver_root(tree: &SyntaxTree, id: NodeId) -> bool {
    fn walk(tree: &SyntaxTree, id: NodeId, receiver: &mut bool, projected: &mut bool) {
        let Some(node) = tree.node(id) else {
            return;
        };
        match node.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => {
                *receiver |= word.spelling() == "self";
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)) => *projected = true,
            SyntaxForm::Token(_) => {}
            _ => {
                for child in node.children() {
                    walk(tree, *child, receiver, projected);
                }
            }
        }
    }
    let mut receiver = false;
    let mut projected = false;
    walk(tree, id, &mut receiver, &mut projected);
    receiver && !projected
}

/// Returns whether one expression is a whole binding path rather than a projection or a call.
///
/// Only a whole place transfers an ownership obligation to the caller; a projection or a produced
/// value is a copy of one place or of no place at all.
fn expression_is_whole_place(tree: &SyntaxTree, id: NodeId) -> bool {
    fn walk(tree: &SyntaxTree, id: NodeId, identifier: &mut bool, disqualified: &mut bool) {
        let Some(node) = tree.node(id) else {
            return;
        };
        match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(_)) => *identifier = true,
            SyntaxForm::Token(TokenKind::Punctuation(_)) => *disqualified = true,
            SyntaxForm::Token(_) => {}
            _ => {
                for child in node.children() {
                    walk(tree, *child, identifier, disqualified);
                }
            }
        }
    }
    let mut identifier = false;
    let mut disqualified = false;
    walk(tree, id, &mut identifier, &mut disqualified);
    identifier && !disqualified
}

/// Returns whether one expression names a place: a binding root with struct-field projections.
///
/// A `return` operand is a consumption transfer only when it names the `MustConsume` place
/// itself, so a call, index, literal, or operator expression is not one and stays a copy.
fn expression_names_a_place(tree: &SyntaxTree, id: NodeId) -> bool {
    fn walk(tree: &SyntaxTree, id: NodeId, identifier: &mut bool, disqualified: &mut bool) {
        let Some(node) = tree.node(id) else {
            return;
        };
        match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(_)) => *identifier = true,
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)) => {}
            SyntaxForm::Token(TokenKind::Punctuation(_)) => *disqualified = true,
            SyntaxForm::Token(_) => {}
            _ => {
                for child in node.children() {
                    walk(tree, *child, identifier, disqualified);
                }
            }
        }
    }
    let mut identifier = false;
    let mut disqualified = false;
    walk(tree, id, &mut identifier, &mut disqualified);
    identifier && !disqualified
}

fn node_has_identifier(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    expected: &str,
) -> bool {
    node.children().iter().filter_map(|child| tree.node(*child)).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::Identifier(value)) if value.as_ref() == expected)
    })
}

fn method_receiver_type(
    tree: &SyntaxTree,
    method: &gantry_frontend::SyntaxNode,
    context: &BodyContext,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(implementation) = tree.nodes().iter().find(|node| {
        matches!(node.form(), SyntaxForm::ImplDeclaration)
            && span_contains(node.span(), method.span())
    }) else {
        return Ok(None);
    };
    let receiver = implementation_receiver_descriptor(
        tree,
        implementation,
        &context.generic_types,
        &context.references,
        &context.structs,
    )?;
    if receiver.is_some() {
        return Ok(receiver);
    }
    let Some(receiver_node) = direct_child_form(tree, implementation, SyntaxForm::ValueType) else {
        return Ok(None);
    };
    let expression = tree
        .node(receiver_node)
        .and_then(|node| context.generic_types.get(node.span()))
        .ok_or(AnalysisError::Invariant)?;
    context
        .current_type_substitution
        .borrow()
        .as_ref()
        .map(|substitution| {
            substitution
                .apply(expression)
                .map_err(|_| AnalysisError::Invariant)
        })
        .transpose()
}

fn implementation_receiver_descriptor(
    tree: &SyntaxTree,
    implementation: &gantry_frontend::SyntaxNode,
    generic_types: &BTreeMap<SourceSpan, TypeExpression>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    structs: &BTreeMap<SymbolId, StructShape>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    if let Some(receiver) = direct_child_form(tree, implementation, SyntaxForm::ValueType) {
        let receiver = tree.node(receiver).ok_or(AnalysisError::Invariant)?;
        let Some(expression) = generic_types.get(receiver.span()) else {
            return Ok(None);
        };
        return if expression.is_closed() {
            expression
                .to_descriptor(u64::MAX)
                .map(Some)
                .map_err(|_| AnalysisError::Invariant)
        } else {
            Ok(None)
        };
    }
    let path = direct_child_form(tree, implementation, SyntaxForm::Path)
        .ok_or(AnalysisError::Invariant)?;
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let Some(target) = references.get(path_node.span()) else {
        return Ok(None);
    };
    Ok(structs.get(target).map(|shape| shape.descriptor.clone()))
}

fn span_contains(outer: &SourceSpan, inner: &SourceSpan) -> bool {
    outer.source() == inner.source()
        && outer.bytes().start() <= inner.bytes().start()
        && outer.bytes().end() >= inner.bytes().end()
}

fn span_width(span: &SourceSpan) -> u64 {
    span.bytes().end().saturating_sub(span.bytes().start())
}

pub(crate) fn bool_fact(tree: &SyntaxTree, root: NodeId) -> Result<BoolFact, AnalysisError> {
    let mut facts = BTreeMap::<NodeId, BoolFact>::new();
    let mut work = vec![(root, false)];
    while let Some((id, expanded)) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        if !expanded {
            work.push((id, true));
            work.extend(
                node.children()
                    .iter()
                    .rev()
                    .copied()
                    .filter(|child| {
                        tree.node(*child).is_some_and(|child| {
                            matches!(
                                child.form(),
                                SyntaxForm::Expression
                                    | SyntaxForm::UnaryExpression
                                    | SyntaxForm::BinaryExpression
                            )
                        })
                    })
                    .map(|child| (child, false)),
            );
            continue;
        }

        let nested = node
            .children()
            .iter()
            .filter_map(|child| facts.get(child).copied())
            .collect::<Vec<_>>();
        let operator = node
            .children()
            .iter()
            .filter_map(|child| tree.node(*child))
            .find_map(|child| match child.form() {
                SyntaxForm::Token(TokenKind::Punctuation(operator)) => Some(*operator),
                _ => None,
            });
        let literal = node
            .children()
            .iter()
            .filter_map(|child| tree.node(*child))
            .find_map(|child| match child.form() {
                SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "true" => {
                    Some(BoolFact::True)
                }
                SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "false" => {
                    Some(BoolFact::False)
                }
                _ => None,
            });
        let fact = match operator {
            Some(Punctuation::Bang) => {
                nested
                    .first()
                    .copied()
                    .map_or(BoolFact::Unknown, |fact| match fact {
                        BoolFact::True => BoolFact::False,
                        BoolFact::False => BoolFact::True,
                        BoolFact::Unknown => BoolFact::Unknown,
                    })
            }
            Some(Punctuation::AndAnd) if nested.len() == 2 => match (nested[0], nested[1]) {
                (BoolFact::False, _) | (_, BoolFact::False) => BoolFact::False,
                (BoolFact::True, BoolFact::True) => BoolFact::True,
                _ => BoolFact::Unknown,
            },
            Some(Punctuation::OrOr) if nested.len() == 2 => match (nested[0], nested[1]) {
                (BoolFact::True, _) | (_, BoolFact::True) => BoolFact::True,
                (BoolFact::False, BoolFact::False) => BoolFact::False,
                _ => BoolFact::Unknown,
            },
            Some(Punctuation::LeftParenthesis | Punctuation::RightParenthesis) => {
                nested.first().copied().unwrap_or(BoolFact::Unknown)
            }
            Some(_) => BoolFact::Unknown,
            None if nested.len() == 1 => nested[0],
            None if nested.is_empty() => literal.unwrap_or(BoolFact::Unknown),
            None => BoolFact::Unknown,
        };
        facts.insert(id, fact);
    }
    Ok(facts.get(&root).copied().unwrap_or(BoolFact::Unknown))
}

fn infer_expression(
    tree: &SyntaxTree,
    expression: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let inferred = infer_expression_inner(
        tree,
        expression,
        facts,
        environment,
        expected,
        context,
        diagnostics,
    )?;
    if let Some(ty) = &inferred {
        check_inferred_type_depth(ty, context.maximum_constructed_type_depth)?;
        context
            .expression_types
            .borrow_mut()
            .insert(expression, ty.clone());
    }
    Ok(inferred)
}

fn check_inferred_type_depth(
    descriptor: &TypeDescriptor,
    maximum_constructed_type_depth: Option<u64>,
) -> Result<(), AnalysisError> {
    let Some(maximum_constructed_type_depth) = maximum_constructed_type_depth else {
        return Ok(());
    };
    match TypeDescriptor::from_canonical_string_with_depth_limit(
        &descriptor.canonical_string(),
        maximum_constructed_type_depth,
    ) {
        Ok(_) => Ok(()),
        Err(TypeDescriptorError::ConstructedTypeDepth { limit, observed }) => {
            Err(AnalysisError::ResourceLimit {
                error: FrontendResourceLimit {
                    code: FrontendResourceCode::ConstructedTypeDepthLimit,
                    limit,
                    observed: Some(observed),
                },
                diagnostics: Vec::new(),
            })
        }
        Err(_) => Err(AnalysisError::Invariant),
    }
}

fn infer_expression_inner(
    tree: &SyntaxTree,
    expression: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let node = tree.node(expression).ok_or(AnalysisError::Invariant)?;
    if let [left, right] = node.children()
        && node_is_punctuation(tree, *left, Punctuation::LeftParenthesis)
        && node_is_punctuation(tree, *right, Punctuation::RightParenthesis)
    {
        return Ok(Some(TypeDescriptor::UNIT));
    }
    if let Some(join) = node.children().iter().copied().find(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::JoinExpression | SyntaxForm::JoinAllExpression
            )
        })
    }) {
        return infer_join_expression(tree, join, facts, diagnostics);
    }
    if node_has_reserved_word(tree, node, "self") {
        let Some(receiver) = environment.get("self") else {
            diagnostics.push(body_diagnostic(
                "receiver-scope",
                DiagnosticCategory::Type,
                "self is available only inside an inherent method body",
                node.span().clone(),
                [] as [(&str, &str); 0],
            )?);
            return Ok(None);
        };
        if !node
            .children()
            .iter()
            .copied()
            .any(|child| node_contains_punctuation(tree, child, Punctuation::Dot))
        {
            return Ok(Some(receiver.clone()));
        }
    }
    if let Some(operation) = node.children().iter().copied().find(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::PromptExpression
                    | SyntaxForm::DecideExpression
                    | SyntaxForm::ActionExpression
                    | SyntaxForm::AttemptExpression
            )
        })
    }) {
        return infer_operation(tree, operation, facts, environment, context, diagnostics);
    }
    if matches!(node.form(), SyntaxForm::UnaryExpression) {
        return infer_unary_expression(tree, node, facts, environment, context, diagnostics);
    }
    if let Some(unary) = direct_child_form(tree, node, SyntaxForm::UnaryExpression) {
        let unary_node = tree.node(unary).ok_or(AnalysisError::Invariant)?;
        return infer_unary_expression(tree, unary_node, facts, environment, context, diagnostics);
    }
    if let Some(context_expression) = node.children().iter().copied().find(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::WithExpression | SyntaxForm::SessionExpression
            )
        })
    }) {
        let context_node = tree
            .node(context_expression)
            .ok_or(AnalysisError::Invariant)?;
        let body = direct_child_form(tree, context_node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        return Ok(check_block(
            tree,
            body,
            facts,
            environment,
            expected.unwrap_or(&TypeDescriptor::UNIT),
            context,
            diagnostics,
        )?
        .trailing);
    }
    if matches!(node.form(), SyntaxForm::MatchExpression) {
        return infer_match(
            tree,
            expression,
            facts,
            environment,
            expected,
            context,
            diagnostics,
        );
    }
    if node.children().iter().copied().any(|child| {
        tree.node(child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::TupleExpression))
    }) {
        return infer_tuple(
            tree,
            node,
            facts,
            environment,
            expected,
            context,
            diagnostics,
        );
    }
    if let Some(list) = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::ListExpression))
    }) {
        return infer_list(
            tree,
            list,
            facts,
            environment,
            expected,
            context,
            diagnostics,
        );
    }
    if let Some(struct_expression) = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::StructExpression))
    }) {
        let has_member = node
            .children()
            .iter()
            .copied()
            .any(|child| node_contains_punctuation(tree, child, Punctuation::Dot));
        let receiver = infer_struct(
            tree,
            node,
            struct_expression,
            facts,
            environment,
            if has_member { None } else { expected },
            context,
            diagnostics,
        )?;
        if has_member {
            return match receiver {
                Some(receiver) => infer_member_sequence(
                    tree,
                    node.children(),
                    facts,
                    environment,
                    Some(receiver),
                    expected,
                    context,
                    diagnostics,
                ),
                None => Ok(None),
            };
        }
        return Ok(receiver);
    }
    if matches!(
        direct_reserved_word(tree, node).as_deref(),
        Some("Ok" | "Err")
    ) {
        return infer_result_constructor(
            tree,
            node,
            facts,
            environment,
            expected,
            context,
            diagnostics,
        );
    }
    if direct_reserved_word(tree, node).as_deref() == Some("Some") {
        return infer_some(
            tree,
            node,
            facts,
            environment,
            expected,
            context,
            diagnostics,
        );
    }
    if let Some(value) = infer_enum_constructor(
        tree,
        node,
        facts,
        environment,
        expected,
        context,
        diagnostics,
    )? {
        return Ok(Some(value));
    }
    if node.children().iter().copied().any(|child| {
        tree.node(child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::PostfixExpression
                    if node_contains_punctuation(tree, child, Punctuation::LeftBracket)
            )
        })
    }) {
        return infer_projection(tree, node, facts, environment, context, diagnostics);
    }
    if let Some((operator, index)) = direct_binary_operator(tree, node) {
        let left = infer_operand_sequence(
            tree,
            node.children().get(..index).unwrap_or_default(),
            facts,
            environment,
            Some(operator),
            context,
            diagnostics,
        )?;
        let right = infer_operand_sequence(
            tree,
            node.children()
                .get(index.saturating_add(1)..)
                .unwrap_or_default(),
            facts,
            environment,
            Some(operator),
            context,
            diagnostics,
        )?;
        if let (Some(left), Some(right)) = (left, right) {
            return infer_binary_operator(
                operator,
                left,
                right,
                node.span().clone(),
                context,
                diagnostics,
            )
            .map(Some);
        }
        return Ok(None);
    }
    if let Some(value) = infer_member_sequence(
        tree,
        node.children(),
        facts,
        environment,
        None,
        expected,
        context,
        diagnostics,
    )? {
        return Ok(Some(value));
    }
    if let Some(value) = infer_call_sequence(
        tree,
        node.children(),
        facts,
        environment,
        expected,
        context,
        diagnostics,
    )? {
        return Ok(Some(value));
    }
    for child in node.children().iter().copied() {
        let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
        match child_node.form() {
            SyntaxForm::MatchExpression => {
                return infer_match(
                    tree,
                    child,
                    facts,
                    environment,
                    expected,
                    context,
                    diagnostics,
                );
            }
            SyntaxForm::Expression | SyntaxForm::Block => {
                if let Some(value) = infer_expression(
                    tree,
                    child,
                    facts,
                    environment,
                    expected,
                    context,
                    diagnostics,
                )? {
                    return Ok(Some(value));
                }
            }
            SyntaxForm::Path => {
                if let Some(name) = direct_identifier(tree, child)? {
                    if let Some(ty) = environment.get(&name).cloned() {
                        record_affine_read(
                            name,
                            &ty,
                            child_node.span().clone(),
                            context,
                            diagnostics,
                        )?;
                        return Ok(Some(ty));
                    }
                    return Ok(None);
                }
            }
            SyntaxForm::Token(token) => {
                if let Some(value) =
                    token_type(token, child_node.span().clone(), expected, diagnostics)?
                {
                    return Ok(Some(value));
                }
            }
            _ => {}
        }
    }
    let _ = facts;
    Ok(None)
}

fn infer_join_expression(
    tree: &SyntaxTree,
    join: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let node = tree.node(join).ok_or(AnalysisError::Invariant)?;
    let mut blocks = tree
        .nodes()
        .iter()
        .filter(|candidate| {
            matches!(candidate.form(), SyntaxForm::Block)
                && span_contains(candidate.span(), node.span())
        })
        .collect::<Vec<_>>();
    blocks.sort_by_key(|candidate| span_width(candidate.span()));
    if blocks.is_empty() {
        return Err(AnalysisError::Invariant);
    }
    let mut available = BTreeMap::<Arc<str>, TypeDescriptor>::new();
    let mut declaration_order = Vec::<Arc<str>>::new();
    let selected_names = matches!(node.form(), SyntaxForm::JoinExpression)
        .then(|| direct_identifiers(tree, join))
        .transpose()?
        .unwrap_or_default();
    for block in blocks {
        for statement in block.children().iter().copied() {
            let statement_node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
            if statement_node.span().bytes().start() >= node.span().bytes().start()
                || span_contains(statement_node.span(), node.span())
            {
                break;
            }
            if matches!(statement_node.form(), SyntaxForm::SpawnStatement) {
                let name = direct_identifier(tree, statement)?.ok_or(AnalysisError::Invariant)?;
                let result = direct_child_form(tree, statement_node, SyntaxForm::ValueType)
                    .and_then(|type_node| facts.get(&type_node))
                    .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
                declaration_order.push(name.clone());
                available.insert(name, result);
                continue;
            }
            apply_static_task_consumptions(tree, statement, &mut available)?;
        }
        if matches!(node.form(), SyntaxForm::JoinAllExpression)
            || selected_names
                .iter()
                .all(|handle| available.contains_key(handle))
        {
            break;
        }
    }

    let selected = match node.form() {
        SyntaxForm::JoinExpression => selected_names
            .into_iter()
            .filter_map(|handle| available.get(&handle).cloned())
            .collect::<Vec<_>>(),
        SyntaxForm::JoinAllExpression => declaration_order
            .into_iter()
            .filter_map(|handle| available.get(&handle).cloned())
            .collect::<Vec<_>>(),
        _ => return Err(AnalysisError::Invariant),
    };
    join_result_type(selected, node.span().clone(), diagnostics).map(Some)
}

fn apply_static_task_consumptions(
    tree: &SyntaxTree,
    root: NodeId,
    available: &mut BTreeMap<Arc<str>, TypeDescriptor>,
) -> Result<(), AnalysisError> {
    let node = tree.node(root).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::JoinExpression | SyntaxForm::DetachStatement => {
            for consumed in direct_identifiers(tree, root)? {
                available.remove(&consumed);
            }
            return Ok(());
        }
        SyntaxForm::JoinAllExpression => {
            available.clear();
            return Ok(());
        }
        SyntaxForm::SpawnStatement => return Ok(()),
        SyntaxForm::IfStatement => {
            let mut branches = node
                .children()
                .iter()
                .copied()
                .filter(|child| {
                    tree.node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
                })
                .map(|block| {
                    let mut branch = available.clone();
                    apply_static_task_consumptions(tree, block, &mut branch)?;
                    Ok(branch)
                })
                .collect::<Result<Vec<_>, AnalysisError>>()?;
            let has_else = node.children().iter().any(|child| {
                tree.node(*child).is_some_and(|node| {
                    matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "else")
                })
            });
            if !has_else {
                branches.push(available.clone());
            }
            retain_definitely_available(available, &branches);
            return Ok(());
        }
        SyntaxForm::MatchStatement | SyntaxForm::MatchExpression => {
            let mut branches = Vec::new();
            for arm in node.children().iter().copied().filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
            }) {
                let arm_node = tree.node(arm).ok_or(AnalysisError::Invariant)?;
                let mut branch = available.clone();
                for child in arm_node.children().iter().copied().filter(|child| {
                    tree.node(*child).is_some_and(|node| {
                        matches!(node.form(), SyntaxForm::Expression | SyntaxForm::Block)
                    })
                }) {
                    apply_static_task_consumptions(tree, child, &mut branch)?;
                }
                branches.push(branch);
            }
            retain_definitely_available(available, &branches);
            return Ok(());
        }
        SyntaxForm::WithStatement
        | SyntaxForm::SessionStatement
        | SyntaxForm::WithExpression
        | SyntaxForm::SessionExpression => {
            let block =
                direct_child_form(tree, node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
            return apply_static_task_consumptions(tree, block, available);
        }
        SyntaxForm::ForStatement
        | SyntaxForm::LoopStatement
        | SyntaxForm::WhileStatement
        | SyntaxForm::UntilStatement => return Ok(()),
        _ => {}
    }

    for child in node.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| !matches!(node.form(), SyntaxForm::Token(_)))
    }) {
        apply_static_task_consumptions(tree, child, available)?;
    }
    Ok(())
}

fn retain_definitely_available(
    available: &mut BTreeMap<Arc<str>, TypeDescriptor>,
    branches: &[BTreeMap<Arc<str>, TypeDescriptor>],
) {
    if !branches.is_empty() {
        available.retain(|handle, _| branches.iter().all(|branch| branch.contains_key(handle)));
    }
}

fn join_result_type(
    selected: Vec<TypeDescriptor>,
    span: SourceSpan,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<TypeDescriptor, AnalysisError> {
    if selected.is_empty()
        || selected
            .iter()
            .all(|result| *result == TypeDescriptor::UNIT)
    {
        return Ok(TypeDescriptor::UNIT);
    }
    if selected.contains(&TypeDescriptor::UNIT) {
        diagnostics.push(body_diagnostic(
            "mixed-task-results",
            DiagnosticCategory::TaskOwnership,
            "a join mixes Unit and value-producing task results",
            span,
            [] as [(&str, &str); 0],
        )?);
        return Ok(TypeDescriptor::UNIT);
    }
    if selected.len() == 1 {
        return selected.into_iter().next().ok_or(AnalysisError::Invariant);
    }
    if selected.windows(2).all(|pair| pair[0] == pair[1]) {
        return selected
            .into_iter()
            .next()
            .map(TypeDescriptor::list)
            .ok_or(AnalysisError::Invariant);
    }
    TypeDescriptor::tuple(selected).map_err(|_| AnalysisError::Invariant)
}

fn infer_unary_expression(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some((operator_index, operator)) =
        node.children()
            .iter()
            .copied()
            .enumerate()
            .find_map(|(index, child)| match tree.node(child)?.form() {
                SyntaxForm::Token(TokenKind::Punctuation(operator))
                    if matches!(operator, Punctuation::Bang | Punctuation::Minus) =>
                {
                    Some((index, *operator))
                }
                _ => None,
            })
    else {
        return Ok(None);
    };
    let operand = infer_operand_sequence(
        tree,
        node.children()
            .get(operator_index.saturating_add(1)..)
            .unwrap_or_default(),
        facts,
        environment,
        Some(operator),
        context,
        diagnostics,
    )?;
    let Some(operand) = operand else {
        return Ok(None);
    };
    let valid = match operator {
        Punctuation::Bang => operand == TypeDescriptor::BOOL,
        Punctuation::Minus => matches!(operand.kind(), TypeKind::Int | TypeKind::Float),
        _ => false,
    };
    if valid {
        return Ok(Some(operand));
    }
    diagnostics.push(body_diagnostic(
        "invalid-primitive",
        DiagnosticCategory::Type,
        "a deterministic primitive has no signature for its operand type",
        node.span().clone(),
        [
            ("operator", operator.spelling()),
            ("operand", operand.canonical_string().as_str()),
        ],
    )?);
    Ok(Some(operand))
}

fn infer_operation(
    tree: &SyntaxTree,
    operation: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let node = tree.node(operation).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::PromptExpression => {
            infer_model_operation_inputs(tree, node, facts, environment, context, diagnostics)?;
            Ok(Some(
                direct_child_form(tree, node, SyntaxForm::ValueType)
                    .and_then(|type_node| facts.get(&type_node))
                    .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone()),
            ))
        }
        SyntaxForm::DecideExpression => {
            infer_model_operation_inputs(tree, node, facts, environment, context, diagnostics)?;
            Ok(Some(TypeDescriptor::DECISION))
        }
        SyntaxForm::ActionExpression => {
            infer_action_operation(tree, node, facts, environment, context, diagnostics)
        }
        SyntaxForm::AttemptExpression => {
            let nested = node
                .children()
                .iter()
                .copied()
                .find(|child| {
                    tree.node(*child).is_some_and(|node| {
                        matches!(
                            node.form(),
                            SyntaxForm::PromptExpression
                                | SyntaxForm::DecideExpression
                                | SyntaxForm::ActionExpression
                        )
                    })
                })
                .ok_or(AnalysisError::Invariant)?;
            Ok(
                infer_operation(tree, nested, facts, environment, context, diagnostics)?
                    .map(|result| TypeDescriptor::result(result, TypeDescriptor::OPERATION_ERROR)),
            )
        }
        _ => Ok(None),
    }
}

fn infer_model_operation_inputs(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for child in node.children().iter().copied() {
        let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
        if matches!(child_node.form(), SyntaxForm::InterpolationExpression) {
            let _ = infer_expression(tree, child, facts, environment, None, context, diagnostics)?;
            continue;
        }
        if !matches!(child_node.form(), SyntaxForm::UsingClause) {
            continue;
        }
        for input in child_node.children().iter().copied() {
            let input_node = tree.node(input).ok_or(AnalysisError::Invariant)?;
            if !matches!(input_node.form(), SyntaxForm::NamedInput) {
                continue;
            }
            let inferred = if let Some(expression) =
                direct_child_form(tree, input_node, SyntaxForm::Expression)
            {
                infer_expression(
                    tree,
                    expression,
                    facts,
                    environment,
                    None,
                    context,
                    diagnostics,
                )?
            } else {
                direct_identifier(tree, input)?.and_then(|name| environment.get(&name).cloned())
            };
            if let Some(ty) = inferred {
                context.expression_types.borrow_mut().insert(input, ty);
            }
        }
    }
    Ok(())
}

fn infer_action_operation(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let path_id =
        direct_child_form(tree, node, SyntaxForm::Path).ok_or(AnalysisError::Invariant)?;
    let path = tree.node(path_id).ok_or(AnalysisError::Invariant)?;
    let Some(target) = context.references.get(path.span()).copied() else {
        return Ok(None);
    };
    let Some(signature) = context.actions.get(&target) else {
        if context.callables.contains_key(&target) {
            diagnostics.push(body_diagnostic(
                "invalid-action-target",
                DiagnosticCategory::Type,
                "an action invocation resolves to an ordinary workflow",
                path.span().clone(),
                [] as [(&str, &str); 0],
            )?);
        }
        return Ok(None);
    };
    let arguments = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect::<Vec<_>>();
    if arguments.len() != signature.parameters.len() {
        diagnostics.push(body_diagnostic(
            "call-arity",
            DiagnosticCategory::Type,
            "a workflow call has the wrong number of arguments",
            path.span().clone(),
            [
                ("actual", arguments.len().to_string()),
                ("expected", signature.parameters.len().to_string()),
            ],
        )?);
    }
    for (argument, expected) in arguments.iter().zip(&signature.parameters) {
        if let Some(actual) = infer_expression(
            tree,
            *argument,
            facts,
            environment,
            Some(expected),
            context,
            diagnostics,
        )? && &actual != expected
        {
            diagnostics.push(body_diagnostic(
                "call-argument-type",
                DiagnosticCategory::Type,
                "a workflow argument differs from its exact parameter type",
                tree.node(*argument)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [
                    ("actual", actual.canonical_string()),
                    ("expected", expected.canonical_string()),
                ],
            )?);
        }
    }
    Ok(Some(signature.result.clone()))
}

fn infer_tuple(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let expected_members = expected
        .filter(|value| value.kind() == TypeKind::Tuple)
        .map(TypeDescriptor::immediate_members)
        .unwrap_or_default();
    let expressions = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect::<Vec<_>>();
    let mut members = Vec::with_capacity(expressions.len());
    for (index, expression) in expressions.into_iter().enumerate() {
        let member_expected = expected_members.get(index);
        if let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            member_expected,
            context,
            diagnostics,
        )? {
            if let Some(member_expected) = member_expected {
                require_aggregate_member(member_expected, &actual, tree, expression, diagnostics)?;
            }
            members.push(actual);
        }
    }
    if members.len() < 2 {
        return Ok(None);
    }
    TypeDescriptor::tuple(members)
        .map(Some)
        .map_err(|_| AnalysisError::Invariant)
}

fn infer_list(
    tree: &SyntaxTree,
    list: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let node = tree.node(list).ok_or(AnalysisError::Invariant)?;
    let expected_member = expected
        .filter(|value| value.kind() == TypeKind::List)
        .and_then(|value| value.immediate_members().into_iter().next());
    let expressions = node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect::<Vec<_>>();
    if expressions.is_empty() {
        return Ok(expected
            .cloned()
            .filter(|value| value.kind() == TypeKind::List));
    }
    let mut member_type = expected_member;
    for expression in expressions {
        if let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            member_type.as_ref(),
            context,
            diagnostics,
        )? {
            if let Some(expected) = &member_type {
                require_aggregate_member(expected, &actual, tree, expression, diagnostics)?;
            } else {
                member_type = Some(actual);
            }
        }
    }
    Ok(member_type.map(TypeDescriptor::list))
}

fn infer_some(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(option) = expected.filter(|value| value.kind() == TypeKind::Option) else {
        diagnostics.push(body_diagnostic(
            "ambiguous-constructor-type",
            DiagnosticCategory::Type,
            "an Option constructor has no compatible expected type",
            node.span().clone(),
            [("constructor", "Some")],
        )?);
        return Ok(None);
    };
    let member = option
        .immediate_members()
        .into_iter()
        .next()
        .ok_or(AnalysisError::Invariant)?;
    if let Some(expression) = direct_child_form(tree, node, SyntaxForm::Expression)
        && let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            Some(&member),
            context,
            diagnostics,
        )?
    {
        require_aggregate_member(&member, &actual, tree, expression, diagnostics)?;
    }
    Ok(Some(option.clone()))
}

fn infer_result_constructor(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let word = direct_reserved_word(tree, node).ok_or(AnalysisError::Invariant)?;
    let Some(result) = expected.filter(|value| value.kind() == TypeKind::Result) else {
        diagnostics.push(body_diagnostic(
            "ambiguous-constructor-type",
            DiagnosticCategory::Type,
            "a Result constructor has no compatible expected type",
            node.span().clone(),
            [("constructor", word.as_str())],
        )?);
        return Ok(None);
    };
    let members = result.immediate_members();
    let member = match word.as_str() {
        "Ok" => members.first(),
        "Err" => members.get(1),
        _ => None,
    }
    .ok_or(AnalysisError::Invariant)?;
    if let Some(expression) = direct_child_form(tree, node, SyntaxForm::Expression)
        && let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            Some(member),
            context,
            diagnostics,
        )?
    {
        require_aggregate_member(member, &actual, tree, expression, diagnostics)?;
    }
    Ok(Some(result.clone()))
}

fn infer_enum_constructor(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(path) = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Path))
    }) else {
        return Ok(None);
    };
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let Some(target) = context.references.get(path_node.span()).copied() else {
        return Ok(None);
    };
    let mut direct_variant = node.children().iter().filter_map(|child| {
        let child = tree.node(*child)?;
        match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        }
    });
    let path_variant = direct_identifiers(tree, path)?.into_iter().last();
    let Some(variant) = direct_variant.next_back().or(path_variant) else {
        return Ok(None);
    };
    if let Some(template) = context.generic_enums.get(&target) {
        return infer_generic_enum_constructor(
            tree,
            node,
            facts,
            environment,
            expected,
            context,
            diagnostics,
            template,
            &variant,
        );
    }
    let Some(shape) = context.enums.get(&target) else {
        return Ok(None);
    };
    let Some(payload) = shape.variants.get(&variant) else {
        return Ok(None);
    };
    let expression = direct_child_form(tree, node, SyntaxForm::Expression);
    if payload.is_some() != expression.is_some() {
        diagnostics.push(body_diagnostic(
            "invalid-enum-constructor",
            DiagnosticCategory::Type,
            "an enum constructor does not match its variant payload shape",
            node.span().clone(),
            [("variant", variant.as_ref())],
        )?);
    }
    if let (Some(payload), Some(expression)) = (payload, expression)
        && let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            Some(payload),
            context,
            diagnostics,
        )?
    {
        require_aggregate_member(payload, &actual, tree, expression, diagnostics)?;
    }
    Ok(Some(shape.descriptor.clone()))
}

#[allow(clippy::too_many_arguments)]
fn infer_generic_enum_constructor(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    template: &GenericEnumShape,
    variant: &Arc<str>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let explicit = direct_child_form(tree, node, SyntaxForm::TypeArgumentList)
        .map(|list| closed_type_arguments(tree, list, context))
        .transpose()?;
    let descriptor = if let Some(arguments) = explicit {
        if arguments.len() != template.required.len() {
            diagnostics.push(body_diagnostic(
                GenericAnalysisCode::TypeArgumentArity.wire_name(),
                DiagnosticCategory::Type,
                "an enum constructor has the wrong number of explicit type arguments",
                node.span().clone(),
                [
                    ("expected", template.required.len().to_string()),
                    ("observed", arguments.len().to_string()),
                ],
            )?);
            return Ok(None);
        }
        TypeDescriptor::declared_with_arguments(template.path.clone(), arguments)
    } else if let Some(expected) = expected.filter(|candidate| {
        candidate.declared_path() == Some(&template.path)
            && candidate.immediate_members().len() == template.required.len()
    }) {
        expected.clone()
    } else {
        diagnostics.push(body_diagnostic(
            GenericAnalysisCode::IncompleteTypeInference.wire_name(),
            DiagnosticCategory::Type,
            "a generic enum constructor has no complete type substitution",
            node.span().clone(),
            [] as [(&str, &str); 0],
        )?);
        return Ok(None);
    };
    if diagnose_invalid_inferred_option_member(&descriptor, node.span(), context, diagnostics)? {
        return Ok(None);
    }
    let shape = enum_shape_for_descriptor(context, &descriptor)?.ok_or(AnalysisError::Invariant)?;
    let Some(payload) = shape.variants.get(variant) else {
        return Ok(None);
    };
    let expression = direct_child_form(tree, node, SyntaxForm::Expression);
    if payload.is_some() != expression.is_some() {
        diagnostics.push(body_diagnostic(
            "invalid-enum-constructor",
            DiagnosticCategory::Type,
            "an enum constructor does not match its substituted variant payload shape",
            node.span().clone(),
            [("variant", variant.as_ref())],
        )?);
    }
    if let (Some(payload), Some(expression)) = (payload, expression)
        && let Some(actual) = infer_expression(
            tree,
            expression,
            facts,
            environment,
            Some(payload),
            context,
            diagnostics,
        )?
    {
        require_aggregate_member(payload, &actual, tree, expression, diagnostics)?;
    }
    Ok(Some(descriptor))
}

fn closed_type_arguments(
    tree: &SyntaxTree,
    list: NodeId,
    context: &BodyContext,
) -> Result<Vec<TypeDescriptor>, AnalysisError> {
    let list = tree.node(list).ok_or(AnalysisError::Invariant)?;
    list.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter(|node| matches!(node.form(), SyntaxForm::ValueType))
        .map(|node| {
            let expression = context
                .generic_types
                .get(node.span())
                .ok_or(AnalysisError::Invariant)?;
            if expression.is_closed() {
                expression
                    .to_descriptor(u64::MAX)
                    .map_err(|_| AnalysisError::Invariant)
            } else {
                context
                    .current_type_substitution
                    .borrow()
                    .as_ref()
                    .ok_or(AnalysisError::Invariant)?
                    .apply(expression)
                    .map_err(|_| AnalysisError::Invariant)
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn infer_struct(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    struct_expression: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(path) = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Path))
    }) else {
        return Ok(None);
    };
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let Some(target) = context.references.get(path_node.span()).copied() else {
        return Ok(None);
    };
    if let Some(shape) = context.generic_structs.get(&target) {
        return infer_generic_struct(
            tree,
            node,
            struct_expression,
            facts,
            environment,
            expected,
            context,
            diagnostics,
            shape,
        );
    }
    let Some(shape) = context.structs.get(&target) else {
        return Ok(None);
    };
    let constructor = tree
        .node(struct_expression)
        .ok_or(AnalysisError::Invariant)?;
    let mut supplied = BTreeSet::new();
    for initializer in constructor.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::FieldInitializer))
    }) {
        let Some(name) = direct_identifier(tree, initializer)? else {
            return Err(AnalysisError::Invariant);
        };
        if !supplied.insert(name.clone()) {
            diagnostics.push(body_diagnostic(
                "duplicate-struct-field",
                DiagnosticCategory::Type,
                "a struct constructor supplies one field more than once",
                tree.node(initializer)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [("field", name.as_ref())],
            )?);
        }
        let Some(field) = shape.fields.get(&name) else {
            diagnostics.push(body_diagnostic(
                "unknown-struct-field",
                DiagnosticCategory::Type,
                "a struct constructor supplies an unknown field",
                tree.node(initializer)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [("field", name.as_ref())],
            )?);
            continue;
        };
        let expression = direct_child_form(
            tree,
            tree.node(initializer).ok_or(AnalysisError::Invariant)?,
            SyntaxForm::Expression,
        );
        let actual = if let Some(expression) = expression {
            infer_expression(
                tree,
                expression,
                facts,
                environment,
                Some(&field.ty),
                context,
                diagnostics,
            )?
        } else {
            environment.get(&name).cloned()
        };
        if let Some(actual) = actual {
            require_aggregate_member(&field.ty, &actual, tree, initializer, diagnostics)?;
        }
    }
    for (name, field) in &shape.fields {
        if field.required && !supplied.contains(name) {
            diagnostics.push(body_diagnostic(
                "missing-struct-field",
                DiagnosticCategory::Type,
                "a struct constructor omits a required field",
                constructor.span().clone(),
                [("field", name.as_ref())],
            )?);
        }
    }
    Ok(Some(shape.descriptor.clone()))
}

#[allow(clippy::too_many_arguments)]
fn infer_generic_struct(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    struct_expression: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
    shape: &GenericStructShape,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let constructor = tree
        .node(struct_expression)
        .ok_or(AnalysisError::Invariant)?;
    let mut supplied = BTreeSet::new();
    let mut initializers = Vec::new();
    for initializer in constructor.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::FieldInitializer))
    }) {
        let Some(name) = direct_identifier(tree, initializer)? else {
            return Err(AnalysisError::Invariant);
        };
        if !supplied.insert(name.clone()) {
            diagnostics.push(body_diagnostic(
                "duplicate-struct-field",
                DiagnosticCategory::Type,
                "a generic struct constructor supplies one field more than once",
                tree.node(initializer)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [("field", name.as_ref())],
            )?);
        }
        if !shape.fields.contains_key(&name) {
            diagnostics.push(body_diagnostic(
                "unknown-struct-field",
                DiagnosticCategory::Type,
                "a generic struct constructor supplies an unknown field",
                tree.node(initializer)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [("field", name.as_ref())],
            )?);
            continue;
        }
        initializers.push((initializer, name));
    }

    let explicit = direct_child_form(tree, node, SyntaxForm::TypeArgumentList)
        .map(|list| closed_type_arguments(tree, list, context))
        .transpose()?;
    let mut inferred_actuals = BTreeMap::<NodeId, TypeDescriptor>::new();
    let substitution = if let Some(arguments) = explicit {
        ExactTypeSubstitution::explicit(&shape.required, &arguments)
    } else if let Some(expected) = expected.filter(|candidate| {
        candidate.declared_path() == Some(&shape.path)
            && candidate.immediate_members().len() == shape.required.len()
    }) {
        ExactTypeSubstitution::explicit(&shape.required, &expected.immediate_members())
    } else {
        let mut constraints = Vec::new();
        for (initializer, name) in &initializers {
            let field = shape.fields.get(name).ok_or(AnalysisError::Invariant)?;
            let initializer_node = tree.node(*initializer).ok_or(AnalysisError::Invariant)?;
            let actual = if let Some(expression) =
                direct_child_form(tree, initializer_node, SyntaxForm::Expression)
            {
                infer_expression(
                    tree,
                    expression,
                    facts,
                    environment,
                    None,
                    context,
                    diagnostics,
                )?
            } else {
                environment.get(name).cloned()
            };
            if let Some(actual) = actual {
                constraints.push((
                    field.ty.clone(),
                    TypeExpression::closed(&actual, u64::MAX)
                        .map_err(|_| AnalysisError::Invariant)?,
                ));
                inferred_actuals.insert(*initializer, actual);
            }
        }
        ExactTypeSubstitution::infer(&shape.required, &constraints)
    };
    let substitution = match substitution {
        Ok(substitution) => substitution,
        Err(error) => {
            let code = match error {
                TypeInferenceFailure::Arity => GenericAnalysisCode::TypeArgumentArity,
                TypeInferenceFailure::Conflict | TypeInferenceFailure::OccursCheck => {
                    GenericAnalysisCode::ConflictingTypeInference
                }
                TypeInferenceFailure::Incomplete | TypeInferenceFailure::InvalidOptionMember => {
                    GenericAnalysisCode::IncompleteTypeInference
                }
            };
            diagnostics.push(body_diagnostic(
                code.wire_name(),
                DiagnosticCategory::Type,
                "generic struct inference did not produce one complete substitution",
                node.span().clone(),
                [] as [(&str, &str); 0],
            )?);
            return Ok(None);
        }
    };

    for (initializer, name) in &initializers {
        let field = shape.fields.get(name).ok_or(AnalysisError::Invariant)?;
        let Some(expected_field) =
            apply_generic_type_or_diagnose(&substitution, &field.ty, node.span(), diagnostics)?
        else {
            return Ok(None);
        };
        let initializer_node = tree.node(*initializer).ok_or(AnalysisError::Invariant)?;
        let actual = if let Some(actual) = inferred_actuals.get(initializer).cloned() {
            Some(actual)
        } else if let Some(expression) =
            direct_child_form(tree, initializer_node, SyntaxForm::Expression)
        {
            infer_expression(
                tree,
                expression,
                facts,
                environment,
                Some(&expected_field),
                context,
                diagnostics,
            )?
        } else {
            environment.get(name).cloned()
        };
        if let Some(actual) = actual {
            require_aggregate_member(&expected_field, &actual, tree, *initializer, diagnostics)?;
        }
    }
    for (name, field) in &shape.fields {
        if field.required && !supplied.contains(name) {
            diagnostics.push(body_diagnostic(
                "missing-struct-field",
                DiagnosticCategory::Type,
                "a generic struct constructor omits a required field",
                constructor.span().clone(),
                [("field", name.as_ref())],
            )?);
        }
    }

    let application = TypeExpression::declared(
        shape.path.clone(),
        shape
            .required
            .iter()
            .map(|parameter| {
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| AnalysisError::Invariant)
            })
            .collect::<Result<Vec<_>, _>>()?,
        u64::MAX,
    )
    .map_err(|_| AnalysisError::Invariant)?;
    let descriptor = substitution
        .apply(&application)
        .map_err(|_| AnalysisError::Invariant)?;
    if diagnose_invalid_inferred_option_member(&descriptor, node.span(), context, diagnostics)? {
        return Ok(None);
    }
    Ok(Some(descriptor))
}

fn infer_projection(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(path) = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Path))
    }) else {
        return Ok(None);
    };
    let Some(name) = direct_identifier(tree, path)? else {
        return Ok(None);
    };
    let Some(base) = environment.get(&name).cloned() else {
        return Ok(None);
    };
    let index_expression = node.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
    });
    let literal_index = index_expression.and_then(|expression| {
        tree.node(expression)?
            .children()
            .iter()
            .find_map(|token| match tree.node(*token)?.form() {
                SyntaxForm::Token(TokenKind::IntegerLiteral(value)) => value.parse::<usize>().ok(),
                _ => None,
            })
    });
    if base.kind() == TypeKind::Tuple {
        let Some(index) = literal_index else {
            return Ok(None);
        };
        if let Some(member) = base.immediate_members().into_iter().nth(index) {
            diagnose_projected_shared_receiver_place(tree, node, &member, context, diagnostics)?;
            return Ok(Some(member));
        }
        diagnostics.push(body_diagnostic(
            "tuple-index-out-of-range",
            DiagnosticCategory::Type,
            "a tuple projection index is outside its static arity",
            node.span().clone(),
            [("index", index.to_string())],
        )?);
        return Ok(None);
    }
    if base.kind() == TypeKind::List {
        if let Some(index_expression) = index_expression
            && let Some(actual) = infer_expression(
                tree,
                index_expression,
                facts,
                environment,
                Some(&TypeDescriptor::INT),
                context,
                diagnostics,
            )?
            && actual != TypeDescriptor::INT
        {
            diagnostics.push(body_diagnostic(
                "projection-index-type",
                DiagnosticCategory::Type,
                "a list projection index is not Int",
                tree.node(index_expression)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [("actual", actual.canonical_string())],
            )?);
        }
        let projected = base.immediate_members().into_iter().next();
        if let Some(receiver) = &projected {
            diagnose_projected_shared_receiver_place(tree, node, receiver, context, diagnostics)?;
        }
        return Ok(projected);
    }
    Ok(None)
}

fn diagnose_projected_shared_receiver_place(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    receiver: &TypeDescriptor,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if let Some((member, member_id)) = postfix_called_member(tree, node)
        && let Some(metadata) = context
            .inherent_method_sources
            .get(&(receiver.clone(), member.clone()))
        && (metadata.receiver_mode.requires_caller_place()
            || (metadata.receiver_mode == ReceiverMode::Owned
                && requires_consumption(receiver, context)))
    {
        // Projection here never yields a caller place, so this site only reports
        // the not-a-caller-place case of an `exclusive self` admission failure.
        let (code, message) = match metadata.receiver_mode {
            ReceiverMode::ExclusivePlace => (
                "exclusive-receiver-place",
                "`exclusive self` requires an admitted caller place: a mutable binding root of the calling frame or a struct-field projection from one",
            ),
            ReceiverMode::Owned => (
                "owned-receiver-scope",
                "`owned self` on a consumption-requiring receiver requires a binding root or struct-field receiver place",
            ),
            _ => (
                "shared-receiver-place",
                "`shared self` requires a binding root or struct-field receiver place",
            ),
        };
        diagnostics.push(body_diagnostic(
            code,
            DiagnosticCategory::Type,
            message,
            tree.node(member_id)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    Ok(())
}

fn require_aggregate_member(
    expected: &TypeDescriptor,
    actual: &TypeDescriptor,
    tree: &SyntaxTree,
    node: NodeId,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if expected != actual {
        diagnostics.push(body_diagnostic(
            "aggregate-member-type",
            DiagnosticCategory::Type,
            "an aggregate member differs from its exact expected type",
            tree.node(node)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone(),
            [
                ("actual", actual.canonical_string()),
                ("expected", expected.canonical_string()),
            ],
        )?);
    }
    Ok(())
}

fn infer_operand_sequence(
    tree: &SyntaxTree,
    children: &[NodeId],
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    operator: Option<Punctuation>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    if let Some((operator, index)) = direct_binary_operator_in(tree, children) {
        let left = infer_operand_sequence(
            tree,
            children.get(..index).unwrap_or_default(),
            facts,
            environment,
            Some(operator),
            context,
            diagnostics,
        )?;
        let right = infer_operand_sequence(
            tree,
            children.get(index.saturating_add(1)..).unwrap_or_default(),
            facts,
            environment,
            Some(operator),
            context,
            diagnostics,
        )?;
        if let (Some(left), Some(right)) = (left, right) {
            let span = children
                .first()
                .and_then(|child| tree.node(*child))
                .map(|node| node.span().clone())
                .ok_or(AnalysisError::Invariant)?;
            return infer_binary_operator(operator, left, right, span, context, diagnostics)
                .map(Some);
        }
        return Ok(None);
    }
    if let Some(value) = infer_member_sequence(
        tree,
        children,
        facts,
        environment,
        None,
        None,
        context,
        diagnostics,
    )? {
        return Ok(Some(value));
    }
    if let Some(value) = infer_call_sequence(
        tree,
        children,
        facts,
        environment,
        None,
        context,
        diagnostics,
    )? {
        return Ok(Some(value));
    }
    if operator.is_some_and(operand_projection_supported)
        && let Some(value) =
            infer_operand_projection_sequence(tree, children, environment, context, diagnostics)?
    {
        return Ok(Some(value));
    }
    for child in children {
        let node = tree.node(*child).ok_or(AnalysisError::Invariant)?;
        match node.form() {
            SyntaxForm::Expression | SyntaxForm::BinaryExpression | SyntaxForm::UnaryExpression => {
                if let Some(value) =
                    infer_expression(tree, *child, facts, environment, None, context, diagnostics)?
                {
                    return Ok(Some(value));
                }
            }
            SyntaxForm::Path => {
                if let Some(name) = direct_identifier(tree, *child)?
                    && let Some(value) = environment.get(&name)
                {
                    record_affine_read(
                        name.clone(),
                        value,
                        node.span().clone(),
                        context,
                        diagnostics,
                    )?;
                    return Ok(Some(value.clone()));
                }
            }
            SyntaxForm::Token(token) => {
                if let Some(value) = token_type(token, node.span().clone(), None, diagnostics)? {
                    return Ok(Some(value));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Resolves a dotted operand whose root and member tokens arrived as sibling nodes.
///
/// The parser splits a leading field projection into sibling children (a root `Path`
/// followed by one `PostfixExpression` and member node per dot) while a trailing one
/// arrives as a single `Expression`. Multi-member chains are already resolved by the
/// member-sequence path, so only the single-member split shape is resolved here, which
/// keeps exactly one place recorded per operand read.
fn infer_operand_projection_sequence(
    tree: &SyntaxTree,
    children: &[NodeId],
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    if children.len() < 2 {
        return Ok(None);
    }
    let Some((root, fields)) = postfix_field_sequence(tree, children) else {
        return Ok(None);
    };
    if fields.len() != 1 {
        return Ok(None);
    }
    let Some(root_binding) = environment.get(&root).cloned() else {
        return Ok(None);
    };
    let (member, member_id) = fields.into_iter().next().ok_or(AnalysisError::Invariant)?;
    let member_node = tree.node(member_id).ok_or(AnalysisError::Invariant)?;
    let Some(field) = projected_member_type(&root_binding, member.as_ref(), context)? else {
        diagnostics.push(body_diagnostic(
            "unknown-member",
            DiagnosticCategory::Type,
            "a receiver type has no field or inherent method with this name",
            member_node.span().clone(),
            [
                ("member", member.as_ref()),
                ("receiver", root_binding.canonical_string().as_str()),
            ],
        )?);
        return Ok(None);
    };
    let member_span = member_node.span().clone();
    record_affine_place(
        AffinePlace::projected(root, vec![member]),
        Some(&root_binding),
        &field,
        member_span,
        AffineAccess::Read,
        context,
        diagnostics,
    )?;
    Ok(Some(field))
}

/// Reports whether the lowering publishes a primitive for one enclosing operator.
///
/// Split dotted operands are merged only for operators the lowering consumes, so a
/// merged operand type never reaches a lowering step that has no primitive for it.
fn operand_projection_supported(operator: Punctuation) -> bool {
    matches!(
        operator,
        Punctuation::Plus
            | Punctuation::Minus
            | Punctuation::Star
            | Punctuation::Slash
            | Punctuation::Percent
            | Punctuation::EqualEqual
            | Punctuation::NotEqual
            | Punctuation::Less
            | Punctuation::LessEqual
            | Punctuation::Greater
            | Punctuation::GreaterEqual
            | Punctuation::Bang
    )
}

#[allow(clippy::too_many_arguments)]
fn infer_member_sequence(
    tree: &SyntaxTree,
    children: &[NodeId],
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    receiver: Option<TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    if receiver.is_none()
        && let Some((root, fields)) = postfix_field_sequence(tree, children)
        && fields.len() > 1
    {
        let Some(root_binding) = environment.get(&root).cloned() else {
            return Ok(None);
        };
        let mut receiver = root_binding.clone();
        let mut path = Vec::with_capacity(fields.len());
        for (member, member_id) in fields {
            path.push(member.clone());
            let field = projected_member_type(&receiver, member.as_ref(), context)?;
            let Some(field) = field else {
                let member_node = tree.node(member_id).ok_or(AnalysisError::Invariant)?;
                diagnostics.push(body_diagnostic(
                    "unknown-member",
                    DiagnosticCategory::Type,
                    "a receiver type has no field or inherent method with this name",
                    member_node.span().clone(),
                    [
                        ("member", member.as_ref()),
                        ("receiver", receiver.canonical_string().as_str()),
                    ],
                )?);
                return Ok(None);
            };
            receiver = field;
        }
        let place_span = children
            .last()
            .and_then(|child| tree.node(*child))
            .map(|node| node.span().clone())
            .ok_or(AnalysisError::Invariant)?;
        record_affine_place(
            AffinePlace::projected(root, path),
            Some(&root_binding),
            &receiver,
            place_span,
            AffineAccess::Read,
            context,
            diagnostics,
        )?;
        return Ok(Some(receiver));
    }
    let Some(dot) = children
        .iter()
        .rposition(|child| node_contains_punctuation(tree, *child, Punctuation::Dot))
    else {
        return Ok(None);
    };
    let receiver = if let Some(receiver) = receiver {
        receiver
    } else if let Some((root, fields)) =
        postfix_field_sequence(tree, children.get(..dot).unwrap_or_default())
    {
        let Some(mut receiver) = environment.get(&root).cloned() else {
            return Ok(None);
        };
        for (field, field_id) in fields {
            let resolved = context
                .structs
                .values()
                .find(|shape| shape.descriptor == receiver)
                .and_then(|shape| shape.fields.get(&field))
                .map(|field| field.ty.clone())
                .or_else(|| {
                    generic_field_type(&receiver, &field, context)
                        .ok()
                        .flatten()
                });
            let Some(resolved) = resolved else {
                let field_node = tree.node(field_id).ok_or(AnalysisError::Invariant)?;
                diagnostics.push(body_diagnostic(
                    "unknown-member",
                    DiagnosticCategory::Type,
                    "a receiver type has no field or inherent method with this name",
                    field_node.span().clone(),
                    [
                        ("member", field.as_ref()),
                        ("receiver", receiver.canonical_string().as_str()),
                    ],
                )?);
                return Ok(None);
            };
            receiver = resolved;
        }
        receiver
    } else {
        let root = children
            .get(..dot)
            .unwrap_or_default()
            .iter()
            .find_map(|child| {
                let node = tree.node(*child)?;
                match node.form() {
                    SyntaxForm::Path => direct_identifier(tree, *child).ok().flatten(),
                    SyntaxForm::Token(TokenKind::ReservedWord(word))
                        if word.spelling() == "self" =>
                    {
                        Some(Arc::from("self"))
                    }
                    _ => None,
                }
            });
        if let Some(root) = root
            && let Some(receiver) = environment.get(&root).cloned()
        {
            receiver
        } else {
            let Some(receiver) = infer_operand_sequence(
                tree,
                children.get(..dot).unwrap_or_default(),
                facts,
                environment,
                None,
                context,
                diagnostics,
            )?
            else {
                return Ok(None);
            };
            receiver
        }
    };
    let member_id = children
        .get(dot.saturating_add(1))
        .copied()
        .ok_or(AnalysisError::Invariant)?;
    let member_node = tree.node(member_id).ok_or(AnalysisError::Invariant)?;
    let member = match member_node.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        _ => return Ok(None),
    };
    let call_open = children
        .iter()
        .enumerate()
        .skip(dot.saturating_add(2))
        .find(|(_, child)| node_contains_punctuation(tree, **child, Punctuation::LeftParenthesis))
        .map(|(index, _)| index);
    if let Some(open) = call_open {
        let close = split_call_close_index(tree, children, open).unwrap_or(children.len());
        // The receiver place and the member dot precede the call parenthesis, so the
        // argument fragments are excluded from the receiver scans: an argument that is
        // itself a receiver call owns a dot and parentheses of its own, which must not be
        // read as the outer member dot and call.
        let receiver_scope = children.get(..open).unwrap_or(children);
        let arguments = children
            .get(open.saturating_add(1)..close)
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
            })
            .collect::<Vec<_>>();
        let mut actual_arguments = Vec::with_capacity(arguments.len());
        for argument in &arguments {
            let Some(actual) = infer_expression(
                tree,
                *argument,
                facts,
                environment,
                None,
                context,
                diagnostics,
            )?
            else {
                return Ok(None);
            };
            actual_arguments.push(actual);
        }
        let explicit_method_arguments = children
            .get(dot.saturating_add(2)..open)
            .unwrap_or_default()
            .iter()
            .find_map(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::TypeArgumentList))
                    .then_some(*child)
            })
            .map(|list| closed_type_arguments(tree, list, context))
            .transpose()?;
        let builtin = builtin_method_signature(&receiver, &member)?;
        let inherent_source = builtin.is_none().then(|| {
            context
                .inherent_method_sources
                .get(&(receiver.clone(), member.clone()))
                .cloned()
        });
        let inherent = builtin.or_else(|| {
            context
                .methods
                .get(&(receiver.clone(), member.clone()))
                .cloned()
        });
        let mut generic = None;
        let signature = if let Some(inherent) = inherent {
            Some(inherent)
        } else if let Some(resolution) = resolve_generic_inherent_method(
            &receiver,
            &member,
            explicit_method_arguments.as_deref(),
            &actual_arguments,
            expected,
            context,
            member_node,
            diagnostics,
        )? {
            let callable = resolution.callable.clone();
            generic = Some(resolution);
            Some(callable)
        } else {
            let resolution = resolve_trait_method(
                &receiver,
                &member,
                None,
                None,
                explicit_method_arguments.as_deref(),
                Some(&actual_arguments),
                expected,
                context,
                member_node,
                diagnostics,
            )?;
            if let Some((_, retained)) = &resolution {
                generic = retained.clone();
            }
            resolution.map(|(callable, _)| callable)
        };
        let Some(signature) = signature else {
            return Ok(None);
        };
        if let Some(metadata) = inherent_source.flatten() {
            let exclusive_admission = if metadata.receiver_mode == ReceiverMode::ExclusivePlace {
                Some(postfix_exclusive_receiver_place(
                    tree,
                    receiver_scope,
                    context,
                    member_node.span(),
                )?)
            } else {
                None
            };
            let caller_place_is_valid = match exclusive_admission {
                Some(admission) => admission.is_admitted(),
                None => postfix_shared_receiver_place(tree, receiver_scope, context),
            };
            let requires_place = metadata.receiver_mode.requires_caller_place()
                || (metadata.receiver_mode == ReceiverMode::Owned
                    && requires_consumption(&receiver, context));
            if requires_place && !caller_place_is_valid {
                let (code, message) = match metadata.receiver_mode {
                    ReceiverMode::ExclusivePlace => match exclusive_admission {
                        Some(ExclusiveReceiverAdmission::ImmutableRoot) => (
                            "exclusive-receiver-immutable",
                            "`exclusive self` requires a mutable binding root: the receiver place root is not mutable",
                        ),
                        Some(ExclusiveReceiverAdmission::NotAStrictStructFieldSubplace) => (
                            "exclusive-reborrow-subplace",
                            "a nested `exclusive self` reborrow must select a strict struct-field subplace of the enclosing admitted place, not the admitted place itself",
                        ),
                        _ => (
                            "exclusive-receiver-place",
                            "`exclusive self` requires an admitted caller place: a mutable binding root of the calling frame or a struct-field projection from one",
                        ),
                    },
                    ReceiverMode::Owned => (
                        "owned-receiver-scope",
                        "`owned self` on a consumption-requiring receiver requires a binding root or struct-field receiver place",
                    ),
                    _ => (
                        "shared-receiver-place",
                        "`shared self` requires a binding root or struct-field receiver place",
                    ),
                };
                diagnostics.push(body_diagnostic(
                    code,
                    DiagnosticCategory::Type,
                    message,
                    member_node.span().clone(),
                    [] as [(&str, &str); 0],
                )?);
            }
            if !requires_place
                && !receiver_is_syntactic_place(tree, receiver_scope)
                && !receiver_is_constructed(tree, receiver_scope)
            {
                diagnostics.push(body_diagnostic(
                    "receiver-value-place",
                    DiagnosticCategory::Type,
                    "a receiver call requires a binding root, a struct-field receiver place, or a constructed value",
                    member_node.span().clone(),
                    [] as [(&str, &str); 0],
                )?);
            }
            if metadata.receiver_mode == ReceiverMode::Owned {
                check_owned_move_receiver(
                    tree,
                    children.get(..dot).unwrap_or_default(),
                    &receiver,
                    environment,
                    member_node.span().clone(),
                    context,
                    diagnostics,
                )?;
            }
            let call_site = call_sequence_span(tree, children, member_node)
                .unwrap_or_else(|| member_node.span().clone());
            if let Some(caller) = context.current_effect_owner.borrow().clone() {
                context.resolved_calls.borrow_mut().insert(
                    (
                        caller,
                        call_site.clone(),
                        EffectNode::Source(metadata.declaration.clone()),
                    ),
                    None,
                );
            }
            record_effect_call(context, EffectNode::Source(metadata.declaration), call_site);
        }
        if arguments.len() != signature.parameters.len() {
            diagnostics.push(body_diagnostic(
                "call-arity",
                DiagnosticCategory::Type,
                "a workflow call has the wrong number of arguments",
                member_node.span().clone(),
                [
                    ("actual", arguments.len().to_string()),
                    ("expected", signature.parameters.len().to_string()),
                ],
            )?);
        }
        for ((argument, actual), expected) in arguments
            .iter()
            .zip(&actual_arguments)
            .zip(&signature.parameters)
        {
            if actual != expected {
                diagnostics.push(body_diagnostic(
                    "call-argument-type",
                    DiagnosticCategory::Type,
                    "a workflow argument differs from its exact parameter type",
                    tree.node(*argument)
                        .ok_or(AnalysisError::Invariant)?
                        .span()
                        .clone(),
                    [
                        ("actual", actual.canonical_string()),
                        ("expected", expected.canonical_string()),
                    ],
                )?);
            }
        }
        if let Some(resolution) = generic {
            // Register the instantiation against the whole call span, exactly as a
            // monomorphic receiver call registers its own resolved call site, so that
            // operand lowering finds the call the split operand reconstructs instead of
            // falling back to the fragment walk. Diagnostics and source origins keep the
            // authored callee reference.
            let call_site = call_sequence_span(tree, children, member_node)
                .unwrap_or_else(|| member_node.span().clone());
            retain_generic_instantiation(
                &resolution.signature,
                resolution.concrete_arguments,
                member_node,
                &call_site,
                context,
                diagnostics,
            )?;
        }
        return Ok(Some(signature.result.clone()));
    }

    let field = projected_member_type(&receiver, member.as_ref(), context)?;
    if let Some(field) = field {
        if let Some((root, fields)) = postfix_field_sequence(tree, children)
            && let Some(root_binding) = environment.get(&root).cloned()
        {
            record_affine_place(
                AffinePlace::projected(root, fields.into_iter().map(|(field, _)| field).collect()),
                Some(&root_binding),
                &field,
                member_node.span().clone(),
                AffineAccess::Read,
                context,
                diagnostics,
            )?;
        }
        return Ok(Some(field));
    }
    diagnostics.push(body_diagnostic(
        "unknown-member",
        DiagnosticCategory::Type,
        "a receiver type has no field or inherent method with this name",
        member_node.span().clone(),
        [
            ("member", member.as_ref()),
            ("receiver", receiver.canonical_string().as_str()),
        ],
    )?);
    Ok(None)
}

fn postfix_field_sequence(tree: &SyntaxTree, children: &[NodeId]) -> Option<PostfixFieldSequence> {
    let mut tokens = Vec::new();
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        if matches!(node.form(), SyntaxForm::Token(_)) {
            tokens.push((id, node));
        } else {
            work.extend(node.children().iter().rev().copied());
        }
    }
    if tokens.iter().any(|(_, node)| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(
                Punctuation::LeftParenthesis | Punctuation::LeftBracket
            ))
        )
    }) {
        return None;
    }
    let root = match tokens.first()?.1.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
            Arc::from("self")
        }
        _ => return None,
    };
    let mut fields = Vec::new();
    let mut cursor = 1;
    while cursor < tokens.len() {
        if !matches!(
            tokens.get(cursor)?.1.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        ) {
            return None;
        }
        let (id, node) = tokens.get(cursor + 1)?;
        let SyntaxForm::Token(TokenKind::Identifier(field)) = node.form() else {
            return None;
        };
        fields.push((field.clone(), *id));
        cursor += 2;
    }
    (!fields.is_empty()).then_some((root, fields))
}

/// Reports whether the receiver before the method dot is a root or field projection.
fn receiver_is_syntactic_place(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    let mut tokens = Vec::new();
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let Some(node) = tree.node(id) else {
            return false;
        };
        if matches!(node.form(), SyntaxForm::Token(_)) {
            tokens.push(node);
        } else {
            work.extend(node.children().iter().rev().copied());
        }
    }
    let Some(dot) = tokens.iter().rposition(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        )
    }) else {
        return false;
    };
    let receiver = &tokens[..dot];
    let Some(first) = receiver.first() else {
        return false;
    };
    let starts_with_root = matches!(first.form(), SyntaxForm::Token(TokenKind::Identifier(_)))
        || matches!(
            first.form(),
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self"
        );
    starts_with_root
        && receiver[1..].chunks(2).all(|pair| {
            matches!(
                pair.first().map(|node| node.form()),
                Some(SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)))
            ) && matches!(
                pair.get(1).map(|node| node.form()),
                Some(SyntaxForm::Token(TokenKind::Identifier(_)))
            )
        })
}

/// Reports whether any receiver child before the method dot constructs an aggregate.
fn receiver_is_constructed(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    let receiver_children = children
        .iter()
        .rposition(|child| node_contains_punctuation(tree, *child, Punctuation::Dot))
        .map_or_else(|| children, |dot| children.get(..dot).unwrap_or_default());
    receiver_children
        .iter()
        .any(|child| subtree_constructs_aggregate(tree, *child))
}

/// Reports whether one subtree contains a struct expression.
fn subtree_constructs_aggregate(tree: &SyntaxTree, node: NodeId) -> bool {
    let mut work = vec![node];
    while let Some(id) = work.pop() {
        let Some(node) = tree.node(id) else {
            continue;
        };
        if matches!(node.form(), SyntaxForm::StructExpression) {
            return true;
        }
        work.extend(node.children().iter().copied());
    }
    false
}

fn postfix_shared_receiver_place(
    tree: &SyntaxTree,
    children: &[NodeId],
    context: &BodyContext,
) -> bool {
    let mut tokens = Vec::new();
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let Some(node) = tree.node(id) else {
            return false;
        };
        if matches!(node.form(), SyntaxForm::Token(_)) {
            tokens.push(node);
        } else {
            work.extend(node.children().iter().rev().copied());
        }
    }
    let Some(method_dot) = tokens.iter().rposition(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        )
    }) else {
        return false;
    };
    let root_is_place = match tokens.first().map(|node| node.form()) {
        Some(SyntaxForm::Token(TokenKind::Identifier(_))) => true,
        Some(SyntaxForm::Token(TokenKind::ReservedWord(word))) => word.spelling() == "self",
        _ => false,
    };
    root_is_place
        && tokens.first().is_some_and(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(root)) => {
                !context.shared_receiver_value_roots.borrow().contains(root)
            }
            _ => true,
        })
        && tokens[..method_dot]
            .iter()
            .enumerate()
            .skip(1)
            .all(|(index, node)| {
                matches!(
                    (index % 2, node.form()),
                    (
                        1,
                        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
                    ) | (0, SyntaxForm::Token(TokenKind::Identifier(_)))
                )
            })
}

/// Admission outcome for one `exclusive self` call receiver place.
///
/// Item 2f admits a caller place only for a mutable binding root of the calling
/// frame or, inside a `shared self` or `exclusive self` method, a strict
/// struct-field reborrow of the enclosing admitted place. Each failure cause is
/// retained so the call site can report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExclusiveReceiverAdmission {
    /// The receiver is an admitted caller place.
    Admitted,
    /// The receiver is not an admitted caller place: neither a mutable binding root
    /// of the calling frame nor a struct-field projection from one.
    NotACallerPlace,
    /// The receiver place root is not a mutable binding.
    ImmutableRoot,
    /// The receiver is the enclosing callable's own admitted caller place rather than
    /// a strict struct-field subplace of that place.
    NotAStrictStructFieldSubplace,
}

impl ExclusiveReceiverAdmission {
    /// Whether this outcome admits the receiver as a caller place.
    const fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

fn postfix_exclusive_receiver_place(
    tree: &SyntaxTree,
    children: &[NodeId],
    context: &BodyContext,
    call: &SourceSpan,
) -> Result<ExclusiveReceiverAdmission, AnalysisError> {
    if !postfix_shared_receiver_place(tree, children, context) {
        return Ok(ExclusiveReceiverAdmission::NotACallerPlace);
    }
    let mut tokens = Vec::new();
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        if matches!(node.form(), SyntaxForm::Token(_)) {
            tokens.push(node);
            continue;
        }
        work.extend(node.children().iter().rev().copied());
    }
    let method_dot = tokens.iter().rposition(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        )
    });
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        if let SyntaxForm::Token(TokenKind::Identifier(root)) = node.form() {
            return Ok(if assignment_root_is_mutable(tree, call, root, false)? {
                ExclusiveReceiverAdmission::Admitted
            } else {
                ExclusiveReceiverAdmission::ImmutableRoot
            });
        }
        if matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self")
        {
            if !assignment_root_is_mutable(tree, call, &Arc::from("self"), true)? {
                return Ok(ExclusiveReceiverAdmission::ImmutableRoot);
            }
            if method_dot.is_some_and(|dot| dot > 1) {
                return Ok(ExclusiveReceiverAdmission::Admitted);
            }
            // Only a `shared self` or `exclusive self` method binds `self` to the
            // admitted caller place; an `owned self`, `mut self`, or plain `self`
            // method binds a copy or an owned value, so `self` itself is never an
            // admitted caller place and the failure is not a reborrow subplace.
            let reborrows_enclosing_place = enclosing_callable_receiver_mode(tree, call)?
                .is_some_and(ReceiverMode::requires_caller_place);
            return Ok(if reborrows_enclosing_place {
                ExclusiveReceiverAdmission::NotAStrictStructFieldSubplace
            } else {
                ExclusiveReceiverAdmission::NotACallerPlace
            });
        }
        work.extend(node.children().iter().rev().copied());
    }
    Ok(ExclusiveReceiverAdmission::NotACallerPlace)
}

fn call_sequence_span(
    tree: &SyntaxTree,
    children: &[NodeId],
    callee: &gantry_frontend::SyntaxNode,
) -> Option<SourceSpan> {
    let mut local_tokens = Vec::new();
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        if matches!(node.form(), SyntaxForm::Token(_)) {
            local_tokens.push(node);
        } else {
            work.extend(node.children().iter().rev().copied());
        }
    }
    let start = local_tokens.first()?;
    let mut tokens = tree
        .nodes()
        .iter()
        .filter(|node| {
            matches!(node.form(), SyntaxForm::Token(_))
                && node.span().source() == callee.span().source()
        })
        .collect::<Vec<_>>();
    tokens.sort_by_key(|token| token.span().bytes());
    let callee_index = tokens
        .iter()
        .position(|token| token.span() == callee.span())?;
    let open = tokens
        .get(callee_index.saturating_add(1)..)?
        .iter()
        .position(|token| {
            matches!(
                token.form(),
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
            )
        })?
        .saturating_add(callee_index.saturating_add(1));
    let mut depth = 0_u64;
    let closing = tokens.get(open..)?.iter().find(|token| {
        matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
        )
        .then(|| depth = depth.saturating_add(1));
        matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
        ) && {
            depth = depth.saturating_sub(1);
            depth == 0
        }
    })?;
    (start.span().source() == closing.span().source())
        .then(|| {
            SourceSpan::from_portable_parts(
                start.span().source().package_path().as_str(),
                start.span().bytes().start(),
                closing.span().bytes().end(),
            )
            .ok()
        })
        .flatten()
}

fn postfix_called_member(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<(Arc<str>, NodeId)> {
    let mut tokens = Vec::new();
    let mut work = node.children().iter().rev().copied().collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let token = tree.node(id)?;
        if matches!(token.form(), SyntaxForm::Token(_)) {
            tokens.push((id, token));
        } else {
            work.extend(token.children().iter().rev().copied());
        }
    }
    let dot = tokens.iter().rposition(|(_, token)| {
        matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        )
    })?;
    let (member_id, member) = tokens.get(dot.saturating_add(1))?;
    let SyntaxForm::Token(TokenKind::Identifier(member)) = member.form() else {
        return None;
    };
    tokens
        .get(dot.saturating_add(2)..)
        .is_some_and(|tail| {
            tail.iter().any(|(_, token)| {
                matches!(
                    token.form(),
                    SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
                )
            })
        })
        .then_some((member.clone(), *member_id))
}

fn struct_fields_for_descriptor(
    context: &BodyContext,
    descriptor: &TypeDescriptor,
) -> Result<Option<BTreeMap<Arc<str>, TypeDescriptor>>, AnalysisError> {
    if let Some(shape) = context
        .structs
        .values()
        .find(|shape| shape.descriptor == *descriptor)
    {
        return Ok(Some(
            shape
                .fields
                .iter()
                .map(|(name, field)| (name.clone(), field.ty.clone()))
                .collect(),
        ));
    }
    let Some(path) = descriptor.declared_path() else {
        return Ok(None);
    };
    let arguments = descriptor.immediate_members();
    let Some(shape) = context
        .generic_structs
        .values()
        .find(|shape| &shape.path == path && shape.required.len() == arguments.len())
    else {
        return Ok(None);
    };
    let substitution = ExactTypeSubstitution::explicit(&shape.required, &arguments)
        .map_err(|_| AnalysisError::Invariant)?;
    shape
        .fields
        .iter()
        .map(|(name, field)| {
            substitution
                .apply(&field.ty)
                .map(|ty| (name.clone(), ty))
                .map_err(|_| AnalysisError::Invariant)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map(Some)
}

fn generic_field_type(
    receiver: &TypeDescriptor,
    member: &str,
    context: &BodyContext,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let fields = struct_fields_for_descriptor(context, receiver)?;
    if let Some(fields) = &fields {
        context
            .resolved_struct_fields
            .borrow_mut()
            .insert(receiver.clone(), fields.clone());
    }
    Ok(fields.and_then(|fields| fields.get(member).cloned()))
}

/// Resolves one immediately declared member type on a closed or instantiated receiver.
///
/// Member resolution is shared between the resolved member-chain path and the split
/// operand path so both report the same projected type for the same member.
fn projected_member_type(
    receiver: &TypeDescriptor,
    member: &str,
    context: &BodyContext,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    if *receiver == TypeDescriptor::DECISION {
        return Ok(match member {
            "decision" => Some(TypeDescriptor::BOOL),
            "rationale" => Some(TypeDescriptor::STRING),
            _ => None,
        });
    }
    let closed = context
        .structs
        .values()
        .find(|shape| shape.descriptor == *receiver)
        .and_then(|shape| shape.fields.get(member))
        .map(|field| field.ty.clone());
    if closed.is_some() {
        return Ok(closed);
    }
    generic_field_type(receiver, member, context)
}

#[allow(clippy::too_many_arguments)]
fn instantiate_generic_method(
    signature: &GenericCallableSignature,
    receiver: &TypeDescriptor,
    trait_arguments: Option<&[TypeDescriptor]>,
    explicit_method_arguments: Option<&[TypeDescriptor]>,
    actual_arguments: &[TypeDescriptor],
    expected_result: Option<&TypeDescriptor>,
) -> Result<GenericMethodResolution, TypeInferenceFailure> {
    let receiver_template = signature
        .receiver
        .as_ref()
        .ok_or(TypeInferenceFailure::Conflict)?;
    let mut constraints = vec![(
        receiver_template.clone(),
        TypeExpression::closed(receiver, u64::MAX).map_err(|_| TypeInferenceFailure::Conflict)?,
    )];
    if let Some(arguments) = trait_arguments {
        let reference = signature
            .trait_reference
            .as_ref()
            .ok_or(TypeInferenceFailure::Conflict)?;
        if arguments.len() != reference.arguments().len() {
            return Err(TypeInferenceFailure::Arity);
        }
        for (template, argument) in reference.arguments().iter().zip(arguments) {
            constraints.push((
                template.clone(),
                TypeExpression::closed(argument, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
            ));
        }
    }
    let method_required = signature
        .required
        .get(signature.implementation_parameter_count..)
        .ok_or(TypeInferenceFailure::Arity)?;
    if let Some(arguments) = explicit_method_arguments {
        if arguments.len() != method_required.len() {
            return Err(TypeInferenceFailure::Arity);
        }
        for (parameter, argument) in method_required.iter().zip(arguments) {
            constraints.push((
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
                TypeExpression::closed(argument, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
            ));
        }
    }
    if actual_arguments.len() != signature.parameters.len() {
        return Err(TypeInferenceFailure::Arity);
    }
    for (template, argument) in signature.parameters.iter().zip(actual_arguments) {
        constraints.push((
            substitute_self_type(template, receiver).map_err(|_| TypeInferenceFailure::Conflict)?,
            TypeExpression::closed(argument, u64::MAX)
                .map_err(|_| TypeInferenceFailure::Conflict)?,
        ));
    }
    if let Some(expected) = expected_result {
        constraints.push((
            substitute_self_type(&signature.result, receiver)
                .map_err(|_| TypeInferenceFailure::Conflict)?,
            TypeExpression::closed(expected, u64::MAX)
                .map_err(|_| TypeInferenceFailure::Conflict)?,
        ));
    }
    let substitution = ExactTypeSubstitution::infer(&signature.required, &constraints)?;
    let concrete_arguments = signature
        .required
        .iter()
        .map(|parameter| {
            TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                .map_err(|_| TypeInferenceFailure::Conflict)
                .and_then(|expression| substitution.apply(&expression))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| substitution.apply_with_receiver(parameter, Some(receiver)))
        .collect::<Result<Vec<_>, _>>()?;
    let result = substitution.apply_with_receiver(&signature.result, Some(receiver))?;
    Ok(GenericMethodResolution {
        signature: signature.clone(),
        concrete_arguments,
        callable: CallableSignature { parameters, result },
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_generic_inherent_method(
    receiver: &TypeDescriptor,
    member: &str,
    explicit_method_arguments: Option<&[TypeDescriptor]>,
    actual_arguments: &[TypeDescriptor],
    expected_result: Option<&TypeDescriptor>,
    context: &BodyContext,
    source: &gantry_frontend::SyntaxNode,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<GenericMethodResolution>, AnalysisError> {
    let mut candidates = context
        .generic_methods
        .iter()
        .filter(|signature| signature.kind == TemplateKind::InherentMethod)
        .filter(|signature| signature.method_name.as_deref() == Some(member))
        .filter_map(|signature| {
            instantiate_generic_method(
                signature,
                receiver,
                None,
                explicit_method_arguments,
                actual_arguments,
                expected_result,
            )
            .ok()
        })
        .collect::<Vec<_>>();
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        _ => {
            diagnostics.push(body_diagnostic(
                GenericAnalysisCode::ConflictingTypeInference.wire_name(),
                DiagnosticCategory::Type,
                "more than one generic inherent method has an exact substitution",
                source.span().clone(),
                [
                    ("member", member.to_owned()),
                    ("receiver", receiver.canonical_string()),
                ],
            )?);
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_trait_method(
    receiver: &TypeDescriptor,
    member: &str,
    restricted_trait: Option<&CanonicalPath>,
    explicit_trait_arguments: Option<&[TypeDescriptor]>,
    explicit_method_arguments: Option<&[TypeDescriptor]>,
    actual_arguments: Option<&[TypeDescriptor]>,
    expected_result: Option<&TypeDescriptor>,
    context: &BodyContext,
    source: &gantry_frontend::SyntaxNode,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<(CallableSignature, Option<GenericMethodResolution>)>, AnalysisError> {
    let visible_traits = context.current_visible_traits.borrow().clone();
    let declaring_traits = context
        .trait_contracts
        .iter()
        .filter(|contract| restricted_trait.is_none_or(|path| contract.path() == path))
        .filter(|contract| restricted_trait.is_some() || visible_traits.contains(contract.path()))
        .filter(|contract| {
            contract
                .methods()
                .iter()
                .any(|method| method.name() == member)
        })
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    let mut inference_failed = false;
    for contract in &declaring_traits {
        let method = contract
            .methods()
            .iter()
            .find(|method| method.name() == member)
            .ok_or(AnalysisError::Invariant)?;
        if let Some(arguments) = explicit_trait_arguments {
            let expected = usize::try_from(contract.parameter_count())
                .map_err(|_| AnalysisError::Invariant)?;
            if arguments.len() != expected {
                diagnostics.push(body_diagnostic(
                    GenericAnalysisCode::TypeArgumentArity.wire_name(),
                    DiagnosticCategory::Type,
                    "a qualified trait call has the wrong number of trait type arguments",
                    source.span().clone(),
                    [
                        ("actual", arguments.len().to_string()),
                        ("expected", expected.to_string()),
                    ],
                )?);
                continue;
            }
        }
        if let Some(arguments) = explicit_method_arguments {
            let expected =
                usize::try_from(method.parameter_count()).map_err(|_| AnalysisError::Invariant)?;
            if arguments.len() != expected {
                diagnostics.push(body_diagnostic(
                    GenericAnalysisCode::TypeArgumentArity.wire_name(),
                    DiagnosticCategory::Type,
                    "a trait method call has the wrong number of method type arguments",
                    source.span().clone(),
                    [
                        ("actual", arguments.len().to_string()),
                        ("expected", expected.to_string()),
                    ],
                )?);
                continue;
            }
        }
        let (trait_arguments, method_arguments) = match infer_trait_call_arguments(
            receiver,
            contract,
            method,
            explicit_trait_arguments,
            explicit_method_arguments,
            actual_arguments,
            expected_result,
        ) {
            Ok(arguments) => arguments,
            Err(error) => {
                inference_failed = true;
                let code = match error {
                    TypeInferenceFailure::Arity => GenericAnalysisCode::TypeArgumentArity,
                    TypeInferenceFailure::Conflict | TypeInferenceFailure::OccursCheck => {
                        GenericAnalysisCode::ConflictingTypeInference
                    }
                    TypeInferenceFailure::Incomplete => {
                        GenericAnalysisCode::IncompleteTypeInference
                    }
                    TypeInferenceFailure::InvalidOptionMember => {
                        GenericAnalysisCode::IncompleteTypeInference
                    }
                };
                diagnostics.push(body_diagnostic(
                    code.wire_name(),
                    DiagnosticCategory::Type,
                    "trait call type inference did not produce one complete substitution",
                    source.span().clone(),
                    [("trait", contract.path().as_str())],
                )?);
                continue;
            }
        };
        if context.parametric_validation.get()
            && context
                .current_declared_obligations
                .borrow()
                .iter()
                .any(|obligation| {
                    obligation.trait_path == *contract.path()
                        && obligation.trait_arguments == trait_arguments
                        && obligation.receiver == *receiver
                })
        {
            candidates.push((
                instantiate_declared_trait_method(
                    receiver,
                    contract,
                    method,
                    &trait_arguments,
                    &method_arguments,
                )?,
                None,
                None,
                None,
                *method.effects(),
            ));
            continue;
        }
        let mut active = BTreeSet::new();
        let proof = prove_trait_obligation(
            contract.path(),
            &trait_arguments,
            receiver,
            context,
            &mut active,
        )?;
        match proof.result {
            ObligationResult::Proven => {
                let selected = proof
                    .selected_implementation
                    .and_then(|index| context.implementation_heads.get(index))
                    .ok_or(AnalysisError::Invariant)?;
                if let Some(signature) = instantiate_trait_method(
                    receiver,
                    contract,
                    method,
                    selected,
                    &trait_arguments,
                    Some(&method_arguments),
                )? {
                    let retained = context
                        .generic_methods
                        .iter()
                        .find(|candidate| {
                            candidate.kind == TemplateKind::TraitMethod
                                && candidate.method_name.as_deref() == Some(member)
                                && candidate.implementation.as_ref() == Some(selected.identity())
                        })
                        .map(|candidate| {
                            instantiate_generic_method(
                                candidate,
                                receiver,
                                Some(&trait_arguments),
                                Some(&method_arguments),
                                actual_arguments.unwrap_or_default(),
                                expected_result,
                            )
                            .map_err(|_| AnalysisError::Invariant)
                        })
                        .transpose()?;
                    let effect_target = if retained.is_none() {
                        Some(EffectNode::Source(
                            context
                                .method_sources
                                .get(&(selected.identity().clone(), Arc::from(member)))
                                .cloned()
                                .ok_or(AnalysisError::Invariant)?,
                        ))
                    } else {
                        None
                    };
                    candidates.push((
                        signature,
                        retained,
                        effect_target,
                        Some(selected.identity().clone()),
                        EffectSet::default(),
                    ));
                }
            }
            ObligationResult::Cyclic => {
                diagnostics.push(body_diagnostic(
                    GenericAnalysisCode::CyclicTraitObligation.wire_name(),
                    DiagnosticCategory::Type,
                    "a concrete trait obligation depends on itself",
                    source.span().clone(),
                    [
                        (
                            "obligation",
                            obligation_key(contract.path(), &trait_arguments, receiver),
                        ),
                        ("obligation_chain", proof.chain.join(" -> ")),
                    ],
                )?);
            }
            ObligationResult::Unsatisfied => {}
        }
    }
    match candidates.len() {
        0 if inference_failed => Ok(None),
        0 if !declaring_traits.is_empty() => {
            diagnostics.push(body_diagnostic(
                GenericAnalysisCode::MissingImplementation.wire_name(),
                DiagnosticCategory::Type,
                "no trait implementation applies to this receiver and method",
                source.span().clone(),
                [
                    ("member", member.to_owned()),
                    ("receiver", receiver.canonical_string()),
                ],
            )?);
            Ok(None)
        }
        0 => {
            diagnostics.push(body_diagnostic(
                "unknown-member",
                DiagnosticCategory::Type,
                "a receiver type has no field, inherent method, or visible trait method",
                source.span().clone(),
                [
                    ("member", member.to_owned()),
                    ("receiver", receiver.canonical_string()),
                ],
            )?);
            Ok(None)
        }
        1 => {
            let (signature, retained, effect_target, selected_implementation, direct_effects) =
                candidates.pop().ok_or(AnalysisError::Invariant)?;
            record_direct_effects(context, direct_effects);
            if let Some(effect_target) = effect_target {
                if !context.parametric_validation.get()
                    && let Some(caller) = context.current_effect_owner.borrow().clone()
                {
                    context.resolved_calls.borrow_mut().insert(
                        (caller, source.span().clone(), effect_target.clone()),
                        selected_implementation,
                    );
                }
                record_effect_call(context, effect_target, source.span().clone());
            }
            Ok(Some((signature, retained)))
        }
        _ => {
            diagnostics.push(body_diagnostic(
                GenericAnalysisCode::AmbiguousTraitMethod.wire_name(),
                DiagnosticCategory::Type,
                "more than one trait supplies an applicable method",
                source.span().clone(),
                [
                    ("member", member.to_owned()),
                    ("receiver", receiver.canonical_string()),
                ],
            )?);
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn infer_trait_call_arguments(
    receiver: &TypeDescriptor,
    contract: &TraitContract,
    method: &TraitMethodContract,
    explicit_trait_arguments: Option<&[TypeDescriptor]>,
    explicit_method_arguments: Option<&[TypeDescriptor]>,
    actual_arguments: Option<&[TypeDescriptor]>,
    expected_result: Option<&TypeDescriptor>,
) -> Result<(Vec<TypeDescriptor>, Vec<TypeDescriptor>), TypeInferenceFailure> {
    let trait_required = (0..contract.parameter_count())
        .map(|ordinal| TypeParameterKey {
            binder_depth: 0,
            ordinal,
        })
        .collect::<Vec<_>>();
    let method_depth = u64::from(contract.parameter_count() > 0);
    let method_required = (0..method.parameter_count())
        .map(|ordinal| TypeParameterKey {
            binder_depth: method_depth,
            ordinal,
        })
        .collect::<Vec<_>>();
    let required = trait_required
        .iter()
        .chain(&method_required)
        .copied()
        .collect::<Vec<_>>();
    let mut constraints = Vec::new();
    if let Some(arguments) = explicit_trait_arguments {
        for (parameter, argument) in trait_required.iter().zip(arguments) {
            constraints.push((
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
                TypeExpression::closed(argument, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
            ));
        }
    }
    if let Some(arguments) = explicit_method_arguments {
        for (parameter, argument) in method_required.iter().zip(arguments) {
            constraints.push((
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
                TypeExpression::closed(argument, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
            ));
        }
    }
    if let Some(arguments) = actual_arguments {
        if arguments.len() != method.parameters().len() {
            return Err(TypeInferenceFailure::Arity);
        }
        for (template, argument) in method.parameters().iter().zip(arguments) {
            constraints.push((
                substitute_self_type(template, receiver)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
                TypeExpression::closed(argument, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?,
            ));
        }
    }
    if let Some(expected) = expected_result {
        constraints.push((
            substitute_self_type(method.result(), receiver)
                .map_err(|_| TypeInferenceFailure::Conflict)?,
            TypeExpression::closed(expected, u64::MAX)
                .map_err(|_| TypeInferenceFailure::Conflict)?,
        ));
    }
    let substitution = ExactTypeSubstitution::infer(&required, &constraints)?;
    let trait_arguments = trait_required
        .iter()
        .map(|parameter| {
            let expression =
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?;
            substitution.apply(&expression)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let method_arguments = method_required
        .iter()
        .map(|parameter| {
            let expression =
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| TypeInferenceFailure::Conflict)?;
            substitution.apply(&expression)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((trait_arguments, method_arguments))
}

fn prove_trait_obligation(
    trait_path: &CanonicalPath,
    trait_arguments: &[TypeDescriptor],
    receiver: &TypeDescriptor,
    context: &BodyContext,
    active: &mut BTreeSet<String>,
) -> Result<ObligationProof, AnalysisError> {
    let key = obligation_key(trait_path, trait_arguments, receiver);
    charge_trait_resolution_step(context)?;
    if let Some(proof) = context.trait_obligations.borrow().get(&key).cloned() {
        return Ok(proof);
    }
    if !active.insert(key.clone()) {
        return Ok(ObligationProof {
            result: ObligationResult::Cyclic,
            chain: vec![key],
            selected_implementation: None,
        });
    }

    let contract = context
        .trait_contracts
        .iter()
        .find(|contract| contract.path() == trait_path)
        .ok_or(AnalysisError::Invariant)?;
    let required = (0..contract.parameter_count())
        .map(|ordinal| TypeParameterKey {
            binder_depth: 0,
            ordinal,
        })
        .collect::<Vec<_>>();
    let trait_substitution = match ExactTypeSubstitution::explicit(&required, trait_arguments) {
        Ok(substitution) => substitution,
        Err(TypeInferenceFailure::Arity) => {
            active.remove(&key);
            return Ok(ObligationProof {
                result: ObligationResult::Unsatisfied,
                chain: vec![key],
                selected_implementation: None,
            });
        }
        Err(_) => return Err(AnalysisError::Invariant),
    };
    for predicate in contract.predicates() {
        charge_trait_resolution_step(context)?;
        let predicate_receiver = substitute_self_type(predicate.receiver(), receiver)?;
        let predicate_receiver = trait_substitution
            .apply(&predicate_receiver)
            .map_err(|_| AnalysisError::Invariant)?;
        let predicate_arguments = predicate
            .trait_reference()
            .arguments()
            .iter()
            .map(|argument| {
                let argument = substitute_self_type(argument, receiver)?;
                trait_substitution
                    .apply(&argument)
                    .map_err(|_| AnalysisError::Invariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let nested = prove_trait_obligation(
            predicate.trait_reference().path(),
            &predicate_arguments,
            &predicate_receiver,
            context,
            active,
        )?;
        if nested.result != ObligationResult::Proven {
            let proof = ObligationProof {
                result: nested.result,
                chain: std::iter::once(key.clone()).chain(nested.chain).collect(),
                selected_implementation: None,
            };
            active.remove(&key);
            context
                .trait_obligations
                .borrow_mut()
                .insert(key, proof.clone());
            return Ok(proof);
        }
    }

    let mut proof = ObligationProof {
        result: ObligationResult::Unsatisfied,
        chain: vec![key.clone()],
        selected_implementation: None,
    };
    let candidate_key = (
        trait_path.clone(),
        outer_type_constructor(&receiver.canonical_string()),
    );
    let candidate_indices = context
        .implementation_candidates
        .get(&candidate_key)
        .cloned()
        .unwrap_or_default();
    for index in candidate_indices {
        let head = context
            .implementation_heads
            .get(index)
            .ok_or(AnalysisError::Invariant)?;
        charge_trait_resolution_step(context)?;
        let Some((substitution, _)) =
            infer_implementation_substitution(receiver, Some(trait_arguments), head)?
        else {
            continue;
        };
        let mut candidate = ObligationProof {
            result: ObligationResult::Proven,
            chain: Vec::new(),
            selected_implementation: Some(index),
        };
        for predicate in head.predicates() {
            charge_trait_resolution_step(context)?;
            let predicate_receiver = substitute_self_type(predicate.receiver(), receiver)?;
            let predicate_receiver = substitution
                .apply(&predicate_receiver)
                .map_err(|_| AnalysisError::Invariant)?;
            let predicate_arguments = predicate
                .trait_reference()
                .arguments()
                .iter()
                .map(|argument| {
                    let argument = substitute_self_type(argument, receiver)?;
                    substitution
                        .apply(&argument)
                        .map_err(|_| AnalysisError::Invariant)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let nested = prove_trait_obligation(
                predicate.trait_reference().path(),
                &predicate_arguments,
                &predicate_receiver,
                context,
                active,
            )?;
            if nested.result != ObligationResult::Proven {
                candidate.result = nested.result;
                candidate.chain = std::iter::once(key.clone()).chain(nested.chain).collect();
                candidate.selected_implementation = None;
                break;
            }
        }
        if candidate.result == ObligationResult::Proven {
            proof = candidate;
            break;
        }
        if candidate.result == ObligationResult::Cyclic {
            proof = candidate;
        }
    }
    active.remove(&key);
    context
        .trait_obligations
        .borrow_mut()
        .insert(key, proof.clone());
    Ok(proof)
}

fn outer_type_constructor(canonical: &str) -> Arc<str> {
    Arc::from(
        canonical
            .split_once('<')
            .map_or(canonical, |(outer, _)| outer),
    )
}

fn charge_trait_resolution_step(context: &BodyContext) -> Result<(), AnalysisError> {
    let mut counters = context.generic_analysis_counters.borrow_mut();
    let Some(counters) = counters.as_mut() else {
        return Ok(());
    };
    counters
        .charge_trait_resolution_steps(1)
        .map_err(|error| AnalysisError::ResourceLimit {
            error,
            diagnostics: Vec::new(),
        })
}

fn obligation_key(
    trait_path: &CanonicalPath,
    trait_arguments: &[TypeDescriptor],
    receiver: &TypeDescriptor,
) -> String {
    let mut key = trait_path.as_str().to_owned();
    if !trait_arguments.is_empty() {
        key.push('<');
        for (index, argument) in trait_arguments.iter().enumerate() {
            if index > 0 {
                key.push(',');
            }
            key.push_str(&argument.canonical_string());
        }
        key.push('>');
    }
    format!("{key} for {}", receiver.canonical_string())
}

fn infer_implementation_substitution(
    receiver: &TypeDescriptor,
    trait_arguments: Option<&[TypeDescriptor]>,
    head: &ImplementationHead,
) -> Result<Option<(ExactTypeSubstitution, Vec<TypeDescriptor>)>, AnalysisError> {
    let trait_reference = head.trait_reference().ok_or(AnalysisError::Invariant)?;
    if trait_arguments.is_some_and(|arguments| arguments.len() != trait_reference.arguments().len())
    {
        return Ok(None);
    }
    let mut head_expressions = vec![head.receiver()];
    head_expressions.extend(trait_reference.arguments());
    let required = collect_type_parameter_keys(&head_expressions)?;
    let mut constraints = vec![(
        head.receiver().clone(),
        TypeExpression::closed(receiver, u64::MAX).map_err(|_| AnalysisError::Invariant)?,
    )];
    if let Some(arguments) = trait_arguments {
        for (template, argument) in trait_reference.arguments().iter().zip(arguments) {
            constraints.push((
                template.clone(),
                TypeExpression::closed(argument, u64::MAX).map_err(|_| AnalysisError::Invariant)?,
            ));
        }
    }
    let substitution = match ExactTypeSubstitution::infer(&required, &constraints) {
        Ok(substitution) => substitution,
        Err(
            TypeInferenceFailure::Arity
            | TypeInferenceFailure::Conflict
            | TypeInferenceFailure::Incomplete
            | TypeInferenceFailure::InvalidOptionMember
            | TypeInferenceFailure::OccursCheck,
        ) => return Ok(None),
    };
    let resolved_arguments = trait_reference
        .arguments()
        .iter()
        .map(|argument| substitution.apply(argument))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AnalysisError::Invariant)?;
    Ok(Some((substitution, resolved_arguments)))
}

fn instantiate_trait_method(
    receiver: &TypeDescriptor,
    contract: &TraitContract,
    method: &TraitMethodContract,
    head: &ImplementationHead,
    trait_arguments: &[TypeDescriptor],
    method_arguments: Option<&[TypeDescriptor]>,
) -> Result<Option<CallableSignature>, AnalysisError> {
    let Some((_, resolved_trait_arguments)) =
        infer_implementation_substitution(receiver, Some(trait_arguments), head)?
    else {
        return Ok(None);
    };
    if resolved_trait_arguments != trait_arguments {
        return Ok(None);
    }
    let Some(method_arguments) =
        method_arguments.or_else(|| (method.parameter_count() == 0).then_some([].as_slice()))
    else {
        return Ok(None);
    };
    instantiate_declared_trait_method(
        receiver,
        contract,
        method,
        trait_arguments,
        method_arguments,
    )
    .map(Some)
}

fn instantiate_declared_trait_method(
    receiver: &TypeDescriptor,
    contract: &TraitContract,
    method: &TraitMethodContract,
    trait_arguments: &[TypeDescriptor],
    method_arguments: &[TypeDescriptor],
) -> Result<CallableSignature, AnalysisError> {
    let mut required = (0..contract.parameter_count())
        .map(|ordinal| TypeParameterKey {
            binder_depth: 0,
            ordinal,
        })
        .collect::<Vec<_>>();
    let method_depth = u64::from(contract.parameter_count() > 0);
    required.extend(
        (0..method.parameter_count()).map(|ordinal| TypeParameterKey {
            binder_depth: method_depth,
            ordinal,
        }),
    );
    let arguments = trait_arguments
        .iter()
        .chain(method_arguments)
        .cloned()
        .collect::<Vec<_>>();
    let substitution = ExactTypeSubstitution::explicit(&required, &arguments)
        .map_err(|_| AnalysisError::Invariant)?;
    let parameters = method
        .parameters()
        .iter()
        .map(|parameter| instantiate_trait_type(parameter, receiver, &substitution))
        .collect::<Result<Vec<_>, _>>()?;
    let result = instantiate_trait_type(method.result(), receiver, &substitution)?;
    Ok(CallableSignature { parameters, result })
}

fn instantiate_trait_type(
    expression: &TypeExpression,
    receiver: &TypeDescriptor,
    substitution: &ExactTypeSubstitution,
) -> Result<TypeDescriptor, AnalysisError> {
    let expression = substitute_self_type(expression, receiver)?;
    substitution
        .apply(&expression)
        .map_err(|_| AnalysisError::Invariant)
}

fn builtin_method_signature(
    receiver: &TypeDescriptor,
    member: &str,
) -> Result<Option<CallableSignature>, AnalysisError> {
    let no_parameters = Vec::new();
    let signature = match (receiver.kind(), member) {
        (TypeKind::Bool | TypeKind::Int | TypeKind::Float, "to_string") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::STRING,
        },
        (TypeKind::Int, "to_float") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::FLOAT,
        },
        (TypeKind::Float, "to_int") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::option(TypeDescriptor::INT)
                .map_err(|_| AnalysisError::Invariant)?,
        },
        (TypeKind::String, "len") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::INT,
        },
        (TypeKind::String, "is_empty") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::BOOL,
        },
        (TypeKind::String, "contains" | "starts_with" | "ends_with") => CallableSignature {
            parameters: vec![TypeDescriptor::STRING],
            result: TypeDescriptor::BOOL,
        },
        (
            TypeKind::String,
            "trim" | "trim_start" | "trim_end" | "to_lowercase" | "to_uppercase",
        ) => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::STRING,
        },
        (TypeKind::String, "replace") => CallableSignature {
            parameters: vec![TypeDescriptor::STRING, TypeDescriptor::STRING],
            result: TypeDescriptor::STRING,
        },
        (TypeKind::String, "split") => CallableSignature {
            parameters: vec![TypeDescriptor::STRING],
            result: TypeDescriptor::list(TypeDescriptor::STRING),
        },
        (TypeKind::String, "parse_bool") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::option(TypeDescriptor::BOOL)
                .map_err(|_| AnalysisError::Invariant)?,
        },
        (TypeKind::String, "parse_int") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::option(TypeDescriptor::INT)
                .map_err(|_| AnalysisError::Invariant)?,
        },
        (TypeKind::String, "parse_float") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::option(TypeDescriptor::FLOAT)
                .map_err(|_| AnalysisError::Invariant)?,
        },
        (TypeKind::List, "len") => CallableSignature {
            parameters: no_parameters,
            result: TypeDescriptor::INT,
        },
        (TypeKind::List, "join")
            if receiver.immediate_members().first() == Some(&TypeDescriptor::STRING) =>
        {
            CallableSignature {
                parameters: vec![TypeDescriptor::STRING],
                result: TypeDescriptor::STRING,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(signature))
}

fn infer_call_sequence(
    tree: &SyntaxTree,
    children: &[NodeId],
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected_result: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(open) = children
        .iter()
        .position(|child| node_contains_punctuation(tree, *child, Punctuation::LeftParenthesis))
    else {
        return Ok(None);
    };
    let Some(path_id) = children
        .get(..open)
        .unwrap_or_default()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Path))
        })
    else {
        return Ok(None);
    };
    let path = tree.node(path_id).ok_or(AnalysisError::Invariant)?;
    let Some(target) = context.references.get(path.span()).copied() else {
        return Ok(None);
    };
    if let Some(trait_path) = context.trait_symbols.get(&target) {
        return infer_qualified_trait_call(
            tree,
            children,
            open,
            path,
            trait_path,
            facts,
            environment,
            expected_result,
            context,
            diagnostics,
        );
    }
    if let Some(signature) = context.generic_callables.get(&target) {
        return infer_generic_call(
            tree,
            children,
            open,
            path,
            signature,
            facts,
            environment,
            expected_result,
            context,
            diagnostics,
        );
    }
    let Some(signature) = context.callables.get(&target) else {
        if context.actions.contains_key(&target) {
            diagnostics.push(body_diagnostic(
                "invalid-call-target",
                DiagnosticCategory::Type,
                "an ordinary call resolves to a declared action",
                path.span().clone(),
                [] as [(&str, &str); 0],
            )?);
        }
        return Ok(None);
    };
    let close = children
        .iter()
        .enumerate()
        .skip(open.saturating_add(1))
        .find(|(_, child)| node_is_punctuation(tree, **child, Punctuation::RightParenthesis))
        .map_or(children.len(), |(index, _)| index);
    if let Some(source) = context.callable_sources.get(&target).cloned() {
        let call_site =
            call_sequence_span(tree, children, path).unwrap_or_else(|| path.span().clone());
        if let Some(caller) = context.current_effect_owner.borrow().clone() {
            context.resolved_calls.borrow_mut().insert(
                (
                    caller,
                    call_site.clone(),
                    EffectNode::Source(source.clone()),
                ),
                None,
            );
        }
        record_effect_call(context, EffectNode::Source(source), call_site);
    }
    let arguments = children
        .get(open.saturating_add(1)..close)
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect::<Vec<_>>();
    if arguments.len() != signature.parameters.len() {
        diagnostics.push(body_diagnostic(
            "call-arity",
            DiagnosticCategory::Type,
            "a workflow call has the wrong number of arguments",
            path.span().clone(),
            [
                ("actual", arguments.len().to_string()),
                ("expected", signature.parameters.len().to_string()),
            ],
        )?);
    }
    for (argument, expected) in arguments.iter().zip(&signature.parameters) {
        if let Some(actual) = infer_expression(
            tree,
            *argument,
            facts,
            environment,
            Some(expected),
            context,
            diagnostics,
        )? && &actual != expected
        {
            diagnostics.push(body_diagnostic(
                "call-argument-type",
                DiagnosticCategory::Type,
                "a workflow argument differs from its exact parameter type",
                tree.node(*argument)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [
                    ("actual", actual.canonical_string()),
                    ("expected", expected.canonical_string()),
                ],
            )?);
        }
    }
    Ok(Some(signature.result.clone()))
}

#[allow(clippy::too_many_arguments)]
fn infer_qualified_trait_call(
    tree: &SyntaxTree,
    children: &[NodeId],
    open: usize,
    path: &gantry_frontend::SyntaxNode,
    trait_path: &CanonicalPath,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected_result: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let path_index = children
        .get(..open)
        .unwrap_or_default()
        .iter()
        .position(|child| {
            tree.node(*child)
                .is_some_and(|node| std::ptr::eq(node, path))
        })
        .ok_or(AnalysisError::Invariant)?;
    let separate_method = children
        .get(path_index.saturating_add(1)..open)
        .unwrap_or_default()
        .iter()
        .enumerate()
        .filter_map(|(offset, child)| tree.node(*child).map(|node| (offset, node)))
        .rfind(|(_, node)| matches!(node.form(), SyntaxForm::Token(TokenKind::Identifier(_))))
        .map(|(offset, node)| (path_index.saturating_add(1).saturating_add(offset), node));
    let (method_index, method_node) = if let Some((index, node)) = separate_method {
        (Some(index), node)
    } else {
        let node = path
            .children()
            .iter()
            .filter_map(|child| tree.node(*child))
            .rfind(|node| matches!(node.form(), SyntaxForm::Token(TokenKind::Identifier(_))))
            .ok_or(AnalysisError::Invariant)?;
        (None, node)
    };
    let SyntaxForm::Token(TokenKind::Identifier(method)) = method_node.form() else {
        return Err(AnalysisError::Invariant);
    };
    let explicit_trait_arguments = children
        .get(path_index.saturating_add(1)..method_index.unwrap_or(path_index.saturating_add(1)))
        .unwrap_or_default()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::TypeArgumentList))
        })
        .map(|list| closed_type_arguments(tree, list, context))
        .transpose()?;
    let explicit_method_arguments = children
        .get(
            method_index.map_or(path_index.saturating_add(1), |index| {
                index.saturating_add(1)
            })..open,
        )
        .unwrap_or_default()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::TypeArgumentList))
        })
        .map(|list| closed_type_arguments(tree, list, context))
        .transpose()?;
    let close = children
        .iter()
        .enumerate()
        .skip(open.saturating_add(1))
        .find(|(_, child)| node_is_punctuation(tree, **child, Punctuation::RightParenthesis))
        .map_or(children.len(), |(index, _)| index);
    let arguments = children
        .get(open.saturating_add(1)..close)
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect::<Vec<_>>();
    let Some(receiver_expression) = arguments.first().copied() else {
        diagnostics.push(body_diagnostic(
            "call-arity",
            DiagnosticCategory::Type,
            "a qualified trait call requires its receiver as the first argument",
            method_node.span().clone(),
            [] as [(&str, &str); 0],
        )?);
        return Ok(None);
    };
    let Some(receiver) = infer_expression(
        tree,
        receiver_expression,
        facts,
        environment,
        None,
        context,
        diagnostics,
    )?
    else {
        return Ok(None);
    };
    let value_arguments = arguments.get(1..).unwrap_or_default();
    let mut actual_arguments = Vec::with_capacity(value_arguments.len());
    for argument in value_arguments {
        let Some(actual) = infer_expression(
            tree,
            *argument,
            facts,
            environment,
            None,
            context,
            diagnostics,
        )?
        else {
            return Ok(None);
        };
        actual_arguments.push(actual);
    }
    let Some((signature, retained)) = resolve_trait_method(
        &receiver,
        method,
        Some(trait_path),
        explicit_trait_arguments.as_deref(),
        explicit_method_arguments.as_deref(),
        Some(&actual_arguments),
        expected_result,
        context,
        method_node,
        diagnostics,
    )?
    else {
        return Ok(None);
    };
    if let Some(resolution) = retained {
        retain_generic_instantiation(
            &resolution.signature,
            resolution.concrete_arguments,
            method_node,
            method_node.span(),
            context,
            diagnostics,
        )?;
    }
    if value_arguments.len() != signature.parameters.len() {
        diagnostics.push(body_diagnostic(
            "call-arity",
            DiagnosticCategory::Type,
            "a qualified trait call has the wrong number of value arguments",
            method_node.span().clone(),
            [
                ("actual", value_arguments.len().to_string()),
                ("expected", signature.parameters.len().to_string()),
            ],
        )?);
    }
    for ((argument, actual), expected) in value_arguments
        .iter()
        .zip(&actual_arguments)
        .zip(&signature.parameters)
    {
        if actual != expected {
            diagnostics.push(body_diagnostic(
                "call-argument-type",
                DiagnosticCategory::Type,
                "a qualified trait argument differs from its exact parameter type",
                tree.node(*argument)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [
                    ("actual", actual.canonical_string()),
                    ("expected", expected.canonical_string()),
                ],
            )?);
        }
    }
    Ok(Some(signature.result))
}

#[allow(clippy::too_many_arguments)]
fn infer_generic_call(
    tree: &SyntaxTree,
    children: &[NodeId],
    open: usize,
    path: &gantry_frontend::SyntaxNode,
    signature: &GenericCallableSignature,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected_result: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let close = children
        .iter()
        .enumerate()
        .skip(open.saturating_add(1))
        .find(|(_, child)| node_is_punctuation(tree, **child, Punctuation::RightParenthesis))
        .map_or(children.len(), |(index, _)| index);
    let arguments = children
        .get(open.saturating_add(1)..close)
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect::<Vec<_>>();
    if arguments.len() != signature.parameters.len() {
        diagnostics.push(body_diagnostic(
            "call-arity",
            DiagnosticCategory::Type,
            "a generic workflow call has the wrong number of value arguments",
            path.span().clone(),
            [
                ("actual", arguments.len().to_string()),
                ("expected", signature.parameters.len().to_string()),
            ],
        )?);
        return Ok(None);
    }

    let mut actual_arguments = Vec::with_capacity(arguments.len());
    let mut constraints = Vec::with_capacity(arguments.len().saturating_add(1));
    for (argument, template) in arguments.iter().zip(&signature.parameters) {
        let Some(actual) = infer_expression(
            tree,
            *argument,
            facts,
            environment,
            None,
            context,
            diagnostics,
        )?
        else {
            return Ok(None);
        };
        let actual_expression =
            TypeExpression::closed(&actual, u64::MAX).map_err(|_| AnalysisError::Invariant)?;
        constraints.push((template.clone(), actual_expression));
        actual_arguments.push(actual);
    }
    if let Some(expected) = expected_result {
        constraints.push((
            signature.result.clone(),
            TypeExpression::closed(expected, u64::MAX).map_err(|_| AnalysisError::Invariant)?,
        ));
    }

    let explicit = children
        .get(..open)
        .unwrap_or_default()
        .iter()
        .copied()
        .find_map(|child| {
            let node = tree.node(child)?;
            matches!(node.form(), SyntaxForm::TypeArgumentList).then_some(node)
        })
        .map(|list| {
            list.children()
                .iter()
                .filter_map(|child| tree.node(*child))
                .filter(|node| matches!(node.form(), SyntaxForm::ValueType))
                .map(|node| {
                    let expression = context
                        .generic_types
                        .get(node.span())
                        .ok_or(TypeInferenceFailure::Incomplete)?;
                    if expression.is_closed() {
                        expression
                            .to_descriptor(u64::MAX)
                            .map_err(|_| TypeInferenceFailure::Incomplete)
                    } else {
                        context
                            .current_type_substitution
                            .borrow()
                            .as_ref()
                            .ok_or(TypeInferenceFailure::Incomplete)?
                            .apply(expression)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose();

    let substitution = match explicit {
        Ok(Some(arguments)) => ExactTypeSubstitution::explicit(&signature.required, &arguments),
        Ok(None) => ExactTypeSubstitution::infer(&signature.required, &constraints),
        Err(error) => Err(error),
    };
    let substitution = match substitution {
        Ok(substitution) => substitution,
        Err(error) => {
            let code = match error {
                TypeInferenceFailure::Arity => GenericAnalysisCode::TypeArgumentArity,
                TypeInferenceFailure::Conflict | TypeInferenceFailure::OccursCheck => {
                    GenericAnalysisCode::ConflictingTypeInference
                }
                TypeInferenceFailure::Incomplete | TypeInferenceFailure::InvalidOptionMember => {
                    GenericAnalysisCode::IncompleteTypeInference
                }
            };
            diagnostics.push(body_diagnostic(
                code.wire_name(),
                DiagnosticCategory::Type,
                "generic call type inference did not produce one complete substitution",
                path.span().clone(),
                [] as [(&str, &str); 0],
            )?);
            return Ok(None);
        }
    };

    let mut instantiated_parameters = Vec::with_capacity(signature.parameters.len());
    for parameter in &signature.parameters {
        let Some(parameter) =
            apply_generic_type_or_diagnose(&substitution, parameter, path.span(), diagnostics)?
        else {
            return Ok(None);
        };
        instantiated_parameters.push(parameter);
    }
    let Some(instantiated_result) =
        apply_generic_type_or_diagnose(&substitution, &signature.result, path.span(), diagnostics)?
    else {
        return Ok(None);
    };
    if diagnose_invalid_inferred_option_member(
        &instantiated_result,
        path.span(),
        context,
        diagnostics,
    )? {
        return Ok(None);
    }
    for ((argument, actual), template) in arguments
        .iter()
        .zip(&actual_arguments)
        .zip(&instantiated_parameters)
    {
        if template != actual {
            diagnostics.push(body_diagnostic(
                "call-argument-type",
                DiagnosticCategory::Type,
                "a generic workflow argument differs from its substituted parameter type",
                tree.node(*argument)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [
                    ("actual", actual.canonical_string()),
                    ("expected", template.canonical_string()),
                ],
            )?);
        }
    }
    let concrete_arguments = signature
        .required
        .iter()
        .map(|parameter| {
            let expression =
                TypeExpression::parameter(parameter.binder_depth, parameter.ordinal, u64::MAX)
                    .map_err(|_| AnalysisError::Invariant)?;
            substitution
                .apply(&expression)
                .map_err(|_| AnalysisError::Invariant)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let call_site = call_sequence_span(tree, children, path).unwrap_or_else(|| path.span().clone());
    retain_generic_instantiation(
        signature,
        concrete_arguments,
        path,
        &call_site,
        context,
        diagnostics,
    )?;
    Ok(Some(instantiated_result))
}

/// Rejects an inferred descriptor whose instantiated declarations hide an invalid option.
fn diagnose_invalid_inferred_option_member(
    descriptor: &TypeDescriptor,
    span: &SourceSpan,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<bool, AnalysisError> {
    let key = descriptor.canonical_string();
    let invalid = if let Some(invalid) = context.invalid_option_members.borrow().get(&key) {
        invalid.clone()
    } else {
        let invalid = invalid_generic_option_member_declaration(
            descriptor,
            &context.capability_declarations,
            &mut context.generic_analysis_counters.borrow_mut(),
        )?;
        context
            .invalid_option_members
            .borrow_mut()
            .insert(key, invalid.clone());
        invalid
    };
    if invalid.is_none() {
        return Ok(false);
    }
    diagnostics.push(body_diagnostic(
        "invalid-option-type",
        DiagnosticCategory::Type,
        "generic substitution gives Option an ambiguous immediate member type",
        span.clone(),
        [("type", descriptor.canonical_string())],
    )?);
    Ok(true)
}

/// Applies one closed generic type and reports a forbidden substituted option member.
fn apply_generic_type_or_diagnose(
    substitution: &ExactTypeSubstitution,
    expression: &TypeExpression,
    span: &SourceSpan,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    match substitution.apply(expression) {
        Ok(descriptor) => Ok(Some(descriptor)),
        Err(TypeInferenceFailure::InvalidOptionMember) => {
            diagnostics.push(body_diagnostic(
                "invalid-option-type",
                DiagnosticCategory::Type,
                "generic substitution gives Option an ambiguous immediate member type",
                span.clone(),
                [("type", expression.as_str())],
            )?);
            Ok(None)
        }
        Err(_) => Err(AnalysisError::Invariant),
    }
}

/// Checks callee capabilities using concrete types or the caller's rigid assumptions.
fn check_callable_sealed_bounds(
    signature: &GenericCallableSignature,
    arguments: &[TypeDescriptor],
    call_site: &gantry_frontend::SyntaxNode,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<bool, AnalysisError> {
    for predicate in &signature.sealed_predicates {
        let index = signature
            .required
            .iter()
            .position(|parameter| parameter == &predicate.parameter)
            .ok_or(AnalysisError::Invariant)?;
        let argument = arguments.get(index).ok_or(AnalysisError::Invariant)?;
        if !prove_sealed_capability(
            predicate.capability,
            argument,
            &context.capability_declarations,
            &mut context.generic_analysis_counters.borrow_mut(),
            &mut context.capability_proofs.borrow_mut(),
        )? {
            diagnostics.push(body_diagnostic(
                GenericAnalysisCode::UnsatisfiedBound.wire_name(),
                DiagnosticCategory::Type,
                "a generic workflow argument does not satisfy its sealed bound",
                call_site.span().clone(),
                [
                    ("capability", predicate.capability.wire_name()),
                    ("type", argument.canonical_string().as_str()),
                ],
            )?);
            return Ok(false);
        }
    }
    Ok(true)
}

/// Retains one generic instantiation of a call site.
///
/// `reference` is the authored callee reference that requests the instantiation, and it keeps
/// diagnostics and instantiation source origins on the callee the author wrote. `call_site` is the
/// whole call span, the same shape a monomorphic call registers, so operand lowering resolves the
/// call that a split operand reconstructs instead of falling back to the fragment walk.
fn retain_generic_instantiation(
    signature: &GenericCallableSignature,
    concrete_arguments: Vec<TypeDescriptor>,
    reference: &gantry_frontend::SyntaxNode,
    call_site: &SourceSpan,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if context.parametric_validation.get() {
        record_effect_call(
            context,
            EffectNode::Template(signature.template.clone()),
            call_site.clone(),
        );
        check_callable_sealed_bounds(
            signature,
            &concrete_arguments,
            reference,
            context,
            diagnostics,
        )?;
        return Ok(());
    }
    let key = (signature.template.clone(), concrete_arguments.clone());
    context
        .generic_instantiation_origins
        .borrow_mut()
        .entry(key.clone())
        .or_default()
        .insert(reference.span().clone());
    if let Some(caller) = context.current_effect_owner.borrow().clone() {
        let selected_implementation = matches!(signature.kind, TemplateKind::TraitMethod)
            .then(|| signature.implementation.clone())
            .flatten();
        context.resolved_calls.borrow_mut().insert(
            (caller, call_site.clone(), EffectNode::Concrete(key.clone())),
            selected_implementation,
        );
    }
    record_effect_call(
        context,
        EffectNode::Concrete(key.clone()),
        call_site.clone(),
    );
    if context.generic_instantiations.borrow().contains_key(&key) {
        return Ok(());
    }
    let witness = if let Some((_, witness)) = context.current_instantiation.borrow().clone() {
        if witness
            .iter()
            .any(|ancestor| ancestor.0 == key.0 && ancestor.1 != key.1)
        {
            let mut cycle = witness;
            cycle.push(key);
            diagnostics.push(body_diagnostic(
                GenericAnalysisCode::PolymorphicRecursion.wire_name(),
                DiagnosticCategory::Type,
                "a generic callable recursively changes its own type arguments",
                reference.span().clone(),
                [("instantiation_witness", instantiation_witness(&cycle))],
            )?);
            return Ok(());
        }
        let mut nested = witness;
        nested.push(key.clone());
        nested
    } else {
        vec![key.clone()]
    };
    if let Some(counters) = context.generic_analysis_counters.borrow_mut().as_mut() {
        counters
            .charge_generic_instantiation()
            .map_err(|error| AnalysisError::ResourceLimit {
                error,
                diagnostics: Vec::new(),
            })?;
    }
    let substitution = ExactTypeSubstitution::explicit(&signature.required, &concrete_arguments)
        .map_err(|_| AnalysisError::Invariant)?;
    if !check_callable_sealed_bounds(
        signature,
        &concrete_arguments,
        reference,
        context,
        diagnostics,
    )? {
        return Ok(());
    }
    let concrete = match signature.kind {
        TemplateKind::FreeWorkflow => {
            CanonicalCallableIdentity::free(&signature.path, &concrete_arguments)
        }
        TemplateKind::InherentMethod => {
            let receiver = substitution
                .apply(
                    signature
                        .receiver
                        .as_ref()
                        .ok_or(AnalysisError::Invariant)?,
                )
                .map_err(|_| AnalysisError::Invariant)?;
            CanonicalCallableIdentity::inherent(
                &receiver,
                signature
                    .method_name
                    .as_deref()
                    .ok_or(AnalysisError::Invariant)?,
                concrete_arguments
                    .get(signature.implementation_parameter_count..)
                    .ok_or(AnalysisError::Invariant)?,
            )
            .map_err(|_| AnalysisError::Invariant)?
        }
        TemplateKind::TraitMethod => {
            let receiver = substitution
                .apply(
                    signature
                        .receiver
                        .as_ref()
                        .ok_or(AnalysisError::Invariant)?,
                )
                .map_err(|_| AnalysisError::Invariant)?;
            let trait_reference = signature
                .trait_reference
                .as_ref()
                .ok_or(AnalysisError::Invariant)?;
            let trait_arguments = trait_reference
                .arguments()
                .iter()
                .map(|argument| {
                    substitution
                        .apply(argument)
                        .map_err(|_| AnalysisError::Invariant)
                })
                .collect::<Result<Vec<_>, _>>()?;
            CanonicalCallableIdentity::trait_method(
                &receiver,
                trait_reference.path(),
                &trait_arguments,
                signature
                    .method_name
                    .as_deref()
                    .ok_or(AnalysisError::Invariant)?,
                concrete_arguments
                    .get(signature.implementation_parameter_count..)
                    .ok_or(AnalysisError::Invariant)?,
            )
            .map_err(|_| AnalysisError::Invariant)?
        }
        TemplateKind::DeclaredType => return Err(AnalysisError::Invariant),
    };
    let instantiation = ConcreteInstantiation::new(
        signature.kind,
        signature.template.clone(),
        concrete_arguments,
        ConcreteIdentity::Callable(concrete),
    )
    .map_err(|_| AnalysisError::Invariant)?;
    context
        .generic_instantiations
        .borrow_mut()
        .insert(key.clone(), instantiation);
    context
        .generic_instantiation_witnesses
        .borrow_mut()
        .insert(key, witness);
    Ok(())
}

fn instantiation_witness(witness: &[InstantiationKey]) -> String {
    witness
        .iter()
        .map(|(template, arguments)| {
            let mut value = template.as_str().to_owned();
            value.push_str(" => [");
            for (index, argument) in arguments.iter().enumerate() {
                if index > 0 {
                    value.push(',');
                }
                value.push_str(&argument.canonical_string());
            }
            value.push(']');
            value
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn direct_binary_operator(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<(Punctuation, usize)> {
    direct_binary_operator_in(tree, node.children())
}

fn direct_binary_operator_in(
    tree: &SyntaxTree,
    children: &[NodeId],
) -> Option<(Punctuation, usize)> {
    children
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, child)| match tree.node(*child)?.form() {
            SyntaxForm::Token(TokenKind::Punctuation(operator))
                if matches!(
                    operator,
                    Punctuation::Plus
                        | Punctuation::Minus
                        | Punctuation::Star
                        | Punctuation::Slash
                        | Punctuation::Percent
                        | Punctuation::EqualEqual
                        | Punctuation::NotEqual
                        | Punctuation::Less
                        | Punctuation::LessEqual
                        | Punctuation::Greater
                        | Punctuation::GreaterEqual
                        | Punctuation::AndAnd
                        | Punctuation::OrOr
                ) =>
            {
                Some((*operator, index))
            }
            _ => None,
        })
}

fn infer_binary_operator(
    operator: Punctuation,
    left: TypeDescriptor,
    right: TypeDescriptor,
    span: SourceSpan,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<TypeDescriptor, AnalysisError> {
    let result = match operator {
        Punctuation::Plus
            if left == right
                && matches!(
                    left.kind(),
                    TypeKind::Int | TypeKind::Float | TypeKind::String
                ) =>
        {
            Some(left.clone())
        }
        Punctuation::Minus | Punctuation::Star | Punctuation::Slash
            if left == right && matches!(left.kind(), TypeKind::Int | TypeKind::Float) =>
        {
            Some(left.clone())
        }
        Punctuation::Percent if left == TypeDescriptor::INT && right == TypeDescriptor::INT => {
            Some(TypeDescriptor::INT)
        }
        Punctuation::Less
        | Punctuation::LessEqual
        | Punctuation::Greater
        | Punctuation::GreaterEqual
            if left == right && matches!(left.kind(), TypeKind::Int | TypeKind::Float) =>
        {
            Some(TypeDescriptor::BOOL)
        }
        Punctuation::EqualEqual | Punctuation::NotEqual
            if left == right
                && prove_sealed_capability(
                    SealedCapability::Equatable,
                    &left,
                    &context.capability_declarations,
                    &mut context.generic_analysis_counters.borrow_mut(),
                    &mut context.capability_proofs.borrow_mut(),
                )? =>
        {
            Some(TypeDescriptor::BOOL)
        }
        Punctuation::AndAnd | Punctuation::OrOr
            if left == TypeDescriptor::BOOL && right == TypeDescriptor::BOOL =>
        {
            Some(TypeDescriptor::BOOL)
        }
        _ => None,
    };
    if let Some(result) = result {
        return Ok(result);
    }
    diagnostics.push(body_diagnostic(
        "invalid-primitive",
        DiagnosticCategory::Type,
        "a deterministic primitive has no signature for its operand types",
        span,
        [
            ("left", left.canonical_string()),
            ("right", right.canonical_string()),
        ],
    )?);
    Ok(left)
}

fn node_contains_punctuation(tree: &SyntaxTree, id: NodeId, expected: Punctuation) -> bool {
    tree.node(id).is_some_and(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::Punctuation(value)) if *value == expected)
            || node.children().iter().copied().any(|child| {
                tree.node(child).is_some_and(|child| {
                    matches!(child.form(), SyntaxForm::Token(TokenKind::Punctuation(value)) if *value == expected)
                })
            })
    })
}

fn node_is_punctuation(tree: &SyntaxTree, id: NodeId, expected: Punctuation) -> bool {
    tree.node(id).is_some_and(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::Punctuation(value)) if *value == expected)
    })
}

/// Returns the fragment child holding the parenthesis token that closes a call.
///
/// The call's opening parenthesis is introduced by the fragment child at `open`. An
/// argument of that call may itself be a receiver call and so owns parentheses of its
/// own, which a shallow containment check mistakes for the call's closing parenthesis and
/// truncates the argument list. Counting parenthesis depth over the fragment's tokens in
/// authored order identifies the token that actually closes the call. `None` reports that
/// the fragment holds no matching closing parenthesis.
fn split_call_close_index(tree: &SyntaxTree, children: &[NodeId], open: usize) -> Option<usize> {
    let mut depth = 0_u64;
    for (index, child) in children.iter().enumerate().skip(open) {
        let mut tokens = Vec::new();
        let mut work = vec![*child];
        while let Some(id) = work.pop() {
            let node = tree.node(id)?;
            if matches!(node.form(), SyntaxForm::Token(_)) {
                tokens.push(node);
            } else {
                work.extend(node.children().iter().rev().copied());
            }
        }
        for token in tokens {
            match token.form() {
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis)) => {
                    depth = depth.saturating_add(1);
                }
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis)) => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn infer_match(
    tree: &SyntaxTree,
    expression: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    expected: Option<&TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let node = tree.node(expression).ok_or(AnalysisError::Invariant)?;
    let scrutinee = node
        .children()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .ok_or(AnalysisError::Invariant)?;
    let Some(scrutinee_type) = infer_expression(
        tree,
        scrutinee,
        facts,
        environment,
        None,
        context,
        diagnostics,
    )?
    else {
        return Ok(None);
    };
    if scrutinee_type == TypeDescriptor::DECISION {
        diagnostics.push(body_diagnostic(
            "sealed-value-operation",
            DiagnosticCategory::Type,
            "Decision values cannot be pattern-matched",
            node.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    let universe = coverage_universe(&scrutinee_type, context)?;
    let saved = ObligationSnapshot::capture(context);
    let mut covered = BTreeSet::new();
    let mut result_type = None;
    let mut branch_states = Vec::new();
    for arm in node.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
    }) {
        let arm_node = tree.node(arm).ok_or(AnalysisError::Invariant)?;
        let pattern = direct_child_form(tree, arm_node, SyntaxForm::Pattern)
            .ok_or(AnalysisError::Invariant)?;
        let (keys, bindings) = pattern_coverage(
            tree,
            pattern,
            &scrutinee_type,
            &universe,
            context,
            diagnostics,
        )?;
        if !keys.is_empty() && keys.iter().all(|key| covered.contains(key)) {
            diagnostics.push(body_diagnostic(
                "redundant-pattern",
                DiagnosticCategory::ControlFlow,
                "a match arm is unreachable after preceding ordered patterns",
                tree.node(pattern)
                    .ok_or(AnalysisError::Invariant)?
                    .span()
                    .clone(),
                [] as [(&str, &str); 0],
            )?);
        }
        covered.extend(keys);
        let mut arm_environment = environment.clone();
        let payload_roots = pattern_payload_binding_names(tree, pattern, &bindings)?;
        arm_environment.extend(bindings.clone());
        let body = arm_node
            .children()
            .iter()
            .copied()
            .find(|child| {
                tree.node(*child).is_some_and(|node| {
                    matches!(node.form(), SyntaxForm::Expression | SyntaxForm::Block)
                })
            })
            .ok_or(AnalysisError::Invariant)?;
        let pattern_span = tree
            .node(pattern)
            .ok_or(AnalysisError::Invariant)?
            .span()
            .clone();
        saved.restore(context);
        enter_obligation_bindings(context, &bindings, &pattern_span);
        let checked = with_shared_receiver_payload_roots(context, payload_roots, || {
            if tree
                .node(body)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
            {
                Ok(check_block(
                    tree,
                    body,
                    facts,
                    &arm_environment,
                    expected.unwrap_or(&TypeDescriptor::UNIT),
                    context,
                    diagnostics,
                )?
                .trailing)
            } else {
                infer_expression(
                    tree,
                    body,
                    facts,
                    &arm_environment,
                    expected,
                    context,
                    diagnostics,
                )
            }
        });
        let actual = checked?;
        leave_obligation_scope(context, diagnostics)?;
        branch_states.push(ObligationSnapshot::capture(context));
        if let Some(actual) = actual {
            if let Some(previous) = &result_type {
                require_type(previous, &actual, arm_node.span().clone(), diagnostics)?;
            } else {
                result_type = Some(actual);
            }
        }
    }
    let exhaustive = !universe.is_empty() && universe.is_subset(&covered);
    merge_obligation_states(&saved, &branch_states, !exhaustive, context);
    if !exhaustive {
        diagnostics.push(body_diagnostic(
            "nonexhaustive-match",
            DiagnosticCategory::ControlFlow,
            "a structural match does not cover every value of its scrutinee type",
            node.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    Ok(result_type)
}

fn coverage_universe(
    scrutinee: &TypeDescriptor,
    context: &BodyContext,
) -> Result<BTreeSet<String>, AnalysisError> {
    Ok(match scrutinee.kind() {
        TypeKind::Option => ["none".to_owned(), "some".to_owned()].into_iter().collect(),
        TypeKind::Result => ["err".to_owned(), "ok".to_owned()].into_iter().collect(),
        TypeKind::OperationError => [
            "Cancelled",
            "Declined",
            "InvalidOutput",
            "PolicyDenied",
            "ProviderFailure",
            "Timeout",
            "UnknownOutcome",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        TypeKind::Declared => enum_shape_for_descriptor(context, scrutinee)?
            .as_ref()
            .map(|shape| shape.variants.keys().map(ToString::to_string).collect())
            .unwrap_or_default(),
        _ => BTreeSet::new(),
    })
}

fn enum_shape_for_descriptor(
    context: &BodyContext,
    descriptor: &TypeDescriptor,
) -> Result<Option<EnumShape>, AnalysisError> {
    if let Some(shape) = context
        .enums
        .values()
        .find(|shape| shape.descriptor == *descriptor)
    {
        return Ok(Some(shape.clone()));
    }
    let Some(path) = descriptor.declared_path() else {
        return Ok(None);
    };
    let Some(shape) = context
        .generic_enums
        .values()
        .find(|shape| shape.path == *path)
    else {
        return Ok(None);
    };
    let substitution =
        ExactTypeSubstitution::explicit(&shape.required, &descriptor.immediate_members())
            .map_err(|_| AnalysisError::Invariant)?;
    let variants = shape
        .variants
        .iter()
        .map(|(name, payload)| {
            let payload = match payload.as_ref().map(|payload| substitution.apply(payload)) {
                Some(Ok(payload)) => Some(payload),
                Some(Err(TypeInferenceFailure::InvalidOptionMember)) => return Ok(None),
                Some(Err(_)) => return Err(AnalysisError::Invariant),
                None => None,
            };
            Ok(Some((name.clone(), payload)))
        })
        .collect::<Result<Option<BTreeMap<_, _>>, _>>()?;
    let Some(variants) = variants else {
        return Ok(None);
    };
    Ok(Some(EnumShape {
        descriptor: descriptor.clone(),
        variants,
    }))
}

fn pattern_coverage(
    tree: &SyntaxTree,
    pattern: NodeId,
    scrutinee: &TypeDescriptor,
    universe: &BTreeSet<String>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<PatternAnalysis, AnalysisError> {
    let node = tree.node(pattern).ok_or(AnalysisError::Invariant)?;
    let mut bindings = BTreeMap::new();
    if node.children().iter().any(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Underscore))
            )
        })
    }) {
        return Ok((universe.clone(), bindings));
    }
    let word = node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => Some(word.spelling()),
            _ => None,
        });
    let compatible = match word {
        Some("None" | "Some") => scrutinee.kind() == TypeKind::Option,
        Some("Ok" | "Err") => scrutinee.kind() == TypeKind::Result,
        _ => true,
    };
    if !compatible {
        diagnostics.push(body_diagnostic(
            "incompatible-pattern",
            DiagnosticCategory::Type,
            "a pattern constructor is incompatible with the scrutinee type",
            node.span().clone(),
            [("scrutinee", scrutinee.canonical_string())],
        )?);
        return Ok((BTreeSet::new(), bindings));
    }
    if word == Some("None") {
        return Ok((["none".to_owned()].into_iter().collect(), bindings));
    }
    if word == Some("Some") {
        let member = scrutinee
            .immediate_members()
            .into_iter()
            .next()
            .unwrap_or(TypeDescriptor::UNIT);
        if let Some(nested) = direct_child_form(tree, node, SyntaxForm::Pattern) {
            bindings.extend(pattern_type_bindings(tree, nested, &member)?);
        }
        return Ok((["some".to_owned()].into_iter().collect(), bindings));
    }
    if matches!(word, Some("Ok" | "Err")) && scrutinee.kind() == TypeKind::Result {
        let members = scrutinee.immediate_members();
        let (key, member) = if word == Some("Ok") {
            ("ok", members.first())
        } else {
            ("err", members.get(1))
        };
        if let (Some(member), Some(nested)) =
            (member, direct_child_form(tree, node, SyntaxForm::Pattern))
        {
            bindings.extend(pattern_type_bindings(tree, nested, member)?);
        }
        return Ok(([key.to_owned()].into_iter().collect(), bindings));
    }
    if word == Some("OperationError") && scrutinee.kind() == TypeKind::OperationError {
        let identifiers = direct_identifiers(tree, pattern)?;
        let Some(variant) = identifiers.first() else {
            return Ok((BTreeSet::new(), bindings));
        };
        let payload = match variant.as_ref() {
            "Declined" | "ProviderFailure" | "Timeout" | "PolicyDenied" | "Cancelled" => {
                Some(TypeDescriptor::STRING)
            }
            "UnknownOutcome" => Some(
                TypeDescriptor::tuple(vec![TypeDescriptor::STRING, TypeDescriptor::STRING])
                    .map_err(|_| AnalysisError::Invariant)?,
            ),
            "InvalidOutput" => None,
            _ => return Ok((BTreeSet::new(), bindings)),
        };
        if let (Some(payload), Some(nested)) =
            (payload, direct_child_form(tree, node, SyntaxForm::Pattern))
        {
            bindings.extend(pattern_type_bindings(tree, nested, &payload)?);
        }
        return Ok(([variant.to_string()].into_iter().collect(), bindings));
    }
    if scrutinee.kind() == TypeKind::Declared {
        let identifiers = direct_identifiers(tree, pattern)?;
        if identifiers.len() >= 2
            && let Some(shape) = enum_shape_for_descriptor(context, scrutinee)?
            && let Some(variant) = identifiers.last()
            && let Some(payload) = shape.variants.get(variant)
        {
            if let Some(list) = direct_child_form(tree, node, SyntaxForm::TypeArgumentList) {
                let arguments = closed_type_arguments(tree, list, context)?;
                let expected = scrutinee.immediate_members();
                if arguments.len() != expected.len() {
                    diagnostics.push(body_diagnostic(
                        GenericAnalysisCode::TypeArgumentArity.wire_name(),
                        DiagnosticCategory::Type,
                        "an enum pattern has the wrong number of explicit type arguments",
                        node.span().clone(),
                        [
                            ("expected", expected.len().to_string()),
                            ("observed", arguments.len().to_string()),
                        ],
                    )?);
                    return Ok((BTreeSet::new(), bindings));
                }
                if arguments != expected {
                    diagnostics.push(body_diagnostic(
                        "pattern-type-mismatch",
                        DiagnosticCategory::Type,
                        "an explicit generic enum pattern differs from its scrutinee type",
                        node.span().clone(),
                        [
                            (
                                "pattern",
                                TypeDescriptor::declared_with_arguments(
                                    shape
                                        .descriptor
                                        .declared_path()
                                        .ok_or(AnalysisError::Invariant)?
                                        .clone(),
                                    arguments,
                                )
                                .canonical_string(),
                            ),
                            ("scrutinee", scrutinee.canonical_string()),
                        ],
                    )?);
                    return Ok((BTreeSet::new(), bindings));
                }
            }
            if let (Some(payload), Some(nested)) =
                (payload, direct_child_form(tree, node, SyntaxForm::Pattern))
            {
                bindings.extend(pattern_type_bindings(tree, nested, payload)?);
            }
            return Ok(([variant.to_string()].into_iter().collect(), bindings));
        }
    }
    if let Some(name) = direct_identifier(tree, pattern)?
        && !node
            .children()
            .iter()
            .copied()
            .any(|child| node_contains_punctuation(tree, child, Punctuation::PathSeparator))
    {
        bindings.insert(name, scrutinee.clone());
        return Ok((universe.clone(), bindings));
    }
    Ok((BTreeSet::new(), bindings))
}

fn token_type(
    token: &TokenKind,
    span: SourceSpan,
    expected: Option<&TypeDescriptor>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let value = match token {
        TokenKind::IntegerLiteral(value) => {
            if value
                .parse::<u64>()
                .map_or(true, |value| value > 9_007_199_254_740_991)
            {
                diagnostics.push(body_diagnostic(
                    "integer-literal-out-of-range",
                    DiagnosticCategory::Type,
                    "an integer literal exceeds the inclusive Gantry Int range",
                    span,
                    [("literal", value.as_ref())],
                )?);
            }
            Some(TypeDescriptor::INT)
        }
        TokenKind::FloatLiteral(_) => Some(TypeDescriptor::FLOAT),
        TokenKind::StringLiteral(_) | TokenKind::RawStringLiteral(_) => {
            Some(TypeDescriptor::STRING)
        }
        TokenKind::ReservedWord(word) if matches!(word.spelling(), "true" | "false") => {
            Some(TypeDescriptor::BOOL)
        }
        TokenKind::ReservedWord(word) if word.spelling() == "None" => expected
            .filter(|value| value.kind() == TypeKind::Option)
            .cloned()
            .or_else(|| {
                diagnostics.push(
                    body_diagnostic(
                        "ambiguous-constructor-type",
                        DiagnosticCategory::Type,
                        "None has no compatible expected Option type",
                        span,
                        [("constructor", "None")],
                    )
                    .ok()?,
                );
                None
            }),
        _ => None,
    };
    Ok(value)
}

fn require_type(
    expected: &TypeDescriptor,
    actual: &TypeDescriptor,
    span: SourceSpan,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if expected != actual {
        diagnostics.push(body_diagnostic(
            "type-mismatch",
            DiagnosticCategory::Type,
            "an expression type does not match its required exact type",
            span,
            [
                ("actual", actual.canonical_string()),
                ("expected", expected.canonical_string()),
            ],
        )?);
    }
    Ok(())
}

fn direct_child_form(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    form: SyntaxForm,
) -> Option<NodeId> {
    node.children().iter().copied().find(|child| {
        tree.node(*child).is_some_and(|node| {
            std::mem::discriminant(node.form()) == std::mem::discriminant(&form)
        })
    })
}

fn direct_identifier_span(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<SourceSpan> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(_)) => Some(node.span().clone()),
            _ => None,
        })
}

fn direct_identifier(tree: &SyntaxTree, node: NodeId) -> Result<Option<Arc<str>>, AnalysisError> {
    let node = tree.node(node).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        }))
}

fn direct_identifiers(tree: &SyntaxTree, node: NodeId) -> Result<Vec<Arc<str>>, AnalysisError> {
    let node = tree.node(node).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })
        .collect())
}

fn is_token(form: &SyntaxForm) -> bool {
    matches!(form, SyntaxForm::Token(_))
}

fn body_diagnostic<K, V, const N: usize>(
    code: &str,
    category: DiagnosticCategory,
    message: &str,
    primary: SourceSpan,
    fields: [(K, V); N],
) -> Result<StructuredDiagnostic, AnalysisError>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let fields = fields
        .into_iter()
        .map(|(key, value)| (Arc::from(key.as_ref()), Arc::from(value.as_ref())))
        .collect::<BTreeMap<_, _>>();
    StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Analysis,
            severity: DiagnosticSeverity::Error,
            category,
            code: DiagnosticCode::new(code).map_err(|_| AnalysisError::Invariant)?,
        },
        message,
        Some(primary),
        Vec::new(),
        fields,
    )
    .map_err(|_| AnalysisError::Invariant)
}
