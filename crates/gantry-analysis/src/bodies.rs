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
    ImplementationHead, Predicate, TraitContract, TraitMethodContract, TraitReference,
    TypeDescriptor, TypeDescriptorError, TypeExpression, WorkflowParameter,
};

use crate::generics::{
    ExactTypeSubstitution, TypeInferenceFailure, TypeParameterKey, collect_type_parameter_keys,
    collect_where_predicates, substitute_self_type,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoolFact {
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
    parameters: Vec<TypeExpression>,
    result: TypeExpression,
}

pub(crate) type InstantiationKey = (CanonicalTemplateIdentity, Vec<TypeDescriptor>);

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
}

pub(crate) struct BodyAnalysis {
    pub(crate) expression_types: Vec<BTreeMap<NodeId, TypeDescriptor>>,
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

pub(crate) struct ConcreteCallableMetadata {
    pub(crate) key: InstantiationKey,
    pub(crate) receiver: Option<TypeDescriptor>,
    pub(crate) mutable_receiver: bool,
    pub(crate) parameters: Vec<TypeDescriptor>,
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
    inherent_method_sources: BTreeMap<(TypeDescriptor, Arc<str>), SourceSpan>,
    action_effects: BTreeMap<SymbolId, Effect>,
    parametric_validation: Cell<bool>,
    generic_analysis_counters: RefCell<Option<GenericAnalysisCounters>>,
    trait_obligations: RefCell<BTreeMap<String, ObligationProof>>,
    expression_types: RefCell<BTreeMap<NodeId, TypeDescriptor>>,
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
                                parameters,
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
                    method_node.span().clone(),
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
        for implementation in tree.nodes() {
            if !matches!(implementation.form(), SyntaxForm::ImplDeclaration) {
                continue;
            }
            let Some(receiver_node) =
                direct_child_form(tree, implementation, SyntaxForm::ValueType)
            else {
                continue;
            };
            let receiver = tree
                .node(receiver_node)
                .and_then(|node| generic_types.get(node.span()))
                .cloned()
                .ok_or(AnalysisError::Invariant)?;
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
                    parameters,
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
    trait_contracts: &[TraitContract],
    implementation_heads: &[ImplementationHead],
    maximum_constructed_type_depth: Option<u64>,
    generic_analysis_counters: &mut Option<GenericAnalysisCounters>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<BodyAnalysis, AnalysisError> {
    let context = build_body_context(
        sources,
        facts,
        generic_facts,
        binders,
        structure,
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
        let mut closed_enums = BTreeMap::new();
        for descriptor in closed_types {
            if let Some(shape) = enum_shape_for_descriptor(&context, &descriptor)? {
                closed_enums.insert(descriptor, shape.variants);
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
        generic_declarations.extend(context.method_sources.values().cloned());
        context.expression_types.borrow_mut().clear();
        Ok(BodyAnalysis {
            expression_types,
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
                .map(|parameter| {
                    substitution
                        .apply_with_receiver(parameter, receiver.as_ref())
                        .map_err(|_| AnalysisError::Invariant)
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
            parameters,
            result: signature.result.clone(),
            effects: effects.get(&declaration).copied().unwrap_or_default(),
            declaration: declaration.clone(),
            direct_calls: source_direct_calls(context, &declaration),
        });
    }
    for ((receiver, method), declaration) in &context.inherent_method_sources {
        let (source_index, tree, callable) = find_source_callable(sources, declaration)?;
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
            parameters,
            result,
            effects: effects.get(declaration).copied().unwrap_or_default(),
            declaration: declaration.clone(),
            direct_calls: source_direct_calls(context, declaration),
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
        parameters.push(WorkflowParameter {
            mutable: node_has_reserved_word(tree, node, "mut"),
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
                CanonicalPath::new(&format!(
                    "crate::__gantry_parametric_{signature_index}_{parameter_index}"
                ))
                .map(TypeDescriptor::declared)
                .map_err(|_| AnalysisError::Invariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let substitution = ExactTypeSubstitution::explicit(&signature.required, &rigid_arguments)
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
    let mut work = vec![block];
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
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
        work.extend(node.children().iter().rev().copied());
    }
    let mut drafts = context.effect_drafts.borrow_mut();
    let draft = drafts.entry(owner).or_default();
    draft.direct = draft.direct.union(direct);
    draft.pure = node_has_reserved_word(tree, callable, "pure");
    draft.source = Some(callable.span().clone());
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
        if draft.pure && !effects.is_empty() {
            diagnostics.push(body_diagnostic(
                "impure-workflow",
                DiagnosticCategory::Type,
                "a pure generic workflow has a nonempty transitive inferred effect set",
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

fn record_effect_call(context: &BodyContext, callee: EffectNode) {
    let Some(owner) = context.current_effect_owner.borrow().clone() else {
        return;
    };
    context
        .effect_drafts
        .borrow_mut()
        .entry(owner)
        .or_default()
        .calls
        .insert(callee);
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
            environment.insert(name, fact.descriptor.clone());
        }
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
    let mut environment = inherited.clone();
    let mut reachable = true;
    let mut trailing = None;
    let mut breaks_loop = false;
    let mut continues_loop = false;
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
                let _ = infer_expression(
                    tree,
                    expression,
                    facts,
                    &environment,
                    None,
                    context,
                    diagnostics,
                )?;
            }
            SyntaxForm::SpawnStatement => {
                check_spawned_block(tree, child_node, facts, &environment, context, diagnostics)?;
            }
            SyntaxForm::ReturnStatement => {
                let expression = direct_child_form(tree, child_node, SyntaxForm::Expression);
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
                require_type(
                    expected_result,
                    &actual,
                    child_node.span().clone(),
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
            }
            SyntaxForm::MatchStatement => {
                reachable = check_match_statement(
                    tree,
                    child_node,
                    facts,
                    &environment,
                    expected_result,
                    context,
                    diagnostics,
                )?;
            }
            SyntaxForm::IfStatement => {
                let has_pattern = child_node.children().iter().copied().any(|nested| {
                    tree.node(nested)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
                });
                let mut pattern_environment = environment.clone();
                if has_pattern {
                    let pattern = direct_child_form(tree, child_node, SyntaxForm::Pattern)
                        .ok_or(AnalysisError::Invariant)?;
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
                        pattern_environment.extend(pattern_type_bindings(
                            tree,
                            pattern,
                            &scrutinee_type,
                        )?);
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
                    let result = check_block(
                        tree,
                        nested,
                        facts,
                        branch_environment,
                        expected_result,
                        context,
                        diagnostics,
                    )?;
                    branch_results.push(result);
                }
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
                let _ = check_block(
                    tree,
                    body,
                    facts,
                    &body_environment,
                    expected_result,
                    context,
                    diagnostics,
                )?;
            }
            SyntaxForm::LoopStatement | SyntaxForm::WhileStatement | SyntaxForm::UntilStatement => {
                check_loop_limit(tree, child_node, diagnostics)?;
                let condition = direct_child_form(tree, child_node, SyntaxForm::Expression);
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
                let body = direct_child_form(tree, child_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                let body_result = check_block(
                    tree,
                    body,
                    facts,
                    &environment,
                    expected_result,
                    context,
                    diagnostics,
                )?;
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
            }
            SyntaxForm::Expression => {
                let actual = infer_expression(
                    tree,
                    child,
                    facts,
                    &environment,
                    Some(expected_result),
                    context,
                    diagnostics,
                )?;
                let terminated = node
                    .children()
                    .get(child_index.saturating_add(1))
                    .and_then(|next| tree.node(*next))
                    .is_some_and(|next| matches!(next.form(), SyntaxForm::ExpressionStatement));
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
    Ok(BlockResult {
        falls_through: reachable,
        trailing,
        breaks_loop,
        continues_loop,
    })
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
) -> Result<bool, AnalysisError> {
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
        return Ok(true);
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
    let mut covered = BTreeSet::new();
    let mut any_fallthrough = false;
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
        arm_environment.extend(bindings);
        let body =
            direct_child_form(tree, arm_node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
        let result = check_block(
            tree,
            body,
            facts,
            &arm_environment,
            expected_result,
            context,
            diagnostics,
        )?;
        any_fallthrough |= result.falls_through;
    }
    let exhaustive = !universe.is_empty() && universe.is_subset(&covered);
    if !universe.is_empty() && !exhaustive {
        diagnostics.push(body_diagnostic(
            "nonexhaustive-match",
            DiagnosticCategory::ControlFlow,
            "a structural match does not cover every value of its scrutinee type",
            statement.span().clone(),
            [] as [(&str, &str); 0],
        )?);
    }
    Ok(!exhaustive || any_fallthrough)
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
            environment.extend(pattern_type_bindings(tree, pattern, &expected)?);
        }
    } else if let Some(name) = direct_identifier(tree, statement)? {
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
                diagnostics,
            )?;
            require_type(&expected, &result, node.span().clone(), diagnostics)?;
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

fn assignment_root_is_mutable(
    tree: &SyntaxTree,
    assignment: &SourceSpan,
    root: &Arc<str>,
    receiver: bool,
) -> Result<bool, AnalysisError> {
    let Some(callable) = tree
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node.form(),
                SyntaxForm::FunctionDeclaration | SyntaxForm::MethodDeclaration
            ) && span_contains(node.span(), assignment)
        })
        .min_by_key(|node| span_width(node.span()))
    else {
        return Ok(false);
    };

    if receiver {
        return Ok(callable.children().iter().copied().any(|child| {
            tree.node(child).is_some_and(|parameter| {
                matches!(parameter.form(), SyntaxForm::Parameter)
                    && node_has_reserved_word(tree, parameter, "self")
                    && node_has_reserved_word(tree, parameter, "mut")
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
                        && context
                            .enums
                            .values()
                            .any(|shape| shape.descriptor == current_type))
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

fn bool_fact(tree: &SyntaxTree, root: NodeId) -> Result<BoolFact, AnalysisError> {
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
            context,
            diagnostics,
        )?;
        if let (Some(left), Some(right)) = (left, right) {
            return infer_binary_operator(operator, left, right, node.span().clone(), diagnostics)
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
                    return Ok(environment.get(&name).cloned());
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
        SyntaxForm::JoinAllExpression => available.into_values().collect::<Vec<_>>(),
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
                TypeInferenceFailure::Incomplete => GenericAnalysisCode::IncompleteTypeInference,
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
        let expected_field = substitution
            .apply(&field.ty)
            .map_err(|_| AnalysisError::Invariant)?;
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
    substitution
        .apply(&application)
        .map(Some)
        .map_err(|_| AnalysisError::Invariant)
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
        return Ok(base.immediate_members().into_iter().next());
    }
    Ok(None)
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
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    if let Some((operator, index)) = direct_binary_operator_in(tree, children) {
        let left = infer_operand_sequence(
            tree,
            children.get(..index).unwrap_or_default(),
            facts,
            environment,
            context,
            diagnostics,
        )?;
        let right = infer_operand_sequence(
            tree,
            children.get(index.saturating_add(1)..).unwrap_or_default(),
            facts,
            environment,
            context,
            diagnostics,
        )?;
        if let (Some(left), Some(right)) = (left, right) {
            let span = children
                .first()
                .and_then(|child| tree.node(*child))
                .map(|node| node.span().clone())
                .ok_or(AnalysisError::Invariant)?;
            return infer_binary_operator(operator, left, right, span, diagnostics).map(Some);
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
    let Some(dot) = children
        .iter()
        .position(|child| node_contains_punctuation(tree, *child, Punctuation::Dot))
    else {
        return Ok(None);
    };
    let receiver = if let Some(receiver) = receiver {
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
        let Some(root) = root else {
            return Ok(None);
        };
        let Some(receiver) = environment.get(&root).cloned() else {
            return Ok(None);
        };
        receiver
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
        let close = children
            .iter()
            .enumerate()
            .skip(open.saturating_add(1))
            .find(|(_, child)| {
                node_contains_punctuation(tree, **child, Punctuation::RightParenthesis)
            })
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
        if let Some(source) = inherent_source.flatten() {
            record_effect_call(context, EffectNode::Source(source));
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
            retain_generic_instantiation(
                &resolution.signature,
                resolution.concrete_arguments,
                member_node,
                context,
                diagnostics,
            )?;
        }
        return Ok(Some(signature.result.clone()));
    }

    let field = if receiver == TypeDescriptor::DECISION {
        match member.as_ref() {
            "decision" => Some(TypeDescriptor::BOOL),
            "rationale" => Some(TypeDescriptor::STRING),
            _ => None,
        }
    } else {
        let closed = context
            .structs
            .values()
            .find(|shape| shape.descriptor == receiver)
            .and_then(|shape| shape.fields.get(&member))
            .map(|field| field.ty.clone());
        if closed.is_some() {
            closed
        } else {
            generic_field_type(&receiver, &member, context)?
        }
    };
    if let Some(field) = field {
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

fn generic_field_type(
    receiver: &TypeDescriptor,
    member: &str,
    context: &BodyContext,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(path) = receiver.declared_path() else {
        return Ok(None);
    };
    let arguments = receiver.immediate_members();
    let Some(shape) = context
        .generic_structs
        .values()
        .find(|shape| &shape.path == path && shape.required.len() == arguments.len())
    else {
        return Ok(None);
    };
    let Some(field) = shape.fields.get(member) else {
        return Ok(None);
    };
    let substitution = ExactTypeSubstitution::explicit(&shape.required, &arguments)
        .map_err(|_| AnalysisError::Invariant)?;
    substitution
        .apply(&field.ty)
        .map(Some)
        .map_err(|_| AnalysisError::Invariant)
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
                record_effect_call(context, effect_target);
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
    if let Some(source) = context.callable_sources.get(&target).cloned() {
        record_effect_call(context, EffectNode::Source(source));
    }
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
                TypeInferenceFailure::Incomplete => GenericAnalysisCode::IncompleteTypeInference,
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

    for ((argument, actual), template) in arguments
        .iter()
        .zip(&actual_arguments)
        .zip(&signature.parameters)
    {
        let instantiated = substitution
            .apply(template)
            .map_err(|_| AnalysisError::Invariant)?;
        if &instantiated != actual {
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
                    ("expected", instantiated.canonical_string()),
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
    retain_generic_instantiation(signature, concrete_arguments, path, context, diagnostics)?;
    substitution
        .apply(&signature.result)
        .map(Some)
        .map_err(|_| AnalysisError::Invariant)
}

fn retain_generic_instantiation(
    signature: &GenericCallableSignature,
    concrete_arguments: Vec<TypeDescriptor>,
    call_site: &gantry_frontend::SyntaxNode,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if context.parametric_validation.get() {
        record_effect_call(context, EffectNode::Template(signature.template.clone()));
        return Ok(());
    }
    let key = (signature.template.clone(), concrete_arguments.clone());
    context
        .generic_instantiation_origins
        .borrow_mut()
        .entry(key.clone())
        .or_default()
        .insert(call_site.span().clone());
    if let Some(caller) = context.current_effect_owner.borrow().clone() {
        let selected_implementation = matches!(signature.kind, TemplateKind::TraitMethod)
            .then(|| signature.implementation.clone())
            .flatten();
        context.resolved_calls.borrow_mut().insert(
            (
                caller,
                call_site.span().clone(),
                EffectNode::Concrete(key.clone()),
            ),
            selected_implementation,
        );
    }
    record_effect_call(context, EffectNode::Concrete(key.clone()));
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
                call_site.span().clone(),
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
            if left == right && !left.contains_sealed_boundary() =>
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
    let mut covered = BTreeSet::new();
    let mut result_type = None;
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
        arm_environment.extend(bindings);
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
        let actual = if tree
            .node(body)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
        {
            check_block(
                tree,
                body,
                facts,
                &arm_environment,
                expected.unwrap_or(&TypeDescriptor::UNIT),
                context,
                diagnostics,
            )?
            .trailing
        } else {
            infer_expression(
                tree,
                body,
                facts,
                &arm_environment,
                expected,
                context,
                diagnostics,
            )?
        };
        if let Some(actual) = actual {
            if let Some(previous) = &result_type {
                require_type(previous, &actual, arm_node.span().clone(), diagnostics)?;
            } else {
                result_type = Some(actual);
            }
        }
    }
    if !universe.is_empty() && !universe.is_subset(&covered) {
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
            payload
                .as_ref()
                .map(|payload| substitution.apply(payload))
                .transpose()
                .map(|payload| (name.clone(), payload))
                .map_err(|_| AnalysisError::Invariant)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
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
        if let Some(nested) = direct_child_form(tree, node, SyntaxForm::Pattern)
            && let Some(name) = direct_identifier(tree, nested)?
        {
            bindings.insert(name, member);
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
