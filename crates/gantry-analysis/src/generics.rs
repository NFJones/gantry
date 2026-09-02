//! Generic binders, trait contracts, coherence, and sealed capabilities.
//!
//! This pass retains open analyzer-only type expressions, proves closed
//! declaration bounds structurally, collects canonical user-trait contracts
//! and implementation heads, rejects incoherent implementations, and charges
//! portable generic-analysis work. Concrete user-trait selection occurs in
//! body typing; parametric body validation and executable monomorphization
//! remain separate later analyzer stages.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity, GenericAnalysisCode};
use gantry_core::source::{
    DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, FrontendResourceLimit,
    GenericAnalysisCounters, RelatedSpan, SourceSpan, StructuredDiagnostic,
};
use gantry_frontend::{NodeId, ParsedSource, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::{Effect, TypeExpressionKind, TypeKind};
use gantry_ir::{
    EffectSet, ImplementationHead, Predicate, TraitContract, TraitMethodContract, TraitReference,
    TypeDescriptor, TypeExpression,
};

use crate::{
    AnalysisError, GenericTypeFact, PackageStructure, Symbol, SymbolId, SymbolKind, TypeBinder,
    TypeBinderId, TypeParameterBinding,
};

#[derive(Clone)]
struct BinderDraft {
    source_index: usize,
    owner: NodeId,
    parent_owner: Option<NodeId>,
    declaration: SourceSpan,
    parameters: Vec<(Arc<str>, SourceSpan)>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TypeParameterKey {
    pub(crate) binder_depth: u64,
    pub(crate) ordinal: u64,
}

/// Returns every binder-qualified parameter used by canonical expressions.
pub(crate) fn collect_type_parameter_keys(
    expressions: &[&TypeExpression],
) -> Result<Vec<TypeParameterKey>, AnalysisError> {
    let mut parameters = BTreeSet::new();
    let mut work = expressions
        .iter()
        .map(|expression| expression.as_str().to_owned())
        .collect::<Vec<_>>();
    while let Some(expression) = work.pop() {
        match expression_root(&expression).map_err(|_| AnalysisError::Invariant)? {
            ExpressionRoot::Parameter(parameter) => {
                parameters.insert(parameter);
            }
            ExpressionRoot::Application { arguments, .. } => {
                work.extend(arguments.into_iter().map(str::to_owned));
            }
            ExpressionRoot::SelfType(_) => {}
        }
    }
    Ok(parameters.into_iter().collect())
}

/// Replaces contextual `Self` leaves with one concrete receiver expression.
pub(crate) fn substitute_self_type(
    expression: &TypeExpression,
    receiver: &TypeDescriptor,
) -> Result<TypeExpression, AnalysisError> {
    let mut output = String::with_capacity(expression.as_str().len());
    let mut cursor = 0_usize;
    while cursor < expression.as_str().len() {
        let suffix = expression
            .as_str()
            .get(cursor..)
            .ok_or(AnalysisError::Invariant)?;
        if suffix.starts_with("^self:") {
            let end = suffix.find([',', '>', '<']).unwrap_or(suffix.len());
            output.push_str(&receiver.canonical_string());
            cursor = cursor.checked_add(end).ok_or(AnalysisError::Invariant)?;
            continue;
        }
        let scalar = suffix.chars().next().ok_or(AnalysisError::Invariant)?;
        output.push(scalar);
        cursor = cursor
            .checked_add(scalar.len_utf8())
            .ok_or(AnalysisError::Invariant)?;
    }
    TypeExpression::from_canonical_string(&output, u64::MAX).map_err(|_| AnalysisError::Invariant)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactTypeSubstitution {
    bindings: BTreeMap<TypeParameterKey, TypeDescriptor>,
}

impl ExactTypeSubstitution {
    pub(crate) fn infer(
        required: &[TypeParameterKey],
        constraints: &[(TypeExpression, TypeExpression)],
    ) -> Result<Self, TypeInferenceFailure> {
        let mut open = BTreeMap::<TypeParameterKey, TypeExpression>::new();
        for (template, actual) in constraints {
            unify_type_expressions(template, actual, &mut open)?;
        }

        let mut bindings = BTreeMap::new();
        for parameter in required {
            let Some(expression) = open.get(parameter) else {
                return Err(TypeInferenceFailure::Incomplete);
            };
            let canonical = substitute_canonical(expression.as_str(), &open)?;
            let expression = TypeExpression::from_canonical_string(&canonical, u64::MAX)
                .map_err(|_| TypeInferenceFailure::Conflict)?;
            let descriptor = expression
                .to_descriptor(u64::MAX)
                .map_err(|_| TypeInferenceFailure::Incomplete)?;
            bindings.insert(*parameter, descriptor);
        }
        Ok(Self { bindings })
    }

    pub(crate) fn explicit(
        required: &[TypeParameterKey],
        arguments: &[TypeDescriptor],
    ) -> Result<Self, TypeInferenceFailure> {
        if required.len() != arguments.len() {
            return Err(TypeInferenceFailure::Arity);
        }
        Ok(Self {
            bindings: required
                .iter()
                .copied()
                .zip(arguments.iter().cloned())
                .collect(),
        })
    }

    pub(crate) fn apply(
        &self,
        expression: &TypeExpression,
    ) -> Result<TypeDescriptor, TypeInferenceFailure> {
        let open = self
            .bindings
            .iter()
            .map(|(key, descriptor)| {
                TypeExpression::closed(descriptor, u64::MAX)
                    .map(|expression| (*key, expression))
                    .map_err(|_| TypeInferenceFailure::Conflict)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let canonical = substitute_canonical(expression.as_str(), &open)?;
        TypeDescriptor::from_canonical_string(&canonical)
            .map_err(|_| TypeInferenceFailure::Incomplete)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TypeInferenceFailure {
    Arity,
    Conflict,
    Incomplete,
    OccursCheck,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExpressionRoot<'a> {
    Parameter(TypeParameterKey),
    SelfType(u64),
    Application {
        constructor: &'a str,
        arguments: Vec<&'a str>,
    },
}

fn unify_type_expressions(
    left: &TypeExpression,
    right: &TypeExpression,
    bindings: &mut BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<(), TypeInferenceFailure> {
    let mut work = vec![(left.as_str().to_owned(), right.as_str().to_owned())];
    while let Some((left, right)) = work.pop() {
        let left = resolve_parameter_alias(&left, bindings)?;
        let right = resolve_parameter_alias(&right, bindings)?;
        if left == right {
            continue;
        }
        match (expression_root(&left)?, expression_root(&right)?) {
            (ExpressionRoot::Parameter(parameter), _) => {
                bind_parameter(parameter, &right, bindings)?;
            }
            (_, ExpressionRoot::Parameter(parameter)) => {
                bind_parameter(parameter, &left, bindings)?;
            }
            (ExpressionRoot::SelfType(left), ExpressionRoot::SelfType(right)) if left == right => {}
            (
                ExpressionRoot::Application {
                    constructor: left_constructor,
                    arguments: left_arguments,
                },
                ExpressionRoot::Application {
                    constructor: right_constructor,
                    arguments: right_arguments,
                },
            ) if left_constructor == right_constructor
                && left_arguments.len() == right_arguments.len() =>
            {
                work.extend(
                    left_arguments
                        .into_iter()
                        .zip(right_arguments)
                        .rev()
                        .map(|(left, right)| (left.to_owned(), right.to_owned())),
                );
            }
            _ => return Err(TypeInferenceFailure::Conflict),
        }
    }
    Ok(())
}

fn bind_parameter(
    parameter: TypeParameterKey,
    expression: &str,
    bindings: &mut BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<(), TypeInferenceFailure> {
    if contains_parameter(expression, parameter, bindings)? {
        return Err(TypeInferenceFailure::OccursCheck);
    }
    let expression = TypeExpression::from_canonical_string(expression, u64::MAX)
        .map_err(|_| TypeInferenceFailure::Conflict)?;
    bindings.insert(parameter, expression);
    Ok(())
}

fn contains_parameter(
    expression: &str,
    parameter: TypeParameterKey,
    bindings: &BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<bool, TypeInferenceFailure> {
    let mut work = vec![expression.to_owned()];
    let mut visited = BTreeSet::new();
    while let Some(current) = work.pop() {
        match expression_root(&current)? {
            ExpressionRoot::Parameter(candidate) => {
                if candidate == parameter {
                    return Ok(true);
                }
                if visited.insert(candidate)
                    && let Some(bound) = bindings.get(&candidate)
                {
                    work.push(bound.as_str().to_owned());
                }
            }
            ExpressionRoot::Application { arguments, .. } => {
                work.extend(arguments.into_iter().map(str::to_owned));
            }
            ExpressionRoot::SelfType(_) => {}
        }
    }
    Ok(false)
}

fn resolve_parameter_alias(
    expression: &str,
    bindings: &BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<String, TypeInferenceFailure> {
    let mut current = expression.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        let ExpressionRoot::Parameter(parameter) = expression_root(&current)? else {
            return Ok(current);
        };
        let Some(bound) = bindings.get(&parameter) else {
            return Ok(current);
        };
        if !visited.insert(parameter) {
            return Err(TypeInferenceFailure::OccursCheck);
        }
        current = bound.as_str().to_owned();
    }
}

fn substitute_canonical(
    expression: &str,
    bindings: &BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<String, TypeInferenceFailure> {
    let mut current = expression.to_owned();
    for _ in 0..=bindings.len() {
        let mut output = String::with_capacity(current.len());
        let mut cursor = 0_usize;
        let mut changed = false;
        while cursor < current.len() {
            let suffix = current
                .get(cursor..)
                .ok_or(TypeInferenceFailure::Conflict)?;
            if suffix.starts_with("^self:") {
                return Err(TypeInferenceFailure::Incomplete);
            }
            if suffix.starts_with('^') {
                let end = suffix.find([',', '>', '<']).unwrap_or(suffix.len());
                let marker = suffix.get(..end).ok_or(TypeInferenceFailure::Conflict)?;
                let ExpressionRoot::Parameter(parameter) = expression_root(marker)? else {
                    return Err(TypeInferenceFailure::Conflict);
                };
                if let Some(bound) = bindings.get(&parameter) {
                    output.push_str(bound.as_str());
                    changed = true;
                } else {
                    output.push_str(marker);
                }
                cursor = cursor
                    .checked_add(end)
                    .ok_or(TypeInferenceFailure::Conflict)?;
                continue;
            }
            let scalar = suffix
                .chars()
                .next()
                .ok_or(TypeInferenceFailure::Conflict)?;
            output.push(scalar);
            cursor = cursor
                .checked_add(scalar.len_utf8())
                .ok_or(TypeInferenceFailure::Conflict)?;
        }
        if !changed {
            return if output.contains('^') {
                Err(TypeInferenceFailure::Incomplete)
            } else {
                Ok(output)
            };
        }
        current = output;
    }
    Err(TypeInferenceFailure::OccursCheck)
}

fn expression_root(expression: &str) -> Result<ExpressionRoot<'_>, TypeInferenceFailure> {
    if let Some(value) = expression.strip_prefix("^self:") {
        return parse_decimal(value).map(ExpressionRoot::SelfType);
    }
    if let Some(value) = expression.strip_prefix('^') {
        let (binder, ordinal) = value
            .split_once('.')
            .ok_or(TypeInferenceFailure::Conflict)?;
        return Ok(ExpressionRoot::Parameter(TypeParameterKey {
            binder_depth: parse_decimal(binder)?,
            ordinal: parse_decimal(ordinal)?,
        }));
    }
    let Some(open) = expression.find('<') else {
        return Ok(ExpressionRoot::Application {
            constructor: expression,
            arguments: Vec::new(),
        });
    };
    if !expression.ends_with('>') {
        return Err(TypeInferenceFailure::Conflict);
    }
    let constructor = expression
        .get(..open)
        .filter(|constructor| !constructor.is_empty())
        .ok_or(TypeInferenceFailure::Conflict)?;
    let body = expression
        .get(open.saturating_add(1)..expression.len().saturating_sub(1))
        .ok_or(TypeInferenceFailure::Conflict)?;
    Ok(ExpressionRoot::Application {
        constructor,
        arguments: split_top_level_arguments(body)?,
    })
}

fn split_top_level_arguments(expression: &str) -> Result<Vec<&str>, TypeInferenceFailure> {
    if expression.is_empty() {
        return Err(TypeInferenceFailure::Conflict);
    }
    let mut arguments = Vec::new();
    let mut depth = 0_u64;
    let mut start = 0_usize;
    for (index, byte) in expression.bytes().enumerate() {
        match byte {
            b'<' => depth = depth.checked_add(1).ok_or(TypeInferenceFailure::Conflict)?,
            b'>' => depth = depth.checked_sub(1).ok_or(TypeInferenceFailure::Conflict)?,
            b',' if depth == 0 => {
                arguments.push(
                    expression
                        .get(start..index)
                        .filter(|argument| !argument.is_empty())
                        .ok_or(TypeInferenceFailure::Conflict)?,
                );
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(TypeInferenceFailure::Conflict);
    }
    arguments.push(
        expression
            .get(start..)
            .filter(|argument| !argument.is_empty())
            .ok_or(TypeInferenceFailure::Conflict)?,
    );
    Ok(arguments)
}

fn parse_decimal(value: &str) -> Result<u64, TypeInferenceFailure> {
    if value.is_empty() || value.len() > 1 && value.starts_with('0') {
        return Err(TypeInferenceFailure::Conflict);
    }
    value.parse().map_err(|_| TypeInferenceFailure::Conflict)
}

/// Collects nested declaration binders and reports duplicate or shadowed parameters.
pub(crate) fn collect_type_binders(
    sources: &[ParsedSource],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Vec<TypeBinder>, AnalysisError> {
    diagnose_duplicate_where_predicates(sources, diagnostics)?;
    let mut drafts = Vec::new();
    for (source_index, source) in sources.iter().enumerate() {
        let tree = source.tree();
        let parents = parent_index(tree)?;
        let owners = tree
            .nodes()
            .iter()
            .enumerate()
            .filter_map(|(index, node)| {
                is_binder_owner(node.form()).then_some(NodeId::from_index(index))
            })
            .filter(|owner| direct_parameter_list(tree, *owner).is_some())
            .collect::<BTreeSet<_>>();

        for owner in owners.iter().copied() {
            let declaration = tree
                .node(owner)
                .ok_or(AnalysisError::Invariant)?
                .span()
                .clone();
            let list = direct_parameter_list(tree, owner).ok_or(AnalysisError::Invariant)?;
            let parameters = direct_identifiers(tree, list)?;
            let parent_owner = nearest_owner(owner, &parents, &owners);
            drafts.push(BinderDraft {
                source_index,
                owner,
                parent_owner,
                declaration,
                parameters,
            });
        }
    }

    drafts.sort_by(|left, right| left.declaration.cmp(&right.declaration));
    let ids = drafts
        .iter()
        .enumerate()
        .map(|(index, draft)| {
            let value = u32::try_from(index).map_err(|_| AnalysisError::Invariant)?;
            Ok(((draft.source_index, draft.owner), TypeBinderId::new(value)))
        })
        .collect::<Result<BTreeMap<_, _>, AnalysisError>>()?;

    let by_owner = drafts
        .iter()
        .map(|draft| ((draft.source_index, draft.owner), draft))
        .collect::<BTreeMap<_, _>>();
    let mut binders = Vec::with_capacity(drafts.len());
    for draft in &drafts {
        let id = *ids
            .get(&(draft.source_index, draft.owner))
            .ok_or(AnalysisError::Invariant)?;
        let parent = draft
            .parent_owner
            .and_then(|owner| ids.get(&(draft.source_index, owner)).copied());
        let depth = parent
            .map(|parent| binder_depth(parent, &binders))
            .transpose()?
            .unwrap_or(0);
        diagnose_parameters(draft, parent, &by_owner, diagnostics)?;
        let parameters = draft
            .parameters
            .iter()
            .cloned()
            .enumerate()
            .map(|(ordinal, (name, span))| {
                Ok(TypeParameterBinding {
                    binder: id,
                    ordinal: u64::try_from(ordinal).map_err(|_| AnalysisError::Invariant)?,
                    name,
                    span,
                })
            })
            .collect::<Result<Vec<_>, AnalysisError>>()?;
        binders.push(TypeBinder {
            id,
            parent,
            depth,
            declaration: draft.declaration.clone(),
            parameters,
        });
    }
    Ok(binders)
}

/// Rejects repeated authored predicates in every declaration-level where clause.
fn diagnose_duplicate_where_predicates(
    sources: &[ParsedSource],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for source in sources {
        let tree = source.tree();
        for clause in tree
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::WhereClause))
        {
            let mut first = BTreeMap::<String, SourceSpan>::new();
            for predicate in clause.children().iter().copied() {
                let predicate_node = tree.node(predicate).ok_or(AnalysisError::Invariant)?;
                if !matches!(predicate_node.form(), SyntaxForm::WherePredicate) {
                    continue;
                }
                let signature = predicate_token_signature(tree, predicate)?;
                if let Some(previous) = first.get(&signature) {
                    diagnostics.push(named_generic_diagnostic(
                        "duplicate-where-predicate",
                        "a where clause repeats one predicate",
                        predicate_node.span().clone(),
                        vec![RelatedSpan {
                            label: Arc::from("first predicate"),
                            span: previous.clone(),
                        }],
                        [] as [(&str, &str); 0],
                    )?);
                } else {
                    first.insert(signature, predicate_node.span().clone());
                }
            }
        }
    }
    Ok(())
}

fn predicate_token_signature(tree: &SyntaxTree, root: NodeId) -> Result<String, AnalysisError> {
    let mut signature = String::new();
    let mut work = vec![root];
    while let Some(id) = work.pop() {
        let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
        match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => {
                signature.push('i');
                signature.push_str(value);
                signature.push('\0');
            }
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => {
                signature.push('r');
                signature.push_str(word.spelling());
                signature.push('\0');
            }
            SyntaxForm::Token(TokenKind::Punctuation(punctuation)) => {
                signature.push('p');
                signature.push_str(punctuation.spelling());
                signature.push('\0');
            }
            _ => work.extend(node.children().iter().rev().copied()),
        }
    }
    Ok(signature)
}

/// Resolves every authored type to a canonical open-or-closed expression.
pub(crate) fn collect_generic_type_facts(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    binders: &[TypeBinder],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Vec<GenericTypeFact>, AnalysisError> {
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let binders_by_declaration = binders
        .iter()
        .map(|binder| (binder.declaration.clone(), binder))
        .collect::<BTreeMap<_, _>>();
    let parameter_names = binders
        .iter()
        .flat_map(|binder| {
            binder
                .parameters
                .iter()
                .map(|parameter| parameter.name.clone())
        })
        .collect::<BTreeSet<_>>();
    let arities = declared_type_arities(sources, structure)?;
    let mut facts = Vec::new();

    for source in sources {
        let tree = source.tree();
        let parents = parent_index(tree)?;
        let mut resolved = BTreeMap::<NodeId, TypeExpression>::new();
        for (index, node) in tree.nodes().iter().enumerate() {
            if !matches!(node.form(), SyntaxForm::ValueType) {
                continue;
            }
            let id = NodeId::from_index(index);
            let context = TypeResolutionContext {
                tree,
                parents: &parents,
                references: &references,
                symbols: &symbols,
                binders: &binders_by_declaration,
                parameter_names: &parameter_names,
                arities: &arities,
            };
            if let Some(expression) =
                resolve_generic_type_node(id, &resolved, &context, diagnostics)?
            {
                let descriptor = if expression.is_closed() {
                    let substitution = ExactTypeSubstitution::infer(
                        &[],
                        &[(expression.clone(), expression.clone())],
                    )
                    .map_err(|_| AnalysisError::Invariant)?;
                    Some(
                        substitution
                            .apply(&expression)
                            .map_err(|_| AnalysisError::Invariant)?,
                    )
                } else {
                    None
                };
                facts.push(GenericTypeFact {
                    span: node.span().clone(),
                    expression: expression.clone(),
                    descriptor,
                });
                resolved.insert(id, expression);
            }
        }
    }
    facts.sort_by(|left, right| left.span.cmp(&right.span));
    facts.dedup_by(|left, right| left.span == right.span);
    Ok(facts)
}

/// Charges each unique closed generic declared application once per activity.
pub(crate) fn charge_generic_instantiations(
    facts: &[GenericTypeFact],
    counters: &mut GenericAnalysisCounters,
) -> Result<(), FrontendResourceLimit> {
    let mut charged = BTreeSet::new();
    for fact in facts {
        let Some(descriptor) = fact.descriptor.as_ref() else {
            continue;
        };
        if descriptor.kind() != TypeKind::Declared
            || descriptor.immediate_members().is_empty()
            || !charged.insert(descriptor.canonical_string())
        {
            continue;
        }
        counters.charge_generic_instantiation()?;
    }
    Ok(())
}

/// Rejects implementation heads whose receiver has no concrete outer constructor.
pub(crate) fn check_implementation_heads(
    sources: &[ParsedSource],
    facts: &[GenericTypeFact],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let facts = facts
        .iter()
        .map(|fact| (fact.span.clone(), &fact.expression))
        .collect::<BTreeMap<_, _>>();
    for source in sources {
        let tree = source.tree();
        for implementation in tree
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::ImplDeclaration))
        {
            if direct_child(
                tree,
                implementation_id(tree, implementation)?,
                SyntaxForm::TraitReference,
            )
            .is_none()
            {
                continue;
            }
            let receiver = implementation
                .children()
                .iter()
                .copied()
                .find(|child| {
                    tree.node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                })
                .ok_or(AnalysisError::Invariant)?;
            let receiver_node = tree.node(receiver).ok_or(AnalysisError::Invariant)?;
            let Some(expression) = facts.get(receiver_node.span()).copied() else {
                continue;
            };
            let open_builtin = expression.kind() == TypeExpressionKind::BuiltinApplication
                && !expression.is_closed();
            if expression.kind() == TypeExpressionKind::Parameter || open_builtin {
                diagnostics.push(generic_diagnostic(
                    GenericAnalysisCode::InvalidImplementationHead,
                    "an implementation receiver must have a declared outer constructor or be a closed built-in type",
                    receiver_node.span().clone(),
                    vec![RelatedSpan {
                        label: Arc::from("implementation declaration"),
                        span: implementation.span().clone(),
                    }],
                    [("receiver", expression.as_str())],
                )?);
            }
        }
    }
    Ok(())
}

type TraitContractCollection = (Vec<TraitContract>, Vec<ImplementationHead>, Vec<SourceSpan>);

/// Collects canonical user-trait contracts and implementation heads.
pub(crate) fn collect_trait_contracts_and_implementation_heads(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    binders: &[TypeBinder],
    facts: &[GenericTypeFact],
) -> Result<TraitContractCollection, AnalysisError> {
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let symbols_by_id = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let symbols_by_span = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol))
        .collect::<BTreeMap<_, _>>();
    let binders = binders
        .iter()
        .map(|binder| (binder.declaration.clone(), binder))
        .collect::<BTreeMap<_, _>>();
    let facts = facts
        .iter()
        .map(|fact| (fact.span.clone(), &fact.expression))
        .collect::<BTreeMap<_, _>>();
    let mut traits = Vec::new();
    let mut implementations = Vec::new();

    for source in sources {
        let tree = source.tree();
        for (index, declaration) in tree.nodes().iter().enumerate() {
            match declaration.form() {
                SyntaxForm::TraitDeclaration => {
                    let owner = NodeId::from_index(index);
                    let name_span = direct_identifiers(tree, owner)?
                        .into_iter()
                        .next()
                        .map(|(_, span)| span)
                        .ok_or(AnalysisError::Invariant)?;
                    let Some(symbol) = symbols_by_span.get(&name_span).copied() else {
                        continue;
                    };
                    let parameter_count = binders
                        .get(declaration.span())
                        .map_or(0, |binder| binder.parameters.len());
                    let parameter_count =
                        u64::try_from(parameter_count).map_err(|_| AnalysisError::Invariant)?;
                    let mut methods = declaration
                        .children()
                        .iter()
                        .copied()
                        .filter(|child| {
                            tree.node(*child).is_some_and(|node| {
                                matches!(node.form(), SyntaxForm::TraitMethodDeclaration)
                            })
                        })
                        .map(|method| {
                            collect_trait_method(
                                tree,
                                method,
                                &binders,
                                &facts,
                                &references,
                                &symbols_by_id,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    methods.sort_by(|left, right| left.name().cmp(right.name()));
                    let predicates = collect_where_predicates(
                        tree,
                        owner,
                        binders.get(declaration.span()).copied(),
                        &facts,
                        &references,
                        &symbols_by_id,
                    )?;
                    traits.push(
                        TraitContract::new(
                            symbol.path.clone(),
                            parameter_count,
                            predicates,
                            methods,
                        )
                        .map_err(|_| AnalysisError::Invariant)?,
                    );
                }
                SyntaxForm::ImplDeclaration => {
                    let owner = NodeId::from_index(index);
                    let parameter_count = binders
                        .get(declaration.span())
                        .map_or(0, |binder| binder.parameters.len());
                    let parameter_count =
                        u64::try_from(parameter_count).map_err(|_| AnalysisError::Invariant)?;
                    let receiver = implementation_receiver_expression(
                        tree,
                        owner,
                        &facts,
                        &references,
                        &symbols_by_id,
                    )?;
                    let trait_reference = direct_child(tree, owner, SyntaxForm::TraitReference)
                        .map(|reference| {
                            collect_trait_reference(
                                tree,
                                reference,
                                &facts,
                                &references,
                                &symbols_by_id,
                            )
                        })
                        .transpose()?;
                    let predicates = collect_where_predicates(
                        tree,
                        owner,
                        binders.get(declaration.span()).copied(),
                        &facts,
                        &references,
                        &symbols_by_id,
                    )?;
                    implementations.push((
                        ImplementationHead::new(
                            parameter_count,
                            receiver,
                            trait_reference,
                            predicates,
                        )
                        .map_err(|_| AnalysisError::Invariant)?,
                        declaration.span().clone(),
                    ));
                }
                _ => {}
            }
        }
    }
    traits.sort_by(|left, right| left.path().cmp(right.path()));
    implementations.sort_by(|left, right| left.0.identity().cmp(right.0.identity()));
    let (implementations, implementation_spans) = implementations.into_iter().unzip();
    Ok((traits, implementations, implementation_spans))
}

/// Rejects pairwise-unifiable user-trait implementation heads in canonical order.
pub(crate) fn check_trait_implementation_coherence(
    sources: &[ParsedSource],
    contracts: &[TraitContract],
    implementations: &[ImplementationHead],
    spans: &[SourceSpan],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if implementations.len() != spans.len() {
        return Err(AnalysisError::Invariant);
    }
    let contract_arities = contracts
        .iter()
        .map(|contract| (contract.path(), contract.parameter_count()))
        .collect::<BTreeMap<_, _>>();
    for (implementation, span) in implementations.iter().zip(spans) {
        let mut expressions = vec![implementation.receiver()];
        if let Some(trait_reference) = implementation.trait_reference() {
            expressions.extend(trait_reference.arguments());
            let expected = contract_arities
                .get(trait_reference.path())
                .copied()
                .ok_or(AnalysisError::Invariant)?;
            let observed = u64::try_from(trait_reference.arguments().len())
                .map_err(|_| AnalysisError::Invariant)?;
            if observed != expected {
                diagnostics.push(generic_diagnostic(
                    GenericAnalysisCode::TypeArgumentArity,
                    "a trait reference has the wrong number of type arguments",
                    span.clone(),
                    Vec::new(),
                    [
                        ("expected", expected.to_string()),
                        ("observed", observed.to_string()),
                        ("trait", trait_reference.path().as_str().to_owned()),
                    ],
                )?);
            }
        }
        let constrained = collect_type_parameter_keys(&expressions)?;
        let constrained_count =
            u64::try_from(constrained.len()).map_err(|_| AnalysisError::Invariant)?;
        if constrained_count != implementation.parameter_count() {
            diagnostics.push(generic_diagnostic(
                GenericAnalysisCode::InvalidImplementationHead,
                "every implementation parameter must occur in its receiver or trait arguments",
                span.clone(),
                Vec::new(),
                [
                    (
                        "declared_parameters",
                        implementation.parameter_count().to_string(),
                    ),
                    ("constrained_parameters", constrained_count.to_string()),
                ],
            )?);
        }
    }
    for right in 1..implementations.len() {
        for left in 0..right {
            if trait_implementation_heads_unify(
                implementations.get(left).ok_or(AnalysisError::Invariant)?,
                implementations.get(right).ok_or(AnalysisError::Invariant)?,
            )? {
                diagnostics.push(generic_diagnostic(
                    GenericAnalysisCode::OverlappingImplementation,
                    "two trait implementation heads apply to a common concrete obligation",
                    spans.get(right).cloned().ok_or(AnalysisError::Invariant)?,
                    vec![RelatedSpan {
                        label: Arc::from("overlapping implementation"),
                        span: spans.get(left).cloned().ok_or(AnalysisError::Invariant)?,
                    }],
                    [
                        (
                            "first",
                            implementations[left].identity().as_str().to_owned(),
                        ),
                        (
                            "second",
                            implementations[right].identity().as_str().to_owned(),
                        ),
                    ],
                )?);
            }
        }
    }
    let method_names = inherent_method_names(sources)?;
    for right in 1..implementations.len() {
        let right_head = implementations.get(right).ok_or(AnalysisError::Invariant)?;
        if right_head.trait_reference().is_some() {
            continue;
        }
        for left in 0..right {
            let left_head = implementations.get(left).ok_or(AnalysisError::Invariant)?;
            if left_head.trait_reference().is_some()
                || !inherent_implementation_heads_unify(left_head, right_head)?
            {
                continue;
            }
            let left_span = spans.get(left).ok_or(AnalysisError::Invariant)?;
            let right_span = spans.get(right).ok_or(AnalysisError::Invariant)?;
            let left_methods = method_names
                .get(left_span)
                .ok_or(AnalysisError::Invariant)?;
            let right_methods = method_names
                .get(right_span)
                .ok_or(AnalysisError::Invariant)?;
            for method in left_methods.intersection(right_methods) {
                diagnostics.push(generic_diagnostic(
                    GenericAnalysisCode::OverlappingInherentMethod,
                    "two inherent implementation heads overlap for the same method",
                    right_span.clone(),
                    vec![RelatedSpan {
                        label: Arc::from("overlapping inherent implementation"),
                        span: left_span.clone(),
                    }],
                    [
                        ("first", left_head.identity().as_str().to_owned()),
                        ("method", method.as_ref().to_owned()),
                        ("second", right_head.identity().as_str().to_owned()),
                    ],
                )?);
            }
        }
    }
    Ok(())
}

fn inherent_method_names(
    sources: &[ParsedSource],
) -> Result<BTreeMap<SourceSpan, BTreeSet<Arc<str>>>, AnalysisError> {
    let mut names = BTreeMap::new();
    for source in sources {
        let tree = source.tree();
        for (index, implementation) in tree.nodes().iter().enumerate() {
            if !matches!(implementation.form(), SyntaxForm::ImplDeclaration) {
                continue;
            }
            let owner = NodeId::from_index(index);
            if direct_child(tree, owner, SyntaxForm::TraitReference).is_some() {
                continue;
            }
            let methods = implementation
                .children()
                .iter()
                .copied()
                .filter(|child| {
                    tree.node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::MethodDeclaration))
                })
                .map(|method| {
                    direct_identifiers(tree, method)?
                        .into_iter()
                        .next()
                        .map(|(name, _)| name)
                        .ok_or(AnalysisError::Invariant)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            names.insert(implementation.span().clone(), methods);
        }
    }
    Ok(names)
}

fn inherent_implementation_heads_unify(
    left: &ImplementationHead,
    right: &ImplementationHead,
) -> Result<bool, AnalysisError> {
    let offset = maximum_parameter_depth([left.receiver(), right.receiver()].into_iter())?
        .checked_add(1)
        .ok_or(AnalysisError::Invariant)?;
    let right_receiver = freshen_expression(right.receiver(), offset)?;
    let mut bindings = BTreeMap::new();
    Ok(unify_type_expressions(left.receiver(), &right_receiver, &mut bindings).is_ok())
}

/// Requires each trait implementation to define exactly its trait's methods.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_trait_implementation_methods(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    binders: &[TypeBinder],
    facts: &[GenericTypeFact],
    contracts: &[TraitContract],
    implementations: &[ImplementationHead],
    implementation_spans: &[SourceSpan],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    if implementations.len() != implementation_spans.len() {
        return Err(AnalysisError::Invariant);
    }
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    let binders = binders
        .iter()
        .map(|binder| (binder.declaration.clone(), binder))
        .collect::<BTreeMap<_, _>>();
    let facts = facts
        .iter()
        .map(|fact| (fact.span.clone(), &fact.expression))
        .collect::<BTreeMap<_, _>>();
    let contracts = contracts
        .iter()
        .map(|contract| (contract.path(), contract))
        .collect::<BTreeMap<_, _>>();
    let implementations = implementation_spans
        .iter()
        .zip(implementations)
        .collect::<BTreeMap<_, _>>();

    for source in sources {
        let tree = source.tree();
        for (index, implementation) in tree.nodes().iter().enumerate() {
            if !matches!(implementation.form(), SyntaxForm::ImplDeclaration) {
                continue;
            }
            let owner = NodeId::from_index(index);
            let Some(reference) = direct_child(tree, owner, SyntaxForm::TraitReference) else {
                continue;
            };
            let path =
                direct_child(tree, reference, SyntaxForm::Path).ok_or(AnalysisError::Invariant)?;
            let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
            let target = references
                .get(path_node.span())
                .copied()
                .ok_or(AnalysisError::Invariant)?;
            let trait_symbol = symbols
                .get(&target)
                .copied()
                .ok_or(AnalysisError::Invariant)?;
            let contract = contracts
                .get(&trait_symbol.path)
                .copied()
                .ok_or(AnalysisError::Invariant)?;
            let head = implementations
                .get(implementation.span())
                .copied()
                .ok_or(AnalysisError::Invariant)?;
            let mut methods = implementation
                .children()
                .iter()
                .copied()
                .filter(|child| {
                    tree.node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::MethodDeclaration))
                })
                .map(|method| {
                    collect_trait_method(tree, method, &binders, &facts, &references, &symbols)
                })
                .collect::<Result<Vec<_>, _>>()?;
            methods.sort_by(|left, right| left.name().cmp(right.name()));

            let mut complete = methods.len() == contract.methods().len();
            if complete {
                for (actual, expected) in methods.iter().zip(contract.methods()) {
                    if !trait_method_matches_head(actual, expected, contract, head)? {
                        complete = false;
                        break;
                    }
                }
            }
            if complete {
                continue;
            }
            diagnostics.push(generic_diagnostic(
                GenericAnalysisCode::ImplementationMethodMismatch,
                "a trait implementation does not exactly implement its trait methods",
                implementation.span().clone(),
                vec![RelatedSpan {
                    label: Arc::from("trait declaration"),
                    span: trait_symbol.span.clone(),
                }],
                [
                    ("implementation_method_count", methods.len().to_string()),
                    ("trait_method_count", contract.methods().len().to_string()),
                ],
            )?);
        }
    }
    Ok(())
}

fn trait_method_matches_head(
    actual: &TraitMethodContract,
    expected: &TraitMethodContract,
    contract: &TraitContract,
    implementation: &ImplementationHead,
) -> Result<bool, AnalysisError> {
    let reference = implementation
        .trait_reference()
        .ok_or(AnalysisError::Invariant)?;
    if reference.path() != contract.path()
        || reference.arguments().len()
            != usize::try_from(contract.parameter_count()).map_err(|_| AnalysisError::Invariant)?
        || actual.name() != expected.name()
        || actual.parameter_count() != expected.parameter_count()
        || actual.mutable_receiver() != expected.mutable_receiver()
        || !actual
            .effects()
            .iter()
            .all(|effect| expected.effects().contains(effect))
    {
        return Ok(false);
    }
    let substitutions = reference
        .arguments()
        .iter()
        .cloned()
        .enumerate()
        .map(|(ordinal, argument)| {
            Ok((
                TypeParameterKey {
                    binder_depth: 0,
                    ordinal: u64::try_from(ordinal).map_err(|_| AnalysisError::Invariant)?,
                },
                argument,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AnalysisError>>()?;
    let mut substitutions = substitutions;
    let expected_method_depth = u64::from(contract.parameter_count() > 0);
    let actual_method_depth = u64::from(implementation.parameter_count() > 0);
    for ordinal in 0..expected.parameter_count() {
        substitutions.insert(
            TypeParameterKey {
                binder_depth: expected_method_depth,
                ordinal,
            },
            TypeExpression::parameter(actual_method_depth, ordinal, u64::MAX)
                .map_err(|_| AnalysisError::Invariant)?,
        );
    }
    let expected_parameters = expected
        .parameters()
        .iter()
        .map(|parameter| substitute_selected_parameters(parameter, &substitutions))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_result = substitute_selected_parameters(expected.result(), &substitutions)?;
    let mut expected_predicates = expected
        .predicates()
        .iter()
        .map(|predicate| substitute_predicate_parameters(predicate, &substitutions))
        .collect::<Result<Vec<_>, _>>()?;
    expected_predicates.sort_by_key(Predicate::canonical_string);
    Ok(actual.parameters() == expected_parameters
        && actual.result() == &expected_result
        && actual.predicates() == expected_predicates)
}

fn substitute_predicate_parameters(
    predicate: &Predicate,
    substitutions: &BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<Predicate, AnalysisError> {
    let arguments = predicate
        .trait_reference()
        .arguments()
        .iter()
        .map(|argument| substitute_selected_parameters(argument, substitutions))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Predicate::new(
        TraitReference::new(predicate.trait_reference().path().clone(), arguments),
        substitute_selected_parameters(predicate.receiver(), substitutions)?,
    ))
}

fn substitute_selected_parameters(
    expression: &TypeExpression,
    substitutions: &BTreeMap<TypeParameterKey, TypeExpression>,
) -> Result<TypeExpression, AnalysisError> {
    let mut output = String::with_capacity(expression.as_str().len());
    let mut cursor = 0_usize;
    while cursor < expression.as_str().len() {
        let suffix = expression
            .as_str()
            .get(cursor..)
            .ok_or(AnalysisError::Invariant)?;
        if suffix.starts_with('^') && !suffix.starts_with("^self:") {
            let end = suffix.find([',', '>', '<']).unwrap_or(suffix.len());
            let marker = suffix.get(..end).ok_or(AnalysisError::Invariant)?;
            let ExpressionRoot::Parameter(parameter) =
                expression_root(marker).map_err(|_| AnalysisError::Invariant)?
            else {
                return Err(AnalysisError::Invariant);
            };
            output.push_str(
                substitutions
                    .get(&parameter)
                    .map_or(marker, TypeExpression::as_str),
            );
            cursor = cursor.checked_add(end).ok_or(AnalysisError::Invariant)?;
            continue;
        }
        let scalar = suffix.chars().next().ok_or(AnalysisError::Invariant)?;
        output.push(scalar);
        cursor = cursor
            .checked_add(scalar.len_utf8())
            .ok_or(AnalysisError::Invariant)?;
    }
    TypeExpression::from_canonical_string(&output, u64::MAX).map_err(|_| AnalysisError::Invariant)
}

fn trait_implementation_heads_unify(
    left: &ImplementationHead,
    right: &ImplementationHead,
) -> Result<bool, AnalysisError> {
    let (Some(left_trait), Some(right_trait)) = (left.trait_reference(), right.trait_reference())
    else {
        return Ok(false);
    };
    if left_trait.path() != right_trait.path()
        || left_trait.arguments().len() != right_trait.arguments().len()
    {
        return Ok(false);
    }
    let offset = maximum_parameter_depth(
        std::iter::once(left.receiver())
            .chain(left_trait.arguments())
            .chain(std::iter::once(right.receiver()))
            .chain(right_trait.arguments()),
    )?
    .checked_add(1)
    .ok_or(AnalysisError::Invariant)?;
    let right_receiver = freshen_expression(right.receiver(), offset)?;
    let right_arguments = right_trait
        .arguments()
        .iter()
        .map(|argument| freshen_expression(argument, offset))
        .collect::<Result<Vec<_>, _>>()?;
    let mut bindings = BTreeMap::new();
    if unify_type_expressions(left.receiver(), &right_receiver, &mut bindings).is_err() {
        return Ok(false);
    }
    for (left, right) in left_trait.arguments().iter().zip(&right_arguments) {
        if unify_type_expressions(left, right, &mut bindings).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn maximum_parameter_depth<'a>(
    expressions: impl Iterator<Item = &'a TypeExpression>,
) -> Result<u64, AnalysisError> {
    let mut maximum = 0_u64;
    let mut work = expressions
        .map(|expression| expression.as_str().to_owned())
        .collect::<Vec<_>>();
    while let Some(expression) = work.pop() {
        match expression_root(&expression).map_err(|_| AnalysisError::Invariant)? {
            ExpressionRoot::Parameter(parameter) => {
                maximum = maximum.max(parameter.binder_depth);
            }
            ExpressionRoot::SelfType(depth) => maximum = maximum.max(depth),
            ExpressionRoot::Application { arguments, .. } => {
                work.extend(arguments.into_iter().map(str::to_owned));
            }
        }
    }
    Ok(maximum)
}

fn freshen_expression(
    expression: &TypeExpression,
    binder_offset: u64,
) -> Result<TypeExpression, AnalysisError> {
    let mut output = String::with_capacity(expression.as_str().len());
    let mut cursor = 0_usize;
    while cursor < expression.as_str().len() {
        let suffix = expression
            .as_str()
            .get(cursor..)
            .ok_or(AnalysisError::Invariant)?;
        if suffix.starts_with("^self:") {
            return Err(AnalysisError::Invariant);
        }
        if suffix.starts_with('^') {
            let end = suffix.find([',', '>', '<']).unwrap_or(suffix.len());
            let marker = suffix.get(..end).ok_or(AnalysisError::Invariant)?;
            let ExpressionRoot::Parameter(parameter) =
                expression_root(marker).map_err(|_| AnalysisError::Invariant)?
            else {
                return Err(AnalysisError::Invariant);
            };
            let binder_depth = parameter
                .binder_depth
                .checked_add(binder_offset)
                .ok_or(AnalysisError::Invariant)?;
            output.push_str(&format!("^{binder_depth}.{}", parameter.ordinal));
            cursor = cursor.checked_add(end).ok_or(AnalysisError::Invariant)?;
            continue;
        }
        let scalar = suffix.chars().next().ok_or(AnalysisError::Invariant)?;
        output.push(scalar);
        cursor = cursor
            .checked_add(scalar.len_utf8())
            .ok_or(AnalysisError::Invariant)?;
    }
    TypeExpression::from_canonical_string(&output, u64::MAX).map_err(|_| AnalysisError::Invariant)
}

fn collect_trait_method(
    tree: &SyntaxTree,
    method: NodeId,
    binders: &BTreeMap<SourceSpan, &TypeBinder>,
    facts: &BTreeMap<SourceSpan, &TypeExpression>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
) -> Result<TraitMethodContract, AnalysisError> {
    let method_node = tree.node(method).ok_or(AnalysisError::Invariant)?;
    let name = direct_identifiers(tree, method)?
        .into_iter()
        .next()
        .map(|(name, _)| name)
        .ok_or(AnalysisError::Invariant)?;
    let parameter_count = binders
        .get(method_node.span())
        .map_or(0, |binder| binder.parameters.len());
    let parameter_count = u64::try_from(parameter_count).map_err(|_| AnalysisError::Invariant)?;
    let receiver = method_node
        .children()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Parameter))
        })
        .ok_or(AnalysisError::Invariant)?;
    let mutable_receiver = tree
        .node(receiver)
        .ok_or(AnalysisError::Invariant)?
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .any(|node| {
            matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "mut")
        });
    let parameters = method_node
        .children()
        .iter()
        .copied()
        .filter_map(|child| {
            let parameter = tree.node(child)?;
            matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
        })
        .filter(|parameter| {
            !parameter.children().iter().filter_map(|child| tree.node(*child)).any(|node| {
                matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self")
            })
        })
        .filter_map(|parameter| direct_child_node(tree, parameter, SyntaxForm::ValueType))
        .map(|type_node| {
            let span = tree.node(type_node).ok_or(AnalysisError::Invariant)?.span();
            facts.get(span).copied().cloned().ok_or(AnalysisError::Invariant)
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
            let span = tree.node(type_node).ok_or(AnalysisError::Invariant)?.span();
            facts
                .get(span)
                .copied()
                .cloned()
                .ok_or(AnalysisError::Invariant)
        })
        .transpose()?
        .unwrap_or(
            TypeExpression::closed(&TypeDescriptor::UNIT, u64::MAX)
                .map_err(|_| AnalysisError::Invariant)?,
        );
    let effects = direct_child(tree, method, SyntaxForm::EffectContract)
        .map(|contract| collect_effect_contract(tree, contract))
        .transpose()?
        .unwrap_or_default();
    let predicates = collect_where_predicates(
        tree,
        method,
        binders.get(method_node.span()).copied(),
        facts,
        references,
        symbols,
    )?;
    TraitMethodContract::new(
        &name,
        parameter_count,
        mutable_receiver,
        parameters,
        result,
        predicates,
        effects,
    )
    .map_err(|_| AnalysisError::Invariant)
}

fn collect_effect_contract(
    tree: &SyntaxTree,
    contract: NodeId,
) -> Result<EffectSet, AnalysisError> {
    let contract = tree.node(contract).ok_or(AnalysisError::Invariant)?;
    let mut effects = EffectSet::default();
    let tokens = contract
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        let spelling = match token.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => word.spelling(),
            SyntaxForm::Token(TokenKind::Identifier(value)) => value,
            _ => continue,
        };
        let effect = match spelling {
            "prompt" => Some(Effect::Prompt),
            "decide" => Some(Effect::Decide),
            "spawn" => Some(Effect::Spawn),
            "join" => Some(Effect::Join),
            "background" => Some(Effect::Background),
            "session" => Some(Effect::Session),
            "attempt" => Some(Effect::Attempt),
            "action" => match tokens.get(index.saturating_add(2)).map(|node| node.form()) {
                Some(SyntaxForm::Token(TokenKind::ReservedWord(word)))
                    if word.spelling() == "read_only" =>
                {
                    Some(Effect::ActionReadOnly)
                }
                Some(SyntaxForm::Token(TokenKind::ReservedWord(word)))
                    if word.spelling() == "idempotent" =>
                {
                    Some(Effect::ActionIdempotent)
                }
                Some(SyntaxForm::Token(TokenKind::ReservedWord(word)))
                    if word.spelling() == "non_idempotent" =>
                {
                    Some(Effect::ActionNonIdempotent)
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(effect) = effect {
            effects.insert(effect);
        }
    }
    Ok(effects)
}

fn implementation_receiver_expression(
    tree: &SyntaxTree,
    implementation: NodeId,
    facts: &BTreeMap<SourceSpan, &TypeExpression>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
) -> Result<TypeExpression, AnalysisError> {
    if let Some(receiver) = direct_child(tree, implementation, SyntaxForm::ValueType) {
        let span = tree.node(receiver).ok_or(AnalysisError::Invariant)?.span();
        return facts
            .get(span)
            .copied()
            .cloned()
            .ok_or(AnalysisError::Invariant);
    }
    let path =
        direct_child(tree, implementation, SyntaxForm::Path).ok_or(AnalysisError::Invariant)?;
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let target = references
        .get(path_node.span())
        .copied()
        .ok_or(AnalysisError::Invariant)?;
    let symbol = symbols
        .get(&target)
        .copied()
        .ok_or(AnalysisError::Invariant)?;
    TypeExpression::declared(symbol.path.clone(), Vec::new(), u64::MAX)
        .map_err(|_| AnalysisError::Invariant)
}

fn collect_trait_reference(
    tree: &SyntaxTree,
    reference: NodeId,
    facts: &BTreeMap<SourceSpan, &TypeExpression>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
) -> Result<TraitReference, AnalysisError> {
    let path = direct_child(tree, reference, SyntaxForm::Path).ok_or(AnalysisError::Invariant)?;
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let target = references
        .get(path_node.span())
        .copied()
        .ok_or(AnalysisError::Invariant)?;
    let symbol = symbols
        .get(&target)
        .copied()
        .ok_or(AnalysisError::Invariant)?;
    let arguments = direct_child(tree, reference, SyntaxForm::TypeArgumentList)
        .map(|list| {
            tree.node(list)
                .ok_or(AnalysisError::Invariant)?
                .children()
                .iter()
                .filter_map(|child| tree.node(*child))
                .filter(|node| matches!(node.form(), SyntaxForm::ValueType))
                .map(|node| {
                    facts
                        .get(node.span())
                        .copied()
                        .cloned()
                        .ok_or(AnalysisError::Invariant)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(TraitReference::new(symbol.path.clone(), arguments))
}

fn collect_where_predicates(
    tree: &SyntaxTree,
    owner: NodeId,
    binder: Option<&TypeBinder>,
    facts: &BTreeMap<SourceSpan, &TypeExpression>,
    references: &BTreeMap<SourceSpan, SymbolId>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
) -> Result<Vec<Predicate>, AnalysisError> {
    let Some(where_clause) = direct_child(tree, owner, SyntaxForm::WhereClause) else {
        return Ok(Vec::new());
    };
    let clause = tree.node(where_clause).ok_or(AnalysisError::Invariant)?;
    let mut predicates = Vec::new();
    for predicate in clause.children().iter().copied() {
        let predicate_node = tree.node(predicate).ok_or(AnalysisError::Invariant)?;
        if !matches!(predicate_node.form(), SyntaxForm::WherePredicate) {
            continue;
        }
        let receiver = if direct_reserved_word(tree, predicate)?.as_deref() == Some("Self") {
            TypeExpression::self_type(binder.map_or(0, |binder| binder.depth), u64::MAX)
                .map_err(|_| AnalysisError::Invariant)?
        } else {
            let Some((subject, _)) = direct_identifiers(tree, predicate)?.into_iter().next() else {
                continue;
            };
            let Some(parameter) = binder.and_then(|binder| {
                binder
                    .parameters
                    .iter()
                    .find(|parameter| parameter.name == subject)
            }) else {
                continue;
            };
            TypeExpression::parameter(
                binder.map_or(0, |binder| binder.depth),
                parameter.ordinal,
                u64::MAX,
            )
            .map_err(|_| AnalysisError::Invariant)?
        };
        let trait_reference = direct_child(tree, predicate, SyntaxForm::TraitReference)
            .ok_or(AnalysisError::Invariant)?;
        predicates.push(Predicate::new(
            collect_trait_reference(tree, trait_reference, facts, references, symbols)?,
            receiver,
        ));
    }
    predicates.sort_by(|left, right| {
        left.canonical_string()
            .as_bytes()
            .cmp(right.canonical_string().as_bytes())
    });
    Ok(predicates)
}

fn direct_child_node(
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

fn implementation_id(
    tree: &SyntaxTree,
    implementation: &gantry_frontend::SyntaxNode,
) -> Result<NodeId, AnalysisError> {
    tree.nodes()
        .iter()
        .position(|candidate| std::ptr::eq(candidate, implementation))
        .map(NodeId::from_index)
        .ok_or(AnalysisError::Invariant)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SealedCapability {
    Equatable,
    ExternalValue,
    Interpolatable,
}

impl SealedCapability {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Equatable => "Equatable",
            Self::ExternalValue => "ExternalValue",
            Self::Interpolatable => "Interpolatable",
        }
    }

    fn from_path(segments: &[(Arc<str>, SourceSpan)]) -> Option<Self> {
        if segments.len() != 1 {
            return None;
        }
        match segments.first()?.0.as_ref() {
            "Equatable" => Some(Self::Equatable),
            "ExternalValue" => Some(Self::ExternalValue),
            "Interpolatable" => Some(Self::Interpolatable),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct CapabilityPredicate {
    parameter: TypeParameterKey,
    capability: SealedCapability,
    span: SourceSpan,
}

struct GenericDeclarationShape {
    binder: Option<TypeBinder>,
    declaration: SourceSpan,
    members: Vec<TypeExpression>,
    predicates: Vec<CapabilityPredicate>,
}

struct CapabilityFrame {
    descriptor: TypeDescriptor,
    key: String,
    members: Option<Vec<TypeDescriptor>>,
    next_member: usize,
    satisfied: bool,
}

enum CapabilityNode {
    Leaf(bool),
    Members(Vec<TypeDescriptor>),
}

/// Proves every compiler-owned declaration predicate after complete substitution.
pub(crate) fn check_sealed_declaration_bounds(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    binders: &[TypeBinder],
    facts: &[GenericTypeFact],
    counters: &mut Option<GenericAnalysisCounters>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let declarations = collect_generic_declaration_shapes(sources, structure, binders, facts)?;
    let mut memo = BTreeMap::<(SealedCapability, String), bool>::new();

    for fact in facts {
        let Some(descriptor) = fact.descriptor.as_ref() else {
            continue;
        };
        let Some(path) = descriptor.declared_path() else {
            continue;
        };
        let Some(declaration) = declarations.get(path.as_str()) else {
            continue;
        };
        let arguments = descriptor.immediate_members();
        for predicate in &declaration.predicates {
            charge_trait_steps(counters, 1)?;
            let Some(argument) = arguments.get(predicate.parameter.ordinal as usize) else {
                return Err(AnalysisError::Invariant);
            };
            if prove_sealed_capability(
                predicate.capability,
                argument,
                &declarations,
                counters,
                &mut memo,
            )? {
                continue;
            }
            diagnostics.push(generic_diagnostic(
                GenericAnalysisCode::UnsatisfiedBound,
                "a closed declared application does not satisfy its declaration bound",
                fact.span.clone(),
                vec![
                    RelatedSpan {
                        label: Arc::from("generic declaration"),
                        span: declaration.declaration.clone(),
                    },
                    RelatedSpan {
                        label: Arc::from("declaration predicate"),
                        span: predicate.span.clone(),
                    },
                ],
                [
                    ("capability", predicate.capability.wire_name().to_owned()),
                    ("type", argument.canonical_string()),
                ],
            )?);
        }
    }
    Ok(())
}

fn collect_generic_declaration_shapes(
    sources: &[ParsedSource],
    structure: &PackageStructure,
    binders: &[TypeBinder],
    facts: &[GenericTypeFact],
) -> Result<BTreeMap<String, GenericDeclarationShape>, AnalysisError> {
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol))
        .collect::<BTreeMap<_, _>>();
    let binders = binders
        .iter()
        .map(|binder| (binder.declaration.clone(), binder.clone()))
        .collect::<BTreeMap<_, _>>();
    let facts = facts
        .iter()
        .map(|fact| (fact.span.clone(), fact.expression.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut declarations = BTreeMap::new();

    for source in sources {
        let tree = source.tree();
        for (index, node) in tree.nodes().iter().enumerate() {
            if !matches!(
                node.form(),
                SyntaxForm::StructDeclaration | SyntaxForm::EnumDeclaration
            ) {
                continue;
            }
            let owner = NodeId::from_index(index);
            let name_span = direct_identifiers(tree, owner)?
                .into_iter()
                .next()
                .map(|(_, span)| span)
                .ok_or(AnalysisError::Invariant)?;
            let Some(symbol) = symbols.get(&name_span).copied() else {
                continue;
            };
            let binder = binders.get(node.span()).cloned();
            let mut members = Vec::new();
            for member in node.children().iter().copied() {
                let member_node = tree.node(member).ok_or(AnalysisError::Invariant)?;
                if !matches!(
                    member_node.form(),
                    SyntaxForm::StructField | SyntaxForm::EnumVariant
                ) {
                    continue;
                }
                if let Some(ty) = direct_child(tree, member, SyntaxForm::ValueType) {
                    let span = tree.node(ty).ok_or(AnalysisError::Invariant)?.span();
                    if let Some(expression) = facts.get(span) {
                        members.push(expression.clone());
                    }
                }
            }
            let predicates = collect_capability_predicates(tree, owner, binder.as_ref())?;
            declarations.insert(
                symbol.path.as_str().to_owned(),
                GenericDeclarationShape {
                    binder,
                    declaration: node.span().clone(),
                    members,
                    predicates,
                },
            );
        }
    }
    Ok(declarations)
}

fn collect_capability_predicates(
    tree: &SyntaxTree,
    owner: NodeId,
    binder: Option<&TypeBinder>,
) -> Result<Vec<CapabilityPredicate>, AnalysisError> {
    let Some(where_clause) = direct_child(tree, owner, SyntaxForm::WhereClause) else {
        return Ok(Vec::new());
    };
    let clause = tree.node(where_clause).ok_or(AnalysisError::Invariant)?;
    let mut predicates = Vec::new();
    for predicate in clause.children().iter().copied() {
        let predicate_node = tree.node(predicate).ok_or(AnalysisError::Invariant)?;
        if !matches!(predicate_node.form(), SyntaxForm::WherePredicate) {
            continue;
        }
        let Some((subject, _)) = direct_identifiers(tree, predicate)?.into_iter().next() else {
            continue;
        };
        let Some(trait_reference) = direct_child(tree, predicate, SyntaxForm::TraitReference)
        else {
            return Err(AnalysisError::Invariant);
        };
        let path = direct_child(tree, trait_reference, SyntaxForm::Path)
            .ok_or(AnalysisError::Invariant)?;
        let Some(capability) = SealedCapability::from_path(&direct_identifiers(tree, path)?) else {
            continue;
        };
        let Some(binder) = binder else {
            continue;
        };
        let Some(parameter) = binder
            .parameters
            .iter()
            .find(|parameter| parameter.name == subject)
        else {
            continue;
        };
        predicates.push(CapabilityPredicate {
            parameter: TypeParameterKey {
                binder_depth: binder.depth,
                ordinal: parameter.ordinal,
            },
            capability,
            span: predicate_node.span().clone(),
        });
    }
    predicates.sort_by(|left, right| {
        left.capability
            .cmp(&right.capability)
            .then_with(|| left.parameter.cmp(&right.parameter))
            .then_with(|| left.span.cmp(&right.span))
    });
    Ok(predicates)
}

fn prove_sealed_capability(
    capability: SealedCapability,
    root: &TypeDescriptor,
    declarations: &BTreeMap<String, GenericDeclarationShape>,
    counters: &mut Option<GenericAnalysisCounters>,
    memo: &mut BTreeMap<(SealedCapability, String), bool>,
) -> Result<bool, AnalysisError> {
    charge_trait_steps(counters, 1)?;
    let root_key = root.canonical_string();
    if let Some(result) = memo.get(&(capability, root_key.clone())).copied() {
        return Ok(result);
    }

    let mut active = BTreeSet::from([root_key.clone()]);
    let mut stack = vec![CapabilityFrame {
        descriptor: root.clone(),
        key: root_key,
        members: None,
        next_member: 0,
        satisfied: true,
    }];
    loop {
        let index = stack.len().checked_sub(1).ok_or(AnalysisError::Invariant)?;
        if stack[index].members.is_none() {
            charge_trait_steps(counters, 1)?;
            match capability_node(capability, &stack[index].descriptor, declarations)? {
                CapabilityNode::Leaf(result) => {
                    let frame = stack.pop().ok_or(AnalysisError::Invariant)?;
                    active.remove(&frame.key);
                    memo.insert((capability, frame.key), result);
                    if let Some(parent) = stack.last_mut() {
                        parent.satisfied &= result;
                        continue;
                    }
                    return Ok(result);
                }
                CapabilityNode::Members(mut members) => {
                    members.sort_by_key(TypeDescriptor::canonical_string);
                    stack[index].members = Some(members);
                }
            }
        }

        if !stack[index].satisfied {
            let frame = stack.pop().ok_or(AnalysisError::Invariant)?;
            active.remove(&frame.key);
            memo.insert((capability, frame.key), false);
            if let Some(parent) = stack.last_mut() {
                parent.satisfied = false;
                continue;
            }
            return Ok(false);
        }

        let members = stack[index]
            .members
            .as_ref()
            .ok_or(AnalysisError::Invariant)?;
        let Some(member) = members.get(stack[index].next_member).cloned() else {
            let frame = stack.pop().ok_or(AnalysisError::Invariant)?;
            active.remove(&frame.key);
            memo.insert((capability, frame.key), true);
            if stack.is_empty() {
                return Ok(true);
            }
            continue;
        };
        stack[index].next_member = stack[index].next_member.saturating_add(1);
        charge_trait_steps(counters, 1)?;
        let member_key = member.canonical_string();
        if active.contains(&member_key) {
            continue;
        }
        if let Some(result) = memo.get(&(capability, member_key.clone())).copied() {
            stack[index].satisfied &= result;
            continue;
        }
        active.insert(member_key.clone());
        stack.push(CapabilityFrame {
            descriptor: member,
            key: member_key,
            members: None,
            next_member: 0,
            satisfied: true,
        });
    }
}

fn capability_node(
    capability: SealedCapability,
    descriptor: &TypeDescriptor,
    declarations: &BTreeMap<String, GenericDeclarationShape>,
) -> Result<CapabilityNode, AnalysisError> {
    match descriptor.kind() {
        TypeKind::Decision | TypeKind::OperationError
            if capability == SealedCapability::Equatable =>
        {
            Ok(CapabilityNode::Leaf(false))
        }
        TypeKind::Unit
        | TypeKind::Bool
        | TypeKind::Int
        | TypeKind::Float
        | TypeKind::String
        | TypeKind::Decision
        | TypeKind::OperationError => Ok(CapabilityNode::Leaf(true)),
        TypeKind::Option | TypeKind::Result | TypeKind::List | TypeKind::Tuple => {
            Ok(CapabilityNode::Members(descriptor.immediate_members()))
        }
        TypeKind::Declared => {
            let path = descriptor.declared_path().ok_or(AnalysisError::Invariant)?;
            let Some(declaration) = declarations.get(path.as_str()) else {
                return Ok(CapabilityNode::Leaf(false));
            };
            let members = if let Some(binder) = declaration.binder.as_ref() {
                let required = binder
                    .parameters
                    .iter()
                    .map(|parameter| TypeParameterKey {
                        binder_depth: binder.depth,
                        ordinal: parameter.ordinal,
                    })
                    .collect::<Vec<_>>();
                let substitution =
                    ExactTypeSubstitution::explicit(&required, &descriptor.immediate_members())
                        .map_err(|_| AnalysisError::Invariant)?;
                declaration
                    .members
                    .iter()
                    .map(|member| {
                        substitution
                            .apply(member)
                            .map_err(|_| AnalysisError::Invariant)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                declaration
                    .members
                    .iter()
                    .map(|member| {
                        member
                            .to_descriptor(u64::MAX)
                            .map_err(|_| AnalysisError::Invariant)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };
            Ok(CapabilityNode::Members(members))
        }
    }
}

fn charge_trait_steps(
    counters: &mut Option<GenericAnalysisCounters>,
    amount: u64,
) -> Result<(), AnalysisError> {
    let Some(counters) = counters.as_mut() else {
        return Ok(());
    };
    counters
        .charge_trait_resolution_steps(amount)
        .map_err(|error| AnalysisError::ResourceLimit {
            error,
            diagnostics: Vec::new(),
        })
}

struct TypeResolutionContext<'a> {
    tree: &'a SyntaxTree,
    parents: &'a [Option<NodeId>],
    references: &'a BTreeMap<SourceSpan, SymbolId>,
    symbols: &'a BTreeMap<SymbolId, &'a Symbol>,
    binders: &'a BTreeMap<SourceSpan, &'a TypeBinder>,
    parameter_names: &'a BTreeSet<Arc<str>>,
    arities: &'a BTreeMap<SymbolId, usize>,
}

fn resolve_generic_type_node(
    id: NodeId,
    resolved: &BTreeMap<NodeId, TypeExpression>,
    context: &TypeResolutionContext<'_>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeExpression>, AnalysisError> {
    let arguments = type_argument_nodes(context.tree, id)?
        .into_iter()
        .map(|argument| resolved.get(&argument).cloned())
        .collect::<Option<Vec<_>>>();
    let word = direct_reserved_word(context.tree, id)?;
    let expression = match word.as_deref() {
        Some("Unit") => closed_expression(TypeDescriptor::UNIT)?,
        Some("Bool") => closed_expression(TypeDescriptor::BOOL)?,
        Some("Int") => closed_expression(TypeDescriptor::INT)?,
        Some("Float") => closed_expression(TypeDescriptor::FLOAT)?,
        Some("String") => closed_expression(TypeDescriptor::STRING)?,
        Some("Decision") => closed_expression(TypeDescriptor::DECISION)?,
        Some("OperationError") => closed_expression(TypeDescriptor::OPERATION_ERROR)?,
        Some("Option") => {
            let Some(mut arguments) = arguments else {
                return Ok(None);
            };
            let member = arguments.pop().ok_or(AnalysisError::Invariant)?;
            let Ok(expression) = TypeExpression::option(member, u64::MAX) else {
                return Ok(None);
            };
            expression
        }
        Some("List") => {
            let Some(mut arguments) = arguments else {
                return Ok(None);
            };
            TypeExpression::list(arguments.pop().ok_or(AnalysisError::Invariant)?, u64::MAX)
                .map_err(|_| AnalysisError::Invariant)?
        }
        Some("Result") => {
            let Some(arguments) = arguments else {
                return Ok(None);
            };
            if arguments.len() != 2 {
                return Err(AnalysisError::Invariant);
            }
            TypeExpression::result(arguments[0].clone(), arguments[1].clone(), u64::MAX)
                .map_err(|_| AnalysisError::Invariant)?
        }
        Some("Tuple") => {
            let Some(arguments) = arguments else {
                return Ok(None);
            };
            TypeExpression::tuple(arguments, u64::MAX).map_err(|_| AnalysisError::Invariant)?
        }
        Some("Self") => TypeExpression::self_type(self_binder_depth(id, context)?, u64::MAX)
            .map_err(|_| AnalysisError::Invariant)?,
        Some(_) => return Err(AnalysisError::Invariant),
        None => {
            let path_id =
                direct_child(context.tree, id, SyntaxForm::Path).ok_or(AnalysisError::Invariant)?;
            let path = context.tree.node(path_id).ok_or(AnalysisError::Invariant)?;
            let name = direct_path_identifier(context.tree, path_id)?;
            if let Some(parameter) = in_scope_parameter(id, &name, context)? {
                let supplied = arguments.as_ref().map_or(0, Vec::len);
                if supplied != 0 {
                    diagnostics.push(arity_diagnostic(path.span().clone(), 0, supplied)?);
                    return Ok(None);
                }
                TypeExpression::parameter(parameter.0, parameter.1, u64::MAX)
                    .map_err(|_| AnalysisError::Invariant)?
            } else if let Some(target) = context.references.get(path.span()).copied() {
                let symbol = context
                    .symbols
                    .get(&target)
                    .ok_or(AnalysisError::Invariant)?;
                if !matches!(symbol.kind, SymbolKind::Struct | SymbolKind::Enum) {
                    return Ok(None);
                }
                let arguments = arguments.unwrap_or_default();
                let expected = context.arities.get(&target).copied().unwrap_or(0);
                if arguments.len() != expected {
                    diagnostics.push(arity_diagnostic(
                        path.span().clone(),
                        expected,
                        arguments.len(),
                    )?);
                    return Ok(None);
                }
                TypeExpression::declared(symbol.path.clone(), arguments, u64::MAX)
                    .map_err(|_| AnalysisError::Invariant)?
            } else {
                if context.parameter_names.contains(&name) {
                    diagnostics.push(generic_diagnostic(
                        GenericAnalysisCode::EscapedTypeParameter,
                        "a type parameter is used outside its owning binder scope",
                        path.span().clone(),
                        Vec::new(),
                        [("parameter", name.as_ref())],
                    )?);
                }
                return Ok(None);
            }
        }
    };
    Ok(Some(expression))
}

fn closed_expression(descriptor: TypeDescriptor) -> Result<TypeExpression, AnalysisError> {
    TypeExpression::closed(&descriptor, u64::MAX).map_err(|_| AnalysisError::Invariant)
}

fn type_argument_nodes(tree: &SyntaxTree, id: NodeId) -> Result<Vec<NodeId>, AnalysisError> {
    let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
    let mut arguments = Vec::new();
    for child in node.children().iter().copied() {
        let child_node = tree.node(child).ok_or(AnalysisError::Invariant)?;
        match child_node.form() {
            SyntaxForm::ValueType => arguments.push(child),
            SyntaxForm::TypeArgumentList => {
                arguments.extend(child_node.children().iter().copied().filter(|argument| {
                    tree.node(*argument)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::ValueType))
                }))
            }
            _ => {}
        }
    }
    Ok(arguments)
}

fn in_scope_parameter(
    id: NodeId,
    name: &str,
    context: &TypeResolutionContext<'_>,
) -> Result<Option<(u64, u64)>, AnalysisError> {
    let mut current = context.parents.get(id.index()).copied().flatten();
    while let Some(parent) = current {
        let owner = context.tree.node(parent).ok_or(AnalysisError::Invariant)?;
        if is_binder_owner(owner.form())
            && let Some(binder) = context.binders.get(owner.span()).copied()
            && let Some(parameter) = binder
                .parameters
                .iter()
                .find(|parameter| parameter.name.as_ref() == name)
        {
            return Ok(Some((binder.depth, parameter.ordinal)));
        }
        current = context.parents.get(parent.index()).copied().flatten();
    }
    Ok(None)
}

fn self_binder_depth(
    id: NodeId,
    context: &TypeResolutionContext<'_>,
) -> Result<u64, AnalysisError> {
    let mut current = context.parents.get(id.index()).copied().flatten();
    while let Some(parent) = current {
        let owner = context.tree.node(parent).ok_or(AnalysisError::Invariant)?;
        if matches!(
            owner.form(),
            SyntaxForm::TraitDeclaration | SyntaxForm::ImplDeclaration
        ) {
            return Ok(context
                .binders
                .get(owner.span())
                .map_or(0, |binder| binder.depth));
        }
        current = context.parents.get(parent.index()).copied().flatten();
    }
    Ok(0)
}

fn declared_type_arities(
    sources: &[ParsedSource],
    structure: &PackageStructure,
) -> Result<BTreeMap<SymbolId, usize>, AnalysisError> {
    let symbols = structure
        .symbols()
        .iter()
        .map(|symbol| (symbol.span.clone(), symbol.id))
        .collect::<BTreeMap<_, _>>();
    let mut arities = BTreeMap::new();
    for source in sources {
        for (index, node) in source.tree().nodes().iter().enumerate() {
            if !matches!(
                node.form(),
                SyntaxForm::StructDeclaration | SyntaxForm::EnumDeclaration
            ) {
                continue;
            }
            let owner = NodeId::from_index(index);
            let name = direct_identifiers(source.tree(), owner)?
                .into_iter()
                .next()
                .ok_or(AnalysisError::Invariant)?;
            let Some(symbol) = symbols.get(&name.1).copied() else {
                continue;
            };
            let arity = direct_parameter_list(source.tree(), owner)
                .map(|list| direct_identifiers(source.tree(), list))
                .transpose()?
                .map_or(0, |parameters| parameters.len());
            arities.insert(symbol, arity);
        }
    }
    Ok(arities)
}

fn direct_child(tree: &SyntaxTree, id: NodeId, form: SyntaxForm) -> Option<NodeId> {
    tree.node(id)?.children().iter().copied().find(|child| {
        tree.node(*child).is_some_and(|node| {
            std::mem::discriminant(node.form()) == std::mem::discriminant(&form)
        })
    })
}

fn direct_path_identifier(tree: &SyntaxTree, path: NodeId) -> Result<Arc<str>, AnalysisError> {
    direct_identifiers(tree, path)?
        .into_iter()
        .next()
        .map(|(name, _)| name)
        .ok_or(AnalysisError::Invariant)
}

fn direct_reserved_word(tree: &SyntaxTree, id: NodeId) -> Result<Option<String>, AnalysisError> {
    let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => Some(word.spelling().to_owned()),
            _ => None,
        }))
}

fn arity_diagnostic(
    primary: SourceSpan,
    expected: usize,
    observed: usize,
) -> Result<StructuredDiagnostic, AnalysisError> {
    generic_diagnostic(
        GenericAnalysisCode::TypeArgumentArity,
        "a type application has the wrong number of arguments",
        primary,
        Vec::new(),
        [
            ("expected", expected.to_string()),
            ("observed", observed.to_string()),
        ],
    )
}

fn diagnose_parameters(
    draft: &BinderDraft,
    _parent: Option<TypeBinderId>,
    drafts: &BTreeMap<(usize, NodeId), &BinderDraft>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut first = BTreeMap::<Arc<str>, SourceSpan>::new();
    for (name, span) in &draft.parameters {
        if let Some(previous) = first.get(name) {
            diagnostics.push(generic_diagnostic(
                GenericAnalysisCode::DuplicateTypeParameter,
                "a generic binder declares one type parameter more than once",
                span.clone(),
                vec![RelatedSpan {
                    label: Arc::from("first declaration"),
                    span: previous.clone(),
                }],
                [("parameter", name.as_ref())],
            )?);
        } else {
            first.insert(name.clone(), span.clone());
        }
    }

    let mut ancestor = draft.parent_owner;
    while let Some(owner) = ancestor {
        let enclosing = drafts
            .get(&(draft.source_index, owner))
            .copied()
            .ok_or(AnalysisError::Invariant)?;
        for (name, span) in &draft.parameters {
            if let Some((_, previous)) = enclosing
                .parameters
                .iter()
                .find(|(candidate, _)| candidate == name)
            {
                diagnostics.push(generic_diagnostic(
                    GenericAnalysisCode::ShadowedTypeParameter,
                    "a nested generic binder shadows an enclosing type parameter",
                    span.clone(),
                    vec![RelatedSpan {
                        label: Arc::from("enclosing declaration"),
                        span: previous.clone(),
                    }],
                    [("parameter", name.as_ref())],
                )?);
            }
        }
        ancestor = enclosing.parent_owner;
    }
    Ok(())
}

fn binder_depth(parent: TypeBinderId, binders: &[TypeBinder]) -> Result<u64, AnalysisError> {
    binders
        .get(parent.index() as usize)
        .ok_or(AnalysisError::Invariant)?
        .depth
        .checked_add(1)
        .ok_or(AnalysisError::Invariant)
}

fn nearest_owner(
    owner: NodeId,
    parents: &[Option<NodeId>],
    owners: &BTreeSet<NodeId>,
) -> Option<NodeId> {
    let mut current = parents.get(owner.index()).copied().flatten();
    while let Some(parent) = current {
        if owners.contains(&parent) {
            return Some(parent);
        }
        current = parents.get(parent.index()).copied().flatten();
    }
    None
}

fn is_binder_owner(form: &SyntaxForm) -> bool {
    matches!(
        form,
        SyntaxForm::StructDeclaration
            | SyntaxForm::EnumDeclaration
            | SyntaxForm::TraitDeclaration
            | SyntaxForm::FunctionDeclaration
            | SyntaxForm::ImplDeclaration
            | SyntaxForm::MethodDeclaration
            | SyntaxForm::TraitMethodDeclaration
    )
}

fn direct_parameter_list(tree: &SyntaxTree, owner: NodeId) -> Option<NodeId> {
    tree.node(owner)?.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::TypeParameterList))
    })
}

fn direct_identifiers(
    tree: &SyntaxTree,
    node: NodeId,
) -> Result<Vec<(Arc<str>, SourceSpan)>, AnalysisError> {
    let node = tree.node(node).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => {
                Some((value.clone(), child.span().clone()))
            }
            _ => None,
        })
        .collect())
}

fn parent_index(tree: &SyntaxTree) -> Result<Vec<Option<NodeId>>, AnalysisError> {
    let mut parents = vec![None; tree.nodes().len()];
    for (index, node) in tree.nodes().iter().enumerate() {
        let parent = NodeId::from_index(index);
        for child in node.children().iter().copied() {
            *parents
                .get_mut(child.index())
                .ok_or(AnalysisError::Invariant)? = Some(parent);
        }
    }
    Ok(parents)
}

fn generic_diagnostic<K, V, const N: usize>(
    code: GenericAnalysisCode,
    message: &str,
    primary: SourceSpan,
    related: Vec<RelatedSpan>,
    fields: [(K, V); N],
) -> Result<StructuredDiagnostic, AnalysisError>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    named_generic_diagnostic(code.wire_name(), message, primary, related, fields)
}

fn named_generic_diagnostic<K, V, const N: usize>(
    code: &str,
    message: &str,
    primary: SourceSpan,
    related: Vec<RelatedSpan>,
    fields: [(K, V); N],
) -> Result<StructuredDiagnostic, AnalysisError>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Analysis,
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::Type,
            code: DiagnosticCode::new(code).map_err(|_| AnalysisError::Invariant)?,
        },
        message,
        Some(primary),
        related,
        fields
            .into_iter()
            .map(|(key, value)| (Arc::from(key.as_ref()), Arc::from(value.as_ref())))
            .collect(),
    )
    .map_err(|_| AnalysisError::Invariant)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gantry_core::source::SourceLimits;
    use gantry_frontend::validate_package_syntax;

    use super::{
        ExactTypeSubstitution, TypeInferenceFailure, TypeParameterKey, collect_generic_type_facts,
        collect_type_binders,
    };
    use crate::{AnalysisStatus, SymbolKind, analyze_package_structure};
    use gantry_ir::{TypeDescriptor, TypeExpression};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn with_source(source: &str) -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-generic-binders-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
            fs::write(path.join("main.gnt"), source)
                .unwrap_or_else(|error| panic!("could not write generic fixture: {error}"));
            Self(path)
        }

        fn syntax(&self) -> gantry_frontend::CompletedSyntaxPhase {
            let limits = SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
                .unwrap_or_else(|_| unreachable!("positive limits"));
            validate_package_syntax(&self.0, limits, 64)
                .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"))
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn traits_are_package_symbols_and_nested_binders_use_stable_ordinals() {
        let root = TempDirectory::with_source(
            "trait Convert<T> { pure fn convert<U>(self, value: U) -> T; } fn main() {}",
        );
        let phase = root.syntax();
        let structure = analyze_package_structure(&phase)
            .unwrap_or_else(|error| panic!("structure analysis failed: {error:?}"));
        assert_eq!(structure.status(), AnalysisStatus::Valid);
        assert!(structure.symbols().iter().any(|symbol| {
            symbol.kind == SymbolKind::Trait && symbol.path.as_str() == "crate::Convert"
        }));

        let mut diagnostics = Vec::new();
        let binders = collect_type_binders(phase.parsed_sources(), &mut diagnostics)
            .unwrap_or_else(|error| panic!("binder collection failed: {error:?}"));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(binders.len(), 2);
        assert_eq!(binders[0].depth, 0);
        assert_eq!(binders[0].parameters[0].ordinal, 0);
        assert_eq!(binders[0].parameters[0].name.as_ref(), "T");
        assert_eq!(binders[1].parent, Some(binders[0].id));
        assert_eq!(binders[1].depth, 1);
        assert_eq!(binders[1].parameters[0].ordinal, 0);
        assert_eq!(binders[1].parameters[0].name.as_ref(), "U");
    }

    #[test]
    fn duplicate_and_shadowed_type_parameters_have_portable_codes() {
        let root = TempDirectory::with_source(
            "struct Pair<T, T> { value: T } trait Convert<U> { pure fn convert<U>(self, value: U); } fn main() {}",
        );
        let phase = root.syntax();
        let mut diagnostics = Vec::new();
        let binders = collect_type_binders(phase.parsed_sources(), &mut diagnostics)
            .unwrap_or_else(|error| panic!("binder collection failed: {error:?}"));
        assert_eq!(binders.len(), 3);
        let codes = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"duplicate-type-parameter"));
        assert!(codes.contains(&"shadowed-type-parameter"));
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.related.is_empty())
        );
    }

    #[test]
    fn open_type_facts_use_binder_ordinals_and_close_complete_applications() {
        let root = TempDirectory::with_source(
            "struct Envelope<T> { value: T } fn inspect(value: Envelope<String>) {} fn main() {}",
        );
        let phase = root.syntax();
        let structure = analyze_package_structure(&phase)
            .unwrap_or_else(|error| panic!("structure analysis failed: {error:?}"));
        let mut diagnostics = Vec::new();
        let binders = collect_type_binders(phase.parsed_sources(), &mut diagnostics)
            .unwrap_or_else(|error| panic!("binder collection failed: {error:?}"));
        let facts = collect_generic_type_facts(
            phase.parsed_sources(),
            &structure,
            &binders,
            &mut diagnostics,
        )
        .unwrap_or_else(|error| panic!("generic type collection failed: {error:?}"));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let expressions = facts
            .iter()
            .map(|fact| fact.expression.as_str())
            .collect::<Vec<_>>();
        assert!(expressions.contains(&"^0.0"));
        assert!(expressions.contains(&"crate::Envelope<String>"));
        assert!(
            facts
                .iter()
                .any(|fact| { fact.expression.as_str() == "^0.0" && fact.descriptor.is_none() })
        );
        assert!(facts.iter().any(|fact| {
            fact.expression.as_str() == "crate::Envelope<String>"
                && fact.descriptor.as_ref().is_some_and(|descriptor| {
                    descriptor.canonical_string() == "crate::Envelope<String>"
                })
        }));
    }

    #[test]
    fn escaped_parameters_and_declared_arity_use_portable_diagnostics() {
        let root = TempDirectory::with_source(
            "struct Envelope<T> { value: T } struct Bad { escaped: T, missing: Envelope, extra: Envelope<String,Int> } fn main() {}",
        );
        let phase = root.syntax();
        let structure = analyze_package_structure(&phase)
            .unwrap_or_else(|error| panic!("structure analysis failed: {error:?}"));
        let mut diagnostics = Vec::new();
        let binders = collect_type_binders(phase.parsed_sources(), &mut diagnostics)
            .unwrap_or_else(|error| panic!("binder collection failed: {error:?}"));
        let _ = collect_generic_type_facts(
            phase.parsed_sources(),
            &structure,
            &binders,
            &mut diagnostics,
        )
        .unwrap_or_else(|error| panic!("generic type collection failed: {error:?}"));
        let codes = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"escaped-type-parameter"));
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == "type-argument-arity")
                .count(),
            2
        );
    }

    #[test]
    fn exact_substitution_is_complete_and_occurs_checked() {
        let key = TypeParameterKey {
            binder_depth: 0,
            ordinal: 0,
        };
        let parameter = TypeExpression::parameter(0, 0, 8)
            .unwrap_or_else(|_| unreachable!("parameter expression is canonical"));
        let string = TypeExpression::closed(&TypeDescriptor::STRING, 8)
            .unwrap_or_else(|_| unreachable!("closed String expression is canonical"));
        let substitution = ExactTypeSubstitution::infer(&[key], &[(parameter.clone(), string)])
            .unwrap_or_else(|error| panic!("exact inference failed: {error:?}"));
        let list = TypeExpression::list(parameter.clone(), 8)
            .unwrap_or_else(|_| unreachable!("list template is canonical"));
        assert_eq!(
            substitution
                .apply(&list)
                .map(|value| value.canonical_string()),
            Ok("List<String>".to_owned())
        );

        let recursive = TypeExpression::list(parameter.clone(), 8)
            .unwrap_or_else(|_| unreachable!("recursive constraint is canonical"));
        assert_eq!(
            ExactTypeSubstitution::infer(&[key], &[(parameter.clone(), recursive)]),
            Err(TypeInferenceFailure::OccursCheck)
        );
        assert_eq!(
            ExactTypeSubstitution::infer(&[key], &[]),
            Err(TypeInferenceFailure::Incomplete)
        );
    }
}
