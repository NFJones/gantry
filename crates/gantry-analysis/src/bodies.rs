//! Body typing, pattern coverage, and normal-completion validation.
//!
//! This pass intentionally uses explicit syntax-node work collections. It
//! validates deterministic value flow without performing ownership, effect,
//! operation, or lowering work owned by later analyzer stages.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry_core::source::{
    DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, SourceSpan, StructuredDiagnostic,
};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::TypeDescriptor;
use gantry_ir::generated::TypeKind;

use crate::{AnalysisError, PackageStructure, SymbolId, TypeFact};

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
struct EnumShape {
    descriptor: TypeDescriptor,
    variants: BTreeMap<Arc<str>, Option<TypeDescriptor>>,
}

#[derive(Clone, Debug)]
struct BodyContext {
    callables: BTreeMap<SymbolId, CallableSignature>,
    actions: BTreeMap<SymbolId, CallableSignature>,
    methods: BTreeMap<(TypeDescriptor, Arc<str>), CallableSignature>,
    references: BTreeMap<SourceSpan, SymbolId>,
    structs: BTreeMap<SymbolId, StructShape>,
    enums: BTreeMap<SymbolId, EnumShape>,
    expression_types: RefCell<BTreeMap<NodeId, TypeDescriptor>>,
}

type PatternAnalysis = (BTreeSet<String>, BTreeMap<Arc<str>, TypeDescriptor>);

fn build_body_context(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    structure: &PackageStructure,
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
    let references = structure
        .references()
        .iter()
        .map(|reference| (reference.span.clone(), reference.target))
        .collect::<BTreeMap<_, _>>();
    let mut callables = BTreeMap::new();
    let mut actions = BTreeMap::new();
    let mut methods = BTreeMap::new();
    let mut structs = BTreeMap::new();
    let mut enums = BTreeMap::new();
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
            let path = direct_child_form(source.tree(), node, SyntaxForm::Path)
                .ok_or(AnalysisError::Invariant)?;
            let path_node = source.tree().node(path).ok_or(AnalysisError::Invariant)?;
            let Some(target) = references.get(path_node.span()) else {
                continue;
            };
            let Some(symbol) = symbols_by_id.get(target) else {
                return Err(AnalysisError::Invariant);
            };
            let receiver = TypeDescriptor::declared(symbol.path.clone());
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
            }
        }
    }
    Ok(BodyContext {
        callables,
        actions,
        methods,
        references,
        structs,
        enums,
        expression_types: RefCell::new(BTreeMap::new()),
    })
}

/// Checks every free-function and method body against its declared signature.
pub(crate) fn check_package_bodies(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    structure: &PackageStructure,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Vec<BTreeMap<NodeId, TypeDescriptor>>, AnalysisError> {
    let context = build_body_context(sources, facts, structure)?;
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
            check_callable(
                source.tree(),
                NodeId::from_index(index),
                resolved,
                &context,
                diagnostics,
            )?;
        }
        expression_types.push(context.expression_types.take());
    }
    Ok(expression_types)
}

fn check_callable(
    tree: &SyntaxTree,
    callable: NodeId,
    facts: &BTreeMap<NodeId, TypeFact>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let node = tree.node(callable).ok_or(AnalysisError::Invariant)?;
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
    let universe = coverage_universe(&scrutinee_type, context);
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
    let path = direct_child_form(tree, implementation, SyntaxForm::Path)
        .ok_or(AnalysisError::Invariant)?;
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let Some(target) = context.references.get(path_node.span()) else {
        return Ok(None);
    };
    Ok(context
        .structs
        .get(target)
        .map(|shape| shape.descriptor.clone()))
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
        context
            .expression_types
            .borrow_mut()
            .insert(expression, ty.clone());
    }
    Ok(inferred)
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
        return infer_struct(
            tree,
            node,
            struct_expression,
            facts,
            environment,
            context,
            diagnostics,
        );
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
    if let Some(value) =
        infer_enum_constructor(tree, node, facts, environment, context, diagnostics)?
    {
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
        SyntaxForm::PromptExpression => Ok(Some(
            direct_child_form(tree, node, SyntaxForm::ValueType)
                .and_then(|type_node| facts.get(&type_node))
                .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone()),
        )),
        SyntaxForm::DecideExpression => Ok(Some(TypeDescriptor::DECISION)),
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
    let Some(shape) = context.enums.get(&target) else {
        return Ok(None);
    };
    let identifiers = direct_identifiers(tree, path)?;
    let Some(variant) = identifiers.last() else {
        return Ok(None);
    };
    let Some(payload) = shape.variants.get(variant) else {
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

fn infer_struct(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    struct_expression: NodeId,
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
    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
    let Some(target) = context.references.get(path_node.span()).copied() else {
        return Ok(None);
    };
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
    if let Some(value) =
        infer_member_sequence(tree, children, facts, environment, context, diagnostics)?
    {
        return Ok(Some(value));
    }
    if let Some(value) =
        infer_call_sequence(tree, children, facts, environment, context, diagnostics)?
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

fn infer_member_sequence(
    tree: &SyntaxTree,
    children: &[NodeId],
    facts: &BTreeMap<NodeId, TypeFact>,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &BodyContext,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let Some(dot) = children
        .iter()
        .position(|child| node_contains_punctuation(tree, *child, Punctuation::Dot))
    else {
        return Ok(None);
    };
    let root = children
        .get(..dot)
        .unwrap_or_default()
        .iter()
        .find_map(|child| {
            let node = tree.node(*child)?;
            match node.form() {
                SyntaxForm::Path => direct_identifier(tree, *child).ok().flatten(),
                SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
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
        .get(dot.saturating_add(2))
        .is_some_and(|child| node_contains_punctuation(tree, *child, Punctuation::LeftParenthesis));
    if call_open {
        let signature = builtin_method_signature(&receiver, &member)?.or_else(|| {
            context
                .methods
                .get(&(receiver.clone(), member.clone()))
                .cloned()
        });
        let Some(signature) = signature else {
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
        let open = dot.saturating_add(2);
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
        return Ok(Some(signature.result.clone()));
    }

    let field = if receiver == TypeDescriptor::DECISION {
        match member.as_ref() {
            "decision" => Some(TypeDescriptor::BOOL),
            "rationale" => Some(TypeDescriptor::STRING),
            _ => None,
        }
    } else {
        context
            .structs
            .values()
            .find(|shape| shape.descriptor == receiver)
            .and_then(|shape| shape.fields.get(&member))
            .map(|field| field.ty.clone())
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
        .find(|(_, child)| node_contains_punctuation(tree, **child, Punctuation::RightParenthesis))
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
    let universe = coverage_universe(&scrutinee_type, context);
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

fn coverage_universe(scrutinee: &TypeDescriptor, context: &BodyContext) -> BTreeSet<String> {
    match scrutinee.kind() {
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
        TypeKind::Declared => context
            .enums
            .values()
            .find(|shape| shape.descriptor == *scrutinee)
            .map(|shape| shape.variants.keys().map(ToString::to_string).collect())
            .unwrap_or_default(),
        _ => BTreeSet::new(),
    }
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
            && let Some(shape) = context
                .enums
                .values()
                .find(|shape| shape.descriptor == *scrutinee)
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
