//! Canonical workflow facts and least-fixed-point effect inference.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry_core::source::{
    DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, SourceSpan, StructuredDiagnostic,
};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::{Effect, OperationSiteKind, RecoveryClass, TaskControlSiteKind};
use gantry_ir::{
    ActionEffectContributor, ActionInventory, ActionParameter, CallEdge, CanonicalPath,
    CanonicalSignature, EffectSet, OperationSite, StaticSiteId, StructuralPosition,
    TaskControlSite, TypeDescriptor, WorkflowFacts, WorkflowParameter,
};

use crate::{AnalysisError, PackageStructure, Symbol, SymbolId, SymbolKind, TypeFact};

#[derive(Clone, Debug)]
struct ActionShape {
    path: CanonicalPath,
    signature: CanonicalSignature,
    parameters: Vec<ActionParameter>,
    recovery: RecoveryClass,
    result: TypeDescriptor,
    source: SourceSpan,
}

#[derive(Clone, Debug)]
struct MethodShape {
    path: CanonicalPath,
}

#[derive(Clone, Debug)]
struct WorkflowDraft {
    path: CanonicalPath,
    signature: CanonicalSignature,
    result: TypeDescriptor,
    direct_effects: EffectSet,
    calls: Vec<CallEdge>,
    operations: Vec<OperationSite>,
    task_controls: Vec<TaskControlSite>,
    direct_action_contributors: Vec<ActionEffectContributor>,
    pure: bool,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandleState {
    Attached,
    Joined,
    Detached,
    Discharged,
}

#[derive(Clone, Debug)]
struct HandleRecord {
    state: HandleState,
}

struct WorkflowContext<'a> {
    references: &'a BTreeMap<SourceSpan, SymbolId>,
    symbols: &'a BTreeMap<SymbolId, &'a Symbol>,
    actions: &'a BTreeMap<SymbolId, ActionShape>,
    methods: &'a BTreeMap<(CanonicalPath, Arc<str>), MethodShape>,
}

/// Produces canonical workflow facts and checks source `pure` assertions.
pub(crate) fn analyze_workflow_facts(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    structure: &PackageStructure,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(Vec<WorkflowFacts>, Vec<ActionInventory>), AnalysisError> {
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
    let actions = collect_actions(sources, facts, &symbols_by_span)?;
    let methods = collect_methods(sources, &references, &symbols_by_id)?;
    let context = WorkflowContext {
        references: &references,
        symbols: &symbols_by_id,
        actions: &actions,
        methods: &methods,
    };
    let mut drafts = Vec::new();

    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for (index, node) in source.tree().nodes().iter().enumerate() {
            if !matches!(node.form(), SyntaxForm::FunctionDeclaration) {
                continue;
            }
            let Some(name_span) = direct_identifier_span(source.tree(), node) else {
                return Err(AnalysisError::Invariant);
            };
            let Some(symbol) = symbols_by_span.get(&name_span).copied() else {
                continue;
            };
            if symbol.kind != SymbolKind::Function {
                return Err(AnalysisError::Invariant);
            }
            drafts.push(analyze_callable(
                source.tree(),
                NodeId::from_index(index),
                symbol.path.clone(),
                None,
                resolved,
                &context,
                diagnostics,
            )?);
        }
        for implementation in source
            .tree()
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::ImplDeclaration))
        {
            let receiver = direct_child_form(source.tree(), implementation, SyntaxForm::Path)
                .and_then(|path| source.tree().node(path))
                .and_then(|path| references.get(path.span()))
                .and_then(|target| symbols_by_id.get(target))
                .map(|symbol| symbol.path.clone());
            let Some(receiver) = receiver else {
                continue;
            };
            for method in implementation.children().iter().copied().filter(|child| {
                source
                    .tree()
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MethodDeclaration))
            }) {
                let method_node = source.tree().node(method).ok_or(AnalysisError::Invariant)?;
                let name = direct_identifier(source.tree(), method_node)
                    .ok_or(AnalysisError::Invariant)?;
                let path = CanonicalPath::method(&receiver, &name)
                    .map_err(|_| AnalysisError::Invariant)?;
                drafts.push(analyze_callable(
                    source.tree(),
                    method,
                    path,
                    Some(&receiver),
                    resolved,
                    &context,
                    diagnostics,
                )?);
            }
        }
    }
    drafts.sort_by(|left, right| left.path.cmp(&right.path));

    let mut summaries = drafts
        .iter()
        .map(|draft| (draft.path.clone(), draft.direct_effects))
        .collect::<BTreeMap<_, _>>();
    let mut action_contributors = drafts
        .iter()
        .map(|draft| (draft.path.clone(), draft.direct_action_contributors.clone()))
        .collect::<BTreeMap<_, _>>();
    loop {
        let mut changed = false;
        for draft in &drafts {
            let mut summary = draft.direct_effects;
            let mut contributors = draft.direct_action_contributors.clone();
            for call in &draft.calls {
                if let Some(callee) = summaries.get(&call.callee) {
                    summary = summary.union(*callee);
                }
                if let Some(callee) = action_contributors.get(&call.callee) {
                    contributors.extend(callee.iter().cloned());
                }
            }
            contributors.sort_by(|left, right| left.site.cmp(&right.site));
            contributors.dedup_by(|left, right| left.site == right.site);
            let current = summaries
                .get_mut(&draft.path)
                .ok_or(AnalysisError::Invariant)?;
            if *current != summary {
                *current = summary;
                changed = true;
            }
            let current_contributors = action_contributors
                .get_mut(&draft.path)
                .ok_or(AnalysisError::Invariant)?;
            if *current_contributors != contributors {
                *current_contributors = contributors;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut workflows = Vec::with_capacity(drafts.len());
    for draft in drafts {
        let effects = *summaries.get(&draft.path).ok_or(AnalysisError::Invariant)?;
        let contributors = action_contributors
            .get(&draft.path)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        if draft.pure && !effects.is_empty() {
            diagnostics.push(effect_diagnostic(
                "impure-workflow",
                "a pure workflow has a nonempty transitive inferred effect set",
                draft.span.clone(),
                [("effects", effect_names(effects))],
            )?);
        }
        workflows.push(
            WorkflowFacts::new(
                draft.path,
                draft.signature,
                draft.result,
                draft.span,
                effects,
                draft.calls,
                draft.operations,
                draft.task_controls,
                contributors,
            )
            .map_err(|_| AnalysisError::Invariant)?,
        );
    }
    let mut action_inventory = actions
        .values()
        .map(|action| ActionInventory {
            path: action.path.clone(),
            signature: action.signature.clone(),
            parameters: action.parameters.clone(),
            recovery: action.recovery,
            result: action.result.clone(),
            source: action.source.clone(),
        })
        .collect::<Vec<_>>();
    action_inventory.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((workflows, action_inventory))
}

fn analyze_callable(
    tree: &SyntaxTree,
    callable: NodeId,
    path: CanonicalPath,
    receiver: Option<&CanonicalPath>,
    facts: &BTreeMap<NodeId, TypeFact>,
    context: &WorkflowContext<'_>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<WorkflowDraft, AnalysisError> {
    let node = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    let parameters = node
        .children()
        .iter()
        .copied()
        .filter_map(|child| {
            let parameter = tree.node(child)?;
            matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
        })
        .filter_map(|parameter| {
            let type_node = direct_child_form(tree, parameter, SyntaxForm::ValueType)?;
            let fact = facts.get(&type_node)?;
            Some(WorkflowParameter {
                mutable: has_direct_word(tree, parameter, "mut"),
                ty: fact.descriptor.clone(),
            })
        })
        .collect::<Vec<_>>();
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
    let signature = if let Some(receiver) = receiver {
        let name = direct_identifier(tree, node).ok_or(AnalysisError::Invariant)?;
        let mutable_receiver = node.children().iter().copied().any(|child| {
            tree.node(child).is_some_and(|parameter| {
                matches!(parameter.form(), SyntaxForm::Parameter)
                    && has_direct_word(tree, parameter, "self")
                    && has_direct_word(tree, parameter, "mut")
            })
        });
        CanonicalSignature::method(receiver, &name, mutable_receiver, &parameters, &result)
            .map_err(|_| AnalysisError::Invariant)?
    } else {
        CanonicalSignature::function(&path, &parameters, &result)
    };
    let block = direct_child_form(tree, node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
    validate_straight_line_ownership(tree, block, diagnostics)?;
    let environment = callable_environment(tree, node, receiver, facts)?;
    let mut direct_effects = EffectSet::default();
    let mut calls = Vec::new();
    let mut operations = Vec::new();
    let mut task_controls = Vec::new();
    let mut direct_action_contributors = Vec::new();
    let mut work = semantic_children(tree, block)?
        .into_iter()
        .enumerate()
        .rev()
        .map(|(index, child)| (child, vec![index as u64]))
        .collect::<Vec<_>>();

    while let Some((id, position)) = work.pop() {
        let current = tree.node(id).ok_or(AnalysisError::Invariant)?;
        let site = || site_id(&path, &position);
        match current.form() {
            SyntaxForm::PromptExpression => {
                direct_effects.insert(Effect::Prompt);
                if has_descendant_word(tree, current, "fork")
                    || has_descendant_word(tree, current, "new")
                {
                    direct_effects.insert(Effect::Session);
                }
                let result = direct_child_form(tree, current, SyntaxForm::ValueType)
                    .and_then(|type_node| facts.get(&type_node))
                    .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
                operations.push(
                    OperationSite::new(
                        site()?,
                        OperationSiteKind::Prompt,
                        result,
                        None,
                        None,
                        current.span().clone(),
                    )
                    .map_err(|_| AnalysisError::Invariant)?,
                );
            }
            SyntaxForm::DecideExpression => {
                direct_effects.insert(Effect::Decide);
                if has_descendant_word(tree, current, "fork")
                    || has_descendant_word(tree, current, "new")
                {
                    direct_effects.insert(Effect::Session);
                }
                operations.push(
                    OperationSite::new(
                        site()?,
                        OperationSiteKind::Decide,
                        TypeDescriptor::DECISION,
                        None,
                        None,
                        current.span().clone(),
                    )
                    .map_err(|_| AnalysisError::Invariant)?,
                );
            }
            SyntaxForm::ActionExpression => {
                let path = direct_child_form(tree, current, SyntaxForm::Path)
                    .ok_or(AnalysisError::Invariant)?;
                let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
                let Some(target) = context.references.get(path_node.span()) else {
                    continue;
                };
                let Some(action) = context.actions.get(target) else {
                    continue;
                };
                direct_effects.insert(action_effect(action.recovery));
                direct_action_contributors.push(ActionEffectContributor {
                    site: site()?,
                    action: action.path.clone(),
                    recovery: action.recovery,
                    source: current.span().clone(),
                });
                operations.push(
                    OperationSite::new(
                        site()?,
                        OperationSiteKind::Action,
                        action.result.clone(),
                        Some(action.recovery),
                        Some(action.path.clone()),
                        current.span().clone(),
                    )
                    .map_err(|_| AnalysisError::Invariant)?,
                );
            }
            SyntaxForm::AttemptExpression => {
                direct_effects.insert(Effect::Attempt);
            }
            SyntaxForm::SpawnStatement => {
                direct_effects.insert(Effect::Spawn);
                task_controls.push(TaskControlSite {
                    id: site()?,
                    kind: TaskControlSiteKind::Spawn,
                    handles: direct_identifiers(tree, id).into_iter().take(1).collect(),
                    source: current.span().clone(),
                });
            }
            SyntaxForm::JoinExpression => {
                direct_effects.insert(Effect::Join);
                task_controls.push(TaskControlSite {
                    id: site()?,
                    kind: TaskControlSiteKind::Join,
                    handles: direct_identifiers(tree, id),
                    source: current.span().clone(),
                });
            }
            SyntaxForm::JoinAllExpression => {
                direct_effects.insert(Effect::Join);
                task_controls.push(TaskControlSite {
                    id: site()?,
                    kind: TaskControlSiteKind::JoinAll,
                    handles: static_joinall_membership(tree, current)?,
                    source: current.span().clone(),
                });
            }
            SyntaxForm::DetachStatement => {
                direct_effects.insert(Effect::Background);
                task_controls.push(TaskControlSite {
                    id: site()?,
                    kind: TaskControlSiteKind::Detach,
                    handles: direct_identifiers(tree, id),
                    source: current.span().clone(),
                });
            }
            SyntaxForm::SessionStatement | SyntaxForm::SessionExpression
                if has_direct_word(tree, current, "fork")
                    || has_direct_word(tree, current, "new") =>
            {
                direct_effects.insert(Effect::Session);
            }
            SyntaxForm::LoopStatement | SyntaxForm::WhileStatement | SyntaxForm::UntilStatement
                if has_descendant_word(tree, current, "fork")
                    || has_descendant_word(tree, current, "new") =>
            {
                direct_effects.insert(Effect::Session);
            }
            SyntaxForm::Expression | SyntaxForm::BinaryExpression | SyntaxForm::UnaryExpression => {
                if let Some(path) = direct_call_path(tree, current) {
                    let path_node = tree.node(path).ok_or(AnalysisError::Invariant)?;
                    if let Some(target) = context.references.get(path_node.span()).copied()
                        && let Some(callee) = context.symbols.get(&target)
                        && callee.kind == SymbolKind::Function
                    {
                        calls.push(CallEdge {
                            site: site()?,
                            callee: callee.path.clone(),
                            source: current.span().clone(),
                        });
                    }
                }
                if let Some(callee) = direct_method_call(tree, current, &environment, context) {
                    calls.push(CallEdge {
                        site: site()?,
                        callee,
                        source: current.span().clone(),
                    });
                }
            }
            _ => {}
        }

        let children = semantic_children(tree, id)?;
        for (index, child) in children.into_iter().enumerate().rev() {
            let mut child_position = position.clone();
            child_position.push(index as u64);
            work.push((child, child_position));
        }
    }
    calls.sort_by(|left, right| left.site.cmp(&right.site));
    operations.sort_by(|left, right| left.id.cmp(&right.id));
    task_controls.sort_by(|left, right| left.id.cmp(&right.id));
    direct_action_contributors.sort_by(|left, right| left.site.cmp(&right.site));
    Ok(WorkflowDraft {
        path,
        signature,
        result,
        direct_effects,
        calls,
        operations,
        task_controls,
        direct_action_contributors,
        pure: has_direct_word(tree, node, "pure"),
        span: node.span().clone(),
    })
}

fn validate_straight_line_ownership(
    tree: &SyntaxTree,
    root: NodeId,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut tasks = vec![(root, BTreeSet::<Arc<str>>::new())];
    while let Some((block, foreign)) = tasks.pop() {
        let node = tree.node(block).ok_or(AnalysisError::Invariant)?;
        let mut handles = BTreeMap::<Arc<str>, HandleRecord>::new();
        let mut falls_through = true;
        for statement in node.children().iter().copied() {
            let statement_node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
            if matches!(statement_node.form(), SyntaxForm::SpawnStatement) {
                let name = direct_identifiers(tree, statement)
                    .into_iter()
                    .next()
                    .ok_or(AnalysisError::Invariant)?;
                handles.insert(
                    name,
                    HandleRecord {
                        state: HandleState::Attached,
                    },
                );
                let child = direct_child_form(tree, statement_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                let mut child_foreign = foreign.clone();
                child_foreign.extend(handles.keys().cloned());
                tasks.push((child, child_foreign));
                continue;
            }
            if matches!(statement_node.form(), SyntaxForm::IfStatement) {
                merge_if_ownership(tree, statement_node, &mut handles, &foreign, diagnostics)?;
                continue;
            }
            if matches!(statement_node.form(), SyntaxForm::MatchStatement) {
                merge_match_ownership(tree, statement_node, &mut handles, &foreign, diagnostics)?;
                continue;
            }
            if matches!(
                statement_node.form(),
                SyntaxForm::WithStatement | SyntaxForm::SessionStatement
            ) {
                let body = direct_child_form(tree, statement_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                if !apply_direct_ownership_controls(
                    tree,
                    body,
                    &mut handles,
                    &foreign,
                    diagnostics,
                )? {
                    falls_through = false;
                    break;
                }
                continue;
            }
            if matches!(
                statement_node.form(),
                SyntaxForm::ForStatement
                    | SyntaxForm::LoopStatement
                    | SyntaxForm::WhileStatement
                    | SyntaxForm::UntilStatement
            ) {
                let body = direct_child_form(tree, statement_node, SyntaxForm::Block)
                    .ok_or(AnalysisError::Invariant)?;
                let mut repeated = handles.clone();
                apply_direct_ownership_controls(tree, body, &mut repeated, &foreign, diagnostics)?;
                merge_loop_ownership(statement_node.span(), &mut handles, &repeated, diagnostics)?;
                tasks.push((body, foreign.clone()));
                continue;
            }
            apply_expression_ownership(tree, statement, &mut handles, &foreign, diagnostics)?;
            if matches!(
                statement_node.form(),
                SyntaxForm::ReturnStatement
                    | SyntaxForm::BreakStatement
                    | SyntaxForm::ContinueStatement
            ) {
                reject_attached_at_exit(statement_node.span(), &mut handles, diagnostics)?;
                falls_through = false;
                break;
            }
        }
        if falls_through {
            reject_attached_at_exit(node.span(), &mut handles, diagnostics)?;
        }
    }
    validate_nested_spawn_foreign_handles(tree, root, diagnostics)?;
    Ok(())
}

fn validate_nested_spawn_foreign_handles(
    tree: &SyntaxTree,
    root: NodeId,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let root_node = tree.node(root).ok_or(AnalysisError::Invariant)?;
    let spawns = tree
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            matches!(node.form(), SyntaxForm::SpawnStatement)
                && span_contains(root_node.span(), node.span())
        })
        .map(|(index, node)| (NodeId::from_index(index), node))
        .collect::<Vec<_>>();

    for (spawn_id, spawn) in &spawns {
        let mut foreign = BTreeSet::new();
        for (candidate_id, candidate) in &spawns {
            if candidate_id == spawn_id
                || candidate.span().bytes().start() >= spawn.span().bytes().start()
            {
                continue;
            }
            let containing_block = tree
                .nodes()
                .iter()
                .filter(|node| {
                    matches!(node.form(), SyntaxForm::Block)
                        && span_contains(node.span(), candidate.span())
                })
                .min_by_key(|node| span_width(node.span()))
                .ok_or(AnalysisError::Invariant)?;
            if span_contains(containing_block.span(), spawn.span())
                && let Some(handle) = direct_identifiers(tree, *candidate_id).into_iter().next()
            {
                foreign.insert(handle);
            }
        }
        if foreign.is_empty() {
            continue;
        }

        let body =
            direct_child_form(tree, spawn, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
        let mut work = vec![body];
        while let Some(id) = work.pop() {
            let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
            if id != body && matches!(node.form(), SyntaxForm::SpawnStatement) {
                continue;
            }
            if matches!(
                node.form(),
                SyntaxForm::JoinExpression | SyntaxForm::DetachStatement
            ) {
                for handle in direct_identifiers(tree, id) {
                    if foreign.contains(&handle) {
                        diagnostics.push(ownership_diagnostic(
                            "foreign-task-handle",
                            "a spawned task attempts to consume a handle owned by another task",
                            node.span().clone(),
                            [("handle", handle.as_ref())],
                        )?);
                    }
                }
                continue;
            }
            work.extend(node.children().iter().rev().copied());
        }
    }
    Ok(())
}

fn merge_if_ownership(
    tree: &SyntaxTree,
    statement: &gantry_frontend::SyntaxNode,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    foreign: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut branches = Vec::new();
    for block in statement.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
    }) {
        let mut branch = handles.clone();
        if apply_direct_ownership_controls(tree, block, &mut branch, foreign, diagnostics)? {
            branches.push(branch);
        }
    }
    let has_else = statement.children().iter().any(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "else")
        })
    });
    if !has_else {
        branches.push(handles.clone());
    }

    merge_ownership_branches(statement.span(), handles, &branches, diagnostics)
}

fn merge_match_ownership(
    tree: &SyntaxTree,
    statement: &gantry_frontend::SyntaxNode,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    foreign: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let mut branches = Vec::new();
    for arm in statement.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
    }) {
        let arm_node = tree.node(arm).ok_or(AnalysisError::Invariant)?;
        let block =
            direct_child_form(tree, arm_node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
        let mut branch = handles.clone();
        if apply_direct_ownership_controls(tree, block, &mut branch, foreign, diagnostics)? {
            branches.push(branch);
        }
    }

    merge_ownership_branches(statement.span(), handles, &branches, diagnostics)
}

fn merge_loop_ownership(
    span: &SourceSpan,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    repeated: &BTreeMap<Arc<str>, HandleRecord>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for (handle, record) in handles.iter_mut() {
        let Some(repeated) = repeated.get(handle) else {
            continue;
        };
        if record.state != repeated.state {
            diagnostics.push(ownership_diagnostic(
                "inconsistent-task-ownership",
                "a loop changes task ownership across its repeat or zero-iteration paths",
                span.clone(),
                [("handle", handle.as_ref())],
            )?);
            record.state = HandleState::Discharged;
        }
    }
    Ok(())
}

fn merge_ownership_branches(
    span: &SourceSpan,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    branches: &[BTreeMap<Arc<str>, HandleRecord>],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for (handle, record) in handles.iter_mut() {
        let states = branches
            .iter()
            .filter_map(|branch| branch.get(handle).map(|record| record.state))
            .collect::<Vec<_>>();
        let attached = states
            .iter()
            .filter(|state| **state == HandleState::Attached)
            .count();
        if attached > 0 && attached < states.len() {
            diagnostics.push(ownership_diagnostic(
                "inconsistent-task-ownership",
                "a task handle is attached on some control-flow paths and consumed on others",
                span.clone(),
                [("handle", handle.as_ref())],
            )?);
            record.state = HandleState::Discharged;
        } else if attached == states.len() {
            record.state = HandleState::Attached;
        } else if let Some(first) = states.first().copied() {
            record.state = if states.iter().all(|state| *state == first) {
                first
            } else {
                HandleState::Discharged
            };
        }
    }
    Ok(())
}

fn apply_direct_ownership_controls(
    tree: &SyntaxTree,
    block: NodeId,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    foreign: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<bool, AnalysisError> {
    let node = tree.node(block).ok_or(AnalysisError::Invariant)?;
    let mut local_handles = Vec::new();
    for statement in node.children().iter().copied() {
        let statement_node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
        if matches!(statement_node.form(), SyntaxForm::SpawnStatement) {
            let name = direct_identifiers(tree, statement)
                .into_iter()
                .next()
                .ok_or(AnalysisError::Invariant)?;
            handles.insert(
                name.clone(),
                HandleRecord {
                    state: HandleState::Attached,
                },
            );
            local_handles.push(name);
            continue;
        }
        if matches!(statement_node.form(), SyntaxForm::IfStatement) {
            merge_if_ownership(tree, statement_node, handles, foreign, diagnostics)?;
            continue;
        }
        if matches!(statement_node.form(), SyntaxForm::MatchStatement) {
            merge_match_ownership(tree, statement_node, handles, foreign, diagnostics)?;
            continue;
        }
        if matches!(
            statement_node.form(),
            SyntaxForm::ForStatement
                | SyntaxForm::LoopStatement
                | SyntaxForm::WhileStatement
                | SyntaxForm::UntilStatement
        ) {
            let body = direct_child_form(tree, statement_node, SyntaxForm::Block)
                .ok_or(AnalysisError::Invariant)?;
            let mut repeated = handles.clone();
            apply_direct_ownership_controls(tree, body, &mut repeated, foreign, diagnostics)?;
            merge_loop_ownership(statement_node.span(), handles, &repeated, diagnostics)?;
            continue;
        }
        if matches!(
            statement_node.form(),
            SyntaxForm::WithStatement | SyntaxForm::SessionStatement
        ) {
            let body = direct_child_form(tree, statement_node, SyntaxForm::Block)
                .ok_or(AnalysisError::Invariant)?;
            if !apply_direct_ownership_controls(tree, body, handles, foreign, diagnostics)? {
                return Ok(false);
            }
            continue;
        }
        apply_expression_ownership(tree, statement, handles, foreign, diagnostics)?;
        if matches!(
            statement_node.form(),
            SyntaxForm::ReturnStatement
                | SyntaxForm::BreakStatement
                | SyntaxForm::ContinueStatement
        ) {
            reject_attached_at_exit(statement_node.span(), handles, diagnostics)?;
            remove_local_handles(handles, &local_handles);
            return Ok(false);
        }
    }
    reject_local_handles_at_exit(node.span(), handles, &local_handles, diagnostics)?;
    remove_local_handles(handles, &local_handles);
    Ok(true)
}

fn reject_local_handles_at_exit(
    span: &SourceSpan,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    local_handles: &[Arc<str>],
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for handle in local_handles {
        let Some(record) = handles.get_mut(handle) else {
            continue;
        };
        if record.state != HandleState::Attached {
            continue;
        }
        diagnostics.push(ownership_diagnostic(
            "unconsumed-task-handle",
            "an attached task handle reaches a lexical scope exit",
            span.clone(),
            [("handle", handle.as_ref())],
        )?);
        record.state = HandleState::Discharged;
    }
    Ok(())
}

fn remove_local_handles(
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    local_handles: &[Arc<str>],
) {
    for handle in local_handles {
        handles.remove(handle);
    }
}

fn apply_expression_ownership(
    tree: &SyntaxTree,
    root: NodeId,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    foreign: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let node = tree.node(root).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::JoinExpression => {
            consume_named_handles(
                tree,
                root,
                HandleState::Joined,
                handles,
                foreign,
                diagnostics,
            )?;
            return Ok(());
        }
        SyntaxForm::JoinAllExpression => {
            for record in handles.values_mut() {
                if record.state == HandleState::Attached {
                    record.state = HandleState::Joined;
                }
            }
            return Ok(());
        }
        SyntaxForm::DetachStatement => {
            consume_named_handles(
                tree,
                root,
                HandleState::Detached,
                handles,
                foreign,
                diagnostics,
            )?;
            return Ok(());
        }
        SyntaxForm::MatchExpression => {
            for child in node.children().iter().copied().filter(|child| {
                tree.node(*child).is_some_and(|node| {
                    !matches!(node.form(), SyntaxForm::Token(_) | SyntaxForm::MatchArm)
                })
            }) {
                apply_expression_ownership(tree, child, handles, foreign, diagnostics)?;
            }
            let mut branches = Vec::new();
            for arm in node.children().iter().copied().filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
            }) {
                let arm_node = tree.node(arm).ok_or(AnalysisError::Invariant)?;
                let mut branch = handles.clone();
                for child in arm_node.children().iter().copied().filter(|child| {
                    tree.node(*child).is_some_and(|node| {
                        matches!(node.form(), SyntaxForm::Expression | SyntaxForm::Block)
                    })
                }) {
                    if matches!(
                        tree.node(child).ok_or(AnalysisError::Invariant)?.form(),
                        SyntaxForm::Block
                    ) {
                        apply_direct_ownership_controls(
                            tree,
                            child,
                            &mut branch,
                            foreign,
                            diagnostics,
                        )?;
                    } else {
                        apply_expression_ownership(tree, child, &mut branch, foreign, diagnostics)?;
                    }
                }
                branches.push(branch);
            }
            return merge_ownership_branches(node.span(), handles, &branches, diagnostics);
        }
        SyntaxForm::WithExpression | SyntaxForm::SessionExpression => {
            let body =
                direct_child_form(tree, node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
            apply_direct_ownership_controls(tree, body, handles, foreign, diagnostics)?;
            return Ok(());
        }
        SyntaxForm::SpawnStatement => return Ok(()),
        _ => {}
    }

    for child in node.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|node| !matches!(node.form(), SyntaxForm::Token(_)))
    }) {
        apply_expression_ownership(tree, child, handles, foreign, diagnostics)?;
    }
    Ok(())
}

fn reject_attached_at_exit(
    span: &SourceSpan,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    for (handle, record) in handles.iter_mut() {
        if record.state != HandleState::Attached {
            continue;
        }
        diagnostics.push(ownership_diagnostic(
            "unconsumed-task-handle",
            "an attached task handle reaches a lexical scope exit",
            span.clone(),
            [("handle", handle.as_ref())],
        )?);
        record.state = HandleState::Discharged;
    }
    Ok(())
}

fn consume_named_handles(
    tree: &SyntaxTree,
    control: NodeId,
    consumed: HandleState,
    handles: &mut BTreeMap<Arc<str>, HandleRecord>,
    foreign: &BTreeSet<Arc<str>>,
    diagnostics: &mut Vec<StructuredDiagnostic>,
) -> Result<(), AnalysisError> {
    let node = tree.node(control).ok_or(AnalysisError::Invariant)?;
    let mut seen = BTreeSet::new();
    for handle in direct_identifiers(tree, control) {
        if !seen.insert(handle.clone()) {
            diagnostics.push(ownership_diagnostic(
                "duplicate-task-handle",
                "one task handle appears more than once in a single consumption",
                node.span().clone(),
                [("handle", handle.as_ref())],
            )?);
            continue;
        }
        let Some(record) = handles.get_mut(&handle) else {
            if foreign.contains(&handle) {
                diagnostics.push(ownership_diagnostic(
                    "foreign-task-handle",
                    "a spawned task attempts to consume a handle owned by another task",
                    node.span().clone(),
                    [("handle", handle.as_ref())],
                )?);
            }
            continue;
        };
        if record.state != HandleState::Attached {
            diagnostics.push(ownership_diagnostic(
                "consumed-task-handle",
                "a task handle is consumed more than once",
                node.span().clone(),
                [("handle", handle.as_ref())],
            )?);
            continue;
        }
        record.state = consumed;
    }
    Ok(())
}

fn collect_actions(
    sources: &[ParsedSource],
    facts: &[BTreeMap<NodeId, TypeFact>],
    symbols_by_span: &BTreeMap<SourceSpan, &Symbol>,
) -> Result<BTreeMap<SymbolId, ActionShape>, AnalysisError> {
    let mut actions = BTreeMap::new();
    for (source_index, source) in sources.iter().enumerate() {
        let resolved = facts.get(source_index).ok_or(AnalysisError::Invariant)?;
        for node in source
            .tree()
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::ActionDeclaration))
        {
            let Some(name_span) = direct_identifier_span(source.tree(), node) else {
                return Err(AnalysisError::Invariant);
            };
            let Some(symbol) = symbols_by_span.get(&name_span).copied() else {
                continue;
            };
            let recovery = if has_direct_word(source.tree(), node, "read_only") {
                RecoveryClass::ReadOnly
            } else if has_direct_word(source.tree(), node, "idempotent") {
                RecoveryClass::Idempotent
            } else if has_direct_word(source.tree(), node, "non_idempotent") {
                RecoveryClass::NonIdempotent
            } else {
                return Err(AnalysisError::Invariant);
            };
            let parameters = node
                .children()
                .iter()
                .copied()
                .filter_map(|child| {
                    let parameter = source.tree().node(child)?;
                    matches!(parameter.form(), SyntaxForm::Parameter).then_some(parameter)
                })
                .filter_map(|parameter| {
                    let name = direct_identifier(source.tree(), parameter)?;
                    let type_node =
                        direct_child_form(source.tree(), parameter, SyntaxForm::ValueType)?;
                    let ty = resolved.get(&type_node)?.descriptor.clone();
                    ActionParameter::new(&name, ty).ok()
                })
                .collect::<Vec<_>>();
            let result = node
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
            let signature =
                CanonicalSignature::action(recovery, &symbol.path, &parameters, &result);
            actions.insert(
                symbol.id,
                ActionShape {
                    path: symbol.path.clone(),
                    signature,
                    parameters,
                    recovery,
                    result,
                    source: node.span().clone(),
                },
            );
        }
    }
    Ok(actions)
}

fn collect_methods(
    sources: &[ParsedSource],
    references: &BTreeMap<SourceSpan, SymbolId>,
    symbols: &BTreeMap<SymbolId, &Symbol>,
) -> Result<BTreeMap<(CanonicalPath, Arc<str>), MethodShape>, AnalysisError> {
    let mut methods = BTreeMap::new();
    for source in sources {
        for implementation in source
            .tree()
            .nodes()
            .iter()
            .filter(|node| matches!(node.form(), SyntaxForm::ImplDeclaration))
        {
            let Some(receiver) = direct_child_form(source.tree(), implementation, SyntaxForm::Path)
                .and_then(|path| source.tree().node(path))
                .and_then(|path| references.get(path.span()))
                .and_then(|target| symbols.get(target))
                .map(|symbol| symbol.path.clone())
            else {
                continue;
            };
            for method in implementation
                .children()
                .iter()
                .copied()
                .filter_map(|child| {
                    let node = source.tree().node(child)?;
                    matches!(node.form(), SyntaxForm::MethodDeclaration).then_some(node)
                })
            {
                let name =
                    direct_identifier(source.tree(), method).ok_or(AnalysisError::Invariant)?;
                let path = CanonicalPath::method(&receiver, &name)
                    .map_err(|_| AnalysisError::Invariant)?;
                methods.insert((receiver.clone(), name), MethodShape { path });
            }
        }
    }
    Ok(methods)
}

fn callable_environment(
    tree: &SyntaxTree,
    callable: &gantry_frontend::SyntaxNode,
    receiver: Option<&CanonicalPath>,
    facts: &BTreeMap<NodeId, TypeFact>,
) -> Result<BTreeMap<Arc<str>, TypeDescriptor>, AnalysisError> {
    let mut environment = BTreeMap::new();
    for parameter in callable.children().iter().copied().filter_map(|child| {
        let node = tree.node(child)?;
        matches!(node.form(), SyntaxForm::Parameter).then_some(node)
    }) {
        if has_direct_word(tree, parameter, "self") {
            if let Some(receiver) = receiver {
                environment.insert(
                    Arc::from("self"),
                    TypeDescriptor::declared(receiver.clone()),
                );
            }
            continue;
        }
        let Some(name) = direct_identifier(tree, parameter) else {
            continue;
        };
        let Some(ty) = direct_child_form(tree, parameter, SyntaxForm::ValueType)
            .and_then(|type_node| facts.get(&type_node))
            .map(|fact| fact.descriptor.clone())
        else {
            continue;
        };
        environment.insert(name, ty);
    }
    Ok(environment)
}

fn direct_method_call(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
    environment: &BTreeMap<Arc<str>, TypeDescriptor>,
    context: &WorkflowContext<'_>,
) -> Option<CanonicalPath> {
    let mut tokens = Vec::new();
    let mut work = expression
        .children()
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        if matches!(node.form(), SyntaxForm::Token(_)) {
            tokens.push(node);
        } else {
            work.extend(node.children().iter().rev().copied());
        }
    }
    let dot = tokens.iter().position(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        )
    })?;
    let root = tokens
        .get(..dot)?
        .iter()
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
                Some(Arc::from("self"))
            }
            _ => None,
        })?;
    let method = tokens
        .get(dot.saturating_add(1))
        .and_then(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })?;
    let called = tokens.get(dot.saturating_add(2)..).is_some_and(|tail| {
        tail.iter().any(|node| {
            matches!(
                node.form(),
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
            )
        })
    });
    if !called {
        return None;
    }
    let receiver = environment.get(&root)?.declared_path()?.clone();
    context
        .methods
        .get(&(receiver, method))
        .map(|shape| shape.path.clone())
}

fn semantic_children(tree: &SyntaxTree, id: NodeId) -> Result<Vec<NodeId>, AnalysisError> {
    let node = tree.node(id).ok_or(AnalysisError::Invariant)?;
    Ok(node
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| !matches!(node.form(), SyntaxForm::Token(_)))
        })
        .collect())
}

fn direct_call_path(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<NodeId> {
    let has_call = node
        .children()
        .iter()
        .copied()
        .any(|child| node_contains_punctuation(tree, child, Punctuation::LeftParenthesis));
    has_call.then(|| direct_child_form(tree, node, SyntaxForm::Path))?
}

fn static_joinall_membership(
    tree: &SyntaxTree,
    joinall: &gantry_frontend::SyntaxNode,
) -> Result<Vec<Arc<str>>, AnalysisError> {
    let block = tree
        .nodes()
        .iter()
        .filter(|candidate| {
            matches!(candidate.form(), SyntaxForm::Block)
                && span_contains(candidate.span(), joinall.span())
        })
        .min_by_key(|candidate| span_width(candidate.span()))
        .ok_or(AnalysisError::Invariant)?;
    let mut handles = Vec::new();
    for statement in block.children().iter().copied() {
        let statement_node = tree.node(statement).ok_or(AnalysisError::Invariant)?;
        if statement_node.span().bytes().start() >= joinall.span().bytes().start()
            || span_contains(statement_node.span(), joinall.span())
        {
            break;
        }
        if matches!(statement_node.form(), SyntaxForm::SpawnStatement) {
            if let Some(handle) = direct_identifiers(tree, statement).into_iter().next() {
                handles.push(handle);
            }
            continue;
        }
        apply_static_membership_consumptions(tree, statement, &mut handles)?;
    }
    Ok(handles)
}

fn apply_static_membership_consumptions(
    tree: &SyntaxTree,
    root: NodeId,
    handles: &mut Vec<Arc<str>>,
) -> Result<(), AnalysisError> {
    let node = tree.node(root).ok_or(AnalysisError::Invariant)?;
    match node.form() {
        SyntaxForm::JoinExpression | SyntaxForm::DetachStatement => {
            let consumed = direct_identifiers(tree, root)
                .into_iter()
                .collect::<BTreeSet<_>>();
            handles.retain(|handle| !consumed.contains(handle));
            return Ok(());
        }
        SyntaxForm::JoinAllExpression => {
            handles.clear();
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
                    let mut branch = handles.clone();
                    apply_static_membership_consumptions(tree, block, &mut branch)?;
                    Ok(branch)
                })
                .collect::<Result<Vec<_>, AnalysisError>>()?;
            let has_else = node.children().iter().any(|child| {
                tree.node(*child).is_some_and(|node| {
                    matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "else")
                })
            });
            if !has_else {
                branches.push(handles.clone());
            }
            retain_definite_membership(handles, &branches);
            return Ok(());
        }
        SyntaxForm::MatchStatement | SyntaxForm::MatchExpression => {
            let mut branches = Vec::new();
            for arm in node.children().iter().copied().filter(|child| {
                tree.node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
            }) {
                let arm_node = tree.node(arm).ok_or(AnalysisError::Invariant)?;
                let mut branch = handles.clone();
                for child in arm_node.children().iter().copied().filter(|child| {
                    tree.node(*child).is_some_and(|node| {
                        matches!(node.form(), SyntaxForm::Expression | SyntaxForm::Block)
                    })
                }) {
                    apply_static_membership_consumptions(tree, child, &mut branch)?;
                }
                branches.push(branch);
            }
            retain_definite_membership(handles, &branches);
            return Ok(());
        }
        SyntaxForm::WithStatement
        | SyntaxForm::SessionStatement
        | SyntaxForm::WithExpression
        | SyntaxForm::SessionExpression => {
            let block =
                direct_child_form(tree, node, SyntaxForm::Block).ok_or(AnalysisError::Invariant)?;
            return apply_static_membership_consumptions(tree, block, handles);
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
        apply_static_membership_consumptions(tree, child, handles)?;
    }
    Ok(())
}

fn retain_definite_membership(handles: &mut Vec<Arc<str>>, branches: &[Vec<Arc<str>>]) {
    if !branches.is_empty() {
        handles.retain(|handle| branches.iter().all(|branch| branch.contains(handle)));
    }
}

fn span_contains(outer: &SourceSpan, inner: &SourceSpan) -> bool {
    outer.source() == inner.source()
        && outer.bytes().start() <= inner.bytes().start()
        && outer.bytes().end() >= inner.bytes().end()
}

fn span_width(span: &SourceSpan) -> u64 {
    span.bytes().end().saturating_sub(span.bytes().start())
}

fn site_id(path: &CanonicalPath, position: &[u64]) -> Result<StaticSiteId, AnalysisError> {
    let position =
        StructuralPosition::new(position.to_vec()).map_err(|_| AnalysisError::Invariant)?;
    Ok(StaticSiteId::new(path.clone(), position))
}

fn action_effect(recovery: RecoveryClass) -> Effect {
    match recovery {
        RecoveryClass::ReadOnly => Effect::ActionReadOnly,
        RecoveryClass::Idempotent => Effect::ActionIdempotent,
        RecoveryClass::NonIdempotent => Effect::ActionNonIdempotent,
    }
}

fn effect_names(effects: EffectSet) -> String {
    effects
        .iter()
        .map(Effect::wire_name)
        .collect::<Vec<_>>()
        .join(",")
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
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(_)) => Some(child.span().clone()),
            _ => None,
        })
}

fn direct_identifier(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<Arc<str>> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })
}

fn direct_identifiers(tree: &SyntaxTree, id: NodeId) -> Vec<Arc<str>> {
    tree.node(id)
        .into_iter()
        .flat_map(gantry_frontend::SyntaxNode::children)
        .filter_map(|child| tree.node(*child))
        .filter_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn has_direct_word(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode, expected: &str) -> bool {
    node.children().iter().filter_map(|child| tree.node(*child)).any(|child| {
        matches!(child.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == expected)
    })
}

fn has_descendant_word(
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

fn effect_diagnostic<K, V, const N: usize>(
    code: &str,
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
            category: DiagnosticCategory::Type,
            code: DiagnosticCode::new(code).map_err(|_| AnalysisError::Invariant)?,
        },
        message,
        Some(primary),
        Vec::new(),
        fields,
    )
    .map_err(|_| AnalysisError::Invariant)
}

fn ownership_diagnostic<K, V, const N: usize>(
    code: &str,
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
            category: DiagnosticCategory::TaskOwnership,
            code: DiagnosticCode::new(code).map_err(|_| AnalysisError::Invariant)?,
        },
        message,
        Some(primary),
        Vec::new(),
        fields,
    )
    .map_err(|_| AnalysisError::Invariant)
}
