//! Bounded canonical artifact construction from analyzer-owned workflow facts.

use std::collections::{BTreeMap, BTreeSet};

use gantry_core::protocol::ProtocolVersion;
use gantry_core::source::{FrontendResourceLimit, SourceSnapshot, SourceSpan};
use gantry_frontend::{NodeId, ParsedSource, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::{CoreForm, TaskControlSiteKind};
use gantry_ir::{
    ArtifactEncodingError, ArtifactLimits, CanonicalIr, CanonicalNode, CanonicalOperationSite,
    CanonicalSourceMap, CanonicalTaskControlSite, CanonicalWorkflow, GenericAnalysisFacts,
    IrArtifactError, ManifestError, PackageSourceManifest, SourceMapEntry, StructuralPosition,
    TypeDescriptor, WorkflowFacts,
};

pub(crate) struct LoweredArtifacts {
    pub(crate) manifest: PackageSourceManifest,
    pub(crate) canonical_ir: CanonicalIr,
    pub(crate) source_map: CanonicalSourceMap,
}

pub(crate) enum LoweringError {
    ResourceLimit(FrontendResourceLimit),
    Invariant,
}

pub(crate) fn lower_package_manifest(
    snapshot: &SourceSnapshot,
    limits: ArtifactLimits,
) -> Result<PackageSourceManifest, LoweringError> {
    PackageSourceManifest::from_snapshot(snapshot, ProtocolVersion { major: 1, minor: 0 }, limits)
        .map_err(map_manifest_error)
}

pub(crate) fn lower_package_artifacts(
    snapshot: &SourceSnapshot,
    sources: &[ParsedSource],
    body_types: &[BTreeMap<NodeId, TypeDescriptor>],
    workflows: &[WorkflowFacts],
    generic: Option<GenericAnalysisFacts>,
    generic_declarations: &BTreeSet<SourceSpan>,
    limits: ArtifactLimits,
) -> Result<LoweredArtifacts, LoweringError> {
    if sources.len() != body_types.len() {
        return Err(LoweringError::Invariant);
    }
    let manifest = lower_package_manifest(snapshot, limits)?;
    let results = workflows
        .iter()
        .map(|workflow| (workflow.path.clone(), workflow.result.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut source_entries = Vec::new();
    let canonical_workflows = workflows
        .iter()
        .filter(|workflow| !generic_declarations.contains(&workflow.source))
        .map(|workflow| {
            let mut nodes = lower_workflow_nodes(sources, body_types, workflow, &results)?;
            nodes.sort_by(|left, right| left.0.position.cmp(&right.0.position));
            source_entries.extend(nodes.iter().map(|(node, source)| SourceMapEntry {
                workflow: workflow.path.clone(),
                position: node.position.clone(),
                source: source.clone(),
            }));
            CanonicalWorkflow::new(
                workflow.path.clone(),
                workflow.signature.clone(),
                workflow.effects,
                nodes.into_iter().map(|(node, _)| node).collect(),
            )
            .map_err(map_ir_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let generic = generic.unwrap_or_else(GenericAnalysisFacts::empty);
    let generic_entries = generic.source_map().to_vec();
    let canonical_ir = CanonicalIr::with_generic_facts(canonical_workflows, generic, limits)
        .map_err(map_ir_error)?;
    source_entries.sort_by(|left, right| {
        (&left.workflow, &left.position).cmp(&(&right.workflow, &right.position))
    });
    let source_map =
        CanonicalSourceMap::with_generic_entries(source_entries, generic_entries, limits)
            .map_err(map_ir_error)?;
    Ok(LoweredArtifacts {
        manifest,
        canonical_ir,
        source_map,
    })
}

fn lower_workflow_nodes(
    sources: &[ParsedSource],
    body_types: &[BTreeMap<NodeId, TypeDescriptor>],
    workflow: &WorkflowFacts,
    results: &BTreeMap<gantry_ir::CanonicalPath, TypeDescriptor>,
) -> Result<Vec<(CanonicalNode, gantry_core::source::SourceSpan)>, LoweringError> {
    let (source_index, source, callable) = sources
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
                    ) && node.span() == &workflow.source
                })
                .map(|(node_index, _)| (source_index, source, NodeId::from_index(node_index)))
        })
        .ok_or(LoweringError::Invariant)?;
    let types = body_types
        .get(source_index)
        .ok_or(LoweringError::Invariant)?;
    let tree = source.tree();
    let callable = tree.node(callable).ok_or(LoweringError::Invariant)?;
    let block = callable
        .children()
        .iter()
        .copied()
        .find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
        })
        .ok_or(LoweringError::Invariant)?;
    let mut work = semantic_children(tree, block)?
        .into_iter()
        .enumerate()
        .rev()
        .map(|(index, child)| (child, vec![index as u64], None))
        .collect::<Vec<_>>();
    let mut lowered = Vec::new();

    while let Some((id, position, inherited_type)) = work.pop() {
        let node = tree.node(id).ok_or(LoweringError::Invariant)?;
        let position = StructuralPosition::new(position).map_err(|_| LoweringError::Invariant)?;
        let children = semantic_children(tree, id)?;
        let child_positions = (0..children.len())
            .map(|index| {
                let mut child = position.components().to_vec();
                child.push(index as u64);
                StructuralPosition::new(child).map_err(|_| LoweringError::Invariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let inferred_type = types.get(&id).cloned().or(inherited_type);
        let (form, ty, operation, task_control) =
            classify_node(tree, node, &position, inferred_type, workflow, results);
        lowered.push((
            CanonicalNode {
                position: position.clone(),
                form,
                ty: ty.clone(),
                children: child_positions,
                operation,
                task_control,
            },
            node.span().clone(),
        ));
        for (index, child) in children.into_iter().enumerate().rev() {
            let mut child_position = position.components().to_vec();
            child_position.push(index as u64);
            work.push((child, child_position, Some(ty.clone())));
        }
    }
    let entry_check =
        StructuralPosition::new(vec![u64::MAX]).map_err(|_| LoweringError::Invariant)?;
    lowered.push((
        CanonicalNode {
            position: entry_check,
            form: CoreForm::CancellationCheck,
            ty: TypeDescriptor::UNIT,
            children: Vec::new(),
            operation: None,
            task_control: None,
        },
        workflow.source.clone(),
    ));
    Ok(lowered)
}

fn classify_node(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    position: &StructuralPosition,
    inferred_type: Option<TypeDescriptor>,
    workflow: &WorkflowFacts,
    results: &BTreeMap<gantry_ir::CanonicalPath, TypeDescriptor>,
) -> (
    CoreForm,
    TypeDescriptor,
    Option<CanonicalOperationSite>,
    Option<CanonicalTaskControlSite>,
) {
    if let Some(operation) = workflow
        .operations
        .iter()
        .find(|operation| operation.id.position() == position)
    {
        return (
            CoreForm::Operation,
            operation.result.clone(),
            Some(CanonicalOperationSite {
                kind: operation.kind,
                action: operation.action.clone(),
                recovery: operation.recovery,
                template_segments: operation_template_segments(tree, node),
                interpolation_inputs: operation_interpolation_inputs(tree, node),
                named_input_names: operation_named_input_names(tree, node),
                named_inputs: operation_named_inputs(tree, node, position),
            }),
            None,
        );
    }
    if let Some(call) = workflow
        .calls
        .iter()
        .find(|call| call.site.position() == position)
    {
        return (
            CoreForm::Call,
            results
                .get(&call.callee)
                .cloned()
                .unwrap_or(TypeDescriptor::UNIT),
            None,
            None,
        );
    }
    if let Some(control) = workflow
        .task_controls
        .iter()
        .find(|control| control.id.position() == position)
    {
        let form = match control.kind {
            TaskControlSiteKind::Spawn => CoreForm::Spawn,
            TaskControlSiteKind::Join | TaskControlSiteKind::JoinAll => CoreForm::Join,
            TaskControlSiteKind::Detach => CoreForm::BackgroundTransfer,
        };
        return (
            form,
            inferred_type.unwrap_or(TypeDescriptor::UNIT),
            None,
            Some(CanonicalTaskControlSite {
                kind: control.kind,
                handles: control.handles.clone(),
            }),
        );
    }

    let form = match node.form() {
        SyntaxForm::LetStatement | SyntaxForm::AssignmentStatement => CoreForm::Assignment,
        SyntaxForm::ReturnStatement
        | SyntaxForm::BreakStatement
        | SyntaxForm::ContinueStatement => CoreForm::Return,
        SyntaxForm::WithStatement | SyntaxForm::WithExpression => CoreForm::WithScope,
        SyntaxForm::SessionStatement | SyntaxForm::SessionExpression => CoreForm::SessionScope,
        SyntaxForm::IfStatement
        | SyntaxForm::MatchStatement
        | SyntaxForm::MatchExpression
        | SyntaxForm::MatchArm => CoreForm::Branch,
        SyntaxForm::LoopStatement
        | SyntaxForm::WhileStatement
        | SyntaxForm::UntilStatement
        | SyntaxForm::ForStatement => CoreForm::Loop,
        SyntaxForm::AttemptExpression => CoreForm::Attempt,
        SyntaxForm::StructExpression
        | SyntaxForm::FieldInitializer
        | SyntaxForm::ListExpression
        | SyntaxForm::TupleExpression => CoreForm::Aggregate,
        SyntaxForm::PostfixExpression => CoreForm::Projection,
        SyntaxForm::Path | SyntaxForm::Pattern | SyntaxForm::Parameter => CoreForm::Variable,
        SyntaxForm::Expression if expression_is_literal(tree, node) => CoreForm::Literal,
        SyntaxForm::Expression if expression_is_aggregate(tree, node) => CoreForm::Aggregate,
        SyntaxForm::Expression if expression_is_projection(tree, node) => CoreForm::Projection,
        SyntaxForm::Expression if expression_is_variable(tree, node) => CoreForm::Variable,
        SyntaxForm::PromptExpression
        | SyntaxForm::DecideExpression
        | SyntaxForm::ActionExpression => CoreForm::Operation,
        SyntaxForm::JoinExpression | SyntaxForm::JoinAllExpression => CoreForm::Join,
        SyntaxForm::SpawnStatement => CoreForm::Spawn,
        SyntaxForm::DetachStatement => CoreForm::BackgroundTransfer,
        _ => CoreForm::Sequence,
    };
    let ty = inferred_type
        .or_else(|| literal_type(tree, node))
        .unwrap_or(TypeDescriptor::UNIT);
    (form, ty, None, None)
}

fn operation_interpolation_inputs(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Vec<u64> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::PromptTemplate(template)) => {
                Some(0..u64::try_from(template.interpolations().len()).unwrap_or(u64::MAX))
            }
            _ => None,
        })
        .map(Iterator::collect)
        .unwrap_or_default()
}

fn operation_template_segments(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Vec<std::sync::Arc<str>> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::PromptTemplate(template)) => {
                Some(template.literals().to_vec())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn operation_named_input_names(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Vec<std::sync::Arc<str>> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter(|child| matches!(child.form(), SyntaxForm::UsingClause))
        .flat_map(|clause| {
            clause
                .children()
                .iter()
                .filter_map(|child| tree.node(*child))
        })
        .filter(|child| matches!(child.form(), SyntaxForm::NamedInput))
        .filter_map(|input| {
            input
                .children()
                .iter()
                .filter_map(|child| tree.node(*child))
                .find_map(|child| match child.form() {
                    SyntaxForm::Token(TokenKind::Identifier(name)) => Some(name.clone()),
                    _ => None,
                })
        })
        .collect()
}

fn operation_named_inputs(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    position: &StructuralPosition,
) -> Vec<StructuralPosition> {
    semantic_children(
        tree,
        NodeId::from_index(
            tree.nodes()
                .iter()
                .position(|candidate| std::ptr::eq(candidate, node))
                .unwrap_or(usize::MAX),
        ),
    )
    .ok()
    .into_iter()
    .flatten()
    .enumerate()
    .filter_map(|(child_index, child)| {
        let child = tree.node(child)?;
        if !matches!(child.form(), SyntaxForm::UsingClause) {
            return None;
        }
        Some(
            semantic_children(
                tree,
                NodeId::from_index(
                    tree.nodes()
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, child))
                        .unwrap_or(usize::MAX),
                ),
            )
            .ok()?
            .into_iter()
            .enumerate()
            .filter_map(|(input_index, input)| {
                let input = tree.node(input)?;
                matches!(input.form(), SyntaxForm::NamedInput).then(|| {
                    let mut components = position.components().to_vec();
                    components.push(child_index as u64);
                    components.push(input_index as u64);
                    StructuralPosition::new(components).ok()
                })?
            })
            .collect::<Vec<_>>(),
        )
    })
    .flatten()
    .collect()
}

fn semantic_children(tree: &SyntaxTree, id: NodeId) -> Result<Vec<NodeId>, LoweringError> {
    let node = tree.node(id).ok_or(LoweringError::Invariant)?;
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

fn expression_is_literal(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    node.children().iter().copied().any(|child| {
        tree.node(child).is_some_and(|child| match child.form() {
            SyntaxForm::Token(
                TokenKind::IntegerLiteral(_)
                | TokenKind::FloatLiteral(_)
                | TokenKind::StringLiteral(_)
                | TokenKind::RawStringLiteral(_),
            ) => true,
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => {
                matches!(word.spelling(), "true" | "false" | "null" | "None")
            }
            _ => false,
        })
    })
}

fn expression_is_aggregate(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    node.children().iter().copied().any(|child| {
        tree.node(child).is_some_and(|child| {
            matches!(
                child.form(),
                SyntaxForm::StructExpression
                    | SyntaxForm::ListExpression
                    | SyntaxForm::TupleExpression
            )
        })
    })
}

fn expression_is_projection(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    node.children().iter().copied().any(|child| {
        tree.node(child)
            .is_some_and(|child| matches!(child.form(), SyntaxForm::PostfixExpression))
    })
}

fn expression_is_variable(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    node.children().iter().copied().any(|child| {
        tree.node(child)
            .is_some_and(|child| matches!(child.form(), SyntaxForm::Path))
    })
}

fn literal_type(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<TypeDescriptor> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::IntegerLiteral(_)) => Some(TypeDescriptor::INT),
            SyntaxForm::Token(TokenKind::FloatLiteral(_)) => Some(TypeDescriptor::FLOAT),
            SyntaxForm::Token(TokenKind::StringLiteral(_) | TokenKind::RawStringLiteral(_)) => {
                Some(TypeDescriptor::STRING)
            }
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => match word.spelling() {
                "true" | "false" => Some(TypeDescriptor::BOOL),
                "null" => Some(TypeDescriptor::UNIT),
                _ => None,
            },
            _ => None,
        })
}

fn map_manifest_error(error: ManifestError) -> LoweringError {
    match error {
        ManifestError::Encoding(ArtifactEncodingError::ResourceLimit(error)) => {
            LoweringError::ResourceLimit(error)
        }
        ManifestError::UnsupportedSourceLanguage
        | ManifestError::MissingRootFile
        | ManifestError::NoncanonicalFileOrder
        | ManifestError::ByteLengthOverflow
        | ManifestError::Encoding(ArtifactEncodingError::Empty) => LoweringError::Invariant,
    }
}

fn map_ir_error(error: IrArtifactError) -> LoweringError {
    match error {
        IrArtifactError::Encoding(ArtifactEncodingError::ResourceLimit(error)) => {
            LoweringError::ResourceLimit(error)
        }
        IrArtifactError::NoncanonicalOrder
        | IrArtifactError::Encoding(ArtifactEncodingError::Empty) => LoweringError::Invariant,
    }
}
