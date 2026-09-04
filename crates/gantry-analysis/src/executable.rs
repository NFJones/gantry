//! Analyzer-owned lowering from typed surface syntax to executable machine IR.
//!
//! This private pass resolves syntax while the analyzer still owns source trees,
//! then emits only typed, name-resolved contracts from `gantry-ir`. The runtime
//! consumes that contract without parsing source or repeating static analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValuePathSegment};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::{
    ActionInventory, AggregateKind, CanonicalCallableIdentity, CanonicalPath, Comparison,
    EffectSet, EntryInventory, ExecutableAction, ExecutableOperation, ExecutableTaskBody,
    ExecutableTaskCapture, ExecutableTaskContext, ExecutableTaskHandle, Instruction,
    InstructionKind, LoopPhase, MachineProgram, Parameter, Primitive, ProgramError, Projection,
    StructuralPosition, TaskBodyIdentity, TypeDescriptor, Workflow, WorkflowFacts,
};

use crate::bodies::{BodyAnalysis, EffectNode, SpawnCaptureMetadata};
use crate::{AnalysisError, TypeFact};

pub(crate) fn lower_executable_program(
    sources: &[ParsedSource],
    type_facts: &[BTreeMap<NodeId, TypeFact>],
    body_types: &[BTreeMap<NodeId, TypeDescriptor>],
    entry: &EntryInventory,
    workflows: &[WorkflowFacts],
    actions: &[ActionInventory],
    body: &BodyAnalysis,
) -> Result<MachineProgram, AnalysisError> {
    if sources.len() != type_facts.len() || sources.len() != body_types.len() {
        return Err(AnalysisError::Invariant);
    }

    let source_identities = body
        .source_callables
        .iter()
        .map(|callable| (callable.declaration.clone(), callable.identity.clone()))
        .collect::<BTreeMap<_, _>>();
    let concrete_identities = body
        .generic_instantiations
        .iter()
        .filter_map(|instantiation| {
            let gantry_ir::ConcreteIdentity::Callable(identity) = instantiation.concrete() else {
                return None;
            };
            Some((
                (
                    instantiation.template().clone(),
                    instantiation.arguments().to_vec(),
                ),
                identity.clone(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let identity_for = |node: &EffectNode| -> Result<CanonicalCallableIdentity, AnalysisError> {
        match node {
            EffectNode::Source(source) => source_identities.get(source),
            EffectNode::Concrete(key) => concrete_identities.get(key),
            EffectNode::Template(_) => None,
        }
        .cloned()
        .ok_or(AnalysisError::Invariant)
    };
    let mut direct_targets = BTreeMap::<
        CanonicalCallableIdentity,
        Vec<(gantry_core::source::SourceSpan, CanonicalCallableIdentity)>,
    >::new();
    for call in &body.resolved_calls {
        direct_targets
            .entry(identity_for(&call.caller)?)
            .or_default()
            .push((call.source.clone(), identity_for(&call.callee)?));
    }
    for targets in direct_targets.values_mut() {
        targets.sort();
        targets.dedup();
    }
    let mut edges = BTreeMap::<CanonicalCallableIdentity, Vec<CanonicalCallableIdentity>>::new();
    for callable in &body.source_callables {
        edges.insert(
            callable.identity.clone(),
            callable
                .direct_calls
                .iter()
                .map(&identity_for)
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    for callable in &body.concrete_callables {
        let identity = concrete_identities
            .get(&callable.key)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        edges.insert(
            identity,
            callable
                .direct_calls
                .iter()
                .map(&identity_for)
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let root_identity = CanonicalCallableIdentity::free(&entry.path, &[]);
    let mut reachable = BTreeSet::new();
    let mut pending = vec![root_identity.clone()];
    while let Some(identity) = pending.pop() {
        if !reachable.insert(identity.clone()) {
            continue;
        }
        pending.extend(
            edges
                .get(&identity)
                .ok_or(AnalysisError::Invariant)?
                .iter()
                .cloned(),
        );
    }
    let mut lowered = Vec::with_capacity(reachable.len());
    let mut task_bodies = Vec::new();
    for metadata in body
        .source_callables
        .iter()
        .filter(|callable| reachable.contains(&callable.identity))
    {
        let facts = workflows
            .iter()
            .find(|facts| facts.source == metadata.declaration)
            .ok_or(AnalysisError::Invariant)?;
        let (source_index, tree, callable) = find_callable(sources, &metadata.declaration)?;
        let mut compiler = Compiler {
            tree,
            declaration_types: type_facts
                .get(source_index)
                .ok_or(AnalysisError::Invariant)?,
            body_types: body_types
                .get(source_index)
                .ok_or(AnalysisError::Invariant)?,
            facts,
            receiver_type: metadata.receiver.as_ref(),
            result: &metadata.result,
            effects: metadata.effects,
            direct_targets: direct_targets
                .get(&metadata.identity)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            operation_results: None,
            closed_enums: &body.closed_enums,
            actions,
            instructions: Vec::new(),
            identity: &metadata.identity,
            spawn_captures: body
                .spawn_captures
                .get(&EffectNode::Source(metadata.declaration.clone())),
            task_bodies: &mut task_bodies,
            task_sites: BTreeMap::new(),
            loops: Vec::new(),
            cleanup: Vec::new(),
        };
        let compiled = compiler.compile_callable(callable)?;
        lowered.push((metadata.identity.clone(), compiled));
    }
    for metadata in body.concrete_callables.iter().filter(|callable| {
        concrete_identities
            .get(&callable.key)
            .is_some_and(|identity| reachable.contains(identity))
    }) {
        let identity = concrete_identities
            .get(&metadata.key)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        let facts = workflows
            .iter()
            .find(|facts| facts.source == metadata.declaration)
            .ok_or(AnalysisError::Invariant)?;
        let (_, tree, callable) = find_callable(sources, &metadata.declaration)?;
        let effects = body
            .generic_concrete_effects
            .get(&metadata.key)
            .copied()
            .ok_or(AnalysisError::Invariant)?;
        let mut compiler = Compiler {
            tree,
            declaration_types: &metadata.declaration_types,
            body_types: &metadata.expression_types,
            facts,
            receiver_type: metadata.receiver.as_ref(),
            result: &metadata.result,
            effects,
            direct_targets: direct_targets
                .get(&identity)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            operation_results: Some(&metadata.operation_results),
            closed_enums: &body.closed_enums,
            actions,
            instructions: Vec::new(),
            identity: &identity,
            spawn_captures: body
                .spawn_captures
                .get(&EffectNode::Concrete(metadata.key.clone())),
            task_bodies: &mut task_bodies,
            task_sites: BTreeMap::new(),
            loops: Vec::new(),
            cleanup: Vec::new(),
        };
        let compiled = compiler.compile_callable(callable)?;
        lowered.push((identity, compiled));
    }
    lowered.sort_by(|left, right| left.0.cmp(&right.0));
    task_bodies.sort_by(|left, right| left.identity().cmp(right.identity()));
    MachineProgram::with_task_bodies(lowered, task_bodies).map_err(|_| AnalysisError::Invariant)
}

fn find_callable<'a>(
    sources: &'a [ParsedSource],
    declaration: &gantry_core::source::SourceSpan,
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

struct Compiler<'a> {
    tree: &'a SyntaxTree,
    declaration_types: &'a BTreeMap<NodeId, TypeFact>,
    body_types: &'a BTreeMap<NodeId, TypeDescriptor>,
    facts: &'a WorkflowFacts,
    receiver_type: Option<&'a TypeDescriptor>,
    result: &'a TypeDescriptor,
    effects: EffectSet,
    direct_targets: &'a [(gantry_core::source::SourceSpan, CanonicalCallableIdentity)],
    operation_results: Option<&'a BTreeMap<gantry_core::source::SourceSpan, TypeDescriptor>>,
    closed_enums: &'a BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, Option<TypeDescriptor>>>,
    actions: &'a [ActionInventory],
    instructions: Vec<Instruction>,
    identity: &'a CanonicalCallableIdentity,
    spawn_captures:
        Option<&'a BTreeMap<gantry_core::source::SourceSpan, Vec<SpawnCaptureMetadata>>>,
    task_bodies: &'a mut Vec<ExecutableTaskBody>,
    task_sites: BTreeMap<usize, StructuralPosition>,
    loops: Vec<LoopTarget>,
    cleanup: Vec<InstructionKind>,
}

/// Pending lexical loop transfers, isolated from enclosing callable/task bodies.
struct LoopTarget {
    start: usize,
    cleanup_depth: usize,
    breaks: Vec<usize>,
}

impl Compiler<'_> {
    fn compile_callable(&mut self, callable: NodeId) -> Result<Workflow, AnalysisError> {
        let parameters = self.compile_parameters(callable)?;
        let node = self.node(callable)?;
        let block = direct_child_form(self.tree, node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        self.compile_block(block, BlockMode::Callable)?;
        self.finish_sites()?;
        Ok(Workflow {
            path: self.facts.path.clone(),
            parameters,
            result: self.result.clone(),
            effects: self.effects,
            instructions: std::mem::take(&mut self.instructions),
        })
    }

    /// Lowers one independent child and restores the parent's instruction stream.
    fn compile_spawn(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?.clone();
        let site = self
            .facts
            .task_controls
            .iter()
            .find(|site| site.source == *node.span())
            .ok_or(AnalysisError::Invariant)?
            .clone();
        let result = direct_child_form(self.tree, &node, SyntaxForm::ValueType)
            .and_then(|id| self.declaration_types.get(&id))
            .map_or(TypeDescriptor::UNIT, |fact| fact.descriptor.clone());
        let block = direct_child_form(self.tree, &node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        let identity = TaskBodyIdentity::new(self.identity.clone(), site.id.position().clone());
        let candidates = self
            .spawn_captures
            .and_then(|sites| sites.get(node.span()))
            .ok_or(AnalysisError::Invariant)?;
        let mut child = Compiler {
            tree: self.tree,
            declaration_types: self.declaration_types,
            body_types: self.body_types,
            facts: self.facts,
            receiver_type: self.receiver_type,
            result: &result,
            effects: self.effects,
            direct_targets: self.direct_targets,
            operation_results: self.operation_results,
            closed_enums: self.closed_enums,
            actions: self.actions,
            instructions: Vec::new(),
            identity: self.identity,
            spawn_captures: self.spawn_captures,
            task_bodies: self.task_bodies,
            task_sites: BTreeMap::new(),
            loops: Vec::new(),
            cleanup: Vec::new(),
        };
        child.compile_block(block, BlockMode::Callable)?;
        child.finish_sites()?;
        let captures = child.select_captures(candidates)?;
        for instruction in &mut child.instructions {
            if matches!(instruction.kind, InstructionKind::Return) {
                instruction.kind = InstructionKind::TaskComplete;
            }
        }
        let body = ExecutableTaskBody::new(
            identity.clone(),
            result.clone(),
            captures,
            ExecutableTaskContext::v1(),
            child.instructions,
        )
        .map_err(|_| AnalysisError::Invariant)?;
        self.task_bodies.push(body);
        let handle = ExecutableTaskHandle::new(
            site.handles
                .first()
                .cloned()
                .ok_or(AnalysisError::Invariant)?,
            result,
        )
        .map_err(|_| AnalysisError::Invariant)?;
        let index = self.emit(
            TypeDescriptor::UNIT,
            InstructionKind::Spawn {
                handle,
                body: identity,
            },
        )?;
        self.task_sites.insert(index, site.id.position().clone());
        Ok(())
    }

    /// Selects free value bindings in first-use order, including nested captures.
    fn select_captures(
        &self,
        candidates: &[SpawnCaptureMetadata],
    ) -> Result<Vec<ExecutableTaskCapture>, AnalysisError> {
        // Valid source cannot shadow an outer binding. Runtime cleanup may be
        // emitted on several control-flow edges, so it is not a lexical walk.
        let locals = self
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let InstructionKind::Bind { name, .. } = &instruction.kind {
                    Some(name)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        let mut selected = BTreeSet::new();
        let mut captures = Vec::new();
        for instruction in &self.instructions {
            let names = match &instruction.kind {
                InstructionKind::Load(name) | InstructionKind::Assign { name, .. } => {
                    vec![name.clone()]
                }
                InstructionKind::Spawn { body, .. } => self
                    .task_bodies
                    .iter()
                    .find(|candidate| candidate.identity() == body)
                    .ok_or(AnalysisError::Invariant)?
                    .captures()
                    .iter()
                    .map(|capture| Arc::from(capture.name()))
                    .collect(),
                _ => Vec::new(),
            };
            for name in names {
                if locals.contains(&name) || !selected.insert(name.clone()) {
                    continue;
                }
                let candidate = candidates
                    .iter()
                    .find(|candidate| candidate.name == name)
                    .ok_or(AnalysisError::Invariant)?;
                captures.push(
                    ExecutableTaskCapture::new(name, candidate.ty.clone(), candidate.mutable)
                        .map_err(|_| AnalysisError::Invariant)?,
                );
            }
        }
        Ok(captures)
    }

    /// Uses ownership analysis's exact source/declaration-order handle selection.
    fn compile_task_control(
        &mut self,
        control: NodeId,
        ty: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let node = self.node(control)?;
        let site = self
            .facts
            .task_controls
            .iter()
            .find(|site| site.source == *node.span())
            .ok_or(AnalysisError::Invariant)?
            .clone();
        let kind = match node.form() {
            SyntaxForm::JoinExpression => InstructionKind::Join {
                handles: site.handles,
            },
            SyntaxForm::JoinAllExpression => InstructionKind::JoinAll {
                handles: site.handles,
            },
            SyntaxForm::DetachStatement => InstructionKind::Detach {
                handle: site
                    .handles
                    .first()
                    .cloned()
                    .ok_or(AnalysisError::Invariant)?,
            },
            _ => return Err(AnalysisError::Invariant),
        };
        let index = self.emit(ty.clone(), kind)?;
        self.task_sites.insert(index, site.id.position().clone());
        Ok(ty)
    }

    /// Retains canonical task sites while placing auxiliary instructions between them.
    fn finish_sites(&mut self) -> Result<(), AnalysisError> {
        if self.task_sites.is_empty() {
            return Ok(());
        }
        let mut previous: Option<StructuralPosition> = None;
        for index in 0..self.instructions.len() {
            let site = if let Some(site) = self.task_sites.get(&index) {
                site.clone()
            } else {
                let upper = self.task_sites.range(index..).next().map(|(_, site)| site);
                let mut components = previous
                    .as_ref()
                    .map_or_else(Vec::new, |site| site.components().to_vec());
                components.push(0);
                let mut candidate =
                    StructuralPosition::new(components).map_err(|_| AnalysisError::Invariant)?;
                if let Some(upper) = upper.filter(|upper| candidate >= **upper) {
                    let components = upper.components();
                    let pivot = components
                        .iter()
                        .rposition(|part| *part > 0)
                        .ok_or(AnalysisError::Invariant)?;
                    let mut before = components[..pivot].to_vec();
                    before.extend([components[pivot] - 1, u64::MAX, index as u64]);
                    candidate =
                        StructuralPosition::new(before).map_err(|_| AnalysisError::Invariant)?;
                }
                candidate
            };
            if previous.as_ref().is_some_and(|previous| previous >= &site) {
                return Err(AnalysisError::Invariant);
            }
            self.instructions[index].site = site.clone();
            previous = Some(site);
        }
        Ok(())
    }

    fn compile_parameters(&self, callable: NodeId) -> Result<Vec<Parameter>, AnalysisError> {
        let node = self.node(callable)?;
        let mut parameters = Vec::new();
        if matches!(node.form(), SyntaxForm::MethodDeclaration) {
            let receiver = self
                .receiver_type
                .cloned()
                .ok_or(AnalysisError::Invariant)?;
            let mutable = semantic_children(self.tree, callable)?
                .into_iter()
                .any(|parameter| {
                    self.tree.node(parameter).is_some_and(|parameter| {
                        matches!(parameter.form(), SyntaxForm::Parameter)
                            && node_has_word(self.tree, parameter, "self")
                            && node_has_word(self.tree, parameter, "mut")
                    })
                });
            parameters.push(Parameter {
                name: Arc::from("self"),
                ty: receiver,
                mutable,
            });
        }
        for parameter in semantic_children(self.tree, callable)? {
            let parameter_node = self.node(parameter)?;
            if !matches!(parameter_node.form(), SyntaxForm::Parameter)
                || node_has_word(self.tree, parameter_node, "self")
            {
                continue;
            }
            let name = direct_identifier(self.tree, parameter).ok_or(AnalysisError::Invariant)?;
            let type_node = direct_child_form(self.tree, parameter_node, SyntaxForm::ValueType)
                .ok_or(AnalysisError::Invariant)?;
            let ty = self
                .declaration_types
                .get(&type_node)
                .map(|fact| fact.descriptor.clone())
                .ok_or(AnalysisError::Invariant)?;
            parameters.push(Parameter {
                name,
                ty,
                mutable: node_has_word(self.tree, parameter_node, "mut"),
            });
        }
        Ok(parameters)
    }

    fn compile_block(&mut self, block: NodeId, mode: BlockMode) -> Result<(), AnalysisError> {
        let children = semantic_children(self.tree, block)?;
        let mut cursor = 0_usize;
        let mut produced_value = false;
        while cursor < children.len() {
            let child = children[cursor];
            let node = self.node(child)?;
            match node.form() {
                SyntaxForm::LetStatement => self.compile_let(child)?,
                SyntaxForm::AssignmentStatement => self.compile_assignment(child)?,
                SyntaxForm::SpawnStatement => self.compile_spawn(child)?,
                SyntaxForm::DetachStatement => {
                    self.compile_task_control(child, TypeDescriptor::UNIT)?;
                }
                SyntaxForm::DiscardStatement => {
                    let expression = direct_child_form(self.tree, node, SyntaxForm::Expression)
                        .ok_or(AnalysisError::Invariant)?;
                    let ty = self.compile_expression(expression)?;
                    self.emit(ty, InstructionKind::Pop)?;
                }
                SyntaxForm::ReturnStatement => {
                    if let Some(expression) =
                        direct_child_form(self.tree, node, SyntaxForm::Expression)
                    {
                        let ty = self.compile_expression(expression)?;
                        self.emit(ty, InstructionKind::Return)?;
                    } else {
                        self.emit(
                            TypeDescriptor::UNIT,
                            InstructionKind::Push(LogicalValue::unit()),
                        )?;
                        self.emit(TypeDescriptor::UNIT, InstructionKind::Return)?;
                    }
                    return Ok(());
                }
                SyntaxForm::IfStatement => self.compile_if(child)?,
                SyntaxForm::WhileStatement | SyntaxForm::LoopStatement => {
                    self.compile_while(child)?
                }
                SyntaxForm::BreakStatement | SyntaxForm::ContinueStatement => {
                    self.compile_loop_transfer(matches!(node.form(), SyntaxForm::BreakStatement))?;
                    return Ok(());
                }
                SyntaxForm::WithStatement | SyntaxForm::SessionStatement => {
                    self.compile_context_statement(child)?;
                }
                SyntaxForm::Expression => {
                    let ty = self.compile_expression(child)?;
                    let terminated = children.get(cursor.saturating_add(1)).is_some_and(|next| {
                        self.tree.node(*next).is_some_and(|node| {
                            matches!(node.form(), SyntaxForm::ExpressionStatement)
                        })
                    });
                    if terminated {
                        self.emit(ty, InstructionKind::Pop)?;
                        cursor = cursor.saturating_add(1);
                    } else {
                        produced_value = true;
                        match mode {
                            BlockMode::Callable => {
                                self.emit(ty, InstructionKind::Return)?;
                                return Ok(());
                            }
                            BlockMode::Value => return Ok(()),
                            BlockMode::Statement => {
                                self.emit(ty, InstructionKind::Pop)?;
                            }
                        }
                    }
                }
                SyntaxForm::ExpressionStatement => {}
                _ => return Err(AnalysisError::Invariant),
            }
            cursor = cursor.saturating_add(1);
        }
        if mode == BlockMode::Callable {
            if self.result != &TypeDescriptor::UNIT {
                return Err(AnalysisError::Invariant);
            }
            self.emit(
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            )?;
            self.emit(TypeDescriptor::UNIT, InstructionKind::Return)?;
        } else if mode == BlockMode::Value && !produced_value {
            self.emit(
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            )?;
        }
        Ok(())
    }

    fn compile_let(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?.clone();
        let expression = direct_child_form(self.tree, &node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        let mutable = node_has_word(self.tree, &node, "mut");
        let ty = self.compile_expression(expression)?;
        let name = direct_identifier(self.tree, statement).ok_or(AnalysisError::Invariant)?;
        self.emit(ty.clone(), InstructionKind::Bind { name, ty, mutable })?;
        Ok(())
    }

    fn compile_assignment(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?;
        let names = direct_identifiers(self.tree, statement);
        let root = if node_has_word(self.tree, node, "self") {
            Arc::from("self")
        } else {
            names.first().cloned().ok_or(AnalysisError::Invariant)?
        };
        let fields = if root.as_ref() == "self" {
            names.as_slice()
        } else {
            names.get(1..).unwrap_or_default()
        };
        let expression = direct_child_form(self.tree, node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        let operator = assignment_operator(self.tree, node).ok_or(AnalysisError::Invariant)?;
        if operator != Punctuation::Equal {
            self.emit(
                TypeDescriptor::UNIT,
                InstructionKind::Load(Arc::clone(&root)),
            )?;
        }
        let ty = self.compile_expression(expression)?;
        if operator != Punctuation::Equal {
            let primitive = primitive_for_assignment(operator).ok_or(AnalysisError::Invariant)?;
            self.emit(ty.clone(), InstructionKind::Primitive(primitive))?;
        }
        self.emit(
            ty.clone(),
            InstructionKind::Assign {
                name: root,
                path: fields
                    .iter()
                    .map(|field| ValuePathSegment::StructField(field.to_string()))
                    .collect(),
                target_type: ty,
            },
        )?;
        Ok(())
    }

    fn compile_if(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?;
        let condition = direct_child_form(self.tree, node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        let condition_type = self.compile_expression(condition)?;
        let branch = self.emit(
            condition_type,
            InstructionKind::Branch {
                when_true: 0,
                when_false: 0,
            },
        )?;
        let blocks = semantic_children(self.tree, statement)?
            .into_iter()
            .filter(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
            })
            .collect::<Vec<_>>();
        let when_true = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        self.compile_block(
            *blocks.first().ok_or(AnalysisError::Invariant)?,
            BlockMode::Statement,
        )?;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;
        let when_false = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        if let Some(otherwise) = blocks.get(1) {
            self.compile_block(*otherwise, BlockMode::Statement)?;
        }
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let end = self.instructions.len();
        self.instructions[branch].kind = InstructionKind::Branch {
            when_true,
            when_false,
        };
        self.instructions[jump].kind = InstructionKind::Jump(end);
        Ok(())
    }

    fn compile_while(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?.clone();
        let condition = direct_child_form(self.tree, &node, SyntaxForm::Expression);
        let body = direct_child_form(self.tree, &node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        let source_limit = loop_limit(self.tree, &node);
        let start = self.instructions.len();
        self.emit(
            TypeDescriptor::UNIT,
            InstructionKind::EnterLoop {
                phase: LoopPhase::Condition,
                source_limit: None,
            },
        )?;
        let condition_type = if let Some(condition) = condition {
            self.compile_expression(condition)?
        } else {
            self.emit(
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            )?;
            TypeDescriptor::BOOL
        };
        let branch = self.emit(
            condition_type,
            InstructionKind::Branch {
                when_true: 0,
                when_false: 0,
            },
        )?;
        let when_true = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        self.emit(
            TypeDescriptor::UNIT,
            InstructionKind::EnterLoop {
                phase: LoopPhase::Body,
                source_limit,
            },
        )?;
        self.loops.push(LoopTarget {
            start,
            cleanup_depth: self.cleanup.len(),
            breaks: Vec::new(),
        });
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.compile_block(body, BlockMode::Statement)?;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(start))?;
        let when_false = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        self.instructions[branch].kind = InstructionKind::Branch {
            when_true,
            when_false,
        };
        let end = self.instructions.len();
        let target = self.loops.pop().ok_or(AnalysisError::Invariant)?;
        for jump in target.breaks {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        Ok(())
    }

    /// Leaves nested lexical scopes before transferring to the nearest loop.
    fn compile_loop_transfer(&mut self, is_break: bool) -> Result<(), AnalysisError> {
        let target = self.loops.last().ok_or(AnalysisError::Invariant)?;
        let start = target.start;
        let cleanup = self.cleanup[target.cleanup_depth..].to_vec();
        for kind in cleanup.into_iter().rev() {
            self.emit(TypeDescriptor::UNIT, kind)?;
        }
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(start))?;
        if is_break {
            self.loops
                .last_mut()
                .ok_or(AnalysisError::Invariant)?
                .breaks
                .push(jump);
        }
        Ok(())
    }

    fn compile_context_statement(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?.clone();
        let is_with = matches!(node.form(), SyntaxForm::WithStatement);
        let body = direct_child_form(self.tree, &node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        if is_with {
            let agent = direct_identifier(self.tree, statement).ok_or(AnalysisError::Invariant)?;
            self.emit(TypeDescriptor::UNIT, InstructionKind::EnterAgent(agent))?;
        } else {
            let session = direct_word(self.tree, &node, &["inline", "fork", "new"])
                .ok_or(AnalysisError::Invariant)?;
            self.emit(TypeDescriptor::UNIT, InstructionKind::EnterSession(session))?;
        }
        self.cleanup.push(if is_with {
            InstructionKind::ExitAgent
        } else {
            InstructionKind::ExitSession
        });
        self.compile_block(body, BlockMode::Statement)?;
        self.cleanup.pop();
        self.emit(
            TypeDescriptor::UNIT,
            if is_with {
                InstructionKind::ExitAgent
            } else {
                InstructionKind::ExitSession
            },
        )?;
        Ok(())
    }

    fn compile_expression(&mut self, expression: NodeId) -> Result<TypeDescriptor, AnalysisError> {
        let node = self.node(expression)?.clone();
        let ty = self
            .body_types
            .get(&expression)
            .cloned()
            .or_else(|| literal_type(self.tree, &node))
            .unwrap_or(TypeDescriptor::UNIT);

        let control = if matches!(
            node.form(),
            SyntaxForm::JoinExpression | SyntaxForm::JoinAllExpression
        ) {
            Some(expression)
        } else if binary_operator(self.tree, &node).is_none() {
            let children = semantic_children(self.tree, expression)?;
            (children.len() == 1).then(|| children[0]).filter(|child| {
                self.tree.node(*child).is_some_and(|node| {
                    matches!(
                        node.form(),
                        SyntaxForm::JoinExpression | SyntaxForm::JoinAllExpression
                    )
                })
            })
        } else {
            None
        };
        if let Some(control) = control {
            return self.compile_task_control(control, ty);
        }
        if let Some(match_expression) =
            descendant_form(self.tree, expression, &[SyntaxForm::MatchExpression])
        {
            return self.compile_match(match_expression, ty);
        }
        if let Some(operation) = descendant_form(
            self.tree,
            expression,
            &[
                SyntaxForm::PromptExpression,
                SyntaxForm::DecideExpression,
                SyntaxForm::ActionExpression,
                SyntaxForm::AttemptExpression,
            ],
        ) {
            return self.compile_operation(operation, ty);
        }
        if let Some((operator, index)) = binary_operator(self.tree, &node) {
            let left = node.children()[..index].to_vec();
            let right = node.children()[index.saturating_add(1)..].to_vec();
            self.compile_sequence(&left)?;
            self.compile_sequence(&right)?;
            let primitive = primitive_for_binary(operator).ok_or(AnalysisError::Invariant)?;
            self.emit(ty.clone(), InstructionKind::Primitive(primitive))?;
            return Ok(ty);
        }
        if matches!(node.form(), SyntaxForm::UnaryExpression)
            || descendant_form(self.tree, expression, &[SyntaxForm::UnaryExpression]).is_some()
        {
            let unary = if matches!(node.form(), SyntaxForm::UnaryExpression) {
                expression
            } else {
                descendant_form(self.tree, expression, &[SyntaxForm::UnaryExpression])
                    .ok_or(AnalysisError::Invariant)?
            };
            let unary_node = self.node(unary)?.clone();
            let operator =
                direct_punctuation(self.tree, &unary_node).ok_or(AnalysisError::Invariant)?;
            let children = unary_node.children().to_vec();
            self.compile_sequence(&children)?;
            self.emit(
                ty.clone(),
                InstructionKind::Primitive(match operator {
                    Punctuation::Bang => Primitive::Not,
                    Punctuation::Minus => Primitive::Negate,
                    _ => return Err(AnalysisError::Invariant),
                }),
            )?;
            return Ok(ty);
        }
        if let Some(callee) = self.direct_target(&node) {
            let receiver_type = callee.receiver_type();
            let constructed_receiver = receiver_type.as_ref().and_then(|_| {
                descendant_form(self.tree, expression, &[SyntaxForm::StructExpression])
            });
            let named_receiver = receiver_type
                .as_ref()
                .and_then(|_| postfix_method_receiver(self.tree, &node));
            let has_implicit_receiver = constructed_receiver.is_some() || named_receiver.is_some();
            if let (Some(struct_expression), Some(receiver_type)) =
                (constructed_receiver, receiver_type.as_ref())
            {
                self.compile_struct(expression, struct_expression, receiver_type.clone())?;
            } else if let (Some(receiver), Some(receiver_type)) =
                (&named_receiver, receiver_type.as_ref())
            {
                self.emit(
                    receiver_type.clone(),
                    InstructionKind::Load(receiver.clone()),
                )?;
            }
            let arguments = direct_expressions(self.tree, &node);
            for argument in &arguments {
                self.compile_expression(*argument)?;
            }
            self.emit(
                ty.clone(),
                InstructionKind::Call {
                    callee,
                    arguments: arguments
                        .len()
                        .saturating_add(usize::from(has_implicit_receiver)),
                },
            )?;
            return Ok(ty);
        }
        if let Some(call) = self
            .facts
            .calls
            .iter()
            .find(|call| &call.source == node.span())
        {
            let receiver = postfix_method_receiver(self.tree, &node);
            if let Some(receiver) = &receiver {
                let receiver_type = method_receiver_type(&call.callee)?;
                self.emit(receiver_type, InstructionKind::Load(receiver.clone()))?;
            }
            let arguments = direct_expressions(self.tree, &node);
            for argument in &arguments {
                self.compile_expression(*argument)?;
            }
            self.emit(
                ty.clone(),
                InstructionKind::Call {
                    callee: CanonicalCallableIdentity::free(&call.callee, &[]),
                    arguments: arguments
                        .len()
                        .saturating_add(usize::from(receiver.is_some())),
                },
            )?;
            return Ok(ty);
        }
        if let Some(struct_expression) =
            descendant_form(self.tree, expression, &[SyntaxForm::StructExpression])
        {
            return self.compile_struct(expression, struct_expression, ty);
        }
        if let Some((root, field)) = postfix_field_projection(self.tree, &node) {
            self.emit(ty.clone(), InstructionKind::Load(root))?;
            self.emit(
                ty.clone(),
                InstructionKind::Project(Projection::Field(field)),
            )?;
            return Ok(ty);
        }
        if let Some(projection) = self.compile_static_projection(expression, &node, &ty)? {
            return Ok(projection);
        }
        if let Some(variant) =
            enum_constructor_variant(self.tree, &node, self.closed_enums.get(&ty))
        {
            let variants = self.closed_enums.get(&ty).ok_or(AnalysisError::Invariant)?;
            let has_payload = variants
                .get(&variant)
                .ok_or(AnalysisError::Invariant)?
                .is_some();
            let expressions = direct_expressions(self.tree, &node);
            if expressions.len() != usize::from(has_payload) {
                return Err(AnalysisError::Invariant);
            }
            for payload in &expressions {
                self.compile_expression(*payload)?;
            }
            let type_name = Arc::from(ty.canonical_string());
            self.emit(
                ty.clone(),
                InstructionKind::Aggregate {
                    kind: AggregateKind::Enum {
                        type_name,
                        variant,
                        has_payload,
                    },
                    operands: expressions.len(),
                },
            )?;
            return Ok(ty);
        }
        if let Some(list) = descendant_form(self.tree, expression, &[SyntaxForm::ListExpression]) {
            let members = direct_expressions(self.tree, self.node(list)?);
            for member in &members {
                self.compile_expression(*member)?;
            }
            self.emit(
                ty.clone(),
                InstructionKind::Aggregate {
                    kind: AggregateKind::List,
                    operands: members.len(),
                },
            )?;
            return Ok(ty);
        }
        if descendant_form(self.tree, expression, &[SyntaxForm::TupleExpression]).is_some() {
            let members = direct_expressions(self.tree, &node);
            for member in &members {
                self.compile_expression(*member)?;
            }
            self.emit(
                ty.clone(),
                InstructionKind::Aggregate {
                    kind: AggregateKind::Tuple,
                    operands: members.len(),
                },
            )?;
            return Ok(ty);
        }
        if let Some(word) = direct_word(self.tree, &node, &["Some", "Ok", "Err", "None"]) {
            let expressions = direct_expressions(self.tree, &node);
            for member in &expressions {
                self.compile_expression(*member)?;
            }
            let kind = match word.as_ref() {
                "Some" => AggregateKind::Some,
                "Ok" => AggregateKind::Ok,
                "Err" => AggregateKind::Err,
                "None" => AggregateKind::None,
                _ => return Err(AnalysisError::Invariant),
            };
            self.emit(
                ty.clone(),
                InstructionKind::Aggregate {
                    kind,
                    operands: expressions.len(),
                },
            )?;
            return Ok(ty);
        }
        if let Some(value) = literal_value(self.tree, &node)? {
            self.emit(ty.clone(), InstructionKind::Push(value))?;
            return Ok(ty);
        }
        if node_has_word(self.tree, &node, "self") {
            self.emit(ty.clone(), InstructionKind::Load(Arc::from("self")))?;
            return Ok(ty);
        }
        if let Some(path) = direct_child_form(self.tree, &node, SyntaxForm::Path) {
            let name = direct_identifier(self.tree, path).ok_or(AnalysisError::Invariant)?;
            self.emit(ty.clone(), InstructionKind::Load(name))?;
            return Ok(ty);
        }
        let semantic = semantic_children(self.tree, expression)?;
        if semantic.len() == 1 {
            return self.compile_expression(semantic[0]);
        }
        Err(AnalysisError::Invariant)
    }

    fn compile_struct(
        &mut self,
        expression: NodeId,
        struct_expression: NodeId,
        ty: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let type_name = ty.canonical_string();
        let constructor = self.node(struct_expression)?.clone();
        let mut fields = Vec::new();
        for initializer in semantic_children(self.tree, struct_expression)? {
            let initializer_node = self.node(initializer)?.clone();
            if !matches!(initializer_node.form(), SyntaxForm::FieldInitializer) {
                continue;
            }
            let name = direct_identifier(self.tree, initializer).ok_or(AnalysisError::Invariant)?;
            if let Some(value) =
                direct_child_form(self.tree, &initializer_node, SyntaxForm::Expression)
            {
                self.compile_expression(value)?;
            } else {
                self.emit(
                    TypeDescriptor::UNIT,
                    InstructionKind::Load(Arc::clone(&name)),
                )?;
            }
            fields.push(name);
        }
        if fields.is_empty() && !constructor.children().is_empty() {
            return Err(AnalysisError::Invariant);
        }
        self.emit(
            ty.clone(),
            InstructionKind::Aggregate {
                kind: AggregateKind::Struct {
                    type_name: Arc::from(type_name),
                    fields,
                },
                operands: semantic_children(self.tree, struct_expression)?
                    .into_iter()
                    .filter(|child| {
                        self.tree
                            .node(*child)
                            .is_some_and(|node| matches!(node.form(), SyntaxForm::FieldInitializer))
                    })
                    .count(),
            },
        )?;
        let _ = expression;
        Ok(ty)
    }

    fn compile_static_projection(
        &mut self,
        expression: NodeId,
        node: &gantry_frontend::SyntaxNode,
        ty: &TypeDescriptor,
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let Some(postfix) =
            descendant_form(self.tree, expression, &[SyntaxForm::PostfixExpression])
        else {
            return Ok(None);
        };
        let postfix_node = self.node(postfix)?;
        if !node_contains_punctuation(self.tree, postfix_node, Punctuation::LeftBracket) {
            return Ok(None);
        }
        let path =
            direct_child_form(self.tree, node, SyntaxForm::Path).ok_or(AnalysisError::Invariant)?;
        let name = direct_identifier(self.tree, path).ok_or(AnalysisError::Invariant)?;
        let index = direct_expressions(self.tree, node)
            .into_iter()
            .find_map(|index| integer_literal(self.tree, index))
            .ok_or(AnalysisError::Invariant)?;
        self.emit(ty.clone(), InstructionKind::Load(name))?;
        self.emit(
            ty.clone(),
            InstructionKind::Project(Projection::Member(index)),
        )?;
        Ok(Some(ty.clone()))
    }

    fn compile_match(
        &mut self,
        match_expression: NodeId,
        ty: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let node = self.node(match_expression)?.clone();
        let scrutinee = direct_child_form(self.tree, &node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        let scrutinee_type = self.compile_expression(scrutinee)?;
        if self.closed_enums.contains_key(&scrutinee_type) {
            return self.compile_enum_match(match_expression, scrutinee_type, ty);
        }
        let member_type = scrutinee_type
            .immediate_members()
            .into_iter()
            .next()
            .ok_or(AnalysisError::Invariant)?;
        let branch = self.emit(
            scrutinee_type,
            InstructionKind::BranchOption {
                when_some: 0,
                when_none: 0,
            },
        )?;
        let arms = semantic_children(self.tree, match_expression)?
            .into_iter()
            .filter(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
            })
            .collect::<Vec<_>>();
        let some = arms
            .iter()
            .copied()
            .find(|arm| pattern_word(self.tree, *arm, "Some"))
            .ok_or(AnalysisError::Invariant)?;
        let none = arms
            .iter()
            .copied()
            .find(|arm| pattern_word(self.tree, *arm, "None"))
            .ok_or(AnalysisError::Invariant)?;

        let when_some = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        let binding = pattern_binding(self.tree, some).ok_or(AnalysisError::Invariant)?;
        self.emit(
            member_type.clone(),
            InstructionKind::Bind {
                name: binding,
                ty: member_type,
                mutable: false,
            },
        )?;
        self.compile_match_arm(some)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;

        let when_none = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.compile_match_arm(none)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let end = self.instructions.len();
        self.instructions[branch].kind = InstructionKind::BranchOption {
            when_some,
            when_none,
        };
        self.instructions[jump].kind = InstructionKind::Jump(end);
        Ok(ty)
    }

    fn compile_enum_match(
        &mut self,
        match_expression: NodeId,
        scrutinee_type: TypeDescriptor,
        ty: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let variants = self
            .closed_enums
            .get(&scrutinee_type)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        let source_arms = semantic_children(self.tree, match_expression)?
            .into_iter()
            .filter(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::MatchArm))
            })
            .collect::<Vec<_>>();
        let branch = self.emit(
            scrutinee_type,
            InstructionKind::BranchEnum { arms: Vec::new() },
        )?;
        let mut lowered_arms = Vec::with_capacity(source_arms.len());
        let mut jumps = Vec::with_capacity(source_arms.len());
        for arm in source_arms {
            let variant =
                enum_pattern_variant(self.tree, arm, &variants).ok_or(AnalysisError::Invariant)?;
            let payload = variants.get(&variant).ok_or(AnalysisError::Invariant)?;
            let target = self.instructions.len();
            lowered_arms.push((variant, target));
            self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
            if let Some(payload) = payload {
                if let Some(binding) = enum_pattern_binding(self.tree, arm) {
                    self.emit(
                        payload.clone(),
                        InstructionKind::Bind {
                            name: binding,
                            ty: payload.clone(),
                            mutable: false,
                        },
                    )?;
                } else {
                    self.emit(payload.clone(), InstructionKind::Pop)?;
                }
            }
            self.compile_match_arm(arm)?;
            self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
            self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
            jumps.push(self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?);
        }
        let end = self.instructions.len();
        for jump in jumps {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        self.instructions[branch].kind = InstructionKind::BranchEnum { arms: lowered_arms };
        Ok(ty)
    }

    fn compile_match_arm(&mut self, arm: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(arm)?.clone();
        if let Some(expression) = direct_child_form(self.tree, &node, SyntaxForm::Expression) {
            self.compile_expression(expression)?;
            return Ok(());
        }
        let block = direct_child_form(self.tree, &node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        self.compile_block(block, BlockMode::Value)
    }

    fn compile_operation(
        &mut self,
        operation: NodeId,
        ty: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let operation_node = self.node(operation)?;
        let attempted = matches!(operation_node.form(), SyntaxForm::AttemptExpression);
        let actual = if attempted {
            descendant_form(
                self.tree,
                operation,
                &[
                    SyntaxForm::PromptExpression,
                    SyntaxForm::DecideExpression,
                    SyntaxForm::ActionExpression,
                ],
            )
            .ok_or(AnalysisError::Invariant)?
        } else {
            operation
        };
        let actual_node = self.node(actual)?.clone();
        let operation_source = actual_node.span().clone();
        let mut interpolation_types = Vec::new();
        let mut named_input_types = Vec::new();
        let operands = if matches!(
            actual_node.form(),
            SyntaxForm::PromptExpression | SyntaxForm::DecideExpression
        ) {
            let mut count = 0_usize;
            for interpolation in actual_node.children().iter().copied().filter(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::InterpolationExpression))
            }) {
                interpolation_types.push(self.compile_expression(interpolation)?);
                count = count.saturating_add(1);
            }
            if let Some(using_clause) =
                direct_child_form(self.tree, &actual_node, SyntaxForm::UsingClause)
            {
                for input in semantic_children(self.tree, using_clause)? {
                    let input_node = self.node(input)?.clone();
                    if !matches!(input_node.form(), SyntaxForm::NamedInput) {
                        continue;
                    }
                    let ty = if let Some(expression) =
                        direct_child_form(self.tree, &input_node, SyntaxForm::Expression)
                    {
                        self.compile_expression(expression)?
                    } else {
                        let name =
                            direct_identifier(self.tree, input).ok_or(AnalysisError::Invariant)?;
                        let ty = self
                            .body_types
                            .get(&input)
                            .cloned()
                            .ok_or(AnalysisError::Invariant)?;
                        self.emit(ty.clone(), InstructionKind::Load(name))?;
                        ty
                    };
                    named_input_types.push(ty);
                    count = count.saturating_add(1);
                }
            }
            count
        } else {
            let operands = direct_expressions(self.tree, &actual_node);
            for operand in &operands {
                self.compile_expression(*operand)?;
            }
            operands.len()
        };
        let site = self
            .facts
            .operations
            .iter()
            .find(|site| site.source == operation_source)
            .ok_or(AnalysisError::Invariant)?;
        let result_type = self
            .operation_results
            .and_then(|results| results.get(&operation_source))
            .cloned()
            .unwrap_or_else(|| site.result.clone());
        let action = site
            .action
            .as_ref()
            .map(|path| {
                self.actions
                    .iter()
                    .find(|action| &action.path == path)
                    .map(|action| ExecutableAction {
                        path: action.path.clone(),
                        signature: action.signature.clone(),
                        recovery: action.recovery,
                        parameters: action.parameters.clone(),
                    })
                    .ok_or(AnalysisError::Invariant)
            })
            .transpose()?;
        let metadata = ExecutableOperation {
            kind: site.kind,
            result_type,
            action,
            template_segments: operation_template_segments(self.tree, &actual_node),
            interpolation_types,
            named_input_names: operation_named_input_names(self.tree, &actual_node),
            named_input_types,
            retry_limit: operation_retry_limit(self.tree, &actual_node),
            session_mode: operation_session_mode(self.tree, &actual_node),
            attempted,
        };
        self.emit(
            ty.clone(),
            InstructionKind::OperationCall {
                operation: metadata,
                operands,
            },
        )?;
        Ok(ty)
    }

    fn compile_sequence(&mut self, children: &[NodeId]) -> Result<(), AnalysisError> {
        for child in children {
            let node = self.node(*child)?;
            if matches!(node.form(), SyntaxForm::Token(_)) {
                continue;
            }
            self.compile_expression(*child)?;
        }
        Ok(())
    }

    fn emit(&mut self, ty: TypeDescriptor, kind: InstructionKind) -> Result<usize, AnalysisError> {
        let index = self.instructions.len();
        let component = u64::try_from(index).map_err(|_| AnalysisError::Invariant)?;
        let site =
            StructuralPosition::new(vec![component]).map_err(|_| AnalysisError::Invariant)?;
        self.instructions.push(Instruction { site, ty, kind });
        Ok(index)
    }

    fn node(&self, id: NodeId) -> Result<&gantry_frontend::SyntaxNode, AnalysisError> {
        self.tree.node(id).ok_or(AnalysisError::Invariant)
    }

    fn direct_target(
        &self,
        expression: &gantry_frontend::SyntaxNode,
    ) -> Option<CanonicalCallableIdentity> {
        let arguments = direct_expressions(self.tree, expression)
            .into_iter()
            .filter_map(|argument| self.tree.node(argument).map(|node| node.span()))
            .collect::<Vec<_>>();
        self.direct_targets
            .iter()
            .find(|(source, _)| {
                source_span_contains(expression.span(), source)
                    && !arguments
                        .iter()
                        .any(|argument| source_span_contains(argument, source))
            })
            .map(|(_, target)| target.clone())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BlockMode {
    Callable,
    Statement,
    Value,
}

fn semantic_children(tree: &SyntaxTree, id: NodeId) -> Result<Vec<NodeId>, AnalysisError> {
    Ok(tree
        .node(id)
        .ok_or(AnalysisError::Invariant)?
        .children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| !matches!(node.form(), SyntaxForm::Token(_)))
        })
        .collect())
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

fn descendant_form(tree: &SyntaxTree, root: NodeId, forms: &[SyntaxForm]) -> Option<NodeId> {
    let mut work = vec![root];
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        if id != root
            && forms
                .iter()
                .any(|form| std::mem::discriminant(node.form()) == std::mem::discriminant(form))
        {
            return Some(id);
        }
        work.extend(node.children().iter().rev().copied());
    }
    None
}

fn direct_identifier(tree: &SyntaxTree, id: NodeId) -> Option<Arc<str>> {
    tree.node(id)?
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })
}

fn direct_identifiers(tree: &SyntaxTree, id: NodeId) -> Vec<Arc<str>> {
    tree.node(id)
        .into_iter()
        .flat_map(gantry_frontend::SyntaxNode::children)
        .filter_map(|child| tree.node(*child))
        .filter_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn direct_expressions(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Vec<NodeId> {
    node.children()
        .iter()
        .copied()
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        })
        .collect()
}

fn source_span_contains(
    outer: &gantry_core::source::SourceSpan,
    inner: &gantry_core::source::SourceSpan,
) -> bool {
    outer.source() == inner.source()
        && outer.bytes().start() <= inner.bytes().start()
        && outer.bytes().end() >= inner.bytes().end()
}

fn postfix_method_receiver(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
) -> Option<Arc<str>> {
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
    tokens
        .get(..dot)?
        .iter()
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
                Some(Arc::from("self"))
            }
            _ => None,
        })
}

fn postfix_field_projection(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
) -> Option<(Arc<str>, Arc<str>)> {
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
    if tokens.iter().any(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(
                Punctuation::LeftParenthesis | Punctuation::LeftBracket
            ))
        )
    }) {
        return None;
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
    let field = tokens
        .get(dot.saturating_add(1)..)?
        .iter()
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
            _ => None,
        })?;
    Some((root, field))
}

fn method_receiver_type(path: &CanonicalPath) -> Result<TypeDescriptor, AnalysisError> {
    let receiver = path
        .as_str()
        .strip_prefix('<')
        .and_then(|value| value.split_once(">::"))
        .map(|(receiver, _)| receiver)
        .ok_or(AnalysisError::Invariant)?;
    TypeDescriptor::from_canonical_string(receiver).map_err(|_| AnalysisError::Invariant)
}

fn operation_template_segments(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Vec<Arc<str>> {
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
) -> Vec<Arc<str>> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter(|child| matches!(child.form(), SyntaxForm::UsingClause))
        .flat_map(gantry_frontend::SyntaxNode::children)
        .filter_map(|child| tree.node(*child))
        .filter(|child| matches!(child.form(), SyntaxForm::NamedInput))
        .filter_map(|input| direct_identifier(tree, node_id(tree, input)?))
        .collect()
}

fn operation_retry_limit(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<u64> {
    descendant_token(tree, node, |token| match token {
        TokenKind::DirectiveInteger(value) => value.parse().ok(),
        _ => None,
    })
}

fn operation_session_mode(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<Arc<str>> {
    descendant_token(tree, node, |token| match token {
        TokenKind::ReservedWord(word) if matches!(word.spelling(), "fork" | "new") => {
            Some(Arc::from(word.spelling()))
        }
        _ => None,
    })
}

fn descendant_token<T>(
    tree: &SyntaxTree,
    root: &gantry_frontend::SyntaxNode,
    mut select: impl FnMut(&TokenKind) -> Option<T>,
) -> Option<T> {
    let mut work = root.children().to_vec();
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        if let SyntaxForm::Token(token) = node.form()
            && let Some(value) = select(token)
        {
            return Some(value);
        }
        work.extend(node.children().iter().rev().copied());
    }
    None
}

fn node_id(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<NodeId> {
    tree.nodes()
        .iter()
        .position(|candidate| std::ptr::eq(candidate, node))
        .map(NodeId::from_index)
}

fn node_has_word(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode, expected: &str) -> bool {
    direct_word(tree, node, &[expected]).is_some()
}

fn direct_word(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    expected: &[&str],
) -> Option<Arc<str>> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::ReservedWord(word))
                if expected.contains(&word.spelling()) =>
            {
                Some(Arc::from(word.spelling()))
            }
            _ => None,
        })
}

fn direct_punctuation(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<Punctuation> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Punctuation(value)) => Some(*value),
            _ => None,
        })
}

fn assignment_operator(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<Punctuation> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
            SyntaxForm::Token(TokenKind::Punctuation(
                value @ (Punctuation::Equal
                | Punctuation::PlusEqual
                | Punctuation::MinusEqual
                | Punctuation::StarEqual
                | Punctuation::SlashEqual),
            )) => Some(*value),
            _ => None,
        })
}

fn binary_operator(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<(Punctuation, usize)> {
    node.children()
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, child)| match tree.node(*child)?.form() {
            SyntaxForm::Token(TokenKind::Punctuation(value))
                if primitive_for_binary(*value).is_some() =>
            {
                Some((*value, index))
            }
            _ => None,
        })
}

fn primitive_for_binary(value: Punctuation) -> Option<Primitive> {
    Some(match value {
        Punctuation::Plus => Primitive::Add,
        Punctuation::Minus => Primitive::Subtract,
        Punctuation::Star => Primitive::Multiply,
        Punctuation::Slash => Primitive::Divide,
        Punctuation::Percent => Primitive::Remainder,
        Punctuation::EqualEqual => Primitive::Equal,
        Punctuation::NotEqual => Primitive::NotEqual,
        Punctuation::Less => Primitive::Compare(Comparison::Less),
        Punctuation::LessEqual => Primitive::Compare(Comparison::LessOrEqual),
        Punctuation::Greater => Primitive::Compare(Comparison::Greater),
        Punctuation::GreaterEqual => Primitive::Compare(Comparison::GreaterOrEqual),
        _ => return None,
    })
}

fn primitive_for_assignment(value: Punctuation) -> Option<Primitive> {
    primitive_for_binary(match value {
        Punctuation::PlusEqual => Punctuation::Plus,
        Punctuation::MinusEqual => Punctuation::Minus,
        Punctuation::StarEqual => Punctuation::Star,
        Punctuation::SlashEqual => Punctuation::Slash,
        Punctuation::PercentEqual => Punctuation::Percent,
        _ => return None,
    })
}

fn literal_type(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<TypeDescriptor> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find_map(|node| match node.form() {
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

fn literal_value(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Result<Option<LogicalValue>, AnalysisError> {
    for token in node.children().iter().filter_map(|child| tree.node(*child)) {
        let value = match token.form() {
            SyntaxForm::Token(TokenKind::IntegerLiteral(value)) => value
                .parse::<i64>()
                .ok()
                .and_then(GantryInt::new)
                .map(LogicalValue::integer),
            SyntaxForm::Token(TokenKind::FloatLiteral(value)) => value
                .parse::<f64>()
                .ok()
                .and_then(GantryFloat::new)
                .map(LogicalValue::float),
            SyntaxForm::Token(
                TokenKind::StringLiteral(value) | TokenKind::RawStringLiteral(value),
            ) => Some(
                LogicalValue::string(value.to_string(), DEFAULT_VALUE_LIMITS)
                    .map_err(|_| AnalysisError::Invariant)?,
            ),
            SyntaxForm::Token(TokenKind::ReservedWord(word)) => match word.spelling() {
                "true" => Some(LogicalValue::boolean(true)),
                "false" => Some(LogicalValue::boolean(false)),
                "null" => Some(LogicalValue::unit()),
                _ => None,
            },
            _ => None,
        };
        if value.is_some() {
            return Ok(value);
        }
    }
    if node
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .all(|child| {
            matches!(
                child.form(),
                SyntaxForm::Token(TokenKind::Punctuation(
                    Punctuation::LeftParenthesis | Punctuation::RightParenthesis
                ))
            )
        })
    {
        return Ok(Some(LogicalValue::unit()));
    }
    Ok(None)
}

fn node_contains_punctuation(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    expected: Punctuation,
) -> bool {
    node.children().iter().copied().any(|child| {
        tree.node(child).is_some_and(|child| {
            matches!(child.form(), SyntaxForm::Token(TokenKind::Punctuation(value)) if *value == expected)
        })
    })
}

fn integer_literal(tree: &SyntaxTree, root: NodeId) -> Option<usize> {
    let mut work = vec![root];
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        if let SyntaxForm::Token(TokenKind::IntegerLiteral(value)) = node.form() {
            return value.parse().ok();
        }
        work.extend(node.children().iter().rev().copied());
    }
    None
}

fn enum_constructor_variant(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
    variants: Option<&BTreeMap<Arc<str>, Option<TypeDescriptor>>>,
) -> Option<Arc<str>> {
    let variants = variants?;
    let mut selected = None;
    let mut work = expression
        .children()
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    while let Some(id) = work.pop() {
        let node = tree.node(id)?;
        match node.form() {
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis)) => break,
            SyntaxForm::Token(TokenKind::Identifier(candidate))
                if variants.contains_key(candidate) =>
            {
                selected = Some(candidate.clone());
            }
            SyntaxForm::Token(_) => {}
            _ => work.extend(node.children().iter().rev().copied()),
        }
    }
    selected
}

fn enum_pattern_variant(
    tree: &SyntaxTree,
    arm: NodeId,
    variants: &BTreeMap<Arc<str>, Option<TypeDescriptor>>,
) -> Option<Arc<str>> {
    let pattern = tree.node(arm)?.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
    })?;
    direct_identifiers(tree, pattern)
        .into_iter()
        .rev()
        .find(|candidate| variants.contains_key(candidate))
}

fn enum_pattern_binding(tree: &SyntaxTree, arm: NodeId) -> Option<Arc<str>> {
    let pattern = tree.node(arm)?.children().iter().copied().find(|child| {
        tree.node(*child)
            .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
    })?;
    let nested = direct_child_form(tree, tree.node(pattern)?, SyntaxForm::Pattern)?;
    direct_identifier(tree, nested)
}

fn pattern_word(tree: &SyntaxTree, arm: NodeId, expected: &str) -> bool {
    descendant_pattern_tokens(tree, arm).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == expected)
    })
}

fn pattern_binding(tree: &SyntaxTree, arm: NodeId) -> Option<Arc<str>> {
    descendant_pattern_tokens(tree, arm).find_map(|node| match node.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.clone()),
        _ => None,
    })
}

fn descendant_pattern_tokens(
    tree: &SyntaxTree,
    root: NodeId,
) -> impl Iterator<Item = &gantry_frontend::SyntaxNode> {
    let pattern = tree.node(root).and_then(|arm| {
        arm.children().iter().copied().find(|child| {
            tree.node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Pattern))
        })
    });
    let mut work = pattern.into_iter().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    while let Some(id) = work.pop() {
        if let Some(node) = tree.node(id) {
            if matches!(node.form(), SyntaxForm::Token(_)) {
                tokens.push(node);
            } else {
                work.extend(node.children().iter().rev().copied());
            }
        }
    }
    tokens.into_iter()
}

fn loop_limit(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<u64> {
    node.children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .filter(|child| matches!(child.form(), SyntaxForm::ModifierList))
        .flat_map(gantry_frontend::SyntaxNode::children)
        .filter_map(|child| tree.node(*child))
        .flat_map(gantry_frontend::SyntaxNode::children)
        .filter_map(|child| tree.node(*child))
        .find_map(|child| match child.form() {
            SyntaxForm::Token(TokenKind::DirectiveInteger(value)) => value.parse().ok(),
            _ => None,
        })
}

fn _program_error_is_typed(_: ProgramError, _: EffectSet, _: Projection) {}
