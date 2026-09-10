//! Analyzer-owned lowering from typed surface syntax to executable machine IR.
//!
//! This private pass resolves syntax while the analyzer still owns source trees,
//! then emits only typed, name-resolved contracts from `gantry-ir`. The runtime
//! consumes that contract without parsing source or repeating static analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::source::SourceSpan;
use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValuePathSegment};
use gantry_frontend::{NodeId, ParsedSource, Punctuation, SyntaxForm, SyntaxTree, TokenKind};
use gantry_ir::generated::TypeKind;
use gantry_ir::{
    ActionInventory, AggregateKind, CanonicalCallableIdentity, CanonicalPath, Comparison,
    EffectSet, EntryInventory, ExecutableAction, ExecutableOperation, ExecutableTaskBody,
    ExecutableTaskCapture, ExecutableTaskContext, ExecutableTaskHandle, Instruction,
    InstructionKind, LoopPhase, MachineProgram, OwnershipClass, Parameter, Primitive, ProgramError,
    Projection, StructuralPosition, TaskBodyIdentity, TypeDescriptor, Workflow, WorkflowFacts,
};

use crate::bodies::{BodyAnalysis, EffectNode, SpawnCaptureMetadata};
use crate::generics::{GenericDeclarationShape, prove_ownership_class};
use crate::{AnalysisError, TypeFact};

#[allow(clippy::too_many_arguments)]
pub(crate) fn lower_executable_program(
    sources: &[ParsedSource],
    type_facts: &[BTreeMap<NodeId, TypeFact>],
    body_types: &[BTreeMap<NodeId, TypeDescriptor>],
    entry: &EntryInventory,
    workflows: &[WorkflowFacts],
    actions: &[ActionInventory],
    body: &BodyAnalysis,
    capability_declarations: &BTreeMap<String, GenericDeclarationShape>,
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
    let mut callable_results = body
        .source_callables
        .iter()
        .map(|callable| (callable.identity.clone(), callable.result.clone()))
        .collect::<BTreeMap<_, _>>();
    for callable in &body.concrete_callables {
        let identity = concrete_identities
            .get(&callable.key)
            .cloned()
            .ok_or(AnalysisError::Invariant)?;
        callable_results.insert(identity, callable.result.clone());
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
    let shared_receivers = body
        .source_callables
        .iter()
        .filter(|callable| {
            callable
                .receiver_mode
                .is_some_and(gantry_ir::ReceiverMode::requires_caller_place)
        })
        .map(|callable| callable.identity.clone())
        .collect::<BTreeSet<_>>();
    let owned_move_receivers = body
        .source_callables
        .iter()
        .filter(|callable| {
            callable.receiver_mode == Some(gantry_ir::ReceiverMode::Owned)
                && callable.receiver.as_ref().is_some_and(|ty| {
                    prove_ownership_class(ty, capability_declarations)
                        .is_ok_and(|class| class == OwnershipClass::AffineDroppable)
                })
        })
        .map(|callable| callable.identity.clone())
        .collect::<BTreeSet<_>>();
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
            struct_fields: &body.struct_fields,
            facts,
            receiver_type: metadata.receiver.as_ref(),
            result: &metadata.result,
            effects: metadata.effects,
            direct_targets: direct_targets
                .get(&metadata.identity)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            callable_results: &callable_results,
            shared_receivers: &shared_receivers,
            owned_move_receivers: &owned_move_receivers,
            operation_results: None,
            closed_enums: &body.closed_enums,
            actions,
            binding_types: BTreeMap::new(),
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
            struct_fields: &body.struct_fields,
            facts,
            receiver_type: metadata.receiver.as_ref(),
            result: &metadata.result,
            effects,
            direct_targets: direct_targets
                .get(&identity)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            callable_results: &callable_results,
            shared_receivers: &shared_receivers,
            owned_move_receivers: &owned_move_receivers,
            operation_results: Some(&metadata.operation_results),
            closed_enums: &body.closed_enums,
            actions,
            binding_types: BTreeMap::new(),
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
    struct_fields: &'a BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, TypeDescriptor>>,
    facts: &'a WorkflowFacts,
    receiver_type: Option<&'a TypeDescriptor>,
    result: &'a TypeDescriptor,
    effects: EffectSet,
    direct_targets: &'a [(gantry_core::source::SourceSpan, CanonicalCallableIdentity)],
    callable_results: &'a BTreeMap<CanonicalCallableIdentity, TypeDescriptor>,
    shared_receivers: &'a BTreeSet<CanonicalCallableIdentity>,
    owned_move_receivers: &'a BTreeSet<CanonicalCallableIdentity>,
    operation_results: Option<&'a BTreeMap<gantry_core::source::SourceSpan, TypeDescriptor>>,
    closed_enums: &'a BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, Option<TypeDescriptor>>>,
    actions: &'a [ActionInventory],
    binding_types: BTreeMap<Arc<str>, TypeDescriptor>,
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
        self.binding_types = parameters
            .iter()
            .map(|parameter| (parameter.name.clone(), parameter.ty.clone()))
            .collect();
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
            struct_fields: self.struct_fields,
            facts: self.facts,
            receiver_type: self.receiver_type,
            result: &result,
            effects: self.effects,
            direct_targets: self.direct_targets,
            callable_results: self.callable_results,
            shared_receivers: self.shared_receivers,
            owned_move_receivers: self.owned_move_receivers,
            operation_results: self.operation_results,
            closed_enums: self.closed_enums,
            actions: self.actions,
            binding_types: self.binding_types.clone(),
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
                InstructionKind::ReceiverCall {
                    source: gantry_ir::ReceiverSource::CallerPlace { root, .. },
                    ..
                } => vec![root.clone()],
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
            let receiver_mode = method_receiver_mode(self.tree, callable)?;
            let mutable = matches!(
                receiver_mode,
                gantry_ir::ReceiverMode::MutableLocalCopy
                    | gantry_ir::ReceiverMode::Owned
                    | gantry_ir::ReceiverMode::ExclusivePlace
            );
            parameters.push(Parameter {
                name: Arc::from("self"),
                ty: receiver,
                mutable,
                receiver_mode: Some(receiver_mode),
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
                receiver_mode: None,
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
        if let Some(pattern) = direct_child_form(self.tree, &node, SyntaxForm::Pattern) {
            let temporary = self.compiler_temporary("tuple");
            self.emit(
                ty.clone(),
                InstructionKind::Bind {
                    name: temporary.clone(),
                    ty: ty.clone(),
                    mutable: false,
                },
            )?;
            self.binding_types.insert(temporary.clone(), ty.clone());
            self.compile_pattern_bindings(pattern, ty, &temporary, mutable)?;
            return Ok(());
        }
        let name = direct_identifier(self.tree, statement).ok_or(AnalysisError::Invariant)?;
        self.binding_types.insert(name.clone(), ty.clone());
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
            for field in fields {
                self.emit(
                    TypeDescriptor::UNIT,
                    InstructionKind::Project(Projection::Field(field.clone())),
                )?;
            }
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
        let node = self.node(statement)?.clone();
        let condition = direct_child_form(self.tree, &node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        let condition_type = self.compile_expression(condition)?;
        if let Some(pattern) = direct_child_form(self.tree, &node, SyntaxForm::Pattern) {
            return self.compile_pattern_if(statement, pattern, condition_type);
        }
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
        let true_bindings = self.binding_types.clone();
        self.compile_block(
            *blocks.first().ok_or(AnalysisError::Invariant)?,
            BlockMode::Statement,
        )?;
        self.binding_types = true_bindings;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;
        let when_false = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        let false_bindings = self.binding_types.clone();
        if let Some(otherwise) = blocks.get(1) {
            self.compile_block(*otherwise, BlockMode::Statement)?;
        }
        self.binding_types = false_bindings;
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

    /// Lowers a refutable `if let` using the runtime's exact value discriminants.
    fn compile_pattern_if(
        &mut self,
        statement: NodeId,
        pattern: NodeId,
        scrutinee_type: TypeDescriptor,
    ) -> Result<(), AnalysisError> {
        let blocks = semantic_children(self.tree, statement)?
            .into_iter()
            .filter(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
            })
            .collect::<Vec<_>>();
        let branch = match scrutinee_type.kind() {
            TypeKind::Option => self.emit(
                scrutinee_type.clone(),
                InstructionKind::BranchOption {
                    when_some: 0,
                    when_none: 0,
                },
            )?,
            TypeKind::Result => self.emit(
                scrutinee_type.clone(),
                InstructionKind::BranchResult {
                    when_ok: 0,
                    when_err: 0,
                },
            )?,
            TypeKind::Declared => self.emit(
                scrutinee_type.clone(),
                InstructionKind::BranchEnum { arms: Vec::new() },
            )?,
            _ => return Err(AnalysisError::Invariant),
        };
        let when_true = self.instructions.len();
        let payload_type =
            pattern_payload_type(self.tree, pattern, &scrutinee_type, self.closed_enums)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        let true_bindings = self.binding_types.clone();
        if let Some(payload_type) = payload_type {
            let payload_root = self.compiler_temporary("payload");
            self.emit(
                payload_type.clone(),
                InstructionKind::Bind {
                    name: payload_root.clone(),
                    ty: payload_type.clone(),
                    mutable: false,
                },
            )?;
            self.binding_types
                .insert(payload_root.clone(), payload_type.clone());
            self.compile_pattern_bindings(
                pattern_payload_pattern(self.tree, pattern)?,
                payload_type,
                &payload_root,
                false,
            )?;
        }
        self.compile_block(
            *blocks.first().ok_or(AnalysisError::Invariant)?,
            BlockMode::Statement,
        )?;
        self.binding_types = true_bindings;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;
        let when_false = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        let false_bindings = self.binding_types.clone();
        if let Some(otherwise) = blocks.get(1) {
            self.compile_block(*otherwise, BlockMode::Statement)?;
        }
        self.binding_types = false_bindings;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let false_jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;
        let false_shims = match scrutinee_type.kind() {
            TypeKind::Option => {
                let mut shims = BTreeMap::new();
                if pattern_word_at(self.tree, pattern, "None") {
                    let shim = self.instructions.len();
                    self.emit(
                        scrutinee_type
                            .immediate_members()
                            .first()
                            .cloned()
                            .ok_or(AnalysisError::Invariant)?,
                        InstructionKind::Pop,
                    )?;
                    self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(when_false))?;
                    shims.insert(Arc::from("Some"), shim);
                }
                shims
            }
            TypeKind::Result => {
                let mut shims = BTreeMap::new();
                let members = scrutinee_type.immediate_members();
                for (variant, payload) in [("Ok", members.first()), ("Err", members.get(1))] {
                    if !pattern_word_at(self.tree, pattern, variant) {
                        let shim = self.instructions.len();
                        self.emit(
                            payload.cloned().ok_or(AnalysisError::Invariant)?,
                            InstructionKind::Pop,
                        )?;
                        self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(when_false))?;
                        shims.insert(Arc::from(variant), shim);
                    }
                }
                shims
            }
            TypeKind::Declared => {
                let mut shims = BTreeMap::new();
                let variants = self
                    .closed_enums
                    .get(&scrutinee_type)
                    .ok_or(AnalysisError::Invariant)?;
                let selected = pattern_variant(self.tree, pattern, variants)?;
                for (variant, payload) in variants {
                    if variant != &selected
                        && let Some(payload) = payload
                    {
                        let shim = self.instructions.len();
                        self.emit(payload.clone(), InstructionKind::Pop)?;
                        self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(when_false))?;
                        shims.insert(variant.clone(), shim);
                    }
                }
                shims
            }
            _ => return Err(AnalysisError::Invariant),
        };
        let end = self.instructions.len();
        self.instructions[jump].kind = InstructionKind::Jump(end);
        self.instructions[false_jump].kind = InstructionKind::Jump(end);
        self.instructions[branch].kind = match scrutinee_type.kind() {
            TypeKind::Option => InstructionKind::BranchOption {
                when_some: if pattern_word_at(self.tree, pattern, "Some") {
                    when_true
                } else {
                    false_shims.get("Some").copied().unwrap_or(when_false)
                },
                when_none: if pattern_word_at(self.tree, pattern, "None") {
                    when_true
                } else {
                    false_shims.get("None").copied().unwrap_or(when_false)
                },
            },
            TypeKind::Result => InstructionKind::BranchResult {
                when_ok: if pattern_word_at(self.tree, pattern, "Ok") {
                    when_true
                } else {
                    false_shims.get("Ok").copied().unwrap_or(when_false)
                },
                when_err: if pattern_word_at(self.tree, pattern, "Err") {
                    when_true
                } else {
                    false_shims.get("Err").copied().unwrap_or(when_false)
                },
            },
            TypeKind::Declared => InstructionKind::BranchEnum {
                arms: enum_if_arms(
                    self.tree,
                    pattern,
                    &scrutinee_type,
                    self.closed_enums,
                    when_true,
                    when_false,
                    &false_shims,
                )?,
            },
            _ => return Err(AnalysisError::Invariant),
        };
        Ok(())
    }

    /// Returns an internal binding identity that source text cannot spell.
    fn compiler_temporary(&self, purpose: &str) -> Arc<str> {
        Arc::from(format!("\0gantry_{purpose}_{}", self.instructions.len()))
    }

    /// Binds a pattern from an already-evaluated value, recursively projecting tuple members.
    fn compile_pattern_bindings(
        &mut self,
        pattern: NodeId,
        ty: TypeDescriptor,
        root: &Arc<str>,
        mutable: bool,
    ) -> Result<(), AnalysisError> {
        let bindings = pattern_binding_paths(self.tree, pattern, ty)?;
        for (name, binding_type, path) in bindings {
            let Some(name) = name else {
                continue;
            };
            let mut current = self
                .binding_types
                .get(root)
                .cloned()
                .ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Load(root.clone()))?;
            for index in path {
                let members = current.immediate_members();
                current = members
                    .get(index)
                    .cloned()
                    .ok_or(AnalysisError::Invariant)?;
                self.emit(
                    current.clone(),
                    InstructionKind::Project(Projection::Member(index)),
                )?;
            }
            self.binding_types
                .insert(name.clone(), binding_type.clone());
            self.emit(
                binding_type.clone(),
                InstructionKind::Bind {
                    name,
                    ty: binding_type,
                    mutable,
                },
            )?;
        }
        Ok(())
    }

    /// Names the payload already exposed by a branch, then recursively binds its pattern.
    fn bind_pattern_payload(
        &mut self,
        arm: NodeId,
        payload_type: TypeDescriptor,
    ) -> Result<(), AnalysisError> {
        let pattern = direct_child_form(self.tree, self.node(arm)?, SyntaxForm::Pattern)
            .ok_or(AnalysisError::Invariant)?;
        let payload_pattern = pattern_payload_pattern(self.tree, pattern)?;
        let root = self.compiler_temporary("payload");
        self.emit(
            payload_type.clone(),
            InstructionKind::Bind {
                name: root.clone(),
                ty: payload_type.clone(),
                mutable: false,
            },
        )?;
        self.binding_types
            .insert(root.clone(), payload_type.clone());
        self.compile_pattern_bindings(payload_pattern, payload_type, &root, false)
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
        let body_bindings = self.binding_types.clone();
        self.compile_block(body, BlockMode::Statement)?;
        self.binding_types = body_bindings;
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
        let body_bindings = self.binding_types.clone();
        self.compile_block(body, BlockMode::Statement)?;
        self.binding_types = body_bindings;
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
            let operator_index = unary_node
                .children()
                .iter()
                .position(|child| {
                    self.tree.node(*child).is_some_and(|node| {
                        matches!(
                            node.form(),
                            SyntaxForm::Token(TokenKind::Punctuation(
                                Punctuation::Bang | Punctuation::Minus
                            ))
                        )
                    })
                })
                .ok_or(AnalysisError::Invariant)?;
            let children = unary_node
                .children()
                .get(operator_index.saturating_add(1)..)
                .unwrap_or_default()
                .to_vec();
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
            let shared_receiver = self.shared_receivers.contains(&callee);
            let owned_move_receiver = self.owned_move_receivers.contains(&callee);
            let requires_place = shared_receiver || owned_move_receiver;
            let constructed_receiver = receiver_type.as_ref().and_then(|_| {
                descendant_form(self.tree, expression, &[SyntaxForm::StructExpression])
            });
            let receiver_place = receiver_type
                .as_ref()
                .and_then(|_| postfix_method_receiver_place(self.tree, &node));
            let has_implicit_receiver = constructed_receiver.is_some() || receiver_place.is_some();
            let caller_place = if requires_place {
                postfix_method_receiver_place(self.tree, &node)
            } else {
                None
            };
            if let (Some(struct_expression), Some(receiver_type)) =
                (constructed_receiver, receiver_type.as_ref())
            {
                if requires_place {
                    return Err(AnalysisError::Invariant);
                }
                self.compile_struct(expression, struct_expression, receiver_type.clone())?;
            } else if let (Some((root, path)), Some(_)) = (&receiver_place, receiver_type.as_ref())
                && !requires_place
            {
                let mut projection_types =
                    receiver_place_types(root, path, &self.binding_types, self.struct_fields)
                        .ok_or(AnalysisError::Invariant)?
                        .into_iter();
                self.emit(
                    projection_types.next().ok_or(AnalysisError::Invariant)?,
                    InstructionKind::Load(root.clone()),
                )?;
                for field in path {
                    let ValuePathSegment::StructField(field) = field else {
                        return Err(AnalysisError::Invariant);
                    };
                    self.emit(
                        projection_types.next().ok_or(AnalysisError::Invariant)?,
                        InstructionKind::Project(Projection::Field(Arc::from(field.as_str()))),
                    )?;
                }
                if projection_types.next().is_some() {
                    return Err(AnalysisError::Invariant);
                }
            }
            let arguments = direct_expressions(self.tree, &node);
            for argument in &arguments {
                self.compile_expression(*argument)?;
            }
            let arguments = arguments
                .len()
                .saturating_add(usize::from(has_implicit_receiver));
            self.emit(
                ty.clone(),
                if has_implicit_receiver {
                    InstructionKind::ReceiverCall {
                        callee,
                        arguments,
                        source: if requires_place {
                            let (root, path) = caller_place.ok_or(AnalysisError::Invariant)?;
                            gantry_ir::ReceiverSource::CallerPlace { root, path }
                        } else {
                            gantry_ir::ReceiverSource::CopiedValue
                        },
                    }
                } else {
                    InstructionKind::Call { callee, arguments }
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
            let callee = CanonicalCallableIdentity::free(&call.callee, &[]);
            let shared_receiver = self.shared_receivers.contains(&callee);
            let owned_move_receiver = self.owned_move_receivers.contains(&callee);
            let requires_place = shared_receiver || owned_move_receiver;
            if let Some(receiver) = &receiver
                && !requires_place
            {
                let receiver_type = method_receiver_type(&call.callee)?;
                self.emit(receiver_type, InstructionKind::Load(receiver.clone()))?;
            }
            let arguments = direct_expressions(self.tree, &node);
            for argument in &arguments {
                self.compile_expression(*argument)?;
            }
            let arguments = arguments
                .len()
                .saturating_add(usize::from(receiver.is_some()));
            self.emit(
                ty.clone(),
                if receiver.is_some() {
                    InstructionKind::ReceiverCall {
                        callee,
                        arguments,
                        source: if requires_place {
                            let (root, path) = postfix_method_receiver_place(self.tree, &node)
                                .ok_or(AnalysisError::Invariant)?;
                            gantry_ir::ReceiverSource::CallerPlace { root, path }
                        } else {
                            gantry_ir::ReceiverSource::CopiedValue
                        },
                    }
                } else {
                    InstructionKind::Call { callee, arguments }
                },
            )?;
            return Ok(ty);
        }
        if let Some(struct_expression) =
            descendant_form(self.tree, expression, &[SyntaxForm::StructExpression])
        {
            return self.compile_struct(expression, struct_expression, ty);
        }
        if let Some((root, fields)) = postfix_field_projection(self.tree, &node) {
            self.emit(ty.clone(), InstructionKind::Load(root))?;
            for field in fields {
                self.emit(
                    ty.clone(),
                    InstructionKind::Project(Projection::Field(field)),
                )?;
            }
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
        if matches!(node.form(), SyntaxForm::Path) {
            let name = direct_identifier(self.tree, expression).ok_or(AnalysisError::Invariant)?;
            self.emit(ty.clone(), InstructionKind::Load(name))?;
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
        let members = scrutinee_type.immediate_members();
        let is_result = scrutinee_type.kind() == TypeKind::Result;
        let branch = if is_result {
            self.emit(
                scrutinee_type,
                InstructionKind::BranchResult {
                    when_ok: 0,
                    when_err: 0,
                },
            )?
        } else {
            self.emit(
                scrutinee_type,
                InstructionKind::BranchOption {
                    when_some: 0,
                    when_none: 0,
                },
            )?
        };
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
            .find(|arm| pattern_word(self.tree, *arm, if is_result { "Ok" } else { "Some" }))
            .ok_or(AnalysisError::Invariant)?;
        let none = arms
            .iter()
            .copied()
            .find(|arm| pattern_word(self.tree, *arm, if is_result { "Err" } else { "None" }))
            .ok_or(AnalysisError::Invariant)?;

        let when_some = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        let some_bindings = self.binding_types.clone();
        self.bind_pattern_payload(
            some,
            members.first().cloned().ok_or(AnalysisError::Invariant)?,
        )?;
        self.compile_match_arm(some)?;
        self.binding_types = some_bindings;
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;

        let when_none = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        let none_bindings = self.binding_types.clone();
        if is_result {
            self.bind_pattern_payload(
                none,
                members.get(1).cloned().ok_or(AnalysisError::Invariant)?,
            )?;
        }
        self.compile_match_arm(none)?;
        self.binding_types = none_bindings;
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let end = self.instructions.len();
        self.instructions[branch].kind = if is_result {
            InstructionKind::BranchResult {
                when_ok: when_some,
                when_err: when_none,
            }
        } else {
            InstructionKind::BranchOption {
                when_some,
                when_none,
            }
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
            let arm_bindings = self.binding_types.clone();
            if let Some(payload) = payload {
                self.bind_pattern_payload(arm, payload.clone())?;
            }
            self.compile_match_arm(arm)?;
            self.binding_types = arm_bindings;
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
        if let Some((callee, result)) = self.direct_sequence_target(children) {
            let arguments = children
                .iter()
                .copied()
                .filter(|child| {
                    self.tree
                        .node(*child)
                        .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
                })
                .collect::<Vec<_>>();
            for argument in &arguments {
                self.compile_expression(*argument)?;
            }
            self.emit(
                result,
                InstructionKind::Call {
                    callee,
                    arguments: arguments.len(),
                },
            )?;
            return Ok(());
        }
        self.compile_operand_sequence(children)?;
        Ok(())
    }

    /// Compiles one operand sequence, mirroring the analyzer's operand walk.
    ///
    /// A slice carrying a split field-projection fragment also carries the inner operator
    /// tokens of a flattened same-precedence chain, so its enclosing operator is compiled
    /// as left and right operand sequences followed by one primitive. The returned type is
    /// the one that primitive publishes, which an enclosing operator reuses as its operand
    /// type. Slices without a split fragment keep the child walk, so unrelated operand
    /// chains lower exactly as before.
    fn compile_operand_sequence(
        &mut self,
        children: &[NodeId],
    ) -> Result<TypeDescriptor, AnalysisError> {
        if carries_split_projection(self.tree, children)
            && let Some((operator, index)) = children_binary_operator(self.tree, children)
        {
            let left = self.compile_operand_sequence(children.get(..index).unwrap_or_default())?;
            self.compile_operand_sequence(
                children.get(index.saturating_add(1)..).unwrap_or_default(),
            )?;
            let primitive = primitive_for_binary(operator).ok_or(AnalysisError::Invariant)?;
            let result = primitive_result_type(&primitive, &left);
            self.emit(result.clone(), InstructionKind::Primitive(primitive))?;
            return Ok(result);
        }
        if let Some(result) = self.compile_projected_operand_place(children)? {
            return Ok(result);
        }
        let mut result = TypeDescriptor::UNIT;
        for child in children {
            let node = self.node(*child)?;
            if matches!(node.form(), SyntaxForm::Token(_)) {
                continue;
            }
            result = self.compile_expression(*child)?;
        }
        Ok(result)
    }

    /// Lowers a split dotted operand as one root load plus one projection per member.
    ///
    /// The analyzer types such an operand as its projected member, so the sibling
    /// fragments are never compiled on their own; callers fall back to the child walk
    /// when this sequence is not a dotted place.
    fn compile_projected_operand_place(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        if children.len() < 2 {
            return Ok(None);
        }
        let Some((root, path)) = operand_field_place(self.tree, children) else {
            return Ok(None);
        };
        let Some(types) =
            receiver_place_types(&root, &path, &self.binding_types, self.struct_fields)
        else {
            return Ok(None);
        };
        let mut types = types.into_iter();
        let mut result = types.next().ok_or(AnalysisError::Invariant)?;
        self.emit(result.clone(), InstructionKind::Load(root))?;
        for segment in &path {
            let ValuePathSegment::StructField(field) = segment else {
                return Err(AnalysisError::Invariant);
            };
            result = types.next().ok_or(AnalysisError::Invariant)?;
            self.emit(
                result.clone(),
                InstructionKind::Project(Projection::Field(Arc::from(field.as_str()))),
            )?;
        }
        if types.next().is_some() {
            return Err(AnalysisError::Invariant);
        }
        Ok(Some(result))
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
            .filter(|(source, callee)| {
                if self.shared_receivers.contains(callee) {
                    source == expression.span()
                } else {
                    source_span_contains(expression.span(), source)
                        && !arguments
                            .iter()
                            .any(|argument| source_span_contains(argument, source))
                }
            })
            .min_by_key(|(source, _)| source.bytes().end().saturating_sub(source.bytes().start()))
            .map(|(_, target)| target.clone())
    }

    fn direct_sequence_target(
        &self,
        children: &[NodeId],
    ) -> Option<(CanonicalCallableIdentity, TypeDescriptor)> {
        let source = sequence_call_site_span(self.tree, children)?;
        self.direct_targets
            .iter()
            .find(|(candidate, callee)| candidate == &source && callee.receiver_type().is_none())
            .and_then(|(_, callee)| {
                self.callable_results
                    .get(callee)
                    .cloned()
                    .map(|result| (callee.clone(), result))
            })
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

fn pattern_payload_type(
    tree: &SyntaxTree,
    pattern: NodeId,
    scrutinee: &TypeDescriptor,
    closed_enums: &BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, Option<TypeDescriptor>>>,
) -> Result<Option<TypeDescriptor>, AnalysisError> {
    let members = scrutinee.immediate_members();
    match scrutinee.kind() {
        TypeKind::Option => Ok(pattern_word_at(tree, pattern, "Some").then(|| members[0].clone())),
        TypeKind::Result => Ok(if pattern_word_at(tree, pattern, "Ok") {
            Some(members[0].clone())
        } else {
            Some(members[1].clone())
        }),
        TypeKind::Declared => {
            let variants = closed_enums
                .get(scrutinee)
                .ok_or(AnalysisError::Invariant)?;
            let variant = pattern_variant(tree, pattern, variants)?;
            Ok(variants
                .get(&variant)
                .cloned()
                .ok_or(AnalysisError::Invariant)?)
        }
        _ => Err(AnalysisError::Invariant),
    }
}

fn pattern_payload_pattern(tree: &SyntaxTree, pattern: NodeId) -> Result<NodeId, AnalysisError> {
    direct_child_form(
        tree,
        tree.node(pattern).ok_or(AnalysisError::Invariant)?,
        SyntaxForm::Pattern,
    )
    .ok_or(AnalysisError::Invariant)
}

type PatternBindingPath = (Option<Arc<str>>, TypeDescriptor, Vec<usize>);

fn pattern_binding_paths(
    tree: &SyntaxTree,
    pattern: NodeId,
    ty: TypeDescriptor,
) -> Result<Vec<PatternBindingPath>, AnalysisError> {
    let mut bindings = Vec::new();
    let mut work = vec![(pattern, ty, Vec::new())];
    while let Some((pattern, ty, path)) = work.pop() {
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
        if nested.is_empty() {
            bindings.push((direct_identifier(tree, pattern), ty, path));
            continue;
        }
        let members = ty.immediate_members();
        if nested.len() != members.len() {
            return Err(AnalysisError::Invariant);
        }
        for (index, (nested, member)) in nested.into_iter().zip(members).enumerate().rev() {
            let mut nested_path = path.clone();
            nested_path.push(index);
            work.push((nested, member, nested_path));
        }
    }
    Ok(bindings)
}

fn enum_if_arms(
    tree: &SyntaxTree,
    pattern: NodeId,
    scrutinee: &TypeDescriptor,
    closed_enums: &BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, Option<TypeDescriptor>>>,
    when_true: usize,
    when_false: usize,
    false_shims: &BTreeMap<Arc<str>, usize>,
) -> Result<Vec<(Arc<str>, usize)>, AnalysisError> {
    let variants = closed_enums
        .get(scrutinee)
        .ok_or(AnalysisError::Invariant)?;
    let selected = pattern_variant(tree, pattern, variants)?;
    Ok(variants
        .keys()
        .map(|variant| {
            (
                variant.clone(),
                if variant == &selected {
                    when_true
                } else {
                    false_shims.get(variant).copied().unwrap_or(when_false)
                },
            )
        })
        .collect())
}

fn pattern_variant(
    tree: &SyntaxTree,
    pattern: NodeId,
    variants: &BTreeMap<Arc<str>, Option<TypeDescriptor>>,
) -> Result<Arc<str>, AnalysisError> {
    direct_identifiers(tree, pattern)
        .into_iter()
        .rev()
        .find(|name| variants.contains_key(name))
        .ok_or(AnalysisError::Invariant)
}

fn pattern_word_at(tree: &SyntaxTree, pattern: NodeId, expected: &str) -> bool {
    tree.node(pattern)
        .into_iter()
        .flat_map(gantry_frontend::SyntaxNode::children)
        .filter_map(|child| tree.node(*child))
        .any(|node| matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == expected))
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

fn sequence_call_site_span(tree: &SyntaxTree, children: &[NodeId]) -> Option<SourceSpan> {
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
    let callee = local_tokens.first()?;
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
        if matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
        ) {
            depth = depth.saturating_add(1);
        }
        if matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
        ) {
            depth = depth.saturating_sub(1);
        }
        depth == 0
    })?;
    SourceSpan::from_portable_parts(
        callee.span().source().package_path().as_str(),
        callee.span().bytes().start(),
        closing.span().bytes().end(),
    )
    .ok()
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

fn postfix_method_receiver_place(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
) -> Option<(Arc<str>, Vec<ValuePathSegment>)> {
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
    let method_dot = tokens.iter().rposition(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        )
    })?;
    let root = match tokens.first()?.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
            Arc::from("self")
        }
        _ => return None,
    };
    let mut path = Vec::new();
    let mut cursor = 1;
    while cursor < method_dot {
        if !matches!(
            tokens.get(cursor)?.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        ) {
            return None;
        }
        let SyntaxForm::Token(TokenKind::Identifier(field)) = tokens.get(cursor + 1)?.form() else {
            return None;
        };
        path.push(ValuePathSegment::StructField(field.to_string()));
        cursor += 2;
    }
    Some((root, path))
}

fn receiver_place_types(
    root: &Arc<str>,
    path: &[ValuePathSegment],
    binding_types: &BTreeMap<Arc<str>, TypeDescriptor>,
    struct_fields: &BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, TypeDescriptor>>,
) -> Option<Vec<TypeDescriptor>> {
    let mut current = binding_types.get(root)?.clone();
    let mut types = vec![current.clone()];
    for segment in path {
        let ValuePathSegment::StructField(field) = segment else {
            return None;
        };
        current = struct_fields.get(&current)?.get(field.as_str())?.clone();
        types.push(current.clone());
    }
    Some(types)
}

fn postfix_field_projection(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
) -> Option<(Arc<str>, Vec<Arc<str>>)> {
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
    let root = match tokens.first()?.form() {
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
            tokens.get(cursor)?.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        ) {
            return None;
        }
        let SyntaxForm::Token(TokenKind::Identifier(field)) = tokens.get(cursor + 1)?.form() else {
            return None;
        };
        fields.push(field.clone());
        cursor += 2;
    }
    (!fields.is_empty()).then_some((root, fields))
}

/// Returns the dotted place of a split operand whose member tokens are sibling nodes.
///
/// The analyzer merges the same sibling shape into one projected operand, so lowering
/// loads the root and projects each member instead of compiling the fragments.
fn operand_field_place(
    tree: &SyntaxTree,
    children: &[NodeId],
) -> Option<(Arc<str>, Vec<ValuePathSegment>)> {
    let mut tokens = Vec::new();
    let mut work = children.iter().rev().copied().collect::<Vec<_>>();
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
    let root = match tokens.first()?.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
            Arc::from("self")
        }
        _ => return None,
    };
    let mut path = Vec::new();
    let mut cursor = 1;
    while cursor < tokens.len() {
        if !matches!(
            tokens.get(cursor)?.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        ) {
            return None;
        }
        let SyntaxForm::Token(TokenKind::Identifier(field)) = tokens.get(cursor + 1)?.form() else {
            return None;
        };
        path.push(ValuePathSegment::StructField(field.to_string()));
        cursor += 2;
    }
    (!path.is_empty()).then_some((root, path))
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

fn method_receiver_mode(
    tree: &SyntaxTree,
    callable: NodeId,
) -> Result<gantry_ir::ReceiverMode, AnalysisError> {
    let callable = tree.node(callable).ok_or(AnalysisError::Invariant)?;
    let receiver = callable
        .children()
        .iter()
        .filter_map(|child| tree.node(*child))
        .find(|node| matches!(node.form(), SyntaxForm::Parameter))
        .ok_or(AnalysisError::Invariant)?;
    let shared = receiver.children().iter().filter_map(|child| tree.node(*child)).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::Identifier(value)) if value.as_ref() == "shared")
    });
    if shared {
        Ok(gantry_ir::ReceiverMode::SharedPlace)
    } else if receiver.children().iter().filter_map(|child| tree.node(*child)).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::Identifier(value)) if value.as_ref() == "exclusive")
    }) {
        Ok(gantry_ir::ReceiverMode::ExclusivePlace)
    } else if receiver.children().iter().filter_map(|child| tree.node(*child)).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::Identifier(value)) if value.as_ref() == "owned")
    }) {
        Ok(gantry_ir::ReceiverMode::Owned)
    } else {
        Ok(gantry_ir::ReceiverMode::from_v1_mutability(node_has_word(
            tree, receiver, "mut",
        )))
    }
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
    children_binary_operator(tree, node.children())
}

fn children_binary_operator(
    tree: &SyntaxTree,
    children: &[NodeId],
) -> Option<(Punctuation, usize)> {
    children
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

/// Reports whether one operand slice carries a split field-projection fragment.
///
/// The parser emits a sibling `PostfixExpression` holding the projection dot when it
/// splits a leading dotted operand. That fragment cannot be compiled on its own, so its
/// slice is compiled structurally instead of through the child walk.
fn carries_split_projection(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    children.iter().any(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(node.form(), SyntaxForm::PostfixExpression)
                && node_contains_punctuation(tree, node, Punctuation::Dot)
        })
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

/// Returns the type one binary primitive publishes for its operands.
///
/// Comparison primitives publish `Bool`; every arithmetic primitive publishes the left
/// operand type that the analyzer already proved equal to the right operand type.
fn primitive_result_type(primitive: &Primitive, left: &TypeDescriptor) -> TypeDescriptor {
    match primitive {
        Primitive::Compare(_) | Primitive::Equal | Primitive::NotEqual => TypeDescriptor::BOOL,
        _ => left.clone(),
    }
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

fn pattern_word(tree: &SyntaxTree, arm: NodeId, expected: &str) -> bool {
    descendant_pattern_tokens(tree, arm).any(|node| {
        matches!(node.form(), SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == expected)
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
