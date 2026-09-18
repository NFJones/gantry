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

use crate::bodies::{BodyAnalysis, BoolFact, EffectNode, SpawnCaptureMetadata, bool_fact};
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
    let mut builtin_targets = BTreeMap::<
        CanonicalCallableIdentity,
        Vec<(gantry_core::source::SourceSpan, Primitive, TypeDescriptor)>,
    >::new();
    for call in &body.builtin_calls {
        builtin_targets
            .entry(identity_for(&call.caller)?)
            .or_default()
            .push((call.source.clone(), call.primitive, call.result.clone()));
    }
    for targets in builtin_targets.values_mut() {
        targets.sort_by(|left, right| left.0.cmp(&right.0));
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
        .filter_map(|callable| {
            if callable.receiver_mode != Some(gantry_ir::ReceiverMode::Owned) {
                return None;
            }
            let class = callable
                .receiver
                .as_ref()
                .and_then(|ty| prove_ownership_class(ty, capability_declarations).ok())
                .filter(|class| class.requires_consumption())?;
            Some((callable.identity.clone(), class))
        })
        .collect::<BTreeMap<_, _>>();
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
            builtin_targets: builtin_targets
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
            infeasible: 0,
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
            builtin_targets: builtin_targets
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
            infeasible: 0,
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
    builtin_targets: &'a [(gantry_core::source::SourceSpan, Primitive, TypeDescriptor)],
    callable_results: &'a BTreeMap<CanonicalCallableIdentity, TypeDescriptor>,
    shared_receivers: &'a BTreeSet<CanonicalCallableIdentity>,
    owned_move_receivers: &'a BTreeMap<CanonicalCallableIdentity, OwnershipClass>,
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
    /// Nonzero while lowering a branch that a compile-time `Bool` fact excludes, so
    /// that unreachable loop transfers keep their shape without completing the loop
    /// (`GNT-3-T-BRANCH`).
    infeasible: usize,
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
            builtin_targets: self.builtin_targets,
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
            infeasible: self.infeasible,
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

    fn compile_block(&mut self, block: NodeId, mode: BlockMode) -> Result<bool, AnalysisError> {
        let children = semantic_children(self.tree, block)?;
        let mut cursor = 0_usize;
        let mut produced_value = false;
        let mut falls_through = true;
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
                    return Ok(false);
                }
                SyntaxForm::IfStatement => {
                    falls_through = self.compile_if(child)?;
                }
                SyntaxForm::WhileStatement | SyntaxForm::LoopStatement => {
                    falls_through = self.compile_while(child)?;
                }
                SyntaxForm::BreakStatement | SyntaxForm::ContinueStatement => {
                    self.compile_loop_transfer(matches!(node.form(), SyntaxForm::BreakStatement))?;
                    return Ok(false);
                }
                SyntaxForm::WithStatement | SyntaxForm::SessionStatement => {
                    falls_through = self.compile_context_statement(child)?;
                }
                SyntaxForm::MatchStatement => {
                    falls_through = self.compile_statement_match(child)?;
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
                                return Ok(false);
                            }
                            BlockMode::Value => return Ok(true),
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
            if self.result == &TypeDescriptor::UNIT {
                self.emit(
                    TypeDescriptor::UNIT,
                    InstructionKind::Push(LogicalValue::unit()),
                )?;
                self.emit(TypeDescriptor::UNIT, InstructionKind::Return)?;
            } else if falls_through {
                // A value-returning body must produce its result on every reachable normal
                // completion; an unreachable end needs no implicit return
                // (`GNT-3-T-COMPLETION`).
                return Err(AnalysisError::Invariant);
            }
        } else if mode == BlockMode::Value && !produced_value {
            self.emit(
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            )?;
        }
        Ok(falls_through)
    }

    fn compile_let(&mut self, statement: NodeId) -> Result<(), AnalysisError> {
        let node = self.node(statement)?.clone();
        let expression = direct_child_form(self.tree, &node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        // A binding whose annotation is a callable type holds a statically resolved alias
        // rather than a runtime value (`GNT-37.0`): every admitted use resolves to the
        // declared callable the binding names, so the binding emits no instruction and owns
        // no local slot.
        if let Some(type_node) = direct_child_form(self.tree, &node, SyntaxForm::ValueType)
            && self
                .declaration_types
                .get(&type_node)
                .is_some_and(|fact| fact.descriptor.callable_type().is_some())
        {
            return Ok(());
        }
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

    fn compile_if(&mut self, statement: NodeId) -> Result<bool, AnalysisError> {
        let node = self.node(statement)?.clone();
        if let Some(pattern) = direct_child_form(self.tree, &node, SyntaxForm::Pattern) {
            let condition = direct_child_form(self.tree, &node, SyntaxForm::Expression)
                .ok_or(AnalysisError::Invariant)?;
            let condition_type = self.compile_expression(condition)?;
            return self.compile_pattern_if(statement, pattern, condition_type);
        }
        let children = semantic_children(self.tree, statement)?;
        self.compile_if_chain(&children)
    }

    /// Lowers one condition of an `if`/`else if` chain from the flattened sibling children the
    /// parser produces, recursing into the remaining chain for the `else` position.
    ///
    /// Every condition of a chain must be folded, because the selected arm and the completion
    /// verdict both depend on all of them (`GNT-3-T-BRANCH`). A branch excluded by a compile-time
    /// fact is still lowered so the program keeps one shape, but it contributes neither a join
    /// transfer nor a completing loop transfer: a join label that no feasible path reaches may
    /// not exist, and `validate_workflow` rejects a target at or past the instruction length.
    fn compile_if_chain(&mut self, children: &[NodeId]) -> Result<bool, AnalysisError> {
        let condition = children
            .iter()
            .copied()
            .find(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
            })
            .ok_or(AnalysisError::Invariant)?;
        let block = children
            .iter()
            .copied()
            .find(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
            })
            .ok_or(AnalysisError::Invariant)?;
        let rest = children
            .iter()
            .position(|child| *child == block)
            .map(|index| &children[index + 1..])
            .unwrap_or_default();
        let condition_type = self.compile_expression(condition)?;
        let condition_fact = bool_fact(self.tree, condition)?;
        let branch = self.emit(
            condition_type,
            InstructionKind::Branch {
                when_true: 0,
                when_false: 0,
            },
        )?;
        let when_true = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        let true_bindings = self.binding_types.clone();
        let true_infeasible = condition_fact == BoolFact::False;
        self.infeasible += usize::from(true_infeasible);
        let true_falls_through = self.compile_block(block, BlockMode::Statement);
        self.infeasible -= usize::from(true_infeasible);
        let true_falls_through = true_falls_through?;
        self.binding_types = true_bindings;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        // A branch that cannot complete normally never reaches the join, so it needs no
        // transfer; an infeasible branch contributes no transfer either, because the join
        // label it would name may not exist yet (`validate_workflow` rejects a target at or
        // past the instruction length).
        let jump = if !true_infeasible && true_falls_through {
            Some(self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?)
        } else {
            None
        };
        let when_false = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        let false_bindings = self.binding_types.clone();
        let false_infeasible = condition_fact == BoolFact::True;
        self.infeasible += usize::from(false_infeasible);
        let has_further_condition = rest.iter().any(|child| {
            self.tree
                .node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
        });
        let false_falls_through = if has_further_condition {
            self.compile_if_chain(rest)
        } else if let Some(otherwise) = rest.iter().copied().find(|child| {
            self.tree
                .node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::Block))
        }) {
            self.compile_block(otherwise, BlockMode::Statement)
        } else {
            Ok(true)
        };
        self.infeasible -= usize::from(false_infeasible);
        let false_falls_through = false_falls_through?;
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
        if let Some(jump) = jump {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        Ok(match condition_fact {
            BoolFact::True => true_falls_through,
            BoolFact::False => false_falls_through,
            BoolFact::Unknown => true_falls_through || false_falls_through,
        })
    }

    /// Lowers a refutable `if let` using the runtime's exact value discriminants.
    fn compile_pattern_if(
        &mut self,
        statement: NodeId,
        pattern: NodeId,
        scrutinee_type: TypeDescriptor,
    ) -> Result<bool, AnalysisError> {
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
        let true_falls_through = self.compile_block(
            *blocks.first().ok_or(AnalysisError::Invariant)?,
            BlockMode::Statement,
        )?;
        self.binding_types = true_bindings;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = if true_falls_through {
            Some(self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?)
        } else {
            None
        };
        let when_false = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        self.cleanup.push(InstructionKind::LeaveOccurrence);
        self.cleanup.push(InstructionKind::ExitScope);
        let false_bindings = self.binding_types.clone();
        let false_falls_through = if let Some(otherwise) = blocks.get(1) {
            self.compile_block(*otherwise, BlockMode::Statement)?
        } else {
            true
        };
        self.binding_types = false_bindings;
        self.cleanup.pop();
        self.cleanup.pop();
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let false_jump = if false_falls_through {
            Some(self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?)
        } else {
            None
        };
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
        if let Some(jump) = jump {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        if let Some(false_jump) = false_jump {
            self.instructions[false_jump].kind = InstructionKind::Jump(end);
        }
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
        Ok(true_falls_through || false_falls_through)
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

    fn compile_while(&mut self, statement: NodeId) -> Result<bool, AnalysisError> {
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
        let body_infeasible = condition
            .map(|condition| bool_fact(self.tree, condition))
            .transpose()?
            .is_some_and(|fact| fact == BoolFact::False);
        self.infeasible += usize::from(body_infeasible);
        let body_result = self.compile_block(body, BlockMode::Statement);
        self.infeasible -= usize::from(body_infeasible);
        body_result?;
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
        let breaks = !target.breaks.is_empty();
        for jump in target.breaks {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        let condition_fact = condition
            .map(|condition| bool_fact(self.tree, condition))
            .transpose()?
            .unwrap_or(BoolFact::Unknown);
        Ok(match node.form() {
            SyntaxForm::LoopStatement => breaks,
            SyntaxForm::WhileStatement => breaks || condition_fact != BoolFact::True,
            _ => return Err(AnalysisError::Invariant),
        })
    }

    /// Leaves nested lexical scopes before transferring to the nearest loop.
    fn compile_loop_transfer(&mut self, is_break: bool) -> Result<(), AnalysisError> {
        let target = self.loops.last().ok_or(AnalysisError::Invariant)?;
        let start = target.start;
        let cleanup = self.cleanup[target.cleanup_depth..].to_vec();
        for kind in cleanup.into_iter().rev() {
            self.emit(TypeDescriptor::UNIT, kind)?;
        }
        // A transfer on a path that a compile-time fact excludes keeps its cleanup shape but
        // emits no jump: its target label may not exist, and an unreachable transfer must not
        // make the loop look like it can complete (`GNT-3-T-BRANCH`, `GNT-3-T-LOOP`).
        if self.infeasible > 0 {
            return Ok(());
        }
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(start))?;
        if is_break {
            let target = self.loops.last_mut().ok_or(AnalysisError::Invariant)?;
            target.breaks.push(jump);
        }
        Ok(())
    }

    fn compile_context_statement(&mut self, statement: NodeId) -> Result<bool, AnalysisError> {
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
        let body_falls_through = self.compile_block(body, BlockMode::Statement)?;
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
        Ok(body_falls_through)
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
            self.compile_match(match_expression)?;
            return Ok(ty);
        }
        // One node that carries its own operator tokens is an operator chain whose operands may
        // hold an operation, so the chain decides whether an operand is reached at all.
        if binary_operators(self.tree, node.children()).is_empty()
            && let Some(operation) = descendant_form(
                self.tree,
                expression,
                &[
                    SyntaxForm::PromptExpression,
                    SyntaxForm::DecideExpression,
                    SyntaxForm::ActionExpression,
                    SyntaxForm::AttemptExpression,
                ],
            )
        {
            return self.compile_operation(operation, ty);
        }
        let operators = binary_operators(self.tree, node.children());
        if !operators.is_empty() {
            if operators.len() > 1 {
                return self.compile_binary_chain(node.children(), ty);
            }
            let (operator, index) = operators[0];
            let left = node.children()[..index].to_vec();
            let right = node.children()[index.saturating_add(1)..].to_vec();
            if logical_constant(operator).is_some() {
                self.compile_sequence(&left)?;
                self.emit_logical_step(operator, |compiler| compiler.compile_sequence(&right))?;
                return Ok(ty);
            }
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
        // The type phase reads a node with a top-level index postfix and no operator as one
        // projection on its own, so a call nested in its receiver part must not claim the node:
        // `head(xs)[0]` projects the call result instead of being the call `head(xs)`.
        // A builtin member call lowers to the primitive that implements it: the receiver is
        // copied first, then every argument, in the order the primitive consumes them.
        if let Some((primitive, _)) = self.builtin_target(&node) {
            let receiver_children = node
                .children()
                .iter()
                .rposition(|child| {
                    self.tree.node(*child).is_some_and(|child_node| {
                        node_contains_punctuation(self.tree, child_node, Punctuation::Dot)
                    })
                })
                .and_then(|dot| node.children().get(..dot))
                .unwrap_or_default()
                .to_vec();
            // A receiver this walk cannot key leaves the node to the ordinary aggregate or
            // value walk instead of aborting, so an enclosing shape keeps its own lowering.
            if self
                .compile_builtin_receiver(expression, &node, &receiver_children)?
                .is_some()
            {
                let arguments = call_argument_expressions(self.tree, &node);
                for argument in &arguments {
                    self.compile_expression(*argument)?;
                }
                self.emit(ty.clone(), InstructionKind::Primitive(primitive))?;
                return Ok(ty);
            }
        }
        let projection_node = is_projection_node(self.tree, expression);
        if let Some(callee) = self.direct_target(&node).filter(|_| !projection_node) {
            let receiver_type = callee.receiver_type();
            let shared_receiver = self.shared_receivers.contains(&callee);
            let owned_move_receiver = self.owned_move_receivers.get(&callee).copied();
            let requires_place = shared_receiver || owned_move_receiver.is_some();
            let constructed_receiver = receiver_type.as_ref().and_then(|_| {
                // The constructed value is the receiver part's own literal, exactly as the type
                // phase admits it: a literal inside an argument belongs to that argument.
                let receiver_children = node
                    .children()
                    .iter()
                    .rposition(|child| {
                        self.tree.node(*child).is_some_and(|child_node| {
                            node_contains_punctuation(self.tree, child_node, Punctuation::Dot)
                        })
                    })
                    .map_or_else(
                        || node.children(),
                        |dot| node.children().get(..dot).unwrap_or_default(),
                    );
                crate::bodies::receiver_owns_aggregate_literal(self.tree, receiver_children)
            });
            let receiver_place = receiver_type.as_ref().and_then(|_| {
                postfix_method_receiver_place(self.tree, &node)
                    .or_else(|| grouped_method_receiver_place(self.tree, &node))
            });
            // A receiver call whose result is projected (`p.flip().value`) must publish the call
            // before the projection steps apply: the place walk below would read the called member
            // as this node's own call and leave the field unread, so the computed receiver and its
            // steps are compiled first whenever this node carries such a tail.
            if let Some(result) =
                self.compile_computed_member_projection_operand(node.children())?
            {
                return Ok(result);
            }
            let has_implicit_receiver = constructed_receiver.is_some() || receiver_place.is_some();
            let caller_place = if requires_place {
                postfix_method_receiver_place(self.tree, &node)
                    .or_else(|| grouped_method_receiver_place(self.tree, &node))
            } else {
                None
            };
            if let (Some(struct_expression), Some(receiver_type)) =
                (constructed_receiver, receiver_type.as_ref())
            {
                if requires_place {
                    return Err(AnalysisError::Invariant);
                }
                self.compile_literal_aggregate(expression, struct_expression, Some(receiver_type))?;
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
            let arguments = call_argument_expressions(self.tree, &node);
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
                            gantry_ir::ReceiverSource::CallerPlace {
                                root,
                                path,
                                ownership: owned_move_receiver.unwrap_or(OwnershipClass::Copyable),
                            }
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
            .filter(|_| !projection_node)
        {
            let receiver_place = postfix_method_receiver_place(self.tree, &node)
                .or_else(|| grouped_method_receiver_place(self.tree, &node));
            let receiver = postfix_method_receiver(self.tree, &node)
                .or_else(|| receiver_place.as_ref().map(|(root, _)| Arc::clone(root)));
            let callee = CanonicalCallableIdentity::free(&call.callee, &[]);
            let shared_receiver = self.shared_receivers.contains(&callee);
            let owned_move_receiver = self.owned_move_receivers.get(&callee).copied();
            let requires_place = shared_receiver || owned_move_receiver.is_some();
            if let (Some((root, path)), false) = (receiver_place.as_ref(), requires_place)
                && !path.is_empty()
            {
                // A dotted receiver place loads its root and projects every field, so the call
                // reads the place it names rather than the root alone.
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
            } else if let Some(receiver) = &receiver
                && !requires_place
            {
                let receiver_type = method_receiver_type(&call.callee)?;
                self.emit(receiver_type, InstructionKind::Load(receiver.clone()))?;
            }
            let arguments = call_argument_expressions(self.tree, &node);
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
                            let (root, path) =
                                receiver_place.as_ref().ok_or(AnalysisError::Invariant)?;
                            gantry_ir::ReceiverSource::CallerPlace {
                                root: Arc::clone(root),
                                path: path.clone(),
                                ownership: owned_move_receiver.unwrap_or(OwnershipClass::Copyable),
                            }
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
        // The parser splits an operator operand into sibling fragments, so a list literal operand
        // reaches this walk as the literal node itself rather than through a wrapper expression:
        // `[1, 2] == [1, 2]` lowers its left operand here, where the aggregate arm below cannot key
        // the literal and the fallback would publish one member alone or fail on a multi-member
        // literal. The literal owns the whole node whatever its members are, so the arm runs before
        // the aggregate arms a single member would otherwise let claim it (`[Item { count: 1 }]`).
        if matches!(node.form(), SyntaxForm::ListExpression)
            && let Some(value) = self.compile_list_literal_value(expression, None)?
        {
            return Ok(value);
        }
        if let Some(struct_expression) =
            descendant_form(self.tree, expression, &[SyntaxForm::StructExpression]).filter(
                |literal| {
                    matches!(
                        owning_value(self.tree, expression),
                        Some(ExpressionValue::Struct(owner)) if owner == *literal
                    )
                },
            )
        {
            // A literal that reaches the walk inside an operand fragment carries no recorded type
            // of its own, so the constructor's name path names the declared type it builds.
            let derived = direct_child_form(self.tree, &node, SyntaxForm::Path)
                .and_then(|path| direct_identifier(self.tree, path))
                .and_then(|name| self.struct_type_by_name(name.as_ref()));
            let ty = match self.body_types.get(&expression) {
                Some(recorded) if recorded.kind() != TypeKind::Unit => recorded.clone(),
                _ => derived.unwrap_or_else(|| ty.clone()),
            };
            let literal = self.compile_struct(expression, struct_expression, ty.clone())?;
            return self.compile_projection_tail(&node, 0, &ty, literal);
        }
        if let Some((root, steps)) = postfix_projection_chain(self.tree, &node) {
            self.emit(ty.clone(), InstructionKind::Load(root))?;
            for step in steps {
                let projection = match step {
                    ProjectionChainStep::Field(field) => Projection::Field(field),
                    ProjectionChainStep::Member(index) => Projection::Member(index),
                };
                self.emit(ty.clone(), InstructionKind::Project(projection))?;
            }
            return Ok(ty);
        }
        if let Some(projection) = self.compile_static_projection(expression, &node, &ty)? {
            return Ok(projection);
        }
        if let Some(projection) = self.compile_grouped_receiver_operand(node.children())? {
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
        if let Some(list) = descendant_form(self.tree, expression, &[SyntaxForm::ListExpression])
            .filter(|literal| {
                matches!(
                    owning_value(self.tree, expression),
                    Some(ExpressionValue::List(owner)) if owner == *literal
                )
            })
        {
            if let Some(value) = self.compile_list_literal_value(list, Some(&ty))? {
                return Ok(value);
            }
            // A literal this walk cannot give an element type keeps the type its own node already
            // carries: `discard []; 0` records no element and stays the unit-typed empty list.
            self.emit(
                ty.clone(),
                InstructionKind::Aggregate {
                    kind: AggregateKind::List,
                    operands: 0,
                },
            )?;
            return Ok(ty);
        }
        if matches!(
            owning_value(self.tree, expression),
            Some(ExpressionValue::Tuple(_))
        ) {
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
        // A call-shaped sequence whose callee is a parenthesized expression is refused by the
        // type phase, so its lowering compiles the callee side of the sequence instead of
        // failing internally here and hiding the refusal that was already published.
        let node = self.node(expression)?.clone();
        if crate::bodies::expression_callee_span(self.tree, node.children())?.is_some()
            && let Some(first) = semantic.first().copied()
        {
            return self.compile_expression(first);
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

    /// Compiles one aggregate literal as the value a receiver call consumes.
    ///
    /// The type phase admits exactly the receiver parts that own a struct or list literal, so the
    /// lowering publishes the literal the call reads: a struct literal publishes its fields and
    /// then the struct aggregate, and a list literal publishes its members in order and then the
    /// list aggregate. The callee's declared receiver type is authoritative whenever the caller
    /// knows it, and the literal's own recorded type or its first member's type otherwise.
    fn compile_literal_aggregate(
        &mut self,
        expression: NodeId,
        literal: NodeId,
        authoritative: Option<&TypeDescriptor>,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let node = self.node(literal)?.clone();
        if matches!(node.form(), SyntaxForm::ListExpression) {
            return self
                .compile_list_literal_value(literal, authoritative)?
                .ok_or(AnalysisError::Invariant);
        }
        let constructed = authoritative
            .cloned()
            .or_else(|| self.body_types.get(&literal).cloned())
            .ok_or(AnalysisError::Invariant)?;
        self.compile_struct(expression, literal, constructed)
    }

    /// Publishes one list literal as the list value its members build.
    ///
    /// The members are compiled in source order and the aggregate carries `List<element>`, where
    /// the element comes from the authoritative receiver type, the literal's own recorded type, or
    /// the first member. A literal with neither a recorded element type nor a member reports no
    /// value at all, so the caller keeps whichever arm it would otherwise take.
    fn compile_list_literal_value(
        &mut self,
        literal: NodeId,
        authoritative: Option<&TypeDescriptor>,
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let node = self.node(literal)?.clone();
        let members = direct_expressions(self.tree, &node);
        let mut element = authoritative
            .cloned()
            .or_else(|| self.body_types.get(&literal).cloned())
            .filter(|ty| ty.kind() == TypeKind::List)
            .and_then(|ty| ty.immediate_members().into_iter().next());
        if element.is_none() && members.is_empty() {
            return Ok(None);
        }
        for (index, member) in members.iter().enumerate() {
            let member_type = self.compile_expression(*member)?;
            if index == 0 {
                element = Some(member_type);
            }
        }
        let Some(element) = element else {
            return Err(AnalysisError::Invariant);
        };
        let list = TypeDescriptor::list(element);
        self.emit(
            list.clone(),
            InstructionKind::Aggregate {
                kind: AggregateKind::List,
                operands: members.len(),
            },
        )?;
        Ok(Some(list))
    }

    fn compile_static_projection(
        &mut self,
        expression: NodeId,
        node: &gantry_frontend::SyntaxNode,
        ty: &TypeDescriptor,
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        // The index postfix is the direct child that carries this projection's `[`: an earlier
        // postfix belongs to a receiver part such as a call inside the receiver literal, so taking
        // the first postfix in the tree would miss the projection entirely.
        let Some(index_postfix) = node.children().iter().position(|child| {
            self.tree.node(*child).is_some_and(|child| {
                matches!(child.form(), SyntaxForm::PostfixExpression)
                    && node_contains_punctuation(self.tree, child, Punctuation::LeftBracket)
            })
        }) else {
            return Ok(None);
        };
        let index = node
            .children()
            .iter()
            .copied()
            .skip(index_postfix.saturating_add(1))
            .find_map(|child| integer_literal(self.tree, child))
            .or_else(|| {
                direct_expressions(self.tree, node)
                    .into_iter()
                    .find_map(|index| integer_literal(self.tree, index))
            })
            .ok_or(AnalysisError::Invariant)?;
        let receiver_children = node.children().get(..index_postfix).unwrap_or_default();
        // A receiver part that carries a call or grouping parenthesis is a computed receiver:
        // `head(xs)[0]` projects the call result, so the callee path must not be read as the
        // projection's receiver, and the call arms above must not lower the call alone. The
        // computed part leaves exactly the value this projection reads.
        let computed_receiver = receiver_children.iter().any(|child| {
            self.tree.node(*child).is_some_and(|child| {
                node_is_call_postfix(self.tree, child)
                    || matches!(
                        child.form(),
                        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
                    )
            })
        });
        if computed_receiver {
            if self
                .compile_computed_projection_receiver(receiver_children)?
                .is_none()
            {
                return Err(AnalysisError::Invariant);
            }
        } else if let Some(path) = direct_child_form(self.tree, node, SyntaxForm::Path) {
            let name = direct_identifier(self.tree, path).ok_or(AnalysisError::Invariant)?;
            self.emit(ty.clone(), InstructionKind::Load(name))?;
        } else if let Some(list) = node
            .children()
            .get(..index_postfix)
            .unwrap_or_default()
            .iter()
            .copied()
            .find(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|child| matches!(child.form(), SyntaxForm::ListExpression))
            })
            .or_else(|| descendant_form(self.tree, expression, &[SyntaxForm::ListExpression]))
        {
            // A receiver that is a literal aggregate lowers as the list value it denotes, so the
            // projection applies to that value instead of aborting with no receiver at all.
            let list_type = TypeDescriptor::list(ty.clone());
            let members = direct_expressions(self.tree, self.node(list)?);
            for member in &members {
                self.compile_expression(*member)?;
            }
            self.emit(
                list_type,
                InstructionKind::Aggregate {
                    kind: AggregateKind::List,
                    operands: members.len(),
                },
            )?;
        } else {
            return Err(AnalysisError::Invariant);
        }
        self.emit(
            ty.clone(),
            InstructionKind::Project(Projection::Member(index)),
        )?;
        let projected =
            self.compile_projection_tail(node, index_postfix.saturating_add(1), ty, ty.clone())?;
        Ok(Some(projected))
    }

    /// Compiles one projection receiver part that is neither a place nor a literal aggregate.
    ///
    /// A projection receiver can be a grouping parenthesis around an inner expression
    /// (`(xs)[0]`, `((xs))[0]`), a free call whose result is projected (`head(xs)[0]`), or a
    /// receiver call (`b.all()[0]`). Each of those leaves exactly the receiver value on the
    /// stack, and a part with none of those shapes reports no receiver so the caller keeps its
    /// own arms for the place and literal receivers.
    fn compile_computed_projection_receiver(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        if let Some(expression) = grouped_receiver_expression(self.tree, children) {
            let compiled = self.compile_expression(expression)?;
            // A grouping wrapper the analyzer never typed compiles to `Unit` while its inner
            // expression holds the receiver value, so the receiver type is the type the analyzer
            // recorded for that expression whenever one exists.
            return Ok(Some(
                self.body_types
                    .get(&expression)
                    .cloned()
                    .unwrap_or(compiled),
            ));
        }
        if let Some(result) = self.compile_receiver_call_operand(children)? {
            return Ok(Some(result));
        }
        let Some((callee, result)) = self.direct_sequence_target(children) else {
            return Ok(None);
        };
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
            result.clone(),
            InstructionKind::Call {
                callee,
                arguments: arguments.len(),
            },
        )?;
        Ok(Some(result))
    }

    /// Emits the projection steps one chain applies after `after` of its direct children.
    ///
    /// A chain whose receiver is an aggregate literal publishes that receiver first and then every
    /// remaining step, so `[[1, 2], [3]][1][0]` and `Item { count: 1 }.count` project each step
    /// instead of stopping at the first one and leaving the program to abort.
    fn compile_projection_tail(
        &mut self,
        node: &gantry_frontend::SyntaxNode,
        after: usize,
        ty: &TypeDescriptor,
        receiver: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let Some(steps) = postfix_projection_steps(self.tree, node.children(), after) else {
            return Ok(receiver);
        };
        if steps.is_empty() {
            return Ok(receiver);
        }
        for step in steps {
            let projection = match step {
                ProjectionChainStep::Field(field) => Projection::Field(field),
                ProjectionChainStep::Member(index) => Projection::Member(index),
            };
            self.emit(ty.clone(), InstructionKind::Project(projection))?;
        }
        Ok(ty.clone())
    }

    fn compile_match(&mut self, match_expression: NodeId) -> Result<bool, AnalysisError> {
        let node = self.node(match_expression)?.clone();
        let scrutinee = direct_child_form(self.tree, &node, SyntaxForm::Expression)
            .ok_or(AnalysisError::Invariant)?;
        let scrutinee_type = self.compile_expression(scrutinee)?;
        if self.closed_enums.contains_key(&scrutinee_type) {
            return self.compile_enum_match(match_expression, scrutinee_type);
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
        // A `_` arm covers whichever alternative the explicit arm does not name, so it stands in
        // for the missing `None`/`Err` arm (`GNT-3-T-BRANCH`).
        let wildcard = arms
            .iter()
            .copied()
            .find(|arm| is_wildcard_arm(self.tree, *arm));
        let some = arms
            .iter()
            .copied()
            .find(|arm| pattern_word(self.tree, *arm, if is_result { "Ok" } else { "Some" }))
            .or(wildcard)
            .ok_or(AnalysisError::Invariant)?;
        let none = arms
            .iter()
            .copied()
            .find(|arm| pattern_word(self.tree, *arm, if is_result { "Err" } else { "None" }))
            .or(wildcard)
            .ok_or(AnalysisError::Invariant)?;

        let when_some = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        let some_bindings = self.binding_types.clone();
        if !is_wildcard_arm(self.tree, some) {
            self.bind_pattern_payload(
                some,
                members.first().cloned().ok_or(AnalysisError::Invariant)?,
            )?;
        }
        let some_falls_through = self.compile_match_arm(some)?;
        self.binding_types = some_bindings;
        self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = if some_falls_through {
            Some(self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?)
        } else {
            None
        };

        let when_none = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
        let none_bindings = self.binding_types.clone();
        if is_result && !is_wildcard_arm(self.tree, none) {
            self.bind_pattern_payload(
                none,
                members.get(1).cloned().ok_or(AnalysisError::Invariant)?,
            )?;
        }
        let none_falls_through = self.compile_match_arm(none)?;
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
        if let Some(jump) = jump {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        Ok(some_falls_through || none_falls_through)
    }

    fn compile_enum_match(
        &mut self,
        match_expression: NodeId,
        scrutinee_type: TypeDescriptor,
    ) -> Result<bool, AnalysisError> {
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
        let mut falls_through = false;
        let mut named = BTreeSet::new();
        for arm in source_arms.iter().copied() {
            if is_wildcard_arm(self.tree, arm) {
                continue;
            }
            named.insert(
                enum_pattern_variant(self.tree, arm, &variants).ok_or(AnalysisError::Invariant)?,
            );
        }
        for arm in source_arms {
            // A `_` arm is the default target: it runs for every variant the explicit arms do not
            // name (`GNT-3-T-BRANCH`), and it cannot bind a payload.
            let variant = if is_wildcard_arm(self.tree, arm) {
                None
            } else {
                Some(
                    enum_pattern_variant(self.tree, arm, &variants)
                        .ok_or(AnalysisError::Invariant)?,
                )
            };
            let payload = variant
                .as_ref()
                .and_then(|variant| variants.get(variant))
                .cloned()
                .flatten();
            let target = self.instructions.len();
            if let Some(variant) = &variant {
                lowered_arms.push((variant.clone(), target));
            } else {
                for candidate in variants.keys() {
                    if !named.contains(candidate) {
                        lowered_arms.push((candidate.clone(), target));
                    }
                }
            }
            self.emit(TypeDescriptor::UNIT, InstructionKind::EnterScope)?;
            let arm_bindings = self.binding_types.clone();
            if let Some(payload) = payload {
                self.bind_pattern_payload(arm, payload.clone())?;
            }
            let arm_falls_through = self.compile_match_arm(arm)?;
            falls_through |= arm_falls_through;
            self.binding_types = arm_bindings;
            self.emit(TypeDescriptor::UNIT, InstructionKind::ExitScope)?;
            self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
            if arm_falls_through {
                jumps.push(self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?);
            }
        }
        let end = self.instructions.len();
        for jump in jumps {
            self.instructions[jump].kind = InstructionKind::Jump(end);
        }
        self.instructions[branch].kind = InstructionKind::BranchEnum { arms: lowered_arms };
        Ok(falls_through)
    }

    fn compile_match_arm(&mut self, arm: NodeId) -> Result<bool, AnalysisError> {
        let node = self.node(arm)?.clone();
        if let Some(expression) = direct_child_form(self.tree, &node, SyntaxForm::Expression) {
            self.compile_expression(expression)?;
            return Ok(true);
        }
        let block = direct_child_form(self.tree, &node, SyntaxForm::Block)
            .ok_or(AnalysisError::Invariant)?;
        self.compile_block(block, BlockMode::Value)
    }

    /// Lowers an effect-only `match` statement.
    ///
    /// Every statement arm completes with `Unit` when it can complete normally, so the
    /// value merged at the arm join is discarded exactly when some arm falls through
    /// (`GNT-3-T-BRANCH`). A match whose arms all diverge leaves the enclosing block with
    /// no reachable normal completion, exactly as the analyzer reports.
    fn compile_statement_match(&mut self, statement: NodeId) -> Result<bool, AnalysisError> {
        let falls_through = self.compile_match(statement)?;
        if falls_through {
            self.emit(TypeDescriptor::UNIT, InstructionKind::Pop)?;
        }
        Ok(falls_through)
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
        // The parser leaves an operator-free `BinaryExpression` wrapper around one operand when
        // a chain folds around it (`1 + f(1) + f(2)` wraps the middle call), and that wrapper is
        // not a sequence: the call path would read the wrapped node as the call's argument list
        // and emit one call with no argument. Descending to the wrapped node and compiling it as
        // this slice gives the same shape the same call has in a two-term chain, where the
        // operand is that expression node itself. A wrapper holding only a token child is a
        // literal, which `compile_expression` already handles for the wrapper node.
        if let [only] = children
            && let Some(node) = self.tree.node(*only)
            && matches!(node.form(), SyntaxForm::BinaryExpression)
            && binary_operators(self.tree, node.children()).is_empty()
            && let Some(wrapped) = single_wrapped_node(self.tree, node)
        {
            return self.compile_sequence(std::slice::from_ref(&wrapped));
        }
        // A slice that indexes the result of a call is not that call, whether the index postfix is
        // nested in one child or a sibling fragment of the flattened slice: `head(xs)[0]` must
        // compile the projection instead of the call and then the projection again. A projection
        // that lies inside the call's own parentheses is that call's argument instead, so
        // `f(xs[0])` still compiles one call whose argument projects.
        let projects = children.iter().any(|child| {
            is_projection_node(self.tree, *child)
                && !child_is_inside_call_parentheses(self.tree, children, *child)
        }) || slice_indexes_call_result(self.tree, children);
        // The call path assembles a call from sibling fragments. A slice that opens with anything
        // but a callee token is not one of those fragments - `(bag()[0]).count` hands the parser's
        // inner call to the span helper - and a slice that is one expression node already is that
        // call, so compiling the node that is the call as its own argument list would emit it
        // twice.
        let assembles_call = slice_opens_with_callee(self.tree, children)
            && !slice_is_call_expression(self.tree, children);
        if !projects
            && assembles_call
            && let Some((callee, result)) = self.direct_sequence_target(children)
        {
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

    /// Compiles one operand slice and returns the type of the value it leaves.
    ///
    /// The last instruction an operand emits publishes the operand's own type, which the
    /// enclosing primitive consumes. Wrapper nodes injected by the parser carry no declared
    /// type, so the emitted instruction is the reliable source for that operand.
    fn compile_operand(&mut self, children: &[NodeId]) -> Result<TypeDescriptor, AnalysisError> {
        let before = self.instructions.len();
        self.compile_sequence(children)?;
        self.instructions
            .get(before..)
            .and_then(|emitted| emitted.last())
            .map(|instruction| instruction.ty.clone())
            .ok_or(AnalysisError::Invariant)
    }

    /// Compiles a flattened operator chain left to right, one step per operator.
    ///
    /// `10 - 2 - 3` parses as one expression node holding `[10, -, 2, -, 3]`, so folding
    /// that slice in source order emits `((10 - 2) - 3)` rather than applying one primitive
    /// to the last two operands. An operator of tighter precedence keeps its right operand
    /// inside a nested node, which this fold compiles as a single operand. A node can also
    /// carry a lower-precedence `&&` or `||` after the operators it follows, so each step
    /// chooses between one deterministic primitive and one short-circuit logical step.
    fn compile_binary_chain(
        &mut self,
        children: &[NodeId],
        ty: TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let operators = binary_operators(self.tree, children);
        if operators.is_empty() {
            return Err(AnalysisError::Invariant);
        }
        let mut operands = Vec::with_capacity(operators.len().saturating_add(1));
        let mut start = 0_usize;
        for (_, index) in &operators {
            operands.push(children.get(start..*index).unwrap_or_default());
            start = index.saturating_add(1);
        }
        operands.push(children.get(start..).unwrap_or_default());
        let mut left_type = self.compile_operand(operands[0])?;
        for ((operator, _), operand) in operators.iter().zip(operands.iter().skip(1)) {
            if logical_constant(*operator).is_some() {
                self.emit_logical_step(*operator, |compiler| compiler.compile_sequence(operand))?;
                left_type = TypeDescriptor::BOOL;
            } else {
                self.compile_operand(operand)?;
                left_type = self.emit_binary_primitive(*operator, &left_type)?;
            }
        }
        Ok(ty)
    }

    /// Emits one binary primitive and returns the type of the value it publishes.
    fn emit_binary_primitive(
        &mut self,
        operator: Punctuation,
        left_type: &TypeDescriptor,
    ) -> Result<TypeDescriptor, AnalysisError> {
        let primitive = primitive_for_binary(operator).ok_or(AnalysisError::Invariant)?;
        let result = primitive_result_type(&primitive, left_type);
        self.emit(result.clone(), InstructionKind::Primitive(primitive))?;
        Ok(result)
    }

    /// Emits one short-circuit logical step over the accumulated left operand.
    ///
    /// The caller has published the completed left operand as the stack top. `GNT-5.15` makes
    /// `&&` and `||` accept `Bool`, evaluate left to right, short-circuit, and return `Bool`,
    /// and requires that the right operand is not evaluated once the left operand determines
    /// the result, so one eager primitive over completed operands cannot express either
    /// operator. This instead reuses the deterministic branch the machine already executes for
    /// `if`: a `Branch` on the left operand, the deciding constant in the arm that skips the
    /// right operand, and the right operand in the arm that still needs it. Both arms leave
    /// exactly one `Bool`, and each balances the dynamic occurrence its `Branch` records, so an
    /// enclosing chain observes one value and no leftover branch frame. A skipped right operand
    /// executes no instruction on that path, so it creates no operation, dispatch, task,
    /// journal transition, or event.
    fn emit_logical_step<F>(
        &mut self,
        operator: Punctuation,
        compile: F,
    ) -> Result<(), AnalysisError>
    where
        F: FnOnce(&mut Self) -> Result<(), AnalysisError>,
    {
        let constant = logical_constant(operator).ok_or(AnalysisError::Invariant)?;
        let branch = self.emit(
            TypeDescriptor::BOOL,
            InstructionKind::Branch {
                when_true: 0,
                when_false: 0,
            },
        )?;
        let decide = self.instructions.len();
        compile(self)?;
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        let jump = self.emit(TypeDescriptor::UNIT, InstructionKind::Jump(0))?;
        let decided = self.instructions.len();
        self.emit(TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence)?;
        self.emit(
            TypeDescriptor::BOOL,
            InstructionKind::Push(LogicalValue::boolean(constant)),
        )?;
        let resume = self.instructions.len();
        // `&&` needs its right operand exactly when the left operand is true; `||` needs it
        // exactly when it is false, and otherwise publishes its deciding constant.
        self.instructions[branch].kind = InstructionKind::Branch {
            when_true: if constant { decided } else { decide },
            when_false: if constant { decide } else { decided },
        };
        self.instructions[jump].kind = InstructionKind::Jump(resume);
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
            let left = children.get(..index).unwrap_or_default();
            let right = children.get(index.saturating_add(1)..).unwrap_or_default();
            if logical_constant(operator).is_some() {
                self.compile_operand_sequence(left)?;
                self.emit_logical_step(operator, |compiler| {
                    compiler.compile_operand_sequence(right).map(|_| ())
                })?;
                return Ok(TypeDescriptor::BOOL);
            }
            let left_type = self.compile_operand_sequence(left)?;
            self.compile_operand_sequence(right)?;
            let primitive = primitive_for_binary(operator).ok_or(AnalysisError::Invariant)?;
            let result = primitive_result_type(&primitive, &left_type);
            self.emit(result.clone(), InstructionKind::Primitive(primitive))?;
            return Ok(result);
        }
        if let Some(result) = self.compile_projected_operand_place(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_index_projection_operand(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_literal_index_projection_operand(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_split_struct_operand(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_computed_member_projection_operand(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_builtin_call_operand(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_receiver_call_operand(children)? {
            return Ok(result);
        }
        if let Some(result) = self.compile_grouped_receiver_operand(children)? {
            return Ok(result);
        }
        let mut result = TypeDescriptor::UNIT;
        let valued = children
            .iter()
            .filter(|child| {
                self.tree.node(**child).is_some_and(|node| {
                    !matches!(node.form(), SyntaxForm::Token(_))
                        && !is_parenthesis_boundary(self.tree, node)
                })
            })
            .count();
        for child in children {
            let node = self.node(*child)?;
            if matches!(node.form(), SyntaxForm::Token(_)) {
                continue;
            }
            if valued > 0 && is_parenthesis_boundary(self.tree, node) {
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

    /// Lowers a split index projection whose receiver part is a list literal.
    ///
    /// `Item { count: 1 }` reaches an operator operand as the constructor's name path and the
    /// struct expression itself in sibling fragments, so the child walk would publish the name as a
    /// binding load and then aggregate the fields with no type of their own. The declared type is
    /// the one whose canonical name the path spells, and the struct expression supplies the fields,
    /// so the operand lowers as the constructed value it denotes.
    fn compile_split_struct_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        // The constructor's name and the struct expression it names are the whole operand: any
        // further fragment is a step this walk does not own (`Counter { value: 5 }.read()`).
        let valued = children
            .iter()
            .copied()
            .filter(|child| {
                self.tree.node(*child).is_some_and(|node| {
                    !matches!(node.form(), SyntaxForm::Token(_))
                        && !is_parenthesis_boundary(self.tree, node)
                })
            })
            .collect::<Vec<_>>();
        let [name, body] = valued.as_slice() else {
            return Ok(None);
        };
        let Some(identifier) = direct_identifier(self.tree, *name) else {
            return Ok(None);
        };
        let body_node = self.node(*body)?;
        let struct_expression = if matches!(body_node.form(), SyntaxForm::StructExpression) {
            Some(*body)
        } else {
            descendant_form(self.tree, *body, &[SyntaxForm::StructExpression])
        };
        let Some(struct_expression) = struct_expression else {
            return Ok(None);
        };
        let Some(declared) = self.struct_type_by_name(identifier.as_ref()) else {
            return Ok(None);
        };
        let literal = self.compile_struct(*name, struct_expression, declared.clone())?;
        Ok(Some(literal))
    }

    /// Returns the declared type whose canonical name ends with one identifier.
    ///
    /// A struct literal that reaches the walk as an operand fragment carries no recorded type of
    /// its own, and the constructor's name path is the only spelling it has, so the declared type
    /// is the one whose final canonical segment is that name.
    fn struct_type_by_name(&self, name: &str) -> Option<TypeDescriptor> {
        self.struct_fields
            .keys()
            .find(|ty| {
                ty.canonical_string()
                    .rsplit("::")
                    .next()
                    .is_some_and(|last| last == name)
            })
            .cloned()
    }

    /// Lowers a split index projection whose receiver part is a list literal.
    ///
    /// `[1, 2][0]` reaches an operator operand as the literal and its index postfix in sibling
    /// fragments, which the place walk above cannot key because its receiver is not a place: the
    /// literal publishes the list value it denotes and the projection reads the element the index
    /// expression names. Only an index that is exactly one integer-literal token is read here, the
    /// same rule the type phase applies to the operand, and a shape this walk cannot key reports no
    /// operand so the caller keeps the ordinary child walk.
    fn compile_literal_index_projection_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let Some(index_postfix) = children.iter().position(|child| {
            self.tree.node(*child).is_some_and(|node| {
                matches!(node.form(), SyntaxForm::PostfixExpression)
                    && node_contains_punctuation(self.tree, node, Punctuation::LeftBracket)
            })
        }) else {
            return Ok(None);
        };
        let receiver_children = children.get(..index_postfix).unwrap_or_default();
        let Some(literal) = receiver_children.iter().copied().find(|child| {
            self.tree
                .node(*child)
                .is_some_and(|node| matches!(node.form(), SyntaxForm::ListExpression))
        }) else {
            return Ok(None);
        };
        let Some(index_expression) = children
            .iter()
            .copied()
            .skip(index_postfix.saturating_add(1))
            .find(|child| {
                self.tree
                    .node(*child)
                    .is_some_and(|node| matches!(node.form(), SyntaxForm::Expression))
            })
        else {
            return Ok(None);
        };
        let Some(index) = crate::bodies::literal_projection_index(self.tree, index_expression)
        else {
            return Ok(None);
        };
        // Every later step belongs to the same chain, so the literal publishes the value the first
        // index reads and each following step projects from it (`[[1, 2], [3]][0][1]` reads the
        // second element of the list the first step selected).
        let Some(steps) =
            postfix_projection_steps(self.tree, children, index_postfix.saturating_add(1))
        else {
            return Ok(None);
        };
        let Some(list) = self.compile_list_literal_value(literal, None)? else {
            return Ok(None);
        };
        let member = Projection::Member(index);
        let mut current = projection_step_type(&list, &member, self.struct_fields)
            .ok_or(AnalysisError::Invariant)?;
        self.emit(current.clone(), InstructionKind::Project(member))?;
        for step in steps {
            let projection = match step {
                ProjectionChainStep::Field(field) => Projection::Field(field),
                ProjectionChainStep::Member(index) => Projection::Member(index),
            };
            current = projection_step_type(&current, &projection, self.struct_fields)
                .ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Project(projection))?;
        }
        Ok(Some(current))
    }

    /// Lowers a split index-projection operand as one root load plus one projection per step.
    ///
    /// The parser splits a leading projection into sibling fragments, so `xs[0]` has no node of its
    /// own and the analyzer types that shape as the element the projection reads. Lowering resolves
    /// the same root and steps from the sibling tokens: the first bracket step and every later dot
    /// or bracket step becomes one `Project` instruction, and a shape this walk cannot key reports
    /// no operand so the caller keeps the ordinary child walk.
    fn compile_index_projection_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let Some((root, path)) = operand_index_place(self.tree, children) else {
            return self.compile_computed_index_projection_operand(children);
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
            let projection = match segment {
                ValuePathSegment::StructField(field) => {
                    Projection::Field(Arc::from(field.as_str()))
                }
                ValuePathSegment::ListItem(index) | ValuePathSegment::TupleMember(index) => {
                    Projection::Member(*index)
                }
                _ => return Err(AnalysisError::Invariant),
            };
            result = types.next().ok_or(AnalysisError::Invariant)?;
            self.emit(result.clone(), InstructionKind::Project(projection))?;
        }
        if types.next().is_some() {
            return Err(AnalysisError::Invariant);
        }
        Ok(Some(result))
    }

    /// Lowers a split index-projection operand whose receiver part is computed.
    ///
    /// A receiver part that is a grouping parenthesis or a call (`(xs)[0]`, `head(xs)[0]`)
    /// leaves exactly the value it produces on the stack, so the element projection reads that
    /// value rather than a caller place. The literal index and every later step are keyed the way
    /// the place-backed arm keys them, and a shape this walk cannot key reports no operand so the
    /// caller keeps the ordinary child walk.
    fn compile_computed_index_projection_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        // A computed receiver reaches the operand walk either as sibling fragments or as one
        // nested expression, so a slice that is a single wrapper node offers its own children to
        // the same arm before the caller falls back to the ordinary child walk.
        if let [only] = children {
            let nested = self
                .tree
                .node(*only)
                .map(|node| node.children().to_vec())
                .filter(|nested| !nested.is_empty());
            if let Some(nested) = nested
                && let Some(result) = self.compile_computed_index_projection_operand(&nested)?
            {
                return Ok(Some(result));
            }
        }
        let Some(index_postfix) = children.iter().position(|child| {
            self.tree.node(*child).is_some_and(|node| {
                matches!(node.form(), SyntaxForm::PostfixExpression)
                    && node_contains_punctuation(self.tree, node, Punctuation::LeftBracket)
            })
        }) else {
            return Ok(None);
        };
        let receiver_children = children.get(..index_postfix).unwrap_or_default();
        // A receiver part with no call and no grouping parenthesis is a caller place, so the place
        // arm above already had its chance and a value left here would sit on the stack with no
        // later instruction to consume it.
        let computed = receiver_children.iter().any(|child| {
            self.tree.node(*child).is_some_and(|node| {
                node_is_call_postfix(self.tree, node)
                    || matches!(
                        node.form(),
                        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
                    )
            })
        });
        if !computed {
            return Ok(None);
        }
        let Some(index) = children
            .iter()
            .copied()
            .skip(index_postfix.saturating_add(1))
            .find_map(|child| integer_literal(self.tree, child))
        else {
            return Ok(None);
        };
        let Some(steps) =
            postfix_projection_steps(self.tree, children, index_postfix.saturating_add(1))
        else {
            return Ok(None);
        };
        let Some(receiver_type) = self.compile_computed_projection_receiver(receiver_children)?
        else {
            return Ok(None);
        };
        let member = Projection::Member(index);
        let mut current = projection_step_type(&receiver_type, &member, self.struct_fields)
            .ok_or(AnalysisError::Invariant)?;
        self.emit(current.clone(), InstructionKind::Project(member))?;
        for step in steps {
            let projection = match step {
                ProjectionChainStep::Field(field) => Projection::Field(field),
                ProjectionChainStep::Member(index) => Projection::Member(index),
            };
            current = projection_step_type(&current, &projection, self.struct_fields)
                .ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Project(projection))?;
        }
        Ok(Some(current))
    }

    /// Lowers a split member projection whose receiver part computes a value.
    ///
    /// `p.flip().value` and `mk().value` read a field of the value the receiver call publishes:
    /// the receiver part up to the call's closing parenthesis is compiled to that value (grouped
    /// and free-call receivers included), and every `.member` or literal index step after it
    /// projects from that value. A tail that still opens a call belongs to the receiver-call arm,
    /// and a shape this walk cannot key reports no operand so the caller keeps its own walk.
    fn compile_computed_member_projection_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        // A computed receiver reaches the operand walk either as sibling fragments or as one
        // nested expression, so a slice that is a single wrapper node offers its own children to
        // the same arm before the caller falls back to the ordinary child walk.
        if let [only] = children {
            let nested = self
                .tree
                .node(*only)
                .map(|node| node.children().to_vec())
                .filter(|nested| !nested.is_empty());
            if let Some(nested) = nested
                && let Some(result) = self.compile_computed_member_projection_operand(&nested)?
            {
                return Ok(Some(result));
            }
        }
        let Some(close) = children.iter().position(|child| {
            self.tree
                .node(*child)
                .is_some_and(|node| node_is_closing_parenthesis(self.tree, node))
        }) else {
            return Ok(None);
        };
        let receiver_children = children.get(..=close).unwrap_or_default();
        // A receiver part that is only a dotted place was already keyed by the place arm, and one
        // without a call or grouping parenthesis has no computed value to project from.
        let computed = receiver_children.iter().any(|child| {
            self.tree.node(*child).is_some_and(|node| {
                node_is_call_postfix(self.tree, node)
                    || matches!(
                        node.form(),
                        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
                    )
            })
        });
        if !computed {
            return Ok(None);
        }
        if !projection_tail_is_step_only(self.tree, children, close.saturating_add(1)) {
            return Ok(None);
        }
        let Some(steps) = postfix_projection_steps(self.tree, children, close.saturating_add(1))
        else {
            return Ok(None);
        };
        if steps.is_empty() {
            return Ok(None);
        }
        let Some(mut current) = self.compile_computed_projection_receiver(receiver_children)?
        else {
            return Ok(None);
        };
        for step in steps {
            let projection = match step {
                ProjectionChainStep::Field(field) => Projection::Field(field),
                ProjectionChainStep::Member(index) => Projection::Member(index),
            };
            current = projection_step_type(&current, &projection, self.struct_fields)
                .ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Project(projection))?;
        }
        Ok(Some(current))
    }

    /// Lowers a computed operand whose receiver part is one grouping parenthesis.
    ///
    /// `(bag()[0]).count` keeps its receiver inside a group rather than in sibling fragments, so no
    /// top-level index postfix reaches the fragment walks above. The group's own expression is
    /// compiled as the value it produces and every later step is projected from that value, exactly
    /// as those walks project a computed receiver. A tail that carries a call belongs to the
    /// receiver-call arm above, and a tail this walk cannot key reports no operand so the caller
    /// keeps the ordinary child walk.
    fn compile_grouped_receiver_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let Some((inner, after)) = grouped_receiver_split(self.tree, children) else {
            return Ok(None);
        };
        if !projection_tail_is_step_only(self.tree, children, after) {
            return Ok(None);
        }
        let Some(steps) = postfix_projection_steps(self.tree, children, after) else {
            return Ok(None);
        };
        if steps.is_empty() {
            return Ok(None);
        }
        let mut current = self.compile_expression(inner)?;
        for step in steps {
            let projection = match step {
                ProjectionChainStep::Field(field) => Projection::Field(field),
                ProjectionChainStep::Member(index) => Projection::Member(index),
            };
            current = projection_step_type(&current, &projection, self.struct_fields)
                .ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Project(projection))?;
        }
        Ok(Some(current))
    }

    /// Lowers a split receiver-call operand as its receiver, arguments, and one call.
    ///
    /// The parser splits a leading dotted receiver call into sibling fragments, so the call
    /// has no node of its own to compile. The analyzer still types that shape as the callee's
    /// result, so lowering resolves the same direct target by the call-site span the fragments
    /// reconstruct, admits the receiver per its mode, and emits the call whose result the
    /// enclosing primitive or chain step consumes.
    fn compile_receiver_call_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let Some((receiver, arguments)) = operand_receiver_call_split(self.tree, children) else {
            return Ok(None);
        };
        let Some(source) = sequence_call_site_span(self.tree, children) else {
            return Ok(None);
        };
        // The type phase records one call site per resolved call - the whole call sequence for a
        // free or inherent call, and the member name for a trait method - so a recorded site that
        // is this slice's own member names the same call the fragments reconstruct.
        let member = sequence_call_member_span(self.tree, children);
        let Some(callee) = self
            .direct_targets
            .iter()
            .find(|(candidate, callee)| {
                callee.receiver_type().is_some()
                    && (*candidate == source
                        || member.as_ref().is_some_and(|member| *candidate == *member))
            })
            .map(|(_, callee)| callee.clone())
        else {
            return Ok(None);
        };
        let Some(result) = self.callable_results.get(&callee).cloned() else {
            return Ok(None);
        };
        let owned_move_receiver = self.owned_move_receivers.get(&callee).copied();
        let requires_place =
            self.shared_receivers.contains(&callee) || owned_move_receiver.is_some();
        match &receiver {
            SplitOperandReceiver::Place(root, path) => {
                let Some(receiver_types) =
                    receiver_place_types(root, path, &self.binding_types, self.struct_fields)
                else {
                    return Ok(None);
                };
                if !requires_place {
                    let mut receiver_types = receiver_types.into_iter();
                    self.emit(
                        receiver_types.next().ok_or(AnalysisError::Invariant)?,
                        InstructionKind::Load(root.clone()),
                    )?;
                    for segment in path {
                        let ValuePathSegment::StructField(field) = segment else {
                            return Err(AnalysisError::Invariant);
                        };
                        self.emit(
                            receiver_types.next().ok_or(AnalysisError::Invariant)?,
                            InstructionKind::Project(Projection::Field(Arc::from(field.as_str()))),
                        )?;
                    }
                }
            }
            SplitOperandReceiver::Constructed(struct_expression) => {
                let receiver_type = callee
                    .receiver_type()
                    .ok_or(AnalysisError::Invariant)?
                    .clone();
                if requires_place {
                    return Err(AnalysisError::Invariant);
                }
                self.compile_struct(
                    children.first().copied().ok_or(AnalysisError::Invariant)?,
                    *struct_expression,
                    receiver_type,
                )?;
            }
        }
        for argument in &arguments {
            self.compile_expression(*argument)?;
        }
        self.emit(
            result.clone(),
            InstructionKind::ReceiverCall {
                callee,
                arguments: arguments.len().saturating_add(1),
                source: if requires_place {
                    let SplitOperandReceiver::Place(root, path) = &receiver else {
                        return Err(AnalysisError::Invariant);
                    };
                    gantry_ir::ReceiverSource::CallerPlace {
                        root: root.clone(),
                        path: path.clone(),
                        ownership: owned_move_receiver.unwrap_or(OwnershipClass::Copyable),
                    }
                } else {
                    gantry_ir::ReceiverSource::CopiedValue
                },
            },
        )?;
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
                        // The matched call site must be this expression's own call rather
                        // than a call nested inside it: a list or struct literal whose text
                        // contains a call (for example `[g(1)]`) otherwise matches that inner
                        // call here, so the aggregate is lowered as the call and the operand
                        // stream no longer matches its type.
                        && (source.bytes().start() == expression.span().bytes().start()
                            || !aggregate_contains_span(self.tree, expression, source))
                        && !arguments
                            .iter()
                            .any(|argument| source_span_contains(argument, source))
                }
            })
            .min_by_key(|(source, _)| source.bytes().end().saturating_sub(source.bytes().start()))
            .map(|(_, target)| target.clone())
    }

    /// Returns the primitive one recorded builtin member call lowers to.
    ///
    /// The type phase records one builtin call per resolved call site, so the walk matches the
    /// smallest recorded span the node contains outside its argument list, exactly as recorded
    /// source calls are matched.
    fn builtin_target(
        &self,
        expression: &gantry_frontend::SyntaxNode,
    ) -> Option<(Primitive, TypeDescriptor)> {
        let arguments = call_argument_expressions(self.tree, expression)
            .into_iter()
            .filter_map(|argument| self.tree.node(argument).map(|node| node.span()))
            .collect::<Vec<_>>();
        self.builtin_targets
            .iter()
            .filter(|(source, _, _)| {
                source_span_contains(expression.span(), source)
                    // The matched call site must be this expression's own call rather than a
                    // call nested inside an aggregate: a list or struct literal whose text
                    // contains a builtin call (`[xs.len()]`) otherwise claims that inner call
                    // here, exactly as a recorded source call would.
                    && (source.bytes().start() == expression.span().bytes().start()
                        || !aggregate_contains_span(self.tree, expression, source))
                    && !arguments
                        .iter()
                        .any(|argument| source_span_contains(argument, source))
            })
            .min_by_key(|(source, _, _)| {
                source.bytes().end().saturating_sub(source.bytes().start())
            })
            .map(|(_, primitive, result)| (*primitive, result.clone()))
    }

    /// Returns the primitive one recorded builtin call names for one operand slice.
    ///
    /// The operand walk receives a call as sibling fragments, so the slice's own record is
    /// matched by the call-site span the fragments reconstruct, exactly as the receiver-call arm
    /// matches a recorded source call.
    fn builtin_target_parts(&self, children: &[NodeId]) -> Option<(Primitive, TypeDescriptor)> {
        let source = sequence_call_site_span(self.tree, children)?;
        self.builtin_targets
            .iter()
            .find(|(target, _, _)| target == &source)
            .map(|(_, primitive, result)| (*primitive, result.clone()))
    }

    /// Lowers a split builtin member call operand as its receiver, arguments, and one primitive.
    ///
    /// The operand walk receives the call as sibling fragments, so the receiver part is the slice
    /// before the call parenthesis (its member dot separates the receiver from the member name)
    /// and the arguments are the expression fragments inside it.
    fn compile_builtin_call_operand(
        &mut self,
        children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        let Some((primitive, result)) = self.builtin_target_parts(children) else {
            return Ok(None);
        };
        let Some(open) = children.iter().position(|child| {
            self.tree
                .node(*child)
                .is_some_and(|node| node_is_call_postfix(self.tree, node))
        }) else {
            return Ok(None);
        };
        let Some(close) = children.len().checked_sub(1) else {
            return Ok(None);
        };
        if close <= open {
            return Ok(None);
        }
        let receiver = children.get(..open).unwrap_or_default();
        let Some(_) = self.compile_builtin_receiver_parts(receiver)? else {
            return Ok(None);
        };
        for argument in children
            .get(open.saturating_add(1)..close)
            .unwrap_or_default()
        {
            if matches!(self.node(*argument)?.form(), SyntaxForm::Expression) {
                self.compile_expression(*argument)?;
            }
        }
        self.emit(result.clone(), InstructionKind::Primitive(primitive))?;
        Ok(Some(result))
    }

    /// Compiles one builtin call operand's receiver from its sibling fragments.
    ///
    /// The operand walk sees the receiver, the member name, and the arguments as siblings, so the
    /// receiver part is a place (grouped or not), a constructed value, or a literal value; the
    /// type phase refuses every other receiver expression.
    fn compile_builtin_receiver_parts(
        &mut self,
        receiver: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        if let Some((root, path)) = operand_receiver_place(self.tree, receiver) {
            let mut projection_types =
                receiver_place_types(&root, &path, &self.binding_types, self.struct_fields)
                    .ok_or(AnalysisError::Invariant)?
                    .into_iter();
            let mut current = projection_types.next().ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Load(root.clone()))?;
            for field in &path {
                let ValuePathSegment::StructField(field) = field else {
                    return Err(AnalysisError::Invariant);
                };
                current = projection_types.next().ok_or(AnalysisError::Invariant)?;
                self.emit(
                    current.clone(),
                    InstructionKind::Project(Projection::Field(Arc::from(field.as_str()))),
                )?;
            }
            if projection_types.next().is_some() {
                return Err(AnalysisError::Invariant);
            }
            return Ok(Some(current));
        }
        if let Some(literal) = crate::bodies::receiver_owns_aggregate_literal(self.tree, receiver) {
            return Ok(Some(
                self.compile_literal_aggregate(literal, literal, None)?,
            ));
        }
        let mut tokens = Vec::new();
        let mut work = receiver.iter().rev().copied().collect::<Vec<_>>();
        while let Some(id) = work.pop() {
            let Some(node) = self.tree.node(id) else {
                break;
            };
            if matches!(node.form(), SyntaxForm::Token(_)) {
                tokens.push(id);
            } else {
                work.extend(node.children().iter().rev().copied());
            }
        }
        let member_dot = tokens.iter().rposition(|id| {
            matches!(
                self.tree.node(*id).map(|node| node.form()),
                Some(SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)))
            )
        });
        let mut receiver_tokens = member_dot
            .map_or(tokens.as_slice(), |dot| &tokens[..dot])
            .to_vec();
        // A grouping pair around a literal is transparent here exactly as it is in the type
        // phase, so `("abc").len()` publishes the same literal value `"abc".len()` does.
        if let [first, .., last] = receiver_tokens.as_slice()
            && matches!(
                self.tree.node(*first).map(|node| node.form()),
                Some(SyntaxForm::Token(TokenKind::Punctuation(
                    Punctuation::LeftParenthesis
                )))
            )
            && matches!(
                self.tree.node(*last).map(|node| node.form()),
                Some(SyntaxForm::Token(TokenKind::Punctuation(
                    Punctuation::RightParenthesis
                )))
            )
        {
            receiver_tokens = receiver_tokens[1..receiver_tokens.len().saturating_sub(1)].to_vec();
        }
        if let [only] = receiver_tokens.as_slice()
            && let Some((value, ty)) = literal_token(self.tree, *only)?
        {
            self.emit(ty.clone(), InstructionKind::Push(value))?;
            return Ok(Some(ty));
        }
        Ok(None)
    }

    /// Compiles one builtin member call's receiver, which the primitive copies.
    ///
    /// A builtin receiver is a binding root or struct-field place (grouped or not), a constructed
    /// value, or a literal value; the type phase refuses every other receiver expression.
    fn compile_builtin_receiver(
        &mut self,
        expression: NodeId,
        node: &gantry_frontend::SyntaxNode,
        receiver_children: &[NodeId],
    ) -> Result<Option<TypeDescriptor>, AnalysisError> {
        if let Some((root, path)) = postfix_method_receiver_place(self.tree, node)
            .or_else(|| grouped_method_receiver_place(self.tree, node))
        {
            let mut projection_types =
                receiver_place_types(&root, &path, &self.binding_types, self.struct_fields)
                    .ok_or(AnalysisError::Invariant)?
                    .into_iter();
            let mut current = projection_types.next().ok_or(AnalysisError::Invariant)?;
            self.emit(current.clone(), InstructionKind::Load(root.clone()))?;
            for field in &path {
                let ValuePathSegment::StructField(field) = field else {
                    return Err(AnalysisError::Invariant);
                };
                current = projection_types.next().ok_or(AnalysisError::Invariant)?;
                self.emit(
                    current.clone(),
                    InstructionKind::Project(Projection::Field(Arc::from(field.as_str()))),
                )?;
            }
            if projection_types.next().is_some() {
                return Err(AnalysisError::Invariant);
            }
            return Ok(Some(current));
        }
        if let Some(literal) =
            crate::bodies::receiver_owns_aggregate_literal(self.tree, receiver_children)
        {
            return Ok(Some(
                self.compile_literal_aggregate(expression, literal, None)?,
            ));
        }
        if let Some(inner) = grouped_receiver_expression(self.tree, receiver_children) {
            return Ok(Some(self.compile_expression(inner)?));
        }
        // A literal receiver publishes its own value (`1.to_string()`, `"abc".len()`); the type
        // phase admits no other receiver here, so a remaining value compiles its expression.
        if let Some(value) = literal_value(self.tree, node)? {
            let ty = literal_type(self.tree, node).ok_or(AnalysisError::Invariant)?;
            self.emit(ty.clone(), InstructionKind::Push(value))?;
            return Ok(Some(ty));
        }
        for child in receiver_children {
            let Some(child_node) = self.tree.node(*child) else {
                continue;
            };
            if matches!(child_node.form(), SyntaxForm::Expression) {
                return Ok(Some(self.compile_expression(*child)?));
            }
        }
        Ok(None)
    }

    fn direct_sequence_target(
        &self,
        children: &[NodeId],
    ) -> Option<(CanonicalCallableIdentity, TypeDescriptor)> {
        // A slice whose call result is projected (`head(xs).count`) is not the call alone: the
        // computed member-projection arm publishes the call and then the projection steps, so this
        // path leaves the slice to that arm instead of emitting the call and dropping the tail.
        if let Some(close) = children.iter().position(|child| {
            self.tree
                .node(*child)
                .is_some_and(|node| node_is_closing_parenthesis(self.tree, node))
        }) && projection_tail_is_step_only(self.tree, children, close.saturating_add(1))
            && postfix_projection_steps(self.tree, children, close.saturating_add(1))
                .is_some_and(|steps| !steps.is_empty())
        {
            return None;
        }
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

/// Whether a list or struct literal inside `node` strictly contains `source`, which makes a call
/// at `source` a member of that literal rather than the call `node` itself performs.
fn aggregate_contains_span(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
    source: &gantry_core::source::SourceSpan,
) -> bool {
    let mut work = node.children().to_vec();
    while let Some(id) = work.pop() {
        let Some(child) = tree.node(id) else {
            continue;
        };
        if matches!(
            child.form(),
            SyntaxForm::ListExpression | SyntaxForm::StructExpression
        ) && child.span() != source
            && source_span_contains(child.span(), source)
        {
            return true;
        }
        work.extend(child.children().iter().copied());
    }
    false
}

/// The value construct one expression denotes at its own level.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ExpressionValue {
    /// The expression's own list literal.
    List(NodeId),
    /// The expression's own struct literal.
    Struct(NodeId),
    /// The comma that carries the expression's own tuple literal.
    Tuple(NodeId),
    /// The node carrying the expression's own `Some`, `Ok`, `Err`, or `None` constructor.
    Constructor(NodeId),
}

/// Returns the construct that owns one expression's result: the aggregate literal or option
/// constructor the expression denotes before any operand nested inside it.
///
/// Only nodes that wrap this value without holding an operand of their own are descended, so a
/// literal reached through a nested operand is not mistaken for the expression's own literal. In
/// `[Item { count: 1 }]` the struct literal belongs to the list element and in
/// `Some(Item { count: 1 })` it belongs to the constructor operand, so neither is the value the
/// enclosing expression must lower.
fn owning_value(tree: &SyntaxTree, root: NodeId) -> Option<ExpressionValue> {
    let mut current = root;
    loop {
        let node = tree.node(current)?;
        if direct_word(tree, node, &["Some", "Ok", "Err", "None"]).is_some() {
            return Some(ExpressionValue::Constructor(current));
        }
        if let Some(literal) = direct_child_form(tree, node, SyntaxForm::StructExpression) {
            return Some(ExpressionValue::Struct(literal));
        }
        if let Some(literal) = direct_child_form(tree, node, SyntaxForm::ListExpression) {
            return Some(ExpressionValue::List(literal));
        }
        if let Some(literal) = direct_child_form(tree, node, SyntaxForm::TupleExpression) {
            return Some(ExpressionValue::Tuple(literal));
        }
        let mut wrapped = semantic_children(tree, current).ok()?;
        match wrapped.pop() {
            Some(only) if wrapped.is_empty() => current = only,
            _ => return None,
        }
    }
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

/// Returns the argument expressions of one call node, excluding its receiver part.
///
/// A grouped receiver spells its inner expression as a direct child of the same node
/// (`(Plain { value: 42 }).greet()`), so taking every direct expression child would count the
/// receiver as one argument; only expressions after the call parenthesis are arguments.
fn call_argument_expressions(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Vec<NodeId> {
    let children = node.children();
    let Some(open) = children.iter().position(|child| {
        tree.node(*child)
            .is_some_and(|child| node_is_call_postfix(tree, child))
    }) else {
        return direct_expressions(tree, node);
    };
    children
        .iter()
        .copied()
        .skip(open.saturating_add(1))
        .filter(|child| {
            tree.node(*child)
                .is_some_and(|child| matches!(child.form(), SyntaxForm::Expression))
        })
        .collect()
}

/// Returns the identifier that names the call one split operand performs.
///
/// The parser splits a receiver call into sibling fragments, so the call's own member is the last
/// identifier the slice spells outside parentheses: an argument or a grouped receiver sits inside
/// a group, and a receiver chain still ends with the member this slice calls. The type phase keys
/// a trait method's recorded call site at that member name rather than at the call sequence.
fn sequence_call_member_span(tree: &SyntaxTree, children: &[NodeId]) -> Option<SourceSpan> {
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
    let mut depth = 0_u64;
    let mut member = None;
    for token in tokens {
        match token.form() {
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis)) => {
                depth = depth.saturating_add(1);
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis)) => {
                depth = depth.saturating_sub(1);
            }
            SyntaxForm::Token(TokenKind::Identifier(_)) if depth == 0 => {
                member = Some(token.span().clone());
            }
            _ => {}
        }
    }
    member
}

/// Returns the index of the parenthesis one closing parenthesis at `close` ends.
fn matching_open_parenthesis(
    tokens: &[&gantry_frontend::SyntaxNode],
    close: usize,
) -> Option<usize> {
    let mut depth = 0_u64;
    for index in (0..=close).rev() {
        let token = tokens.get(index)?;
        if matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
        ) {
            depth = depth.saturating_add(1);
        }
        if matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
        ) {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// Reports whether one opening parenthesis announces a member call.
///
/// A member call is spelled `<receiver> . <member> (`, so the pair is a member call's when the two
/// tokens before the parenthesis are the dot and the member name it names.
fn member_call_parenthesis(tokens: &[&gantry_frontend::SyntaxNode], open: usize) -> bool {
    let Some(member) = open.checked_sub(1).and_then(|index| tokens.get(index)) else {
        return false;
    };
    let Some(dot) = open.checked_sub(2).and_then(|index| tokens.get(index)) else {
        return false;
    };
    matches!(
        member.form(),
        SyntaxForm::Token(TokenKind::Identifier(_) | TokenKind::ReservedWord(_))
    ) && matches!(
        dot.form(),
        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
    )
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
    // The call a slice performs is the member call it names, and that call's closing parenthesis is
    // the last one the slice spells: a receiver containing a call of its own (`[f(1)].len()`) or a
    // grouped receiver that does (`([f(1)]).len()`) spells an inner pair before the member pair, so
    // the pair this slice performs is the one a member name announces. A slice whose last
    // parenthesis is not a member call keeps the token walk below.
    if let Some(closing) = local_tokens.iter().rposition(|token| {
        matches!(
            token.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
        )
    }) && let Some(open) = matching_open_parenthesis(&local_tokens, closing)
        && member_call_parenthesis(&local_tokens, open)
        && let Some(close) = local_tokens.get(closing)
    {
        return SourceSpan::from_portable_parts(
            close.span().source().package_path().as_str(),
            callee.span().bytes().start(),
            close.span().bytes().end(),
        )
        .ok();
    }
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

/// Reports whether one child of a slice sits inside parentheses the slice opens before it.
///
/// The parser hands a call as sibling fragments, so the argument expressions of `f(xs[0])` follow
/// the opening parenthesis as direct children of the same slice. A projection inside those
/// parentheses projects that argument rather than the slice's own value.
fn child_is_inside_call_parentheses(
    tree: &SyntaxTree,
    children: &[NodeId],
    target: NodeId,
) -> bool {
    let mut depth = 0_usize;
    for child in children {
        if *child == target {
            return depth > 0;
        }
        depth = depth.saturating_add(parenthesis_delta(tree, *child));
    }
    false
}

/// Counts the parentheses one subtree opens and does not close.
fn parenthesis_delta(tree: &SyntaxTree, id: NodeId) -> usize {
    let mut opened = 0_usize;
    let mut closed = 0_usize;
    let mut work = vec![id];
    while let Some(id) = work.pop() {
        let Some(node) = tree.node(id) else {
            continue;
        };
        if let SyntaxForm::Token(kind) = node.form() {
            match kind {
                TokenKind::Punctuation(Punctuation::LeftParenthesis) => {
                    opened = opened.saturating_add(1);
                }
                TokenKind::Punctuation(Punctuation::RightParenthesis) => {
                    closed = closed.saturating_add(1);
                }
                _ => {}
            }
        } else {
            work.extend(node.children().iter().copied());
        }
    }
    opened.saturating_sub(closed)
}

/// Reports whether one slice opens with the token that names its callee.
///
/// A slice that opens with a grouping parenthesis spells that group's own expression first, so
/// `(bag()[0]).count` is not a call of `bag` and must not take the call path.
fn slice_opens_with_callee(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    let Some(first) = children.first() else {
        return false;
    };
    let mut work = vec![*first];
    while let Some(id) = work.pop() {
        let Some(node) = tree.node(id) else {
            return false;
        };
        if let SyntaxForm::Token(kind) = node.form() {
            return matches!(kind, TokenKind::Identifier(_))
                || matches!(kind, TokenKind::ReservedWord(word) if word.spelling() == "self");
        }
        work.extend(node.children().iter().rev().copied());
    }
    false
}

/// Reports whether one slice is a single expression node that already is a call.
fn slice_is_call_expression(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    let [only] = children else {
        return false;
    };
    tree.node(*only).is_some_and(|node| {
        matches!(node.form(), SyntaxForm::Expression)
            && sequence_call_site_span(tree, children).is_some()
    })
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
    let tokens = authored_tokens(tree, expression)?;
    let method_dot = call_member_dot(tree, &tokens).or_else(|| {
        tokens.iter().rposition(|id| {
            tree.node(*id).is_some_and(|node| {
                matches!(
                    node.form(),
                    SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
                )
            })
        })
    })?;
    receiver_place_tokens(tree, tokens.get(..method_dot)?)
}

/// Returns the dotted place one receiver-part token sequence names.
///
/// The sequence must be a binding root or `self` followed by zero or more `.field` steps and
/// nothing else, so a computed receiver or an aggregate literal reports no place.
fn receiver_place_tokens(
    tree: &SyntaxTree,
    tokens: &[NodeId],
) -> Option<(Arc<str>, Vec<ValuePathSegment>)> {
    let root = match tree.node(*tokens.first()?)?.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
            Arc::from("self")
        }
        _ => return None,
    };
    let mut path = Vec::new();
    let mut cursor = 1;
    while let Some(token) = tokens.get(cursor) {
        if !matches!(
            tree.node(*token)?.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
        ) {
            return None;
        }
        let SyntaxForm::Token(TokenKind::Identifier(field)) =
            tree.node(*tokens.get(cursor.saturating_add(1))?)?.form()
        else {
            return None;
        };
        path.push(ValuePathSegment::StructField(field.to_string()));
        cursor = cursor.saturating_add(2);
    }
    Some((root, path))
}

/// Returns the place one grouped receiver names.
///
/// A grouping parenthesis is transparent for a receiver call, so `(p).greet()` names the same
/// place `p.greet()` does and every nested group peels before the place is keyed.
fn grouped_method_receiver_place(
    tree: &SyntaxTree,
    node: &gantry_frontend::SyntaxNode,
) -> Option<(Arc<str>, Vec<ValuePathSegment>)> {
    let (inner, _) = grouped_receiver_split(tree, node.children())?;
    let mut current = tree.node(inner)?;
    while let Some((nested, _)) = grouped_receiver_split(tree, current.children()) {
        current = tree.node(nested)?;
    }
    let tokens = authored_tokens(tree, current)?;
    receiver_place_tokens(tree, &tokens)
}

/// Returns every retained token of one expression in authored order.
fn authored_tokens(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
) -> Option<Vec<NodeId>> {
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
            tokens.push(id);
        } else {
            work.extend(node.children().iter().rev().copied());
        }
    }
    Some(tokens)
}

/// Returns the index of the dot naming the member of the call that ends an expression.
///
/// The member identifier sits immediately before the call's own opening parenthesis, and
/// that parenthesis opens the parenthesized group ending at the expression's last token.
/// Counting parenthesis depth backwards therefore finds this call's parenthesis even when
/// an argument is a call of its own, where the last dot of the whole expression belongs to
/// the argument rather than to this call.
fn call_member_dot(tree: &SyntaxTree, tokens: &[NodeId]) -> Option<usize> {
    let mut depth = 0_u64;
    let mut open = None;
    for (index, id) in tokens.iter().enumerate().rev() {
        match tree.node(*id)?.form() {
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis)) => {
                depth = depth.saturating_add(1);
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis)) => {
                if depth == 0 {
                    return None;
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    open = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open?;
    let member = tree.node(*tokens.get(open.checked_sub(1)?)?)?.form();
    if !matches!(member, SyntaxForm::Token(TokenKind::Identifier(_))) {
        return None;
    }
    let dot = open.checked_sub(2)?;
    matches!(
        tree.node(*tokens.get(dot)?)?.form(),
        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot))
    )
    .then_some(dot)
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
        current = match segment {
            ValuePathSegment::StructField(field) => {
                struct_fields.get(&current)?.get(field.as_str())?.clone()
            }
            ValuePathSegment::ListItem(_) => current.immediate_members().into_iter().next()?,
            ValuePathSegment::TupleMember(index) => {
                current.immediate_members().into_iter().nth(*index)?
            }
            _ => return None,
        };
        types.push(current.clone());
    }
    Some(types)
}

/// Returns the type one projection step publishes over the value it reads.
///
/// A field step resolves through the struct fields of the receiver type and a member step through
/// its list element or tuple member, mirroring the fold the place-backed receiver applies to its
/// own path. A step the receiver type does not publish reports no type, so the caller keeps its
/// own arms for the whole chain.
fn projection_step_type(
    receiver: &TypeDescriptor,
    projection: &Projection,
    struct_fields: &BTreeMap<TypeDescriptor, BTreeMap<Arc<str>, TypeDescriptor>>,
) -> Option<TypeDescriptor> {
    match projection {
        Projection::Field(field) => struct_fields
            .get(receiver)
            .and_then(|fields| fields.get(field.as_ref()))
            .cloned(),
        Projection::Member(index) => match receiver.kind() {
            TypeKind::List => receiver.immediate_members().into_iter().next(),
            TypeKind::Tuple => receiver.immediate_members().into_iter().nth(*index),
            _ => None,
        },
        Projection::Payload => None,
    }
}

/// Reports whether one expression is an index projection, directly or through a wrapper.
///
/// The parser sometimes hands an operand one extra single-child node around the projection, and
/// the value-position arms must not read that wrapper as the call its receiver makes: `1 +
/// head(xs)[0]` compiles the projection once instead of the call and then the projection again.
fn is_projection_node(tree: &SyntaxTree, expression: NodeId) -> bool {
    let Some(node) = tree.node(expression) else {
        return false;
    };
    if !binary_operators(tree, node.children()).is_empty() {
        return false;
    }
    if node.children().iter().any(|child| {
        tree.node(*child).is_some_and(|child| {
            matches!(child.form(), SyntaxForm::PostfixExpression)
                && node_contains_punctuation(tree, child, Punctuation::LeftBracket)
        })
    }) {
        return true;
    }
    let [only] = node.children() else {
        return false;
    };
    tree.node(*only)
        .is_some_and(|child| !matches!(child.form(), SyntaxForm::Token(_)))
        && is_projection_node(tree, *only)
}

/// Returns the projection steps one chain applies after `after` of its direct children.
///
/// A child that is not a postfix step belongs to the receiver literal or to a step's own index
/// expression, so this walk skips it; a shape it cannot key reports no steps at all, which keeps
/// the caller's own arm responsible for the whole chain.
fn postfix_projection_steps(
    tree: &SyntaxTree,
    children: &[NodeId],
    after: usize,
) -> Option<Vec<ProjectionChainStep>> {
    let mut steps = Vec::new();
    let mut cursor = after;
    while let Some(child) = children.get(cursor).copied() {
        let step = tree.node(child)?;
        if !matches!(step.form(), SyntaxForm::PostfixExpression) {
            cursor += 1;
            continue;
        }
        if node_contains_punctuation(tree, step, Punctuation::Dot) {
            let member = *children.get(cursor.checked_add(1)?)?;
            let field = projection_member_identifier(tree, member)?;
            steps.push(ProjectionChainStep::Field(field));
            cursor += 2;
            continue;
        }
        if node_contains_punctuation(tree, step, Punctuation::LeftBracket) {
            let index = children
                .iter()
                .copied()
                .skip(cursor.checked_add(1)?)
                .find_map(|child| integer_literal(tree, child))?;
            steps.push(ProjectionChainStep::Member(index));
            cursor += 1;
            continue;
        }
        cursor += 1;
    }
    Some(steps)
}

/// Splits one operand that opens with a grouping parenthesis into its inner expression and the
/// index of the child after the closing parenthesis.
///
/// The parser flattens a grouped receiver into an opening token, one expression, and a closing
/// token, so `(bag()[0]).count` offers its receiver as one whole expression rather than as sibling
/// fragments. A slice that does not open with one completed group reports no split.
fn grouped_receiver_split(tree: &SyntaxTree, children: &[NodeId]) -> Option<(NodeId, usize)> {
    let opening = children.first()?;
    if !matches!(
        tree.node(*opening)?.form(),
        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
    ) {
        return None;
    }
    let inner = *children.get(1)?;
    if !matches!(tree.node(inner)?.form(), SyntaxForm::Expression) {
        return None;
    }
    let close = children.iter().position(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(
                node.form(),
                SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
            )
        })
    })?;
    if close != 2 {
        return None;
    }
    Some((inner, close.saturating_add(1)))
}

/// Reports whether every child after `after` is a projection step rather than a call.
///
/// A tail that opens a call parenthesis belongs to the receiver-call arm, so this walk leaves it
/// alone instead of projecting a field in the place of a method call.
fn projection_tail_is_step_only(tree: &SyntaxTree, children: &[NodeId], after: usize) -> bool {
    !children.iter().skip(after).any(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(node.form(), SyntaxForm::PostfixExpression)
                && node_contains_punctuation(tree, node, Punctuation::LeftParenthesis)
        })
    })
}

/// Reports whether one slice indexes the result of a call with a sibling index postfix.
///
/// The parser flattens a leading call and a top-level index postfix into siblings, so
/// `head(xs)[0]` is one slice that is not the call itself. An index postfix that still has a
/// closing parenthesis after it belongs to a call's argument list instead (`f(xs[0])`), where the
/// slice really is that call, and a slice without a call postfix stays with the other arms.
fn slice_indexes_call_result(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    let Some(index_postfix) = children.iter().position(|child| {
        tree.node(*child).is_some_and(|node| {
            matches!(node.form(), SyntaxForm::PostfixExpression)
                && node_contains_punctuation(tree, node, Punctuation::LeftBracket)
        })
    }) else {
        return false;
    };
    let calls = children
        .get(..index_postfix)
        .unwrap_or_default()
        .iter()
        .any(|child| {
            tree.node(*child).is_some_and(|node| {
                matches!(node.form(), SyntaxForm::PostfixExpression)
                    && node_contains_punctuation(tree, node, Punctuation::LeftParenthesis)
            })
        });
    if !calls {
        return false;
    }
    !children
        .iter()
        .skip(index_postfix.saturating_add(1))
        .any(|child| {
            tree.node(*child).is_some_and(|node| {
                matches!(
                    node.form(),
                    SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
                )
            })
        })
}

/// One step of a postfix projection chain over a binding root.
enum ProjectionChainStep {
    Field(Arc<str>),
    Member(usize),
}

/// Returns the member name one dotted projection step names.
///
/// The parser hands a member name either as its own identifier token or wrapped in one
/// one-expression node, so both spellings resolve to the same field and a step the walk cannot
/// key still reports no steps at all.
fn projection_member_identifier(tree: &SyntaxTree, id: NodeId) -> Option<Arc<str>> {
    let node = tree.node(id)?;
    match node.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => Some(Arc::clone(value)),
        SyntaxForm::Expression | SyntaxForm::BinaryExpression | SyntaxForm::Path => {
            let [inner] = node.children() else {
                return None;
            };
            projection_member_identifier(tree, *inner)
        }
        _ => None,
    }
}

/// Returns the root binding and the ordered steps of one postfix chain over that binding.
///
/// The parser flattens a postfix chain into sibling children, so a receiver part such as
/// `item.values` is not one syntax node: the chain is the flat token sequence from the root binding
/// through every `.field` and `[index]` step. A chain with a grouping parenthesis, a call, or a
/// computed index reports no chain here, so the caller keeps its own arms for those shapes.
fn postfix_projection_chain(
    tree: &SyntaxTree,
    expression: &gantry_frontend::SyntaxNode,
) -> Option<(Arc<str>, Vec<ProjectionChainStep>)> {
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
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
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
    let mut steps = Vec::new();
    let mut cursor = 1;
    while cursor < tokens.len() {
        match tokens.get(cursor)?.form() {
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)) => {
                let SyntaxForm::Token(TokenKind::Identifier(field)) =
                    tokens.get(cursor + 1)?.form()
                else {
                    return None;
                };
                steps.push(ProjectionChainStep::Field(field.clone()));
                cursor += 2;
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftBracket)) => {
                let SyntaxForm::Token(TokenKind::IntegerLiteral(index)) =
                    tokens.get(cursor + 1)?.form()
                else {
                    return None;
                };
                let SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightBracket)) =
                    tokens.get(cursor + 2)?.form()
                else {
                    return None;
                };
                steps.push(ProjectionChainStep::Member(index.parse::<usize>().ok()?));
                cursor += 3;
            }
            _ => return None,
        }
    }
    Some((root, steps))
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

/// Returns the place of a split index-projection operand whose fragments are sibling nodes.
///
/// The analyzer merges the same sibling shape into one projected operand, so lowering loads the
/// root and projects the element each step reads instead of compiling the fragments on their own.
/// Grouping parentheses round the chain or one of its names are skipped exactly as the analyzer's
/// place chain skips them, so `(xs)[0]` and `((xs))[0]` name the same place as `xs[0]`. A
/// parenthesis that opens right after a name calls that name, and a call, a computed index, or a
/// root that is not a binding report no place for the caller's own arms.
fn operand_index_place(
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
    let mut cursor = 0_usize;
    let mut grouping = 0_usize;
    while matches!(
        tokens.get(cursor)?.form(),
        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
    ) {
        grouping = grouping.saturating_add(1);
        cursor = cursor.checked_add(1)?;
    }
    let root = match tokens.get(cursor)?.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
            Arc::from("self")
        }
        _ => return None,
    };
    cursor = cursor.checked_add(1)?;
    let mut path = Vec::new();
    while let Some(token) = tokens.get(cursor) {
        match token.form() {
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis)) => {
                if matches!(
                    tokens.get(cursor.checked_sub(1)?).map(|node| node.form()),
                    Some(SyntaxForm::Token(TokenKind::Identifier(_)))
                ) {
                    return None;
                }
                grouping = grouping.saturating_add(1);
                cursor = cursor.checked_add(1)?;
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis)) => {
                grouping = grouping.checked_sub(1)?;
                cursor = cursor.checked_add(1)?;
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)) => {
                let SyntaxForm::Token(TokenKind::Identifier(field)) =
                    tokens.get(cursor.checked_add(1)?)?.form()
                else {
                    return None;
                };
                path.push(ValuePathSegment::StructField(field.to_string()));
                cursor = cursor.checked_add(2)?;
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftBracket)) => {
                let SyntaxForm::Token(TokenKind::IntegerLiteral(index)) =
                    tokens.get(cursor.checked_add(1)?)?.form()
                else {
                    return None;
                };
                let SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightBracket)) =
                    tokens.get(cursor.checked_add(2)?)?.form()
                else {
                    return None;
                };
                path.push(ValuePathSegment::ListItem(index.parse::<usize>().ok()?));
                cursor = cursor.checked_add(3)?;
            }
            _ => return None,
        }
    }
    (grouping == 0 && !path.is_empty()).then_some((root, path))
}

/// Returns the inner expression of one projection receiver part that is a grouping parenthesis.
///
/// The parser keeps every grouping layer as sibling parenthesis tokens around one expression, and
/// `SPEC.md` keeps `(value)` as grouping, so `(xs)` and `((xs))` name the same receiver. A part
/// whose remaining children are not one expression — a call, a literal, or a comma-separated
/// tuple — reports no inner expression here.
fn grouped_receiver_expression(tree: &SyntaxTree, children: &[NodeId]) -> Option<NodeId> {
    let mut inner = children;
    loop {
        let (Some(open), Some(close)) = (inner.first().copied(), inner.last().copied()) else {
            return None;
        };
        let open = tree.node(open)?;
        let close = tree.node(close)?;
        if !matches!(
            open.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
        ) || !matches!(
            close.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
        ) {
            return None;
        }
        let middle = inner.get(1..inner.len().checked_sub(1)?)?;
        let [only] = middle else {
            inner = middle;
            continue;
        };
        let node = tree.node(*only)?;
        return matches!(node.form(), SyntaxForm::Expression).then_some(*only);
    }
}

/// Receiver selection of one split receiver-call operand.
enum SplitOperandReceiver {
    /// A dotted place named before the call parenthesis.
    Place(Arc<str>, Vec<ValuePathSegment>),
    /// An aggregate constructed before the call parenthesis.
    Constructed(NodeId),
}

/// Receiver selection and argument expressions of one split receiver-call operand.
type SplitReceiverCall = (SplitOperandReceiver, Vec<NodeId>);

/// Splits a leading receiver-call operand into its receiver selection and arguments.
///
/// The parser splits a leading receiver call into sibling fragments: the receiver (a root
/// path with one member postfix plus identifier per member, or a constructed aggregate), the
/// call-parenthesis postfix, one `Expression` per argument, and a boundary node holding the
/// closing `)`. The analyzer types that sibling shape as the callee's result, so lowering
/// resolves the same direct target by the call-site span these fragments reconstruct. Only
/// that exact shape yields a receiver here; anything else falls back to the ordinary child
/// walk.
fn operand_receiver_call_split(
    tree: &SyntaxTree,
    children: &[NodeId],
) -> Option<SplitReceiverCall> {
    let open = children.iter().position(|child| {
        tree.node(*child)
            .is_some_and(|node| node_is_call_postfix(tree, node))
    })?;
    let close = children.len().checked_sub(1)?;
    if close <= open || !node_is_closing_parenthesis(tree, tree.node(*children.get(close)?)?) {
        return None;
    }
    let mut arguments = Vec::new();
    for child in children.get(open.saturating_add(1)..close)? {
        match tree.node(*child)?.form() {
            SyntaxForm::Expression => arguments.push(*child),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Comma)) => {}
            _ => return None,
        }
    }
    let receiver = operand_receiver_selection(tree, children.get(..open)?)?;
    Some((receiver, arguments))
}

/// Resolves the receiver fragment before a split receiver call's parenthesis.
///
/// A dotted receiver roots a named place; any other receiver fragment must construct the
/// aggregate the analyzer admitted, because a receiver that is neither a place nor a
/// construction has no lowering here and its enclosing operand falls back to the child walk.
fn operand_receiver_selection(
    tree: &SyntaxTree,
    receiver: &[NodeId],
) -> Option<SplitOperandReceiver> {
    if let Some((root, path)) = operand_receiver_place(tree, receiver) {
        return Some(SplitOperandReceiver::Place(root, path));
    }
    receiver
        .iter()
        .find_map(|child| {
            let node = tree.node(*child)?;
            matches!(node.form(), SyntaxForm::StructExpression)
                .then_some(*child)
                .or_else(|| descendant_form(tree, *child, &[SyntaxForm::StructExpression]))
        })
        .map(SplitOperandReceiver::Constructed)
}

/// Returns the dotted place named before a split receiver call's parenthesis.
fn operand_receiver_place(
    tree: &SyntaxTree,
    receiver: &[NodeId],
) -> Option<(Arc<str>, Vec<ValuePathSegment>)> {
    let mut tokens = Vec::new();
    let mut work = receiver.iter().rev().copied().collect::<Vec<_>>();
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
    let mut cursor = 0_usize;
    let mut grouping = 0_usize;
    while matches!(
        tokens.get(cursor)?.form(),
        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis))
    ) {
        grouping = grouping.saturating_add(1);
        cursor = cursor.checked_add(1)?;
    }
    let root = match tokens.get(cursor)?.form() {
        SyntaxForm::Token(TokenKind::Identifier(value)) => value.clone(),
        SyntaxForm::Token(TokenKind::ReservedWord(word)) if word.spelling() == "self" => {
            Arc::from("self")
        }
        _ => return None,
    };
    cursor = cursor.checked_add(1)?;
    let mut path = Vec::new();
    while cursor < method_dot {
        match tokens.get(cursor)?.form() {
            // A parenthesis that opens right after a name calls that name, so the receiver is a
            // computed value rather than the place this walk keys.
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::LeftParenthesis)) => {
                if matches!(
                    tokens.get(cursor.checked_sub(1)?).map(|node| node.form()),
                    Some(SyntaxForm::Token(TokenKind::Identifier(_)))
                ) {
                    return None;
                }
                grouping = grouping.saturating_add(1);
                cursor = cursor.checked_add(1)?;
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis)) => {
                grouping = grouping.checked_sub(1)?;
                cursor = cursor.checked_add(1)?;
            }
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Dot)) => {
                let SyntaxForm::Token(TokenKind::Identifier(field)) =
                    tokens.get(cursor.checked_add(1)?)?.form()
                else {
                    return None;
                };
                path.push(ValuePathSegment::StructField(field.to_string()));
                cursor = cursor.saturating_add(2);
            }
            _ => return None,
        }
    }
    (grouping == 0).then_some((root, path))
}

fn node_is_dot_postfix(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    matches!(node.form(), SyntaxForm::PostfixExpression)
        && node_contains_punctuation(tree, node, Punctuation::Dot)
}

fn node_is_call_postfix(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    matches!(node.form(), SyntaxForm::PostfixExpression)
        && node_contains_punctuation(tree, node, Punctuation::LeftParenthesis)
}

fn node_is_closing_parenthesis(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    matches!(
        node.form(),
        SyntaxForm::Token(TokenKind::Punctuation(Punctuation::RightParenthesis))
    ) || node_contains_punctuation(tree, node, Punctuation::RightParenthesis)
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
    binary_operators(tree, children).into_iter().last()
}

/// Returns every binary operator token in one operand slice in source order.
///
/// The parser appends an operator and its right operand to the same expression node while
/// the operator precedence stays at or above the chain's minimum, so one slice can hold
/// several operators that must be folded left to right.
fn binary_operators(tree: &SyntaxTree, children: &[NodeId]) -> Vec<(Punctuation, usize)> {
    children
        .iter()
        .enumerate()
        .filter_map(|(index, child)| match tree.node(*child)?.form() {
            SyntaxForm::Token(TokenKind::Punctuation(value)) if is_binary_operator(*value) => {
                Some((*value, index))
            }
            _ => None,
        })
        .collect()
}

/// Returns the single non-token child of one operator-free wrapper node.
///
/// The parser leaves a `BinaryExpression` wrapper holding no operator token around one operand
/// when a chain folds around it, and the wrapped operand may be an expression node or a literal
/// token; only the expression form carries a child the sequence walk can compile in the
/// wrapper's place.
fn single_wrapped_node(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> Option<NodeId> {
    let mut children = node.children().iter().copied().filter(|child| {
        tree.node(*child)
            .is_some_and(|child| !matches!(child.form(), SyntaxForm::Token(_)))
    });
    let only = children.next()?;
    children.next().is_none().then_some(only)
}

/// Reports whether one node holds only grouping parenthesis boundary tokens.
///
/// A leading parenthesized operand keeps its parentheses as sibling children of the
/// enclosing operator chain, and the parser wraps the closing token in a node with no
/// operand of its own. Such boundary nodes publish no value, so operand compilation skips
/// them. A lone `()` literal stays its slice's only valued child and is still compiled.
fn is_parenthesis_boundary(tree: &SyntaxTree, node: &gantry_frontend::SyntaxNode) -> bool {
    let mut boundary = false;
    for child in node.children() {
        let Some(child) = tree.node(*child) else {
            return false;
        };
        if !matches!(
            child.form(),
            SyntaxForm::Token(TokenKind::Punctuation(
                Punctuation::LeftParenthesis | Punctuation::RightParenthesis
            ))
        ) {
            return false;
        }
        boundary = true;
    }
    boundary
}

/// Reports whether one operand slice carries a split field-projection fragment.
///
/// The parser emits a sibling `PostfixExpression` holding the projection dot when it
/// splits a leading dotted operand. That fragment cannot be compiled on its own, so its
/// slice is compiled structurally instead of through the child walk.
fn carries_split_projection(tree: &SyntaxTree, children: &[NodeId]) -> bool {
    children.iter().any(|child| {
        tree.node(*child)
            .is_some_and(|node| node_is_dot_postfix(tree, node))
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

/// Returns the constant one logical operator leaves when its left operand decides.
///
/// `&&` decides `false` and `||` decides `true`, so the arm that skips the remaining operands
/// needs no operand value after the branch has consumed the left one.
fn logical_constant(value: Punctuation) -> Option<bool> {
    match value {
        Punctuation::AndAnd => Some(false),
        Punctuation::OrOr => Some(true),
        _ => None,
    }
}

/// Reports whether one punctuation token is a binary operator of this lowering.
///
/// `&&` and `||` are binary operators with a dedicated short-circuit lowering, so they take
/// part in chain detection even though `primitive_for_binary` has no eager primitive for them.
fn is_binary_operator(value: Punctuation) -> bool {
    primitive_for_binary(value).is_some() || logical_constant(value).is_some()
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

/// Returns the value and type one literal token publishes.
///
/// A token-level walk serves the operand path, where a literal receiver arrives as a fragment
/// rather than as a node of its own.
fn literal_token(
    tree: &SyntaxTree,
    token: NodeId,
) -> Result<Option<(LogicalValue, TypeDescriptor)>, AnalysisError> {
    let Some(node) = tree.node(token) else {
        return Ok(None);
    };
    let value = match node.form() {
        SyntaxForm::Token(TokenKind::IntegerLiteral(value)) => value
            .parse::<i64>()
            .ok()
            .and_then(GantryInt::new)
            .map(|value| (LogicalValue::integer(value), TypeDescriptor::INT)),
        SyntaxForm::Token(TokenKind::FloatLiteral(value)) => value
            .parse::<f64>()
            .ok()
            .and_then(GantryFloat::new)
            .map(|value| (LogicalValue::float(value), TypeDescriptor::FLOAT)),
        SyntaxForm::Token(TokenKind::StringLiteral(value) | TokenKind::RawStringLiteral(value)) => {
            Some((
                LogicalValue::string(value.to_string(), DEFAULT_VALUE_LIMITS)
                    .map_err(|_| AnalysisError::Invariant)?,
                TypeDescriptor::STRING,
            ))
        }
        SyntaxForm::Token(TokenKind::ReservedWord(word)) => match word.spelling() {
            "true" => Some((LogicalValue::boolean(true), TypeDescriptor::BOOL)),
            "false" => Some((LogicalValue::boolean(false), TypeDescriptor::BOOL)),
            _ => None,
        },
        _ => None,
    };
    Ok(value)
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

fn is_wildcard_arm(tree: &SyntaxTree, arm: NodeId) -> bool {
    descendant_pattern_tokens(tree, arm).any(|node| {
        matches!(
            node.form(),
            SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Underscore))
        )
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
