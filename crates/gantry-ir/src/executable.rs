//! Indexed executable program contracts consumed by the transition machine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::generated::{Effect, OperationSiteKind, RecoveryClass};
use crate::{
    ActionParameter, CanonicalCallableIdentity, CanonicalPath, CanonicalSignature, EffectSet,
    StructuralPosition, TypeDescriptor,
};
use gantry_core::value::{LogicalValue, ValuePathSegment};

use crate::Primitive;

/// Analyzer-resolved action metadata retained by one executable operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableAction {
    /// Canonical declared action path.
    pub path: CanonicalPath,
    /// Canonical declaration signature.
    pub signature: CanonicalSignature,
    /// Declared recovery class.
    pub recovery: RecoveryClass,
    /// Declaration-order typed parameters.
    pub parameters: Vec<ActionParameter>,
}

/// Typed semantic metadata for one executable integration operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableOperation {
    /// Prompt, decision, or harness-action classification.
    pub kind: OperationSiteKind,
    /// Exact successful operation result type before optional `attempt` wrapping.
    pub result_type: TypeDescriptor,
    /// Action-specific metadata, present only for an action invocation.
    pub action: Option<ExecutableAction>,
    /// Decoded prompt-template literal segments in source order.
    pub template_segments: Vec<Arc<str>>,
    /// Static types of interpolation inputs in source order.
    pub interpolation_types: Vec<TypeDescriptor>,
    /// Named model-input names in source order.
    pub named_input_names: Vec<Arc<str>>,
    /// Static types of named model inputs in source order.
    pub named_input_types: Vec<TypeDescriptor>,
    /// Optional source-level validation retry override.
    pub retry_limit: Option<u64>,
    /// Optional model session directive (`inline`, `fork`, or `new`).
    pub session_mode: Option<Arc<str>>,
    /// Whether source wraps this operation in `attempt`.
    pub attempted: bool,
}

/// One analyzed workflow parameter copied into a fresh local root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameter {
    /// Exact source binding name.
    pub name: Arc<str>,
    /// Exact analyzed parameter type.
    pub ty: TypeDescriptor,
    /// Whether the callee-local root may be replaced.
    pub mutable: bool,
}

/// Stable identity of one independently executable spawned block.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskBodyIdentity {
    enclosing_callable: CanonicalCallableIdentity,
    spawn_site: StructuralPosition,
}

impl TaskBodyIdentity {
    /// Binds one canonical spawn site to its analyzer-selected closed callable.
    #[must_use]
    pub const fn new(
        enclosing_callable: CanonicalCallableIdentity,
        spawn_site: StructuralPosition,
    ) -> Self {
        Self {
            enclosing_callable,
            spawn_site,
        }
    }

    /// Returns the closed callable containing this spawned block.
    #[must_use]
    pub const fn enclosing_callable(&self) -> &CanonicalCallableIdentity {
        &self.enclosing_callable
    }

    /// Returns the canonical spawn site within the enclosing callable.
    #[must_use]
    pub const fn spawn_site(&self) -> &StructuralPosition {
        &self.spawn_site
    }
}

/// One analyzer-selected binding copied into a spawned task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableTaskCapture {
    name: Arc<str>,
    ty: TypeDescriptor,
    mutable: bool,
}

impl ExecutableTaskCapture {
    /// Constructs one typed capture contract.
    pub fn new(name: Arc<str>, ty: TypeDescriptor, mutable: bool) -> Result<Self, ProgramError> {
        if name.is_empty() {
            return Err(ProgramError::InvalidTaskCaptureName);
        }
        Ok(Self { name, ty, mutable })
    }

    /// Returns the exact captured binding name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the analyzer-proven closed binding type.
    #[must_use]
    pub const fn ty(&self) -> &TypeDescriptor {
        &self.ty
    }

    /// Returns whether the child-local copied root may be replaced.
    #[must_use]
    pub const fn is_mutable(&self) -> bool {
        self.mutable
    }
}

/// One source task handle retained outside the logical value domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableTaskHandle {
    name: Arc<str>,
    result_type: TypeDescriptor,
}

impl ExecutableTaskHandle {
    /// Constructs one typed lexical task-handle declaration.
    pub fn new(name: Arc<str>, result_type: TypeDescriptor) -> Result<Self, ProgramError> {
        if name.is_empty() {
            return Err(ProgramError::InvalidTaskHandleName);
        }
        Ok(Self { name, result_type })
    }

    /// Returns the exact lexical source name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared child result type.
    #[must_use]
    pub const fn result_type(&self) -> &TypeDescriptor {
        &self.result_type
    }
}

/// Closed v1 context contract applied when a spawned task is materialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableTaskContext {
    inherit_agent: bool,
    snapshot_active_session: bool,
    fork_session: bool,
    derive_task_path: bool,
    derive_recovery_identity: bool,
}

impl ExecutableTaskContext {
    /// Returns the only v1 spawned-task context policy.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            inherit_agent: true,
            snapshot_active_session: true,
            fork_session: true,
            derive_task_path: true,
            derive_recovery_identity: true,
        }
    }

    /// Returns whether the active agent is copied from the parent.
    #[must_use]
    pub const fn inherits_agent(self) -> bool {
        self.inherit_agent
    }

    /// Returns whether the parent's active session is captured at spawn.
    #[must_use]
    pub const fn snapshots_active_session(self) -> bool {
        self.snapshot_active_session
    }

    /// Returns whether the child receives a forked enclosing session.
    #[must_use]
    pub const fn forks_session(self) -> bool {
        self.fork_session
    }

    /// Returns whether a canonical dynamic task path is derived at spawn.
    #[must_use]
    pub const fn derives_task_path(self) -> bool {
        self.derive_task_path
    }

    /// Returns whether task recovery uses a stable derived identity.
    #[must_use]
    pub const fn derives_recovery_identity(self) -> bool {
        self.derive_recovery_identity
    }
}

/// One independently executable spawned block with its own return boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableTaskBody {
    identity: TaskBodyIdentity,
    result_type: TypeDescriptor,
    captures: Vec<ExecutableTaskCapture>,
    context: ExecutableTaskContext,
    instructions: Vec<Instruction>,
}

impl ExecutableTaskBody {
    /// Constructs one task body and validates its local canonical shape.
    pub fn new(
        identity: TaskBodyIdentity,
        result_type: TypeDescriptor,
        captures: Vec<ExecutableTaskCapture>,
        context: ExecutableTaskContext,
        instructions: Vec<Instruction>,
    ) -> Result<Self, ProgramError> {
        if captures
            .iter()
            .map(ExecutableTaskCapture::name)
            .collect::<BTreeSet<_>>()
            .len()
            != captures.len()
        {
            return Err(ProgramError::InvalidTaskBody(identity));
        }
        if instructions.is_empty()
            || instructions
                .windows(2)
                .any(|pair| pair[0].site >= pair[1].site)
            || instructions.iter().any(|instruction| {
                matches!(instruction.kind, InstructionKind::Return)
                    || matches!(instruction.kind, InstructionKind::TaskComplete)
                        && instruction.ty != result_type
            })
        {
            return Err(ProgramError::InvalidTaskBody(identity));
        }
        Ok(Self {
            identity,
            result_type,
            captures,
            context,
            instructions,
        })
    }

    /// Returns the stable closed body identity.
    #[must_use]
    pub const fn identity(&self) -> &TaskBodyIdentity {
        &self.identity
    }

    /// Returns the declared task result type.
    #[must_use]
    pub const fn result_type(&self) -> &TypeDescriptor {
        &self.result_type
    }

    /// Returns captures in analyzer-selected deterministic order.
    #[must_use]
    pub fn captures(&self) -> &[ExecutableTaskCapture] {
        &self.captures
    }

    /// Returns the v1 inherited-context contract.
    #[must_use]
    pub const fn context(&self) -> &ExecutableTaskContext {
        &self.context
    }

    /// Returns task-local instructions in canonical structural order.
    #[must_use]
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }
}

/// Task-control boundary at which one task must await coordinator work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskSuspension {
    /// Child creation and owned executor submission remain pending.
    Spawn {
        /// Lexical handle to publish after submission settles.
        handle: ExecutableTaskHandle,
        /// Independently executable child body.
        body: TaskBodyIdentity,
    },
    /// Named all-settled task wait.
    Join {
        /// Handles consumed in source order.
        handles: Vec<Arc<str>>,
    },
    /// Declaration-order all-settled task wait, including the empty case.
    JoinAll {
        /// Handles consumed in declaration order.
        handles: Vec<Arc<str>>,
    },
    /// Background ownership transfer remains pending at the coordinator.
    Detach {
        /// Exact lexical handle consumed by the transfer.
        handle: Arc<str>,
    },
}

/// Coordinator result that allows suspended task control to continue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCompletion {
    /// Child submission settled and its attached handle is now visible.
    Spawned {
        /// Published lexical handle.
        handle: ExecutableTaskHandle,
    },
    /// A named join settled in source order.
    Joined {
        /// Consumed lexical handle names.
        handles: Vec<Arc<str>>,
    },
    /// A joinall settled in declaration order.
    JoinedAll {
        /// Consumed lexical handle names.
        handles: Vec<Arc<str>>,
    },
    /// Ownership transferred to execution-owned background work.
    Detached {
        /// Consumed lexical handle name.
        handle: Arc<str>,
    },
}

/// Aggregate construction performed after every operand has completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateKind {
    /// Ordered homogeneous List construction.
    List,
    /// Fixed-arity Tuple construction.
    Tuple,
    /// Complete declared Struct construction in declaration-field order.
    Struct {
        /// Canonical declared type name.
        type_name: Arc<str>,
        /// Field names corresponding to stack operands.
        fields: Vec<Arc<str>>,
    },
    /// Declared Enum construction.
    Enum {
        /// Canonical declared type name.
        type_name: Arc<str>,
        /// Selected variant.
        variant: Arc<str>,
        /// Whether one payload operand is required.
        has_payload: bool,
    },
    /// Present Option construction.
    Some,
    /// Absent Option construction.
    None,
    /// Successful Result construction.
    Ok,
    /// Error Result construction.
    Err,
}

/// Deterministic projection from one already evaluated value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Projection {
    /// List or Tuple member.
    Member(usize),
    /// Named Struct field.
    Field(Arc<str>),
    /// Enum, Option, or Result payload.
    Payload,
}

/// Dynamic loop path phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LoopPhase {
    /// Condition evaluation.
    Condition,
    /// Body execution; this phase charges loop limits and budgets.
    Body,
}

/// One low-level instruction in deterministic semantic order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstructionKind {
    /// Push one immutable normalized value.
    Push(LogicalValue),
    /// Copy one visible binding onto the value stack.
    Load(Arc<str>),
    /// Atomically introduce one binding after its initializer is complete.
    Bind {
        /// Exact binding name.
        name: Arc<str>,
        /// Exact analyzed binding type.
        ty: TypeDescriptor,
        /// Whether later root replacement is permitted.
        mutable: bool,
    },
    /// Atomically replace one complete mutable root.
    Assign {
        /// Root binding name.
        name: Arc<str>,
        /// Nested path copied before publication.
        path: Vec<ValuePathSegment>,
        /// Exact analyzed type of the replacement expression.
        target_type: TypeDescriptor,
    },
    /// Discard one completed value.
    Pop,
    /// Construct one complete aggregate from the reported number of operands.
    Aggregate {
        /// Aggregate shape.
        kind: AggregateKind,
        /// Number of values consumed in left-to-right order.
        operands: usize,
    },
    /// Project from one completed value.
    Project(Projection),
    /// Apply one deterministic primitive to completed operands.
    Primitive(Primitive),
    /// Enter one nested lexical scope.
    EnterScope,
    /// Leave the innermost lexical scope.
    ExitScope,
    /// Jump to one instruction in the current workflow.
    Jump(usize),
    /// Select one branch from a Bool or Decision and record its dynamic arm.
    Branch {
        /// Program counter for the true arm.
        when_true: usize,
        /// Program counter for the false arm.
        when_false: usize,
    },
    /// Select an Option arm and expose the present payload to that arm.
    BranchOption {
        /// Program counter for the `Some` arm.
        when_some: usize,
        /// Program counter for the `None` arm.
        when_none: usize,
    },
    /// Select one analyzer-validated declared-enum arm by exact variant name.
    BranchEnum {
        /// Distinct variant names and their arm program counters in source order.
        arms: Vec<(Arc<str>, usize)>,
    },
    /// Enter one dynamic loop condition or body occurrence.
    EnterLoop {
        /// Condition or body phase.
        phase: LoopPhase,
        /// Optional source body-entry limit; valid only for `Body`.
        source_limit: Option<u64>,
    },
    /// Leave the latest branch or loop occurrence frame.
    LeaveOccurrence,
    /// Call one workflow with the reported number of stack arguments.
    Call {
        /// Analyzer-selected closed callee identity.
        callee: CanonicalCallableIdentity,
        /// Number of completed arguments.
        arguments: usize,
    },
    /// Return one completed value from the current workflow frame.
    Return,
    /// Suspend while creating and submitting one independently executable child.
    Spawn {
        /// Lexical handle introduced after submission settles.
        handle: ExecutableTaskHandle,
        /// Closed independently executable body.
        body: TaskBodyIdentity,
    },
    /// Consume named handles and suspend for all-settled results.
    Join {
        /// Exact source-order lexical handle names.
        handles: Vec<Arc<str>>,
    },
    /// Consume all selected handles and suspend for declaration-order results.
    JoinAll {
        /// Exact declaration-order lexical handle names, possibly empty.
        handles: Vec<Arc<str>>,
    },
    /// Transfer one attached handle to execution-owned background work.
    Detach {
        /// Exact lexical handle name.
        handle: Arc<str>,
    },
    /// Complete the current spawned body rather than a workflow frame.
    TaskComplete,
    /// Prepare one logical operation that has no evaluated input values.
    Operation,
    /// Prepare one logical operation after capturing its completed input values.
    OperationWithOperands {
        /// Number of left-to-right values retained for immutable request capture.
        operands: usize,
    },
    /// Prepare one analyzer-resolved hook operation after capturing its input values.
    OperationCall {
        /// Complete static operation metadata.
        operation: ExecutableOperation,
        /// Number of left-to-right values retained for immutable request capture.
        operands: usize,
    },
    /// Enter one active-agent dynamic scope.
    EnterAgent(Arc<str>),
    /// Restore the prior active agent.
    ExitAgent,
    /// Enter one active-session dynamic scope.
    EnterSession(Arc<str>),
    /// Restore the prior active session.
    ExitSession,
    /// Explicit cooperative cancellation checkpoint.
    CancellationCheck,
}

/// One instruction tied to its canonical structural site and result type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    /// Canonical structural position independent of source bytes.
    pub site: StructuralPosition,
    /// Static result type retained for traces and operation results.
    pub ty: TypeDescriptor,
    /// Executable operation.
    pub kind: InstructionKind,
}

/// One indexed analyzed workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Workflow {
    /// Canonical workflow path.
    pub path: CanonicalPath,
    /// Declaration-order parameters.
    pub parameters: Vec<Parameter>,
    /// Declared result type.
    pub result: TypeDescriptor,
    /// Transitive analyzed effects.
    pub effects: EffectSet,
    /// Linearized explicit-frame instructions.
    pub instructions: Vec<Instruction>,
}

/// One immutable indexed program for the task-neutral machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineProgram {
    workflows: Vec<Workflow>,
    callable_identities: Vec<CanonicalCallableIdentity>,
    callable_indexes: BTreeMap<CanonicalCallableIdentity, usize>,
    entry_indexes: BTreeMap<CanonicalPath, usize>,
    task_bodies: Vec<ExecutableTaskBody>,
    task_body_indexes: BTreeMap<TaskBodyIdentity, usize>,
}

impl MachineProgram {
    /// Validates canonical workflow order, instruction targets, and call seams.
    pub fn new(workflows: Vec<Workflow>) -> Result<Self, ProgramError> {
        let callables = workflows
            .into_iter()
            .map(|workflow| {
                (
                    CanonicalCallableIdentity::free(&workflow.path, &[]),
                    workflow,
                )
            })
            .collect();
        Self::with_callable_identities(callables)
    }

    /// Validates a program whose analyzer assigned every closed callable identity.
    pub fn with_callable_identities(
        callables: Vec<(CanonicalCallableIdentity, Workflow)>,
    ) -> Result<Self, ProgramError> {
        Self::with_task_bodies(callables, Vec::new())
    }

    /// Validates closed callables together with independently executable task bodies.
    pub fn with_task_bodies(
        callables: Vec<(CanonicalCallableIdentity, Workflow)>,
        task_bodies: Vec<ExecutableTaskBody>,
    ) -> Result<Self, ProgramError> {
        if callables.is_empty() {
            return Err(ProgramError::EmptyProgram);
        }
        if callables.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(ProgramError::WorkflowOrder);
        }
        if task_bodies
            .windows(2)
            .any(|pair| pair[0].identity >= pair[1].identity)
        {
            return Err(ProgramError::TaskBodyOrder);
        }
        let callable_identities = callables
            .iter()
            .map(|(identity, _)| identity.clone())
            .collect::<Vec<_>>();
        let workflows = callables
            .into_iter()
            .map(|(_, workflow)| workflow)
            .collect::<Vec<_>>();
        let callable_indexes = callable_identities
            .iter()
            .enumerate()
            .map(|(index, identity)| (identity.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let entry_indexes = workflows
            .iter()
            .enumerate()
            .filter(|(index, workflow)| {
                callable_identities[*index] == CanonicalCallableIdentity::free(&workflow.path, &[])
            })
            .map(|(index, workflow)| (workflow.path.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let task_body_indexes = task_bodies
            .iter()
            .enumerate()
            .map(|(index, body)| (body.identity.clone(), index))
            .collect::<BTreeMap<_, _>>();
        for (identity, workflow) in callable_identities.iter().zip(&workflows) {
            validate_workflow(
                identity,
                workflow,
                &workflows,
                &callable_indexes,
                &task_bodies,
                &task_body_indexes,
            )?;
        }
        for body in &task_bodies {
            validate_task_body(
                body,
                &workflows,
                &callable_indexes,
                &task_bodies,
                &task_body_indexes,
            )?;
        }
        let mut task_body_references = BTreeMap::<&TaskBodyIdentity, usize>::new();
        for instruction in workflows
            .iter()
            .flat_map(|workflow| &workflow.instructions)
            .chain(
                task_bodies
                    .iter()
                    .flat_map(ExecutableTaskBody::instructions),
            )
        {
            if let InstructionKind::Spawn { body, .. } = &instruction.kind {
                *task_body_references.entry(body).or_default() += 1;
            }
        }
        if task_bodies.iter().any(|body| {
            task_body_references
                .get(body.identity())
                .copied()
                .unwrap_or_default()
                != 1
        }) {
            return Err(ProgramError::TaskBodyReference);
        }
        Ok(Self {
            workflows,
            callable_identities,
            callable_indexes,
            entry_indexes,
            task_bodies,
            task_body_indexes,
        })
    }

    /// Returns workflows in the same canonical callable-identity order as
    /// [`Self::callable_identities`].
    #[must_use]
    pub fn workflows(&self) -> &[Workflow] {
        &self.workflows
    }

    /// Returns closed callable identities in the same order as [`Self::workflows`].
    #[must_use]
    pub fn callable_identities(&self) -> &[CanonicalCallableIdentity] {
        &self.callable_identities
    }

    /// Resolves one canonical workflow.
    #[must_use]
    pub fn workflow(&self, path: &CanonicalPath) -> Option<&Workflow> {
        self.entry_indexes
            .get(path)
            .and_then(|index| self.workflows.get(*index))
    }

    /// Resolves one analyzer-selected closed callable identity.
    #[must_use]
    pub fn callable(&self, identity: &CanonicalCallableIdentity) -> Option<&Workflow> {
        self.callable_indexes
            .get(identity)
            .and_then(|index| self.workflows.get(*index))
    }

    /// Returns the stable index of one canonical workflow in this program.
    #[must_use]
    pub fn workflow_index(&self, path: &CanonicalPath) -> Option<usize> {
        self.entry_indexes.get(path).copied()
    }

    /// Returns the stable index of one closed callable identity.
    #[must_use]
    pub fn callable_index(&self, identity: &CanonicalCallableIdentity) -> Option<usize> {
        self.callable_indexes.get(identity).copied()
    }

    /// Returns spawned task bodies in canonical identity order.
    #[must_use]
    pub fn task_bodies(&self) -> &[ExecutableTaskBody] {
        &self.task_bodies
    }

    /// Resolves one independently executable spawned body.
    #[must_use]
    pub fn task_body(&self, identity: &TaskBodyIdentity) -> Option<&ExecutableTaskBody> {
        self.task_body_indexes
            .get(identity)
            .and_then(|index| self.task_bodies.get(*index))
    }

    /// Returns the first reachable effect unsupported by the base sequential profile.
    #[must_use]
    pub fn unsupported_effect(&self, root: usize) -> Option<Effect> {
        let mut pending = vec![root];
        let mut visited = BTreeSet::new();
        while let Some(index) = pending.pop() {
            if !visited.insert(index) {
                continue;
            }
            let workflow = &self.workflows[index];
            for effect in workflow.effects.iter() {
                if matches!(effect, Effect::Spawn | Effect::Join | Effect::Background) {
                    return Some(effect);
                }
            }
            for instruction in &workflow.instructions {
                if let InstructionKind::Call { callee, .. } = &instruction.kind
                    && let Some(index) = self.callable_index(callee)
                {
                    pending.push(index);
                }
            }
        }
        None
    }
}

/// Rejection of malformed executable IR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramError {
    /// No workflow was supplied.
    EmptyProgram,
    /// Workflow paths are duplicated or not canonical-order sorted.
    WorkflowOrder,
    /// One workflow has no executable instructions.
    EmptyWorkflow(CanonicalPath),
    /// A parameter or binding name is empty or duplicated.
    InvalidBinding(CanonicalPath),
    /// Instruction structural sites are duplicated or not ordered.
    InstructionOrder(CanonicalPath),
    /// A jump target is outside its workflow.
    InvalidTarget(CanonicalPath),
    /// A call references no workflow or has the wrong arity.
    InvalidCall(CanonicalPath),
    /// Aggregate metadata and operand count disagree.
    InvalidAggregate(CanonicalPath),
    /// A source loop limit is zero or attached to a condition phase.
    InvalidLoopLimit(CanonicalPath),
    /// Spawned bodies are duplicated or not in canonical identity order.
    TaskBodyOrder,
    /// One spawned body has malformed local metadata or instructions.
    InvalidTaskBody(TaskBodyIdentity),
    /// One spawned body is orphaned or referenced by more than one spawn site.
    TaskBodyReference,
    /// A task-control instruction has invalid handles or body correspondence.
    InvalidTaskControl(CanonicalPath),
    /// One task capture name is empty.
    InvalidTaskCaptureName,
    /// One lexical task-handle name is empty.
    InvalidTaskHandleName,
}

fn validate_workflow(
    identity: &CanonicalCallableIdentity,
    workflow: &Workflow,
    workflows: &[Workflow],
    indexes: &BTreeMap<CanonicalCallableIdentity, usize>,
    task_bodies: &[ExecutableTaskBody],
    task_body_indexes: &BTreeMap<TaskBodyIdentity, usize>,
) -> Result<(), ProgramError> {
    if workflow.instructions.is_empty() {
        return Err(ProgramError::EmptyWorkflow(workflow.path.clone()));
    }
    let mut names = BTreeSet::new();
    if workflow
        .parameters
        .iter()
        .any(|parameter| parameter.name.is_empty() || !names.insert(parameter.name.as_ref()))
    {
        return Err(ProgramError::InvalidBinding(workflow.path.clone()));
    }
    if workflow
        .instructions
        .windows(2)
        .any(|pair| pair[0].site >= pair[1].site)
    {
        return Err(ProgramError::InstructionOrder(workflow.path.clone()));
    }
    let length = workflow.instructions.len();
    if workflow
        .instructions
        .iter()
        .any(|instruction| matches!(instruction.kind, InstructionKind::TaskComplete))
    {
        return Err(ProgramError::InvalidTaskControl(workflow.path.clone()));
    }
    for instruction in &workflow.instructions {
        validate_instruction(
            identity,
            &workflow.path,
            instruction,
            length,
            workflows,
            indexes,
            task_bodies,
            task_body_indexes,
        )?;
    }
    Ok(())
}

fn validate_task_body(
    body: &ExecutableTaskBody,
    workflows: &[Workflow],
    indexes: &BTreeMap<CanonicalCallableIdentity, usize>,
    task_bodies: &[ExecutableTaskBody],
    task_body_indexes: &BTreeMap<TaskBodyIdentity, usize>,
) -> Result<(), ProgramError> {
    let Some(workflow) = indexes
        .get(body.identity.enclosing_callable())
        .and_then(|index| workflows.get(*index))
    else {
        return Err(ProgramError::InvalidTaskBody(body.identity.clone()));
    };
    let workflow = &workflow.path;
    let length = body.instructions.len();
    for instruction in &body.instructions {
        if matches!(instruction.kind, InstructionKind::Return) {
            return Err(ProgramError::InvalidTaskBody(body.identity.clone()));
        }
        validate_instruction(
            body.identity.enclosing_callable(),
            workflow,
            instruction,
            length,
            workflows,
            indexes,
            task_bodies,
            task_body_indexes,
        )
        .map_err(|_| ProgramError::InvalidTaskBody(body.identity.clone()))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_instruction(
    enclosing_callable: &CanonicalCallableIdentity,
    workflow: &CanonicalPath,
    instruction: &Instruction,
    length: usize,
    workflows: &[Workflow],
    indexes: &BTreeMap<CanonicalCallableIdentity, usize>,
    task_bodies: &[ExecutableTaskBody],
    task_body_indexes: &BTreeMap<TaskBodyIdentity, usize>,
) -> Result<(), ProgramError> {
    match &instruction.kind {
        InstructionKind::Jump(target)
        | InstructionKind::Branch {
            when_true: target, ..
        }
        | InstructionKind::BranchOption {
            when_some: target, ..
        } if *target >= length => {
            return Err(ProgramError::InvalidTarget(workflow.clone()));
        }
        InstructionKind::Branch { when_false, .. } if *when_false >= length => {
            return Err(ProgramError::InvalidTarget(workflow.clone()));
        }
        InstructionKind::BranchOption { when_none, .. } if *when_none >= length => {
            return Err(ProgramError::InvalidTarget(workflow.clone()));
        }
        InstructionKind::BranchEnum { arms }
            if arms.is_empty()
                || arms
                    .iter()
                    .any(|(variant, target)| variant.is_empty() || *target >= length)
                || !enum_arms_are_unique(arms) =>
        {
            return Err(ProgramError::InvalidTarget(workflow.clone()));
        }
        InstructionKind::Call { callee, arguments } => {
            let Some(callee) = indexes.get(callee).and_then(|index| workflows.get(*index)) else {
                return Err(ProgramError::InvalidCall(workflow.clone()));
            };
            if *arguments != callee.parameters.len() {
                return Err(ProgramError::InvalidCall(workflow.clone()));
            }
        }
        InstructionKind::Aggregate { kind, operands } => {
            let valid = match kind {
                AggregateKind::List => true,
                AggregateKind::Tuple => *operands >= 2,
                AggregateKind::Struct { type_name, fields } => {
                    !type_name.is_empty()
                        && fields.len() == *operands
                        && fields.iter().all(|field| !field.is_empty())
                        && fields.windows(2).all(|pair| pair[0] != pair[1])
                }
                AggregateKind::Enum {
                    type_name,
                    variant,
                    has_payload,
                } => {
                    !type_name.is_empty()
                        && !variant.is_empty()
                        && *operands == usize::from(*has_payload)
                }
                AggregateKind::Some | AggregateKind::Ok | AggregateKind::Err => *operands == 1,
                AggregateKind::None => *operands == 0,
            };
            if !valid {
                return Err(ProgramError::InvalidAggregate(workflow.clone()));
            }
        }
        InstructionKind::EnterLoop {
            phase,
            source_limit,
        } if source_limit == &Some(0)
            || matches!(phase, LoopPhase::Condition) && source_limit.is_some() =>
        {
            return Err(ProgramError::InvalidLoopLimit(workflow.clone()));
        }
        InstructionKind::Spawn { handle, body } => {
            let Some(task_body) = task_body_indexes
                .get(body)
                .and_then(|index| task_bodies.get(*index))
            else {
                return Err(ProgramError::InvalidTaskBody(body.clone()));
            };
            if body.enclosing_callable() != enclosing_callable
                || body.spawn_site() != &instruction.site
                || handle.result_type() != task_body.result_type()
                || instruction.ty != TypeDescriptor::UNIT
            {
                return Err(ProgramError::InvalidTaskControl(workflow.clone()));
            }
        }
        InstructionKind::Join { handles } if !valid_handle_names(handles, false) => {
            return Err(ProgramError::InvalidTaskControl(workflow.clone()));
        }
        InstructionKind::JoinAll { handles } if !valid_handle_names(handles, true) => {
            return Err(ProgramError::InvalidTaskControl(workflow.clone()));
        }
        InstructionKind::Detach { handle }
            if handle.is_empty() || instruction.ty != TypeDescriptor::UNIT =>
        {
            return Err(ProgramError::InvalidTaskControl(workflow.clone()));
        }
        _ => {}
    }
    Ok(())
}

fn valid_handle_names(handles: &[Arc<str>], allow_empty: bool) -> bool {
    (allow_empty || !handles.is_empty())
        && handles.iter().all(|handle| !handle.is_empty())
        && handles.iter().collect::<BTreeSet<_>>().len() == handles.len()
}

fn enum_arms_are_unique(arms: &[(Arc<str>, usize)]) -> bool {
    let mut variants = BTreeSet::new();
    arms.iter()
        .all(|(variant, _)| variants.insert(variant.as_ref()))
}
