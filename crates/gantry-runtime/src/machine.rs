//! Explicit-frame transition machine implementation.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{DeterministicEvaluationCode, IdentityKind};
use gantry_core::strict_json::{JsonLimits, JsonNode, StrictJsonDocument};
use gantry_core::unicode::{is_white_space, to_full_lowercase, to_full_uppercase};
use gantry_core::value::{LogicalValue, LogicalValueView, ValueError, ValueLimitKind, ValueLimits};
use gantry_ir::generated::Effect;
use gantry_ir::{
    AggregateKind, CanonicalPath, Comparison, ExecutableOperation, Instruction, InstructionKind,
    LoopPhase, MachineProgram, Primitive, Projection, StructuralPosition, TypeDescriptor,
};

use crate::session::SessionCreationModeV1;

/// Finite positive limits captured for one machine run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineLimits {
    /// Maximum deterministic transitions for the execution.
    pub maximum_deterministic_transitions: u64,
    /// Maximum logical operation preparations for the execution.
    pub maximum_operations: u64,
    /// Maximum loop body entries for the task.
    pub maximum_loop_iterations: u64,
    /// Maximum active workflow frames, counting the root as one.
    pub maximum_workflow_call_depth: u64,
    /// Consecutive deterministic transitions before a cooperative yield.
    pub deterministic_transition_yield_quantum: u64,
    /// Limits applied to every newly constructed logical value.
    pub value_limits: ValueLimits,
}

impl MachineLimits {
    /// Validates one complete finite machine-limit set.
    #[must_use]
    pub const fn new(
        maximum_deterministic_transitions: u64,
        maximum_operations: u64,
        maximum_loop_iterations: u64,
        maximum_workflow_call_depth: u64,
        deterministic_transition_yield_quantum: u64,
        value_limits: ValueLimits,
    ) -> Option<Self> {
        if maximum_deterministic_transitions == 0
            || maximum_operations == 0
            || maximum_loop_iterations == 0
            || maximum_workflow_call_depth == 0
            || deterministic_transition_yield_quantum == 0
        {
            None
        } else {
            Some(Self {
                maximum_deterministic_transitions,
                maximum_operations,
                maximum_loop_iterations,
                maximum_workflow_call_depth,
                deterministic_transition_yield_quantum,
                value_limits,
            })
        }
    }
}

/// Stable runtime failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCode {
    /// One closed deterministic primitive failure from the portable catalog.
    Deterministic(DeterministicEvaluationCode),
    /// One typed integration-operation failure from the portable catalog.
    Operation(gantry_core::portable::RuntimeErrorCategory),
    /// The deterministic-transition execution budget is exhausted.
    DeterministicTransitionBudget,
    /// The logical-operation execution budget is exhausted.
    OperationBudget,
    /// The loop-body-entry execution budget is exhausted.
    LoopIterationBudget,
    /// One source loop limit is exhausted.
    LoopLimitExhausted,
    /// The selected profile does not admit one analyzed effect.
    UnsupportedEffect,
    /// The executable program violated an analyzer/runtime invariant.
    InternalInvariant,
}

impl RuntimeCode {
    /// Returns the stable machine-facing spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Deterministic(code) => code.wire_name(),
            Self::Operation(category) => category.wire_name(),
            Self::DeterministicTransitionBudget => "deterministic-transition-budget",
            Self::OperationBudget => "operation-budget",
            Self::LoopIterationBudget => "loop-iteration-budget",
            Self::LoopLimitExhausted => "loop-limit-exhausted",
            Self::UnsupportedEffect => "unsupported-effect",
            Self::InternalInvariant => "internal-invariant-failure",
        }
    }
}

/// One structured task-local machine failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineFailure {
    /// Stable failure code.
    pub code: RuntimeCode,
    /// Workflow active at failure.
    pub workflow: CanonicalPath,
    /// Canonical structural site active at failure.
    pub site: StructuralPosition,
}

/// Rejection before a machine can begin execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineBuildError {
    /// The root workflow does not exist.
    MissingRoot,
    /// The supplied argument count differs from the root signature.
    ArgumentCount,
    /// One supplied argument does not match its analyzed parameter type.
    ArgumentType,
    /// The identity is not an execution identity.
    InvalidExecutionIdentity,
    /// The initial logical-session identity is not a session identity.
    InvalidSessionIdentity,
    /// One initial argument violates the effective value limits.
    Value(ValueError),
    /// The base sequential profile does not support this reachable effect.
    UnsupportedEffect(Effect),
}

/// Current coarse machine status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineStatus {
    /// A deterministic transition is enabled.
    Running,
    /// One lexical `fork` or `new` scope awaits session creation.
    WaitingSessionScope,
    /// One prepared operation awaits a host-selected result.
    WaitingOperation,
    /// The configured transition quantum requires an executor yield.
    YieldRequired,
    /// The root returned successfully.
    Succeeded,
    /// The root failed.
    Failed,
    /// Cancellation prevented further source consumption.
    Cancelled,
}

/// Fixed foreground result of the base sequential task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineOutcome {
    /// Successful root result.
    Succeeded(LogicalValue),
    /// Structured root failure.
    Failed(MachineFailure),
    /// First effective cancellation reason.
    Cancelled(Arc<str>),
}

/// One prepared logical operation and its stable dynamic identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationOccurrence {
    /// Derived stable operation identity.
    pub identity: ProtocolIdentity,
    /// Canonical containing workflow.
    pub workflow: CanonicalPath,
    /// Canonical static operation site.
    pub site: StructuralPosition,
    /// Ordered dynamic path frames, independent of source spans and yields.
    pub dynamic_path: Arc<[Arc<str>]>,
    /// Exact expected result type.
    pub expected_type: TypeDescriptor,
    /// Analyzer-resolved hook metadata when this came from package lowering.
    pub metadata: Option<Arc<ExecutableOperation>>,
    /// Completed source inputs captured in left-to-right order.
    pub inputs: Arc<[LogicalValue]>,
    /// Active agent selection, when present.
    pub active_agent: Option<Arc<str>>,
    /// Active logical session, when present.
    pub active_session: Option<ProtocolIdentity>,
}

/// One lexical session scope awaiting runtime-owned child-session creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionScopeOccurrence {
    /// Canonical containing workflow.
    pub workflow: CanonicalPath,
    /// Canonical lexical session site.
    pub site: StructuralPosition,
    /// Active enclosing logical session.
    pub parent_session_id: ProtocolIdentity,
    /// Stable dynamic occurrence number for this static site.
    pub occurrence: u64,
    /// Requested child-session creation mode.
    pub mode: SessionCreationModeV1,
}

/// Rejection while completing one pending lexical session scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionScopeCompletionError {
    /// No lexical session scope is awaiting completion.
    NotWaiting,
    /// The supplied occurrence is not the pending lexical scope.
    OccurrenceMismatch,
    /// The supplied child identity is not a logical-session identity.
    InvalidSessionIdentity,
    /// Cancellation made the pending scope nonconsumable.
    Cancelled,
}

/// Rejection of a host result supplied for a logical operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCompletionError {
    /// No operation is awaiting completion.
    NotWaiting,
    /// The supplied identity is not the pending operation.
    IdentityMismatch,
    /// Cancellation has made the host result nonconsumable.
    Cancelled,
    /// The normalized value does not match the expected outer type.
    TypeMismatch,
    /// The normalized value exceeds the machine's captured value limits.
    ValueLimit,
}

/// One abstract label emitted by the base machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineLabel {
    /// One deterministic transition completed.
    Deterministic {
        /// Canonical containing workflow.
        workflow: CanonicalPath,
        /// Canonical structural site.
        site: StructuralPosition,
        /// Stable instruction-kind spelling.
        kind: Arc<str>,
    },
    /// One logical operation was prepared before host dispatch.
    OperationPrepared(OperationOccurrence),
    /// One accepted operation result became source-consumable.
    OperationResult {
        /// Stable logical operation identity.
        operation: ProtocolIdentity,
    },
    /// The first effective cancellation reason was recorded.
    Cancellation {
        /// Immutable first reason.
        reason: Arc<str>,
    },
    /// One task-local failure became fixed.
    Failure(MachineFailure),
    /// The base root task settled exactly once.
    TaskSettled(MachineOutcome),
    /// The base root foreground outcome became fixed.
    ForegroundCompletion(MachineOutcome),
    /// The base execution terminal outcome became fixed.
    TerminalCompletion(MachineOutcome),
}

/// Result of asking the machine for its next transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineStep {
    /// One abstract transition completed.
    Transition(MachineLabel),
    /// One lexical session scope awaits child-session creation.
    WaitingSessionScope(SessionScopeOccurrence),
    /// Host dispatch remains pending for this operation.
    WaitingOperation(OperationOccurrence),
    /// The caller must cooperatively yield before further transitions.
    YieldRequired,
    /// The foreground outcome is already fixed.
    Complete(MachineOutcome),
}

#[derive(Clone, Debug)]
struct Binding {
    value: LogicalValue,
    ty: TypeDescriptor,
    mutable: bool,
}

type Scope = BTreeMap<Arc<str>, Binding>;

#[derive(Clone, Debug)]
struct WorkflowFrame {
    workflow: usize,
    pc: usize,
    scopes: Vec<Scope>,
    stack_base: usize,
    occurrence_base: usize,
    agent_stack_base: usize,
    agent_at_entry: Option<Arc<str>>,
    session_stack_base: usize,
    session_at_entry: Option<ProtocolIdentity>,
}

#[derive(Clone, Debug)]
struct PendingOperation {
    occurrence: OperationOccurrence,
    operands: usize,
}

/// One task-neutral explicit-frame machine.
#[derive(Debug)]
pub struct Machine {
    program: Arc<MachineProgram>,
    execution: ProtocolIdentity,
    limits: MachineLimits,
    frames: Vec<WorkflowFrame>,
    values: Vec<LogicalValue>,
    occurrences: Vec<Arc<str>>,
    counters: BTreeMap<String, u64>,
    source_loop_entries: BTreeMap<String, u64>,
    agent: Option<Arc<str>>,
    agent_stack: Vec<Option<Arc<str>>>,
    session: Option<ProtocolIdentity>,
    session_stack: Vec<Option<ProtocolIdentity>>,
    remaining_transitions: u64,
    remaining_operations: u64,
    remaining_loop_iterations: u64,
    consecutive_transitions: u64,
    pending_session_scope: Option<SessionScopeOccurrence>,
    pending_operation: Option<PendingOperation>,
    pending_labels: VecDeque<MachineLabel>,
    cancellation: Option<Arc<str>>,
    status: MachineStatus,
    outcome: Option<MachineOutcome>,
}

impl Machine {
    /// Creates the root task after profile, identity, argument, and value checks.
    pub fn new(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
        limits: MachineLimits,
    ) -> Result<Self, MachineBuildError> {
        Self::new_with_context(program, root, arguments, execution, limits, None, None)
    }

    /// Creates the root task with its preflight-resolved initial agent and session.
    pub fn new_with_context(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
        limits: MachineLimits,
        initial_agent: Option<Arc<str>>,
        initial_session: Option<ProtocolIdentity>,
    ) -> Result<Self, MachineBuildError> {
        if execution.kind() != IdentityKind::Execution {
            return Err(MachineBuildError::InvalidExecutionIdentity);
        }
        if initial_session.is_some_and(|session| session.kind() != IdentityKind::Session) {
            return Err(MachineBuildError::InvalidSessionIdentity);
        }
        let root_index = program
            .workflow_index(root)
            .ok_or(MachineBuildError::MissingRoot)?;
        let workflow = &program.workflows()[root_index];
        if workflow.parameters.len() != arguments.len() {
            return Err(MachineBuildError::ArgumentCount);
        }
        if let Some(effect) = program.unsupported_effect(root_index) {
            return Err(MachineBuildError::UnsupportedEffect(effect));
        }
        for (parameter, argument) in workflow.parameters.iter().zip(&arguments) {
            argument
                .validate(limits.value_limits)
                .map_err(MachineBuildError::Value)?;
            if !value_matches_type(argument, &parameter.ty) {
                return Err(MachineBuildError::ArgumentType);
            }
        }
        let mut root_scope = Scope::new();
        for (parameter, argument) in workflow.parameters.iter().zip(arguments) {
            root_scope.insert(
                Arc::clone(&parameter.name),
                Binding {
                    value: argument,
                    ty: parameter.ty.clone(),
                    mutable: parameter.mutable,
                },
            );
        }
        Ok(Self {
            program,
            execution,
            limits,
            frames: vec![WorkflowFrame {
                workflow: root_index,
                pc: 0,
                scopes: vec![root_scope],
                stack_base: 0,
                occurrence_base: 0,
                agent_stack_base: 0,
                agent_at_entry: None,
                session_stack_base: 0,
                session_at_entry: None,
            }],
            values: Vec::new(),
            occurrences: Vec::new(),
            counters: BTreeMap::new(),
            source_loop_entries: BTreeMap::new(),
            agent: initial_agent,
            agent_stack: Vec::new(),
            session: initial_session,
            session_stack: Vec::new(),
            remaining_transitions: limits.maximum_deterministic_transitions,
            remaining_operations: limits.maximum_operations,
            remaining_loop_iterations: limits.maximum_loop_iterations,
            consecutive_transitions: 0,
            pending_session_scope: None,
            pending_operation: None,
            pending_labels: VecDeque::new(),
            cancellation: None,
            status: MachineStatus::Running,
            outcome: None,
        })
    }

    /// Returns the current coarse status.
    #[must_use]
    pub const fn status(&self) -> MachineStatus {
        self.status
    }

    /// Returns the fixed foreground outcome, when terminal.
    #[must_use]
    pub fn outcome(&self) -> Option<&MachineOutcome> {
        self.outcome.as_ref()
    }

    /// Returns remaining deterministic, operation, and loop-entry budgets.
    #[must_use]
    pub const fn remaining_budgets(&self) -> (u64, u64, u64) {
        (
            self.remaining_transitions,
            self.remaining_operations,
            self.remaining_loop_iterations,
        )
    }

    /// Records the first cancellation reason without consuming source state.
    pub fn cancel(&mut self, reason: impl Into<Arc<str>>) -> Option<MachineLabel> {
        if self.outcome.is_some() || self.cancellation.is_some() {
            return None;
        }
        let reason = reason.into();
        self.cancellation = Some(Arc::clone(&reason));
        Some(MachineLabel::Cancellation { reason })
    }

    /// Resumes after the caller has performed the required cooperative yield.
    pub fn resume_after_yield(&mut self) -> bool {
        if self.status != MachineStatus::YieldRequired {
            return false;
        }
        self.consecutive_transitions = 0;
        self.status = MachineStatus::Running;
        true
    }

    /// Enters one pending lexical session scope after its child was recorded and established.
    pub fn complete_session_scope(
        &mut self,
        occurrence: &SessionScopeOccurrence,
        session: ProtocolIdentity,
    ) -> Result<MachineLabel, SessionScopeCompletionError> {
        let pending = self
            .pending_session_scope
            .as_ref()
            .ok_or(SessionScopeCompletionError::NotWaiting)?;
        if pending != occurrence {
            return Err(SessionScopeCompletionError::OccurrenceMismatch);
        }
        if session.kind() != IdentityKind::Session {
            return Err(SessionScopeCompletionError::InvalidSessionIdentity);
        }
        if self.cancellation.is_some() {
            return Err(SessionScopeCompletionError::Cancelled);
        }
        self.session_stack.push(self.session.replace(session));
        self.advance_pc();
        self.pending_session_scope = None;
        self.status = MachineStatus::Running;
        self.consecutive_transitions = 0;
        let label = MachineLabel::Deterministic {
            workflow: occurrence.workflow.clone(),
            site: occurrence.site.clone(),
            kind: Arc::from("session-enter"),
        };
        Ok(label)
    }

    /// Fails one pending lexical session scope before its body becomes active.
    pub fn fail_session_scope(
        &mut self,
        occurrence: &SessionScopeOccurrence,
        code: RuntimeCode,
    ) -> Result<MachineLabel, SessionScopeCompletionError> {
        let pending = self
            .pending_session_scope
            .as_ref()
            .ok_or(SessionScopeCompletionError::NotWaiting)?;
        if pending != occurrence {
            return Err(SessionScopeCompletionError::OccurrenceMismatch);
        }
        self.pending_session_scope = None;
        match self.fail_at(code, occurrence.workflow.clone(), occurrence.site.clone()) {
            MachineStep::Transition(label) => Ok(label),
            _ => unreachable!("session-scope failure emits one transition"),
        }
    }

    /// Supplies one normalized result for the exact pending logical operation.
    pub fn complete_operation(
        &mut self,
        operation: ProtocolIdentity,
        value: LogicalValue,
    ) -> Result<MachineLabel, OperationCompletionError> {
        let pending = self
            .pending_operation
            .as_ref()
            .ok_or(OperationCompletionError::NotWaiting)?;
        if pending.occurrence.identity != operation {
            return Err(OperationCompletionError::IdentityMismatch);
        }
        if self.cancellation.is_some() {
            return Err(OperationCompletionError::Cancelled);
        }
        value
            .validate(self.limits.value_limits)
            .map_err(|_| OperationCompletionError::ValueLimit)?;
        if !value_matches_type(&value, &pending.occurrence.expected_type) {
            return Err(OperationCompletionError::TypeMismatch);
        }
        let operands = pending.operands;
        if operands > self.values.len() {
            return Err(OperationCompletionError::NotWaiting);
        }
        self.values.truncate(self.values.len() - operands);
        self.values.push(value);
        self.pending_operation = None;
        self.status = MachineStatus::Running;
        self.consecutive_transitions = 0;
        Ok(MachineLabel::OperationResult { operation })
    }

    /// Fails the exact pending logical operation with one portable runtime category.
    pub fn fail_operation(
        &mut self,
        operation: ProtocolIdentity,
        category: gantry_core::portable::RuntimeErrorCategory,
    ) -> Result<MachineLabel, OperationCompletionError> {
        self.fail_operation_with_code(operation, RuntimeCode::Operation(category))
    }

    /// Fails the exact pending logical operation with one typed runtime code.
    pub fn fail_operation_with_code(
        &mut self,
        operation: ProtocolIdentity,
        code: RuntimeCode,
    ) -> Result<MachineLabel, OperationCompletionError> {
        let pending = self
            .pending_operation
            .as_ref()
            .ok_or(OperationCompletionError::NotWaiting)?;
        if pending.occurrence.identity != operation {
            return Err(OperationCompletionError::IdentityMismatch);
        }
        if self.cancellation.is_some() {
            return Err(OperationCompletionError::Cancelled);
        }
        let workflow = pending.occurrence.workflow.clone();
        let site = pending.occurrence.site.clone();
        match self.fail_at(code, workflow, site) {
            MachineStep::Transition(label) => Ok(label),
            _ => unreachable!("operation failure emits one transition"),
        }
    }

    /// Takes the next unique deterministic or operation-preparation transition.
    pub fn step(&mut self) -> MachineStep {
        loop {
            if let Some(label) = self.pending_labels.pop_front() {
                return MachineStep::Transition(label);
            }
            if let Some(outcome) = &self.outcome {
                return MachineStep::Complete(outcome.clone());
            }
            if let Some(reason) = self.cancellation.clone() {
                return self.finish_cancelled(reason);
            }
            match self.status {
                MachineStatus::WaitingSessionScope => {
                    let occurrence = self.pending_session_scope.clone().unwrap_or_else(|| {
                        unreachable!("waiting status retains one session scope")
                    });
                    return MachineStep::WaitingSessionScope(occurrence);
                }
                MachineStatus::WaitingOperation => {
                    let occurrence = self
                        .pending_operation
                        .as_ref()
                        .map(|pending| pending.occurrence.clone())
                        .unwrap_or_else(|| unreachable!("waiting status retains one operation"));
                    return MachineStep::WaitingOperation(occurrence);
                }
                MachineStatus::YieldRequired => return MachineStep::YieldRequired,
                MachineStatus::Succeeded | MachineStatus::Failed | MachineStatus::Cancelled => {
                    return MachineStep::Complete(
                        self.outcome
                            .clone()
                            .unwrap_or_else(|| unreachable!("terminal status retains outcome")),
                    );
                }
                MachineStatus::Running => {}
            }
            let Some((instruction, workflow)) = self.current_instruction() else {
                return self.fail_current(RuntimeCode::InternalInvariant);
            };
            if matches!(instruction.kind, InstructionKind::CancellationCheck) {
                self.advance_pc();
                continue;
            }
            return self.execute(instruction, workflow);
        }
    }

    fn current_instruction(&self) -> Option<(Instruction, CanonicalPath)> {
        let frame = self.frames.last()?;
        let workflow = self.program.workflows().get(frame.workflow)?;
        let instruction = workflow.instructions.get(frame.pc)?.clone();
        Some((instruction, workflow.path.clone()))
    }

    fn execute(&mut self, instruction: Instruction, workflow: CanonicalPath) -> MachineStep {
        let site = instruction.site.clone();
        let kind_name = instruction_name(&instruction.kind);
        let result = match instruction.kind {
            InstructionKind::Push(value) => self.push_value(value),
            InstructionKind::Load(name) => self.load_binding(&name),
            InstructionKind::Bind { name, ty, mutable } => self.bind_value(name, ty, mutable),
            InstructionKind::Assign {
                name,
                path,
                target_type,
            } => self.assign_value(&name, &path, &target_type),
            InstructionKind::Pop => self.pop_value(),
            InstructionKind::Aggregate { kind, operands } => {
                self.construct_aggregate(kind, operands)
            }
            InstructionKind::Project(projection) => self.project_value(projection),
            InstructionKind::Primitive(primitive) => self.apply_primitive(primitive),
            InstructionKind::EnterScope => self.enter_scope(),
            InstructionKind::ExitScope => self.exit_scope(),
            InstructionKind::Jump(target) => self.jump(target),
            InstructionKind::Branch {
                when_true,
                when_false,
            } => self.branch(&workflow, &site, when_true, when_false),
            InstructionKind::BranchOption {
                when_some,
                when_none,
            } => self.branch_option(&workflow, &site, when_some, when_none),
            InstructionKind::EnterLoop {
                phase,
                source_limit,
            } => self.enter_loop(&workflow, &site, phase, source_limit),
            InstructionKind::LeaveOccurrence => self.leave_occurrence(),
            InstructionKind::Call { callee, arguments } => {
                return self.call(workflow, site, callee, arguments);
            }
            InstructionKind::Return => return self.return_value(workflow, site),
            InstructionKind::Operation => {
                return self.prepare_operation(workflow, instruction, 0);
            }
            InstructionKind::OperationWithOperands { operands } => {
                return self.prepare_operation(workflow, instruction, operands);
            }
            InstructionKind::OperationCall { operands, .. } => {
                return self.prepare_operation(workflow, instruction, operands);
            }
            InstructionKind::EnterAgent(agent) => self.enter_agent(agent),
            InstructionKind::ExitAgent => self.exit_agent(),
            InstructionKind::EnterSession(mode) => {
                return self.enter_session(workflow, site, &mode);
            }
            InstructionKind::ExitSession => self.exit_session(),
            InstructionKind::CancellationCheck => unreachable!("checks are consumed by step"),
        };
        match result {
            Ok(()) => self.finish_deterministic(workflow, site, kind_name),
            Err(code) => self.fail_at(code, workflow, site),
        }
    }

    fn push_value(&mut self, value: LogicalValue) -> Result<(), RuntimeCode> {
        value
            .validate(self.limits.value_limits)
            .map_err(map_value_error)?;
        self.charge_transition()?;
        self.values.push(value);
        self.advance_pc();
        Ok(())
    }

    fn load_binding(&mut self, name: &str) -> Result<(), RuntimeCode> {
        let value = self
            .binding(name)
            .map(|binding| binding.value.clone())
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition()?;
        self.values.push(value);
        self.advance_pc();
        Ok(())
    }

    fn bind_value(
        &mut self,
        name: Arc<str>,
        ty: TypeDescriptor,
        mutable: bool,
    ) -> Result<(), RuntimeCode> {
        if self.binding(&name).is_some() {
            return Err(RuntimeCode::InternalInvariant);
        }
        let value = self
            .values
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        if !value_matches_type(&value, &ty) {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition()?;
        self.values.pop();
        self.frames
            .last_mut()
            .and_then(|frame| frame.scopes.last_mut())
            .ok_or(RuntimeCode::InternalInvariant)?
            .insert(name, Binding { value, ty, mutable });
        self.advance_pc();
        Ok(())
    }

    fn assign_value(
        &mut self,
        name: &str,
        path: &[gantry_core::value::ValuePathSegment],
        target_type: &TypeDescriptor,
    ) -> Result<(), RuntimeCode> {
        let replacement = self.values.last().ok_or(RuntimeCode::InternalInvariant)?;
        let binding = self.binding(name).ok_or(RuntimeCode::InternalInvariant)?;
        if !binding.mutable {
            return Err(RuntimeCode::InternalInvariant);
        }
        if !value_matches_type(replacement, target_type) {
            return Err(RuntimeCode::InternalInvariant);
        }
        let candidate = binding
            .value
            .replaced(path, replacement, self.limits.value_limits)
            .map_err(map_value_error)?;
        if !value_matches_type(&candidate, &binding.ty) {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition()?;
        self.values.pop();
        self.binding_mut(name)
            .ok_or(RuntimeCode::InternalInvariant)?
            .value = candidate;
        self.advance_pc();
        Ok(())
    }

    fn pop_value(&mut self) -> Result<(), RuntimeCode> {
        if self.values.is_empty() {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition()?;
        self.values.pop();
        self.advance_pc();
        Ok(())
    }

    fn construct_aggregate(
        &mut self,
        kind: AggregateKind,
        operands: usize,
    ) -> Result<(), RuntimeCode> {
        let values = self.peek_operands(operands)?.to_vec();
        let candidate = match kind {
            AggregateKind::List => LogicalValue::list(values, self.limits.value_limits),
            AggregateKind::Tuple => LogicalValue::tuple(values, self.limits.value_limits),
            AggregateKind::Struct { type_name, fields } => LogicalValue::structure(
                type_name.as_ref(),
                fields
                    .into_iter()
                    .zip(values)
                    .map(|(name, value)| (name.to_string(), value))
                    .collect(),
                self.limits.value_limits,
            ),
            AggregateKind::Enum {
                type_name,
                variant,
                has_payload,
            } => LogicalValue::enumeration(
                type_name.as_ref(),
                variant.as_ref(),
                has_payload.then(|| values[0].clone()),
                self.limits.value_limits,
            ),
            AggregateKind::Some => LogicalValue::some(values[0].clone(), self.limits.value_limits),
            AggregateKind::None => Ok(LogicalValue::none()),
            AggregateKind::Ok => LogicalValue::ok(values[0].clone(), self.limits.value_limits),
            AggregateKind::Err => LogicalValue::err(values[0].clone(), self.limits.value_limits),
        }
        .map_err(map_value_error)?;
        self.charge_transition()?;
        self.truncate_operands(operands);
        self.values.push(candidate);
        self.advance_pc();
        Ok(())
    }

    fn project_value(&mut self, projection: Projection) -> Result<(), RuntimeCode> {
        let source = self.values.last().ok_or(RuntimeCode::InternalInvariant)?;
        let projected = match projection {
            Projection::Member(index) => source.member(index).ok_or_else(|| {
                if matches!(source.view(), LogicalValueView::List(_)) {
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::ListIndexOutOfBounds)
                } else {
                    RuntimeCode::InternalInvariant
                }
            })?,
            Projection::Field(name) => source.field(&name).ok_or(RuntimeCode::InternalInvariant)?,
            Projection::Payload => source.payload().ok_or(RuntimeCode::InternalInvariant)?,
        };
        self.charge_transition()?;
        self.values.pop();
        self.values.push(projected);
        self.advance_pc();
        Ok(())
    }

    fn apply_primitive(&mut self, primitive: Primitive) -> Result<(), RuntimeCode> {
        let arity = primitive.arity();
        let operands = self.peek_operands(arity)?;
        let result = evaluate_primitive(primitive, operands, self.limits.value_limits)?;
        self.charge_transition()?;
        self.truncate_operands(arity);
        self.values.push(result);
        self.advance_pc();
        Ok(())
    }

    fn enter_scope(&mut self) -> Result<(), RuntimeCode> {
        self.charge_transition()?;
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .scopes
            .push(Scope::new());
        self.advance_pc();
        Ok(())
    }

    fn exit_scope(&mut self) -> Result<(), RuntimeCode> {
        let frame = self.frames.last().ok_or(RuntimeCode::InternalInvariant)?;
        if frame.scopes.len() <= 1 {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition()?;
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .scopes
            .pop();
        self.advance_pc();
        Ok(())
    }

    fn jump(&mut self, target: usize) -> Result<(), RuntimeCode> {
        self.charge_transition()?;
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .pc = target;
        Ok(())
    }

    fn branch(
        &mut self,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
        when_true: usize,
        when_false: usize,
    ) -> Result<(), RuntimeCode> {
        let condition = self
            .values
            .last()
            .and_then(condition_value)
            .ok_or(RuntimeCode::InternalInvariant)?;
        let arm = usize::from(!condition);
        let target = if condition { when_true } else { when_false };
        let occurrence = Arc::from(format!(
            "branch:{}:{}:{arm}",
            workflow.as_str(),
            position_key(site)
        ));
        self.charge_transition()?;
        self.values.pop();
        self.occurrences.push(occurrence);
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .pc = target;
        Ok(())
    }

    fn branch_option(
        &mut self,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
        when_some: usize,
        when_none: usize,
    ) -> Result<(), RuntimeCode> {
        let value = self
            .values
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        let LogicalValueView::Option { is_some } = value.view() else {
            return Err(RuntimeCode::InternalInvariant);
        };
        let payload = if is_some {
            Some(value.payload().ok_or(RuntimeCode::InternalInvariant)?)
        } else {
            None
        };
        let arm = usize::from(!is_some);
        let target = if is_some { when_some } else { when_none };
        let occurrence = Arc::from(format!(
            "branch:{}:{}:{arm}",
            workflow.as_str(),
            position_key(site)
        ));
        self.charge_transition()?;
        self.values.pop();
        if let Some(payload) = payload {
            self.values.push(payload);
        }
        self.occurrences.push(occurrence);
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .pc = target;
        Ok(())
    }

    fn enter_loop(
        &mut self,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
        phase: LoopPhase,
        source_limit: Option<u64>,
    ) -> Result<(), RuntimeCode> {
        let phase_name = match phase {
            LoopPhase::Condition => "condition",
            LoopPhase::Body => "body",
        };
        let key = self.counter_key(
            match phase {
                LoopPhase::Condition => "loop-condition",
                LoopPhase::Body => "loop-body",
            },
            workflow,
            site,
        );
        let source_key = self.counter_key("loop-source", workflow, site);
        let occurrence = self.counters.get(&key).copied().unwrap_or(0);
        if matches!(phase, LoopPhase::Body) {
            let source_entries = self
                .source_loop_entries
                .get(&source_key)
                .copied()
                .unwrap_or(0);
            if source_limit.is_some_and(|limit| source_entries >= limit) {
                return Err(RuntimeCode::LoopLimitExhausted);
            }
            if self.remaining_loop_iterations == 0 {
                return Err(RuntimeCode::LoopIterationBudget);
            }
        }
        self.charge_transition()?;
        self.counters
            .insert(key.clone(), occurrence.saturating_add(1));
        if matches!(phase, LoopPhase::Body) {
            self.remaining_loop_iterations -= 1;
            let entries = self
                .source_loop_entries
                .get(&source_key)
                .copied()
                .unwrap_or(0);
            self.source_loop_entries
                .insert(source_key, entries.saturating_add(1));
        }
        self.occurrences.push(Arc::from(format!(
            "loop:{}:{}:{phase_name}:{occurrence}",
            workflow.as_str(),
            position_key(site)
        )));
        self.advance_pc();
        Ok(())
    }

    fn leave_occurrence(&mut self) -> Result<(), RuntimeCode> {
        let base = self
            .frames
            .last()
            .map(|frame| frame.occurrence_base)
            .ok_or(RuntimeCode::InternalInvariant)?;
        if self.occurrences.len() <= base {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition()?;
        self.occurrences.pop();
        self.advance_pc();
        Ok(())
    }

    fn call(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        callee: CanonicalPath,
        arguments: usize,
    ) -> MachineStep {
        if u64::try_from(self.frames.len()).map_or(true, |depth| {
            depth >= self.limits.maximum_workflow_call_depth
        }) {
            return self.fail_at(
                RuntimeCode::Deterministic(DeterministicEvaluationCode::WorkflowCallDepthLimit),
                workflow,
                site,
            );
        }
        let values = match self.peek_operands(arguments) {
            Ok(values) => values.to_vec(),
            Err(code) => return self.fail_at(code, workflow, site),
        };
        let Some(callee_index) = self.program.workflow_index(&callee) else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let callee_workflow = &self.program.workflows()[callee_index];
        let parameters = callee_workflow.parameters.clone();
        if parameters.len() != values.len() {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        if parameters
            .iter()
            .zip(&values)
            .any(|(parameter, value)| !value_matches_type(value, &parameter.ty))
        {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        if let Err(code) = self.charge_transition() {
            return self.fail_at(code, workflow, site);
        }
        let occurrence = self.next_occurrence("call", &workflow, &site, None);
        self.truncate_operands(arguments);
        self.advance_pc();
        self.occurrences.push(occurrence);
        let mut scope = Scope::new();
        for (parameter, value) in parameters.iter().zip(values) {
            scope.insert(
                Arc::clone(&parameter.name),
                Binding {
                    value,
                    ty: parameter.ty.clone(),
                    mutable: parameter.mutable,
                },
            );
        }
        self.frames.push(WorkflowFrame {
            workflow: callee_index,
            pc: 0,
            scopes: vec![scope],
            stack_base: self.values.len(),
            occurrence_base: self.occurrences.len(),
            agent_stack_base: self.agent_stack.len(),
            agent_at_entry: self.agent.clone(),
            session_stack_base: self.session_stack.len(),
            session_at_entry: self.session,
        });
        self.finish_deterministic(workflow, site, Arc::from("call"))
    }

    fn return_value(&mut self, workflow: CanonicalPath, site: StructuralPosition) -> MachineStep {
        let Some(value) = self.values.last().cloned() else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let Some(expected) = self
            .frames
            .last()
            .and_then(|frame| self.program.workflows().get(frame.workflow))
            .map(|workflow| &workflow.result)
        else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        if !value_matches_type(&value, expected) {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        if self.frames.len() == 1 {
            self.values.pop();
            let outcome = MachineOutcome::Succeeded(value);
            return self.finish_outcome(outcome);
        }
        if let Err(code) = self.charge_transition() {
            return self.fail_at(code, workflow, site);
        }
        let frame = self
            .frames
            .pop()
            .unwrap_or_else(|| unreachable!("nonroot return retains frame"));
        self.values.truncate(frame.stack_base);
        self.values.push(value);
        self.occurrences
            .truncate(frame.occurrence_base.saturating_sub(1));
        self.agent_stack.truncate(frame.agent_stack_base);
        self.agent = frame.agent_at_entry;
        self.session_stack.truncate(frame.session_stack_base);
        self.session = frame.session_at_entry;
        self.finish_deterministic(workflow, site, Arc::from("return"))
    }

    fn prepare_operation(
        &mut self,
        workflow: CanonicalPath,
        instruction: Instruction,
        operands: usize,
    ) -> MachineStep {
        if self.remaining_operations == 0 {
            return self.fail_at(RuntimeCode::OperationBudget, workflow, instruction.site);
        }
        let inputs = match self.peek_operands(operands) {
            Ok(inputs) => Arc::from(inputs.to_vec()),
            Err(_) => {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, instruction.site);
            }
        };
        let metadata = match &instruction.kind {
            InstructionKind::OperationCall { operation, .. } => Some(Arc::new(operation.clone())),
            _ => None,
        };
        let operation_frame = self.next_occurrence("operation", &workflow, &instruction.site, None);
        let mut path = self.occurrences.clone();
        path.push(operation_frame);
        let key = operation_key(self.execution, &workflow, &instruction.site, &path);
        let identity = match ProtocolIdentity::derive(IdentityKind::Operation, &key) {
            Ok(identity) => identity,
            Err(_) => {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, instruction.site);
            }
        };
        self.remaining_operations -= 1;
        self.advance_pc();
        let occurrence = OperationOccurrence {
            identity,
            workflow,
            site: instruction.site,
            dynamic_path: Arc::from(path),
            expected_type: instruction.ty,
            metadata,
            inputs,
            active_agent: self.agent.clone(),
            active_session: self.session,
        };
        self.pending_operation = Some(PendingOperation {
            occurrence: occurrence.clone(),
            operands,
        });
        self.status = MachineStatus::WaitingOperation;
        self.consecutive_transitions = 0;
        MachineStep::Transition(MachineLabel::OperationPrepared(occurrence))
    }

    fn enter_agent(&mut self, agent: Arc<str>) -> Result<(), RuntimeCode> {
        self.charge_transition()?;
        self.agent_stack.push(self.agent.replace(agent));
        self.advance_pc();
        Ok(())
    }

    fn exit_agent(&mut self) -> Result<(), RuntimeCode> {
        let previous = self
            .agent_stack
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition()?;
        self.agent_stack.pop();
        self.agent = previous;
        self.advance_pc();
        Ok(())
    }

    fn enter_session(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        mode: &str,
    ) -> MachineStep {
        if let Err(code) = self.charge_transition() {
            return self.fail_at(code, workflow, site);
        }
        if mode == "inline" {
            self.session_stack.push(self.session);
            self.advance_pc();
            return self.finish_deterministic(workflow, site, Arc::from("session-enter"));
        }
        let Some(parent_session_id) = self.session else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let mode = match mode {
            "fork" => SessionCreationModeV1::Fork,
            "new" => SessionCreationModeV1::New,
            _ => return self.fail_at(RuntimeCode::InternalInvariant, workflow, site),
        };
        let key = self.counter_key("session", &workflow, &site);
        let occurrence = self.counters.get(&key).copied().unwrap_or(0);
        self.counters.insert(key, occurrence.saturating_add(1));
        let pending = SessionScopeOccurrence {
            workflow,
            site,
            parent_session_id,
            occurrence,
            mode,
        };
        self.pending_session_scope = Some(pending.clone());
        self.status = MachineStatus::WaitingSessionScope;
        self.consecutive_transitions = 0;
        MachineStep::WaitingSessionScope(pending)
    }

    fn exit_session(&mut self) -> Result<(), RuntimeCode> {
        let previous = self
            .session_stack
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition()?;
        self.session_stack.pop();
        self.session = previous;
        self.advance_pc();
        Ok(())
    }

    fn charge_transition(&mut self) -> Result<(), RuntimeCode> {
        if self.remaining_transitions == 0 {
            return Err(RuntimeCode::DeterministicTransitionBudget);
        }
        self.remaining_transitions -= 1;
        self.consecutive_transitions = self.consecutive_transitions.saturating_add(1);
        Ok(())
    }

    fn finish_deterministic(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        kind: Arc<str>,
    ) -> MachineStep {
        if self.consecutive_transitions >= self.limits.deterministic_transition_yield_quantum {
            self.status = MachineStatus::YieldRequired;
        }
        MachineStep::Transition(MachineLabel::Deterministic {
            workflow,
            site,
            kind,
        })
    }

    fn finish_cancelled(&mut self, reason: Arc<str>) -> MachineStep {
        let outcome = MachineOutcome::Cancelled(reason);
        self.pending_session_scope = None;
        self.pending_operation = None;
        self.finish_outcome(outcome)
    }

    fn finish_outcome(&mut self, outcome: MachineOutcome) -> MachineStep {
        self.status = match outcome {
            MachineOutcome::Succeeded(_) => MachineStatus::Succeeded,
            MachineOutcome::Failed(_) => MachineStatus::Failed,
            MachineOutcome::Cancelled(_) => MachineStatus::Cancelled,
        };
        self.outcome = Some(outcome.clone());
        self.pending_labels
            .push_back(MachineLabel::ForegroundCompletion(outcome.clone()));
        self.pending_labels
            .push_back(MachineLabel::TerminalCompletion(outcome.clone()));
        MachineStep::Transition(MachineLabel::TaskSettled(outcome))
    }

    fn fail_current(&mut self, code: RuntimeCode) -> MachineStep {
        let Some((instruction, workflow)) = self.current_instruction() else {
            let workflow = self
                .frames
                .last()
                .and_then(|frame| self.program.workflows().get(frame.workflow))
                .map(|workflow| workflow.path.clone())
                .unwrap_or_else(|| {
                    CanonicalPath::new("crate::invalid")
                        .unwrap_or_else(|_| unreachable!("constant path is canonical"))
                });
            let site = StructuralPosition::new(vec![u64::MAX])
                .unwrap_or_else(|_| unreachable!("constant position is nonempty"));
            return self.fail_at(code, workflow, site);
        };
        self.fail_at(code, workflow, instruction.site)
    }

    fn fail_at(
        &mut self,
        code: RuntimeCode,
        workflow: CanonicalPath,
        site: StructuralPosition,
    ) -> MachineStep {
        let failure = MachineFailure {
            code,
            workflow,
            site,
        };
        self.pending_session_scope = None;
        self.pending_operation = None;
        self.status = MachineStatus::Failed;
        let outcome = MachineOutcome::Failed(failure.clone());
        self.outcome = Some(outcome.clone());
        self.pending_labels
            .push_back(MachineLabel::TaskSettled(outcome.clone()));
        self.pending_labels
            .push_back(MachineLabel::ForegroundCompletion(outcome.clone()));
        self.pending_labels
            .push_back(MachineLabel::TerminalCompletion(outcome));
        MachineStep::Transition(MachineLabel::Failure(failure))
    }

    fn binding(&self, name: &str) -> Option<&Binding> {
        self.frames
            .last()?
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name))
    }

    fn binding_mut(&mut self, name: &str) -> Option<&mut Binding> {
        self.frames
            .last_mut()?
            .scopes
            .iter_mut()
            .rev()
            .find_map(|scope| scope.get_mut(name))
    }

    fn peek_operands(&self, count: usize) -> Result<&[LogicalValue], RuntimeCode> {
        let start = self
            .values
            .len()
            .checked_sub(count)
            .ok_or(RuntimeCode::InternalInvariant)?;
        Ok(&self.values[start..])
    }

    fn truncate_operands(&mut self, count: usize) {
        let length = self.values.len().saturating_sub(count);
        self.values.truncate(length);
    }

    fn advance_pc(&mut self) {
        if let Some(frame) = self.frames.last_mut() {
            frame.pc = frame.pc.saturating_add(1);
        }
    }

    fn counter_key(
        &self,
        kind: &str,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
    ) -> String {
        let mut key = self
            .occurrences
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join("/");
        key.push('|');
        key.push_str(kind);
        key.push('|');
        key.push_str(workflow.as_str());
        key.push('|');
        key.push_str(&position_key(site));
        key
    }

    fn next_occurrence(
        &mut self,
        kind: &str,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
        discriminator: Option<u64>,
    ) -> Arc<str> {
        let key = self.counter_key(kind, workflow, site);
        let occurrence = self.counters.get(&key).copied().unwrap_or(0);
        self.counters.insert(key, occurrence.saturating_add(1));
        Arc::from(format!(
            "{kind}:{}:{}:{}:{occurrence}",
            workflow.as_str(),
            position_key(site),
            discriminator
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        ))
    }
}

fn instruction_name(instruction: &InstructionKind) -> Arc<str> {
    Arc::from(match instruction {
        InstructionKind::Push(_) => "literal",
        InstructionKind::Load(_) => "variable",
        InstructionKind::Bind { .. } => "binding",
        InstructionKind::Assign { .. } => "assignment",
        InstructionKind::Pop => "discard",
        InstructionKind::Aggregate { .. } => "aggregate",
        InstructionKind::Project(_) => "projection",
        InstructionKind::Primitive(_) => "primitive",
        InstructionKind::EnterScope => "scope-enter",
        InstructionKind::ExitScope => "scope-exit",
        InstructionKind::Jump(_) => "jump",
        InstructionKind::Branch { .. } | InstructionKind::BranchOption { .. } => "branch",
        InstructionKind::EnterLoop { .. } => "loop",
        InstructionKind::LeaveOccurrence => "occurrence-exit",
        InstructionKind::Call { .. } => "call",
        InstructionKind::Return => "return",
        InstructionKind::Operation
        | InstructionKind::OperationWithOperands { .. }
        | InstructionKind::OperationCall { .. } => "operation",
        InstructionKind::EnterAgent(_) => "agent-enter",
        InstructionKind::ExitAgent => "agent-exit",
        InstructionKind::EnterSession(_) => "session-enter",
        InstructionKind::ExitSession => "session-exit",
        InstructionKind::CancellationCheck => "cancellation-check",
    })
}

fn evaluate_primitive(
    primitive: Primitive,
    operands: &[LogicalValue],
    limits: ValueLimits,
) -> Result<LogicalValue, RuntimeCode> {
    match primitive {
        Primitive::Not => bool_operand(operands, 0).map(|value| LogicalValue::boolean(!value)),
        Primitive::Negate => match operands[0].view() {
            LogicalValueView::Int(value) => value
                .checked_neg()
                .map(LogicalValue::integer)
                .map_err(RuntimeCode::Deterministic),
            LogicalValueView::Float(value) => Ok(LogicalValue::float(value.negated())),
            _ => Err(RuntimeCode::InternalInvariant),
        },
        Primitive::Add => numeric_binary(operands, NumericBinary::Add).or_else(|code| {
            if code != RuntimeCode::InternalInvariant {
                return Err(code);
            }
            let left = string_operand(operands, 0)?;
            let right = string_operand(operands, 1)?;
            let mut value = String::with_capacity(left.len().saturating_add(right.len()));
            value.push_str(left);
            value.push_str(right);
            LogicalValue::string(value, limits).map_err(map_string_value_error)
        }),
        Primitive::Subtract => numeric_binary(operands, NumericBinary::Subtract),
        Primitive::Multiply => numeric_binary(operands, NumericBinary::Multiply),
        Primitive::Divide => numeric_binary(operands, NumericBinary::Divide),
        Primitive::Remainder => numeric_binary(operands, NumericBinary::Remainder),
        Primitive::Compare(comparison) => compare_numeric(operands, comparison),
        Primitive::Equal => Ok(LogicalValue::boolean(operands[0] == operands[1])),
        Primitive::NotEqual => Ok(LogicalValue::boolean(operands[0] != operands[1])),
        Primitive::IntToFloat => int_operand(operands, 0)
            .map(GantryInt::to_float)
            .map(LogicalValue::float),
        Primitive::FloatToInt => {
            let value = float_operand(operands, 0)?;
            value.to_int().map_or_else(
                || Ok(LogicalValue::none()),
                |value| {
                    LogicalValue::some(LogicalValue::integer(value), limits)
                        .map_err(map_value_error)
                },
            )
        }
        Primitive::ToString => {
            let value = match operands[0].view() {
                LogicalValueView::Bool(value) => value.to_string(),
                LogicalValueView::Int(value) => value.get().to_string(),
                LogicalValueView::Float(value) => value.canonical_string(),
                _ => return Err(RuntimeCode::InternalInvariant),
            };
            LogicalValue::string(value, limits).map_err(map_string_value_error)
        }
        Primitive::ListLength => {
            let LogicalValueView::List(length) = operands[0].view() else {
                return Err(RuntimeCode::InternalInvariant);
            };
            length_value(length)
        }
        Primitive::StringLength => length_value(string_operand(operands, 0)?.chars().count()),
        Primitive::StringIsEmpty => Ok(LogicalValue::boolean(
            string_operand(operands, 0)?.is_empty(),
        )),
        Primitive::StringContains => Ok(LogicalValue::boolean(
            string_operand(operands, 0)?.contains(string_operand(operands, 1)?),
        )),
        Primitive::StringStartsWith => Ok(LogicalValue::boolean(
            string_operand(operands, 0)?.starts_with(string_operand(operands, 1)?),
        )),
        Primitive::StringEndsWith => Ok(LogicalValue::boolean(
            string_operand(operands, 0)?.ends_with(string_operand(operands, 1)?),
        )),
        Primitive::StringTrim | Primitive::StringTrimStart | Primitive::StringTrimEnd => {
            let value = string_operand(operands, 0)?;
            let trimmed = match primitive {
                Primitive::StringTrim => value.trim_matches(is_white_space),
                Primitive::StringTrimStart => value.trim_start_matches(is_white_space),
                Primitive::StringTrimEnd => value.trim_end_matches(is_white_space),
                _ => unreachable!("closed trim primitive"),
            };
            LogicalValue::string(trimmed, limits).map_err(map_string_value_error)
        }
        Primitive::StringLowercase => {
            LogicalValue::string(to_full_lowercase(string_operand(operands, 0)?), limits)
                .map_err(map_string_value_error)
        }
        Primitive::StringUppercase => {
            LogicalValue::string(to_full_uppercase(string_operand(operands, 0)?), limits)
                .map_err(map_string_value_error)
        }
        Primitive::StringReplace => {
            let source = string_operand(operands, 0)?;
            let from = string_operand(operands, 1)?;
            let to = string_operand(operands, 2)?;
            if from.is_empty() {
                return Err(RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::StringEmptyPattern,
                ));
            }
            LogicalValue::string(source.replace(from, to), limits).map_err(map_string_value_error)
        }
        Primitive::StringSplit => {
            let source = string_operand(operands, 0)?;
            let separator = string_operand(operands, 1)?;
            if separator.is_empty() {
                return Err(RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::StringEmptySeparator,
                ));
            }
            let items = source
                .split(separator)
                .map(|item| LogicalValue::string(item, limits).map_err(map_string_value_error))
                .collect::<Result<Vec<_>, _>>()?;
            LogicalValue::list(items, limits).map_err(map_list_value_error)
        }
        Primitive::StringParseBool => {
            let value = match string_operand(operands, 0)? {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            };
            value.map_or_else(
                || Ok(LogicalValue::none()),
                |value| {
                    LogicalValue::some(LogicalValue::boolean(value), limits)
                        .map_err(map_value_error)
                },
            )
        }
        Primitive::StringParseInt => parse_int(string_operand(operands, 0)?).map_or_else(
            || Ok(LogicalValue::none()),
            |value| {
                LogicalValue::some(LogicalValue::integer(value), limits).map_err(map_value_error)
            },
        ),
        Primitive::StringParseFloat => parse_float(string_operand(operands, 0)?).map_or_else(
            || Ok(LogicalValue::none()),
            |value| LogicalValue::some(LogicalValue::float(value), limits).map_err(map_value_error),
        ),
        Primitive::StringListJoin => {
            let LogicalValueView::List(length) = operands[0].view() else {
                return Err(RuntimeCode::InternalInvariant);
            };
            let separator = string_operand(operands, 1)?;
            let mut output = String::new();
            for index in 0..length {
                if index > 0 {
                    output.push_str(separator);
                }
                let item = operands[0]
                    .member(index)
                    .ok_or(RuntimeCode::InternalInvariant)?;
                output.push_str(item.as_string().ok_or(RuntimeCode::InternalInvariant)?);
            }
            LogicalValue::string(output, limits).map_err(map_string_value_error)
        }
    }
}

#[derive(Clone, Copy)]
enum NumericBinary {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
}

fn numeric_binary(
    operands: &[LogicalValue],
    operation: NumericBinary,
) -> Result<LogicalValue, RuntimeCode> {
    match (operands[0].view(), operands[1].view()) {
        (LogicalValueView::Int(left), LogicalValueView::Int(right)) => {
            let result = match operation {
                NumericBinary::Add => left.checked_add(right),
                NumericBinary::Subtract => left.checked_sub(right),
                NumericBinary::Multiply => left.checked_mul(right),
                NumericBinary::Divide => left.checked_div(right),
                NumericBinary::Remainder => left.checked_rem(right),
            }
            .map_err(RuntimeCode::Deterministic)?;
            Ok(LogicalValue::integer(result))
        }
        (LogicalValueView::Float(left), LogicalValueView::Float(right)) => {
            let result = match operation {
                NumericBinary::Add => left.checked_add(right),
                NumericBinary::Subtract => left.checked_sub(right),
                NumericBinary::Multiply => left.checked_mul(right),
                NumericBinary::Divide => left.checked_div(right),
                NumericBinary::Remainder => return Err(RuntimeCode::InternalInvariant),
            }
            .map_err(RuntimeCode::Deterministic)?;
            Ok(LogicalValue::float(result))
        }
        _ => Err(RuntimeCode::InternalInvariant),
    }
}

fn compare_numeric(
    operands: &[LogicalValue],
    comparison: Comparison,
) -> Result<LogicalValue, RuntimeCode> {
    let result = match (operands[0].view(), operands[1].view()) {
        (LogicalValueView::Int(left), LogicalValueView::Int(right)) => {
            compare_order(left.cmp(&right), comparison)
        }
        (LogicalValueView::Float(left), LogicalValueView::Float(right)) => {
            let ordering = left
                .partial_cmp(&right)
                .ok_or(RuntimeCode::InternalInvariant)?;
            compare_order(ordering, comparison)
        }
        _ => return Err(RuntimeCode::InternalInvariant),
    };
    Ok(LogicalValue::boolean(result))
}

fn compare_order(ordering: std::cmp::Ordering, comparison: Comparison) -> bool {
    match comparison {
        Comparison::Less => ordering.is_lt(),
        Comparison::LessOrEqual => !ordering.is_gt(),
        Comparison::Greater => ordering.is_gt(),
        Comparison::GreaterOrEqual => !ordering.is_lt(),
    }
}

fn bool_operand(operands: &[LogicalValue], index: usize) -> Result<bool, RuntimeCode> {
    match operands[index].view() {
        LogicalValueView::Bool(value) => Ok(value),
        _ => Err(RuntimeCode::InternalInvariant),
    }
}

fn condition_value(value: &LogicalValue) -> Option<bool> {
    match value.view() {
        LogicalValueView::Bool(value) => Some(value),
        LogicalValueView::Decision { decision, .. } => Some(decision),
        _ => None,
    }
}

fn int_operand(operands: &[LogicalValue], index: usize) -> Result<GantryInt, RuntimeCode> {
    match operands[index].view() {
        LogicalValueView::Int(value) => Ok(value),
        _ => Err(RuntimeCode::InternalInvariant),
    }
}

fn float_operand(operands: &[LogicalValue], index: usize) -> Result<GantryFloat, RuntimeCode> {
    match operands[index].view() {
        LogicalValueView::Float(value) => Ok(value),
        _ => Err(RuntimeCode::InternalInvariant),
    }
}

fn string_operand(operands: &[LogicalValue], index: usize) -> Result<&str, RuntimeCode> {
    operands[index]
        .as_string()
        .ok_or(RuntimeCode::InternalInvariant)
}

fn length_value(length: usize) -> Result<LogicalValue, RuntimeCode> {
    let length = i64::try_from(length).map_err(|_| RuntimeCode::InternalInvariant)?;
    GantryInt::new(length)
        .map(LogicalValue::integer)
        .ok_or(RuntimeCode::InternalInvariant)
}

fn parse_int(value: &str) -> Option<GantryInt> {
    if value == "0" {
        return GantryInt::new(0);
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if unsigned.starts_with('0')
        || unsigned.is_empty()
        || !unsigned.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse::<i64>().ok().and_then(GantryInt::new)
}

fn parse_float(value: &str) -> Option<GantryFloat> {
    let bytes = value.as_bytes();
    if bytes
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        || bytes
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        return None;
    }
    let maximum_bytes = u64::try_from(bytes.len()).ok()?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: 1,
            maximum_nodes: 1,
            maximum_string_scalars: 1,
            maximum_list_items: 1,
        },
    )
    .ok()?;
    let JsonNode::Number(number) = document.node(document.root())? else {
        return None;
    };
    number.to_gantry_float().ok().and_then(GantryFloat::new)
}

fn value_matches_type(value: &LogicalValue, expected: &TypeDescriptor) -> bool {
    use gantry_ir::generated::TypeKind;

    let mut work = vec![(value.clone(), expected.clone())];
    while let Some((value, expected)) = work.pop() {
        match expected.kind() {
            TypeKind::Unit if matches!(value.view(), LogicalValueView::Unit) => {}
            TypeKind::Bool if matches!(value.view(), LogicalValueView::Bool(_)) => {}
            TypeKind::Int if matches!(value.view(), LogicalValueView::Int(_)) => {}
            TypeKind::Float if matches!(value.view(), LogicalValueView::Float(_)) => {}
            TypeKind::String if matches!(value.view(), LogicalValueView::String(_)) => {}
            TypeKind::Declared => match value.view() {
                LogicalValueView::Struct { type_name, .. }
                | LogicalValueView::Enum { type_name, .. }
                    if expected
                        .declared_path()
                        .is_some_and(|path| path.as_str() == type_name) => {}
                _ => return false,
            },
            TypeKind::Option => {
                let members = expected.immediate_members();
                if members.len() != 1 {
                    return false;
                }
                match value.view() {
                    LogicalValueView::Option { is_some: false } => {}
                    LogicalValueView::Option { is_some: true } => {
                        let Some(payload) = value.payload() else {
                            return false;
                        };
                        work.push((payload, members[0].clone()));
                    }
                    _ => return false,
                }
            }
            TypeKind::Result => {
                let members = expected.immediate_members();
                let LogicalValueView::Result { is_ok } = value.view() else {
                    return false;
                };
                if members.len() != 2 {
                    return false;
                }
                let Some(payload) = value.payload() else {
                    return false;
                };
                work.push((payload, members[usize::from(!is_ok)].clone()));
            }
            TypeKind::List => {
                let members = expected.immediate_members();
                let LogicalValueView::List(length) = value.view() else {
                    return false;
                };
                if members.len() != 1 {
                    return false;
                }
                for index in (0..length).rev() {
                    let Some(item) = value.member(index) else {
                        return false;
                    };
                    work.push((item, members[0].clone()));
                }
            }
            TypeKind::Tuple => {
                let members = expected.immediate_members();
                let LogicalValueView::Tuple(length) = value.view() else {
                    return false;
                };
                if length != members.len() {
                    return false;
                }
                for (index, member) in members.into_iter().enumerate().rev() {
                    let Some(item) = value.member(index) else {
                        return false;
                    };
                    work.push((item, member));
                }
            }
            TypeKind::Decision if matches!(value.view(), LogicalValueView::Decision { .. }) => {}
            TypeKind::OperationError
                if matches!(value.view(), LogicalValueView::OperationError(_)) => {}
            _ => return false,
        }
    }
    true
}

fn map_value_error(error: ValueError) -> RuntimeCode {
    match error {
        ValueError::ResourceLimit {
            kind: ValueLimitKind::StringScalars,
            ..
        } => RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
        ValueError::ResourceLimit {
            kind: ValueLimitKind::ListItems,
            ..
        } => RuntimeCode::Deterministic(DeterministicEvaluationCode::ListSizeLimit),
        ValueError::ResourceLimit { .. }
        | ValueError::TupleArity
        | ValueError::EmptyName
        | ValueError::DuplicateField(_)
        | ValueError::EmptyDecisionRationale
        | ValueError::EmptyOperationErrorText
        | ValueError::InvalidPath { .. } => RuntimeCode::InternalInvariant,
    }
}

fn map_string_value_error(error: ValueError) -> RuntimeCode {
    match error {
        ValueError::ResourceLimit { .. } => {
            RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit)
        }
        _ => RuntimeCode::InternalInvariant,
    }
}

fn map_list_value_error(error: ValueError) -> RuntimeCode {
    match error {
        ValueError::ResourceLimit {
            kind: ValueLimitKind::ListItems,
            ..
        } => RuntimeCode::Deterministic(DeterministicEvaluationCode::ListSizeLimit),
        ValueError::ResourceLimit {
            kind: ValueLimitKind::StringScalars,
            ..
        } => RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
        _ => RuntimeCode::InternalInvariant,
    }
}

fn position_key(position: &StructuralPosition) -> String {
    position
        .components()
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn operation_key(
    execution: ProtocolIdentity,
    workflow: &CanonicalPath,
    site: &StructuralPosition,
    path: &[Arc<str>],
) -> Vec<u8> {
    let mut output = String::from("{\"execution\":");
    push_json_string(&mut output, &execution.to_string());
    output.push_str(",\"path\":[");
    for (index, frame) in path.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, frame);
    }
    output.push_str("],\"site\":[");
    for (index, component) in site.components().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, &component.to_string());
    }
    output.push_str("],\"workflow\":");
    push_json_string(&mut output, workflow.as_str());
    output.push('}');
    output.into_bytes()
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            value if value <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}
