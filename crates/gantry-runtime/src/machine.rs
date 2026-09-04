//! Explicit-frame transition machine implementation.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{DeterministicEvaluationCode, IdentityKind};
use gantry_core::strict_json::{JsonLimits, JsonNode, StrictJsonDocument};
use gantry_core::unicode::{is_white_space, to_full_lowercase, to_full_uppercase};
use gantry_core::value::{LogicalValue, LogicalValueView, ValueError, ValueLimitKind, ValueLimits};
use gantry_ir::generated::Effect;
use gantry_ir::{
    AggregateKind, CanonicalCallableIdentity, CanonicalPath, Comparison, ExecutableOperation,
    Instruction, InstructionKind, LoopPhase, MachineProgram, Primitive, Projection,
    StructuralPosition, TypeDescriptor,
};

use crate::session::SessionCreationModeV1;

#[cfg(feature = "durable")]
pub(crate) mod checkpoint_codec;
#[cfg(feature = "durable")]
use checkpoint_codec::{
    decode_execution_budget_snapshot, decode_machine_checkpoint, encode_execution_budget_snapshot,
    encode_machine_checkpoint,
};
#[cfg(feature = "durable")]
mod program_codec;
#[cfg(feature = "durable")]
pub(crate) use program_codec::{decode_machine_program, encode_machine_program};

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
            || maximum_deterministic_transitions
                .checked_add(maximum_operations)
                .is_none()
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

/// Shared owner of counters limited across every task in one execution.
#[derive(Clone, Debug)]
pub struct ExecutionBudget {
    inner: Arc<Mutex<ExecutionBudgetState>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutionBudgetState {
    execution: ProtocolIdentity,
    maximum_transitions: u64,
    maximum_operations: u64,
    remaining_transitions: u64,
    remaining_operations: u64,
    revision: u64,
}

/// Immutable point-in-time projection of one execution's shared counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudgetSnapshot {
    /// Execution identity bound to these counters.
    pub execution: ProtocolIdentity,
    /// Configured maximum deterministic transitions.
    pub maximum_transitions: u64,
    /// Configured maximum logical operation preparations.
    pub maximum_operations: u64,
    /// Deterministic transitions still available.
    pub remaining_transitions: u64,
    /// Logical operation preparations still available.
    pub remaining_operations: u64,
    /// Monotonic successful-charge revision.
    pub revision: u64,
}

impl ExecutionBudget {
    /// Creates identity-bound execution counters from configured machine limits.
    #[must_use]
    pub fn new(execution: ProtocolIdentity, limits: MachineLimits) -> Self {
        Self::from_snapshot(ExecutionBudgetSnapshot {
            execution,
            maximum_transitions: limits.maximum_deterministic_transitions,
            maximum_operations: limits.maximum_operations,
            remaining_transitions: limits.maximum_deterministic_transitions,
            remaining_operations: limits.maximum_operations,
            revision: 0,
        })
    }

    fn from_snapshot(snapshot: ExecutionBudgetSnapshot) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExecutionBudgetState {
                execution: snapshot.execution,
                maximum_transitions: snapshot.maximum_transitions,
                maximum_operations: snapshot.maximum_operations,
                remaining_transitions: snapshot.remaining_transitions,
                remaining_operations: snapshot.remaining_operations,
                revision: snapshot.revision,
            })),
        }
    }

    /// Recovers one shared execution budget from a validated durable projection.
    #[cfg(feature = "durable")]
    pub fn recover_from_checkpoint(
        checkpoint: ExecutionBudgetSnapshot,
    ) -> Result<Self, MachineRecoveryError> {
        validate_execution_budget_snapshot(&checkpoint)?;
        Ok(Self::from_snapshot(checkpoint))
    }

    /// Captures all execution-wide counters at one linearization point.
    #[must_use]
    pub fn snapshot(&self) -> ExecutionBudgetSnapshot {
        let state = self.lock();
        ExecutionBudgetSnapshot {
            execution: state.execution,
            maximum_transitions: state.maximum_transitions,
            maximum_operations: state.maximum_operations,
            remaining_transitions: state.remaining_transitions,
            remaining_operations: state.remaining_operations,
            revision: state.revision,
        }
    }

    fn lock(&self) -> MutexGuard<'_, ExecutionBudgetState> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn matches(&self, execution: ProtocolIdentity, limits: MachineLimits) -> bool {
        let state = self.lock();
        state.execution == execution
            && state.maximum_transitions == limits.maximum_deterministic_transitions
            && state.maximum_operations == limits.maximum_operations
    }

    fn remaining(&self) -> (u64, u64) {
        let state = self.lock();
        (state.remaining_transitions, state.remaining_operations)
    }

    fn charge_transition(state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let Some(remaining) = state.remaining_transitions.checked_sub(1) else {
            return Err(RuntimeCode::DeterministicTransitionBudget);
        };
        let Some(revision) = state.revision.checked_add(1) else {
            return Err(RuntimeCode::InternalInvariant);
        };
        state.remaining_transitions = remaining;
        state.revision = revision;
        Ok(())
    }

    fn charge_operation(state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let Some(remaining) = state.remaining_operations.checked_sub(1) else {
            return Err(RuntimeCode::OperationBudget);
        };
        let Some(revision) = state.revision.checked_add(1) else {
            return Err(RuntimeCode::InternalInvariant);
        };
        state.remaining_operations = remaining;
        state.revision = revision;
        Ok(())
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

#[cfg(feature = "durable")]
impl ExecutionBudgetSnapshot {
    /// Encodes this validated projection as its unique binary representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_execution_budget_snapshot(self)
    }

    /// Decodes and validates one canonical execution-budget projection.
    pub fn decode(bytes: &[u8]) -> Result<Self, MachineRecoveryError> {
        decode_execution_budget_snapshot(bytes)
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
    /// The configured executor rejected an already accepted root task.
    RootSubmissionFailure,
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
            Self::RootSubmissionFailure => "root-submission-failure",
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
    /// The task identity or canonical task path does not match the execution.
    InvalidTaskIdentity,
    /// The shared budget belongs to another execution or configured maxima.
    ExecutionBudgetMismatch,
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

/// Already-durable completion coordinates preserved by an execution-wide failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionFailureProjection {
    /// No task or execution completion coordinate is durable yet.
    Full,
    /// Task settlement is durable; only foreground and terminal coordinates remain.
    AfterTaskSettlement,
    /// Foreground completion is durable; only terminal completion remains.
    AfterForegroundCompletion,
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
    /// Stable identity of the task executing this operation.
    pub task_id: ProtocolIdentity,
    /// Canonical dynamic path of the task executing this operation.
    pub task_path: Arc<[Arc<str>]>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    value: LogicalValue,
    ty: TypeDescriptor,
    mutable: bool,
}

type Scope = BTreeMap<Arc<str>, Binding>;

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingOperation {
    occurrence: OperationOccurrence,
    operands: usize,
}

/// Complete task-local checkpoint for the existing explicit-frame machine.
///
/// The durable recovery projection treats this as typed logical state rather
/// than a serialization of Rust memory layout. Fields remain private so only
/// validated construction and recovery can create runnable machine state.
#[cfg(feature = "durable")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineCheckpointV3 {
    execution: ProtocolIdentity,
    task_id: ProtocolIdentity,
    task_path: Arc<[Arc<str>]>,
    execution_foreground: bool,
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
    remaining_loop_iterations: u64,
    consecutive_transitions: u64,
    pending_session_scope: Option<SessionScopeOccurrence>,
    pending_operation: Option<PendingOperation>,
    pending_labels: VecDeque<MachineLabel>,
    cancellation: Option<Arc<str>>,
    status: MachineStatus,
    outcome: Option<MachineOutcome>,
}

#[cfg(feature = "durable")]
impl MachineCheckpointV3 {
    /// Returns the accepted execution identity represented by this checkpoint.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution
    }

    /// Returns the stable task identity represented by this checkpoint.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns the canonical task path represented by this checkpoint.
    #[must_use]
    pub fn task_path(&self) -> &[Arc<str>] {
        &self.task_path
    }

    /// Returns the machine limits represented by this checkpoint.
    pub(crate) const fn machine_limits(&self) -> MachineLimits {
        self.limits
    }

    /// Returns whether this checkpoint owns execution foreground/terminal labels.
    #[cfg(feature = "concurrent")]
    #[must_use]
    pub const fn is_execution_foreground(&self) -> bool {
        self.execution_foreground
    }

    /// Returns the value limits captured for this machine run.
    #[must_use]
    pub const fn value_limits(&self) -> ValueLimits {
        self.limits.value_limits
    }

    /// Returns the logical operation awaiting source-visible completion, when any.
    #[must_use]
    pub fn pending_operation(&self) -> Option<&OperationOccurrence> {
        self.pending_operation
            .as_ref()
            .map(|pending| &pending.occurrence)
    }

    /// Returns the first effective cancellation reason retained by this checkpoint.
    #[must_use]
    pub fn cancellation_reason(&self) -> Option<&str> {
        self.cancellation.as_deref()
    }

    /// Returns the fixed machine outcome retained by this checkpoint, when terminal.
    #[must_use]
    pub const fn outcome(&self) -> Option<&MachineOutcome> {
        self.outcome.as_ref()
    }

    /// Returns the exact coarse state represented by this checkpoint.
    #[must_use]
    pub const fn status(&self) -> MachineStatus {
        self.status
    }

    /// Returns the remaining task-local loop-entry budget.
    #[must_use]
    pub const fn remaining_loop_iterations(&self) -> u64 {
        self.remaining_loop_iterations
    }

    /// Encodes this task-local checkpoint as the unique version-three binary representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_machine_checkpoint(self)
    }

    /// Decodes one exact version-three checkpoint against its immutable program.
    pub fn decode(program: &MachineProgram, bytes: &[u8]) -> Result<Self, MachineRecoveryError> {
        decode_machine_checkpoint(program, bytes)
    }
}

/// Rejection of malformed or program-incompatible durable machine state.
#[cfg(feature = "durable")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineRecoveryError {
    /// Checkpoint bytes are truncated, noncanonical, or use an unsupported version.
    InvalidEncoding,
    /// The checkpoint violates a typed machine invariant.
    InvalidCheckpoint,
    /// A checkpoint frame or operation no longer resolves in the supplied program.
    ProgramMismatch,
    /// The supplied shared budget belongs to another execution or configured maxima.
    ExecutionBudgetMismatch,
}

/// One task-neutral explicit-frame machine.
#[derive(Clone, Debug)]
pub struct Machine {
    program: Arc<MachineProgram>,
    execution: ProtocolIdentity,
    task_id: ProtocolIdentity,
    task_path: Arc<[Arc<str>]>,
    execution_foreground: bool,
    limits: MachineLimits,
    execution_budget: ExecutionBudget,
    frames: Vec<WorkflowFrame>,
    values: Vec<LogicalValue>,
    occurrences: Vec<Arc<str>>,
    counters: BTreeMap<String, u64>,
    source_loop_entries: BTreeMap<String, u64>,
    agent: Option<Arc<str>>,
    agent_stack: Vec<Option<Arc<str>>>,
    session: Option<ProtocolIdentity>,
    session_stack: Vec<Option<ProtocolIdentity>>,
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

    /// Creates a root task using counters shared by its execution's machines.
    pub fn new_with_budget(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
        limits: MachineLimits,
        execution_budget: ExecutionBudget,
    ) -> Result<Self, MachineBuildError> {
        Self::new_task_context(
            program,
            root,
            arguments,
            execution,
            root_task_identity(execution),
            Arc::from([]),
            limits,
            execution_budget,
            None,
            None,
            true,
            true,
        )
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
        let execution_budget = ExecutionBudget::new(execution, limits);
        Self::new_task_context(
            program,
            root,
            arguments,
            execution,
            root_task_identity(execution),
            Arc::from([]),
            limits,
            execution_budget,
            initial_agent,
            initial_session,
            true,
            true,
        )
    }

    /// Creates one spawned task over the same explicit-frame evaluator.
    ///
    /// Child settlement emits `TaskSettled` but does not fabricate root-only
    /// foreground or terminal execution labels. Concurrent effect metadata is
    /// admitted because the execution-scoped scheduler owns task expansion.
    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_concurrent_task_with_context(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_path: Arc<[Arc<str>]>,
        limits: MachineLimits,
        execution_budget: ExecutionBudget,
        initial_agent: Option<Arc<str>>,
        initial_session: Option<ProtocolIdentity>,
    ) -> Result<Self, MachineBuildError> {
        Self::new_concurrent_task_with_budget_and_context(
            program,
            root,
            arguments,
            execution,
            task_id,
            task_path,
            limits,
            execution_budget,
            initial_agent,
            initial_session,
        )
    }

    /// Creates a spawned task using counters shared by its execution's machines.
    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_concurrent_task_with_budget_and_context(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_path: Arc<[Arc<str>]>,
        limits: MachineLimits,
        execution_budget: ExecutionBudget,
        initial_agent: Option<Arc<str>>,
        initial_session: Option<ProtocolIdentity>,
    ) -> Result<Self, MachineBuildError> {
        Self::new_task_context(
            program,
            root,
            arguments,
            execution,
            task_id,
            task_path,
            limits,
            execution_budget,
            initial_agent,
            initial_session,
            false,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_task_context(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_path: Arc<[Arc<str>]>,
        limits: MachineLimits,
        execution_budget: ExecutionBudget,
        initial_agent: Option<Arc<str>>,
        initial_session: Option<ProtocolIdentity>,
        execution_foreground: bool,
        reject_concurrent_effects: bool,
    ) -> Result<Self, MachineBuildError> {
        if execution.kind() != IdentityKind::Execution {
            return Err(MachineBuildError::InvalidExecutionIdentity);
        }
        if task_id != expected_task_identity(execution, &task_path)?
            || execution_foreground != task_path.is_empty()
        {
            return Err(MachineBuildError::InvalidTaskIdentity);
        }
        if !execution_budget.matches(execution, limits) {
            return Err(MachineBuildError::ExecutionBudgetMismatch);
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
        if reject_concurrent_effects && let Some(effect) = program.unsupported_effect(root_index) {
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
            task_id,
            task_path,
            execution_foreground,
            limits,
            execution_budget,
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

    /// Returns the accepted execution identity shared by this task machine.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution
    }

    /// Returns this machine's stable task identity.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns this machine's canonical task path; the root path is empty.
    #[must_use]
    pub fn task_path(&self) -> &[Arc<str>] {
        &self.task_path
    }

    /// Returns the active dynamic agent restored for the next operation.
    #[must_use]
    pub fn active_agent(&self) -> Option<&str> {
        self.agent.as_deref()
    }

    /// Returns the active logical session restored for the next operation.
    #[must_use]
    pub const fn active_session(&self) -> Option<ProtocolIdentity> {
        self.session
    }

    /// Returns whether this machine owns execution foreground/terminal labels.
    #[cfg(feature = "concurrent")]
    #[must_use]
    pub const fn is_execution_foreground(&self) -> bool {
        self.execution_foreground
    }

    /// Returns a clone of this machine's execution-wide budget owner.
    #[cfg(feature = "concurrent")]
    #[must_use]
    pub fn execution_budget(&self) -> ExecutionBudget {
        self.execution_budget.clone()
    }

    /// Validates this child machine against its scheduler-owned task coordinate.
    #[cfg(feature = "concurrent")]
    pub(crate) fn has_concurrent_task_context(
        &self,
        task_id: ProtocolIdentity,
        task_path: &[Arc<str>],
    ) -> bool {
        !self.execution_foreground
            && self.task_id == task_id
            && self.task_path.as_ref() == task_path
    }

    /// Returns the fixed foreground outcome, when terminal.
    #[must_use]
    pub fn outcome(&self) -> Option<&MachineOutcome> {
        self.outcome.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn test_instruction_state(&self) -> (usize, usize, bool) {
        (
            self.frames.last().map_or(usize::MAX, |frame| frame.pc),
            self.values.len(),
            self.pending_operation.is_some(),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_fail_current(&mut self, code: RuntimeCode) -> MachineStep {
        self.fail_current(code)
    }

    /// Returns remaining deterministic, operation, and loop-entry budgets.
    #[must_use]
    pub fn remaining_budgets(&self) -> (u64, u64, u64) {
        let (remaining_transitions, remaining_operations) = self.execution_budget.remaining();
        (
            remaining_transitions,
            remaining_operations,
            self.remaining_loop_iterations,
        )
    }

    /// Captures complete typed state at one durable checkpoint boundary.
    #[cfg(feature = "durable")]
    #[must_use]
    pub fn checkpoint(&self) -> MachineCheckpointV3 {
        MachineCheckpointV3 {
            execution: self.execution,
            task_id: self.task_id,
            task_path: Arc::clone(&self.task_path),
            execution_foreground: self.execution_foreground,
            limits: self.limits,
            frames: self.frames.clone(),
            values: self.values.clone(),
            occurrences: self.occurrences.clone(),
            counters: self.counters.clone(),
            source_loop_entries: self.source_loop_entries.clone(),
            agent: self.agent.clone(),
            agent_stack: self.agent_stack.clone(),
            session: self.session,
            session_stack: self.session_stack.clone(),
            remaining_loop_iterations: self.remaining_loop_iterations,
            consecutive_transitions: self.consecutive_transitions,
            pending_session_scope: self.pending_session_scope.clone(),
            pending_operation: self.pending_operation.clone(),
            pending_labels: self.pending_labels.clone(),
            cancellation: self.cancellation.clone(),
            status: self.status,
            outcome: self.outcome.clone(),
        }
    }

    /// Captures the shared execution budget at one linearization point.
    #[cfg(feature = "durable")]
    #[must_use]
    pub fn budget_checkpoint(&self) -> ExecutionBudgetSnapshot {
        self.execution_budget.snapshot()
    }

    /// Reconstructs the same evaluator using its separately recovered shared budget.
    #[cfg(feature = "durable")]
    pub fn recover_from_checkpoint(
        program: Arc<MachineProgram>,
        checkpoint: MachineCheckpointV3,
        execution_budget: ExecutionBudget,
    ) -> Result<Self, MachineRecoveryError> {
        Self::recover_from_checkpoint_with_budget(program, checkpoint, execution_budget)
    }

    /// Reconstructs task-local state after validating the shared budget identity and maxima.
    #[cfg(feature = "durable")]
    pub fn recover_from_checkpoint_with_budget(
        program: Arc<MachineProgram>,
        checkpoint: MachineCheckpointV3,
        execution_budget: ExecutionBudget,
    ) -> Result<Self, MachineRecoveryError> {
        validate_machine_checkpoint(&program, &checkpoint)?;
        if !execution_budget.matches(checkpoint.execution, checkpoint.limits) {
            return Err(MachineRecoveryError::ExecutionBudgetMismatch);
        }
        Ok(Self {
            program,
            execution: checkpoint.execution,
            task_id: checkpoint.task_id,
            task_path: checkpoint.task_path,
            execution_foreground: checkpoint.execution_foreground,
            limits: checkpoint.limits,
            execution_budget,
            frames: checkpoint.frames,
            values: checkpoint.values,
            occurrences: checkpoint.occurrences,
            counters: checkpoint.counters,
            source_loop_entries: checkpoint.source_loop_entries,
            agent: checkpoint.agent,
            agent_stack: checkpoint.agent_stack,
            session: checkpoint.session,
            session_stack: checkpoint.session_stack,
            remaining_loop_iterations: checkpoint.remaining_loop_iterations,
            consecutive_transitions: checkpoint.consecutive_transitions,
            pending_session_scope: checkpoint.pending_session_scope,
            pending_operation: checkpoint.pending_operation,
            pending_labels: checkpoint.pending_labels,
            cancellation: checkpoint.cancellation,
            status: checkpoint.status,
            outcome: checkpoint.outcome,
        })
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

    /// Fixes executor rejection of an already accepted root as a runtime failure.
    pub fn fail_root_submission(&mut self) -> MachineLabel {
        match self.fail_current(RuntimeCode::RootSubmissionFailure) {
            MachineStep::Transition(label) => label,
            _ => unreachable!("root submission failure emits one transition"),
        }
    }

    /// Fixes an execution-wide runtime failure while preserving completion cuts
    /// that are already durable.
    pub fn fail_execution(
        &mut self,
        category: gantry_core::portable::RuntimeErrorCategory,
        projection: ExecutionFailureProjection,
    ) -> MachineLabel {
        self.pending_labels.clear();
        let label = match self.fail_current(RuntimeCode::Operation(category)) {
            MachineStep::Transition(label) => label,
            _ => unreachable!("execution failure emits one transition"),
        };
        match projection {
            ExecutionFailureProjection::Full => {}
            ExecutionFailureProjection::AfterTaskSettlement => {
                let _ = self.pending_labels.pop_front();
            }
            ExecutionFailureProjection::AfterForegroundCompletion => {
                let _ = self.pending_labels.pop_front();
                let _ = self.pending_labels.pop_front();
            }
        }
        label
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
        let execution_budget = self.execution_budget.clone();
        let mut budget_state = execution_budget.lock();
        let site = instruction.site.clone();
        let kind_name = instruction_name(&instruction.kind);
        let result = match instruction.kind {
            InstructionKind::Push(value) => self.push_value(value, &mut budget_state),
            InstructionKind::Load(name) => self.load_binding(&name, &mut budget_state),
            InstructionKind::Bind { name, ty, mutable } => {
                self.bind_value(name, ty, mutable, &mut budget_state)
            }
            InstructionKind::Assign {
                name,
                path,
                target_type,
            } => self.assign_value(&name, &path, &target_type, &mut budget_state),
            InstructionKind::Pop => self.pop_value(&mut budget_state),
            InstructionKind::Aggregate { kind, operands } => {
                self.construct_aggregate(kind, operands, &mut budget_state)
            }
            InstructionKind::Project(projection) => {
                self.project_value(projection, &mut budget_state)
            }
            InstructionKind::Primitive(primitive) => {
                self.apply_primitive(primitive, &mut budget_state)
            }
            InstructionKind::EnterScope => self.enter_scope(&mut budget_state),
            InstructionKind::ExitScope => self.exit_scope(&mut budget_state),
            InstructionKind::Jump(target) => self.jump(target, &mut budget_state),
            InstructionKind::Branch {
                when_true,
                when_false,
            } => self.branch(&workflow, &site, when_true, when_false, &mut budget_state),
            InstructionKind::BranchOption {
                when_some,
                when_none,
            } => self.branch_option(&workflow, &site, when_some, when_none, &mut budget_state),
            InstructionKind::BranchEnum { arms } => {
                self.branch_enum(&workflow, &site, &arms, &mut budget_state)
            }
            InstructionKind::EnterLoop {
                phase,
                source_limit,
            } => self.enter_loop(&workflow, &site, phase, source_limit, &mut budget_state),
            InstructionKind::LeaveOccurrence => self.leave_occurrence(&mut budget_state),
            InstructionKind::Call { callee, arguments } => {
                return self.call(workflow, site, callee, arguments, &mut budget_state);
            }
            InstructionKind::Return => {
                return self.return_value(workflow, site, &mut budget_state);
            }
            InstructionKind::Spawn { .. }
            | InstructionKind::Join { .. }
            | InstructionKind::JoinAll { .. }
            | InstructionKind::Detach { .. }
            | InstructionKind::TaskComplete => {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            }
            InstructionKind::Operation => {
                return self.prepare_operation(workflow, instruction, 0, &mut budget_state);
            }
            InstructionKind::OperationWithOperands { operands } => {
                return self.prepare_operation(workflow, instruction, operands, &mut budget_state);
            }
            InstructionKind::OperationCall { operands, .. } => {
                return self.prepare_operation(workflow, instruction, operands, &mut budget_state);
            }
            InstructionKind::EnterAgent(agent) => self.enter_agent(agent, &mut budget_state),
            InstructionKind::ExitAgent => self.exit_agent(&mut budget_state),
            InstructionKind::EnterSession(mode) => {
                return self.enter_session(workflow, site, &mode, &mut budget_state);
            }
            InstructionKind::ExitSession => self.exit_session(&mut budget_state),
            InstructionKind::CancellationCheck => unreachable!("checks are consumed by step"),
        };
        match result {
            Ok(()) => self.finish_deterministic(workflow, site, kind_name),
            Err(code) => self.fail_at(code, workflow, site),
        }
    }

    fn push_value(
        &mut self,
        value: LogicalValue,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        value
            .validate(self.limits.value_limits)
            .map_err(map_value_error)?;
        self.charge_transition(budget_state)?;
        self.values.push(value);
        self.advance_pc();
        Ok(())
    }

    fn load_binding(
        &mut self,
        name: &str,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        let value = self
            .binding(name)
            .map(|binding| binding.value.clone())
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition(budget_state)?;
        self.values.push(value);
        self.advance_pc();
        Ok(())
    }

    fn bind_value(
        &mut self,
        name: Arc<str>,
        ty: TypeDescriptor,
        mutable: bool,
        budget_state: &mut ExecutionBudgetState,
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
        self.charge_transition(budget_state)?;
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
        budget_state: &mut ExecutionBudgetState,
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
        self.charge_transition(budget_state)?;
        self.values.pop();
        self.binding_mut(name)
            .ok_or(RuntimeCode::InternalInvariant)?
            .value = candidate;
        self.advance_pc();
        Ok(())
    }

    fn pop_value(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        if self.values.is_empty() {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition(budget_state)?;
        self.values.pop();
        self.advance_pc();
        Ok(())
    }

    fn construct_aggregate(
        &mut self,
        kind: AggregateKind,
        operands: usize,
        budget_state: &mut ExecutionBudgetState,
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
        self.charge_transition(budget_state)?;
        self.truncate_operands(operands);
        self.values.push(candidate);
        self.advance_pc();
        Ok(())
    }

    fn project_value(
        &mut self,
        projection: Projection,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
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
        self.charge_transition(budget_state)?;
        self.values.pop();
        self.values.push(projected);
        self.advance_pc();
        Ok(())
    }

    fn apply_primitive(
        &mut self,
        primitive: Primitive,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        let arity = primitive.arity();
        let operands = self.peek_operands(arity)?;
        let result = evaluate_primitive(primitive, operands, self.limits.value_limits)?;
        self.charge_transition(budget_state)?;
        self.truncate_operands(arity);
        self.values.push(result);
        self.advance_pc();
        Ok(())
    }

    fn enter_scope(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        self.charge_transition(budget_state)?;
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .scopes
            .push(Scope::new());
        self.advance_pc();
        Ok(())
    }

    fn exit_scope(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let frame = self.frames.last().ok_or(RuntimeCode::InternalInvariant)?;
        if frame.scopes.len() <= 1 {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition(budget_state)?;
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .scopes
            .pop();
        self.advance_pc();
        Ok(())
    }

    fn jump(
        &mut self,
        target: usize,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        self.charge_transition(budget_state)?;
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
        budget_state: &mut ExecutionBudgetState,
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
        self.charge_transition(budget_state)?;
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
        budget_state: &mut ExecutionBudgetState,
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
        self.charge_transition(budget_state)?;
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

    fn branch_enum(
        &mut self,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
        arms: &[(Arc<str>, usize)],
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        let value = self
            .values
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        let LogicalValueView::Enum {
            variant,
            has_payload,
            ..
        } = value.view()
        else {
            return Err(RuntimeCode::InternalInvariant);
        };
        let (arm, target) = arms
            .iter()
            .enumerate()
            .find_map(|(index, (candidate, target))| {
                (candidate.as_ref() == variant).then_some((index, *target))
            })
            .ok_or(RuntimeCode::InternalInvariant)?;
        let payload = has_payload
            .then(|| value.payload().ok_or(RuntimeCode::InternalInvariant))
            .transpose()?;
        let occurrence = Arc::from(format!(
            "branch:{}:{}:{arm}",
            workflow.as_str(),
            position_key(site)
        ));
        self.charge_transition(budget_state)?;
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
        budget_state: &mut ExecutionBudgetState,
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
        self.charge_transition(budget_state)?;
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

    fn leave_occurrence(
        &mut self,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        let base = self
            .frames
            .last()
            .map(|frame| frame.occurrence_base)
            .ok_or(RuntimeCode::InternalInvariant)?;
        if self.occurrences.len() <= base {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition(budget_state)?;
        self.occurrences.pop();
        self.advance_pc();
        Ok(())
    }

    fn call(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        callee: CanonicalCallableIdentity,
        arguments: usize,
        budget_state: &mut ExecutionBudgetState,
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
        let Some(callee_index) = self.program.callable_index(&callee) else {
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
        if let Err(code) = self.charge_transition(budget_state) {
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

    fn return_value(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        budget_state: &mut ExecutionBudgetState,
    ) -> MachineStep {
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
        if let Err(code) = self.charge_transition(budget_state) {
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
        budget_state: &mut ExecutionBudgetState,
    ) -> MachineStep {
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
        if let Err(code) = ExecutionBudget::charge_operation(budget_state) {
            return self.fail_at(code, workflow, instruction.site);
        }
        let operation_frame = self.next_occurrence("operation", &workflow, &instruction.site, None);
        let mut path = self.task_path.to_vec();
        path.extend(self.occurrences.iter().cloned());
        path.push(operation_frame);
        let key = operation_key(self.execution, &workflow, &instruction.site, &path);
        let identity = match ProtocolIdentity::derive(IdentityKind::Operation, &key) {
            Ok(identity) => identity,
            Err(_) => {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, instruction.site);
            }
        };
        self.advance_pc();
        let occurrence = OperationOccurrence {
            identity,
            task_id: self.task_id,
            task_path: Arc::clone(&self.task_path),
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

    fn enter_agent(
        &mut self,
        agent: Arc<str>,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        self.charge_transition(budget_state)?;
        self.agent_stack.push(self.agent.replace(agent));
        self.advance_pc();
        Ok(())
    }

    fn exit_agent(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let previous = self
            .agent_stack
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition(budget_state)?;
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
        budget_state: &mut ExecutionBudgetState,
    ) -> MachineStep {
        if let Err(code) = self.charge_transition(budget_state) {
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

    fn exit_session(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let previous = self
            .session_stack
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition(budget_state)?;
        self.session_stack.pop();
        self.session = previous;
        self.advance_pc();
        Ok(())
    }

    fn charge_transition(
        &mut self,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        ExecutionBudget::charge_transition(budget_state)?;
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
        if self.execution_foreground {
            self.pending_labels
                .push_back(MachineLabel::ForegroundCompletion(outcome.clone()));
            self.pending_labels
                .push_back(MachineLabel::TerminalCompletion(outcome.clone()));
        }
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
        if self.execution_foreground {
            self.pending_labels
                .push_back(MachineLabel::ForegroundCompletion(outcome.clone()));
            self.pending_labels
                .push_back(MachineLabel::TerminalCompletion(outcome));
        }
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

#[cfg(feature = "durable")]
fn validate_execution_budget_snapshot(
    snapshot: &ExecutionBudgetSnapshot,
) -> Result<(), MachineRecoveryError> {
    let consumed_transitions = snapshot
        .maximum_transitions
        .checked_sub(snapshot.remaining_transitions);
    let consumed_operations = snapshot
        .maximum_operations
        .checked_sub(snapshot.remaining_operations);
    let consumed = consumed_transitions
        .zip(consumed_operations)
        .and_then(|(transitions, operations)| transitions.checked_add(operations));
    if snapshot.execution.kind() != IdentityKind::Execution
        || snapshot.maximum_transitions == 0
        || snapshot.maximum_operations == 0
        || snapshot
            .maximum_transitions
            .checked_add(snapshot.maximum_operations)
            .is_none()
        || consumed != Some(snapshot.revision)
    {
        return Err(MachineRecoveryError::InvalidCheckpoint);
    }
    Ok(())
}

#[cfg(feature = "durable")]
fn validate_machine_checkpoint(
    program: &MachineProgram,
    checkpoint: &MachineCheckpointV3,
) -> Result<(), MachineRecoveryError> {
    if checkpoint.execution.kind() != IdentityKind::Execution
        || !matches!(
            expected_task_identity(checkpoint.execution, &checkpoint.task_path),
            Ok(expected) if expected == checkpoint.task_id
        )
        || checkpoint.execution_foreground != checkpoint.task_path.is_empty()
        || checkpoint.frames.is_empty()
        || checkpoint.limits.maximum_deterministic_transitions == 0
        || checkpoint.limits.maximum_operations == 0
        || checkpoint.limits.maximum_loop_iterations == 0
        || checkpoint.limits.maximum_workflow_call_depth == 0
        || checkpoint.limits.deterministic_transition_yield_quantum == 0
        || checkpoint.remaining_loop_iterations > checkpoint.limits.maximum_loop_iterations
        || checkpoint.consecutive_transitions
            > checkpoint.limits.deterministic_transition_yield_quantum
        || checkpoint
            .session
            .is_some_and(|session| session.kind() != IdentityKind::Session)
        || checkpoint
            .session_stack
            .iter()
            .flatten()
            .any(|session| session.kind() != IdentityKind::Session)
        || checkpoint
            .values
            .iter()
            .any(|value| value.validate(checkpoint.limits.value_limits).is_err())
    {
        return Err(MachineRecoveryError::InvalidCheckpoint);
    }

    for frame in &checkpoint.frames {
        let workflow = program
            .workflows()
            .get(frame.workflow)
            .ok_or(MachineRecoveryError::ProgramMismatch)?;
        if frame.pc >= workflow.instructions.len()
            || frame.scopes.is_empty()
            || frame.stack_base > checkpoint.values.len()
            || frame.occurrence_base > checkpoint.occurrences.len()
            || frame.agent_stack_base > checkpoint.agent_stack.len()
            || frame.session_stack_base > checkpoint.session_stack.len()
            || frame
                .session_at_entry
                .is_some_and(|session| session.kind() != IdentityKind::Session)
        {
            return Err(MachineRecoveryError::InvalidCheckpoint);
        }
        for scope in &frame.scopes {
            for (name, binding) in scope {
                if name.is_empty()
                    || binding
                        .value
                        .validate(checkpoint.limits.value_limits)
                        .is_err()
                    || !value_matches_type(&binding.value, &binding.ty)
                {
                    return Err(MachineRecoveryError::InvalidCheckpoint);
                }
            }
        }
    }

    let pending_session_valid = checkpoint
        .pending_session_scope
        .as_ref()
        .is_none_or(|pending| {
            let Some(frame) = checkpoint.frames.last() else {
                return false;
            };
            let Some(workflow) = program.workflows().get(frame.workflow) else {
                return false;
            };
            pending.parent_session_id.kind() == IdentityKind::Session
                && workflow.path == pending.workflow
                && workflow
                    .instructions
                    .get(frame.pc)
                    .is_some_and(|instruction| {
                        instruction.site == pending.site
                            && matches!(instruction.kind, InstructionKind::EnterSession(_))
                    })
        });
    if !pending_session_valid {
        return Err(MachineRecoveryError::ProgramMismatch);
    }

    let pending_operation_valid = checkpoint.pending_operation.as_ref().is_none_or(|pending| {
        let occurrence = &pending.occurrence;
        let Some(frame) = checkpoint.frames.last() else {
            return false;
        };
        let Some(workflow) = program.workflows().get(frame.workflow) else {
            return false;
        };
        let Some(index) = frame.pc.checked_sub(1) else {
            return false;
        };
        let Some(instruction) = workflow.instructions.get(index) else {
            return false;
        };
        let (operands, metadata) = match &instruction.kind {
            InstructionKind::Operation => (0, None),
            InstructionKind::OperationWithOperands { operands } => (*operands, None),
            InstructionKind::OperationCall {
                operation,
                operands,
            } => (*operands, Some(operation)),
            _ => return false,
        };
        let identity_matches = ProtocolIdentity::derive(
            IdentityKind::Operation,
            &operation_key(
                checkpoint.execution,
                &occurrence.workflow,
                &occurrence.site,
                &occurrence.dynamic_path,
            ),
        )
        .is_ok_and(|expected| expected == occurrence.identity);
        occurrence.identity.kind() == IdentityKind::Operation
            && identity_matches
            && occurrence.task_id == checkpoint.task_id
            && occurrence.task_path == checkpoint.task_path
            && occurrence.dynamic_path.starts_with(&checkpoint.task_path)
            && occurrence
                .active_session
                .is_none_or(|session| session.kind() == IdentityKind::Session)
            && workflow.path == occurrence.workflow
            && instruction.site == occurrence.site
            && instruction.ty == occurrence.expected_type
            && pending.operands == operands
            && occurrence.metadata.as_deref() == metadata
            && pending.operands <= checkpoint.values.len()
    });
    if !pending_operation_valid {
        return Err(MachineRecoveryError::ProgramMismatch);
    }

    let state_valid = match (checkpoint.status, checkpoint.outcome.as_ref()) {
        (MachineStatus::Running | MachineStatus::YieldRequired, None) => {
            checkpoint.pending_session_scope.is_none() && checkpoint.pending_operation.is_none()
        }
        (MachineStatus::WaitingSessionScope, None) => {
            checkpoint.pending_session_scope.is_some() && checkpoint.pending_operation.is_none()
        }
        (MachineStatus::WaitingOperation, None) => {
            checkpoint.pending_operation.is_some() && checkpoint.pending_session_scope.is_none()
        }
        (MachineStatus::Succeeded, Some(MachineOutcome::Succeeded(value))) => {
            value.validate(checkpoint.limits.value_limits).is_ok()
        }
        (MachineStatus::Failed, Some(MachineOutcome::Failed(_)))
        | (MachineStatus::Cancelled, Some(MachineOutcome::Cancelled(_))) => true,
        _ => false,
    };
    if !state_valid {
        return Err(MachineRecoveryError::InvalidCheckpoint);
    }
    Ok(())
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
        InstructionKind::Branch { .. }
        | InstructionKind::BranchOption { .. }
        | InstructionKind::BranchEnum { .. } => "branch",
        InstructionKind::EnterLoop { .. } => "loop",
        InstructionKind::LeaveOccurrence => "occurrence-exit",
        InstructionKind::Call { .. } => "call",
        InstructionKind::Return => "return",
        InstructionKind::Spawn { .. } => "spawn",
        InstructionKind::Join { .. } => "join",
        InstructionKind::JoinAll { .. } => "joinall",
        InstructionKind::Detach { .. } => "detach",
        InstructionKind::TaskComplete => "task-complete",
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

pub(crate) fn value_matches_type(value: &LogicalValue, expected: &TypeDescriptor) -> bool {
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
                    if expected.canonical_string() == type_name => {}
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

/// Derives the established stable root-task identity.
#[must_use]
pub fn root_task_identity(execution: ProtocolIdentity) -> ProtocolIdentity {
    ProtocolIdentity::derive(
        IdentityKind::Task,
        format!("root-task:{execution}").as_bytes(),
    )
    .unwrap_or_else(|_| unreachable!("typed root task identity derivation is valid"))
}

fn expected_task_identity(
    execution: ProtocolIdentity,
    path: &[Arc<str>],
) -> Result<ProtocolIdentity, MachineBuildError> {
    if path.is_empty() {
        return Ok(root_task_identity(execution));
    }
    ProtocolIdentity::derive(IdentityKind::Task, &task_identity_key(execution, path))
        .map_err(|_| MachineBuildError::InvalidTaskIdentity)
}

pub(crate) fn task_identity_key(execution: ProtocolIdentity, path: &[Arc<str>]) -> Vec<u8> {
    let mut output = String::from("{\"execution\":");
    push_json_string(&mut output, &execution.to_string());
    output.push_str(",\"path\":[");
    for (index, frame) in path.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, frame);
    }
    output.push_str("]}");
    output.into_bytes()
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
