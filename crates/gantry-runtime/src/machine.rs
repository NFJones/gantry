//! Explicit-frame transition machine implementation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::limit::ResourceLimit;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{DeterministicEvaluationCode, IdentityKind};
use gantry_core::strict_json::{JsonLimits, JsonNode, StrictJsonDocument};
use gantry_core::unicode::{is_white_space, to_full_lowercase, to_full_uppercase};
use gantry_core::value::{
    LogicalValue, LogicalValueView, ValueError, ValueLimitKind, ValueLimits, ValuePathSegment,
};
use gantry_ir::generated::Effect;
use gantry_ir::{
    AggregateKind, CanonicalCallableIdentity, CanonicalPath, Comparison, ExecutableOperation,
    Instruction, InstructionKind, LoopPhase, MachineProgram, OwnershipClass, Parameter, Primitive,
    Projection, ReceiverMode, ReceiverSource, StructuralPosition, TypeDescriptor,
};
#[cfg(feature = "concurrent")]
use gantry_ir::{ExecutableTaskHandle, TaskBodyIdentity};

use crate::resource::ResourceSubjectBinding;
use crate::session::SessionCreationModeV1;
#[cfg(feature = "concurrent")]
use crate::task::{DynamicTaskHandleIdentity, JoinResolutionV1, TaskCaptureV1, TaskJoinFailureV1};

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
pub use program_codec::{decode_machine_program, encode_machine_program};

/// Semantic limits captured for one machine run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineLimits {
    /// Deterministic-transition policy for the execution.
    pub maximum_deterministic_transitions: ResourceLimit,
    /// Logical-operation policy for the execution.
    pub maximum_operations: ResourceLimit,
    /// Loop-entry policy for the task.
    pub maximum_loop_iterations: ResourceLimit,
    /// Workflow-frame policy, counting the root as one.
    pub maximum_workflow_call_depth: ResourceLimit,
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
                maximum_deterministic_transitions: match ResourceLimit::limited(
                    maximum_deterministic_transitions,
                ) {
                    Some(limit) => limit,
                    None => return None,
                },
                maximum_operations: match ResourceLimit::limited(maximum_operations) {
                    Some(limit) => limit,
                    None => return None,
                },
                maximum_loop_iterations: match ResourceLimit::limited(maximum_loop_iterations) {
                    Some(limit) => limit,
                    None => return None,
                },
                maximum_workflow_call_depth: match ResourceLimit::limited(
                    maximum_workflow_call_depth,
                ) {
                    Some(limit) => limit,
                    None => return None,
                },
                deterministic_transition_yield_quantum,
                value_limits,
            })
        }
    }

    /// Creates a machine with no semantic execution ceilings.
    #[must_use]
    pub const fn unlimited(
        deterministic_transition_yield_quantum: u64,
        value_limits: ValueLimits,
    ) -> Option<Self> {
        if deterministic_transition_yield_quantum == 0 {
            None
        } else {
            Some(Self {
                maximum_deterministic_transitions: ResourceLimit::Unlimited,
                maximum_operations: ResourceLimit::Unlimited,
                maximum_loop_iterations: ResourceLimit::Unlimited,
                maximum_workflow_call_depth: ResourceLimit::Unlimited,
                deterministic_transition_yield_quantum,
                value_limits,
            })
        }
    }

    /// Validates an explicit finite-or-unlimited machine-limit set.
    #[must_use]
    pub const fn with_resource_limits(
        maximum_deterministic_transitions: ResourceLimit,
        maximum_operations: ResourceLimit,
        maximum_loop_iterations: ResourceLimit,
        maximum_workflow_call_depth: ResourceLimit,
        deterministic_transition_yield_quantum: u64,
        value_limits: ValueLimits,
    ) -> Option<Self> {
        if deterministic_transition_yield_quantum == 0
            || matches!(
                (
                    maximum_deterministic_transitions.maximum(),
                    maximum_operations.maximum(),
                ),
                (Some(transitions), Some(operations))
                    if transitions.checked_add(operations).is_none()
            )
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
    maximum_transitions: ResourceLimit,
    maximum_operations: ResourceLimit,
    remaining_transitions: Option<u64>,
    remaining_operations: Option<u64>,
    revision: u64,
}

/// Immutable point-in-time projection of one execution's shared counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBudgetSnapshot {
    /// Execution identity bound to these counters.
    pub execution: ProtocolIdentity,
    /// Configured maximum deterministic transitions.
    pub maximum_transitions: ResourceLimit,
    /// Configured maximum logical operation preparations.
    pub maximum_operations: ResourceLimit,
    /// Deterministic transitions still available.
    pub remaining_transitions: Option<u64>,
    /// Logical operation preparations still available.
    pub remaining_operations: Option<u64>,
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
            remaining_transitions: limits.maximum_deterministic_transitions.maximum(),
            remaining_operations: limits.maximum_operations.maximum(),
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

    /// Publishes a validated durable budget frontier after its journal commit.
    ///
    /// The serialized durable owner must call this only after committing the
    /// corresponding machine cut. This observer budget must not drive machines;
    /// runnable durable machines use private staged projections instead.
    #[cfg(feature = "durable")]
    pub fn publish_committed_snapshot(
        &self,
        checkpoint: ExecutionBudgetSnapshot,
    ) -> Result<(), MachineRecoveryError> {
        validate_execution_budget_snapshot(&checkpoint)?;
        let mut state = self.lock();
        if state.execution != checkpoint.execution
            || state.maximum_transitions != checkpoint.maximum_transitions
            || state.maximum_operations != checkpoint.maximum_operations
            || state.remaining_transitions < checkpoint.remaining_transitions
            || state.remaining_operations < checkpoint.remaining_operations
            || state.revision > checkpoint.revision
        {
            return Err(MachineRecoveryError::ExecutionBudgetMismatch);
        }
        state.remaining_transitions = checkpoint.remaining_transitions;
        state.remaining_operations = checkpoint.remaining_operations;
        state.revision = checkpoint.revision;
        Ok(())
    }

    fn matches(&self, execution: ProtocolIdentity, limits: MachineLimits) -> bool {
        let state = self.lock();
        state.execution == execution
            && state.maximum_transitions == limits.maximum_deterministic_transitions
            && state.maximum_operations == limits.maximum_operations
    }

    fn remaining(&self) -> (Option<u64>, Option<u64>) {
        let state = self.lock();
        (state.remaining_transitions, state.remaining_operations)
    }

    fn charge_transition(state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let remaining = match state.remaining_transitions {
            Some(remaining) => Some(
                remaining
                    .checked_sub(1)
                    .ok_or(RuntimeCode::DeterministicTransitionBudget)?,
            ),
            None => None,
        };
        let Some(revision) = state.revision.checked_add(1) else {
            return Err(RuntimeCode::InternalInvariant);
        };
        state.remaining_transitions = remaining;
        state.revision = revision;
        Ok(())
    }

    fn charge_operation(state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let remaining = match state.remaining_operations {
            Some(remaining) => Some(
                remaining
                    .checked_sub(1)
                    .ok_or(RuntimeCode::OperationBudget)?,
            ),
            None => None,
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
    /// An integration unwind reached an owned task boundary without a narrower boundary result.
    IntegrationPanic,
    /// One source panic or checked assertion settled the enclosing callable as failed.
    SourcePanic,
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
            Self::IntegrationPanic => "integration-panic",
            Self::SourcePanic => "source-panic",
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
    /// Ordered member failures retained for `task-join-failure`.
    #[cfg(feature = "concurrent")]
    pub join_failure: Option<TaskJoinFailureV1>,
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
    /// One source task-control transition awaits coordinator completion.
    #[cfg(feature = "concurrent")]
    WaitingTaskControl,
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

/// One typed captured binding required to construct a spawned child machine.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineTaskCapture {
    capture: TaskCaptureV1,
}

#[cfg(feature = "concurrent")]
impl MachineTaskCapture {
    /// Returns the detached typed capture accepted by concurrent task state.
    #[must_use]
    pub const fn task_capture(&self) -> &TaskCaptureV1 {
        &self.capture
    }
}

/// Machine-owned spawn state that a coordinator must create and submit.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineSpawnSuspension {
    /// Canonical workflow containing the source spawn.
    pub workflow: CanonicalPath,
    /// Canonical structural spawn site.
    pub site: StructuralPosition,
    /// Zero-based dynamic occurrence at this spawn site.
    pub occurrence: u64,
    /// Lexical handle declaration published after submission settles.
    pub handle: ExecutableTaskHandle,
    /// Independently executable child body.
    pub body: TaskBodyIdentity,
    /// Analyzer-selected detached captures in declared order.
    pub captures: Vec<MachineTaskCapture>,
    /// Active agent inherited by the child under the v1 context contract.
    pub inherited_agent: Option<Arc<str>>,
    /// Active parent session snapshot, when established.
    pub parent_session: Option<ProtocolIdentity>,
}

/// One consumed lexical task handle supplied to coordinator-owned task control.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineTaskControlHandle {
    name: Arc<str>,
    handle: MachineTaskHandle,
}

#[cfg(feature = "concurrent")]
impl MachineTaskControlHandle {
    /// Returns the exact consumed lexical handle name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the scheduler-owned dynamic handle identity.
    #[must_use]
    pub const fn identity(&self) -> DynamicTaskHandleIdentity {
        self.handle.identity()
    }

    /// Returns the statically declared child result type.
    #[must_use]
    pub const fn result_type(&self) -> &TypeDescriptor {
        self.handle.result_type()
    }
}

/// Machine-owned all-settled join state awaiting coordinator resolution.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineJoinSuspension {
    /// Canonical workflow containing the source join.
    pub workflow: CanonicalPath,
    /// Canonical structural join site.
    pub site: StructuralPosition,
    /// Consumed handles in normative source or declaration order.
    pub handles: Vec<MachineTaskControlHandle>,
    /// Exact analyzed value type produced by successful completion.
    pub expected_type: TypeDescriptor,
}

/// Machine-owned detach state awaiting coordinator ownership transfer.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineDetachSuspension {
    /// Canonical workflow containing the source detach.
    pub workflow: CanonicalPath,
    /// Canonical structural detach site.
    pub site: StructuralPosition,
    /// Consumed lexical handle transferred to background ownership.
    pub handle: MachineTaskControlHandle,
}

/// Complete machine-side suspension exposed to a concurrent coordinator.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineTaskControlSuspension {
    /// Child creation and executor submission remain pending.
    Spawn(MachineSpawnSuspension),
    /// A named join remains pending.
    Join(MachineJoinSuspension),
    /// A declaration-order joinall remains pending.
    JoinAll(MachineJoinSuspension),
    /// A detach ownership transfer remains pending.
    Detach(MachineDetachSuspension),
}

#[cfg(feature = "concurrent")]
impl MachineTaskControlSuspension {
    /// Returns the pending spawn, when this is child creation.
    #[must_use]
    pub const fn spawn(&self) -> Option<&MachineSpawnSuspension> {
        match self {
            Self::Spawn(spawn) => Some(spawn),
            Self::Join(_) | Self::JoinAll(_) | Self::Detach(_) => None,
        }
    }

    /// Returns the pending join and whether it is a declaration-order joinall.
    #[must_use]
    pub const fn join(&self) -> Option<(&MachineJoinSuspension, bool)> {
        match self {
            Self::Join(join) => Some((join, false)),
            Self::JoinAll(join) => Some((join, true)),
            Self::Spawn(_) | Self::Detach(_) => None,
        }
    }

    /// Returns the pending detach, when this is an ownership transfer.
    #[must_use]
    pub const fn detach(&self) -> Option<&MachineDetachSuspension> {
        match self {
            Self::Detach(detach) => Some(detach),
            Self::Spawn(_) | Self::Join(_) | Self::JoinAll(_) => None,
        }
    }
}

/// Rejection while completing one suspended source spawn.
#[cfg(feature = "concurrent")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskControlCompletionError {
    /// No task-control operation is awaiting completion.
    NotWaiting,
    /// The supplied suspension is not the pending task-control operation.
    SuspensionMismatch,
    /// The dynamic handle is owned by another task or names a non-task identity.
    InvalidHandle,
    /// Cancellation made the pending completion nonconsumable.
    Cancelled,
    /// The lexical handle name is already visible in this scope.
    DuplicateHandle,
    /// The supplied completion kind does not match the pending suspension.
    CompletionMismatch,
    /// At least one joined task has not settled yet.
    JoinPending,
    /// A successful join value does not match its analyzed result type.
    TypeMismatch,
    /// A successful join value exceeds the captured machine value limits.
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
    /// One source spawn suspended before coordinator-owned child submission.
    #[cfg(feature = "concurrent")]
    TaskControlSuspended(MachineSpawnSuspension),
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

/// One coordinator-created dynamic task handle visible in a lexical machine scope.
#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineTaskHandle {
    identity: DynamicTaskHandleIdentity,
    result_type: TypeDescriptor,
}

#[cfg(feature = "concurrent")]
impl MachineTaskHandle {
    /// Returns the scheduler-owned dynamic handle identity.
    #[must_use]
    pub const fn identity(&self) -> DynamicTaskHandleIdentity {
        self.identity
    }

    /// Returns the declared result type of the child named by this handle.
    #[must_use]
    pub const fn result_type(&self) -> &TypeDescriptor {
        &self.result_type
    }
}

#[cfg(feature = "concurrent")]
type HandleScope = BTreeMap<Arc<str>, MachineTaskHandle>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkflowFrame {
    workflow: usize,
    pc: usize,
    scopes: Vec<Scope>,
    #[cfg(feature = "concurrent")]
    handle_scopes: Vec<HandleScope>,
    stack_base: usize,
    occurrence_base: usize,
    agent_stack_base: usize,
    agent_at_entry: Option<Arc<str>>,
    session_stack_base: usize,
    session_at_entry: Option<ProtocolIdentity>,
    receiver_admission: Option<SharedPlaceAdmission>,
    place_initialization: Vec<PlaceInitialization>,
    moved_out: Vec<MovedPlace>,
    consumption_obligation: Vec<ConsumptionObligation>,
}

/// Durable evidence that a callee frame was admitted through a shared caller place.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SharedPlaceAdmission {
    root: Arc<str>,
    path: Vec<ValuePathSegment>,
}

/// Durable evidence that a caller-place move left one subplace uninitialized.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PlaceInitialization {
    root: Arc<str>,
    path: Vec<ValuePathSegment>,
    /// Reserved bit: the wire layout keeps it so a checkpoint that claims an initialized staging
    /// entry is rejected, and every valid checkpoint must carry `false`, because a staging entry
    /// only exists while the moved-out subplace has not been reinitialized.
    initialized: bool,
}

/// Durable evidence that a completed owned call moved one caller place out.
///
/// The entry is recorded in the frame that owned the place, not in the callee frame that staged
/// the move, so the mark survives the callee-frame pop. The analyzer is the source-level guard
/// that rejects a read or admission of a moved-out place, and the machine enforces the same guard
/// dynamically as a defence in depth: a read of the moved-out place, a receiver or capture
/// admission of it, and a projection of an enclosing loaded value into one of its subplaces are
/// reported as an internal invariant violation rather than as a recoverable evaluation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MovedPlace {
    root: Arc<str>,
    path: Vec<ValuePathSegment>,
}

/// Durable evidence that one owned `MustConsume` admission has not been accounted for.
///
/// The obligation is recorded in the frame that owns the consumed caller place. A normal return
/// transfers it to the caller frame exactly like the moved-out mark, and a failure cut drains it
/// into the machine-level settled list so an unaccounted consumption is retained rather than
/// silently discarded together with the frames. A failure, a cancellation, and a successful root
/// return all settle the same way, so the evidence stays observable through
/// [`Machine::settled_consumption_obligations`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumptionObligation {
    pub(crate) root: Arc<str>,
    pub(crate) path: Vec<ValuePathSegment>,
}

impl ConsumptionObligation {
    /// Returns the binding root whose place staged an unaccounted `MustConsume` consumption.
    #[must_use]
    pub fn root(&self) -> &str {
        self.root.as_ref()
    }

    /// Returns the value path inside that root, empty for a whole-binding place.
    #[must_use]
    pub fn path(&self) -> &[ValuePathSegment] {
        &self.path
    }

    /// Orders two obligations by root and then by canonical path segments.
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| canonical_path_cmp(&self.path, &other.path))
    }
}

/// Records one consumption obligation in the frame that owns the consumed place.
///
/// Every existing intersecting entry is replaced, so a frame never records two intersecting
/// obligations and the resulting vector stays in canonical order.
fn record_consumption_obligation(
    frame: &mut WorkflowFrame,
    root: Arc<str>,
    path: Vec<ValuePathSegment>,
) {
    let entry = ConsumptionObligation { root, path };
    frame.consumption_obligation.retain(|existing| {
        !places_intersect(&existing.root, &existing.path, &entry.root, &entry.path)
    });
    frame.consumption_obligation.push(entry);
    frame
        .consumption_obligation
        .sort_by(ConsumptionObligation::canonical_cmp);
}

/// Two places intersect when they share one root and one path is a prefix of the other.
fn places_intersect(
    left_root: &str,
    left_path: &[ValuePathSegment],
    right_root: &str,
    right_path: &[ValuePathSegment],
) -> bool {
    left_root == right_root
        && (left_path.starts_with(right_path) || right_path.starts_with(left_path))
}

/// Ranks one path segment by the canonical wire tag of the checkpoint codec.
fn value_path_segment_rank(segment: &ValuePathSegment) -> u8 {
    match segment {
        ValuePathSegment::ListItem(_) => 0,
        ValuePathSegment::TupleMember(_) => 1,
        ValuePathSegment::StructField(_) => 2,
        ValuePathSegment::EnumPayload => 3,
        ValuePathSegment::OptionValue => 4,
        ValuePathSegment::ResultValue => 5,
    }
}

/// Orders two path segments by canonical tag and then by tag payload.
fn value_path_segment_cmp(left: &ValuePathSegment, right: &ValuePathSegment) -> Ordering {
    value_path_segment_rank(left)
        .cmp(&value_path_segment_rank(right))
        .then_with(|| match (left, right) {
            (ValuePathSegment::ListItem(left), ValuePathSegment::ListItem(right))
            | (ValuePathSegment::TupleMember(left), ValuePathSegment::TupleMember(right)) => {
                left.cmp(right)
            }
            (ValuePathSegment::StructField(left), ValuePathSegment::StructField(right)) => {
                left.cmp(right)
            }
            _ => Ordering::Equal,
        })
}

/// Orders two canonical path segments by their canonical segment order.
fn canonical_path_cmp(left: &[ValuePathSegment], right: &[ValuePathSegment]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = value_path_segment_cmp(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

impl MovedPlace {
    /// Orders two moved-out entries by root and then by canonical path segments.
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| canonical_path_cmp(&self.path, &other.path))
    }
}

/// Place origin of one staged value.
///
/// `Load` records the place it read and every `Project` extends that record, so a projection into
/// a moved-out subplace of an enclosing place can be detected even though reading the enclosing
/// place itself stays legal. The stack runs in lockstep with the staged value stack.
///
/// The origin is a read-guard hint, not an integrity mechanism. A runtime-produced checkpoint
/// carries the same origin list, and recovery restores it so the guard fires after resume, but a
/// forged or stripped origin is only a consistency concern: an adversary who can rewrite
/// checkpoint bytes can at most lose the guard optimization or be rejected. As with the moved-out
/// mark, recovery never derives a caller binding from this record.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedPlace {
    root: Arc<str>,
    path: Vec<ValuePathSegment>,
}

impl LoadedPlace {
    /// Returns this place extended by one projected path segment.
    fn extended(&self, segment: ValuePathSegment) -> Self {
        let mut path = Vec::with_capacity(self.path.len() + 1);
        path.extend_from_slice(&self.path);
        path.push(segment);
        Self {
            root: Arc::clone(&self.root),
            path,
        }
    }
}

/// Records one completed owned move in the frame that owned the caller place.
///
/// Every existing intersecting entry is replaced by the transferred one, so a frame never records
/// two intersecting moved-out places and the resulting vector stays in canonical order.
fn record_moved_out(frame: &mut WorkflowFrame, root: Arc<str>, path: Vec<ValuePathSegment>) {
    frame
        .moved_out
        .retain(|entry| !places_intersect(&entry.root, &entry.path, &root, &path));
    frame.moved_out.push(MovedPlace { root, path });
    frame.moved_out.sort_by(MovedPlace::canonical_cmp);
}

/// Resolves an immutable logical subvalue through an admitted caller-place path.
fn value_at_path(value: &LogicalValue, path: &[ValuePathSegment]) -> Option<LogicalValue> {
    let mut current = value.clone();
    for segment in path {
        current = match segment {
            ValuePathSegment::ListItem(index)
                if matches!(current.view(), LogicalValueView::List(_)) =>
            {
                current.member(*index)?
            }
            ValuePathSegment::TupleMember(index)
                if matches!(current.view(), LogicalValueView::Tuple(_)) =>
            {
                current.member(*index)?
            }
            ValuePathSegment::StructField(name)
                if matches!(current.view(), LogicalValueView::Struct { .. }) =>
            {
                current.field(name)?
            }
            ValuePathSegment::EnumPayload
                if matches!(
                    current.view(),
                    LogicalValueView::Enum {
                        has_payload: true,
                        ..
                    }
                ) =>
            {
                current.payload()?
            }
            ValuePathSegment::OptionValue
                if matches!(current.view(), LogicalValueView::Option { is_some: true }) =>
            {
                current.payload()?
            }
            ValuePathSegment::ResultValue
                if matches!(current.view(), LogicalValueView::Result { .. }) =>
            {
                current.payload()?
            }
            _ => return None,
        };
    }
    Some(current)
}

/// Returns the canonical path segment one list or tuple member projection addresses.
fn member_path_segment(source: &LogicalValue, index: usize) -> ValuePathSegment {
    match source.view() {
        LogicalValueView::Tuple(_) => ValuePathSegment::TupleMember(index),
        _ => ValuePathSegment::ListItem(index),
    }
}

/// Returns the canonical path segment one payload projection addresses.
fn payload_path_segment(source: &LogicalValue) -> ValuePathSegment {
    match source.view() {
        LogicalValueView::Enum { .. } => ValuePathSegment::EnumPayload,
        LogicalValueView::Option { .. } => ValuePathSegment::OptionValue,
        LogicalValueView::Result { .. } => ValuePathSegment::ResultValue,
        _ => ValuePathSegment::EnumPayload,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingOperation {
    occurrence: OperationOccurrence,
    operands: usize,
}

#[cfg(feature = "concurrent")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingTaskControl {
    suspension: MachineTaskControlSuspension,
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
    #[cfg(feature = "concurrent")]
    task_body: Option<TaskBodyIdentity>,
    limits: MachineLimits,
    frames: Vec<WorkflowFrame>,
    /// Obligations retained after a discarded frame, in canonical place order.
    settled_obligations: Vec<ConsumptionObligation>,
    values: Vec<LogicalValue>,
    /// Read-guard hints: the place origin of each staged value, in stack order.
    ///
    /// The list runs in lockstep with `values`. One origin is a read-guard hint for the projection
    /// guard rather than an integrity mechanism: a forged or missing origin on a runtime-produced
    /// checkpoint is a consistency concern, and an adversary who can rewrite checkpoint bytes can
    /// only disable the guard optimization or be rejected, never change the recovered bindings.
    values_places: Vec<Option<LoadedPlace>>,
    occurrences: Vec<Arc<str>>,
    counters: BTreeMap<String, u64>,
    source_loop_entries: BTreeMap<String, u64>,
    agent: Option<Arc<str>>,
    agent_stack: Vec<Option<Arc<str>>>,
    session: Option<ProtocolIdentity>,
    session_stack: Vec<Option<ProtocolIdentity>>,
    remaining_loop_iterations: Option<u64>,
    consecutive_transitions: u64,
    pending_session_scope: Option<SessionScopeOccurrence>,
    pending_operation: Option<PendingOperation>,
    #[cfg(feature = "concurrent")]
    pending_task_control: Option<PendingTaskControl>,
    pending_labels: VecDeque<MachineLabel>,
    cancellation: Option<Arc<str>>,
    status: MachineStatus,
    outcome: Option<MachineOutcome>,
}

/// Successor machine-checkpoint state encoded with `GNTMCP04` when v4-only
/// task-control state is present.
///
/// The state model remains source-compatible with [`MachineCheckpointV3`];
/// decoding accepts frozen v3 bytes while canonical encoding selects the
/// oldest wire version that can represent the state exactly.
#[cfg(feature = "durable")]
pub type MachineCheckpointV4 = MachineCheckpointV3;

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

    /// Returns the active logical session retained for the next operation.
    #[must_use]
    pub(crate) const fn active_session(&self) -> Option<ProtocolIdentity> {
        self.session
    }

    /// Returns the source spawn retained by this checkpoint, when suspended.
    #[cfg(feature = "concurrent")]
    pub(crate) fn pending_spawn_checkpoint(&self) -> Option<&MachineSpawnSuspension> {
        self.pending_task_control
            .as_ref()
            .and_then(|pending| pending.suspension.spawn())
    }

    /// Returns the exact pending task-control state for composed checkpoint validation.
    #[cfg(feature = "concurrent")]
    pub(crate) fn pending_task_control_checkpoint(&self) -> Option<&MachineTaskControlSuspension> {
        self.pending_task_control
            .as_ref()
            .map(|pending| &pending.suspension)
    }

    /// Iterates every recovered lexical task handle retained by this checkpoint.
    #[cfg(feature = "concurrent")]
    pub(crate) fn lexical_task_handles(&self) -> impl Iterator<Item = (&str, &MachineTaskHandle)> {
        self.frames.iter().flat_map(|frame| {
            frame
                .handle_scopes
                .iter()
                .flat_map(|scope| scope.iter().map(|(name, handle)| (name.as_ref(), handle)))
        })
    }

    /// Tests the exact machine-local successor produced by publishing one spawn handle.
    #[cfg(feature = "concurrent")]
    pub(crate) fn is_spawn_completion_successor(
        &self,
        previous: &Self,
        identity: DynamicTaskHandleIdentity,
    ) -> bool {
        let mut expected = previous.clone();
        let Some(pending) = expected.pending_task_control.take() else {
            return false;
        };
        let MachineTaskControlSuspension::Spawn(spawn) = pending.suspension else {
            return false;
        };
        if identity.owner() != expected.task_id
            || identity.child().kind() != IdentityKind::Task
            || expected.cancellation.is_some()
        {
            return false;
        }
        let Some(frame) = expected.frames.last_mut() else {
            return false;
        };
        let Some(scope) = frame.handle_scopes.last_mut() else {
            return false;
        };
        if scope
            .insert(
                Arc::from(spawn.handle.name()),
                MachineTaskHandle {
                    identity,
                    result_type: spawn.handle.result_type().clone(),
                },
            )
            .is_some()
        {
            return false;
        }
        frame.pc = frame.pc.saturating_add(1);
        expected.status = MachineStatus::Running;
        expected.consecutive_transitions = 0;
        expected == *self
    }

    /// Returns the remaining task-local loop-entry budget.
    #[must_use]
    pub const fn remaining_loop_iterations(&self) -> Option<u64> {
        self.remaining_loop_iterations
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_clear_receiver_admission(&mut self) -> bool {
        self.frames
            .last_mut()
            .and_then(|frame| frame.receiver_admission.take())
            .is_some()
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_add_receiver_admission_to_root(&mut self) -> bool {
        let Some(frame) = self.frames.first_mut() else {
            return false;
        };
        if frame.receiver_admission.is_some() {
            return false;
        }
        frame.receiver_admission = Some(SharedPlaceAdmission {
            root: Arc::from("item"),
            path: Vec::new(),
        });
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_receiver_admission_parent_mutable(&mut self, mutable: bool) -> bool {
        let Some(parent) = self.frames.iter_mut().rev().nth(1) else {
            return false;
        };
        let Some(binding) = parent
            .scopes
            .iter_mut()
            .rev()
            .find_map(|scope| scope.values_mut().next())
        else {
            return false;
        };
        binding.mutable = mutable;
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_receiver_admission_callee_mutable(&mut self, mutable: bool) -> bool {
        let Some(binding) = self
            .frames
            .last_mut()
            .and_then(|frame| frame.scopes.first_mut())
            .and_then(|scope| scope.get_mut("self"))
        else {
            return false;
        };
        binding.mutable = mutable;
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_receiver_admission_path(&mut self, path: Vec<ValuePathSegment>) -> bool {
        let Some(admission) = self
            .frames
            .last_mut()
            .and_then(|frame| frame.receiver_admission.as_mut())
        else {
            return false;
        };
        admission.path = path;
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_receiver_admission_callee_value(&mut self, value: LogicalValue) -> bool {
        let Some(binding) = self
            .frames
            .last_mut()
            .and_then(|frame| frame.scopes.first_mut())
            .and_then(|scope| scope.get_mut("self"))
        else {
            return false;
        };
        binding.value = value;
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_add_place_initialization(
        &mut self,
        frame_index: usize,
        root: &str,
        path: Vec<ValuePathSegment>,
    ) -> bool {
        let Some(frame) = self.frames.get_mut(frame_index) else {
            return false;
        };
        frame.place_initialization.push(PlaceInitialization {
            root: Arc::from(root),
            path,
            initialized: false,
        });
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_place_initialization_initialized(
        &mut self,
        frame_index: usize,
        entry_index: usize,
        initialized: bool,
    ) -> bool {
        self.frames
            .get_mut(frame_index)
            .and_then(|frame| frame.place_initialization.get_mut(entry_index))
            .is_some_and(|entry| {
                entry.initialized = initialized;
                true
            })
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_clear_place_initialization(&mut self) -> bool {
        self.frames.iter_mut().any(|frame| {
            let had_entry = !frame.place_initialization.is_empty();
            frame.place_initialization.clear();
            had_entry
        })
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_place_initialization_path(
        &mut self,
        frame_index: usize,
        entry_index: usize,
        path: Vec<ValuePathSegment>,
    ) -> bool {
        self.frames
            .get_mut(frame_index)
            .and_then(|frame| frame.place_initialization.get_mut(entry_index))
            .is_some_and(|entry| {
                entry.path = path;
                true
            })
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_add_moved_out(
        &mut self,
        frame_index: usize,
        root: &str,
        path: Vec<ValuePathSegment>,
    ) -> bool {
        let Some(frame) = self.frames.get_mut(frame_index) else {
            return false;
        };
        frame.moved_out.push(MovedPlace {
            root: Arc::from(root),
            path,
        });
        true
    }

    #[cfg(all(test, feature = "concurrent"))]
    pub(crate) fn test_set_pending_spawn_capture_value(
        &mut self,
        index: usize,
        value: LogicalValue,
    ) -> bool {
        let Some(capture) =
            self.pending_task_control
                .as_mut()
                .and_then(|pending| match &mut pending.suspension {
                    MachineTaskControlSuspension::Spawn(spawn) => spawn.captures.get_mut(index),
                    _ => None,
                })
        else {
            return false;
        };
        let current = capture.task_capture();
        let Ok(updated) = TaskCaptureV1::new(
            Arc::from(current.name()),
            current.ty().clone(),
            current.is_mutable(),
            &value,
            self.limits.value_limits,
        ) else {
            return false;
        };
        capture.capture = updated;
        true
    }

    #[cfg(all(test, feature = "concurrent"))]
    pub(crate) fn test_set_pending_spawn_inherited_agent(
        &mut self,
        agent: Option<Arc<str>>,
    ) -> bool {
        let Some(pending) = self.pending_task_control.as_mut() else {
            return false;
        };
        let MachineTaskControlSuspension::Spawn(spawn) = &mut pending.suspension else {
            return false;
        };
        spawn.inherited_agent = agent;
        true
    }

    #[cfg(all(test, feature = "concurrent"))]
    pub(crate) fn test_set_pending_spawn_parent_session(
        &mut self,
        session: Option<ProtocolIdentity>,
    ) -> bool {
        let Some(pending) = self.pending_task_control.as_mut() else {
            return false;
        };
        let MachineTaskControlSuspension::Spawn(spawn) = &mut pending.suspension else {
            return false;
        };
        spawn.parent_session = session;
        true
    }

    #[cfg(all(test, feature = "concurrent"))]
    pub(crate) fn test_set_pending_spawn_occurrence(&mut self, occurrence: u64) -> bool {
        let Some(pending) = self.pending_task_control.as_mut() else {
            return false;
        };
        let MachineTaskControlSuspension::Spawn(spawn) = &mut pending.suspension else {
            return false;
        };
        spawn.occurrence = occurrence;
        true
    }

    #[cfg(all(test, feature = "concurrent", feature = "durable"))]
    pub(crate) fn test_rename_task_capture(&mut self, name: &str) -> bool {
        let Some(scope) = self
            .frames
            .first_mut()
            .and_then(|frame| frame.scopes.first_mut())
        else {
            return false;
        };
        let Some((previous, binding)) = scope
            .iter()
            .next()
            .map(|(name, binding)| (name.clone(), binding.clone()))
        else {
            return false;
        };
        if previous.as_ref() == name {
            return false;
        }
        scope.remove(&previous);
        scope.insert(Arc::from(name), binding);
        true
    }

    #[cfg(all(test, feature = "concurrent", feature = "durable"))]
    pub(crate) fn test_set_task_capture_type(&mut self, ty: TypeDescriptor) -> bool {
        let Some(binding) = self
            .frames
            .first_mut()
            .and_then(|frame| frame.scopes.first_mut())
            .and_then(|scope| scope.values_mut().next())
        else {
            return false;
        };
        binding.ty = ty;
        true
    }

    #[cfg(all(test, feature = "concurrent", feature = "durable"))]
    pub(crate) fn test_set_task_capture_mutable(&mut self, mutable: bool) -> bool {
        let Some(binding) = self
            .frames
            .first_mut()
            .and_then(|frame| frame.scopes.first_mut())
            .and_then(|scope| scope.values_mut().next())
        else {
            return false;
        };
        binding.mutable = mutable;
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_rename_parameter_binding(&mut self, previous: &str, name: &str) -> bool {
        if previous == name {
            return false;
        }
        let Some(scope) = self
            .frames
            .first_mut()
            .and_then(|frame| frame.scopes.first_mut())
        else {
            return false;
        };
        let Some(binding) = scope.remove(previous) else {
            return false;
        };
        scope.insert(Arc::from(name), binding);
        true
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_parameter_binding_type(
        &mut self,
        name: &str,
        ty: TypeDescriptor,
    ) -> bool {
        self.frames
            .first_mut()
            .and_then(|frame| frame.scopes.first_mut())
            .and_then(|scope| scope.get_mut(name))
            .is_some_and(|binding| {
                binding.ty = ty;
                true
            })
    }

    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_set_parameter_binding_mutable(&mut self, name: &str, mutable: bool) -> bool {
        self.frames
            .first_mut()
            .and_then(|frame| frame.scopes.first_mut())
            .and_then(|scope| scope.get_mut(name))
            .is_some_and(|binding| {
                binding.mutable = mutable;
                true
            })
    }

    /// Encodes this checkpoint with the oldest exact machine wire representation.
    ///
    /// Legacy-representable state retains `GNTMCP03`; task-control state uses the successor
    /// `GNTMCP04` representation, and a recorded staged place origin uses the successor `GNTMCP08`
    /// representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_machine_checkpoint(self)
    }

    /// Decodes one exact `GNTMCP03` through `GNTMCP08` checkpoint.
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
    #[cfg(feature = "concurrent")]
    task_body: Option<TaskBodyIdentity>,
    execution: ProtocolIdentity,
    task_id: ProtocolIdentity,
    task_path: Arc<[Arc<str>]>,
    execution_foreground: bool,
    limits: MachineLimits,
    execution_budget: ExecutionBudget,
    frames: Vec<WorkflowFrame>,
    /// Obligations that survived a discarded frame, in canonical place order.
    settled_obligations: Vec<ConsumptionObligation>,
    values: Vec<LogicalValue>,
    values_places: Vec<Option<LoadedPlace>>,
    occurrences: Vec<Arc<str>>,
    counters: BTreeMap<String, u64>,
    source_loop_entries: BTreeMap<String, u64>,
    agent: Option<Arc<str>>,
    agent_stack: Vec<Option<Arc<str>>>,
    session: Option<ProtocolIdentity>,
    session_stack: Vec<Option<ProtocolIdentity>>,
    remaining_loop_iterations: Option<u64>,
    consecutive_transitions: u64,
    pending_session_scope: Option<SessionScopeOccurrence>,
    pending_operation: Option<PendingOperation>,
    #[cfg(feature = "concurrent")]
    pending_task_control: Option<PendingTaskControl>,
    pending_labels: VecDeque<MachineLabel>,
    cancellation: Option<Arc<str>>,
    status: MachineStatus,
    outcome: Option<MachineOutcome>,
}

impl Machine {
    /// Returns one frame's live consumption obligations in canonical place order.
    #[cfg(all(test, feature = "durable"))]
    pub(crate) fn test_consumption_obligations(
        &self,
        frame_index: usize,
    ) -> Option<&[ConsumptionObligation]> {
        self.frames
            .get(frame_index)
            .map(|frame| frame.consumption_obligation.as_slice())
    }

    /// Returns every `MustConsume` consumption obligation settled by a terminal cut.
    ///
    /// A terminal cut drains the obligations still live in the frames into this machine-level
    /// list, so a staged [`ConsumptionObligation`] that no path accounted for stays observable
    /// with the task's settled evidence instead of disappearing with the frames. A failure, a
    /// cancellation, and a successful root return settle the same way, the settlement is
    /// idempotent, and the list stays empty while the task is still running with only frame-level
    /// obligations.
    #[must_use]
    pub fn settled_consumption_obligations(&self) -> &[ConsumptionObligation] {
        &self.settled_obligations
    }

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

    /// Creates a concurrent-profile root using counters shared with child machines.
    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_concurrent_root_with_budget_and_context(
        program: Arc<MachineProgram>,
        root: &CanonicalPath,
        arguments: Vec<LogicalValue>,
        execution: ProtocolIdentity,
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
            root_task_identity(execution),
            Arc::from([]),
            limits,
            execution_budget,
            initial_agent,
            initial_session,
            true,
            false,
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

    /// Constructs a spawned body from its analyzer-selected typed captures and context.
    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_concurrent_task_body_with_context(
        program: Arc<MachineProgram>,
        body_identity: &TaskBodyIdentity,
        captures: &[TaskCaptureV1],
        execution: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_path: Arc<[Arc<str>]>,
        limits: MachineLimits,
        execution_budget: ExecutionBudget,
        inherited_agent: Option<Arc<str>>,
        child_session: Option<ProtocolIdentity>,
    ) -> Result<Self, MachineBuildError> {
        if execution.kind() != IdentityKind::Execution {
            return Err(MachineBuildError::InvalidExecutionIdentity);
        }
        if task_id != expected_task_identity(execution, &task_path)? || task_path.is_empty() {
            return Err(MachineBuildError::InvalidTaskIdentity);
        }
        if !execution_budget.matches(execution, limits) {
            return Err(MachineBuildError::ExecutionBudgetMismatch);
        }
        if child_session.is_some_and(|session| session.kind() != IdentityKind::Session) {
            return Err(MachineBuildError::InvalidSessionIdentity);
        }
        let body = program
            .task_body(body_identity)
            .ok_or(MachineBuildError::MissingRoot)?;
        if captures.len() != body.captures().len() {
            return Err(MachineBuildError::ArgumentCount);
        }
        let mut root_scope = Scope::new();
        for expected in body.captures() {
            let capture = captures
                .iter()
                .find(|capture| capture.name() == expected.name())
                .ok_or(MachineBuildError::ArgumentCount)?;
            capture
                .value()
                .validate(limits.value_limits)
                .map_err(MachineBuildError::Value)?;
            if capture.ty() != expected.ty()
                || capture.is_mutable() != expected.is_mutable()
                || !value_matches_type(capture.value(), expected.ty())
            {
                return Err(MachineBuildError::ArgumentType);
            }
            root_scope.insert(
                Arc::from(expected.name()),
                Binding {
                    value: capture.value().clone(),
                    ty: expected.ty().clone(),
                    mutable: expected.is_mutable(),
                },
            );
        }
        let workflow = program
            .callable_index(body_identity.enclosing_callable())
            .ok_or(MachineBuildError::MissingRoot)?;
        Ok(Self {
            program,
            task_body: Some(body_identity.clone()),
            execution,
            task_id,
            task_path,
            execution_foreground: false,
            limits,
            execution_budget,
            frames: vec![WorkflowFrame {
                workflow,
                pc: 0,
                scopes: vec![root_scope],
                handle_scopes: vec![HandleScope::new()],
                stack_base: 0,
                occurrence_base: 0,
                agent_stack_base: 0,
                agent_at_entry: None,
                session_stack_base: 0,
                session_at_entry: None,
                receiver_admission: None,
                place_initialization: Vec::new(),
                moved_out: Vec::new(),
                consumption_obligation: Vec::new(),
            }],
            settled_obligations: Vec::new(),
            values: Vec::new(),
            values_places: Vec::new(),
            occurrences: Vec::new(),
            counters: BTreeMap::new(),
            source_loop_entries: BTreeMap::new(),
            agent: inherited_agent,
            agent_stack: Vec::new(),
            session: child_session,
            session_stack: Vec::new(),
            remaining_loop_iterations: limits.maximum_loop_iterations.maximum(),
            consecutive_transitions: 0,
            pending_session_scope: None,
            pending_operation: None,
            pending_task_control: None,
            pending_labels: VecDeque::new(),
            cancellation: None,
            status: MachineStatus::Running,
            outcome: None,
        })
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
            #[cfg(feature = "concurrent")]
            task_body: None,
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
                #[cfg(feature = "concurrent")]
                handle_scopes: vec![HandleScope::new()],
                stack_base: 0,
                occurrence_base: 0,
                agent_stack_base: 0,
                agent_at_entry: None,
                session_stack_base: 0,
                session_at_entry: None,
                receiver_admission: None,
                place_initialization: Vec::new(),
                moved_out: Vec::new(),
                consumption_obligation: Vec::new(),
            }],
            settled_obligations: Vec::new(),
            values: Vec::new(),
            values_places: Vec::new(),
            occurrences: Vec::new(),
            counters: BTreeMap::new(),
            source_loop_entries: BTreeMap::new(),
            agent: initial_agent,
            agent_stack: Vec::new(),
            session: initial_session,
            session_stack: Vec::new(),
            remaining_loop_iterations: limits.maximum_loop_iterations.maximum(),
            consecutive_transitions: 0,
            pending_session_scope: None,
            pending_operation: None,
            #[cfg(feature = "concurrent")]
            pending_task_control: None,
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
    #[cfg(any(feature = "concurrent", feature = "durable"))]
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

    /// Resolves one coordinator-published lexical task handle visible to this frame.
    #[cfg(feature = "concurrent")]
    #[must_use]
    pub fn task_handle(&self, name: &str) -> Option<&MachineTaskHandle> {
        self.frames
            .last()?
            .handle_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name))
    }

    /// Returns the source spawn still awaiting coordinator completion, if any.
    #[cfg(feature = "concurrent")]
    #[must_use]
    pub fn pending_spawn(&self) -> Option<&MachineSpawnSuspension> {
        self.pending_task_control
            .as_ref()
            .and_then(|pending| pending.suspension.spawn())
    }

    /// Returns the exact source task-control operation awaiting coordinator work.
    #[cfg(feature = "concurrent")]
    #[must_use]
    pub fn pending_task_control(&self) -> Option<&MachineTaskControlSuspension> {
        self.pending_task_control
            .as_ref()
            .map(|pending| &pending.suspension)
    }

    /// Returns the immutable program used to validate a durable graph transition.
    #[cfg(feature = "durable")]
    pub(crate) fn program_arc(&self) -> Arc<MachineProgram> {
        Arc::clone(&self.program)
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
    pub(crate) fn test_value_stack_alignment(&self) -> (usize, usize) {
        (self.values.len(), self.values_places.len())
    }

    #[cfg(test)]
    pub(crate) fn test_binding_value(&self, name: &str) -> Option<LogicalValue> {
        self.binding(name).map(|binding| binding.value.clone())
    }

    #[cfg(test)]
    pub(crate) fn test_frame_binding_value(
        &self,
        frame_index: usize,
        name: &str,
    ) -> Option<LogicalValue> {
        self.frames
            .get(frame_index)?
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name))
            .map(|binding| binding.value.clone())
    }

    #[cfg(test)]
    pub(crate) fn test_fail_current(&mut self, code: RuntimeCode) -> MachineStep {
        self.fail_current(code)
    }

    /// Returns remaining deterministic, operation, and loop-entry budgets.
    #[must_use]
    pub fn remaining_budgets(&self) -> (Option<u64>, Option<u64>, Option<u64>) {
        let (remaining_transitions, remaining_operations) = self.execution_budget.remaining();
        (
            remaining_transitions,
            remaining_operations,
            self.remaining_loop_iterations,
        )
    }

    /// Derives the Section 20 resource subject of the pending operation occurrence.
    ///
    /// The subject is derived from this machine's own occurrence facts — the pending operation's
    /// canonical workflow, structural site, and decoded operation metadata — and the machine's own
    /// per-site counter that numbered that occurrence, so no caller can name another operation. An
    /// occurrence whose decoded metadata declares no action has no resource subject.
    #[must_use]
    pub fn pending_resource_subject(&self) -> Option<ResourceSubjectBinding> {
        let occurrence = self
            .pending_operation
            .as_ref()
            .map(|pending| &pending.occurrence)?;
        let metadata = occurrence.metadata.as_deref()?;
        let generation = self
            .counters
            .get(&self.counter_key("operation", &occurrence.workflow, &occurrence.site))?
            .checked_sub(1)?;
        ResourceSubjectBinding::from_declared_operation(
            &occurrence.workflow,
            &occurrence.site,
            metadata,
            generation,
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
            #[cfg(feature = "concurrent")]
            task_body: self.task_body.clone(),
            limits: self.limits,
            frames: self.frames.clone(),
            settled_obligations: self.settled_obligations.clone(),
            values: self.values.clone(),
            values_places: self.values_places.clone(),
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
            #[cfg(feature = "concurrent")]
            pending_task_control: self.pending_task_control.clone(),
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

    /// Copies a privately owned durable machine with an independent budget.
    ///
    /// This is a rollback/staging projection, not a new sibling task. The caller
    /// must exclusively own this machine while capturing it; ordinary machine
    /// clones continue sharing their execution-wide budget.
    #[cfg(feature = "durable")]
    pub(crate) fn clone_durable_projection(&self) -> Self {
        let mut projection = self.clone();
        projection.execution_budget =
            ExecutionBudget::from_snapshot(self.execution_budget.snapshot());
        projection
    }

    /// Copies task-local state onto the private shared budget of a staged graph.
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    pub(crate) fn clone_with_staged_budget(
        &self,
        budget: ExecutionBudget,
    ) -> Result<Self, MachineRecoveryError> {
        if !budget.matches(self.execution, self.limits) {
            return Err(MachineRecoveryError::ExecutionBudgetMismatch);
        }
        let mut staged = self.clone();
        staged.execution_budget = budget;
        Ok(staged)
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
            #[cfg(feature = "concurrent")]
            task_body: checkpoint.task_body,
            execution: checkpoint.execution,
            task_id: checkpoint.task_id,
            task_path: checkpoint.task_path,
            execution_foreground: checkpoint.execution_foreground,
            limits: checkpoint.limits,
            execution_budget,
            frames: checkpoint.frames,
            settled_obligations: checkpoint.settled_obligations,
            // Staged values resume with the place origins the checkpoint recorded, so the
            // projection guard still fires after recovery. A wire form that cannot carry origins
            // resumes every staged value without one.
            values_places: checkpoint.values_places,
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
            #[cfg(feature = "concurrent")]
            pending_task_control: checkpoint.pending_task_control,
            pending_labels: checkpoint.pending_labels,
            cancellation: checkpoint.cancellation,
            status: checkpoint.status,
            outcome: checkpoint.outcome,
        })
    }

    /// Publishes the coordinator-created dynamic handle and resumes after spawn submission.
    #[cfg(feature = "concurrent")]
    pub fn complete_spawn(
        &mut self,
        suspension: &MachineSpawnSuspension,
        identity: DynamicTaskHandleIdentity,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        self.complete_spawn_inner(suspension, identity, false)
    }

    /// Publishes a created child after cancellation has already become effective.
    ///
    /// This preserves the ordinary [`Self::complete_spawn`] rejection after
    /// cancellation while allowing a durable task-settlement cut to expose the
    /// same lexical handle before the cancelled parent is polled to settlement.
    #[cfg(feature = "concurrent")]
    #[doc(hidden)]
    pub fn complete_cancelled_spawn(
        &mut self,
        suspension: &MachineSpawnSuspension,
        identity: DynamicTaskHandleIdentity,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        self.complete_spawn_inner(suspension, identity, true)
    }

    #[cfg(feature = "concurrent")]
    fn complete_spawn_inner(
        &mut self,
        suspension: &MachineSpawnSuspension,
        identity: DynamicTaskHandleIdentity,
        allow_cancelled: bool,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        let pending = self
            .pending_task_control
            .as_ref()
            .ok_or(TaskControlCompletionError::NotWaiting)?;
        if pending.suspension.spawn() != Some(suspension) {
            return Err(TaskControlCompletionError::SuspensionMismatch);
        }
        if identity.owner() != self.task_id || identity.child().kind() != IdentityKind::Task {
            return Err(TaskControlCompletionError::InvalidHandle);
        }
        if self.cancellation.is_some() && !allow_cancelled {
            return Err(TaskControlCompletionError::Cancelled);
        }
        let scope = self
            .frames
            .last_mut()
            .and_then(|frame| frame.handle_scopes.last_mut())
            .ok_or(TaskControlCompletionError::NotWaiting)?;
        if scope.contains_key(suspension.handle.name()) {
            return Err(TaskControlCompletionError::DuplicateHandle);
        }
        scope.insert(
            Arc::from(suspension.handle.name()),
            MachineTaskHandle {
                identity,
                result_type: suspension.handle.result_type().clone(),
            },
        );
        self.advance_pc();
        self.pending_task_control = None;
        self.status = MachineStatus::Running;
        self.consecutive_transitions = 0;
        Ok(MachineLabel::Deterministic {
            workflow: suspension.workflow.clone(),
            site: suspension.site.clone(),
            kind: Arc::from("spawn-complete"),
        })
    }

    /// Fails the exact pending source spawn with one typed runtime code.
    #[cfg(feature = "concurrent")]
    pub fn fail_spawn(
        &mut self,
        suspension: &MachineSpawnSuspension,
        code: RuntimeCode,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        let pending = self
            .pending_task_control
            .as_ref()
            .ok_or(TaskControlCompletionError::NotWaiting)?;
        if pending.suspension.spawn() != Some(suspension) {
            return Err(TaskControlCompletionError::SuspensionMismatch);
        }
        if self.cancellation.is_some() {
            return Err(TaskControlCompletionError::Cancelled);
        }
        match self.fail_at(code, suspension.workflow.clone(), suspension.site.clone()) {
            MachineStep::Transition(label) => Ok(label),
            _ => unreachable!("spawn failure emits one transition"),
        }
    }

    /// Completes an all-settled join with the scheduler's ordered resolution.
    #[cfg(feature = "concurrent")]
    pub fn complete_join(
        &mut self,
        suspension: &MachineJoinSuspension,
        resolution: JoinResolutionV1,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        let pending = self
            .pending_task_control
            .as_ref()
            .ok_or(TaskControlCompletionError::NotWaiting)?;
        if pending.suspension.join().map(|(join, _)| join) != Some(suspension) {
            return Err(TaskControlCompletionError::SuspensionMismatch);
        }
        if self.cancellation.is_some() {
            return Err(TaskControlCompletionError::Cancelled);
        }
        match resolution {
            JoinResolutionV1::Pending(_) => Err(TaskControlCompletionError::JoinPending),
            JoinResolutionV1::Succeeded(value) => {
                value
                    .validate(self.limits.value_limits)
                    .map_err(|_| TaskControlCompletionError::ValueLimit)?;
                if !value_matches_type(&value, &suspension.expected_type) {
                    return Err(TaskControlCompletionError::TypeMismatch);
                }
                self.push_staged(value, None);
                self.finish_task_control(
                    suspension.workflow.clone(),
                    suspension.site.clone(),
                    "join-complete",
                )
            }
            JoinResolutionV1::Failed(failure) => {
                if failure.category != gantry_core::portable::RuntimeErrorCategory::TaskJoinFailure
                    || failure.failures.is_empty()
                {
                    return Err(TaskControlCompletionError::CompletionMismatch);
                }
                match self.fail_join(
                    suspension.workflow.clone(),
                    suspension.site.clone(),
                    failure,
                ) {
                    MachineStep::Transition(label) => Ok(label),
                    _ => unreachable!("join failure emits one transition"),
                }
            }
        }
    }

    /// Completes a detach after scheduler ownership transfer and produces Unit.
    #[cfg(feature = "concurrent")]
    pub fn complete_detach(
        &mut self,
        suspension: &MachineDetachSuspension,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        let pending = self
            .pending_task_control
            .as_ref()
            .ok_or(TaskControlCompletionError::NotWaiting)?;
        if pending.suspension.detach() != Some(suspension) {
            return Err(TaskControlCompletionError::SuspensionMismatch);
        }
        if self.cancellation.is_some() {
            return Err(TaskControlCompletionError::Cancelled);
        }
        self.push_staged(LogicalValue::unit(), None);
        self.finish_task_control(
            suspension.workflow.clone(),
            suspension.site.clone(),
            "detach-complete",
        )
    }

    #[cfg(feature = "concurrent")]
    fn finish_task_control(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        kind: &'static str,
    ) -> Result<MachineLabel, TaskControlCompletionError> {
        self.advance_pc();
        self.pending_task_control = None;
        self.status = MachineStatus::Running;
        self.consecutive_transitions = 0;
        Ok(MachineLabel::Deterministic {
            workflow,
            site,
            kind: Arc::from(kind),
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
        self.truncate_staged(self.values.len() - operands);
        self.push_staged(value, None);
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

    /// Restores one consumed transition that could not yet be published.
    ///
    /// Durable drivers use this before releasing machine ownership for a wait,
    /// so another committed cut cannot absorb the uncommitted label removal.
    #[doc(hidden)]
    pub fn defer_transition(&mut self, label: MachineLabel) {
        self.pending_labels.push_front(label);
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
                #[cfg(feature = "concurrent")]
                MachineStatus::WaitingTaskControl => {
                    let pending = self
                        .pending_task_control
                        .as_ref()
                        .map(|pending| pending.suspension.clone())
                        .unwrap_or_else(|| unreachable!("waiting status retains task control"));
                    return match pending {
                        MachineTaskControlSuspension::Spawn(spawn) => {
                            MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn))
                        }
                        MachineTaskControlSuspension::Join(join)
                        | MachineTaskControlSuspension::JoinAll(join) => {
                            MachineStep::Transition(MachineLabel::Deterministic {
                                workflow: join.workflow,
                                site: join.site,
                                kind: Arc::from("join-suspended"),
                            })
                        }
                        MachineTaskControlSuspension::Detach(detach) => {
                            MachineStep::Transition(MachineLabel::Deterministic {
                                workflow: detach.workflow,
                                site: detach.site,
                                kind: Arc::from("detach-suspended"),
                            })
                        }
                    };
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
        #[cfg(feature = "concurrent")]
        let instructions = if self.frames.len() == 1 {
            self.task_body
                .as_ref()
                .and_then(|identity| self.program.task_body(identity))
                .map_or(workflow.instructions.as_slice(), |body| body.instructions())
        } else {
            workflow.instructions.as_slice()
        };
        #[cfg(not(feature = "concurrent"))]
        let instructions = workflow.instructions.as_slice();
        let instruction = instructions.get(frame.pc)?.clone();
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
            InstructionKind::Panic => Err(RuntimeCode::SourcePanic),
            InstructionKind::Branch {
                when_true,
                when_false,
            } => self.branch(&workflow, &site, when_true, when_false, &mut budget_state),
            InstructionKind::BranchOption {
                when_some,
                when_none,
            } => self.branch_option(&workflow, &site, when_some, when_none, &mut budget_state),
            InstructionKind::BranchResult { when_ok, when_err } => {
                self.branch_result(&workflow, &site, when_ok, when_err, &mut budget_state)
            }
            InstructionKind::BranchEnum { arms } => {
                self.branch_enum(&workflow, &site, &arms, &mut budget_state)
            }
            InstructionKind::EnterLoop {
                phase,
                source_limit,
            } => self.enter_loop(&workflow, &site, phase, source_limit, &mut budget_state),
            InstructionKind::LeaveOccurrence => self.leave_occurrence(&mut budget_state),
            InstructionKind::Call { callee, arguments } => {
                return self.call(workflow, site, callee, arguments, None, &mut budget_state);
            }
            InstructionKind::ReceiverCall {
                callee,
                arguments,
                source,
            } => {
                return self.call(
                    workflow,
                    site,
                    callee,
                    arguments,
                    Some(source),
                    &mut budget_state,
                );
            }
            InstructionKind::Return => {
                return self.return_value(workflow, site, &mut budget_state);
            }
            #[cfg(feature = "concurrent")]
            InstructionKind::Spawn { handle, body } => {
                return self.prepare_spawn(workflow, site, handle, body);
            }
            #[cfg(not(feature = "concurrent"))]
            InstructionKind::Spawn { .. } => {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            }
            #[cfg(feature = "concurrent")]
            InstructionKind::Join { handles } => {
                return self.prepare_join(workflow, site, handles, instruction.ty, false);
            }
            #[cfg(feature = "concurrent")]
            InstructionKind::JoinAll { handles } => {
                return self.prepare_join(workflow, site, handles, instruction.ty, true);
            }
            #[cfg(feature = "concurrent")]
            InstructionKind::Detach { handle } => {
                return self.prepare_detach(workflow, site, handle);
            }
            #[cfg(not(feature = "concurrent"))]
            InstructionKind::Join { .. }
            | InstructionKind::JoinAll { .. }
            | InstructionKind::Detach { .. } => {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            }
            #[cfg(feature = "concurrent")]
            InstructionKind::TaskComplete => {
                return self.complete_task_body(workflow, site, &mut budget_state);
            }
            #[cfg(not(feature = "concurrent"))]
            InstructionKind::TaskComplete => {
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
        self.push_staged(value, None);
        self.advance_pc();
        Ok(())
    }

    fn load_binding(
        &mut self,
        name: &str,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        // Reading the moved-out place, or one of its subplaces, cannot occur in an analyzed program,
        // so reaching one is an internal invariant violation rather than an evaluation failure.
        if self.current_place_reads_moved_out(name, &[]) {
            return Err(RuntimeCode::InternalInvariant);
        }
        let value = self
            .binding(name)
            .map(|binding| binding.value.clone())
            .ok_or(RuntimeCode::InternalInvariant)?;
        self.charge_transition(budget_state)?;
        self.push_staged(
            value,
            Some(LoadedPlace {
                root: Arc::from(name),
                path: Vec::new(),
            }),
        );
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
        self.pop_staged();
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
        let replacement = self
            .values
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        let binding = self
            .binding(name)
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        if !binding.mutable {
            return Err(RuntimeCode::InternalInvariant);
        }
        if !value_matches_type(&replacement, target_type) {
            return Err(RuntimeCode::InternalInvariant);
        }
        let candidate = binding
            .value
            .replaced(path, &replacement, self.limits.value_limits)
            .map_err(map_value_error)?;
        if !value_matches_type(&candidate, &binding.ty) {
            return Err(RuntimeCode::InternalInvariant);
        }
        let mut caller_candidates = Vec::new();
        if name == "self" {
            let mut frame_index = self.frames.len().checked_sub(1);
            let mut updated_receiver = candidate.clone();
            while let Some(index) = frame_index {
                let at_task_root = index == 0 && {
                    #[cfg(feature = "concurrent")]
                    {
                        self.task_body.is_some()
                    }
                    #[cfg(not(feature = "concurrent"))]
                    {
                        false
                    }
                };
                if at_task_root {
                    break;
                }
                let frame = self
                    .frames
                    .get(index)
                    .ok_or(RuntimeCode::InternalInvariant)?;
                let workflow = self
                    .program
                    .workflows()
                    .get(frame.workflow)
                    .ok_or(RuntimeCode::InternalInvariant)?;
                if workflow
                    .parameters
                    .first()
                    .and_then(Parameter::receiver_mode)
                    != Some(ReceiverMode::ExclusivePlace)
                {
                    break;
                }
                let admission = frame
                    .receiver_admission
                    .as_ref()
                    .ok_or(RuntimeCode::InternalInvariant)?;
                if admission
                    .path
                    .iter()
                    .any(|segment| !matches!(segment, ValuePathSegment::StructField(_)))
                {
                    return Err(RuntimeCode::InternalInvariant);
                }
                let parent_index = index.checked_sub(1).ok_or(RuntimeCode::InternalInvariant)?;
                let parent = self
                    .frames
                    .get(parent_index)
                    .ok_or(RuntimeCode::InternalInvariant)?;
                let caller = parent
                    .scopes
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(admission.root.as_ref()))
                    .cloned()
                    .ok_or(RuntimeCode::InternalInvariant)?;
                if !caller.mutable {
                    return Err(RuntimeCode::InternalInvariant);
                }
                let updated = caller
                    .value
                    .replaced(&admission.path, &updated_receiver, self.limits.value_limits)
                    .map_err(map_value_error)?;
                if !value_matches_type(&updated, &caller.ty) {
                    return Err(RuntimeCode::InternalInvariant);
                }
                let continues = admission.root.as_ref() == "self";
                caller_candidates.push((parent_index, admission.root.clone(), updated.clone()));
                let task_root = parent_index == 0 && {
                    #[cfg(feature = "concurrent")]
                    {
                        self.task_body.is_some()
                    }
                    #[cfg(not(feature = "concurrent"))]
                    {
                        false
                    }
                };
                if !continues || task_root {
                    break;
                }
                updated_receiver = updated;
                frame_index = Some(parent_index);
            }
        }
        self.charge_transition(budget_state)?;
        self.pop_staged();
        self.binding_mut(name)
            .ok_or(RuntimeCode::InternalInvariant)?
            .value = candidate;
        for (parent_index, root, candidate) in caller_candidates {
            let parent = self
                .frames
                .get_mut(parent_index)
                .ok_or(RuntimeCode::InternalInvariant)?;
            parent
                .scopes
                .iter_mut()
                .rev()
                .find_map(|scope| scope.get_mut(root.as_ref()))
                .ok_or(RuntimeCode::InternalInvariant)?
                .value = candidate;
        }
        self.clear_moved_out(name, path);
        self.clear_consumption_obligations(name, path);
        self.advance_pc();
        Ok(())
    }

    fn pop_value(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        if self.values.is_empty() {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition(budget_state)?;
        self.pop_staged();
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
        self.push_staged(candidate, None);
        self.advance_pc();
        Ok(())
    }

    fn project_value(
        &mut self,
        projection: Projection,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        let source = self.values.last().ok_or(RuntimeCode::InternalInvariant)?;
        let source_place = self
            .values_places
            .last()
            .ok_or(RuntimeCode::InternalInvariant)?
            .clone();
        let (projected, segment) = match projection {
            Projection::Member(index) => (
                source.member(index).ok_or_else(|| {
                    if matches!(source.view(), LogicalValueView::List(_)) {
                        RuntimeCode::Deterministic(
                            DeterministicEvaluationCode::ListIndexOutOfBounds,
                        )
                    } else {
                        RuntimeCode::InternalInvariant
                    }
                })?,
                member_path_segment(source, index),
            ),
            Projection::Field(name) => (
                source.field(&name).ok_or(RuntimeCode::InternalInvariant)?,
                ValuePathSegment::StructField(name.to_string()),
            ),
            Projection::Payload => (
                source.payload().ok_or(RuntimeCode::InternalInvariant)?,
                payload_path_segment(source),
            ),
        };
        // Reading the enclosing place stays legal, but projecting one of its moved-out subplaces
        // must fail closed, and only the recorded place origin tells the two apart at run time.
        let projected_place = match source_place {
            Some(place) => {
                let place = place.extended(segment);
                if self.current_place_moved_out(&place.root, &place.path) {
                    return Err(RuntimeCode::InternalInvariant);
                }
                Some(place)
            }
            None => None,
        };
        self.charge_transition(budget_state)?;
        self.pop_staged();
        self.push_staged(projected, projected_place);
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
        self.push_staged(result, None);
        self.advance_pc();
        Ok(())
    }

    fn enter_scope(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        self.charge_transition(budget_state)?;
        let frame = self
            .frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?;
        frame.scopes.push(Scope::new());
        #[cfg(feature = "concurrent")]
        frame.handle_scopes.push(HandleScope::new());
        self.advance_pc();
        Ok(())
    }

    fn exit_scope(&mut self, budget_state: &mut ExecutionBudgetState) -> Result<(), RuntimeCode> {
        let frame = self.frames.last().ok_or(RuntimeCode::InternalInvariant)?;
        if frame.scopes.len() <= 1 {
            return Err(RuntimeCode::InternalInvariant);
        }
        #[cfg(feature = "concurrent")]
        if frame.handle_scopes.len() != frame.scopes.len() {
            return Err(RuntimeCode::InternalInvariant);
        }
        self.charge_transition(budget_state)?;
        let frame = self
            .frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?;
        frame.scopes.pop();
        #[cfg(feature = "concurrent")]
        frame.handle_scopes.pop();
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
        self.pop_staged();
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
        let place = self
            .values_places
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
        self.pop_staged();
        if let Some(payload) = payload {
            self.push_staged(
                payload,
                place.map(|place| place.extended(ValuePathSegment::OptionValue)),
            );
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
        let place = self
            .values_places
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
        self.pop_staged();
        if let Some(payload) = payload {
            self.push_staged(
                payload,
                place.map(|place| place.extended(ValuePathSegment::EnumPayload)),
            );
        }
        self.occurrences.push(occurrence);
        self.frames
            .last_mut()
            .ok_or(RuntimeCode::InternalInvariant)?
            .pc = target;
        Ok(())
    }

    fn branch_result(
        &mut self,
        workflow: &CanonicalPath,
        site: &StructuralPosition,
        when_ok: usize,
        when_err: usize,
        budget_state: &mut ExecutionBudgetState,
    ) -> Result<(), RuntimeCode> {
        let value = self
            .values
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        let place = self
            .values_places
            .last()
            .cloned()
            .ok_or(RuntimeCode::InternalInvariant)?;
        let LogicalValueView::Result { is_ok } = value.view() else {
            return Err(RuntimeCode::InternalInvariant);
        };
        let payload = value.payload().ok_or(RuntimeCode::InternalInvariant)?;
        let arm = usize::from(!is_ok);
        let target = if is_ok { when_ok } else { when_err };
        let occurrence = Arc::from(format!(
            "branch:{}:{}:{arm}",
            workflow.as_str(),
            position_key(site)
        ));
        self.charge_transition(budget_state)?;
        self.pop_staged();
        self.push_staged(
            payload,
            place.map(|place| place.extended(ValuePathSegment::ResultValue)),
        );
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
            if self.remaining_loop_iterations == Some(0) {
                return Err(RuntimeCode::LoopIterationBudget);
            }
        }
        self.charge_transition(budget_state)?;
        self.counters
            .insert(key.clone(), occurrence.saturating_add(1));
        if matches!(phase, LoopPhase::Body) {
            if let Some(remaining) = self.remaining_loop_iterations.as_mut() {
                *remaining -= 1;
            }
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
        receiver_source: Option<ReceiverSource>,
        budget_state: &mut ExecutionBudgetState,
    ) -> MachineStep {
        if self
            .limits
            .maximum_workflow_call_depth
            .maximum()
            .is_some_and(|maximum| {
                u64::try_from(self.frames.len()).map_or(true, |depth| depth >= maximum)
            })
        {
            return self.fail_at(
                RuntimeCode::Deterministic(DeterministicEvaluationCode::WorkflowCallDepthLimit),
                workflow,
                site,
            );
        }
        let (values, stack_arguments, caller_place) = match receiver_source.as_ref() {
            Some(ReceiverSource::CallerPlace { root, path, .. }) => {
                let Some(stack_arguments) = arguments.checked_sub(1) else {
                    return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
                };
                // A caller place that this frame already moved out cannot be admitted again, so a
                // re-admission is an internal invariant violation rather than an evaluation error.
                if self.current_place_moved_out(root, path) {
                    return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
                }
                let Some(binding) = self.binding(root) else {
                    return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
                };
                let Some(receiver) = value_at_path(&binding.value, path) else {
                    return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
                };
                let operands = match self.peek_operands(stack_arguments) {
                    Ok(values) => values,
                    Err(code) => return self.fail_at(code, workflow, site),
                };
                let mut values = Vec::with_capacity(arguments);
                values.push(receiver);
                values.extend_from_slice(operands);
                (values, stack_arguments, Some((root.clone(), path.clone())))
            }
            Some(ReceiverSource::CopiedValue) | None => match self.peek_operands(arguments) {
                Ok(values) => (values.to_vec(), arguments, None),
                Err(code) => return self.fail_at(code, workflow, site),
            },
        };
        let Some(callee_index) = self.program.callable_index(&callee) else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let callee_workflow = &self.program.workflows()[callee_index];
        let parameters = callee_workflow.parameters.clone();
        if parameters.len() != values.len() {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        let owned_move = caller_place.is_some()
            && parameters.first().and_then(Parameter::receiver_mode) == Some(ReceiverMode::Owned);
        // Only an owned admission of a `MustConsume` caller place consumes a place that must be
        // accounted for; a shared or exclusive admission only reads it.
        let consumed_place = match receiver_source.as_ref() {
            Some(ReceiverSource::CallerPlace {
                ownership: OwnershipClass::MustConsume,
                ..
            }) if owned_move => caller_place.clone(),
            _ => None,
        };
        let receiver_admission = if owned_move {
            None
        } else {
            caller_place
                .as_ref()
                .map(|(root, path)| SharedPlaceAdmission {
                    root: root.clone(),
                    path: path.clone(),
                })
        };
        let place_initialization = if owned_move {
            let Some((root, path)) = caller_place.as_ref() else {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            };
            vec![PlaceInitialization {
                root: root.clone(),
                path: path.clone(),
                initialized: false,
            }]
        } else {
            Vec::new()
        };
        if let Some(ReceiverSource::CallerPlace { root, path, .. }) = receiver_source.as_ref()
            && parameters.first().and_then(Parameter::receiver_mode)
                == Some(ReceiverMode::ExclusivePlace)
            && (self.binding(root).is_none_or(|binding| !binding.mutable)
                || path
                    .iter()
                    .any(|segment| !matches!(segment, ValuePathSegment::StructField(_))))
        {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        if let Some(ReceiverSource::CallerPlace { root, path, .. }) = receiver_source.as_ref()
            && parameters.first().and_then(Parameter::receiver_mode)
                == Some(ReceiverMode::ExclusivePlace)
            && root.as_ref() == "self"
            && path.is_empty()
            && self
                .frames
                .last()
                .and_then(|frame| self.program.workflows().get(frame.workflow))
                .and_then(|workflow| workflow.parameters.first())
                .and_then(Parameter::receiver_mode)
                == Some(ReceiverMode::ExclusivePlace)
        {
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
        self.truncate_operands(stack_arguments);
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
            #[cfg(feature = "concurrent")]
            handle_scopes: vec![HandleScope::new()],
            stack_base: self.values.len(),
            occurrence_base: self.occurrences.len(),
            agent_stack_base: self.agent_stack.len(),
            agent_at_entry: self.agent.clone(),
            session_stack_base: self.session_stack.len(),
            session_at_entry: self.session,
            receiver_admission,
            place_initialization,
            moved_out: Vec::new(),
            consumption_obligation: consumed_place
                .map(|(root, path)| ConsumptionObligation { root, path })
                .into_iter()
                .collect(),
        });
        self.finish_deterministic(workflow, site, Arc::from("call"))
    }

    #[cfg(feature = "concurrent")]
    fn prepare_spawn(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        handle: ExecutableTaskHandle,
        body_identity: TaskBodyIdentity,
    ) -> MachineStep {
        let Some(body) = self.program.task_body(&body_identity) else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        if self.task_handle(handle.name()).is_some() {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        let mut captures = Vec::with_capacity(body.captures().len());
        for expected in body.captures() {
            // A task capture reads the caller-frame place, so a moved-out place cannot be captured.
            if self.current_place_moved_out(expected.name(), &[]) {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            }
            let Some(binding) = self.binding(expected.name()) else {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            };
            if binding.ty != *expected.ty() || binding.mutable != expected.is_mutable() {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            }
            let capture = match TaskCaptureV1::new(
                Arc::from(expected.name()),
                expected.ty().clone(),
                expected.is_mutable(),
                &binding.value,
                self.limits.value_limits,
            ) {
                Ok(capture) => capture,
                Err(_) => return self.fail_at(RuntimeCode::InternalInvariant, workflow, site),
            };
            captures.push(MachineTaskCapture { capture });
        }
        let key = self.counter_key("spawn", &workflow, &site);
        let occurrence = self.counters.get(&key).copied().unwrap_or(0);
        self.counters.insert(key, occurrence.saturating_add(1));
        let spawn = MachineSpawnSuspension {
            workflow,
            site,
            occurrence,
            handle,
            body: body_identity,
            captures,
            inherited_agent: self.agent.clone(),
            parent_session: self.session,
        };
        self.pending_task_control = Some(PendingTaskControl {
            suspension: MachineTaskControlSuspension::Spawn(spawn.clone()),
        });
        self.status = MachineStatus::WaitingTaskControl;
        self.consecutive_transitions = 0;
        MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn))
    }

    #[cfg(feature = "concurrent")]
    fn prepare_join(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        names: Vec<Arc<str>>,
        expected_type: TypeDescriptor,
        all: bool,
    ) -> MachineStep {
        if all && names.is_empty() {
            if expected_type != TypeDescriptor::UNIT {
                return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
            }
            self.push_staged(LogicalValue::unit(), None);
            self.advance_pc();
            self.consecutive_transitions = 0;
            return MachineStep::Transition(MachineLabel::Deterministic {
                workflow,
                site,
                kind: Arc::from("joinall-empty"),
            });
        }
        let Some(handles) = self.consume_task_handles(&names) else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let join = MachineJoinSuspension {
            workflow: workflow.clone(),
            site: site.clone(),
            handles,
            expected_type,
        };
        let suspension = if all {
            MachineTaskControlSuspension::JoinAll(join)
        } else {
            MachineTaskControlSuspension::Join(join)
        };
        self.pending_task_control = Some(PendingTaskControl { suspension });
        self.status = MachineStatus::WaitingTaskControl;
        self.consecutive_transitions = 0;
        MachineStep::Transition(MachineLabel::Deterministic {
            workflow,
            site,
            kind: Arc::from("join-suspended"),
        })
    }

    #[cfg(feature = "concurrent")]
    fn prepare_detach(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        name: Arc<str>,
    ) -> MachineStep {
        let names = [name];
        let Some(mut handles) = self.consume_task_handles(&names) else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let Some(handle) = handles.pop() else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let detach = MachineDetachSuspension {
            workflow: workflow.clone(),
            site: site.clone(),
            handle,
        };
        self.pending_task_control = Some(PendingTaskControl {
            suspension: MachineTaskControlSuspension::Detach(detach),
        });
        self.status = MachineStatus::WaitingTaskControl;
        self.consecutive_transitions = 0;
        MachineStep::Transition(MachineLabel::Deterministic {
            workflow,
            site,
            kind: Arc::from("detach-suspended"),
        })
    }

    #[cfg(feature = "concurrent")]
    fn consume_task_handles(
        &mut self,
        names: &[Arc<str>],
    ) -> Option<Vec<MachineTaskControlHandle>> {
        let handles = names
            .iter()
            .map(|name| {
                self.task_handle(name)
                    .cloned()
                    .map(|handle| MachineTaskControlHandle {
                        name: Arc::clone(name),
                        handle,
                    })
            })
            .collect::<Option<Vec<_>>>()?;
        let frame = self.frames.last_mut()?;
        for name in names {
            let scope = frame
                .handle_scopes
                .iter_mut()
                .rev()
                .find(|scope| scope.contains_key(name.as_ref()))?;
            scope.remove(name.as_ref())?;
        }
        Some(handles)
    }

    #[cfg(feature = "concurrent")]
    fn complete_task_body(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        budget_state: &mut ExecutionBudgetState,
    ) -> MachineStep {
        let Some(body_identity) = self.task_body.as_ref() else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let Some(body) = self.program.task_body(body_identity) else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        let Some(value) = self.values.last().cloned() else {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        };
        if self.frames.len() != 1 || !value_matches_type(&value, body.result_type()) {
            return self.fail_at(RuntimeCode::InternalInvariant, workflow, site);
        }
        if let Err(code) = self.charge_transition(budget_state) {
            return self.fail_at(code, workflow, site);
        }
        self.pop_staged();
        self.finish_outcome(MachineOutcome::Succeeded(value))
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
            self.pop_staged();
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
        self.truncate_staged(frame.stack_base);
        self.push_staged(value, None);
        self.occurrences
            .truncate(frame.occurrence_base.saturating_sub(1));
        self.agent_stack.truncate(frame.agent_stack_base);
        self.agent = frame.agent_at_entry;
        self.session_stack.truncate(frame.session_stack_base);
        self.session = frame.session_at_entry;
        // A normal return of an owned callee transfers its single staging entry into the caller
        // frame, so the moved-out place stays durably marked after the callee frame is gone. The
        // caller binding keeps its value; the transfer is a logical discard. Failure and
        // cancellation paths never reach this transfer.
        let mut staged = frame.place_initialization;
        if staged.len() == 1
            && let Some(entry) = staged.pop()
            && let Some(caller) = self.frames.last_mut()
        {
            record_moved_out(caller, entry.root, entry.path);
        }
        // A normal return transfers the callee's live obligations to the caller frame that owns the
        // consumed place, so the accounting survives the callee-frame pop.
        if let Some(caller) = self.frames.last_mut() {
            for entry in frame.consumption_obligation {
                record_consumption_obligation(caller, entry.root, entry.path);
            }
        }
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
        // One loop creation point executes once per iteration and each execution must create its own
        // child (`SPEC.md` GNT-9.6), so the occurrence counts executions of this static site rather
        // than inheriting the enclosing loop or call occurrence: a site reached from any dynamic
        // context advances the same sequence, and a single execution still derives occurrence zero.
        let key = occurrence_counter_key(&[], "session", &workflow, &site);
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
        #[cfg(feature = "concurrent")]
        {
            self.pending_task_control = None;
        }
        self.finish_outcome(outcome)
    }

    fn finish_outcome(&mut self, outcome: MachineOutcome) -> MachineStep {
        self.settle_consumption_obligations();
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

    /// Retains every live frame obligation in the machine-level settled list exactly once.
    ///
    /// Every terminal path funnels through [`Self::finish_outcome`], so a failure, a cancellation,
    /// and a successful root return all settle their unaccounted `MustConsume` evidence the same
    /// way rather than letting it disappear with the retired frames. The drain empties the frame
    /// vectors, which makes the settlement idempotent: a second settlement finds nothing left to
    /// retain.
    fn settle_consumption_obligations(&mut self) {
        for frame in &mut self.frames {
            for entry in frame.consumption_obligation.drain(..) {
                self.settled_obligations.push(entry);
            }
        }
        self.settled_obligations
            .sort_by(ConsumptionObligation::canonical_cmp);
        self.settled_obligations
            .dedup_by(|left, right| left.canonical_cmp(right) == Ordering::Equal);
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
            #[cfg(feature = "concurrent")]
            join_failure: None,
        };
        self.finish_failure(failure)
    }

    #[cfg(feature = "concurrent")]
    fn fail_join(
        &mut self,
        workflow: CanonicalPath,
        site: StructuralPosition,
        join_failure: TaskJoinFailureV1,
    ) -> MachineStep {
        self.finish_failure(MachineFailure {
            code: RuntimeCode::Operation(
                gantry_core::portable::RuntimeErrorCategory::TaskJoinFailure,
            ),
            workflow,
            site,
            join_failure: Some(join_failure),
        })
    }

    fn finish_failure(&mut self, failure: MachineFailure) -> MachineStep {
        self.pending_session_scope = None;
        self.pending_operation = None;
        #[cfg(feature = "concurrent")]
        {
            self.pending_task_control = None;
        }
        let outcome = MachineOutcome::Failed(failure.clone());
        // A failure cut discards the frames, so the settled evidence order keeps the task
        // settlement ahead of the foreground and terminal completions that `finish_outcome`
        // queues. The settlement itself lives only in `finish_outcome`.
        self.pending_labels
            .push_back(MachineLabel::TaskSettled(outcome.clone()));
        let _ = self.finish_outcome(outcome);
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

    /// Reports whether the current frame recorded an intersecting moved-out place.
    fn current_place_moved_out(&self, root: &str, path: &[ValuePathSegment]) -> bool {
        self.frames.last().is_some_and(|frame| {
            frame
                .moved_out
                .iter()
                .any(|entry| places_intersect(&entry.root, &entry.path, root, path))
        })
    }

    /// Reports whether reading the place `root`/`path` would expose a moved-out place.
    ///
    /// A read of the moved-out place itself, or of one of its subplaces, is impossible for an
    /// analyzed program. Reading an *enclosing* place is not: the lowering loads the enclosing
    /// aggregate and then projects the surviving sibling subplace, which is how
    /// `holder.token.consume(); moved + holder.marker` reads `holder.marker` after the partial
    /// move of `holder.token`.
    fn current_place_reads_moved_out(&self, root: &str, path: &[ValuePathSegment]) -> bool {
        self.frames.last().is_some_and(|frame| {
            frame
                .moved_out
                .iter()
                .any(|entry| entry.root.as_ref() == root && path.starts_with(&entry.path))
        })
    }

    /// Clears every moved-out entry of the current frame intersecting a freshly written place.
    fn clear_moved_out(&mut self, root: &str, path: &[ValuePathSegment]) {
        if let Some(frame) = self.frames.last_mut() {
            frame
                .moved_out
                .retain(|entry| !places_intersect(&entry.root, &entry.path, root, path));
        }
    }

    /// Discharges every obligation that re-initialising one place makes accounted for.
    fn clear_consumption_obligations(&mut self, root: &str, path: &[ValuePathSegment]) {
        if let Some(frame) = self.frames.last_mut() {
            frame
                .consumption_obligation
                .retain(|entry| !places_intersect(&entry.root, &entry.path, root, path));
        }
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
        self.truncate_staged(length);
    }

    /// Pushes one staged value together with the place it was loaded from, when known.
    ///
    /// The place stack always holds exactly one entry per staged value, so every push, pop, and
    /// truncation goes through these helpers and asserts the invariant in debug builds.
    fn push_staged(&mut self, value: LogicalValue, place: Option<LoadedPlace>) {
        self.values.push(value);
        self.values_places.push(place);
        debug_assert_eq!(self.values.len(), self.values_places.len());
    }

    /// Pops one staged value together with its recorded place origin.
    fn pop_staged(&mut self) -> Option<(LogicalValue, Option<LoadedPlace>)> {
        let value = self.values.pop()?;
        let place = self.values_places.pop().flatten();
        debug_assert_eq!(self.values.len(), self.values_places.len());
        Some((value, place))
    }

    /// Truncates the staged value stack, and its place origins, to `length` entries.
    fn truncate_staged(&mut self, length: usize) {
        self.values.truncate(length);
        self.values_places.truncate(length);
        debug_assert_eq!(self.values.len(), self.values_places.len());
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
        occurrence_counter_key(&self.occurrences, kind, workflow, site)
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

fn occurrence_counter_key(
    occurrences: &[Arc<str>],
    kind: &str,
    workflow: &CanonicalPath,
    site: &StructuralPosition,
) -> String {
    let mut key = occurrences
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

#[cfg(feature = "durable")]
fn validate_execution_budget_snapshot(
    snapshot: &ExecutionBudgetSnapshot,
) -> Result<(), MachineRecoveryError> {
    let consumed_transitions = match (
        snapshot.maximum_transitions.maximum(),
        snapshot.remaining_transitions,
    ) {
        (Some(maximum), Some(remaining)) => maximum.checked_sub(remaining),
        (None, None) => Some(0),
        _ => None,
    };
    let consumed_operations = match (
        snapshot.maximum_operations.maximum(),
        snapshot.remaining_operations,
    ) {
        (Some(maximum), Some(remaining)) => maximum.checked_sub(remaining),
        (None, None) => Some(0),
        _ => None,
    };
    let consumed = consumed_transitions
        .zip(consumed_operations)
        .and_then(|(transitions, operations)| transitions.checked_add(operations));
    if snapshot.execution.kind() != IdentityKind::Execution
        || consumed.is_none()
        || consumed.is_some_and(|consumed| consumed > snapshot.revision)
        || (snapshot.maximum_transitions.maximum().is_some()
            && snapshot.maximum_operations.maximum().is_some()
            && consumed != Some(snapshot.revision))
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
    #[cfg(feature = "concurrent")]
    let task_body = checkpoint
        .task_body
        .as_ref()
        .map(|identity| {
            let body = program
                .task_body(identity)
                .ok_or(MachineRecoveryError::ProgramMismatch)?;
            let root = checkpoint
                .frames
                .first()
                .ok_or(MachineRecoveryError::InvalidCheckpoint)?;
            if checkpoint.execution_foreground
                || program.callable_index(identity.enclosing_callable()) != Some(root.workflow)
            {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
            Ok(body)
        })
        .transpose()?;
    if checkpoint.execution.kind() != IdentityKind::Execution
        || !matches!(
            expected_task_identity(checkpoint.execution, &checkpoint.task_path),
            Ok(expected) if expected == checkpoint.task_id
        )
        || checkpoint.execution_foreground != checkpoint.task_path.is_empty()
        || checkpoint.frames.is_empty()
        || checkpoint.limits.deterministic_transition_yield_quantum == 0
        || match (
            checkpoint.limits.maximum_loop_iterations.maximum(),
            checkpoint.remaining_loop_iterations,
        ) {
            (Some(maximum), Some(remaining)) => remaining > maximum,
            (None, None) => false,
            _ => true,
        }
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

    for (frame_index, frame) in checkpoint.frames.iter().enumerate() {
        let workflow = program
            .workflows()
            .get(frame.workflow)
            .ok_or(MachineRecoveryError::ProgramMismatch)?;
        #[cfg(feature = "concurrent")]
        let is_task_capture_root = task_body.is_some() && frame_index == 0;
        #[cfg(not(feature = "concurrent"))]
        let is_task_capture_root = false;
        #[cfg(feature = "concurrent")]
        if let Some(body) = task_body.filter(|_| is_task_capture_root)
            && frame.scopes.first().is_none_or(|scope| {
                body.captures().iter().any(|capture| {
                    !scope.get(capture.name()).is_some_and(|binding| {
                        binding.ty == *capture.ty() && binding.mutable == capture.is_mutable()
                    })
                })
            })
        {
            return Err(MachineRecoveryError::ProgramMismatch);
        }
        if !is_task_capture_root
            && frame.scopes.first().is_none_or(|scope| {
                workflow.parameters.iter().any(|parameter| {
                    !scope.get(&parameter.name).is_some_and(|binding| {
                        binding.ty == parameter.ty && binding.mutable == parameter.mutable
                    })
                })
            })
        {
            return Err(MachineRecoveryError::ProgramMismatch);
        }
        #[cfg(feature = "concurrent")]
        let instructions = if frame_index == 0 {
            task_body.map_or(workflow.instructions.as_slice(), |body| body.instructions())
        } else {
            workflow.instructions.as_slice()
        };
        #[cfg(not(feature = "concurrent"))]
        let instructions = workflow.instructions.as_slice();
        if frame.pc >= instructions.len()
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
        #[cfg(feature = "concurrent")]
        if frame.handle_scopes.len() != frame.scopes.len()
            || frame.handle_scopes.iter().any(|scope| {
                scope.iter().any(|(name, handle)| {
                    name.is_empty()
                        || handle.identity.owner() != checkpoint.task_id
                        || handle.identity.child().kind() != IdentityKind::Task
                })
            })
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
        let parent_instruction = frame_index.checked_sub(1).and_then(|parent_index| {
            let parent = checkpoint.frames.get(parent_index)?;
            let parent_workflow = program.workflows().get(parent.workflow)?;
            #[cfg(feature = "concurrent")]
            let instructions = if parent_index == 0 {
                task_body.map_or(parent_workflow.instructions.as_slice(), |body| {
                    body.instructions()
                })
            } else {
                parent_workflow.instructions.as_slice()
            };
            #[cfg(not(feature = "concurrent"))]
            let instructions = parent_workflow.instructions.as_slice();
            parent
                .pc
                .checked_sub(1)
                .and_then(|index| instructions.get(index))
        });
        let parent_caller_place = match parent_instruction.map(|instruction| &instruction.kind) {
            Some(InstructionKind::ReceiverCall {
                source: ReceiverSource::CallerPlace { root, path, .. },
                ..
            }) => Some((root, path)),
            _ => None,
        };
        let receiver_mode = workflow
            .parameters
            .first()
            .and_then(Parameter::receiver_mode);
        match (parent_caller_place, receiver_mode) {
            (Some(_), Some(ReceiverMode::Owned)) => {
                if frame.receiver_admission.is_some() || frame.place_initialization.len() != 1 {
                    return Err(MachineRecoveryError::ProgramMismatch);
                }
            }
            (Some(_), _) => {
                if frame.receiver_admission.is_none() || !frame.place_initialization.is_empty() {
                    return Err(MachineRecoveryError::ProgramMismatch);
                }
            }
            (None, _) => {
                if frame.receiver_admission.is_some() {
                    return Err(MachineRecoveryError::ProgramMismatch);
                }
            }
        }
        if let Some(admission) = &frame.receiver_admission {
            let Some(parent) = frame_index
                .checked_sub(1)
                .and_then(|index| checkpoint.frames.get(index))
            else {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            };
            let Some(parameter) = workflow.parameters.first() else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let Some(receiver) = frame.scopes.first().and_then(|scope| scope.get("self")) else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let Some(caller) = parent
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(admission.root.as_ref()))
            else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let Some(caller_value) = value_at_path(&caller.value, &admission.path) else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let Some(parent_instruction) = parent_instruction else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let Some(callee) = program.callable_identities().get(frame.workflow) else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let admission_matches_call = matches!(
                &parent_instruction.kind,
                InstructionKind::ReceiverCall {
                    callee: instruction_callee,
                    source: ReceiverSource::CallerPlace { root, path, .. },
                    ..
                } if instruction_callee == callee
                    && root.as_ref() == admission.root.as_ref()
                    && path == &admission.path
            );
            if !admission_matches_call
                || !value_matches_type(&caller_value, &receiver.ty)
                || caller_value != receiver.value
            {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
            if parameter.receiver_mode == Some(ReceiverMode::ExclusivePlace)
                && (!caller.mutable
                    || !parameter.mutable
                    || receiver.ty != parameter.ty
                    || receiver.mutable != parameter.mutable
                    || admission
                        .path
                        .iter()
                        .any(|segment| !matches!(segment, ValuePathSegment::StructField(_)))
                    || (admission.root.as_ref() == "self"
                        && admission.path.is_empty()
                        && checkpoint
                            .frames
                            .get(frame_index - 1)
                            .and_then(|parent| program.workflows().get(parent.workflow))
                            .and_then(|parent| parent.parameters.first())
                            .and_then(Parameter::receiver_mode)
                            == Some(ReceiverMode::ExclusivePlace)))
            {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
        }
        let mut staged_values = Vec::with_capacity(frame.place_initialization.len());
        for (entry_index, entry) in frame.place_initialization.iter().enumerate() {
            if entry.initialized {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            }
            if entry.root.is_empty()
                || frame.place_initialization[..entry_index]
                    .iter()
                    .any(|prior| prior.root == entry.root && prior.path == entry.path)
            {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            }
            let Some(parent) = frame_index
                .checked_sub(1)
                .and_then(|index| checkpoint.frames.get(index))
            else {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            };
            let Some(binding) = parent
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(entry.root.as_ref()))
            else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            let Some(staged) = value_at_path(&binding.value, &entry.path) else {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            };
            staged_values.push(staged);
        }
        for (entry, staged) in frame.place_initialization.iter().zip(&staged_values) {
            if receiver_mode != Some(ReceiverMode::Owned)
                || parent_caller_place.is_none_or(|(root, path)| {
                    root.as_ref() != entry.root.as_ref() || path != &entry.path
                })
            {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
            let Some(receiver) = frame.scopes.first().and_then(|scope| scope.get("self")) else {
                return Err(MachineRecoveryError::ProgramMismatch);
            };
            if !value_matches_type(staged, &receiver.ty) {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
        }
        // Every moved-out entry must be justified by an earlier owned caller-place call in this
        // frame's own workflow, and the entries must stay canonical and pairwise non-intersecting.
        // The justification is an existence check over instructions strictly before `pc`, and it
        // keeps runtime-produced checkpoints consistent rather than verifying integrity: an
        // adversary who can rewrite checkpoint bytes can also forge a mark. A forged mark can only
        // be rejected here, fail closed on a later read, or lose the guard optimization; it never
        // changes the caller binding, which recovery reproduces from this frame's own scopes.
        for (entry_index, entry) in frame.moved_out.iter().enumerate() {
            if entry.root.is_empty() {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            }
            if frame.moved_out[..entry_index].iter().any(|prior| {
                prior.canonical_cmp(entry) != Ordering::Less
                    || places_intersect(&prior.root, &prior.path, &entry.root, &entry.path)
            }) {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            }
            let justified =
                instructions[..frame.pc]
                    .iter()
                    .any(|instruction| match &instruction.kind {
                        InstructionKind::ReceiverCall {
                            callee,
                            source: ReceiverSource::CallerPlace { root, path, .. },
                            ..
                        } => {
                            root.as_ref() == entry.root.as_ref()
                                && path == &entry.path
                                && program
                                    .callable_index(callee)
                                    .and_then(|index| program.workflows().get(index))
                                    .and_then(|workflow| workflow.parameters.first())
                                    .and_then(Parameter::receiver_mode)
                                    == Some(ReceiverMode::Owned)
                        }
                        _ => false,
                    });
            if !justified {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
        }
        // Every live obligation must stay canonical, pairwise non-intersecting, rooted in a
        // non-empty name, and justified by an earlier MustConsume owned caller-place call in this
        // frame's own workflow.
        for (entry_index, entry) in frame.consumption_obligation.iter().enumerate() {
            if entry.root.is_empty() {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            }
            if frame.consumption_obligation[..entry_index]
                .iter()
                .any(|prior| {
                    prior.canonical_cmp(entry) != Ordering::Less
                        || places_intersect(&prior.root, &prior.path, &entry.root, &entry.path)
                })
            {
                return Err(MachineRecoveryError::InvalidCheckpoint);
            }
            let justified =
                instructions[..frame.pc]
                    .iter()
                    .any(|instruction| match &instruction.kind {
                        InstructionKind::ReceiverCall {
                            callee,
                            source:
                                ReceiverSource::CallerPlace {
                                    root,
                                    path,
                                    ownership: OwnershipClass::MustConsume,
                                },
                            ..
                        } => {
                            root.as_ref() == entry.root.as_ref()
                                && path == &entry.path
                                && program
                                    .callable_index(callee)
                                    .and_then(|index| program.workflows().get(index))
                                    .and_then(|workflow| workflow.parameters.first())
                                    .and_then(Parameter::receiver_mode)
                                    == Some(ReceiverMode::Owned)
                        }
                        _ => false,
                    });
            // The parent frame's admission staged this obligation when it consumed the caller place,
            // so the justification may also come from that earlier parent instruction.
            let justified = justified
                || parent_instruction.is_some_and(|instruction| {
                    matches!(
                        &instruction.kind,
                        InstructionKind::ReceiverCall {
                            source: ReceiverSource::CallerPlace {
                                root,
                                path,
                                ownership: OwnershipClass::MustConsume,
                            },
                            ..
                        } if root.as_ref() == entry.root.as_ref() && path == &entry.path
                    )
                });
            if !justified {
                return Err(MachineRecoveryError::ProgramMismatch);
            }
        }
    }

    // The machine-level settled list survives discarded frames, so it carries the same structural
    // requirements while its justification may come from any `MustConsume` owned caller-place call
    // the retained program can still execute.
    for (entry_index, entry) in checkpoint.settled_obligations.iter().enumerate() {
        if entry.root.is_empty() {
            return Err(MachineRecoveryError::InvalidCheckpoint);
        }
        if checkpoint.settled_obligations[..entry_index]
            .iter()
            .any(|prior| {
                prior.canonical_cmp(entry) != Ordering::Less
                    || places_intersect(&prior.root, &prior.path, &entry.root, &entry.path)
            })
        {
            return Err(MachineRecoveryError::InvalidCheckpoint);
        }
        let justified = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .chain(
                program
                    .task_bodies()
                    .iter()
                    .flat_map(|body| body.instructions().iter()),
            )
            .any(|instruction| {
                matches!(
                    &instruction.kind,
                    InstructionKind::ReceiverCall {
                        source: ReceiverSource::CallerPlace {
                            root,
                            path,
                            ownership: OwnershipClass::MustConsume,
                        },
                        ..
                    } if root.as_ref() == entry.root.as_ref()
                        && path == &entry.path
                )
            });
        if !justified {
            return Err(MachineRecoveryError::ProgramMismatch);
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
        #[cfg(feature = "concurrent")]
        let instructions = if checkpoint.frames.len() == 1 {
            task_body.map_or(workflow.instructions.as_slice(), |body| body.instructions())
        } else {
            workflow.instructions.as_slice()
        };
        #[cfg(not(feature = "concurrent"))]
        let instructions = workflow.instructions.as_slice();
        let Some(instruction) = instructions.get(index) else {
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

    #[cfg(feature = "concurrent")]
    let pending_task_control_valid =
        checkpoint
            .pending_task_control
            .as_ref()
            .is_none_or(|pending| {
                let Some(frame) = checkpoint.frames.last() else {
                    return false;
                };
                let Some(workflow) = program.workflows().get(frame.workflow) else {
                    return false;
                };
                let instructions = if checkpoint.frames.len() == 1 {
                    task_body.map_or(workflow.instructions.as_slice(), |body| body.instructions())
                } else {
                    workflow.instructions.as_slice()
                };
                let Some(instruction) = instructions.get(frame.pc) else {
                    return false;
                };
                validate_pending_task_control(
                    program,
                    checkpoint,
                    frame,
                    workflow,
                    instruction,
                    &pending.suspension,
                )
            });
    #[cfg(feature = "concurrent")]
    if !pending_task_control_valid {
        return Err(MachineRecoveryError::ProgramMismatch);
    }

    let state_valid = match (checkpoint.status, checkpoint.outcome.as_ref()) {
        (MachineStatus::Running | MachineStatus::YieldRequired, None) => {
            checkpoint.pending_session_scope.is_none()
                && checkpoint.pending_operation.is_none()
                && {
                    #[cfg(feature = "concurrent")]
                    {
                        checkpoint.pending_task_control.is_none()
                    }
                    #[cfg(not(feature = "concurrent"))]
                    {
                        true
                    }
                }
        }
        (MachineStatus::WaitingSessionScope, None) => {
            checkpoint.pending_session_scope.is_some()
                && checkpoint.pending_operation.is_none()
                && {
                    #[cfg(feature = "concurrent")]
                    {
                        checkpoint.pending_task_control.is_none()
                    }
                    #[cfg(not(feature = "concurrent"))]
                    {
                        true
                    }
                }
        }
        (MachineStatus::WaitingOperation, None) => {
            checkpoint.pending_operation.is_some()
                && checkpoint.pending_session_scope.is_none()
                && {
                    #[cfg(feature = "concurrent")]
                    {
                        checkpoint.pending_task_control.is_none()
                    }
                    #[cfg(not(feature = "concurrent"))]
                    {
                        true
                    }
                }
        }
        #[cfg(feature = "concurrent")]
        (MachineStatus::WaitingTaskControl, None) => {
            checkpoint.pending_task_control.is_some()
                && checkpoint.pending_session_scope.is_none()
                && checkpoint.pending_operation.is_none()
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

#[cfg(all(feature = "concurrent", feature = "durable"))]
fn validate_pending_task_control(
    program: &MachineProgram,
    checkpoint: &MachineCheckpointV3,
    frame: &WorkflowFrame,
    workflow: &gantry_ir::Workflow,
    instruction: &Instruction,
    suspension: &MachineTaskControlSuspension,
) -> bool {
    let handles_consumed = |handles: &[MachineTaskControlHandle]| {
        handles.iter().all(|handle| {
            !handle.name.is_empty()
                && handle.handle.identity.owner() == checkpoint.task_id
                && handle.handle.identity.child().kind() == IdentityKind::Task
                && frame
                    .handle_scopes
                    .iter()
                    .all(|scope| !scope.contains_key(handle.name.as_ref()))
        })
    };
    match suspension {
        MachineTaskControlSuspension::Spawn(spawn) => {
            let Some(body) = program.task_body(&spawn.body) else {
                return false;
            };
            let occurrence_key = occurrence_counter_key(
                &checkpoint.occurrences,
                "spawn",
                &spawn.workflow,
                &spawn.site,
            );
            workflow.path == spawn.workflow
                && spawn.handle.result_type() == body.result_type()
                && spawn.inherited_agent == checkpoint.agent
                && spawn.parent_session == checkpoint.session
                && checkpoint.counters.get(&occurrence_key)
                    == Some(&spawn.occurrence.saturating_add(1))
                && instruction.site == spawn.site
                && matches!(
                    &instruction.kind,
                    InstructionKind::Spawn { handle, body }
                        if handle == &spawn.handle && body == &spawn.body
                )
                && body.captures().len() == spawn.captures.len()
                && body
                    .captures()
                    .iter()
                    .zip(&spawn.captures)
                    .all(|(expected, actual)| {
                        let actual = actual.task_capture();
                        let binding = frame
                            .scopes
                            .iter()
                            .rev()
                            .find_map(|scope| scope.get(expected.name()));
                        expected.name() == actual.name()
                            && expected.ty() == actual.ty()
                            && expected.is_mutable() == actual.is_mutable()
                            && value_matches_type(actual.value(), expected.ty())
                            && binding.is_some_and(|binding| {
                                binding.ty == *expected.ty()
                                    && binding.mutable == expected.is_mutable()
                                    && binding.value == *actual.value()
                            })
                            && actual
                                .value()
                                .validate(checkpoint.limits.value_limits)
                                .is_ok()
                    })
                && frame
                    .handle_scopes
                    .iter()
                    .all(|scope| !scope.contains_key(spawn.handle.name()))
        }
        MachineTaskControlSuspension::Join(join) | MachineTaskControlSuspension::JoinAll(join) => {
            let names = join
                .handles
                .iter()
                .map(|handle| handle.name.as_ref())
                .collect::<Vec<_>>();
            let instruction_names = match (&suspension, &instruction.kind) {
                (MachineTaskControlSuspension::Join(_), InstructionKind::Join { handles })
                | (
                    MachineTaskControlSuspension::JoinAll(_),
                    InstructionKind::JoinAll { handles },
                ) => Some(handles),
                _ => None,
            };
            workflow.path == join.workflow
                && instruction.site == join.site
                && instruction.ty == join.expected_type
                && instruction_names.is_some_and(|expected| {
                    expected.iter().map(AsRef::as_ref).eq(names.iter().copied())
                })
                && handles_consumed(&join.handles)
        }
        MachineTaskControlSuspension::Detach(detach) => {
            workflow.path == detach.workflow
                && instruction.site == detach.site
                && matches!(
                    &instruction.kind,
                    InstructionKind::Detach { handle } if handle.as_ref() == detach.handle.name()
                )
                && handles_consumed(std::slice::from_ref(&detach.handle))
        }
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
        InstructionKind::Panic => "panic",
        InstructionKind::Branch { .. }
        | InstructionKind::BranchOption { .. }
        | InstructionKind::BranchResult { .. }
        | InstructionKind::BranchEnum { .. } => "branch",
        InstructionKind::EnterLoop { .. } => "loop",
        InstructionKind::LeaveOccurrence => "occurrence-exit",
        InstructionKind::Call { .. } => "call",
        InstructionKind::ReceiverCall { .. } => "receiver-call",
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
        Primitive::ListIndex => {
            let LogicalValueView::List(_) = operands[0].view() else {
                return Err(RuntimeCode::InternalInvariant);
            };
            let LogicalValueView::Int(index) = operands[1].view() else {
                return Err(RuntimeCode::InternalInvariant);
            };
            let Ok(index) = usize::try_from(index.get()) else {
                return Err(RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::ListIndexOutOfBounds,
                ));
            };
            operands[0].member(index).ok_or(RuntimeCode::Deterministic(
                DeterministicEvaluationCode::ListIndexOutOfBounds,
            ))
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
