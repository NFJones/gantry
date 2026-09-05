//! Deliberate public composition of package admission, the shared machine, and lifecycle control.
//!
//! The facade owns orchestration only. Source analysis, machine transitions,
//! cancellation, waits, and shutdown remain in their existing subsystem owners.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

#[cfg(any(feature = "durable", feature = "test-support"))]
use std::collections::BTreeMap;
#[cfg(all(feature = "concurrent", feature = "durable"))]
use std::collections::VecDeque;
#[cfg(all(feature = "durable", feature = "test-support"))]
use std::sync::Condvar;

use gantry_analysis::{DeclaredValueShape, DeclaredValueShapes};
use gantry_core::canonical_json::CanonicalJson;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{
    CancellationReasonCategory, DeterministicEvaluationCode, IdentityKind,
    ResumeStartFailureCategory, RuntimeErrorCategory, StartFailureCategory,
};
use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_core::value::{LogicalValue, OperationErrorValue, ValueLimits};
use gantry_host::contracts::{
    CancellationSignal, CancellationToken, DeadlineOutcome, DurationMicros, ExecutorAdapter,
    FreshIdentityAllocator, HookFactory, HostError, HostFuture, InclusiveJitterRange,
    IntegrationPreflight, OwnedTaskCompletion, OwnedTaskFuture, OwnedTaskResult,
    RuntimeSessionService, UtcClock, deadline_race,
};
use gantry_host::event::{EventDeliveryRequest, EventDeliveryRuntime, EventSink};
use gantry_ir::TypeDescriptor;
use gantry_ir::generated::{OperationSiteKind, TypeKind};
use gantry_observe::{
    DeliveryError, DeliveryKernel, EventCompleter, EventCompletionError, SinkPlan,
    SinkSettlementStatus,
};
use gantry_runtime::{
    AbnormalCompletionHandler, AcceptedTranscriptResultV1, ActionOperationRequestV1, AdapterPoison,
    AdmissionClass, AdmissionExhaustion, CancellationReason, CancellationRecord,
    CapturedOperationRequestV1, ConcurrentTaskStateV1, ExecutionCoordinator,
    ExecutionDeliveryConsequenceV1, ExecutionEventError, ExecutionEventPipeline, ExecutionHandle,
    ExecutionSnapshot, FinalShutdownEventFailure, FinalShutdownEventSettlement,
    InterpolationInputV1, InterpreterConfiguration, InterpreterLifecycle, LifecycleError,
    LogicalSessionRegistryV1, Machine, MachineBuildError, MachineFailure, MachineLabel,
    MachineOutcome, MachineStep, ModelOperationRequestV1, ModelSessionUseV1, NamedInputV1,
    OperationLifecycle, OperationLifecycleError, OperationLifecycleFailureV1,
    OperationRequestHeaderV1, OperationRetryPolicyV1, PhysicalCompletionHandler,
    ProcessedHookOutcomeV1, RootSessionProvenanceV1, RuntimeCode, SessionCreationModeV1,
    SessionEstablisher, SessionEstablishmentV1, ShutdownCompletionError, ShutdownEventSummaryV1,
    ShutdownReport, SupervisedTaskDomain, SupervisionSignal, TaskContextV1, TaskHook,
    TaskHookError, TaskSessionContextV1, TaskStateError, TranscriptResultKindV1, TranscriptTurnV1,
    TypedActionArgumentV1, catch_integration, contain_integration_future, machine_lifecycle_event,
    shutdown_event,
};
#[cfg(feature = "concurrent")]
use gantry_runtime::{
    ConcurrentTaskStatusV1, ExecutionBudget, MachineSpawnSuspension, TaskCreationRequestV1,
    concurrent_spawn_event,
};

#[cfg(feature = "durable")]
use gantry_host::journal::JournalStorage;
#[cfg(all(feature = "concurrent", feature = "durable"))]
use gantry_runtime::AdmissionReservation;
#[cfg(feature = "durable")]
use gantry_runtime::{
    DurableCommitCutV1, DurableEventBarrierV1, DurableOperationEvidenceV1, ExecutionEventDraftV1,
    OperationResultEventKindV1, SupervisedTask, operation_completion_event,
    operation_dispatch_event, operation_result_event,
};

use crate::start::{PreparedExecutionStart, StartExecutionCoordinator};
use crate::{
    AnalyzePackageCoordinator, AnalyzePackageResult, StartExecutionAccepted, StartExecutionFailure,
    StartExecutionRequest, StartExecutionResult,
};

#[cfg(feature = "durable")]
use crate::durable_start::{
    DurableRegistrationEvent, DurableStartExecutionCoordinator, PreparedDurableResume,
};
#[cfg(feature = "durable")]
use crate::{
    DurableResumeExecutionFailure, DurableResumeExecutionRequest, DurableResumeExecutionResult,
    DurableRunFailure, DurableStartExecutionFailure, DurableStartExecutionRequest,
    DurableStartExecutionResult,
};

/// Supported nondurable interpreter facade over injected host integrations.
pub struct Interpreter {
    inner: Arc<InterpreterInner>,
    external_owner: bool,
}

struct InterpreterInner {
    external_owners: AtomicUsize,
    shutdown_started: AtomicBool,
    shutdown: Arc<SharedShutdown>,
    #[cfg(feature = "test-support")]
    nondurable_test_coordinators: Mutex<BTreeMap<ProtocolIdentity, ExecutionCoordinator>>,
    #[cfg(feature = "durable")]
    durable_executions: DurableExecutionRegistry,
    #[cfg(all(feature = "durable", feature = "test-support"))]
    durable_handoff_test_gate: Mutex<Option<Arc<DurableHandoffTestGate>>>,
    configuration: InterpreterConfiguration,
    lifecycle: InterpreterLifecycle,
    allocator: FreshIdentityAllocator,
    blocking_work_poison: AdapterPoison,
    clock: Arc<dyn UtcClock>,
    preflight: Arc<dyn IntegrationPreflight>,
    session_establisher: SessionEstablisher,
    hook_factory: Arc<dyn HookFactory>,
    event_delivery_runtime: Arc<dyn EventDeliveryRuntime>,
    event_delivery: SinkPlan,
}

struct ExecutorEventDeliveryRuntime {
    executor: Arc<dyn ExecutorAdapter>,
}

impl EventDeliveryRuntime for ExecutorEventDeliveryRuntime {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        timeout_us: u64,
    ) -> HostFuture<'a, Result<gantry_core::portable::DeliveryOutcome, HostError>> {
        let timeout = DurationMicros::new(timeout_us)
            .unwrap_or_else(|| unreachable!("validated event timeout is portable"));
        Box::pin(async move {
            match deadline_race(&*self.executor, sink.deliver(request), timeout, None).await {
                DeadlineOutcome::Completed(result) => result,
                DeadlineOutcome::TimedOut => Ok(gantry_core::portable::DeliveryOutcome::Retriable),
                DeadlineOutcome::Failed(error) => Err(error),
                DeadlineOutcome::Cancelled => Err(HostError {
                    code: Arc::from("event-delivery-cancelled"),
                    protected_diagnostic: None,
                }),
            }
        })
    }

    fn sleep<'a>(&'a self, delay_us: u64) -> HostFuture<'a, Result<(), HostError>> {
        let delay = DurationMicros::new(delay_us)
            .unwrap_or_else(|| unreachable!("validated event delay is portable"));
        self.executor.sleep(delay)
    }

    fn sample_full_jitter(&self, ceiling_us: u64) -> Result<u64, HostError> {
        let range = InclusiveJitterRange::new(0, ceiling_us)
            .unwrap_or_else(|| unreachable!("event jitter range begins at zero"));
        self.executor.sample_inclusive(range)
    }
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct DurableExecutionRegistry {
    state: Mutex<DurableExecutionRegistryState>,
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct DurableExecutionRegistryState {
    executions: BTreeMap<ProtocolIdentity, DurableExecutionRegistration>,
    waiters: BTreeMap<ProtocolIdentity, Vec<Waker>>,
}

#[cfg(feature = "durable")]
enum DurableExecutionRegistration {
    Pending,
    Owned(Arc<crate::DurableOwnedExecution>),
}

/// Test-support gate that pauses a durable start after lifecycle acceptance
/// and before its durable owner is published to the interpreter registry.
#[cfg(all(feature = "durable", feature = "test-support"))]
#[doc(hidden)]
#[derive(Default)]
pub struct DurableHandoffTestGate {
    state: Mutex<DurableHandoffTestGateState>,
    changed: Condvar,
}

#[cfg(all(feature = "durable", feature = "test-support"))]
#[derive(Default)]
struct DurableHandoffTestGateState {
    accepted: Option<ExecutionHandle>,
    released: bool,
}

#[cfg(all(feature = "durable", feature = "test-support"))]
impl DurableHandoffTestGate {
    /// Waits until lifecycle acceptance has completed and returns its handle.
    #[must_use]
    pub fn wait_until_accepted(&self) -> ExecutionHandle {
        let mut state = lock_shutdown(&self.state);
        while state.accepted.is_none() {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state
            .accepted
            .clone()
            .unwrap_or_else(|| unreachable!("accepted handoff gate retains its handle"))
    }

    /// Releases the paused durable owner publication.
    pub fn release(&self) {
        let mut state = lock_shutdown(&self.state);
        state.released = true;
        self.changed.notify_all();
    }

    fn pause(&self, handle: ExecutionHandle) {
        let mut state = lock_shutdown(&self.state);
        state.accepted = Some(handle);
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

#[cfg(feature = "durable")]
impl DurableExecutionRegistry {
    fn mark(&self, execution_id: ProtocolIdentity) {
        let mut state = lock_shutdown(&self.state);
        state
            .executions
            .entry(execution_id)
            .or_insert(DurableExecutionRegistration::Pending);
    }

    fn publish(&self, owner: Arc<crate::DurableOwnedExecution>) {
        let execution_id = owner.execution_id();
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            state
                .executions
                .insert(execution_id, DurableExecutionRegistration::Owned(owner));
            state.waiters.remove(&execution_id).unwrap_or_default()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn abandon(&self, execution_id: ProtocolIdentity) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            state.executions.remove(&execution_id);
            state.waiters.remove(&execution_id).unwrap_or_default()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    async fn owner(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<Arc<crate::DurableOwnedExecution>> {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            match state.executions.get(&execution_id) {
                Some(DurableExecutionRegistration::Owned(owner)) => {
                    Poll::Ready(Some(Arc::clone(owner)))
                }
                Some(DurableExecutionRegistration::Pending) => {
                    let waiters = state.waiters.entry(execution_id).or_default();
                    if !waiters
                        .iter()
                        .any(|waiter| waiter.will_wake(context.waker()))
                    {
                        waiters.push(context.waker().clone());
                    }
                    Poll::Pending
                }
                None => Poll::Ready(None),
            }
        })
        .await
    }
}

#[cfg(feature = "durable")]
struct OwnedDurableResumeRequest {
    journal_id: gantry_host::journal::JournalId,
    protocol_selection: gantry_core::protocol::ProtocolSelection,
    candidate_package_root: Option<PathBuf>,
    expected_execution_id: Option<ProtocolIdentity>,
    event_delivery: Option<gantry_observe::SinkPlan>,
}

#[cfg(feature = "durable")]
impl OwnedDurableResumeRequest {
    fn borrowed(&self) -> DurableResumeExecutionRequest<'_> {
        DurableResumeExecutionRequest {
            journal_id: self.journal_id.clone(),
            protocol_selection: &self.protocol_selection,
            candidate_package_root: self.candidate_package_root.as_deref(),
            expected_execution_id: self.expected_execution_id,
            event_delivery: self.event_delivery.as_ref(),
        }
    }
}

#[cfg(feature = "durable")]
struct RecoveredRootDriver {
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    create_request: gantry_host::contracts::HostRequest,
    operations: DurableOperationContext,
    #[cfg(feature = "concurrent")]
    program: Arc<gantry_ir::MachineProgram>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    root_supervision: Arc<Mutex<Option<SupervisedTask>>>,
}

/// Privately owned machine graph shared by independent durable task futures.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableMachineGraph {
    foreground: Machine,
    children: BTreeMap<ProtocolIdentity, Machine>,
    frontier: (ProtocolIdentity, u64),
    next_event_sequence: BTreeMap<ProtocolIdentity, u64>,
}

/// Wake-driven exclusive access to one durable machine graph.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct SharedDurableMachineGraph {
    state: Mutex<SharedDurableMachineGraphState>,
    program: Arc<gantry_ir::MachineProgram>,
    operations: DurableOperationContext,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
struct SharedDurableMachineGraphState {
    graph: Option<DurableMachineGraph>,
    failed: bool,
    finalization_requested: bool,
    control_started: bool,
    control_reservation: Option<AdmissionReservation>,
    tasks: BTreeMap<ProtocolIdentity, SupervisedTask>,
    commands: VecDeque<DurableGraphControlCommand>,
    control_waker: Option<Waker>,
    waiters: Vec<Waker>,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
enum DurableGraphControlCommand {
    SettleAbnormalChild {
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    },
    Complete,
    Fail(DurableRunFailure),
}

/// RAII graph lease restored to the wake-driven owner on every normal return.
#[cfg(all(feature = "concurrent", feature = "durable"))]
struct DurableMachineGraphLease {
    shared: Arc<SharedDurableMachineGraph>,
    graph: Option<DurableMachineGraph>,
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl SharedDurableMachineGraph {
    fn new(
        graph: DurableMachineGraph,
        root_task_id: ProtocolIdentity,
        root_supervision: SupervisedTask,
        control_reservation: AdmissionReservation,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SharedDurableMachineGraphState {
                graph: Some(graph),
                failed: false,
                finalization_requested: false,
                control_started: false,
                control_reservation: Some(control_reservation),
                tasks: BTreeMap::from([(root_task_id, root_supervision)]),
                commands: VecDeque::new(),
                control_waker: None,
                waiters: Vec::new(),
            }),
            program,
            operations,
        })
    }

    async fn acquire(self: &Arc<Self>) -> Option<DurableMachineGraphLease> {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            if state.failed {
                return Poll::Ready(None);
            }
            if let Some(graph) = state.graph.take() {
                return Poll::Ready(Some(DurableMachineGraphLease {
                    shared: Arc::clone(self),
                    graph: Some(graph),
                }));
            }
            if !state
                .waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                state.waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    fn request_failure(&self, failure: DurableRunFailure) {
        let (control_waker, waiters) = {
            let mut state = lock_shutdown(&self.state);
            if state.failed {
                return;
            }
            state.failed = true;
            state.finalization_requested = true;
            state
                .commands
                .push_back(DurableGraphControlCommand::Fail(failure));
            (
                state.control_waker.take(),
                std::mem::take(&mut state.waiters),
            )
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn request_abnormal_child_settlement(
        &self,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) {
        let control_waker = {
            let mut state = lock_shutdown(&self.state);
            if state.failed || state.finalization_requested {
                return;
            }
            state
                .commands
                .push_back(DurableGraphControlCommand::SettleAbnormalChild { task_id, outcome });
            state.control_waker.take()
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
    }

    fn request_completion(&self) {
        let control_waker = {
            let mut state = lock_shutdown(&self.state);
            if state.failed || state.finalization_requested {
                return;
            }
            state.finalization_requested = true;
            state
                .commands
                .push_back(DurableGraphControlCommand::Complete);
            state.control_waker.take()
        };
        if let Some(waker) = control_waker {
            waker.wake();
        }
    }

    async fn next_control_command(&self) -> DurableGraphControlCommand {
        std::future::poll_fn(|context| {
            let mut state = lock_shutdown(&self.state);
            if let Some(command) = state.commands.pop_front() {
                return Poll::Ready(command);
            }
            state.control_waker = Some(context.waker().clone());
            Poll::Pending
        })
        .await
    }

    fn register_task(&self, task_id: ProtocolIdentity, task: SupervisedTask) {
        let mut state = lock_shutdown(&self.state);
        if state.tasks.insert(task_id, task).is_some() {
            unreachable!("one supervised handle exists per durable graph task");
        }
    }

    fn take_tasks(&self) -> Vec<SupervisedTask> {
        std::mem::take(&mut lock_shutdown(&self.state).tasks)
            .into_values()
            .collect()
    }

    fn begin_control(&self) -> Result<Option<AdmissionReservation>, DurableRunFailure> {
        let mut state = lock_shutdown(&self.state);
        if state.control_started {
            return Ok(None);
        }
        state.control_started = true;
        state
            .control_reservation
            .take()
            .map(Some)
            .ok_or(DurableRunFailure::Internal)
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl std::ops::Deref for DurableMachineGraphLease {
    type Target = DurableMachineGraph;

    fn deref(&self) -> &Self::Target {
        self.graph
            .as_ref()
            .unwrap_or_else(|| unreachable!("live graph lease retains its graph"))
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl std::ops::DerefMut for DurableMachineGraphLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.graph
            .as_mut()
            .unwrap_or_else(|| unreachable!("live graph lease retains its graph"))
    }
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
impl Drop for DurableMachineGraphLease {
    fn drop(&mut self) {
        let Some(graph) = self.graph.take() else {
            return;
        };
        let waiters = {
            let mut state = lock_shutdown(&self.shared.state);
            if !state.failed {
                state.graph = Some(graph);
            }
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

#[cfg(feature = "durable")]
#[derive(Clone)]
struct DurableOperationContext {
    execution_id: ProtocolIdentity,
    activity_id: ProtocolIdentity,
    mapping_revisions: crate::MappingRevisions,
    declared_value_shapes: Option<DeclaredValueShapes>,
    schemas: BTreeMap<TypeDescriptor, Arc<[u8]>>,
}

#[cfg(feature = "durable")]
impl DurableOperationContext {
    fn from_start(accepted: &StartExecutionAccepted) -> Self {
        let analysis = accepted
            .package_activity
            .analysis
            .as_ref()
            .unwrap_or_else(|| unreachable!("accepted durable start retains analysis"));
        let schemas = analysis
            .schemas()
            .map(|schemas| schemas.entries().iter().cloned().collect())
            .unwrap_or_default();
        Self {
            execution_id: accepted.execution_id,
            activity_id: accepted.package_activity.activity_id,
            mapping_revisions: accepted.mapping_revisions.clone(),
            declared_value_shapes: analysis.declared_value_shapes().cloned(),
            schemas,
        }
    }

    fn schema(&self, ty: &TypeDescriptor) -> Option<Arc<[u8]>> {
        self.schemas.get(ty).cloned()
    }
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct SharedResume {
    state: Mutex<SharedResumeState>,
}

#[cfg(feature = "durable")]
#[derive(Default)]
struct SharedResumeState {
    published: Option<DurableResumeExecutionResult>,
    waiters: Vec<Waker>,
}

#[cfg(feature = "durable")]
impl SharedResume {
    fn publish(&self, result: DurableResumeExecutionResult) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.published.is_some() {
                return;
            }
            state.published = Some(result);
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn poll(&self, context: &mut Context<'_>) -> Poll<DurableResumeExecutionResult> {
        let mut state = lock_shutdown(&self.state);
        if let Some(result) = &state.published {
            return Poll::Ready(result.clone());
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}

struct PreparedRootDriver {
    machine: Machine,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    workflow: gantry_ir::CanonicalPath,
    create_request: gantry_host::contracts::HostRequest,
    #[cfg(feature = "concurrent")]
    program: Arc<gantry_ir::MachineProgram>,
    #[cfg(feature = "concurrent")]
    execution_budget: ExecutionBudget,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    root_supervision: Arc<Mutex<Option<SupervisedTask>>>,
}

struct PreparedTaskDriver {
    machine: Machine,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    workflow: gantry_ir::CanonicalPath,
    create_request: gantry_host::contracts::HostRequest,
    base_session: Option<ProtocolIdentity>,
    #[cfg(feature = "concurrent")]
    program: Arc<gantry_ir::MachineProgram>,
    #[cfg(feature = "concurrent")]
    execution_budget: ExecutionBudget,
}

impl From<PreparedRootDriver> for PreparedTaskDriver {
    fn from(root: PreparedRootDriver) -> Self {
        Self {
            machine: root.machine,
            coordinator: root.coordinator,
            task_id: root.task_id,
            workflow: root.workflow,
            create_request: root.create_request,
            base_session: None,
            #[cfg(feature = "concurrent")]
            program: root.program,
            #[cfg(feature = "concurrent")]
            execution_budget: root.execution_budget,
        }
    }
}

impl PreparedRootDriver {
    fn new_for_prepared(
        inner: &InterpreterInner,
        prepared: &PreparedExecutionStart,
    ) -> Result<Self, RunExecutionError> {
        Self::new(
            inner,
            prepared.execution_id,
            &prepared.package_activity,
            prepared.entry_input.as_ref(),
            &prepared.root_session,
            true,
            None,
        )
    }

    #[cfg(all(feature = "durable", feature = "concurrent"))]
    fn new_for_durable_accepted(
        inner: &InterpreterInner,
        accepted: &StartExecutionAccepted,
        execution_budget: gantry_runtime::ExecutionBudget,
    ) -> Result<Self, RunExecutionError> {
        Self::new(
            inner,
            accepted.execution_id,
            &accepted.package_activity,
            accepted.entry_input.as_ref(),
            &accepted.root_session,
            true,
            Some(execution_budget),
        )
    }

    #[cfg(all(feature = "durable", not(feature = "concurrent")))]
    fn new_for_durable_accepted(
        inner: &InterpreterInner,
        accepted: &StartExecutionAccepted,
    ) -> Result<Self, RunExecutionError> {
        Self::new(
            inner,
            accepted.execution_id,
            &accepted.package_activity,
            accepted.entry_input.as_ref(),
            &accepted.root_session,
            true,
            None,
        )
    }

    fn new(
        inner: &InterpreterInner,
        execution_id: ProtocolIdentity,
        package_activity: &AnalyzePackageResult,
        entry_input: Option<&crate::ValidatedEntryInput>,
        root_session: &crate::RootSessionState,
        submitting: bool,
        execution_budget: Option<gantry_runtime::ExecutionBudget>,
    ) -> Result<Self, RunExecutionError> {
        let analysis = package_activity
            .analysis
            .as_ref()
            .ok_or(RunExecutionError::MissingAnalysis)?;
        let entry = analysis
            .entry()
            .cloned()
            .ok_or(RunExecutionError::MissingEntry)?;
        let program = analysis
            .executable_program()
            .cloned()
            .ok_or(RunExecutionError::MissingExecutableProgram)?;
        let arguments = entry_input
            .map(|input| {
                decode_logical_value(
                    input.canonical_json.bytes(),
                    &input.ty,
                    inner.configuration.required().value_limits,
                    analysis.declared_value_shapes(),
                )
                .map(|value| vec![value])
            })
            .transpose()?
            .unwrap_or_default();
        let initial_agent = analysis.structure().default_agent().map(Arc::from);
        let program = Arc::new(program);
        let machine_limits = inner.configuration.machine_limits();
        #[cfg(feature = "concurrent")]
        let execution_budget =
            execution_budget.unwrap_or_else(|| ExecutionBudget::new(execution_id, machine_limits));
        #[cfg(feature = "concurrent")]
        let machine = Machine::new_concurrent_root_with_budget_and_context(
            Arc::clone(&program),
            &entry.path,
            arguments,
            execution_id,
            machine_limits,
            execution_budget.clone(),
            initial_agent.clone(),
            Some(root_session.id),
        )
        .map_err(RunExecutionError::MachineBuild)?;
        #[cfg(not(feature = "concurrent"))]
        let machine = Machine::new_with_context(
            Arc::clone(&program),
            &entry.path,
            arguments,
            execution_id,
            machine_limits,
            initial_agent.clone(),
            Some(root_session.id),
        )
        .map_err(RunExecutionError::MachineBuild)?;
        let task_id = root_task_identity(execution_id);
        let root_mode = match root_session.provenance {
            crate::RootSessionProvenance::EmbedderSupplied => SessionCreationModeV1::EmbedderRoot,
            crate::RootSessionProvenance::GantryCreated => SessionCreationModeV1::GantryRoot,
        };
        let sessions = LogicalSessionRegistryV1::new(
            execution_id,
            root_session.id,
            root_mode,
            root_session.transcript.clone(),
        )
        .map_err(RunExecutionError::Session)?;
        let tasks = if submitting {
            ConcurrentTaskStateV1::with_submitting_root(
                execution_id,
                task_id,
                inner.configuration.maximum_tasks_per_execution(),
            )
        } else {
            ConcurrentTaskStateV1::new(
                execution_id,
                task_id,
                inner.configuration.maximum_tasks_per_execution(),
            )
        }
        .map_err(RunExecutionError::TaskState)?;
        #[cfg(feature = "concurrent")]
        let coordinator =
            ExecutionCoordinator::new_with_budget(tasks, sessions, execution_budget.clone())
                .map_err(RunExecutionError::TaskState)?;
        #[cfg(not(feature = "concurrent"))]
        let coordinator = {
            let _ = execution_budget;
            ExecutionCoordinator::new(tasks, sessions).map_err(RunExecutionError::TaskState)?
        };
        let create_request = TaskContextV1 {
            execution_id,
            task_id,
            inherited_agent: initial_agent,
            session: TaskSessionContextV1::Root {
                root_session_id: root_session.id,
                provenance: match root_session.provenance {
                    crate::RootSessionProvenance::EmbedderSupplied => {
                        RootSessionProvenanceV1::EmbedderSupplied
                    }
                    crate::RootSessionProvenance::GantryCreated => {
                        RootSessionProvenanceV1::GantryCreated
                    }
                },
            },
        }
        .into_host_request()
        .map_err(RunExecutionError::HookRequest)?;
        Ok(Self {
            machine,
            coordinator,
            task_id,
            workflow: entry.path,
            create_request,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            execution_budget,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            root_supervision: Arc::new(Mutex::new(None)),
        })
    }
}

#[derive(Default)]
struct RootStartGate {
    state: std::sync::atomic::AtomicU8,
    waiters: Mutex<Vec<Waker>>,
}

impl RootStartGate {
    async fn wait(&self) -> bool {
        std::future::poll_fn(|context| {
            let state = self.state.load(Ordering::Acquire);
            if state != 0 {
                return Poll::Ready(state == 1);
            }
            let mut waiters = lock_shutdown(&self.waiters);
            let state = self.state.load(Ordering::Acquire);
            if state != 0 {
                return Poll::Ready(state == 1);
            }
            if !waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    fn release(&self) {
        self.finish(1);
    }

    fn cancel(&self) {
        self.finish(2);
    }

    fn finish(&self, state: u8) {
        if self
            .state
            .compare_exchange(0, state, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let waiters = std::mem::take(&mut *lock_shutdown(&self.waiters));
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl Clone for Interpreter {
    fn clone(&self) -> Self {
        self.inner.external_owners.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
            external_owner: true,
        }
    }
}

impl Drop for Interpreter {
    fn drop(&mut self) {
        if self.external_owner && self.inner.external_owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.lifecycle.begin_unclean_drop();
        }
    }
}

impl std::fmt::Debug for Interpreter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Interpreter")
            .field("configuration", &self.inner.configuration)
            .field("lifecycle", &self.inner.lifecycle)
            .finish_non_exhaustive()
    }
}

impl Interpreter {
    /// Constructs one running interpreter from explicit executor-neutral integrations.
    #[must_use]
    pub fn new(
        configuration: InterpreterConfiguration,
        clock: Arc<dyn UtcClock>,
        preflight: Arc<dyn IntegrationPreflight>,
        runtime_sessions: Arc<dyn RuntimeSessionService>,
        hook_factory: Arc<dyn HookFactory>,
    ) -> Self {
        let event_delivery_runtime = Arc::new(ExecutorEventDeliveryRuntime {
            executor: configuration.executor_arc(),
        });
        Self::new_with_event_delivery(
            configuration,
            clock,
            preflight,
            runtime_sessions,
            hook_factory,
            event_delivery_runtime,
            SinkPlan::default(),
        )
    }

    /// Constructs one interpreter with explicit event-delivery services and a default sink plan.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_event_delivery(
        configuration: InterpreterConfiguration,
        clock: Arc<dyn UtcClock>,
        preflight: Arc<dyn IntegrationPreflight>,
        runtime_sessions: Arc<dyn RuntimeSessionService>,
        hook_factory: Arc<dyn HookFactory>,
        event_delivery_runtime: Arc<dyn EventDeliveryRuntime>,
        event_delivery: SinkPlan,
    ) -> Self {
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let session_establisher = SessionEstablisher::new(
            lifecycle.task_supervisor(),
            runtime_sessions,
            AdapterPoison::default(),
        );
        Self {
            inner: Arc::new(InterpreterInner {
                external_owners: AtomicUsize::new(1),
                shutdown_started: AtomicBool::new(false),
                shutdown: Arc::new(SharedShutdown::default()),
                #[cfg(feature = "test-support")]
                nondurable_test_coordinators: Mutex::new(BTreeMap::new()),
                #[cfg(feature = "durable")]
                durable_executions: DurableExecutionRegistry::default(),
                #[cfg(all(feature = "durable", feature = "test-support"))]
                durable_handoff_test_gate: Mutex::new(None),
                configuration,
                lifecycle,
                allocator: FreshIdentityAllocator::default(),
                blocking_work_poison: AdapterPoison::default(),
                clock,
                preflight,
                session_establisher,
                hook_factory,
                event_delivery_runtime,
                event_delivery,
            }),
            external_owner: true,
        }
    }

    /// Installs the one-shot durable acceptance handoff gate used by
    /// deterministic conformance tests.
    #[cfg(all(feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub fn install_durable_handoff_test_gate(&self, gate: Arc<DurableHandoffTestGate>) {
        *lock_shutdown(&self.inner.durable_handoff_test_gate) = Some(gate);
    }

    /// Runs preflight, publishes accepted state, and submits the root to the configured executor.
    pub async fn start_execution(
        &self,
        request: StartExecutionRequest<'_>,
    ) -> StartExecutionResult {
        let event_delivery = request.event_delivery.unwrap_or(&self.inner.event_delivery);
        let request = StartExecutionRequest {
            event_delivery: Some(event_delivery),
            ..request
        };
        let package = AnalyzePackageCoordinator::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
            self.inner.configuration.blocking_work(),
        )
        .with_blocking_work_poison(self.inner.blocking_work_poison.clone())
        .with_delivery_runtime(self.inner.event_delivery_runtime.as_ref());
        let coordinator = StartExecutionCoordinator::new(
            &package,
            &self.inner.lifecycle,
            &self.inner.configuration,
            &self.inner.allocator,
            Arc::clone(&self.inner.preflight),
        )
        .with_owned_event_delivery(owned_event_delivery_factory(Arc::clone(&self.inner)));
        let prepared = match coordinator.prepare(request).await {
            Ok(prepared) => prepared,
            Err(failure) => return StartExecutionResult::Rejected(failure),
        };
        let root = match PreparedRootDriver::new_for_prepared(&self.inner, &prepared) {
            Ok(root) => root,
            Err(error) => {
                return StartExecutionResult::Rejected(prepared_start_failure(
                    prepared,
                    StartFailureCategory::Internal,
                    preparation_error_code(&error),
                ));
            }
        };
        let workflow = root.workflow.clone();
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::RootTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                return StartExecutionResult::Rejected(prepared_start_failure(
                    prepared,
                    StartFailureCategory::ImplementationResourceExhaustion,
                    "root-task-capacity",
                ));
            }
        };
        let accepted = match prepared.accept_state() {
            Ok(accepted) => accepted,
            Err(failure) => return StartExecutionResult::Rejected(failure),
        };
        let driver = TaskDriver::from_prepared(Arc::clone(&self.inner), accepted.clone(), root);
        let task_coordinator = driver.coordinator();
        #[cfg(feature = "test-support")]
        lock_shutdown(&self.inner.nondurable_test_coordinators)
            .insert(accepted.execution_id, task_coordinator.clone());
        let abnormal = driver.abnormal_completion_handler();
        let completion = driver.physical_completion_handler();
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::Root,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task = driver.into_gated_owned_task(signal, Arc::clone(&gate));
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                if task_coordinator.resolve_root_submission().is_ok() {
                    task.relinquish();
                    gate.release();
                } else {
                    let outcome = root_start_failure(&workflow, RuntimeCode::InternalInvariant);
                    let _ = settle_root_start_failure(
                        &self.inner.lifecycle,
                        &accepted,
                        &task_coordinator,
                        outcome,
                        false,
                    );
                    gate.cancel();
                    task.relinquish();
                }
            }
            Err(_) => {
                let outcome = root_start_failure(&workflow, RuntimeCode::RootSubmissionFailure);
                let _ = settle_root_start_failure(
                    &self.inner.lifecycle,
                    &accepted,
                    &task_coordinator,
                    outcome,
                    true,
                );
            }
        }
        StartExecutionResult::Accepted(Box::new(accepted))
    }

    /// Commits durable acceptance, publishes owned state, and submits the root automatically.
    #[cfg(feature = "durable")]
    pub async fn start_durable_execution(
        &self,
        storage: Arc<dyn JournalStorage>,
        request: DurableStartExecutionRequest<'_>,
    ) -> DurableStartExecutionResult {
        let event_delivery = request
            .start
            .event_delivery
            .unwrap_or(&self.inner.event_delivery);
        let request = DurableStartExecutionRequest {
            journal_id: request.journal_id,
            start: StartExecutionRequest {
                event_delivery: Some(event_delivery),
                ..request.start
            },
        };
        let journal_id = request.journal_id.clone();
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::RootTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                return DurableStartExecutionResult::Rejected(DurableStartExecutionFailure {
                    journal_id,
                    failure: StartExecutionFailure {
                        category: StartFailureCategory::ImplementationResourceExhaustion,
                        code: Arc::from("root-task-capacity"),
                        package_activity: None,
                    },
                    release_error: None,
                });
            }
        };
        let package = AnalyzePackageCoordinator::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
            self.inner.configuration.blocking_work(),
        )
        .with_blocking_work_poison(self.inner.blocking_work_poison.clone())
        .with_delivery_runtime(self.inner.event_delivery_runtime.as_ref());
        let start = StartExecutionCoordinator::new(
            &package,
            &self.inner.lifecycle,
            &self.inner.configuration,
            &self.inner.allocator,
            Arc::clone(&self.inner.preflight),
        )
        .with_owned_event_delivery(owned_event_delivery_factory(Arc::clone(&self.inner)));
        let durable = DurableStartExecutionCoordinator::new(
            start,
            &self.inner.configuration,
            Arc::clone(&storage),
        );
        let registry = &self.inner.durable_executions;
        let accepted = match durable
            .start_with_registration(request, |event| match event {
                DurableRegistrationEvent::Marked(execution_id) => registry.mark(execution_id),
                #[cfg(feature = "test-support")]
                DurableRegistrationEvent::Accepted(handle) => {
                    let gate = lock_shutdown(&self.inner.durable_handoff_test_gate).clone();
                    if let Some(gate) = gate {
                        gate.pause(handle);
                    }
                }
                DurableRegistrationEvent::Published(owner) => registry.publish(owner),
                DurableRegistrationEvent::Abandoned(execution_id) => registry.abandon(execution_id),
            })
            .await
        {
            DurableStartExecutionResult::Accepted(accepted) => accepted,
            rejected => return rejected,
        };
        #[cfg(feature = "concurrent")]
        let prepared = PreparedRootDriver::new_for_durable_accepted(
            &self.inner,
            &accepted.start,
            accepted.execution_budget.clone(),
        )
        .unwrap_or_else(|_| unreachable!("committed start retained validated root state"));
        #[cfg(not(feature = "concurrent"))]
        let prepared = PreparedRootDriver::new_for_durable_accepted(&self.inner, &accepted.start)
            .unwrap_or_else(|_| unreachable!("committed start retained validated root state"));
        let task_id = prepared.task_id;
        let task_coordinator = prepared.coordinator.clone();
        #[cfg(feature = "concurrent")]
        let root_supervision = Arc::clone(&prepared.root_supervision);
        let completion_coordinator = task_coordinator.clone();
        let completion: PhysicalCompletionHandler = Arc::new(move |_| {
            let _ = completion_coordinator.mark_driver_physically_settled(task_id);
        });
        let registration =
            supervisor.prepare_with_completion(SupervisedTaskDomain::Root, None, Some(completion));
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let owner = Arc::clone(&accepted.owned);
        let driver_owner = Arc::clone(&owner);
        let driver_inner = Arc::clone(&self.inner);
        let driver_accepted = accepted.start.clone();
        let driver_gate = Arc::clone(&gate);
        let task: OwnedTaskFuture = Box::pin(async move {
            if driver_gate.wait().await {
                let interpreter = Interpreter {
                    inner: driver_inner,
                    external_owner: false,
                };
                interpreter
                    .drive_durable_execution(driver_accepted, prepared, driver_owner)
                    .await;
            }
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                if task_coordinator.resolve_root_submission().is_ok() {
                    #[cfg(feature = "concurrent")]
                    {
                        *lock_shutdown(&root_supervision) = Some(task);
                    }
                    #[cfg(not(feature = "concurrent"))]
                    task.relinquish();
                    gate.release();
                } else {
                    gate.cancel();
                    task.relinquish();
                    if let Some(recovered) = owner.begin_driver() {
                        owner.fail_driver(recovered, DurableRunFailure::Internal);
                    }
                }
            }
            Err(_) => {
                self.start_owned_durable_submission_failure(
                    task_coordinator,
                    owner,
                    accepted.start.package_activity.activity_id,
                    task_id,
                );
            }
        }
        DurableStartExecutionResult::Accepted(accepted)
    }

    /// Reconstructs and atomically admits one existing durable execution.
    #[cfg(feature = "durable")]
    pub async fn resume_durable_execution(
        &self,
        storage: Arc<dyn JournalStorage>,
        request: DurableResumeExecutionRequest<'_>,
    ) -> DurableResumeExecutionResult {
        let request = OwnedDurableResumeRequest {
            journal_id: request.journal_id,
            protocol_selection: request.protocol_selection.clone(),
            candidate_package_root: request.candidate_package_root.map(PathBuf::from),
            expected_execution_id: request.expected_execution_id,
            event_delivery: Some(
                request
                    .event_delivery
                    .cloned()
                    .unwrap_or_else(|| self.inner.event_delivery.clone()),
            ),
        };
        let result = Arc::new(SharedResume::default());
        self.start_owned_durable_resume(storage, request, Arc::clone(&result));
        std::future::poll_fn(|context| result.poll(context)).await
    }

    #[cfg(feature = "durable")]
    fn start_owned_durable_resume(
        &self,
        storage: Arc<dyn JournalStorage>,
        request: OwnedDurableResumeRequest,
        result: Arc<SharedResume>,
    ) {
        let journal_id = request.journal_id.clone();
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::PublicActivity) {
            Ok(reservation) => reservation,
            Err(_) => {
                result.publish(resume_failure(
                    journal_id,
                    ResumeStartFailureCategory::ImplementationResourceExhaustion,
                    "resume-activity-capacity",
                ));
                return;
            }
        };
        let abnormal_result = Arc::clone(&result);
        let abnormal_journal = journal_id.clone();
        let abnormal: AbnormalCompletionHandler = Arc::new(move |_| {
            abnormal_result.publish(resume_failure(
                abnormal_journal.clone(),
                ResumeStartFailureCategory::Internal,
                "resume-coordinator-failure",
            ));
        });
        let registration = supervisor.prepare(SupervisedTaskDomain::PublicActivity, Some(abnormal));
        let signal = registration.signal();
        let inner = Arc::clone(&self.inner);
        let task_result = Arc::clone(&result);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            let package = AnalyzePackageCoordinator::new(
                &interpreter.inner.allocator,
                interpreter.inner.configuration.identity_source(),
                interpreter.inner.clock.as_ref(),
                interpreter.inner.configuration.blocking_work(),
            )
            .with_blocking_work_poison(interpreter.inner.blocking_work_poison.clone())
            .with_delivery_runtime(interpreter.inner.event_delivery_runtime.as_ref());
            let start = StartExecutionCoordinator::new(
                &package,
                &interpreter.inner.lifecycle,
                &interpreter.inner.configuration,
                &interpreter.inner.allocator,
                Arc::clone(&interpreter.inner.preflight),
            )
            .with_owned_event_delivery(owned_event_delivery_factory(Arc::clone(
                &interpreter.inner,
            )));
            let durable = DurableStartExecutionCoordinator::new(
                start,
                &interpreter.inner.configuration,
                storage,
            );
            let resumed = durable
                .resume_with_handoff(request.borrowed(), |prepared| {
                    interpreter.handoff_prepared_resume(&durable, prepared)
                })
                .await;
            task_result.publish(resumed);
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task.relinquish(),
            Err(_) => result.publish(resume_failure(
                journal_id,
                ResumeStartFailureCategory::Internal,
                "resume-coordinator-submission-failure",
            )),
        }
    }

    #[cfg(feature = "durable")]
    async fn handoff_prepared_resume(
        &self,
        durable: &DurableStartExecutionCoordinator<'_>,
        mut prepared: PreparedDurableResume,
    ) -> DurableResumeExecutionResult {
        if prepared.recovered.latest_cut() == DurableCommitCutV1::TerminalCompletion {
            if let Err(failure) = durable.commit_prepared_resume_revision(&mut prepared).await {
                return durable.reject_prepared_resume_with(prepared, failure).await;
            }
            self.mark_durable_execution(prepared.execution_id);
            let accepted = match durable.publish_prepared_resume(prepared) {
                Ok(accepted) => accepted,
                Err(prepared) => {
                    self.abandon_durable_execution(prepared.execution_id);
                    unreachable!("reserved resume identity remains publishable")
                }
            };
            self.register_durable_execution(Arc::clone(&accepted.owned));
            let _ = accepted
                .owned
                .drain_event_obligations(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await;
            return DurableResumeExecutionResult::Accepted(Box::new(accepted));
        }

        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::ResumeRunnableTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::ImplementationResourceExhaustion,
                        "resume-runnable-task-capacity",
                    )
                    .await;
            }
        };
        let driver = match self.recovered_root_driver(&prepared) {
            Ok(driver) => driver,
            Err(code) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                        code,
                    )
                    .await;
            }
        };
        let task_id = driver.task_id;
        #[cfg(feature = "concurrent")]
        let root_supervision = Arc::clone(&driver.root_supervision);
        let completion_coordinator = driver.coordinator.clone();
        let completion: PhysicalCompletionHandler = Arc::new(move |_| {
            let _ = completion_coordinator.mark_driver_physically_settled(task_id);
        });
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::Resume,
            None,
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task_gate = Arc::clone(&gate);
        let inner = Arc::clone(&self.inner);
        let slot = Arc::new(Mutex::new(None));
        let task_slot = Arc::clone(&slot);
        let task: OwnedTaskFuture = Box::pin(async move {
            if task_gate.wait().await {
                let (driver, owner) = lock_shutdown(&task_slot)
                    .take()
                    .unwrap_or_else(|| unreachable!("released resume gate retains its driver"));
                let interpreter = Interpreter {
                    inner,
                    external_owner: false,
                };
                interpreter
                    .drive_recovered_durable_execution(driver, owner)
                    .await;
            }
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        let submitted = match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task,
            Err(_) => {
                return durable
                    .reject_prepared_resume(
                        prepared,
                        ResumeStartFailureCategory::Internal,
                        "resume-task-submission-failure",
                    )
                    .await;
            }
        };
        if let Err(failure) = durable.commit_prepared_resume_revision(&mut prepared).await {
            rollback_submitted_resume(submitted, gate).await;
            return durable.reject_prepared_resume_with(prepared, failure).await;
        }
        self.mark_durable_execution(prepared.execution_id);
        let accepted = match durable.publish_prepared_resume(prepared) {
            Ok(accepted) => accepted,
            Err(prepared) => {
                self.abandon_durable_execution(prepared.execution_id);
                unreachable!("reserved resume identity remains publishable")
            }
        };
        self.register_durable_execution(Arc::clone(&accepted.owned));
        *lock_shutdown(&slot) = Some((driver, Arc::clone(&accepted.owned)));
        #[cfg(feature = "concurrent")]
        {
            *lock_shutdown(&root_supervision) = Some(submitted);
        }
        #[cfg(not(feature = "concurrent"))]
        submitted.relinquish();
        gate.release();
        DurableResumeExecutionResult::Accepted(Box::new(accepted))
    }

    #[cfg(feature = "durable")]
    fn recovered_root_driver(
        &self,
        prepared: &PreparedDurableResume,
    ) -> Result<RecoveredRootDriver, &'static str> {
        let sessions = prepared
            .recovered
            .sessions()
            .cloned()
            .ok_or("missing-logical-sessions")?;
        let (root_session_id, provenance) = {
            let root = sessions
                .sessions()
                .find(|session| session.parent.is_none())
                .ok_or("missing-root-session")?;
            let provenance = match root.mode {
                SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
                SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
                SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
                    return Err("invalid-root-session");
                }
            };
            (root.id, provenance)
        };
        let task_id = root_task_identity(prepared.execution_id);
        let tasks = ConcurrentTaskStateV1::from_sequential_recovery(
            prepared.execution_id,
            task_id,
            self.inner.configuration.maximum_tasks_per_execution(),
            prepared.recovered.latest_cut(),
            prepared.recovered.machine().outcome().cloned(),
        )
        .map_err(|_| "invalid-recovered-task-state")?;
        #[cfg(feature = "concurrent")]
        let coordinator = ExecutionCoordinator::new_with_budget(
            tasks,
            sessions,
            prepared.recovered.machine().execution_budget(),
        )
        .map_err(|_| "invalid-recovered-task-state")?;
        #[cfg(not(feature = "concurrent"))]
        let coordinator = ExecutionCoordinator::new(tasks, sessions)
            .map_err(|_| "invalid-recovered-task-state")?;
        let create_request = TaskContextV1 {
            execution_id: prepared.execution_id,
            task_id,
            inherited_agent: prepared.recovered.machine().active_agent().map(Arc::from),
            session: TaskSessionContextV1::Root {
                root_session_id,
                provenance,
            },
        }
        .into_host_request()
        .map_err(|_| "invalid-recovered-hook-context")?;
        let declared_value_shapes = prepared
            .candidate_package_activity
            .as_ref()
            .and_then(|activity| activity.analysis.as_ref())
            .and_then(|analysis| analysis.declared_value_shapes())
            .cloned();
        let schemas = decode_retained_schemas(
            prepared.retained_artifacts.generated_schemas(),
            self.inner
                .configuration
                .required()
                .frontend_limits
                .maximum_constructed_type_depth(),
        )?;
        Ok(RecoveredRootDriver {
            coordinator,
            task_id,
            create_request,
            operations: DurableOperationContext {
                execution_id: prepared.execution_id,
                activity_id: prepared.activity_id,
                mapping_revisions: prepared.mapping_revisions.clone(),
                declared_value_shapes,
                schemas,
            },
            #[cfg(feature = "concurrent")]
            program: Arc::new(
                prepared
                    .recovered
                    .execution_start()
                    .ok_or("missing-execution-start")?
                    .program()
                    .map_err(|_| "invalid-retained-program")?,
            ),
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            root_supervision: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(feature = "durable")]
    fn start_owned_durable_submission_failure(
        &self,
        coordinator: ExecutionCoordinator,
        owner: Arc<crate::DurableOwnedExecution>,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) {
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve_control_plane() {
            Ok(reservation) => reservation,
            Err(_) => {
                if let Some(recovered) = owner.begin_driver() {
                    owner.fail_driver(recovered, DurableRunFailure::Internal);
                }
                return;
            }
        };
        let registration = supervisor.prepare(SupervisedTaskDomain::ControlPlane, None);
        let signal = registration.signal();
        let inner = Arc::clone(&self.inner);
        let fallback_owner = Arc::clone(&owner);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            interpreter
                .settle_durable_submission_failure(coordinator, owner, activity_id, task_id)
                .await;
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task.relinquish(),
            Err(_) => {
                if let Some(recovered) = fallback_owner.begin_driver() {
                    fallback_owner.fail_driver(recovered, DurableRunFailure::Internal);
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    fn start_durable_graph_finalizer(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) -> Result<(), DurableRunFailure> {
        let supervisor = self.inner.lifecycle.task_supervisor();
        let Some(reservation) = graph.begin_control()? else {
            return Ok(());
        };
        let registration = supervisor.prepare(SupervisedTaskDomain::ControlPlane, None);
        let signal = registration.signal();
        let inner = Arc::clone(&self.inner);
        let fallback_graph = Arc::clone(&graph);
        let fallback_owner = Arc::clone(&owner);
        let task: OwnedTaskFuture = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            interpreter
                .drive_durable_graph_control(graph, owner, coordinator, program, operations)
                .await;
            let _ = signal.settle();
            OwnedTaskResult::new()
        });
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                task.relinquish();
                Ok(())
            }
            Err(_) => {
                let _ = fallback_owner;
                fallback_graph.request_failure(DurableRunFailure::Internal);
                Err(DurableRunFailure::Internal)
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn drive_durable_graph_control(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
    ) {
        loop {
            match graph.next_control_command().await {
                DurableGraphControlCommand::SettleAbnormalChild { task_id, outcome } => {
                    if let Err(failure) = self
                        .settle_durable_abnormal_child(
                            &graph,
                            &owner,
                            &coordinator,
                            &operations,
                            task_id,
                            outcome,
                        )
                        .await
                    {
                        graph.request_failure(failure);
                    }
                }
                DurableGraphControlCommand::Complete => {
                    let tasks = graph.take_tasks();
                    for task in tasks {
                        let _ = task.completion().await;
                    }
                    match owner
                        .drain_graph_event_obligations(
                            program,
                            &coordinator,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                            self.inner.event_delivery_runtime.as_ref(),
                        )
                        .await
                    {
                        Ok(_) => {
                            let _ = owner.finish_graph_driver().await;
                        }
                        Err(failure) => {
                            let _ = owner.finish_failed_graph_driver(failure).await;
                        }
                    }
                    return;
                }
                DurableGraphControlCommand::Fail(failure) => {
                    if let Ok(cancellation) = owner.execution_handle().cancellation_signal() {
                        let _ = cancellation.cancel();
                    }
                    let tasks = graph.take_tasks();
                    for task in &tasks {
                        let _ = task.request_abort();
                    }
                    for task in tasks {
                        let _ = task.completion().await;
                    }
                    let _ = owner.finish_failed_graph_driver(failure).await;
                    return;
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn settle_durable_abnormal_child(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) -> Result<(), DurableRunFailure> {
        let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
        let sequence = lease
            .next_event_sequence
            .get(&task_id)
            .copied()
            .unwrap_or(0);
        let draft = machine_lifecycle_event(
            &MachineLabel::TaskSettled(outcome.clone()),
            operations.execution_id,
            task_id,
        )
        .ok_or(DurableRunFailure::Internal)?;
        let event = self
            .complete_graph_event(operations, task_id, sequence, draft.clone())
            .await?;
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut *lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .update(|_, children, tasks, _| {
                children.remove(&task_id);
                tasks.mark_driver_physically_settled(task_id)?;
                tasks.settle(task_id, outcome)
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::TaskSettlement,
                task_id,
            )
            .await?;
        lease.next_event_sequence.insert(
            task_id,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );
        Ok(())
    }

    #[cfg(feature = "durable")]
    async fn settle_durable_submission_failure(
        &self,
        coordinator: ExecutionCoordinator,
        owner: Arc<crate::DurableOwnedExecution>,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) {
        let Some(mut recovered) = owner.begin_driver() else {
            return;
        };
        let mut last_committed = recovered.clone();
        let mut task_event_sequence = 0_u64;
        let _ = recovered.machine_mut().fail_root_submission();
        loop {
            match recovered.machine_mut().step() {
                MachineStep::Transition(MachineLabel::Failure(_)) => {}
                MachineStep::Transition(MachineLabel::TaskSettled(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(&mut recovered, DurableCommitCutV1::TaskSettlement, None)
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TaskSettled(outcome.clone()),
                        owner.execution_id(),
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("task settlement has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::ForegroundCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::ForegroundCompletion(outcome.clone()),
                        owner.execution_id(),
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("foreground completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                    if let Err(failure) = owner.publish_driver_progress(&recovered) {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::TerminalCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TerminalCompletion(outcome),
                        owner.execution_id(),
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("terminal completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                MachineStep::Complete(_) => {
                    let _ = owner
                        .finish_driver_terminal(
                            recovered,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                            self.inner.event_delivery_runtime.as_ref(),
                        )
                        .await;
                    return;
                }
                _ => {
                    owner.fail_driver(last_committed, DurableRunFailure::Internal);
                    return;
                }
            }
        }
    }

    #[cfg(feature = "durable")]
    async fn drive_durable_execution(
        &self,
        accepted: StartExecutionAccepted,
        prepared: PreparedRootDriver,
        owner: Arc<crate::DurableOwnedExecution>,
    ) {
        let operations = DurableOperationContext::from_start(&accepted);
        let PreparedRootDriver {
            machine: _,
            coordinator,
            task_id,
            workflow: _,
            create_request,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            root_supervision,
            ..
        } = prepared;
        self.drive_recovered_durable_execution(
            RecoveredRootDriver {
                coordinator,
                task_id,
                create_request,
                operations,
                #[cfg(feature = "concurrent")]
                program,
                #[cfg(feature = "concurrent")]
                root_supervision,
            },
            owner,
        )
        .await;
    }

    #[cfg(feature = "durable")]
    async fn drive_recovered_durable_execution(
        &self,
        driver: RecoveredRootDriver,
        owner: Arc<crate::DurableOwnedExecution>,
    ) {
        let Some(mut recovered) = owner.begin_driver() else {
            return;
        };
        let mut last_committed = recovered.clone();
        if let Err(failure) = owner.reconcile_driver_required_delivery_failure(&mut recovered) {
            owner.fail_driver(last_committed, failure);
            return;
        }
        let RecoveredRootDriver {
            coordinator,
            task_id,
            create_request,
            operations,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            root_supervision,
        } = driver;
        let cancellation = owner
            .execution_handle()
            .cancellation_signal()
            .unwrap_or_else(|_| unreachable!("accepted durable execution retains cancellation"));
        let mut hook = TaskHook::new(
            &self.inner.lifecycle,
            self.inner.hook_factory.as_ref(),
            AdapterPoison::default(),
            create_request,
        )
        .unwrap_or_else(|_| unreachable!("committed durable start retains hook context"));
        let mut model_session_occurrence = 0_u64;
        let mut task_event_sequence = 0_u64;
        loop {
            if let Some(reason) = owner.take_driver_cancellation() {
                if let Err(failure) = owner
                    .commit_driver_cancellation(&mut recovered, reason)
                    .await
                {
                    owner.fail_driver(last_committed, failure);
                    return;
                }
                last_committed = recovered.clone();
            }
            match recovered.machine_mut().step() {
                MachineStep::Transition(MachineLabel::TaskSettled(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(&mut recovered, DurableCommitCutV1::TaskSettlement, None)
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TaskSettled(outcome.clone()),
                        operations.execution_id,
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("task settlement has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::ForegroundCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::ForegroundCompletion(outcome.clone()),
                        operations.execution_id,
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("foreground completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                    if let Err(failure) = owner.publish_driver_progress(&recovered) {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                    if let Err(failure) = owner
                        .commit_driver_cut(
                            &mut recovered,
                            DurableCommitCutV1::TerminalCompletion,
                            None,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    last_committed = recovered.clone();
                    let event = machine_lifecycle_event(
                        &MachineLabel::TerminalCompletion(outcome),
                        operations.execution_id,
                        task_id,
                    )
                    .unwrap_or_else(|| unreachable!("terminal completion has one event draft"));
                    if let Err(failure) = self
                        .commit_durable_event(
                            &owner,
                            &mut recovered,
                            operations.activity_id,
                            task_id,
                            &mut task_event_sequence,
                            event,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                    if coordinator.publish_committed_root(&recovered).is_err() {
                        owner.fail_driver(last_committed, DurableRunFailure::Internal);
                        return;
                    }
                }
                #[cfg(feature = "concurrent")]
                MachineStep::Transition(MachineLabel::TaskControlSuspended(suspension)) => {
                    let root_supervision = lock_shutdown(&root_supervision)
                        .take()
                        .ok_or(DurableRunFailure::Internal);
                    let control_reservation = self
                        .inner
                        .lifecycle
                        .task_supervisor()
                        .try_reserve_control_plane()
                        .map_err(|_| DurableRunFailure::Internal);
                    let (root_supervision, control_reservation) =
                        match (root_supervision, control_reservation) {
                            (Ok(root_supervision), Ok(control_reservation)) => {
                                (root_supervision, control_reservation)
                            }
                            _ => {
                                owner.fail_driver(last_committed, DurableRunFailure::Internal);
                                return;
                            }
                        };
                    let graph = SharedDurableMachineGraph::new(
                        DurableMachineGraph {
                            foreground: recovered.into_machine(),
                            children: BTreeMap::new(),
                            frontier: (
                                last_committed.latest_evidence_id(),
                                last_committed.latest_sequence(),
                            ),
                            next_event_sequence: BTreeMap::from([(task_id, task_event_sequence)]),
                        },
                        task_id,
                        root_supervision,
                        control_reservation,
                        Arc::clone(&program),
                        operations.clone(),
                    );
                    owner.activate_graph_driver();
                    let result = self
                        .drive_durable_graph_task(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                            task_id,
                            Some(hook),
                            Some(suspension),
                            model_session_occurrence,
                        )
                        .await;
                    if let Err(failure) = result {
                        graph.request_failure(failure.clone());
                        let _ = self.start_durable_graph_finalizer(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                        );
                    }
                    return;
                }
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => {
                    match owner
                        .poll_driver_future(
                            &mut recovered,
                            &mut last_committed,
                            self.inner.configuration.executor().yield_now(),
                        )
                        .await
                    {
                        Ok(crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(()))) => {
                            if !recovered.machine_mut().resume_after_yield() {
                                owner.fail_driver(last_committed, DurableRunFailure::Internal);
                                return;
                            }
                        }
                        Ok(crate::durable_lifecycle::DurableDriverPoll::CancellationSettled) => {}
                        Ok(crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_))) => {
                            owner.fail_driver(last_committed, DurableRunFailure::Internal);
                            return;
                        }
                        Err(failure) => {
                            owner.fail_driver(last_committed, failure);
                            return;
                        }
                    }
                }
                MachineStep::Complete(_) => {
                    let _ = owner
                        .finish_driver_terminal(
                            recovered,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                            self.inner.event_delivery_runtime.as_ref(),
                        )
                        .await;
                    return;
                }
                MachineStep::WaitingSessionScope(scope) => {
                    if let Err(failure) = self
                        .drive_durable_session_scope(
                            operations.execution_id,
                            task_id,
                            &mut recovered,
                            &scope,
                            &owner,
                            &mut last_committed,
                        )
                        .await
                    {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
                MachineStep::WaitingOperation(operation) => {
                    let result = if operation
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.kind == OperationSiteKind::Action)
                    {
                        self.drive_durable_action_operation(
                            &operations,
                            &mut recovered,
                            &mut hook,
                            &cancellation,
                            &operation,
                            &owner,
                            &mut task_event_sequence,
                            &mut last_committed,
                        )
                        .await
                    } else {
                        let result = self
                            .drive_durable_model_operation(
                                &operations,
                                &mut recovered,
                                &mut hook,
                                &cancellation,
                                &operation,
                                &owner,
                                model_session_occurrence,
                                &mut task_event_sequence,
                                &mut last_committed,
                            )
                            .await;
                        model_session_occurrence = model_session_occurrence.saturating_add(1);
                        result
                    };
                    if let Err(failure) = result {
                        owner.fail_driver(last_committed, failure);
                        return;
                    }
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    fn drive_durable_graph_task<'a>(
        &'a self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
        task_id: ProtocolIdentity,
        mut hook: Option<TaskHook<'a>>,
        mut initial_spawn: Option<MachineSpawnSuspension>,
        mut model_session_occurrence: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), DurableRunFailure>> + Send + 'a>> {
        Box::pin(async move {
            let cancellation = owner
                .execution_handle()
                .cancellation_signal()
                .map_err(DurableRunFailure::Lifecycle)?;
            'graph_driver: loop {
                if let Some(suspension) = initial_spawn.take() {
                    self.submit_durable_source_child(
                        Arc::clone(&graph),
                        Arc::clone(&owner),
                        coordinator.clone(),
                        Arc::clone(&program),
                        operations.clone(),
                        task_id,
                        suspension,
                    )
                    .await?;
                    continue;
                }

                let mut lease = match self
                    .poll_durable_graph_future(&graph, &owner, &coordinator, graph.acquire())
                    .await?
                {
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(lease)) => {
                        lease
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                        return Ok(());
                    }
                    crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                        continue;
                    }
                };
                let step = if task_id == lease.foreground.task_id() {
                    lease.foreground.step()
                } else {
                    lease
                        .children
                        .get_mut(&task_id)
                        .ok_or(DurableRunFailure::Internal)?
                        .step()
                };
                match step {
                    MachineStep::Transition(MachineLabel::TaskControlSuspended(suspension)) => {
                        drop(lease);
                        self.submit_durable_source_child(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                            task_id,
                            suspension,
                        )
                        .await?;
                    }
                    MachineStep::Transition(MachineLabel::TaskSettled(outcome)) => {
                        let sequence = lease
                            .next_event_sequence
                            .get(&task_id)
                            .copied()
                            .unwrap_or(0);
                        let draft = machine_lifecycle_event(
                            &MachineLabel::TaskSettled(outcome.clone()),
                            operations.execution_id,
                            task_id,
                        )
                        .ok_or(DurableRunFailure::Internal)?;
                        let event = self
                            .complete_graph_event(&operations, task_id, sequence, draft.clone())
                            .await?;
                        let predecessor = lease.frontier;
                        let DurableMachineGraph {
                            foreground,
                            children,
                            ..
                        } = &mut *lease;
                        let mut transaction = coordinator
                            .stage_graph(foreground, children)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        transaction
                            .update(|_, children, tasks, _| {
                                if task_id != tasks.root_task_id() {
                                    children.remove(&task_id);
                                }
                                tasks.settle(task_id, outcome)
                            })
                            .map_err(|_| DurableRunFailure::Internal)?;
                        transaction
                            .set_event(
                                event,
                                owner.graph_event_plan()?,
                                draft.protected_payloads.to_vec(),
                            )
                            .map_err(DurableRunFailure::Commit)?;
                        lease.frontier = owner
                            .commit_graph_transaction(
                                &coordinator,
                                transaction,
                                predecessor,
                                DurableCommitCutV1::TaskSettlement,
                                task_id,
                            )
                            .await?;
                        lease.next_event_sequence.insert(
                            task_id,
                            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                        );
                        if task_id != coordinator.snapshot().state().root_task_id() {
                            return Ok(());
                        }
                    }
                    MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                        loop {
                            let attached = coordinator.shutdown_cohort().attached_tasks;
                            if attached.is_empty() {
                                break;
                            }
                            drop(lease);
                            for child in attached {
                                let wait = coordinator
                                    .wait_for_task_settlement(child)
                                    .map_err(|_| DurableRunFailure::Internal)?;
                                let _ = self
                                    .poll_durable_graph_future(&graph, &owner, &coordinator, wait)
                                    .await?;
                            }
                            lease = match self
                                .poll_durable_graph_future(
                                    &graph,
                                    &owner,
                                    &coordinator,
                                    graph.acquire(),
                                )
                                .await?
                            {
                                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(
                                    lease,
                                )) => lease,
                                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                                    return Ok(())
                                }
                                crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                    continue 'graph_driver
                                }
                            };
                        }
                        self.commit_durable_graph_lifecycle(
                            &mut lease,
                            &owner,
                            &coordinator,
                            &operations,
                            task_id,
                            MachineLabel::ForegroundCompletion(outcome),
                            DurableCommitCutV1::ForegroundCompletion,
                        )
                        .await?;
                    }
                    MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                        loop {
                            let detached = coordinator.shutdown_cohort().detached_tasks;
                            if detached.is_empty() {
                                break;
                            }
                            drop(lease);
                            for child in detached {
                                let wait = coordinator
                                    .wait_for_task_settlement(child)
                                    .map_err(|_| DurableRunFailure::Internal)?;
                                let _ = self
                                    .poll_durable_graph_future(&graph, &owner, &coordinator, wait)
                                    .await?;
                            }
                            lease = match self
                                .poll_durable_graph_future(
                                    &graph,
                                    &owner,
                                    &coordinator,
                                    graph.acquire(),
                                )
                                .await?
                            {
                                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(
                                    lease,
                                )) => lease,
                                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                                    return Ok(())
                                }
                                crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                    continue 'graph_driver
                                }
                            };
                        }
                        self.commit_durable_graph_lifecycle(
                            &mut lease,
                            &owner,
                            &coordinator,
                            &operations,
                            task_id,
                            MachineLabel::TerminalCompletion(outcome),
                            DurableCommitCutV1::TerminalCompletion,
                        )
                        .await?;
                        drop(lease);
                        graph.request_completion();
                        self.start_durable_graph_finalizer(
                            Arc::clone(&graph),
                            Arc::clone(&owner),
                            coordinator.clone(),
                            Arc::clone(&program),
                            operations.clone(),
                        )?;
                        return Ok(());
                    }
                    MachineStep::Transition(MachineLabel::OperationPrepared(_)) => {}
                    MachineStep::Transition(_) => {}
                    MachineStep::YieldRequired => {
                        drop(lease);
                        match self
                            .poll_durable_graph_future(
                                &graph,
                                &owner,
                                &coordinator,
                                self.inner.configuration.executor().yield_now(),
                            )
                            .await?
                        {
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Ok(())) => {}
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Err(_)) => {
                                return Err(DurableRunFailure::Internal)
                            }
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                continue
                            }
                        }
                        let mut lease = match self
                            .poll_durable_graph_future(
                                &graph,
                                &owner,
                                &coordinator,
                                graph.acquire(),
                            )
                            .await?
                        {
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(Some(
                                lease,
                            )) => lease,
                            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(None) => {
                                return Ok(())
                            }
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                                continue
                            }
                        };
                        let machine = if task_id == lease.foreground.task_id() {
                            &mut lease.foreground
                        } else {
                            lease
                                .children
                                .get_mut(&task_id)
                                .ok_or(DurableRunFailure::Internal)?
                        };
                        if !machine.resume_after_yield() {
                            return Err(DurableRunFailure::Internal);
                        }
                    }
                    MachineStep::WaitingOperation(operation) => {
                        drop(lease);
                        if operation
                            .metadata
                            .as_ref()
                            .is_some_and(|metadata| metadata.kind == OperationSiteKind::Action)
                        {
                            self.drive_durable_graph_action_operation(
                                &graph,
                                &owner,
                                &coordinator,
                                &operations,
                                task_id,
                                hook.as_mut().ok_or(DurableRunFailure::Internal)?,
                                &cancellation,
                                &operation,
                            )
                            .await?;
                        } else {
                            self.drive_durable_graph_model_operation(
                                &graph,
                                &owner,
                                &coordinator,
                                &operations,
                                task_id,
                                hook.as_mut().ok_or(DurableRunFailure::Internal)?,
                                &cancellation,
                                &operation,
                                model_session_occurrence,
                            )
                            .await?;
                            model_session_occurrence = model_session_occurrence.saturating_add(1);
                        }
                    }
                    MachineStep::WaitingSessionScope(_) => {
                        return Err(DurableRunFailure::Internal);
                    }
                    MachineStep::Complete(_) => return Ok(()),
                }
            }
        })
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn poll_durable_graph_future<F>(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        future: F,
    ) -> Result<crate::durable_lifecycle::DurableGraphDriverPoll<F::Output>, DurableRunFailure>
    where
        F: Future,
    {
        let mut future = std::pin::pin!(future);
        let first = std::future::poll_fn(|context| match owner.poll_graph_cancellation(context) {
            crate::durable_lifecycle::DurableGraphCancellationPoll::Claimed(reason) => {
                Poll::Ready(Err(reason))
            }
            crate::durable_lifecycle::DurableGraphCancellationPoll::Waiting => Poll::Pending,
            crate::durable_lifecycle::DurableGraphCancellationPoll::Continue => {
                match future.as_mut().poll(context) {
                    Poll::Ready(output) => {
                        owner.clear_graph_driver_waker(context.waker());
                        Poll::Ready(Ok(output))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        })
        .await;
        match first {
            Ok(output) => Ok(crate::durable_lifecycle::DurableGraphDriverPoll::Completed(
                output,
            )),
            Err(reason) => {
                self.commit_durable_graph_cancellation(graph, owner, coordinator, reason)
                    .await?;
                Ok(crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled)
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_graph_cancellation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        reason: CancellationReason,
    ) -> Result<(), DurableRunFailure> {
        let mut lease = graph.acquire().await.ok_or(DurableRunFailure::Internal)?;
        self.commit_durable_graph_cancellation_with_lease(&mut lease, owner, coordinator, reason)
            .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_graph_cancellation_with_lease(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        reason: CancellationReason,
    ) -> Result<(), DurableRunFailure> {
        let reason_text = reason
            .message
            .clone()
            .unwrap_or_else(|| Arc::from(reason.category.wire_name()));
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let affected = transaction
            .update(|foreground, children, tasks, _| {
                let affected = tasks.cancel_execution(Arc::clone(&reason_text))?;
                for task_id in &affected {
                    if *task_id == foreground.task_id() {
                        let _ = foreground.cancel(Arc::clone(&reason_text));
                    } else if let Some(machine) = children.get_mut(task_id) {
                        let _ = machine.cancel(Arc::clone(&reason_text));
                    }
                }
                Ok::<_, TaskStateError>(affected)
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        let Some(affected_task) = affected.first().copied() else {
            drop(transaction);
            owner.complete_graph_cancellation_without_cut();
            return Ok(());
        };
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::Cancellation,
                affected_task,
            )
            .await?;
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn acquire_durable_graph_lease(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
    ) -> Result<Option<DurableMachineGraphLease>, DurableRunFailure> {
        match self
            .poll_durable_graph_future(graph, owner, coordinator, graph.acquire())
            .await?
        {
            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(lease) => Ok(lease),
            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => Ok(None),
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    fn durable_graph_machine_mut(
        lease: &mut DurableMachineGraphLease,
        task_id: ProtocolIdentity,
    ) -> Result<&mut Machine, DurableRunFailure> {
        if task_id == lease.foreground.task_id() {
            Ok(&mut lease.foreground)
        } else {
            lease
                .children
                .get_mut(&task_id)
                .ok_or(DurableRunFailure::Internal)
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn fail_durable_graph_spawn(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        suspension: &MachineSpawnSuspension,
        code: RuntimeCode,
    ) -> Result<(), DurableRunFailure> {
        Self::durable_graph_machine_mut(lease, parent_task_id)?
            .fail_spawn(suspension, code)
            .map_err(|_| DurableRunFailure::Internal)?;
        self.commit_durable_graph_checkpoint(lease, owner, coordinator)
            .await
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn submit_durable_source_child(
        &self,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        coordinator: ExecutionCoordinator,
        program: Arc<gantry_ir::MachineProgram>,
        operations: DurableOperationContext,
        parent_task_id: ProtocolIdentity,
        suspension: MachineSpawnSuspension,
    ) -> Result<(), DurableRunFailure> {
        let task_limit_reached = |coordinator: &ExecutionCoordinator| {
            let snapshot = coordinator.snapshot();
            snapshot.state().created_task_count() >= snapshot.state().maximum_task_count()
        };
        let parent_is_cancelled = |coordinator: &ExecutionCoordinator| {
            coordinator
                .snapshot()
                .state()
                .task_cancellation_reason(parent_task_id)
                .is_some()
        };

        let Some(mut lease) = self
            .acquire_durable_graph_lease(&graph, &owner, &coordinator)
            .await?
        else {
            return Ok(());
        };
        if parent_is_cancelled(&coordinator)
            || Self::durable_graph_machine_mut(&mut lease, parent_task_id)?
                .outcome()
                .is_some()
        {
            return Ok(());
        }
        if task_limit_reached(&coordinator) {
            return self
                .fail_durable_graph_spawn(
                    &mut lease,
                    &owner,
                    &coordinator,
                    parent_task_id,
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .await;
        }
        let parent_session_id = suspension
            .parent_session
            .ok_or(DurableRunFailure::Internal)?;
        let parent_session = coordinator
            .session(parent_session_id)
            .ok_or(DurableRunFailure::Internal)?;
        drop(lease);
        let established = match self
            .poll_durable_graph_future(
                &graph,
                &owner,
                &coordinator,
                self.inner
                    .session_establisher
                    .establish(operations.execution_id, &parent_session),
            )
            .await?
        {
            crate::durable_lifecycle::DurableGraphDriverPoll::Completed(established) => established,
            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => return Ok(()),
        };
        let Some(mut lease) = self
            .acquire_durable_graph_lease(&graph, &owner, &coordinator)
            .await?
        else {
            return Ok(());
        };
        if parent_is_cancelled(&coordinator)
            || Self::durable_graph_machine_mut(&mut lease, parent_task_id)?
                .outcome()
                .is_some()
        {
            return Ok(());
        }
        if established.is_err() {
            return self
                .fail_durable_graph_spawn(
                    &mut lease,
                    &owner,
                    &coordinator,
                    parent_task_id,
                    &suspension,
                    RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                )
                .await;
        }
        if task_limit_reached(&coordinator) {
            return self
                .fail_durable_graph_spawn(
                    &mut lease,
                    &owner,
                    &coordinator,
                    parent_task_id,
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .await;
        }
        let sequence = lease
            .next_event_sequence
            .get(&parent_task_id)
            .copied()
            .unwrap_or(0);
        let captures = suspension
            .captures
            .iter()
            .map(|capture| capture.task_capture().clone())
            .collect::<Vec<_>>();
        let predecessor = lease.frontier;
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut *lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let created = match transaction.update(|_, _, tasks, sessions| {
            tasks.create_child(
                sessions,
                TaskCreationRequestV1 {
                    parent_task_id,
                    handle_name: Arc::from(suspension.handle.name()),
                    workflow: suspension.workflow.clone(),
                    spawn_site: suspension.site.clone(),
                    spawn_occurrence: suspension.occurrence,
                    result_type: suspension.handle.result_type().clone(),
                    captures: captures.clone(),
                    inherited_agent: suspension.inherited_agent.clone(),
                    parent_session_id,
                },
                self.inner.configuration.required().value_limits,
            )
        }) {
            Ok(created) => created,
            Err(TaskStateError::TaskCountLimit) => {
                transaction
                    .update(|foreground, children, _, _| {
                        let parent = if foreground.task_id() == parent_task_id {
                            foreground
                        } else {
                            children
                                .get_mut(&parent_task_id)
                                .ok_or(TaskStateError::UnknownTask)?
                        };
                        parent
                            .fail_spawn(
                                &suspension,
                                RuntimeCode::Deterministic(
                                    DeterministicEvaluationCode::TaskCountLimit,
                                ),
                            )
                            .map(|_| ())
                            .map_err(|_| TaskStateError::InvalidTransition)
                    })
                    .map_err(|_| DurableRunFailure::Internal)?;
                lease.frontier = owner
                    .commit_graph_transaction(
                        &coordinator,
                        transaction,
                        predecessor,
                        DurableCommitCutV1::Checkpoint,
                        root_task,
                    )
                    .await?;
                return Ok(());
            }
            Err(TaskStateError::TaskCancelled) => return Ok(()),
            Err(_) => return Err(DurableRunFailure::Internal),
        };
        let draft = concurrent_spawn_event(operations.execution_id, &created.transition, sequence)
            .map_err(|_| DurableRunFailure::Internal)?;
        let event = self
            .complete_graph_event(&operations, parent_task_id, sequence, draft.clone())
            .await?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        lease.frontier = owner
            .commit_graph_transaction(
                &coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::TaskCreation,
                created.task_id,
            )
            .await?;
        lease.next_event_sequence.insert(
            parent_task_id,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );

        let occurrence_frontier = lease.frontier.1;
        let (frontier, barrier) = owner
            .drain_graph_required_event_obligations_through(
                Arc::clone(&program),
                &coordinator,
                occurrence_frontier,
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                self.inner.event_delivery_runtime.as_ref(),
            )
            .await?;
        lease.frontier = frontier;
        if let DurableEventBarrierV1::RequiredExhausted(failure) = barrier {
            let reason = owner.request_graph_cancellation(CancellationReason {
                category: CancellationReasonCategory::Runtime,
                message: Some(Arc::from("required-event-delivery-failure")),
                causal_identity: None,
            });
            self.commit_durable_graph_cancellation_with_lease(
                &mut lease,
                &owner,
                &coordinator,
                reason,
            )
            .await?;
            owner.record_graph_required_delivery_failure(failure)?;
            self.settle_durable_cancelled_unsubmitted_child(
                &mut lease,
                &owner,
                &coordinator,
                created.task_id,
            )
            .await?;
            return Ok(());
        }

        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::SourceChildTask) {
            Ok(reservation) => reservation,
            Err(_) => {
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
                return Ok(());
            }
        };

        let snapshot = coordinator.snapshot();
        let child_record = snapshot
            .state()
            .task(created.task_id)
            .ok_or(DurableRunFailure::Internal)?;
        let child_session = coordinator
            .session(created.base_session_id)
            .ok_or(DurableRunFailure::Internal)?;
        let root_session = coordinator
            .session(child_session.root)
            .ok_or(DurableRunFailure::Internal)?;
        let root_provenance = match root_session.mode {
            SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
            SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
            SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
                return Err(DurableRunFailure::Internal);
            }
        };
        let child_machine = match Machine::new_concurrent_task_body_with_context(
            Arc::clone(&program),
            &suspension.body,
            &captures,
            operations.execution_id,
            created.task_id,
            Arc::from(child_record.task_path()),
            self.inner.configuration.machine_limits(),
            lease.foreground.execution_budget(),
            suspension.inherited_agent.clone(),
            Some(created.base_session_id),
        ) {
            Ok(machine) => machine,
            Err(_) => {
                drop(reservation);
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
                return Ok(());
            }
        };
        let create_request = match (TaskContextV1 {
            execution_id: operations.execution_id,
            task_id: created.task_id,
            inherited_agent: suspension.inherited_agent.clone(),
            session: TaskSessionContextV1::Forked {
                base_session_id: created.base_session_id,
                parent_session_id,
                root_session_id: child_session.root,
                root_provenance,
            },
        })
        .into_host_request()
        {
            Ok(request) => request,
            Err(_) => {
                drop(reservation);
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
                return Ok(());
            }
        };

        let child_task_id = created.task_id;
        let task_graph = Arc::clone(&graph);
        let task_owner = Arc::clone(&owner);
        let task_coordinator = coordinator.clone();
        let task_program = Arc::clone(&program);
        let task_operations = operations.clone();
        let task_inner = Arc::clone(&self.inner);
        let task_session = child_session.clone();
        let task_future = Box::pin(async move {
            let interpreter = Interpreter {
                inner: task_inner,
                external_owner: false,
            };
            let (established, cancellation_settled) = match interpreter
                .poll_durable_graph_future(
                    &task_graph,
                    &task_owner,
                    &task_coordinator,
                    interpreter
                        .inner
                        .session_establisher
                        .establish(task_operations.execution_id, &task_session),
                )
                .await
            {
                Ok(crate::durable_lifecycle::DurableGraphDriverPoll::Completed(established)) => {
                    match interpreter
                        .poll_durable_graph_future(
                            &task_graph,
                            &task_owner,
                            &task_coordinator,
                            std::future::ready(()),
                        )
                        .await
                    {
                        Ok(crate::durable_lifecycle::DurableGraphDriverPoll::Completed(())) => {
                            (established, false)
                        }
                        Ok(
                            crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled,
                        ) => (Ok(()), true),
                        Err(failure) => {
                            task_graph.request_failure(failure.clone());
                            let _ = interpreter.start_durable_graph_finalizer(
                                Arc::clone(&task_graph),
                                Arc::clone(&task_owner),
                                task_coordinator,
                                task_program,
                                task_operations,
                            );
                            return Ok(());
                        }
                    }
                }
                Ok(crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled) => {
                    (Ok(()), true)
                }
                Err(failure) => {
                    task_graph.request_failure(failure.clone());
                    let _ = interpreter.start_durable_graph_finalizer(
                        Arc::clone(&task_graph),
                        Arc::clone(&task_owner),
                        task_coordinator,
                        task_program,
                        task_operations,
                    );
                    return Ok(());
                }
            };
            let hook = if cancellation_settled {
                None
            } else if established.is_err() {
                if let Some(mut lease) = task_graph.acquire().await
                    && let Some(machine) = lease.children.get_mut(&child_task_id)
                {
                    let _ = machine.fail_execution(
                        RuntimeErrorCategory::LogicalSessionSetup,
                        gantry_runtime::ExecutionFailureProjection::Full,
                    );
                }
                None
            } else {
                Some(
                    TaskHook::new(
                        &interpreter.inner.lifecycle,
                        interpreter.inner.hook_factory.as_ref(),
                        AdapterPoison::default(),
                        create_request,
                    )
                    .map_err(|_| DurableRunFailure::Internal),
                )
            };
            let result = match hook.transpose() {
                Ok(hook) => {
                    interpreter
                        .drive_durable_graph_task(
                            Arc::clone(&task_graph),
                            Arc::clone(&task_owner),
                            task_coordinator.clone(),
                            Arc::clone(&task_program),
                            task_operations.clone(),
                            child_task_id,
                            hook,
                            None,
                            0,
                        )
                        .await
                }
                Err(failure) => Err(failure),
            };
            if let Err(failure) = result {
                task_graph.request_failure(failure.clone());
                let _ = interpreter.start_durable_graph_finalizer(
                    Arc::clone(&task_graph),
                    Arc::clone(&task_owner),
                    task_coordinator,
                    task_program,
                    task_operations,
                );
            }
            Ok(())
        });
        let driver = TaskDriver::from_durable_graph_child(
            Arc::clone(&self.inner),
            coordinator.clone(),
            child_task_id,
            suspension.workflow.clone(),
            Arc::clone(&graph),
            Arc::clone(&owner),
            task_future,
        );
        let abnormal = driver.abnormal_completion_handler();
        let completion = driver.physical_completion_handler();
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::SourceChild,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task = driver.into_gated_owned_task(signal, Arc::clone(&gate));

        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                let disposition = self
                    .commit_durable_child_submission_resolution(
                        &mut lease,
                        &owner,
                        &coordinator,
                        &operations,
                        parent_task_id,
                        &created,
                        &suspension,
                        Some(child_machine),
                    )
                    .await;
                match disposition {
                    Ok(false) => {
                        graph.register_task(child_task_id, task);
                        gate.release();
                    }
                    Ok(true) => {
                        gate.cancel();
                        let _ = task.request_abort();
                        let _ = task.completion().await;
                        task.relinquish();
                    }
                    Err(failure) => {
                        gate.cancel();
                        let _ = task.request_abort();
                        let _ = task.completion().await;
                        task.relinquish();
                        return Err(failure);
                    }
                }
            }
            Err(_) => {
                self.commit_durable_child_submission_resolution(
                    &mut lease,
                    &owner,
                    &coordinator,
                    &operations,
                    parent_task_id,
                    &created,
                    &suspension,
                    None,
                )
                .await?;
            }
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn settle_durable_cancelled_unsubmitted_child(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
    ) -> Result<(), DurableRunFailure> {
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .update(|_, _, tasks, _| {
                tasks.resolve_submission(task_id, Ok(()))?;
                tasks.mark_driver_physically_settled(task_id)?;
                Ok::<_, TaskStateError>(())
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::TaskSettlement,
                task_id,
            )
            .await?;
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_child_submission_resolution(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        parent_task_id: ProtocolIdentity,
        created: &gantry_runtime::TaskCreationV1,
        suspension: &MachineSpawnSuspension,
        child_machine: Option<Machine>,
    ) -> Result<bool, DurableRunFailure> {
        let completed_event = if child_machine.is_none() {
            let sequence = lease
                .next_event_sequence
                .get(&created.task_id)
                .copied()
                .unwrap_or(0);
            let outcome = MachineOutcome::Failed(MachineFailure {
                code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
                workflow: suspension.workflow.clone(),
                site: suspension.site.clone(),
            });
            let draft = machine_lifecycle_event(
                &MachineLabel::TaskSettled(outcome),
                operations.execution_id,
                created.task_id,
            )
            .ok_or(DurableRunFailure::Internal)?;
            let event = self
                .complete_graph_event(operations, created.task_id, sequence, draft.clone())
                .await?;
            Some((sequence, event, draft))
        } else {
            None
        };
        let predecessor = lease.frontier;
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        let submitted = child_machine.is_some();
        let disposition = transaction
            .update(|foreground, children, tasks, _| {
                let parent = if foreground.task_id() == parent_task_id {
                    foreground
                } else {
                    children
                        .get_mut(&parent_task_id)
                        .ok_or(TaskStateError::UnknownTask)?
                };
                parent
                    .complete_spawn(suspension, created.handle_id)
                    .map_err(|_| TaskStateError::InvalidTransition)?;
                tasks.resolve_submission(
                    created.task_id,
                    if submitted {
                        Ok(())
                    } else {
                        Err(HostError {
                            code: Arc::from("task-submission-failure"),
                            protected_diagnostic: None,
                        })
                    },
                )
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        if !disposition.is_cancelled()
            && let Some(machine) = child_machine
        {
            transaction
                .install_child_machine(created.task_id, machine)
                .map_err(|_| DurableRunFailure::Internal)?;
        }
        if disposition.is_rejected()
            && let Some((_, event, draft)) = &completed_event
        {
            transaction
                .set_event(
                    event.clone(),
                    owner.graph_event_plan()?,
                    draft.protected_payloads.to_vec(),
                )
                .map_err(DurableRunFailure::Commit)?;
        }
        let (cut, affected_task) = if submitted && !disposition.is_cancelled() {
            (DurableCommitCutV1::Checkpoint, root_task)
        } else {
            (DurableCommitCutV1::TaskSettlement, created.task_id)
        };
        lease.frontier = owner
            .commit_graph_transaction(coordinator, transaction, predecessor, cut, affected_task)
            .await?;
        if disposition.is_rejected()
            && let Some((sequence, _, _)) = completed_event
        {
            lease.next_event_sequence.insert(
                created.task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(disposition.is_cancelled())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_graph_action_operation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        hook: &mut TaskHook<'_>,
        cancellation: &CancellationSignal,
        occurrence: &gantry_runtime::OperationOccurrence,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let action = metadata
            .action
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        if metadata.kind != OperationSiteKind::Action
            || action.parameters.len() != occurrence.inputs.len()
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .action
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: action.path.clone(),
                signature: action.signature.clone(),
                recovery: action.recovery,
                mapping_revision,
                arguments: action
                    .parameters
                    .iter()
                    .zip(occurrence.inputs.iter())
                    .map(|(parameter, value)| TypedActionArgumentV1 {
                        name: Arc::from(parameter.name()),
                        ty: parameter.ty().clone(),
                        value: value.canonical_json(),
                    })
                    .collect(),
            },
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(|_| DurableRunFailure::Internal)?;
        let mut retries_left = None;

        loop {
            let (prepared, validation_attempt, recovery_dispatch) =
                operation
                    .prepared_dispatch()
                    .ok_or(DurableRunFailure::Internal)?;
            let dispatch_id = prepared.dispatch_id;
            let request_bytes: Arc<[u8]> = Arc::from(prepared.request.canonical_bytes());
            let action_recovery = Some(action.recovery);
            let dispatch_event = operation_dispatch_event(
                operation.captured(),
                prepared,
                validation_attempt,
                recovery_dispatch,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            self.commit_durable_graph_operation_cut(
                &mut lease,
                owner,
                coordinator,
                context,
                task_id,
                DurableCommitCutV1::OperationPrepared,
                DurableOperationEvidenceV1 {
                    operation_id: occurrence.identity,
                    dispatch_id: Some(dispatch_id),
                    validation_attempt,
                    recovery_dispatch,
                    retry_delay_us: None,
                    retries_left,
                    action_recovery,
                    request_bytes: Some(Arc::clone(&request_bytes)),
                    outcome: None,
                    retry_errors: Arc::from([]),
                    result_type: None,
                    result_bytes: None,
                },
                Some(dispatch_event),
            )
            .await?;
            drop(lease);
            let dispatch = match self
                .poll_durable_graph_future(
                    graph,
                    owner,
                    coordinator,
                    operation.dispatch(hook, cancellation),
                )
                .await?
            {
                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => result,
                crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                    return Ok(());
                }
            };
            if dispatch.is_err() {
                let Some(mut lease) = self
                    .acquire_durable_graph_lease(graph, owner, coordinator)
                    .await?
                else {
                    return Ok(());
                };
                let machine = if task_id == lease.foreground.task_id() {
                    &mut lease.foreground
                } else {
                    lease
                        .children
                        .get_mut(&task_id)
                        .ok_or(DurableRunFailure::Internal)?
                };
                let category = if hook.is_ready() {
                    RuntimeErrorCategory::HookFailure
                } else {
                    RuntimeErrorCategory::HookCreation
                };
                machine
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                    .await?;
                return Ok(());
            }
            let (_, outcome, validation_attempt, recovery_dispatch) =
                operation
                    .outcome_context()
                    .ok_or(DurableRunFailure::Internal)?;
            let outcome = outcome.clone();
            let completion_event = operation_completion_event(
                operation.captured(),
                dispatch_id,
                validation_attempt,
                recovery_dispatch,
                &outcome,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            self.commit_durable_graph_operation_cut(
                &mut lease,
                owner,
                coordinator,
                context,
                task_id,
                DurableCommitCutV1::OperationOutcome,
                DurableOperationEvidenceV1 {
                    operation_id: occurrence.identity,
                    dispatch_id: Some(dispatch_id),
                    validation_attempt,
                    recovery_dispatch,
                    retry_delay_us: None,
                    retries_left,
                    action_recovery,
                    request_bytes: Some(Arc::clone(&request_bytes)),
                    outcome: Some(outcome.clone()),
                    retry_errors: Arc::from([]),
                    result_type: None,
                    result_bytes: None,
                },
                Some(completion_event),
            )
            .await?;
            drop(lease);
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                    if metadata.attempted {
                        operation.accept_attempt(machine, value)
                    } else {
                        operation.accept(machine, value)
                    }
                    .map_err(|_| DurableRunFailure::Internal)?;
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::OperationResult,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: None,
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery,
                            request_bytes: None,
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: Some(metadata.result_type.clone()),
                            result_bytes: Some(result_bytes),
                        },
                        Some(result_event),
                    )
                    .await?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::RetryWaiting,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: Some(wait.delay.get()),
                            retries_left,
                            action_recovery,
                            request_bytes: Some(request_bytes),
                            outcome: Some(outcome),
                            retry_errors: Arc::clone(&wait.errors),
                            result_type: None,
                            result_bytes: None,
                        },
                        None,
                    )
                    .await?;
                    drop(lease);
                    let prepared = match self
                        .poll_durable_graph_future(
                            graph,
                            owner,
                            coordinator,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                            result.map_err(|_| DurableRunFailure::Internal)?
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    };
                    if prepared.is_none() {
                        let Some(mut lease) = self
                            .acquire_durable_graph_lease(graph, owner, coordinator)
                            .await?
                        else {
                            return Ok(());
                        };
                        let machine = if task_id == lease.foreground.task_id() {
                            &mut lease.foreground
                        } else {
                            lease
                                .children
                                .get_mut(&task_id)
                                .ok_or(DurableRunFailure::Internal)?
                        };
                        Self::settle_retry_terminal(machine, occurrence, &operation)
                            .map_err(|_| DurableRunFailure::Internal)?;
                        self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                            .await?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                        .await?;
                    return Ok(());
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_graph_model_operation(
        &self,
        graph: &Arc<SharedDurableMachineGraph>,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        hook: &mut TaskHook<'_>,
        cancellation: &CancellationSignal,
        occurrence: &gantry_runtime::OperationOccurrence,
        session_occurrence: u64,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_count = metadata.interpolation_types.len();
        if !matches!(
            metadata.kind,
            OperationSiteKind::Prompt | OperationSiteKind::Decide
        ) || metadata.named_input_names.len() != metadata.named_input_types.len()
            || occurrence.inputs.len()
                != interpolation_count.saturating_add(metadata.named_input_types.len())
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let selected_agent = occurrence
            .active_agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let parent_session_id = occurrence
            .active_session
            .ok_or(DurableRunFailure::Internal)?;
        let active_session_id = if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(DurableRunFailure::Internal),
            };
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            let predecessor = lease.frontier;
            let root_task = coordinator.snapshot().state().root_task_id();
            let DurableMachineGraph {
                foreground,
                children,
                ..
            } = &mut *lease;
            let mut transaction = coordinator
                .stage_graph(foreground, children)
                .map_err(|_| DurableRunFailure::Internal)?;
            let session_id = transaction
                .update(|_, _, _, sessions| {
                    sessions
                        .create(
                            parent_session_id,
                            task_id,
                            occurrence.site.clone(),
                            session_occurrence,
                            mode,
                            SessionEstablishmentV1::OperationRequest,
                        )
                        .map(|session| session.id)
                })
                .map_err(|_| DurableRunFailure::Internal)?;
            lease.frontier = owner
                .commit_graph_transaction(
                    coordinator,
                    transaction,
                    predecessor,
                    DurableCommitCutV1::Checkpoint,
                    root_task,
                )
                .await?;
            session_id
        } else {
            parent_session_id
        };
        let session = coordinator
            .session(active_session_id)
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_inputs = metadata
            .interpolation_types
            .iter()
            .zip(occurrence.inputs.iter().take(interpolation_count))
            .enumerate()
            .map(|(position, (ty, value))| {
                Ok(InterpolationInputV1 {
                    position: u64::try_from(position).map_err(|_| DurableRunFailure::Internal)?,
                    ty: ty.clone(),
                    value: value.canonical_json(),
                })
            })
            .collect::<Result<Vec<_>, DurableRunFailure>>()?;
        let named_inputs = metadata
            .named_input_names
            .iter()
            .zip(&metadata.named_input_types)
            .zip(occurrence.inputs.iter().skip(interpolation_count))
            .map(|((name, ty), value)| NamedInputV1 {
                name: Arc::clone(name),
                ty: ty.clone(),
                value: value.canonical_json(),
            })
            .collect::<Vec<_>>();
        let rendered_prompt = match render_prompt(
            &metadata.template_segments,
            occurrence.inputs.iter().take(interpolation_count),
            self.inner
                .configuration
                .required()
                .value_limits
                .maximum_string_scalars(),
        ) {
            Ok(prompt) => prompt,
            Err(RenderPromptError::Limit) => {
                let Some(mut lease) = self
                    .acquire_durable_graph_lease(graph, owner, coordinator)
                    .await?
                else {
                    return Ok(());
                };
                Self::durable_graph_machine_mut(&mut lease, task_id)?
                    .fail_operation_with_code(
                        occurrence.identity,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                    .await?;
                return Ok(());
            }
            Err(RenderPromptError::Shape) => return Err(DurableRunFailure::Internal),
        };
        let session_use = if let Some(mode) = metadata.session_mode.as_ref() {
            ModelSessionUseV1::Create {
                mode: Arc::clone(mode),
                session_id: session.id,
                parent_session_id,
                root_session_id: session.root,
                provenance: Arc::from("operation-request"),
            }
        } else {
            ModelSessionUseV1::Inline
        };
        let captured = CapturedOperationRequestV1::Model {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::clone(&selected_agent),
                mapping_revision,
                template_segments: metadata.template_segments.clone(),
                rendered_prompt: Arc::clone(&rendered_prompt),
                interpolation_inputs: interpolation_inputs.clone(),
                named_inputs: named_inputs.clone(),
                transcript: session.transcript.clone(),
                active_session_id: session.id,
                parent_session_id: session.parent,
                root_session_id: session.root,
                session_use,
            }),
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(|_| DurableRunFailure::Internal)?;
        let mut retries_left = None;

        loop {
            let (prepared, validation_attempt, recovery_dispatch) =
                operation
                    .prepared_dispatch()
                    .ok_or(DurableRunFailure::Internal)?;
            let dispatch_id = prepared.dispatch_id;
            let request_bytes: Arc<[u8]> = Arc::from(prepared.request.canonical_bytes());
            let dispatch_event = operation_dispatch_event(
                operation.captured(),
                prepared,
                validation_attempt,
                recovery_dispatch,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            self.commit_durable_graph_operation_cut(
                &mut lease,
                owner,
                coordinator,
                context,
                task_id,
                DurableCommitCutV1::OperationPrepared,
                DurableOperationEvidenceV1 {
                    operation_id: occurrence.identity,
                    dispatch_id: Some(dispatch_id),
                    validation_attempt,
                    recovery_dispatch,
                    retry_delay_us: None,
                    retries_left,
                    action_recovery: None,
                    request_bytes: Some(Arc::clone(&request_bytes)),
                    outcome: None,
                    retry_errors: Arc::from([]),
                    result_type: None,
                    result_bytes: None,
                },
                Some(dispatch_event),
            )
            .await?;
            drop(lease);

            let dispatch = match self
                .poll_durable_graph_future(
                    graph,
                    owner,
                    coordinator,
                    operation.dispatch_model(
                        hook,
                        cancellation,
                        &self.inner.session_establisher,
                        context.execution_id,
                        &session,
                    ),
                )
                .await?
            {
                crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => result,
                crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                    return Ok(());
                }
            };
            if let Err(error) = dispatch {
                let category = match error {
                    OperationLifecycleError::Cancelled => RuntimeErrorCategory::Cancellation,
                    OperationLifecycleError::Session(_) => {
                        RuntimeErrorCategory::LogicalSessionSetup
                    }
                    OperationLifecycleError::Hook(_) if hook.is_ready() => {
                        RuntimeErrorCategory::HookFailure
                    }
                    OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookCreation,
                    _ => return Err(DurableRunFailure::Internal),
                };
                let Some(mut lease) = self
                    .acquire_durable_graph_lease(graph, owner, coordinator)
                    .await?
                else {
                    return Ok(());
                };
                Self::durable_graph_machine_mut(&mut lease, task_id)?
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| DurableRunFailure::Internal)?;
                self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                    .await?;
                return Ok(());
            }

            let (_, outcome, validation_attempt, recovery_dispatch) =
                operation
                    .outcome_context()
                    .ok_or(DurableRunFailure::Internal)?;
            let outcome = outcome.clone();
            let completion_event = operation_completion_event(
                operation.captured(),
                dispatch_id,
                validation_attempt,
                recovery_dispatch,
                &outcome,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            let Some(mut lease) = self
                .acquire_durable_graph_lease(graph, owner, coordinator)
                .await?
            else {
                return Ok(());
            };
            self.commit_durable_graph_operation_cut(
                &mut lease,
                owner,
                coordinator,
                context,
                task_id,
                DurableCommitCutV1::OperationOutcome,
                DurableOperationEvidenceV1 {
                    operation_id: occurrence.identity,
                    dispatch_id: Some(dispatch_id),
                    validation_attempt,
                    recovery_dispatch,
                    retry_delay_us: None,
                    retries_left,
                    action_recovery: None,
                    request_bytes: Some(Arc::clone(&request_bytes)),
                    outcome: Some(outcome.clone()),
                    retry_errors: Arc::from([]),
                    result_type: None,
                    result_bytes: None,
                },
                Some(completion_event),
            )
            .await?;
            drop(lease);

            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let turn = TranscriptTurnV1 {
                        operation_kind: metadata.kind,
                        template_representation: metadata.template_segments.clone(),
                        rendered_prompt: Arc::clone(&rendered_prompt),
                        interpolation_inputs: interpolation_inputs.clone(),
                        using_inputs: named_inputs.clone(),
                        selected_agent: Arc::clone(&selected_agent),
                        accepted_result: AcceptedTranscriptResultV1 {
                            kind: transcript_result_kind(&metadata.result_type),
                            ty: metadata.result_type.clone(),
                            value: value.canonical_json(),
                        },
                    };
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let sequence = lease
                        .next_event_sequence
                        .get(&task_id)
                        .copied()
                        .unwrap_or(0);
                    let completed_event = self
                        .complete_graph_event(context, task_id, sequence, result_event.clone())
                        .await?;
                    let predecessor = lease.frontier;
                    let DurableMachineGraph {
                        foreground,
                        children,
                        ..
                    } = &mut *lease;
                    let mut transaction = coordinator
                        .stage_graph(foreground, children)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    let accepted = transaction.update(|foreground, children, _, sessions| {
                        let machine = if foreground.task_id() == task_id {
                            foreground
                        } else {
                            children
                                .get_mut(&task_id)
                                .ok_or(OperationLifecycleError::InvalidAcceptedValue)?
                        };
                        let session = sessions
                            .get_mut(active_session_id)
                            .ok_or(OperationLifecycleError::InvalidAcceptedValue)?;
                        if metadata.attempted {
                            operation.accept_model_attempt(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        } else {
                            operation.accept_model(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        }
                    });
                    match accepted {
                        Ok(_) => {}
                        Err(OperationLifecycleError::Transcript(
                            gantry_runtime::TranscriptError::Limit,
                        )) => {
                            drop(transaction);
                            Self::durable_graph_machine_mut(&mut lease, task_id)?
                                .fail_operation(
                                    occurrence.identity,
                                    RuntimeErrorCategory::LogicalSessionTranscriptLimit,
                                )
                                .map_err(|_| DurableRunFailure::Internal)?;
                            self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                                .await?;
                            return Ok(());
                        }
                        Err(_) => return Err(DurableRunFailure::Internal),
                    }
                    transaction
                        .set_operation(DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: None,
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: None,
                            retries_left,
                            action_recovery: None,
                            request_bytes: None,
                            outcome: None,
                            retry_errors: Arc::from([]),
                            result_type: Some(metadata.result_type.clone()),
                            result_bytes: Some(result_bytes),
                        })
                        .map_err(DurableRunFailure::Commit)?;
                    transaction
                        .set_event(
                            completed_event,
                            owner.graph_event_plan()?,
                            result_event.protected_payloads.to_vec(),
                        )
                        .map_err(DurableRunFailure::Commit)?;
                    lease.frontier = owner
                        .commit_graph_transaction(
                            coordinator,
                            transaction,
                            predecessor,
                            DurableCommitCutV1::OperationResult,
                            task_id,
                        )
                        .await?;
                    lease.next_event_sequence.insert(
                        task_id,
                        sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
                    );
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    self.commit_durable_graph_operation_cut(
                        &mut lease,
                        owner,
                        coordinator,
                        context,
                        task_id,
                        DurableCommitCutV1::RetryWaiting,
                        DurableOperationEvidenceV1 {
                            operation_id: occurrence.identity,
                            dispatch_id: Some(dispatch_id),
                            validation_attempt,
                            recovery_dispatch,
                            retry_delay_us: Some(wait.delay.get()),
                            retries_left,
                            action_recovery: None,
                            request_bytes: Some(request_bytes),
                            outcome: Some(outcome),
                            retry_errors: Arc::clone(&wait.errors),
                            result_type: None,
                            result_bytes: None,
                        },
                        None,
                    )
                    .await?;
                    drop(lease);
                    let prepared = match self
                        .poll_durable_graph_future(
                            graph,
                            owner,
                            coordinator,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableGraphDriverPoll::Completed(result) => {
                            result.map_err(|_| DurableRunFailure::Internal)?
                        }
                        crate::durable_lifecycle::DurableGraphDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    };
                    if prepared.is_none() {
                        let Some(mut lease) = self
                            .acquire_durable_graph_lease(graph, owner, coordinator)
                            .await?
                        else {
                            return Ok(());
                        };
                        Self::settle_retry_terminal(
                            Self::durable_graph_machine_mut(&mut lease, task_id)?,
                            occurrence,
                            &operation,
                        )
                        .map_err(|_| DurableRunFailure::Internal)?;
                        self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                            .await?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    let Some(mut lease) = self
                        .acquire_durable_graph_lease(graph, owner, coordinator)
                        .await?
                    else {
                        return Ok(());
                    };
                    let machine = Self::durable_graph_machine_mut(&mut lease, task_id)?;
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    self.commit_durable_graph_checkpoint(&mut lease, owner, coordinator)
                        .await?;
                    return Ok(());
                }
            }
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_graph_operation_cut(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        context: &DurableOperationContext,
        task_id: ProtocolIdentity,
        cut: DurableCommitCutV1,
        operation: DurableOperationEvidenceV1,
        event: Option<ExecutionEventDraftV1>,
    ) -> Result<(), DurableRunFailure> {
        let completed_event = if let Some(event) = event {
            let sequence = lease
                .next_event_sequence
                .get(&task_id)
                .copied()
                .unwrap_or(0);
            Some((
                sequence,
                self.complete_graph_event(context, task_id, sequence, event.clone())
                    .await?,
                event,
            ))
        } else {
            None
        };
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .set_operation(operation)
            .map_err(DurableRunFailure::Commit)?;
        if let Some((_, completed, draft)) = &completed_event {
            transaction
                .set_event(
                    completed.clone(),
                    owner.graph_event_plan()?,
                    draft.protected_payloads.to_vec(),
                )
                .map_err(DurableRunFailure::Commit)?;
        }
        lease.frontier = owner
            .commit_graph_transaction(coordinator, transaction, predecessor, cut, task_id)
            .await?;
        if let Some((sequence, _, _)) = completed_event {
            lease.next_event_sequence.insert(
                task_id,
                sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
            );
        }
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn commit_durable_graph_checkpoint(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
    ) -> Result<(), DurableRunFailure> {
        let predecessor = lease.frontier;
        let root_task = coordinator.snapshot().state().root_task_id();
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        lease.frontier = owner
            .commit_graph_transaction(
                coordinator,
                transaction,
                predecessor,
                DurableCommitCutV1::Checkpoint,
                root_task,
            )
            .await?;
        Ok(())
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    async fn complete_graph_event(
        &self,
        operations: &DurableOperationContext,
        task_id: ProtocolIdentity,
        sequence: u64,
        event: ExecutionEventDraftV1,
    ) -> Result<gantry_core::event::EventEnvelope, DurableRunFailure> {
        let draft = event
            .draft
            .with_execution_id(operations.execution_id)
            .and_then(|draft| draft.with_task(task_id, sequence))
            .map_err(|_| DurableRunFailure::Internal)?;
        EventCompleter::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
        )
        .complete(operations.activity_id, draft)
        .await
        .map_err(|_| DurableRunFailure::Internal)
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_graph_lifecycle(
        &self,
        lease: &mut DurableMachineGraphLease,
        owner: &crate::DurableOwnedExecution,
        coordinator: &ExecutionCoordinator,
        operations: &DurableOperationContext,
        task_id: ProtocolIdentity,
        label: MachineLabel,
        cut: DurableCommitCutV1,
    ) -> Result<(), DurableRunFailure> {
        let sequence = lease
            .next_event_sequence
            .get(&task_id)
            .copied()
            .unwrap_or(0);
        let draft = machine_lifecycle_event(&label, operations.execution_id, task_id)
            .ok_or(DurableRunFailure::Internal)?;
        let event = self
            .complete_graph_event(operations, task_id, sequence, draft.clone())
            .await?;
        let outcome = match label {
            MachineLabel::ForegroundCompletion(outcome)
            | MachineLabel::TerminalCompletion(outcome) => outcome,
            _ => return Err(DurableRunFailure::Internal),
        };
        let predecessor = lease.frontier;
        let DurableMachineGraph {
            foreground,
            children,
            ..
        } = &mut **lease;
        let mut transaction = coordinator
            .stage_graph(foreground, children)
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .update(|_, _, tasks, _| match cut {
                DurableCommitCutV1::ForegroundCompletion => tasks.complete_foreground(outcome),
                DurableCommitCutV1::TerminalCompletion => tasks.complete_terminal().map(|_| ()),
                _ => Err(TaskStateError::InvalidTransition),
            })
            .map_err(|_| DurableRunFailure::Internal)?;
        transaction
            .set_event(
                event,
                owner.graph_event_plan()?,
                draft.protected_payloads.to_vec(),
            )
            .map_err(DurableRunFailure::Commit)?;
        lease.frontier = owner
            .commit_graph_transaction(coordinator, transaction, predecessor, cut, task_id)
            .await?;
        lease.next_event_sequence.insert(
            task_id,
            sequence.checked_add(1).ok_or(DurableRunFailure::Internal)?,
        );
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[allow(clippy::too_many_arguments)]
    async fn commit_durable_event(
        &self,
        owner: &crate::DurableOwnedExecution,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_sequence: &mut u64,
        event: ExecutionEventDraftV1,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let protected_payloads = Arc::clone(&event.protected_payloads);
        let draft = event
            .draft
            .with_execution_id(recovered.machine().execution_id())
            .and_then(|draft| draft.with_task(task_id, *task_sequence))
            .map_err(|_| DurableRunFailure::Internal)?;
        let event = EventCompleter::new(
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
        )
        .complete(activity_id, draft)
        .await
        .map_err(|_| DurableRunFailure::Internal)?;
        let frontier = owner
            .commit_driver_event(recovered, event, &protected_payloads)
            .await?;
        *task_sequence = task_sequence
            .checked_add(1)
            .ok_or(DurableRunFailure::Internal)?;
        *last_committed = recovered.clone();
        if recovered.latest_cut() != DurableCommitCutV1::TerminalCompletion {
            let barrier = owner
                .drain_driver_required_event_obligations_through(
                    recovered,
                    frontier,
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await?;
            *last_committed = recovered.clone();
            if let DurableEventBarrierV1::RequiredExhausted(failure) = barrier {
                owner.project_driver_required_delivery_failure(recovered, failure)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "durable")]
    async fn drive_durable_session_scope(
        &self,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        scope: &gantry_runtime::SessionScopeOccurrence,
        owner: &crate::DurableOwnedExecution,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let parent = recovered
            .sessions()
            .and_then(|sessions| sessions.get(scope.parent_session_id))
            .cloned()
            .ok_or(DurableRunFailure::Internal)?;
        match owner
            .poll_driver_future(
                recovered,
                last_committed,
                self.inner
                    .session_establisher
                    .establish(execution_id, &parent),
            )
            .await?
        {
            crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
            crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                recovered
                    .machine_mut()
                    .fail_session_scope(
                        scope,
                        RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                return Ok(());
            }
            crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
        }
        let mut staged = recovered.clone();
        let child = staged
            .sessions_mut()
            .ok_or(DurableRunFailure::Internal)?
            .create(
                scope.parent_session_id,
                task_id,
                scope.site.clone(),
                scope.occurrence,
                scope.mode,
                SessionEstablishmentV1::Separate,
            )
            .map_err(|_| DurableRunFailure::Internal)?
            .clone();
        owner
            .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
            .await?;
        *recovered = staged;
        *last_committed = recovered.clone();
        match owner
            .poll_driver_future(
                recovered,
                last_committed,
                self.inner
                    .session_establisher
                    .establish(execution_id, &child),
            )
            .await?
        {
            crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
            crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                let mut staged = recovered.clone();
                staged
                    .machine_mut()
                    .fail_session_scope(
                        scope,
                        RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                owner
                    .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
                    .await?;
                *recovered = staged;
                *last_committed = recovered.clone();
                return Ok(());
            }
            crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
        }
        let mut staged = recovered.clone();
        staged
            .machine_mut()
            .complete_session_scope(scope, child.id)
            .map_err(|_| DurableRunFailure::Internal)?;
        owner
            .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
            .await?;
        *recovered = staged;
        *last_committed = recovered.clone();
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_action_operation(
        &self,
        context: &DurableOperationContext,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        hook: &mut TaskHook<'_>,
        cancellation: &CancellationSignal,
        occurrence: &gantry_runtime::OperationOccurrence,
        owner: &crate::DurableOwnedExecution,
        task_event_sequence: &mut u64,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let action = metadata
            .action
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        if metadata.kind != OperationSiteKind::Action
            || action.parameters.len() != occurrence.inputs.len()
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .action
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id: occurrence.task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: action.path.clone(),
                signature: action.signature.clone(),
                recovery: action.recovery,
                mapping_revision,
                arguments: action
                    .parameters
                    .iter()
                    .zip(occurrence.inputs.iter())
                    .map(|(parameter, value)| TypedActionArgumentV1 {
                        name: Arc::from(parameter.name()),
                        ty: parameter.ty().clone(),
                        value: value.canonical_json(),
                    })
                    .collect(),
            },
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(|_| DurableRunFailure::Internal)?;
        let mut retries_left = None;
        loop {
            let (prepared, validation_attempt, recovery_dispatch) =
                operation
                    .prepared_dispatch()
                    .ok_or(DurableRunFailure::Internal)?;
            let dispatch_id = prepared.dispatch_id;
            let request_bytes: Arc<[u8]> = Arc::from(prepared.request.canonical_bytes());
            let action_recovery = Some(action.recovery);
            let dispatch_event = operation_dispatch_event(
                operation.captured(),
                prepared,
                validation_attempt,
                recovery_dispatch,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            owner
                .commit_driver_cut(
                    recovered,
                    DurableCommitCutV1::OperationPrepared,
                    Some(DurableOperationEvidenceV1 {
                        operation_id: occurrence.identity,
                        dispatch_id: Some(dispatch_id),
                        validation_attempt,
                        recovery_dispatch,
                        retry_delay_us: None,
                        retries_left,
                        action_recovery,
                        request_bytes: Some(Arc::clone(&request_bytes)),
                        outcome: None,
                        retry_errors: Arc::from([]),
                        result_type: None,
                        result_bytes: None,
                    }),
                )
                .await?;
            *last_committed = recovered.clone();
            self.commit_durable_event(
                owner,
                recovered,
                context.activity_id,
                root_task_identity(context.execution_id),
                task_event_sequence,
                dispatch_event,
                last_committed,
            )
            .await?;
            if recovered.machine().outcome().is_some() {
                return Ok(());
            }
            match owner
                .poll_driver_future(
                    recovered,
                    last_committed,
                    operation.dispatch(hook, cancellation),
                )
                .await?
            {
                crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
                crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                    recovered
                        .machine_mut()
                        .fail_operation(occurrence.identity, RuntimeErrorCategory::HookFailure)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    return Ok(());
                }
                crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
            }
            let (_, outcome, validation_attempt, recovery_dispatch) =
                operation
                    .outcome_context()
                    .ok_or(DurableRunFailure::Internal)?;
            let outcome = outcome.clone();
            let completion_event = operation_completion_event(
                operation.captured(),
                dispatch_id,
                validation_attempt,
                recovery_dispatch,
                &outcome,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            owner
                .commit_driver_cut(
                    recovered,
                    DurableCommitCutV1::OperationOutcome,
                    Some(DurableOperationEvidenceV1 {
                        operation_id: occurrence.identity,
                        dispatch_id: Some(dispatch_id),
                        validation_attempt,
                        recovery_dispatch,
                        retry_delay_us: None,
                        retries_left,
                        action_recovery,
                        request_bytes: Some(Arc::clone(&request_bytes)),
                        outcome: Some(outcome.clone()),
                        retry_errors: Arc::from([]),
                        result_type: None,
                        result_bytes: None,
                    }),
                )
                .await?;
            *last_committed = recovered.clone();
            self.commit_durable_event(
                owner,
                recovered,
                context.activity_id,
                root_task_identity(context.execution_id),
                task_event_sequence,
                completion_event,
                last_committed,
            )
            .await?;
            if recovered.machine().outcome().is_some() {
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let mut staged = recovered.clone();
                    if metadata.attempted {
                        operation.accept_attempt(staged.machine_mut(), value)
                    } else {
                        operation.accept(staged.machine_mut(), value)
                    }
                    .map_err(|_| DurableRunFailure::Internal)?;
                    owner
                        .commit_driver_cut(
                            &mut staged,
                            DurableCommitCutV1::OperationResult,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: None,
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: None,
                                retries_left,
                                action_recovery,
                                request_bytes: None,
                                outcome: None,
                                retry_errors: Arc::from([]),
                                result_type: Some(metadata.result_type.clone()),
                                result_bytes: Some(result_bytes),
                            }),
                        )
                        .await?;
                    *recovered = staged;
                    *last_committed = recovered.clone();
                    self.commit_durable_event(
                        owner,
                        recovered,
                        context.activity_id,
                        root_task_identity(context.execution_id),
                        task_event_sequence,
                        result_event,
                        last_committed,
                    )
                    .await?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    owner
                        .commit_driver_cut(
                            recovered,
                            DurableCommitCutV1::RetryWaiting,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: Some(dispatch_id),
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: Some(wait.delay.get()),
                                retries_left,
                                action_recovery,
                                request_bytes: Some(request_bytes),
                                outcome: Some(outcome),
                                retry_errors: Arc::clone(&wait.errors),
                                result_type: None,
                                result_bytes: None,
                            }),
                        )
                        .await?;
                    *last_committed = recovered.clone();
                    match owner
                        .poll_driver_future(
                            recovered,
                            last_committed,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(Some(_))) => {}
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(None)) => {
                            Self::settle_retry_terminal(
                                recovered.machine_mut(),
                                occurrence,
                                &operation,
                            )
                            .map_err(|_| DurableRunFailure::Internal)?;
                            return Ok(());
                        }
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                            return Err(DurableRunFailure::Internal);
                        }
                        crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(recovered.machine_mut())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        recovered
                            .machine_mut()
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    #[cfg(feature = "durable")]
    #[allow(clippy::too_many_arguments)]
    async fn drive_durable_model_operation(
        &self,
        context: &DurableOperationContext,
        recovered: &mut gantry_runtime::RecoveredDurableStateV1,
        hook: &mut TaskHook<'_>,
        cancellation: &CancellationSignal,
        occurrence: &gantry_runtime::OperationOccurrence,
        owner: &crate::DurableOwnedExecution,
        session_occurrence: u64,
        task_event_sequence: &mut u64,
        last_committed: &mut gantry_runtime::RecoveredDurableStateV1,
    ) -> Result<(), DurableRunFailure> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_count = metadata.interpolation_types.len();
        if !matches!(
            metadata.kind,
            OperationSiteKind::Prompt | OperationSiteKind::Decide
        ) || metadata.named_input_names.len() != metadata.named_input_types.len()
            || occurrence.inputs.len()
                != interpolation_count.saturating_add(metadata.named_input_types.len())
        {
            return Err(DurableRunFailure::Internal);
        }
        let expected_schema = context
            .schema(&metadata.result_type)
            .ok_or(DurableRunFailure::Internal)?;
        let selected_agent = occurrence
            .active_agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let mapping_revision = context
            .mapping_revisions
            .agent
            .clone()
            .ok_or(DurableRunFailure::Internal)?;
        let parent_session_id = occurrence
            .active_session
            .ok_or(DurableRunFailure::Internal)?;
        let task_id = occurrence.task_id;
        let active_session_id = if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(DurableRunFailure::Internal),
            };
            let mut staged = recovered.clone();
            let session_id = staged
                .sessions_mut()
                .ok_or(DurableRunFailure::Internal)?
                .create(
                    parent_session_id,
                    task_id,
                    occurrence.site.clone(),
                    session_occurrence,
                    mode,
                    SessionEstablishmentV1::OperationRequest,
                )
                .map_err(|_| DurableRunFailure::Internal)?
                .id;
            owner
                .commit_driver_cut(&mut staged, DurableCommitCutV1::Checkpoint, None)
                .await?;
            *recovered = staged;
            *last_committed = recovered.clone();
            session_id
        } else {
            parent_session_id
        };
        let session = recovered
            .sessions()
            .and_then(|sessions| sessions.get(active_session_id))
            .cloned()
            .ok_or(DurableRunFailure::Internal)?;
        let interpolation_inputs = metadata
            .interpolation_types
            .iter()
            .zip(occurrence.inputs.iter().take(interpolation_count))
            .enumerate()
            .map(|(position, (ty, value))| {
                Ok(InterpolationInputV1 {
                    position: u64::try_from(position).map_err(|_| DurableRunFailure::Internal)?,
                    ty: ty.clone(),
                    value: value.canonical_json(),
                })
            })
            .collect::<Result<Vec<_>, DurableRunFailure>>()?;
        let named_inputs = metadata
            .named_input_names
            .iter()
            .zip(&metadata.named_input_types)
            .zip(occurrence.inputs.iter().skip(interpolation_count))
            .map(|((name, ty), value)| NamedInputV1 {
                name: Arc::clone(name),
                ty: ty.clone(),
                value: value.canonical_json(),
            })
            .collect::<Vec<_>>();
        let rendered_prompt = match render_prompt(
            &metadata.template_segments,
            occurrence.inputs.iter().take(interpolation_count),
            self.inner
                .configuration
                .required()
                .value_limits
                .maximum_string_scalars(),
        ) {
            Ok(prompt) => prompt,
            Err(RenderPromptError::Limit) => {
                recovered
                    .machine_mut()
                    .fail_operation_with_code(
                        occurrence.identity,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                return Ok(());
            }
            Err(RenderPromptError::Shape) => return Err(DurableRunFailure::Internal),
        };
        let session_use = if let Some(mode) = metadata.session_mode.as_ref() {
            ModelSessionUseV1::Create {
                mode: Arc::clone(mode),
                session_id: session.id,
                parent_session_id,
                root_session_id: session.root,
                provenance: Arc::from("operation-request"),
            }
        } else {
            ModelSessionUseV1::Inline
        };
        let captured = CapturedOperationRequestV1::Model {
            header: OperationRequestHeaderV1 {
                execution_id: context.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::clone(&selected_agent),
                mapping_revision,
                template_segments: metadata.template_segments.clone(),
                rendered_prompt: Arc::clone(&rendered_prompt),
                interpolation_inputs: interpolation_inputs.clone(),
                named_inputs: named_inputs.clone(),
                transcript: session.transcript.clone(),
                active_session_id: session.id,
                parent_session_id: session.parent,
                root_session_id: session.root,
                session_use,
            }),
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(|_| DurableRunFailure::Internal)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| DurableRunFailure::Internal)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(|_| DurableRunFailure::Internal)?;
        let mut retries_left = None;
        loop {
            let (prepared, validation_attempt, recovery_dispatch) =
                operation
                    .prepared_dispatch()
                    .ok_or(DurableRunFailure::Internal)?;
            let dispatch_id = prepared.dispatch_id;
            let request_bytes: Arc<[u8]> = Arc::from(prepared.request.canonical_bytes());
            let dispatch_event = operation_dispatch_event(
                operation.captured(),
                prepared,
                validation_attempt,
                recovery_dispatch,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            owner
                .commit_driver_cut(
                    recovered,
                    DurableCommitCutV1::OperationPrepared,
                    Some(DurableOperationEvidenceV1 {
                        operation_id: occurrence.identity,
                        dispatch_id: Some(dispatch_id),
                        validation_attempt,
                        recovery_dispatch,
                        retry_delay_us: None,
                        retries_left,
                        action_recovery: None,
                        request_bytes: Some(Arc::clone(&request_bytes)),
                        outcome: None,
                        retry_errors: Arc::from([]),
                        result_type: None,
                        result_bytes: None,
                    }),
                )
                .await?;
            *last_committed = recovered.clone();
            self.commit_durable_event(
                owner,
                recovered,
                context.activity_id,
                root_task_identity(context.execution_id),
                task_event_sequence,
                dispatch_event,
                last_committed,
            )
            .await?;
            if recovered.machine().outcome().is_some() {
                return Ok(());
            }
            match owner
                .poll_driver_future(
                    recovered,
                    last_committed,
                    operation.dispatch_model(
                        hook,
                        cancellation,
                        &self.inner.session_establisher,
                        context.execution_id,
                        &session,
                    ),
                )
                .await?
            {
                crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(_)) => {}
                crate::durable_lifecycle::DurableDriverPoll::Completed(Err(error)) => {
                    let category = match error {
                        OperationLifecycleError::Cancelled => RuntimeErrorCategory::Cancellation,
                        OperationLifecycleError::Session(_) => {
                            RuntimeErrorCategory::LogicalSessionSetup
                        }
                        OperationLifecycleError::Hook(_) if hook.is_ready() => {
                            RuntimeErrorCategory::HookFailure
                        }
                        OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookCreation,
                        _ => return Err(DurableRunFailure::Internal),
                    };
                    recovered
                        .machine_mut()
                        .fail_operation(occurrence.identity, category)
                        .map_err(|_| DurableRunFailure::Internal)?;
                    return Ok(());
                }
                crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => return Ok(()),
            }
            let (_, outcome, validation_attempt, recovery_dispatch) =
                operation
                    .outcome_context()
                    .ok_or(DurableRunFailure::Internal)?;
            let outcome = outcome.clone();
            let completion_event = operation_completion_event(
                operation.captured(),
                dispatch_id,
                validation_attempt,
                recovery_dispatch,
                &outcome,
            )
            .map_err(|_| DurableRunFailure::Internal)?;
            owner
                .commit_driver_cut(
                    recovered,
                    DurableCommitCutV1::OperationOutcome,
                    Some(DurableOperationEvidenceV1 {
                        operation_id: occurrence.identity,
                        dispatch_id: Some(dispatch_id),
                        validation_attempt,
                        recovery_dispatch,
                        retry_delay_us: None,
                        retries_left,
                        action_recovery: None,
                        request_bytes: Some(Arc::clone(&request_bytes)),
                        outcome: Some(outcome.clone()),
                        retry_errors: Arc::from([]),
                        result_type: None,
                        result_bytes: None,
                    }),
                )
                .await?;
            *last_committed = recovered.clone();
            self.commit_durable_event(
                owner,
                recovered,
                context.activity_id,
                root_task_identity(context.execution_id),
                task_event_sequence,
                completion_event,
                last_committed,
            )
            .await?;
            if recovered.machine().outcome().is_some() {
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(|_| DurableRunFailure::Internal)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let result_bytes: Arc<[u8]> = Arc::from(output.canonical_json().bytes());
                    let value = decode_logical_value(
                        &result_bytes,
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        context.declared_value_shapes.as_ref(),
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let turn = TranscriptTurnV1 {
                        operation_kind: metadata.kind,
                        template_representation: metadata.template_segments.clone(),
                        rendered_prompt: Arc::clone(&rendered_prompt),
                        interpolation_inputs: interpolation_inputs.clone(),
                        using_inputs: named_inputs.clone(),
                        selected_agent: Arc::clone(&selected_agent),
                        accepted_result: AcceptedTranscriptResultV1 {
                            kind: transcript_result_kind(&metadata.result_type),
                            ty: metadata.result_type.clone(),
                            value: value.canonical_json(),
                        },
                    };
                    let (result_kind, result_value) = match metadata.result_type.kind() {
                        TypeKind::Unit => (OperationResultEventKindV1::Unit, None),
                        TypeKind::Decision => (OperationResultEventKindV1::Decision, Some(&value)),
                        _ => (OperationResultEventKindV1::Value, Some(&value)),
                    };
                    let result_event = operation_result_event(
                        occurrence.identity,
                        &metadata.result_type,
                        result_kind,
                        result_value,
                    )
                    .map_err(|_| DurableRunFailure::Internal)?;
                    let mut staged = recovered.clone();
                    let accepted_result = {
                        let (machine, sessions) = staged.state_mut();
                        let session = sessions
                            .and_then(|sessions| sessions.get_mut(active_session_id))
                            .ok_or(DurableRunFailure::Internal)?;
                        if metadata.attempted {
                            operation.accept_model_attempt(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        } else {
                            operation.accept_model(
                                machine,
                                session,
                                &turn,
                                self.inner.configuration.required().value_limits,
                                value,
                            )
                        }
                    };
                    match accepted_result {
                        Ok(_) => {}
                        Err(OperationLifecycleError::Transcript(
                            gantry_runtime::TranscriptError::Limit,
                        )) => {
                            staged
                                .machine_mut()
                                .fail_operation(
                                    occurrence.identity,
                                    RuntimeErrorCategory::LogicalSessionTranscriptLimit,
                                )
                                .map_err(|_| DurableRunFailure::Internal)?;
                            *recovered = staged;
                            return Ok(());
                        }
                        Err(_) => return Err(DurableRunFailure::Internal),
                    }
                    owner
                        .commit_driver_cut(
                            &mut staged,
                            DurableCommitCutV1::OperationResult,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: None,
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: None,
                                retries_left,
                                action_recovery: None,
                                request_bytes: None,
                                outcome: None,
                                retry_errors: Arc::from([]),
                                result_type: Some(metadata.result_type.clone()),
                                result_bytes: Some(result_bytes),
                            }),
                        )
                        .await?;
                    *recovered = staged;
                    *last_committed = recovered.clone();
                    self.commit_durable_event(
                        owner,
                        recovered,
                        context.activity_id,
                        root_task_identity(context.execution_id),
                        task_event_sequence,
                        result_event,
                        last_committed,
                    )
                    .await?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(wait) => {
                    retries_left = Some(wait.retries_left);
                    owner
                        .commit_driver_cut(
                            recovered,
                            DurableCommitCutV1::RetryWaiting,
                            Some(DurableOperationEvidenceV1 {
                                operation_id: occurrence.identity,
                                dispatch_id: Some(dispatch_id),
                                validation_attempt,
                                recovery_dispatch,
                                retry_delay_us: Some(wait.delay.get()),
                                retries_left,
                                action_recovery: None,
                                request_bytes: Some(request_bytes),
                                outcome: Some(outcome),
                                retry_errors: Arc::clone(&wait.errors),
                                result_type: None,
                                result_bytes: None,
                            }),
                        )
                        .await?;
                    *last_committed = recovered.clone();
                    match owner
                        .poll_driver_future(
                            recovered,
                            last_committed,
                            operation.prepare_after_retry_wait(
                                self.inner.configuration.executor(),
                                cancellation,
                                &self.inner.allocator,
                                self.inner.configuration.identity_source(),
                            ),
                        )
                        .await?
                    {
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(Some(_))) => {}
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Ok(None)) => {
                            Self::settle_retry_terminal(
                                recovered.machine_mut(),
                                occurrence,
                                &operation,
                            )
                            .map_err(|_| DurableRunFailure::Internal)?;
                            return Ok(());
                        }
                        crate::durable_lifecycle::DurableDriverPoll::Completed(Err(_)) => {
                            return Err(DurableRunFailure::Internal);
                        }
                        crate::durable_lifecycle::DurableDriverPoll::CancellationSettled => {
                            return Ok(());
                        }
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(recovered.machine_mut())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    } else {
                        recovered
                            .machine_mut()
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| DurableRunFailure::Internal)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    async fn drive_execution(
        &self,
        accepted: StartExecutionAccepted,
        prepared: PreparedRootDriver,
    ) -> Result<ExecutionSnapshot, RunExecutionError> {
        self.drive_task(accepted, prepared.into(), true)
            .await?
            .ok_or(RunExecutionError::ExecutionNotFound)
    }

    async fn drive_task(
        &self,
        accepted: StartExecutionAccepted,
        prepared: PreparedTaskDriver,
        execution_foreground: bool,
    ) -> Result<Option<ExecutionSnapshot>, RunExecutionError> {
        let analysis = accepted
            .package_activity
            .analysis
            .as_ref()
            .ok_or(RunExecutionError::MissingAnalysis)?;
        let PreparedTaskDriver {
            mut machine,
            coordinator,
            task_id,
            workflow,
            create_request,
            base_session,
            #[cfg(feature = "concurrent")]
            program,
            #[cfg(feature = "concurrent")]
            execution_budget,
        } = prepared;
        let cancellation = accepted
            .handle
            .cancellation_signal()
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        let session_establisher = self.inner.session_establisher.clone();
        let setup_succeeded = if let Some(base_session) = base_session {
            let session = coordinator
                .session(base_session)
                .ok_or(RunExecutionError::MissingLogicalSession)?;
            let established = session_establisher
                .establish(accepted.execution_id, &session)
                .await;
            self.apply_task_cancellation(&accepted, &coordinator, task_id, &mut machine)?;
            if established.is_err() && machine.outcome().is_none() {
                let _ = machine.fail_execution(
                    RuntimeErrorCategory::LogicalSessionSetup,
                    gantry_runtime::ExecutionFailureProjection::Full,
                );
            }
            established.is_ok() && machine.outcome().is_none()
        } else {
            true
        };
        let mut hook = setup_succeeded
            .then(|| {
                TaskHook::new(
                    &self.inner.lifecycle,
                    self.inner.hook_factory.as_ref(),
                    AdapterPoison::default(),
                    create_request,
                )
            })
            .transpose()
            .map_err(RunExecutionError::TaskHook)?;
        let mut model_session_occurrence = 0_u64;
        let mut foreground_fixed = false;
        let mut terminal_fixed = false;
        let mut events = ExecutionEventPipeline::new(
            &accepted.handle,
            accepted.package_activity.activity_id,
            task_id,
            &self.inner.allocator,
            self.inner.configuration.identity_source(),
            self.inner.clock.as_ref(),
            self.inner.event_delivery_runtime.as_ref(),
            accepted.event_delivery.clone(),
        )
        .map_err(RunExecutionError::Event)?;

        loop {
            self.apply_task_cancellation(&accepted, &coordinator, task_id, &mut machine)?;
            match machine.step() {
                MachineStep::Transition(label) => {
                    if let Some(event) =
                        machine_lifecycle_event(&label, accepted.execution_id, task_id)
                    {
                        let event = events
                            .emit_task_draft(event)
                            .await
                            .map_err(RunExecutionError::Event)?;
                        if matches!(
                            event.consequence,
                            ExecutionDeliveryConsequenceV1::ExecutionCancellationStarted(_)
                        ) {
                            coordinator
                                .cancel_task_tree(
                                    task_id,
                                    Arc::from("required-event-delivery-failure"),
                                )
                                .map_err(RunExecutionError::TaskState)?;
                            let _ = machine.fail_execution(
                                RuntimeErrorCategory::RequiredEventDeliveryFailure,
                                gantry_runtime::ExecutionFailureProjection::Full,
                            );
                            continue;
                        }
                    }
                    match label {
                        MachineLabel::TaskSettled(outcome) => {
                            coordinator
                                .settle_task(task_id, outcome)
                                .map_err(RunExecutionError::TaskState)?;
                        }
                        MachineLabel::ForegroundCompletion(outcome) if execution_foreground => {
                            if !foreground_fixed {
                                let coordinated =
                                    self.complete_nondurable_foreground(&coordinator).await?;
                                if coordinated != outcome {
                                    return Err(RunExecutionError::LifecycleTransition);
                                }
                                self.inner
                                    .lifecycle
                                    .complete_foreground(&accepted.handle, outcome)
                                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                                foreground_fixed = true;
                            }
                        }
                        MachineLabel::TerminalCompletion(outcome)
                            if execution_foreground && !terminal_fixed =>
                        {
                            coordinator
                                .complete_terminal()
                                .map_err(RunExecutionError::TaskState)?;
                            self.inner
                                .lifecycle
                                .complete_terminal(&accepted.handle, outcome)
                                .map_err(|_| RunExecutionError::LifecycleTransition)?;
                            terminal_fixed = true;
                        }
                        #[cfg(feature = "concurrent")]
                        MachineLabel::TaskControlSuspended(suspension) => {
                            self.submit_source_child(
                                &accepted,
                                &mut machine,
                                &coordinator,
                                task_id,
                                &program,
                                &execution_budget,
                                &session_establisher,
                                &cancellation,
                                &mut events,
                                execution_foreground,
                                suspension,
                            )
                            .await?;
                        }
                        _ => {}
                    }
                }
                MachineStep::WaitingSessionScope(scope) => {
                    let parent = coordinator
                        .session(scope.parent_session_id)
                        .ok_or(RunExecutionError::MissingLogicalSession)?;
                    if session_establisher
                        .establish(accepted.execution_id, &parent)
                        .await
                        .is_err()
                    {
                        machine
                            .fail_session_scope(
                                &scope,
                                RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                            )
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                        continue;
                    }
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    let child = coordinator
                        .create_session(
                            scope.parent_session_id,
                            task_id,
                            scope.site.clone(),
                            scope.occurrence,
                            scope.mode,
                            SessionEstablishmentV1::Separate,
                        )
                        .map_err(RunExecutionError::Session)?;
                    if session_establisher
                        .establish(accepted.execution_id, &child)
                        .await
                        .is_err()
                    {
                        machine
                            .fail_session_scope(
                                &scope,
                                RuntimeCode::Operation(RuntimeErrorCategory::LogicalSessionSetup),
                            )
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                        continue;
                    }
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    machine
                        .complete_session_scope(&scope, child.id)
                        .map_err(|_| RunExecutionError::LifecycleTransition)?;
                }
                MachineStep::YieldRequired => {
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    if self
                        .inner
                        .configuration
                        .executor()
                        .yield_now()
                        .await
                        .is_err()
                    {
                        if !execution_foreground {
                            let _ = machine.fail_execution(
                                RuntimeErrorCategory::ExecutorFailure,
                                gantry_runtime::ExecutionFailureProjection::Full,
                            );
                            continue;
                        }
                        let failure = MachineFailure {
                            code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
                            workflow: workflow.clone(),
                            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                        };
                        let outcome = MachineOutcome::Failed(failure.clone());
                        coordinator
                            .settle_task(task_id, outcome.clone())
                            .map_err(RunExecutionError::TaskState)?;
                        let coordinated = coordinator
                            .complete_foreground()
                            .map_err(RunExecutionError::TaskState)?;
                        if coordinated != outcome {
                            return Err(RunExecutionError::LifecycleTransition);
                        }
                        coordinator
                            .complete_terminal()
                            .map_err(RunExecutionError::TaskState)?;
                        self.fix_failed_execution(&accepted, failure)?;
                        return Err(RunExecutionError::ExecutorFailure);
                    }
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    if !machine.resume_after_yield() {
                        return Err(RunExecutionError::LifecycleTransition);
                    }
                }
                MachineStep::WaitingOperation(operation) => {
                    let Some(metadata) = operation.metadata.as_ref() else {
                        if !execution_foreground {
                            let _ = machine.fail_execution(
                                RuntimeErrorCategory::InternalInvariantFailure,
                                gantry_runtime::ExecutionFailureProjection::Full,
                            );
                            continue;
                        }
                        let failure = MachineFailure {
                            code: RuntimeCode::InternalInvariant,
                            workflow: operation.workflow,
                            site: operation.site,
                        };
                        self.fix_failed_execution(&accepted, failure)?;
                        return Err(RunExecutionError::MissingOperationMetadata);
                    };
                    match metadata.kind {
                        OperationSiteKind::Action => {
                            self.drive_action_operation(
                                &accepted,
                                analysis,
                                &mut machine,
                                hook.as_mut()
                                    .ok_or(RunExecutionError::LifecycleTransition)?,
                                &cancellation,
                                &operation,
                            )
                            .await?;
                        }
                        OperationSiteKind::Prompt | OperationSiteKind::Decide => {
                            self.drive_model_operation(
                                &accepted,
                                analysis,
                                &mut machine,
                                hook.as_mut()
                                    .ok_or(RunExecutionError::LifecycleTransition)?,
                                &cancellation,
                                &operation,
                                &coordinator,
                                &session_establisher,
                                model_session_occurrence,
                            )
                            .await?;
                            model_session_occurrence = model_session_occurrence.saturating_add(1);
                        }
                    }
                }
                MachineStep::Complete(_) => {
                    if execution_foreground {
                        return self
                            .inner
                            .lifecycle
                            .query_execution(accepted.execution_id)
                            .map_err(RunExecutionError::Lifecycle);
                    }
                    return Ok(None);
                }
            }
        }
    }

    fn apply_task_cancellation(
        &self,
        accepted: &StartExecutionAccepted,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        machine: &mut Machine,
    ) -> Result<(), RunExecutionError> {
        if machine.outcome().is_some() {
            return Ok(());
        }
        let coordinated_reason = coordinator
            .snapshot()
            .state()
            .task_cancellation_reason(task_id)
            .map(Arc::from);
        let lifecycle_reason = accepted
            .handle
            .cancellation_signal()
            .ok()
            .filter(CancellationToken::is_cancelled)
            .map(|_| {
                self.inner
                    .lifecycle
                    .query_execution(accepted.execution_id)
                    .ok()
                    .flatten()
                    .and_then(|snapshot| snapshot.cancellation)
                    .map_or_else(
                        || Arc::from("cancellation"),
                        |reason| {
                            reason
                                .message
                                .unwrap_or_else(|| Arc::from(reason.category.wire_name()))
                        },
                    )
            });
        let Some(reason) = coordinated_reason.or(lifecycle_reason) else {
            return Ok(());
        };
        coordinator
            .cancel_task_tree(task_id, Arc::clone(&reason))
            .map_err(RunExecutionError::TaskState)?;
        let _ = machine.cancel(reason);
        Ok(())
    }

    async fn complete_nondurable_foreground(
        &self,
        coordinator: &ExecutionCoordinator,
    ) -> Result<MachineOutcome, RunExecutionError> {
        loop {
            match coordinator.complete_foreground() {
                Ok(outcome) => return Ok(outcome),
                Err(TaskStateError::AttachedTasksPending) => {
                    let attached = coordinator.shutdown_cohort().attached_tasks;
                    if attached.is_empty() {
                        return Err(RunExecutionError::LifecycleTransition);
                    }
                    for task_id in attached {
                        coordinator
                            .wait_for_task_settlement(task_id)
                            .map_err(RunExecutionError::TaskState)?
                            .await;
                    }
                }
                Err(error) => return Err(RunExecutionError::TaskState(error)),
            }
        }
    }

    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    async fn fail_source_child_submission(
        &self,
        accepted: &StartExecutionAccepted,
        machine: &mut Machine,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        handle_id: gantry_runtime::DynamicTaskHandleIdentity,
        cancellation: &dyn CancellationToken,
        events: &mut ExecutionEventPipeline<'_>,
        suspension: &MachineSpawnSuspension,
    ) -> Result<(), RunExecutionError> {
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            coordinator
                .resolve_unsubmitted_cancellation(task_id)
                .map_err(RunExecutionError::TaskState)?;
            return Ok(());
        }
        let outcome = MachineOutcome::Failed(MachineFailure {
            code: RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure),
            workflow: suspension.workflow.clone(),
            site: suspension.site.clone(),
        });
        machine
            .complete_spawn(suspension, handle_id)
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        let disposition = coordinator
            .resolve_submission(
                task_id,
                Err(HostError {
                    code: Arc::from("task-submission-failure"),
                    protected_diagnostic: None,
                }),
            )
            .map_err(RunExecutionError::TaskState)?;
        if disposition.is_cancelled() {
            return Ok(());
        }
        let draft = machine_lifecycle_event(
            &MachineLabel::TaskSettled(outcome),
            accepted.execution_id,
            task_id,
        )
        .ok_or(RunExecutionError::LifecycleTransition)?;
        let completion = events
            .emit_task_draft_for(task_id, 0, draft)
            .await
            .map_err(RunExecutionError::Event)?;
        if matches!(
            completion.consequence,
            ExecutionDeliveryConsequenceV1::ExecutionCancellationStarted(_)
                | ExecutionDeliveryConsequenceV1::ExecutionCancellationAlreadyActive(_)
        ) {
            coordinator
                .cancel_task_tree(parent_task_id, Arc::from("required-event-delivery-failure"))
                .map_err(RunExecutionError::TaskState)?;
            self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
            return Ok(());
        }
        Ok(())
    }

    #[cfg(feature = "concurrent")]
    #[allow(clippy::too_many_arguments)]
    async fn submit_source_child(
        &self,
        accepted: &StartExecutionAccepted,
        machine: &mut Machine,
        coordinator: &ExecutionCoordinator,
        parent_task_id: ProtocolIdentity,
        program: &Arc<gantry_ir::MachineProgram>,
        execution_budget: &ExecutionBudget,
        session_establisher: &SessionEstablisher,
        cancellation: &dyn CancellationToken,
        events: &mut ExecutionEventPipeline<'_>,
        _execution_foreground: bool,
        suspension: MachineSpawnSuspension,
    ) -> Result<(), RunExecutionError> {
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            return Ok(());
        }
        let task_limit_reached = |coordinator: &ExecutionCoordinator| {
            let state = coordinator.snapshot();
            state.state().created_task_count() >= state.state().maximum_task_count()
        };
        if task_limit_reached(coordinator) {
            machine
                .fail_spawn(
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
            return Ok(());
        }
        let parent_session_id = suspension
            .parent_session
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let parent_session = coordinator
            .session(parent_session_id)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        if session_establisher
            .establish(accepted.execution_id, &parent_session)
            .await
            .is_err()
        {
            let _ = machine.fail_execution(
                RuntimeErrorCategory::LogicalSessionSetup,
                gantry_runtime::ExecutionFailureProjection::Full,
            );
            return Ok(());
        }
        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            return Ok(());
        }
        if task_limit_reached(coordinator) {
            machine
                .fail_spawn(
                    &suspension,
                    RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                )
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
            return Ok(());
        }

        let captures = suspension
            .captures
            .iter()
            .map(|capture| capture.task_capture().clone())
            .collect::<Vec<_>>();
        let created = match coordinator.create_child(
            TaskCreationRequestV1 {
                parent_task_id,
                handle_name: Arc::from(suspension.handle.name()),
                workflow: suspension.workflow.clone(),
                spawn_site: suspension.site.clone(),
                spawn_occurrence: suspension.occurrence,
                result_type: suspension.handle.result_type().clone(),
                captures: captures.clone(),
                inherited_agent: suspension.inherited_agent.clone(),
                parent_session_id,
            },
            self.inner.configuration.required().value_limits,
        ) {
            Ok(created) => created,
            Err(TaskStateError::TaskCountLimit) => {
                machine
                    .fail_spawn(
                        &suspension,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::TaskCountLimit),
                    )
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            Err(error) => return Err(RunExecutionError::TaskState(error)),
        };

        let spawn_event = concurrent_spawn_event(accepted.execution_id, &created.transition, 0)
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        let spawn_event = events
            .emit_task_draft(spawn_event)
            .await
            .map_err(RunExecutionError::Event)?;
        if matches!(
            spawn_event.consequence,
            ExecutionDeliveryConsequenceV1::ExecutionCancellationStarted(_)
                | ExecutionDeliveryConsequenceV1::ExecutionCancellationAlreadyActive(_)
        ) {
            coordinator
                .cancel_task_tree(parent_task_id, Arc::from("required-event-delivery-failure"))
                .map_err(RunExecutionError::TaskState)?;
        }

        self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
        if cancellation.is_cancelled() || machine.outcome().is_some() {
            // This already-created child never acquired executor ownership, so
            // cancellation settles both its semantics and physical driver coordinate.
            coordinator
                .resolve_unsubmitted_cancellation(created.task_id)
                .map_err(RunExecutionError::TaskState)?;
            return Ok(());
        }
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve(AdmissionClass::SourceChildTask) {
            Ok(reservation) if !cancellation.is_cancelled() && machine.outcome().is_none() => {
                reservation
            }
            Ok(reservation) => {
                drop(reservation);
                self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
                coordinator
                    .resolve_unsubmitted_cancellation(created.task_id)
                    .map_err(RunExecutionError::TaskState)?;
                return Ok(());
            }
            Err(_) => {
                self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
                if cancellation.is_cancelled() || machine.outcome().is_some() {
                    coordinator
                        .resolve_unsubmitted_cancellation(created.task_id)
                        .map_err(RunExecutionError::TaskState)?;
                    return Ok(());
                }
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
                return Ok(());
            }
        };

        let snapshot = coordinator.snapshot();
        let child_record = snapshot
            .state()
            .task(created.task_id)
            .ok_or(RunExecutionError::TaskState(TaskStateError::UnknownTask))?;
        let child_session = coordinator
            .session(created.base_session_id)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let root_session = coordinator
            .session(child_session.root)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let root_provenance = match root_session.mode {
            SessionCreationModeV1::EmbedderRoot => RootSessionProvenanceV1::EmbedderSupplied,
            SessionCreationModeV1::GantryRoot => RootSessionProvenanceV1::GantryCreated,
            SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
                return Err(RunExecutionError::LifecycleTransition);
            }
        };
        let child_machine = match Machine::new_concurrent_task_body_with_context(
            Arc::clone(program),
            &suspension.body,
            &captures,
            accepted.execution_id,
            created.task_id,
            Arc::from(child_record.task_path()),
            self.inner.configuration.machine_limits(),
            execution_budget.clone(),
            suspension.inherited_agent.clone(),
            Some(created.base_session_id),
        ) {
            Ok(machine) => machine,
            Err(_) => {
                drop(reservation);
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
                return Ok(());
            }
        };
        let create_request = match (TaskContextV1 {
            execution_id: accepted.execution_id,
            task_id: created.task_id,
            inherited_agent: suspension.inherited_agent.clone(),
            session: TaskSessionContextV1::Forked {
                base_session_id: created.base_session_id,
                parent_session_id,
                root_session_id: child_session.root,
                root_provenance,
            },
        })
        .into_host_request()
        {
            Ok(request) => request,
            Err(_) => {
                drop(reservation);
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
                return Ok(());
            }
        };
        let prepared = PreparedTaskDriver {
            machine: child_machine,
            coordinator: coordinator.clone(),
            task_id: created.task_id,
            workflow: suspension.workflow.clone(),
            create_request,
            base_session: Some(created.base_session_id),
            program: Arc::clone(program),
            execution_budget: execution_budget.clone(),
        };
        let driver = TaskDriver::from_child(Arc::clone(&self.inner), accepted.clone(), prepared);
        let abnormal = driver.abnormal_completion_handler();
        let completion = driver.physical_completion_handler();
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::SourceChild,
            Some(abnormal),
            Some(completion),
        );
        let signal = registration.signal();
        let gate = Arc::new(RootStartGate::default());
        let task = driver.into_gated_owned_task(signal, Arc::clone(&gate));
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => {
                // The child gate stays closed until the task-created event, submission
                // handle, and submission state are published in that order. These two
                // in-memory transitions cannot be atomic; the closed gate prevents child
                // progress across their bounded interval.
                let disposition = machine
                    .complete_spawn(&suspension, created.handle_id)
                    .map_err(|_| TaskStateError::InvalidTransition)
                    .and_then(|_| coordinator.resolve_submission(created.task_id, Ok(())));
                let Ok(disposition) = disposition else {
                    gate.cancel();
                    let fallback = MachineOutcome::Failed(MachineFailure {
                        code: RuntimeCode::InternalInvariant,
                        workflow: suspension.workflow,
                        site: suspension.site,
                    });
                    let _ = coordinator.settle_task(created.task_id, fallback);
                    task.relinquish();
                    return Err(RunExecutionError::LifecycleTransition);
                };
                if disposition.is_cancelled() {
                    gate.cancel();
                    let _ = task.request_abort();
                    let _ = task.completion().await;
                    task.relinquish();
                    return Ok(());
                }
                task.relinquish();
                gate.release();
            }
            Err(_) => {
                self.apply_task_cancellation(accepted, coordinator, parent_task_id, machine)?;
                if cancellation.is_cancelled() || machine.outcome().is_some() {
                    coordinator
                        .resolve_unsubmitted_cancellation(created.task_id)
                        .map_err(RunExecutionError::TaskState)?;
                    return Ok(());
                }
                self.fail_source_child_submission(
                    accepted,
                    machine,
                    coordinator,
                    parent_task_id,
                    created.task_id,
                    created.handle_id,
                    cancellation,
                    events,
                    &suspension,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Returns one point-in-time snapshot for an accepted execution identity.
    pub fn query_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        self.inner.lifecycle.query_execution(execution_id)
    }

    /// Returns concurrent task state for focused nondurable conformance assertions.
    #[cfg(all(feature = "concurrent", feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_nondurable_task_state(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<ConcurrentTaskStateV1> {
        lock_shutdown(&self.inner.nondurable_test_coordinators)
            .get(&execution_id)
            .map(|coordinator| coordinator.snapshot().state().clone())
    }

    /// Returns the in-process durable observation for focused failure-order assertions.
    #[cfg(all(feature = "durable", feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_durable_observation(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<crate::DurableExecutionObservation> {
        self.durable_execution(execution_id)
            .await
            .map(|owner| owner.observation())
    }

    /// Waits independently for the foreground coordinate of one in-process handle.
    pub async fn await_foreground(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        Ok(self
            .inner
            .lifecycle
            .await_foreground(handle.execution_id())?
            .await)
    }

    /// Waits independently for the terminal coordinate of one in-process handle.
    pub async fn await_terminal(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        Ok(self
            .inner
            .lifecycle
            .await_terminal(handle.execution_id())?
            .await)
    }

    /// Records the first effective cancellation reason and waits for terminal settlement.
    pub async fn cancel_execution(
        &self,
        execution_id: ProtocolIdentity,
        reason: CancellationReason,
    ) -> Result<CancellationRecord, CancelExecutionError> {
        #[cfg(feature = "durable")]
        if let Some(owner) = self.durable_execution(execution_id).await {
            return match self
                .cancel_durable_execution(&owner, execution_id, reason)
                .await
            {
                crate::DurableCancelExecutionResult::Accepted {
                    effective_reason, ..
                } => Ok(CancellationRecord::Accepted {
                    reason: effective_reason,
                    signal: owner
                        .execution_handle()
                        .cancellation_signal()
                        .map_err(CancelExecutionError::Transition)?,
                }),
                crate::DurableCancelExecutionResult::AlreadyTerminal(_) => owner
                    .execution_handle()
                    .snapshot()
                    .map(CancellationRecord::AlreadyTerminal)
                    .map_err(CancelExecutionError::Transition),
                crate::DurableCancelExecutionResult::NotFound { .. } => {
                    Ok(CancellationRecord::NotFound)
                }
                crate::DurableCancelExecutionResult::Failed { failure, .. } => {
                    Err(CancelExecutionError::Durable(failure))
                }
            };
        }
        let record = self
            .inner
            .lifecycle
            .cancel_execution(execution_id, reason)
            .map_err(CancelExecutionError::Lifecycle)?;
        if matches!(
            record,
            CancellationRecord::Accepted { .. } | CancellationRecord::Existing { .. }
        ) {
            let _ = self
                .inner
                .lifecycle
                .await_terminal(execution_id)
                .map_err(CancelExecutionError::Lifecycle)?
                .await;
        }
        Ok(record)
    }

    #[cfg(feature = "durable")]
    async fn cancel_durable_execution(
        &self,
        owner: &crate::DurableOwnedExecution,
        execution_id: ProtocolIdentity,
        reason: CancellationReason,
    ) -> crate::DurableCancelExecutionResult {
        let result = owner.cancel_execution(execution_id, reason).await;
        match result {
            crate::DurableCancelExecutionResult::Accepted {
                effective_reason, ..
            } => match owner
                .drain_event_obligations(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await
            {
                Ok(terminal) => crate::DurableCancelExecutionResult::Accepted {
                    effective_reason,
                    terminal: Box::new(terminal),
                },
                Err(failure) => crate::DurableCancelExecutionResult::Failed {
                    effective_reason: Some(effective_reason),
                    failure,
                    observation: Box::new(owner.observation()),
                },
            },
            crate::DurableCancelExecutionResult::AlreadyTerminal(_) => match owner
                .drain_event_obligations(
                    &self.inner.allocator,
                    self.inner.configuration.identity_source(),
                    self.inner.event_delivery_runtime.as_ref(),
                )
                .await
            {
                Ok(terminal) => {
                    crate::DurableCancelExecutionResult::AlreadyTerminal(Box::new(terminal))
                }
                Err(failure) => crate::DurableCancelExecutionResult::Failed {
                    effective_reason: owner.observation().cancellation,
                    failure,
                    observation: Box::new(owner.observation()),
                },
            },
            result => result,
        }
    }

    #[cfg(feature = "durable")]
    fn mark_durable_execution(&self, execution_id: ProtocolIdentity) {
        self.inner.durable_executions.mark(execution_id);
    }

    #[cfg(feature = "durable")]
    fn register_durable_execution(&self, owner: Arc<crate::DurableOwnedExecution>) {
        self.inner.durable_executions.publish(owner);
    }

    #[cfg(feature = "durable")]
    fn abandon_durable_execution(&self, execution_id: ProtocolIdentity) {
        self.inner.durable_executions.abandon(execution_id);
    }

    #[cfg(feature = "durable")]
    async fn durable_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Option<Arc<crate::DurableOwnedExecution>> {
        self.inner.durable_executions.owner(execution_id).await
    }

    /// Starts or joins the caller-independent shutdown coordinator.
    ///
    /// Once this future is first polled, dropping it stops only this caller's
    /// observation. The unique coordinator remains supervised until physical
    /// completion, and every caller observes the same immutable result.
    pub async fn shutdown(&self) -> Result<Arc<ShutdownReport>, ShutdownError> {
        if self
            .inner
            .shutdown_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.start_owned_shutdown();
        }
        std::future::poll_fn(|context| self.inner.shutdown.poll(context)).await
    }

    fn start_owned_shutdown(&self) {
        let supervisor = self.inner.lifecycle.task_supervisor();
        let reservation = match supervisor.try_reserve_control_plane() {
            Ok(reservation) => reservation,
            Err(error) => {
                self.inner.lifecycle.fail_owned_shutdown();
                self.inner
                    .shutdown
                    .publish(Err(ShutdownError::Admission(error)));
                return;
            }
        };
        let mut admission = match self.inner.lifecycle.begin_shutdown(None, None) {
            Ok(admission) => admission,
            Err(error) => {
                self.inner
                    .shutdown
                    .publish(Err(ShutdownError::Lifecycle(error)));
                return;
            }
        };
        let durations = admission.durations;
        let completion_state = Arc::clone(&self.inner.shutdown);
        let completion_lifecycle = self.inner.lifecycle.clone();
        let completion: PhysicalCompletionHandler = Arc::new(move |completion| {
            if !matches!(completion, OwnedTaskCompletion::Completed(_)) {
                completion_lifecycle.fail_owned_shutdown();
            }
            completion_state.publish_physical(completion);
        });
        let registration = supervisor.prepare_with_completion(
            SupervisedTaskDomain::Shutdown,
            None,
            Some(completion),
        );
        let signal = registration.signal();
        let shutdown_owner = Arc::clone(&self.inner);
        let task: OwnedTaskFuture = if let Some(coordinator) = admission.coordinator.take() {
            let executions_at_start = coordinator.initial_executions();
            let tasks_at_start = usize_to_u64(executions_at_start.len());
            Box::pin(async move {
                coordinator.wait_for_admission_handoffs().await;
                let mut orderly = true;
                for execution_id in coordinator.pending_executions().iter().copied() {
                    #[cfg(feature = "durable")]
                    let owner = shutdown_owner.durable_executions.owner(execution_id).await;
                    let reason = CancellationReason::new(
                        CancellationReasonCategory::Shutdown,
                        None,
                        None,
                        0,
                    )
                    .unwrap_or_else(|_| unreachable!("empty shutdown reason is always bounded"));
                    #[cfg(feature = "durable")]
                    if let Some(owner) = owner {
                        orderly &= matches!(
                            Interpreter {
                                inner: Arc::clone(&shutdown_owner),
                                external_owner: false,
                            }
                            .cancel_durable_execution(&owner, execution_id, reason)
                            .await,
                            crate::DurableCancelExecutionResult::Accepted { .. }
                                | crate::DurableCancelExecutionResult::AlreadyTerminal(_)
                        );
                        continue;
                    }
                    orderly &= shutdown_owner
                        .lifecycle
                        .cancel_execution(execution_id, reason)
                        .is_ok();
                }
                coordinator.wait_for_quiescence().await;
                let blocking_shutdown =
                    match catch_integration(&shutdown_owner.blocking_work_poison, || {
                        shutdown_owner.configuration.blocking_work().shutdown()
                    }) {
                        Ok(shutdown) => contain_integration_future(
                            shutdown,
                            shutdown_owner.blocking_work_poison.clone(),
                        )
                        .await
                        .is_ok_and(|result| result.is_ok()),
                        Err(_) => false,
                    };
                orderly &= blocking_shutdown;
                let cohort = coordinator.cohort_executions();
                let final_event = settle_final_shutdown_event(
                    &shutdown_owner,
                    durations,
                    &executions_at_start,
                    &cohort,
                    tasks_at_start,
                )
                .await;
                orderly &= final_event.required_sinks_settled;
                let result = coordinator
                    .complete(orderly, final_event.settlement)
                    .map_err(ShutdownError::Completion);
                shutdown_owner.shutdown.stage(result);
                signal.settle();
                OwnedTaskResult::new()
            })
        } else {
            Box::pin(async move {
                let report = admission.wait.await;
                shutdown_owner.shutdown.stage(Ok(report));
                signal.settle();
                OwnedTaskResult::new()
            })
        };
        match supervisor.submit(registration, task, reservation.transfer()) {
            Ok(task) => task.relinquish(),
            Err(error) => {
                self.inner.lifecycle.fail_owned_shutdown();
                self.inner
                    .shutdown
                    .publish(Err(ShutdownError::Executor(error)));
            }
        }
    }

    async fn drive_action_operation(
        &self,
        accepted: &StartExecutionAccepted,
        analysis: &gantry_analysis::TypedPackage,
        machine: &mut Machine,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
        occurrence: &gantry_runtime::OperationOccurrence,
    ) -> Result<(), RunExecutionError> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(RunExecutionError::MissingOperationMetadata)?;
        let action = metadata
            .action
            .as_ref()
            .ok_or(RunExecutionError::MissingOperationMetadata)?;
        if action.parameters.len() != occurrence.inputs.len() {
            return Err(RunExecutionError::MissingOperationMetadata);
        }
        let expected_schema = analysis
            .schemas()
            .and_then(|schemas| {
                schemas
                    .entries()
                    .iter()
                    .find(|(ty, _)| ty == &metadata.result_type)
                    .map(|(_, schema)| Arc::clone(schema))
            })
            .ok_or(RunExecutionError::MissingOperationSchema)?;
        let mapping_revision = accepted
            .mapping_revisions
            .action
            .clone()
            .ok_or(RunExecutionError::MissingActionMappingRevision)?;
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: accepted.execution_id,
                task_id: occurrence.task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: action.path.clone(),
                signature: action.signature.clone(),
                recovery: action.recovery,
                mapping_revision,
                arguments: action
                    .parameters
                    .iter()
                    .zip(occurrence.inputs.iter())
                    .map(|(parameter, value)| TypedActionArgumentV1 {
                        name: Arc::from(parameter.name()),
                        ty: parameter.ty().clone(),
                        value: value.canonical_json(),
                    })
                    .collect(),
            },
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(RunExecutionError::OperationLifecycle)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| RunExecutionError::RetryPolicy)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(RunExecutionError::OperationLifecycle)?;
        loop {
            if let Err(error) = operation.dispatch(hook, cancellation).await {
                let category = if hook.is_ready() {
                    RuntimeErrorCategory::HookFailure
                } else {
                    RuntimeErrorCategory::HookCreation
                };
                machine
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return match error {
                    OperationLifecycleError::Hook(_) => Ok(()),
                    other => Err(RunExecutionError::OperationLifecycle(other)),
                };
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(RunExecutionError::OperationLifecycle)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let value = decode_logical_value(
                        output.canonical_json().bytes(),
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        analysis.declared_value_shapes(),
                    )?;
                    if metadata.attempted {
                        operation.accept_attempt(machine, value)
                    } else {
                        operation.accept(machine, value)
                    }
                    .map_err(RunExecutionError::OperationLifecycle)?;
                    return Ok(());
                }
                ProcessedHookOutcomeV1::Retry(_) => {
                    if operation
                        .prepare_after_retry_wait(
                            self.inner.configuration.executor(),
                            &accepted
                                .handle
                                .cancellation_signal()
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                        )
                        .await
                        .map_err(RunExecutionError::OperationLifecycle)?
                        .is_none()
                    {
                        Self::settle_retry_terminal(machine, occurrence, &operation)?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(RunExecutionError::OperationLifecycle)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_model_operation(
        &self,
        accepted: &StartExecutionAccepted,
        analysis: &gantry_analysis::TypedPackage,
        machine: &mut Machine,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
        occurrence: &gantry_runtime::OperationOccurrence,
        coordinator: &ExecutionCoordinator,
        establisher: &SessionEstablisher,
        session_occurrence: u64,
    ) -> Result<(), RunExecutionError> {
        let metadata = occurrence
            .metadata
            .as_ref()
            .ok_or(RunExecutionError::MissingOperationMetadata)?;
        let interpolation_count = metadata.interpolation_types.len();
        if metadata.named_input_names.len() != metadata.named_input_types.len()
            || occurrence.inputs.len()
                != interpolation_count.saturating_add(metadata.named_input_types.len())
        {
            return Err(RunExecutionError::MissingOperationMetadata);
        }
        let expected_schema = analysis
            .schemas()
            .and_then(|schemas| {
                schemas
                    .entries()
                    .iter()
                    .find(|(ty, _)| ty == &metadata.result_type)
                    .map(|(_, schema)| Arc::clone(schema))
            })
            .ok_or(RunExecutionError::MissingOperationSchema)?;
        let selected_agent = occurrence
            .active_agent
            .clone()
            .ok_or(RunExecutionError::MissingActiveAgent)?;
        let mapping_revision = accepted
            .mapping_revisions
            .agent
            .clone()
            .ok_or(RunExecutionError::MissingAgentMappingRevision)?;
        let parent_session_id = occurrence
            .active_session
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let task_id = occurrence.task_id;
        let active_session_id = if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(RunExecutionError::MissingOperationMetadata),
            };
            coordinator
                .create_session(
                    parent_session_id,
                    task_id,
                    occurrence.site.clone(),
                    session_occurrence,
                    mode,
                    SessionEstablishmentV1::OperationRequest,
                )
                .map_err(RunExecutionError::Session)?
                .id
        } else {
            parent_session_id
        };
        let session = coordinator
            .session(active_session_id)
            .ok_or(RunExecutionError::MissingLogicalSession)?;
        let interpolation_inputs = metadata
            .interpolation_types
            .iter()
            .zip(occurrence.inputs.iter().take(interpolation_count))
            .enumerate()
            .map(|(position, (ty, value))| {
                Ok(InterpolationInputV1 {
                    position: u64::try_from(position)
                        .map_err(|_| RunExecutionError::MissingOperationMetadata)?,
                    ty: ty.clone(),
                    value: value.canonical_json(),
                })
            })
            .collect::<Result<Vec<_>, RunExecutionError>>()?;
        let named_inputs = metadata
            .named_input_names
            .iter()
            .zip(&metadata.named_input_types)
            .zip(occurrence.inputs.iter().skip(interpolation_count))
            .map(|((name, ty), value)| NamedInputV1 {
                name: Arc::clone(name),
                ty: ty.clone(),
                value: value.canonical_json(),
            })
            .collect::<Vec<_>>();
        let rendered_prompt = match render_prompt(
            &metadata.template_segments,
            occurrence.inputs.iter().take(interpolation_count),
            self.inner
                .configuration
                .required()
                .value_limits
                .maximum_string_scalars(),
        ) {
            Ok(prompt) => prompt,
            Err(RenderPromptError::Limit) => {
                machine
                    .fail_operation_with_code(
                        occurrence.identity,
                        RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
                    )
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            Err(RenderPromptError::Shape) => {
                return Err(RunExecutionError::MissingOperationMetadata);
            }
        };
        let session_use = if let Some(mode) = metadata.session_mode.as_ref() {
            ModelSessionUseV1::Create {
                mode: Arc::clone(mode),
                session_id: session.id,
                parent_session_id,
                root_session_id: session.root,
                provenance: Arc::from("operation-request"),
            }
        } else {
            ModelSessionUseV1::Inline
        };
        let captured = CapturedOperationRequestV1::Model {
            header: OperationRequestHeaderV1 {
                execution_id: accepted.execution_id,
                task_id,
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self
                    .inner
                    .configuration
                    .required()
                    .maximum_hook_output_bytes,
                value_limits: self.inner.configuration.required().value_limits,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::clone(&selected_agent),
                mapping_revision,
                template_segments: metadata.template_segments.clone(),
                rendered_prompt: Arc::clone(&rendered_prompt),
                interpolation_inputs: interpolation_inputs.clone(),
                named_inputs: named_inputs.clone(),
                transcript: session.transcript.clone(),
                active_session_id: session.id,
                parent_session_id: session.parent,
                root_session_id: session.root,
                session_use,
            }),
        };
        let mut operation =
            OperationLifecycle::new(captured).map_err(RunExecutionError::OperationLifecycle)?;
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            self.inner.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| RunExecutionError::RetryPolicy)?;
        operation
            .prepare(
                &self.inner.allocator,
                self.inner.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(RunExecutionError::OperationLifecycle)?;
        loop {
            if let Err(error) = operation
                .dispatch_model(
                    hook,
                    cancellation,
                    establisher,
                    accepted.execution_id,
                    &session,
                )
                .await
            {
                let category = match error {
                    OperationLifecycleError::Cancelled => return Ok(()),
                    OperationLifecycleError::Session(_) => {
                        RuntimeErrorCategory::LogicalSessionSetup
                    }
                    OperationLifecycleError::Hook(_) if hook.is_ready() => {
                        RuntimeErrorCategory::HookFailure
                    }
                    OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookCreation,
                    other => return Err(RunExecutionError::OperationLifecycle(other)),
                };
                machine
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.inner.configuration.executor(), cancellation)
                .map_err(RunExecutionError::OperationLifecycle)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let value = decode_logical_value(
                        output.canonical_json().bytes(),
                        &metadata.result_type,
                        self.inner.configuration.required().value_limits,
                        analysis.declared_value_shapes(),
                    )?;
                    let turn = TranscriptTurnV1 {
                        operation_kind: metadata.kind,
                        template_representation: metadata.template_segments.clone(),
                        rendered_prompt: Arc::clone(&rendered_prompt),
                        interpolation_inputs: interpolation_inputs.clone(),
                        using_inputs: named_inputs.clone(),
                        selected_agent: Arc::clone(&selected_agent),
                        accepted_result: AcceptedTranscriptResultV1 {
                            kind: transcript_result_kind(&metadata.result_type),
                            ty: metadata.result_type.clone(),
                            value: value.canonical_json(),
                        },
                    };
                    let accepted_result = coordinator
                        .with_session_mut(active_session_id, |session| {
                            if metadata.attempted {
                                operation.accept_model_attempt(
                                    machine,
                                    session,
                                    &turn,
                                    self.inner.configuration.required().value_limits,
                                    value,
                                )
                            } else {
                                operation.accept_model(
                                    machine,
                                    session,
                                    &turn,
                                    self.inner.configuration.required().value_limits,
                                    value,
                                )
                            }
                        })
                        .map_err(RunExecutionError::Session)?;
                    match accepted_result {
                        Ok(_) => return Ok(()),
                        Err(OperationLifecycleError::Transcript(
                            gantry_runtime::TranscriptError::Limit,
                        )) => {
                            machine
                                .fail_operation(
                                    occurrence.identity,
                                    RuntimeErrorCategory::LogicalSessionTranscriptLimit,
                                )
                                .map_err(|_| RunExecutionError::LifecycleTransition)?;
                            return Ok(());
                        }
                        Err(error) => return Err(RunExecutionError::OperationLifecycle(error)),
                    }
                }
                ProcessedHookOutcomeV1::Retry(_) => {
                    if operation
                        .prepare_after_retry_wait(
                            self.inner.configuration.executor(),
                            &accepted
                                .handle
                                .cancellation_signal()
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            &self.inner.allocator,
                            self.inner.configuration.identity_source(),
                        )
                        .await
                        .map_err(RunExecutionError::OperationLifecycle)?
                        .is_none()
                    {
                        Self::settle_retry_terminal(machine, occurrence, &operation)?;
                        return Ok(());
                    }
                }
                ProcessedHookOutcomeV1::Failed(failure) => {
                    if metadata.attempted
                        && matches!(
                            operation.lifecycle_failure(),
                            Some(OperationLifecycleFailureV1::Operation(_))
                        )
                    {
                        operation
                            .accept_attempt_failure(machine)
                            .map_err(RunExecutionError::OperationLifecycle)?;
                    } else {
                        machine
                            .fail_operation(occurrence.identity, failure.runtime_category())
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    fn settle_retry_terminal(
        machine: &mut Machine,
        occurrence: &gantry_runtime::OperationOccurrence,
        operation: &OperationLifecycle,
    ) -> Result<(), RunExecutionError> {
        match operation.lifecycle_failure() {
            Some(OperationLifecycleFailureV1::Operation(
                gantry_runtime::OperationFailureV1::TaskCancellation,
            )) => Ok(()),
            Some(OperationLifecycleFailureV1::Operation(failure)) => {
                machine
                    .fail_operation(occurrence.identity, failure.runtime_category())
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                Ok(())
            }
            _ => Err(RunExecutionError::LifecycleTransition),
        }
    }

    fn fix_failed_execution(
        &self,
        accepted: &StartExecutionAccepted,
        failure: MachineFailure,
    ) -> Result<(), RunExecutionError> {
        let outcome = MachineOutcome::Failed(failure);
        self.inner
            .lifecycle
            .complete_foreground(&accepted.handle, outcome.clone())
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        self.inner
            .lifecycle
            .complete_terminal(&accepted.handle, outcome)
            .map_err(|_| RunExecutionError::LifecycleTransition)
    }

    fn settle_unhandled_driver_failure(
        &self,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        handle: &ExecutionHandle,
        workflow: gantry_ir::CanonicalPath,
    ) -> Result<(), RunExecutionError> {
        let fallback = MachineOutcome::Failed(MachineFailure {
            code: RuntimeCode::InternalInvariant,
            workflow,
            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                .map_err(|_| RunExecutionError::LifecycleTransition)?,
        });
        self.settle_driver_failure(coordinator, task_id, handle, fallback)
    }

    #[cfg(feature = "concurrent")]
    fn settle_child_driver_failure(
        &self,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        fallback: MachineOutcome,
    ) -> Result<(), RunExecutionError> {
        let snapshot = coordinator.snapshot();
        let status = snapshot
            .state()
            .task(task_id)
            .ok_or(RunExecutionError::TaskState(TaskStateError::UnknownTask))?
            .status();
        if matches!(
            status,
            ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
        ) {
            coordinator
                .settle_task(task_id, fallback)
                .map_err(RunExecutionError::TaskState)?;
        }
        Ok(())
    }

    fn settle_driver_failure(
        &self,
        coordinator: &ExecutionCoordinator,
        task_id: ProtocolIdentity,
        handle: &ExecutionHandle,
        fallback: MachineOutcome,
    ) -> Result<(), RunExecutionError> {
        let mut coordinated = coordinator.snapshot();
        let outcome = if let Some(outcome) = coordinated.state().root_settled_outcome().cloned() {
            outcome
        } else {
            coordinator
                .settle_task(task_id, fallback.clone())
                .map_err(RunExecutionError::TaskState)?;
            fallback
        };
        coordinated = coordinator.snapshot();
        if coordinated.state().foreground_outcome().is_none() {
            let published = coordinator
                .complete_foreground()
                .map_err(RunExecutionError::TaskState)?;
            if published != outcome {
                return Err(RunExecutionError::LifecycleTransition);
            }
        } else if coordinated.state().foreground_outcome() != Some(&outcome) {
            return Err(RunExecutionError::LifecycleTransition);
        }
        if coordinator.snapshot().state().terminal_outcome().is_none() {
            coordinator
                .complete_terminal()
                .map_err(RunExecutionError::TaskState)?;
        }

        let execution = self
            .inner
            .lifecycle
            .query_execution(handle.execution_id())
            .map_err(RunExecutionError::Lifecycle)?
            .ok_or(RunExecutionError::ExecutionNotFound)?;
        if execution.foreground.is_none() {
            self.inner
                .lifecycle
                .complete_foreground(handle, outcome.clone())
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
        } else if execution.foreground.as_ref() != Some(&outcome) {
            return Err(RunExecutionError::LifecycleTransition);
        }
        let execution = self
            .inner
            .lifecycle
            .query_execution(handle.execution_id())
            .map_err(RunExecutionError::Lifecycle)?
            .ok_or(RunExecutionError::ExecutionNotFound)?;
        if execution.terminal.is_none() {
            self.inner
                .lifecycle
                .complete_terminal(handle, outcome)
                .map_err(|_| RunExecutionError::LifecycleTransition)?;
        }
        Ok(())
    }
}

/// One interpreter-owned `Send + 'static` asynchronous driver for a Gantry task.
struct TaskDriver {
    task_id: ProtocolIdentity,
    coordinator: ExecutionCoordinator,
    failure_context: TaskDriverFailureContext,
    future: Pin<Box<dyn Future<Output = Result<(), RunExecutionError>> + Send + 'static>>,
}

#[derive(Clone)]
struct TaskDriverFailureContext {
    inner: Arc<InterpreterInner>,
    coordinator: ExecutionCoordinator,
    task_id: ProtocolIdentity,
    handle: ExecutionHandle,
    workflow: gantry_ir::CanonicalPath,
    execution_foreground: bool,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    durable_graph: Option<Arc<SharedDurableMachineGraph>>,
    #[cfg(all(feature = "concurrent", feature = "durable"))]
    durable_owner: Option<Arc<crate::DurableOwnedExecution>>,
}

impl TaskDriverFailureContext {
    fn settle(&self, completion: &OwnedTaskCompletion) {
        let code = match completion {
            OwnedTaskCompletion::Panicked {
                origin: gantry_host::contracts::OwnedTaskPanicOrigin::Integration,
                ..
            } => RuntimeCode::Operation(RuntimeErrorCategory::HookFailure),
            OwnedTaskCompletion::Panicked {
                origin: gantry_host::contracts::OwnedTaskPanicOrigin::GantryInvariant,
                ..
            } => RuntimeCode::InternalInvariant,
            OwnedTaskCompletion::Stopped | OwnedTaskCompletion::Failed(_) => {
                RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure)
            }
            OwnedTaskCompletion::Completed(_) => return,
        };
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        let code = if self.durable_graph.is_some() {
            RuntimeCode::Operation(RuntimeErrorCategory::ExecutorFailure)
        } else {
            code
        };
        let interpreter = Interpreter {
            inner: Arc::clone(&self.inner),
            external_owner: false,
        };
        let fallback = MachineOutcome::Failed(MachineFailure {
            code,
            workflow: self.workflow.clone(),
            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                .unwrap_or_else(|_| unreachable!("constant position is valid")),
        });
        #[cfg(all(feature = "concurrent", feature = "durable"))]
        if let (Some(graph), Some(owner)) = (&self.durable_graph, &self.durable_owner) {
            graph.request_abnormal_child_settlement(self.task_id, fallback);
            let _ = interpreter.start_durable_graph_finalizer(
                Arc::clone(graph),
                Arc::clone(owner),
                self.coordinator.clone(),
                Arc::clone(&graph.program),
                graph.operations.clone(),
            );
            return;
        }
        if self.execution_foreground {
            let _ = interpreter.settle_driver_failure(
                &self.coordinator,
                self.task_id,
                &self.handle,
                fallback.clone(),
            );
        }
        #[cfg(feature = "concurrent")]
        if !self.execution_foreground {
            let _ =
                interpreter.settle_child_driver_failure(&self.coordinator, self.task_id, fallback);
        }
    }
}

impl TaskDriver {
    fn from_prepared(
        inner: Arc<InterpreterInner>,
        accepted: StartExecutionAccepted,
        prepared: PreparedRootDriver,
    ) -> Self {
        let task_id = prepared.task_id;
        let coordinator = prepared.coordinator.clone();
        let failure_coordinator = coordinator.clone();
        let handle = accepted.handle.clone();
        let workflow = prepared.workflow.clone();
        let failure_context = TaskDriverFailureContext {
            inner: Arc::clone(&inner),
            coordinator: coordinator.clone(),
            task_id,
            handle: handle.clone(),
            workflow: workflow.clone(),
            execution_foreground: true,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_graph: None,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_owner: None,
        };
        let future = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            let result = interpreter.drive_execution(accepted, prepared).await;
            if let Err(error) = result {
                interpreter.settle_unhandled_driver_failure(
                    &failure_coordinator,
                    task_id,
                    &handle,
                    workflow,
                )?;
                Err(error)
            } else {
                Ok(())
            }
        });
        Self {
            task_id,
            coordinator,
            failure_context,
            future,
        }
    }

    #[cfg(feature = "concurrent")]
    fn from_child(
        inner: Arc<InterpreterInner>,
        accepted: StartExecutionAccepted,
        prepared: PreparedTaskDriver,
    ) -> Self {
        let task_id = prepared.task_id;
        let coordinator = prepared.coordinator.clone();
        let failure_coordinator = coordinator.clone();
        let handle = accepted.handle.clone();
        let workflow = prepared.workflow.clone();
        let failure_context = TaskDriverFailureContext {
            inner: Arc::clone(&inner),
            coordinator: coordinator.clone(),
            task_id,
            handle,
            workflow: workflow.clone(),
            execution_foreground: false,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_graph: None,
            #[cfg(all(feature = "concurrent", feature = "durable"))]
            durable_owner: None,
        };
        let future = Box::pin(async move {
            let interpreter = Interpreter {
                inner,
                external_owner: false,
            };
            match interpreter.drive_task(accepted, prepared, false).await {
                Ok(_) => Ok(()),
                Err(error) => {
                    let fallback = MachineOutcome::Failed(MachineFailure {
                        code: RuntimeCode::InternalInvariant,
                        workflow,
                        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                            .map_err(|_| RunExecutionError::LifecycleTransition)?,
                    });
                    interpreter.settle_child_driver_failure(
                        &failure_coordinator,
                        task_id,
                        fallback,
                    )?;
                    Err(error)
                }
            }
        });
        Self {
            task_id,
            coordinator,
            failure_context,
            future,
        }
    }

    #[cfg(all(feature = "concurrent", feature = "durable"))]
    #[allow(clippy::too_many_arguments)]
    fn from_durable_graph_child(
        inner: Arc<InterpreterInner>,
        coordinator: ExecutionCoordinator,
        task_id: ProtocolIdentity,
        workflow: gantry_ir::CanonicalPath,
        graph: Arc<SharedDurableMachineGraph>,
        owner: Arc<crate::DurableOwnedExecution>,
        future: Pin<Box<dyn Future<Output = Result<(), RunExecutionError>> + Send + 'static>>,
    ) -> Self {
        let failure_context = TaskDriverFailureContext {
            inner,
            coordinator: coordinator.clone(),
            task_id,
            handle: owner.execution_handle(),
            workflow,
            execution_foreground: false,
            durable_graph: Some(graph),
            durable_owner: Some(owner),
        };
        Self {
            task_id,
            coordinator,
            failure_context,
            future,
        }
    }

    /// Returns the shared semantic coordinator used by this driver.
    #[must_use]
    fn coordinator(&self) -> ExecutionCoordinator {
        self.coordinator.clone()
    }

    /// Returns the semantic fallback used when physical completion wins unexpectedly.
    #[must_use]
    fn abnormal_completion_handler(&self) -> AbnormalCompletionHandler {
        let context = self.failure_context.clone();
        Arc::new(move |completion| context.settle(&completion))
    }

    /// Returns the callback that releases process-local driver ownership exactly once.
    #[must_use]
    fn physical_completion_handler(&self) -> PhysicalCompletionHandler {
        let coordinator = self.coordinator.clone();
        let task_id = self.task_id;
        Arc::new(move |_| {
            let _ = coordinator.mark_driver_physically_settled(task_id);
        })
    }

    fn into_gated_owned_task(
        self,
        signal: SupervisionSignal,
        gate: Arc<RootStartGate>,
    ) -> OwnedTaskFuture {
        Box::pin(async move {
            if gate.wait().await {
                let _ = self.await;
            }
            let _ = signal.settle();
            OwnedTaskResult::new()
        })
    }
}

impl Future for TaskDriver {
    type Output = Result<(), RunExecutionError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(context)
    }
}

#[cfg(feature = "durable")]
async fn rollback_submitted_resume(task: SupervisedTask, gate: Arc<RootStartGate>) {
    gate.cancel();
    let _ = task.request_abort();
    let _ = task.completion().await;
}

#[cfg(feature = "durable")]
fn resume_failure(
    journal_id: gantry_host::journal::JournalId,
    category: ResumeStartFailureCategory,
    code: &'static str,
) -> DurableResumeExecutionResult {
    DurableResumeExecutionResult::Rejected(DurableResumeExecutionFailure {
        journal_id,
        category,
        code: Arc::from(code),
        candidate_package_activity: None,
        release_error: None,
    })
}

#[cfg(feature = "durable")]
fn decode_retained_schemas(
    bytes: &[u8],
    maximum_constructed_type_depth: u64,
) -> Result<BTreeMap<TypeDescriptor, Arc<[u8]>>, &'static str> {
    let length = u64::try_from(bytes.len()).map_err(|_| "invalid-retained-schemas")?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: length.max(1),
            maximum_nodes: length.max(1),
            maximum_string_scalars: length.max(1),
            maximum_list_items: length.max(1),
        },
    )
    .map_err(|_| "invalid-retained-schemas")?;
    let canonical =
        CanonicalJson::from_document(&document).map_err(|_| "invalid-retained-schemas")?;
    if canonical.bytes() != bytes {
        return Err("invalid-retained-schemas");
    }
    let JsonNode::Object(entries) = document
        .node(document.root())
        .ok_or("invalid-retained-schemas")?
    else {
        return Err("invalid-retained-schemas");
    };
    entries
        .iter()
        .map(|(descriptor, schema)| {
            let descriptor = TypeDescriptor::from_canonical_string_with_depth_limit(
                descriptor,
                maximum_constructed_type_depth,
            )
            .map_err(|_| "invalid-retained-schemas")?;
            let schema = CanonicalJson::from_node(&document, *schema)
                .map_err(|_| "invalid-retained-schemas")?;
            Ok((descriptor, Arc::from(schema.bytes())))
        })
        .collect()
}

/// Failure while driving an already accepted nondurable execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunExecutionError {
    /// The accepted root is already owned by the interpreter's executor submission.
    ExecutionAlreadyOwned,
    /// Accepted package state unexpectedly omitted analysis.
    MissingAnalysis,
    /// Accepted package state unexpectedly omitted its entry inventory.
    MissingEntry,
    /// Accepted package state unexpectedly omitted executable typed IR.
    MissingExecutableProgram,
    /// Entry input could not be reconstructed as the normalized logical value.
    InvalidEntryValue,
    /// Analyzer-owned operation metadata was absent or internally inconsistent.
    MissingOperationMetadata,
    /// The analyzed package omitted the generated schema for an operation result.
    MissingOperationSchema,
    /// An action occurrence had no preflight-resolved action mapping revision.
    MissingActionMappingRevision,
    /// A model occurrence had no preflight-resolved agent mapping revision.
    MissingAgentMappingRevision,
    /// A model occurrence had no active agent selection.
    MissingActiveAgent,
    /// A model occurrence referenced no known logical session.
    MissingLogicalSession,
    /// Logical-session construction contradicted the runtime contract.
    Session(gantry_runtime::SessionError),
    /// Shared root or child task state rejected a driver transition.
    TaskState(TaskStateError),
    /// A versioned hook request could not be constructed.
    HookRequest(gantry_runtime::HookRequestError),
    /// The task-local hook owner rejected construction.
    TaskHook(TaskHookError),
    /// The shared operation lifecycle rejected a transition.
    OperationLifecycle(OperationLifecycleError),
    /// Effective retry policy contradicted analyzed action recovery metadata.
    RetryPolicy,
    /// The shared machine rejected the analyzed entry.
    MachineBuild(MachineBuildError),
    /// The configured executor failed one cooperative yield.
    ExecutorFailure,
    /// Nondurable execution-event completion or delivery failed.
    Event(ExecutionEventError),
    /// A lifecycle transition contradicted accepted execution state.
    LifecycleTransition,
    /// A lifecycle public operation failed.
    Lifecycle(LifecycleError),
    /// Accepted execution state disappeared before observation.
    ExecutionNotFound,
}

/// Failure while coordinating one public execution-cancellation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelExecutionError {
    /// The public operation was rejected by the interpreter lifecycle.
    Lifecycle(LifecycleError),
    /// A committed durable transition could not be reflected in lifecycle state.
    #[cfg(feature = "durable")]
    Transition(gantry_runtime::ExecutionTransitionError),
    /// Durable cancellation failed without fabricating terminal state.
    #[cfg(feature = "durable")]
    Durable(DurableRunFailure),
}

/// Failure while coordinating interpreter shutdown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShutdownError {
    /// The isolated control-plane capacity was unavailable.
    Admission(AdmissionExhaustion),
    /// Shutdown admission failed at the lifecycle boundary.
    Lifecycle(LifecycleError),
    /// The unique coordinator could not publish the report.
    Completion(ShutdownCompletionError),
    /// The executor rejected the owned shutdown coordinator.
    Executor(gantry_host::contracts::HostError),
    /// The shutdown task stopped, panicked, or failed before normal completion.
    Physical(OwnedTaskCompletion),
}

#[derive(Default)]
struct SharedShutdown {
    state: Mutex<SharedShutdownState>,
}

#[derive(Default)]
struct SharedShutdownState {
    staged: Option<Result<Arc<ShutdownReport>, ShutdownError>>,
    published: Option<Result<Arc<ShutdownReport>, ShutdownError>>,
    waiters: Vec<Waker>,
}

impl SharedShutdown {
    fn stage(&self, result: Result<Arc<ShutdownReport>, ShutdownError>) {
        let mut state = lock_shutdown(&self.state);
        if state.staged.is_none() && state.published.is_none() {
            state.staged = Some(result);
        }
    }

    fn publish_physical(&self, completion: OwnedTaskCompletion) {
        let result = {
            let mut state = lock_shutdown(&self.state);
            if state.published.is_some() {
                return;
            }
            match completion {
                OwnedTaskCompletion::Completed(_) => state.staged.take().unwrap_or_else(|| {
                    Err(ShutdownError::Executor(gantry_host::contracts::HostError {
                        code: Arc::from("executor-failure"),
                        protected_diagnostic: None,
                    }))
                }),
                other => Err(ShutdownError::Physical(other)),
            }
        };
        self.publish(result);
    }

    fn publish(&self, result: Result<Arc<ShutdownReport>, ShutdownError>) {
        let waiters = {
            let mut state = lock_shutdown(&self.state);
            if state.published.is_some() {
                return;
            }
            state.published = Some(result);
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn poll(&self, context: &mut Context<'_>) -> Poll<Result<Arc<ShutdownReport>, ShutdownError>> {
        let mut state = lock_shutdown(&self.state);
        if let Some(result) = &state.published {
            return Poll::Ready(result.clone());
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}

fn lock_shutdown<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn owned_event_delivery_factory(
    inner: Arc<InterpreterInner>,
) -> crate::start::OwnedEventDeliveryFactory {
    Arc::new(move |events, plan| {
        let inner = Arc::clone(&inner);
        Box::pin(async move {
            let package = AnalyzePackageCoordinator::new(
                &inner.allocator,
                inner.configuration.identity_source(),
                inner.clock.as_ref(),
                inner.configuration.blocking_work(),
            )
            .with_blocking_work_poison(inner.blocking_work_poison.clone())
            .with_delivery_runtime(inner.event_delivery_runtime.as_ref());
            package.deliver_completed_events(&events, Some(&plan)).await
        })
    })
}

async fn settle_final_shutdown_event(
    inner: &InterpreterInner,
    durations: gantry_runtime::ShutdownDurations,
    executions_at_start: &[ProtocolIdentity],
    cohort: &[ProtocolIdentity],
    tasks_at_start: u64,
) -> FinalShutdownEventOutcome {
    let activity_id = match inner.allocator.allocate(
        inner.configuration.identity_source(),
        IdentityKind::Activity,
    ) {
        Ok(activity_id) => activity_id,
        Err(_) => {
            return FinalShutdownEventOutcome::failed(
                FinalShutdownEventFailure::IdentityGeneration,
            );
        }
    };
    let snapshots = cohort
        .iter()
        .filter_map(|execution_id| {
            inner
                .lifecycle
                .query_execution(*execution_id)
                .ok()
                .flatten()
        })
        .collect::<Vec<_>>();
    let cancelled = usize_to_u64(
        snapshots
            .iter()
            .filter(|snapshot| snapshot.cancellation.is_some())
            .count(),
    );
    let completed_naturally = usize_to_u64(
        snapshots
            .iter()
            .filter(|snapshot| snapshot.cancellation.is_none() && snapshot.terminal.is_some())
            .count(),
    );
    let draft = match shutdown_event(&ShutdownEventSummaryV1 {
        activity_id,
        graceful_us: durations.graceful.get(),
        drain_us: durations.drain.get(),
        executions_at_start: usize_to_u64(executions_at_start.len()),
        tasks_at_start,
        admitted_after_start: usize_to_u64(cohort.len().saturating_sub(executions_at_start.len())),
        completed_naturally,
        cancelled,
        aborted: 0,
        required_state_commit_status: Arc::from("not-applicable"),
        shutdown_report_reference: Arc::from(format!("shutdown-report:{activity_id}")),
    }) {
        Ok(draft) => draft,
        Err(_) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Internal);
        }
    };
    let event = match EventCompleter::new(
        &inner.allocator,
        inner.configuration.identity_source(),
        inner.clock.as_ref(),
    )
    .complete(activity_id, draft.draft)
    .await
    {
        Ok(event) => event,
        Err(EventCompletionError::Identity(_)) => {
            return FinalShutdownEventOutcome::failed(
                FinalShutdownEventFailure::IdentityGeneration,
            );
        }
        Err(EventCompletionError::Clock(_)) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Executor);
        }
        Err(EventCompletionError::InvalidActivityIdentity | EventCompletionError::Contract(_)) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Internal);
        }
    };
    let delivery = DeliveryKernel::new(
        &inner.allocator,
        inner.configuration.identity_source(),
        inner.event_delivery_runtime.as_ref(),
    )
    .deliver(event, &draft.protected_payloads, &inner.event_delivery)
    .await;
    let delivery = match delivery {
        Ok(delivery) => delivery,
        Err(DeliveryError::Identity(_)) => {
            return FinalShutdownEventOutcome::failed(
                FinalShutdownEventFailure::IdentityGeneration,
            );
        }
        Err(DeliveryError::Runtime(_) | DeliveryError::Retry(_)) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Executor);
        }
        Err(
            DeliveryError::Projection(_)
            | DeliveryError::RetryOverflow
            | DeliveryError::MissingAttempt,
        ) => {
            return FinalShutdownEventOutcome::failed(FinalShutdownEventFailure::Internal);
        }
    };
    let all_settled = delivery
        .settlements
        .iter()
        .all(|settlement| settlement.status == SinkSettlementStatus::Success);
    let required_sinks_settled = delivery.settlements.iter().all(|settlement| {
        settlement.class != gantry_core::portable::SinkClass::Required
            || settlement.status == SinkSettlementStatus::Success
    });
    FinalShutdownEventOutcome {
        settlement: if all_settled {
            FinalShutdownEventSettlement::Settled
        } else {
            FinalShutdownEventSettlement::Exhausted
        },
        required_sinks_settled,
    }
}

struct FinalShutdownEventOutcome {
    settlement: FinalShutdownEventSettlement,
    required_sinks_settled: bool,
}

impl FinalShutdownEventOutcome {
    const fn failed(failure: FinalShutdownEventFailure) -> Self {
        Self {
            settlement: FinalShutdownEventSettlement::Failed(failure),
            required_sinks_settled: false,
        }
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn preparation_error_code(error: &RunExecutionError) -> &'static str {
    match error {
        RunExecutionError::MissingAnalysis => "missing-analysis",
        RunExecutionError::MissingEntry => "missing-entry",
        RunExecutionError::MissingExecutableProgram => "missing-executable-program",
        RunExecutionError::InvalidEntryValue => "invalid-entry-value",
        RunExecutionError::MachineBuild(MachineBuildError::UnsupportedEffect(_)) => {
            "unsupported-profile-effect"
        }
        RunExecutionError::MachineBuild(_) => "root-machine-construction",
        RunExecutionError::Session(_) => "root-session-state",
        RunExecutionError::TaskState(_) => "root-task-state",
        RunExecutionError::HookRequest(_) => "root-hook-request",
        _ => "root-preparation-invariant",
    }
}

fn prepared_start_failure(
    prepared: PreparedExecutionStart,
    category: StartFailureCategory,
    code: impl Into<Arc<str>>,
) -> StartExecutionFailure {
    StartExecutionFailure {
        category,
        code: code.into(),
        package_activity: Some(Box::new(prepared.package_activity)),
    }
}

fn root_start_failure(workflow: &gantry_ir::CanonicalPath, code: RuntimeCode) -> MachineOutcome {
    MachineOutcome::Failed(MachineFailure {
        code,
        workflow: workflow.clone(),
        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
            .unwrap_or_else(|_| unreachable!("constant position is valid")),
    })
}

fn settle_root_start_failure(
    lifecycle: &InterpreterLifecycle,
    accepted: &StartExecutionAccepted,
    coordinator: &ExecutionCoordinator,
    outcome: MachineOutcome,
    physically_settled: bool,
) -> Result<(), RunExecutionError> {
    if physically_settled {
        coordinator
            .fail_root_submission(outcome.clone())
            .map_err(RunExecutionError::TaskState)?;
    } else {
        coordinator
            .fail_root_registration(outcome.clone())
            .map_err(RunExecutionError::TaskState)?;
    }
    let foreground = coordinator
        .complete_foreground()
        .map_err(RunExecutionError::TaskState)?;
    if foreground != outcome {
        return Err(RunExecutionError::LifecycleTransition);
    }
    coordinator
        .complete_terminal()
        .map_err(RunExecutionError::TaskState)?;
    lifecycle
        .complete_foreground(&accepted.handle, outcome.clone())
        .map_err(|_| RunExecutionError::LifecycleTransition)?;
    lifecycle
        .complete_terminal(&accepted.handle, outcome)
        .map_err(|_| RunExecutionError::LifecycleTransition)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenderPromptError {
    Shape,
    Limit,
}

fn render_prompt<'a>(
    segments: &[Arc<str>],
    inputs: impl Iterator<Item = &'a LogicalValue>,
    maximum_string_scalars: u64,
) -> Result<Arc<str>, RenderPromptError> {
    let inputs = inputs.collect::<Vec<_>>();
    if segments.len() != inputs.len().saturating_add(1) {
        return Err(RenderPromptError::Shape);
    }
    let mut rendered = String::new();
    for (index, input) in inputs.iter().enumerate() {
        rendered.push_str(&segments[index]);
        if let Some(value) = input.as_string() {
            rendered.push_str(value);
        } else {
            rendered.push_str(
                std::str::from_utf8(input.canonical_json().bytes())
                    .map_err(|_| RenderPromptError::Shape)?,
            );
        }
    }
    rendered.push_str(segments.last().ok_or(RenderPromptError::Shape)?);
    let scalars = u64::try_from(rendered.chars().count()).unwrap_or(u64::MAX);
    if scalars > maximum_string_scalars {
        return Err(RenderPromptError::Limit);
    }
    Ok(Arc::from(rendered))
}

fn transcript_result_kind(ty: &TypeDescriptor) -> TranscriptResultKindV1 {
    match ty.kind() {
        TypeKind::Unit => TranscriptResultKindV1::Unit,
        TypeKind::Decision => TranscriptResultKindV1::Decision,
        _ => TranscriptResultKindV1::Value,
    }
}

pub(crate) fn decode_logical_value(
    bytes: &[u8],
    ty: &TypeDescriptor,
    limits: ValueLimits,
    shapes: Option<&DeclaredValueShapes>,
) -> Result<LogicalValue, RunExecutionError> {
    let length = u64::try_from(bytes.len()).map_err(|_| RunExecutionError::InvalidEntryValue)?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: limits.maximum_nesting_depth(),
            maximum_nodes: limits.maximum_nodes(),
            maximum_string_scalars: limits.maximum_string_scalars(),
            maximum_list_items: limits.maximum_list_items(),
        },
    )
    .map_err(|_| RunExecutionError::InvalidEntryValue)?;
    decode_node(&document, document.root(), ty, limits, shapes)
}

fn decode_node(
    document: &StrictJsonDocument,
    id: JsonNodeId,
    ty: &TypeDescriptor,
    limits: ValueLimits,
    shapes: Option<&DeclaredValueShapes>,
) -> Result<LogicalValue, RunExecutionError> {
    let node = document
        .node(id)
        .ok_or(RunExecutionError::InvalidEntryValue)?;
    match (ty.kind(), node) {
        (TypeKind::Unit, JsonNode::Null) => Ok(LogicalValue::unit()),
        (TypeKind::Bool, JsonNode::Bool(value)) => Ok(LogicalValue::boolean(*value)),
        (TypeKind::Int, JsonNode::Number(value)) => value
            .to_gantry_int()
            .ok()
            .and_then(GantryInt::new)
            .map(LogicalValue::integer)
            .ok_or(RunExecutionError::InvalidEntryValue),
        (TypeKind::Float, JsonNode::Number(value)) => value
            .to_gantry_float()
            .ok()
            .and_then(GantryFloat::new)
            .map(LogicalValue::float)
            .ok_or(RunExecutionError::InvalidEntryValue),
        (TypeKind::String, JsonNode::String(value)) => {
            LogicalValue::string(value.to_string(), limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Declared, JsonNode::Object(members)) => {
            decode_declared_value(document, members, ty, limits, shapes)
        }
        (TypeKind::Decision, JsonNode::Object(members)) => {
            if members.len() != 2 {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let decision = object_member(document, members, "decision")
                .and_then(|id| document.node(id))
                .and_then(|node| match node {
                    JsonNode::Bool(value) => Some(*value),
                    _ => None,
                })
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let rationale = object_member(document, members, "rationale")
                .and_then(|id| document.node(id))
                .and_then(|node| match node {
                    JsonNode::String(value) => Some(value.to_string()),
                    _ => None,
                })
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            LogicalValue::decision(decision, rationale, limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Option, JsonNode::Null) => Ok(LogicalValue::none()),
        (TypeKind::Option, _) => {
            let member = ty
                .immediate_members()
                .into_iter()
                .next()
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            LogicalValue::some(decode_node(document, id, &member, limits, shapes)?, limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Result, JsonNode::Object(members)) => {
            if members.len() != 2 {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let variant = object_string(document, members, "variant")?;
            let value = object_member(document, members, "value")
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let result_members = ty.immediate_members();
            match variant {
                "Ok" => LogicalValue::ok(
                    decode_node(
                        document,
                        value,
                        result_members
                            .first()
                            .ok_or(RunExecutionError::InvalidEntryValue)?,
                        limits,
                        shapes,
                    )?,
                    limits,
                ),
                "Err" => LogicalValue::err(
                    decode_node(
                        document,
                        value,
                        result_members
                            .get(1)
                            .ok_or(RunExecutionError::InvalidEntryValue)?,
                        limits,
                        shapes,
                    )?,
                    limits,
                ),
                _ => return Err(RunExecutionError::InvalidEntryValue),
            }
            .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::List, JsonNode::Array(items)) => {
            let member = ty
                .immediate_members()
                .into_iter()
                .next()
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let values = items
                .iter()
                .map(|item| decode_node(document, *item, &member, limits, shapes))
                .collect::<Result<Vec<_>, _>>()?;
            LogicalValue::list(values, limits).map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::Tuple, JsonNode::Array(items)) => {
            let members = ty.immediate_members();
            if members.len() != items.len() {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let values = items
                .iter()
                .zip(&members)
                .map(|(item, member)| decode_node(document, *item, member, limits, shapes))
                .collect::<Result<Vec<_>, _>>()?;
            LogicalValue::tuple(values, limits).map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        (TypeKind::OperationError, JsonNode::Object(members)) => {
            decode_operation_error(document, members, limits)
        }
        _ => Err(RunExecutionError::InvalidEntryValue),
    }
}

fn decode_declared_value(
    document: &StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    ty: &TypeDescriptor,
    limits: ValueLimits,
    shapes: Option<&DeclaredValueShapes>,
) -> Result<LogicalValue, RunExecutionError> {
    let shape = shapes
        .and_then(|shapes| shapes.get(ty))
        .ok_or(RunExecutionError::InvalidEntryValue)?;
    match shape {
        DeclaredValueShape::Struct(fields) => {
            if members
                .iter()
                .any(|(name, _)| !fields.iter().any(|field| field.name == *name))
            {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let values = fields
                .iter()
                .map(|field| {
                    let value = if let Some(id) = object_member(document, members, &field.name) {
                        decode_node(document, id, &field.ty, limits, shapes)
                    } else if field.ty.kind() == TypeKind::Option {
                        field.default_json.as_ref().map_or_else(
                            || Ok(LogicalValue::none()),
                            |default| decode_logical_value(default, &field.ty, limits, shapes),
                        )
                    } else {
                        Err(RunExecutionError::InvalidEntryValue)
                    }?;
                    Ok((field.name.to_string(), value))
                })
                .collect::<Result<Vec<_>, RunExecutionError>>()?;
            LogicalValue::structure(ty.canonical_string(), values, limits)
                .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
        DeclaredValueShape::Enum(variants) => {
            let variant_name = object_string(document, members, "variant")?;
            let variant = variants
                .iter()
                .find(|variant| variant.name.as_ref() == variant_name)
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let payload = match &variant.payload {
                Some(payload_ty) if members.len() == 2 => {
                    let id = object_member(document, members, "value")
                        .ok_or(RunExecutionError::InvalidEntryValue)?;
                    Some(decode_node(document, id, payload_ty, limits, shapes)?)
                }
                None if members.len() == 1 => None,
                _ => return Err(RunExecutionError::InvalidEntryValue),
            };
            LogicalValue::enumeration(
                ty.canonical_string(),
                variant.name.to_string(),
                payload,
                limits,
            )
            .map_err(|_| RunExecutionError::InvalidEntryValue)
        }
    }
}

fn decode_operation_error(
    document: &StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    limits: ValueLimits,
) -> Result<LogicalValue, RunExecutionError> {
    let variant = object_string(document, members, "variant")?;
    let string_payload = || {
        if members.len() != 2 {
            return Err(RunExecutionError::InvalidEntryValue);
        }
        let id = object_member(document, members, "value")
            .ok_or(RunExecutionError::InvalidEntryValue)?;
        match document.node(id) {
            Some(JsonNode::String(value)) => Ok(value.to_string()),
            _ => Err(RunExecutionError::InvalidEntryValue),
        }
    };
    let error = match variant {
        "Declined" => OperationErrorValue::Declined(string_payload()?),
        "InvalidOutput" if members.len() == 1 => OperationErrorValue::InvalidOutput,
        "ProviderFailure" => OperationErrorValue::ProviderFailure(string_payload()?),
        "Timeout" => OperationErrorValue::Timeout(string_payload()?),
        "PolicyDenied" => OperationErrorValue::PolicyDenied(string_payload()?),
        "Cancelled" => OperationErrorValue::Cancelled(string_payload()?),
        "UnknownOutcome" if members.len() == 2 => {
            let id = object_member(document, members, "value")
                .ok_or(RunExecutionError::InvalidEntryValue)?;
            let Some(JsonNode::Array(values)) = document.node(id) else {
                return Err(RunExecutionError::InvalidEntryValue);
            };
            if values.len() != 2 {
                return Err(RunExecutionError::InvalidEntryValue);
            }
            let operation_id = json_string_node(document, values[0])?.to_owned();
            let message = json_string_node(document, values[1])?.to_owned();
            OperationErrorValue::UnknownOutcome {
                operation_id,
                message,
            }
        }
        _ => return Err(RunExecutionError::InvalidEntryValue),
    };
    LogicalValue::operation_error(error, limits).map_err(|_| RunExecutionError::InvalidEntryValue)
}

fn object_string<'a>(
    document: &'a StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Result<&'a str, RunExecutionError> {
    let id = object_member(document, members, name).ok_or(RunExecutionError::InvalidEntryValue)?;
    json_string_node(document, id)
}

fn json_string_node(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&str, RunExecutionError> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Ok(value),
        _ => Err(RunExecutionError::InvalidEntryValue),
    }
}

fn object_member(
    _document: &StrictJsonDocument,
    members: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Option<JsonNodeId> {
    members
        .iter()
        .find(|(candidate, _)| candidate.as_ref() == name)
        .map(|(_, id)| *id)
}

/// Constructs the ordinary caller cancellation reason under one value limit.
pub fn caller_cancellation_reason(
    message: Option<Arc<str>>,
    maximum_string_scalars: u64,
) -> Result<CancellationReason, gantry_runtime::CancellationReasonError> {
    CancellationReason::new(
        CancellationReasonCategory::Caller,
        message,
        None,
        maximum_string_scalars,
    )
}

/// Derives the stable root-task identity for public hook composition.
pub fn root_task_identity(execution_id: ProtocolIdentity) -> ProtocolIdentity {
    gantry_runtime::root_task_identity(execution_id)
}
