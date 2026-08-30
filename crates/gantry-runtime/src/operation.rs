//! Task-local lazy hook construction and serial dispatch boundaries.

use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::OperationStateKind;
use gantry_core::value::LogicalValue;
use gantry_host::contracts::{
    CancellationToken, EmbeddingVersion, FreshIdentityAllocator, HookFactory, HostError,
    HostRequest, HostResponse, IdentitySource, OperationHook,
};
use gantry_host::embedding::EmbeddingOperation;

use crate::{
    AdapterPoison, BoundaryFailure, CapturedOperationRequestV1, HookRequestError,
    InterpreterLifecycle, Machine, MachineLabel, OperationCompletionError, PreparedHookDispatch,
    ValidationErrorV1, drop_integration,
};

/// One task-owned hook boundary for one in-process execution or resume run.
///
/// A mutable borrow is required for dispatch, so one hook instance cannot be
/// invoked concurrently. Construction remains lazy until the first valid
/// dispatch request reaches this owner.
pub struct TaskHook<'a> {
    lifecycle: &'a InterpreterLifecycle,
    factory: &'a dyn HookFactory,
    factory_poison: AdapterPoison,
    hook_poison: AdapterPoison,
    create_request: HostRequest,
    state: HookState,
}

enum HookState {
    Uninitialized,
    Failed(TaskHookError),
    Ready(Box<dyn OperationHook>),
}

/// Structured failure at the hook factory or task-local hook boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskHookError {
    /// The supplied envelope has the wrong exact version or operation.
    InvalidRequest,
    /// The integration returned a response for another version or operation.
    InvalidResponse,
    /// Integration code returned a structured adapter failure.
    Host(HostError),
    /// Integration code panicked while being invoked, polled, or destroyed.
    Boundary(BoundaryFailure),
}

/// Public projection of one logical operation's current lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationLifecycleState {
    /// Captured semantic input exists, but no physical dispatch identity does.
    Absent,
    /// One fresh physical dispatch is ready for the task-local hook.
    Prepared {
        /// Fresh physical dispatch identity.
        dispatch_id: ProtocolIdentity,
    },
    /// One exact hook response has returned and awaits Gantry validation.
    Outcome {
        /// Physical dispatch that produced the outcome.
        dispatch_id: ProtocolIdentity,
    },
    /// One normalized result became source-consumable exactly once.
    Accepted,
    /// The factory or hook boundary failed before result acceptance.
    Failed {
        /// Physical dispatch when failure occurred after preparation.
        dispatch_id: Option<ProtocolIdentity>,
    },
}

impl OperationLifecycleState {
    /// Returns the exact portable operation-state vocabulary value.
    #[must_use]
    pub const fn kind(&self) -> OperationStateKind {
        match self {
            Self::Absent => OperationStateKind::Absent,
            Self::Prepared { .. } => OperationStateKind::Prepared,
            Self::Outcome { .. } => OperationStateKind::Outcome,
            Self::Accepted => OperationStateKind::Accepted,
            Self::Failed { .. } => OperationStateKind::Failed,
        }
    }
}

/// Rejection of an invalid operation lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationLifecycleError {
    /// Immutable request validation or physical identity allocation failed.
    Request(HookRequestError),
    /// Hook creation, invocation, response, or integration containment failed.
    Hook(TaskHookError),
    /// The requested transition is not enabled from the current state.
    InvalidState {
        /// Current exact portable state.
        actual: OperationStateKind,
    },
    /// The normalized result could not enter the matching machine operation.
    Completion(OperationCompletionError),
}

/// One logical operation from immutable capture through source-result acceptance.
pub struct OperationLifecycle {
    captured: Arc<CapturedOperationRequestV1>,
    state: OperationRuntimeState,
}

enum OperationRuntimeState {
    Absent,
    Prepared(PreparedHookDispatch),
    Outcome {
        dispatch_id: ProtocolIdentity,
        response: HostResponse,
    },
    Accepted,
    Failed {
        dispatch_id: Option<ProtocolIdentity>,
        error: TaskHookError,
    },
}

impl OperationLifecycle {
    /// Validates and captures one immutable semantic request before dispatch.
    pub fn new(captured: CapturedOperationRequestV1) -> Result<Self, OperationLifecycleError> {
        captured
            .validate()
            .map_err(OperationLifecycleError::Request)?;
        Ok(Self {
            captured: Arc::new(captured),
            state: OperationRuntimeState::Absent,
        })
    }

    /// Returns the immutable semantic request reused by every physical dispatch.
    #[must_use]
    pub fn captured(&self) -> &CapturedOperationRequestV1 {
        &self.captured
    }

    /// Returns the exact public lifecycle projection.
    #[must_use]
    pub fn state(&self) -> OperationLifecycleState {
        match &self.state {
            OperationRuntimeState::Absent => OperationLifecycleState::Absent,
            OperationRuntimeState::Prepared(dispatch) => OperationLifecycleState::Prepared {
                dispatch_id: dispatch.dispatch_id,
            },
            OperationRuntimeState::Outcome { dispatch_id, .. } => {
                OperationLifecycleState::Outcome {
                    dispatch_id: *dispatch_id,
                }
            }
            OperationRuntimeState::Accepted => OperationLifecycleState::Accepted,
            OperationRuntimeState::Failed { dispatch_id, .. } => OperationLifecycleState::Failed {
                dispatch_id: *dispatch_id,
            },
        }
    }

    /// Returns the exact returned hook response while validation is pending.
    #[must_use]
    pub fn outcome(&self) -> Option<&HostResponse> {
        match &self.state {
            OperationRuntimeState::Outcome { response, .. } => Some(response),
            _ => None,
        }
    }

    /// Returns the retained integration failure after the operation fails.
    #[must_use]
    pub fn failure(&self) -> Option<&TaskHookError> {
        match &self.state {
            OperationRuntimeState::Failed { error, .. } => Some(error),
            _ => None,
        }
    }

    /// Allocates one fresh physical dispatch after immutable capture succeeds.
    pub fn prepare(
        &mut self,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
        validation_attempt: u64,
        recovery_dispatch: u64,
        validation_errors: &[ValidationErrorV1],
    ) -> Result<ProtocolIdentity, OperationLifecycleError> {
        self.require_state(OperationStateKind::Absent)?;
        let dispatch = self
            .captured
            .prepare_dispatch(
                allocator,
                identity_source,
                validation_attempt,
                recovery_dispatch,
                validation_errors,
            )
            .map_err(OperationLifecycleError::Request)?;
        let dispatch_id = dispatch.dispatch_id;
        self.state = OperationRuntimeState::Prepared(dispatch);
        Ok(dispatch_id)
    }

    /// Lazily creates the task hook, dispatches serially, and retains one outcome.
    pub async fn dispatch(
        &mut self,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
    ) -> Result<&HostResponse, OperationLifecycleError> {
        self.require_state(OperationStateKind::Prepared)?;
        let OperationRuntimeState::Prepared(prepared) = &self.state else {
            unreachable!("state check preserves prepared dispatch")
        };
        let dispatch_id = prepared.dispatch_id;
        let request = prepared.request.clone();
        match hook.dispatch(request, cancellation).await {
            Ok(response) => {
                self.state = OperationRuntimeState::Outcome {
                    dispatch_id,
                    response,
                };
                self.outcome()
                    .ok_or_else(|| invalid_state(OperationStateKind::Outcome))
            }
            Err(error) => {
                self.state = OperationRuntimeState::Failed {
                    dispatch_id: Some(dispatch_id),
                    error: error.clone(),
                };
                Err(OperationLifecycleError::Hook(error))
            }
        }
    }

    /// Makes one validated normalized result source-consumable in the machine.
    pub fn accept(
        &mut self,
        machine: &mut Machine,
        value: LogicalValue,
    ) -> Result<MachineLabel, OperationLifecycleError> {
        self.require_state(OperationStateKind::Outcome)?;
        let operation = self.captured.header().operation_id;
        let label = machine
            .complete_operation(operation, value)
            .map_err(OperationLifecycleError::Completion)?;
        self.state = OperationRuntimeState::Accepted;
        Ok(label)
    }

    fn require_state(&self, expected: OperationStateKind) -> Result<(), OperationLifecycleError> {
        let actual = self.state().kind();
        if actual == expected {
            Ok(())
        } else {
            Err(invalid_state(actual))
        }
    }
}

fn invalid_state(actual: OperationStateKind) -> OperationLifecycleError {
    OperationLifecycleError::InvalidState { actual }
}

impl<'a> TaskHook<'a> {
    /// Binds one task context to a shared hook factory without invoking it.
    pub fn new(
        lifecycle: &'a InterpreterLifecycle,
        factory: &'a dyn HookFactory,
        factory_poison: AdapterPoison,
        create_request: HostRequest,
    ) -> Result<Self, TaskHookError> {
        require_request(&create_request, EmbeddingOperation::CreateHook)?;
        Ok(Self {
            lifecycle,
            factory,
            factory_poison,
            hook_poison: AdapterPoison::default(),
            create_request,
            state: HookState::Uninitialized,
        })
    }

    /// Returns whether the factory boundary has been crossed.
    #[must_use]
    pub const fn creation_attempted(&self) -> bool {
        !matches!(self.state, HookState::Uninitialized)
    }

    /// Returns whether one usable task-local hook has been created.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, HookState::Ready(_))
    }

    /// Lazily creates the task hook and performs one serial operation dispatch.
    pub async fn dispatch(
        &mut self,
        request: HostRequest,
        cancellation: &dyn CancellationToken,
    ) -> Result<HostResponse, TaskHookError> {
        require_request(&request, EmbeddingOperation::DispatchOperation)?;
        self.ensure_created().await?;

        let lifecycle = self.lifecycle;
        let poison = self.hook_poison.clone();
        let future = match &mut self.state {
            HookState::Ready(hook) => lifecycle
                .catch_adapter(&poison, || hook.dispatch(request, cancellation))
                .map_err(TaskHookError::Boundary)?,
            HookState::Failed(error) => return Err(error.clone()),
            HookState::Uninitialized => unreachable!("successful creation installs one hook"),
        };
        let response = lifecycle
            .contain_adapter_future(future, poison)
            .await
            .map_err(TaskHookError::Boundary)?
            .map_err(TaskHookError::Host)?;
        require_response(&response, EmbeddingOperation::DispatchOperation)?;
        Ok(response)
    }

    async fn ensure_created(&mut self) -> Result<(), TaskHookError> {
        match &self.state {
            HookState::Ready(_) => return Ok(()),
            HookState::Failed(error) => return Err(error.clone()),
            HookState::Uninitialized => {}
        }

        let future = self
            .lifecycle
            .catch_adapter(&self.factory_poison, || {
                self.factory.create_hook(self.create_request.clone())
            })
            .map_err(TaskHookError::Boundary);
        let result = match future {
            Ok(future) => self
                .lifecycle
                .contain_adapter_future(future, self.factory_poison.clone())
                .await
                .map_err(TaskHookError::Boundary)
                .and_then(|result| result.map_err(TaskHookError::Host)),
            Err(error) => Err(error),
        };
        match result {
            Ok(hook) => {
                self.state = HookState::Ready(hook);
                Ok(())
            }
            Err(error) => {
                self.state = HookState::Failed(error.clone());
                Err(error)
            }
        }
    }
}

impl Drop for TaskHook<'_> {
    fn drop(&mut self) {
        let HookState::Ready(hook) = std::mem::replace(&mut self.state, HookState::Uninitialized)
        else {
            return;
        };
        let mut hook = Some(hook);
        let _ = drop_integration(&self.hook_poison, &mut hook);
    }
}

fn require_request(
    request: &HostRequest,
    operation: EmbeddingOperation,
) -> Result<(), TaskHookError> {
    if request.version() == EmbeddingVersion::V1 && request.operation() == operation {
        Ok(())
    } else {
        Err(TaskHookError::InvalidRequest)
    }
}

fn require_response(
    response: &HostResponse,
    operation: EmbeddingOperation,
) -> Result<(), TaskHookError> {
    if response.version() == EmbeddingVersion::V1 && response.operation() == operation {
        Ok(())
    } else {
        Err(TaskHookError::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use gantry_core::portable::IdentityKind;
    use gantry_core::source::FrontendLimits;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, ValueLimits};
    use gantry_host::contracts::{
        ActionMappingRevision, CancellationSignal, DurationMicros, ExecutorAdapter, HostFuture,
        IdentitySource, InclusiveJitterRange,
    };
    use gantry_ir::generated::RecoveryClass;
    use gantry_ir::{
        CanonicalPath, CanonicalSignature, EffectSet, StructuralPosition, TypeDescriptor,
    };

    use super::*;
    use crate::{
        ActionOperationRequestV1, CapturedOperationRequestV1, Instruction, InstructionKind,
        InterpreterConfiguration, MachineLimits, MachineProgram, MachineStep,
        OperationRequestHeaderV1, RequiredConfiguration, Workflow,
    };

    struct Services;

    impl IdentitySource for Services {
        fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
            Ok([1; 32])
        }
    }

    impl ExecutorAdapter for Services {
        fn sleep<'a>(&'a self, _: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
            Ok(range.minimum())
        }
    }

    struct RecordingFactory {
        creations: Arc<AtomicUsize>,
        dispatches: Arc<AtomicUsize>,
    }

    impl HookFactory for RecordingFactory {
        fn create_hook<'a>(
            &'a self,
            request: HostRequest,
        ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
            assert_eq!(request.operation(), EmbeddingOperation::CreateHook);
            self.creations.fetch_add(1, Ordering::AcqRel);
            let dispatches = Arc::clone(&self.dispatches);
            Box::pin(
                async move { Ok(Box::new(RecordingHook { dispatches }) as Box<dyn OperationHook>) },
            )
        }
    }

    struct RecordingHook {
        dispatches: Arc<AtomicUsize>,
    }

    impl OperationHook for RecordingHook {
        fn dispatch<'a>(
            &'a mut self,
            request: HostRequest,
            _: &'a dyn CancellationToken,
        ) -> HostFuture<'a, Result<HostResponse, HostError>> {
            assert_eq!(request.operation(), EmbeddingOperation::DispatchOperation);
            self.dispatches.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                HostResponse::new(
                    EmbeddingVersion::V1,
                    EmbeddingOperation::DispatchOperation,
                    Arc::from(&b"{\"result\":\"completed\"}"[..]),
                )
                .map_err(|_| HostError {
                    code: Arc::from("response-invariant"),
                    protected_diagnostic: None,
                })
            })
        }
    }

    #[test]
    fn task_hook_is_lazy_created_once_and_dispatched_serially() {
        let configuration = configuration();
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let creations = Arc::new(AtomicUsize::new(0));
        let dispatches = Arc::new(AtomicUsize::new(0));
        let factory = RecordingFactory {
            creations: Arc::clone(&creations),
            dispatches: Arc::clone(&dispatches),
        };
        let mut hook = TaskHook::new(
            &lifecycle,
            &factory,
            AdapterPoison::default(),
            request(EmbeddingOperation::CreateHook),
        )
        .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
        assert!(!hook.creation_attempted());
        assert_eq!(creations.load(Ordering::Acquire), 0);

        let cancellation = CancellationSignal::default();
        for expected in 1..=2 {
            let result = block_on(hook.dispatch(
                request(EmbeddingOperation::DispatchOperation),
                &cancellation,
            ));
            assert!(result.is_ok());
            assert!(hook.is_ready());
            assert_eq!(creations.load(Ordering::Acquire), 1);
            assert_eq!(dispatches.load(Ordering::Acquire), expected);
        }
    }

    #[test]
    fn invalid_dispatch_does_not_create_a_hook() {
        let configuration = configuration();
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let creations = Arc::new(AtomicUsize::new(0));
        let factory = RecordingFactory {
            creations: Arc::clone(&creations),
            dispatches: Arc::new(AtomicUsize::new(0)),
        };
        let mut hook = TaskHook::new(
            &lifecycle,
            &factory,
            AdapterPoison::default(),
            request(EmbeddingOperation::CreateHook),
        )
        .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
        let result = block_on(hook.dispatch(
            request(EmbeddingOperation::ResolveMappings),
            &CancellationSignal::default(),
        ));
        assert_eq!(result, Err(TaskHookError::InvalidRequest));
        assert!(!hook.creation_attempted());
        assert_eq!(creations.load(Ordering::Acquire), 0);
    }

    #[test]
    fn operation_lifecycle_accepts_once_after_lazy_serial_dispatch() {
        let configuration = configuration();
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let creations = Arc::new(AtomicUsize::new(0));
        let dispatches = Arc::new(AtomicUsize::new(0));
        let factory = RecordingFactory {
            creations: Arc::clone(&creations),
            dispatches: Arc::clone(&dispatches),
        };
        let mut hook = TaskHook::new(
            &lifecycle,
            &factory,
            AdapterPoison::default(),
            request(EmbeddingOperation::CreateHook),
        )
        .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
        let (mut machine, occurrence) = machine_with_operation();
        let mut operation = operation_lifecycle(&occurrence);
        assert_eq!(operation.state().kind(), OperationStateKind::Absent);

        let dispatch_id = operation
            .prepare(&FreshIdentityAllocator::default(), &Services, 0, 0, &[])
            .unwrap_or_else(|error| panic!("operation preparation failed: {error:?}"));
        assert_eq!(dispatch_id.kind(), IdentityKind::Dispatch);
        assert_eq!(operation.state().kind(), OperationStateKind::Prepared);
        assert!(!hook.creation_attempted());

        let cancellation = CancellationSignal::default();
        let response = block_on(operation.dispatch(&mut hook, &cancellation));
        assert!(response.is_ok());
        assert_eq!(operation.state().kind(), OperationStateKind::Outcome);
        assert_eq!(creations.load(Ordering::Acquire), 1);
        assert_eq!(dispatches.load(Ordering::Acquire), 1);

        assert!(matches!(
            operation.accept(&mut machine, LogicalValue::unit()),
            Ok(MachineLabel::OperationResult { operation: identity })
                if identity == occurrence.identity
        ));
        assert_eq!(operation.state().kind(), OperationStateKind::Accepted);
        assert_eq!(
            operation.accept(&mut machine, LogicalValue::unit()),
            Err(OperationLifecycleError::InvalidState {
                actual: OperationStateKind::Accepted,
            })
        );
    }

    #[test]
    fn cancellation_after_hook_outcome_prevents_result_consumption() {
        let configuration = configuration();
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let factory = RecordingFactory {
            creations: Arc::new(AtomicUsize::new(0)),
            dispatches: Arc::new(AtomicUsize::new(0)),
        };
        let mut hook = TaskHook::new(
            &lifecycle,
            &factory,
            AdapterPoison::default(),
            request(EmbeddingOperation::CreateHook),
        )
        .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
        let (mut machine, occurrence) = machine_with_operation();
        let mut operation = operation_lifecycle(&occurrence);
        operation
            .prepare(&FreshIdentityAllocator::default(), &Services, 0, 0, &[])
            .unwrap_or_else(|error| panic!("operation preparation failed: {error:?}"));
        assert!(block_on(operation.dispatch(&mut hook, &CancellationSignal::default(),)).is_ok());

        assert!(machine.cancel("caller").is_some());
        assert_eq!(
            operation.accept(&mut machine, LogicalValue::unit()),
            Err(OperationLifecycleError::Completion(
                OperationCompletionError::Cancelled,
            ))
        );
        assert_eq!(operation.state().kind(), OperationStateKind::Outcome);
        assert_eq!(machine.status(), crate::MachineStatus::WaitingOperation);
    }

    fn machine_with_operation() -> (Machine, crate::OperationOccurrence) {
        let workflow_path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("workflow path failed: {error}"));
        let site = StructuralPosition::new(vec![0])
            .unwrap_or_else(|error| panic!("operation site failed: {error}"));
        let program = MachineProgram::new(vec![Workflow {
            path: workflow_path.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site,
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Operation,
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("return site failed: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("machine program failed: {error:?}"));
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [9; 32])
            .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
        let limits = MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("machine limits failed"));
        let mut machine = Machine::new(
            Arc::new(program),
            &workflow_path,
            Vec::new(),
            execution,
            limits,
        )
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"));
        let occurrence = match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(occurrence)) => occurrence,
            other => panic!("unexpected machine step: {other:?}"),
        };
        (machine, occurrence)
    }

    fn operation_lifecycle(occurrence: &crate::OperationOccurrence) -> OperationLifecycle {
        let path = CanonicalPath::new("crate::noop")
            .unwrap_or_else(|error| panic!("action path failed: {error}"));
        let captured = CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: ProtocolIdentity::from_fresh_material(
                    IdentityKind::Execution,
                    [9; 32],
                )
                .unwrap_or_else(|error| panic!("execution identity failed: {error}")),
                task_id: ProtocolIdentity::derive(IdentityKind::Task, b"root-task")
                    .unwrap_or_else(|error| panic!("task identity failed: {error}")),
                operation_id: occurrence.identity,
                kind: gantry_ir::generated::OperationSiteKind::Action,
                expected_type: TypeDescriptor::UNIT,
                expected_schema: Arc::from(&br#"{"type":"null"}"#[..]),
                maximum_hook_output_bytes: 1_024,
                value_limits: DEFAULT_VALUE_LIMITS,
                workflow: occurrence.workflow.clone(),
                site: occurrence.site.clone(),
            },
            body: ActionOperationRequestV1 {
                path: path.clone(),
                signature: CanonicalSignature::action(
                    RecoveryClass::ReadOnly,
                    &path,
                    &[],
                    &TypeDescriptor::UNIT,
                ),
                recovery: RecoveryClass::ReadOnly,
                mapping_revision: ActionMappingRevision::new("actions-v1")
                    .unwrap_or_else(|error| panic!("mapping revision failed: {error:?}")),
                arguments: Vec::new(),
            },
        };
        OperationLifecycle::new(captured)
            .unwrap_or_else(|error| panic!("operation lifecycle failed: {error:?}"))
    }

    fn request(operation: EmbeddingOperation) -> HostRequest {
        HostRequest::new(EmbeddingVersion::V1, operation, Arc::from(&b"{}"[..]))
            .unwrap_or_else(|error| panic!("request failed: {error}"))
    }

    fn configuration() -> InterpreterConfiguration {
        let services = Arc::new(Services);
        let required = RequiredConfiguration::new(
            FrontendLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1)
                .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
            1,
            1,
            ValueLimits::new(1, 1, 1, 1).unwrap_or_else(|| panic!("value limits failed")),
            1,
            1,
            1,
            1,
        )
        .unwrap_or_else(|error| panic!("configuration failed: {error}"));
        InterpreterConfiguration::new(services.clone(), services, required)
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
