//! Task-local lazy hook construction and serial dispatch boundaries.

use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::OperationStateKind;
use gantry_core::value::{LogicalValue, ValueError};
use gantry_host::contracts::{
    CancellationSignal, CancellationToken, EmbeddingVersion, ExecutorAdapter,
    FreshIdentityAllocator, HookFactory, HookOutcomeV1, HostError, HostRequest, IdentitySource,
    OperationHook,
};
use gantry_host::embedding::EmbeddingOperation;

use crate::{
    AdapterPoison, BoundaryFailure, CapturedOperationRequestV1, HookOutcomeProcessingError,
    HookRequestError, InterpreterLifecycle, LogicalSessionV1, Machine, MachineLabel,
    ModelSessionUseV1, OperationCompletionError, OperationFailureV1, OperationRetryPolicyV1,
    OperationRetryWaitV1, PreparedHookDispatch, ProcessedHookOutcomeV1, SessionCreationModeV1,
    SessionEstablisher, SessionEstablishmentError, SessionEstablishmentV1, TranscriptError,
    TranscriptResultKindV1, TranscriptTurnV1, ValidatedHookOutputV1, ValidationErrorV1,
    drop_integration, process_hook_outcome, wait_retry_delay,
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
    /// Integration code returned a structured adapter failure.
    Host(HostError),
    /// Integration code panicked while being invoked, polled, or destroyed.
    Boundary(BoundaryFailure),
}

/// Failure while enforcing session setup before one model-hook dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskHookSessionError {
    /// Required logical-session establishment failed before hook construction.
    Session(SessionEstablishmentError),
    /// Hook construction or dispatch failed after session setup succeeded.
    Hook(TaskHookError),
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
    /// One recorded validation-repair delay precedes a fresh physical dispatch.
    RetryWaiting {
        /// Physical dispatch whose invalid output selected this retry.
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
            Self::RetryWaiting { .. } => OperationStateKind::RetryWaiting,
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
    /// Gantry could not validate or normalize an otherwise typed hook outcome.
    Outcome(HookOutcomeProcessingError),
    /// The requested transition is not enabled from the current state.
    InvalidState {
        /// Current exact portable state.
        actual: OperationStateKind,
    },
    /// The normalized result could not enter the matching machine operation.
    Completion(OperationCompletionError),
    /// The complete proposed model transcript was invalid or exceeded a limit.
    Transcript(TranscriptError),
    /// The supplied source value did not equal the validated normalized hook output.
    InvalidAcceptedValue,
    /// Construction of an explicit `attempt` result exceeded value invariants or limits.
    AttemptValue(ValueError),
    /// The retained failure domain is not catchable by `attempt`.
    AttemptNotCatchable,
    /// The retained attempted failure has already been consumed by the machine.
    AttemptResultConsumed,
}

/// Retained terminal failure for one logical operation lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationLifecycleFailureV1 {
    /// Hook construction or dispatch failed at the integration boundary.
    Hook(TaskHookError),
    /// A validated typed hook outcome selected an operation-local failure.
    Operation(OperationFailureV1),
    /// Gantry could not validate or normalize an otherwise typed hook outcome.
    Outcome(HookOutcomeProcessingError),
    /// Fresh retry dispatch preparation failed after its recorded delay elapsed.
    Request(HookRequestError),
}

/// One logical operation from immutable capture through source-result acceptance.
pub struct OperationLifecycle {
    captured: Arc<CapturedOperationRequestV1>,
    state: OperationRuntimeState,
}

enum OperationRuntimeState {
    Absent,
    Prepared {
        dispatch: PreparedHookDispatch,
        validation_attempt: u64,
        recovery_dispatch: u64,
        retries_left: Option<u64>,
        retry_policy: Option<OperationRetryPolicyV1>,
    },
    Outcome {
        dispatch_id: ProtocolIdentity,
        outcome: HookOutcomeV1,
        validation_attempt: u64,
        recovery_dispatch: u64,
        retries_left: Option<u64>,
        retry_policy: Option<OperationRetryPolicyV1>,
    },
    Validated {
        dispatch_id: ProtocolIdentity,
        output: ValidatedHookOutputV1,
    },
    RetryWaiting {
        dispatch_id: ProtocolIdentity,
        wait: OperationRetryWaitV1,
        retry_policy: OperationRetryPolicyV1,
    },
    Accepted,
    Failed {
        dispatch_id: Option<ProtocolIdentity>,
        failure: OperationLifecycleFailureV1,
        attempt_consumed: bool,
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
            OperationRuntimeState::Prepared { dispatch, .. } => OperationLifecycleState::Prepared {
                dispatch_id: dispatch.dispatch_id,
            },
            OperationRuntimeState::Outcome { dispatch_id, .. }
            | OperationRuntimeState::Validated { dispatch_id, .. } => {
                OperationLifecycleState::Outcome {
                    dispatch_id: *dispatch_id,
                }
            }
            OperationRuntimeState::RetryWaiting { dispatch_id, .. } => {
                OperationLifecycleState::RetryWaiting {
                    dispatch_id: *dispatch_id,
                }
            }
            OperationRuntimeState::Accepted => OperationLifecycleState::Accepted,
            OperationRuntimeState::Failed { dispatch_id, .. } => OperationLifecycleState::Failed {
                dispatch_id: *dispatch_id,
            },
        }
    }

    /// Returns the exact typed hook outcome while validation is pending.
    #[must_use]
    pub fn outcome(&self) -> Option<&HookOutcomeV1> {
        match &self.state {
            OperationRuntimeState::Outcome { outcome, .. } => Some(outcome),
            _ => None,
        }
    }

    /// Returns the normalized output after all ordered validation stages succeed.
    #[must_use]
    pub fn validated_output(&self) -> Option<&ValidatedHookOutputV1> {
        match &self.state {
            OperationRuntimeState::Validated { output, .. } => Some(output),
            _ => None,
        }
    }

    /// Returns the recorded validation-repair wait before redispatch.
    #[must_use]
    pub fn retry_wait(&self) -> Option<&OperationRetryWaitV1> {
        match &self.state {
            OperationRuntimeState::RetryWaiting { wait, .. } => Some(wait),
            _ => None,
        }
    }

    /// Returns the retained integration failure after the operation fails.
    #[must_use]
    pub fn failure(&self) -> Option<&TaskHookError> {
        match &self.state {
            OperationRuntimeState::Failed {
                failure: OperationLifecycleFailureV1::Hook(error),
                ..
            } => Some(error),
            _ => None,
        }
    }

    /// Returns the complete retained terminal lifecycle failure.
    #[must_use]
    pub fn lifecycle_failure(&self) -> Option<&OperationLifecycleFailureV1> {
        match &self.state {
            OperationRuntimeState::Failed { failure, .. } => Some(failure),
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
        self.state = OperationRuntimeState::Prepared {
            dispatch,
            validation_attempt,
            recovery_dispatch,
            retries_left: None,
            retry_policy: None,
        };
        Ok(dispatch_id)
    }

    /// Lazily creates the task hook, dispatches serially, and retains one outcome.
    pub async fn dispatch(
        &mut self,
        hook: &mut TaskHook<'_>,
        cancellation: &dyn CancellationToken,
    ) -> Result<&HookOutcomeV1, OperationLifecycleError> {
        self.require_state(OperationStateKind::Prepared)?;
        let OperationRuntimeState::Prepared {
            dispatch: prepared,
            validation_attempt,
            recovery_dispatch,
            retries_left,
            retry_policy,
        } = &self.state
        else {
            unreachable!("state check preserves prepared dispatch")
        };
        let dispatch_id = prepared.dispatch_id;
        let request = prepared.request.clone();
        let validation_attempt = *validation_attempt;
        let recovery_dispatch = *recovery_dispatch;
        let retries_left = *retries_left;
        let retry_policy = *retry_policy;
        match hook.dispatch(request, cancellation).await {
            Ok(outcome) => {
                self.state = OperationRuntimeState::Outcome {
                    dispatch_id,
                    outcome,
                    validation_attempt,
                    recovery_dispatch,
                    retries_left,
                    retry_policy,
                };
                self.outcome()
                    .ok_or_else(|| invalid_state(OperationStateKind::Outcome))
            }
            Err(error) => {
                self.state = OperationRuntimeState::Failed {
                    dispatch_id: Some(dispatch_id),
                    failure: OperationLifecycleFailureV1::Hook(error.clone()),
                    attempt_consumed: false,
                };
                Err(OperationLifecycleError::Hook(error))
            }
        }
    }

    /// Validates one retained typed outcome and selects acceptance, retry, or failure.
    pub fn process_outcome(
        &mut self,
        policy: OperationRetryPolicyV1,
        executor: &dyn ExecutorAdapter,
        cancellation: &dyn CancellationToken,
    ) -> Result<ProcessedHookOutcomeV1, OperationLifecycleError> {
        self.require_state(OperationStateKind::Outcome)?;
        let OperationRuntimeState::Outcome {
            dispatch_id,
            outcome,
            validation_attempt,
            recovery_dispatch,
            retries_left,
            retry_policy,
        } = &self.state
        else {
            return Err(invalid_state(OperationStateKind::Outcome));
        };
        let dispatch_id = *dispatch_id;
        let outcome = outcome.clone();
        let validation_attempt = *validation_attempt;
        let recovery_dispatch = *recovery_dispatch;
        let policy = retry_policy.unwrap_or(policy);
        let retries_left = retries_left.unwrap_or(policy.retry_limit);
        let processed = match process_hook_outcome(
            &self.captured,
            &outcome,
            policy,
            validation_attempt,
            recovery_dispatch,
            retries_left,
            executor,
            cancellation.is_cancelled(),
        ) {
            Ok(processed) => processed,
            Err(error) => {
                self.state = OperationRuntimeState::Failed {
                    dispatch_id: Some(dispatch_id),
                    failure: OperationLifecycleFailureV1::Outcome(error.clone()),
                    attempt_consumed: false,
                };
                return Err(OperationLifecycleError::Outcome(error));
            }
        };
        self.state = match &processed {
            ProcessedHookOutcomeV1::Accepted(output) => OperationRuntimeState::Validated {
                dispatch_id,
                output: output.clone(),
            },
            ProcessedHookOutcomeV1::Retry(wait) => OperationRuntimeState::RetryWaiting {
                dispatch_id,
                wait: wait.clone(),
                retry_policy: policy,
            },
            ProcessedHookOutcomeV1::Failed(failure) => OperationRuntimeState::Failed {
                dispatch_id: Some(dispatch_id),
                failure: OperationLifecycleFailureV1::Operation(failure.clone()),
                attempt_consumed: false,
            },
        };
        Ok(processed)
    }

    /// Waits the recorded retry delay and prepares one fresh physical dispatch.
    ///
    /// `Ok(None)` means cancellation or executor failure became terminal while
    /// waiting. The immutable captured semantic request is reused verbatim.
    pub async fn prepare_after_retry_wait(
        &mut self,
        executor: &dyn ExecutorAdapter,
        cancellation: &CancellationSignal,
        allocator: &FreshIdentityAllocator,
        identity_source: &dyn IdentitySource,
    ) -> Result<Option<ProtocolIdentity>, OperationLifecycleError> {
        self.require_state(OperationStateKind::RetryWaiting)?;
        let OperationRuntimeState::RetryWaiting {
            dispatch_id,
            wait,
            retry_policy,
        } = &self.state
        else {
            unreachable!("state check preserves retry wait")
        };
        let dispatch_id = *dispatch_id;
        let wait = wait.clone();
        let retry_policy = *retry_policy;
        match wait_retry_delay(executor, wait.delay, cancellation).await {
            crate::RetryDelayOutcomeV1::Completed => {}
            crate::RetryDelayOutcomeV1::Cancelled => {
                self.state = OperationRuntimeState::Failed {
                    dispatch_id: Some(dispatch_id),
                    failure: OperationLifecycleFailureV1::Operation(
                        OperationFailureV1::TaskCancellation,
                    ),
                    attempt_consumed: false,
                };
                return Ok(None);
            }
            crate::RetryDelayOutcomeV1::Failed(error) => {
                self.state = OperationRuntimeState::Failed {
                    dispatch_id: Some(dispatch_id),
                    failure: OperationLifecycleFailureV1::Operation(OperationFailureV1::Executor(
                        error,
                    )),
                    attempt_consumed: false,
                };
                return Ok(None);
            }
        }
        let dispatch = match self.captured.prepare_dispatch(
            allocator,
            identity_source,
            wait.next_validation_attempt,
            wait.recovery_dispatch,
            &wait.errors,
        ) {
            Ok(dispatch) => dispatch,
            Err(error) => {
                self.state = OperationRuntimeState::Failed {
                    dispatch_id: Some(dispatch_id),
                    failure: OperationLifecycleFailureV1::Request(error.clone()),
                    attempt_consumed: false,
                };
                return Err(OperationLifecycleError::Request(error));
            }
        };
        let next_dispatch_id = dispatch.dispatch_id;
        self.state = OperationRuntimeState::Prepared {
            dispatch,
            validation_attempt: wait.next_validation_attempt,
            recovery_dispatch: wait.recovery_dispatch,
            retries_left: Some(wait.retries_left),
            retry_policy: Some(retry_policy),
        };
        Ok(Some(next_dispatch_id))
    }

    /// Makes one validated normalized result source-consumable in the machine.
    pub fn accept(
        &mut self,
        machine: &mut Machine,
        value: LogicalValue,
    ) -> Result<MachineLabel, OperationLifecycleError> {
        self.require_validated_value(&value)?;
        let operation = self.captured.header().operation_id;
        let label = machine
            .complete_operation(operation, value)
            .map_err(OperationLifecycleError::Completion)?;
        self.state = OperationRuntimeState::Accepted;
        Ok(label)
    }

    /// Wraps one validated successful operation as the `Ok` result of `attempt`.
    pub fn accept_attempt(
        &mut self,
        machine: &mut Machine,
        value: LogicalValue,
    ) -> Result<MachineLabel, OperationLifecycleError> {
        self.require_validated_value(&value)?;
        let attempted = LogicalValue::ok(value, self.captured.header().value_limits)
            .map_err(OperationLifecycleError::AttemptValue)?;
        let operation = self.captured.header().operation_id;
        let label = machine
            .complete_operation(operation, attempted)
            .map_err(OperationLifecycleError::Completion)?;
        self.state = OperationRuntimeState::Accepted;
        Ok(label)
    }

    /// Consumes one catchable terminal operation failure as `Err(OperationError)`.
    ///
    /// The lifecycle remains terminally failed for observability. The source
    /// result can enter the matching machine operation at most once.
    pub fn accept_attempt_failure(
        &mut self,
        machine: &mut Machine,
    ) -> Result<MachineLabel, OperationLifecycleError> {
        let OperationRuntimeState::Failed {
            failure: OperationLifecycleFailureV1::Operation(failure),
            attempt_consumed,
            ..
        } = &self.state
        else {
            return Err(OperationLifecycleError::AttemptNotCatchable);
        };
        if *attempt_consumed {
            return Err(OperationLifecycleError::AttemptResultConsumed);
        }
        let operation = self.captured.header().operation_id;
        let error = failure
            .attempt_value(&operation.to_string(), self.captured.header().value_limits)
            .map_err(OperationLifecycleError::AttemptValue)?
            .ok_or(OperationLifecycleError::AttemptNotCatchable)?;
        let attempted = LogicalValue::err(error, self.captured.header().value_limits)
            .map_err(OperationLifecycleError::AttemptValue)?;
        let label = machine
            .complete_operation(operation, attempted)
            .map_err(OperationLifecycleError::Completion)?;
        let OperationRuntimeState::Failed {
            attempt_consumed, ..
        } = &mut self.state
        else {
            unreachable!("attempted failure remains terminal")
        };
        *attempt_consumed = true;
        Ok(label)
    }

    /// Atomically appends one accepted model turn and makes its result source-consumable.
    ///
    /// The complete proposed transcript is validated first. The session is
    /// published only after the matching machine operation accepts the value.
    pub fn accept_model(
        &mut self,
        machine: &mut Machine,
        session: &mut LogicalSessionV1,
        turn: &TranscriptTurnV1,
        limits: gantry_core::value::ValueLimits,
        value: LogicalValue,
    ) -> Result<MachineLabel, OperationLifecycleError> {
        self.require_validated_value(&value)?;
        validate_model_acceptance(self.captured(), session, turn, &value)
            .map_err(OperationLifecycleError::Transcript)?;
        let mut proposed = session.transcript.clone();
        proposed
            .append(turn, limits)
            .map_err(OperationLifecycleError::Transcript)?;
        let operation = self.captured.header().operation_id;
        let label = machine
            .complete_operation(operation, value)
            .map_err(OperationLifecycleError::Completion)?;
        session.transcript = proposed;
        self.state = OperationRuntimeState::Accepted;
        Ok(label)
    }

    /// Atomically appends one accepted model turn and returns `Ok(value)` from `attempt`.
    pub fn accept_model_attempt(
        &mut self,
        machine: &mut Machine,
        session: &mut LogicalSessionV1,
        turn: &TranscriptTurnV1,
        limits: gantry_core::value::ValueLimits,
        value: LogicalValue,
    ) -> Result<MachineLabel, OperationLifecycleError> {
        self.require_validated_value(&value)?;
        validate_model_acceptance(self.captured(), session, turn, &value)
            .map_err(OperationLifecycleError::Transcript)?;
        let mut proposed = session.transcript.clone();
        proposed
            .append(turn, limits)
            .map_err(OperationLifecycleError::Transcript)?;
        let attempted = LogicalValue::ok(value, self.captured.header().value_limits)
            .map_err(OperationLifecycleError::AttemptValue)?;
        let operation = self.captured.header().operation_id;
        let label = machine
            .complete_operation(operation, attempted)
            .map_err(OperationLifecycleError::Completion)?;
        session.transcript = proposed;
        self.state = OperationRuntimeState::Accepted;
        Ok(label)
    }

    fn require_validated_value(&self, value: &LogicalValue) -> Result<(), OperationLifecycleError> {
        let OperationRuntimeState::Validated { output, .. } = &self.state else {
            return Err(invalid_state(self.state().kind()));
        };
        if value.canonical_json() == *output.canonical_json() {
            Ok(())
        } else {
            Err(OperationLifecycleError::InvalidAcceptedValue)
        }
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

fn validate_model_acceptance(
    captured: &CapturedOperationRequestV1,
    session: &LogicalSessionV1,
    turn: &TranscriptTurnV1,
    value: &LogicalValue,
) -> Result<(), TranscriptError> {
    let CapturedOperationRequestV1::Model { header, body } = captured else {
        return Err(TranscriptError::Invalid);
    };
    let expected_kind = match header.expected_type.kind() {
        gantry_ir::generated::TypeKind::Unit => TranscriptResultKindV1::Unit,
        gantry_ir::generated::TypeKind::Decision => TranscriptResultKindV1::Decision,
        _ => TranscriptResultKindV1::Value,
    };
    if session.execution_id != header.execution_id
        || session.id != body.active_session_id
        || session.parent != body.parent_session_id
        || session.root != body.root_session_id
        || session.transcript != body.transcript
        || turn.operation_kind != header.kind
        || turn.template_representation != body.template_segments
        || turn.rendered_prompt != body.rendered_prompt
        || turn.interpolation_inputs != body.interpolation_inputs
        || turn.using_inputs != body.named_inputs
        || turn.selected_agent != body.selected_agent
        || turn.accepted_result.kind != expected_kind
        || turn.accepted_result.ty != header.expected_type
        || turn.accepted_result.value != value.canonical_json()
    {
        return Err(TranscriptError::Invalid);
    }
    match (&body.session_use, session.establishment, session.mode) {
        (ModelSessionUseV1::Inline, _, _) => Ok(()),
        (
            ModelSessionUseV1::Create {
                mode,
                session_id,
                parent_session_id,
                root_session_id,
                ..
            },
            SessionEstablishmentV1::OperationRequest,
            session_mode,
        ) if *session_id == session.id
            && Some(*parent_session_id) == session.parent
            && *root_session_id == session.root
            && matches!(
                (mode.as_ref(), session_mode),
                ("new", SessionCreationModeV1::New) | ("fork", SessionCreationModeV1::Fork)
            ) =>
        {
            Ok(())
        }
        (ModelSessionUseV1::Create { .. }, _, _) => Err(TranscriptError::Invalid),
    }
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

    /// Establishes the active model session before lazy hook creation and dispatch.
    pub async fn dispatch_model(
        &mut self,
        request: HostRequest,
        cancellation: &dyn CancellationToken,
        establisher: &mut SessionEstablisher<'_>,
        execution_id: ProtocolIdentity,
        session: &LogicalSessionV1,
    ) -> Result<HookOutcomeV1, TaskHookSessionError> {
        require_request(&request, EmbeddingOperation::DispatchOperation)
            .map_err(TaskHookSessionError::Hook)?;
        establisher
            .establish(execution_id, session)
            .await
            .map_err(TaskHookSessionError::Session)?;
        self.dispatch(request, cancellation)
            .await
            .map_err(TaskHookSessionError::Hook)
    }

    /// Lazily creates the task hook and performs one serial operation dispatch.
    pub async fn dispatch(
        &mut self,
        request: HostRequest,
        cancellation: &dyn CancellationToken,
    ) -> Result<HookOutcomeV1, TaskHookError> {
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
        lifecycle
            .contain_adapter_future(future, poison)
            .await
            .map_err(TaskHookError::Boundary)?
            .map_err(TaskHookError::Host)
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use gantry_core::portable::{IdentityKind, JitterMode};
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
        OperationRequestHeaderV1, RequiredConfiguration, RetryDefaults, Workflow,
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

    #[derive(Default)]
    struct UniqueServices {
        next: AtomicUsize,
    }

    impl IdentitySource for UniqueServices {
        fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
            let value = self.next.fetch_add(1, Ordering::AcqRel).saturating_add(1);
            let mut material = [0_u8; 32];
            material[..8].copy_from_slice(&value.to_be_bytes());
            Ok(material)
        }
    }

    impl ExecutorAdapter for UniqueServices {
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
        ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
            assert_eq!(request.operation(), EmbeddingOperation::DispatchOperation);
            self.dispatches.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move { Ok(HookOutcomeV1::Completed(Arc::from(&b"null"[..]))) })
        }
    }

    struct ScriptedFactory {
        outcomes: Arc<Mutex<VecDeque<HookOutcomeV1>>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl HookFactory for ScriptedFactory {
        fn create_hook<'a>(
            &'a self,
            request: HostRequest,
        ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
            assert_eq!(request.operation(), EmbeddingOperation::CreateHook);
            let hook = ScriptedHook {
                outcomes: Arc::clone(&self.outcomes),
                requests: Arc::clone(&self.requests),
            };
            Box::pin(async move { Ok(Box::new(hook) as Box<dyn OperationHook>) })
        }
    }

    struct ScriptedHook {
        outcomes: Arc<Mutex<VecDeque<HookOutcomeV1>>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl OperationHook for ScriptedHook {
        fn dispatch<'a>(
            &'a mut self,
            request: HostRequest,
            _: &'a dyn CancellationToken,
        ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
            assert_eq!(request.operation(), EmbeddingOperation::DispatchOperation);
            self.requests
                .lock()
                .unwrap_or_else(|_| panic!("request recorder was poisoned"))
                .push(request.canonical_bytes().to_vec());
            let outcome = self
                .outcomes
                .lock()
                .unwrap_or_else(|_| panic!("outcome script was poisoned"))
                .pop_front()
                .unwrap_or_else(|| panic!("outcome script was exhausted"));
            Box::pin(async move { Ok(outcome) })
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

        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            RetryDefaults::default(),
            None,
        )
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
        assert!(matches!(
            operation.process_outcome(policy, &Services, &cancellation),
            Ok(ProcessedHookOutcomeV1::Accepted(_))
        ));

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
        let cancellation = CancellationSignal::default();
        assert!(block_on(operation.dispatch(&mut hook, &cancellation)).is_ok());
        let policy = OperationRetryPolicyV1::for_request(
            operation.captured(),
            RetryDefaults::default(),
            None,
        )
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
        assert!(matches!(
            operation.process_outcome(policy, &Services, &cancellation),
            Ok(ProcessedHookOutcomeV1::Accepted(_))
        ));

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

    #[test]
    fn attempt_consumes_success_or_catchable_failure_exactly_once() {
        let attempted_type =
            TypeDescriptor::result(TypeDescriptor::UNIT, TypeDescriptor::OPERATION_ERROR);
        let (mut success_machine, success_occurrence) =
            machine_with_operation_type(attempted_type.clone());
        let mut success = operation_lifecycle(&success_occurrence);
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
        let cancellation = CancellationSignal::default();
        success
            .prepare(&FreshIdentityAllocator::default(), &Services, 0, 0, &[])
            .unwrap_or_else(|error| panic!("success preparation failed: {error:?}"));
        assert!(block_on(success.dispatch(&mut hook, &cancellation)).is_ok());
        let success_policy =
            OperationRetryPolicyV1::for_request(success.captured(), RetryDefaults::default(), None)
                .unwrap_or_else(|error| panic!("success policy failed: {error:?}"));
        assert!(matches!(
            success.process_outcome(success_policy, &Services, &cancellation),
            Ok(ProcessedHookOutcomeV1::Accepted(_))
        ));
        assert!(
            success
                .accept_attempt(&mut success_machine, LogicalValue::unit())
                .is_ok()
        );
        assert_eq!(
            success.accept_attempt(&mut success_machine, LogicalValue::unit()),
            Err(OperationLifecycleError::InvalidState {
                actual: OperationStateKind::Accepted,
            })
        );

        let (mut failure_machine, failure_occurrence) =
            machine_with_operation_type(attempted_type.clone());
        let mut failure = operation_lifecycle(&failure_occurrence);
        failure.state = OperationRuntimeState::Failed {
            dispatch_id: None,
            failure: OperationLifecycleFailureV1::Operation(OperationFailureV1::Declined(
                Arc::from("not available"),
            )),
            attempt_consumed: false,
        };
        assert!(failure.accept_attempt_failure(&mut failure_machine).is_ok());
        assert_eq!(failure.state().kind(), OperationStateKind::Failed);
        assert_eq!(
            failure.accept_attempt_failure(&mut failure_machine),
            Err(OperationLifecycleError::AttemptResultConsumed)
        );

        let (mut cancelled_machine, cancelled_occurrence) =
            machine_with_operation_type(attempted_type);
        let mut cancelled = operation_lifecycle(&cancelled_occurrence);
        cancelled.state = OperationRuntimeState::Failed {
            dispatch_id: None,
            failure: OperationLifecycleFailureV1::Operation(OperationFailureV1::TaskCancellation),
            attempt_consumed: false,
        };
        assert_eq!(
            cancelled.accept_attempt_failure(&mut cancelled_machine),
            Err(OperationLifecycleError::AttemptNotCatchable)
        );
        assert_eq!(
            cancelled_machine.status(),
            crate::MachineStatus::WaitingOperation
        );
    }

    #[test]
    fn structured_output_retry_reuses_capture_and_prepares_a_fresh_dispatch() {
        let configuration = configuration();
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let outcomes = Arc::new(Mutex::new(VecDeque::from([
            HookOutcomeV1::Completed(Arc::from(&b"true"[..])),
            HookOutcomeV1::Completed(Arc::from(&b"null"[..])),
        ])));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let factory = ScriptedFactory {
            outcomes,
            requests: Arc::clone(&requests),
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
        let allocator = FreshIdentityAllocator::default();
        let services = UniqueServices::default();
        let cancellation = CancellationSignal::default();
        let first_dispatch = operation
            .prepare(&allocator, &services, 0, 0, &[])
            .unwrap_or_else(|error| panic!("initial preparation failed: {error:?}"));
        assert!(block_on(operation.dispatch(&mut hook, &cancellation)).is_ok());
        let policy = OperationRetryPolicyV1 {
            retry_limit: 1,
            initial_delay: DurationMicros::new(0).unwrap_or_else(|| unreachable!()),
            cap: DurationMicros::new(0).unwrap_or_else(|| unreachable!()),
            jitter: JitterMode::None,
        };
        assert!(matches!(
            operation.process_outcome(policy, &services, &cancellation),
            Ok(ProcessedHookOutcomeV1::Retry(ref wait))
                if wait.next_validation_attempt == 1
                    && wait.recovery_dispatch == 0
                    && wait.retries_left == 0
                    && wait.errors[0].category == crate::ValidationErrorCategoryV1::Schema
        ));
        assert_eq!(operation.state().kind(), OperationStateKind::RetryWaiting);

        let second_dispatch = block_on(operation.prepare_after_retry_wait(
            &services,
            &cancellation,
            &allocator,
            &services,
        ))
        .unwrap_or_else(|error| panic!("retry preparation failed: {error:?}"))
        .unwrap_or_else(|| panic!("retry preparation became terminal"));
        assert_ne!(first_dispatch, second_dispatch);
        assert!(block_on(operation.dispatch(&mut hook, &cancellation)).is_ok());
        assert!(matches!(
            operation.process_outcome(policy, &services, &cancellation),
            Ok(ProcessedHookOutcomeV1::Accepted(_))
        ));
        assert!(operation.accept(&mut machine, LogicalValue::unit()).is_ok());

        let requests = requests
            .lock()
            .unwrap_or_else(|_| panic!("request recorder was poisoned"));
        assert_eq!(requests.len(), 2);
        let first = std::str::from_utf8(&requests[0])
            .unwrap_or_else(|error| panic!("initial request was not UTF-8: {error}"));
        let second = std::str::from_utf8(&requests[1])
            .unwrap_or_else(|error| panic!("retry request was not UTF-8: {error}"));
        assert!(first.contains("\"validation_attempt\":0"));
        assert!(!first.contains("validation_errors"));
        assert!(second.contains("\"validation_attempt\":1"));
        assert!(second.contains("\"validation_errors\":"));
        assert!(!second.contains("true"));
        for retained in [
            "\"canonical_path\":\"crate::noop\"",
            "\"action_mapping_revision\":\"actions-v1\"",
            "\"recovery_class\":\"read_only\"",
            "\"recovery_dispatch\":0",
        ] {
            assert!(first.contains(retained));
            assert!(second.contains(retained));
        }
    }

    fn machine_with_operation() -> (Machine, crate::OperationOccurrence) {
        machine_with_operation_type(TypeDescriptor::UNIT)
    }

    fn machine_with_operation_type(
        expected_type: TypeDescriptor,
    ) -> (Machine, crate::OperationOccurrence) {
        let workflow_path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("workflow path failed: {error}"));
        let site = StructuralPosition::new(vec![0])
            .unwrap_or_else(|error| panic!("operation site failed: {error}"));
        let program = MachineProgram::new(vec![Workflow {
            path: workflow_path.clone(),
            parameters: Vec::new(),
            result: expected_type.clone(),
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site,
                    ty: expected_type.clone(),
                    kind: InstructionKind::Operation,
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("return site failed: {error}")),
                    ty: expected_type,
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
