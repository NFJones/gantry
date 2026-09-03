//! Deliberate public composition of package admission, the shared machine, and lifecycle control.
//!
//! The facade owns orchestration only. Source analysis, machine transitions,
//! cancellation, waits, and shutdown remain in their existing subsystem owners.

use std::sync::Arc;

use gantry_analysis::{DeclaredValueShape, DeclaredValueShapes};
use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{
    CancellationReasonCategory, DeterministicEvaluationCode, IdentityKind, RuntimeErrorCategory,
};
use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_core::value::{LogicalValue, OperationErrorValue, ValueLimits};
use gantry_host::contracts::{
    CancellationToken, FreshIdentityAllocator, HookFactory, IntegrationPreflight,
    RuntimeSessionService, UtcClock,
};
use gantry_ir::TypeDescriptor;
use gantry_ir::generated::{OperationSiteKind, TypeKind};
use gantry_runtime::{
    AcceptedTranscriptResultV1, ActionOperationRequestV1, AdapterPoison, CancellationReason,
    CancellationRecord, CapturedOperationRequestV1, ExecutionHandle, ExecutionSnapshot,
    FinalShutdownEventSettlement, InterpolationInputV1, InterpreterConfiguration,
    InterpreterLifecycle, LifecycleError, LogicalSessionRegistryV1, Machine, MachineBuildError,
    MachineFailure, MachineLabel, MachineOutcome, MachineStep, ModelOperationRequestV1,
    ModelSessionUseV1, NamedInputV1, OperationLifecycle, OperationLifecycleError,
    OperationLifecycleFailureV1, OperationRequestHeaderV1, OperationRetryPolicyV1,
    ProcessedHookOutcomeV1, RootSessionProvenanceV1, RuntimeCode, SessionCreationModeV1,
    SessionEstablisher, SessionEstablishmentV1, ShutdownCompletionError, ShutdownReport,
    TaskContextV1, TaskHook, TaskHookError, TaskSessionContextV1, TranscriptResultKindV1,
    TranscriptTurnV1, TypedActionArgumentV1,
};

use crate::{
    AnalyzePackageCoordinator, StartExecutionAccepted, StartExecutionCoordinator,
    StartExecutionRequest, StartExecutionResult,
};

/// Supported nondurable interpreter facade over injected host integrations.
pub struct Interpreter {
    configuration: InterpreterConfiguration,
    lifecycle: InterpreterLifecycle,
    allocator: FreshIdentityAllocator,
    clock: Arc<dyn UtcClock>,
    preflight: Arc<dyn IntegrationPreflight>,
    session_establisher: SessionEstablisher,
    hook_factory: Arc<dyn HookFactory>,
}

impl std::fmt::Debug for Interpreter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Interpreter")
            .field("configuration", &self.configuration)
            .field("lifecycle", &self.lifecycle)
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
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let session_establisher = SessionEstablisher::new(
            lifecycle.task_supervisor(),
            runtime_sessions,
            AdapterPoison::default(),
        );
        Self {
            configuration,
            lifecycle,
            allocator: FreshIdentityAllocator::default(),
            clock,
            preflight,
            session_establisher,
            hook_factory,
        }
    }

    /// Runs ordered nondurable preflight and returns the exact accepted/rejected start union.
    pub async fn start_execution(
        &self,
        request: StartExecutionRequest<'_>,
    ) -> StartExecutionResult {
        let package = AnalyzePackageCoordinator::new(
            &self.allocator,
            self.configuration.identity_source(),
            self.clock.as_ref(),
        );
        StartExecutionCoordinator::new(
            &package,
            &self.lifecycle,
            &self.configuration,
            &self.allocator,
            Arc::clone(&self.preflight),
        )
        .start(request)
        .await
    }

    /// Drives one accepted sequential execution through the shared machine.
    pub async fn run_execution(
        &self,
        accepted: StartExecutionAccepted,
    ) -> Result<ExecutionSnapshot, RunExecutionError> {
        let analysis = accepted
            .package_activity
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
        let arguments = accepted
            .entry_input
            .as_ref()
            .map(|input| {
                decode_logical_value(
                    input.canonical_json.bytes(),
                    &input.ty,
                    self.configuration.required().value_limits,
                    analysis.declared_value_shapes(),
                )
                .map(|value| vec![value])
            })
            .transpose()?
            .unwrap_or_default();
        let initial_agent = analysis.structure().default_agent().map(Arc::from);
        let initial_session = Some(accepted.root_session.id);
        let mut machine = match Machine::new_with_context(
            Arc::new(program),
            &entry.path,
            arguments,
            accepted.execution_id,
            self.configuration.machine_limits(),
            initial_agent.clone(),
            initial_session,
        ) {
            Ok(machine) => machine,
            Err(error) => {
                let failure = build_failure(&entry.path, &error);
                self.fix_failed_execution(&accepted, failure.clone())?;
                return Err(RunExecutionError::MachineBuild(error));
            }
        };
        let cancellation = accepted
            .handle
            .cancellation_signal()
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        let task_id = root_task_identity(accepted.execution_id);
        let create_request = TaskContextV1 {
            execution_id: accepted.execution_id,
            task_id,
            inherited_agent: initial_agent,
            session: TaskSessionContextV1::Root {
                root_session_id: accepted.root_session.id,
                provenance: match accepted.root_session.provenance {
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
        let mut hook = TaskHook::new(
            &self.lifecycle,
            self.hook_factory.as_ref(),
            AdapterPoison::default(),
            create_request,
        )
        .map_err(RunExecutionError::TaskHook)?;
        let root_mode = match accepted.root_session.provenance {
            crate::RootSessionProvenance::EmbedderSupplied => SessionCreationModeV1::EmbedderRoot,
            crate::RootSessionProvenance::GantryCreated => SessionCreationModeV1::GantryRoot,
        };
        let mut sessions = LogicalSessionRegistryV1::new(
            accepted.execution_id,
            accepted.root_session.id,
            root_mode,
            accepted.root_session.transcript.clone(),
        )
        .map_err(RunExecutionError::Session)?;
        let session_establisher = self.session_establisher.clone();
        let mut model_session_occurrence = 0_u64;
        let mut foreground_fixed = false;
        let mut terminal_fixed = false;

        loop {
            if cancellation.is_cancelled() && machine.outcome().is_none() {
                let reason = self
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
                    );
                let _ = machine.cancel(reason);
            }
            match machine.step() {
                MachineStep::Transition(MachineLabel::ForegroundCompletion(outcome)) => {
                    if !foreground_fixed {
                        self.lifecycle
                            .complete_foreground(&accepted.handle, outcome)
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                        foreground_fixed = true;
                    }
                }
                MachineStep::Transition(MachineLabel::TerminalCompletion(outcome)) => {
                    if !terminal_fixed {
                        self.lifecycle
                            .complete_terminal(&accepted.handle, outcome)
                            .map_err(|_| RunExecutionError::LifecycleTransition)?;
                        terminal_fixed = true;
                    }
                }
                MachineStep::Transition(_) => {}
                MachineStep::WaitingSessionScope(scope) => {
                    let parent = sessions
                        .get(scope.parent_session_id)
                        .cloned()
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
                    let child = sessions
                        .create(
                            scope.parent_session_id,
                            task_id,
                            scope.site.clone(),
                            scope.occurrence,
                            scope.mode,
                            SessionEstablishmentV1::Separate,
                        )
                        .map_err(RunExecutionError::Session)?
                        .clone();
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
                    if self.configuration.executor().yield_now().await.is_err() {
                        let failure = MachineFailure {
                            code: RuntimeCode::InternalInvariant,
                            workflow: entry.path.clone(),
                            site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                        };
                        self.fix_failed_execution(&accepted, failure)?;
                        return Err(RunExecutionError::ExecutorFailure);
                    }
                    if !machine.resume_after_yield() {
                        return Err(RunExecutionError::LifecycleTransition);
                    }
                }
                MachineStep::WaitingOperation(operation) => {
                    let Some(metadata) = operation.metadata.as_ref() else {
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
                                &mut hook,
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
                                &mut hook,
                                &cancellation,
                                &operation,
                                &mut sessions,
                                &session_establisher,
                                model_session_occurrence,
                            )
                            .await?;
                            model_session_occurrence = model_session_occurrence.saturating_add(1);
                        }
                    }
                }
                MachineStep::Complete(_) => {
                    return self
                        .lifecycle
                        .query_execution(accepted.execution_id)
                        .map_err(RunExecutionError::Lifecycle)?
                        .ok_or(RunExecutionError::ExecutionNotFound);
                }
            }
        }
    }

    /// Returns one point-in-time snapshot for an accepted execution identity.
    pub fn query_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        self.lifecycle.query_execution(execution_id)
    }

    /// Waits independently for the foreground coordinate of one in-process handle.
    pub async fn await_foreground(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        Ok(self
            .lifecycle
            .await_foreground(handle.execution_id())?
            .await)
    }

    /// Waits independently for the terminal coordinate of one in-process handle.
    pub async fn await_terminal(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<Option<ExecutionSnapshot>, LifecycleError> {
        Ok(self.lifecycle.await_terminal(handle.execution_id())?.await)
    }

    /// Records the first effective cancellation reason and waits for terminal settlement.
    pub async fn cancel_execution(
        &self,
        execution_id: ProtocolIdentity,
        reason: CancellationReason,
    ) -> Result<CancellationRecord, LifecycleError> {
        let record = self.lifecycle.cancel_execution(execution_id, reason)?;
        if matches!(
            record,
            CancellationRecord::Accepted { .. } | CancellationRecord::Existing { .. }
        ) {
            let _ = self.lifecycle.await_terminal(execution_id)?.await;
        }
        Ok(record)
    }

    /// Runs or joins the unique shutdown coordinator and returns its immutable report.
    pub async fn shutdown(&self) -> Result<Arc<ShutdownReport>, ShutdownError> {
        let mut admission = self
            .lifecycle
            .begin_shutdown(None, None)
            .map_err(ShutdownError::Lifecycle)?;
        if let Some(coordinator) = admission.coordinator.take() {
            let _ = coordinator.cancel_remaining();
            coordinator.wait_for_quiescence().await;
            coordinator
                .complete(true, FinalShutdownEventSettlement::Settled)
                .map_err(ShutdownError::Completion)?;
        }
        Ok(admission.wait.await)
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
                task_id: root_task_identity(accepted.execution_id),
                operation_id: occurrence.identity,
                kind: metadata.kind,
                expected_type: metadata.result_type.clone(),
                expected_schema,
                maximum_hook_output_bytes: self.configuration.required().maximum_hook_output_bytes,
                value_limits: self.configuration.required().value_limits,
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
            self.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| RunExecutionError::RetryPolicy)?;
        operation
            .prepare(
                &self.allocator,
                self.configuration.identity_source(),
                0,
                0,
                &[],
            )
            .map_err(RunExecutionError::OperationLifecycle)?;
        loop {
            if let Err(error) = operation.dispatch(hook, cancellation).await {
                machine
                    .fail_operation(occurrence.identity, RuntimeErrorCategory::HookFailure)
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return match error {
                    OperationLifecycleError::Hook(_) => Ok(()),
                    other => Err(RunExecutionError::OperationLifecycle(other)),
                };
            }
            match operation
                .process_outcome(policy, self.configuration.executor(), cancellation)
                .map_err(RunExecutionError::OperationLifecycle)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let value = decode_logical_value(
                        output.canonical_json().bytes(),
                        &metadata.result_type,
                        self.configuration.required().value_limits,
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
                            self.configuration.executor(),
                            &accepted
                                .handle
                                .cancellation_signal()
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            &self.allocator,
                            self.configuration.identity_source(),
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
        sessions: &mut LogicalSessionRegistryV1,
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
        let task_id = root_task_identity(accepted.execution_id);
        let active_session_id = if let Some(mode) = metadata.session_mode.as_deref() {
            let mode = match mode {
                "fork" => SessionCreationModeV1::Fork,
                "new" => SessionCreationModeV1::New,
                _ => return Err(RunExecutionError::MissingOperationMetadata),
            };
            sessions
                .create(
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
        let session = sessions
            .get(active_session_id)
            .cloned()
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
            self.configuration
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
                maximum_hook_output_bytes: self.configuration.required().maximum_hook_output_bytes,
                value_limits: self.configuration.required().value_limits,
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
            self.configuration.retry_defaults(),
            metadata.retry_limit,
        )
        .map_err(|_| RunExecutionError::RetryPolicy)?;
        operation
            .prepare(
                &self.allocator,
                self.configuration.identity_source(),
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
                    OperationLifecycleError::Hook(_) => RuntimeErrorCategory::HookFailure,
                    other => return Err(RunExecutionError::OperationLifecycle(other)),
                };
                machine
                    .fail_operation(occurrence.identity, category)
                    .map_err(|_| RunExecutionError::LifecycleTransition)?;
                return Ok(());
            }
            match operation
                .process_outcome(policy, self.configuration.executor(), cancellation)
                .map_err(RunExecutionError::OperationLifecycle)?
            {
                ProcessedHookOutcomeV1::Accepted(output) => {
                    let value = decode_logical_value(
                        output.canonical_json().bytes(),
                        &metadata.result_type,
                        self.configuration.required().value_limits,
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
                    let session = sessions
                        .get_mut(active_session_id)
                        .ok_or(RunExecutionError::MissingLogicalSession)?;
                    let accepted_result = if metadata.attempted {
                        operation.accept_model_attempt(
                            machine,
                            session,
                            &turn,
                            self.configuration.required().value_limits,
                            value,
                        )
                    } else {
                        operation.accept_model(
                            machine,
                            session,
                            &turn,
                            self.configuration.required().value_limits,
                            value,
                        )
                    };
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
                            self.configuration.executor(),
                            &accepted
                                .handle
                                .cancellation_signal()
                                .map_err(|_| RunExecutionError::LifecycleTransition)?,
                            &self.allocator,
                            self.configuration.identity_source(),
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
        self.lifecycle
            .complete_foreground(&accepted.handle, outcome.clone())
            .map_err(|_| RunExecutionError::LifecycleTransition)?;
        self.lifecycle
            .complete_terminal(&accepted.handle, outcome)
            .map_err(|_| RunExecutionError::LifecycleTransition)
    }
}

/// Failure while driving an already accepted nondurable execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunExecutionError {
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
    /// A lifecycle transition contradicted accepted execution state.
    LifecycleTransition,
    /// A lifecycle public operation failed.
    Lifecycle(LifecycleError),
    /// Accepted execution state disappeared before observation.
    ExecutionNotFound,
}

/// Failure while coordinating interpreter shutdown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShutdownError {
    /// Shutdown admission failed at the lifecycle boundary.
    Lifecycle(LifecycleError),
    /// The unique coordinator could not publish the report.
    Completion(ShutdownCompletionError),
}

fn build_failure(root: &gantry_ir::CanonicalPath, error: &MachineBuildError) -> MachineFailure {
    let code = match error {
        MachineBuildError::UnsupportedEffect(_) => RuntimeCode::UnsupportedEffect,
        MachineBuildError::MissingRoot
        | MachineBuildError::ArgumentCount
        | MachineBuildError::ArgumentType
        | MachineBuildError::InvalidExecutionIdentity
        | MachineBuildError::InvalidSessionIdentity
        | MachineBuildError::Value(_) => RuntimeCode::InternalInvariant,
    };
    MachineFailure {
        code,
        workflow: root.clone(),
        site: gantry_ir::StructuralPosition::new(vec![u64::MAX])
            .unwrap_or_else(|_| unreachable!("constant position is valid")),
    }
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
    ProtocolIdentity::derive(
        IdentityKind::Task,
        format!("root-task:{execution_id}").as_bytes(),
    )
    .unwrap_or_else(|_| unreachable!("typed root task identity derivation is valid"))
}
