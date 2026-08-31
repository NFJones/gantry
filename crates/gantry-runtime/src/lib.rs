//! Task-neutral explicit-frame execution for analyzed Gantry programs.
//!
//! This crate owns the one deterministic machine later refined by concurrent
//! scheduling and durable recovery. It contains no host orchestration,
//! executor implementation, hook transport, or journal backend.

mod configuration;
mod containment;
mod event;
mod hook_request;
mod lifecycle;
mod machine;
mod operation;
mod outcome;
mod session;

pub use configuration::{
    ConfigurationError, ConfigurationErrorKind, InterpreterConfiguration, RequiredConfiguration,
    RetryDefaults,
};
pub use containment::{
    AdapterPoison, BoundaryFailure, PanicOrigin, catch_gantry, catch_integration,
    contain_gantry_future, contain_integration_future, drop_integration,
};
pub use event::{
    BranchConditionV1, ExecutionDeliveryConsequenceV1, ExecutionEventDraftV1, ExecutionEventError,
    ExecutionEventOutcomeV1, ExecutionEventPipeline, OperationEventDraftError,
    OperationResultEventKindV1, ShutdownEventSummaryV1, WorkflowEventPhaseV1,
    branch_decision_event, machine_lifecycle_event, mutation_event, operation_completion_event,
    operation_dispatch_event, operation_result_event, report_emergency_diagnostic, shutdown_event,
    structured_output_validation_failure_event, validation_retry_event, workflow_event,
};
pub use gantry_ir::Comparison;
pub use gantry_ir::{
    AggregateKind, Instruction, InstructionKind, LoopPhase, MachineProgram, Parameter, Primitive,
    ProgramError, Projection, Workflow,
};
pub use hook_request::{
    ActionOperationRequestV1, CapturedOperationRequestV1, HookRequestError, InterpolationInputV1,
    ModelOperationRequestV1, ModelSessionUseV1, NamedInputV1, OperationRequestHeaderV1,
    PreparedHookDispatch, RootSessionProvenanceV1, TaskContextV1, TaskSessionContextV1,
    TypedActionArgumentV1, ValidationErrorCategoryV1, ValidationErrorV1,
};
pub use lifecycle::{
    AcceptExecutionError, AdmissionKind, CancellationCausalIdentity, CancellationReason,
    CancellationReasonError, CancellationRecord, ExecutionHandle, ExecutionSnapshot,
    ExecutionTransitionError, ExecutionWait, FinalShutdownEventSettlement, InterpreterLifecycle,
    LifecycleCode, LifecycleError, LifecycleSnapshot, OperationAdmission, RequiredDeliveryRecordV1,
    RequiredEventDeliveryFailureV1, ShutdownAdmission, ShutdownCompletionError,
    ShutdownCoordinator, ShutdownDurations, ShutdownProgress, ShutdownReport, ShutdownWait,
};
pub use machine::{
    Machine, MachineBuildError, MachineFailure, MachineLabel, MachineLimits, MachineOutcome,
    MachineStatus, MachineStep, OperationCompletionError, OperationOccurrence, RuntimeCode,
    SessionScopeCompletionError, SessionScopeOccurrence,
};
pub use operation::{
    OperationLifecycle, OperationLifecycleError, OperationLifecycleFailureV1,
    OperationLifecycleState, TaskHook, TaskHookError, TaskHookSessionError,
};
pub use outcome::{
    HookOutcomeProcessingError, OperationFailureV1, OperationRetryPolicyV1, OperationRetryWaitV1,
    ProcessedHookOutcomeV1, RetryDelayOutcomeV1, RetryPolicyError, ValidatedHookOutputV1,
    process_hook_outcome, wait_retry_delay,
};
pub use session::{
    AcceptedTranscriptResultV1, CanonicalTranscriptV1, LogicalSessionRegistryV1, LogicalSessionV1,
    SessionCreationModeV1, SessionError, SessionEstablisher, SessionEstablishmentError,
    SessionEstablishmentV1, TranscriptError, TranscriptResultKindV1, TranscriptTurnV1,
};

#[cfg(test)]
mod tests;
