//! Task-neutral explicit-frame execution for analyzed Gantry programs.
//!
//! This crate owns the one deterministic machine later refined by concurrent
//! scheduling and durable recovery. It contains no host orchestration,
//! executor implementation, hook transport, or journal backend.

mod configuration;
mod containment;
mod hook_request;
mod lifecycle;
mod machine;
mod operation;
mod primitive;
mod program;

pub use configuration::{
    ConfigurationError, ConfigurationErrorKind, InterpreterConfiguration, RequiredConfiguration,
    RetryDefaults,
};
pub use containment::{
    AdapterPoison, BoundaryFailure, PanicOrigin, catch_gantry, catch_integration,
    contain_gantry_future, contain_integration_future, drop_integration,
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
    LifecycleCode, LifecycleError, LifecycleSnapshot, OperationAdmission, ShutdownAdmission,
    ShutdownCompletionError, ShutdownCoordinator, ShutdownDurations, ShutdownProgress,
    ShutdownReport, ShutdownWait,
};
pub use machine::{
    Machine, MachineBuildError, MachineFailure, MachineLabel, MachineLimits, MachineOutcome,
    MachineStatus, MachineStep, OperationCompletionError, OperationOccurrence, RuntimeCode,
};
pub use operation::{
    OperationLifecycle, OperationLifecycleError, OperationLifecycleState, TaskHook, TaskHookError,
};
pub use primitive::{Comparison, Primitive};
pub use program::{
    AggregateKind, Instruction, InstructionKind, LoopPhase, MachineProgram, Parameter,
    ProgramError, Projection, Workflow,
};

#[cfg(test)]
mod tests;
