//! Validated interpreter configuration and normative v1 defaults.

use std::fmt;
use std::sync::Arc;

use gantry_core::portable::{ConfigurationField, JitterMode, MAXIMUM_DIRECTIVE_INTEGER};
use gantry_core::source::FrontendLimits;
use gantry_core::value::ValueLimits;
use gantry_host::contracts::{DurationMicros, ExecutorAdapter, IdentitySource};

use crate::MachineLimits;
use crate::admission::{AdmissionClass, AsyncAdmission};

const MAXIMUM_LENGTH: u64 = 9_007_199_254_740_991;

/// Normative default structured-output and event-delivery retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryDefaults {
    /// Model-output retries after the initial dispatch.
    pub model_retry_limit: u64,
    /// Action-output retries after the initial dispatch.
    pub action_retry_limit: u64,
    /// Initial exponential-backoff ceiling in whole microseconds.
    pub backoff_initial: DurationMicros,
    /// Saturating exponential-backoff cap in whole microseconds.
    pub backoff_cap: DurationMicros,
    /// Exact closed jitter mode.
    pub jitter: JitterMode,
    /// Event-delivery retries after the initial attempt.
    pub event_delivery_retry_limit: u64,
    /// Finite positive timeout for one event-delivery attempt.
    pub event_delivery_attempt_timeout: DurationMicros,
}

impl Default for RetryDefaults {
    fn default() -> Self {
        Self {
            model_retry_limit: 2,
            action_retry_limit: 0,
            backoff_initial: duration(100_000),
            backoff_cap: duration(2_000_000),
            jitter: JitterMode::Full,
            event_delivery_retry_limit: 3,
            event_delivery_attempt_timeout: duration(30_000_000),
        }
    }
}

impl RetryDefaults {
    /// Validates replacement defaults against the portable configuration bounds.
    pub fn new(
        model_retry_limit: u64,
        action_retry_limit: u64,
        backoff_initial_us: u64,
        backoff_cap_us: u64,
        jitter: JitterMode,
        event_delivery_retry_limit: u64,
        event_delivery_attempt_timeout_us: u64,
    ) -> Result<Self, ConfigurationError> {
        check(
            ConfigurationField::ModelRetryLimit,
            model_retry_limit,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        check(
            ConfigurationField::ActionRetryLimit,
            action_retry_limit,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        check(
            ConfigurationField::RetryBackoffInitialUs,
            backoff_initial_us,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        check(
            ConfigurationField::RetryBackoffCapUs,
            backoff_cap_us,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        check(
            ConfigurationField::EventDeliveryRetryLimit,
            event_delivery_retry_limit,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        check(
            ConfigurationField::EventDeliveryAttemptTimeoutUs,
            event_delivery_attempt_timeout_us,
            false,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        Ok(Self {
            model_retry_limit,
            action_retry_limit,
            backoff_initial: duration(backoff_initial_us),
            backoff_cap: duration(backoff_cap_us),
            jitter,
            event_delivery_retry_limit,
            event_delivery_attempt_timeout: duration(event_delivery_attempt_timeout_us),
        })
    }
}

/// Positive implementation-selected limits for fields with no normative v1 default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredConfiguration {
    /// Activity-local frontend policy.
    pub frontend_limits: FrontendLimits,
    /// Raw entry-input byte limit.
    pub maximum_entry_input_bytes: u64,
    /// Raw hook-output byte limit.
    pub maximum_hook_output_bytes: u64,
    /// Logical value limits.
    pub value_limits: ValueLimits,
    /// Deterministic transitions admitted for one execution.
    pub maximum_deterministic_transitions_per_execution: u64,
    /// Logical operation preparations admitted for one execution.
    pub maximum_operations_per_execution: u64,
    /// Loop body entries admitted for one task.
    pub maximum_loop_iterations_per_task: u64,
    /// Consecutive deterministic transitions before a cooperative yield.
    pub deterministic_transition_yield_quantum: u64,
}

impl RequiredConfiguration {
    /// Validates every implementation-selected field against its exact maximum.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        frontend_limits: FrontendLimits,
        maximum_entry_input_bytes: u64,
        maximum_hook_output_bytes: u64,
        value_limits: ValueLimits,
        maximum_deterministic_transitions_per_execution: u64,
        maximum_operations_per_execution: u64,
        maximum_loop_iterations_per_task: u64,
        deterministic_transition_yield_quantum: u64,
    ) -> Result<Self, ConfigurationError> {
        for (field, value) in [
            (
                ConfigurationField::MaximumEntryInputBytes,
                maximum_entry_input_bytes,
            ),
            (
                ConfigurationField::MaximumHookOutputBytes,
                maximum_hook_output_bytes,
            ),
            (
                ConfigurationField::MaximumValueNestingDepth,
                value_limits.maximum_nesting_depth(),
            ),
            (
                ConfigurationField::MaximumValueNodes,
                value_limits.maximum_nodes(),
            ),
            (
                ConfigurationField::MaximumDeterministicTransitionsPerExecution,
                maximum_deterministic_transitions_per_execution,
            ),
            (
                ConfigurationField::MaximumOperationsPerExecution,
                maximum_operations_per_execution,
            ),
            (
                ConfigurationField::MaximumLoopIterationsPerTask,
                maximum_loop_iterations_per_task,
            ),
            (
                ConfigurationField::DeterministicTransitionYieldQuantum,
                deterministic_transition_yield_quantum,
            ),
        ] {
            check(field, value, false, MAXIMUM_DIRECTIVE_INTEGER)?;
        }
        check(
            ConfigurationField::MaximumStringScalars,
            value_limits.maximum_string_scalars(),
            false,
            MAXIMUM_LENGTH,
        )?;
        check(
            ConfigurationField::MaximumListItems,
            value_limits.maximum_list_items(),
            false,
            MAXIMUM_LENGTH,
        )?;
        Ok(Self {
            frontend_limits,
            maximum_entry_input_bytes,
            maximum_hook_output_bytes,
            value_limits,
            maximum_deterministic_transitions_per_execution,
            maximum_operations_per_execution,
            maximum_loop_iterations_per_task,
            deterministic_transition_yield_quantum,
        })
    }
}

/// Positive operational capacities excluded from durable execution identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsyncCapacityLimits {
    /// Root drivers across executions.
    maximum_active_root_tasks: u64,
    /// Source-created child drivers across executions.
    maximum_active_source_child_tasks: u64,
    /// Runnable drivers reconstructed by one or more resume activities.
    maximum_resume_runnable_tasks: u64,
    /// Admitted public-operation activities.
    maximum_admitted_public_activities: u64,
    /// Interpreter-owned background tasks.
    maximum_interpreter_background_tasks: u64,
    /// Blocking jobs retained in the bounded queue.
    maximum_queued_blocking_jobs: u64,
    /// Started blocking jobs retained to completion.
    maximum_active_blocking_jobs: u64,
    /// Active event-delivery activities.
    maximum_active_event_deliveries: u64,
    /// Cleanup and control-plane tasks unavailable to ordinary work.
    reserved_control_plane_tasks: u64,
}

impl AsyncCapacityLimits {
    /// Validates every required operational capacity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maximum_active_root_tasks: u64,
        maximum_active_source_child_tasks: u64,
        maximum_resume_runnable_tasks: u64,
        maximum_admitted_public_activities: u64,
        maximum_interpreter_background_tasks: u64,
        maximum_queued_blocking_jobs: u64,
        maximum_active_blocking_jobs: u64,
        maximum_active_event_deliveries: u64,
        reserved_control_plane_tasks: u64,
    ) -> Result<Self, ConfigurationError> {
        for (field, value) in [
            (
                ConfigurationField::MaximumActiveRootTasks,
                maximum_active_root_tasks,
            ),
            (
                ConfigurationField::MaximumActiveSourceChildTasks,
                maximum_active_source_child_tasks,
            ),
            (
                ConfigurationField::MaximumResumeRunnableTasks,
                maximum_resume_runnable_tasks,
            ),
            (
                ConfigurationField::MaximumAdmittedPublicActivities,
                maximum_admitted_public_activities,
            ),
            (
                ConfigurationField::MaximumInterpreterBackgroundTasks,
                maximum_interpreter_background_tasks,
            ),
            (
                ConfigurationField::MaximumQueuedBlockingJobs,
                maximum_queued_blocking_jobs,
            ),
            (
                ConfigurationField::MaximumActiveBlockingJobs,
                maximum_active_blocking_jobs,
            ),
            (
                ConfigurationField::MaximumActiveEventDeliveries,
                maximum_active_event_deliveries,
            ),
            (
                ConfigurationField::ReservedControlPlaneTasks,
                reserved_control_plane_tasks,
            ),
        ] {
            check(field, value, false, MAXIMUM_DIRECTIVE_INTEGER)?;
        }
        Ok(Self {
            maximum_active_root_tasks,
            maximum_active_source_child_tasks,
            maximum_resume_runnable_tasks,
            maximum_admitted_public_activities,
            maximum_interpreter_background_tasks,
            maximum_queued_blocking_jobs,
            maximum_active_blocking_jobs,
            maximum_active_event_deliveries,
            reserved_control_plane_tasks,
        })
    }

    /// Returns the root-driver capacity across executions.
    #[must_use]
    pub const fn maximum_active_root_tasks(self) -> u64 {
        self.maximum_active_root_tasks
    }

    /// Returns the source-child-driver capacity across executions.
    #[must_use]
    pub const fn maximum_active_source_child_tasks(self) -> u64 {
        self.maximum_active_source_child_tasks
    }

    /// Returns the reconstructed runnable-task capacity.
    #[must_use]
    pub const fn maximum_resume_runnable_tasks(self) -> u64 {
        self.maximum_resume_runnable_tasks
    }

    /// Returns the admitted public-activity capacity.
    #[must_use]
    pub const fn maximum_admitted_public_activities(self) -> u64 {
        self.maximum_admitted_public_activities
    }

    /// Returns the interpreter-background-task capacity.
    #[must_use]
    pub const fn maximum_interpreter_background_tasks(self) -> u64 {
        self.maximum_interpreter_background_tasks
    }

    /// Returns the queued-blocking-job capacity.
    #[must_use]
    pub const fn maximum_queued_blocking_jobs(self) -> u64 {
        self.maximum_queued_blocking_jobs
    }

    /// Returns the active-blocking-job capacity.
    #[must_use]
    pub const fn maximum_active_blocking_jobs(self) -> u64 {
        self.maximum_active_blocking_jobs
    }

    /// Returns the active-event-delivery capacity.
    #[must_use]
    pub const fn maximum_active_event_deliveries(self) -> u64 {
        self.maximum_active_event_deliveries
    }

    /// Returns the cleanup/control-plane reserve.
    #[must_use]
    pub const fn reserved_control_plane_tasks(self) -> u64 {
        self.reserved_control_plane_tasks
    }

    pub(crate) const fn capacity(self, class: AdmissionClass) -> u64 {
        match class {
            AdmissionClass::RootTask => self.maximum_active_root_tasks,
            AdmissionClass::SourceChildTask => self.maximum_active_source_child_tasks,
            AdmissionClass::ResumeRunnableTask => self.maximum_resume_runnable_tasks,
            AdmissionClass::PublicActivity => self.maximum_admitted_public_activities,
            AdmissionClass::InterpreterBackgroundTask => self.maximum_interpreter_background_tasks,
            AdmissionClass::QueuedBlockingJob => self.maximum_queued_blocking_jobs,
            AdmissionClass::ActiveBlockingJob => self.maximum_active_blocking_jobs,
            AdmissionClass::EventDelivery => self.maximum_active_event_deliveries,
        }
    }
}

/// Complete validated interpreter configuration with executor-neutral integrations.
pub struct InterpreterConfiguration {
    executor: Arc<dyn ExecutorAdapter>,
    identity_source: Arc<dyn IdentitySource>,
    required: RequiredConfiguration,
    async_capacities: AsyncCapacityLimits,
    async_admission: AsyncAdmission,
    retry: RetryDefaults,
    graceful_shutdown_timeout: DurationMicros,
    post_cancellation_drain: DurationMicros,
    maximum_workflow_call_depth: u64,
    maximum_tasks_per_execution: u64,
}

impl fmt::Debug for InterpreterConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterpreterConfiguration")
            .field("required", &self.required)
            .field("async_capacities", &self.async_capacities)
            .field("retry", &self.retry)
            .field("graceful_shutdown_timeout", &self.graceful_shutdown_timeout)
            .field("post_cancellation_drain", &self.post_cancellation_drain)
            .field(
                "maximum_workflow_call_depth",
                &self.maximum_workflow_call_depth,
            )
            .field(
                "maximum_tasks_per_execution",
                &self.maximum_tasks_per_execution,
            )
            .finish_non_exhaustive()
    }
}

impl InterpreterConfiguration {
    /// Applies every normative v1 default to a validated required limit set.
    #[must_use]
    pub fn new(
        executor: Arc<dyn ExecutorAdapter>,
        identity_source: Arc<dyn IdentitySource>,
        required: RequiredConfiguration,
        async_capacities: AsyncCapacityLimits,
    ) -> Self {
        Self {
            executor,
            identity_source,
            required,
            async_capacities,
            async_admission: AsyncAdmission::new(async_capacities),
            retry: RetryDefaults::default(),
            graceful_shutdown_timeout: duration(30_000_000),
            post_cancellation_drain: duration(5_000_000),
            maximum_workflow_call_depth: 1_024,
            maximum_tasks_per_execution: 65_536,
        }
    }

    /// Replaces the structured-output and event-delivery retry defaults.
    #[must_use]
    pub fn with_retry_defaults(mut self, retry: RetryDefaults) -> Self {
        self.retry = retry;
        self
    }

    /// Replaces the finite, nonnegative graceful-shutdown default.
    pub fn with_graceful_shutdown_timeout_us(
        mut self,
        value: u64,
    ) -> Result<Self, ConfigurationError> {
        check(
            ConfigurationField::GracefulShutdownTimeoutUs,
            value,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        self.graceful_shutdown_timeout = duration(value);
        Ok(self)
    }

    /// Replaces the finite, nonnegative post-cancellation drain default.
    pub fn with_post_cancellation_drain_us(
        mut self,
        value: u64,
    ) -> Result<Self, ConfigurationError> {
        check(
            ConfigurationField::PostCancellationDrainUs,
            value,
            true,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        self.post_cancellation_drain = duration(value);
        Ok(self)
    }

    /// Replaces the positive workflow-call-depth limit.
    pub fn with_maximum_workflow_call_depth(
        mut self,
        value: u64,
    ) -> Result<Self, ConfigurationError> {
        check(
            ConfigurationField::MaximumWorkflowCallDepth,
            value,
            false,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        self.maximum_workflow_call_depth = value;
        Ok(self)
    }

    /// Replaces the positive cumulative task-count limit.
    pub fn with_maximum_tasks_per_execution(
        mut self,
        value: u64,
    ) -> Result<Self, ConfigurationError> {
        check(
            ConfigurationField::MaximumTasksPerExecution,
            value,
            false,
            MAXIMUM_DIRECTIVE_INTEGER,
        )?;
        self.maximum_tasks_per_execution = value;
        Ok(self)
    }

    /// Returns the configured executor without exposing an executor-specific type.
    #[must_use]
    pub fn executor(&self) -> &(dyn ExecutorAdapter + 'static) {
        self.executor.as_ref()
    }

    /// Returns a shared executor owner for independently admitted operations.
    #[must_use]
    pub fn executor_arc(&self) -> Arc<dyn ExecutorAdapter> {
        Arc::clone(&self.executor)
    }

    /// Returns the configured fresh-identity source.
    #[must_use]
    pub fn identity_source(&self) -> &(dyn IdentitySource + 'static) {
        self.identity_source.as_ref()
    }

    /// Returns all implementation-selected limits.
    #[must_use]
    pub const fn required(&self) -> RequiredConfiguration {
        self.required
    }

    /// Returns the operational capacity policy excluded from durable identity.
    #[must_use]
    pub const fn async_capacity_limits(&self) -> AsyncCapacityLimits {
        self.async_capacities
    }

    /// Returns the shared nonblocking admission owner for operational work.
    #[must_use]
    pub fn async_admission(&self) -> AsyncAdmission {
        self.async_admission.clone()
    }

    /// Returns effective retry defaults.
    #[must_use]
    pub const fn retry_defaults(&self) -> RetryDefaults {
        self.retry
    }

    /// Returns the effective graceful-shutdown default.
    #[must_use]
    pub const fn graceful_shutdown_timeout(&self) -> DurationMicros {
        self.graceful_shutdown_timeout
    }

    /// Returns the effective post-cancellation drain default.
    #[must_use]
    pub const fn post_cancellation_drain(&self) -> DurationMicros {
        self.post_cancellation_drain
    }

    /// Returns the effective workflow-call-depth limit.
    #[must_use]
    pub const fn maximum_workflow_call_depth(&self) -> u64 {
        self.maximum_workflow_call_depth
    }

    /// Returns the effective cumulative task-count limit.
    #[must_use]
    pub const fn maximum_tasks_per_execution(&self) -> u64 {
        self.maximum_tasks_per_execution
    }

    /// Projects the immutable execution limits into the explicit-frame machine.
    #[must_use]
    pub fn machine_limits(&self) -> MachineLimits {
        MachineLimits::new(
            self.required
                .maximum_deterministic_transitions_per_execution,
            self.required.maximum_operations_per_execution,
            self.required.maximum_loop_iterations_per_task,
            self.maximum_workflow_call_depth,
            self.required.deterministic_transition_yield_quantum,
            self.required.value_limits,
        )
        .unwrap_or_else(|| unreachable!("configuration validation preserves positive limits"))
    }
}

/// Exact reason a numeric configuration field was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationError {
    /// Portable field identity.
    pub field: ConfigurationField,
    /// Exact failed bound.
    pub kind: ConfigurationErrorKind,
}

/// Closed configuration-bound failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationErrorKind {
    /// A field that must be positive was zero.
    Zero,
    /// A value exceeded its field-specific inclusive maximum.
    TooLarge,
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {}: {}",
            self.field.wire_name(),
            match self.kind {
                ConfigurationErrorKind::Zero => "zero is not allowed",
                ConfigurationErrorKind::TooLarge => "value exceeds the portable maximum",
            }
        )
    }
}

impl std::error::Error for ConfigurationError {}

fn check(
    field: ConfigurationField,
    value: u64,
    zero_allowed: bool,
    maximum: u64,
) -> Result<(), ConfigurationError> {
    if value == 0 && !zero_allowed {
        return Err(ConfigurationError {
            field,
            kind: ConfigurationErrorKind::Zero,
        });
    }
    if value > maximum {
        return Err(ConfigurationError {
            field,
            kind: ConfigurationErrorKind::TooLarge,
        });
    }
    Ok(())
}

const fn duration(value: u64) -> DurationMicros {
    match DurationMicros::new(value) {
        Some(duration) => duration,
        None => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use gantry_core::portable::{ConfigurationField, JitterMode};

    use super::{ConfigurationErrorKind, MAXIMUM_DIRECTIVE_INTEGER, RetryDefaults};

    #[test]
    fn retry_defaults_and_exact_numeric_boundaries_are_stable() {
        let defaults = RetryDefaults::default();
        assert_eq!(defaults.model_retry_limit, 2);
        assert_eq!(defaults.action_retry_limit, 0);
        assert_eq!(defaults.backoff_initial.get(), 100_000);
        assert_eq!(defaults.backoff_cap.get(), 2_000_000);
        assert_eq!(defaults.jitter, JitterMode::Full);
        assert_eq!(defaults.event_delivery_retry_limit, 3);
        assert_eq!(defaults.event_delivery_attempt_timeout.get(), 30_000_000);

        let maximum = RetryDefaults::new(
            MAXIMUM_DIRECTIVE_INTEGER,
            MAXIMUM_DIRECTIVE_INTEGER,
            MAXIMUM_DIRECTIVE_INTEGER,
            MAXIMUM_DIRECTIVE_INTEGER,
            JitterMode::None,
            MAXIMUM_DIRECTIVE_INTEGER,
            MAXIMUM_DIRECTIVE_INTEGER,
        );
        assert!(maximum.is_ok());
        let too_large = RetryDefaults::new(
            0,
            0,
            0,
            0,
            JitterMode::None,
            0,
            MAXIMUM_DIRECTIVE_INTEGER + 1,
        );
        assert!(matches!(
            too_large,
            Err(error)
                if error.field == ConfigurationField::EventDeliveryAttemptTimeoutUs
                    && error.kind == ConfigurationErrorKind::TooLarge
        ));
        let zero = RetryDefaults::new(0, 0, 0, 0, JitterMode::None, 0, 0);
        assert!(matches!(
            zero,
            Err(error)
                if error.field == ConfigurationField::EventDeliveryAttemptTimeoutUs
                    && error.kind == ConfigurationErrorKind::Zero
        ));
    }
}
