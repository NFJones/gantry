//! Typed hook-outcome validation and structured-output retry policy.

use std::sync::Arc;
use std::task::Poll;

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::portable::{HookFailureCategory, JitterMode, RuntimeErrorCategory};
use gantry_core::schema::{NormalizationError, SchemaValidator};
use gantry_core::strict_json::{JsonError, JsonLimitKind, JsonLimits, StrictJsonDocument};
use gantry_core::value::{LogicalValue, OperationErrorValue, ValueError, ValueLimits};
use gantry_host::contracts::{
    CancellationSignal, DurationMicros, ExecutorAdapter, HookOutcomeV1, HostError, HostFuture,
    InclusiveJitterRange,
};
use gantry_ir::generated::RecoveryClass;

use crate::{
    CapturedOperationRequestV1, RetryDefaults, ValidationErrorCategoryV1, ValidationErrorV1,
};

/// Immutable normalized output admitted from one `Completed` hook outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHookOutputV1 {
    canonical_json: CanonicalJson,
}

impl ValidatedHookOutputV1 {
    /// Returns the complete normalized canonical JSON value.
    #[must_use]
    pub const fn canonical_json(&self) -> &CanonicalJson {
        &self.canonical_json
    }
}

/// Effective structured-output retry policy for one logical operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRetryPolicyV1 {
    /// Retries admitted after the initial physical dispatch.
    pub retry_limit: u64,
    /// Initial exponential ceiling in whole microseconds.
    pub initial_delay: DurationMicros,
    /// Saturating exponential cap in whole microseconds.
    pub cap: DurationMicros,
    /// Exact no-jitter or inclusive-full-jitter mode.
    pub jitter: JitterMode,
}

impl OperationRetryPolicyV1 {
    /// Resolves defaults and an optional source override, enforcing action recovery rules.
    pub fn for_request(
        request: &CapturedOperationRequestV1,
        defaults: RetryDefaults,
        override_limit: Option<u64>,
    ) -> Result<Self, RetryPolicyError> {
        let default_limit = match request {
            CapturedOperationRequestV1::Model { .. } => defaults.model_retry_limit,
            CapturedOperationRequestV1::Action { .. } => defaults.action_retry_limit,
        };
        let retry_limit = override_limit.unwrap_or(default_limit);
        if matches!(
            request,
            CapturedOperationRequestV1::Action { body, .. }
                if body.recovery == RecoveryClass::NonIdempotent && retry_limit != 0
        ) {
            return Err(RetryPolicyError::NonIdempotentRetry);
        }
        if defaults.backoff_cap < defaults.backoff_initial {
            return Err(RetryPolicyError::InvalidBackoff);
        }
        Ok(Self {
            retry_limit,
            initial_delay: defaults.backoff_initial,
            cap: defaults.backoff_cap,
            jitter: defaults.jitter,
        })
    }

    /// Returns the saturating ceiling for one one-based retry number.
    #[must_use]
    pub fn ceiling(self, retry_number: u64) -> DurationMicros {
        let initial = self.initial_delay.get();
        let cap = self.cap.get();
        if retry_number == 0 || initial == 0 {
            return DurationMicros::new(0).unwrap_or_else(|| unreachable!("zero is portable"));
        }
        if initial >= cap {
            return self.cap;
        }
        let shifts = retry_number.saturating_sub(1);
        let value = u32::try_from(shifts)
            .ok()
            .and_then(|shifts| initial.checked_shl(shifts))
            .unwrap_or(cap)
            .min(cap);
        DurationMicros::new(value).unwrap_or_else(|| unreachable!("validated policy is portable"))
    }

    fn select_delay(
        self,
        retry_number: u64,
        executor: &dyn ExecutorAdapter,
    ) -> Result<DurationMicros, HostError> {
        let ceiling = self.ceiling(retry_number);
        match self.jitter {
            JitterMode::None => Ok(ceiling),
            JitterMode::Full => {
                let range = InclusiveJitterRange::new(0, ceiling.get())
                    .unwrap_or_else(|| unreachable!("validated ceiling forms a range"));
                let sampled = executor.sample_inclusive(range)?;
                if sampled > ceiling.get() {
                    return Err(executor_contract_failure());
                }
                DurationMicros::new(sampled).ok_or_else(executor_contract_failure)
            }
        }
    }
}

/// Retry-policy construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyError {
    /// A non-idempotent action requested an automatic redispatch.
    NonIdempotentRetry,
    /// The configured backoff cap is below the initial delay.
    InvalidBackoff,
}

/// One recorded validation-repair wait before another physical dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRetryWaitV1 {
    /// Canonical validation errors sent on the next dispatch.
    pub errors: Arc<[ValidationErrorV1]>,
    /// Selected delay recorded before sleeping.
    pub delay: DurationMicros,
    /// Zero-based validation-attempt number for the next dispatch.
    pub next_validation_attempt: u64,
    /// Recovery redispatch number retained independently of validation retries.
    pub recovery_dispatch: u64,
    /// Retries remaining after this wait is admitted.
    pub retries_left: u64,
}

/// Settlement of one recorded structured-output retry delay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryDelayOutcomeV1 {
    /// The complete recorded delay elapsed.
    Completed,
    /// Gantry task cancellation became effective first.
    Cancelled,
    /// The executor timer returned a structured failure.
    Failed(HostError),
}

/// Waits one complete recorded retry delay without resampling it.
///
/// Cancellation is polled first so an effective task cancellation prevents a
/// fresh physical dispatch when it and timer completion are both ready.
pub fn wait_retry_delay<'a>(
    executor: &'a dyn ExecutorAdapter,
    delay: DurationMicros,
    cancellation: &'a CancellationSignal,
) -> HostFuture<'a, RetryDelayOutcomeV1> {
    let mut timer = executor.sleep(delay);
    let mut cancelled = cancellation.cancelled();
    Box::pin(std::future::poll_fn(move |context| {
        if cancelled.as_mut().poll(context).is_ready() {
            return Poll::Ready(RetryDelayOutcomeV1::Cancelled);
        }
        match timer.as_mut().poll(context) {
            Poll::Ready(Ok(())) => return Poll::Ready(RetryDelayOutcomeV1::Completed),
            Poll::Ready(Err(error)) => return Poll::Ready(RetryDelayOutcomeV1::Failed(error)),
            Poll::Pending => {}
        }
        Poll::Pending
    }))
}

/// Validated processing result for one typed hook outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessedHookOutcomeV1 {
    /// Completed output passed every ordered validation and normalization stage.
    Accepted(ValidatedHookOutputV1),
    /// Completed output failed validation and one retry remains.
    Retry(OperationRetryWaitV1),
    /// Decline, failure, contract violation, cancellation, or retry exhaustion.
    Failed(OperationFailureV1),
}

/// Stable operation-local failure after validating one hook outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationFailureV1 {
    /// Hook declined a required result.
    Declined(Arc<str>),
    /// Hook returned one exact categorized failure.
    Hook {
        /// Exact portable hook failure category.
        category: HookFailureCategory,
        /// Bounded diagnostic message.
        message: Arc<str>,
    },
    /// Hook diagnostic data or variant use violated the contract.
    ContractViolation,
    /// Structured-output validation retries were exhausted.
    StructuredOutputExhaustion(Arc<[ValidationErrorV1]>),
    /// Gantry task cancellation won before outcome consumption.
    TaskCancellation,
    /// Retry delay selection failed at the executor boundary.
    Executor(HostError),
}

impl OperationFailureV1 {
    /// Returns the runtime category used when this failure is not caught by `attempt`.
    #[must_use]
    pub const fn runtime_category(&self) -> RuntimeErrorCategory {
        match self {
            Self::Declined(_) => RuntimeErrorCategory::RequiredResultDecline,
            Self::Hook { category, .. } => match category {
                HookFailureCategory::Cancelled => RuntimeErrorCategory::Cancellation,
                HookFailureCategory::PolicyDenied => RuntimeErrorCategory::PolicyDenied,
                HookFailureCategory::ProviderFailure => RuntimeErrorCategory::ProviderFailure,
                HookFailureCategory::Timeout => RuntimeErrorCategory::Timeout,
                HookFailureCategory::UnknownOutcome => RuntimeErrorCategory::UnknownActionOutcome,
            },
            Self::ContractViolation => RuntimeErrorCategory::HookFailure,
            Self::StructuredOutputExhaustion(_) => RuntimeErrorCategory::StructuredOutputExhaustion,
            Self::TaskCancellation => RuntimeErrorCategory::Cancellation,
            Self::Executor(_) => RuntimeErrorCategory::ExecutorFailure,
        }
    }

    /// Converts only the operation-local failures catchable by `attempt`.
    pub fn attempt_value(
        &self,
        operation_id: &str,
        limits: ValueLimits,
    ) -> Result<Option<LogicalValue>, ValueError> {
        let error = match self {
            Self::Declined(message) => OperationErrorValue::Declined(message.to_string()),
            Self::Hook { category, message } => match category {
                HookFailureCategory::Cancelled => {
                    OperationErrorValue::Cancelled(message.to_string())
                }
                HookFailureCategory::PolicyDenied => {
                    OperationErrorValue::PolicyDenied(message.to_string())
                }
                HookFailureCategory::ProviderFailure => {
                    OperationErrorValue::ProviderFailure(message.to_string())
                }
                HookFailureCategory::Timeout => OperationErrorValue::Timeout(message.to_string()),
                HookFailureCategory::UnknownOutcome => OperationErrorValue::UnknownOutcome {
                    operation_id: operation_id.to_owned(),
                    message: message.to_string(),
                },
            },
            Self::StructuredOutputExhaustion(_) => OperationErrorValue::InvalidOutput,
            Self::ContractViolation | Self::TaskCancellation | Self::Executor(_) => {
                return Ok(None);
            }
        };
        LogicalValue::operation_error(error, limits).map(Some)
    }
}

/// Gantry-internal processing failure distinct from a hook outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookOutcomeProcessingError {
    /// The captured generated schema is malformed or cannot be evaluated.
    InvalidSchema,
    /// Canonical normalization failed after successful schema validation.
    CanonicalInvariant,
}

/// Validates one typed hook outcome in normative order and selects retry state.
#[allow(clippy::too_many_arguments)]
pub fn process_hook_outcome(
    request: &CapturedOperationRequestV1,
    outcome: &HookOutcomeV1,
    policy: OperationRetryPolicyV1,
    validation_attempt: u64,
    recovery_dispatch: u64,
    retries_left: u64,
    executor: &dyn ExecutorAdapter,
    task_cancelled: bool,
) -> Result<ProcessedHookOutcomeV1, HookOutcomeProcessingError> {
    if task_cancelled {
        return Ok(ProcessedHookOutcomeV1::Failed(
            OperationFailureV1::TaskCancellation,
        ));
    }
    let header = request.header();
    match outcome {
        HookOutcomeV1::Completed(raw_output) => {
            let result = validate_completed(header, raw_output);
            match result {
                Ok(output) => Ok(ProcessedHookOutcomeV1::Accepted(output)),
                Err(CompletedValidationError::Errors(errors)) if retries_left > 0 => {
                    let next_validation_attempt = validation_attempt.saturating_add(1);
                    let delay = match policy.select_delay(next_validation_attempt, executor) {
                        Ok(delay) => delay,
                        Err(error) => {
                            return Ok(ProcessedHookOutcomeV1::Failed(
                                OperationFailureV1::Executor(error),
                            ));
                        }
                    };
                    Ok(ProcessedHookOutcomeV1::Retry(OperationRetryWaitV1 {
                        errors: Arc::from(errors),
                        delay,
                        next_validation_attempt,
                        recovery_dispatch,
                        retries_left: retries_left.saturating_sub(1),
                    }))
                }
                Err(CompletedValidationError::Errors(errors)) => {
                    Ok(ProcessedHookOutcomeV1::Failed(
                        OperationFailureV1::StructuredOutputExhaustion(Arc::from(errors)),
                    ))
                }
                Err(CompletedValidationError::InvalidSchema) => {
                    Err(HookOutcomeProcessingError::InvalidSchema)
                }
                Err(CompletedValidationError::CanonicalInvariant) => {
                    Err(HookOutcomeProcessingError::CanonicalInvariant)
                }
            }
        }
        HookOutcomeV1::Declined(reason) => Ok(ProcessedHookOutcomeV1::Failed(
            validate_diagnostic(reason, header)
                .map(OperationFailureV1::Declined)
                .unwrap_or(OperationFailureV1::ContractViolation),
        )),
        HookOutcomeV1::Failed { category, message } => {
            let valid_category = *category != HookFailureCategory::UnknownOutcome
                || matches!(request, CapturedOperationRequestV1::Action { .. });
            let failure = if valid_category {
                validate_diagnostic(message, header).map(|message| OperationFailureV1::Hook {
                    category: *category,
                    message,
                })
            } else {
                None
            };
            Ok(ProcessedHookOutcomeV1::Failed(
                failure.unwrap_or(OperationFailureV1::ContractViolation),
            ))
        }
    }
}

enum CompletedValidationError {
    Errors(Vec<ValidationErrorV1>),
    InvalidSchema,
    CanonicalInvariant,
}

fn validate_completed(
    header: &crate::OperationRequestHeaderV1,
    raw_output: &[u8],
) -> Result<ValidatedHookOutputV1, CompletedValidationError> {
    let parse_limits = JsonLimits {
        maximum_bytes: header.maximum_hook_output_bytes,
        maximum_nesting_depth: header.value_limits.maximum_nesting_depth(),
        maximum_nodes: header.value_limits.maximum_nodes(),
        maximum_string_scalars: u64::MAX,
        maximum_list_items: u64::MAX,
    };
    let document = StrictJsonDocument::decode(raw_output, parse_limits)
        .map_err(|error| CompletedValidationError::Errors(vec![json_validation_error(&error)]))?;
    let schema_length = u64::try_from(header.expected_schema.len()).unwrap_or(u64::MAX);
    let schema_limits = JsonLimits {
        maximum_bytes: schema_length,
        maximum_nesting_depth: schema_length.max(1),
        maximum_nodes: schema_length.max(1),
        maximum_string_scalars: schema_length.max(1),
        maximum_list_items: schema_length.max(1),
    };
    let validator = SchemaValidator::compile(Arc::clone(&header.expected_schema), schema_limits)
        .map_err(|_| CompletedValidationError::InvalidSchema)?;
    let normalize_limits = JsonLimits {
        maximum_bytes: u64::MAX,
        maximum_nesting_depth: header.value_limits.maximum_nesting_depth(),
        maximum_nodes: header.value_limits.maximum_nodes(),
        maximum_string_scalars: header.value_limits.maximum_string_scalars(),
        maximum_list_items: header.value_limits.maximum_list_items(),
    };
    let canonical_json = validator
        .normalize(&document, normalize_limits)
        .map_err(|error| match error {
            NormalizationError::Validation(errors) => CompletedValidationError::Errors(
                errors
                    .into_iter()
                    .map(|error| ValidationErrorV1 {
                        category: ValidationErrorCategoryV1::Schema,
                        instance_location: Some(error.instance_location),
                        message: error.message,
                        schema_location: Some(error.schema_location),
                    })
                    .collect(),
            ),
            NormalizationError::Json(error) => {
                CompletedValidationError::Errors(vec![json_validation_error(&error)])
            }
            NormalizationError::Schema(_) => CompletedValidationError::InvalidSchema,
            NormalizationError::Canonical(_) => CompletedValidationError::CanonicalInvariant,
        })?;
    Ok(ValidatedHookOutputV1 { canonical_json })
}

fn validate_diagnostic(
    value: &Arc<str>,
    header: &crate::OperationRequestHeaderV1,
) -> Option<Arc<str>> {
    let bytes = u64::try_from(value.len()).ok()?;
    let scalars = u64::try_from(value.chars().count()).ok()?;
    (!value.is_empty()
        && bytes <= header.maximum_hook_output_bytes
        && scalars <= header.value_limits.maximum_string_scalars())
    .then(|| Arc::clone(value))
}

fn json_validation_error(error: &JsonError) -> ValidationErrorV1 {
    let category = match error {
        JsonError::InvalidUtf8 => ValidationErrorCategoryV1::Utf8,
        JsonError::DuplicateMember { .. } => ValidationErrorCategoryV1::JsonDuplicateKey,
        JsonError::UnpairedSurrogate { .. } => ValidationErrorCategoryV1::JsonUnicode,
        JsonError::ResourceLimit { .. } => ValidationErrorCategoryV1::ResourceLimit,
        JsonError::Empty | JsonError::Syntax { .. } | JsonError::TrailingData { .. } => {
            ValidationErrorCategoryV1::JsonSyntax
        }
    };
    let message: Arc<str> = match error {
        JsonError::InvalidUtf8 => Arc::from("raw output is not valid UTF-8"),
        JsonError::Empty => Arc::from("raw output contains no JSON value"),
        JsonError::Syntax { .. } => Arc::from("raw output is not valid strict JSON"),
        JsonError::TrailingData { .. } => Arc::from("raw output contains trailing data"),
        JsonError::DuplicateMember { .. } => Arc::from("raw output contains a duplicate member"),
        JsonError::UnpairedSurrogate { .. } => Arc::from("raw output contains invalid Unicode"),
        JsonError::ResourceLimit { kind, .. } => Arc::from(match kind {
            JsonLimitKind::Bytes => "raw output exceeds the byte limit",
            JsonLimitKind::NestingDepth => "raw output exceeds the nesting-depth limit",
            JsonLimitKind::Nodes => "raw output exceeds the value-node limit",
            JsonLimitKind::StringScalars => "raw output exceeds the String-scalar limit",
            JsonLimitKind::ListItems => "raw output exceeds the List-item limit",
        }),
    };
    ValidationErrorV1 {
        category,
        instance_location: None,
        message,
        schema_location: None,
    }
}

fn executor_contract_failure() -> HostError {
    HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    }
}

#[cfg(test)]
mod tests {
    use gantry_core::portable::IdentityKind;
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, ValueLimits};
    use gantry_host::contracts::{ActionMappingRevision, HostFuture, IdentitySource};
    use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
    use gantry_ir::{CanonicalPath, CanonicalSignature, StructuralPosition, TypeDescriptor};

    use super::*;
    use crate::{ActionOperationRequestV1, OperationRequestHeaderV1};

    struct Executor(u64);

    impl ExecutorAdapter for Executor {
        fn spawn(
            &self,
            task: gantry_host::contracts::OwnedTaskFuture,
        ) -> Result<Box<dyn gantry_host::contracts::SubmittedTask>, HostError> {
            gantry_host::contracts::reject_task_submission(task)
        }

        fn sleep<'a>(&'a self, _: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
            Ok(self.0.min(range.maximum()))
        }
    }

    impl IdentitySource for Executor {
        fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
            Ok([1; 32])
        }
    }

    #[test]
    fn completed_output_is_validated_in_order_and_selects_retry() {
        let request = request(RecoveryClass::ReadOnly);
        let policy =
            OperationRetryPolicyV1::for_request(&request, RetryDefaults::default(), Some(2))
                .unwrap_or_else(|error| panic!("policy failed: {error:?}"));
        let accepted = process_hook_outcome(
            &request,
            &HookOutcomeV1::Completed(Arc::from(&b"\"ok\""[..])),
            policy,
            0,
            0,
            2,
            &Executor(0),
            false,
        );
        assert!(matches!(accepted, Ok(ProcessedHookOutcomeV1::Accepted(_))));

        let retry = process_hook_outcome(
            &request,
            &HookOutcomeV1::Completed(Arc::from(&b"true"[..])),
            policy,
            0,
            0,
            2,
            &Executor(7),
            false,
        );
        assert!(matches!(
            retry,
            Ok(ProcessedHookOutcomeV1::Retry(ref wait))
                if wait.next_validation_attempt == 1
                    && wait.retries_left == 1
                    && wait.delay.get() == 7
                    && wait.errors[0].category == ValidationErrorCategoryV1::Schema
        ));
    }

    #[test]
    fn diagnostic_contracts_unknown_outcome_and_attempt_mapping_are_exact() {
        let model = model_request();
        let policy = OperationRetryPolicyV1::for_request(&model, RetryDefaults::default(), None)
            .unwrap_or_else(|error| panic!("policy failed: {error:?}"));
        let invalid = process_hook_outcome(
            &model,
            &HookOutcomeV1::Failed {
                category: HookFailureCategory::UnknownOutcome,
                message: Arc::from("ambiguous"),
            },
            policy,
            0,
            0,
            2,
            &Executor(0),
            false,
        );
        assert_eq!(
            invalid,
            Ok(ProcessedHookOutcomeV1::Failed(
                OperationFailureV1::ContractViolation
            ))
        );

        let declined = OperationFailureV1::Declined(Arc::from("no"));
        let value = declined
            .attempt_value("operation:00", DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("attempt value failed: {error:?}"));
        assert!(
            matches!(value, Some(value) if matches!(value.view(), gantry_core::value::LogicalValueView::OperationError(_)))
        );
        assert_eq!(
            OperationFailureV1::TaskCancellation
                .attempt_value("operation:00", DEFAULT_VALUE_LIMITS),
            Ok(None)
        );
    }

    #[test]
    fn retry_ceiling_saturates_without_unbounded_shift() {
        let policy = OperationRetryPolicyV1 {
            retry_limit: u64::MAX,
            initial_delay: DurationMicros::new(100_000).unwrap_or_else(|| unreachable!()),
            cap: DurationMicros::new(2_000_000).unwrap_or_else(|| unreachable!()),
            jitter: JitterMode::None,
        };
        assert_eq!(policy.ceiling(1).get(), 100_000);
        assert_eq!(policy.ceiling(2).get(), 200_000);
        assert_eq!(policy.ceiling(u64::MAX).get(), 2_000_000);
    }

    #[test]
    fn completed_validation_order_is_bounded_and_never_discloses_raw_output() {
        let mut byte_limited = request(RecoveryClass::ReadOnly);
        let CapturedOperationRequestV1::Action { header, .. } = &mut byte_limited else {
            unreachable!("fixture is an action")
        };
        header.maximum_hook_output_bytes = 1;
        assert_eq!(
            validation_errors(&byte_limited, Arc::from(&[0xff, 0xfe][..]))[0].category,
            ValidationErrorCategoryV1::ResourceLimit
        );

        let ordinary = request(RecoveryClass::ReadOnly);
        assert_eq!(
            validation_errors(&ordinary, Arc::from(&[0xff][..]))[0].category,
            ValidationErrorCategoryV1::Utf8
        );
        assert_eq!(
            validation_errors(&ordinary, Arc::from(&b"{"[..]))[0].category,
            ValidationErrorCategoryV1::JsonSyntax
        );
        assert_eq!(
            validation_errors(&ordinary, Arc::from(&br#"{"x":1,"x":2}"#[..]))[0].category,
            ValidationErrorCategoryV1::JsonDuplicateKey
        );

        let mut parser_limited = request(RecoveryClass::ReadOnly);
        let CapturedOperationRequestV1::Action { header, .. } = &mut parser_limited else {
            unreachable!("fixture is an action")
        };
        header.value_limits = ValueLimits::new(1, 32, 32, 32)
            .unwrap_or_else(|| unreachable!("fixture limits are positive"));
        assert_eq!(
            validation_errors(&parser_limited, Arc::from(&b"[[]]"[..]))[0].category,
            ValidationErrorCategoryV1::ResourceLimit
        );
        assert_eq!(
            validation_errors(&ordinary, Arc::from(&b"true"[..]))[0].category,
            ValidationErrorCategoryV1::Schema
        );

        let mut value_limited = request(RecoveryClass::ReadOnly);
        let CapturedOperationRequestV1::Action { header, .. } = &mut value_limited else {
            unreachable!("fixture is an action")
        };
        header.value_limits = ValueLimits::new(8, 32, 1, 32)
            .unwrap_or_else(|| unreachable!("fixture limits are positive"));
        let secret = Arc::<[u8]>::from(&br#""private-output""#[..]);
        let processed = process_without_retries(&value_limited, secret);
        assert!(matches!(
            processed,
            ProcessedHookOutcomeV1::Failed(OperationFailureV1::StructuredOutputExhaustion(
                ref errors
            )) if errors[0].category == ValidationErrorCategoryV1::ResourceLimit
        ));
        assert!(!format!("{processed:?}").contains("private-output"));
    }

    #[test]
    fn retry_policy_diagnostics_jitter_and_cancellation_are_exact() {
        let mut bounded = request(RecoveryClass::ReadOnly);
        let CapturedOperationRequestV1::Action { header, .. } = &mut bounded else {
            unreachable!("fixture is an action")
        };
        header.maximum_hook_output_bytes = 1;
        let policy =
            OperationRetryPolicyV1::for_request(&bounded, RetryDefaults::default(), Some(0))
                .unwrap_or_else(|error| panic!("policy failed: {error:?}"));
        for outcome in [
            HookOutcomeV1::Declined(Arc::from("")),
            HookOutcomeV1::Declined(Arc::from("too long")),
        ] {
            assert_eq!(
                process_hook_outcome(&bounded, &outcome, policy, 0, 0, 0, &Executor(0), false),
                Ok(ProcessedHookOutcomeV1::Failed(
                    OperationFailureV1::ContractViolation
                ))
            );
        }

        let action = request(RecoveryClass::ReadOnly);
        let action_policy =
            OperationRetryPolicyV1::for_request(&action, RetryDefaults::default(), Some(0))
                .unwrap_or_else(|error| panic!("policy failed: {error:?}"));
        assert!(matches!(
            process_hook_outcome(
                &action,
                &HookOutcomeV1::Failed {
                    category: HookFailureCategory::UnknownOutcome,
                    message: Arc::from("ambiguous"),
                },
                action_policy,
                0,
                0,
                0,
                &Executor(0),
                false,
            ),
            Ok(ProcessedHookOutcomeV1::Failed(OperationFailureV1::Hook {
                category: HookFailureCategory::UnknownOutcome,
                ..
            }))
        ));
        assert_eq!(
            OperationRetryPolicyV1::for_request(
                &request(RecoveryClass::NonIdempotent),
                RetryDefaults::default(),
                Some(1),
            ),
            Err(RetryPolicyError::NonIdempotentRetry)
        );

        let jitter = OperationRetryPolicyV1 {
            retry_limit: 1,
            initial_delay: DurationMicros::new(5).unwrap_or_else(|| unreachable!()),
            cap: DurationMicros::new(5).unwrap_or_else(|| unreachable!()),
            jitter: JitterMode::Full,
        };
        assert_eq!(
            jitter
                .select_delay(1, &Executor(0))
                .unwrap_or_else(|error| panic!("minimum jitter failed: {error:?}"))
                .get(),
            0
        );
        assert_eq!(
            jitter
                .select_delay(1, &Executor(u64::MAX))
                .unwrap_or_else(|error| panic!("maximum jitter failed: {error:?}"))
                .get(),
            5
        );

        let cancellation = CancellationSignal::default();
        assert!(cancellation.cancel());
        assert_eq!(
            block_on(wait_retry_delay(
                &Executor(0),
                DurationMicros::new(1).unwrap_or_else(|| unreachable!()),
                &cancellation,
            )),
            RetryDelayOutcomeV1::Cancelled
        );
    }

    fn validation_errors(
        request: &CapturedOperationRequestV1,
        raw_output: Arc<[u8]>,
    ) -> Arc<[ValidationErrorV1]> {
        match process_without_retries(request, raw_output) {
            ProcessedHookOutcomeV1::Failed(OperationFailureV1::StructuredOutputExhaustion(
                errors,
            )) => errors,
            other => panic!("unexpected validation result: {other:?}"),
        }
    }

    fn process_without_retries(
        request: &CapturedOperationRequestV1,
        raw_output: Arc<[u8]>,
    ) -> ProcessedHookOutcomeV1 {
        let policy =
            OperationRetryPolicyV1::for_request(request, RetryDefaults::default(), Some(0))
                .unwrap_or_else(|error| panic!("policy failed: {error:?}"));
        process_hook_outcome(
            request,
            &HookOutcomeV1::Completed(raw_output),
            policy,
            0,
            0,
            0,
            &Executor(0),
            false,
        )
        .unwrap_or_else(|error| panic!("processing failed: {error:?}"))
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn request(recovery: RecoveryClass) -> CapturedOperationRequestV1 {
        let path = CanonicalPath::new("crate::lookup")
            .unwrap_or_else(|error| panic!("path failed: {error}"));
        CapturedOperationRequestV1::Action {
            header: header(OperationSiteKind::Action),
            body: ActionOperationRequestV1 {
                path: path.clone(),
                signature: CanonicalSignature::action(
                    recovery,
                    &path,
                    &[],
                    &TypeDescriptor::STRING,
                ),
                recovery,
                mapping_revision: ActionMappingRevision::new("actions-v1")
                    .unwrap_or_else(|error| panic!("revision failed: {error:?}")),
                arguments: Vec::new(),
            },
        }
    }

    fn model_request() -> CapturedOperationRequestV1 {
        use crate::{CanonicalTranscriptV1, ModelOperationRequestV1, ModelSessionUseV1};
        use gantry_host::contracts::AgentMappingRevision;

        CapturedOperationRequestV1::Model {
            header: header(OperationSiteKind::Prompt),
            body: Box::new(ModelOperationRequestV1 {
                selected_agent: Arc::from("worker"),
                mapping_revision: AgentMappingRevision::new("agents-v1")
                    .unwrap_or_else(|error| panic!("revision failed: {error:?}")),
                template_segments: Vec::new(),
                rendered_prompt: Arc::from("prompt"),
                interpolation_inputs: Vec::new(),
                named_inputs: Vec::new(),
                transcript: CanonicalTranscriptV1::empty(),
                active_session_id: fresh(IdentityKind::Session, 4),
                parent_session_id: None,
                root_session_id: fresh(IdentityKind::Session, 4),
                session_use: ModelSessionUseV1::Inline,
            }),
        }
    }

    fn header(kind: OperationSiteKind) -> OperationRequestHeaderV1 {
        OperationRequestHeaderV1 {
            execution_id: fresh(IdentityKind::Execution, 1),
            task_id: derived(IdentityKind::Task, b"task"),
            operation_id: derived(IdentityKind::Operation, b"operation"),
            kind,
            expected_type: TypeDescriptor::STRING,
            expected_schema: Arc::from(
                &br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string"}"#[..],
            ),
            maximum_hook_output_bytes: 1_024,
            value_limits: DEFAULT_VALUE_LIMITS,
            workflow: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("workflow failed: {error}")),
            site: StructuralPosition::new(vec![0])
                .unwrap_or_else(|error| panic!("site failed: {error}")),
        }
    }

    fn fresh(kind: IdentityKind, byte: u8) -> gantry_core::identity::ProtocolIdentity {
        gantry_core::identity::ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }

    fn derived(kind: IdentityKind, key: &[u8]) -> gantry_core::identity::ProtocolIdentity {
        gantry_core::identity::ProtocolIdentity::derive(kind, key)
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }
}
