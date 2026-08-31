//! Nondurable execution-event completion, delivery, and lifecycle consequences.

use std::sync::Arc;

use gantry_core::event::{
    EventContractError, EventDraft, EventEnvelope, EventPayload, ProtectedReference,
};
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{HookFailureCategory, IdentityKind, ProtectedReferenceClass};
use gantry_core::value::LogicalValue;
use gantry_host::contracts::{
    DeadlineOutcome, DurationMicros, FreshIdentityAllocator, HookOutcomeV1, IdentitySource,
    UtcClock, deadline_race,
};
use gantry_host::event::{
    EmergencyDiagnostic, EmergencyDiagnosticCallback, EventDeliveryRuntime, ProtectedPayload,
};
use gantry_ir::TypeDescriptor;
use gantry_ir::generated::TypeKind;
use gantry_observe::{
    ActivityBarrier, ActivityDeliveryResult, DeliveryError, DeliveryKernel, EventCompleter,
    EventCompletionError, SinkPlan,
};

use crate::{
    AdapterPoison, CapturedOperationRequestV1, ExecutionHandle, MachineFailure, MachineLabel,
    MachineOutcome, OperationRetryWaitV1, PreparedHookDispatch, RequiredDeliveryRecordV1,
    RequiredEventDeliveryFailureV1, RuntimeCode, ValidationErrorCategoryV1, ValidationErrorV1,
};

/// Performs one bounded best-effort emergency report and ignores every settlement.
///
/// The callback is invoked outside standard event delivery, receives no protected
/// bundle, and cannot create a delivery barrier or alter a language outcome.
pub async fn report_emergency_diagnostic(
    callback: &dyn EmergencyDiagnosticCallback,
    code: impl Into<Arc<str>>,
    executor: &dyn gantry_host::contracts::ExecutorAdapter,
    timeout: DurationMicros,
) {
    let poison = AdapterPoison::default();
    let future = match crate::catch_integration(&poison, || {
        callback.report(EmergencyDiagnostic { code: code.into() })
    }) {
        Ok(future) => crate::contain_integration_future(future, poison),
        Err(_) => return,
    };
    let _ = match deadline_race(executor, future, timeout, None).await {
        DeadlineOutcome::Completed(_) | DeadlineOutcome::TimedOut | DeadlineOutcome::Failed(_) => {
            Some(())
        }
        DeadlineOutcome::Cancelled => None,
    };
}

/// One typed standard-event draft and its sink-neutral protected side bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEventDraftV1 {
    /// Typed ordinary event data containing references but no protected bytes.
    pub draft: EventDraft,
    /// Exact protected bytes corresponding to every reference in the draft.
    pub protected_payloads: Arc<[ProtectedPayload]>,
}

/// Rejection while deriving an operation event from runtime-owned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationEventDraftError {
    /// Typed event fields violated the portable event contract.
    Contract(EventContractError),
    /// A decline/failure diagnostic or category violated the hook contract.
    HookContractViolation,
    /// The declared result kind and protected normalized value disagree.
    ResultShape,
    /// Required structured event context was empty or internally inconsistent.
    InvalidContext,
}

/// Builds one physical `operation-dispatch` event and protected request bundle.
pub fn operation_dispatch_event(
    captured: &CapturedOperationRequestV1,
    prepared: &PreparedHookDispatch,
    validation_attempt: u64,
    recovery_dispatch: u64,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    let header = captured.header();
    let schema = protected(
        format!("dispatch:{}:schema", prepared.dispatch_id),
        ProtectedReferenceClass::OperationRequest,
        Arc::clone(&header.expected_schema),
    )?;
    let request = protected(
        format!("dispatch:{}:operation-request", prepared.dispatch_id),
        ProtectedReferenceClass::OperationRequest,
        Arc::from(prepared.request.canonical_bytes()),
    )?;
    let mut references = vec![schema.0.clone(), request.0.clone()];
    let mut payloads = vec![schema.1, request.1];
    let mut json = String::from("{");
    match captured {
        CapturedOperationRequestV1::Action { body, .. } => {
            json.push_str("\"action_mapping_revision\":");
            push_json_string(&mut json, body.mapping_revision.as_str());
            json.push_str(",\"canonical_path\":");
            push_json_string(&mut json, body.path.as_str());
            json.push_str(",\"canonical_signature\":");
            push_json_string(&mut json, body.signature.as_str());
        }
        CapturedOperationRequestV1::Model { body, .. } => {
            json.push_str("\"active_agent_mapping_revision\":");
            push_json_string(&mut json, body.mapping_revision.as_str());
            json.push_str(",\"active_session_creation\":");
            push_json_string(&mut json, session_directive(&body.session_use));
        }
    }
    json.push_str(",\"dispatch_id\":");
    push_json_string(&mut json, &prepared.dispatch_id.to_string());
    if let CapturedOperationRequestV1::Model { body, .. } = captured {
        json.push_str(",\"has_parent_session\":");
        json.push_str(if body.parent_session_id.is_some() {
            "true"
        } else {
            "false"
        });
    }
    json.push_str(",\"operation_id\":");
    push_json_string(&mut json, &header.operation_id.to_string());
    json.push_str(",\"operation_kind\":");
    push_json_string(&mut json, header.kind.wire_name());
    json.push_str(",\"operation_request_reference\":");
    push_json_string(&mut json, request.0.key());
    if let CapturedOperationRequestV1::Model { body, .. } = captured {
        let prompt = protected(
            format!("dispatch:{}:prompt", prepared.dispatch_id),
            ProtectedReferenceClass::OperationRequest,
            Arc::from(body.rendered_prompt.as_bytes()),
        )?;
        json.push_str(",\"prompt_reference\":");
        push_json_string(&mut json, prompt.0.key());
        references.push(prompt.0);
        payloads.push(prompt.1);
    }
    json.push_str(",\"recovery_dispatch\":");
    json.push_str(&recovery_dispatch.to_string());
    if let CapturedOperationRequestV1::Model { body, .. } = captured {
        json.push_str(",\"request_session_directive\":");
        push_json_string(&mut json, session_directive(&body.session_use));
    }
    json.push_str(",\"result_kind\":");
    push_json_string(&mut json, result_kind(header.expected_type.kind()));
    json.push_str(",\"schema_reference\":");
    push_json_string(&mut json, schema.0.key());
    if let CapturedOperationRequestV1::Model { body, .. } = captured {
        json.push_str(",\"selected_agent\":");
        push_json_string(&mut json, &body.selected_agent);
    }
    json.push_str(",\"state\":\"prepared\",\"validation_attempt\":");
    json.push_str(&validation_attempt.to_string());
    json.push('}');
    let draft = EventDraft::new(
        gantry_core::portable::EventKind::OperationDispatch,
        event_payload(json),
    )
    .with_operation_id(header.operation_id)
    .and_then(|draft| draft.with_protected_references(references))
    .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from(payloads),
    })
}

/// Builds one physical `operation-completion` event from a valid hook outcome.
pub fn operation_completion_event(
    captured: &CapturedOperationRequestV1,
    dispatch_id: ProtocolIdentity,
    validation_attempt: u64,
    recovery_dispatch: u64,
    outcome: &HookOutcomeV1,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    let header = captured.header();
    let (variant, diagnostic_category, protected_payload) = match outcome {
        HookOutcomeV1::Completed(raw) => (
            "completed",
            None,
            protected(
                format!("dispatch:{dispatch_id}:raw-output"),
                ProtectedReferenceClass::RawOutput,
                Arc::clone(raw),
            )?,
        ),
        HookOutcomeV1::Declined(reason) => {
            require_diagnostic(captured, reason, None)?;
            (
                "declined",
                None,
                protected(
                    format!("dispatch:{dispatch_id}:integration-diagnostic"),
                    ProtectedReferenceClass::IntegrationDiagnostic,
                    Arc::from(reason.as_bytes()),
                )?,
            )
        }
        HookOutcomeV1::Failed { category, message } => {
            require_diagnostic(captured, message, Some(*category))?;
            (
                "failed",
                Some(category.wire_name()),
                protected(
                    format!("dispatch:{dispatch_id}:integration-diagnostic"),
                    ProtectedReferenceClass::IntegrationDiagnostic,
                    Arc::from(message.as_bytes()),
                )?,
            )
        }
    };
    let mut json = String::from("{\"dispatch_id\":");
    push_json_string(&mut json, &dispatch_id.to_string());
    if let Some(category) = diagnostic_category {
        json.push_str(",\"failure_category\":");
        push_json_string(&mut json, category);
    }
    json.push_str(",\"operation_id\":");
    push_json_string(&mut json, &header.operation_id.to_string());
    json.push_str(",\"outcome_variant\":");
    push_json_string(&mut json, variant);
    json.push_str(",\"protected_reference\":");
    push_json_string(&mut json, protected_payload.0.key());
    json.push_str(",\"recovery_dispatch\":");
    json.push_str(&recovery_dispatch.to_string());
    json.push_str(",\"validation_attempt\":");
    json.push_str(&validation_attempt.to_string());
    json.push('}');
    let draft = EventDraft::new(
        gantry_core::portable::EventKind::OperationCompletion,
        event_payload(json),
    )
    .with_operation_id(header.operation_id)
    .and_then(|draft| {
        draft
            .with_causal_ids([dispatch_id])
            .with_protected_references(vec![protected_payload.0])
    })
    .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from([protected_payload.1]),
    })
}

/// Builds one physical structured-output validation-failure event.
pub fn structured_output_validation_failure_event(
    operation_id: ProtocolIdentity,
    dispatch_id: ProtocolIdentity,
    errors: &[ValidationErrorV1],
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    let mut json = String::from("{\"dispatch_id\":");
    push_json_string(&mut json, &dispatch_id.to_string());
    json.push_str(",\"operation_id\":");
    push_json_string(&mut json, &operation_id.to_string());
    json.push_str(",\"validation_errors\":[");
    push_validation_errors(&mut json, errors);
    json.push_str("]}");
    let draft = EventDraft::new(
        gantry_core::portable::EventKind::StructuredOutputValidationFailure,
        event_payload(json),
    )
    .with_operation_id(operation_id)
    .map(|draft| draft.with_causal_ids([dispatch_id]))
    .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from([]),
    })
}

/// Builds one admitted validation-repair retry event.
pub fn validation_retry_event(
    operation_id: ProtocolIdentity,
    preceding_dispatch_id: ProtocolIdentity,
    next_dispatch_id: Option<ProtocolIdentity>,
    wait: &OperationRetryWaitV1,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    let mut json = String::from("{\"next_dispatch_id\":");
    if let Some(identity) = next_dispatch_id {
        push_json_string(&mut json, &identity.to_string());
    } else {
        json.push_str("null");
    }
    json.push_str(",\"operation_id\":");
    push_json_string(&mut json, &operation_id.to_string());
    json.push_str(",\"preceding_dispatch_id\":");
    push_json_string(&mut json, &preceding_dispatch_id.to_string());
    json.push_str(",\"recovery_dispatch\":");
    json.push_str(&wait.recovery_dispatch.to_string());
    json.push_str(",\"retry_class\":\"validation\",\"selected_delay_us\":");
    json.push_str(&wait.delay.get().to_string());
    json.push_str(",\"validation_attempt\":");
    json.push_str(&wait.next_validation_attempt.to_string());
    json.push('}');
    let mut causal = vec![preceding_dispatch_id];
    if let Some(identity) = next_dispatch_id {
        causal.push(identity);
    }
    let draft = EventDraft::new(gantry_core::portable::EventKind::Retry, event_payload(json))
        .with_operation_id(operation_id)
        .map(|draft| draft.with_causal_ids(causal))
        .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from([]),
    })
}

/// Exact source-consumable operation-result representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationResultEventKindV1 {
    /// The sole `Unit` result, which has no protected value bytes.
    Unit,
    /// An ordinary normalized operation value.
    Value,
    /// A normalized sealed `Decision`.
    Decision,
    /// An explicit `Err(OperationError)` produced by `attempt`.
    AttemptError,
}

/// Builds the one logical `operation-result` event for a source-consumable result.
pub fn operation_result_event(
    operation_id: ProtocolIdentity,
    ty: &TypeDescriptor,
    kind: OperationResultEventKindV1,
    normalized: Option<&LogicalValue>,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    let (wire_kind, outcome_variant, class) = match kind {
        OperationResultEventKindV1::Unit => ("unit", "ok", None),
        OperationResultEventKindV1::Value => (
            "value",
            "ok",
            Some(ProtectedReferenceClass::NormalizedValue),
        ),
        OperationResultEventKindV1::Decision => (
            "decision",
            "ok",
            Some(ProtectedReferenceClass::NormalizedDecision),
        ),
        OperationResultEventKindV1::AttemptError => (
            "operation-error",
            "err",
            Some(ProtectedReferenceClass::NormalizedOperationError),
        ),
    };
    if class.is_some() != normalized.is_some() {
        return Err(OperationEventDraftError::ResultShape);
    }
    let mut references = Vec::new();
    let mut payloads = Vec::new();
    let protected_value = class
        .zip(normalized)
        .map(|(class, value)| {
            protected(
                format!("operation:{operation_id}:normalized-result"),
                class,
                Arc::from(value.canonical_json().bytes()),
            )
        })
        .transpose()?;
    let mut json = String::from("{\"operation_id\":");
    push_json_string(&mut json, &operation_id.to_string());
    json.push_str(",\"operation_result_reference\":");
    push_json_string(&mut json, &format!("operation:{operation_id}:result"));
    json.push_str(",\"outcome_reference\":");
    push_json_string(&mut json, &format!("operation:{operation_id}:outcome"));
    json.push_str(",\"outcome_variant\":");
    push_json_string(&mut json, outcome_variant);
    json.push_str(",\"result_kind\":");
    push_json_string(&mut json, wire_kind);
    json.push_str(",\"type\":");
    push_json_string(&mut json, &ty.canonical_string());
    if let Some((reference, payload)) = protected_value {
        json.push_str(",\"value_reference\":");
        push_json_string(&mut json, reference.key());
        references.push(reference);
        payloads.push(payload);
    }
    json.push('}');
    let draft = EventDraft::new(
        gantry_core::portable::EventKind::OperationResult,
        event_payload(json),
    )
    .with_operation_id(operation_id)
    .and_then(|draft| draft.with_protected_references(references))
    .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from(payloads),
    })
}

/// Maps root lifecycle machine labels to their exact logical event drafts.
///
/// Deterministic, operation-preparation, and operation-result labels require
/// richer typed context and therefore use their dedicated builders.
pub fn machine_lifecycle_event(
    label: &MachineLabel,
    execution_id: ProtocolIdentity,
    task_id: ProtocolIdentity,
) -> Option<ExecutionEventDraftV1> {
    let (kind, payload, causal) = match label {
        MachineLabel::Cancellation { reason } => {
            let mut json = String::from("{\"reason\":");
            push_json_string(&mut json, reason);
            json.push_str(",\"state\":\"requested\",\"target\":");
            push_json_string(&mut json, &execution_id.to_string());
            json.push_str(",\"target_kind\":\"execution\"}");
            (
                gantry_core::portable::EventKind::Cancellation,
                json,
                vec![execution_id],
            )
        }
        MachineLabel::Failure(failure) => (
            gantry_core::portable::EventKind::Failure,
            failure_payload(failure),
            vec![task_id],
        ),
        MachineLabel::TaskSettled(outcome) => (
            gantry_core::portable::EventKind::TaskCompletion,
            completion_payload("task_id", task_id, outcome),
            vec![task_id],
        ),
        MachineLabel::ForegroundCompletion(outcome) => (
            gantry_core::portable::EventKind::ForegroundCompletion,
            completion_payload("execution_id", execution_id, outcome),
            vec![task_id],
        ),
        MachineLabel::TerminalCompletion(outcome) => {
            let mut json = completion_payload("execution_id", execution_id, outcome);
            json.pop();
            json.push_str(",\"terminal_execution_reference\":");
            push_json_string(&mut json, &format!("execution:{execution_id}:terminal"));
            json.push('}');
            (
                gantry_core::portable::EventKind::TerminalExecution,
                json,
                vec![task_id],
            )
        }
        MachineLabel::Deterministic { .. }
        | MachineLabel::OperationPrepared(_)
        | MachineLabel::OperationResult { .. } => return None,
    };
    Some(ExecutionEventDraftV1 {
        draft: EventDraft::new(kind, event_payload(payload)).with_causal_ids(causal),
        protected_payloads: Arc::from([]),
    })
}

/// Dynamic workflow-frame event phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowEventPhaseV1 {
    /// One workflow frame became active.
    Start,
    /// One workflow frame settled.
    End,
}

/// Builds one logical workflow-frame event.
pub fn workflow_event(
    phase: WorkflowEventPhaseV1,
    workflow: &gantry_ir::CanonicalPath,
    frame_occurrence: &str,
    completion_status: &str,
    result: Option<(&TypeDescriptor, &LogicalValue)>,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    if frame_occurrence.is_empty()
        || completion_status.is_empty()
        || matches!(phase, WorkflowEventPhaseV1::Start) && result.is_some()
    {
        return Err(OperationEventDraftError::InvalidContext);
    }
    let mut references = Vec::new();
    let mut payloads = Vec::new();
    let protected_result = result
        .map(|(_, value)| {
            protected(
                format!("workflow:{}:{frame_occurrence}:result", workflow.as_str()),
                ProtectedReferenceClass::NormalizedValue,
                Arc::from(value.canonical_json().bytes()),
            )
        })
        .transpose()?;
    let mut json = String::from("{\"completion_status\":");
    push_json_string(&mut json, completion_status);
    json.push_str(",\"frame_occurrence\":");
    push_json_string(&mut json, frame_occurrence);
    if let (Some((ty, _)), Some((reference, payload))) = (result, protected_result) {
        json.push_str(",\"result_reference\":");
        push_json_string(&mut json, reference.key());
        json.push_str(",\"result_type\":");
        push_json_string(&mut json, &ty.canonical_string());
        references.push(reference);
        payloads.push(payload);
    }
    json.push_str(",\"workflow_path\":");
    push_json_string(&mut json, workflow.as_str());
    json.push('}');
    let kind = match phase {
        WorkflowEventPhaseV1::Start => gantry_core::portable::EventKind::WorkflowStart,
        WorkflowEventPhaseV1::End => gantry_core::portable::EventKind::WorkflowEnd,
    };
    let draft = EventDraft::new(kind, event_payload(json))
        .with_protected_references(references)
        .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from(payloads),
    })
}

/// Exact condition evidence for one selected branch transition.
#[derive(Clone, Copy, Debug)]
pub enum BranchConditionV1<'a> {
    /// An ordinary Boolean condition.
    Bool(bool),
    /// A pattern condition and whether it matched.
    Pattern(bool),
    /// A sealed Decision whose visible fields remain protected.
    Decision {
        /// Logical decide operation that produced the value.
        operation_id: ProtocolIdentity,
        /// Complete normalized Decision value.
        value: &'a LogicalValue,
    },
}

/// Builds one logical branch, match, or loop selection event.
pub fn branch_decision_event(
    identity: &str,
    selected_transition: &str,
    condition: BranchConditionV1<'_>,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    if identity.is_empty() || selected_transition.is_empty() {
        return Err(OperationEventDraftError::InvalidContext);
    }
    let mut references = Vec::new();
    let mut payloads = Vec::new();
    let mut json = String::from("{\"condition_kind\":");
    match condition {
        BranchConditionV1::Bool(outcome) => {
            push_json_string(&mut json, "bool");
            json.push_str(",\"condition_outcome\":");
            json.push_str(if outcome { "true" } else { "false" });
        }
        BranchConditionV1::Pattern(outcome) => {
            push_json_string(&mut json, "pattern");
            json.push_str(",\"condition_outcome\":");
            json.push_str(if outcome { "true" } else { "false" });
        }
        BranchConditionV1::Decision {
            operation_id,
            value,
        } => {
            if operation_id.kind() != IdentityKind::Operation {
                return Err(OperationEventDraftError::InvalidContext);
            }
            push_json_string(&mut json, "decision");
            json.push_str(",\"decision_operation_id\":");
            push_json_string(&mut json, &operation_id.to_string());
            let (reference, payload) = protected(
                format!("operation:{operation_id}:normalized-decision"),
                ProtectedReferenceClass::NormalizedDecision,
                Arc::from(value.canonical_json().bytes()),
            )?;
            json.push_str(",\"decision_reference\":");
            push_json_string(&mut json, reference.key());
            references.push(reference);
            payloads.push(payload);
        }
    }
    json.push_str(",\"identity\":");
    push_json_string(&mut json, identity);
    json.push_str(",\"selected_transition\":");
    push_json_string(&mut json, selected_transition);
    json.push('}');
    let draft = EventDraft::new(
        gantry_core::portable::EventKind::BranchDecision,
        event_payload(json),
    )
    .with_protected_references(references)
    .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from(payloads),
    })
}

/// Builds one successful source assignment event.
pub fn mutation_event(
    task_id: ProtocolIdentity,
    target_path: &str,
    ty: &TypeDescriptor,
    value: &LogicalValue,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    if task_id.kind() != IdentityKind::Task || target_path.is_empty() {
        return Err(OperationEventDraftError::InvalidContext);
    }
    let (reference, payload) = protected(
        format!("task:{task_id}:mutation:{target_path}"),
        ProtectedReferenceClass::NormalizedValue,
        Arc::from(value.canonical_json().bytes()),
    )?;
    let mut json = String::from("{\"committed_value_reference\":");
    push_json_string(&mut json, reference.key());
    json.push_str(",\"static_type\":");
    push_json_string(&mut json, &ty.canonical_string());
    json.push_str(",\"target_path\":");
    push_json_string(&mut json, target_path);
    json.push_str(",\"task_id\":");
    push_json_string(&mut json, &task_id.to_string());
    json.push('}');
    let draft = EventDraft::new(
        gantry_core::portable::EventKind::Mutation,
        event_payload(json),
    )
    .with_causal_ids([task_id])
    .with_protected_references(vec![reference])
    .map_err(OperationEventDraftError::Contract)?;
    Ok(ExecutionEventDraftV1 {
        draft,
        protected_payloads: Arc::from([payload]),
    })
}

/// Complete nondurable shutdown occurrence summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownEventSummaryV1 {
    /// Shutdown invocation activity identity.
    pub activity_id: ProtocolIdentity,
    /// Effective graceful-shutdown duration in whole microseconds.
    pub graceful_us: u64,
    /// Effective post-cancellation drain duration in whole microseconds.
    pub drain_us: u64,
    /// Executions observed when shutdown began.
    pub executions_at_start: u64,
    /// Tasks observed when shutdown began.
    pub tasks_at_start: u64,
    /// Executions admitted into the cohort after shutdown began.
    pub admitted_after_start: u64,
    /// Work that completed naturally.
    pub completed_naturally: u64,
    /// Work settled through cancellation.
    pub cancelled: u64,
    /// Work stopped through executor abortion.
    pub aborted: u64,
    /// Stable required-state commit status.
    pub required_state_commit_status: Arc<str>,
    /// Stable shutdown-report reference.
    pub shutdown_report_reference: Arc<str>,
}

/// Builds the final physical event for one nondurable shutdown invocation.
pub fn shutdown_event(
    summary: &ShutdownEventSummaryV1,
) -> Result<ExecutionEventDraftV1, OperationEventDraftError> {
    if summary.activity_id.kind() != IdentityKind::Activity
        || summary.required_state_commit_status.is_empty()
        || summary.shutdown_report_reference.is_empty()
    {
        return Err(OperationEventDraftError::InvalidContext);
    }
    let mut json = String::from("{\"aborted_count\":");
    json.push_str(&summary.aborted.to_string());
    json.push_str(",\"admitted_after_start_count\":");
    json.push_str(&summary.admitted_after_start.to_string());
    json.push_str(",\"cancelled_count\":");
    json.push_str(&summary.cancelled.to_string());
    json.push_str(",\"completed_naturally_count\":");
    json.push_str(&summary.completed_naturally.to_string());
    json.push_str(",\"drain_us\":");
    json.push_str(&summary.drain_us.to_string());
    json.push_str(",\"executions_at_start\":");
    json.push_str(&summary.executions_at_start.to_string());
    json.push_str(",\"graceful_us\":");
    json.push_str(&summary.graceful_us.to_string());
    json.push_str(",\"required_state_commit_status\":");
    push_json_string(&mut json, &summary.required_state_commit_status);
    json.push_str(",\"shutdown_activity_id\":");
    push_json_string(&mut json, &summary.activity_id.to_string());
    json.push_str(",\"shutdown_report_reference\":");
    push_json_string(&mut json, &summary.shutdown_report_reference);
    json.push_str(",\"tasks_at_start\":");
    json.push_str(&summary.tasks_at_start.to_string());
    json.push('}');
    Ok(ExecutionEventDraftV1 {
        draft: EventDraft::new(
            gantry_core::portable::EventKind::Shutdown,
            event_payload(json),
        )
        .with_causal_ids([summary.activity_id]),
        protected_payloads: Arc::from([]),
    })
}

fn completion_payload(
    identity_field: &str,
    identity: ProtocolIdentity,
    outcome: &MachineOutcome,
) -> String {
    let mut json = String::from("{\"completion_category\":");
    push_json_string(&mut json, completion_category(outcome));
    if identity_field == "execution_id" {
        json.push_str(",\"execution_id\":");
        push_json_string(&mut json, &identity.to_string());
    }
    match outcome {
        MachineOutcome::Succeeded(_) => {
            json.push_str(",\"result_reference\":");
            push_json_string(&mut json, &format!("{identity}:result"));
        }
        MachineOutcome::Failed(failure) => {
            json.push_str(",\"failure_reference\":");
            push_json_string(
                &mut json,
                &format!(
                    "failure:{}:{}:{}",
                    failure.workflow.as_str(),
                    position(&failure.site),
                    failure.code.wire_name()
                ),
            );
        }
        MachineOutcome::Cancelled(_) => {}
    }
    if identity_field == "task_id" {
        json.push_str(",\"task_id\":");
        push_json_string(&mut json, &identity.to_string());
    }
    json.push('}');
    json
}

fn completion_category(outcome: &MachineOutcome) -> &'static str {
    match outcome {
        MachineOutcome::Succeeded(_) => "success",
        MachineOutcome::Failed(failure) => runtime_category(failure.code),
        MachineOutcome::Cancelled(_) => "cancellation",
    }
}

fn failure_payload(failure: &MachineFailure) -> String {
    let mut json = String::from("{\"code\":");
    push_json_string(&mut json, failure.code.wire_name());
    json.push_str(",\"diagnostic\":{\"redacted\":true},\"runtime_error_category\":");
    push_json_string(&mut json, runtime_category(failure.code));
    json.push_str(",\"site\":{\"position\":[");
    for (index, component) in failure.site.components().iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&component.to_string());
    }
    json.push_str("],\"workflow\":");
    push_json_string(&mut json, failure.workflow.as_str());
    json.push_str("}}");
    json
}

fn runtime_category(code: RuntimeCode) -> &'static str {
    match code {
        RuntimeCode::Operation(category) => category.wire_name(),
        RuntimeCode::InternalInvariant | RuntimeCode::UnsupportedEffect => {
            "internal-invariant-failure"
        }
        RuntimeCode::Deterministic(_)
        | RuntimeCode::DeterministicTransitionBudget
        | RuntimeCode::OperationBudget
        | RuntimeCode::LoopIterationBudget
        | RuntimeCode::LoopLimitExhausted => "deterministic-evaluation-failure",
    }
}

fn position(site: &gantry_ir::StructuralPosition) -> String {
    site.components()
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn protected(
    key: String,
    class: ProtectedReferenceClass,
    bytes: Arc<[u8]>,
) -> Result<(ProtectedReference, ProtectedPayload), OperationEventDraftError> {
    let reference = ProtectedReference::new(Arc::<str>::from(key), class)
        .map_err(OperationEventDraftError::Contract)?;
    let payload = ProtectedPayload {
        reference: reference.clone(),
        bytes,
    };
    Ok((reference, payload))
}

fn require_diagnostic(
    captured: &CapturedOperationRequestV1,
    value: &Arc<str>,
    category: Option<HookFailureCategory>,
) -> Result<(), OperationEventDraftError> {
    let header = captured.header();
    let valid_unknown = category != Some(HookFailureCategory::UnknownOutcome)
        || matches!(captured, CapturedOperationRequestV1::Action { .. });
    let bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
    let scalars = u64::try_from(value.chars().count()).unwrap_or(u64::MAX);
    if value.is_empty()
        || bytes > header.maximum_hook_output_bytes
        || scalars > header.value_limits.maximum_string_scalars()
        || !valid_unknown
    {
        return Err(OperationEventDraftError::HookContractViolation);
    }
    Ok(())
}

fn event_payload(json: String) -> EventPayload {
    EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(json.into_bytes()))
        .unwrap_or_else(|_| unreachable!("runtime event payload is nonempty"))
}

fn result_kind(kind: TypeKind) -> &'static str {
    match kind {
        TypeKind::Unit => "unit",
        TypeKind::Decision => "decision",
        _ => "value",
    }
}

fn session_directive(session: &crate::ModelSessionUseV1) -> &str {
    match session {
        crate::ModelSessionUseV1::Inline => "inline",
        crate::ModelSessionUseV1::Create { mode, .. } => mode,
    }
}

fn push_validation_errors(output: &mut String, errors: &[ValidationErrorV1]) {
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"category\":");
        push_json_string(output, validation_category(error.category));
        if let Some(location) = &error.instance_location {
            output.push_str(",\"instance_location\":");
            push_json_string(output, location);
        }
        output.push_str(",\"message\":");
        push_json_string(output, &error.message);
        if let Some(location) = &error.schema_location {
            output.push_str(",\"schema_location\":");
            push_json_string(output, location);
        }
        output.push('}');
    }
}

fn validation_category(category: ValidationErrorCategoryV1) -> &'static str {
    match category {
        ValidationErrorCategoryV1::Utf8 => "utf8",
        ValidationErrorCategoryV1::JsonSyntax => "json-syntax",
        ValidationErrorCategoryV1::JsonDuplicateKey => "json-duplicate-key",
        ValidationErrorCategoryV1::JsonUnicode => "json-unicode",
        ValidationErrorCategoryV1::Schema => "schema",
        ValidationErrorCategoryV1::ResourceLimit => "resource-limit",
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

/// Execution-wide consequence of settling one nondurable event occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionDeliveryConsequenceV1 {
    /// This event introduced no required-delivery failure.
    Continue,
    /// Required delivery failed before terminal settlement and cancellation was signalled.
    ExecutionCancellationStarted(RequiredEventDeliveryFailureV1),
    /// Required delivery failed while an earlier cancellation was already effective.
    ExecutionCancellationAlreadyActive(RequiredEventDeliveryFailureV1),
    /// Required delivery failed after the language terminal outcome was already fixed.
    PostTerminalBarrier {
        /// Delivery failure reported separately from the language outcome.
        failure: RequiredEventDeliveryFailureV1,
        /// Existing terminal language outcome, retained without replacement.
        terminal: MachineOutcome,
    },
}

/// Completed event, finite delivery settlements, and execution consequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEventOutcomeV1 {
    /// Immutable standard event occurrence.
    pub event: EventEnvelope,
    /// Required and best-effort settlements in canonical sink order.
    pub delivery: ActivityDeliveryResult,
    /// Runtime-owned execution consequence.
    pub consequence: ExecutionDeliveryConsequenceV1,
}

/// Failure before one execution event can be fully completed and settled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionEventError {
    /// Activity, task, or execution identity has the wrong exact kind.
    IdentityKind,
    /// The per-task event sequence exhausted its portable counter.
    TaskSequenceExhausted,
    /// Required delivery failed, so only termination-consequence events remain enabled.
    NonconsequenceAfterRequiredFailure,
    /// Typed event context violated the portable event contract.
    Contract(EventContractError),
    /// Event identity allocation, timestamping, or completion failed.
    Completion(EventCompletionError),
    /// Protected projection or finite delivery driving failed.
    Delivery(DeliveryError),
    /// The lifecycle owner rejected an internal execution transition.
    Lifecycle(crate::ExecutionTransitionError),
    /// The accepted execution disappeared from its lifecycle owner.
    ExecutionNotFound,
}

/// Runtime owner for one nondurable execution activity's event stream.
///
/// The pipeline adds execution and root-task causality, completes occurrences
/// through `gantry-observe`, drives the frozen sink plan, and applies the
/// required-delivery cancellation boundary. It never places protected bytes in
/// the ordinary event envelope.
pub struct ExecutionEventPipeline<'a> {
    handle: ExecutionHandle,
    execution_id: ProtocolIdentity,
    activity_id: ProtocolIdentity,
    task_id: ProtocolIdentity,
    completer: EventCompleter<'a>,
    delivery: DeliveryKernel<'a>,
    active_plan: SinkPlan,
    next_task_sequence: Option<u64>,
    required_failures: Vec<RequiredEventDeliveryFailureV1>,
}

impl<'a> ExecutionEventPipeline<'a> {
    /// Binds one accepted execution to occurrence and delivery services.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle: &ExecutionHandle,
        activity_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        allocator: &'a FreshIdentityAllocator,
        identity_source: &'a dyn IdentitySource,
        clock: &'a dyn UtcClock,
        delivery_runtime: &'a dyn EventDeliveryRuntime,
        plan: SinkPlan,
    ) -> Result<Self, ExecutionEventError> {
        let execution_id = handle.execution_id();
        if execution_id.kind() != IdentityKind::Execution
            || activity_id.kind() != IdentityKind::Activity
            || task_id.kind() != IdentityKind::Task
        {
            return Err(ExecutionEventError::IdentityKind);
        }
        Ok(Self {
            handle: handle.clone(),
            execution_id,
            activity_id,
            task_id,
            completer: EventCompleter::new(allocator, identity_source, clock),
            delivery: DeliveryKernel::new(allocator, identity_source, delivery_runtime),
            active_plan: plan,
            next_task_sequence: Some(0),
            required_failures: Vec::new(),
        })
    }

    /// Returns the immutable execution identity attached to every event.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns required-delivery failures in occurrence order.
    #[must_use]
    pub fn required_failures(&self) -> &[RequiredEventDeliveryFailureV1] {
        &self.required_failures
    }

    /// Completes and settles one typed root-task event and its protected side bundle.
    pub async fn emit_task_draft(
        &mut self,
        event: ExecutionEventDraftV1,
    ) -> Result<ExecutionEventOutcomeV1, ExecutionEventError> {
        self.emit_task_event(event.draft, &event.protected_payloads)
            .await
    }

    /// Completes and settles one typed execution event and its protected side bundle.
    pub async fn emit_execution_draft(
        &mut self,
        event: ExecutionEventDraftV1,
    ) -> Result<ExecutionEventOutcomeV1, ExecutionEventError> {
        self.emit_execution_event(event.draft, &event.protected_payloads)
            .await
    }

    /// Completes and settles one root-task-backed event in per-task order.
    pub async fn emit_task_event(
        &mut self,
        draft: EventDraft,
        protected_payloads: &[ProtectedPayload],
    ) -> Result<ExecutionEventOutcomeV1, ExecutionEventError> {
        self.require_enabled_event(draft.kind())?;
        let sequence = self
            .next_task_sequence
            .ok_or(ExecutionEventError::TaskSequenceExhausted)?;
        let draft = draft
            .with_execution_id(self.execution_id)
            .and_then(|draft| draft.with_task(self.task_id, sequence))
            .map_err(ExecutionEventError::Contract)?;
        let event = self.complete(draft).await?;
        self.next_task_sequence = sequence.checked_add(1);
        self.deliver(event, protected_payloads).await
    }

    /// Completes and settles one execution-level event without a task sequence.
    pub async fn emit_execution_event(
        &mut self,
        draft: EventDraft,
        protected_payloads: &[ProtectedPayload],
    ) -> Result<ExecutionEventOutcomeV1, ExecutionEventError> {
        self.require_enabled_event(draft.kind())?;
        let draft = draft
            .with_execution_id(self.execution_id)
            .map_err(ExecutionEventError::Contract)?;
        let event = self.complete(draft).await?;
        self.deliver(event, protected_payloads).await
    }

    async fn complete(&self, draft: EventDraft) -> Result<EventEnvelope, ExecutionEventError> {
        self.completer
            .complete(self.activity_id, draft)
            .await
            .map_err(ExecutionEventError::Completion)
    }

    fn require_enabled_event(
        &self,
        kind: gantry_core::portable::EventKind,
    ) -> Result<(), ExecutionEventError> {
        if self.required_failures.is_empty()
            || matches!(
                kind,
                gantry_core::portable::EventKind::Cancellation
                    | gantry_core::portable::EventKind::Failure
                    | gantry_core::portable::EventKind::ForegroundCompletion
                    | gantry_core::portable::EventKind::TaskCompletion
                    | gantry_core::portable::EventKind::TerminalExecution
            )
        {
            Ok(())
        } else {
            Err(ExecutionEventError::NonconsequenceAfterRequiredFailure)
        }
    }

    async fn deliver(
        &mut self,
        event: EventEnvelope,
        protected_payloads: &[ProtectedPayload],
    ) -> Result<ExecutionEventOutcomeV1, ExecutionEventError> {
        let delivery = self
            .delivery
            .deliver(event.clone(), protected_payloads, &self.active_plan)
            .await
            .map_err(ExecutionEventError::Delivery)?;
        let consequence = match &delivery.barrier {
            ActivityBarrier::Delivered => ExecutionDeliveryConsequenceV1::Continue,
            ActivityBarrier::RequiredExhausted {
                sink_id,
                event_id,
                attempt_id,
            } => {
                let failure = RequiredEventDeliveryFailureV1 {
                    sink_id: sink_id.clone(),
                    event_id: *event_id,
                    attempt_id: *attempt_id,
                };
                self.active_plan = self.active_plan.without_sink(sink_id);
                self.required_failures.push(failure.clone());
                self.apply_required_failure(failure)?
            }
        };
        Ok(ExecutionEventOutcomeV1 {
            event,
            delivery,
            consequence,
        })
    }

    fn apply_required_failure(
        &self,
        failure: RequiredEventDeliveryFailureV1,
    ) -> Result<ExecutionDeliveryConsequenceV1, ExecutionEventError> {
        match self
            .handle
            .record_required_delivery_failure(failure.clone())
            .map_err(ExecutionEventError::Lifecycle)?
        {
            RequiredDeliveryRecordV1::CancellationStarted => {
                Ok(ExecutionDeliveryConsequenceV1::ExecutionCancellationStarted(failure))
            }
            RequiredDeliveryRecordV1::CancellationAlreadyActive => {
                Ok(ExecutionDeliveryConsequenceV1::ExecutionCancellationAlreadyActive(failure))
            }
            RequiredDeliveryRecordV1::PostTerminal(terminal) => {
                Ok(ExecutionDeliveryConsequenceV1::PostTerminalBarrier { failure, terminal })
            }
            RequiredDeliveryRecordV1::Existing => Ok(ExecutionDeliveryConsequenceV1::Continue),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use gantry_core::canonical_json::CanonicalJson;
    use gantry_core::event::{EventPayload, EventVersion};
    use gantry_core::portable::{DeliveryOutcome, EventKind, JitterMode, SinkClass};
    use gantry_core::source::FrontendLimits;
    use gantry_core::strict_json::{JsonLimits, StrictJsonDocument};
    use gantry_core::timestamp::UtcTimestamp;
    use gantry_core::value::{LogicalValue, ValueLimits};
    use gantry_host::contracts::{
        ActionMappingRevision, DurationMicros, ExecutorAdapter, HostError, HostFuture,
    };
    use gantry_host::event::{
        EmergencyDiagnostic, EmergencyDiagnosticCallback, EventDeliveryRequest, EventRetryPolicy,
        EventSink, RedactionCapabilities, SinkDeliveryPolicy, SinkId,
    };
    use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
    use gantry_ir::{CanonicalPath, CanonicalSignature, StructuralPosition, TypeDescriptor};
    use gantry_observe::SinkRegistration;

    use super::*;
    use crate::{
        ActionOperationRequestV1, AdmissionKind, InterpreterConfiguration, InterpreterLifecycle,
        OperationRequestHeaderV1, RequiredConfiguration,
    };

    #[derive(Default)]
    struct Services {
        next: AtomicUsize,
    }

    impl IdentitySource for Services {
        fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
            let value = self.next.fetch_add(1, Ordering::AcqRel).saturating_add(1);
            let mut material = [0_u8; 32];
            material[..8].copy_from_slice(&value.to_be_bytes());
            Ok(material)
        }
    }

    impl ExecutorAdapter for Services {
        fn sleep<'b>(&'b self, _: DurationMicros) -> HostFuture<'b, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn yield_now<'b>(&'b self) -> HostFuture<'b, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn sample_inclusive(
            &self,
            range: gantry_host::contracts::InclusiveJitterRange,
        ) -> Result<u64, HostError> {
            Ok(range.minimum())
        }
    }

    impl UtcClock for Services {
        fn utc_now<'b>(&'b self) -> HostFuture<'b, Result<UtcTimestamp, HostError>> {
            Box::pin(async { UtcTimestamp::from_unix_seconds(0, 1).map_err(|_| failure("clock")) })
        }
    }

    impl EventDeliveryRuntime for Services {
        fn deliver_with_timeout<'b>(
            &'b self,
            sink: &'b dyn EventSink,
            request: EventDeliveryRequest,
            _: u64,
        ) -> HostFuture<'b, Result<DeliveryOutcome, HostError>> {
            sink.deliver(request)
        }

        fn sleep<'b>(&'b self, _: u64) -> HostFuture<'b, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn sample_full_jitter(&self, _: u64) -> Result<u64, HostError> {
            Ok(0)
        }
    }

    struct RecordingSink {
        outcome: DeliveryOutcome,
        calls: Mutex<Vec<EventDeliveryRequest>>,
    }

    impl RecordingSink {
        fn new(outcome: DeliveryOutcome) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().map_or(0, |calls| calls.len())
        }
    }

    impl EventSink for RecordingSink {
        fn deliver<'b>(
            &'b self,
            request: EventDeliveryRequest,
        ) -> HostFuture<'b, Result<DeliveryOutcome, HostError>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| failure("sink-calls"))?
                    .push(request);
                Ok(self.outcome)
            })
        }
    }

    struct EmergencyCallback {
        reports: AtomicUsize,
        behavior: EmergencyBehavior,
    }

    #[derive(Clone, Copy)]
    enum EmergencyBehavior {
        Success,
        Failure,
        Panic,
        Pending,
    }

    impl EmergencyDiagnosticCallback for EmergencyCallback {
        fn report<'b>(
            &'b self,
            diagnostic: EmergencyDiagnostic,
        ) -> HostFuture<'b, Result<(), HostError>> {
            assert_eq!(diagnostic.code.as_ref(), "event-stream-unavailable");
            self.reports.fetch_add(1, Ordering::AcqRel);
            match self.behavior {
                EmergencyBehavior::Success => Box::pin(async { Ok(()) }),
                EmergencyBehavior::Failure => Box::pin(async { Err(failure("emergency-failure")) }),
                EmergencyBehavior::Panic => panic!("protected emergency callback payload"),
                EmergencyBehavior::Pending => Box::pin(std::future::pending()),
            }
        }
    }

    #[test]
    fn emergency_diagnostics_are_bounded_isolated_and_settlement_neutral() {
        let services = Services::default();
        let timeout = DurationMicros::new(1).unwrap_or_else(|| unreachable!());
        for behavior in [
            EmergencyBehavior::Success,
            EmergencyBehavior::Failure,
            EmergencyBehavior::Panic,
            EmergencyBehavior::Pending,
        ] {
            let callback = EmergencyCallback {
                reports: AtomicUsize::new(0),
                behavior,
            };
            block_on(report_emergency_diagnostic(
                &callback,
                "event-stream-unavailable",
                &services,
                timeout,
            ));
            assert_eq!(callback.reports.load(Ordering::Acquire), 1);
        }
    }

    #[test]
    fn operation_events_are_canonical_and_keep_protected_bytes_out_of_envelopes() {
        let services = Services::default();
        let allocator = FreshIdentityAllocator::default();
        let captured = action_request();
        let prepared = captured
            .prepare_dispatch(&allocator, &services, 0, 0, &[])
            .unwrap_or_else(|error| panic!("dispatch preparation failed: {error:?}"));

        let dispatch = operation_dispatch_event(&captured, &prepared, 0, 0)
            .unwrap_or_else(|error| panic!("dispatch event failed: {error:?}"));
        assert_eq!(dispatch.draft.kind(), EventKind::OperationDispatch);
        assert_eq!(dispatch.protected_payloads.len(), 2);
        assert_canonical(dispatch.draft.payload().canonical_bytes());
        let dispatch_text = std::str::from_utf8(dispatch.draft.payload().canonical_bytes())
            .unwrap_or_else(|error| panic!("dispatch payload was not UTF-8: {error}"));
        assert!(dispatch_text.contains("\"state\":\"prepared\""));
        assert!(!dispatch_text.contains("expected_json_schema"));
        assert!(!dispatch_text.contains("maximum_hook_output_bytes"));

        let secret = Arc::<[u8]>::from(&b"private raw output"[..]);
        let completion = operation_completion_event(
            &captured,
            prepared.dispatch_id,
            0,
            0,
            &HookOutcomeV1::Completed(Arc::clone(&secret)),
        )
        .unwrap_or_else(|error| panic!("completion event failed: {error:?}"));
        assert_eq!(completion.draft.kind(), EventKind::OperationCompletion);
        assert_eq!(completion.protected_payloads.len(), 1);
        assert_eq!(completion.protected_payloads[0].bytes, secret);
        assert_eq!(
            completion.protected_payloads[0].reference.class(),
            ProtectedReferenceClass::RawOutput
        );
        assert_canonical(completion.draft.payload().canonical_bytes());
        assert!(
            !std::str::from_utf8(completion.draft.payload().canonical_bytes())
                .unwrap_or_else(|error| panic!("completion payload was not UTF-8: {error}"))
                .contains("private raw output")
        );

        assert_eq!(
            operation_completion_event(
                &captured,
                prepared.dispatch_id,
                0,
                0,
                &HookOutcomeV1::Declined(Arc::from("")),
            ),
            Err(OperationEventDraftError::HookContractViolation)
        );
    }

    #[test]
    fn validation_failure_and_retry_events_preserve_physical_causality() {
        let operation = derived(IdentityKind::Operation, b"operation");
        let preceding = fresh(IdentityKind::Dispatch, 20);
        let next = fresh(IdentityKind::Dispatch, 21);
        let errors: Arc<[ValidationErrorV1]> = Arc::from([ValidationErrorV1 {
            category: ValidationErrorCategoryV1::Schema,
            instance_location: Some(Arc::from("/value")),
            message: Arc::from("expected a String"),
            schema_location: Some(Arc::from("/type")),
        }]);
        let validation = structured_output_validation_failure_event(operation, preceding, &errors)
            .unwrap_or_else(|error| panic!("validation event failed: {error:?}"));
        assert_eq!(
            validation.draft.kind(),
            EventKind::StructuredOutputValidationFailure
        );
        assert!(validation.protected_payloads.is_empty());
        assert_canonical(validation.draft.payload().canonical_bytes());

        let wait = OperationRetryWaitV1 {
            errors,
            delay: DurationMicros::new(17).unwrap_or_else(|| unreachable!()),
            next_validation_attempt: 2,
            recovery_dispatch: 3,
            retries_left: 4,
        };
        let retry = validation_retry_event(operation, preceding, Some(next), &wait)
            .unwrap_or_else(|error| panic!("retry event failed: {error:?}"));
        assert_eq!(retry.draft.kind(), EventKind::Retry);
        assert!(retry.protected_payloads.is_empty());
        assert_canonical(retry.draft.payload().canonical_bytes());
        let text = std::str::from_utf8(retry.draft.payload().canonical_bytes())
            .unwrap_or_else(|error| panic!("retry payload was not UTF-8: {error}"));
        assert!(text.contains("\"selected_delay_us\":17"));
        assert!(text.contains("\"validation_attempt\":2"));
    }

    #[test]
    fn logical_result_and_lifecycle_events_are_canonical_and_typed() {
        let operation = derived(IdentityKind::Operation, b"logical-result");
        let value = LogicalValue::string(
            "protected result",
            ValueLimits::new(8, 32, 32, 32).unwrap_or_else(|| panic!("value limits failed")),
        )
        .unwrap_or_else(|error| panic!("logical value failed: {error:?}"));
        let result = operation_result_event(
            operation,
            &TypeDescriptor::STRING,
            OperationResultEventKindV1::Value,
            Some(&value),
        )
        .unwrap_or_else(|error| panic!("operation-result event failed: {error:?}"));
        assert_eq!(result.draft.kind(), EventKind::OperationResult);
        assert_eq!(result.protected_payloads.len(), 1);
        assert_eq!(
            result.protected_payloads[0].reference.class(),
            ProtectedReferenceClass::NormalizedValue
        );
        assert_canonical(result.draft.payload().canonical_bytes());
        assert!(
            !std::str::from_utf8(result.draft.payload().canonical_bytes())
                .unwrap_or_else(|error| panic!("result payload was not UTF-8: {error}"))
                .contains("protected result")
        );
        assert_eq!(
            operation_result_event(
                operation,
                &TypeDescriptor::STRING,
                OperationResultEventKindV1::Value,
                None,
            ),
            Err(OperationEventDraftError::ResultShape)
        );

        let execution = fresh(IdentityKind::Execution, 40);
        let task = derived(IdentityKind::Task, b"root-task");
        let labels = [
            MachineLabel::Cancellation {
                reason: Arc::from("caller"),
            },
            MachineLabel::TaskSettled(MachineOutcome::Succeeded(LogicalValue::unit())),
            MachineLabel::ForegroundCompletion(MachineOutcome::Succeeded(LogicalValue::unit())),
            MachineLabel::TerminalCompletion(MachineOutcome::Succeeded(LogicalValue::unit())),
        ];
        let expected = [
            EventKind::Cancellation,
            EventKind::TaskCompletion,
            EventKind::ForegroundCompletion,
            EventKind::TerminalExecution,
        ];
        for (label, expected_kind) in labels.iter().zip(expected) {
            let event = machine_lifecycle_event(label, execution, task)
                .unwrap_or_else(|| panic!("lifecycle label had no event"));
            assert_eq!(event.draft.kind(), expected_kind);
            assert!(event.protected_payloads.is_empty());
            assert_canonical(event.draft.payload().canonical_bytes());
        }
    }

    #[test]
    fn source_machine_and_shutdown_events_are_canonical_and_protected() {
        let limits =
            ValueLimits::new(8, 32, 32, 32).unwrap_or_else(|| panic!("value limits failed"));
        let value = LogicalValue::string("private value", limits)
            .unwrap_or_else(|error| panic!("logical value failed: {error:?}"));
        let workflow = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("workflow path failed: {error}"));
        let workflow_end = workflow_event(
            WorkflowEventPhaseV1::End,
            &workflow,
            "frame:0",
            "succeeded",
            Some((&TypeDescriptor::STRING, &value)),
        )
        .unwrap_or_else(|error| panic!("workflow event failed: {error:?}"));
        assert_eq!(workflow_end.draft.kind(), EventKind::WorkflowEnd);
        assert_eq!(workflow_end.protected_payloads.len(), 1);
        assert_canonical(workflow_end.draft.payload().canonical_bytes());

        let branch = branch_decision_event("branch:0", "true", BranchConditionV1::Bool(true))
            .unwrap_or_else(|error| panic!("branch event failed: {error:?}"));
        assert_eq!(branch.draft.kind(), EventKind::BranchDecision);
        assert!(branch.protected_payloads.is_empty());
        assert_canonical(branch.draft.payload().canonical_bytes());

        let task = derived(IdentityKind::Task, b"root-task");
        let mutation = mutation_event(task, "record.name", &TypeDescriptor::STRING, &value)
            .unwrap_or_else(|error| panic!("mutation event failed: {error:?}"));
        assert_eq!(mutation.draft.kind(), EventKind::Mutation);
        assert_eq!(mutation.protected_payloads.len(), 1);
        assert_canonical(mutation.draft.payload().canonical_bytes());
        for event in [&workflow_end, &mutation] {
            assert!(
                !std::str::from_utf8(event.draft.payload().canonical_bytes())
                    .unwrap_or_else(|error| panic!("event payload was not UTF-8: {error}"))
                    .contains("private value")
            );
        }

        let shutdown = shutdown_event(&ShutdownEventSummaryV1 {
            activity_id: fresh(IdentityKind::Activity, 41),
            graceful_us: 30,
            drain_us: 5,
            executions_at_start: 2,
            tasks_at_start: 2,
            admitted_after_start: 1,
            completed_naturally: 1,
            cancelled: 1,
            aborted: 0,
            required_state_commit_status: Arc::from("not-applicable"),
            shutdown_report_reference: Arc::from("shutdown-report:1"),
        })
        .unwrap_or_else(|error| panic!("shutdown event failed: {error:?}"));
        assert_eq!(shutdown.draft.kind(), EventKind::Shutdown);
        assert!(shutdown.protected_payloads.is_empty());
        assert_canonical(shutdown.draft.payload().canonical_bytes());
    }

    #[test]
    fn required_exhaustion_cancels_execution_and_excludes_only_that_sink() {
        let services = Arc::new(Services::default());
        let configuration = configuration(services.clone());
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let execution = fresh(IdentityKind::Execution, 9);
        let mut admission = lifecycle
            .admit(AdmissionKind::NewWork)
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        let handle = admission
            .accept_execution(execution)
            .unwrap_or_else(|error| panic!("acceptance failed: {error:?}"));
        let failed = Arc::new(RecordingSink::new(DeliveryOutcome::Terminal));
        let healthy = Arc::new(RecordingSink::new(DeliveryOutcome::Success));
        let plan = SinkPlan::new(vec![
            SinkRegistration::new(sink_id("failed"), policy(), failed.clone()),
            SinkRegistration::new(sink_id("healthy"), policy(), healthy.clone()),
        ])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"));
        let allocator = FreshIdentityAllocator::default();
        let task = derived(IdentityKind::Task, b"root-task");
        let mut pipeline = ExecutionEventPipeline::new(
            &handle,
            fresh(IdentityKind::Activity, 8),
            task,
            &allocator,
            services.as_ref(),
            services.as_ref(),
            services.as_ref(),
            plan,
        )
        .unwrap_or_else(|error| panic!("pipeline failed: {error:?}"));

        let first = block_on(pipeline.emit_task_event(draft(EventKind::Mutation), &[]))
            .unwrap_or_else(|error| panic!("first event failed: {error:?}"));
        assert_eq!(first.event.version(), EventVersion::V1);
        assert_eq!(first.event.execution_id(), Some(execution));
        assert_eq!(first.event.task_id(), Some(task));
        assert_eq!(first.event.per_task_sequence(), Some(0));
        assert!(matches!(
            first.consequence,
            ExecutionDeliveryConsequenceV1::ExecutionCancellationStarted(_)
        ));
        let snapshot = lifecycle
            .query_execution(execution)
            .unwrap_or_else(|error| panic!("query failed: {error:?}"))
            .unwrap_or_else(|| panic!("accepted execution was absent"));
        assert!(snapshot.cancellation.is_some());
        assert_eq!(snapshot.required_delivery_failures.len(), 1);
        assert_eq!(
            snapshot.required_delivery_failures[0].event_id,
            first.event.event_id()
        );

        assert_eq!(
            block_on(pipeline.emit_task_event(draft(EventKind::Mutation), &[])),
            Err(ExecutionEventError::NonconsequenceAfterRequiredFailure)
        );

        let second = block_on(pipeline.emit_task_event(draft(EventKind::Cancellation), &[]))
            .unwrap_or_else(|error| panic!("second event failed: {error:?}"));
        assert_eq!(second.event.per_task_sequence(), Some(1));
        assert_eq!(failed.call_count(), 1);
        assert_eq!(healthy.call_count(), 2);
        assert_eq!(pipeline.required_failures().len(), 1);
    }

    #[test]
    fn required_exhaustion_after_terminal_preserves_the_language_outcome() {
        let services = Arc::new(Services::default());
        let configuration = configuration(services.clone());
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let execution = fresh(IdentityKind::Execution, 19);
        let mut admission = lifecycle
            .admit(AdmissionKind::NewWork)
            .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
        let handle = admission
            .accept_execution(execution)
            .unwrap_or_else(|error| panic!("acceptance failed: {error:?}"));
        let terminal = MachineOutcome::Succeeded(LogicalValue::unit());
        lifecycle
            .complete_foreground(&handle, terminal.clone())
            .unwrap_or_else(|error| panic!("foreground failed: {error:?}"));
        lifecycle
            .complete_terminal(&handle, terminal.clone())
            .unwrap_or_else(|error| panic!("terminal failed: {error:?}"));
        let failed = Arc::new(RecordingSink::new(DeliveryOutcome::Terminal));
        let plan = SinkPlan::new(vec![SinkRegistration::new(
            sink_id("failed"),
            policy(),
            failed,
        )])
        .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"));
        let allocator = FreshIdentityAllocator::default();
        let mut pipeline = ExecutionEventPipeline::new(
            &handle,
            fresh(IdentityKind::Activity, 18),
            derived(IdentityKind::Task, b"root-task"),
            &allocator,
            services.as_ref(),
            services.as_ref(),
            services.as_ref(),
            plan,
        )
        .unwrap_or_else(|error| panic!("pipeline failed: {error:?}"));
        let result =
            block_on(pipeline.emit_execution_event(draft(EventKind::TerminalExecution), &[]))
                .unwrap_or_else(|error| panic!("terminal event failed: {error:?}"));
        assert!(matches!(
            result.consequence,
            ExecutionDeliveryConsequenceV1::PostTerminalBarrier {
                terminal: MachineOutcome::Succeeded(_),
                ..
            }
        ));
        assert_eq!(
            lifecycle
                .query_execution(execution)
                .unwrap_or_else(|error| panic!("query failed: {error:?}"))
                .and_then(|snapshot| snapshot.terminal),
            Some(terminal)
        );
    }

    fn draft(kind: EventKind) -> EventDraft {
        let payload = EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(&b"{}"[..]))
            .unwrap_or_else(|error| panic!("payload failed: {error:?}"));
        EventDraft::new(kind, payload)
    }

    fn action_request() -> CapturedOperationRequestV1 {
        let path = CanonicalPath::new("crate::lookup")
            .unwrap_or_else(|error| panic!("action path failed: {error}"));
        CapturedOperationRequestV1::Action {
            header: OperationRequestHeaderV1 {
                execution_id: fresh(IdentityKind::Execution, 30),
                task_id: derived(IdentityKind::Task, b"root-task"),
                operation_id: derived(IdentityKind::Operation, b"operation"),
                kind: OperationSiteKind::Action,
                expected_type: TypeDescriptor::UNIT,
                expected_schema: Arc::from(&br#"{"type":"null"}"#[..]),
                maximum_hook_output_bytes: 1_024,
                value_limits: ValueLimits::new(8, 32, 32, 32)
                    .unwrap_or_else(|| panic!("value limits failed")),
                workflow: CanonicalPath::new("crate::main")
                    .unwrap_or_else(|error| panic!("workflow path failed: {error}")),
                site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("site failed: {error}")),
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
        }
    }

    fn assert_canonical(bytes: &[u8]) {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let document = StrictJsonDocument::decode(
            bytes,
            JsonLimits {
                maximum_bytes: length,
                maximum_nesting_depth: 32,
                maximum_nodes: length.max(1),
                maximum_string_scalars: length.max(1),
                maximum_list_items: length.max(1),
            },
        )
        .unwrap_or_else(|error| panic!("event payload decode failed: {error:?}"));
        let canonical = CanonicalJson::from_document(&document)
            .unwrap_or_else(|error| panic!("event payload canonicalization failed: {error:?}"));
        assert_eq!(canonical.bytes(), bytes);
    }

    fn policy() -> SinkDeliveryPolicy {
        let retry = EventRetryPolicy::new("retry-v1", 0, 0, 0, JitterMode::None)
            .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
        SinkDeliveryPolicy::new(
            SinkClass::Required,
            false,
            "redaction-v1",
            RedactionCapabilities::default(),
            retry,
            30,
        )
        .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"))
    }

    fn configuration(services: Arc<Services>) -> InterpreterConfiguration {
        let required = RequiredConfiguration::new(
            FrontendLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1)
                .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
            1,
            1,
            ValueLimits::new(8, 32, 32, 32).unwrap_or_else(|| panic!("value limits failed")),
            8,
            8,
            8,
            8,
        )
        .unwrap_or_else(|error| panic!("configuration failed: {error:?}"));
        InterpreterConfiguration::new(services.clone(), services, required)
    }

    fn sink_id(value: &str) -> SinkId {
        SinkId::new(value).unwrap_or_else(|error| panic!("sink ID failed: {error:?}"))
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("fresh identity failed: {error:?}"))
    }

    fn derived(kind: IdentityKind, key: &[u8]) -> ProtocolIdentity {
        ProtocolIdentity::derive(kind, key)
            .unwrap_or_else(|error| panic!("derived identity failed: {error:?}"))
    }

    fn failure(code: &'static str) -> HostError {
        HostError {
            code: Arc::from(code),
            protected_diagnostic: None,
        }
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
