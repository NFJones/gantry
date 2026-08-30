//! Public-facade conformance for sequential execution events and delivery barriers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::canonical_json::CanonicalJson;
use gantry::event::{EventDraft, EventPayload};
use gantry::host::contracts::{
    ActionMappingRevision, DurationMicros, ExecutorAdapter, FreshIdentityAllocator, HostError,
    HostFuture, IdentitySource, InclusiveJitterRange, UtcClock,
};
use gantry::host::event::{
    EmergencyDiagnostic, EmergencyDiagnosticCallback, EventDeliveryRequest, EventDeliveryRuntime,
    EventRetryPolicy, EventSink, RedactionCapabilities, SinkDeliveryPolicy, SinkId,
};
use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{CanonicalPath, CanonicalSignature, StructuralPosition, TypeDescriptor};
use gantry::portable::{
    DeliveryOutcome, EventKind, EventLayer, IdentityKind, JitterMode, ProtectedReferenceClass,
    SinkClass,
};
use gantry::runtime::{
    ActionOperationRequestV1, AdmissionKind, BranchConditionV1, CapturedOperationRequestV1,
    ExecutionDeliveryConsequenceV1, ExecutionEventError, ExecutionEventPipeline,
    InterpreterConfiguration, InterpreterLifecycle, MachineFailure, MachineLabel, MachineOutcome,
    OperationRequestHeaderV1, OperationResultEventKindV1, OperationRetryWaitV1,
    RequiredConfiguration, RuntimeCode, ShutdownEventSummaryV1, ValidationErrorCategoryV1,
    ValidationErrorV1, WorkflowEventPhaseV1, branch_decision_event, machine_lifecycle_event,
    mutation_event, operation_completion_event, operation_dispatch_event, operation_result_event,
    report_emergency_diagnostic, shutdown_event, structured_output_validation_failure_event,
    validation_retry_event, workflow_event,
};
use gantry::source::FrontendLimits;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::timestamp::UtcTimestamp;
use gantry::value::{LogicalValue, ValueLimits};
use gantry::{observe::ActivityBarrier, observe::SinkPlan, observe::SinkRegistration};
use serde::Deserialize;

const CATALOG_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_observation.rs#public_execution_event_catalog_is_typed_canonical_and_protected";
const DELIVERY_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_observation.rs#public_required_delivery_failure_is_isolated_nonrecursive_and_post_terminal_safe";
const EMERGENCY_EVIDENCE: &str = "crates/gantry-conformance/tests/execution_observation.rs#public_emergency_diagnostic_is_bounded_out_of_band_and_settlement_neutral";
const RETRY_EVIDENCE: &str = "crates/gantry-conformance/tests/activity_observation.rs#canonical_projection_and_retry_vectors_match_the_public_kernel";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
    profile: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewedRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewedRequirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

#[test]
fn reviewed_execution_observation_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/execution-observation-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.execution-observation-evidence/v1");
    assert_eq!(manifest.issue, "GNT-OBS-002");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            CATALOG_EVIDENCE | DELIVERY_EVIDENCE | EMERGENCY_EVIDENCE | RETRY_EVIDENCE
        ));
        entries
            .entry((entry.requirement, entry.clause, entry.profile))
            .or_default()
            .push(entry.evidence);
    }

    for ((requirement, clause_key, profile_name), evidence) in entries {
        let profile = review
            .requirements
            .iter()
            .find(|candidate| candidate.id == requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == clause_key)
            })
            .and_then(|clause| {
                clause
                    .profile_reviews
                    .iter()
                    .find(|profile| profile.profile == profile_name)
            })
            .unwrap_or_else(|| {
                panic!("missing {profile_name} review for {requirement}:{clause_key}")
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, evidence);
    }
}

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

impl UtcClock for Services {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async {
            UtcTimestamp::from_unix_seconds(0, 42).map_err(|_| host_error("clock-failure"))
        })
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

impl EventDeliveryRuntime for Services {
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        _: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        sink.deliver(request)
    }

    fn sleep<'a>(&'a self, _: u64) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_full_jitter(&self, _: u64) -> Result<u64, HostError> {
        Ok(0)
    }
}

struct ScriptedSink {
    outcomes: Mutex<VecDeque<DeliveryOutcome>>,
    calls: AtomicUsize,
}

impl ScriptedSink {
    fn new(outcomes: impl IntoIterator<Item = DeliveryOutcome>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl EventSink for ScriptedSink {
    fn deliver<'a>(
        &'a self,
        _: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(self
                .outcomes
                .lock()
                .map_err(|_| host_error("sink-state"))?
                .pop_front()
                .unwrap_or(DeliveryOutcome::Success))
        })
    }
}

struct PanickingEmergencyCallback {
    calls: AtomicUsize,
}

impl EmergencyDiagnosticCallback for PanickingEmergencyCallback {
    fn report<'a>(
        &'a self,
        diagnostic: EmergencyDiagnostic,
    ) -> HostFuture<'a, Result<(), HostError>> {
        assert_eq!(diagnostic.code.as_ref(), "event-stream-unavailable");
        self.calls.fetch_add(1, Ordering::AcqRel);
        panic!("protected emergency callback payload")
    }
}

#[test]
fn public_emergency_diagnostic_is_bounded_out_of_band_and_settlement_neutral() {
    let callback = PanickingEmergencyCallback {
        calls: AtomicUsize::new(0),
    };
    block_on(report_emergency_diagnostic(
        &callback,
        "event-stream-unavailable",
        &Services::default(),
        DurationMicros::new(1).unwrap_or_else(|| unreachable!()),
    ));
    assert_eq!(callback.calls.load(Ordering::Acquire), 1);
}

#[test]
fn public_execution_event_catalog_is_typed_canonical_and_protected() {
    let services = Services::default();
    let allocator = FreshIdentityAllocator::default();
    let captured = action_request();
    let prepared = captured
        .prepare_dispatch(&allocator, &services, 0, 0, &[])
        .unwrap_or_else(|error| panic!("dispatch preparation failed: {error:?}"));
    let operation = captured.header().operation_id;
    let task = captured.header().task_id;
    let execution = captured.header().execution_id;
    let workflow = captured.header().workflow.clone();
    let limits = captured.header().value_limits;
    let value = LogicalValue::string("protected result", limits)
        .unwrap_or_else(|error| panic!("logical value failed: {error:?}"));
    let decision = LogicalValue::decision(true, "protected rationale", limits)
        .unwrap_or_else(|error| panic!("decision failed: {error:?}"));
    let errors: Arc<[ValidationErrorV1]> = Arc::from([ValidationErrorV1 {
        category: ValidationErrorCategoryV1::Schema,
        instance_location: Some(Arc::from("/value")),
        message: Arc::from("expected a String"),
        schema_location: Some(Arc::from("/type")),
    }]);
    let wait = OperationRetryWaitV1 {
        errors: Arc::clone(&errors),
        delay: DurationMicros::new(17).unwrap_or_else(|| unreachable!()),
        next_validation_attempt: 1,
        recovery_dispatch: 0,
        retries_left: 0,
    };

    let mut events = vec![
        workflow_event(
            WorkflowEventPhaseV1::Start,
            &workflow,
            "frame:0",
            "running",
            None,
        )
        .unwrap_or_else(|error| panic!("workflow-start failed: {error:?}")),
        workflow_event(
            WorkflowEventPhaseV1::End,
            &workflow,
            "frame:0",
            "succeeded",
            Some((&TypeDescriptor::STRING, &value)),
        )
        .unwrap_or_else(|error| panic!("workflow-end failed: {error:?}")),
        operation_dispatch_event(&captured, &prepared, 0, 0)
            .unwrap_or_else(|error| panic!("operation-dispatch failed: {error:?}")),
        operation_completion_event(
            &captured,
            prepared.dispatch_id,
            0,
            0,
            &gantry::host::contracts::HookOutcomeV1::Completed(Arc::from(
                &b"private raw output"[..],
            )),
        )
        .unwrap_or_else(|error| panic!("operation-completion failed: {error:?}")),
        operation_result_event(
            operation,
            &TypeDescriptor::STRING,
            OperationResultEventKindV1::Value,
            Some(&value),
        )
        .unwrap_or_else(|error| panic!("operation-result failed: {error:?}")),
        structured_output_validation_failure_event(operation, prepared.dispatch_id, &errors)
            .unwrap_or_else(|error| panic!("validation event failed: {error:?}")),
        validation_retry_event(operation, prepared.dispatch_id, None, &wait)
            .unwrap_or_else(|error| panic!("retry event failed: {error:?}")),
        branch_decision_event("branch:0", "true", BranchConditionV1::Bool(true))
            .unwrap_or_else(|error| panic!("branch event failed: {error:?}")),
        branch_decision_event(
            "branch:decision",
            "true",
            BranchConditionV1::Decision {
                operation_id: operation,
                value: &decision,
            },
        )
        .unwrap_or_else(|error| panic!("decision branch event failed: {error:?}")),
        mutation_event(task, "record.name", &TypeDescriptor::STRING, &value)
            .unwrap_or_else(|error| panic!("mutation event failed: {error:?}")),
        shutdown_event(&ShutdownEventSummaryV1 {
            activity_id: fresh(IdentityKind::Activity, 41),
            graceful_us: 30,
            drain_us: 5,
            executions_at_start: 1,
            tasks_at_start: 1,
            admitted_after_start: 0,
            completed_naturally: 1,
            cancelled: 0,
            aborted: 0,
            required_state_commit_status: Arc::from("not-applicable"),
            shutdown_report_reference: Arc::from("shutdown-report:1"),
        })
        .unwrap_or_else(|error| panic!("shutdown event failed: {error:?}")),
    ];
    let failure = MachineFailure {
        code: RuntimeCode::OperationBudget,
        workflow,
        site: StructuralPosition::new(vec![9])
            .unwrap_or_else(|error| panic!("failure site failed: {error}")),
    };
    for label in [
        MachineLabel::Cancellation {
            reason: Arc::from("caller"),
        },
        MachineLabel::Failure(failure.clone()),
        MachineLabel::TaskSettled(MachineOutcome::Failed(failure.clone())),
        MachineLabel::ForegroundCompletion(MachineOutcome::Failed(failure.clone())),
        MachineLabel::TerminalCompletion(MachineOutcome::Failed(failure)),
    ] {
        events.push(
            machine_lifecycle_event(&label, execution, task)
                .unwrap_or_else(|| panic!("lifecycle label had no event")),
        );
    }

    let kinds = events
        .iter()
        .map(|event| event.draft.kind())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds,
        BTreeSet::from([
            EventKind::BranchDecision,
            EventKind::Cancellation,
            EventKind::Failure,
            EventKind::ForegroundCompletion,
            EventKind::Mutation,
            EventKind::OperationCompletion,
            EventKind::OperationDispatch,
            EventKind::OperationResult,
            EventKind::Retry,
            EventKind::Shutdown,
            EventKind::StructuredOutputValidationFailure,
            EventKind::TaskCompletion,
            EventKind::TerminalExecution,
            EventKind::WorkflowEnd,
            EventKind::WorkflowStart,
        ])
    );
    for event in &events {
        assert_canonical(event.draft.payload().canonical_bytes());
        assert_eq!(
            event.draft.kind().layer(),
            expected_layer(event.draft.kind())
        );
        let ordinary = std::str::from_utf8(event.draft.payload().canonical_bytes())
            .unwrap_or_else(|error| panic!("event payload was not UTF-8: {error}"));
        assert!(!ordinary.contains("private raw output"));
        assert!(!ordinary.contains("protected result"));
        assert!(!ordinary.contains("protected rationale"));
    }
    assert!(events.iter().any(|event| {
        event
            .protected_payloads
            .iter()
            .any(|payload| payload.reference.class() == ProtectedReferenceClass::RawOutput)
    }));
    assert!(events.iter().any(|event| {
        event
            .protected_payloads
            .iter()
            .any(|payload| payload.reference.class() == ProtectedReferenceClass::NormalizedDecision)
    }));
}

#[test]
fn public_required_delivery_failure_is_isolated_nonrecursive_and_post_terminal_safe() {
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let execution = fresh(IdentityKind::Execution, 50);
    let handle = accept(&lifecycle, execution);
    let failed = Arc::new(ScriptedSink::new([DeliveryOutcome::Terminal]));
    let healthy = Arc::new(ScriptedSink::new([
        DeliveryOutcome::Success,
        DeliveryOutcome::Success,
    ]));
    let plan = SinkPlan::new(vec![
        SinkRegistration::new(
            sink_id("failed"),
            policy(SinkClass::Required),
            failed.clone(),
        ),
        SinkRegistration::new(
            sink_id("healthy"),
            policy(SinkClass::Required),
            healthy.clone(),
        ),
    ])
    .unwrap_or_else(|error| panic!("sink plan failed: {error:?}"));
    let allocator = FreshIdentityAllocator::default();
    let task = derived(IdentityKind::Task, b"root-task");
    let mut pipeline = ExecutionEventPipeline::new(
        &handle,
        fresh(IdentityKind::Activity, 51),
        task,
        &allocator,
        services.as_ref(),
        services.as_ref(),
        services.as_ref(),
        plan,
    )
    .unwrap_or_else(|error| panic!("pipeline failed: {error:?}"));

    let first = block_on(pipeline.emit_task_event(event_draft(EventKind::Mutation), &[]))
        .unwrap_or_else(|error| panic!("first event failed: {error:?}"));
    assert!(matches!(
        first.delivery.barrier,
        ActivityBarrier::RequiredExhausted { .. }
    ));
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
        block_on(pipeline.emit_task_event(event_draft(EventKind::Mutation), &[])),
        Err(ExecutionEventError::NonconsequenceAfterRequiredFailure)
    );
    block_on(pipeline.emit_task_event(event_draft(EventKind::Cancellation), &[]))
        .unwrap_or_else(|error| panic!("consequence event failed: {error:?}"));
    assert_eq!(failed.calls(), 1);
    assert_eq!(healthy.calls(), 2);

    let terminal_execution = fresh(IdentityKind::Execution, 60);
    let terminal_handle = accept(&lifecycle, terminal_execution);
    let terminal = MachineOutcome::Succeeded(LogicalValue::unit());
    lifecycle
        .complete_foreground(&terminal_handle, terminal.clone())
        .unwrap_or_else(|error| panic!("foreground completion failed: {error:?}"));
    lifecycle
        .complete_terminal(&terminal_handle, terminal.clone())
        .unwrap_or_else(|error| panic!("terminal completion failed: {error:?}"));
    let terminal_sink = Arc::new(ScriptedSink::new([DeliveryOutcome::Terminal]));
    let terminal_plan = SinkPlan::new(vec![SinkRegistration::new(
        sink_id("terminal-failure"),
        policy(SinkClass::Required),
        terminal_sink.clone(),
    )])
    .unwrap_or_else(|error| panic!("terminal sink plan failed: {error:?}"));
    let mut terminal_pipeline = ExecutionEventPipeline::new(
        &terminal_handle,
        fresh(IdentityKind::Activity, 61),
        task,
        &allocator,
        services.as_ref(),
        services.as_ref(),
        services.as_ref(),
        terminal_plan,
    )
    .unwrap_or_else(|error| panic!("terminal pipeline failed: {error:?}"));
    let result = block_on(
        terminal_pipeline.emit_execution_event(event_draft(EventKind::TerminalExecution), &[]),
    )
    .unwrap_or_else(|error| panic!("terminal event failed: {error:?}"));
    assert!(matches!(
        result.consequence,
        ExecutionDeliveryConsequenceV1::PostTerminalBarrier {
            terminal: MachineOutcome::Succeeded(_),
            ..
        }
    ));
    let snapshot = lifecycle
        .query_execution(terminal_execution)
        .unwrap_or_else(|error| panic!("terminal query failed: {error:?}"))
        .unwrap_or_else(|| panic!("terminal execution was absent"));
    assert_eq!(snapshot.terminal, Some(terminal));
    assert_eq!(snapshot.required_delivery_failures.len(), 1);
    assert_eq!(terminal_sink.calls(), 1);
}

fn expected_layer(kind: EventKind) -> EventLayer {
    match kind {
        EventKind::OperationCompletion
        | EventKind::OperationDispatch
        | EventKind::Retry
        | EventKind::Shutdown
        | EventKind::StructuredOutputValidationFailure => EventLayer::Physical,
        EventKind::BranchDecision
        | EventKind::Cancellation
        | EventKind::Failure
        | EventKind::ForegroundCompletion
        | EventKind::Mutation
        | EventKind::OperationResult
        | EventKind::TaskCompletion
        | EventKind::TerminalExecution
        | EventKind::WorkflowEnd
        | EventKind::WorkflowStart => EventLayer::Logical,
        EventKind::Analysis
        | EventKind::Detach
        | EventKind::Join
        | EventKind::Parse
        | EventKind::Spawn => kind.layer(),
    }
}

fn action_request() -> CapturedOperationRequestV1 {
    let path = CanonicalPath::new("crate::lookup")
        .unwrap_or_else(|error| panic!("action path failed: {error}"));
    let value_limits =
        ValueLimits::new(8, 64, 64, 64).unwrap_or_else(|| panic!("value limits failed"));
    CapturedOperationRequestV1::Action {
        header: OperationRequestHeaderV1 {
            execution_id: fresh(IdentityKind::Execution, 1),
            task_id: derived(IdentityKind::Task, b"root-task"),
            operation_id: derived(IdentityKind::Operation, b"operation"),
            kind: OperationSiteKind::Action,
            expected_type: TypeDescriptor::STRING,
            expected_schema: Arc::from(&br#"{"type":"string"}"#[..]),
            maximum_hook_output_bytes: 1_024,
            value_limits,
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
                &TypeDescriptor::STRING,
            ),
            recovery: RecoveryClass::ReadOnly,
            mapping_revision: ActionMappingRevision::new("actions-v1")
                .unwrap_or_else(|error| panic!("mapping revision failed: {error:?}")),
            arguments: Vec::new(),
        },
    }
}

fn accept(
    lifecycle: &InterpreterLifecycle,
    execution: ProtocolIdentity,
) -> gantry::runtime::ExecutionHandle {
    let mut admission = lifecycle
        .admit(AdmissionKind::NewWork)
        .unwrap_or_else(|error| panic!("admission failed: {error:?}"));
    admission
        .accept_execution(execution)
        .unwrap_or_else(|error| panic!("acceptance failed: {error:?}"))
}

fn configuration(services: Arc<Services>) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1)
            .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1,
        1,
        ValueLimits::new(8, 64, 64, 64).unwrap_or_else(|| panic!("value limits failed")),
        8,
        8,
        8,
        8,
    )
    .unwrap_or_else(|error| panic!("configuration failed: {error:?}"));
    InterpreterConfiguration::new(services.clone(), services, required)
}

fn policy(class: SinkClass) -> SinkDeliveryPolicy {
    let retry = EventRetryPolicy::new("retry-v1", 0, 0, 0, JitterMode::None)
        .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
    SinkDeliveryPolicy::new(
        class,
        false,
        "redaction-v1",
        RedactionCapabilities::default(),
        retry,
        30,
    )
    .unwrap_or_else(|error| panic!("sink policy failed: {error:?}"))
}

fn event_draft(kind: EventKind) -> EventDraft {
    EventDraft::new(kind, event_payload(b"{}"))
}

fn event_payload(bytes: &[u8]) -> EventPayload {
    EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(bytes))
        .unwrap_or_else(|error| panic!("event payload failed: {error:?}"))
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
        .unwrap_or_else(|error| panic!("event canonicalization failed: {error:?}"));
    assert_eq!(canonical.bytes(), bytes);
}

fn sink_id(value: &str) -> SinkId {
    SinkId::new(value).unwrap_or_else(|error| panic!("sink identity failed: {error:?}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("fresh identity failed: {error:?}"))
}

fn derived(kind: IdentityKind, key: &[u8]) -> ProtocolIdentity {
    ProtocolIdentity::derive(kind, key)
        .unwrap_or_else(|error| panic!("derived identity failed: {error:?}"))
}

fn host_error(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
