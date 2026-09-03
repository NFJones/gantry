//! Public conformance coverage for concurrent sessions, cancellation, events, and shutdown state.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::canonical_json::CanonicalJson;
use gantry::host::contracts::{
    DurationMicros, EmbeddingVersion, ExecutorAdapter, HostError, HostFuture, HostRequest,
    HostResponse, IdentitySource, InclusiveJitterRange, IntegrationPreflight,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::TaskControlSiteKind;
use gantry::ir::{
    CanonicalPath, StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor,
};
use gantry::portable::{
    EventKind, ExecutorAbortResultKind, IdentityKind, RuntimeErrorCategory, TaskHandleState,
    TerminalOnlyCategory,
};
use gantry::runtime::{
    AdapterPoison, CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1,
    ConcurrentTaskStatusV1, ConcurrentTerminalCategoryV1, ConcurrentTerminalOutcomeV1,
    DetachedTaskFailureV1, InterpreterConfiguration, InterpreterLifecycle,
    LogicalSessionRegistryV1, MachineOutcome, OperationEventDraftError, RequiredConfiguration,
    SessionCreationModeV1, SessionEstablisher, TaskAbortResultV1, TaskCreationRequestV1,
    TaskFailureV1, TaskStateError, concurrent_detach_event, concurrent_detached_failure_event,
    concurrent_join_event, concurrent_spawn_event, concurrent_task_cancellation_event,
    concurrent_terminal_event, machine_lifecycle_event,
};
use gantry::source::FrontendLimits;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValueLimits};
use serde::Deserialize;

const SESSION_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_lifecycle.rs#public_spawned_sessions_establish_once_before_child_use";
const LIFECYCLE_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_lifecycle.rs#public_cancellation_abort_terminal_and_shutdown_cohorts_are_exact";
const EVENT_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_lifecycle.rs#public_concurrent_events_are_canonical_typed_and_causal";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    reviewed_clauses: Vec<ReviewedClauseLink>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct ReviewedClauseLink {
    requirement: String,
    clause: String,
    profile: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
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

#[derive(Debug, Deserialize)]
struct LifecycleVectors {
    format: String,
    task_statuses: Vec<String>,
    abort_results: Vec<String>,
    terminal_categories: Vec<String>,
    event_kinds: Vec<String>,
    cases: Vec<String>,
}

#[test]
fn checked_in_concurrent_lifecycle_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/concurrent-lifecycle-v1.json"));
    let vectors: LifecycleVectors =
        read_json(&root.join("protocol/goldens/concurrent-lifecycle-v1.json"));
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/concurrent-lifecycle-v1.schema.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.concurrent-lifecycle-evidence/v1");
    assert_eq!(manifest.issue, "GNT-CON-003");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(
        manifest
            .reviewed_clauses
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(manifest.exclusions.len(), 4);
    for capability in &manifest.capabilities {
        assert!(matches!(
            capability.evidence.as_str(),
            SESSION_EVIDENCE | LIFECYCLE_EVIDENCE | EVENT_EVIDENCE
        ));
    }
    for link in manifest.reviewed_clauses {
        if !evidence_is_current {
            continue;
        }
        let profile = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == link.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == link.clause)
            })
            .and_then(|clause| {
                clause
                    .profile_reviews
                    .iter()
                    .find(|profile| profile.profile == link.profile)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing {}:{} {} review",
                    link.requirement, link.clause, link.profile
                )
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, link.evidence);
    }

    assert_eq!(vectors.format, "gantry.concurrent-lifecycle-vectors/v1");
    assert_eq!(vectors.task_statuses.len(), 5);
    assert_eq!(
        vectors.abort_results,
        ["already-settled", "failed", "stopped"]
    );
    assert_eq!(
        vectors.terminal_categories,
        [
            "cancellation",
            "detached-task-failure",
            "runtime-error",
            "success"
        ]
    );
    assert_eq!(vectors.event_kinds.len(), 8);
    assert_eq!(vectors.cases.len(), 4);
    assert_eq!(schema["properties"]["format"]["const"], vectors.format);
}

#[test]
fn public_spawned_sessions_establish_once_before_child_use() {
    let execution = fresh(IdentityKind::Execution, 1);
    let root_task = derived(IdentityKind::Task, b"concurrent-root");
    let root_session = fresh(IdentityKind::Session, 2);
    let state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let mut scheduler = ConcurrentSchedulerV1::new(state);
    let child = scheduler
        .create_child(
            &mut sessions,
            request(root_task, root_session, "child", 0),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    let child_session = sessions
        .get(child.base_session_id)
        .unwrap_or_else(|| panic!("child fork session was absent"));
    assert_eq!(child_session.parent, Some(root_session));
    assert_eq!(child_session.transcript, CanonicalTranscriptV1::empty());

    let services = Arc::new(Services);
    let lifecycle = InterpreterLifecycle::new(&configuration(services));
    let preflight = RecordingPreflight::default();
    let mut establisher = SessionEstablisher::new(&lifecycle, &preflight, AdapterPoison::default());
    block_on(scheduler.establish_child_session(&sessions, &mut establisher, child.task_id))
        .unwrap_or_else(|error| panic!("child session establishment failed: {error:?}"));
    block_on(scheduler.establish_child_session(&sessions, &mut establisher, child.task_id))
        .unwrap_or_else(|error| panic!("idempotent establishment failed: {error:?}"));
    assert_eq!(preflight.calls.load(Ordering::Acquire), 1);
    let request = preflight
        .requests
        .lock()
        .map(|requests| requests.first().cloned())
        .unwrap_or_default()
        .unwrap_or_else(|| panic!("establishment request was absent"));
    let text = std::str::from_utf8(&request)
        .unwrap_or_else(|error| panic!("establishment request was not UTF-8: {error}"));
    assert!(text.contains(&child.base_session_id.to_string()));
    assert!(text.contains(&root_session.to_string()));
}

#[test]
fn public_cancellation_abort_terminal_and_shutdown_cohorts_are_exact() {
    let execution = fresh(IdentityKind::Execution, 3);
    let root_task = derived(IdentityKind::Task, b"lifecycle-root");
    let root_session = fresh(IdentityKind::Session, 4);
    let mut state = ConcurrentTaskStateV1::new(execution, root_task, 4)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);

    let attached = create_running(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "attached",
        0,
    );
    let failed = state
        .create_child(
            &mut sessions,
            request(root_task, root_session, "failed", 1),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("failed child creation failed: {error:?}"));
    state
        .resolve_submission(
            failed.task_id,
            Err(HostError {
                code: Arc::from("executor-stopped"),
                protected_diagnostic: None,
            }),
        )
        .unwrap_or_else(|error| panic!("failed submission settlement failed: {error:?}"));
    state
        .detach(
            root_task,
            &control(TaskControlSiteKind::Detach, "failed", 8),
            failed.handle_id,
        )
        .unwrap_or_else(|error| panic!("failed-child detach failed: {error:?}"));
    let background = create_running(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "background",
        2,
    );
    state
        .detach(
            root_task,
            &control(TaskControlSiteKind::Detach, "background", 9),
            background.handle_id,
        )
        .unwrap_or_else(|error| panic!("background detach failed: {error:?}"));

    let cohort = state.shutdown_cohort();
    assert_eq!(cohort.execution_id, execution);
    assert_eq!(cohort.foreground_task, Some(root_task));
    assert_eq!(cohort.attached_tasks, [attached.task_id]);
    assert_eq!(cohort.detached_tasks, [background.task_id]);
    assert_eq!(
        state.complete_foreground(MachineOutcome::Succeeded(LogicalValue::unit())),
        Err(TaskStateError::AttachedTasksPending)
    );

    assert_eq!(
        state
            .cancel_task_tree(root_task, "parent-failed")
            .unwrap_or_else(|error| panic!("task-tree cancellation failed: {error:?}")),
        [root_task, attached.task_id]
    );
    assert_eq!(state.task_cancellation_reason(background.task_id), None);
    assert!(
        state
            .cancel_task_tree(root_task, "later-reason")
            .unwrap_or_else(|error| panic!("repeat cancellation failed: {error:?}"))
            .is_empty()
    );
    assert_eq!(
        state
            .cancel_execution("caller")
            .unwrap_or_else(|error| panic!("execution cancellation failed: {error:?}")),
        [background.task_id]
    );
    assert_eq!(
        state.task_cancellation_reason(background.task_id),
        Some("caller")
    );
    assert!(
        state
            .cancel_execution("later-caller")
            .unwrap_or_else(|error| panic!("repeat execution cancellation failed: {error:?}"))
            .is_empty()
    );
    state
        .settle(
            attached.task_id,
            MachineOutcome::Succeeded(LogicalValue::unit()),
        )
        .unwrap_or_else(|error| panic!("attached settlement failed: {error:?}"));
    assert!(matches!(
        state.task(attached.task_id).map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Cancelled(reason)) if reason.as_ref() == "parent-failed"
    ));

    let foreground = MachineOutcome::Succeeded(LogicalValue::unit());
    state
        .complete_foreground(foreground.clone())
        .unwrap_or_else(|error| panic!("foreground completion failed: {error:?}"));
    assert_eq!(
        state.complete_terminal(),
        Err(TaskStateError::DetachedTasksPending)
    );
    assert_eq!(
        state
            .apply_abort_result(background.task_id, TaskAbortResultV1::Stopped)
            .unwrap_or_else(|error| panic!("background abort failed: {error:?}")),
        ExecutorAbortResultKind::Stopped
    );
    assert_eq!(
        state
            .apply_abort_result(background.task_id, TaskAbortResultV1::Stopped)
            .unwrap_or_else(|error| panic!("repeat abort failed: {error:?}")),
        ExecutorAbortResultKind::AlreadySettled
    );
    let terminal = state
        .complete_terminal()
        .unwrap_or_else(|error| panic!("terminal completion failed: {error:?}"));
    assert_eq!(terminal.foreground, foreground);
    assert_eq!(
        terminal.category,
        ConcurrentTerminalCategoryV1::TerminalOnly(TerminalOnlyCategory::DetachedTaskFailure)
    );
    assert_eq!(terminal.detached_failures.len(), 1);
    assert_eq!(terminal.detached_failures[0].task_id, failed.task_id);
    assert_eq!(state.shutdown_cohort().foreground_task, None);
    assert!(state.pending_task_ids().is_empty());
    assert!(
        state
            .cancel_execution("after-terminal")
            .unwrap_or_else(|error| panic!("post-terminal cancellation failed: {error:?}"))
            .is_empty()
    );
}

#[test]
fn public_concurrent_events_are_canonical_typed_and_causal() {
    let execution = fresh(IdentityKind::Execution, 5);
    let root_task = derived(IdentityKind::Task, b"event-root");
    let child_task = derived(IdentityKind::Task, b"event-child");
    let transition = gantry::runtime::TaskCreatedV1 {
        task_id: child_task,
        parent_task_id: root_task,
        workflow: path("crate::main"),
        spawn_site: site(7),
        spawn_occurrence: 3,
        result_type: TypeDescriptor::UNIT,
        attachment: TaskHandleState::Attached,
    };
    let spawn = concurrent_spawn_event(execution, &transition, 0)
        .unwrap_or_else(|error| panic!("spawn event failed: {error:?}"));
    let mut state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("event task state failed: {error:?}"));
    let root_session = fresh(IdentityKind::Session, 6);
    let mut sessions = session_registry(execution, root_session);
    let child = create_running(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "child",
        3,
    );
    let ownership = state
        .detach(
            root_task,
            &control(TaskControlSiteKind::Detach, "child", 7),
            child.handle_id,
        )
        .unwrap_or_else(|error| panic!("event detach failed: {error:?}"));
    let detach = concurrent_detach_event(execution, &ownership, 1)
        .unwrap_or_else(|error| panic!("detach event failed: {error:?}"));
    let join = concurrent_join_event(
        execution,
        root_task,
        TaskControlSiteKind::Join,
        &[child_task],
        "succeeded",
        Some(&TypeDescriptor::UNIT),
        None,
        2,
    )
    .unwrap_or_else(|error| panic!("join event failed: {error:?}"));
    let cancellation =
        concurrent_task_cancellation_event(execution, child_task, "parent-failed", false, 3)
            .unwrap_or_else(|error| panic!("cancellation event failed: {error:?}"));
    let failure = TaskFailureV1 {
        category: RuntimeErrorCategory::ExecutorFailure,
        code: Arc::from("executor-stopped"),
        protected_diagnostic: None,
    };
    let detached_failure = concurrent_detached_failure_event(
        execution,
        child_task,
        &[Arc::from("spawn:crate::main:7:3")],
        &failure,
        4,
    )
    .unwrap_or_else(|error| panic!("failure event failed: {error:?}"));
    let foreground = machine_lifecycle_event(
        &gantry::runtime::MachineLabel::ForegroundCompletion(MachineOutcome::Succeeded(
            LogicalValue::unit(),
        )),
        execution,
        root_task,
    )
    .unwrap_or_else(|| panic!("foreground event was absent"));
    let task_completion = machine_lifecycle_event(
        &gantry::runtime::MachineLabel::TaskSettled(
            MachineOutcome::Succeeded(LogicalValue::unit()),
        ),
        execution,
        child_task,
    )
    .unwrap_or_else(|| panic!("task-completion event was absent"));
    let terminal = ConcurrentTerminalOutcomeV1 {
        category: ConcurrentTerminalCategoryV1::TerminalOnly(
            TerminalOnlyCategory::DetachedTaskFailure,
        ),
        foreground: MachineOutcome::Succeeded(LogicalValue::unit()),
        detached_failures: vec![DetachedTaskFailureV1 {
            task_id: child_task,
            task_path: Arc::from([Arc::from("spawn:crate::main:7:3")]),
            failure,
        }],
    };
    let terminal = concurrent_terminal_event(execution, root_task, &terminal)
        .unwrap_or_else(|error| panic!("terminal event failed: {error:?}"));

    let events = [
        spawn,
        detach,
        join,
        cancellation,
        detached_failure,
        foreground,
        task_completion,
        terminal,
    ];
    let kinds = [
        EventKind::Spawn,
        EventKind::Detach,
        EventKind::Join,
        EventKind::Cancellation,
        EventKind::Failure,
        EventKind::ForegroundCompletion,
        EventKind::TaskCompletion,
        EventKind::TerminalExecution,
    ];
    for (event, kind) in events.iter().zip(kinds) {
        assert_eq!(event.draft.kind(), kind);
        assert!(event.protected_payloads.is_empty());
        assert_canonical(event.draft.payload().canonical_bytes());
    }
    assert_eq!(events[0].draft.causal_ids(), [root_task, child_task]);
    assert_eq!(events[7].draft.causal_ids(), [root_task, child_task]);
    let terminal_payload = std::str::from_utf8(events[7].draft.payload().canonical_bytes())
        .unwrap_or_else(|error| panic!("terminal payload was not UTF-8: {error}"));
    assert!(terminal_payload.contains("\"completion_category\":\"detached-task-failure\""));
    assert!(matches!(
        concurrent_join_event(
            execution,
            root_task,
            TaskControlSiteKind::Detach,
            &[child_task],
            "succeeded",
            None,
            None,
            4,
        ),
        Err(OperationEventDraftError::InvalidContext)
    ));
}

#[derive(Default)]
struct RecordingPreflight {
    calls: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl IntegrationPreflight for RecordingPreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::EstablishSession);
        self.calls.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request.canonical_bytes().to_vec());
        }
        Box::pin(async {
            HostResponse::new(
                EmbeddingVersion::V1,
                EmbeddingOperation::EstablishSession,
                Arc::from(&b"{\"result\":\"established\"}"[..]),
            )
            .map_err(|_| HostError {
                code: Arc::from("response-invariant"),
                protected_diagnostic: None,
            })
        })
    }
}

struct Services;

impl IdentitySource for Services {
    fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
        Ok([17; 32])
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

fn create_running(
    state: &mut ConcurrentTaskStateV1,
    sessions: &mut LogicalSessionRegistryV1,
    root_task: ProtocolIdentity,
    root_session: ProtocolIdentity,
    name: &str,
    occurrence: u64,
) -> gantry::runtime::TaskCreationV1 {
    let child = state
        .create_child(
            sessions,
            request(root_task, root_session, name, occurrence),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    state
        .resolve_submission(child.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("child submission failed: {error:?}"));
    child
}

fn request(
    parent_task_id: ProtocolIdentity,
    parent_session_id: ProtocolIdentity,
    handle_name: &str,
    occurrence: u64,
) -> TaskCreationRequestV1 {
    TaskCreationRequestV1 {
        parent_task_id,
        handle_name: Arc::from(handle_name),
        workflow: path("crate::main"),
        spawn_site: site(0),
        spawn_occurrence: occurrence,
        result_type: TypeDescriptor::UNIT,
        captures: Vec::new(),
        inherited_agent: Some(Arc::from("writer")),
        parent_session_id,
    }
}

fn control(kind: TaskControlSiteKind, handle: &str, position: u64) -> TaskControlSite {
    TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(position)),
        kind,
        handles: vec![Arc::from(handle)],
        source: source_span(),
    }
}

fn source_span() -> gantry::source::SourceSpan {
    let limits = gantry::source::SourceLimits::new(1, 64, 64, 1, 1)
        .unwrap_or_else(|error| panic!("source limits failed: {error:?}"));
    let mut builder = gantry::source::SourceSnapshotBuilder::new(limits);
    let id = builder
        .add_file("main.gnt", b"detach(child);")
        .unwrap_or_else(|error| panic!("source fixture failed: {error:?}"));
    let snapshot = builder.finish();
    let record = snapshot
        .get(&id)
        .unwrap_or_else(|| panic!("source fixture record was absent"));
    gantry::source::SourceSpan::new(
        record,
        gantry::source::ByteSpan::new(0, 1)
            .unwrap_or_else(|error| panic!("byte span failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("source span failed: {error:?}"))
}

fn session_registry(
    execution: ProtocolIdentity,
    root_session: ProtocolIdentity,
) -> LogicalSessionRegistryV1 {
    LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"))
}

fn configuration(services: Arc<Services>) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(1, 64, 64, 64, 8, 64, 64, 64, 64, 16, 64, 64)
            .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        64,
        64,
        ValueLimits::new(8, 64, 64, 64).unwrap_or_else(|| panic!("value limits are positive")),
        64,
        64,
        64,
        8,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(services.clone(), services, required)
}

fn assert_canonical(bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
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
    .unwrap_or_else(|error| panic!("strict JSON failed: {error:?}"));
    let canonical = CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("canonical JSON failed: {error:?}"));
    assert_eq!(canonical.bytes(), bytes);
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn site(value: u64) -> StructuralPosition {
    StructuralPosition::new(vec![value]).unwrap_or_else(|error| panic!("position failed: {error}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("fresh identity failed: {error}"))
}

fn derived(kind: IdentityKind, key: &[u8]) -> ProtocolIdentity {
    ProtocolIdentity::derive(kind, key)
        .unwrap_or_else(|error| panic!("derived identity failed: {error}"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not parse {}: {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance package was outside the workspace"))
        .to_path_buf()
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
