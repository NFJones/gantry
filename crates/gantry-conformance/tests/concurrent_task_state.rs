//! Public conformance coverage for concurrent task creation and scheduler state.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::identity::ProtocolIdentity;
use gantry::ir::{
    CanonicalPath, EffectSet, StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor,
};
use gantry::portable::{IdentityKind, RuntimeErrorCategory, TaskHandleState, TaskStatusKind};
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
    Instruction, InstructionKind, LogicalSessionRegistryV1, Machine, MachineLabel, MachineLimits,
    MachineOutcome, MachineProgram, MachineStep, OperationCompletionError, Parameter,
    SessionCreationModeV1, TaskCaptureV1, TaskCreationRequestV1, TaskStateError, Workflow,
};
use gantry::source::{SourceLimits, SourceSpan};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView, ValuePathSegment};
use serde::Deserialize;

const CREATION_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_task_state.rs#public_task_creation_is_bounded_stable_and_snapshot_isolated";
const SCHEDULER_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_task_state.rs#public_submission_and_scheduler_preserve_one_shared_machine_path";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-concurrent-task-state-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write generic fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
    exclusions: Vec<String>,
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

#[test]
fn reviewed_concurrent_task_state_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/concurrent-task-state-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.concurrent-task-state-evidence/v1");
    assert_eq!(manifest.issue, "GNT-CON-001");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(manifest.exclusions.len(), 5);

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            CREATION_EVIDENCE | SCHEDULER_EVIDENCE
        ));
        entries
            .entry((entry.requirement, entry.clause, entry.profile))
            .or_default()
            .push(entry.evidence);
    }

    for ((requirement, clause_key, profile_name), evidence) in entries {
        if !evidence_is_current {
            continue;
        }
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

#[test]
fn public_task_creation_is_bounded_stable_and_snapshot_isolated() {
    let execution = fresh(IdentityKind::Execution, 1);
    let root_task = derived_task(b"{\"root\":true}");
    let root_session = fresh(IdentityKind::Session, 2);
    let mut state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let parent_value = LogicalValue::boolean(false);
    let capture = TaskCaptureV1::new(
        Arc::from("flag"),
        TypeDescriptor::BOOL,
        true,
        &parent_value,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("capture failed: {error:?}"));

    let created = state
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 0, vec![capture]),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
    let task = state
        .task(created.task_id)
        .unwrap_or_else(|| panic!("created task missing"));
    assert_eq!(state.created_task_count(), 2);
    assert_eq!(state.maximum_task_count(), 2);
    assert_eq!(task.parent_task_id(), root_task);
    assert_eq!(task.handle_name(), "child");
    assert_eq!(task.handle_id(), created.handle_id);
    assert_eq!(task.handle_id().owner(), root_task);
    assert_eq!(task.handle_id().child(), created.task_id);
    assert_eq!(task.handle_state(), TaskHandleState::Attached);
    assert_eq!(task.status().kind(), TaskStatusKind::Submitting);
    assert!(!task.handle_is_visible());
    assert!(state.parent_is_suspended(root_task));
    assert_eq!(created.transition.task_id, created.task_id);
    assert_eq!(created.transition.parent_task_id, root_task);
    assert_eq!(created.transition.workflow, path("crate::main"));
    assert_eq!(created.transition.spawn_site, site(0));
    assert_eq!(created.transition.spawn_occurrence, 0);
    assert_eq!(created.transition.result_type, TypeDescriptor::UNIT);
    assert_eq!(created.transition.attachment, TaskHandleState::Attached);
    assert_eq!(task.task_path(), [Arc::from("spawn:crate::main:0:0")]);
    assert_eq!(task.base_session_id(), created.base_session_id);
    assert_eq!(
        sessions
            .get(created.base_session_id)
            .and_then(|session| session.parent),
        Some(root_session)
    );

    state
        .replace_capture(
            created.task_id,
            "flag",
            &[],
            &LogicalValue::boolean(true),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("capture replacement failed: {error:?}"));
    assert!(matches!(parent_value.view(), LogicalValueView::Bool(false)));
    assert!(matches!(
        state
            .task(created.task_id)
            .and_then(|record| record.captures().get("flag"))
            .map(TaskCaptureV1::value)
            .map(LogicalValue::view),
        Some(LogicalValueView::Bool(true))
    ));

    state
        .resolve_submission(created.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("submission resolution failed: {error:?}"));
    assert!(!state.parent_is_suspended(root_task));

    assert_eq!(
        state.create_child(
            &mut sessions,
            creation_request(root_task, root_session, 1, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        ),
        Err(TaskStateError::TaskCountLimit)
    );
    assert_eq!(state.created_task_count(), 2);
}

#[test]
fn concrete_generic_capture_result_and_join_preserve_exact_application() {
    let execution = fresh(IdentityKind::Execution, 5);
    let root_task = derived_task(b"{\"generic-root\":true}");
    let root_session = fresh(IdentityKind::Session, 6);
    let mut state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let envelope = path("crate::Envelope");
    let integer_envelope =
        TypeDescriptor::declared_with_arguments(envelope.clone(), vec![TypeDescriptor::INT]);
    let string_envelope =
        TypeDescriptor::declared_with_arguments(envelope.clone(), vec![TypeDescriptor::STRING]);
    let parent = LogicalValue::structure(
        integer_envelope.canonical_string(),
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                gantry::numeric::GantryInt::new(1)
                    .unwrap_or_else(|| unreachable!("fixture integer is in range")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("generic value failed: {error:?}"));
    let capture = TaskCaptureV1::new(
        Arc::from("item"),
        integer_envelope.clone(),
        true,
        &parent,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("generic capture failed: {error:?}"));
    assert_eq!(capture.ty(), &integer_envelope);
    assert_eq!(
        TaskCaptureV1::new(
            Arc::from("item"),
            string_envelope,
            false,
            &parent,
            DEFAULT_VALUE_LIMITS,
        ),
        Err(TaskStateError::CaptureType)
    );

    let created = state
        .create_child(
            &mut sessions,
            TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from("child"),
                workflow: path("crate::main"),
                spawn_site: site(0),
                spawn_occurrence: 0,
                result_type: integer_envelope.clone(),
                captures: vec![capture],
                inherited_agent: None,
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("generic child creation failed: {error:?}"));
    let replacement = LogicalValue::integer(
        gantry::numeric::GantryInt::new(7)
            .unwrap_or_else(|| unreachable!("fixture integer is in range")),
    );
    let child_value = state
        .replace_capture(
            created.task_id,
            "item",
            &[ValuePathSegment::StructField("value".to_owned())],
            &replacement,
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("generic capture replacement failed: {error:?}"));
    let parent_member = parent
        .field("value")
        .unwrap_or_else(|| panic!("parent generic value omitted its field"));
    assert!(matches!(parent_member.view(), LogicalValueView::Int(value) if value.get() == 1));
    assert_eq!(child_value.canonical_json().bytes(), br#"{"value":7}"#);

    state
        .resolve_submission(created.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("generic submission failed: {error:?}"));
    state
        .settle(
            created.task_id,
            MachineOutcome::Succeeded(child_value.clone()),
        )
        .unwrap_or_else(|error| panic!("generic settlement failed: {error:?}"));
    let control = TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(1)),
        kind: gantry::ir::generated::TaskControlSiteKind::Join,
        handles: vec![Arc::from("child")],
        source: source_span(),
    };
    let ownership = match state
        .begin_join(root_task, &control, &[created.handle_id])
        .unwrap_or_else(|error| panic!("generic join start failed: {error:?}"))
    {
        gantry::runtime::JoinStartV1::Started(ownership) => ownership,
        gantry::runtime::JoinStartV1::Empty => panic!("generic join was unexpectedly empty"),
    };
    assert_eq!(
        state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(gantry::runtime::JoinResolutionV1::Succeeded(child_value))
    );
}

#[test]
fn concrete_generic_operation_schema_and_result_survive_task_boundary() {
    let package = analyze_source(
        r#"
agents { worker }
default agent = worker;
struct Envelope<T> { value: T }
fn generate<T>() -> T where T: ExternalValue { prompt "Generate." -> T }
fn child() -> Envelope<String> { generate::<Envelope<String>>() }
fn main() -> Envelope<String> { child() }
"#,
    );
    let descriptor = TypeDescriptor::declared_with_arguments(
        path("crate::Envelope"),
        vec![TypeDescriptor::STRING],
    );
    let schema = package
        .schemas()
        .and_then(|schemas| {
            schemas
                .entries()
                .iter()
                .find(|(candidate, _)| candidate == &descriptor)
        })
        .map(|(_, schema)| schema)
        .unwrap_or_else(|| panic!("closed Envelope<String> schema was not generated"));
    let schema = std::str::from_utf8(schema)
        .unwrap_or_else(|error| panic!("generic schema was not UTF-8: {error}"));
    assert!(schema.contains("\"value\""));
    assert!(schema.contains("\"type\":\"string\""));

    let program = Arc::new(
        package
            .executable_program()
            .cloned()
            .unwrap_or_else(|| panic!("generic package omitted its executable program")),
    );
    let execution = fresh(IdentityKind::Execution, 11);
    let root_task = derived_task(b"{\"generic-operation-root\":true}");
    let root_session = fresh(IdentityKind::Session, 12);
    let state = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let mut scheduler = ConcurrentSchedulerV1::new(state);
    let created = scheduler
        .create_child(
            &mut sessions,
            TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from("child"),
                workflow: path("crate::main"),
                spawn_site: site(6),
                spawn_occurrence: 0,
                result_type: descriptor.clone(),
                captures: Vec::new(),
                inherited_agent: Some(Arc::from("worker")),
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("generic operation child creation failed: {error:?}"));
    let child = Machine::new_concurrent_task_with_context(
        Arc::clone(&program),
        &path("crate::child"),
        Vec::new(),
        execution,
        MachineLimits::new(1_000, 100, 100, 64, 100, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive generic operation limits")),
        Some(Arc::from("worker")),
        Some(created.base_session_id),
    )
    .unwrap_or_else(|error| panic!("generic operation child machine failed: {error:?}"));
    scheduler
        .resolve_submission(created.task_id, Ok(child))
        .unwrap_or_else(|error| panic!("generic operation submission failed: {error:?}"));

    let operation = loop {
        let step = scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("generic operation scheduler failed: {error:?}"))
            .unwrap_or_else(|| panic!("generic operation child stopped before dispatch"));
        match step.step {
            MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => break operation,
            MachineStep::Transition(_) => {}
            other => panic!("generic operation child reached unexpected state: {other:?}"),
        }
    };
    assert_eq!(operation.expected_type, descriptor);
    assert_eq!(
        operation
            .metadata
            .as_ref()
            .map(|metadata| &metadata.result_type),
        Some(&descriptor)
    );
    let task_path = scheduler
        .state()
        .task(created.task_id)
        .unwrap_or_else(|| panic!("generic operation task was lost"))
        .task_path();
    assert!(operation.dynamic_path.starts_with(task_path));

    let wrong = LogicalValue::structure(
        TypeDescriptor::declared_with_arguments(path("crate::Envelope"), vec![TypeDescriptor::INT])
            .canonical_string(),
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                gantry::numeric::GantryInt::new(1)
                    .unwrap_or_else(|| unreachable!("fixture integer is in range")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("wrong generic result failed: {error:?}"));
    assert_eq!(
        scheduler
            .machine_mut(created.task_id)
            .unwrap_or_else(|| panic!("generic operation machine was lost"))
            .complete_operation(operation.identity, wrong),
        Err(OperationCompletionError::TypeMismatch)
    );
    let result = LogicalValue::structure(
        descriptor.canonical_string(),
        vec![(
            "value".to_owned(),
            LogicalValue::string("done", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("generic result string failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("generic operation result failed: {error:?}"));
    scheduler
        .machine_mut(created.task_id)
        .unwrap_or_else(|| panic!("generic operation machine was lost"))
        .complete_operation(operation.identity, result.clone())
        .unwrap_or_else(|error| panic!("generic operation completion failed: {error:?}"));
    scheduler
        .schedule(created.task_id)
        .unwrap_or_else(|error| panic!("generic operation reschedule failed: {error:?}"));
    loop {
        let step = scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("generic result scheduler failed: {error:?}"))
            .unwrap_or_else(|| panic!("generic child stopped before settlement"));
        if matches!(
            step.step,
            MachineStep::Transition(MachineLabel::TaskSettled(_)) | MachineStep::Complete(_)
        ) {
            break;
        }
    }
    assert!(matches!(
        scheduler.state().task(created.task_id).map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Succeeded(value)) if value == &result
    ));
    let control = TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(7)),
        kind: gantry::ir::generated::TaskControlSiteKind::Join,
        handles: vec![Arc::from("child")],
        source: source_span(),
    };
    let ownership = match scheduler
        .begin_join(root_task, &control, &[created.handle_id])
        .unwrap_or_else(|error| panic!("generic operation join start failed: {error:?}"))
    {
        gantry::runtime::JoinStartV1::Started(ownership) => ownership,
        gantry::runtime::JoinStartV1::Empty => panic!("generic operation join was empty"),
    };
    assert_eq!(
        scheduler.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(gantry::runtime::JoinResolutionV1::Succeeded(result))
    );
}

#[test]
fn concrete_generic_descriptors_survive_mixed_join_detach_cancel_and_shutdown() {
    let execution = fresh(IdentityKind::Execution, 9);
    let root_task = derived_task(b"{\"generic-lifecycle-root\":true}");
    let root_session = fresh(IdentityKind::Session, 10);
    let mut state = ConcurrentTaskStateV1::new(execution, root_task, 4)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let envelope = path("crate::Envelope");
    let integer_envelope =
        TypeDescriptor::declared_with_arguments(envelope.clone(), vec![TypeDescriptor::INT]);
    let string_envelope =
        TypeDescriptor::declared_with_arguments(envelope, vec![TypeDescriptor::STRING]);
    let integer_value = LogicalValue::structure(
        integer_envelope.canonical_string(),
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                gantry::numeric::GantryInt::new(7)
                    .unwrap_or_else(|| unreachable!("fixture integer is in range")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("integer envelope failed: {error:?}"));
    let string_value = LogicalValue::structure(
        string_envelope.canonical_string(),
        vec![(
            "value".to_owned(),
            LogicalValue::string("ready", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("string field failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("string envelope failed: {error:?}"));

    let (first, second) = {
        let mut create = |handle: &str,
                          occurrence: u64,
                          ty: TypeDescriptor,
                          value: &LogicalValue| {
            let capture = TaskCaptureV1::new(
                Arc::from("input"),
                ty.clone(),
                false,
                value,
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("generic lifecycle capture failed: {error:?}"));
            let created = state
                .create_child(
                    &mut sessions,
                    TaskCreationRequestV1 {
                        parent_task_id: root_task,
                        handle_name: Arc::from(handle),
                        workflow: path("crate::main"),
                        spawn_site: site(2),
                        spawn_occurrence: occurrence,
                        result_type: ty,
                        captures: vec![capture],
                        inherited_agent: None,
                        parent_session_id: root_session,
                    },
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("generic lifecycle child failed: {error:?}"));
            state
                .resolve_submission(created.task_id, Ok(()))
                .unwrap_or_else(|error| panic!("generic lifecycle submission failed: {error:?}"));
            created
        };
        (
            create("first", 0, integer_envelope.clone(), &integer_value),
            create("second", 1, string_envelope.clone(), &string_value),
        )
    };

    let joinall = TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(3)),
        kind: gantry::ir::generated::TaskControlSiteKind::JoinAll,
        handles: vec![Arc::from("first"), Arc::from("second")],
        source: source_span(),
    };
    let ownership = match state
        .begin_join(root_task, &joinall, &[first.handle_id, second.handle_id])
        .unwrap_or_else(|error| panic!("generic joinall start failed: {error:?}"))
    {
        gantry::runtime::JoinStartV1::Started(ownership) => ownership,
        gantry::runtime::JoinStartV1::Empty => panic!("generic joinall was unexpectedly empty"),
    };
    state
        .settle(
            second.task_id,
            MachineOutcome::Cancelled(Arc::from("second-cancelled")),
        )
        .unwrap_or_else(|error| panic!("generic cancellation settlement failed: {error:?}"));
    assert_eq!(
        state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(gantry::runtime::JoinResolutionV1::Pending(vec![
            first.task_id
        ]))
    );
    state
        .settle(
            first.task_id,
            MachineOutcome::Succeeded(integer_value.clone()),
        )
        .unwrap_or_else(|error| panic!("generic success settlement failed: {error:?}"));
    let failure = match state
        .resolve_join(&ownership, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("generic mixed join failed: {error:?}"))
    {
        gantry::runtime::JoinResolutionV1::Failed(failure) => failure,
        other => panic!("generic mixed join unexpectedly resolved as {other:?}"),
    };
    assert_eq!(failure.category, RuntimeErrorCategory::TaskJoinFailure);
    assert_eq!(failure.failures.len(), 1);
    assert_eq!(failure.failures[0].task_id, second.task_id);
    assert!(matches!(
        &failure.failures[0].failure,
        gantry::runtime::TaskJoinMemberFailureKindV1::Cancelled(reason)
            if reason.as_ref() == "second-cancelled"
    ));

    let background_capture = TaskCaptureV1::new(
        Arc::from("input"),
        integer_envelope.clone(),
        false,
        &integer_value,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("background generic capture failed: {error:?}"));
    let background = state
        .create_child(
            &mut sessions,
            TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from("background"),
                workflow: path("crate::main"),
                spawn_site: site(4),
                spawn_occurrence: 0,
                result_type: integer_envelope.clone(),
                captures: vec![background_capture],
                inherited_agent: None,
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("background generic child failed: {error:?}"));
    state
        .resolve_submission(background.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("background generic submission failed: {error:?}"));
    let detach = TaskControlSite {
        id: StaticSiteId::new(path("crate::main"), site(5)),
        kind: gantry::ir::generated::TaskControlSiteKind::Detach,
        handles: vec![Arc::from("background")],
        source: source_span(),
    };
    state
        .detach(root_task, &detach, background.handle_id)
        .unwrap_or_else(|error| panic!("generic detach failed: {error:?}"));

    assert_eq!(
        state
            .cancel_task_tree(root_task, "parent-failed")
            .unwrap_or_else(|error| panic!("generic task-tree cancellation failed: {error:?}")),
        [root_task]
    );
    assert_eq!(state.task_cancellation_reason(background.task_id), None);
    let cohort = state.shutdown_cohort();
    assert_eq!(cohort.foreground_task, Some(root_task));
    assert!(cohort.attached_tasks.is_empty());
    assert_eq!(cohort.detached_tasks, [background.task_id]);
    assert_eq!(
        state
            .cancel_execution("shutdown")
            .unwrap_or_else(|error| panic!("generic execution cancellation failed: {error:?}")),
        [background.task_id]
    );
    let record = state
        .task(background.task_id)
        .unwrap_or_else(|| panic!("background generic task was lost"));
    assert_eq!(record.result_type(), &integer_envelope);
    assert!(!record.result_type().canonical_string().contains('^'));
    assert!(record.captures().values().all(|capture| {
        !capture.ty().canonical_string().contains('^')
            && matches!(
                capture.value().view(),
                LogicalValueView::Struct { type_name, .. }
                    if type_name == integer_envelope.canonical_string()
            )
    }));
    assert_eq!(
        state
            .apply_abort_result(
                background.task_id,
                gantry::runtime::TaskAbortResultV1::Stopped
            )
            .unwrap_or_else(|error| panic!("generic shutdown abort failed: {error:?}")),
        gantry::portable::ExecutorAbortResultKind::Stopped
    );
    state
        .complete_foreground(MachineOutcome::Succeeded(LogicalValue::unit()))
        .unwrap_or_else(|error| panic!("generic foreground completion failed: {error:?}"));
    let terminal = state
        .complete_terminal()
        .unwrap_or_else(|error| panic!("generic terminal completion failed: {error:?}"));
    assert_eq!(
        terminal.category,
        gantry::runtime::ConcurrentTerminalCategoryV1::Cancellation
    );
    assert!(state.pending_task_ids().is_empty());
}

#[test]
fn concurrent_operation_identities_include_the_dynamic_task_path() {
    let execution = fresh(IdentityKind::Execution, 7);
    let root_task = derived_task(b"{\"operation-root\":true}");
    let root_session = fresh(IdentityKind::Session, 8);
    let state = ConcurrentTaskStateV1::new(execution, root_task, 3)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let mut scheduler = ConcurrentSchedulerV1::new(state);
    let first = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 0, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
    let first_path = scheduler
        .state()
        .task(first.task_id)
        .unwrap_or_else(|| panic!("first task missing"))
        .task_path()
        .to_vec();
    scheduler
        .resolve_submission(
            first.task_id,
            Ok(operation_child_machine(execution, root_session)),
        )
        .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
    let second = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 1, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
    let second_path = scheduler
        .state()
        .task(second.task_id)
        .unwrap_or_else(|| panic!("second task missing"))
        .task_path()
        .to_vec();
    scheduler
        .resolve_submission(
            second.task_id,
            Ok(operation_child_machine(execution, root_session)),
        )
        .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));

    let first_operation = match scheduler
        .step_next()
        .unwrap_or_else(|error| panic!("first scheduler step failed: {error:?}"))
        .unwrap_or_else(|| panic!("first task was not runnable"))
        .step
    {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("first child did not prepare an operation: {other:?}"),
    };
    let second_operation = match scheduler
        .step_next()
        .unwrap_or_else(|error| panic!("second scheduler step failed: {error:?}"))
        .unwrap_or_else(|| panic!("second task was not runnable"))
        .step
    {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("second child did not prepare an operation: {other:?}"),
    };

    assert!(first_operation.dynamic_path.starts_with(&first_path));
    assert!(second_operation.dynamic_path.starts_with(&second_path));
    assert_ne!(first_operation.identity, second_operation.identity);
}

#[test]
fn public_submission_and_scheduler_preserve_one_shared_machine_path() {
    let execution = fresh(IdentityKind::Execution, 3);
    let root_task = derived_task(b"{\"root\":true}");
    let root_session = fresh(IdentityKind::Session, 4);
    let state = ConcurrentTaskStateV1::new(execution, root_task, 3)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let mut sessions = session_registry(execution, root_session);
    let mut scheduler = ConcurrentSchedulerV1::new(state);
    let first = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 0, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
    scheduler
        .resolve_submission(first.task_id, Ok(child_machine(execution, root_session)))
        .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
    let second = scheduler
        .create_child(
            &mut sessions,
            creation_request(root_task, root_session, 1, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
    scheduler
        .resolve_submission(
            second.task_id,
            Err(gantry::host::contracts::HostError {
                code: Arc::from("queue-closed"),
                protected_diagnostic: Some(Arc::from("executor-1")),
            }),
        )
        .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));

    let failed = scheduler
        .state()
        .task(second.task_id)
        .unwrap_or_else(|| panic!("failed task missing"));
    assert!(failed.handle_is_visible());
    assert_eq!(failed.handle_id(), second.handle_id);
    assert!(matches!(
        failed.status(),
        ConcurrentTaskStatusV1::Failed(failure)
            if failure.category == RuntimeErrorCategory::ExecutorFailure
                && failure.code.as_ref() == "queue-closed"
    ));

    let deterministic = scheduler
        .step_next()
        .unwrap_or_else(|error| panic!("scheduler step failed: {error:?}"))
        .unwrap_or_else(|| panic!("submitted task was not runnable"));
    assert_eq!(deterministic.task_id, first.task_id);
    assert!(matches!(
        deterministic.step,
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let settlement = scheduler
        .step_next()
        .unwrap_or_else(|error| panic!("scheduler settlement failed: {error:?}"))
        .unwrap_or_else(|| panic!("submitted task did not settle"));
    assert_eq!(settlement.task_id, first.task_id);
    assert!(matches!(
        settlement.step,
        MachineStep::Transition(MachineLabel::TaskSettled(_))
    ));
    assert!(matches!(
        scheduler
            .state()
            .task(first.task_id)
            .map(|task| task.status()),
        Some(ConcurrentTaskStatusV1::Succeeded(_))
    ));
    assert_eq!(scheduler.step_next(), Ok(None));
}

fn creation_request(
    parent_task_id: ProtocolIdentity,
    parent_session_id: ProtocolIdentity,
    spawn_occurrence: u64,
    captures: Vec<TaskCaptureV1>,
) -> TaskCreationRequestV1 {
    TaskCreationRequestV1 {
        parent_task_id,
        handle_name: Arc::from("child"),
        workflow: path("crate::main"),
        spawn_site: site(0),
        spawn_occurrence,
        result_type: TypeDescriptor::UNIT,
        captures,
        inherited_agent: Some(Arc::from("writer")),
        parent_session_id,
    }
}

fn child_machine(execution: ProtocolIdentity, session: ProtocolIdentity) -> Machine {
    let root = path("crate::child");
    let program = MachineProgram::new(vec![Workflow {
        path: root.clone(),
        parameters: Vec::<Parameter>::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: site(0),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: site(1),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("child program failed: {error:?}"));
    Machine::new_concurrent_task_with_context(
        Arc::new(program),
        &root,
        Vec::new(),
        execution,
        MachineLimits::new(16, 1, 1, 4, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive child limits")),
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("child machine failed: {error:?}"))
}

fn operation_child_machine(execution: ProtocolIdentity, session: ProtocolIdentity) -> Machine {
    let root = path("crate::operation_child");
    let program = MachineProgram::new(vec![Workflow {
        path: root.clone(),
        parameters: Vec::<Parameter>::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: site(0),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Operation,
            },
            Instruction {
                site: site(1),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("operation child program failed: {error:?}"));
    Machine::new_concurrent_task_with_context(
        Arc::new(program),
        &root,
        Vec::new(),
        execution,
        MachineLimits::new(16, 1, 1, 4, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive child limits")),
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("operation child machine failed: {error:?}"))
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

fn analyze_source(source: &str) -> gantry::analysis::TypedPackage {
    let root = TempDirectory::new(source);
    let syntax = validate_package_syntax(
        &root.0,
        SourceLimits::new(8, 1_048_576, 4_194_304, 262_144, 256)
            .unwrap_or_else(|_| unreachable!("positive fixture limits")),
        i64::MAX as u64,
    )
    .unwrap_or_else(|error| panic!("generic syntax failed: {error}"));
    let package = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("generic analysis failed operationally: {error}"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    package
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn site(value: u64) -> StructuralPosition {
    StructuralPosition::new(vec![value]).unwrap_or_else(|error| panic!("site failed: {error}"))
}

fn source_span() -> SourceSpan {
    SourceSpan::from_portable_parts("main.gnt", 0, 1)
        .unwrap_or_else(|error| panic!("source span failed: {error}"))
}

fn derived_task(key: &[u8]) -> ProtocolIdentity {
    ProtocolIdentity::derive(IdentityKind::Task, key)
        .unwrap_or_else(|error| panic!("task identity failed: {error}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
