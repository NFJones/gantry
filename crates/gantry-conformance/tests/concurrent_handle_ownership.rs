//! Public conformance coverage for linear concurrent handle ownership.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, TypedPackage, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::identity::ProtocolIdentity;
use gantry::ir::{
    CanonicalPath, OwnershipFact, StructuralPosition, TaskControlSite, TypeDescriptor,
};
use gantry::portable::{IdentityKind, RuntimeErrorCategory, TaskHandleState};
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1, JoinResolutionV1,
    JoinStartV1, LogicalSessionRegistryV1, SessionCreationModeV1, TaskCreationRequestV1,
    TaskJoinMemberFailureKindV1, TaskStateError,
};
use gantry::source::SourceLimits;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use serde::Deserialize;

const NAMED_JOIN_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_handle_ownership.rs#public_named_join_consumes_linearly_and_preserves_analyzer_order";
const JOINALL_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_handle_ownership.rs#public_joinall_waits_for_all_and_reports_source_order";
const DETACH_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_handle_ownership.rs#public_detach_transfers_ownership_and_preserves_path_evidence";

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
fn checked_in_concurrent_handle_ownership_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/concurrent-handle-ownership-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(
        manifest.format,
        "gantry.concurrent-handle-ownership-evidence/v1"
    );
    assert_eq!(manifest.issue, "GNT-CON-002");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(manifest.exclusions.len(), 4);

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            NAMED_JOIN_EVIDENCE | JOINALL_EVIDENCE | DETACH_EVIDENCE
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

#[test]
fn public_named_join_consumes_linearly_and_preserves_analyzer_order() {
    let package = analyzed_controls();
    let control = task_control(&package, "crate::named", "join");
    assert_eq!(handle_names(control), ["first", "second"]);

    let (mut state, mut sessions, root_task, root_session) = fixture(3);
    let first = create_child(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "crate::named",
        "first",
        0,
        TypeDescriptor::BOOL,
    );
    let second = create_child(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "crate::named",
        "second",
        1,
        TypeDescriptor::BOOL,
    );

    assert_eq!(
        state.begin_join(root_task, control, &[second.handle_id, first.handle_id]),
        Err(TaskStateError::HandleSelectionMismatch)
    );
    assert!(
        state
            .task(first.task_id)
            .is_some_and(|task| { task.handle_state() == TaskHandleState::Attached })
    );
    let ownership = match state
        .begin_join(root_task, control, &[first.handle_id, second.handle_id])
        .unwrap_or_else(|error| panic!("join start failed: {error:?}"))
    {
        JoinStartV1::Started(ownership) => ownership,
        JoinStartV1::Empty => panic!("named join unexpectedly reduced as empty"),
    };
    assert_eq!(
        ownership
            .members()
            .iter()
            .map(|member| member.handle_name())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert!(ownership.members().iter().all(|member| {
        state
            .task(member.task_id())
            .is_some_and(|task| task.handle_state() == TaskHandleState::Joined)
    }));
    assert_eq!(
        state.begin_join(root_task, control, &[first.handle_id, second.handle_id]),
        Err(TaskStateError::ConsumedHandle)
    );

    state
        .settle(
            second.task_id,
            gantry::runtime::MachineOutcome::Succeeded(LogicalValue::boolean(true)),
        )
        .unwrap_or_else(|error| panic!("second settlement failed: {error:?}"));
    assert_eq!(
        state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(JoinResolutionV1::Pending(vec![first.task_id]))
    );
    state
        .settle(
            first.task_id,
            gantry::runtime::MachineOutcome::Succeeded(LogicalValue::boolean(false)),
        )
        .unwrap_or_else(|error| panic!("first settlement failed: {error:?}"));
    let expected = LogicalValue::list(
        vec![LogicalValue::boolean(false), LogicalValue::boolean(true)],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("expected result failed: {error:?}"));
    assert_eq!(
        state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(JoinResolutionV1::Succeeded(expected))
    );

    let fact = OwnershipFact {
        handle: Arc::from("first"),
        state: TaskHandleState::Joined,
        source: control.source.clone(),
    };
    state
        .validate_analyzer_ownership(first.handle_id, &fact)
        .unwrap_or_else(|error| panic!("joined analyzer fact mismatch: {error:?}"));
}

#[test]
fn public_joinall_waits_for_all_and_reports_source_order() {
    let package = analyzed_controls();
    let control = task_control(&package, "crate::scoped", "joinall");
    assert_eq!(handle_names(control), ["first", "second"]);

    let (mut state, mut sessions, root_task, root_session) = fixture(3);
    let first = create_child(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "crate::scoped",
        "first",
        0,
        TypeDescriptor::UNIT,
    );
    let second = create_child(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "crate::scoped",
        "second",
        1,
        TypeDescriptor::UNIT,
    );
    let ownership = match state
        .begin_join(root_task, control, &[first.handle_id, second.handle_id])
        .unwrap_or_else(|error| panic!("joinall start failed: {error:?}"))
    {
        JoinStartV1::Started(ownership) => ownership,
        JoinStartV1::Empty => panic!("nonempty joinall unexpectedly reduced as empty"),
    };

    state
        .settle(
            second.task_id,
            gantry::runtime::MachineOutcome::Cancelled(Arc::from("second-cancelled")),
        )
        .unwrap_or_else(|error| panic!("second settlement failed: {error:?}"));
    assert_eq!(
        state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
        Ok(JoinResolutionV1::Pending(vec![first.task_id]))
    );
    state
        .settle(
            first.task_id,
            gantry::runtime::MachineOutcome::Cancelled(Arc::from("first-cancelled")),
        )
        .unwrap_or_else(|error| panic!("first settlement failed: {error:?}"));
    let failure = match state
        .resolve_join(&ownership, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("joinall resolution failed: {error:?}"))
    {
        JoinResolutionV1::Failed(failure) => failure,
        other => panic!("joinall unexpectedly resolved as {other:?}"),
    };
    assert_eq!(failure.category, RuntimeErrorCategory::TaskJoinFailure);
    assert_eq!(
        failure
            .failures
            .iter()
            .map(|member| member.task_id)
            .collect::<Vec<_>>(),
        [first.task_id, second.task_id]
    );
    assert!(matches!(
        &failure.failures[0].failure,
        TaskJoinMemberFailureKindV1::Cancelled(reason)
            if reason.as_ref() == "first-cancelled"
    ));
    assert!(matches!(
        &failure.failures[1].failure,
        TaskJoinMemberFailureKindV1::Cancelled(reason)
            if reason.as_ref() == "second-cancelled"
    ));

    let empty = task_control(&package, "crate::empty", "joinall");
    assert!(empty.handles.is_empty());
    assert_eq!(
        state.begin_join(root_task, empty, &[]),
        Ok(JoinStartV1::Empty)
    );
}

#[test]
fn public_detach_transfers_ownership_and_preserves_path_evidence() {
    let package = analyzed_controls();
    let control = task_control(&package, "crate::background", "detach");
    assert_eq!(handle_names(control), ["worker"]);

    let (mut state, mut sessions, root_task, root_session) = fixture(2);
    let created = create_child(
        &mut state,
        &mut sessions,
        root_task,
        root_session,
        "crate::background",
        "worker",
        0,
        TypeDescriptor::BOOL,
    );
    let ownership = state
        .detach(root_task, control, created.handle_id)
        .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
    assert_eq!(ownership.disposition(), TaskHandleState::Detached);
    assert_eq!(ownership.members().len(), 1);
    assert_eq!(ownership.members()[0].task_id(), created.task_id);
    assert_eq!(
        ownership.members()[0].task_path(),
        [Arc::from("spawn:crate::background:0:0")]
    );
    assert!(matches!(
        state.task(created.task_id),
        Some(task)
            if task.handle_state() == TaskHandleState::Detached
                && matches!(task.status(), ConcurrentTaskStatusV1::Running)
    ));
    assert_eq!(
        state.detach(root_task, control, created.handle_id),
        Err(TaskStateError::ConsumedHandle)
    );

    state
        .settle(
            created.task_id,
            gantry::runtime::MachineOutcome::Succeeded(LogicalValue::boolean(true)),
        )
        .unwrap_or_else(|error| panic!("detached settlement failed: {error:?}"));
    assert!(matches!(
        state.task(created.task_id),
        Some(task)
            if task.handle_state() == TaskHandleState::Detached
                && matches!(task.status(), ConcurrentTaskStatusV1::Succeeded(_))
    ));

    for analyzer_state in [TaskHandleState::Detached, TaskHandleState::Discharged] {
        let fact = OwnershipFact {
            handle: Arc::from("worker"),
            state: analyzer_state,
            source: control.source.clone(),
        };
        state
            .validate_analyzer_ownership(created.handle_id, &fact)
            .unwrap_or_else(|error| panic!("analyzer fact mismatch: {error:?}"));
    }
}

fn analyzed_controls() -> TypedPackage {
    let root = TempDirectory::new();
    root.write(
        r#"
fn named() -> List<Bool> {
    spawn first -> Bool { false }
    spawn second -> Bool { true }
    join(first, second)
}
fn scoped() {
    spawn first { return; }
    spawn second { return; }
    joinall();
}
fn background() {
    spawn worker -> Bool { true }
    detach(worker);
}
fn empty() { joinall(); }
fn main() {}
"#,
    );
    let syntax = validate_package_syntax(&root.0, source_limits())
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let package = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("analysis failed operationally: {error:?}"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    package
}

fn task_control<'a>(package: &'a TypedPackage, workflow: &str, kind: &str) -> &'a TaskControlSite {
    package
        .workflows()
        .iter()
        .find(|candidate| candidate.path.as_str() == workflow)
        .and_then(|workflow| {
            workflow
                .task_controls
                .iter()
                .find(|control| control.kind.wire_name() == kind)
        })
        .unwrap_or_else(|| panic!("missing {kind} control in {workflow}"))
}

fn handle_names(control: &TaskControlSite) -> Vec<&str> {
    control.handles.iter().map(AsRef::as_ref).collect()
}

fn fixture(
    maximum_tasks: u64,
) -> (
    ConcurrentTaskStateV1,
    LogicalSessionRegistryV1,
    ProtocolIdentity,
    ProtocolIdentity,
) {
    let execution = fresh(IdentityKind::Execution, 1);
    let root_task = ProtocolIdentity::derive(IdentityKind::Task, b"concurrent-owner-root")
        .unwrap_or_else(|error| panic!("root task identity failed: {error}"));
    let root_session = fresh(IdentityKind::Session, 2);
    let state = ConcurrentTaskStateV1::new(execution, root_task, maximum_tasks)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    (state, sessions, root_task, root_session)
}

#[allow(clippy::too_many_arguments)]
fn create_child(
    state: &mut ConcurrentTaskStateV1,
    sessions: &mut LogicalSessionRegistryV1,
    parent_task_id: ProtocolIdentity,
    parent_session_id: ProtocolIdentity,
    workflow: &str,
    handle_name: &str,
    spawn_occurrence: u64,
    result_type: TypeDescriptor,
) -> gantry::runtime::TaskCreationV1 {
    let created = state
        .create_child(
            sessions,
            TaskCreationRequestV1 {
                parent_task_id,
                handle_name: Arc::from(handle_name),
                workflow: CanonicalPath::new(workflow)
                    .unwrap_or_else(|error| panic!("workflow path failed: {error}")),
                spawn_site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("spawn site failed: {error}")),
                spawn_occurrence,
                result_type,
                captures: Vec::new(),
                inherited_agent: None,
                parent_session_id,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
    state
        .resolve_submission(created.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("submission resolution failed: {error:?}"));
    created
}

fn source_limits() -> SourceLimits {
    SourceLimits::new(1, 65_536, 65_536, 65_536, 64)
        .unwrap_or_else(|_| unreachable!("positive source limits"))
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
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-concurrent-ownership-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        Self(path)
    }

    fn write(&self, source: &str) {
        let path = self.0.join("main.gnt");
        fs::write(&path, source)
            .unwrap_or_else(|error| panic!("could not write {}: {error}", path.display()));
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
