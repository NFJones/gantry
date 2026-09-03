//! Bounded model and written-argument checks for concurrent evaluator refinement.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const MODEL_EVIDENCE: &str = "crates/gantry-conformance/tests/concurrent_refinement_model.rs#bounded_concurrent_refinement_model_and_counterexamples_replay";
const OBLIGATIONS: [&str; 15] = [
    "all-settled-source-order",
    "cancellation-nonconsumption",
    "enabled-task-progress",
    "fixed-outcome-observation-isolation",
    "foreground-terminal-separation",
    "linear-handle-ownership",
    "per-task-transition-order",
    "shared-machine-refinement",
    "shutdown-cohort-closure",
    "task-settlement-at-most-once",
    "terminal-completion-uniqueness",
    "weak-fair-runnable-polling",
    "closed-generic-task-transfer",
    "schedule-independent-static-selection",
    "no-concurrent-generic-analysis",
];
const ACTIONS: [Action; 25] = [
    Action::BarrierFail,
    Action::BeginShutdown,
    Action::CancelExecution,
    Action::DetachA,
    Action::DetachB,
    Action::FailRoot,
    Action::FinishShutdown,
    Action::ForegroundComplete,
    Action::JoinA,
    Action::JoinB,
    Action::SettleACancelled,
    Action::SettleAFailed,
    Action::SettleASucceeded,
    Action::SettleBCancelled,
    Action::SettleBFailed,
    Action::SettleBSucceeded,
    Action::SettleRootCancelled,
    Action::SettleRootFailed,
    Action::SettleRootSucceeded,
    Action::SpawnA,
    Action::SpawnB,
    Action::SubmitAFailed,
    Action::SubmitAOk,
    Action::SubmitBFailed,
    Action::SubmitBOk,
];

#[derive(Debug, Deserialize)]
struct RefinementManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profile: String,
    argument: String,
    model: String,
    model_evidence: String,
    reviewed_clauses: Vec<ReviewedClauseLink>,
    trace_evidence: Vec<String>,
    evidence_manifests: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClauseLink {
    requirement: String,
    clause: String,
}

#[derive(Debug, Deserialize)]
struct ConcurrentModel {
    format: String,
    maximum_depth: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    obligations: Vec<String>,
    assumptions: Vec<String>,
    counterexamples: Vec<Counterexample>,
}

#[derive(Debug, Deserialize)]
struct Counterexample {
    id: String,
    trace: Vec<String>,
    rejected_action: String,
    invariant: String,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum InterpreterPhase {
    Running,
    ShuttingDown,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TaskStatus {
    Absent,
    Submitting,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum HandleStatus {
    Absent,
    Pending,
    Attached,
    Joined,
    Detached,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Outcome {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TerminalCategory {
    Success,
    RuntimeFailure,
    DetachedTaskFailure,
    Cancellation,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelState {
    phase: InterpreterPhase,
    root: TaskStatus,
    generic_descriptor_closed: bool,
    concrete_call_target_selected: bool,
    concurrent_generic_analysis_steps: u8,
    child_a: TaskStatus,
    child_b: TaskStatus,
    handle_a: HandleStatus,
    handle_b: HandleStatus,
    cancellation: bool,
    root_failure: bool,
    root_marked: bool,
    a_marked: bool,
    b_marked: bool,
    foreground: Option<Outcome>,
    terminal: Option<TerminalCategory>,
    barrier_failed: bool,
}

impl ModelState {
    const fn initial() -> Self {
        Self {
            phase: InterpreterPhase::Running,
            root: TaskStatus::Running,
            generic_descriptor_closed: true,
            concrete_call_target_selected: true,
            concurrent_generic_analysis_steps: 0,
            child_a: TaskStatus::Absent,
            child_b: TaskStatus::Absent,
            handle_a: HandleStatus::Absent,
            handle_b: HandleStatus::Absent,
            cancellation: false,
            root_failure: false,
            root_marked: false,
            a_marked: false,
            b_marked: false,
            foreground: None,
            terminal: None,
            barrier_failed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    BarrierFail,
    BeginShutdown,
    CancelExecution,
    DetachA,
    DetachB,
    FailRoot,
    FinishShutdown,
    ForegroundComplete,
    JoinA,
    JoinB,
    SettleACancelled,
    SettleAFailed,
    SettleASucceeded,
    SettleBCancelled,
    SettleBFailed,
    SettleBSucceeded,
    SettleRootCancelled,
    SettleRootFailed,
    SettleRootSucceeded,
    SpawnA,
    SpawnB,
    SubmitAFailed,
    SubmitAOk,
    SubmitBFailed,
    SubmitBOk,
    TerminalComplete,
    ResolveTraitAtRuntime,
    RewriteConcreteCallTarget,
    SubmitOpenGeneric,
}

impl Action {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "barrier-fail" => Self::BarrierFail,
            "begin-shutdown" => Self::BeginShutdown,
            "cancel-execution" => Self::CancelExecution,
            "detach-a" => Self::DetachA,
            "detach-b" => Self::DetachB,
            "fail-root" => Self::FailRoot,
            "finish-shutdown" => Self::FinishShutdown,
            "foreground-complete" => Self::ForegroundComplete,
            "join-a" => Self::JoinA,
            "join-b" => Self::JoinB,
            "settle-a-cancelled" => Self::SettleACancelled,
            "settle-a-failed" => Self::SettleAFailed,
            "settle-a-succeeded" => Self::SettleASucceeded,
            "settle-b-cancelled" => Self::SettleBCancelled,
            "settle-b-failed" => Self::SettleBFailed,
            "settle-b-succeeded" => Self::SettleBSucceeded,
            "settle-root-cancelled" => Self::SettleRootCancelled,
            "settle-root-failed" => Self::SettleRootFailed,
            "settle-root-succeeded" => Self::SettleRootSucceeded,
            "spawn-a" => Self::SpawnA,
            "spawn-b" => Self::SpawnB,
            "submit-a-failed" => Self::SubmitAFailed,
            "submit-a-ok" => Self::SubmitAOk,
            "submit-b-failed" => Self::SubmitBFailed,
            "submit-b-ok" => Self::SubmitBOk,
            "terminal-complete" => Self::TerminalComplete,
            "resolve-trait-at-runtime" => Self::ResolveTraitAtRuntime,
            "rewrite-concrete-call-target" => Self::RewriteConcreteCallTarget,
            "submit-open-generic" => Self::SubmitOpenGeneric,
            _ => return None,
        })
    }
}

#[test]
fn bounded_concurrent_refinement_model_and_counterexamples_replay() {
    let root = workspace_root();
    let model: ConcurrentModel =
        read_json(&root.join("protocol/goldens/concurrent-refinement-model-v1.json"));
    assert_eq!(model.format, "gantry.concurrent-refinement-model/v1");
    assert_eq!(model.obligations, OBLIGATIONS);
    assert!(
        model
            .assumptions
            .iter()
            .any(|value| value.contains("not an unbounded proof"))
    );

    let initial = ModelState::initial();
    let mut visited = BTreeSet::from([initial]);
    let mut pending = VecDeque::from([(initial, 0_usize)]);
    while let Some((state, depth)) = pending.pop_front() {
        assert_invariants(state);
        if state.terminal.is_none() && !waits_for_host(state) {
            assert!(
                ACTIONS.iter().any(|action| apply(state, *action).is_some())
                    || apply(state, Action::TerminalComplete).is_some(),
                "enabled concurrent state has no Gantry transition: {state:?}"
            );
        }
        if depth == model.maximum_depth {
            continue;
        }
        for action in ACTIONS.into_iter().chain([Action::TerminalComplete]) {
            let Some(next) = apply(state, action) else {
                continue;
            };
            assert_invariants(next);
            if action == Action::BarrierFail {
                assert_eq!(next.foreground, state.foreground);
                assert_eq!(next.terminal, state.terminal);
            }
            if visited.insert(next) {
                pending.push_back((next, depth.saturating_add(1)));
            }
        }
    }
    assert_eq!(visited.len(), model.explored_state_count);
    assert_eq!(
        visited
            .iter()
            .filter(|state| state.terminal.is_some())
            .count(),
        model.terminal_state_count
    );

    let ids = model
        .counterexamples
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    for case in &model.counterexamples {
        assert!(!case.invariant.is_empty());
        let mut state = ModelState::initial();
        for action in &case.trace {
            let action = Action::parse(action)
                .unwrap_or_else(|| panic!("unknown action in {}: {action}", case.id));
            state = apply(state, action)
                .unwrap_or_else(|| panic!("invalid replay prefix in {}: {action:?}", case.id));
        }
        let rejected = Action::parse(&case.rejected_action)
            .unwrap_or_else(|| panic!("unknown rejected action in {}", case.id));
        assert!(apply(state, rejected).is_none(), "{}", case.id);
        assert_invariants(state);
    }
}

#[test]
fn written_concurrent_argument_links_current_reviewed_evidence() {
    let root = workspace_root();
    let manifest: RefinementManifest =
        read_json(&root.join("protocol/conformance/concurrent-refinement-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    assert_eq!(manifest.format, "gantry.concurrent-refinement-evidence/v1");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert_eq!(manifest.issue, "GNT-CON-005");
    assert_eq!(manifest.profile, "concurrent-evaluator");
    assert_eq!(manifest.model_evidence, MODEL_EVIDENCE);
    assert!(manifest.exclusions.len() >= 4);
    assert_sorted_unique(&manifest.trace_evidence);
    assert_sorted_unique(&manifest.evidence_manifests);

    let argument = fs::read_to_string(root.join(&manifest.argument))
        .unwrap_or_else(|error| panic!("could not read concurrent argument: {error}"));
    for heading in [
        "## Scope and claim",
        "## Assumptions, fairness, and bounds",
        "## Refinement mapping",
        "## Property argument",
        "## Requirement and trace links",
        "## Counterexample replay",
    ] {
        assert!(argument.contains(heading));
    }
    assert!(argument.contains("not an unbounded proof"));
    assert!(argument.contains("genuinely pending"));
    assert!(argument.contains("No assumption"));
    assert!(argument.contains("fixes cross-task order"));
    assert!(root.join(&manifest.model).is_file());

    validate_evidence_anchor(&root, &manifest.model_evidence);
    for evidence in &manifest.trace_evidence {
        validate_evidence_anchor(&root, evidence);
    }
    for path in &manifest.evidence_manifests {
        let value: serde_json::Value = read_json(&root.join(path));
        assert!(gantry_conformance::evidence_revision_is_expected(
            value["specification_sha256"].as_str().unwrap_or_default(),
            &review.specification_sha256,
        ));
    }
    for link in &manifest.reviewed_clauses {
        if !evidence_is_current {
            continue;
        }
        let reviewed = review
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
                    .find(|profile| profile.profile == manifest.profile)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing concurrent review for {}#{}",
                    link.requirement, link.clause
                )
            });
        assert_eq!(reviewed.state, "covered");
        assert!(
            reviewed
                .evidence
                .iter()
                .any(|evidence| evidence == MODEL_EVIDENCE)
        );
    }
}

fn apply(mut state: ModelState, action: Action) -> Option<ModelState> {
    match action {
        Action::BarrierFail if !state.barrier_failed => state.barrier_failed = true,
        Action::BeginShutdown if state.phase == InterpreterPhase::Running => {
            state.phase = InterpreterPhase::ShuttingDown;
        }
        Action::CancelExecution if !state.cancellation && state.terminal.is_none() => {
            state.cancellation = true;
            state.root_marked = state.root == TaskStatus::Running;
            state.a_marked = nonterminal(state.child_a);
            state.b_marked = nonterminal(state.child_b);
        }
        Action::DetachA
            if source_action_allowed(state) && state.handle_a == HandleStatus::Attached =>
        {
            state.handle_a = HandleStatus::Detached;
        }
        Action::DetachB
            if source_action_allowed(state) && state.handle_b == HandleStatus::Attached =>
        {
            state.handle_b = HandleStatus::Detached;
        }
        Action::FailRoot
            if state.root == TaskStatus::Running && !state.root_failure && !state.root_marked =>
        {
            state.root_failure = true;
            state.a_marked = attached_nonterminal(state.child_a, state.handle_a);
            state.b_marked = attached_nonterminal(state.child_b, state.handle_b);
        }
        Action::FinishShutdown
            if state.phase == InterpreterPhase::ShuttingDown && state.terminal.is_some() =>
        {
            state.phase = InterpreterPhase::Terminated;
        }
        Action::ForegroundComplete if state.foreground.is_none() && foreground_ready(state) => {
            state.foreground = Some(task_outcome(state.root));
        }
        Action::JoinA
            if source_action_allowed(state) && state.handle_a == HandleStatus::Attached =>
        {
            state.handle_a = HandleStatus::Joined;
        }
        Action::JoinB
            if source_action_allowed(state) && state.handle_b == HandleStatus::Attached =>
        {
            state.handle_b = HandleStatus::Joined;
        }
        Action::SettleACancelled if state.a_marked && nonterminal(state.child_a) => {
            state.child_a = TaskStatus::Cancelled;
            if state.handle_a == HandleStatus::Pending {
                state.handle_a = HandleStatus::Attached;
            }
        }
        Action::SettleAFailed if state.child_a == TaskStatus::Running && !state.a_marked => {
            state.child_a = TaskStatus::Failed;
        }
        Action::SettleASucceeded if state.child_a == TaskStatus::Running && !state.a_marked => {
            state.child_a = TaskStatus::Succeeded;
        }
        Action::SettleBCancelled if state.b_marked && nonterminal(state.child_b) => {
            state.child_b = TaskStatus::Cancelled;
            if state.handle_b == HandleStatus::Pending {
                state.handle_b = HandleStatus::Attached;
            }
        }
        Action::SettleBFailed if state.child_b == TaskStatus::Running && !state.b_marked => {
            state.child_b = TaskStatus::Failed;
        }
        Action::SettleBSucceeded if state.child_b == TaskStatus::Running && !state.b_marked => {
            state.child_b = TaskStatus::Succeeded;
        }
        Action::SettleRootCancelled
            if state.root == TaskStatus::Running && state.root_marked && !state.root_failure =>
        {
            state.root = TaskStatus::Cancelled;
        }
        Action::SettleRootFailed
            if state.root == TaskStatus::Running
                && state.root_failure
                && attached_drain_complete(state) =>
        {
            state.root = TaskStatus::Failed;
        }
        Action::SettleRootSucceeded
            if source_action_allowed(state)
                && handles_discharged(state.handle_a, state.handle_b) =>
        {
            state.root = TaskStatus::Succeeded;
        }
        Action::SpawnA if source_action_allowed(state) && state.child_a == TaskStatus::Absent => {
            state.child_a = TaskStatus::Submitting;
            state.handle_a = HandleStatus::Pending;
        }
        Action::SpawnB if source_action_allowed(state) && state.child_b == TaskStatus::Absent => {
            state.child_b = TaskStatus::Submitting;
            state.handle_b = HandleStatus::Pending;
        }
        Action::SubmitAFailed if state.child_a == TaskStatus::Submitting && !state.a_marked => {
            state.child_a = TaskStatus::Failed;
            state.handle_a = HandleStatus::Attached;
        }
        Action::SubmitAOk if state.child_a == TaskStatus::Submitting && !state.a_marked => {
            state.child_a = TaskStatus::Running;
            state.handle_a = HandleStatus::Attached;
        }
        Action::SubmitBFailed if state.child_b == TaskStatus::Submitting && !state.b_marked => {
            state.child_b = TaskStatus::Failed;
            state.handle_b = HandleStatus::Attached;
        }
        Action::SubmitBOk if state.child_b == TaskStatus::Submitting && !state.b_marked => {
            state.child_b = TaskStatus::Running;
            state.handle_b = HandleStatus::Attached;
        }
        Action::TerminalComplete
            if state.terminal.is_none()
                && state.foreground.is_some()
                && task_terminal(state.child_a)
                && task_terminal(state.child_b) =>
        {
            state.terminal = Some(terminal_category(state));
        }
        _ => return None,
    }
    Some(state)
}

fn source_action_allowed(state: ModelState) -> bool {
    state.root == TaskStatus::Running
        && !state.root_marked
        && !state.root_failure
        && !state.cancellation
        && !joined_failure(state)
        && !join_is_pending(state.child_a, state.handle_a)
        && !join_is_pending(state.child_b, state.handle_b)
}

fn attached_nonterminal(child: TaskStatus, handle: HandleStatus) -> bool {
    handle != HandleStatus::Detached && nonterminal(child)
}

fn attached_drain_complete(state: ModelState) -> bool {
    [
        (state.child_a, state.handle_a),
        (state.child_b, state.handle_b),
    ]
    .into_iter()
    .all(|(child, handle)| handle == HandleStatus::Detached || task_terminal(child))
}

fn joined_failure(state: ModelState) -> bool {
    (state.handle_a == HandleStatus::Joined && state.child_a == TaskStatus::Failed)
        || (state.handle_b == HandleStatus::Joined && state.child_b == TaskStatus::Failed)
}

fn handles_discharged(first: HandleStatus, second: HandleStatus) -> bool {
    [first, second].into_iter().all(|handle| {
        matches!(
            handle,
            HandleStatus::Absent | HandleStatus::Joined | HandleStatus::Detached
        )
    })
}

fn join_is_pending(child: TaskStatus, handle: HandleStatus) -> bool {
    handle == HandleStatus::Joined && !task_terminal(child)
}

fn waits_for_host(state: ModelState) -> bool {
    (state.child_a == TaskStatus::Submitting && !state.a_marked)
        || (state.child_b == TaskStatus::Submitting && !state.b_marked)
}

fn foreground_ready(state: ModelState) -> bool {
    if !task_terminal(state.root) {
        return false;
    }
    attached_ready(state.root, state.child_a, state.handle_a)
        && attached_ready(state.root, state.child_b, state.handle_b)
}

fn attached_ready(root: TaskStatus, child: TaskStatus, handle: HandleStatus) -> bool {
    match handle {
        HandleStatus::Absent | HandleStatus::Detached => true,
        HandleStatus::Joined => task_terminal(child),
        HandleStatus::Attached => root != TaskStatus::Succeeded && task_terminal(child),
        HandleStatus::Pending => false,
    }
}

fn terminal_category(state: ModelState) -> TerminalCategory {
    if state.root == TaskStatus::Failed {
        TerminalCategory::RuntimeFailure
    } else if (state.handle_a == HandleStatus::Detached && state.child_a == TaskStatus::Failed)
        || (state.handle_b == HandleStatus::Detached && state.child_b == TaskStatus::Failed)
    {
        TerminalCategory::DetachedTaskFailure
    } else if state.cancellation || state.root == TaskStatus::Cancelled {
        TerminalCategory::Cancellation
    } else {
        TerminalCategory::Success
    }
}

fn assert_invariants(state: ModelState) {
    assert!(state.generic_descriptor_closed);
    assert!(state.concrete_call_target_selected);
    assert_eq!(state.concurrent_generic_analysis_steps, 0);
    assert_eq!(
        state.child_a == TaskStatus::Absent,
        state.handle_a == HandleStatus::Absent
    );
    assert_eq!(
        state.child_b == TaskStatus::Absent,
        state.handle_b == HandleStatus::Absent
    );
    assert_eq!(
        state.child_a == TaskStatus::Submitting,
        state.handle_a == HandleStatus::Pending
    );
    assert_eq!(
        state.child_b == TaskStatus::Submitting,
        state.handle_b == HandleStatus::Pending
    );
    assert!(!state.root_marked || state.cancellation);
    assert!(!state.a_marked || state.cancellation || state.root_failure);
    assert!(!state.b_marked || state.cancellation || state.root_failure);
    if state.root_failure {
        assert_ne!(state.root, TaskStatus::Succeeded);
    }
    if let Some(foreground) = state.foreground {
        assert!(foreground_ready(state));
        assert_eq!(foreground, task_outcome(state.root));
    }
    if let Some(terminal) = state.terminal {
        assert!(state.foreground.is_some());
        assert!(task_terminal(state.child_a));
        assert!(task_terminal(state.child_b));
        assert_eq!(terminal, terminal_category(state));
    }
    if state.phase == InterpreterPhase::Terminated {
        assert!(state.terminal.is_some());
    }
}

fn nonterminal(status: TaskStatus) -> bool {
    matches!(status, TaskStatus::Submitting | TaskStatus::Running)
}

fn task_terminal(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Absent | TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

fn task_outcome(status: TaskStatus) -> Outcome {
    match status {
        TaskStatus::Succeeded => Outcome::Succeeded,
        TaskStatus::Failed => Outcome::Failed,
        TaskStatus::Cancelled => Outcome::Cancelled,
        TaskStatus::Absent | TaskStatus::Submitting | TaskStatus::Running => {
            unreachable!("outcome requires settled root")
        }
    }
}

fn validate_evidence_anchor(root: &Path, evidence: &str) {
    let (path, test) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("evidence anchor has no test: {evidence}"));
    assert!(path.starts_with("crates/gantry-conformance/tests/"));
    assert!(path.ends_with(".rs"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read evidence {path}: {error}"));
    assert!(source.contains(&format!("fn {test}(")), "{evidence}");
}

fn assert_sorted_unique(values: &[impl AsRef<str>]) {
    assert!(
        values
            .windows(2)
            .all(|pair| pair[0].as_ref() < pair[1].as_ref())
    );
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
