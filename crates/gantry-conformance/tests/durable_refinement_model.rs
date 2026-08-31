//! Bounded model and written-argument checks for durable-runtime refinement.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const MODEL_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_refinement_model.rs#bounded_durable_refinement_model_and_counterexamples_replay";
const OBLIGATIONS: [&str; 10] = [
    "cancellation-nonconsumption",
    "causally-closed-prefix-recovery",
    "commit-before-observation",
    "compaction-equivalent-projection",
    "fixed-outcome-status-isolation",
    "indeterminate-delivery-classification",
    "indeterminate-operation-classification",
    "recorded-delay-reuse",
    "single-result-consumption",
    "terminal-completion-uniqueness",
];
const ACTIONS: [Action; 25] = [
    Action::AcceptResult,
    Action::BeginShutdown,
    Action::CommitCancellation,
    Action::CommitEventCause,
    Action::CommitEventOccurrence,
    Action::CommitForeground,
    Action::CommitOperationOutcome,
    Action::CommitTerminal,
    Action::DispatchDelivery,
    Action::FailBarrier,
    Action::FailOwnerRelease,
    Action::FinishShutdown,
    Action::OperationRetryReady,
    Action::PrepareNonIdempotent,
    Action::PrepareReadOnly,
    Action::ReleaseOwner,
    Action::SelectDeliveryRetry,
    Action::SelectOperationRetry,
    Action::SettleBarrierSuccess,
    Action::SettleCancelled,
    Action::SettleDeliverySuccess,
    Action::SettleDeliveryTerminal,
    Action::SettleFailed,
    Action::SettleSucceeded,
    Action::DeliveryRetryReady,
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
struct DurableModel {
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
enum TaskState {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OperationState {
    Absent,
    PreparedReadOnly,
    PreparedNonIdempotent,
    Outcome,
    RetryWaiting,
    Accepted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DeliveryState {
    Absent,
    Cause,
    Occurrence,
    Dispatched,
    RetryWaiting,
    Success,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BarrierState {
    Pending,
    Satisfied,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OwnerState {
    Held,
    Released,
    ReleaseFailed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Outcome {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Representation {
    Full,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelState {
    phase: InterpreterPhase,
    task: TaskState,
    operation: OperationState,
    delivery: DeliveryState,
    barrier: BarrierState,
    owner: OwnerState,
    cancelled: bool,
    accepted_results: u8,
    foreground: Option<Outcome>,
    terminal: Option<Outcome>,
    representation: Representation,
}

impl ModelState {
    const fn initial(representation: Representation) -> Self {
        Self {
            phase: InterpreterPhase::Running,
            task: TaskState::Running,
            operation: OperationState::Absent,
            delivery: DeliveryState::Absent,
            barrier: BarrierState::Pending,
            owner: OwnerState::Held,
            cancelled: false,
            accepted_results: 0,
            foreground: None,
            terminal: None,
            representation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationRecovery {
    None,
    Redispatch,
    UnknownOutcome,
    ReuseOutcome,
    RetryDelay,
    ReuseResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryRecovery {
    None,
    CreateReplacement,
    Ready,
    Indeterminate,
    RetryDelay,
    Settled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryProjection {
    phase: InterpreterPhase,
    task: TaskState,
    operation: OperationRecovery,
    delivery: DeliveryRecovery,
    barrier: BarrierState,
    owner: OwnerState,
    cancelled: bool,
    accepted_results: u8,
    foreground: Option<Outcome>,
    terminal: Option<Outcome>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    AcceptResult,
    BeginShutdown,
    CommitCancellation,
    CommitEventCause,
    CommitEventOccurrence,
    CommitForeground,
    CommitOperationOutcome,
    CommitTerminal,
    DeliveryRetryReady,
    DispatchDelivery,
    FailBarrier,
    FailOwnerRelease,
    FinishShutdown,
    OperationRetryReady,
    PrepareNonIdempotent,
    PrepareReadOnly,
    ReleaseOwner,
    SelectDeliveryRetry,
    SelectOperationRetry,
    SettleBarrierSuccess,
    SettleCancelled,
    SettleDeliverySuccess,
    SettleDeliveryTerminal,
    SettleFailed,
    SettleSucceeded,
}

impl Action {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "accept-result" => Self::AcceptResult,
            "begin-shutdown" => Self::BeginShutdown,
            "commit-cancellation" => Self::CommitCancellation,
            "commit-event-cause" => Self::CommitEventCause,
            "commit-event-occurrence" => Self::CommitEventOccurrence,
            "commit-foreground" => Self::CommitForeground,
            "commit-operation-outcome" => Self::CommitOperationOutcome,
            "commit-terminal" => Self::CommitTerminal,
            "delivery-retry-ready" => Self::DeliveryRetryReady,
            "dispatch-delivery" => Self::DispatchDelivery,
            "fail-barrier" => Self::FailBarrier,
            "fail-owner-release" => Self::FailOwnerRelease,
            "finish-shutdown" => Self::FinishShutdown,
            "operation-retry-ready" => Self::OperationRetryReady,
            "prepare-non-idempotent" => Self::PrepareNonIdempotent,
            "prepare-read-only" => Self::PrepareReadOnly,
            "release-owner" => Self::ReleaseOwner,
            "select-delivery-retry" => Self::SelectDeliveryRetry,
            "select-operation-retry" => Self::SelectOperationRetry,
            "settle-barrier-success" => Self::SettleBarrierSuccess,
            "settle-cancelled" => Self::SettleCancelled,
            "settle-delivery-success" => Self::SettleDeliverySuccess,
            "settle-delivery-terminal" => Self::SettleDeliveryTerminal,
            "settle-failed" => Self::SettleFailed,
            "settle-succeeded" => Self::SettleSucceeded,
            _ => return None,
        })
    }
}

#[test]
fn bounded_durable_refinement_model_and_counterexamples_replay() {
    let root = workspace_root();
    let model: DurableModel =
        read_json(&root.join("protocol/goldens/durable-refinement-model-v1.json"));
    assert_eq!(model.format, "gantry.durable-refinement-model/v1");
    assert_eq!(model.obligations, OBLIGATIONS);
    assert!(
        model
            .assumptions
            .iter()
            .any(|value| value.contains("not an unbounded proof"))
    );

    let mut visited = BTreeSet::new();
    let mut pending = VecDeque::new();
    for representation in [Representation::Full, Representation::Snapshot] {
        let state = ModelState::initial(representation);
        visited.insert(state);
        pending.push_back((state, 0_usize));
    }
    while let Some((state, depth)) = pending.pop_front() {
        assert_invariants(state);
        assert_compaction_equivalence(state);
        if depth == model.maximum_depth {
            continue;
        }
        for action in ACTIONS {
            let Some(next) = apply(state, action) else {
                continue;
            };
            assert_invariants(next);
            if matches!(action, Action::FailBarrier | Action::FailOwnerRelease) {
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
    assert_sorted_unique(&ids);
    for case in &model.counterexamples {
        assert!(!case.invariant.is_empty());
        let mut state = ModelState::initial(Representation::Full);
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
fn written_durable_argument_links_current_reviewed_evidence() {
    let root = workspace_root();
    let manifest: RefinementManifest =
        read_json(&root.join("protocol/conformance/durable-refinement-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    assert_eq!(manifest.format, "gantry.durable-refinement-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-DUR-006");
    assert_eq!(manifest.profile, "durable-runtime");
    assert_eq!(manifest.model_evidence, MODEL_EVIDENCE);
    assert!(manifest.exclusions.len() >= 4);
    assert_sorted_unique(&manifest.trace_evidence);
    assert_sorted_unique(&manifest.evidence_manifests);

    let argument = fs::read_to_string(root.join(&manifest.argument))
        .unwrap_or_else(|error| panic!("could not read durable argument: {error}"));
    for heading in [
        "## Scope and claim",
        "## Assumptions, crash choices, and bounds",
        "## Recovery-prefix refinement mapping",
        "## Property argument",
        "## Requirement and trace links",
        "## Counterexample replay",
    ] {
        assert!(argument.contains(heading));
    }
    assert!(argument.contains("not an unbounded proof"));
    assert!(argument.contains("Genuinely pending"));
    assert!(argument.contains("Physical SQLite"));
    assert!(root.join(&manifest.model).is_file());

    validate_evidence_anchor(&root, &manifest.model_evidence);
    for evidence in &manifest.trace_evidence {
        validate_evidence_anchor(&root, evidence);
    }
    for path in &manifest.evidence_manifests {
        let value: serde_json::Value = read_json(&root.join(path));
        assert_eq!(value["specification_sha256"], review.specification_sha256);
    }
    let links = manifest
        .reviewed_clauses
        .iter()
        .map(|link| format!("{}#{}", link.requirement, link.clause))
        .collect::<Vec<_>>();
    assert_sorted_unique(&links);
    for link in &manifest.reviewed_clauses {
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
                    "missing durable review for {}#{}",
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
        Action::AcceptResult
            if state.task == TaskState::Running
                && !state.cancelled
                && state.operation == OperationState::Outcome
                && state.accepted_results == 0 =>
        {
            state.operation = OperationState::Accepted;
            state.accepted_results = 1;
        }
        Action::BeginShutdown if state.phase == InterpreterPhase::Running => {
            state.phase = InterpreterPhase::ShuttingDown;
        }
        Action::CommitCancellation if state.task == TaskState::Running && !state.cancelled => {
            state.cancelled = true;
        }
        Action::CommitEventCause if state.delivery == DeliveryState::Absent => {
            state.delivery = DeliveryState::Cause;
        }
        Action::CommitEventOccurrence if state.delivery == DeliveryState::Cause => {
            state.delivery = DeliveryState::Occurrence;
        }
        Action::CommitForeground
            if state.task != TaskState::Running && state.foreground.is_none() =>
        {
            state.foreground = Some(task_outcome(state.task));
        }
        Action::CommitOperationOutcome
            if matches!(
                state.operation,
                OperationState::PreparedReadOnly | OperationState::PreparedNonIdempotent
            ) =>
        {
            state.operation = OperationState::Outcome;
        }
        Action::CommitTerminal if state.foreground.is_some() && state.terminal.is_none() => {
            state.terminal = state.foreground;
        }
        Action::DeliveryRetryReady if state.delivery == DeliveryState::RetryWaiting => {
            state.delivery = DeliveryState::Occurrence;
        }
        Action::DispatchDelivery if state.delivery == DeliveryState::Occurrence => {
            state.delivery = DeliveryState::Dispatched;
        }
        Action::FailBarrier
            if state.terminal.is_some() && state.barrier == BarrierState::Pending =>
        {
            state.barrier = BarrierState::Failed;
        }
        Action::FailOwnerRelease
            if state.terminal.is_some()
                && state.barrier != BarrierState::Pending
                && state.owner == OwnerState::Held =>
        {
            state.owner = OwnerState::ReleaseFailed;
        }
        Action::FinishShutdown
            if state.phase == InterpreterPhase::ShuttingDown
                && state.terminal.is_some()
                && state.owner != OwnerState::Held =>
        {
            state.phase = InterpreterPhase::Terminated;
        }
        Action::OperationRetryReady if state.operation == OperationState::RetryWaiting => {
            state.operation = OperationState::PreparedReadOnly;
        }
        Action::PrepareNonIdempotent
            if source_action_allowed(state) && state.operation == OperationState::Absent =>
        {
            state.operation = OperationState::PreparedNonIdempotent;
        }
        Action::PrepareReadOnly
            if source_action_allowed(state) && state.operation == OperationState::Absent =>
        {
            state.operation = OperationState::PreparedReadOnly;
        }
        Action::ReleaseOwner
            if state.terminal.is_some()
                && state.barrier != BarrierState::Pending
                && state.owner == OwnerState::Held =>
        {
            state.owner = OwnerState::Released;
        }
        Action::SelectDeliveryRetry if state.delivery == DeliveryState::Dispatched => {
            state.delivery = DeliveryState::RetryWaiting;
        }
        Action::SelectOperationRetry
            if state.operation == OperationState::Outcome && !state.cancelled =>
        {
            state.operation = OperationState::RetryWaiting;
        }
        Action::SettleBarrierSuccess
            if state.terminal.is_some() && state.barrier == BarrierState::Pending =>
        {
            state.barrier = BarrierState::Satisfied;
        }
        Action::SettleCancelled if state.task == TaskState::Running && state.cancelled => {
            state.task = TaskState::Cancelled;
        }
        Action::SettleDeliverySuccess if state.delivery == DeliveryState::Dispatched => {
            state.delivery = DeliveryState::Success;
        }
        Action::SettleDeliveryTerminal if state.delivery == DeliveryState::Dispatched => {
            state.delivery = DeliveryState::Terminal;
        }
        Action::SettleFailed
            if state.task == TaskState::Running
                && state.operation == OperationState::Outcome
                && !state.cancelled =>
        {
            state.task = TaskState::Failed;
        }
        Action::SettleSucceeded
            if state.task == TaskState::Running
                && !state.cancelled
                && matches!(
                    state.operation,
                    OperationState::Absent | OperationState::Accepted
                ) =>
        {
            state.task = TaskState::Succeeded;
        }
        _ => return None,
    }
    Some(state)
}

fn source_action_allowed(state: ModelState) -> bool {
    state.task == TaskState::Running && !state.cancelled && state.terminal.is_none()
}

fn recover(state: ModelState) -> RecoveryProjection {
    RecoveryProjection {
        phase: state.phase,
        task: state.task,
        operation: match state.operation {
            OperationState::Absent => OperationRecovery::None,
            OperationState::PreparedReadOnly => OperationRecovery::Redispatch,
            OperationState::PreparedNonIdempotent => OperationRecovery::UnknownOutcome,
            OperationState::Outcome => OperationRecovery::ReuseOutcome,
            OperationState::RetryWaiting => OperationRecovery::RetryDelay,
            OperationState::Accepted => OperationRecovery::ReuseResult,
        },
        delivery: match state.delivery {
            DeliveryState::Absent => DeliveryRecovery::None,
            DeliveryState::Cause => DeliveryRecovery::CreateReplacement,
            DeliveryState::Occurrence => DeliveryRecovery::Ready,
            DeliveryState::Dispatched => DeliveryRecovery::Indeterminate,
            DeliveryState::RetryWaiting => DeliveryRecovery::RetryDelay,
            DeliveryState::Success | DeliveryState::Terminal => DeliveryRecovery::Settled,
        },
        barrier: state.barrier,
        owner: state.owner,
        cancelled: state.cancelled,
        accepted_results: state.accepted_results,
        foreground: state.foreground,
        terminal: state.terminal,
    }
}

fn assert_compaction_equivalence(state: ModelState) {
    let full = ModelState {
        representation: Representation::Full,
        ..state
    };
    let snapshot = ModelState {
        representation: Representation::Snapshot,
        ..state
    };
    assert_eq!(recover(full), recover(snapshot));
}

fn assert_invariants(state: ModelState) {
    assert!(state.accepted_results <= 1);
    assert_eq!(
        state.operation == OperationState::Accepted,
        state.accepted_results == 1
    );
    if state.cancelled {
        assert_ne!(state.task, TaskState::Succeeded);
    }
    if let Some(foreground) = state.foreground {
        assert_eq!(foreground, task_outcome(state.task));
        assert_ne!(state.task, TaskState::Running);
    }
    if let Some(terminal) = state.terminal {
        assert_eq!(state.foreground, Some(terminal));
    }
    if state.owner != OwnerState::Held {
        assert!(state.terminal.is_some());
        assert_ne!(state.barrier, BarrierState::Pending);
    }
    if state.phase == InterpreterPhase::Terminated {
        assert!(state.terminal.is_some());
        assert_ne!(state.owner, OwnerState::Held);
    }
}

fn task_outcome(task: TaskState) -> Outcome {
    match task {
        TaskState::Succeeded => Outcome::Succeeded,
        TaskState::Failed => Outcome::Failed,
        TaskState::Cancelled => Outcome::Cancelled,
        TaskState::Running => unreachable!("foreground completion requires settlement"),
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
