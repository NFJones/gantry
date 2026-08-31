//! Bounded model and written-argument checks for sequential evaluator refinement.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const MODEL_EVIDENCE: &str = "crates/gantry-conformance/tests/sequential_refinement_model.rs#bounded_sequential_refinement_model_and_counterexamples_replay";
const OBLIGATIONS: [&str; 8] = [
    "enabled-machine-progress",
    "type-and-store-preservation",
    "base-handle-ownership-vacuous",
    "operation-single-consumption",
    "cancellation-nonconsumption",
    "lifecycle-linearization",
    "fixed-outcome-observation-isolation",
    "terminal-completion-uniqueness",
];
const ACTIONS: [Action; 17] = [
    Action::AdmitNewWork,
    Action::BarrierFail,
    Action::BeginShutdown,
    Action::Cancel,
    Action::DeterministicStep,
    Action::FinishShutdown,
    Action::ForegroundComplete,
    Action::ObserveHostOutcome,
    Action::OperationFail,
    Action::PrepareOperation,
    Action::RetryReady,
    Action::SelectRetry,
    Action::SettleCancelled,
    Action::SettleFailed,
    Action::SettleSucceeded,
    Action::TerminalComplete,
    Action::ValidateAccept,
];
const MACHINE_ACTIONS: [Action; 9] = [
    Action::Cancel,
    Action::DeterministicStep,
    Action::OperationFail,
    Action::PrepareOperation,
    Action::SelectRetry,
    Action::SettleCancelled,
    Action::SettleFailed,
    Action::SettleSucceeded,
    Action::ValidateAccept,
];

#[derive(Debug, Deserialize)]
struct RefinementManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profiles: Vec<String>,
    argument: String,
    model: String,
    model_evidence: String,
    reviewed_clauses: Vec<ReviewedClauseLink>,
    excluded_clauses: Vec<ExcludedClauseLink>,
    trace_evidence: Vec<String>,
    evidence_manifests: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClauseLink {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExcludedClauseLink {
    requirement: String,
    clause: String,
    profile: String,
    rationale: String,
}

#[derive(Debug, Deserialize)]
struct SequentialModel {
    format: String,
    maximum_depth: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    obligations: Vec<String>,
    assumptions: Vec<String>,
    host_wait_states: Vec<String>,
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
    rationale: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum InterpreterPhase {
    Running,
    ShuttingDown,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TaskStatus {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OperationStatus {
    Absent,
    Prepared,
    Outcome,
    RetryWaiting,
    Accepted,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ValueType {
    Unit,
    Int,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Outcome {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelState {
    phase: InterpreterPhase,
    task: TaskStatus,
    operation: OperationStatus,
    value_type: ValueType,
    remaining_source_steps: u8,
    accepted_results: u8,
    cancelled: bool,
    source_steps_at_cancellation: Option<u8>,
    accepted_results_at_cancellation: Option<u8>,
    foreground: Option<Outcome>,
    terminal: Option<Outcome>,
    required_barrier_failed: bool,
}

impl ModelState {
    const fn initial(value_type: ValueType) -> Self {
        Self {
            phase: InterpreterPhase::Running,
            task: TaskStatus::Running,
            operation: OperationStatus::Absent,
            value_type,
            remaining_source_steps: 1,
            accepted_results: 0,
            cancelled: false,
            source_steps_at_cancellation: None,
            accepted_results_at_cancellation: None,
            foreground: None,
            terminal: None,
            required_barrier_failed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    AdmitNewWork,
    BarrierFail,
    BeginShutdown,
    Cancel,
    DeterministicStep,
    FinishShutdown,
    ForegroundComplete,
    ObserveHostOutcome,
    OperationFail,
    PrepareOperation,
    RetryReady,
    SelectRetry,
    SettleCancelled,
    SettleFailed,
    SettleSucceeded,
    TerminalComplete,
    ValidateAccept,
}

impl Action {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "admit-new-work" => Self::AdmitNewWork,
            "barrier-fail" => Self::BarrierFail,
            "begin-shutdown" => Self::BeginShutdown,
            "cancel" => Self::Cancel,
            "deterministic-step" => Self::DeterministicStep,
            "finish-shutdown" => Self::FinishShutdown,
            "foreground-complete" => Self::ForegroundComplete,
            "observe-host-outcome" => Self::ObserveHostOutcome,
            "operation-fail" => Self::OperationFail,
            "prepare-operation" => Self::PrepareOperation,
            "retry-ready" => Self::RetryReady,
            "select-retry" => Self::SelectRetry,
            "settle-cancelled" => Self::SettleCancelled,
            "settle-failed" => Self::SettleFailed,
            "settle-succeeded" => Self::SettleSucceeded,
            "terminal-complete" => Self::TerminalComplete,
            "validate-accept" => Self::ValidateAccept,
            _ => return None,
        })
    }
}

#[test]
fn bounded_sequential_refinement_model_and_counterexamples_replay() {
    let root = workspace_root();
    let model: SequentialModel =
        read_json(&root.join("protocol/goldens/sequential-evaluator-model-v1.json"));
    assert_eq!(model.format, "gantry.sequential-evaluator-model/v1");
    assert_eq!(model.obligations, OBLIGATIONS);
    assert!(!model.assumptions.is_empty());
    assert_eq!(
        model.host_wait_states,
        ["prepared-integration-result", "retry-waiting-timer"]
    );

    let mut visited = BTreeSet::new();
    let mut pending = VecDeque::new();
    for value_type in [ValueType::Unit, ValueType::Int] {
        let state = ModelState::initial(value_type);
        visited.insert(state);
        pending.push_back((state, 0_usize));
    }
    while let Some((state, depth)) = pending.pop_front() {
        assert_invariants(state);
        if state.task == TaskStatus::Running && !waits_for_host(state) {
            assert!(
                MACHINE_ACTIONS
                    .iter()
                    .any(|action| apply(state, *action).is_some()),
                "enabled nonterminal machine state has no Gantry transition: {state:?}"
            );
        }
        if depth == model.maximum_depth {
            continue;
        }
        for action in ACTIONS {
            let Some(next) = apply(state, action) else {
                continue;
            };
            assert_eq!(next.value_type, state.value_type);
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
        let mut state = ModelState::initial(ValueType::Unit);
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
fn written_sequential_argument_links_current_reviewed_evidence() {
    let root = workspace_root();
    let manifest: RefinementManifest =
        read_json(&root.join("protocol/conformance/sequential-evaluator-refinement-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    assert_eq!(
        manifest.format,
        "gantry.sequential-evaluator-refinement-evidence/v1"
    );
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-RUN-002");
    assert_eq!(manifest.profiles, ["embedding", "evaluator"]);
    assert_eq!(manifest.model_evidence, MODEL_EVIDENCE);
    assert!(manifest.exclusions.len() >= 3);
    assert_sorted_unique(&manifest.trace_evidence);
    assert_sorted_unique(&manifest.evidence_manifests);

    let argument = fs::read_to_string(root.join(&manifest.argument))
        .unwrap_or_else(|error| panic!("could not read sequential argument: {error}"));
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
    assert!(argument.contains("no unconditional termination"));
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
        assert_sorted_unique(&link.profiles);
        let clause = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == link.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == link.clause)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing reviewed clause {}#{}",
                    link.requirement, link.clause
                )
            });
        for profile in &link.profiles {
            let reviewed = clause
                .profile_reviews
                .iter()
                .find(|review| review.profile == *profile)
                .unwrap_or_else(|| {
                    panic!(
                        "missing {profile} review for {}#{}",
                        link.requirement, link.clause
                    )
                });
            assert_eq!(reviewed.state, "covered");
            assert!(
                reviewed
                    .evidence
                    .iter()
                    .any(|value| value == MODEL_EVIDENCE)
            );
        }
    }

    let exclusions = manifest
        .excluded_clauses
        .iter()
        .map(|link| format!("{}#{}#{}", link.requirement, link.clause, link.profile))
        .collect::<Vec<_>>();
    assert_sorted_unique(&exclusions);
    for link in &manifest.excluded_clauses {
        assert!(!link.rationale.is_empty());
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
                    .find(|review| review.profile == link.profile)
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing {} review for {}#{}",
                    link.profile, link.requirement, link.clause
                )
            });
        assert_eq!(reviewed.state, "not-applicable");
        assert!(reviewed.evidence.is_empty());
        assert_eq!(reviewed.rationale.as_deref(), Some(link.rationale.as_str()));
    }
}

fn apply(mut state: ModelState, action: Action) -> Option<ModelState> {
    match action {
        Action::AdmitNewWork if state.phase == InterpreterPhase::Running => {}
        Action::BarrierFail if !state.required_barrier_failed => {
            state.required_barrier_failed = true;
        }
        Action::BeginShutdown if state.phase == InterpreterPhase::Running => {
            state.phase = InterpreterPhase::ShuttingDown;
        }
        Action::Cancel if state.task == TaskStatus::Running && !state.cancelled => {
            state.cancelled = true;
            state.source_steps_at_cancellation = Some(state.remaining_source_steps);
            state.accepted_results_at_cancellation = Some(state.accepted_results);
        }
        Action::DeterministicStep
            if state.task == TaskStatus::Running
                && !state.cancelled
                && state.operation == OperationStatus::Absent
                && state.remaining_source_steps > 0 =>
        {
            state.remaining_source_steps -= 1;
        }
        Action::FinishShutdown
            if state.phase == InterpreterPhase::ShuttingDown && state.terminal.is_some() =>
        {
            state.phase = InterpreterPhase::Terminated;
        }
        Action::ForegroundComplete
            if state.task != TaskStatus::Running && state.foreground.is_none() =>
        {
            state.foreground = Some(task_outcome(state.task));
        }
        Action::ObserveHostOutcome if state.operation == OperationStatus::Prepared => {
            state.operation = OperationStatus::Outcome;
        }
        Action::OperationFail
            if state.task == TaskStatus::Running
                && !state.cancelled
                && state.operation == OperationStatus::Outcome =>
        {
            state.operation = OperationStatus::Failed;
        }
        Action::PrepareOperation
            if state.task == TaskStatus::Running
                && !state.cancelled
                && state.operation == OperationStatus::Absent =>
        {
            state.operation = OperationStatus::Prepared;
        }
        Action::RetryReady
            if state.task == TaskStatus::Running
                && !state.cancelled
                && state.operation == OperationStatus::RetryWaiting =>
        {
            state.operation = OperationStatus::Prepared;
        }
        Action::SelectRetry
            if state.task == TaskStatus::Running
                && !state.cancelled
                && state.operation == OperationStatus::Outcome =>
        {
            state.operation = OperationStatus::RetryWaiting;
        }
        Action::SettleCancelled if state.task == TaskStatus::Running && state.cancelled => {
            state.task = TaskStatus::Cancelled;
        }
        Action::SettleFailed
            if state.task == TaskStatus::Running && state.operation == OperationStatus::Failed =>
        {
            state.task = TaskStatus::Failed;
        }
        Action::SettleSucceeded
            if state.task == TaskStatus::Running
                && !state.cancelled
                && (state.remaining_source_steps == 0
                    || state.operation == OperationStatus::Accepted) =>
        {
            state.task = TaskStatus::Succeeded;
        }
        Action::TerminalComplete
            if state.task != TaskStatus::Running
                && state.foreground.is_some()
                && state.terminal.is_none() =>
        {
            state.terminal = state.foreground;
        }
        Action::ValidateAccept
            if state.task == TaskStatus::Running
                && !state.cancelled
                && state.operation == OperationStatus::Outcome
                && state.accepted_results == 0 =>
        {
            state.operation = OperationStatus::Accepted;
            state.accepted_results = 1;
        }
        _ => return None,
    }
    Some(state)
}

fn waits_for_host(state: ModelState) -> bool {
    !state.cancelled
        && matches!(
            state.operation,
            OperationStatus::Prepared | OperationStatus::RetryWaiting
        )
}

fn assert_invariants(state: ModelState) {
    assert!(state.accepted_results <= 1);
    assert_eq!(
        state.operation == OperationStatus::Accepted,
        state.accepted_results == 1
    );
    if state.cancelled {
        assert_eq!(
            state.source_steps_at_cancellation,
            Some(state.remaining_source_steps)
        );
        assert_eq!(
            state.accepted_results_at_cancellation,
            Some(state.accepted_results)
        );
    } else {
        assert!(state.source_steps_at_cancellation.is_none());
        assert!(state.accepted_results_at_cancellation.is_none());
    }
    if let Some(terminal) = state.terminal {
        assert_eq!(state.foreground, Some(terminal));
        assert_ne!(state.task, TaskStatus::Running);
    }
    if state.phase == InterpreterPhase::Terminated {
        assert!(state.terminal.is_some());
    }
}

fn task_outcome(status: TaskStatus) -> Outcome {
    match status {
        TaskStatus::Succeeded => Outcome::Succeeded,
        TaskStatus::Failed => Outcome::Failed,
        TaskStatus::Cancelled => Outcome::Cancelled,
        TaskStatus::Running => unreachable!("foreground completion requires settlement"),
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
