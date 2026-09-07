//! Bounded model and written-argument checks for durable-runtime refinement.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const MODEL_EVIDENCE: &str = "crates/gantry-conformance/tests/durable_refinement_model.rs#bounded_durable_refinement_model_and_counterexamples_replay";
const OBLIGATIONS: [&str; 15] = [
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
    "retained-generic-projection-equivalence",
    "source-free-generic-recovery",
    "selected-target-preservation",
    "no-recovery-generic-analysis",
    "fail-closed-generic-artifacts",
];
const RECOVERED_GRAPH_OBLIGATIONS: [&str; 10] = [
    "coherent-reconstruction-before-submission",
    "complete-runnable-set-registration-behind-closed-gates",
    "exactly-once-logical-creation",
    "exactly-once-logical-foreground",
    "exactly-once-logical-ownership",
    "exactly-once-logical-result",
    "exactly-once-logical-settlement",
    "exactly-once-logical-terminal",
    "owner-epoch-fencing",
    "replacement-physical-submissions",
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
    recovered_graph_maximum_depth: usize,
    recovered_graph_explored_state_count: usize,
    recovered_graph_terminal_state_count: usize,
    obligations: Vec<String>,
    recovered_graph_obligations: Vec<String>,
    assumptions: Vec<String>,
    counterexamples: Vec<Counterexample>,
    recovered_graph_counterexamples: Vec<RecoveredGraphCounterexample>,
}

#[derive(Debug, Deserialize)]
struct Counterexample {
    id: String,
    trace: Vec<String>,
    rejected_action: String,
    invariant: String,
}

#[derive(Debug, Deserialize)]
struct RecoveredGraphCounterexample {
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
struct RecoveredGraphState {
    owner_epoch: u8,
    child_creation_commits: u8,
    child_ownership_commits: u8,
    root_reconstructed: bool,
    child_reconstructed: bool,
    admitted: bool,
    root_physical_submissions: u8,
    child_physical_submissions: u8,
    root_registered: bool,
    child_registered: bool,
    gates_open: bool,
    child_settlement_commits: u8,
    child_result_commits: u8,
    root_settlement_commits: u8,
    foreground_commits: u8,
    terminal_commits: u8,
}

impl RecoveredGraphState {
    const fn initial() -> Self {
        Self {
            owner_epoch: 1,
            child_creation_commits: 0,
            child_ownership_commits: 0,
            root_reconstructed: false,
            child_reconstructed: false,
            admitted: false,
            root_physical_submissions: 0,
            child_physical_submissions: 0,
            root_registered: false,
            child_registered: false,
            gates_open: false,
            child_settlement_commits: 0,
            child_result_commits: 0,
            root_settlement_commits: 0,
            foreground_commits: 0,
            terminal_commits: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelState {
    phase: InterpreterPhase,
    task: TaskState,
    generic_descriptor_closed: bool,
    concrete_call_target_selected: bool,
    concrete_effect_and_schema_selected: bool,
    executable_projection_validated: bool,
    recovery_generic_analysis_steps: u8,
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
            generic_descriptor_closed: true,
            concrete_call_target_selected: true,
            concrete_effect_and_schema_selected: true,
            executable_projection_validated: true,
            recovery_generic_analysis_steps: 0,
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
    generic_descriptor_closed: bool,
    concrete_call_target_selected: bool,
    concrete_effect_and_schema_selected: bool,
    executable_projection_validated: bool,
    recovery_generic_analysis_steps: u8,
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
    CommitTamperedGenericArtifact,
    RecoverOpenGeneric,
    ResolveTraitDuringRecovery,
    RewriteRecoveredCallTarget,
}

const RECOVERED_GRAPH_ACTIONS: [RecoveredGraphAction; 16] = [
    RecoveredGraphAction::AcquireReplacementOwner,
    RecoveredGraphAction::AdmitRecoveredGraph,
    RecoveredGraphAction::CommitChildCreation,
    RecoveredGraphAction::CommitChildOwnership,
    RecoveredGraphAction::CommitChildResult,
    RecoveredGraphAction::CommitChildSettlement,
    RecoveredGraphAction::CommitForeground,
    RecoveredGraphAction::CommitRootSettlement,
    RecoveredGraphAction::CommitTerminal,
    RecoveredGraphAction::OpenGates,
    RecoveredGraphAction::ReconstructChild,
    RecoveredGraphAction::ReconstructRoot,
    RecoveredGraphAction::RegisterChild,
    RecoveredGraphAction::RegisterRoot,
    RecoveredGraphAction::SubmitReplacementChild,
    RecoveredGraphAction::SubmitReplacementRoot,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveredGraphAction {
    AcquireReplacementOwner,
    AdmitRecoveredGraph,
    CommitChildCreation,
    CommitChildOwnership,
    CommitChildResult,
    CommitChildSettlement,
    CommitForeground,
    CommitRootSettlement,
    CommitTerminal,
    OpenGates,
    PublishFromStaleOwner,
    ReconstructChild,
    ReconstructRoot,
    RegisterChild,
    RegisterRoot,
    SubmitReplacementChild,
    SubmitReplacementRoot,
}

impl RecoveredGraphAction {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "acquire-replacement-owner" => Self::AcquireReplacementOwner,
            "admit-recovered-graph" => Self::AdmitRecoveredGraph,
            "commit-child-creation" => Self::CommitChildCreation,
            "commit-child-ownership" => Self::CommitChildOwnership,
            "commit-child-result" => Self::CommitChildResult,
            "commit-child-settlement" => Self::CommitChildSettlement,
            "commit-foreground" => Self::CommitForeground,
            "commit-root-settlement" => Self::CommitRootSettlement,
            "commit-terminal" => Self::CommitTerminal,
            "open-gates" => Self::OpenGates,
            "publish-from-stale-owner" => Self::PublishFromStaleOwner,
            "reconstruct-child" => Self::ReconstructChild,
            "reconstruct-root" => Self::ReconstructRoot,
            "register-child" => Self::RegisterChild,
            "register-root" => Self::RegisterRoot,
            "submit-replacement-child" => Self::SubmitReplacementChild,
            "submit-replacement-root" => Self::SubmitReplacementRoot,
            _ => return None,
        })
    }
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
            "commit-tampered-generic-artifact" => Self::CommitTamperedGenericArtifact,
            "recover-open-generic" => Self::RecoverOpenGeneric,
            "resolve-trait-during-recovery" => Self::ResolveTraitDuringRecovery,
            "rewrite-recovered-call-target" => Self::RewriteRecoveredCallTarget,
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
    assert_eq!(
        model.recovered_graph_obligations,
        RECOVERED_GRAPH_OBLIGATIONS
    );
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

    let mut recovered_visited = BTreeSet::from([RecoveredGraphState::initial()]);
    let mut recovered_pending = VecDeque::from([(RecoveredGraphState::initial(), 0_usize)]);
    while let Some((state, depth)) = recovered_pending.pop_front() {
        assert_recovered_graph_invariants(state);
        if depth == model.recovered_graph_maximum_depth {
            continue;
        }
        for action in RECOVERED_GRAPH_ACTIONS {
            let Some(next) = apply_recovered_graph(state, action) else {
                continue;
            };
            assert_recovered_graph_invariants(next);
            if recovered_visited.insert(next) {
                recovered_pending.push_back((next, depth.saturating_add(1)));
            }
        }
    }
    assert_eq!(
        recovered_visited.len(),
        model.recovered_graph_explored_state_count
    );
    assert_eq!(
        recovered_visited
            .iter()
            .filter(|state| state.terminal_commits == 1)
            .count(),
        model.recovered_graph_terminal_state_count
    );
    assert!(recovered_visited.iter().any(|state| {
        state.root_physical_submissions == 2
            && state.child_physical_submissions == 2
            && state.gates_open
    }));

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

    let recovered_ids = model
        .recovered_graph_counterexamples
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    assert_sorted_unique(&recovered_ids);
    for case in &model.recovered_graph_counterexamples {
        assert!(
            model
                .recovered_graph_obligations
                .iter()
                .any(|obligation| obligation == &case.invariant),
            "{}",
            case.id
        );
        let mut state = RecoveredGraphState::initial();
        for action in &case.trace {
            let action = RecoveredGraphAction::parse(action).unwrap_or_else(|| {
                panic!("unknown recovered-graph action in {}: {action}", case.id)
            });
            state = apply_recovered_graph(state, action).unwrap_or_else(|| {
                panic!(
                    "invalid recovered-graph replay prefix in {}: {action:?}",
                    case.id
                )
            });
        }
        let rejected = RecoveredGraphAction::parse(&case.rejected_action)
            .unwrap_or_else(|| panic!("unknown recovered-graph rejected action in {}", case.id));
        assert!(
            apply_recovered_graph(state, rejected).is_none(),
            "{}",
            case.id
        );
        assert_recovered_graph_invariants(state);
    }
}

#[test]
fn written_durable_argument_links_current_reviewed_evidence() {
    let root = workspace_root();
    let manifest: RefinementManifest =
        read_json(&root.join("protocol/conformance/durable-refinement-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));
    assert_eq!(manifest.format, "gantry.durable-refinement-evidence/v1");
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
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
        assert!(gantry_conformance::evidence_revision_is_expected(
            value["specification_sha256"].as_str().unwrap_or_default(),
            &review.specification_sha256,
        ));
    }
    let links = manifest
        .reviewed_clauses
        .iter()
        .map(|link| format!("{}#{}", link.requirement, link.clause))
        .collect::<Vec<_>>();
    assert_sorted_unique(&links);
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

fn apply_recovered_graph(
    mut state: RecoveredGraphState,
    action: RecoveredGraphAction,
) -> Option<RecoveredGraphState> {
    match action {
        RecoveredGraphAction::CommitChildCreation if state.child_creation_commits == 0 => {
            state.child_creation_commits = 1;
        }
        RecoveredGraphAction::CommitChildOwnership
            if state.child_creation_commits == 1 && state.child_ownership_commits == 0 =>
        {
            state.child_ownership_commits = 1;
        }
        RecoveredGraphAction::AcquireReplacementOwner
            if state.owner_epoch == 1 && state.child_ownership_commits == 1 =>
        {
            state.owner_epoch = 2;
        }
        RecoveredGraphAction::ReconstructRoot
            if state.owner_epoch == 2 && !state.root_reconstructed && !state.admitted =>
        {
            state.root_reconstructed = true;
        }
        RecoveredGraphAction::ReconstructChild
            if state.owner_epoch == 2 && !state.child_reconstructed && !state.admitted =>
        {
            state.child_reconstructed = true;
        }
        RecoveredGraphAction::AdmitRecoveredGraph
            if state.owner_epoch == 2
                && state.root_reconstructed
                && state.child_reconstructed
                && !state.admitted =>
        {
            state.admitted = true;
        }
        RecoveredGraphAction::SubmitReplacementRoot
            if state.admitted && !state.gates_open && state.root_physical_submissions < 2 =>
        {
            state.root_physical_submissions += 1;
        }
        RecoveredGraphAction::SubmitReplacementChild
            if state.admitted && !state.gates_open && state.child_physical_submissions < 2 =>
        {
            state.child_physical_submissions += 1;
        }
        RecoveredGraphAction::RegisterRoot
            if !state.gates_open
                && state.root_physical_submissions > 0
                && !state.root_registered =>
        {
            state.root_registered = true;
        }
        RecoveredGraphAction::RegisterChild
            if !state.gates_open
                && state.child_physical_submissions > 0
                && !state.child_registered =>
        {
            state.child_registered = true;
        }
        RecoveredGraphAction::OpenGates
            if state.admitted
                && state.root_registered
                && state.child_registered
                && !state.gates_open =>
        {
            state.gates_open = true;
        }
        RecoveredGraphAction::CommitChildSettlement
            if current_owner_can_publish(state)
                && state.child_settlement_commits == 0
                && state.root_settlement_commits == 0 =>
        {
            state.child_settlement_commits = 1;
        }
        RecoveredGraphAction::CommitChildResult
            if current_owner_can_publish(state)
                && state.child_settlement_commits == 1
                && state.child_result_commits == 0 =>
        {
            state.child_result_commits = 1;
        }
        RecoveredGraphAction::CommitRootSettlement
            if current_owner_can_publish(state)
                && state.child_result_commits == 1
                && state.root_settlement_commits == 0 =>
        {
            state.root_settlement_commits = 1;
        }
        RecoveredGraphAction::CommitForeground
            if current_owner_can_publish(state)
                && state.root_settlement_commits == 1
                && state.foreground_commits == 0 =>
        {
            state.foreground_commits = 1;
        }
        RecoveredGraphAction::CommitTerminal
            if current_owner_can_publish(state)
                && state.foreground_commits == 1
                && state.terminal_commits == 0 =>
        {
            state.terminal_commits = 1;
        }
        RecoveredGraphAction::PublishFromStaleOwner => return None,
        _ => return None,
    }
    Some(state)
}

fn current_owner_can_publish(state: RecoveredGraphState) -> bool {
    state.owner_epoch == 2 && state.gates_open
}

fn source_action_allowed(state: ModelState) -> bool {
    state.task == TaskState::Running && !state.cancelled && state.terminal.is_none()
}

fn recover(state: ModelState) -> RecoveryProjection {
    RecoveryProjection {
        phase: state.phase,
        task: state.task,
        generic_descriptor_closed: state.generic_descriptor_closed,
        concrete_call_target_selected: state.concrete_call_target_selected,
        concrete_effect_and_schema_selected: state.concrete_effect_and_schema_selected,
        executable_projection_validated: state.executable_projection_validated,
        recovery_generic_analysis_steps: state.recovery_generic_analysis_steps,
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
    assert!(state.generic_descriptor_closed);
    assert!(state.concrete_call_target_selected);
    assert!(state.concrete_effect_and_schema_selected);
    assert!(state.executable_projection_validated);
    assert_eq!(state.recovery_generic_analysis_steps, 0);
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

fn assert_recovered_graph_invariants(state: RecoveredGraphState) {
    assert!((1..=2).contains(&state.owner_epoch));
    for logical_commits in [
        state.child_creation_commits,
        state.child_ownership_commits,
        state.child_settlement_commits,
        state.child_result_commits,
        state.root_settlement_commits,
        state.foreground_commits,
        state.terminal_commits,
    ] {
        assert!(logical_commits <= 1);
    }
    assert!(state.root_physical_submissions <= 2);
    assert!(state.child_physical_submissions <= 2);
    if state.child_ownership_commits == 1 {
        assert_eq!(state.child_creation_commits, 1);
    }
    if state.owner_epoch == 2 {
        assert_eq!(state.child_ownership_commits, 1);
    }
    if state.admitted {
        assert!(state.root_reconstructed && state.child_reconstructed);
    }
    if state.root_physical_submissions > 0 || state.child_physical_submissions > 0 {
        assert_eq!(state.owner_epoch, 2);
        assert!(state.admitted && state.root_reconstructed && state.child_reconstructed);
    }
    if state.root_registered {
        assert!(state.admitted && state.root_physical_submissions > 0);
    }
    if state.child_registered {
        assert!(state.admitted && state.child_physical_submissions > 0);
    }
    if state.gates_open {
        assert!(state.root_registered && state.child_registered);
    }
    if state.child_settlement_commits == 1 {
        assert!(current_owner_can_publish(state));
    }
    if state.child_result_commits == 1 {
        assert_eq!(state.child_settlement_commits, 1);
    }
    if state.root_settlement_commits == 1 {
        assert_eq!(state.child_result_commits, 1);
    }
    if state.foreground_commits == 1 {
        assert_eq!(state.root_settlement_commits, 1);
    }
    if state.terminal_commits == 1 {
        assert_eq!(state.foreground_commits, 1);
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
