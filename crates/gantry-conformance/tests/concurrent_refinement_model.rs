//! Bounded model and written-argument checks for concurrent evaluator refinement.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
#[serde(deny_unknown_fields)]
struct AsyncCoordinatorManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    evidence_scope: String,
    full_clause_proof: bool,
    argument: String,
    model: String,
    model_evidence: String,
    requirements: Vec<AssignedRequirement>,
    invariant_mappings: Vec<InvariantMapping>,
    validation_commands: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AssignedRequirement {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvariantMapping {
    invariant: InvariantId,
    model_search: SearchId,
    implementation_tests: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AsyncContract {
    requirement_assignments: Vec<ContractAssignment>,
}

#[derive(Debug, Deserialize)]
struct ContractAssignment {
    requirement: String,
    clause: String,
    profiles: Vec<String>,
    evidence_owners: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcurrentModel {
    format: String,
    maximum_depth: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    obligations: Vec<String>,
    assumptions: Vec<String>,
    counterexamples: Vec<Counterexample>,
    coordinator_searches: Vec<SearchExpectation>,
    coordinator_counterexamples: Vec<CoordinatorCounterexample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Counterexample {
    id: String,
    trace: Vec<String>,
    rejected_action: String,
    invariant: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchExpectation {
    id: SearchId,
    state_domains: Vec<StateDomain>,
    action_domain: Vec<ModelAction>,
    initial: StateDescription,
    terminal: StateDescription,
    closure: SearchClosure,
    safety_ceiling: usize,
    explored_state_count: usize,
    terminal_state_count: usize,
    maximum_shortest_depth: usize,
    frontier_state_count: usize,
    fixed_point: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorCounterexample {
    id: String,
    search: SearchId,
    trace: Vec<ModelAction>,
    mutation: NegativeMutation,
    rejected_action: ModelAction,
    rejection_reason: RejectionReason,
    invariant: InvariantId,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateDomain {
    field: String,
    values: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateDescription {
    description: String,
    assignments: Vec<StateAssignment>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateAssignment {
    field: String,
    value: String,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum SearchId {
    IntegratedCoordinatorLifecycle,
    AuxiliaryResourceIdentity,
    CoordinatorGuardExternalCall,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum SearchClosure {
    QueueExhaustion,
}

impl SearchId {
    const fn as_str(self) -> &'static str {
        match self {
            Self::IntegratedCoordinatorLifecycle => "integrated-coordinator-lifecycle",
            Self::AuxiliaryResourceIdentity => "auxiliary-resource-identity",
            Self::CoordinatorGuardExternalCall => "coordinator-guard-external-call",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum InvariantId {
    AbortAfterCancellation,
    AttachedDrainBeforeRootSettlement,
    ChildEventAfterSemanticSettlement,
    ChildEventAtMostOnce,
    ChildEventBeforeTerminal,
    CoordinatorExternalCallAfterGuardRelease,
    CreationPublicationBeforeSubmission,
    ForegroundBeforeTerminal,
    GateReleaseAfterRegistration,
    HandleOwnershipLinearization,
    NoLostWakeup,
    OneUnitAdmissionBound,
    OperationIdentityUniqueness,
    PermitReleaseAfterPhysicalSettlement,
    RootSettlementBeforeForeground,
    SemanticSettlementAfterGateRelease,
    SharedOperationBudgetBound,
    SharedTransitionBudgetBound,
    SubmissionBeforeRegistration,
    SuccessorPublicationBeforeNotification,
    TaskIdentityUniqueness,
    WaiterNotificationAfterGuardRelease,
}

impl InvariantId {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AbortAfterCancellation => "abort-after-cancellation",
            Self::AttachedDrainBeforeRootSettlement => "attached-drain-before-root-settlement",
            Self::ChildEventAfterSemanticSettlement => "child-event-after-semantic-settlement",
            Self::ChildEventAtMostOnce => "child-event-at-most-once",
            Self::ChildEventBeforeTerminal => "child-event-before-terminal",
            Self::CoordinatorExternalCallAfterGuardRelease => {
                "coordinator-external-call-after-guard-release"
            }
            Self::CreationPublicationBeforeSubmission => "creation-publication-before-submission",
            Self::ForegroundBeforeTerminal => "foreground-before-terminal",
            Self::GateReleaseAfterRegistration => "gate-release-after-registration",
            Self::HandleOwnershipLinearization => "handle-ownership-linearization",
            Self::NoLostWakeup => "no-lost-wakeup",
            Self::OneUnitAdmissionBound => "one-unit-admission-bound",
            Self::OperationIdentityUniqueness => "operation-identity-uniqueness",
            Self::PermitReleaseAfterPhysicalSettlement => {
                "permit-release-after-physical-settlement"
            }
            Self::RootSettlementBeforeForeground => "root-settlement-before-foreground",
            Self::SemanticSettlementAfterGateRelease => "semantic-settlement-after-gate-release",
            Self::SharedOperationBudgetBound => "shared-operation-budget-bound",
            Self::SharedTransitionBudgetBound => "shared-transition-budget-bound",
            Self::SubmissionBeforeRegistration => "submission-before-registration",
            Self::SuccessorPublicationBeforeNotification => {
                "successor-publication-before-notification"
            }
            Self::TaskIdentityUniqueness => "task-identity-uniqueness",
            Self::WaiterNotificationAfterGuardRelease => "waiter-notification-after-guard-release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum RejectionReason {
    AbortAlreadyRequested,
    ActionOutsideSearch,
    AdmissionExhausted,
    AlreadyCreated,
    AlreadyNotified,
    AlreadyPublished,
    AttachedChildPending,
    CancellationNotRequested,
    ChildEventAlreadyPublished,
    ChildEventPending,
    ChildNotCreated,
    CancellationAlreadyRequested,
    CoordinatorGuardAlreadyAcquired,
    CoordinatorGuardHeld,
    CoordinatorGuardNotHeld,
    CreationUnpublished,
    DriverAlreadyRegistered,
    DriverAlreadySubmitted,
    DriverNotRegistered,
    DriverNotSubmitted,
    ExternalCallAlreadyStarted,
    ExternalCallNotStarted,
    ForegroundAlreadyComplete,
    ForegroundPending,
    GateAlreadyOpen,
    GateClosed,
    HandleAlreadyConsumed,
    HandleNotRegistered,
    OperationBudgetExhausted,
    OperationIdentityDuplicate,
    OperationIdentityMissing,
    OperationSlotAlreadyAssigned,
    PermitAlreadyReleased,
    PermitReleasePending,
    PhysicalAlreadySettled,
    PhysicalSettlementPending,
    RootAlreadySettled,
    RootPending,
    SemanticAlreadySettled,
    SemanticSettlementPending,
    SuccessorAlreadyPublished,
    SuccessorUnpublished,
    TaskIdentityDuplicate,
    TaskIdentityMissing,
    TaskSlotAlreadyAssigned,
    TerminalAlreadyComplete,
    TransitionBudgetExhausted,
    WaiterAlreadyRegistered,
    WaiterMissing,
    WaiterNotReady,
    WaitersNotTaken,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum NegativeMutation {
    AbortWithoutCancellation,
    ChildEventBeforeSemanticSettlement,
    DuplicateChildEvent,
    DuplicateOperationIdentity,
    DuplicateTaskIdentity,
    ExternalCallUnderCoordinatorGuard,
    ForegroundBeforeRootSettlement,
    GateBeforeRegistration,
    JoinedAndDetached,
    LostRegisteredWake,
    OneUnitAdmissionOversubscribed,
    OperationBudgetOversubscribed,
    PermitReleasedBeforePhysicalSettlement,
    RegistrationBeforeSubmission,
    RootBeforeAttachedDrain,
    SemanticSettlementBeforeGate,
    SubmissionBeforeCreationPublication,
    TerminalBeforeChildEvent,
    TerminalBeforeForeground,
    TransitionBudgetOversubscribed,
    WaiterNotifiedBeforePublication,
    WaiterNotifiedUnderCoordinatorGuard,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ModelAction {
    AcquireCoordinatorGuard,
    AcquirePermitA,
    AcquirePermitB,
    AssignOperationAOne,
    AssignOperationATwo,
    AssignOperationBOne,
    AssignOperationBTwo,
    AssignTaskAOne,
    AssignTaskATwo,
    AssignTaskBOne,
    AssignTaskBTwo,
    BeginExternalCall,
    CompleteExternalCall,
    CompleteForeground,
    CompleteTerminal,
    ConsumeOperationA,
    ConsumeOperationB,
    ConsumeTransitionA,
    ConsumeTransitionB,
    CreateChild,
    DetachHandle,
    JoinHandle,
    NotifyWaiter,
    PublishChildEvent,
    PublishCreation,
    PublishSuccessor,
    RegisterCoordinatorWaiter,
    RegisterDriver,
    RegisterWaiter,
    ReleaseCoordinatorGuard,
    ReleaseGate,
    ReleasePermit,
    RequestAbort,
    RequestCancellation,
    SettleChildPhysical,
    SettleChildSemantic,
    SettleRoot,
    SubmitDriver,
    TakePublishedWaiters,
    WakePublishedWaiters,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum WaiterState {
    Absent,
    Registered,
    Queued,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LifecycleState {
    created: bool,
    creation_published: bool,
    submitted: bool,
    registered: bool,
    gate_open: bool,
    joined: bool,
    detached: bool,
    cancelled: bool,
    abort_requested: bool,
    semantic_settled: bool,
    physical_settled: bool,
    permit_released: bool,
    waiter: WaiterState,
    child_events: u8,
    root_settled: bool,
    foreground: bool,
    terminal: bool,
}

impl LifecycleState {
    const fn initial() -> Self {
        Self {
            created: false,
            creation_published: false,
            submitted: false,
            registered: false,
            gate_open: false,
            joined: false,
            detached: false,
            cancelled: false,
            abort_requested: false,
            semantic_settled: false,
            physical_settled: false,
            permit_released: false,
            waiter: WaiterState::Absent,
            child_events: 0,
            root_settled: false,
            foreground: false,
            terminal: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum FiniteIdentity {
    One,
    Two,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceState {
    task_a: Option<FiniteIdentity>,
    task_b: Option<FiniteIdentity>,
    operation_a: Option<FiniteIdentity>,
    operation_b: Option<FiniteIdentity>,
    permit_a: bool,
    permit_b: bool,
    transition_a: bool,
    transition_b: bool,
    operation_budget_a: bool,
    operation_budget_b: bool,
}

impl ResourceState {
    const fn initial() -> Self {
        Self {
            task_a: None,
            task_b: None,
            operation_a: None,
            operation_b: None,
            permit_a: false,
            permit_b: false,
            transition_a: false,
            transition_b: false,
            operation_budget_a: false,
            operation_budget_b: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BoundaryWaiterState {
    Absent,
    Registered,
    Taken,
    Notified,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ExternalCallState {
    NotStarted,
    InFlight,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BoundaryState {
    guard_held: bool,
    guard_acquisitions: u8,
    successor_published: bool,
    waiter: BoundaryWaiterState,
    external_call: ExternalCallState,
}

impl BoundaryState {
    const fn initial() -> Self {
        Self {
            guard_held: false,
            guard_acquisitions: 0,
            successor_published: false,
            waiter: BoundaryWaiterState::Absent,
            external_call: ExternalCallState::NotStarted,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SearchReport {
    explored_state_count: usize,
    terminal_state_count: usize,
    maximum_shortest_depth: usize,
    frontier_state_count: usize,
    fixed_point: bool,
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

    let actual = model
        .coordinator_searches
        .iter()
        .map(|search| {
            let report = match search.id {
                SearchId::IntegratedCoordinatorLifecycle => explore_lifecycle(search),
                SearchId::AuxiliaryResourceIdentity => explore_resources(search),
                SearchId::CoordinatorGuardExternalCall => explore_boundary(search),
            };
            eprintln!(
                "{}: states={}, terminal={}, max-shortest-depth={}",
                search.id.as_str(),
                report.explored_state_count,
                report.terminal_state_count,
                report.maximum_shortest_depth
            );
            (search, report)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual
            .iter()
            .map(|(search, _)| search.id)
            .collect::<Vec<_>>(),
        [
            SearchId::IntegratedCoordinatorLifecycle,
            SearchId::AuxiliaryResourceIdentity,
            SearchId::CoordinatorGuardExternalCall,
        ]
    );
    for (search, report) in actual {
        assert_eq!(
            report.explored_state_count,
            search.explored_state_count,
            "{}",
            search.id.as_str()
        );
        assert_eq!(
            report.terminal_state_count,
            search.terminal_state_count,
            "{}",
            search.id.as_str()
        );
        assert_eq!(
            report.maximum_shortest_depth,
            search.maximum_shortest_depth,
            "{}",
            search.id.as_str()
        );
        assert_eq!(
            report.frontier_state_count,
            search.frontier_state_count,
            "{}",
            search.id.as_str()
        );
        assert_eq!(
            report.fixed_point,
            search.fixed_point,
            "{}",
            search.id.as_str()
        );
        assert_eq!(report.frontier_state_count, 0, "{}", search.id.as_str());
        assert!(report.fixed_point, "{}", search.id.as_str());
    }

    let ids = model
        .coordinator_counterexamples
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    for case in &model.coordinator_counterexamples {
        replay_coordinator_counterexample(case);
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

#[test]
fn async_coordinator_model_manifest_freezes_assignments_and_invariant_evidence() {
    const MANIFEST_PATH: &str = "protocol/conformance/async-coordinator-model-v1.json";
    const CONTRACT_PATH: &str = "protocol/conformance/async-execution-contract-v1.json";
    const EXPECTED_INVARIANTS: [&str; 14] = [
        "attached-drain-before-root-settlement",
        "creation-publication-before-submission",
        "foreground-before-terminal",
        "gate-release-after-registration",
        "handle-ownership-linearization",
        "no-lost-wakeup",
        "one-unit-admission-bound",
        "operation-identity-uniqueness",
        "permit-release-after-physical-settlement",
        "shared-operation-budget-bound",
        "shared-transition-budget-bound",
        "successor-publication-before-notification",
        "task-identity-uniqueness",
        "waiter-notification-after-guard-release",
    ];
    const EXPECTED_COMMANDS: [&str; 6] = [
        "timeout 180s rustup run 1.97.1 cargo fmt --all -- --check",
        "timeout 180s rustup run 1.97.1 cargo run --locked -p xtask -- check generated",
        "timeout 180s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test concurrent_refinement_model",
        "timeout 180s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test execution_coordinator",
        "timeout 180s rustup run 1.97.1 cargo test --locked -p gantry-conformance --test source_spawn_tokio seeded_native_source_stress",
        "timeout 180s rustup run 1.97.1 cargo test --locked -p gantry-runtime --features concurrent simultaneous_final_operation_unit_has_one_preparation_and_one_unchanged_loser",
    ];

    let root = workspace_root();
    let manifest: AsyncCoordinatorManifest = read_json(&root.join(MANIFEST_PATH));
    let contract: AsyncContract = read_json(&root.join(CONTRACT_PATH));
    let expected_requirements = contract
        .requirement_assignments
        .into_iter()
        .filter(|assignment| {
            assignment
                .evidence_owners
                .iter()
                .any(|owner| owner == "GNT-ASYNC-MODEL-001")
        })
        .map(|assignment| AssignedRequirement {
            requirement: assignment.requirement,
            clause: assignment.clause,
            profiles: assignment.profiles,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        manifest.format,
        "gantry.async-coordinator-model-evidence/v1"
    );
    assert_eq!(manifest.issue, "GNT-ASYNC-MODEL-001");
    assert_eq!(manifest.evidence_scope, "partial-property-evidence");
    assert!(!manifest.full_clause_proof);
    assert_eq!(
        manifest.specification_sha256,
        gantry::portable::PORTABLE_SPECIFICATION_REVISION
    );
    assert_eq!(manifest.requirements, expected_requirements);
    assert_eq!(manifest.model_evidence, MODEL_EVIDENCE);
    assert_eq!(
        manifest.model,
        "protocol/goldens/concurrent-refinement-model-v1.json"
    );
    assert_eq!(
        manifest
            .invariant_mappings
            .iter()
            .map(|mapping| mapping.invariant.as_str())
            .collect::<Vec<_>>(),
        EXPECTED_INVARIANTS
    );
    assert_eq!(
        manifest
            .validation_commands
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        EXPECTED_COMMANDS
    );
    assert_eq!(manifest.exclusions.len(), 4);
    assert!(
        manifest
            .exclusions
            .iter()
            .any(|exclusion| exclusion.contains("not an unbounded proof"))
    );
    assert!(
        manifest
            .exclusions
            .iter()
            .any(|exclusion| exclusion.contains("does not require deterministic sibling"))
    );

    let model: ConcurrentModel = read_json(&root.join(&manifest.model));
    let searches = model
        .coordinator_searches
        .iter()
        .map(|search| search.id.as_str())
        .collect::<BTreeSet<_>>();
    for mapping in &manifest.invariant_mappings {
        assert!(searches.contains(mapping.model_search.as_str()));
        assert_sorted_unique(&mapping.implementation_tests);
        assert!(!mapping.implementation_tests.is_empty());
        for evidence in &mapping.implementation_tests {
            validate_implementation_anchor(&root, evidence);
        }
    }
    validate_evidence_anchor(&root, &manifest.model_evidence);

    let argument = fs::read_to_string(root.join(&manifest.argument))
        .unwrap_or_else(|error| panic!("could not read async coordinator argument: {error}"));
    for heading in [
        "## Scope and bounded claim",
        "## State-space decomposition and counts",
        "## Invariant-to-implementation mapping",
        "## Normative assignment authentication",
        "## Validation and gate integration",
    ] {
        assert!(argument.contains(heading));
    }
    for invariant in EXPECTED_INVARIANTS {
        assert!(argument.contains(invariant), "{invariant}");
    }
    assert!(argument.contains("not an unbounded proof"));
    assert!(argument.contains("partial property evidence"));
    assert!(argument.contains("not a full-clause proof"));
    assert!(argument.contains("not a global lock-order proof"));
    let normalized_argument = argument.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_argument.contains("does not require deterministic sibling order"));
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

const LIFECYCLE_ACTIONS: [ModelAction; 18] = [
    ModelAction::CreateChild,
    ModelAction::PublishCreation,
    ModelAction::SubmitDriver,
    ModelAction::RegisterDriver,
    ModelAction::ReleaseGate,
    ModelAction::JoinHandle,
    ModelAction::DetachHandle,
    ModelAction::RequestCancellation,
    ModelAction::RequestAbort,
    ModelAction::RegisterWaiter,
    ModelAction::SettleChildSemantic,
    ModelAction::NotifyWaiter,
    ModelAction::SettleChildPhysical,
    ModelAction::ReleasePermit,
    ModelAction::PublishChildEvent,
    ModelAction::SettleRoot,
    ModelAction::CompleteForeground,
    ModelAction::CompleteTerminal,
];

const RESOURCE_ACTIONS: [ModelAction; 14] = [
    ModelAction::AssignTaskAOne,
    ModelAction::AssignTaskATwo,
    ModelAction::AssignTaskBOne,
    ModelAction::AssignTaskBTwo,
    ModelAction::AssignOperationAOne,
    ModelAction::AssignOperationATwo,
    ModelAction::AssignOperationBOne,
    ModelAction::AssignOperationBTwo,
    ModelAction::AcquirePermitA,
    ModelAction::AcquirePermitB,
    ModelAction::ConsumeTransitionA,
    ModelAction::ConsumeTransitionB,
    ModelAction::ConsumeOperationA,
    ModelAction::ConsumeOperationB,
];

const BOUNDARY_ACTIONS: [ModelAction; 8] = [
    ModelAction::AcquireCoordinatorGuard,
    ModelAction::RegisterCoordinatorWaiter,
    ModelAction::ReleaseCoordinatorGuard,
    ModelAction::BeginExternalCall,
    ModelAction::CompleteExternalCall,
    ModelAction::PublishSuccessor,
    ModelAction::TakePublishedWaiters,
    ModelAction::WakePublishedWaiters,
];

fn explore_lifecycle(search: &SearchExpectation) -> SearchReport {
    assert_eq!(search.action_domain, LIFECYCLE_ACTIONS, "{:?}", search.id);
    assert_search_metadata(
        search,
        &[
            ("created", &["false", "true"]),
            ("creation-published", &["false", "true"]),
            ("submitted", &["false", "true"]),
            ("registered", &["false", "true"]),
            ("gate-open", &["false", "true"]),
            ("joined", &["false", "true"]),
            ("detached", &["false", "true"]),
            ("cancelled", &["false", "true"]),
            ("abort-requested", &["false", "true"]),
            ("semantic-settled", &["false", "true"]),
            ("physical-settled", &["false", "true"]),
            ("permit-released", &["false", "true"]),
            ("waiter", &["absent", "registered", "queued", "ready"]),
            ("child-events", &["0", "1"]),
            ("root-settled", &["false", "true"]),
            ("foreground", &["false", "true"]),
            ("terminal", &["false", "true"]),
        ],
        &[
            ("created", "false"),
            ("creation-published", "false"),
            ("submitted", "false"),
            ("registered", "false"),
            ("gate-open", "false"),
            ("joined", "false"),
            ("detached", "false"),
            ("cancelled", "false"),
            ("abort-requested", "false"),
            ("semantic-settled", "false"),
            ("physical-settled", "false"),
            ("permit-released", "false"),
            ("waiter", "absent"),
            ("child-events", "0"),
            ("root-settled", "false"),
            ("foreground", "false"),
            ("terminal", "false"),
        ],
        &[
            ("created", "true"),
            ("creation-published", "true"),
            ("submitted", "true"),
            ("registered", "true"),
            ("gate-open", "true"),
            ("semantic-settled", "true"),
            ("physical-settled", "true"),
            ("permit-released", "true"),
            ("waiter", "ready"),
            ("child-events", "1"),
            ("root-settled", "true"),
            ("foreground", "true"),
            ("terminal", "true"),
        ],
    );
    exhaustive_search(
        LifecycleState::initial(),
        &LIFECYCLE_ACTIONS,
        search.safety_ceiling,
        apply_lifecycle,
        assert_lifecycle_invariants,
        |state| state.terminal,
    )
}

fn apply_lifecycle(
    mut state: LifecycleState,
    action: ModelAction,
) -> Result<LifecycleState, RejectionReason> {
    if state.terminal {
        return Err(RejectionReason::TerminalAlreadyComplete);
    }
    match action {
        ModelAction::CreateChild => {
            if state.created {
                return Err(RejectionReason::AlreadyCreated);
            }
            state.created = true;
        }
        ModelAction::PublishCreation => {
            if !state.created {
                return Err(RejectionReason::ChildNotCreated);
            }
            if state.creation_published {
                return Err(RejectionReason::AlreadyPublished);
            }
            state.creation_published = true;
        }
        ModelAction::SubmitDriver => {
            if !state.creation_published {
                return Err(RejectionReason::CreationUnpublished);
            }
            if state.submitted {
                return Err(RejectionReason::DriverAlreadySubmitted);
            }
            state.submitted = true;
        }
        ModelAction::RegisterDriver => {
            if !state.submitted {
                return Err(RejectionReason::DriverNotSubmitted);
            }
            if state.registered {
                return Err(RejectionReason::DriverAlreadyRegistered);
            }
            state.registered = true;
        }
        ModelAction::ReleaseGate => {
            if !state.registered {
                return Err(RejectionReason::DriverNotRegistered);
            }
            if state.gate_open {
                return Err(RejectionReason::GateAlreadyOpen);
            }
            state.gate_open = true;
        }
        ModelAction::JoinHandle | ModelAction::DetachHandle => {
            if !state.registered {
                return Err(RejectionReason::HandleNotRegistered);
            }
            if state.joined || state.detached {
                return Err(RejectionReason::HandleAlreadyConsumed);
            }
            state.joined = action == ModelAction::JoinHandle;
            state.detached = action == ModelAction::DetachHandle;
        }
        ModelAction::RequestCancellation => {
            if !state.gate_open {
                return Err(RejectionReason::GateClosed);
            }
            if state.cancelled {
                return Err(RejectionReason::CancellationAlreadyRequested);
            }
            if state.semantic_settled {
                return Err(RejectionReason::SemanticAlreadySettled);
            }
            state.cancelled = true;
        }
        ModelAction::RequestAbort => {
            if !state.cancelled {
                return Err(RejectionReason::CancellationNotRequested);
            }
            if state.abort_requested {
                return Err(RejectionReason::AbortAlreadyRequested);
            }
            state.abort_requested = true;
        }
        ModelAction::RegisterWaiter => {
            if !state.registered {
                return Err(RejectionReason::DriverNotRegistered);
            }
            if state.waiter != WaiterState::Absent {
                return Err(RejectionReason::WaiterAlreadyRegistered);
            }
            state.waiter = if state.semantic_settled {
                WaiterState::Queued
            } else {
                WaiterState::Registered
            };
        }
        ModelAction::SettleChildSemantic => {
            if !state.gate_open {
                return Err(RejectionReason::GateClosed);
            }
            if state.semantic_settled {
                return Err(RejectionReason::SemanticAlreadySettled);
            }
            state.semantic_settled = true;
            if state.waiter == WaiterState::Registered {
                state.waiter = WaiterState::Queued;
            }
        }
        ModelAction::NotifyWaiter => match state.waiter {
            WaiterState::Queued => state.waiter = WaiterState::Ready,
            WaiterState::Ready => return Err(RejectionReason::AlreadyNotified),
            WaiterState::Absent | WaiterState::Registered => {
                return Err(RejectionReason::WaiterNotReady);
            }
        },
        ModelAction::SettleChildPhysical => {
            if !state.gate_open {
                return Err(RejectionReason::GateClosed);
            }
            if state.physical_settled {
                return Err(RejectionReason::PhysicalAlreadySettled);
            }
            state.physical_settled = true;
        }
        ModelAction::ReleasePermit => {
            if !state.physical_settled {
                return Err(RejectionReason::PhysicalSettlementPending);
            }
            if state.permit_released {
                return Err(RejectionReason::PermitAlreadyReleased);
            }
            state.permit_released = true;
        }
        ModelAction::PublishChildEvent => {
            if !state.semantic_settled {
                return Err(RejectionReason::SemanticSettlementPending);
            }
            if state.child_events != 0 {
                return Err(RejectionReason::ChildEventAlreadyPublished);
            }
            state.child_events = 1;
        }
        ModelAction::SettleRoot => {
            if state.root_settled {
                return Err(RejectionReason::RootAlreadySettled);
            }
            if !state.detached && !(state.joined && state.semantic_settled) {
                return Err(RejectionReason::AttachedChildPending);
            }
            state.root_settled = true;
        }
        ModelAction::CompleteForeground => {
            if !state.root_settled {
                return Err(RejectionReason::RootPending);
            }
            if state.foreground {
                return Err(RejectionReason::ForegroundAlreadyComplete);
            }
            state.foreground = true;
        }
        ModelAction::CompleteTerminal => {
            if !state.foreground {
                return Err(RejectionReason::ForegroundPending);
            }
            if !state.semantic_settled {
                return Err(RejectionReason::SemanticSettlementPending);
            }
            if !state.physical_settled {
                return Err(RejectionReason::PhysicalSettlementPending);
            }
            if !state.permit_released {
                return Err(RejectionReason::PermitReleasePending);
            }
            if state.waiter != WaiterState::Ready {
                return Err(RejectionReason::WaiterNotReady);
            }
            if state.child_events == 0 {
                return Err(RejectionReason::ChildEventPending);
            }
            state.terminal = true;
        }
        _ => return Err(RejectionReason::ActionOutsideSearch),
    }
    Ok(state)
}

fn lifecycle_violations(state: LifecycleState) -> BTreeSet<InvariantId> {
    let mut violations = BTreeSet::new();
    if state.submitted && !state.creation_published {
        violations.insert(InvariantId::CreationPublicationBeforeSubmission);
    }
    if state.registered && !state.submitted {
        violations.insert(InvariantId::SubmissionBeforeRegistration);
    }
    if state.gate_open && !state.registered {
        violations.insert(InvariantId::GateReleaseAfterRegistration);
    }
    if state.joined && state.detached {
        violations.insert(InvariantId::HandleOwnershipLinearization);
    }
    if state.abort_requested && !state.cancelled {
        violations.insert(InvariantId::AbortAfterCancellation);
    }
    if state.semantic_settled && !state.gate_open {
        violations.insert(InvariantId::SemanticSettlementAfterGateRelease);
    }
    if state.permit_released && !state.physical_settled {
        violations.insert(InvariantId::PermitReleaseAfterPhysicalSettlement);
    }
    if state.semantic_settled && state.waiter == WaiterState::Registered {
        violations.insert(InvariantId::NoLostWakeup);
    }
    if state.child_events > 0 && !state.semantic_settled {
        violations.insert(InvariantId::ChildEventAfterSemanticSettlement);
    }
    if state.child_events > 1 {
        violations.insert(InvariantId::ChildEventAtMostOnce);
    }
    if state.root_settled && state.joined && !state.semantic_settled {
        violations.insert(InvariantId::AttachedDrainBeforeRootSettlement);
    }
    if state.foreground && !state.root_settled {
        violations.insert(InvariantId::RootSettlementBeforeForeground);
    }
    if state.terminal && !state.foreground {
        violations.insert(InvariantId::ForegroundBeforeTerminal);
    }
    if state.terminal && state.child_events == 0 {
        violations.insert(InvariantId::ChildEventBeforeTerminal);
    }
    violations
}

fn assert_lifecycle_invariants(state: LifecycleState) {
    assert!(lifecycle_violations(state).is_empty(), "{state:?}");
}

fn explore_resources(search: &SearchExpectation) -> SearchReport {
    assert_eq!(search.action_domain, RESOURCE_ACTIONS, "{:?}", search.id);
    assert_search_metadata(
        search,
        &[
            ("task-a", &["none", "one", "two"]),
            ("task-b", &["none", "one", "two"]),
            ("operation-a", &["none", "one", "two"]),
            ("operation-b", &["none", "one", "two"]),
            ("permit-a", &["false", "true"]),
            ("permit-b", &["false", "true"]),
            ("transition-a", &["false", "true"]),
            ("transition-b", &["false", "true"]),
            ("operation-budget-a", &["false", "true"]),
            ("operation-budget-b", &["false", "true"]),
        ],
        &[
            ("task-a", "none"),
            ("task-b", "none"),
            ("operation-a", "none"),
            ("operation-b", "none"),
            ("permit-a", "false"),
            ("permit-b", "false"),
            ("transition-a", "false"),
            ("transition-b", "false"),
            ("operation-budget-a", "false"),
            ("operation-budget-b", "false"),
        ],
        &[
            ("task-a", "one"),
            ("task-b", "two"),
            ("operation-a", "one"),
            ("operation-b", "two"),
            ("permit-a", "true"),
            ("permit-b", "false"),
            ("transition-a", "true"),
            ("transition-b", "false"),
            ("operation-budget-a", "true"),
            ("operation-budget-b", "false"),
        ],
    );
    exhaustive_search(
        ResourceState::initial(),
        &RESOURCE_ACTIONS,
        search.safety_ceiling,
        apply_resource,
        assert_resource_invariants,
        |state| {
            state.task_a == Some(FiniteIdentity::One)
                && state.task_b == Some(FiniteIdentity::Two)
                && state.operation_a == Some(FiniteIdentity::One)
                && state.operation_b == Some(FiniteIdentity::Two)
                && state.permit_a
                && !state.permit_b
                && state.transition_a
                && !state.transition_b
                && state.operation_budget_a
                && !state.operation_budget_b
        },
    )
}

fn apply_resource(
    mut state: ResourceState,
    action: ModelAction,
) -> Result<ResourceState, RejectionReason> {
    match action {
        ModelAction::AssignTaskAOne => {
            assign_task(&mut state.task_a, state.task_b, FiniteIdentity::One)?
        }
        ModelAction::AssignTaskATwo => {
            assign_task(&mut state.task_a, state.task_b, FiniteIdentity::Two)?
        }
        ModelAction::AssignTaskBOne => {
            assign_task(&mut state.task_b, state.task_a, FiniteIdentity::One)?
        }
        ModelAction::AssignTaskBTwo => {
            assign_task(&mut state.task_b, state.task_a, FiniteIdentity::Two)?
        }
        ModelAction::AssignOperationAOne => {
            assign_operation(
                &mut state.operation_a,
                state.operation_b,
                state.task_a,
                FiniteIdentity::One,
            )?;
        }
        ModelAction::AssignOperationATwo => {
            assign_operation(
                &mut state.operation_a,
                state.operation_b,
                state.task_a,
                FiniteIdentity::Two,
            )?;
        }
        ModelAction::AssignOperationBOne => {
            assign_operation(
                &mut state.operation_b,
                state.operation_a,
                state.task_b,
                FiniteIdentity::One,
            )?;
        }
        ModelAction::AssignOperationBTwo => {
            assign_operation(
                &mut state.operation_b,
                state.operation_a,
                state.task_b,
                FiniteIdentity::Two,
            )?;
        }
        ModelAction::AcquirePermitA => consume_budget(
            &mut state.permit_a,
            state.permit_b,
            RejectionReason::AdmissionExhausted,
        )?,
        ModelAction::AcquirePermitB => consume_budget(
            &mut state.permit_b,
            state.permit_a,
            RejectionReason::AdmissionExhausted,
        )?,
        ModelAction::ConsumeTransitionA => consume_budget(
            &mut state.transition_a,
            state.transition_b,
            RejectionReason::TransitionBudgetExhausted,
        )?,
        ModelAction::ConsumeTransitionB => consume_budget(
            &mut state.transition_b,
            state.transition_a,
            RejectionReason::TransitionBudgetExhausted,
        )?,
        ModelAction::ConsumeOperationA => consume_budget(
            &mut state.operation_budget_a,
            state.operation_budget_b,
            RejectionReason::OperationBudgetExhausted,
        )?,
        ModelAction::ConsumeOperationB => consume_budget(
            &mut state.operation_budget_b,
            state.operation_budget_a,
            RejectionReason::OperationBudgetExhausted,
        )?,
        _ => return Err(RejectionReason::ActionOutsideSearch),
    }
    Ok(state)
}

fn assign_task(
    slot: &mut Option<FiniteIdentity>,
    other: Option<FiniteIdentity>,
    identity: FiniteIdentity,
) -> Result<(), RejectionReason> {
    if slot.is_some() {
        return Err(RejectionReason::TaskSlotAlreadyAssigned);
    }
    if other == Some(identity) {
        return Err(RejectionReason::TaskIdentityDuplicate);
    }
    *slot = Some(identity);
    Ok(())
}

fn assign_operation(
    slot: &mut Option<FiniteIdentity>,
    other: Option<FiniteIdentity>,
    task: Option<FiniteIdentity>,
    identity: FiniteIdentity,
) -> Result<(), RejectionReason> {
    if task.is_none() {
        return Err(RejectionReason::TaskIdentityMissing);
    }
    if slot.is_some() {
        return Err(RejectionReason::OperationSlotAlreadyAssigned);
    }
    if other == Some(identity) {
        return Err(RejectionReason::OperationIdentityDuplicate);
    }
    *slot = Some(identity);
    Ok(())
}

fn consume_budget(
    slot: &mut bool,
    other: bool,
    exhausted: RejectionReason,
) -> Result<(), RejectionReason> {
    if *slot || other {
        return Err(exhausted);
    }
    *slot = true;
    Ok(())
}

fn resource_violations(state: ResourceState) -> BTreeSet<InvariantId> {
    let mut violations = BTreeSet::new();
    if state.task_a.is_some() && state.task_a == state.task_b {
        violations.insert(InvariantId::TaskIdentityUniqueness);
    }
    if state.operation_a.is_some() && state.operation_a == state.operation_b {
        violations.insert(InvariantId::OperationIdentityUniqueness);
    }
    if state.permit_a && state.permit_b {
        violations.insert(InvariantId::OneUnitAdmissionBound);
    }
    if state.transition_a && state.transition_b {
        violations.insert(InvariantId::SharedTransitionBudgetBound);
    }
    if state.operation_budget_a && state.operation_budget_b {
        violations.insert(InvariantId::SharedOperationBudgetBound);
    }
    violations
}

fn assert_resource_invariants(state: ResourceState) {
    assert!(resource_violations(state).is_empty(), "{state:?}");
}

fn explore_boundary(search: &SearchExpectation) -> SearchReport {
    assert_eq!(search.action_domain, BOUNDARY_ACTIONS, "{:?}", search.id);
    assert_search_metadata(
        search,
        &[
            ("guard-held", &["false", "true"]),
            ("guard-acquisitions", &["0", "1", "2"]),
            ("external-call", &["not-started", "in-flight", "complete"]),
            ("successor-published", &["false", "true"]),
            ("waiter", &["absent", "registered", "taken", "notified"]),
        ],
        &[
            ("guard-held", "false"),
            ("guard-acquisitions", "0"),
            ("external-call", "not-started"),
            ("successor-published", "false"),
            ("waiter", "absent"),
        ],
        &[
            ("guard-held", "false"),
            ("guard-acquisitions", "2"),
            ("external-call", "complete"),
            ("successor-published", "true"),
            ("waiter", "notified"),
        ],
    );
    exhaustive_search(
        BoundaryState::initial(),
        &BOUNDARY_ACTIONS,
        search.safety_ceiling,
        apply_boundary,
        assert_boundary_invariants,
        |state| {
            !state.guard_held
                && state.guard_acquisitions == 2
                && state.external_call == ExternalCallState::Complete
                && state.successor_published
                && state.waiter == BoundaryWaiterState::Notified
        },
    )
}

fn apply_boundary(
    mut state: BoundaryState,
    action: ModelAction,
) -> Result<BoundaryState, RejectionReason> {
    match action {
        ModelAction::AcquireCoordinatorGuard => {
            if state.guard_held {
                return Err(RejectionReason::CoordinatorGuardAlreadyAcquired);
            }
            match (state.guard_acquisitions, state.external_call) {
                (0, ExternalCallState::NotStarted) => state.guard_acquisitions = 1,
                (1, ExternalCallState::Complete) => state.guard_acquisitions = 2,
                _ => return Err(RejectionReason::ExternalCallNotStarted),
            }
            state.guard_held = true;
        }
        ModelAction::RegisterCoordinatorWaiter => {
            if !state.guard_held || state.guard_acquisitions != 1 {
                return Err(RejectionReason::CoordinatorGuardNotHeld);
            }
            if state.waiter != BoundaryWaiterState::Absent {
                return Err(RejectionReason::WaiterAlreadyRegistered);
            }
            state.waiter = BoundaryWaiterState::Registered;
        }
        ModelAction::ReleaseCoordinatorGuard => {
            if !state.guard_held {
                return Err(RejectionReason::CoordinatorGuardNotHeld);
            }
            if state.guard_acquisitions == 2
                && (!state.successor_published || state.waiter != BoundaryWaiterState::Taken)
            {
                return Err(RejectionReason::WaitersNotTaken);
            }
            state.guard_held = false;
        }
        ModelAction::BeginExternalCall => {
            if state.guard_held {
                return Err(RejectionReason::CoordinatorGuardHeld);
            }
            if state.guard_acquisitions != 1 {
                return Err(RejectionReason::CoordinatorGuardNotHeld);
            }
            if state.external_call != ExternalCallState::NotStarted {
                return Err(RejectionReason::ExternalCallAlreadyStarted);
            }
            state.external_call = ExternalCallState::InFlight;
        }
        ModelAction::CompleteExternalCall => {
            if state.external_call != ExternalCallState::InFlight {
                return Err(RejectionReason::ExternalCallNotStarted);
            }
            state.external_call = ExternalCallState::Complete;
        }
        ModelAction::PublishSuccessor => {
            if !state.guard_held || state.guard_acquisitions != 2 {
                return Err(RejectionReason::CoordinatorGuardNotHeld);
            }
            if state.successor_published {
                return Err(RejectionReason::SuccessorAlreadyPublished);
            }
            state.successor_published = true;
        }
        ModelAction::TakePublishedWaiters => {
            if !state.guard_held || state.guard_acquisitions != 2 {
                return Err(RejectionReason::CoordinatorGuardNotHeld);
            }
            if !state.successor_published {
                return Err(RejectionReason::SuccessorUnpublished);
            }
            if state.waiter != BoundaryWaiterState::Registered {
                return Err(RejectionReason::WaiterMissing);
            }
            state.waiter = BoundaryWaiterState::Taken;
        }
        ModelAction::WakePublishedWaiters => {
            if state.guard_held {
                return Err(RejectionReason::CoordinatorGuardHeld);
            }
            if !state.successor_published {
                return Err(RejectionReason::SuccessorUnpublished);
            }
            match state.waiter {
                BoundaryWaiterState::Taken => state.waiter = BoundaryWaiterState::Notified,
                BoundaryWaiterState::Notified => return Err(RejectionReason::AlreadyNotified),
                BoundaryWaiterState::Absent | BoundaryWaiterState::Registered => {
                    return Err(RejectionReason::WaitersNotTaken);
                }
            }
        }
        _ => return Err(RejectionReason::ActionOutsideSearch),
    }
    Ok(state)
}

fn boundary_violations(state: BoundaryState) -> BTreeSet<InvariantId> {
    let mut violations = BTreeSet::new();
    if state.guard_held && state.external_call == ExternalCallState::InFlight {
        violations.insert(InvariantId::CoordinatorExternalCallAfterGuardRelease);
    }
    if state.waiter == BoundaryWaiterState::Notified && !state.successor_published {
        violations.insert(InvariantId::SuccessorPublicationBeforeNotification);
    }
    if state.guard_held && state.waiter == BoundaryWaiterState::Notified {
        violations.insert(InvariantId::WaiterNotificationAfterGuardRelease);
    }
    violations
}

fn assert_boundary_invariants(state: BoundaryState) {
    assert!(boundary_violations(state).is_empty(), "{state:?}");
}

fn exhaustive_search<State: Copy + std::fmt::Debug + Ord>(
    initial: State,
    actions: &[ModelAction],
    safety_ceiling: usize,
    apply: fn(State, ModelAction) -> Result<State, RejectionReason>,
    assert_invariants: fn(State),
    terminal: impl Fn(State) -> bool,
) -> SearchReport {
    let mut shortest = BTreeMap::from([(initial, 0_usize)]);
    let mut pending = VecDeque::from([initial]);
    while let Some(state) = pending.pop_front() {
        assert_invariants(state);
        let depth = shortest[&state];
        for action in actions {
            let Ok(next) = apply(state, *action) else {
                continue;
            };
            assert_invariants(next);
            if let std::collections::btree_map::Entry::Vacant(entry) = shortest.entry(next) {
                entry.insert(depth.saturating_add(1));
                assert!(
                    shortest.len() <= safety_ceiling,
                    "state search exceeded safety ceiling {safety_ceiling}"
                );
                pending.push_back(next);
            }
        }
    }
    let fixed_point = shortest.keys().all(|state| {
        actions.iter().all(|action| {
            apply(*state, *action)
                .map(|next| shortest.contains_key(&next))
                .unwrap_or(true)
        })
    });
    SearchReport {
        explored_state_count: shortest.len(),
        terminal_state_count: shortest.keys().filter(|state| terminal(**state)).count(),
        maximum_shortest_depth: shortest.values().copied().max().unwrap_or(0),
        frontier_state_count: pending.len(),
        fixed_point,
    }
}

fn assert_search_metadata(
    search: &SearchExpectation,
    domains: &[(&str, &[&str])],
    initial: &[(&str, &str)],
    terminal: &[(&str, &str)],
) {
    assert_eq!(search.closure, SearchClosure::QueueExhaustion);
    assert_eq!(search.state_domains.len(), domains.len(), "{:?}", search.id);
    for (actual, (field, values)) in search.state_domains.iter().zip(domains) {
        assert_eq!(actual.field, *field, "{:?}", search.id);
        assert_eq!(
            actual.values.iter().map(String::as_str).collect::<Vec<_>>(),
            *values,
            "{:?}",
            search.id
        );
    }
    assert!(!search.initial.description.is_empty());
    assert!(!search.terminal.description.is_empty());
    assert_assignments(search, &search.initial.assignments, initial);
    assert_assignments(search, &search.terminal.assignments, terminal);
}

fn assert_assignments(
    search: &SearchExpectation,
    actual: &[StateAssignment],
    expected: &[(&str, &str)],
) {
    assert_eq!(actual.len(), expected.len(), "{:?}", search.id);
    for (actual, (field, value)) in actual.iter().zip(expected) {
        assert_eq!(actual.field, *field, "{:?}", search.id);
        assert_eq!(actual.value, *value, "{:?}", search.id);
    }
}

fn replay_coordinator_counterexample(case: &CoordinatorCounterexample) {
    match case.search {
        SearchId::IntegratedCoordinatorLifecycle => {
            let state = replay_prefix(
                LifecycleState::initial(),
                &case.trace,
                apply_lifecycle,
                &case.id,
            );
            let mutated = mutate_lifecycle(state, case.mutation);
            assert_eq!(
                lifecycle_violations(mutated),
                BTreeSet::from([case.invariant]),
                "{}",
                case.id
            );
            assert_eq!(
                apply_lifecycle(state, case.rejected_action),
                Err(case.rejection_reason),
                "{}",
                case.id
            );
        }
        SearchId::AuxiliaryResourceIdentity => {
            let state = replay_prefix(
                ResourceState::initial(),
                &case.trace,
                apply_resource,
                &case.id,
            );
            let mutated = mutate_resource(state, case.mutation);
            assert_eq!(
                resource_violations(mutated),
                BTreeSet::from([case.invariant]),
                "{}",
                case.id
            );
            assert_eq!(
                apply_resource(state, case.rejected_action),
                Err(case.rejection_reason),
                "{}",
                case.id
            );
        }
        SearchId::CoordinatorGuardExternalCall => {
            let state = replay_prefix(
                BoundaryState::initial(),
                &case.trace,
                apply_boundary,
                &case.id,
            );
            let mutated = mutate_boundary(state, case.mutation);
            assert_eq!(
                boundary_violations(mutated),
                BTreeSet::from([case.invariant]),
                "{}",
                case.id
            );
            assert_eq!(
                apply_boundary(state, case.rejected_action),
                Err(case.rejection_reason),
                "{}",
                case.id
            );
        }
    }
}

fn replay_prefix<State: Copy>(
    mut state: State,
    trace: &[ModelAction],
    apply: fn(State, ModelAction) -> Result<State, RejectionReason>,
    id: &str,
) -> State {
    for action in trace {
        state = apply(state, *action).unwrap_or_else(|reason| {
            panic!("invalid replay prefix in {id}: {action:?}: {reason:?}")
        });
    }
    state
}

fn mutate_lifecycle(mut state: LifecycleState, mutation: NegativeMutation) -> LifecycleState {
    match mutation {
        NegativeMutation::AbortWithoutCancellation => state.abort_requested = true,
        NegativeMutation::ChildEventBeforeSemanticSettlement => state.child_events = 1,
        NegativeMutation::DuplicateChildEvent => state.child_events = 2,
        NegativeMutation::ForegroundBeforeRootSettlement => state.foreground = true,
        NegativeMutation::GateBeforeRegistration => state.gate_open = true,
        NegativeMutation::JoinedAndDetached => {
            state.joined = true;
            state.detached = true;
        }
        NegativeMutation::LostRegisteredWake => {
            state.semantic_settled = true;
            state.waiter = WaiterState::Registered;
        }
        NegativeMutation::PermitReleasedBeforePhysicalSettlement => state.permit_released = true,
        NegativeMutation::RegistrationBeforeSubmission => state.registered = true,
        NegativeMutation::RootBeforeAttachedDrain => state.root_settled = true,
        NegativeMutation::SemanticSettlementBeforeGate => state.semantic_settled = true,
        NegativeMutation::SubmissionBeforeCreationPublication => state.submitted = true,
        NegativeMutation::TerminalBeforeChildEvent | NegativeMutation::TerminalBeforeForeground => {
            state.terminal = true;
        }
        _ => panic!("mutation is outside lifecycle search: {mutation:?}"),
    }
    state
}

fn mutate_resource(mut state: ResourceState, mutation: NegativeMutation) -> ResourceState {
    match mutation {
        NegativeMutation::DuplicateTaskIdentity => state.task_b = state.task_a,
        NegativeMutation::DuplicateOperationIdentity => state.operation_b = state.operation_a,
        NegativeMutation::OneUnitAdmissionOversubscribed => {
            state.permit_a = true;
            state.permit_b = true;
        }
        NegativeMutation::TransitionBudgetOversubscribed => {
            state.transition_a = true;
            state.transition_b = true;
        }
        NegativeMutation::OperationBudgetOversubscribed => {
            state.operation_budget_a = true;
            state.operation_budget_b = true;
        }
        _ => panic!("mutation is outside resource search: {mutation:?}"),
    }
    state
}

fn mutate_boundary(mut state: BoundaryState, mutation: NegativeMutation) -> BoundaryState {
    match mutation {
        NegativeMutation::ExternalCallUnderCoordinatorGuard => {
            state.external_call = ExternalCallState::InFlight;
        }
        NegativeMutation::WaiterNotifiedBeforePublication
        | NegativeMutation::WaiterNotifiedUnderCoordinatorGuard => {
            state.waiter = BoundaryWaiterState::Notified;
        }
        _ => panic!("mutation is outside boundary search: {mutation:?}"),
    }
    state
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

fn validate_implementation_anchor(root: &Path, evidence: &str) {
    let (path, test) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("implementation anchor has no test: {evidence}"));
    assert!(
        path.starts_with("crates/gantry-conformance/tests/")
            || path.starts_with("crates/gantry-runtime/src/"),
        "{evidence}"
    );
    assert!(path.ends_with(".rs"), "{evidence}");
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read implementation evidence {path}: {error}"));
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
