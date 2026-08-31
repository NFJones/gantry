//! Concurrent task creation and scheduler-owned state.
//!
//! This module records language task state independently of executor handles.
//! The scheduler added by the concurrent profile can therefore create and
//! settle one task identity without deriving semantics from adapter timing.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    ExecutorAbortResultKind, IdentityKind, RuntimeErrorCategory, TaskHandleState, TaskStatusKind,
    TerminalOnlyCategory,
};
use gantry_core::value::{LogicalValue, ValueError, ValueLimits, ValuePathSegment};
use gantry_host::contracts::HostError;
use gantry_ir::generated::TaskControlSiteKind;
use gantry_ir::{
    CanonicalPath, OwnershipFact, StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor,
};

use crate::machine::value_matches_type;
use crate::{
    LogicalSessionRegistryV1, Machine, MachineLabel, MachineOutcome, MachineStatus, MachineStep,
    SessionCreationModeV1, SessionError, SessionEstablisher, SessionEstablishmentError,
    SessionEstablishmentV1,
};

/// One analyzer-selected value binding copied into a child task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskCaptureV1 {
    name: Arc<str>,
    ty: TypeDescriptor,
    mutable: bool,
    value: LogicalValue,
}

impl TaskCaptureV1 {
    /// Constructs one typed capture after making a detached logical copy.
    pub fn new(
        name: Arc<str>,
        ty: TypeDescriptor,
        mutable: bool,
        value: &LogicalValue,
        limits: ValueLimits,
    ) -> Result<Self, TaskStateError> {
        if name.is_empty() {
            return Err(TaskStateError::InvalidCaptureName);
        }
        if !value_matches_type(value, &ty) {
            return Err(TaskStateError::CaptureType);
        }
        let value = value
            .detached_copy(limits)
            .map_err(TaskStateError::CaptureValue)?;
        Ok(Self {
            name,
            ty,
            mutable,
            value,
        })
    }

    /// Returns the exact source binding name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the analyzed binding type.
    #[must_use]
    pub const fn ty(&self) -> &TypeDescriptor {
        &self.ty
    }

    /// Returns whether the copied child-local root may be replaced.
    #[must_use]
    pub const fn is_mutable(&self) -> bool {
        self.mutable
    }

    /// Returns the isolated child-local value.
    #[must_use]
    pub const fn value(&self) -> &LogicalValue {
        &self.value
    }
}

/// Stable internal identity of one dynamic source task handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DynamicTaskHandleIdentity {
    owner: ProtocolIdentity,
    child: ProtocolIdentity,
}

impl DynamicTaskHandleIdentity {
    /// Returns the Gantry task that exclusively owns this handle.
    #[must_use]
    pub const fn owner(self) -> ProtocolIdentity {
        self.owner
    }

    /// Returns the child task named by this handle.
    #[must_use]
    pub const fn child(self) -> ProtocolIdentity {
        self.child
    }
}

/// Executor submission or task-local runtime failure retained by task state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskFailureV1 {
    /// Exact portable runtime category.
    pub category: RuntimeErrorCategory,
    /// Stable adapter code or machine code.
    pub code: Arc<str>,
    /// Optional protected integration diagnostic reference.
    pub protected_diagnostic: Option<Arc<str>>,
}

/// One dynamic handle named by canonical ownership-change evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskOwnershipMemberV1 {
    /// Stable internal handle identity.
    handle_id: DynamicTaskHandleIdentity,
    /// Exact lexical handle name selected by analysis.
    handle_name: Arc<str>,
    /// Stable child task identity.
    task_id: ProtocolIdentity,
    /// Canonical dynamic task path fixed at spawn.
    task_path: Arc<[Arc<str>]>,
}

impl TaskOwnershipMemberV1 {
    /// Returns the stable internal handle identity.
    #[must_use]
    pub const fn handle_id(&self) -> DynamicTaskHandleIdentity {
        self.handle_id
    }

    /// Returns the exact analyzer-selected lexical handle name.
    #[must_use]
    pub fn handle_name(&self) -> &str {
        &self.handle_name
    }

    /// Returns the stable child task identity.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns the canonical dynamic task path fixed at spawn.
    #[must_use]
    pub fn task_path(&self) -> &[Arc<str>] {
        &self.task_path
    }
}

/// One atomic source-language ownership transition in canonical member order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskOwnershipChangedV1 {
    /// Gantry task that owned every selected attached handle.
    owner_task_id: ProtocolIdentity,
    /// Canonical named-join, joinall, or detach site.
    control_site: StaticSiteId,
    /// Exact task-control form that caused the transition.
    control_kind: TaskControlSiteKind,
    /// Exact resulting source-language disposition.
    disposition: TaskHandleState,
    /// Selected dynamic members in source or declaration order.
    members: Vec<TaskOwnershipMemberV1>,
}

impl TaskOwnershipChangedV1 {
    /// Returns the Gantry task that owned every selected handle.
    #[must_use]
    pub const fn owner_task_id(&self) -> ProtocolIdentity {
        self.owner_task_id
    }

    /// Returns the canonical task-control site that caused the transition.
    #[must_use]
    pub const fn control_site(&self) -> &StaticSiteId {
        &self.control_site
    }

    /// Returns the exact task-control form that caused the transition.
    #[must_use]
    pub const fn control_kind(&self) -> TaskControlSiteKind {
        self.control_kind
    }

    /// Returns the resulting source-language disposition.
    #[must_use]
    pub const fn disposition(&self) -> TaskHandleState {
        self.disposition
    }

    /// Returns selected members in immutable source or declaration order.
    #[must_use]
    pub fn members(&self) -> &[TaskOwnershipMemberV1] {
        &self.members
    }
}

/// Result of atomically consuming one analyzed join selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JoinStartV1 {
    /// An empty joinall reduced directly to Unit without ownership evidence.
    Empty,
    /// A nonempty join consumed every selected handle before waiting.
    Started(TaskOwnershipChangedV1),
}

/// Exact terminal failure of one joined member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskJoinMemberFailureKindV1 {
    /// The child settled with its retained runtime failure.
    Failed(TaskFailureV1),
    /// The child settled through cancellation with its protected reason reference.
    Cancelled(Arc<str>),
}

/// One failed joined task in source or declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskJoinMemberFailureV1 {
    /// Stable child task identity.
    pub task_id: ProtocolIdentity,
    /// Canonical dynamic task path fixed at spawn.
    pub task_path: Arc<[Arc<str>]>,
    /// Exact terminal child failure.
    pub failure: TaskJoinMemberFailureKindV1,
}

/// Ordered aggregate `task-join-failure` retained after every member settles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskJoinFailureV1 {
    /// Exact portable aggregate category.
    pub category: RuntimeErrorCategory,
    /// Failed or cancelled members in the join's normative order.
    pub failures: Vec<TaskJoinMemberFailureV1>,
}

/// Current all-settled resolution of one consumed join selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JoinResolutionV1 {
    /// At least one selected task remains unsettled; identities retain join order.
    Pending(Vec<ProtocolIdentity>),
    /// Every selected task succeeded and produced the statically determined shape.
    Succeeded(LogicalValue),
    /// Every selected task settled and at least one failed or was cancelled.
    Failed(TaskJoinFailureV1),
}

/// Complete scheduler-owned status of one admitted child task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConcurrentTaskStatusV1 {
    /// Language state exists, but executor submission has not resolved.
    Submitting,
    /// Executor submission succeeded and the task may be scheduled.
    Running,
    /// The child returned one typed value.
    Succeeded(LogicalValue),
    /// The child failed before or after becoming runnable.
    Failed(TaskFailureV1),
    /// Cancellation settled the child without a source result.
    Cancelled(Arc<str>),
}

impl ConcurrentTaskStatusV1 {
    /// Projects the closed portable task-status vocabulary.
    #[must_use]
    pub const fn kind(&self) -> TaskStatusKind {
        match self {
            Self::Submitting => TaskStatusKind::Submitting,
            Self::Running => TaskStatusKind::Running,
            Self::Succeeded(_) => TaskStatusKind::Succeeded,
            Self::Failed(_) => TaskStatusKind::Failed,
            Self::Cancelled(_) => TaskStatusKind::Cancelled,
        }
    }
}

/// One task whose detached failure contributes to execution-terminal state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedTaskFailureV1 {
    /// Stable failed task identity.
    pub task_id: ProtocolIdentity,
    /// Canonical dynamic task path used for stable failure ordering.
    pub task_path: Arc<[Arc<str>]>,
    /// Exact retained task-local failure.
    pub failure: TaskFailureV1,
}

/// Precedence-selected terminal category for one concurrent execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcurrentTerminalCategoryV1 {
    /// The foreground task failed with this portable runtime category.
    Runtime(RuntimeErrorCategory),
    /// Foreground settled without failure, but detached work failed.
    TerminalOnly(TerminalOnlyCategory),
    /// Cancellation was effective after higher-precedence failures were absent.
    Cancellation,
}

/// Terminal execution projection fixed only after all detached work settles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentTerminalOutcomeV1 {
    /// Exact precedence-selected terminal category.
    pub category: ConcurrentTerminalCategoryV1,
    /// Foreground outcome fixed independently of detached work.
    pub foreground: MachineOutcome,
    /// Detached failures in canonical dynamic task-path order.
    pub detached_failures: Vec<DetachedTaskFailureV1>,
}

/// Result of one idempotent executor-abort attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskAbortResultV1 {
    /// The executor confirms that the task future will no longer be polled.
    Stopped,
    /// The executor reports that the task had already settled.
    AlreadySettled,
    /// The executor could not stop the task.
    Failed(HostError),
}

impl TaskAbortResultV1 {
    /// Projects the closed portable executor-abort result vocabulary.
    #[must_use]
    pub const fn kind(&self) -> ExecutorAbortResultKind {
        match self {
            Self::Stopped => ExecutorAbortResultKind::Stopped,
            Self::AlreadySettled => ExecutorAbortResultKind::AlreadySettled,
            Self::Failed(_) => ExecutorAbortResultKind::Failed,
        }
    }
}

/// Immutable and mutable state retained for one admitted child task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentTaskRecordV1 {
    task_id: ProtocolIdentity,
    parent_task_id: ProtocolIdentity,
    handle_name: Arc<str>,
    handle_id: DynamicTaskHandleIdentity,
    task_path: Arc<[Arc<str>]>,
    workflow: CanonicalPath,
    spawn_site: StructuralPosition,
    spawn_occurrence: u64,
    result_type: TypeDescriptor,
    captures: BTreeMap<Arc<str>, TaskCaptureV1>,
    inherited_agent: Option<Arc<str>>,
    parent_session_id: ProtocolIdentity,
    base_session_id: ProtocolIdentity,
    handle_state: TaskHandleState,
    handle_visible: bool,
    status: ConcurrentTaskStatusV1,
}

impl ConcurrentTaskRecordV1 {
    /// Returns the stable child task identity.
    #[must_use]
    pub const fn task_id(&self) -> ProtocolIdentity {
        self.task_id
    }

    /// Returns the parent task that owns the source handle.
    #[must_use]
    pub const fn parent_task_id(&self) -> ProtocolIdentity {
        self.parent_task_id
    }

    /// Returns the exact lexical handle name exposed after submission resolves.
    #[must_use]
    pub fn handle_name(&self) -> &str {
        &self.handle_name
    }

    /// Returns the stable internal handle identity.
    #[must_use]
    pub const fn handle_id(&self) -> DynamicTaskHandleIdentity {
        self.handle_id
    }

    /// Returns the canonical dynamic task path.
    #[must_use]
    pub fn task_path(&self) -> &[Arc<str>] {
        &self.task_path
    }

    /// Returns the canonical containing workflow.
    #[must_use]
    pub const fn workflow(&self) -> &CanonicalPath {
        &self.workflow
    }

    /// Returns the canonical spawn site.
    #[must_use]
    pub const fn spawn_site(&self) -> &StructuralPosition {
        &self.spawn_site
    }

    /// Returns the zero-based dynamic occurrence at the static spawn site.
    #[must_use]
    pub const fn spawn_occurrence(&self) -> u64 {
        self.spawn_occurrence
    }

    /// Returns the declared child result type.
    #[must_use]
    pub const fn result_type(&self) -> &TypeDescriptor {
        &self.result_type
    }

    /// Returns all copied captures in canonical name order.
    #[must_use]
    pub const fn captures(&self) -> &BTreeMap<Arc<str>, TaskCaptureV1> {
        &self.captures
    }

    /// Returns the optional agent snapshot taken at task creation.
    #[must_use]
    pub fn inherited_agent(&self) -> Option<&str> {
        self.inherited_agent.as_deref()
    }

    /// Returns the active parent session captured at task creation.
    #[must_use]
    pub const fn parent_session_id(&self) -> ProtocolIdentity {
        self.parent_session_id
    }

    /// Returns the automatic fork session fixed for the child task.
    #[must_use]
    pub const fn base_session_id(&self) -> ProtocolIdentity {
        self.base_session_id
    }

    /// Returns the source-language ownership state of the dynamic handle.
    #[must_use]
    pub const fn handle_state(&self) -> TaskHandleState {
        self.handle_state
    }

    /// Returns whether submission resolution exposed the handle to its owner.
    #[must_use]
    pub const fn handle_is_visible(&self) -> bool {
        self.handle_visible
    }

    /// Returns the complete task status.
    #[must_use]
    pub const fn status(&self) -> &ConcurrentTaskStatusV1 {
        &self.status
    }
}

/// Result of recording one admitted task before executor submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskCreationV1 {
    /// Stable child task identity.
    pub task_id: ProtocolIdentity,
    /// Stable owner-local handle identity.
    pub handle_id: DynamicTaskHandleIdentity,
    /// Automatic child fork-session identity.
    pub base_session_id: ProtocolIdentity,
    /// Exact scheduler-owned `task-created` transition.
    pub transition: TaskCreatedV1,
}

/// Exact scheduler transition recorded before child executor submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskCreatedV1 {
    /// Stable child task identity.
    pub task_id: ProtocolIdentity,
    /// Task that created and owns the attached source handle.
    pub parent_task_id: ProtocolIdentity,
    /// Canonical workflow containing the spawn.
    pub workflow: CanonicalPath,
    /// Canonical static spawn position.
    pub spawn_site: StructuralPosition,
    /// Zero-based dynamic occurrence at the static site.
    pub spawn_occurrence: u64,
    /// Declared child result type.
    pub result_type: TypeDescriptor,
    /// Initial source-language ownership state.
    pub attachment: TaskHandleState,
}

/// Input captured at the exact source spawn boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskCreationRequestV1 {
    /// Task executing the source spawn site.
    pub parent_task_id: ProtocolIdentity,
    /// Exact lexical handle declared by the source spawn.
    pub handle_name: Arc<str>,
    /// Canonical workflow containing the spawn.
    pub workflow: CanonicalPath,
    /// Canonical static spawn position.
    pub spawn_site: StructuralPosition,
    /// Zero-based dynamic occurrence at that site.
    pub spawn_occurrence: u64,
    /// Declared child result type.
    pub result_type: TypeDescriptor,
    /// Analyzer-selected captures before child execution.
    pub captures: Vec<TaskCaptureV1>,
    /// Active agent snapshot.
    pub inherited_agent: Option<Arc<str>>,
    /// Active parent session snapshot.
    pub parent_session_id: ProtocolIdentity,
}

/// Stable snapshot of all still-owned work in one concurrent shutdown cohort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentShutdownCohortV1 {
    /// Accepted execution that owns every listed task.
    pub execution_id: ProtocolIdentity,
    /// Foreground root task when its outcome is not yet fixed.
    pub foreground_task: Option<ProtocolIdentity>,
    /// Pending attached descendants in canonical dynamic task-path order.
    pub attached_tasks: Vec<ProtocolIdentity>,
    /// Pending detached work in canonical dynamic task-path order.
    pub detached_tasks: Vec<ProtocolIdentity>,
}

/// Execution-scoped owner of cumulative task count and child task state.
#[derive(Debug)]
pub struct ConcurrentTaskStateV1 {
    execution_id: ProtocolIdentity,
    root_task_id: ProtocolIdentity,
    maximum_tasks: u64,
    created_tasks: u64,
    task_paths: BTreeMap<ProtocolIdentity, Arc<[Arc<str>]>>,
    tasks: BTreeMap<ProtocolIdentity, ConcurrentTaskRecordV1>,
    submitting_by_parent: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
    cancellation_reasons: BTreeMap<ProtocolIdentity, Arc<str>>,
    execution_cancellation: Option<Arc<str>>,
    foreground: Option<MachineOutcome>,
    terminal: Option<ConcurrentTerminalOutcomeV1>,
}

impl ConcurrentTaskStateV1 {
    /// Creates task state containing the already-running root task.
    pub fn new(
        execution_id: ProtocolIdentity,
        root_task_id: ProtocolIdentity,
        maximum_tasks: u64,
    ) -> Result<Self, TaskStateError> {
        if execution_id.kind() != IdentityKind::Execution {
            return Err(TaskStateError::InvalidExecutionIdentity);
        }
        if root_task_id.kind() != IdentityKind::Task {
            return Err(TaskStateError::InvalidTaskIdentity);
        }
        if maximum_tasks == 0 {
            return Err(TaskStateError::InvalidTaskLimit);
        }
        Ok(Self {
            execution_id,
            root_task_id,
            maximum_tasks,
            created_tasks: 1,
            task_paths: BTreeMap::from([(root_task_id, Arc::from([]))]),
            tasks: BTreeMap::new(),
            submitting_by_parent: BTreeMap::new(),
            cancellation_reasons: BTreeMap::new(),
            execution_cancellation: None,
            foreground: None,
            terminal: None,
        })
    }

    /// Returns the cumulative count, including the root and settled children.
    #[must_use]
    pub const fn created_task_count(&self) -> u64 {
        self.created_tasks
    }

    /// Returns the accepted execution that owns this task tree.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns the stable root task identity for this execution.
    #[must_use]
    pub const fn root_task_id(&self) -> ProtocolIdentity {
        self.root_task_id
    }

    /// Returns the configured cumulative task-count ceiling.
    #[must_use]
    pub const fn maximum_task_count(&self) -> u64 {
        self.maximum_tasks
    }

    /// Returns one admitted child task.
    #[must_use]
    pub fn task(&self, task_id: ProtocolIdentity) -> Option<&ConcurrentTaskRecordV1> {
        self.tasks.get(&task_id)
    }

    /// Returns the first effective cancellation reason for one task.
    #[must_use]
    pub fn task_cancellation_reason(&self, task_id: ProtocolIdentity) -> Option<&str> {
        self.cancellation_reasons.get(&task_id).map(AsRef::as_ref)
    }

    /// Returns the fixed foreground outcome, independently of detached work.
    #[must_use]
    pub const fn foreground_outcome(&self) -> Option<&MachineOutcome> {
        self.foreground.as_ref()
    }

    /// Returns the fixed execution-terminal projection, when detached work is settled.
    #[must_use]
    pub const fn terminal_outcome(&self) -> Option<&ConcurrentTerminalOutcomeV1> {
        self.terminal.as_ref()
    }

    /// Returns whether one task is suspended on unresolved child submission.
    #[must_use]
    pub fn parent_is_suspended(&self, task_id: ProtocolIdentity) -> bool {
        self.submitting_by_parent.contains_key(&task_id)
    }

    /// Snapshots every unsettled task owned by this execution for shutdown coordination.
    #[must_use]
    pub fn shutdown_cohort(&self) -> ConcurrentShutdownCohortV1 {
        let mut attached = Vec::new();
        let mut detached = Vec::new();
        for (task_id, task) in &self.tasks {
            if !matches!(
                task.status,
                ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
            ) {
                continue;
            }
            if task.handle_state == TaskHandleState::Detached {
                detached.push(*task_id);
            } else {
                attached.push(*task_id);
            }
        }
        let by_path = |left: &ProtocolIdentity, right: &ProtocolIdentity| {
            self.task_paths.get(left).cmp(&self.task_paths.get(right))
        };
        attached.sort_by(by_path);
        detached.sort_by(by_path);
        ConcurrentShutdownCohortV1 {
            execution_id: self.execution_id,
            foreground_task: self.foreground.is_none().then_some(self.root_task_id),
            attached_tasks: attached,
            detached_tasks: detached,
        }
    }

    /// Records the first execution cancellation reason and propagates it to all live tasks.
    pub fn cancel_execution(
        &mut self,
        reason: impl Into<Arc<str>>,
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        if self.terminal.is_some() {
            return Ok(Vec::new());
        }
        let reason = reason.into();
        if reason.is_empty() {
            return Err(TaskStateError::InvalidCancellationReason);
        }
        let reason = self
            .execution_cancellation
            .get_or_insert_with(|| Arc::clone(&reason))
            .clone();
        let mut affected = Vec::new();
        if !self.cancellation_reasons.contains_key(&self.root_task_id) {
            self.cancellation_reasons
                .insert(self.root_task_id, Arc::clone(&reason));
            affected.push(self.root_task_id);
        }
        for (task_id, task) in &self.tasks {
            if matches!(
                task.status,
                ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
            ) && !self.cancellation_reasons.contains_key(task_id)
            {
                self.cancellation_reasons
                    .insert(*task_id, Arc::clone(&reason));
                affected.push(*task_id);
            }
        }
        affected.sort_by(|left, right| self.task_paths.get(left).cmp(&self.task_paths.get(right)));
        Ok(affected)
    }

    /// Records a parent-task cancellation and propagates it through attached descendants.
    pub fn cancel_task_tree(
        &mut self,
        task_id: ProtocolIdentity,
        reason: impl Into<Arc<str>>,
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        if !self.task_paths.contains_key(&task_id) {
            return Err(TaskStateError::UnknownTask);
        }
        let reason = reason.into();
        if reason.is_empty() {
            return Err(TaskStateError::InvalidCancellationReason);
        }
        let existing = self.cancellation_reasons.get(&task_id).cloned();
        let reason = existing.unwrap_or_else(|| Arc::clone(&reason));
        let mut affected = Vec::new();
        if let std::collections::btree_map::Entry::Vacant(entry) =
            self.cancellation_reasons.entry(task_id)
        {
            entry.insert(Arc::clone(&reason));
            affected.push(task_id);
        }
        let mut frontier = vec![task_id];
        while let Some(parent) = frontier.pop() {
            for (child_id, child) in &self.tasks {
                if child.parent_task_id == parent
                    && child.handle_state != TaskHandleState::Detached
                    && matches!(
                        child.status,
                        ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                    )
                    && !self.cancellation_reasons.contains_key(child_id)
                {
                    self.cancellation_reasons
                        .insert(*child_id, Arc::clone(&reason));
                    affected.push(*child_id);
                    frontier.push(*child_id);
                }
            }
        }
        affected.sort_by(|left, right| self.task_paths.get(left).cmp(&self.task_paths.get(right)));
        Ok(affected)
    }

    /// Fixes foreground completion exactly once without waiting for detached work.
    pub fn complete_foreground(&mut self, outcome: MachineOutcome) -> Result<(), TaskStateError> {
        if self.foreground.is_some() {
            return Err(TaskStateError::ForegroundAlreadyFixed);
        }
        if self.tasks.values().any(|task| {
            task.handle_state != TaskHandleState::Detached
                && matches!(
                    task.status,
                    ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                )
        }) {
            return Err(TaskStateError::AttachedTasksPending);
        }
        self.foreground = Some(outcome);
        Ok(())
    }

    /// Fixes terminal execution after every detached task has settled.
    pub fn complete_terminal(&mut self) -> Result<&ConcurrentTerminalOutcomeV1, TaskStateError> {
        if self.terminal.is_some() {
            return self
                .terminal
                .as_ref()
                .ok_or(TaskStateError::TerminalAlreadyFixed);
        }
        let foreground = self
            .foreground
            .clone()
            .ok_or(TaskStateError::ForegroundUnknown)?;
        if self.tasks.values().any(|task| {
            task.handle_state == TaskHandleState::Detached
                && matches!(
                    task.status,
                    ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                )
        }) {
            return Err(TaskStateError::DetachedTasksPending);
        }
        let mut detached_failures = self
            .tasks
            .values()
            .filter_map(|task| {
                if task.handle_state != TaskHandleState::Detached {
                    return None;
                }
                let ConcurrentTaskStatusV1::Failed(failure) = &task.status else {
                    return None;
                };
                Some(DetachedTaskFailureV1 {
                    task_id: task.task_id,
                    task_path: Arc::clone(&task.task_path),
                    failure: failure.clone(),
                })
            })
            .collect::<Vec<_>>();
        detached_failures.sort_by(|left, right| left.task_path.cmp(&right.task_path));
        let category = match &foreground {
            MachineOutcome::Failed(failure) => {
                ConcurrentTerminalCategoryV1::Runtime(machine_failure_category(failure.code))
            }
            MachineOutcome::Succeeded(_) if !detached_failures.is_empty() => {
                ConcurrentTerminalCategoryV1::TerminalOnly(
                    TerminalOnlyCategory::DetachedTaskFailure,
                )
            }
            MachineOutcome::Cancelled(_) => ConcurrentTerminalCategoryV1::Cancellation,
            MachineOutcome::Succeeded(_) if self.execution_cancellation.is_some() => {
                ConcurrentTerminalCategoryV1::Cancellation
            }
            MachineOutcome::Succeeded(_) => {
                ConcurrentTerminalCategoryV1::TerminalOnly(TerminalOnlyCategory::Success)
            }
        };
        self.terminal = Some(ConcurrentTerminalOutcomeV1 {
            category,
            foreground,
            detached_failures,
        });
        self.terminal
            .as_ref()
            .ok_or(TaskStateError::TerminalAlreadyFixed)
    }

    /// Records task, handle, captures, and fork-session state before submission.
    pub fn create_child(
        &mut self,
        sessions: &mut LogicalSessionRegistryV1,
        request: TaskCreationRequestV1,
        limits: ValueLimits,
    ) -> Result<TaskCreationV1, TaskStateError> {
        if request.handle_name.is_empty() {
            return Err(TaskStateError::InvalidHandleName);
        }
        if self.execution_cancellation.is_some()
            || self
                .cancellation_reasons
                .contains_key(&request.parent_task_id)
        {
            return Err(TaskStateError::TaskCancelled);
        }
        if self
            .submitting_by_parent
            .contains_key(&request.parent_task_id)
        {
            return Err(TaskStateError::ParentSuspended);
        }
        let next_count = self
            .created_tasks
            .checked_add(1)
            .ok_or(TaskStateError::TaskCountLimit)?;
        if next_count > self.maximum_tasks {
            return Err(TaskStateError::TaskCountLimit);
        }
        if request.parent_task_id.kind() != IdentityKind::Task {
            return Err(TaskStateError::InvalidTaskIdentity);
        }
        if request.parent_session_id.kind() != IdentityKind::Session {
            return Err(TaskStateError::InvalidSessionIdentity);
        }
        let parent_path = self
            .task_paths
            .get(&request.parent_task_id)
            .ok_or(TaskStateError::UnknownParentTask)?;
        let mut task_path = parent_path.to_vec();
        task_path.push(Arc::from(task_path_frame(
            &request.workflow,
            &request.spawn_site,
            request.spawn_occurrence,
        )));
        let task_id = ProtocolIdentity::derive(
            IdentityKind::Task,
            &task_identity_key(self.execution_id, &task_path),
        )
        .map_err(|_| TaskStateError::IdentityInvariant)?;
        if self.task_paths.contains_key(&task_id) || self.tasks.contains_key(&task_id) {
            return Err(TaskStateError::IdentityCollision);
        }

        let mut captures = BTreeMap::new();
        for capture in request.captures {
            if captures.contains_key(capture.name()) {
                return Err(TaskStateError::DuplicateCapture);
            }
            let capture = TaskCaptureV1::new(
                Arc::clone(&capture.name),
                capture.ty.clone(),
                capture.mutable,
                &capture.value,
                limits,
            )?;
            captures.insert(Arc::clone(&capture.name), capture);
        }

        let base_session_id = sessions
            .create(
                request.parent_session_id,
                task_id,
                request.spawn_site.clone(),
                request.spawn_occurrence,
                SessionCreationModeV1::Fork,
                SessionEstablishmentV1::Separate,
            )
            .map_err(TaskStateError::Session)?
            .id;
        let handle_id = DynamicTaskHandleIdentity {
            owner: request.parent_task_id,
            child: task_id,
        };
        let record = ConcurrentTaskRecordV1 {
            task_id,
            parent_task_id: request.parent_task_id,
            handle_name: request.handle_name,
            handle_id,
            task_path: Arc::from(task_path.clone()),
            workflow: request.workflow.clone(),
            spawn_site: request.spawn_site.clone(),
            spawn_occurrence: request.spawn_occurrence,
            result_type: request.result_type.clone(),
            captures,
            inherited_agent: request.inherited_agent,
            parent_session_id: request.parent_session_id,
            base_session_id,
            handle_state: TaskHandleState::Attached,
            handle_visible: false,
            status: ConcurrentTaskStatusV1::Submitting,
        };
        self.created_tasks = next_count;
        self.task_paths.insert(task_id, Arc::from(task_path));
        self.submitting_by_parent
            .insert(request.parent_task_id, task_id);
        self.tasks.insert(task_id, record);
        Ok(TaskCreationV1 {
            task_id,
            handle_id,
            base_session_id,
            transition: TaskCreatedV1 {
                task_id,
                parent_task_id: request.parent_task_id,
                workflow: request.workflow,
                spawn_site: request.spawn_site,
                spawn_occurrence: request.spawn_occurrence,
                result_type: request.result_type,
                attachment: TaskHandleState::Attached,
            },
        })
    }

    /// Resolves executor submission and exposes the same attached handle.
    pub fn resolve_submission(
        &mut self,
        task_id: ProtocolIdentity,
        result: Result<(), HostError>,
    ) -> Result<(), TaskStateError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or(TaskStateError::UnknownTask)?;
        if !matches!(task.status, ConcurrentTaskStatusV1::Submitting) {
            return Err(TaskStateError::InvalidTransition);
        }
        if self.submitting_by_parent.remove(&task.parent_task_id) != Some(task_id) {
            return Err(TaskStateError::InvalidTransition);
        }
        task.status = match result {
            Ok(()) => self
                .cancellation_reasons
                .get(&task_id)
                .map_or(ConcurrentTaskStatusV1::Running, |reason| {
                    ConcurrentTaskStatusV1::Cancelled(Arc::clone(reason))
                }),
            Err(error) => ConcurrentTaskStatusV1::Failed(TaskFailureV1 {
                category: RuntimeErrorCategory::ExecutorFailure,
                code: error.code,
                protected_diagnostic: error.protected_diagnostic,
            }),
        };
        task.handle_visible = true;
        Ok(())
    }

    /// Settles one running child exactly once from the shared machine outcome.
    pub fn settle(
        &mut self,
        task_id: ProtocolIdentity,
        outcome: MachineOutcome,
    ) -> Result<(), TaskStateError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or(TaskStateError::UnknownTask)?;
        if !matches!(task.status, ConcurrentTaskStatusV1::Running) {
            return Err(TaskStateError::InvalidTransition);
        }
        let outcome = self
            .cancellation_reasons
            .get(&task_id)
            .map_or(outcome, |reason| {
                MachineOutcome::Cancelled(Arc::clone(reason))
            });
        if let MachineOutcome::Succeeded(value) = &outcome
            && !value_matches_type(value, &task.result_type)
        {
            return Err(TaskStateError::ResultType);
        }
        task.status = match outcome {
            MachineOutcome::Succeeded(value) => ConcurrentTaskStatusV1::Succeeded(value),
            MachineOutcome::Failed(failure) => ConcurrentTaskStatusV1::Failed(TaskFailureV1 {
                category: match failure.code {
                    crate::RuntimeCode::Operation(category) => category,
                    crate::RuntimeCode::UnsupportedEffect
                    | crate::RuntimeCode::InternalInvariant => {
                        RuntimeErrorCategory::InternalInvariantFailure
                    }
                    crate::RuntimeCode::Deterministic(_)
                    | crate::RuntimeCode::DeterministicTransitionBudget
                    | crate::RuntimeCode::OperationBudget
                    | crate::RuntimeCode::LoopIterationBudget
                    | crate::RuntimeCode::LoopLimitExhausted => {
                        RuntimeErrorCategory::DeterministicEvaluationFailure
                    }
                },
                code: Arc::from(failure.code.wire_name()),
                protected_diagnostic: None,
            }),
            MachineOutcome::Cancelled(reason) => ConcurrentTaskStatusV1::Cancelled(reason),
        };
        Ok(())
    }

    /// Atomically consumes an analyzer-selected named join or joinall selection.
    ///
    /// The supplied dynamic vector is resolved against the analyzer's static
    /// handle vector, so neither runtime settlement order nor caller ordering
    /// can change the normative result order.
    pub fn begin_join(
        &mut self,
        owner_task_id: ProtocolIdentity,
        control: &TaskControlSite,
        handles: &[DynamicTaskHandleIdentity],
    ) -> Result<JoinStartV1, TaskStateError> {
        if !matches!(
            control.kind,
            TaskControlSiteKind::Join | TaskControlSiteKind::JoinAll
        ) {
            return Err(TaskStateError::InvalidTaskControl);
        }
        if handles.is_empty() {
            if control.kind != TaskControlSiteKind::JoinAll || !control.handles.is_empty() {
                return Err(TaskStateError::InvalidTaskControl);
            }
            return Ok(JoinStartV1::Empty);
        }

        let task_ids = self.validate_control_selection(owner_task_id, control, handles)?;
        let members = task_ids
            .iter()
            .map(|task_id| {
                let task = self.tasks.get(task_id).ok_or(TaskStateError::UnknownTask)?;
                Ok(TaskOwnershipMemberV1 {
                    handle_id: task.handle_id,
                    handle_name: Arc::clone(&task.handle_name),
                    task_id: *task_id,
                    task_path: Arc::clone(&task.task_path),
                })
            })
            .collect::<Result<Vec<_>, TaskStateError>>()?;
        for task_id in task_ids {
            let task = self
                .tasks
                .get_mut(&task_id)
                .ok_or(TaskStateError::UnknownTask)?;
            task.handle_state = TaskHandleState::Joined;
        }

        Ok(JoinStartV1::Started(TaskOwnershipChangedV1 {
            owner_task_id,
            control_site: control.id.clone(),
            control_kind: control.kind,
            disposition: TaskHandleState::Joined,
            members,
        }))
    }

    /// Resolves one already-consumed join only after every selected task settles.
    pub fn resolve_join(
        &self,
        ownership: &TaskOwnershipChangedV1,
        limits: ValueLimits,
    ) -> Result<JoinResolutionV1, TaskStateError> {
        if ownership.disposition != TaskHandleState::Joined
            || !matches!(
                ownership.control_kind,
                TaskControlSiteKind::Join | TaskControlSiteKind::JoinAll
            )
            || ownership.members.is_empty()
        {
            return Err(TaskStateError::InvalidOwnershipEvidence);
        }

        let mut seen = BTreeSet::new();
        let mut pending = Vec::new();
        let mut result_types = Vec::new();
        let mut values = Vec::new();
        let mut failures = Vec::new();
        for member in &ownership.members {
            if !seen.insert(member.handle_id) {
                return Err(TaskStateError::InvalidOwnershipEvidence);
            }
            let task = self
                .tasks
                .get(&member.task_id)
                .ok_or(TaskStateError::UnknownTask)?;
            if task.parent_task_id != ownership.owner_task_id
                || task.handle_id != member.handle_id
                || task.handle_name != member.handle_name
                || task.task_path != member.task_path
                || task.handle_state != TaskHandleState::Joined
            {
                return Err(TaskStateError::InvalidOwnershipEvidence);
            }
            match &task.status {
                ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running => {
                    pending.push(task.task_id);
                }
                ConcurrentTaskStatusV1::Succeeded(value) => {
                    result_types.push(task.result_type.clone());
                    values.push(value.clone());
                }
                ConcurrentTaskStatusV1::Failed(failure) => {
                    failures.push(TaskJoinMemberFailureV1 {
                        task_id: task.task_id,
                        task_path: Arc::clone(&task.task_path),
                        failure: TaskJoinMemberFailureKindV1::Failed(failure.clone()),
                    });
                }
                ConcurrentTaskStatusV1::Cancelled(reason) => {
                    failures.push(TaskJoinMemberFailureV1 {
                        task_id: task.task_id,
                        task_path: Arc::clone(&task.task_path),
                        failure: TaskJoinMemberFailureKindV1::Cancelled(Arc::clone(reason)),
                    });
                }
            }
        }
        if !pending.is_empty() {
            return Ok(JoinResolutionV1::Pending(pending));
        }
        if !failures.is_empty() {
            return Ok(JoinResolutionV1::Failed(TaskJoinFailureV1 {
                category: RuntimeErrorCategory::TaskJoinFailure,
                failures,
            }));
        }

        let all_unit = result_types
            .iter()
            .all(|result_type| *result_type == TypeDescriptor::UNIT);
        let any_unit = result_types.contains(&TypeDescriptor::UNIT);
        let value = if all_unit {
            LogicalValue::unit()
        } else if any_unit {
            return Err(TaskStateError::JoinResultType);
        } else if values.len() == 1 {
            values
                .pop()
                .ok_or(TaskStateError::InvalidOwnershipEvidence)?
        } else if result_types.windows(2).all(|pair| pair[0] == pair[1]) {
            LogicalValue::list(values, limits).map_err(TaskStateError::JoinValue)?
        } else {
            LogicalValue::tuple(values, limits).map_err(TaskStateError::JoinValue)?
        };
        Ok(JoinResolutionV1::Succeeded(value))
    }

    /// Transfers one attached handle to execution-owned detached work without waiting.
    pub fn detach(
        &mut self,
        owner_task_id: ProtocolIdentity,
        control: &TaskControlSite,
        handle: DynamicTaskHandleIdentity,
    ) -> Result<TaskOwnershipChangedV1, TaskStateError> {
        if control.kind != TaskControlSiteKind::Detach {
            return Err(TaskStateError::InvalidTaskControl);
        }
        let task_ids = self.validate_control_selection(owner_task_id, control, &[handle])?;
        let task_id = task_ids
            .into_iter()
            .next()
            .ok_or(TaskStateError::InvalidTaskControl)?;
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or(TaskStateError::UnknownTask)?;
        task.handle_state = TaskHandleState::Detached;
        Ok(TaskOwnershipChangedV1 {
            owner_task_id,
            control_site: control.id.clone(),
            control_kind: control.kind,
            disposition: TaskHandleState::Detached,
            members: vec![TaskOwnershipMemberV1 {
                handle_id: task.handle_id,
                handle_name: Arc::clone(&task.handle_name),
                task_id: task.task_id,
                task_path: Arc::clone(&task.task_path),
            }],
        })
    }

    /// Cross-checks one exact dynamic path against an analyzer ownership fact.
    ///
    /// `discharged` is analysis-only: it accepts either exact consumed runtime
    /// disposition while preserving the joined or detached path evidence.
    pub fn validate_analyzer_ownership(
        &self,
        handle: DynamicTaskHandleIdentity,
        fact: &OwnershipFact,
    ) -> Result<(), TaskStateError> {
        let task = self
            .tasks
            .get(&handle.child())
            .ok_or(TaskStateError::UnknownTask)?;
        let compatible = match fact.state {
            TaskHandleState::Discharged => matches!(
                task.handle_state,
                TaskHandleState::Joined | TaskHandleState::Detached | TaskHandleState::Discharged
            ),
            expected => task.handle_state == expected,
        };
        if task.handle_id != handle || task.handle_name != fact.handle || !compatible {
            return Err(TaskStateError::AnalyzerOwnershipMismatch);
        }
        Ok(())
    }

    fn validate_control_selection(
        &self,
        owner_task_id: ProtocolIdentity,
        control: &TaskControlSite,
        handles: &[DynamicTaskHandleIdentity],
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        if owner_task_id.kind() != IdentityKind::Task
            || !self.task_paths.contains_key(&owner_task_id)
        {
            return Err(TaskStateError::InvalidTaskIdentity);
        }
        if handles.len() != control.handles.len() {
            return Err(TaskStateError::HandleSelectionMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut task_ids = Vec::with_capacity(handles.len());
        for (handle, static_name) in handles.iter().zip(&control.handles) {
            if !seen.insert(*handle) {
                return Err(TaskStateError::DuplicateHandle);
            }
            if handle.owner() != owner_task_id {
                return Err(TaskStateError::ForeignHandle);
            }
            let task = self
                .tasks
                .get(&handle.child())
                .ok_or(TaskStateError::UnknownTask)?;
            if task.handle_id != *handle
                || task.handle_name != *static_name
                || task.workflow != *control.id.workflow()
            {
                return Err(TaskStateError::HandleSelectionMismatch);
            }
            if !task.handle_visible {
                return Err(TaskStateError::HandleNotVisible);
            }
            if task.handle_state != TaskHandleState::Attached {
                return Err(TaskStateError::ConsumedHandle);
            }
            task_ids.push(task.task_id);
        }
        Ok(task_ids)
    }

    /// Replaces one mutable child-local capture without changing its parent copy.
    pub fn replace_capture(
        &mut self,
        task_id: ProtocolIdentity,
        name: &str,
        path: &[ValuePathSegment],
        replacement: &LogicalValue,
        limits: ValueLimits,
    ) -> Result<LogicalValue, TaskStateError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or(TaskStateError::UnknownTask)?;
        let capture = task
            .captures
            .get_mut(name)
            .ok_or(TaskStateError::UnknownCapture)?;
        if !capture.mutable {
            return Err(TaskStateError::ImmutableCapture);
        }
        let value = capture
            .value
            .replaced(path, replacement, limits)
            .map_err(TaskStateError::CaptureValue)?;
        capture.value = value.clone();
        Ok(value)
    }

    /// Applies one idempotent executor-abort result to a live task.
    pub fn apply_abort_result(
        &mut self,
        task_id: ProtocolIdentity,
        result: TaskAbortResultV1,
    ) -> Result<ExecutorAbortResultKind, TaskStateError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or(TaskStateError::UnknownTask)?;
        if !matches!(
            task.status,
            ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
        ) {
            return Ok(ExecutorAbortResultKind::AlreadySettled);
        }
        let kind = result.kind();
        if let TaskAbortResultV1::Stopped = result {
            let reason = self
                .cancellation_reasons
                .entry(task_id)
                .or_insert_with(|| Arc::from("executor-abort"))
                .clone();
            self.submitting_by_parent.remove(&task.parent_task_id);
            task.handle_visible = true;
            task.status = ConcurrentTaskStatusV1::Cancelled(reason);
        }
        Ok(kind)
    }

    /// Returns all submitting or running child tasks in stable identity order.
    #[must_use]
    pub fn pending_task_ids(&self) -> Vec<ProtocolIdentity> {
        self.tasks
            .iter()
            .filter_map(|(task_id, task)| {
                matches!(
                    task.status,
                    ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                )
                .then_some(*task_id)
            })
            .collect()
    }
}

/// One scheduler-selected transition from a child instance of the shared machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledMachineStepV1 {
    /// Stable identity of the task that produced this step.
    pub task_id: ProtocolIdentity,
    /// Exact shared-machine result for this scheduling turn.
    pub step: MachineStep,
}

/// Execution-scoped round-robin scheduler over the shared explicit-frame machine.
#[derive(Debug)]
pub struct ConcurrentSchedulerV1 {
    state: ConcurrentTaskStateV1,
    machines: BTreeMap<ProtocolIdentity, Machine>,
    runnable: VecDeque<ProtocolIdentity>,
}

impl ConcurrentSchedulerV1 {
    /// Creates an idle scheduler around execution-scoped task state.
    #[must_use]
    pub fn new(state: ConcurrentTaskStateV1) -> Self {
        Self {
            state,
            machines: BTreeMap::new(),
            runnable: VecDeque::new(),
        }
    }

    /// Returns the scheduler-owned language task state.
    #[must_use]
    pub const fn state(&self) -> &ConcurrentTaskStateV1 {
        &self.state
    }

    /// Records one child before an executor submission is attempted.
    pub fn create_child(
        &mut self,
        sessions: &mut LogicalSessionRegistryV1,
        request: TaskCreationRequestV1,
        limits: ValueLimits,
    ) -> Result<TaskCreationV1, TaskStateError> {
        self.state.create_child(sessions, request, limits)
    }

    /// Establishes the child's creation-time fork session before child hook construction.
    pub async fn establish_child_session(
        &self,
        sessions: &LogicalSessionRegistryV1,
        establisher: &mut SessionEstablisher<'_>,
        task_id: ProtocolIdentity,
    ) -> Result<(), SessionEstablishmentError> {
        let session_id = self
            .state
            .task(task_id)
            .ok_or(SessionEstablishmentError::InvalidRequest)?
            .base_session_id();
        let session = sessions
            .get(session_id)
            .ok_or(SessionEstablishmentError::InvalidRequest)?;
        establisher
            .establish(self.state.execution_id(), session)
            .await
    }

    /// Snapshots all foreground, attached, and detached work for shutdown coordination.
    #[must_use]
    pub fn shutdown_cohort(&self) -> ConcurrentShutdownCohortV1 {
        self.state.shutdown_cohort()
    }

    /// Resolves submission with either the child shared-machine instance or its failure.
    pub fn resolve_submission(
        &mut self,
        task_id: ProtocolIdentity,
        result: Result<Machine, HostError>,
    ) -> Result<(), TaskStateError> {
        match result {
            Ok(machine) => {
                if machine.execution_id() != self.state.execution_id
                    || machine.is_execution_foreground()
                    || self.machines.contains_key(&task_id)
                {
                    return Err(TaskStateError::InvalidTaskMachine);
                }
                self.state.resolve_submission(task_id, Ok(()))?;
                if matches!(
                    self.state.task(task_id).map(ConcurrentTaskRecordV1::status),
                    Some(ConcurrentTaskStatusV1::Running)
                ) {
                    self.machines.insert(task_id, machine);
                    self.runnable.push_back(task_id);
                }
            }
            Err(error) => self.state.resolve_submission(task_id, Err(error))?,
        }
        Ok(())
    }

    /// Records execution cancellation and signals every live shared-machine task.
    pub fn cancel_execution(
        &mut self,
        reason: impl Into<Arc<str>>,
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        let affected = self.state.cancel_execution(reason)?;
        for task_id in &affected {
            if let Some(machine) = self.machines.get_mut(task_id)
                && let Some(reason) = self.state.task_cancellation_reason(*task_id)
            {
                let _ = machine.cancel(Arc::<str>::from(reason));
            }
        }
        Ok(affected)
    }

    /// Records parent failure cancellation through attached descendants only.
    pub fn cancel_task_tree(
        &mut self,
        task_id: ProtocolIdentity,
        reason: impl Into<Arc<str>>,
    ) -> Result<Vec<ProtocolIdentity>, TaskStateError> {
        let affected = self.state.cancel_task_tree(task_id, reason)?;
        for affected_id in &affected {
            if let Some(machine) = self.machines.get_mut(affected_id)
                && let Some(reason) = self.state.task_cancellation_reason(*affected_id)
            {
                let _ = machine.cancel(Arc::<str>::from(reason));
            }
        }
        Ok(affected)
    }

    /// Applies one idempotent executor-abort result and drops stopped machine ownership.
    pub fn apply_abort_result(
        &mut self,
        task_id: ProtocolIdentity,
        result: TaskAbortResultV1,
    ) -> Result<ExecutorAbortResultKind, TaskStateError> {
        let kind = self.state.apply_abort_result(task_id, result)?;
        if kind == ExecutorAbortResultKind::Stopped {
            self.machines.remove(&task_id);
            self.runnable.retain(|candidate| *candidate != task_id);
        }
        Ok(kind)
    }

    /// Returns a suspended child machine for host-result completion.
    pub fn machine_mut(&mut self, task_id: ProtocolIdentity) -> Option<&mut Machine> {
        self.machines.get_mut(&task_id)
    }

    /// Re-enqueues a running task after a host wait or explicit yield resolves.
    pub fn schedule(&mut self, task_id: ProtocolIdentity) -> Result<(), TaskStateError> {
        let task = self
            .state
            .task(task_id)
            .ok_or(TaskStateError::UnknownTask)?;
        let machine = self
            .machines
            .get(&task_id)
            .ok_or(TaskStateError::InvalidTaskMachine)?;
        if !matches!(task.status(), ConcurrentTaskStatusV1::Running)
            || machine.status() != MachineStatus::Running
            || self.runnable.contains(&task_id)
        {
            return Err(TaskStateError::InvalidTransition);
        }
        self.runnable.push_back(task_id);
        Ok(())
    }

    /// Resolves one cooperative yield and re-enqueues that child.
    pub fn resume_after_yield(&mut self, task_id: ProtocolIdentity) -> Result<(), TaskStateError> {
        let machine = self
            .machines
            .get_mut(&task_id)
            .ok_or(TaskStateError::InvalidTaskMachine)?;
        if !machine.resume_after_yield() {
            return Err(TaskStateError::InvalidTransition);
        }
        self.schedule(task_id)
    }

    /// Advances the next runnable task once and rotates remaining runnable work.
    pub fn step_next(&mut self) -> Result<Option<ScheduledMachineStepV1>, TaskStateError> {
        let Some(task_id) = self.runnable.pop_front() else {
            return Ok(None);
        };
        let step = self
            .machines
            .get_mut(&task_id)
            .ok_or(TaskStateError::InvalidTaskMachine)?
            .step();

        match &step {
            MachineStep::Transition(MachineLabel::TaskSettled(outcome))
            | MachineStep::Complete(outcome) => {
                self.state.settle(task_id, outcome.clone())?;
                self.machines.remove(&task_id);
            }
            MachineStep::Transition(_) => {
                if self.machines.get(&task_id).is_some_and(|machine| {
                    machine.status() == MachineStatus::Running || machine.outcome().is_some()
                }) {
                    self.runnable.push_back(task_id);
                }
            }
            MachineStep::WaitingSessionScope(_)
            | MachineStep::WaitingOperation(_)
            | MachineStep::YieldRequired => {}
        }

        Ok(Some(ScheduledMachineStepV1 { task_id, step }))
    }
}

/// Failure to construct or advance concurrent task state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskStateError {
    /// The configured cumulative task limit is zero.
    InvalidTaskLimit,
    /// Creating another child would exceed or overflow the cumulative limit.
    TaskCountLimit,
    /// An execution identity has the wrong kind.
    InvalidExecutionIdentity,
    /// A task identity has the wrong kind.
    InvalidTaskIdentity,
    /// A source spawn declares an empty lexical task-handle name.
    InvalidHandleName,
    /// A logical-session identity has the wrong kind.
    InvalidSessionIdentity,
    /// The parent task is outside this execution's known task tree.
    UnknownParentTask,
    /// The requested child task is absent.
    UnknownTask,
    /// The parent cannot create or run another source transition until submission resolves.
    ParentSuspended,
    /// A submitted machine is absent, belongs to another execution, or owns root labels.
    InvalidTaskMachine,
    /// One derived identity collides with existing execution state.
    IdentityCollision,
    /// Identity derivation violated its internal typed invariant.
    IdentityInvariant,
    /// One capture has an empty source name.
    InvalidCaptureName,
    /// One analyzer-selected capture name is repeated.
    DuplicateCapture,
    /// A captured value differs from its analyzer-declared type.
    CaptureType,
    /// The selected capture is absent.
    UnknownCapture,
    /// The selected capture is immutable.
    ImmutableCapture,
    /// A copied or replacement value violates its configured limits.
    CaptureValue(ValueError),
    /// A successful child result differs from its analyzer-declared type.
    ResultType,
    /// A join or detach request does not match its analyzer task-control form.
    InvalidTaskControl,
    /// One dynamic handle is selected more than once in an atomic consumption.
    DuplicateHandle,
    /// A task attempts to consume a handle owned by another Gantry task.
    ForeignHandle,
    /// The selected handle has not been exposed after submission resolution.
    HandleNotVisible,
    /// Dynamic handles differ from the analyzer's exact source-ordered selection.
    HandleSelectionMismatch,
    /// A joined or detached handle cannot be consumed again.
    ConsumedHandle,
    /// Retained ownership-change evidence no longer matches scheduler state.
    InvalidOwnershipEvidence,
    /// Runtime ownership differs from the analyzer's attached or consumed fact.
    AnalyzerOwnershipMismatch,
    /// A supposedly valid join mixes Unit and value-producing task results.
    JoinResultType,
    /// Constructing the analyzer-selected aggregate exceeded value limits.
    JoinValue(ValueError),
    /// Automatic fork-session construction failed.
    Session(SessionError),
    /// A cancellation reason must be nonempty.
    InvalidCancellationReason,
    /// Cancellation prevents creation of more child work.
    TaskCancelled,
    /// Foreground completion was already fixed.
    ForegroundAlreadyFixed,
    /// Foreground completion requires every attached descendant to settle.
    AttachedTasksPending,
    /// Terminal completion requires a fixed foreground outcome.
    ForegroundUnknown,
    /// Detached tasks must settle before terminal completion.
    DetachedTasksPending,
    /// Terminal completion was already fixed.
    TerminalAlreadyFixed,
    /// The requested status transition is not defined.
    InvalidTransition,
}

fn machine_failure_category(code: crate::RuntimeCode) -> RuntimeErrorCategory {
    match code {
        crate::RuntimeCode::Operation(category) => category,
        crate::RuntimeCode::UnsupportedEffect | crate::RuntimeCode::InternalInvariant => {
            RuntimeErrorCategory::InternalInvariantFailure
        }
        crate::RuntimeCode::Deterministic(_)
        | crate::RuntimeCode::DeterministicTransitionBudget
        | crate::RuntimeCode::OperationBudget
        | crate::RuntimeCode::LoopIterationBudget
        | crate::RuntimeCode::LoopLimitExhausted => {
            RuntimeErrorCategory::DeterministicEvaluationFailure
        }
    }
}

fn task_path_frame(workflow: &CanonicalPath, site: &StructuralPosition, occurrence: u64) -> String {
    format!(
        "spawn:{}:{}:{occurrence}",
        workflow.as_str(),
        site.components()
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".")
    )
}

fn task_identity_key(execution: ProtocolIdentity, path: &[Arc<str>]) -> Vec<u8> {
    let mut output = String::from("{\"execution\":");
    push_json_string(&mut output, &execution.to_string());
    output.push_str(",\"path\":[");
    for (index, frame) in path.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, frame);
    }
    output.push_str("]}");
    output.into_bytes()
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::numeric::GantryInt;
    use gantry_core::portable::{
        ExecutorAbortResultKind, IdentityKind, RuntimeErrorCategory, TaskHandleState,
        TaskStatusKind, TerminalOnlyCategory,
    };
    use gantry_core::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};
    use gantry_host::contracts::HostError;
    use gantry_ir::generated::TaskControlSiteKind;
    use gantry_ir::{
        CanonicalPath, EffectSet, OwnershipFact, StaticSiteId, StructuralPosition, TaskControlSite,
        TypeDescriptor,
    };

    use super::{
        ConcurrentSchedulerV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
        ConcurrentTerminalCategoryV1, JoinResolutionV1, JoinStartV1, TaskAbortResultV1,
        TaskCaptureV1, TaskCreationRequestV1, TaskJoinMemberFailureKindV1, TaskStateError,
    };
    use crate::{
        CanonicalTranscriptV1, Instruction, InstructionKind, LogicalSessionRegistryV1, Machine,
        MachineLabel, MachineLimits, MachineProgram, MachineStep, Parameter, SessionCreationModeV1,
        Workflow,
    };

    #[test]
    fn cumulative_task_limit_rejects_before_identity_session_or_state_creation() {
        let (mut state, mut sessions, root_task, root_session) = fixture(2);
        let first = state.create_child(
            &mut sessions,
            request(root_task, root_session, 0, Vec::new()),
            DEFAULT_VALUE_LIMITS,
        );
        assert!(first.is_ok());
        let first = first.unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
        state
            .resolve_submission(first.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
        let session_count = sessions_len(&sessions);
        assert_eq!(
            state.create_child(
                &mut sessions,
                request(root_task, root_session, 1, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            ),
            Err(TaskStateError::TaskCountLimit)
        );
        assert_eq!(state.created_task_count(), 2);
        assert_eq!(sessions_len(&sessions), session_count);

        state.created_tasks = u64::MAX;
        state.maximum_tasks = u64::MAX;
        assert_eq!(
            state.create_child(
                &mut sessions,
                request(root_task, root_session, 2, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            ),
            Err(TaskStateError::TaskCountLimit)
        );
    }

    #[test]
    fn task_creation_fixes_stable_identities_sessions_and_isolated_captures() {
        let (mut state, mut sessions, root_task, root_session) = fixture(4);
        let original = LogicalValue::boolean(false);
        let capture = TaskCaptureV1::new(
            Arc::from("flag"),
            TypeDescriptor::BOOL,
            true,
            &original,
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("capture failed: {error:?}"));
        let created = state
            .create_child(
                &mut sessions,
                request(root_task, root_session, 0, vec![capture]),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        let record = state
            .task(created.task_id)
            .unwrap_or_else(|| panic!("created task missing"));
        assert_eq!(record.handle_name(), "child");
        assert_eq!(record.status().kind(), TaskStatusKind::Submitting);
        assert!(!record.handle_is_visible());
        assert!(state.parent_is_suspended(root_task));
        assert_eq!(record.handle_id(), created.handle_id);
        assert_eq!(record.base_session_id(), created.base_session_id);
        assert_eq!(record.task_path(), [Arc::from("spawn:crate::main:0:0")]);
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
        assert!(matches!(original.view(), LogicalValueView::Bool(false)));
        assert!(matches!(
            state
                .task(created.task_id)
                .and_then(|task| task.captures().get("flag"))
                .map(TaskCaptureV1::value)
                .map(LogicalValue::view),
            Some(LogicalValueView::Bool(true))
        ));
    }

    #[test]
    fn submission_failure_settles_the_same_child_and_exposes_its_handle() {
        let (mut state, mut sessions, root_task, root_session) = fixture(2);
        let created = state
            .create_child(
                &mut sessions,
                request(root_task, root_session, 0, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        state
            .resolve_submission(
                created.task_id,
                Err(HostError {
                    code: Arc::from("queue-closed"),
                    protected_diagnostic: Some(Arc::from("executor-1")),
                }),
            )
            .unwrap_or_else(|error| panic!("submission resolution failed: {error:?}"));
        assert!(!state.parent_is_suspended(root_task));
        let record = state
            .task(created.task_id)
            .unwrap_or_else(|| panic!("created task missing"));
        assert!(record.handle_is_visible());
        assert_eq!(record.handle_id(), created.handle_id);
        assert!(matches!(
            record.status(),
            ConcurrentTaskStatusV1::Failed(failure)
                if failure.category == RuntimeErrorCategory::ExecutorFailure
                    && failure.code.as_ref() == "queue-closed"
        ));
        assert_eq!(
            state.resolve_submission(created.task_id, Ok(())),
            Err(TaskStateError::InvalidTransition)
        );
    }

    #[test]
    fn scheduler_round_robins_shared_machine_tasks_and_settles_once() {
        let (state, mut sessions, root_task, root_session) = fixture(3);
        let execution = state.execution_id();
        let mut scheduler = ConcurrentSchedulerV1::new(state);
        let first = scheduler
            .create_child(
                &mut sessions,
                request(root_task, root_session, 0, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
        scheduler
            .resolve_submission(first.task_id, Ok(child_machine(execution, root_session)))
            .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
        let second = scheduler
            .create_child(
                &mut sessions,
                request(root_task, root_session, 1, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
        scheduler
            .resolve_submission(second.task_id, Ok(child_machine(execution, root_session)))
            .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));

        let first_step = scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("first step failed: {error:?}"))
            .unwrap_or_else(|| panic!("first task was not runnable"));
        let second_step = scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("second step failed: {error:?}"))
            .unwrap_or_else(|| panic!("second task was not runnable"));
        assert_eq!(first_step.task_id, first.task_id);
        assert_eq!(second_step.task_id, second.task_id);
        assert!(matches!(
            first_step.step,
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
        assert!(matches!(
            second_step.step,
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));

        for expected in [first.task_id, second.task_id] {
            let settlement = scheduler
                .step_next()
                .unwrap_or_else(|error| panic!("settlement failed: {error:?}"))
                .unwrap_or_else(|| panic!("settlement task was not runnable"));
            assert_eq!(settlement.task_id, expected);
            assert!(matches!(
                settlement.step,
                MachineStep::Transition(MachineLabel::TaskSettled(_))
            ));
            assert!(matches!(
                scheduler.state().task(expected).map(|task| task.status()),
                Some(ConcurrentTaskStatusV1::Succeeded(_))
            ));
        }
        assert_eq!(
            scheduler
                .step_next()
                .unwrap_or_else(|error| panic!("idle step failed: {error:?}")),
            None
        );
    }

    #[test]
    fn scheduler_preserves_failure_then_task_settlement_order() {
        let (state, mut sessions, root_task, root_session) = fixture(2);
        let execution = state.execution_id();
        let mut scheduler = ConcurrentSchedulerV1::new(state);
        let created = scheduler
            .create_child(
                &mut sessions,
                request(root_task, root_session, 0, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        scheduler
            .resolve_submission(
                created.task_id,
                Ok(failing_child_machine(execution, root_session)),
            )
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));

        let failure = scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("failure step failed: {error:?}"))
            .unwrap_or_else(|| panic!("failed task was not runnable"));
        assert!(matches!(
            failure.step,
            MachineStep::Transition(MachineLabel::Failure(_))
        ));
        assert!(matches!(
            scheduler
                .state()
                .task(created.task_id)
                .map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Running)
        ));

        let settlement = scheduler
            .step_next()
            .unwrap_or_else(|error| panic!("settlement step failed: {error:?}"))
            .unwrap_or_else(|| panic!("failed task settlement was not runnable"));
        assert!(matches!(
            settlement.step,
            MachineStep::Transition(MachineLabel::TaskSettled(_))
        ));
        assert!(matches!(
            scheduler
                .state()
                .task(created.task_id)
                .map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Failed(_))
        ));
    }

    #[test]
    fn successful_settlement_requires_the_declared_child_result_type() {
        let (mut state, mut sessions, root_task, root_session) = fixture(2);
        let created = state
            .create_child(
                &mut sessions,
                request(root_task, root_session, 0, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        state
            .resolve_submission(created.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        assert_eq!(
            state.settle(
                created.task_id,
                crate::MachineOutcome::Succeeded(LogicalValue::boolean(true)),
            ),
            Err(TaskStateError::ResultType)
        );
        assert!(matches!(
            state.task(created.task_id).map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Running)
        ));
    }

    #[test]
    fn named_join_consumes_atomically_before_waiting_and_rejects_reuse() {
        let (mut state, mut sessions, root_task, root_session) = fixture(3);
        let first = state
            .create_child(
                &mut sessions,
                typed_request(root_task, root_session, "first", 0, TypeDescriptor::INT),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
        state
            .resolve_submission(first.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
        let second = state
            .create_child(
                &mut sessions,
                typed_request(root_task, root_session, "second", 1, TypeDescriptor::INT),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
        state
            .resolve_submission(second.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));
        let join = task_control(TaskControlSiteKind::Join, 4, &["first", "second"]);

        assert_eq!(
            state.begin_join(root_task, &join, &[second.handle_id, first.handle_id]),
            Err(TaskStateError::HandleSelectionMismatch)
        );
        assert_eq!(
            state.task(first.task_id).map(|task| task.handle_state()),
            Some(TaskHandleState::Attached)
        );
        let ownership = match state
            .begin_join(root_task, &join, &[first.handle_id, second.handle_id])
            .unwrap_or_else(|error| panic!("join start failed: {error:?}"))
        {
            JoinStartV1::Started(ownership) => ownership,
            JoinStartV1::Empty => panic!("named join unexpectedly reduced as empty"),
        };
        assert_eq!(
            ownership
                .members
                .iter()
                .map(|member| member.task_id)
                .collect::<Vec<_>>(),
            vec![first.task_id, second.task_id]
        );
        assert_eq!(
            ownership.members[0].task_path.as_ref(),
            [Arc::from("spawn:crate::main:0:0")]
        );
        assert!(ownership.members.iter().all(|member| {
            state
                .task(member.task_id)
                .is_some_and(|task| task.handle_state() == TaskHandleState::Joined)
        }));
        assert_eq!(
            state.begin_join(root_task, &join, &[first.handle_id, second.handle_id]),
            Err(TaskStateError::ConsumedHandle)
        );

        state
            .settle(second.task_id, crate::MachineOutcome::Succeeded(integer(2)))
            .unwrap_or_else(|error| panic!("second settlement failed: {error:?}"));
        assert_eq!(
            state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
            Ok(JoinResolutionV1::Pending(vec![first.task_id]))
        );
        state
            .settle(first.task_id, crate::MachineOutcome::Succeeded(integer(1)))
            .unwrap_or_else(|error| panic!("first settlement failed: {error:?}"));
        let expected = LogicalValue::list(vec![integer(1), integer(2)], DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("expected list failed: {error:?}"));
        assert_eq!(
            state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
            Ok(JoinResolutionV1::Succeeded(expected))
        );

        let joined = OwnershipFact {
            handle: Arc::from("first"),
            state: TaskHandleState::Joined,
            source: source_span(),
        };
        state
            .validate_analyzer_ownership(first.handle_id, &joined)
            .unwrap_or_else(|error| panic!("joined ownership mismatch: {error:?}"));
    }

    #[test]
    fn joinall_is_all_settled_orders_failures_and_handles_zero_members() {
        let (mut state, mut sessions, root_task, root_session) = fixture(3);
        let first = state
            .create_child(
                &mut sessions,
                typed_request(root_task, root_session, "first", 0, TypeDescriptor::UNIT),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("first task creation failed: {error:?}"));
        state
            .resolve_submission(first.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("first submission failed: {error:?}"));
        let second = state
            .create_child(
                &mut sessions,
                typed_request(root_task, root_session, "second", 1, TypeDescriptor::UNIT),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("second task creation failed: {error:?}"));
        state
            .resolve_submission(second.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("second submission failed: {error:?}"));
        let joinall = task_control(TaskControlSiteKind::JoinAll, 5, &["first", "second"]);
        let ownership = match state
            .begin_join(root_task, &joinall, &[first.handle_id, second.handle_id])
            .unwrap_or_else(|error| panic!("joinall start failed: {error:?}"))
        {
            JoinStartV1::Started(ownership) => ownership,
            JoinStartV1::Empty => panic!("nonempty joinall unexpectedly reduced as empty"),
        };

        state
            .settle(
                second.task_id,
                crate::MachineOutcome::Cancelled(Arc::from("second-cancelled")),
            )
            .unwrap_or_else(|error| panic!("second cancellation failed: {error:?}"));
        assert_eq!(
            state.resolve_join(&ownership, DEFAULT_VALUE_LIMITS),
            Ok(JoinResolutionV1::Pending(vec![first.task_id]))
        );
        state
            .settle(
                first.task_id,
                crate::MachineOutcome::Cancelled(Arc::from("first-cancelled")),
            )
            .unwrap_or_else(|error| panic!("first cancellation failed: {error:?}"));
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
            vec![first.task_id, second.task_id]
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

        let empty = task_control(TaskControlSiteKind::JoinAll, 6, &[]);
        assert_eq!(
            state.begin_join(root_task, &empty, &[]),
            Ok(JoinStartV1::Empty)
        );
    }

    #[test]
    fn detach_transfers_ownership_without_dropping_running_work() {
        let (mut state, mut sessions, root_task, root_session) = fixture(2);
        let created = state
            .create_child(
                &mut sessions,
                typed_request(
                    root_task,
                    root_session,
                    "background",
                    0,
                    TypeDescriptor::INT,
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        state
            .resolve_submission(created.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        let detach = task_control(TaskControlSiteKind::Detach, 7, &["background"]);
        let ownership = state
            .detach(root_task, &detach, created.handle_id)
            .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
        assert_eq!(ownership.disposition, TaskHandleState::Detached);
        assert_eq!(ownership.members.len(), 1);
        assert_eq!(ownership.members[0].task_id, created.task_id);
        assert_eq!(
            ownership.members[0].task_path.as_ref(),
            [Arc::from("spawn:crate::main:0:0")]
        );
        assert!(matches!(
            state.task(created.task_id),
            Some(task)
                if task.handle_state() == TaskHandleState::Detached
                    && matches!(task.status(), ConcurrentTaskStatusV1::Running)
        ));
        assert_eq!(
            state.detach(root_task, &detach, created.handle_id),
            Err(TaskStateError::ConsumedHandle)
        );

        let detached = OwnershipFact {
            handle: Arc::from("background"),
            state: TaskHandleState::Detached,
            source: source_span(),
        };
        state
            .validate_analyzer_ownership(created.handle_id, &detached)
            .unwrap_or_else(|error| panic!("detached ownership mismatch: {error:?}"));
        let discharged = OwnershipFact {
            handle: Arc::from("background"),
            state: TaskHandleState::Discharged,
            source: source_span(),
        };
        state
            .validate_analyzer_ownership(created.handle_id, &discharged)
            .unwrap_or_else(|error| panic!("discharged ownership mismatch: {error:?}"));
        let joined = OwnershipFact {
            handle: Arc::from("background"),
            state: TaskHandleState::Joined,
            source: source_span(),
        };
        assert_eq!(
            state.validate_analyzer_ownership(created.handle_id, &joined),
            Err(TaskStateError::AnalyzerOwnershipMismatch)
        );
    }

    #[test]
    fn cancellation_propagates_through_attached_descendants_but_not_detached_work() {
        let (mut state, mut sessions, root_task, root_session) = fixture(4);
        let attached = state
            .create_child(
                &mut sessions,
                typed_request(root_task, root_session, "attached", 0, TypeDescriptor::UNIT),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("attached task creation failed: {error:?}"));
        state
            .resolve_submission(attached.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("attached submission failed: {error:?}"));
        let detached = state
            .create_child(
                &mut sessions,
                typed_request(root_task, root_session, "detached", 1, TypeDescriptor::UNIT),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("detached task creation failed: {error:?}"));
        state
            .resolve_submission(detached.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("detached submission failed: {error:?}"));
        let detach = task_control(TaskControlSiteKind::Detach, 8, &["detached"]);
        state
            .detach(root_task, &detach, detached.handle_id)
            .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
        let grandchild = state
            .create_child(
                &mut sessions,
                typed_request(
                    attached.task_id,
                    attached.base_session_id,
                    "grandchild",
                    0,
                    TypeDescriptor::UNIT,
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("grandchild creation failed: {error:?}"));
        state
            .resolve_submission(grandchild.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("grandchild submission failed: {error:?}"));

        let affected = state
            .cancel_task_tree(root_task, "parent-failed")
            .unwrap_or_else(|error| panic!("task cancellation failed: {error:?}"));
        assert_eq!(affected, [root_task, attached.task_id, grandchild.task_id]);
        assert_eq!(
            state.task_cancellation_reason(attached.task_id),
            Some("parent-failed")
        );
        assert_eq!(state.task_cancellation_reason(detached.task_id), None);
        assert_eq!(
            state
                .cancel_task_tree(root_task, "later-reason")
                .unwrap_or_else(|error| panic!("repeat cancellation failed: {error:?}")),
            []
        );
        assert_eq!(
            state.task_cancellation_reason(root_task),
            Some("parent-failed")
        );

        state
            .settle(
                attached.task_id,
                crate::MachineOutcome::Succeeded(LogicalValue::unit()),
            )
            .unwrap_or_else(|error| panic!("attached settlement failed: {error:?}"));
        assert!(matches!(
            state.task(attached.task_id).map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Cancelled(reason))
                if reason.as_ref() == "parent-failed"
        ));
        assert!(matches!(
            state.task(detached.task_id).map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Running)
        ));
    }

    #[test]
    fn detached_failure_does_not_replace_foreground_but_selects_terminal_category() {
        let (mut state, mut sessions, root_task, root_session) = fixture(2);
        let detached = state
            .create_child(
                &mut sessions,
                typed_request(
                    root_task,
                    root_session,
                    "background",
                    0,
                    TypeDescriptor::UNIT,
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("detached task creation failed: {error:?}"));
        state
            .resolve_submission(
                detached.task_id,
                Err(HostError {
                    code: Arc::from("executor-stopped"),
                    protected_diagnostic: None,
                }),
            )
            .unwrap_or_else(|error| panic!("submission failure failed: {error:?}"));
        let detach = task_control(TaskControlSiteKind::Detach, 9, &["background"]);
        state
            .detach(root_task, &detach, detached.handle_id)
            .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
        let foreground = crate::MachineOutcome::Succeeded(LogicalValue::unit());
        state
            .complete_foreground(foreground.clone())
            .unwrap_or_else(|error| panic!("foreground completion failed: {error:?}"));
        let terminal = state
            .complete_terminal()
            .unwrap_or_else(|error| panic!("terminal completion failed: {error:?}"));

        assert_eq!(terminal.foreground, foreground);
        assert_eq!(
            terminal.category,
            ConcurrentTerminalCategoryV1::TerminalOnly(TerminalOnlyCategory::DetachedTaskFailure)
        );
        assert_eq!(terminal.detached_failures.len(), 1);
        assert_eq!(terminal.detached_failures[0].task_id, detached.task_id);
        assert_eq!(
            terminal.detached_failures[0].failure.category,
            RuntimeErrorCategory::ExecutorFailure
        );
        assert_eq!(state.foreground_outcome(), Some(&foreground));
    }

    #[test]
    fn executor_abort_is_idempotent_and_preserves_the_first_cancellation_reason() {
        let (mut state, mut sessions, root_task, root_session) = fixture(2);
        let created = state
            .create_child(
                &mut sessions,
                request(root_task, root_session, 0, Vec::new()),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        state
            .resolve_submission(created.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        state
            .cancel_task_tree(root_task, "shutdown")
            .unwrap_or_else(|error| panic!("cancellation failed: {error:?}"));

        assert_eq!(
            state
                .apply_abort_result(
                    created.task_id,
                    TaskAbortResultV1::Failed(HostError {
                        code: Arc::from("abort-failed"),
                        protected_diagnostic: None,
                    }),
                )
                .unwrap_or_else(|error| panic!("failed abort result failed: {error:?}")),
            ExecutorAbortResultKind::Failed
        );
        assert!(matches!(
            state.task(created.task_id).map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Running)
        ));
        assert_eq!(
            state
                .apply_abort_result(created.task_id, TaskAbortResultV1::Stopped)
                .unwrap_or_else(|error| panic!("stopped abort failed: {error:?}")),
            ExecutorAbortResultKind::Stopped
        );
        assert!(matches!(
            state.task(created.task_id).map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Cancelled(reason)) if reason.as_ref() == "shutdown"
        ));
        assert_eq!(
            state
                .apply_abort_result(created.task_id, TaskAbortResultV1::Stopped)
                .unwrap_or_else(|error| panic!("repeat abort failed: {error:?}")),
            ExecutorAbortResultKind::AlreadySettled
        );
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
        let root_task = ProtocolIdentity::derive(IdentityKind::Task, b"{\"root\":true}")
            .unwrap_or_else(|error| panic!("root task failed: {error}"));
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

    fn request(
        parent_task_id: ProtocolIdentity,
        parent_session_id: ProtocolIdentity,
        spawn_occurrence: u64,
        captures: Vec<TaskCaptureV1>,
    ) -> TaskCreationRequestV1 {
        let mut request = typed_request(
            parent_task_id,
            parent_session_id,
            "child",
            spawn_occurrence,
            TypeDescriptor::UNIT,
        );
        request.captures = captures;
        request
    }

    fn typed_request(
        parent_task_id: ProtocolIdentity,
        parent_session_id: ProtocolIdentity,
        handle_name: &str,
        spawn_occurrence: u64,
        result_type: TypeDescriptor,
    ) -> TaskCreationRequestV1 {
        TaskCreationRequestV1 {
            parent_task_id,
            handle_name: Arc::from(handle_name),
            workflow: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("path failed: {error}")),
            spawn_site: StructuralPosition::new(vec![0])
                .unwrap_or_else(|error| panic!("site failed: {error}")),
            spawn_occurrence,
            result_type,
            captures: Vec::new(),
            inherited_agent: Some(Arc::from("writer")),
            parent_session_id,
        }
    }

    fn task_control(kind: TaskControlSiteKind, position: u64, handles: &[&str]) -> TaskControlSite {
        let workflow = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("path failed: {error}"));
        let position = StructuralPosition::new(vec![position])
            .unwrap_or_else(|error| panic!("site failed: {error}"));
        TaskControlSite {
            id: StaticSiteId::new(workflow, position),
            kind,
            handles: handles.iter().map(|handle| Arc::from(*handle)).collect(),
            source: source_span(),
        }
    }

    fn source_span() -> SourceSpan {
        let limits = SourceLimits::new(1, 64, 64, 1, 1)
            .unwrap_or_else(|error| panic!("source limits failed: {error:?}"));
        let mut builder = SourceSnapshotBuilder::new(limits);
        let id = builder
            .add_file("main.gnt", b"joinall()")
            .unwrap_or_else(|error| panic!("source fixture failed: {error:?}"));
        let snapshot = builder.finish();
        let record = snapshot
            .get(&id)
            .unwrap_or_else(|| panic!("source fixture record missing"));
        SourceSpan::new(
            record,
            ByteSpan::new(0, 1).unwrap_or_else(|error| panic!("span failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("source span failed: {error:?}"))
    }

    fn integer(value: i64) -> LogicalValue {
        LogicalValue::integer(
            GantryInt::new(value).unwrap_or_else(|| panic!("fixture integer is out of range")),
        )
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }

    fn sessions_len(sessions: &LogicalSessionRegistryV1) -> usize {
        sessions.len()
    }

    fn child_machine(execution: ProtocolIdentity, session: ProtocolIdentity) -> Machine {
        let root = CanonicalPath::new("crate::child")
            .unwrap_or_else(|error| panic!("child path failed: {error}"));
        let program = MachineProgram::new(vec![Workflow {
            path: root.clone(),
            parameters: Vec::<Parameter>::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("child site failed: {error}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("child site failed: {error}")),
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

    fn failing_child_machine(execution: ProtocolIdentity, session: ProtocolIdentity) -> Machine {
        let root = CanonicalPath::new("crate::failed_child")
            .unwrap_or_else(|error| panic!("child path failed: {error}"));
        let program = MachineProgram::new(vec![Workflow {
            path: root.clone(),
            parameters: Vec::<Parameter>::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![Instruction {
                site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("child site failed: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Pop,
            }],
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
}
