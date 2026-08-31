//! Concurrent task creation and scheduler-owned state.
//!
//! This module records language task state independently of executor handles.
//! The scheduler added by the concurrent profile can therefore create and
//! settle one task identity without deriving semantics from adapter timing.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, RuntimeErrorCategory, TaskHandleState, TaskStatusKind};
use gantry_core::value::{LogicalValue, ValueError, ValueLimits, ValuePathSegment};
use gantry_host::contracts::HostError;
use gantry_ir::{CanonicalPath, StructuralPosition, TypeDescriptor};

use crate::machine::value_matches_type;
use crate::{
    LogicalSessionRegistryV1, Machine, MachineLabel, MachineOutcome, MachineStatus, MachineStep,
    SessionCreationModeV1, SessionError, SessionEstablishmentV1,
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

/// Execution-scoped owner of cumulative task count and child task state.
#[derive(Debug)]
pub struct ConcurrentTaskStateV1 {
    execution_id: ProtocolIdentity,
    maximum_tasks: u64,
    created_tasks: u64,
    task_paths: BTreeMap<ProtocolIdentity, Arc<[Arc<str>]>>,
    tasks: BTreeMap<ProtocolIdentity, ConcurrentTaskRecordV1>,
    submitting_by_parent: BTreeMap<ProtocolIdentity, ProtocolIdentity>,
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
            maximum_tasks,
            created_tasks: 1,
            task_paths: BTreeMap::from([(root_task_id, Arc::from([]))]),
            tasks: BTreeMap::new(),
            submitting_by_parent: BTreeMap::new(),
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

    /// Returns whether one task is suspended on unresolved child submission.
    #[must_use]
    pub fn parent_is_suspended(&self, task_id: ProtocolIdentity) -> bool {
        self.submitting_by_parent.contains_key(&task_id)
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
            Ok(()) => ConcurrentTaskStatusV1::Running,
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
                self.machines.insert(task_id, machine);
                self.runnable.push_back(task_id);
            }
            Err(error) => self.state.resolve_submission(task_id, Err(error))?,
        }
        Ok(())
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
    /// Automatic fork-session construction failed.
    Session(SessionError),
    /// The requested status transition is not defined.
    InvalidTransition,
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
    use gantry_core::portable::{IdentityKind, RuntimeErrorCategory, TaskStatusKind};
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};
    use gantry_host::contracts::HostError;
    use gantry_ir::{CanonicalPath, EffectSet, StructuralPosition, TypeDescriptor};

    use super::{
        ConcurrentSchedulerV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1, TaskCaptureV1,
        TaskCreationRequestV1, TaskStateError,
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
        TaskCreationRequestV1 {
            parent_task_id,
            handle_name: Arc::from("child"),
            workflow: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("path failed: {error}")),
            spawn_site: StructuralPosition::new(vec![0])
                .unwrap_or_else(|error| panic!("site failed: {error}")),
            spawn_occurrence,
            result_type: TypeDescriptor::UNIT,
            captures,
            inherited_agent: Some(Arc::from("writer")),
            parent_session_id,
        }
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
