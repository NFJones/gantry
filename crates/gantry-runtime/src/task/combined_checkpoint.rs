//! Canonical durable recovery of the concurrent scheduler refinement.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, RuntimeErrorCategory, TaskHandleState, TaskStatusKind};
use gantry_core::value::ValueLimits;
use gantry_ir::{CanonicalPath, MachineProgram, TypeDescriptor};

use crate::machine::checkpoint_codec::{Reader, Writer, read_outcome, write_outcome};
use crate::machine::value_matches_type;
use crate::{
    ExecutionBudget, ExecutionBudgetSnapshot, LogicalSessionRegistryCheckpointV1,
    LogicalSessionRegistryV1, Machine, MachineCheckpointV3, MachineOutcome, MachineRecoveryError,
    MachineStatus, SessionCreationModeV1, SessionEstablishmentV1, SessionRecoveryError,
};

use super::{
    ConcurrentSchedulerV1, ConcurrentTaskRecordV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
    DynamicTaskHandleIdentity, TaskCaptureV1, TaskFailureV1, task_identity_key, task_path_frame,
};

const MAGIC: &[u8; 8] = b"GNTCDP04";
const MAX_CAPTURE_ATTEMPTS: usize = 8;

/// One versioned commit-cut snapshot of the composed concurrent-durable runtime.
///
/// The checkpoint owns no evaluator implementation. It projects the existing
/// foreground machine, scheduler task state, child machine checkpoints, and
/// logical-session registry into one canonical recovery boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableCheckpointV4 {
    execution_budget: ExecutionBudgetSnapshot,
    foreground: MachineCheckpointV3,
    sessions: LogicalSessionRegistryCheckpointV1,
    state: TaskStateCheckpointV1,
    machines: BTreeMap<ProtocolIdentity, MachineCheckpointV3>,
    runnable: VecDeque<ProtocolIdentity>,
}

impl ConcurrentDurableCheckpointV4 {
    /// Captures immutably borrowed machines under the coordinator's state lock.
    pub(crate) fn capture_coordinated(
        foreground: &Machine,
        children: &BTreeMap<ProtocolIdentity, Machine>,
        tasks: &ConcurrentTaskStateV1,
        sessions: &LogicalSessionRegistryV1,
        budget: &ExecutionBudget,
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        if !budget.same_owner(&foreground.execution_budget())
            || children
                .values()
                .any(|machine| !budget.same_owner(&machine.execution_budget()))
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        let before = budget.snapshot();
        let checkpoint = Self {
            execution_budget: before,
            foreground: foreground.checkpoint(),
            sessions: sessions.checkpoint(),
            state: TaskStateCheckpointV1::from_state(tasks),
            machines: children
                .iter()
                .map(|(id, machine)| (*id, machine.checkpoint()))
                .collect(),
            runnable: children
                .iter()
                .filter_map(|(id, machine)| {
                    (!matches!(
                        machine.status(),
                        MachineStatus::WaitingSessionScope
                            | MachineStatus::WaitingOperation
                            | MachineStatus::YieldRequired
                    ))
                    .then_some(*id)
                })
                .collect(),
        };
        if budget.snapshot() != before {
            return Err(ConcurrentDurableCheckpointError::CaptureRace);
        }
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Captures one complete combined state after validating every correspondence.
    pub fn capture(
        foreground: &Machine,
        scheduler: &ConcurrentSchedulerV1,
        sessions: &LogicalSessionRegistryV1,
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        Self::capture_with_interleaving(foreground, scheduler, sessions, |_| {})
    }

    /// Captures with a deterministic interleaving hook for external conformance tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn capture_with_test_interleaving(
        foreground: &Machine,
        scheduler: &ConcurrentSchedulerV1,
        sessions: &LogicalSessionRegistryV1,
        interleave: impl FnMut(usize),
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        Self::capture_with_interleaving(foreground, scheduler, sessions, interleave)
    }

    fn capture_with_interleaving(
        foreground: &Machine,
        scheduler: &ConcurrentSchedulerV1,
        sessions: &LogicalSessionRegistryV1,
        mut interleave: impl FnMut(usize),
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        let foreground_budget = foreground.execution_budget();
        if !scheduler.execution_budget.same_owner(&foreground_budget)
            || scheduler
                .machines
                .values()
                .any(|machine| !machine.execution_budget().same_owner(&foreground_budget))
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        for attempt in 0..MAX_CAPTURE_ATTEMPTS {
            let budget_before = foreground_budget.snapshot();
            interleave(attempt);
            let checkpoint = Self {
                execution_budget: budget_before,
                foreground: foreground.checkpoint(),
                sessions: sessions.checkpoint(),
                state: TaskStateCheckpointV1::from_state(&scheduler.state),
                machines: scheduler
                    .machines
                    .iter()
                    .map(|(task_id, machine)| (*task_id, machine.checkpoint()))
                    .collect(),
                runnable: scheduler.runnable.clone(),
            };
            if foreground_budget.snapshot() != budget_before {
                continue;
            }
            let recovered_sessions =
                LogicalSessionRegistryV1::recover_from_checkpoint(checkpoint.sessions.clone())?;
            let recovered_state = checkpoint
                .state
                .recover(&recovered_sessions, checkpoint.foreground.value_limits())?;
            if recovered_state != scheduler.state {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
            checkpoint.validate()?;
            return Ok(checkpoint);
        }
        Err(ConcurrentDurableCheckpointError::CaptureRace)
    }

    /// Returns the accepted execution represented by the whole task graph.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.state.execution_id
    }

    /// Returns the cumulative number of tasks created before this commit cut.
    #[must_use]
    pub const fn created_task_count(&self) -> u64 {
        self.state.created_tasks
    }

    /// Returns the stable root task represented by this graph.
    #[must_use]
    pub const fn root_task_id(&self) -> ProtocolIdentity {
        self.state.root_task_id
    }

    /// Returns the canonical execution-wide budget projection captured with this graph cut.
    #[must_use]
    pub const fn execution_budget(&self) -> ExecutionBudgetSnapshot {
        self.execution_budget
    }

    /// Returns whether one task identity belongs to this graph.
    #[must_use]
    pub fn contains_task(&self, task_id: ProtocolIdentity) -> bool {
        task_id == self.state.root_task_id
            || self.state.tasks.iter().any(|task| task.task_id == task_id)
    }

    /// Returns every task identity in canonical dynamic-path order.
    #[must_use]
    pub fn task_ids(&self) -> Vec<ProtocolIdentity> {
        std::iter::once(self.state.root_task_id)
            .chain(self.state.tasks.iter().map(|task| task.task_id))
            .collect()
    }

    /// Returns one root or child task's portable status.
    #[must_use]
    pub fn task_status(&self, task_id: ProtocolIdentity) -> Option<TaskStatusKind> {
        if task_id == self.state.root_task_id {
            return Some(self.state.root.status.kind());
        }
        self.state
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .map(|task| task.status.kind())
    }

    /// Returns one child task's source-language handle disposition.
    #[must_use]
    pub fn task_handle_state(&self, task_id: ProtocolIdentity) -> Option<TaskHandleState> {
        self.state
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .map(|task| task.handle_state)
    }

    /// Returns whether submission resolution exposed one child handle.
    #[must_use]
    pub fn task_handle_is_visible(&self, task_id: ProtocolIdentity) -> bool {
        self.state
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .is_some_and(|task| task.handle_visible)
    }

    /// Returns whether the task has a committed cancellation reason.
    #[must_use]
    pub fn task_is_cancelled(&self, task_id: ProtocolIdentity) -> bool {
        self.state.cancellation_reasons.contains_key(&task_id)
    }

    /// Returns whether foreground completion has been fixed.
    #[must_use]
    pub const fn foreground_is_fixed(&self) -> bool {
        self.state.foreground.is_some()
    }

    /// Returns whether terminal completion has been fixed.
    #[must_use]
    pub const fn terminal_is_fixed(&self) -> bool {
        self.state.terminal_fixed
    }

    /// Returns the exact foreground checkpoint composed into this graph cut.
    #[must_use]
    pub const fn foreground_checkpoint(&self) -> &MachineCheckpointV3 {
        &self.foreground
    }

    /// Returns one root or running child machine checkpoint from this graph cut.
    #[must_use]
    pub fn task_checkpoint(&self, task_id: ProtocolIdentity) -> Option<&MachineCheckpointV3> {
        if task_id == self.state.root_task_id {
            Some(&self.foreground)
        } else {
            self.machines.get(&task_id)
        }
    }

    /// Returns the child tasks currently retained as submitting and hidden.
    pub(crate) fn hidden_submission_task_ids(&self) -> Vec<ProtocolIdentity> {
        self.state
            .tasks
            .iter()
            .filter(|task| {
                matches!(task.status, ConcurrentTaskStatusV1::Submitting) && !task.handle_visible
            })
            .map(|task| task.task_id)
            .collect()
    }

    /// Identifies one previously hidden child whose submission became visible.
    pub(crate) fn submission_resolution_task(
        &self,
        previous_hidden: &[ProtocolIdentity],
    ) -> Result<Option<ProtocolIdentity>, ConcurrentDurableCheckpointError> {
        let candidates = previous_hidden
            .iter()
            .filter(|task_id| {
                self.state.tasks.iter().any(|current| {
                    current.task_id == **task_id
                        && current.handle_visible
                        && matches!(
                            current.status,
                            ConcurrentTaskStatusV1::Running | ConcurrentTaskStatusV1::Failed(_)
                        )
                })
            })
            .copied()
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [] => Ok(None),
            [task_id] => Ok(Some(*task_id)),
            _ => Err(ConcurrentDurableCheckpointError::InvalidCheckpoint),
        }
    }

    /// Validates the exact child-only successor of one submission resolution.
    pub(crate) fn validate_submission_resolution(
        &self,
        previous: &Self,
        task_id: ProtocolIdentity,
        program: Arc<MachineProgram>,
    ) -> Result<(), ConcurrentDurableCheckpointError> {
        if self.submission_resolution_task(&previous.hidden_submission_task_ids())? != Some(task_id)
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        let task = previous
            .state
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .cloned()
            .ok_or(ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
        if !matches!(task.status, ConcurrentTaskStatusV1::Submitting)
            || task.handle_visible
            || task.driver_ownership != super::TaskDriverOwnershipV1::AwaitingSubmission
            || task.pending_outcome.is_some()
            || self.execution_budget != previous.execution_budget
            || self.sessions != previous.sessions
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        let current_task = self
            .state
            .tasks
            .iter()
            .find(|current| current.task_id == task_id)
            .ok_or(ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
        let mut expected_state = previous.state.clone();
        let expected_task = expected_state
            .tasks
            .iter_mut()
            .find(|current| current.task_id == task_id)
            .ok_or(ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
        expected_task.handle_visible = true;
        match &current_task.status {
            ConcurrentTaskStatusV1::Running => {
                expected_task.status = ConcurrentTaskStatusV1::Running;
                expected_task.driver_ownership = super::TaskDriverOwnershipV1::Supervised;
            }
            ConcurrentTaskStatusV1::Failed(failure)
                if failure.category == RuntimeErrorCategory::ExecutorFailure =>
            {
                expected_task.status = ConcurrentTaskStatusV1::Failed(failure.clone());
                expected_task.driver_ownership = super::TaskDriverOwnershipV1::PhysicallySettled;
            }
            _ => return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint),
        }
        if expected_state != self.state {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        let previous_parent = if task.parent_task_id == previous.foreground.task_id() {
            &previous.foreground
        } else {
            previous
                .machines
                .get(&task.parent_task_id)
                .ok_or(ConcurrentDurableCheckpointError::InvalidCheckpoint)?
        };
        let current_parent = if task.parent_task_id == self.foreground.task_id() {
            &self.foreground
        } else {
            self.machines
                .get(&task.parent_task_id)
                .ok_or(ConcurrentDurableCheckpointError::InvalidCheckpoint)?
        };
        let suspension = previous_parent.pending_spawn_checkpoint().cloned();
        if let Some(suspension) = &suspension {
            let matching_creation = suspension.workflow == task.workflow
                && suspension.site == task.spawn_site
                && suspension.occurrence == task.spawn_occurrence
                && suspension.handle.name() == task.handle_name.as_ref()
                && suspension.handle.result_type() == &task.result_type
                && suspension.inherited_agent == task.inherited_agent
                && suspension.parent_session == Some(task.parent_session_id)
                && suspension.captures.len() == task.captures.len()
                && suspension.captures.iter().all(|capture| {
                    task.captures.get(capture.task_capture().name()) == Some(capture.task_capture())
                });
            if !matching_creation {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
            if !current_parent.is_spawn_completion_successor(previous_parent, task.handle_id) {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        } else if current_parent != previous_parent
            || matches!(current_task.status, ConcurrentTaskStatusV1::Running)
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        let mut expected_foreground = previous.foreground.clone();
        let mut expected_machines = previous.machines.clone();
        if task.parent_task_id == previous.foreground.task_id() {
            expected_foreground = current_parent.clone();
        } else {
            expected_machines.insert(task.parent_task_id, current_parent.clone());
        }
        match &current_task.status {
            ConcurrentTaskStatusV1::Running => {
                let suspension =
                    suspension.ok_or(ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
                let limits = previous_parent.machine_limits();
                let budget = ExecutionBudget::recover_from_checkpoint(self.execution_budget)?;
                let machine = Machine::new_concurrent_task_body_with_context(
                    program,
                    &suspension.body,
                    &suspension
                        .captures
                        .iter()
                        .map(|capture| capture.task_capture().clone())
                        .collect::<Vec<_>>(),
                    previous.execution_id(),
                    task_id,
                    Arc::clone(&task.task_path),
                    limits,
                    budget,
                    suspension.inherited_agent,
                    Some(task.base_session_id),
                )
                .map_err(|_| ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
                expected_machines.insert(task_id, machine.checkpoint());
            }
            ConcurrentTaskStatusV1::Failed(_) => {}
            _ => return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint),
        }
        let expected_runnable = expected_machines
            .iter()
            .filter_map(|(id, machine)| {
                (!matches!(
                    machine.status(),
                    MachineStatus::WaitingSessionScope
                        | MachineStatus::WaitingOperation
                        | MachineStatus::YieldRequired
                ))
                .then_some(*id)
            })
            .collect::<VecDeque<_>>();
        if self.foreground != expected_foreground
            || self.machines != expected_machines
            || self.runnable != expected_runnable
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        Ok(())
    }

    /// Returns the exact session checkpoint composed into this graph cut.
    #[must_use]
    pub const fn session_checkpoint(&self) -> &LogicalSessionRegistryCheckpointV1 {
        &self.sessions
    }

    /// Encodes the unique version-four combined checkpoint.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.raw(MAGIC);
        writer.bytes(&self.execution_budget.canonical_bytes());
        writer.bytes(&self.foreground.canonical_bytes());
        writer.bytes(&self.sessions.canonical_bytes());
        self.state
            .encode(&mut writer, self.foreground.value_limits());
        writer.count(self.state.tasks.len());
        for task in &self.state.tasks {
            write_identity(&mut writer, task.task_id);
            match self.machines.get(&task.task_id) {
                Some(machine) => {
                    writer.boolean(true);
                    writer.bytes(&machine.canonical_bytes());
                }
                None => writer.boolean(false),
            }
        }
        writer.count(self.runnable.len());
        for task_id in &self.runnable {
            write_identity(&mut writer, *task_id);
        }
        writer.finish()
    }

    /// Decodes and validates one exact combined checkpoint against its program.
    pub fn decode(
        program: &MachineProgram,
        bytes: &[u8],
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        let mut reader = Reader::new(bytes);
        if reader.raw(MAGIC.len())? != MAGIC {
            return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
        }
        let execution_budget = ExecutionBudgetSnapshot::decode(reader.bytes()?)?;
        let foreground = MachineCheckpointV3::decode(program, reader.bytes()?)?;
        let sessions =
            LogicalSessionRegistryCheckpointV1::decode(reader.bytes()?, foreground.value_limits())?;
        let state = TaskStateCheckpointV1::decode(&mut reader, foreground.value_limits())?;
        let machine_count = reader.count()?;
        if machine_count != state.tasks.len() {
            return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
        }
        let mut machines = BTreeMap::new();
        for task in &state.tasks {
            if read_identity(&mut reader, IdentityKind::Task)? != task.task_id {
                return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
            }
            if reader.boolean()? {
                let checkpoint = MachineCheckpointV3::decode(program, reader.bytes()?)?;
                if machines.insert(task.task_id, checkpoint).is_some() {
                    return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
                }
            }
        }
        let runnable_count = reader.count()?;
        let mut runnable = VecDeque::new();
        for _ in 0..runnable_count {
            runnable.push_back(read_identity(&mut reader, IdentityKind::Task)?);
        }
        if !reader.is_empty() {
            return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
        }
        let checkpoint = Self {
            execution_budget,
            foreground,
            sessions,
            state,
            machines,
            runnable,
        };
        checkpoint.validate()?;
        if checkpoint.canonical_bytes() != bytes {
            return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
        }
        Ok(checkpoint)
    }

    /// Reconstructs the same foreground machine, scheduler, and session registry.
    pub fn recover(
        self,
        program: Arc<MachineProgram>,
    ) -> Result<RecoveredConcurrentDurableExecutionV1, ConcurrentDurableCheckpointError> {
        self.validate()?;
        let sessions = LogicalSessionRegistryV1::recover_from_checkpoint(self.sessions)?;
        let state = self
            .state
            .recover(&sessions, self.foreground.value_limits())?;
        let execution_budget = ExecutionBudget::recover_from_checkpoint(self.execution_budget)?;
        let foreground = Machine::recover_from_checkpoint(
            Arc::clone(&program),
            self.foreground,
            execution_budget.clone(),
        )?;
        let mut machines = BTreeMap::new();
        for (task_id, checkpoint) in self.machines {
            let machine = Machine::recover_from_checkpoint(
                Arc::clone(&program),
                checkpoint,
                execution_budget.clone(),
            )?;
            machines.insert(task_id, machine);
        }
        Ok(RecoveredConcurrentDurableExecutionV1 {
            foreground,
            scheduler: ConcurrentSchedulerV1 {
                state,
                execution_budget,
                machines,
                runnable: self.runnable,
            },
            sessions,
        })
    }

    fn validate(&self) -> Result<(), ConcurrentDurableCheckpointError> {
        let sessions = LogicalSessionRegistryV1::recover_from_checkpoint(self.sessions.clone())?;
        let state = self
            .state
            .recover(&sessions, self.foreground.value_limits())?;
        if !budget_matches_machine(&self.execution_budget, &self.foreground)
            || self.foreground.execution_id() != state.execution_id
            || self.foreground.task_id() != state.root_task_id
            || !self.foreground.task_path().is_empty()
            || !self.foreground.is_execution_foreground()
            || self.sessions.execution_id() != state.execution_id
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        if self.foreground.outcome().is_none()
            && state.task_cancellation_reason(state.root_task_id)
                != self.foreground.cancellation_reason()
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        let running = state
            .tasks
            .iter()
            .filter_map(|(task_id, task)| {
                matches!(task.status, ConcurrentTaskStatusV1::Running).then_some(*task_id)
            })
            .collect::<BTreeSet<_>>();
        if running != self.machines.keys().copied().collect() {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        for (task_id, machine) in &self.machines {
            let Some(task) = state.task(*task_id) else {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            };
            if !budget_matches_machine(&self.execution_budget, machine)
                || machine.execution_id() != state.execution_id
                || machine.task_id() != *task_id
                || machine.task_path() != task.task_path()
                || machine.is_execution_foreground()
                || state.task_cancellation_reason(*task_id) != machine.cancellation_reason()
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }

        let mut seen = BTreeSet::new();
        for task_id in &self.runnable {
            let Some(machine) = self.machines.get(task_id) else {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            };
            if !seen.insert(*task_id)
                || matches!(
                    machine.status(),
                    MachineStatus::WaitingSessionScope
                        | MachineStatus::WaitingOperation
                        | MachineStatus::YieldRequired
                )
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }
        let expected_runnable = self
            .machines
            .iter()
            .filter_map(|(task_id, machine)| {
                (!matches!(
                    machine.status(),
                    MachineStatus::WaitingSessionScope
                        | MachineStatus::WaitingOperation
                        | MachineStatus::YieldRequired
                ))
                .then_some(*task_id)
            })
            .collect::<BTreeSet<_>>();
        if seen != expected_runnable {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        Ok(())
    }
}

fn budget_matches_machine(budget: &ExecutionBudgetSnapshot, machine: &MachineCheckpointV3) -> bool {
    let limits = machine.machine_limits();
    machine.execution_id() == budget.execution
        && limits.maximum_deterministic_transitions == budget.maximum_transitions
        && limits.maximum_operations == budget.maximum_operations
}

/// Recovered ownership of all existing runtime components in one combined execution.
#[derive(Debug)]
pub struct RecoveredConcurrentDurableExecutionV1 {
    foreground: Machine,
    scheduler: ConcurrentSchedulerV1,
    sessions: LogicalSessionRegistryV1,
}

impl RecoveredConcurrentDurableExecutionV1 {
    /// Returns the recovered foreground machine.
    #[must_use]
    pub const fn foreground(&self) -> &Machine {
        &self.foreground
    }

    /// Returns mutable access to the recovered foreground machine.
    pub const fn foreground_mut(&mut self) -> &mut Machine {
        &mut self.foreground
    }

    /// Returns the recovered concurrent scheduler.
    #[must_use]
    pub const fn scheduler(&self) -> &ConcurrentSchedulerV1 {
        &self.scheduler
    }

    /// Returns mutable access to the recovered concurrent scheduler.
    pub const fn scheduler_mut(&mut self) -> &mut ConcurrentSchedulerV1 {
        &mut self.scheduler
    }

    /// Returns the recovered logical-session registry.
    #[must_use]
    pub const fn sessions(&self) -> &LogicalSessionRegistryV1 {
        &self.sessions
    }

    /// Returns mutable access to the recovered logical-session registry.
    pub const fn sessions_mut(&mut self) -> &mut LogicalSessionRegistryV1 {
        &mut self.sessions
    }

    /// Consumes recovery into the existing machine, scheduler, and session owners.
    #[must_use]
    pub fn into_parts(self) -> (Machine, ConcurrentSchedulerV1, LogicalSessionRegistryV1) {
        (self.foreground, self.scheduler, self.sessions)
    }

    /// Consumes recovery into independently driven root and child machines.
    ///
    /// The returned machines retain one private shared budget owner. Production
    /// task drivers use this graph form rather than polling the legacy scheduler.
    #[must_use]
    pub fn into_machine_graph(self) -> (Machine, BTreeMap<ProtocolIdentity, Machine>) {
        (self.foreground, self.scheduler.machines)
    }
}

/// Rejection of malformed or internally inconsistent combined recovery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcurrentDurableCheckpointError {
    /// Bytes are truncated, noncanonical, or use another version.
    InvalidEncoding,
    /// Task graph, scheduler, machine, or session correspondences disagree.
    InvalidCheckpoint,
    /// The shared execution budget changed during every bounded capture attempt.
    CaptureRace,
    /// One nested machine checkpoint is invalid or program-incompatible.
    Machine(MachineRecoveryError),
    /// The logical-session checkpoint is invalid.
    Session(SessionRecoveryError),
}

impl From<MachineRecoveryError> for ConcurrentDurableCheckpointError {
    fn from(error: MachineRecoveryError) -> Self {
        match error {
            MachineRecoveryError::InvalidEncoding => Self::InvalidEncoding,
            error => Self::Machine(error),
        }
    }
}

impl From<SessionRecoveryError> for ConcurrentDurableCheckpointError {
    fn from(error: SessionRecoveryError) -> Self {
        match error {
            SessionRecoveryError::InvalidEncoding => Self::InvalidEncoding,
            error => Self::Session(error),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TaskStateCheckpointV1 {
    execution_id: ProtocolIdentity,
    root_task_id: ProtocolIdentity,
    root: super::RootTaskRecordV1,
    maximum_tasks: u64,
    created_tasks: u64,
    tasks: Vec<ConcurrentTaskRecordV1>,
    cancellation_reasons: BTreeMap<ProtocolIdentity, Arc<str>>,
    execution_cancellation: Option<Arc<str>>,
    foreground: Option<MachineOutcome>,
    terminal_fixed: bool,
}

impl TaskStateCheckpointV1 {
    fn from_state(state: &ConcurrentTaskStateV1) -> Self {
        let mut tasks = state.tasks.values().cloned().collect::<Vec<_>>();
        tasks.sort_by(|left, right| left.task_path.cmp(&right.task_path));
        Self {
            execution_id: state.execution_id,
            root_task_id: state.root_task_id,
            root: state.root.clone(),
            maximum_tasks: state.maximum_tasks,
            created_tasks: state.created_tasks,
            tasks,
            cancellation_reasons: state.cancellation_reasons.clone(),
            execution_cancellation: state.execution_cancellation.clone(),
            foreground: state.foreground.clone(),
            terminal_fixed: state.terminal.is_some(),
        }
    }

    fn encode(&self, writer: &mut Writer, limits: ValueLimits) {
        write_identity(writer, self.execution_id);
        write_identity(writer, self.root_task_id);
        write_task_status(writer, &self.root.status);
        write_optional_outcome(writer, self.root.pending_outcome.as_ref(), limits);
        write_optional_outcome(writer, self.root.settled_outcome.as_ref(), limits);
        write_driver_state(writer, self.root.driver_ownership, self.root.recovery_state);
        writer.u64(self.maximum_tasks);
        writer.u64(self.created_tasks);
        writer.count(self.tasks.len());
        for task in &self.tasks {
            write_task(writer, task, limits);
        }
        let paths = self.task_paths();
        let mut cancellations = self.cancellation_reasons.iter().collect::<Vec<_>>();
        cancellations.sort_by(|(left, _), (right, _)| paths.get(left).cmp(&paths.get(right)));
        writer.count(cancellations.len());
        for (task_id, reason) in cancellations {
            write_identity(writer, *task_id);
            writer.string(reason);
        }
        writer.optional_string(self.execution_cancellation.as_deref());
        writer.boolean(self.foreground.is_some());
        if let Some(foreground) = &self.foreground {
            write_outcome(writer, foreground, limits);
        }
        writer.boolean(self.terminal_fixed);
    }

    fn decode(
        reader: &mut Reader<'_>,
        limits: ValueLimits,
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        let execution_id = read_identity(reader, IdentityKind::Execution)?;
        let root_task_id = read_identity(reader, IdentityKind::Task)?;
        let status = read_task_status(reader, limits)?;
        let pending_outcome = read_optional_outcome(reader, limits)?;
        let settled_outcome = read_optional_outcome(reader, limits)?;
        let (driver_ownership, recovery_state) = read_driver_state(reader)?;
        let root = super::RootTaskRecordV1 {
            task_id: root_task_id,
            task_path: Arc::from([]),
            status,
            pending_outcome,
            settled_outcome,
            driver_ownership,
            recovery_state,
        };
        let maximum_tasks = reader.u64()?;
        let created_tasks = reader.u64()?;
        let task_count = reader.count()?;
        let mut tasks = Vec::new();
        for _ in 0..task_count {
            tasks.push(read_task(reader, limits)?);
        }
        let cancellation_count = reader.count()?;
        let mut cancellation_reasons = BTreeMap::new();
        for _ in 0..cancellation_count {
            let task_id = read_identity(reader, IdentityKind::Task)?;
            let reason = Arc::from(reader.string()?);
            if cancellation_reasons.insert(task_id, reason).is_some() {
                return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
            }
        }
        let execution_cancellation = reader.optional_string()?.map(Arc::from);
        let foreground = reader
            .boolean()?
            .then(|| read_outcome(reader, limits))
            .transpose()?;
        let terminal_fixed = reader.boolean()?;
        Ok(Self {
            execution_id,
            root_task_id,
            root,
            maximum_tasks,
            created_tasks,
            tasks,
            cancellation_reasons,
            execution_cancellation,
            foreground,
            terminal_fixed,
        })
    }

    fn recover(
        &self,
        sessions: &LogicalSessionRegistryV1,
        limits: ValueLimits,
    ) -> Result<ConcurrentTaskStateV1, ConcurrentDurableCheckpointError> {
        let expected_created_tasks = u64::try_from(self.tasks.len())
            .ok()
            .and_then(|count| count.checked_add(1));
        if self.execution_id.kind() != IdentityKind::Execution
            || self.root_task_id.kind() != IdentityKind::Task
            || self.root.task_id != self.root_task_id
            || !self.root.task_path.is_empty()
            || self.root.pending_outcome.is_some()
                && !matches!(self.root.status, ConcurrentTaskStatusV1::Running)
            || match &self.root.settled_outcome {
                Some(outcome) => {
                    self.root.status != super::task_status_from_outcome(outcome.clone())
                }
                None => !matches!(
                    self.root.status,
                    ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                ),
            }
            || self.maximum_tasks == 0
            || expected_created_tasks != Some(self.created_tasks)
            || self.created_tasks > self.maximum_tasks
            || self
                .execution_cancellation
                .as_ref()
                .is_some_and(|reason| reason.is_empty())
            || self.foreground.is_none() && self.terminal_fixed
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        let mut task_paths: BTreeMap<ProtocolIdentity, Arc<[Arc<str>]>> =
            BTreeMap::from([(self.root_task_id, Arc::from([]))]);
        let mut tasks = BTreeMap::new();
        let mut submitting_by_parent = BTreeMap::new();
        let mut previous_path: Option<&[Arc<str>]> = None;
        for task in &self.tasks {
            if previous_path.is_some_and(|previous| previous >= task.task_path.as_ref())
                || task.task_id.kind() != IdentityKind::Task
                || task.parent_task_id.kind() != IdentityKind::Task
                || task.parent_session_id.kind() != IdentityKind::Session
                || task.base_session_id.kind() != IdentityKind::Session
                || task.handle_name.is_empty()
                || task.handle_id.owner != task.parent_task_id
                || task.handle_id.child != task.task_id
                || task.handle_state == TaskHandleState::Discharged
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
            previous_path = Some(&task.task_path);
            let Some(parent_path) = task_paths.get(&task.parent_task_id) else {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            };
            let mut expected_path = parent_path.to_vec();
            expected_path.push(Arc::from(task_path_frame(
                &task.workflow,
                &task.spawn_site,
                task.spawn_occurrence,
            )));
            let expected_id = ProtocolIdentity::derive(
                IdentityKind::Task,
                &task_identity_key(self.execution_id, &expected_path),
            )
            .map_err(|_| ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
            if task.task_path.as_ref() != expected_path
                || task.task_id != expected_id
                || task_paths.contains_key(&task.task_id)
                || tasks.contains_key(&task.task_id)
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
            validate_task(task, limits)?;
            validate_task_session(task, sessions, self.execution_id)?;
            if matches!(task.status, ConcurrentTaskStatusV1::Submitting) {
                if task.handle_visible
                    || submitting_by_parent
                        .insert(task.parent_task_id, task.task_id)
                        .is_some()
                {
                    return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
                }
            } else if !task.handle_visible {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
            task_paths.insert(task.task_id, Arc::clone(&task.task_path));
            tasks.insert(task.task_id, task.clone());
        }

        for (task_id, reason) in &self.cancellation_reasons {
            if !task_paths.contains_key(task_id) || reason.is_empty() {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
            if let Some(ConcurrentTaskStatusV1::Cancelled(settled_reason)) =
                tasks.get(task_id).map(|task| &task.status)
                && settled_reason != reason
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }
        if self.execution_cancellation.is_some()
            && matches!(
                self.root.status,
                ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
            )
            && !self.cancellation_reasons.contains_key(&self.root_task_id)
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }

        let known_tasks = task_paths.keys().copied().collect::<BTreeSet<_>>();
        for session in sessions.sessions() {
            if session.execution_id != self.execution_id
                || session
                    .creator_task
                    .is_some_and(|creator| !known_tasks.contains(&creator))
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }

        let mut state = ConcurrentTaskStateV1 {
            execution_id: self.execution_id,
            root_task_id: self.root_task_id,
            root: self.root.clone(),
            maximum_tasks: self.maximum_tasks,
            created_tasks: self.created_tasks,
            task_paths,
            tasks,
            submitting_by_parent,
            cancellation_reasons: self.cancellation_reasons.clone(),
            execution_cancellation: self.execution_cancellation.clone(),
            foreground: self.foreground.clone(),
            terminal: None,
        };
        if state.foreground.is_some()
            && state.tasks.values().any(|task| {
                task.handle_state != TaskHandleState::Detached
                    && matches!(
                        task.status,
                        ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running
                    )
            })
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        if self.terminal_fixed {
            state
                .complete_terminal()
                .map_err(|_| ConcurrentDurableCheckpointError::InvalidCheckpoint)?;
        }
        Ok(state)
    }

    fn task_paths(&self) -> BTreeMap<ProtocolIdentity, Arc<[Arc<str>]>> {
        let mut paths = BTreeMap::from([(self.root_task_id, Arc::from([]))]);
        paths.extend(
            self.tasks
                .iter()
                .map(|task| (task.task_id, Arc::clone(&task.task_path))),
        );
        paths
    }
}

fn validate_task(
    task: &ConcurrentTaskRecordV1,
    limits: ValueLimits,
) -> Result<(), ConcurrentDurableCheckpointError> {
    if task.pending_outcome.is_some() && !matches!(task.status, ConcurrentTaskStatusV1::Running) {
        return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
    }
    if let Some(MachineOutcome::Succeeded(value)) = &task.pending_outcome
        && (!value_matches_type(value, &task.result_type) || value.detached_copy(limits).is_err())
    {
        return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
    }
    for (name, capture) in &task.captures {
        if name.is_empty()
            || name.as_ref() != capture.name.as_ref()
            || !value_matches_type(&capture.value, &capture.ty)
            || capture.value.detached_copy(limits).is_err()
        {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
    }
    match &task.status {
        ConcurrentTaskStatusV1::Succeeded(value) => {
            if !value_matches_type(value, &task.result_type) || value.detached_copy(limits).is_err()
            {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }
        ConcurrentTaskStatusV1::Failed(failure) => {
            if failure.code.is_empty() {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }
        ConcurrentTaskStatusV1::Cancelled(reason) => {
            if reason.is_empty() {
                return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
            }
        }
        ConcurrentTaskStatusV1::Submitting | ConcurrentTaskStatusV1::Running => {}
    }
    Ok(())
}

fn validate_task_session(
    task: &ConcurrentTaskRecordV1,
    sessions: &LogicalSessionRegistryV1,
    execution_id: ProtocolIdentity,
) -> Result<(), ConcurrentDurableCheckpointError> {
    if sessions.get(task.parent_session_id).is_none() {
        return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
    }
    let Some(base) = sessions.get(task.base_session_id) else {
        return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
    };
    if base.execution_id != execution_id
        || base.parent != Some(task.parent_session_id)
        || base.mode != SessionCreationModeV1::Fork
        || base.establishment != SessionEstablishmentV1::Separate
        || base.creator_task != Some(task.task_id)
        || base.creation_site.as_ref() != Some(&task.spawn_site)
        || base.creation_occurrence != Some(task.spawn_occurrence)
    {
        return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
    }
    Ok(())
}

fn write_task(writer: &mut Writer, task: &ConcurrentTaskRecordV1, limits: ValueLimits) {
    write_identity(writer, task.task_id);
    write_identity(writer, task.parent_task_id);
    writer.string(&task.handle_name);
    writer.count(task.task_path.len());
    for frame in task.task_path.iter() {
        writer.string(frame);
    }
    writer.string(task.workflow.as_str());
    writer.position(&task.spawn_site);
    writer.u64(task.spawn_occurrence);
    writer.string(&task.result_type.canonical_string());
    writer.count(task.captures.len());
    for capture in task.captures.values() {
        writer.string(&capture.name);
        writer.string(&capture.ty.canonical_string());
        writer.boolean(capture.mutable);
        writer.value(&capture.value);
    }
    writer.optional_string(task.inherited_agent.as_deref());
    write_identity(writer, task.parent_session_id);
    write_identity(writer, task.base_session_id);
    writer.string(task.handle_state.wire_name());
    writer.boolean(task.handle_visible);
    write_task_status(writer, &task.status);
    write_optional_outcome(writer, task.pending_outcome.as_ref(), limits);
    write_driver_state(writer, task.driver_ownership, task.recovery_state);
}

fn read_task(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<ConcurrentTaskRecordV1, ConcurrentDurableCheckpointError> {
    let task_id = read_identity(reader, IdentityKind::Task)?;
    let parent_task_id = read_identity(reader, IdentityKind::Task)?;
    let handle_name = Arc::from(reader.string()?);
    let path_count = reader.count()?;
    let mut task_path = Vec::new();
    for _ in 0..path_count {
        task_path.push(Arc::from(reader.string()?));
    }
    let workflow = CanonicalPath::new(&reader.string()?)
        .map_err(|_| ConcurrentDurableCheckpointError::InvalidEncoding)?;
    let spawn_site = reader.position()?;
    let spawn_occurrence = reader.u64()?;
    let result_type = TypeDescriptor::from_canonical_string(&reader.string()?)
        .map_err(|_| ConcurrentDurableCheckpointError::InvalidEncoding)?;
    let capture_count = reader.count()?;
    let mut captures = BTreeMap::new();
    for _ in 0..capture_count {
        let name: Arc<str> = Arc::from(reader.string()?);
        let ty = TypeDescriptor::from_canonical_string(&reader.string()?)
            .map_err(|_| ConcurrentDurableCheckpointError::InvalidEncoding)?;
        let mutable = reader.boolean()?;
        let value = reader.value(limits)?;
        let capture = TaskCaptureV1 {
            name: Arc::clone(&name),
            ty,
            mutable,
            value,
        };
        if captures.insert(name, capture).is_some() {
            return Err(ConcurrentDurableCheckpointError::InvalidEncoding);
        }
    }
    let inherited_agent = reader.optional_string()?.map(Arc::from);
    let parent_session_id = read_identity(reader, IdentityKind::Session)?;
    let base_session_id = read_identity(reader, IdentityKind::Session)?;
    let handle_state = TaskHandleState::from_wire_name(&reader.string()?)
        .ok_or(ConcurrentDurableCheckpointError::InvalidEncoding)?;
    let handle_visible = reader.boolean()?;
    let status = read_task_status(reader, limits)?;
    let pending_outcome = read_optional_outcome(reader, limits)?;
    let (driver_ownership, recovery_state) = read_driver_state(reader)?;
    Ok(ConcurrentTaskRecordV1 {
        task_id,
        parent_task_id,
        handle_name,
        handle_id: DynamicTaskHandleIdentity {
            owner: parent_task_id,
            child: task_id,
        },
        task_path: Arc::from(task_path),
        workflow,
        spawn_site,
        spawn_occurrence,
        result_type,
        captures,
        inherited_agent,
        parent_session_id,
        base_session_id,
        handle_state,
        handle_visible,
        status,
        pending_outcome,
        driver_ownership,
        recovery_state,
    })
}

/// Encodes an optional logical outcome without inventing settlement.
fn write_optional_outcome(
    writer: &mut Writer,
    outcome: Option<&MachineOutcome>,
    limits: ValueLimits,
) {
    writer.boolean(outcome.is_some());
    if let Some(outcome) = outcome {
        write_outcome(writer, outcome, limits);
    }
}

/// Decodes a pending or settled outcome from the graph cut.
fn read_optional_outcome(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<Option<MachineOutcome>, ConcurrentDurableCheckpointError> {
    Ok(reader
        .boolean()?
        .then(|| read_outcome(reader, limits))
        .transpose()?)
}

/// Retains ownership bookkeeping as evidence, never as an executor capability.
fn write_driver_state(
    writer: &mut Writer,
    ownership: super::TaskDriverOwnershipV1,
    recovery: super::TaskRecoveryStateV1,
) {
    writer.u8(match ownership {
        super::TaskDriverOwnershipV1::AwaitingSubmission => 0,
        super::TaskDriverOwnershipV1::Supervised => 1,
        super::TaskDriverOwnershipV1::PhysicallySettled => 2,
    });
    writer.u8(match recovery {
        super::TaskRecoveryStateV1::Original => 0,
        super::TaskRecoveryStateV1::Recovered => 1,
    });
}

/// Rejects unknown driver bookkeeping tags in retained graph evidence.
fn read_driver_state(
    reader: &mut Reader<'_>,
) -> Result<
    (super::TaskDriverOwnershipV1, super::TaskRecoveryStateV1),
    ConcurrentDurableCheckpointError,
> {
    let ownership = match reader.u8()? {
        0 => super::TaskDriverOwnershipV1::AwaitingSubmission,
        1 => super::TaskDriverOwnershipV1::Supervised,
        2 => super::TaskDriverOwnershipV1::PhysicallySettled,
        _ => return Err(ConcurrentDurableCheckpointError::InvalidEncoding),
    };
    let recovery = match reader.u8()? {
        0 => super::TaskRecoveryStateV1::Original,
        1 => super::TaskRecoveryStateV1::Recovered,
        _ => return Err(ConcurrentDurableCheckpointError::InvalidEncoding),
    };
    Ok((ownership, recovery))
}

fn write_task_status(writer: &mut Writer, status: &ConcurrentTaskStatusV1) {
    match status {
        ConcurrentTaskStatusV1::Submitting => writer.u8(0),
        ConcurrentTaskStatusV1::Running => writer.u8(1),
        ConcurrentTaskStatusV1::Succeeded(value) => {
            writer.u8(2);
            writer.value(value);
        }
        ConcurrentTaskStatusV1::Failed(failure) => {
            writer.u8(3);
            writer.string(failure.category.wire_name());
            writer.string(&failure.code);
            writer.optional_string(failure.protected_diagnostic.as_deref());
        }
        ConcurrentTaskStatusV1::Cancelled(reason) => {
            writer.u8(4);
            writer.string(reason);
        }
    }
}

fn read_task_status(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<ConcurrentTaskStatusV1, ConcurrentDurableCheckpointError> {
    match reader.u8()? {
        0 => Ok(ConcurrentTaskStatusV1::Submitting),
        1 => Ok(ConcurrentTaskStatusV1::Running),
        2 => Ok(ConcurrentTaskStatusV1::Succeeded(reader.value(limits)?)),
        3 => Ok(ConcurrentTaskStatusV1::Failed(TaskFailureV1 {
            category: RuntimeErrorCategory::from_wire_name(&reader.string()?)
                .ok_or(ConcurrentDurableCheckpointError::InvalidEncoding)?,
            code: Arc::from(reader.string()?),
            protected_diagnostic: reader.optional_string()?.map(Arc::from),
        })),
        4 => Ok(ConcurrentTaskStatusV1::Cancelled(Arc::from(
            reader.string()?,
        ))),
        _ => Err(ConcurrentDurableCheckpointError::InvalidEncoding),
    }
}

fn write_identity(writer: &mut Writer, identity: ProtocolIdentity) {
    writer.string(&identity.to_string());
}

fn read_identity(
    reader: &mut Reader<'_>,
    kind: IdentityKind,
) -> Result<ProtocolIdentity, ConcurrentDurableCheckpointError> {
    ProtocolIdentity::parse_kind(&reader.string()?, kind)
        .map_err(|_| ConcurrentDurableCheckpointError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gantry_core::identity::ProtocolIdentity;
    use gantry_core::portable::{IdentityKind, TaskHandleState, TaskStatusKind};
    use gantry_core::source::{ByteSpan, SourceLimits, SourceSnapshotBuilder, SourceSpan};
    use gantry_core::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
    use gantry_host::contracts::HostError;
    use gantry_ir::generated::TaskControlSiteKind;
    use gantry_ir::{
        CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
        StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor, Workflow,
    };

    use super::{
        ConcurrentDurableCheckpointError, ConcurrentDurableCheckpointV4, MAX_CAPTURE_ATTEMPTS,
    };
    use crate::machine::task_identity_key;
    use crate::{
        CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1,
        ConcurrentTaskStatusV1, ExecutionBudget, LogicalSessionRegistryV1, Machine, MachineLabel,
        MachineLimits, MachineOutcome, MachineStep, RuntimeCode, SessionCreationModeV1,
        TaskCreationRequestV1, TaskStateError, root_task_identity,
    };

    #[test]
    fn pre_submission_cut_recovers_task_session_and_cumulative_identity_once() {
        let mut fixture = fixture();
        let created = fixture
            .scheduler
            .create_child(
                &mut fixture.sessions,
                request(fixture.root_task, fixture.root_session, 0),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));

        let checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));
        let bytes = checkpoint.canonical_bytes();
        let decoded = ConcurrentDurableCheckpointV4::decode(&fixture.program, &bytes)
            .unwrap_or_else(|error| panic!("checkpoint decode failed: {error:?}"));
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert_eq!(decoded.created_task_count(), 2);

        let mut recovered = decoded
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        let task = recovered
            .scheduler()
            .state()
            .task(created.task_id)
            .unwrap_or_else(|| panic!("recovered task missing"));
        assert_eq!(task.status().kind(), TaskStatusKind::Submitting);
        assert!(!task.handle_is_visible());
        assert!(
            recovered
                .scheduler()
                .state()
                .parent_is_suspended(fixture.root_task)
        );
        assert!(recovered.sessions().get(created.base_session_id).is_some());

        let task_path = Arc::from(task.task_path());
        let machine = child_machine(
            Arc::clone(&fixture.program),
            fixture.execution,
            created.task_id,
            task_path,
            created.base_session_id,
            recovered.foreground().execution_budget(),
        );
        recovered
            .scheduler_mut()
            .resolve_submission(created.task_id, Ok(machine))
            .unwrap_or_else(|error| panic!("submission recovery failed: {error:?}"));
        let repeated_creation = {
            let scheduler = &mut recovered.scheduler;
            let sessions = &mut recovered.sessions;
            scheduler.create_child(
                sessions,
                request(fixture.root_task, fixture.root_session, 0),
                DEFAULT_VALUE_LIMITS,
            )
        };
        assert_eq!(repeated_creation, Err(TaskStateError::IdentityCollision));
        assert_eq!(recovered.scheduler().state().created_task_count(), 2);

        let truncated = &bytes[..bytes.len().saturating_sub(1)];
        assert_eq!(
            ConcurrentDurableCheckpointV4::decode(&fixture.program, truncated),
            Err(ConcurrentDurableCheckpointError::InvalidEncoding)
        );
    }

    #[test]
    fn submission_resolution_preserves_every_unrelated_checkpoint_component() {
        let mut fixture = fixture();
        let created = fixture
            .scheduler
            .create_child(
                &mut fixture.sessions,
                request(fixture.root_task, fixture.root_session, 0),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        let previous = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("pre-submission capture failed: {error:?}"));
        let mut recovered = previous
            .clone()
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("pre-submission recovery failed: {error:?}"));
        recovered
            .scheduler
            .resolve_submission(
                created.task_id,
                Err(HostError {
                    code: Arc::from("executor-closed"),
                    protected_diagnostic: None,
                }),
            )
            .unwrap_or_else(|error| panic!("submission failure failed: {error:?}"));
        let resolved = ConcurrentDurableCheckpointV4::capture(
            &recovered.foreground,
            &recovered.scheduler,
            &recovered.sessions,
        )
        .unwrap_or_else(|error| panic!("resolved capture failed: {error:?}"));

        assert_eq!(
            resolved.validate_submission_resolution(
                &previous,
                created.task_id,
                Arc::clone(&fixture.program),
            ),
            Ok(())
        );
        assert_eq!(
            resolved.validate_submission_resolution(
                &previous,
                fixture.root_task,
                Arc::clone(&fixture.program),
            ),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );

        assert!(matches!(
            recovered.foreground.step(),
            MachineStep::Transition(_)
        ));
        let unrelated_progress = ConcurrentDurableCheckpointV4::capture(
            &recovered.foreground,
            &recovered.scheduler,
            &recovered.sessions,
        )
        .unwrap_or_else(|error| panic!("unrelated-progress capture failed: {error:?}"));
        assert_eq!(
            unrelated_progress.validate_submission_resolution(
                &previous,
                created.task_id,
                Arc::clone(&fixture.program),
            ),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );
    }

    #[test]
    fn detached_cancelled_task_recovers_and_settles_exactly_once() {
        let mut fixture = fixture();
        let created = fixture
            .scheduler
            .create_child(
                &mut fixture.sessions,
                request(fixture.root_task, fixture.root_session, 0),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        let task_path = Arc::from(
            fixture
                .scheduler
                .state()
                .task(created.task_id)
                .unwrap_or_else(|| panic!("created task missing"))
                .task_path(),
        );
        fixture
            .scheduler
            .resolve_submission(
                created.task_id,
                Ok(child_machine(
                    Arc::clone(&fixture.program),
                    fixture.execution,
                    created.task_id,
                    task_path,
                    created.base_session_id,
                    fixture.budget.clone(),
                )),
            )
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        fixture
            .scheduler
            .state
            .detach(fixture.root_task, &detach_control(), created.handle_id)
            .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
        fixture
            .scheduler
            .cancel_execution("shutdown")
            .unwrap_or_else(|error| panic!("cancellation failed: {error:?}"));
        assert!(fixture.foreground.cancel("shutdown").is_some());

        let checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));
        let mut recovered =
            ConcurrentDurableCheckpointV4::decode(&fixture.program, &checkpoint.canonical_bytes())
                .unwrap_or_else(|error| panic!("checkpoint decode failed: {error:?}"))
                .recover(Arc::clone(&fixture.program))
                .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));

        let task = recovered
            .scheduler()
            .state()
            .task(created.task_id)
            .unwrap_or_else(|| panic!("recovered task missing"));
        assert_eq!(task.handle_state(), TaskHandleState::Detached);
        assert_eq!(
            recovered
                .scheduler()
                .state()
                .task_cancellation_reason(created.task_id),
            Some("shutdown")
        );
        assert_eq!(
            recovered.scheduler().shutdown_cohort().detached_tasks,
            [created.task_id]
        );

        for _ in 0..8 {
            if !matches!(
                recovered
                    .scheduler()
                    .state()
                    .task(created.task_id)
                    .map(|task| task.status()),
                Some(ConcurrentTaskStatusV1::Running)
            ) {
                break;
            }
            recovered
                .scheduler_mut()
                .step_next()
                .unwrap_or_else(|error| panic!("scheduler step failed: {error:?}"));
        }
        assert!(matches!(
            recovered
                .scheduler()
                .state()
                .task(created.task_id)
                .map(|task| task.status()),
            Some(ConcurrentTaskStatusV1::Cancelled(reason)) if reason.as_ref() == "shutdown"
        ));

        let settled = ConcurrentDurableCheckpointV4::capture(
            recovered.foreground(),
            recovered.scheduler(),
            recovered.sessions(),
        )
        .unwrap_or_else(|error| panic!("settled checkpoint failed: {error:?}"));
        let mut settled = settled
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("settled recovery failed: {error:?}"));
        assert_eq!(
            settled
                .scheduler_mut()
                .step_next()
                .unwrap_or_else(|error| panic!("empty scheduler step failed: {error:?}")),
            None
        );
        assert_eq!(
            settled.scheduler.state.settle(
                created.task_id,
                MachineOutcome::Succeeded(LogicalValue::unit()),
            ),
            Err(TaskStateError::InvalidTransition)
        );
    }

    #[test]
    fn malformed_scheduler_correspondences_are_rejected_before_publication() {
        let mut fixture = fixture();
        let created = fixture
            .scheduler
            .create_child(
                &mut fixture.sessions,
                request(fixture.root_task, fixture.root_session, 0),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        let task_path = Arc::from(
            fixture
                .scheduler
                .state()
                .task(created.task_id)
                .unwrap_or_else(|| panic!("created task missing"))
                .task_path(),
        );
        fixture
            .scheduler
            .resolve_submission(
                created.task_id,
                Ok(child_machine(
                    Arc::clone(&fixture.program),
                    fixture.execution,
                    created.task_id,
                    task_path,
                    created.base_session_id,
                    fixture.budget.clone(),
                )),
            )
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        let checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));

        let mut duplicate_runnable = checkpoint.clone();
        duplicate_runnable.runnable.push_back(created.task_id);
        assert_eq!(
            ConcurrentDurableCheckpointV4::decode(
                &fixture.program,
                &duplicate_runnable.canonical_bytes(),
            ),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );

        let mut cancellation_mismatch = checkpoint;
        cancellation_mismatch
            .state
            .cancellation_reasons
            .insert(created.task_id, Arc::from("not-signalled"));
        assert_eq!(
            ConcurrentDurableCheckpointV4::decode(
                &fixture.program,
                &cancellation_mismatch.canonical_bytes(),
            ),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );
    }

    #[test]
    fn combined_recovery_restores_one_shared_budget_owner() {
        let mut fixture = fixture();
        let created = running_child(&mut fixture, 0);
        let recovered = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"))
        .recover(Arc::clone(&fixture.program))
        .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));

        let foreground_budget = recovered.foreground.execution_budget();
        let scheduler_budget = &recovered.scheduler.execution_budget;
        let child_budget = recovered
            .scheduler
            .machines
            .get(&created.task_id)
            .unwrap_or_else(|| panic!("recovered child machine missing"))
            .execution_budget();
        assert!(foreground_budget.same_owner(scheduler_budget));
        assert!(foreground_budget.same_owner(&child_budget));
    }

    #[test]
    fn malformed_and_mixed_budget_projections_are_rejected() {
        let mut fixture = fixture();
        let _ = running_child(&mut fixture, 0);
        let checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));

        let mut malformed = checkpoint.clone();
        malformed.execution_budget.remaining_transitions =
            malformed.execution_budget.maximum_transitions + 1;
        assert_eq!(
            ConcurrentDurableCheckpointV4::decode(&fixture.program, &malformed.canonical_bytes(),),
            Err(ConcurrentDurableCheckpointError::Machine(
                crate::MachineRecoveryError::InvalidCheckpoint,
            ))
        );

        let mut mixed = checkpoint;
        mixed.execution_budget.maximum_transitions += 1;
        mixed.execution_budget.remaining_transitions += 1;
        assert_eq!(
            ConcurrentDurableCheckpointV4::decode(&fixture.program, &mixed.canonical_bytes()),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );
    }

    #[test]
    fn capture_retries_a_torn_budget_and_machine_interleaving() {
        let fixture = fixture();
        let before = fixture.budget.snapshot();
        let (task_id, task_path) = standalone_child_coordinate(fixture.execution);
        let mut racer = child_machine(
            Arc::clone(&fixture.program),
            fixture.execution,
            task_id,
            task_path,
            fixture.root_session,
            fixture.budget.clone(),
        );

        let checkpoint = ConcurrentDurableCheckpointV4::capture_with_interleaving(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
            |attempt| {
                if attempt == 0 {
                    assert!(matches!(
                        racer.step(),
                        MachineStep::Transition(MachineLabel::Deterministic { .. })
                    ));
                }
            },
        )
        .unwrap_or_else(|error| panic!("checkpoint retry failed: {error:?}"));

        assert_eq!(checkpoint.execution_budget, fixture.budget.snapshot());
        assert_eq!(checkpoint.execution_budget.revision, before.revision + 1);
    }

    #[test]
    fn capture_rejects_continuous_budget_and_machine_interleavings() {
        let fixture = fixture();
        let (task_id, task_path) = standalone_child_coordinate(fixture.execution);
        let mut racers = (0..MAX_CAPTURE_ATTEMPTS)
            .map(|_| {
                child_machine(
                    Arc::clone(&fixture.program),
                    fixture.execution,
                    task_id,
                    Arc::clone(&task_path),
                    fixture.root_session,
                    fixture.budget.clone(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ConcurrentDurableCheckpointV4::capture_with_interleaving(
                &fixture.foreground,
                &fixture.scheduler,
                &fixture.sessions,
                |attempt| {
                    assert!(matches!(
                        racers[attempt].step(),
                        MachineStep::Transition(MachineLabel::Deterministic { .. })
                    ));
                },
            ),
            Err(ConcurrentDurableCheckpointError::CaptureRace)
        );
    }

    #[test]
    fn post_recovery_final_unit_charges_the_shared_budget() {
        let mut fixture = fixture();
        let created = running_child(&mut fixture, 0);
        let mut checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));
        checkpoint.execution_budget.remaining_transitions = 1;
        checkpoint.execution_budget.revision = checkpoint.execution_budget.maximum_transitions - 1;
        let mut recovered = checkpoint
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
        let before = recovered.foreground.budget_checkpoint();
        assert_eq!(before.remaining_transitions, 1);

        for _ in 0..2 {
            recovered
                .scheduler
                .step_next()
                .unwrap_or_else(|error| panic!("scheduler step failed: {error:?}"));
        }

        assert_eq!(
            recovered
                .scheduler
                .state
                .task(created.task_id)
                .map(|task| task.status()),
            Some(&ConcurrentTaskStatusV1::Succeeded(LogicalValue::unit()))
        );
        let after = recovered.foreground.budget_checkpoint();
        assert_eq!(after.remaining_transitions, 0);
        assert_eq!(after.revision, before.revision + 1);
        assert_eq!(recovered.scheduler.execution_budget(), after);
        assert!(matches!(
            recovered.foreground.step(),
            MachineStep::Transition(MachineLabel::Failure(ref failure))
                if failure.code == RuntimeCode::DeterministicTransitionBudget
        ));
        assert_eq!(recovered.foreground.budget_checkpoint(), after);
    }

    /// A graph cut must preserve root settlement before foreground publication.
    #[test]
    fn settled_root_survives_graph_checkpoint_round_trip() {
        let mut fixture = fixture();
        let mut outcome = None;
        for _ in 0..100 {
            match fixture.foreground.step() {
                MachineStep::Transition(MachineLabel::TaskSettled(settled)) => {
                    outcome = Some(settled);
                    break;
                }
                MachineStep::Transition(_) => {}
                other => panic!("unexpected root step: {other:?}"),
            }
        }
        let outcome = outcome.unwrap_or_else(|| panic!("root did not settle"));
        fixture
            .scheduler
            .state
            .settle(fixture.root_task, outcome)
            .unwrap_or_else(|error| panic!("root settlement failed: {error:?}"));
        let checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("settled-root capture failed: {error:?}"));
        assert!(
            crate::ConcurrentDurableEvidenceV4::new(
                crate::DurableCommitCutV1::TaskSettlement,
                fixture.root_task,
                checkpoint.clone(),
            )
            .is_ok()
        );
        let decoded =
            ConcurrentDurableCheckpointV4::decode(&fixture.program, &checkpoint.canonical_bytes())
                .unwrap_or_else(|error| panic!("settled-root decode failed: {error:?}"));
        let recovered = decoded
            .recover(Arc::clone(&fixture.program))
            .unwrap_or_else(|error| panic!("settled-root recovery failed: {error:?}"));
        assert_eq!(recovered.scheduler().state(), fixture.scheduler.state());
    }

    /// Pending outcomes are logical state; physical ownership is not settlement.
    #[test]
    fn pending_child_and_root_state_round_trip_and_reject_inconsistency() {
        let mut fixture = fixture();
        let child = running_child(&mut fixture, 0);
        fixture
            .scheduler
            .state
            .stage_task_outcome(
                child.task_id,
                MachineOutcome::Succeeded(LogicalValue::unit()),
            )
            .unwrap_or_else(|error| panic!("child staging failed: {error:?}"));
        fixture
            .scheduler
            .state
            .stage_task_outcome(
                fixture.root_task,
                MachineOutcome::Succeeded(LogicalValue::unit()),
            )
            .unwrap_or_else(|error| panic!("root staging failed: {error:?}"));
        let checkpoint = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("pending capture failed: {error:?}"));
        let bytes = checkpoint.canonical_bytes();
        let decoded = ConcurrentDurableCheckpointV4::decode(&fixture.program, &bytes)
            .unwrap_or_else(|error| panic!("pending decode failed: {error:?}"));
        assert_eq!(decoded, checkpoint);
        let mut legacy = bytes;
        legacy[..8].copy_from_slice(b"GNTCDP03");
        assert!(ConcurrentDurableCheckpointV4::decode(&fixture.program, &legacy).is_err());
        let mut malformed = checkpoint.clone();
        malformed.state.root.status = ConcurrentTaskStatusV1::Succeeded(LogicalValue::unit());
        assert!(
            ConcurrentDurableCheckpointV4::decode(&fixture.program, &malformed.canonical_bytes())
                .is_err()
        );
        let mut malformed = checkpoint;
        malformed.state.tasks[0].status = ConcurrentTaskStatusV1::Succeeded(LogicalValue::unit());
        assert!(
            ConcurrentDurableCheckpointV4::decode(&fixture.program, &malformed.canonical_bytes())
                .is_err()
        );
    }

    /// Coordinator capture needs no scheduler and rejects incomplete live sets.
    #[test]
    fn coordinator_capture_preserves_graph_and_rejects_missing_machine() {
        let mut fixture = fixture();
        let child = running_child(&mut fixture, 0);
        let coordinator = crate::ExecutionCoordinator::new_with_budget(
            fixture.scheduler.state.clone(),
            fixture.sessions.clone(),
            fixture.budget.clone(),
        )
        .unwrap_or_else(|error| panic!("coordinator failed: {error:?}"));
        let checkpoint = coordinator
            .capture_checkpoint(&fixture.foreground, &fixture.scheduler.machines)
            .unwrap_or_else(|error| panic!("coordinator capture failed: {error:?}"));
        let reference = ConcurrentDurableCheckpointV4::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("reference capture failed: {error:?}"));
        assert_eq!(checkpoint, reference);
        assert!(coordinator.try_snapshot().is_some());
        fixture.scheduler.machines.remove(&child.task_id);
        assert_eq!(
            coordinator.capture_checkpoint(&fixture.foreground, &fixture.scheduler.machines),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );
    }

    struct Fixture {
        program: Arc<MachineProgram>,
        execution: ProtocolIdentity,
        root_task: ProtocolIdentity,
        root_session: ProtocolIdentity,
        budget: ExecutionBudget,
        foreground: Machine,
        scheduler: ConcurrentSchedulerV1,
        sessions: LogicalSessionRegistryV1,
    }

    fn fixture() -> Fixture {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 1);
        let root_task = root_task_identity(execution);
        let root_session = fresh(IdentityKind::Session, 2);
        let sessions = LogicalSessionRegistryV1::new(
            execution,
            root_session,
            SessionCreationModeV1::GantryRoot,
            CanonicalTranscriptV1::empty(),
        )
        .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
        let foreground = Machine::new_with_context(
            Arc::clone(&program),
            &path("crate::main"),
            Vec::new(),
            execution,
            machine_limits(),
            None,
            Some(root_session),
        )
        .unwrap_or_else(|error| panic!("foreground machine failed: {error:?}"));
        let budget = foreground.execution_budget();
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        let scheduler = ConcurrentSchedulerV1::new(state, budget.clone())
            .unwrap_or_else(|error| panic!("scheduler construction failed: {error:?}"));
        Fixture {
            program,
            execution,
            root_task,
            root_session,
            budget,
            foreground,
            scheduler,
            sessions,
        }
    }

    fn running_child(fixture: &mut Fixture, occurrence: u64) -> crate::TaskCreationV1 {
        let created = fixture
            .scheduler
            .create_child(
                &mut fixture.sessions,
                request(fixture.root_task, fixture.root_session, occurrence),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("task creation failed: {error:?}"));
        let task_path = Arc::from(
            fixture
                .scheduler
                .state()
                .task(created.task_id)
                .unwrap_or_else(|| panic!("created task missing"))
                .task_path(),
        );
        fixture
            .scheduler
            .resolve_submission(
                created.task_id,
                Ok(child_machine(
                    Arc::clone(&fixture.program),
                    fixture.execution,
                    created.task_id,
                    task_path,
                    created.base_session_id,
                    fixture.budget.clone(),
                )),
            )
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        created
    }

    fn request(
        parent_task_id: ProtocolIdentity,
        parent_session_id: ProtocolIdentity,
        occurrence: u64,
    ) -> TaskCreationRequestV1 {
        TaskCreationRequestV1 {
            parent_task_id,
            handle_name: Arc::from("child"),
            workflow: path("crate::main"),
            spawn_site: position(0),
            spawn_occurrence: occurrence,
            result_type: TypeDescriptor::UNIT,
            captures: Vec::new(),
            inherited_agent: None,
            parent_session_id,
        }
    }

    fn detach_control() -> TaskControlSite {
        TaskControlSite {
            id: StaticSiteId::new(path("crate::main"), position(9)),
            kind: TaskControlSiteKind::Detach,
            handles: vec![Arc::from("child")],
            source: source_span(),
        }
    }

    fn child_machine(
        program: Arc<MachineProgram>,
        execution: ProtocolIdentity,
        task_id: ProtocolIdentity,
        task_path: Arc<[Arc<str>]>,
        session: ProtocolIdentity,
        budget: ExecutionBudget,
    ) -> Machine {
        Machine::new_concurrent_task_with_context(
            program,
            &path("crate::child"),
            Vec::new(),
            execution,
            task_id,
            task_path,
            machine_limits(),
            budget,
            None,
            Some(session),
        )
        .unwrap_or_else(|error| panic!("child machine failed: {error:?}"))
    }

    fn standalone_child_coordinate(
        execution: ProtocolIdentity,
    ) -> (ProtocolIdentity, Arc<[Arc<str>]>) {
        let task_path = Arc::from([Arc::from("spawn:crate::main:0:0")]);
        let task_id = ProtocolIdentity::derive(
            IdentityKind::Task,
            &task_identity_key(execution, &task_path),
        )
        .unwrap_or_else(|error| panic!("child task identity failed: {error}"));
        (task_id, task_path)
    }

    fn program() -> Arc<MachineProgram> {
        Arc::new(
            MachineProgram::new(vec![workflow("crate::child"), workflow("crate::main")])
                .unwrap_or_else(|error| panic!("program failed: {error:?}")),
        )
    }

    fn workflow(name: &str) -> Workflow {
        Workflow {
            path: path(name),
            parameters: Vec::<Parameter>::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: position(0),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: position(1),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }
    }

    fn machine_limits() -> MachineLimits {
        MachineLimits::new(32, 4, 4, 8, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive machine limits"))
    }

    fn path(value: &str) -> CanonicalPath {
        CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
    }

    fn position(value: u64) -> StructuralPosition {
        StructuralPosition::new(vec![value])
            .unwrap_or_else(|error| panic!("position failed: {error}"))
    }

    fn source_span() -> SourceSpan {
        let limits = SourceLimits::new(1, 64, 64, 1, 1)
            .unwrap_or_else(|error| panic!("source limits failed: {error:?}"));
        let mut builder = SourceSnapshotBuilder::new(limits);
        let id = builder
            .add_file("main.gnt", b"detach(child)")
            .unwrap_or_else(|error| panic!("source fixture failed: {error:?}"));
        let snapshot = builder.finish();
        let record = snapshot
            .get(&id)
            .unwrap_or_else(|| panic!("source record missing"));
        SourceSpan::new(
            record,
            ByteSpan::new(0, 1).unwrap_or_else(|error| panic!("span failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("source span failed: {error:?}"))
    }

    fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
        ProtocolIdentity::from_fresh_material(kind, [byte; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"))
    }
}
