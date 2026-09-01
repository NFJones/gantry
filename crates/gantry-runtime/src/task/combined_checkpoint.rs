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
    LogicalSessionRegistryCheckpointV1, LogicalSessionRegistryV1, Machine, MachineCheckpointV1,
    MachineOutcome, MachineRecoveryError, MachineStatus, SessionCreationModeV1,
    SessionEstablishmentV1, SessionRecoveryError,
};

use super::{
    ConcurrentSchedulerV1, ConcurrentTaskRecordV1, ConcurrentTaskStateV1, ConcurrentTaskStatusV1,
    DynamicTaskHandleIdentity, TaskCaptureV1, TaskFailureV1, task_identity_key, task_path_frame,
};

const MAGIC: &[u8; 8] = b"GNTCDP01";

/// One versioned commit-cut snapshot of the composed concurrent-durable runtime.
///
/// The checkpoint owns no evaluator implementation. It projects the existing
/// foreground machine, scheduler task state, child machine checkpoints, and
/// logical-session registry into one canonical recovery boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentDurableCheckpointV1 {
    foreground: MachineCheckpointV1,
    sessions: LogicalSessionRegistryCheckpointV1,
    state: TaskStateCheckpointV1,
    machines: BTreeMap<ProtocolIdentity, MachineCheckpointV1>,
    runnable: VecDeque<ProtocolIdentity>,
}

impl ConcurrentDurableCheckpointV1 {
    /// Captures one complete combined state after validating every correspondence.
    pub fn capture(
        foreground: &Machine,
        scheduler: &ConcurrentSchedulerV1,
        sessions: &LogicalSessionRegistryV1,
    ) -> Result<Self, ConcurrentDurableCheckpointError> {
        let checkpoint = Self {
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
        let recovered_sessions =
            LogicalSessionRegistryV1::recover_from_checkpoint(checkpoint.sessions.clone())?;
        let recovered_state = checkpoint
            .state
            .recover(&recovered_sessions, checkpoint.foreground.value_limits())?;
        if recovered_state != scheduler.state {
            return Err(ConcurrentDurableCheckpointError::InvalidCheckpoint);
        }
        checkpoint.validate()?;
        Ok(checkpoint)
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

    /// Returns one child task's portable status, excluding the foreground root.
    #[must_use]
    pub fn task_status(&self, task_id: ProtocolIdentity) -> Option<TaskStatusKind> {
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
    pub const fn foreground_checkpoint(&self) -> &MachineCheckpointV1 {
        &self.foreground
    }

    /// Returns the exact session checkpoint composed into this graph cut.
    #[must_use]
    pub const fn session_checkpoint(&self) -> &LogicalSessionRegistryCheckpointV1 {
        &self.sessions
    }

    /// Encodes the unique version-one combined checkpoint.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.raw(MAGIC);
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
        let foreground = MachineCheckpointV1::decode(program, reader.bytes()?)?;
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
                let checkpoint = MachineCheckpointV1::decode(program, reader.bytes()?)?;
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
        let foreground = Machine::recover_from_checkpoint(Arc::clone(&program), self.foreground)?;
        let mut machines = BTreeMap::new();
        for (task_id, checkpoint) in self.machines {
            let machine = Machine::recover_from_checkpoint(Arc::clone(&program), checkpoint)?;
            machines.insert(task_id, machine);
        }
        Ok(RecoveredConcurrentDurableExecutionV1 {
            foreground,
            scheduler: ConcurrentSchedulerV1 {
                state,
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
        if self.foreground.execution_id() != state.execution_id
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
            if machine.execution_id() != state.execution_id
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
}

/// Rejection of malformed or internally inconsistent combined recovery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcurrentDurableCheckpointError {
    /// Bytes are truncated, noncanonical, or use another version.
    InvalidEncoding,
    /// Task graph, scheduler, machine, or session correspondences disagree.
    InvalidCheckpoint,
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
        writer.u64(self.maximum_tasks);
        writer.u64(self.created_tasks);
        writer.count(self.tasks.len());
        for task in &self.tasks {
            write_task(writer, task);
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

fn write_task(writer: &mut Writer, task: &ConcurrentTaskRecordV1) {
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
    })
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
    use gantry_ir::generated::TaskControlSiteKind;
    use gantry_ir::{
        CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
        StaticSiteId, StructuralPosition, TaskControlSite, TypeDescriptor, Workflow,
    };

    use super::{ConcurrentDurableCheckpointError, ConcurrentDurableCheckpointV1};
    use crate::{
        CanonicalTranscriptV1, ConcurrentSchedulerV1, ConcurrentTaskStateV1,
        ConcurrentTaskStatusV1, LogicalSessionRegistryV1, Machine, MachineLimits, MachineOutcome,
        SessionCreationModeV1, TaskCreationRequestV1, TaskStateError,
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

        let checkpoint = ConcurrentDurableCheckpointV1::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));
        let bytes = checkpoint.canonical_bytes();
        let decoded = ConcurrentDurableCheckpointV1::decode(&fixture.program, &bytes)
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

        let machine = child_machine(
            Arc::clone(&fixture.program),
            fixture.execution,
            created.base_session_id,
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
            ConcurrentDurableCheckpointV1::decode(&fixture.program, truncated),
            Err(ConcurrentDurableCheckpointError::InvalidEncoding)
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
        fixture
            .scheduler
            .resolve_submission(
                created.task_id,
                Ok(child_machine(
                    Arc::clone(&fixture.program),
                    fixture.execution,
                    created.base_session_id,
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

        let checkpoint = ConcurrentDurableCheckpointV1::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));
        let mut recovered =
            ConcurrentDurableCheckpointV1::decode(&fixture.program, &checkpoint.canonical_bytes())
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

        let settled = ConcurrentDurableCheckpointV1::capture(
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
        fixture
            .scheduler
            .resolve_submission(
                created.task_id,
                Ok(child_machine(
                    Arc::clone(&fixture.program),
                    fixture.execution,
                    created.base_session_id,
                )),
            )
            .unwrap_or_else(|error| panic!("submission failed: {error:?}"));
        let checkpoint = ConcurrentDurableCheckpointV1::capture(
            &fixture.foreground,
            &fixture.scheduler,
            &fixture.sessions,
        )
        .unwrap_or_else(|error| panic!("checkpoint capture failed: {error:?}"));

        let mut duplicate_runnable = checkpoint.clone();
        duplicate_runnable.runnable.push_back(created.task_id);
        assert_eq!(
            ConcurrentDurableCheckpointV1::decode(
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
            ConcurrentDurableCheckpointV1::decode(
                &fixture.program,
                &cancellation_mismatch.canonical_bytes(),
            ),
            Err(ConcurrentDurableCheckpointError::InvalidCheckpoint)
        );
    }

    struct Fixture {
        program: Arc<MachineProgram>,
        execution: ProtocolIdentity,
        root_task: ProtocolIdentity,
        root_session: ProtocolIdentity,
        foreground: Machine,
        scheduler: ConcurrentSchedulerV1,
        sessions: LogicalSessionRegistryV1,
    }

    fn fixture() -> Fixture {
        let program = program();
        let execution = fresh(IdentityKind::Execution, 1);
        let root_task = ProtocolIdentity::derive(IdentityKind::Task, b"{\"root\":true}")
            .unwrap_or_else(|error| panic!("root task identity failed: {error}"));
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
        let state = ConcurrentTaskStateV1::new(execution, root_task, 8)
            .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
        Fixture {
            program,
            execution,
            root_task,
            root_session,
            foreground,
            scheduler: ConcurrentSchedulerV1::new(state),
            sessions,
        }
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
        session: ProtocolIdentity,
    ) -> Machine {
        Machine::new_concurrent_task_with_context(
            program,
            &path("crate::child"),
            Vec::new(),
            execution,
            machine_limits(),
            None,
            Some(session),
        )
        .unwrap_or_else(|error| panic!("child machine failed: {error:?}"))
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
