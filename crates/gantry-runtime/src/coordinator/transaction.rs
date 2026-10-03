//! Exclusive journal-first graph staging over the existing coordinator.
//!
//! Machine borrows prevent their drivers from advancing during a transaction.
//! Only private copies advance; observers retain the previous coordinator cut.
//! Dropping before submission rolls back. Dropping after submission fences
//! semantic publication because the journal result may be indeterminate.

use super::*;
use crate::machine::ResourceAdmissionGuard;
use crate::recovery::validate_budget_successor;
use crate::{
    ConcurrentDurableCheckpointV4, DurableCommitCoordinatorV1, DurableCommitCutV1,
    DurableCommitError, DurableEvidenceCommitV1, DurableOperationEvidenceV1, Machine,
    TaskDriverOwnershipV1,
};

#[cfg(test)]
mod tests;

/// Exclusive staged machine, task, session, and budget successor.
///
/// This primitive must be driven by a must-settle execution owner, not a public
/// waiter. It does not submit executor work or drive event delivery. Such work
/// may depend on the successor only after `commit` succeeds.
pub struct DurableGraphTransaction<'a> {
    coordinator: &'a ExecutionCoordinator,
    foreground: &'a mut Machine,
    children: &'a mut BTreeMap<ProtocolIdentity, Machine>,
    staged_foreground: Machine,
    staged_children: BTreeMap<ProtocolIdentity, Machine>,
    staged_foreground_resource_admission_guard: Option<ResourceAdmissionGuard>,
    staged_child_resource_admission_guards: BTreeMap<ProtocolIdentity, ResourceAdmissionGuard>,
    tasks: ConcurrentTaskStateV1,
    sessions: LogicalSessionRegistryV1,
    budget: ExecutionBudget,
    original_budget: ExecutionBudgetSnapshot,
    resource_policy: Option<(Option<u64>, Option<u64>)>,
    retained_resource_limit: Option<u64>,
    resource_records: Vec<crate::RecoveredResourceRecord>,
    original_checkpoint: Box<ConcurrentDurableCheckpointV4>,
    resource_finish: Option<(
        usize,
        gantry_ir::OwnerGeneration,
        crate::ResourceFinishTransition,
        Vec<gantry_ir::Charge>,
    )>,
    resource_owner: Option<(
        usize,
        (gantry_ir::OwnerGeneration, gantry_ir::OwnerGeneration),
        Vec<gantry_ir::Charge>,
    )>,
    commit_started: bool,
    installed: bool,
    events: Vec<(
        gantry_core::event::EventEnvelope,
        crate::DurableEventPlanV1,
        Vec<gantry_host::event::ProtectedPayload>,
    )>,
    operation: Option<DurableOperationEvidenceV1>,
}

impl ExecutionCoordinator {
    /// Reserves publication and copies a quiescent graph onto a private budget.
    ///
    /// Fails without mutation if another transaction owns publication or the
    /// supplied machine set does not represent the coordinator's current cut.
    pub fn stage_graph<'a>(
        &'a self,
        foreground: &'a mut Machine,
        children: &'a mut BTreeMap<ProtocolIdentity, Machine>,
    ) -> Result<DurableGraphTransaction<'a>, TaskStateError> {
        let mut state = lock(&self.inner.state);
        require_publication_available(&state)?;
        let resource_records =
            ConcurrentDurableCheckpointV4::capture_resource_records(state.resources.as_ref())
                .map_err(|_| TaskStateError::ResourceStateUnsupported)?;
        if state
            .durable_resource_baseline
            .as_ref()
            .is_some_and(|baseline| baseline != &resource_records)
        {
            return Err(TaskStateError::ResourceStateUnsupported);
        }
        let original_budget = state
            .execution_budget
            .as_ref()
            .map(ExecutionBudget::snapshot)
            .ok_or(TaskStateError::InvalidTaskMachine)?;
        let successor_budget = foreground.budget_checkpoint();
        validate_budget_successor(&original_budget, &successor_budget)
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        if children
            .values()
            .any(|machine| machine.budget_checkpoint() != successor_budget)
        {
            return Err(TaskStateError::InvalidTaskMachine);
        }
        let budget = ExecutionBudget::recover_from_checkpoint(successor_budget)
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        let (staged_foreground, staged_foreground_resource_admission_guard) = foreground
            .clone_with_staged_budget(budget.clone())
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        let mut staged_children = BTreeMap::new();
        let mut staged_child_resource_admission_guards = BTreeMap::new();
        for (id, machine) in children.iter() {
            let (staged, guard) = machine
                .clone_with_staged_budget(budget.clone())
                .map_err(|_| TaskStateError::InvalidTaskMachine)?;
            staged_children.insert(*id, staged);
            if let Some(guard) = guard {
                staged_child_resource_admission_guards.insert(*id, guard);
            }
        }
        let (tasks, sessions) = if let Some((tasks, sessions)) = &state.durable_graph_baseline {
            (tasks.clone(), sessions.clone())
        } else {
            (state.tasks.clone(), state.sessions.clone())
        };
        let original_checkpoint = ConcurrentDurableCheckpointV4::capture_coordinated(
            &staged_foreground,
            &staged_children,
            &tasks,
            &sessions,
            &budget,
            state
                .resources
                .as_ref()
                .map(|registry| (registry.live_limit(), registry.pending_limit())),
            state
                .resources
                .as_ref()
                .and_then(crate::ResourceRegistry::retained_limit),
        )
        .and_then(|checkpoint| {
            checkpoint.with_resource_records(foreground.program_arc(), resource_records.clone())
        })
        .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        state.durable_publication_reserved = true;
        Ok(DurableGraphTransaction {
            coordinator: self,
            foreground,
            children,
            staged_foreground,
            staged_children,
            staged_foreground_resource_admission_guard,
            staged_child_resource_admission_guards,
            tasks,
            sessions,
            budget,
            original_budget,
            resource_policy: state
                .resources
                .as_ref()
                .map(|registry| (registry.live_limit(), registry.pending_limit())),
            retained_resource_limit: state
                .resources
                .as_ref()
                .and_then(crate::ResourceRegistry::retained_limit),
            resource_records,
            original_checkpoint: Box::new(original_checkpoint),
            resource_finish: None,
            resource_owner: None,
            commit_started: false,
            installed: false,
            events: Vec::new(),
            operation: None,
        })
    }
}

impl DurableGraphTransaction<'_> {
    /// Returns the immutable executable needed to validate authoritative finish history.
    #[must_use]
    pub fn program_arc(&self) -> Arc<gantry_ir::MachineProgram> {
        self.staged_foreground.program_arc()
    }

    /// Stages one logical finish without changing the published registry or physical ownership.
    ///
    /// Commit must use ResourceFinish and preserve all other graph facts. A second transition,
    /// operation or event combination refuses; dropping the transaction before submission rolls back.
    pub fn stage_resource_finish(
        &mut self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        transition: crate::ResourceFinishTransition,
    ) -> Result<(), CoordinatorResourceRefusal> {
        self.stage_resource_finish_with_charges(subject, owner, transition, &[])
    }

    /// Privately stages a bounded explicit release vector with one logical Begin transition.
    /// Refusal preserves the staged record; publication requires exact charged evidence.
    pub fn stage_resource_finish_with_charges(
        &mut self,
        subject: &crate::ResourceSubjectBinding,
        owner: gantry_ir::OwnerGeneration,
        transition: crate::ResourceFinishTransition,
        charges: &[gantry_ir::Charge],
    ) -> Result<(), CoordinatorResourceRefusal> {
        if charges.len() > crate::ResourceFinishEvidenceV1::MAXIMUM_CHARGES {
            return Err(CoordinatorResourceRefusal::Task(
                TaskStateError::ResourceStateUnsupported,
            ));
        }
        if self.resource_finish.is_some()
            || self.resource_owner.is_some()
            || self.operation.is_some()
            || !self.events.is_empty()
        {
            return Err(CoordinatorResourceRefusal::Task(
                TaskStateError::ResourceStateUnsupported,
            ));
        }
        let index = self
            .resource_records
            .iter()
            .position(|record| record.subject() == subject)
            .ok_or(CoordinatorResourceRefusal::Registry(
                crate::ResourceRegistryRefusal::UnknownSubject,
            ))?;
        let candidate = self.resource_records[index]
            .stage_finish_with_charges(owner, transition, charges)
            .map_err(|error| {
                CoordinatorResourceRefusal::Registry(crate::ResourceRegistryRefusal::Admission(
                    error,
                ))
            })?;
        self.resource_records[index] = candidate;
        self.resource_finish = Some((index, owner, transition, charges.to_vec()));
        Ok(())
    }

    /// Privately stages exact same-cleanup-task advancement without publishing accounting.
    /// Existing transfer fences and the authored-vector bound precede candidate replacement.
    /// Commit must use ResourceOwnerAdvance with no other semantic mutation or event.
    pub fn stage_resource_owner_advance(
        &mut self,
        subject: &crate::ResourceSubjectBinding,
        generations: (gantry_ir::OwnerGeneration, gantry_ir::OwnerGeneration),
        charges: &[gantry_ir::Charge],
    ) -> Result<(), CoordinatorResourceRefusal> {
        if charges.len() > crate::ResourceOwnerEvidenceV1::MAXIMUM_CHARGES
            || self.resource_finish.is_some()
            || self.resource_owner.is_some()
            || self.operation.is_some()
            || !self.events.is_empty()
        {
            return Err(CoordinatorResourceRefusal::Task(
                TaskStateError::ResourceStateUnsupported,
            ));
        }
        let index = self
            .resource_records
            .iter()
            .position(|record| record.subject() == subject)
            .ok_or(CoordinatorResourceRefusal::Registry(
                crate::ResourceRegistryRefusal::UnknownSubject,
            ))?;
        let candidate = self.resource_records[index]
            .stage_owner_advance(generations.0, generations.1, charges)
            .map_err(CoordinatorResourceRefusal::Registry)?;
        self.resource_records[index] = candidate;
        self.resource_owner = Some((index, generations, charges.to_vec()));
        Ok(())
    }

    /// Validates the complete private accounting set before any journal submission.
    fn reconstruct_staged_resources(&self) -> Result<crate::ResourceRegistry, DurableCommitError> {
        let (live, pending) = self
            .resource_policy
            .ok_or(DurableCommitError::InvalidState)?;
        let encoded = self
            .resource_records
            .iter()
            .map(|record| {
                crate::encode_resource_recovery_envelope(
                    record,
                    crate::task::MAXIMUM_RESOURCE_SECTION_BYTES,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DurableCommitError::InvalidState)?;
        let inputs = encoded
            .iter()
            .zip(&self.resource_records)
            .map(|(bytes, record)| (bytes.as_slice(), record.owner(), record.task_owner()))
            .collect::<Vec<_>>();
        crate::ResourceRegistry::reconstruct_recovery_envelopes(
            self.staged_foreground.program_arc(),
            &inputs,
            crate::task::MAXIMUM_RESOURCE_SECTION_BYTES,
            (live, pending, self.retained_resource_limit),
        )
        .map_err(|_| DurableCommitError::InvalidState)
    }

    /// Freezes the causal event and delivery policy before journal submission.
    ///
    /// Sets the primary occurrence. Distinct task cancellation labels may be
    /// appended; all occurrences commit before graph publication.
    pub fn set_event(
        &mut self,
        event: gantry_core::event::EventEnvelope,
        plan: crate::DurableEventPlanV1,
        payloads: Vec<gantry_host::event::ProtectedPayload>,
    ) -> Result<(), DurableCommitError> {
        if !self.events.is_empty() || event.execution_id() != Some(self.tasks.execution_id()) {
            return Err(DurableCommitError::InvalidState);
        }
        self.events.push((event, plan, payloads));
        Ok(())
    }

    /// Appends one newly emitted task cancellation label to the same causal cut.
    /// Duplicate targets and labels not represented by the staged machines reject.
    pub fn add_task_cancellation_event(
        &mut self,
        event: gantry_core::event::EventEnvelope,
        plan: crate::DurableEventPlanV1,
    ) -> Result<(), DurableCommitError> {
        let task = event.task_id().ok_or(DurableCommitError::InvalidState)?;
        let machine = if task == self.staged_foreground.task_id() {
            Some(&self.staged_foreground)
        } else {
            self.staged_children.get(&task)
        }
        .ok_or(DurableCommitError::InvalidState)?;
        let checkpoint = machine.checkpoint();
        if event.execution_id() != Some(self.tasks.execution_id())
            || event.kind() != gantry_core::portable::EventKind::Cancellation
            || !event.protected_references().is_empty()
            || checkpoint.cancellation_reason().is_none()
            || !self
                .original_checkpoint
                .task_checkpoint(task)
                .is_some_and(|old| old.cancellation_reason().is_none())
        {
            return Err(DurableCommitError::InvalidState);
        }
        // Use the occurrence index's strict target validation, not string matching.
        let cause = ProtocolIdentity::from_storage_material([0; 32]);
        let key = crate::durable_event::occurrence_key(cause, &event)
            .map_err(|_| DurableCommitError::InvalidState)?;
        if key.1 != Some(task)
            || self.events.iter().any(|(existing, _, _)| {
                crate::durable_event::occurrence_key(cause, existing).ok() == Some(key)
            })
        {
            return Err(DurableCommitError::InvalidState);
        }
        self.events.push((event, plan, Vec::new()));
        Ok(())
    }

    /// Attaches operation coordinates to an operation-related graph cut.
    pub fn set_operation(
        &mut self,
        operation: DurableOperationEvidenceV1,
    ) -> Result<(), DurableCommitError> {
        if self.operation.is_some() {
            return Err(DurableCommitError::InvalidState);
        }
        self.operation = Some(operation);
        Ok(())
    }

    /// Installs one newly submitted child on this transaction's private budget.
    ///
    /// Callers first resolve the staged task from `submitting` to `running` in
    /// `update`, then add the corresponding machine before committing the same
    /// checkpoint. The original child machine is never published directly.
    pub fn install_child_machine(
        &mut self,
        task_id: ProtocolIdentity,
        machine: Machine,
    ) -> Result<(), TaskStateError> {
        let task_path = self
            .tasks
            .task(task_id)
            .filter(|task| matches!(task.status(), ConcurrentTaskStatusV1::Running))
            .map(|task| task.task_path().to_vec())
            .ok_or(TaskStateError::InvalidTaskMachine)?;
        if self.staged_children.contains_key(&task_id) {
            return Err(TaskStateError::InvalidTaskMachine);
        }
        let (machine, guard) = machine
            .clone_with_staged_budget(self.budget.clone())
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        if !machine.has_concurrent_task_context(task_id, &task_path) {
            return Err(TaskStateError::InvalidTaskMachine);
        }
        self.staged_children.insert(task_id, machine);
        if let Some(guard) = guard {
            self.staged_child_resource_admission_guards
                .insert(task_id, guard);
        }
        Ok(())
    }

    /// Mutates the private successor synchronously using existing semantic APIs.
    ///
    /// The callback must not invoke integrations or retain budget handles. It
    /// must preserve correspondence between task state and the machine set.
    pub fn update<T>(
        &mut self,
        update: impl FnOnce(
            &mut Machine,
            &mut BTreeMap<ProtocolIdentity, Machine>,
            &mut ConcurrentTaskStateV1,
            &mut LogicalSessionRegistryV1,
        ) -> T,
    ) -> T {
        update(
            &mut self.staged_foreground,
            &mut self.staged_children,
            &mut self.tasks,
            &mut self.sessions,
        )
    }

    /// Commits the frozen successor, installs it, then wakes observers unlocked.
    ///
    /// Any error after journal submission leaves publication fenced. Recovery
    /// under a new owner must determine whether the submitted cut committed.
    pub async fn commit(
        mut self,
        commits: &mut DurableCommitCoordinatorV1<'_>,
        cut: DurableCommitCutV1,
        affected_task: ProtocolIdentity,
    ) -> Result<DurableEvidenceCommitV1, DurableCommitError> {
        let checkpoint = ConcurrentDurableCheckpointV4::capture_coordinated(
            &self.staged_foreground,
            &self.staged_children,
            &self.tasks,
            &self.sessions,
            &self.budget,
            self.resource_policy,
            self.retained_resource_limit,
        )
        .and_then(|checkpoint| {
            checkpoint.with_resource_records(
                self.staged_foreground.program_arc(),
                self.resource_records.clone(),
            )
        })
        .map_err(|error| {
            DurableCommitError::Evidence(crate::DurableEvidenceError::ConcurrentCheckpoint(error))
        })?;
        let committed_budget = checkpoint.execution_budget();
        let task_ids = checkpoint.task_ids();
        let submission_resolution = if self.operation.is_none() {
            checkpoint
                .submission_resolution_task(&self.original_checkpoint.hidden_submission_task_ids())
                .map_err(|error| {
                    DurableCommitError::Evidence(crate::DurableEvidenceError::ConcurrentCheckpoint(
                        error,
                    ))
                })?
        } else {
            None
        };
        if let Some(task_id) = submission_resolution {
            checkpoint
                .validate_submission_resolution(
                    &self.original_checkpoint,
                    task_id,
                    self.staged_foreground.program_arc(),
                )
                .map_err(|error| {
                    DurableCommitError::Evidence(crate::DurableEvidenceError::ConcurrentCheckpoint(
                        error,
                    ))
                })?;
        }
        {
            let state = lock(&self.coordinator.inner.state);
            if state
                .execution_budget
                .as_ref()
                .map(ExecutionBudget::snapshot)
                != Some(self.original_budget)
            {
                return Err(DurableCommitError::InvalidState);
            }
        }
        commits.retain_graph_resource_baseline(&self.original_checkpoint)?;
        let mut staged_resources = None;
        let receipt = if let Some((index, owner, transition, charges)) = self.resource_finish.take()
        {
            if cut != DurableCommitCutV1::ResourceFinish
                || self.operation.is_some()
                || !self.events.is_empty()
                || submission_resolution.is_some()
                || self.resource_records[index].task_owner() != affected_task
            {
                return Err(DurableCommitError::InvalidState);
            }
            let evidence = crate::ResourceFinishEvidenceV1::new_with_charges(
                self.staged_foreground.program_arc(),
                (*self.original_checkpoint).clone(),
                checkpoint,
                index,
                (owner, transition),
                &charges,
            )
            .map_err(DurableCommitError::Evidence)?;
            staged_resources = Some(self.reconstruct_staged_resources()?);
            commits
                .commit_resource_finish_with_submission(evidence, || {
                    self.commit_started = true;
                })
                .await?
        } else if let Some((index, generations, charges)) = self.resource_owner.take() {
            if cut != DurableCommitCutV1::ResourceOwnerAdvance
                || self.operation.is_some()
                || !self.events.is_empty()
                || submission_resolution.is_some()
                || self.resource_records[index].task_owner() != affected_task
            {
                return Err(DurableCommitError::InvalidState);
            }
            let evidence = crate::ResourceOwnerEvidenceV1::new(
                self.staged_foreground.program_arc(),
                (*self.original_checkpoint).clone(),
                checkpoint,
                index,
                generations,
                &charges,
            )
            .map_err(DurableCommitError::Evidence)?;
            staged_resources = Some(self.reconstruct_staged_resources()?);
            commits
                .commit_resource_owner_advance_with_submission(evidence, || {
                    self.commit_started = true;
                })
                .await?
        } else {
            if matches!(
                cut,
                DurableCommitCutV1::ResourceFinish | DurableCommitCutV1::ResourceOwnerAdvance
            ) {
                return Err(DurableCommitError::InvalidState);
            }
            commits
                .commit_graph_checkpoint_with_record_submission(
                    cut,
                    submission_resolution.unwrap_or(affected_task),
                    self.operation.take(),
                    submission_resolution.is_some(),
                    checkpoint,
                    || {
                        self.commit_started = true;
                    },
                )
                .await?
        };
        let mut event_envelopes = Vec::with_capacity(self.events.len());
        for (event, plan, payloads) in std::mem::take(&mut self.events) {
            event_envelopes.push(
                commits
                    .commit_graph_event(&receipt, event, plan, &payloads)
                    .await?,
            );
        }
        let waiters = {
            let mut state = lock(&self.coordinator.inner.state);
            if state
                .execution_budget
                .as_ref()
                .map(ExecutionBudget::snapshot)
                != Some(self.original_budget)
                || self.budget.snapshot() != committed_budget
            {
                return Err(DurableCommitError::InvalidState);
            }
            let mut published_tasks = self.tasks.clone();
            // Physical completion can race storage without becoming a semantic
            // transition. Preserve that monotonic bookkeeping only in the live cut.
            for id in task_ids {
                if state.tasks.task_record(id).is_some_and(|record| {
                    record.driver_ownership() == TaskDriverOwnershipV1::PhysicallySettled
                }) {
                    published_tasks
                        .mark_driver_physically_settled(id)
                        .map_err(|_| DurableCommitError::InvalidState)?;
                }
            }
            let mut events = state.durable_events.clone();
            for envelope in &event_envelopes {
                events.apply_envelope(envelope).map_err(|error| {
                    DurableCommitError::Evidence(crate::DurableEvidenceError::Event(error))
                })?;
            }
            let execution_budget = ExecutionBudget::recover_from_checkpoint(committed_budget)
                .map_err(|_| DurableCommitError::InvalidState)?;
            state.durable_graph_baseline = Some((self.tasks.clone(), self.sessions.clone()));
            state.durable_resource_baseline = Some(self.resource_records.clone());
            if let Some(resources) = staged_resources.take() {
                state.resources = Some(resources);
            }
            self.foreground
                .commit_staged_resource_admission(&mut self.staged_foreground);
            for (task_id, authoritative) in self.children.iter_mut() {
                if let Some(staged) = self.staged_children.get_mut(task_id) {
                    authoritative.commit_staged_resource_admission(staged);
                } else {
                    authoritative.close_resource_admission();
                }
            }
            *self.foreground = self.staged_foreground.clone();
            *self.children = self.staged_children.clone();
            state.tasks = published_tasks;
            state.sessions = self.sessions.clone();
            state.durable_events = events;
            state.execution_budget = Some(execution_budget);
            state.publication = state.publication.wrapping_add(1);
            state.durable_publication_reserved = false;
            if let Some(guard) = self.staged_foreground_resource_admission_guard.as_mut() {
                guard.disarm();
            }
            for task_id in self.staged_children.keys() {
                if let Some(guard) = self.staged_child_resource_admission_guards.get_mut(task_id) {
                    guard.disarm();
                }
            }
            self.installed = true;
            let ids = state
                .task_waiters
                .keys()
                .copied()
                .filter(|id| task_is_settled(&state.tasks, *id))
                .collect::<Vec<_>>();
            let mut waiters = Vec::new();
            for id in ids {
                waiters.extend(state.task_waiters.remove(&id).unwrap_or_default());
            }
            if state.tasks.foreground_outcome().is_some() {
                waiters.append(&mut state.foreground_waiters);
            }
            if state.tasks.terminal_outcome().is_some() {
                waiters.append(&mut state.terminal_waiters);
            }
            waiters.extend(take_shutdown_waiters_if_quiescent(&mut state));
            waiters
        };
        wake_all(waiters);
        Ok(receipt)
    }
}

impl Drop for DurableGraphTransaction<'_> {
    fn drop(&mut self) {
        if !self.installed && !self.commit_started {
            lock(&self.coordinator.inner.state).durable_publication_reserved = false;
        }
    }
}
