//! Exclusive journal-first graph staging over the existing coordinator.
//!
//! Machine borrows prevent their drivers from advancing during a transaction.
//! Only private copies advance; observers retain the previous coordinator cut.
//! Dropping before submission rolls back. Dropping after submission fences
//! semantic publication because the journal result may be indeterminate.

use super::*;
use crate::{
    ConcurrentDurableCheckpointV4, DurableCommitCoordinatorV1, DurableCommitCutV1,
    DurableCommitError, DurableEvidenceCommitV1, Machine, TaskDriverOwnershipV1,
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
    tasks: ConcurrentTaskStateV1,
    sessions: LogicalSessionRegistryV1,
    budget: ExecutionBudget,
    original_budget: ExecutionBudgetSnapshot,
    commit_started: bool,
    installed: bool,
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
        let original = state
            .execution_budget
            .as_ref()
            .ok_or(TaskStateError::InvalidTaskMachine)?;
        let checkpoint = ConcurrentDurableCheckpointV4::capture_coordinated(
            foreground,
            children,
            &state.tasks,
            &state.sessions,
            original,
        )
        .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        let original_budget = checkpoint.execution_budget();
        let budget = ExecutionBudget::recover_from_checkpoint(original_budget)
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        let staged_foreground = foreground
            .clone_with_staged_budget(budget.clone())
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        let staged_children = children
            .iter()
            .map(|(id, machine)| {
                machine
                    .clone_with_staged_budget(budget.clone())
                    .map(|machine| (*id, machine))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(|_| TaskStateError::InvalidTaskMachine)?;
        state.durable_publication_reserved = true;
        Ok(DurableGraphTransaction {
            coordinator: self,
            foreground,
            children,
            staged_foreground,
            staged_children,
            tasks: state.tasks.clone(),
            sessions: state.sessions.clone(),
            budget,
            original_budget,
            commit_started: false,
            installed: false,
        })
    }
}

impl DurableGraphTransaction<'_> {
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
        )
        .map_err(|_| DurableCommitError::InvalidState)?;
        let committed_budget = checkpoint.execution_budget();
        let task_ids = checkpoint.task_ids();
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
        let receipt = commits
            .commit_graph_checkpoint_with_submission(cut, affected_task, checkpoint, || {
                self.commit_started = true;
            })
            .await?;
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
            // Physical completion can race storage without becoming a semantic
            // transition. Preserve that monotonic bookkeeping in the installed cut.
            for id in task_ids {
                if state.tasks.task_record(id).is_some_and(|record| {
                    record.driver_ownership() == TaskDriverOwnershipV1::PhysicallySettled
                }) {
                    self.tasks
                        .mark_driver_physically_settled(id)
                        .map_err(|_| DurableCommitError::InvalidState)?;
                }
            }
            *self.foreground = self.staged_foreground.clone();
            *self.children = self.staged_children.clone();
            state.tasks = self.tasks.clone();
            state.sessions = self.sessions.clone();
            state.execution_budget = Some(self.budget.clone());
            state.publication = state.publication.wrapping_add(1);
            state.durable_publication_reserved = false;
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
        if !self.commit_started && !self.installed {
            lock(&self.coordinator.inner.state).durable_publication_reserved = false;
        }
    }
}
