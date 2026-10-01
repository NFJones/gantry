//! Service-owned observation of settled physical cleanup outside async workers.
//!
//! Submission captures only the coordinator, never extracted physical values. Started work
//! remains owned by the bounded blocking service even if every observer is dropped. This
//! boundary supports physical sweeps and explicitly witnessed emergency cohorts; it supplies
//! no escalation authority, source transport or durable resource reconstruction.

use std::sync::{Arc, Mutex};

use gantry_host::containment::{
    AdapterPoison, BoundaryFailure, catch_integration, contain_integration_future, drop_integration,
};
use gantry_host::contracts::{
    BlockingJobCompletion, BlockingWorkService, BlockingWorkSubmitError, OwnedBlockingJob,
    SubmittedBlockingJob,
};

use crate::{
    CoordinatorResourceCleanup, CoordinatorResourceRefusal, ExecutionCoordinator,
    ResourcePhysicalCleanupResults,
};

/// Operational refusal or failure of a service-owned physical cleanup sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceCleanupError {
    /// Integration submission, observation or disposal panicked; no payload is disclosed.
    Boundary(BoundaryFailure),
    /// The blocking service refused to retain the sweep.
    Submission(BlockingWorkSubmitError),
    /// Accepted blocking work did not return normally.
    Completion(BlockingJobCompletion),
    /// The coordinator refused selection before physical extraction.
    Coordinator(CoordinatorResourceRefusal),
    /// The service reported success without running the owned closure to its result.
    MissingResult,
}

/// Observer of one service-owned sweep, without authority to cancel accepted cleanup.
pub struct ResourceCleanupObserver<T = ResourcePhysicalCleanupResults> {
    handle: Option<Arc<dyn SubmittedBlockingJob>>,
    poison: AdapterPoison,
    result: Arc<Mutex<Option<Result<T, CoordinatorResourceRefusal>>>>,
}

impl<T: Clone + Send> ResourceCleanupObserver<T> {
    /// Observes physical completion and the independent per-resource cleanup outcomes.
    ///
    /// Dropping this future or observer does not cancel accepted work. Queued cancellation by
    /// the service leaves physical slots untouched. Repeated observations return the same result.
    pub async fn completion(&self) -> Result<T, ResourceCleanupError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or(ResourceCleanupError::MissingResult)?;
        let future = catch_integration(&self.poison, || handle.completion())
            .map_err(ResourceCleanupError::Boundary)?;
        let completion = contain_integration_future(future, self.poison.clone())
            .await
            .map_err(ResourceCleanupError::Boundary)?;
        if completion != BlockingJobCompletion::Completed {
            return Err(ResourceCleanupError::Completion(completion));
        }
        self.result
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .ok_or(ResourceCleanupError::MissingResult)?
            .map_err(ResourceCleanupError::Coordinator)
    }
}

impl<T> Drop for ResourceCleanupObserver<T> {
    /// Contains observation-handle disposal without cancelling service-owned cleanup.
    fn drop(&mut self) {
        let _ = drop_integration(&self.poison, &mut self.handle);
    }
}

impl ExecutionCoordinator {
    /// Submits a settled physical sweep to a bounded blocking-work owner.
    ///
    /// No physical ownership is extracted during submission. The service owns accepted work
    /// independently of this observer; the coordinator's publication and lifetime fences run
    /// when the job executes. The caller supplies a durable service-instance poison boundary.
    pub fn submit_settled_resource_cleanup(
        &self,
        service: &dyn BlockingWorkService,
        service_poison: &AdapterPoison,
    ) -> Result<ResourceCleanupObserver, ResourceCleanupError> {
        let coordinator = self.clone();
        submit_cleanup(service, service_poison, move || {
            coordinator.dispose_settled_resource_host_values()
        })
    }

    /// Submits explicitly witnessed emergency settlement and physical cleanup off async workers.
    ///
    /// Witnesses are consumed on all paths. Refusal or queued cancellation does not settle any
    /// account; canonical semantic prefix settlement starts only when the owned job runs. Started
    /// cleanup remains service-owned after observer drop, and physical failure never rolls back
    /// the settled prefix. This method grants no escalation or host authority.
    pub fn submit_emergency_resource_cleanup(
        &self,
        service: &dyn BlockingWorkService,
        service_poison: &AdapterPoison,
        cleanups: Vec<(
            crate::ResourceSubjectBinding,
            gantry_ir::EmergencyCleanupWitness,
        )>,
    ) -> Result<ResourceCleanupObserver<CoordinatorResourceCleanup>, ResourceCleanupError> {
        let coordinator = self.clone();
        submit_cleanup(service, service_poison, move || {
            coordinator.emergency_release_resource_cohort(cleanups)
        })
    }
}

impl ExecutionCoordinator {
    /// Submits registry-selected cleanup of cancelled and physically settled task owners.
    ///
    /// Validation and selection happen when the service-owned job starts, under the same lock
    /// as semantic settlement. The caller authenticates the escalation/cohort association;
    /// submission grants no escalation authority and never closes accepted machine leases.
    pub fn submit_task_resource_cleanup(
        &self,
        service: &dyn BlockingWorkService,
        service_poison: &AdapterPoison,
        task_ids: Vec<gantry_core::identity::ProtocolIdentity>,
        escalation: gantry_ir::Escalation,
    ) -> Result<ResourceCleanupObserver<CoordinatorResourceCleanup>, ResourceCleanupError> {
        let coordinator = self.clone();
        submit_cleanup(service, service_poison, move || {
            coordinator.emergency_release_task_resources(&task_ids, escalation)
        })
    }
}

/// Submits only the owned closure; integration refusal cannot extract coordinator-held values.
fn submit_cleanup<T: Send + 'static>(
    service: &dyn BlockingWorkService,
    service_poison: &AdapterPoison,
    work: impl FnOnce() -> Result<T, CoordinatorResourceRefusal> + Send + 'static,
) -> Result<ResourceCleanupObserver<T>, ResourceCleanupError> {
    let result = Arc::new(Mutex::new(None));
    let output = Arc::clone(&result);
    let mut job: Option<OwnedBlockingJob> = Some(Box::new(move || {
        let completed = work();
        *output.lock().unwrap_or_else(|error| error.into_inner()) = Some(completed);
    }));
    // Keep unused closure ownership outside the already-poisoned fast path.
    let submitted = catch_integration(service_poison, || {
        service.submit(job.take().unwrap_or_else(|| unreachable!("submitted once")))
    });
    drop_integration(service_poison, &mut job).map_err(ResourceCleanupError::Boundary)?;
    let handle = submitted
        .map_err(ResourceCleanupError::Boundary)?
        .map_err(ResourceCleanupError::Submission)?;
    Ok(ResourceCleanupObserver {
        handle: Some(handle),
        poison: AdapterPoison::default(),
        result,
    })
}
