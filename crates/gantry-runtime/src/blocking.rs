//! Bounded ownership for blocking and CPU-heavy host work.
//!
//! This service uses dedicated operating-system threads rather than an async
//! executor's worker or blocking pool. Queue admission never waits, queued
//! cancellation wins only before start, and started closures remain owned
//! until their contained physical completion.

use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Poll, Waker};

use gantry_host::contracts::{
    BlockingJobCancellation, BlockingJobCompletion, BlockingWorkCapacities, BlockingWorkService,
    BlockingWorkSubmitError, HostError, HostFuture, OwnedBlockingJob, SubmittedBlockingJob,
};

/// Rejection of a zero blocking-work capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockingWorkConfigurationError {
    /// Queue or active capacity was zero.
    InvalidCapacities,
    /// The service panicked while reporting its capacity contract.
    IntegrationFailure,
    /// An injected service reports capacities different from interpreter policy.
    CapacityMismatch {
        /// Capacities required by the interpreter configuration.
        expected: BlockingWorkCapacities,
        /// Capacities reported by the injected service.
        actual: BlockingWorkCapacities,
    },
}

impl fmt::Display for BlockingWorkConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacities => "blocking-work queue and active capacities must be positive",
            Self::IntegrationFailure => "blocking-work service capacity inspection failed",
            Self::CapacityMismatch { .. } => {
                "blocking-work service capacities do not match interpreter policy"
            }
        })
    }
}

impl std::error::Error for BlockingWorkConfigurationError {}

/// Dedicated bounded service for blocking and CPU-heavy jobs.
///
/// Threads are created lazily and never exceed `maximum_active_jobs`. The
/// separate queue bound applies only to jobs waiting to start, so a running
/// job never consumes queued capacity.
pub struct BoundedBlockingWorkService {
    inner: Arc<ServiceInner>,
}

impl fmt::Debug for BoundedBlockingWorkService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        formatter
            .debug_struct("BoundedBlockingWorkService")
            .field("maximum_queued_jobs", &self.inner.maximum_queued_jobs)
            .field("maximum_active_jobs", &self.inner.maximum_active_jobs)
            .field("queued_jobs", &state.queue.len())
            .field("active_jobs", &state.active_jobs)
            .field("accepting", &state.accepting)
            .finish()
    }
}

impl BoundedBlockingWorkService {
    /// Creates an empty service with finite positive queue and active bounds.
    pub fn new(
        maximum_queued_jobs: u64,
        maximum_active_jobs: u64,
    ) -> Result<Self, BlockingWorkConfigurationError> {
        if maximum_queued_jobs == 0 || maximum_active_jobs == 0 {
            return Err(BlockingWorkConfigurationError::InvalidCapacities);
        }
        Ok(Self {
            inner: Arc::new(ServiceInner {
                maximum_queued_jobs,
                maximum_active_jobs,
                state: Mutex::new(ServiceState {
                    accepting: true,
                    next_job_id: 0,
                    active_jobs: 0,
                    queue: VecDeque::new(),
                    shutdown_waiters: Vec::new(),
                }),
            }),
        })
    }

    /// Creates one uniquely owned service from an interpreter capacity policy.
    pub fn from_capacities(
        capacities: crate::AsyncCapacityLimits,
    ) -> Result<Self, BlockingWorkConfigurationError> {
        Self::new(
            capacities.maximum_queued_blocking_jobs(),
            capacities.maximum_active_blocking_jobs(),
        )
    }

    fn begin_shutdown(&self) {
        let cancelled = {
            let mut state = lock(&self.inner.state);
            state.accepting = false;
            state.queue.drain(..).collect::<Vec<_>>()
        };
        for job in cancelled {
            job.publish(BlockingJobCompletion::CancelledBeforeStart);
        }
        self.inner.wake_shutdown_if_settled();
    }
}

impl Drop for BoundedBlockingWorkService {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

impl BlockingWorkService for BoundedBlockingWorkService {
    fn capacities(&self) -> BlockingWorkCapacities {
        BlockingWorkCapacities::new(
            self.inner.maximum_queued_jobs,
            self.inner.maximum_active_jobs,
        )
        .unwrap_or_else(|| unreachable!("constructed service capacities are positive"))
    }

    fn submit(
        &self,
        job: OwnedBlockingJob,
    ) -> Result<Arc<dyn SubmittedBlockingJob>, BlockingWorkSubmitError> {
        let (control, start_now) = {
            let mut state = lock(&self.inner.state);
            if !state.accepting {
                return Err(BlockingWorkSubmitError::Failed(host_failure(
                    "blocking-work-shutting-down",
                )));
            }
            let job_id = state.next_job_id;
            state.next_job_id = state.next_job_id.wrapping_add(1);
            let control = Arc::new(JobControl {
                id: job_id,
                service: Arc::downgrade(&self.inner),
                state: Mutex::new(JobState {
                    status: JobStatus::Queued,
                    job: Some(job),
                    waiters: Vec::new(),
                }),
            });
            if state.active_jobs < self.inner.maximum_active_jobs {
                state.active_jobs = state.active_jobs.saturating_add(1);
                lock(&control.state).status = JobStatus::Started;
                (control, true)
            } else {
                let queued = u64::try_from(state.queue.len()).unwrap_or(u64::MAX);
                if queued >= self.inner.maximum_queued_jobs {
                    return Err(BlockingWorkSubmitError::CapacityExhausted);
                }
                state.queue.push_back(Arc::clone(&control));
                (control, false)
            }
        };
        if start_now {
            spawn_started(Arc::clone(&control));
        }
        Ok(Arc::new(SubmittedBlockingJobHandle { control }))
    }

    fn shutdown<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        self.begin_shutdown();
        Box::pin(std::future::poll_fn(move |context| {
            {
                let state = lock(&self.inner.state);
                if state.active_jobs == 0 && state.queue.is_empty() {
                    return Poll::Ready(Ok(()));
                }
            }
            let Some(waker) = clone_waker_contained(context.waker()) else {
                return Poll::Ready(Err(host_failure("blocking-work-waker-failure")));
            };
            let duplicate = {
                let mut state = lock(&self.inner.state);
                if state.active_jobs == 0 && state.queue.is_empty() {
                    drop(state);
                    drop_waker_contained(waker);
                    return Poll::Ready(Ok(()));
                }
                register(&mut state.shutdown_waiters, waker)
            };
            if let Some(waker) = duplicate {
                drop_waker_contained(waker);
            }
            Poll::Pending
        }))
    }
}

struct ServiceInner {
    maximum_queued_jobs: u64,
    maximum_active_jobs: u64,
    state: Mutex<ServiceState>,
}

struct ServiceState {
    accepting: bool,
    next_job_id: u64,
    active_jobs: u64,
    queue: VecDeque<Arc<JobControl>>,
    shutdown_waiters: Vec<Waker>,
}

impl ServiceInner {
    fn finish_started(self: &Arc<Self>, job: &Arc<JobControl>, completion: BlockingJobCompletion) {
        if let Some(next) = self.settle_started(job, completion) {
            spawn_started(next);
        }
    }

    fn settle_started(
        self: &Arc<Self>,
        job: &Arc<JobControl>,
        completion: BlockingJobCompletion,
    ) -> Option<Arc<JobControl>> {
        let next = {
            let mut service = lock(&self.state);
            service.active_jobs = service.active_jobs.saturating_sub(1);
            let mut next = None;
            while service.accepting && service.active_jobs < self.maximum_active_jobs {
                let Some(candidate) = service.queue.pop_front() else {
                    break;
                };
                let mut candidate_state = lock(&candidate.state);
                if !matches!(candidate_state.status, JobStatus::Queued) {
                    continue;
                }
                candidate_state.status = JobStatus::Started;
                drop(candidate_state);
                service.active_jobs = service.active_jobs.saturating_add(1);
                next = Some(candidate);
                break;
            }
            next
        };
        job.publish(completion);
        self.wake_shutdown_if_settled();
        next
    }

    fn wake_shutdown_if_settled(&self) {
        let waiters = {
            let mut state = lock(&self.state);
            if state.active_jobs != 0 || !state.queue.is_empty() {
                return;
            }
            std::mem::take(&mut state.shutdown_waiters)
        };
        wake_all(waiters);
    }
}

struct JobControl {
    id: u64,
    service: Weak<ServiceInner>,
    state: Mutex<JobState>,
}

struct JobState {
    status: JobStatus,
    job: Option<OwnedBlockingJob>,
    waiters: Vec<Waker>,
}

enum JobStatus {
    Queued,
    Started,
    Terminal(BlockingJobCompletion),
}

impl JobControl {
    fn publish(&self, completion: BlockingJobCompletion) {
        let (job, waiters) = {
            let mut state = lock(&self.state);
            if matches!(state.status, JobStatus::Terminal(_)) {
                return;
            }
            let job = state.job.take();
            state.status = JobStatus::Terminal(completion);
            (job, std::mem::take(&mut state.waiters))
        };
        drop_contained(job);
        wake_all(waiters);
    }
}

struct SubmittedBlockingJobHandle {
    control: Arc<JobControl>,
}

impl SubmittedBlockingJob for SubmittedBlockingJobHandle {
    fn cancel_before_start(&self) -> BlockingJobCancellation {
        let Some(service) = self.control.service.upgrade() else {
            return cancellation_after_service_drop(&self.control);
        };
        let (job, waiters) = {
            let mut service_state = lock(&service.state);
            let mut job_state = lock(&self.control.state);
            match &job_state.status {
                JobStatus::Queued => {
                    if let Some(index) = service_state
                        .queue
                        .iter()
                        .position(|candidate| candidate.id == self.control.id)
                    {
                        service_state.queue.remove(index);
                    }
                    let job = job_state.job.take();
                    job_state.status =
                        JobStatus::Terminal(BlockingJobCompletion::CancelledBeforeStart);
                    let waiters = std::mem::take(&mut job_state.waiters);
                    (job, waiters)
                }
                JobStatus::Started => return BlockingJobCancellation::AlreadyStarted,
                JobStatus::Terminal(_) => return BlockingJobCancellation::AlreadySettled,
            }
        };
        drop_contained(job);
        wake_all(waiters);
        service.wake_shutdown_if_settled();
        BlockingJobCancellation::Cancelled
    }

    fn completion<'a>(&'a self) -> HostFuture<'a, BlockingJobCompletion> {
        Box::pin(std::future::poll_fn(move |context| {
            {
                let state = lock(&self.control.state);
                if let JobStatus::Terminal(completion) = &state.status {
                    return Poll::Ready(completion.clone());
                }
            }
            let Some(waker) = clone_waker_contained(context.waker()) else {
                return Poll::Ready(BlockingJobCompletion::Failed(host_failure(
                    "blocking-work-waker-failure",
                )));
            };
            let duplicate = {
                let mut state = lock(&self.control.state);
                if let JobStatus::Terminal(completion) = &state.status {
                    let completion = completion.clone();
                    drop(state);
                    drop_waker_contained(waker);
                    return Poll::Ready(completion);
                }
                register(&mut state.waiters, waker)
            };
            if let Some(waker) = duplicate {
                drop_waker_contained(waker);
            }
            Poll::Pending
        }))
    }
}

fn cancellation_after_service_drop(control: &JobControl) -> BlockingJobCancellation {
    match lock(&control.state).status {
        JobStatus::Queued => BlockingJobCancellation::AlreadySettled,
        JobStatus::Started => BlockingJobCancellation::AlreadyStarted,
        JobStatus::Terminal(_) => BlockingJobCancellation::AlreadySettled,
    }
}

fn spawn_started(mut control: Arc<JobControl>) {
    loop {
        let service = control.service.upgrade();
        let spawned = std::thread::Builder::new()
            .name("gantry-blocking-work".to_owned())
            .spawn({
                let control = Arc::clone(&control);
                move || {
                    let job = lock(&control.state).job.take();
                    let completion = match job {
                        Some(job) => match catch_unwind(AssertUnwindSafe(job)) {
                            Ok(()) => BlockingJobCompletion::Completed,
                            Err(payload) => {
                                forget_panic_payload(payload);
                                BlockingJobCompletion::Panicked
                            }
                        },
                        None => {
                            BlockingJobCompletion::Failed(host_failure("blocking-work-missing-job"))
                        }
                    };
                    if let Some(service) = control.service.upgrade() {
                        service.finish_started(&control, completion);
                    } else {
                        control.publish(completion);
                    }
                }
            });
        if spawned.is_ok() {
            return;
        }
        let completion =
            BlockingJobCompletion::Failed(host_failure("blocking-worker-spawn-failure"));
        let Some(service) = service else {
            control.publish(completion);
            return;
        };
        let Some(next) = service.settle_started(&control, completion) else {
            return;
        };
        control = next;
    }
}

fn host_failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn register(waiters: &mut Vec<Waker>, waker: Waker) -> Option<Waker> {
    if !waiters.iter().any(|candidate| candidate.will_wake(&waker)) {
        waiters.push(waker);
        None
    } else {
        Some(waker)
    }
}

fn wake_all(waiters: Vec<Waker>) {
    for waiter in waiters {
        contain_callback(|| waiter.wake());
    }
}

fn drop_contained(job: Option<OwnedBlockingJob>) {
    contain_callback(|| drop(job));
}

fn clone_waker_contained(waker: &Waker) -> Option<Waker> {
    match catch_unwind(AssertUnwindSafe(|| waker.clone())) {
        Ok(waker) => Some(waker),
        Err(payload) => {
            forget_panic_payload(payload);
            None
        }
    }
}

fn drop_waker_contained(waker: Waker) {
    contain_callback(|| drop(waker));
}

fn contain_callback(invoke: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(invoke)) {
        forget_panic_payload(payload);
    }
}

fn forget_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    std::mem::forget(payload);
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
