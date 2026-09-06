//! Bounded, executor-neutral supervision of submitted asynchronous work.
//!
//! One registry owns every submitted handle until physical settlement. Handle
//! completion is polled by a serialized wake-driven queue, so reaping does not
//! require an unregistered watcher task or a recursive watcher chain.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Wake, Waker};

use gantry_core::identity::ProtocolIdentity;
use gantry_host::contracts::{
    ExecutorAdapter, HostError, OwnedTaskAbort, OwnedTaskCompletion, OwnedTaskFuture,
    SubmittedTask, reject_task_submission,
};

use crate::{
    AdmissionClass, AdmissionExhaustion, AdmissionPermit, AdmissionRequest, AdmissionReservation,
    AdmissionResourceClass, AsyncAdmission,
};

static NEXT_SUPERVISED_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// Semantic ownership class of one executor-submitted future.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SupervisedTaskDomain {
    /// A root task for a newly accepted execution.
    Root,
    /// A source-created child task.
    SourceChild,
    /// A runnable task reconstructed during resume.
    Resume,
    /// A caller-independent public-operation subactivity.
    PublicActivity,
    /// Execution-owned logical-session establishment.
    RuntimeSession,
    /// Interpreter-owned background work.
    InterpreterBackground,
    /// Asynchronous event-delivery work.
    EventDelivery,
    /// The unique orderly-shutdown coordinator.
    Shutdown,
    /// Cleanup work using the isolated control-plane reserve.
    ControlPlane,
}

impl SupervisedTaskDomain {
    /// Returns the stable diagnostic spelling for this ownership class.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::SourceChild => "source-child",
            Self::Resume => "resume",
            Self::PublicActivity => "public-activity",
            Self::RuntimeSession => "runtime-session",
            Self::InterpreterBackground => "interpreter-background",
            Self::EventDelivery => "event-delivery",
            Self::Shutdown => "shutdown",
            Self::ControlPlane => "control-plane",
        }
    }

    /// Returns the exact operational capacity owned by this task domain.
    #[must_use]
    pub const fn admission_resource(self) -> AdmissionResourceClass {
        match self {
            Self::Root => AdmissionResourceClass::Ordinary(AdmissionClass::RootTask),
            Self::SourceChild => AdmissionResourceClass::Ordinary(AdmissionClass::SourceChildTask),
            Self::Resume => AdmissionResourceClass::Ordinary(AdmissionClass::ResumeRunnableTask),
            Self::PublicActivity => {
                AdmissionResourceClass::Ordinary(AdmissionClass::PublicActivity)
            }
            Self::RuntimeSession | Self::InterpreterBackground => {
                AdmissionResourceClass::Ordinary(AdmissionClass::InterpreterBackgroundTask)
            }
            Self::EventDelivery => AdmissionResourceClass::Ordinary(AdmissionClass::EventDelivery),
            Self::Shutdown | Self::ControlPlane => AdmissionResourceClass::ControlPlaneTask,
        }
    }
}

/// Callback for physical completion that precedes semantic settlement.
pub type AbnormalCompletionHandler = Arc<dyn Fn(OwnedTaskCompletion) + Send + Sync + 'static>;

/// Callback invoked exactly once for any physically completed supervised task.
pub type PhysicalCompletionHandler = Arc<dyn Fn(OwnedTaskCompletion) + Send + Sync + 'static>;

/// Shared owner of submitted executor tasks.
#[derive(Clone)]
pub struct TaskSupervisor {
    inner: Arc<SupervisorInner>,
}

impl std::fmt::Debug for TaskSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskSupervisor")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl TaskSupervisor {
    /// Creates one empty registry over the configured executor and admission owner.
    #[must_use]
    pub fn new(executor: Arc<dyn ExecutorAdapter>, admission: AsyncAdmission) -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                executor,
                admission,
                state: Mutex::new(SupervisorState::default()),
            }),
        }
    }

    /// Returns the configured executor for lifecycle deadline coordination.
    #[must_use]
    pub fn executor_arc(&self) -> Arc<dyn ExecutorAdapter> {
        Arc::clone(&self.inner.executor)
    }

    /// Reserves one ordinary capacity unit before submission.
    pub fn try_reserve(
        &self,
        class: AdmissionClass,
    ) -> Result<AdmissionReservation, AdmissionExhaustion> {
        self.inner
            .admission
            .try_reserve(AdmissionRequest::single(class, 1))
    }

    /// Reserves one isolated cleanup/control-plane unit before submission.
    pub fn try_reserve_control_plane(&self) -> Result<AdmissionReservation, AdmissionExhaustion> {
        self.inner.admission.try_reserve_control_plane(1)
    }

    /// Allocates the semantic signal and abnormal-completion policy before submission.
    #[must_use]
    pub fn prepare(
        &self,
        domain: SupervisedTaskDomain,
        abnormal: Option<AbnormalCompletionHandler>,
    ) -> SupervisionRegistration {
        self.prepare_with_completion(domain, abnormal, None)
    }

    /// Allocates supervision metadata with an optional physical-completion observer.
    #[must_use]
    pub fn prepare_with_completion(
        &self,
        domain: SupervisedTaskDomain,
        abnormal: Option<AbnormalCompletionHandler>,
        completion: Option<PhysicalCompletionHandler>,
    ) -> SupervisionRegistration {
        self.prepare_inner(domain, None, abnormal, completion)
    }

    /// Allocates supervision metadata owned by one execution task.
    #[must_use]
    pub fn prepare_owned(
        &self,
        domain: SupervisedTaskDomain,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        abnormal: Option<AbnormalCompletionHandler>,
    ) -> SupervisionRegistration {
        self.prepare_owned_with_completion(domain, execution_id, task_id, abnormal, None)
    }

    /// Allocates owned supervision metadata with a physical-completion observer.
    #[must_use]
    pub fn prepare_owned_with_completion(
        &self,
        domain: SupervisedTaskDomain,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        abnormal: Option<AbnormalCompletionHandler>,
        completion: Option<PhysicalCompletionHandler>,
    ) -> SupervisionRegistration {
        self.prepare_inner(
            domain,
            Some(SupervisedTaskOwner {
                execution_id,
                task_id,
            }),
            abnormal,
            completion,
        )
    }

    fn prepare_inner(
        &self,
        domain: SupervisedTaskDomain,
        owner: Option<SupervisedTaskOwner>,
        abnormal: Option<AbnormalCompletionHandler>,
        completion: Option<PhysicalCompletionHandler>,
    ) -> SupervisionRegistration {
        let id = NEXT_SUPERVISED_TASK_ID.fetch_add(1, Ordering::Relaxed);
        let semantic = Arc::new(AtomicBool::new(false));
        SupervisionRegistration {
            id,
            domain,
            owner,
            supervisor: Arc::downgrade(&self.inner),
            semantic: Arc::clone(&semantic),
            signal: SupervisionSignal {
                id,
                supervisor: Arc::downgrade(&self.inner),
                semantic,
            },
            abnormal,
            completion,
            observation_armed: true,
        }
    }

    /// Allocates supervision metadata whose handle completion is not observed
    /// until the submitter publishes its semantic submission transition.
    #[must_use]
    pub fn prepare_deferred_with_completion(
        &self,
        domain: SupervisedTaskDomain,
        abnormal: Option<AbnormalCompletionHandler>,
        completion: Option<PhysicalCompletionHandler>,
    ) -> SupervisionRegistration {
        let mut registration = self.prepare_with_completion(domain, abnormal, completion);
        registration.observation_armed = false;
        registration
    }

    /// Allocates owned supervision metadata with deferred completion observation.
    #[must_use]
    pub fn prepare_owned_deferred_with_completion(
        &self,
        domain: SupervisedTaskDomain,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
        abnormal: Option<AbnormalCompletionHandler>,
        completion: Option<PhysicalCompletionHandler>,
    ) -> SupervisionRegistration {
        let mut registration =
            self.prepare_owned_with_completion(domain, execution_id, task_id, abnormal, completion);
        registration.observation_armed = false;
        registration
    }

    /// Submits and registers one prepared task with its physical-settlement permit.
    pub fn submit(
        &self,
        registration: SupervisionRegistration,
        task: OwnedTaskFuture,
        permit: AdmissionPermit,
    ) -> Result<SupervisedTask, HostError> {
        let Some(supervisor) = registration.supervisor.upgrade() else {
            return reject_task_submission(task).map(|_| unreachable!("submission was rejected"));
        };
        if !Arc::ptr_eq(&supervisor, &self.inner)
            || !permit.matches(
                &self.inner.admission,
                registration.domain.admission_resource(),
            )
        {
            return reject_task_submission(task).map(|_| unreachable!("submission was rejected"));
        }
        {
            let mut state = lock(&self.inner.state);
            if state.closed {
                drop(state);
                return reject_task_submission(task)
                    .map(|_| unreachable!("submission was rejected"));
            }
            state.submitting.insert(registration.id);
        }
        let submitted = match catch_unwind(AssertUnwindSafe(|| self.inner.executor.spawn(task)))
            .unwrap_or_else(|_| Err(executor_failure()))
        {
            Ok(submitted) => submitted,
            Err(error) => {
                SupervisorInner::finish_failed_submission(&self.inner, registration.id);
                return Err(error);
            }
        };
        let handle: Arc<dyn SubmittedTask> = Arc::from(submitted);
        let observation = Arc::new(Mutex::new(SupervisedObservation::default()));
        let wake = Arc::new(ReaperWake {
            id: registration.id,
            supervisor: Arc::clone(&self.inner),
        });
        let entry = Arc::new(SupervisedEntry {
            id: registration.id,
            domain: registration.domain,
            owner: registration.owner,
            semantic: registration.semantic,
            handle,
            abort: Mutex::new(None),
            observation: Arc::clone(&observation),
            wake,
            permit: Mutex::new(Some(permit)),
            abnormal: Mutex::new(registration.abnormal),
            completion: Mutex::new(registration.completion),
            observation_armed: AtomicBool::new(registration.observation_armed),
            unclean_relinquished: AtomicBool::new(false),
        });
        {
            let mut state = lock(&self.inner.state);
            state.submitting.remove(&registration.id);
            if state.closed {
                entry.unclean_relinquished.store(true, Ordering::Release);
                let mut observation = lock(&entry.observation);
                observation.abort_requested = true;
                observation.control_relinquished = true;
            }
            state.active.insert(registration.id, Arc::clone(&entry));
        }
        if entry.observation_armed.load(Ordering::Acquire)
            || entry.unclean_relinquished.load(Ordering::Acquire)
        {
            SupervisorInner::enqueue(&self.inner, registration.id);
        }
        Ok(SupervisedTask {
            id: registration.id,
            domain: registration.domain,
            owner: registration.owner,
            supervisor: Arc::downgrade(&self.inner),
            semantic: Arc::clone(&entry.semantic),
            observation,
        })
    }

    /// Returns a stable point-in-time projection of active physical work.
    #[must_use]
    pub fn snapshot(&self) -> TaskSupervisorSnapshot {
        let state = lock(&self.inner.state);
        TaskSupervisorSnapshot {
            closed: state.closed,
            tasks: Arc::from(
                state
                    .active
                    .values()
                    .map(|entry| entry.snapshot())
                    .collect::<Vec<_>>(),
            ),
        }
    }

    /// Returns the number of active tasks in one ownership domain.
    #[must_use]
    pub fn active_count(&self, domain: SupervisedTaskDomain) -> usize {
        lock(&self.inner.state)
            .active
            .values()
            .filter(|entry| entry.domain == domain)
            .count()
    }

    /// Returns whether no physical task or completion callback remains owned.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let state = lock(&self.inner.state);
        state.active.is_empty() && state.submitting.is_empty() && state.finalizing == 0
    }

    /// Returns whether only the shutdown coordinator itself remains active.
    #[must_use]
    pub fn is_shutdown_quiescent(&self) -> bool {
        shutdown_quiescent(&lock(&self.inner.state))
    }

    /// Polls registry quiescence and registers one wake without allocating a watcher task.
    pub fn poll_quiescence(&self, context: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.inner.state);
        if state.active.is_empty() && state.submitting.is_empty() && state.finalizing == 0 {
            Poll::Ready(())
        } else {
            register_waker(&mut state.quiescence_waiters, context.waker());
            Poll::Pending
        }
    }

    /// Polls until all work other than the shutdown coordinator has settled.
    pub fn poll_shutdown_quiescence(&self, context: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.inner.state);
        if shutdown_quiescent(&state) {
            Poll::Ready(())
        } else {
            register_waker(&mut state.quiescence_waiters, context.waker());
            Poll::Pending
        }
    }

    /// Requests abort for every active task without waiting for physical settlement.
    pub fn request_abort_all(&self) {
        let ids = {
            let state = lock(&self.inner.state);
            state.active.keys().copied().collect::<Vec<_>>()
        };
        for id in ids {
            SupervisorInner::request_abort(&self.inner, id);
        }
    }

    /// Selects active physical work owned by selected tasks without requesting abort.
    ///
    /// Returned controls retain immutable completion observations after registry
    /// removal and may request abort later without reselecting by semantic state.
    #[must_use]
    pub fn owned_task_controls(
        &self,
        execution_id: ProtocolIdentity,
        task_ids: &[ProtocolIdentity],
    ) -> Arc<[SupervisedTask]> {
        let state = lock(&self.inner.state);
        Arc::from(
            state
                .active
                .values()
                .filter(|entry| {
                    entry.owner.is_some_and(|owner| {
                        owner.execution_id == execution_id && task_ids.contains(&owner.task_id)
                    })
                })
                .map(|entry| self.control_for_entry(entry))
                .collect::<Vec<_>>(),
        )
    }

    /// Requests abort for active work owned by selected tasks in one execution.
    ///
    /// Selection completes while holding the registry lock. Abort requests are
    /// issued only after releasing it, and returned controls remain suitable
    /// for bounded physical-completion drain.
    #[must_use]
    pub fn request_abort_owned_tasks(
        &self,
        execution_id: ProtocolIdentity,
        task_ids: &[ProtocolIdentity],
    ) -> Arc<[SupervisedTask]> {
        let tasks = self.owned_task_controls(execution_id, task_ids);
        for task in tasks.iter() {
            let _ = task.request_abort();
        }
        tasks
    }

    /// Requests abort for every active physical driver owned by one execution.
    ///
    /// Selection uses supervisor ownership rather than semantic task status, so
    /// it includes drivers accepted by the executor whose submission transition
    /// has not yet been published by the coordinator.
    #[must_use]
    pub fn request_abort_owned_execution(
        &self,
        execution_id: ProtocolIdentity,
    ) -> Arc<[SupervisedTask]> {
        let entries = {
            let state = lock(&self.inner.state);
            state
                .active
                .values()
                .filter(|entry| {
                    entry
                        .owner
                        .is_some_and(|owner| owner.execution_id == execution_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let tasks = entries
            .into_iter()
            .map(|entry| self.control_for_entry(&entry))
            .collect::<Vec<_>>();
        for task in &tasks {
            let _ = task.request_abort();
        }
        Arc::from(tasks)
    }

    /// Requests abort for all work except the shutdown coordinator itself.
    ///
    /// Returned controls retain immutable abort and completion observations even
    /// after the registry removes physically settled entries.
    #[must_use]
    pub fn request_abort_shutdown_work(&self) -> Arc<[SupervisedTask]> {
        let entries = {
            let state = lock(&self.inner.state);
            state
                .active
                .values()
                .filter(|entry| entry.domain != SupervisedTaskDomain::Shutdown)
                .cloned()
                .collect::<Vec<_>>()
        };
        let tasks = entries
            .into_iter()
            .map(|entry| self.control_for_entry(&entry))
            .collect::<Vec<_>>();
        for task in &tasks {
            let _ = task.request_abort();
        }
        Arc::from(tasks)
    }

    fn control_for_entry(&self, entry: &SupervisedEntry) -> SupervisedTask {
        SupervisedTask {
            id: entry.id,
            domain: entry.domain,
            owner: entry.owner,
            supervisor: Arc::downgrade(&self.inner),
            semantic: Arc::clone(&entry.semantic),
            observation: Arc::clone(&entry.observation),
        }
    }

    /// Closes the registry, requests abort once, and relinquishes every control share.
    ///
    /// This is the synchronous unclean-drop path. Accepted handles and permits
    /// remain registry-owned until physical settlement. This path deliberately
    /// does not run callbacks or fabricate semantic settlement.
    pub fn abort_and_relinquish_all(&self) {
        let entries = {
            let mut state = lock(&self.inner.state);
            state.closed = true;
            let entries = state.active.values().cloned().collect::<Vec<_>>();
            for entry in &entries {
                entry.unclean_relinquished.store(true, Ordering::Release);
                entry.observation_armed.store(true, Ordering::Release);
                let mut observation = lock(&entry.observation);
                observation.abort_requested = true;
                observation.control_relinquished = true;
            }
            entries
        };
        for entry in entries {
            SupervisorInner::enqueue(&self.inner, entry.id);
        }
    }
}

/// Prepared ownership metadata shared with a task before executor submission.
pub struct SupervisionRegistration {
    id: u64,
    domain: SupervisedTaskDomain,
    owner: Option<SupervisedTaskOwner>,
    supervisor: Weak<SupervisorInner>,
    semantic: Arc<AtomicBool>,
    signal: SupervisionSignal,
    abnormal: Option<AbnormalCompletionHandler>,
    completion: Option<PhysicalCompletionHandler>,
    observation_armed: bool,
}

impl SupervisionRegistration {
    /// Returns a signal that the submitted task settles before physical return.
    #[must_use]
    pub fn signal(&self) -> SupervisionSignal {
        self.signal.clone()
    }
}

/// Monotonic semantic-settlement signal for one prepared task.
#[derive(Clone)]
pub struct SupervisionSignal {
    id: u64,
    supervisor: Weak<SupervisorInner>,
    semantic: Arc<AtomicBool>,
}

impl SupervisionSignal {
    /// Publishes semantic settlement once and prompts physical observation.
    pub fn settle(&self) -> bool {
        if self.semantic.swap(true, Ordering::AcqRel) {
            return false;
        }
        if let Some(supervisor) = self.supervisor.upgrade() {
            SupervisorInner::enqueue(&supervisor, self.id);
        }
        true
    }

    /// Returns whether semantic settlement has been published.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.semantic.load(Ordering::Acquire)
    }

    /// Arms deferred physical completion observation after submission state is visible.
    ///
    /// Returns `false` when observation was already armed or the registry no
    /// longer owns this task.
    pub fn arm_completion_observation(&self) -> bool {
        let Some(supervisor) = self.supervisor.upgrade() else {
            return false;
        };
        let entry = lock(&supervisor.state).active.get(&self.id).cloned();
        let Some(entry) = entry else {
            return false;
        };
        if entry.observation_armed.swap(true, Ordering::AcqRel) {
            return false;
        }
        SupervisorInner::enqueue(&supervisor, self.id);
        true
    }
}

/// Non-owning control and observation capability for one registered task.
pub struct SupervisedTask {
    id: u64,
    domain: SupervisedTaskDomain,
    owner: Option<SupervisedTaskOwner>,
    supervisor: Weak<SupervisorInner>,
    semantic: Arc<AtomicBool>,
    observation: Arc<Mutex<SupervisedObservation>>,
}

impl SupervisedTask {
    /// Returns the registry-local task identity.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the semantic ownership domain.
    #[must_use]
    pub const fn domain(&self) -> SupervisedTaskDomain {
        self.domain
    }

    /// Requests physical abort without waiting or reaching into adapter internals.
    pub fn request_abort(&self) -> bool {
        self.supervisor
            .upgrade()
            .is_some_and(|supervisor| SupervisorInner::request_abort(&supervisor, self.id))
    }

    /// Returns one immutable-or-pending observation snapshot.
    #[must_use]
    pub fn snapshot(&self) -> SupervisedTaskSnapshot {
        observation_snapshot(
            self.id,
            self.domain,
            self.owner,
            &self.observation,
            self.semantic.load(Ordering::Acquire),
        )
    }

    /// Observes the immutable physical completion without owning the executor handle.
    pub fn completion(&self) -> SupervisedCompletionWait {
        SupervisedCompletionWait {
            observation: Arc::clone(&self.observation),
        }
    }

    /// Relinquishes this control share while the registry retains physical ownership.
    pub fn relinquish(mut self) {
        lock(&self.observation).control_relinquished = true;
        self.id = 0;
    }
}

impl Drop for SupervisedTask {
    fn drop(&mut self) {
        if self.id != 0 {
            lock(&self.observation).control_relinquished = true;
        }
    }
}

/// Future for immutable physical completion observed through the registry.
pub struct SupervisedCompletionWait {
    observation: Arc<Mutex<SupervisedObservation>>,
}

impl Future for SupervisedCompletionWait {
    type Output = OwnedTaskCompletion;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut observation = lock(&self.observation);
        if let Some(completion) = &observation.completion {
            Poll::Ready(completion.clone())
        } else {
            register_waker(&mut observation.waiters, context.waker());
            Poll::Pending
        }
    }
}

/// Immutable registry projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSupervisorSnapshot {
    /// Whether unclean relinquish closed the registry to new submissions.
    pub closed: bool,
    /// Active physical tasks in registry identity order.
    pub tasks: Arc<[SupervisedTaskSnapshot]>,
}

/// Point-in-time state of one supervised task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisedTaskSnapshot {
    /// Registry-local task identity.
    pub id: u64,
    /// Semantic ownership domain.
    pub domain: SupervisedTaskDomain,
    /// Process-local execution owner, absent for legacy unowned preparation.
    pub execution_id: Option<ProtocolIdentity>,
    /// Process-local task owner, absent for legacy unowned preparation.
    pub task_id: Option<ProtocolIdentity>,
    /// Whether Gantry semantic settlement preceded physical observation.
    pub semantic_settled: bool,
    /// Immutable physical completion, when known.
    pub completion: Option<OwnedTaskCompletion>,
    /// Whether abort was requested through the registry.
    pub abort_requested: bool,
    /// First fixed abort result, when known.
    pub abort_result: Option<OwnedTaskAbort>,
    /// Whether the bounded external control share was relinquished.
    pub control_relinquished: bool,
    /// Whether physical completion preceded semantic settlement.
    pub abnormal_before_semantic: bool,
}

struct SupervisorInner {
    executor: Arc<dyn ExecutorAdapter>,
    admission: AsyncAdmission,
    state: Mutex<SupervisorState>,
}

#[derive(Default)]
struct SupervisorState {
    active: BTreeMap<u64, Arc<SupervisedEntry>>,
    submitting: BTreeSet<u64>,
    queue: VecDeque<u64>,
    queued: BTreeSet<u64>,
    draining: bool,
    finalizing: usize,
    closed: bool,
    quiescence_waiters: Vec<Waker>,
}

impl SupervisorInner {
    fn enqueue(this: &Arc<Self>, id: u64) {
        let should_drain = {
            let mut state = lock(&this.state);
            if !state.active.contains_key(&id) || !state.queued.insert(id) {
                return;
            }
            state.queue.push_back(id);
            if state.draining {
                false
            } else {
                state.draining = true;
                true
            }
        };
        if should_drain {
            Self::drain(this);
        }
    }

    fn drain(this: &Arc<Self>) {
        loop {
            let entry = {
                let mut state = lock(&this.state);
                let Some(id) = state.queue.pop_front() else {
                    state.draining = false;
                    return;
                };
                state.queued.remove(&id);
                state.active.get(&id).cloned()
            };
            let Some(entry) = entry else {
                continue;
            };
            let waker = Waker::from(Arc::clone(&entry.wake));
            let mut context = Context::from_waker(&waker);

            let abort_requested = lock(&entry.observation).abort_requested;
            if abort_requested
                && lock(&entry.observation).abort_result.is_none()
                && let Poll::Ready(result) = poll_abort(&entry, &mut context)
            {
                let waiters = {
                    let mut observation = lock(&entry.observation);
                    if observation.abort_result.is_none() {
                        observation.abort_result = Some(result);
                    }
                    std::mem::take(&mut observation.waiters)
                };
                wake_all(waiters);
            }

            if entry.observation_armed.load(Ordering::Acquire)
                && let Poll::Ready(completion) = poll_completion(&entry.handle, &mut context)
            {
                Self::complete(this, entry, completion);
            }
        }
    }

    fn complete(this: &Arc<Self>, entry: Arc<SupervisedEntry>, completion: OwnedTaskCompletion) {
        let entry = {
            let mut state = lock(&this.state);
            let Some(entry) = state.active.remove(&entry.id) else {
                return;
            };
            state.finalizing = state.finalizing.saturating_add(1);
            entry
        };
        let semantic_settled = entry.semantic.load(Ordering::Acquire);
        let run_callbacks = !entry.unclean_relinquished.load(Ordering::Acquire);
        let abnormal = (run_callbacks && !semantic_settled)
            .then(|| lock(&entry.abnormal).take())
            .flatten();
        if let Some(abnormal) = abnormal {
            let _ = catch_unwind(AssertUnwindSafe(|| abnormal(completion.clone())));
        }
        let completion_observer = run_callbacks
            .then(|| lock(&entry.completion).take())
            .flatten();
        let observation_waiters = {
            let mut observation = lock(&entry.observation);
            if observation.completion.is_none() {
                if observation.abort_requested && observation.abort_result.is_none() {
                    observation.abort_result = Some(abort_result_from_completion(&completion));
                }
                observation.abnormal_before_semantic = !semantic_settled;
                observation.completion = Some(completion.clone());
                std::mem::take(&mut observation.waiters)
            } else {
                Vec::new()
            }
        };
        let permit = lock(&entry.permit).take();
        wake_all(observation_waiters);
        drop(permit);
        if let Some(observer) = completion_observer {
            let observed = completion.clone();
            let _ = catch_unwind(AssertUnwindSafe(|| observer(observed)));
        }
        let _ = catch_unwind(AssertUnwindSafe(|| drop(entry)));
        let quiescence_waiters = {
            let mut state = lock(&this.state);
            state.finalizing = state.finalizing.saturating_sub(1);
            if shutdown_quiescent(&state) {
                std::mem::take(&mut state.quiescence_waiters)
            } else {
                Vec::new()
            }
        };
        wake_all(quiescence_waiters);
    }

    fn finish_failed_submission(this: &Arc<Self>, id: u64) {
        let waiters = {
            let mut state = lock(&this.state);
            state.submitting.remove(&id);
            if shutdown_quiescent(&state) {
                std::mem::take(&mut state.quiescence_waiters)
            } else {
                Vec::new()
            }
        };
        wake_all(waiters);
    }

    fn request_abort(this: &Arc<Self>, id: u64) -> bool {
        let entry = lock(&this.state).active.get(&id).cloned();
        let Some(entry) = entry else {
            return false;
        };
        entry.observation_armed.store(true, Ordering::Release);
        let completion_known = {
            let mut observation = lock(&entry.observation);
            observation.abort_requested = true;
            if observation.abort_result.is_none()
                && let Some(completion) = &observation.completion
            {
                observation.abort_result = Some(abort_result_from_completion(completion));
            }
            observation.completion.is_some()
        };
        if !completion_known {
            Self::enqueue(this, id);
        }
        true
    }
}

struct SupervisedEntry {
    id: u64,
    domain: SupervisedTaskDomain,
    owner: Option<SupervisedTaskOwner>,
    semantic: Arc<AtomicBool>,
    handle: Arc<dyn SubmittedTask>,
    abort: Mutex<Option<Pin<Box<dyn Future<Output = OwnedTaskAbort> + Send + 'static>>>>,
    observation: Arc<Mutex<SupervisedObservation>>,
    wake: Arc<ReaperWake>,
    permit: Mutex<Option<AdmissionPermit>>,
    abnormal: Mutex<Option<AbnormalCompletionHandler>>,
    completion: Mutex<Option<PhysicalCompletionHandler>>,
    observation_armed: AtomicBool,
    unclean_relinquished: AtomicBool,
}

impl SupervisedEntry {
    fn snapshot(&self) -> SupervisedTaskSnapshot {
        observation_snapshot(
            self.id,
            self.domain,
            self.owner,
            &self.observation,
            self.semantic.load(Ordering::Acquire),
        )
    }
}

#[derive(Clone, Copy)]
struct SupervisedTaskOwner {
    execution_id: ProtocolIdentity,
    task_id: ProtocolIdentity,
}

#[derive(Default)]
struct SupervisedObservation {
    completion: Option<OwnedTaskCompletion>,
    abort_requested: bool,
    abort_result: Option<OwnedTaskAbort>,
    control_relinquished: bool,
    abnormal_before_semantic: bool,
    waiters: Vec<Waker>,
}

struct ReaperWake {
    id: u64,
    supervisor: Arc<SupervisorInner>,
}

impl Wake for ReaperWake {
    fn wake(self: Arc<Self>) {
        self.enqueue();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.enqueue();
    }
}

impl ReaperWake {
    fn enqueue(&self) {
        SupervisorInner::enqueue(&self.supervisor, self.id);
    }
}

fn observation_snapshot(
    id: u64,
    domain: SupervisedTaskDomain,
    owner: Option<SupervisedTaskOwner>,
    observation: &Mutex<SupervisedObservation>,
    semantic_settled: bool,
) -> SupervisedTaskSnapshot {
    let observation = lock(observation);
    SupervisedTaskSnapshot {
        id,
        domain,
        execution_id: owner.map(|owner| owner.execution_id),
        task_id: owner.map(|owner| owner.task_id),
        semantic_settled,
        completion: observation.completion.clone(),
        abort_requested: observation.abort_requested,
        abort_result: observation.abort_result.clone(),
        control_relinquished: observation.control_relinquished,
        abnormal_before_semantic: observation.abnormal_before_semantic,
    }
}

fn poll_completion(
    handle: &Arc<dyn SubmittedTask>,
    context: &mut Context<'_>,
) -> Poll<OwnedTaskCompletion> {
    catch_unwind(AssertUnwindSafe(|| {
        let mut completion = handle.completion();
        completion.as_mut().poll(context)
    }))
    .unwrap_or_else(|_| Poll::Ready(OwnedTaskCompletion::Failed(executor_failure())))
}

fn poll_abort(entry: &SupervisedEntry, context: &mut Context<'_>) -> Poll<OwnedTaskAbort> {
    let mut admitted = lock(&entry.abort);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let abort = admitted.get_or_insert_with(|| {
            let handle = Arc::clone(&entry.handle);
            Box::pin(async move { handle.abort().await })
        });
        abort.as_mut().poll(context)
    }))
    .unwrap_or_else(|_| Poll::Ready(OwnedTaskAbort::Failed(executor_failure())));
    if result.is_ready() {
        let _ = admitted.take();
    }
    result
}

fn abort_result_from_completion(completion: &OwnedTaskCompletion) -> OwnedTaskAbort {
    match completion {
        OwnedTaskCompletion::Stopped => OwnedTaskAbort::Stopped,
        OwnedTaskCompletion::Failed(error) => OwnedTaskAbort::Failed(error.clone()),
        OwnedTaskCompletion::Completed(_) | OwnedTaskCompletion::Panicked { .. } => {
            OwnedTaskAbort::AlreadySettled
        }
    }
}

fn shutdown_quiescent(state: &SupervisorState) -> bool {
    state.finalizing == 0
        && state.submitting.is_empty()
        && state
            .active
            .values()
            .all(|entry| entry.domain == SupervisedTaskDomain::Shutdown)
}

fn register_waker(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|candidate| candidate.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

fn wake_all(waiters: Vec<Waker>) {
    for waiter in waiters {
        waiter.wake();
    }
}

fn executor_failure() -> HostError {
    HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use gantry_core::portable::IdentityKind;
    use gantry_host::contracts::{
        DurationMicros, HostFuture, InclusiveJitterRange, OwnedTaskResult,
    };

    use super::*;
    use crate::AsyncCapacityLimits;

    #[derive(Default)]
    struct RecordingExecutor {
        tasks: Mutex<Vec<Arc<RecordedTaskState>>>,
        fail_abort: AtomicBool,
        pending_abort: AtomicBool,
    }

    impl RecordingExecutor {
        fn tasks(&self) -> Vec<Arc<RecordedTaskState>> {
            lock(&self.tasks).clone()
        }

        fn fail_abort(&self) {
            self.fail_abort.store(true, Ordering::Release);
        }

        fn pending_abort(&self) {
            self.pending_abort.store(true, Ordering::Release);
        }
    }

    impl ExecutorAdapter for RecordingExecutor {
        fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
            let state = Arc::new(RecordedTaskState {
                task: Mutex::new(Some(task)),
                stopped: AtomicBool::new(false),
                aborts: AtomicUsize::new(0),
                abort_polls: AtomicUsize::new(0),
                completion_polls: AtomicUsize::new(0),
                fail_abort: self.fail_abort.load(Ordering::Acquire),
                pending_abort: self.pending_abort.load(Ordering::Acquire),
            });
            lock(&self.tasks).push(Arc::clone(&state));
            Ok(Box::new(RecordedTask { state }))
        }

        fn sleep<'a>(&'a self, _: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Ok(()) })
        }

        fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
            Ok(range.minimum())
        }
    }

    struct RecordedTask {
        state: Arc<RecordedTaskState>,
    }

    struct RecordedTaskState {
        task: Mutex<Option<OwnedTaskFuture>>,
        stopped: AtomicBool,
        aborts: AtomicUsize,
        abort_polls: AtomicUsize,
        completion_polls: AtomicUsize,
        fail_abort: bool,
        pending_abort: bool,
    }

    impl SubmittedTask for RecordedTask {
        fn completion<'a>(&'a self) -> HostFuture<'a, OwnedTaskCompletion> {
            Box::pin(std::future::poll_fn(move |_| {
                self.state.completion_polls.fetch_add(1, Ordering::AcqRel);
                if self.state.stopped.load(Ordering::Acquire) {
                    Poll::Ready(OwnedTaskCompletion::Stopped)
                } else {
                    Poll::Pending
                }
            }))
        }

        fn abort<'a>(&'a self) -> HostFuture<'a, OwnedTaskAbort> {
            self.state.aborts.fetch_add(1, Ordering::AcqRel);
            let result = if self.state.fail_abort {
                OwnedTaskAbort::Failed(HostError {
                    code: Arc::from("test-abort-failed"),
                    protected_diagnostic: None,
                })
            } else {
                OwnedTaskAbort::Stopped
            };
            let mut pending = self.state.pending_abort;
            Box::pin(std::future::poll_fn(move |context| {
                self.state.abort_polls.fetch_add(1, Ordering::AcqRel);
                if pending {
                    pending = false;
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.state.stopped.store(true, Ordering::Release);
                let _ = lock(&self.state.task).take();
                Poll::Ready(result.clone())
            }))
        }
    }

    #[test]
    fn owned_abort_selection_excludes_another_execution() {
        let (supervisor, executor) = supervisor();
        let execution_a = identity(IdentityKind::Execution, 1);
        let execution_b = identity(IdentityKind::Execution, 2);
        let task_a = identity(IdentityKind::Task, 3);
        let task_b = identity(IdentityKind::Task, 4);

        submit_owned(&supervisor, execution_a, task_a);
        submit_owned(&supervisor, execution_b, task_b);
        let unowned = submit_unowned(&supervisor);
        assert_eq!(unowned.snapshot().execution_id, None);
        assert_eq!(unowned.snapshot().task_id, None);

        let selected = supervisor.owned_task_controls(execution_a, &[task_a, task_b]);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].snapshot().execution_id, Some(execution_a));
        assert_eq!(selected[0].snapshot().task_id, Some(task_a));
        let tasks = executor.tasks();
        assert_eq!(tasks[0].aborts.load(Ordering::Acquire), 0);
        assert_eq!(tasks[1].aborts.load(Ordering::Acquire), 0);
        assert_eq!(tasks[2].aborts.load(Ordering::Acquire), 0);

        assert!(selected[0].request_abort());
        assert_eq!(
            selected[0].snapshot().completion,
            Some(OwnedTaskCompletion::Stopped)
        );
        assert_eq!(tasks[0].aborts.load(Ordering::Acquire), 1);
        assert_eq!(tasks[1].aborts.load(Ordering::Acquire), 0);
        assert_eq!(tasks[2].aborts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn owned_abort_selection_limits_one_execution_to_task_tree_subset() {
        let (supervisor, executor) = supervisor();
        let execution = identity(IdentityKind::Execution, 10);
        let root = identity(IdentityKind::Task, 11);
        let descendant = identity(IdentityKind::Task, 12);
        let other_task = identity(IdentityKind::Task, 13);

        submit_owned(&supervisor, execution, root);
        submit_owned(&supervisor, execution, descendant);
        submit_owned(&supervisor, execution, other_task);

        let selected = supervisor.request_abort_owned_tasks(execution, &[root, descendant]);

        assert_eq!(
            selected
                .iter()
                .map(|task| task.snapshot().task_id)
                .collect::<Vec<_>>(),
            vec![Some(root), Some(descendant)]
        );
        let tasks = executor.tasks();
        assert_eq!(tasks[0].aborts.load(Ordering::Acquire), 1);
        assert_eq!(tasks[1].aborts.load(Ordering::Acquire), 1);
        assert_eq!(tasks[2].aborts.load(Ordering::Acquire), 0);
        assert_eq!(
            supervisor
                .snapshot()
                .tasks
                .iter()
                .map(|task| task.task_id)
                .collect::<Vec<_>>(),
            vec![Some(other_task)]
        );
    }

    #[test]
    fn owned_abort_arms_deferred_completion_and_releases_permit() {
        let (supervisor, executor) = supervisor_with_root_capacity(1);
        let execution = identity(IdentityKind::Execution, 20);
        let task_id = identity(IdentityKind::Task, 21);
        let task = submit_owned_deferred(&supervisor, execution, task_id);
        let state = &executor.tasks()[0];

        assert_eq!(state.completion_polls.load(Ordering::Acquire), 0);
        assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_err());

        let selected = supervisor.request_abort_owned_tasks(execution, &[task_id]);

        assert_eq!(selected.len(), 1);
        assert_eq!(
            task.snapshot().completion,
            Some(OwnedTaskCompletion::Stopped)
        );
        assert!(state.completion_polls.load(Ordering::Acquire) > 0);
        assert!(supervisor.is_quiescent());
        assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_ok());
    }

    #[test]
    fn shutdown_abort_arms_deferred_completion_and_releases_permit() {
        let (supervisor, executor) = supervisor_with_root_capacity(1);
        let execution = identity(IdentityKind::Execution, 30);
        let task_id = identity(IdentityKind::Task, 31);
        let task = submit_owned_deferred(&supervisor, execution, task_id);
        let state = &executor.tasks()[0];

        assert_eq!(state.completion_polls.load(Ordering::Acquire), 0);
        assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_err());

        let selected = supervisor.request_abort_shutdown_work();

        assert_eq!(selected.len(), 1);
        assert_eq!(
            task.snapshot().completion,
            Some(OwnedTaskCompletion::Stopped)
        );
        assert!(state.completion_polls.load(Ordering::Acquire) > 0);
        assert!(supervisor.is_quiescent());
        assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_ok());
    }

    #[test]
    fn deferred_abort_failure_remains_observable_after_completion() {
        let (supervisor, executor) = supervisor_with_root_capacity(1);
        executor.fail_abort();
        let execution = identity(IdentityKind::Execution, 40);
        let task_id = identity(IdentityKind::Task, 41);
        submit_owned_deferred(&supervisor, execution, task_id);

        let selected = supervisor.request_abort_owned_tasks(execution, &[task_id]);
        let snapshot = selected[0].snapshot();

        assert!(matches!(
            snapshot.abort_result,
            Some(OwnedTaskAbort::Failed(_))
        ));
        assert_eq!(snapshot.completion, Some(OwnedTaskCompletion::Stopped));
        assert!(supervisor.is_quiescent());
        assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_ok());
    }

    #[test]
    fn pending_abort_future_is_retained_until_ready() {
        let (supervisor, executor) = supervisor_with_root_capacity(1);
        executor.pending_abort();
        let execution = identity(IdentityKind::Execution, 50);
        let task_id = identity(IdentityKind::Task, 51);
        let task = submit_owned_deferred(&supervisor, execution, task_id);

        let selected = supervisor.request_abort_owned_tasks(execution, &[task_id]);
        let state = &executor.tasks()[0];

        assert_eq!(selected.len(), 1);
        assert_eq!(state.aborts.load(Ordering::Acquire), 1);
        assert_eq!(state.abort_polls.load(Ordering::Acquire), 2);
        assert_eq!(task.snapshot().abort_result, Some(OwnedTaskAbort::Stopped));
        assert_eq!(
            task.snapshot().completion,
            Some(OwnedTaskCompletion::Stopped)
        );
        assert!(supervisor.is_quiescent());
        assert!(supervisor.try_reserve(AdmissionClass::RootTask).is_ok());
    }

    fn supervisor() -> (TaskSupervisor, Arc<RecordingExecutor>) {
        supervisor_with_root_capacity(8)
    }

    fn supervisor_with_root_capacity(
        maximum_active_root_tasks: u64,
    ) -> (TaskSupervisor, Arc<RecordingExecutor>) {
        let executor = Arc::new(RecordingExecutor::default());
        let limits = AsyncCapacityLimits::new(maximum_active_root_tasks, 8, 8, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity fixture failed: {error}"));
        let supervisor = TaskSupervisor::new(executor.clone(), AsyncAdmission::new(limits));
        (supervisor, executor)
    }

    fn submit_owned(
        supervisor: &TaskSupervisor,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) -> SupervisedTask {
        let registration =
            supervisor.prepare_owned(SupervisedTaskDomain::Root, execution_id, task_id, None);
        submit(supervisor, registration)
    }

    fn submit_unowned(supervisor: &TaskSupervisor) -> SupervisedTask {
        let registration = supervisor.prepare(SupervisedTaskDomain::Root, None);
        submit(supervisor, registration)
    }

    fn submit_owned_deferred(
        supervisor: &TaskSupervisor,
        execution_id: ProtocolIdentity,
        task_id: ProtocolIdentity,
    ) -> SupervisedTask {
        let registration = supervisor.prepare_owned_deferred_with_completion(
            SupervisedTaskDomain::Root,
            execution_id,
            task_id,
            None,
            None,
        );
        submit(supervisor, registration)
    }

    fn submit(
        supervisor: &TaskSupervisor,
        registration: SupervisionRegistration,
    ) -> SupervisedTask {
        let permit = supervisor
            .try_reserve(AdmissionClass::RootTask)
            .unwrap_or_else(|error| panic!("task reservation failed: {error}"))
            .transfer();
        supervisor
            .submit(
                registration,
                Box::pin(async { OwnedTaskResult::new() }),
                permit,
            )
            .unwrap_or_else(|error| panic!("task submission failed: {error:?}"))
    }

    fn identity(kind: IdentityKind, value: u8) -> ProtocolIdentity {
        match kind {
            IdentityKind::Execution => ProtocolIdentity::from_fresh_material(kind, [value; 32])
                .unwrap_or_else(|error| panic!("execution identity failed: {error}")),
            IdentityKind::Task => ProtocolIdentity::derive(kind, &[value])
                .unwrap_or_else(|error| panic!("task identity failed: {error}")),
            _ => unreachable!("fixture supports execution and task identities"),
        }
    }
}
