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
        let id = NEXT_SUPERVISED_TASK_ID.fetch_add(1, Ordering::Relaxed);
        let semantic = Arc::new(AtomicBool::new(false));
        SupervisionRegistration {
            id,
            domain,
            supervisor: Arc::downgrade(&self.inner),
            semantic: Arc::clone(&semantic),
            signal: SupervisionSignal {
                id,
                supervisor: Arc::downgrade(&self.inner),
                semantic,
            },
            abnormal,
            completion,
        }
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
            || lock(&self.inner.state).closed
        {
            return reject_task_submission(task).map(|_| unreachable!("submission was rejected"));
        }
        let submitted = catch_unwind(AssertUnwindSafe(|| self.inner.executor.spawn(task)))
            .unwrap_or_else(|_| Err(executor_failure()))?;
        let handle: Arc<dyn SubmittedTask> = Arc::from(submitted);
        let observation = Arc::new(Mutex::new(SupervisedObservation::default()));
        let wake = Arc::new(ReaperWake {
            id: registration.id,
            supervisor: Arc::clone(&self.inner),
        });
        let entry = Arc::new(SupervisedEntry {
            id: registration.id,
            domain: registration.domain,
            semantic: registration.semantic,
            handle,
            observation: Arc::clone(&observation),
            wake,
            permit: Mutex::new(Some(permit)),
            abnormal: Mutex::new(registration.abnormal),
            completion: Mutex::new(registration.completion),
        });
        {
            let mut state = lock(&self.inner.state);
            if state.closed {
                drop(state);
                drop(entry);
                return Err(executor_failure());
            }
            state.active.insert(registration.id, Arc::clone(&entry));
        }
        SupervisorInner::enqueue(&self.inner, registration.id);
        Ok(SupervisedTask {
            id: registration.id,
            domain: registration.domain,
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
        state.active.is_empty() && state.finalizing == 0
    }

    /// Returns whether only the shutdown coordinator itself remains active.
    #[must_use]
    pub fn is_shutdown_quiescent(&self) -> bool {
        shutdown_quiescent(&lock(&self.inner.state))
    }

    /// Polls registry quiescence and registers one wake without allocating a watcher task.
    pub fn poll_quiescence(&self, context: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.inner.state);
        if state.active.is_empty() && state.finalizing == 0 {
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

    /// Closes the registry, requests abort once, and relinquishes every handle.
    ///
    /// This is the synchronous unclean-drop path. It deliberately does not run
    /// abnormal-completion callbacks or fabricate semantic settlement.
    pub fn abort_and_relinquish_all(&self) {
        let entries = {
            let mut state = lock(&self.inner.state);
            state.closed = true;
            state.queue.clear();
            state.queued.clear();
            std::mem::take(&mut state.active)
                .into_values()
                .collect::<Vec<_>>()
        };
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        for entry in entries {
            let abort = poll_abort(&entry.handle, &mut context);
            let completion = poll_completion(&entry.handle, &mut context);
            let waiters = {
                let mut observation = lock(&entry.observation);
                observation.abort_requested = true;
                if let Poll::Ready(result) = abort {
                    observation.abort_result = Some(result);
                }
                if let Poll::Ready(completion) = completion {
                    observation.abnormal_before_semantic = !entry.semantic.load(Ordering::Acquire);
                    observation.completion = Some(completion);
                }
                observation.control_relinquished = true;
                std::mem::take(&mut observation.waiters)
            };
            wake_all(waiters);
            let permit = lock(&entry.permit).take();
            drop(permit);
            let _ = catch_unwind(AssertUnwindSafe(|| drop(entry)));
        }
        wake_all(take_quiescence_waiters(&self.inner));
    }
}

/// Prepared ownership metadata shared with a task before executor submission.
pub struct SupervisionRegistration {
    id: u64,
    domain: SupervisedTaskDomain,
    supervisor: Weak<SupervisorInner>,
    semantic: Arc<AtomicBool>,
    signal: SupervisionSignal,
    abnormal: Option<AbnormalCompletionHandler>,
    completion: Option<PhysicalCompletionHandler>,
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
}

/// Non-owning control and observation capability for one registered task.
pub struct SupervisedTask {
    id: u64,
    domain: SupervisedTaskDomain,
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
            if state.closed || !state.active.contains_key(&id) || !state.queued.insert(id) {
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
                && let Poll::Ready(result) = poll_abort(&entry.handle, &mut context)
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

            if let Poll::Ready(completion) = poll_completion(&entry.handle, &mut context) {
                Self::complete(this, entry, completion);
            }
        }
    }

    fn complete(this: &Arc<Self>, entry: Arc<SupervisedEntry>, completion: OwnedTaskCompletion) {
        let entry = {
            let mut state = lock(&this.state);
            if state.closed {
                return;
            }
            let Some(entry) = state.active.remove(&entry.id) else {
                return;
            };
            state.finalizing = state.finalizing.saturating_add(1);
            entry
        };
        let semantic_settled = entry.semantic.load(Ordering::Acquire);
        let abnormal = (!semantic_settled)
            .then(|| lock(&entry.abnormal).take())
            .flatten();
        if let Some(abnormal) = abnormal {
            let _ = catch_unwind(AssertUnwindSafe(|| abnormal(completion.clone())));
        }
        if let Some(observer) = lock(&entry.completion).take() {
            let observed = completion.clone();
            let _ = catch_unwind(AssertUnwindSafe(|| observer(observed)));
        }
        let observation_waiters = {
            let mut observation = lock(&entry.observation);
            if observation.completion.is_none() {
                if observation.abort_requested && observation.abort_result.is_none() {
                    observation.abort_result = Some(abort_result_from_completion(&completion));
                }
                observation.abnormal_before_semantic = !semantic_settled;
                observation.completion = Some(completion);
                std::mem::take(&mut observation.waiters)
            } else {
                Vec::new()
            }
        };
        let permit = lock(&entry.permit).take();
        wake_all(observation_waiters);
        drop(permit);
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

    fn request_abort(this: &Arc<Self>, id: u64) -> bool {
        let entry = lock(&this.state).active.get(&id).cloned();
        let Some(entry) = entry else {
            return false;
        };
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
    semantic: Arc<AtomicBool>,
    handle: Arc<dyn SubmittedTask>,
    observation: Arc<Mutex<SupervisedObservation>>,
    wake: Arc<ReaperWake>,
    permit: Mutex<Option<AdmissionPermit>>,
    abnormal: Mutex<Option<AbnormalCompletionHandler>>,
    completion: Mutex<Option<PhysicalCompletionHandler>>,
}

impl SupervisedEntry {
    fn snapshot(&self) -> SupervisedTaskSnapshot {
        observation_snapshot(
            self.id,
            self.domain,
            &self.observation,
            self.semantic.load(Ordering::Acquire),
        )
    }
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
    observation: &Mutex<SupervisedObservation>,
    semantic_settled: bool,
) -> SupervisedTaskSnapshot {
    let observation = lock(observation);
    SupervisedTaskSnapshot {
        id,
        domain,
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

fn poll_abort(handle: &Arc<dyn SubmittedTask>, context: &mut Context<'_>) -> Poll<OwnedTaskAbort> {
    catch_unwind(AssertUnwindSafe(|| {
        let mut abort = handle.abort();
        abort.as_mut().poll(context)
    }))
    .unwrap_or_else(|_| Poll::Ready(OwnedTaskAbort::Failed(executor_failure())))
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

fn take_quiescence_waiters(inner: &SupervisorInner) -> Vec<Waker> {
    std::mem::take(&mut lock(&inner.state).quiescence_waiters)
}

fn shutdown_quiescent(state: &SupervisorState) -> bool {
    state.finalizing == 0
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
