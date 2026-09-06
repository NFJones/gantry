//! Bounded nonblocking admission for interpreter-owned operational work.
//!
//! This module owns operational capacity only. It is distinct from public-call
//! lifecycle admission and from the cumulative source-language task limit.
//! Ordinary batch requests are evaluated in one fixed acquisition order under
//! one short-lived lock, so partial acquisition and permit-order cycles are
//! impossible. The control-plane reserve has a separate entry point and cannot
//! be included in an ordinary request.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use crate::AsyncCapacityLimits;

const ORDINARY_CLASS_COUNT: usize = 8;
static NEXT_ADMISSION_WAITER_ID: AtomicU64 = AtomicU64::new(1);

/// One ordinary bounded operational resource class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum AdmissionClass {
    /// Root drivers across all executions.
    RootTask = 0,
    /// Source-created child drivers across all executions.
    SourceChildTask = 1,
    /// Complete runnable sets reconstructed by resume.
    ResumeRunnableTask = 2,
    /// Admitted public-operation activities.
    PublicActivity = 3,
    /// Interpreter-owned background tasks.
    InterpreterBackgroundTask = 4,
    /// Blocking jobs admitted to a bounded queue.
    QueuedBlockingJob = 5,
    /// Blocking jobs that have started and must be retained.
    ActiveBlockingJob = 6,
    /// Active event-delivery work.
    EventDelivery = 7,
}

impl AdmissionClass {
    /// Global ordinary acquisition order.
    pub const ACQUISITION_ORDER: [Self; ORDINARY_CLASS_COUNT] = [
        Self::RootTask,
        Self::SourceChildTask,
        Self::ResumeRunnableTask,
        Self::PublicActivity,
        Self::InterpreterBackgroundTask,
        Self::QueuedBlockingJob,
        Self::ActiveBlockingJob,
        Self::EventDelivery,
    ];

    /// Returns the stable operational name used in diagnostics and tests.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::RootTask => "root-task",
            Self::SourceChildTask => "source-child-task",
            Self::ResumeRunnableTask => "resume-runnable-task",
            Self::PublicActivity => "public-activity",
            Self::InterpreterBackgroundTask => "interpreter-background-task",
            Self::QueuedBlockingJob => "queued-blocking-job",
            Self::ActiveBlockingJob => "active-blocking-job",
            Self::EventDelivery => "event-delivery",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Any bounded admission resource, including the isolated cleanup reserve.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionResourceClass {
    /// An ordinary resource class.
    Ordinary(AdmissionClass),
    /// Capacity reserved for cleanup and control-plane progress.
    ControlPlaneTask,
}

impl AdmissionResourceClass {
    /// Returns the stable operational name used in diagnostics and tests.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ordinary(class) => class.wire_name(),
            Self::ControlPlaneTask => "control-plane-task",
        }
    }
}

/// Canonical ordinary admission request.
///
/// Counts are stored by [`AdmissionClass::ACQUISITION_ORDER`], independent of
/// the order in which callers populate the request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionRequest {
    counts: [u64; ORDINARY_CLASS_COUNT],
}

impl AdmissionRequest {
    /// Creates an empty request, useful for a terminal resume with no runnable work.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counts: [0; ORDINARY_CLASS_COUNT],
        }
    }

    /// Creates a request for one ordinary resource class.
    #[must_use]
    pub const fn single(class: AdmissionClass, count: u64) -> Self {
        Self::new().with(class, count)
    }

    /// Replaces one class count while preserving canonical acquisition order.
    #[must_use]
    pub const fn with(mut self, class: AdmissionClass, count: u64) -> Self {
        self.counts[class.index()] = count;
        self
    }

    /// Returns the requested count for one class.
    #[must_use]
    pub const fn count(self, class: AdmissionClass) -> u64 {
        self.counts[class.index()]
    }

    /// Returns whether the request consumes no operational capacity.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.counts.iter().all(|count| *count == 0)
    }
}

/// Side of an acceptance boundary at which overload is reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionBoundary {
    /// Predictable refusal before start, resume, or activity acceptance.
    PreAcceptance,
    /// Exceptional refusal after Gantry has admitted semantic work.
    PostAcceptance,
}

/// Stable failure category selected for admission exhaustion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionFailureCategory {
    /// Predictable operational saturation before acceptance.
    ImplementationResourceExhaustion,
    /// Operational capacity loss after semantic acceptance.
    ExecutorFailure,
}

impl AdmissionFailureCategory {
    /// Returns the exact public failure-category spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ImplementationResourceExhaustion => "implementation-resource-exhaustion",
            Self::ExecutorFailure => "executor-failure",
        }
    }
}

/// Nonblocking admission refusal for one exhausted resource class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionExhaustion {
    /// Resource that could not satisfy the complete request.
    pub resource: AdmissionResourceClass,
    /// Requested units for that resource.
    pub requested: u64,
    /// Units available at the atomic admission check.
    pub available: u64,
}

impl AdmissionExhaustion {
    /// Maps overload according to the owning operation's acceptance boundary.
    #[must_use]
    pub const fn category(self, boundary: AdmissionBoundary) -> AdmissionFailureCategory {
        match boundary {
            AdmissionBoundary::PreAcceptance => {
                AdmissionFailureCategory::ImplementationResourceExhaustion
            }
            AdmissionBoundary::PostAcceptance => AdmissionFailureCategory::ExecutorFailure,
        }
    }
}

impl fmt::Display for AdmissionExhaustion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} admission exhausted: requested {}, available {}",
            self.resource.wire_name(),
            self.requested,
            self.available
        )
    }
}

impl std::error::Error for AdmissionExhaustion {}

/// Shared bounded operational admission owner.
#[derive(Clone)]
pub struct AsyncAdmission {
    inner: Arc<AdmissionInner>,
}

impl fmt::Debug for AsyncAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsyncAdmission")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl AsyncAdmission {
    /// Creates an empty admission owner for the validated capacity policy.
    #[must_use]
    pub fn new(limits: AsyncCapacityLimits) -> Self {
        Self {
            inner: Arc::new(AdmissionInner {
                limits,
                state: Mutex::new(AdmissionState::default()),
            }),
        }
    }

    /// Atomically reserves a complete ordinary request without waiting.
    pub fn try_reserve(
        &self,
        request: AdmissionRequest,
    ) -> Result<AdmissionReservation, AdmissionExhaustion> {
        let mut state = lock(&self.inner.state);
        for class in AdmissionClass::ACQUISITION_ORDER {
            let requested = request.count(class);
            let available = self
                .inner
                .limits
                .capacity(class)
                .saturating_sub(state.ordinary[class.index()]);
            if requested > available {
                return Err(AdmissionExhaustion {
                    resource: AdmissionResourceClass::Ordinary(class),
                    requested,
                    available,
                });
            }
        }
        for class in AdmissionClass::ACQUISITION_ORDER {
            state.ordinary[class.index()] =
                state.ordinary[class.index()].saturating_add(request.count(class));
        }
        drop(state);
        Ok(AdmissionReservation::new(AdmissionLease {
            admission: self.clone(),
            ordinary: request.counts,
            control_plane: 0,
        }))
    }

    /// Creates an owned wait for one complete ordinary reservation.
    pub(crate) fn reserve(&self, request: AdmissionRequest) -> AdmissionWait {
        AdmissionWait {
            admission: self.clone(),
            request,
            waiter_id: NEXT_ADMISSION_WAITER_ID.fetch_add(1, Ordering::Relaxed),
            completed: false,
        }
    }

    /// Reserves cleanup/control-plane capacity without exposing it to ordinary batches.
    pub fn try_reserve_control_plane(
        &self,
        count: u64,
    ) -> Result<AdmissionReservation, AdmissionExhaustion> {
        let mut state = lock(&self.inner.state);
        let available = self
            .inner
            .limits
            .reserved_control_plane_tasks()
            .saturating_sub(state.control_plane);
        if count > available {
            return Err(AdmissionExhaustion {
                resource: AdmissionResourceClass::ControlPlaneTask,
                requested: count,
                available,
            });
        }
        state.control_plane = state.control_plane.saturating_add(count);
        drop(state);
        Ok(AdmissionReservation::new(AdmissionLease {
            admission: self.clone(),
            ordinary: [0; ORDINARY_CLASS_COUNT],
            control_plane: count,
        }))
    }

    /// Returns one bounded point-in-time usage snapshot.
    #[must_use]
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let state = lock(&self.inner.state);
        AdmissionSnapshot {
            limits: self.inner.limits,
            ordinary: state.ordinary,
            control_plane: state.control_plane,
        }
    }

    fn release(&self, ordinary: [u64; ORDINARY_CLASS_COUNT], control_plane: u64) {
        let mut state = lock(&self.inner.state);
        for class in AdmissionClass::ACQUISITION_ORDER {
            state.ordinary[class.index()] =
                state.ordinary[class.index()].saturating_sub(ordinary[class.index()]);
        }
        state.control_plane = state.control_plane.saturating_sub(control_plane);
        let waiters = std::mem::take(&mut state.waiters);
        drop(state);
        for waiter in waiters {
            waiter.waker.wake();
        }
    }
}

struct AdmissionInner {
    limits: AsyncCapacityLimits,
    state: Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    ordinary: [u64; ORDINARY_CLASS_COUNT],
    control_plane: u64,
    waiters: Vec<AdmissionWaiter>,
}

struct AdmissionWaiter {
    id: u64,
    waker: Waker,
}

/// Owned registration for one atomically acquired ordinary request.
pub(crate) struct AdmissionWait {
    admission: AsyncAdmission,
    request: AdmissionRequest,
    waiter_id: u64,
    completed: bool,
}

impl Future for AdmissionWait {
    type Output = AdmissionReservation;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let reservation = {
            let mut state = lock(&self.admission.inner.state);
            let available = AdmissionClass::ACQUISITION_ORDER.into_iter().all(|class| {
                self.request.count(class)
                    <= self
                        .admission
                        .inner
                        .limits
                        .capacity(class)
                        .saturating_sub(state.ordinary[class.index()])
            });
            if available {
                remove_admission_waiter(&mut state.waiters, self.waiter_id);
                for class in AdmissionClass::ACQUISITION_ORDER {
                    state.ordinary[class.index()] =
                        state.ordinary[class.index()].saturating_add(self.request.count(class));
                }
                Some(AdmissionReservation::new(AdmissionLease {
                    admission: self.admission.clone(),
                    ordinary: self.request.counts,
                    control_plane: 0,
                }))
            } else {
                register_admission_waiter(&mut state.waiters, self.waiter_id, context.waker());
                None
            }
        };
        if let Some(reservation) = reservation {
            self.completed = true;
            Poll::Ready(reservation)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for AdmissionWait {
    fn drop(&mut self) {
        if !self.completed {
            remove_admission_waiter(
                &mut lock(&self.admission.inner.state).waiters,
                self.waiter_id,
            );
        }
    }
}

fn register_admission_waiter(waiters: &mut Vec<AdmissionWaiter>, id: u64, waker: &Waker) {
    if let Some(waiter) = waiters.iter_mut().find(|waiter| waiter.id == id) {
        if !waiter.waker.will_wake(waker) {
            waiter.waker = waker.clone();
        }
    } else {
        waiters.push(AdmissionWaiter {
            id,
            waker: waker.clone(),
        });
    }
}

fn remove_admission_waiter(waiters: &mut Vec<AdmissionWaiter>, id: u64) {
    waiters.retain(|waiter| waiter.id != id);
}

/// Immutable bounded usage projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionSnapshot {
    limits: AsyncCapacityLimits,
    ordinary: [u64; ORDINARY_CLASS_COUNT],
    control_plane: u64,
}

impl AdmissionSnapshot {
    /// Returns the configured capacity for one resource.
    #[must_use]
    pub const fn capacity(self, resource: AdmissionResourceClass) -> u64 {
        match resource {
            AdmissionResourceClass::Ordinary(class) => self.limits.capacity(class),
            AdmissionResourceClass::ControlPlaneTask => self.limits.reserved_control_plane_tasks(),
        }
    }

    /// Returns currently owned units for one resource.
    #[must_use]
    pub const fn in_use(self, resource: AdmissionResourceClass) -> u64 {
        match resource {
            AdmissionResourceClass::Ordinary(class) => self.ordinary[class.index()],
            AdmissionResourceClass::ControlPlaneTask => self.control_plane,
        }
    }
}

struct AdmissionLease {
    admission: AsyncAdmission,
    ordinary: [u64; ORDINARY_CLASS_COUNT],
    control_plane: u64,
}

impl AdmissionLease {
    fn release(self) {
        self.admission.release(self.ordinary, self.control_plane);
    }
}

/// Pre-submission capacity whose drop performs bounded rollback.
#[must_use = "dropping a reservation rolls its capacity back"]
pub struct AdmissionReservation {
    lease: Option<AdmissionLease>,
}

impl AdmissionReservation {
    fn new(lease: AdmissionLease) -> Self {
        Self { lease: Some(lease) }
    }

    /// Splits one single-class batch into exact single-unit task permits.
    ///
    /// This preserves the atomic reservation boundary while allowing each
    /// independently supervised task to retain its own physical-settlement
    /// permit. Mixed-class and control-plane reservations are rejected.
    pub(crate) fn into_single_permits(
        mut self,
        class: AdmissionClass,
    ) -> Result<Vec<AdmissionPermit>, Self> {
        let Some(lease) = self.lease.as_ref() else {
            return Err(self);
        };
        let count = lease.ordinary[class.index()];
        if lease.control_plane != 0
            || count == 0
            || AdmissionClass::ACQUISITION_ORDER
                .into_iter()
                .filter(|candidate| *candidate != class)
                .any(|candidate| lease.ordinary[candidate.index()] != 0)
        {
            return Err(self);
        }
        let lease = self
            .lease
            .take()
            .unwrap_or_else(|| unreachable!("validated reservation retains its lease"));
        let admission = lease.admission;
        let permits = (0..count)
            .map(|_| {
                let mut ordinary = [0; ORDINARY_CLASS_COUNT];
                ordinary[class.index()] = 1;
                AdmissionPermit {
                    lease: Some(AdmissionLease {
                        admission: admission.clone(),
                        ordinary,
                        control_plane: 0,
                    }),
                }
            })
            .collect();
        Ok(permits)
    }

    /// Transfers the complete reservation to its submitted-work owner.
    pub fn transfer(mut self) -> AdmissionPermit {
        AdmissionPermit {
            lease: self.lease.take(),
        }
    }

    /// Releases a pre-acceptance reservation explicitly.
    pub fn rollback(mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}

/// Capacity owned by admitted or submitted work until physical settlement.
#[must_use = "the permit must be retained until owned work physically settles"]
pub struct AdmissionPermit {
    lease: Option<AdmissionLease>,
}

impl AdmissionPermit {
    pub(crate) fn matches(
        &self,
        admission: &AsyncAdmission,
        resource: AdmissionResourceClass,
    ) -> bool {
        let Some(lease) = &self.lease else {
            return false;
        };
        if !Arc::ptr_eq(&lease.admission.inner, &admission.inner) {
            return false;
        }
        match resource {
            AdmissionResourceClass::Ordinary(class) => {
                lease.control_plane == 0
                    && lease.ordinary[class.index()] == 1
                    && AdmissionClass::ACQUISITION_ORDER
                        .into_iter()
                        .filter(|candidate| *candidate != class)
                        .all(|candidate| lease.ordinary[candidate.index()] == 0)
            }
            AdmissionResourceClass::ControlPlaneTask => {
                lease.control_plane == 1 && lease.ordinary.into_iter().all(|count| count == 0)
            }
        }
    }

    /// Releases capacity after physical settlement or completed bounded rollback.
    pub fn release(mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    use super::{
        AdmissionBoundary, AdmissionClass, AdmissionFailureCategory, AdmissionRequest,
        AdmissionResourceClass, AsyncAdmission, lock,
    };
    use crate::AsyncCapacityLimits;

    #[derive(Default)]
    struct CountingWake {
        wakes: AtomicUsize,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn batch_reservation_is_atomic_and_transfer_releases_once() {
        let admission = AsyncAdmission::new(limits(1));
        let request = AdmissionRequest::new()
            .with(AdmissionClass::RootTask, 1)
            .with(AdmissionClass::EventDelivery, 1);
        let reservation = admission
            .try_reserve(request)
            .unwrap_or_else(|error| panic!("initial reservation failed: {error}"));
        let refused = admission.try_reserve(request);
        assert!(matches!(
            refused,
            Err(error)
                if error.resource
                    == AdmissionResourceClass::Ordinary(AdmissionClass::RootTask)
                    && error.requested == 1
                    && error.available == 0
                    && error.category(AdmissionBoundary::PreAcceptance)
                        == AdmissionFailureCategory::ImplementationResourceExhaustion
                    && error.category(AdmissionBoundary::PostAcceptance)
                        == AdmissionFailureCategory::ExecutorFailure
        ));
        let snapshot = admission.snapshot();
        assert_eq!(
            snapshot.in_use(AdmissionResourceClass::Ordinary(
                AdmissionClass::EventDelivery
            )),
            1
        );

        let permit = reservation.transfer();
        assert!(admission.try_reserve(request).is_err());
        permit.release();
        assert!(admission.try_reserve(request).is_ok());
    }

    #[test]
    fn ordinary_saturation_cannot_consume_cleanup_progress() {
        let admission = AsyncAdmission::new(limits(1));
        let ordinary = admission
            .try_reserve(AdmissionRequest::single(
                AdmissionClass::InterpreterBackgroundTask,
                1,
            ))
            .unwrap_or_else(|error| panic!("ordinary reservation failed: {error}"));
        assert!(
            admission
                .try_reserve(AdmissionRequest::single(
                    AdmissionClass::InterpreterBackgroundTask,
                    1,
                ))
                .is_err()
        );
        let cleanup = admission
            .try_reserve_control_plane(1)
            .unwrap_or_else(|error| panic!("cleanup reservation failed: {error}"));
        assert!(admission.try_reserve_control_plane(1).is_err());
        drop(ordinary);
        drop(cleanup);
        assert_eq!(
            admission
                .snapshot()
                .in_use(AdmissionResourceClass::ControlPlaneTask),
            0
        );
    }

    #[test]
    fn failed_batch_and_capacity_one_child_request_do_not_partially_acquire() {
        let admission = AsyncAdmission::new(limits(1));
        let root = admission
            .try_reserve(AdmissionRequest::single(AdmissionClass::RootTask, 1))
            .unwrap_or_else(|error| panic!("root reservation failed: {error}"));
        let batch = AdmissionRequest::new()
            .with(AdmissionClass::RootTask, 1)
            .with(AdmissionClass::SourceChildTask, 1);
        assert!(admission.try_reserve(batch).is_err());
        assert_eq!(
            admission
                .snapshot()
                .in_use(AdmissionResourceClass::Ordinary(
                    AdmissionClass::SourceChildTask
                )),
            0
        );
        let child =
            admission.try_reserve(AdmissionRequest::single(AdmissionClass::SourceChildTask, 1));
        assert!(
            child.is_ok(),
            "child admission waited on or shared root capacity"
        );
        drop(root);
    }

    #[test]
    fn owned_waiters_replace_wakers_deregister_on_drop_and_wake_once() {
        let admission = AsyncAdmission::new(limits(1));
        let request = AdmissionRequest::single(AdmissionClass::EventDelivery, 1);
        let occupied = admission
            .try_reserve(request)
            .unwrap_or_else(|error| panic!("initial reservation failed: {error}"));

        for _ in 0..128 {
            let wake = Arc::new(CountingWake::default());
            let waker = Waker::from(Arc::clone(&wake));
            let mut context = Context::from_waker(&waker);
            let mut cancelled = Box::pin(admission.reserve(request));
            assert!(cancelled.as_mut().poll(&mut context).is_pending());
            assert_eq!(lock(&admission.inner.state).waiters.len(), 1);
            drop(cancelled);
            assert!(lock(&admission.inner.state).waiters.is_empty());
            assert_eq!(wake.wakes.load(Ordering::Acquire), 0);
        }

        let first_wake = Arc::new(CountingWake::default());
        let replacement_wake = Arc::new(CountingWake::default());
        let dropped_wake = Arc::new(CountingWake::default());
        let mut first = Box::pin(admission.reserve(request));
        let mut dropped = Box::pin(admission.reserve(request));
        let first_waker = Waker::from(Arc::clone(&first_wake));
        let replacement_waker = Waker::from(Arc::clone(&replacement_wake));
        let dropped_waker = Waker::from(Arc::clone(&dropped_wake));
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&replacement_waker))
                .is_pending()
        );
        assert!(
            dropped
                .as_mut()
                .poll(&mut Context::from_waker(&dropped_waker))
                .is_pending()
        );
        assert_eq!(lock(&admission.inner.state).waiters.len(), 2);
        drop(dropped);
        assert_eq!(lock(&admission.inner.state).waiters.len(), 1);

        drop(occupied);
        assert_eq!(first_wake.wakes.load(Ordering::Acquire), 0);
        assert_eq!(replacement_wake.wakes.load(Ordering::Acquire), 1);
        assert_eq!(dropped_wake.wakes.load(Ordering::Acquire), 0);
        let reservation = match Pin::new(&mut first)
            .poll(&mut Context::from_waker(&replacement_waker))
        {
            std::task::Poll::Ready(reservation) => reservation,
            std::task::Poll::Pending => panic!("retained waiter was not admitted after release"),
        };
        assert!(lock(&admission.inner.state).waiters.is_empty());
        drop(reservation);
    }

    fn limits(value: u64) -> AsyncCapacityLimits {
        AsyncCapacityLimits::new(
            value, value, value, value, value, value, value, value, value,
        )
        .unwrap_or_else(|error| panic!("capacity fixture failed: {error}"))
    }
}
