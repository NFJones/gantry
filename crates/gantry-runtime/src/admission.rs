//! Bounded nonblocking admission for interpreter-owned operational work.
//!
//! This module owns operational capacity only. It is distinct from public-call
//! lifecycle admission and from the cumulative source-language task limit.
//! Ordinary batch requests are evaluated in one fixed acquisition order under
//! one short-lived lock, so partial acquisition and permit-order cycles are
//! impossible. The control-plane reserve has a separate entry point and cannot
//! be included in an ordinary request.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::AsyncCapacityLimits;

const ORDINARY_CLASS_COUNT: usize = 8;

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
    use super::{
        AdmissionBoundary, AdmissionClass, AdmissionFailureCategory, AdmissionRequest,
        AdmissionResourceClass, AsyncAdmission,
    };
    use crate::AsyncCapacityLimits;

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

    fn limits(value: u64) -> AsyncCapacityLimits {
        AsyncCapacityLimits::new(
            value, value, value, value, value, value, value, value, value,
        )
        .unwrap_or_else(|error| panic!("capacity fixture failed: {error}"))
    }
}
