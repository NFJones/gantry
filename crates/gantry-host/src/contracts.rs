//! Executor-neutral Rust boundaries for Gantry integrations.
//!
//! These interfaces own transport and asynchronous ownership shape only.
//! Canonical JSON Schemas under `protocol/` remain the wire authority; Rust
//! layouts and trait method names do not define portable envelope bytes.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{HookFailureCategory, IdentityKind, IdentityOrigin};
use gantry_core::timestamp::UtcTimestamp;

use crate::embedding::{EMBEDDING_OPERATIONS, EmbeddingOperation};
pub use crate::event::EventSink;
pub use crate::journal::JournalStorage;

/// A borrowed, executor-neutral future returned by a host integration.
pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An owned task future that may be submitted to an executor adapter.
///
/// Normal return carries only an opaque transport acknowledgement. The
/// executor wraps normal return, stop, panic, and executor failure in
/// [`OwnedTaskCompletion`] for observation through [`SubmittedTask`].
pub type OwnedTaskFuture = Pin<Box<dyn Future<Output = OwnedTaskResult> + Send + 'static>>;

/// Exact protocol version carried by a public embedding envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddingVersion {
    /// Protocol major version.
    pub major: u64,
    /// Protocol minor version.
    pub minor: u64,
}

impl EmbeddingVersion {
    /// Gantry's published embedding protocol version.
    pub const V1: Self = Self { major: 1, minor: 0 };
}

/// Exact validated bytes of one versioned embedding request.
///
/// The bytes are immutable so retries cannot silently change an accepted
/// request. Construction verifies the supported version and operation; schema
/// validation of required, optional, and unknown fields occurs before this
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRequest {
    version: EmbeddingVersion,
    operation: EmbeddingOperation,
    canonical_bytes: Arc<[u8]>,
}

impl HostRequest {
    /// Constructs a request after its bytes pass the selected published schema.
    pub fn new(
        version: EmbeddingVersion,
        operation: EmbeddingOperation,
        canonical_bytes: Arc<[u8]>,
    ) -> Result<Self, EnvelopeError> {
        validate_operation_version(version, operation)?;
        Ok(Self {
            version,
            operation,
            canonical_bytes,
        })
    }

    /// Returns the selected embedding version.
    #[must_use]
    pub const fn version(&self) -> EmbeddingVersion {
        self.version
    }

    /// Returns the exact operation discriminant.
    #[must_use]
    pub const fn operation(&self) -> EmbeddingOperation {
        self.operation
    }

    /// Returns the immutable validated envelope bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Exact validated bytes of one versioned embedding result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostResponse {
    version: EmbeddingVersion,
    operation: EmbeddingOperation,
    canonical_bytes: Arc<[u8]>,
}

impl HostResponse {
    /// Constructs a result after its bytes pass the operation's result schema.
    pub fn new(
        version: EmbeddingVersion,
        operation: EmbeddingOperation,
        canonical_bytes: Arc<[u8]>,
    ) -> Result<Self, EnvelopeError> {
        validate_operation_version(version, operation)?;
        Ok(Self {
            version,
            operation,
            canonical_bytes,
        })
    }

    /// Returns the selected embedding version.
    #[must_use]
    pub const fn version(&self) -> EmbeddingVersion {
        self.version
    }

    /// Returns the exact operation discriminant.
    #[must_use]
    pub const fn operation(&self) -> EmbeddingOperation {
        self.operation
    }

    /// Returns the immutable validated result bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Rejection while constructing a versioned host envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// The exact embedding version is not published by this build.
    UnsupportedVersion,
    /// The operation is absent from the selected embedding catalog.
    UnknownOperation,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "unsupported embedding protocol version",
            Self::UnknownOperation => "unknown embedding operation",
        })
    }
}

impl std::error::Error for EnvelopeError {}

/// Structured integration failure returned through a documented result union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostError {
    /// Stable protocol category or code.
    pub code: Arc<str>,
    /// Optional stable key for protected diagnostic bytes.
    pub protected_diagnostic: Option<Arc<str>>,
}

/// Origin retained when an executor-submitted Gantry future panics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedTaskPanicOrigin {
    /// The unwind originated while Gantry invoked integration-owned code.
    Integration,
    /// The unwind originated from a Gantry invariant violation.
    GantryInvariant,
}

/// Typed panic payload used to preserve an owned task's boundary origin.
///
/// Task drivers catch integration unwinds at their owning boundary and may
/// resume unwinding with this payload. An executor treats any other unwind as
/// a Gantry invariant panic and never exposes the original panic payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedTaskPanic {
    origin: OwnedTaskPanicOrigin,
    protected_diagnostic: Option<Arc<str>>,
}

impl OwnedTaskPanic {
    /// Constructs a classified panic with an optional protected diagnostic key.
    #[must_use]
    pub fn new(origin: OwnedTaskPanicOrigin, protected_diagnostic: Option<Arc<str>>) -> Self {
        Self {
            origin,
            protected_diagnostic,
        }
    }

    /// Returns the preserved panic boundary.
    #[must_use]
    pub const fn origin(&self) -> OwnedTaskPanicOrigin {
        self.origin
    }

    /// Returns the protected diagnostic reference, when one was recorded.
    #[must_use]
    pub fn protected_diagnostic(&self) -> Option<&Arc<str>> {
        self.protected_diagnostic.as_ref()
    }
}

/// Immutable physical completion observed for one submitted task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedTaskCompletion {
    /// The task future returned its opaque transport acknowledgement.
    Completed(OwnedTaskResult),
    /// The executor confirmed that the future will no longer be polled.
    Stopped,
    /// The future panicked with its preserved boundary origin.
    Panicked {
        /// Boundary that originated the panic.
        origin: OwnedTaskPanicOrigin,
        /// Optional stable key for protected diagnostic bytes.
        protected_diagnostic: Option<Arc<str>>,
    },
    /// The executor failed independently of a task panic.
    Failed(HostError),
}

/// Fixed result of one idempotent abort request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedTaskAbort {
    /// The executor confirmed that the future will no longer be polled.
    Stopped,
    /// Physical completion had already become immutable.
    AlreadySettled,
    /// The executor could not complete the abort request.
    Failed(HostError),
}

/// Monotonic Gantry cancellation observation supplied to integrations.
pub trait CancellationToken: Send + Sync {
    /// Returns whether cancellation has become effective.
    fn is_cancelled(&self) -> bool;
}

/// Monotonic cancellation signal owned by Gantry.
///
/// Clones observe the same one-way state transition. Registered waiters are
/// woken when cancellation first becomes effective.
#[derive(Clone, Debug, Default)]
pub struct CancellationSignal {
    state: Arc<CancellationState>,
}

#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl CancellationSignal {
    /// Makes cancellation effective and wakes every current waiter.
    ///
    /// Returns whether this call performed the first effective transition.
    pub fn cancel(&self) -> bool {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return false;
        }
        let waiters = self
            .state
            .waiters
            .lock()
            .map(|mut waiters| waiters.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        for waiter in waiters {
            waiter.wake();
        }
        true
    }

    /// Waits until cancellation becomes effective.
    pub fn cancelled(&self) -> HostFuture<'_, ()> {
        Box::pin(std::future::poll_fn(move |context| {
            if self.is_cancelled() {
                return Poll::Ready(());
            }
            let Ok(mut waiters) = self.state.waiters.lock() else {
                return Poll::Ready(());
            };
            if self.is_cancelled() {
                return Poll::Ready(());
            }
            if !waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                waiters.push(context.waker().clone());
            }
            Poll::Pending
        }))
    }
}

impl CancellationToken for CancellationSignal {
    fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }
}

/// Checked whole-microsecond duration accepted by executor services.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurationMicros(u64);

impl DurationMicros {
    /// Maximum portable configured duration.
    pub const MAXIMUM: u64 = i64::MAX as u64;

    /// Admits a nonnegative duration no greater than `2^63 - 1` microseconds.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAXIMUM {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the exact whole-microsecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Checked inclusive whole-microsecond sampling range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InclusiveJitterRange {
    minimum: u64,
    maximum: u64,
}

impl InclusiveJitterRange {
    /// Constructs one ordered portable range.
    #[must_use]
    pub const fn new(minimum: u64, maximum: u64) -> Option<Self> {
        if minimum <= maximum && maximum <= DurationMicros::MAXIMUM {
            Some(Self { minimum, maximum })
        } else {
            None
        }
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn minimum(self) -> u64 {
        self.minimum
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn maximum(self) -> u64 {
        self.maximum
    }
}

/// Thread-safe source of unbiased inclusive whole-microsecond samples.
pub trait JitterSource: Send + Sync {
    /// Samples uniformly from the complete inclusive range.
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError>;
}

/// Synchronous, thread-safe source of fresh 256-bit occurrence material.
pub trait IdentitySource: Send + Sync {
    /// Returns fresh material for the supplied typed identity kind.
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError>;
}

/// Executor-neutral source of current UTC event time.
pub trait UtcClock: Send + Sync {
    /// Returns one checked canonical UTC timestamp or an executor failure.
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>>;
}

/// Thread-safe registry and allocator for fresh protocol identities.
#[derive(Debug, Default)]
pub struct FreshIdentityAllocator {
    known: Mutex<std::collections::BTreeSet<ProtocolIdentity>>,
}

impl FreshIdentityAllocator {
    /// Records an identity already known by this interpreter or activity.
    pub fn reserve(&self, identity: ProtocolIdentity) -> Result<bool, IdentityAllocationError> {
        self.known
            .lock()
            .map_err(|_| IdentityAllocationError::RegistryUnavailable)
            .map(|mut known| known.insert(identity))
    }

    /// Allocates one fresh identity with the required three-call collision bound.
    pub fn allocate(
        &self,
        source: &dyn IdentitySource,
        kind: IdentityKind,
    ) -> Result<ProtocolIdentity, IdentityAllocationError> {
        if !matches!(
            kind.origin(),
            IdentityOrigin::Fresh | IdentityOrigin::FreshOrDerived
        ) {
            return Err(IdentityAllocationError::WrongOrigin);
        }

        for _ in 0..3 {
            let material = source
                .fresh_material(kind)
                .map_err(IdentityAllocationError::Source)?;
            let identity = ProtocolIdentity::from_fresh_material(kind, material)
                .map_err(|_| IdentityAllocationError::WrongOrigin)?;
            if self.reserve(identity)? {
                return Ok(identity);
            }
        }
        Err(IdentityAllocationError::CollisionLimit)
    }
}

/// Failure while allocating a fresh protocol identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityAllocationError {
    /// The requested identity kind is derived or storage-owned.
    WrongOrigin,
    /// The configured identity source returned a structured failure.
    Source(HostError),
    /// Three source calls all collided with known same-kind identities.
    CollisionLimit,
    /// The interpreter-local identity registry is unavailable.
    RegistryUnavailable,
}

impl IdentityAllocationError {
    /// Returns the exact portable package-operation failure category.
    #[must_use]
    pub const fn portable_code(&self) -> &'static str {
        "identity-generation-failure"
    }
}

impl std::fmt::Display for IdentityAllocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.portable_code())
    }
}

impl std::error::Error for IdentityAllocationError {}

/// Pre-execution mapping and logical-session resolution boundary.
///
/// The service is shared across admitted public activities and therefore is
/// `Send + Sync`. Its returned future is `Send` for the lifetime of its borrow.
pub trait IntegrationPreflight: Send + Sync {
    /// Performs one versioned preflight operation.
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>>;
}

/// Post-acceptance logical-session establishment boundary.
///
/// The service is independently owned from preflight, is safe to share across
/// task drivers, and returns a `Send` future for the lifetime of its borrow.
pub trait RuntimeSessionService: Send + Sync {
    /// Establishes or resolves one versioned logical-session descriptor.
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>>;
}

/// Opaque stable agent-mapping revision returned by integration preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMappingRevision(Arc<str>);

impl AgentMappingRevision {
    /// Validates one nonempty integration-owned revision identifier.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, MappingRevisionError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MappingRevisionError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the exact integration-owned revision identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque stable action-mapping revision returned by integration preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionMappingRevision(Arc<str>);

impl ActionMappingRevision {
    /// Validates one nonempty integration-owned revision identifier.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, MappingRevisionError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MappingRevisionError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the exact integration-owned revision identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete run-scoped mapping revisions fixed before execution acceptance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MappingRevisions {
    /// Present exactly when the package declares at least one agent.
    pub agent: Option<AgentMappingRevision>,
    /// Present exactly when the package declares at least one action.
    pub action: Option<ActionMappingRevision>,
}

/// Rejection of an invalid opaque mapping revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingRevisionError {
    /// Mapping revision identifiers are nonempty.
    Empty,
}

/// Lazily creates task-owned operation hooks.
pub trait HookFactory: Send + Sync {
    /// Creates one hook for a validated task context.
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>>;
}

/// Exact typed v1 outcome returned by one operation-hook invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookOutcomeV1 {
    /// The integration completed and returned uninterpreted raw output bytes.
    Completed(Arc<[u8]>),
    /// The integration declined with one bounded diagnostic reason.
    Declined(Arc<str>),
    /// The integration failed with one exact portable category and message.
    Failed {
        /// Exact closed hook-failure category.
        category: HookFailureCategory,
        /// Bounded integration diagnostic.
        message: Arc<str>,
    },
}

/// One serially invoked task-owned operation hook.
///
/// Hooks are `Send` but deliberately need not be `Sync`; Gantry invokes one
/// instance serially through a mutable borrow.
pub trait OperationHook: Send {
    /// Dispatches one immutable versioned operation request.
    fn dispatch<'a>(
        &'a mut self,
        request: HostRequest,
        cancellation: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>>;
}

/// Base executor-neutral runtime services used by every evaluator.
pub trait ExecutorAdapter: Send + Sync {
    /// Synchronously admits and submits one owned `Send + 'static` task future.
    ///
    /// Success transfers the future to the executor and returns its physical
    /// supervision capability. Failure consumes and safely destroys the future
    /// before returning a structured executor error.
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError>;

    /// Waits using a monotonic timer. Zero remains a timer wait, not a yield.
    fn sleep<'a>(&'a self, duration: DurationMicros) -> HostFuture<'a, Result<(), HostError>>;

    /// Performs one explicit scheduler yield.
    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>>;

    /// Samples uniformly from an inclusive whole-microsecond range.
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError>;
}

/// Rejects task submission for a narrow executor double that does not run tasks.
///
/// The supplied future is destroyed behind an unwind boundary before the
/// structured executor failure is returned. Evaluator adapters must provide a
/// real submission implementation instead of calling this helper.
pub fn reject_task_submission(task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
    let _ = catch_unwind(AssertUnwindSafe(|| drop(task)));
    Err(HostError {
        code: Arc::from("executor-failure"),
        protected_diagnostic: None,
    })
}

/// Completion-first result of racing work against cancellation and a deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeadlineOutcome<T> {
    /// Work completed no later than the deadline.
    Completed(T),
    /// Cancellation became effective while work remained pending.
    Cancelled,
    /// The monotonic deadline elapsed while work remained pending.
    TimedOut,
    /// The executor timer failed.
    Failed(HostError),
}

/// Races one borrowed future against cancellation and a monotonic timeout.
///
/// Polling always checks completion first, so completion wins when it and the
/// deadline are ready in the same poll. Returning drops the losing futures.
pub fn deadline_race<'a, T: Send + 'a>(
    executor: &'a dyn ExecutorAdapter,
    completion: HostFuture<'a, T>,
    timeout: DurationMicros,
    cancellation: Option<&'a CancellationSignal>,
) -> HostFuture<'a, DeadlineOutcome<T>> {
    let mut completion = completion;
    let mut timer = executor.sleep(timeout);
    let mut cancellation = cancellation.map(CancellationSignal::cancelled);
    Box::pin(std::future::poll_fn(move |context| {
        if let Poll::Ready(value) = completion.as_mut().poll(context) {
            return Poll::Ready(DeadlineOutcome::Completed(value));
        }
        if let Some(future) = cancellation.as_mut()
            && future.as_mut().poll(context).is_ready()
        {
            return Poll::Ready(DeadlineOutcome::Cancelled);
        }
        match timer.as_mut().poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(DeadlineOutcome::TimedOut),
            Poll::Ready(Err(error)) => Poll::Ready(DeadlineOutcome::Failed(error)),
            Poll::Pending => Poll::Pending,
        }
    }))
}

/// Executor-owned task handle with executor-neutral observation and abort operations.
///
/// Completion observation and an admitted abort are must-settle operations for
/// Gantry's supervising owner. Dropping one observation future does not stop the
/// submitted task or change its immutable physical completion.
pub trait SubmittedTask: Send + Sync {
    /// Observes the same immutable physical completion for every caller.
    fn completion<'a>(&'a self) -> HostFuture<'a, OwnedTaskCompletion>;

    /// Requests task abortion with one fixed result for concurrent callers.
    ///
    /// Calls begun after physical completion return `AlreadySettled`.
    fn abort<'a>(&'a self) -> HostFuture<'a, OwnedTaskAbort>;
}

/// Opaque acknowledgement returned by a normally completed owned task.
///
/// This value deliberately contains no source value, Gantry task status, or
/// durable settlement state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnedTaskResult {
    private: (),
}

impl OwnedTaskResult {
    /// Creates the opaque normal-completion acknowledgement.
    #[must_use]
    pub const fn new() -> Self {
        Self { private: () }
    }
}

fn validate_operation_version(
    version: EmbeddingVersion,
    operation: EmbeddingOperation,
) -> Result<(), EnvelopeError> {
    if version != EmbeddingVersion::V1 {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if !EMBEDDING_OPERATIONS
        .iter()
        .any(|definition| definition.operation == operation)
    {
        return Err(EnvelopeError::UnknownOperation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        CancellationToken, EmbeddingVersion, EnvelopeError, EventSink, ExecutorAdapter,
        HookFactory, HostRequest, IdentitySource, IntegrationPreflight, JitterSource,
        JournalStorage, OperationHook, OwnedTaskFuture, OwnedTaskResult, RuntimeSessionService,
        SubmittedTask, UtcClock,
    };
    use crate::embedding::EmbeddingOperation;

    fn assert_send<T: ?Sized + Send>() {}

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn envelope_construction_rejects_unpublished_versions() {
        let result = HostRequest::new(
            EmbeddingVersion { major: 1, minor: 1 },
            EmbeddingOperation::ValidatePackage,
            Arc::from(&b"{}"[..]),
        );
        assert_eq!(result, Err(EnvelopeError::UnsupportedVersion));
    }

    #[test]
    fn envelope_preserves_exact_validated_bytes() {
        let bytes: Arc<[u8]> = Arc::from(&b"{\"major\":1,\"minor\":0}"[..]);
        let request = HostRequest::new(
            EmbeddingVersion::V1,
            EmbeddingOperation::ValidatePackage,
            Arc::clone(&bytes),
        );
        assert!(request.is_ok());
        let request = request.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(request.canonical_bytes(), bytes.as_ref());
    }

    #[test]
    fn integration_traits_have_the_required_auto_traits_and_are_object_safe() {
        assert_send_sync::<dyn CancellationToken>();
        assert_send_sync::<dyn EventSink>();
        assert_send_sync::<dyn ExecutorAdapter>();
        assert_send_sync::<dyn HookFactory>();
        assert_send_sync::<dyn IdentitySource>();
        assert_send_sync::<dyn JitterSource>();
        assert_send_sync::<dyn JournalStorage>();
        assert_send_sync::<dyn SubmittedTask>();
        assert_send_sync::<dyn UtcClock>();
        assert_send::<dyn OperationHook>();

        assert_send_sync::<dyn IntegrationPreflight>();
        assert_send_sync::<dyn RuntimeSessionService>();

        fn accepts_owned_task(_: OwnedTaskFuture) {}
        accepts_owned_task(Box::pin(async { OwnedTaskResult::new() }));
    }
}
