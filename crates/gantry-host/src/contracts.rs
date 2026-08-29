//! Executor-neutral Rust boundaries for Gantry integrations.
//!
//! These interfaces own transport and asynchronous ownership shape only.
//! Canonical JSON Schemas under `protocol/` remain the wire authority; Rust
//! layouts and trait method names do not define portable envelope bytes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use gantry_core::portable::IdentityKind;

use crate::embedding::{EMBEDDING_OPERATIONS, EmbeddingOperation};

/// A borrowed, executor-neutral future returned by a host integration.
pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An owned task future that may be submitted to an executor adapter.
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

/// Monotonic Gantry cancellation observation supplied to integrations.
pub trait CancellationToken: Send + Sync {
    /// Returns whether cancellation has become effective.
    fn is_cancelled(&self) -> bool;
}

/// Synchronous, thread-safe source of fresh 256-bit occurrence material.
pub trait IdentitySource: Send + Sync {
    /// Returns fresh material for the supplied typed identity kind.
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError>;
}

/// Pre-execution mapping and logical-session resolution boundary.
///
/// The specification does not impose `Send + Sync` on a separately owned
/// preflight object. Its returned future is nevertheless `Send` for the
/// lifetime of its borrow.
pub trait IntegrationPreflight {
    /// Performs one versioned preflight operation.
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>>;
}

/// Lazily creates task-owned operation hooks.
pub trait HookFactory: Send + Sync {
    /// Creates one hook for a validated task context.
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>>;
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
    ) -> HostFuture<'a, Result<HostResponse, HostError>>;
}

/// Executor-neutral runtime services used by Gantry.
pub trait ExecutorAdapter: Send + Sync {
    /// Performs sleep, yield, deadline, time, jitter, join, or abort service.
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>>;

    /// Submits an owned `Send + 'static` task future.
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError>;
}

/// Executor-owned task handle with executor-neutral join and abort operations.
pub trait SubmittedTask: Send + Sync {
    /// Waits for the submitted task to settle.
    fn join<'a>(&'a self) -> HostFuture<'a, Result<OwnedTaskResult, HostError>>;

    /// Requests idempotent task abortion.
    fn abort<'a>(&'a self) -> HostFuture<'a, Result<HostResponse, HostError>>;
}

/// Settlement returned by an owned executor task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedTaskResult {
    /// Exact validated settlement bytes.
    pub canonical_bytes: Arc<[u8]>,
}

/// Backend-neutral durable journal operation boundary.
pub trait JournalStorage: Send + Sync {
    /// Performs one ownership, read, commit, payload, or release operation.
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>>;
}

/// Capability-filtered event delivery boundary.
pub trait EventSink: Send + Sync {
    /// Delivers one immutable event occurrence and protected projection.
    fn deliver<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>>;
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
        HookFactory, HostRequest, IdentitySource, IntegrationPreflight, JournalStorage,
        OperationHook, SubmittedTask,
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
        assert_send_sync::<dyn JournalStorage>();
        assert_send_sync::<dyn SubmittedTask>();
        assert_send::<dyn OperationHook>();

        fn accepts_preflight(_: Option<&dyn IntegrationPreflight>) {}
        accepts_preflight(None);
    }
}
