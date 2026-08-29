//! Executor-neutral event sink and protected-delivery contracts.

use std::fmt;
use std::sync::Arc;

use gantry_core::event::{EventEnvelope, ProtectedReference};
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{DeliveryOutcome, DeliveryProjection, JitterMode, SinkClass};

use crate::contracts::{HostError, HostFuture};

const MAXIMUM_PORTABLE_INTEGER: u64 = i64::MAX as u64;

/// Stable integration-owned event sink identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SinkId(Arc<str>);

impl SinkId {
    /// Constructs a nonempty UTF-8 sink identity.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, EventPolicyError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EventPolicyError::EmptySinkId);
        }
        Ok(Self(value))
    }

    /// Returns the exact configured identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resolved protected-data permissions frozen for one sink obligation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RedactionCapabilities {
    /// Permit protected operation request content.
    pub operation_request_content: bool,
    /// Permit protected normalized operation result content.
    pub operation_result_content: bool,
    /// Permit protected integration diagnostics.
    pub integration_diagnostics: bool,
    /// Permit protected source snippets.
    pub source_snippets: bool,
}

/// Finite event-delivery retry policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRetryPolicy {
    /// Stable audit identity for the selected retry policy.
    pub revision: Arc<str>,
    /// Known retriable failures permitted after the initial attempt.
    pub retry_limit: u64,
    /// Initial retry delay in whole microseconds.
    pub initial_delay_us: u64,
    /// Saturating retry-delay cap in whole microseconds.
    pub cap_us: u64,
    /// Exact jitter mode.
    pub jitter: JitterMode,
}

impl EventRetryPolicy {
    /// Validates one finite portable retry policy.
    pub fn new(
        revision: impl Into<Arc<str>>,
        retry_limit: u64,
        initial_delay_us: u64,
        cap_us: u64,
        jitter: JitterMode,
    ) -> Result<Self, EventPolicyError> {
        let revision = revision.into();
        if revision.is_empty() {
            return Err(EventPolicyError::EmptyRetryRevision);
        }
        if [retry_limit, initial_delay_us, cap_us]
            .into_iter()
            .any(|value| value > MAXIMUM_PORTABLE_INTEGER)
        {
            return Err(EventPolicyError::OutOfRange);
        }
        if cap_us < initial_delay_us {
            return Err(EventPolicyError::CapBeforeInitialDelay);
        }
        Ok(Self {
            revision,
            retry_limit,
            initial_delay_us,
            cap_us,
            jitter,
        })
    }
}

/// Complete immutable policy captured for one sink and event occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SinkDeliveryPolicy {
    /// Required or best-effort delivery class.
    pub class: SinkClass,
    /// Separate permission for raw integration output.
    pub raw_output: bool,
    /// Stable audit identity of the selected redaction policy.
    pub redaction_policy_id: Arc<str>,
    /// Resolved semantic protected-data permissions.
    pub capabilities: RedactionCapabilities,
    /// Finite retry policy.
    pub retry: EventRetryPolicy,
    /// Positive attempt timeout in whole microseconds.
    pub attempt_timeout_us: u64,
}

impl SinkDeliveryPolicy {
    /// Validates a complete sink delivery policy.
    pub fn new(
        class: SinkClass,
        raw_output: bool,
        redaction_policy_id: impl Into<Arc<str>>,
        capabilities: RedactionCapabilities,
        retry: EventRetryPolicy,
        attempt_timeout_us: u64,
    ) -> Result<Self, EventPolicyError> {
        let redaction_policy_id = redaction_policy_id.into();
        if redaction_policy_id.is_empty() {
            return Err(EventPolicyError::EmptyRedactionPolicy);
        }
        if attempt_timeout_us == 0 || attempt_timeout_us > MAXIMUM_PORTABLE_INTEGER {
            return Err(EventPolicyError::InvalidAttemptTimeout);
        }
        Ok(Self {
            class,
            raw_output,
            redaction_policy_id,
            capabilities,
            retry,
            attempt_timeout_us,
        })
    }
}

/// Exact protected bytes associated with one stable event reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedPayload {
    /// Reference and permission class from the event envelope.
    pub reference: ProtectedReference,
    /// Exact protected bytes, supplied outside the ordinary event envelope.
    pub bytes: Arc<[u8]>,
}

/// One sink-specific protected-reference projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedPayload {
    /// Stable reference from the sink-neutral event envelope.
    pub reference: ProtectedReference,
    /// Available, redacted, or not-applicable state.
    pub projection: DeliveryProjection,
    /// Exact bytes only when the projection is available.
    pub bytes: Option<Arc<[u8]>>,
}

/// Capability-filtered protected payloads delivered alongside one event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedPayloadBundle(Arc<[ProjectedPayload]>);

impl ProtectedPayloadBundle {
    /// Constructs a bundle after projection against a frozen sink policy.
    #[must_use]
    pub fn new(payloads: impl Into<Arc<[ProjectedPayload]>>) -> Self {
        Self(payloads.into())
    }

    /// Returns projected payloads in event-reference order.
    #[must_use]
    pub fn payloads(&self) -> &[ProjectedPayload] {
        &self.0
    }
}

/// One physical event-delivery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDeliveryRequest {
    /// Immutable standard event occurrence.
    pub event: EventEnvelope,
    /// Capability-filtered protected payload bundle.
    pub protected_payloads: ProtectedPayloadBundle,
    /// Distinct identity for this physical attempt.
    pub attempt_id: ProtocolIdentity,
    /// Zero-based retry number; zero is the initial attempt.
    pub retry_number: u64,
}

/// Capability-filtered event delivery boundary.
pub trait EventSink: Send + Sync {
    /// Delivers one immutable event occurrence and protected projection.
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>>;
}

/// Executor-neutral timeout, sleep, and jitter services for event delivery.
pub trait EventDeliveryRuntime: Send + Sync {
    /// Runs one sink attempt with a finite positive timeout and drops the loser.
    fn deliver_with_timeout<'a>(
        &'a self,
        sink: &'a dyn EventSink,
        request: EventDeliveryRequest,
        timeout_us: u64,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>>;

    /// Waits one selected whole-microsecond retry delay.
    fn sleep<'a>(&'a self, delay_us: u64) -> HostFuture<'a, Result<(), HostError>>;

    /// Samples uniformly from the inclusive range zero through `ceiling_us`.
    fn sample_full_jitter(&self, ceiling_us: u64) -> Result<u64, HostError>;
}

/// Invalid event sink policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPolicyError {
    /// The sink identity was empty.
    EmptySinkId,
    /// The retry policy revision was empty.
    EmptyRetryRevision,
    /// The redaction policy identity was empty.
    EmptyRedactionPolicy,
    /// A numeric field exceeded the portable signed-64-bit maximum.
    OutOfRange,
    /// The retry cap preceded the initial delay.
    CapBeforeInitialDelay,
    /// The attempt timeout was zero or exceeded the portable maximum.
    InvalidAttemptTimeout,
}

impl fmt::Display for EventPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptySinkId => "event sink identity is empty",
            Self::EmptyRetryRevision => "event retry policy revision is empty",
            Self::EmptyRedactionPolicy => "event redaction policy identity is empty",
            Self::OutOfRange => "event policy value exceeds the portable maximum",
            Self::CapBeforeInitialDelay => "event retry cap precedes its initial delay",
            Self::InvalidAttemptTimeout => "event delivery attempt timeout is invalid",
        })
    }
}

impl std::error::Error for EventPolicyError {}
