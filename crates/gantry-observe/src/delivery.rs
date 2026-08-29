//! Shared nondurable event delivery and retry driving.

use std::fmt;
use std::sync::Arc;

use gantry_core::event::EventEnvelope;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{DeliveryOutcome, IdentityKind, SinkClass};
use gantry_host::contracts::{
    FreshIdentityAllocator, HostError, IdentityAllocationError, IdentitySource,
};
use gantry_host::event::{EventDeliveryRequest, EventDeliveryRuntime, ProtectedPayload, SinkId};

use crate::barrier::{ActivityBarrier, ActivityDeliveryResult};
use crate::plan::{SinkPlan, SinkRegistration};
use crate::projection::{ProjectionError, project_payloads};
use crate::retry::{RetrySelectionError, select_delay};

/// Terminal state of one sink obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkSettlementStatus {
    /// Delivery succeeded.
    Success,
    /// Delivery exhausted its finite policy.
    Exhausted,
}

/// One physical attempt and its nondurable policy evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecord {
    /// Distinct physical delivery-attempt identity.
    pub attempt_id: ProtocolIdentity,
    /// Zero-based retry number.
    pub retry_number: u64,
    /// Effective outcome after applying the remaining retry budget.
    pub outcome: DeliveryOutcome,
    /// Selected delay before the next attempt, when any.
    pub selected_delay_us: Option<u64>,
    /// Stable adapter/runtime error code for a terminal failed attempt.
    pub failure_code: Option<Arc<str>>,
}

/// Terminal settlement of one captured sink obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SinkSettlement {
    /// Stable sink identity.
    pub sink_id: SinkId,
    /// Required or best-effort class frozen in the plan.
    pub class: SinkClass,
    /// Success or finite exhaustion.
    pub status: SinkSettlementStatus,
    /// Physical attempts in retry-number order.
    pub attempts: Vec<AttemptRecord>,
}

/// Shared nondurable delivery driver.
pub struct DeliveryKernel<'a> {
    allocator: &'a FreshIdentityAllocator,
    identity_source: &'a dyn IdentitySource,
    runtime: &'a dyn EventDeliveryRuntime,
}

impl<'a> DeliveryKernel<'a> {
    /// Constructs a kernel from occurrence identity and executor-neutral services.
    #[must_use]
    pub const fn new(
        allocator: &'a FreshIdentityAllocator,
        identity_source: &'a dyn IdentitySource,
        runtime: &'a dyn EventDeliveryRuntime,
    ) -> Self {
        Self {
            allocator,
            identity_source,
            runtime,
        }
    }

    /// Delivers one immutable event through its captured activity sink plan.
    pub async fn deliver(
        &self,
        event: EventEnvelope,
        payloads: &[ProtectedPayload],
        plan: &SinkPlan,
    ) -> Result<ActivityDeliveryResult, DeliveryError> {
        let mut settlements = Vec::with_capacity(plan.registrations().len());
        let mut first_required_failure = None;
        for registration in plan.registrations() {
            let settlement = self.deliver_to_sink(&event, payloads, registration).await?;
            if first_required_failure.is_none()
                && settlement.class == SinkClass::Required
                && settlement.status == SinkSettlementStatus::Exhausted
            {
                let attempt_id = settlement
                    .attempts
                    .last()
                    .map(|attempt| attempt.attempt_id)
                    .ok_or(DeliveryError::MissingAttempt)?;
                first_required_failure = Some((settlement.sink_id.clone(), attempt_id));
            }
            settlements.push(settlement);
        }
        let barrier =
            first_required_failure.map_or(ActivityBarrier::Delivered, |(sink_id, attempt_id)| {
                ActivityBarrier::RequiredExhausted {
                    sink_id,
                    event_id: event.event_id(),
                    attempt_id,
                }
            });
        Ok(ActivityDeliveryResult {
            barrier,
            settlements,
        })
    }

    async fn deliver_to_sink(
        &self,
        event: &EventEnvelope,
        payloads: &[ProtectedPayload],
        registration: &SinkRegistration,
    ) -> Result<SinkSettlement, DeliveryError> {
        let protected_payloads = project_payloads(event, payloads, registration.policy())
            .map_err(DeliveryError::Projection)?;
        let mut retry_number = 0_u64;
        let mut attempts = Vec::new();
        loop {
            let attempt_id = self
                .allocator
                .allocate(self.identity_source, IdentityKind::DeliveryAttempt)
                .map_err(DeliveryError::Identity)?;
            let request = EventDeliveryRequest {
                event: event.clone(),
                protected_payloads: protected_payloads.clone(),
                attempt_id,
                retry_number,
            };
            let outcome = self
                .runtime
                .deliver_with_timeout(
                    registration.sink(),
                    request,
                    registration.policy().attempt_timeout_us,
                )
                .await;
            let (outcome, failure_code) = match outcome {
                Ok(outcome) => (outcome, None),
                Err(error) => (DeliveryOutcome::Terminal, Some(error.code)),
            };
            if outcome == DeliveryOutcome::Success {
                attempts.push(AttemptRecord {
                    attempt_id,
                    retry_number,
                    outcome,
                    selected_delay_us: None,
                    failure_code,
                });
                return Ok(SinkSettlement {
                    sink_id: registration.id().clone(),
                    class: registration.policy().class,
                    status: SinkSettlementStatus::Success,
                    attempts,
                });
            }
            if outcome == DeliveryOutcome::Retriable
                && retry_number < registration.policy().retry.retry_limit
            {
                let next_retry = retry_number
                    .checked_add(1)
                    .ok_or(DeliveryError::RetryOverflow)?;
                let delay = select_delay(&registration.policy().retry, next_retry, self.runtime)
                    .map_err(DeliveryError::Retry)?;
                attempts.push(AttemptRecord {
                    attempt_id,
                    retry_number,
                    outcome,
                    selected_delay_us: Some(delay),
                    failure_code,
                });
                self.runtime
                    .sleep(delay)
                    .await
                    .map_err(DeliveryError::Runtime)?;
                retry_number = next_retry;
                continue;
            }
            attempts.push(AttemptRecord {
                attempt_id,
                retry_number,
                outcome: DeliveryOutcome::Terminal,
                selected_delay_us: None,
                failure_code,
            });
            return Ok(SinkSettlement {
                sink_id: registration.id().clone(),
                class: registration.policy().class,
                status: SinkSettlementStatus::Exhausted,
                attempts,
            });
        }
    }
}

/// Failure before a nondurable event's finite sink obligations can settle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    /// Protected bytes did not match the event's stable references.
    Projection(ProjectionError),
    /// Fresh delivery-attempt identity allocation failed.
    Identity(IdentityAllocationError),
    /// Retry-delay selection failed.
    Retry(RetrySelectionError),
    /// Executor-neutral sleep or other delivery runtime service failed.
    Runtime(HostError),
    /// A retry counter overflowed.
    RetryOverflow,
    /// An exhausted settlement unexpectedly contained no attempt.
    MissingAttempt,
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Projection(_) => "event protected-payload projection failed",
            Self::Identity(_) => "delivery-attempt identity generation failed",
            Self::Retry(_) => "event retry-delay selection failed",
            Self::Runtime(_) => "event delivery runtime failed",
            Self::RetryOverflow => "event delivery retry counter overflowed",
            Self::MissingAttempt => "event sink exhaustion has no physical attempt",
        })
    }
}

impl std::error::Error for DeliveryError {}
