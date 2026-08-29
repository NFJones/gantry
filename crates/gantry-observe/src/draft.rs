//! Completion of semantic event drafts with occurrence metadata.

use std::fmt;

use gantry_core::event::{EventContractError, EventDraft, EventEnvelope};
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, IdentityOrigin};
use gantry_host::contracts::{
    FreshIdentityAllocator, HostError, IdentityAllocationError, IdentitySource, UtcClock,
};

/// Completes typed event drafts without allocating the caller-owned activity.
pub struct EventCompleter<'a> {
    allocator: &'a FreshIdentityAllocator,
    identity_source: &'a dyn IdentitySource,
    clock: &'a dyn UtcClock,
}

impl<'a> EventCompleter<'a> {
    /// Constructs a completer from shared fresh-identity and UTC services.
    #[must_use]
    pub const fn new(
        allocator: &'a FreshIdentityAllocator,
        identity_source: &'a dyn IdentitySource,
        clock: &'a dyn UtcClock,
    ) -> Self {
        Self {
            allocator,
            identity_source,
            clock,
        }
    }

    /// Allocates one event ID, obtains its creation timestamp, and completes a draft.
    pub async fn complete(
        &self,
        activity_id: ProtocolIdentity,
        draft: EventDraft,
    ) -> Result<EventEnvelope, EventCompletionError> {
        if activity_id.kind() != IdentityKind::Activity {
            return Err(EventCompletionError::InvalidActivityIdentity);
        }
        debug_assert_eq!(IdentityKind::Event.origin(), IdentityOrigin::Fresh);
        let event_id = self
            .allocator
            .allocate(self.identity_source, IdentityKind::Event)
            .map_err(EventCompletionError::Identity)?;
        let timestamp = self
            .clock
            .utc_now()
            .await
            .map_err(EventCompletionError::Clock)?;
        EventEnvelope::complete(event_id, activity_id, timestamp, draft)
            .map_err(EventCompletionError::Contract)
    }
}

/// Failure while completing one event occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventCompletionError {
    /// The caller supplied an identity other than an activity identity.
    InvalidActivityIdentity,
    /// Fresh event identity allocation failed.
    Identity(IdentityAllocationError),
    /// The UTC service failed before an event could be created.
    Clock(HostError),
    /// The completed fields violated the portable event contract.
    Contract(EventContractError),
}

impl fmt::Display for EventCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidActivityIdentity => "invalid activity identity",
            Self::Identity(_) => "event identity generation failed",
            Self::Clock(_) => "event timestamp generation failed",
            Self::Contract(_) => "completed event violated its portable contract",
        })
    }
}

impl std::error::Error for EventCompletionError {}
