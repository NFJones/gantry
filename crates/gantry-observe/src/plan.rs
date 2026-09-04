//! Immutable event sink plans.

use std::fmt;
use std::sync::Arc;

use gantry_host::event::{EventSink, SinkDeliveryPolicy, SinkId};

/// One configured sink and the policy captured for new event occurrences.
#[derive(Clone)]
pub struct SinkRegistration {
    id: SinkId,
    policy: SinkDeliveryPolicy,
    sink: Arc<dyn EventSink>,
}

impl SinkRegistration {
    /// Constructs one sink registration.
    #[must_use]
    pub fn new(id: SinkId, policy: SinkDeliveryPolicy, sink: Arc<dyn EventSink>) -> Self {
        Self { id, policy, sink }
    }

    /// Returns the stable sink identity.
    #[must_use]
    pub fn id(&self) -> &SinkId {
        &self.id
    }

    /// Returns the complete frozen policy.
    #[must_use]
    pub const fn policy(&self) -> &SinkDeliveryPolicy {
        &self.policy
    }

    /// Returns the configured sink adapter.
    #[must_use]
    pub fn sink(&self) -> &dyn EventSink {
        self.sink.as_ref()
    }
}

/// Canonically ordered immutable sink obligations for one event occurrence.
#[derive(Clone, Default)]
pub struct SinkPlan(Arc<[SinkRegistration]>);

impl SinkPlan {
    /// Sorts registrations by unsigned UTF-8 sink ID and rejects duplicates.
    pub fn new(mut registrations: Vec<SinkRegistration>) -> Result<Self, SinkPlanError> {
        registrations.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        if registrations
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        {
            return Err(SinkPlanError::DuplicateSinkId);
        }
        Ok(Self(registrations.into()))
    }

    /// Returns captured registrations in canonical sink-ID order.
    #[must_use]
    pub fn registrations(&self) -> &[SinkRegistration] {
        &self.0
    }

    /// Finds the currently configured adapter for one stable sink identity.
    #[must_use]
    pub fn registration(&self, sink_id: &SinkId) -> Option<&SinkRegistration> {
        self.0
            .binary_search_by(|registration| registration.id().as_str().cmp(sink_id.as_str()))
            .ok()
            .and_then(|index| self.0.get(index))
    }

    /// Returns a frozen plan without one exhausted sink obligation.
    ///
    /// This is used only for consequence events created while terminating the
    /// affected activity. Every other registration retains its captured policy
    /// and canonical sink-ID order.
    #[must_use]
    pub fn without_sink(&self, sink_id: &SinkId) -> Self {
        Self(
            self.0
                .iter()
                .filter(|registration| registration.id() != sink_id)
                .cloned()
                .collect(),
        )
    }
}

/// Invalid immutable sink plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkPlanError {
    /// Two configured adapters used the same stable sink ID.
    DuplicateSinkId,
}

impl fmt::Display for SinkPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("event sink plan contains a duplicate sink identity")
    }
}

impl std::error::Error for SinkPlanError {}
