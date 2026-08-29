//! Activity-scoped required and best-effort delivery barriers.

use gantry_core::identity::ProtocolIdentity;
use gantry_host::event::SinkId;

use crate::delivery::SinkSettlement;

/// Required-sink state through the activity's current final event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityBarrier {
    /// Every required obligation settled successfully.
    Delivered,
    /// A required sink exhausted without changing another activity.
    RequiredExhausted {
        /// Stable identity of the exhausted sink.
        sink_id: SinkId,
        /// Event whose required obligation exhausted.
        event_id: ProtocolIdentity,
        /// Final physical delivery-attempt identity.
        attempt_id: ProtocolIdentity,
    },
}

/// Complete nondurable delivery result for one event in one activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityDeliveryResult {
    /// Required-sink barrier state.
    pub barrier: ActivityBarrier,
    /// Required and best-effort settlements in canonical sink-ID order.
    pub settlements: Vec<SinkSettlement>,
}
