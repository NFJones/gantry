//! Shared nondurable event completion and delivery for Gantry activities.
//!
//! This crate owns event occurrence completion, immutable sink plans,
//! protected-data projection, retry policy, and activity barriers. It does not
//! admit activities, interpret source, apply execution-wide consequences, or
//! persist delivery evidence.

pub mod barrier;
pub mod delivery;
pub mod draft;
pub mod plan;
pub mod projection;
pub mod retry;

pub use barrier::{ActivityBarrier, ActivityDeliveryResult};
pub use delivery::{
    AttemptRecord, DeliveryError, DeliveryKernel, SinkSettlement, SinkSettlementStatus,
};
pub use draft::{EventCompleter, EventCompletionError};
pub use plan::{SinkPlan, SinkPlanError, SinkRegistration};
pub use projection::{ProjectionError, project_payloads};

#[cfg(test)]
mod tests;
