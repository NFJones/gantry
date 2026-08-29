//! Overflow-safe event-delivery backoff selection.

use gantry_core::portable::JitterMode;
use gantry_host::contracts::HostError;
use gantry_host::event::{EventDeliveryRuntime, EventRetryPolicy};

/// Returns the saturating delay ceiling for a one-based retry number.
#[must_use]
pub fn delay_ceiling(policy: &EventRetryPolicy, retry_number: u64) -> Option<u64> {
    let doublings = retry_number.checked_sub(1)?;
    if policy.initial_delay_us == 0 {
        return Some(0);
    }
    if doublings >= 63 {
        return Some(policy.cap_us);
    }
    Some(
        policy
            .initial_delay_us
            .saturating_mul(1_u64 << doublings)
            .min(policy.cap_us),
    )
}

/// Selects one retry delay under the policy's exact jitter mode.
pub fn select_delay(
    policy: &EventRetryPolicy,
    retry_number: u64,
    runtime: &dyn EventDeliveryRuntime,
) -> Result<u64, RetrySelectionError> {
    let ceiling = delay_ceiling(policy, retry_number).ok_or(RetrySelectionError::ZeroRetry)?;
    match policy.jitter {
        JitterMode::None => Ok(ceiling),
        JitterMode::Full => {
            let selected = runtime
                .sample_full_jitter(ceiling)
                .map_err(RetrySelectionError::Runtime)?;
            if selected > ceiling {
                return Err(RetrySelectionError::OutOfRangeJitter);
            }
            Ok(selected)
        }
    }
}

/// Invalid or failed retry-delay selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrySelectionError {
    /// Retry numbers are one-based at delay selection.
    ZeroRetry,
    /// The runtime jitter service failed.
    Runtime(HostError),
    /// The runtime returned a sample above the inclusive ceiling.
    OutOfRangeJitter,
}
