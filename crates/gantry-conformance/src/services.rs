//! Deterministic fresh-identity and UTC-clock conformance doubles.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use gantry::host::contracts::{HostError, HostFuture, IdentitySource, UtcClock};
use gantry::portable::IdentityKind;
use gantry::timestamp::UtcTimestamp;

/// Scripted thread-safe identity source for adapter contract tests.
#[derive(Debug, Default)]
pub struct DeterministicIdentitySource {
    responses: Mutex<VecDeque<Result<[u8; 32], HostError>>>,
    calls: Mutex<Vec<IdentityKind>>,
}

impl DeterministicIdentitySource {
    /// Constructs a source from exact scripted responses.
    #[must_use]
    pub fn new(responses: impl IntoIterator<Item = Result<[u8; 32], HostError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Returns the identity kinds requested so far.
    #[must_use]
    pub fn calls(&self) -> Vec<IdentityKind> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl IdentitySource for DeterministicIdentitySource {
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError> {
        self.calls
            .lock()
            .map_err(|_| scripted_failure("identity-source-state"))?
            .push(kind);
        self.responses
            .lock()
            .map_err(|_| scripted_failure("identity-source-state"))?
            .pop_front()
            .unwrap_or_else(|| Err(scripted_failure("identity-source-exhausted")))
    }
}

/// Scripted executor-neutral UTC clock for adapter contract tests.
#[derive(Debug, Default)]
pub struct DeterministicUtcClock {
    responses: Mutex<VecDeque<Result<UtcTimestamp, HostError>>>,
}

impl DeterministicUtcClock {
    /// Constructs a clock from exact scripted responses.
    #[must_use]
    pub fn new(responses: impl IntoIterator<Item = Result<UtcTimestamp, HostError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

impl UtcClock for DeterministicUtcClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async move {
            self.responses
                .lock()
                .map_err(|_| scripted_failure("utc-clock-state"))?
                .pop_front()
                .unwrap_or_else(|| Err(scripted_failure("utc-clock-exhausted")))
        })
    }
}

fn scripted_failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}
