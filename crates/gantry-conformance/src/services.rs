//! Deterministic fresh-identity and UTC-clock conformance doubles.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use gantry::host::contracts::{
    DurationMicros, ExecutorAdapter, HostError, HostFuture, IdentitySource, InclusiveJitterRange,
    UtcClock,
};
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

/// Scripted executor double with observable sleep and yield calls.
#[derive(Debug, Default)]
pub struct DeterministicExecutor {
    sleep_responses: Mutex<VecDeque<Result<(), HostError>>>,
    jitter_responses: Mutex<VecDeque<Result<u64, HostError>>>,
    sleeps: Mutex<Vec<DurationMicros>>,
    yields: Mutex<usize>,
}

impl DeterministicExecutor {
    /// Constructs an executor from exact sleep and jitter responses.
    #[must_use]
    pub fn new(
        sleep_responses: impl IntoIterator<Item = Result<(), HostError>>,
        jitter_responses: impl IntoIterator<Item = Result<u64, HostError>>,
    ) -> Self {
        Self {
            sleep_responses: Mutex::new(sleep_responses.into_iter().collect()),
            jitter_responses: Mutex::new(jitter_responses.into_iter().collect()),
            sleeps: Mutex::new(Vec::new()),
            yields: Mutex::new(0),
        }
    }

    /// Returns requested sleep durations in call order.
    #[must_use]
    pub fn sleeps(&self) -> Vec<DurationMicros> {
        self.sleeps
            .lock()
            .map(|sleeps| sleeps.clone())
            .unwrap_or_default()
    }

    /// Returns the number of explicit scheduler yields requested.
    #[must_use]
    pub fn yields(&self) -> usize {
        self.yields.lock().map_or(0, |count| *count)
    }
}

impl ExecutorAdapter for DeterministicExecutor {
    fn spawn(
        &self,
        task: gantry::host::contracts::OwnedTaskFuture,
    ) -> Result<Box<dyn gantry::host::contracts::SubmittedTask>, HostError> {
        gantry::host::contracts::reject_task_submission(task)
    }

    fn sleep<'a>(&'a self, duration: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async move {
            self.sleeps
                .lock()
                .map_err(|_| scripted_failure("executor-state"))?
                .push(duration);
            self.sleep_responses
                .lock()
                .map_err(|_| scripted_failure("executor-state"))?
                .pop_front()
                .unwrap_or_else(|| Err(scripted_failure("executor-sleep-exhausted")))
        })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async move {
            let mut count = self
                .yields
                .lock()
                .map_err(|_| scripted_failure("executor-state"))?;
            *count = count.saturating_add(1);
            Ok(())
        })
    }

    fn sample_inclusive(&self, _: InclusiveJitterRange) -> Result<u64, HostError> {
        self.jitter_responses
            .lock()
            .map_err(|_| scripted_failure("executor-state"))?
            .pop_front()
            .unwrap_or_else(|| Err(scripted_failure("executor-jitter-exhausted")))
    }
}

fn scripted_failure(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}
