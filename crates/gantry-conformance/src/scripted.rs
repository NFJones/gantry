//! Harness-only scripted integration for public embedding-contract tests.
//!
//! The adapter consumes an explicit sequence of versioned preflight responses,
//! hook creations, and hook outcomes. It records only public envelope bytes and
//! cancellation observations, so conformance cases cannot depend on private
//! interpreter state.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use gantry::host::contracts::{
    CancellationToken, EmbeddingVersion, HookFactory, HookOutcomeV1, HostError, HostFuture,
    HostRequest, HostResponse, IntegrationPreflight, OperationHook,
};
use gantry::host::embedding::EmbeddingOperation;

/// One recorded call through a public embedding boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedCall {
    /// Exact operation discriminant from the request envelope.
    pub operation: EmbeddingOperation,
    /// Immutable canonical request bytes.
    pub canonical_bytes: Arc<[u8]>,
    /// Cancellation state observed by a hook dispatch, when applicable.
    pub cancellation_observed: Option<bool>,
}

/// One expected preflight call and its scripted result bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedPreflight {
    operation: EmbeddingOperation,
    result: Result<Arc<[u8]>, HostError>,
}

impl ScriptedPreflight {
    /// Scripts one successful response for the exact preflight operation.
    #[must_use]
    pub fn success(operation: EmbeddingOperation, canonical_bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            operation,
            result: Ok(canonical_bytes.into()),
        }
    }

    /// Scripts one structured integration failure for the exact operation.
    #[must_use]
    pub fn failure(operation: EmbeddingOperation, error: HostError) -> Self {
        Self {
            operation,
            result: Err(error),
        }
    }
}

/// One task-hook creation and its serial dispatch outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedHook {
    outcomes: Result<VecDeque<Result<HookOutcomeV1, HostError>>, HostError>,
}

impl ScriptedHook {
    /// Scripts one successfully created hook with ordered dispatch outcomes.
    #[must_use]
    pub fn created(outcomes: impl IntoIterator<Item = Result<HookOutcomeV1, HostError>>) -> Self {
        Self {
            outcomes: Ok(outcomes.into_iter().collect()),
        }
    }

    /// Scripts one structured hook-creation failure.
    #[must_use]
    pub fn creation_failure(error: HostError) -> Self {
        Self {
            outcomes: Err(error),
        }
    }
}

/// Deterministic harness integration over public preflight and hook traits.
#[derive(Debug, Default)]
pub struct ScriptedIntegration {
    preflight: Mutex<VecDeque<ScriptedPreflight>>,
    hooks: Mutex<VecDeque<ScriptedHook>>,
    calls: Arc<Mutex<Vec<ScriptedCall>>>,
}

impl ScriptedIntegration {
    /// Constructs an integration from exact preflight and task-hook scripts.
    #[must_use]
    pub fn new(
        preflight: impl IntoIterator<Item = ScriptedPreflight>,
        hooks: impl IntoIterator<Item = ScriptedHook>,
    ) -> Self {
        Self {
            preflight: Mutex::new(preflight.into_iter().collect()),
            hooks: Mutex::new(hooks.into_iter().collect()),
            calls: Arc::default(),
        }
    }

    /// Returns all calls in observed boundary order.
    #[must_use]
    pub fn calls(&self) -> Vec<ScriptedCall> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }

    fn record(&self, request: &HostRequest, cancellation_observed: Option<bool>) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(ScriptedCall {
                operation: request.operation(),
                canonical_bytes: Arc::from(request.canonical_bytes()),
                cancellation_observed,
            });
        }
    }
}

impl IntegrationPreflight for ScriptedIntegration {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        self.record(&request, None);
        let step = self
            .preflight
            .lock()
            .map_err(|_| scripted_error("scripted-preflight-state"))
            .and_then(|mut steps| {
                steps
                    .pop_front()
                    .ok_or_else(|| scripted_error("scripted-preflight-exhausted"))
            });
        Box::pin(async move {
            let step = step?;
            if step.operation != request.operation() {
                return Err(scripted_error("scripted-operation-mismatch"));
            }
            let bytes = step.result?;
            HostResponse::new(EmbeddingVersion::V1, request.operation(), bytes)
                .map_err(|_| scripted_error("scripted-response-envelope"))
        })
    }
}

impl HookFactory for ScriptedIntegration {
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        self.record(&request, None);
        let step = self
            .hooks
            .lock()
            .map_err(|_| scripted_error("scripted-hook-state"))
            .and_then(|mut hooks| {
                hooks
                    .pop_front()
                    .ok_or_else(|| scripted_error("scripted-hook-exhausted"))
            });
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            if request.operation() != EmbeddingOperation::CreateHook {
                return Err(scripted_error("scripted-operation-mismatch"));
            }
            let outcomes = step?.outcomes?;
            Ok(Box::new(ScriptedOperationHook { outcomes, calls }) as Box<dyn OperationHook>)
        })
    }
}

struct ScriptedOperationHook {
    outcomes: VecDeque<Result<HookOutcomeV1, HostError>>,
    calls: Arc<Mutex<Vec<ScriptedCall>>>,
}

impl OperationHook for ScriptedOperationHook {
    fn dispatch<'a>(
        &'a mut self,
        request: HostRequest,
        cancellation: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(ScriptedCall {
                operation: request.operation(),
                canonical_bytes: Arc::from(request.canonical_bytes()),
                cancellation_observed: Some(cancellation.is_cancelled()),
            });
        }
        let outcome = if request.operation() == EmbeddingOperation::DispatchOperation {
            self.outcomes
                .pop_front()
                .unwrap_or_else(|| Err(scripted_error("scripted-outcome-exhausted")))
        } else {
            Err(scripted_error("scripted-operation-mismatch"))
        };
        Box::pin(async move { outcome })
    }
}

fn scripted_error(code: &'static str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}
