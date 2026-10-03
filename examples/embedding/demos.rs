//! Public Rust embedding demonstrations compiled by `example_durability`.
//!
//! Host services are local; cancellation waits for an entered operation instead
//! of racing a fast source program. All waits are bounded by the test driver.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::support;
use gantry::host::contracts::{
    CancellationToken, EmbeddingVersion, HookFactory, HookOutcomeV1, HostError, HostFuture,
    HostRequest, HostResponse, IntegrationPreflight, OperationHook, RuntimeSessionService,
};
use gantry::host::event::{
    EventDeliveryRequest, EventRetryPolicy, EventSink, RedactionCapabilities, SinkDeliveryPolicy,
    SinkId,
};
use gantry::observe::{SinkPlan, SinkRegistration};
use gantry::portable::{DeliveryOutcome, EventKind, JitterMode, SinkClass};
use gantry::runtime::{CancellationRecord, MachineOutcome};
use gantry::{
    DurableStartExecutionRequest, DurableStartExecutionResult, StartExecutionRequest,
    StartExecutionResult,
};

/// Offline host whose action can be held until cooperative cancellation.
#[derive(Default)]
struct Host {
    entered: Arc<AtomicBool>,
    hold: bool,
}

/// Encodes a valid local session or mapping response.
fn response(request: &HostRequest, bytes: &'static [u8]) -> Result<HostResponse, HostError> {
    HostResponse::new(EmbeddingVersion::V1, request.operation(), Arc::from(bytes))
        .map_err(|_| error())
}
/// Creates a protected-data-free local host error.
fn error() -> HostError {
    HostError {
        code: Arc::from("embedding-demo"),
        protected_diagnostic: None,
    }
}
impl IntegrationPreflight for Host {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            let body: serde_json::Value =
                serde_json::from_slice(request.canonical_bytes()).map_err(|_| error())?;
            if body["action_signatures"]
                .as_array()
                .is_some_and(|actions| !actions.is_empty())
            {
                response(
                    &request,
                    br#"{"action_mapping_revision":"embedding-v1","result":"resolved"}"#,
                )
            } else {
                response(&request, br#"{"result":"resolved"}"#)
            }
        })
    }
}
impl RuntimeSessionService for Host {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move { response(&request, br#"{"result":"established"}"#) })
    }
}
impl HookFactory for Host {
    fn create_hook<'a>(
        &'a self,
        _: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        Box::pin(async move {
            Ok(Box::new(Host {
                entered: self.entered.clone(),
                hold: self.hold,
            }) as Box<dyn OperationHook>)
        })
    }
}
impl OperationHook for Host {
    fn dispatch<'a>(
        &'a mut self,
        _: HostRequest,
        cancellation: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        Box::pin(async move {
            self.entered.store(true, Ordering::Release);
            while self.hold && !cancellation.is_cancelled() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok(HookOutcomeV1::Completed(Arc::from(&br#"42"#[..])))
        })
    }
}

/// Queries pending work, cancels it, observes terminal state, and shuts down.
pub async fn lifecycle(root: &Path) -> Result<(), String> {
    let host = Arc::new(Host {
        hold: true,
        ..Host::default()
    });
    let interpreter = support::durable::interpreter(host.clone(), 1, false)?;
    let selection = support::selection()?;
    let accepted = match interpreter
        .start_execution(StartExecutionRequest {
            package_root: root,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        })
        .await
    {
        StartExecutionResult::Accepted(value) => value,
        StartExecutionResult::Rejected(error) => return Err(format!("start: {}", error.code)),
    };
    while !host.entered.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let pending = interpreter
        .query_execution(accepted.execution_id())
        .map_err(|e| format!("query: {e:?}"))?
        .ok_or("missing execution")?;
    if pending.terminal.is_some() {
        return Err("held action unexpectedly terminal".into());
    }
    let reason = gantry::caller_cancellation_reason(Some(Arc::from("demo stop")), 64)
        .map_err(|e| format!("reason: {e:?}"))?;
    let record = interpreter
        .cancel_execution(accepted.execution_id(), reason.clone())
        .await
        .map_err(|e| format!("cancel: {e:?}"))?;
    if !matches!(record, CancellationRecord::Accepted { .. }) {
        return Err(format!("cancellation: {record:?}"));
    }
    let terminal = interpreter
        .await_terminal(accepted.handle())
        .await
        .map_err(|e| format!("terminal: {e:?}"))?
        .ok_or("missing terminal")?;
    if !matches!(terminal.foreground, Some(MachineOutcome::Failed(ref failure)) if failure.code.wire_name() == "cancellation")
        || terminal.cancellation.as_ref() != Some(&reason)
        || terminal.terminal.is_none()
    {
        return Err(format!("not cancelled: {terminal:?}"));
    }
    let repeated = interpreter
        .cancel_execution(accepted.execution_id(), reason.clone())
        .await
        .map_err(|e| format!("repeat cancel: {e:?}"))?;
    if !matches!(repeated, CancellationRecord::Accepted { reason: ref effective, .. } | CancellationRecord::Existing { reason: ref effective, .. } if effective == &reason)
    {
        return Err(format!("repeated cancellation changed: {repeated:?}"));
    }
    if !interpreter
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e:?}"))?
        .orderly
    {
        return Err("shutdown not orderly".into());
    }
    Ok(())
}

/// Counts actual delivered events, with explicit no-raw-output policy.
#[derive(Default)]
struct Sink {
    events: AtomicUsize,
    terminal: AtomicBool,
}
impl EventSink for Sink {
    fn deliver<'a>(
        &'a self,
        request: EventDeliveryRequest,
    ) -> HostFuture<'a, Result<DeliveryOutcome, HostError>> {
        if request
            .protected_payloads
            .payloads()
            .iter()
            .any(|payload| payload.bytes.is_some())
        {
            return Box::pin(async { Err(error()) });
        }
        self.events.fetch_add(1, Ordering::Relaxed);
        if request.event.kind() == EventKind::TerminalExecution {
            self.terminal.store(true, Ordering::Release);
        }
        Box::pin(async { Ok(DeliveryOutcome::Success) })
    }
}

/// Runs a real required sink and verifies delivery reached terminal observation.
pub async fn observation(root: &Path) -> Result<(), String> {
    let interpreter = support::durable::interpreter(Arc::new(Host::default()), 1, false)?;
    let sink = Arc::new(Sink::default());
    let retry = EventRetryPolicy::new("offline-no-retry", 0, 0, 0, JitterMode::None)
        .map_err(|e| format!("retry: {e:?}"))?;
    let policy = SinkDeliveryPolicy::new(
        SinkClass::Required,
        false,
        "deny-protected",
        RedactionCapabilities::default(),
        retry,
        1_000_000,
    )
    .map_err(|e| format!("policy: {e:?}"))?;
    let plan = SinkPlan::new(vec![SinkRegistration::new(
        SinkId::new("local-audit").map_err(|e| format!("sink: {e:?}"))?,
        policy,
        sink.clone(),
    )])
    .map_err(|e| e.to_string())?;
    let selection = support::selection()?;
    let accepted = match interpreter
        .start_execution(StartExecutionRequest {
            package_root: root,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: Some(&plan),
        })
        .await
    {
        StartExecutionResult::Accepted(value) => value,
        StartExecutionResult::Rejected(error) => return Err(format!("start: {}", error.code)),
    };
    let terminal = interpreter
        .await_terminal(accepted.handle())
        .await
        .map_err(|e| format!("terminal: {e:?}"))?
        .ok_or("missing terminal")?;
    if !matches!(terminal.foreground, Some(MachineOutcome::Succeeded(_)))
        || !terminal.required_delivery_failures.is_empty()
        || !sink.terminal.load(Ordering::Acquire)
        || sink.events.load(Ordering::Relaxed) == 0
    {
        return Err("required terminal delivery not observed".into());
    }
    if !interpreter
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e:?}"))?
        .orderly
    {
        return Err("shutdown not orderly".into());
    }
    Ok(())
}

/// Exercises finite accounting and the explicit unsupported durable adapter policy.
pub async fn resource_policy(root: &Path) -> Result<(), String> {
    let host = Arc::new(Host::default());
    let interpreter = support::durable::interpreter_with_policy(host, 1, false, |config| {
        config.with_adapter_bounded_resource_accounting_limits(64, 64, 128, 64)
    })?;
    let selection = support::selection()?;
    let accepted = match interpreter
        .start_execution(StartExecutionRequest {
            package_root: root,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        })
        .await
    {
        StartExecutionResult::Accepted(value) => value,
        StartExecutionResult::Rejected(error) => {
            return Err(format!("finite policy start: {}", error.code));
        }
    };
    let snapshot = interpreter
        .await_terminal(accepted.handle())
        .await
        .map_err(|e| format!("finite terminal: {e:?}"))?
        .ok_or("missing finite execution")?;
    if !matches!(snapshot.foreground, Some(MachineOutcome::Succeeded(_)))
        || snapshot.terminal.is_none()
    {
        return Err("finite-policy execution failed".into());
    }
    let store = Arc::new(gantry::runtime::InMemoryJournalStore::new());
    let result = interpreter
        .start_durable_execution(
            store,
            DurableStartExecutionRequest {
                journal_id: gantry::host::journal::JournalId::new("resource-policy-demo")
                    .map_err(|e| format!("id: {e:?}"))?,
                start: StartExecutionRequest {
                    package_root: root,
                    protocol_selection: &selection,
                    required_peers: &[],
                    entry_input: None,
                    root_session: None,
                    event_delivery: None,
                },
            },
        )
        .await;
    match result {
        DurableStartExecutionResult::Rejected(error)
            if error.failure.code.as_ref() == "unsupported-durable-adapter-identity-policy"
                && error.release_error.is_none() => {}
        _ => return Err("durable adapter policy was not explicitly refused".into()),
    }
    if !interpreter
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e:?}"))?
        .orderly
    {
        return Err("shutdown not orderly".into());
    }
    Ok(())
}
