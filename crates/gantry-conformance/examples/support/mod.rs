//! Shared, network-free corpus runner over Gantry's public facade.
//!
//! `case.json` is either one case or `{ "scenarios": [case, ...] }`.
//! Cases require `class` and `expected` (including explicit JSON null), except
//! negative cases require `expected_diagnostic` and runtime failures require
//! `expected_error`. Concurrent cases require exactly `expected` or `expected_error`.
//! Optional `expected_terminal` names a closed terminal wire category; by default
//! success is required for value cases and the foreground failure category for
//! error cases. Optional `input` is passed as entry JSON. `hooks` is an
//! ordered script of `{kind, output}` or `{kind, error}`; kinds are prompt,
//! decide, action. An optional `assert_request` object maps JSON pointers into
//! the full dispatch envelope to exact expected values. All dispatch envelopes
//! are captured. Parallel scripts must not depend on unspecified sibling order.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gantry::host::contracts::{
    CancellationToken, EmbeddingVersion, FreshIdentityAllocator, HookFactory, HookOutcomeV1,
    HostError, HostFuture, HostRequest, HostResponse, InclusiveJitterRange, IntegrationPreflight,
    JitterSource, OperationHook, RuntimeSessionService,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::mode::SemanticMode;
use gantry::portable::{
    HookFailureCategory, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
    RuntimeErrorCategory, TerminalOnlyCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{
    AsyncCapacityLimits, ConcurrentTerminalCategoryV1, ConcurrentTerminalOutcomeV1,
    ExecutionSnapshot, InterpreterConfiguration, MachineOutcome, RequiredConfiguration,
};
use gantry::source::FrontendLimits;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::timestamp::UtcTimestamp;
use gantry::value::DEFAULT_VALUE_LIMITS;
use gantry::{
    AnalyzePackageCoordinator, AnalyzePackageRequest, AnalyzePackageStatus, Interpreter,
    StartExecutionRequest, StartExecutionResult,
};
use gantry_adapter_tokio::TokioExecutor;
use gantry_conformance::services::{DeterministicIdentitySource, DeterministicUtcClock};
use serde::Deserialize;
use serde_json::{Value, json};

pub mod durable;

/// Maximum wall-clock time per scenario, including analysis and shutdown.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(30);

/// Closed corpus execution classes; durable cases are delegated separately.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    Cli,
    Host,
    Concurrent,
    Durable,
    Negative,
    RuntimeFailure,
}

/// One explicit execution/analysis assertion. Values retain absent versus null.
#[derive(Clone, Debug, Deserialize)]
pub struct Case {
    pub class: Class,
    #[serde(default)]
    pub hooks: Vec<Hook>,
    #[serde(default, deserialize_with = "present_error")]
    pub expected_error: Option<String>,
    pub expected_diagnostic: Option<String>,
    #[serde(flatten)]
    pub values: BTreeMap<String, Value>,
}

/// An authored error must be a string; null must not masquerade as absence.
fn present_error<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// One scripted host outcome and exact optional request assertions.
#[derive(Clone, Debug, Deserialize)]
pub struct Hook {
    pub kind: String,
    #[serde(default)]
    pub assert_request: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub outcome: BTreeMap<String, Value>,
}

/// Captured public dispatch envelopes, retained for callers and tests.
#[derive(Debug)]
pub struct Report {
    pub requests: Vec<Value>,
}

/// Reads strict case metadata and expands a nonempty scenarios container.
pub fn read_cases(root: &Path) -> Result<Vec<Case>, String> {
    let bytes = fs::read(root.join("case.json")).map_err(|e| format!("{}: {e}", root.display()))?;
    // Validate raw bytes before serde's Value map can discard duplicate keys.
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: 4_194_304,
            maximum_nesting_depth: 128,
            maximum_nodes: 262_144,
            maximum_string_scalars: 1_048_576,
            maximum_list_items: 65_536,
        },
    )
    .map_err(|e| format!("case.json: {e:?}"))?;
    let mut value: Value = serde_json::from_slice(document.input()).map_err(|e| e.to_string())?;
    let cases: Vec<Case> = if let Some(scenarios) = value.get_mut("scenarios") {
        let scenarios = scenarios.take();
        if value.as_object().is_none_or(|object| object.len() != 1) {
            return Err("scenarios container must have no other fields".into());
        }
        serde_json::from_value(scenarios).map_err(|e| e.to_string())?
    } else {
        vec![serde_json::from_value(value).map_err(|e| e.to_string())?]
    };
    if cases.is_empty() {
        return Err("scenarios must not be empty".into());
    }
    for case in &cases {
        validate_case(case)?;
    }
    Ok(cases)
}

/// Rejects typos, contradictory outcomes and unrecognized portable hook codes.
fn validate_case(case: &Case) -> Result<(), String> {
    if case.values.keys().any(|key| {
        !matches!(
            key.as_str(),
            "expected" | "input" | "durable_mode" | "expected_terminal"
        )
    }) {
        return Err("unknown case field".into());
    }
    durable::validate(case)?;
    if let Some(terminal) = case.values.get("expected_terminal")
        && (case.class == Class::Negative
            || terminal.as_str().and_then(terminal_category).is_none())
    {
        return Err("invalid expected_terminal for execution class".into());
    }
    match case.class {
        Class::Negative
            if case.expected_diagnostic.is_some()
                && case.expected_error.is_none()
                && !case.values.contains_key("expected")
                && case.hooks.is_empty() => {}
        Class::RuntimeFailure
            if case.expected_error.is_some()
                && case.expected_diagnostic.is_none()
                && !case.values.contains_key("expected") => {}
        Class::Concurrent
            if case.values.contains_key("expected") != case.expected_error.is_some()
                && case.expected_diagnostic.is_none() => {}
        Class::Cli | Class::Host | Class::Durable
            if case.values.contains_key("expected")
                && case.expected_error.is_none()
                && case.expected_diagnostic.is_none() => {}
        _ => return Err("case must specify exactly the outcome required by its class".into()),
    }
    for hook in &case.hooks {
        if !matches!(hook.kind.as_str(), "prompt" | "decide" | "action") {
            return Err(format!("unknown hook kind: {}", hook.kind));
        }
        if hook.outcome.len() != 1
            || !hook
                .outcome
                .keys()
                .all(|key| key == "output" || key == "error")
        {
            return Err("hook requires exactly one output or error".into());
        }
        if let Some(error) = hook.outcome.get("error")
            && error
                .as_str()
                .and_then(HookFailureCategory::from_wire_name)
                .is_none()
        {
            return Err(format!("unknown hook error: {error}"));
        }
        if hook
            .assert_request
            .keys()
            .any(|pointer| !pointer.is_empty() && !pointer.starts_with('/'))
        {
            return Err("assert_request keys must be JSON pointers".into());
        }
    }
    Ok(())
}

/// Parses only the public runtime, terminal-only, and cancellation wire categories.
fn terminal_category(wire: &str) -> Option<ConcurrentTerminalCategoryV1> {
    RuntimeErrorCategory::from_wire_name(wire)
        .map(ConcurrentTerminalCategoryV1::Runtime)
        .or_else(|| {
            TerminalOnlyCategory::from_wire_name(wire)
                .map(ConcurrentTerminalCategoryV1::TerminalOnly)
        })
        .or_else(|| (wire == "cancellation").then_some(ConcurrentTerminalCategoryV1::Cancellation))
}

/// Checks terminal independently of foreground; failures default to their portable
/// category, not the often narrower foreground error code (e.g. division by zero).
fn check_terminal(snapshot: &ExecutionSnapshot, case: &Case) -> Result<(), String> {
    let expected = if let Some(value) = case.values.get("expected_terminal") {
        value
            .as_str()
            .and_then(terminal_category)
            .ok_or("invalid expected_terminal")?
    } else if case.expected_error.is_some() {
        match &snapshot.foreground {
            Some(outcome @ MachineOutcome::Failed(_)) => {
                ConcurrentTerminalOutcomeV1::from(outcome.clone()).category
            }
            other => {
                return Err(format!(
                    "expected failed foreground for terminal default: {other:?}"
                ));
            }
        }
    } else {
        ConcurrentTerminalCategoryV1::TerminalOnly(TerminalOnlyCategory::Success)
    };
    let actual = snapshot.terminal.as_ref().map(|terminal| terminal.category);
    if actual != Some(expected) {
        return Err(format!("expected terminal {expected:?}, got {actual:?}"));
    }
    Ok(())
}

/// Recursively discovers metadata without following symlinks or leaving the root.
pub fn discover(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in
            fs::read_dir(&directory).map_err(|e| format!("{}: {e}", directory.display()))?
        {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name() == "case.json" {
                if !directory.join("main.gnt").is_file() {
                    return Err(format!("{} lacks main.gnt", directory.display()));
                }
                found.push(directory.clone());
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Runs every scenario with an independent bounded Tokio runtime.
pub fn run_package(root: &Path) -> Result<Vec<Report>, String> {
    let cases = read_cases(root)?;
    cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .map_err(|e| e.to_string())?;
            let result = runtime.block_on(async {
                tokio::time::timeout(SCENARIO_TIMEOUT, run_case(root, case))
                    .await
                    .map_err(|_| "scenario exceeded 30 second timeout".to_owned())?
            });
            runtime.shutdown_timeout(Duration::from_secs(1));
            result.map_err(|e| format!("{} scenario {}: {e}", root.display(), index + 1))
        })
        .collect()
}

/// Uses fixed minimal jitter; no external random source or model is consulted.
struct FixedJitter;
impl JitterSource for FixedJitter {
    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

/// Constructs the same finite frontend limits used by public facade tests.
fn frontend_limits() -> Result<FrontendLimits, String> {
    FrontendLimits::new(
        32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304, 256,
        65_536, 1_000_000,
    )
    .map_err(|e| format!("{e:?}"))
}

/// Selects the complete current public protocol tuple.
pub fn selection() -> Result<ProtocolSelection, String> {
    ProtocolSelection::new(
        PORTABLE_SPECIFICATION_REVISION,
        PROTOCOL_FAMILY_DEFINITIONS
            .iter()
            .map(|definition| SelectedProtocol {
                family: definition.family,
                version: ProtocolVersion {
                    major: definition.major,
                    minor: definition.minor,
                },
            })
            .collect(),
    )
    .map_err(|e| e.to_string())
}

/// Analyzes a negative or drives an accepted public interpreter to terminal.
async fn run_case(root: &Path, case: &Case) -> Result<Report, String> {
    if case.class == Class::Durable {
        return durable::run(root, case).await;
    }
    let identities = Arc::new(DeterministicIdentitySource::new((1_u64..=4096).map(|n| {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Ok(bytes)
    })));
    let clock = Arc::new(DeterministicUtcClock::new((0..100_000).map(|n| {
        UtcTimestamp::from_unix_seconds(0, n).map_err(|_| host_error("corpus-clock"))
    })));
    let selection = selection()?;
    if case.class == Class::Negative {
        let allocator = FreshIdentityAllocator::default();
        let coordinator = AnalyzePackageCoordinator::new(
            &allocator,
            identities.as_ref(),
            clock.as_ref(),
            gantry_conformance::blocking_work(),
        );
        let result = coordinator
            .analyze(AnalyzePackageRequest {
                package_root: root,
                protocol_selection: &selection,
                semantic_mode: SemanticMode::Application,
                frontend_limits: frontend_limits()?,
                event_delivery: None,
            })
            .await
            .map_err(|e| format!("analysis: {e:?}"))?;
        let codes: Vec<_> = result
            .diagnostics()
            .iter()
            .map(|d| d.code.as_str())
            .collect();
        if result.status != AnalyzePackageStatus::SourceInvalid
            || !codes
                .iter()
                .any(|code| Some(*code) == case.expected_diagnostic.as_deref())
        {
            return Err(format!(
                "expected diagnostic {:?}; got {:?}: {codes:?}",
                case.expected_diagnostic, result.status
            ));
        }
        return Ok(Report {
            requests: Vec::new(),
        });
    }
    let executor = Arc::new(TokioExecutor::new(
        tokio::runtime::Handle::current(),
        Arc::new(FixedJitter),
    ));
    let required = RequiredConfiguration::new(
        frontend_limits()?,
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .map_err(|e| e.to_string())?;
    let capacity =
        AsyncCapacityLimits::new(64, 64, 64, 64, 64, 64, 64, 64, 64).map_err(|e| e.to_string())?;
    let host = Arc::new(OfflineHost {
        state: Arc::new(Mutex::new(ScriptState {
            pending: case.hooks.clone().into(),
            requests: Vec::new(),
            failures: Vec::new(),
        })),
    });
    let interpreter = Interpreter::new(
        InterpreterConfiguration::new(executor, identities, required, capacity),
        clock,
        host.clone(),
        host.clone(),
        host.clone(),
    );
    let input = case
        .values
        .get("input")
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|e| e.to_string())?;
    let accepted = match interpreter
        .start_execution(StartExecutionRequest {
            package_root: root,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: input.as_deref(),
            root_session: None,
            event_delivery: None,
        })
        .await
    {
        StartExecutionResult::Accepted(accepted) => accepted,
        StartExecutionResult::Rejected(error) => return Err(format!("start rejected: {error:?}")),
    };
    let snapshot = interpreter
        .await_terminal(accepted.handle())
        .await
        .map_err(|e| format!("await terminal: {e:?}"))?
        .ok_or("accepted execution disappeared")?;
    let shutdown = interpreter
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e:?}"))?;
    if !shutdown.orderly {
        return Err(format!("non-orderly shutdown: {shutdown:?}"));
    }
    let report = host.finish()?;
    match &snapshot.foreground {
        Some(MachineOutcome::Succeeded(value)) if case.expected_error.is_none() => {
            let actual: Value = serde_json::from_slice(value.canonical_json().bytes())
                .map_err(|e| e.to_string())?;
            if case.values.get("expected") != Some(&actual) {
                return Err(format!(
                    "expected {:?}, got {actual}",
                    case.values.get("expected")
                ));
            }
        }
        Some(MachineOutcome::Failed(failure))
            if Some(failure.code.wire_name()) == case.expected_error.as_deref() => {}
        outcome => {
            return Err(format!(
                "unexpected foreground: {outcome:?}; expected error {:?}",
                case.expected_error
            ));
        }
    }
    check_terminal(&snapshot, case)?;
    Ok(report)
}

/// Shared response queue, retained assertions, and captured requests.
struct ScriptState {
    pending: VecDeque<Hook>,
    requests: Vec<Value>,
    failures: Vec<String>,
}
/// Offline mappings/sessions and task-local hooks sharing the explicit script.
struct OfflineHost {
    state: Arc<Mutex<ScriptState>>,
}
impl OfflineHost {
    /// Ensures ignored or handled host errors cannot hide a script mismatch.
    fn finish(&self) -> Result<Report, String> {
        let state = self.state.lock().map_err(|_| "script mutex poisoned")?;
        if !state.failures.is_empty() {
            return Err(format!("script assertions: {:?}", state.failures));
        }
        if !state.pending.is_empty() {
            return Err(format!("{} unconsumed hook responses", state.pending.len()));
        }
        Ok(Report {
            requests: state.requests.clone(),
        })
    }
}

/// Creates a structured local-only host error.
fn host_error(code: &str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}
/// Encodes one versioned public host response.
fn response(request: &HostRequest, value: Value) -> Result<HostResponse, HostError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| host_error("corpus-json"))?;
    HostResponse::new(
        EmbeddingVersion::V1,
        request.operation(),
        Arc::<[u8]>::from(bytes),
    )
    .map_err(|_| host_error("corpus-response"))
}
impl IntegrationPreflight for OfflineHost {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            if request.operation() != EmbeddingOperation::ResolveMappings {
                return Err(host_error("corpus-preflight-operation"));
            }
            let body: Value = serde_json::from_slice(request.canonical_bytes())
                .map_err(|_| host_error("corpus-request-json"))?;
            let mut resolved = json!({"result":"resolved"});
            if body["agent_names"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
            {
                resolved["agent_mapping_revision"] = json!("corpus-agents-v1");
            }
            if body["action_signatures"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
            {
                resolved["action_mapping_revision"] = json!("corpus-actions-v1");
            }
            response(&request, resolved)
        })
    }
}
impl RuntimeSessionService for OfflineHost {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            if request.operation() != EmbeddingOperation::EstablishSession {
                return Err(host_error("corpus-session-operation"));
            }
            response(&request, json!({"result":"established"}))
        })
    }
}
impl HookFactory for OfflineHost {
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        Box::pin(async move {
            if request.operation() != EmbeddingOperation::CreateHook {
                return Err(host_error("corpus-hook-operation"));
            }
            Ok(Box::new(OfflineHost {
                state: self.state.clone(),
            }) as Box<dyn OperationHook>)
        })
    }
}
impl OperationHook for OfflineHost {
    fn dispatch<'a>(
        &'a mut self,
        request: HostRequest,
        _: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        let outcome = (|| {
            let mut state = self.state.lock().map_err(|_| host_error("corpus-state"))?;
            let envelope: Value = serde_json::from_slice(request.canonical_bytes())
                .map_err(|_| host_error("corpus-request-json"))?;
            state.requests.push(envelope.clone());
            let Some(hook) = state.pending.pop_front() else {
                state
                    .failures
                    .push("unexpected dispatch after script exhausted".into());
                return Err(host_error("corpus-script-exhausted"));
            };
            if request.operation() != EmbeddingOperation::DispatchOperation
                || envelope
                    .pointer("/operation_request/operation_kind")
                    .and_then(Value::as_str)
                    != Some(&hook.kind)
            {
                state
                    .failures
                    .push(format!("expected {} dispatch, got {}", hook.kind, envelope));
                return Err(host_error("corpus-operation-mismatch"));
            }
            for (pointer, expected) in &hook.assert_request {
                if envelope.pointer(pointer) != Some(expected) {
                    state.failures.push(format!(
                        "{pointer}: expected {expected}, got {:?}",
                        envelope.pointer(pointer)
                    ));
                }
            }
            if let Some(output) = hook.outcome.get("output") {
                Ok(HookOutcomeV1::Completed(Arc::from(
                    serde_json::to_vec(output).map_err(|_| host_error("corpus-json"))?,
                )))
            } else {
                let category = hook
                    .outcome
                    .get("error")
                    .and_then(Value::as_str)
                    .and_then(HookFailureCategory::from_wire_name)
                    .ok_or_else(|| host_error("corpus-invalid-error"))?;
                Ok(HookOutcomeV1::Failed {
                    category,
                    message: Arc::from("offline scripted failure"),
                })
            }
        })();
        Box::pin(async move { outcome })
    }
}
