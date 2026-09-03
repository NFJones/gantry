//! Public lifecycle coverage for the supported nondurable Interpreter facade.

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{ExecutorAdapter, HookOutcomeV1, HostError, IdentitySource};
use gantry::host::embedding::EmbeddingOperation;
use gantry::portable::{
    CancellationReasonCategory, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{CancellationRecord, InterpreterConfiguration, RequiredConfiguration};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValueView};
use gantry::{
    Interpreter, StartExecutionRequest, StartExecutionResult, caller_cancellation_reason,
};
use gantry_conformance::scripted::{ScriptedHook, ScriptedIntegration, ScriptedPreflight};
use gantry_conformance::services::{
    DeterministicExecutor, DeterministicIdentitySource, DeterministicUtcClock,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-interpreter-facade-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write facade fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn public_interpreter_drives_and_observes_one_sequential_execution() {
    let root = TempDirectory::new("fn main() -> Int { 1 + 2 }");
    let identities = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=8).map(|byte| Ok([byte; 32])),
    ));
    let executor = Arc::new(DeterministicExecutor::new([], []));
    let clock = Arc::new(DeterministicUtcClock::new([timestamp(1), timestamp(2)]));
    let integration = Arc::new(ScriptedIntegration::new([], []));
    let configuration = configuration(executor, identities);
    let interpreter = Interpreter::new(configuration, clock, integration.clone(), integration);
    let selection = selection();

    let started = block_on(interpreter.start_execution(StartExecutionRequest {
        package_root: &root.0,
        protocol_selection: &selection,
        required_peers: &[],
        entry_input: None,
        root_session: None,
        event_delivery: None,
    }));
    let StartExecutionResult::Accepted(accepted) = started else {
        panic!("valid deterministic execution was rejected")
    };
    let execution_id = accepted.execution_id;
    let handle = accepted.handle.clone();
    let initial = interpreter
        .query_execution(execution_id)
        .unwrap_or_else(|error| panic!("initial query failed: {error}"))
        .unwrap_or_else(|| panic!("accepted execution was not registered"));
    assert!(initial.foreground.is_none());
    assert!(initial.terminal.is_none());

    let completed = block_on(interpreter.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("execution drive failed: {error:?}"));
    let foreground = completed
        .foreground
        .as_ref()
        .unwrap_or_else(|| panic!("foreground outcome was not fixed"));
    let gantry::runtime::MachineOutcome::Succeeded(value) = foreground else {
        panic!("deterministic execution did not succeed")
    };
    assert!(matches!(value.view(), LogicalValueView::Int(value) if value.get() == 3));
    assert_eq!(completed.terminal, completed.foreground);

    assert_eq!(
        block_on(interpreter.await_foreground(&handle))
            .unwrap_or_else(|error| panic!("foreground await failed: {error}")),
        Some(completed.clone())
    );
    assert_eq!(
        block_on(interpreter.await_terminal(&handle))
            .unwrap_or_else(|error| panic!("terminal await failed: {error}")),
        Some(completed.clone())
    );
    let cancellation = caller_cancellation_reason(Some(Arc::from("late")), 32)
        .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    assert!(matches!(
        block_on(interpreter.cancel_execution(execution_id, cancellation)),
        Ok(CancellationRecord::AlreadyTerminal(snapshot)) if snapshot == completed
    ));

    let first_shutdown = block_on(interpreter.shutdown())
        .unwrap_or_else(|error| panic!("shutdown failed: {error:?}"));
    let repeated_shutdown = block_on(interpreter.shutdown())
        .unwrap_or_else(|error| panic!("repeated shutdown failed: {error:?}"));
    assert!(Arc::ptr_eq(&first_shutdown, &repeated_shutdown));
    assert!(first_shutdown.orderly);
    assert!(first_shutdown.cohort.is_empty());
}

#[test]
fn public_interpreter_drives_scripted_action_success_and_decline() {
    let successful_root = TempDirectory::new(
        "action read_only lookup(value: Int) -> String;\nfn main() -> String { action lookup(7) }",
    );
    let successful_integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let successful = Interpreter::new(
        configuration(
            Arc::new(DeterministicExecutor::new([], [])),
            Arc::new(DeterministicIdentitySource::new(
                (1_u8..=16).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(1), timestamp(2)])),
        successful_integration.clone(),
        successful_integration.clone(),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(successful.start_execution(StartExecutionRequest {
            package_root: &successful_root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid action execution was rejected")
    };
    let snapshot = block_on(successful.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("action execution failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::String("done"))
    ));
    assert_eq!(
        successful_integration
            .calls()
            .into_iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
        ]
    );

    let declined_root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action lookup() }",
    );
    let declined_integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Declined(
            Arc::from("unavailable"),
        ))])],
    ));
    let declined = Interpreter::new(
        configuration(
            Arc::new(DeterministicExecutor::new([], [])),
            Arc::new(DeterministicIdentitySource::new(
                (17_u8..=32).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(3), timestamp(4)])),
        declined_integration.clone(),
        declined_integration,
    );
    let StartExecutionResult::Accepted(accepted) =
        block_on(declined.start_execution(StartExecutionRequest {
            package_root: &declined_root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid declined action execution was rejected")
    };
    let snapshot = block_on(declined.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("declined action drive failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code
                == gantry::runtime::RuntimeCode::Operation(
                    gantry::portable::RuntimeErrorCategory::RequiredResultDecline
                )
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn public_interpreter_captures_and_completes_one_model_prompt() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nfn main() -> String { prompt \"Hello ${7}\" using { enabled: true } -> String }",
    );
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let interpreter = Interpreter::new(
        configuration(
            Arc::new(DeterministicExecutor::new([], [])),
            Arc::new(DeterministicIdentitySource::new(
                (33_u8..=64).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(5), timestamp(6)])),
        integration.clone(),
        integration.clone(),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid prompt execution was rejected")
    };
    let snapshot = block_on(interpreter.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("prompt execution failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::String("done"))
    ));
    let calls = integration.calls();
    assert_eq!(
        calls.iter().map(|call| call.operation).collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::EstablishSession,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
        ]
    );
    let dispatch = std::str::from_utf8(&calls[3].canonical_bytes)
        .unwrap_or_else(|error| panic!("dispatch was not UTF-8: {error}"));
    assert!(dispatch.contains("\"rendered_prompt\":\"Hello 7\""));
    assert!(dispatch.contains("\"position\":0,\"type\":\"Int\",\"value\":7"));
    assert!(dispatch.contains("\"name\":\"enabled\",\"type\":\"Bool\",\"value\":true"));
}

#[test]
fn public_interpreter_reuses_one_lexical_fork_session() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nfn main() { session(fork) { discard prompt \"First\" -> String; discard prompt \"Second\" -> String; } }",
    );
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([
            Ok(HookOutcomeV1::Completed(Arc::from(&br#""one""#[..]))),
            Ok(HookOutcomeV1::Completed(Arc::from(&br#""two""#[..]))),
        ])],
    ));
    let interpreter = Interpreter::new(
        configuration(
            Arc::new(DeterministicExecutor::new([], [])),
            Arc::new(DeterministicIdentitySource::new(
                (121_u8..=152).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(11), timestamp(12)])),
        integration.clone(),
        integration.clone(),
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid lexical fork execution was rejected")
    };
    let snapshot = block_on(interpreter.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("lexical fork execution failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Unit)
    ));

    let calls = integration.calls();
    assert_eq!(
        calls.iter().map(|call| call.operation).collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::EstablishSession,
            EmbeddingOperation::EstablishSession,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
            EmbeddingOperation::DispatchOperation,
        ]
    );
    let first = std::str::from_utf8(&calls[4].canonical_bytes)
        .unwrap_or_else(|error| panic!("first dispatch was not UTF-8: {error}"));
    let second = std::str::from_utf8(&calls[5].canonical_bytes)
        .unwrap_or_else(|error| panic!("second dispatch was not UTF-8: {error}"));
    let first_session = json_string_member(first, "active_session_id");
    let second_session = json_string_member(second, "active_session_id");
    assert_eq!(first_session, second_session);
    assert!(first.contains("\"session_use\":{\"kind\":\"inline\"}"));
    assert!(second.contains("\"session_use\":{\"kind\":\"inline\"}"));
    assert!(second.contains("\"rendered_prompt\":\"First\""));
}

#[test]
fn public_interpreter_normalizes_declared_result_output() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nenum Choice { Empty, Number(Int) }\nstruct Report { choice: Choice, note: Option<String> = \"fallback\" }\nfn main() -> Result<Report, String> { prompt \"Report\" -> Result<Report, String> }",
    );
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(
                &br#"{"variant":"Ok","value":{"choice":{"variant":"Number","value":7}}}"#[..],
            ),
        ))])],
    ));
    let interpreter = Interpreter::new(
        configuration(
            Arc::new(DeterministicExecutor::new([], [])),
            Arc::new(DeterministicIdentitySource::new(
                (153_u8..=184).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(13), timestamp(14)])),
        integration.clone(),
        integration,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid declared result execution was rejected")
    };
    let snapshot = block_on(interpreter.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("declared result execution failed: {error:?}"));
    let Some(gantry::runtime::MachineOutcome::Succeeded(value)) = snapshot.foreground else {
        panic!("declared result execution did not succeed")
    };
    assert_eq!(
        value.canonical_json().bytes(),
        br#"{"value":{"choice":{"value":7,"variant":"Number"},"note":"fallback"},"variant":"Ok"}"#
    );
}

#[test]
fn public_interpreter_decodes_one_sealed_decision() {
    let root = TempDirectory::new(
        "agents { worker }\ndefault agent = worker;\nfn main() { discard decide \"Proceed?\"; }",
    );
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#"{"decision":true,"rationale":"ready"}"#[..]),
        ))])],
    ));
    let interpreter = Interpreter::new(
        configuration(
            Arc::new(DeterministicExecutor::new([], [])),
            Arc::new(DeterministicIdentitySource::new(
                (65_u8..=96).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(7), timestamp(8)])),
        integration.clone(),
        integration,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid decide execution was rejected")
    };
    let snapshot = block_on(interpreter.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("decide execution failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Succeeded(ref value))
            if matches!(value.view(), LogicalValueView::Unit)
    ));
}

#[test]
fn public_interpreter_settles_retry_delay_executor_failure() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action(retry_limit = 1) lookup() }",
    );
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"true"[..]),
        ))])],
    ));
    let executor = Arc::new(DeterministicExecutor::new(
        [Err(HostError {
            code: Arc::from("timer-failure"),
            protected_diagnostic: None,
        })],
        [Ok(0)],
    ));
    let interpreter = Interpreter::new(
        configuration(
            executor,
            Arc::new(DeterministicIdentitySource::new(
                (97_u8..=120).map(|byte| Ok([byte; 32])),
            )),
        ),
        Arc::new(DeterministicUtcClock::new([timestamp(9), timestamp(10)])),
        integration.clone(),
        integration,
    );
    let selection = selection();
    let StartExecutionResult::Accepted(accepted) =
        block_on(interpreter.start_execution(StartExecutionRequest {
            package_root: &root.0,
            protocol_selection: &selection,
            required_peers: &[],
            entry_input: None,
            root_session: None,
            event_delivery: None,
        }))
    else {
        panic!("valid retry execution was rejected")
    };
    let snapshot = block_on(interpreter.run_execution(*accepted))
        .unwrap_or_else(|error| panic!("retry execution failed: {error:?}"));
    assert!(matches!(
        snapshot.foreground,
        Some(gantry::runtime::MachineOutcome::Failed(ref failure))
            if failure.code
                == gantry::runtime::RuntimeCode::Operation(
                    gantry::portable::RuntimeErrorCategory::ExecutorFailure
                )
    ));
    assert_eq!(snapshot.terminal, snapshot.foreground);
}

#[test]
fn caller_cancellation_reason_is_typed_and_bounded() {
    let reason = caller_cancellation_reason(Some(Arc::from("stop")), 4)
        .unwrap_or_else(|error| panic!("bounded reason failed: {error:?}"));
    assert_eq!(reason.category, CancellationReasonCategory::Caller);
    assert!(caller_cancellation_reason(Some(Arc::from("longer")), 4).is_err());
}

fn configuration(
    executor: Arc<DeterministicExecutor>,
    identities: Arc<DeterministicIdentitySource>,
) -> InterpreterConfiguration {
    let executor: Arc<dyn ExecutorAdapter> = executor;
    let identities: Arc<dyn IdentitySource> = identities;
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            256, 65_536, 1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(
        executor,
        identities,
        required,
        gantry::runtime::AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
            .unwrap_or_else(|error| panic!("capacity configuration failed: {error}")),
    )
}

fn selection() -> ProtocolSelection {
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
    .unwrap_or_else(|error| panic!("selection failed: {error}"))
}

fn timestamp(microseconds: u32) -> Result<UtcTimestamp, gantry::host::contracts::HostError> {
    UtcTimestamp::from_unix_seconds(0, microseconds).map_err(|_| {
        gantry::host::contracts::HostError {
            code: Arc::from("clock-invariant"),
            protected_diagnostic: None,
        }
    })
}

fn json_string_member<'a>(document: &'a str, name: &str) -> &'a str {
    let prefix = format!("\"{name}\":\"");
    let value = document
        .split_once(&prefix)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing JSON member {name}"));
    value
        .split_once('"')
        .map(|(value, _)| value)
        .unwrap_or_else(|| panic!("unterminated JSON member {name}"))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
