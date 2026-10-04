//! Public runtime-input evidence for cancellation at String primitive executor yields.
//!
//! A high ordinary transition quantum and a short-input control distinguish primitive work
//! yields from transition-counter scheduling. No hook or source task is required.

use super::*;

/// Constructs an otherwise ordinary interpreter with a quantum above these straight-line cases.
fn interpreter(
    executor: Arc<DeterministicConcurrentExecutor>,
    integration: Arc<ScriptedIntegration>,
) -> Interpreter {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            256, 65_536, 1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits: {error:?}")),
        1_048_576,
        1_048_576,
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1000,
    )
    .unwrap_or_else(|error| panic!("required limits: {error:?}"));
    let capacities = AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
        .unwrap_or_else(|error| panic!("capacities: {error:?}"));
    let identities = Arc::new(DeterministicIdentitySource::new(
        (1_u8..=192).map(|byte| Ok([byte; 32])),
    ));
    Interpreter::new_with_event_delivery(
        InterpreterConfiguration::new(executor, identities, required, capacities),
        execution_clock(),
        integration.clone(),
        integration.clone(),
        integration,
        Arc::new(ImmediateDeliveryRuntime),
        SinkPlan::default(),
    )
}

/// Public cancellation must be observable during primitive work without hooks or spawned tasks.
#[test]
fn runtime_string_work_yields_observe_public_cancellation() {
    for expression in [
        "value == value",
        "[value, value] == [value, value]",
        "value.starts_with(value)",
        "value.ends_with(value)",
        "value.contains(\"missing\")",
        "value.trim()",
        "value.to_uppercase()",
        "value.to_lowercase()",
        "value + value",
        "[value, value].join(\"x\")",
        "value.replace(\"missing\", \"replacement\")",
        "value.split(\"missing\")",
        "value.parse_float()",
    ] {
        for long in [false, true] {
            let source = format!("fn main(value: String) {{ discard {expression}; }}");
            let root = TempDirectory::new(&source);
            let executor = Arc::new(DeterministicConcurrentExecutor::default());
            let integration = Arc::new(ScriptedIntegration::new(
                [ScriptedPreflight::success(
                    EmbeddingOperation::ResolveSessions,
                    &br#"{"result":"resolved"}"#[..],
                )],
                [],
            ));
            let interpreter = interpreter(executor.clone(), integration.clone());
            let input = serde_json::to_vec(&if long {
                if expression == "value.parse_float()" {
                    format!("1.{}", "0".repeat(10_000))
                } else {
                    " ".repeat(10_000)
                }
            } else if expression == "value.parse_float()" {
                "1.0".to_owned()
            } else {
                " ".to_owned()
            })
            .unwrap_or_else(|error| panic!("input: {error:?}"));
            let selection = selection();
            let started = block_on(
                interpreter.start_execution(StartExecutionRequest {
                    package_root: &root.0,
                    protocol_selection: &selection,
                    required_peers: &[],
                    entry_input: Some(&input),
                    root_session: Some(RootSessionSpecification {
                        id: ProtocolIdentity::from_fresh_material(
                            IdentityKind::Session,
                            [0xf0; 32],
                        )
                        .unwrap_or_else(|error| panic!("session: {error:?}")),
                        transcript: Some(b"{\"protocol\":{\"major\":1,\"minor\":0},\"turns\":[]}"),
                        opaque_lookup_material: Some(b"string-cooperation"),
                    }),
                    event_delivery: None,
                }),
            );
            let StartExecutionResult::Accepted(accepted) = started else {
                panic!("source admission: {expression}: {started:?}")
            };
            let handle = accepted.handle().clone();
            drop(accepted);
            assert_eq!(executor.yields(), 0, "start must not run source");
            executor.cancel_on_next_yield(
                handle
                    .cancellation_signal()
                    .unwrap_or_else(|error| panic!("cancellation signal: {error:?}")),
            );
            let snapshot = drive_to_terminal(&executor, &interpreter, &handle);
            if long {
                assert!(
                    executor.yields() > 0,
                    "primitive must cooperate: {expression}"
                );
                assert!(
                    matches!(snapshot.foreground, Some(MachineOutcome::Cancelled(_))),
                    "primitive cancellation: {expression}: {snapshot:?}"
                );
            } else {
                assert_eq!(executor.yields(), 0, "short control: {expression}");
                assert!(matches!(
                    snapshot.foreground,
                    Some(MachineOutcome::Succeeded(_))
                ));
            }
            assert!(
                integration
                    .calls()
                    .iter()
                    .all(|call| call.operation == EmbeddingOperation::ResolveSessions)
            );
        }
    }
}
