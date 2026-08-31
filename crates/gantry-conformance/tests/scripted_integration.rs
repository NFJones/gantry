//! Public-contract tests for the harness-only scripted integration.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    CancellationSignal, EmbeddingVersion, HookFactory, HookOutcomeV1, HostError, HostRequest,
    IntegrationPreflight,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry_conformance::scripted::{ScriptedHook, ScriptedIntegration, ScriptedPreflight};

#[test]
fn scripted_adapter_exercises_preflight_hook_and_cancellation_contracts() {
    let integration = ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                Arc::<[u8]>::from(&b"{\"result\":\"resolved\"}"[..]),
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                Arc::<[u8]>::from(&b"{\"result\":\"resolved\"}"[..]),
            ),
        ],
        [ScriptedHook::created([
            Ok(HookOutcomeV1::Completed(Arc::from(&b"{\"value\":1}"[..]))),
            Ok(HookOutcomeV1::Declined(Arc::from("policy"))),
        ])],
    );

    for operation in [
        EmbeddingOperation::ResolveMappings,
        EmbeddingOperation::ResolveSessions,
    ] {
        let response = block_on(integration.call(request(operation, b"{}")));
        assert!(response.is_ok_and(|response| response.operation() == operation));
    }

    let mut hook =
        block_on(integration.create_hook(request(EmbeddingOperation::CreateHook, b"{}")))
            .unwrap_or_else(|error| panic!("hook creation failed: {}", error.code));
    let cancellation = CancellationSignal::default();
    let completed = block_on(hook.dispatch(
        request(EmbeddingOperation::DispatchOperation, b"{\"attempt\":0}"),
        &cancellation,
    ));
    assert!(matches!(completed, Ok(HookOutcomeV1::Completed(_))));
    assert!(cancellation.cancel());
    let declined = block_on(hook.dispatch(
        request(EmbeddingOperation::DispatchOperation, b"{\"attempt\":1}"),
        &cancellation,
    ));
    assert!(matches!(declined, Ok(HookOutcomeV1::Declined(reason)) if &*reason == "policy"));

    let calls = integration.calls();
    assert_eq!(
        calls.iter().map(|call| call.operation).collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::ResolveSessions,
            EmbeddingOperation::CreateHook,
            EmbeddingOperation::DispatchOperation,
            EmbeddingOperation::DispatchOperation,
        ]
    );
    assert_eq!(calls[3].cancellation_observed, Some(false));
    assert_eq!(calls[4].cancellation_observed, Some(true));
    assert_eq!(&*calls[4].canonical_bytes, b"{\"attempt\":1}");
}

#[test]
fn scripted_adapter_preserves_failures_and_rejects_script_mismatch() {
    let integration = ScriptedIntegration::new(
        [ScriptedPreflight::failure(
            EmbeddingOperation::ResolveMappings,
            failure("mapping-failure", Some("protected:1")),
        )],
        [ScriptedHook::creation_failure(failure(
            "hook-creation-failure",
            None,
        ))],
    );
    let error =
        block_on(integration.call(request(EmbeddingOperation::ResolveMappings, b"{}"))).err();
    assert_eq!(
        error.as_ref().map(|error| error.code.as_ref()),
        Some("mapping-failure")
    );
    assert_eq!(
        error.and_then(|error| error.protected_diagnostic),
        Some(Arc::from("protected:1"))
    );
    let hook_error =
        block_on(integration.create_hook(request(EmbeddingOperation::CreateHook, b"{}"))).err();
    assert_eq!(
        hook_error.as_ref().map(|error| error.code.as_ref()),
        Some("hook-creation-failure")
    );

    let mismatched = ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            Arc::<[u8]>::from(&b"{}"[..]),
        )],
        [],
    );
    let mismatch =
        block_on(mismatched.call(request(EmbeddingOperation::ResolveMappings, b"{}"))).err();
    assert_eq!(
        mismatch.as_ref().map(|error| error.code.as_ref()),
        Some("scripted-operation-mismatch")
    );
}

fn request(operation: EmbeddingOperation, bytes: &'static [u8]) -> HostRequest {
    HostRequest::new(EmbeddingVersion::V1, operation, Arc::from(bytes))
        .unwrap_or_else(|error| panic!("request envelope failed: {error}"))
}

fn failure(code: &'static str, protected: Option<&'static str>) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: protected.map(Arc::from),
    }
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
