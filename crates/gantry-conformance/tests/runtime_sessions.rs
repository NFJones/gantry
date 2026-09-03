//! Public conformance for owned runtime-session establishment.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use gantry::host::contracts::{
    EmbeddingVersion, HostError, HostFuture, HostRequest, HostResponse, RuntimeSessionService,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::identity::ProtocolIdentity;
use gantry::portable::IdentityKind;
use gantry::runtime::{
    AdapterPoison, CanonicalTranscriptV1, LogicalSessionRegistryV1, SessionCreationModeV1,
    SessionEstablisher, SessionEstablishmentError,
};
use gantry_conformance::concurrent_executor::{
    DeterministicConcurrentExecutor, DeterministicTaskPoll,
};
use serde::Deserialize;

const SHARING_EVIDENCE: &str = "crates/gantry-conformance/tests/runtime_sessions.rs#concurrent_runtime_session_waiters_share_one_must_settle_success";
const FAILURE_EVIDENCE: &str = "crates/gantry-conformance/tests/runtime_sessions.rs#runtime_session_failure_is_fixed_and_fanned_out_once";
const OWNED_EVIDENCE: &str = "crates/gantry-conformance/tests/runtime_sessions.rs#runtime_session_role_and_driver_future_are_send_owned";
const CANCELLATION_EVIDENCE: &str = "crates/gantry-conformance/tests/logical_sessions.rs#public_session_cancellation_after_establishment_prevents_hook_creation";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    capabilities: Vec<CapabilityEvidence>,
    exclusions: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityEvidence {
    id: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
}

#[derive(Default)]
struct PendingSessionService {
    calls: AtomicUsize,
    result: Mutex<Option<Result<HostResponse, HostError>>>,
    waiter: Mutex<Option<Waker>>,
}

impl PendingSessionService {
    fn complete(&self, result: Result<HostResponse, HostError>) {
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result);
        }
        if let Ok(mut waiter) = self.waiter.lock()
            && let Some(waiter) = waiter.take()
        {
            waiter.wake();
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl RuntimeSessionService for PendingSessionService {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::EstablishSession);
        self.calls.fetch_add(1, Ordering::AcqRel);
        Box::pin(std::future::poll_fn(move |context| {
            if let Ok(mut result) = self.result.lock()
                && let Some(result) = result.take()
            {
                return Poll::Ready(result);
            }
            if let Ok(mut waiter) = self.waiter.lock() {
                *waiter = Some(context.waker().clone());
            }
            Poll::Pending
        }))
    }
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn checked_in_runtime_session_evidence_is_narrow_and_current() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/runtime-sessions-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.runtime-session-evidence/v1");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(manifest.issue, "GNT-ASYNC-SESS-001");
    assert!(
        manifest
            .capabilities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(|entry| entry.evidence.as_str())
            .collect::<Vec<_>>(),
        [
            CANCELLATION_EVIDENCE,
            SHARING_EVIDENCE,
            FAILURE_EVIDENCE,
            OWNED_EVIDENCE,
        ]
    );
    assert_eq!(manifest.exclusions.len(), 4);
}

#[test]
fn concurrent_runtime_session_waiters_share_one_must_settle_success() {
    let (execution, session) = session_fixture(1, 2);
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let service = Arc::new(PendingSessionService::default());
    let establisher =
        SessionEstablisher::new(executor.clone(), service.clone(), AdapterPoison::default());
    let first_owner = establisher.clone();
    let second_owner = establisher.clone();
    let mut first = Box::pin(first_owner.establish(execution, &session));
    let mut second = Box::pin(second_owner.establish(execution, &session));
    let first_wakes = Arc::new(WakeCounter::default());
    let second_wakes = Arc::new(WakeCounter::default());

    assert!(poll_once(first.as_mut(), &Waker::from(first_wakes)).is_pending());
    assert!(poll_once(second.as_mut(), &Waker::from(second_wakes.clone())).is_pending());
    assert_eq!(service.calls(), 1);
    assert_eq!(executor.task_ids(), [0]);
    assert_eq!(establisher.submitted_task_count(), 1);
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));

    drop(first);
    service.complete(established_response());
    assert!(executor.is_runnable(0));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));
    assert!(second_wakes.0.load(Ordering::Acquire) > 0);
    assert_eq!(
        poll_once(second.as_mut(), Waker::noop()),
        Poll::Ready(Ok(()))
    );
    assert_eq!(block_on(establisher.establish(execution, &session)), Ok(()));
    assert_eq!(service.calls(), 1);
}

#[test]
fn runtime_session_failure_is_fixed_and_fanned_out_once() {
    let (execution, session) = session_fixture(3, 4);
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let service = Arc::new(PendingSessionService::default());
    let establisher =
        SessionEstablisher::new(executor.clone(), service.clone(), AdapterPoison::default());
    let first_owner = establisher.clone();
    let second_owner = establisher.clone();
    let mut first = Box::pin(first_owner.establish(execution, &session));
    let mut second = Box::pin(second_owner.establish(execution, &session));

    assert!(poll_once(first.as_mut(), Waker::noop()).is_pending());
    assert!(poll_once(second.as_mut(), Waker::noop()).is_pending());
    assert_eq!(service.calls(), 1);
    assert_eq!(executor.poll_task(0), Ok(DeterministicTaskPoll::Pending));
    service.complete(Err(host_error("session-provider-failure")));
    assert!(matches!(
        executor.poll_task(0),
        Ok(DeterministicTaskPoll::Settled(_))
    ));

    let expected = Err(SessionEstablishmentError::Host(host_error(
        "session-provider-failure",
    )));
    assert_eq!(
        poll_once(first.as_mut(), Waker::noop()),
        Poll::Ready(expected.clone())
    );
    assert_eq!(
        poll_once(second.as_mut(), Waker::noop()),
        Poll::Ready(expected.clone())
    );
    assert_eq!(
        block_on(establisher.establish(execution, &session)),
        expected
    );
    assert_eq!(service.calls(), 1);
}

#[test]
fn runtime_session_role_and_driver_future_are_send_owned() {
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    fn assert_send<T: Send>(_: T) {}

    assert_send_sync::<dyn RuntimeSessionService>();
    assert_send_sync::<SessionEstablisher>();

    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let service = Arc::new(PendingSessionService::default());
    let establisher = SessionEstablisher::new(executor, service, AdapterPoison::default());
    let (execution, session) = session_fixture(5, 6);
    assert_send(async move { establisher.establish(execution, &session).await });
}

fn session_fixture(
    execution_byte: u8,
    session_byte: u8,
) -> (ProtocolIdentity, gantry::runtime::LogicalSessionV1) {
    let execution = fresh(IdentityKind::Execution, execution_byte);
    let session_id = fresh(IdentityKind::Session, session_byte);
    let registry = LogicalSessionRegistryV1::new(
        execution,
        session_id,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session fixture failed: {error:?}"));
    let session = registry
        .get(session_id)
        .cloned()
        .unwrap_or_else(|| unreachable!("root session exists"));
    (execution, session)
}

fn established_response() -> Result<HostResponse, HostError> {
    HostResponse::new(
        EmbeddingVersion::V1,
        EmbeddingOperation::EstablishSession,
        Arc::from(&b"{\"result\":\"established\"}"[..]),
    )
    .map_err(|_| host_error("response-invariant"))
}

fn host_error(code: &str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
    }
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity fixture failed: {error}"))
}

fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match poll_once(future.as_mut(), Waker::noop()) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
