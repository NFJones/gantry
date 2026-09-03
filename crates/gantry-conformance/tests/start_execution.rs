//! Public-facade conformance for nondurable pre-execution coordination.

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::host::contracts::{
    EmbeddingVersion, ExecutorAdapter, FreshIdentityAllocator, HostError, HostFuture, HostRequest,
    HostResponse, IdentitySource, InclusiveJitterRange, IntegrationPreflight, UtcClock,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::identity::ProtocolIdentity;
use gantry::portable::{
    IdentityKind, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
    StartFailureCategory,
};
use gantry::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
use gantry::runtime::{InterpreterConfiguration, InterpreterLifecycle, RequiredConfiguration};
use gantry::source::FrontendLimits;
use gantry::timestamp::UtcTimestamp;
use gantry::value::ValueLimits;
use gantry::{
    AnalyzePackageCoordinator, RootSessionProvenance, RootSessionSpecification,
    StartExecutionCoordinator, StartExecutionRequest, StartExecutionResult,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &[u8]) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-start-conformance-{}-{suffix}",
            std::process::id()
        ));
        assert!(fs::create_dir(&path).is_ok());
        assert!(fs::write(path.join("main.gnt"), source).is_ok());
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Default)]
struct Services {
    next_identity: AtomicU64,
    identity_calls: Mutex<Vec<IdentityKind>>,
}

impl Services {
    fn calls(&self) -> Vec<IdentityKind> {
        self.identity_calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl IdentitySource for Services {
    fn fresh_material(&self, kind: IdentityKind) -> Result<[u8; 32], HostError> {
        self.identity_calls
            .lock()
            .map_err(|_| host_failure("identity-state"))?
            .push(kind);
        let value = self.next_identity.fetch_add(1, Ordering::Relaxed) + 1;
        let mut material = [0_u8; 32];
        material[..8].copy_from_slice(&value.to_be_bytes());
        Ok(material)
    }
}

impl ExecutorAdapter for Services {
    fn spawn(
        &self,
        task: gantry::host::contracts::OwnedTaskFuture,
    ) -> Result<Box<dyn gantry::host::contracts::SubmittedTask>, HostError> {
        gantry::host::contracts::reject_task_submission(task)
    }

    fn sleep<'a>(
        &'a self,
        _duration: gantry::host::contracts::DurationMicros,
    ) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

struct FixedClock;

impl UtcClock for FixedClock {
    fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
        Box::pin(async {
            UtcTimestamp::from_unix_seconds(0, 1).map_err(|_| host_failure("clock-invariant"))
        })
    }
}

#[derive(Clone, Debug)]
struct PreflightCall {
    operation: EmbeddingOperation,
    request: Vec<u8>,
    identity_calls: Vec<IdentityKind>,
}

struct RecordingPreflight {
    services: Arc<Services>,
    calls: Mutex<Vec<PreflightCall>>,
    failure: Option<&'static str>,
    malformed_mapping: bool,
}

impl RecordingPreflight {
    fn resolved(services: Arc<Services>) -> Self {
        Self {
            services,
            calls: Mutex::new(Vec::new()),
            failure: None,
            malformed_mapping: false,
        }
    }

    fn failing(services: Arc<Services>, code: &'static str) -> Self {
        Self {
            services,
            calls: Mutex::new(Vec::new()),
            failure: Some(code),
            malformed_mapping: false,
        }
    }

    fn malformed_mapping(services: Arc<Services>) -> Self {
        Self {
            services,
            calls: Mutex::new(Vec::new()),
            failure: None,
            malformed_mapping: true,
        }
    }

    fn calls(&self) -> Vec<PreflightCall> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl IntegrationPreflight for RecordingPreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        let operation = request.operation();
        let call = PreflightCall {
            operation,
            request: request.canonical_bytes().to_vec(),
            identity_calls: self.services.calls(),
        };
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
        let failure = self.failure;
        let malformed_mapping = self.malformed_mapping;
        Box::pin(async move {
            if let Some(code) = failure {
                return Err(host_failure(code));
            }
            let bytes = if operation == EmbeddingOperation::ResolveMappings && malformed_mapping {
                &b"{\"result\":\"resolved\"}"[..]
            } else if operation == EmbeddingOperation::ResolveMappings {
                &b"{\"action_mapping_revision\":\"actions-v1\",\"agent_mapping_revision\":\"agents-v1\",\"result\":\"resolved\"}"[..]
            } else {
                &b"{\"result\":\"resolved\"}"[..]
            };
            HostResponse::new(EmbeddingVersion::V1, operation, Arc::from(bytes))
                .map_err(|_| host_failure("response-invariant"))
        })
    }
}

#[test]
fn syntax_and_analysis_rejections_cross_no_preflight_or_execution_boundary() {
    for (source, category, expected_identities) in [
        (
            &b"fn main( {"[..],
            StartFailureCategory::Syntax,
            vec![IdentityKind::Activity, IdentityKind::Event],
        ),
        (
            &b"fn main() -> Int { \"wrong\" }"[..],
            StartFailureCategory::Analysis,
            vec![
                IdentityKind::Activity,
                IdentityKind::Event,
                IdentityKind::Event,
            ],
        ),
    ] {
        let root = TempDirectory::new(source);
        let services = Arc::new(Services::default());
        let configuration = configuration(Arc::clone(&services));
        let lifecycle = InterpreterLifecycle::new(&configuration);
        let allocator = FreshIdentityAllocator::default();
        let clock = FixedClock;
        let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
        let preflight = RecordingPreflight::resolved(Arc::clone(&services));
        let coordinator = StartExecutionCoordinator::new(
            &package,
            &lifecycle,
            &configuration,
            &allocator,
            &preflight,
        );
        let selection = selection();

        let result = block_on(coordinator.start(request(&root.0, &selection, None, None)));
        let StartExecutionResult::Rejected(failure) = result else {
            panic!("invalid source was accepted");
        };
        assert_eq!(failure.category, category);
        assert!(failure.package_activity.is_some());
        assert!(preflight.calls().is_empty());
        assert_eq!(services.calls(), expected_identities);
    }
}

#[test]
fn constructed_type_depth_rejects_start_before_preflight_or_execution_identity() {
    let root = TempDirectory::new(b"fn main(value: Option<Option<Int>>) {}");
    let services = Arc::new(Services::default());
    let configuration = configuration_with_type_depth(Arc::clone(&services), 2);
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock;
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let preflight = RecordingPreflight::resolved(Arc::clone(&services));
    let coordinator = StartExecutionCoordinator::new(
        &package,
        &lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let selection = selection();

    let result = block_on(coordinator.start(request(&root.0, &selection, None, None)));
    let StartExecutionResult::Rejected(failure) = result else {
        panic!("over-depth source was accepted");
    };
    assert_eq!(
        failure.category,
        StartFailureCategory::FrontendResourceLimit
    );
    assert_eq!(&*failure.code, "frontend-resource-limit");
    assert!(failure.package_activity.is_none());
    assert!(preflight.calls().is_empty());
    assert_eq!(services.calls(), [IdentityKind::Activity]);
}

#[test]
fn mapping_and_root_preflight_precede_identity_and_accept_normalized_entry() {
    let root = TempDirectory::new(
        br#"
agents { worker }
default agent = worker;
struct Input { count: Int, empty: Option<Bool>, note: Option<String> = "fallback" }
action read_only inspect(value: Input) -> Result<String, Input>;
fn main(value: Input) -> Input { value }
"#,
    );
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock;
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let preflight = RecordingPreflight::resolved(Arc::clone(&services));
    let coordinator = StartExecutionCoordinator::new(
        &package,
        &lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let selection = selection();
    let session_id = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0xf0; 32])
        .unwrap_or_else(|error| panic!("session identity failed: {error}"));
    let root_session = RootSessionSpecification {
        id: session_id,
        transcript: Some(b"{\"protocol\":{\"major\":1,\"minor\":0},\"turns\":[]}"),
        opaque_lookup_material: Some(b"lookup"),
    };

    let result = block_on(coordinator.start(request(
        &root.0,
        &selection,
        Some(br#"{"count":1e0}"#),
        Some(root_session),
    )));
    let StartExecutionResult::Accepted(accepted) = result else {
        panic!("valid start was rejected");
    };
    let entry = accepted
        .entry_input
        .as_ref()
        .unwrap_or_else(|| panic!("normalized entry input was absent"));
    assert_eq!(
        entry.canonical_json.bytes(),
        br#"{"count":1,"empty":null,"note":"fallback"}"#
    );
    assert_eq!(accepted.root_session.id, session_id);
    assert_eq!(
        accepted.root_session.provenance,
        RootSessionProvenance::EmbedderSupplied
    );
    assert_eq!(accepted.execution_id.kind(), IdentityKind::Execution);
    assert_eq!(accepted.handle.execution_id(), accepted.execution_id);
    assert_eq!(
        accepted
            .mapping_revisions
            .agent
            .as_ref()
            .map(|revision| revision.as_str()),
        Some("agents-v1")
    );
    assert_eq!(
        accepted
            .mapping_revisions
            .action
            .as_ref()
            .map(|revision| revision.as_str()),
        Some("actions-v1")
    );
    assert!(
        lifecycle
            .query_execution(accepted.execution_id)
            .is_ok_and(|value| value.is_some())
    );

    let preflight_calls = preflight.calls();
    assert_eq!(preflight_calls.len(), 2);
    assert_eq!(
        preflight_calls
            .iter()
            .map(|call| call.operation)
            .collect::<Vec<_>>(),
        [
            EmbeddingOperation::ResolveMappings,
            EmbeddingOperation::ResolveSessions,
        ]
    );
    assert!(
        preflight_calls[0]
            .request
            .starts_with(b"{\"action_signatures\":")
    );
    assert!(
        preflight_calls[0]
            .request
            .windows(8)
            .any(|bytes| bytes == b"\"worker\"")
    );
    assert!(
        preflight_calls[1]
            .request
            .starts_with(b"{\"session_descriptors\":[{")
    );
    assert!(preflight_calls.iter().all(|call| {
        call.identity_calls
            == [
                IdentityKind::Activity,
                IdentityKind::Event,
                IdentityKind::Event,
            ]
    }));
    assert_eq!(
        services.calls(),
        [
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::Event,
            IdentityKind::Execution,
        ]
    );
}

#[test]
fn preflight_failure_allocates_no_root_or_execution_identity() {
    let root = TempDirectory::new(
        b"agents { worker } default agent = worker; fn main() { with worker {} }",
    );
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock;
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let preflight = RecordingPreflight::failing(Arc::clone(&services), "mapping-provider-failure");
    let coordinator = StartExecutionCoordinator::new(
        &package,
        &lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let selection = selection();

    let result = block_on(coordinator.start(request(&root.0, &selection, None, None)));
    let StartExecutionResult::Rejected(failure) = result else {
        panic!("failed preflight was accepted");
    };
    assert_eq!(failure.category, StartFailureCategory::IntegrationPreflight);
    assert_eq!(&*failure.code, "mapping-provider-failure");
    assert_eq!(preflight.calls().len(), 1);
    assert_eq!(
        services.calls(),
        [
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::Event,
        ]
    );
}

#[test]
fn malformed_mapping_revision_response_rejects_before_execution_identity() {
    let root = TempDirectory::new(
        b"agents { worker } default agent = worker; fn main() { with worker {} }",
    );
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let allocator = FreshIdentityAllocator::default();
    let clock = FixedClock;
    let package = AnalyzePackageCoordinator::new(&allocator, services.as_ref(), &clock);
    let preflight = RecordingPreflight::malformed_mapping(Arc::clone(&services));
    let coordinator = StartExecutionCoordinator::new(
        &package,
        &lifecycle,
        &configuration,
        &allocator,
        &preflight,
    );
    let selection = selection();

    let result = block_on(coordinator.start(request(&root.0, &selection, None, None)));
    let StartExecutionResult::Rejected(failure) = result else {
        panic!("malformed mapping response was accepted");
    };
    assert_eq!(failure.category, StartFailureCategory::IntegrationPreflight);
    assert_eq!(&*failure.code, "invalid-preflight-response");
    assert_eq!(preflight.calls().len(), 1);
    assert_eq!(
        services.calls(),
        [
            IdentityKind::Activity,
            IdentityKind::Event,
            IdentityKind::Event,
        ]
    );
}

fn request<'a>(
    package_root: &'a std::path::Path,
    protocol_selection: &'a ProtocolSelection,
    entry_input: Option<&'a [u8]>,
    root_session: Option<RootSessionSpecification<'a>>,
) -> StartExecutionRequest<'a> {
    StartExecutionRequest {
        package_root,
        protocol_selection,
        required_peers: &[],
        entry_input,
        root_session,
        event_delivery: None,
    }
}

fn configuration(services: Arc<Services>) -> InterpreterConfiguration {
    configuration_with_type_depth(services, 256)
}

fn configuration_with_type_depth(
    services: Arc<Services>,
    maximum_constructed_type_depth: u64,
) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            32,
            1_048_576,
            4_194_304,
            262_144,
            256,
            4_194_304,
            4_194_304,
            4_194_304,
            4_194_304,
            maximum_constructed_type_depth,
            65_536,
            1_000_000,
        )
        .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_048_576,
        1_048_576,
        ValueLimits::new(128, 262_144, 262_144, 65_536)
            .unwrap_or_else(|| panic!("value limits failed")),
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .unwrap_or_else(|error| panic!("required configuration failed: {error}"));
    InterpreterConfiguration::new(services.clone(), services, required)
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
    .unwrap_or_else(|error| panic!("published selection failed: {error:?}"))
}

fn host_failure(code: &str) -> HostError {
    HostError {
        code: Arc::from(code),
        protected_diagnostic: None,
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
