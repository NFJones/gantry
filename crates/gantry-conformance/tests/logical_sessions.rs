//! Public-facade conformance for logical sessions and canonical transcripts.

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::canonical_json::CanonicalJson;
use gantry::host::contracts::{
    AgentMappingRevision, CancellationSignal, CancellationToken, DurationMicros, EmbeddingVersion,
    ExecutorAdapter, FreshIdentityAllocator, HookFactory, HookOutcomeV1, HostError, HostFuture,
    HostRequest, HostResponse, IdentitySource, InclusiveJitterRange, IntegrationPreflight,
    OperationHook,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::OperationSiteKind;
use gantry::ir::{CanonicalPath, EffectSet, StructuralPosition, TypeDescriptor};
use gantry::portable::{IdentityKind, OperationStateKind};
use gantry::runtime::{
    AcceptedTranscriptResultV1, AdapterPoison, CanonicalTranscriptV1, CapturedOperationRequestV1,
    Instruction, InstructionKind, InterpreterConfiguration, InterpreterLifecycle,
    LogicalSessionRegistryV1, Machine, MachineLabel, MachineLimits, MachineProgram, MachineStatus,
    MachineStep, ModelOperationRequestV1, ModelSessionUseV1, OperationLifecycle,
    OperationLifecycleError, OperationRequestHeaderV1, OperationRetryPolicyV1,
    ProcessedHookOutcomeV1, RequiredConfiguration, RootSessionProvenanceV1, SessionCreationModeV1,
    SessionEstablisher, SessionEstablishmentError, SessionEstablishmentV1, TaskContextV1, TaskHook,
    TaskHookSessionError, TaskSessionContextV1, TranscriptError, TranscriptResultKindV1,
    TranscriptTurnV1, Workflow,
};
use gantry::source::FrontendLimits;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, ValueLimits};

#[derive(Default)]
struct Services {
    next: AtomicUsize,
}

impl IdentitySource for Services {
    fn fresh_material(&self, _: IdentityKind) -> Result<[u8; 32], HostError> {
        let value = self.next.fetch_add(1, Ordering::AcqRel) + 1;
        let mut material = [0_u8; 32];
        material[..8].copy_from_slice(&value.to_be_bytes());
        Ok(material)
    }
}

impl ExecutorAdapter for Services {
    fn sleep<'a>(&'a self, _: DurationMicros) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn yield_now<'a>(&'a self) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async { Ok(()) })
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        Ok(range.minimum())
    }
}

struct OrderedPreflight {
    order: Arc<Mutex<Vec<&'static str>>>,
    fail: bool,
}

impl IntegrationPreflight for OrderedPreflight {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::EstablishSession);
        if let Ok(mut order) = self.order.lock() {
            order.push("establish-session");
        }
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                return Err(host_error("session-provider-failure"));
            }
            HostResponse::new(
                EmbeddingVersion::V1,
                EmbeddingOperation::EstablishSession,
                Arc::from(&b"{\"result\":\"established\"}"[..]),
            )
            .map_err(|_| host_error("response-invariant"))
        })
    }
}

struct OrderedFactory {
    order: Arc<Mutex<Vec<&'static str>>>,
    creations: AtomicUsize,
}

impl HookFactory for OrderedFactory {
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::CreateHook);
        self.creations.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut order) = self.order.lock() {
            order.push("create-hook");
        }
        let order = Arc::clone(&self.order);
        Box::pin(async move { Ok(Box::new(OrderedHook { order }) as Box<dyn OperationHook>) })
    }
}

struct OrderedHook {
    order: Arc<Mutex<Vec<&'static str>>>,
}

impl OperationHook for OrderedHook {
    fn dispatch<'a>(
        &'a mut self,
        request: HostRequest,
        _: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        assert_eq!(request.operation(), EmbeddingOperation::DispatchOperation);
        if let Ok(mut order) = self.order.lock() {
            order.push("dispatch-operation");
        }
        Box::pin(async { Ok(HookOutcomeV1::Completed(Arc::from(&b"\"ok\""[..]))) })
    }
}

#[test]
fn public_transcripts_are_versioned_closed_canonical_and_atomic() {
    let mut transcript = CanonicalTranscriptV1::empty();
    assert_eq!(
        transcript.bytes(),
        br#"{"protocol":{"major":1,"minor":0},"turns":[]}"#
    );
    transcript
        .append(&turn("hello"), DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("transcript append failed: {error:?}"));
    assert_canonical(transcript.bytes());
    assert_contains(
        transcript.bytes(),
        &[
            "\"operation_kind\":\"prompt\"",
            "\"selected_agent\":\"worker\"",
        ],
    );

    let before = transcript.clone();
    let tiny =
        ValueLimits::new(32, 256, 2, 16).unwrap_or_else(|| panic!("tiny limits were not positive"));
    assert_eq!(
        transcript.append(&turn("too long"), tiny),
        Err(TranscriptError::Limit)
    );
    assert_eq!(transcript, before);

    assert_eq!(
        CanonicalTranscriptV1::decode(
            br#"{"extra":true,"protocol":{"major":1,"minor":0},"turns":[]}"#,
            DEFAULT_VALUE_LIMITS,
        ),
        Err(TranscriptError::Invalid)
    );
}

#[test]
fn public_new_and_fork_sessions_replay_identity_and_snapshot_creation_state() {
    let execution = fresh(IdentityKind::Execution, 1);
    let root = fresh(IdentityKind::Session, 2);
    let task = derived(IdentityKind::Task, b"task");
    let mut registry = LogicalSessionRegistryV1::new(
        execution,
        root,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    registry
        .get_mut(root)
        .unwrap_or_else(|| panic!("root session was absent"))
        .transcript
        .append(&turn("before fork"), DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("root append failed: {error:?}"));
    let site = StructuralPosition::new(vec![4, 2])
        .unwrap_or_else(|error| panic!("session site failed: {error}"));
    let fork = registry
        .create(
            root,
            task,
            site.clone(),
            0,
            SessionCreationModeV1::Fork,
            SessionEstablishmentV1::Separate,
        )
        .unwrap_or_else(|error| panic!("fork creation failed: {error:?}"))
        .clone();
    let replay = registry
        .create(
            root,
            task,
            site.clone(),
            0,
            SessionCreationModeV1::Fork,
            SessionEstablishmentV1::Separate,
        )
        .unwrap_or_else(|error| panic!("fork replay failed: {error:?}"))
        .clone();
    assert_eq!(fork.id, replay.id);
    assert_eq!(fork.transcript, replay.transcript);

    registry
        .get_mut(root)
        .unwrap_or_else(|| panic!("root session was absent"))
        .transcript
        .append(&turn("after fork"), DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("second root append failed: {error:?}"));
    assert_ne!(
        fork.transcript,
        registry
            .get(root)
            .unwrap_or_else(|| panic!("root session was absent"))
            .transcript
    );

    let new = registry
        .create(
            root,
            task,
            site,
            1,
            SessionCreationModeV1::New,
            SessionEstablishmentV1::OperationRequest,
        )
        .unwrap_or_else(|error| panic!("new session failed: {error:?}"));
    assert_eq!(new.transcript, CanonicalTranscriptV1::empty());
    assert_ne!(new.id, fork.id);
}

#[test]
fn public_session_establishment_is_idempotent_and_precedes_hook_creation() {
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let execution = fresh(IdentityKind::Execution, 9);
    let root = fresh(IdentityKind::Session, 8);
    let registry = LogicalSessionRegistryV1::new(
        execution,
        root,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let session = registry
        .get(root)
        .unwrap_or_else(|| panic!("root session was absent"));
    let order = Arc::new(Mutex::new(Vec::new()));
    let preflight = OrderedPreflight {
        order: Arc::clone(&order),
        fail: false,
    };
    let factory = OrderedFactory {
        order: Arc::clone(&order),
        creations: AtomicUsize::new(0),
    };
    let mut establisher = SessionEstablisher::new(&lifecycle, &preflight, AdapterPoison::default());
    let mut hook = TaskHook::new(
        &lifecycle,
        &factory,
        AdapterPoison::default(),
        task_context(execution, root),
    )
    .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
    let captured = model_request(
        execution,
        derived(IdentityKind::Operation, b"operation"),
        session,
    );
    let allocator = FreshIdentityAllocator::default();
    for expected_dispatches in 1..=2 {
        let prepared = captured
            .prepare_dispatch(&allocator, services.as_ref(), 0, 0, &[])
            .unwrap_or_else(|error| panic!("model dispatch failed: {error:?}"));
        assert!(
            block_on(hook.dispatch_model(
                prepared.request,
                &CancellationSignal::default(),
                &mut establisher,
                execution,
                session,
            ))
            .is_ok()
        );
        assert_eq!(factory.creations.load(Ordering::Acquire), 1);
        let observed = order.lock().map(|order| order.clone()).unwrap_or_default();
        assert_eq!(
            observed
                .iter()
                .filter(|entry| **entry == "dispatch-operation")
                .count(),
            expected_dispatches
        );
    }
    assert_eq!(
        order.lock().map(|order| order.clone()).unwrap_or_default(),
        [
            "establish-session",
            "create-hook",
            "dispatch-operation",
            "dispatch-operation",
        ]
    );

    let failed_order = Arc::new(Mutex::new(Vec::new()));
    let failed_preflight = OrderedPreflight {
        order: Arc::clone(&failed_order),
        fail: true,
    };
    let failed_factory = OrderedFactory {
        order: Arc::clone(&failed_order),
        creations: AtomicUsize::new(0),
    };
    let mut failed_establisher =
        SessionEstablisher::new(&lifecycle, &failed_preflight, AdapterPoison::default());
    let mut failed_hook = TaskHook::new(
        &lifecycle,
        &failed_factory,
        AdapterPoison::default(),
        task_context(execution, root),
    )
    .unwrap_or_else(|error| panic!("failed task hook construction failed: {error:?}"));
    let prepared = captured
        .prepare_dispatch(&allocator, services.as_ref(), 0, 0, &[])
        .unwrap_or_else(|error| panic!("failed model dispatch preparation failed: {error:?}"));
    assert!(matches!(
        block_on(failed_hook.dispatch_model(
            prepared.request,
            &CancellationSignal::default(),
            &mut failed_establisher,
            execution,
            session,
        )),
        Err(TaskHookSessionError::Session(SessionEstablishmentError::Host(ref error)))
            if error.code.as_ref() == "session-provider-failure"
    ));
    assert_eq!(failed_factory.creations.load(Ordering::Acquire), 0);
    assert_eq!(
        failed_order
            .lock()
            .map(|order| order.clone())
            .unwrap_or_default(),
        ["establish-session"]
    );
}

#[test]
fn public_model_acceptance_appends_atomically_after_machine_acceptance() {
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let lifecycle = InterpreterLifecycle::new(&configuration);
    let execution = fresh(IdentityKind::Execution, 9);
    let root = fresh(IdentityKind::Session, 8);
    let mut registry = LogicalSessionRegistryV1::new(
        execution,
        root,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let session_snapshot = registry
        .get(root)
        .unwrap_or_else(|| panic!("root session was absent"))
        .clone();
    let (mut machine, occurrence) = machine_with_string_operation(execution);
    let captured = model_request(execution, occurrence.identity, &session_snapshot);
    let mut operation = OperationLifecycle::new(captured)
        .unwrap_or_else(|error| panic!("operation lifecycle failed: {error:?}"));
    operation
        .prepare(
            &FreshIdentityAllocator::default(),
            services.as_ref(),
            0,
            0,
            &[],
        )
        .unwrap_or_else(|error| panic!("operation preparation failed: {error:?}"));
    let order = Arc::new(Mutex::new(Vec::new()));
    let factory = OrderedFactory {
        order,
        creations: AtomicUsize::new(0),
    };
    let mut hook = TaskHook::new(
        &lifecycle,
        &factory,
        AdapterPoison::default(),
        task_context(execution, root),
    )
    .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
    let cancellation = CancellationSignal::default();
    assert!(block_on(operation.dispatch(&mut hook, &cancellation)).is_ok());
    let policy = OperationRetryPolicyV1::for_request(
        operation.captured(),
        configuration.retry_defaults(),
        None,
    )
    .unwrap_or_else(|error| panic!("retry policy failed: {error:?}"));
    assert!(matches!(
        operation.process_outcome(policy, services.as_ref(), &cancellation),
        Ok(ProcessedHookOutcomeV1::Accepted(_))
    ));
    let session = registry
        .get_mut(root)
        .unwrap_or_else(|| panic!("root session was absent"));
    let before = session.transcript.clone();
    let value = LogicalValue::string("ok", DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("result value failed: {error:?}"));
    let tiny =
        ValueLimits::new(32, 256, 2, 16).unwrap_or_else(|| panic!("tiny limits were not positive"));
    assert_eq!(
        operation.accept_model(&mut machine, session, &turn("prompt"), tiny, value.clone()),
        Err(OperationLifecycleError::Transcript(TranscriptError::Limit))
    );
    assert_eq!(session.transcript, before);
    assert_eq!(operation.state().kind(), OperationStateKind::Outcome);
    assert_eq!(machine.status(), MachineStatus::WaitingOperation);

    assert!(matches!(
        operation.accept_model(
            &mut machine,
            session,
            &turn("prompt"),
            DEFAULT_VALUE_LIMITS,
            value,
        ),
        Ok(MachineLabel::OperationResult { operation }) if operation == occurrence.identity
    ));
    assert_ne!(session.transcript, before);
    assert_eq!(operation.state().kind(), OperationStateKind::Accepted);
}

fn model_request(
    execution_id: ProtocolIdentity,
    operation_id: ProtocolIdentity,
    session: &gantry::runtime::LogicalSessionV1,
) -> CapturedOperationRequestV1 {
    CapturedOperationRequestV1::Model {
        header: OperationRequestHeaderV1 {
            execution_id,
            task_id: derived(IdentityKind::Task, b"root-task"),
            operation_id,
            kind: OperationSiteKind::Prompt,
            expected_type: TypeDescriptor::STRING,
            expected_schema: Arc::from(&br#"{"type":"string"}"#[..]),
            maximum_hook_output_bytes: 1_024,
            value_limits: DEFAULT_VALUE_LIMITS,
            workflow: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("workflow path failed: {error}")),
            site: StructuralPosition::new(vec![0])
                .unwrap_or_else(|error| panic!("operation site failed: {error}")),
        },
        body: Box::new(ModelOperationRequestV1 {
            selected_agent: Arc::from("worker"),
            mapping_revision: AgentMappingRevision::new("agents-v1")
                .unwrap_or_else(|error| panic!("mapping revision failed: {error:?}")),
            template_segments: vec![Arc::from("prompt")],
            rendered_prompt: Arc::from("prompt"),
            interpolation_inputs: Vec::new(),
            named_inputs: Vec::new(),
            transcript: session.transcript.clone(),
            active_session_id: session.id,
            parent_session_id: session.parent,
            root_session_id: session.root,
            session_use: ModelSessionUseV1::Inline,
        }),
    }
}

fn task_context(execution_id: ProtocolIdentity, root_session_id: ProtocolIdentity) -> HostRequest {
    TaskContextV1 {
        execution_id,
        task_id: derived(IdentityKind::Task, b"root-task"),
        inherited_agent: Some(Arc::from("worker")),
        session: TaskSessionContextV1::Root {
            root_session_id,
            provenance: RootSessionProvenanceV1::GantryCreated,
        },
    }
    .into_host_request()
    .unwrap_or_else(|error| panic!("task context failed: {error:?}"))
}

fn machine_with_string_operation(
    execution: ProtocolIdentity,
) -> (Machine, gantry::runtime::OperationOccurrence) {
    let root = CanonicalPath::new("crate::main")
        .unwrap_or_else(|error| panic!("root path failed: {error}"));
    let program = MachineProgram::new(vec![Workflow {
        path: root.clone(),
        parameters: Vec::new(),
        result: TypeDescriptor::STRING,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("operation site failed: {error}")),
                ty: TypeDescriptor::STRING,
                kind: InstructionKind::Operation,
            },
            Instruction {
                site: StructuralPosition::new(vec![1])
                    .unwrap_or_else(|error| panic!("return site failed: {error}")),
                ty: TypeDescriptor::STRING,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("program failed: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("machine limits failed"));
    let mut machine = Machine::new(Arc::new(program), &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine failed: {error:?}"));
    let occurrence = match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(occurrence)) => occurrence,
        other => panic!("unexpected machine step: {other:?}"),
    };
    (machine, occurrence)
}

fn turn(prompt: &str) -> TranscriptTurnV1 {
    TranscriptTurnV1 {
        operation_kind: OperationSiteKind::Prompt,
        template_representation: vec![Arc::from("prompt")],
        rendered_prompt: Arc::from(prompt),
        interpolation_inputs: Vec::new(),
        using_inputs: Vec::new(),
        selected_agent: Arc::from("worker"),
        accepted_result: AcceptedTranscriptResultV1 {
            kind: TranscriptResultKindV1::Value,
            ty: TypeDescriptor::STRING,
            value: canonical(br#""ok""#),
        },
    }
}

fn configuration(services: Arc<Services>) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(8, 1_024, 4_096, 1_024, 32, 4_096, 4_096, 4_096, 4_096)
            .unwrap_or_else(|error| panic!("frontend limits failed: {error:?}")),
        1_024,
        1_024,
        DEFAULT_VALUE_LIMITS,
        1_024,
        128,
        128,
        64,
    )
    .unwrap_or_else(|error| panic!("configuration failed: {error}"));
    InterpreterConfiguration::new(services.clone(), services, required)
}

fn canonical(bytes: &[u8]) -> CanonicalJson {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes: length,
            maximum_nesting_depth: length.max(1),
            maximum_nodes: length.max(1),
            maximum_string_scalars: length.max(1),
            maximum_list_items: length.max(1),
        },
    )
    .unwrap_or_else(|error| panic!("strict JSON failed: {error:?}"));
    CanonicalJson::from_document(&document)
        .unwrap_or_else(|error| panic!("canonical JSON failed: {error:?}"))
}

fn assert_canonical(bytes: &[u8]) {
    assert_eq!(canonical(bytes).bytes(), bytes);
}

fn assert_contains(bytes: &[u8], expected: &[&str]) {
    let text =
        std::str::from_utf8(bytes).unwrap_or_else(|error| panic!("request was not UTF-8: {error}"));
    for value in expected {
        assert!(text.contains(value), "missing transcript field: {value}");
    }
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("fresh identity failed: {error}"))
}

fn derived(kind: IdentityKind, key: &[u8]) -> ProtocolIdentity {
    ProtocolIdentity::derive(kind, key)
        .unwrap_or_else(|error| panic!("derived identity failed: {error}"))
}

fn host_error(code: &str) -> HostError {
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
