//! Public-facade conformance for mapping, hook, and operation boundaries.

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use gantry::canonical_json::CanonicalJson;
use gantry::host::contracts::{
    ActionMappingRevision, AgentMappingRevision, CancellationSignal, CancellationToken,
    DurationMicros, ExecutorAdapter, FreshIdentityAllocator, HookFactory, HookOutcomeV1, HostError,
    HostFuture, HostRequest, IdentitySource, InclusiveJitterRange, OperationHook,
};
use gantry::host::embedding::EmbeddingOperation;
use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, EffectSet, StructuralPosition, TypeDescriptor,
};
use gantry::portable::{IdentityKind, OperationStateKind};
use gantry::runtime::{
    ActionOperationRequestV1, AdapterPoison, CanonicalTranscriptV1, CapturedOperationRequestV1,
    Instruction, InstructionKind, InterpolationInputV1, InterpreterConfiguration,
    InterpreterLifecycle, Machine, MachineLabel, MachineLimits, MachineProgram, MachineStatus,
    MachineStep, ModelOperationRequestV1, ModelSessionUseV1, NamedInputV1, OperationLifecycle,
    OperationLifecycleError, OperationRequestHeaderV1, OperationRetryPolicyV1,
    ProcessedHookOutcomeV1, RequiredConfiguration, RootSessionProvenanceV1, TaskContextV1,
    TaskHook, TaskHookError, TaskSessionContextV1, TypedActionArgumentV1, Workflow,
};
use gantry::source::FrontendLimits;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};

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
    fn spawn(
        &self,
        task: gantry::host::contracts::OwnedTaskFuture,
    ) -> Result<Box<dyn gantry::host::contracts::SubmittedTask>, HostError> {
        gantry::host::contracts::reject_task_submission(task)
    }

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

#[derive(Default)]
struct RecordingFactory {
    creations: AtomicUsize,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl HookFactory for RecordingFactory {
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        self.creations.fetch_add(1, Ordering::AcqRel);
        let requests = Arc::clone(&self.requests);
        if let Ok(mut recorded) = requests.lock() {
            recorded.push(request.canonical_bytes().to_vec());
        }
        Box::pin(async move { Ok(Box::new(RecordingHook { requests }) as Box<dyn OperationHook>) })
    }
}

struct RecordingHook {
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl OperationHook for RecordingHook {
    fn dispatch<'a>(
        &'a mut self,
        request: HostRequest,
        _: &'a dyn CancellationToken,
    ) -> HostFuture<'a, Result<HookOutcomeV1, HostError>> {
        if let Ok(mut recorded) = self.requests.lock() {
            recorded.push(request.canonical_bytes().to_vec());
        }
        Box::pin(async { Ok(HookOutcomeV1::Completed(Arc::from(&b"null"[..]))) })
    }
}

struct FailingFactory;

impl HookFactory for FailingFactory {
    fn create_hook<'a>(
        &'a self,
        _: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        Box::pin(async { Err(host_error("hook-provider-failure")) })
    }
}

#[test]
fn public_hook_requests_are_canonical_typed_and_exclude_forbidden_fields() {
    let task_context = TaskContextV1 {
        execution_id: fresh(IdentityKind::Execution, 1),
        task_id: derived(IdentityKind::Task, b"root-task"),
        inherited_agent: Some(Arc::from("worker")),
        session: TaskSessionContextV1::Root {
            root_session_id: fresh(IdentityKind::Session, 2),
            provenance: RootSessionProvenanceV1::EmbedderSupplied,
        },
    }
    .into_host_request()
    .unwrap_or_else(|error| panic!("task context failed: {error:?}"));
    assert_eq!(task_context.operation(), EmbeddingOperation::CreateHook);
    assert_canonical(task_context.canonical_bytes());
    assert_excludes(
        task_context.canonical_bytes(),
        &["workflow", "branch", "parent_task", "source", "ancestry"],
    );

    let allocator = FreshIdentityAllocator::default();
    let services = Services::default();
    let action = action_request();
    let first = action
        .prepare_dispatch(&allocator, &services, 0, 0, &[])
        .unwrap_or_else(|error| panic!("action dispatch failed: {error:?}"));
    let second = action
        .prepare_dispatch(&allocator, &services, 0, 0, &[])
        .unwrap_or_else(|error| panic!("action redispatch failed: {error:?}"));
    assert_ne!(first.dispatch_id, second.dispatch_id);
    assert_canonical(first.request.canonical_bytes());
    assert_contains(
        first.request.canonical_bytes(),
        &[
            "\"action_mapping_revision\":\"actions-v1\"",
            "\"recovery_class\":\"read_only\"",
        ],
    );
    assert_excludes(
        first.request.canonical_bytes(),
        &[
            "selected_agent",
            "session_use",
            "source",
            "provider_history",
        ],
    );

    let model = model_request();
    let model_dispatch = model
        .prepare_dispatch(&allocator, &services, 0, 0, &[])
        .unwrap_or_else(|error| panic!("model dispatch failed: {error:?}"));
    assert_canonical(model_dispatch.request.canonical_bytes());
    assert_contains(
        model_dispatch.request.canonical_bytes(),
        &[
            "\"agent_mapping_revision\":\"agents-v1\"",
            "\"selected_agent\":\"worker\"",
            "\"session_use\":{\"kind\":\"inline\"}",
        ],
    );
    assert_excludes(
        model_dispatch.request.canonical_bytes(),
        &[
            "canonical_path",
            "canonical_signature",
            "recovery_class",
            "source",
        ],
    );
}

#[test]
fn public_operation_lifecycle_is_lazy_serial_and_single_consumption() {
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let interpreter = InterpreterLifecycle::new(&configuration);
    let factory = RecordingFactory::default();
    let create_request = TaskContextV1 {
        execution_id: fresh(IdentityKind::Execution, 9),
        task_id: derived(IdentityKind::Task, b"root-task"),
        inherited_agent: None,
        session: TaskSessionContextV1::Root {
            root_session_id: fresh(IdentityKind::Session, 8),
            provenance: RootSessionProvenanceV1::GantryCreated,
        },
    }
    .into_host_request()
    .unwrap_or_else(|error| panic!("task context failed: {error:?}"));
    let mut hook = TaskHook::new(
        &interpreter,
        &factory,
        AdapterPoison::default(),
        create_request,
    )
    .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
    let (mut machine, occurrence) = machine_with_operation();
    let mut operation = operation_for(&occurrence);

    assert_eq!(operation.state().kind(), OperationStateKind::Absent);
    let dispatch_id = operation
        .prepare(
            &FreshIdentityAllocator::default(),
            services.as_ref(),
            0,
            0,
            &[],
        )
        .unwrap_or_else(|error| panic!("preparation failed: {error:?}"));
    assert_eq!(dispatch_id.kind(), IdentityKind::Dispatch);
    assert_eq!(operation.state().kind(), OperationStateKind::Prepared);
    assert_eq!(factory.creations.load(Ordering::Acquire), 0);

    let cancellation = CancellationSignal::default();
    assert!(block_on(operation.dispatch(&mut hook, &cancellation)).is_ok());
    assert_eq!(operation.state().kind(), OperationStateKind::Outcome);
    assert_eq!(factory.creations.load(Ordering::Acquire), 1);
    assert_eq!(
        factory.requests.lock().map_or(0, |requests| requests.len()),
        2
    );
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
    assert!(matches!(
        operation.accept(&mut machine, LogicalValue::unit()),
        Ok(MachineLabel::OperationResult { operation }) if operation == occurrence.identity
    ));
    assert_eq!(operation.state().kind(), OperationStateKind::Accepted);
    assert!(matches!(
        operation.accept(&mut machine, LogicalValue::unit()),
        Err(OperationLifecycleError::InvalidState {
            actual: OperationStateKind::Accepted,
        })
    ));
}

#[test]
fn public_cancellation_after_outcome_prevents_source_consumption() {
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let interpreter = InterpreterLifecycle::new(&configuration);
    let factory = RecordingFactory::default();
    let create_request = TaskContextV1 {
        execution_id: fresh(IdentityKind::Execution, 9),
        task_id: derived(IdentityKind::Task, b"root-task"),
        inherited_agent: None,
        session: TaskSessionContextV1::Root {
            root_session_id: fresh(IdentityKind::Session, 8),
            provenance: RootSessionProvenanceV1::GantryCreated,
        },
    }
    .into_host_request()
    .unwrap_or_else(|error| panic!("task context failed: {error:?}"));
    let mut hook = TaskHook::new(
        &interpreter,
        &factory,
        AdapterPoison::default(),
        create_request,
    )
    .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
    let (mut machine, occurrence) = machine_with_operation();
    let mut operation = operation_for(&occurrence);
    operation
        .prepare(
            &FreshIdentityAllocator::default(),
            services.as_ref(),
            0,
            0,
            &[],
        )
        .unwrap_or_else(|error| panic!("preparation failed: {error:?}"));
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
    assert!(machine.cancel("caller").is_some());
    assert!(matches!(
        operation.accept(&mut machine, LogicalValue::unit()),
        Err(OperationLifecycleError::Completion(
            gantry::runtime::OperationCompletionError::Cancelled,
        ))
    ));
    assert_eq!(operation.state().kind(), OperationStateKind::Outcome);
    assert_eq!(machine.status(), MachineStatus::WaitingOperation);
}

#[test]
fn public_hook_provider_failure_is_preserved_and_fixes_failed_state() {
    let services = Arc::new(Services::default());
    let configuration = configuration(Arc::clone(&services));
    let interpreter = InterpreterLifecycle::new(&configuration);
    let create_request = TaskContextV1 {
        execution_id: fresh(IdentityKind::Execution, 9),
        task_id: derived(IdentityKind::Task, b"root-task"),
        inherited_agent: None,
        session: TaskSessionContextV1::Root {
            root_session_id: fresh(IdentityKind::Session, 8),
            provenance: RootSessionProvenanceV1::GantryCreated,
        },
    }
    .into_host_request()
    .unwrap_or_else(|error| panic!("task context failed: {error:?}"));
    let mut hook = TaskHook::new(
        &interpreter,
        &FailingFactory,
        AdapterPoison::default(),
        create_request,
    )
    .unwrap_or_else(|error| panic!("task hook failed: {error:?}"));
    let (_, occurrence) = machine_with_operation();
    let mut operation = operation_for(&occurrence);
    operation
        .prepare(
            &FreshIdentityAllocator::default(),
            services.as_ref(),
            0,
            0,
            &[],
        )
        .unwrap_or_else(|error| panic!("preparation failed: {error:?}"));

    let result = block_on(operation.dispatch(&mut hook, &CancellationSignal::default()));
    assert!(matches!(
        result,
        Err(OperationLifecycleError::Hook(TaskHookError::Host(ref error)))
            if error.code.as_ref() == "hook-provider-failure"
    ));
    assert_eq!(operation.state().kind(), OperationStateKind::Failed);
    assert!(matches!(
        operation.failure(),
        Some(TaskHookError::Host(error)) if error.code.as_ref() == "hook-provider-failure"
    ));
}

fn action_request() -> CapturedOperationRequestV1 {
    let path = CanonicalPath::new("crate::lookup")
        .unwrap_or_else(|error| panic!("action path failed: {error}"));
    CapturedOperationRequestV1::Action {
        header: header(OperationSiteKind::Action, TypeDescriptor::STRING),
        body: ActionOperationRequestV1 {
            path: path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::ReadOnly,
                &path,
                &[],
                &TypeDescriptor::STRING,
            ),
            recovery: RecoveryClass::ReadOnly,
            mapping_revision: ActionMappingRevision::new("actions-v1")
                .unwrap_or_else(|error| panic!("action revision failed: {error:?}")),
            arguments: vec![TypedActionArgumentV1 {
                name: Arc::from("key"),
                ty: TypeDescriptor::STRING,
                value: canonical(br#""value""#),
            }],
        },
    }
}

fn model_request() -> CapturedOperationRequestV1 {
    CapturedOperationRequestV1::Model {
        header: header(OperationSiteKind::Prompt, TypeDescriptor::STRING),
        body: Box::new(ModelOperationRequestV1 {
            selected_agent: Arc::from("worker"),
            mapping_revision: AgentMappingRevision::new("agents-v1")
                .unwrap_or_else(|error| panic!("agent revision failed: {error:?}")),
            template_segments: vec![Arc::from("Hello "), Arc::from("!")],
            rendered_prompt: Arc::from("Hello value!"),
            interpolation_inputs: vec![InterpolationInputV1 {
                position: 0,
                ty: TypeDescriptor::STRING,
                value: canonical(br#""value""#),
            }],
            named_inputs: vec![NamedInputV1 {
                name: Arc::from("context"),
                ty: TypeDescriptor::BOOL,
                value: canonical(b"true"),
            }],
            transcript: CanonicalTranscriptV1::empty(),
            active_session_id: fresh(IdentityKind::Session, 3),
            parent_session_id: None,
            root_session_id: fresh(IdentityKind::Session, 3),
            session_use: ModelSessionUseV1::Inline,
        }),
    }
}

fn operation_for(occurrence: &gantry::runtime::OperationOccurrence) -> OperationLifecycle {
    let path = CanonicalPath::new("crate::noop")
        .unwrap_or_else(|error| panic!("action path failed: {error}"));
    OperationLifecycle::new(CapturedOperationRequestV1::Action {
        header: OperationRequestHeaderV1 {
            execution_id: fresh(IdentityKind::Execution, 9),
            task_id: derived(IdentityKind::Task, b"root-task"),
            operation_id: occurrence.identity,
            kind: OperationSiteKind::Action,
            expected_type: TypeDescriptor::UNIT,
            expected_schema: Arc::from(&br#"{"type":"null"}"#[..]),
            maximum_hook_output_bytes: 1_024,
            value_limits: DEFAULT_VALUE_LIMITS,
            workflow: occurrence.workflow.clone(),
            site: occurrence.site.clone(),
        },
        body: ActionOperationRequestV1 {
            path: path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::ReadOnly,
                &path,
                &[],
                &TypeDescriptor::UNIT,
            ),
            recovery: RecoveryClass::ReadOnly,
            mapping_revision: ActionMappingRevision::new("actions-v1")
                .unwrap_or_else(|error| panic!("action revision failed: {error:?}")),
            arguments: Vec::new(),
        },
    })
    .unwrap_or_else(|error| panic!("operation lifecycle failed: {error:?}"))
}

fn machine_with_operation() -> (Machine, gantry::runtime::OperationOccurrence) {
    let root = CanonicalPath::new("crate::main")
        .unwrap_or_else(|error| panic!("root path failed: {error}"));
    let program = MachineProgram::new(vec![Workflow {
        path: root.clone(),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            Instruction {
                site: StructuralPosition::new(vec![0])
                    .unwrap_or_else(|error| panic!("operation site failed: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Operation,
            },
            Instruction {
                site: StructuralPosition::new(vec![1])
                    .unwrap_or_else(|error| panic!("return site failed: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Return,
            },
        ],
    }])
    .unwrap_or_else(|error| panic!("program failed: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("machine limits failed"));
    let mut machine = Machine::new(
        Arc::new(program),
        &root,
        Vec::new(),
        fresh(IdentityKind::Execution, 9),
        limits,
    )
    .unwrap_or_else(|error| panic!("machine failed: {error:?}"));
    let occurrence = match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(occurrence)) => occurrence,
        other => panic!("unexpected machine step: {other:?}"),
    };
    (machine, occurrence)
}

fn header(kind: OperationSiteKind, expected_type: TypeDescriptor) -> OperationRequestHeaderV1 {
    OperationRequestHeaderV1 {
        execution_id: fresh(IdentityKind::Execution, 1),
        task_id: derived(IdentityKind::Task, b"task"),
        operation_id: derived(IdentityKind::Operation, b"operation"),
        kind,
        expected_type,
        expected_schema: Arc::from(&br#"{"type":"string"}"#[..]),
        maximum_hook_output_bytes: 1_024,
        value_limits: DEFAULT_VALUE_LIMITS,
        workflow: CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("workflow path failed: {error}")),
        site: StructuralPosition::new(vec![1, 2])
            .unwrap_or_else(|error| panic!("site failed: {error}")),
    }
}

fn configuration(services: Arc<Services>) -> InterpreterConfiguration {
    let required = RequiredConfiguration::new(
        FrontendLimits::new(
            8, 1_024, 4_096, 1_024, 32, 4_096, 4_096, 4_096, 4_096, 64, 1_024, 4_096,
        )
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
        assert!(text.contains(value), "missing request field: {value}");
    }
}

fn assert_excludes(bytes: &[u8], forbidden: &[&str]) {
    let text =
        std::str::from_utf8(bytes).unwrap_or_else(|error| panic!("request was not UTF-8: {error}"));
    for value in forbidden {
        assert!(!text.contains(value), "forbidden request field: {value}");
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
