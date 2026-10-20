//! Public-surface conformance for the redirected console output runtime integration.
//!
//! These rows exercise the published runtime surface over the landed common bounded I/O settlement
//! and machine resource carrier: one launch-injected `output-flush` grant, one authenticated
//! receiver, one admitted bounded request, one settlement with its exact accepted prefix, the
//! zero-dispatch denials of the declaration model, the byte-preserving attached-terminal refusal,
//! the unsupported-sink refusal, cancellation before admission, the atomic occurrence reservation,
//! a contained carrier fault, one finishing end of access, and the grantor-owned shutdown that
//! returns the fixed task outcome on every path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, ConsoleAccessIdentity, ConsoleAuthorityDiagnosticCode,
    ConsoleAuthorityError, ConsoleFlushOutcome, ConsoleGrant, ConsoleOutputTarget,
    ConsoleRequirementGroup, DisclosureCharge, EffectSet, ExecutableAction, ExecutableOperation,
    ExternalOutcome, IO_REQUEST_OCTET_BOUND, Instruction, InstructionKind, IoError, IoOperation,
    LivenessRoot, MachineProgram, ObservationAllowance, OperationAbi, OperationKind,
    OwnerGeneration, ProgressObservation, ResourceCarrier, ResourceLedger, ResourceLifetimeState,
    ResourceState, TypeDescriptor, Workflow,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    AdmittedResource, BoundedIoEndpoint, ConsoleOutputAccess, ConsoleOutputInstance,
    ConsoleOutputSettlement, ConsoleOutputSink, ConsoleRedirectedSink, ConsoleRuntimeRefusal,
    InMemoryIoTransport, IoCallBinding, IoCallOutcome, IoEvidence, IoHostCompletion,
    IoHostResponse, IoOperationalFault, IoRefusal, Machine, MachineLimits, ResourceSubjectBinding,
};
use gantry::value::DEFAULT_VALUE_LIMITS;

/// The grantor of every fixture injection.
const GRANTOR: &str = "launch";

/// The requester of every fixture grant.
const REQUESTER: &str = "task";

/// One canonical fixture path.
fn path(name: &str) -> CanonicalPath {
    CanonicalPath::new(name).unwrap_or_else(|error| panic!("fixture path: {error}"))
}

/// One structural fixture site.
fn site(index: u64) -> gantry::ir::StructuralPosition {
    gantry::ir::StructuralPosition::new(vec![index])
        .unwrap_or_else(|error| panic!("fixture site: {error}"))
}

/// One declared observation allowance of `observations` charged observations.
fn allowance(observations: u64) -> ObservationAllowance {
    OperationAbi::observation_allowance(
        observations,
        DisclosureCharge::new(1).unwrap_or_else(|| panic!("fixture charge")),
    )
}

/// One live-resource action declaration the machine authenticates as Section 20 live.
fn live_operation() -> ExecutableOperation {
    let action = path("crate::stream");
    ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(ExecutableAction {
            path: action.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &action,
                &[],
                &TypeDescriptor::UNIT,
            ),
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    }
}

/// One machine prepared at exactly one pending live-resource occurrence.
fn live_machine() -> Machine {
    let workflow = Workflow {
        path: path("crate::main"),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![Instruction {
            site: site(0),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::OperationCall {
                operation: live_operation(),
                operands: 0,
            },
        }],
    };
    let program = MachineProgram::new(vec![workflow])
        .unwrap_or_else(|error| panic!("fixture program: {error:?}"));
    let limits = MachineLimits::new(64, 8, 8, 4, 8, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture limits"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x63; 32])
        .unwrap_or_else(|error| panic!("fixture identity: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &path("crate::main"),
        Vec::new(),
        execution,
        limits,
    )
    .unwrap_or_else(|error| panic!("fixture machine: {error:?}"));
    let _ = machine.step();
    if machine.pending_resource_subject().is_none() {
        panic!("the fixture machine must prepare one live-resource occurrence");
    }
    machine
}

/// The one `output-flush` grant every fixture injection issues.
fn output_grant() -> ConsoleGrant {
    ConsoleGrant::new(ConsoleRequirementGroup::OutputFlush, REQUESTER, GRANTOR)
}

/// The one control grant a control-authority row injects.
fn control_grant() -> ConsoleGrant {
    ConsoleGrant::new(ConsoleRequirementGroup::Control, REQUESTER, GRANTOR)
}

/// One grantor-owned access issuing exactly the presented grants.
fn access(grants: Vec<ConsoleGrant>) -> ConsoleOutputAccess {
    ConsoleOutputAccess::from_launch(GRANTOR, grants)
}

/// One runtime refusal presented by the declaration boundary for one console authority error.
fn authority_refusal(error: ConsoleAuthorityError) -> ConsoleRuntimeRefusal {
    ConsoleRuntimeRefusal::Authority(gantry::ir::ConsoleCallError::from(error))
}

/// One machine pending occurrence, one current owner, and one accounting record.
struct Fixture {
    machine: Machine,
    owner: OwnerGeneration,
    subject: ResourceSubjectBinding,
    record: gantry::ir::DurableResourceRecord,
}

impl Fixture {
    /// Builds one fixture whose ledger retains the resource and loan liveness roots.
    fn new() -> Self {
        let machine = live_machine();
        let subject = machine
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("the fixture machine must prepare one pending subject"));
        let owner = OwnerGeneration::new(4);
        let record = ResourceLedger::new(
            owner,
            ResourceState::Usable,
            &[LivenessRoot::Resource, LivenessRoot::Loan],
            &[],
        )
        .unwrap_or_else(|error| panic!("fixture ledger: {error:?}"))
        .durable_record();
        Self {
            machine,
            owner,
            subject,
            record,
        }
    }

    /// Admits one fresh account of this fixture's occurrence.
    fn account(&self) -> AdmittedResource {
        AdmittedResource::admit(
            ResourceCarrier::ReconstructionRecord,
            self.record.clone(),
            self.subject.clone(),
        )
        .unwrap_or_else(|error| panic!("fixture account: {error:?}"))
    }

    /// Binds one redirected sink under the presented granting access.
    fn bind<'a, T: BoundedIoEndpoint>(
        &self,
        access: &'a ConsoleOutputAccess,
        sink: ConsoleRedirectedSink<T>,
    ) -> ConsoleOutputInstance<'a, T> {
        access
            .bind(self.account(), sink)
            .unwrap_or_else(|_| panic!("fixture physical binding"))
    }

    /// Admits one requester route over the presented access and identity.
    fn route<'a>(
        &'a self,
        access: &'a ConsoleOutputAccess,
        identity: ConsoleAccessIdentity,
    ) -> Result<ConsoleOutputSettlement<'a>, ConsoleRuntimeRefusal> {
        ConsoleOutputSettlement::new(
            access,
            identity,
            &self.machine,
            self.owner,
            allowance(8),
            Vec::new(),
            7,
        )
    }
}

/// One carrier that counts every dispatched call and reports one declared accepted count.
struct CountingCarrier {
    accepted: u64,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for CountingCarrier {
    fn attempt(&mut self, call: &IoCallBinding, _provided: &[u8]) -> IoHostResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        IoHostResponse::new(
            call.clone(),
            IoHostCompletion::Write {
                accepted: self.accepted,
            },
        )
    }
}

/// A redirected write settles committed progress and publishes exactly its accepted prefix.
#[test]
fn redirected_write_settles_the_accepted_prefix_once() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 8)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(&access, ConsoleRedirectedSink::new(transport));
    assert_eq!(
        instance.target(),
        ConsoleOutputTarget::RedirectedNonControlling
    );
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcdef")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert_eq!(call.admission().accepted_prefix(), 6);
    assert_eq!(call.accepted_prefix(), Some(6));
    let IoCallOutcome::Settled(settlement) = call.outcome() else {
        panic!(
            "the redirected write must settle, observed {:?}",
            call.outcome()
        );
    };
    assert_eq!(
        settlement.progress(),
        ProgressObservation::CommittedProgress
    );
    assert_eq!(settlement.outcome(), ExternalOutcome::Accepted);
    assert_eq!(
        settlement.evidence(),
        &IoEvidence::Write {
            provided: 6,
            accepted: 6,
            prefix: b"abcdef".to_vec(),
        }
    );
    assert_eq!(handle.retained(), b"abcdef".to_vec());
    assert_eq!(handle.calls(), 1);
    assert_eq!(
        instance.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// A redirected sink publishes control-bearing octets unchanged: it grants no control authority.
#[test]
fn redirected_write_publishes_control_octets_unchanged() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 16)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(&access, ConsoleRedirectedSink::new(transport));
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let presented = b"a\x1b[31mb";
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), presented)
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert_eq!(call.accepted_prefix(), Some(7));
    assert_eq!(handle.retained(), presented.to_vec());
    assert_eq!(handle.calls(), 1);
}

/// A short write reports short progress and leaves the remainder with its caller.
#[test]
fn short_write_reports_short_progress_of_exactly_the_accepted_prefix() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 2)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(&access, ConsoleRedirectedSink::new(transport));
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcde")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert_eq!(call.accepted_prefix(), Some(2));
    let IoCallOutcome::Settled(settlement) = call.outcome() else {
        panic!("the short write must settle, observed {:?}", call.outcome());
    };
    assert_eq!(settlement.progress(), ProgressObservation::ShortWrite);
    assert_eq!(
        settlement.evidence(),
        &IoEvidence::Write {
            provided: 5,
            accepted: 2,
            prefix: b"ab".to_vec(),
        }
    );
    assert_eq!(handle.retained(), b"ab".to_vec());
    assert_eq!(
        handle.calls(),
        1,
        "a short write settles this one call and is never retried"
    );
}

/// A missing, ambient, wrong-group, and forged access is refused before any dispatch.
#[test]
fn missing_ambient_wrong_group_and_forged_access_refuse_before_dispatch() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let ambient = access(vec![output_grant()]);
    let instance = fixture.bind(
        &ambient,
        ConsoleRedirectedSink::new(CountingCarrier {
            accepted: 4,
            calls: Arc::clone(&calls),
        }),
    );
    assert_eq!(
        fixture
            .route(&ambient, ConsoleAccessIdentity::AmbientDescriptor(1))
            .err(),
        Some(authority_refusal(
            ConsoleAuthorityError::AmbientDescriptor { descriptor: 1 }
        ))
    );
    let missing = access(Vec::new());
    assert_eq!(
        fixture
            .route(&missing, ConsoleAccessIdentity::Injected(output_grant()))
            .err(),
        Some(authority_refusal(ConsoleAuthorityError::AuthorityMissing {
            group: ConsoleRequirementGroup::OutputFlush,
        }))
    );
    let inconsistent = access(vec![
        output_grant(),
        ConsoleGrant::new(ConsoleRequirementGroup::Input, REQUESTER, GRANTOR),
    ]);
    assert_eq!(
        fixture
            .route(
                &inconsistent,
                ConsoleAccessIdentity::Injected(ConsoleGrant::new(
                    ConsoleRequirementGroup::Input,
                    REQUESTER,
                    GRANTOR,
                )),
            )
            .err(),
        Some(authority_refusal(
            ConsoleAuthorityError::RequirementGroupInconsistent {
                observed: "input".to_owned(),
                declared: "output-flush".to_owned(),
            }
        ))
    );
    let forged = ConsoleGrant::new(
        ConsoleRequirementGroup::OutputFlush,
        REQUESTER,
        "another-grantor",
    );
    let issued = access(vec![output_grant()]);
    let Err(ConsoleRuntimeRefusal::Authority(error)) =
        fixture.route(&issued, ConsoleAccessIdentity::Injected(forged))
    else {
        panic!("a forged grant must be refused by the declaration boundary");
    };
    assert_eq!(
        error.console_code(),
        Some(ConsoleAuthorityDiagnosticCode::AuthorityForged)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(instance);
}

/// Control-bearing octets on an attached terminal are refused byte-preservingly.
#[test]
fn attached_terminal_control_octets_are_refused_byte_preservingly() {
    let fixture = Fixture::new();
    let access = access(vec![output_grant()]);
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let presented = b"a\x1b[31mb";
    assert_eq!(
        route.write(
            ConsoleOutputSink::<InMemoryIoTransport>::AttachedTerminal,
            presented
        ),
        Err(authority_refusal(
            ConsoleAuthorityError::ControlBearingOutputRefused {
                preserved_octets: presented.to_vec(),
            }
        ))
    );
}

/// An injected control grant never delivers attached-terminal output in this slice.
#[test]
fn attached_terminal_delivery_is_undelivered_even_with_control_authority() {
    let fixture = Fixture::new();
    let access = access(vec![output_grant(), control_grant()]);
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let presented = b"a\x1bb";
    assert_eq!(
        route.write(
            ConsoleOutputSink::<InMemoryIoTransport>::AttachedTerminal,
            presented
        ),
        Err(ConsoleRuntimeRefusal::AttachedTerminalUndelivered {
            preserved_octets: presented.to_vec(),
        })
    );
}

/// A sink kind Section 46.9 does not declare is refused even without a control octet.
#[test]
fn an_undeclared_sink_is_refused_without_a_control_octet() {
    let fixture = Fixture::new();
    let access = access(vec![output_grant()]);
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    assert_eq!(
        route.write(
            ConsoleOutputSink::<InMemoryIoTransport>::Unsupported("network"),
            b"plain"
        ),
        Err(authority_refusal(
            ConsoleAuthorityError::SafeOutputUnsupported { sink: "network" }
        ))
    );
}

/// A zero-octet write is refused by the Section 45 request contract before any dispatch.
#[test]
fn zero_octet_write_is_refused_before_any_dispatch() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier {
            accepted: 0,
            calls: Arc::clone(&calls),
        }),
    );
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    assert_eq!(
        route.write(ConsoleOutputSink::Redirected(&mut instance), b""),
        Err(ConsoleRuntimeRefusal::Request(IoError::RequestBound {
            operation: IoOperation::Write,
            observed: 0,
            maximum: IO_REQUEST_OCTET_BOUND,
        }))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// A cancellation observed before admission refuses without a dispatch.
#[test]
fn cancellation_before_admission_refuses_without_a_dispatch() {
    let mut fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier {
            accepted: 4,
            calls: Arc::clone(&calls),
        }),
    );
    let _ = fixture.machine.cancel("fixture cancellation");
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcd")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert_eq!(
        call.outcome(),
        &IoCallOutcome::Refused(IoRefusal::CancelledBeforeAdmission)
    );
    assert_eq!(call.accepted_prefix(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// A duplicate presentation is refused without a second dispatch.
#[test]
fn duplicate_presentation_is_refused_without_a_second_dispatch() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 8)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(&access, ConsoleRedirectedSink::new(transport));
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let first = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"ab")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert!(matches!(first.outcome(), IoCallOutcome::Settled(_)));
    assert_eq!(
        route
            .write(ConsoleOutputSink::Redirected(&mut instance), b"ab")
            .err(),
        Some(ConsoleRuntimeRefusal::Settlement(
            IoRefusal::DuplicateSettlement
        )),
        "a settled occurrence must be refused before any second dispatch"
    );
    assert_eq!(handle.calls(), 1);
    assert_eq!(handle.retained(), b"ab".to_vec());
}

/// Two independently admitted accounts cannot settle one occurrence under one grant.
#[test]
fn two_independently_admitted_accounts_cannot_settle_one_occurrence() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let access = access(vec![output_grant()]);
    let mut first = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier {
            accepted: 2,
            calls: Arc::clone(&calls),
        }),
    );
    let mut second = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier {
            accepted: 2,
            calls: Arc::clone(&calls),
        }),
    );
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let one = route
        .write(ConsoleOutputSink::Redirected(&mut first), b"ab")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert!(matches!(one.outcome(), IoCallOutcome::Settled(_)));
    assert_eq!(
        route
            .write(ConsoleOutputSink::Redirected(&mut second), b"ab")
            .err(),
        Some(ConsoleRuntimeRefusal::Settlement(
            IoRefusal::DuplicateSettlement
        )),
        "a second account of the same occurrence must be refused before dispatch"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// An over-accepting carrier is a contained fault that publishes no accepted prefix.
#[test]
fn an_over_accepting_carrier_is_a_contained_fault() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier {
            accepted: 9,
            calls: Arc::clone(&calls),
        }),
    );
    let route = fixture
        .route(&access, ConsoleAccessIdentity::Injected(output_grant()))
        .unwrap_or_else(|error| panic!("fixture route: {error}"));
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcd")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    let IoCallOutcome::Failed(failed) = call.outcome() else {
        panic!(
            "an over-accepting carrier must fail, observed {:?}",
            call.outcome()
        );
    };
    assert_eq!(
        failed.fault(),
        &gantry::runtime::IoCallFault::Operational(IoOperationalFault::WriteOverAccepted {
            provided: 4,
            accepted: 9,
        })
    );
    assert_eq!(call.accepted_prefix(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Shutdown refuses while a bound instance was not finished, and keeps the task outcome.
#[test]
fn shutdown_refuses_an_unfinished_output_instance() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let access = access(vec![output_grant()]);
    let instance = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier { accepted: 0, calls }),
    );
    drop(instance);
    let (task_outcome, settlement) = access.settle_shutdown("task:ok");
    assert_eq!(task_outcome, "task:ok");
    assert_eq!(
        settlement.err(),
        Some(ConsoleRuntimeRefusal::UnfinishedOutput { count: 1 })
    );
}

/// One finishing end of access publishes the flush and keeps the task outcome unchanged.
#[test]
fn grantor_shutdown_publishes_the_empty_flush_and_keeps_the_task_outcome() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let access = access(vec![output_grant()]);
    let mut instance = fixture.bind(
        &access,
        ConsoleRedirectedSink::new(CountingCarrier { accepted: 0, calls }),
    );
    let state = instance
        .finish(11)
        .unwrap_or_else(|error| panic!("fixture finish: {error}"));
    assert_eq!(state, ResourceLifetimeState::Finished);
    drop(instance);
    let (task_outcome, settlement) = access.settle_shutdown("task:ok");
    assert_eq!(task_outcome, "task:ok");
    let settlement = settlement.unwrap_or_else(|error| panic!("fixture shutdown: {error}"));
    assert!(!settlement.flush_failed());
    assert!(!settlement.task_outcome_rewritten());
    assert_eq!(settlement.flush(), ConsoleFlushOutcome::Flushed);
}

/// The published specification still declares the boundary this slice consumes.
#[test]
fn the_published_boundary_this_slice_consumes_is_current() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    let start = spec
        .find("<a id=\"GNT-46.9-console-control-and-output-boundary\"></a>")
        .unwrap_or_else(|| panic!("GNT-46.9 must be published"));
    let end = spec
        .find("<a id=\"GNT-47.0-filesystem-foundation-scope\"></a>")
        .unwrap_or_else(|| panic!("GNT-47.0 must follow GNT-46.9"));
    let clause: String = spec[start..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for term in [
        "redirected or otherwise non-controlling sink",
        "console-control-bearing-output-refused",
        "console-safe-output-unsupported",
        "byte-preserving",
        "0x1b",
        "never a silent grant of terminal-control authority",
    ] {
        assert!(clause.contains(term), "GNT-46.9 must publish `{term}`");
    }
    let scope = spec
        .find("<a id=\"GNT-46.8-console-authority-admission\"></a>")
        .map(|position| {
            spec[position..]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| panic!("GNT-46.8 must be published"));
    assert!(
        scope.contains("console-authority-ambient-descriptor")
            && scope.contains("console-authority-missing")
            && scope.contains("console-authority-forged"),
        "GNT-46.8 must publish the injected-access refusals this slice presents"
    );
}
