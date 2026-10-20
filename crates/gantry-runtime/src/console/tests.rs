//! Runtime unit lanes for the redirected console output integration.
//!
//! These lanes drive the console route through the landed settlement service and the machine-issued
//! admission lease directly, which no external test can reach. They cover one settled write and its
//! exact accepted prefix, a short write that stays short progress, the zero-dispatch refusals of the
//! request, authority, output-boundary, and attached-terminal decisions, cancellation before and
//! during dispatch, a stale completion of an earlier call, an over-accepting carrier, a duplicate
//! presentation, and the grantor-owned final-flush settlement.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_core::value::DEFAULT_VALUE_LIMITS;
use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
use gantry_ir::{
    CanonicalSignature, ConsoleAccessIdentity, ConsoleAuthorityDiagnosticCode,
    ConsoleAuthorityError, ConsoleCallError, ConsoleFlushOutcome, ConsoleGrant,
    ConsoleRequirementGroup, DisclosureCharge, EffectSet, ExecutableAction, ExecutableOperation,
    ExternalOutcome, IO_REQUEST_OCTET_BOUND, Instruction, InstructionKind, LivenessRoot, LoanId,
    LogicalOperationId, MachineProgram, ObservationAllowance, OperationAbi, OperationKind,
    ProgressObservation, ReceiverOwnership, ResourceCarrier, ResourceGenerationId, ResourceLedger,
    ResourceLifetimeState, ResourceState, StaticSiteId, TypeDescriptor, Workflow,
};

use super::*;
use crate::machine::ResourceOperationLease;
use crate::{
    AdmittedResource, InMemoryIoTransport, IoAttemptStage, IoCallFault, IoCallOutcome, IoEvidence,
    IoHostCompletion, IoOccurrence, IoOperationalFault, IoRefusal, Machine, MachineLimits,
    ResourceSubjectBinding,
};

/// The grantor of every fixture injection.
const GRANTOR: &str = "launch";

/// The requester of every fixture grant.
const REQUESTER: &str = "task";

/// One canonical fixture path.
fn path(name: &str) -> gantry_ir::CanonicalPath {
    gantry_ir::CanonicalPath::new(name).unwrap_or_else(|error| panic!("fixture path: {error}"))
}

/// One structural fixture site.
fn site(index: u64) -> gantry_ir::StructuralPosition {
    gantry_ir::StructuralPosition::new(vec![index])
        .unwrap_or_else(|error| panic!("fixture site: {error}"))
}

/// One stable fixture execution identity.
fn execution() -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x63; 32])
        .unwrap_or_else(|error| panic!("fixture identity: {error}"))
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
    let mut machine = Machine::new(
        Arc::new(program),
        &path("crate::main"),
        Vec::new(),
        execution(),
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

/// The one control grant a control-authority lane injects.
fn control_grant() -> ConsoleGrant {
    ConsoleGrant::new(ConsoleRequirementGroup::Control, REQUESTER, GRANTOR)
}

/// One grantor-owned access issuing exactly the presented grants.
fn access(grants: Vec<ConsoleGrant>) -> ConsoleOutputAccess {
    ConsoleOutputAccess::from_launch(GRANTOR, grants)
}

/// One runtime refusal presented by the declaration boundary for one console authority error.
fn authority_refusal(error: ConsoleAuthorityError) -> ConsoleRuntimeRefusal {
    ConsoleRuntimeRefusal::Authority(ConsoleCallError::from(error))
}

/// One machine pending occurrence, one current owner, and one accounting record.
struct Fixture {
    machine: Machine,
    owner: OwnerGeneration,
    subject: ResourceSubjectBinding,
    record: gantry_ir::DurableResourceRecord,
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

    /// Returns the machine-issued admission lease of this occurrence.
    fn lease(&self) -> Arc<Mutex<ResourceOperationLease>> {
        self.subject.admission_lease()
    }

    /// Admits one fresh account and binds one redirected sink to it.
    fn bind<T: BoundedIoEndpoint>(
        &self,
        sink: ConsoleRedirectedSink<T>,
    ) -> ConsoleOutputInstance<T> {
        let account = AdmittedResource::admit(
            ResourceCarrier::ReconstructionRecord,
            self.record.clone(),
            self.subject.clone(),
        )
        .unwrap_or_else(|error| panic!("fixture account: {error:?}"));
        ConsoleOutputInstance::bind(account, sink)
            .unwrap_or_else(|_| panic!("fixture physical binding"))
    }

    /// Admits one requester route over the presented access and grant.
    fn route<'a>(
        &'a self,
        access: &'a ConsoleOutputAccess,
        grant: ConsoleGrant,
    ) -> ConsoleOutputSettlement<'a> {
        ConsoleOutputSettlement::new(
            access,
            ConsoleAccessIdentity::Injected(grant),
            &self.machine,
            self.owner,
            allowance(8),
            Vec::new(),
            7,
        )
        .unwrap_or_else(|error| panic!("fixture route: {error}"))
    }
}

/// One carrier that counts every dispatched call and reports one declared accepted count.
struct DeclaredCarrier {
    accepted: u64,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for DeclaredCarrier {
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

/// One carrier that reports cancellation on the account lease while the call is in flight.
struct CancellingCarrier {
    accepted: u64,
    lease: Arc<Mutex<ResourceOperationLease>>,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for CancellingCarrier {
    fn attempt(&mut self, call: &IoCallBinding, _provided: &[u8]) -> IoHostResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut admission) = self.lease.lock() {
            admission.cancellation_requested = true;
        }
        IoHostResponse::new(
            call.clone(),
            IoHostCompletion::Write {
                accepted: self.accepted,
            },
        )
    }
}

/// One carrier that answers a later call with the completion of an earlier one.
struct StaleCarrier {
    stale: IoCallBinding,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for StaleCarrier {
    fn attempt(&mut self, _call: &IoCallBinding, _provided: &[u8]) -> IoHostResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        IoHostResponse::new(self.stale.clone(), IoHostCompletion::Write { accepted: 4 })
    }
}

/// One sealed receiver binding of another occurrence, used as a stale completion claim.
fn stale_binding() -> IoCallBinding {
    let declaration = path("crate::stream");
    let static_site = StaticSiteId::new(path("crate::main"), site(0));
    let operation = LogicalOperationId::derive(&declaration, &static_site);
    let generation = ResourceGenerationId::derive(&operation, &static_site, 0);
    let abi = OperationAbi::new(
        OperationKind::LiveResource,
        &declaration,
        &static_site,
        0,
        RecoveryClass::Idempotent,
        ReceiverOwnership::BorrowedLoan(LoanId::seal(&declaration, &static_site, &generation)),
    )
    .unwrap_or_else(|error| panic!("fixture loan abi: {error:?}"));
    let live = abi
        .open_live(OwnerGeneration::new(2), allowance(2))
        .unwrap_or_else(|error| panic!("fixture loan: {error:?}"));
    let occurrence = IoOccurrence::authenticate(&live, IoOperation::Write)
        .unwrap_or_else(|error| panic!("fixture occurrence: {error:?}"));
    IoCallBinding::bind(
        occurrence,
        IoRequest::write(4).unwrap_or_else(|error| panic!("fixture request: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("fixture binding: {error:?}"))
}

/// One redirected write settles committed progress and publishes exactly its accepted prefix.
#[test]
fn a_redirected_write_settles_committed_progress_once() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 8)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(transport));
    assert_eq!(
        instance.target(),
        ConsoleOutputTarget::RedirectedNonControlling
    );
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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
    drop(route);
    assert_eq!(
        instance.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// One short write stays short progress, publishes its accepted prefix, and is never retried.
#[test]
fn a_short_write_publishes_the_accepted_prefix_without_a_retry() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 2)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(transport));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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

/// A zero-octet write and a write beyond the Section 45 bound are refused before any dispatch.
#[test]
fn zero_and_over_bound_writes_are_refused_before_any_dispatch() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 0,
        calls: Arc::clone(&calls),
    }));
    let record = instance.account().durable_record();
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
    assert_eq!(
        route.write(ConsoleOutputSink::Redirected(&mut instance), b""),
        Err(ConsoleRuntimeRefusal::Request(
            gantry_ir::IoError::RequestBound {
                operation: IoOperation::Write,
                observed: 0,
                maximum: IO_REQUEST_OCTET_BOUND,
            }
        ))
    );
    let beyond = usize::try_from(IO_REQUEST_OCTET_BOUND).unwrap_or(usize::MAX);
    let over = vec![0_u8; beyond.saturating_add(1)];
    assert_eq!(
        route.write(ConsoleOutputSink::Redirected(&mut instance), &over),
        Err(ConsoleRuntimeRefusal::Request(
            gantry_ir::IoError::RequestBound {
                operation: IoOperation::Write,
                observed: IO_REQUEST_OCTET_BOUND.saturating_add(1),
                maximum: IO_REQUEST_OCTET_BOUND,
            }
        ))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(instance.account().durable_record(), record);
    assert_eq!(
        instance.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// A missing, ambient, wrong-group, and forged access is refused before any dispatch.
#[test]
fn missing_ambient_wrong_group_and_forged_access_are_refused_before_dispatch() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let instance = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 4,
        calls: Arc::clone(&calls),
    }));
    let record = instance.account().durable_record();

    let ambient = access(vec![output_grant()]);
    assert_eq!(
        ConsoleOutputSettlement::new(
            &ambient,
            ConsoleAccessIdentity::AmbientDescriptor(1),
            &fixture.machine,
            fixture.owner,
            allowance(8),
            Vec::new(),
            3,
        )
        .err(),
        Some(authority_refusal(
            ConsoleAuthorityError::AmbientDescriptor { descriptor: 1 }
        ))
    );

    let missing = access(Vec::new());
    assert_eq!(
        ConsoleOutputSettlement::new(
            &missing,
            ConsoleAccessIdentity::Injected(output_grant()),
            &fixture.machine,
            fixture.owner,
            allowance(8),
            Vec::new(),
            3,
        )
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
        ConsoleOutputSettlement::new(
            &inconsistent,
            ConsoleAccessIdentity::Injected(ConsoleGrant::new(
                ConsoleRequirementGroup::Input,
                REQUESTER,
                GRANTOR,
            )),
            &fixture.machine,
            fixture.owner,
            allowance(8),
            Vec::new(),
            3,
        )
        .err(),
        Some(authority_refusal(
            ConsoleAuthorityError::RequirementGroupInconsistent {
                observed: "input".to_owned(),
                declared: "output-flush".to_owned(),
            }
        ))
    );

    let forged_grant = ConsoleGrant::new(
        ConsoleRequirementGroup::OutputFlush,
        REQUESTER,
        "another-grantor",
    );
    let issued = access(vec![output_grant()]);
    let forged = ConsoleOutputSettlement::new(
        &issued,
        ConsoleAccessIdentity::Injected(forged_grant),
        &fixture.machine,
        fixture.owner,
        allowance(8),
        Vec::new(),
        3,
    );
    let Err(ConsoleRuntimeRefusal::Authority(error)) = forged else {
        panic!("a forged grant must be refused by the declaration boundary");
    };
    assert_eq!(
        error.console_code(),
        Some(ConsoleAuthorityDiagnosticCode::AuthorityForged)
    );

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(instance.account().durable_record(), record);
    let _ = ConsoleOutputSink::<InMemoryIoTransport>::AttachedTerminal;
}

/// Control-bearing octets on an attached terminal are refused byte-preservingly.
#[test]
fn attached_terminal_control_octets_are_refused_byte_preservingly() {
    let fixture = Fixture::new();
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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
fn attached_terminal_delivery_stays_undelivered_even_with_control_authority() {
    let fixture = Fixture::new();
    let access = access(vec![output_grant(), control_grant()]);
    let route = fixture.route(&access, output_grant());
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
    let plain = b"plain";
    assert_eq!(
        route.write(
            ConsoleOutputSink::<InMemoryIoTransport>::AttachedTerminal,
            plain
        ),
        Err(ConsoleRuntimeRefusal::AttachedTerminalUndelivered {
            preserved_octets: plain.to_vec(),
        })
    );
}

/// A sink kind Section 46.9 does not declare is refused even without a control octet.
#[test]
fn an_undeclared_sink_is_refused_without_a_control_octet() {
    let fixture = Fixture::new();
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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

/// A cancellation requested before admission refuses without a dispatch.
#[test]
fn cancellation_before_admission_refuses_without_a_dispatch() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 4,
        calls: Arc::clone(&calls),
    }));
    let lease = fixture.lease();
    if let Ok(mut admission) = lease.lock() {
        admission.cancellation_requested = true;
    }
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcd")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert_eq!(
        call.outcome(),
        &IoCallOutcome::Refused(IoRefusal::CancelledBeforeAdmission)
    );
    assert_eq!(call.accepted_prefix(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        instance.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// A cancellation during dispatch settles once and withholds the prefix from publication.
#[test]
fn cancellation_during_dispatch_settles_once_and_withholds_the_prefix() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let lease = fixture.lease();
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(CancellingCarrier {
        accepted: 3,
        lease: Arc::clone(&lease),
        calls: Arc::clone(&calls),
    }));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcde")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    let IoCallOutcome::Cancelled(cancelled) = call.outcome() else {
        panic!(
            "a cancelled write must settle as cancelled, observed {:?}",
            call.outcome()
        );
    };
    assert_eq!(cancelled.stage(), IoAttemptStage::Dispatched);
    assert_eq!(cancelled.settlement().outcome(), ExternalOutcome::Ambiguous);
    assert_eq!(
        cancelled.settlement().evidence(),
        &IoEvidence::Write {
            provided: 5,
            accepted: 3,
            prefix: b"abc".to_vec(),
        },
        "the accepted prefix stays protected evidence and is never published as output"
    );
    assert_eq!(call.accepted_prefix(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        route
            .write(ConsoleOutputSink::Redirected(&mut instance), b"abcde")
            .err(),
        Some(ConsoleRuntimeRefusal::Settlement(
            IoRefusal::DuplicateSettlement
        )),
        "a settled occurrence must be refused before any second dispatch"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A stale completion cannot publish its octets or produce a second settlement.
#[test]
fn a_stale_completion_cannot_publish_or_settle_twice() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(StaleCarrier {
        stale: stale_binding(),
        calls: Arc::clone(&calls),
    }));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"abcd")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    let IoCallOutcome::Failed(failed) = call.outcome() else {
        panic!(
            "a stale completion must fail, observed {:?}",
            call.outcome()
        );
    };
    assert_eq!(
        failed.fault(),
        &IoCallFault::Operational(IoOperationalFault::ForeignCompletion)
    );
    let settlement = failed
        .settlement()
        .unwrap_or_else(|| panic!("a contained failure still settles this attempt once"));
    assert_eq!(settlement.outcome(), ExternalOutcome::Ambiguous);
    assert_eq!(settlement.evidence(), &IoEvidence::NoOctets);
    assert_eq!(call.accepted_prefix(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// An over-accepting carrier is a contained fault and publishes no accepted prefix.
#[test]
fn an_over_accepting_carrier_is_a_contained_fault() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 9,
        calls: Arc::clone(&calls),
    }));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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
        &IoCallFault::Operational(IoOperationalFault::WriteOverAccepted {
            provided: 4,
            accepted: 9,
        })
    );
    assert_eq!(call.accepted_prefix(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A duplicate presentation is refused without a second dispatch.
#[test]
fn a_duplicate_presentation_is_refused_without_a_second_dispatch() {
    let fixture = Fixture::new();
    let transport = InMemoryIoTransport::bounded(Vec::new(), 8)
        .unwrap_or_else(|error| panic!("fixture transport: {error:?}"));
    let handle = transport.handle();
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(transport));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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

/// The grantor-owned shutdown finalizes the bound account and returns the task outcome unchanged.
#[test]
fn shutdown_finalizes_the_bound_account_and_returns_the_fixed_task_outcome() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let instance = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 0,
        calls,
    }));
    let access = access(vec![output_grant()]);
    let (task_outcome, settlement) = access
        .settle_shutdown(vec![instance], "task:ok", 11)
        .unwrap_or_else(|error| panic!("fixture shutdown: {error}"));
    assert_eq!(task_outcome, "task:ok");
    assert!(!settlement.flush_failed());
    assert!(!settlement.task_outcome_rewritten());
    assert_eq!(settlement.flush(), ConsoleFlushOutcome::Flushed);
}

/// A shutdown that cannot finalize its account refuses and withholds the flush settlement.
#[test]
fn shutdown_refuses_an_account_it_cannot_finalize() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut instance = fixture.bind(ConsoleRedirectedSink::new(CancellingCarrier {
        accepted: 2,
        lease: fixture.lease(),
        calls: Arc::clone(&calls),
    }));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
    let call = route
        .write(ConsoleOutputSink::Redirected(&mut instance), b"ab")
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    assert!(matches!(call.outcome(), IoCallOutcome::Cancelled(_)));
    drop(route);
    let refused = access.settle_shutdown(vec![instance], "task:ok", 12);
    assert!(
        matches!(refused, Err(ConsoleRuntimeRefusal::Transport(_))),
        "a poisoned account must refuse shutdown, observed {refused:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Two independently admitted accounts cannot settle one machine occurrence.
#[test]
fn two_independently_admitted_instances_cannot_settle_one_occurrence() {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let mut first = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 2,
        calls: Arc::clone(&calls),
    }));
    let mut second = fixture.bind(ConsoleRedirectedSink::new(DeclaredCarrier {
        accepted: 2,
        calls: Arc::clone(&calls),
    }));
    let access = access(vec![output_grant()]);
    let route = fixture.route(&access, output_grant());
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
