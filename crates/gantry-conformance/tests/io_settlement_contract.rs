//! Machine-checked conformance for the bounded in-memory I/O settlement contract.
//!
//! These rows exercise only the public surface the runtime publishes for one bounded
//! Section 45 call: the admitted request bound, the executor-neutral endpoint boundary, the
//! bounded in-memory transport, the authenticated receiver occurrence and call binding, the
//! settlement service admission gate, and one end-to-end read settled through the public service
//! over an admitted account. They perform no filesystem, socket, console, or process I/O, open no
//! source handle, and publish no adapter, family integration, durable cleanup cut, or task
//! transfer. The cancellation races, the closed and unreadable lease containment, and the
//! contained-failure lanes are exercised by the runtime crate own unit tests, which can drive the
//! machine-issued admission lease directly.

use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, DisclosureCharge, EffectSet, ExecutableAction,
    ExecutableOperation, ExternalOutcome, Instruction, InstructionKind, IoBackpressure,
    IoOperation, IoRequest, LivenessRoot, LoanId, LogicalOperationId, MachineProgram,
    ObservationAllowance, OperationAbi, OperationKind, OwnerGeneration, ProgressObservation,
    ReceiverOwnership, ResourceCarrier, ResourceGenerationId, ResourceLedger, ResourceState,
    StaticSiteId, StructuralPosition, TypeDescriptor, Workflow,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    AdmittedResource, BoundedIoEndpoint, InMemoryIoTransport, IoCallBinding, IoCallOutcome,
    IoEvidence, IoHostCompletion, IoOccurrence, IoRefusal, IoSettlementService, Machine,
    MachineLimits, OwnedHostResource,
};
use gantry::value::DEFAULT_VALUE_LIMITS;

/// One canonical fixture path.
fn path(name: &str) -> CanonicalPath {
    CanonicalPath::new(name).unwrap_or_else(|error| panic!("fixture path: {error}"))
}

/// One structural fixture site.
fn position(index: u64) -> StructuralPosition {
    StructuralPosition::new(vec![index]).unwrap_or_else(|error| panic!("fixture site: {error}"))
}

/// One declared observation allowance of `observations` charged observations.
fn allowance(observations: u64) -> ObservationAllowance {
    OperationAbi::observation_allowance(
        observations,
        DisclosureCharge::new(1).unwrap_or_else(|| panic!("fixture charge")),
    )
}

/// One synthetic exclusive receiver loan of one sealed generation.
fn loan_live() -> gantry::ir::LiveResource {
    let declaration = path("crate::stream");
    let static_site = StaticSiteId::new(path("crate::main"), position(0));
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
    .unwrap_or_else(|error| panic!("synthetic loan abi: {error:?}"));
    abi.open_live(OwnerGeneration::new(2), allowance(2))
        .unwrap_or_else(|error| panic!("synthetic loan live: {error:?}"))
}

/// One synthetic retained receiver, which is not a bounded-call receiver.
fn retained_live() -> gantry::ir::LiveResource {
    let declaration = path("crate::stream");
    let static_site = StaticSiteId::new(path("crate::main"), position(0));
    let abi = OperationAbi::new(
        OperationKind::LiveResource,
        &declaration,
        &static_site,
        0,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|error| panic!("synthetic retained abi: {error:?}"));
    abi.open_live(OwnerGeneration::new(2), allowance(2))
        .unwrap_or_else(|error| panic!("synthetic retained live: {error:?}"))
}

/// One bound call over one sealed loan occurrence.
fn binding(kind: IoOperation, request: IoRequest) -> IoCallBinding {
    let live = loan_live();
    let occurrence = IoOccurrence::authenticate(&live, kind)
        .unwrap_or_else(|error| panic!("loan occurrence: {error:?}"));
    IoCallBinding::bind(occurrence, request)
        .unwrap_or_else(|error| panic!("loan binding: {error:?}"))
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
            site: position(0),
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
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x32; 32])
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

/// One empty machine, which supplies no pending occurrence.
fn empty_machine() -> Machine {
    let workflow = Workflow {
        path: path("crate::main"),
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![Instruction {
            site: position(0),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::Panic,
        }],
    };
    let program = MachineProgram::new(vec![workflow])
        .unwrap_or_else(|error| panic!("fixture program: {error:?}"));
    let limits = MachineLimits::new(8, 4, 4, 2, 4, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture limits"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x31; 32])
        .unwrap_or_else(|error| panic!("fixture identity: {error}"));
    Machine::new(
        Arc::new(program),
        &path("crate::main"),
        Vec::new(),
        execution,
        limits,
    )
    .unwrap_or_else(|error| panic!("fixture machine: {error:?}"))
}

/// A zero or excess quantity is refused by the admitted request contract itself.
#[test]
fn the_request_contract_refuses_zero_and_excess_quantities() {
    assert!(IoRequest::read(0).is_err());
    assert!(IoRequest::write(0).is_err());
    assert!(IoRequest::read(gantry::ir::IO_REQUEST_OCTET_BOUND + 1).is_err());
    assert!(IoRequest::write(gantry::ir::IO_REQUEST_OCTET_BOUND + 1).is_err());
    assert_eq!(
        IoRequest::read(gantry::ir::IO_REQUEST_OCTET_BOUND).map(|request| request.quantity()),
        Ok(gantry::ir::IO_REQUEST_OCTET_BOUND)
    );
}

/// The bounded in-memory endpoint exposes exactly its initialized octets and final EOF octets.
#[test]
fn the_bounded_transport_exposes_exactly_its_initialized_octets() {
    let call = binding(
        IoOperation::Read,
        IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
    );
    let mut endpoint = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
        .unwrap_or_else(|error| panic!("transport: {error:?}"));
    let handle = endpoint.handle();
    let response = endpoint.attempt(&call, &[]);
    assert_eq!(response.binding(), &call);
    assert_eq!(
        response.completion(),
        &IoHostCompletion::Read {
            advanced: 2,
            bytes: b"ab".to_vec(),
            ended: true,
        }
    );
    assert_eq!(handle.retained(), b"ab".to_vec());
    assert_eq!(handle.capacity(), 4);
    assert_eq!(handle.position(), 2);
    assert_eq!(handle.calls(), 1);
}

/// The bounded in-memory endpoint reports exactly the prefix it accepted.
#[test]
fn the_bounded_transport_reports_exactly_the_accepted_prefix() {
    let call = binding(
        IoOperation::Write,
        IoRequest::write(4).unwrap_or_else(|error| panic!("request: {error:?}")),
    );
    let mut endpoint = InMemoryIoTransport::bounded(b"abc".to_vec(), 5)
        .unwrap_or_else(|error| panic!("transport: {error:?}"));
    let handle = endpoint.handle();
    let payload = b"WXYZ".to_vec();
    let response = endpoint.attempt(&call, &payload);
    assert_eq!(
        response.completion(),
        &IoHostCompletion::Write { accepted: 2 }
    );
    assert_eq!(handle.retained(), b"abcWX".to_vec());
    assert_eq!(payload, b"WXYZ".to_vec());
}

/// A declared not-ready peer blocks one call without advancing the stream.
#[test]
fn the_bounded_transport_reports_not_ready_without_advancing() {
    let call = binding(
        IoOperation::Read,
        IoRequest::read(2).unwrap_or_else(|error| panic!("request: {error:?}")),
    );
    let mut endpoint = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
        .unwrap_or_else(|error| panic!("transport: {error:?}"));
    let handle = endpoint.handle();
    handle.declare_not_ready(Some(IoOperation::Read));
    let response = endpoint.attempt(&call, &[]);
    assert_eq!(
        response.completion(),
        &IoHostCompletion::Blocked {
            operation: IoBackpressure::Read,
        }
    );
    assert_eq!(handle.position(), 0);
    assert_eq!(handle.retained(), b"ab".to_vec());
}

/// Only an exclusive borrowed receiver loan carries a bounded call, and its kind is bound.
#[test]
fn an_occurrence_requires_an_exclusive_loan_and_binds_the_request_kind() {
    let retained = retained_live();
    assert_eq!(
        IoOccurrence::authenticate(&retained, IoOperation::Read),
        Err(IoRefusal::NotAReceiverLoan {
            arrangement: "retained-by-caller",
        })
    );

    let live = loan_live();
    let occurrence = IoOccurrence::authenticate(&live, IoOperation::Read)
        .unwrap_or_else(|error| panic!("loan occurrence: {error:?}"));
    assert_eq!(occurrence.owner(), live.owner());
    assert_eq!(occurrence.generation(), live.generation());
    assert_eq!(
        IoCallBinding::bind(
            occurrence,
            IoRequest::write(1).unwrap_or_else(|error| panic!("request: {error:?}"))
        ),
        Err(IoRefusal::RequestKind {
            declared: IoOperation::Read,
            request: IoOperation::Write,
        })
    );
}

/// The public service settles exactly one read of one admitted occurrence, once.
#[test]
fn the_public_service_settles_one_read_and_refuses_a_second_attempt() {
    let machine = live_machine();
    let subject = machine
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("pending subject"));
    let owner = OwnerGeneration::new(4);
    let record = ResourceLedger::new(
        owner,
        ResourceState::Usable,
        &[LivenessRoot::Resource, LivenessRoot::Loan],
        &[],
    )
    .unwrap_or_else(|error| panic!("fixture ledger: {error:?}"))
    .durable_record();
    let account = AdmittedResource::admit(ResourceCarrier::ReconstructionRecord, record, subject)
        .unwrap_or_else(|error| panic!("fixture account: {error:?}"));
    let transport = InMemoryIoTransport::bounded(b"ab".to_vec(), 4)
        .unwrap_or_else(|error| panic!("transport: {error:?}"));
    let handle = transport.handle();
    let mut resource =
        OwnedHostResource::bind(account, transport).unwrap_or_else(|_| panic!("fixture binding"));
    let mut service = IoSettlementService::new(
        &machine,
        owner,
        IoOperation::Read,
        allowance(4),
        Vec::new(),
        7,
    )
    .unwrap_or_else(|error| panic!("fixture service: {error:?}"));
    let request = IoRequest::read(4).unwrap_or_else(|error| panic!("request: {error:?}"));
    let outcome = service.attempt(&mut resource, request.clone(), &[]);
    let IoCallOutcome::Settled(settlement) = outcome else {
        panic!("a read must settle, observed {outcome:?}")
    };
    assert_eq!(settlement.outcome(), ExternalOutcome::Accepted);
    assert_eq!(settlement.progress(), ProgressObservation::Eof);
    assert_eq!(
        settlement.evidence(),
        &IoEvidence::Read {
            requested: 4,
            returned: b"ab".to_vec(),
            ended: true,
        }
    );
    assert_eq!(settlement.settled_at_us(), 7);
    let settled_record = resource.account().durable_record();
    assert_eq!(
        service.attempt(&mut resource, request, &[]),
        IoCallOutcome::Refused(IoRefusal::DuplicateSettlement)
    );
    assert_eq!(resource.account().durable_record(), settled_record);
    assert_eq!(handle.retained(), b"ab".to_vec());
}

/// The settlement service refuses an exhausted allowance before any loan, charge, or effect.
#[test]
fn the_settlement_service_refuses_an_exhausted_allowance_before_effects() {
    let machine = empty_machine();
    let refusal = IoSettlementService::new(
        &machine,
        OwnerGeneration::new(1),
        IoOperation::Read,
        ObservationAllowance::declared(
            0,
            DisclosureCharge::new(1).unwrap_or_else(|| panic!("fixture charge")),
        ),
        Vec::new(),
        0,
    )
    .err()
    .unwrap_or_else(|| panic!("an exhausted allowance must refuse before any effect"));
    assert_eq!(
        refusal,
        IoRefusal::ObservationAllowanceExhausted {
            remaining: 0,
            charge: 1,
        }
    );
}
