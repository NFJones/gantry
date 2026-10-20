//! Runtime unit lanes for the rooted read-only filesystem integration.
//!
//! These lanes exercise the filesystem endpoint through the landed settlement service with a real
//! file descriptor and drive the machine-issued admission lease directly, which no external test
//! can reach. They cover cancellation before admission, cancellation during dispatch with octets
//! withheld from publication, a stale completion of a previous call, a closed instance that
//! refuses every later call, and the fact that a finished account is not a reconstruction of a
//! live descriptor.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_core::value::DEFAULT_VALUE_LIMITS;
use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
use gantry_ir::{
    CanonicalSignature, DisclosureCharge, EffectSet, ExecutableAction, ExecutableOperation,
    ExternalOutcome, Instruction, InstructionKind, LivenessRoot, LoanId, LogicalOperationId,
    MachineProgram, ObservationAllowance, OperationAbi, OperationKind, ReceiverOwnership,
    ResourceCarrier, ResourceGenerationId, ResourceLedger, ResourceState, StaticSiteId,
    TypeDescriptor, Workflow,
};

use super::*;
use crate::machine::ResourceOperationLease;
use crate::{
    AdmittedResource, IoAttemptStage, IoCallFault, IoCallOutcome, IoEvidence, IoOccurrence,
    IoRefusal, IoSettlementService, Machine, MachineLimits, OwnedHostResource,
    ResourceSubjectBinding,
};

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
    ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x51; 32])
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

    /// Admits one fresh account and binds one physical endpoint to it.
    fn bind<T: FsOpenInstance + BoundedIoEndpoint>(&self, endpoint: T) -> FsReadOnlyInstance<T> {
        let account = AdmittedResource::admit(
            ResourceCarrier::ReconstructionRecord,
            self.record.clone(),
            self.subject.clone(),
        )
        .unwrap_or_else(|error| panic!("fixture account: {error:?}"));
        FsReadOnlyInstance::bind(account, endpoint)
            .unwrap_or_else(|_| panic!("fixture physical binding"))
    }

    /// Admits one settlement service over the bound account for one receiver kind.
    fn service(&self, kind: IoOperation) -> IoSettlementService<'_> {
        IoSettlementService::new(&self.machine, self.owner, kind, allowance(8), Vec::new(), 7)
            .unwrap_or_else(|error| panic!("fixture service: {error:?}"))
    }
}

/// One fresh temporary directory tree removed when the value is dropped.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    /// Creates one fresh tree under the canonical temporary directory.
    fn new() -> Self {
        let ordinal = NEXT_TEMP.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "gantry-fs-runtime-{}-{ordinal}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("temporary root: {error}"));
        Self { root }
    }

    /// Writes the one fixture file and returns one mounted root and one read-only grant.
    fn endpoint_fixture(&self) -> (FsRootDirectory, FsReadOnlyGrant) {
        std::fs::write(self.root.join("notes.txt"), b"payload")
            .unwrap_or_else(|error| panic!("fixture file: {error}"));
        let root = FsRootDirectory::mount("data", &self.root)
            .unwrap_or_else(|error| panic!("fixture mount: {error:?}"));
        let path = FsPath::rooted("data", &["notes.txt"])
            .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
        let grant = root
            .issue_grant(&path)
            .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
        (root, grant)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The next temporary tree ordinal.
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// One endpoint that counts every dispatched call before delegating one read.
struct CountingEndpoint {
    inner: FsReadOnlyEndpoint,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for CountingEndpoint {
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.attempt(call, provided)
    }
}

impl super::sealed::FsOpenInstanceSealed for CountingEndpoint {}

impl FsOpenInstance for CountingEndpoint {
    fn open_receipt(&self) -> FsOpenReceipt {
        self.inner.receipt()
    }
}

/// One endpoint that reports cancellation on the account lease while the call is in flight.
struct CancellingEndpoint {
    inner: FsReadOnlyEndpoint,
    lease: Arc<Mutex<ResourceOperationLease>>,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for CancellingEndpoint {
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut admission) = self.lease.lock() {
            admission.cancellation_requested = true;
        }
        self.inner.attempt(call, provided)
    }
}

impl super::sealed::FsOpenInstanceSealed for CancellingEndpoint {}

impl FsOpenInstance for CancellingEndpoint {
    fn open_receipt(&self) -> FsOpenReceipt {
        self.inner.receipt()
    }
}

/// One endpoint that answers a later call with the completion of an earlier one.
struct StaleEndpoint {
    inner: FsReadOnlyEndpoint,
    stale: IoCallBinding,
    calls: Arc<AtomicU64>,
}

impl BoundedIoEndpoint for StaleEndpoint {
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let response = self.inner.attempt(call, provided);
        IoHostResponse::new(self.stale.clone(), response.completion().clone())
    }
}

impl super::sealed::FsOpenInstanceSealed for StaleEndpoint {}

impl FsOpenInstance for StaleEndpoint {
    fn open_receipt(&self) -> FsOpenReceipt {
        self.inner.receipt()
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
    let occurrence = IoOccurrence::authenticate(&live, IoOperation::Read)
        .unwrap_or_else(|error| panic!("fixture occurrence: {error:?}"));
    IoCallBinding::bind(
        occurrence,
        IoRequest::read(4).unwrap_or_else(|error| panic!("fixture request: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("fixture binding: {error:?}"))
}

/// A cancellation requested before admission refuses without dispatch or a refund.
#[test]
fn cancellation_before_admission_refuses_without_a_read() {
    let tree = TempTree::new();
    let (root, grant) = tree.endpoint_fixture();
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let mut resource = fixture.bind(CountingEndpoint {
        inner: endpoint,
        calls: Arc::clone(&calls),
    });
    // Binding linearizes against cancellation, so the cancellation this lane presents is the one
    // that races the admitted call rather than the physical acquisition.
    let lease = fixture.lease();
    if let Ok(mut admission) = lease.lock() {
        admission.cancellation_requested = true;
    }
    let mut service = fixture.service(IoOperation::Read);
    let request = IoRequest::read(4).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    assert_eq!(
        service.attempt(resource.resource_mut(), request, &[]),
        IoCallOutcome::Refused(IoRefusal::CancelledBeforeAdmission)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// A cancellation during dispatch settles once and withholds the octets from publication.
#[test]
fn cancellation_during_dispatch_settles_once_and_withholds_the_octets() {
    let tree = TempTree::new();
    let (root, grant) = tree.endpoint_fixture();
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let mut resource = fixture.bind(CancellingEndpoint {
        inner: endpoint,
        lease: fixture.lease(),
        calls: Arc::clone(&calls),
    });
    let mut service = fixture.service(IoOperation::Read);
    let request = IoRequest::read(16).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let outcome = service.attempt(resource.resource_mut(), request.clone(), &[]);
    let IoCallOutcome::Cancelled(cancelled) = outcome else {
        panic!("cancellation during dispatch must settle as cancelled, observed {outcome:?}");
    };
    assert_eq!(cancelled.stage(), IoAttemptStage::Dispatched);
    assert_eq!(cancelled.settlement().outcome(), ExternalOutcome::Ambiguous);
    assert_eq!(cancelled.settlement().state(), ResourceState::Poisoned);
    assert_eq!(
        cancelled.settlement().evidence(),
        &IoEvidence::Read {
            requested: 16,
            returned: b"payload".to_vec(),
            ended: false,
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let record = resource.account().durable_record();
    let mut second = fixture.service(IoOperation::Read);
    let refused = second.attempt(resource.resource_mut(), request, &[]);
    assert!(
        matches!(refused, IoCallOutcome::Refused(_)),
        "a cancelled account must refuse a later call, observed {refused:?}"
    );
    assert_eq!(resource.account().durable_record(), record);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A stale completion cannot publish its octets or produce a second settlement.
#[test]
fn a_stale_completion_cannot_publish_or_settle_twice() {
    let tree = TempTree::new();
    let (root, grant) = tree.endpoint_fixture();
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let mut resource = fixture.bind(StaleEndpoint {
        inner: endpoint,
        stale: stale_binding(),
        calls: Arc::clone(&calls),
    });
    let mut service = fixture.service(IoOperation::Read);
    let request = IoRequest::read(16).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let outcome = service.attempt(resource.resource_mut(), request.clone(), &[]);
    let IoCallOutcome::Failed(failed) = outcome else {
        panic!("a stale completion must fail, observed {outcome:?}");
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
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let record = resource.account().durable_record();
    let mut second = fixture.service(IoOperation::Read);
    let refused = second.attempt(resource.resource_mut(), request, &[]);
    assert!(
        matches!(refused, IoCallOutcome::Refused(_)),
        "a contained account must refuse a later call, observed {refused:?}"
    );
    assert_eq!(resource.account().durable_record(), record);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A closed instance refuses every later call and no reconstruction reopens the descriptor.
#[test]
fn a_closed_instance_refuses_later_calls_and_never_reopens() {
    let tree = TempTree::new();
    let (root, grant) = tree.endpoint_fixture();
    let fixture = Fixture::new();
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = endpoint.receipt();
    let mut resource = fixture.bind(endpoint);
    let mut service = fixture.service(IoOperation::Read);
    let request = IoRequest::read(16).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let outcome = service.attempt(resource.resource_mut(), request.clone(), &[]);
    let IoCallOutcome::Settled(settlement) = outcome else {
        panic!("the first read must settle, observed {outcome:?}");
    };
    assert_eq!(
        settlement.evidence(),
        &IoEvidence::Read {
            requested: 16,
            returned: b"payload".to_vec(),
            ended: false,
        }
    );
    drop(service);
    let lifetime = close_read_only(&mut resource, &grant, &receipt, fixture.owner, 9)
        .unwrap_or_else(|error| panic!("fixture close: {error:?}"));
    assert_eq!(lifetime, ResourceLifetimeState::Finished);
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Finished
    );
    let mut second = fixture.service(IoOperation::Read);
    let refused = second.attempt(resource.resource_mut(), request, &[]);
    assert!(
        matches!(refused, IoCallOutcome::Refused(_)),
        "a closed account must refuse a later call, observed {refused:?}"
    );
    let record = resource.account().durable_record();
    let reopened = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture reopen: {error:?}"));
    if let Ok(account) = AdmittedResource::admit(
        ResourceCarrier::ReconstructionRecord,
        record,
        fixture.subject.clone(),
    ) {
        assert!(
            OwnedHostResource::bind(account, reopened).is_err(),
            "a finished account must not accept a live descriptor"
        );
    }
}

/// A named pipe is refused as a non-regular object and never blocks acquisition.
#[test]
fn a_named_pipe_is_refused_without_blocking() {
    let tree = TempTree::new();
    let pipe = tree.root.join("pipe");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        pipe.as_path(),
        FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .unwrap_or_else(|error| panic!("fixture pipe: {error}"));
    let root = FsRootDirectory::mount("data", &tree.root)
        .unwrap_or_else(|error| panic!("fixture mount: {error:?}"));
    let path =
        FsPath::rooted("data", &["pipe"]).unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::NotRegularFile { position: 0 })
    );
}

/// A write request is refused by the read-only grant before any endpoint dispatch.
///
/// The endpoint counts every dispatched call, so a zero count proves the refusal happened in the
/// grant preflight rather than in a host call. The durable record is compared before and after so no
/// accounting fact moved either, which is the property the earlier defect violated.
#[test]
fn a_write_request_is_refused_without_dispatch_or_accounting_movement() {
    let tree = TempTree::new();
    let (root, grant) = tree.endpoint_fixture();
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicU64::new(0));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = endpoint.receipt();
    let mut instance = fixture.bind(CountingEndpoint {
        inner: endpoint,
        calls: Arc::clone(&calls),
    });
    let record = instance.account().durable_record();
    let settlement = FsReadOnlySettlement::new(
        &grant,
        &fixture.machine,
        fixture.owner,
        allowance(8),
        Vec::new(),
        5,
    )
    .unwrap_or_else(|error| panic!("fixture settlement: {error:?}"));
    let request = IoRequest::write(4).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    assert_eq!(
        settlement.read(&mut instance, &receipt, request),
        Err(FsRuntimeRefusal::ReadOnlyGrantDenied {
            operation: FsResourceOperation::Write,
        })
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(instance.account().durable_record(), record);
    assert_eq!(
        instance.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
}

/// A close presenting another open instance receipt is refused and preserves the account.
///
/// The second open names the same root, path, and mapping, so only the open-instance identity
/// differs. The refusal must precede accounting, leaving the first instance active with an identical
/// durable record rather than stranding it in a finishing state.
#[test]
fn a_wrong_instance_close_is_refused_and_preserves_the_account() {
    let tree = TempTree::new();
    let (root, grant) = tree.endpoint_fixture();
    let fixture = Fixture::new();
    let first = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let first_receipt = first.receipt();
    let second = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let second_receipt = second.receipt();
    drop(second);
    let mut instance = fixture.bind(first);
    let record = instance.account().durable_record();
    assert_eq!(
        close_read_only(&mut instance, &grant, &second_receipt, fixture.owner, 11),
        Err(FsRuntimeRefusal::ForeignInstance)
    );
    assert_eq!(
        instance.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );
    assert_eq!(instance.account().durable_record(), record);
    let lifetime = close_read_only(&mut instance, &grant, &first_receipt, fixture.owner, 12)
        .unwrap_or_else(|error| panic!("fixture close: {error:?}"));
    assert_eq!(lifetime, ResourceLifetimeState::Finished);
}
