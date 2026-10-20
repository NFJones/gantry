//! Public-surface conformance for the rooted read-only filesystem integration.
//!
//! These rows exercise the published runtime surface over real host directories: one declared root,
//! one declared path value, one read-only grant, one bounded read settled through the public
//! settlement service, one close, and the refusals of the declaration model. They cover path escape,
//! link refusal, a concurrent link swap, read-only denial, short reads and end of stream, the
//! delivered target mappings, and the fact that accounting never reconstructs a live descriptor.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, DisclosureCharge, EffectSet, ExecutableAction,
    ExecutableOperation, ExternalOutcome, FS_RESOLUTION_COUNT, FsAction, FsDiagnosticCode, FsPath,
    FsResourceOperation, Instruction, InstructionKind, IoOperation, IoRequest, LivenessRoot,
    LoanId, LogicalOperationId, MachineProgram, ObservationAllowance, OperationAbi, OperationKind,
    OwnerGeneration, ProgressObservation, ReceiverOwnership, ResourceCarrier, ResourceGenerationId,
    ResourceLedger, ResourceLifetimeState, ResourceState, StaticSiteId, StructuralPosition,
    TypeDescriptor, Workflow, fs_durable_carrier_is_admissible,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    AdmittedResource, BoundedIoEndpoint, FsHostTarget, FsOpenInstance, FsReadOnlyGrant,
    FsReadOnlyInstance, FsReadOnlySettlement, FsRootDirectory, FsRuntimeRefusal, FsTargetMapping,
    IoCallBinding, IoCallOutcome, IoEvidence, IoHostCompletion, IoOccurrence, IoOperationalFault,
    Machine, MachineLimits, close_read_only, decode_resource_reconstruction_record,
    encode_resource_reconstruction_record,
};
use gantry::value::DEFAULT_VALUE_LIMITS;

/// One canonical fixture path.
fn path(name: &str) -> CanonicalPath {
    CanonicalPath::new(name).unwrap_or_else(|error| panic!("fixture path: {error}"))
}

/// One structural fixture site.
fn site(index: u64) -> StructuralPosition {
    StructuralPosition::new(vec![index]).unwrap_or_else(|error| panic!("fixture site: {error}"))
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
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x47; 32])
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

/// One machine pending occurrence and one accounting record.
struct Fixture {
    machine: Machine,
    owner: OwnerGeneration,
    subject: gantry::runtime::ResourceSubjectBinding,
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

    /// Admits one read-only settlement route over one issued grant.
    fn settlement<'a>(&'a self, grant: &'a FsReadOnlyGrant) -> FsReadOnlySettlement<'a> {
        FsReadOnlySettlement::new(
            grant,
            &self.machine,
            self.owner,
            allowance(8),
            Vec::new(),
            7,
        )
        .unwrap_or_else(|error| panic!("fixture settlement: {error:?}"))
    }
}

/// One synthetic exclusive receiver loan of one sealed generation.
fn loan_live() -> gantry::ir::LiveResource {
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
    abi.open_live(OwnerGeneration::new(2), allowance(2))
        .unwrap_or_else(|error| panic!("fixture loan: {error:?}"))
}

/// One bound read call of `quantity` octets over a synthetic loan.
fn read_binding(quantity: u64) -> IoCallBinding {
    let live = loan_live();
    let occurrence = IoOccurrence::authenticate(&live, IoOperation::Read)
        .unwrap_or_else(|error| panic!("fixture occurrence: {error:?}"));
    IoCallBinding::bind(
        occurrence,
        IoRequest::read(quantity).unwrap_or_else(|error| panic!("fixture request: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("fixture binding: {error:?}"))
}

/// One bound write call of `quantity` octets over a synthetic loan.
fn write_binding(quantity: u64) -> IoCallBinding {
    let live = loan_live();
    let occurrence = IoOccurrence::authenticate(&live, IoOperation::Write)
        .unwrap_or_else(|error| panic!("fixture occurrence: {error:?}"));
    IoCallBinding::bind(
        occurrence,
        IoRequest::write(quantity).unwrap_or_else(|error| panic!("fixture request: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("fixture binding: {error:?}"))
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
            "gantry-fs-conformance-{}-{ordinal}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("temporary root: {error}"));
        Self { root }
    }

    /// Returns the host directory this tree owns.
    fn path(&self) -> &std::path::Path {
        &self.root
    }

    /// Mounts this tree as the declared root `data`.
    fn mount(&self) -> FsRootDirectory {
        FsRootDirectory::mount("data", &self.root)
            .unwrap_or_else(|error| panic!("fixture mount: {error:?}"))
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The next temporary tree ordinal.
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// One rooted read publishes exactly the initialized octets and never promotes a short read to EOF.
#[test]
fn a_rooted_read_publishes_exactly_the_initialized_octets() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"hello")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    assert_eq!(root.name(), "data");
    assert_eq!(root.target(), FsHostTarget::current());
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = endpoint.receipt();
    assert_eq!(endpoint.calls(), 0);
    let fixture = Fixture::new();
    let mut resource = fixture.bind(endpoint);
    let request = IoRequest::read(8).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let outcome = fixture
        .settlement(&grant)
        .read(&mut resource, &receipt, request.clone())
        .unwrap_or_else(|error| panic!("fixture read: {error:?}"));
    let IoCallOutcome::Settled(settlement) = outcome else {
        panic!("one read must settle, observed {outcome:?}");
    };
    assert_eq!(settlement.outcome(), ExternalOutcome::Accepted);
    assert_eq!(settlement.progress(), ProgressObservation::ShortRead);
    assert_eq!(settlement.settled_at_us(), 7);
    assert_eq!(
        settlement.evidence(),
        &IoEvidence::Read {
            requested: 8,
            returned: b"hello".to_vec(),
            ended: false,
        }
    );
    let refused = fixture
        .settlement(&grant)
        .read(&mut resource, &receipt, request)
        .unwrap_or_else(|error| panic!("fixture refusal: {error:?}"));
    assert!(
        matches!(refused, IoCallOutcome::Refused(_)),
        "one settled call must close the admitted occurrence, observed {refused:?}"
    );
    let lifetime = close_read_only(&mut resource, &grant, &receipt, fixture.owner, 11)
        .unwrap_or_else(|error| panic!("fixture close: {error:?}"));
    assert_eq!(lifetime, ResourceLifetimeState::Finished);
}

/// A short read publishes no remainder, and only a zero-octet read observes end of stream.
#[test]
fn a_short_read_publishes_no_remainder_and_a_later_call_is_new() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"abcdef")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let mut endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let first = endpoint.attempt(&read_binding(4), &[]);
    assert_eq!(
        first.completion(),
        &IoHostCompletion::Read {
            advanced: 4,
            bytes: b"abcd".to_vec(),
            ended: false,
        }
    );
    let second = endpoint.attempt(&read_binding(8), &[]);
    assert_eq!(
        second.completion(),
        &IoHostCompletion::Read {
            advanced: 2,
            bytes: b"ef".to_vec(),
            ended: false,
        }
    );
    let third = endpoint.attempt(&read_binding(8), &[]);
    assert_eq!(
        third.completion(),
        &IoHostCompletion::Read {
            advanced: 0,
            bytes: Vec::new(),
            ended: true,
        }
    );
    assert_eq!(endpoint.calls(), 3);
    let refused = endpoint.attempt(&write_binding(4), &[]);
    assert_eq!(
        refused.completion(),
        &IoHostCompletion::Operational(IoOperationalFault::UnsupportedRequest {
            operation: IoOperation::Write,
        })
    );
    assert_eq!(endpoint.calls(), 3);
}

/// Every mutating action and operation is denied by the grant before execution.
#[test]
fn read_only_grants_refuse_each_mutating_operation_before_execution() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"payload")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        FsAction::Read.declared_recovery_class(),
        RecoveryClass::ReadOnly
    );
    for action in FsAction::ALL {
        let expected = match action {
            FsAction::Read => Ok(()),
            other => Err(FsRuntimeRefusal::ReadOnlyActionDenied { action: other }),
        };
        assert_eq!(grant.admit_action(action), expected);
    }
    for operation in FsResourceOperation::ALL {
        let expected = match operation {
            FsResourceOperation::Open | FsResourceOperation::Read | FsResourceOperation::Close => {
                Ok(())
            }
            FsResourceOperation::Write | FsResourceOperation::Truncate => {
                Err(FsRuntimeRefusal::ReadOnlyGrantDenied { operation })
            }
            other => Err(FsRuntimeRefusal::Undelivered { operation: other }),
        };
        assert_eq!(grant.authorize(operation), expected);
    }
    assert_eq!(
        grant.admit_request(
            &IoRequest::write(4).unwrap_or_else(|error| panic!("fixture request: {error:?}"))
        ),
        Err(FsRuntimeRefusal::ReadOnlyGrantDenied {
            operation: FsResourceOperation::Write,
        })
    );
    assert_eq!(
        grant.admit_request(&IoRequest::seek(0)),
        Err(FsRuntimeRefusal::Undelivered {
            operation: FsResourceOperation::Seek,
        })
    );
    assert_eq!(
        std::fs::read(tree.path().join("notes.txt"))
            .unwrap_or_else(|error| panic!("fixture read: {error}")),
        b"payload".to_vec()
    );
}

/// A write request is refused before any endpoint dispatch or accounting transition.
#[test]
fn a_write_request_is_refused_before_dispatch() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"payload")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = endpoint.receipt();
    let fixture = Fixture::new();
    let mut resource = fixture.bind(endpoint);
    let record = resource.account().durable_record();
    let request = IoRequest::write(4).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    assert_eq!(
        fixture
            .settlement(&grant)
            .read(&mut resource, &receipt, request),
        Err(FsRuntimeRefusal::ReadOnlyGrantDenied {
            operation: FsResourceOperation::Write,
        })
    );
    assert_eq!(resource.account().durable_record(), record);
    // The account admits exactly one settlement, so a read that still settles proves the refused
    // write never reached dispatch, charge, or settlement.
    let read = IoRequest::read(16).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let outcome = fixture
        .settlement(&grant)
        .read(&mut resource, &receipt, read)
        .unwrap_or_else(|error| panic!("fixture read: {error:?}"));
    assert!(
        matches!(outcome, IoCallOutcome::Settled(_)),
        "the refused write must leave the one admitted read available, observed {outcome:?}"
    );
}

/// A declared path value cannot escape its mounted root through a reserved component or a link.
#[test]
fn a_declared_path_value_cannot_escape_its_mounted_root() {
    let tree = TempTree::new();
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("outside: {error}"));
    std::fs::write(outside.join("secret.txt"), b"secret")
        .unwrap_or_else(|error| panic!("outside file: {error}"));
    let root = tree.mount();
    std::os::unix::fs::symlink(outside.join("secret.txt"), tree.path().join("escape"))
        .unwrap_or_else(|error| panic!("escape link: {error}"));
    std::os::unix::fs::symlink(&outside, tree.path().join("linkdir"))
        .unwrap_or_else(|error| panic!("directory link: {error}"));
    std::fs::create_dir_all(tree.path().join("sub"))
        .unwrap_or_else(|error| panic!("subdirectory: {error}"));
    let escape = FsPath::rooted("data", &["escape"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&escape)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::LinkRefused { position: 0 })
    );
    let through = FsPath::rooted("data", &["linkdir", "secret.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&through)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::LinkRefused { position: 0 })
    );
    let absent = FsPath::rooted("data", &["missing.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&absent)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::TargetStateUnadmitted { position: 0 })
    );
    let directory =
        FsPath::rooted("data", &["sub"]).unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&directory)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::NotRegularFile { position: 0 })
    );
    let foreign = FsPath::rooted("other", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    assert_eq!(
        root.issue_grant(&foreign).err(),
        Some(FsRuntimeRefusal::ForeignRoot {
            declared: "other".to_owned(),
            mounted: "data".to_owned(),
        })
    );
    let refused = FsPath::rooted("data", &[".."])
        .err()
        .unwrap_or_else(|| panic!("a reserved component must be refused"));
    assert_eq!(refused.code(), FsDiagnosticCode::PathEscape);
    assert_eq!(refused.position(), 0);
}

/// A grant is bound to the exact mounted root instance that issued it.
#[test]
fn a_grant_from_another_root_instance_cannot_open() {
    let first = TempTree::new();
    let second = TempTree::new();
    std::fs::write(first.path().join("notes.txt"), b"first")
        .unwrap_or_else(|error| panic!("first file: {error}"));
    std::fs::write(second.path().join("notes.txt"), b"second")
        .unwrap_or_else(|error| panic!("second file: {error}"));
    let first_root = first.mount();
    let second_root = second.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let foreign = second_root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert_eq!(
        first_root.open_read_only(&foreign).err(),
        Some(FsRuntimeRefusal::ForeignGrant {
            root: "data".to_owned(),
        })
    );
    let own = first_root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    assert!(first_root.open_read_only(&own).is_ok());
}

/// A foreign grant or receipt cannot close an instance, and predispatch refusal preserves it.
#[test]
fn a_foreign_grant_or_receipt_cannot_close_the_instance() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"notes")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    std::fs::write(tree.path().join("other.txt"), b"other")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let notes = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let other = FsPath::rooted("data", &["other.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let notes_grant = root
        .issue_grant(&notes)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let other_grant = root
        .issue_grant(&other)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let other_endpoint = root
        .open_read_only(&other_grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let other_receipt = other_endpoint.receipt();
    drop(other_endpoint);
    let notes_endpoint = root
        .open_read_only(&notes_grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = notes_endpoint.receipt();
    let second_endpoint = root
        .open_read_only(&notes_grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let second_receipt = second_endpoint.receipt();
    drop(second_endpoint);
    let fixture = Fixture::new();
    let mut resource = fixture.bind(notes_endpoint);

    // A grant that does not cover the presented receipt is refused before accounting moves.
    assert_eq!(
        close_read_only(
            &mut resource,
            &notes_grant,
            &other_receipt,
            fixture.owner,
            11
        ),
        Err(FsRuntimeRefusal::ForeignInstance)
    );
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );

    // The read route applies the same grant, receipt, and bound-endpoint preflight.
    let request =
        || IoRequest::read(4).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    assert_eq!(
        fixture
            .settlement(&notes_grant)
            .read(&mut resource, &other_receipt, request()),
        Err(FsRuntimeRefusal::ForeignInstance)
    );
    assert_eq!(
        fixture
            .settlement(&other_grant)
            .read(&mut resource, &receipt, request()),
        Err(FsRuntimeRefusal::ForeignInstance)
    );
    assert_eq!(
        fixture
            .settlement(&notes_grant)
            .read(&mut resource, &second_receipt, request()),
        Err(FsRuntimeRefusal::ForeignInstance)
    );
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Active
    );

    let lifetime = close_read_only(&mut resource, &notes_grant, &receipt, fixture.owner, 12)
        .unwrap_or_else(|error| panic!("fixture close: {error:?}"));
    assert_eq!(lifetime, ResourceLifetimeState::Finished);
}

/// One resolved descriptor stays pinned to its object when the declared path is replaced.
#[test]
fn a_resolved_component_stays_pinned_when_the_declared_path_is_replaced() {
    let tree = TempTree::new();
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(tree.path().join("sub"))
        .unwrap_or_else(|error| panic!("subdirectory: {error}"));
    std::fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("outside: {error}"));
    std::fs::write(tree.path().join("sub").join("file"), b"inside")
        .unwrap_or_else(|error| panic!("inside file: {error}"));
    std::fs::write(outside.join("file"), b"outside")
        .unwrap_or_else(|error| panic!("outside file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["sub", "file"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let mut endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let first = endpoint.attempt(&read_binding(4), &[]);
    assert_eq!(
        first.completion(),
        &IoHostCompletion::Read {
            advanced: 4,
            bytes: b"insi".to_vec(),
            ended: false,
        }
    );
    std::fs::rename(tree.path().join("sub"), tree.path().join("old-sub"))
        .unwrap_or_else(|error| panic!("rename: {error}"));
    std::os::unix::fs::symlink(&outside, tree.path().join("sub"))
        .unwrap_or_else(|error| panic!("replacement link: {error}"));
    let second = endpoint.attempt(&read_binding(16), &[]);
    assert_eq!(
        second.completion(),
        &IoHostCompletion::Read {
            advanced: 2,
            bytes: b"de".to_vec(),
            ended: false,
        }
    );
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::LinkRefused { position: 0 })
    );
}

/// A pinned descriptor orders bytes of the same inode and never claims a content snapshot.
#[test]
fn a_pinned_descriptor_does_not_claim_content_immutability() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"abc")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let mut endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let first = endpoint.attempt(&read_binding(3), &[]);
    assert_eq!(
        first.completion(),
        &IoHostCompletion::Read {
            advanced: 3,
            bytes: b"abc".to_vec(),
            ended: false,
        }
    );
    std::fs::write(tree.path().join("notes.txt"), b"abcdef")
        .unwrap_or_else(|error| panic!("in-place write: {error}"));
    let second = endpoint.attempt(&read_binding(3), &[]);
    assert_eq!(
        second.completion(),
        &IoHostCompletion::Read {
            advanced: 3,
            bytes: b"def".to_vec(),
            ended: false,
        }
    );
}

/// A concurrent link swap never redirects a read and never follows the replacement.
#[test]
fn a_concurrent_symlink_swap_never_redirects_a_read() {
    let tree = TempTree::new();
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("outside: {error}"));
    std::fs::write(outside.join("file"), b"outside")
        .unwrap_or_else(|error| panic!("outside file: {error}"));
    let staged = tree.path().join("staged");
    std::fs::create_dir_all(&staged).unwrap_or_else(|error| panic!("staged: {error}"));
    std::fs::write(staged.join("file"), b"inside")
        .unwrap_or_else(|error| panic!("staged file: {error}"));
    let race = tree.path().join("race");
    std::fs::rename(&staged, &race).unwrap_or_else(|error| panic!("publish: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["race", "file"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let binding = read_binding(16);
    let mut endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let response = endpoint.attempt(&binding, &[]);
    assert_eq!(
        response.completion(),
        &IoHostCompletion::Read {
            advanced: 6,
            bytes: b"inside".to_vec(),
            ended: false,
        }
    );
    std::fs::rename(&race, &staged).unwrap_or_else(|error| panic!("withdraw: {error}"));
    std::os::unix::fs::symlink(&outside, &race)
        .unwrap_or_else(|error| panic!("replacement link: {error}"));
    assert_eq!(
        root.open_read_only(&grant).err(),
        Some(FsRuntimeRefusal::LinkRefused { position: 0 })
    );
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let staged = staged.clone();
        let race = race.clone();
        let outside = outside.clone();
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let _ = std::fs::remove_file(&race);
                let _ = std::fs::rename(&staged, &race);
                let _ = std::fs::rename(&race, &staged);
                let _ = std::fs::remove_file(&race);
                let _ = std::os::unix::fs::symlink(&outside, &race);
                let _ = std::fs::remove_file(&race);
            }
        })
    };
    for _ in 0..200 {
        match root.open_read_only(&grant) {
            Ok(mut endpoint) => {
                let response = endpoint.attempt(&binding, &[]);
                match response.completion() {
                    IoHostCompletion::Read { bytes, .. } => {
                        assert_eq!(
                            bytes,
                            &b"inside".to_vec(),
                            "a resolved descriptor must never observe the replacement object"
                        );
                    }
                    other => panic!("unexpected completion: {other:?}"),
                }
            }
            Err(
                FsRuntimeRefusal::LinkRefused { .. }
                | FsRuntimeRefusal::NotDirectory { .. }
                | FsRuntimeRefusal::TargetStateUnadmitted { .. },
            ) => {}
            Err(other) => panic!("unexpected refusal: {other:?}"),
        }
    }
    stop.store(true, Ordering::SeqCst);
    churn
        .join()
        .unwrap_or_else(|error| panic!("churn thread failed: {error:?}"));
}

/// Accounting records carry no live descriptor and no declared path spelling.
#[test]
fn accounting_records_carry_no_live_handle_or_path_spelling() {
    assert_eq!(ResourceCarrier::ALL.len(), 3);
    assert!(fs_durable_carrier_is_admissible(
        ResourceCarrier::ReconstructionRecord
    ));
    assert!(!fs_durable_carrier_is_admissible(
        ResourceCarrier::OrdinarySerialization
    ));
    assert!(!fs_durable_carrier_is_admissible(
        ResourceCarrier::OrdinaryDurableState
    ));
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"payload")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = endpoint.receipt();
    let fixture = Fixture::new();
    let mut resource = fixture.bind(endpoint);
    let request = IoRequest::read(16).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let outcome = fixture
        .settlement(&grant)
        .read(&mut resource, &receipt, request)
        .unwrap_or_else(|error| panic!("fixture read: {error:?}"));
    assert!(
        matches!(outcome, IoCallOutcome::Settled(_)),
        "the durability lane needs one settled read, observed {outcome:?}"
    );
    let record = resource.account().durable_record();
    let encoded = encode_resource_reconstruction_record(&record);
    let text = String::from_utf8_lossy(&encoded);
    assert!(
        !text.contains("notes.txt"),
        "a path segment entered the record"
    );
    assert!(
        !text.contains("data/notes.txt"),
        "a path spelling entered the record"
    );
    let decoded = decode_resource_reconstruction_record(&encoded)
        .unwrap_or_else(|error| panic!("fixture decode: {error:?}"));
    assert_eq!(decoded, record);
    assert_eq!(record, resource.account().durable_record());
}

/// Only the Linux mapping is delivered, and every other target refuses before execution.
///
/// macOS is refused because no effect-free no-follow acquisition method for it is established: an
/// `O_EVTONLY` probe still reaches FIFO reader wait and device `d_open`, so claiming delivery would
/// claim an equivalence this slice cannot test. The refusal is an initial runtime availability
/// limit of this slice, recorded as a typed preflight outcome before any descriptor exists.
#[test]
fn only_the_linux_mapping_is_delivered_and_other_targets_refuse() {
    let linux = FsHostTarget::Linux
        .walk_policy()
        .unwrap_or_else(|| panic!("the linux mapping must be delivered"));
    assert!(linux.no_follow_components());
    assert!(linux.directory_components());
    assert!(linux.close_on_exec());
    assert_eq!(linux.resolution_count(), FS_RESOLUTION_COUNT);
    assert!(
        FsHostTarget::MacOs.walk_policy().is_none(),
        "macos must not claim a delivered mapping without an effect-free acquisition"
    );
    assert_eq!(
        FsTargetMapping::admit(FsHostTarget::MacOs).err(),
        Some(FsRuntimeRefusal::UnsupportedTarget {
            target: FsHostTarget::MacOs,
        })
    );
    assert!(FsHostTarget::Unsupported.walk_policy().is_none());
    assert_eq!(
        FsTargetMapping::admit(FsHostTarget::Unsupported).err(),
        Some(FsRuntimeRefusal::UnsupportedTarget {
            target: FsHostTarget::Unsupported,
        })
    );
    if cfg!(target_os = "linux") {
        assert_eq!(FsHostTarget::current(), FsHostTarget::Linux);
    }
    if cfg!(target_os = "macos") {
        assert_eq!(FsHostTarget::current(), FsHostTarget::MacOs);
        assert!(
            FsTargetMapping::for_current().is_err(),
            "the macos process target must be refused before acquisition"
        );
    }
}

/// Closing an instance releases it once, and no later call is admitted.
#[test]
fn close_releases_the_instance_once_and_refuses_later_calls() {
    let tree = TempTree::new();
    std::fs::write(tree.path().join("notes.txt"), b"hello")
        .unwrap_or_else(|error| panic!("fixture file: {error}"));
    let root = tree.mount();
    let path = FsPath::rooted("data", &["notes.txt"])
        .unwrap_or_else(|error| panic!("fixture path: {error:?}"));
    let grant = root
        .issue_grant(&path)
        .unwrap_or_else(|error| panic!("fixture grant: {error:?}"));
    let endpoint = root
        .open_read_only(&grant)
        .unwrap_or_else(|error| panic!("fixture open: {error:?}"));
    let receipt = endpoint.receipt();
    let fixture = Fixture::new();
    let mut resource = fixture.bind(endpoint);
    let lifetime = close_read_only(&mut resource, &grant, &receipt, fixture.owner, 11)
        .unwrap_or_else(|error| panic!("fixture close: {error:?}"));
    assert_eq!(lifetime, ResourceLifetimeState::Finished);
    assert_eq!(
        resource.account().ledger().lifetime(),
        ResourceLifetimeState::Finished
    );
    assert!(
        close_read_only(&mut resource, &grant, &receipt, fixture.owner, 12).is_err(),
        "a finished instance must not close twice"
    );
    let request = IoRequest::read(4).unwrap_or_else(|error| panic!("fixture request: {error:?}"));
    let record = resource.account().durable_record();
    let refused = fixture
        .settlement(&grant)
        .read(&mut resource, &receipt, request)
        .unwrap_or_else(|error| panic!("fixture refusal: {error:?}"));
    assert!(
        matches!(refused, IoCallOutcome::Refused(_)),
        "a closed account must refuse a later call, observed {refused:?}"
    );
    assert_eq!(resource.account().durable_record(), record);
}
