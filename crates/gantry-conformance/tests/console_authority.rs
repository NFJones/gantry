//! Conformance for the declared `std.console` signatures, requirement groups, and authority.
//!
//! The lane pins the five declared signature shapes and their exact operation identities, the
//! four separately granted requirement groups, and the admission refusals of `GNT-46.8` and
//! `GNT-46.9` over `crates/gantry-ir/src/console.rs`. It performs no host I/O and claims no
//! terminal, adapter, capability, or runtime behavior.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CONSOLE_CLAUSES, CONSOLE_CONTROL_OCTET, CONSOLE_ITEMS, CONSOLE_SIGNATURE_VERSION,
    ConsoleAccessIdentity, ConsoleAccessInjection, ConsoleAuthorityDiagnosticCode,
    ConsoleAuthorityError, ConsoleCallError, ConsoleControlFlags, ConsoleFlushOutcome,
    ConsoleGrant, ConsoleOperation, ConsoleOutputTarget, ConsoleReceiver, ConsoleRequirementGroup,
    ConsoleResultShape, ConsoleShutdownSettlement, ConsoleSignature, IO_REQUEST_OCTET_BOUND,
    IoDiagnosticCode, IoError, IoRequest, admit_console_requirement_groups, admit_console_set_mode,
    admit_console_signatures, admit_console_write, console_octets_carry_control,
    declare_console_requirement_groups, declare_console_signatures,
};

const GRANTOR: &str = "launch";
const REQUESTER: &str = "task";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn injection_for(groups: &[ConsoleRequirementGroup]) -> ConsoleAccessInjection {
    let grants = groups
        .iter()
        .map(|group| ConsoleGrant::new(*group, REQUESTER, GRANTOR))
        .collect::<Vec<_>>();
    ConsoleAccessInjection::from_launch(GRANTOR, grants)
}

fn output_grant() -> ConsoleGrant {
    ConsoleGrant::new(ConsoleRequirementGroup::OutputFlush, REQUESTER, GRANTOR)
}

/// Returns the one admitted write request declaring exactly the presented octets.
fn octets_request(octets: &[u8]) -> IoRequest {
    let count = match u64::try_from(octets.len()) {
        Ok(count) => count,
        Err(error) => panic!("the presented octet count is not a quantity: {error}"),
    };
    match IoRequest::write(count) {
        Ok(request) => request,
        Err(error) => panic!("the presented octet count must be admissible: {error:?}"),
    }
}

/// Returns the console authority refusal of one write call that must be refused.
fn call_refusal<T>(result: Result<T, ConsoleCallError>) -> ConsoleAuthorityError {
    match result {
        Ok(_) => panic!("the declared console write must be refused"),
        Err(ConsoleCallError::Authority(error)) => error,
        Err(ConsoleCallError::Request(error)) => {
            panic!("the console write must be refused by this section: {error:?}")
        }
    }
}

#[test]
fn console_authority_clauses_are_published() {
    assert_eq!(CONSOLE_CLAUSES.len(), 10);
    assert_eq!(CONSOLE_CLAUSES[6], "GNT-46.6-console-operation-signatures");
    assert_eq!(CONSOLE_CLAUSES[7], "GNT-46.7-console-requirement-groups");
    assert_eq!(CONSOLE_CLAUSES[8], "GNT-46.8-console-authority-admission");
    assert_eq!(
        CONSOLE_CLAUSES[9],
        "GNT-46.9-console-control-and-output-boundary"
    );
    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in CONSOLE_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for phrase in [
        "Input receiver loan, bounded request",
        "accepted-prefix receipt",
        "typed echo/canonical-input flags",
        "no group implies another",
        "ambient numeric descriptor",
        "the refusal is byte-preserving",
        "unsupported safe output refuses",
    ] {
        assert!(
            specification.contains(phrase),
            "the specification must publish the clause text {phrase}"
        );
    }
}

#[test]
fn console_signatures_declare_the_five_selected_shapes() {
    let declared = declare_console_signatures();
    assert_eq!(declared, ConsoleSignature::ALL);
    assert_eq!(CONSOLE_SIGNATURE_VERSION, 1);
    let identities = declared
        .iter()
        .map(|signature| signature.identity())
        .collect::<Vec<_>>();
    assert_eq!(
        identities,
        [
            "std.console::input::read@1",
            "std.console::output::write@1",
            "std.console::output::flush@1",
            "std.console::terminal::inspect@1",
            "std.console::control::set_mode@1",
        ]
    );
    assert_eq!(
        ConsoleSignature::InputRead.receiver(),
        ConsoleReceiver::InputLoan
    );
    assert_eq!(
        ConsoleSignature::OutputWrite.receiver(),
        ConsoleReceiver::OutputLoan
    );
    assert_eq!(
        ConsoleSignature::OutputFlush.receiver(),
        ConsoleReceiver::OutputLoan
    );
    assert_eq!(
        ConsoleSignature::TerminalInspect.receiver(),
        ConsoleReceiver::Observation
    );
    assert_eq!(
        ConsoleSignature::ControlSetMode.receiver(),
        ConsoleReceiver::Control
    );
    assert_eq!(
        ConsoleSignature::InputRead.result(),
        ConsoleResultShape::ChunkOrError
    );
    assert_eq!(
        ConsoleSignature::OutputWrite.result(),
        ConsoleResultShape::AcceptedPrefixReceiptOrError
    );
    assert_eq!(
        ConsoleSignature::OutputFlush.result(),
        ConsoleResultShape::UnitOrError
    );
    assert_eq!(
        ConsoleSignature::TerminalInspect.result(),
        ConsoleResultShape::TerminalReportOrError
    );
    assert_eq!(
        ConsoleSignature::InputRead.declared_recovery_class(),
        RecoveryClass::NonIdempotent
    );
    assert_eq!(
        ConsoleSignature::OutputWrite.declared_recovery_class(),
        RecoveryClass::NonIdempotent
    );
    assert_eq!(
        ConsoleSignature::OutputFlush.declared_recovery_class(),
        RecoveryClass::Idempotent
    );
    assert_eq!(
        ConsoleSignature::TerminalInspect.declared_recovery_class(),
        RecoveryClass::ReadOnly
    );
    assert_eq!(
        ConsoleSignature::ControlSetMode.declared_recovery_class(),
        RecoveryClass::Idempotent
    );
    assert!(ConsoleSignature::ControlSetMode.declares_control_flags());
    assert!(!ConsoleSignature::InputRead.declares_control_flags());
    assert!(ConsoleSignature::InputRead.consumes_request());
    assert!(!ConsoleSignature::OutputFlush.consumes_request());
}

#[test]
fn inspect_and_control_are_not_console_operation_members() {
    assert_eq!(ConsoleOperation::ALL.len(), 3);
    assert_eq!(
        ConsoleSignature::InputRead.console_operation(),
        Some(ConsoleOperation::Read)
    );
    assert_eq!(
        ConsoleSignature::OutputWrite.console_operation(),
        Some(ConsoleOperation::Write)
    );
    assert_eq!(
        ConsoleSignature::OutputFlush.console_operation(),
        Some(ConsoleOperation::Flush)
    );
    assert_eq!(ConsoleSignature::TerminalInspect.console_operation(), None);
    assert_eq!(ConsoleSignature::ControlSetMode.console_operation(), None);
    let names = ConsoleOperation::ALL
        .iter()
        .map(|operation| operation.wire_name())
        .collect::<Vec<_>>();
    assert_eq!(names, ["read", "write", "flush"]);
}

#[test]
fn console_requirement_groups_bind_exact_operation_identities() {
    let groups = declare_console_requirement_groups();
    assert_eq!(groups, ConsoleRequirementGroup::ALL);
    let names = groups
        .iter()
        .map(|group| group.wire_name())
        .collect::<Vec<_>>();
    assert_eq!(names, ["input", "output-flush", "observation", "control"]);
    let input = ConsoleRequirementGroup::Input
        .signatures()
        .iter()
        .map(|signature| signature.identity())
        .collect::<Vec<_>>();
    assert_eq!(input, ["std.console::input::read@1"]);
    let output = ConsoleRequirementGroup::OutputFlush
        .signatures()
        .iter()
        .map(|signature| signature.identity())
        .collect::<Vec<_>>();
    assert_eq!(
        output,
        [
            "std.console::output::write@1",
            "std.console::output::flush@1",
        ]
    );
    let observation = ConsoleRequirementGroup::Observation
        .signatures()
        .iter()
        .map(|signature| signature.identity())
        .collect::<Vec<_>>();
    assert_eq!(observation, ["std.console::terminal::inspect@1"]);
    let control = ConsoleRequirementGroup::Control
        .signatures()
        .iter()
        .map(|signature| signature.identity())
        .collect::<Vec<_>>();
    assert_eq!(control, ["std.console::control::set_mode@1"]);
    let mut governed = Vec::new();
    for group in groups {
        for signature in group.signatures() {
            assert!(
                !governed.contains(&signature.identity()),
                "two groups must never share an operation identity"
            );
            governed.push(signature.identity());
        }
    }
    let declared = ConsoleSignature::ALL
        .iter()
        .map(|signature| signature.identity())
        .collect::<Vec<_>>();
    assert_eq!(governed.len(), declared.len());
    for identity in declared {
        assert!(governed.contains(&identity), "{identity} must be governed");
    }
}

#[test]
fn console_requirement_groups_imply_no_authority_between_them() {
    for left in ConsoleRequirementGroup::ALL {
        for right in ConsoleRequirementGroup::ALL {
            assert!(
                !left.implies_authority_over(right),
                "{} must not imply authority over {}",
                left.wire_name(),
                right.wire_name()
            );
        }
    }
    assert!(
        !ConsoleRequirementGroup::OutputFlush
            .implies_authority_over(ConsoleRequirementGroup::Control)
    );
    assert!(
        !ConsoleRequirementGroup::Control
            .implies_authority_over(ConsoleRequirementGroup::Observation)
    );
}

#[test]
fn console_signature_surface_refusals_name_the_exact_identity() {
    assert!(admit_console_signatures(&ConsoleSignature::ALL).is_ok());
    let mut partial = ConsoleSignature::ALL.to_vec();
    partial.pop();
    let error = admit_console_signatures(&partial)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::SignatureUndeclared
    );
    assert_eq!(error.observed(), Some("none"));
    assert_eq!(error.declared(), Some("std.console::control::set_mode@1"));
    let mut reordered = ConsoleSignature::ALL.to_vec();
    reordered.swap(0, 1);
    let error = admit_console_signatures(&reordered)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::SignatureUndeclared
    );
    assert_eq!(error.observed(), Some("std.console::output::write@1"));
    assert_eq!(error.declared(), Some("std.console::input::read@1"));
    let mut extra = ConsoleSignature::ALL.to_vec();
    extra.push(ConsoleSignature::InputRead);
    let error = admit_console_signatures(&extra)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(error.observed(), Some("std.console::input::read@1"));
    assert_eq!(error.declared(), Some("none"));
}

#[test]
fn console_requirement_group_surface_refusals_are_exact() {
    assert!(admit_console_requirement_groups(&ConsoleRequirementGroup::ALL).is_ok());
    let mut partial = ConsoleRequirementGroup::ALL.to_vec();
    partial.pop();
    let error = admit_console_requirement_groups(&partial)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::RequirementGroupInconsistent
    );
    assert_eq!(error.observed(), Some("none"));
    assert_eq!(error.declared(), Some("control"));
    let mut reordered = ConsoleRequirementGroup::ALL.to_vec();
    reordered.swap(0, 1);
    let error = admit_console_requirement_groups(&reordered)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(error.observed(), Some("output-flush"));
    assert_eq!(error.declared(), Some("input"));
}

#[test]
fn console_access_admission_requires_launch_injected_grants() {
    let injection = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    let issued = output_grant();
    assert!(
        ConsoleAccessIdentity::Injected(issued)
            .admit(&injection, ConsoleRequirementGroup::OutputFlush)
            .is_ok()
    );
    let read_grant = ConsoleGrant::new(ConsoleRequirementGroup::Input, REQUESTER, GRANTOR);
    let error = ConsoleAccessIdentity::Injected(read_grant)
        .admit(&injection, ConsoleRequirementGroup::Input)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(error.group(), Some(ConsoleRequirementGroup::Input));
    let error = call_refusal(admit_console_write(
        &injection,
        &read_grant,
        &octets_request(b"never delivered"),
        ConsoleOutputTarget::RedirectedNonControlling,
        b"never delivered",
    ));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::RequirementGroupInconsistent
    );
    assert_eq!(error.observed(), Some("input"));
    assert_eq!(error.declared(), Some("output-flush"));
    // The required output-flush group is consulted first, so a write under an injection that
    // issues no output-flush grant still reports the missing required group.
    let input_only = injection_for(&[ConsoleRequirementGroup::Input]);
    let error = call_refusal(admit_console_write(
        &input_only,
        &output_grant(),
        &octets_request(b"never delivered"),
        ConsoleOutputTarget::RedirectedNonControlling,
        b"never delivered",
    ));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(error.group(), Some(ConsoleRequirementGroup::OutputFlush));
}

#[test]
fn forged_console_grants_are_refused() {
    let injection = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    let forged_grantor =
        ConsoleGrant::new(ConsoleRequirementGroup::OutputFlush, REQUESTER, "elsewhere");
    let error = injection
        .admit(&forged_grantor)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityForged
    );
    assert_eq!(error.group(), Some(ConsoleRequirementGroup::OutputFlush));
    let forged_requester =
        ConsoleGrant::new(ConsoleRequirementGroup::OutputFlush, "other-task", GRANTOR);
    let error = injection
        .admit(&forged_requester)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityForged
    );
    let forged_group = ConsoleGrant::new(ConsoleRequirementGroup::Control, REQUESTER, GRANTOR);
    let error = injection
        .admit(&forged_group)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityForged
    );
    assert_eq!(error.group(), Some(ConsoleRequirementGroup::Control));
    let error = ConsoleAccessIdentity::Injected(forged_grantor)
        .admit(&injection, ConsoleRequirementGroup::OutputFlush)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityForged
    );
}

#[test]
fn ambient_numeric_descriptor_access_is_refused() {
    let injection = injection_for(&[ConsoleRequirementGroup::Input]);
    for descriptor in [0, 1, 2] {
        let error = ConsoleAccessIdentity::AmbientDescriptor(descriptor)
            .admit(&injection, ConsoleRequirementGroup::Input)
            .err()
            .unwrap_or_else(|| panic!("expected a console refusal"));
        assert_eq!(
            error.code(),
            ConsoleAuthorityDiagnosticCode::AmbientDescriptor
        );
        assert_eq!(error.descriptor(), Some(descriptor));
        assert_eq!(error.group(), None);
    }
    assert!(
        injection
            .grants()
            .iter()
            .all(|grant| grant.grantor() == GRANTOR)
    );
    assert_eq!(injection.grantor(), GRANTOR);
}

#[test]
fn control_bearing_output_on_a_terminal_is_refused_byte_preservingly() {
    let injection = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    let grant = output_grant();
    let octets = b"\x1b[2Jclear\x1b[0m";
    assert_eq!(CONSOLE_CONTROL_OCTET, 0x1b);
    assert!(console_octets_carry_control(octets));
    let error = call_refusal(admit_console_write(
        &injection,
        &grant,
        &octets_request(octets),
        ConsoleOutputTarget::AttachedTerminal,
        octets,
    ));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::ControlBearingOutputRefused
    );
    assert_eq!(error.preserved_octets(), Some(octets.as_slice()));
    let preserved = error.preserved_octets().unwrap_or_default();
    assert_eq!(preserved.len(), octets.len());
    assert!(preserved.contains(&CONSOLE_CONTROL_OCTET));
    let redirected = admit_console_write(
        &injection,
        &grant,
        &octets_request(octets),
        ConsoleOutputTarget::RedirectedNonControlling,
        octets,
    )
    .unwrap_or_else(|error| panic!("a redirected sink must accept the octets: {error}"));
    assert_eq!(redirected.accepted_prefix(), octets.len());
    let safe = admit_console_write(
        &injection,
        &grant,
        &octets_request(b"plain"),
        ConsoleOutputTarget::AttachedTerminal,
        b"plain",
    )
    .unwrap_or_else(|error| panic!("safe output must reach the terminal: {error}"));
    assert_eq!(safe.accepted_prefix(), 5);
    let with_control = injection_for(&[
        ConsoleRequirementGroup::OutputFlush,
        ConsoleRequirementGroup::Control,
    ]);
    let admitted = admit_console_write(
        &with_control,
        &grant,
        &octets_request(octets),
        ConsoleOutputTarget::AttachedTerminal,
        octets,
    )
    .unwrap_or_else(|error| panic!("an explicit control grant must admit: {error}"));
    assert_eq!(admitted.accepted_prefix(), octets.len());
    let foreign = ConsoleAccessInjection::from_launch(
        GRANTOR,
        vec![
            output_grant(),
            ConsoleGrant::new(ConsoleRequirementGroup::Control, "another", GRANTOR),
        ],
    );
    let error = call_refusal(admit_console_write(
        &foreign,
        &grant,
        &octets_request(octets),
        ConsoleOutputTarget::AttachedTerminal,
        octets,
    ));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::ControlBearingOutputRefused
    );
    assert_eq!(error.preserved_octets(), Some(octets.as_slice()));
}

#[test]
fn unsupported_safe_output_is_refused() {
    let injection = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    assert!(!ConsoleOutputTarget::Unsupported("socket").is_declared());
    assert!(ConsoleOutputTarget::RedirectedNonControlling.is_declared());
    assert!(ConsoleOutputTarget::AttachedTerminal.is_declared());
    let error = call_refusal(admit_console_write(
        &injection,
        &output_grant(),
        &octets_request(b"safe"),
        ConsoleOutputTarget::Unsupported("socket"),
        b"safe",
    ));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::SafeOutputUnsupported
    );
    assert!(!console_octets_carry_control(b"safe"));
}

#[test]
fn flush_failure_cannot_rewrite_a_fixed_task_outcome() {
    let failed = ConsoleShutdownSettlement::settle(ConsoleFlushOutcome::Failed);
    assert_eq!(failed.flush(), ConsoleFlushOutcome::Failed);
    assert!(failed.flush_failed());
    assert!(!failed.task_outcome_rewritten());
    let flushed = ConsoleShutdownSettlement::settle(ConsoleFlushOutcome::Flushed);
    assert_eq!(flushed.flush(), ConsoleFlushOutcome::Flushed);
    assert!(!flushed.flush_failed());
    assert!(!flushed.task_outcome_rewritten());
    assert!(ConsoleFlushOutcome::Failed.is_failure());
    assert!(!ConsoleFlushOutcome::Flushed.is_failure());
    assert!(!ConsoleSignature::OutputFlush.consumes_request());
    assert!(!ConsoleSignature::OutputFlush.declares_control_flags());
}

#[test]
fn control_set_mode_requires_the_control_group_and_typed_flags() {
    assert_eq!(
        ConsoleControlFlags::DECLARED_FLAGS,
        ["echo", "canonical-input"]
    );
    let flags = ConsoleControlFlags::new(true, false);
    assert!(flags.echo());
    assert!(!flags.canonical_input());
    let control = injection_for(&[ConsoleRequirementGroup::Control]);
    let grant = ConsoleGrant::new(ConsoleRequirementGroup::Control, REQUESTER, GRANTOR);
    assert!(admit_console_set_mode(&control, &grant, flags).is_ok());
    let output_only = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    let error = admit_console_set_mode(&output_only, &grant, flags)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(error.group(), Some(ConsoleRequirementGroup::Control));
    let both = injection_for(&[
        ConsoleRequirementGroup::OutputFlush,
        ConsoleRequirementGroup::Control,
    ]);
    let error = admit_console_set_mode(&both, &output_grant(), flags)
        .err()
        .unwrap_or_else(|| panic!("expected a console refusal"));
    assert_eq!(
        error.code(),
        ConsoleAuthorityDiagnosticCode::RequirementGroupInconsistent
    );
    assert_eq!(error.observed(), Some("output-flush"));
    assert_eq!(error.declared(), Some("control"));
}

#[test]
fn console_item_rows_publish_the_signature_and_authority_clauses() {
    assert_eq!(CONSOLE_ITEMS.len(), 4);
    let control = CONSOLE_ITEMS
        .iter()
        .find(|row| row.name == "std.console::control")
        .unwrap_or_else(|| panic!("the control row must be declared"));
    assert!(
        control
            .clauses
            .contains(&"GNT-46.6-console-operation-signatures")
    );
    assert!(
        control
            .clauses
            .contains(&"GNT-46.7-console-requirement-groups")
    );
    assert!(
        control
            .clauses
            .contains(&"GNT-46.8-console-authority-admission")
    );
    assert!(
        control
            .clauses
            .contains(&"GNT-46.9-console-control-and-output-boundary")
    );
    let terminal = CONSOLE_ITEMS
        .iter()
        .find(|row| row.name == "std.console::terminal")
        .unwrap_or_else(|| panic!("the terminal row must be declared"));
    assert!(
        terminal
            .clauses
            .contains(&"GNT-46.6-console-operation-signatures")
    );
    assert!(
        terminal
            .clauses
            .contains(&"GNT-46.7-console-requirement-groups")
    );
    let output = CONSOLE_ITEMS
        .iter()
        .find(|row| row.name == "std.console::output")
        .unwrap_or_else(|| panic!("the output row must be declared"));
    assert!(
        output
            .clauses
            .contains(&"GNT-46.9-console-control-and-output-boundary")
    );
    assert!(
        output
            .clauses
            .contains(&"GNT-46.8-console-authority-admission")
    );
}

#[test]
fn console_write_consumes_one_admitted_bounded_request() {
    let injection = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    let grant = output_grant();
    // Zero and over-bound quantities never become an admitted request at all: Section 45 refuses
    // them under its own bound code, so no console write is presented with one.
    match IoRequest::write(0) {
        Ok(_) => panic!("a zero-quantity write request must be refused"),
        Err(error) => assert_eq!(error.code(), IoDiagnosticCode::RequestBound),
    }
    match IoRequest::write(IO_REQUEST_OCTET_BOUND + 1) {
        Ok(_) => panic!("a write request above the declared bound must be refused"),
        Err(error) => assert_eq!(error.code(), IoDiagnosticCode::RequestBound),
    }
    let bounded = match IoRequest::write(IO_REQUEST_OCTET_BOUND) {
        Ok(request) => request,
        Err(error) => panic!("the declared bound is itself admissible: {error:?}"),
    };
    assert_eq!(bounded.quantity(), IO_REQUEST_OCTET_BOUND);
    // The bound is itself a write the console admits when the request declares exactly the
    // presented octets, so the bound-equal case is exercised through the console write and not
    // only through request admission.
    let bound_len = usize::try_from(IO_REQUEST_OCTET_BOUND)
        .unwrap_or_else(|error| panic!("the declared bound is a buffer length: {error}"));
    let bound_octets = vec![0_u8; bound_len];
    let bound_admitted = admit_console_write(
        &injection,
        &grant,
        &bounded,
        ConsoleOutputTarget::RedirectedNonControlling,
        &bound_octets,
    )
    .unwrap_or_else(|error| panic!("the bound-equal write must be admitted: {error}"));
    assert_eq!(bound_admitted.accepted_prefix(), bound_len);

    // The happy path consumes exactly the admitted request that declares the presented octets.
    let octets = b"123456789";
    let admitted = admit_console_write(
        &injection,
        &grant,
        &octets_request(octets),
        ConsoleOutputTarget::RedirectedNonControlling,
        octets,
    )
    .unwrap_or_else(|error| panic!("the declared write must be admitted: {error}"));
    assert_eq!(admitted.accepted_prefix(), octets.len());
    // A request whose declared quantity is not the presented octet count is refused under the
    // Section 45 mismatch code naming the provided fact, and no octet is delivered.
    let short = octets_request(&octets[..octets.len() - 1]);
    let mismatch = admit_console_write(
        &injection,
        &grant,
        &short,
        ConsoleOutputTarget::RedirectedNonControlling,
        octets,
    )
    .err()
    .unwrap_or_else(|| panic!("a declared quantity that differs must be refused"));
    assert_eq!(
        mismatch.io_code(),
        Some(IoDiagnosticCode::OutcomeRequestMismatch)
    );
    assert!(mismatch.console_code().is_none());
    match mismatch.request() {
        Some(IoError::RequestMismatch { fact, .. }) => assert_eq!(*fact, "provided"),
        other => panic!("the mismatch names the provided fact: {other:?}"),
    }
    // A request of another operation kind is refused before any octet is read out of it.
    let read = match IoRequest::read(2) {
        Ok(request) => request,
        Err(error) => panic!("a two-octet read request is admissible: {error:?}"),
    };
    let wrong_kind = admit_console_write(
        &injection,
        &grant,
        &read,
        ConsoleOutputTarget::RedirectedNonControlling,
        b"ab",
    )
    .err()
    .unwrap_or_else(|| panic!("a read request presented to a write must be refused"));
    assert_eq!(
        wrong_kind.io_code(),
        Some(IoDiagnosticCode::OutcomeRequestMismatch)
    );
    match wrong_kind.request() {
        Some(IoError::RequestMismatch { fact, .. }) => assert_eq!(*fact, "operation"),
        other => panic!("the mismatch names the operation fact: {other:?}"),
    }
}

#[test]
fn console_call_admission_precedence_is_ordered() {
    // (a) The required group carries no injected grant, so missing is reported for the required
    // group before the presented grant is compared with anything.
    let input_only = injection_for(&[ConsoleRequirementGroup::Input]);
    let missing = input_only
        .admit_call(ConsoleRequirementGroup::OutputFlush, &output_grant())
        .err()
        .unwrap_or_else(|| panic!("an unissued required group must be refused"));
    assert_eq!(
        missing.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(missing.group(), Some(ConsoleRequirementGroup::OutputFlush));
    let output_only = injection_for(&[ConsoleRequirementGroup::OutputFlush]);
    let control_grant = ConsoleGrant::new(ConsoleRequirementGroup::Control, REQUESTER, GRANTOR);
    let flags = ConsoleControlFlags::new(false, false);
    let missing_control = admit_console_set_mode(&output_only, &control_grant, flags)
        .err()
        .unwrap_or_else(|| panic!("a set-mode under an output-only injection must be refused"));
    assert_eq!(
        missing_control.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(
        missing_control.group(),
        Some(ConsoleRequirementGroup::Control)
    );
    // (b) The presented grant names another group while the required group is issued, so the
    // inconsistency is reported before any forged verdict is considered.
    let both = injection_for(&[
        ConsoleRequirementGroup::Input,
        ConsoleRequirementGroup::OutputFlush,
    ]);
    let input_grant = ConsoleGrant::new(ConsoleRequirementGroup::Input, REQUESTER, GRANTOR);
    let inconsistent = call_refusal(admit_console_write(
        &both,
        &input_grant,
        &octets_request(b"four"),
        ConsoleOutputTarget::RedirectedNonControlling,
        b"four",
    ));
    assert_eq!(
        inconsistent.code(),
        ConsoleAuthorityDiagnosticCode::RequirementGroupInconsistent
    );
    assert_eq!(inconsistent.observed(), Some("input"));
    assert_eq!(inconsistent.declared(), Some("output-flush"));
    // (c) The presented grant was not issued for that requester and group.
    let forged = ConsoleGrant::new(ConsoleRequirementGroup::OutputFlush, "other-task", GRANTOR);
    let forged_refusal = call_refusal(admit_console_write(
        &output_only,
        &forged,
        &octets_request(b"four"),
        ConsoleOutputTarget::RedirectedNonControlling,
        b"four",
    ));
    assert_eq!(
        forged_refusal.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityForged
    );
    assert_eq!(
        forged_refusal.group(),
        Some(ConsoleRequirementGroup::OutputFlush)
    );
    // The steps are ordered: an unissued required group is missing even when the presented grant
    // also names another group.
    let unissued = ConsoleAccessInjection::from_launch(GRANTOR, Vec::new());
    let ordered = unissued
        .admit_call(ConsoleRequirementGroup::Control, &output_grant())
        .err()
        .unwrap_or_else(|| panic!("an unissued required group is refused first"));
    assert_eq!(
        ordered.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(ordered.group(), Some(ConsoleRequirementGroup::Control));
}

#[test]
fn ambient_descriptor_refusal_precedes_the_required_group_check() {
    // The access is classified before any grant is compared, so a descriptor presented as access
    // is an ambient refusal even when the required group of the called signature carries no
    // grant at all.
    let none = ConsoleAccessInjection::from_launch(GRANTOR, Vec::new());
    assert!(none.grants().is_empty());
    let ambient = ConsoleAccessIdentity::AmbientDescriptor(1)
        .admit(&none, ConsoleRequirementGroup::OutputFlush)
        .err()
        .unwrap_or_else(|| panic!("an ambient descriptor is refused before any grant comparison"));
    assert_eq!(
        ambient.code(),
        ConsoleAuthorityDiagnosticCode::AmbientDescriptor
    );
    assert_eq!(ambient.descriptor(), Some(1));
    assert_eq!(ambient.group(), None);
}

#[test]
fn missing_required_group_is_not_reported_as_an_ambient_refusal() {
    // The same grant-less injection leaves an injected output-flush grant missing, and the
    // missing group is named as missing rather than absorbed into an ambient refusal.
    let none = ConsoleAccessInjection::from_launch(GRANTOR, Vec::new());
    let missing = ConsoleAccessIdentity::Injected(output_grant())
        .admit(&none, ConsoleRequirementGroup::OutputFlush)
        .err()
        .unwrap_or_else(|| panic!("an unissued required group must be refused"));
    assert_eq!(
        missing.code(),
        ConsoleAuthorityDiagnosticCode::AuthorityMissing
    );
    assert_eq!(missing.group(), Some(ConsoleRequirementGroup::OutputFlush));
    assert_eq!(missing.descriptor(), None);
}
