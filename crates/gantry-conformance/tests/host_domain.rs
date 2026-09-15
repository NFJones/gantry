//! Machine-checked conformance for the pure Section 29 host-domain model.
//!
//! These tests use only declared vocabulary, mappings, outcomes, and owner generations.
//! They do not create a runtime adapter, host trait, checkpoint, evaluator, or host resource.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::{HostDomainCategory, HostDomainFamily, HostTarget};
use gantry::ir::{
    AdapterContractDeclaration, CanonicalPath, EffectCertainty, FailureClass, HOST_DOMAIN_CLAUSES,
    HostDomainDiagnosticCode, HostDomainError, HostDomainErrorKind, HostOperationFailure,
    HostOperationOutcome, HostProgress, HostSettlement, HostSettlementError,
    NativeMappingDeclaration, OperationAbi, OperationKind, OwnerGeneration,
    PORTABLE_MESSAGE_MAX_BYTES, ProcessConfinement, ProcessLifecycle, ProcessStdio,
    ProcessSupervision, ReceiverOwnership, StaticSiteId, StructuralPosition,
};

#[test]
fn application_stdio_is_a_declaration_not_a_host_process_mapping() {
    assert_eq!(
        gantry::ir::StdioArrangement::ALL.map(gantry::ir::StdioArrangement::wire_name),
        ["inherit", "null", "pipe"]
    );
    assert_ne!(gantry::ir::StdioArrangement::Pipe.wire_name(), "piped");
}

fn mappings(family: HostDomainFamily) -> Vec<NativeMappingDeclaration> {
    family
        .categories()
        .iter()
        .map(|category| {
            NativeMappingDeclaration::new(family, *category, category.wire_name())
                .unwrap_or_else(|error| panic!("fixture mapping is valid: {error}"))
        })
        .collect()
}

/// Returns the refusal produced by one rejected host-domain decision.
fn refuse<T>(outcome: Result<T, HostDomainErrorKind>, context: &str) -> HostDomainErrorKind {
    match outcome {
        Ok(_) => panic!("{context}: the decision must be refused"),
        Err(error) => error,
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

fn launched_lifecycle(owner: u64) -> ProcessLifecycle {
    ProcessLifecycle::launched(OwnerGeneration::new(owner))
}

fn post_failure(receiver: ReceiverOwnership) -> gantry::ir::PostFailureSettlement {
    let path = CanonicalPath::new("crate::host_domain")
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"));
    let position = StructuralPosition::new(vec![29, 20])
        .unwrap_or_else(|_| unreachable!("fixture position is canonical"));
    let site = StaticSiteId::new(path.clone(), position);
    OperationAbi::new(
        OperationKind::LiveResource,
        &path,
        &site,
        1,
        gantry::ir::generated::RecoveryClass::Idempotent,
        receiver,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation is admissible"))
    .settle_failure(FailureClass::ResourceFailure)
}

#[test]
fn section_29_anchors_catalog_and_closed_vocabulary_are_published() {
    assert_eq!(HOST_DOMAIN_CLAUSES.len(), 16);
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"));
    for clause in HOST_DOMAIN_CLAUSES {
        assert!(
            specification.contains(&format!("<a id=\"{clause}\"></a>")),
            "Section 29 must publish {clause}"
        );
    }
    for family in HostDomainFamily::ALL {
        assert_eq!(
            HostDomainFamily::from_wire_name(family.wire_name()),
            Some(family)
        );
        assert!(family.admits(HostDomainCategory::Unclassified));
    }
    assert_eq!(HostDomainFamily::from_wire_name("ambient"), None);
    assert_eq!(HostDomainCategory::from_wire_name("native-errno"), None);
    assert!(HostDomainFamily::Codec.applies_to(HostTarget::Portable));
    assert!(HostDomainFamily::Codec.applies_to(HostTarget::Durable));
    assert!(!HostDomainFamily::Process.applies_to(HostTarget::Durable));
}

#[test]
fn family_category_envelopes_are_strict_and_exclude_native_detail() {
    let error = refuse(
        HostDomainError::new(
            HostDomainFamily::Filesystem,
            HostDomainCategory::Handshake,
            "not a filesystem category",
        ),
        "a mismatched family category is refused",
    );
    assert_eq!(error, HostDomainErrorKind::MismatchedFamilyCategory);
    let error = refuse(
        HostDomainError::new(
            HostDomainFamily::Filesystem,
            HostDomainCategory::Missing,
            format!("native\0errno:{}", "x".repeat(PORTABLE_MESSAGE_MAX_BYTES)),
        ),
        "native detail is refused",
    );
    assert_eq!(error, HostDomainErrorKind::InvalidPortableDetail);
    let error = refuse(
        HostDomainError::new(
            HostDomainFamily::Filesystem,
            HostDomainCategory::Missing,
            "x".repeat(PORTABLE_MESSAGE_MAX_BYTES + 1),
        ),
        "an oversized portable message is refused",
    );
    assert_eq!(error, HostDomainErrorKind::InvalidPortableDetail);
    for native_detail in ["errno 13", "/private/path", "PID 42", "provider text"] {
        assert_eq!(
            HostDomainError::new(
                HostDomainFamily::Filesystem,
                HostDomainCategory::Missing,
                native_detail,
            ),
            Err(HostDomainErrorKind::InvalidPortableDetail),
            "native detail {native_detail:?} must not enter the portable message"
        );
    }
    let envelope = HostDomainError::new(
        HostDomainFamily::Filesystem,
        HostDomainCategory::Unclassified,
        "portable message",
    )
    .unwrap_or_else(|error| panic!("unclassified fallback is valid: {error}"));
    assert_eq!(envelope.family(), HostDomainFamily::Filesystem);
    assert_eq!(envelope.category(), HostDomainCategory::Unclassified);
    assert_eq!(envelope.message(), "portable message");
}

#[test]
fn operational_and_domain_channels_progress_and_settlement_stay_separate() {
    let domain = HostDomainError::new(
        HostDomainFamily::Console,
        HostDomainCategory::Read,
        "read refused",
    )
    .unwrap_or_else(|error| panic!("fixture envelope is valid: {error}"));
    assert_eq!(
        HostOperationOutcome::DomainError(domain).failure_channel(),
        Some(HostOperationFailure::Domain)
    );
    assert_eq!(
        HostOperationOutcome::OperationalFailure.failure_channel(),
        Some(HostOperationFailure::Operational)
    );
    assert_eq!(HostOperationOutcome::Succeeded.failure_channel(), None);
    assert_eq!(HostProgress::Eof.observation().wire_name(), "eof");
    assert_eq!(
        HostProgress::ShortRead.observation().wire_name(),
        "short-read"
    );
    assert_eq!(
        HostProgress::ShortWrite.observation().wire_name(),
        "short-write"
    );
    assert_eq!(
        HostProgress::Complete.observation().wire_name(),
        "committed-progress"
    );
    assert_eq!(
        HostProgress::NotStarted.observation().wire_name(),
        "not-started"
    );
    let settlement = HostSettlement::new(
        HostOperationOutcome::Succeeded,
        HostProgress::Complete,
        ReceiverOwnership::RetainedByCaller,
        None,
        EffectCertainty::AmbiguouslyBegun,
        OwnerGeneration::new(7),
    )
    .unwrap_or_else(|error| panic!("consistent settlement is valid: {error:?}"));
    assert_eq!(settlement.owner(), OwnerGeneration::new(7));
    assert_eq!(settlement.effect(), EffectCertainty::AmbiguouslyBegun);
    assert!(settlement.post_failure().is_none());
    assert!(matches!(
        settlement.receiver(),
        ReceiverOwnership::RetainedByCaller
    ));

    assert_eq!(
        HostSettlement::new(
            HostOperationOutcome::Succeeded,
            HostProgress::Complete,
            ReceiverOwnership::RetainedByCaller,
            None,
            EffectCertainty::DefiniteNotStarted,
            OwnerGeneration::new(7),
        ),
        Err(HostSettlementError::SuccessContradictsFailureFacts)
    );
    assert_eq!(
        HostSettlement::new(
            HostOperationOutcome::OperationalFailure,
            HostProgress::NotStarted,
            ReceiverOwnership::RetainedByCaller,
            None,
            EffectCertainty::AmbiguouslyBegun,
            OwnerGeneration::new(7),
        ),
        Err(HostSettlementError::FailureMissingPostFailureSettlement)
    );
    assert_eq!(
        HostSettlement::new(
            HostOperationOutcome::OperationalFailure,
            HostProgress::ShortWrite,
            ReceiverOwnership::RetainedByCaller,
            None,
            EffectCertainty::DefiniteNotStarted,
            OwnerGeneration::new(7),
        ),
        Err(HostSettlementError::ProgressContradictsEffectCertainty)
    );
    assert_eq!(
        HostSettlement::new(
            HostOperationOutcome::Succeeded,
            HostProgress::Complete,
            ReceiverOwnership::TransferredIn(OwnerGeneration::new(8)),
            None,
            EffectCertainty::AmbiguouslyBegun,
            OwnerGeneration::new(7),
        ),
        Err(HostSettlementError::OwnerMismatch)
    );
    assert_eq!(
        HostSettlement::new(
            HostOperationOutcome::OperationalFailure,
            HostProgress::NotStarted,
            ReceiverOwnership::TransferredIn(OwnerGeneration::new(7)),
            Some(post_failure(ReceiverOwnership::RetainedByCaller)),
            EffectCertainty::AmbiguouslyBegun,
            OwnerGeneration::new(7),
        ),
        Err(HostSettlementError::OwnerMismatch)
    );
}

#[test]
fn adapter_mappings_close_every_family_row_and_target_mapping() {
    let filesystem = mappings(HostDomainFamily::Filesystem);
    assert!(AdapterContractDeclaration::new(HostTarget::Application, filesystem, None).is_ok());
    let mut incomplete = mappings(HostDomainFamily::Filesystem);
    incomplete.pop();
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(HostTarget::Application, incomplete, None),
            "an incomplete adapter mapping is refused",
        ),
        HostDomainErrorKind::IncompleteAdapterDeclaration
    );
    let mut duplicate = mappings(HostDomainFamily::Filesystem);
    duplicate.push(
        NativeMappingDeclaration::new(
            HostDomainFamily::Filesystem,
            HostDomainCategory::Unclassified,
            "duplicate",
        )
        .unwrap_or_else(|error| panic!("fixture mapping is valid: {error}")),
    );
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(HostTarget::Application, duplicate, None),
            "a duplicated adapter mapping is refused",
        ),
        HostDomainErrorKind::IncompleteAdapterDeclaration
    );
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(
                HostTarget::Durable,
                mappings(HostDomainFamily::Console),
                None
            ),
            "a durable target mapping is inapplicable",
        ),
        HostDomainErrorKind::TargetMappingInapplicable
    );
}

#[test]
fn process_declarations_are_explicit_single_owner_and_reaped_once() {
    let process = mappings(HostDomainFamily::Process);
    assert!(
        AdapterContractDeclaration::new(
            HostTarget::Application,
            process,
            Some((
                ProcessConfinement::Confined,
                ProcessStdio::Piped,
                OwnerGeneration::new(3),
                launched_lifecycle(3),
            )),
        )
        .is_ok()
    );
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(
                HostTarget::Application,
                mappings(HostDomainFamily::Filesystem),
                Some((
                    ProcessConfinement::AuditedUnconfined,
                    ProcessStdio::Null,
                    OwnerGeneration::new(3),
                    launched_lifecycle(3),
                )),
            ),
            "a process declaration outside the process family is refused",
        ),
        HostDomainErrorKind::ProcessDeclarationOutsideProcess
    );
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(
                HostTarget::Application,
                mappings(HostDomainFamily::Process),
                Some((
                    ProcessConfinement::Confined,
                    ProcessStdio::Piped,
                    OwnerGeneration::new(4),
                    launched_lifecycle(3),
                )),
            ),
            "a process owner mismatch is refused",
        ),
        HostDomainErrorKind::ProcessOwnerMismatch
    );
    let mut reaped = ProcessLifecycle::launched(OwnerGeneration::new(3));
    assert!(
        reaped
            .advance(OwnerGeneration::new(3), ProcessSupervision::Waited)
            .is_ok()
    );
    assert!(
        reaped
            .advance(OwnerGeneration::new(3), ProcessSupervision::Reaped)
            .is_ok()
    );
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(
                HostTarget::Application,
                mappings(HostDomainFamily::Process),
                Some((
                    ProcessConfinement::Confined,
                    ProcessStdio::Piped,
                    OwnerGeneration::new(3),
                    reaped,
                )),
            ),
            "an already reaped lifecycle is refused",
        ),
        HostDomainErrorKind::InvalidProcessLifecycleTransition
    );
    let mut lifecycle = ProcessLifecycle::launched(OwnerGeneration::new(3));
    assert!(
        lifecycle
            .advance(OwnerGeneration::new(3), ProcessSupervision::Waited)
            .is_ok()
    );
    assert_eq!(
        refuse(
            AdapterContractDeclaration::new(
                HostTarget::Application,
                mappings(HostDomainFamily::Process),
                Some((
                    ProcessConfinement::Confined,
                    ProcessStdio::Piped,
                    OwnerGeneration::new(3),
                    lifecycle,
                )),
            ),
            "a waited lifecycle is refused",
        ),
        HostDomainErrorKind::InvalidProcessLifecycleTransition
    );
    assert_eq!(
        refuse(
            lifecycle.advance(OwnerGeneration::new(2), ProcessSupervision::Reaped),
            "a stale process owner is refused",
        ),
        HostDomainErrorKind::ProcessOwnerMismatch
    );
    assert!(
        lifecycle
            .advance(OwnerGeneration::new(3), ProcessSupervision::Reaped)
            .is_ok()
    );
    assert_eq!(
        refuse(
            lifecycle.advance(OwnerGeneration::new(3), ProcessSupervision::Reaped),
            "a second reap is refused",
        ),
        HostDomainErrorKind::InvalidProcessLifecycleTransition
    );
}

#[test]
fn diagnostic_registry_and_non_claims_are_closed() {
    let mut codes = BTreeSet::new();
    for code in HostDomainDiagnosticCode::ALL {
        assert!(codes.insert(code.as_str()));
        assert!(HOST_DOMAIN_CLAUSES.contains(&code.requirement()));
    }
    assert_eq!(codes.len(), HostDomainDiagnosticCode::ALL.len());
    let specification = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"));
    let non_claims = HOST_DOMAIN_CLAUSES[15];
    let start = specification
        .find(&format!("<a id=\"{non_claims}\"></a>"))
        .unwrap_or_else(|| panic!("non-claims anchor exists"));
    let body = &specification[start..];
    assert!(body.contains("runtime adapter"));
    assert!(body.contains("external or durable grant"));
}
