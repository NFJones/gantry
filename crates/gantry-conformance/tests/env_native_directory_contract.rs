//! Machine-checked conformance for the native-directory contract of SPEC.md Section 52.
//!
//! Every test is a pure function of its own declared inputs: no test opens a directory, reads a
//! host path, samples a clock, observes a process, or materializes a native handle. The model
//! decisions under test are declaration and refusal decisions, so each verdict is reproducible
//! from its arguments alone.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AuthorityGeneration, AuthorityRequirementId, AuthorityRight, CanonicalCallableIdentity,
    CanonicalPath, CanonicalSignature, DeclaredName, LogicalExecutionId, LogicalOperationId,
    NATIVE_DIRECTORY_CLAUSES, NativeDirectoryAuthority, NativeDirectoryCase,
    NativeDirectoryChildGrant, NativeDirectoryComparison, NativeDirectoryCompletion,
    NativeDirectoryDiagnosticCode, NativeDirectoryDurablePresentation, NativeDirectoryHandle,
    NativeDirectoryIssuer, NativeDirectoryLedger, NativeDirectoryMapping, NativeDirectoryPath,
    NativeDirectoryRefusal, NativeDirectoryRequirement, NativeDirectoryRequirementKind,
    NativeDirectorySlot, NativeDirectorySubjectFacts, NativeDirectoryTarget, OwnerGeneration,
    ResourceGenerationId, RightsSet, SemanticMode, StaticSiteId, StructuralPosition,
    TaskBodyIdentity, TypeDescriptor, recover_native_directory,
};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming the
/// associated item requires an inference that cannot be resolved and compilation fails. A Clone
/// implementation for the native handle would stop this crate compiling, which is exactly what
/// GNT-52.3 forbids: the handle is affine, so one issuance yields one settlement and no copy can
/// settle the same slot twice.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_name:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $(
                impl<T: ?Sized + $trait_name> AmbiguousIfImpl<Invalid> for T {}
            )+
            struct Invalid;
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl_any!(NativeDirectoryHandle: Clone);

/// One canonical workflow path declared by a test fixture.
fn canonical(value: &str) -> CanonicalPath {
    match CanonicalPath::new(value) {
        Ok(path) => path,
        Err(error) => panic!("the declared path {value} is canonical: {error:?}"),
    }
}

/// One declared static site of a test fixture.
fn site() -> StaticSiteId {
    match StructuralPosition::new(vec![0, 3]) {
        Ok(position) => StaticSiteId::new(canonical("crate::main"), position),
        Err(error) => panic!("the declared position is nonempty: {error:?}"),
    }
}

/// One landed resource generation of one operation, site, and counter.
fn generation(counter: u64) -> ResourceGenerationId {
    let site = site();
    let operation = LogicalOperationId::derive(&canonical("crate::open_directory"), &site);
    ResourceGenerationId::derive(&operation, &site, counter)
}

/// One declared logical execution of one declared label.
fn execution(label: &str) -> LogicalExecutionId {
    let entry = CanonicalCallableIdentity::free(&canonical("crate::main"), &[]);
    match DeclaredName::new(label) {
        Ok(name) => LogicalExecutionId::derive(&entry, &name),
        Err(error) => panic!("the declared label {label} is named: {error:?}"),
    }
}

/// One declared task body of the test fixture.
fn task() -> TaskBodyIdentity {
    let entry = CanonicalCallableIdentity::free(&canonical("crate::main"), &[]);
    match StructuralPosition::new(vec![1, 2]) {
        Ok(position) => TaskBodyIdentity::new(entry, position),
        Err(error) => panic!("the task position is nonempty: {error:?}"),
    }
}

/// One declared subject with one generation counter, execution label, and owner generation.
fn subject(counter: u64, label: &str, owner: u64) -> NativeDirectorySubjectFacts {
    NativeDirectorySubjectFacts::new(
        generation(counter),
        execution(label),
        task(),
        OwnerGeneration::new(owner),
    )
}

/// One typed requirement identity of the native-directory family.
fn requirement(kind: NativeDirectoryRequirementKind, result: &str) -> NativeDirectoryRequirement {
    let path = canonical("crate::open_directory");
    let descriptor = match TypeDescriptor::from_canonical_string(result) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the declared result type {result} is canonical: {error:?}"),
    };
    let signature = CanonicalSignature::function(&path, &[], &descriptor);
    match AuthorityRequirementId::new(
        &path,
        &signature,
        "native-directory",
        RecoveryClass::Idempotent,
    ) {
        Ok(identity) => NativeDirectoryRequirement::new(identity, kind),
        Err(error) => panic!("the declared requirement identity is canonical: {error:?}"),
    }
}

/// One admitted native directory path text.
fn path(text: &str, mapping: NativeDirectoryMapping) -> NativeDirectoryPath {
    match NativeDirectoryPath::new(text, mapping) {
        Ok(path) => path,
        Err(error) => panic!("the declared path {text} is admitted: {error}"),
    }
}

/// One attached slot over one admitted path.
fn slot(identity: &str, text: &str, facts: &NativeDirectorySubjectFacts) -> NativeDirectorySlot {
    let mapping = NativeDirectoryMapping::LINUX_SENSITIVE;
    match NativeDirectorySlot::new(identity, path(text, mapping), facts.clone()) {
        Ok(slot) => slot,
        Err(error) => panic!("the declared slot identity {identity} is named: {error}"),
    }
}

/// One declared authority that holds observe and read-only invocation.
fn authority(
    facts: &NativeDirectorySubjectFacts,
    text: &str,
    fence: u64,
) -> NativeDirectoryAuthority {
    let mapping = NativeDirectoryMapping::LINUX_SENSITIVE;
    match NativeDirectoryAuthority::declare(
        requirement(NativeDirectoryRequirementKind::Open, "Int"),
        RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::InvokeReadOnly]),
        mapping,
        SemanticMode::Application,
        facts.clone(),
        path(text, mapping),
        AuthorityGeneration::new(fence),
    ) {
        Ok(authority) => authority,
        Err(error) => panic!("the declared authority is admitted: {error}"),
    }
}

/// Returns the exact refusal code of a refused model decision.
fn refusal<T>(result: Result<T, NativeDirectoryRefusal>) -> NativeDirectoryDiagnosticCode {
    match result {
        Ok(_) => panic!("the presented native directory decision must be refused"),
        Err(error) => error.code(),
    }
}

#[test]
fn section_52_clauses_and_refusals_are_closed_bound_and_published() {
    let clauses = NATIVE_DIRECTORY_CLAUSES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(clauses.len(), NATIVE_DIRECTORY_CLAUSES.len());

    let spellings = NativeDirectoryDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(spellings.len(), NativeDirectoryDiagnosticCode::ALL.len());
    for code in NativeDirectoryDiagnosticCode::ALL {
        assert!(code.as_str().starts_with("native-dir-"));
        assert!(clauses.contains(code.clause()));
    }
    for (code, index) in [
        (NativeDirectoryDiagnosticCode::Amplification, 7),
        (NativeDirectoryDiagnosticCode::DuplicateIssuance, 3),
        (NativeDirectoryDiagnosticCode::EmptyRights, 1),
        (NativeDirectoryDiagnosticCode::ForeignSubject, 2),
        (NativeDirectoryDiagnosticCode::InvalidChildPath, 7),
        (NativeDirectoryDiagnosticCode::InvalidPath, 1),
        (NativeDirectoryDiagnosticCode::InvalidSlotIdentity, 3),
        (NativeDirectoryDiagnosticCode::LateCompletion, 5),
        (NativeDirectoryDiagnosticCode::NeverResurrects, 6),
        (NativeDirectoryDiagnosticCode::NotLive, 3),
        (NativeDirectoryDiagnosticCode::PathBindingRefused, 2),
        (NativeDirectoryDiagnosticCode::PathGrantsNoAuthority, 6),
        (NativeDirectoryDiagnosticCode::RequirementMismatch, 1),
        (NativeDirectoryDiagnosticCode::Revoked, 4),
        (NativeDirectoryDiagnosticCode::StaleGeneration, 3),
        (NativeDirectoryDiagnosticCode::UndeclaredMapping, 1),
        (NativeDirectoryDiagnosticCode::UnsupportedMode, 1),
        (NativeDirectoryDiagnosticCode::UnsupportedRepresentation, 1),
    ] {
        assert_eq!(
            code.clause(),
            NATIVE_DIRECTORY_CLAUSES[index],
            "each spelling names exactly one owning clause",
        );
    }

    let specification = read_text(&workspace_root().join("SPEC.md"));
    let quote = char::from(34);
    for clause in NATIVE_DIRECTORY_CLAUSES {
        let needle = format!("id={quote}{clause}{quote}");
        assert!(
            specification.contains(&needle),
            "SPEC.md anchors every Section 52 clause"
        );
    }
    for spelling in &spellings {
        assert!(
            specification.contains(spelling),
            "SPEC.md publishes every native-dir spelling"
        );
    }
    assert!(
        specification.contains(
            "native-dir-empty-rights, native-dir-invalid-path, native-dir-requirement-mismatch"
        ),
        "GNT-52.8 assigns requirement-mismatch to the clause that defines it",
    );
    assert!(
        specification.contains("native-dir-foreign-subject and native-dir-path-binding-refused"),
        "GNT-52.8 keeps the path and fact refusals with GNT-52.2",
    );
}

#[test]
fn declared_mappings_are_the_only_admitted_target_case_combinations() {
    assert_eq!(
        NativeDirectoryTarget::ALL,
        [NativeDirectoryTarget::Linux, NativeDirectoryTarget::MacOs]
    );
    assert_eq!(
        NativeDirectoryCase::ALL,
        [
            NativeDirectoryCase::Sensitive,
            NativeDirectoryCase::AsciiInsensitive
        ]
    );
    assert_eq!(
        NativeDirectoryMapping::DECLARED,
        [
            NativeDirectoryMapping::LINUX_SENSITIVE,
            NativeDirectoryMapping::MACOS_SENSITIVE,
            NativeDirectoryMapping::MACOS_ASCII_INSENSITIVE,
        ]
    );

    for (target, case) in [
        (NativeDirectoryTarget::Linux, NativeDirectoryCase::Sensitive),
        (NativeDirectoryTarget::MacOs, NativeDirectoryCase::Sensitive),
        (
            NativeDirectoryTarget::MacOs,
            NativeDirectoryCase::AsciiInsensitive,
        ),
    ] {
        let mapping = match NativeDirectoryMapping::new(target, case) {
            Ok(mapping) => mapping,
            Err(error) => panic!("the declared mapping pair is admitted: {error}"),
        };
        assert_eq!(mapping.target(), target);
        assert_eq!(mapping.case(), case);
    }

    assert_eq!(
        refusal(NativeDirectoryMapping::new(
            NativeDirectoryTarget::Linux,
            NativeDirectoryCase::AsciiInsensitive,
        )),
        NativeDirectoryDiagnosticCode::UndeclaredMapping,
    );
}

#[test]
fn mapping_admission_and_comparison_are_explicit_and_target_aware() {
    let linux = NativeDirectoryMapping::LINUX_SENSITIVE;
    let exact = path("/Work/é", linux);
    assert_eq!(exact.as_str(), "/Work/é");
    assert!(!exact.grants_authority());
    assert_eq!(
        linux.compare("/Work", "/Work"),
        NativeDirectoryComparison::Identical
    );
    assert_eq!(
        linux.compare("/Work", "/work"),
        NativeDirectoryComparison::Distinct
    );
    assert_eq!(
        NativeDirectoryMapping::MACOS_ASCII_INSENSITIVE.compare("/Work", "/work"),
        NativeDirectoryComparison::EqualUnderDeclaredAsciiFold
    );
    assert_eq!(
        path("/Hé", NativeDirectoryMapping::MACOS_SENSITIVE).as_str(),
        "/Hé"
    );

    for (text, mapping, code) in [
        ("", linux, NativeDirectoryDiagnosticCode::InvalidPath),
        (
            "relative",
            linux,
            NativeDirectoryDiagnosticCode::InvalidPath,
        ),
        (
            "/a/\u{1}b",
            linux,
            NativeDirectoryDiagnosticCode::InvalidPath,
        ),
        (
            "/hé",
            NativeDirectoryMapping::MACOS_ASCII_INSENSITIVE,
            NativeDirectoryDiagnosticCode::UnsupportedRepresentation,
        ),
    ] {
        assert_eq!(refusal(NativeDirectoryPath::new(text, mapping)), code);
    }
}

#[test]
fn path_text_is_admitted_data_that_never_grants_authority() {
    let admitted = path("/srv/work", NativeDirectoryMapping::LINUX_SENSITIVE);
    assert!(!admitted.grants_authority());
    assert_eq!(admitted.to_string(), "/srv/work");
    assert!(
        NativeDirectoryPath::new("/srv/work", NativeDirectoryMapping::MACOS_ASCII_INSENSITIVE)
            .is_ok()
    );
}

/// One admitted issuance of one declared slot.
fn issue(
    ledger: &mut NativeDirectoryLedger,
    identity: &str,
    text: &str,
    facts: &NativeDirectorySubjectFacts,
    fence: u64,
) -> NativeDirectoryHandle {
    match ledger.issue(slot(identity, text, facts), authority(facts, text, fence)) {
        Ok(handle) => handle,
        Err(error) => panic!("the declared issuance is admitted: {error}"),
    }
}

/// One task body distinct from the default fixture task.
fn other_task() -> TaskBodyIdentity {
    let entry = CanonicalCallableIdentity::free(&canonical("crate::main"), &[]);
    match StructuralPosition::new(vec![2, 3]) {
        Ok(position) => TaskBodyIdentity::new(entry, position),
        Err(error) => panic!("the task position is nonempty: {error:?}"),
    }
}

#[test]
fn authority_requires_a_right_and_the_application_mode() {
    let mapping = NativeDirectoryMapping::LINUX_SENSITIVE;
    let facts = subject(1, "run", 4);
    assert_eq!(
        refusal(NativeDirectoryAuthority::declare(
            requirement(NativeDirectoryRequirementKind::Open, "Int"),
            RightsSet::empty(),
            mapping,
            SemanticMode::Application,
            facts.clone(),
            path("/srv/work", mapping),
            AuthorityGeneration::new(2),
        )),
        NativeDirectoryDiagnosticCode::EmptyRights,
    );
    assert_eq!(
        refusal(NativeDirectoryAuthority::declare(
            requirement(NativeDirectoryRequirementKind::Open, "Int"),
            RightsSet::from_rights(&[AuthorityRight::Observe]),
            mapping,
            SemanticMode::Portable,
            facts,
            path("/srv/work", mapping),
            AuthorityGeneration::new(2),
        )),
        NativeDirectoryDiagnosticCode::UnsupportedMode,
    );
}

#[test]
fn every_route_compares_the_exact_requirement_identity() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    assert!(ledger.route(&handle, &held, &facts).is_ok());
    let other_kind = requirement(NativeDirectoryRequirementKind::Enumerate, "Int");
    assert_eq!(
        refusal(ledger.route(&handle, &other_kind, &facts)),
        NativeDirectoryDiagnosticCode::RequirementMismatch,
    );
    let other_identity = requirement(NativeDirectoryRequirementKind::Open, "Bool");
    assert_eq!(
        refusal(ledger.route(&handle, &other_identity, &facts)),
        NativeDirectoryDiagnosticCode::RequirementMismatch,
    );
}

#[test]
fn every_route_compares_exact_facts_including_execution_and_task_provenance() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");

    let other_execution = subject(1, "rerun", 4);
    assert_ne!(facts.execution(), other_execution.execution());
    assert_eq!(
        refusal(ledger.route(&handle, &held, &other_execution)),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );

    let other_task_facts = NativeDirectorySubjectFacts::new(
        generation(1),
        execution("run"),
        other_task(),
        OwnerGeneration::new(4),
    );
    assert_ne!(facts.task(), other_task_facts.task());
    assert_eq!(
        refusal(ledger.route(&handle, &held, &other_task_facts)),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );

    let other_owner = subject(1, "run", 5);
    assert_eq!(
        refusal(ledger.route(&handle, &held, &other_owner)),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );
}

#[test]
fn issuance_binds_the_handle_path_to_the_attached_slot_path() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    assert_eq!(
        refusal(ledger.issue(
            slot("slot-a", "/srv/work", &facts),
            authority(&facts, "/srv/other", 2),
        )),
        NativeDirectoryDiagnosticCode::PathBindingRefused,
    );

    let _handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let drifted = match NativeDirectorySlot::new(
        "slot-a",
        path("/srv/other", NativeDirectoryMapping::LINUX_SENSITIVE),
        facts.clone(),
    ) {
        Ok(slot) => slot,
        Err(error) => panic!("the declared slot identity is named: {error}"),
    };
    assert_eq!(
        refusal(ledger.settle_completion(
            &drifted,
            &facts,
            NativeDirectoryCompletion::Completed { settled_at: 7 },
        )),
        NativeDirectoryDiagnosticCode::PathBindingRefused,
    );
}

#[test]
fn exclusive_issuance_admits_one_live_handle_per_slot() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let first = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    assert_eq!(
        refusal(ledger.issue(
            slot("slot-a", "/srv/work", &facts),
            authority(&facts, "/srv/work", 2),
        )),
        NativeDirectoryDiagnosticCode::DuplicateIssuance,
    );
    let winner = match ledger.settle(
        &first,
        NativeDirectoryCompletion::Completed { settled_at: 5 },
    ) {
        Ok(winner) => winner,
        Err(error) => panic!("the declared settlement is admitted: {error}"),
    };
    assert!(!winner.is_cancellation());
    assert_eq!(winner.slot_identity(), "slot-a");
    assert_eq!(winner.settled_at(), 5);
    assert_eq!(winner.owner(), OwnerGeneration::new(4));
}

#[test]
fn a_settled_slot_reissues_only_a_succeeding_owner_generation() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let first = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    match ledger.settle(
        &first,
        NativeDirectoryCompletion::Cancelled { settled_at: 6 },
    ) {
        Ok(winner) => assert!(winner.is_cancellation()),
        Err(error) => panic!("the declared settlement is admitted: {error}"),
    }
    assert_eq!(
        refusal(ledger.issue(
            slot("slot-a", "/srv/work", &facts),
            authority(&facts, "/srv/work", 2),
        )),
        NativeDirectoryDiagnosticCode::StaleGeneration,
    );
    let succeeding = subject(1, "run", 5);
    let _reissued = issue(&mut ledger, "slot-a", "/srv/work", &succeeding, 2);
}

#[test]
fn the_handle_is_affine_and_settles_exactly_once() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    assert!(ledger.route(&handle, &held, &facts).is_ok());
    match ledger.settle(
        &handle,
        NativeDirectoryCompletion::Completed { settled_at: 8 },
    ) {
        Ok(winner) => assert_eq!(winner.settled_at(), 8),
        Err(error) => panic!("the declared settlement is admitted: {error}"),
    }
    assert_eq!(
        refusal(ledger.settle_completion(
            &slot("slot-a", "/srv/work", &facts),
            &facts,
            NativeDirectoryCompletion::Completed { settled_at: 9 },
        )),
        NativeDirectoryDiagnosticCode::LateCompletion,
    );
}

#[test]
fn revocation_fences_every_route_of_already_issued_handles() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    ledger.revoke(AuthorityGeneration::new(2));
    assert_eq!(
        refusal(ledger.route(&handle, &held, &facts)),
        NativeDirectoryDiagnosticCode::Revoked,
    );
    assert_eq!(
        refusal(ledger.issue(
            slot("slot-b", "/srv/other", &facts),
            authority(&facts, "/srv/other", 2),
        )),
        NativeDirectoryDiagnosticCode::Revoked,
    );
    match ledger.settle(
        &handle,
        NativeDirectoryCompletion::Cancelled { settled_at: 11 },
    ) {
        Ok(winner) => assert!(winner.is_cancellation()),
        Err(error) => panic!("revocation keeps the settlement obligation: {error}"),
    }
}

#[test]
fn late_and_repeated_completions_are_refused_without_effect() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let live = slot("slot-a", "/srv/work", &facts);
    assert_eq!(
        refusal(ledger.settle(&handle, NativeDirectoryCompletion::Late { settled_at: 3 })),
        NativeDirectoryDiagnosticCode::LateCompletion,
    );
    assert_eq!(
        refusal(ledger.settle_completion(
            &live,
            &facts,
            NativeDirectoryCompletion::Late { settled_at: 4 },
        )),
        NativeDirectoryDiagnosticCode::LateCompletion,
    );
    match ledger.settle_completion(
        &live,
        &facts,
        NativeDirectoryCompletion::Completed { settled_at: 7 },
    ) {
        Ok(winner) => assert_eq!(winner.settled_at(), 7),
        Err(error) => panic!("a refused late completion leaves the issuance live: {error}"),
    }
    assert_eq!(
        refusal(ledger.settle_completion(
            &live,
            &facts,
            NativeDirectoryCompletion::Completed { settled_at: 8 },
        )),
        NativeDirectoryDiagnosticCode::LateCompletion,
    );
    assert_eq!(
        refusal(ledger.settle_completion(
            &slot("slot-z", "/srv/nowhere", &facts),
            &facts,
            NativeDirectoryCompletion::Completed { settled_at: 9 },
        )),
        NativeDirectoryDiagnosticCode::NotLive,
    );
}

#[test]
fn child_projection_attenuates_rights_and_refuses_escapes() {
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let facts = subject(1, "run", 4);
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    let child_rights = RightsSet::from_rights(&[AuthorityRight::Observe]);
    let projection = match ledger.project_child(
        &handle,
        &NativeDirectoryChildGrant::new(child_rights, "reports"),
    ) {
        Ok(projection) => projection,
        Err(error) => panic!("the attenuated projection is admitted: {error}"),
    };
    assert_eq!(projection.rights(), child_rights);
    assert_eq!(projection.relative(), "reports");
    assert_eq!(projection.lineage().parent(), &facts);
    assert_eq!(
        projection.mapping(),
        NativeDirectoryMapping::LINUX_SENSITIVE
    );

    let widened =
        RightsSet::from_rights(&[AuthorityRight::Observe, AuthorityRight::InvokeIdempotent]);
    assert_eq!(
        refusal(
            ledger.project_child(&handle, &NativeDirectoryChildGrant::new(widened, "reports"),)
        ),
        NativeDirectoryDiagnosticCode::Amplification,
    );
    for text in ["/absolute", "..", "a/../b", ""] {
        assert_eq!(
            refusal(
                ledger.project_child(&handle, &NativeDirectoryChildGrant::new(child_rights, text),)
            ),
            NativeDirectoryDiagnosticCode::InvalidChildPath,
        );
    }
}

#[test]
fn child_projection_keeps_the_inherited_mapping_refusal() {
    let mapping = NativeDirectoryMapping::MACOS_ASCII_INSENSITIVE;
    let facts = subject(1, "run", 4);
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let attached =
        match NativeDirectorySlot::new("slot-a", path("/srv/work", mapping), facts.clone()) {
            Ok(attached) => attached,
            Err(error) => panic!("the declared slot identity is named: {error}"),
        };
    let authority = match NativeDirectoryAuthority::declare(
        requirement(NativeDirectoryRequirementKind::Open, "Int"),
        RightsSet::from_rights(&[AuthorityRight::Observe]),
        mapping,
        SemanticMode::Application,
        facts,
        path("/srv/work", mapping),
        AuthorityGeneration::new(2),
    ) {
        Ok(authority) => authority,
        Err(error) => panic!("the declared authority is admitted: {error}"),
    };
    let handle = match ledger.issue(attached, authority) {
        Ok(handle) => handle,
        Err(error) => panic!("the declared issuance is admitted: {error}"),
    };
    let rights = RightsSet::from_rights(&[AuthorityRight::Observe]);
    assert_eq!(
        refusal(ledger.project_child(
            &handle,
            &NativeDirectoryChildGrant::new(rights, "rapports/é"),
        )),
        NativeDirectoryDiagnosticCode::UnsupportedRepresentation,
    );
    assert!(
        ledger
            .project_child(&handle, &NativeDirectoryChildGrant::new(rights, "rapports"))
            .is_ok()
    );
}

#[test]
fn durable_presentations_never_resurrect_a_native_handle() {
    for (presentation, code) in [
        (
            NativeDirectoryDurablePresentation::Handle,
            NativeDirectoryDiagnosticCode::NeverResurrects,
        ),
        (
            NativeDirectoryDurablePresentation::Path("/srv/work".to_owned()),
            NativeDirectoryDiagnosticCode::PathGrantsNoAuthority,
        ),
        (
            NativeDirectoryDurablePresentation::Digest("sha256:00".to_owned()),
            NativeDirectoryDiagnosticCode::PathGrantsNoAuthority,
        ),
    ] {
        assert_eq!(refusal(recover_native_directory(presentation)), code);
    }
    let recovered = match recover_native_directory(NativeDirectoryDurablePresentation::LogicalText(
        "workspace/a".to_owned(),
    )) {
        Ok(recovered) => recovered,
        Err(error) => panic!("logical text recovers as declared data: {error}"),
    };
    assert_eq!(recovered.logical_text(), "workspace/a");
}

#[test]
fn section_52_note_publishes_the_contract_boundaries() {
    let note = read_text(&workspace_root().join("docs/env-native-directory-contract.md"));
    let flattened = note.split_whitespace().collect::<Vec<_>>().join(" ");
    for clause in NATIVE_DIRECTORY_CLAUSES {
        assert!(
            flattened.contains(clause),
            "the note cites every Section 52 clause"
        );
    }
    for phrase in [
        "crates/gantry-ir/src/env_native.rs",
        "crates/gantry-conformance/tests/env_native_directory_contract.rs",
        "declared data",
        "no host adapter",
    ] {
        assert!(
            flattened.contains(phrase),
            "the note publishes its boundaries"
        );
    }
}

#[test]
fn a_handle_from_another_issuer_is_not_an_equivalent_issuance() {
    let facts = subject(1, "run", 4);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    let mut first = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let mut second = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(2));
    let handle = issue(&mut first, "slot-a", "/srv/work", &facts, 2);
    let foreign = issue(&mut second, "slot-a", "/srv/work", &facts, 2);
    assert_ne!(handle.issuance(), foreign.issuance());

    assert!(first.route(&handle, &held, &facts).is_ok());
    assert_eq!(
        refusal(first.route(&foreign, &held, &facts)),
        NativeDirectoryDiagnosticCode::ForeignSubject,
        "an equivalent declaration from another issuer is not this ledger issuance",
    );

    first.revoke(AuthorityGeneration::new(2));
    assert_eq!(
        refusal(first.route(&handle, &held, &facts)),
        NativeDirectoryDiagnosticCode::Revoked,
    );
    assert!(
        second.route(&foreign, &held, &facts).is_ok(),
        "another issuer revocation never fences this issuance",
    );
}

#[test]
fn a_path_admitted_under_another_mapping_is_refused() {
    let admitted = path("/hé", NativeDirectoryMapping::LINUX_SENSITIVE);
    assert_eq!(
        refusal(NativeDirectoryAuthority::declare(
            requirement(NativeDirectoryRequirementKind::Open, "Int"),
            RightsSet::from_rights(&[AuthorityRight::Observe]),
            NativeDirectoryMapping::MACOS_ASCII_INSENSITIVE,
            SemanticMode::Application,
            subject(1, "run", 4),
            admitted,
            AuthorityGeneration::new(2),
        )),
        NativeDirectoryDiagnosticCode::UnsupportedRepresentation,
        "the declared mapping cannot preserve a path admitted under another mapping",
    );
}

#[test]
fn attached_slot_facts_must_be_the_declared_subject_facts() {
    let facts = subject(1, "run", 4);
    let other = subject(1, "rerun", 4);
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    assert_eq!(
        refusal(ledger.issue(
            slot("slot-a", "/srv/work", &other),
            authority(&facts, "/srv/work", 2),
        )),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );
}

#[test]
fn a_refused_late_presentation_leaves_the_handle_usable() {
    let facts = subject(1, "run", 4);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    assert_eq!(
        refusal(ledger.settle(&handle, NativeDirectoryCompletion::Late { settled_at: 3 })),
        NativeDirectoryDiagnosticCode::LateCompletion,
    );
    assert!(
        ledger.route(&handle, &held, &facts).is_ok(),
        "a refused late presentation leaves the live issuance routable",
    );
    assert!(
        ledger
            .settle(
                &handle,
                NativeDirectoryCompletion::Completed { settled_at: 9 }
            )
            .is_ok(),
        "the same handle still settles exactly once afterwards",
    );
}

#[test]
fn a_recreated_registry_with_the_same_issuer_identity_cannot_adopt_another_handle() {
    let facts = subject(1, "run", 4);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    let child = RightsSet::from_rights(&[AuthorityRight::Observe]);
    let mut first = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let mut second = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let handle = issue(&mut first, "slot-a", "/srv/work", &facts, 2);
    let foreign = issue(&mut second, "slot-a", "/srv/work", &facts, 2);
    assert_ne!(
        handle.issuance(),
        foreign.issuance(),
        "two registries that declare one issuer identity still mint distinct identities",
    );

    assert_eq!(
        refusal(first.route(&foreign, &held, &facts)),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );
    assert_eq!(
        refusal(first.project_child(&foreign, &NativeDirectoryChildGrant::new(child, "reports"))),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );
    assert_eq!(
        refusal(first.settle(
            &foreign,
            NativeDirectoryCompletion::Completed { settled_at: 4 }
        )),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );
    assert!(
        second.route(&foreign, &held, &facts).is_ok(),
        "the minting registry routes its own issuance",
    );
    match second.settle(
        &foreign,
        NativeDirectoryCompletion::Cancelled { settled_at: 5 },
    ) {
        Ok(winner) => assert!(winner.is_cancellation()),
        Err(error) => panic!("the minting registry settles its own issuance: {error}"),
    }
    first.revoke(AuthorityGeneration::new(2));
    assert_eq!(
        refusal(first.route(&handle, &held, &facts)),
        NativeDirectoryDiagnosticCode::Revoked,
    );
    assert!(
        first
            .settle(
                &handle,
                NativeDirectoryCompletion::Completed { settled_at: 6 },
            )
            .is_ok(),
        "revocation fences routes and leaves the first registry issuance settleable once",
    );
}

#[test]
fn completion_compares_the_attached_slot_facts() {
    let facts = subject(1, "run", 4);
    let other = subject(1, "rerun", 4);
    let held = requirement(NativeDirectoryRequirementKind::Open, "Int");
    let mut ledger = NativeDirectoryLedger::new(NativeDirectoryIssuer::new(1));
    let handle = issue(&mut ledger, "slot-a", "/srv/work", &facts, 2);
    assert_eq!(
        refusal(ledger.settle_completion(
            &slot("slot-a", "/srv/work", &other),
            &facts,
            NativeDirectoryCompletion::Completed { settled_at: 4 },
        )),
        NativeDirectoryDiagnosticCode::ForeignSubject,
    );
    assert!(
        ledger.settlement("slot-a").is_none(),
        "a refused completion records no winner",
    );
    assert!(ledger.route(&handle, &held, &facts).is_ok());
    assert!(
        ledger
            .settle_completion(
                &slot("slot-a", "/srv/work", &facts),
                &facts,
                NativeDirectoryCompletion::Completed { settled_at: 5 },
            )
            .is_ok(),
        "the authentic completion still settles exactly once",
    );
}

/// The workspace root of the conformance crate.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads one workspace file as text.
fn read_text(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("the workspace file is readable: {error}"),
    }
}
