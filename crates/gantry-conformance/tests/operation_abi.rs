//! Machine-checked conformance for the pure operation-ABI model of `GNT-20.0`
//! through `GNT-20.11-adapter-obligations-and-diagnostics`.
//!
//! These tests exercise the public `gantry::ir` surface of the operation ABI model
//! together with the landed authority and protected models it reuses. They check the
//! model the specification makes normative, not a runtime adapter or resource
//! registry: no test here observes a live sink, a provider, a host service, a clock,
//! a locale, a filesystem, or a protected payload, and every verdict is decided from
//! explicit arguments alone.
//!
//! Every test names the behavior it proves, and each invariant of the model has a
//! test that fails without its rule: a live resource is never a durable value, a
//! stale generation never settles a later operation, a cancellation is never a
//! definite not-started effect, an ambiguous effect is never retried without the
//! deduplication record of its own generation, a completion settles at most once, a
//! failure settles into exactly one declared state, compaction preserves every
//! identity needed to redispatch, and adapter substitution can neither widen
//! authority nor reuse a retired identity.

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    AdapterInstance, AuthorityRight, CanonicalImplementationIdentity, CanonicalPath, DedupRecord,
    DedupRecordState, DedupRetentionBounds, DisclosureBudget, DisclosureCharge, DispatchAdmission,
    DurableOperationCut, EffectCertainty, ExternalOutcome, FailureClass, FenceCategory,
    LiveResource, LoanId, LogicalOperationId, OPERATION_ABI_CLAUSES, OperationAbi,
    OperationAbiDiagnosticCode, OperationAbiError, OperationCancellation, OperationKind,
    OperationSettlement, OwnerGeneration, ProgressDisposition, ProgressObservation,
    ReceiverOwnership, ResourceGenerationId, ResourceState, RetryEligibility, RightsSet,
    StaticSiteId, StructuralPosition, TypeExpression, admit_dispatch, classify_effect,
    retry_eligibility,
};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming
/// the associated item requires an inference that cannot be resolved and compilation
/// fails. A deserializer for a resource generation, a loan, or a durable settlement, a
/// free conversion from text into one of them, and a default live handle would each
/// stop this crate compiling, which is exactly what `GNT-20.2`, `GNT-20.3`, and
/// `GNT-20.10` forbid.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_name:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait_name> AmbiguousIfImpl<Invalid> for T {}
            })+
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

/// The canonical operation declaration of every fixture.
const DECLARATION: &str = "crate::operation_abi";

/// Returns one canonical fixture path.
fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|_| unreachable!("fixture path is canonical"))
}

/// Returns one canonical fixture static site at one structural route.
fn site_at(components: &[u64]) -> StaticSiteId {
    let position = StructuralPosition::new(components.to_vec())
        .unwrap_or_else(|_| unreachable!("fixture structural position is canonical"));
    StaticSiteId::new(path(DECLARATION), position)
}

/// Returns the stable logical operation identity of one fixture site.
fn operation_at(site: &StaticSiteId) -> LogicalOperationId {
    LogicalOperationId::derive(&path(DECLARATION), site)
}

/// Returns the derived resource generation of one fixture site and counter.
fn resource_generation(site: &StaticSiteId, counter: u64) -> ResourceGenerationId {
    ResourceGenerationId::derive(&operation_at(site), site, counter)
}

/// Returns one sealed receiver loan of one fixture site and generation counter.
fn sealed_loan(site: &StaticSiteId, counter: u64) -> LoanId {
    LoanId::seal(
        &path(DECLARATION),
        site,
        &resource_generation(site, counter),
    )
}

/// Returns one fixture nonzero charge of one live-resource observation allowance.
fn charge(value: u64) -> DisclosureCharge {
    DisclosureCharge::new(value).unwrap_or_else(|| unreachable!("fixture charge is nonzero"))
}

/// Returns one fixture operation ABI over the canonical fixture site.
fn abi(
    kind: OperationKind,
    counter: u64,
    recovery: RecoveryClass,
    ownership: ReceiverOwnership,
) -> OperationAbi {
    OperationAbi::new(
        kind,
        &path(DECLARATION),
        &site_at(&[1, 2]),
        counter,
        recovery,
        ownership,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation ABI is admissible"))
}

/// Returns one fixture operation ABI over one deliberate other site.
fn abi_at(
    kind: OperationKind,
    components: &[u64],
    counter: u64,
    recovery: RecoveryClass,
) -> OperationAbi {
    OperationAbi::new(
        kind,
        &path(DECLARATION),
        &site_at(components),
        counter,
        recovery,
        ReceiverOwnership::RetainedByCaller,
    )
    .unwrap_or_else(|_| unreachable!("fixture operation ABI is admissible"))
}

/// Opens one fixture live resource of one operation ABI.
fn resource(operation: &OperationAbi, owner: OwnerGeneration, charge_value: u64) -> LiveResource {
    operation
        .open_live(
            owner,
            OperationAbi::observation_allowance(8, charge(charge_value)),
        )
        .unwrap_or_else(|_| unreachable!("fixture ABI carries a live handle"))
}

/// Returns one fixture durable settlement of one operation ABI.
fn settlement(
    operation: &OperationAbi,
    owner: OwnerGeneration,
    outcome: ExternalOutcome,
    progress: ProgressObservation,
    settled_at_us: u64,
) -> OperationSettlement {
    OperationSettlement::new(
        operation.operation(),
        operation.generation(),
        owner,
        outcome,
        progress,
        settled_at_us,
    )
    .unwrap_or_else(|_| unreachable!("fixture settlement names its own generation"))
}

/// Returns the canonical text of one resource's settlement, when it settled.
fn settled(live: &LiveResource) -> Option<String> {
    live.settlement().map(OperationSettlement::canonical_text)
}

/// Returns one fixture retention bound.
fn bounds(generations: u64, instants_us: u64) -> DedupRetentionBounds {
    DedupRetentionBounds::new(generations, instants_us)
        .unwrap_or_else(|_| unreachable!("fixture retention bounds are bounded"))
}

/// Returns one fixture authority rights set.
fn rights(list: &[AuthorityRight]) -> RightsSet {
    RightsSet::from_rights(list)
}

/// Returns one fixture downstream implementation identity.
fn implementation(name: &str) -> CanonicalImplementationIdentity {
    let receiver = TypeExpression::from_canonical_string(&format!("crate::{name}"), 4)
        .unwrap_or_else(|_| unreachable!("fixture receiver is a canonical type"));
    CanonicalImplementationIdentity::inherent(&receiver)
}

/// Returns one fixture adapter binding of one implementation, rights set, owner
/// generation, and binding sequence.
fn adapter(
    name: &str,
    list: &[AuthorityRight],
    generation: u64,
    binding_sequence: u64,
) -> AdapterInstance {
    AdapterInstance::bind(
        &implementation(name),
        rights(list),
        OwnerGeneration::new(generation),
        binding_sequence,
    )
}

/// Returns the frozen diagnostic code of one refusal.
fn refusal<T>(result: Result<T, OperationAbiError>) -> OperationAbiDiagnosticCode {
    match result {
        Ok(_) => unreachable!("the model must refuse this fixture"),
        Err(error) => error.code(),
    }
}

/// Returns the frozen diagnostic of one refusal, including its rendered text.
fn refusal_error<T>(result: Result<T, OperationAbiError>) -> OperationAbiError {
    match result {
        Ok(_) => unreachable!("the model must refuse this fixture"),
        Err(error) => error,
    }
}

#[test]
fn every_closed_vocabulary_round_trips_its_exact_wire_name() {
    // Each vocabulary is closed and exhaustive, so every member decodes back from the
    // exact spelling it publishes and an unknown spelling has no member.
    for kind in OperationKind::ALL {
        assert_eq!(OperationKind::from_wire_name(kind.wire_name()), Some(kind));
        assert_eq!(kind.as_str(), kind.wire_name());
    }
    for state in ResourceState::ALL {
        assert_eq!(
            ResourceState::from_wire_name(state.wire_name()),
            Some(state)
        );
        assert_eq!(state.as_str(), state.wire_name());
    }
    for progress in ProgressObservation::ALL {
        assert_eq!(
            ProgressObservation::from_wire_name(progress.wire_name()),
            Some(progress)
        );
        assert_eq!(progress.as_str(), progress.wire_name());
    }
    for disposition in ProgressDisposition::ALL {
        assert_eq!(
            ProgressDisposition::from_wire_name(disposition.wire_name()),
            Some(disposition)
        );
    }
    for certainty in EffectCertainty::ALL {
        assert_eq!(
            EffectCertainty::from_wire_name(certainty.wire_name()),
            Some(certainty)
        );
    }
    for eligibility in RetryEligibility::ALL {
        assert_eq!(
            RetryEligibility::from_wire_name(eligibility.wire_name()),
            Some(eligibility)
        );
    }
    for state in DedupRecordState::ALL {
        assert_eq!(
            DedupRecordState::from_wire_name(state.wire_name()),
            Some(state)
        );
    }
    for cut in DurableOperationCut::ALL {
        assert_eq!(
            DurableOperationCut::from_wire_name(cut.wire_name()),
            Some(cut)
        );
    }
    for failure in FailureClass::ALL {
        assert_eq!(
            FailureClass::from_wire_name(failure.wire_name()),
            Some(failure)
        );
    }
    for admission in DispatchAdmission::ALL {
        assert_eq!(
            DispatchAdmission::from_wire_name(admission.wire_name()),
            Some(admission)
        );
    }
    for cancellation in OperationCancellation::ALL {
        assert_eq!(
            OperationCancellation::from_wire_name(cancellation.wire_name()),
            Some(cancellation)
        );
    }
    assert_eq!(OperationKind::from_wire_name("durable-value"), None);
    assert_eq!(ProgressObservation::from_wire_name("end-of-file"), None);
    assert_eq!(ResourceState::from_wire_name(""), None);
}

#[test]
fn a_live_resource_operation_is_never_a_durable_value_and_carries_the_only_live_handle() {
    // The kind decides the live handle and the durable value as exact complements, so
    // no operation kind can be read as another one.
    assert_eq!(OperationKind::ALL.len(), 3);
    for kind in OperationKind::ALL {
        assert_eq!(kind.reports_durable_value(), !kind.carries_live_handle());
    }
    assert!(OperationKind::LiveResource.carries_live_handle());
    assert!(!OperationKind::LiveResource.reports_durable_value());

    let live = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    assert!(live.carries_live_handle());
    assert!(
        live.open_live(
            OwnerGeneration::initial(),
            OperationAbi::observation_allowance(4, charge(1)),
        )
        .is_ok()
    );
    assert_eq!(
        refusal(live.durable_value()),
        OperationAbiDiagnosticCode::DurableValueForLiveResource
    );

    for kind in [
        OperationKind::ValueAction,
        OperationKind::ProtectedOperation,
    ] {
        let value = abi(
            kind,
            1,
            RecoveryClass::ReadOnly,
            ReceiverOwnership::RetainedByCaller,
        );
        let record = value.durable_value().unwrap_or_else(|_| {
            unreachable!("a value action and a protected operation are durable")
        });
        assert_eq!(record.kind(), kind);
        assert_eq!(record.operation(), value.operation());
        assert_eq!(record.generation(), value.generation());
        assert!(!record.is_live_resource());
        assert_eq!(
            refusal(value.open_live(
                OwnerGeneration::initial(),
                OperationAbi::observation_allowance(4, charge(1)),
            )),
            OperationAbiDiagnosticCode::LiveHandleOnNonLiveKind
        );
    }
}

#[test]
fn receiver_arrangements_are_distinct_and_a_borrowed_receiver_is_a_sealed_loan() {
    let site = site_at(&[1, 2]);
    let loan = sealed_loan(&site, 1);
    let borrowed = ReceiverOwnership::BorrowedLoan(loan.clone());
    let transferred = ReceiverOwnership::TransferredIn(OwnerGeneration::new(2));
    let retained = ReceiverOwnership::RetainedByCaller;

    assert_eq!(ReceiverOwnership::WIRE_NAMES.len(), 3);
    assert_eq!(borrowed.wire_name(), "borrowed-loan");
    assert_eq!(transferred.wire_name(), "transferred-in");
    assert_eq!(retained.wire_name(), "retained-by-caller");
    assert!(borrowed.is_borrowed_loan() && !borrowed.is_transferred_in());
    assert!(borrowed.loan().is_some() && borrowed.owner().is_none());
    assert!(transferred.is_transferred_in() && transferred.loan().is_none());
    assert_eq!(transferred.owner(), Some(OwnerGeneration::new(2)));
    assert!(retained.is_retained_by_caller() && retained.loan().is_none());

    // The seal is the only path to a borrowed receiver, and it names its exact site
    // and generation, so it is accepted there and refused anywhere else.
    let declared = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        borrowed.clone(),
    );
    assert_eq!(declared.ownership(), &borrowed);
    assert_eq!(
        refusal(OperationAbi::new(
            OperationKind::LiveResource,
            &path(DECLARATION),
            &site,
            2,
            RecoveryClass::Idempotent,
            borrowed.clone(),
        )),
        OperationAbiDiagnosticCode::ForeignLoan
    );
    assert_eq!(
        refusal(OperationAbi::new(
            OperationKind::LiveResource,
            &path(DECLARATION),
            &site_at(&[3, 4]),
            1,
            RecoveryClass::Idempotent,
            borrowed,
        )),
        OperationAbiDiagnosticCode::ForeignLoan
    );

    // Equal seals are one identity and a later generation is a distinct one.
    assert_eq!(sealed_loan(&site, 1), loan);
    assert_ne!(sealed_loan(&site, 2), loan);
    assert_eq!(loan.site(), &site);
    assert_eq!(loan.generation(), &resource_generation(&site, 1));
    assert_eq!(
        loan.as_str(),
        format!("receiver-loan:{}", loan.digest_hex())
    );
    assert!(loan.matches(&site, &resource_generation(&site, 1)));
    assert!(!loan.matches(&site, &resource_generation(&site, 2)));
}

#[test]
fn a_stale_resource_generation_can_never_settle_a_later_operation() {
    let site = site_at(&[1, 2]);
    let first = resource_generation(&site, 1);
    let second = resource_generation(&site, 2);

    // The generation is derived from the operation, the exact site, and the counter,
    // so equal inputs produce one identity and a later counter a distinct one.
    assert_eq!(resource_generation(&site, 1), first);
    assert_ne!(first, second);
    assert_eq!(first.generation(), 1);
    assert_eq!(second.generation(), 2);
    assert_eq!(first.operation(), &operation_at(&site));
    assert_eq!(first.site(), &site);
    assert_eq!(
        first.as_str(),
        format!("resource-generation:{}", first.digest_hex())
    );
    assert_ne!(first.as_str(), second.as_str());

    let retired = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let current = abi(
        OperationKind::LiveResource,
        2,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let stale = settlement(
        &retired,
        OwnerGeneration::initial(),
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        10,
    );
    let mut live = resource(&current, OwnerGeneration::initial(), 1);
    assert_eq!(
        refusal(live.settle(&stale)),
        OperationAbiDiagnosticCode::StaleGeneration
    );
    assert!(live.settlement().is_none());
    assert_eq!(live.state(), ResourceState::Usable);
    assert_eq!(live.generation(), current.generation());

    // A settlement of one operation never names another operation's generation, even
    // when that generation is a later counter of the same declaration.
    let foreign = abi_at(
        OperationKind::LiveResource,
        &[3, 4],
        1,
        RecoveryClass::Idempotent,
    );
    assert_eq!(
        refusal(OperationSettlement::new(
            current.operation(),
            foreign.generation(),
            OwnerGeneration::initial(),
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            10,
        )),
        OperationAbiDiagnosticCode::ForeignOperation
    );
}

#[test]
fn cancellation_is_never_classified_definite_not_started() {
    // A requested cancellation races with admission, so the cancelled operation is
    // ambiguous rather than a definite not-started effect.
    assert_eq!(
        classify_effect(
            DurableOperationCut::Declared,
            OperationCancellation::Requested
        ),
        EffectCertainty::AmbiguouslyBegun
    );
    assert!(
        !classify_effect(
            DurableOperationCut::Declared,
            OperationCancellation::Requested
        )
        .is_definite_not_started()
    );

    // Only an operation that has not passed admission and was not cancelled is a
    // definite not-started effect.
    assert_eq!(
        classify_effect(
            DurableOperationCut::Declared,
            OperationCancellation::NotRequested
        ),
        EffectCertainty::DefiniteNotStarted
    );
    for cut in [
        DurableOperationCut::Admitted,
        DurableOperationCut::Dispatched,
        DurableOperationCut::Settled,
    ] {
        for cancellation in OperationCancellation::ALL {
            assert_eq!(
                classify_effect(cut, cancellation),
                EffectCertainty::AmbiguouslyBegun
            );
            assert!(!classify_effect(cut, cancellation).is_definite_not_started());
        }
    }

    // The cut order decides admission, so dispatch is refused before it.
    assert!(!DurableOperationCut::Declared.is_at_or_after_admission());
    for cut in [
        DurableOperationCut::Admitted,
        DurableOperationCut::Dispatched,
        DurableOperationCut::Settled,
    ] {
        assert!(cut.is_at_or_after_admission());
    }
    assert!(DurableOperationCut::Declared.rank() < DurableOperationCut::Admitted.rank());
}

#[test]
fn an_ambiguous_effect_is_never_retry_eligible_without_the_record_of_its_own_generation() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        2,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );

    // A definitely not-started effect is retried as a fresh invocation.
    assert_eq!(
        retry_eligibility(
            EffectCertainty::DefiniteNotStarted,
            RecoveryClass::NonIdempotent,
            None,
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::Eligible
    );

    // An ambiguous effect without a record is never eligible, for any recovery class.
    for recovery in [
        RecoveryClass::ReadOnly,
        RecoveryClass::Idempotent,
        RecoveryClass::NonIdempotent,
    ] {
        let verdict = retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            recovery,
            None,
            current.operation(),
            current.generation(),
        );
        assert_eq!(verdict, RetryEligibility::Ineligible);
        assert!(!verdict.is_eligible());
    }

    // A record of another generation is not the deduplication record of this one.
    let other = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let foreign = DedupRecord::authoritative(
        settlement(
            &other,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            10,
        ),
        bounds(1, 100),
    );
    assert_eq!(
        retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            RecoveryClass::NonIdempotent,
            Some(&foreign),
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::Ineligible
    );

    // The record of the exact operation and generation gates the retry: a repeat that
    // must not run twice requires the proof, an idempotent repeat may proceed.
    let record = DedupRecord::authoritative(
        settlement(
            &current,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            10,
        ),
        bounds(1, 100),
    );
    assert_eq!(
        retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            RecoveryClass::NonIdempotent,
            Some(&record),
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::RequiresDeduplicationProof
    );
    assert_eq!(
        retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            RecoveryClass::Idempotent,
            Some(&record),
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::Eligible
    );
    assert!(
        !retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            RecoveryClass::Idempotent,
            None,
            current.operation(),
            current.generation(),
        )
        .is_eligible()
    );

    // A retired record never authorizes a retry of the generation it retired.
    let retired = record
        .clone()
        .request_retirement(owner.advanced())
        .unwrap_or_else(|_| unreachable!("a settled record retires under an advanced owner"));
    assert_eq!(
        retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            RecoveryClass::Idempotent,
            Some(&retired),
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::Ineligible
    );
}

#[test]
fn a_crash_before_admission_carries_no_effect_and_a_crash_after_admission_without_proof_is_ambiguous()
 {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );

    // A crash before admission carries no effect and is never ambiguous.
    let no_effect = current.classify_crash_cut(DurableOperationCut::Declared, None);
    assert!(no_effect.is_no_effect());
    assert!(!no_effect.is_ambiguous());
    assert!(no_effect.settlement().is_none());
    assert_eq!(no_effect.wire_name(), "no-effect");

    // A crash at or after admission without retained proof is ambiguous.
    for cut in [
        DurableOperationCut::Admitted,
        DurableOperationCut::Dispatched,
        DurableOperationCut::Settled,
    ] {
        let ambiguous = current.classify_crash_cut(cut, None);
        assert!(ambiguous.is_ambiguous());
        assert!(!ambiguous.is_no_effect());
        assert!(ambiguous.settlement().is_none());
        assert_eq!(ambiguous.wire_name(), "ambiguous");
    }

    // A record of another site is no proof of this operation.
    let other = abi_at(
        OperationKind::LiveResource,
        &[3, 4],
        1,
        RecoveryClass::Idempotent,
    );
    let foreign = DedupRecord::authoritative(
        settlement(
            &other,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            10,
        ),
        bounds(1, 100),
    );
    assert!(
        current
            .classify_crash_cut(DurableOperationCut::Admitted, Some(&foreign))
            .is_ambiguous()
    );

    // A record that rejected a stale owner carries no settlement, so it is no proof
    // either, and the identity and settlement are reconstructed only from a record
    // that carries a durable settlement of this exact generation.
    let rejected = DedupRecord::rejected_stale_owner(
        current.operation(),
        current.generation(),
        owner,
        bounds(1, 100),
    );
    assert!(
        current
            .classify_crash_cut(DurableOperationCut::Admitted, Some(&rejected))
            .is_ambiguous()
    );

    let record = DedupRecord::authoritative(
        settlement(
            &current,
            owner,
            ExternalOutcome::Rejected,
            ProgressObservation::NotStarted,
            20,
        ),
        bounds(1, 100),
    );
    let reconstructed = current.classify_crash_cut(DurableOperationCut::Dispatched, Some(&record));
    assert!(!reconstructed.is_ambiguous());
    assert!(!reconstructed.is_no_effect());
    assert_eq!(reconstructed.wire_name(), "settled");
    assert_eq!(
        reconstructed
            .settlement()
            .map(OperationSettlement::canonical_text),
        record.settlement().map(OperationSettlement::canonical_text)
    );
    assert_eq!(
        reconstructed
            .settlement()
            .map(OperationSettlement::generation),
        Some(current.generation())
    );
}

#[test]
fn partial_progress_is_distinct_from_completion_and_eof() {
    // A short read and a short write are progress, never completion and never EOF.
    for progress in [
        ProgressObservation::PartialAdvance,
        ProgressObservation::ShortRead,
        ProgressObservation::ShortWrite,
    ] {
        assert!(progress.is_progress());
        assert!(!progress.is_completion());
        assert!(!progress.is_eof());
        assert_eq!(progress.disposition(), ProgressDisposition::Progress);
    }
    assert_eq!(
        ProgressObservation::Eof.disposition(),
        ProgressDisposition::EndOfStream
    );
    assert!(ProgressObservation::Eof.is_eof() && !ProgressObservation::Eof.is_completion());
    assert_eq!(
        ProgressObservation::CommittedProgress.disposition(),
        ProgressDisposition::Completion
    );
    assert!(ProgressObservation::CommittedProgress.is_completion());
    assert!(!ProgressObservation::CommittedProgress.is_eof());
    assert_eq!(
        ProgressObservation::NotStarted.disposition(),
        ProgressDisposition::NotStarted
    );
    assert_eq!(ProgressDisposition::ALL.len(), 4);

    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let mut live = resource(&current, owner, 1);
    let observed = live
        .observe(ProgressObservation::ShortRead)
        .unwrap_or_else(|_| unreachable!("a usable resource observes progress"));
    assert_eq!(observed.progress(), ProgressObservation::ShortRead);
    assert_eq!(live.state(), ResourceState::PartiallyAdvanced);

    // A short read never becomes an end of stream, and partial progress never becomes
    // a committed completion.
    let eof_claim = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::Eof,
        10,
    );
    assert_eq!(
        refusal(live.settle(&eof_claim)),
        OperationAbiDiagnosticCode::ShortObservationAsEof
    );
    let completion_claim = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        10,
    );
    assert_eq!(
        refusal(live.settle(&completion_claim)),
        OperationAbiDiagnosticCode::PartialProgressAsCompletion
    );
    assert!(live.settlement().is_none());
    assert_eq!(live.progress(), ProgressObservation::ShortRead);

    // The guard is symmetric: a claimed progress must equal the observed progress or be
    // a declared upgrade of it, so progress never moves backwards, a committed completion
    // is never reported as an end of stream, and the declared progress record is retained.
    assert!(ProgressObservation::NotStarted.upgrades_to(ProgressObservation::CommittedProgress));
    assert!(ProgressObservation::PartialAdvance.upgrades_to(ProgressObservation::Eof));
    assert!(ProgressObservation::ShortRead.upgrades_to(ProgressObservation::PartialAdvance));
    assert!(!ProgressObservation::CommittedProgress.upgrades_to(ProgressObservation::Eof));
    assert!(!ProgressObservation::Eof.upgrades_to(ProgressObservation::PartialAdvance));
    assert!(!ProgressObservation::PartialAdvance.upgrades_to(ProgressObservation::NotStarted));
    assert!(!ProgressObservation::ShortRead.upgrades_to(ProgressObservation::Eof));
    assert!(ProgressObservation::Eof.upgrades_to(ProgressObservation::Eof));
    assert!(
        ProgressObservation::CommittedProgress.upgrades_to(ProgressObservation::CommittedProgress)
    );

    let mut completed = resource(&current, owner, 1);
    completed
        .observe(ProgressObservation::CommittedProgress)
        .unwrap_or_else(|_| unreachable!("a usable resource observes its completion"));
    let backwards_eof = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::Eof,
        12,
    );
    assert_eq!(
        refusal(completed.settle(&backwards_eof)),
        OperationAbiDiagnosticCode::ProgressObservationMismatch
    );
    assert_eq!(completed.progress(), ProgressObservation::CommittedProgress);
    assert!(completed.settlement().is_none());

    let mut progressed = resource(&current, owner, 1);
    progressed
        .observe(ProgressObservation::PartialAdvance)
        .unwrap_or_else(|_| unreachable!("a usable resource observes progress"));
    let backwards_unstarted = settlement(
        &current,
        owner,
        ExternalOutcome::Ambiguous,
        ProgressObservation::NotStarted,
        12,
    );
    assert_eq!(
        refusal(progressed.settle(&backwards_unstarted)),
        OperationAbiDiagnosticCode::ProgressObservationMismatch
    );
    assert_eq!(progressed.progress(), ProgressObservation::PartialAdvance);
    assert!(progressed.settlement().is_none());

    // A declared upgrade of the observed progress is accepted, and the declared progress
    // record advances with it rather than being discarded.
    let upgraded = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::Eof,
        13,
    );
    progressed
        .settle(&upgraded)
        .unwrap_or_else(|_| unreachable!("an end of stream upgrades an observed partial advance"));
    assert_eq!(progressed.progress(), ProgressObservation::Eof);

    // An end of stream closes a usable resource and a committed completion consumes it.
    let mut eof_resource = resource(&current, owner, 1);
    eof_resource
        .observe(ProgressObservation::Eof)
        .unwrap_or_else(|_| unreachable!("a usable resource observes its end of stream"));
    assert_eq!(eof_resource.state(), ResourceState::Closed);
    let mut completing = resource(&current, owner, 1);
    completing
        .observe(ProgressObservation::CommittedProgress)
        .unwrap_or_else(|_| unreachable!("a usable resource observes a completion"));
    completing
        .settle(&completion_claim)
        .unwrap_or_else(|_| unreachable!("the matching completion settles"));
    assert_eq!(completing.state(), ResourceState::Consumed);

    // The declared post-settlement state is a function of the outcome and the progress.
    assert_eq!(
        settlement(
            &current,
            owner,
            ExternalOutcome::Ambiguous,
            ProgressObservation::NotStarted,
            1
        )
        .resource_state(),
        ResourceState::Poisoned
    );
    assert_eq!(
        settlement(
            &current,
            owner,
            ExternalOutcome::Rejected,
            ProgressObservation::NotStarted,
            1
        )
        .resource_state(),
        ResourceState::Usable
    );
    assert_eq!(
        settlement(
            &current,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::Eof,
            1
        )
        .resource_state(),
        ResourceState::Closed
    );
    assert_eq!(
        settlement(
            &current,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::PartialAdvance,
            1,
        )
        .resource_state(),
        ResourceState::PartiallyAdvanced
    );
}

#[test]
fn a_duplicate_late_or_wrong_generation_completion_settles_exactly_once() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let mut live = resource(&current, owner, 1);
    let winner = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        10,
    );
    live.settle(&winner)
        .unwrap_or_else(|_| unreachable!("the first completion settles"));
    assert_eq!(settled(&live), Some(winner.canonical_text()));
    assert_eq!(live.state(), ResourceState::Consumed);

    // The duplicate and the late completion both lose the race and record nothing.
    let duplicate = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        11,
    );
    let late = settlement(
        &current,
        owner,
        ExternalOutcome::Ambiguous,
        ProgressObservation::PartialAdvance,
        12,
    );
    assert_eq!(
        refusal(live.settle(&duplicate)),
        OperationAbiDiagnosticCode::SecondSettlement
    );
    assert_eq!(
        refusal(live.settle(&late)),
        OperationAbiDiagnosticCode::SecondSettlement
    );
    assert_eq!(settled(&live), Some(winner.canonical_text()));

    // A completion of a later generation never settles this generation, and a
    // completion of a stale owner generation never settles this owner.
    let later = abi(
        OperationKind::LiveResource,
        2,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let mut later_live = resource(&later, owner, 1);
    assert_eq!(
        refusal(later_live.settle(&winner)),
        OperationAbiDiagnosticCode::StaleGeneration
    );
    assert!(later_live.settlement().is_none());

    let mut owner_live = resource(&later, owner.advanced(), 1);
    let stale_owner = settlement(
        &later,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        14,
    );
    assert_eq!(
        refusal(owner_live.settle(&stale_owner)),
        OperationAbiDiagnosticCode::StaleOwnerGeneration
    );
    assert!(owner_live.settlement().is_none());

    // The refusals recorded nothing, so the correct generation and owner still settles.
    let correct = settlement(
        &later,
        owner.advanced(),
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        15,
    );
    owner_live
        .settle(&correct)
        .unwrap_or_else(|_| unreachable!("the generation and owner the resource holds settle"));
    assert_eq!(settled(&owner_live), Some(correct.canonical_text()));
}

#[test]
fn the_cancellation_race_has_exactly_one_settlement_winner() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );

    // A cancellation requested after admission is ambiguous, so it can never be
    // retried as a fresh invocation.
    let ambiguity = classify_effect(
        DurableOperationCut::Admitted,
        OperationCancellation::Requested,
    );
    assert_eq!(ambiguity, EffectCertainty::AmbiguouslyBegun);
    assert_eq!(
        retry_eligibility(
            ambiguity,
            RecoveryClass::NonIdempotent,
            None,
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::Ineligible
    );

    // The adapter path and the cancellation path both present a completion of one
    // generation, and the first presented completion is the only winner.
    let adapter_winner = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        10,
    );
    let cancellation_candidate = settlement(
        &current,
        owner,
        ExternalOutcome::Ambiguous,
        ProgressObservation::PartialAdvance,
        10,
    );
    let mut live = resource(&current, owner, 1);
    live.settle(&adapter_winner)
        .unwrap_or_else(|_| unreachable!("the first presented completion settles"));
    assert_eq!(
        refusal(live.settle(&cancellation_candidate)),
        OperationAbiDiagnosticCode::SecondSettlement
    );
    assert_eq!(settled(&live), Some(adapter_winner.canonical_text()));

    // The mirrored race has exactly one winner as well.
    let mut mirrored = resource(&current, owner, 1);
    mirrored
        .settle(&cancellation_candidate)
        .unwrap_or_else(|_| unreachable!("the first presented completion settles"));
    assert_eq!(
        refusal(mirrored.settle(&adapter_winner)),
        OperationAbiDiagnosticCode::SecondSettlement
    );
    assert_eq!(
        settled(&mirrored),
        Some(cancellation_candidate.canonical_text())
    );
}

#[test]
fn an_interruption_retains_the_declared_progress_record() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let mut live = resource(&current, owner, 1);

    // A resource that observed nothing interrupts with its declared not-started record.
    let untouched = live.interrupt();
    assert_eq!(untouched.progress(), ProgressObservation::NotStarted);
    assert_eq!(untouched.operation(), current.operation());
    assert_eq!(untouched.generation(), current.generation());
    assert_eq!(untouched.owner(), owner);

    let observed = live
        .observe(ProgressObservation::PartialAdvance)
        .unwrap_or_else(|_| unreachable!("a usable resource observes progress"));
    assert_eq!(observed.progress(), ProgressObservation::PartialAdvance);
    assert_eq!(live.observation_allowance().accepted(), 1);

    // The interruption loses no progress and changes no state, so a resume continues
    // from the progress that was actually declared.
    let interrupted = live.interrupt();
    assert_eq!(interrupted.canonical_text(), observed.canonical_text());
    assert_eq!(interrupted.progress(), ProgressObservation::PartialAdvance);
    assert_eq!(live.progress(), ProgressObservation::PartialAdvance);
    assert_eq!(live.state(), ResourceState::PartiallyAdvanced);
    assert_eq!(
        live.interrupt().progress(),
        ProgressObservation::PartialAdvance
    );
    assert_eq!(live.observation_allowance().accepted(), 1);
}

#[test]
fn failure_settlement_yields_exactly_one_declared_state_and_poisons_the_adapter_instance() {
    let owner = OwnerGeneration::initial();
    let live_abi = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::TransferredIn(owner.advanced()),
    );
    let mut live = resource(&live_abi, owner, 1);

    // An adapter failure half-closes the resource, poisons the failing instance, and
    // preserves the declared ownership and the generation.
    let half = live
        .settle_failure(FailureClass::AdapterFailure)
        .unwrap_or_else(|_| unreachable!("an open resource half-closes after an adapter failure"));
    assert_eq!(half.state(), ResourceState::HalfClosed);
    assert_eq!(half.ownership(), live_abi.ownership());
    assert_eq!(half.generation(), live.generation());
    assert!(half.poisons_adapter());
    assert_eq!(live.state(), ResourceState::HalfClosed);

    // A resource failure poisons the resource, and poisoning it twice is refused.
    let mut poisoned = resource(&live_abi, owner, 1);
    let settlement = poisoned
        .settle_failure(FailureClass::ResourceFailure)
        .unwrap_or_else(|_| unreachable!("an open resource is poisoned by a resource failure"));
    assert_eq!(settlement.state(), ResourceState::Poisoned);
    assert!(!settlement.poisons_adapter());
    assert_eq!(poisoned.state(), ResourceState::Poisoned);
    assert_eq!(
        refusal(poisoned.settle_failure(FailureClass::ResourceFailure)),
        OperationAbiDiagnosticCode::PoisonedResourceReuse
    );

    // A value action and a protected operation carry no live half, so their declared
    // post-failure states are the durable ones.
    for kind in [
        OperationKind::ValueAction,
        OperationKind::ProtectedOperation,
    ] {
        let value = abi(
            kind,
            1,
            RecoveryClass::NonIdempotent,
            ReceiverOwnership::TransferredIn(owner),
        );
        let adapter_failed = value.settle_failure(FailureClass::AdapterFailure);
        assert_eq!(adapter_failed.state(), ResourceState::Consumed);
        assert!(adapter_failed.poisons_adapter());
        assert_eq!(adapter_failed.ownership(), value.ownership());
        let resource_failed = value.settle_failure(FailureClass::ResourceFailure);
        assert_eq!(resource_failed.state(), ResourceState::PartiallyAdvanced);
        assert!(!resource_failed.poisons_adapter());
        assert!(ResourceState::ALL.contains(&resource_failed.state()));
        assert!(FailureClass::ALL.contains(&FailureClass::AdapterFailure));
    }

    // A poisoned adapter instance is never reused and never substituted.
    let mut binding = adapter(
        "FailureAdapter",
        &[AuthorityRight::InvokeNonIdempotent],
        0,
        0,
    );
    let non_idempotent = abi(
        OperationKind::ValueAction,
        2,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    binding
        .dispatch(&non_idempotent)
        .unwrap_or_else(|_| unreachable!("the matching right dispatches"));
    binding.poison();
    assert!(binding.is_poisoned());
    assert_eq!(
        refusal(binding.dispatch(&non_idempotent)),
        OperationAbiDiagnosticCode::AdapterInstancePoisoned
    );
    assert_eq!(
        refusal(binding.substitute(
            &implementation("FailureAdapterB"),
            rights(&[AuthorityRight::InvokeNonIdempotent]),
            OwnerGeneration::new(1),
            1,
        )),
        OperationAbiDiagnosticCode::AdapterInstancePoisoned
    );

    // A binding must carry the right the declared recovery class demands.
    let insufficient = adapter("InsufficientAdapter", &[AuthorityRight::Observe], 0, 0);
    assert_eq!(
        refusal(insufficient.dispatch(&non_idempotent)),
        OperationAbiDiagnosticCode::AdapterRightsInsufficient
    );
    let read_only = abi(
        OperationKind::ValueAction,
        3,
        RecoveryClass::ReadOnly,
        ReceiverOwnership::RetainedByCaller,
    );
    assert_eq!(
        refusal(insufficient.dispatch(&read_only)),
        OperationAbiDiagnosticCode::AdapterRightsInsufficient
    );
    assert!(binding.is_poisoned() && !binding.is_retired());
}

#[test]
fn half_close_preserves_the_still_open_half_and_its_generation() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::BorrowedLoan(sealed_loan(&site_at(&[1, 2]), 1)),
    );
    let mut live = resource(&current, owner, 1);
    let generation = live.generation().clone();

    live.half_close()
        .unwrap_or_else(|_| unreachable!("a usable resource half-closes"));
    assert_eq!(live.state(), ResourceState::HalfClosed);
    assert_eq!(live.generation(), &generation);
    assert_eq!(live.owner(), owner);
    assert_eq!(live.ownership(), current.ownership());

    // A half-closed resource has no second half to close and no open half to observe.
    assert_eq!(
        refusal(live.half_close()),
        OperationAbiDiagnosticCode::HalfCloseWithoutOpenHalf
    );
    assert_eq!(
        refusal(live.observe(ProgressObservation::PartialAdvance)),
        OperationAbiDiagnosticCode::ResourceNotUsable
    );
    assert_eq!(
        refusal(live.settle_failure(FailureClass::AdapterFailure)),
        OperationAbiDiagnosticCode::HalfCloseWithoutOpenHalf
    );

    // A consumed resource has no still-open half either.
    let mut consumed = resource(&current, owner, 1);
    consumed
        .settle(&settlement(
            &current,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            10,
        ))
        .unwrap_or_else(|_| unreachable!("the completion settles"));
    assert_eq!(consumed.state(), ResourceState::Consumed);
    assert_eq!(
        refusal(consumed.half_close()),
        OperationAbiDiagnosticCode::HalfCloseWithoutOpenHalf
    );
}

#[test]
fn post_failure_ownership_is_exactly_one_declared_state_for_every_receiver_arrangement() {
    let owner = OwnerGeneration::new(2);
    let arrangements = [
        ReceiverOwnership::BorrowedLoan(sealed_loan(&site_at(&[1, 2]), 1)),
        ReceiverOwnership::TransferredIn(owner),
        ReceiverOwnership::RetainedByCaller,
    ];
    for arrangement in arrangements {
        let current = abi(
            OperationKind::LiveResource,
            1,
            RecoveryClass::NonIdempotent,
            arrangement.clone(),
        );
        for failure in FailureClass::ALL {
            let settled = current.settle_failure(failure);
            // Exactly one declared post-failure state and one declared arrangement.
            assert!(ResourceState::ALL.contains(&settled.state()));
            assert_eq!(settled.ownership(), &arrangement);
            assert_eq!(settled.operation(), current.operation());
            assert_eq!(settled.generation(), current.generation());
            assert_eq!(
                settled.poisons_adapter(),
                failure == FailureClass::AdapterFailure
            );
            assert!(settled.canonical_text().contains(arrangement.wire_name()));
            assert!(
                settled
                    .canonical_text()
                    .contains(settled.state().wire_name())
            );
        }
    }
}

#[test]
fn compaction_preserves_every_identity_needed_to_redispatch_and_restart_reconstructs_the_record() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let durable = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        40,
    );
    let record = DedupRecord::authoritative(durable.clone(), bounds(2, 100));
    assert_eq!(record.state(), DedupRecordState::Authoritative);
    assert!(record.matches(current.operation(), current.generation()));
    assert_eq!(
        record.settlement().map(OperationSettlement::canonical_text),
        Some(durable.canonical_text())
    );

    // Compaction keeps the operation, the generation, the owner, and the settlement,
    // so the compacted record still answers its own identity and still gates the retry.
    let compacted = record.compact(bounds(1, 50));
    assert_eq!(compacted.state(), DedupRecordState::Compacted);
    assert!(compacted.matches(current.operation(), current.generation()));
    assert_eq!(compacted.operation(), record.operation());
    assert_eq!(compacted.generation(), record.generation());
    assert_eq!(compacted.owner(), record.owner());
    assert_eq!(
        compacted
            .settlement()
            .map(OperationSettlement::canonical_text),
        Some(durable.canonical_text())
    );
    assert_eq!(
        retry_eligibility(
            EffectCertainty::AmbiguouslyBegun,
            RecoveryClass::NonIdempotent,
            Some(&compacted),
            current.operation(),
            current.generation(),
        ),
        RetryEligibility::RequiresDeduplicationProof
    );

    // A restart reconstructs identity and settlement from retained evidence...
    let restored = DedupRecord::restore(
        current.operation(),
        current.generation(),
        DedupRecordState::Compacted,
        Some(durable.clone()),
        owner,
        bounds(1, 50),
    )
    .unwrap_or_else(|_| unreachable!("retained evidence reconstructs the record"));
    assert_eq!(restored.state(), DedupRecordState::Compacted);
    assert!(restored.matches(current.operation(), current.generation()));
    assert_eq!(
        restored
            .settlement()
            .map(OperationSettlement::canonical_text),
        Some(durable.canonical_text())
    );

    // ... and refuses to reconstruct what the evidence does not carry.
    for state in [
        DedupRecordState::Authoritative,
        DedupRecordState::Compacted,
        DedupRecordState::Retired,
    ] {
        assert_eq!(
            refusal(DedupRecord::restore(
                current.operation(),
                current.generation(),
                state,
                None,
                owner,
                bounds(1, 50),
            )),
            OperationAbiDiagnosticCode::SettlementEvidenceMissing
        );
    }
    let later = abi(
        OperationKind::LiveResource,
        2,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    assert_eq!(
        refusal(DedupRecord::restore(
            later.operation(),
            later.generation(),
            DedupRecordState::Authoritative,
            Some(durable.clone()),
            owner,
            bounds(1, 50),
        )),
        OperationAbiDiagnosticCode::StaleGeneration
    );
    assert_eq!(
        refusal(DedupRecord::restore(
            current.operation(),
            current.generation(),
            DedupRecordState::RejectedStaleOwner,
            Some(durable.clone()),
            owner,
            bounds(1, 50),
        )),
        OperationAbiDiagnosticCode::SettlementForStaleOwner
    );

    // A restored record carries the owner generation its settlement names, so a record
    // whose settlement names another owner generation is refused rather than restored
    // against an unrelated owner, and retirement always compares against the settling
    // generation.
    assert_eq!(
        refusal(DedupRecord::restore(
            current.operation(),
            current.generation(),
            DedupRecordState::Authoritative,
            Some(durable.clone()),
            owner.advanced(),
            bounds(1, 50),
        )),
        OperationAbiDiagnosticCode::StaleOwnerGeneration
    );
    let restored_under_settling_owner = DedupRecord::restore(
        current.operation(),
        current.generation(),
        DedupRecordState::Authoritative,
        Some(durable.clone()),
        durable.owner(),
        bounds(1, 50),
    )
    .unwrap_or_else(|_| unreachable!("the settlement's own owner restores the record"));
    assert_eq!(restored_under_settling_owner.owner(), durable.owner());
    assert_eq!(
        restored_under_settling_owner
            .settlement()
            .map(OperationSettlement::canonical_text),
        Some(durable.canonical_text())
    );
    assert_eq!(
        refusal(
            restored_under_settling_owner
                .clone()
                .request_retirement(durable.owner())
        ),
        OperationAbiDiagnosticCode::RetirementWithoutAdvancedOwner
    );
    let retired_restored = restored_under_settling_owner
        .request_retirement(durable.owner().advanced())
        .unwrap_or_else(|_| unreachable!("an advanced owner retires the restored record"));
    assert_eq!(retired_restored.state(), DedupRecordState::Retired);
    assert_eq!(retired_restored.owner(), durable.owner().advanced());
    assert!(retired_restored.fences(durable.owner()));
    assert!(!retired_restored.fences(durable.owner().advanced().advanced()));

    // A record that rejected a stale owner carries no settlement and no retention
    // evidence, and it restores without one.
    let rejected = DedupRecord::rejected_stale_owner(
        current.operation(),
        current.generation(),
        owner,
        bounds(1, 50),
    );
    assert_eq!(rejected.state(), DedupRecordState::RejectedStaleOwner);
    assert!(rejected.settlement().is_none());
    assert!(!rejected.retains(owner, 40));
    assert!(!DedupRecordState::RejectedStaleOwner.carries_settlement());
    assert!(!DedupRecordState::Retired.carries_proof());
    assert!(
        DedupRecord::restore(
            current.operation(),
            current.generation(),
            DedupRecordState::RejectedStaleOwner,
            None,
            owner,
            bounds(1, 50),
        )
        .is_ok()
    );

    // Retention bounds are declared, bounded, and deterministic in their arguments.
    assert_eq!(
        refusal(DedupRetentionBounds::new(0, 0)),
        OperationAbiDiagnosticCode::UnboundedRetention
    );
    let declared = bounds(1, 100);
    assert_eq!(declared.generations(), 1);
    assert_eq!(declared.instants_us(), 100);
    assert_eq!(declared.canonical_text(), "generations=1;instants-us=100");
    assert!(declared.retains(owner, 40, owner.advanced(), 140));
    assert!(!declared.retains(owner, 40, OwnerGeneration::new(3), 140));
    assert!(!declared.retains(owner, 40, owner.advanced(), 141));
    assert!(record.retains(owner.advanced(), 140));
    assert!(!record.retains(owner, 141));
}

#[test]
fn retirement_requires_durable_settlement_and_an_advanced_owner_generation_and_fences_the_stale_owner()
 {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let record = DedupRecord::authoritative(
        settlement(
            &current,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            10,
        ),
        bounds(1, 100),
    );
    let unproven = DedupRecord::rejected_stale_owner(
        current.operation(),
        current.generation(),
        owner,
        bounds(1, 100),
    );

    // Retirement without durable settlement, and retirement that does not advance the
    // owner generation, are both refused.
    assert_eq!(
        refusal(unproven.clone().request_retirement(owner.advanced())),
        OperationAbiDiagnosticCode::RetirementWithoutSettlement
    );
    assert_eq!(
        refusal(record.clone().request_retirement(owner)),
        OperationAbiDiagnosticCode::RetirementWithoutAdvancedOwner
    );
    // A record retired at one owner generation is not retired again by an owner that
    // does not advance past it.
    let retired_once = record
        .clone()
        .request_retirement(owner.advanced())
        .unwrap_or_else(|_| unreachable!("a settled record retires under an advanced owner"));
    assert_eq!(
        refusal(retired_once.request_retirement(owner.advanced())),
        OperationAbiDiagnosticCode::RetirementWithoutAdvancedOwner
    );

    // The durable settlement plus an advanced owner generation retires the record.
    let retired = record
        .clone()
        .request_retirement(owner.advanced())
        .unwrap_or_else(|_| unreachable!("a settled record retires under an advanced owner"));
    assert_eq!(retired.state(), DedupRecordState::Retired);
    assert_eq!(retired.owner(), owner.advanced());
    assert_eq!(
        retired
            .settlement()
            .map(OperationSettlement::canonical_text),
        record.settlement().map(OperationSettlement::canonical_text)
    );

    // The retired record fences the stale owner and admits no invocation through it.
    assert!(retired.fences(owner));
    assert!(retired.fences(owner.advanced()));
    assert!(!retired.fences(owner.advanced().advanced()));
    assert!(!record.fences(owner));
    assert_eq!(
        refusal(admit_dispatch(
            &current,
            DurableOperationCut::Admitted,
            OperationCancellation::NotRequested,
            Some(&retired),
            owner,
        )),
        OperationAbiDiagnosticCode::RetiredRecordFencesStaleOwner
    );

    // A genuinely advanced owner is admitted as a fresh invocation instead.
    assert_eq!(
        admit_dispatch(
            &current,
            DurableOperationCut::Admitted,
            OperationCancellation::NotRequested,
            Some(&retired),
            owner.advanced().advanced(),
        )
        .unwrap_or_else(|_| unreachable!("an advanced owner dispatches past the retired record")),
        DispatchAdmission::Fresh
    );

    // A record that rejected a stale owner refuses the stale owner as well.
    assert_eq!(
        refusal(admit_dispatch(
            &current,
            DurableOperationCut::Admitted,
            OperationCancellation::NotRequested,
            Some(&unproven),
            owner,
        )),
        OperationAbiDiagnosticCode::StaleOwnerGeneration
    );
}

#[test]
fn adapter_substitution_cannot_widen_authority_or_reuse_a_retired_identity() {
    let declared = adapter(
        "SubstitutionAdapterA",
        &[AuthorityRight::Observe, AuthorityRight::InvokeIdempotent],
        0,
        0,
    );
    let narrower = declared
        .substitute(
            &implementation("SubstitutionAdapterB"),
            rights(&[AuthorityRight::InvokeIdempotent]),
            OwnerGeneration::new(1),
            1,
        )
        .unwrap_or_else(|_| {
            unreachable!("a narrowing substitution under an advanced owner is accepted")
        });
    assert!(narrower.rights().is_subset_of(declared.rights()));
    assert_eq!(narrower.generation(), OwnerGeneration::new(1));
    assert_eq!(
        narrower.implementation(),
        &implementation("SubstitutionAdapterB")
    );
    assert!(!narrower.is_poisoned() && !narrower.is_retired());
    assert_ne!(narrower.as_str(), declared.as_str());
    assert_eq!(declared.binding_sequence(), 0);
    assert_eq!(narrower.binding_sequence(), 1);
    assert_eq!(
        narrower.as_str(),
        format!("adapter-instance:{}", narrower.digest_hex())
    );
    // Binding is a pure derivation of its declared inputs, so the same sequence
    // reproduces the same identity.
    assert_eq!(
        declared.as_str(),
        AdapterInstance::bind(
            &implementation("SubstitutionAdapterA"),
            rights(&[AuthorityRight::Observe, AuthorityRight::InvokeIdempotent]),
            OwnerGeneration::initial(),
            0,
        )
        .as_str()
    );

    // A substitution that would widen authority is refused.
    assert_eq!(
        refusal(declared.substitute(
            &implementation("SubstitutionAdapterB"),
            rights(&[AuthorityRight::Observe, AuthorityRight::InvokeNonIdempotent]),
            OwnerGeneration::new(1),
            1,
        )),
        OperationAbiDiagnosticCode::AdapterWidensAuthority
    );
    // A substitution that does not advance the owner generation is refused.
    assert_eq!(
        refusal(declared.substitute(
            &implementation("SubstitutionAdapterB"),
            rights(&[AuthorityRight::InvokeIdempotent]),
            OwnerGeneration::initial(),
            1,
        )),
        OperationAbiDiagnosticCode::StaleOwnerGeneration
    );

    // A retired identity is never reused for dispatch or substitution.
    let mut retired = declared.clone();
    retired.retire();
    assert!(retired.is_retired());
    assert_eq!(
        refusal(retired.substitute(
            &implementation("SubstitutionAdapterC"),
            rights(&[AuthorityRight::InvokeIdempotent]),
            OwnerGeneration::new(1),
            1,
        )),
        OperationAbiDiagnosticCode::AdapterInstanceRetired
    );
    let idempotent = abi(
        OperationKind::ValueAction,
        4,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    assert_eq!(
        refusal(retired.dispatch(&idempotent)),
        OperationAbiDiagnosticCode::AdapterInstanceRetired
    );
    assert!(declared.dispatch(&idempotent).is_ok());

    // A deployment that binds that implementation again after the retirement advances
    // the binding sequence, so the reinstated binding carries a distinct identity even
    // though every other identity input is equal. A distinct sequence alone decides a
    // distinct identity, and the sequence is never compared by the model.
    let reinstated = adapter(
        "SubstitutionAdapterA",
        &[AuthorityRight::Observe, AuthorityRight::InvokeIdempotent],
        0,
        1,
    );
    assert_eq!(reinstated.binding_sequence(), 1);
    assert!(!reinstated.is_poisoned() && !reinstated.is_retired());
    assert_ne!(reinstated.as_str(), retired.as_str());
    assert_ne!(reinstated.as_str(), declared.as_str());
    assert_ne!(
        reinstated.as_str(),
        adapter(
            "SubstitutionAdapterA",
            &[AuthorityRight::Observe, AuthorityRight::InvokeIdempotent],
            0,
            2,
        )
        .as_str()
    );
    assert!(reinstated.dispatch(&idempotent).is_ok());
}

#[test]
fn a_fenced_generation_or_an_exhausted_observation_budget_refuses_further_observation() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::Idempotent,
        ReceiverOwnership::RetainedByCaller,
    );

    // A fenced generation is poisoned and preserves the landed fencing category.
    let mut fenced = resource(&current, owner, 1);
    let fenced_settlement = fenced.fence(FenceCategory::Revocation);
    assert_eq!(fenced_settlement.state(), ResourceState::Poisoned);
    assert_eq!(fenced.fenced(), Some(FenceCategory::Revocation));
    assert_eq!(fenced.state(), ResourceState::Poisoned);
    assert_eq!(
        refusal(fenced.observe(ProgressObservation::PartialAdvance)),
        OperationAbiDiagnosticCode::FencedResource
    );
    assert_eq!(
        refusal(fenced.settle_failure(FailureClass::ResourceFailure)),
        OperationAbiDiagnosticCode::PoisonedResourceReuse
    );

    // A fenced generation still records its observed outcome, and stays poisoned.
    let observed = settlement(
        &current,
        owner,
        ExternalOutcome::Accepted,
        ProgressObservation::CommittedProgress,
        10,
    );
    fenced
        .settle(&observed)
        .unwrap_or_else(|_| unreachable!("a fenced generation records its observed outcome"));
    assert_eq!(settled(&fenced), Some(observed.canonical_text()));
    assert_eq!(fenced.state(), ResourceState::Poisoned);

    let mut expired = resource(&current, owner, 1);
    expired.fence(FenceCategory::Expiry);
    assert_eq!(expired.fenced(), Some(FenceCategory::Expiry));
    assert_ne!(expired.fenced(), fenced.fenced());

    // The declared observation allowance bounds how far an adapter may observe, and the
    // charge is consumed from that Section 20 allowance alone: a Section 15 disclosure
    // budget is charged per accepted release and is never charged by an observation.
    let release_budget = DisclosureBudget::new(40, charge(10));
    let mut budgeted = resource(&current, owner, 3);
    assert_eq!(budgeted.observation_allowance().remaining(), 8);
    assert_eq!(budgeted.observation_allowance().charge().value(), 3);
    budgeted
        .observe(ProgressObservation::PartialAdvance)
        .unwrap_or_else(|_| unreachable!("the first observation is within the allowance"));
    budgeted
        .observe(ProgressObservation::PartialAdvance)
        .unwrap_or_else(|_| unreachable!("the second observation is within the allowance"));
    assert_eq!(budgeted.observation_allowance().accepted(), 2);
    assert_eq!(budgeted.observation_allowance().remaining(), 2);
    assert!(budgeted.observation_allowance().is_exhausted());
    assert_eq!(
        refusal(budgeted.observe(ProgressObservation::PartialAdvance)),
        OperationAbiDiagnosticCode::ObservationBudgetExhausted
    );
    assert_eq!(budgeted.observation_allowance().accepted(), 2);
    assert_eq!(budgeted.observation_allowance().remaining(), 2);
    assert_eq!(release_budget.accepted(), 0);
    assert_eq!(release_budget.remaining(), 40);
}

#[test]
fn dispatch_is_admitted_only_after_admission_and_only_with_its_deduplication_proof() {
    let owner = OwnerGeneration::initial();
    let current = abi(
        OperationKind::ValueAction,
        1,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );

    // Dispatch before the admission commit point is refused, so a crash before
    // admission can never carry an effect.
    assert_eq!(
        refusal(admit_dispatch(
            &current,
            DurableOperationCut::Declared,
            OperationCancellation::NotRequested,
            None,
            owner,
        )),
        OperationAbiDiagnosticCode::DispatchBeforeAdmission
    );
    // The certainty is derived from the presented cut and cancellation rather than
    // supplied, so every at-or-after-admission cut is may-have-begun and is admitted
    // only through the deduplication proof of its exact operation and generation.
    for cancellation in OperationCancellation::ALL {
        assert_eq!(
            refusal(admit_dispatch(
                &current,
                DurableOperationCut::Admitted,
                cancellation,
                None,
                owner,
            )),
            OperationAbiDiagnosticCode::AmbiguousEffectWithoutDeduplication
        );
    }
    assert_eq!(
        classify_effect(
            DurableOperationCut::Admitted,
            OperationCancellation::NotRequested
        ),
        EffectCertainty::AmbiguouslyBegun
    );
    assert_eq!(
        classify_effect(
            DurableOperationCut::Admitted,
            OperationCancellation::Requested
        ),
        EffectCertainty::AmbiguouslyBegun
    );

    // An ambiguous effect without its own record is never dispatched.
    assert_eq!(
        refusal(admit_dispatch(
            &current,
            DurableOperationCut::Dispatched,
            OperationCancellation::NotRequested,
            None,
            owner,
        )),
        OperationAbiDiagnosticCode::AmbiguousEffectWithoutDeduplication
    );
    let record = DedupRecord::authoritative(
        settlement(
            &current,
            owner,
            ExternalOutcome::Rejected,
            ProgressObservation::NotStarted,
            5,
        ),
        bounds(1, 100),
    );
    assert_eq!(
        admit_dispatch(
            &current,
            DurableOperationCut::Dispatched,
            OperationCancellation::Requested,
            Some(&record),
            owner,
        )
        .unwrap_or_else(|_| unreachable!("the record admits a deduplicated dispatch")),
        DispatchAdmission::Deduplicated
    );

    // A record of another generation is no proof here.
    let other = abi(
        OperationKind::ValueAction,
        2,
        RecoveryClass::NonIdempotent,
        ReceiverOwnership::RetainedByCaller,
    );
    let foreign = DedupRecord::authoritative(
        settlement(
            &other,
            owner,
            ExternalOutcome::Accepted,
            ProgressObservation::CommittedProgress,
            5,
        ),
        bounds(1, 100),
    );
    assert_eq!(
        refusal(admit_dispatch(
            &current,
            DurableOperationCut::Dispatched,
            OperationCancellation::NotRequested,
            Some(&foreign),
            owner,
        )),
        OperationAbiDiagnosticCode::AmbiguousEffectWithoutDeduplication
    );
}

#[test]
fn the_diagnostic_registry_is_closed_sorted_and_anchored_to_every_clause() {
    let codes = OperationAbiDiagnosticCode::ALL;
    assert_eq!(codes.len(), 27);
    assert_eq!(OPERATION_ABI_CLAUSES.len(), 12);
    for pair in codes.windows(2) {
        assert!(pair[0].as_str() < pair[1].as_str());
    }
    let mut spellings = codes.map(OperationAbiDiagnosticCode::as_str).to_vec();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(spellings.len(), codes.len());
    for code in codes {
        assert_eq!(code.wire_name(), code.as_str());
        assert!(!code.meaning().is_empty());
        assert!(code.as_str().starts_with("operation-abi-"));
        assert!(OPERATION_ABI_CLAUSES.contains(&code.requirement()));
    }
    // Every clause owns at least one diagnostic.
    for clause in OPERATION_ABI_CLAUSES {
        assert!(codes.iter().any(|code| code.requirement() == clause));
    }

    // A refusal renders its own code first and names the clause that owns it.
    let live = abi(
        OperationKind::LiveResource,
        1,
        RecoveryClass::ReadOnly,
        ReceiverOwnership::RetainedByCaller,
    );
    let error = refusal_error(live.durable_value());
    assert_eq!(
        error.code(),
        OperationAbiDiagnosticCode::DurableValueForLiveResource
    );
    assert_eq!(error.requirement(), error.code().requirement());
    assert_eq!(
        error.requirement(),
        "GNT-20.0-value-actions-and-live-resource-operations"
    );
    assert!(error.to_string().starts_with(error.code().as_str()));
    assert!(error.to_string().contains("live resource"));

    // A unit refusal names its own code and clause as well.
    let unbounded = refusal_error(DedupRetentionBounds::new(0, 0));
    assert_eq!(
        unbounded.code(),
        OperationAbiDiagnosticCode::UnboundedRetention
    );
    assert_eq!(
        unbounded.requirement(),
        "GNT-20.9-deduplication-retention-and-compaction"
    );
    assert!(unbounded.to_string().starts_with(unbounded.code().as_str()));
}

#[test]
fn no_resource_identity_loan_settlement_or_live_handle_is_serializable_or_text_convertible() {
    // A resource generation, a sealed loan, a durable settlement, and a live handle are
    // opaque model values: they have no deserializer, no conversion from text, and no
    // default, so no serialized form, host path, environment value, clock reading, or
    // adapter field can become one of them.
    assert_not_impl_any!(
        ResourceGenerationId: serde::Serialize,
        serde::Deserialize<'static>,
        From<&'static str>,
        From<String>,
        Default
    );
    assert_not_impl_any!(
        LoanId: serde::Serialize,
        serde::Deserialize<'static>,
        From<&'static str>,
        From<String>,
        Default
    );
    assert_not_impl_any!(
        OperationSettlement: serde::Serialize,
        serde::Deserialize<'static>,
        From<String>,
        Default
    );
    assert_not_impl_any!(
        LiveResource: serde::Serialize,
        serde::Deserialize<'static>,
        From<OperationAbi>,
        From<ResourceGenerationId>,
        Default
    );
    assert_not_impl_any!(
        DedupRecord: serde::Serialize,
        serde::Deserialize<'static>,
        From<OperationSettlement>,
        Default
    );
    assert_not_impl_any!(OperationAbi: serde::Serialize, serde::Deserialize<'static>);
    assert_not_impl_any!(AdapterInstance: serde::Serialize, serde::Deserialize<'static>);

    // The three opaque identities are distinct even though none of them is text.
    let site = site_at(&[1, 2]);
    assert_ne!(
        resource_generation(&site, 1).as_str(),
        sealed_loan(&site, 1).as_str()
    );
    assert_ne!(
        sealed_loan(&site, 1).as_str(),
        adapter("IdentityAdapter", &[AuthorityRight::Observe], 0, 0).as_str()
    );
}
