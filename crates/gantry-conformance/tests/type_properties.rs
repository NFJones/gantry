//! Public independent-property laws, separate from source-type admission.

use gantry::ir::{
    IndependentTypeProperties, OwnershipClass, ReceiverMode, RecoveryProjectionClass,
    SourceProtectionClass, TransferEligibility, TypeDescriptor, ValueResourceClass,
};

/// Receiver modes distinguish V1 local copies from future caller-place access.
#[test]
fn receiver_modes_preserve_v1_copy_isolation_and_name_place_access() {
    assert_eq!(
        ReceiverMode::from_v1_mutability(false),
        ReceiverMode::LocalCopy
    );
    assert_eq!(
        ReceiverMode::from_v1_mutability(true),
        ReceiverMode::MutableLocalCopy
    );
    for mode in [
        ReceiverMode::LocalCopy,
        ReceiverMode::MutableLocalCopy,
        ReceiverMode::Owned,
        ReceiverMode::SharedPlace,
    ] {
        assert!(!mode.mutates_caller_place(), "{}", mode.wire_name());
    }
    assert!(ReceiverMode::ExclusivePlace.mutates_caller_place());
    assert_eq!(ReceiverMode::ExclusivePlace.wire_name(), "exclusive-place");
    assert!(ReceiverMode::LocalCopy.copies_receiver());
    assert!(ReceiverMode::MutableLocalCopy.copies_receiver());
    assert!(ReceiverMode::Owned.consumes_receiver());
    assert!(ReceiverMode::SharedPlace.borrows_shared_place());
    assert!(ReceiverMode::ExclusivePlace.borrows_exclusive_place());
    assert!(!ReceiverMode::LocalCopy.requires_caller_place());
    assert!(!ReceiverMode::MutableLocalCopy.requires_caller_place());
    assert!(!ReceiverMode::Owned.requires_caller_place());
    assert!(ReceiverMode::SharedPlace.requires_caller_place());
    assert!(ReceiverMode::ExclusivePlace.requires_caller_place());
}

/// Aggregates retain the strongest member obligation regardless of grouping or order.
#[test]
fn ownership_classes_form_a_conservative_aggregate_algebra() {
    use OwnershipClass::{AffineDroppable, Copyable, MustConsume};

    let classes = [Copyable, AffineDroppable, MustConsume];
    let expected = [
        [Copyable, AffineDroppable, MustConsume],
        [AffineDroppable, AffineDroppable, MustConsume],
        [MustConsume, MustConsume, MustConsume],
    ];
    for (i, a) in classes.into_iter().enumerate() {
        assert_eq!(a.combine(a), a);
        assert_eq!(Copyable.combine(a), a);
        for (j, b) in classes.into_iter().enumerate() {
            assert_eq!(a.combine(b), expected[i][j]);
            assert_eq!(a.combine(b), b.combine(a));
            for c in classes {
                assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
            }
        }
    }
    assert_eq!(
        [].into_iter().fold(Copyable, OwnershipClass::combine),
        Copyable
    );
}

/// Every independent axis uses its permissive class as identity and its
/// restrictive class as an absorbing aggregate result.
#[test]
fn independent_property_axes_form_conservative_aggregate_algebras() {
    fn laws<T: Copy + std::fmt::Debug + Eq>(
        identity: T,
        restrictive: T,
        combine: impl Fn(T, T) -> T,
    ) {
        for a in [identity, restrictive] {
            assert_eq!(combine(identity, a), a);
            assert_eq!(combine(a, a), a);
            for b in [identity, restrictive] {
                assert_eq!(combine(a, b), combine(b, a));
                for c in [identity, restrictive] {
                    assert_eq!(combine(combine(a, b), c), combine(a, combine(b, c)));
                }
            }
        }
        assert_eq!(combine(restrictive, identity), restrictive);
    }

    laws(
        TransferEligibility::IsolatedTaskCapture,
        TransferEligibility::Ineligible,
        TransferEligibility::combine,
    );
    laws(
        ValueResourceClass::NonLiveResource,
        ValueResourceClass::LiveResource,
        ValueResourceClass::combine,
    );
    laws(
        SourceProtectionClass::Unsealed,
        SourceProtectionClass::Sealed,
        SourceProtectionClass::combine,
    );
    laws(
        RecoveryProjectionClass::SealedValue,
        RecoveryProjectionClass::Unavailable,
        RecoveryProjectionClass::combine,
    );

    let empty = IndependentTypeProperties::empty_aggregate();
    assert_eq!(empty.combine(empty), empty);
    assert_eq!(empty.ownership_class(), OwnershipClass::Copyable);
    assert_eq!(
        empty.transfer_eligibility(),
        TransferEligibility::IsolatedTaskCapture
    );
    assert_eq!(empty.resource_class(), ValueResourceClass::NonLiveResource);
    assert_eq!(
        empty.source_protection_class(),
        SourceProtectionClass::Unsealed
    );
    assert_eq!(
        empty.recovery_projection_class(),
        RecoveryProjectionClass::SealedValue
    );
}

/// Sealed nonexternal primitives still preserve their existing v1 copy semantics.
#[test]
fn v1_primitive_ownership_does_not_depend_on_external_eligibility() {
    for ty in [
        TypeDescriptor::UNIT,
        TypeDescriptor::BOOL,
        TypeDescriptor::INT,
        TypeDescriptor::FLOAT,
        TypeDescriptor::STRING,
        TypeDescriptor::DECISION,
        TypeDescriptor::OPERATION_ERROR,
    ] {
        let properties = ty
            .primitive_properties()
            .unwrap_or_else(|| panic!("missing primitive properties for {ty:?}"));
        assert_eq!(properties.ownership_class(), OwnershipClass::Copyable);
        assert!(properties.is_copyable());
        assert_eq!(
            properties.transfer_eligibility(),
            TransferEligibility::IsolatedTaskCapture
        );
        assert_eq!(
            properties.resource_class(),
            ValueResourceClass::NonLiveResource
        );
        assert_eq!(
            properties.recovery_projection_class(),
            RecoveryProjectionClass::SealedValue
        );
    }
    let decision = TypeDescriptor::DECISION
        .primitive_properties()
        .unwrap_or_else(|| panic!("missing Decision properties"));
    assert!(!decision.is_external());
    assert_eq!(
        decision.source_protection_class(),
        SourceProtectionClass::Sealed
    );
    let string = TypeDescriptor::STRING
        .primitive_properties()
        .unwrap_or_else(|| panic!("missing String properties"));
    assert_eq!(
        string.source_protection_class(),
        SourceProtectionClass::Unsealed
    );
}
