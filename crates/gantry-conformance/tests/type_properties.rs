//! Public ownership classification laws, separate from source-type admission.

use gantry::ir::{OwnershipClass, TypeDescriptor};

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
    }
    assert!(
        !TypeDescriptor::DECISION
            .primitive_properties()
            .unwrap_or_else(|| panic!("missing Decision properties"))
            .is_external()
    );
}
