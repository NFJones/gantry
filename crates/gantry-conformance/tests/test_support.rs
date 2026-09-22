//! Public-facade conformance for the `std.test` package surface (`GNT-GP-TEST-001`).
//!
//! The surface declares the target-qualified test package, its closed test-kind vocabulary, and
//! the deterministic substitutions a test run may consume. These rows require the package
//! identity, the closed ordered vocabularies, the no-ambient-authority rule, the one non-shipping
//! test target kind that qualifies every kind, and the ceiling bound a test requirement obeys.

use std::collections::BTreeSet;

use gantry::ir::{
    DeclaredCeiling, ModeAdmission, NameClass, PackageError, PackageFamily, RequirementDemand,
    STD_TEST_ADMITTED_MODE, STD_TEST_CLASS, STD_TEST_NON_CLAIMS, STD_TEST_PACKAGE,
    STD_TEST_TARGET_KIND, STD_TEST_TIER, SemanticMode, StabilityTier, TargetKind, TestKind,
    TestSubstitution, ambient_authority_is_never_acquired, bound_test_requirement, std_test_family,
    test_target_is_shipping_authority,
};

#[test]
fn std_test_package_identity_is_declared() {
    assert_eq!(STD_TEST_PACKAGE, "std.test");
    assert_eq!(STD_TEST_CLASS, NameClass::Package);
    assert_eq!(STD_TEST_TIER, StabilityTier::Stable);
    assert_eq!(std_test_family(), PackageFamily::Test);
    assert_eq!(PackageFamily::Test.wire_name(), "test");
    assert_eq!(PackageFamily::Test.package_name(), STD_TEST_PACKAGE);
    assert!(
        !PackageFamily::Test.is_pure(),
        "the test package is target-qualified, never part of the pure closure"
    );
}

#[test]
fn test_kinds_are_closed_and_canonically_ordered() {
    assert_eq!(TestKind::ALL.len(), 9);
    let mut prior: Option<&str> = None;
    let mut spellings = BTreeSet::new();
    for kind in TestKind::ALL {
        let spelling = kind.wire_name();
        if let Some(previous) = prior {
            assert!(previous < spelling, "{previous} then {spelling}");
        }
        prior = Some(spelling);
        assert!(spellings.insert(spelling), "one spelling per kind");
        assert_eq!(TestKind::from_wire_name(spelling), Some(kind));
    }
    assert_eq!(
        spellings.iter().copied().collect::<Vec<_>>(),
        vec![
            "benchmark",
            "compile-fail",
            "durable-recovery",
            "example",
            "integration",
            "property",
            "replay",
            "snapshot",
            "unit",
        ]
    );
    assert!(TestKind::from_wire_name("fuzz").is_none());
    assert!(TestKind::from_wire_name("not-a-kind").is_none());
}

#[test]
fn substitutions_are_closed_explicit_and_never_ambient() {
    assert_eq!(TestSubstitution::ALL.len(), 6);
    let mut prior: Option<&str> = None;
    for substitution in TestSubstitution::ALL {
        let spelling = substitution.wire_name();
        if let Some(previous) = prior {
            assert!(previous < spelling, "{previous} then {spelling}");
        }
        prior = Some(spelling);
        assert!(!substitution.meaning().is_empty());
        assert_eq!(
            TestSubstitution::from_wire_name(spelling),
            Some(substitution)
        );
    }
    assert!(TestSubstitution::from_wire_name("network").is_none());
    assert!(
        !ambient_authority_is_never_acquired(),
        "a test run never acquires ambient authority"
    );
    assert_eq!(
        STD_TEST_NON_CLAIMS.to_vec(),
        vec![
            "ambient-authority",
            "oracle-provider",
            "test-only-semantics",
            "wildcard-prelude",
        ]
    );
    let mut declared = STD_TEST_NON_CLAIMS.to_vec();
    declared.sort_unstable();
    assert_eq!(declared, STD_TEST_NON_CLAIMS.to_vec());
}

#[test]
fn test_kinds_are_qualified_by_the_non_shipping_test_target() {
    assert_eq!(STD_TEST_TARGET_KIND, TargetKind::Test);
    assert_eq!(STD_TEST_TARGET_KIND.wire_name(), "test");
    assert_eq!(STD_TEST_ADMITTED_MODE, SemanticMode::Portable);
    assert!(
        !test_target_is_shipping_authority(),
        "a test target is never shipping authority"
    );
    assert!(!TargetKind::Test.is_shipping());
    assert!(TargetKind::Library.is_shipping());
    assert!(TargetKind::Binary.is_shipping());
    assert!(TargetKind::ALL.contains(&TargetKind::Test));

    let admitted = ModeAdmission::admitted_modes(TargetKind::Test);
    assert_eq!(admitted, [SemanticMode::Portable].as_slice());
    assert!(ModeAdmission::admits(
        TargetKind::Test,
        SemanticMode::Portable
    ));
    assert!(!ModeAdmission::admits(
        TargetKind::Test,
        SemanticMode::Application
    ));
    assert!(!ModeAdmission::admits(
        TargetKind::Test,
        SemanticMode::Durable
    ));

    for kind in TestKind::ALL {
        assert_eq!(
            kind.target_kind(),
            STD_TEST_TARGET_KIND,
            "{}",
            kind.wire_name()
        );
        assert_eq!(kind.admitted_modes(), admitted, "{}", kind.wire_name());
    }
}

#[test]
#[allow(clippy::result_large_err)]
fn test_requirements_are_bounded_by_the_exercised_shipping_ceiling() -> Result<(), PackageError> {
    let declared = DeclaredCeiling::new("network", 2)?;
    let within = RequirementDemand::new("network", 2)?;
    assert!(bound_test_requirement(&declared, &within).is_ok());
    let below = RequirementDemand::new("network", 0)?;
    assert!(bound_test_requirement(&declared, &below).is_ok());
    let above = RequirementDemand::new("network", 3)?;
    assert!(matches!(
        bound_test_requirement(&declared, &above),
        Err(PackageError::RequirementExceedsCeiling { .. })
    ));
    let foreign = RequirementDemand::new("filesystem", 0)?;
    assert!(matches!(
        bound_test_requirement(&declared, &foreign),
        Err(PackageError::RequirementExceedsCeiling { .. })
    ));
    Ok(())
}
