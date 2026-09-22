//! Public-facade conformance for the `std.test` package surface (`GNT-GP-TEST-001`).
//!
//! The surface declares the target-qualified test package, its closed test-kind vocabulary, and
//! the deterministic substitutions a test run may consume. These rows require the package
//! identity, the closed ordered vocabularies, and the no-ambient-authority rule to hold.

use std::collections::BTreeSet;

use gantry::ir::{
    NameClass, PackageFamily, STD_TEST_CLASS, STD_TEST_NON_CLAIMS, STD_TEST_PACKAGE, STD_TEST_TIER,
    StabilityTier, TestKind, TestSubstitution, ambient_authority_is_never_acquired,
    std_test_family,
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
