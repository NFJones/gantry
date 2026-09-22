//! Public-facade conformance for the `std.test` package surface (`GNT-GP-TEST-001`).
//!
//! The surface declares the target-qualified test package, its closed test-kind vocabulary, and
//! the deterministic substitutions a test run may consume. These rows require the package
//! identity, the closed ordered vocabularies, the no-ambient-authority rule, the one non-shipping
//! test target kind that qualifies every kind, the ceiling bound a test requirement obeys, and the
//! declared testing-support harness contract with its strict substitution declaration, plus the
//! declared execution rules, the canonical discovery order a run enumerates, and the declared run
//! plan that binds kinds and substitutions to those rules. Every declared identity is checked
//! against the module's executable kebab-case identity rule.

use std::collections::BTreeSet;

use gantry::ir::{
    DeclaredCeiling, ModeAdmission, NameClass, PackageError, PackageFamily, RequirementDemand,
    STD_TEST_ADMITTED_MODE, STD_TEST_CLASS, STD_TEST_NON_CLAIMS, STD_TEST_PACKAGE,
    STD_TEST_TARGET_KIND, STD_TEST_TIER, SemanticMode, StabilityTier, TargetKind,
    TestDiscoveryRefusal, TestExecutionRule, TestHarnessCapability, TestKind, TestRunPlan,
    TestRunRefusal, TestSubstitution, TestSubstitutionRefusal, bound_test_requirement,
    canonical_wire_name, declare_test_discovery, declare_test_run, declare_test_substitutions,
    may_acquire_ambient_authority, std_test_family, test_target_is_shipping_authority,
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
        !may_acquire_ambient_authority(),
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

#[test]
fn harness_capabilities_are_closed_in_requirement_order() {
    assert_eq!(TestHarnessCapability::ALL.len(), 7);
    let mut spellings = BTreeSet::new();
    for capability in TestHarnessCapability::ALL {
        let spelling = capability.wire_name();
        assert!(spellings.insert(spelling), "one spelling per capability");
        assert_eq!(
            TestHarnessCapability::from_wire_name(spelling),
            Some(capability)
        );
    }
    assert_eq!(
        TestHarnessCapability::ALL
            .map(TestHarnessCapability::wire_name)
            .to_vec(),
        vec![
            "deterministic-test-ordering-and-isolation",
            "assertion-and-comparison-diagnostics",
            "fixtures-and-temporary-capability-roots",
            "fake-clocks-random-sources-and-host-capabilities",
            "expected-failure-and-timeout-support",
            "property-test-shrinking-contracts",
            "durable-replay-and-recovery-test-harnesses",
        ]
    );
    assert_eq!(
        TestHarnessCapability::ALL
            .map(TestHarnessCapability::requirement)
            .to_vec(),
        vec![
            "deterministic test ordering and isolation",
            "assertion and comparison diagnostics",
            "fixtures and temporary capability roots",
            "fake clocks, random sources, and host capabilities",
            "expected-failure and timeout support",
            "property-test shrinking contracts",
            "durable replay and recovery test harnesses",
        ]
    );
    assert!(TestHarnessCapability::from_wire_name("ambient-host-network").is_none());
}

#[test]
fn declared_substitutions_are_canonical_and_strictly_refused() -> Result<(), TestSubstitutionRefusal>
{
    assert_eq!(declare_test_substitutions(&[])?, Vec::new());
    assert_eq!(
        declare_test_substitutions(&["prng", "clock", "capability"])?,
        vec![
            TestSubstitution::Capability,
            TestSubstitution::Clock,
            TestSubstitution::Prng
        ]
    );
    assert_eq!(
        declare_test_substitutions(&[
            "storage-fault",
            "scheduler",
            "provider",
            "prng",
            "clock",
            "capability",
        ])?,
        TestSubstitution::ALL.to_vec()
    );
    assert_eq!(
        declare_test_substitutions(&["clock", "prng"])?,
        declare_test_substitutions(&["prng", "clock"])?
    );
    assert!(matches!(
        declare_test_substitutions(&["network"]),
        Err(TestSubstitutionRefusal::Unknown)
    ));
    assert!(matches!(
        declare_test_substitutions(&["clock", "nope"]),
        Err(TestSubstitutionRefusal::Unknown)
    ));
    assert!(matches!(
        declare_test_substitutions(&["clock", "clock"]),
        Err(TestSubstitutionRefusal::Duplicate)
    ));
    Ok(())
}

#[test]
fn execution_rules_are_closed_in_plan_order() {
    assert_eq!(TestExecutionRule::ALL.len(), 9);
    let mut spellings = BTreeSet::new();
    for rule in TestExecutionRule::ALL {
        let spelling = rule.wire_name();
        assert!(spellings.insert(spelling), "one spelling per rule");
        assert_eq!(TestExecutionRule::from_wire_name(spelling), Some(rule));
    }
    assert_eq!(
        TestExecutionRule::ALL
            .map(TestExecutionRule::wire_name)
            .to_vec(),
        vec![
            "deterministic-discovery-and-ordering",
            "per-test-isolation",
            "bounded-parallelism",
            "timeouts",
            "fixtures",
            "temporary-capability-roots",
            "structured-assertions",
            "shrinking",
            "replay",
        ]
    );
    assert_eq!(
        TestExecutionRule::ALL
            .map(TestExecutionRule::requirement)
            .to_vec(),
        vec![
            "deterministic discovery and ordering",
            "per-test isolation",
            "bounded parallelism",
            "timeouts",
            "fixtures",
            "temporary capability roots",
            "structured assertions",
            "shrinking",
            "replay",
        ]
    );
    assert!(TestExecutionRule::from_wire_name("ambient-parallelism").is_none());
}

#[test]
fn declared_discovery_is_canonical_and_strictly_refused() -> Result<(), TestDiscoveryRefusal> {
    assert_eq!(declare_test_discovery(&[])?, Vec::<&str>::new());
    assert_eq!(
        declare_test_discovery(&["crate-b", "crate-a"])?,
        vec!["crate-a", "crate-b"]
    );
    assert_eq!(
        declare_test_discovery(&["zeta", "alpha", "mid"])?,
        declare_test_discovery(&["mid", "zeta", "alpha"])?
    );
    assert!(matches!(
        declare_test_discovery(&[""]),
        Err(TestDiscoveryRefusal::Empty)
    ));
    assert!(matches!(
        declare_test_discovery(&["alpha", "alpha"]),
        Err(TestDiscoveryRefusal::Duplicate)
    ));
    Ok(())
}

#[test]
fn declared_run_plans_are_canonical_and_strictly_refused() -> Result<(), TestRunRefusal> {
    let plan = declare_test_run(&["unit", "property"], &["prng", "clock"])?;
    assert_eq!(
        plan.kinds(),
        [TestKind::Property, TestKind::Unit].as_slice()
    );
    assert_eq!(
        plan.substitutions(),
        [TestSubstitution::Clock, TestSubstitution::Prng].as_slice()
    );
    assert_eq!(plan.execution_rules(), TestExecutionRule::ALL.as_slice());

    let permuted = declare_test_run(&["property", "unit"], &["clock", "prng"])?;
    assert_eq!(plan.kinds(), permuted.kinds());
    assert_eq!(plan.substitutions(), permuted.substitutions());
    assert_eq!(plan, permuted);

    let empty = declare_test_run(&[], &[])?;
    assert!(empty.kinds().is_empty());
    assert!(empty.substitutions().is_empty());
    assert_eq!(empty.execution_rules(), TestExecutionRule::ALL.as_slice());

    assert!(matches!(
        declare_test_run(&["fuzz"], &[]),
        Err(TestRunRefusal::UnknownKind)
    ));
    assert!(matches!(
        declare_test_run(&["unit", "unit"], &[]),
        Err(TestRunRefusal::DuplicateKind)
    ));
    assert!(matches!(
        declare_test_run(&[], &["network"]),
        Err(TestRunRefusal::UnknownSubstitution)
    ));
    assert!(matches!(
        declare_test_run(&[], &["clock", "clock"]),
        Err(TestRunRefusal::DuplicateSubstitution)
    ));
    let _: fn(&[&str], &[&str]) -> Result<TestRunPlan, TestRunRefusal> = declare_test_run;
    Ok(())
}

#[test]
fn declared_identities_are_the_kebab_case_of_their_requirement() {
    assert_eq!(canonical_wire_name(""), "");
    assert_eq!(
        canonical_wire_name("expected-failure and timeout support"),
        "expected-failure-and-timeout-support"
    );
    assert_eq!(
        canonical_wire_name("fake clocks, random sources, and host capabilities"),
        "fake-clocks-random-sources-and-host-capabilities"
    );
    assert_eq!(canonical_wire_name("  spaced\tname  "), "spaced-name");

    for capability in TestHarnessCapability::ALL {
        assert_eq!(
            capability.wire_name(),
            canonical_wire_name(capability.requirement()),
            "{}",
            capability.wire_name()
        );
    }
    for rule in TestExecutionRule::ALL {
        assert_eq!(
            rule.wire_name(),
            canonical_wire_name(rule.requirement()),
            "{}",
            rule.wire_name()
        );
    }
}
