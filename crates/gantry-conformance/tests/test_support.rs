//! Public-facade conformance for the `std.test` package surface (`GNT-GP-TEST-001`).
//!
//! The surface declares the target-qualified test package, its closed test-kind vocabulary, and
//! the deterministic substitutions a test run may consume. These rows require the package
//! identity, the closed ordered vocabularies, the no-ambient-authority rule, the one non-shipping
//! test target kind that qualifies every kind, the ceiling bound a test requirement obeys, and the
//! declared testing-support harness contract with its strict substitution declaration, plus the
//! declared execution rules, the canonical discovery order a run enumerates, and the declared run
//! plan that binds kinds and substitutions to those rules. Every declared identity is checked
//! against the module's executable kebab-case identity rule, and the published surface catalog is
//! pinned field by field against the live model.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

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

#[test]
fn std_test_surface_catalog_matches_the_live_surface() {
    let document =
        fs::read_to_string(workspace_root().join("protocol/catalogs/std-test-surface-v1.json"))
            .unwrap_or_else(|error| panic!("the std.test surface catalog reads: {error}"));
    let catalog: Value = serde_json::from_str(&document)
        .unwrap_or_else(|error| panic!("the std.test surface catalog is JSON: {error}"));
    assert_eq!(catalog["format"], Value::from("gantry-std-test-surface-v1"));
    assert_eq!(catalog["contract"]["major"], Value::from(1));
    assert_eq!(catalog["contract"]["minor"], Value::from(0));

    let package = &catalog["package"];
    assert_eq!(package["name"], Value::from(STD_TEST_PACKAGE));
    assert_eq!(package["class"], Value::from("package"));
    assert_eq!(package["tier"], Value::from("stable"));
    assert_eq!(
        package["family"],
        Value::from(std_test_family().wire_name())
    );
    assert_eq!(
        package["target_kind"],
        Value::from(STD_TEST_TARGET_KIND.wire_name())
    );
    assert_eq!(
        package["shipping_authority"],
        Value::from(test_target_is_shipping_authority())
    );
    assert_eq!(
        package["admitted_modes"],
        Value::from(vec![STD_TEST_ADMITTED_MODE.wire_name()])
    );
    assert_eq!(
        package["non_claims"],
        Value::from(STD_TEST_NON_CLAIMS.to_vec())
    );

    let kinds = catalog["kinds"]
        .as_array()
        .unwrap_or_else(|| panic!("the catalog publishes kinds as an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("a catalog kind is a string"))
        })
        .collect::<Vec<_>>();
    assert_eq!(kinds, TestKind::ALL.map(TestKind::wire_name).to_vec());

    let substitutions = catalog["substitutions"]
        .as_array()
        .unwrap_or_else(|| panic!("the catalog publishes substitutions as an array"));
    assert_eq!(substitutions.len(), TestSubstitution::ALL.len());
    for (entry, substitution) in substitutions.iter().zip(TestSubstitution::ALL) {
        assert_eq!(entry["wire_name"], Value::from(substitution.wire_name()));
        assert_eq!(entry["meaning"], Value::from(substitution.meaning()));
    }

    let harness = catalog["harness_capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("the catalog publishes harness capabilities as an array"));
    assert_eq!(harness.len(), TestHarnessCapability::ALL.len());
    for (entry, capability) in harness.iter().zip(TestHarnessCapability::ALL) {
        assert_eq!(entry["wire_name"], Value::from(capability.wire_name()));
        assert_eq!(entry["requirement"], Value::from(capability.requirement()));
    }

    let rules = catalog["execution_rules"]
        .as_array()
        .unwrap_or_else(|| panic!("the catalog publishes execution rules as an array"));
    assert_eq!(rules.len(), TestExecutionRule::ALL.len());
    for (entry, rule) in rules.iter().zip(TestExecutionRule::ALL) {
        assert_eq!(entry["wire_name"], Value::from(rule.wire_name()));
        assert_eq!(entry["requirement"], Value::from(rule.requirement()));
    }
}

#[test]
fn testing_support_note_is_current() {
    let note = fs::read_to_string(workspace_root().join("docs/testing-support.md"))
        .unwrap_or_else(|error| panic!("docs/testing-support.md: {error}"));
    for required in [
        "`std.test`",
        "`GNT-GP-TEST-001`",
        "`protocol/catalogs/std-test-surface-v1.json`",
        "`may_acquire_ambient_authority`",
        "`declare_test_run`",
        "`canonical_wire_name`",
    ] {
        assert!(note.contains(required), "the note names {required}");
    }
    assert_eq!(
        sorted_members(section_members(&note, "## Test kinds")),
        sorted_members(
            TestKind::ALL
                .map(|kind| kind.wire_name().to_owned())
                .to_vec()
        )
    );
    assert_eq!(
        sorted_members(section_members(&note, "## Declared substitutions")),
        sorted_members(
            TestSubstitution::ALL
                .map(|substitution| substitution.wire_name().to_owned())
                .to_vec()
        )
    );
    assert_eq!(
        sorted_members(section_members(&note, "## Harness capabilities")),
        sorted_members(
            TestHarnessCapability::ALL
                .map(|capability| capability.wire_name().to_owned())
                .to_vec()
        )
    );
    assert_eq!(
        sorted_members(section_members(&note, "## Execution rules")),
        sorted_members(
            TestExecutionRule::ALL
                .map(|rule| rule.wire_name().to_owned())
                .to_vec()
        )
    );
    assert_eq!(
        sorted_members(section_members(&note, "## Non-claims")),
        sorted_members(
            STD_TEST_NON_CLAIMS
                .iter()
                .map(|non_claim| (*non_claim).to_owned())
                .collect()
        )
    );
}

/// Returns the backticked members one note section declares as its bullets, with multiplicity.
///
/// The note is compared section by section, so a vocabulary member removed from the model cannot
/// survive as a stale bullet in the note: every compared section must list exactly the live
/// members, no more and no fewer. One entry is collected per bullet, so a duplicated member also
/// fails rather than being collapsed by set collection. Only bullet members are collected, so a
/// prose sentence inside a section may still name an API without being mistaken for a member.
fn section_members(note: &str, heading: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut in_section = false;
    for line in note.lines() {
        if line.starts_with("## ") {
            in_section = line.trim_end() == heading;
            continue;
        }
        if !in_section || !line.starts_with("- ") {
            continue;
        }
        for (index, part) in line.split('`').enumerate() {
            if index % 2 == 1 && !part.is_empty() {
                members.push(part.to_owned());
            }
        }
    }
    members
}

/// Returns the collected members in canonical order, preserving any duplication.
fn sorted_members(mut members: Vec<String>) -> Vec<String> {
    members.sort_unstable();
    members
}

/// Returns the workspace root that holds the published protocol catalog.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}
