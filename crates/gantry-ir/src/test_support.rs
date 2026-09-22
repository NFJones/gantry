//! The `std.test` package surface of `GNT-GP-TEST-001`: the target-qualified logical test
//! package of the standard-library hierarchy, its closed test-kind vocabulary, and the
//! deterministic substitutions a test run may consume.
//!
//! The package is a capability package: every kind below consumes production package, artifact,
//! authority, runtime, and standard-library interfaces, and every substitution is declared
//! explicitly rather than acquired from ambient authority. Every kind is qualified by the one
//! non-shipping `test` target kind of `GNT-16.6-target-kinds`, and a test requirement is bounded
//! by the declared ceiling of the shipping target it exercises. The declared testing-support
//! contract is published as a closed harness vocabulary, the execution rules a run obeys are
//! declared the same way, the substitutions a run consumes are declared through a strict decoder,
//! and declared tests are enumerated in a canonical discovery order. The surface declares facts
//! only; the runtime harness that executes a test target is not part of this module.

// The ceiling bound returns the landed package diagnostic, which deliberately carries full
// identities so a rejected requirement reports the exact subject it disagreed with. Boxing those
// fields would hide identity behind an allocation at every construction and match site, so this
// module answers the size lint explicitly instead of weakening the diagnostic.
#![allow(clippy::result_large_err)]

use crate::SemanticMode;
use crate::package::{DeclaredCeiling, PackageError, RequirementDemand, TargetKind, check_ceiling};
use crate::stdlib::{NameClass, PackageFamily, StabilityTier};
use crate::target::ModeAdmission;

/// The canonical package name of the target-qualified test package.
pub const STD_TEST_PACKAGE: &str = "std.test";

/// The declared stability tier of the test package and every kind it publishes.
pub const STD_TEST_TIER: StabilityTier = StabilityTier::Stable;

/// The declared name classification of the test package.
pub const STD_TEST_CLASS: NameClass = NameClass::Package;

/// Returns the declared package family of the test package.
#[must_use]
pub const fn std_test_family() -> PackageFamily {
    PackageFamily::Test
}

/// The single target kind every kind of `std.test` is qualified by.
///
/// `GNT-16.6-target-kinds` closes the target-kind vocabulary at `library`, `binary`, `test`,
/// `example`, and `benchmark`: a test kind is a kind *within* the test package and never a
/// target kind of its own, so every declared test kind is qualified by exactly this kind.
pub const STD_TEST_TARGET_KIND: TargetKind = TargetKind::Test;

/// The single semantic mode the qualifying test target admits.
///
/// `GNT-17.10-target-selected-mode-admission` admits exactly one mode for one selected target
/// and target kind, and `GNT-16.6-target-kinds` makes a `test` target non-shipping and
/// bounded-authority, so only the portable mode of `GNT-3.1` is admitted here.
pub const STD_TEST_ADMITTED_MODE: SemanticMode = SemanticMode::Portable;

/// One declared test kind of `std.test`, in canonical wire-name order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestKind {
    /// A benchmark target.
    Benchmark,
    /// A compile-fail target.
    CompileFail,
    /// A durable-recovery target.
    DurableRecovery,
    /// An example target.
    Example,
    /// An integration target.
    Integration,
    /// A property target.
    Property,
    /// A replay target.
    Replay,
    /// A snapshot target.
    Snapshot,
    /// A unit target.
    Unit,
}

impl TestKind {
    /// The closed declared set, in canonical wire-name order.
    pub const ALL: [TestKind; 9] = [
        Self::Benchmark,
        Self::CompileFail,
        Self::DurableRecovery,
        Self::Example,
        Self::Integration,
        Self::Property,
        Self::Replay,
        Self::Snapshot,
        Self::Unit,
    ];

    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Benchmark => "benchmark",
            Self::CompileFail => "compile-fail",
            Self::DurableRecovery => "durable-recovery",
            Self::Example => "example",
            Self::Integration => "integration",
            Self::Property => "property",
            Self::Replay => "replay",
            Self::Snapshot => "snapshot",
            Self::Unit => "unit",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == name)
    }

    /// Returns the target kind this test kind is qualified by.
    ///
    /// Every kind is qualified by the one non-shipping `test` target kind, so a test kind never
    /// declares a second target identity of its own.
    #[must_use]
    pub const fn target_kind(self) -> TargetKind {
        STD_TEST_TARGET_KIND
    }

    /// Returns the modes the qualifying test target admits, in `GNT-3.1` order.
    #[must_use]
    pub fn admitted_modes(self) -> &'static [SemanticMode] {
        ModeAdmission::admitted_modes(self.target_kind())
    }

    /// Returns this kind's index in the canonical declaration order.
    #[must_use]
    pub fn canonical_index(self) -> usize {
        Self::ALL
            .into_iter()
            .position(|candidate| candidate == self)
            .unwrap_or(Self::ALL.len())
    }
}

/// One declared deterministic substitution of `std.test`, in canonical wire-name order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestSubstitution {
    /// A deterministic capability grant replaces ambient authority.
    Capability,
    /// A deterministic clock replaces the host clock.
    Clock,
    /// A deterministic provider or recorded transcript replaces a real provider.
    Provider,
    /// A deterministic pseudo-random source replaces host entropy.
    Prng,
    /// A controlled scheduler replaces host thread timing.
    Scheduler,
    /// A deterministic storage fault replaces host failure injection.
    StorageFault,
}

impl TestSubstitution {
    /// The closed declared set, in canonical wire-name order.
    pub const ALL: [TestSubstitution; 6] = [
        Self::Capability,
        Self::Clock,
        Self::Prng,
        Self::Provider,
        Self::Scheduler,
        Self::StorageFault,
    ];

    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Clock => "clock",
            Self::Provider => "provider",
            Self::Prng => "prng",
            Self::Scheduler => "scheduler",
            Self::StorageFault => "storage-fault",
        }
    }

    /// Returns the declared meaning of this substitution.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Capability => "A declared capability grant supplies the authority a test uses.",
            Self::Clock => "A deterministic clock supplies the time a test observes.",
            Self::Provider => {
                "A deterministic provider or recorded transcript supplies model results."
            }
            Self::Prng => "A deterministic pseudo-random source supplies generated values.",
            Self::Scheduler => "A controlled scheduler supplies interleaving and wake order.",
            Self::StorageFault => "A deterministic storage fault supplies failure injection.",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|substitution| substitution.wire_name() == name)
    }

    /// Returns this substitution's index in the canonical declaration order.
    #[must_use]
    pub fn canonical_index(self) -> usize {
        Self::ALL
            .into_iter()
            .position(|candidate| candidate == self)
            .unwrap_or(Self::ALL.len())
    }
}

/// The closed declared non-claims of `std.test`, in canonical wire-name order.
pub const STD_TEST_NON_CLAIMS: [&str; 4] = [
    "ambient-authority",
    "oracle-provider",
    "test-only-semantics",
    "wildcard-prelude",
];

/// Returns whether a test run of this package may acquire ambient authority.
///
/// Every kind and substitution above consumes explicitly declared authority only: no test kind
/// reads the ambient environment, the host clock, host entropy, a real provider, an ambient
/// scheduler, or a host failure facility, and no test kind changes language semantics. The
/// declared non-claim `ambient-authority` is exactly this answer, so the predicate is the
/// positive acquisition question and it answers `false`.
#[must_use]
pub const fn may_acquire_ambient_authority() -> bool {
    false
}

/// Returns whether `std.test` is shipping authority (`GNT-16.6-target-kinds`).
///
/// A test target is non-shipping: its items never appear in another target's public interface,
/// are never exported by a shipping target, and are never represented as shipping authority.
#[must_use]
pub const fn test_target_is_shipping_authority() -> bool {
    STD_TEST_TARGET_KIND.is_shipping()
}

/// Bounds one test requirement by the ceiling declared for the shipping target it exercises.
///
/// `GNT-16.6-target-kinds` bounds a non-shipping test target's capability ceiling by the declared
/// ceiling of the shipping target it exercises: the test target never widens that target's
/// authority closure, capability requirements, or exported interface. The landed one-directional
/// `check_ceiling` is reused unchanged, so a requirement outside the declared subject or above
/// the declared strength fails here and the bound grants nothing.
pub fn bound_test_requirement(
    declared: &DeclaredCeiling,
    required: &RequirementDemand,
) -> Result<(), PackageError> {
    check_ceiling(declared, required)
}

/// One declared harness capability of the testing-support contract, in requirement order.
///
/// The declared order is the bullet order of the testing-support contract, each wire spelling is
/// that contract's requirement in kebab case, and `requirement` returns the contract's own
/// wording. The vocabulary is closed: a harness capability outside it is invalid rather than an
/// extension point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestHarnessCapability {
    /// Deterministic test ordering and isolation.
    DeterministicOrderingAndIsolation,
    /// Assertion and comparison diagnostics.
    AssertionDiagnostics,
    /// Fixtures and temporary capability roots.
    FixturesAndTemporaryCapabilityRoots,
    /// Fake clocks, random sources, and host capabilities.
    FakeClockRandomnessAndCapabilities,
    /// Expected-failure and timeout support.
    ExpectedFailureAndTimeout,
    /// Property-test shrinking contracts.
    PropertyShrinking,
    /// Durable replay and recovery test harnesses.
    DurableReplayAndRecovery,
}

impl TestHarnessCapability {
    /// The closed declared set, in the testing-support contract's requirement order.
    pub const ALL: [TestHarnessCapability; 7] = [
        Self::DeterministicOrderingAndIsolation,
        Self::AssertionDiagnostics,
        Self::FixturesAndTemporaryCapabilityRoots,
        Self::FakeClockRandomnessAndCapabilities,
        Self::ExpectedFailureAndTimeout,
        Self::PropertyShrinking,
        Self::DurableReplayAndRecovery,
    ];

    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DeterministicOrderingAndIsolation => "deterministic-test-ordering-and-isolation",
            Self::AssertionDiagnostics => "assertion-and-comparison-diagnostics",
            Self::FixturesAndTemporaryCapabilityRoots => "fixtures-and-temporary-capability-roots",
            Self::FakeClockRandomnessAndCapabilities => {
                "fake-clocks-random-sources-and-host-capabilities"
            }
            Self::ExpectedFailureAndTimeout => "expected-failure-and-timeout-support",
            Self::PropertyShrinking => "property-test-shrinking-contracts",
            Self::DurableReplayAndRecovery => "durable-replay-and-recovery-harnesses",
        }
    }

    /// Returns the declared requirement text of the testing-support contract.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::DeterministicOrderingAndIsolation => "deterministic test ordering and isolation",
            Self::AssertionDiagnostics => "assertion and comparison diagnostics",
            Self::FixturesAndTemporaryCapabilityRoots => "fixtures and temporary capability roots",
            Self::FakeClockRandomnessAndCapabilities => {
                "fake clocks, random sources, and host capabilities"
            }
            Self::ExpectedFailureAndTimeout => "expected-failure and timeout support",
            Self::PropertyShrinking => "property-test shrinking contracts",
            Self::DurableReplayAndRecovery => "durable replay and recovery test harnesses",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.wire_name() == name)
    }
}

/// Why one declared test-run substitution set is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestSubstitutionRefusal {
    /// A declared spelling is not one of the closed substitutions of `std.test`.
    Unknown,
    /// A declared spelling appears more than once in the same declaration.
    Duplicate,
}

/// Decodes one declared test-run substitution set into canonical declaration order.
///
/// A run declares the substitutions it consumes instead of acquiring ambient authority: every
/// spelling must be one of the closed `TestSubstitution` set, no spelling may appear twice, and
/// the returned set is in the canonical declaration order of `TestSubstitution::ALL` rather than
/// the presentation order, so two runs declaring the same set in different orders publish the
/// same declaration. An empty declaration is admitted and declares no substitution.
pub fn declare_test_substitutions(
    names: &[&str],
) -> Result<Vec<TestSubstitution>, TestSubstitutionRefusal> {
    let mut declared = Vec::with_capacity(names.len());
    for name in names {
        let substitution =
            TestSubstitution::from_wire_name(name).ok_or(TestSubstitutionRefusal::Unknown)?;
        if declared.contains(&substitution) {
            return Err(TestSubstitutionRefusal::Duplicate);
        }
        declared.push(substitution);
    }
    declared.sort_by_key(|substitution| substitution.canonical_index());
    Ok(declared)
}

/// One declared execution rule of the `std.test` harness, in the issue plan's declaration order.
///
/// The declared order is the order of the `GNT-GP-TEST-001` implementation bullet, each wire
/// spelling is that rule in kebab case, and `requirement` returns the plan's own wording. The
/// vocabulary is closed: an execution rule outside it is invalid rather than an extension point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestExecutionRule {
    /// Deterministic discovery and ordering.
    DeterministicDiscoveryAndOrdering,
    /// Per-test isolation.
    PerTestIsolation,
    /// Bounded parallelism.
    BoundedParallelism,
    /// Timeouts.
    Timeout,
    /// Fixtures.
    Fixture,
    /// Temporary capability roots.
    TemporaryCapabilityRoot,
    /// Structured assertions.
    StructuredAssertion,
    /// Shrinking.
    Shrinking,
    /// Replay.
    Replay,
}

impl TestExecutionRule {
    /// The closed declared set, in the issue plan's declaration order.
    pub const ALL: [TestExecutionRule; 9] = [
        Self::DeterministicDiscoveryAndOrdering,
        Self::PerTestIsolation,
        Self::BoundedParallelism,
        Self::Timeout,
        Self::Fixture,
        Self::TemporaryCapabilityRoot,
        Self::StructuredAssertion,
        Self::Shrinking,
        Self::Replay,
    ];

    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DeterministicDiscoveryAndOrdering => "deterministic-discovery-and-ordering",
            Self::PerTestIsolation => "per-test-isolation",
            Self::BoundedParallelism => "bounded-parallelism",
            Self::Timeout => "timeouts",
            Self::Fixture => "fixtures",
            Self::TemporaryCapabilityRoot => "temporary-capability-roots",
            Self::StructuredAssertion => "structured-assertions",
            Self::Shrinking => "shrinking",
            Self::Replay => "replay",
        }
    }

    /// Returns the declared requirement text of the issue plan.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::DeterministicDiscoveryAndOrdering => "deterministic discovery and ordering",
            Self::PerTestIsolation => "per-test isolation",
            Self::BoundedParallelism => "bounded parallelism",
            Self::Timeout => "timeouts",
            Self::Fixture => "fixtures",
            Self::TemporaryCapabilityRoot => "temporary capability roots",
            Self::StructuredAssertion => "structured assertions",
            Self::Shrinking => "shrinking",
            Self::Replay => "replay",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.wire_name() == name)
    }
}

/// Why one declared test discovery set is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestDiscoveryRefusal {
    /// A declared test name is empty, so it names no test.
    Empty,
    /// A declared test name appears more than once in the same discovery set.
    Duplicate,
}

/// Orders one declared test discovery set into the canonical discovery order.
///
/// Discovery is deterministic and independent of presentation order: the declared names are
/// returned in ascending byte order, which is the declared canonical discovery order, so two runs
/// that declare the same tests in different orders enumerate them identically. A name that is
/// empty or declared twice is refused rather than repaired, so the enumerated set is exactly the
/// declared one, and an empty declaration enumerates no test.
pub fn declare_test_discovery<'a>(names: &[&'a str]) -> Result<Vec<&'a str>, TestDiscoveryRefusal> {
    let mut declared = Vec::with_capacity(names.len());
    for name in names {
        if name.is_empty() {
            return Err(TestDiscoveryRefusal::Empty);
        }
        if declared.contains(name) {
            return Err(TestDiscoveryRefusal::Duplicate);
        }
        declared.push(*name);
    }
    declared.sort_unstable();
    Ok(declared)
}

/// Why one declared test-run plan is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestRunRefusal {
    /// A declared kind spelling is not one of the closed test kinds.
    UnknownKind,
    /// A declared kind appears more than once in the same plan.
    DuplicateKind,
    /// A declared substitution spelling is not one of the closed substitutions.
    UnknownSubstitution,
    /// A declared substitution appears more than once in the same plan.
    DuplicateSubstitution,
}

/// One declared test-run plan: the kinds it contains, the substitutions it consumes, and the
/// execution rules it obeys.
///
/// A plan is a declaration only: it schedules nothing, executes nothing, and acquires no
/// authority. Both declared sets are held in canonical declaration order, independent of the
/// order they were presented in, and every plan obeys the whole closed `TestExecutionRule` set
/// because the harness rules are kind-independent: no kind opts out of deterministic discovery,
/// isolation, bounded parallelism, timeouts, fixtures, temporary capability roots, structured
/// assertions, shrinking, or replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestRunPlan {
    kinds: Vec<TestKind>,
    substitutions: Vec<TestSubstitution>,
}

impl TestRunPlan {
    /// Returns the declared kinds, in canonical declaration order.
    #[must_use]
    pub fn kinds(&self) -> &[TestKind] {
        &self.kinds
    }

    /// Returns the declared substitutions, in canonical declaration order.
    #[must_use]
    pub fn substitutions(&self) -> &[TestSubstitution] {
        &self.substitutions
    }

    /// Returns the execution rules every declared plan obeys.
    #[must_use]
    pub fn execution_rules(&self) -> &'static [TestExecutionRule] {
        &TestExecutionRule::ALL
    }
}

/// Declares one test-run plan over a presented kind set and a presented substitution set.
///
/// Both sets are decoded strictly and returned in canonical declaration order, so two runs that
/// declare the same kinds and substitutions in different orders declare the same plan. An unknown
/// or twice-declared kind or substitution is refused rather than repaired, and an empty plan is
/// admitted: it declares no kind and no substitution.
pub fn declare_test_run(
    kinds: &[&str],
    substitutions: &[&str],
) -> Result<TestRunPlan, TestRunRefusal> {
    let mut declared_kinds = Vec::with_capacity(kinds.len());
    for name in kinds {
        let kind = TestKind::from_wire_name(name).ok_or(TestRunRefusal::UnknownKind)?;
        if declared_kinds.contains(&kind) {
            return Err(TestRunRefusal::DuplicateKind);
        }
        declared_kinds.push(kind);
    }
    declared_kinds.sort_by_key(|kind| kind.canonical_index());
    let declared_substitutions =
        declare_test_substitutions(substitutions).map_err(|refusal| match refusal {
            TestSubstitutionRefusal::Unknown => TestRunRefusal::UnknownSubstitution,
            TestSubstitutionRefusal::Duplicate => TestRunRefusal::DuplicateSubstitution,
        })?;
    Ok(TestRunPlan {
        kinds: declared_kinds,
        substitutions: declared_substitutions,
    })
}
