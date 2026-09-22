//! The `std.test` package surface of `GNT-GP-TEST-001`: the target-qualified logical test
//! package of the standard-library hierarchy, its closed test-kind vocabulary, and the
//! deterministic substitutions a test run may consume.
//!
//! The package is a capability package: every kind below consumes production package, artifact,
//! authority, runtime, and standard-library interfaces, and every substitution is declared
//! explicitly rather than acquired from ambient authority. The surface declares facts only; the
//! runtime harness that executes a test target is not part of this module.

use crate::stdlib::{NameClass, PackageFamily, StabilityTier};

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
/// scheduler, or a host failure facility, and no test kind changes language semantics.
#[must_use]
pub const fn ambient_authority_is_never_acquired() -> bool {
    false
}
