//! The versioned deterministic pseudo-random generator of `GNT-40.1`.
//!
//! The generator is pure: its state is owned by the value, every step is exact 64-bit arithmetic
//! with wrapping defined by the algorithm, and nothing here reads host entropy, global state,
//! timing, or a target facility. Copying a generator copies its state, so two copies advance
//! independently. This module publishes no streaming, iteration, durability, quota, schema,
//! recovery, boundary encoding, or machine representation, and claims no secure randomness: secure
//! randomness is the capability-backed `std.random` surface and must never be substituted for this
//! generator or presented as one.

/// The declared clauses of `GNT-40.0` and `GNT-40.1`, in specification order.
pub const NUM_CLAUSES: [&str; 2] = [
    "GNT-40.0-deterministic-numeric-scope",
    "GNT-40.1-deterministic-prng-identity",
];

/// The canonical wire spelling of the one admitted generator algorithm.
pub const PRNG_ALGORITHM: &str = "splitmix64";

/// The admitted algorithm version of the one admitted generator algorithm.
pub const PRNG_ALGORITHM_VERSION: u32 = 1;

/// The 64-bit state advance increment of `GNT-40.1`.
pub const PRNG_STATE_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;

/// The first mixing constant of `GNT-40.1`.
pub const PRNG_MIX_FIRST: u64 = 0xBF58_476D_1CE4_E5B9;

/// The second mixing constant of `GNT-40.1`.
pub const PRNG_MIX_SECOND: u64 = 0x94D0_49BB_1331_11EB;

/// One admitted algorithm and version pair of `GNT-40.1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrngAlgorithmVersion {
    /// The `splitmix64` algorithm at version 1.
    SplitMix64V1,
}

impl PrngAlgorithmVersion {
    /// Every admitted algorithm and version, in declaration order.
    pub const ALL: [Self; 1] = [Self::SplitMix64V1];

    /// Returns the canonical algorithm spelling of this version.
    #[must_use]
    pub const fn algorithm(self) -> &'static str {
        match self {
            Self::SplitMix64V1 => PRNG_ALGORITHM,
        }
    }

    /// Returns the admitted version of this algorithm.
    #[must_use]
    pub const fn version(self) -> u32 {
        match self {
            Self::SplitMix64V1 => PRNG_ALGORITHM_VERSION,
        }
    }

    /// Returns the admitted version of one algorithm spelling, or nothing when the pair is not
    /// admitted; an unknown spelling and an unknown version both refuse rather than falling back.
    #[must_use]
    pub fn admits(algorithm: &str, version: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.algorithm() == algorithm && candidate.version() == version)
    }
}

/// One versioned deterministic generator value of `GNT-40.1`.
///
/// The value owns its 64-bit state, so a copy is an independent generator with the same state; the
/// type is `Copy` deliberately, and no step shares, aliases, or globally caches state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicPrng {
    state: u64,
}

impl DeterministicPrng {
    /// Returns the admitted algorithm and version of every generator value.
    #[must_use]
    pub const fn algorithm_version() -> PrngAlgorithmVersion {
        PrngAlgorithmVersion::SplitMix64V1
    }

    /// Seeds one generator from an exact 64-bit seed.
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the exact current state.
    #[must_use]
    pub const fn state(self) -> u64 {
        self.state
    }

    /// Advances one step and returns its mixed 64-bit output.
    ///
    /// The state advances by the increment with wrapping addition, and the output mixes the new
    /// state with two xorshift-multiply rounds and a final shift. Wrapping is part of the algorithm
    /// rather than an overflow mode, so no step refuses, saturates, or depends on a host facility.
    pub fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(PRNG_STATE_INCREMENT);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(PRNG_MIX_FIRST);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(PRNG_MIX_SECOND);
        mixed ^ (mixed >> 31)
    }
}
