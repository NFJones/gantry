//! Conformance for the versioned deterministic generator of `GNT-40.1`.
//!
//! The lanes read the published clause and note, and require the model to take exactly the declared
//! step: one admitted algorithm and version, exact 64-bit wrapping arithmetic, deterministic output
//! for a seed and a number of steps, intentional copy semantics, and no entropy, global state, or
//! substitute path.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    DeterministicPrng, NUM_CLAUSES, PRNG_ALGORITHM, PRNG_ALGORITHM_VERSION, PRNG_MIX_FIRST,
    PRNG_MIX_SECOND, PRNG_STATE_INCREMENT, PrngAlgorithmVersion,
};

const REQUIRED_ANCHORS: [&str; 2] = [
    "GNT-40.0-deterministic-numeric-scope",
    "GNT-40.1-deterministic-prng-identity",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

#[test]
fn deterministic_prng_surface_is_published() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    assert_eq!(NUM_CLAUSES, REQUIRED_ANCHORS);
    for anchor in NUM_CLAUSES {
        assert!(
            specification.contains(&format!("<a id=\"{anchor}\"></a>")),
            "the specification anchors `{anchor}`"
        );
        assert!(note.contains(anchor), "the note names `{anchor}`");
    }

    assert_eq!(PrngAlgorithmVersion::ALL.len(), 1);
    assert_eq!(PrngAlgorithmVersion::ALL[0].algorithm(), PRNG_ALGORITHM);
    assert_eq!(
        PrngAlgorithmVersion::ALL[0].version(),
        PRNG_ALGORITHM_VERSION
    );
    for spelling in [
        PRNG_ALGORITHM,
        &format!("0x{PRNG_STATE_INCREMENT:016X}"),
        &format!("0x{PRNG_MIX_FIRST:016X}"),
        &format!("0x{PRNG_MIX_SECOND:016X}"),
    ] {
        assert!(
            specification.contains(spelling),
            "the specification publishes `{spelling}`"
        );
    }

    // An algorithm or version pair the clause does not admit is refused rather than substituted.
    assert_eq!(
        PrngAlgorithmVersion::admits(PRNG_ALGORITHM, PRNG_ALGORITHM_VERSION),
        Some(PrngAlgorithmVersion::SplitMix64V1)
    );
    for (algorithm, version) in [
        (PRNG_ALGORITHM, PRNG_ALGORITHM_VERSION + 1),
        (PRNG_ALGORITHM, 0),
        ("SplitMix64", PRNG_ALGORITHM_VERSION),
        ("", 0),
        ("host", PRNG_ALGORITHM_VERSION),
    ] {
        assert_eq!(
            PrngAlgorithmVersion::admits(algorithm, version),
            None,
            "`{algorithm}` at version {version} is not admitted"
        );
    }
}

#[test]
fn deterministic_prng_step_is_exact_and_copy_is_intentional() {
    let mut generator = DeterministicPrng::seeded(0);
    assert_eq!(generator.state(), 0);
    // Reference vectors of the declared algorithm: seed 0 produces these two outputs in order, and
    // the state after the first step is exactly the increment.
    assert_eq!(generator.next(), 0xE220_A839_7B1D_CDAF);
    assert_eq!(generator.state(), PRNG_STATE_INCREMENT);
    assert_eq!(generator.next(), 0x6E78_9E6A_A1B9_65F4);
    assert_eq!(generator.state(), PRNG_STATE_INCREMENT.wrapping_mul(2));
    assert_ne!(
        DeterministicPrng::seeded(1).next(),
        0xE220_A839_7B1D_CDAF,
        "a different seed produces a different first output"
    );

    // The state advance wraps by definition rather than refusing or saturating.
    let mut wrapped = DeterministicPrng::seeded(u64::MAX);
    wrapped.next();
    assert_eq!(wrapped.state(), u64::MAX.wrapping_add(PRNG_STATE_INCREMENT));

    // One seed and one number of steps produce identical state and outputs every time.
    let mut first = DeterministicPrng::seeded(7);
    let mut second = DeterministicPrng::seeded(7);
    for step in 0..8 {
        let left = first.next();
        let right = second.next();
        assert_eq!(left, right, "step {step} agrees");
        assert_eq!(first.state(), second.state(), "step {step} state agrees");
    }

    // Copying a generator copies its state: the copy advances independently of the original.
    let mut original = DeterministicPrng::seeded(11);
    let mut copy = original;
    assert_eq!(copy.state(), original.state());
    let original_first = original.next();
    let copy_first = copy.next();
    assert_eq!(
        original_first, copy_first,
        "the copy starts where it was copied"
    );
    assert_eq!(original.state(), copy.state());
    let original_second = original.next();
    assert_ne!(
        original_second, copy_first,
        "the copy did not advance with the original"
    );
    assert_eq!(
        DeterministicPrng::seeded(11).next(),
        DeterministicPrng::seeded(11).next(),
        "one seed always produces the same first output"
    );
}
