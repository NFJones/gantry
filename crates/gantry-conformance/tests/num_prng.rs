//! Conformance for the versioned deterministic generator of `GNT-40.1`.
//!
//! The lanes read the published clause and note, and require the model to take exactly the declared
//! step: one admitted algorithm and version, exact 64-bit wrapping arithmetic, deterministic output
//! for a seed and a number of steps, intentional copy semantics, and no entropy, global state, or
//! substitute path.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CONSTANT_CLAUSES, DeterministicPrng, ERROR_SEMANTICS_CLAUSES, HOST_DOMAIN_CLAUSES, NUM_CLAUSES,
    PRNG_ALGORITHM, PRNG_ALGORITHM_VERSION, PRNG_MIX_FIRST, PRNG_MIX_SECOND, PRNG_STATE_INCREMENT,
    PrngAlgorithmVersion, SCALAR_CLAUSES, STDLIB_CLAUSES,
};

const REQUIRED_ANCHORS: [&str; 7] = [
    "GNT-40.0-deterministic-numeric-scope",
    "GNT-40.1-deterministic-prng-identity",
    "GNT-40.2-checked-integer-algorithms",
    "GNT-40.3-numeric-conversions",
    "GNT-40.4-integer-bit-operations",
    "GNT-40.5-finite-float-algorithms",
    "GNT-40.6-canonical-numeric-text",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the body of one clause: the text between its anchor and the next anchor, or to the end
/// of the specification when the clause is the final one.
fn clause_body<'a>(specification: &'a str, anchor: &str) -> &'a str {
    let declaration = format!("<a id=\"{anchor}\"></a>");
    let start = specification
        .find(&declaration)
        .unwrap_or_else(|| panic!("the specification anchors `{anchor}`"))
        + declaration.len();
    let rest = &specification[start..];
    match rest.find("<a id=") {
        Some(end) => &rest[..end],
        None => rest,
    }
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
    let prng_clause = clause_body(&specification, "GNT-40.1-deterministic-prng-identity");
    for spelling in [
        PRNG_ALGORITHM,
        &format!("0x{PRNG_STATE_INCREMENT:016X}"),
        &format!("0x{PRNG_MIX_FIRST:016X}"),
        &format!("0x{PRNG_MIX_SECOND:016X}"),
    ] {
        assert!(
            prng_clause.contains(spelling),
            "the `GNT-40.1` clause publishes `{spelling}`"
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

/// Every declared clause anchor exists in the specification and the Section 2.1 registration row
/// reaches each covered section's last clause.
///
/// The row is one line of the specification that lists the anchors of each governed section; a new
/// clause the row does not reach is registered nowhere, and a vocabulary entry with no matching
/// specification anchor names a clause the specification does not declare. Both classes fail here.
#[test]
fn section_2_1_registration_row_covers_the_declared_clauses() {
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let row = specification
        .lines()
        .find(|line| line.contains("GNT-39.0-collection-key-and-order-scope"))
        .unwrap_or_else(|| panic!("the registration row names the collection section"));
    // The row lists each section as a range of anchors, so requiring its first and last anchor
    // proves the range reaches the clause the section currently ends at.
    for vocabulary in [
        gantry::ir::COLLECTION_CLAUSES.as_slice(),
        NUM_CLAUSES.as_slice(),
        STDLIB_CLAUSES.as_slice(),
        SCALAR_CLAUSES.as_slice(),
        HOST_DOMAIN_CLAUSES.as_slice(),
        CONSTANT_CLAUSES.as_slice(),
        ERROR_SEMANTICS_CLAUSES.as_slice(),
    ] {
        for anchor in [vocabulary[0], vocabulary[vocabulary.len() - 1]] {
            assert!(
                row.contains(anchor),
                "the registration row names `{anchor}`"
            );
        }
        for anchor in vocabulary {
            assert!(
                specification.contains(&format!("<a id=\"{anchor}\"></a>")),
                "the specification declares the anchor `{anchor}`"
            );
        }
    }
}

#[test]
fn deterministic_prng_step_is_exact_and_copy_is_intentional() {
    let mut generator = DeterministicPrng::seeded(0);
    assert_eq!(generator.state(), 0);
    // Reference vectors of the declared algorithm: seed 0 produces these two outputs in order, and
    // the state after the first step is exactly the increment.
    assert_eq!(generator.next_output(), 0xE220_A839_7B1D_CDAF);
    assert_eq!(generator.state(), PRNG_STATE_INCREMENT);
    assert_eq!(generator.next_output(), 0x6E78_9E6A_A1B9_65F4);
    assert_eq!(generator.state(), PRNG_STATE_INCREMENT.wrapping_mul(2));
    assert_ne!(
        DeterministicPrng::seeded(1).next_output(),
        0xE220_A839_7B1D_CDAF,
        "a different seed produces a different first output"
    );

    // The state advance wraps by definition rather than refusing or saturating.
    let mut wrapped = DeterministicPrng::seeded(u64::MAX);
    wrapped.next_output();
    assert_eq!(wrapped.state(), u64::MAX.wrapping_add(PRNG_STATE_INCREMENT));

    // One seed and one number of steps produce identical state and outputs every time.
    let mut first = DeterministicPrng::seeded(7);
    let mut second = DeterministicPrng::seeded(7);
    for step in 0..8 {
        let left = first.next_output();
        let right = second.next_output();
        assert_eq!(left, right, "step {step} agrees");
        assert_eq!(first.state(), second.state(), "step {step} state agrees");
    }

    // Copying a generator copies its state: the copy advances independently of the original.
    let mut original = DeterministicPrng::seeded(11);
    let mut copy = original;
    assert_eq!(copy.state(), original.state());
    let original_first = original.next_output();
    let copy_first = copy.next_output();
    assert_eq!(
        original_first, copy_first,
        "the copy starts where it was copied"
    );
    assert_eq!(original.state(), copy.state());
    let original_second = original.next_output();
    assert_ne!(
        original_second, copy_first,
        "the copy did not advance with the original"
    );
    assert_eq!(
        DeterministicPrng::seeded(11).next_output(),
        DeterministicPrng::seeded(11).next_output(),
        "one seed always produces the same first output"
    );
}
