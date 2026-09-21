//! Machine-checked evidence for the published authority-closure note.
//!
//! The note describes the model of `GNT-3-T-AUTHORITY-CLOSURE` and
//! `GNT-7.2-authority-rebinding` in `crates/gantry-ir/src/authority.rs`. This
//! lane checks that the note names every declared anchor, every registered
//! refusal code, every declared ceiling by the constant that declares it, every
//! clause member the model does not implement, and its non-claim, so a note
//! edit that drops a fact fails here.

use gantry::ir::{CapabilityAuthorityClosure, RequirementResolution};

/// The published note guarded by this lane.
const AUTHORITY_NOTE: &str = include_str!("../../../docs/authority-closure.md");

/// Returns whether one block of the note contains the phrase, after collapsing
/// the whitespace inside that block. A block is a paragraph, a list item, or a
/// table row: a phrase wrapped inside one block is recognised, while a phrase
/// assembled across two blocks is not.
fn block_contains(needle: &str) -> bool {
    AUTHORITY_NOTE.split("\n\n").any(|block| {
        block
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains(needle)
    })
}

#[test]
fn authority_note_names_the_owned_clauses_codes_and_ceilings() {
    for anchor in [
        "GNT-3-T-AUTHORITY-CLOSURE",
        "GNT-7.2-authority-rebinding",
        "GNT-3-T-AUTHORITY-ADMISSION",
    ] {
        assert!(block_contains(anchor), "the authority note names {anchor}");
    }
    for code in [
        "authority-closure-exceeds-maximum",
        "authority-unresolved-requirement",
        "authority-ambiguous-requirement",
        "authority-rebinding-widens-closure",
        "authority-resolution-exceeds-maximum",
    ] {
        assert!(
            block_contains(code),
            "the authority note names the registered code {code}"
        );
    }
    for member in [
        "schema root",
        "instantiation key",
        "callable row",
        "maximum static authority",
        "not representable",
    ] {
        assert!(
            block_contains(member),
            "the authority note names the clause member {member}"
        );
    }
    let ceilings = [
        (
            "CapabilityAuthorityClosure::MAXIMUM_INSTANCES",
            CapabilityAuthorityClosure::MAXIMUM_INSTANCES,
        ),
        (
            "CapabilityAuthorityClosure::MAXIMUM_SLOTS",
            CapabilityAuthorityClosure::MAXIMUM_SLOTS,
        ),
        (
            "RequirementResolution::MAXIMUM_REQUIREMENTS",
            RequirementResolution::MAXIMUM_REQUIREMENTS,
        ),
    ];
    for (constant, value) in ceilings {
        let declared = format!("{constant}` ({value})");
        assert!(
            block_contains(&declared),
            "the authority note declares {constant} as {value} in one block"
        );
    }
    assert!(
        block_contains("It grants nothing"),
        "the authority note carries its non-claim"
    );
}
