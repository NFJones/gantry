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

/// Returns the note with every whitespace run collapsed to one space, so a
/// phrase that a wrap splits in the file can still be asserted as one phrase.
fn flattened_note() -> String {
    AUTHORITY_NOTE
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn authority_note_names_the_owned_clauses_codes_and_ceilings() {
    for anchor in [
        "GNT-3-T-AUTHORITY-CLOSURE",
        "GNT-7.2-authority-rebinding",
        "GNT-3-T-AUTHORITY-ADMISSION",
    ] {
        assert!(
            AUTHORITY_NOTE.contains(anchor),
            "the authority note names {anchor}"
        );
    }
    for code in [
        "authority-closure-exceeds-maximum",
        "authority-unresolved-requirement",
        "authority-ambiguous-requirement",
        "authority-rebinding-widens-closure",
        "authority-resolution-exceeds-maximum",
    ] {
        assert!(
            AUTHORITY_NOTE.contains(code),
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
            AUTHORITY_NOTE.contains(member),
            "the authority note names the clause member {member}"
        );
    }
    let flattened = flattened_note();
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
            flattened.contains(&declared),
            "the authority note declares {constant} as {value} in one phrase"
        );
    }
    assert!(
        AUTHORITY_NOTE.contains("It grants nothing"),
        "the authority note carries its non-claim"
    );
}
