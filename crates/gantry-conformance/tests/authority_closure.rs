//! Machine-checked evidence for the published authority-closure note.
//!
//! The note describes the model of `GNT-3-T-AUTHORITY-CLOSURE` and
//! `GNT-7.2-authority-rebinding` in `crates/gantry-ir/src/authority.rs`. This
//! lane binds the note to the model: every declared anchor, every registered
//! refusal code, and every declared ceiling value must appear, so the note
//! cannot drift from the types it describes.

use gantry::ir::{CapabilityAuthorityClosure, RequirementResolution};

/// The published note guarded by this lane.
const AUTHORITY_NOTE: &str = include_str!("../../../docs/authority-closure.md");

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
    for ceiling in [
        CapabilityAuthorityClosure::MAXIMUM_INSTANCES,
        CapabilityAuthorityClosure::MAXIMUM_SLOTS,
        RequirementResolution::MAXIMUM_REQUIREMENTS,
    ] {
        assert!(
            AUTHORITY_NOTE.contains(&ceiling.to_string()),
            "the authority note states the declared ceiling {ceiling}"
        );
    }
    assert!(
        AUTHORITY_NOTE.contains("It grants nothing"),
        "the authority note carries its non-claim"
    );
}
