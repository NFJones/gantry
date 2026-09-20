//! Conformance for the declared `std.random` capability surface.
//!
//! The lane reads the published note and requires it to name the declared package family, the
//! declared host-domain family with its application-only applicability, and only specification
//! anchors that the model's clause vocabularies declare.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::{HostDomainFamily, HostTarget};
use gantry::ir::{CONSTANT_CLAUSES, HOST_DOMAIN_CLAUSES, PackageFamily, STDLIB_CLAUSES};

const REQUIRED_ANCHORS: [&str; 5] = ["GNT-29.8", "GNT-29.10", "GNT-29.15", "GNT-32.3", "GNT-34.1"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns whether some declared clause vocabulary carries an anchor starting with `token`.
fn declared_anchor(token: &str) -> bool {
    STDLIB_CLAUSES
        .iter()
        .chain(HOST_DOMAIN_CLAUSES.iter())
        .chain(CONSTANT_CLAUSES.iter())
        .any(|anchor| anchor.starts_with(token))
}

#[test]
fn random_capability_note_names_the_declared_family_and_applicability() {
    let root = workspace_root();
    let note = read_text(&root.join("docs/random-capability.md"));

    let package = PackageFamily::Random.package_name();
    assert!(
        note.contains(&package),
        "the note must name the declared package {package}"
    );
    let wire = PackageFamily::Random.wire_name();
    assert!(
        note.contains(&format!("wire spelling `{wire}`")),
        "the note must introduce the declared wire spelling `{wire}` as such"
    );
    assert!(
        !PackageFamily::Random.is_pure(),
        "std.random is a capability-backed family"
    );

    let domain = HostDomainFamily::Randomness.wire_name();
    assert!(
        note.contains(&format!("wire spelling `{domain}`")),
        "the note must introduce the {domain} host domain by its declared wire spelling"
    );
    assert!(HostDomainFamily::Randomness.applies_to(HostTarget::Application));
    assert!(!HostDomainFamily::Randomness.applies_to(HostTarget::Portable));
    assert!(!HostDomainFamily::Randomness.applies_to(HostTarget::Durable));

    assert!(
        note.contains("std.num"),
        "the note must keep deterministic PRNG ownership with std.num"
    );

    for anchor in REQUIRED_ANCHORS {
        assert!(note.contains(anchor), "the note must cite {anchor}");
        assert!(
            declared_anchor(anchor),
            "{anchor} must be declared by a clause vocabulary"
        );
    }

    let mut cited = 0_usize;
    let mut remaining = note.as_str();
    while let Some(index) = remaining.find("GNT-") {
        let rest = &remaining[index..];
        let end = rest
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '.' || character == '-')
            })
            .unwrap_or(rest.len());
        let token = rest[..end].trim_end_matches(['-', '.']);
        if token.contains('.') {
            assert!(
                declared_anchor(token),
                "the note cites {token}, which no clause vocabulary declares"
            );
            cited += 1;
        }
        remaining = &rest[end..];
    }
    assert!(
        cited >= REQUIRED_ANCHORS.len(),
        "the note must cite the anchors it relies on"
    );
}
