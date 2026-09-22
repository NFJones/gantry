//! Conformance for the declared `std.io` common I/O surface.
//!
//! The lane reads the published note and requires it to name the declared capability family, to
//! mirror the declared Reader/Writer/Seek progress mapping exactly, to cite only specification
//! anchors the model's clause vocabularies declare, and to state the unlanded contract without
//! claiming it.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::HostDomainFamily;
use gantry::ir::{
    CONSTANT_CLAUSES, HOST_DOMAIN_CLAUSES, HostProgress, PackageFamily, ProgressObservation,
    STDLIB_CLAUSES,
};

const REQUIRED_ANCHORS: [&str; 6] = [
    "GNT-29.1",
    "GNT-29.2",
    "GNT-29.3",
    "GNT-29.14",
    "GNT-29.15",
    "GNT-34.1",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the note with every whitespace run collapsed to one space, so a published sentence
/// can be pinned without depending on its line wrapping.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns whether some declared clause vocabulary carries exactly `token` or an anchor
/// introduced by `token-`, so a prefix-imprecise citation such as `GNT-29.9` never matches the
/// declared `GNT-29.9-codec-contract` anchor's siblings by accident of spelling.
fn declared_anchor(token: &str) -> bool {
    let introduced = format!("{token}-");
    STDLIB_CLAUSES
        .iter()
        .chain(HOST_DOMAIN_CLAUSES.iter())
        .chain(CONSTANT_CLAUSES.iter())
        .any(|anchor| *anchor == token || anchor.starts_with(&introduced))
}

#[test]
fn io_note_names_the_declared_capability_family() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    assert!(PackageFamily::ALL.contains(&PackageFamily::Io));
    assert!(!PackageFamily::Io.is_pure());
    let package = PackageFamily::Io.package_name();
    assert!(
        flat.contains("capability-backed family `PackageFamily::Io`"),
        "the note must name the declared family `PackageFamily::Io` as capability-backed"
    );
    assert!(
        flat.contains(&format!("logical package name `{package}`")),
        "the note must name the declared package {package}"
    );
    assert!(
        flat.contains(&format!(
            "wire spelling `{}`",
            PackageFamily::Io.wire_name()
        )),
        "the note must name the declared wire spelling"
    );
}

#[test]
fn io_note_mirrors_the_declared_progress_mapping() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    let declared = [
        (HostProgress::Eof, ProgressObservation::Eof),
        (HostProgress::ShortRead, ProgressObservation::ShortRead),
        (HostProgress::ShortWrite, ProgressObservation::ShortWrite),
        (HostProgress::NotStarted, ProgressObservation::NotStarted),
        (
            HostProgress::Complete,
            ProgressObservation::CommittedProgress,
        ),
    ];
    for (progress, observation) in declared {
        assert_eq!(progress.observation(), observation);
        let spelling = observation.wire_name();
        assert!(
            flat.contains(&format!(
                "`HostProgress::{progress:?}` maps to `{spelling}`"
            )),
            "the note must state that `{progress:?}` maps to `{spelling}`"
        );
    }
}

#[test]
fn io_surface_declares_no_host_domain_family() {
    let names = HostDomainFamily::ALL
        .into_iter()
        .map(HostDomainFamily::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 12);
    assert!(
        !names.contains(&"io"),
        "the host-domain matrix must declare no io family while the note says so"
    );

    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);
    assert!(
        flat.contains(
            "carries no `io` row: `HostDomainFamily::ALL` holds exactly those twelve entries"
        ),
        "the note must state that no io host-domain row is declared"
    );
}

#[test]
fn io_note_cites_only_declared_anchors_and_the_required_bounds() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    for anchor in REQUIRED_ANCHORS {
        assert!(
            flat.contains(anchor),
            "the note must cite the declared bound {anchor}"
        );
    }
    for token in note.split('`').filter(|token| token.starts_with("GNT-")) {
        assert!(
            declared_anchor(token),
            "the note must not cite an undeclared anchor {token}"
        );
    }
}

#[test]
fn io_note_records_the_unlanded_contract_without_claiming_it() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    for needle in [
        "It declares no Reader, Writer, or Seek contract clause: no operation kinds, no per-call bound, no interruption, cancellation, backpressure, or post-failure ownership rule, and no refusal spellings.",
        "It declares no item or interface row for `std.io`, no interface digest, and no stability tier",
        "It grants no adapter, no host trait, no runtime availability, and no capability: adapters remain leaves",
    ] {
        assert!(
            flat.contains(needle),
            "the note must record the unlanded contract: {needle}"
        );
    }
}
