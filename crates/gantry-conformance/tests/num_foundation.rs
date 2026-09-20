//! Conformance for the declared `std.num` surface.
//!
//! The lane reads the published note and requires it to name the declared pure package family, its
//! separation from the capability-backed `std.random` family, the clauses whose semantics it must
//! preserve, and only specification anchors that the model's clause vocabularies declare.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{HOST_DOMAIN_CLAUSES, PackageFamily, SCALAR_CLAUSES, STDLIB_CLAUSES};

const REQUIRED_ANCHORS: [&str; 8] = [
    "GNT-34.1",
    "GNT-34.3",
    "GNT-34.7",
    "GNT-34.12",
    "GNT-35.3",
    "GNT-35.4",
    "GNT-35.5",
    "GNT-35.12",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns whether some declared clause vocabulary carries exactly `token` or an anchor introduced
/// by `token-`, so a prefix-imprecise citation such as `GNT-35.1` never matches the declared
/// `GNT-35.10` anchor.
fn declared_anchor(token: &str) -> bool {
    let introduced = format!("{token}-");
    STDLIB_CLAUSES
        .iter()
        .chain(SCALAR_CLAUSES.iter())
        .chain(HOST_DOMAIN_CLAUSES.iter())
        .any(|anchor| *anchor == token || anchor.starts_with(&introduced))
}

/// Returns every `GNT-` token the note cites, in order of first appearance.
fn cited_tokens(note: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    for (index, _) in note.match_indices("GNT-") {
        let rest = &note[index..];
        let end = rest
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '.' || character == '-')
            })
            .unwrap_or(rest.len());
        let token = &rest[..end];
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    tokens
}

#[test]
fn num_note_names_the_declared_family_purity_and_separation() {
    let note = read_text(&workspace_root().join("docs/num-foundation.md"));

    // The declared family facts come from the model rather than the note's prose.
    assert!(
        PackageFamily::ALL.contains(&PackageFamily::Num),
        "the numeric family is one of the declared families"
    );
    assert_eq!(PackageFamily::Num.package_name(), "std.num");
    assert_eq!(PackageFamily::Num.wire_name(), "num");
    assert!(PackageFamily::Num.is_pure());
    assert!(note.contains(&PackageFamily::Num.package_name()));
    assert!(note.contains(PackageFamily::Num.wire_name()));

    // The separation is a model fact: the random counterpart is capability-backed, not pure.
    assert!(!PackageFamily::Random.is_pure());
    assert!(note.contains(&PackageFamily::Random.package_name()));
    let separation = note
        .split("\n\n")
        .find(|paragraph| paragraph.contains(&PackageFamily::Random.package_name()))
        .unwrap_or_else(|| panic!("the note names the random counterpart"));
    assert!(
        separation.contains("capability-backed"),
        "the separation paragraph marks the random family capability-backed: {separation}"
    );

    // The note records declarations only.
    assert!(
        note.contains("adds no normative row"),
        "the note states that it adds no normative row"
    );

    for anchor in REQUIRED_ANCHORS {
        assert!(note.contains(anchor), "the note cites `{anchor}`");
        assert!(
            declared_anchor(anchor),
            "`{anchor}` is declared by the model"
        );
    }
    for token in cited_tokens(&note) {
        assert!(
            declared_anchor(token),
            "`{token}` is declared by a clause vocabulary"
        );
    }
}
