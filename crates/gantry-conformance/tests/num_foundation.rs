//! Conformance for the declared `std.num` surface.
//!
//! The lane reads the published note and requires it to name the declared pure package family, its
//! separation from the capability-backed `std.random` family, the clauses whose semantics it must
//! preserve, and only specification anchors that the model's clause vocabularies declare.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    COLLECTION_CLAUSES, CONSTANT_CLAUSES, ERROR_SEMANTICS_CLAUSES, HOST_DOMAIN_CLAUSES,
    PackageFamily, SCALAR_CLAUSES, STDLIB_CLAUSES, SemanticMode, StabilityTier, TargetKind,
    canonical_pure_hierarchy,
};

const REQUIRED_ANCHORS: [&str; 9] = [
    "GNT-5.15",
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
        .chain(CONSTANT_CLAUSES.iter())
        .chain(ERROR_SEMANTICS_CLAUSES.iter())
        .chain(COLLECTION_CLAUSES.iter())
        .any(|anchor| *anchor == token || anchor.starts_with(&introduced))
}

/// Returns every anchor identifier the specification declares.
fn specification_anchors(specification: &str) -> Vec<&str> {
    specification
        .match_indices("<a id=\"")
        .filter_map(|(index, marker)| {
            let rest = &specification[index + marker.len()..];
            rest.find('"').map(|end| &rest[..end])
        })
        .collect()
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

    // The declared applicability, tier, dependency, and downstream consumer are model facts.
    let graph = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy declares: {error}"));
    let numeric = graph
        .package(&PackageFamily::Num.package_name())
        .unwrap_or_else(|| panic!("std.num is declared in the canonical pure hierarchy"));
    assert_eq!(numeric.tier(), StabilityTier::Stable);
    assert_eq!(
        numeric.modes(),
        &BTreeSet::from([SemanticMode::Portable, SemanticMode::Application]),
        "the numeric family declares exactly the portable and application modes"
    );
    assert_eq!(
        numeric.targets(),
        &BTreeSet::from([TargetKind::Library, TargetKind::Binary]),
        "the numeric family declares exactly the library and binary targets"
    );
    assert_eq!(
        numeric
            .dependencies()
            .iter()
            .cloned()
            .collect::<Vec<String>>(),
        vec!["std.core".to_owned()],
        "the numeric family depends on `std.core` alone"
    );
    let crypto = graph
        .package(&PackageFamily::Crypto.package_name())
        .unwrap_or_else(|| panic!("std.crypto is declared in the canonical pure hierarchy"));
    assert!(
        crypto
            .dependencies()
            .contains(&PackageFamily::Num.package_name()),
        "`std.crypto` consumes the numeric family"
    );

    // The note publishes every declared fact, in the model's own spellings, in the applicability
    // paragraph itself.
    let applicability = note
        .split("\n\n")
        .find(|paragraph| paragraph.contains("GNT-34.7-applicability-and-feature-granularity"))
        .unwrap_or_else(|| panic!("the note cites the applicability clause"));
    for spelling in [
        numeric.tier().wire_name(),
        SemanticMode::Portable.wire_name(),
        SemanticMode::Application.wire_name(),
        TargetKind::Library.wire_name(),
        TargetKind::Binary.wire_name(),
        "std.core",
        &PackageFamily::Crypto.package_name(),
    ] {
        assert!(
            applicability.contains(spelling),
            "the applicability paragraph publishes `{spelling}`"
        );
    }

    for anchor in REQUIRED_ANCHORS {
        assert!(note.contains(anchor), "the note cites `{anchor}`");
    }
    let specification = read_text(&workspace_root().join("SPEC.md"));
    let anchors = specification_anchors(&specification);
    let spec_exists = |token: &str| {
        let introduced = format!("{token}-");
        anchors
            .iter()
            .any(|anchor| *anchor == token || anchor.starts_with(&introduced))
    };
    for anchor in REQUIRED_ANCHORS {
        assert!(
            declared_anchor(anchor) || spec_exists(anchor),
            "`{anchor}` is declared by the model or the specification"
        );
    }
    for token in cited_tokens(&note) {
        assert!(
            declared_anchor(token) || spec_exists(token),
            "`{token}` is declared by a clause vocabulary or the specification"
        );
    }
}
