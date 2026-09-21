//! Public conformance for the canonical text case mapping of
//! `GNT-41.3-canonical-text-case-mapping`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{CaseMapping, TEXT_CLAUSES, TextValue};

/// The declared clauses of Section 41, written out independently of the model.
const EXPECTED_CLAUSES: [&str; 11] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
    "GNT-41.3-canonical-text-case-mapping",
    "GNT-41.4-canonical-text-builders",
    "GNT-41.5-canonical-text-traversal",
    "GNT-41.6-canonical-text-comparison",
    "GNT-41.7-canonical-grapheme-clusters",
    "GNT-41.8-bounded-text-matching",
    "GNT-41.9-canonical-text-conversions",
    "GNT-41.10-text-work-limits",
];
const CASE_CLAUSE: &str = "GNT-41.3-canonical-text-case-mapping";

#[test]
fn case_clause_publishes_the_two_full_default_mappings() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    let mappings = CaseMapping::ALL.map(CaseMapping::spelling);
    assert_eq!(mappings, ["lower", "upper"]);
    let body = clause_body(&specification, CASE_CLAUSE);
    // Each assertion is scoped to the phrase that declares the mapping, so an incidental mention
    // of a spelling elsewhere in the clause cannot satisfy it.
    for declaration in [
        "the lowercase mapping spelled `lower`",
        "the uppercase mapping spelled `upper`",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    for citation in [
        "`GNT-4.12`",
        "`GNT-5.16`",
        "`GNT-41.1-canonical-text-values`",
        "`GNT-41.2-canonical-text-normalization`",
    ] {
        assert!(body.contains(citation), "the clause cites {citation}");
    }
}

#[test]
fn case_mapping_matches_the_pinned_unicode_data() {
    assert_eq!(mapped("gantry", CaseMapping::Upper), "GANTRY");
    assert_eq!(mapped("GANTRY", CaseMapping::Lower), "gantry");
    assert_eq!(mapped("\u{e9}", CaseMapping::Upper), "\u{c9}");
    assert_eq!(mapped("\u{c9}", CaseMapping::Lower), "\u{e9}");
    // A full default mapping may publish more scalars than it maps from.
    assert_eq!(admitted("\u{df}".as_bytes()).scalar_count(), 1);
    assert_eq!(mapped("\u{df}", CaseMapping::Upper), "SS");
    assert_eq!(mapped("SS", CaseMapping::Lower), "ss");
    // A full default mapping is not required to be symmetric: the fi ligature has a full uppercase
    // mapping that expands it and no lowercase mapping, so the lowercase mapping publishes it
    // unchanged rather than decomposing it.
    assert_eq!(mapped("\u{fb01}", CaseMapping::Upper), "FI");
    assert_eq!(mapped("\u{fb01}", CaseMapping::Lower), "\u{fb01}");
    assert_eq!(
        TextValue::empty().map_case(CaseMapping::Upper),
        TextValue::empty()
    );
}

#[test]
fn case_mapping_is_locale_neutral() {
    // The default mappings are published, never the Turkish or Azeri tailoring.
    assert_eq!(mapped("i", CaseMapping::Upper), "I");
    assert_eq!(mapped("I", CaseMapping::Lower), "i");
    assert_ne!(mapped("i", CaseMapping::Upper), "\u{130}");
    assert_ne!(mapped("I", CaseMapping::Lower), "\u{131}");
    // The dotted capital I keeps its default lowercase mapping of i plus the combining dot above.
    assert_eq!(mapped("\u{130}", CaseMapping::Lower), "i\u{307}");
}

#[test]
fn case_mapping_is_total_and_noninvasive() {
    let value = admitted("\u{df}\u{130}\u{fb01}".as_bytes());
    let recorded = value.clone();
    assert_eq!(value.scalar_count(), 3);
    for mapping in CaseMapping::ALL {
        let _ = value.map_case(mapping);
        assert_eq!(value, recorded, "case mapping never modifies its input");
        assert_eq!(value.canonical_octets(), recorded.canonical_octets());
    }
    assert_eq!(rendered(&value.map_case(CaseMapping::Upper)), "SS\u{130}FI");
    assert_eq!(
        rendered(&value.map_case(CaseMapping::Lower)),
        "\u{df}i\u{307}\u{fb01}"
    );
    // A mapping is not a case fold: a fold would equate `ß` with `SS`, while the lowercase mapping
    // publishes `ß` unchanged and `SS` as `ss`.
    assert_eq!(mapped("\u{df}", CaseMapping::Lower), "\u{df}");
    assert_ne!(
        mapped("\u{df}", CaseMapping::Lower),
        mapped("SS", CaseMapping::Lower)
    );
}

#[test]
fn case_mapping_never_reduces_the_scalar_count() {
    // The pinned data publishes one or more scalars per mapped scalar, so the clause's count rule is
    // non-decreasing. The scan covers the basic multilingual plane and the astral blocks that carry
    // case mappings, plus a mixed value.
    let ranges = [
        (0x0000_u32, 0xFFFF_u32),
        (0x10400, 0x104FF),
        (0x1D400, 0x1D7FF),
        (0x1E900, 0x1E95F),
        (0x1F130, 0x1F149),
    ];
    for (start, end) in ranges {
        for code in start..=end {
            let Some(character) = char::from_u32(code) else {
                continue;
            };
            let text = character.to_string();
            let value = admitted(text.as_bytes());
            for mapping in CaseMapping::ALL {
                assert!(
                    value.map_case(mapping).scalar_count() >= value.scalar_count(),
                    "the `{}` mapping of U+{code:04X} never reduces the scalar count",
                    mapping.spelling()
                );
            }
        }
    }
    let mixed = admitted("\u{df}Gantry\u{130}".as_bytes());
    for mapping in CaseMapping::ALL {
        assert!(
            mixed.map_case(mapping).scalar_count() >= mixed.scalar_count(),
            "the `{}` mapping never reduces the scalar count of a value",
            mapping.spelling()
        );
    }
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn mapped(text: &str, mapping: CaseMapping) -> String {
    rendered(&admitted(text.as_bytes()).map_case(mapping))
}

fn rendered(value: &TextValue) -> String {
    String::from_utf8(value.canonical_octets().to_vec())
        .unwrap_or_else(|error| panic!("the canonical octets are UTF-8: {error}"))
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

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}
