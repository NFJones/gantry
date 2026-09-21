//! Public conformance for the canonical text normalization of
//! `GNT-41.2-canonical-text-normalization`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{NormalizationForm, TEXT_CLAUSES, TextValue};

/// The declared clauses of Section 41, written out independently of the model.
const EXPECTED_CLAUSES: [&str; 5] = [
    "GNT-41.0-text-foundation-scope",
    "GNT-41.1-canonical-text-values",
    "GNT-41.2-canonical-text-normalization",
    "GNT-41.3-canonical-text-case-mapping",
    "GNT-41.4-canonical-text-builders",
];
const NORMALIZATION_CLAUSE: &str = "GNT-41.2-canonical-text-normalization";
const SECTION_HEADING: &str = "## 41. Text Foundation";

#[test]
fn normalization_clause_publishes_the_two_canonical_forms() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    let forms = NormalizationForm::ALL.map(NormalizationForm::spelling);
    assert_eq!(forms, ["nfd", "nfc"]);
    let body = clause_body(&specification, NORMALIZATION_CLAUSE);
    // Each assertion is scoped to the phrase that declares the form, so an incidental mention of a
    // spelling elsewhere in the clause cannot satisfy it.
    for declaration in [
        "Normalization Form D, the canonical decomposition spelled `nfd`",
        "Normalization Form C, the canonical composition spelled `nfc`",
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
    ] {
        assert!(body.contains(citation), "the clause cites {citation}");
    }
}

#[test]
fn normalization_matches_the_pinned_unicode_data() {
    let composed = admitted("\u{e9}".as_bytes());
    let decomposed = admitted("e\u{301}".as_bytes());
    assert_eq!(composed.scalar_count(), 1);
    assert_eq!(decomposed.scalar_count(), 2);
    assert_ne!(
        composed, decomposed,
        "the spellings are distinct text values"
    );
    assert_eq!(decomposed.normalize(NormalizationForm::Nfc), composed);
    assert_eq!(composed.normalize(NormalizationForm::Nfd), decomposed);

    let syllable = admitted("\u{ac01}".as_bytes());
    let jamo = admitted("\u{1100}\u{1161}\u{11a8}".as_bytes());
    assert_eq!(syllable.normalize(NormalizationForm::Nfd), jamo);
    assert_eq!(jamo.normalize(NormalizationForm::Nfc), syllable);

    let ascii = admitted(b"gantry");
    assert_eq!(ascii.normalize(NormalizationForm::Nfc), ascii);
    assert_eq!(ascii.normalize(NormalizationForm::Nfd), ascii);
    assert_eq!(
        TextValue::empty().normalize(NormalizationForm::Nfc),
        TextValue::empty()
    );
}

#[test]
fn normalization_is_total_idempotent_and_noninvasive() {
    let value = admitted("e\u{301}\u{ac01}\u{feff}".as_bytes());
    let recorded = value.clone();
    for form in NormalizationForm::ALL {
        let normalized = value.normalize(form);
        assert_eq!(value, recorded, "normalization never modifies its input");
        assert_eq!(value.canonical_octets(), recorded.canonical_octets());
        assert_eq!(
            normalized.normalize(form),
            normalized,
            "the `{}` form is idempotent",
            form.spelling()
        );
    }
    let decomposed = value.normalize(NormalizationForm::Nfd);
    let composed = value.normalize(NormalizationForm::Nfc);
    assert_eq!(
        composed.scalar_count(),
        3,
        "the composed form holds the mark, the syllable, and the mark"
    );
    assert_eq!(
        decomposed.scalar_count(),
        6,
        "the decomposed form expands the mark and the syllable"
    );
    assert_ne!(composed, decomposed);
    assert_eq!(composed.normalize(NormalizationForm::Nfd), decomposed);
}

#[test]
fn admission_still_preserves_octets_exactly() {
    let decomposed = "e\u{301}".as_bytes();
    let value = admitted(decomposed);
    assert_eq!(value.canonical_octets(), decomposed);
    assert_eq!(value.scalar_count(), 2);
    assert_ne!(value, value.normalize(NormalizationForm::Nfc));
}

/// Every anchor Section 41 cites resolves to an anchor the specification declares.
#[test]
fn section_41_citations_resolve_to_declared_anchors() {
    let specification = read_workspace_file("SPEC.md");
    let declared = declared_anchors(&specification);
    let cited = citations(section_text(&specification, SECTION_HEADING));
    for required in [
        "GNT-4.12",
        "GNT-5.16",
        "GNT-41.1-canonical-text-values",
        "GNT-35.6-char-values-and-unicode-scalars",
        "GNT-35.7-bytes-and-canonical-encoding",
    ] {
        assert!(cited.contains(required), "the section cites `{required}`");
    }
    for anchor in cited {
        assert!(
            declared.contains(&anchor),
            "the section cites the declared anchor `{anchor}`"
        );
    }
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
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

fn section_text<'a>(specification: &'a str, heading: &str) -> &'a str {
    let start = specification
        .find(heading)
        .unwrap_or_else(|| panic!("the specification declares `{heading}`"));
    let rest = &specification[start..];
    match rest[1..].find("\n## ") {
        Some(end) => &rest[..end + 1],
        None => rest,
    }
}

fn declared_anchors(specification: &str) -> BTreeSet<String> {
    let mut anchors = BTreeSet::new();
    let mut rest = specification;
    while let Some(start) = rest.find("<a id=\"") {
        let after = &rest[start + "<a id=\"".len()..];
        let Some(end) = after.find('"') else { break };
        anchors.insert(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    anchors
}

fn citations(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find("`GNT-") {
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else { break };
        let token = &after[..end];
        if token.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        }) {
            found.insert(token.to_owned());
        }
        rest = &after[end + 1..];
    }
    found
}

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}
