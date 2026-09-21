//! Public conformance for the canonical text conversions of
//! `GNT-41.9-canonical-text-conversions`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{TEXT_CLAUSES, TextDiagnosticCode, TextError, TextValue};

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
const CONVERSION_CLAUSE: &str = "GNT-41.9-canonical-text-conversions";

#[test]
fn conversions_clause_publishes_the_declared_exact_conversions() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    assert_eq!(
        TextDiagnosticCode::InvalidUtf16.spelling(),
        "text-invalid-utf16"
    );
    assert_eq!(
        TextDiagnosticCode::InvalidUtf16.owning_clause(),
        CONVERSION_CLAUSE
    );
    let body = clause_body(&specification, CONVERSION_CLAUSE);
    for declaration in [
        "`from_utf16_code_units` admits one UTF-16 code-unit sequence as a text value",
        "`utf16_code_units` publishes the canonical UTF-16 code units of a text value",
        "`from_lossless_octets` publishes a text value from an octet sequence under the declared",
        "`lossless_octets` publishes the octets of a text value under that",
        "the mapping keeps every octet it was given",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    for citation in ["`GNT-41.1-canonical-text-values`", "`text-invalid-utf16`"] {
        assert!(body.contains(citation), "the clause cites {citation}");
    }
}

#[test]
fn conversions_publish_canonical_utf16_code_units() {
    let cases = [
        ("", Vec::new()),
        ("a", vec![0x0061]),
        ("é", vec![0x00E9]),
        ("😀", vec![0xD83D, 0xDE00]),
        ("aé😀", vec![0x0061, 0x00E9, 0xD83D, 0xDE00]),
        ("\u{10FFFF}", vec![0xDBFF, 0xDFFF]),
    ];
    for (text, expected) in cases {
        let value = admitted(text.as_bytes());
        assert_eq!(
            value.utf16_code_units(),
            expected,
            "the canonical UTF-16 form of `{text}`"
        );
        let round_tripped = TextValue::from_utf16_code_units(&expected)
            .unwrap_or_else(|error| panic!("the canonical form of `{text}` is admitted: {error}"));
        assert_eq!(
            round_tripped, value,
            "`{text}` survives a UTF-16 round trip"
        );
        assert_eq!(round_tripped.scalar_count(), value.scalar_count());
    }
    let pair = TextValue::from_utf16_code_units(&[0xD83D, 0xDE00])
        .unwrap_or_else(|error| panic!("a surrogate pair is admitted: {error}"));
    assert_eq!(pair.canonical_octets(), "😀".as_bytes());
}

#[test]
fn conversions_refuse_unpaired_utf16_surrogates() {
    for (units, index) in [
        (vec![0xD83D], 0_usize),
        (vec![0x0061, 0xDE00], 1),
        (vec![0xD83D, 0x0061], 0),
        (vec![0x0061, 0xD83D], 1),
    ] {
        let error = refusal(
            TextValue::from_utf16_code_units(&units),
            TextDiagnosticCode::InvalidUtf16,
        );
        assert!(
            error.detail().contains(&format!("code unit {index}")),
            "the refusal names code unit {index}: {}",
            error.detail()
        );
    }
    let empty = TextValue::from_utf16_code_units(&[])
        .unwrap_or_else(|error| panic!("the empty sequence is admitted: {error}"));
    assert_eq!(empty, TextValue::empty());
}

#[test]
fn conversions_map_octets_losslessly() {
    let octets = [0x00_u8, 0x41, 0x7F, 0x80, 0xC3, 0xFF];
    let value = TextValue::from_lossless_octets(&octets)
        .unwrap_or_else(|error| panic!("the octet sequence is admitted: {error}"));
    assert_eq!(value.scalar_count(), octets.len());
    assert_eq!(value.lossless_octets(), Some(octets.to_vec()));
    assert_eq!(
        TextValue::from_lossless_octets(&octets)
            .unwrap_or_else(|error| panic!("the octet sequence is admitted: {error}"))
            .lossless_octets(),
        Some(octets.to_vec()),
        "the mapping round-trips deterministically"
    );
    assert_eq!(
        TextValue::from_lossless_octets(&[])
            .unwrap_or_else(|error| panic!("the empty octet sequence is admitted: {error}")),
        TextValue::empty()
    );
    assert_eq!(
        TextValue::from_lossless_octets(&[0xE9])
            .unwrap_or_else(|error| panic!("the octet sequence is admitted: {error}"))
            .lossless_octets(),
        Some(vec![0xE9])
    );
    assert_eq!(admitted(b"ab").lossless_octets(), Some(b"ab".to_vec()));
    assert_eq!(
        admitted("€".as_bytes()).lossless_octets(),
        None,
        "a scalar with no octet publishes nothing"
    );
    assert_eq!(admitted("😀".as_bytes()).lossless_octets(), None);
}

#[test]
fn conversions_are_observation_only_and_deterministic() {
    let value = admitted("aé😀".as_bytes());
    let recorded = value.canonical_octets().to_vec();
    let units = value.utf16_code_units();
    assert_eq!(
        units,
        value.utf16_code_units(),
        "the conversion is deterministic"
    );
    assert_eq!(value.canonical_octets(), recorded.as_slice());
    let restored = TextValue::from_utf16_code_units(&units)
        .unwrap_or_else(|error| panic!("the canonical form is admitted: {error}"));
    assert_eq!(restored, value);
    assert_eq!(restored.canonical_octets(), recorded.as_slice());
    let from_octets = TextValue::from_lossless_octets(recorded.as_slice())
        .unwrap_or_else(|error| panic!("the octet sequence is admitted: {error}"));
    assert_eq!(
        from_octets.canonical_octets(),
        TextValue::from_lossless_octets(recorded.as_slice())
            .unwrap_or_else(|error| panic!("the octet sequence is admitted: {error}"))
            .canonical_octets()
    );
    assert_eq!(value.canonical_octets(), recorded.as_slice());
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn refusal<T>(result: Result<T, TextError>, code: TextDiagnosticCode) -> TextError {
    match result {
        Ok(_) => panic!("the call is refused under `{}`", code.spelling()),
        Err(error) => {
            assert_eq!(
                error.code(),
                code,
                "the refusal is reported under `{}`: {}",
                code.spelling(),
                error.detail()
            );
            error
        }
    }
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
