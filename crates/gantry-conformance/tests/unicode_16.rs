//! Independent checks of the vendored and generated Unicode 16 contract.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::unicode::{
    UNICODE_VERSION, confusable_skeleton, is_identifier_recommended,
    is_identifier_security_excluded, is_nfc, is_white_space, is_xid_continue, is_xid_start,
    normalize_nfc, normalize_nfd, push_full_lowercase, push_full_uppercase, script,
    script_extensions, to_full_lowercase, to_full_uppercase,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionVectors {
    format: String,
    unicode_version: [u8; 3],
    cases: Vec<VersionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionCase {
    code_point: String,
    property: String,
    unicode_15_1: bool,
    unicode_16_0: bool,
    unicode_17_0: bool,
}

#[test]
fn vendored_unicode_inputs_match_the_reviewed_manifest() {
    let root = unicode_root();
    let manifest = read_text(&root.join("SHA256SUMS"));
    let mut checked = 0_usize;
    for line in manifest.lines() {
        let pair = line.split_once("  ");
        assert!(pair.is_some(), "malformed SHA256SUMS row");
        let (expected, relative) = pair.unwrap_or_else(|| unreachable!("checked above"));
        let bytes = fs::read(root.join(relative));
        assert!(bytes.is_ok(), "could not read {relative}");
        let digest = bytes
            .map(|value| format!("{:x}", Sha256::digest(value)))
            .unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(digest, expected, "hash mismatch for {relative}");
        checked += 1;
    }
    assert_eq!(checked, 15);
    assert!(read_text(&root.join("ucd/ReadMe.txt")).contains("Version 16.0.0"));
    assert!(read_text(&root.join("security/confusables.txt")).contains("# Version: 16.0.0"));
}

#[test]
fn archived_unicode_16_normalization_suite_passes() {
    let text = read_text(&unicode_root().join("ucd/NormalizationTest.txt"));
    let mut rows = 0_usize;
    for line in text.lines() {
        let body = line.split('#').next().unwrap_or_default().trim();
        if body.is_empty() || body.starts_with('@') {
            continue;
        }
        let fields = body.split(';').take(5).collect::<Vec<_>>();
        assert_eq!(fields.len(), 5, "malformed normalization row");
        let c1 = decode_code_points(fields[0]);
        let c2 = decode_code_points(fields[1]);
        let c3 = decode_code_points(fields[2]);
        let c4 = decode_code_points(fields[3]);
        let c5 = decode_code_points(fields[4]);

        assert_eq!(normalize_nfc(&c1), c2);
        assert_eq!(normalize_nfc(&c2), c2);
        assert_eq!(normalize_nfc(&c3), c2);
        assert_eq!(normalize_nfc(&c4), c4);
        assert_eq!(normalize_nfc(&c5), c4);
        assert_eq!(normalize_nfd(&c1), c3);
        assert_eq!(normalize_nfd(&c2), c3);
        assert_eq!(normalize_nfd(&c3), c3);
        assert_eq!(normalize_nfd(&c4), c5);
        assert_eq!(normalize_nfd(&c5), c5);
        rows += 1;
    }
    assert!(rows > 19_000, "normalization corpus was unexpectedly small");
}

#[test]
fn unicode_16_properties_and_version_boundaries_are_pinned() {
    let vectors: VersionVectors =
        read_json(&protocol_root().join("goldens/unicode-version-vectors-v1.json"));
    assert_eq!(vectors.format, "gantry.unicode-version-vectors/v1");
    assert_eq!(vectors.unicode_version, [16, 0, 0]);
    assert_eq!(UNICODE_VERSION, (16, 0, 0));

    let mut covers_15_1_to_16_0 = false;
    let mut covers_16_0_to_17_0 = false;
    for case in vectors.cases {
        let character = decode_code_point(&case.code_point);
        let actual = match case.property.as_str() {
            "XID_Start" => is_xid_start(character),
            "XID_Continue" => is_xid_continue(character),
            other => panic!("unknown version-vector property {other}"),
        };
        assert_eq!(actual, case.unicode_16_0, "{}", case.code_point);
        covers_15_1_to_16_0 |= case.unicode_15_1 != case.unicode_16_0;
        covers_16_0_to_17_0 |= case.unicode_16_0 != case.unicode_17_0;
    }
    assert!(covers_15_1_to_16_0, "missing Unicode 15.1 boundary vector");
    assert!(covers_16_0_to_17_0, "missing Unicode 17.0 boundary vector");

    assert!(is_white_space('\u{2003}'));
    assert!(is_identifier_security_excluded('\u{200D}'));
    assert!(is_identifier_recommended('A'));
    assert!(is_nfc("À"));
    assert_eq!(script('A').short_name(), "Latn");
    assert!(
        script_extensions('\u{00B7}')
            .iter()
            .any(|value| value.short_name() == "Latn")
    );
    assert_eq!(confusable_skeleton("раypal"), "paypal");
}

#[test]
fn full_default_case_mappings_are_generated() {
    let mut lower = String::new();
    push_full_lowercase('İ', &mut lower);
    assert_eq!(lower, "i\u{0307}");
    let mut upper = String::new();
    push_full_uppercase('ß', &mut upper);
    assert_eq!(upper, "SS");
    assert_eq!(to_full_lowercase("ΟΣ"), "ος");
    assert_eq!(to_full_lowercase("ΟΣΑ"), "οσα");
    assert_eq!(to_full_lowercase("ΟΣ\u{0301}"), "ος\u{0301}");
    assert_eq!(to_full_uppercase("Straße"), "STRASSE");
}

fn decode_code_point(value: &str) -> char {
    let hexadecimal = value.strip_prefix("U+");
    assert!(hexadecimal.is_some(), "invalid code-point fixture");
    let code = hexadecimal.and_then(|value| u32::from_str_radix(value, 16).ok());
    assert!(code.is_some(), "invalid code-point fixture");
    code.and_then(char::from_u32)
        .unwrap_or_else(|| unreachable!("fixture is a Unicode scalar"))
}

fn decode_code_points(value: &str) -> String {
    value
        .split_whitespace()
        .map(|code| {
            let parsed = u32::from_str_radix(code, 16);
            assert!(parsed.is_ok(), "invalid normalization scalar");
            parsed
                .ok()
                .and_then(char::from_u32)
                .unwrap_or_else(|| unreachable!("normalization fixture contains scalars"))
        })
        .collect()
}

fn unicode_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/unicode/16.0.0")
}

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol")
}

fn read_text(path: &Path) -> String {
    let value = fs::read_to_string(path);
    assert!(value.is_ok(), "could not read {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
