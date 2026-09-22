//! Public-facade conformance for the `GNT-42.0`-`GNT-42.5` codec foundation and hex, base64,
//! binary, and dynamic JSON codecs.
//!
//! The section declares the `std.codec` family, its five module items, the versioned codec
//! identity and its exact admission rule, the frozen refusal vocabulary with its codec categories
//! of `GNT-29.9-codec-contract`, the canonical hex, base64, binary, and dynamic JSON codecs of
//! `GNT-42.2-hex-codec`, `GNT-42.3-base64-codec`,
//! `GNT-42.4-binary-endian-readers-and-writers`, and `GNT-42.5-bounded-dynamic-json`, and the
//! separation between application codecs and the sealed canonical boundary and durable recovery
//! projections: these lanes require every declared clause, module row, refusal, and category to
//! be published in the specification and the model, and exercise the version-admission rule and
//! the hex, base64, binary, and dynamic JSON codecs' canonical forms, bounds, and refusals
//! directly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    BASE64_TEXT_OCTET_BOUND, BASE64_VALUE_OCTET_BOUND, BINARY_VALUE_OCTET_BOUND, CODEC_CLAUSES,
    CODEC_ITEMS, CodecCategory, CodecDiagnosticCode, CodecError, CodecKind, CodecVersion,
    DECLARED_CODEC_VERSION, Endian, HEX_TEXT_OCTET_BOUND, HEX_VALUE_OCTET_BOUND, JSON_DEPTH_BOUND,
    JSON_NODE_BOUND, JSON_TEXT_OCTET_BOUND, JsonValue, NameClass, PackageFamily, StabilityTier,
    base64_decode, base64_encode, canonical_codec_hierarchy, canonical_pure_hierarchy, hex_decode,
    hex_encode, json_decode, json_encode, read_u16, read_u32, read_u64, write_u16, write_u32,
    write_u64,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

#[test]
fn section_42_clauses_are_published() {
    let spec = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(CODEC_CLAUSES.len(), 6);
    let mut prior = 0_usize;
    for clause in CODEC_CLAUSES {
        let anchor = format!("<a id=\"{clause}\"></a>");
        let position = spec
            .find(&anchor)
            .unwrap_or_else(|| panic!("{clause} is not published"));
        assert!(
            position > prior,
            "the clauses appear in specification order"
        );
        prior = position;
        assert!(
            spec.contains(&format!("**[{clause}] ")),
            "{clause} carries no clause text"
        );
    }
    let scope = &spec[spec
        .find(&format!("<a id=\"{}\"></a>", CODEC_CLAUSES[0]))
        .unwrap_or_else(|| panic!("the scope anchor is published"))..];
    for term in [
        "`std.codec`",
        "`base64`",
        "`binary`",
        "`compression`",
        "`hex`",
        "`json`",
        "`codec-unsupported-version`",
        "`codec-malformed-input`",
        "`codec-expansion-limit`",
        "`GNT-29.9-codec-contract`",
        "`GNT-3-D-REFINEMENT`",
    ] {
        assert!(scope.contains(term), "the section must name {term}");
    }
}

#[test]
fn codec_surface_declares_the_five_modules() {
    let aggregate = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error:?}"));
    let owner = PackageFamily::Codec.package_name();
    assert_eq!(
        aggregate
            .package(&owner)
            .unwrap_or_else(|| panic!("the aggregate hierarchy declares `{owner}`"))
            .items()
            .len(),
        0,
        "the aggregate constructor declares no family item"
    );
    let graph = canonical_codec_hierarchy()
        .unwrap_or_else(|error| panic!("the family hierarchy is declared: {error:?}"));
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the hierarchy declares `{owner}`"));
    assert_eq!(CODEC_ITEMS.len(), CodecKind::ALL.len());
    let mut expected = CodecKind::ALL
        .iter()
        .map(|kind| format!("std.codec.{}", kind.wire_name()))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(
        package.items().keys().cloned().collect::<Vec<_>>(),
        expected,
        "the family declares exactly one module item per declared codec"
    );
    for (row, kind) in CODEC_ITEMS.iter().zip(CodecKind::ALL) {
        assert_eq!(row.kind, kind);
        assert_eq!(
            row.name,
            format!("std.codec::{}", kind.wire_name()),
            "the item name is the canonical module name of its codec"
        );
        assert_eq!(row.name, kind.module_name());
        assert_eq!(row.class, NameClass::Module, "`{}` is a module", row.name);
        assert_eq!(row.tier, StabilityTier::Stable, "`{}` is stable", row.name);
        let base64_expected = [CODEC_CLAUSES[0], CODEC_CLAUSES[1], CODEC_CLAUSES[3]];
        let binary_expected = [CODEC_CLAUSES[0], CODEC_CLAUSES[1], CODEC_CLAUSES[4]];
        let json_expected = [CODEC_CLAUSES[0], CODEC_CLAUSES[1], CODEC_CLAUSES[5]];
        let expected: &[&str] = match kind {
            CodecKind::Hex => &CODEC_CLAUSES[..3],
            CodecKind::Base64 => &base64_expected[..],
            CodecKind::Binary => &binary_expected[..],
            CodecKind::Json => &json_expected[..],
            _ => &CODEC_CLAUSES[..2],
        };
        assert_eq!(
            row.clauses, expected,
            "`{}` publishes exactly the clauses that publish facts about its surface",
            row.name
        );
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("`{}` is declared", row.name));
        assert_eq!(item.class(), NameClass::Module);
        assert_eq!(item.tier(), StabilityTier::Stable);
    }
    for kind in CodecKind::ALL {
        assert_eq!(CodecKind::from_module_name(kind.module_name()), Some(kind));
    }
    assert!(CodecKind::from_module_name("std.codec::other").is_none());
    assert!(CodecKind::from_module_name("std.collections::map").is_none());
}

#[test]
fn declared_versions_admit_exactly_the_declared_identity() {
    assert_eq!(DECLARED_CODEC_VERSION, 1);
    for kind in CodecKind::ALL {
        let declared = CodecVersion::declared(kind);
        assert_eq!(declared, kind.declared_version());
        assert_eq!(declared.kind(), kind);
        assert_eq!(declared.version(), DECLARED_CODEC_VERSION);
        assert_eq!(
            declared.canonical_identity(),
            format!("{}@{}", kind.module_name(), DECLARED_CODEC_VERSION)
        );
        assert_eq!(
            CodecVersion::admit(&declared.canonical_identity()),
            Ok(declared)
        );
        for version in [0_u16, 2_u16] {
            let presented = format!("{}@{version}", kind.module_name());
            let error = match CodecVersion::admit(&presented) {
                Ok(identity) => panic!(
                    "`{presented}` must be refused, got `{}`",
                    identity.canonical_identity()
                ),
                Err(error) => error,
            };
            assert_eq!(error.code(), CodecDiagnosticCode::UnsupportedVersion);
            assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
            assert_eq!(error.category(), CodecCategory::Decode);
            assert!(error.detail().contains(&presented), "{}", error.detail());
            assert!(
                error.detail().contains(kind.module_name()),
                "{}",
                error.detail()
            );
        }
    }
    assert_eq!(
        CodecVersion::admit("std.codec::hex@1").map(|identity| identity.canonical_identity()),
        Ok("std.codec::hex@1".to_owned())
    );
    // A parseable but noncanonical version spelling is not the declared identity.
    for (presented, declared_identity) in [
        ("std.codec::hex@01", "std.codec::hex@1"),
        ("std.codec::hex@+1", "std.codec::hex@1"),
        ("std.codec::base64@0001", "std.codec::base64@1"),
    ] {
        let error = match CodecVersion::admit(presented) {
            Ok(identity) => panic!(
                "`{presented}` must be refused, got `{}`",
                identity.canonical_identity()
            ),
            Err(error) => error,
        };
        assert_eq!(error.code(), CodecDiagnosticCode::UnsupportedVersion);
        assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
        assert_eq!(error.category(), CodecCategory::Decode);
        assert!(error.detail().contains(presented), "{}", error.detail());
        assert!(
            error.detail().contains(declared_identity),
            "the refusal names the declared identity: {}",
            error.detail()
        );
    }
    for presented in ["std.codec::other@1", "std.codec::hex", "not-an-identity"] {
        let error = match CodecVersion::admit(presented) {
            Ok(identity) => panic!(
                "`{presented}` must be refused, got `{}`",
                identity.canonical_identity()
            ),
            Err(error) => error,
        };
        assert_eq!(error.code(), CodecDiagnosticCode::UnsupportedVersion);
        assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
        assert_eq!(error.category(), CodecCategory::Decode);
        assert!(
            error.detail().contains(presented),
            "the refusal names the observed identity: {}",
            error.detail()
        );
        assert!(
            error.detail().contains("std.codec::base64"),
            "the refusal names the declared set: {}",
            error.detail()
        );
    }
}

#[test]
fn refusals_are_frozen_and_classified() {
    let mut prior: Option<&str> = None;
    let mut spellings = BTreeSet::new();
    for code in CodecDiagnosticCode::ALL {
        let spelling = code.as_str();
        if let Some(previous) = prior {
            assert!(
                previous < spelling,
                "the refusal registry is sorted: {previous} then {spelling}"
            );
        }
        prior = Some(spelling);
        assert!(
            spellings.insert(spelling),
            "one distinct spelling per refusal"
        );
        assert!(
            !code.meaning().is_empty(),
            "every refusal publishes a meaning"
        );
        assert_eq!(code.requirement(), CODEC_CLAUSES[1]);
        assert!(CODEC_CLAUSES.contains(&code.requirement()));
    }
    assert_eq!(spellings.len(), CodecDiagnosticCode::ALL.len());
    assert_eq!(
        CodecDiagnosticCode::UnsupportedVersion.category(),
        CodecCategory::Decode
    );
    assert_eq!(
        CodecDiagnosticCode::MalformedInput.category(),
        CodecCategory::MalformedInput
    );
    assert_eq!(
        CodecDiagnosticCode::ExpansionLimit.category(),
        CodecCategory::ResourceLimit
    );
    let error = CodecError::new(CodecDiagnosticCode::MalformedInput, "octet 3");
    assert_eq!(error.code(), CodecDiagnosticCode::MalformedInput);
    assert_eq!(error.code().as_str(), "codec-malformed-input");
    assert_eq!(error.detail(), "octet 3");
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::MalformedInput);
    let mut wire_spellings = BTreeSet::new();
    for category in CodecCategory::ALL {
        assert!(
            wire_spellings.insert(category.wire_name()),
            "one wire spelling per codec category"
        );
        assert_eq!(
            CodecCategory::from_wire_name(category.wire_name()),
            Some(category)
        );
    }
    assert!(CodecCategory::from_wire_name("not-a-category").is_none());
}

#[test]
fn hex_codec_encodes_and_decodes_canonical_forms() {
    let vectors: [(&[u8], &str); 6] = [
        (&[], ""),
        (&[0x00], "00"),
        (&[0x0f], "0f"),
        (&[0xf0], "f0"),
        (&[0xde, 0xad, 0xbe, 0xef], "deadbeef"),
        (&[0x00, 0x7f, 0x80, 0xff], "007f80ff"),
    ];
    for (octets, text) in vectors {
        assert_eq!(hex_encode(octets), Ok(text.to_owned()));
        assert_eq!(hex_decode(text), Ok(octets.to_vec()));
        let encoded = match hex_encode(octets) {
            Ok(encoded) => encoded,
            Err(error) => panic!(
                "the declared value bound admits every vector: {}",
                error.detail()
            ),
        };
        let decoded = match hex_decode(&encoded) {
            Ok(decoded) => decoded,
            Err(error) => panic!("an encode result is admitted text: {}", error.detail()),
        };
        assert_eq!(
            decoded.as_slice(),
            octets,
            "decode of encode publishes the same octets"
        );
        let admitted = match hex_decode(text) {
            Ok(admitted) => admitted,
            Err(error) => panic!("the vector text is admitted: {}", error.detail()),
        };
        let spelled = match hex_encode(&admitted) {
            Ok(spelled) => spelled,
            Err(error) => panic!("a decoded vector is within the bound: {}", error.detail()),
        };
        assert_eq!(
            spelled, text,
            "encode of decode publishes the same text, digit for digit"
        );
    }
    let bound_octets = vec![0xab; HEX_VALUE_OCTET_BOUND];
    let encoded = match hex_encode(&bound_octets) {
        Ok(encoded) => encoded,
        Err(error) => panic!(
            "the declared value bound admits its encode: {}",
            error.detail()
        ),
    };
    assert_eq!(encoded.len(), HEX_TEXT_OCTET_BOUND);
    assert_eq!(hex_decode(&encoded), Ok(bound_octets));
}

#[test]
fn hex_codec_refuses_malformed_and_oversized_input() {
    for (presented, index) in [
        ("0", 0_usize),
        ("abc", 2),
        ("0g", 1),
        ("AB", 0),
        ("0x00", 1),
        ("00 11", 2),
    ] {
        let error = match hex_decode(presented) {
            Ok(value) => panic!("`{presented}` must be refused, got {value:?}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), CodecDiagnosticCode::MalformedInput);
        assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
        assert_eq!(error.category(), CodecCategory::MalformedInput);
        assert!(
            error.detail().contains(&format!("index {index}")),
            "the refusal names the departure index: {}",
            error.detail()
        );
    }
    let oversized_text = "00".repeat(HEX_VALUE_OCTET_BOUND + 1);
    let error = match hex_decode(&oversized_text) {
        Ok(value) => panic!("the oversized text must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::ResourceLimit);
    assert!(
        error.detail().contains(&oversized_text.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&HEX_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let ill_formed_and_oversized = "z".repeat(HEX_TEXT_OCTET_BOUND + 2);
    let error = match hex_decode(&ill_formed_and_oversized) {
        Ok(value) => panic!("the over-long text must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    let oversized_octets = vec![0_u8; HEX_VALUE_OCTET_BOUND + 1];
    let error = match hex_encode(&oversized_octets) {
        Ok(value) => panic!("the oversized input must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::ResourceLimit);
    assert!(
        error.detail().contains(&oversized_octets.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&HEX_VALUE_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
}

#[test]
fn base64_codec_encodes_and_decodes_canonical_forms() {
    let vectors: [(&[u8], &str); 7] = [
        (&[], ""),
        (&[0x00], "AA=="),
        (&[0xff], "/w=="),
        (&[0xde, 0xad], "3q0="),
        (&[0xde, 0xad, 0xbe], "3q2+"),
        (&[0xde, 0xad, 0xbe, 0xef], "3q2+7w=="),
        (&[0x00, 0x7f, 0x80, 0xff], "AH+A/w=="),
    ];
    for (octets, text) in vectors {
        assert_eq!(base64_encode(octets), Ok(text.to_owned()));
        assert_eq!(base64_decode(text), Ok(octets.to_vec()));
        let encoded = match base64_encode(octets) {
            Ok(encoded) => encoded,
            Err(error) => panic!(
                "the declared value bound admits every vector: {}",
                error.detail()
            ),
        };
        let decoded = match base64_decode(&encoded) {
            Ok(decoded) => decoded,
            Err(error) => panic!("an encode result is admitted text: {}", error.detail()),
        };
        assert_eq!(
            decoded.as_slice(),
            octets,
            "decode of encode publishes the same octets"
        );
        let admitted = match base64_decode(text) {
            Ok(admitted) => admitted,
            Err(error) => panic!("the vector text is admitted: {}", error.detail()),
        };
        let spelled = match base64_encode(&admitted) {
            Ok(spelled) => spelled,
            Err(error) => panic!("a decoded vector is within the bound: {}", error.detail()),
        };
        assert_eq!(
            spelled, text,
            "encode of decode publishes the same text, symbol for symbol"
        );
    }
    let bound_octets = vec![0xab; BASE64_VALUE_OCTET_BOUND];
    let encoded = match base64_encode(&bound_octets) {
        Ok(encoded) => encoded,
        Err(error) => panic!(
            "the declared value bound admits its encode: {}",
            error.detail()
        ),
    };
    assert_eq!(encoded.len(), BASE64_TEXT_OCTET_BOUND);
    assert_eq!(base64_decode(&encoded), Ok(bound_octets));
}

#[test]
fn base64_codec_refuses_malformed_and_oversized_input() {
    for (presented, index) in [
        ("A", 1_usize),
        ("AA", 2),
        ("AAA", 3),
        ("AAAAA", 5),
        ("AA=", 2),
        ("A===", 1),
        ("=AAA", 0),
        ("AAAA=", 4),
        ("AB==", 1),
        ("ABC=", 2),
        ("AA=A", 2),
        ("AA_A", 2),
        ("AB CD", 2),
        ("AAAA=!", 4),
        ("A=!A", 1),
    ] {
        let error = match base64_decode(presented) {
            Ok(value) => panic!("`{presented}` must be refused, got {value:?}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), CodecDiagnosticCode::MalformedInput);
        assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
        assert_eq!(error.category(), CodecCategory::MalformedInput);
        assert!(
            error.detail().contains(&format!("index {index}")),
            "the refusal names the departure index: {}",
            error.detail()
        );
    }
    let oversized_text = "A".repeat(BASE64_TEXT_OCTET_BOUND + 4);
    let error = match base64_decode(&oversized_text) {
        Ok(value) => panic!("the oversized text must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::ResourceLimit);
    assert!(
        error.detail().contains(&oversized_text.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&BASE64_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let ill_formed_and_oversized = "!".repeat(BASE64_TEXT_OCTET_BOUND + 4);
    let error = match base64_decode(&ill_formed_and_oversized) {
        Ok(value) => panic!("the over-long text must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    let oversized_octets = vec![0_u8; BASE64_VALUE_OCTET_BOUND + 1];
    let error = match base64_encode(&oversized_octets) {
        Ok(value) => panic!("the oversized input must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::ResourceLimit);
    assert!(
        error.detail().contains(&oversized_octets.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&BASE64_VALUE_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
}

#[test]
fn binary_codec_reads_and_writes_canonical_forms() {
    let octets = [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(read_u16(Endian::Big, &octets, 0), Ok(0x0102));
    assert_eq!(read_u16(Endian::Little, &octets, 0), Ok(0x0201));
    assert_eq!(read_u16(Endian::Big, &octets, 6), Ok(0x0708));
    assert_eq!(read_u32(Endian::Big, &octets, 2), Ok(0x0304_0506));
    assert_eq!(read_u32(Endian::Little, &octets, 2), Ok(0x0605_0403));
    assert_eq!(read_u64(Endian::Big, &octets, 0), Ok(0x0102_0304_0506_0708));
    assert_eq!(
        read_u64(Endian::Little, &octets, 0),
        Ok(0x0807_0605_0403_0201)
    );
    assert_eq!(write_u16(Endian::Big, 0x0102), [0x01, 0x02]);
    assert_eq!(write_u16(Endian::Little, 0x0102), [0x02, 0x01]);
    assert_eq!(
        write_u32(Endian::Big, 0x0102_0304),
        [0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(
        write_u32(Endian::Little, 0x0102_0304),
        [0x04, 0x03, 0x02, 0x01]
    );
    assert_eq!(
        write_u64(Endian::Big, 0x0102_0304_0506_0708),
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        write_u64(Endian::Little, 0x0102_0304_0506_0708),
        [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
    for endian in Endian::ALL {
        assert_eq!(Endian::from_wire_name(endian.wire_name()), Some(endian));
        let value = match read_u16(endian, &octets, 2) {
            Ok(value) => value,
            Err(error) => panic!("the window is held: {}", error.detail()),
        };
        assert_eq!(write_u16(endian, value), octets[2..4]);
        let wide = match read_u64(endian, &octets, 0) {
            Ok(value) => value,
            Err(error) => panic!("the window is held: {}", error.detail()),
        };
        assert_eq!(write_u64(endian, wide), octets);
        let word = match read_u32(endian, &octets, 0) {
            Ok(value) => value,
            Err(error) => panic!("the window is held: {}", error.detail()),
        };
        assert_eq!(write_u32(endian, word), octets[0..4]);
    }
    assert_eq!(Endian::ALL.len(), 2);
    assert_eq!(Endian::from_wire_name("native"), None);
    assert_eq!(Endian::from_wire_name("Big"), None);
    let bound_octets = vec![0_u8; BINARY_VALUE_OCTET_BOUND];
    assert_eq!(
        read_u64(Endian::Big, &bound_octets, BINARY_VALUE_OCTET_BOUND - 8),
        Ok(0)
    );
}

#[test]
fn binary_codec_refuses_truncated_and_oversized_sequences() {
    let octets = [0x00_u8; 4];
    let truncation_cases: [(Option<CodecError>, usize); 5] = [
        (read_u16(Endian::Big, &octets, 3).err(), 4),
        (read_u16(Endian::Little, &octets, 4).err(), 4),
        (read_u16(Endian::Big, &octets, 9).err(), 9),
        (read_u32(Endian::Big, &octets, 1).err(), 4),
        (read_u64(Endian::Little, &octets, 0).err(), 4),
    ];
    for (refusal, index) in truncation_cases {
        let error = match refusal {
            Some(error) => error,
            None => panic!("the window at departure index {index} must be refused"),
        };
        assert_eq!(error.code(), CodecDiagnosticCode::MalformedInput);
        assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
        assert_eq!(error.category(), CodecCategory::MalformedInput);
        assert!(
            error
                .detail()
                .contains(&format!("first octet index it does not hold is {index}")),
            "the refusal names the departure index: {}",
            error.detail()
        );
    }
    let oversized = vec![0_u8; BINARY_VALUE_OCTET_BOUND + 1];
    let error = match read_u16(Endian::Big, &oversized, 0) {
        Ok(value) => panic!("the oversized sequence must be refused, got {value}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::ResourceLimit);
    assert!(
        error.detail().contains(&oversized.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&BINARY_VALUE_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
}

#[test]
fn json_codec_round_trips_the_compact_canonical_language() {
    let vectors: [&str; 12] = [
        "null",
        "true",
        "false",
        "0",
        "-1",
        "9223372036854775807",
        "-9223372036854775808",
        "\"text\"",
        "\"a\\nb\"",
        "\"\\u0000\"",
        "[1,2,3]",
        "{\"a\":1,\"b\":[true,null]}",
    ];
    for text in vectors {
        let value = match json_decode(text) {
            Ok(value) => value,
            Err(error) => panic!("`{text}` is admitted: {}", error.detail()),
        };
        let encoded = match json_encode(&value) {
            Ok(encoded) => encoded,
            Err(error) => panic!("a decoded vector encodes: {}", error.detail()),
        };
        assert_eq!(encoded, text, "encode of decode publishes the same text");
        let round_trip = match json_decode(&encoded) {
            Ok(value) => value,
            Err(error) => panic!("an encode result is admitted: {}", error.detail()),
        };
        assert_eq!(
            round_trip, value,
            "decode of encode publishes the same value"
        );
    }
    let value = JsonValue::Object(vec![
        ("a".to_owned(), JsonValue::Integer(1)),
        (
            "b".to_owned(),
            JsonValue::Array(vec![JsonValue::Bool(true), JsonValue::Null]),
        ),
    ]);
    let encoded = match json_encode(&value) {
        Ok(encoded) => encoded,
        Err(error) => panic!("the declared value encodes: {}", error.detail()),
    };
    assert_eq!(encoded, "{\"a\":1,\"b\":[true,null]}");
    assert_eq!(json_decode(&encoded), Ok(value));
    assert_eq!(JsonValue::Null.node_count(), 1);
    assert_eq!(JsonValue::Array(vec![JsonValue::Null; 3]).node_count(), 4);
    assert_eq!(
        JsonValue::Object(vec![("k".to_owned(), JsonValue::Null)]).node_count(),
        3
    );
    assert_eq!(JsonValue::Null.container_depth(), 0);
    assert_eq!(
        JsonValue::Array(vec![JsonValue::Array(vec![JsonValue::Null])]).container_depth(),
        2
    );
    let mut boundary = String::from("[");
    for position in 0..JSON_NODE_BOUND - 1 {
        if position > 0 {
            boundary.push(',');
        }
        boundary.push('0');
    }
    boundary.push(']');
    let decoded = match json_decode(&boundary) {
        Ok(value) => value,
        Err(error) => panic!(
            "the node bound admits its boundary value: {}",
            error.detail()
        ),
    };
    assert_eq!(decoded.node_count(), JSON_NODE_BOUND);
    assert_eq!(json_encode(&decoded), Ok(boundary));
}

#[test]
fn json_codec_refuses_noncanonical_and_oversized_input() {
    for (presented, index) in [
        ("", 0_usize),
        (" 1", 0),
        ("01", 1),
        ("-0", 1),
        ("+1", 0),
        ("1.", 1),
        ("1e3", 1),
        ("9223372036854775808", 0),
        ("-9223372036854775809", 0),
        ("[1,2", 4),
        ("[1 2]", 2),
        ("[1,]", 3),
        ("{\"a\":1,\"a\":2}", 7),
        ("{\"a\" 1}", 4),
        ("nul", 3),
        ("\"a\\/b\"", 3),
        ("\"\\u0041\"", 5),
        ("\"\\u001F\"", 6),
        ("\"a\nb\"", 2),
    ] {
        let error = match json_decode(presented) {
            Ok(value) => panic!("`{presented}` must be refused, got {value:?}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), CodecDiagnosticCode::MalformedInput);
        assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
        assert_eq!(error.category(), CodecCategory::MalformedInput);
        assert!(
            error.detail().contains(&format!("index {index}")),
            "the refusal names the departure index: {}",
            error.detail()
        );
    }
    let oversized_text = "0".repeat(JSON_TEXT_OCTET_BOUND + 1);
    let error = match json_decode(&oversized_text) {
        Ok(value) => panic!("the oversized text must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
    assert_eq!(error.category(), CodecCategory::ResourceLimit);
    assert!(
        error.detail().contains(&oversized_text.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&JSON_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let mut oversubscribed = String::from("[");
    for position in 0..JSON_NODE_BOUND {
        if position > 0 {
            oversubscribed.push(',');
        }
        oversubscribed.push('0');
    }
    oversubscribed.push(']');
    let error = match json_decode(&oversubscribed) {
        Ok(value) => panic!("the oversubscribed value must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    let depth = JSON_DEPTH_BOUND as usize + 1;
    let too_deep_text = "[".repeat(depth) + "0" + &"]".repeat(depth);
    let error = match json_decode(&too_deep_text) {
        Ok(value) => panic!("the over-deep text must be refused, got {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    let too_many_nodes = JsonValue::Array(vec![JsonValue::Null; JSON_NODE_BOUND]);
    let error = match json_encode(&too_many_nodes) {
        Ok(value) => panic!("the oversubscribed value must be refused, got {value}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    let mut too_deep_value = JsonValue::Null;
    for _ in 0..depth {
        too_deep_value = JsonValue::Array(vec![too_deep_value]);
    }
    let error = match json_encode(&too_deep_value) {
        Ok(value) => panic!("the over-deep value must be refused, got {value}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    let long_text = JsonValue::Text("x".repeat(JSON_TEXT_OCTET_BOUND));
    let error = match json_encode(&long_text) {
        Ok(value) => panic!("the over-long text must be refused, got {value}"),
        Err(error) => error,
    };
    assert_eq!(error.code(), CodecDiagnosticCode::ExpansionLimit);
    assert!(
        error
            .detail()
            .contains(&(JSON_TEXT_OCTET_BOUND + 2).to_string()),
        "{}",
        error.detail()
    );
}
