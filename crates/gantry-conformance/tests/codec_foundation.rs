//! Public-facade conformance for the `GNT-42.0`-`GNT-42.2` codec foundation and hex codec.
//!
//! The section declares the `std.codec` family, its five module items, the versioned codec
//! identity and its exact admission rule, the frozen refusal vocabulary with its codec categories
//! of `GNT-29.9-codec-contract`, the canonical hex codec of `GNT-42.2-hex-codec`, and the
//! separation between application codecs and the sealed canonical boundary and durable recovery
//! projections: these lanes require every declared clause, module row, refusal, and category to
//! be published in the specification and the model, and exercise the version-admission rule and
//! the hex codec's canonical forms, bounds, and refusals directly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CODEC_CLAUSES, CODEC_ITEMS, CodecCategory, CodecDiagnosticCode, CodecError, CodecKind,
    CodecVersion, DECLARED_CODEC_VERSION, HEX_TEXT_OCTET_BOUND, HEX_VALUE_OCTET_BOUND, NameClass,
    PackageFamily, StabilityTier, canonical_codec_hierarchy, canonical_pure_hierarchy, hex_decode,
    hex_encode,
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
    assert_eq!(CODEC_CLAUSES.len(), 3);
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
        let expected = if kind == CodecKind::Hex {
            &CODEC_CLAUSES[..]
        } else {
            &CODEC_CLAUSES[..2]
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
