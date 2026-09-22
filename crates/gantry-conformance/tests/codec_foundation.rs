//! Public-facade conformance for the `GNT-42.0`-`GNT-42.1` codec foundation.
//!
//! The section declares the `std.codec` family, its five module items, the versioned codec
//! identity and its exact admission rule, the frozen refusal vocabulary with its codec categories
//! of `GNT-29.9-codec-contract`, and the separation between application codecs and the sealed
//! canonical boundary and durable recovery projections: these lanes require every declared
//! clause, module row, refusal, and category to be published in the specification and the model,
//! and exercise the version-admission rule directly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CODEC_CLAUSES, CODEC_ITEMS, CodecCategory, CodecDiagnosticCode, CodecError, CodecKind,
    CodecVersion, DECLARED_CODEC_VERSION, NameClass, PackageFamily, StabilityTier,
    canonical_codec_hierarchy, canonical_pure_hierarchy,
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
    assert_eq!(CODEC_CLAUSES.len(), 2);
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
        assert_eq!(
            row.clauses,
            &CODEC_CLAUSES[..],
            "`{}` publishes exactly the declared clauses",
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
            CodecVersion::admit(kind, DECLARED_CODEC_VERSION),
            Ok(declared)
        );
        for version in [0_u16, 2_u16] {
            let error = match CodecVersion::admit(kind, version) {
                Ok(identity) => panic!(
                    "@{version} must be refused, got `{}`",
                    identity.canonical_identity()
                ),
                Err(error) => error,
            };
            assert_eq!(error.code(), CodecDiagnosticCode::UnsupportedVersion);
            assert_eq!(error.requirement(), CODEC_CLAUSES[1]);
            assert_eq!(error.category(), CodecCategory::Decode);
            assert!(
                error.detail().contains(&format!("@{}", version)),
                "{}",
                error.detail()
            );
            assert!(
                error.detail().contains(kind.module_name()),
                "{}",
                error.detail()
            );
        }
    }
    assert_eq!(
        CodecVersion::admit(CodecKind::Hex, DECLARED_CODEC_VERSION)
            .map(|identity| identity.canonical_identity()),
        Ok("std.codec::hex@1".to_owned())
    );
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
