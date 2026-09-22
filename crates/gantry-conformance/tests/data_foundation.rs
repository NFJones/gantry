//! Public-facade conformance for the `GNT-43.0`-`GNT-43.1` data foundation.
//!
//! The section declares the `std.data` family, its three module items, the versioned value-model
//! identity and its exact admission rule, the frozen refusal vocabulary with its declared refusal
//! categories, and the separation between these pure value models and the capability-backed
//! network contracts of `GNT-29.6-dns-socket-tls-and-http-contracts`: these lanes require every
//! declared clause, module row, refusal, and category to be published in the specification and
//! the model, and exercise the version-admission rule directly.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    DATA_CLAUSES, DATA_ITEMS, DECLARED_DATA_VERSION, DataDiagnosticCode, DataError, DataModule,
    DataRefusalCategory, DataVersion, NameClass, PackageFamily, StabilityTier,
    canonical_data_hierarchy, canonical_pure_hierarchy,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("conformance crate has a workspace parent"))
        .to_path_buf()
}

#[test]
fn section_43_clauses_are_published() {
    let spec = fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(DATA_CLAUSES.len(), 2);
    let mut prior = 0_usize;
    for clause in DATA_CLAUSES {
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
    let scope_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[0]))
        .unwrap_or_else(|| panic!("the scope anchor is published"));
    let contract_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[1]))
        .unwrap_or_else(|| panic!("the contract anchor is published"));
    assert!(scope_start < contract_start);
    let scope = &spec[scope_start..contract_start];
    for term in [
        "`std.data`",
        "`http`",
        "`mime`",
        "`url`",
        "`data-unsupported-version`",
        "`data-malformed-input`",
        "`data-expansion-limit`",
        "`GNT-29.6-dns-socket-tls-and-http-contracts`",
        "`GNT-35.7-bytes-and-canonical-encoding`",
    ] {
        assert!(scope.contains(term), "the scope clause must name {term}");
    }
    let contract = &spec[contract_start..];
    for term in [
        "`std.data::http`",
        "`std.data::mime`",
        "`std.data::url`",
        "`std.data::<module>@<version>`",
        "`GNT-34.1-canonical-hierarchy-and-package-names`",
        "`GNT-34.2-name-classification`",
        "`GNT-34.6-stability-tiers`",
        "`unsupported-version`",
        "`malformed-input`",
        "`resource-limit`",
        "`ExternalValue`",
    ] {
        assert!(
            contract.contains(term),
            "the contract clause must name {term}"
        );
    }
}

#[test]
fn data_surface_declares_the_three_modules() {
    let aggregate = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the aggregate hierarchy is declared: {error:?}"));
    let owner = PackageFamily::Data.package_name();
    assert_eq!(
        aggregate
            .package(&owner)
            .unwrap_or_else(|| panic!("the aggregate hierarchy declares `{owner}`"))
            .items()
            .len(),
        0,
        "the aggregate constructor declares no family item"
    );
    let graph = canonical_data_hierarchy()
        .unwrap_or_else(|error| panic!("the family hierarchy is declared: {error:?}"));
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the hierarchy declares `{owner}`"));
    assert_eq!(DATA_ITEMS.len(), DataModule::ALL.len());
    let mut expected = DataModule::ALL
        .iter()
        .map(|module| format!("std.data.{}", module.wire_name()))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(
        package.items().keys().cloned().collect::<Vec<_>>(),
        expected,
        "the family declares exactly one module item per declared value model"
    );
    for (row, module) in DATA_ITEMS.iter().zip(DataModule::ALL) {
        assert_eq!(row.module, module);
        assert_eq!(
            row.name,
            format!("std.data::{}", module.wire_name()),
            "the item name is the canonical module name of its value model"
        );
        assert_eq!(row.name, module.module_name());
        assert_eq!(row.class, NameClass::Module, "`{}` is a module", row.name);
        assert_eq!(row.tier, StabilityTier::Stable, "`{}` is stable", row.name);
        assert_eq!(
            row.clauses,
            &DATA_CLAUSES[..],
            "`{}` publishes exactly the clauses that publish facts about its surface",
            row.name
        );
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("`{}` is declared", row.name));
        assert_eq!(item.class(), NameClass::Module);
        assert_eq!(item.tier(), StabilityTier::Stable);
    }
    for module in DataModule::ALL {
        assert_eq!(
            DataModule::from_module_name(module.module_name()),
            Some(module)
        );
    }
    assert!(DataModule::from_module_name("std.data::other").is_none());
    assert!(DataModule::from_module_name("std.codec::hex").is_none());
}

#[test]
fn declared_versions_admit_exactly_the_declared_identity() {
    assert_eq!(DECLARED_DATA_VERSION, 1);
    for module in DataModule::ALL {
        let declared = DataVersion::declared(module);
        assert_eq!(declared, module.declared_version());
        assert_eq!(declared.module(), module);
        assert_eq!(declared.version(), DECLARED_DATA_VERSION);
        assert_eq!(
            declared.canonical_identity(),
            format!("{}@{}", module.module_name(), DECLARED_DATA_VERSION)
        );
        assert_eq!(
            DataVersion::admit(&declared.canonical_identity()),
            Ok(declared)
        );
        for version in [0_u16, 2_u16] {
            let presented = format!("{}@{version}", module.module_name());
            let error = match DataVersion::admit(&presented) {
                Ok(identity) => panic!(
                    "`{presented}` must be refused, got `{}`",
                    identity.canonical_identity()
                ),
                Err(error) => error,
            };
            assert_eq!(error.code(), DataDiagnosticCode::UnsupportedVersion);
            assert_eq!(error.requirement(), DATA_CLAUSES[1]);
            assert_eq!(error.category(), DataRefusalCategory::UnsupportedVersion);
            assert!(error.detail().contains(&presented), "{}", error.detail());
            assert!(
                error.detail().contains(module.module_name()),
                "{}",
                error.detail()
            );
        }
    }
    // A parseable but noncanonical version spelling is not the declared identity.
    for (presented, declared_identity) in [
        ("std.data::url@01", "std.data::url@1"),
        ("std.data::url@+1", "std.data::url@1"),
        ("std.data::mime@0001", "std.data::mime@1"),
    ] {
        let error = match DataVersion::admit(presented) {
            Ok(identity) => panic!(
                "`{presented}` must be refused, got `{}`",
                identity.canonical_identity()
            ),
            Err(error) => error,
        };
        assert_eq!(error.code(), DataDiagnosticCode::UnsupportedVersion);
        assert_eq!(error.requirement(), DATA_CLAUSES[1]);
        assert_eq!(error.category(), DataRefusalCategory::UnsupportedVersion);
        assert!(error.detail().contains(presented), "{}", error.detail());
        assert!(
            error.detail().contains(declared_identity),
            "the refusal names the declared identity: {}",
            error.detail()
        );
    }
    for presented in ["std.data::other@1", "std.data::url", "not-an-identity"] {
        let error = match DataVersion::admit(presented) {
            Ok(identity) => panic!(
                "`{presented}` must be refused, got `{}`",
                identity.canonical_identity()
            ),
            Err(error) => error,
        };
        assert_eq!(error.code(), DataDiagnosticCode::UnsupportedVersion);
        assert_eq!(error.requirement(), DATA_CLAUSES[1]);
        assert_eq!(error.category(), DataRefusalCategory::UnsupportedVersion);
        assert!(
            error.detail().contains(presented),
            "the refusal names the observed identity: {}",
            error.detail()
        );
        assert!(
            error.detail().contains("std.data::http"),
            "the refusal names the declared set: {}",
            error.detail()
        );
    }
}

#[test]
fn refusals_are_frozen_and_classified() {
    let mut prior: Option<&str> = None;
    let mut spellings = BTreeSet::new();
    for code in DataDiagnosticCode::ALL {
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
        assert_eq!(code.requirement(), DATA_CLAUSES[1]);
        assert!(DATA_CLAUSES.contains(&code.requirement()));
    }
    assert_eq!(spellings.len(), DataDiagnosticCode::ALL.len());
    assert_eq!(
        spellings.iter().copied().collect::<Vec<_>>(),
        vec![
            "data-expansion-limit",
            "data-malformed-input",
            "data-unsupported-version"
        ]
    );
    assert_eq!(
        DataDiagnosticCode::UnsupportedVersion.category(),
        DataRefusalCategory::UnsupportedVersion
    );
    assert_eq!(
        DataDiagnosticCode::MalformedInput.category(),
        DataRefusalCategory::MalformedInput
    );
    assert_eq!(
        DataDiagnosticCode::ExpansionLimit.category(),
        DataRefusalCategory::ResourceLimit
    );
    let error = DataError::new(DataDiagnosticCode::MalformedInput, "octet 3");
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert_eq!(error.code().as_str(), "data-malformed-input");
    assert_eq!(error.detail(), "octet 3");
    assert_eq!(error.requirement(), DATA_CLAUSES[1]);
    assert_eq!(error.category(), DataRefusalCategory::MalformedInput);
    assert_eq!(
        DataRefusalCategory::ALL
            .iter()
            .map(|category| category.wire_name())
            .collect::<Vec<_>>(),
        vec!["malformed-input", "resource-limit", "unsupported-version"]
    );
    let mut wire_spellings = BTreeSet::new();
    for category in DataRefusalCategory::ALL {
        assert!(
            wire_spellings.insert(category.wire_name()),
            "one wire spelling per refusal category"
        );
        assert_eq!(
            DataRefusalCategory::from_wire_name(category.wire_name()),
            Some(category)
        );
    }
    assert!(DataRefusalCategory::from_wire_name("not-a-category").is_none());
}
