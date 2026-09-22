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
    URL_FRAGMENT_OCTET_BOUND, URL_HOST_SCALAR_BOUND, URL_LABEL_SCALAR_BOUND, URL_QUERY_OCTET_BOUND,
    URL_SCHEME_SCALAR_BOUND, URL_SEGMENT_COUNT_BOUND, URL_SEGMENT_OCTET_BOUND,
    URL_TEXT_OCTET_BOUND, URL_ZONE_SCALAR_BOUND, Url, UrlHost, canonical_data_hierarchy,
    canonical_pure_hierarchy,
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
    assert_eq!(DATA_CLAUSES.len(), 3);
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
    let url_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[2]))
        .unwrap_or_else(|| panic!("the URL clause anchor is published"));
    let url = &spec[url_start..];
    for term in [
        "`std.data::url`",
        "`GNT-43.1-data-value-model-contract`",
        "`URL_TEXT_OCTET_BOUND`",
        "`URL_SCHEME_SCALAR_BOUND`",
        "`URL_HOST_SCALAR_BOUND`",
        "`URL_LABEL_SCALAR_BOUND`",
        "`URL_ZONE_SCALAR_BOUND`",
        "`URL_SEGMENT_COUNT_BOUND`",
        "`URL_SEGMENT_OCTET_BOUND`",
        "`URL_QUERY_OCTET_BOUND`",
        "`URL_FRAGMENT_OCTET_BOUND`",
        "`%25`",
        "`data-malformed-input`",
        "`data-expansion-limit`",
    ] {
        assert!(url.contains(term), "the URL clause must name {term}");
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
        let expected: &[&str] = match module {
            DataModule::Url => &DATA_CLAUSES[..],
            DataModule::Http | DataModule::Mime => &DATA_CLAUSES[..2],
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

fn refusal(result: Result<Url, DataError>) -> DataError {
    match result {
        Ok(value) => panic!("the value must be refused: {}", value.canonical_text()),
        Err(error) => error,
    }
}

#[test]
fn url_parses_and_displays_the_canonical_form() {
    for text in [
        "https://example.test/",
        "https://example.test/a/b?x=1#frag",
        "http://127.0.0.1:8080/p",
        "http://[::1]/",
        "http://[fe80::1%25eth0]/",
        "http://[2001:db8::1]:443/x",
        "ssh://h/",
        "https://example.test/%2Fescaped?p=%20#f%20g",
    ] {
        let value = match Url::parse(text) {
            Ok(value) => value,
            Err(error) => panic!("`{text}` must be admitted: {}", error.detail()),
        };
        assert_eq!(
            value.canonical_text(),
            text,
            "the canonical form is the text"
        );
        assert_eq!(
            value.to_string(),
            text,
            "display publishes the canonical form"
        );
        let reparsed = match Url::parse(&value.canonical_text()) {
            Ok(value) => value,
            Err(error) => panic!("the canonical form must round-trip: {}", error.detail()),
        };
        assert_eq!(
            reparsed, value,
            "a parse of the canonical form is the value"
        );
    }
    let zoned = match Url::parse("http://[fe80::1%25eth0]:80/x") {
        Ok(value) => value,
        Err(error) => panic!("the zoned literal must be admitted: {}", error.detail()),
    };
    assert_eq!(zoned.scheme(), "http");
    assert_eq!(zoned.port(), Some(80));
    assert_eq!(
        zoned.host(),
        &UrlHost::Ipv6 {
            groups: [0xfe80, 0, 0, 0, 0, 0, 0, 1],
            zone: Some("eth0".to_owned()),
        }
    );
    assert_eq!(zoned.segments().len(), 1);
    assert_eq!(zoned.segments()[0], "x");
    assert_eq!(zoned.query(), None);
    assert_eq!(zoned.fragment(), None);
    let v4 = match Url::parse("http://127.0.0.1:8080/p") {
        Ok(value) => value,
        Err(error) => panic!("the IPv4 literal must be admitted: {}", error.detail()),
    };
    assert_eq!(v4.host(), &UrlHost::Ipv4([127, 0, 0, 1]));
    let parts = match Url::parse("https://example.test/a/b?x=1#frag") {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(parts.host(), &UrlHost::RegName("example.test".to_owned()));
    assert_eq!(parts.segments(), ["a", "b"]);
    assert_eq!(parts.query(), Some("x=1"));
    assert_eq!(parts.fragment(), Some("frag"));
    let root = match Url::parse("https://example.test/") {
        Ok(value) => value,
        Err(error) => panic!("the empty segment must be admitted: {}", error.detail()),
    };
    assert_eq!(root.segments().len(), 1);
    assert_eq!(root.segments()[0], "");
}

#[test]
fn url_refuses_noncanonical_spellings_and_indexes_the_departure() {
    let cases: [(&str, usize); 21] = [
        ("HTTP://h/", 0),
        ("https://Example.test/", 8),
        ("https://ex%41mple.test/", 10),
        ("https://h:0/", 10),
        ("https://h:080/", 10),
        ("https://h:65536/", 14),
        ("https://h:/", 10),
        ("https://h", 9),
        ("https://h?x", 9),
        ("https://h/./x", 10),
        ("https://h/../x", 10),
        ("https://h/a%2fb/", 13),
        ("https://h/a%41b/", 11),
        ("https://[0:0:0:0:0:0:0:1]/", 9),
        ("https://[::1%eth0]/", 12),
        ("https://[fe80::1%25ET]/", 19),
        ("https://h/p?a b", 13),
        ("https://user@h/", 12),
        ("https://10.0.0.256/", 17),
        ("https://10.0.0.01/", 16),
        ("https://10.0.0/", 14),
    ];
    for (text, index) in cases {
        let error = refusal(Url::parse(text));
        assert_eq!(error.code(), DataDiagnosticCode::MalformedInput, "{text}");
        assert_eq!(error.requirement(), DATA_CLAUSES[1], "{text}");
        assert_eq!(
            error.category(),
            DataRefusalCategory::MalformedInput,
            "{text}"
        );
        assert!(
            error.detail().starts_with(&format!("octet {index}: ")),
            "`{text}` departs at octet {index}: {}",
            error.detail()
        );
    }
}

#[test]
fn url_construction_admits_only_canonical_components() {
    let bare = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        Vec::new(),
        None,
        None,
    ) {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(bare.canonical_text(), "https://h/");
    let empty_query = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        Vec::new(),
        Some(String::new()),
        None,
    ) {
        Ok(value) => value,
        Err(error) => panic!("the empty query must be admitted: {}", error.detail()),
    };
    assert_eq!(empty_query.canonical_text(), "https://h/?");
    let empty_fragment = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        Vec::new(),
        None,
        Some(String::new()),
    ) {
        Ok(value) => value,
        Err(error) => panic!("the empty fragment must be admitted: {}", error.detail()),
    };
    assert_eq!(empty_fragment.canonical_text(), "https://h/#");
    let with_port = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        Some(443),
        Vec::new(),
        None,
        None,
    ) {
        Ok(value) => value,
        Err(error) => panic!("the port must be admitted: {}", error.detail()),
    };
    assert_ne!(bare, empty_query, "absent and empty are distinct");
    assert_ne!(bare, empty_fragment, "absent and empty are distinct");
    assert_ne!(empty_query, empty_fragment);
    assert_ne!(bare, with_port);
    let same = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        Vec::new(),
        None,
        None,
    ) {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(bare, same, "equality is component equality");
    let composed = match Url::new(
        "http",
        UrlHost::Ipv6 {
            groups: [0xfe80, 0, 0, 0, 0, 0, 0, 1],
            zone: Some("eth0".to_owned()),
        },
        Some(8080),
        vec!["a".to_owned(), "b".to_owned()],
        Some("x=1".to_owned()),
        Some("f".to_owned()),
    ) {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(
        composed.canonical_text(),
        "http://[fe80::1%25eth0]:8080/a/b?x=1#f"
    );
    for (value, expected) in [
        (
            Url::new(
                "HTTPS",
                UrlHost::RegName("h".to_owned()),
                None,
                Vec::new(),
                None,
                None,
            ),
            0_usize,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("Example".to_owned()),
                None,
                Vec::new(),
                None,
                None,
            ),
            0,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("h".to_owned()),
                None,
                vec![".".to_owned()],
                None,
                None,
            ),
            0,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("h".to_owned()),
                None,
                vec!["a%2f".to_owned()],
                None,
                None,
            ),
            3,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("h".to_owned()),
                None,
                Vec::new(),
                Some("a b".to_owned()),
                None,
            ),
            1,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("h".to_owned()),
                None,
                Vec::new(),
                None,
                Some("a b".to_owned()),
            ),
            1,
        ),
    ] {
        let error = refusal(value);
        assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
        assert!(
            error.detail().starts_with(&format!("octet {expected}: ")),
            "the refusal names the component index: {}",
            error.detail()
        );
    }
    let error = refusal(Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        Some(0),
        Vec::new(),
        None,
        None,
    ));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert_eq!(error.requirement(), DATA_CLAUSES[1]);
    let error = refusal(Url::new(
        "HTTPS",
        UrlHost::RegName("h".to_owned()),
        None,
        Vec::new(),
        None,
        None,
    ));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
}

#[test]
fn url_bounds_are_declared_and_enforced() {
    let over_text = format!("https://h/{}", "a".repeat(URL_TEXT_OCTET_BOUND));
    let error = refusal(Url::parse(&over_text));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the presented text"),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&over_text.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&URL_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let long_scheme = format!("{}://h/", "a".repeat(URL_SCHEME_SCALAR_BOUND + 1));
    let error = refusal(Url::parse(&long_scheme));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(error.detail().contains("the scheme"), "{}", error.detail());
    assert!(
        error
            .detail()
            .contains(&(URL_SCHEME_SCALAR_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&URL_SCHEME_SCALAR_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let long_label = format!("https://{}.test/", "a".repeat(URL_LABEL_SCALAR_BOUND + 1));
    let error = refusal(Url::parse(&long_label));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("a host label"),
        "{}",
        error.detail()
    );
    let long_host = format!(
        "https://{}/",
        vec!["a".repeat(URL_LABEL_SCALAR_BOUND); 5].join(".")
    );
    let error = refusal(Url::parse(&long_host));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the reg-name host"),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&URL_HOST_SCALAR_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let long_segment = format!("https://h/{}", "a".repeat(URL_SEGMENT_OCTET_BOUND + 1));
    let error = refusal(Url::parse(&long_segment));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("a path segment"),
        "{}",
        error.detail()
    );
    let many_segments = format!(
        "https://h/{}",
        vec!["a"; URL_SEGMENT_COUNT_BOUND + 1].join("/")
    );
    let error = refusal(Url::parse(&many_segments));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the path segment count"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(URL_SEGMENT_COUNT_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let long_query = format!("https://h/?{}", "a".repeat(URL_QUERY_OCTET_BOUND + 1));
    let error = refusal(Url::parse(&long_query));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(error.detail().contains("the query"), "{}", error.detail());
    let long_fragment = format!("https://h/#{}", "a".repeat(URL_FRAGMENT_OCTET_BOUND + 1));
    let error = refusal(Url::parse(&long_fragment));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the fragment"),
        "{}",
        error.detail()
    );
    let long_zone = format!(
        "https://[fe80::1%25{}]/",
        "a".repeat(URL_ZONE_SCALAR_BOUND + 1)
    );
    let error = refusal(Url::parse(&long_zone));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the zone identifier"),
        "{}",
        error.detail()
    );
    let segments = vec!["a".repeat(URL_SEGMENT_OCTET_BOUND); 65];
    let error = refusal(Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        segments,
        None,
        None,
    ));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the canonical form"),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&URL_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
}
