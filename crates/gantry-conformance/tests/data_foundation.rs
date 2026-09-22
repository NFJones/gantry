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
    DATA_CLAUSES, DATA_ITEMS, DATA_NON_CLAIMS, DECLARED_DATA_VERSION, DataDiagnosticCode,
    DataError, DataModule, DataNonClaim, DataRefusalCategory, DataVersion,
    FRAMING_BODY_OCTET_BOUND, FRAMING_CHUNKED_CODING, HEADER_FIELD_COUNT_BOUND,
    HEADER_NAME_TOKEN_BOUND, HEADER_TEXT_OCTET_BOUND, HEADER_VALUE_OCTET_BOUND,
    HTTP_METHOD_SCALAR_BOUND, HTTP_REASON_OCTET_BOUND, HTTP_STATUS_MAXIMUM, HTTP_STATUS_MINIMUM,
    HeaderField, HeaderFieldList, HttpMethod, HttpRequest, HttpResponse, HttpStatus,
    MIME_PARAMETER_COUNT_BOUND, MIME_PARAMETER_NAME_TOKEN_BOUND, MIME_PARAMETER_VALUE_OCTET_BOUND,
    MIME_SUBTYPE_TOKEN_BOUND, MIME_TEXT_OCTET_BOUND, MIME_TYPE_TOKEN_BOUND, MessageFraming,
    MimeType, NameClass, PackageFamily, StabilityTier, URL_FRAGMENT_OCTET_BOUND,
    URL_HOST_SCALAR_BOUND, URL_LABEL_SCALAR_BOUND, URL_QUERY_OCTET_BOUND, URL_SCHEME_SCALAR_BOUND,
    URL_SEGMENT_COUNT_BOUND, URL_SEGMENT_OCTET_BOUND, URL_TEXT_OCTET_BOUND, URL_ZONE_SCALAR_BOUND,
    Url, UrlHost, canonical_data_hierarchy, canonical_pure_hierarchy, message_framing,
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
    assert_eq!(DATA_CLAUSES.len(), 7);
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
    let mime_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[3]))
        .unwrap_or_else(|| panic!("the MIME clause anchor is published"));
    let mime = &spec[mime_start..];
    for term in [
        "`std.data::mime`",
        "`GNT-43.1-data-value-model-contract`",
        "`MIME_TEXT_OCTET_BOUND`",
        "`MIME_TYPE_TOKEN_BOUND`",
        "`MIME_SUBTYPE_TOKEN_BOUND`",
        "`MIME_PARAMETER_NAME_TOKEN_BOUND`",
        "`MIME_PARAMETER_VALUE_OCTET_BOUND`",
        "`MIME_PARAMETER_COUNT_BOUND`",
        "`; `",
        "`data-malformed-input`",
        "`data-expansion-limit`",
    ] {
        assert!(mime.contains(term), "the MIME clause must name {term}");
    }
    let header_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[4]))
        .unwrap_or_else(|| panic!("the header clause anchor is published"));
    let header = &spec[header_start..];
    for term in [
        "`std.data::http`",
        "`GNT-43.1-data-value-model-contract`",
        "`HEADER_TEXT_OCTET_BOUND`",
        "`HEADER_NAME_TOKEN_BOUND`",
        "`HEADER_VALUE_OCTET_BOUND`",
        "`HEADER_FIELD_COUNT_BOUND`",
        "`data-malformed-input`",
        "`data-expansion-limit`",
    ] {
        assert!(header.contains(term), "the header clause must name {term}");
    }
    let framing_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[5]))
        .unwrap_or_else(|| panic!("the framing clause anchor is published"));
    let framing = &spec[framing_start..];
    for term in [
        "`std.data::http`",
        "`GNT-43.1-data-value-model-contract`",
        "`FRAMING_BODY_OCTET_BOUND`",
        "`content-length`",
        "`transfer-encoding`",
        "`chunked`",
        "`data-malformed-input`",
        "`data-expansion-limit`",
    ] {
        assert!(
            framing.contains(term),
            "the framing clause must name {term}"
        );
    }
    let messages_start = spec
        .find(&format!("<a id=\"{}\"></a>", DATA_CLAUSES[6]))
        .unwrap_or_else(|| panic!("the request/response clause anchor is published"));
    let messages = &spec[messages_start..];
    for term in [
        "`Url`",
        "`HTTP_METHOD_SCALAR_BOUND`",
        "`HTTP_STATUS_MINIMUM`",
        "`HTTP_STATUS_MAXIMUM`",
        "`HTTP_REASON_OCTET_BOUND`",
        "`DataNonClaim`",
        "`DATA_NON_CLAIMS`",
        "`ambient-registry`",
        "`wire-framing`",
        "`ExternalValue`",
    ] {
        assert!(
            messages.contains(term),
            "the request/response clause must name {term}"
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
        let expected: &[&str] = match module {
            DataModule::Url => &[DATA_CLAUSES[0], DATA_CLAUSES[1], DATA_CLAUSES[2]],
            DataModule::Mime => &[DATA_CLAUSES[0], DATA_CLAUSES[1], DATA_CLAUSES[3]],
            DataModule::Http => &[
                DATA_CLAUSES[0],
                DATA_CLAUSES[1],
                DATA_CLAUSES[4],
                DATA_CLAUSES[5],
                DATA_CLAUSES[6],
            ],
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
    let cases: [(&str, usize); 22] = [
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
        ("https://123/", 11),
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
    let long_numeric = format!("https://{}/", "9".repeat(40));
    let error = refusal(Url::parse(&long_numeric));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("octet 10: "),
        "a long numeric host refuses at the third digit: {}",
        error.detail()
    );
    let multibyte_scheme = format!("{}://h/", "é".repeat(33));
    let error = refusal(Url::parse(&multibyte_scheme));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("octet 0: "),
        "a scheme counts scalars but refuses the first non-ASCII octet: {}",
        error.detail()
    );
    let error = refusal(Url::parse("1abc"));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("octet 0: "),
        "a leading digit departs at the first octet: {}",
        error.detail()
    );
    let bracketed = refusal(Url::parse("http://[::1]:0/"));
    assert_eq!(bracketed.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        bracketed.detail().starts_with("octet 13: "),
        "the bracketed port refusal names the port digit: {}",
        bracketed.detail()
    );
    let multibyte_zone = format!("https://[fe80::1%25{}]/", "é".repeat(32));
    let error = refusal(Url::parse(&multibyte_zone));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("octet 19: "),
        "a zone counts scalars but refuses the first non-ASCII octet: {}",
        error.detail()
    );
}

#[test]
fn url_construction_admits_only_canonical_components() {
    let bare = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        vec![String::new()],
        None,
        None,
    ) {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(bare.canonical_text(), "https://h/");
    let reparsed = match Url::parse(&bare.canonical_text()) {
        Ok(value) => value,
        Err(error) => panic!("the canonical form must round-trip: {}", error.detail()),
    };
    assert_eq!(reparsed, bare, "a constructed value parses back unchanged");
    let empty_query = match Url::new(
        "https",
        UrlHost::RegName("h".to_owned()),
        None,
        vec![String::new()],
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
        vec![String::new()],
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
        vec![String::new()],
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
        vec![String::new()],
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
                vec![String::new()],
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
                vec![String::new()],
                None,
                Some("a b".to_owned()),
            ),
            1,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("127.0.0.1".to_owned()),
                None,
                vec![String::new()],
                None,
                None,
            ),
            0,
        ),
        (
            Url::new(
                "https",
                UrlHost::RegName("123".to_owned()),
                None,
                vec![String::new()],
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
                Vec::new(),
                None,
                None,
            ),
            0,
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

fn mime_refusal(result: Result<MimeType, DataError>) -> DataError {
    match result {
        Ok(value) => panic!("the value must be refused: {}", value.canonical_text()),
        Err(error) => error,
    }
}

#[test]
fn mime_parses_and_displays_the_canonical_form() {
    for text in [
        "application/json",
        "text/plain; charset=utf-8",
        "application/vnd.example+json; a=b; b=\"two words\"",
        "text/plain; x=\"\"",
        "application/x-custom; a=\"0\"",
        "application/octet-stream; a=\"quote\\\"inside\"",
        "application/octet-stream; a=\"back\\\\slash\"",
    ] {
        let value = match MimeType::parse(text) {
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
        let reparsed = match MimeType::parse(&value.canonical_text()) {
            Ok(value) => value,
            Err(error) => panic!("the canonical form must round-trip: {}", error.detail()),
        };
        assert_eq!(
            reparsed, value,
            "a parse of the canonical form is the value"
        );
    }
    let value = match MimeType::parse("text/plain; charset=utf-8") {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(value.media_type(), "text");
    assert_eq!(value.subtype(), "plain");
    assert_eq!(
        value.parameters(),
        &[("charset".to_owned(), "utf-8".to_owned())][..]
    );
    let escaped = match MimeType::parse("application/octet-stream; a=\"quote\\\"inside\"") {
        Ok(value) => value,
        Err(error) => panic!("the escaped value must be admitted: {}", error.detail()),
    };
    assert_eq!(
        escaped.parameters(),
        &[("a".to_owned(), "quote\"inside".to_owned())][..],
        "the carried value holds the unescaped octet"
    );
    let parsed = match MimeType::parse("text/plain") {
        Ok(value) => value,
        Err(error) => panic!("the bare type must be admitted: {}", error.detail()),
    };
    assert_ne!(value, parsed, "a parameter changes the value");
}

#[test]
fn mime_refuses_noncanonical_spellings_and_indexes_the_departure() {
    let cases: [(&str, usize); 14] = [
        ("Application/Json", 0),
        ("text/Plain", 5),
        ("text /plain", 4),
        ("text", 4),
        ("text/", 5),
        ("text/plain;Charset=utf-8", 11),
        ("text/plain; charset=utf-8; a=b", 27),
        ("text/plain; a=b; a=c", 17),
        ("text/plain; a=\"b\"", 14),
        ("text/plain; a=\"x\\y\"", 17),
        ("text/plain; a=\"x", 16),
        ("text/plain; a=x y", 15),
        ("text/plain;", 11),
        ("text/plain; ", 12),
    ];
    for (text, index) in cases {
        let error = mime_refusal(MimeType::parse(text));
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
    let ordered = mime_refusal(MimeType::parse("text/plain; b=x; a=\"x\\y\""));
    assert_eq!(ordered.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        ordered.detail().starts_with("octet 17: "),
        "the name order departs before the value is examined: {}",
        ordered.detail()
    );
    let repeated = mime_refusal(MimeType::parse("text/plain; a=x; a=\"b\\c\""));
    assert_eq!(repeated.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        repeated.detail().starts_with("octet 17: "),
        "the repeated name departs before the value is examined: {}",
        repeated.detail()
    );
}

#[test]
fn mime_construction_admits_only_canonical_components() {
    let bare = match MimeType::new("text", "plain", Vec::new()) {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(bare.canonical_text(), "text/plain");
    let parsed = match MimeType::parse("text/plain") {
        Ok(value) => value,
        Err(error) => panic!("the bare type must be admitted: {}", error.detail()),
    };
    assert_eq!(bare, parsed, "equality is component equality");
    let with_parameters = match MimeType::new(
        "text",
        "plain",
        vec![
            ("a".to_owned(), "x".to_owned()),
            ("b".to_owned(), "two words".to_owned()),
        ],
    ) {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(
        with_parameters.canonical_text(),
        "text/plain; a=x; b=\"two words\""
    );
    let reparsed = match MimeType::parse(&with_parameters.canonical_text()) {
        Ok(value) => value,
        Err(error) => panic!("the constructed form must round-trip: {}", error.detail()),
    };
    assert_eq!(reparsed, with_parameters);
    for (result, index) in [
        (MimeType::new("Text", "plain", Vec::new()), 0_usize),
        (MimeType::new("text", "Plain", Vec::new()), 0),
        (
            MimeType::new("text", "plain", vec![("A".to_owned(), "x".to_owned())]),
            0,
        ),
        (
            MimeType::new(
                "text",
                "plain",
                vec![
                    ("b".to_owned(), "x".to_owned()),
                    ("a".to_owned(), "y".to_owned()),
                ],
            ),
            0,
        ),
        (
            MimeType::new(
                "text",
                "plain",
                vec![
                    ("a".to_owned(), "x".to_owned()),
                    ("a".to_owned(), "y".to_owned()),
                ],
            ),
            0,
        ),
        (
            MimeType::new(
                "text",
                "plain",
                vec![("a".to_owned(), "line\nbreak".to_owned())],
            ),
            4,
        ),
    ] {
        let error = mime_refusal(result);
        assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
        assert_eq!(error.requirement(), DATA_CLAUSES[1]);
        assert!(
            error.detail().starts_with(&format!("octet {index}: ")),
            "the refusal names the component index: {}",
            error.detail()
        );
    }
}

#[test]
fn mime_bounds_are_declared_and_enforced() {
    let over_text = format!("text/plain; a={}", "a".repeat(MIME_TEXT_OCTET_BOUND));
    let error = mime_refusal(MimeType::parse(&over_text));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the presented text"),
        "{}",
        error.detail()
    );
    let long_type = format!("{}/plain", "a".repeat(MIME_TYPE_TOKEN_BOUND + 1));
    let error = mime_refusal(MimeType::parse(&long_type));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(error.detail().contains("the type"), "{}", error.detail());
    assert!(
        error
            .detail()
            .contains(&(MIME_TYPE_TOKEN_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let long_subtype = format!("text/{}", "a".repeat(MIME_SUBTYPE_TOKEN_BOUND + 1));
    let error = mime_refusal(MimeType::parse(&long_subtype));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(error.detail().contains("the subtype"), "{}", error.detail());
    let long_name = format!(
        "text/plain; {}=x",
        "a".repeat(MIME_PARAMETER_NAME_TOKEN_BOUND + 1)
    );
    let error = mime_refusal(MimeType::parse(&long_name));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the parameter name"),
        "{}",
        error.detail()
    );
    let long_value = format!(
        "text/plain; a=\"{}\"",
        "b".repeat(MIME_PARAMETER_VALUE_OCTET_BOUND + 1)
    );
    let error = mime_refusal(MimeType::parse(&long_value));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("a parameter value"),
        "{}",
        error.detail()
    );
    let many_parameters = format!(
        "text/plain; {}",
        (0..MIME_PARAMETER_COUNT_BOUND + 1)
            .map(|index| format!("p{index:02}=x"))
            .collect::<Vec<_>>()
            .join("; ")
    );
    let error = mime_refusal(MimeType::parse(&many_parameters));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the parameter count"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(MIME_PARAMETER_COUNT_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let parameters = (0..MIME_PARAMETER_COUNT_BOUND)
        .map(|index| (format!("p{index:02}"), "a".repeat(1_000)))
        .collect::<Vec<_>>();
    let error = mime_refusal(MimeType::new("text", "plain", parameters));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the canonical form"),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&MIME_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let over_quoted = format!(
        "text/plain; a=\"{}\\q\"",
        "b".repeat(MIME_PARAMETER_VALUE_OCTET_BOUND + 1)
    );
    let error = mime_refusal(MimeType::parse(&over_quoted));
    assert_eq!(
        error.code(),
        DataDiagnosticCode::ExpansionLimit,
        "the bound is refused before the malformed tail is examined: {}",
        error.detail()
    );
    assert!(
        error.detail().contains("a parameter value"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(MIME_PARAMETER_VALUE_OCTET_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
}

fn header_field_refusal(result: Result<HeaderField, DataError>) -> DataError {
    match result {
        Ok(value) => panic!("the field must be refused: {}", value.canonical_text()),
        Err(error) => error,
    }
}

fn header_list_refusal(result: Result<HeaderFieldList, DataError>) -> DataError {
    match result {
        Ok(value) => panic!("the list must be refused: {}", value.canonical_text()),
        Err(error) => error,
    }
}

#[test]
fn header_parses_and_displays_the_canonical_form() {
    for text in [
        "content-type: text/plain",
        "x-empty:",
        "a: 1\nb: 2",
        "a: 1\na: 2",
        "cache-control: no-cache, no-store",
        "a: x  y",
    ] {
        let list = match HeaderFieldList::parse(text) {
            Ok(value) => value,
            Err(error) => panic!("`{text}` must be admitted: {}", error.detail()),
        };
        assert_eq!(
            list.canonical_text(),
            text,
            "the canonical form is the text"
        );
        assert_eq!(
            list.to_string(),
            text,
            "display publishes the canonical form"
        );
        let reparsed = match HeaderFieldList::parse(&list.canonical_text()) {
            Ok(value) => value,
            Err(error) => panic!("the canonical form must round-trip: {}", error.detail()),
        };
        assert_eq!(reparsed, list, "a parse of the canonical form is the value");
    }
    let field = match HeaderField::parse("content-type: text/plain") {
        Ok(value) => value,
        Err(error) => panic!("the field must be admitted: {}", error.detail()),
    };
    assert_eq!(field.name(), "content-type");
    assert_eq!(field.value(), "text/plain");
    let empty = match HeaderField::parse("x-empty:") {
        Ok(value) => value,
        Err(error) => panic!("the empty value must be admitted: {}", error.detail()),
    };
    assert_eq!(empty.value(), "");
    assert_eq!(empty.canonical_text(), "x-empty:");
    let list = match HeaderFieldList::parse("a: 1\nb: 2") {
        Ok(value) => value,
        Err(error) => panic!("the list must be admitted: {}", error.detail()),
    };
    assert_eq!(list.fields().len(), 2);
    assert_eq!(list.fields()[0].name(), "a");
    assert_eq!(list.fields()[1].value(), "2");
    let empty_list = match HeaderFieldList::parse("") {
        Ok(value) => value,
        Err(error) => panic!("the empty list must be admitted: {}", error.detail()),
    };
    assert!(empty_list.fields().is_empty());
    assert_eq!(empty_list.canonical_text(), "");
    let single = match HeaderFieldList::parse("a: 1") {
        Ok(value) => value,
        Err(error) => panic!("the single field must be admitted: {}", error.detail()),
    };
    assert_ne!(single, list, "one field and two fields are distinct");
    assert_ne!(
        HeaderFieldList::parse("a: 1").unwrap_or_else(|error| panic!("{}", error.detail())),
        HeaderFieldList::parse("a: 1\na: 2").unwrap_or_else(|error| panic!("{}", error.detail())),
        "a repeated name is a distinct list"
    );
}

#[test]
fn header_refuses_noncanonical_spellings_and_indexes_the_departure() {
    let cases: [(&str, usize); 13] = [
        ("Content-Type: text/plain", 0),
        ("content-type:text/plain", 13),
        ("content-type:  text/plain", 14),
        ("content-type: ", 13),
        ("content-type: text/plain ", 24),
        ("b: 1\na: 2", 5),
        ("a: x\nB: y", 5),
        ("a\nb: 1", 1),
        ("a: 1\n", 5),
        ("\na: 1", 0),
        ("a: x\ty", 4),
        ("a: é", 3),
        ("b: x\na: \t", 5),
    ];
    for (text, index) in cases {
        let error = header_list_refusal(HeaderFieldList::parse(text));
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
fn header_construction_admits_only_canonical_components() {
    let field = match HeaderField::new("a", "x") {
        Ok(value) => value,
        Err(error) => panic!("the components must be admitted: {}", error.detail()),
    };
    assert_eq!(field.canonical_text(), "a: x");
    let parsed = match HeaderField::parse("a: x") {
        Ok(value) => value,
        Err(error) => panic!("the field must be admitted: {}", error.detail()),
    };
    assert_eq!(field, parsed, "equality is component equality");
    let empty = match HeaderField::new("a", "") {
        Ok(value) => value,
        Err(error) => panic!("the empty value must be admitted: {}", error.detail()),
    };
    assert_eq!(empty.canonical_text(), "a:");
    let empty_parsed = match HeaderField::parse("a:") {
        Ok(value) => value,
        Err(error) => panic!("the empty field must be admitted: {}", error.detail()),
    };
    assert_eq!(empty, empty_parsed);
    let list = match HeaderFieldList::new(vec![
        match HeaderField::new("a", "1") {
            Ok(value) => value,
            Err(error) => panic!("the field must be admitted: {}", error.detail()),
        },
        match HeaderField::new("a", "2") {
            Ok(value) => value,
            Err(error) => panic!("the field must be admitted: {}", error.detail()),
        },
        match HeaderField::new("b", "3") {
            Ok(value) => value,
            Err(error) => panic!("the field must be admitted: {}", error.detail()),
        },
    ]) {
        Ok(value) => value,
        Err(error) => panic!("the fields must be admitted: {}", error.detail()),
    };
    assert_eq!(list.canonical_text(), "a: 1\na: 2\nb: 3");
    let reparsed = match HeaderFieldList::parse(&list.canonical_text()) {
        Ok(value) => value,
        Err(error) => panic!("the constructed list must round-trip: {}", error.detail()),
    };
    assert_eq!(reparsed, list);
    for (result, index) in [
        (HeaderField::new("A", "x"), 0_usize),
        (HeaderField::new("a", " x"), 0),
        (HeaderField::new("a", "x "), 1),
        (HeaderField::new("a", "x\ty"), 1),
        (HeaderField::new("a", "x\u{7f}y"), 1),
    ] {
        let error = header_field_refusal(result);
        assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
        assert_eq!(error.requirement(), DATA_CLAUSES[1]);
        assert!(
            error.detail().starts_with(&format!("octet {index}: ")),
            "the refusal names the component index: {}",
            error.detail()
        );
    }
    let first = match HeaderField::new("b", "1") {
        Ok(value) => value,
        Err(error) => panic!("the field must be admitted: {}", error.detail()),
    };
    let second = match HeaderField::new("a", "2") {
        Ok(value) => value,
        Err(error) => panic!("the field must be admitted: {}", error.detail()),
    };
    let error = header_list_refusal(HeaderFieldList::new(vec![first, second]));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("octet 0: "),
        "an out-of-order list is refused: {}",
        error.detail()
    );
    let empty_list = match HeaderFieldList::new(Vec::new()) {
        Ok(value) => value,
        Err(error) => panic!("the empty list must be admitted: {}", error.detail()),
    };
    assert_ne!(
        empty_list,
        match HeaderFieldList::new(vec![match HeaderField::new("a", "") {
            Ok(value) => value,
            Err(error) => panic!("the field must be admitted: {}", error.detail()),
        }]) {
            Ok(value) => value,
            Err(error) => panic!("the list must be admitted: {}", error.detail()),
        },
        "an empty list and one empty-valued field are distinct"
    );
}

#[test]
fn header_bounds_are_declared_and_enforced() {
    let field_text = format!("a: {}", "b".repeat(HEADER_VALUE_OCTET_BOUND));
    let list_text = format!("{field_text}\n{field_text}");
    let error = header_list_refusal(HeaderFieldList::parse(&list_text));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the presented text"),
        "{}",
        error.detail()
    );
    assert!(
        error.detail().contains(&list_text.len().to_string()),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&HEADER_TEXT_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let long_name = format!("{}: x", "a".repeat(HEADER_NAME_TOKEN_BOUND + 1));
    let error = header_field_refusal(HeaderField::parse(&long_name));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the field name"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(HEADER_NAME_TOKEN_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let long_value = format!("a: {}", "b".repeat(HEADER_VALUE_OCTET_BOUND + 1));
    let error = header_field_refusal(HeaderField::parse(&long_value));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the field value"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(HEADER_VALUE_OCTET_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let many = vec!["a: 1"; HEADER_FIELD_COUNT_BOUND + 1].join("\n");
    let error = header_list_refusal(HeaderFieldList::parse(&many));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the field count"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(HEADER_FIELD_COUNT_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let fields = (0..HEADER_FIELD_COUNT_BOUND)
        .map(
            |_| match HeaderField::new("a", &"b".repeat(HEADER_VALUE_OCTET_BOUND)) {
                Ok(value) => value,
                Err(error) => panic!("the field must be admitted: {}", error.detail()),
            },
        )
        .collect::<Vec<_>>();
    let error = header_list_refusal(HeaderFieldList::new(fields));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the canonical form"),
        "{}",
        error.detail()
    );
    let extra = (0..HEADER_FIELD_COUNT_BOUND + 1)
        .map(|_| match HeaderField::new("a", "1") {
            Ok(value) => value,
            Err(error) => panic!("the field must be admitted: {}", error.detail()),
        })
        .collect::<Vec<_>>();
    let error = header_list_refusal(HeaderFieldList::new(extra));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().contains("the field count"),
        "{}",
        error.detail()
    );
    let over_name = format!("{}!: x", "a".repeat(HEADER_NAME_TOKEN_BOUND + 1));
    let error = header_field_refusal(HeaderField::parse(&over_name));
    assert_eq!(
        error.code(),
        DataDiagnosticCode::ExpansionLimit,
        "the bound is refused before the malformed tail is examined: {}",
        error.detail()
    );
    assert!(
        error.detail().contains("the field name"),
        "{}",
        error.detail()
    );
    assert!(
        error
            .detail()
            .contains(&(HEADER_NAME_TOKEN_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    let mixed_name = format!("A{}: x", "a".repeat(HEADER_NAME_TOKEN_BOUND));
    let error = header_field_refusal(HeaderField::parse(&mixed_name));
    assert_eq!(
        error.code(),
        DataDiagnosticCode::MalformedInput,
        "the malformed first octet precedes the name bound: {}",
        error.detail()
    );
    assert!(
        error.detail().starts_with("octet 0: "),
        "{}",
        error.detail()
    );
    let mixed_value = format!("a: \t{}", "b".repeat(HEADER_VALUE_OCTET_BOUND));
    let error = header_field_refusal(HeaderField::parse(&mixed_value));
    assert_eq!(
        error.code(),
        DataDiagnosticCode::MalformedInput,
        "the malformed octet precedes the value bound: {}",
        error.detail()
    );
    assert!(
        error.detail().starts_with("octet 3: "),
        "{}",
        error.detail()
    );
}

fn framing_refusal(result: Result<MessageFraming, DataError>) -> DataError {
    match result {
        Ok(framing) => panic!("the framing must be refused: {framing:?}"),
        Err(error) => error,
    }
}

fn header_field_of(name: &str, value: &str) -> HeaderField {
    match HeaderField::new(name, value) {
        Ok(field) => field,
        Err(error) => panic!("the field must be admitted: {}", error.detail()),
    }
}

fn header_list_of(fields: Vec<HeaderField>) -> HeaderFieldList {
    match HeaderFieldList::new(fields) {
        Ok(list) => list,
        Err(error) => panic!("the list must be admitted: {}", error.detail()),
    }
}

#[test]
fn framing_decides_from_the_declared_fields() {
    assert_eq!(
        message_framing(&header_list_of(Vec::new())),
        Ok(MessageFraming::UntilClose)
    );
    assert_eq!(
        message_framing(&header_list_of(vec![header_field_of("x-unrelated", "y")])),
        Ok(MessageFraming::UntilClose)
    );
    assert_eq!(
        message_framing(&header_list_of(vec![header_field_of(
            "transfer-encoding",
            FRAMING_CHUNKED_CODING,
        )])),
        Ok(MessageFraming::Chunked)
    );
    assert_eq!(
        message_framing(&header_list_of(vec![header_field_of(
            "content-length",
            "0"
        )])),
        Ok(MessageFraming::Length { octets: 0 })
    );
    assert_eq!(
        message_framing(&header_list_of(vec![header_field_of(
            "content-length",
            "12"
        )])),
        Ok(MessageFraming::Length { octets: 12 })
    );
    assert_eq!(
        message_framing(&header_list_of(vec![
            header_field_of("content-length", "5"),
            header_field_of("content-length", "5"),
        ])),
        Ok(MessageFraming::Length { octets: 5 })
    );
    let at_bound = FRAMING_BODY_OCTET_BOUND.to_string();
    assert_eq!(
        message_framing(&header_list_of(vec![header_field_of(
            "content-length",
            &at_bound,
        )])),
        Ok(MessageFraming::Length {
            octets: FRAMING_BODY_OCTET_BOUND
        })
    );
    assert_eq!(
        message_framing(&header_list_of(vec![
            header_field_of("content-length", "7"),
            header_field_of("x-unrelated", "y"),
        ])),
        Ok(MessageFraming::Length { octets: 7 })
    );
}

#[test]
fn framing_refuses_smuggling_shapes_with_exact_positions() {
    let both = header_list_of(vec![
        header_field_of("content-length", "5"),
        header_field_of("transfer-encoding", FRAMING_CHUNKED_CODING),
    ]);
    let error = framing_refusal(message_framing(&both));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("field 1: "),
        "{}",
        error.detail()
    );
    let differing = header_list_of(vec![
        header_field_of("content-length", "5"),
        header_field_of("content-length", "6"),
    ]);
    let error = framing_refusal(message_framing(&differing));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("field 1: "),
        "{}",
        error.detail()
    );
    let unknown = header_list_of(vec![header_field_of("transfer-encoding", "gzip")]);
    let error = framing_refusal(message_framing(&unknown));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("field 0 octet 0: "),
        "{}",
        error.detail()
    );
    let trailing = header_list_of(vec![header_field_of("transfer-encoding", "chunkedd")]);
    let error = framing_refusal(message_framing(&trailing));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("field 0 octet 7: "),
        "{}",
        error.detail()
    );
    let repeated = header_list_of(vec![
        header_field_of("transfer-encoding", FRAMING_CHUNKED_CODING),
        header_field_of("transfer-encoding", FRAMING_CHUNKED_CODING),
    ]);
    let error = framing_refusal(message_framing(&repeated));
    assert_eq!(error.code(), DataDiagnosticCode::MalformedInput);
    assert!(
        error.detail().starts_with("field 1: "),
        "{}",
        error.detail()
    );
}

#[test]
fn framing_refuses_noncanonical_content_length_and_its_bound() {
    for (value, prefix) in [
        ("", "field 0 octet 0: "),
        ("05", "field 0 octet 1: "),
        ("+5", "field 0 octet 0: "),
        ("5x", "field 0 octet 1: "),
    ] {
        let error = framing_refusal(message_framing(&header_list_of(vec![header_field_of(
            "content-length",
            value,
        )])));
        assert_eq!(error.code(), DataDiagnosticCode::MalformedInput, "{value}");
        assert!(error.detail().starts_with(prefix), "{}", error.detail());
    }
    let over = (FRAMING_BODY_OCTET_BOUND + 1).to_string();
    let error = framing_refusal(message_framing(&header_list_of(vec![header_field_of(
        "content-length",
        &over,
    )])));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error.detail().starts_with("field 0: "),
        "{}",
        error.detail()
    );
    assert!(error.detail().contains(&over), "{}", error.detail());
    assert!(
        error
            .detail()
            .contains(&FRAMING_BODY_OCTET_BOUND.to_string()),
        "{}",
        error.detail()
    );
    let error = framing_refusal(message_framing(&header_list_of(vec![header_field_of(
        "content-length",
        "9999999",
    )])));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(error.detail().contains("999999"), "{}", error.detail());
}

fn http_refusal<T>(result: Result<T, DataError>) -> DataError {
    match result {
        Ok(_) => panic!("the value must be refused"),
        Err(error) => error,
    }
}

#[test]
fn request_and_response_values_are_constructed_from_declared_components() {
    let target = match Url::parse("https://example.test/a?x=1") {
        Ok(value) => value,
        Err(error) => panic!("the target must be admitted: {}", error.detail()),
    };
    let headers = header_list_of(vec![header_field_of("content-length", "0")]);
    let method = match HttpMethod::new("POST") {
        Ok(value) => value,
        Err(error) => panic!("the method must be admitted: {}", error.detail()),
    };
    let request = HttpRequest::new(method, target, headers.clone());
    assert_eq!(request.method().as_str(), "POST");
    assert_eq!(
        request.target().canonical_text(),
        "https://example.test/a?x=1"
    );
    assert_eq!(request.headers().fields().len(), 1);
    assert_eq!(
        request.canonical_text(),
        "POST https://example.test/a?x=1\ncontent-length: 0"
    );
    assert_eq!(request.to_string(), request.canonical_text());
    let status = match HttpStatus::new(200) {
        Ok(value) => value,
        Err(error) => panic!("the status must be admitted: {}", error.detail()),
    };
    assert_eq!(status.code(), 200);
    assert_eq!(status.canonical_text(), "200");
    let no_reason = match HttpResponse::new(status, None, headers.clone()) {
        Ok(value) => value,
        Err(error) => panic!("the response must be admitted: {}", error.detail()),
    };
    assert_eq!(no_reason.reason(), None);
    assert_eq!(no_reason.canonical_text(), "200\ncontent-length: 0");
    let with_reason = match HttpResponse::new(status, Some("OK"), headers.clone()) {
        Ok(value) => value,
        Err(error) => panic!("the response must be admitted: {}", error.detail()),
    };
    assert_eq!(with_reason.reason(), Some("OK"));
    assert_eq!(with_reason.canonical_text(), "200 OK\ncontent-length: 0");
    assert_ne!(
        no_reason, with_reason,
        "a reason present and a reason absent are distinct"
    );
    let not_found_status = match HttpStatus::new(404) {
        Ok(value) => value,
        Err(error) => panic!("the status must be admitted: {}", error.detail()),
    };
    let not_found = match HttpResponse::new(not_found_status, Some("Not Found"), headers) {
        Ok(value) => value,
        Err(error) => panic!("the response must be admitted: {}", error.detail()),
    };
    assert_ne!(not_found, with_reason);
}

#[test]
fn request_and_response_refuse_noncanonical_components() {
    for (text, index) in [
        ("get", 0_usize),
        ("Post", 1),
        ("1ET", 0),
        ("", 0),
        ("P0ST ", 4),
    ] {
        let error = http_refusal(HttpMethod::new(text));
        assert_eq!(error.code(), DataDiagnosticCode::MalformedInput, "{text}");
        assert!(
            error.detail().starts_with(&format!("octet {index}: ")),
            "`{text}` departs at octet {index}: {}",
            error.detail()
        );
    }
    let long_method = "A".repeat(HTTP_METHOD_SCALAR_BOUND + 1);
    let error = http_refusal(HttpMethod::new(&long_method));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error
            .detail()
            .contains(&(HTTP_METHOD_SCALAR_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
    assert_eq!(
        http_refusal(HttpStatus::new(HTTP_STATUS_MINIMUM - 1)).code(),
        DataDiagnosticCode::MalformedInput
    );
    assert_eq!(
        http_refusal(HttpStatus::new(HTTP_STATUS_MAXIMUM + 1)).code(),
        DataDiagnosticCode::MalformedInput
    );
    let headers = header_list_of(Vec::new());
    let status = match HttpStatus::new(200) {
        Ok(value) => value,
        Err(error) => panic!("the status must be admitted: {}", error.detail()),
    };
    for (reason, index) in [("", 0_usize), (" ok", 0), ("ok ", 2), ("o\tk", 1)] {
        let error = http_refusal(HttpResponse::new(status, Some(reason), headers.clone()));
        assert_eq!(
            error.code(),
            DataDiagnosticCode::MalformedInput,
            "{reason:?}"
        );
        assert!(
            error.detail().starts_with(&format!("octet {index}: ")),
            "the reason departs at octet {index}: {}",
            error.detail()
        );
    }
    let long_reason = "o".repeat(HTTP_REASON_OCTET_BOUND + 1);
    let error = http_refusal(HttpResponse::new(status, Some(&long_reason), headers));
    assert_eq!(error.code(), DataDiagnosticCode::ExpansionLimit);
    assert!(
        error
            .detail()
            .contains(&(HTTP_REASON_OCTET_BOUND + 1).to_string()),
        "{}",
        error.detail()
    );
}

#[test]
fn data_non_claims_are_closed_and_ordered() {
    assert_eq!(DataNonClaim::ALL.len(), 8);
    assert_eq!(DATA_NON_CLAIMS.len(), DataNonClaim::ALL.len());
    let mut prior: Option<&str> = None;
    let mut wire_names = BTreeSet::new();
    let mut statements = BTreeSet::new();
    for claim in DataNonClaim::ALL {
        let wire_name = claim.wire_name();
        if let Some(previous) = prior {
            assert!(
                previous < wire_name,
                "the non-claim registry is sorted: {previous} then {wire_name}"
            );
        }
        prior = Some(wire_name);
        assert!(
            wire_names.insert(wire_name),
            "one wire spelling per non-claim"
        );
        assert_eq!(DataNonClaim::from_wire_name(wire_name), Some(claim));
        assert!(
            !claim.statement().is_empty(),
            "every non-claim publishes a statement"
        );
        assert!(
            statements.insert(claim.statement()),
            "one statement per non-claim"
        );
    }
    assert!(DataNonClaim::from_wire_name("not-a-non-claim").is_none());
    assert!(
        DataNonClaim::WireFraming
            .statement()
            .contains("GNT-43.5-message-framing-model")
    );
    assert!(
        DataNonClaim::ExternalEligibility
            .statement()
            .contains("ExternalValue")
    );
}
