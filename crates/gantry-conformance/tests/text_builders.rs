//! Public conformance for the bounded text builder of
//! `GNT-41.4-canonical-text-builders`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    TEXT_CLAUSES, TEXT_VALUE_SCALAR_BOUND, TextBuilder, TextDiagnosticCode, TextValue,
};

/// The declared clauses of Section 41, written out independently of the model.
const EXPECTED_CLAUSES: [&str; 12] = [
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
    "GNT-41.10-canonical-text-admission-bound",
    "GNT-41.11-canonical-text-value-bound",
];
const BUILDER_CLAUSE: &str = "GNT-41.4-canonical-text-builders";

#[test]
fn builder_refuses_a_value_beyond_the_declared_bound() {
    let at_bound = TextValue::from_lossless_octets(&vec![b'a'; TEXT_VALUE_SCALAR_BOUND])
        .unwrap_or_else(|error| panic!("the value at the bound is admitted: {error}"));
    let mut builder = TextBuilder::with_octet_bound(TEXT_VALUE_SCALAR_BOUND + 1);
    builder
        .append(&at_bound)
        .unwrap_or_else(|error| panic!("the value at the bound is appended: {error}"));
    assert_eq!(
        built(&builder).scalar_count(),
        TEXT_VALUE_SCALAR_BOUND,
        "a build at the declared bound publishes"
    );
    builder
        .append(
            &TextValue::from_lossless_octets(b"a")
                .unwrap_or_else(|error| panic!("one scalar is admitted: {error}")),
        )
        .unwrap_or_else(|error| panic!("one more scalar is appended: {error}"));
    let error = builder
        .build()
        .err()
        .unwrap_or_else(|| panic!("a build beyond the bound is refused"));
    assert_eq!(error.code(), TextDiagnosticCode::ValueBound);
    assert_eq!(
        error.detail(),
        format!(
            "the value would hold {} scalar values, beyond the declared bound {TEXT_VALUE_SCALAR_BOUND}",
            TEXT_VALUE_SCALAR_BOUND + 1
        )
    );
}

#[test]
fn builder_clause_publishes_the_bounded_builder() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    assert_eq!(
        TextDiagnosticCode::ALL.map(TextDiagnosticCode::spelling),
        [
            "text-invalid-utf8",
            "text-builder-bound",
            "text-pattern-syntax",
            "text-pattern-bound",
            "text-match-budget",
            "text-value-bound",
            "text-invalid-utf16",
        ]
    );
    let body = clause_body(&specification, BUILDER_CLAUSE);
    for declaration in [
        "`with_octet_bound` publishes a builder whose accumulated canonical octets may never exceed that bound",
        "otherwise refuses under `text-builder-bound` and leaves the builder exactly as it was",
        "`build` publishes the text value whose canonical octets are exactly the accumulated sequence",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    assert!(
        body.contains("`GNT-41.1-canonical-text-values`"),
        "the clause cites `GNT-41.1-canonical-text-values`"
    );
}

#[test]
fn builder_accumulates_in_append_order() {
    let mut builder = TextBuilder::with_octet_bound(64);
    assert_eq!(builder.octet_bound(), 64);
    assert!(builder.is_empty());
    assert_eq!(builder.len(), 0);
    assert_eq!(built(&builder), TextValue::empty());

    let decomposed = admitted("e\u{301}".as_bytes());
    let syllable = admitted("\u{ac01}".as_bytes());
    append(&mut builder, &decomposed);
    append(&mut builder, &syllable);
    let accumulated = [decomposed.canonical_octets(), syllable.canonical_octets()].concat();
    assert_eq!(
        builder.len(),
        decomposed.canonical_octets().len() + syllable.canonical_octets().len()
    );
    assert!(!builder.is_empty());
    assert_eq!(built(&builder).canonical_octets(), accumulated);

    // Appending the empty value changes nothing.
    append(&mut builder, &TextValue::empty());
    assert_eq!(built(&builder).canonical_octets(), accumulated);
}

#[test]
fn builder_refuses_at_the_declared_bound_atomically() {
    let mut builder = TextBuilder::with_octet_bound(3);
    let three = admitted(b"abc");
    let four = admitted(b"abcd");
    append(&mut builder, &three);
    let refusal = match builder.append(&four) {
        Ok(()) => panic!("four more octets exceed the bound"),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.code(), TextDiagnosticCode::BuilderBound);
    assert_eq!(refusal.code().owning_clause(), BUILDER_CLAUSE);
    assert!(
        refusal.detail().contains("bound of 3"),
        "the refusal names the declared bound: {}",
        refusal.detail()
    );
    assert_eq!(builder.len(), 3, "a refused append changes nothing");
    assert_eq!(built(&builder).canonical_octets(), b"abc");

    // A zero bound admits exactly the empty value.
    let mut zero = TextBuilder::with_octet_bound(0);
    assert_eq!(built(&zero), TextValue::empty());
    assert!(zero.append(&three).is_err());
    append(&mut zero, &TextValue::empty());
}

#[test]
fn builder_publication_is_independent_of_later_appends() {
    let mut builder = TextBuilder::with_octet_bound(8);
    append(&mut builder, &admitted(b"ab"));
    let published = built(&builder);
    let recorded = published.clone();
    append(&mut builder, &admitted(b"cd"));
    assert_eq!(
        published, recorded,
        "a later append cannot change a published value"
    );
    assert_eq!(published.canonical_octets(), b"ab");
    assert_eq!(built(&builder).canonical_octets(), b"abcd");
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn append(builder: &mut TextBuilder, value: &TextValue) {
    builder.append(value).unwrap_or_else(|error| {
        panic!("`{value:?}` is appended within the declared bound: {error}")
    });
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

fn built(builder: &TextBuilder) -> TextValue {
    builder.build().unwrap_or_else(|error| {
        panic!("the published value stays within the declared bound: {error}")
    })
}
