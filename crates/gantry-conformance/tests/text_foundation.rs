//! Public conformance for the text foundation of `GNT-41.0-text-foundation-scope` and
//! `GNT-41.1-canonical-text-values`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CharValue, PATTERN_INSTRUCTION_BOUND, PATTERN_REPEAT_BOUND, PATTERN_SCALAR_BOUND,
    PackageFamily, StabilityTier, TEXT_CLAUSES, TextDiagnosticCode, TextValue,
    canonical_pure_hierarchy,
};

/// The text surface this slice publishes, written out independently of the model and the note: the
/// clause anchors in specification order and the registered refusal spellings in declaration order.
const EXPECTED_CLAUSES: [&str; 10] = [
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
];
const EXPECTED_DIAGNOSTICS: [&str; 6] = [
    "text-invalid-utf8",
    "text-builder-bound",
    "text-pattern-syntax",
    "text-pattern-bound",
    "text-match-budget",
    "text-invalid-utf16",
];

#[test]
fn text_clauses_and_the_diagnostic_are_published() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(
        TEXT_CLAUSES, EXPECTED_CLAUSES,
        "the model publishes the expected clauses in specification order"
    );
    assert_eq!(
        specification.matches("<a id=\"GNT-41.").count(),
        EXPECTED_CLAUSES.len(),
        "the section declares one anchor per published clause"
    );
    let mut previous = 0_usize;
    for clause in EXPECTED_CLAUSES {
        let declaration = format!("<a id=\"{clause}\"");
        let position = specification
            .find(&declaration)
            .unwrap_or_else(|| panic!("the specification declares `{clause}`"));
        assert!(
            position > previous,
            "`{clause}` is declared after the clause before it"
        );
        previous = position;
    }
    assert_eq!(
        TextDiagnosticCode::ALL.map(TextDiagnosticCode::spelling),
        EXPECTED_DIAGNOSTICS,
        "the section declares the registered diagnostics in declaration order"
    );
    for diagnostic in EXPECTED_DIAGNOSTICS {
        assert!(
            specification.contains(diagnostic),
            "the section declares the registered diagnostic `{diagnostic}`"
        );
    }
    for code in TextDiagnosticCode::ALL {
        assert!(EXPECTED_CLAUSES.contains(&code.owning_clause()));
    }
}

#[test]
fn note_names_the_declared_ownership_and_gated_obligations() {
    let note = read_workspace_file("docs/text-foundation.md");
    let section = section_body(&note, "## Declared ownership and handoff");
    for clause in EXPECTED_CLAUSES {
        assert!(
            section.contains(clause),
            "the handoff record names the declared clause `{clause}`"
        );
    }
    for diagnostic in EXPECTED_DIAGNOSTICS {
        assert!(
            section.contains(diagnostic),
            "the handoff record names the declared diagnostic `{diagnostic}`"
        );
    }
    for owner in [
        "std.num",
        "GNT-40.6-canonical-numeric-text",
        "TIME-001",
        "4cf122ef",
        "RESOURCE-001",
        "926a4a0f",
        "GATE-200",
        "916d98cf",
        "STDLIB-001",
        "f3908168",
        "PUB-001",
        "624db3b4",
    ] {
        assert!(
            section.contains(owner),
            "the handoff record names the owner `{owner}`"
        );
    }
    assert!(
        section.contains("remain gated on the runtime owners named above"),
        "the handoff record states the gated runtime obligation"
    );
    assert!(
        section.contains("Only two kernels of the section declare an exact bound or budget"),
        "the handoff record names exactly which kernels declare bounds"
    );
    assert!(
        section.contains("are exact validity rules for their inputs, not work limits"),
        "the handoff record distinguishes admission validity from work limits"
    );
    assert!(
        section.contains("publish no declared work limit yet"),
        "the handoff record states the remaining kernels' undeclared limit"
    );
    assert!(
        !section
            .contains("Every input-dependent kernel of the section has an exact declared bound"),
        "the handoff record does not claim a bound for every kernel"
    );
}

#[test]
fn kernels_examine_their_input_in_one_forward_pass() {
    let note = read_workspace_file("docs/text-foundation.md");
    let record = section_body(&note, "## Declared ownership and handoff");
    for required in [
        "8697435",
        "16ea7fd",
        "counts the combining classes of each non-starter segment",
        "one output buffer",
        "one reverse presence pass followed by one forward mapping pass",
        "carries one forward state per scalar",
        "does not claim that each kernel traverses its input exactly once",
    ] {
        assert!(
            record.contains(required),
            "the record names the work shape `{required}`"
        );
    }
    let source = read_workspace_file("crates/gantry-core/src/unicode.rs");
    for removed in [
        "indic_conjunct_before",
        "extended_pictographic_before_zwj",
        "has_cased_before",
        "has_cased_after",
        "codes.remove(",
    ] {
        assert!(
            !source.contains(removed),
            "the kernel source does not name the removed scan `{removed}`"
        );
    }
}

/// Returns the body of one note section: the text between its heading and the next level-two
/// heading, or to the end of the note when the section is the final one.
fn section_body<'a>(note: &'a str, heading: &str) -> &'a str {
    let start = note
        .find(heading)
        .unwrap_or_else(|| panic!("the note has the section `{heading}`"))
        + heading.len();
    let rest = &note[start..];
    match rest.find("\n## ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

#[test]
fn note_names_the_completion_criteria_and_their_evidence() {
    let note = read_workspace_file("docs/text-foundation.md");
    let section = section_body(&note, "## Completion criteria and their evidence");
    for criterion in [
        "text results are target-independent",
        "every input-dependent kernel has exact limits and safe points",
        "package dependencies obey the pure standard-library DAG",
        "optimized and reference implementations agree",
    ] {
        assert!(
            section.contains(criterion),
            "the completion record names the criterion `{criterion}`"
        );
    }
    for owner in ["RESOURCE-001", "926a4a0f", "GATE-200", "916d98cf"] {
        assert!(
            section.contains(owner),
            "the completion record names the gated owner `{owner}`"
        );
    }
    assert_eq!(
        section.matches("**met**").count(),
        3,
        "three criteria are met and the limits-and-safe-points criterion is not"
    );
    assert!(
        section.contains("**unmet, gated**"),
        "the limits-and-safe-points criterion is recorded as unmet"
    );
    assert!(
        section.contains("does not resolve `GNT-GP-STDLIB-TEXT-001`"),
        "the record states that the issue is not resolved"
    );
    for bound in [
        PATTERN_SCALAR_BOUND.to_string(),
        PATTERN_REPEAT_BOUND.to_string(),
        PATTERN_INSTRUCTION_BOUND.to_string(),
    ] {
        assert!(
            section.contains(&bound),
            "the completion record names the declared bound {bound}"
        );
    }
}

#[test]
fn text_family_obeys_the_pure_standard_library_dag() {
    let graph = canonical_pure_hierarchy()
        .unwrap_or_else(|error| panic!("the canonical pure hierarchy is declared: {error:?}"));
    let text = graph
        .package(&PackageFamily::Text.package_name())
        .unwrap_or_else(|| panic!("the hierarchy declares `std.text`"));
    assert!(PackageFamily::Text.is_pure(), "`std.text` is a pure family");
    assert_eq!(
        text.tier(),
        StabilityTier::Stable,
        "`std.text` is a stable family"
    );
    assert!(
        !text.identity().as_str().is_empty(),
        "`std.text` publishes an interface identity"
    );
    let dependencies = text.dependencies().iter().cloned().collect::<Vec<_>>();
    assert_eq!(
        dependencies,
        vec![
            PackageFamily::Collections.package_name(),
            PackageFamily::Core.package_name(),
        ],
        "`std.text` depends on exactly `std.collections` and `std.core`"
    );
    let pure = PackageFamily::ALL
        .iter()
        .filter(|family| family.is_pure())
        .map(|family| family.package_name())
        .collect::<Vec<_>>();
    for dependency in &dependencies {
        assert!(
            pure.contains(dependency),
            "`{dependency}` is a pure standard package"
        );
    }
    for (name, item) in text.items() {
        assert_eq!(
            item.owner(),
            text.name(),
            "`{name}` is owned by the family that declares it"
        );
    }
}

#[test]
fn text_model_is_host_independent_and_publishes_no_suspension_entry_point() {
    let source = read_workspace_file("crates/gantry-ir/src/text.rs");
    for needle in [
        "std::env",
        "std::time",
        "std::fs",
        "std::net",
        "SystemTime",
        "Instant",
        "thread",
        "spawn",
        "unsafe",
        "cutoff",
        "suspend",
        "cancel",
        "resume",
        "abort",
    ] {
        assert!(
            !source.contains(needle),
            "the text model names no `{needle}`"
        );
    }
    assert!(
        source.contains("pub struct TextValue"),
        "the model publishes its text value"
    );
    assert_eq!(PATTERN_SCALAR_BOUND, 4096);
    assert_eq!(PATTERN_REPEAT_BOUND, 255);
    assert_eq!(PATTERN_INSTRUCTION_BOUND, 16_384);
}

#[test]
fn text_values_admit_exactly_well_formed_utf8() {
    let empty = admitted(b"");
    assert!(empty.is_empty());
    assert_eq!(empty.scalar_count(), 0);
    assert_eq!(empty.canonical_octets(), b"");

    let text = "a\u{e9}\u{1f600}b";
    let value = admitted(text.as_bytes());
    assert_eq!(value.scalar_count(), 4);
    assert_eq!(
        value.canonical_octets(),
        text.as_bytes(),
        "admission keeps exactly the admitted octets"
    );
    assert!(!value.is_empty());

    let mark = admitted("\u{feff}".as_bytes());
    assert_eq!(
        mark.scalar_count(),
        1,
        "a byte-order mark is admitted as its scalar rather than stripped"
    );
    assert_eq!(mark.canonical_octets(), "\u{feff}".as_bytes());

    for (octets, index) in [
        (b"\xFF".as_slice(), 0_usize),
        (b"\xE2\x82".as_slice(), 0),
        (b"a\x80".as_slice(), 1),
        (b"\xC0\xAF".as_slice(), 0),
        (b"\xED\xA0\x80".as_slice(), 0),
    ] {
        let refusal = TextValue::from_octets(octets)
            .err()
            .unwrap_or_else(|| panic!("`{octets:?}` is ill-formed UTF-8"));
        assert_eq!(refusal.code(), TextDiagnosticCode::InvalidUtf8);
        assert!(
            refusal.detail().contains(&format!("octet {index}")),
            "the refusal names the failing octet index: {}",
            refusal.detail()
        );
    }
}

#[test]
fn text_slicing_publishes_only_scalars_the_value_holds() {
    // An empty value holds no scalar, so no range with a positive end may publish anything, while
    // the empty range at position zero still publishes the empty value.
    let empty = TextValue::empty();
    assert_eq!(rendered(&slice(&empty, 0, 0)), "");
    assert!(
        empty.slice_scalars(0, 1).is_none(),
        "a range whose end exceeds the empty value's scalar count publishes nothing"
    );
    assert!(
        empty.slice_scalars(1, 1).is_none(),
        "a range beyond the empty value publishes nothing"
    );
    assert_eq!(empty.scalar_at(0), None);

    let value = admitted("a\u{e9}\u{1f600}b".as_bytes());
    assert_eq!(value.scalar_count(), 4);
    assert_eq!(rendered(&slice(&value, 0, 0)), "");
    assert_eq!(rendered(&slice(&value, 0, 4)), "a\u{e9}\u{1f600}b");
    assert_eq!(rendered(&slice(&value, 1, 3)), "\u{e9}\u{1f600}");
    assert_eq!(rendered(&slice(&value, 4, 4)), "");
    assert!(
        value.slice_scalars(3, 5).is_none(),
        "an end beyond the scalar count publishes nothing"
    );
    assert!(
        value.slice_scalars(2, 1).is_none(),
        "a start after the end publishes nothing"
    );
    assert_eq!(value.scalar_at(0), Some(scalar("a")));
    assert_eq!(value.scalar_at(2), Some(scalar("\u{1f600}")));
    assert_eq!(value.scalar_at(3), Some(scalar("b")));
    assert_eq!(value.scalar_at(4), None);
    assert_eq!(
        value.scalar_count(),
        4,
        "slicing does not modify the value it reads"
    );
    assert_eq!(
        value.canonical_octets(),
        "a\u{e9}\u{1f600}b".as_bytes(),
        "slicing does not re-encode the value it reads"
    );
}

#[test]
fn text_identity_is_the_scalar_sequence() {
    let from_octets = admitted("a\u{e9}".as_bytes());
    let scalars = [scalar("a"), scalar("\u{e9}")];
    let from_scalars = TextValue::from_scalars(&scalars);
    assert_eq!(from_scalars, from_octets);
    assert_eq!(
        from_scalars.canonical_octets(),
        from_octets.canonical_octets()
    );
    assert!(admitted(b"a") < admitted(b"b"));
    assert!(admitted(b"b") < admitted("\u{e9}".as_bytes()));
    assert!(admitted("\u{e9}".as_bytes()) < admitted("\u{1f600}".as_bytes()));
    assert_eq!(TextValue::empty(), TextValue::from_scalars(&[]));
}

#[test]
fn text_note_names_every_declared_clause_and_the_diagnostic() {
    let note = read_workspace_file("docs/text-foundation.md");
    for clause in TEXT_CLAUSES {
        assert!(note.contains(clause), "the note names `{clause}`");
    }
    for diagnostic in EXPECTED_DIAGNOSTICS {
        assert!(
            note.contains(diagnostic),
            "the note names the registered diagnostic `{diagnostic}`"
        );
    }
    // Prose assertions read the note with its whitespace flattened, so re-wrapping a paragraph
    // cannot change whether the note declares a non-claim.
    let flat = note.split_whitespace().collect::<Vec<_>>().join(" ");
    for phrase in [
        "no grapheme-cluster segmentation",
        "no case folding",
        "no regular expression",
        "no locale",
        "no compatibility form",
        "no `String` method",
    ] {
        assert!(flat.contains(phrase), "the note declares `{phrase}`");
    }
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn slice(value: &TextValue, start: usize, end: usize) -> TextValue {
    value
        .slice_scalars(start, end)
        .unwrap_or_else(|| panic!("`{start}..{end}` is a scalar-boundary slice"))
}

fn scalar(text: &str) -> CharValue {
    let mut scalars = text.chars();
    let (Some(value), None) = (scalars.next(), scalars.next()) else {
        panic!("`{text}` is exactly one scalar value");
    };
    CharValue::new(u32::from(value))
        .unwrap_or_else(|error| panic!("`{text}` is an admitted scalar: {error}"))
}

fn rendered(value: &TextValue) -> String {
    String::from_utf8(value.canonical_octets().to_vec())
        .unwrap_or_else(|error| panic!("the canonical octets are UTF-8: {error}"))
}

fn read_workspace_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("`{}` is readable: {error}", path.display()))
}
