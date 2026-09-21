//! Public conformance for the canonical grapheme clusters of
//! `GNT-41.7-canonical-grapheme-clusters`, whose pure model is `crates/gantry-ir/src/text.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{CaseMapping, TEXT_CLAUSES, TextValue};

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
const GRAPHEME_CLAUSE: &str = "GNT-41.7-canonical-grapheme-clusters";

#[test]
fn grapheme_clause_publishes_the_forward_cluster_cursor() {
    let specification = read_workspace_file("SPEC.md");
    assert_eq!(TEXT_CLAUSES, EXPECTED_CLAUSES);
    let body = clause_body(&specification, GRAPHEME_CLAUSE);
    for declaration in [
        "`graphemes` publishes a cursor over a text value",
        "`next_cluster` publishes the next extended grapheme cluster as a text value",
        "`remaining` publishes the number of clusters the cursor has not yet published",
        "The clusters partition the value's scalar sequence",
    ] {
        assert!(
            body.contains(declaration),
            "the clause declares `{declaration}`"
        );
    }
    for citation in [
        "`GNT-41.1-canonical-text-values`",
        "`GNT-41.2-canonical-text-normalization`",
        "`GNT-41.3-canonical-text-case-mapping`",
    ] {
        assert!(body.contains(citation), "the clause cites {citation}");
    }
}

#[test]
fn grapheme_clusters_partition_the_value_exactly() {
    let sample = [
        "",
        "a",
        "a\u{301}",
        "\r\n",
        "\u{1f1e6}\u{1f1e7}\u{1f1e8}",
        "e\u{301}\u{1f600}",
        "\u{915}\u{94d}\u{937}",
        "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
        "ok\u{301}\u{1f1e6}",
    ];
    for text in sample {
        let value = admitted(text.as_bytes());
        let clusters = clusters_of(&value);
        assert_eq!(clusters.concat(), text, "the clusters rejoin the value");
        assert!(
            clusters.iter().all(|cluster| !cluster.is_empty()),
            "no cluster of `{text}` is empty"
        );
        let scalars: usize = clusters.iter().map(|cluster| cluster.chars().count()).sum();
        assert_eq!(
            scalars,
            value.scalar_count(),
            "every scalar lies in one cluster"
        );
        let mut cursor = value.graphemes();
        assert_eq!(cursor.remaining(), clusters.len());
        let mut observed = 0_usize;
        while let Some(cluster) = cursor.next_cluster() {
            observed += 1;
            assert_eq!(cursor.remaining(), clusters.len() - observed);
            assert!(!cluster.is_empty(), "a published cluster holds a scalar");
        }
        assert_eq!(observed, clusters.len());
        assert_eq!(cursor.remaining(), 0);
        assert!(cursor.next_cluster().is_none());
    }
    let empty = admitted(b"");
    assert!(clusters_of(&empty).is_empty());
    assert_eq!(empty.graphemes().remaining(), 0);
}

#[test]
fn grapheme_clusters_match_the_pinned_unicode_vectors() {
    let text =
        read_workspace_file("third_party/unicode/16.0.0/ucd/auxiliary/GraphemeBreakTest.txt");
    let mut cases = 0_usize;
    for line in text.lines() {
        let body = line.split('#').next().unwrap_or_default().trim();
        if body.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = body.split_whitespace().collect();
        let mut scalars = String::new();
        let mut expected: Vec<usize> = Vec::new();
        let mut index = 0_usize;
        while index + 1 < tokens.len() {
            let marker = tokens[index];
            let code = tokens[index + 1];
            assert!(
                marker == "÷" || marker == "×",
                "malformed marker {marker:?}"
            );
            if marker == "÷" {
                expected.push(scalars.chars().count());
            }
            let (start, end) = pinned_range(code);
            for value in start..=end {
                scalars.push(
                    char::from_u32(value)
                        .unwrap_or_else(|| panic!("U+{value:04X} is a Unicode scalar")),
                );
            }
            index += 2;
        }
        // The vector ends with the end-of-text marker, which every rule set breaks on.
        let last = tokens.last().copied().unwrap_or_default();
        assert!(last == "÷" || last == "×", "malformed end marker {last:?}");
        if last == "÷" {
            expected.push(scalars.chars().count());
        }
        let value = admitted(scalars.as_bytes());
        let observed = clusters_of(&value);
        let mut rebuilt = String::new();
        let mut positions = vec![0_usize];
        for cluster in &observed {
            rebuilt.push_str(cluster);
            positions.push(rebuilt.chars().count());
        }
        assert_eq!(
            rebuilt, scalars,
            "vector {cases} preserves its scalar sequence"
        );
        assert_eq!(positions, expected, "vector {cases} boundaries");
        cases += 1;
    }
    assert!(
        cases > 1000,
        "the pinned vectors were exercised: {cases} cases"
    );
}

#[test]
fn grapheme_clusters_are_decided_on_the_value_scalar_sequence() {
    let composed = admitted("\u{e9}".as_bytes());
    let decomposed = admitted("e\u{301}".as_bytes());
    assert_eq!(clusters_of(&composed), vec!["\u{e9}".to_owned()]);
    assert_eq!(clusters_of(&decomposed), vec!["e\u{301}".to_owned()]);
    let recorded = composed.canonical_octets().to_vec();
    assert_eq!(clusters_of(&composed), vec!["\u{e9}".to_owned()]);
    assert_eq!(composed.canonical_octets(), recorded.as_slice());
    let sharp = admitted("\u{df}".as_bytes());
    let upper = sharp.map_case(CaseMapping::Upper);
    assert_eq!(clusters_of(&sharp), vec!["\u{df}".to_owned()]);
    assert_eq!(clusters_of(&upper), vec!["S".to_owned(), "S".to_owned()]);
    assert_eq!(sharp.canonical_octets(), "\u{df}".as_bytes());
}

#[test]
fn grapheme_cursor_publishes_in_order_and_advances_independently() {
    let value = admitted("a\u{301}b".as_bytes());
    let mut first = value.graphemes();
    let mut second = value.graphemes();
    assert_eq!(first.remaining(), 2);
    let head = first
        .next_cluster()
        .unwrap_or_else(|| panic!("the first cluster is published"));
    assert_eq!(head.canonical_octets(), "a\u{301}".as_bytes());
    assert_eq!(first.remaining(), 1);
    assert_eq!(second.remaining(), 2, "cursors advance independently");
    let same = second
        .next_cluster()
        .unwrap_or_else(|| panic!("the second cursor publishes the first cluster"));
    assert_eq!(same, head);
    let tail = first
        .next_cluster()
        .unwrap_or_else(|| panic!("the second cluster is published"));
    assert_eq!(tail.canonical_octets(), b"b");
    assert!(first.next_cluster().is_none());
    assert_eq!(
        second
            .next_cluster()
            .map(|cluster| cluster.canonical_octets().to_vec()),
        Some(b"b".to_vec())
    );
    assert_eq!(value.canonical_octets(), "a\u{301}b".as_bytes());
}

fn clusters_of(value: &TextValue) -> Vec<String> {
    let mut cursor = value.graphemes();
    let mut clusters = Vec::new();
    while let Some(cluster) = cursor.next_cluster() {
        clusters.push(String::from_utf8_lossy(cluster.canonical_octets()).into_owned());
    }
    clusters
}

fn admitted(octets: &[u8]) -> TextValue {
    TextValue::from_octets(octets)
        .unwrap_or_else(|error| panic!("`{octets:?}` is admitted: {error}"))
}

fn pinned_range(value: &str) -> (u32, u32) {
    match value.split_once("..") {
        Some((start, end)) => (pinned_code(start), pinned_code(end)),
        None => {
            let code = pinned_code(value);
            (code, code)
        }
    }
}

fn pinned_code(value: &str) -> u32 {
    u32::from_str_radix(value, 16)
        .unwrap_or_else(|error| panic!("`{value}` is a hexadecimal code point: {error}"))
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
