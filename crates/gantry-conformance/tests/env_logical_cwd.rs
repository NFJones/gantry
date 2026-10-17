//! Conformance for the portable `std.env::working_directory` value model.
//!
//! The lane covers the value-only CWD slice: rooted logical values, explicit root and relative
//! composition, normalization with escape refusal, exact finite bounds, declared target encoding
//! and ASCII case policy, refusal of implicit native forms, and the data-only boundary. It performs
//! no host I/O, reads no ambient process state, and creates no directory handle or authority.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    CWD_DEFAULT_MAX_PATH_BYTES, CWD_DEFAULT_MAX_SEGMENT_BYTES, CWD_DEFAULT_MAX_SEGMENTS,
    CWD_TARGET_POLICIES, CWD_VALUE_CONTRACT_VERSION, CwdCasePolicy, CwdComparison,
    CwdDiagnosticCode, CwdEncodingPolicy, CwdError, CwdLimits, CwdTargetPolicy, ENV_ITEMS,
    LogicalCwdRoot, LogicalCwdSegment, LogicalWorkingDirectory,
};

/// The portable specification anchors this value model implements.
const REQUIRED_ANCHORS: [&str; 3] = [
    "GNT-30.2-bounded-launch-snapshot-and-capability-closure",
    "GNT-30.3-arguments-environment-and-logical-cwd",
    "GNT-49.0-environment-foundation-scope",
];

/// Returns the repository root from the conformance crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reads one repository file, panicking with the path on failure.
fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Collapses every whitespace run so a published sentence can be pinned across line wrapping.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns the declared default bounds.
fn declared() -> CwdLimits {
    CwdLimits::declared()
}

/// Returns a small bound set used to reach every boundary cheaply.
fn tight() -> CwdLimits {
    CwdLimits::new(16, 3, 4)
        .unwrap_or_else(|error| panic!("the tight CWD bounds are valid: {error}"))
}

/// Admits one value or panics with the refusal.
fn cwd(root: &str, text: &str, limits: &CwdLimits) -> LogicalWorkingDirectory {
    LogicalWorkingDirectory::from_text(root, text, limits)
        .unwrap_or_else(|error| panic!("the logical path `{text}` is admitted: {error}"))
}

/// Returns the refusal code of a result that must be refused.
fn refusal<T>(result: Result<T, CwdError>) -> CwdDiagnosticCode {
    match result {
        Ok(_) => panic!("the presented logical path value must be refused"),
        Err(error) => error.code(),
    }
}

/// The value contract is closed, adds no `std.env` row, and reuses existing anchors.
#[test]
fn cwd_value_contract_is_closed_and_publishes_no_new_module_row() {
    assert_eq!(CWD_VALUE_CONTRACT_VERSION, 1);
    assert_eq!(CWD_DEFAULT_MAX_PATH_BYTES, 4_096);
    assert_eq!(CWD_DEFAULT_MAX_SEGMENTS, 256);
    assert_eq!(CWD_DEFAULT_MAX_SEGMENT_BYTES, 255);
    let bounds = declared();
    assert_eq!(bounds.max_path_bytes(), CWD_DEFAULT_MAX_PATH_BYTES);
    assert_eq!(bounds.max_segments(), CWD_DEFAULT_MAX_SEGMENTS);
    assert_eq!(bounds.max_segment_bytes(), CWD_DEFAULT_MAX_SEGMENT_BYTES);

    // The CWD value model adds no `std.env` module row; that vocabulary is owned elsewhere.
    assert_eq!(ENV_ITEMS.len(), 3);

    let codes = CwdDiagnosticCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(codes.len(), CwdDiagnosticCode::ALL.len());
    assert!(
        CwdDiagnosticCode::ALL
            .iter()
            .all(|code| code.as_str().starts_with("cwd-"))
    );

    assert_eq!(
        CwdEncodingPolicy::ALL,
        [CwdEncodingPolicy::Ascii, CwdEncodingPolicy::Utf8]
    );
    assert_eq!(
        CwdCasePolicy::ALL,
        [CwdCasePolicy::AsciiInsensitive, CwdCasePolicy::Sensitive]
    );
    assert_eq!(
        CwdComparison::ALL,
        [
            CwdComparison::Different,
            CwdComparison::DifferentRoot,
            CwdComparison::Equal,
            CwdComparison::EqualUnderCaseFolding,
        ]
    );
    let policies = CWD_TARGET_POLICIES
        .iter()
        .map(|policy| policy.wire_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(policies.len(), CWD_TARGET_POLICIES.len());
    assert_eq!(CwdTargetPolicy::PORTABLE.wire_name(), "utf8/sensitive");

    let specification = read_text(&workspace_root().join("SPEC.md"));
    for anchor in REQUIRED_ANCHORS {
        assert!(
            specification.contains(&format!("id=\"{anchor}\"")),
            "SPEC.md already anchors {anchor}"
        );
    }
}

/// Root and segment admission refuses malformed, native, and oversize presentations exactly.
#[test]
fn cwd_roots_and_segments_refuse_malformed_forms() {
    let bounds = declared();
    assert_eq!(
        refusal(LogicalCwdRoot::new("", &bounds)),
        CwdDiagnosticCode::InvalidRoot
    );
    for root in [
        "Workspace",
        "work space",
        "work/space",
        "work:space",
        "-work",
    ] {
        assert_eq!(
            refusal(LogicalCwdRoot::new(root, &bounds)),
            CwdDiagnosticCode::InvalidRoot
        );
    }
    assert_eq!(
        refusal(LogicalCwdRoot::new(&"a".repeat(256), &bounds)),
        CwdDiagnosticCode::LimitExceeded
    );
    for root in ["a", "w0_1", "workspace"] {
        assert!(
            LogicalCwdRoot::new(root, &bounds).is_ok(),
            "the portable root `{root}` is admitted"
        );
    }

    for segment in ["", ".", "..", "a/b", "a\\b", "a:b", "a\nb", "\0"] {
        assert_eq!(
            refusal(LogicalCwdSegment::new(segment, &bounds)),
            CwdDiagnosticCode::InvalidSegment,
            "the segment `{segment}` must be refused"
        );
    }
    assert_eq!(
        refusal(LogicalCwdSegment::new(&"a".repeat(256), &bounds)),
        CwdDiagnosticCode::LimitExceeded
    );
    for segment in ["a", "~", "$HOME", "é", "file.txt"] {
        assert!(
            LogicalCwdSegment::new(segment, &bounds).is_ok(),
            "the exact segment `{segment}` is admitted"
        );
    }

    assert_eq!(
        refusal(LogicalWorkingDirectory::from_bytes(
            "workspace",
            &[0xff],
            &bounds
        )),
        CwdDiagnosticCode::InvalidEncoding
    );
}

/// Portable text is rooted, normalized explicitly, and never resolved against a host.
#[test]
fn cwd_from_text_is_rooted_and_normalized() {
    let bounds = declared();
    for text in ["/a//./b/", "a/b", "/a/b"] {
        let value = cwd("workspace", text, &bounds);
        assert_eq!(value.as_text(), "workspace/a/b");
        assert_eq!(value.relative_text(), "/a/b");
        assert_eq!(
            value
                .segments()
                .iter()
                .map(LogicalCwdSegment::as_str)
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    for text in ["", ".", "/", "/./"] {
        let value = cwd("workspace", text, &bounds);
        assert!(value.is_root());
        assert_eq!(value.segment_count(), 0);
        assert_eq!(value.as_text(), "workspace");
        assert_eq!(value.relative_text(), "/");
    }

    assert_eq!(
        refusal(LogicalWorkingDirectory::from_text(
            "workspace",
            "/../a",
            &bounds
        )),
        CwdDiagnosticCode::Escape
    );
    for text in ["////", "//server/share", "/a\\b", "C:/work", "a:b"] {
        assert_eq!(
            refusal(LogicalWorkingDirectory::from_text(
                "workspace",
                text,
                &bounds
            )),
            CwdDiagnosticCode::NativeForm,
            "the native form `{text}` must be refused rather than translated"
        );
    }
}

/// Explicit relative composition normalizes, pops within the root, and refuses escape.
#[test]
fn cwd_composition_is_explicit_and_refuses_escape() {
    let bounds = declared();
    let base = cwd("workspace", "/a/b", &bounds);

    assert_eq!(
        base.compose("../c")
            .unwrap_or_else(|error| panic!("the in-root composition is admitted: {error}"))
            .as_text(),
        "workspace/a/c"
    );
    assert_eq!(
        base.compose("./d")
            .unwrap_or_else(|error| panic!("the child composition is admitted: {error}"))
            .as_text(),
        "workspace/a/b/d"
    );
    assert_eq!(
        base.compose("../../x")
            .unwrap_or_else(|error| panic!("the root composition is admitted: {error}"))
            .as_text(),
        "workspace/x"
    );
    assert_eq!(
        base.compose("/x/../y")
            .unwrap_or_else(|error| panic!("the root-relative composition is admitted: {error}"))
            .as_text(),
        "workspace/y"
    );
    assert_eq!(
        base.compose("")
            .unwrap_or_else(|error| panic!("the empty composition is admitted: {error}")),
        base
    );
    assert_eq!(
        base.compose(".")
            .unwrap_or_else(|error| panic!("the dot composition is admitted: {error}")),
        base
    );
    for text in ["../../..", "/../x"] {
        assert_eq!(
            refusal(base.compose(text)),
            CwdDiagnosticCode::Escape,
            "the composition `{text}` must not escape"
        );
    }
    assert_eq!(
        refusal(cwd("workspace", "", &bounds).compose("..")),
        CwdDiagnosticCode::Escape,
        "a `..` at the declared root must not escape"
    );

    // Composition returns a new value and leaves the receiver exact.
    assert_eq!(base.as_text(), "workspace/a/b");
    assert_eq!(base.segment_count(), 2);
}

/// The presented-text, canonical path, segment-count, and segment-byte bounds are exact.
#[test]
fn cwd_bounds_are_exact_at_and_beyond_the_boundary() {
    for index in 0..3 {
        let mut values = [16, 3, 4];
        values[index] = 0;
        assert_eq!(
            refusal(CwdLimits::new(values[0], values[1], values[2])),
            CwdDiagnosticCode::LimitExceeded
        );
    }
    let bounds = tight();
    let exact = cwd("root", "/abcd/abcd/e", &bounds);
    assert_eq!(exact.as_text(), "root/abcd/abcd/e");
    assert_eq!(exact.as_text().len(), 16);
    assert_eq!(exact.segment_count(), 3);

    assert_eq!(
        refusal(LogicalWorkingDirectory::from_text(
            "root",
            "/abcd/abcd/ef",
            &bounds
        )),
        CwdDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refusal(LogicalWorkingDirectory::from_text(
            "root", "/a/b/c/d", &bounds
        )),
        CwdDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refusal(LogicalWorkingDirectory::from_text(
            "root", "/abcde", &bounds
        )),
        CwdDiagnosticCode::LimitExceeded
    );
    assert_eq!(
        refusal(LogicalWorkingDirectory::from_text(
            "root",
            "/abcdefghijklmnopq",
            &bounds
        )),
        CwdDiagnosticCode::LimitExceeded
    );
}

/// Target encoding and case behavior is selected explicitly and folds only ASCII uppercase.
#[test]
fn cwd_target_policy_is_explicit_and_ascii_only() {
    let bounds = declared();
    let ascii_sensitive = CwdTargetPolicy::new(CwdEncodingPolicy::Ascii, CwdCasePolicy::Sensitive);
    let ascii_folded =
        CwdTargetPolicy::new(CwdEncodingPolicy::Ascii, CwdCasePolicy::AsciiInsensitive);
    let utf8_folded =
        CwdTargetPolicy::new(CwdEncodingPolicy::Utf8, CwdCasePolicy::AsciiInsensitive);

    let upper = cwd("workspace", "/A", &bounds);
    let lower = cwd("workspace", "/a", &bounds);
    assert_eq!(
        upper
            .compare_under(&lower, ascii_sensitive)
            .unwrap_or_else(|error| panic!("the sensitive comparison is admitted: {error}")),
        CwdComparison::Different
    );
    assert_eq!(
        upper
            .compare_under(&lower, ascii_folded)
            .unwrap_or_else(|error| panic!("the folded comparison is admitted: {error}")),
        CwdComparison::EqualUnderCaseFolding
    );
    assert_eq!(
        upper
            .compare_under(&upper, CwdTargetPolicy::PORTABLE)
            .unwrap_or_else(|error| panic!("the exact comparison is admitted: {error}")),
        CwdComparison::Equal
    );
    assert_eq!(
        upper
            .compare_under(&cwd("other", "/A", &bounds), CwdTargetPolicy::PORTABLE)
            .unwrap_or_else(|error| panic!("the root comparison is admitted: {error}")),
        CwdComparison::DifferentRoot
    );
    assert_eq!(
        upper
            .compare_under(
                &cwd("workspace", "/A/b", &bounds),
                CwdTargetPolicy::PORTABLE
            )
            .unwrap_or_else(|error| panic!("the segment-count comparison is admitted: {error}")),
        CwdComparison::Different
    );

    // ASCII-only folding leaves non-ASCII scalars exact, so this is not locale-sensitive.
    let unicode_upper = cwd("workspace", "/É", &bounds);
    let unicode_lower = cwd("workspace", "/é", &bounds);
    assert_eq!(
        unicode_upper
            .compare_under(&unicode_lower, utf8_folded)
            .unwrap_or_else(|error| panic!("the UTF-8 folded comparison is admitted: {error}")),
        CwdComparison::Different
    );
    assert_eq!(
        refusal(unicode_upper.admit_under(ascii_sensitive)),
        CwdDiagnosticCode::UnsupportedEncoding
    );
    assert!(unicode_upper.admit_under(CwdTargetPolicy::PORTABLE).is_ok());
    assert_eq!(
        refusal(unicode_upper.compare_under(&unicode_lower, ascii_folded)),
        CwdDiagnosticCode::UnsupportedEncoding
    );

    // Case policy never changes a stored value.
    assert_eq!(upper.as_text(), "workspace/A");
    assert_eq!(lower.as_text(), "workspace/a");
    assert_eq!(
        CwdEncodingPolicy::from_wire_name("ascii"),
        Some(CwdEncodingPolicy::Ascii)
    );
    assert_eq!(
        CwdCasePolicy::from_wire_name("sensitive"),
        Some(CwdCasePolicy::Sensitive)
    );
    assert_eq!(CwdEncodingPolicy::from_wire_name("latin1"), None);
}

/// Path text is data only: no native conversion, expansion, or hidden authority.
#[test]
fn cwd_text_is_data_and_grants_no_authority() {
    let bounds = declared();
    assert_eq!(cwd("workspace", "/~/x", &bounds).as_text(), "workspace/~/x");
    assert_eq!(
        cwd("workspace", "/$HOME", &bounds).as_text(),
        "workspace/$HOME"
    );
    assert_ne!(
        cwd("workspace", "/x", &bounds),
        cwd("other", "/x", &bounds),
        "the declared root is part of the exact value"
    );

    // Admission bounds are not part of value identity.
    let wide = cwd("root", "/x", &declared());
    let narrow = cwd("root", "/x", &tight());
    assert_eq!(wide, narrow);
    assert_ne!(wide.limits(), narrow.limits());

    // The canonical spelling is exactly the admitted root and segments, with no host prefix.
    let value = cwd("workspace", "/a/b", &bounds);
    assert_eq!(value.as_text(), "workspace/a/b");
    assert_eq!(value.relative_text(), "/a/b");
    assert_eq!(value.root().as_str(), "workspace");
}

/// The published note states the landed value contract and its data-only boundaries.
#[test]
fn cwd_note_publishes_the_value_contract_boundaries() {
    let note = flatten(&read_text(
        &workspace_root().join("docs/env-logical-working-directory.md"),
    ));
    for anchor in REQUIRED_ANCHORS {
        assert!(note.contains(anchor), "the note must cite {anchor}");
    }
    for phrase in [
        "rooted portable logical working-directory values",
        "explicit root and relative composition",
        "normalization refuses escape",
        "target encoding and case policy is explicit",
        "no implicit native or text conversion",
        "carries no directory authority",
        "no ambient process state",
        "crates/gantry-conformance/tests/env_logical_cwd.rs",
    ] {
        assert!(
            note.to_lowercase().contains(&phrase.to_lowercase()),
            "the note must state: {phrase}"
        );
    }
}
