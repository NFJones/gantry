//! Independent public-surface coverage for immutable sources and diagnostics.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::portable::{DiagnosticCategory, DiagnosticSeverity, FrontendResourceCode};
use gantry::source::{
    ByteSpan, DiagnosticBuffer, DiagnosticBufferError, DiagnosticCode, DiagnosticMetadata,
    DiagnosticPhase, FrontendResourceLimit, PackagePath, RelatedSpan, SourceCounters, SourceError,
    SourceLimits, SourceSnapshotBuilder, SourceSpan, StructuredDiagnostic,
    validate_diagnostic_code_registry,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SourceVectors {
    format: String,
    paths: Vec<PathVector>,
    spans: Vec<SpanVector>,
    limits: Vec<LimitVector>,
}

#[derive(Debug, Deserialize)]
struct PathVector {
    input: String,
    accepted: bool,
}

#[derive(Debug, Deserialize)]
struct SpanVector {
    source: String,
    start: u64,
    end: u64,
    expected: Option<String>,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LimitVector {
    kind: String,
    limit: u64,
    charges: Vec<u64>,
    expected_count: u64,
    expected_error: Option<String>,
}

#[test]
fn source_limits_are_atomic_at_boundaries_and_on_overflow() {
    let limits = SourceLimits::new(2, 4, 7, 2, 2);
    assert!(limits.is_ok());
    let mut builder =
        SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    assert!(builder.add_file("main.gnt", b"1234").is_ok());
    assert!(builder.add_file("a.gnt", b"123").is_ok());
    assert_eq!(builder.counters_mut().counts(), (2, 7, 0, 0));
    let failure = builder.add_file("b.gnt", b"1");
    assert!(matches!(
        failure,
        Err(SourceError::ResourceLimit(FrontendResourceLimit {
            code: FrontendResourceCode::PackageFileCountLimit,
            limit: 2,
            observed: Some(3),
        }))
    ));
    assert_eq!(builder.counters_mut().counts(), (2, 7, 0, 0));

    let counters = builder.counters_mut();
    assert!(counters.charge_tokens(2).is_ok());
    assert!(matches!(
        counters.charge_tokens(u64::MAX),
        Err(FrontendResourceLimit {
            code: FrontendResourceCode::SourceTokenLimit,
            observed: None,
            ..
        })
    ));
    assert_eq!(counters.counts(), (2, 7, 2, 0));
}

#[test]
fn malformed_utf8_and_multibyte_spans_keep_exact_bytes() {
    let limits = SourceLimits::new(2, 16, 32, 1, 1);
    assert!(limits.is_ok());
    let mut builder =
        SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    let invalid = builder.add_file("invalid.gnt", &[b'a', 0xff, b'z']);
    let valid = builder.add_file("main.gnt", "aéz".as_bytes());
    assert!(invalid.is_ok() && valid.is_ok());
    let snapshot = builder.finish();
    let invalid = snapshot.get(&invalid.unwrap_or_else(|_| unreachable!()));
    assert!(invalid.is_some());
    let utf8 = invalid.unwrap_or_else(|| unreachable!()).text().err();
    assert!(utf8.is_some());
    assert_eq!(utf8.unwrap_or_else(|| unreachable!()).valid_up_to, 1);

    let valid = snapshot.get(&valid.unwrap_or_else(|_| unreachable!()));
    assert!(valid.is_some());
    let valid = valid.unwrap_or_else(|| unreachable!());
    let span = ByteSpan::new(1, 3);
    assert!(span.is_ok());
    assert_eq!(
        valid.text_slice(span.unwrap_or_else(|_| unreachable!())),
        Ok("é")
    );
}

#[test]
fn diagnostics_are_disclosure_neutral_and_deterministically_bounded() {
    assert_eq!(validate_diagnostic_code_registry(), Ok(()));
    let limits = SourceLimits::new(1, 64, 64, 1, 2);
    assert!(limits.is_ok());
    let mut builder =
        SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    let source_text = "SECRET source";
    let source = builder.add_file("main.gnt", source_text.as_bytes());
    assert!(source.is_ok());
    let snapshot = builder.finish();
    let source = snapshot.get(&source.unwrap_or_else(|_| unreachable!()));
    assert!(source.is_some());
    let source = source.unwrap_or_else(|| unreachable!());
    let first = SourceSpan::new(
        source,
        ByteSpan::new(0, 1).unwrap_or_else(|_| unreachable!()),
    );
    let second = SourceSpan::new(
        source,
        ByteSpan::new(2, 3).unwrap_or_else(|_| unreachable!()),
    );
    assert!(first.is_ok() && second.is_ok());
    let first = first.unwrap_or_else(|_| unreachable!());
    let second = second.unwrap_or_else(|_| unreachable!());
    let diagnostic = StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Syntax,
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::Syntax,
            code: DiagnosticCode::new("unexpected-token").unwrap_or_else(|_| unreachable!()),
        },
        "unexpected token",
        Some(first.clone()),
        vec![RelatedSpan {
            label: "previous-token".into(),
            span: second,
        }],
        BTreeMap::from([("expected".into(), "identifier".into())]),
    );
    assert!(diagnostic.is_ok());
    let diagnostic = diagnostic.unwrap_or_else(|_| unreachable!());
    assert!(!format!("{diagnostic:?}").contains(source_text));

    let mut buffer = DiagnosticBuffer::new(1).unwrap_or_else(|_| unreachable!());
    assert!(buffer.push(diagnostic.clone()).is_ok());
    assert!(matches!(
        buffer.push(diagnostic),
        Err(DiagnosticBufferError::ResourceLimit(limit))
            if limit.code == FrontendResourceCode::DiagnosticCountLimit
    ));
    assert_eq!(buffer.diagnostics().len(), 1);
}

#[test]
fn canonical_source_vectors_match_the_public_substrate() {
    let root = workspace_root();
    let schema: serde_json::Value =
        read_json(&root.join("protocol/schemas/source-substrate-v1.schema.json"));
    assert_eq!(
        schema["$id"],
        "https://gantry.invalid/protocol/source-substrate/v1/schema.json"
    );
    assert_eq!(
        schema["properties"]["format"]["const"],
        "gantry.source-substrate-vectors/v1"
    );

    let vectors: SourceVectors =
        read_json(&root.join("protocol/goldens/source-substrate-vectors-v1.json"));
    assert_eq!(vectors.format, "gantry.source-substrate-vectors/v1");
    for vector in vectors.paths {
        assert_eq!(PackagePath::new(&vector.input).is_ok(), vector.accepted);
    }
    for vector in vectors.spans {
        let byte_len = u64::try_from(vector.source.len()).unwrap_or(u64::MAX);
        let limits = SourceLimits::new(1, byte_len.max(1), byte_len.max(1), 1, 1);
        assert!(limits.is_ok());
        let mut builder =
            SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
        let id = builder.add_file("main.gnt", vector.source.as_bytes());
        assert!(id.is_ok());
        let snapshot = builder.finish();
        let record = snapshot.get(&id.unwrap_or_else(|_| unreachable!("checked above")));
        assert!(record.is_some());
        let span = ByteSpan::new(vector.start, vector.end);
        assert!(span.is_ok());
        let result = record
            .unwrap_or_else(|| unreachable!("checked above"))
            .text_slice(span.unwrap_or_else(|_| unreachable!("checked above")));
        assert_eq!(
            result.as_ref().map(|value| (*value).to_owned()).ok(),
            vector.expected
        );
        assert_eq!(
            result.err().map(|error| error.to_string()),
            vector.expected_error
        );
    }
    for vector in vectors.limits {
        validate_limit_vector(&vector);
    }
}

fn validate_limit_vector(vector: &LimitVector) {
    let maximum = i64::MAX as u64;
    let limits = match vector.kind.as_str() {
        "package-files" => SourceLimits::new(vector.limit, maximum, maximum, maximum, maximum),
        "file-bytes" => SourceLimits::new(maximum, vector.limit, maximum, maximum, maximum),
        "package-bytes" => SourceLimits::new(maximum, maximum, vector.limit, maximum, maximum),
        "tokens" => SourceLimits::new(maximum, maximum, maximum, vector.limit, maximum),
        "diagnostics" => SourceLimits::new(maximum, maximum, maximum, maximum, vector.limit),
        _ => unreachable!("schema restricts limit kinds"),
    };
    assert!(limits.is_ok());
    let mut counters =
        SourceCounters::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    let mut failure = None;
    for charge in &vector.charges {
        let result = match vector.kind.as_str() {
            "package-files" => {
                let mut result = Ok(());
                for _ in 0..*charge {
                    result = counters.admit_file(0);
                    if result.is_err() {
                        break;
                    }
                }
                result
            }
            "file-bytes" | "package-bytes" => counters.admit_file(*charge),
            "tokens" => counters.charge_tokens(*charge),
            "diagnostics" => {
                let mut result = Ok(());
                for _ in 0..*charge {
                    result = counters.charge_diagnostic();
                    if result.is_err() {
                        break;
                    }
                }
                result
            }
            _ => unreachable!("schema restricts limit kinds"),
        };
        if let Err(error) = result {
            failure = Some(error.code.wire_name().to_owned());
            break;
        }
    }
    let counts = counters.counts();
    let actual_count = match vector.kind.as_str() {
        "package-files" => counts.0,
        "file-bytes" | "package-bytes" => counts.1,
        "tokens" => counts.2,
        "diagnostics" => counts.3,
        _ => unreachable!("schema restricts limit kinds"),
    };
    assert_eq!(actual_count, vector.expected_count);
    assert_eq!(failure, vector.expected_error);
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path);
    assert!(bytes.is_ok(), "could not read {}", path.display());
    let value =
        bytes.and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other));
    assert!(value.is_ok(), "could not decode {}", path.display());
    value.unwrap_or_else(|_| unreachable!("checked above"))
}
