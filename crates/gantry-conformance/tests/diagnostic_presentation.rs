//! External coverage for safe, disclosure-controlled diagnostic presentation.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::diagnostic::{
    DiagnosticRenderError, DiagnosticRenderOptions, SourceDisclosure, render_diagnostic,
};
use gantry::portable::{DiagnosticCategory, DiagnosticSeverity};
use gantry::source::{
    ByteSpan, DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, SourceLimits,
    SourceSnapshotBuilder, SourceSpan, StructuredDiagnostic,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MachineFixture {
    format: String,
    case: String,
    diagnostic: MachineDiagnostic,
}

#[derive(Debug, Deserialize)]
struct MachineDiagnostic {
    phase: String,
    severity: String,
    category: String,
    code: String,
    message: String,
    primary: MachineSpan,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct MachineSpan {
    path: String,
    start: u64,
    end: u64,
}

#[derive(Debug, Deserialize)]
struct PresentationFixture {
    format: String,
    case: String,
    source: PresentationSource,
    hidden: String,
    disclosed: String,
}

#[derive(Debug, Deserialize)]
struct PresentationSource {
    path: String,
    text: String,
}

#[test]
fn rendering_derives_multibyte_locations_and_requires_explicit_source_disclosure() {
    let source_text = "α\nlet secret = \u{202e}hidden;\n";
    let limits = SourceLimits::new(1, 128, 128, 1, 1);
    assert!(limits.is_ok());
    let mut builder =
        SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    let source_id = builder.add_file("main.gnt", source_text.as_bytes());
    assert!(source_id.is_ok());
    let snapshot = builder.finish();
    let source = snapshot.get(&source_id.unwrap_or_else(|_| unreachable!("checked above")));
    assert!(source.is_some());
    let source = source.unwrap_or_else(|| unreachable!("checked above"));
    let start = source_text
        .find("secret")
        .and_then(|offset| u64::try_from(offset).ok());
    assert!(start.is_some());
    let start = start.unwrap_or_else(|| unreachable!("checked above"));
    let primary = SourceSpan::new(
        source,
        ByteSpan::new(start, start + 6).unwrap_or_else(|_| unreachable!("ordered span")),
    );
    assert!(primary.is_ok());
    let diagnostic = StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Syntax,
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::Syntax,
            code: DiagnosticCode::new("unexpected-token")
                .unwrap_or_else(|_| unreachable!("valid code")),
        },
        "unexpected \u{202e} token",
        Some(primary.unwrap_or_else(|_| unreachable!("checked above"))),
        Vec::new(),
        BTreeMap::from([("expected".into(), "identifier\nname".into())]),
    );
    assert!(diagnostic.is_ok());
    let diagnostic = diagnostic.unwrap_or_else(|_| unreachable!("checked above"));

    let hidden = render_diagnostic(&diagnostic, &snapshot, DiagnosticRenderOptions::default());
    assert!(hidden.is_ok());
    let hidden = hidden.unwrap_or_else(|_| unreachable!("checked above"));
    assert!(hidden.text.contains("main.gnt:2:5-2:11"));
    assert!(!hidden.text.contains("secret"));
    assert!(hidden.text.contains("<U+202E>"));
    assert!(hidden.text.contains("<U+000A>"));
    assert!(!hidden.text.contains('\u{202e}'));

    let disclosed = render_diagnostic(
        &diagnostic,
        &snapshot,
        DiagnosticRenderOptions {
            source_disclosure: SourceDisclosure::Include,
        },
    );
    assert!(disclosed.is_ok());
    let disclosed = disclosed.unwrap_or_else(|_| unreachable!("checked above"));
    assert!(disclosed.text.contains("secret"));
    assert!(!disclosed.text.contains('\u{202e}'));

    assert_eq!(diagnostic.code.as_str(), "unexpected-token");
    assert_eq!(
        diagnostic.fields.get("expected").map(AsRef::as_ref),
        Some("identifier\nname")
    );
}

#[test]
fn reviewed_machine_and_presentation_goldens_match_independently() {
    let root = workspace_root();
    let machine: MachineFixture =
        read_json(&root.join("protocol/goldens/diagnostic-machine-v1.json"));
    let presentation: PresentationFixture =
        read_json(&root.join("protocol/goldens/diagnostic-presentation-v1.json"));

    assert_eq!(machine.format, "gantry.diagnostic-machine/v1");
    assert_eq!(presentation.format, "gantry.diagnostic-presentation/v1");
    assert_eq!(machine.case, presentation.case);
    assert_eq!(machine.diagnostic.phase, "syntax");
    assert_eq!(machine.diagnostic.severity, "error");
    assert_eq!(machine.diagnostic.category, "syntax");
    assert_eq!(machine.diagnostic.code, "unexpected-token");
    assert_eq!(machine.diagnostic.primary.path, presentation.source.path);

    let limits = SourceLimits::new(1, 128, 128, 1, 1);
    assert!(limits.is_ok());
    let mut builder =
        SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    let source_id = builder.add_file(
        &presentation.source.path,
        presentation.source.text.as_bytes(),
    );
    assert!(source_id.is_ok());
    let snapshot = builder.finish();
    let source = snapshot.get(&source_id.unwrap_or_else(|_| unreachable!("checked above")));
    assert!(source.is_some());
    let primary = SourceSpan::new(
        source.unwrap_or_else(|| unreachable!("checked above")),
        ByteSpan::new(
            machine.diagnostic.primary.start,
            machine.diagnostic.primary.end,
        )
        .unwrap_or_else(|_| unreachable!("fixture span is ordered")),
    );
    assert!(primary.is_ok());
    let diagnostic = StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Syntax,
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::Syntax,
            code: DiagnosticCode::new(&machine.diagnostic.code)
                .unwrap_or_else(|_| unreachable!("fixture code is valid")),
        },
        machine.diagnostic.message,
        Some(primary.unwrap_or_else(|_| unreachable!("checked above"))),
        Vec::new(),
        machine
            .diagnostic
            .fields
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect(),
    );
    assert!(diagnostic.is_ok());
    let diagnostic = diagnostic.unwrap_or_else(|_| unreachable!("checked above"));

    let hidden = render_diagnostic(&diagnostic, &snapshot, DiagnosticRenderOptions::default());
    assert!(hidden.is_ok());
    assert_eq!(
        hidden
            .unwrap_or_else(|_| unreachable!("checked above"))
            .text,
        presentation.hidden
    );
    let disclosed = render_diagnostic(
        &diagnostic,
        &snapshot,
        DiagnosticRenderOptions {
            source_disclosure: SourceDisclosure::Include,
        },
    );
    assert!(disclosed.is_ok());
    assert_eq!(
        disclosed
            .unwrap_or_else(|_| unreachable!("checked above"))
            .text,
        presentation.disclosed
    );

    assert_eq!(diagnostic.phase.wire_name(), "syntax");
    assert_eq!(diagnostic.severity.wire_name(), "error");
    assert_eq!(diagnostic.category.wire_name(), "syntax");
    assert_eq!(diagnostic.code.as_str(), "unexpected-token");
    assert_eq!(
        diagnostic.fields.get("expected").map(AsRef::as_ref),
        Some("identifier\nname")
    );
}

#[test]
fn invalid_utf8_missing_sources_and_split_scalars_fail_closed() {
    let limits = SourceLimits::new(1, 8, 8, 1, 1);
    assert!(limits.is_ok());

    let mut utf8_builder =
        SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
    let invalid_id = utf8_builder.add_file("invalid.gnt", &[0xff]);
    assert!(invalid_id.is_ok());
    let invalid_snapshot = utf8_builder.finish();
    let invalid =
        invalid_snapshot.get(&invalid_id.unwrap_or_else(|_| unreachable!("checked above")));
    assert!(invalid.is_some());
    let invalid_span = SourceSpan::new(
        invalid.unwrap_or_else(|| unreachable!("checked above")),
        ByteSpan::new(0, 1).unwrap_or_else(|_| unreachable!("ordered span")),
    );
    assert!(invalid_span.is_ok());
    let invalid_diagnostic =
        diagnostic_with_primary(invalid_span.unwrap_or_else(|_| unreachable!("checked above")));
    assert!(matches!(
        render_diagnostic(
            &invalid_diagnostic,
            &invalid_snapshot,
            DiagnosticRenderOptions::default()
        ),
        Err(DiagnosticRenderError::InvalidUtf8(_))
    ));

    let mut scalar_builder = SourceSnapshotBuilder::new(
        SourceLimits::new(1, 8, 8, 1, 1).unwrap_or_else(|_| unreachable!("valid limits")),
    );
    let scalar_id = scalar_builder.add_file("scalar.gnt", "é".as_bytes());
    assert!(scalar_id.is_ok());
    let scalar_snapshot = scalar_builder.finish();
    let scalar = scalar_snapshot.get(&scalar_id.unwrap_or_else(|_| unreachable!("checked above")));
    assert!(scalar.is_some());
    let split_span = SourceSpan::new(
        scalar.unwrap_or_else(|| unreachable!("checked above")),
        ByteSpan::new(1, 2).unwrap_or_else(|_| unreachable!("ordered span")),
    );
    assert!(split_span.is_ok());
    let split_diagnostic =
        diagnostic_with_primary(split_span.unwrap_or_else(|_| unreachable!("checked above")));
    assert_eq!(
        render_diagnostic(
            &split_diagnostic,
            &scalar_snapshot,
            DiagnosticRenderOptions::default()
        ),
        Err(DiagnosticRenderError::InvalidSpan(
            gantry::source::SpanError::NotCharacterBoundary
        ))
    );

    let empty_snapshot = SourceSnapshotBuilder::new(
        SourceLimits::new(1, 1, 1, 1, 1).unwrap_or_else(|_| unreachable!("valid limits")),
    )
    .finish();
    assert!(matches!(
        render_diagnostic(
            &split_diagnostic,
            &empty_snapshot,
            DiagnosticRenderOptions::default()
        ),
        Err(DiagnosticRenderError::MissingSource(_))
    ));
}

fn diagnostic_with_primary(primary: SourceSpan) -> StructuredDiagnostic {
    StructuredDiagnostic::new(
        DiagnosticMetadata {
            phase: DiagnosticPhase::Syntax,
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::Syntax,
            code: DiagnosticCode::new("invalid-source-span")
                .unwrap_or_else(|_| unreachable!("valid code")),
        },
        "invalid source span",
        Some(primary),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap_or_else(|_| unreachable!("valid diagnostic"))
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
