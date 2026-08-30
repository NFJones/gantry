//! Command-line entry point for Gantry.

mod services;

/// Starts the Gantry command-line application.
fn main() {
    let _ = services::SystemIdentitySource;
    let _ = services::SystemUtcClock;
    println!("gantry: agent-control language for Mezzanine");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use gantry::diagnostic::{DiagnosticRenderOptions, render_diagnostic};
    use gantry::portable::{DiagnosticCategory, DiagnosticSeverity};
    use gantry::source::{
        ByteSpan, DiagnosticCode, DiagnosticMetadata, DiagnosticPhase, SourceLimits,
        SourceSnapshotBuilder, SourceSpan, StructuredDiagnostic,
    };

    #[test]
    fn cli_composition_defaults_to_source_redaction() {
        let limits = SourceLimits::new(1, 32, 32, 1, 1);
        assert!(limits.is_ok());
        let mut builder =
            SourceSnapshotBuilder::new(limits.unwrap_or_else(|_| unreachable!("checked above")));
        let source_id = builder.add_file("main.gnt", b"SECRET");
        assert!(source_id.is_ok());
        let snapshot = builder.finish();
        let source = snapshot.get(&source_id.unwrap_or_else(|_| unreachable!("checked above")));
        assert!(source.is_some());
        let primary = SourceSpan::new(
            source.unwrap_or_else(|| unreachable!("checked above")),
            ByteSpan::new(0, 6).unwrap_or_else(|_| unreachable!("ordered span")),
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
            "unexpected token",
            Some(primary.unwrap_or_else(|_| unreachable!("checked above"))),
            Vec::new(),
            BTreeMap::new(),
        );
        assert!(diagnostic.is_ok());
        let rendered = render_diagnostic(
            &diagnostic.unwrap_or_else(|_| unreachable!("checked above")),
            &snapshot,
            DiagnosticRenderOptions::default(),
        );
        assert!(rendered.is_ok());
        assert!(
            !rendered
                .unwrap_or_else(|_| unreachable!("checked above"))
                .text
                .contains("SECRET")
        );
    }
}
