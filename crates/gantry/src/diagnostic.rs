//! Human-facing diagnostic presentation over portable machine contracts.
//!
//! This module derives locations only from an immutable source snapshot and
//! keeps copied source text behind an explicit per-consumer disclosure choice.
//! Rendering never changes or replaces the structured diagnostic fields.

use std::fmt;

use gantry_core::source::{
    ByteSpan, SourceId, SourceRecord, SourceSnapshot, SpanError, StructuredDiagnostic,
    Utf8SourceError,
};

const FIRST_STRONG_ISOLATE: char = '\u{2068}';
const POP_DIRECTIONAL_ISOLATE: char = '\u{2069}';

/// Whether a diagnostic consumer may receive copied source text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SourceDisclosure {
    /// Report source identities, byte spans, and derived locations only.
    #[default]
    Omit,
    /// Include a terminal-safe copy of the primary source line.
    Include,
}

/// Presentation choices that do not alter machine-facing diagnostic fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticRenderOptions {
    /// Explicit source-snippet disclosure for this consumer.
    pub source_disclosure: SourceDisclosure,
}

/// A one-based human-facing source position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePosition {
    /// One-based line number.
    pub line: u64,
    /// One-based Unicode-scalar column number.
    pub column: u64,
}

/// Human-facing positions derived from one zero-based byte span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRange {
    /// Position at the inclusive byte-span start.
    pub start: SourcePosition,
    /// Position at the exclusive byte-span end.
    pub end: SourcePosition,
}

/// Complete terminal presentation for one structured diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedDiagnostic {
    /// Deterministic plain-text presentation.
    pub text: String,
}

/// Failure to derive a presentation from the supplied immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticRenderError {
    /// A diagnostic span names a source absent from the supplied snapshot.
    MissingSource(SourceId),
    /// The named immutable source is not valid UTF-8.
    InvalidUtf8(Utf8SourceError),
    /// A diagnostic offset is outside the source or splits a UTF-8 scalar.
    InvalidSpan(SpanError),
}

impl fmt::Display for DiagnosticRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSource(source) => {
                write!(formatter, "source {source} is not in the snapshot")
            }
            Self::InvalidUtf8(_) => formatter.write_str("diagnostic source is not valid UTF-8"),
            Self::InvalidSpan(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DiagnosticRenderError {}

/// Derives a one-based line and Unicode-scalar column range.
pub fn derive_source_range(
    source: &SourceRecord,
    span: ByteSpan,
) -> Result<SourceRange, DiagnosticRenderError> {
    if span.end() > source.byte_len() {
        return Err(DiagnosticRenderError::InvalidSpan(SpanError::OutOfBounds));
    }
    let text = source.text().map_err(DiagnosticRenderError::InvalidUtf8)?;
    let start = position_at(text, span.start())?;
    let end = position_at(text, span.end())?;
    Ok(SourceRange { start, end })
}

/// Renders one structured diagnostic without mutating its machine fields.
pub fn render_diagnostic(
    diagnostic: &StructuredDiagnostic,
    snapshot: &SourceSnapshot,
    options: DiagnosticRenderOptions,
) -> Result<RenderedDiagnostic, DiagnosticRenderError> {
    let mut text = String::new();
    text.push_str(diagnostic.severity.wire_name());
    text.push('[');
    text.push_str(diagnostic.code.as_str());
    text.push_str("] ");
    text.push_str(diagnostic.phase.wire_name());
    text.push('/');
    text.push_str(diagnostic.category.wire_name());
    text.push_str(": ");
    push_isolated_safe(&mut text, &diagnostic.message);
    text.push('\n');

    if let Some(primary) = &diagnostic.primary {
        let source = snapshot
            .get(primary.source())
            .ok_or_else(|| DiagnosticRenderError::MissingSource(primary.source().clone()))?;
        let range = derive_source_range(source, primary.bytes())?;
        text.push_str("  --> ");
        push_isolated_safe(&mut text, &format_range(source.id(), range));
        text.push('\n');
        if options.source_disclosure == SourceDisclosure::Include {
            text.push_str("  | ");
            push_isolated_safe(&mut text, primary_line(source, primary.bytes())?);
            text.push('\n');
        }
    }

    for related in &diagnostic.related {
        let source = snapshot
            .get(related.span.source())
            .ok_or_else(|| DiagnosticRenderError::MissingSource(related.span.source().clone()))?;
        let range = derive_source_range(source, related.span.bytes())?;
        text.push_str("  = ");
        push_isolated_safe(&mut text, &related.label);
        text.push_str(": ");
        push_isolated_safe(&mut text, &format_range(source.id(), range));
        text.push('\n');
    }

    for (key, value) in &diagnostic.fields {
        text.push_str("  ");
        push_terminal_safe(&mut text, key);
        text.push_str(": ");
        push_isolated_safe(&mut text, value);
        text.push('\n');
    }

    Ok(RenderedDiagnostic { text })
}

fn position_at(text: &str, offset: u64) -> Result<SourcePosition, DiagnosticRenderError> {
    let index = usize::try_from(offset)
        .map_err(|_| DiagnosticRenderError::InvalidSpan(SpanError::OutOfBounds))?;
    if index > text.len() {
        return Err(DiagnosticRenderError::InvalidSpan(SpanError::OutOfBounds));
    }
    if !text.is_char_boundary(index) {
        return Err(DiagnosticRenderError::InvalidSpan(
            SpanError::NotCharacterBoundary,
        ));
    }
    let mut line = 1_u64;
    let mut column = 1_u64;
    for scalar in text[..index].chars() {
        if scalar == '\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }
    Ok(SourcePosition { line, column })
}

fn format_range(source: &SourceId, range: SourceRange) -> String {
    format!(
        "{source}:{}:{}-{}:{}",
        range.start.line, range.start.column, range.end.line, range.end.column
    )
}

fn primary_line(source: &SourceRecord, span: ByteSpan) -> Result<&str, DiagnosticRenderError> {
    let text = source.text().map_err(DiagnosticRenderError::InvalidUtf8)?;
    let index = usize::try_from(span.start())
        .map_err(|_| DiagnosticRenderError::InvalidSpan(SpanError::OutOfBounds))?;
    if index > text.len() || !text.is_char_boundary(index) {
        return Err(DiagnosticRenderError::InvalidSpan(if index > text.len() {
            SpanError::OutOfBounds
        } else {
            SpanError::NotCharacterBoundary
        }));
    }
    let line_start = text[..index].rfind('\n').map_or(0, |offset| offset + 1);
    let line_end = text[index..]
        .find('\n')
        .map_or(text.len(), |offset| index + offset);
    Ok(text[line_start..line_end]
        .strip_suffix('\r')
        .unwrap_or(&text[line_start..line_end]))
}

fn push_isolated_safe(output: &mut String, value: &str) {
    output.push(FIRST_STRONG_ISOLATE);
    push_terminal_safe(output, value);
    output.push(POP_DIRECTIONAL_ISOLATE);
}

fn push_terminal_safe(output: &mut String, value: &str) {
    for scalar in value.chars() {
        if scalar.is_control() || is_bidi_control(scalar) {
            output.push_str(&format!("<U+{:04X}>", scalar as u32));
        } else {
            output.push(scalar);
        }
    }
}

const fn is_bidi_control(scalar: char) -> bool {
    matches!(
        scalar,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}
