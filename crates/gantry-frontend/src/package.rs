//! Immutable multi-file package discovery and syntax-only validation.
//!
//! File modules are discovered from successfully parsed authored syntax in
//! deterministic declaration order. Each selected file is copied exactly once
//! into the activity snapshot before lexing, parsing, spans, or diagnostics use
//! its bytes.

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use gantry_core::event::{EventContractError, EventDraft, EventPayload};
use gantry_core::portable::EventKind;
use gantry_core::source::{
    FrontendResourceLimit, PackagePath, SourceError, SourceId, SourceLimits, SourceSnapshot,
    StructuredDiagnostic,
};

use crate::ast::{SyntaxForm, SyntaxTree};
use crate::parser::{ParseError, Parser};
use crate::provider::{PackageSnapshotLoader, RootDirectorySourceProvider, SourceProviderError};
use crate::token::{Punctuation, TokenKind};

/// Syntax-only judgment for one immutable package snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageSyntaxStatus {
    /// Every reachable source file parsed successfully.
    Valid,
    /// A reachable source file produced lexical or syntax diagnostics.
    Invalid,
}

impl PackageSyntaxStatus {
    /// Returns the exact embedding result spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Valid => "syntax-valid",
            Self::Invalid => "syntax-invalid",
        }
    }
}

/// One successfully parsed selected source file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedSource {
    source: SourceId,
    tree: SyntaxTree,
}

impl ParsedSource {
    /// Returns the immutable source identity.
    #[must_use]
    pub const fn source(&self) -> &SourceId {
        &self.source
    }

    /// Returns the authored-order surface syntax tree.
    #[must_use]
    pub const fn tree(&self) -> &SyntaxTree {
        &self.tree
    }
}

/// Completed syntax-validation phase before occurrence metadata is allocated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedSyntaxPhase {
    status: PackageSyntaxStatus,
    diagnostics: Vec<StructuredDiagnostic>,
    snapshot: SourceSnapshot,
    parsed_sources: Vec<ParsedSource>,
    event_draft: EventDraft,
}

impl CompletedSyntaxPhase {
    /// Returns the syntax-only package judgment.
    #[must_use]
    pub const fn status(&self) -> PackageSyntaxStatus {
        self.status
    }

    /// Returns diagnostics in deterministic discovery and source order.
    #[must_use]
    pub fn diagnostics(&self) -> &[StructuredDiagnostic] {
        &self.diagnostics
    }

    /// Returns the immutable selected source snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &SourceSnapshot {
        &self.snapshot
    }

    /// Returns successfully parsed sources in deterministic discovery order.
    #[must_use]
    pub fn parsed_sources(&self) -> &[ParsedSource] {
        &self.parsed_sources
    }

    /// Returns the canonical physical-layer parse event draft.
    #[must_use]
    pub const fn event_draft(&self) -> &EventDraft {
        &self.event_draft
    }
}

/// Operational failure before the syntax phase can produce a package judgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageSyntaxError {
    /// Package-root or selected-source discovery failed.
    Source(SourceProviderError),
    /// A configured frontend limit or parser invariant prevented completion.
    Parse(ParseError),
    /// The deterministic parse payload violated the core event contract.
    Event(EventContractError),
    /// Parsed module syntax did not preserve an expected internal shape.
    Invariant,
}

impl fmt::Display for PackageSyntaxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source(_) => "package source discovery failed",
            Self::Parse(_) => "package syntax phase failed operationally",
            Self::Event(_) => "parse event payload construction failed",
            Self::Invariant => "package syntax invariant failure",
        })
    }
}

impl std::error::Error for PackageSyntaxError {}

impl PackageSyntaxError {
    /// Returns the exact frontend limit outcome when one prevented completion.
    #[must_use]
    pub const fn frontend_resource_limit(&self) -> Option<FrontendResourceLimit> {
        match self {
            Self::Source(SourceProviderError::ResourceLimit(error))
            | Self::Source(SourceProviderError::Source(SourceError::ResourceLimit(error)))
            | Self::Parse(ParseError::ResourceLimit(error)) => Some(*error),
            _ => None,
        }
    }

    /// Returns the stable operational category for embedding and CLI mapping.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        if self.frontend_resource_limit().is_some() {
            return "frontend-resource-limit";
        }
        match self {
            Self::Source(_) => "package-source-failure",
            Self::Parse(_) | Self::Event(_) | Self::Invariant => "internal",
        }
    }
}

/// Discovers and parses every reachable file module from one package root.
pub fn validate_package_syntax(
    package_root: &std::path::Path,
    limits: SourceLimits,
) -> Result<CompletedSyntaxPhase, PackageSyntaxError> {
    let provider =
        RootDirectorySourceProvider::open(package_root).map_err(PackageSyntaxError::Source)?;
    let mut loader = PackageSnapshotLoader::new(&provider, limits);
    let root = loader
        .load("main.gnt")
        .map_err(PackageSyntaxError::Source)?;
    let mut pending = VecDeque::from([root]);
    let mut seen_requests = BTreeSet::new();
    let mut parsed_sources = Vec::new();
    let mut diagnostics = Vec::new();

    while let Some(source) = pending.pop_front() {
        let (record, counters) = loader.record_and_counters_mut(&source);
        let record = record.ok_or(PackageSyntaxError::Invariant)?;
        let outcome = Parser::new(record, counters)
            .parse_module()
            .map_err(PackageSyntaxError::Parse)?;
        diagnostics.extend_from_slice(outcome.diagnostics());
        let valid = outcome.is_valid();
        let Some(tree) = outcome.recovered_tree().cloned() else {
            continue;
        };
        let directory = source_module_directory(source.package_path())?;
        let requests = file_module_requests(&tree, &directory)?;
        if valid {
            parsed_sources.push(ParsedSource {
                source: source.clone(),
                tree,
            });
        }
        for request in requests {
            if !seen_requests.insert((request.directory.clone(), request.name.clone())) {
                continue;
            }
            let declaring = conceptual_declaring_source(&request.directory)?;
            let read_limits = loader
                .next_source_read_limits()
                .map_err(PackageSyntaxError::Source)?;
            let resolution = provider
                .resolve_module_bounded(&declaring, &request.name, read_limits)
                .map_err(PackageSyntaxError::Source)?;
            let child = loader
                .add_resolution(resolution)
                .map_err(PackageSyntaxError::Source)?;
            pending.push_back(child);
        }
    }

    let status = if diagnostics.is_empty() {
        PackageSyntaxStatus::Valid
    } else {
        PackageSyntaxStatus::Invalid
    };
    let event_payload =
        EventPayload::from_validated_canonical_bytes(parse_payload(status, &diagnostics))
            .map_err(PackageSyntaxError::Event)?;
    let event_draft = EventDraft::new(EventKind::Parse, event_payload);
    Ok(CompletedSyntaxPhase {
        status,
        diagnostics,
        snapshot: loader.finish(),
        parsed_sources,
        event_draft,
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModuleRequest {
    directory: String,
    name: String,
}

fn file_module_requests(
    tree: &SyntaxTree,
    source_directory: &str,
) -> Result<Vec<ModuleRequest>, PackageSyntaxError> {
    let root = tree
        .node(tree.root())
        .ok_or(PackageSyntaxError::Invariant)?;
    let mut work = root
        .children()
        .iter()
        .rev()
        .copied()
        .map(|node| (node, source_directory.to_owned()))
        .collect::<Vec<_>>();
    let mut requests = Vec::new();
    while let Some((node_id, directory)) = work.pop() {
        let node = tree.node(node_id).ok_or(PackageSyntaxError::Invariant)?;
        if !matches!(node.form(), SyntaxForm::ModuleDeclaration) {
            continue;
        }
        let name = node
            .children()
            .iter()
            .filter_map(|child| tree.node(*child))
            .find_map(|child| match child.form() {
                SyntaxForm::Token(TokenKind::Identifier(value)) => Some(value.to_string()),
                _ => None,
            })
            .ok_or(PackageSyntaxError::Invariant)?;
        let file_module = node
            .children()
            .iter()
            .filter_map(|child| tree.node(*child))
            .any(|child| {
                matches!(
                    child.form(),
                    SyntaxForm::Token(TokenKind::Punctuation(Punctuation::Semicolon))
                )
            });
        if file_module {
            requests.push(ModuleRequest { directory, name });
            continue;
        }
        let nested_directory = join_directory(&directory, &name);
        for child in node.children().iter().rev().copied() {
            work.push((child, nested_directory.clone()));
        }
    }
    Ok(requests)
}

fn source_module_directory(path: &PackagePath) -> Result<String, PackageSyntaxError> {
    let path = path.as_str();
    if path == "main.gnt" {
        return Ok(String::new());
    }
    if let Some(parent) = path.strip_suffix("/mod.gnt") {
        return Ok(parent.to_owned());
    }
    path.strip_suffix(".gnt")
        .map(str::to_owned)
        .ok_or(PackageSyntaxError::Invariant)
}

fn conceptual_declaring_source(directory: &str) -> Result<PackagePath, PackageSyntaxError> {
    let path = if directory.is_empty() {
        "main.gnt".to_owned()
    } else {
        format!("{directory}/mod.gnt")
    };
    PackagePath::new(&path).map_err(|_| PackageSyntaxError::Invariant)
}

fn join_directory(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

fn parse_payload(status: PackageSyntaxStatus, diagnostics: &[StructuredDiagnostic]) -> Arc<[u8]> {
    let mut json = String::from("{\"diagnostics\":[");
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        if index != 0 {
            json.push(',');
        }
        json.push_str("{\"category\":");
        push_json_string(&mut json, diagnostic.category.wire_name());
        json.push_str(",\"code\":");
        push_json_string(&mut json, diagnostic.code.as_str());
        json.push_str(",\"fields\":{");
        for (field_index, (key, value)) in diagnostic.fields.iter().enumerate() {
            if field_index != 0 {
                json.push(',');
            }
            push_json_string(&mut json, key);
            json.push(':');
            push_json_string(&mut json, value);
        }
        json.push_str("},\"message\":");
        push_json_string(&mut json, &diagnostic.message);
        json.push_str(",\"phase\":");
        push_json_string(&mut json, diagnostic.phase.wire_name());
        json.push_str(",\"primary\":");
        if let Some(primary) = &diagnostic.primary {
            json.push_str("{\"end\":");
            json.push_str(&primary.bytes().end().to_string());
            json.push_str(",\"path\":");
            push_json_string(&mut json, primary.source().package_path().as_str());
            json.push_str(",\"start\":");
            json.push_str(&primary.bytes().start().to_string());
            json.push('}');
        } else {
            json.push_str("null");
        }
        json.push_str(",\"related\":[");
        for (related_index, related) in diagnostic.related.iter().enumerate() {
            if related_index != 0 {
                json.push(',');
            }
            json.push_str("{\"end\":");
            json.push_str(&related.span.bytes().end().to_string());
            json.push_str(",\"label\":");
            push_json_string(&mut json, &related.label);
            json.push_str(",\"path\":");
            push_json_string(&mut json, related.span.source().package_path().as_str());
            json.push_str(",\"start\":");
            json.push_str(&related.span.bytes().start().to_string());
            json.push('}');
        }
        json.push(']');
        json.push_str(",\"severity\":");
        push_json_string(&mut json, diagnostic.severity.wire_name());
        json.push('}');
    }
    json.push_str("],\"phase\":\"parse\",\"status\":");
    push_json_string(&mut json, status.wire_name());
    json.push('}');
    Arc::from(json.into_bytes())
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use gantry_core::portable::FrontendResourceCode;
    use gantry_core::source::SourceLimits;

    use super::{PackageSyntaxError, PackageSyntaxStatus, validate_package_syntax};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-package-syntax-{}-{suffix}",
                std::process::id()
            ));
            assert!(fs::create_dir(&path).is_ok());
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits(files: u64, package_bytes: u64) -> SourceLimits {
        SourceLimits::new(files, 4_096, package_bytes, 1_024, 32)
            .unwrap_or_else(|_| unreachable!("positive limits"))
    }

    #[test]
    fn discovers_file_modules_through_inline_module_directories() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"mod outer { mod child; }").is_ok());
        assert!(fs::create_dir(root.0.join("outer")).is_ok());
        assert!(fs::write(root.0.join("outer/child.gnt"), b"fn child() {}").is_ok());

        let phase = validate_package_syntax(&root.0, limits(2, 4_096));
        assert!(phase.is_ok());
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(phase.status(), PackageSyntaxStatus::Valid);
        assert_eq!(phase.snapshot().records().len(), 2);
        assert_eq!(phase.parsed_sources().len(), 2);
        assert_eq!(
            phase.snapshot().records()[1].id().package_path().as_str(),
            "outer/child.gnt"
        );
        assert_eq!(phase.event_draft().kind().wire_name(), "parse");
        assert_eq!(
            std::str::from_utf8(phase.event_draft().payload().canonical_bytes()),
            Ok("{\"diagnostics\":[],\"phase\":\"parse\",\"status\":\"syntax-valid\"}")
        );
    }

    #[test]
    fn syntax_diagnostics_produce_one_invalid_phase_payload() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"fn broken( {}").is_ok());

        let phase = validate_package_syntax(&root.0, limits(1, 4_096));
        assert!(phase.is_ok());
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(phase.status(), PackageSyntaxStatus::Invalid);
        assert_eq!(phase.diagnostics().len(), 1);
        assert!(
            std::str::from_utf8(phase.event_draft().payload().canonical_bytes())
                .is_ok_and(|payload| payload.contains("\"status\":\"syntax-invalid\""))
        );
    }

    #[test]
    fn valid_module_declarations_survive_other_item_recovery() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"mod child;\nfn broken( {").is_ok());
        assert!(fs::write(root.0.join("child.gnt"), b"fn also_broken( {").is_ok());

        let phase = validate_package_syntax(&root.0, limits(2, 4_096));
        assert!(phase.is_ok());
        let phase = phase.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(phase.status(), PackageSyntaxStatus::Invalid);
        assert_eq!(phase.snapshot().records().len(), 2);
        assert_eq!(phase.diagnostics().len(), 2);
        assert_eq!(
            phase.diagnostics()[0]
                .primary
                .as_ref()
                .map(|span| span.source().package_path().as_str()),
            Some("main.gnt")
        );
        assert_eq!(
            phase.diagnostics()[1]
                .primary
                .as_ref()
                .map(|span| span.source().package_path().as_str()),
            Some("child.gnt")
        );
    }

    #[test]
    fn cumulative_module_bytes_fail_as_an_operational_limit() {
        let root = TempDirectory::new();
        assert!(fs::write(root.0.join("main.gnt"), b"mod child;").is_ok());
        assert!(fs::write(root.0.join("child.gnt"), b"fn child() {}").is_ok());

        let phase = validate_package_syntax(&root.0, limits(2, 20));
        assert!(matches!(
            phase,
            Err(PackageSyntaxError::Source(error))
                if matches!(
                    error,
                    crate::SourceProviderError::ResourceLimit(limit)
                        if limit.code == FrontendResourceCode::PackageSourceByteLimit
                )
        ));
    }
}
