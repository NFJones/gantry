//! Pure declaration model for Section 31 source metadata.
//!
//! This module validates bounded, identity-aware metadata records. It is not a
//! parser, formatter, documentation renderer, example executor, compiler
//! plugin, generator, LSP, or runtime facility.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use crate::package::PublicInterfaceManifest;
use gantry_core::mode::SemanticMode;

pub const SOURCE_METADATA_CLAUSES: [&str; 13] = [
    "GNT-31.0-source-metadata-documentation-attributes-and-lint-policy",
    "GNT-31.1-metadata-subject-and-doc-comment-attachment",
    "GNT-31.2-documentation-format-links-and-bounds",
    "GNT-31.3-checked-example-declarations",
    "GNT-31.4-deprecation-through-aliases-and-reexports",
    "GNT-31.5-closed-semantic-attributes",
    "GNT-31.6-namespaced-tool-metadata",
    "GNT-31.7-stable-lint-identities-and-severity",
    "GNT-31.8-scoped-lint-controls-and-suppression",
    "GNT-31.9-dependency-warning-policy",
    "GNT-31.10-generated-code-origins",
    "GNT-31.11-metadata-diagnostics-and-determinism",
    "GNT-31.12-source-metadata-non-claims",
];

const MAX_SUBJECT_BYTES: usize = 256;
const MAX_DOCUMENTATION_BYTES: usize = 16_384;
const MAX_TOOL_VALUE_BYTES: usize = 4_096;

macro_rules! closed {
    ($name:ident, [$($variant:ident => $text:literal),+ $(,)?]) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: [Self; <[()]>::len(&[$(closed!(@unit $variant)),+])] = [$(Self::$variant),+];
            #[must_use] pub const fn wire_name(self) -> &'static str { match self { $(Self::$variant => $text),+ } }
            #[must_use] pub fn from_wire_name(value: &str) -> Option<Self> { Self::ALL.into_iter().find(|item| item.wire_name() == value) }
        }
    };
    (@unit $_:ident) => { () };
}

closed!(DocumentationFormat, [Markdown => "markdown", PlainText => "plain-text"]);
closed!(DocumentationBoundary, [Leading => "leading", Trailing => "trailing", Detached => "detached"]);
closed!(ExampleMode, [Compile => "compile", CompileFail => "compile-fail", DisplayOnly => "display-only"]);
closed!(SemanticAttribute, [Entry => "entry", Export => "export", Test => "test"]);
closed!(LintSeverity, [Allow => "allow", Deny => "deny", Forbid => "forbid", Warn => "warn"]);
closed!(LintScope, [Dependency => "dependency", Item => "item", Package => "package"]);
closed!(DependencyWarningPolicy, [Deny => "deny", Ignore => "ignore", Inherit => "inherit", Warn => "warn"]);

/// Admits one presented compiler-owned semantic attribute (`GNT-31.5`).
///
/// The declared attribute set is closed and payload-free: an unknown spelling or any presented
/// payload is refused rather than preserved for a future compiler.
pub fn admit_semantic_attribute(
    spelling: &str,
    payload: Option<&str>,
) -> Result<SemanticAttribute, MetadataError> {
    let attribute = SemanticAttribute::from_wire_name(spelling)
        .ok_or(MetadataError::UnknownSemanticAttribute)?;
    if payload.is_some() {
        return Err(MetadataError::UnknownSemanticAttribute);
    }
    Ok(attribute)
}

/// Resolves one documentation link against one frozen Section 16 interface (`GNT-31.2`).
///
/// The link names one package-qualified target (`package::item`). The presented package name and
/// the target interface must agree, and the named target must be recorded and exported there; an
/// unknown, invisible, or foreign-package target is refused rather than resolved through an
/// import, display label, filesystem path, or renderer convention.
pub fn resolve_documentation_link(
    link: &DocumentationLink,
    package: &str,
    interface: &PublicInterfaceManifest,
) -> Result<MetadataSubject, MetadataError> {
    let (qualified, item) = link
        .target()
        .split_once("::")
        .ok_or(MetadataError::InvalidLink)?;
    if package.is_empty() || qualified != package || !interface.is_exported(item) {
        return Err(MetadataError::InvalidLink);
    }
    MetadataSubject::new(link.target())
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MetadataSubject(String);

impl MetadataSubject {
    pub fn new(value: impl Into<String>) -> Result<Self, MetadataError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SUBJECT_BYTES {
            return Err(MetadataError::InvalidSubject);
        }
        Ok(Self(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentationLink(String);
impl DocumentationLink {
    pub fn new(value: impl Into<String>) -> Result<Self, MetadataError> {
        let value = value.into();
        if value.len() > MAX_SUBJECT_BYTES
            || value.split("::").count() != 2
            || value.split("::").any(str::is_empty)
        {
            return Err(MetadataError::InvalidLink);
        }
        Ok(Self(value))
    }
    #[must_use]
    pub fn target(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentationComment {
    subject: MetadataSubject,
    format: DocumentationFormat,
    text: String,
    links: Vec<DocumentationLink>,
}
impl DocumentationComment {
    pub fn new(
        subject: MetadataSubject,
        format: DocumentationFormat,
        text: impl Into<String>,
        links: Vec<DocumentationLink>,
    ) -> Result<Self, MetadataError> {
        let text = text.into();
        if text.is_empty() || text.len() > MAX_DOCUMENTATION_BYTES || links.len() > 64 {
            return Err(MetadataError::InvalidDocumentationAttachment);
        }
        Ok(Self {
            subject,
            format,
            text,
            links,
        })
    }
    #[must_use]
    pub fn subject(&self) -> &MetadataSubject {
        &self.subject
    }
    #[must_use]
    pub const fn format(&self) -> DocumentationFormat {
        self.format
    }
    #[must_use]
    pub fn links(&self) -> &[DocumentationLink] {
        &self.links
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExampleDeclaration {
    mode: ExampleMode,
    semantic_mode: Option<SemanticMode>,
    source: String,
}
impl ExampleDeclaration {
    pub fn new(
        mode: ExampleMode,
        semantic_mode: Option<SemanticMode>,
        source: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let source = source.into();
        let semantic_mode_is_valid = match mode {
            ExampleMode::Compile | ExampleMode::CompileFail => semantic_mode.is_some(),
            ExampleMode::DisplayOnly => semantic_mode.is_none(),
        };
        if source.is_empty() || source.len() > MAX_DOCUMENTATION_BYTES || !semantic_mode_is_valid {
            return Err(MetadataError::ExampleLimitExceeded);
        }
        Ok(Self {
            mode,
            semantic_mode,
            source,
        })
    }
    #[must_use]
    pub const fn mode(&self) -> ExampleMode {
        self.mode
    }
    #[must_use]
    pub const fn semantic_mode(&self) -> Option<SemanticMode> {
        self.semantic_mode
    }
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deprecation {
    deprecated: MetadataSubject,
    replacement: MetadataSubject,
    message: String,
}
impl Deprecation {
    pub fn new(
        deprecated: MetadataSubject,
        replacement: MetadataSubject,
        message: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let message = message.into();
        if deprecated == replacement || message.len() > MAX_DOCUMENTATION_BYTES {
            return Err(MetadataError::InvalidDeprecation);
        }
        Ok(Self {
            deprecated,
            replacement,
            message,
        })
    }
    #[must_use]
    pub fn deprecated(&self) -> &MetadataSubject {
        &self.deprecated
    }
    #[must_use]
    pub fn replacement(&self) -> &MetadataSubject {
        &self.replacement
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolMetadata {
    namespace: String,
    key: String,
    value: String,
}
impl ToolMetadata {
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let (namespace, key, value) = (namespace.into(), key.into(), value.into());
        if namespace.is_empty()
            || !namespace.is_ascii()
            || key.is_empty()
            || value.len() > MAX_TOOL_VALUE_BYTES
        {
            return Err(MetadataError::InvalidToolMetadata);
        }
        Ok(Self {
            namespace,
            key,
            value,
        })
    }
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LintId(String);
impl LintId {
    pub fn new(value: impl Into<String>) -> Result<Self, MetadataError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SUBJECT_BYTES {
            return Err(MetadataError::DuplicateLint);
        }
        Ok(Self(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LintDeclaration {
    subject: MetadataSubject,
    id: LintId,
    severity: LintSeverity,
    suppressible: bool,
}
impl LintDeclaration {
    #[must_use]
    pub fn new(
        subject: MetadataSubject,
        id: LintId,
        severity: LintSeverity,
        suppressible: bool,
    ) -> Self {
        Self {
            subject,
            id,
            severity,
            suppressible,
        }
    }
    #[must_use]
    pub fn id(&self) -> &LintId {
        &self.id
    }
    #[must_use]
    pub fn subject(&self) -> &MetadataSubject {
        &self.subject
    }
    #[must_use]
    pub const fn severity(&self) -> LintSeverity {
        self.severity
    }
}

pub fn admit_lint_control(
    lint: &LintDeclaration,
    scope: LintScope,
    severity: LintSeverity,
) -> Result<(LintScope, LintSeverity), MetadataError> {
    if (!lint.suppressible && severity != lint.severity)
        || lint.severity == LintSeverity::Forbid && severity != LintSeverity::Forbid
    {
        return Err(MetadataError::UnsuppressibleLint);
    }
    Ok((scope, severity))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedOrigin {
    generated: MetadataSubject,
    source: MetadataSubject,
    generator: String,
}
impl GeneratedOrigin {
    pub fn new(
        generated: MetadataSubject,
        source: MetadataSubject,
        generator: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let generator = generator.into();
        if generated == source || generator.is_empty() || generator.len() > MAX_SUBJECT_BYTES {
            return Err(MetadataError::InvalidGeneratedOrigin);
        }
        Ok(Self {
            generated,
            source,
            generator,
        })
    }
    #[must_use]
    pub fn generated(&self) -> &MetadataSubject {
        &self.generated
    }
    #[must_use]
    pub fn source(&self) -> &MetadataSubject {
        &self.source
    }
}

#[derive(Default)]
pub struct MetadataDeclarations {
    documentation: BTreeMap<MetadataSubject, DocumentationComment>,
    deprecated: BTreeSet<MetadataSubject>,
    tool_keys: BTreeSet<(MetadataSubject, String, String)>,
    lints: BTreeSet<(MetadataSubject, LintId)>,
    dependency_policies: BTreeMap<MetadataSubject, DependencyWarningPolicy>,
    generated: BTreeSet<MetadataSubject>,
}
impl MetadataDeclarations {
    pub fn attach(&mut self, comment: DocumentationComment) -> Result<(), MetadataError> {
        if self
            .documentation
            .insert(comment.subject.clone(), comment)
            .is_some()
        {
            return Err(MetadataError::InvalidDocumentationAttachment);
        }
        Ok(())
    }
    /// Attaches one documentation comment at its presented declaration boundary (`GNT-31.1`).
    ///
    /// Only the leading boundary is admissible: a trailing or detached comment is refused, and a
    /// duplicate or reattached comment for the same subject is refused by the leading admission.
    pub fn attach_at_boundary(
        &mut self,
        comment: DocumentationComment,
        boundary: DocumentationBoundary,
    ) -> Result<(), MetadataError> {
        if boundary != DocumentationBoundary::Leading {
            return Err(MetadataError::InvalidDocumentationAttachment);
        }
        self.attach(comment)
    }
    pub fn insert_tool_metadata(
        &mut self,
        subject: MetadataSubject,
        metadata: ToolMetadata,
    ) -> Result<(), MetadataError> {
        if !self
            .tool_keys
            .insert((subject, metadata.namespace, metadata.key))
        {
            return Err(MetadataError::InvalidToolMetadata);
        }
        Ok(())
    }
    pub fn insert_deprecation(&mut self, deprecation: &Deprecation) -> Result<(), MetadataError> {
        if !self.deprecated.insert(deprecation.deprecated.clone()) {
            return Err(MetadataError::InvalidDeprecation);
        }
        Ok(())
    }
    pub fn insert_lint(&mut self, lint: &LintDeclaration) -> Result<(), MetadataError> {
        if !self.lints.insert((lint.subject.clone(), lint.id.clone())) {
            return Err(MetadataError::DuplicateLint);
        }
        Ok(())
    }
    pub fn set_dependency_policy(
        &mut self,
        dependency: MetadataSubject,
        policy: DependencyWarningPolicy,
    ) -> Result<(), MetadataError> {
        if self
            .dependency_policies
            .insert(dependency, policy)
            .is_some()
        {
            return Err(MetadataError::InvalidDependencyWarningPolicy);
        }
        Ok(())
    }
    pub fn insert_origin(&mut self, origin: &GeneratedOrigin) -> Result<(), MetadataError> {
        if !self.generated.insert(origin.generated.clone()) {
            return Err(MetadataError::InvalidGeneratedOrigin);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataError {
    InvalidSubject,
    InvalidDocumentationAttachment,
    InvalidLink,
    ExampleLimitExceeded,
    InvalidDeprecation,
    UnknownSemanticAttribute,
    InvalidToolMetadata,
    DuplicateLint,
    UnsuppressibleLint,
    InvalidDependencyWarningPolicy,
    InvalidGeneratedOrigin,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetadataDiagnosticCode {
    InvalidSubject,
    InvalidDocumentationAttachment,
    InvalidLink,
    ExampleLimitExceeded,
    InvalidDeprecation,
    UnknownSemanticAttribute,
    InvalidToolMetadata,
    DuplicateLint,
    UnsuppressibleLint,
    InvalidDependencyWarningPolicy,
    InvalidGeneratedOrigin,
}
impl MetadataDiagnosticCode {
    pub const ALL: [Self; 11] = [
        Self::InvalidSubject,
        Self::InvalidDocumentationAttachment,
        Self::InvalidLink,
        Self::ExampleLimitExceeded,
        Self::InvalidDeprecation,
        Self::UnknownSemanticAttribute,
        Self::InvalidToolMetadata,
        Self::DuplicateLint,
        Self::UnsuppressibleLint,
        Self::InvalidDependencyWarningPolicy,
        Self::InvalidGeneratedOrigin,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSubject => "metadata-invalid-subject",
            Self::InvalidDocumentationAttachment => "metadata-invalid-doc-attachment",
            Self::InvalidLink => "metadata-invalid-link",
            Self::ExampleLimitExceeded => "metadata-example-limit-exceeded",
            Self::InvalidDeprecation => "metadata-invalid-deprecation",
            Self::UnknownSemanticAttribute => "metadata-unknown-semantic-attribute",
            Self::InvalidToolMetadata => "metadata-invalid-tool-metadata",
            Self::DuplicateLint => "metadata-duplicate-lint",
            Self::UnsuppressibleLint => "metadata-unsuppressible-lint",
            Self::InvalidDependencyWarningPolicy => "metadata-invalid-dependency-warning-policy",
            Self::InvalidGeneratedOrigin => "metadata-invalid-generated-origin",
        }
    }
}
