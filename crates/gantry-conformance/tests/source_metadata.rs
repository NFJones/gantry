//! Machine-checked conformance for the pure Section 31 source metadata model.
//!
//! These tests validate declarations only; they do not parse, render, execute,
//! generate code, run lints, or invoke editor services.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::ir::{
    ConstructionPolicy, DeclaredSurface, DependencyDiagnosticClass, DependencyWarningPolicy,
    Deprecation, DocumentationBoundary, DocumentationComment, DocumentationFormat,
    DocumentationLink, ExampleDeclaration, ExampleMode, ExhaustivenessPolicy, GeneratedOrigin,
    InterfaceItem, InterfaceMetadata, InterfaceSeal, ItemKind, LintControlSet, LintDeclaration,
    LintId, LintScope, LintSeverity, MetadataDeclarations, MetadataDiagnosticCode, MetadataError,
    MetadataSubject, NominalFacts, PublicInterfaceManifest, SOURCE_METADATA_CLAUSES,
    SelectedFeatureSet, SemanticAttribute, SemanticMode, TargetKind, ToolMetadata, Visibility,
    admit_lint_control, admit_semantic_attribute, dependency_policy_ignores,
    resolve_documentation_link,
};
use gantry::protocol::ProtocolVersion;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("workspace root"))
        .to_path_buf()
}

fn subject(value: &str) -> MetadataSubject {
    MetadataSubject::new(value).unwrap_or_else(|error| panic!("subject {value:?}: {error:?}"))
}

#[test]
fn anchors_vocabulary_and_non_claims_are_published() {
    let spec = fs::read_to_string(root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(SOURCE_METADATA_CLAUSES.len(), 13);
    for clause in SOURCE_METADATA_CLAUSES {
        assert!(spec.contains(&format!("<a id=\"{clause}\"></a>")));
    }
    assert_eq!(
        DocumentationFormat::ALL.map(DocumentationFormat::wire_name),
        ["markdown", "plain-text"]
    );
    assert_eq!(
        ExampleMode::ALL.map(ExampleMode::wire_name),
        ["compile", "compile-fail", "display-only"]
    );
    assert_eq!(
        SemanticAttribute::ALL.map(SemanticAttribute::wire_name),
        ["entry", "export", "test"]
    );
    assert_eq!(MetadataDiagnosticCode::ALL.len(), 11);
    let non_claims = spec
        .split("<a id=\"GNT-31.12-source-metadata-non-claims\"></a>")
        .nth(1)
        .unwrap_or_else(|| panic!("non-claims"));
    for phrase in [
        "Markdown rendering",
        "example parsing or execution",
        "compile-time plugins",
        "runtime behavior",
    ] {
        assert!(non_claims.contains(phrase));
    }
}

#[test]
fn documentation_attachment_links_and_examples_are_bounded_and_explicit() {
    let link = DocumentationLink::new("std.core::Option")
        .unwrap_or_else(|error| panic!("link: {error:?}"));
    assert_eq!(
        DocumentationLink::new("Option"),
        Err(MetadataError::InvalidLink)
    );
    let comment = DocumentationComment::new(
        subject("std.core::Result"),
        DocumentationFormat::Markdown,
        "A result.",
        vec![link],
    )
    .unwrap_or_else(|error| panic!("comment: {error:?}"));
    let mut declarations = MetadataDeclarations::default();
    assert!(declarations.attach(comment.clone()).is_ok());
    assert_eq!(
        declarations.attach(comment),
        Err(MetadataError::InvalidDocumentationAttachment)
    );
    assert_eq!(
        DocumentationComment::new(subject("x"), DocumentationFormat::PlainText, "", vec![]),
        Err(MetadataError::InvalidDocumentationAttachment)
    );
    assert!(
        ExampleDeclaration::new(
            ExampleMode::Compile,
            Some(SemanticMode::Portable),
            "fn main() {} "
        )
        .is_ok()
    );
    assert!(
        ExampleDeclaration::new(
            ExampleMode::CompileFail,
            Some(SemanticMode::Durable),
            "not source"
        )
        .is_ok()
    );
    assert!(ExampleDeclaration::new(ExampleMode::DisplayOnly, None, "text").is_ok());
    assert_eq!(
        ExampleDeclaration::new(ExampleMode::Compile, None, ""),
        Err(MetadataError::ExampleLimitExceeded)
    );
    assert_eq!(
        ExampleDeclaration::new(
            ExampleMode::DisplayOnly,
            Some(SemanticMode::Application),
            "text"
        ),
        Err(MetadataError::ExampleLimitExceeded)
    );
}

#[test]
fn deprecations_tool_metadata_lints_policies_and_origins_preserve_identity() {
    let old = subject("pkg::old");
    let new = subject("pkg::new");
    let deprecation = Deprecation::new(old.clone(), new.clone(), "use new")
        .unwrap_or_else(|error| panic!("deprecation: {error:?}"));
    assert_eq!(
        Deprecation::new(old.clone(), old.clone(), "self"),
        Err(MetadataError::InvalidDeprecation)
    );
    let tool = ToolMetadata::new("docs", "category", "public")
        .unwrap_or_else(|error| panic!("tool metadata: {error:?}"));
    let mut declarations = MetadataDeclarations::default();
    assert!(declarations.insert_deprecation(&deprecation).is_ok());
    assert_eq!(
        declarations.insert_deprecation(&deprecation),
        Err(MetadataError::InvalidDeprecation)
    );
    assert!(
        declarations
            .insert_tool_metadata(old.clone(), tool.clone())
            .is_ok()
    );
    assert_eq!(
        declarations.insert_tool_metadata(old.clone(), tool),
        Err(MetadataError::InvalidToolMetadata)
    );
    assert_eq!(
        ToolMetadata::new("non ascii Ω", "key", "value"),
        Err(MetadataError::InvalidToolMetadata)
    );
    let lint = LintDeclaration::new(
        old.clone(),
        LintId::new("metadata::missing-doc").unwrap_or_else(|_| panic!()),
        LintSeverity::Warn,
        true,
    );
    assert!(declarations.insert_lint(&lint).is_ok());
    assert_eq!(
        declarations.insert_lint(&lint),
        Err(MetadataError::DuplicateLint)
    );
    assert_eq!(
        admit_lint_control(&lint, LintScope::Item, LintSeverity::Deny),
        Ok((LintScope::Item, LintSeverity::Deny))
    );
    let security = LintDeclaration::new(
        subject("security"),
        LintId::new("security::authority").unwrap_or_else(|_| panic!()),
        LintSeverity::Deny,
        false,
    );
    assert_eq!(
        admit_lint_control(&security, LintScope::Package, LintSeverity::Allow),
        Err(MetadataError::UnsuppressibleLint)
    );
    assert!(
        declarations
            .set_dependency_policy(subject("dep"), DependencyWarningPolicy::Ignore)
            .is_ok()
    );
    assert_eq!(
        declarations.set_dependency_policy(subject("dep"), DependencyWarningPolicy::Warn),
        Err(MetadataError::InvalidDependencyWarningPolicy)
    );
    let origin = GeneratedOrigin::new(subject("generated::item"), new.clone(), "schema-v1")
        .unwrap_or_else(|error| panic!("origin: {error:?}"));
    assert!(declarations.insert_origin(&origin).is_ok());
    assert_eq!(
        declarations.insert_origin(&origin),
        Err(MetadataError::InvalidGeneratedOrigin)
    );
    assert_eq!(
        GeneratedOrigin::new(new.clone(), new, "generator"),
        Err(MetadataError::InvalidGeneratedOrigin)
    );
}

#[test]
fn semantic_attributes_are_closed_and_payload_free() {
    let spec = fs::read_to_string(root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert!(spec.contains("`metadata-unknown-semantic-attribute`"));
    assert_eq!(
        SemanticAttribute::ALL.map(SemanticAttribute::wire_name),
        ["entry", "export", "test"]
    );
    for attribute in SemanticAttribute::ALL {
        assert_eq!(
            admit_semantic_attribute(attribute.wire_name(), None),
            Ok(attribute)
        );
    }
    for spelling in ["inline", "derive", "Entry", "", "entry "] {
        assert_eq!(
            admit_semantic_attribute(spelling, None),
            Err(MetadataError::UnknownSemanticAttribute),
            "{spelling:?} is not a declared semantic attribute"
        );
    }
    for payload in [Some(""), Some("true"), Some("x")] {
        for attribute in SemanticAttribute::ALL {
            assert_eq!(
                admit_semantic_attribute(attribute.wire_name(), payload),
                Err(MetadataError::UnknownSemanticAttribute),
                "a payload for {} is refused",
                attribute.wire_name()
            );
        }
    }
    assert_eq!(
        MetadataDiagnosticCode::UnknownSemanticAttribute.as_str(),
        "metadata-unknown-semantic-attribute"
    );
}

#[test]
fn documentation_attaches_only_at_the_leading_boundary() {
    assert_eq!(
        DocumentationBoundary::ALL.map(DocumentationBoundary::wire_name),
        ["leading", "trailing", "detached"]
    );
    let comment = DocumentationComment::new(
        subject("std.core::Option"),
        DocumentationFormat::Markdown,
        "An option.",
        vec![],
    )
    .unwrap_or_else(|error| panic!("comment: {error:?}"));
    let mut declarations = MetadataDeclarations::default();
    assert_eq!(
        declarations.attach_at_boundary(comment.clone(), DocumentationBoundary::Trailing),
        Err(MetadataError::InvalidDocumentationAttachment)
    );
    assert_eq!(
        declarations.attach_at_boundary(comment.clone(), DocumentationBoundary::Detached),
        Err(MetadataError::InvalidDocumentationAttachment)
    );
    assert!(
        declarations
            .attach_at_boundary(comment.clone(), DocumentationBoundary::Leading)
            .is_ok()
    );
    assert_eq!(
        declarations.attach_at_boundary(comment, DocumentationBoundary::Leading),
        Err(MetadataError::InvalidDocumentationAttachment)
    );
}

#[test]
fn documentation_links_resolve_only_against_visible_interface_targets() {
    let metadata = InterfaceMetadata {
        edition: Arc::from("2026"),
        stdlib_contract: ProtocolVersion { major: 1, minor: 0 },
        protocol_versions: Vec::new(),
        target_predicates: Vec::new(),
        public_features: SelectedFeatureSet::empty(),
    };
    let declared = DeclaredSurface::from_names(&["Export", "Hidden"])
        .unwrap_or_else(|error| panic!("surface: {error:?}"));
    let nominal = |name: &str, visibility: Visibility| {
        let mut item = InterfaceItem::new(name, ItemKind::Nominal, visibility, TargetKind::Library)
            .unwrap_or_else(|error| panic!("item {name}: {error:?}"));
        item.nominal = Some(NominalFacts {
            fields: vec![Arc::from("value")],
            variants: Vec::new(),
            construction: ConstructionPolicy::Exhaustive,
            exhaustiveness: ExhaustivenessPolicy::Exhaustive,
            schema: None,
        });
        item
    };
    let interface = PublicInterfaceManifest::seal(InterfaceSeal {
        version: PublicInterfaceManifest::VERSION,
        metadata: &metadata,
        surface: &declared,
        items: &[
            nominal("Export", Visibility::Exported),
            nominal("Hidden", Visibility::PackageLocal),
        ],
        dependencies: &[],
        exports: &[],
    })
    .unwrap_or_else(|error| panic!("seal: {error:?}"));
    let link = |target: &str| {
        DocumentationLink::new(target).unwrap_or_else(|error| panic!("link {target:?}: {error:?}"))
    };
    let resolved = resolve_documentation_link(&link("pkg::Export"), "pkg", &interface)
        .unwrap_or_else(|error| panic!("resolution: {error:?}"));
    assert_eq!(resolved.as_str(), "pkg::Export");
    assert_eq!(
        resolve_documentation_link(&link("pkg::Hidden"), "pkg", &interface),
        Err(MetadataError::InvalidLink)
    );
    assert_eq!(
        resolve_documentation_link(&link("pkg::Absent"), "pkg", &interface),
        Err(MetadataError::InvalidLink)
    );
    assert_eq!(
        resolve_documentation_link(&link("other::Export"), "pkg", &interface),
        Err(MetadataError::InvalidLink)
    );
    assert_eq!(
        resolve_documentation_link(&link("pkg::Export"), "", &interface),
        Err(MetadataError::InvalidLink)
    );
}

#[test]
fn dependency_policies_hide_only_ordinary_warnings() {
    assert_eq!(
        DependencyWarningPolicy::ALL.map(DependencyWarningPolicy::wire_name),
        ["deny", "ignore", "inherit", "warn"]
    );
    assert_eq!(
        DependencyDiagnosticClass::ALL.map(DependencyDiagnosticClass::wire_name),
        [
            "ordinary-warning",
            "semantic",
            "security",
            "integrity",
            "authority",
            "compatibility",
            "publication"
        ]
    );
    for policy in DependencyWarningPolicy::ALL {
        for class in DependencyDiagnosticClass::ALL {
            let hides = policy == DependencyWarningPolicy::Ignore
                && class == DependencyDiagnosticClass::OrdinaryWarning;
            assert_eq!(
                dependency_policy_ignores(policy, class),
                hides,
                "{} / {}",
                policy.wire_name(),
                class.wire_name()
            );
        }
    }
}

#[test]
fn lint_controls_apply_only_declared_scoped_severities() {
    let subject = subject("std.core::Option");
    let id = LintId::new("metadata::missing-doc").unwrap_or_else(|_| panic!());
    let mut controls = LintControlSet::default();
    let lint = LintDeclaration::new(subject.clone(), id.clone(), LintSeverity::Warn, true);
    assert!(controls.declare(subject.clone(), &lint).is_ok());
    assert_eq!(
        controls.declare(subject.clone(), &lint),
        Err(MetadataError::DuplicateLint)
    );
    // A duplicate declaration of one lint identity is refused even when its severity or
    // suppressibility differs from the first declaration.
    assert_eq!(
        controls.declare(
            subject.clone(),
            &LintDeclaration::new(subject.clone(), id.clone(), LintSeverity::Deny, true),
        ),
        Err(MetadataError::DuplicateLint)
    );
    assert_eq!(
        controls.declare(
            subject.clone(),
            &LintDeclaration::new(subject.clone(), id.clone(), LintSeverity::Warn, false),
        ),
        Err(MetadataError::DuplicateLint)
    );
    assert_eq!(
        controls.effective_severity(&subject, &id),
        Some(LintSeverity::Warn)
    );
    assert_eq!(
        controls.control(&subject, &id, LintScope::Item, LintSeverity::Deny),
        Ok((LintScope::Item, LintSeverity::Deny))
    );
    assert_eq!(
        controls.effective_severity(&subject, &id),
        Some(LintSeverity::Deny)
    );
    assert_eq!(
        controls.control(&subject, &id, LintScope::Package, LintSeverity::Allow),
        Err(MetadataError::DuplicateLint)
    );
    let unknown = LintId::new("unknown::lint").unwrap_or_else(|_| panic!());
    assert_eq!(
        controls.control(&subject, &unknown, LintScope::Item, LintSeverity::Deny),
        Err(MetadataError::DuplicateLint)
    );
    let security = LintDeclaration::new(
        subject.clone(),
        LintId::new("security::authority").unwrap_or_else(|_| panic!()),
        LintSeverity::Deny,
        false,
    );
    assert!(controls.declare(subject.clone(), &security).is_ok());
    assert_eq!(
        controls.control(
            &subject,
            security.id(),
            LintScope::Package,
            LintSeverity::Allow
        ),
        Err(MetadataError::UnsuppressibleLint)
    );
    let forbidden = LintDeclaration::new(
        subject.clone(),
        LintId::new("style::forbidden").unwrap_or_else(|_| panic!()),
        LintSeverity::Forbid,
        true,
    );
    assert!(controls.declare(subject.clone(), &forbidden).is_ok());
    assert_eq!(
        controls.control(
            &subject,
            forbidden.id(),
            LintScope::Dependency,
            LintSeverity::Deny
        ),
        Err(MetadataError::UnsuppressibleLint)
    );
}
