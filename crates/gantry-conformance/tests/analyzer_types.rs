//! Public-facade conformance for analyzer type and receiver semantics.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::source::SourceLimits;
use serde::Deserialize;

const RECEIVER_EVIDENCE: &str =
    "crates/gantry-conformance/tests/analyzer_types.rs#public_impl_targets_and_receivers_are_typed";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

/// Primitive facts do not infer declared fields or grant boundary admission.
#[test]
fn primitive_properties_keep_eligibility_axes_separate() {
    use gantry::ir::TypeDescriptor;

    for (ty, external, orderable) in [
        (TypeDescriptor::UNIT, true, false),
        (TypeDescriptor::BOOL, true, false),
        (TypeDescriptor::INT, true, true),
        (TypeDescriptor::FLOAT, true, true),
        (TypeDescriptor::STRING, true, false),
        (TypeDescriptor::DECISION, false, false),
        (TypeDescriptor::OPERATION_ERROR, false, false),
    ] {
        let properties = ty
            .primitive_properties()
            .unwrap_or_else(|| panic!("primitive omitted properties: {ty:?}"));
        assert_eq!(properties.is_external(), external);
        assert_eq!(properties.is_equatable(), external);
        assert_eq!(properties.is_orderable(), orderable);
        assert!(properties.is_copyable());
        assert!(properties.is_interpolatable());
        assert!(properties.has_recovery_projection());
    }
    for canonical in [
        "crate::Unknown",
        "List<Int>",
        "Option<Int>",
        "Result<Int,String>",
        "Tuple<Int,Bool>",
    ] {
        let ty = TypeDescriptor::from_canonical_string(canonical)
            .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
        assert_eq!(ty.primitive_properties(), None);
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-analyzer-types-conformance-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        Self(path)
    }

    fn write(&self, source: &str) {
        let path = self.0.join("main.gnt");
        fs::write(&path, source)
            .unwrap_or_else(|error| panic!("could not write {}: {error}", path.display()));
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn reviewed_analyzer_type_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/analyzer-types-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.analyzer-type-evidence/v1");
    assert_eq!(manifest.issue, "GNT-AN-003");
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    for entry in manifest.entries {
        assert_eq!(entry.evidence, RECEIVER_EVIDENCE);
        if !evidence_is_current {
            continue;
        }
        let clause = review
            .requirements
            .iter()
            .find(|requirement| requirement.id == entry.requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == entry.clause)
            })
            .unwrap_or_else(|| panic!("missing {}:{}", entry.requirement, entry.clause));
        let analyzer = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == "analyzer")
            .unwrap_or_else(|| {
                panic!(
                    "missing analyzer review for {}:{}",
                    entry.requirement, entry.clause
                )
            });
        assert_eq!(analyzer.state, "covered");
        assert_eq!(analyzer.evidence, [entry.evidence]);
    }
}

#[test]
fn public_impl_targets_and_receivers_are_typed() {
    let valid = analyze(
        r#"
struct Counter { value: Int }
impl Counter { fn current(self) -> Int { self.value } }
impl Counter { fn increment(mut self) -> Counter { self.value += 1; self } }
fn inspect(counter: Counter) -> Int { counter.current() }
fn main() {}
"#,
    );
    assert_eq!(
        valid.status(),
        AnalysisStatus::Valid,
        "{:?}",
        valid.diagnostics()
    );

    let invalid = analyze(
        r#"
enum Choice { Ready }
fn helper() {}
mod nested {}
impl Choice { fn enum_method(self) {} }
impl helper { fn function_method(self) {} }
impl nested { fn module_method(self) {} }
struct Duplicate {}
impl Duplicate { fn repeated(self) {} }
impl Duplicate { fn repeated(self) {} }
fn main() {}
"#,
    );
    assert_eq!(invalid.status(), AnalysisStatus::Invalid);
    assert_eq!(
        invalid
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "invalid-impl-target")
            .count(),
        3
    );
    assert!(
        invalid
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "duplicate-member")
    );
}

#[test]
fn public_generic_analysis_proves_bounds_and_substitutes_enum_patterns() {
    let valid = analyze(
        r#"
struct Envelope<T> where T: Equatable { value: T }
enum State<T, E> { Ready(T), Failed(E) }
fn inspect(value: Envelope<String>) {}
fn main(value: State<String, Int>) -> String {
    match value {
        State::<String, Int>::Ready(item) => item,
        State::<String, Int>::Failed(_) => "failed",
    }
}
"#,
    );
    assert_eq!(
        valid.status(),
        AnalysisStatus::Valid,
        "{:?}",
        valid.diagnostics()
    );

    let invalid = analyze(
        r#"
struct Envelope<T> where T: Equatable { value: T }
fn inspect(value: Envelope<Decision>) {}
fn main() {}
"#,
    );
    assert_eq!(invalid.status(), AnalysisStatus::Invalid);
    assert!(invalid.diagnostics().iter().any(|diagnostic| {
        diagnostic.code.as_str() == "unsatisfied-bound"
            && diagnostic.fields.get("capability").map(AsRef::as_ref) == Some("Equatable")
    }));
}

/// A recursive back-edge cannot publish a proof before all stored fields qualify.
#[test]
fn recursive_equality_proofs_do_not_cache_provisional_success() {
    for comparisons in [
        "discard value == value; discard value.next == value.next;",
        "discard value.next == value.next; discard value == value;",
    ] {
        let package = analyze(&format!(
            "struct Sealed {{ value: Decision }}\nstruct Node {{ next: Option<Node>, sealed: Sealed }}\nfn compare(value: Node) {{ {comparisons} }}\nfn main() {{}}"
        ));
        assert_eq!(package.status(), AnalysisStatus::Invalid);
        assert_eq!(
            package
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "invalid-primitive")
                .count(),
            2,
            "{:?}",
            package.diagnostics()
        );
    }
}

/// Equality follows stored members and requires an explicit generic capability.
#[test]
fn public_equality_uses_structural_capabilities() {
    for source in [
        "struct Phantom<T> { value: Int }\nfn compare(value: Phantom<Decision>) -> Bool { value == value }\nfn main() {}",
        "fn compare<T>(value: T) -> Bool where T: Equatable { value == value }\nfn main() { discard compare(1); }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
    }
    for source in [
        "struct Stored { value: Decision }\nfn compare(value: Stored) -> Bool { value == value }\nfn main() {}",
        "fn compare<T>(value: T) -> Bool { value == value }\nfn main() {}",
        "struct __gantry_parametric_0_0 { value: Int }\nfn compare<T>(value: T) -> Bool { value == value }\nfn main() {}",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Invalid,
            "{:?}",
            package.diagnostics()
        );
        assert!(
            package
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "invalid-primitive"),
            "{:?}",
            package.diagnostics()
        );
    }
}

/// Unused generic callers must prove the capabilities required by their callees.
#[test]
fn public_parametric_calls_require_callee_bounds() {
    for (bound, expected) in [
        ("where U: ExternalValue", AnalysisStatus::Valid),
        ("", AnalysisStatus::Invalid),
    ] {
        let package = analyze(&format!(
            "fn accept<T>(value: T) -> T where T: ExternalValue {{ value }}\nfn wrapper<U>(value: U) -> U {bound} {{ accept(value) }}\nfn main() {{}}"
        ));
        assert_eq!(package.status(), expected, "{:?}", package.diagnostics());
        if expected == AnalysisStatus::Invalid {
            assert!(
                package
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| { diagnostic.code.as_str() == "unsatisfied-bound" })
            );
        }
    }
}

/// Public queries reuse structural proof without admitting unknown descriptors.
#[test]
fn public_type_capability_queries_are_bounded_and_declaration_aware() {
    use gantry::analysis::TypeCapabilityQueryError;
    use gantry::ir::TypeDescriptor;
    use gantry::source::FrontendLimits;

    let nested = analyze("struct Nested { value: List<List<Int>> }\nfn main(value: Nested) {}");
    let nested_type = TypeDescriptor::from_canonical_string("crate::Nested")
        .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
    for (depth, succeeds) in [(3, true), (2, false), (3, true)] {
        let policy = FrontendLimits::new(
            4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, depth, 64, 100,
        )
        .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
        let result = nested.type_capabilities(&nested_type, policy);
        if succeeds {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(
                matches!(result, Err(TypeCapabilityQueryError::ResourceLimit(error))
                if error.code == gantry::portable::FrontendResourceCode::ConstructedTypeDepthLimit)
            );
        }
    }

    let package = analyze(
        "struct Phantom<T> { value: Int }\nstruct Stored { value: Decision }\nfn inspect(value: Stored) {}\nfn main(value: Phantom<Decision>) {}",
    );
    let policy = FrontendLimits::new(
        4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, 64, 64, 100,
    )
    .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
    for (name, external) in [("crate::Phantom<Decision>", true), ("crate::Stored", false)] {
        let ty = TypeDescriptor::from_canonical_string(name)
            .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
        let properties = package
            .type_capabilities(&ty, policy)
            .unwrap_or_else(|error| panic!("query failed: {error:?}"));
        assert_eq!(properties.is_external(), external);
        assert_eq!(properties.is_equatable(), external);
        assert!(properties.is_interpolatable());
        assert!(properties.is_copyable());
        assert!(properties.is_task_capturable());
        assert_eq!(package.type_capabilities(&ty, policy), Ok(properties));
    }
    let unknown = TypeDescriptor::from_canonical_string("crate::Unknown")
        .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
    assert_eq!(
        package.type_capabilities(&unknown, policy),
        Err(TypeCapabilityQueryError::TypeNotRetained)
    );
    for (steps, succeeds) in [(6, true), (5, false), (6, true)] {
        let bounded = FrontendLimits::new(
            4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, 64, 64, steps,
        )
        .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
        let result = package.type_capabilities(&TypeDescriptor::INT, bounded);
        if succeeds {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(matches!(
                result,
                Err(TypeCapabilityQueryError::ResourceLimit(_))
            ));
        }
    }
    let invalid = analyze("fn main() -> Int { true }");
    assert_eq!(
        invalid.type_capabilities(&TypeDescriptor::INT, policy),
        Err(TypeCapabilityQueryError::InvalidPackage)
    );
}

/// Entry boundaries use stored members rather than phantom type arguments.
#[test]
fn public_entry_boundaries_use_declared_members() {
    let valid = analyze(
        "struct Phantom<T> { value: Int }\nfn main(value: Phantom<Decision>) { discard value; }",
    );
    assert_eq!(
        valid.status(),
        AnalysisStatus::Valid,
        "{:?}",
        valid.diagnostics()
    );

    let invalid =
        analyze("struct Stored { value: Decision }\nfn main(value: Stored) { discard value; }");
    assert_eq!(
        invalid.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        invalid.diagnostics()
    );
    assert!(
        invalid
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "sealed-type-boundary")
    );
}

/// Callable capabilities follow stored members, not phantom type arguments.
#[test]
fn public_callable_bounds_use_declared_members() {
    let method = analyze(
        "struct Phantom<T> { value: Int }\nstruct Acceptor {}\nimpl Acceptor { fn accept<T>(self, value: T) -> T where T: ExternalValue { value } }\nfn main() { let receiver: Acceptor = Acceptor {}; let argument: Phantom<Decision> = Phantom::<Decision> { value: 1 }; discard receiver.accept(argument); }",
    );
    assert_eq!(
        method.status(),
        AnalysisStatus::Valid,
        "{:?}",
        method.diagnostics()
    );

    let stored = analyze(
        "struct Stored { value: Decision }\nfn accept<T>(value: T) -> T where T: ExternalValue { value }\nfn main() { discard accept(Stored { value: decide \"x\" }); }",
    );
    assert_eq!(stored.status(), AnalysisStatus::Invalid);
    assert!(
        stored.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "unsatisfied-bound"
                && diagnostic.fields.get("capability").map(AsRef::as_ref) == Some("ExternalValue")
                && diagnostic.fields.get("type").map(AsRef::as_ref) == Some("crate::Stored")
        }),
        "{:?}",
        stored.diagnostics()
    );

    let valid = analyze(
        "struct Phantom<T> { value: Int }\nfn accept<T>(value: T) -> T where T: ExternalValue { value }\nfn main() { discard accept(Phantom::<Decision> { value: 1 }); }",
    );
    assert_eq!(
        valid.status(),
        AnalysisStatus::Valid,
        "{:?}",
        valid.diagnostics()
    );

    let invalid = analyze(
        "fn accept<T>(value: T) -> T where T: ExternalValue { value }\nfn main() { discard accept(decide \"x\"); }",
    );
    assert_eq!(invalid.status(), AnalysisStatus::Invalid);
    assert!(
        invalid.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "unsatisfied-bound"
                && diagnostic.fields.get("capability").map(AsRef::as_ref) == Some("ExternalValue")
        }),
        "{:?}",
        invalid.diagnostics()
    );
}

#[test]
fn public_static_trait_resolution_is_coherent_and_diagnostic() {
    let valid = analyze(
        r#"
trait Convert<T> {
    pure fn convert<U>(self, fallback: U) -> T;
}
struct Item {}
impl Convert<String> for Item {
    pure fn convert<U>(self, fallback: U) -> String { "converted" }
}
fn main(value: Item) -> String {
    Convert::<String>::convert::<Int>(value, 1)
}
"#,
    );
    assert_eq!(
        valid.status(),
        AnalysisStatus::Valid,
        "{:?}",
        valid.diagnostics()
    );
    assert_eq!(valid.trait_contracts().len(), 1);
    assert_eq!(valid.implementation_heads().len(), 1);

    let invalid = analyze(
        r#"
trait Label { pure fn label(self) -> String; }
struct Envelope<T> { value: T }
impl<T> Label for Envelope<T> {
    pure fn label(self) -> String { "generic" }
}
impl Label for Envelope<String> {
    pure fn label(self) -> String { "specific" }
}
fn main() {}
"#,
    );
    assert_eq!(invalid.status(), AnalysisStatus::Invalid);
    assert!(
        invalid
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "overlapping-implementation"),
        "{:?}",
        invalid.diagnostics()
    );
}

#[test]
fn public_generic_bodies_retain_closed_calls_effects_and_failures() {
    let valid = analyze(
        r#"
trait Label { pure fn label(self) -> String; }
struct Envelope<T> { value: T }
impl<T> Label for Envelope<T> {
    pure fn label(self) -> String { "label" }
}
fn render<T>(value: T) -> String where T: Label { value.label() }
fn effect<T>(value: T) -> T {
    discard prompt "Generate." -> String;
    value
}
fn main(value: Envelope<String>) -> String {
    discard effect(value);
    render(value)
}
"#,
    );
    assert_eq!(
        valid.status(),
        AnalysisStatus::Valid,
        "{:?}",
        valid.diagnostics()
    );
    assert!(valid.generic_templates().iter().any(|template| {
        template.identity().as_str() == "crate::render<^0.0>" && template.predicates().len() == 1
    }));
    let identities = valid
        .generic_instantiations()
        .iter()
        .map(|instantiation| instantiation.concrete().canonical_string())
        .collect::<Vec<_>>();
    assert_eq!(
        identities,
        [
            "crate::Envelope<String>",
            "crate::effect<crate::Envelope<String>>",
            "crate::render<crate::Envelope<String>>",
            "<crate::Envelope<String> as crate::Label>::label",
        ]
    );
    assert!(valid.generic_concrete_effects().iter().any(|effect| {
        effect.callable.as_str() == "crate::effect<crate::Envelope<String>>"
            && effect
                .effects
                .iter()
                .map(|effect| effect.wire_name())
                .eq(["prompt"])
    }));

    let invalid_body = analyze("fn invalid<T>(value: T) -> Int { value } fn main() {}");
    assert_eq!(invalid_body.status(), AnalysisStatus::Invalid);
    assert!(
        invalid_body
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "type-mismatch")
    );

    let polymorphic = analyze("fn grow<T>() { grow::<List<T>>() } fn main() { grow::<String>() }");
    assert_eq!(polymorphic.status(), AnalysisStatus::Invalid);
    assert!(polymorphic.diagnostics().iter().any(|diagnostic| {
        diagnostic.code.as_str() == "polymorphic-recursion"
            && diagnostic.fields.contains_key("instantiation_witness")
    }));
}

fn analyze(source: &str) -> gantry::analysis::TypedPackage {
    let root = TempDirectory::new();
    root.write(source);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    analyze_package_types(&syntax).unwrap_or_else(|error| panic!("type analysis failed: {error:?}"))
}

fn limits() -> SourceLimits {
    SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
        .unwrap_or_else(|_| unreachable!("positive limits"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
