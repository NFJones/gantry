//! Public-facade conformance for analyzer type and receiver semantics.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{
    AnalysisError, AnalysisStatus, analyze_package_types, analyze_package_types_with_limits,
};
use gantry::frontend::validate_package_syntax;
use gantry::ir::{AggregateKind, InstructionKind, Primitive, Projection};
use gantry::portable::{DiagnosticCategory, FrontendResourceCode};
use gantry::source::{FrontendLimits, SourceLimits};
use serde::Deserialize;

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
    use gantry::ir::{
        RecoveryProjectionClass, SourceProtectionClass, TransferEligibility, TypeDescriptor,
        ValueResourceClass,
    };

    for (ty, external, hashable, orderable, canonical_scalar_key) in [
        (TypeDescriptor::UNIT, true, true, false, true),
        (TypeDescriptor::BOOL, true, true, false, true),
        (TypeDescriptor::INT, true, true, true, true),
        (TypeDescriptor::FLOAT, true, true, true, true),
        (TypeDescriptor::STRING, true, true, false, true),
        (TypeDescriptor::DECISION, false, false, false, false),
        (TypeDescriptor::OPERATION_ERROR, false, false, false, false),
    ] {
        let properties = ty
            .primitive_properties()
            .unwrap_or_else(|| panic!("primitive omitted properties: {ty:?}"));
        assert_eq!(properties.is_external(), external);
        assert_eq!(properties.is_equatable(), external);
        assert_eq!(properties.is_hashable(), hashable);
        assert_eq!(properties.is_orderable(), orderable);
        assert_eq!(properties.is_canonical_scalar_key(), canonical_scalar_key);
        assert!(properties.is_copyable());
        assert!(properties.is_interpolatable());
        assert!(properties.has_recovery_projection());
        assert_eq!(
            properties.transfer_eligibility(),
            TransferEligibility::IsolatedTaskCapture
        );
        assert_eq!(
            properties.resource_class(),
            ValueResourceClass::NonLiveResource
        );
        assert_eq!(
            properties.recovery_projection_class(),
            RecoveryProjectionClass::SealedValue
        );
        assert_eq!(
            properties.source_protection_class(),
            if ty == TypeDescriptor::DECISION || ty == TypeDescriptor::OPERATION_ERROR {
                SourceProtectionClass::Sealed
            } else {
                SourceProtectionClass::Unsealed
            }
        );
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

    fn write_named(&self, name: &str, source: &str) {
        let path = self.0.join(name);
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
        assert!(
            entry
                .evidence
                .starts_with("crates/gantry-conformance/tests/analyzer_types.rs#public_")
        );
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
        assert!(analyzer.evidence.contains(&entry.evidence));
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

/// Shared receivers are restricted to monomorphic zero-argument inherent methods.
#[test]
fn public_shared_receiver_admission_is_scoped_to_monomorphic_zero_argument_inherent_methods() {
    let accepted = analyze(
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(counter: Counter) -> Int { counter.read() }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    for source in [
        "struct Counter { value: Int } impl Counter { fn read(shared self, extra: Int) -> Int { extra } } fn main() {}",
        "struct Box<T> { value: T } impl Box<Int> { fn read(shared self) -> Int { self.value } } fn main() {}",
        "struct Counter<T> { value: T } impl<T> Counter<T> { fn read(shared self) -> T { self.value } } fn main() {}",
        "struct Counter { value: Int } impl Counter { fn read<T>(shared self) -> Int { self.value } } fn main() {}",
        "trait Value { pure fn read(shared self) -> Int; } fn main() {}",
        "struct Counter { value: Int } trait Value { pure fn read(self) -> Int; } impl Value for Counter { pure fn read(shared self) -> Int { self.value } } fn main() {}",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main() -> Int { Counter { value: 1 }.read() }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(items: List<Counter>) -> Int { items[0].read() }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(items: Tuple<Counter, Int>) -> Int { items[0].read() }",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected.diagnostics().iter().any(|diagnostic| matches!(
                diagnostic.code.as_str(),
                "shared-receiver-scope" | "shared-receiver-place"
            )),
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// Exclusive receivers are restricted to mutable ordinary binding-root and struct-field
/// places, and each rejected fixture reports its precise admission cause code.
#[test]
fn public_exclusive_receiver_admission_is_scoped_to_mutable_monomorphic_inherent_places() {
    let accepted = analyze(
        "struct Counter { value: Int } struct Holder { counter: Counter } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main() -> Int { let mut holder: Holder = Holder { counter: Counter { value: 1 } }; holder.counter.increment(); holder.counter.value }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    for (source, expected_code) in [
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main(counter: Counter) { counter.increment(); }",
            "exclusive-receiver-immutable",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self, extra: Int) { self.value += extra; } } fn main() {}",
            "exclusive-receiver-scope",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment<T>(exclusive self) { self.value += 1; } } fn main() {}",
            "exclusive-receiver-scope",
        ),
        (
            "struct Box<T> { value: T } impl Box<Int> { fn increment(exclusive self) { self.value += 1; } } fn main() {}",
            "exclusive-receiver-scope",
        ),
        (
            "struct Counter { value: Int } trait Value { pure fn increment(self); } impl Value for Counter { pure fn increment(exclusive self) { self.value += 1; } } fn main() {}",
            "exclusive-receiver-scope",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main() { Counter { value: 1 }.increment(); }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main(items: List<Counter>) { discard items[0].increment(); }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main(items: Tuple<Counter, Int>) { discard items[0].increment(); }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main(state: Option<Counter>) { if let Some(counter) = state { discard counter.increment(); } }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main(state: Result<Counter, Int>) { if let Ok(counter) = state { discard counter.increment(); } }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } enum State { Ready(Counter), Empty } impl Counter { fn increment(exclusive self) { self.value += 1; } } fn main(state: State) { if let State::Ready(counter) = state { discard counter.increment(); } }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.increment(); } } fn main() { let mut counter: Counter = Counter { value: 1 }; counter.increment(); }",
            "exclusive-reborrow-subplace",
        ),
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            receiver_family_codes(rejected.diagnostics()),
            [expected_code],
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// A nested `exclusive self` reborrow must select a strict struct-field subplace of the
/// enclosing admitted place, while a receiver binding that admits no caller place is
/// rejected with its own cause code (item 2f).
#[test]
fn public_exclusive_reborrow_requires_a_strict_struct_field_subplace() {
    for source in [
        "struct Counter { value: Int } struct Holder { counter: Counter } impl Counter { fn increment(exclusive self) { self.value += 1; } } impl Holder { fn bump(exclusive self) { self.counter.increment(); } } fn main() -> Int { let mut holder: Holder = Holder { counter: Counter { value: 1 } }; holder.bump(); holder.counter.value }",
        // A `mut self` receiver binds a mutable local copy, so a strict struct-field
        // subplace of that binding is still admitted.
        "struct Counter { value: Int } struct Holder { counter: Counter } impl Counter { fn increment(exclusive self) { self.value += 1; } } impl Holder { fn bump(mut self) { self.counter.increment(); } } fn main() -> Int { let mut holder: Holder = Holder { counter: Counter { value: 1 } }; holder.bump(); holder.counter.value }",
    ] {
        let accepted = analyze(source);
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            accepted.diagnostics()
        );
        assert!(
            accepted.diagnostics().is_empty(),
            "{source}: {:?}",
            accepted.diagnostics()
        );
        assert!(accepted.executable_program().is_some());
    }

    for (source, expected_code) in [
        // An `owned self` or `mut self` receiver binding is not an admitted caller
        // place, so the nested call reports the not-an-admitted-place cause.
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } fn take(owned self) { self.increment(); } } fn main() { let mut counter: Counter = Counter { value: 1 }; counter.increment(); }",
            "exclusive-receiver-place",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } fn bump(mut self) { self.increment(); } } fn main() { let mut counter: Counter = Counter { value: 1 }; counter.increment(); }",
            "exclusive-receiver-place",
        ),
        // A plain `self` receiver is an immutable local copy, so its place root is
        // reported immutable, as is the enclosing root of a `shared self` method.
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } fn probe(self) { self.increment(); } } fn main() { let mut counter: Counter = Counter { value: 1 }; counter.increment(); }",
            "exclusive-receiver-immutable",
        ),
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.value += 1; } fn peek(shared self) { self.increment(); } } fn main() { let mut counter: Counter = Counter { value: 1 }; counter.increment(); }",
            "exclusive-receiver-immutable",
        ),
        // The enclosing admitted place itself is not a strict struct-field subplace.
        (
            "struct Counter { value: Int } impl Counter { fn increment(exclusive self) { self.increment(); } } fn main() { let mut counter: Counter = Counter { value: 1 }; counter.increment(); }",
            "exclusive-reborrow-subplace",
        ),
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            receiver_family_codes(rejected.diagnostics()),
            [expected_code],
            "{source}: {:?}",
            rejected.diagnostics()
        );
        // Each shape reports exactly one diagnostic, so the complete list is asserted.
        assert_eq!(
            diagnostic_codes(rejected.diagnostics()),
            [expected_code],
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// Owned receivers are mutable independent local copies scoped to zero-argument monomorphic inherent methods.
#[test]
fn analyzer_admits_and_scopes_owned_receiver() {
    let accepted = analyze(
        "struct Counter { value: Int } impl Counter { fn bump(owned self) { self.value += 1; } } fn main(counter: Counter) { counter.bump(); }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
    assert!(accepted.executable_program().is_some());

    for source in [
        "struct Counter { value: Int } impl Counter { fn bump(owned self, extra: Int) -> Int { extra } } fn main() {}",
        "struct Box<T> { value: T } impl Box<Int> { fn read(owned self) -> Int { self.value } } fn main() {}",
        "struct Counter<T> { value: T } impl<T> Counter<T> { fn read(owned self) -> T { self.value } } fn main() {}",
        "struct Counter { value: Int } impl Counter { fn read<T>(owned self) -> Int { self.value } } fn main() {}",
        "trait Value { pure fn read(owned self) -> Int; } fn main() {}",
        "struct Counter { value: Int } trait Value { pure fn read(self) -> Int; } impl Value for Counter { pure fn read(owned self) -> Int { self.value } } fn main() {}",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "owned-receiver-scope"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// Owned receivers render a mutable receiver in the closed callable signature, distinct from
/// immutable `self` and `shared self`, while the workflow signature keeps the `owned self` spelling.
#[test]
fn owned_receiver_closed_signature_marks_the_receiver_mutable() {
    let package = analyze(
        "fn identity<T>(value: T) -> T { value } struct Counter { value: Int } impl Counter { fn bump(owned self) { self.value += 1; } fn read(self) -> Int { self.value } fn peek(shared self) -> Int { self.value } } fn main(counter: Counter) { counter.bump(); discard identity::<Int>(1); }",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    let signatures = package
        .canonical_ir()
        .unwrap_or_else(|| unreachable!("valid package has canonical IR"))
        .generic_facts()
        .executable()
        .callables()
        .iter()
        .map(|callable| callable.signature().as_str())
        .collect::<Vec<_>>();
    assert!(
        signatures.contains(&"fn <crate::Counter>::bump(mut crate::Counter)->Unit"),
        "{signatures:?}"
    );
    assert!(
        signatures.contains(&"fn <crate::Counter>::read(crate::Counter)->Int"),
        "{signatures:?}"
    );
    assert!(
        signatures.contains(&"fn <crate::Counter>::peek(crate::Counter)->Int"),
        "{signatures:?}"
    );
    assert!(
        package.workflows().iter().any(|workflow| {
            workflow.signature.as_str() == "fn <crate::Counter>::bump(owned self)->Unit"
        }),
        "{:#?}",
        package.workflows()
    );
}

/// A shared receiver exposes an immutable callee-local `self` binding.
#[test]
fn public_shared_receiver_is_immutable() {
    let rejected = analyze(
        "struct Counter { value: Int } impl Counter { fn replace(shared self) { self.value = 2; } } fn main(counter: Counter) { counter.replace(); }",
    );
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "immutable-assignment"),
        "{:?}",
        rejected.diagnostics()
    );
    assert!(rejected.executable_program().is_none());
}

/// Tuple-index receivers are rejected at the public shared-place boundary.
#[test]
fn public_shared_receiver_rejects_tuple_index_places() {
    let rejected = analyze(
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(items: Tuple<Counter, Int>) -> Int { items[0].read() }",
    );
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place"),
        "{:?}",
        rejected.diagnostics()
    );
    assert!(rejected.executable_program().is_none());
}

/// Pattern payloads are values, not caller-owned shared receiver places.
#[test]
fn public_shared_receiver_rejects_pattern_payload_roots() {
    for source in [
        "struct Counter { value: Int } enum State { Ready(Counter), Empty } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: State) -> Int { match state { State::Ready(counter) => counter.read(), State::Empty => 0 } }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: Option<Counter>) -> Int { match state { Some(counter) => counter.read(), None => 0 } }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: Result<Counter, Int>) -> Int { match state { Ok(counter) => counter.read(), Err(_) => 0 } }",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            rejected
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place")
                .count(),
            1,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        let diagnostic = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place")
            .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
        let primary = diagnostic
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("{source}: missing primary span"));
        let call_start = source
            .rfind("read()")
            .unwrap_or_else(|| panic!("{source}: missing method call"))
            as u64;
        assert_eq!(primary.bytes().start(), call_start, "{source}");
        assert_eq!(primary.bytes().end(), call_start + 4, "{source}");
        assert!(rejected.executable_program().is_none());
    }
}

/// Refutable payload bindings are never admitted as shared caller-place roots.
#[test]
fn public_shared_receiver_rejects_if_let_payload_roots_exactly() {
    for source in [
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: Option<Counter>) { if let Some(counter) = state { discard counter.read(); } }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: Result<Counter, Int>) { if let Ok(counter) = state { discard counter.read(); } }",
        "struct Counter { value: Int } enum State { Ready(Counter), Empty } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: State) { if let State::Ready(counter) = state { discard counter.read(); } }",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            rejected
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place")
                .count(),
            1,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .all(|diagnostic| diagnostic.code.as_str() != "invariant")
        );
        let diagnostic = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place")
            .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
        let primary = diagnostic
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("{source}: missing primary span"));
        let call_start = source
            .rfind("read()")
            .unwrap_or_else(|| panic!("{source}: missing method call"))
            as u64;
        assert_eq!(primary.bytes().start(), call_start, "{source}");
        assert_eq!(primary.bytes().end(), call_start + 4, "{source}");
        assert!(rejected.executable_program().is_none());
    }
}

/// Payload provenance ends with the `if let` branch, permitting a later ordinary root with the same name.
#[test]
fn public_shared_receiver_payload_provenance_does_not_leak_from_if_let_scope() {
    let accepted = analyze(
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn main(state: Option<Counter>) -> Int { if let Some(counter) = state { discard counter.value; } let counter: Counter = Counter { value: 7 }; counter.read() }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
    assert!(accepted.executable_program().is_some());
}

/// Call-produced receiver values cannot be lowered as caller-owned shared places.
#[test]
fn public_shared_receiver_rejects_call_produced_temporary_roots() {
    for source in [
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn make() -> Counter { Counter { value: 1 } } fn main() -> Int { make().read() }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn make() -> Counter { Counter { value: 1 } } fn main() -> Int { (make()).read() }",
        "struct Counter { value: Int } impl Counter { pure fn read(shared self) -> Int { self.value } } fn make() -> Counter { Counter { value: 1 } } fn main() -> Int { make().read() + 1 }",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            rejected
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place")
                .count(),
            1,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        let diagnostic = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "shared-receiver-place")
            .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
        let primary = diagnostic
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("{source}: missing primary span"));
        let call_start = source
            .rfind("read()")
            .unwrap_or_else(|| panic!("{source}: missing method call"))
            as u64;
        assert_eq!(primary.bytes().start(), call_start, "{source}");
        assert_eq!(primary.bytes().end(), call_start + 4, "{source}");
        assert!(
            rejected
                .diagnostics()
                .iter()
                .all(|diagnostic| diagnostic.code.as_str() != "type-mismatch"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// Shared receiver place admission follows resolved method metadata across package sources.
#[test]
fn public_shared_receiver_places_are_validated_across_sources() {
    let root = TempDirectory::new();
    root.write_named(
        "counter.gnt",
        "struct Counter { value: Int } struct Holder { counter: Counter } impl Counter { pure fn read(shared self) -> Int { self.value } }",
    );
    root.write_named(
        "main.gnt",
        "mod counter; fn read_root(item: crate::counter::Counter) -> Int { item.read() } fn main(holder: crate::counter::Holder) -> Int { read_root(holder.counter) + holder.counter.read() }",
    );
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let accepted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    for source in [
        "mod counter; fn main() -> Int { crate::counter::Counter { value: 1 }.read() }",
        "mod counter; fn main(items: List<crate::counter::Counter>) -> Int { items[0].read() }",
        "mod counter; enum State { Ready(Int) } fn main() -> State { State::Ready(crate::counter::Counter { value: 1 }.read()) }",
    ] {
        root.write_named("main.gnt", source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
        let rejected = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code.as_str() == "shared-receiver-place" }),
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
    }
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

/// A typed scrutinee closes an unqualified generic enum pattern substitution.
#[test]
fn public_generic_enum_patterns_infer_substitution_from_scrutinee() {
    let accepted = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main(value: State<String, Int>) -> String { match value { State::Ready(item) => item, State::Failed(_) => \"failed\", } }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
}

/// Explicit generic enum patterns must agree with the typed scrutinee.
#[test]
fn public_explicit_generic_enum_patterns_reject_conflicting_scrutinee_types() {
    let rejected = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main(value: State<String, Int>) -> String { match value { State::<Int, String>::Ready(_) => \"ready\", State::<Int, String>::Failed(_) => \"failed\", } }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected.diagnostics().iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "pattern-type-mismatch" | "type-mismatch" | "conflicting-type-inference"
            )
        }),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Explicit generic enum patterns require exactly every type argument.
#[test]
fn public_explicit_generic_enum_pattern_argument_arity_is_exact() {
    for source in [
        "enum State<T, E> { Ready(T), Failed(E) } fn main(value: State<String, Int>) -> String { match value { State::<String>::Ready(item) => item, State::<String>::Failed(_) => \"failed\", } }",
        "enum State<T, E> { Ready(T), Failed(E) } fn main(value: State<String, Int>) -> String { match value { State::<String, Int, Bool>::Ready(item) => item, State::<String, Int, Bool>::Failed(_) => \"failed\", } }",
    ] {
        let rejected = analyze(source);
        assert_eq!(rejected.status(), AnalysisStatus::Invalid);
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "type-argument-arity"),
            "{:?}",
            rejected.diagnostics()
        );
    }
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
    use gantry::ir::{
        OwnershipClass, RecoveryProjectionClass, SourceProtectionClass, TransferEligibility,
        TypeDescriptor, ValueResourceClass,
    };
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
        "struct Phantom<T> { value: Int }\nenum GenericChoice<T, E> { Open(T), Closed(E) }\nstruct Stored { value: Decision }\nstruct Node<T> { value: T, next: Option<Node<T>> }\nfn inspect(value: Stored) {}\nfn inspect_node(value: Node<Decision>) {}\nfn inspect_choice(value: GenericChoice<Decision, Int>) {}\nfn main(value: Tuple<Phantom<Decision>, GenericChoice<Int, String>>) {}",
    );
    let policy = FrontendLimits::new(
        4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, 64, 64, 100,
    )
    .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
    for (name, external) in [
        ("crate::Phantom<Decision>", true),
        ("crate::GenericChoice<Int,String>", true),
        ("crate::GenericChoice<Decision,Int>", false),
        ("crate::Stored", false),
        ("crate::Node<Decision>", false),
    ] {
        let ty = TypeDescriptor::from_canonical_string(name)
            .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
        let properties = package
            .type_capabilities(&ty, policy)
            .unwrap_or_else(|error| panic!("query failed: {error:?}"));
        assert_eq!(properties.is_external(), external);
        assert_eq!(properties.is_equatable(), external);
        assert!(properties.is_interpolatable());
        assert_eq!(properties.ownership_class(), OwnershipClass::Copyable);
        assert!(properties.is_copyable());
        assert!(properties.is_task_capturable());
        assert_eq!(
            properties.transfer_eligibility(),
            TransferEligibility::IsolatedTaskCapture
        );
        assert_eq!(
            properties.resource_class(),
            ValueResourceClass::NonLiveResource
        );
        assert!(!properties.is_live_resource());
        assert_eq!(
            properties.source_protection_class(),
            if external {
                SourceProtectionClass::Unsealed
            } else {
                SourceProtectionClass::Sealed
            }
        );
        assert_eq!(properties.is_source_protected(), !external);
        assert_eq!(
            properties.recovery_projection_class(),
            RecoveryProjectionClass::SealedValue
        );
        assert!(properties.has_sealed_recovery_projection());
        assert_eq!(package.type_capabilities(&ty, policy), Ok(properties));
    }
    let unknown = TypeDescriptor::from_canonical_string("crate::Unknown")
        .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
    assert_eq!(
        package.type_capabilities(&unknown, policy),
        Err(TypeCapabilityQueryError::TypeNotRetained)
    );
    for (steps, succeeds) in [(8, true), (7, false), (8, true)] {
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

/// Standard containers fold stored sealed members without changing v1 value axes.
#[test]
fn public_standard_container_capabilities_fold_sealed_members() {
    use gantry::ir::{
        OwnershipClass, RecoveryProjectionClass, SourceProtectionClass, TransferEligibility,
        TypeDescriptor, ValueResourceClass,
    };
    use gantry::source::FrontendLimits;

    let package = analyze(
        "enum Choice { Open(Int), Protected(Decision) }\nfn option(value: Option<Decision>) {}\nfn result(value: Result<Int,Decision>) {}\nfn list(value: List<Decision>) {}\nfn tuple(value: Tuple<Int,Decision>) {}\nfn choice(value: Choice) {}\nfn main() {}",
    );
    let policy = FrontendLimits::new(
        4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, 64, 64, 100,
    )
    .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
    let tuple = TypeDescriptor::tuple(vec![TypeDescriptor::INT, TypeDescriptor::DECISION])
        .unwrap_or_else(|error| panic!("tuple descriptor failed: {error:?}"));

    for descriptor in [
        TypeDescriptor::option(TypeDescriptor::DECISION)
            .unwrap_or_else(|error| panic!("option descriptor failed: {error:?}")),
        TypeDescriptor::result(TypeDescriptor::INT, TypeDescriptor::DECISION),
        TypeDescriptor::list(TypeDescriptor::DECISION),
        tuple,
        TypeDescriptor::from_canonical_string("crate::Choice")
            .unwrap_or_else(|error| panic!("enum descriptor failed: {error:?}")),
    ] {
        let report = package
            .type_capabilities(&descriptor, policy)
            .unwrap_or_else(|error| panic!("container report failed: {error:?}"));
        assert!(!report.is_external(), "{descriptor:?}");
        assert!(!report.is_equatable(), "{descriptor:?}");
        assert!(report.is_interpolatable(), "{descriptor:?}");
        assert_eq!(
            report.source_protection_class(),
            SourceProtectionClass::Sealed,
            "{descriptor:?}"
        );
        assert_eq!(
            report.ownership_class(),
            OwnershipClass::Copyable,
            "{descriptor:?}"
        );
        assert_eq!(
            report.transfer_eligibility(),
            TransferEligibility::IsolatedTaskCapture,
            "{descriptor:?}"
        );
        assert_eq!(
            report.resource_class(),
            ValueResourceClass::NonLiveResource,
            "{descriptor:?}"
        );
        assert_eq!(
            report.recovery_projection_class(),
            RecoveryProjectionClass::SealedValue,
            "{descriptor:?}"
        );
    }
}

/// Ordered comparisons accept only same-type `Int` and `Float` operands.
#[test]
fn public_ordered_comparisons_require_exact_numeric_operands() {
    for source in [
        "fn compare(left: Int, right: Int) -> Bool { left < right } fn main() {}",
        "fn compare(left: Float, right: Float) -> Bool { left >= right } fn main() {}",
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
        "fn compare(left: Bool, right: Bool) -> Bool { left < right } fn main() {}",
        "fn compare(left: Int, right: Float) -> Bool { left < right } fn main() {}",
        "fn compare(left: List<Int>, right: List<Int>) -> Bool { left < right } fn main() {}",
        "fn compare(left: Decision, right: Decision) -> Bool { left < right } fn main() {}",
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
        assert!(package.executable_program().is_none());
    }
}

/// Type reports match canonical-key admission without extending the scalar domain.
#[test]
fn public_canonical_scalar_key_reports_match_value_admission() {
    use gantry::canonical_key::{CanonicalKeyError, DEFAULT_CANONICAL_KEY_LIMITS};
    use gantry::ir::TypeDescriptor;
    use gantry::numeric::{GantryFloat, GantryInt};
    use gantry::source::FrontendLimits;
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, OperationErrorValue};

    let package = analyze(
        "struct Pair { left: Int }\nfn list(value: List<Int>) {}\nfn tuple(value: Tuple<Int,Bool>) {}\nfn option(value: Option<Int>) {}\nfn result(value: Result<Int,String>) {}\nfn pair(value: Pair) {}\nfn main() {}",
    );
    let policy = FrontendLimits::new(
        4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, 64, 64, 100,
    )
    .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
    let integer = |value| {
        LogicalValue::integer(
            GantryInt::new(value).unwrap_or_else(|| unreachable!("test integer is in range")),
        )
    };
    let floating = |value| {
        LogicalValue::float(
            GantryFloat::new(value).unwrap_or_else(|| unreachable!("test float is finite")),
        )
    };

    for (descriptor, value) in [
        (TypeDescriptor::UNIT, LogicalValue::unit()),
        (TypeDescriptor::BOOL, LogicalValue::boolean(true)),
        (TypeDescriptor::INT, integer(7)),
        (TypeDescriptor::FLOAT, floating(1.5)),
        (
            TypeDescriptor::STRING,
            LogicalValue::string("key", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("test string failed: {error:?}")),
        ),
    ] {
        let report = package
            .type_capabilities(&descriptor, policy)
            .unwrap_or_else(|error| panic!("primitive report failed: {error:?}"));
        assert!(report.is_canonical_scalar_key(), "{descriptor:?}");
        assert!(report.is_hashable(), "{descriptor:?}");
        assert_eq!(
            report.is_orderable(),
            descriptor == TypeDescriptor::INT || descriptor == TypeDescriptor::FLOAT,
            "{descriptor:?}"
        );
        assert!(
            value.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS).is_ok(),
            "{descriptor:?}"
        );
    }

    let tuple = TypeDescriptor::tuple(vec![TypeDescriptor::INT, TypeDescriptor::BOOL])
        .unwrap_or_else(|error| panic!("tuple descriptor failed: {error:?}"));
    let option = TypeDescriptor::option(TypeDescriptor::INT)
        .unwrap_or_else(|error| panic!("option descriptor failed: {error:?}"));
    let cases = [
        (
            TypeDescriptor::DECISION,
            LogicalValue::decision(true, "because", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("test decision failed: {error:?}")),
        ),
        (
            TypeDescriptor::OPERATION_ERROR,
            LogicalValue::operation_error(OperationErrorValue::InvalidOutput, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("test operation error failed: {error:?}")),
        ),
        (
            TypeDescriptor::list(TypeDescriptor::INT),
            LogicalValue::list(vec![integer(1)], DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("test list failed: {error:?}")),
        ),
        (
            tuple,
            LogicalValue::tuple(
                vec![integer(1), LogicalValue::boolean(true)],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("test tuple failed: {error:?}")),
        ),
        (option, LogicalValue::none()),
        (
            TypeDescriptor::result(TypeDescriptor::INT, TypeDescriptor::STRING),
            LogicalValue::ok(integer(1), DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("test result failed: {error:?}")),
        ),
        (
            TypeDescriptor::from_canonical_string("crate::Pair")
                .unwrap_or_else(|error| panic!("pair descriptor failed: {error:?}")),
            LogicalValue::structure(
                "crate::Pair",
                vec![("left".to_owned(), integer(1))],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("test structure failed: {error:?}")),
        ),
    ];
    for (descriptor, value) in cases {
        let report = package
            .type_capabilities(&descriptor, policy)
            .unwrap_or_else(|error| panic!("non-scalar report failed: {error:?}"));
        assert!(!report.is_canonical_scalar_key(), "{descriptor:?}");
        assert!(!report.is_hashable(), "{descriptor:?}");
        assert!(!report.is_orderable(), "{descriptor:?}");
        assert!(matches!(
            value.canonical_key(DEFAULT_CANONICAL_KEY_LIMITS),
            Err(CanonicalKeyError::IneligibleKind(_))
        ));
    }
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

    let generic_enum = analyze(
        "enum Choice<T, E> { Open(T), Closed(E) }\nfn accept<T>(value: T) -> T where T: ExternalValue { value }\nfn main() { discard accept(Choice::<Decision, Int>::Open(decide \"x\")); }",
    );
    assert_eq!(generic_enum.status(), AnalysisStatus::Invalid);
    assert!(
        generic_enum.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "unsatisfied-bound"
                && diagnostic.fields.get("capability").map(AsRef::as_ref) == Some("ExternalValue")
                && diagnostic.fields.get("type").map(AsRef::as_ref)
                    == Some("crate::Choice<Decision,Int>")
        }),
        "{:?}",
        generic_enum.diagnostics()
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
    // Two inherent implementation blocks and one trait implementation name the same receiver, and
    // the canonical fact set keeps one head per identity while every block's methods stay
    // collected, so the package analyses (`0c64313b`).
    let split_inherent = analyze(
        r#"
struct P { v: Int }
trait T { pure fn t(self) -> Int; }
impl P { fn a(self) -> Int { self.v } }
impl T for P { fn t(self) -> Int { self.v } }
impl P { fn b(self) -> Int { self.v } }
fn main() -> Int { let p: P = P { v: 1 }; p.a() + p.b() }
"#,
    );
    assert_eq!(
        split_inherent.status(),
        AnalysisStatus::Valid,
        "{:?}",
        split_inherent.diagnostics()
    );
    assert_eq!(split_inherent.implementation_heads().len(), 3);
    // This accessor reports one head per block, while the canonical fact set built for execution
    // keeps one per identity; the two counts differ exactly by the redundant inherent head.
    // A duplicated inherent method name stays refused by name resolution.
    let duplicated_method = analyze(
        r#"
struct P { v: Int }
trait T { pure fn t(self) -> Int; }
impl P { fn a(self) -> Int { self.v } }
impl T for P { fn t(self) -> Int { self.v } }
impl P { fn a(self) -> Int { self.v } }
fn main() -> Int { let p: P = P { v: 1 }; p.a() }
"#,
    );
    assert_eq!(duplicated_method.status(), AnalysisStatus::Invalid);
    assert!(
        duplicated_method
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "duplicate-member"),
        "{:?}",
        duplicated_method.diagnostics()
    );
}

#[test]
/// An expected result is a permitted local fact and can close a substitution.
fn public_expected_result_completes_generic_substitution() {
    let expected_result =
        analyze("fn make<T>() -> T { make::<T>() } fn main() -> String { make() }");
    assert_eq!(
        expected_result.status(),
        AnalysisStatus::Valid,
        "{:?}",
        expected_result.diagnostics()
    );
    assert!(
        expected_result
            .generic_instantiations()
            .iter()
            .any(|instantiation| {
                instantiation.concrete().canonical_string() == "crate::make<String>"
            })
    );
}

/// Explicit generic argument lists must supply exactly every type parameter.
#[test]
fn public_explicit_generic_argument_arity_is_exact() {
    let accepted = analyze(
        "fn preserve<T>(value: T) -> T { value } fn main() { discard preserve::<String>(\"value\"); }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(
        "fn preserve<T>(value: T) -> T { value } fn main() { discard preserve::<String, Int>(\"value\"); }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "type-argument-arity"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Trait selection cannot infer a type parameter that local facts leave open.
#[test]
fn public_qualified_trait_calls_require_complete_inference() {
    let accepted = analyze(
        "trait Convert<T> { pure fn convert<U>(self, fallback: U) -> T; } struct Item {} impl Convert<String> for Item { pure fn convert<U>(self, fallback: U) -> String { \"converted\" } } fn main(value: Item) -> String { Convert::convert(value, 1) }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(
        "trait Convert<T> { pure fn convert<U>(self, fallback: U) -> T; } struct Item {} impl Convert<String> for Item { pure fn convert<U>(self, fallback: U) -> String { \"converted\" } } fn main(value: Item) { discard Convert::convert(value, 1); }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "incomplete-type-inference"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Qualified trait calls must prove the trait declaration's concrete predicates.
#[test]
fn public_qualified_trait_calls_enforce_declaration_predicates() {
    let source = |argument, receiver| {
        format!(
            "trait Marker {{ pure fn marker(self); }} trait Wrapped<T> where T: Marker {{ pure fn wrapped(self) -> String; }} struct Item {{}} struct Missing {{}} struct Envelope<T> {{ value: T }} impl Marker for Item {{ pure fn marker(self) {{}} }} impl<T> Wrapped<T> for Envelope<T> {{ pure fn wrapped(self) -> String {{ \"wrapped\" }} }} fn main(value: {receiver}) -> String {{ Wrapped::<{argument}>::wrapped(value) }}"
        )
    };

    let accepted = analyze(&source("Item", "Envelope<Item>"));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(&source("Missing", "Envelope<Missing>"));
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "missing-implementation"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Cyclic trait predicates reject instead of completing a provisional proof.
#[test]
fn public_cyclic_trait_obligations_are_rejected() {
    let cyclic = analyze(
        "trait First<T> { pure fn label(self) -> String; } trait Second<T> { pure fn second(self) -> String; } struct Item {} struct Envelope<T> { value: T } impl<T> First<T> for Envelope<T> where T: Second<Envelope<T>> { pure fn label(self) -> String { \"first\" } } impl<T> Second<T> for Item where T: First<Item> { pure fn second(self) -> String { \"second\" } } fn main(value: Envelope<Item>) -> String { First::<Item>::label(value) }",
    );
    assert_eq!(cyclic.status(), AnalysisStatus::Invalid);
    assert!(
        cyclic
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "cyclic-trait-obligation"),
        "{:?}",
        cyclic.diagnostics()
    );
}

/// Recursive capability proofs inspect stored members and ignore declaration order.
#[test]
fn public_recursive_generic_capabilities_are_structural() {
    for source in [
        "struct Node<T> { value: T, next: Option<Node<T>> } struct Envelope<T> where T: Equatable { value: T } fn inspect(value: Envelope<Node<String>>) {} fn main() {}",
        "struct Envelope<T> where T: Equatable { value: T } struct Node<T> { value: T, next: Option<Node<T>> } fn inspect(value: Envelope<Node<String>>) {} fn main() {}",
    ] {
        let accepted = analyze(source);
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{:?}",
            accepted.diagnostics()
        );
    }

    let rejected = analyze(
        "struct Node<T> { value: T, next: Option<Node<T>> } struct Envelope<T> where T: Equatable { value: T } fn inspect(value: Envelope<Node<Decision>>) {} fn main() {}",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "unsatisfied-bound"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Generic enum constructors use the selected substitution for every payload.
#[test]
fn public_generic_enum_constructor_payloads_are_exact() {
    let accepted = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() { discard State::<String, Int>::Ready(\"ok\"); }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() { discard State::<String, Int>::Ready(1); }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected.diagnostics().iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "aggregate-member-type" | "type-mismatch"
            )
        }),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Generic enum constructors require exactly every explicit type argument.
#[test]
fn public_explicit_generic_enum_constructor_argument_arity_is_exact() {
    let accepted = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() { discard State::<String, Int>::Ready(\"ok\"); }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    for source in [
        "enum State<T, E> { Ready(T), Failed(E) } fn main() { discard State::<String>::Ready(\"ok\"); }",
        "enum State<T, E> { Ready(T), Failed(E) } fn main() { discard State::<String, Int, Bool>::Ready(\"ok\"); }",
    ] {
        let rejected = analyze(source);
        assert_eq!(rejected.status(), AnalysisStatus::Invalid);
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "type-argument-arity"),
            "{:?}",
            rejected.diagnostics()
        );
    }
}

/// An unqualified generic enum constructor must resolve every type parameter.
#[test]
fn public_unqualified_generic_enum_constructor_requires_complete_substitution() {
    let unresolved = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() { discard State::Ready(\"ok\"); }",
    );
    assert_eq!(unresolved.status(), AnalysisStatus::Invalid);
    assert!(
        unresolved
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "incomplete-type-inference"),
        "{:?}",
        unresolved.diagnostics()
    );
    assert!(unresolved.executable_program().is_none());
}

/// Expected results close payloadless generic enum constructor substitutions.
#[test]
fn public_expected_result_completes_payloadless_generic_enum_constructor() {
    let accepted = analyze(
        "enum State<T, E> { Ready(T), Failed(E), Pending } fn main() -> State<String, Int> { State::Pending }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let unresolved = analyze(
        "enum State<T, E> { Ready(T), Failed(E), Pending } fn main() { discard State::Pending; }",
    );
    assert_eq!(unresolved.status(), AnalysisStatus::Invalid);
    assert!(
        unresolved
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "incomplete-type-inference"),
        "{:?}",
        unresolved.diagnostics()
    );
}

/// Expected results select generic enum payload types for nested constructors.
#[test]
fn public_expected_result_completes_generic_enum_constructor_substitution() {
    let accepted = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() -> State<Option<String>, Int> { State::Ready(None) }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() -> State<Option<String>, Int> { State::Ready(1) }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected.diagnostics().iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "aggregate-member-type" | "type-mismatch" | "conflicting-type-inference"
            )
        }),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Expected results select generic enum error payload types for nested constructors.
#[test]
fn public_expected_result_completes_generic_enum_error_constructor_substitution() {
    let accepted = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() -> State<Int, Option<String>> { State::Failed(None) }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(
        "enum State<T, E> { Ready(T), Failed(E) } fn main() -> State<Int, Option<String>> { State::Failed(1) }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected.diagnostics().iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "aggregate-member-type" | "type-mismatch" | "conflicting-type-inference"
            )
        }),
        "{:?}",
        rejected.diagnostics()
    );
}

#[test]
/// An expected aggregate result closes its generic struct substitution.
fn public_expected_result_completes_generic_struct_substitution() {
    let expected_result =
        analyze("struct Envelope<T> {} fn main() -> Envelope<String> { Envelope {} }");
    assert_eq!(
        expected_result.status(),
        AnalysisStatus::Valid,
        "{:?}",
        expected_result.diagnostics()
    );
    assert!(expected_result.generic_types().iter().any(|fact| {
        fact.descriptor
            .as_ref()
            .is_some_and(|descriptor| descriptor.canonical_string() == "crate::Envelope<String>")
    }));
}

/// A generic field default must remain valid for every admitted substitution.
#[test]
fn public_generic_field_defaults_are_universal() {
    let accepted = analyze("struct Envelope<T> { value: Option<T> = None } fn main() {}");
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze("struct Envelope<T> { value: T = \"not universal\" } fn main() {}");
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "invalid-field-default"),
        "{:?}",
        rejected.diagnostics()
    );
}

#[test]
/// A generic aggregate without member or expected-type facts remains incomplete.
fn public_unconstrained_generic_struct_construction_is_rejected() {
    let unconstrained = analyze("struct Envelope<T> {} fn main() { discard Envelope {}; }");
    assert_eq!(unconstrained.status(), AnalysisStatus::Invalid);
    assert!(
        unconstrained
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "incomplete-type-inference"),
        "{:?}",
        unconstrained.diagnostics()
    );
    assert!(unconstrained.executable_program().is_none());
}

#[test]
/// A resolved generic aggregate field supplies the expected type for `None`.
fn public_expected_generic_aggregate_propagates_nested_constructor_type() {
    let expected_result = analyze(
        "struct Envelope<T> { value: Option<T> } fn main() -> Envelope<String> { Envelope { value: None } }",
    );
    assert_eq!(
        expected_result.status(),
        AnalysisStatus::Valid,
        "{:?}",
        expected_result.diagnostics()
    );
    assert!(expected_result.generic_types().iter().any(|fact| {
        fact.descriptor
            .as_ref()
            .is_some_and(|descriptor| descriptor.canonical_string() == "crate::Envelope<String>")
    }));
}

#[test]
/// Expected `Result` variants propagate their selected member type to nested constructors.
fn public_expected_result_variants_propagate_nested_constructor_types() {
    for source in [
        "fn main() -> Result<Option<String>, Int> { Ok(None) }",
        "fn main() -> Result<Int, Option<String>> { Err(None) }",
        "enum State<T, E> { Ready(T), Failed(E) } fn main() -> State<Option<String>, Int> { State::Ready(None) }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
    }
}

#[test]
/// Trait selection occurs after inference and cannot supply a missing type.
fn public_unique_trait_implementation_cannot_guess_missing_type() {
    let implementation_must_not_guess = analyze(
        r#"
trait Produce<T> { pure fn produce(self) -> T; }
struct Factory {}
impl Produce<String> for Factory {
    pure fn produce(self) -> String { "made" }
}
fn main(value: Factory) { discard Produce::produce(value); }
"#,
    );
    assert_eq!(
        implementation_must_not_guess.status(),
        AnalysisStatus::Invalid
    );
    assert!(
        implementation_must_not_guess
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.code.as_str() == "incomplete-type-inference" })
    );
}

#[test]
/// Conflicting expected and argument facts produce one stable inference error.
fn public_conflicting_expected_and_argument_facts_reject_deterministically() {
    let conflicting_facts =
        analyze("fn preserve<T>(value: T) -> T { value } fn main() -> String { preserve(1) }");
    assert_eq!(conflicting_facts.status(), AnalysisStatus::Invalid);
    let inference_codes = conflicting_facts
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "conflicting-type-inference" | "incomplete-type-inference"
            )
        })
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(inference_codes, ["conflicting-type-inference"]);
}

#[test]
/// Substitution cannot introduce an option member forbidden by the public wire contract.
fn public_generic_substitution_rejects_ambiguous_option_members() {
    for source in [
        "struct Stored<T> { value: Option<T> } fn internal(value: Stored<Unit>) {} fn main() {}",
        "struct Stored<T> { value: Option<T> } struct Outer<T> { inner: Stored<T> } fn internal(value: List<Outer<Option<Int>>>) {} fn main() {}",
        "struct Stored<T> { value: Option<T> } struct Wrap<T> { value: T } fn make<T>(value: T) -> Wrap<Wrap<Stored<T>>> { make(value) } fn main() { discard make(()); }",
        "enum Stored<T> { Empty, Value(Option<T>) } fn main() { discard Stored::<Unit>::Empty; }",
        "struct Stored<T> { value: Option<T> } struct Outer<T> { inner: Stored<T> } fn main(value: Outer<Unit>) { discard value; }",
        "struct Stored<T> { value: Option<T> } struct Outer<T> { inner: Stored<T> } fn make<T>(value: T) -> Outer<T> { make(value) } fn main() { let value: Option<Int> = Some(1); discard make(value); }",
        "struct Stored<T> { value: Option<T> } fn main(value: Stored<Unit>) { discard value; }",
        "struct Stored<T> { value: Option<T> } fn main(value: Stored<Option<Int>>) { discard value; }",
        "enum Stored<T> { Value(Option<T>) } fn main(value: Stored<Unit>) { discard value; }",
        "enum Stored<T> { Value(Option<T>) } fn main(value: Stored<Option<Int>>) { discard value; }",
        "fn make<T>() -> Option<T> { None } fn main() { discard make::<Unit>(); }",
        "fn make<T>() -> Option<T> { None } fn main() { discard make::<Option<Int>>(); }",
    ] {
        assert_forbidden_generic_option(source);
    }
}

#[test]
/// Tagged and object-shaped members keep an outer generic option injective.
fn public_generic_substitution_accepts_shaped_option_members() {
    for source in [
        "struct Payload { value: Option<Int> } struct Stored<T> { value: Option<T> } fn main(value: Stored<Payload>) { discard value; }",
        "struct Payload { value: Option<Int> } enum Stored<T> { Value(Option<T>) } fn main(value: Stored<Payload>) { discard value; }",
        "struct Payload { value: Option<Int> } struct Stored<T> { value: Option<T> } struct Wrap<T> { value: T } fn main(value: Wrap<Wrap<Stored<Payload>>>) { discard value; }",
        "fn identity<T>(value: T) -> T { value } fn main() { discard identity(()); }",
        "enum Payload { Present(Option<Int>) } fn make<T>() -> Option<T> { None } fn main() -> Option<Payload> { make::<Payload>() }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
        assert!(package.executable_program().is_some());
    }
}

#[test]
/// Stored-member option validation has inclusive public cutoffs and retains earlier diagnostics.
fn public_generic_option_validation_obeys_work_and_depth_cutoffs() {
    let source = "use crate::missing; struct Stored<T> { value: Option<T> } struct Outer<T> { inner: Stored<T> } fn main(value: Outer<Unit>) { discard value; }";
    let phase = syntax(source);

    let at_work_limit = analyze_package_types_with_limits(&phase, analysis_limits(64, 6))
        .unwrap_or_else(|error| panic!("at-limit option validation failed: {error:?}"));
    assert_eq!(at_work_limit.status(), AnalysisStatus::Invalid);
    assert!(
        at_work_limit
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "invalid-option-type")
    );
    let at_depth_limit = analyze_package_types_with_limits(&phase, analysis_limits(2, 6))
        .unwrap_or_else(|error| panic!("at-limit option depth failed: {error:?}"));
    assert_eq!(at_depth_limit.diagnostics(), at_work_limit.diagnostics());

    for (depth, work, code) in [
        (64, 5, FrontendResourceCode::TraitResolutionStepLimit),
        (1, 6, FrontendResourceCode::ConstructedTypeDepthLimit),
    ] {
        let Err(AnalysisError::ResourceLimit { error, diagnostics }) =
            analyze_package_types_with_limits(&phase, analysis_limits(depth, work))
        else {
            panic!("option validation unexpectedly crossed the {code:?} cutoff")
        };
        assert_eq!(error.code, code);
        assert_eq!(error.limit, if depth == 1 { depth } else { work });
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "unresolved-import"),
            "prior diagnostic was lost at {code:?}: {diagnostics:?}"
        );
        if code == FrontendResourceCode::TraitResolutionStepLimit {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code.as_str() == "invalid-option-type"),
                "validated option diagnostic was lost at the work cutoff: {diagnostics:?}"
            );
        }
    }
}

#[test]
/// Declared recursion permits only guarded regular self recursion in v1.
fn public_declared_recursion_obeys_guarded_regular_v1_rules() {
    let phase =
        syntax("struct Node<T> { next: Option<Node<List<T>>> } fn main(value: Node<Int>) {}");
    let package = analyze_package_types_with_limits(&phase, analysis_limits(16, 256))
        .unwrap_or_else(|error| panic!("rejected recursion reached later expansion: {error:?}"));
    assert_eq!(package.status(), AnalysisStatus::Invalid);
    assert!(
        package
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "polymorphic-recursion")
    );
    assert!(package.executable_program().is_none());

    let bounded = syntax(
        "struct Node<T> { next: Option<Node<List<T>>> } struct Envelope<T> where T: Equatable { value: T } fn main(value: Envelope<Node<Int>>) {}",
    );
    let package = analyze_package_types_with_limits(&bounded, analysis_limits(16, 256))
        .unwrap_or_else(|error| panic!("rejected bound proof kept expanding: {error:?}"));
    assert_eq!(package.status(), AnalysisStatus::Invalid);
    for code in ["polymorphic-recursion", "unsatisfied-bound"] {
        assert!(
            package
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "expected {code}: {:?}",
            package.diagnostics()
        );
    }

    let regular = syntax(
        "struct Node<T> { value: T, next: Option<Node<T>> } struct Envelope<T> where T: Equatable { value: T } fn main(value: Envelope<Node<Int>>) {}",
    );
    let package = analyze_package_types_with_limits(&regular, analysis_limits(16, 256))
        .unwrap_or_else(|error| panic!("regular recursion proof failed: {error:?}"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    assert!(package.executable_program().is_some());

    for source in [
        "struct Node { next: Option<Node> } fn main() {}",
        "struct Node<T> { next: List<Node<T>> } fn main() {}",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{:?}",
            package.diagnostics()
        );
    }

    for (source, code) in [
        (
            "struct Node { next: Node } fn main() {}",
            "unguarded-recursive-type",
        ),
        (
            "struct Node<T> { next: Option<Node<List<T>>> } fn main() {}",
            "polymorphic-recursion",
        ),
        (
            "struct Pair<T, U> { next: Option<Pair<U, T>> } fn main() {}",
            "polymorphic-recursion",
        ),
        (
            "struct Left { right: Option<Right> } struct Right { left: Option<Left> } fn main() {}",
            "recursive-type-cycle",
        ),
        (
            "enum Node { Next(Option<Node>) } fn main() {}",
            "recursive-enum",
        ),
    ] {
        let package = analyze(source);
        assert_eq!(package.status(), AnalysisStatus::Invalid);
        assert!(
            package
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "expected {code}: {:?}",
            package.diagnostics()
        );
    }
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
    analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed: {error:?} in source: {source}"))
}

/// Requires one substituted ambiguous option to invalidate analysis without publishing a program.
fn assert_forbidden_generic_option(source: &str) {
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
            .any(|diagnostic| diagnostic.code.as_str() == "invalid-option-type"),
        "{:?}",
        package.diagnostics()
    );
    assert!(package.executable_program().is_none());
}

fn syntax(source: &str) -> gantry::frontend::CompletedSyntaxPhase {
    let root = TempDirectory::new();
    root.write(source);
    validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"))
}

/// Field projections in operand position type as their projected member type.
#[test]
fn field_projection_operands_type_as_their_member_type() {
    let package =
        analyze("struct Token { a: Int, b: Int }\nfn main(t: Token) -> Int { t.a + t.b }");
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    assert!(package.executable_program().is_some());
}

/// A nested field projection chain in operand position types as its leaf member type.
#[test]
fn nested_field_projection_operands_type_as_their_member_type() {
    let package = analyze(
        "struct Inner { value: Int }\nstruct Outer { inner: Inner }\nfn main(o: Outer) -> Int { o.inner.value + o.inner.value }",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    assert!(package.executable_program().is_some());
}

/// Distinct affine field reads in operand position record one projected place each.
#[test]
fn affine_field_projection_operands_avoid_spurious_reuse() {
    let package =
        analyze("affine struct Token { a: Int, b: Int }\nfn main(t: Token) -> Int { t.a + t.b }");
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    assert!(
        !package
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "affine-value-reuse"),
        "{:?}",
        package.diagnostics()
    );
}

/// A projection read after an owned move of its root stays rejected.
#[test]
fn affine_projection_read_after_owned_move_stays_rejected() {
    let rejected = analyze(
        "affine struct Token { a: Int, b: Int }\nimpl Token { fn consume(owned self) {} }\nfn main(t: Token) -> Int { t.consume(); t.a }",
    );
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "affine-value-reuse"),
        "{:?}",
        rejected.diagnostics()
    );
    assert!(rejected.executable_program().is_none());
}

/// Bare and mixed operands beside a field projection keep their accepted types.
#[test]
fn field_projection_operand_controls_stay_valid() {
    for source in [
        "struct Token { a: Int, b: Int } fn main(t: Token) -> Int { t.a + 1 }",
        "struct Token { a: Int, b: Int } fn main(t: Token) -> Int { 1 + t.a }",
        "struct Token { a: Int, b: Int } fn main(t: Token) -> Bool { t.a == t.b }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            package.diagnostics()
        );
    }
}

fn analysis_limits(depth: u64, trait_steps: u64) -> FrontendLimits {
    FrontendLimits::new(
        4,
        65_536,
        65_536,
        65_536,
        64,
        65_536,
        65_536,
        65_536,
        65_536,
        depth,
        64,
        trait_steps,
    )
    .unwrap_or_else(|_| unreachable!("positive frontend limits"))
}

fn limits() -> SourceLimits {
    SourceLimits::new(4, 65_536, 65_536, 65_536, 64)
        .unwrap_or_else(|_| unreachable!("positive limits"))
}

/// Every receiver-family diagnostic code reported for one analyzed package.
fn receiver_family_codes(diagnostics: &[gantry::source::StructuredDiagnostic]) -> Vec<&str> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .filter(|code| {
            code.starts_with("exclusive-receiver-")
                || code.starts_with("exclusive-reborrow-")
                || code.starts_with("shared-receiver-")
                || code.starts_with("owned-receiver-")
        })
        .collect()
}

/// Every diagnostic code reported for one analyzed package.
fn diagnostic_codes(diagnostics: &[gantry::source::StructuredDiagnostic]) -> Vec<&str> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
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

/// `affine struct` seeds `AffineDroppable`; plain structs fold member classes, and empty or
/// generic affine structs stay affine.
#[test]
fn affine_structs_fold_ownership_class_and_generics() {
    use gantry::ir::{OwnershipClass, TypeDescriptor};

    let package = analyze(
        "affine struct Token { value: Int }\n\
         affine struct Empty {}\n\
         affine struct Generic<T> { value: T }\n\
         struct Plain { value: Int }\n\
         struct Contains { token: Token }\n\
         fn use_token(value: Token) {}\n\
         fn use_empty(value: Empty) {}\n\
         fn use_generic(value: Generic<Int>) {}\n\
         fn use_plain(value: Plain) {}\n\
         fn use_contains(value: Contains) {}\n\
         fn main() {}",
    );
    let policy = analysis_limits(64, 100);
    for (name, affine) in [
        ("crate::Token", true),
        ("crate::Empty", true),
        ("crate::Generic<Int>", true),
        ("crate::Plain", false),
        ("crate::Contains", true),
    ] {
        let ty = TypeDescriptor::from_canonical_string(name)
            .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
        let properties = package
            .type_capabilities(&ty, policy)
            .unwrap_or_else(|error| panic!("query failed for {name}: {error:?}"));
        assert_eq!(
            properties.ownership_class(),
            if affine {
                OwnershipClass::AffineDroppable
            } else {
                OwnershipClass::Copyable
            },
            "{name}"
        );
    }
}

/// Copying or reusing an `AffineDroppable` value is a compile-time rejection.
#[test]
fn affine_values_are_rejected_when_copied_or_reused() {
    for source in [
        "affine struct Token {}\nfn take(t: Token) {}\nfn main(t: Token) {\n    take(t);\n    take(t);\n}",
        "affine struct Token {}\nfn main(t: Token) {\n    let a: Token = t;\n    let b: Token = t;\n}",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "affine-value-reuse"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }
}

/// An `owned self` method on an affine receiver lowers to `CallerPlace`, while a copyable owned
/// receiver stays `CopiedValue`.
#[test]
fn affine_owned_receiver_lowers_to_caller_place_move() {
    use gantry::ir::{InstructionKind, ReceiverSource};

    let package = analyze(
        "affine struct Token { value: Int }\n\
         struct Counter { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         impl Counter { fn bump(owned self) -> Int { self.value } }\n\
         fn bump_counter(counter: Counter) -> Int { counter.bump() }\n\
         fn consume_token(token: Token) -> Int { token.consume() }\n\
         fn main(token: Token) -> Int {\n\
             discard bump_counter(Counter { value: 1 });\n\
             consume_token(token)\n\
         }",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package has an executable program"));
    let mut saw_caller_place = false;
    let mut saw_copied_value = false;
    for workflow in program.workflows() {
        for instruction in &workflow.instructions {
            if let InstructionKind::ReceiverCall { source, .. } = &instruction.kind {
                match source {
                    ReceiverSource::CallerPlace { .. } => saw_caller_place = true,
                    ReceiverSource::CopiedValue => saw_copied_value = true,
                }
            }
        }
    }
    assert!(
        saw_caller_place,
        "affine owned receiver did not lower to CallerPlace"
    );
    assert!(
        saw_copied_value,
        "copyable owned receiver did not stay CopiedValue"
    );
}

/// Reading a moved affine place after an owned move is rejected.
#[test]
fn affine_moved_place_cannot_be_read_again() {
    let rejected = analyze(
        "affine struct Token {} fn take(t: Token) {} impl Token { fn consume(owned self) {} } fn main(t: Token) { t.consume(); take(t); }",
    );
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "affine-value-reuse"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Requires one affine misuse to be rejected by a source diagnostic, never an internal failure.
///
/// A group around an affine receiver's root is transparent to the place it names: `(w).inner.take()`
/// keys the same binding-root struct-field place as `w.inner.take()`, so two sibling fields are two
/// places rather than one reuse, while a second call through the same field stays a reuse of it.
#[test]
fn public_grouped_affine_receiver_places_are_field_precise() {
    let header = "affine struct Plain { value: Int } affine struct Marker { value: Int } \
        struct Wrap { inner: Plain, marker: Marker } \
        impl Plain { fn take(self) -> Int { self.value } } \
        impl Marker { fn take(self) -> Int { self.value } } \
        fn main() -> Int { let w: Wrap = Wrap { inner: Plain { value: 42 }, marker: Marker { value: 1 } }; ";
    for tail in [
        "let a: Int = (w).inner.take(); let b: Int = (w).marker.take(); a + b }",
        "let a: Int = w.inner.take(); let b: Int = w.marker.take(); a + b }",
    ] {
        let source = format!("{header}{tail}");
        let admitted = analyze(&source);
        assert!(
            admitted.status() != AnalysisStatus::Invalid,
            "{source}: {:?}",
            admitted.diagnostics()
        );
        assert!(
            admitted.executable_program().is_some(),
            "{source}: two sibling fields publish a program"
        );
    }
    let reuse =
        format!("{header}let a: Int = (w).inner.take(); let b: Int = (w).inner.take(); a + b }}");
    assert_affine_rejected(&reuse, "affine-value-reuse");
}

/// An index projection in an operand position is the element it reads.
///
/// `h.items[0]` is one element of the list a field holds, so an operator sees `Int` whether the
/// receiver is a binding, a grouped binding, or a constructed value; a projection whose receiver
/// publishes no element refuses with the projection's own code and publishes no program.
#[test]
fn public_index_projection_operands_are_keyed() {
    for (source, admitted) in [
        (
            "struct HL { items: List<Int> } fn main() -> Int { let h: HL = HL { items: [7] }; h.items[0] + h.items[0] }",
            true,
        ),
        (
            "struct HL { items: List<Int> } fn main() -> Int { let h: HL = HL { items: [7] }; (h).items[0] + h.items[0] }",
            true,
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; xs[0] + xs[1] }",
            true,
        ),
        ("fn main() -> Int { [1, 2][0] + [3, 4][1] }", true),
        (
            "struct Bag { items: List<Int> } fn main() -> Int { Bag { items: [7] }.items[0] + Bag { items: [7] }.items[0] }",
            true,
        ),
        ("fn main() -> Int { [1, 2][0][0] + 1 }", false),
        ("fn main() -> Bool { [1, 2][0][0] == 1 }", false),
    ] {
        let analysed = analyze(source);
        if admitted {
            assert!(
                analysed.status() != AnalysisStatus::Invalid,
                "{source}: {:?}",
                analysed.diagnostics()
            );
            assert!(
                analysed.executable_program().is_some(),
                "{source}: an admitted projection operand publishes a program"
            );
            continue;
        }
        assert_eq!(
            analysed.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            analysed.diagnostics()
        );
        assert_eq!(
            analysed.diagnostics().len(),
            1,
            "{source}: {:?}",
            analysed.diagnostics()
        );
        assert!(
            analysed
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "projection-receiver-type"),
            "{source}: {:?}",
            analysed.diagnostics()
        );
        assert!(
            analysed.executable_program().is_none(),
            "{source}: a refused projection operand publishes no program"
        );
    }
}

/// Section 38: a panic types its operand, lowers on every path the machine reaches, and leaves
/// the source that follows it unreachable (`GNT-38.2-assertions-and-panic`).
#[test]
fn section_38_panic_positions_are_typed_and_refused() {
    let admitted = analyze("fn boom() -> Int { panic(\"x\"); } fn main() -> Int { 0 }");
    assert_eq!(admitted.status(), AnalysisStatus::Valid);
    let called = analyze("fn boom() -> Int { panic(\"x\"); } fn main() -> Int { boom() }");
    assert_eq!(called.status(), AnalysisStatus::Valid);
    let operand = analyze("fn boom() -> Int { panic(1); } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(operand.diagnostics()).contains(&"panic-path-refused"));
    let entry = analyze("fn main() -> Int { panic(\"x\"); 1 }");
    assert!(diagnostic_codes(entry.diagnostics()).contains(&"unreachable-source"));
    assert!(!diagnostic_codes(entry.diagnostics()).contains(&"panic-path-refused"));
    let control = analyze("fn main() -> Int { 0 }");
    assert_eq!(control.status(), AnalysisStatus::Valid);
}

/// Section 38: an assertion operand is checked, an admitted path lowers it, and a refused operand
/// names its reason (`GNT-38.2-assertions-and-panic`).
#[test]
fn section_38_assertions_are_typed_and_refused() {
    let admitted = analyze("fn boom() -> Int { assert(true); 1 } fn main() -> Int { 0 }");
    assert_eq!(admitted.status(), AnalysisStatus::Valid);
    let called = analyze("fn boom() -> Int { assert(true); 1 } fn main() -> Int { boom() }");
    assert_eq!(called.status(), AnalysisStatus::Valid);
    let operand = analyze("fn boom() -> Int { assert(1); 1 } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(operand.diagnostics()).contains(&"panic-path-refused"));
    let entry = analyze("fn main() -> Int { assert(true); 1 }");
    assert_eq!(entry.status(), AnalysisStatus::Valid);
    let control = analyze("fn main() -> Int { 0 }");
    assert_eq!(control.status(), AnalysisStatus::Valid);
    fn reason<'a>(
        diagnostics: &'a [gantry::source::StructuredDiagnostic],
        field: &str,
    ) -> Option<&'a str> {
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "panic-path-refused")
            .and_then(|diagnostic| diagnostic.fields.get(field))
            .map(|value| value.as_ref())
    }
    assert_eq!(reason(called.diagnostics(), "reason"), None);
    assert_eq!(reason(entry.diagnostics(), "reason"), None);
    assert_eq!(
        reason(operand.diagnostics(), "reason"),
        Some("operand-type")
    );
}

/// Section 38: both admitted source forms lower to the failure instruction, and an assertion
/// guards it with its condition branch (`GNT-38.2-assertions-and-panic`).
#[test]
fn section_38_panic_and_assertion_lower_to_the_failure_instruction() {
    let panicking = analyze("fn boom() -> Int { panic(\"x\"); } fn main() -> Int { boom() }");
    assert_eq!(panicking.status(), AnalysisStatus::Valid);
    let program = panicking
        .executable_program()
        .unwrap_or_else(|| panic!("a valid package publishes a program"));
    let boom = program
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::boom")
        .unwrap_or_else(|| panic!("the called panic workflow is lowered"));
    assert!(
        boom.instructions
            .iter()
            .any(|instruction| matches!(instruction.kind, InstructionKind::Panic)),
        "a panic body lowers to the failure instruction"
    );

    let asserted = analyze("fn check() -> Int { assert(true); 1 } fn main() -> Int { check() }");
    assert_eq!(asserted.status(), AnalysisStatus::Valid);
    let program = asserted
        .executable_program()
        .unwrap_or_else(|| panic!("a valid package publishes a program"));
    let check = program
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::check")
        .unwrap_or_else(|| panic!("the called assertion workflow is lowered"));
    assert!(
        check
            .instructions
            .iter()
            .any(|instruction| matches!(instruction.kind, InstructionKind::Panic)),
        "an assertion lowers its failure arm to the failure instruction"
    );
}

/// Section 38: a reachable panic lowers on generic and method callees alike, the operand refusal
/// names its reason, and the statement form requires its own semicolon.
#[test]
fn section_38_panic_refusals_name_their_reason() {
    fn reason<'a>(
        diagnostics: &'a [gantry::source::StructuredDiagnostic],
        field: &str,
    ) -> Option<&'a str> {
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "panic-path-refused")
            .and_then(|diagnostic| diagnostic.fields.get(field))
            .map(|value| value.as_ref())
    }
    let generic = analyze("fn boom<X>(x: X) -> Int { panic(\"x\"); } fn main() -> Int { boom(1) }");
    assert_eq!(generic.status(), AnalysisStatus::Valid);
    let method = analyze(
        "struct S {} impl S { fn boom(self) -> Int { panic(\"x\"); } } fn main() -> Int { let s: S = S {}; s.boom() }",
    );
    assert_eq!(method.status(), AnalysisStatus::Valid);
    let operand = analyze("fn boom() -> Int { panic(1); } fn main() -> Int { 0 }");
    assert_eq!(
        reason(operand.diagnostics(), "reason"),
        Some("operand-type")
    );
    // Neither an uncalled generic template nor an uncalled monomorphic method reaches a panic
    // path the lowering compiles, so both stay source-valid.
    let template = analyze("fn boom<X>(x: X) -> Int { panic(\"x\"); } fn main() -> Int { 0 }");
    assert_eq!(template.status(), AnalysisStatus::Valid);
    let uncalled = analyze(
        "struct S {} impl S { fn boom(self) -> Int { panic(\"x\"); } } fn main() -> Int { 0 }",
    );
    assert_eq!(uncalled.status(), AnalysisStatus::Valid);
    // The statement form carries its own semicolon, like `discard` and `return`: the syntax phase
    // succeeds but reports an invalid status for the trailing spelling.
    let root = TempDirectory::new();
    root.write("fn main() -> Int { panic(\"x\") }");
    let phase = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    assert_eq!(
        phase.status(),
        gantry::frontend::PackageSyntaxStatus::Invalid
    );
}

/// Section 38: divergence through statement branches and loops is admitted and lowers to the
/// failure instruction, and it never constrains the declared result
/// (`GNT-38.3-divergence-and-never`).
#[test]
fn section_38_divergent_branches_and_loops_are_admitted() {
    // Every branch diverges, so the declared `Int` result is satisfied without a value.
    let both = analyze(
        "fn both(flag: Bool) -> Int { if flag { panic(\"a\"); } else { panic(\"b\"); } } fn main() -> Int { both(true) }",
    );
    assert_eq!(both.status(), AnalysisStatus::Valid);
    let program = both
        .executable_program()
        .unwrap_or_else(|| panic!("a valid package publishes a program"));
    let divergent = program
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::both")
        .unwrap_or_else(|| panic!("the divergent workflow is lowered"));
    assert!(
        divergent
            .instructions
            .iter()
            .any(|instruction| matches!(instruction.kind, InstructionKind::Panic)),
        "a divergent branch lowers to the failure instruction"
    );

    // One branch returns and the other diverges; the body still has no normal completion.
    let mixed = analyze(
        "fn stop(flag: Bool) -> Int { if flag { return 1; } else { panic(\"s\"); } } fn main() -> Int { stop(false) }",
    );
    assert_eq!(mixed.status(), AnalysisStatus::Valid);

    // An unbroken loop has no normal completion either.
    let looping = analyze("fn main() -> Int { loop { } }");
    assert_eq!(looping.status(), AnalysisStatus::Valid);

    // A loop that can fall through still reports the missing result.
    let falling = analyze("fn main() -> Int { let mut i: Int = 0; while i < 3 { i += 1; } }");
    assert!(diagnostic_codes(falling.diagnostics()).contains(&"missing-result"));

    // Value-position branching cannot diverge today: `match` arms are expressions, so the
    // statement forms and loops are the divergence carriers (`if` is a command, not an
    // expression). The value match remains the admitted control.
    let values = analyze(
        "fn main() -> Int { let o: Option<Int> = Some(1); let x: Int = match o { Some(v) => v, None => 0 }; x }",
    );
    assert_eq!(values.status(), AnalysisStatus::Valid);

    // A non-returning statement is not an expression, so it cannot appear as a match arm: the
    // expression-level divergence carrier this phase would need does not exist yet.
    let root = TempDirectory::new();
    root.write(
        "fn main() -> Int { let o: Option<Int> = Some(1); let x: Int = match o { Some(v) => v, None => panic(\"b\") }; x }",
    );
    let phase = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    assert_eq!(
        phase.status(),
        gantry::frontend::PackageSyntaxStatus::Invalid
    );

    // A nested all-divergent branch exercises the same completion rule one level deeper.
    let nested = analyze(
        "fn nest(a: Bool, b: Bool) -> Int { if a { if b { panic(\"x\"); } else { return 1; } } else { panic(\"y\"); } } fn main() -> Int { nest(true, false) }",
    );
    assert_eq!(nested.status(), AnalysisStatus::Valid);
}

/// Section 38: a propagation operand has no exactly one declared conversion while no
/// error-conversion contract is published, so every operand is refused with its types named
/// (`GNT-38.1-typed-error-propagation`).
#[test]
fn section_38_propagation_operands_are_refused() {
    let refused = analyze(
        "fn f() -> Result<Int, String> { Err(\"x\") } fn main() -> Result<Int, String> { let v: Int = f()?; Ok(v) }",
    );
    let propagation = refused
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "error-propagation-refused")
        .unwrap_or_else(|| panic!("the propagation operand is refused"));
    assert_eq!(
        propagation
            .fields
            .get("enclosing")
            .map(|value| value.as_ref()),
        Some("Result<Int,String>")
    );
    assert_eq!(
        propagation
            .fields
            .get("operand")
            .map(|value| value.as_ref()),
        Some("Result<Int,String>")
    );

    // A non-`Result` operand is refused by the same code. The `operand` field reports the
    // fallback `Unit` here because the analyzer records no fact for a bare literal operand;
    // the field becomes exact when payload typing records the marker expression's own type.
    let literal = analyze("fn main() -> Int { let v: Int = 1?; v }");
    assert!(diagnostic_codes(literal.diagnostics()).contains(&"error-propagation-refused"));

    // The same call without a propagation operand stays admitted.
    let control = analyze(
        "fn f() -> Result<Int, String> { Err(\"x\") } fn main() -> Int { let r: Result<Int, String> = f(); match r { Ok(v) => v, Err(e) => 0 } }",
    );
    assert_eq!(control.status(), AnalysisStatus::Valid);

    // Every operand is named, not only the first one in the body.
    let both = analyze(
        "fn f() -> Result<Int, String> { Err(\"x\") } fn g() -> Result<Int, String> { Err(\"y\") } fn main() -> Result<Int, String> { let a: Int = f()?; let b: Int = g()?; Ok(a + b) }",
    );
    let refused = both
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "error-propagation-refused")
        .count();
    assert_eq!(refused, 2);
    // Each refusal names its own operand at a distinct span, so attribution is pinned rather
    // than only the count.
    let mut attributions = both
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "error-propagation-refused")
        .map(|diagnostic| {
            (
                format!("{:?}", diagnostic.primary),
                diagnostic
                    .fields
                    .get("operand")
                    .map(|value| value.as_ref().to_owned()),
            )
        })
        .collect::<Vec<_>>();
    attributions.sort();
    attributions.dedup_by(|left, right| left.0 == right.0);
    assert_eq!(attributions.len(), 2);
    for (_, operand) in &attributions {
        assert_eq!(operand.as_deref(), Some("Result<Int,String>"));
    }
    // A marker inside a nested block and a marker nested in another marker are both reached by
    // the body traversal.
    let nested = analyze(
        "fn f() -> Result<Int, String> { Err(\"x\") } fn main() -> Result<Int, String> { if true { let a: Int = f()?; discard a; } Ok(0) }",
    );
    let nested_count = nested
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "error-propagation-refused")
        .count();
    assert_eq!(nested_count, 1);
    let doubled = analyze(
        "fn f() -> Result<Int, String> { Err(\"x\") } fn main() -> Result<Int, String> { let v: Int = f()??; Ok(v) }",
    );
    let count = doubled
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "error-propagation-refused")
        .count();
    assert_eq!(count, 2);
}

/// Section 38: a conversion is declared by one implementation of the reserved `ErrorConversion`
/// trait whose receiver names one concrete error type; two methods or an open receiver are
/// refused (`GNT-38.1-typed-error-propagation`).
#[test]
fn section_38_conversion_declarations_are_reserved_trait_implementations() {
    let admitted = analyze(
        "trait ErrorConversion { pure fn convert(self) -> String; } struct E {} impl ErrorConversion for E { pure fn convert(self) -> String { \"x\" } } fn main() -> Int { 0 }",
    );
    assert_eq!(admitted.status(), AnalysisStatus::Valid);
    let two = analyze(
        "trait ErrorConversion { pure fn convert(self) -> String; } struct E {} impl ErrorConversion for E { pure fn a(self) -> String { \"x\" } pure fn b(self) -> String { \"y\" } } fn main() -> Int { 0 }",
    );
    assert!(diagnostic_codes(two.diagnostics()).contains(&"error-conversion-refused"));
    let open = analyze(
        "trait ErrorConversion { pure fn convert(self) -> String; } struct G<T> { v: T } impl<T> ErrorConversion for G<T> { pure fn convert(self) -> String { \"x\" } } fn main() -> Int { 0 }",
    );
    let refusal = open
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "error-conversion-refused")
        .unwrap_or_else(|| panic!("the open receiver is refused"));
    assert_eq!(
        refusal.fields.get("type").map(|value| value.as_ref()),
        Some("crate::G<^0.0>")
    );
}

/// Section 38: `Never` is refused at a boundary and in a signature position, and a value
/// is never coerced into it (`GNT-38.4-boundaries-durability-and-non-claims`).
#[test]
fn section_38_never_positions_are_refused() {
    let boundary = analyze("fn main() -> Never { }");
    assert_eq!(boundary.status(), AnalysisStatus::Invalid);
    assert!(diagnostic_codes(boundary.diagnostics()).contains(&"never-boundary-refused"));
    // A `Never` result admits no fall-through, so the empty body also reports its missing result.
    assert!(diagnostic_codes(boundary.diagnostics()).contains(&"missing-result"));
    let action = analyze("action read_only probe() -> Never; fn main() -> Int { 0 }");
    assert!(diagnostic_codes(action.diagnostics()).contains(&"never-boundary-refused"));
    let nested = analyze("fn main() -> List<Never> { [] }");
    assert!(diagnostic_codes(nested.diagnostics()).contains(&"never-boundary-refused"));
    let signature = analyze("fn never_value() -> Never { 1 } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(signature.diagnostics()).contains(&"never-signature-refused"));
    let parameter = analyze("fn takes(x: Never) -> Int { 1 } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(parameter.diagnostics()).contains(&"never-signature-refused"));
    let binding = analyze("fn main() -> Int { let x: Never = 1; 0 }");
    assert!(diagnostic_codes(binding.diagnostics()).contains(&"type-mismatch"));
    let control = analyze("fn main() -> Int { 0 }");
    assert_eq!(control.status(), AnalysisStatus::Valid);
    // The refined rows report the declared uninhabited type, not a fallback `Unit`.
    fn field_of<'a>(
        diagnostics: &'a [gantry::source::StructuredDiagnostic],
        code: &str,
        field: &str,
    ) -> Option<&'a str> {
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == code)
            .and_then(|diagnostic| diagnostic.fields.get(field))
            .map(|value| value.as_ref())
    }
    assert_eq!(
        field_of(signature.diagnostics(), "type-mismatch", "expected"),
        Some("Never")
    );
    // A nested refused result spelling publishes its refusal and no fallback mismatch.
    let nested_signature = analyze("fn nested() -> List<Never> { 0 } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(nested_signature.diagnostics()).contains(&"never-signature-refused"));
    assert!(!diagnostic_codes(nested_signature.diagnostics()).contains(&"type-mismatch"));
    // Both nested branches stay silent: the empty falls-through body and a body whose value the
    // refusal left without a shape.
    let nested_empty = analyze("fn nested() -> List<Never> { } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(nested_empty.diagnostics()).contains(&"never-signature-refused"));
    assert!(!diagnostic_codes(nested_empty.diagnostics()).contains(&"missing-result"));
    let nested_value = analyze("fn nested() -> List<Never> { [] } fn main() -> Int { 0 }");
    assert!(diagnostic_codes(nested_value.diagnostics()).contains(&"never-signature-refused"));
    assert!(!diagnostic_codes(nested_value.diagnostics()).contains(&"type-mismatch"));
}

/// A refused operator publishes exactly one diagnostic.
///
/// A declared-descriptor mismatch has no operator signature, so the operator refusal is the whole
/// answer: the enclosing result or annotation position must not reject the same expression a second
/// time. The scalar spelling and the nested-operator control publish one diagnostic too.
#[test]
fn public_refused_operators_publish_one_diagnostic() {
    for source in [
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } == B { v: 1 } }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } != B { v: 1 } }",
        "struct A { v: Int } fn main() -> Bool { A { v: 1 } == 1 }",
        "struct A { v: Int } fn main() -> Bool { A { v: 1 } != 1 }",
        "struct A { v: Int } fn main() -> Bool { A { v: 1 } == true }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } < B { v: 1 } }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } + B { v: 1 } == A { v: 1 } }",
        "fn main() -> Bool { [1] == [\"a\"] }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { let x: Bool = A { v: 1 } == B { v: 1 }; x }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { (A { v: 1 } == B { v: 1 }) == true }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } == B { v: 1 } && true }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Int { if (A { v: 1 } == B { v: 1 }) { discard 1; } else { discard 2; } 0 }",
    ] {
        let refused = analyze(source);
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics().len(),
            1,
            "{source}: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "invalid-primitive"),
            "{source}: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "{source}: a refused operator publishes no program"
        );
    }
}

/// Requires one affine misuse to be rejected by a source diagnostic, never an internal failure.
fn assert_affine_rejected(source: &str, code: &str) {
    let rejected = analyze(source);
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{source}: {:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == code),
        "{source}: {:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .all(|diagnostic| !diagnostic.code.as_str().contains("internal")),
        "{source}: {:?}",
        rejected.diagnostics()
    );
    assert!(rejected.executable_program().is_none(), "{source}");
}

fn assert_affine_accepted(source: &str) {
    let accepted = analyze(source);
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{source}: {:?}",
        accepted.diagnostics()
    );
}

/// The affinity ledger keys places by binding root and struct-field path: a transferred subplace,
/// every place containing or contained in it, and the marked place itself are rejected, while an
/// unrelated sibling place stays readable and assignable.
#[test]
fn affine_place_ledger_keys_places_and_keeps_siblings_usable() {
    let header = "affine struct Leaf { value: Int }\n\
                  struct Holder { leaf: Leaf, other: Int }\n\
                  struct Outer { inner: Holder }\n\
                  fn make() -> Holder { Holder { leaf: Leaf { value: 1 }, other: 2 } }\n\
                  fn make_outer() -> Outer { Outer { inner: Holder { leaf: Leaf { value: 1 }, other: 2 } } }\n";
    // An unrelated sibling projection stays readable and assignable after the transfer.
    for accepted in [
        "fn main() -> Int {\n\
             let holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             holder.other\n\
         }",
        "fn main() -> Int {\n\
             let mut holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             holder.other = 5;\n\
             holder.other\n\
         }",
        // A sibling at any depth is unaffected.
        "fn main() -> Int {\n\
             let outer: Outer = make_outer();\n\
             let first: Leaf = outer.inner.leaf;\n\
             outer.inner.other\n\
         }",
        // Assignment stays admitted for the marked place itself.
        "fn main() -> Int {\n\
             let mut holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             holder.leaf = Leaf { value: 3 };\n\
             holder.other\n\
         }",
    ] {
        assert_affine_accepted(&format!("{header}{accepted}"));
    }

    for rejected in [
        // The marked place, a place contained in it, and every place containing it.
        "fn main() -> Int {\n\
             let holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             let second: Leaf = holder.leaf;\n\
             first.value + second.value\n\
         }",
        "fn main() -> Int {\n\
             let holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             holder.leaf.value\n\
         }",
        "fn main() -> Int {\n\
             let holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             discard holder;\n\
             first.value\n\
         }",
        "fn main() -> Int {\n\
             let outer: Outer = make_outer();\n\
             let first: Leaf = outer.inner.leaf;\n\
             discard outer;\n\
             first.value\n\
         }",
        // A moved binding root makes every place under it unreadable.
        "fn main() -> Int {\n\
             let holder: Holder = make();\n\
             let whole: Holder = holder;\n\
             holder.other\n\
         }",
        // A mark survives assignment to the marked place and to its binding root.
        "fn main() -> Int {\n\
             let mut holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             holder.leaf = Leaf { value: 3 };\n\
             holder.leaf.value\n\
         }",
        "fn main() -> Int {\n\
             let mut holder: Holder = make();\n\
             let first: Leaf = holder.leaf;\n\
             holder = make();\n\
             holder.leaf.value\n\
         }",
        // A transfer inside a loop body is a potentially repeated transfer.
        "fn main(count: Int) -> Int {\n\
             let holder: Holder = make();\n\
             let mut total: Int = 0;\n\
             let mut index: Int = 0;\n\
             while index < count {\n\
                 let first: Leaf = holder.leaf;\n\
                 total += first.value;\n\
                 index = index + 1;\n\
             }\n\
             total\n\
         }",
    ] {
        assert_affine_rejected(&format!("{header}{rejected}"), "affine-value-reuse");
    }

    // A consuming receiver call reads the place it names exactly once, whether or not the receiver
    // spelling groups its root, so a second call through the same field is a reuse while a call
    // through a sibling affine field stays admitted (`e49cbc5e`).
    let consumers = "affine struct Leaf { value: Int }\n\
                     affine struct Mark { value: Int }\n\
                     struct Pair { leaf: Leaf, mark: Mark }\n\
                     impl Leaf { fn take(self) -> Int { self.value } fn look(shared self) -> Int { self.value } fn bump(exclusive self) -> Int { self.value } }\n\
                     impl Mark { fn take(self) -> Int { self.value } fn look(shared self) -> Int { self.value } }\n";
    for rejected in [
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let first: Int = pair.leaf.take();\n\
             let second: Int = pair.leaf.take();\n\
             first + second\n\
         }",
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let leaf: Leaf = pair.leaf;\n\
             let second: Int = pair.leaf.take();\n\
             leaf.value + second\n\
         }",
    ] {
        assert_affine_rejected(&format!("{consumers}{rejected}"), "affine-value-reuse");
    }
    assert_affine_accepted(&format!(
        "{consumers}fn main() -> Int {{\n\
             let pair: Pair = Pair {{ leaf: Leaf {{ value: 1 }}, mark: Mark {{ value: 2 }} }};\n\
             let first: Int = pair.leaf.take();\n\
             let second: Int = pair.mark.take();\n\
             first + second\n\
         }}"
    ));
    // A transfer mark survives whole-root re-initialization, exactly as the move rows pin.
    assert_affine_rejected(
        &format!(
            "{consumers}fn main() -> Int {{\n\
                 let mut pair: Pair = Pair {{ leaf: Leaf {{ value: 1 }}, mark: Mark {{ value: 2 }} }};\n\
                 let first: Int = pair.leaf.take();\n\
                 pair = Pair {{ leaf: Leaf {{ value: 3 }}, mark: Mark {{ value: 4 }} }};\n\
                 let second: Int = pair.leaf.take();\n\
                 first + second\n\
             }}"
        ),
        "affine-value-reuse",
    );
    // A `shared self` or `exclusive self` receiver only borrows the place, so its loan records
    // no transfer and two borrows, or a borrow followed by a transfer, stay admitted.
    for borrowed in [
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let first: Int = pair.leaf.look();\n\
             let second: Int = pair.leaf.look();\n\
             first + second\n\
         }",
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let first: Int = pair.leaf.look();\n\
             let second: Int = pair.leaf.take();\n\
             first + second\n\
         }",
        "fn main() -> Int {\n\
             let mut pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let first: Int = pair.leaf.bump();\n\
             let second: Int = pair.leaf.bump();\n\
             first + second\n\
         }",
    ] {
        assert_affine_accepted(&format!("{consumers}{borrowed}"));
    }
    // A loan reads the place it borrows, so a place an earlier transfer or move claimed refuses
    // the loan exactly as a field read of it does, while a sibling field stays usable.
    for loaned in [
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let first: Int = pair.leaf.take();\n\
             let second: Int = pair.leaf.look();\n\
             first + second\n\
         }",
        "fn main() -> Int {\n\
             let mut pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let first: Int = pair.leaf.take();\n\
             let second: Int = pair.leaf.bump();\n\
             first + second\n\
         }",
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let leaf: Leaf = pair.leaf;\n\
             let second: Int = pair.leaf.look();\n\
             leaf.value + second\n\
         }",
    ] {
        assert_affine_rejected(&format!("{consumers}{loaned}"), "affine-value-reuse");
    }
    assert_affine_accepted(&format!(
        "{consumers}fn main() -> Int {{\n\
             let pair: Pair = Pair {{ leaf: Leaf {{ value: 1 }}, mark: Mark {{ value: 2 }} }};\n\
             let first: Int = pair.leaf.take();\n\
             let second: Int = pair.mark.look();\n\
             first + second\n\
         }}"
    ));
    // A loan inserts no mark, so repeating it across loop iterations is harmless; a transfer
    // inside a loop body stays a potentially repeated transfer.
    for loaned in [
        "fn main() -> Int {\n\
             let pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let mut total: Int = 0;\n\
             let mut index: Int = 0;\n\
             while index < 2 {\n\
                 total = total + pair.leaf.look();\n\
                 index = index + 1;\n\
             }\n\
             total\n\
         }",
        "fn main() -> Int {\n\
             let mut pair: Pair = Pair { leaf: Leaf { value: 1 }, mark: Mark { value: 2 } };\n\
             let mut total: Int = 0;\n\
             let mut index: Int = 0;\n\
             while index < 2 {\n\
                 total = total + pair.leaf.bump();\n\
                 index = index + 1;\n\
             }\n\
             total\n\
         }",
    ] {
        assert_affine_accepted(&format!("{consumers}{loaned}"));
    }
    assert_affine_rejected(
        &format!(
            "{consumers}fn main() -> Int {{\n\
                 let pair: Pair = Pair {{ leaf: Leaf {{ value: 1 }}, mark: Mark {{ value: 2 }} }};\n\
                 let mut total: Int = 0;\n\
                 let mut index: Int = 0;\n\
                 while index < 2 {{\n\
                     total = total + pair.leaf.take();\n\
                     index = index + 1;\n\
                 }}\n\
                 total\n\
             }}"
        ),
        "affine-value-reuse",
    );
    // An owned consumption of a `MustConsume` place discharges it, so a later loan reuses it: the
    // reuse verdict joins the copy verdict rather than replacing it.
    assert_eq!(
        diagnostic_codes(
            analyze(
                "must_consume struct Token { value: Int }\n\
                 struct Holder { token: Token }\n\
                 impl Token { fn consume(owned self) -> Int { self.value } fn look(shared self) -> Int { self.value } }\n\
                 fn main() -> Int {\n\
                     let holder: Holder = Holder { token: Token { value: 1 } };\n\
                     let first: Int = holder.token.consume();\n\
                     let second: Int = holder.token.look();\n\
                     first + second\n\
                 }"
            )
            .diagnostics()
        ),
        ["affine-value-reuse", "must-consume-copy"],
    );
    // A copyable field receiver copies its value, so two consuming calls stay admitted.
    assert_affine_accepted(
        "struct Counter { value: Int }\n\
         impl Counter { fn read(self) -> Int { self.value } }\n\
         struct Basket { counter: Counter }\n\
         fn main() -> Int {\n\
             let basket: Basket = Basket { counter: Counter { value: 21 } };\n\
             basket.counter.read() + basket.counter.read()\n\
         }",
    );
}

/// A partial move and a pattern commit both key the affinity ledger by place: the transferred or
/// matched place, every place containing it, and a repeated commit are rejected, while a sibling
/// projection stays readable and a `Copyable` matched place transfers nothing (2g).
#[test]
fn affine_partial_moves_and_pattern_commits() {
    const DECLARATIONS: &str = "affine struct Leaf { value: Int }\n\
         enum Maybe { Present(Leaf), Absent }\n\
         struct Wrapper { inner: Maybe, other: Int }\n\
         fn make() -> Wrapper { Wrapper { inner: Maybe::Present(Leaf { value: 6 }), other: 3 } }\n\
         enum Count { One(Int), Zero }\n\
         fn tally() -> Count { Count::One(1) }\n";

    for accepted in [
        // A commit whose matched place is a projection leaves the sibling projection readable.
        "fn main() -> Int {\n\
             let w: Wrapper = make();\n\
             let r: Int = match w.inner { Maybe::Present(leaf) => leaf.value, Maybe::Absent => 0 };\n\
             w.other + r\n\
         }",
        // A partial move leaves the sibling projection readable too.
        "fn main() -> Int {\n\
             let w: Wrapper = make();\n\
             let m: Maybe = w.inner;\n\
             w.other\n\
         }",
        // A `Copyable` matched place transfers nothing and may be committed twice.
        "fn main() -> Int {\n\
             let c: Count = tally();\n\
             let a: Int = match c { Count::One(v) => v, Count::Zero => 0 };\n\
             let b: Int = match c { Count::One(v) => v, Count::Zero => 1 };\n\
             a + b\n\
         }",
        // A temporary scrutinee is not a place, so each call-result commit is independent.
        "fn main() -> Int {\n\
             let a: Int = match tally() { Count::One(v) => v, Count::Zero => 0 };\n\
             let b: Int = match tally() { Count::One(v) => v, Count::Zero => 1 };\n\
             a + b\n\
         }",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    for rejected in [
        // A place containing the matched place is unreadable after the commit.
        "fn main() -> Int {\n\
             let w: Wrapper = make();\n\
             let r: Int = match w.inner { Maybe::Present(leaf) => leaf.value, Maybe::Absent => 0 };\n\
             discard w;\n\
             r\n\
         }",
        // The matched place itself cannot be transferred after the commit.
        "fn main() -> Int {\n\
             let w: Wrapper = make();\n\
             let r: Int = match w.inner { Maybe::Present(leaf) => leaf.value, Maybe::Absent => 0 };\n\
             let m: Maybe = w.inner;\n\
             r\n\
         }",
        // A partial move and a commit address the same place, so the second use is a reuse.
        "fn main() -> Int {\n\
             let w: Wrapper = make();\n\
             let m: Maybe = w.inner;\n\
             let r: Int = match w.inner { Maybe::Present(leaf) => leaf.value, Maybe::Absent => 0 };\n\
             r\n\
         }",
        // A commit inside a loop body is a potentially repeated transfer.
        "fn main() -> Int {\n\
             let w: Wrapper = make();\n\
             let mut total: Int = 0;\n\
             loop(limit = 2) {\n\
                 match w.inner { Maybe::Present(leaf) => { total = total + leaf.value; }, Maybe::Absent => { break; } }\n\
             }\n\
             total\n\
         }",
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{rejected}"), "affine-value-reuse");
    }

    // A `MustConsume` matched place is not consumed by a commit: the pattern's read of the place
    // is a copy, and item 2d admits only an `owned self` call or a `return` as consumption.
    assert_affine_rejected(
        "must_consume struct Token { value: Int }\n\
         enum Slot { Filled(Token), Empty }\n\
         fn slot() -> Slot { Slot::Filled(Token { value: 1 }) }\n\
         fn main() -> Int {\n\
             let s: Slot = slot();\n\
             let r: Int = match s { Slot::Filled(token) => 1, Slot::Empty => 0 };\n\
             r\n\
         }",
        "must-consume-copy",
    );
}

/// The affine move ledger keys `(root, field path)` places, so a repeated owned move and a read of
/// an already-moved place — including through a struct-field projection — are rejected.
#[test]
fn affine_owned_move_ledger_rejects_repeated_moves_and_moved_place_reads() {
    // The same binding root cannot be moved twice.
    assert_affine_rejected(
        "affine struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn main() -> Int {\n\
             let token: Token = Token { value: 5 };\n\
             let first: Int = token.consume();\n\
             let second: Int = token.consume();\n\
             first + second\n\
         }",
        "affine-value-reuse",
    );
    // A field read after the whole value moved is rejected.
    assert_affine_rejected(
        "affine struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn main(token: Token) -> Int {\n\
             let first: Int = token.consume();\n\
             first + token.value\n\
         }",
        "affine-value-reuse",
    );
    // A struct-field receiver place cannot be moved twice.
    assert_affine_rejected(
        "affine struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         struct Holder { token: Token }\n\
         fn main(holder: Holder) -> Int {\n\
             let first: Int = holder.token.consume();\n\
             let second: Int = holder.token.consume();\n\
             first + second\n\
         }",
        "affine-value-reuse",
    );
}

/// An `owned self` receiver whose type requires consumption admits only a caller place: a binding
/// root of the calling frame or struct-field projections from one. An indexed place, a pattern
/// payload binding, and a call result are values rather than caller places, while a `Copyable`
/// receiver admits any receiver place and a constructed value because it is a copy (2b).
#[test]
fn public_owned_receiver_place_rule_admits_caller_places_and_rejects_values() {
    const DECLARATIONS: &str = "affine struct Token { value: Int }\n\
         struct Holder { token: Token, marker: Int }\n\
         struct Inner { holder: Holder }\n\
         enum Maybe { Present(Token), Absent }\n\
         struct Counter { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         impl Counter { fn consume(owned self) -> Int { self.value } }\n";

    // A struct-field projection and a nested projection are caller places, the sibling place stays
    // readable after the projected partial move, a constructed value is admitted for a `Copyable`
    // receiver, and a receiver bound inside the loop body is a fresh place on every iteration.
    for accepted in [
        "fn main() -> Int {\n\
             let holder: Holder = Holder { token: Token { value: 7 }, marker: 3 };\n\
             let moved: Int = holder.token.consume();\n\
             moved + holder.marker\n\
         }",
        "fn main() -> Int {\n\
             let inner: Inner = Inner { holder: Holder { token: Token { value: 7 }, marker: 3 } };\n\
             let moved: Int = inner.holder.token.consume();\n\
             moved + inner.holder.marker\n\
         }",
        "fn main() -> Int { Counter { value: 4 }.consume() }",
        "fn main(flag: Bool) -> Int {\n\
             while flag {\n\
                 let token: Token = Token { value: 1 };\n\
                 discard token.consume();\n\
             }\n\
             0\n\
         }",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    for (rejected, code) in [
        // An indexed place is not a caller place.
        (
            "fn main(items: List<Token>) -> Int { let moved: Int = items[0].consume(); moved }",
            "owned-receiver-scope",
        ),
        // An arm pattern payload binding is a fresh value, not a caller place.
        (
            "fn main(maybe: Maybe) -> Int { if let Maybe::Present(token) = maybe { discard token.consume(); } 0 }",
            "owned-receiver-scope",
        ),
        // A call result is not a receiver place even though a `Copyable` receiver is a copy.
        (
            "fn make() -> Counter { Counter { value: 5 } }\n\
             fn main() -> Int { make().consume() }",
            "receiver-value-place",
        ),
        // The projected partial move leaves the containing place unreadable.
        (
            "fn main() -> Int {\n\
                 let holder: Holder = Holder { token: Token { value: 7 }, marker: 3 };\n\
                 let moved: Int = holder.token.consume();\n\
                 let again: Int = holder.token.value;\n\
                 moved + again\n\
             }",
            "affine-value-reuse",
        ),
        // A receiver transfer inside a loop body whose root is bound outside is a repeated move.
        (
            "fn main(flag: Bool) -> Int {\n\
                 let token: Token = Token { value: 1 };\n\
                 while flag { discard token.consume(); }\n\
                 0\n\
             }",
            "affine-value-reuse",
        ),
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{rejected}"), code);
    }
}

/// A read of an affine place that executes once per loop iteration is repeated use.
#[test]
fn affine_repeated_read_inside_loop_is_rejected() {
    assert_affine_rejected(
        "affine struct Token {}\n\
         fn take(token: Token) {}\n\
         fn run(token: Token, count: Int) {\n\
             let mut index: Int = 0;\n\
             while index < count {\n\
                 take(token);\n\
                 index = index + 1;\n\
             }\n\
         }\n\
         fn main(seed: Int) { run(Token {}, 2); }",
        "affine-value-reuse",
    );
    assert_affine_rejected(
        "affine struct Token { flag: Bool }\n\
         fn main(token: Token) {\n\
             let mut index: Int = 0;\n\
             while token.flag {\n\
                 index = index + 1;\n\
             }\n\
         }",
        "affine-value-reuse",
    );
}

/// An `owned self` receiver on an `AffineDroppable` type requires an addressable caller place and
/// is rejected with a source diagnostic rather than an internal lowering or runtime failure.
#[test]
fn affine_owned_receiver_requires_addressable_caller_place() {
    for source in [
        "affine struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn main(seed: Int) -> Int { Token { value: 1 }.consume() }",
        "affine struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn make(seed: Int) -> Token { Token { value: seed } }\n\
         fn main() -> Int { make(7).consume() }",
    ] {
        assert_affine_rejected(source, "owned-receiver-scope");
    }
}

/// Permitted affine uses and copyable values must stay source-valid.
#[test]
fn affine_single_use_guards_stay_valid() {
    for source in [
        // A single read.
        "affine struct Token {}\n\
         fn take(t: Token) {}\n\
         fn main(token: Token) { take(token); }",
        // Discarding an affine value is permitted.
        "affine struct Token {}\n\
         fn main(token: Token) { discard token; }",
        // Returning a parameter is a single use.
        "affine struct Token {}\n\
         fn identity(token: Token) -> Token { token }\n\
         fn main() {}",
        // A generic call reads one argument once.
        "affine struct Token {}\n\
         fn identity<T>(value: T) -> T { value }\n\
         fn main(token: Token) { discard identity(token); }",
        // Unrelated sibling bindings do not intersect.
        "affine struct Token {}\n\
         fn take(t: Token) {}\n\
         fn run(first: Token, second: Token) { take(first); take(second); }\n\
         fn main() {}",
        // A copyable value may be passed more than once.
        "struct Plain { value: Int }\n\
         fn take(p: Plain) {}\n\
         fn main(p: Plain) { take(p); take(p); }",
        // A single copied argument.
        "struct Plain { value: Int }\n\
         fn take(p: Plain) {}\n\
         fn main(p: Plain) { take(p); }",
        // A trait `self` receiver on an affine value.
        "affine struct Token { value: Int }\n\
         trait Greet { pure fn greet(self) -> Int; }\n\
         impl Greet for Token { pure fn greet(self) -> Int { self.value } }\n\
         fn main(token: Token) -> Int { token.greet() }",
    ] {
        assert_affine_accepted(source);
    }
}

/// A receiver call whose receiver is an rvalue (a call result) is rejected with a source diagnostic
/// instead of failing in lowering or at runtime; constructed receivers stay valid.
#[test]
fn call_result_receiver_is_rejected_with_a_source_diagnostic() {
    let rejected = analyze(
        "struct Counter { value: Int }\n\
         impl Counter { fn bump(self) -> Int { self.value } }\n\
         fn make_counter(seed: Int) -> Counter { Counter { value: seed } }\n\
         fn main() -> Int { make_counter(7).bump() }",
    );
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "receiver-value-place"),
        "{:?}",
        rejected.diagnostics()
    );
    assert!(rejected.executable_program().is_none());
    let accepted = analyze(
        "struct Counter { value: Int }\n\
         impl Counter { fn bump(owned self) -> Int { self.value } }\n\
         fn main() -> Int { Counter { value: 1 }.bump() }",
    );
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
}

/// A trait receiver call whose receiver is a call result is refused with exactly one source
/// diagnostic in every position, including a chained or free-call receiver; no source-valid
/// program reaches lowering with a receiver that has no caller place.
#[test]
fn trait_call_result_receivers_are_refused_in_every_position() {
    let fixture = "struct Plain { value: Int }\n\
         trait Greet { pure fn greet(self) -> Int; }\n\
         impl Greet for Plain { pure fn greet(self) -> Int { self.value } }\n\
         impl Plain { fn flip(self) -> Plain { self } fn add(self, other: Int) -> Int { self.value + other } }\n\
         fn mk() -> Plain { Plain { value: 42 } }\n";
    for body in [
        // The value position.
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; p.flip().greet() }",
        // The left operand.
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; p.flip().greet() + 1 }",
        // The right operand.
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; 1 + p.flip().greet() }",
        // A free-call receiver and a receiver chain of two calls.
        "fn main() -> Int { mk().greet() }",
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; p.flip().flip().greet() }",
        // An argument position.
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; p.add(p.flip().greet()) }",
        // A grouped call result is the same receiver: a group is transparent, and the grouped
        // spelling must not reach lowering either.
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; (p.flip()).greet() }",
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; (p.flip()).greet() + 1 }",
        // A nested group carries the same call result.
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; ((p.flip())).greet() + 1 }",
    ] {
        let refused = analyze(&format!("{fixture}{body}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics().len(),
            1,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics()[0].code.as_str(),
            "receiver-value-place",
            "{body}"
        );
        assert!(refused.executable_program().is_none(), "{body}");
    }
    for body in [
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; p.greet() + 1 }",
        "fn main() -> Int { let p: Plain = Plain { value: 42 }; (p).greet() + 1 }",
        "fn main() -> Int { Plain { value: 42 }.greet() }",
        "fn main() { let p: Plain = Plain { value: 42 }; discard p.flip(); }",
    ] {
        let accepted = analyze(&format!("{fixture}{body}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{body}: {:?}",
            accepted.diagnostics()
        );
    }
}

/// A `must_consume struct` seeds `MustConsume`; nested members, affine declarations, and generic
/// instantiations fold to the dominating class, and unrelated declarations stay accepted.
#[test]
fn must_consume_structs_fold_ownership_class_and_generics() {
    use gantry::ir::{OwnershipClass, TypeDescriptor};

    let package = analyze(
        "must_consume struct Token { value: Int }\n\
         must_consume struct Empty {}\n\
         must_consume struct Generic<T> { value: T }\n\
         struct Plain { value: Int }\n\
         struct Contains { token: Token }\n\
         affine struct Held { token: Token }\n\
         struct Wrapped { inner: Generic<Int> }\n\
         impl Empty { fn consume(owned self) {} }\n\
         impl Contains { fn consume(owned self) {} }\n\
         impl Held { fn consume(owned self) {} }\n\
         impl Wrapped { fn consume(owned self) {} }\n\
         fn take_token(value: Token) { discard value; }\n\
         fn main() {}",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Invalid,
        "a discarded MustConsume parameter must stay rejected: {:?}",
        package.diagnostics()
    );

    let package = analyze(
        "must_consume struct Token { value: Int }\n\
         must_consume struct Empty {}\n\
         must_consume struct Generic<T> { value: T }\n\
         struct Plain { value: Int }\n\
         struct Contains { token: Token }\n\
         affine struct Held { token: Token }\n\
         struct Wrapped { inner: Generic<Int> }\n\
         impl Empty { fn consume(owned self) {} }\n\
         impl Contains { fn consume(owned self) {} }\n\
         impl Held { fn consume(owned self) {} }\n\
         impl Wrapped { fn consume(owned self) {} }\n\
         fn take_empty(value: Empty) { value.consume(); }\n\
         fn take_contains(value: Contains) { value.consume(); }\n\
         fn take_held(value: Held) { value.consume(); }\n\
         fn take_wrapped(value: Wrapped) { value.consume(); }\n\
         fn take_plain(value: Plain) { discard value; }\n\
         fn main() {}",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    assert!(OwnershipClass::MustConsume.requires_consumption());
    assert!(OwnershipClass::AffineDroppable.requires_consumption());
    assert!(!OwnershipClass::Copyable.requires_consumption());
    let policy = analysis_limits(64, 100);
    for (name, class) in [
        ("crate::Empty", OwnershipClass::MustConsume),
        ("crate::Contains", OwnershipClass::MustConsume),
        ("crate::Held", OwnershipClass::MustConsume),
        ("crate::Wrapped", OwnershipClass::MustConsume),
        ("crate::Plain", OwnershipClass::Copyable),
    ] {
        let ty = TypeDescriptor::from_canonical_string(name)
            .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
        let properties = package
            .type_capabilities(&ty, policy)
            .unwrap_or_else(|error| panic!("query failed for {name}: {error:?}"));
        assert_eq!(properties.ownership_class(), class, "{name}");
    }
}

/// A live `MustConsume` place is discharged only by an `owned self` admission: a projection read, a
/// copied argument, a discard, one branch, a loop iteration, and reuse are all rejected.
#[test]
fn must_consume_places_require_an_owned_admission() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    for source in [
        "fn main(token: Token) { token.consume(); }",
        "fn run(token: Token, flag: Bool) { if flag { token.consume(); } else { token.consume(); } } fn main() {}",
        "affine struct Affine {} fn main(value: Affine) { discard value; }",
        "must_consume struct Declared {} affine struct AffineDecl {} struct OrdinaryDecl {} fn main() {}",
    ] {
        let accepted = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            accepted.diagnostics()
        );
    }

    for (source, code) in [
        (
            "fn main(token: Token) -> Int { token.value }",
            "must-consume-copy",
        ),
        (
            "fn take(value: Token) { value.consume(); } fn main(token: Token) { take(token); }",
            "must-consume-copy",
        ),
        (
            "fn main(token: Token) { discard token; }",
            "must-consume-discard",
        ),
        ("fn main(token: Token) {}", "must-consume-unconsumed"),
        (
            "fn run(token: Token, flag: Bool) { if flag { token.consume(); } } fn main() {}",
            "must-consume-path-dependent",
        ),
        (
            "fn run(token: Token) { loop(limit = 1) { token.consume(); break; } } fn main() {}",
            // A loop limit is a dynamic failure rather than a static path (`GNT-9.5`), so a
            // bounded `loop` still begins its body and the mandated rejection is the repeated
            // transfer rather than a zero-iteration verdict.
            "affine-value-reuse",
        ),
        (
            "fn main(token: Token) { token.consume(); token.consume(); }",
            "affine-value-reuse",
        ),
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "{source}: expected {code}: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// A plain struct with a `MustConsume` member is enforced, not merely classified.
#[test]
fn must_consume_member_dominance_is_enforced() {
    const DECLARATIONS: &str = "must_consume struct Token {}\n\
         struct Holder { token: Token }\n\
         impl Holder { fn consume(owned self) {} }\n";

    let rejected = analyze(&format!(
        "{DECLARATIONS}fn main(holder: Holder) {{ discard holder; }}"
    ));
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "must-consume-discard"),
        "{:?}",
        rejected.diagnostics()
    );
    assert!(rejected.executable_program().is_none());

    let accepted = analyze(&format!(
        "{DECLARATIONS}fn main(holder: Holder) {{ holder.consume(); }}"
    ));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
}

/// An `owned self` `MustConsume` receiver cannot leave the consuming callable.
#[test]
fn must_consume_receiver_escape_is_rejected() {
    for source in [
        "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} fn leak(owned self) -> Token { self } }\n\
         fn main(token: Token) { let returned: Token = token.leak(); returned.consume(); }",
        "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Token { fn relay(owned self) { self.consume(); } }\n\
         fn main(token: Token) { token.relay(); }",
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "must-consume-escape"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }
}

/// A `MustConsume` `owned self` receiver still requires an addressable caller place.
#[test]
fn must_consume_owned_receiver_requires_addressable_caller_place() {
    let rejected = analyze(
        "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn make(seed: Int) -> Token { Token { value: seed } }\n\
         fn main() -> Int { make(1).consume() }",
    );
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "owned-receiver-scope"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Every binding introduction of a `MustConsume` value owes consumption: a declared local, a
/// struct literal, and a call result are all rejected until the value is consumed once (D1).
#[test]
fn must_consume_declared_locals_acquire_obligations() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n\
         fn make() -> Token { Token { value: 1 } }\n";

    for source in [
        "fn main() { let token: Token = Token { value: 7 }; token.consume(); }",
        "fn main() { let token: Token = make(); token.consume(); }",
    ] {
        let accepted = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            accepted.diagnostics()
        );
    }

    for source in [
        "fn main() { let token: Token = Token { value: 7 }; }",
        "fn main() { let token: Token = make(); }",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }
}

/// A `return`, `break`, or `continue` that leaves an obligation live exits the region that owes
/// the consumption, so each early exit is rejected (D2).
#[test]
fn must_consume_early_exits_are_rejected() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    for source in [
        "fn run(token: Token, flag: Bool) { if flag { return; } token.consume(); } fn main() {}",
        "fn run(flag: Bool) { loop(limit = 1) { let token: Token = Token { value: 1 }; if flag { break; } token.consume(); } } fn main() {}",
        "fn run(flag: Bool) { loop(limit = 1) { let token: Token = Token { value: 1 }; if flag { continue; } token.consume(); } } fn main() {}",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }
}

/// Every match arm is an analysed path, so one arm that leaves the obligation live is
/// path-dependent while both arms consuming is accepted (D3).
#[test]
fn must_consume_match_arms_merge_obligations() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         enum Flag { On, Off }\n\
         fn main() {}\n";

    for source in [
        "fn run(token: Token, flag: Flag) -> Int { match flag { Flag::On => token.consume(), Flag::Off => 0 } }",
        "fn run(token: Token, flag: Flag) { match flag { Flag::On => { discard token.consume(); }, Flag::Off => { discard 0; } } }",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code.as_str() == "must-consume-path-dependent" }),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }

    let accepted = analyze(&format!(
        "{DECLARATIONS}fn run(token: Token, flag: Flag) -> Int {{ match flag {{ Flag::On => token.consume(), Flag::Off => token.consume() }} }}"
    ));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
}

/// Reassignment of a discharged `MustConsume` place binds a fresh value: the stale discharge is
/// dropped and the new value owes its own consumption (D4).
#[test]
fn must_consume_reassignment_rebinds_the_obligation() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    let accepted = analyze(&format!(
        "{DECLARATIONS}fn main(mut token: Token) {{ token.consume(); token = Token {{ value: 1 }}; token.consume(); }}"
    ));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );

    let rejected = analyze(&format!(
        "{DECLARATIONS}fn main(mut token: Token) {{ token.consume(); token = Token {{ value: 1 }}; }}"
    ));
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// Replacing a place that still owes consumption would silently discard an initialized
/// `MustConsume` value, so the assignment is rejected by the ownership rule rather than by a
/// later missing consumption (`GNT-6.2d`).
#[test]
fn must_consume_live_place_cannot_be_replaced() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    for source in [
        "fn main(mut token: Token) { token = Token { value: 1 }; token.consume(); }",
        "fn main(mut token: Token) { token = Token { value: 1 }; }",
        "fn main(mut token: Token) { if token.value > 0 { token.consume(); } token = Token { value: 1 }; token.consume(); }",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "must-consume-replaced"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(rejected.executable_program().is_none());
    }
}

/// Replacing a struct-field projection of a live `MustConsume` root discards the projected value
/// exactly as replacing the root does, so the assignment is rejected while the root still owes
/// consumption; a field that owes nothing and a discharged root stay assignable (`GNT-6.2d`).
#[test]
fn must_consume_initialized_projection_cannot_be_replaced() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         struct Holder { token: Token, other: Int }\n\
         struct Outer { inner: Holder }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Holder { fn consume(owned self) {} }\n\
         impl Outer { fn consume(owned self) {} }\n";

    for accepted in [
        "fn main(mut holder: Holder) { holder.other = 5; holder.consume(); }",
        "fn main(mut token: Token) { token.consume(); token = Token { value: 1 }; token.consume(); }",
        // Assignment through a method receiver's field is excluded from the rule.
        "impl Holder { fn swap(owned self) { self.token = Token { value: 1 }; } }\nfn main() -> Int { 0 }",
    ] {
        let package = analyze(&format!("{DECLARATIONS}{accepted}"));
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{accepted}: {:?}",
            package.diagnostics()
        );
    }

    for (source, marker) in [
        (
            "fn main(mut holder: Holder) { holder.token = Token { value: 1 }; holder.consume(); }",
            "holder.token = Token { value: 1 }",
        ),
        (
            "fn main(mut outer: Outer) { outer.inner.token = Token { value: 1 }; outer.consume(); }",
            "outer.inner.token = Token { value: 1 }",
        ),
        (
            "fn main(mut holder: Holder, flag: Bool) { if flag { holder.token.consume(); } holder.token = Token { value: 1 }; holder.consume(); }",
            "holder.token = Token { value: 1 }",
        ),
    ] {
        assert_affine_rejected_at(
            &format!("{DECLARATIONS}{source}"),
            "must-consume-replaced",
            marker,
        );
    }
}

/// A `MustConsume` obligation is judged per place rather than per binding root (2d): a declared
/// `must_consume struct` is one atomic place, an aggregate that only inherits the class decomposes
/// into the places of its stored values, and re-initializing a consumed place re-exposes exactly
/// that place's own obligation.
#[test]
fn public_must_consume_obligations_are_judged_per_place() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         must_consume struct Wrap { inner: Token }\n\
         struct Holder { token: Token, marker: Int }\n\
         struct Pair { left: Token, right: Token }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Holder { fn consume(owned self) {} }\n\
         impl Pair { fn consume(owned self) {} }\n\
         impl Wrap { fn consume(owned self) {} }\n";

    // Every stored value carries its own obligation: consuming each field once discharges the
    // inherited aggregate, the same field consumed on both branches joins as definite, and a
    // declared aggregate is discharged by consuming it whole.
    for accepted in [
        "fn main(pair: Pair) { pair.left.consume(); pair.right.consume(); }",
        "fn run(pair: Pair, flag: Bool) { if flag { pair.left.consume(); } else { pair.left.consume(); } pair.right.consume(); } fn main() {}",
        "fn main(wrap: Wrap) { wrap.consume(); }",
        "fn main(mut holder: Holder) { holder.token.consume(); holder.token = Token { value: 1 }; holder.token.consume(); }",
        "fn main(mut holder: Holder) { holder.marker = 5; holder.consume(); }",
        "fn run(token: Token, flag: Bool) -> Int { if flag { token.consume(); return 1; } else { token.consume(); return 0; } } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    for (source, code) in [
        // Consuming one stored value never discharges its sibling.
        (
            "fn main(pair: Pair) { pair.left.consume(); }",
            "must-consume-unconsumed",
        ),
        // A declared aggregate is one place: dismantling a stored value leaves it unconsumed.
        (
            "fn main(wrap: Wrap) { wrap.inner.consume(); }",
            "must-consume-unconsumed",
        ),
        // A re-initialized projection owes its own consumption rather than the stale discharge.
        (
            "fn main(mut holder: Holder) { holder.token.consume(); holder.token = Token { value: 1 }; holder.marker = 5; }",
            "must-consume-unconsumed",
        ),
        // A path that consumed the place still owes exactly one consumption, so a later use is a
        // repeated use even though the other path left the place live.
        (
            "fn run(token: Token, flag: Bool) { if flag { token.consume(); } token.consume(); } fn main() {}",
            "affine-value-reuse",
        ),
        // A return operand that produces a value instead of naming a place stays a copied
        // argument, which the copy rule rejects as the trailing form already does.
        (
            "fn size(token: Token) -> Int { token.consume(); 0 }\n\
             fn run(token: Token) -> Int { return size(token); }\n\
             fn main() {}",
            "must-consume-copy",
        ),
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{source}"), code);
    }

    // Replacing a place that still holds a value stays rejected per place, and the report names
    // the assignment rather than the root.
    for (source, marker) in [
        (
            "fn main(mut holder: Holder) { holder.token = Token { value: 1 }; holder.consume(); }",
            "holder.token = Token { value: 1 }",
        ),
        (
            "fn main(mut pair: Pair) { pair.left.consume(); pair.right = Token { value: 1 }; pair.consume(); }",
            "pair.right = Token { value: 1 }",
        ),
    ] {
        assert_affine_rejected_at(
            &format!("{DECLARATIONS}{source}"),
            "must-consume-replaced",
            marker,
        );
    }
}

/// A partial move of a place inside a declared `MustConsume` aggregate survives a branch join. The
/// only leaf such an aggregate has is the root itself, so a branch that moved a descendant recorded
/// a mark strictly inside that leaf: the join has to carry the mark across, or the whole-root use
/// after it stopped intersecting anything and was accepted.
#[test]
fn public_must_consume_descendant_discharge_survives_a_join() {
    const DECLARATIONS: &str = "must_consume struct Inner { value: Int }\n\
         must_consume struct Outer { inner: Inner }\n\
         struct Bag { a: Inner, b: Inner }\n\
         impl Inner { fn consume(owned self) {} }\n\
         impl Outer { fn consume(owned self) {} }\n";

    // A whole-root use after a descendant move is the repeated use of the partially moved
    // aggregate, whether the move is straight line or only on one reaching path, and whether or not
    // an admitted assignment re-initialized the root in between.
    for (source, codes) in [
        (
            "fn run(mut o: Outer) { o.inner.consume(); o.consume(); } fn main() {}",
            ["affine-value-reuse"],
        ),
        (
            "fn run(mut o: Outer, flag: Bool) { o.inner.consume(); if flag { discard flag; } o.consume(); } fn main() {}",
            ["affine-value-reuse"],
        ),
        (
            "fn run(mut o: Outer, flag: Bool) { if flag { o.inner.consume(); } o.consume(); } fn main() {}",
            ["affine-value-reuse"],
        ),
        (
            "fn run(mut o: Outer, flag: Bool) { o.consume(); o = Outer { inner: Inner { value: 1 } }; if flag { o.inner.consume(); } o.consume(); } fn main() {}",
            ["affine-value-reuse"],
        ),
        // Moving the descendant on every path still only partially moves the aggregate, so the
        // whole-root use afterwards stays a repeated use.
        (
            "fn run(mut o: Outer, flag: Bool) { if flag { o.inner.consume(); } else { o.inner.consume(); } o.consume(); } fn main() {}",
            ["affine-value-reuse"],
        ),
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            diagnostic_codes(rejected.diagnostics()),
            codes,
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }

    // Consuming the declared aggregate itself on every path discharges it, so the join holds no
    // descendant mark to carry.
    assert_affine_accepted(&format!(
        "{DECLARATIONS}fn run(mut o: Outer, flag: Bool) {{ if flag {{ o.consume(); }} else {{ o.consume(); }} }} fn main() {{}}"
    ));

    // A sibling of the conditionally moved field stays usable: the carried mark names the descendant
    // place, not the whole root, so the sibling's transfer is not a repeated use. The report is the
    // sibling-less obligation the conditional field move leaves, exactly as it is without the fix.
    let sibling = analyze(&format!(
        "{DECLARATIONS}fn run(mut bag: Bag, flag: Bool) {{ if flag {{ bag.a.consume(); }} bag.b.consume(); }} fn main() {{}}"
    ));
    assert_eq!(
        diagnostic_codes(sibling.diagnostics()),
        ["must-consume-path-dependent"],
        "{:?}",
        sibling.diagnostics()
    );

    // The conditionally moved descendant leaves the aggregate owed rather than path-dependent: the
    // aggregate is one atomic place, and the leaf the join kept is still live on the path that
    // never moved it.
    let conditional = analyze(&format!(
        "{DECLARATIONS}fn run(mut o: Outer, flag: Bool) {{ if flag {{ o.inner.consume(); }} }} fn main() {{}}"
    ));
    assert_eq!(
        diagnostic_codes(conditional.diagnostics()),
        ["must-consume-unconsumed"],
        "{:?}",
        conditional.diagnostics()
    );
}

/// An index projection reads the element it names rather than moving it out of the aggregate, so a
/// `MustConsume` element is copied by that read exactly as a projected struct field is (2d).
#[test]
fn public_must_consume_indexed_element_reads_are_copies() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         struct Holder { token: Token }\n\
         struct Pair { token: Token, n: Int }\n\
         affine struct Leaf { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Holder { fn consume(owned self) {} }\n";

    // Only a consumption-requiring element is a copied read: an index of a copyable element, a
    // tuple index, and an affine element whose bindings are discarded stay admitted, and distinct
    // indices stay distinct places in the ledger.
    for accepted in [
        "fn run(items: List<Int>) -> Int { items[0] } fn main() {}",
        "fn run(pair: Tuple<Int, Bool>) -> Int { pair[0] } fn main() {}",
        "fn run(items: List<Leaf>) { let a: Leaf = items[0]; let b: Leaf = items[1]; discard a; discard b; } fn main() {}",
        "fn run(items: List<Leaf>, i: Int) { let a: Leaf = items[i]; discard a; } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    // Only a literal index has a statically known element type, so a dynamic tuple index is rejected
    // as an index form rather than as an element class: the same code rejects a tuple of copyable
    // elements.
    for rejected in [
        "fn split(pair: Tuple<Token, Int>, i: Int) -> Tuple<Token, Int> { let t: Token = pair[i]; t.consume(); return pair; } fn main() {}",
        "fn probe(pair: Tuple<Int, Int>, i: Int) -> Int { let n: Int = pair[i]; n } fn main() {}",
    ] {
        assert_affine_rejected(
            &format!("{DECLARATIONS}{rejected}"),
            "tuple-index-not-literal",
        );
    }

    // A dynamic index and a literal index do not name disjoint places: `items[i]` and `items[2 - 2]`
    // each name an element the ledger cannot tell apart from `items[0]`, so the second read of the
    // same value is a repeated use.
    for reuse in [
        "fn split(items: List<Leaf>, i: Int) { let a: Leaf = items[i]; discard a; let b: Leaf = items[0]; discard b; } fn main() {}",
        "fn split(items: List<Leaf>) { let a: Leaf = items[2 - 2]; discard a; let b: Leaf = items[0]; discard b; } fn main() {}",
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{reuse}"), "affine-value-reuse");
    }

    // The reproduction: the element read into a binding leaves the list holding the same stored
    // value, so the read itself is the unaccounted copy.
    assert_affine_rejected(
        &format!(
            "{DECLARATIONS}fn split(items: List<Token>) -> List<Token> {{ let t: Token = items[0]; t.consume(); return items; }} fn main() {{}}"
        ),
        "must-consume-copy",
    );

    // The same read inlined into `main` reports exactly the projection and nothing else.
    let inlined = format!(
        "{DECLARATIONS}fn main(items: List<Token>) -> List<Token> {{ let t: Token = items[0]; t.consume(); return items; }}"
    );
    assert_affine_rejected_at(&inlined, "must-consume-copy", "items[0]");
    assert_eq!(
        diagnostic_codes(analyze(&inlined).diagnostics()),
        ["must-consume-copy"],
        "{inlined}"
    );

    // A copied argument, a tuple projection, an element that only inherits the class from a
    // stored value, a dynamic index, a member read through the element, a receiver admission, and
    // a returned element are copies by the same rule.
    for rejected in [
        "fn take(t: Token) { t.consume(); } fn split(items: List<Token>) -> List<Token> { take(items[0]); return items; } fn main() {}",
        "fn split(pair: Tuple<Token, Int>) -> Tuple<Token, Int> { let t: Token = pair[0]; t.consume(); return pair; } fn main() {}",
        "fn split(items: List<Holder>) -> List<Holder> { let h: Holder = items[0]; h.token.consume(); return items; } fn main() {}",
        "fn split(items: List<Token>, i: Int) -> List<Token> { let t: Token = items[i]; t.consume(); return items; } fn main() {}",
        "fn split(items: List<Token>) { items[0].consume(); } fn main() {}",
        "fn split(items: List<Token>) -> Token { return items[0]; } fn main() {}",
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{rejected}"), "must-consume-copy");
    }

    // A copyable member read through the copied element reports the copy once.
    let member = format!(
        "{DECLARATIONS}fn split(items: List<Token>) -> Int {{ items[0].value }} fn main() {{}}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&member).diagnostics())
            .iter()
            .filter(|code| **code == "must-consume-copy")
            .count(),
        1,
        "{member}"
    );

    // The recorded read is the index expression rather than the whole postfix expression, so the copy
    // is attributed to `items[0]` both for the consuming-receiver shape and for the member read, which
    // is the place the sibling receiver admission already blames.
    let consumed_receiver = format!(
        "{DECLARATIONS}fn split(items: List<Token>) {{ items[0].consume(); }} fn main() {{}}"
    );
    assert_affine_rejected_at(&consumed_receiver, "must-consume-copy", "items[0]");
    assert_affine_rejected_at(&member, "must-consume-copy", "items[0]");

    // The recorded copy span stops at the index expression, so it excludes both the closing bracket
    // and any member or call chained after the projection. The start-only marker above cannot see
    // that end offset, which is the part of the attribution the fix changes.
    for source in [&consumed_receiver, &member] {
        let rejected = analyze(source);
        let primary = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "must-consume-copy")
            .and_then(|diagnostic| diagnostic.primary.as_ref())
            .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
        let start = source
            .find("items[0]")
            .unwrap_or_else(|| panic!("{source}: missing projection"));
        assert_eq!(
            usize::try_from(primary.bytes().start()).unwrap_or_default(),
            start,
            "{source}"
        );
        assert_eq!(
            usize::try_from(primary.bytes().end()).unwrap_or_default(),
            start + "items[0".len(),
            "{source}"
        );
    }

    // A read of any element of a `MustConsume` aggregate is a projection read of that value under
    // `GNT-6.2d`, so the tuple pair and the struct-field pair are rejected with the same code. The
    // struct-field span is the field name alone, so its marker carries the following statement text
    // to stay unique in the source.
    assert_affine_rejected_at(
        &format!(
            "{DECLARATIONS}fn split(pair: Tuple<Token, Int>) -> Int {{ let n: Int = pair[1]; n }} fn main() {{}}"
        ),
        "must-consume-copy",
        "pair[1]",
    );
    assert_affine_rejected_at(
        &format!("{DECLARATIONS}fn split(p: Pair) -> Int {{ let n: Int = p.n; n }} fn main() {{}}"),
        "must-consume-copy",
        "n; n }",
    );

    // `discard` of the element reports the discard once and never as a copy: the projection
    // records it and the statement fallback does not duplicate it.
    let discarded = analyze(&format!(
        "{DECLARATIONS}fn split(items: List<Token>) {{ discard items[0]; }} fn main() {{}}"
    ));
    let codes = diagnostic_codes(discarded.diagnostics());
    assert_eq!(
        codes
            .iter()
            .filter(|code| **code == "must-consume-discard")
            .count(),
        1,
        "{codes:?}"
    );
    assert!(!codes.contains(&"must-consume-copy"), "{codes:?}");

    // A field-chain receiver is not the binding itself, so the same rule resolves the chain root,
    // folds the projected members to reach the indexed aggregate, and keys the place by the field
    // path ahead of its index segment. These declarations add one chain shape per pinned case.
    const FIELD_DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         affine struct Leaf { value: Int }\n\
         struct Bag { items: List<Token> }\n\
         struct BagI { items: List<Int> }\n\
         struct Outer { bag: Bag }\n\
         struct HB { pair: Tuple<Token, Int> }\n\
         struct HBII { pair: Tuple<Int, Int> }\n\
         struct HL { items: List<Leaf> }\n\
         impl Token { fn consume(owned self) {} }\n";

    // A copyable element and a single affine element read stay admitted through the field chain.
    for accepted in [
        "fn run(b: BagI) -> Int { b.items[0] } fn main() {}",
        "fn run(h: HL, i: Int) { let a: Leaf = h.items[i]; discard a; } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{FIELD_DECLARATIONS}{accepted}"));
    }

    // Each field-chain read of a `MustConsume` element is the same unaccounted copy as the
    // bare-binding read, including through a second projected level.
    for source in [
        "fn split(b: Bag) -> Bag { b.items[0].consume(); return b; } fn main() {}",
        "fn split(b: Bag) -> Bag { let t: Token = b.items[0]; t.consume(); return b; } fn main() {}",
        "fn split(o: Outer) -> Outer { let t: Token = o.bag.items[0]; t.consume(); return o; } fn main() {}",
        "fn split(h: HB) -> HB { let t: Token = h.pair[0]; t.consume(); return h; } fn main() {}",
    ] {
        assert_affine_rejected(
            &format!("{FIELD_DECLARATIONS}{source}"),
            "must-consume-copy",
        );
    }

    // The recorded read spans the field chain from the binding root through the index expression,
    // exactly as the bare-binding prefix does.
    for (source, prefix) in [
        (
            "fn split(b: Bag) -> Bag { let t: Token = b.items[0]; t.consume(); return b; } fn main() {}",
            "b.items[0",
        ),
        (
            "fn split(o: Outer) -> Outer { let t: Token = o.bag.items[0]; t.consume(); return o; } fn main() {}",
            "o.bag.items[0",
        ),
    ] {
        let program = format!("{FIELD_DECLARATIONS}{source}");
        let rejected = analyze(&program);
        let primary = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "must-consume-copy")
            .and_then(|diagnostic| diagnostic.primary.as_ref())
            .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
        let start = program
            .find(prefix)
            .unwrap_or_else(|| panic!("{source}: missing prefix {prefix:?}"));
        assert_eq!(
            usize::try_from(primary.bytes().start()).unwrap_or_default(),
            start,
            "{source}"
        );
        assert_eq!(
            usize::try_from(primary.bytes().end()).unwrap_or_default(),
            start + prefix.len(),
            "{source}"
        );
    }

    // A field-receiver tuple index is rejected as an index form rather than as an element class,
    // and the same chain reaches the type check the bare binding already performs.
    assert_affine_rejected(
        &format!(
            "{FIELD_DECLARATIONS}fn run(h: HBII, i: Int) -> Int {{ let n: Int = h.pair[i]; n }} fn main() {{}}"
        ),
        "tuple-index-not-literal",
    );
    assert_affine_rejected(
        &format!(
            "{FIELD_DECLARATIONS}fn run(b: BagI) -> Int {{ let x: Bool = b.items[0]; 1 }} fn main() {{}}"
        ),
        "type-mismatch",
    );

    // A field-chain projection keys the same place ledger as the bare binding, so a second read of
    // the element is a repeated use.
    assert_affine_rejected(
        &format!(
            "{FIELD_DECLARATIONS}fn run(h: HL, i: Int) {{ let a: Leaf = h.items[i]; discard a; let c: Leaf = h.items[0]; discard c; }} fn main() {{}}"
        ),
        "affine-value-reuse",
    );
}

/// An index projection resolves its receiver from the children ahead of the index postfix rather than
/// from one required root path, so a `self` root, a parenthesized place, and a call result all type
/// the element they name and reach the same element rules (`GNT-6.2d`).
#[test]
fn public_must_consume_index_projection_receivers_are_resolved() {
    // Every receiver shape gets one copyable projection to accept: the `self` root of `probe`, the
    // parenthesized place of `run`, and the call prefixes of `head` and `headi`.
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         struct Bag { items: List<Int> }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Bag { fn probe(self) -> Int { self.items[0] } }\n\
         fn head(b: Bag) -> Bag { b }\n\
         fn headi(b: Bag) -> List<Int> { b.items }\n";

    // A copyable element read stays admitted through every shape, nested parentheses included.
    for accepted in [
        "fn run(b: Bag) -> Int { (b.items)[0] } fn main() {}",
        "fn run(b: Bag) -> Int { ((b.items))[0] } fn main() {}",
        "fn run(b: Bag) -> Int { head(b).items[0] } fn main() {}",
        "fn run(b: Bag) -> Int { headi(b)[0] } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    // Each shape reaches the element type check and nothing else, so a `Bool` binding of an `Int`
    // element is the only report.
    for rejected in [
        "fn run(b: Bag) -> Int { let x: Bool = (b.items)[0]; 1 } fn main() {}",
        "fn run(b: Bag) -> Int { let x: Bool = ((b.items))[0]; 1 } fn main() {}",
        "fn run(b: Bag) -> Int { let x: Bool = head(b).items[0]; 1 } fn main() {}",
        "fn run(b: Bag) -> Int { let x: Bool = headi(b)[0]; 1 } fn main() {}",
    ] {
        let program = format!("{DECLARATIONS}{rejected}");
        assert_eq!(
            diagnostic_codes(analyze(&program).diagnostics()),
            ["type-mismatch"],
            "{program}"
        );
    }

    // A `self` root carries no path child at all, so it reaches those rules through the reserved
    // word alone: the same copyable read, element type check, and index form as a binding root.
    const SELF_DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         struct Bag { items: List<Int> }\n\
         struct Pair { pair: Tuple<Int, Int> }\n\
         impl Token { fn consume(owned self) {} }\n\
         fn main() {}\n";

    assert_affine_accepted(&format!(
        "{SELF_DECLARATIONS}impl Bag {{ fn probe(self) -> Int {{ self.items[0] }} }}"
    ));
    let self_mismatch = format!(
        "{SELF_DECLARATIONS}impl Bag {{ fn probe(self) -> Int {{ let x: Bool = self.items[0]; 1 }} }}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&self_mismatch).diagnostics()),
        ["type-mismatch"],
        "{self_mismatch}"
    );
    let self_tuple = format!(
        "{SELF_DECLARATIONS}impl Pair {{ fn probe(self, i: Int) -> Int {{ let n: Int = self.pair[i]; n }} }}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&self_tuple).diagnostics()),
        ["tuple-index-not-literal"],
        "{self_tuple}"
    );

    // A `self` root and a parenthesized place are place-backed, so a read of a `MustConsume` element
    // is recorded against the binding and rejected as a copy exactly as `t.tokens[0]` is. Each source
    // consumes the containing value, so the copied read is the only report.
    const PLACE_DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         struct Toks { tokens: List<Token> }\n\
         struct Pair { pair: Tuple<Int, Int> }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Toks { fn consume(owned self) {} }\n\
         fn main() {}\n";

    let self_read = format!(
        "{PLACE_DECLARATIONS}impl Toks {{ fn read(self) -> Int {{ let x: Token = self.tokens[0]; x.consume(); self.consume(); 1 }} }}"
    );
    let paren_read = format!(
        "{PLACE_DECLARATIONS}fn run(t: Toks) -> Int {{ let x: Token = (t.tokens)[0]; x.consume(); t.consume(); 1 }}"
    );
    for source in [&self_read, &paren_read] {
        assert_eq!(
            diagnostic_codes(analyze(source).diagnostics()),
            ["must-consume-copy"],
            "{source}"
        );
    }

    // The recorded read starts at the receiver part rather than at any inner path, so it covers the
    // reserved word of a `self` root and the parenthesis of a parenthesized place, and it stops at
    // the index expression rather than at the closing bracket.
    for (source, prefix) in [(&self_read, "self.tokens[0"), (&paren_read, "(t.tokens)[0")] {
        assert_affine_rejected_at(source, "must-consume-copy", prefix);
        let rejected = analyze(source);
        let primary = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "must-consume-copy")
            .and_then(|diagnostic| diagnostic.primary.as_ref())
            .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
        let start = source
            .find(prefix)
            .unwrap_or_else(|| panic!("{source}: missing prefix {prefix:?}"));
        assert_eq!(
            usize::try_from(primary.bytes().start()).unwrap_or_default(),
            start,
            "{source}"
        );
        assert_eq!(
            usize::try_from(primary.bytes().end()).unwrap_or_default(),
            start + prefix.len(),
            "{source}"
        );
    }

    // A discarded element of a parenthesized place reports the discard once, under the same prefix
    // span rather than under an inner path node.
    let discarded = format!(
        "{PLACE_DECLARATIONS}fn run(t: Toks) -> Int {{ discard (t.tokens)[0]; t.consume(); 1 }}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&discarded).diagnostics()),
        ["must-consume-discard"],
        "{discarded}"
    );
    assert_affine_rejected_at(&discarded, "must-consume-discard", "(t.tokens)[0");

    // A dynamic tuple index through a parenthesized place is rejected as an index form rather than as
    // an element class, exactly as the bare binding form is.
    let paren_tuple = format!(
        "{PLACE_DECLARATIONS}fn run(p: Pair, i: Int) -> Int {{ let x: Bool = (p.pair)[i]; 1 }}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&paren_tuple).diagnostics()),
        ["tuple-index-not-literal"],
        "{paren_tuple}"
    );

    // Grouping parentheses are transparent at every position of a receiver chain, not only around the
    // whole receiver part: `(h).items`, `((h).items)`, and `(h.items)` all name the same place chain
    // `h.items` names. The chain root stays the binding and each element is its own list segment, so
    // two sibling reads are two element places rather than two reads of the whole chain root.
    const CHAIN_DECLARATIONS: &str = "affine struct Leaf { value: Int }\n\
         struct HL { items: List<Leaf> }\n\
         fn main() {}\n";

    for accepted in [
        // The bare and whole-part-parenthesized forms are the controls the chain-root form matches.
        "fn af(h: HL) { let a: Leaf = h.items[0]; discard a; let c: Leaf = h.items[1]; discard c; }",
        "fn af(h: HL) { let a: Leaf = (h.items)[0]; discard a; let c: Leaf = (h.items)[1]; discard c; }",
        "fn af(h: HL) { let a: Leaf = (h).items[0]; discard a; let c: Leaf = (h).items[1]; discard c; }",
        "fn af(h: HL) { let a: Leaf = ((h).items)[0]; discard a; let c: Leaf = ((h).items)[1]; discard c; }",
    ] {
        assert_affine_accepted(&format!("{CHAIN_DECLARATIONS}{accepted}"));
    }

    // A chain-root parenthesis reaches the element type check and nothing else, exactly as the
    // whole-part parenthesis of `(b.items)[0]` reaches it.
    let rooted_chain = format!(
        "{DECLARATIONS}fn run(b: Bag) -> Int {{ let x: Bool = (b).items[0]; 1 }} fn main() {{}}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&rooted_chain).diagnostics()),
        ["type-mismatch"],
        "{rooted_chain}"
    );

    // The normalized chain records one element read under the receiver part's own prefix span, so a
    // discarded and a copied `MustConsume` element both start at the parenthesis and stop at the
    // index expression rather than at an inner path node.
    let rooted_discard = format!(
        "{PLACE_DECLARATIONS}fn run(t: Toks) -> Int {{ discard (t).tokens[0]; t.consume(); 1 }}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&rooted_discard).diagnostics()),
        ["must-consume-discard"],
        "{rooted_discard}"
    );
    assert_affine_rejected_at(&rooted_discard, "must-consume-discard", "(t).tokens[0");
    let rooted_copy = format!(
        "{PLACE_DECLARATIONS}fn run(t: Toks) -> Int {{ let x: Token = (t).tokens[0]; x.consume(); t.consume(); 1 }}"
    );
    assert_eq!(
        diagnostic_codes(analyze(&rooted_copy).diagnostics()),
        ["must-consume-copy"],
        "{rooted_copy}"
    );
    assert_affine_rejected_at(&rooted_copy, "must-consume-copy", "(t).tokens[0");

    // A member the chain cannot resolve is that chain's own report: the walk reports
    // `unknown-member` once at the member token and reads no element, so the root is neither copied
    // nor reported a second time. The bare binding is the control.
    const UNRESOLVED_DECLARATIONS: &str = "must_consume struct Outer { bag: List<Bool> }\n\
         impl Outer { fn consume(owned self) {} }\n\
         fn main() {}\n";

    for source in [
        "fn run(o: Outer) -> Int { let x: Bool = (o).nope[0]; o.consume(); 1 }",
        "fn run(o: Outer) -> Int { let x: Bool = o.nope[0]; o.consume(); 1 }",
    ] {
        let program = format!("{UNRESOLVED_DECLARATIONS}{source}");
        assert_eq!(
            diagnostic_codes(analyze(&program).diagnostics()),
            ["unknown-member"],
            "{program}"
        );
    }

    // A call result is no caller place, so an element projected out of one is a temporary: reading a
    // `MustConsume` element out of `make()[0]` is consumed by its own binding and the projection
    // contributes no report at all.
    const CALL_DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n\
         fn make() -> List<Token> { [Token { value: 1 }] }\n\
         fn main() {}\n";

    assert_affine_accepted(&format!(
        "{CALL_DECLARATIONS}fn run() -> Int {{ let t: Token = make()[0]; t.consume(); 1 }}"
    ));
}

/// A `for` statement binds a fresh item place per iteration, so the item owes its consumption at
/// the iteration exit exactly as a `let` declaration does (`GNT-6.2d`, `GNT-9.4`).
#[test]
fn public_must_consume_for_item_bindings_owe_consumption() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         must_consume struct Wrap { inner: Token }\n\
         struct Holder { token: Token }\n\
         struct Plain { marker: Int }\n\
         affine struct Droppable {}\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Holder { fn consume(owned self) {} }\n\
         impl Wrap { fn consume(owned self) {} }\n";

    // The item is an ordinary binding introduction: consuming it inside the body discharges the
    // iteration whether the body falls through, breaks, or continues, and an element whose type
    // owes nothing needs no discharge.
    for accepted in [
        "fn run() { for t in [Token { value: 1 }] { t.consume(); } } fn main() {}",
        "fn run() { for t in [Token { value: 1 }] { t.consume(); break; } } fn main() {}",
        "fn run() { for t in [Token { value: 1 }] { t.consume(); continue; } } fn main() {}",
        // A conditional `break`/`continue` retires the iteration scope on that path only, and the
        // item stays consumed on every path that leaves the iteration.
        "fn run(flag: Bool) { for t in [Token { value: 1 }] { t.consume(); if flag { break; } } } fn main() {}",
        "fn run(flag: Bool) { for t in [Token { value: 1 }] { t.consume(); if flag { continue; } } } fn main() {}",
        // A `let` the body introduced is retired by the same transfer, so registering the item must
        // not resurrect it either.
        "fn run(flag: Bool) { for v in [1] { let t: Token = Token { value: 1 }; t.consume(); if flag { break; } } } fn main() {}",
        // A transfer inside a conditional branch retires the scopes that path leaves, including the
        // loop body's scope the fall-through path still holds, so a declaration after the transfer
        // is judged in the body rather than in the loop's enclosing scope.
        "fn run(flag: Bool) { while flag { let b: Token = Token { value: 1 }; b.consume(); if flag { break; } } } fn main() {}",
        "fn run(flag: Bool) { while flag { let b: Token = Token { value: 1 }; b.consume(); if flag { continue; } } } fn main() {}",
        "fn run(flag: Bool) { while flag { if flag { break; } let b: Token = Token { value: 1 }; b.consume(); } } fn main() {}",
        "fn run(flag: Bool) { while flag { if flag { break; } let b: Token = Token { value: 1 }; if flag { b.consume(); } else { b.consume(); } } } fn main() {}",
        // The same restore covers a match arm, so a body declaration the arms consume on every path
        // is discharged.
        "fn run(flag: Bool, o: Option<Int>) { while flag { if flag { break; } let b: Token = Token { value: 1 }; match o { Some(_) => { b.consume(); }, None => { b.consume(); } } } } fn main() {}",
        "fn run() { for h in [Holder { token: Token { value: 1 } }] { h.token.consume(); } } fn main() {}",
        "fn run() { for v in [1, 2] { } } fn main() {}",
        "fn run() { for p in [Plain { marker: 1 }] { } } fn main() {}",
        "fn run() { for d in [Droppable {}] { } } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    for (source, code) in [
        // The item binding owes its consumption, so an empty body leaves it unconsumed ...
        (
            "fn run() { for t in [Token { value: 1 }] { } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // ... and a body that only leaves through `continue` retires the iteration scope with the
        // item still live.
        (
            "fn run() { for t in [Token { value: 1 }] { continue; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A discharge on only one path leaves the item path-dependent, like a `let` binding.
        (
            "fn run(flag: Bool) { for t in [Token { value: 1 }] { if flag { t.consume(); } } } fn main() {}",
            "must-consume-path-dependent",
        ),
        // A conditional `break` retires the item scope with the item still live on that path.
        (
            "fn run(flag: Bool) { for t in [Token { value: 1 }] { if flag { break; } } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A `let` the body introduced is retired by the same transfer, so it owes its own
        // consumption whether or not the item does.
        (
            "fn run(flag: Bool) { for v in [1] { let t: Token = Token { value: 1 }; if flag { break; } } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // An aggregate element that only inherits the class owns each stored place ...
        (
            "fn run() { for h in [Holder { token: Token { value: 1 } }] { } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // ... and a declared aggregate is one place, so consuming the stored value inside the item
        // never discharges the item itself.
        (
            "fn run() { for w in [Wrap { inner: Token { value: 1 } }] { w.inner.consume(); } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // The conditional transfer retires the item scope with the atomic item still live.
        (
            "fn run(flag: Bool) { for w in [Wrap { inner: Token { value: 1 } }] { w.inner.consume(); if flag { break; } } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A transfer inside a conditional branch retires the loop body's scope on that path only, so
        // a declaration the fall-through path reaches afterwards still owes consumption.
        (
            "fn run(flag: Bool) { while flag { if flag { break; } let b: Token = Token { value: 1 }; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        (
            "fn run(flag: Bool) { while flag { if flag { continue; } let b: Token = Token { value: 1 }; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        (
            "fn run(flag: Bool) { loop { if flag { break; } let b: Token = Token { value: 1 }; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        (
            "fn run(flag: Bool) { for v in [1] { if flag { break; } let b: Token = Token { value: 1 }; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        (
            "fn run(flag: Bool) { for v in [1] { if flag { continue; } let b: Token = Token { value: 1 }; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A fresh assignment after the transfer re-initializes the place, so the reassigned value
        // owes its own consumption rather than inheriting the discharge before the transfer.
        (
            "fn run(flag: Bool) { while flag { if flag { break; } let mut b: Token = Token { value: 1 }; b.consume(); b = Token { value: 2 }; } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A match arm the body reaches after the transfer reports at the same body scope exit.
        (
            "fn run(flag: Bool, o: Option<Int>) { while flag { if flag { break; } let b: Token = Token { value: 1 }; match o { Some(_) => { }, None => { } } } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // An arm that leaves through a transfer retires the item scope on that path only.
        (
            "fn run(o: Option<Int>) { for t in [Token { value: 1 }] { match o { Some(_) => { t.consume(); }, None => { break; } } } } fn main() {}",
            "must-consume-unconsumed",
        ),
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{source}"), code);
    }

    // `discard` of the item is rejected exactly as it is for a `let` binding, and it is not a
    // discharge, so the item still reports its own unconsumed obligation.
    let discarded = analyze(&format!(
        "{DECLARATIONS}fn run() {{ for t in [Token {{ value: 1 }}] {{ discard t; }} }} fn main() {{}}"
    ));
    assert_eq!(
        diagnostic_codes(discarded.diagnostics()),
        ["must-consume-discard", "must-consume-unconsumed"],
        "{:?}",
        discarded.diagnostics()
    );

    // The empty-body repro reports the item itself: the primary span is the item identifier and
    // the report names that binding.
    let source = "fn run() { for t in [Token { value: 1 }] { } } fn main() {}";
    let package = analyze(&format!("{DECLARATIONS}{source}"));
    assert_eq!(package.status(), AnalysisStatus::Invalid, "{source}");
    let diagnostic = package
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed")
        .unwrap_or_else(|| panic!("{source}: {:?}", package.diagnostics()));
    assert_eq!(
        diagnostic.fields.get("binding").map(AsRef::as_ref),
        Some("t"),
        "{source}: {:?}",
        package.diagnostics()
    );
    let primary = diagnostic
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{source}: missing primary span"));
    let item = format!("{DECLARATIONS}{source}");
    let binding_start = item
        .find("for t in")
        .unwrap_or_else(|| panic!("{source}: missing the item binding"))
        + "for ".len();
    assert_eq!(
        usize::try_from(primary.bytes().start()).unwrap_or_default(),
        binding_start,
        "{source}"
    );
    assert_eq!(
        usize::try_from(primary.bytes().end()).unwrap_or_default(),
        binding_start + "t".len(),
        "{source}"
    );
    assert_eq!(
        item.get(binding_start..binding_start + "t".len()),
        Some("t"),
        "{source}"
    );

    // The conditional-transfer repro reports the item the transfer retired: the primary span is the
    // item identifier, and the report belongs to the iteration exit rather than the callable
    // return.
    let transferred =
        "fn run(flag: Bool) { for t in [Token { value: 1 }] { if flag { break; } } } fn main() {}";
    let program = format!("{DECLARATIONS}{transferred}");
    let package = analyze(&program);
    assert_eq!(package.status(), AnalysisStatus::Invalid, "{transferred}");
    assert_eq!(
        diagnostic_codes(package.diagnostics()),
        ["must-consume-unconsumed"],
        "{transferred}: the item is reported exactly once: {:?}",
        package.diagnostics()
    );
    let diagnostic = package
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed")
        .unwrap_or_else(|| panic!("{transferred}: {:?}", package.diagnostics()));
    let primary = diagnostic
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{transferred}: missing primary span"));
    let binding_start = program
        .find("t in [")
        .unwrap_or_else(|| panic!("{transferred}: missing the item binding"));
    assert_eq!(
        usize::try_from(primary.bytes().start()).unwrap_or_default(),
        binding_start,
        "{transferred}: the report does not start at the item binding"
    );
    assert_eq!(
        usize::try_from(primary.bytes().end()).unwrap_or_default(),
        binding_start + "t".len(),
        "{transferred}: the report does not end after the item binding"
    );
    assert_eq!(
        program.get(binding_start..binding_start + "t".len()),
        Some("t"),
        "{transferred}: the item span does not slice to the binding"
    );

    // A `let` the loop body introduced is reported by its own declaration statement, so its span
    // covers the statement the body introduced rather than the iteration.
    let shadowed = "fn run(flag: Bool) { for v in [1] { let t: Token = Token { value: 1 }; if flag { break; } } } fn main() {}";
    let program = format!("{DECLARATIONS}{shadowed}");
    let package = analyze(&program);
    assert_eq!(package.status(), AnalysisStatus::Invalid, "{shadowed}");
    let diagnostic = package
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed")
        .unwrap_or_else(|| panic!("{shadowed}: {:?}", package.diagnostics()));
    let primary = diagnostic
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{shadowed}: missing primary span"));
    let declaration = "let t: Token = Token { value: 1 };";
    let declaration_start = program
        .find(declaration)
        .unwrap_or_else(|| panic!("{shadowed}: missing the body binding"));
    let start = usize::try_from(primary.bytes().start()).unwrap_or_default();
    let end = usize::try_from(primary.bytes().end()).unwrap_or_default();
    assert_eq!(start, declaration_start, "{shadowed}");
    assert_eq!(end, declaration_start + declaration.len(), "{shadowed}");
    assert_eq!(program.get(start..end), Some(declaration), "{shadowed}");

    // A transfer retires the loop body's scope, and the fall-through path still holds the frame the
    // transfer retired, so the declaration the body introduced is reported once rather than twice.
    let retried = "fn run(flag: Bool) { while flag { if flag { break; } let b: Token = Token { value: 1 }; } } fn main() {}";
    let program = format!("{DECLARATIONS}{retried}");
    let package = analyze(&program);
    assert_eq!(package.status(), AnalysisStatus::Invalid, "{retried}");
    assert_eq!(
        diagnostic_codes(package.diagnostics()),
        ["must-consume-unconsumed"],
        "{retried}: the body binding is reported exactly once: {:?}",
        package.diagnostics()
    );
    let declaration = "let b: Token = Token { value: 1 };";
    let declaration_start = program
        .find(declaration)
        .unwrap_or_else(|| panic!("{retried}: missing the body binding"));
    let primary = package
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed")
        .and_then(|diagnostic| diagnostic.primary.as_ref())
        .unwrap_or_else(|| panic!("{retried}: missing primary span"));
    let start = usize::try_from(primary.bytes().start()).unwrap_or_default();
    let end = usize::try_from(primary.bytes().end()).unwrap_or_default();
    assert_eq!(start, declaration_start, "{retried}");
    assert_eq!(end, declaration_start + declaration.len(), "{retried}");
    assert_eq!(program.get(start..end), Some(declaration), "{retried}");

    // A place source copies the outer place, which the source span already reports.
    let copied = "fn run(items: List<Token>) { for t in items { t.consume(); } } fn main() {}";
    assert_affine_rejected(&format!("{DECLARATIONS}{copied}"), "must-consume-copy");
}

/// Re-initializing a place inside an already consumed containing place owes the fresh value's own
/// consumption, while the containing place and the places it still contains stay gone
/// (`GNT-6.2d`).
#[test]
fn public_reinitialized_subplace_of_a_consumed_place_owes_consumption() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         must_consume struct Wrap { inner: Token }\n\
         struct Holder { token: Token, marker: Int }\n\
         struct Pair { left: Token, right: Token }\n\
         impl Token { fn consume(owned self) {} }\n\
         impl Holder { fn consume(owned self) {} }\n\
         impl Pair { fn consume(owned self) {} }\n\
         impl Wrap { fn consume(owned self) {} }\n";

    // The fresh value is a new obligation, so consuming it discharges the root again.
    for accepted in [
        "fn main(mut holder: Holder) { holder.consume(); holder.token = Token { value: 1 }; holder.token.consume(); }",
        "fn main(mut wrap: Wrap) { wrap.consume(); wrap.inner = Token { value: 1 }; wrap.inner.consume(); }",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    for (source, code) in [
        // The fresh value is not consumed before the callable returns.
        (
            "fn main(mut holder: Holder) { holder.consume(); holder.token = Token { value: 1 }; }",
            "must-consume-unconsumed",
        ),
        (
            "fn main(mut wrap: Wrap) { wrap.consume(); wrap.inner = Token { value: 1 }; }",
            "must-consume-unconsumed",
        ),
        // Replacing the fresh value discards it.
        (
            "fn main(mut holder: Holder) { holder.consume(); holder.token = Token { value: 1 }; holder.token = Token { value: 2 }; }",
            "must-consume-replaced",
        ),
        // Only the re-initialized place is fresh: a sibling place is still gone with the place
        // that contained it.
        (
            "fn main(mut pair: Pair) { pair.consume(); pair.left = Token { value: 1 }; pair.right.consume(); }",
            "affine-value-reuse",
        ),
        // The containing place itself stays gone, so consuming it again is a repeated use.
        (
            "fn main(mut holder: Holder) { holder.consume(); holder.token = Token { value: 1 }; holder.consume(); }",
            "affine-value-reuse",
        ),
        // A re-initialization inside a branch owes consumption only on the paths that reach it.
        (
            "fn run(mut holder: Holder, flag: Bool) { holder.consume(); if flag { holder.token = Token { value: 1 }; } } fn main() {}",
            "must-consume-path-dependent",
        ),
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{source}"), code);
    }
}

/// The obligation fold uses the same constant-condition facts as the reachability analysis: a
/// statically decided branch cannot make a fully consumed value look path-dependent, and an
/// `else if` chain that can fall through without running a branch keeps the value live
/// (`GNT-6.2d`).
#[test]
fn public_constant_conditions_select_the_reaching_obligation_paths() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    // A statically true condition runs its branch on every path, and a statically false leading
    // condition leaves the following branch as the only outcome.
    for accepted in [
        "fn run() { let t: Token = Token { value: 1 }; if true { t.consume(); } } fn main() {}",
        "fn run() { let t: Token = Token { value: 1 }; if true { t.consume(); } else { t.consume(); } } fn main() {}",
        "fn run() { let t: Token = Token { value: 1 }; if false { t.consume(); } else { t.consume(); } } fn main() {}",
        "fn run() { let t: Token = Token { value: 1 }; if false { } else if true { t.consume(); } } fn main() {}",
        // A diverging branch still settles the consumption performed before it, and a pattern
        // chain whose trailing condition is statically true cannot fall through.
        "fn run() { let t: Token = Token { value: 1 }; if true { t.consume(); while true { } } } fn main() {}",
        "fn run(o: Option<Int>) { let t: Token = Token { value: 1 }; if let Some(x) = o { t.consume(); } else if true { t.consume(); } } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    for (source, code) in [
        // The statically false branch never runs, so its discharge is not a reaching path and
        // the value is still owed at the region exit.
        (
            "fn run() { let t: Token = Token { value: 1 }; if false { t.consume(); } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A statically true condition runs its live branch on every path.
        (
            "fn run() { let t: Token = Token { value: 1 }; if true { } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // An `else if` chain without a final else can fall through without running a branch, so
        // two consumers do not discharge the value.
        (
            "fn run(flag: Bool, other: Bool) { let t: Token = Token { value: 1 }; if flag { t.consume(); } else if other { t.consume(); } } fn main() {}",
            "must-consume-path-dependent",
        ),
        // A runtime condition keeps the partial-consume verdict.
        (
            "fn run(flag: Bool) { let t: Token = Token { value: 1 }; if flag { t.consume(); } } fn main() {}",
            "must-consume-path-dependent",
        ),
        // A branch that diverges never reaches a transfer that reports what it owes, so the
        // value is still unconsumed at the scope exit.
        (
            "fn run() { let t: Token = Token { value: 1 }; if true { while true { } } } fn main() {}",
            "must-consume-unconsumed",
        ),
        // A pattern chain whose trailing runtime condition can fail leaves the value live on
        // the path where neither branch runs.
        (
            "fn run(o: Option<Int>, flag: Bool) { let t: Token = Token { value: 1 }; if let Some(x) = o { t.consume(); } else if flag { t.consume(); } } fn main() {}",
            "must-consume-path-dependent",
        ),
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{source}"), code);
    }
}

/// A `break` retires the scopes opened inside its loop exactly once, so a discharge recorded
/// before the loop survives the enclosing block and a live obligation is reported once
/// (`GNT-6.2d`).
#[test]
fn public_loop_transfers_retire_only_the_scopes_they_leave() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    // The discharge before the conditional is still the scope's discharge after the nested loop
    // retires its own scopes and exits through a `break`.
    for accepted in [
        "fn run() { let t: Token = Token { value: 1 }; t.consume(); if true { while true { break; } } } fn main() {}",
        "fn run() { let t: Token = Token { value: 1 }; t.consume(); if true { loop(limit = 1) { break; } } } fn main() {}",
        "fn run(flag: Bool) { let t: Token = Token { value: 1 }; t.consume(); if flag { while true { break; } } } fn main() {}",
        "fn run(o: Option<Int>) { let t: Token = Token { value: 1 }; t.consume(); if let Some(x) = o { while true { break; } } } fn main() {}",
        "fn run(o: Option<Int>) { let t: Token = Token { value: 1 }; t.consume(); match o { Some(_) => { while true { break; } }, None => { } } } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    // The loop body's scope is retired by the `break` itself, so the enclosing block reports the
    // still-live obligation exactly once.
    for source in [
        "fn run() { let t: Token = Token { value: 1 }; if true { while true { break; } } } fn main() {}",
        "fn run() { let t: Token = Token { value: 1 }; while true { if true { break; } } } fn main() {}",
    ] {
        let package = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(package.status(), AnalysisStatus::Invalid, "{source}");
        // The loop never consumes the value, so the only report is the unconsumed obligation.
        assert_eq!(
            diagnostic_codes(package.diagnostics()),
            ["must-consume-unconsumed"],
            "{source}: {:?}",
            package.diagnostics()
        );
    }
}

/// `GNT-3-T-LOOP` guarantees the first iteration of an unbroken `loop`, an `until`, and a `while`
/// whose condition is statically true, and `GNT-9.5` makes a loop limit or an exhausted budget a
/// dynamic failure rather than a static normal path. A transfer of an outer `MustConsume` place
/// inside such a body is still potentially repeated (`GNT-6.2e`), so that repeated transfer is the
/// only verdict; a runtime condition keeps the zero-iteration path and its conditional verdict.
#[test]
fn public_guaranteed_loop_iterations_leave_no_zero_iteration_path() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    for source in [
        "fn run(token: Token) { loop { token.consume(); break; } } fn main() {}",
        "fn run(token: Token) { loop(limit = 1) { token.consume(); break; } } fn main() {}",
        "fn run(token: Token) { while true { token.consume(); break; } } fn main() {}",
        "fn run(token: Token) { loop { token.consume(); return; } } fn main() {}",
        "fn run(token: Token, flag: Bool) { until { token.consume(); break; } when flag; } fn main() {}",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            diagnostic_codes(rejected.diagnostics()),
            ["affine-value-reuse"],
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }

    // A runtime condition keeps the zero-iteration path, so the discharge stays conditional.
    let conditional = analyze(&format!(
        "{DECLARATIONS}fn run(token: Token, flag: Bool) {{ while flag {{ token.consume(); break; }} }} fn main() {{}}"
    ));
    assert_eq!(conditional.status(), AnalysisStatus::Invalid);
    assert!(
        diagnostic_codes(conditional.diagnostics()).contains(&"must-consume-path-dependent"),
        "{:?}",
        conditional.diagnostics()
    );

    // A root bound inside the body is admitted once per iteration, so those loops stay valid.
    for accepted in [
        "fn run() { loop { let u: Token = Token { value: 1 }; u.consume(); break; } } fn main() {}",
        "fn run(flag: Bool) { while flag { let u: Token = Token { value: 1 }; u.consume(); if flag { break; } } } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    // A guaranteed body completes only through its `break` transfers, so the state after the loop
    // joins those transfers rather than the path its fall-through left (`GNT-3-T-LOOP`): a place
    // re-initialized on one break path is still already gone on another.
    for source in [
        "fn run(mut token: Token, flag: Bool) { token.consume(); loop { if flag { break; } token = Token { value: 1 }; break; } token.consume(); } fn main() {}",
        "fn run(mut token: Token, flag: Bool) { token.consume(); loop(limit = 1) { if flag { break; } token = Token { value: 1 }; break; } token.consume(); } fn main() {}",
        "fn run(mut token: Token, flag: Bool) { token.consume(); until { if flag { break; } token = Token { value: 1 }; break; } when false; token.consume(); } fn main() {}",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            diagnostic_codes(rejected.diagnostics()).contains(&"affine-value-reuse"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }

    // A `break` path that leaves the place live still owes it at the callable exit.
    let live_break = analyze(&format!(
        "{DECLARATIONS}fn run(token: Token, flag: Bool) {{ loop {{ if flag {{ token.consume(); }} else {{ break; }} break; }} }} fn main() {{}}"
    ));
    assert_eq!(live_break.status(), AnalysisStatus::Invalid);
    assert!(
        diagnostic_codes(live_break.diagnostics()).contains(&"must-consume-path-dependent"),
        "{:?}",
        live_break.diagnostics()
    );

    // Every normal completion re-initialized the place, so the replacement value is the one the
    // trailing transfer consumes.
    assert_affine_accepted(&format!(
        "{DECLARATIONS}fn run(mut token: Token) {{ token.consume(); loop {{ token = Token {{ value: 1 }}; break; }} token.consume(); }} fn main() {{}}"
    ));

    // An `until` body that reaches its post-test also completes the loop, so its fall-through is
    // one of the exit states the join must include (`GNT-3-T-LOOP`).
    let until_fallthrough = analyze(&format!(
        "{DECLARATIONS}fn run(mut token: Token, flag: Bool) {{ token.consume(); until {{ if flag {{ token = Token {{ value: 1 }}; break; }} }} when true; token.consume(); }} fn main() {{}}"
    ));
    assert_eq!(
        diagnostic_codes(until_fallthrough.diagnostics()),
        ["affine-value-reuse"],
        "{:?}",
        until_fallthrough.diagnostics()
    );

    // A statically false post-test removes that exit edge, so only the `break` path completes.
    assert_affine_accepted(&format!(
        "{DECLARATIONS}fn run(mut token: Token, flag: Bool) {{ token.consume(); until {{ if flag {{ token = Token {{ value: 1 }}; break; }} }} when false; token.consume(); }} fn main() {{}}"
    ));
}

/// An implementation method must stay within the effect contract its trait method declares,
/// because that declared set is the conservative summary parametric callers rely on
/// (`GNT-3-T-PARAMETRIC-PACKAGE`, `GNT-6.12-static-traits`).
#[test]
fn public_trait_implementation_effects_stay_within_the_declared_contract() {
    let pure_contract = analyze(
        "trait Render { pure fn render(self); }\n\
         struct Item {}\n\
         impl Render for Item { fn render(self) { discard prompt \"Generate.\" -> String; } }\n\
         fn main() {}",
    );
    assert_eq!(
        pure_contract.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        pure_contract.diagnostics()
    );
    assert!(
        pure_contract.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "effect-contract-violation"
                && diagnostic
                    .fields
                    .get("inferred")
                    .is_some_and(|inferred| inferred.as_ref() == "prompt")
                && diagnostic
                    .fields
                    .get("declared")
                    .is_some_and(|declared| declared.as_ref().is_empty())
        }),
        "{:?}",
        pure_contract.diagnostics()
    );
    assert!(pure_contract.executable_program().is_none());

    let wider_template = analyze(
        "trait Render { fn render(self) effects { prompt }; }\n\
         struct Envelope<T> { value: T }\n\
         impl<T> Render for Envelope<T> { fn render(self) { discard prompt \"Generate.\" -> String; spawn background { return; } detach(background); } }\n\
         fn main() {}",
    );
    assert_eq!(
        wider_template.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        wider_template.diagnostics()
    );
    assert!(
        wider_template.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "effect-contract-violation"
                && diagnostic
                    .fields
                    .get("inferred")
                    .is_some_and(|inferred| inferred.as_ref().contains("background"))
        }),
        "{:?}",
        wider_template.diagnostics()
    );

    let matching = analyze(
        "trait Render { fn render(self) effects { prompt }; }\n\
         struct Item {}\n\
         impl Render for Item { fn render(self) { discard prompt \"Generate.\" -> String; } }\n\
         fn main() {}",
    );
    assert_eq!(
        matching.status(),
        AnalysisStatus::Valid,
        "{:?}",
        matching.diagnostics()
    );

    // A helper call contributes transitively, so an implementation that reaches an effect through
    // another callable still violates a narrower contract.
    let transitive_violation = analyze(
        "trait Render { pure fn render(self); }\n\
         struct Item {}\n\
         fn helper() { discard prompt \"Generate.\" -> String; }\n\
         impl Render for Item { fn render(self) { helper(); } }\n\
         fn main() {}",
    );
    assert_eq!(
        transitive_violation.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        transitive_violation.diagnostics()
    );
    assert!(
        transitive_violation
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "effect-contract-violation"),
        "{:?}",
        transitive_violation.diagnostics()
    );

    // A contract strictly wider than the inferred set stays accepted.
    let wider_contract = analyze(
        "trait Render { fn render(self) effects { prompt, background }; }\n\
         struct Item {}\n\
         impl Render for Item { fn render(self) { discard prompt \"Generate.\" -> String; } }\n\
         fn main() {}",
    );
    assert_eq!(
        wider_contract.status(),
        AnalysisStatus::Valid,
        "{:?}",
        wider_contract.diagnostics()
    );

    // A pure method that breaks its own contract reports the contract violation, not the generic
    // purity report, which would describe a method as a workflow and duplicate the finding.
    let pure_method = analyze(
        "trait Render { pure fn render(self); }\n\
         struct Item {}\n\
         impl Render for Item { pure fn render(self) { discard prompt \"Generate.\" -> String; } }\n\
         fn main() {}",
    );
    let codes = pure_method
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert!(
        codes.contains(&"effect-contract-violation"),
        "{:?}",
        pure_method.diagnostics()
    );
    assert!(
        !codes.contains(&"impure-workflow"),
        "{:?}",
        pure_method.diagnostics()
    );

    // Two implementations of one trait method stay distinguishable by their implementing identity.
    let two_impls = analyze(
        "trait Render { pure fn render(self); }\n\
         struct First {}\n\
         struct Second {}\n\
         impl Render for First { fn render(self) { discard prompt \"a\" -> String; } }\n\
         impl Render for Second { fn render(self) { discard prompt \"b\" -> String; } }\n\
         fn main() {}",
    );
    assert_eq!(
        two_impls.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        two_impls.diagnostics()
    );
    let implementations = two_impls
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "effect-contract-violation")
        .filter_map(|diagnostic| {
            diagnostic
                .fields
                .get("implementation")
                .map(std::string::ToString::to_string)
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(implementations.len(), 2, "{:?}", two_impls.diagnostics());
    assert!(
        implementations.iter().any(|value| value.contains("First"))
            && implementations.iter().any(|value| value.contains("Second")),
        "{implementations:?}"
    );

    // The report points at the offending operation rather than the whole declaration or an
    // operation the contract permits.
    let located = analyze(
        "trait Render { fn render(self) effects { prompt }; }\n\
         struct Item {}\n\
         impl Render for Item { fn render(self) { discard prompt \"Generate.\" -> String; spawn background { return; } detach(background); } }\n\
         fn main() {}",
    );
    let diagnostic = located
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "effect-contract-violation")
        .unwrap_or_else(|| panic!("{:?}", located.diagnostics()));
    let primary = diagnostic
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", located.diagnostics()));
    let source = "trait Render { fn render(self) effects { prompt }; }\n\
         struct Item {}\n\
         impl Render for Item { fn render(self) { discard prompt \"Generate.\" -> String; spawn background { return; } detach(background); } }\n\
         fn main() {}";
    let start = usize::try_from(primary.bytes().start()).unwrap_or_default();
    let end = usize::try_from(primary.bytes().end()).unwrap_or_default();
    let located_text = source.get(start..end).unwrap_or_default();
    assert!(
        located_text.contains("spawn") || located_text.contains("detach"),
        "{located_text:?}: {:?}",
        located.diagnostics()
    );
    assert!(
        !located_text.contains("prompt"),
        "the span names an operation the contract permits: {located_text:?}"
    );

    // A pure implementation method whose effects stay inside its contract reports one purity
    // violation, not one per walker.
    let in_contract_pure = analyze(
        "trait Render { fn render(self) effects { prompt }; }\n\
         struct Item {}\n\
         impl Render for Item { pure fn render(self) { discard prompt \"a\" -> String; } }\n\
         fn main() {}",
    );
    assert_eq!(
        in_contract_pure
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "impure-workflow")
            .count(),
        1,
        "{:?}",
        in_contract_pure.diagnostics()
    );

    // The same holds for a pure free function, whose purity report both walkers used to emit with
    // different message text, which defeated the diagnostic dedup.
    let in_contract_function =
        analyze("pure fn helper() { discard prompt \"a\" -> String; }\nfn main() {}");
    assert_eq!(
        in_contract_function
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "impure-workflow")
            .count(),
        1,
        "{:?}",
        in_contract_function.diagnostics()
    );

    // A purely transitive violation points at the call that can reach the effect.
    let transitive_span = analyze(
        "trait Render { pure fn render(self); }\n\
         struct Item {}\n\
         fn helper() { discard prompt \"x\" -> String; }\n\
         impl Render for Item { fn render(self) { helper(); } }\n\
         fn main() {}",
    );
    let transitive_diagnostic = transitive_span
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "effect-contract-violation")
        .unwrap_or_else(|| panic!("{:?}", transitive_span.diagnostics()));
    let transitive_primary = transitive_diagnostic
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", transitive_span.diagnostics()));
    let transitive_source = "trait Render { pure fn render(self); }\n\
         struct Item {}\n\
         fn helper() { discard prompt \"x\" -> String; }\n\
         impl Render for Item { fn render(self) { helper(); } }\n\
         fn main() {}";
    let transitive_start = usize::try_from(transitive_primary.bytes().start()).unwrap_or_default();
    let transitive_end = usize::try_from(transitive_primary.bytes().end()).unwrap_or_default();
    let transitive_text = transitive_source
        .get(transitive_start..transitive_end)
        .unwrap_or_default();
    assert!(
        transitive_text.contains("helper"),
        "{transitive_text:?}: {:?}",
        transitive_span.diagnostics()
    );
    assert!(
        !transitive_text.contains("fn render"),
        "the span covers the declaration instead of the call: {transitive_text:?}"
    );
}

/// A declared effect contract must have unique members written in the canonical effect order,
/// because that declaration is the conservative summary that callers and implementations are
/// checked against (`GNT-6.12-static-traits`).
#[test]
fn public_declared_effect_contracts_require_unique_canonical_members() {
    let canonical = analyze(
        r#"trait Render { fn render(self) effects { prompt, action(read_only), background, session, attempt }; }
struct Item {}
impl Render for Item { fn render(self) { discard prompt "Generate." -> String; } }
fn main() {}"#,
    );
    assert_eq!(
        canonical.status(),
        AnalysisStatus::Valid,
        "{:?}",
        canonical.diagnostics()
    );

    let duplicated_source = r#"trait Render { fn render(self) effects { prompt, prompt }; }
fn main() {}"#;
    let duplicated = analyze(duplicated_source);
    assert_eq!(
        duplicated.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        duplicated.diagnostics()
    );
    let duplicates = duplicated
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "duplicate-effect-contract-member")
        .collect::<Vec<_>>();
    assert_eq!(duplicates.len(), 1, "{:?}", duplicated.diagnostics());
    assert!(
        duplicated
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_str() != "effect-contract-order"),
        "a repeated member is reported once: {:?}",
        duplicated.diagnostics()
    );
    let duplicate_span = duplicates[0]
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", duplicated.diagnostics()));
    let repeated_start = duplicated_source.rfind("prompt").unwrap_or_default();
    assert_eq!(
        usize::try_from(duplicate_span.bytes().start()).unwrap_or_default(),
        repeated_start
    );
    let repeated_end = usize::try_from(duplicate_span.bytes().end()).unwrap_or_default();
    assert_eq!(
        duplicated_source.get(repeated_start..repeated_end),
        Some("prompt"),
        "{:?}",
        duplicated.diagnostics()
    );
    assert!(duplicated.executable_program().is_none());

    let unordered_source = r#"trait Render { fn render(self) effects { session, join }; }
fn main() {}"#;
    let unordered = analyze(unordered_source);
    assert_eq!(
        unordered.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        unordered.diagnostics()
    );
    let orders = unordered
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "effect-contract-order")
        .collect::<Vec<_>>();
    assert_eq!(orders.len(), 1, "{:?}", unordered.diagnostics());
    let order_span = orders[0]
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", unordered.diagnostics()));
    let misplaced_start = unordered_source.rfind("join").unwrap_or_default();
    assert_eq!(
        usize::try_from(order_span.bytes().start()).unwrap_or_default(),
        misplaced_start
    );
    let misplaced_end = usize::try_from(order_span.bytes().end()).unwrap_or_default();
    assert_eq!(
        unordered_source.get(misplaced_start..misplaced_end),
        Some("join"),
        "{:?}",
        unordered.diagnostics()
    );
    assert!(unordered.executable_program().is_none());

    // Action recovery classes hold separate canonical positions, so a lower class after a higher
    // class is out of order even though both members name the `action` effect.
    let action_order = analyze(
        r#"trait Render { fn render(self) effects { action(idempotent), action(read_only) }; }
fn main() {}"#,
    );
    assert!(
        action_order
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "effect-contract-order"),
        "{:?}",
        action_order.diagnostics()
    );
}

/// A pattern payload that binds a `MustConsume` value owes consumption like any other binding
/// introduction, in `match` arms and in `if let` chains (D5).
#[test]
fn must_consume_pattern_payloads_acquire_obligations() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn make() -> Option<Token> { None }\n\
         fn make_result() -> Result<Token, Int> { Err(1) }\n";

    for source in [
        "fn main() -> Int { match make() { Some(token) => 1, None => 2 } }",
        "fn main() { if let Some(token) = make() { discard 1; } }",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "must-consume-unconsumed"),
            "{source}: {:?}",
            rejected.diagnostics()
        );
    }

    for source in [
        "fn main() -> Token { if let Some(token) = make() { return token; } Token { value: 1 } }",
        "fn main() -> Token { if let Ok(token) = make_result() { return token; } Token { value: 1 } }",
    ] {
        let accepted = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            accepted.diagnostics()
        );
    }
}

/// A guard clause that consumes on the early exit and again on the joining statement is accepted,
/// while the genuinely path-dependent shapes stay rejected (D6).
#[test]
fn must_consume_guard_clause_paths_are_accepted() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         fn main() {}\n";

    for source in [
        "fn run(token: Token, flag: Bool) -> Int { if flag { return token.consume(); } token.consume() }",
        "fn run(token: Token, flag: Bool) -> Token { if flag { return token; } token }",
    ] {
        let accepted = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            accepted.diagnostics()
        );
    }

    {
        let rejected = analyze(&format!(
            "{DECLARATIONS}fn run(token: Token, flag: Bool) -> Int {{ if flag {{ discard token.consume(); }} 0 }}"
        ));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code.as_str() == "must-consume-path-dependent" }),
            "{:?}",
            rejected.diagnostics()
        );
    }

    // A bounded `loop` still begins its body on every static path (`GNT-3-T-LOOP`), and its limit
    // is a dynamic failure rather than a static path (`GNT-9.5`), so the only violation its body
    // commits is the repeated transfer `GNT-6.2e` mandates.
    let bounded = analyze(&format!(
        "{DECLARATIONS}fn run(token: Token) {{ loop(limit = 1) {{ discard token.consume(); break; }} }}"
    ));
    assert_eq!(
        bounded.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        bounded.diagnostics()
    );
    assert_eq!(
        diagnostic_codes(bounded.diagnostics()),
        ["affine-value-reuse"],
        "{:?}",
        bounded.diagnostics()
    );
}

/// A statement `match` analyzes every arm as a command, so a value-returning body whose every
/// arm diverges has no reachable normal completion and needs no trailing result, while the
/// merged completion keeps each arm's loop transfer visible to the enclosing loop
/// (`GNT-3-T-BRANCH`, `GNT-3-T-SEQUENCE`, `GNT-3-T-COMPLETION`).
#[test]
fn statement_match_completion_merges_every_arm() {
    const DECLARATIONS: &str = "enum Flag { On, Off }\n\
         enum Box { Wrapped(Flag), Empty }\n\
         fn main() {}\n";

    for source in [
        "fn pick(flag: Flag) -> Int { match flag { Flag::On => { return 1; }, Flag::Off => { return 2; } } }",
        "fn pick(flag: Flag) -> Int { let mut result: Int = 0; match flag { Flag::On => { return 1; }, Flag::Off => { result = 2; } } result }",
        "fn run(flag: Flag) { match flag { Flag::On => { discard 1; }, Flag::Off => { discard 2; } } }",
        "fn pick(flag: Flag) -> Int { let mut x: Int = 0; loop { match flag { Flag::On => { break; }, Flag::Off => { continue; } } } x }",
        "fn pick(value: Box) -> Int { match value { Box::Wrapped(flag) => { match flag { Flag::On => { return 1; }, Flag::Off => { return 2; } } }, Box::Empty => { return 3; } } }",
    ] {
        let accepted = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            accepted.diagnostics()
        );
    }
}

/// A statement or trailing expression after a `match` with no reachable normal completion is
/// still an unreachable-source analysis error (`GNT-9.11`), not an operational failure.
#[test]
fn statements_after_a_diverging_match_remain_unreachable() {
    let rejected = analyze(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { match flag { Flag::On => { return 1; }, Flag::Off => { return 2; } } 9 }\n\
         fn main() {}",
    );
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        rejected.diagnostics()
    );
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "unreachable-source"),
        "{:?}",
        rejected.diagnostics()
    );
}

/// A value-producing `match` expression still infers its single arm result type.
#[test]
fn value_producing_match_still_infers_one_result_type() {
    let package = analyze(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { match flag { Flag::On => 1, Flag::Off => 2 } }\n\
         fn main() {}",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
}

/// A value-producing `match` arm is a value block and therefore requires a trailing value
/// (`GNT-3-F-CORE`); a diverging statement cannot stand in for one, and the restriction is
/// reported as a precise syntax diagnostic rather than an operational failure.
#[test]
fn value_match_arm_without_a_trailing_value_is_a_syntax_error() {
    let phase = syntax(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { match flag { Flag::On => { return 1; }, Flag::Off => { 2 } } }",
    );
    assert!(
        phase.diagnostics().iter().any(|diagnostic| {
            diagnostic.code.as_str() == "unexpected-token"
                && diagnostic.fields.get("expected").is_some_and(|expected| {
                    expected.as_ref() == "value-producing trailing expression"
                })
        }),
        "{:?}",
        phase.diagnostics()
    );
}

/// A loop whose only `break` sits in a fact-excluded branch never completes, so a
/// value-returning body needs no trailing result and lowering must not diverge
/// (`GNT-3-T-BRANCH`, `GNT-3-T-LOOP`, `GNT-3-T-COMPLETION`).
#[test]
fn loop_transfers_in_fact_excluded_branches_do_not_complete_the_loop() {
    for source in [
        "fn f() -> Int { loop { if false { break; } } } fn main() { discard f(); }",
        "fn f() -> Int { while true { if false { break; } } } fn main() { discard f(); }",
        "fn f() -> Int { loop { if true { continue; } else { break; } } } fn main() { discard f(); }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            package.diagnostics()
        );
    }
}

/// An `if` whose feasible branch returns needs no implicit result even when the
/// fact-excluded branch falls through (`GNT-3-T-BRANCH`, `GNT-3-T-COMPLETION`).
#[test]
fn fact_excluded_falling_through_branch_needs_no_result() {
    for source in [
        "fn f() -> Int { if false { } else { return 2; } } fn main() -> Int { f() }",
        "fn f() -> Int { if true { return 2; } else { } } fn main() -> Int { f() }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            package.diagnostics()
        );
    }
}

/// Every condition of an `else if` chain contributes to the completion verdict, so a
/// chain whose only completing path is the final `else` needs no trailing result
/// (`GNT-3-T-BRANCH`, `GNT-3-T-COMPLETION`).
#[test]
fn else_if_chain_completion_folds_every_condition() {
    let package = analyze(
        "fn f() -> Int { if false { } else if false { } else { return 3; } } fn main() -> Int { f() }",
    );
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
}

/// A value position — a call argument, constructor field, binding initializer, assignment
/// right-hand side, `return` operand, or `discard` operand — reads the place it names. That read
/// is the place's one admitted use and records the place under item 2e's containment rules, uses
/// linearize in the mandated source order so the later use is the reported one, and an assignment
/// destination is never a use and never clears a recorded place (`GNT-6.2h`).
#[test]
fn affine_value_positions_use_each_place_once() {
    const DECLARATIONS: &str = "affine struct Token { value: Int }\n\
         struct Pair { a: Token, b: Token }\n\
         fn pair(x: Token, y: Token) {}\n\
         fn mix(x: Int, y: Token) -> Int { 0 }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n";

    // Distinct places at distinct value positions are each read once.
    for accepted in [
        "fn drive(t: Token, u: Token) { pair(t, u); }\nfn main() { }",
        "fn drive(t: Token, u: Token) -> Pair { Pair { a: t, b: u } }\nfn main() { }",
        "fn drive(mut a: Token, b: Token) -> Token { a = b; a }\nfn main() { }",
        "fn drive(p: Pair) -> Token { let x: Token = p.a; p.b }\nfn main() { }",
        "fn drive(mut p: Pair, b: Token, c: Token) { let x: Token = p.a; p = Pair { a: b, b: c }; }\nfn main() { }",
        "fn drive(t: Token) { discard t; }\nfn main() { }",
        "fn pass(t: Token) -> Token { return t; }\nfn main() { }",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    // A second use of the same place at any value position is a reuse, and an assignment
    // destination neither uses the destination nor clears the place recorded for it.
    for rejected in [
        "fn drive(t: Token) { pair(t, t); }\nfn main() { }",
        "fn drive(t: Token) -> Pair { Pair { a: t, b: t } }\nfn main() { }",
        "fn drive(mut a: Token, b: Token) -> Token { let x: Token = a; a = b; a }\nfn main() { }",
        "fn drive(mut p: Pair, b: Token) -> Token { let x: Token = p.a; p.a = b; p.a }\nfn main() { }",
        "fn drive(p: Pair) -> Pair { let x: Token = p.a; p }\nfn main() { }",
        "fn drive(p: Pair) -> Token { let x: Pair = p; p.a }\nfn main() { }",
        "fn drive(t: Token) { discard t; discard t; }\nfn main() { }",
        "fn drive(t: Token) -> Token { discard t; return t; }\nfn main() { }",
    ] {
        assert_affine_rejected(&format!("{DECLARATIONS}{rejected}"), "affine-value-reuse");
    }

    // Uses linearize in source order: the earlier operand is admitted and the later one is the
    // reported reuse, including after the earlier `owned self` receiver admission of item 2b.
    assert_affine_rejected_at(
        &format!("{DECLARATIONS}fn drive(t: Token) {{ pair(t, t); }}\nfn main() {{ }}"),
        "affine-value-reuse",
        "t);",
    );
    assert_affine_rejected_at(
        &format!(
            "{DECLARATIONS}fn drive(t: Token) -> Int {{ mix(t.consume(), t) }}\nfn main() {{ }}"
        ),
        "affine-value-reuse",
        "t) }",
    );
    assert_affine_rejected_at(
        &format!(
            "{DECLARATIONS}fn drive(t: Token) -> Token {{ discard t; return t; }}\nfn main() {{ }}"
        ),
        "affine-value-reuse",
        "t; }",
    );
}

/// A spawned block captures the outer bindings it references, and item 10.3 captures them by
/// copy, so a value whose ownership class prohibits copying has no task-transfer contract: the
/// referencing expression is rejected instead of copied. A binding the block never references is
/// not a capture, so the parent keeps its own place, use record, and consumption obligation
/// (`GNT-6.2i`).
#[test]
fn spawned_block_captures_require_a_task_transfer_contract() {
    const DECLARATIONS: &str = "affine struct Token { value: Int }\n\
         must_consume struct Guard { value: Int }\n\
         struct Holder { token: Token }\n\
         impl Token { fn consume(owned self) -> Int { self.value } }\n\
         impl Guard { fn release(owned self) -> Int { self.value } }\n";

    // A copyable capture is an independent copy, and a binding the block never references is not a
    // capture at all, so the parent still reads or consumes its own place after the join.
    for accepted in [
        "fn main() -> Int { let shared: Int = 1; spawn child -> Int { shared } let seen: Int = join(child); discard seen; shared }",
        "fn main() -> Int { let token: Token = Token { value: 1 }; spawn child -> Int { 1 } let seen: Int = join(child); discard seen; discard token; 0 }",
        "fn main() -> Int { let guard: Guard = Guard { value: 1 }; spawn child -> Int { 1 } let seen: Int = join(child); discard seen; guard.release() }",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{accepted}"));
    }

    // Every reference to an outer owned binding is a capture: a projection read, an `owned self`
    // admission, a `return` of the value, a projection through a containing aggregate, and a
    // reference made by a nested spawned block.
    for rejected in [
        "fn main() -> Int { let token: Token = Token { value: 1 }; spawn child -> Int { token.value } let seen: Int = join(child); seen }",
        "fn main() -> Int { let token: Token = Token { value: 1 }; spawn child -> Int { token.consume() } let seen: Int = join(child); seen }",
        "fn main() -> Int { let token: Token = Token { value: 1 }; spawn child -> Token { token } let seen: Token = join(child); seen.consume() }",
        "fn main() -> Int { let guard: Guard = Guard { value: 1 }; spawn child -> Int { guard.release() } let seen: Int = join(child); seen }",
        "fn main() -> Int { let holder: Holder = Holder { token: Token { value: 1 } }; spawn child -> Int { holder.token.value } let seen: Int = join(child); seen }",
        "fn main() -> Int { let token: Token = Token { value: 1 }; spawn outer -> Int { spawn inner -> Int { token.value } let seen: Int = join(inner); seen } let seen: Int = join(outer); seen }",
    ] {
        assert_affine_rejected(
            &format!("{DECLARATIONS}{rejected}"),
            "task-capture-ineligible",
        );
    }

    // The report blames the referencing expression, not the spawn statement or the declaration.
    assert_affine_rejected_at(
        &format!(
            "{DECLARATIONS}fn main() -> Int {{ let token: Token = Token {{ value: 1 }}; spawn child -> Int {{ token.value }} let seen: Int = join(child); seen }}"
        ),
        "task-capture-ineligible",
        "token.value",
    );
    assert_affine_rejected_at(
        &format!(
            "{DECLARATIONS}fn main() -> Int {{ let guard: Guard = Guard {{ value: 1 }}; spawn child -> Int {{ guard.release() }} let seen: Int = join(child); seen }}"
        ),
        "task-capture-ineligible",
        "guard.release()",
    );
}

/// The task-transfer axis classifies ownership, not just copying: an `affine struct`, a
/// `must_consume struct`, and any aggregate storing one have no isolated task-capture contract,
/// so `is_task_capturable` is false and eligibility is `Ineligible`, while a copyable aggregate
/// stays capturable (`GNT-6.2i`).
#[test]
fn owned_classes_have_no_isolated_task_capture_contract() {
    use gantry::ir::{OwnershipClass, TransferEligibility, TypeDescriptor};
    use gantry::source::FrontendLimits;

    let package = analyze(
        "affine struct Token { value: Int }\n\
         must_consume struct Guard { value: Int }\n\
         struct Plain { value: Int }\n\
         struct Holder { token: Token }\n\
         fn main() { }",
    );
    let policy = FrontendLimits::new(
        4, 65_536, 65_536, 65_536, 64, 65_536, 65_536, 65_536, 65_536, 64, 64, 100,
    )
    .unwrap_or_else(|error| panic!("query policy failed: {error:?}"));
    for (name, ownership, capturable) in [
        ("crate::Token", OwnershipClass::AffineDroppable, false),
        ("crate::Guard", OwnershipClass::MustConsume, false),
        ("crate::Holder", OwnershipClass::AffineDroppable, false),
        ("crate::Plain", OwnershipClass::Copyable, true),
    ] {
        let ty = TypeDescriptor::from_canonical_string(name)
            .unwrap_or_else(|error| panic!("descriptor failed: {error:?}"));
        let properties = package
            .type_capabilities(&ty, policy)
            .unwrap_or_else(|error| panic!("query failed: {error:?}"));
        assert_eq!(properties.ownership_class(), ownership, "{name}");
        assert_eq!(properties.is_task_capturable(), capturable, "{name}");
        assert_eq!(
            properties.transfer_eligibility(),
            if capturable {
                TransferEligibility::IsolatedTaskCapture
            } else {
                TransferEligibility::Ineligible
            },
            "{name}"
        );
    }
}

/// A `MustConsume` `return` operand is a consumption transfer rather than a value-position read.
///
/// The transfer is admitted once on each path that leaves the callable, so exclusive branches MAY
/// each return the same place, and the operand MAY name a struct-field projection of the callable's
/// binding root. An `AffineDroppable` return operand stays the item 2h read, so returning the same
/// place twice, or reading it on one path and returning it on another, stays a reuse.
#[test]
fn must_consume_return_operand_is_a_consumption_transfer() {
    for source in [
        "must_consume struct Guard { v: Int }\nfn pass(g: Guard) -> Guard { return g; }\nfn main() -> Int { 0 }",
        "must_consume struct Guard { v: Int }\nfn pass(g: Guard, b: Bool) -> Guard {\n    if b { return g; }\n    return g;\n}\nfn main() -> Int { 0 }",
        "must_consume struct Guard { v: Int }\nstruct Holder { g: Guard, n: Int }\nfn take(h: Holder) -> Guard { return h.g; }\nfn main() -> Int { 0 }",
        "affine struct Token { v: Int }\nfn pass(t: Token) -> Token { return t; }\nfn main() -> Int { 0 }",
    ] {
        let package = analyze(source);
        assert_eq!(
            package.status(),
            AnalysisStatus::Valid,
            "{source}: {:?}",
            package.diagnostics()
        );
    }

    for (code, source) in [
        (
            "affine-value-reuse",
            "affine struct Token { v: Int }\nfn pass(t: Token, b: Bool) -> Token {\n    if b { return t; }\n    return t;\n}\nfn main() -> Int { 0 }",
        ),
        (
            "affine-value-reuse",
            "affine struct Token { v: Int }\nfn pass(t: Token, b: Bool) -> Token {\n    if b { discard t; }\n    return t;\n}\nfn main() -> Int { 0 }",
        ),
        (
            "affine-value-reuse",
            "affine struct Token { v: Int }\nstruct Wallet { t: Token, n: Int }\nfn pass(w: Wallet, b: Bool) -> Token {\n    if b { return w.t; }\n    return w.t;\n}\nfn main() -> Int { 0 }",
        ),
        (
            "must-consume-copy",
            "must_consume struct Guard { v: Int }\nfn pass(g: Guard) -> Int { let u: Guard = g; 0 }\nfn main() -> Int { 0 }",
        ),
        (
            "must-consume-discard",
            "must_consume struct Guard { v: Int }\nfn drop_it(g: Guard) -> Int { discard g; 0 }\nfn main() -> Int { 0 }",
        ),
        (
            "must-consume-copy",
            "must_consume struct Guard { v: Int }\nfn read_it(g: Guard) -> Int { g.v }\nfn main() -> Int { 0 }",
        ),
        (
            "must-consume-path-dependent",
            "must_consume struct Guard { v: Int }\nimpl Guard { fn consume(owned self) {} }\nfn maybe(g: Guard, b: Bool) -> Int {\n    if b { g.consume(); }\n    0\n}\nfn main() -> Int { 0 }",
        ),
    ] {
        let rejected = analyze(source);
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "{source}: {code}: {:?}",
            rejected.diagnostics()
        );
    }
}

/// Rejects `source` with `code` and requires the primary span to start at the single `marker`
/// occurrence, which pins the value position the report blames.
fn assert_affine_rejected_at(source: &str, code: &str, marker: &str) {
    assert_eq!(
        source.matches(marker).count(),
        1,
        "{source}: marker {marker:?} is not unique"
    );
    let expected = source
        .find(marker)
        .unwrap_or_else(|| panic!("{source}: missing marker {marker:?}"));
    let rejected = analyze(source);
    assert_eq!(
        rejected.status(),
        AnalysisStatus::Invalid,
        "{source}: {:?}",
        rejected.diagnostics()
    );
    let diagnostic = rejected
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == code)
        .unwrap_or_else(|| panic!("{source}: {:?}", rejected.diagnostics()));
    let primary = diagnostic
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("{source}: missing primary span"));
    assert_eq!(
        usize::try_from(primary.bytes().start()).unwrap_or_default(),
        expected,
        "{source}"
    );
}

/// A rebind of an already discharged whole-root `MustConsume` place re-initializes that root, so
/// a loop body that may not execute leaves a fresh value owed after the loop (defect 2be81c0f).
#[test]
fn public_skippable_loop_reinitialization_owes_the_fresh_value() {
    const DECLARATIONS: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n";

    const AGGREGATE: &str = "must_consume struct Token { value: Int }\n\
         impl Token { fn consume(owned self) {} }\n\
         struct Holder { token: Token, marker: Int }\n\
         impl Holder { fn consume(owned self) {} }\n";

    const NESTED: &str = "must_consume struct Inner { value: Int }\n\
         impl Inner { fn consume(owned self) {} }\n\
         must_consume struct Outer { inner: Inner }\n\
         impl Outer { fn consume(owned self) {} }\n";

    for source in [
        "fn run(mut token: Token, flag: Bool) { token.consume(); while flag { token = Token { value: 1 }; break; } } fn main() {}",
        "fn run(mut token: Token, items: List<Int>) { token.consume(); for item in items { discard item; token = Token { value: 1 }; break; } } fn main() {}",
        "fn run(mut token: Token, flag: Bool, other: Bool) { token.consume(); while flag { if other { token = Token { value: 1 }; } break; } } fn main() {}",
        "fn run(mut token: Token, flag: Bool) { token.consume(); while flag { token = Token { value: 1 }; continue; } } fn main() {}",
        "fn run(mut token: Token, flag: Bool) { token.consume(); while flag { token = Token { value: 1 }; } } fn main() {}",
    ] {
        let rejected = analyze(&format!("{DECLARATIONS}{source}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "{source}: {:?}",
            rejected.diagnostics()
        );
        assert_eq!(
            diagnostic_codes(rejected.diagnostics()),
            ["must-consume-path-dependent"],
            "{source}"
        );
    }

    // The same rebind outside a loop, and one inside a loop whose body always executes, still owe
    // the fresh value to the callable exit instead of to a loop re-initialization report.
    for source in [
        "fn run(mut token: Token) { token.consume(); token = Token { value: 1 }; } fn main() {}",
        "fn run(mut token: Token) { token.consume(); loop { token = Token { value: 1 }; break; } } fn main() {}",
    ] {
        assert_affine_rejected(
            &format!("{DECLARATIONS}{source}"),
            "must-consume-unconsumed",
        );
    }

    let conditional = "fn run(mut token: Token, flag: Bool) { token.consume(); if flag { token = Token { value: 1 }; } token.consume(); } fn main() {}";
    assert_affine_rejected(
        &format!("{DECLARATIONS}{conditional}"),
        "affine-value-reuse",
    );

    // A decomposed root marks each obligation place separately: a loop body that may not execute
    // leaves the fresh place owed, consuming the fresh place clears only its own mark, and
    // consuming the whole root afterwards stays a repeated use of the fresh value.
    assert_affine_rejected(
        &format!(
            "{AGGREGATE}fn run(mut h: Holder, flag: Bool) {{ h.token.consume(); while flag {{ h = Holder {{ token: Token {{ value: 1 }}, marker: 0 }}; break; }} }} fn main() {{}}"
        ),
        "must-consume-path-dependent",
    );
    assert_affine_accepted(&format!(
        "{AGGREGATE}fn run(mut h: Holder) {{ h.token.consume(); h = Holder {{ token: Token {{ value: 1 }}, marker: 0 }}; h.token.consume(); }} fn main() {{}}"
    ));
    assert_affine_rejected(
        &format!(
            "{AGGREGATE}fn run(mut h: Holder) {{ h.token.consume(); h = Holder {{ token: Token {{ value: 1 }}, marker: 0 }}; h.token.consume(); h.consume(); }} fn main() {{}}"
        ),
        "affine-value-reuse",
    );

    // A declared aggregate stays one atomic obligation, so a descendant discharge makes the
    // whole-root re-initialization mark stale: using the root afterwards is a repeated use, while
    // consuming the fresh root itself stays valid and leaving it alone stays unconsumed.
    assert_affine_rejected(
        &format!(
            "{NESTED}fn run(mut o: Outer) {{ o.consume(); o = Outer {{ inner: Inner {{ value: 1 }} }}; o.inner.consume(); o.consume(); }} fn main() {{}}"
        ),
        "affine-value-reuse",
    );
    assert_affine_accepted(&format!(
        "{NESTED}fn run(mut o: Outer) {{ o.consume(); o = Outer {{ inner: Inner {{ value: 1 }} }}; o.consume(); }} fn main() {{}}"
    ));
    assert_affine_rejected(
        &format!(
            "{NESTED}fn run(mut o: Outer) {{ o.consume(); o = Outer {{ inner: Inner {{ value: 1 }} }}; }} fn main() {{}}"
        ),
        "must-consume-unconsumed",
    );

    for source in [
        "fn run(mut token: Token, flag: Bool) { token.consume(); while flag { } } fn main() {}",
        "fn run(flag: Bool) { while flag { let u: Token = Token { value: 1 }; u.consume(); } } fn main() {}",
    ] {
        assert_affine_accepted(&format!("{DECLARATIONS}{source}"));
    }
}

/// A callable annotation in a signature position is admitted and resolves to the canonical
/// callable type of its reuse kind, ordered parameter types, and result type (`GNT-37.1`).
#[test]
fn public_callable_type_annotations_are_admitted_in_signatures() {
    use gantry::ir::{CallableKind, TypeDescriptor};

    let root = TempDirectory::new();
    for source in [
        "fn apply(callback: Fn(Int) -> Int) -> Int { 0 } fn main() {}",
        "fn apply(callback: FnMut() -> Int, marker: Bool) -> Int { 0 } fn main() {}",
        "fn apply(callback: FnOnce(Int, String) -> Bool) -> Int { 0 } fn main() {}",
        "struct Item {} impl Item { fn apply(self, callback: Fn(Int) -> Int) -> Int { 0 } } fn main() {}",
        "trait Render { pure fn render(self, cb: Fn(Int) -> Int) -> Int; } fn main() {}",
        "trait Render { pure fn render(self) -> Fn(Int) -> Int; } fn main() {}",
        "trait Render { pure fn render(self, cb: Fn(Int) -> Int) -> Int; } struct Item {} impl Render for Item { pure fn render(self, cb: Fn(Int) -> Int) -> Int { 0 } } fn main() {}",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("source: {source}; type analysis failed: {error:?}"));
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        assert!(
            admitted.executable_program().is_some(),
            "source: {source}; an admitted signature annotation must publish a program"
        );
    }

    // The admitted annotation resolves to the canonical callable type of its shape, and the
    // published executable program carries that descriptor as the parameter it names.
    root.write("fn apply(callback: Fn(Int) -> Int) -> Int { 0 } fn main() {}");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let admitted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        admitted.diagnostics()
    );
    let expected = TypeDescriptor::callable(
        CallableKind::Function,
        vec![TypeDescriptor::INT],
        TypeDescriptor::INT,
    );
    assert_eq!(expected.canonical_string(), "Callable<Fn,Int,Int>");
    assert!(
        admitted
            .types()
            .iter()
            .any(|fact| fact.descriptor == expected),
        "the admitted annotation did not resolve to its canonical callable type: {:?}",
        admitted.types()
    );
    // A callable value cannot be constructed or called by this revision, so no workflow that
    // would need a callable frame value is lowered into the published program.
    let Some(program) = admitted.executable_program() else {
        panic!("a source-valid package publishes a typed program");
    };
    assert_eq!(
        program
            .workflows()
            .iter()
            .map(|workflow| workflow.path.as_str())
            .collect::<Vec<_>>(),
        ["crate::main"],
        "an admitted callable type must not publish a runtime frame value: {:?}",
        program.workflows()
    );
}

/// A `let` binding whose annotation is a callable type holds one declared callable as a
/// statically resolved alias: the initializer is admitted there, an invocation through the
/// binding lowers to the direct call it names (`GNT-37.0`, `GNT-37.10`), and every other
/// value position keeps its own precise refusal.
#[test]
fn public_callable_binding_aliases_are_typed_and_invoked() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("a callable alias invocation did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected) in [
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; g(41) }",
            42i64,
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; let h: Fn(Int) -> Int = g; h(1) }",
            2,
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; g(41) + 1 }",
            43,
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; let h: Fn(Int) -> Int = inc; g(1) + h(2) }",
            5,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted alias must publish a program")
        });
        let kinds = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .map(|instruction| &instruction.kind)
            .collect::<Vec<_>>();
        // The alias is statically resolved rather than materialized: no workflow binds the
        // alias name, and the invocation publishes the direct call it names.
        assert!(
            !kinds
                .iter()
                .any(|kind| matches!(kind, InstructionKind::Bind { name, .. } if name.as_ref() == "g" || name.as_ref() == "h")),
            "source: {source}: a callable binding must hold no runtime value"
        );
        assert!(
            kinds
                .iter()
                .any(|kind| matches!(kind, InstructionKind::Call { .. })),
            "source: {source}: the invocation must lower to a direct call"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x43; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }

    // The admitted binding annotation narrows the reference refusal rather than removing it:
    // a mismatched initializer, a grouped reference, another value position, and a bad call
    // keep their own precise refusal.
    for (source, code, identifier) in [
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = 0; 0 }",
            "type-mismatch",
            None,
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: FnMut(Int) -> Int = inc; 0 }",
            "type-mismatch",
            None,
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { discard inc; 0 }",
            "callable-reference-unadmitted",
            Some("inc"),
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = (inc); 0 }",
            "callable-reference-unadmitted",
            Some("inc"),
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; discard g; 0 }",
            "callable-reference-unadmitted",
            Some("g"),
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn consume(value: Fn(Int) -> Int) -> Int { 0 } fn main() -> Int { let g: Fn(Int) -> Int = inc; consume(g) }",
            "callable-reference-unadmitted",
            Some("g"),
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn give() -> Fn(Int) -> Int { inc } fn main() -> Int { 0 }",
            "callable-reference-unadmitted",
            Some("inc"),
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; g(1, 2) }",
            "call-arity",
            None,
        ),
        (
            "fn inc(value: Int) -> Int { value + 1 } fn main() -> Int { let g: Fn(Int) -> Int = inc; g(true) }",
            "call-argument-type",
            None,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refused
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == code)
            .unwrap_or_else(|| {
                panic!(
                    "source: {source}: expected {code}; diagnostics: {:?}",
                    refused.diagnostics()
                )
            });
        if let Some(identifier) = identifier {
            assert_eq!(
                refusal.fields.get("identifier").map(AsRef::as_ref),
                Some(identifier),
                "source: {source}"
            );
        }
    }

    // A callable-typed parameter is still forwarded as a call argument, and the admitted
    // binding form changes nothing about that shape.
    root.write("fn consume(value: Fn(Int) -> Int) -> Int { 0 } fn forward(callback: Fn(Int) -> Int) -> Int { discard consume(callback); 0 } fn main() -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let admitted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        admitted.diagnostics()
    );
}

/// A callable annotation outside a signature position, and a signature annotation whose
/// parameter or result position does not name a closed type, are refused with the published
/// occurrence class of their position instead of failing internally.
#[test]
fn public_callable_type_annotations_outside_signatures_are_refused_with_their_class() {
    let root = TempDirectory::new();
    for (source, reuse_kind, occurrence) in [
        (
            "fn main(callback: Fn(Int) -> Int) -> Int { 0 }",
            "Fn",
            "boundary-position",
        ),
        (
            "fn main(callback: FnMut() -> Int) -> Int { 0 }",
            "FnMut",
            "boundary-position",
        ),
        (
            "fn main(callback: FnOnce(Int, String) -> Bool) -> Int { 0 }",
            "FnOnce",
            "boundary-position",
        ),
        (
            "struct Holder { callback: Fn(Int) -> Int } fn main() -> Int { 0 }",
            "Fn",
            "non-signature",
        ),
        (
            "struct Holder { callback: Fn(Int) -> Int } action read_only lookup(h: Holder) -> String; fn main() -> Int { 0 }",
            "Fn",
            "non-signature",
        ),
        (
            "fn main(callback: List<Fn(Int) -> Int>) -> Int { 0 }",
            "Fn",
            "nested-component",
        ),
        (
            "fn hold<T>(callback: Fn(T) -> T) -> Int { 0 } fn main() -> Int { 0 }",
            "Fn",
            "open-member",
        ),
        (
            "fn main() -> Fn(Int) -> Int { 0 }",
            "Fn",
            "boundary-position",
        ),
        (
            "action read_only lookup(callback: Fn(Int) -> Int) -> String; fn main() -> Int { 0 }",
            "Fn",
            "boundary-position",
        ),
        (
            "trait Callable { pure fn call(self) -> Int; } impl Callable for Fn(Int) -> Int { pure fn call(self) -> Int { 0 } } fn main() -> Int { 0 }",
            "Fn",
            "non-signature",
        ),
        (
            "fn main() -> Int { discard fn(x: Fn(Int) -> Int) -> Int { x }; 0 }",
            "Fn",
            "non-signature",
        ),
        (
            "struct Box2<T> { value: T } impl Box2<Fn(Int) -> Int> { fn get(self) -> Int { 0 } } fn main() -> Int { 0 }",
            "Fn",
            "nested-component",
        ),
        (
            "trait Callable { pure fn call(self) -> Int; } impl Callable for Option<Fn(Int) -> Int> { pure fn call(self) -> Int { 0 } } fn main() -> Int { 0 }",
            "Fn",
            "nested-component",
        ),
        (
            "struct Box2<T> { value: T } impl Box2<Option<Fn(Int) -> Int>> { fn get(self) -> Int { 0 } } fn main() -> Int { 0 }",
            "Fn",
            "nested-component",
        ),
        (
            "trait Holder<T> { pure fn get(self) -> Int; } struct Item {} impl Holder<Fn(Int) -> Int> for Item { pure fn get(self) -> Int { 0 } } fn main() -> Int { 0 }",
            "Fn",
            "nested-component",
        ),
        (
            "trait Holder<T> { pure fn get(self) -> Int; } fn hold<T>(value: T) -> Int where T: Holder<Fn(Int) -> Int> { 0 } fn main() -> Int { 0 }",
            "Fn",
            "nested-component",
        ),
        (
            "fn id<T>(value: T) -> T { value } fn main() -> Int { discard id::<Fn(Int) -> Int>(0); 0 }",
            "Fn",
            "nested-component",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let rejected = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("source: {source}; type analysis failed: {error:?}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected.executable_program().is_none(),
            "source: {source}; an unadmitted callable type must not publish an executable program"
        );
        let refusal = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted")
            .unwrap_or_else(|| {
                panic!(
                    "source: {source}; diagnostics: {:?}",
                    rejected.diagnostics()
                )
            });
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("reuse_kind").map(AsRef::as_ref),
            Some(reuse_kind),
            "source: {source}; fields: {:?}",
            refusal.fields
        );
        assert_eq!(
            refusal.fields.get("occurrence").map(AsRef::as_ref),
            Some(occurrence),
            "source: {source}; fields: {:?}",
            refusal.fields
        );
    }
    // A callable annotation in an implementation signature is admitted even when its shape
    // departs from the declared trait contract, so the refusal that follows is the
    // trait-contract diagnostic instead of the callable admission refusal.
    root.write(
        "trait Render { pure fn render(self, cb: Int) -> Int; } struct Item {} impl Render for Item { pure fn render(self, cb: Fn(Int) -> Int) -> Int { 0 } } fn main() -> Int { 0 }",
    );
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let mismatched = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
    assert_eq!(mismatched.status(), AnalysisStatus::Invalid);
    assert!(
        !mismatched
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted"),
        "{:?}",
        mismatched.diagnostics()
    );
    // A declared type whose name precedes no parameter list keeps its meaning.
    root.write("struct Fn { value: Int } fn main(callback: Fn) -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let accepted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
}

/// A callable-typed value that reaches a generic call, a capability proof, or one method call
/// resolution is refused with a published diagnostic instead of failing internally.
#[test]
fn public_callable_typed_values_never_fail_internally_when_they_reach_resolution() {
    let root = TempDirectory::new();
    for (source, code) in [
        (
            "fn inner<T>(value: T) -> T { value } fn apply(callback: Fn(Int) -> Int) -> Int { discard inner(callback); 0 } fn main() -> Int { 0 }",
            "callable-type-unadmitted",
        ),
        (
            "fn inner<T>(value: T) -> T { value } fn apply(callback: Fn(Int) -> Int) -> Fn(Int) -> Int { inner(callback) } fn main() -> Int { 0 }",
            "callable-type-unadmitted",
        ),
        (
            "fn same(callback: Fn(Int) -> Int) -> Bool { callback == callback } fn main() -> Int { 0 }",
            "invalid-primitive",
        ),
        (
            "trait Render { pure fn render(self) -> Int; } struct Item {} impl Render for Item { pure fn render(self) -> Int { 0 } } fn probe(callback: Fn(Int) -> Int) -> Int { discard callback.render(); 0 } fn main() -> Int { 0 }",
            "missing-implementation",
        ),
        (
            // A generic method call refuses the same value with the same published class
            // the free-call path uses, so both call shapes agree about an admitted value.
            "struct Item {} impl Item { fn inner<T>(self, value: T) -> T { value } } fn apply(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.inner(callback); 0 } fn main() -> Int { 0 }",
            "callable-type-unadmitted",
        ),
        (
            // A generic trait method reaches the same refusal rather than reporting a
            // substitution that did not complete.
            "trait Render { pure fn inner<T>(self, value: T) -> T; } struct Item {} impl Render for Item { fn inner<T>(self, value: T) -> T { value } } fn apply(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.inner(callback); 0 } fn main() -> Int { 0 }",
            "callable-type-unadmitted",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(refused.executable_program().is_none(), "source: {source}");
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
    }

    // Every call shape reports the published class at the argument that carries the callable
    // type, so no shape reports a member or a substitution for a call the template grammar
    // cannot instantiate (`GNT-37.0`).
    for source in [
        "fn inner<T>(value: T) -> T { value } fn apply(callback: Fn(Int) -> Int) -> Int { discard inner(callback); 0 } fn main() -> Int { 0 }",
        "struct Item {} impl Item { fn inner<T>(self, value: T) -> T { value } } fn apply(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.inner(callback); 0 } fn main() -> Int { 0 }",
        "trait Render { pure fn inner<T>(self, value: T) -> T; } struct Item {} impl Render for Item { fn inner<T>(self, value: T) -> T { value } } fn apply(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.inner(callback); 0 } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}"
        );
        assert_eq!(
            refused
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted")
                .count(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refused
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted")
            .unwrap_or_else(|| panic!("source: {source}; {:?}", refused.diagnostics()));
        assert_eq!(
            refusal.fields.get("occurrence").map(AsRef::as_ref),
            Some("instantiation-argument"),
            "source: {source}"
        );
        assert_eq!(
            refusal.fields.get("reuse_kind").map(AsRef::as_ref),
            Some("Fn"),
            "source: {source}"
        );
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        let call_start = source
            .find("inner(callback)")
            .unwrap_or_else(|| panic!("source: {source}: missing call"))
            as u64;
        let argument_start = call_start + "inner(".len() as u64;
        assert_eq!(primary.bytes().start(), argument_start, "source: {source}");
        assert_eq!(
            primary.bytes().end(),
            argument_start + "callback".len() as u64,
            "source: {source}"
        );
    }

    // The instantiation-argument refusal reports its published class and reuse kind, and an
    // ordinary instantiation argument stays admitted, so the refusal is specific to callables.
    root.write("fn inner<T>(value: T) -> T { value } fn apply(callback: Fn(Int) -> Int) -> Int { discard inner(callback); 0 } fn main() -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    let refusal = refused
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted")
        .unwrap_or_else(|| panic!("{:?}", refused.diagnostics()));
    assert_eq!(
        refusal.fields.get("occurrence").map(AsRef::as_ref),
        Some("instantiation-argument")
    );
    assert_eq!(
        refusal.fields.get("reuse_kind").map(AsRef::as_ref),
        Some("Fn")
    );
    root.write("fn inner<T>(value: T) -> T { value } fn apply(marker: Int) -> Int { discard inner(marker); 0 } fn main() -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let admitted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        admitted.diagnostics()
    );
}

/// A callable-typed parameter that a declaration admits accepts an admitted callable value,
/// while a concrete parameter position keeps its own mismatch diagnostic, so the
/// instantiation-argument refusal stays reserved for generic instantiation arguments.
#[test]
fn public_declared_callable_parameters_accept_values_without_widening_the_refusal() {
    let root = TempDirectory::new();
    for source in [
        // A non-generic free function and inherent method declare callable parameters.
        "fn run(callback: Fn(Int) -> Int) -> Int { 0 } fn outer(callback: Fn(Int) -> Int) -> Int { run(callback) } fn main() -> Int { 0 }",
        "struct Item {} impl Item { fn run(self, callback: Fn(Int) -> Int) -> Int { 0 } } fn outer(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; item.run(callback) } fn main() -> Int { 0 }",
        // A generic method with an ordinary argument stays admitted.
        "struct Item {} impl Item { fn inner<T>(self, value: T) -> T { value } } fn apply() -> Int { let item: Item = Item {}; discard item.inner(1); 0 } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }

    // A concrete parameter position reports its own mismatch instead of the callable refusal.
    // A callable argument at a concrete parameter position is compared with that parameter
    // type directly, so it keeps its own mismatch diagnostic instead of the refusal, in every
    // call shape.
    for source in [
        "struct Item {} impl Item { fn inner(self, value: Int) -> Int { value } } fn apply(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.inner(callback); 0 } fn main() -> Int { 0 }",
        "trait Runner { pure fn run(self, value: Int) -> Int; } struct Item {} impl Runner for Item { fn run(self, value: Int) -> Int { value } } fn apply(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.run(callback); 0 } fn main() -> Int { 0 }",
        "struct Item {} impl Item { fn apply2<U>(self, value: Int, other: U) -> U { other } } fn outer(callback: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.apply2(callback, 1); 0 } fn main() -> Int { 0 }",
        "fn apply2<U>(value: Int, other: U) -> U { other } fn outer(callback: Fn(Int) -> Int) -> Int { discard apply2(callback, 1); 0 } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "call-argument-type"),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            !refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted"),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
    }

    // When one call carries a callable at a concrete position and another at a type-argument
    // position, the refusal names the type-argument argument and nothing else.
    let mixed = "struct Item {} impl Item { fn apply2<U>(self, first: Int, second: U) -> U { second } } fn outer(one: Fn(Int) -> Int, two: Fn(Int) -> Int) -> Int { let item: Item = Item {}; discard item.apply2(one, two); 0 } fn main() -> Int { 0 }";
    root.write(mixed);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(refused.status(), AnalysisStatus::Invalid);
    assert_eq!(
        refused.diagnostics().len(),
        1,
        "{:?}",
        refused.diagnostics()
    );
    let refusal = &refused.diagnostics()[0];
    assert_eq!(refusal.code.as_str(), "callable-type-unadmitted");
    assert_eq!(
        refusal.fields.get("occurrence").map(AsRef::as_ref),
        Some("instantiation-argument")
    );
    let primary = refusal
        .primary
        .as_ref()
        .unwrap_or_else(|| panic!("missing primary span"));
    let call_start = mixed
        .find("apply2(one, two)")
        .unwrap_or_else(|| panic!("missing call")) as u64;
    let argument_start = call_start + "apply2(one, ".len() as u64;
    assert_eq!(primary.bytes().start(), argument_start);
    assert_eq!(primary.bytes().end(), argument_start + "two".len() as u64);
}

/// A callable type that is itself a component of another callable form reports the nested
/// class, so admitting a signature annotation cannot silently admit the types it composes.
#[test]
fn public_callable_components_inside_callable_forms_report_nested_components() {
    let root = TempDirectory::new();
    root.write("fn main(callback: Fn(Fn(Int) -> Int) -> Int) -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let rejected = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(rejected.status(), AnalysisStatus::Invalid);
    assert!(
        rejected.executable_program().is_none(),
        "an unadmitted callable type must not publish an executable program"
    );
    let mut occurrences = rejected
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code.as_str() == "callable-type-unadmitted")
        .map(|diagnostic| {
            diagnostic
                .fields
                .get("occurrence")
                .map(AsRef::as_ref)
                .unwrap_or("?")
                .to_string()
        })
        .collect::<Vec<_>>();
    occurrences.sort_unstable();
    assert_eq!(occurrences, ["boundary-position", "nested-component"]);
}

/// A call through a callable-typed binding is refused with the published invocation
/// refusal instead of the sequence being typed as its own callee, while declaring,
/// passing, and holding a callable value stays admitted.
#[test]
fn public_callable_values_are_not_invocable_until_an_invocation_form_is_admitted() {
    let root = TempDirectory::new();
    for (source, reuse_kind) in [
        (
            "fn apply(callback: Fn(Int) -> Int, value: Int) -> Int { callback(value) } fn main() -> Int { 0 }",
            "Fn",
        ),
        (
            "fn apply(callback: FnMut() -> Int) -> Int { callback() } fn main() -> Int { 0 }",
            "FnMut",
        ),
        (
            "fn apply(callback: FnOnce(Int) -> Int, value: Int) -> Int { callback(value) } fn main() -> Int { 0 }",
            "FnOnce",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics().len(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = &refused.diagnostics()[0];
        assert_eq!(refusal.code.as_str(), "callable-invocation-unadmitted");
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("reuse_kind").map(AsRef::as_ref),
            Some(reuse_kind),
            "source: {source}"
        );
        let call_start = source
            .find("callback(")
            .unwrap_or_else(|| panic!("source: {source}: missing call"))
            as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert!(
            primary.bytes().start() >= call_start,
            "source: {source}: refusal precedes the call site"
        );
    }

    // A parenthesized callee is peeled before the binding lookup, so a grouped call is
    // refused by the same rule instead of being mistyped as its own callee.
    for source in [
        "fn apply(callback: Fn(Int) -> Int) -> Int { discard (callback)(1); 0 } fn main() -> Int { 0 }",
        "fn apply(callback: Fn(Int) -> Int, value: Bool) -> Int { (callback)(value) } fn main() -> Int { 0 }",
        "fn apply(callback: Fn(Int) -> Int) -> Int { (callback)(1) } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics().len(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = &refused.diagnostics()[0];
        assert_eq!(refusal.code.as_str(), "callable-invocation-unadmitted");
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("reuse_kind").map(AsRef::as_ref),
            Some("Fn"),
            "source: {source}"
        );
        let call_start = source
            .find("(callback)")
            .unwrap_or_else(|| panic!("source: {source}: missing call"))
            as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), call_start, "source: {source}");
    }

    // An explicit type-argument tail between the group and its argument list is still an
    // invocation, so the turbofish spelling is refused with the same rule and span.
    for (source, call) in [
        (
            "fn apply(callback: Fn(Int) -> Int) -> Int { discard (callback)::<Int>(1); 0 } fn main() -> Int { 0 }",
            "(callback)::<Int>(1)",
        ),
        (
            "fn apply(callback: Fn(Int) -> Int) -> Int { ((callback))::<Int>(1) } fn main() -> Int { 0 }",
            "((callback))::<Int>(1)",
        ),
        (
            "fn apply(callback: Fn(Int) -> Int) -> Fn(Int) -> Int { (callback)::<Int>(1) } fn main() -> Int { 0 }",
            "(callback)::<Int>(1)",
        ),
        // A plain callee with an arrow-bearing turbofish tail: the type argument contains
        // parentheses, so the refusal must still cover the whole call sequence.
        (
            "fn apply(callback: Fn(Int) -> Int) -> Int { discard callback::<Fn(Int) -> Int>(1); 0 } fn main() -> Int { 0 }",
            "callback::<Fn(Int) -> Int>(1)",
        ),
        (
            "fn apply(callback: Fn(Int) -> Int, value: Int) -> Int { discard callback::<Fn(Int) -> Int>(value); 0 } fn main() -> Int { 0 }",
            "callback::<Fn(Int) -> Int>(value)",
        ),
        // A plain turbofish tail without parentheses inside the argument stays exact.
        (
            "fn apply(callback: Fn(Int) -> Int) -> Int { discard callback::<Int>(1); 0 } fn main() -> Int { 0 }",
            "callback::<Int>(1)",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code.as_str() == "callable-invocation-unadmitted")
                .count(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refused
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "callable-invocation-unadmitted")
            .unwrap_or_else(|| panic!("source: {source}; {:?}", refused.diagnostics()));
        assert_eq!(
            refusal.fields.get("reuse_kind").map(AsRef::as_ref),
            Some("Fn"),
            "source: {source}"
        );
        let call_start = source
            .find(call)
            .unwrap_or_else(|| panic!("source: {source}: missing call"))
            as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), call_start, "source: {source}");
        assert_eq!(
            primary.bytes().end(),
            call_start + call.len() as u64,
            "source: {source}"
        );
    }

    // A grouped call is typed as the callee's declared result instead of as the callee, so
    // holding it in a callable position is a genuine mismatch rather than a silent
    // admission of the call.
    let grouped = "fn apply(callback: Fn(Int) -> Int) -> Fn(Int) -> Int { (callback)(1) } fn main() -> Int { 0 }";
    root.write(grouped);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(refused.status(), AnalysisStatus::Invalid);
    assert_eq!(
        refused
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "callable-invocation-unadmitted")
            .count(),
        1,
        "{:?}",
        refused.diagnostics()
    );
    let mismatch = refused
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "type-mismatch")
        .unwrap_or_else(|| panic!("{:?}", refused.diagnostics()));
    assert_eq!(
        mismatch.fields.get("actual").map(AsRef::as_ref),
        Some("Int")
    );

    // A group consumed by a binary expression is not an invocation either, so the refusal
    // stays reserved for a group that an argument list follows.
    root.write(
        "fn apply(callback: Fn(Int) -> Int) -> Int { discard (callback) + (1); 0 } fn main() -> Int { 0 }",
    );
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let grouped = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(
        grouped.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        grouped.diagnostics()
    );
    assert_eq!(
        grouped.diagnostics().len(),
        1,
        "{:?}",
        grouped.diagnostics()
    );
    assert_eq!(grouped.diagnostics()[0].code.as_str(), "invalid-primitive");

    // Declaring, passing, and holding a callable value stays admitted: only the call
    // through a callable-typed binding is refused.
    for source in [
        "fn apply(callback: Fn(Int) -> Int, value: Int) -> Int { value } fn main() -> Int { 0 }",
        "fn consume(value: Fn(Int) -> Int) -> Int { 0 } fn forward(callback: Fn(Int) -> Int) -> Int { discard consume(callback); 0 } fn main() -> Int { 0 }",
        "fn apply(callback: Fn(Int) -> Int) -> Int { discard (callback); 0 } fn main() -> Int { 0 }",
        "fn apply(callback: Fn(Int) -> Int) -> Fn(Int) -> Int { (callback) } fn main() -> Int { 0 }",
        "fn consume(value: Fn(Int) -> Int) -> Int { 0 } fn apply(callback: Fn(Int) -> Int) -> Int { discard consume((callback)); 0 } fn main() -> Int { 0 }",
        "fn apply(callback: Fn(Int) -> Int) -> Int { discard ((callback)); 0 } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }
}

/// A call whose callee names a binding whose type is not callable has no derivation in
/// `GNT-3-T-CALL`, so it is refused at the call instead of the sequence being typed as
/// its callee with its arguments left unchecked.
#[test]
fn public_non_callable_callees_are_refused_instead_of_being_typed_as_their_callee() {
    let root = TempDirectory::new();
    for (source, call, callee_type) in [
        (
            "fn f(value: Int) -> Int { value(2) } fn main() -> Int { f(3) }",
            "value(2)",
            "Int",
        ),
        (
            "fn f(value: Int) -> Int { value(2) } fn main() -> Int { discard f; 0 }",
            "value(2)",
            "Int",
        ),
        (
            "fn f(value: Int) -> Int { (value)(2) } fn main() -> Int { f(3) }",
            "(value)(2)",
            "Int",
        ),
        (
            "fn main() -> Int { let flag: Bool = true; discard flag(2); 0 }",
            "flag(2)",
            "Bool",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused call must not publish an executable program"
        );
        let refusals = refused
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "invalid-call-target")
            .collect::<Vec<_>>();
        assert_eq!(
            refusals.len(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refusals[0];
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("callee_type").map(AsRef::as_ref),
            Some(callee_type),
            "source: {source}"
        );
        let call_start = source
            .find(call)
            .unwrap_or_else(|| panic!("source: {source}: missing call"))
            as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), call_start, "source: {source}");
        assert_eq!(
            primary.bytes().end(),
            call_start + call.len() as u64,
            "source: {source}"
        );
    }

    // A member path keeps its own member resolution, so only a bare binding callee is
    // refused by the call rule.
    root.write(
        "struct Item {} fn main() -> Int { let item: Item = Item {}; discard item.unknown(2); 0 }",
    );
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let member = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(member.status(), AnalysisStatus::Invalid);
    assert!(
        member
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "unknown-member"),
        "{:?}",
        member.diagnostics()
    );
    assert!(
        member
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_str() != "invalid-call-target"),
        "{:?}",
        member.diagnostics()
    );

    // A declared callable callee stays an ordinary admitted call, and a callable-typed
    // binding keeps the published invocation refusal, so this rule neither rejects a
    // declared call nor preempts `GNT-37.10`.
    root.write("fn f(value: Int) -> Int { value } fn main() -> Int { f(3) }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let declared = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(
        declared.status(),
        AnalysisStatus::Valid,
        "{:?}",
        declared.diagnostics()
    );
    root.write(
        "fn apply(callback: Fn(Int) -> Int, value: Int) -> Int { discard callback(value); 0 } fn main() -> Int { 0 }",
    );
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let callable = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(callable.status(), AnalysisStatus::Invalid);
    assert!(
        callable
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "callable-invocation-unadmitted"),
        "{:?}",
        callable.diagnostics()
    );
    assert!(
        callable
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_str() != "invalid-call-target"),
        "{:?}",
        callable.diagnostics()
    );
}

/// A name that denotes a declared callable is not a value: this revision admits no source
/// callable value (`GNT-37.0`), so the name is refused with its published spelling in
/// every position that requires one, including the qualified spelling, a grouped operand,
/// and a declared action, instead of the analyzer dropping an untyped value into an
/// admitted program.
#[test]
fn public_declared_callable_names_are_refused_in_value_positions() {
    let root = TempDirectory::new();
    for (source, identifier, span_text) in [
        (
            "fn inc(value: Int) -> Int { value } fn main() -> Int { discard inc; 0 }",
            "inc",
            "inc",
        ),
        (
            "fn f(value: Int) -> Int { value } fn inc(value: Int) -> Int { value } fn main() -> Int { f(inc) }",
            "inc",
            "inc",
        ),
        (
            "fn inc(value: Int) -> Int { value } fn apply(callback: Fn(Int) -> Int, value: Int) -> Int { value } fn main() -> Int { discard apply(inc, 1); 0 }",
            "inc",
            "inc",
        ),
        (
            "fn inc(value: Int) -> Int { value } fn main() -> Int { discard crate::inc; 0 }",
            "inc",
            "crate::inc",
        ),
        (
            "fn inc(value: Int) -> Int { value } fn main() -> Int { discard (inc)(1); 0 }",
            "inc",
            "inc",
        ),
        (
            "fn id<T>(value: T) -> T { value } fn main() -> Int { discard (id)::<Int>(1); 0 }",
            "id",
            "id",
        ),
        (
            "action read_only lookup(value: Int) -> Int; fn main() -> Int { discard lookup; 0 }",
            "lookup",
            "lookup",
        ),
        (
            "action read_only lookup(value: Int) -> Int; fn main() -> Int { discard (lookup)(1); 0 }",
            "lookup",
            "lookup",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics().len(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = &refused.diagnostics()[0];
        assert_eq!(refusal.code.as_str(), "callable-reference-unadmitted");
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("identifier").map(AsRef::as_ref),
            Some(identifier),
            "source: {source}"
        );
        let main_start = source.find("fn main").unwrap_or(0);
        let offset = source[main_start..]
            .find(span_text)
            .unwrap_or_else(|| panic!("source: {source}: missing `{span_text}`"));
        let start = (main_start + offset) as u64;
        let end = start + span_text.len() as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), start, "source: {source}");
        assert_eq!(primary.bytes().end(), end, "source: {source}");
    }

    // A declared callable stays reachable through a direct call, a declared type stays
    // reachable through its struct expression, and a callable-typed parameter is still
    // forwarded as a call argument.
    for source in [
        "fn inc(value: Int) -> Int { value } fn main() -> Int { discard inc(1); 0 }",
        "struct Item { count: Int } fn main() -> Int { let item: Item = Item { count: 1 }; discard item; 0 }",
        "fn consume(value: Fn(Int) -> Int) -> Int { 0 } fn forward(callback: Fn(Int) -> Int) -> Int { discard consume(callback); 0 } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }

    // A call through a callable-typed binding keeps the invocation refusal, which
    // `GNT-37.10` owns rather than the reference refusal this lane covers.
    root.write("fn apply(callback: Fn(Int) -> Int) -> Int { callback(1) } fn main() -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let invoked = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(invoked.status(), AnalysisStatus::Invalid);
    assert_eq!(
        invoked.diagnostics().len(),
        1,
        "{:?}",
        invoked.diagnostics()
    );
    assert_eq!(
        invoked.diagnostics()[0].code.as_str(),
        "callable-invocation-unadmitted"
    );
}

/// A call whose callee is a parenthesized expression has no derivation in `GNT-3-T-CALL`,
/// so it is refused at the callee group instead of being admitted and then aborting during
/// lowering or being silently accepted in a body the entry point never reaches.
#[test]
fn public_parenthesized_expression_callees_are_refused_without_internal_failure() {
    let root = TempDirectory::new();
    for (source, span_text) in [
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard (f())(1); 0 }",
            "(f())",
        ),
        (
            "fn f(value: Int) -> Int { value } fn main() -> Int { discard (f(1))(1); 0 }",
            "(f(1))",
        ),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard ((f()))(1); 0 }",
            "((f()))",
        ),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard (f())(); 0 }",
            "(f())",
        ),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard (f())(1, 2); 0 }",
            "(f())",
        ),
        ("fn main() -> Int { discard (1 + 2)(3); 0 }", "(1 + 2)"),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard (f() + 1)(2); 0 }",
            "(f() + 1)",
        ),
        (
            "fn f() -> Int { discard (1 + 2)(3); 0 } fn main() -> Int { 0 }",
            "(1 + 2)",
        ),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard (f())::<Int>(1); 0 }",
            "(f())",
        ),
        (
            "fn f() -> Int { discard (f())::<Int>(1); 0 } fn main() -> Int { 0 }",
            "(f())",
        ),
        ("fn main() -> Int { discard (1)::<Int>(2); 0 }", "(1)"),
        (
            "fn main() -> Int { discard (1 + 2)::<Int>(3); 0 }",
            "(1 + 2)",
        ),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard ((f()))::<Int>(); 0 }",
            "((f()))",
        ),
        (
            "fn f() -> Int { 1 } fn main() -> Int { discard ((f())::<Int>(1)); 0 }",
            "(f())",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let start = source
            .find(span_text)
            .unwrap_or_else(|| panic!("source: {source}: missing `{span_text}`"))
            as u64;
        let end = start + span_text.len() as u64;
        assert!(
            refused.diagnostics().iter().any(|diagnostic| {
                diagnostic.code.as_str() == "invalid-call-target"
                    && diagnostic.primary.as_ref().is_some_and(|span| {
                        span.bytes().start() == start && span.bytes().end() == end
                    })
            }),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
    }

    // A parenthesized expression without an argument list stays an ordinary value.
    root.write("fn main() -> Int { discard (1 + 2); 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let admitted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        admitted.diagnostics()
    );

    // An expression group that contains a refused name publishes both the value refusal and
    // the outer call refusal.
    for source in [
        "fn inc(value: Int) -> Int { value } fn main() -> Int { discard (1 + inc)(1); 0 }",
        "fn inc(value: Int) -> Int { value } fn main() -> Int { discard ((1 + inc))(1); 0 }",
        "fn inc(value: Int) -> Int { value } fn main() -> Int { discard (crate::inc)(1); 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.diagnostics().iter().any(|diagnostic| {
                diagnostic.code.as_str() == "callable-reference-unadmitted"
                    && diagnostic.fields.get("identifier").map(AsRef::as_ref) == Some("inc")
            }),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "invalid-call-target"),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
    }

    // A callable-typed binding inside a call-shaped group refuses both the inner invocation
    // and the outer expression callee.
    root.write("fn apply(x: Fn(Int) -> Int) -> Int { discard (x())(1); 0 } fn main() -> Int { 0 }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed internally: {error:?}"));
    assert_eq!(refused.status(), AnalysisStatus::Invalid);
    assert!(
        refused
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "callable-invocation-unadmitted"),
        "{:?}",
        refused.diagnostics()
    );
    assert!(
        refused
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "invalid-call-target"),
        "{:?}",
        refused.diagnostics()
    );
}

/// A callable expression is recognised by the grammar and refused with its published
/// diagnostic in every position that types a value, instead of failing internally.
#[test]
fn public_callable_expressions_are_refused_without_internal_failure() {
    let root = TempDirectory::new();
    for (source, parameter_counts) in [
        (
            "fn main() -> Int { discard fn(x: Int) -> Int { x }; 0 }",
            vec!["1"],
        ),
        (
            "fn main() -> Int { let callback: Int = fn() -> Int { 0 }; 0 }",
            vec!["0"],
        ),
        (
            "fn main(callback: Int) -> Int { discard fn(x: Int, y: String) -> Bool { true }; 0 }",
            vec!["2"],
        ),
        (
            "struct Holder { callback: Int } fn main() -> Holder { Holder { callback: fn() -> Int { 0 } } }",
            vec!["0"],
        ),
        (
            "fn apply(callback: Int) -> Int { 0 } fn main() -> Int { apply(fn(x: Int) -> Int { x }) }",
            vec!["1"],
        ),
        (
            "fn main() -> Int { discard (fn(x: Int) -> Int { x }); 0 }",
            vec!["1"],
        ),
        (
            "fn main() -> Int { discard fn(x: Int) -> Int { fn(y: Int, z: Int) -> Int { y } }; 0 }",
            vec!["1"],
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let rejected = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected.executable_program().is_none(),
            "source: {source}; an unadmitted callable expression must not publish an executable program"
        );
        let mut refusals = rejected
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "callable-expression-unadmitted")
            .collect::<Vec<_>>();
        assert!(
            !refusals.is_empty(),
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
        for refusal in &refusals {
            assert_eq!(refusal.category, DiagnosticCategory::Type);
        }
        let mut counts = refusals
            .iter()
            .map(|refusal| {
                refusal
                    .fields
                    .get("parameters")
                    .map(AsRef::as_ref)
                    .unwrap_or("?")
                    .to_string()
            })
            .collect::<Vec<_>>();
        counts.sort_unstable();
        assert_eq!(
            counts,
            parameter_counts,
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
        assert!(
            !rejected
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "unresolved-reference"),
            "source: {source}; a refused callable expression must not report its own names: {:?}",
            rejected.diagnostics()
        );
        refusals.clear();
    }
    // An ordinary workflow survives: only the callable expression form is refused.
    root.write("fn named(x: Int) -> Int { x } fn main() -> Int { named(1) }");
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
    let accepted = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
    assert_eq!(
        accepted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        accepted.diagnostics()
    );
}

/// `GNT-13.6` states that v1 has no module, type, function, action, or method values, so a
/// bare path that resolves to a declared type or trait has no value derivation: the refusal
/// is published at the path with its identifier instead of an untyped expression reaching a
/// consumer that cannot check it and admitting a program that fails at run time.
#[test]
fn public_declaration_names_are_refused_in_value_positions() {
    let root = TempDirectory::new();
    for (source, identifier, span_text) in [
        (
            "struct Item {} fn main() -> Int { discard Item; 0 }",
            "Item",
            "Item",
        ),
        (
            "struct Item {} fn f(x: Int) -> Int { x } fn main() -> Int { f(Item) }",
            "Item",
            "Item",
        ),
        (
            "trait Marker {} fn main() -> Int { discard Marker; 0 }",
            "Marker",
            "Marker",
        ),
        (
            "enum Flag { On, Off } fn main() -> Int { discard Flag; 0 }",
            "Flag",
            "Flag",
        ),
        (
            "struct Item {} fn main() -> Int { discard crate::Item; 0 }",
            "Item",
            "crate::Item",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused declaration name must not publish an executable program"
        );
        let refusals = refused
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "non-value-path")
            .collect::<Vec<_>>();
        assert_eq!(
            refusals.len(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refusals[0];
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("identifier").map(AsRef::as_ref),
            Some(identifier),
            "source: {source}"
        );
        // The declaration itself carries the spelling too, so the value use is the last one;
        // a qualified path reports the whole path while `identifier` is its last spelling.
        let path_start = source
            .rfind(span_text)
            .unwrap_or_else(|| panic!("source: {source}: missing path"))
            as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), path_start, "source: {source}");
        assert_eq!(
            primary.bytes().end(),
            path_start + span_text.len() as u64,
            "source: {source}"
        );
    }

    // A struct expression, an enum variant value, a binding read, and a free call keep their
    // meaning.
    for source in [
        "struct Item {} fn main() -> Int { let item: Item = Item {}; 0 }",
        "enum Flag { On, Off } fn main() -> Int { let flag: Flag = Flag::On; 0 }",
        "enum E { V(Int) } fn main() -> Int { let value: E = E::V(1); 0 }",
        "fn f(x: Int) -> Int { x } fn main() -> Int { f(1) }",
        "fn main() -> Int { let value: Int = 1; discard value; 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }

    // A declaration name used as a callee and a declared callable used as a value keep their
    // own published refusals instead of this one.
    for (source, expected) in [
        (
            "struct Item {} fn main() -> Int { discard Item(2); 0 }",
            "invalid-call-target",
        ),
        (
            "fn inc(v: Int) -> Int { v } fn main() -> Int { discard inc; 0 }",
            "callable-reference-unadmitted",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == expected),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .all(|diagnostic| diagnostic.code.as_str() != "non-value-path"),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
    }
}

/// A call whose callee is not a path or a single-identifier group has no derivation
/// (`GNT-3-T-CALL`): a literal, a Boolean, a string, the `self` receiver, and a name that
/// resolves to a declaration which is not a callable are refused with the published
/// `invalid-call-target` code across the complete call span, with the callee type reported
/// where one is known, so no sequence without a call derivation silently drops an argument
/// list, including a bracket- or brace-delimited operand and an argument list applied to a
/// call result.
#[test]
fn public_non_path_callee_shapes_are_refused() {
    let root = TempDirectory::new();
    for (source, call, callee_type) in [
        ("fn main() -> Int { 1(2) }", "1(2)", Some("Int")),
        ("fn main() -> Bool { true(2) }", "true(2)", Some("Bool")),
        (
            "fn main() -> String { \"abc\"(2) }",
            "\"abc\"(2)",
            Some("String"),
        ),
        (
            "struct Item {} impl Item { fn f(self) { discard self(2); } } fn main() -> Int { 0 }",
            "self(2)",
            Some("crate::Item"),
        ),
        (
            "struct Item {} fn main() -> Int { discard Item(2); 0 }",
            "Item(2)",
            None,
        ),
        (
            "struct Item { count: Int } fn main() -> Int { discard Item(1, 2); 0 }",
            "Item(1, 2)",
            None,
        ),
        ("fn main() -> List<Int> { [1, 2](3) }", "[1, 2](3)", None),
        (
            "fn main() -> Int { discard [1, 2](3); 0 }",
            "[1, 2](3)",
            None,
        ),
        (
            "struct Item { count: Int } fn main() -> Int { discard Item { count: 1 }(2); 0 }",
            "Item { count: 1 }(2)",
            None,
        ),
        (
            "fn f(value: Int) -> Int { value } fn main() -> Int { discard f(1)(2); 0 }",
            "f(1)(2)",
            None,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused call must not publish an executable program"
        );
        let refusals = refused
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code.as_str() == "invalid-call-target")
            .collect::<Vec<_>>();
        assert_eq!(
            refusals.len(),
            1,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refusals[0];
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("callee_type").map(AsRef::as_ref),
            callee_type,
            "source: {source}"
        );
        let call_start = source
            .find(call)
            .unwrap_or_else(|| panic!("source: {source}: missing call"))
            as u64;
        let primary = refusal
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), call_start, "source: {source}");
        assert_eq!(
            primary.bytes().end(),
            call_start + call.len() as u64,
            "source: {source}"
        );
    }

    // An operator between an operand and its parenthesis keeps its own meaning, and the
    // admitted call, constructor, receiver-read, and enum-constructor forms keep theirs.
    for source in [
        "fn main() -> Int { 1 + (2) }",
        "struct Item { count: Int } fn main() -> Int { let item: Item = Item { count: 1 }; item.count }",
        "fn f(value: Int) -> Int { value } fn main() -> Int { f(1) }",
        "enum Flag { On, Off } fn main() -> Int { let flag: Flag = Flag::On; 0 }",
        "enum E { V(Int) } fn main() -> Int { let value: E = E::V(1); 0 }",
        "struct Item { count: Int } impl Item { fn bump(self) -> Int { self.count } } fn main() -> Int { let item: Item = Item { count: 1 }; item.bump() }",
        "struct Item {} impl Item { fn f(self) { discard self; } } fn main() -> Int { 0 }",
        "fn main() -> Int { let values: List<Int> = [1, 2]; values[0] }",
        "fn f(values: List<Int>) -> Int { 0 } fn main() -> Int { f([1, 2]) }",
        "struct Item { count: Int } fn f(item: Item) -> Int { 0 } fn main() -> Int { f(Item { count: 1 }) }",
        "fn g(value: Int) -> Int { value } fn f(value: Int) -> Int { value } fn main() -> Int { f(g(1)) }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }
}

/// A call nested in a list- or struct-literal operand is lowered as that call rather than as
/// the enclosing aggregate, so the operand stream matches the expression type and no internal
/// failure reaches analysis (`GNT-GP-VALUE-002`).
#[test]
fn public_calls_inside_aggregate_literals_are_lowered() {
    let root = TempDirectory::new();
    for source in [
        "fn g(v: Int) -> Int { v } fn main() -> Int { discard [g(1)]; 0 }",
        "fn g(v: Int) -> Int { v } fn main() -> Int { let xs: List<Int> = [g(1), 2]; 0 }",
        "fn g(v: Int) -> Int { v } fn main() -> Int { discard [g(1), g(2)]; 0 }",
        "fn g(v: Int) -> Int { v } fn main() -> Int { discard [[g(1)]]; 0 }",
        "fn g(v: Int) -> Int { v } fn main() -> Int { discard [g(1) + 1]; 0 }",
        "struct Item { count: Int } fn g(v: Int) -> Int { v } fn main() -> Int { discard Item { count: g(1) }; 0 }",
        "struct Item { count: Int } fn g(v: Int) -> Int { v } fn main() -> Int { let item: Item = Item { count: g(1) }; 0 }",
        "struct Item { count: Int } impl Item { fn read(self) -> Int { self.count } } fn main() -> Int { let item: Item = Item { count: 1 }; discard [item.read()]; 0 }",
        "fn g(v: Int) -> Int { v } fn main() -> Int { discard [g(1), 2][0]; 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        assert!(
            admitted.executable_program().is_some(),
            "source: {source}: an admitted call inside an aggregate literal must publish a program"
        );
    }

    // The statement-level, tuple, operator, grouped, no-argument, and binding forms keep
    // their meaning.
    for source in [
        "fn g(v: Int) -> Int { v } fn main() -> Int { let x: Int = g(1); x }",
        "fn g(v: Int) -> Int { v } fn main() -> Int { discard (g(1), g(2)); 0 }",
        "fn h() -> Int { 1 } fn main() -> Int { discard [h()]; 0 }",
        "fn g(v: Int) -> Int { v } fn f(v: Int) -> Int { v } fn main() -> Int { f(g(1)) }",
        "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Int { let counter: Counter = Counter { value: 5 }; counter.read() + 1 }",
        "fn main() -> Int { let xs: List<Int> = [1, 2]; xs[0] }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }
}

/// An aggregate literal nested inside another construct is lowered as that construct, so the
/// enclosing expression keeps its own type and value: every row publishes the enclosing aggregate
/// after the literal it contains and executes instead of failing with an internal evaluator
/// invariant (`GNT-GP-VALUE-003`).
#[test]
fn public_nested_aggregate_literals_lower_as_their_enclosing_construct() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("nested aggregate did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, aggregates) in [
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 1 }]; 0 }",
            vec!["struct:crate::Item", "list"],
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 1 }, Item { count: 2 }]; 0 }",
            vec!["struct:crate::Item", "struct:crate::Item", "list"],
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let x: Option<Item> = Some(Item { count: 1 }); 0 }",
            vec!["struct:crate::Item", "some"],
        ),
        (
            "fn main() -> Int { discard ([1, 2], 3); 0 }",
            vec!["list", "tuple"],
        ),
        (
            "struct Bag { values: List<Int> } fn main() -> Int { let bag: Bag = Bag { values: [1, 2] }; 0 }",
            vec!["list", "struct:crate::Bag"],
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let item: Item = (Item { count: 1 }); discard item; 0 }",
            vec!["struct:crate::Item"],
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: a nested aggregate must publish a program")
        });
        let labels = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .filter_map(|instruction| match &instruction.kind {
                InstructionKind::Aggregate { kind, .. } => Some(match kind {
                    AggregateKind::List => "list".to_owned(),
                    AggregateKind::Tuple => "tuple".to_owned(),
                    AggregateKind::Struct { type_name, .. } => format!("struct:{type_name}"),
                    AggregateKind::Enum {
                        type_name, variant, ..
                    } => format!("enum:{type_name}::{variant}"),
                    AggregateKind::Some => "some".to_owned(),
                    AggregateKind::None => "none".to_owned(),
                    AggregateKind::Ok => "ok".to_owned(),
                    AggregateKind::Err => "err".to_owned(),
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            labels, aggregates,
            "source: {source}: the enclosing construct is lowered after the literal it contains"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x31; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(_)),
            "source: {source}: expected the returned Int, observed {value:?}"
        );
    }

    // One row returns its aggregate, so the corrected value is pinned at run time as well as the
    // aggregate order: the enclosing list carries one member whose field is the nested literal.
    let source = "struct Item { count: Int } fn main() -> List<Item> { [Item { count: 1 }] }";
    root.write(source);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
    let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
        panic!("source: {source}; type analysis failed internally: {error:?}")
    });
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "source: {source}; diagnostics: {:?}",
        admitted.diagnostics()
    );
    let program = admitted
        .executable_program()
        .unwrap_or_else(|| panic!("source: {source}: a returned aggregate must publish a program"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
        Vec::new(),
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x31; 32])
            .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
        MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("fixture limits are positive")),
    )
    .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
    let returned = drive(&mut machine);
    assert!(
        matches!(returned.view(), LogicalValueView::List(1)),
        "source: {source}: expected one returned member, observed {returned:?}"
    );
    let member = returned
        .member(0)
        .unwrap_or_else(|| panic!("source: {source}: expected a first member"));
    let count = member
        .field("count")
        .unwrap_or_else(|| panic!("source: {source}: expected the count field"));
    assert!(
        matches!(count.view(), LogicalValueView::Int(value) if value.get() == 1),
        "source: {source}: expected the count 1, observed {count:?}"
    );
}

/// A constructor callee whose operand shape does not match its payload shape is refused precisely
/// at its own span instead of failing internally: too many operands, a missing payload, and any
/// argument list on a payload-free constructor (including an empty one) are all refused, while
/// matching spellings keep their meaning (`GNT-GP-CALLEE-003`).
#[test]
fn public_constructor_callee_operand_counts_are_refused_precisely() {
    let root = TempDirectory::new();
    for (source, code, start, end) in [
        (
            "fn main() -> Option<Int> { None(2) }",
            "ambiguous-constructor-type",
            27_u64,
            31_u64,
        ),
        (
            "fn main() -> Int { let x: Option<Int> = None(2); discard x; 0 }",
            "ambiguous-constructor-type",
            40,
            44,
        ),
        (
            "fn main() -> Int { let x: Option<Int> = None(1, 2); discard x; 0 }",
            "ambiguous-constructor-type",
            40,
            44,
        ),
        (
            "enum E { V(Int) } fn main() -> Int { discard E::V(1, 2); 0 }",
            "invalid-enum-constructor",
            45,
            55,
        ),
        (
            "enum E { V(Int) } fn main() -> Int { discard E::V(1, 2, 3); 0 }",
            "invalid-enum-constructor",
            45,
            58,
        ),
        (
            "enum E { V(Int) } fn main() -> Int { let x: E = E::V(1, 2); discard x; 0 }",
            "invalid-enum-constructor",
            48,
            58,
        ),
        (
            "enum E { V(Int) } fn main() -> Int { discard E::V(); 0 }",
            "invalid-enum-constructor",
            45,
            51,
        ),
        (
            "enum Flag { On, Off } fn main() -> Int { discard Flag::On(1); 0 }",
            "invalid-enum-constructor",
            49,
            60,
        ),
        (
            "fn main() -> Option<Int> { None() }",
            "ambiguous-constructor-type",
            27,
            31,
        ),
        (
            "fn main() -> Int { let x: Option<Int> = None(); discard x; 0 }",
            "ambiguous-constructor-type",
            40,
            44,
        ),
        (
            "enum Flag { On, Off } fn main() -> Int { discard Flag::On(); 0 }",
            "invalid-enum-constructor",
            49,
            59,
        ),
        (
            "enum Boxed<T> { Empty, Full(T) } fn main() -> Int { let b: Boxed<Int> = Boxed::Full(1, 2); discard b; 0 }",
            "invalid-enum-constructor",
            72,
            89,
        ),
        (
            "enum Boxed<T> { Empty, Full(T) } fn main() -> Int { let b: Boxed<Int> = Boxed::Empty(1); discard b; 0 }",
            "invalid-enum-constructor",
            72,
            87,
        ),
        (
            "enum Boxed<T> { Empty, Full(T) } fn main() -> Int { let b: Boxed<Int> = Boxed::Empty(); discard b; 0 }",
            "invalid-enum-constructor",
            72,
            86,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let diagnostic = refused
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == code)
            .unwrap_or_else(|| {
                panic!("source: {source}; diagnostics: {:?}", refused.diagnostics())
            });
        let primary = diagnostic
            .primary
            .as_ref()
            .unwrap_or_else(|| panic!("source: {source}: missing primary span"));
        assert_eq!(primary.bytes().start(), start, "source: {source}");
        assert_eq!(primary.bytes().end(), end, "source: {source}");
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused constructor callee must not publish a program"
        );
    }

    for source in [
        "enum E { V(Int) } fn main() -> Int { discard E::V(1); 0 }",
        "fn main() -> Option<Int> { Some(1) }",
        "fn main() -> Int { let x: Option<Int> = None; discard x; 0 }",
        "fn main() -> Int { let y: Option<Int> = Some(1); discard y; 0 }",
        "fn main() -> Int { let x: Option<Int> = (None); discard x; 0 }",
        "enum Flag { On, Off } fn main() -> Int { discard Flag::On; 0 }",
        "enum Boxed<T> { Empty, Full(T) } fn main() -> Int { let b: Boxed<Int> = Boxed::Empty; discard b; 0 }",
        "enum Boxed<T> { Empty, Full(T) } fn main() -> Int { let b: Boxed<Int> = Boxed::Full(1); discard b; 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
    }
}

/// An annotation naming a type that no declaration provides is refused precisely, including when
/// the enclosing declaration is reachable and would otherwise be lowered into an executable program.
#[test]
fn public_unresolved_type_annotations_are_refused_without_internal_failure() {
    let root = TempDirectory::new();
    for source in [
        "fn main(value: Missing) -> Int { 0 }",
        "struct Holder { field: Missing } fn main() -> Int { 0 }",
        "fn main(value: List<Missing>) -> Int { 0 }",
        "fn helper(value: crate::missing::Kind) -> Int { 0 } fn main(value: Missing) -> Int { 0 }",
        "impl Missing { fn run(self) -> Int { 0 } } fn main() -> Int { 0 }",
        "struct Box<T> { value: T } impl Box<Missing> {} fn main() -> Int { 0 }",
        "trait Tr {} impl Tr for Missing {} fn main() -> Int { 0 }",
        "trait Tr {} struct Box<T> { value: T } impl Tr for Box<Missing> {} fn main() -> Int { 0 }",
        "trait Tr {} struct S {} impl Tr2 for S {} fn main() -> Int { 0 }",
        "trait Tr {} pure fn hold<T>(value: T) -> T where T: Missing { value } fn main() -> Int { hold(1) }",
        "trait Tr {} pure fn hold<T>(value: T) -> T where Missing: Tr { value } fn main() -> Int { hold(1) }",
        "trait Tr {} pure fn hold<T>(value: T) -> T where T: Tr, T: Missing { value } fn main() -> Int { hold(1) }",
        "trait Tr {} pure fn other<T>(value: T) -> T where T: Tr { value } pure fn hold<U>(value: U) -> U where T: Tr { value } fn main() -> Int { discard hold(1); 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
        let rejected = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
        assert_eq!(
            rejected.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            rejected.diagnostics()
        );
        assert!(
            rejected.executable_program().is_none(),
            "source: {source}; an unresolved type must not publish an executable program"
        );
        let refusal = rejected
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "unresolved-reference")
            .unwrap_or_else(|| {
                panic!(
                    "source: {source}; diagnostics: {:?}",
                    rejected.diagnostics()
                )
            });
        assert_eq!(refusal.category, DiagnosticCategory::NameResolution);
        assert!(
            refusal.fields.contains_key("authored_path"),
            "source: {source}; fields: {:?}",
            refusal.fields
        );
    }
    for source in [
        "trait Marker {} trait Wrapped<T> where T: Marker { } fn main() -> Int { 0 }",
        "trait Marker {} pure fn hold<T>(value: T) -> T where T: Marker { value } fn main() -> Int { 0 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("syntax phase failed: {error:?}"));
        let accepted = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("type analysis failed: {error:?}"));
        assert_eq!(
            accepted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            accepted.diagnostics()
        );
    }
}

#[test]
fn public_self_annotations_keep_their_own_spans() {
    // A `Self` annotation's fact belongs to the annotation, not to the implementation receiver it
    // borrows its descriptor from (`TypeFact` promises the exact span of the complete annotation),
    // so each `Self` position carries its own fact and the receiver keeps its own span.
    let root = TempDirectory::new();
    let source = "trait R { pure fn same(self, other: Self) -> Self; } struct S {} impl R for S { fn same(self, other: Self) -> Self { other } } fn main() -> Int { let s: S = S {}; let t: S = s.same(s); 1 }";
    root.write(source);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
    let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
        panic!("source: {source}; type analysis failed internally: {error:?}")
    });
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "source: {source}; diagnostics: {:?}",
        admitted.diagnostics()
    );
    let annotated = admitted
        .types()
        .iter()
        .filter(|fact| {
            let (Ok(start), Ok(end)) = (
                usize::try_from(fact.span.bytes().start()),
                usize::try_from(fact.span.bytes().end()),
            ) else {
                return false;
            };
            source.as_bytes().get(start..end) == Some(b"Self".as_slice())
        })
        .count();
    assert_eq!(
        annotated, 2,
        "the implementation's parameter and result each carry their own `Self` fact"
    );
    // The implementation receiver keeps its own facts: the seeded annotations must not have taken
    // the receiver's span for themselves.
    let receivers = admitted
        .types()
        .iter()
        .filter(|fact| {
            let (Ok(start), Ok(end)) = (
                usize::try_from(fact.span.bytes().start()),
                usize::try_from(fact.span.bytes().end()),
            ) else {
                return false;
            };
            source.as_bytes().get(start..end) == Some(b"S".as_slice())
        })
        .count();
    assert!(
        receivers >= 2,
        "the implementation receiver keeps its own `S` facts"
    );
}

#[test]
fn public_literal_receiver_index_projections_are_lowered_and_typed() {
    let root = TempDirectory::new();
    for (source, index) in [
        ("fn main() -> Int { [1, 2][0] }", 0usize),
        ("fn main() -> Int { [1, 2][1] }", 1),
        ("fn main() -> Int { discard [1, 2][0]; 0 }", 0),
        ("fn main() -> Int { let value: Int = [1, 2][1]; value }", 1),
        ("fn main() -> Int { [1 + 1, 2][0] }", 0),
        (
            "fn g(v: Int) -> Int { v } fn main() -> Int { [g(1), 2][0] }",
            0,
        ),
        (
            "fn g(v: Int) -> Int { v } fn main() -> Int { discard [g(1), 2][1]; 0 }",
            1,
        ),
        (
            "fn g(v: Int) -> Int { v } fn main() -> Int { g([1, 2][0]) }",
            0,
        ),
        ("fn main() -> List<Int> { [[1, 2], [3]][1] }", 1),
        // A constant index expression is folded to the value it names: the first literal token is
        // not the index when the expression carries operators (`[3 - 1]` used to read index 3).
        ("fn main() -> Int { [1, 2, 3][3 - 1] }", 2),
        ("fn main() -> Int { [1, 2, 3][1 + 1] }", 2),
        ("fn main() -> Int { [1, 2, 3][(1 + 1)] }", 2),
        ("fn main() -> Int { [1, 2, 3][2 - 1 + 1] }", 2),
        ("fn main() -> Int { [1, 2, 3][5 - 4] }", 1),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted
            .executable_program()
            .unwrap_or_else(|| panic!("source: {source}: a projection must publish a program"));
        let projected = program.workflows().iter().any(|workflow| {
            workflow.instructions.windows(2).any(|window| {
                matches!(
                    (&window[0].kind, &window[1].kind),
                    (
                        InstructionKind::Aggregate {
                            kind: AggregateKind::List,
                            ..
                        },
                        InstructionKind::Project(Projection::Member(projected))
                    ) if *projected == index
                )
            })
        });
        assert!(
            projected,
            "source: {source}: the literal receiver must lower to its aggregate followed by member {index}"
        );
    }

    // A postfix chain publishes every step it applies: a binding receiver loads once and then each
    // field or member step follows, and a literal receiver publishes its aggregate before the same
    // steps, so neither shape applies a projection to the receiver itself.
    for (source, receiver, steps) in [
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 1 }]; items[0].count }",
            Some("items"),
            vec![Projection::Member(0), Projection::Field("count".into())],
        ),
        (
            "fn main() -> Int { let xs: List<List<Int>> = [[1]]; xs[0][0] }",
            Some("xs"),
            vec![Projection::Member(0), Projection::Member(0)],
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { let item: Item = Item { values: [1] }; item.values[0] }",
            Some("item"),
            vec![Projection::Field("values".into()), Projection::Member(0)],
        ),
        (
            "fn main() -> Int { [[1, 2], [3]][1][0] }",
            None,
            vec![Projection::Member(1), Projection::Member(0)],
        ),
        // A group around the chain's root segment keys the same chain and publishes the same steps
        // as its ungrouped spelling, whether the whole part or only the root segment is grouped
        // (`541af029`).
        (
            "struct Item { values: List<Int> } fn main() -> Int { let item: Item = Item { values: [1] }; (item).values[0] }",
            Some("item"),
            vec![Projection::Field("values".into()), Projection::Member(0)],
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { let item: Item = Item { values: [1] }; ((item).values)[0] }",
            Some("item"),
            vec![Projection::Field("values".into()), Projection::Member(0)],
        ),
        (
            "struct Item { count: Int } fn main() -> Int { Item { count: 1 }.count }",
            None,
            vec![Projection::Field("count".into())],
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted
            .executable_program()
            .unwrap_or_else(|| panic!("source: {source}: a chain must publish a program"));
        let lowered = program.workflows().iter().any(|workflow| {
            let kinds = workflow
                .instructions
                .iter()
                .map(|instruction| &instruction.kind)
                .collect::<Vec<_>>();
            kinds.windows(steps.len() + 1).any(|window| {
                let receiver_matches = match receiver {
                    Some(name) => {
                        matches!(window[0], InstructionKind::Load(loaded) if loaded.as_ref() == name)
                    }
                    None => matches!(window[0], InstructionKind::Aggregate { .. }),
                };
                receiver_matches
                    && window[1..].iter().zip(&steps).all(|(kind, expected)| {
                        matches!(kind, InstructionKind::Project(actual) if actual == expected)
                    })
            })
        });
        assert!(
            lowered,
            "source: {source}: the chain must publish {receiver:?} followed by {steps:?}"
        );
    }

    // A non-integer index keeps its precise refusal and publishes nothing.
    let source = "fn main() -> Int { [1, 2][true] }";
    root.write(source);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("source: {source}; type analysis failed: {error:?}"));
    assert_eq!(
        refused.status(),
        AnalysisStatus::Invalid,
        "source: {source}; diagnostics: {:?}",
        refused.diagnostics()
    );
    assert!(
        refused
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "projection-index-type"),
        "source: {source}; diagnostics: {:?}",
        refused.diagnostics()
    );
    assert!(
        refused.executable_program().is_none(),
        "source: {source}: a refused projection must not publish a program"
    );
}

/// A computed projection receiver is lowered as the value it produces, never as a callee path.
///
/// `SPEC.md` keeps `(value)` as grouping, so `(xs)[0]` and `((xs))[0]` project one element of
/// `xs`, and a call receiver such as `head(xs)[0]` or `b.all()[0]` projects the call result. A
/// receiver part that is itself a chain (`mk().items`, `(Item { values: [1] }).values`) publishes
/// that chain's value, the call or aggregate followed by each field step, before the member
/// projection instead of aborting on the unkeyed receiver. Each row below publishes the receiver
/// value immediately before its member projection and executes to the element it names, and a
/// receiver that is neither a list nor a tuple refuses with the published
/// `projection-receiver-type` code instead of failing inside the evaluator (`GNT-GP-VALUE-004`).
/// A chain of more than one member step over a constructed root
/// (`Outer { inner: Inner { rows: [7] } }.inner.rows[0]`) keys every step against the type the step
/// before it produced, so each intermediate member resolves in turn and the trailing index is
/// judged against the element type instead of being left to the evaluator (`e7e735fc`).
#[test]
fn public_computed_projection_receivers_are_lowered_and_typed() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("computed projection did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    /// The receiver value one row must publish immediately before its member projection.
    #[derive(Clone, Copy)]
    enum ReceiverStep {
        Load,
        Call,
        ReceiverCall,
        /// A field step publishes the receiver value of a chain rooted in a constructed value or a
        /// call result (`mk().items[0]`, `(Item { values: [1] }).values[0]`).
        Field,
    }

    let root = TempDirectory::new();
    for (source, step, forbidden_load, index, expected) in [
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; (xs)[0] }",
            ReceiverStep::Load,
            None,
            0usize,
            1i64,
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; ((xs))[0] }",
            ReceiverStep::Load,
            None,
            0,
            1,
        ),
        (
            "fn head(xs: List<Int>) -> List<Int> { xs } fn main() -> Int { head([1, 2])[0] }",
            ReceiverStep::Call,
            Some("head"),
            0,
            1,
        ),
        (
            "fn head(xs: List<Int>) -> List<Int> { xs } fn main() -> Int { let xs: List<Int> = [1, 2]; head(xs)[1] }",
            ReceiverStep::Call,
            Some("head"),
            1,
            2,
        ),
        (
            "struct Bag { items: List<Int> } impl Bag { fn all(self) -> List<Int> { self.items } } fn main() -> Int { let b: Bag = Bag { items: [1, 2] }; b.all()[0] }",
            ReceiverStep::ReceiverCall,
            None,
            0,
            1,
        ),
        (
            "struct Bag { items: List<Int> } impl Bag { fn all(self) -> List<Int> { self.items } } fn main() -> Int { let b: Bag = Bag { items: [1, 2] }; b.all()[1] }",
            ReceiverStep::ReceiverCall,
            None,
            1,
            2,
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 5 }]; (items)[0].count }",
            ReceiverStep::Load,
            None,
            0,
            5,
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; (xs[0]) }",
            ReceiverStep::Load,
            None,
            0,
            1,
        ),
        (
            "struct HL { items: List<Int> } fn mk() -> HL { HL { items: [7] } } fn main() -> Int { mk().items[0] }",
            ReceiverStep::Field,
            Some("mk"),
            0,
            7,
        ),
        (
            "struct HL { items: List<Int> } fn mk() -> HL { HL { items: [7] } } fn main() -> Int { (mk()).items[0] }",
            ReceiverStep::Field,
            Some("mk"),
            0,
            7,
        ),
        (
            "struct HL { items: List<Int> } fn mk() -> HL { HL { items: [7, 8] } } fn main() -> Int { (mk()).items[1] }",
            ReceiverStep::Field,
            Some("mk"),
            1,
            8,
        ),
        (
            "struct HL { items: List<Int> } fn mk(n: Int) -> HL { HL { items: [n] } } fn main() -> Int { (mk(7)).items[0] }",
            ReceiverStep::Field,
            Some("mk"),
            0,
            7,
        ),
        (
            "struct HL { items: List<Int> } fn mk() -> HL { HL { items: [7] } } fn main() -> Int { ((mk()).items)[0] }",
            ReceiverStep::Field,
            Some("mk"),
            0,
            7,
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { Item { values: [1] }.values[0] }",
            ReceiverStep::Field,
            None,
            0,
            1,
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { (Item { values: [1] }).values[0] }",
            ReceiverStep::Field,
            None,
            0,
            1,
        ),
        (
            "struct Inner { items: List<Int> } struct Outer { inner: Inner } fn mk() -> Outer { Outer { inner: Inner { items: [7] } } } fn main() -> Int { (mk()).inner.items[0] }",
            ReceiverStep::Field,
            Some("mk"),
            0,
            7,
        ),
        (
            "struct LL { rows: List<List<Int>> } fn mkll() -> LL { LL { rows: [[7]] } } fn main() -> Int { (mkll()).rows[0][0] }",
            ReceiverStep::Field,
            Some("mkll"),
            0,
            7,
        ),
        (
            "struct LL { rows: List<List<Int>> } fn mkll() -> LL { LL { rows: [[7]] } } fn main() -> Int { mkll().rows[0][0] }",
            ReceiverStep::Field,
            Some("mkll"),
            0,
            7,
        ),
        (
            "struct LL { rows: List<List<Int>> } fn mkll() -> LL { LL { rows: [[7], [8]] } } fn main() -> Int { (mkll()).rows[1][0] }",
            ReceiverStep::Field,
            Some("mkll"),
            1,
            8,
        ),
        (
            "struct Bag { items: List<Int> } fn main() -> Int { Bag { items: [7] }.items[0] }",
            ReceiverStep::Field,
            None,
            0,
            7,
        ),
        (
            "struct Inner { rows: List<Int> } struct Outer { inner: Inner } fn main() -> Int { Outer { inner: Inner { rows: [7] } }.inner.rows[0] }",
            ReceiverStep::Field,
            None,
            0,
            7,
        ),
        (
            "struct Inner { rows: List<Int> } struct Outer { inner: Inner } fn main() -> Int { (Outer { inner: Inner { rows: [7] } }).inner.rows[0] }",
            ReceiverStep::Field,
            None,
            0,
            7,
        ),
        (
            "struct Inner { rows: List<Int> } struct Outer { inner: Inner } fn main() -> Int { Outer { inner: Inner { rows: [7] } }.inner.rows[0] + 1 }",
            ReceiverStep::Field,
            None,
            0,
            8,
        ),
        // The value position folds the same chain: the binding holds the element the chain read.
        (
            "struct Inner { rows: List<Int> } struct Outer { inner: Inner } fn main() -> Int { let x: List<Int> = Outer { inner: Inner { rows: [7] } }.inner.rows; x[0] }",
            ReceiverStep::Load,
            None,
            0,
            7,
        ),
        (
            "fn main() -> Int { let t: Tuple<Int, Int> = (1, 2); t[1] }",
            ReceiverStep::Load,
            None,
            1,
            2,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: a computed receiver must publish a program")
        });
        let kinds = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .map(|instruction| &instruction.kind)
            .collect::<Vec<_>>();
        let projected = kinds.windows(2).any(|window| {
            let receiver_matches = match step {
                ReceiverStep::Load => matches!(window[0], InstructionKind::Load(_)),
                ReceiverStep::Call => matches!(window[0], InstructionKind::Call { .. }),
                ReceiverStep::ReceiverCall => {
                    matches!(window[0], InstructionKind::ReceiverCall { .. })
                }
                ReceiverStep::Field => {
                    matches!(window[0], InstructionKind::Project(Projection::Field(_)))
                }
            };
            receiver_matches
                && matches!(
                    window[1],
                    InstructionKind::Project(Projection::Member(projected)) if *projected == index
                )
        });
        assert!(
            projected,
            "source: {source}: the receiver value must precede member {index}"
        );
        if let Some(callee) = forbidden_load {
            assert!(
                !kinds.iter().any(
                    |kind| matches!(kind, InstructionKind::Load(name) if name.as_ref() == callee)
                ),
                "source: {source}: the callee {callee} must not be loaded as the receiver"
            );
        }
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x41; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }

    // A receiver that is neither a list nor a tuple has no element to project, so it refuses with
    // its own published code and publishes no program.
    for (source, actual) in [
        ("fn main() -> Int { (1 + 2)[0] }", "Int"),
        (
            "fn main() -> Int { let t: String = \"ab\"; t[0] }",
            "String",
        ),
        (
            "struct HL { items: List<Int> } fn mk() -> HL { HL { items: [7] } } fn main() -> Int { mk().items[0][0] }",
            "Int",
        ),
        (
            "struct HL { items: List<Int> } fn mk() -> HL { HL { items: [7] } } fn main() -> Int { (mk()).items[0][0] }",
            "Int",
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { Item { values: [1] }.values[0][0] }",
            "Int",
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { (Item { values: [1] }).values[0][0] }",
            "Int",
        ),
        (
            "struct Item { values: Int } fn main() -> Int { Item { values: 1 }.values[0] }",
            "Int",
        ),
        (
            "struct Item { values: Int } fn main() -> Int { (Item { values: 1 }).values[0] }",
            "Int",
        ),
        (
            "struct Inner { rows: List<Int> } struct Outer { inner: Inner } fn main() -> Int { Outer { inner: Inner { rows: [7] } }.inner.rows[0][0] }",
            "Int",
        ),
        (
            "struct Inner { rows: List<Int> } struct Outer { inner: Inner } fn main() -> Int { Outer { inner: Inner { rows: [7] } }.inner[0] }",
            "crate::Inner",
        ),
        (
            "struct Bag { items: List<Int> } fn main() -> Int { Bag { items: [7] }[0] }",
            "crate::Bag",
        ),
        (
            "struct Bag { items: List<Int> } fn main() -> Int { (Bag { items: [7] })[0] }",
            "crate::Bag",
        ),
        (
            "fn main() -> Int { let t: Tuple<Int, Int> = (1, 2); t[0][0] }",
            "Int",
        ),
        (
            "fn main() -> Int { let t: Tuple<Int, Tuple<Int, Int>> = (1, (2, 3)); t[1][0][0] }",
            "Int",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax)
            .unwrap_or_else(|error| panic!("source: {source}; type analysis failed: {error:?}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        let refusal = refused
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code.as_str() == "projection-receiver-type")
            .unwrap_or_else(|| {
                panic!("source: {source}; diagnostics: {:?}", refused.diagnostics())
            });
        assert_eq!(refusal.category, DiagnosticCategory::Type);
        assert_eq!(
            refusal.fields.get("actual").map(AsRef::as_ref),
            Some(actual),
            "source: {source}; fields: {:?}",
            refusal.fields
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused receiver must not publish a program"
        );
    }

    // A member the fold cannot key names the receiver the step before it produced, so a wrong
    // member of a multi-step constructed chain is attributed to the intermediate type rather than
    // to the constructed root.
    let source = "struct Inner { rows: Int } struct Outer { inner: Inner } fn main() -> Int { Outer { inner: Inner { rows: 1 } }.inner.nope }";
    root.write(source);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("source: {source}; type analysis failed: {error:?}"));
    assert_eq!(
        refused.status(),
        AnalysisStatus::Invalid,
        "source: {source}; diagnostics: {:?}",
        refused.diagnostics()
    );
    let refusal = refused
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "unknown-member")
        .unwrap_or_else(|| panic!("source: {source}; diagnostics: {:?}", refused.diagnostics()));
    assert_eq!(
        refusal.fields.get("member").map(AsRef::as_ref),
        Some("nope")
    );
    assert_eq!(
        refusal.fields.get("receiver").map(AsRef::as_ref),
        Some("crate::Inner")
    );
    assert!(
        refused.executable_program().is_none(),
        "source: {source}: a refused member chain must not publish a program"
    );
}

/// A split struct operand is the constructed value plus its field steps, not a binding load.
///
/// The parser hands a leading constructed receiver to an operand walk as the constructor's name
/// path plus the struct expression it builds, so `Counter { value: 5 }.value + 1` is neither one
/// projection node nor one place. The operand publishes the literal and then each field step, so
/// the enclosing operator receives the field's value instead of an internal failure; a call step
/// keeps the receiver-call arm, which its own lane covers.
#[test]
fn public_split_struct_operands_are_typed_and_lowered() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("split struct operand did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    /// The value one row must produce, so an integer and a comparison row share one loop.
    #[derive(Clone, Copy, Debug)]
    enum Expected {
        Int(i64),
        Bool(bool),
    }

    let root = TempDirectory::new();
    for (source, expected) in [
        (
            "struct Counter { value: Int } fn main() -> Int { Counter { value: 5 }.value + 1 }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } fn main() -> Int { 1 + Counter { value: 5 }.value }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Int { Counter { value: 5 }.read() + 1 }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Int { 1 + Counter { value: 1 }.read() }",
            Expected::Int(2),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Int { 5 + Counter { value: 1 }.read() }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Bool { Counter { value: 5 }.read() == 5 }",
            Expected::Bool(true),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Bool { Counter { value: 5 }.read() == 5 && true }",
            Expected::Bool(true),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn id(x: Int) -> Int { x } fn main() -> Bool { Counter { value: 5 }.read() == id(5) }",
            Expected::Bool(true),
        ),
        // A chained projection in a let initializer holds the element its steps read, exactly as the
        // tail spelling does: the binding used to be emitted as `Unit` while the steps left the
        // projected value, which failed the machine.
        (
            "fn main() -> Int { let xss: List<List<Int>> = [[1, 2], [3]]; let v: Int = xss[0][0 + 1]; v }",
            Expected::Int(2),
        ),
        (
            "fn main() -> Int { let xss: List<List<Int>> = [[1, 2], [3]]; let v: Int = xss[1][0 + 0]; v }",
            Expected::Int(3),
        ),
        (
            "fn main() -> Int { let t: Tuple<Tuple<Int, Int>, Tuple<Int, Int>> = ((1, 2), (3, 4)); let v: Int = t[1][1]; v }",
            Expected::Int(4),
        ),
        // A `Self` parameter in a trait method denotes the implementation's applied receiver
        // (`SPEC.md` Section 6), so every receiver/argument spelling of the contract works.
        (
            "trait R { pure fn same(self, other: Self) -> Int; } struct S {} impl R for S { fn same(self, other: Self) -> Int { 1 } } fn main() -> Int { let s: S = S {}; s.same(s) }",
            Expected::Int(1),
        ),
        (
            "trait R { pure fn same(self, other: Self) -> Int; } struct S {} impl R for S { fn same(self, other: Self) -> Int { 1 } } fn main() -> Int { S {}.same(S {}) }",
            Expected::Int(1),
        ),
        (
            "trait R { pure fn same(self, other: Self) -> Int; } struct S {} impl R for S { fn same(self, other: Self) -> Int { 1 } } fn same_from(s: S) -> Int { s.same(s) } fn main() -> Int { same_from(S {}) }",
            Expected::Int(1),
        ),
        (
            "trait R { pure fn same(self, other: Self) -> Int; } fn main() -> Int { 1 }",
            Expected::Int(1),
        ),
        (
            "trait T { pure fn e<X>(self, x: X) -> X; } struct S {} impl T for S { fn e<X>(self, x: X) -> X { x } } fn main() -> Int { S {}.e(1) }",
            Expected::Int(1),
        ),
        // The same `Self` contract inside an inherent implementation: the annotation denotes the
        // implementation's receiver in parameter and result positions alone, with a checked
        // argument, in a generic implementation, and when the method body reads the parameter.
        (
            "struct S {} impl S { fn same(self, other: Self) -> Int { 1 } } fn main() -> Int { let s: S = S {}; s.same(s) }",
            Expected::Int(1),
        ),
        (
            "struct S {} impl S { fn same(self, other: Self) -> Int { 1 } } fn main() -> Int { S {}.same(S {}) }",
            Expected::Int(1),
        ),
        (
            "struct S {} impl S { fn pick(self, first: Self, second: Int) -> Int { second } } fn main() -> Int { let s: S = S {}; s.pick(s, 3) }",
            Expected::Int(3),
        ),
        (
            "struct S {} impl S { fn me(self) -> Self { self } } fn main() -> Int { let s: S = S {}; let t: S = s.me(); 0 }",
            Expected::Int(0),
        ),
        (
            "struct S { value: Int } impl S { fn sum(self, other: Self) -> Int { self.value + other.value } } fn main() -> Int { let s: S = S { value: 1 }; let t: S = S { value: 2 }; s.sum(t) }",
            Expected::Int(3),
        ),
        (
            "struct S<T> { value: T } impl<T> S<T> { fn pick(self, other: Self) -> Int { 1 } } fn main() -> Int { let s: S<Int> = S::<Int> { value: 1 }; s.pick(s) }",
            Expected::Int(1),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Bool { Counter { value: 5 }.read() == (5) }",
            Expected::Bool(true),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Bool { Counter { value: 5 }.read() == (1 + 4) }",
            Expected::Bool(true),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn next(self) -> Counter { Counter { value: self.value + 1 } } } fn id(x: Int) -> Int { x } fn main() -> Bool { Counter { value: 1 }.next().value == id(2) }",
            Expected::Bool(true),
        ),
        (
            "struct Counter { value: Int } fn main() -> Int { ((Counter { value: 5 }.value)) + 1 }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } fn main() -> Int { (((Counter { value: 5 }.value))) + 1 }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Bool { ((Counter { value: 5 }.read())) == 5 }",
            Expected::Bool(true),
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { ((Item { values: [1] }.values))[0] }",
            Expected::Int(1),
        ),
        (
            "struct A { v: Int } fn main() -> Bool { A { v: 1 } == A { v: 1 } }",
            Expected::Bool(true),
        ),
        (
            "struct A { v: Int } fn main() -> Bool { A { v: 1 } != A { v: 1 } }",
            Expected::Bool(false),
        ),
        (
            "struct Counter { value: Int } fn main() -> Int { (Counter { value: 5 }.value) + 1 }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } fn main() -> Int { ((Counter { value: 5 })).value + 1 }",
            Expected::Int(6),
        ),
        (
            "struct Counter { value: Int } fn main() -> Int { Counter { value: 5 }.value }",
            Expected::Int(5),
        ),
        (
            "struct Item { values: List<Int> } fn main() -> Int { Item { values: [1] }.values[0] + 1 }",
            Expected::Int(2),
        ),
        (
            "struct Counter { value: Int } fn main() -> Bool { Counter { value: 5 }.value == 5 }",
            Expected::Bool(true),
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: a split struct operand must publish a program")
        });
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x44; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        let matched = match (expected, value.view()) {
            (Expected::Int(expected), LogicalValueView::Int(actual)) => actual.get() == expected,
            (Expected::Bool(expected), LogicalValueView::Bool(actual)) => actual == expected,
            _ => false,
        };
        assert!(
            matched,
            "source: {source}: expected {expected:?}, observed {value:?}"
        );
    }

    // A comparison of two different declared types is not a structural comparison: it refuses with
    // the operator's own code and publishes no program, exactly as the scalar spelling does.
    for source in [
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } == B { v: 1 } }",
        "struct A { v: Int } struct B { v: Int } fn main() -> Bool { A { v: 1 } != B { v: 1 } }",
        "struct Counter { value: Int } impl Counter { fn read(self) -> Int { self.value } } fn main() -> Bool { Counter { value: 5 }.read() + true == 6 }",
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == "invalid-primitive"),
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused comparison must not publish a program"
        );
    }
}

/// A split index-projection operand is the element it reads rather than its receiver.
///
/// The parser flattens `xs[0]` into sibling fragments, so an enclosing operator receives a
/// receiver part and an index part instead of one projection node. The analyzer types that operand
/// as the element of the receiver and the lowering loads the receiver once before the projection
/// steps, which the program shape below pins for both operand positions, for a chain that
/// continues into a field, and for consecutive projections of one binding. The dynamic-index
/// control keeps its refusal: the element access a non-literal index needs is not published yet,
/// so a program that reads one must not be admitted without it.
#[test]
fn public_split_index_projection_operands_are_typed_and_lowered() {
    let root = TempDirectory::new();
    let load = |name: &str| format!("load {name}");
    let member = |index: usize| format!("member {index}");
    let field = |name: &str| format!("field {name}");
    for (source, expected) in [
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; xs[0] + 1 }",
            vec![load("xs"), member(0)],
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + xs[0] }",
            vec![load("xs"), member(0)],
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; xs[0] + xs[1] }",
            vec![load("xs"), member(0), load("xs"), member(1)],
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; xs[0] + xs[1] + 1 }",
            vec![load("xs"), member(0), load("xs"), member(1)],
        ),
        (
            "fn main() -> Int { let xs: List<List<Int>> = [[1, 2], [3]]; xs[0][1] + 1 }",
            vec![load("xs"), member(0), member(1)],
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 3 }]; let value: Int = items[0].count + 1; value }",
            vec![load("items"), member(0), field("count")],
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 3 }]; items[0].count + items[0].count }",
            vec![
                load("items"),
                member(0),
                field("count"),
                load("items"),
                member(0),
                field("count"),
            ],
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; discard xs[0] == 1; 0 }",
            vec![load("xs"), member(0)],
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted operand must publish a program")
        });
        let shapes = program
            .workflows()
            .iter()
            .map(|workflow| {
                workflow
                    .instructions
                    .iter()
                    .filter_map(|instruction| match &instruction.kind {
                        InstructionKind::Load(name) => Some(format!("load {name}")),
                        InstructionKind::Project(Projection::Member(index)) => {
                            Some(format!("member {index}"))
                        }
                        InstructionKind::Project(Projection::Field(name)) => {
                            Some(format!("field {name}"))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // The pinned shape is the projection part a workflow starts with; a workflow that returns a
        // binding continues with that binding's own load, which this check leaves to its own lane.
        let lowered = shapes
            .iter()
            .any(|shape| shape.len() >= expected.len() && shape[..expected.len()] == expected[..]);
        assert!(
            lowered,
            "source: {source}: the operand must lower as {expected:?}; shapes: {shapes:?}"
        );
    }

    // A non-literal index still refuses instead of taking the receiver's type as its operand.
    let source = "fn main() -> Int { let i: Int = 1; let xs: List<Int> = [1, 2]; xs[i] + 1 }";
    root.write(source);
    let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
        .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
    let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
        panic!("source: {source}; type analysis failed internally: {error:?}")
    });
    assert_eq!(
        refused.status(),
        AnalysisStatus::Invalid,
        "source: {source}; diagnostics: {:?}",
        refused.diagnostics()
    );
    assert!(
        refused.executable_program().is_none(),
        "source: {source}: a refused operand must not publish a program"
    );
}

/// A grouping around a projected receiver keeps that projection for its member tail.
///
/// The parser offers a grouped receiver as one expression rather than as sibling fragments, so
/// `(bag()[0]).count` reaches the member walk with no top-level index postfix: the analyzer resolves
/// the member through the grouping and the lowering compiles the group's own expression as the
/// value it produces before projecting every tail step from that value. The rows below execute in
/// value, binding, and operand position, and the same walk covers a grouped place receiver and a
/// grouped free call, while a grouped projection used as a value still refuses with the published
/// type diagnostic (`GNT-GP-VALUE-010`).
#[test]
fn public_grouped_projection_receiver_tails_are_typed_and_lowered() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("grouped projection tail did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected) in [
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { (bag()[0]).count }",
            41i64,
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { ((bag())[0]).count }",
            41,
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { let v: Int = (bag()[0]).count; v + 1 }",
            42,
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { (bag()[0]).count + 1 }",
            42,
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { (bag()[0]).count + (bag()[0]).count }",
            82,
        ),
        (
            "struct It { count: Int } struct Pair { inner: It } fn main() -> Int { let p: Pair = Pair { inner: It { count: 41 } }; (p.inner).count }",
            41,
        ),
        (
            "struct It { count: Int } fn main() -> Int { let v: It = It { count: 41 }; ((v)).count }",
            41,
        ),
        (
            "struct It { count: Int } struct Pair { inner: It } fn main() -> Int { let p: Pair = Pair { inner: It { count: 41 } }; [(p.inner).count][0] }",
            41,
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn head(items: List<It>) -> It { items[0] } fn main() -> Int { (head(bag())).count }",
            41,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted
            .executable_program()
            .unwrap_or_else(|| panic!("source: {source}: an admitted tail must publish a program"));
        let kinds = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .map(|instruction| &instruction.kind)
            .collect::<Vec<_>>();
        // The grouped receiver is compiled as the value it produces and the tail projects the
        // member from that value: a callee is never loaded as the receiver of the tail.
        assert!(
            !kinds.iter().any(|kind| matches!(kind, InstructionKind::Load(name) if name.as_ref() == "bag" || name.as_ref() == "head")),
            "source: {source}: a callee must not be loaded as a receiver"
        );
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                InstructionKind::Project(Projection::Field(field)) if field.as_ref() == "count"
            )),
            "source: {source}: the tail must publish the member projection"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x43; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }

    // A grouped projection that is the whole value is not a member tail and keeps its refusal.
    for (source, code) in [
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { (bag()[0]) }",
            "type-mismatch",
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { (bag()[0]).missing }",
            "unknown-member",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "source: {source}: expected {code}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused tail must not publish a program"
        );
    }
}

/// A call whose argument carries a projection is lowered as one call in either operand position.
///
/// The parser hands `f(xs[0])` either as sibling fragments or as one expression node, and the
/// projection it carries belongs to that argument rather than to the call's result. The lowering
/// compiles the argument once and emits exactly one call for the source call, so an enclosing
/// operator observes the call's result in both operand positions; the shapes below pin the value
/// and the single call instruction per source call (`GNT-GP-VALUE-009`).
#[test]
fn public_call_arguments_that_project_lower_as_one_call() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("projected call argument did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected, calls) in [
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f(xs[0]) + 1 }",
            12i64,
            1usize,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + f(xs[0]) }",
            12,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f(xs[0]) }",
            11,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f(f(xs[0])) + 1 }",
            22,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; let y: Int = f(xs[0]); y + 1 }",
            12,
            1,
        ),
        (
            "fn f(a: Int, b: Int) -> Int { a + b + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; let ys: List<Int> = [1, 2]; f(xs[0], ys[0]) + 1 }",
            13,
            1,
        ),
        (
            "fn f(a: Int, b: Int) -> Int { a + b + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; let ys: List<Int> = [1, 2]; 1 + f(xs[0], ys[0]) }",
            13,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { f([1, 2][0]) + 1 }",
            12,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f((xs)[0]) + 1 }",
            12,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { 1 + f(1) }",
            12,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { f(1) + 1 }",
            12,
            1,
        ),
        (
            "struct It { count: Int } fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let it: It = It { count: 1 }; f(it.count) + 1 }",
            12,
            1,
        ),
        (
            "struct It { count: Int } fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let it: It = It { count: 1 }; 1 + f(it.count) }",
            12,
            1,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted
            .executable_program()
            .unwrap_or_else(|| panic!("source: {source}: an admitted call must publish a program"));
        let emitted = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .filter(|instruction| matches!(instruction.kind, InstructionKind::Call { .. }))
            .count();
        assert_eq!(
            emitted, calls,
            "source: {source}: the source call must be lowered exactly {calls} time(s)"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x51; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
}

/// A call in the middle operand of an additive chain is typed and lowered as one call.
///
/// The parser wraps one operand in an operator-free `BinaryExpression` node when a chain folds
/// around it, so the middle operand of `1 + f(1) + f(2)` is that wrapper rather than the call
/// expression a two-term chain carries. The lowering descends to the wrapped expression and
/// compiles it as the operand slice, which leaves the operand calls on the stack in source order
/// and emits one `Call` per source call; before the repair the wrapper was read as a call
/// sequence, so the operand call was emitted with no argument and the analyzer rejected its own
/// program internally (`GNT-GP-VALUE-012`).
#[test]
fn public_middle_operand_calls_in_additive_chains_are_typed_and_lowered() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("middle-operand call did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected, calls) in [
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { 1 + f(1) + f(2) }",
            24i64,
            2usize,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + f(xs[0]) + f(xs[1]) }",
            24,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f(xs[0]) + f(xs[1]) + 1 }",
            24,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + f(xs[0]) + 1 }",
            13,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { 1 + f(1) + f(2) + f(3) }",
            37,
            3,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { 1 + 2 + f(1) }",
            14,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { 1 * f(1) + f(2) }",
            23,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { 1 + f(1) - f(2) }",
            0,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let x: Int = 5; x + f(1) + f(2) }",
            28,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f(xs[0]) + 1 + f(xs[1]) }",
            24,
            2,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + 1 + f(xs[0]) }",
            13,
            1,
        ),
        (
            "fn f(x: Int) -> Int { x + 10 } fn main() -> Int { let xs: List<Int> = [1, 2]; f(xs[0]) + f(xs[1]) }",
            23,
            2,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted
            .executable_program()
            .unwrap_or_else(|| panic!("source: {source}: an admitted call must publish a program"));
        let emitted = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .filter(|instruction| matches!(instruction.kind, InstructionKind::Call { .. }))
            .count();
        assert_eq!(
            emitted, calls,
            "source: {source}: the source call must be lowered exactly {calls} time(s)"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x52; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
}

/// A computed projection receiver in operand position is typed and lowered as its element.
///
/// An operator receives the projection of a computed receiver either as sibling fragments or as
/// one nested expression. The analyzer types that operand as the element of the receiver part
/// (grouping parenthesis, a receiver call such as `b.all()[0]`, or a free call such as
/// `head(xs)[0]` in either operand position) and the lowering leaves the receiver value on the
/// stack immediately before its member projection, which the shape and execution checks below pin
/// per row. The shapes the operand walk cannot key yet refuse with a published type diagnostic and
/// publish no program instead of failing inside the evaluator (`GNT-GP-VALUE-007`,
/// `GNT-GP-VALUE-008`).
#[test]
fn public_computed_projection_receiver_operands_are_typed_and_lowered() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("computed projection operand did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected) in [
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; (xs)[0] + 1 }",
            2i64,
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; ((xs))[0] + 1 }",
            2,
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; (xs)[0] + (xs)[1] }",
            3,
        ),
        (
            "fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + (xs)[0] }",
            2,
        ),
        (
            "fn head(xs: List<Int>) -> List<Int> { xs } fn main() -> Int { let xs: List<Int> = [1, 2]; 1 + head(xs)[0] }",
            2,
        ),
        (
            "struct Bag { items: List<Int> } impl Bag { fn all(self) -> List<Int> { self.items } } fn main() -> Int { let b: Bag = Bag { items: [1, 2] }; b.all()[0] + 1 }",
            2,
        ),
        (
            "struct Bag { items: List<Int> } impl Bag { fn all(self) -> List<Int> { self.items } } fn main() -> Int { let b: Bag = Bag { items: [1, 2] }; b.all()[1] + 1 }",
            3,
        ),
        (
            "struct Bag { items: List<Int> } impl Bag { fn all(self) -> List<Int> { self.items } } fn main() -> Int { let b: Bag = Bag { items: [1, 2] }; b.all()[0] + b.all()[1] }",
            3,
        ),
        (
            "fn head(xs: List<Int>) -> List<Int> { xs } fn main() -> Int { let xs: List<Int> = [1, 2]; head(xs)[0] + 1 }",
            2,
        ),
        (
            "fn head(xs: List<Int>) -> List<Int> { xs } fn main() -> Int { let xs: List<Int> = [1, 2]; head(xs)[0] + head(xs)[1] }",
            3,
        ),
        (
            "struct It { count: Int } fn bag() -> List<It> { [It { count: 41 }] } fn main() -> Int { bag()[0].count + 1 }",
            42,
        ),
        (
            "struct Item { count: Int } fn main() -> Int { let items: List<Item> = [Item { count: 3 }]; (items)[0].count + 1 }",
            4,
        ),
        (
            "fn main() -> Int { let xs: List<List<Int>> = [[1, 2], [3]]; (xs)[0][1] + 1 }",
            3,
        ),
        // A literal receiver is a value of its own, so its projection is the element it names:
        // the operand was refused while the receiver had no element type, and it now reads the
        // element the index expression selects.
        ("fn main() -> Int { [1, 2][0] + 1 }", 2),
        ("fn main() -> Int { [1, 2][1] + 1 }", 3),
        ("fn main() -> Int { [[1, 2], [3]][0][1] }", 2),
        ("fn main() -> Int { [[1, 2], [3]][1][0] }", 3),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted operand must publish a program")
        });
        let kinds = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .map(|instruction| &instruction.kind)
            .collect::<Vec<_>>();
        // The receiver part is never loaded as a callee name, and the operand carries the member
        // projection of the element it reads.
        assert!(
            !kinds
                .iter()
                .any(|kind| matches!(kind, InstructionKind::Load(name) if name.as_ref() == "head" || name.as_ref() == "bag")),
            "source: {source}: a callee must not be loaded as a receiver"
        );
        assert!(
            kinds
                .iter()
                .any(|kind| matches!(kind, InstructionKind::Project(Projection::Member(_)))),
            "source: {source}: the operand must publish a member projection"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x42; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }

    // A shape the operand walk cannot key yet refuses precisely and publishes no program.
    for (source, code) in [
        (
            "fn main() -> Int { let i: Int = 1; i[0] + 1 }",
            "projection-receiver-type",
        ),
        (
            "fn main() -> Int { (1 + 2)[0] + 1 }",
            "projection-receiver-type",
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "source: {source}: expected {code}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused operand must not publish a program"
        );
    }
}

/// A comparison of list literals is typed and lowered as the list values it compares.
///
/// An operator splits its operands into sibling fragments, so a literal operand reaches the
/// comparison without the wrapper expression the aggregate arm keys on. A multi-member literal had
/// no arm of its own and aborted the lowering with an internal error, while a single-member literal
/// fell through to that member alone, so `[1] == [1]` published `1 == [1]` and answered `false`.
/// Every row below pins an admitted spelling, the value it computes, and the list aggregate the
/// entry workflow publishes; the projection rows pin the element a literal receiver indexes
/// (`8697c9b8`).
#[test]
fn public_list_literal_comparisons_are_typed_and_lowered() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("a list-literal comparison did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    enum Expected {
        Bool(bool),
        Int(i64),
    }

    // The four admitted controls come last: the one-member comparisons are the rows that answered
    // the wrong value while a literal operand resolved to its first member.
    let rows: [(&str, Expected); 30] = [
        (
            "fn main() -> Bool { [1, 2] == [1, 2] }",
            Expected::Bool(true),
        ),
        ("fn main() -> Bool { [1, 2] == [1] }", Expected::Bool(false)),
        (
            "fn main() -> Bool { [1, 2, 3] == [1, 2, 3] }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Bool { [1, 2] != [1, 2] }",
            Expected::Bool(false),
        ),
        (
            "fn main() -> Bool { ([1, 2] == [1, 2]) }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Bool { let b: Bool = [1, 2] == [1, 2]; b }",
            Expected::Bool(true),
        ),
        ("fn main() -> Bool { [1, 2][0] == 1 }", Expected::Bool(true)),
        ("fn main() -> Bool { [1, 2][1] == 2 }", Expected::Bool(true)),
        ("fn main() -> Bool { 1 == [1, 2][0] }", Expected::Bool(true)),
        ("fn main() -> Bool { [1, 2][0] < 2 }", Expected::Bool(true)),
        (
            "fn main() -> Bool { [[1, 2], [3]][0][1] == 2 }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Bool { [[1, 2], [3]][1][0] == 3 }",
            Expected::Bool(true),
        ),
        ("fn main() -> Bool { [1] == [1] }", Expected::Bool(true)),
        ("fn main() -> Bool { [1] != [1] }", Expected::Bool(false)),
        ("fn main() -> Bool { [1] == [1, 2] }", Expected::Bool(false)),
        ("fn main() -> Bool { [1] == [2] }", Expected::Bool(false)),
        (
            "fn main() -> Bool { [[1], [2]] == [[1], [2]] }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Bool { let a: List<Int> = [1, 2]; let b: List<Int> = [1, 2]; a == b }",
            Expected::Bool(true),
        ),
        ("fn main() -> Bool { [1].len() == 1 }", Expected::Bool(true)),
        // A member that is itself a constructed value is the aggregate arm's own shape, so the
        // literal must own the node before that arm can claim the member the literal contains.
        (
            "struct Item { count: Int } fn main() -> Bool { [Item { count: 1 }] == [Item { count: 1 }] }",
            Expected::Bool(true),
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { [Item { count: 1 }] != [Item { count: 1 }] }",
            Expected::Bool(false),
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { [Item { count: 1 }] == [Item { count: 2 }] }",
            Expected::Bool(false),
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { [Item { count: 1 }, Item { count: 2 }] == [Item { count: 1 }, Item { count: 2 }] }",
            Expected::Bool(true),
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { let a: List<Item> = [Item { count: 1 }]; [Item { count: 1 }] == a }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Bool { [(1, 2)] == [(1, 2)] }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Bool { [\"a\"] == [\"a\"] }",
            Expected::Bool(true),
        ),
        (
            "fn main() -> Int { discard [1, 2] == [1, 2]; 1 }",
            Expected::Int(1),
        ),
        (
            "fn main() -> Int { discard [1, 2] != [1, 2]; 1 }",
            Expected::Int(1),
        ),
        (
            "fn main() -> Int { discard ([1, 2] == [1, 2]); 1 }",
            Expected::Int(1),
        ),
        (
            "fn main() -> Int { let b: Bool = [1, 2] == [1, 2]; discard b; 1 }",
            Expected::Int(1),
        ),
    ];
    let root = TempDirectory::new();
    for (source, expected) in rows {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted comparison must publish a program")
        });
        assert!(
            program
                .workflows()
                .iter()
                .flat_map(|workflow| workflow.instructions.iter())
                .any(|instruction| matches!(
                    instruction.kind,
                    InstructionKind::Aggregate {
                        kind: AggregateKind::List,
                        ..
                    }
                )),
            "source: {source}: the comparison must publish the list value its operands build"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x42; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        let observed = match (value.view(), expected) {
            (LogicalValueView::Bool(actual), Expected::Bool(want)) => actual == want,
            (LogicalValueView::Int(actual), Expected::Int(want)) => actual.get() == want,
            (view, _) => panic!("source: {source}: unexpected value {view:?}"),
        };
        assert!(observed, "source: {source}: unexpected value {value:?}");
    }
}

/// An argument the call walk cannot type reports the code that names the literal it drops.
///
/// A parameter type that is not concrete cannot type its argument, so an empty list literal in that
/// position kept no type at all and the call lowering aborted with an internal error (`id([])` for
/// `fn id<T>(x: T) -> T`, `S {}.id([])` for a generic method), while a literal whose parameter type
/// is known stayed admitted (`take_list([])`). The free, receiver-method, trait, generic, and
/// action argument walks now report the registered `untyped-list-literal` code for the literal they
/// cannot type, and the admitted controls below keep executing their exact argument values.
#[test]
fn public_untyped_list_literal_arguments_report_their_code() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("an admitted list-literal argument did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected) in [
        (
            "fn take_list(items: List<Int>) -> List<Int> { items } fn main() -> Int { discard take_list([]); 1 }",
            1i64,
        ),
        (
            "fn id<T>(x: T) -> T { x } fn main() -> Int { discard id([1, 2]); 1 }",
            1,
        ),
        ("fn main() -> Int { discard []; 1 }", 1),
        // A receiver method's declared parameter types are known before resolution, so its
        // argument is typed by the parameter it fills exactly as the free call's is.
        (
            "struct S {} impl S { fn take(self, xs: List<Int>) -> List<Int> { xs } } fn main() -> Int { discard S {}.take([]); 1 }",
            1,
        ),
        (
            "struct S {} impl S { fn take(self, xs: List<Int>) -> List<Int> { xs } } fn main() -> Int { discard S {}.take([1, 2]); 1 }",
            1,
        ),
        // The trait spelling supplies its declared parameters from the visible contracts, so its
        // argument is typed exactly as the inherent and free calls type theirs.
        (
            "trait T { pure fn take(self, xs: List<Int>) -> List<Int>; } struct S {} impl T for S { fn take(self, xs: List<Int>) -> List<Int> { xs } } fn main() -> Int { discard S {}.take([]); 1 }",
            1,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted argument must publish a program")
        });
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x42; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }

    // Every argument walk that cannot type an untypeable literal reports the registered code and
    // publishes no program; a concrete parameter the argument does not satisfy reports the
    // call-argument code from the same walk.
    let method_generic = "struct S {} impl S { fn id<T>(self, x: T) -> T { x } }";
    let trait_generic = "trait Id { pure fn id<T>(self, x: T) -> T; } struct S {} impl Id for S { fn id<T>(self, x: T) -> T { x } }";
    for (source, code) in [
        (
            "fn id<T>(x: T) -> T { x } fn main() -> Int { discard id([]); 1 }".to_string(),
            "untyped-list-literal",
        ),
        (
            format!("{method_generic} fn main() -> Int {{ discard S {{}}.id([]); 1 }}"),
            "untyped-list-literal",
        ),
        (
            format!("{trait_generic} fn main() -> Int {{ discard S {{}}.id([]); 1 }}"),
            "untyped-list-literal",
        ),
        (
            "trait T { pure fn take(self, xs: List<Int>) -> List<Int>; } struct S {} impl T for S { fn take(self, xs: List<Int>) -> List<Int> { xs } } fn main() -> Int { discard S {}.take(1); 1 }".to_string(),
            "call-argument-type",
        ),
        (
            "struct S {} impl S { fn take(self, xs: List<Int>) -> List<Int> { xs } } fn main() -> Int { discard S {}.take(1); 1 }".to_string(),
            "call-argument-type",
        ),
    ] {
        root.write(&source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let refused = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "source: {source}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "source: {source}: expected {code}; diagnostics: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused.executable_program().is_none(),
            "source: {source}: a refused argument must not publish a program"
        );
    }
}

/// A comparison of declared values is typed and lowered as the values it compares.
///
/// `Equatable` admits `==`/`!=` for a declared struct, but an operator splits its operands into
/// sibling fragments: `Item { count: 1 } == Item { count: 1 }` reaches the walk as the constructor's
/// name path beside the struct expression, so the name was published as a binding load and the
/// fields aggregated with no type of their own - the machine then failed on the missing binding
/// (`runtime-failure[internal-invariant-failure]`), and a nested literal aggregated under `Unit`.
/// Every row below pins the value the comparison computes; the list row is the already-working
/// control the direct spelling must agree with (`68d62b63`).
#[test]
fn public_declared_value_comparisons_are_typed_and_lowered() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("a declared-value comparison did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    for (source, expected) in [
        (
            "struct Item { count: Int } fn main() -> Bool { Item { count: 1 } == Item { count: 1 } }",
            true,
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { Item { count: 1 } != Item { count: 1 } }",
            false,
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { Item { count: 1 } == Item { count: 2 } }",
            false,
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { let a: Item = Item { count: 1 }; let b: Item = Item { count: 1 }; a == b }",
            true,
        ),
        (
            "struct Pair { left: Int, right: Bool } fn main() -> Bool { Pair { left: 1, right: true } == Pair { left: 1, right: true } }",
            true,
        ),
        (
            "struct Inner { flag: Bool } struct Outer { inner: Inner } fn main() -> Bool { Outer { inner: Inner { flag: true } } == Outer { inner: Inner { flag: true } } }",
            true,
        ),
        (
            "struct Item { count: Int } fn main() -> Bool { [Item { count: 1 }] == [Item { count: 1 }] }",
            true,
        ),
    ] {
        root.write(source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted comparison must publish a program")
        });
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x42; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Bool(actual) if actual == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
}

/// A builtin member call publishes the primitive that implements it.
///
/// The runtime primitives were machine-tested but no source spelling reached them: a builtin
/// member call was typed by the analyzer and then lowered by the generic fragment walk, which
/// published a program the machine rejected (`xs.len()` failed on a runtime invariant). Each row
/// below asserts the primitives the entry workflow publishes and executes its value; a receiver
/// that is neither a place, a constructed value, nor a literal is refused (`90da59aa`,
/// `dbb4c60`).
#[test]
fn public_builtin_member_calls_publish_their_primitive() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("a builtin member call did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    let root = TempDirectory::new();
    let entries: [(&str, i64, &[Primitive]); 29] = [
        (
            "let xs: List<Int> = [1, 2, 3]; xs.len()",
            3,
            &[Primitive::ListLength],
        ),
        (
            "let s: String = \"abc\"; s.len()",
            3,
            &[Primitive::StringLength],
        ),
        ("\"abc\".len()", 3, &[Primitive::StringLength]),
        (
            "let n: Int = 3; let t: String = n.to_string(); t.len()",
            1,
            &[Primitive::ToString, Primitive::StringLength],
        ),
        (
            "let s: String = \"  a  \"; let t: String = s.trim(); t.len()",
            1,
            &[Primitive::StringTrim, Primitive::StringLength],
        ),
        (
            "let s: String = \"ab\"; let t: String = s.replace(\"a\", \"z\"); t.len()",
            2,
            &[Primitive::StringReplace, Primitive::StringLength],
        ),
        (
            "let s: String = \"abc\"; discard s.contains(\"b\"); 1",
            1,
            &[Primitive::StringContains],
        ),
        (
            "let s: String = \"abc\"; discard s.is_empty(); 1",
            1,
            &[Primitive::StringIsEmpty],
        ),
        (
            "let n: Int = 3; discard n.to_float(); 1",
            1,
            &[Primitive::IntToFloat],
        ),
        (
            "let s: String = \"42\"; discard s.parse_int(); 1",
            1,
            &[Primitive::StringParseInt],
        ),
        (
            "let s: String = \"a,b\"; let parts: List<String> = s.split(\",\"); 1",
            1,
            &[Primitive::StringSplit],
        ),
        // A builtin call in either operand of an operator lowers as the operand the operator
        // consumes.
        (
            "let xs: List<Int> = [1, 2]; xs.len() + 1",
            3,
            &[Primitive::ListLength],
        ),
        (
            "let xs: List<Int> = [1, 2]; 1 + xs.len()",
            3,
            &[Primitive::ListLength],
        ),
        (
            "let xs: List<Int> = [1, 2]; xs.len() * 2",
            4,
            &[Primitive::ListLength, Primitive::Multiply],
        ),
        (
            "let xs: List<Int> = [1, 2]; xs.len() + xs.len()",
            4,
            &[Primitive::ListLength],
        ),
        // A grouping pair around a literal receiver is transparent in operand position too.
        ("(\"abc\").len() + 1", 4, &[Primitive::StringLength]),
        // An aggregate item keeps its own lowering: the literal must not claim the nested call.
        (
            "let xs: List<Int> = [1, 2]; let v: List<Int> = [xs.len()]; v[0]",
            2,
            &[Primitive::ListLength],
        ),
        (
            "let xs: List<Int> = [1, 2]; let v: List<Int> = [xs.len() + 1]; v[0]",
            3,
            &[Primitive::ListLength],
        ),
        // A list literal receiver owns the value its call reads, so the aggregate is published
        // before the primitive in every position, grouped or not (`2e558b5f`).
        ("[1, 2, 3].len()", 3, &[Primitive::ListLength]),
        ("([1, 2, 3]).len()", 3, &[Primitive::ListLength]),
        ("[1, 2, 3].len() + 1", 4, &[Primitive::ListLength]),
        (
            "let n: Int = [1, 2, 3].len(); n",
            3,
            &[Primitive::ListLength],
        ),
        ("discard [1, 2, 3].len(); 3", 3, &[Primitive::ListLength]),
        ("[1 + 1].len()", 1, &[Primitive::ListLength]),
        (
            "let j: String = [\"a\", \"b\"].join(\"-\"); j.len()",
            3,
            &[Primitive::StringListJoin, Primitive::StringLength],
        ),
        // A literal receiver inside a chain keeps its member step and the operator applies to it.
        ("[[1]].len() + [[2]].len()", 2, &[Primitive::ListLength]),
        (
            "[[1]].len() * [[2]].len() + 1",
            2,
            &[Primitive::ListLength, Primitive::Multiply],
        ),
        ("[1 + 1].len() + 1", 2, &[Primitive::ListLength]),
        (
            "let xs: List<Int> = []; xs.len()",
            0,
            &[Primitive::ListLength],
        ),
    ];
    for (body, expected, required) in entries {
        let source = format!("fn main() -> Int {{ {body} }}");
        root.write(&source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: a builtin member call must publish a program")
        });
        let entry = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("invalid entry path: {error}"));
        let instructions = program
            .workflows()
            .iter()
            .filter(|workflow| workflow.path == entry)
            .flat_map(|workflow| workflow.instructions.iter())
            .collect::<Vec<_>>();
        for primitive in required {
            assert!(
                instructions
                    .iter()
                    .any(|instruction| matches!(instruction.kind, InstructionKind::Primitive(value) if value == *primitive)),
                "source: {source}: the program must publish {primitive:?}"
            );
        }
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &entry,
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x56; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
    for body in [
        "(\"a\" + \"b\").len()",
        "let s: String = \"abc\"; s.trim().len()",
        "(1 + 2).to_string().len()",
        "let t: String = (-1).to_string(); t.len()",
        "[\"a\", \"b\"].join(\"-\").len()",
    ] {
        let refused = analyze(&format!("fn main() -> Int {{ {body} }}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics()[0].code.as_str(),
            "receiver-value-place",
            "{body}"
        );
        assert!(refused.executable_program().is_none(), "{body}");
    }
}

/// A receiver part that only mentions a constructed value through an operand is not the value its
/// receiver call reads.
///
/// `take(Item { count: 1 }).len()` reads the list that call returns, and `take(items[0]).len()`
/// reads the list a call with an indexed place returns, so neither part constructs the value its
/// receiver copies. Both aborted internally before this row and now keep the precise refusal an
/// indexed or call receiver already has, while a literal the part does name still executes
/// (`2e558b5f`).
#[test]
fn public_receiver_aggregates_must_be_the_receiver_part_itself() {
    const FIXTURE: &str = "struct Item { count: Int } fn take(item: Item) -> List<Int> { [item.count] } fn take_list(items: List<Int>) -> List<Int> { items } fn add_one(value: Int) -> Int { value + 1 } ";

    for body in [
        "let items: List<Item> = [Item { count: 1 }]; discard take(items[0]).len(); 1",
        "discard take(Item { count: 1 }).len(); 1",
        // A chain whose left operand is a literal receiver still refuses the right operand that
        // only mentions a literal through a call.
        "discard [1, 2].len() + take_list([3]).len(); 1",
        "discard take_list([3]).len() + [1, 2].len(); 1",
    ] {
        let refused = analyze(&format!("{FIXTURE}fn main() -> Int {{ {body} }}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics()[0].code.as_str(),
            "receiver-value-place",
            "{body}"
        );
        assert!(refused.executable_program().is_none(), "{body}");
    }
    // A literal receiver inside a chain keeps its member step: the chain is typed as the operator
    // applied to that step, so the program publishes and the item call is analyzed.
    for body in [
        "[add_one(1)].len() + 1",
        "([add_one(1)]).len() + 1",
        "[Item { count: 1 }].len() + 1",
    ] {
        let admitted = analyze(&format!("{FIXTURE}fn main() -> Int {{ {body} }}"));
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "{body}: {:?}",
            admitted.diagnostics()
        );
        assert!(
            admitted.executable_program().is_some(),
            "{body}: a chain over a literal receiver must publish a program"
        );
    }
    let admitted = analyze(&format!(
        "{FIXTURE}fn main() -> Int {{ [Item {{ count: 1 }}].len() }}"
    ));
    assert_eq!(
        admitted.status(),
        AnalysisStatus::Valid,
        "{:?}",
        admitted.diagnostics()
    );
    // A list literal with no element type of its own is refused wherever its member step sits:
    // statement and initializer positions, either operand of a chain, and through any grouping
    // pair (`ee62b32a`). Each row reports its literal exactly once, and the same literal keeps its
    // admitted spellings where an expected `List<T>` is known.
    for body in [
        "[].len()",
        "discard [].join(\"-\"); 1",
        "let n: Int = [].len(); n",
        "[].len() + 1",
        "let n: Int = [].len() + 1; n",
        "([]).len()",
        "(([])).len()",
    ] {
        let refused = analyze(&format!("fn main() -> Int {{ {body} }}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics().len(),
            1,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert_eq!(
            refused.diagnostics()[0].code.as_str(),
            "untyped-list-literal",
            "{body}"
        );
        assert!(refused.executable_program().is_none(), "{body}");
    }
    // An operator that consumes a list literal needs that operand to have a type of its own, so an
    // untyped literal operand is refused (`aa68886b`). The leftmost untyped operand short-circuits
    // the operation, so a row reports at least one literal — and never an internal failure.
    for body in [
        "discard ([] + []); 1",
        "([] + []).len()",
        "([] + []).len() + 1",
        "(1 + []).len()",
        "([] + [1]).len()",
        "([[]] + [[]]).len()",
        "(([]) + ([])).len()",
        "([] - []).len()",
    ] {
        let refused = analyze(&format!("fn main() -> Int {{ {body} }}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert!(
            !refused.diagnostics().is_empty()
                && refused
                    .diagnostics()
                    .iter()
                    .all(|diagnostic| diagnostic.code.as_str() == "untyped-list-literal"),
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert!(refused.executable_program().is_none(), "{body}");
    }
    for body in [
        "discard []; 0",
        "let xs: List<Int> = []; xs.len()",
        "[[1], []].len()",
        "discard ([1] == [1]); 1",
    ] {
        let admitted = analyze(&format!("fn main() -> Int {{ {body} }}"));
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "{body}: {:?}",
            admitted.diagnostics()
        );
        assert!(
            admitted.executable_program().is_some(),
            "{body}: an admitted empty literal spelling must publish a program"
        );
    }
}

/// A grouping parenthesis is transparent for a receiver call.
///
/// `(p).greet2()` names the same receiver `p.greet2()` does and
/// `(Plain { value: 42 }).greet()` publishes the constructed value before the call, so every
/// grouped spelling below executes: every group pair wrapping the whole receiver part peels
/// (`((w.inner)).greet2()`), and so does every group pair wrapping the root segment of a dotted
/// receiver part (`(w).inner.greet2()`), because neither changes the place the receiver part names
/// (`SPEC.md:3699`). A grouped *index* receiver names a value rather than a place and keeps its
/// refusal, as do a call-result receiver, a grouped `shared self` receiver, and a computed binary
/// receiver (`7e58f733`, `5e20c3b2`, `403bc642`).
#[test]
fn public_grouped_receivers_are_transparent_for_a_receiver_call() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("a grouped receiver call did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    const FIXTURE: &str = "struct Plain { value: Int } struct Wrap { inner: Plain } trait Greet { pure fn greet(self) -> Int; } impl Plain { fn greet2(self) -> Int { self.value } fn add(self, x: Int) -> Int { self.value + x } fn look(shared self) -> Int { self.value } } impl Greet for Plain { pure fn greet(self) -> Int { self.value } } impl Greet for Int { pure fn greet(self) -> Int { 1 } } fn mk() -> Plain { Plain { value: 42 } } struct Counter { value: Int } impl Counter { fn dbl(self) -> Int { self.value } } fn mk_int() -> Int { 7 } ";

    let root = TempDirectory::new();
    for (body, expected) in [
        // The reported row and the grouped inherent spelling of its sibling defect.
        (
            "let p: Plain = Plain { value: 42 }; (Plain { value: 42 }).greet()",
            42i64,
        ),
        ("let p: Plain = Plain { value: 42 }; (p).greet()", 42),
        ("(Plain { value: 42 }).greet2()", 42),
        ("let p: Plain = Plain { value: 42 }; (p).greet2()", 42),
        // A group around a constructed value peels through every further group.
        ("((Plain { value: 42 })).greet()", 42),
        // A nested grouped place names the same place its ungrouped spelling does.
        ("let p: Plain = Plain { value: 42 }; ((p)).greet()", 42),
        ("let p: Plain = Plain { value: 42 }; ((p)).greet2()", 42),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; ((w.inner)).greet2()",
            42,
        ),
        // A group around the root segment of a dotted place names the same field place its
        // ungrouped spelling does, at every depth of nesting and in operand position.
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (w).inner.greet2()",
            42,
        ),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; ((w).inner).greet2()",
            42,
        ),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (((w).inner)).greet2()",
            42,
        ),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (w).inner.greet()",
            42,
        ),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (w).inner.greet() + 1",
            43,
        ),
        // Grouped receivers in operand and argument positions.
        ("let p: Plain = Plain { value: 42 }; (p).greet2() + 1", 43),
        (
            "let p: Plain = Plain { value: 42 }; 1 + (Plain { value: 42 }).greet()",
            43,
        ),
        (
            "let p: Plain = Plain { value: 42 }; p.add((p).greet2())",
            84,
        ),
        // A grouped dotted place names the same struct-field place its ungrouped spelling does.
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (w.inner).greet()",
            42,
        ),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (w.inner).greet2()",
            42,
        ),
        (
            "let w: Wrap = Wrap { inner: Plain { value: 42 } }; (w.inner).greet() + 1",
            43,
        ),
    ] {
        let source = format!("{FIXTURE}fn main() -> Int {{ {body} }}");
        root.write(&source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: a grouped receiver call must publish a program")
        });
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x55; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
    for (body, code) in [
        // A grouped `shared self` receiver needs an admitted caller place.
        (
            "let p: Plain = Plain { value: 42 }; (p).look()",
            "shared-receiver-place",
        ),
        // A grouped call result is still not a place.
        ("(mk()).greet2()", "receiver-value-place"),
        // A computed receiver never reaches a member of its own.
        ("(1 + 2).dbl()", "unknown-member"),
        ("(1 + mk_int()).dbl()", "unknown-member"),
        // A constructed receiver's member step is refused precisely in operand position too: the
        // step used to decline silently there and abort in lowering.
        ("Plain { value: 42 }.absent + 1", "unknown-member"),
        ("Plain { value: 42 }.absent", "unknown-member"),
        // A step the receiver does not have is refused before an index projection reads it.
        ("Plain { value: 42 }.absent[0] + 1", "unknown-member"),
        // A chained projection is typed, so a matching annotation is checked like any other
        // binding: a mismatching one refuses instead of failing the machine after admission.
        (
            "let xs: List<List<Int>> = [[1, 2], [3]]; let v: Bool = xs[0][0 + 1]; 0",
            "type-mismatch",
        ),
        (
            "let xs: List<List<Int>> = [[1, 2], [3]]; let v: List<Int> = xs[0][0 + 1]; 0",
            "type-mismatch",
        ),
        (
            "let xs: List<List<Int>> = [[1, 2], [3]]; let v: Unit = xs[0][0 + 1]; 0",
            "type-mismatch",
        ),
        // An operand position has no lowering route for that chain, so the enclosing operator's own
        // refusal stays the verdict there.
        (
            "let xs: List<List<Int>> = [[1, 2], [3]]; xs[0][0 + 1] == 2",
            "invalid-primitive",
        ),
        // A later tuple step needs a literal index exactly as the first one does: the element type
        // must be statically known, so a computed index is refused rather than left untyped.
        (
            "let t: Tuple<Tuple<Int, Int>, Tuple<Int, Int>> = ((1, 2), (3, 4)); let v: Bool = t[1][0 + 0]; 0",
            "tuple-index-not-literal",
        ),
        (
            "let t: Tuple<Tuple<Int, Int>, Tuple<Int, Int>> = ((1, 2), (3, 4)); let v: Int = t[1][0 + 0]; v",
            "tuple-index-not-literal",
        ),
        (
            "let t: Tuple<Tuple<Int, Int>, Tuple<Int, Int>> = ((1, 2), (3, 4)); t[1][0 + 0]",
            "tuple-index-not-literal",
        ),
        // A computed receiver is refused even when the member resolves for its type.
        ("(1 + 2).greet()", "receiver-value-place"),
        ("(1 + mk_int()).greet() + 1", "receiver-value-place"),
        // A literal receiver is not a place, a struct-field place, or a constructed value.
        ("42.greet()", "receiver-value-place"),
        ("(42).greet()", "receiver-value-place"),
        // A grouped index receiver is a value rather than a place, computed or not.
        (
            "let xs: List<Int> = [42]; (xs[0]).greet()",
            "receiver-value-place",
        ),
        (
            "let xs: List<Int> = [42]; (xs[mk_int()]).greet()",
            "receiver-value-place",
        ),
    ] {
        let refused = analyze(&format!("{FIXTURE}fn main() -> Int {{ {body} }}"));
        assert_eq!(
            refused.status(),
            AnalysisStatus::Invalid,
            "{body}: {:?}",
            refused.diagnostics()
        );
        assert!(
            refused
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_str() == code),
            "{body}: expected {code}, observed {:?}",
            refused.diagnostics()
        );
        assert!(refused.executable_program().is_none(), "{body}");
    }
}

/// A field projection whose receiver part is a call result publishes that call and then the field.
///
/// `p.flip().value` reads a field of the temporary the receiver call returns rather than a caller
/// place, and `head(items).count` reads the field of a free call result, so each spelling below
/// must lower one call per source call followed by one field projection instead of failing on a
/// runtime invariant (`1142adea`).
#[test]
fn public_field_projection_on_a_call_result_publishes_call_then_field() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("projected call result did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    const FIXTURE: &str = "struct Plain { value: Int } impl Plain { fn flip(self) -> Plain { self } fn add(self, x: Int) -> Int { self.value + x } } fn mk() -> Plain { Plain { value: 42 } } struct Bag { count: Int } fn head(items: List<Bag>) -> Bag { items[0] } ";

    let root = TempDirectory::new();
    for (body, expected, receiver_calls, plain_calls) in [
        // The reported row: a receiver call whose result is projected.
        (
            "let p: Plain = Plain { value: 42 }; p.flip().value",
            42i64,
            1usize,
            0usize,
        ),
        // A free-call receiver as a value and as an operand, and a list element result.
        ("mk().value", 42, 0, 1),
        ("mk().value + 1", 43, 0, 1),
        (
            "let items: List<Bag> = [Bag { count: 7 }]; head(items).count",
            7,
            0,
            1,
        ),
        // A grouped call result is the same receiver.
        (
            "let p: Plain = Plain { value: 42 }; (p.flip()).value",
            42,
            1,
            0,
        ),
        // The projected call in operand, argument, and initializer positions.
        (
            "let p: Plain = Plain { value: 42 }; p.flip().value + 1",
            43,
            1,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; 1 + p.flip().value",
            43,
            1,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; p.add(p.flip().value)",
            84,
            2,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; let v: Int = p.flip().value; v",
            42,
            1,
            0,
        ),
    ] {
        let source = format!("{FIXTURE}fn main() -> Int {{ {body} }}");
        root.write(&source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: a projected call result must publish a program")
        });
        let entry = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("invalid entry path: {error}"));
        let entry_instructions = program
            .workflows()
            .iter()
            .filter(|workflow| workflow.path == entry)
            .flat_map(|workflow| workflow.instructions.iter())
            .collect::<Vec<_>>();
        let receiver_emitted = entry_instructions
            .iter()
            .filter(|instruction| matches!(instruction.kind, InstructionKind::ReceiverCall { .. }))
            .count();
        let call_emitted = entry_instructions
            .iter()
            .filter(|instruction| matches!(instruction.kind, InstructionKind::Call { .. }))
            .count();
        let field_emitted = entry_instructions
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction.kind,
                    InstructionKind::Project(Projection::Field(_))
                )
            })
            .count();
        assert_eq!(
            (receiver_emitted, call_emitted, field_emitted),
            (receiver_calls, plain_calls, 1),
            "source: {source}: receiver calls {receiver_emitted} (want {receiver_calls}), plain calls {call_emitted} (want {plain_calls}), field projections {field_emitted}"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x54; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
    // A receiver chain of two calls still refuses the inner call-result receiver, so the executed
    // rows above never depend on an admitted chain (`GNT-GP-VALUE-005-FU`).
    let refused = analyze(&format!(
        "{FIXTURE}fn main() -> Int {{ let p: Plain = Plain {{ value: 42 }}; p.flip().flip().value }}"
    ));
    assert_eq!(
        refused.status(),
        AnalysisStatus::Invalid,
        "{:?}",
        refused.diagnostics()
    );
    assert_eq!(
        refused.diagnostics()[0].code.as_str(),
        "receiver-value-place"
    );
    assert!(refused.executable_program().is_none());
}

/// An operator to the right of a receiver call is an ordinary operand.
///
/// The parser splits a leading receiver call into sibling fragments, so the lowering resolves that
/// call before its enclosing primitive consumes the result. A trait method's recorded call site is
/// the member name those fragments spell rather than the call sequence an inherent method records,
/// and a grouped receiver spells its root inside parentheses, so every spelling below must lower
/// exactly one call instruction per source call - the receiver-call form for an operand whose
/// receiver is a place, and the plain call form a value position already used - instead of failing
/// inside the analyzer (`GNT-GP-VALUE-005`).
#[test]
fn public_operator_after_receiver_call_lowers_the_call_as_the_operand() {
    use std::sync::Arc;

    use gantry::identity::ProtocolIdentity;
    use gantry::ir::CanonicalPath;
    use gantry::portable::IdentityKind;
    use gantry::runtime::{Machine, MachineLimits, MachineStep};
    use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

    fn drive(machine: &mut Machine) -> LogicalValue {
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::WaitingSessionScope(scope) => {
                    panic!("unexpected session-scope wait: {:?}", scope.site)
                }
                MachineStep::WaitingOperation(operation) => {
                    panic!("unexpected operation wait: {}", operation.identity)
                }
                MachineStep::Complete(outcome) => {
                    let gantry::runtime::MachineOutcome::Succeeded(value) = outcome else {
                        panic!("receiver-call operand did not execute: {outcome:?}");
                    };
                    return value;
                }
            }
        }
        panic!("machine did not terminate within the fixture bound")
    }

    const RECEIVERS: &str = "struct Plain { value: Int } trait Greet { pure fn greet(self) -> Int; } impl Greet for Plain { pure fn greet(self) -> Int { self.value } } impl Plain { fn greet2(self) -> Int { self.value } fn add(self, x: Int) -> Int { self.value + x } } ";

    let root = TempDirectory::new();
    for (body, expected, receiver_calls, plain_calls) in [
        (
            "let p: Plain = Plain { value: 42 }; p.greet() + 1",
            43i64,
            1usize,
            0usize,
        ),
        (
            "let p: Plain = Plain { value: 42 }; 1 + p.greet()",
            43,
            1,
            0,
        ),
        ("let p: Plain = Plain { value: 42 }; p.greet()", 42, 1, 0),
        (
            "let p: Plain = Plain { value: 42 }; (p).greet() + 1",
            43,
            1,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; (p).greet() + (p).greet()",
            84,
            // Both grouped receivers lower as receiver calls: grouping is transparent, so a
            // grouped receiver no longer reaches the plain-call path that passed the receiver
            // as an argument.
            2,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; let xs: List<Int> = [p.greet() + 1]; xs[0]",
            43,
            1,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; let q: Plain = Plain { value: 1 }; p.greet() + q.greet()",
            43,
            2,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; p.greet2() + 1",
            43,
            1,
            0,
        ),
        (
            "let p: Plain = Plain { value: 42 }; p.add(p.greet()) + 1",
            85,
            2,
            0,
        ),
        ("let p: Plain = Plain { value: 42 }; p.add(1) + 1", 44, 1, 0),
    ] {
        let source = format!("{RECEIVERS}fn main() -> Int {{ {body} }}");
        root.write(&source);
        let syntax = validate_package_syntax(&root.0, limits(), i64::MAX as u64)
            .unwrap_or_else(|error| panic!("source: {source}; syntax phase failed: {error:?}"));
        let admitted = analyze_package_types(&syntax).unwrap_or_else(|error| {
            panic!("source: {source}; type analysis failed internally: {error:?}")
        });
        assert_eq!(
            admitted.status(),
            AnalysisStatus::Valid,
            "source: {source}; diagnostics: {:?}",
            admitted.diagnostics()
        );
        let program = admitted.executable_program().unwrap_or_else(|| {
            panic!("source: {source}: an admitted receiver call must publish a program")
        });
        let receiver_emitted = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .filter(|instruction| matches!(instruction.kind, InstructionKind::ReceiverCall { .. }))
            .count();
        let call_emitted = program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .filter(|instruction| matches!(instruction.kind, InstructionKind::Call { .. }))
            .count();
        assert_eq!(
            (receiver_emitted, call_emitted),
            (receiver_calls, plain_calls),
            "source: {source}: receiver calls {receiver_emitted} (want {receiver_calls}), plain calls {call_emitted} (want {plain_calls})"
        );
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("invalid entry path: {error}")),
            Vec::new(),
            ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x53; 32])
                .unwrap_or_else(|error| panic!("invalid fixture identity: {error}")),
            MachineLimits::new(256, 64, 16, 16, 16, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("fixture limits are positive")),
        )
        .unwrap_or_else(|error| panic!("source: {source}; machine construction failed: {error:?}"));
        let value = drive(&mut machine);
        assert!(
            matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected),
            "source: {source}: expected {expected}, observed {value:?}"
        );
    }
}
