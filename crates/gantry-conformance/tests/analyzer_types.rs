//! Public-facade conformance for analyzer type and receiver semantics.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{
    AnalysisError, AnalysisStatus, analyze_package_types, analyze_package_types_with_limits,
};
use gantry::frontend::validate_package_syntax;
use gantry::portable::FrontendResourceCode;
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
    analyze_package_types(&syntax).unwrap_or_else(|error| panic!("type analysis failed: {error:?}"))
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
            "must-consume-path-dependent",
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

    for source in [
        "fn run(token: Token, flag: Bool) -> Int { if flag { discard token.consume(); } 0 }",
        "fn run(token: Token) { loop(limit = 1) { token.consume(); break; } }",
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
