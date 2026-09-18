//! Public regression coverage for the analyzer-to-runtime executable handoff.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::identity::ProtocolIdentity;
use gantry::ir::{OwnershipClass, ReceiverSource};
use gantry::numeric::GantryInt;
use gantry::portable::IdentityKind;
use gantry::runtime::{
    CanonicalTranscriptV1, ConcurrentTaskStateV1, ExecutionBudget, InstructionKind,
    LogicalSessionRegistryV1, Machine, MachineBuildError, MachineLabel, MachineLimits,
    MachineOutcome, MachineStep, OperationCompletionError, RuntimeCode, SessionCreationModeV1,
    TaskCaptureV1, TaskCreationRequestV1, root_task_identity,
};
use gantry::source::SourceLimits;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};
use serde::Deserialize;

const RUNTIME_EVIDENCE_PATH: &str = "protocol/conformance/generics-traits-runtime-v1.json";

#[derive(Debug, Deserialize)]
struct RuntimeEvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    profile: String,
    entries: Vec<RuntimeEvidenceEntry>,
    advertises_profiles: Vec<String>,
    exclusions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimeEvidenceEntry {
    requirement: String,
    clause: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<ReviewedRequirement>,
}

#[derive(Debug, Deserialize)]
struct ReviewedRequirement {
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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(source: &str) -> Self {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gantry-executable-bridge-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("could not create {}: {error}", path.display()));
        fs::write(path.join("main.gnt"), source)
            .unwrap_or_else(|error| panic!("could not write executable fixture: {error}"));
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn reviewed_generic_runtime_evidence_is_closed() {
    let root = workspace_root();
    let manifest: RuntimeEvidenceManifest = read_json(&root.join(RUNTIME_EVIDENCE_PATH));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(
        manifest.format,
        "gantry.generics-traits-runtime-evidence/v1"
    );
    assert_eq!(manifest.issue, "GNT-GEN-RUN-001");
    assert_eq!(manifest.profile, "evaluator");
    let evidence_is_current = manifest.specification_sha256 == review.specification_sha256;
    assert!(gantry_conformance::evidence_revision_is_expected(
        &manifest.specification_sha256,
        &review.specification_sha256,
    ));
    assert!(evidence_is_current || gantry::advertised_profiles().is_empty());
    assert_eq!(manifest.entries.len(), 27);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(manifest.advertises_profiles, ["evaluator"]);
    assert_eq!(manifest.exclusions.len(), 3);
    assert!(gantry::advertised_profiles().contains(&gantry::ConformanceProfile::Evaluator));

    for entry in manifest.entries {
        assert_anchor_exists(&root, &entry.evidence);
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
        let evaluator = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == "evaluator")
            .unwrap_or_else(|| {
                panic!(
                    "missing evaluator review for {}:{}",
                    entry.requirement, entry.clause
                )
            });
        assert_eq!(evaluator.state, "covered");
        assert!(
            evaluator
                .evidence
                .iter()
                .any(|evidence| evidence == &entry.evidence)
        );
    }
}

#[test]
fn analyzed_entry_executes_on_the_shared_sequential_machine() {
    let root = TempDirectory::new(
        r#"
fn increment(value: Int) -> Int { value + 1 }
fn main(flag: Bool) -> Int {
    let mut value: Int = 1;
    value = increment(value);
    if flag { value += 3; } else { value = 9; }
    value
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4a; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        vec![LogicalValue::boolean(true)],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("analyzed program was rejected by the machine: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("analyzed program did not succeed")
    };
    assert!(matches!(value.view(), LogicalValueView::Int(value) if value.get() == 5));
}

/// A propagation marker in the first operand of a flat operator chain is admitted and lowered
/// (`GNT-38.1-typed-error-propagation`). The CLI measures these chains as 6 and 5; before the chain
/// operands reached the seam dispatch both analysed valid and then failed at run time with an
/// internal invariant failure, which no analysis-level row could observe.
#[test]
fn admitted_propagation_chains_execute_on_the_shared_sequential_machine() {
    let prelude = "trait ErrorConversion { pure fn convert(self) -> F; }\nstruct E {}\nstruct F {}\nimpl ErrorConversion for E { pure fn convert(self) -> F { F {} } }\nfn inner_ok() -> Result<Int, E> { Ok(1) }\n";
    for (body, expected) in [
        ("let v: Int = inner_ok()? + 2 + 3; Ok(v)", 6),
        ("let v: Int = inner_ok()? * 2 + 3; Ok(v)", 5),
        ("let v: Int = inner_ok()? + 2 + 3 + 4; Ok(v)", 10),
    ] {
        let source = format!(
            "{prelude}fn outer() -> Result<Int, F> {{ {body} }}\nfn main() -> Int {{ match outer() {{ Ok(v) => v, Err(_) => 0 }} }}\n"
        );
        let root = TempDirectory::new(&source);
        let package = analyze(&root);
        let entry = package
            .entry()
            .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
        let program = package
            .executable_program()
            .cloned()
            .unwrap_or_else(|| panic!("valid package omitted its executable program"));
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4b; 32])
            .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
        let mut machine = Machine::new(Arc::new(program), &entry.path, vec![], execution, limits())
            .unwrap_or_else(|error| {
                panic!("analyzed program was rejected by the machine: {error:?}")
            });
        let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
            panic!("the admitted chain expected to answer {expected} did not succeed")
        };
        assert!(
            matches!(value.view(), LogicalValueView::Int(value) if value.get() == expected),
            "the admitted chain answers the value its operands determine"
        );
    }
}

/// A place operand carries its marker exactly where its parenthesized spelling does
/// (`GNT-38.1-typed-error-propagation`): the bare path propagates in a `let` initializer, and the
/// admitted payload is the value the place holds.
#[test]
fn admitted_place_operands_execute_on_the_shared_sequential_machine() {
    let source = "trait ErrorConversion { pure fn convert(self) -> F; }\nstruct E {}\nstruct F {}\nimpl ErrorConversion for E { pure fn convert(self) -> F { F {} } }\nfn outer(r: Result<Int, E>) -> Result<Int, F> { let v: Int = r?; Ok(v) }\nfn main() -> Int { let r: Result<Int, E> = Ok(1); match outer(r) { Ok(v) => v, Err(_) => 0 } }\n";
    let root = TempDirectory::new(source);
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4c; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(Arc::new(program), &entry.path, vec![], execution, limits())
        .unwrap_or_else(|error| panic!("analyzed program was rejected by the machine: {error:?}"));
    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("the admitted place operand did not succeed")
    };
    assert!(
        matches!(value.view(), LogicalValueView::Int(value) if value.get() == 1),
        "the admitted place operand answers the value the place holds"
    );
}

/// A member place carries its marker exactly where its parenthesized spelling does
/// (`GNT-38.1-typed-error-propagation`): the chain resolves through the declared field, and the
/// admitted payload is the value that field holds.
#[test]
fn admitted_member_places_execute_on_the_shared_sequential_machine() {
    let source = "trait ErrorConversion { pure fn convert(self) -> F; }\nstruct E {}\nstruct F {}\nimpl ErrorConversion for E { pure fn convert(self) -> F { F {} } }\nstruct Holder { inner: Result<Int, E> }\nfn outer(h: Holder) -> Result<Int, F> { let v: Int = h.inner?; Ok(v) }\nfn main() -> Int { match outer(Holder { inner: Ok(7) }) { Ok(v) => v, Err(_) => 0 } }\n";
    let root = TempDirectory::new(source);
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4d; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(Arc::new(program), &entry.path, vec![], execution, limits())
        .unwrap_or_else(|error| panic!("analyzed program was rejected by the machine: {error:?}"));
    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("the admitted member place did not succeed")
    };
    assert!(
        matches!(value.view(), LogicalValueView::Int(value) if value.get() == 7),
        "the admitted member place answers the value the field holds"
    );
}

/// A trailing member step follows the marker's payload (`GNT-38.1-typed-error-propagation`): the
/// step projects the declared field of the `Ok` value the marker publishes.
#[test]
fn admitted_trailing_member_steps_execute_on_the_shared_sequential_machine() {
    let source = "trait ErrorConversion { pure fn convert(self) -> F; }\nstruct E {}\nstruct F {}\nimpl ErrorConversion for E { pure fn convert(self) -> F { F {} } }\nstruct V { value: Int }\nfn inner_wrap() -> Result<V, E> { Ok(V { value: 3 }) }\nfn outer() -> Result<Int, F> { let v: Int = inner_wrap()?.value; Ok(v) }\nfn main() -> Int { match outer() { Ok(v) => v, Err(_) => 0 } }\n";
    let root = TempDirectory::new(source);
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4e; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(Arc::new(program), &entry.path, vec![], execution, limits())
        .unwrap_or_else(|error| panic!("analyzed program was rejected by the machine: {error:?}"));
    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("the admitted trailing step did not succeed")
    };
    assert!(
        matches!(value.view(), LogicalValueView::Int(value) if value.get() == 3),
        "the admitted trailing step answers the value the payload's field holds"
    );
}

#[test]
fn analyzed_closed_generic_application_executes_as_a_direct_call() {
    let root = TempDirectory::new(
        r#"
pure fn preserve<T>(value: T) -> T { value }
pure fn main() -> Int { preserve::<Int>(7) }
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed generic package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4c; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed generic program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("closed generic program did not succeed")
    };
    assert!(matches!(value.view(), LogicalValueView::Int(value) if value.get() == 7));
}

#[test]
fn generic_mutable_parameters_are_mutated_only_in_the_callee_copy() {
    let root = TempDirectory::new(
        r#"
struct Holder<T> { value: T }
fn replace<T>(mut holder: Holder<T>, replacement: T) -> Holder<T> { holder.value = replacement; holder }
fn main() -> Tuple<Int, Int> {
    let original: Holder<Int> = Holder::<Int> { value: 1 };
    let changed: Holder<Int> = replace(original, 7);
    (original.value, changed.value)
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed generic package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x54; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed generic program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("closed generic program did not succeed")
    };
    let original = value
        .member(0)
        .unwrap_or_else(|| panic!("result omitted the original value"));
    let changed = value
        .member(1)
        .unwrap_or_else(|| panic!("result omitted the changed value"));
    assert!(matches!(original.view(), LogicalValueView::Int(value) if value.get() == 1));
    assert!(matches!(changed.view(), LogicalValueView::Int(value) if value.get() == 7));
}

#[test]
fn generic_method_compound_assignment_mutates_only_the_receiver_copy() {
    let root = TempDirectory::new(
        r#"
struct Counter<T> { value: T, count: Int }
impl<T> Counter<T> {
    fn bump(mut self, delta: Int) -> Counter<T> { self.count += delta; self }
}
fn main() -> Tuple<Int, Int> {
    let original: Counter<Int> = Counter::<Int> { value: 0, count: 1 };
    let changed: Counter<Int> = original.bump(6);
    (original.count, changed.count)
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed generic package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x57; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed generic program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("closed generic program did not succeed")
    };
    let original = value
        .member(0)
        .unwrap_or_else(|| panic!("result omitted the original count"));
    let changed = value
        .member(1)
        .unwrap_or_else(|| panic!("result omitted the changed count"));
    assert!(matches!(original.view(), LogicalValueView::Int(value) if value.get() == 1));
    assert!(matches!(changed.view(), LogicalValueView::Int(value) if value.get() == 7));
}

#[test]
fn generic_method_nested_compound_assignment_mutates_only_the_receiver_copy() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder<T> { value: T, counter: Counter }
impl<T> Holder<T> {
    fn bump(mut self, delta: Int) -> Holder<T> { self.counter.value += delta; self }
}
fn main() -> Tuple<Int, Int> {
    let original: Holder<Int> = Holder::<Int> { value: 0, counter: Counter { value: 1 } };
    let changed: Holder<Int> = original.bump(6);
    (original.counter.value, changed.counter.value)
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed generic package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x58; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed generic program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("closed generic program did not succeed")
    };
    let original = value
        .member(0)
        .unwrap_or_else(|| panic!("result omitted the original count"));
    let changed = value
        .member(1)
        .unwrap_or_else(|| panic!("result omitted the changed count"));
    assert!(matches!(original.view(), LogicalValueView::Int(value) if value.get() == 1));
    assert!(matches!(changed.view(), LogicalValueView::Int(value) if value.get() == 7));
}

/// Nested replacement publishes a complete callee copy without changing the caller.
#[test]
fn generic_method_nested_assignment_mutates_only_the_receiver_copy() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder<T> { value: T, counter: Counter }
impl<T> Holder<T> {
    fn replace(mut self, replacement: Int) -> Holder<T> { self.counter.value = replacement; self }
}
fn main() -> Tuple<Int, Int> {
    let original: Holder<Int> = Holder::<Int> { value: 0, counter: Counter { value: 1 } };
    let changed: Holder<Int> = original.replace(7);
    (original.counter.value, changed.counter.value)
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed generic package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x59; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed generic program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("closed generic program did not succeed")
    };
    let original = value
        .member(0)
        .unwrap_or_else(|| panic!("result omitted the original count"));
    let changed = value
        .member(1)
        .unwrap_or_else(|| panic!("result omitted the changed count"));
    assert!(matches!(original.view(), LogicalValueView::Int(value) if value.get() == 1));
    assert!(matches!(changed.view(), LogicalValueView::Int(value) if value.get() == 7));
}

#[test]
fn generic_methods_and_static_trait_calls_preserve_logical_copy_isolation() {
    let root = TempDirectory::new(
        r#"
struct Counter<T> { value: T }
trait Label { pure fn label(self) -> String; }
impl<T> Counter<T> {
    pure fn get(self) -> T { self.value }
    pure fn replace(mut self, value: T) -> Counter<T> { self.value = value; self }
}
impl<T> Label for Counter<T> {
    pure fn label(self) -> String { "counter" }
}
pure fn main() -> Tuple<Int, Int, String> {
    let original: Counter<Int> = Counter::<Int> { value: 1 };
    let changed: Counter<Int> = original.replace(7);
    (original.get(), changed.get(), changed.label())
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed method package omitted its executable program"));
    assert!(
        program.callable_identities().iter().any(|identity| {
            identity.as_str() == "<crate::Counter<Int> as crate::Label>::label"
        })
    );
    let receiver_modes = program
        .workflows()
        .iter()
        .filter_map(|workflow| workflow.parameters.first()?.receiver_mode())
        .collect::<Vec<_>>();
    assert!(receiver_modes.contains(&gantry::ir::ReceiverMode::LocalCopy));
    assert!(receiver_modes.contains(&gantry::ir::ReceiverMode::MutableLocalCopy));
    assert!(receiver_modes.iter().all(|mode| mode.copies_receiver()));
    let receiver_calls = program
        .workflows()
        .iter()
        .flat_map(|workflow| &workflow.instructions)
        .filter_map(|instruction| match &instruction.kind {
            InstructionKind::ReceiverCall {
                callee,
                arguments,
                source,
            } => Some((callee, arguments, source)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected_receiver_calls = BTreeMap::from([
        ("<crate::Counter<Int>>::replace", vec![2]),
        ("<crate::Counter<Int>>::get", vec![1, 1]),
        ("<crate::Counter<Int> as crate::Label>::label", vec![1]),
    ]);
    let mut observed_receiver_calls = BTreeMap::<&str, Vec<usize>>::new();
    for (callee, arguments, _) in &receiver_calls {
        observed_receiver_calls
            .entry(callee.as_str())
            .or_default()
            .push(**arguments);
    }
    for arguments in observed_receiver_calls.values_mut() {
        arguments.sort_unstable();
    }
    assert_eq!(observed_receiver_calls, expected_receiver_calls);
    assert!(
        receiver_calls.iter().all(|(callee, _, source)| {
            callee.receiver_type().is_some()
                && matches!(source, gantry::ir::ReceiverSource::CopiedValue)
        }),
        "source lowering must emit copied receiver calls for receiver callables"
    );
    assert!(
        program
            .workflows()
            .iter()
            .flat_map(|workflow| &workflow.instructions)
            .filter_map(|instruction| match &instruction.kind {
                InstructionKind::Call { callee, .. }
                    if expected_receiver_calls.contains_key(callee.as_str()) =>
                {
                    Some(callee.as_str())
                }
                _ => None,
            })
            .next()
            .is_none(),
        "receiver identities must not lower through legacy Call"
    );
    assert!(
        program
            .workflows()
            .iter()
            .flat_map(|workflow| &workflow.instructions)
            .filter_map(|instruction| match &instruction.kind {
                InstructionKind::Call { callee, .. }
                | InstructionKind::ReceiverCall { callee, .. } => Some(callee.as_str()),
                _ => None,
            })
            .all(|callee| !callee.contains('^'))
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4d; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed method program was rejected: {error:?}"));

    let outcome = drive(&mut machine);
    let MachineOutcome::Succeeded(value) = outcome else {
        panic!("closed method program did not succeed: {outcome:?}")
    };
    let original = value
        .member(0)
        .unwrap_or_else(|| panic!("result omitted the original value"));
    let changed = value
        .member(1)
        .unwrap_or_else(|| panic!("result omitted the changed value"));
    let label = value
        .member(2)
        .unwrap_or_else(|| panic!("result omitted the trait-method result"));
    assert!(matches!(original.view(), LogicalValueView::Int(value) if value.get() == 1));
    assert!(matches!(changed.view(), LogicalValueView::Int(value) if value.get() == 7));
    assert!(matches!(label.view(), LogicalValueView::String("counter")));
}

/// A shared inherent receiver lowers from an addressable root without a copied receiver load.
#[test]
fn shared_inherent_method_lowers_caller_root_and_struct_field_places() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter { pure fn read(shared self) -> Int { self.value } }
fn main(holder: Holder) -> Int { holder.counter.read() }
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let main = entry_workflow(&package);
    let shared_signature = "fn <crate::Counter>::read(shared self)->Int";
    assert!(
        package
            .workflows()
            .iter()
            .any(|workflow| workflow.signature.to_string() == shared_signature),
        "{:#?}",
        package.workflows()
    );
    assert!(
        package
            .canonical_ir()
            .unwrap_or_else(|| panic!("valid package omitted canonical IR"))
            .workflows()
            .iter()
            .any(|workflow| workflow.signature.to_string() == shared_signature),
        "source canonical IR omitted {shared_signature}"
    );
    assert!(
        program.workflows().iter().any(|workflow| {
            workflow.path.as_str() == "<crate::Counter>::read"
                && matches!(
                    workflow.parameters.as_slice(),
                    [gantry::ir::Parameter {
                        name,
                        receiver_mode: Some(gantry::ir::ReceiverMode::SharedPlace),
                        ..
                    }] if name.as_ref() == "self"
                )
        }),
        "{:#?}",
        program.workflows()
    );
    let shared_call = main
        .instructions
        .iter()
        .find_map(|instruction| match &instruction.kind {
            InstructionKind::ReceiverCall {
                callee,
                arguments,
                source,
            } if callee.as_str() == "<crate::Counter>::read" => Some((arguments, source)),
            _ => None,
        });
    assert!(
        matches!(
            shared_call,
            Some((1, ReceiverSource::CallerPlace { root, path, .. }))
                if root.as_ref() == "holder"
                    && path == &vec![gantry::value::ValuePathSegment::StructField("counter".to_owned())]
        ),
        "{:#?}",
        main.instructions
    );
    assert!(
        !main.instructions.iter().any(|instruction| matches!(
            &instruction.kind,
            InstructionKind::Load(name) if name.as_ref() == "holder"
        )),
        "shared receiver lowering must not materialize a copied receiver"
    );

    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x3c; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let holder = LogicalValue::structure(
        "crate::Holder",
        vec![(
            "counter".to_owned(),
            LogicalValue::structure(
                "crate::Counter",
                vec![(
                    "value".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                    ),
                )],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![holder],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("shared source program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// An exclusive inherent receiver lowers a mutable caller place and writes its completed receiver back.
#[test]
fn exclusive_inherent_method_lowers_caller_place_and_writes_through() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter { fn increment(exclusive self) { self.value += 1; } }
fn main() -> Int {
    let mut holder: Holder = Holder { counter: Counter { value: 7 } };
    holder.counter.increment();
    holder.counter.value
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let main = entry_workflow(&package);
    assert!(program.workflows().iter().any(|workflow| {
        workflow.path.as_str() == "<crate::Counter>::increment"
            && matches!(
                workflow.parameters.as_slice(),
                [gantry::ir::Parameter {
                    name,
                    mutable: true,
                    receiver_mode: Some(gantry::ir::ReceiverMode::ExclusivePlace),
                    ..
                }] if name.as_ref() == "self"
            )
    }));
    assert!(main.instructions.iter().any(|instruction| matches!(
        &instruction.kind,
        InstructionKind::ReceiverCall {
            callee,
            arguments: 1,
            source: ReceiverSource::CallerPlace { root, path, .. },
        } if callee.as_str() == "<crate::Counter>::increment"
            && root.as_ref() == "holder"
            && matches!(path.as_slice(),
                [gantry::value::ValuePathSegment::StructField(field)] if field == "counter")
    )));
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4e; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("exclusive source program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 8)
    ));
}

/// An owned receiver is an independent mutable local copy: it mutates without changing the caller.
#[test]
fn owned_inherent_method_is_a_mutable_local_copy_that_leaves_the_caller_unchanged() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn bump(owned self) { self.value += 1; } }
fn main() -> Int {
    let counter: Counter = Counter { value: 7 };
    counter.bump();
    counter.value
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let owned_signature = "fn <crate::Counter>::bump(owned self)->Unit";
    assert!(
        package
            .workflows()
            .iter()
            .any(|workflow| workflow.signature.to_string() == owned_signature),
        "{:#?}",
        package.workflows()
    );
    assert!(program.workflows().iter().any(|workflow| {
        workflow.path.as_str() == "<crate::Counter>::bump"
            && matches!(
                workflow.parameters.as_slice(),
                [gantry::ir::Parameter {
                    name,
                    mutable: true,
                    receiver_mode: Some(gantry::ir::ReceiverMode::Owned),
                    ..
                }] if name.as_ref() == "self"
            )
    }));

    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5f; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("owned source program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Exclusive subplace reborrows propagate mutations to their caller while shared reborrows observe the updated value.
#[test]
fn exclusive_inherent_methods_propagate_strict_reborrows_and_allow_shared_reborrows() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter {
    fn increment(exclusive self) { self.value += 1; }
    pure fn read(shared self) -> Int { self.value }
}
impl Holder { fn increment_counter(exclusive self) { self.counter.increment(); } }
fn main() -> Int {
    let mut holder: Holder = Holder { counter: Counter { value: 7 } };
    holder.increment_counter();
    holder.counter.read()
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let mut machine = Machine::new(
        Arc::new(executable(&package).clone()),
        &entry.path,
        Vec::new(),
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4f; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}")),
        limits(),
    )
    .unwrap_or_else(|error| panic!("nested exclusive source program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 8)
    ));
}

/// Source-lowered exclusive calls retain and validate their caller-place checkpoint before write-through.
#[test]
fn source_exclusive_call_recovers_and_rejects_tampered_mid_call_checkpoint() {
    use gantry::runtime::{ExecutionBudget, MachineCheckpointV3};

    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter { fn increment(exclusive self) { self.value += 1; } }
fn main(mut holder: Holder) -> Int { holder.counter.increment(); holder.counter.value }
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let holder = LogicalValue::structure(
        "crate::Holder",
        vec![(
            "counter".to_owned(),
            LogicalValue::structure(
                "crate::Counter",
                vec![(
                    "value".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                    ),
                )],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x50; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![holder],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("exclusive source program did not start: {error:?}"));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));

    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP05".as_slice()));
    let checkpoint = MachineCheckpointV3::decode(program, &bytes)
        .unwrap_or_else(|error| panic!("exclusive checkpoint did not decode: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let mut altered = bytes.clone();
    let root = altered
        .windows(b"holder".len())
        .rposition(|window| window == b"holder")
        .unwrap_or_else(|| panic!("checkpoint omitted exclusive admission root"));
    altered[root..root + b"holder".len()].copy_from_slice(b"absent");
    assert_eq!(
        MachineCheckpointV3::decode(program, &altered),
        Err(gantry::runtime::MachineRecoveryError::ProgramMismatch)
    );
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("exclusive budget recovery failed: {error:?}"));
    let mut recovered =
        Machine::recover_from_checkpoint(Arc::new(program.clone()), checkpoint, budget)
            .unwrap_or_else(|error| panic!("exclusive checkpoint recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 8)
    ));
}

/// A `MustConsume` owned receiver admits its caller place as a staged consumption, keeps the
/// obligation in the mid-call checkpoint, and recovers to the same result.
#[test]
fn source_must_consume_owned_receiver_stages_obligation_and_recovers_mid_call_checkpoint() {
    use gantry::ir::{OwnershipClass, ReceiverMode};
    use gantry::runtime::{ExecutionBudget, MachineCheckpointV3};

    let root = TempDirectory::new(
        r#"
must_consume struct Token { value: Int }
impl Token { fn consume(owned self) -> Int { self.value } }
fn main() -> Int {
    let token: Token = Token { value: 7 };
    token.consume()
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let main = entry_workflow(&package);
    assert!(
        program.workflows().iter().any(|workflow| {
            workflow.path.as_str() == "<crate::Token>::consume"
                && matches!(
                    workflow.parameters.as_slice(),
                    [gantry::ir::Parameter {
                        name,
                        mutable: true,
                        receiver_mode: Some(ReceiverMode::Owned),
                        ..
                    }] if name.as_ref() == "self"
                )
        }),
        "{:#?}",
        program.workflows()
    );
    assert!(
        main.instructions.iter().any(|instruction| matches!(
            &instruction.kind,
            InstructionKind::ReceiverCall {
                callee,
                arguments: 1,
                source: ReceiverSource::CallerPlace { root, path, ownership },
            } if callee.as_str() == "<crate::Token>::consume"
                && root.as_ref() == "token"
                && path.is_empty()
                && *ownership == OwnershipClass::MustConsume
        )),
        "{:#?}",
        main.instructions
    );
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x52; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("must-consume source program did not start: {error:?}"));
    // Step into the owned callee frame, where the consumption obligation is staged.
    for _ in 0..4 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        if machine.checkpoint().canonical_bytes().get(..8) == Some(b"GNTMCP09".as_slice()) {
            break;
        }
    }
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP09".as_slice()));
    let checkpoint = MachineCheckpointV3::decode(program, &bytes)
        .unwrap_or_else(|error| panic!("must-consume checkpoint did not decode: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("must-consume budget recovery failed: {error:?}"));
    let mut recovered =
        Machine::recover_from_checkpoint(Arc::new(program.clone()), checkpoint, budget)
            .unwrap_or_else(|error| panic!("must-consume recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// A source-lowered affine owned move admits the caller place as a move source rather than a
/// copied value and keeps a mid-call checkpoint decodable and tamper-rejecting.
#[test]
fn source_affine_owned_receiver_moves_caller_place_and_recovers_mid_call_checkpoint() {
    use gantry::ir::ReceiverMode;
    use gantry::runtime::{ExecutionBudget, MachineCheckpointV3};

    let root = TempDirectory::new(
        r#"
affine struct Token { value: Int }
struct Holder { token: Token, marker: Int }
impl Token { fn consume(owned self) -> Int { self.value } }
fn main(holder: Holder) -> Int {
    let moved: Int = holder.token.consume();
    moved + holder.marker
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let main = entry_workflow(&package);
    assert!(
        program.workflows().iter().any(|workflow| {
            workflow.path.as_str() == "<crate::Token>::consume"
                && matches!(
                    workflow.parameters.as_slice(),
                    [gantry::ir::Parameter {
                        name,
                        mutable: true,
                        receiver_mode: Some(ReceiverMode::Owned),
                        ..
                    }] if name.as_ref() == "self"
                )
        }),
        "{:#?}",
        program.workflows()
    );
    // The affine owned receiver lowers to a caller-place move, never a copied receiver value.
    assert!(
        main.instructions.iter().any(|instruction| matches!(
            &instruction.kind,
            InstructionKind::ReceiverCall {
                callee,
                arguments: 1,
                source: ReceiverSource::CallerPlace { root, path, .. },
            } if callee.as_str() == "<crate::Token>::consume"
                && root.as_ref() == "holder"
                && path
                    == &vec![gantry::value::ValuePathSegment::StructField(
                        "token".to_owned(),
                    )]
        )),
        "{:#?}",
        main.instructions
    );
    assert!(
        !main.instructions.iter().any(|instruction| matches!(
            &instruction.kind,
            InstructionKind::ReceiverCall {
                callee,
                source: ReceiverSource::CopiedValue,
                ..
            } if callee.as_str() == "<crate::Token>::consume"
        )),
        "{:#?}",
        main.instructions
    );

    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let holder = LogicalValue::structure(
        "crate::Holder",
        vec![
            (
                "token".to_owned(),
                LogicalValue::structure(
                    "crate::Token",
                    vec![(
                        "value".to_owned(),
                        LogicalValue::integer(
                            GantryInt::new(7)
                                .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                        ),
                    )],
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("token fixture failed: {error:?}")),
            ),
            (
                "marker".to_owned(),
                LogicalValue::integer(
                    GantryInt::new(3).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x51; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![holder],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("affine source program did not start: {error:?}"));

    // The first transition admits the caller place and enters the owned callee: a mid-call cut.
    assert!(matches!(machine.step(), MachineStep::Transition(_)));

    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    assert!(
        bytes
            .windows(b"holder".len())
            .any(|window| window == b"holder"),
        "mid-call checkpoint omitted the admitted caller place"
    );
    let checkpoint = MachineCheckpointV3::decode(program, &bytes)
        .unwrap_or_else(|error| panic!("affine owned move checkpoint did not decode: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let mut altered = bytes.clone();
    let caller_at = altered
        .windows(b"holder".len())
        .rposition(|window| window == b"holder")
        .unwrap_or_else(|| panic!("checkpoint omitted the owned-move caller place"));
    altered[caller_at..caller_at + b"holder".len()].copy_from_slice(b"absent");
    assert_eq!(
        MachineCheckpointV3::decode(program, &altered),
        Err(gantry::runtime::MachineRecoveryError::ProgramMismatch)
    );
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("affine owned move budget recovery failed: {error:?}"));
    let mut recovered =
        Machine::recover_from_checkpoint(Arc::new(program.clone()), checkpoint, budget)
            .unwrap_or_else(|error| panic!("affine owned move recovery failed: {error:?}"));
    // The resumed call reads the caller place's own value (7), and the caller frame still exposes
    // its unchanged sibling binding (3) after the call: the owned move is a caller-place move with
    // no write-back of the independent callee receiver.
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 10)
    ));
}

/// Shared caller places preserve every nested field projection in aggregate and assignment RHSs.
#[test]
fn shared_calls_preserve_nested_places_in_aggregate_and_assignment_rhs() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Inner { counter: Counter }
struct Outer { inner: Inner }
impl Counter { pure fn read(shared self) -> Int { self.value } }
fn main(outer: Outer) -> Tuple<Int, Int> {
    let mut result: Tuple<Int, Int> = (0, 0);
    result = (outer.inner.counter.read(), outer.inner.counter.read());
    result
}
"#,
    );
    let package = analyze(&root);
    let main = entry_workflow(&package);
    let calls = main
        .instructions
        .iter()
        .filter_map(|instruction| match &instruction.kind {
            InstructionKind::ReceiverCall { callee, source, .. }
                if callee.as_str() == "<crate::Counter>::read" =>
            {
                Some(source)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2, "{:#?}", main.instructions);
    assert!(calls.iter().all(|source| matches!(
        source,
        ReceiverSource::CallerPlace { root, path, .. }
            if root.as_ref() == "outer"
                && matches!(path.as_slice(),
                    [
                        gantry::value::ValuePathSegment::StructField(inner),
                        gantry::value::ValuePathSegment::StructField(counter),
                    ] if inner == "inner" && counter == "counter")
    )));
    assert!(!main.instructions.iter().any(|instruction| matches!(
        &instruction.kind,
        InstructionKind::Load(root) if root.as_ref() == "outer"
    )));
}

/// A shared receiver may reborrow its own admitted caller place for another shared method.
#[test]
fn shared_inherent_method_reborrows_nested_caller_place() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter {
    pure fn read(shared self) -> Int { self.value }
    pure fn nested(shared self) -> Int { self.read() }
}
fn main(counter: Counter) -> Int { counter.nested() }
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let receiver_calls = program
        .workflows()
        .iter()
        .flat_map(|workflow| &workflow.instructions)
        .filter_map(|instruction| match &instruction.kind {
            InstructionKind::ReceiverCall { callee, source, .. } => Some((callee.as_str(), source)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(receiver_calls.iter().any(|(callee, source)| {
        *callee == "<crate::Counter>::nested"
            && matches!(source, ReceiverSource::CallerPlace { root, path, .. } if root.as_ref() == "counter" && path.is_empty())
    }));
    assert!(receiver_calls.iter().any(|(callee, source)| {
        *callee == "<crate::Counter>::read"
            && matches!(source, ReceiverSource::CallerPlace { root, path, .. } if root.as_ref() == "self" && path.is_empty())
    }));

    let counter = LogicalValue::structure(
        "crate::Counter",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}"));
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x3d; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![counter],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("nested shared source program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Copied receivers retain each projected type and leave the caller value unchanged.
#[test]
fn copied_method_receiver_lowers_root_load_and_nested_field_projections() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder<T> { marker: T, counter: Counter }
impl Counter {
    pure fn read(self) -> Int { self.value }
    fn bump(mut self) -> Int { self.value += 6; self.value }
}
fn main(holder: Holder<Counter>) -> Tuple<Int, Int, Int> {
    (holder.counter.read(), holder.counter.bump(), holder.counter.value)
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let main = entry_workflow(&package);
    for callee in ["<crate::Counter>::read", "<crate::Counter>::bump"] {
        let call = main
            .instructions
            .iter()
            .position(|instruction| matches!(
                &instruction.kind,
                InstructionKind::ReceiverCall { callee: candidate, source: ReceiverSource::CopiedValue, .. }
                    if candidate.as_str() == callee
            ))
            .unwrap_or_else(|| panic!("missing copied {callee} call: {:#?}", main.instructions));
        assert!(
            matches!(
                &main.instructions[call - 2..call],
                [
                    gantry::ir::Instruction { ty: holder, kind: InstructionKind::Load(root), .. },
                    gantry::ir::Instruction { ty: counter_ty, kind: InstructionKind::Project(gantry::ir::Projection::Field(counter)), .. },
                ] if root.as_ref() == "holder" && counter.as_ref() == "counter"
                    && holder.canonical_string() == "crate::Holder<crate::Counter>"
                    && counter_ty.canonical_string() == "crate::Counter"
            ),
            "{:#?}",
            main.instructions
        );
    }
    let holder = LogicalValue::structure(
        "crate::Holder<crate::Counter>",
        vec![
            (
                "marker".to_owned(),
                LogicalValue::structure(
                    "crate::Counter",
                    vec![(
                        "value".to_owned(),
                        LogicalValue::integer(
                            GantryInt::new(0)
                                .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                        ),
                    )],
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("marker fixture failed: {error:?}")),
            ),
            (
                "counter".to_owned(),
                LogicalValue::structure(
                    "crate::Counter",
                    vec![(
                        "value".to_owned(),
                        LogicalValue::integer(
                            GantryInt::new(1)
                                .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                        ),
                    )],
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x3f; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![holder],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("copied receiver program did not start: {error:?}"));
    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("copied receiver program did not succeed")
    };
    let read = value
        .member(0)
        .unwrap_or_else(|| panic!("result omitted the copied read result"));
    let bumped = value
        .member(1)
        .unwrap_or_else(|| panic!("result omitted the copied mutation result"));
    let original = value
        .member(2)
        .unwrap_or_else(|| panic!("result omitted the caller value"));
    assert!(matches!(read.view(), LogicalValueView::Int(number) if number.get() == 1));
    assert!(matches!(bumped.view(), LogicalValueView::Int(number) if number.get() == 7));
    assert!(matches!(original.view(), LogicalValueView::Int(number) if number.get() == 1));
}

/// Shared calls are selected at their own postfix site, not by enclosing-expression containment.
#[test]
fn shared_calls_compose_with_free_calls_and_binary_expressions() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Pair { left: Counter, right: Counter }
impl Counter { pure fn read(shared self) -> Int { self.value } }
fn add(left: Int, right: Int) -> Int { left + right }
fn main(pair: Pair) -> Int { add(pair.left.read(), pair.right.read()) + pair.left.read() }
"#,
    );
    let package = analyze(&root);
    let main = entry_workflow(&package);
    let calls = main
        .instructions
        .iter()
        .filter_map(|instruction| match &instruction.kind {
            InstructionKind::ReceiverCall { callee, source, .. }
                if callee.as_str() == "<crate::Counter>::read" =>
            {
                Some(source)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 3, "{:#?}", main.instructions);
    assert!(calls.iter().all(|source| matches!(
        source,
        ReceiverSource::CallerPlace { root, path, .. }
            if root.as_ref() == "pair"
                && matches!(path.as_slice(),
                    [gantry::value::ValuePathSegment::StructField(field)]
                        if matches!(field.as_str(), "left" | "right"))
    )));
    assert!(
        main.instructions.iter().any(|instruction| matches!(
            &instruction.kind,
            InstructionKind::Call { callee, arguments: 2 } if callee.as_str() == "crate::add"
        )),
        "{:#?}",
        main.instructions
    );
}

/// Source-lowered shared calls retain their v3 program and mid-call checkpoint exactly.
#[test]
fn source_shared_call_round_trips_program_and_rejects_tampered_mid_call_checkpoint() {
    use gantry::runtime::{
        DurableCommitCutV1, DurableExecutionStartV3, DurableLogicalEvidenceV3, ExecutionBudget,
        MachineCheckpointV3, root_task_identity,
    };

    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter { pure fn read(shared self) -> Int { self.value } }
fn main(holder: Holder) -> Int { holder.counter.read() }
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let entry = entry_workflow(&package);
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x3e; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let task = root_task_identity(execution);
    let holder = LogicalValue::structure(
        "crate::Holder",
        vec![(
            "counter".to_owned(),
            LogicalValue::structure(
                "crate::Counter",
                vec![(
                    "value".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                    ),
                )],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![holder],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("shared source program did not start: {error:?}"));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));

    let checkpoint_bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(checkpoint_bytes.get(..8), Some(b"GNTMCP05".as_slice()));
    let checkpoint = MachineCheckpointV3::decode(program, &checkpoint_bytes)
        .unwrap_or_else(|error| panic!("mid-call checkpoint did not decode: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), checkpoint_bytes);
    let mut altered_root = checkpoint_bytes.clone();
    let root = altered_root
        .windows(b"holder".len())
        .rposition(|window| window == b"holder")
        .unwrap_or_else(|| panic!("checkpoint omitted shared admission root"));
    altered_root[root..root + b"holder".len()].copy_from_slice(b"absent");
    assert_eq!(
        MachineCheckpointV3::decode(program, &altered_root),
        Err(gantry::runtime::MachineRecoveryError::ProgramMismatch)
    );
    let mut altered_path = checkpoint_bytes.clone();
    let path = altered_path
        .windows(b"counter".len())
        .rposition(|window| window == b"counter")
        .unwrap_or_else(|| panic!("checkpoint omitted shared admission path"));
    altered_path[path..path + b"counter".len()].copy_from_slice(b"missing");
    assert_eq!(
        MachineCheckpointV3::decode(program, &altered_path),
        Err(gantry::runtime::MachineRecoveryError::ProgramMismatch)
    );

    let state = DurableLogicalEvidenceV3::new(
        execution,
        task,
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
    )
    .unwrap_or_else(|error| panic!("mid-call evidence failed: {error:?}"));
    let retained = DurableExecutionStartV3::new(
        execution,
        task,
        program,
        Arc::<[u8]>::from(&b"{}"[..]),
        state,
    )
    .unwrap_or_else(|error| panic!("retained source program failed: {error:?}"));
    let retained_body = retained.canonical_body();
    assert!(
        retained_body
            .windows(16)
            .any(|window| window == b"474e545052473033")
    );
    assert_eq!(
        DurableExecutionStartV3::retained_program(&retained_body),
        Ok(program.clone())
    );

    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("mid-call budget recovery failed: {error:?}"));
    let mut recovered =
        Machine::recover_from_checkpoint(Arc::new(program.clone()), checkpoint, budget)
            .unwrap_or_else(|error| panic!("mid-call recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Source-lowered Result branches retain their successor wire across checkpoints.
#[test]
fn source_result_if_let_checkpoint_recovers_from_retained_program() {
    use gantry::runtime::{
        DurableCommitCutV1, DurableExecutionStartV3, DurableLogicalEvidenceV3, ExecutionBudget,
        MachineCheckpointV3, root_task_identity,
    };

    let root = TempDirectory::new(
        r#"
fn main(value: Result<Int, Int>) -> Int {
    if let Err(number) = value { return number; }
    0
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let entry = entry_workflow(&package);
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x3f; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let task = root_task_identity(execution);
    let value = LogicalValue::err(
        LogicalValue::integer(
            GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
        ),
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("result fixture failed: {error:?}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![value],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("Result if-let program did not start: {error:?}"));
    for _ in 0..2 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
    }

    let checkpoint_bytes = machine.checkpoint().canonical_bytes();
    let checkpoint = MachineCheckpointV3::decode(program, &checkpoint_bytes)
        .unwrap_or_else(|error| panic!("Result if-let checkpoint did not decode: {error:?}"));
    let state = DurableLogicalEvidenceV3::new(
        execution,
        task,
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
    )
    .unwrap_or_else(|error| panic!("Result if-let evidence failed: {error:?}"));
    let retained = DurableExecutionStartV3::new(
        execution,
        task,
        program,
        Arc::<[u8]>::from(&b"{}"[..]),
        state,
    )
    .unwrap_or_else(|error| panic!("retained Result if-let program failed: {error:?}"));
    assert_eq!(
        retained
            .program()
            .unwrap_or_else(|error| panic!("retained Result if-let decode failed: {error:?}")),
        *program
    );

    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("Result if-let budget recovery failed: {error:?}"));
    let mut recovered =
        Machine::recover_from_checkpoint(Arc::new(program.clone()), checkpoint, budget)
            .unwrap_or_else(|error| panic!("Result if-let recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Explicit IR caller-place admission executes without asserting source syntax or mutations.
#[test]
fn explicit_ir_shared_place_admission_executes_without_copy_or_mutation_claims() {
    use gantry::ir::{
        CanonicalCallableIdentity, CanonicalPath, EffectSet, Parameter, ReceiverMode,
        ReceiverSource, StructuralPosition, TypeDescriptor, Workflow,
    };
    use gantry::numeric::GantryInt;

    let main_path = CanonicalPath::new("crate::main")
        .unwrap_or_else(|error| panic!("main path failed: {error}"));
    let main = CanonicalCallableIdentity::free(&main_path, &[]);
    let method = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let outer = TypeDescriptor::declared(
        CanonicalPath::new("crate::Outer")
            .unwrap_or_else(|error| panic!("outer type path failed: {error}")),
    );
    let instruction = |index, ty, kind| gantry::ir::Instruction {
        site: StructuralPosition::new(vec![index])
            .unwrap_or_else(|error| panic!("instruction site failed: {error}")),
        ty,
        kind,
    };
    let mut callables = vec![
        (
            main,
            Workflow {
                path: main_path.clone(),
                parameters: vec![Parameter {
                    name: Arc::from("item"),
                    ty: outer,
                    mutable: false,
                    receiver_mode: None,
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::ReceiverCall {
                            callee: method.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from("item"),
                                path: vec![gantry::value::ValuePathSegment::StructField(
                                    "value".to_owned(),
                                )],
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            method,
            Workflow {
                path: CanonicalPath::new("crate::Outer::value")
                    .unwrap_or_else(|error| panic!("method path failed: {error}")),
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: TypeDescriptor::INT,
                    mutable: false,
                    receiver_mode: Some(ReceiverMode::SharedPlace),
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::Load(Arc::from("self")),
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
    ];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    let program = gantry::ir::MachineProgram::with_callable_identities(callables)
        .unwrap_or_else(|error| panic!("explicit shared-place IR was rejected: {error:?}"));
    let item = LogicalValue::structure(
        "crate::Outer",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture outer value failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5a; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &main_path,
        vec![item],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("explicit shared-place IR did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

#[test]
fn generic_trait_method_returning_self_executes_with_the_closed_receiver_type() {
    let root = TempDirectory::new(
        r#"
trait Repack { pure fn repack(self) -> Self; }
struct Envelope<T> { value: T }
impl<T> Repack for Envelope<T> {
    pure fn repack(self) -> Self { self }
}
pure fn main() -> Envelope<String> {
    Envelope::<String> { value: "x" }.repack()
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("contextual-Self package omitted its executable program"));
    assert!(program.callable_identities().iter().any(|identity| {
        identity.as_str() == "<crate::Envelope<String> as crate::Repack>::repack"
    }));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x53; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("contextual-Self program was rejected: {error:?}"));

    let outcome = drive(&mut machine);
    assert!(matches!(
        outcome,
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Struct { type_name, .. }
                if type_name == "crate::Envelope<String>")
                && value.canonical_json().bytes() == br#"{"value":"x"}"#
    ));
}

#[test]
fn generic_operation_uses_the_concrete_result_type_and_schema() {
    let root = TempDirectory::new(
        r#"
agents { worker }
default agent = worker;
fn generate<T>() -> T where T: ExternalValue { prompt "Generate." -> T }
fn main() -> String { generate::<String>() }
"#,
    );
    let package = analyze(&root);
    assert!(package.schemas().is_some_and(|schemas| {
        schemas
            .entries()
            .iter()
            .any(|(descriptor, _)| descriptor.canonical_string() == "String")
    }));
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed operation package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4e; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed operation program was rejected: {error:?}"));

    let operation = loop {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::WaitingOperation(operation) => break operation,
            MachineStep::WaitingSessionScope(scope) => {
                panic!("generic operation requested session scope {scope:?}")
            }
            MachineStep::Complete(outcome) => {
                panic!("generic operation settled before dispatch: {outcome:?}")
            }
        }
    };
    assert_eq!(operation.expected_type.canonical_string(), "String");
    assert_eq!(
        operation
            .metadata
            .as_ref()
            .map(|metadata| metadata.result_type.canonical_string())
            .as_deref(),
        Some("String")
    );
    assert_eq!(
        machine.complete_operation(operation.identity, LogicalValue::boolean(true)),
        Err(OperationCompletionError::TypeMismatch)
    );
    machine
        .complete_operation(
            operation.identity,
            LogicalValue::string("done", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("string value failed: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("concrete operation result failed: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::String("done"))
    ));
}

#[test]
fn closed_generic_enum_construction_and_matching_execute_without_runtime_analysis() {
    let root = TempDirectory::new(
        r#"
enum State<T> { Ready(T), Failed }
pure fn ready<T>(value: T) -> State<T> { State::<T>::Ready(value) }
pure fn main() -> Int {
    match ready::<Int>(7) {
        State::<Int>::Ready(value) => value,
        State::<Int>::Failed => 0,
    }
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("closed enum package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4f; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("closed enum program was rejected: {error:?}"));

    let outcome = drive(&mut machine);
    assert!(
        matches!(
            outcome,
            MachineOutcome::Succeeded(ref value)
                if matches!(value.view(), LogicalValueView::Int(value) if value.get() == 7)
        ),
        "closed enum program did not return 7: {outcome:?}"
    );
}

#[test]
fn nested_generic_enum_constructor_call_preserves_and_executes_the_closed_value() {
    let root = TempDirectory::new(
        r#"
enum State<T, E> { Ready(T), Failed(E) }
pure fn preserve<T>(value: T) -> T { value }
fn main() -> State<List<String>, Int> {
    preserve::<State<List<String>, Int>>(
        State::<List<String>, Int>::Ready(["x"])
    )
}
"#,
    );
    let package = analyze(&root);
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid nested generic package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("nested generic package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x50; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("nested generic program was rejected: {error:?}"));

    let outcome = drive(&mut machine);
    assert!(
        matches!(
            outcome,
            MachineOutcome::Succeeded(ref value)
                if matches!(value.view(), LogicalValueView::Enum {
                    type_name: "crate::State<List<String>,Int>",
                    variant: "Ready",
                    has_payload: true,
                }) && value.canonical_json().bytes() == br#"{"value":["x"],"variant":"Ready"}"#
        ),
        "nested generic program did not preserve Ready([\"x\"]): {outcome:?}"
    );
}

#[test]
fn evaluator_program_contains_only_closed_direct_calls_and_no_analyzer_dependency() {
    let root = TempDirectory::new(
        r#"
trait Label { pure fn label(self) -> String; }
struct Item { value: Int }
impl Label for Item { pure fn label(self) -> String { "item" } }
pure fn preserve<T>(value: T) -> T { value }
pure fn main() -> String {
    let retained: Item = preserve::<Item>(Item { value: 1 });
    retained.label()
}
"#,
    );
    let package = analyze(&root);
    let program = package
        .executable_program()
        .unwrap_or_else(|| panic!("closed package omitted its executable program"));
    for identity in program.callable_identities() {
        assert!(!identity.as_str().contains('^'));
        assert!(
            gantry::ir::CanonicalCallableIdentity::from_canonical_string(
                identity.as_str(),
                u64::MAX,
            )
            .is_ok()
        );
    }
    for callee in program
        .workflows()
        .iter()
        .flat_map(|workflow| &workflow.instructions)
        .filter_map(|instruction| match &instruction.kind {
            InstructionKind::Call { callee, .. } | InstructionKind::ReceiverCall { callee, .. } => {
                Some(callee)
            }
            _ => None,
        })
    {
        assert!(!callee.as_str().contains('^'));
        assert!(program.callable(callee).is_some());
    }

    let manifest = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../gantry-runtime/Cargo.toml"),
    )
    .unwrap_or_else(|error| panic!("could not read runtime manifest: {error}"));
    assert!(!manifest.contains("gantry-analysis"));
}

#[test]
fn concurrent_source_lowers_spawn_join_and_typed_captures() {
    let root = TempDirectory::new(
        r#"
fn main() -> Int {
    let retained: Int = 7;
    spawn child -> Int { retained }
    let result: Int = join(child);
    result
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let workflow = program
        .workflow(&entry.path)
        .unwrap_or_else(|| panic!("entry workflow was not lowered"));
    let spawn = workflow
        .instructions
        .iter()
        .find_map(|instruction| match &instruction.kind {
            InstructionKind::Spawn { handle, body } => Some((instruction, handle, body)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("entry workflow omitted spawn lowering"));
    assert_eq!(spawn.1.name(), "child");
    assert_eq!(spawn.1.result_type().canonical_string(), "Int");
    assert_eq!(spawn.2.spawn_site(), &spawn.0.site);
    let canonical_spawn = package
        .workflows()
        .iter()
        .find(|facts| facts.path == entry.path)
        .and_then(|facts| {
            facts
                .task_controls
                .iter()
                .find(|site| site.kind.wire_name() == "spawn")
        })
        .unwrap_or_else(|| panic!("analyzer omitted canonical spawn site"));
    assert_eq!(spawn.2.spawn_site(), canonical_spawn.id.position());
    assert!(workflow.instructions.iter().any(|instruction| {
        matches!(
            &instruction.kind,
            InstructionKind::Join { handles }
                if handles.iter().map(AsRef::as_ref).eq(["child"])
        ) && instruction.ty.canonical_string() == "Int"
    }));

    let body = program
        .task_body(spawn.2)
        .unwrap_or_else(|| panic!("spawned task body was not lowered"));
    assert_eq!(body.result_type().canonical_string(), "Int");
    assert_eq!(body.captures().len(), 1);
    assert_eq!(body.captures()[0].name(), "retained");
    assert_eq!(body.captures()[0].ty().canonical_string(), "Int");
    assert!(!body.captures()[0].is_mutable());
    assert!(matches!(
        body.instructions()
            .last()
            .map(|instruction| &instruction.kind),
        Some(InstructionKind::TaskComplete)
    ));
}

/// Spawned shared calls capture their caller-place roots without materializing copied receivers.
#[test]
fn spawned_shared_calls_capture_root_and_nested_field_places() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
struct Inputs { counter: Counter, holder: Holder }
impl Counter { pure fn read(shared self) -> Int { self.value } }
fn main(inputs: Inputs) -> List<Int> {
    spawn root_read -> Int { inputs.counter.read() }
    spawn field_read -> Int { inputs.holder.counter.read() }
    joinall()
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let bodies = program.task_bodies();
    assert_eq!(bodies.len(), 2, "{bodies:#?}");
    let root_body = bodies
        .iter()
        .find(|body| {
            body.captures()
                .iter()
                .any(|capture| capture.name() == "inputs")
        })
        .unwrap_or_else(|| panic!("root shared task omitted inputs capture: {bodies:#?}"));
    assert!(matches!(root_body.captures(), [capture]
        if capture.name() == "inputs"
            && capture.ty().canonical_string() == "crate::Inputs"
            && !capture.is_mutable()));
    assert!(root_body.instructions().iter().any(|instruction| matches!(
        &instruction.kind,
        InstructionKind::ReceiverCall {
            source: ReceiverSource::CallerPlace { root, path, .. }, ..
        } if root.as_ref() == "inputs"
            && matches!(path.as_slice(),
                [gantry::value::ValuePathSegment::StructField(field)] if field == "counter")
    )));
    let field_body = bodies
        .iter()
        .find(|body| body.identity() != root_body.identity())
        .unwrap_or_else(|| panic!("nested shared task body missing: {bodies:#?}"));
    assert!(matches!(field_body.captures(), [capture]
        if capture.name() == "inputs"
            && capture.ty().canonical_string() == "crate::Inputs"
            && !capture.is_mutable()));
    assert!(field_body.instructions().iter().any(|instruction| matches!(
        &instruction.kind,
        InstructionKind::ReceiverCall {
            source: ReceiverSource::CallerPlace { root, path, .. }, ..
        } if root.as_ref() == "inputs"
            && matches!(path.as_slice(),
                [
                    gantry::value::ValuePathSegment::StructField(holder),
                    gantry::value::ValuePathSegment::StructField(counter),
                ] if holder == "holder" && counter == "counter")
    )));

    let inputs = LogicalValue::structure(
        "crate::Inputs",
        vec![
            (
                "counter".to_owned(),
                LogicalValue::structure(
                    "crate::Counter",
                    vec![(
                        "value".to_owned(),
                        LogicalValue::integer(
                            GantryInt::new(7)
                                .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                        ),
                    )],
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("root counter fixture failed: {error:?}")),
            ),
            (
                "holder".to_owned(),
                LogicalValue::structure(
                    "crate::Holder",
                    vec![(
                        "counter".to_owned(),
                        LogicalValue::structure(
                            "crate::Counter",
                            vec![(
                                "value".to_owned(),
                                LogicalValue::integer(
                                    GantryInt::new(7).unwrap_or_else(|| {
                                        unreachable!("fixture integer is valid")
                                    }),
                                ),
                            )],
                            DEFAULT_VALUE_LIMITS,
                        )
                        .unwrap_or_else(|error| panic!("nested counter fixture failed: {error:?}")),
                    )],
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}")),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("inputs fixture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5b; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let root_task = root_task_identity(execution);
    let root_session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0x5c; 32])
        .unwrap_or_else(|error| panic!("session identity failed: {error}"));
    let mut sessions = LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("root session registry failed: {error:?}"));
    let mut tasks = ConcurrentTaskStateV1::new(execution, root_task, 3)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    for (index, body) in [root_body, field_body].into_iter().enumerate() {
        let captures = body
            .captures()
            .iter()
            .map(|capture| {
                TaskCaptureV1::new(
                    Arc::from(capture.name()),
                    capture.ty().clone(),
                    capture.is_mutable(),
                    &inputs,
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("task capture failed: {error:?}"))
            })
            .collect::<Vec<_>>();
        let created = tasks
            .create_child(
                &mut sessions,
                TaskCreationRequestV1 {
                    parent_task_id: root_task,
                    handle_name: Arc::from(format!("shared-{index}")),
                    workflow: entry_workflow(&package).path.clone(),
                    spawn_site: body.identity().spawn_site().clone(),
                    spawn_occurrence: 0,
                    result_type: body.result_type().clone(),
                    captures: captures.clone(),
                    inherited_agent: None,
                    parent_session_id: root_session,
                },
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
        tasks
            .resolve_submission(created.task_id, Ok(()))
            .unwrap_or_else(|error| panic!("child submission resolution failed: {error:?}"));
        let task_path = Arc::from(
            tasks
                .task_record(created.task_id)
                .unwrap_or_else(|| panic!("child task record is absent"))
                .task_path(),
        );
        let mut child = Machine::new_concurrent_task_body_with_context(
            Arc::new(program.clone()),
            body.identity(),
            &captures,
            execution,
            created.task_id,
            task_path,
            limits(),
            ExecutionBudget::new(execution, limits()),
            None,
            Some(created.base_session_id),
        )
        .unwrap_or_else(|error| panic!("shared child machine failed: {error:?}"));
        assert!(matches!(child.step(), MachineStep::Transition(_)));
        let budget = ExecutionBudget::recover_from_checkpoint(child.budget_checkpoint())
            .unwrap_or_else(|error| panic!("child budget recovery failed: {error:?}"));
        let recovered = child.checkpoint();
        let mut recovered =
            Machine::recover_from_checkpoint(Arc::new(program.clone()), recovered, budget)
                .unwrap_or_else(|error| panic!("shared child recovery failed: {error:?}"));
        assert!(matches!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(ref value)
                if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
        ));
    }
}

/// Spawned exclusive receiver calls update only their copied task-local capture roots.
#[test]
fn spawned_exclusive_receiver_mutation_stops_at_the_copied_task_root() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter { fn increment(exclusive self) { self.value += 1; } }
impl Holder {
    fn spawn_increment(exclusive self) -> Int {
        spawn child -> Int { self.counter.increment(); self.counter.value }
        join(child)
    }
}
fn main(mut holder: Holder) -> Int { discard holder.spawn_increment(); holder.counter.value }
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let body = program
        .task_bodies()
        .first()
        .unwrap_or_else(|| panic!("exclusive spawn body was not lowered"));
    assert!(
        matches!(body.captures(), [capture] if capture.name() == "self" && capture.is_mutable())
    );

    let original = LogicalValue::structure(
        "crate::Holder",
        vec![(
            "counter".to_owned(),
            LogicalValue::structure(
                "crate::Counter",
                vec![(
                    "value".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                    ),
                )],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let capture = TaskCaptureV1::new(
        Arc::from("self"),
        body.captures()[0].ty().clone(),
        true,
        &original,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("task capture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6a; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let root_task = root_task_identity(execution);
    let root_session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0x6b; 32])
        .unwrap_or_else(|error| panic!("session identity failed: {error}"));
    let mut sessions = LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let mut tasks = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let created = tasks
        .create_child(
            &mut sessions,
            TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from("child"),
                workflow: entry_workflow(&package).path.clone(),
                spawn_site: body.identity().spawn_site().clone(),
                spawn_occurrence: 0,
                result_type: body.result_type().clone(),
                captures: vec![capture.clone()],
                inherited_agent: None,
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    tasks
        .resolve_submission(created.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("child submission failed: {error:?}"));
    let task_path = Arc::from(
        tasks
            .task_record(created.task_id)
            .unwrap_or_else(|| panic!("child task record is absent"))
            .task_path(),
    );
    let mut child = Machine::new_concurrent_task_body_with_context(
        Arc::new(program.clone()),
        body.identity(),
        &[capture],
        execution,
        created.task_id,
        task_path,
        limits(),
        ExecutionBudget::new(execution, limits()),
        None,
        Some(created.base_session_id),
    )
    .unwrap_or_else(|error| panic!("exclusive child machine failed: {error:?}"));
    assert!(matches!(
        drive(&mut child),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 8)
    ));
    assert!(matches!(
        original.field("counter").and_then(|counter| counter.field("value")),
        Some(value) if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// A spawned body that directly assigns a captured exclusive self field stops at the task root.
#[test]
fn spawned_exclusive_receiver_direct_field_assignment_stops_at_the_copied_task_root() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Holder {
    fn spawn_increment(exclusive self) -> Int {
        spawn child -> Int { self.counter.value += 1; self.counter.value }
        join(child)
    }
}
fn main(mut holder: Holder) -> Int { discard holder.spawn_increment(); holder.counter.value }
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let body = program
        .task_bodies()
        .first()
        .unwrap_or_else(|| panic!("exclusive spawn body was not lowered"));
    assert!(
        matches!(body.captures(), [capture] if capture.name() == "self" && capture.is_mutable())
    );

    let original = LogicalValue::structure(
        "crate::Holder",
        vec![(
            "counter".to_owned(),
            LogicalValue::structure(
                "crate::Counter",
                vec![(
                    "value".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                    ),
                )],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let capture = TaskCaptureV1::new(
        Arc::from("self"),
        body.captures()[0].ty().clone(),
        true,
        &original,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("task capture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6c; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let root_task = root_task_identity(execution);
    let root_session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0x6d; 32])
        .unwrap_or_else(|error| panic!("session identity failed: {error}"));
    let mut sessions = LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let mut tasks = ConcurrentTaskStateV1::new(execution, root_task, 2)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let created = tasks
        .create_child(
            &mut sessions,
            TaskCreationRequestV1 {
                parent_task_id: root_task,
                handle_name: Arc::from("child"),
                workflow: entry_workflow(&package).path.clone(),
                spawn_site: body.identity().spawn_site().clone(),
                spawn_occurrence: 0,
                result_type: body.result_type().clone(),
                captures: vec![capture.clone()],
                inherited_agent: None,
                parent_session_id: root_session,
            },
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("child creation failed: {error:?}"));
    tasks
        .resolve_submission(created.task_id, Ok(()))
        .unwrap_or_else(|error| panic!("child submission failed: {error:?}"));
    let task_path = Arc::from(
        tasks
            .task_record(created.task_id)
            .unwrap_or_else(|| panic!("child task record is absent"))
            .task_path(),
    );
    let mut child = Machine::new_concurrent_task_body_with_context(
        Arc::new(program.clone()),
        body.identity(),
        &[capture],
        execution,
        created.task_id,
        task_path,
        limits(),
        ExecutionBudget::new(execution, limits()),
        None,
        Some(created.base_session_id),
    )
    .unwrap_or_else(|error| panic!("exclusive child machine failed: {error:?}"));
    assert!(matches!(
        drive(&mut child),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 8)
    ));
    assert!(matches!(
        original.field("counter").and_then(|counter| counter.field("value")),
        Some(value) if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Tuple destructuring creates an ordinary caller-place root for a shared call.
#[test]
fn tuple_destructured_shared_receiver_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { pure fn read(shared self) -> Int { self.value } }
fn main(pair: Tuple<Counter, Int>) -> Int {
    let (counter, _): Tuple<Counter, Int> = pair;
    counter.read()
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let main = entry_workflow(&package);
    assert!(main.instructions.iter().any(|instruction| matches!(
        &instruction.kind,
        InstructionKind::ReceiverCall {
            source: ReceiverSource::CallerPlace { root, path, .. }, ..
        } if root.as_ref() == "counter" && path.is_empty()
    )));
    let counter = LogicalValue::structure(
        "crate::Counter",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}"));
    let pair = LogicalValue::tuple(
        vec![
            counter,
            LogicalValue::integer(
                GantryInt::new(0).unwrap_or_else(|| unreachable!("fixture integer is valid")),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("tuple fixture failed: {error:?}"));
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4c; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![pair],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("tuple shared program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Refutable Option patterns branch on the actual value and bind nested payloads lexically.
#[test]
fn if_let_option_payload_executes_with_early_return() {
    let root = TempDirectory::new(
        r#"
fn main(value: Option<Tuple<Int, Int>>) -> Int {
    if let Some((number, _)) = value {
        return number;
    }
    8
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let value = LogicalValue::some(
        LogicalValue::tuple(
            vec![
                LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
                LogicalValue::integer(
                    GantryInt::new(0).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
            ],
            DEFAULT_VALUE_LIMITS,
        )
        .unwrap_or_else(|error| panic!("tuple fixture failed: {error:?}")),
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("option fixture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6a; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![value],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("if-let program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
    assert!(
        entry_workflow(&package)
            .instructions
            .iter()
            .any(|instruction| matches!(instruction.kind, InstructionKind::BranchOption { .. }))
    );
}

/// Refutable Result and declared-enum patterns use their exact executable discriminants.
#[test]
fn if_let_result_and_enum_payloads_execute() {
    for (source, value, expected) in [
        (
            r#"fn main(value: Result<Int, Int>) -> Int { if let Ok(number) = value { return number; } 4 }"#,
            LogicalValue::ok(
                LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("result fixture failed: {error:?}")),
            7,
        ),
        (
            r#"enum State { Ready(Int), Empty } fn main(value: State) -> Int { if let State::Ready(number) = value { return number; } 5 }"#,
            LogicalValue::enumeration(
                "crate::State",
                "Ready",
                Some(LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                )),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("enum fixture failed: {error:?}")),
            7,
        ),
    ] {
        let root = TempDirectory::new(source);
        let package = analyze(&root);
        let program = executable(&package);
        let entry = package
            .entry()
            .unwrap_or_else(|| panic!("valid package omitted entry"));
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6b; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"));
        let mut machine = Machine::new(
            Arc::new(program.clone()),
            &entry.path,
            vec![value],
            execution,
            limits(),
        )
        .unwrap_or_else(|error| panic!("if-let program did not start: {error:?}"));
        assert!(matches!(
            drive(&mut machine),
            MachineOutcome::Succeeded(ref value)
                if matches!(value.view(), LogicalValueView::Int(number) if number.get() == expected)
        ));
    }
}

/// `if let` follows the authored Option, Result, and declared-enum variant.
#[test]
fn if_let_honors_none_err_and_payloadless_enum_polarity() {
    for (source, value, expected) in [
        (
            r#"fn main(value: Option<Int>) -> Int { if let None = value { return 1; } 2 }"#,
            LogicalValue::none(),
            1,
        ),
        (
            r#"fn main(value: Option<Int>) -> Int { if let None = value { return 1; } 2 }"#,
            LogicalValue::some(
                LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("option fixture failed: {error:?}")),
            2,
        ),
        (
            r#"fn main(value: Result<Int, Int>) -> Int { if let Err(number) = value { return number; } 4 }"#,
            LogicalValue::err(
                LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("result fixture failed: {error:?}")),
            7,
        ),
        (
            r#"fn main(value: Result<Int, Int>) -> Int { if let Err(number) = value { return number; } 4 }"#,
            LogicalValue::ok(
                LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("result fixture failed: {error:?}")),
            4,
        ),
        (
            r#"enum State { Ready(Int), Empty } fn main(value: State) -> Int { if let State::Empty = value { return 1; } 2 }"#,
            LogicalValue::enumeration("crate::State", "Empty", None, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("enum fixture failed: {error:?}")),
            1,
        ),
        (
            r#"enum State { Ready(Int), Empty } fn main(value: State) -> Int { if let State::Empty = value { return 1; } 2 }"#,
            LogicalValue::enumeration(
                "crate::State",
                "Ready",
                Some(LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is valid")),
                )),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("enum fixture failed: {error:?}")),
            2,
        ),
    ] {
        let root = TempDirectory::new(source);
        let package = analyze(&root);
        let entry = package
            .entry()
            .unwrap_or_else(|| panic!("valid package omitted entry"));
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6d; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"));
        let mut machine = Machine::new(
            Arc::new(executable(&package).clone()),
            &entry.path,
            vec![value],
            execution,
            limits(),
        )
        .unwrap_or_else(|error| panic!("if-let program did not start: {error:?}"));
        assert!(matches!(
            drive(&mut machine),
            MachineOutcome::Succeeded(ref value)
                if matches!(value.view(), LogicalValueView::Int(number) if number.get() == expected)
        ));
    }
}

/// False refutable branches discard exposed payloads before looping or checkpoint recovery.
#[test]
fn false_if_let_branches_keep_stack_and_checkpoints_bounded() {
    use gantry::runtime::MachineCheckpointV3;

    for (source, value, expected_discards) in [
        (
            r#"fn main(value: Option<Int>) -> Int { let mut count: Int = 0; while count < 64 { if let None = value { count += 64; } else { count += 1; } } count }"#,
            LogicalValue::some(
                LogicalValue::integer(GantryInt::new(7).unwrap_or_else(|| unreachable!())),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("option fixture failed: {error:?}")),
            64,
        ),
        (
            r#"fn main(value: Result<Int, Int>) -> Int { let mut count: Int = 0; while count < 64 { if let Ok(_) = value { count += 64; } else { count += 1; } } count }"#,
            LogicalValue::err(
                LogicalValue::integer(GantryInt::new(7).unwrap_or_else(|| unreachable!())),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("Result fixture failed: {error:?}")),
            64,
        ),
        (
            r#"fn main(value: Result<Int, Int>) -> Int { let mut count: Int = 0; while count < 64 { if let Err(_) = value { count += 64; } else { count += 1; } } count }"#,
            LogicalValue::ok(
                LogicalValue::integer(GantryInt::new(7).unwrap_or_else(|| unreachable!())),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("Result fixture failed: {error:?}")),
            64,
        ),
        (
            r#"enum State { Ready(Int), Empty } fn main(value: State) -> Int { let mut count: Int = 0; while count < 64 { if let State::Empty = value { count += 64; } else { count += 1; } } count }"#,
            LogicalValue::enumeration(
                "crate::State",
                "Ready",
                Some(LogicalValue::integer(
                    GantryInt::new(7).unwrap_or_else(|| unreachable!()),
                )),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("enum fixture failed: {error:?}")),
            64,
        ),
        (
            r#"enum State { Ready(Int), Empty } fn main(value: State) -> Int { let mut count: Int = 0; while count < 64 { if let State::Ready(_) = value { count += 64; } else { count += 1; } } count }"#,
            LogicalValue::enumeration("crate::State", "Empty", None, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("enum fixture failed: {error:?}")),
            0,
        ),
    ] {
        let root = TempDirectory::new(source);
        let package = analyze(&root);
        let program = Arc::new(executable(&package).clone());
        let entry = package
            .entry()
            .unwrap_or_else(|| panic!("valid package omitted entry"));
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6f; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"));
        let bounded_loop_limits =
            MachineLimits::new(10_000, 100, 100, 64, 100, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|| unreachable!("positive regression limits"));
        let mut machine = Machine::new(
            Arc::clone(&program),
            &entry.path,
            vec![value],
            execution,
            bounded_loop_limits,
        )
        .unwrap_or_else(|error| panic!("false branch fixture did not start: {error:?}"));
        let mut false_branches = 0;
        let mut checkpoint_sizes = Vec::new();
        let mut outcome = None;
        for _ in 0..10_000 {
            match machine.step() {
                MachineStep::Transition(MachineLabel::Deterministic { kind, .. })
                    if kind.as_ref() == "discard" =>
                {
                    false_branches += 1;
                    let checkpoint_bytes = machine.checkpoint().canonical_bytes();
                    if checkpoint_sizes.is_empty() {
                        let checkpoint = MachineCheckpointV3::decode(&program, &checkpoint_bytes)
                            .unwrap_or_else(|error| {
                                panic!("false-branch checkpoint did not decode: {error:?}")
                            });
                        let budget =
                            ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
                                .unwrap_or_else(|error| {
                                    panic!("false-branch budget did not recover: {error:?}")
                                });
                        machine = Machine::recover_from_checkpoint(
                            Arc::clone(&program),
                            checkpoint,
                            budget,
                        )
                        .unwrap_or_else(|error| {
                            panic!("false-branch checkpoint did not recover: {error:?}")
                        });
                    }
                    checkpoint_sizes.push(checkpoint_bytes.len());
                }
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                MachineStep::Complete(result) => {
                    outcome = Some(result);
                    break;
                }
                other => panic!("false branch loop ended unexpectedly: {other:?}"),
            }
        }
        assert_eq!(false_branches, expected_discards);
        if let (Some(smallest_checkpoint), Some(largest_checkpoint)) = (
            checkpoint_sizes.iter().min().copied(),
            checkpoint_sizes.iter().max().copied(),
        ) {
            assert!(
                largest_checkpoint - smallest_checkpoint <= 4,
                "false-branch checkpoints grew from {smallest_checkpoint} to {largest_checkpoint} bytes"
            );
        }
        assert!(matches!(
            outcome,
            Some(MachineOutcome::Succeeded(ref value))
                if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 64)
        ));
    }
}

/// Compiler temporaries cannot collide with visible source bindings in any pattern form.
#[test]
fn pattern_temporaries_do_not_collide_with_outer_source_bindings() {
    for (source, inputs, expected) in [
        (
            r#"fn main(pair: Tuple<Int, Int>) -> Int { let __gantry_tuple_1: Tuple<Int, Int> = pair; let (left, _): Tuple<Int, Int> = __gantry_tuple_1; left }"#,
            vec![
                LogicalValue::tuple(
                    vec![
                        LogicalValue::integer(GantryInt::new(7).unwrap_or_else(|| unreachable!())),
                        LogicalValue::integer(GantryInt::new(0).unwrap_or_else(|| unreachable!())),
                    ],
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("tuple fixture failed: {error:?}")),
            ],
            7,
        ),
        (
            r#"fn main(value: Option<Int>) -> Int { let __gantry_payload: Int = 3; if let Some(number) = value { return number + __gantry_payload; } 0 }"#,
            vec![
                LogicalValue::some(
                    LogicalValue::integer(GantryInt::new(4).unwrap_or_else(|| unreachable!())),
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("option fixture failed: {error:?}")),
            ],
            7,
        ),
        (
            r#"fn main(value: Result<Int, Int>) -> Int { let __gantry_payload: Int = 3; match value { Ok(number) => number + __gantry_payload, Err(number) => number + __gantry_payload, } }"#,
            vec![
                LogicalValue::err(
                    LogicalValue::integer(GantryInt::new(4).unwrap_or_else(|| unreachable!())),
                    DEFAULT_VALUE_LIMITS,
                )
                .unwrap_or_else(|error| panic!("result fixture failed: {error:?}")),
            ],
            7,
        ),
    ] {
        let root = TempDirectory::new(source);
        let package = analyze(&root);
        let entry = package
            .entry()
            .unwrap_or_else(|| panic!("valid package omitted entry"));
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6e; 32])
            .unwrap_or_else(|error| panic!("identity failed: {error}"));
        let mut machine = Machine::new(
            Arc::new(executable(&package).clone()),
            &entry.path,
            inputs,
            execution,
            limits(),
        )
        .unwrap_or_else(|error| panic!("collision fixture did not start: {error:?}"));
        assert!(matches!(
            drive(&mut machine),
            MachineOutcome::Succeeded(ref value)
                if matches!(value.view(), LogicalValueView::Int(number) if number.get() == expected)
        ));
        assert!(
            entry_workflow(&package)
                .instructions
                .iter()
                .all(|instruction| {
                    !matches!(&instruction.kind, InstructionKind::Bind { name, .. }
                if name.starts_with('\0') && !name.starts_with("\0gantry_"))
                })
        );
    }
}

/// Spawned bodies inherit exact if-let payload binding types and capture the lexical value.
#[test]
fn spawned_if_let_payload_compiles_with_typed_capture() {
    let root = TempDirectory::new(
        r#"
fn main(value: Option<Int>) -> Int {
    if let Some(number) = value {
        spawn child -> Int { number }
        return join(child);
    }
    0
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let body = program
        .task_bodies()
        .first()
        .unwrap_or_else(|| panic!("if-let spawn body was not lowered"));
    assert!(matches!(body.captures(), [capture]
        if capture.name() == "number"
            && capture.ty().canonical_string() == "Int"
            && !capture.is_mutable()));
    assert!(body.instructions().iter().any(|instruction| matches!(
        &instruction.kind,
        InstructionKind::Load(name) if name.as_ref() == "number"
    )));
}

/// Tuple destructuring evaluates its source once and supports nested patterns from calls.
#[test]
fn nested_call_produced_tuple_destructuring_executes() {
    let root = TempDirectory::new(
        r#"
fn pair() -> Tuple<Tuple<Int, Int>, Int> { ((7, 8), 9) }
fn main() -> Int {
    let ((number, _), _): Tuple<Tuple<Int, Int>, Int> = pair();
    number
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6b; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("tuple program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

/// Payload bindings remain values, while copied nested receiver calls remain executable.
#[test]
fn copied_nested_payload_receiver_call_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
struct Holder { counter: Counter }
impl Counter { pure fn read(self) -> Int { self.value } }
fn main(value: Option<Holder>) -> Int {
    if let Some(holder) = value { return holder.counter.read(); }
    0
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted entry"));
    let holder = LogicalValue::structure(
        "crate::Holder",
        vec![(
            "counter".to_owned(),
            LogicalValue::structure(
                "crate::Counter",
                vec![(
                    "value".to_owned(),
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is valid")),
                    ),
                )],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("counter fixture failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("holder fixture failed: {error:?}"));
    let value = LogicalValue::some(holder, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("option fixture failed: {error:?}"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x6c; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program.clone()),
        &entry.path,
        vec![value],
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("payload receiver program did not start: {error:?}"));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value)
            if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
}

#[test]
fn analyzed_concurrent_entry_reaches_the_existing_profile_rejection() {
    // Executable lowering does not imply adoption of native runtime scheduling.
    let root = TempDirectory::new(
        r#"
fn main() {
    spawn child { return; }
    discard join(child);
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x4b; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));

    assert!(matches!(
        Machine::new(
            Arc::new(program),
            &entry.path,
            Vec::new(),
            execution,
            limits()
        ),
        Err(MachineBuildError::UnsupportedEffect(_))
    ));
}

/// Exercises independent nested bodies and source-order ownership selections.
#[test]
fn nested_task_bodies_preserve_captures_and_joinall_order() {
    let root = TempDirectory::new(
        r#"
fn main() {
    let mut retained: Int = 7;
    let unused: Bool = false;
    spawn outer -> Int {
        let local: Int = 3;
        spawn inner -> Int { retained = retained + local; retained }
        join(inner)
    }
    spawn alpha -> String { "second" }
    let results: Tuple<Int, String> = joinall();
    discard joinall();
    spawn background { return; }
    detach(background);
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    assert_eq!(program.task_bodies().len(), 4);
    let outer = program
        .task_bodies()
        .iter()
        .find(|body| {
            body.instructions()
                .iter()
                .any(|instruction| matches!(instruction.kind, InstructionKind::Spawn { .. }))
        })
        .unwrap_or_else(|| panic!("nested fixture omitted outer body"));
    assert_eq!(outer.captures().len(), 1);
    assert_eq!(outer.captures()[0].name(), "retained");
    assert!(outer.captures()[0].is_mutable());
    let inner = program
        .task_bodies()
        .iter()
        .find(|body| body.captures().len() == 2)
        .unwrap_or_else(|| panic!("nested fixture omitted inner captures"));
    assert_eq!(
        inner
            .captures()
            .iter()
            .map(|capture| capture.name())
            .collect::<Vec<_>>(),
        ["retained", "local"]
    );
    assert!(inner.captures()[0].is_mutable());
    assert!(!inner.captures()[1].is_mutable());
    let workflow = entry_workflow(&package);
    let joins = workflow
        .instructions
        .iter()
        .filter_map(|instruction| {
            if let InstructionKind::JoinAll { handles } = &instruction.kind {
                Some((
                    handles.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
                    instruction.ty.canonical_string(),
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        joins,
        [
            (vec!["outer", "alpha"], "Tuple<Int,String>".to_string()),
            (vec![], "Unit".to_string())
        ]
    );
    for body in program.task_bodies() {
        assert!(
            !body
                .instructions()
                .iter()
                .any(|instruction| matches!(instruction.kind, InstructionKind::Return))
        );
        assert!(
            body.captures()
                .iter()
                .all(|capture| capture.name() != "unused")
        );
    }
}

/// A single authored spawn must not alias two closed generic instantiations.
#[test]
fn generic_task_bodies_have_closed_distinct_identities() {
    let root = TempDirectory::new(
        r#"
fn copy_task<T>(value: T) -> T {
    spawn copied -> T { value }
    join(copied)
}
fn main() {
    discard copy_task(7);
    discard copy_task("text");
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let bodies = program.task_bodies();
    assert_eq!(bodies.len(), 2);
    assert_ne!(
        bodies[0].identity().enclosing_callable(),
        bodies[1].identity().enclosing_callable()
    );
    assert_eq!(
        bodies[0].identity().spawn_site(),
        bodies[1].identity().spawn_site()
    );
    for body in bodies {
        assert_eq!(body.captures()[0].ty(), body.result_type());
        assert!(["Int", "String"].contains(&body.result_type().canonical_string().as_str()));
    }
    let repeated = analyze(&root);
    assert_eq!(program, executable(&repeated));
}

/// A join operand must not replace its enclosing arithmetic expression.
#[test]
fn join_operand_preserves_surrounding_expression() {
    let root = TempDirectory::new(
        r#"
fn main() -> Int {
    spawn child -> Int { 7 }
    join(child) + 1
}
"#,
    );
    let package = analyze(&root);
    let workflow = entry_workflow(&package);
    assert!(
        workflow
            .instructions
            .iter()
            .any(|instruction| matches!(instruction.kind, InstructionKind::Primitive(_)))
    );
}

/// Break cleanup does not change the statically selected free bindings.
#[test]
fn child_loop_exit_preserves_capture_selection() {
    let root = TempDirectory::new(
        r#"
fn main() -> Int {
    let retained: Int = 7;
    spawn child -> Int {
        loop(limit = 1) { break; }
        let local: Int = 1;
        retained + local
    }
    join(child)
}
"#,
    );
    let package = analyze(&root);
    let body = &executable(&package).task_bodies()[0];
    assert_eq!(body.captures().len(), 1);
    assert_eq!(body.captures()[0].name(), "retained");
}

/// Closed generic methods retain the receiver's child-local mutability.
#[test]
fn generic_task_captures_mutable_receiver() {
    let root = TempDirectory::new(
        r#"
struct Holder<T> { value: T }
impl<T> Holder<T> {
    fn copied(mut self, replacement: T) -> T {
        spawn child -> T { self.value = replacement; self.value }
        join(child)
    }
}
fn main() -> Int {
    let holder: Holder<Int> = Holder::<Int> { value: 1 };
    holder.copied(7)
}
"#,
    );
    let package = analyze(&root);
    let body = &executable(&package).task_bodies()[0];
    let receiver = body
        .captures()
        .iter()
        .find(|capture| capture.name() == "self")
        .unwrap_or_else(|| panic!("method task omitted receiver capture"));
    assert!(receiver.is_mutable());
    assert_eq!(receiver.ty().canonical_string(), "crate::Holder<Int>");
    assert_eq!(body.result_type().canonical_string(), "Int");
}

/// Loop transfers restore nested scopes before continuing or leaving the loop.
#[test]
fn lowered_loop_transfers_execute_with_balanced_scopes() {
    let root = TempDirectory::new(
        r#"
fn main() -> Int {
    let mut count: Int = 0;
    loop(limit = 5) {
        count += 1;
        if count < 3 { continue; }
        break;
    }
    count
}
"#,
    );
    let package = analyze(&root);
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x51; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(executable(&package).clone()),
        &entry_workflow(&package).path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("loop program failed: {error:?}"));
    let outcome = drive(&mut machine);
    assert!(
        matches!(outcome, MachineOutcome::Succeeded(ref value)
        if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 3)),
        "{outcome:?}"
    );
}

/// Requires the executable artifact guaranteed by a valid fixture.
fn executable(package: &gantry::analysis::TypedPackage) -> &gantry::ir::MachineProgram {
    package
        .executable_program()
        .unwrap_or_else(|| panic!("valid fixture omitted executable program"))
}

/// Retaining task IR is independent of executing or recovering a task graph.
#[test]
fn analyzed_task_program_round_trips_through_retained_codec() {
    use gantry::runtime::{
        DurableCommitCutV1, DurableExecutionStartV3, DurableLogicalEvidenceV3, root_task_identity,
    };
    let root = TempDirectory::new(
        r#"
pure fn value() -> Int { 7 }
fn main() -> Int {
    spawn child -> Int { value() }
    join(child)
}
"#,
    );
    let package = analyze(&root);
    let program = executable(&package);
    let helper = program
        .workflows()
        .iter()
        .find(|workflow| workflow.path.as_str() == "crate::value")
        .unwrap_or_else(|| panic!("task call omitted helper"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x52; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"));
    let task = root_task_identity(execution);
    let machine = Machine::new(
        Arc::new(program.clone()),
        &helper.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("helper machine failed: {error:?}"));
    let state = DurableLogicalEvidenceV3::new(
        execution,
        task,
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
    )
    .unwrap_or_else(|error| panic!("checkpoint evidence failed: {error:?}"));
    let retained = DurableExecutionStartV3::new(
        execution,
        task,
        program,
        Arc::<[u8]>::from(&b"{}"[..]),
        state,
    )
    .unwrap_or_else(|error| panic!("retained program failed: {error:?}"));
    assert_eq!(
        &retained
            .program()
            .unwrap_or_else(|error| panic!("decode failed: {error:?}")),
        program
    );
}

/// Resolves the fixture entry without hiding missing-artifact diagnostics.
fn entry_workflow(package: &gantry::analysis::TypedPackage) -> &gantry::ir::Workflow {
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid fixture omitted entry"));
    executable(package)
        .workflow(&entry.path)
        .unwrap_or_else(|| panic!("entry workflow was not lowered"))
}

/// Flattened same-precedence operator chains associate left to right.
#[test]
fn flattened_operator_chains_associate_left_to_right() {
    for (source, expected) in [
        ("fn main() -> Int { 10 - 2 - 3 }", 5),
        ("fn main() -> Int { 20 - 5 - 3 - 2 }", 10),
        ("fn main() -> Int { 100 / 5 / 2 }", 10),
        ("fn main() -> Int { 10 - 2 + 3 }", 11),
        ("fn main() -> Int { 1 + 2 + 3 }", 6),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(
            run_single_entry(&root),
            expected,
            "{source} associated wrongly"
        );
    }
}

/// Parentheses still override the left-to-right chain association.
#[test]
fn parenthesized_operands_override_chain_association() {
    for (source, expected) in [
        ("fn main() -> Int { 10 - (2 - 3) }", 11),
        ("fn main() -> Int { (10 - 2) - 3 }", 5),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(
            run_single_entry(&root),
            expected,
            "{source} ignored its parentheses"
        );
    }
}

/// Mixed-precedence chains fold left to right while tighter precedence still binds first.
#[test]
fn mixed_precedence_chains_keep_tighter_binding() {
    for (source, expected) in [
        ("fn main() -> Int { 1 * 2 + 3 }", 5),
        ("fn main() -> Int { 1 + 2 * 3 }", 7),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(run_single_entry(&root), expected, "{source}");
    }
    let root = TempDirectory::new("fn main() -> Bool { 1 + 2 == 3 }");
    let value = run_entry(&analyze(&root));
    assert!(
        matches!(value.view(), LogicalValueView::Bool(true)),
        "arithmetic-then-comparison chain returned {:?}",
        value.view()
    );
}

/// `&&` and `||` lower to the documented short-circuit Boolean algebra.
#[test]
fn logical_operators_lower_boolean_values() {
    for (source, expected) in [
        ("fn main() -> Bool { true && false }", false),
        ("fn main() -> Bool { false && true }", false),
        ("fn main() -> Bool { true && true }", true),
        ("fn main() -> Bool { true || false }", true),
        ("fn main() -> Bool { false || false }", false),
        ("fn main() -> Bool { false || true }", true),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(boolean_entry(&root), expected, "{source} lowered wrongly");
    }
}

/// Logical operands may be bindings, comparisons, negations, and flattened chains.
#[test]
fn logical_operators_accept_derived_bool_operands() {
    for (source, expected) in [
        (
            "fn main() -> Bool { let flag: Bool = 1 < 2; flag && true }",
            true,
        ),
        (
            "fn main() -> Bool { let flag: Bool = 1 > 2; flag && true }",
            false,
        ),
        (
            "fn main() -> Bool { let flag: Bool = 1 > 2; flag || (1 < 2) }",
            true,
        ),
        (
            "fn main() -> Bool { let left: Bool = 1 < 2; let right: Bool = 2 < 1; left && right }",
            false,
        ),
        (
            "fn main() -> Bool { let flag: Bool = !(1 < 2); flag || true }",
            true,
        ),
        ("fn main() -> Bool { true && true && false }", false),
        ("fn main() -> Bool { false || false || true }", true),
        (
            "fn main() -> Bool { let flag: Bool = 1 < 2; flag && true || false }",
            true,
        ),
        (
            "fn main() -> Bool { let flag: Bool = 1 < 2; flag && (false || true) }",
            true,
        ),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(boolean_entry(&root), expected, "{source} lowered wrongly");
    }
}

/// A deciding left operand skips the right operand, and only a decided one skips it.
#[test]
fn logical_operators_short_circuit_the_right_operand() {
    // A skipped right operand never performs the division that fails deterministically.
    for (source, expected) in [
        (
            "fn main() -> Bool { let zero: Int = 0; false && (1 / zero == 0) }",
            false,
        ),
        (
            "fn main() -> Bool { let zero: Int = 0; true || (1 / zero == 0) }",
            true,
        ),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(boolean_entry(&root), expected, "{source} skipped wrongly");
    }
    // The mirror forms must evaluate it, so the operator is not simply dropped.
    for source in [
        "fn main() -> Bool { let zero: Int = 0; true && (1 / zero == 0) }",
        "fn main() -> Bool { let zero: Int = 0; false || (1 / zero == 0) }",
    ] {
        let root = TempDirectory::new(source);
        let MachineOutcome::Failed(failure) = run_entry_outcome(&analyze(&root)) else {
            panic!("{source} did not evaluate its right operand");
        };
        assert!(
            matches!(failure.code, RuntimeCode::Deterministic(_)),
            "{source} failed for another reason: {failure:?}"
        );
    }
}

/// Runs one fixture entry and reports the `Bool` value it returns.
fn boolean_entry(root: &TempDirectory) -> bool {
    let value = run_entry(&analyze(root));
    match value.view() {
        LogicalValueView::Bool(value) => value,
        other => panic!("entry returned {other:?}"),
    }
}

/// Runs one analyzed fixture entry and reports its outcome without requiring success.
fn run_entry_outcome(package: &gantry::analysis::TypedPackage) -> MachineOutcome {
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5f; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("program was rejected: {error:?}"));
    drive(&mut machine)
}

fn run_single_entry(root: &TempDirectory) -> i64 {
    let package = analyze(root);
    let value = run_entry(&package);
    match value.view() {
        LogicalValueView::Int(value) => value.get(),
        other => panic!("entry returned {other:?}"),
    }
}

/// A plain assignment whose right-hand side reads the same exclusive receiver subplace is accepted
/// and writes back to the caller place, exactly like the compound form.
#[test]
fn exclusive_receiver_plain_assignment_evaluates_and_writes_back() {
    for body in ["self.value = self.value + 1", "self.value += 1"] {
        let source = format!(
            "struct Counter {{ value: Int }}\n\
             impl Counter {{ fn bump(exclusive self) -> Int {{ {body}; self.value }} }}\n\
             fn main() -> Int {{\n\
                 let mut counter: Counter = Counter {{ value: 1 }};\n\
                 discard counter.bump();\n\
                 counter.value\n\
             }}\n"
        );
        let root = TempDirectory::new(&source);
        assert_eq!(
            run_single_entry(&root),
            2,
            "exclusive receiver assignment `{body}` did not write back"
        );
    }
    // A `mut self` receiver is an independent local copy, so the caller place is unchanged.
    let root = TempDirectory::new(
        "struct Counter { value: Int }\n\
         impl Counter { fn bump(mut self) -> Int { self.value = self.value + 1; self.value } }\n\
         fn main() -> Int { let mut counter: Counter = Counter { value: 1 }; discard counter.bump(); counter.value }\n",
    );
    assert_eq!(run_single_entry(&root), 1);
}

/// The filed reproduction: a statement `match` whose block arms all `return` is accepted and
/// runs, returning the matching arm's value (`GNT-3-T-BRANCH`, `GNT-3-T-COMPLETION`).
#[test]
fn reported_diverging_match_statement_executes() {
    let root = TempDirectory::new(
        "enum Flag { On, Off }\n\
         fn make() -> Flag { Flag::On }\n\
         fn pick(flag: Flag) -> Int { match flag { Flag::On => { return 1; }, Flag::Off => { return 2; } } }\n\
         fn main() -> Int { pick(make()) }\n",
    );
    assert_eq!(run_single_entry(&root), 1);
}

/// Every arm of a diverging statement `match` returns through its own arm.
#[test]
fn diverging_statement_match_selects_the_matching_arm() {
    for (flag, expected) in [("Flag::On", 1), ("Flag::Off", 2)] {
        let root = TempDirectory::new(&format!(
            "enum Flag {{ On, Off }}\n\
             fn pick(flag: Flag) -> Int {{ match flag {{ Flag::On => {{ return 1; }}, Flag::Off => {{ return 2; }} }} }}\n\
             fn main() -> Int {{ pick({flag}) }}\n"
        ));
        assert_eq!(run_single_entry(&root), expected, "{flag}");
    }
}

/// When only some arms diverge, the match falls through to the following statement.
#[test]
fn mixed_diverging_match_statement_continues_after_the_match() {
    let root = TempDirectory::new(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { let mut result: Int = 0; match flag { Flag::On => { return 1; }, Flag::Off => { result = 2; } } result }\n\
         fn main() -> Int { pick(Flag::Off) }\n",
    );
    assert_eq!(run_single_entry(&root), 2);
}

/// `break` and `continue` inside match arms target the enclosing loop.
#[test]
fn loop_transfers_inside_match_arms_reach_the_loop() {
    let root = TempDirectory::new(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { let mut x: Int = 0; loop { match flag { Flag::On => { break; }, Flag::Off => { continue; } } } x }\n\
         fn main() -> Int { pick(Flag::On) }\n",
    );
    assert_eq!(run_single_entry(&root), 0);
}

/// A nested all-diverging match and a payload carrier both complete through their arms.
#[test]
fn nested_and_payload_diverging_matches_execute() {
    let nested = TempDirectory::new(
        "enum Flag { On, Off }\n\
         enum Box { Wrapped(Flag), Empty }\n\
         fn pick(value: Box) -> Int { match value { Box::Wrapped(flag) => { match flag { Flag::On => { return 1; }, Flag::Off => { return 2; } } }, Box::Empty => { return 3; } } }\n\
         fn main() -> Int { pick(Box::Empty) }\n",
    );
    assert_eq!(run_single_entry(&nested), 3);

    let payload = TempDirectory::new(
        "enum Box { Wrapped(Int), Empty }\n\
         fn pick(value: Box) -> Int { match value { Box::Wrapped(item) => { return item; }, Box::Empty => { return 0; } } }\n\
         fn main() -> Int { pick(Box::Wrapped(7)) }\n",
    );
    assert_eq!(run_single_entry(&payload), 7);
}

/// An `if`/`else` whose branches both return is the same completion shape and also needs no
/// trailing result.
#[test]
fn diverging_if_else_still_returns_through_its_branches() {
    let root = TempDirectory::new(
        "fn pick(flag: Bool) -> Int { if flag { return 1; } else { return 2; } }\n\
         fn main() -> Int { pick(false) }\n",
    );
    assert_eq!(run_single_entry(&root), 2);
}

/// An ordinary value-producing `match` expression still returns its arm value.
#[test]
fn value_producing_match_still_returns_its_arm_value() {
    let root = TempDirectory::new(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { match flag { Flag::On => 1, Flag::Off => 2 } }\n\
         fn main() -> Int { pick(Flag::Off) }\n",
    );
    assert_eq!(run_single_entry(&root), 2);
}

/// A statement `match` may name one variant and cover the rest with `_`; the catch-all arm
/// runs for every variant the explicit arms do not name (`GNT-3-T-BRANCH`).
#[test]
fn wildcard_statement_match_arms_execute() {
    let root = TempDirectory::new(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { match flag { Flag::On => { return 1; }, _ => { return 2; } } }\n\
         fn main() -> Int { pick(Flag::Off) }\n",
    );
    assert_eq!(run_single_entry(&root), 2);

    let only_wildcard = TempDirectory::new(
        "enum Flag { On, Off }\n\
         fn pick(flag: Flag) -> Int { match flag { _ => { return 1; } } }\n\
         fn main() -> Int { pick(Flag::Off) }\n",
    );
    assert_eq!(run_single_entry(&only_wildcard), 1);
}

/// `Option` and `Result` statement matches accept `_` as the absent/error alternative.
#[test]
fn wildcard_statement_match_alternatives_execute() {
    let option = TempDirectory::new(
        "fn pick(value: Option<Int>) -> Int { match value { Some(item) => { return item; }, _ => { return 0; } } }\n\
         fn main() -> Int { pick(None) }\n",
    );
    assert_eq!(run_single_entry(&option), 0);

    let result = TempDirectory::new(
        "fn pick(value: Result<Int,String>) -> Int { match value { Ok(item) => { return item; }, _ => { return 0; } } }\n\
         fn main() -> Int { pick(Err(\"failed\")) }\n",
    );
    assert_eq!(run_single_entry(&result), 0);
}

/// An `else if` chain selects the first reachable condition's arm, not the first `else` block.
#[test]
fn else_if_chain_selects_the_first_true_condition() {
    for (chain, expected) in [
        (
            "if false { return 1; } else if false { return 2; } else { return 3; }",
            3,
        ),
        (
            "if false { return 1; } else if true { return 2; } else { return 3; }",
            2,
        ),
        (
            "if true { return 1; } else if true { return 2; } else { return 3; }",
            1,
        ),
    ] {
        let root = TempDirectory::new(&format!(
            "fn pick() -> Int {{ {chain} }}\nfn main() -> Int {{ pick() }}\n"
        ));
        assert_eq!(run_single_entry(&root), expected, "{chain}");
    }
}

fn run_entry(package: &gantry::analysis::TypedPackage) -> LogicalValue {
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("valid package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5d; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("program was rejected: {error:?}"));
    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("program did not succeed")
    };
    value
}

fn analyze(root: &TempDirectory) -> gantry::analysis::TypedPackage {
    let syntax = validate_package_syntax(
        &root.0,
        SourceLimits::new(8, 1_048_576, 4_194_304, 262_144, 256)
            .unwrap_or_else(|_| unreachable!("positive fixture limits")),
        i64::MAX as u64,
    )
    .unwrap_or_else(|error| panic!("syntax failed: {error}"));
    let package = analyze_package_types(&syntax)
        .unwrap_or_else(|error| panic!("analysis failed operationally: {error}"));
    assert_eq!(
        package.status(),
        AnalysisStatus::Valid,
        "{:?}",
        package.diagnostics()
    );
    package
}

fn limits() -> MachineLimits {
    MachineLimits::new(1_000, 100, 100, 64, 100, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| unreachable!("positive fixture limits"))
}

fn drive(machine: &mut Machine) -> MachineOutcome {
    for _ in 0..10_000 {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::Complete(outcome) => return outcome,
            MachineStep::WaitingSessionScope(scope) => {
                panic!("deterministic fixture requested session scope {scope:?}")
            }
            MachineStep::WaitingOperation(operation) => {
                panic!("deterministic fixture requested operation {operation:?}")
            }
        }
    }
    panic!("machine did not settle within the fixture bound")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| unreachable!("conformance crate is nested below the workspace"))
        .to_path_buf()
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn assert_anchor_exists(root: &Path, evidence: &str) {
    let (path, anchor) = evidence
        .split_once('#')
        .unwrap_or_else(|| panic!("evidence has no anchor: {evidence}"));
    let source = fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("could not read evidence {path}: {error}"));
    assert!(
        source.contains(&format!("fn {anchor}")),
        "missing evidence anchor {evidence}"
    );
}

/// Split field projection operands execute as their member type on the shared machine.
#[test]
fn split_field_projection_operands_execute_as_their_member_type() {
    let root = TempDirectory::new(
        r#"
struct Token { a: Int, b: Int }
fn main() -> Int {
    let token: Token = Token { a: 1, b: 2 };
    token.a + token.b
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("projected operand package omitted its executable program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5a; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("projected operand program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("projected operand program did not succeed")
    };
    assert!(matches!(value.view(), LogicalValueView::Int(value) if value.get() == 3));
}

/// A nested projection chain operand executes as its leaf member type.
#[test]
fn nested_field_projection_operands_execute_as_their_member_type() {
    let root = TempDirectory::new(
        r#"
struct Inner { value: Int }
struct Outer { inner: Inner }
fn main() -> Int {
    let outer: Outer = Outer { inner: Inner { value: 4 } };
    outer.inner.value + outer.inner.value
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("nested projected operand package omitted its program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5b; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("nested projected operand program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("nested projected operand program did not succeed")
    };
    assert!(matches!(value.view(), LogicalValueView::Int(value) if value.get() == 8));
}

/// A flattened projection chain operand keeps left-to-right operator order.
#[test]
fn chained_field_projection_operands_execute_left_to_right() {
    let root = TempDirectory::new(
        r#"
struct Token { a: Int, b: Int, c: Int }
fn main() -> Int {
    let token: Token = Token { a: 7, b: 2, c: 1 };
    token.a - token.b - token.c
}
"#,
    );
    let package = analyze(&root);
    let entry = package
        .entry()
        .unwrap_or_else(|| panic!("valid package omitted its entry inventory"));
    let program = package
        .executable_program()
        .cloned()
        .unwrap_or_else(|| panic!("chained projected operand package omitted its program"));
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x5c; 32])
        .unwrap_or_else(|error| panic!("execution identity failed: {error}"));
    let mut machine = Machine::new(
        Arc::new(program),
        &entry.path,
        Vec::new(),
        execution,
        limits(),
    )
    .unwrap_or_else(|error| panic!("chained projected operand program was rejected: {error:?}"));

    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("chained projected operand program did not succeed")
    };
    assert!(matches!(value.view(), LogicalValueView::Int(value) if value.get() == 4));
}

/// A receiver call used as the left operand lowers as a call whose result feeds the operator.
#[test]
fn receiver_call_operand_on_the_left_executes_as_its_result_type() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
fn main() -> Int {
    let c: Counter = Counter { value: 5 };
    c.read() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// A receiver call used as the right operand lowers as a call whose result feeds the operator.
#[test]
fn receiver_call_operand_on_the_right_executes_as_its_result_type() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
fn main() -> Int {
    let c: Counter = Counter { value: 5 };
    1 + c.read()
}
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// Two receiver calls in one flattened operand chain each lower once and fold left to right.
#[test]
fn receiver_call_operands_in_a_chain_execute_left_to_right() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
fn main() -> Int {
    let c: Counter = Counter { value: 5 };
    c.read() + c.read()
}
"#,
    );
    assert_eq!(run_single_entry(&root), 10);
}

/// A receiver call used as a call argument lowers as a call producing that argument.
#[test]
fn receiver_call_operand_as_call_argument_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
fn identity(value: Int) -> Int { value }
fn main() -> Int {
    let c: Counter = Counter { value: 5 };
    identity(c.read())
}
"#,
    );
    assert_eq!(run_single_entry(&root), 5);
}

/// A receiver call with an explicit argument used as an operand lowers its argument then the call.
#[test]
fn receiver_call_with_argument_operand_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn add(self, other: Int) -> Int { self.value + other } }
fn main() -> Int {
    let c: Counter = Counter { value: 5 };
    c.add(2) + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 8);
}

/// A receiver-call operand whose receiver is a shared caller place lowers as a place loan.
#[test]
fn shared_receiver_call_operand_lowers_as_a_place_loan() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(shared self) -> Int { self.value } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    counter.read() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// A receiver-call operand whose receiver is an exclusive caller place lowers as a place loan.
#[test]
fn exclusive_receiver_call_operand_lowers_as_a_place_loan() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn bump(exclusive self) -> Int { self.value = self.value + 1; self.value } }
fn main() -> Int {
    let mut counter: Counter = Counter { value: 1 };
    counter.bump() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 3);
}

/// An `owned self` call operand on an affine receiver moves the caller place, then adds.
#[test]
fn owned_receiver_call_operand_moves_caller_place() {
    let root = TempDirectory::new(
        r#"
affine struct Token { value: Int }
impl Token { fn consume(owned self) -> Int { self.value } }
fn main() -> Int {
    let token: Token = Token { value: 5 };
    token.consume() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// An `owned self` call operand on a copyable receiver admits the copied value, then adds.
#[test]
fn copyable_owned_receiver_call_operand_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(owned self) -> Int { self.value } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    counter.read() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// A `MustConsume` return transfer carries the obligation through the call and executes.
#[test]
fn must_consume_return_transfer_executes() {
    let root = TempDirectory::new(
        r#"
must_consume struct Guard { value: Int }
impl Guard { fn release(owned self) -> Int { self.value } }
fn pass(guard: Guard) -> Guard {
    return guard;
}
fn main() -> Int {
    let guard: Guard = pass(Guard { value: 5 });
    guard.release() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// A `MustConsume` return operand that names a struct-field projection executes as a partial move.
#[test]
fn must_consume_projection_return_transfer_executes() {
    let root = TempDirectory::new(
        r#"
must_consume struct Guard { value: Int }
struct Holder { guard: Guard, count: Int }
impl Guard { fn release(owned self) -> Int { self.value } }
fn take(holder: Holder) -> Guard {
    return holder.guard;
}
fn main() -> Int {
    let guard: Guard = take(Holder { guard: Guard { value: 7 }, count: 1 });
    guard.release() + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 8);
}

/// A free call with explicit arguments still lowers when its result is an operand.
#[test]
fn free_call_with_arguments_operand_still_lowers() {
    let root = TempDirectory::new(
        r#"
fn add(left: Int, right: Int) -> Int { left + right }
fn main() -> Int { add(1, 2) + 1 }
"#,
    );
    assert_eq!(run_single_entry(&root), 4);
}

/// A receiver call with an explicit argument still lowers when its result is an operand.
#[test]
fn receiver_call_with_argument_as_call_argument_still_lowers() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn add(self, other: Int) -> Int { self.value + other } }
fn identity(value: Int) -> Int { value }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    identity(counter.add(2)) + counter.add(1)
}
"#,
    );
    assert_eq!(run_single_entry(&root), 13);
}

/// A receiver-call operand whose receiver is a constructed aggregate lowers as a call.
#[test]
fn constructed_receiver_call_operand_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
fn main() -> Int { Counter { value: 5 }.read() + 1 }
"#,
    );
    assert_eq!(run_single_entry(&root), 6);
}

/// A receiver call whose argument is itself a receiver call types and executes as the left operand.
///
/// The argument's own closing parenthesis is a retained token of the argument expression, so
/// reconstructing the outer call must not mistake it for the parenthesis that closes the outer
/// argument list; otherwise the nested call is reported as an arity mismatch.
#[test]
fn receiver_call_argument_that_is_a_receiver_call_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    counter.add(counter.read()) + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 11);
}

/// The same nested receiver-call argument types and executes as the right operand of an operator.
#[test]
fn receiver_call_argument_that_is_a_receiver_call_on_the_right_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    1 + counter.add(counter.read())
}
"#,
    );
    assert_eq!(run_single_entry(&root), 11);
}

/// A plain nested receiver-call argument with no surrounding operator executes as its own result.
#[test]
fn receiver_call_argument_that_is_a_receiver_call_alone_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    counter.add(counter.read())
}
"#,
    );
    assert_eq!(run_single_entry(&root), 10);
}

/// An argument that is a chain of receiver calls types and executes as that chain's value.
#[test]
fn receiver_call_argument_that_is_a_receiver_call_chain_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn read(self) -> Int { self.value } }
impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    counter.add(counter.read() + counter.read())
}
"#,
    );
    assert_eq!(run_single_entry(&root), 15);
}

/// A receiver call with explicit type arguments still lowers when its result is an operand.
///
/// The generic instantiation registers its resolved call site against the whole call, exactly
/// like the monomorphic receiver call, so operand lowering resolves the same direct target the
/// split operand reconstructs instead of falling back to the fragment walk and reporting an
/// internal error.
#[test]
fn generic_receiver_call_operand_executes() {
    let root = TempDirectory::new(
        r#"
struct Counter { value: Int }
impl Counter { fn pick<T>(self, value: Int) -> Int { value } }
fn main() -> Int {
    let counter: Counter = Counter { value: 5 };
    counter.pick::<Int>(2) + 1
}
"#,
    );
    assert_eq!(run_single_entry(&root), 3);
}

/// A generic free call with explicit type arguments still lowers when its result is an operand.
///
/// A free generic call registers its resolved call site the same way, so the operand resolves the
/// call rather than the fragment walk. Its operand form failed with an internal error before that
/// registration was aligned with the monomorphic free call.
#[test]
fn generic_free_call_operand_executes() {
    let root = TempDirectory::new(
        r#"
fn pick<T>(value: Int) -> Int { value }
fn main() -> Int { pick::<Int>(2) + 1 }
"#,
    );
    assert_eq!(run_single_entry(&root), 3);
}

/// The monomorphic receiver-call operands still execute beside the generic form.
#[test]
fn monomorphic_receiver_call_operands_still_execute() {
    for (source, expected) in [
        (
            "struct Counter { value: Int }\n\
             impl Counter { fn read(self) -> Int { self.value } }\n\
             fn main() -> Int { let counter: Counter = Counter { value: 5 }; counter.read() + 1 }\n",
            6,
        ),
        (
            "struct Counter { value: Int }\n\
             impl Counter { fn add(self, other: Int) -> Int { self.value + other } }\n\
             fn main() -> Int { let counter: Counter = Counter { value: 5 }; counter.add(2) + 1 }\n",
            8,
        ),
        (
            "struct Counter { value: Int }\n\
             impl Counter { fn read(self) -> Int { self.value } }\n\
             impl Counter { fn add(self, amount: Int) -> Int { self.value + amount } }\n\
             fn main() -> Int { let counter: Counter = Counter { value: 5 }; counter.add(counter.read()) + 1 }\n",
            11,
        ),
    ] {
        let root = TempDirectory::new(source);
        assert_eq!(
            run_single_entry(&root),
            expected,
            "{source} lowered wrongly"
        );
    }
}
