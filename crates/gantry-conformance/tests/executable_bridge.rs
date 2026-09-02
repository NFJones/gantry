//! Public regression coverage for the analyzer-to-runtime executable handoff.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::identity::ProtocolIdentity;
use gantry::portable::IdentityKind;
use gantry::runtime::{
    InstructionKind, Machine, MachineBuildError, MachineLimits, MachineOutcome, MachineStep,
    OperationCompletionError,
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
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert_eq!(
        manifest.specification_sha256,
        gantry::PROFILE_SPECIFICATION_REVISION
    );
    assert_eq!(manifest.entries.len(), 27);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(manifest.advertises_profiles.is_empty());
    assert_eq!(manifest.exclusions.len(), 3);
    assert!(gantry::advertised_profiles().is_empty());

    for entry in manifest.entries {
        assert_anchor_exists(&root, &entry.evidence);
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
        assert_eq!(evaluator.evidence, [entry.evidence]);
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
    assert!(
        program
            .workflows()
            .iter()
            .flat_map(|workflow| &workflow.instructions)
            .filter_map(|instruction| match &instruction.kind {
                InstructionKind::Call { callee, .. } => Some(callee.as_str()),
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
            InstructionKind::Call { callee, .. } => Some(callee),
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
fn analyzed_concurrent_entry_reaches_the_existing_profile_rejection() {
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
