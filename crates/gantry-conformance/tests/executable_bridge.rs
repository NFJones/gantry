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
    assert_eq!(
        gantry::advertised_profiles().contains(&gantry::ConformanceProfile::Evaluator),
        evidence_is_current
    );

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
