//! Public regression coverage for the analyzer-to-runtime executable handoff.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::analysis::{AnalysisStatus, analyze_package_types};
use gantry::frontend::validate_package_syntax;
use gantry::identity::ProtocolIdentity;
use gantry::portable::IdentityKind;
use gantry::runtime::{Machine, MachineBuildError, MachineLimits, MachineOutcome, MachineStep};
use gantry::source::SourceLimits;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView};

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
            MachineStep::WaitingOperation(operation) => {
                panic!("deterministic fixture requested operation {operation:?}")
            }
        }
    }
    panic!("machine did not settle within the fixture bound")
}
