//! Machine-checked conformance for the runtime test harness of `std.test`.
//!
//! These rows execute declared run plans over caller-presented targets and check the harness's own
//! execution policy: which declared kinds it executes, that every executed target gets its own
//! machine, where a run stops, and that an unsupported plan is refused before any machine exists.
//! They read no clock, use no ambient authority, and add no declaration of the `std.test` surface.

use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, EffectSet, ExecutableAction, ExecutableOperation,
    Instruction, InstructionKind, MachineProgram, OperationKind, StructuralPosition,
    TypeDescriptor, declare_test_run,
};
use gantry::portable::IdentityKind;
use gantry::runtime::{
    MachineBuildError, MachineLimits, TestHarness, TestHarnessRefusal, TestHarnessStop,
    TestTargetOutcome, Workflow,
};
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};

const WORKFLOW: &str = "crate::main";
const DECLARATION: &str = "crate::harness_fixture";

/// Returns one canonical workflow path of the fixture.
fn workflow() -> CanonicalPath {
    CanonicalPath::new(WORKFLOW).unwrap_or_else(|_| unreachable!("fixture workflow is canonical"))
}

/// Returns one canonical structural position of the fixture.
fn site(index: u64) -> StructuralPosition {
    StructuralPosition::new(vec![index])
        .unwrap_or_else(|_| unreachable!("fixture site is canonical"))
}

/// Builds one decoded operation metadata value for the fixture declaration.
fn operation_metadata() -> ExecutableOperation {
    let path = CanonicalPath::new(DECLARATION)
        .unwrap_or_else(|_| unreachable!("fixture action path is canonical"));
    let action = ExecutableAction {
        path: path.clone(),
        signature: CanonicalSignature::action(
            RecoveryClass::Idempotent,
            &path,
            &[],
            &TypeDescriptor::UNIT,
        ),
        recovery: RecoveryClass::Idempotent,
        parameters: Vec::new(),
    };
    ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(action),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    }
}

/// Returns one fixture program that pushes a unit value and returns, so it completes without a host.
fn returning_program() -> Arc<MachineProgram> {
    program(vec![
        Instruction {
            site: site(1),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::Push(LogicalValue::unit()),
        },
        Instruction {
            site: site(2),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::Return,
        },
    ])
}

/// Returns one fixture program that prepares an operation, so it awaits host dispatch.
fn operation_program() -> Arc<MachineProgram> {
    program(vec![
        Instruction {
            site: site(2),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::OperationCall {
                operation: operation_metadata(),
                operands: 0,
            },
        },
        Instruction {
            site: site(4),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::Push(LogicalValue::unit()),
        },
        Instruction {
            site: site(5),
            ty: TypeDescriptor::UNIT,
            kind: InstructionKind::Return,
        },
    ])
}

/// Returns one fixture program that panics, so the machine fixes a failure.
fn failing_program() -> Arc<MachineProgram> {
    program(vec![Instruction {
        site: site(6),
        ty: TypeDescriptor::UNIT,
        kind: InstructionKind::Panic,
    }])
}

/// Returns the fixture machine limits of one declared budget and one yield quantum.
fn limits_with_quantum(maximum_transitions: u64, quantum: u64) -> MachineLimits {
    MachineLimits::new(maximum_transitions, 1, 1, 1, quantum, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture machine limits are positive"))
}

/// Wraps one instruction sequence as a fixture machine program.
fn program(instructions: Vec<Instruction>) -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(vec![Workflow {
            path: workflow(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions,
        }])
        .unwrap_or_else(|error| panic!("fixture machine program is valid: {error:?}")),
    )
}

/// Returns one fixture execution identity of one byte pattern.
fn execution(byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [byte; 32])
        .unwrap_or_else(|error| panic!("fixture execution identity is valid: {error}"))
}

/// Returns the fixture machine limits of one declared transition budget.
fn limits(maximum_transitions: u64) -> MachineLimits {
    MachineLimits::new(maximum_transitions, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture machine limits are positive"))
}

#[test]
fn runtime_harness_executes_declared_plans_over_admitted_targets() {
    let mut harness = TestHarness::new(limits(8));
    assert_eq!(harness.admitted(), Vec::<&str>::new());
    assert_eq!(
        harness.admit("", returning_program(), workflow(), execution(0x11)),
        Err(TestHarnessRefusal::Empty)
    );
    assert!(
        harness
            .admit("alpha", returning_program(), workflow(), execution(0x11))
            .is_ok()
    );
    assert_eq!(
        harness.admit("alpha", returning_program(), workflow(), execution(0x12)),
        Err(TestHarnessRefusal::Duplicate)
    );
    assert_eq!(
        harness.admit("beta", returning_program(), workflow(), execution(0x11)),
        Err(TestHarnessRefusal::DuplicateIdentity)
    );
    assert!(
        harness
            .admit("beta", returning_program(), workflow(), execution(0x12))
            .is_ok()
    );
    assert_eq!(
        harness.admitted(),
        vec!["alpha", "beta"],
        "the harness enumerates its targets in canonical name order"
    );

    let plan = declare_test_run(&["integration", "unit"], &[])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    let report = harness
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert!(
        report.is_clean(),
        "both returning targets complete: {report:?}"
    );
    assert_eq!(
        report.results()[0].outcome(),
        &TestTargetOutcome::Completed { steps: 4 },
        "the count covers every labelled transition observed before the completing observation"
    );
    assert_eq!(
        report
            .results()
            .iter()
            .map(|result| result.name())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta"]
    );
    assert!(
        report
            .results()
            .iter()
            .all(|result| matches!(result.outcome(), TestTargetOutcome::Completed { .. }))
    );

    // The harness is replayable: a second run of the same plan reports the same results.
    let repeated = harness
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs again: {error:?}"));
    assert_eq!(
        repeated, report,
        "two runs of one plan report the same results"
    );
}

#[test]
fn runtime_harness_refuses_unsupported_plans_before_executing() {
    let mut harness = TestHarness::new(limits(8));
    let plan = declare_test_run(&["unit"], &[])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    assert_eq!(
        harness.run(&plan),
        Err(TestHarnessRefusal::NoTargets),
        "an empty harness has nothing to execute"
    );
    assert!(
        harness
            .admit("alpha", returning_program(), workflow(), execution(0x21))
            .is_ok()
    );

    let unsupported_kind = declare_test_run(&["snapshot"], &[])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    assert_eq!(
        harness.run(&unsupported_kind),
        Err(TestHarnessRefusal::UnsupportedKind(
            gantry::ir::TestKind::Snapshot
        )),
        "a kind this entry does not execute is refused by name"
    );
    let substituted = declare_test_run(&["unit"], &["clock"])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    assert_eq!(
        harness.run(&substituted),
        Err(TestHarnessRefusal::UnsupportedSubstitution(
            gantry::ir::TestSubstitution::Clock
        )),
        "a substitution this entry does not provide is refused by name"
    );
}

#[test]
fn runtime_harness_reports_where_a_target_stopped() {
    // A target that prepares an operation awaits host dispatch, which this entry does not provide.
    let mut awaiting = TestHarness::new(limits(8));
    assert!(
        awaiting
            .admit("alpha", operation_program(), workflow(), execution(0x31))
            .is_ok()
    );
    let plan = declare_test_run(&["unit"], &[])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    let report = awaiting
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert!(!report.is_clean(), "an undriveable target is not a pass");
    assert!(matches!(
        report.results()[0].outcome(),
        TestTargetOutcome::Undriveable {
            stop: TestHarnessStop::HostDispatchPending,
            ..
        }
    ));

    // One transition of budget is not enough to reach completion, so the bound is reported.
    let mut bounded = TestHarness::new(limits(1));
    assert!(
        bounded
            .admit("alpha", operation_program(), workflow(), execution(0x32))
            .is_ok()
    );
    let report = bounded
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert!(matches!(
        report.results()[0].outcome(),
        TestTargetOutcome::StepBoundExhausted { steps: 1, bound: 1 }
    ));

    // Limits with no declared transition ceiling give the harness no finite step bound.
    let unbounded_limits = MachineLimits::unlimited(1, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("fixture unlimited limits are valid"));
    let mut unbounded = TestHarness::new(unbounded_limits);
    assert!(
        unbounded
            .admit("alpha", returning_program(), workflow(), execution(0x33))
            .is_ok()
    );
    assert_eq!(
        unbounded.run(&plan),
        Err(TestHarnessRefusal::UnboundedStepBound),
        "a harness with no finite step bound refuses to run"
    );
}

#[test]
fn runtime_harness_admits_only_accepted_targets_and_runs_them_in_canonical_order() {
    let mut harness = TestHarness::new(limits(8));
    // Insertion order is reversed, so enumeration and execution must not follow it.
    assert!(
        harness
            .admit("beta", returning_program(), workflow(), execution(0x41))
            .is_ok()
    );
    assert!(
        harness
            .admit("alpha", returning_program(), workflow(), execution(0x42))
            .is_ok()
    );
    assert_eq!(harness.admitted(), vec!["alpha", "beta"]);

    // A target the machine refuses is refused at admission and never stored.
    let absent = CanonicalPath::new("crate::absent")
        .unwrap_or_else(|_| unreachable!("fixture path is canonical"));
    assert_eq!(
        harness.admit("gamma", returning_program(), absent, execution(0x43)),
        Err(TestHarnessRefusal::TargetRejected(
            MachineBuildError::MissingRoot
        )),
        "a workflow the program does not name is refused at admission"
    );
    assert_eq!(
        harness.admitted(),
        vec!["alpha", "beta"],
        "a refused target is not admitted"
    );

    let plan = declare_test_run(&["unit"], &[])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    let report = harness
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert_eq!(
        report
            .results()
            .iter()
            .map(|result| result.name())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta"],
        "execution follows canonical name order, not insertion order"
    );

    // A machine failure is a failure, never a pass, and it does not hide a later target's result.
    let mut failing = TestHarness::new(limits(8));
    assert!(
        failing
            .admit("beta", returning_program(), workflow(), execution(0x44))
            .is_ok()
    );
    assert!(
        failing
            .admit("alpha", failing_program(), workflow(), execution(0x45))
            .is_ok()
    );
    let report = failing
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert!(!report.is_clean());
    assert_eq!(
        report.results()[0].outcome(),
        &TestTargetOutcome::Failed { steps: 1 },
        "a panicking target reports the failure on its first labelled transition"
    );
    assert!(
        matches!(
            report.results()[1].outcome(),
            TestTargetOutcome::Completed { .. }
        ),
        "a failing target does not hide the target that sorts after it"
    );

    // A cooperative yield is resumed, so a one-transition quantum still completes.
    let mut yielding = TestHarness::new(limits_with_quantum(8, 1));
    assert!(
        yielding
            .admit("alpha", returning_program(), workflow(), execution(0x46))
            .is_ok()
    );
    let report = yielding
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert!(report.is_clean(), "a yielded target resumes and completes");

    // A fixed success is never reported as exhaustion when the bound is reached.
    let mut small = TestHarness::new(limits(2));
    assert!(
        small
            .admit("alpha", returning_program(), workflow(), execution(0x47))
            .is_ok()
    );
    let report = small
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert_eq!(
        report.results()[0].outcome(),
        &TestTargetOutcome::Completed { steps: 2 },
        "a fixed success is reported at the bound with the labelled transitions it took"
    );
}

#[test]
fn runtime_harness_cancels_a_target_that_reaches_its_bound() {
    let reason: Arc<str> = Arc::from("test-harness-budget");
    let mut harness = TestHarness::new(limits(1)).with_cancellation(Arc::clone(&reason));
    assert!(
        harness
            .admit("alpha", operation_program(), workflow(), execution(0x51))
            .is_ok()
    );
    let plan = declare_test_run(&["unit"], &[])
        .unwrap_or_else(|error| panic!("fixture plan is declared: {error:?}"));
    let report = harness
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert!(!report.is_clean(), "a cancelled target is not a pass");
    assert_eq!(
        report.results()[0].outcome(),
        &TestTargetOutcome::Cancelled { steps: 1, reason },
        "the harness presents its declared reason and reports the one the machine fixed"
    );

    // The same target under a harness with no declared reason stops at the bound instead.
    let mut stopping = TestHarness::new(limits(1));
    assert!(
        stopping
            .admit("alpha", operation_program(), workflow(), execution(0x52))
            .is_ok()
    );
    let report = stopping
        .run(&plan)
        .unwrap_or_else(|error| panic!("the declared plan runs: {error:?}"));
    assert_eq!(
        report.results()[0].outcome(),
        &TestTargetOutcome::StepBoundExhausted { steps: 1, bound: 1 },
        "a harness that declares no reason keeps stopping at the bound"
    );
}
