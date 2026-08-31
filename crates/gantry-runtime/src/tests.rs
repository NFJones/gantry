use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::GantryInt;
use gantry_core::portable::{DeterministicEvaluationCode, IdentityKind};
use gantry_core::value::{
    DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView, ValueLimits, ValuePathSegment,
};
use gantry_ir::generated::Effect;
use gantry_ir::{CanonicalPath, EffectSet, StructuralPosition, TypeDescriptor};

use crate::{
    Instruction, InstructionKind, LoopPhase, Machine, MachineBuildError, MachineLabel,
    MachineLimits, MachineOutcome, MachineProgram, MachineStatus, MachineStep,
    OperationCompletionError, Parameter, Primitive, ProgramError, RuntimeCode, Workflow,
};

fn path(name: &str) -> CanonicalPath {
    CanonicalPath::new(name).unwrap_or_else(|error| panic!("invalid fixture path: {error}"))
}

fn site(index: u64) -> StructuralPosition {
    StructuralPosition::new(vec![index])
        .unwrap_or_else(|error| panic!("invalid fixture site: {error}"))
}

fn instruction(index: u64, ty: TypeDescriptor, kind: InstructionKind) -> Instruction {
    Instruction {
        site: site(index),
        ty,
        kind,
    }
}

fn workflow(
    name: &str,
    parameters: Vec<Parameter>,
    result: TypeDescriptor,
    effects: EffectSet,
    instructions: Vec<Instruction>,
) -> Workflow {
    Workflow {
        path: path(name),
        parameters,
        result,
        effects,
        instructions,
    }
}

fn program(workflows: Vec<Workflow>) -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(workflows)
            .unwrap_or_else(|error| panic!("invalid fixture program: {error:?}")),
    )
}

fn limits(
    transitions: u64,
    operations: u64,
    loops: u64,
    depth: u64,
    quantum: u64,
) -> MachineLimits {
    MachineLimits::new(
        transitions,
        operations,
        loops,
        depth,
        quantum,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|| unreachable!("fixture limits are positive"))
}

fn execution() -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x42; 32])
        .unwrap_or_else(|error| panic!("invalid fixture identity: {error}"))
}

fn new_machine(
    program: Arc<MachineProgram>,
    root: &str,
    arguments: Vec<LogicalValue>,
    limits: MachineLimits,
) -> Machine {
    Machine::new(program, &path(root), arguments, execution(), limits)
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"))
}

fn drive(machine: &mut Machine) -> MachineOutcome {
    for _ in 0..100_000 {
        match machine.step() {
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::WaitingSessionScope(scope) => {
                panic!("unexpected session-scope wait: {:?}", scope.site)
            }
            MachineStep::WaitingOperation(operation) => {
                panic!("unexpected operation wait: {}", operation.identity)
            }
            MachineStep::Complete(outcome) => return outcome,
        }
    }
    panic!("machine did not terminate within the fixture bound")
}

#[cfg(feature = "durable")]
#[test]
fn durable_checkpoint_recovers_the_same_explicit_frame_machine() {
    let main = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::BOOL,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            ),
            instruction(1, TypeDescriptor::BOOL, InstructionKind::Return),
        ],
    );
    let program = program(vec![main]);
    let mut original = new_machine(
        Arc::clone(&program),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        original.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let checkpoint = original.checkpoint();
    assert_eq!(checkpoint.execution_id(), execution());
    assert_eq!(checkpoint.status(), MachineStatus::Running);
    assert_eq!(checkpoint.remaining_budgets(), (7, 1, 1));

    let bytes = checkpoint.canonical_bytes();
    let decoded = crate::MachineCheckpointV1::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("checkpoint decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    let mut corrupted = bytes.clone();
    corrupted[0] ^= 1;
    assert_eq!(
        crate::MachineCheckpointV1::decode(&program, &corrupted),
        Err(crate::MachineRecoveryError::InvalidEncoding)
    );

    let mut recovered = Machine::recover_from_checkpoint(program, decoded)
        .unwrap_or_else(|error| panic!("checkpoint recovery failed: {error:?}"));
    assert_eq!(drive(&mut original), drive(&mut recovered));
    assert_eq!(
        recovered.outcome(),
        Some(&MachineOutcome::Succeeded(LogicalValue::boolean(true)))
    );
}

#[test]
fn explicit_frames_are_stack_safe_and_enforce_exact_depth() {
    const DEPTH: usize = 4_096;
    let mut workflows = Vec::with_capacity(DEPTH);
    for index in 0..DEPTH {
        let name = format!("crate::f{index:04}");
        let instructions = if index + 1 == DEPTH {
            vec![
                instruction(
                    0,
                    TypeDescriptor::UNIT,
                    InstructionKind::Push(LogicalValue::unit()),
                ),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
            ]
        } else {
            vec![
                instruction(
                    0,
                    TypeDescriptor::UNIT,
                    InstructionKind::Call {
                        callee: path(&format!("crate::f{:04}", index + 1)),
                        arguments: 0,
                    },
                ),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
            ]
        };
        workflows.push(workflow(
            &name,
            Vec::new(),
            TypeDescriptor::UNIT,
            EffectSet::default(),
            instructions,
        ));
    }

    let program = program(workflows);
    let mut admitted = new_machine(
        Arc::clone(&program),
        "crate::f0000",
        Vec::new(),
        limits(10_000, 1, 1, DEPTH as u64, 10_000),
    );
    assert_eq!(
        drive(&mut admitted),
        MachineOutcome::Succeeded(LogicalValue::unit())
    );

    let mut rejected = new_machine(
        program,
        "crate::f0000",
        Vec::new(),
        limits(10_000, 1, 1, DEPTH as u64 - 1, 10_000),
    );
    let outcome = drive(&mut rejected);
    assert!(matches!(
        outcome,
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::WorkflowCallDepthLimit
                )
    ));
}

#[test]
fn mutable_roots_publish_atomically_without_aliasing_arguments() {
    let original = LogicalValue::structure(
        "crate::Item",
        vec![("flag".to_owned(), LogicalValue::boolean(false))],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture value failed: {error:?}"));
    let retained = original.clone();
    let root = workflow(
        "crate::main",
        vec![Parameter {
            name: Arc::from("item"),
            ty: TypeDescriptor::declared(path("crate::Item")),
            mutable: true,
        }],
        TypeDescriptor::declared(path("crate::Item")),
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Assign {
                    name: Arc::from("item"),
                    path: vec![ValuePathSegment::StructField("flag".to_owned())],
                    target_type: TypeDescriptor::BOOL,
                },
            ),
            instruction(
                2,
                TypeDescriptor::declared(path("crate::Item")),
                InstructionKind::Load(Arc::from("item")),
            ),
            instruction(
                3,
                TypeDescriptor::declared(path("crate::Item")),
                InstructionKind::Return,
            ),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![original],
        limits(16, 1, 1, 1, 16),
    );
    let MachineOutcome::Succeeded(updated) = drive(&mut machine) else {
        panic!("fixture did not succeed")
    };
    let retained_flag = retained
        .field("flag")
        .unwrap_or_else(|| panic!("retained fixture field is missing"));
    assert!(matches!(
        retained_flag.view(),
        LogicalValueView::Bool(false)
    ));
    let updated_flag = updated
        .field("flag")
        .unwrap_or_else(|| panic!("updated fixture field is missing"));
    assert!(matches!(updated_flag.view(), LogicalValueView::Bool(true)));
}

#[test]
fn failure_short_circuits_later_operations_and_preserves_the_exact_code() {
    let maximum = GantryInt::new(9_007_199_254_740_991)
        .unwrap_or_else(|| unreachable!("maximum Int is admitted"));
    let one = GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted"));
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(maximum)),
            ),
            instruction(
                1,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(one)),
            ),
            instruction(
                2,
                TypeDescriptor::INT,
                InstructionKind::Primitive(Primitive::Add),
            ),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(4, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(10, 1, 1, 1, 10),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code
                == RuntimeCode::Deterministic(DeterministicEvaluationCode::IntegerOverflow)
    ));
    assert_eq!(machine.remaining_budgets().1, 1);
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Failed(_)))
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::ForegroundCompletion(MachineOutcome::Failed(
            _
        )))
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::TerminalCompletion(MachineOutcome::Failed(_)))
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Complete(MachineOutcome::Failed(_))
    ));
}

#[test]
fn cancellation_precedes_yield_and_pending_operation_consumption() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 1),
    );
    let operation = match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("unexpected operation step: {other:?}"),
    };
    assert!(matches!(
        machine.cancel("caller"),
        Some(MachineLabel::Cancellation { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(
            MachineOutcome::Cancelled(ref reason)
        )) if reason.as_ref() == "caller"
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::ForegroundCompletion(
            MachineOutcome::Cancelled(ref reason)
        )) if reason.as_ref() == "caller"
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::TerminalCompletion(
            MachineOutcome::Cancelled(ref reason)
        )) if reason.as_ref() == "caller"
    ));
    assert_eq!(
        machine.complete_operation(operation.identity, LogicalValue::unit()),
        Err(OperationCompletionError::NotWaiting)
    );
}

#[test]
fn yield_quantum_does_not_change_dynamic_operation_identity() {
    let build = || {
        workflow(
            "crate::main",
            Vec::new(),
            TypeDescriptor::BOOL,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::BOOL,
                    InstructionKind::Push(LogicalValue::boolean(true)),
                ),
                instruction(
                    1,
                    TypeDescriptor::BOOL,
                    InstructionKind::Branch {
                        when_true: 2,
                        when_false: 2,
                    },
                ),
                instruction(2, TypeDescriptor::BOOL, InstructionKind::Operation),
                instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
        )
    };
    let program = program(vec![build()]);
    let operation_with_quantum = |quantum| {
        let mut machine = new_machine(
            Arc::clone(&program),
            "crate::main",
            Vec::new(),
            limits(16, 1, 1, 1, quantum),
        );
        loop {
            match machine.step() {
                MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => {
                    return operation;
                }
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                other => panic!("unexpected pre-operation step: {other:?}"),
            }
        }
    };
    let frequent = operation_with_quantum(1);
    let sparse = operation_with_quantum(16);
    assert_eq!(frequent.identity, sparse.identity);
    assert_eq!(frequent.dynamic_path, sparse.dynamic_path);
    assert_eq!(
        frequent
            .dynamic_path
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["branch:crate::main:1:0", "operation:crate::main:2:-:0"]
    );
}

#[test]
fn repeated_loop_paths_use_zero_based_phase_specific_counters() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::EnterLoop {
                    phase: LoopPhase::Condition,
                    source_limit: None,
                },
            ),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Pop),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence),
            instruction(4, TypeDescriptor::UNIT, InstructionKind::Jump(0)),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(32, 2, 1, 1, 32),
    );
    let first = loop {
        match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => {
                break operation;
            }
            MachineStep::Transition(_) => {}
            other => panic!("unexpected first loop step: {other:?}"),
        }
    };
    assert_eq!(
        first
            .dynamic_path
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        [
            "loop:crate::main:0:condition:0",
            "operation:crate::main:1:-:0"
        ]
    );
    assert!(
        machine
            .complete_operation(first.identity, LogicalValue::unit())
            .is_ok()
    );

    let second = loop {
        match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => {
                break operation;
            }
            MachineStep::Transition(_) => {}
            other => panic!("unexpected second loop step: {other:?}"),
        }
    };
    assert_eq!(
        second
            .dynamic_path
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        [
            "loop:crate::main:0:condition:1",
            "operation:crate::main:1:-:0"
        ]
    );
    assert_ne!(first.identity, second.identity);
}

#[test]
fn operation_results_are_consumed_once_and_budgeted_once() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Pop),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    let first = match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("unexpected operation step: {other:?}"),
    };
    assert!(matches!(
        machine.complete_operation(first.identity, LogicalValue::unit()),
        Ok(MachineLabel::OperationResult { .. })
    ));
    assert_eq!(
        machine.complete_operation(first.identity, LogicalValue::unit()),
        Err(OperationCompletionError::NotWaiting)
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::OperationBudget
    ));
}

#[test]
fn operation_results_enforce_nested_types_and_captured_value_limits() {
    let expected = TypeDescriptor::list(TypeDescriptor::INT);
    let root = workflow(
        "crate::main",
        Vec::new(),
        expected.clone(),
        EffectSet::default(),
        vec![
            instruction(0, expected.clone(), InstructionKind::Operation),
            instruction(1, expected, InstructionKind::Return),
        ],
    );
    let value_limits =
        ValueLimits::new(4, 8, 4, 1).unwrap_or_else(|| unreachable!("fixture limits are positive"));
    let machine_limits = MachineLimits::new(8, 1, 1, 1, 8, value_limits)
        .unwrap_or_else(|| unreachable!("fixture machine limits are positive"));
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        machine_limits,
    );
    let operation = match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("unexpected operation step: {other:?}"),
    };
    let wrong_member = LogicalValue::list(vec![LogicalValue::boolean(true)], DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("fixture list failed: {error:?}"));
    assert_eq!(
        machine.complete_operation(operation.identity, wrong_member),
        Err(OperationCompletionError::TypeMismatch)
    );
    let too_many = LogicalValue::list(
        vec![
            LogicalValue::integer(
                GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted")),
            ),
            LogicalValue::integer(
                GantryInt::new(2).unwrap_or_else(|| unreachable!("two is admitted")),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture list failed: {error:?}"));
    assert_eq!(
        machine.complete_operation(operation.identity, too_many),
        Err(OperationCompletionError::ValueLimit)
    );
    let accepted = LogicalValue::list(
        vec![LogicalValue::integer(
            GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture list failed: {error:?}"));
    assert!(
        machine
            .complete_operation(operation.identity, accepted)
            .is_ok()
    );
    assert!(matches!(drive(&mut machine), MachineOutcome::Succeeded(_)));
}

#[test]
fn workflow_return_restores_dynamic_agent_and_session_scopes() {
    let session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0x24; 32])
        .unwrap_or_else(|error| panic!("invalid fixture session: {error}"));
    let callee = workflow(
        "crate::callee",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::EnterAgent(Arc::from("inner-agent")),
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::EnterSession(Arc::from("inline")),
            ),
            instruction(
                2,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let main = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::EnterAgent(Arc::from("outer-agent")),
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::EnterSession(Arc::from("inline")),
            ),
            instruction(
                2,
                TypeDescriptor::UNIT,
                InstructionKind::Call {
                    callee: path("crate::callee"),
                    arguments: 0,
                },
            ),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::Pop),
            instruction(4, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(5, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut machine = Machine::new_with_context(
        program(vec![callee, main]),
        &path("crate::main"),
        Vec::new(),
        execution(),
        limits(32, 1, 1, 2, 32),
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"));
    let operation = loop {
        match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => {
                break operation;
            }
            MachineStep::Transition(_) => {}
            other => panic!("unexpected pre-operation step: {other:?}"),
        }
    };
    assert_eq!(operation.active_agent.as_deref(), Some("outer-agent"));
    assert_eq!(operation.active_session, Some(session));
}

#[test]
fn loop_and_transition_budgets_fail_before_rejected_steps_publish() {
    let looping = |source_limit| {
        workflow(
            "crate::main",
            Vec::new(),
            TypeDescriptor::UNIT,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::UNIT,
                    InstructionKind::EnterLoop {
                        phase: LoopPhase::Body,
                        source_limit,
                    },
                ),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence),
                instruction(2, TypeDescriptor::UNIT, InstructionKind::Jump(0)),
            ],
        )
    };
    let mut source_limited = new_machine(
        program(vec![looping(Some(1))]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 2, 1, 8),
    );
    for _ in 0..3 {
        assert!(matches!(
            source_limited.step(),
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
    }
    assert!(matches!(
        source_limited.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::LoopLimitExhausted
    ));

    let mut budget_limited = new_machine(
        program(vec![looping(None)]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    for _ in 0..3 {
        assert!(matches!(
            budget_limited.step(),
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
    }
    assert!(matches!(
        budget_limited.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::LoopIterationBudget
    ));

    let transition_root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Pop),
        ],
    );
    let mut transition_limited = new_machine(
        program(vec![transition_root]),
        "crate::main",
        Vec::new(),
        limits(1, 1, 1, 1, 8),
    );
    assert!(matches!(
        transition_limited.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        transition_limited.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::DeterministicTransitionBudget
    ));
}

#[test]
fn base_profile_rejects_reachable_concurrent_effects_before_start() {
    let mut effects = EffectSet::default();
    assert!(effects.insert(Effect::Spawn));
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        effects,
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Return,
        )],
    );
    let result = Machine::new(
        program(vec![root]),
        &path("crate::main"),
        Vec::new(),
        execution(),
        limits(1, 1, 1, 1, 1),
    );
    assert!(matches!(
        result,
        Err(MachineBuildError::UnsupportedEffect(Effect::Spawn))
    ));
}

#[test]
fn deterministic_string_and_numeric_primitives_return_exact_failures() {
    let maximum = GantryInt::new(9_007_199_254_740_991)
        .unwrap_or_else(|| unreachable!("maximum Int is admitted"));
    let one = GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted"));
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::INT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(maximum)),
            ),
            instruction(
                1,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(one)),
            ),
            instruction(
                2,
                TypeDescriptor::INT,
                InstructionKind::Primitive(Primitive::Add),
            ),
            instruction(3, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut overflow = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        drive(&mut overflow),
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Deterministic(DeterministicEvaluationCode::IntegerOverflow)
    ));

    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::STRING,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("abc", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("fixture string failed: {error:?}")),
                ),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("fixture string failed: {error:?}")),
                ),
            ),
            instruction(
                2,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("x", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("fixture string failed: {error:?}")),
                ),
            ),
            instruction(
                3,
                TypeDescriptor::STRING,
                InstructionKind::Primitive(Primitive::StringReplace),
            ),
            instruction(4, TypeDescriptor::STRING, InstructionKind::Return),
        ],
    );
    let mut empty_pattern = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        drive(&mut empty_pattern),
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::StringEmptyPattern
                )
    ));
}

#[test]
fn string_float_parsing_never_trims_input() {
    let option_float = TypeDescriptor::option(TypeDescriptor::FLOAT)
        .unwrap_or_else(|error| panic!("invalid option type: {error}"));
    let root = workflow(
        "crate::main",
        Vec::new(),
        option_float.clone(),
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(" 1", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("fixture string failed: {error:?}")),
                ),
            ),
            instruction(
                1,
                option_float.clone(),
                InstructionKind::Primitive(Primitive::StringParseFloat),
            ),
            instruction(2, option_float, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
        panic!("parse fixture did not succeed")
    };
    assert!(matches!(
        value.view(),
        LogicalValueView::Option { is_some: false }
    ));
}

#[test]
fn malformed_programs_are_rejected_before_machine_construction() {
    let duplicate = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    assert!(matches!(
        MachineProgram::new(vec![duplicate]),
        Err(ProgramError::InstructionOrder(_))
    ));
    assert_eq!(MachineStatus::Running, MachineStatus::Running);
}

#[test]
fn root_and_call_arguments_preserve_analyzed_types() {
    let parameter = Parameter {
        name: Arc::from("value"),
        ty: TypeDescriptor::INT,
        mutable: false,
    };
    let callee = workflow(
        "crate::callee",
        vec![parameter.clone()],
        TypeDescriptor::INT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Load(Arc::from("value")),
            ),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let main = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::INT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            ),
            instruction(
                1,
                TypeDescriptor::INT,
                InstructionKind::Call {
                    callee: path("crate::callee"),
                    arguments: 1,
                },
            ),
            instruction(2, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let runtime_program = program(vec![callee.clone(), main]);
    let mut call_mismatch = new_machine(
        runtime_program,
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        drive(&mut call_mismatch),
        MachineOutcome::Failed(failure) if failure.code == RuntimeCode::InternalInvariant
    ));

    let root_mismatch = Machine::new(
        program(vec![callee]),
        &path("crate::callee"),
        vec![LogicalValue::boolean(true)],
        execution(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        root_mismatch,
        Err(MachineBuildError::ArgumentType)
    ));
}
