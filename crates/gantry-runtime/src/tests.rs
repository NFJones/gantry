use std::sync::Arc;
#[cfg(feature = "concurrent")]
use std::sync::Barrier;
#[cfg(feature = "concurrent")]
use std::thread;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::GantryInt;
#[cfg(feature = "concurrent")]
use gantry_core::portable::RuntimeErrorCategory;
use gantry_core::portable::{DeterministicEvaluationCode, IdentityKind};
use gantry_core::value::{
    DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView, ValueLimits, ValuePathSegment,
};
#[cfg(feature = "durable")]
use gantry_ir::Projection;
use gantry_ir::generated::Effect;
#[cfg(any(feature = "concurrent", feature = "durable"))]
use gantry_ir::generated::{OperationSiteKind, RecoveryClass};
use gantry_ir::{
    CanonicalCallableIdentity, CanonicalPath, EffectSet, OwnershipClass, ReceiverMode,
    ReceiverSource, StructuralPosition, TypeDescriptor,
};
#[cfg(any(feature = "concurrent", feature = "durable"))]
use gantry_ir::{CanonicalSignature, ExecutableAction, ExecutableOperation, OperationKind};
#[cfg(feature = "concurrent")]
use gantry_ir::{
    ExecutableTaskBody, ExecutableTaskCapture, ExecutableTaskContext, ExecutableTaskHandle,
    TaskBodyIdentity,
};

#[cfg(any(feature = "concurrent", feature = "durable"))]
use crate::ExecutionBudget;
#[cfg(feature = "concurrent")]
use crate::{
    DynamicTaskHandleIdentity, JoinResolutionV1, TaskCaptureV1, TaskControlCompletionError,
    TaskFailureV1, TaskJoinFailureV1, TaskJoinMemberFailureKindV1, TaskJoinMemberFailureV1,
    root_task_identity,
};
use crate::{
    Instruction, InstructionKind, LoopPhase, Machine, MachineBuildError, MachineLabel,
    MachineLimits, MachineOutcome, MachineProgram, MachineStatus, MachineStep,
    OperationCompletionError, Parameter, Primitive, ProgramError, RuntimeCode, Workflow,
};

fn path(name: &str) -> CanonicalPath {
    CanonicalPath::new(name).unwrap_or_else(|error| panic!("invalid fixture path: {error}"))
}

fn callable(name: &str) -> CanonicalCallableIdentity {
    CanonicalCallableIdentity::free(&path(name), &[])
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

/// A source panic or checked assertion settles the enclosing callable as failed with the machine
/// code the runtime vocabulary publishes (`GNT-38.2-assertions-and-panic`).
#[test]
fn a_panic_instruction_settles_the_enclosing_callable_as_failed() {
    let mut machine = new_machine(
        program(vec![workflow(
            "crate::main",
            Vec::new(),
            TypeDescriptor::UNIT,
            EffectSet::default(),
            vec![instruction(0, TypeDescriptor::UNIT, InstructionKind::Panic)],
        )]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 2, 1, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::SourcePanic
    ));
    assert_eq!(RuntimeCode::SourcePanic.wire_name(), "source-panic");
}

#[cfg(feature = "concurrent")]
fn spawn_program() -> (Arc<MachineProgram>, TaskBodyIdentity) {
    spawn_program_with_body(vec![
        instruction(
            0,
            TypeDescriptor::INT,
            InstructionKind::Load(Arc::from("count")),
        ),
        instruction(1, TypeDescriptor::INT, InstructionKind::TaskComplete),
    ])
}

#[cfg(feature = "concurrent")]
fn spawn_program_with_body(
    instructions: Vec<Instruction>,
) -> (Arc<MachineProgram>, TaskBodyIdentity) {
    let root_path = path("crate::main");
    let caller = CanonicalCallableIdentity::free(&root_path, &[]);
    let body_identity = TaskBodyIdentity::new(caller.clone(), site(0));
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::INT,
        vec![
            ExecutableTaskCapture::new(Arc::from("count"), TypeDescriptor::INT, false)
                .unwrap_or_else(|error| panic!("invalid fixture capture: {error:?}")),
        ],
        ExecutableTaskContext::v1(),
        instructions,
    )
    .unwrap_or_else(|error| panic!("invalid fixture task body: {error:?}"));
    let root = workflow(
        "crate::main",
        vec![Parameter {
            name: Arc::from("count"),
            ty: TypeDescriptor::INT,
            mutable: false,
            receiver_mode: None,
        }],
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::INT)
                        .unwrap_or_else(|error| panic!("invalid fixture handle: {error:?}")),
                    body: body_identity.clone(),
                },
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let program = MachineProgram::with_task_bodies(vec![(caller, root)], vec![body])
        .unwrap_or_else(|error| panic!("invalid fixture spawn program: {error:?}"));
    (Arc::new(program), body_identity)
}

#[cfg(feature = "concurrent")]
fn joined_int_program(control: InstructionKind, result: TypeDescriptor) -> Arc<MachineProgram> {
    let root_path = path("crate::main");
    let caller = CanonicalCallableIdentity::free(&root_path, &[]);
    let body_identities = [0, 1].map(|index| TaskBodyIdentity::new(caller.clone(), site(index)));
    let bodies = body_identities
        .iter()
        .enumerate()
        .map(|(index, identity)| {
            let value = LogicalValue::integer(
                GantryInt::new(index as i64 + 1)
                    .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            );
            ExecutableTaskBody::new(
                identity.clone(),
                TypeDescriptor::INT,
                Vec::new(),
                ExecutableTaskContext::v1(),
                vec![
                    instruction(0, TypeDescriptor::INT, InstructionKind::Push(value)),
                    instruction(1, TypeDescriptor::INT, InstructionKind::TaskComplete),
                ],
            )
            .unwrap_or_else(|error| panic!("invalid fixture task body: {error:?}"))
        })
        .collect::<Vec<_>>();
    let handles = ["first", "second"].map(|name| {
        ExecutableTaskHandle::new(Arc::from(name), TypeDescriptor::INT)
            .unwrap_or_else(|error| panic!("invalid fixture handle: {error:?}"))
    });
    let root = workflow(
        "crate::main",
        Vec::new(),
        result.clone(),
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Spawn {
                    handle: handles[0].clone(),
                    body: body_identities[0].clone(),
                },
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Spawn {
                    handle: handles[1].clone(),
                    body: body_identities[1].clone(),
                },
            ),
            instruction(2, result.clone(), control),
            instruction(3, result, InstructionKind::Return),
        ],
    );
    Arc::new(
        MachineProgram::with_task_bodies(vec![(caller, root)], bodies)
            .unwrap_or_else(|error| panic!("invalid fixture task-control program: {error:?}")),
    )
}

#[cfg(feature = "concurrent")]
fn complete_fixture_spawn(machine: &mut Machine, child_material: u8) {
    let suspension = match machine.step() {
        MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn)) => spawn,
        other => panic!("unexpected spawn step: {other:?}"),
    };
    let child = ProtocolIdentity::derive(IdentityKind::Task, &[child_material; 32])
        .unwrap_or_else(|error| panic!("invalid fixture child identity: {error}"));
    let handle = DynamicTaskHandleIdentity::from_parts(machine.task_id(), child);
    machine
        .complete_spawn(&suspension, handle)
        .unwrap_or_else(|error| panic!("fixture spawn completion failed: {error:?}"));
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

#[cfg(feature = "concurrent")]
fn child_task_coordinate() -> (ProtocolIdentity, Arc<[Arc<str>]>) {
    let task_path = Arc::from([Arc::from("spawn:crate::main:0:0")]);
    let task_id = ProtocolIdentity::derive(
        IdentityKind::Task,
        &crate::machine::task_identity_key(execution(), &task_path),
    )
    .unwrap_or_else(|error| panic!("invalid child task identity: {error}"));
    (task_id, task_path)
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

#[cfg(feature = "concurrent")]
#[test]
fn machines_share_one_deterministic_transition_budget_without_partial_mutation() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Push(LogicalValue::unit()),
        )],
    );
    let program = program(vec![root]);
    let machine_limits = limits(1, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut winner = Machine::new_with_budget(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("winner construction failed: {error:?}"));
    let mut loser = Machine::new_concurrent_task_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("loser construction failed: {error:?}"));

    let loser_state = loser.test_instruction_state();
    assert!(matches!(
        winner.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        loser.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::DeterministicTransitionBudget
    ));
    assert_eq!(loser.test_instruction_state(), loser_state);
    assert_eq!(loser.remaining_budgets(), (Some(0), Some(1), Some(1)));
}

#[cfg(feature = "concurrent")]
#[test]
fn machines_share_one_operation_budget_without_partial_mutation() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Operation,
        )],
    );
    let program = program(vec![root]);
    let machine_limits = limits(1, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut winner = Machine::new_with_budget(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("winner construction failed: {error:?}"));
    let mut loser = Machine::new_concurrent_task_with_budget_and_context(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        child_task_id,
        Arc::clone(&child_task_path),
        machine_limits,
        budget.clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("loser construction failed: {error:?}"));
    let mut expected = Machine::new_concurrent_task_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("expected construction failed: {error:?}"));

    let loser_state = loser.test_instruction_state();
    assert!(matches!(
        winner.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    assert!(matches!(
        loser.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::OperationBudget
    ));
    assert!(matches!(
        expected.test_fail_current(RuntimeCode::OperationBudget),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::OperationBudget
    ));
    #[cfg(feature = "durable")]
    assert_eq!(loser.checkpoint(), expected.checkpoint());
    assert_eq!(loser.status(), MachineStatus::Failed);
    assert_eq!(loser.test_instruction_state(), loser_state);
    assert_eq!(loser.remaining_budgets(), (Some(1), Some(0), Some(1)));
    assert!(matches!(
        loser.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Failed(_)))
    ));
}

#[cfg(feature = "concurrent")]
#[test]
fn shared_budget_gives_same_static_action_site_distinct_resource_generations() {
    let action_path = path("crate::action");
    let operation = ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(ExecutableAction {
            path: action_path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &action_path,
                &[],
                &TypeDescriptor::UNIT,
            ),
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    };
    let program = program(vec![workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::OperationCall {
                operation,
                operands: 0,
            },
        )],
    )]);
    let machine_limits = limits(8, 2, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut foreground = Machine::new_with_budget(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("foreground construction failed: {error:?}"));
    let (task_id, task_path) = child_task_coordinate();
    let mut child = Machine::new_concurrent_task_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        task_id,
        task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("child construction failed: {error:?}"));

    assert!(matches!(
        foreground.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let foreground_subject = foreground
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("foreground action has a resource subject"));
    assert!(matches!(
        child.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let child_subject = child
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("child action has a resource subject"));

    assert_ne!(
        foreground_subject.generation(),
        child_subject.generation(),
        "shared execution-budget revisions distinguish tasks at one static action site"
    );
}

#[test]
fn machine_limits_reject_only_aggregate_budget_revision_overflow() {
    assert!(MachineLimits::new(u64::MAX - 1, 1, 1, 1, 1, DEFAULT_VALUE_LIMITS,).is_some());
    assert!(MachineLimits::new(u64::MAX, 1, 1, 1, 1, DEFAULT_VALUE_LIMITS,).is_none());
    assert!(MachineLimits::new(1, u64::MAX, 1, 1, 1, DEFAULT_VALUE_LIMITS,).is_none());
}

#[cfg(feature = "durable")]
#[test]
fn recovered_boundary_budget_can_consume_its_final_configured_unit() {
    let snapshot = crate::ExecutionBudgetSnapshot {
        execution: execution(),
        maximum_transitions: gantry_core::limit::ResourceLimit::limited(u64::MAX - 1)
            .unwrap_or_else(|| unreachable!("fixture maximum is positive")),
        maximum_operations: gantry_core::limit::ResourceLimit::limited(1)
            .unwrap_or_else(|| unreachable!("fixture maximum is positive")),
        remaining_transitions: Some(0),
        remaining_operations: Some(1),
        revision: u64::MAX - 1,
    };
    let budget = ExecutionBudget::recover_from_checkpoint(snapshot)
        .unwrap_or_else(|error| panic!("boundary budget recovery failed: {error:?}"));
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Operation,
        )],
    );
    let machine_limits = limits(u64::MAX - 1, 1, 1, 1, 1);
    let mut machine = Machine::new_with_budget(
        program(vec![root]),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("boundary machine construction failed: {error:?}"));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    assert_eq!(
        budget.snapshot(),
        crate::ExecutionBudgetSnapshot {
            remaining_operations: Some(0),
            revision: u64::MAX,
            ..snapshot
        }
    );
}

#[cfg(feature = "concurrent")]
#[test]
fn simultaneous_final_transition_unit_has_one_successor_and_one_unchanged_loser() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Push(LogicalValue::unit()),
        )],
    );
    let program = program(vec![root]);
    let machine_limits = limits(1, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let (child_task_id, child_task_path) = child_task_coordinate();
    let machines = [true, false].map(|foreground| {
        if foreground {
            Machine::new_with_budget(
                Arc::clone(&program),
                &path("crate::main"),
                Vec::new(),
                execution(),
                machine_limits,
                budget.clone(),
            )
        } else {
            Machine::new_concurrent_task_with_budget_and_context(
                Arc::clone(&program),
                &path("crate::main"),
                Vec::new(),
                execution(),
                child_task_id,
                Arc::clone(&child_task_path),
                machine_limits,
                budget.clone(),
                None,
                None,
            )
        }
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"))
    });
    let barrier = Arc::new(Barrier::new(2));
    let results = machines.map(|mut machine| {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let before = machine.test_instruction_state();
            barrier.wait();
            let step = machine.step();
            (before, machine.test_instruction_state(), step)
        })
    });
    let results = results.map(|handle| {
        handle
            .join()
            .unwrap_or_else(|_| panic!("budget contender panicked"))
    });

    assert_eq!(
        results
            .iter()
            .filter(|(_, _, step)| matches!(
                step,
                MachineStep::Transition(MachineLabel::Deterministic { .. })
            ))
            .count(),
        1
    );
    let loser = results
        .iter()
        .find(|(_, _, step)| {
            matches!(
                step,
                MachineStep::Transition(MachineLabel::Failure(failure))
                    if failure.code == RuntimeCode::DeterministicTransitionBudget
            )
        })
        .unwrap_or_else(|| panic!("missing exhausted contender"));
    assert_eq!(loser.0, loser.1);
    let snapshot = budget.snapshot();
    assert_eq!(snapshot.remaining_transitions, Some(0));
    assert_eq!(snapshot.revision, 1);
}

#[cfg(feature = "concurrent")]
#[test]
fn simultaneous_final_operation_unit_has_one_preparation_and_one_unchanged_loser() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Operation,
        )],
    );
    let program = program(vec![root]);
    let machine_limits = limits(1, 1, 1, 1, 8);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let (child_task_id, child_task_path) = child_task_coordinate();
    let machines = [true, false].map(|foreground| {
        if foreground {
            Machine::new_with_budget(
                Arc::clone(&program),
                &path("crate::main"),
                Vec::new(),
                execution(),
                machine_limits,
                budget.clone(),
            )
        } else {
            Machine::new_concurrent_task_with_budget_and_context(
                Arc::clone(&program),
                &path("crate::main"),
                Vec::new(),
                execution(),
                child_task_id,
                Arc::clone(&child_task_path),
                machine_limits,
                budget.clone(),
                None,
                None,
            )
        }
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"))
    });
    let barrier = Arc::new(Barrier::new(2));
    let results = machines.map(|mut machine| {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let before = machine.test_instruction_state();
            barrier.wait();
            let step = machine.step();
            (before, machine.test_instruction_state(), step)
        })
    });
    let results = results.map(|handle| {
        handle
            .join()
            .unwrap_or_else(|_| panic!("operation budget contender panicked"))
    });

    assert_eq!(
        results
            .iter()
            .filter(|(_, _, step)| matches!(
                step,
                MachineStep::Transition(MachineLabel::OperationPrepared(_))
            ))
            .count(),
        1
    );
    let losers = results
        .iter()
        .filter(|(_, _, step)| {
            matches!(
                step,
                MachineStep::Transition(MachineLabel::Failure(failure))
                    if failure.code == RuntimeCode::OperationBudget
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(losers.len(), 1);
    assert_eq!(losers[0].0, losers[0].1);
    let snapshot = budget.snapshot();
    assert_eq!(snapshot.remaining_operations, Some(0));
    assert_eq!(snapshot.revision, 1);
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_attachment_validates_budget_execution_and_maxima() {
    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Push(LogicalValue::unit()),
        )],
    );
    let program = program(vec![root]);
    let machine_limits = limits(2, 1, 1, 1, 8);
    let other_execution =
        ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x43; 32])
            .unwrap_or_else(|error| panic!("invalid fixture identity: {error}"));
    let wrong_execution = ExecutionBudget::new(other_execution, machine_limits);
    assert!(matches!(
        Machine::new_with_budget(
            Arc::clone(&program),
            &path("crate::main"),
            Vec::new(),
            execution(),
            machine_limits,
            wrong_execution,
        ),
        Err(MachineBuildError::ExecutionBudgetMismatch)
    ));

    let wrong_maxima = ExecutionBudget::new(execution(), limits(3, 1, 1, 1, 8));
    assert!(matches!(
        Machine::new_with_budget(
            program,
            &path("crate::main"),
            Vec::new(),
            execution(),
            machine_limits,
            wrong_maxima,
        ),
        Err(MachineBuildError::ExecutionBudgetMismatch)
    ));
}

#[cfg(feature = "concurrent")]
#[test]
fn shared_execution_budget_keeps_loop_and_yield_state_task_local() {
    let looping = || {
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
                        source_limit: None,
                    },
                ),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence),
                instruction(2, TypeDescriptor::UNIT, InstructionKind::Jump(0)),
            ],
        )
    };
    let program = program(vec![looping()]);
    let machine_limits = limits(16, 1, 1, 1, 1);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut first = Machine::new_with_budget(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("first construction failed: {error:?}"));
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut second = Machine::new_concurrent_task_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("second construction failed: {error:?}"));

    assert!(matches!(
        first.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert_eq!(first.status(), MachineStatus::YieldRequired);
    assert_eq!(second.status(), MachineStatus::Running);
    assert!(matches!(
        second.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert_eq!(first.remaining_budgets().2, Some(0));
    assert_eq!(second.remaining_budgets().2, Some(0));

    assert!(first.resume_after_yield());
    for _ in 0..2 {
        assert!(matches!(
            first.step(),
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
        assert!(first.resume_after_yield());
    }
    assert!(matches!(
        first.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::LoopIterationBudget
    ));
    assert_eq!(second.status(), MachineStatus::YieldRequired);
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
    let budget_checkpoint = original.budget_checkpoint();
    assert_eq!(checkpoint.execution_id(), execution());
    assert_eq!(checkpoint.status(), MachineStatus::Running);
    assert_eq!(budget_checkpoint.remaining_transitions, Some(7));
    assert_eq!(budget_checkpoint.remaining_operations, Some(1));
    assert_eq!(checkpoint.remaining_loop_iterations(), Some(1));

    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP03".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("checkpoint decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    let mut superseded = bytes.clone();
    superseded[..8].copy_from_slice(b"GNTMCP02");
    assert_eq!(
        crate::MachineCheckpointV3::decode(&program, &superseded),
        Err(crate::MachineRecoveryError::InvalidEncoding)
    );
    let mut corrupted = bytes.clone();
    corrupted[0] ^= 1;
    assert_eq!(
        crate::MachineCheckpointV3::decode(&program, &corrupted),
        Err(crate::MachineRecoveryError::InvalidEncoding)
    );

    let recovered_budget = ExecutionBudget::recover_from_checkpoint(budget_checkpoint)
        .unwrap_or_else(|error| panic!("budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, decoded, recovered_budget)
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
                        callee: callable(&format!("crate::f{:04}", index + 1)),
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
            receiver_mode: None,
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

/// A failed RHS leaves its target untouched while earlier assignment commits remain visible.
#[test]
fn overflowing_assignment_rhs_preserves_its_target_and_prior_commits() {
    let maximum = GantryInt::new(9_007_199_254_740_991)
        .unwrap_or_else(|| unreachable!("maximum Int is admitted"));
    let item_type = TypeDescriptor::declared(path("crate::Item"));
    let original = LogicalValue::structure(
        "crate::Item",
        vec![
            ("committed".to_owned(), LogicalValue::boolean(false)),
            (
                "unchanged".to_owned(),
                LogicalValue::integer(
                    GantryInt::new(7)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                ),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture item failed: {error:?}"));
    let root = workflow(
        "crate::main",
        vec![Parameter {
            name: Arc::from("item"),
            ty: item_type.clone(),
            mutable: true,
            receiver_mode: None,
        }],
        TypeDescriptor::UNIT,
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
                    path: vec![ValuePathSegment::StructField("committed".to_owned())],
                    target_type: TypeDescriptor::BOOL,
                },
            ),
            instruction(
                2,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(maximum)),
            ),
            instruction(
                3,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(
                    GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted")),
                )),
            ),
            instruction(
                4,
                TypeDescriptor::INT,
                InstructionKind::Primitive(Primitive::Add),
            ),
            instruction(
                5,
                TypeDescriptor::UNIT,
                InstructionKind::Assign {
                    name: Arc::from("item"),
                    path: vec![ValuePathSegment::StructField("unchanged".to_owned())],
                    target_type: TypeDescriptor::INT,
                },
            ),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![original],
        limits(16, 1, 1, 1, 16),
    );
    for _ in 0..4 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
    }
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code
                == RuntimeCode::Deterministic(DeterministicEvaluationCode::IntegerOverflow)
    ));
    let item = machine
        .test_binding_value("item")
        .unwrap_or_else(|| panic!("item binding is absent after overflow"));
    assert!(
        matches!(item.field("committed"), Some(value) if matches!(value.view(), LogicalValueView::Bool(true)))
    );
    assert!(matches!(
        item.field("unchanged"),
        Some(value) if matches!(value.view(), LogicalValueView::Int(number) if number.get() == 7)
    ));
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
    assert_eq!(machine.remaining_budgets().1, Some(1));
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
                    callee: callable("crate::callee"),
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

/// Long String equality yields before publication without spending a semantic transition.
#[test]
fn long_string_equality_yields_before_atomic_publication_and_cancellation() {
    for primitive in [Primitive::Equal, Primitive::NotEqual] {
        let text = LogicalValue::string("é".repeat(10_000), DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("text: {error:?}"));
        let root = workflow(
            "crate::main",
            vec![],
            TypeDescriptor::BOOL,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(text.clone()),
                ),
                instruction(1, TypeDescriptor::STRING, InstructionKind::Push(text)),
                instruction(
                    2,
                    TypeDescriptor::BOOL,
                    InstructionKind::Primitive(primitive),
                ),
                instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            vec![],
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        assert_eq!(machine.step(), MachineStep::YieldRequired);
        assert_eq!(machine.execution_budget().snapshot(), before);
        assert!(machine.outcome().is_none());
        let mut completing = machine.clone();
        #[cfg(feature = "durable")]
        {
            let bytes = machine.checkpoint().canonical_bytes();
            let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
                .unwrap_or_else(|error| panic!("comparison checkpoint: {error:?}"));
            let budget = ExecutionBudget::recover_from_checkpoint(before)
                .unwrap_or_else(|error| panic!("comparison budget: {error:?}"));
            let mut recovered =
                Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                    .unwrap_or_else(|error| panic!("comparison recovery: {error:?}"));
            assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
            assert!(recovered.resume_after_yield());
            assert_eq!(
                drive(&mut recovered),
                MachineOutcome::Succeeded(LogicalValue::boolean(primitive == Primitive::Equal))
            );
            assert_eq!(
                recovered.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
        assert!(completing.resume_after_yield());
        assert_eq!(
            drive(&mut completing),
            MachineOutcome::Succeeded(LogicalValue::boolean(primitive == Primitive::Equal))
        );
        assert_eq!(
            completing.execution_budget().snapshot().revision,
            before.revision + 1
        );
        assert!(machine.cancel("comparison cancelled").is_some());
        assert!(
            matches!(drive(&mut machine), MachineOutcome::Cancelled(reason) if reason.as_ref() == "comparison cancelled")
        );
    }
}

/// Large String lists must yield without publishing or spending a semantic transition.
#[test]
fn string_list_equality_yields_before_publication_and_restarts_after_recovery() {
    for primitive in [Primitive::Equal, Primitive::NotEqual] {
        let item = LogicalValue::string("é".repeat(5_000), DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("item: {error:?}"));
        let value = LogicalValue::list(vec![item.clone(), item], DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("list: {error:?}"));
        let ty = TypeDescriptor::list(TypeDescriptor::STRING);
        let root = workflow(
            "crate::main",
            vec![],
            TypeDescriptor::BOOL,
            EffectSet::default(),
            vec![
                instruction(0, ty.clone(), InstructionKind::Push(value.clone())),
                instruction(1, ty, InstructionKind::Push(value)),
                instruction(
                    2,
                    TypeDescriptor::BOOL,
                    InstructionKind::Primitive(primitive),
                ),
                instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            vec![],
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        assert_eq!(machine.step(), MachineStep::YieldRequired);
        assert_eq!(machine.execution_budget().snapshot(), before);
        let mut completing = machine.clone();
        #[cfg(feature = "durable")]
        {
            let bytes = machine.checkpoint().canonical_bytes();
            let decoded = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
                .unwrap_or_else(|error| panic!("checkpoint: {error:?}"));
            let budget = ExecutionBudget::recover_from_checkpoint(before)
                .unwrap_or_else(|error| panic!("budget: {error:?}"));
            let mut recovered =
                Machine::recover_from_checkpoint(machine.program_arc(), decoded, budget)
                    .unwrap_or_else(|error| panic!("recovery: {error:?}"));
            assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
            assert!(recovered.resume_after_yield());
            assert_eq!(
                drive(&mut recovered),
                MachineOutcome::Succeeded(LogicalValue::boolean(primitive == Primitive::Equal))
            );
            assert_eq!(
                recovered.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
        assert!(completing.resume_after_yield());
        assert_eq!(
            drive(&mut completing),
            MachineOutcome::Succeeded(LogicalValue::boolean(primitive == Primitive::Equal))
        );
        assert_eq!(
            completing.execution_budget().snapshot().revision,
            before.revision + 1
        );
        assert!(machine.cancel("list comparison cancelled").is_some());
        assert!(matches!(drive(&mut machine), MachineOutcome::Cancelled(_)));
    }
}

/// Aggregate limit refusals retain precedence, and valid candidates publish exactly once.
#[test]
fn aggregate_candidates_preserve_limit_and_publication_boundaries() {
    for (maximum_items, transitions, expected) in [
        (
            1,
            2,
            Some(RuntimeCode::Deterministic(
                DeterministicEvaluationCode::ListSizeLimit,
            )),
        ),
        (2, 2, Some(RuntimeCode::DeterministicTransitionBudget)),
        (2, 3, None),
    ] {
        let ty = TypeDescriptor::list(TypeDescriptor::INT);
        let value =
            LogicalValue::integer(GantryInt::new(7).unwrap_or_else(|| panic!("canonical integer")));
        let root = workflow(
            "crate::main",
            vec![],
            ty.clone(),
            EffectSet::default(),
            vec![
                instruction(0, TypeDescriptor::INT, InstructionKind::Push(value.clone())),
                instruction(1, TypeDescriptor::INT, InstructionKind::Push(value.clone())),
                instruction(
                    2,
                    ty.clone(),
                    InstructionKind::Aggregate {
                        kind: gantry_ir::AggregateKind::List,
                        operands: 2,
                    },
                ),
                instruction(3, ty, InstructionKind::Return),
            ],
        );
        let value_limits = ValueLimits::new(8, 16, 10, maximum_items)
            .unwrap_or_else(|| panic!("positive value limits"));
        let limits = MachineLimits::new(transitions, 1, 1, 1, 8, value_limits)
            .unwrap_or_else(|| panic!("positive machine limits"));
        let mut machine = new_machine(program(vec![root]), "crate::main", vec![], limits);
        for _ in 0..2 {
            assert!(matches!(machine.step(), MachineStep::Transition(_)));
        }
        let before = machine.execution_budget().snapshot();
        let outcome = drive(&mut machine);
        if let Some(code) = expected {
            assert!(
                matches!(&outcome, MachineOutcome::Failed(failure) if failure.code == code),
                "items={maximum_items}, transitions={transitions}: {outcome:?}"
            );
            assert_eq!(machine.execution_budget().snapshot(), before);
        } else {
            assert_eq!(
                outcome,
                MachineOutcome::Succeeded(
                    LogicalValue::list(vec![value.clone(), value], value_limits)
                        .unwrap_or_else(|error| panic!("expected: {error:?}"))
                )
            );
            assert_eq!(
                machine.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
    }
}

/// Evaluation and result limits still refuse before an exhausted publication budget.
#[test]
fn primitive_evaluation_refusals_precede_publication_budget_exhaustion() {
    let text = |value| {
        LogicalValue::string(value, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|error| panic!("text: {error:?}"))
    };
    let integer = |value| {
        LogicalValue::integer(
            GantryInt::new(value).unwrap_or_else(|| panic!("canonical fixture integer")),
        )
    };
    let tight = ValueLimits::new(8, 16, 3, 8).unwrap_or_else(|| panic!("positive limits"));
    for (primitive, ty, operands, value_limits, expected) in [
        (
            Primitive::Divide,
            TypeDescriptor::INT,
            [integer(1), integer(0)],
            DEFAULT_VALUE_LIMITS,
            RuntimeCode::Deterministic(DeterministicEvaluationCode::IntegerDivisionByZero),
        ),
        (
            Primitive::Add,
            TypeDescriptor::STRING,
            [text("éa"), text("😀b")],
            tight,
            RuntimeCode::Deterministic(DeterministicEvaluationCode::StringSizeLimit),
        ),
        (
            Primitive::Add,
            TypeDescriptor::STRING,
            [text("é"), text("😀")],
            tight,
            RuntimeCode::DeterministicTransitionBudget,
        ),
        (
            Primitive::Divide,
            TypeDescriptor::INT,
            [integer(4), integer(2)],
            DEFAULT_VALUE_LIMITS,
            RuntimeCode::DeterministicTransitionBudget,
        ),
    ] {
        let [left, right] = operands;
        let root = workflow(
            "crate::main",
            vec![],
            ty.clone(),
            EffectSet::default(),
            vec![
                instruction(0, ty.clone(), InstructionKind::Push(left)),
                instruction(1, ty.clone(), InstructionKind::Push(right)),
                instruction(2, ty.clone(), InstructionKind::Primitive(primitive)),
                instruction(3, ty, InstructionKind::Return),
            ],
        );
        let limits = MachineLimits::new(2, 1, 1, 1, 8, value_limits)
            .unwrap_or_else(|| panic!("positive machine limits"));
        let mut machine = new_machine(program(vec![root]), "crate::main", vec![], limits);
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        let outcome = drive(&mut machine);
        assert!(
            matches!(&outcome, MachineOutcome::Failed(failure) if failure.code == expected),
            "{primitive:?}: {outcome:?}"
        );
        assert_eq!(machine.execution_budget().snapshot(), before);
    }
}

/// Cached numeric conversion preserves transparent Option metrics and result-transition admission.
#[test]
fn float_conversion_preserves_publication_refusal_precedence() {
    let option_float = TypeDescriptor::option(TypeDescriptor::FLOAT)
        .unwrap_or_else(|error| panic!("option: {error:?}"));
    let tight =
        ValueLimits::new(1, 1, 100_000, 1).unwrap_or_else(|| panic!("positive value limits"));
    for (suffix, transitions, value_limits, expected_code) in [
        (
            "",
            1,
            tight,
            Some(RuntimeCode::DeterministicTransitionBudget),
        ),
        (
            "",
            1,
            DEFAULT_VALUE_LIMITS,
            Some(RuntimeCode::DeterministicTransitionBudget),
        ),
        (
            "x",
            1,
            tight,
            Some(RuntimeCode::DeterministicTransitionBudget),
        ),
        ("x", 2, tight, None),
        ("", 2, tight, None),
    ] {
        let root = workflow(
            "crate::main",
            vec![],
            option_float.clone(),
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(
                            format!("1.{}{suffix}", "0".repeat(20_000)),
                            DEFAULT_VALUE_LIMITS,
                        )
                        .unwrap_or_else(|error| panic!("token: {error:?}")),
                    ),
                ),
                instruction(
                    1,
                    option_float.clone(),
                    InstructionKind::Primitive(Primitive::StringParseFloat),
                ),
                instruction(2, option_float.clone(), InstructionKind::Return),
            ],
        );
        let limits = MachineLimits::new(transitions, 1, 1, 1, 8, value_limits)
            .unwrap_or_else(|| panic!("positive machine limits"));
        let mut machine = new_machine(program(vec![root]), "crate::main", vec![], limits);
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        assert_eq!(machine.step(), MachineStep::YieldRequired);
        assert_eq!(machine.execution_budget().snapshot(), before);
        assert!(machine.resume_after_yield());
        let outcome = drive(&mut machine);
        if let Some(code) = expected_code {
            assert!(
                matches!(&outcome, MachineOutcome::Failed(failure) if failure.code == code),
                "suffix={suffix:?}, transitions={transitions}, expected={code:?}, actual={outcome:?}"
            );
            assert_eq!(machine.execution_budget().snapshot(), before);
        } else {
            let expected = if suffix.is_empty() {
                LogicalValue::some(
                    LogicalValue::float(
                        gantry_core::numeric::GantryFloat::new(1.0)
                            .unwrap_or_else(|| panic!("finite fixture")),
                    ),
                    value_limits,
                )
                .unwrap_or_else(|error| panic!("transparent Option: {error:?}"))
            } else {
                LogicalValue::none()
            };
            assert_eq!(outcome, MachineOutcome::Succeeded(expected));
            assert_eq!(
                machine.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
    }
}

/// Long JSON number grammar admission yields without publishing or charging a partial parse.
#[test]
fn long_float_token_admission_yields_before_publication_and_cancellation() {
    let option_float = TypeDescriptor::option(TypeDescriptor::FLOAT)
        .unwrap_or_else(|error| panic!("option: {error:?}"));
    let root = workflow(
        "crate::main",
        vec![],
        option_float.clone(),
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(format!("1.{}", "0".repeat(20_000)), DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("token: {error:?}")),
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
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("numeric admission cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    assert!(machine.resume_after_yield());
    let expected = LogicalValue::some(
        LogicalValue::float(
            gantry_core::numeric::GantryFloat::new(1.0).unwrap_or_else(|| panic!("finite fixture")),
        ),
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("result: {error:?}"));
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("numeric admission checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("numeric admission budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("numeric admission recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(expected.clone())
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert_eq!(drive(&mut machine), MachineOutcome::Succeeded(expected));
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Late malformed numeric grammar and trailing input refuse identically after checkpoint restart.
#[test]
fn long_malformed_float_tokens_preserve_refusal_after_recovery() {
    let option_float = TypeDescriptor::option(TypeDescriptor::FLOAT)
        .unwrap_or_else(|error| panic!("option: {error:?}"));
    for token in [
        format!("1.{}e+", "0".repeat(20_000)),
        format!("1.{}x", "0".repeat(20_000)),
        format!("1.{} ", "0".repeat(20_000)),
    ] {
        let root = workflow(
            "crate::main",
            vec![],
            option_float.clone(),
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(token, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("token: {error:?}")),
                    ),
                ),
                instruction(
                    1,
                    option_float.clone(),
                    InstructionKind::Primitive(Primitive::StringParseFloat),
                ),
                instruction(2, option_float.clone(), InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            vec![],
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        for _ in 0..3 {
            assert_eq!(machine.step(), MachineStep::YieldRequired);
            assert_eq!(machine.execution_budget().snapshot(), before);
            assert!(machine.resume_after_yield());
        }
        let mut cancelled = machine.clone();
        assert!(
            cancelled
                .cancel("late malformed-token cancellation")
                .is_some()
        );
        assert!(matches!(
            drive(&mut cancelled),
            MachineOutcome::Cancelled(_)
        ));
        assert_eq!(cancelled.execution_budget().snapshot(), before);
        #[cfg(feature = "durable")]
        {
            let bytes = machine.checkpoint().canonical_bytes();
            let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
                .unwrap_or_else(|error| panic!("malformed token checkpoint: {error:?}"));
            let budget = ExecutionBudget::recover_from_checkpoint(before)
                .unwrap_or_else(|error| panic!("malformed token budget: {error:?}"));
            let mut recovered =
                Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                    .unwrap_or_else(|error| panic!("malformed token recovery: {error:?}"));
            assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
            assert_eq!(
                drive(&mut recovered),
                MachineOutcome::Succeeded(LogicalValue::none())
            );
            assert_eq!(
                recovered.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
        assert_eq!(
            drive(&mut machine),
            MachineOutcome::Succeeded(LogicalValue::none())
        );
        assert_eq!(
            machine.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
}

/// Long splitting yields before publication while preserving adjacent and trailing empty segments.
#[test]
fn long_string_splitting_yields_before_publication_and_cancellation() {
    let piece = "é".repeat(10_000);
    let source = format!("{piece}😀😀tail😀");
    let list_type = TypeDescriptor::list(TypeDescriptor::STRING);
    let root = workflow(
        "crate::main",
        vec![],
        list_type.clone(),
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(source, DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("source: {error:?}")),
                ),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("😀", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("separator: {error:?}")),
                ),
            ),
            instruction(
                2,
                list_type.clone(),
                InstructionKind::Primitive(Primitive::StringSplit),
            ),
            instruction(3, list_type, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    for _ in 0..2 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
    }
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("split cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    assert!(machine.resume_after_yield());
    let expected = LogicalValue::list(
        [piece.as_str(), "", "tail", ""]
            .into_iter()
            .map(|text| {
                LogicalValue::string(text, DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("segment: {error:?}"))
            })
            .collect(),
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("expected: {error:?}"));
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("split checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("split budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("split recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        // The original has resumed but has not advanced its operands or program position.
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(expected.clone())
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert_eq!(drive(&mut machine), MachineOutcome::Succeeded(expected));
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Replacement yields before publication and never searches newly inserted text.
#[test]
fn long_string_replacement_yields_before_publication_and_cancellation() {
    let source = format!("{}éé", "a".repeat(20_000));
    let expected = format!("{}éxéx", "a".repeat(20_000));
    let root = workflow(
        "crate::main",
        vec![],
        TypeDescriptor::STRING,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(source, DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("source: {error:?}")),
                ),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("é", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("pattern: {error:?}")),
                ),
            ),
            instruction(
                2,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("éx", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("replacement: {error:?}")),
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
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    for _ in 0..3 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
    }
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("replacement cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("replacement checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("replacement budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("replacement recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        assert!(recovered.resume_after_yield());
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(
                LogicalValue::string(expected.clone(), DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("replacement recovered result: {error:?}"))
            )
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert!(machine.resume_after_yield());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(
            LogicalValue::string(expected, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("replacement expected: {error:?}"))
        )
    );
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Joining long pieces yields before publishing or charging any partial String.
#[test]
fn long_string_join_yields_before_publication_and_cancellation() {
    let piece = "é".repeat(10_000);
    let items = LogicalValue::list(
        vec![
            LogicalValue::string(piece.clone(), DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("piece: {error:?}")),
            LogicalValue::string(piece.clone(), DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("piece: {error:?}")),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("items: {error:?}"));
    let list_type = TypeDescriptor::list(TypeDescriptor::STRING);
    let root = workflow(
        "crate::main",
        vec![],
        TypeDescriptor::STRING,
        EffectSet::default(),
        vec![
            instruction(0, list_type, InstructionKind::Push(items)),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("😀", DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("separator: {error:?}")),
                ),
            ),
            instruction(
                2,
                TypeDescriptor::STRING,
                InstructionKind::Primitive(Primitive::StringListJoin),
            ),
            instruction(3, TypeDescriptor::STRING, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("join cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("join checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("join budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("join recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        assert!(recovered.resume_after_yield());
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(
                LogicalValue::string(format!("{piece}😀{piece}"), DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("join expected: {error:?}"))
            )
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert!(machine.resume_after_yield());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(
            LogicalValue::string(format!("{piece}😀{piece}"), DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("expected: {error:?}"))
        )
    );
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Long concatenation yields before publication without spending the result transition.
#[test]
fn long_string_concatenation_yields_before_publication_and_cancellation() {
    let left = "é".repeat(10_000);
    let right = "😀".repeat(10_000);
    let expected = format!("{left}{right}");
    let root = workflow(
        "crate::main",
        vec![],
        TypeDescriptor::STRING,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(left, DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("left: {error:?}")),
                ),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(right, DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("right: {error:?}")),
                ),
            ),
            instruction(
                2,
                TypeDescriptor::STRING,
                InstructionKind::Primitive(Primitive::Add),
            ),
            instruction(3, TypeDescriptor::STRING, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("concatenation cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("concatenation checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("concatenation budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("concatenation recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        assert!(recovered.resume_after_yield());
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(
                LogicalValue::string(expected.clone(), DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("concatenation expected: {error:?}"))
            )
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert!(machine.resume_after_yield());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(
            LogicalValue::string(expected, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("expected: {error:?}"))
        )
    );
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Contextual lowercase must yield without losing Final_Sigma across ignorable runs.
#[test]
fn long_string_lowercase_yields_with_exact_context_and_cancellation() {
    let input = format!("ΟΣ{}Α ΟΣ", "\u{301}".repeat(10_000));
    let expected = format!("οσ{}α ος", "\u{301}".repeat(10_000));
    let root = workflow(
        "crate::main",
        vec![],
        TypeDescriptor::STRING,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(input, DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("input: {error:?}")),
                ),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Primitive(Primitive::StringLowercase),
            ),
            instruction(2, TypeDescriptor::STRING, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("lowercase cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("lowercase checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("lowercase budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("lowercase recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        assert!(recovered.resume_after_yield());
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(
                LogicalValue::string(expected.clone(), DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("lowercase expected: {error:?}"))
            )
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert!(machine.resume_after_yield());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(
            LogicalValue::string(expected, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("expected: {error:?}"))
        )
    );
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Long uppercase construction yields before publication and retains no partial result on cancel.
#[test]
fn long_string_uppercase_yields_before_publication_and_cancellation() {
    let input = "ßé".repeat(5000);
    let expected = "SSÉ".repeat(5000);
    let root = workflow(
        "crate::main",
        vec![],
        TypeDescriptor::STRING,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string(input, DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("input: {error:?}")),
                ),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Primitive(Primitive::StringUppercase),
            ),
            instruction(2, TypeDescriptor::STRING, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        program(vec![root]),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let before = machine.execution_budget().snapshot();
    assert_eq!(machine.step(), MachineStep::YieldRequired);
    assert_eq!(machine.execution_budget().snapshot(), before);
    let mut cancelled = machine.clone();
    assert!(cancelled.cancel("uppercase cancelled").is_some());
    assert!(matches!(
        drive(&mut cancelled),
        MachineOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled.execution_budget().snapshot(), before);
    #[cfg(feature = "durable")]
    {
        let bytes = machine.checkpoint().canonical_bytes();
        let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
            .unwrap_or_else(|error| panic!("uppercase checkpoint: {error:?}"));
        let budget = ExecutionBudget::recover_from_checkpoint(before)
            .unwrap_or_else(|error| panic!("uppercase budget: {error:?}"));
        let mut recovered =
            Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                .unwrap_or_else(|error| panic!("uppercase recovery: {error:?}"));
        assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
        assert!(recovered.resume_after_yield());
        assert_eq!(
            drive(&mut recovered),
            MachineOutcome::Succeeded(
                LogicalValue::string(expected.clone(), DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("uppercase expected: {error:?}"))
            )
        );
        assert_eq!(
            recovered.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
    assert!(machine.resume_after_yield());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(
            LogicalValue::string(expected, DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("expected: {error:?}"))
        )
    );
    assert_eq!(
        machine.execution_budget().snapshot().revision,
        before.revision + 1
    );
}

/// Long whitespace boundary scans yield without publishing or charging a partial trim.
#[test]
fn long_string_trimming_yields_before_publication_and_cancellation() {
    for primitive in [
        Primitive::StringTrim,
        Primitive::StringTrimStart,
        Primitive::StringTrimEnd,
    ] {
        let input = format!("{}é{}", "\u{2003}".repeat(10_000), "\u{a0}".repeat(10_000));
        let expected = match primitive {
            Primitive::StringTrim => "é".to_owned(),
            Primitive::StringTrimStart => format!("é{}", "\u{a0}".repeat(10_000)),
            Primitive::StringTrimEnd => format!("{}é", "\u{2003}".repeat(10_000)),
            _ => unreachable!("closed trim fixture"),
        };
        let root = workflow(
            "crate::main",
            vec![],
            TypeDescriptor::STRING,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(input, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("input: {error:?}")),
                    ),
                ),
                instruction(
                    1,
                    TypeDescriptor::STRING,
                    InstructionKind::Primitive(primitive),
                ),
                instruction(2, TypeDescriptor::STRING, InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            vec![],
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        assert_eq!(machine.step(), MachineStep::YieldRequired);
        assert_eq!(machine.execution_budget().snapshot(), before);
        let mut cancelled = machine.clone();
        assert!(cancelled.cancel("trim cancelled").is_some());
        assert!(matches!(
            drive(&mut cancelled),
            MachineOutcome::Cancelled(_)
        ));
        assert_eq!(cancelled.execution_budget().snapshot(), before);
        #[cfg(feature = "durable")]
        {
            let bytes = machine.checkpoint().canonical_bytes();
            let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
                .unwrap_or_else(|error| panic!("trim checkpoint: {error:?}"));
            let budget = ExecutionBudget::recover_from_checkpoint(before)
                .unwrap_or_else(|error| panic!("trim budget: {error:?}"));
            let mut recovered =
                Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                    .unwrap_or_else(|error| panic!("trim recovery: {error:?}"));
            assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
            assert!(recovered.resume_after_yield());
            assert_eq!(
                drive(&mut recovered),
                MachineOutcome::Succeeded(
                    LogicalValue::string(expected.clone(), DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("trim expected: {error:?}"))
                )
            );
            assert_eq!(
                recovered.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
        assert!(machine.resume_after_yield());
        assert_eq!(
            drive(&mut machine),
            MachineOutcome::Succeeded(
                LogicalValue::string(expected, DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("expected: {error:?}"))
            )
        );
        assert_eq!(
            machine.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
}

/// Long substring search yields without charging or publishing, including adversarial prefixes.
#[test]
fn long_string_contains_yields_before_publication_and_cancellation() {
    for (source, pattern, expected) in [
        (
            format!("{}b", "a".repeat(20_000)),
            format!("{}b", "a".repeat(5000)),
            true,
        ),
        ("a".repeat(20_000), format!("{}b", "a".repeat(5000)), false),
        (format!("{}😀", "é".repeat(10_000)), "é😀".to_owned(), true),
    ] {
        let root = workflow(
            "crate::main",
            vec![],
            TypeDescriptor::BOOL,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(source, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("source: {error:?}")),
                    ),
                ),
                instruction(
                    1,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(pattern, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("pattern: {error:?}")),
                    ),
                ),
                instruction(
                    2,
                    TypeDescriptor::BOOL,
                    InstructionKind::Primitive(Primitive::StringContains),
                ),
                instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            vec![],
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        assert_eq!(machine.step(), MachineStep::YieldRequired);
        assert_eq!(machine.execution_budget().snapshot(), before);
        let mut cancelled = machine.clone();
        assert!(cancelled.cancel("search cancelled").is_some());
        assert!(matches!(
            drive(&mut cancelled),
            MachineOutcome::Cancelled(_)
        ));
        assert_eq!(cancelled.execution_budget().snapshot(), before);
        #[cfg(feature = "durable")]
        {
            let bytes = machine.checkpoint().canonical_bytes();
            let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
                .unwrap_or_else(|error| panic!("search checkpoint: {error:?}"));
            let budget = ExecutionBudget::recover_from_checkpoint(before)
                .unwrap_or_else(|error| panic!("search budget: {error:?}"));
            let mut recovered =
                Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                    .unwrap_or_else(|error| panic!("search recovery: {error:?}"));
            assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
            assert!(recovered.resume_after_yield());
            assert_eq!(
                drive(&mut recovered),
                MachineOutcome::Succeeded(LogicalValue::boolean(expected))
            );
            assert_eq!(
                recovered.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
        assert!(machine.resume_after_yield());
        assert_eq!(
            drive(&mut machine),
            MachineOutcome::Succeeded(LogicalValue::boolean(expected))
        );
        assert_eq!(
            machine.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
}

/// Long prefix and suffix matching yields before publishing its exact Boolean result.
#[test]
fn long_string_prefix_and_suffix_yield_before_publication() {
    for primitive in [Primitive::StringStartsWith, Primitive::StringEndsWith] {
        let pattern = "é".repeat(10_000);
        let source = if primitive == Primitive::StringStartsWith {
            format!("{pattern}tail")
        } else {
            format!("head{pattern}")
        };
        let root = workflow(
            "crate::main",
            vec![],
            TypeDescriptor::BOOL,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(source, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("source: {error:?}")),
                    ),
                ),
                instruction(
                    1,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(
                        LogicalValue::string(pattern, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("pattern: {error:?}")),
                    ),
                ),
                instruction(
                    2,
                    TypeDescriptor::BOOL,
                    InstructionKind::Primitive(primitive),
                ),
                instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            vec![],
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
        let before = machine.execution_budget().snapshot();
        assert_eq!(machine.step(), MachineStep::YieldRequired);
        assert_eq!(machine.execution_budget().snapshot(), before);
        let mut cancelled = machine.clone();
        assert!(cancelled.cancel("matching cancelled").is_some());
        assert!(matches!(
            drive(&mut cancelled),
            MachineOutcome::Cancelled(_)
        ));
        assert_eq!(cancelled.execution_budget().snapshot(), before);
        #[cfg(feature = "durable")]
        {
            let bytes = machine.checkpoint().canonical_bytes();
            let checkpoint = crate::MachineCheckpointV3::decode(&machine.program_arc(), &bytes)
                .unwrap_or_else(|error| panic!("matching checkpoint: {error:?}"));
            let budget = ExecutionBudget::recover_from_checkpoint(before)
                .unwrap_or_else(|error| panic!("matching budget: {error:?}"));
            let mut recovered =
                Machine::recover_from_checkpoint(machine.program_arc(), checkpoint, budget)
                    .unwrap_or_else(|error| panic!("matching recovery: {error:?}"));
            assert_eq!(recovered.checkpoint().canonical_bytes(), bytes);
            assert!(recovered.resume_after_yield());
            assert_eq!(
                drive(&mut recovered),
                MachineOutcome::Succeeded(LogicalValue::boolean(true))
            );
            assert_eq!(
                recovered.execution_budget().snapshot().revision,
                before.revision + 1
            );
        }
        assert!(machine.resume_after_yield());
        assert_eq!(
            drive(&mut machine),
            MachineOutcome::Succeeded(LogicalValue::boolean(true))
        );
        assert_eq!(
            machine.execution_budget().snapshot().revision,
            before.revision + 1
        );
    }
}

/// Cooperative chunks do not spend transition budget or bypass final-publication refusal.
#[test]
fn cooperative_string_comparison_preserves_budget_and_quantum_boundaries() {
    let text = LogicalValue::string("é".repeat(10_000), DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("text: {error:?}"));
    let fixture = program(vec![workflow(
        "crate::main",
        vec![],
        TypeDescriptor::BOOL,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(text.clone()),
            ),
            instruction(1, TypeDescriptor::STRING, InstructionKind::Push(text)),
            instruction(
                2,
                TypeDescriptor::BOOL,
                InstructionKind::Primitive(Primitive::Equal),
            ),
            instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
        ],
    )]);
    let mut exhausted = new_machine(
        Arc::clone(&fixture),
        "crate::main",
        vec![],
        limits(2, 1, 1, 1, 8),
    );
    assert!(matches!(exhausted.step(), MachineStep::Transition(_)));
    assert!(matches!(exhausted.step(), MachineStep::Transition(_)));
    let before = exhausted.execution_budget().snapshot();
    assert_eq!(exhausted.step(), MachineStep::YieldRequired);
    assert_eq!(exhausted.execution_budget().snapshot(), before);
    assert!(exhausted.resume_after_yield());
    assert!(
        matches!(drive(&mut exhausted), MachineOutcome::Failed(failure)
        if failure.code == RuntimeCode::DeterministicTransitionBudget)
    );
    assert_eq!(exhausted.execution_budget().snapshot(), before);

    let mut quantum_one = new_machine(
        Arc::clone(&fixture),
        "crate::main",
        vec![],
        limits(8, 1, 1, 1, 1),
    );
    assert_eq!(
        drive(&mut quantum_one),
        MachineOutcome::Succeeded(LogicalValue::boolean(true))
    );
    assert_eq!(quantum_one.execution_budget().snapshot().revision, 3);

    let mut cancelled = new_machine(fixture, "crate::main", vec![], limits(8, 1, 1, 1, 8));
    assert!(matches!(cancelled.step(), MachineStep::Transition(_)));
    assert!(matches!(cancelled.step(), MachineStep::Transition(_)));
    let before = cancelled.execution_budget().snapshot();
    for _ in 0..3 {
        assert_eq!(cancelled.step(), MachineStep::YieldRequired);
        assert_eq!(cancelled.execution_budget().snapshot(), before);
        assert!(cancelled.resume_after_yield());
    }
    assert!(cancelled.cancel("cancel after three chunks").is_some());
    assert!(
        matches!(drive(&mut cancelled), MachineOutcome::Cancelled(reason)
        if reason.as_ref() == "cancel after three chunks")
    );
    assert_eq!(cancelled.execution_budget().snapshot(), before);
}

/// Chunk boundaries preserve exact equality for unequal lengths and late UTF-8 differences.
#[test]
fn cooperative_string_comparison_preserves_unequal_and_boundary_results() {
    for (left, right) in [
        (String::new(), String::new()),
        (String::new(), "x".to_owned()),
        ("x".to_owned(), String::new()),
        ("a".repeat(4096), "a".repeat(4096)),
        ("a".repeat(4097), "a".repeat(4096)),
        (
            format!("{}é", "a".repeat(4095)),
            format!("{}ê", "a".repeat(4095)),
        ),
        (
            format!("{}b", "a".repeat(10_000)),
            format!("{}c", "a".repeat(10_000)),
        ),
    ] {
        for primitive in [
            Primitive::Equal,
            Primitive::NotEqual,
            Primitive::StringStartsWith,
            Primitive::StringEndsWith,
        ] {
            let expected = match primitive {
                Primitive::Equal => left == right,
                Primitive::NotEqual => left != right,
                Primitive::StringStartsWith => left.starts_with(&right),
                Primitive::StringEndsWith => left.ends_with(&right),
                _ => unreachable!("closed comparison fixture"),
            };
            let root = workflow(
                "crate::main",
                vec![],
                TypeDescriptor::BOOL,
                EffectSet::default(),
                vec![
                    instruction(
                        0,
                        TypeDescriptor::STRING,
                        InstructionKind::Push(
                            LogicalValue::string(left.clone(), DEFAULT_VALUE_LIMITS)
                                .unwrap_or_else(|error| panic!("left: {error:?}")),
                        ),
                    ),
                    instruction(
                        1,
                        TypeDescriptor::STRING,
                        InstructionKind::Push(
                            LogicalValue::string(right.clone(), DEFAULT_VALUE_LIMITS)
                                .unwrap_or_else(|error| panic!("right: {error:?}")),
                        ),
                    ),
                    instruction(
                        2,
                        TypeDescriptor::BOOL,
                        InstructionKind::Primitive(primitive),
                    ),
                    instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
                ],
            );
            let mut machine = new_machine(
                program(vec![root]),
                "crate::main",
                vec![],
                limits(8, 1, 1, 1, 8),
            );
            assert_eq!(
                drive(&mut machine),
                MachineOutcome::Succeeded(LogicalValue::boolean(expected))
            );
            assert_eq!(machine.execution_budget().snapshot().revision, 3);
        }
    }
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

/// Runtime parsing keeps noncanonical JSON numbers and refuses invalid input without failing.
#[test]
fn string_float_parsing_preserves_json_number_contract() {
    let option_float = TypeDescriptor::option(TypeDescriptor::FLOAT)
        .unwrap_or_else(|error| panic!("option: {error}"));
    for (source, expected) in [
        ("1e+0".to_owned(), Some(1.0)),
        (format!("1.{}", "0".repeat(1000)), Some(1.0)),
        ("-0".to_owned(), Some(0.0)),
        ("1.79769313486231571e308".to_owned(), None),
        ("1 ".to_owned(), None),
        ("[1]".to_owned(), None),
    ] {
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
                        LogicalValue::string(source, DEFAULT_VALUE_LIMITS)
                            .unwrap_or_else(|error| panic!("input: {error:?}")),
                    ),
                ),
                instruction(
                    1,
                    option_float.clone(),
                    InstructionKind::Primitive(Primitive::StringParseFloat),
                ),
                instruction(2, option_float.clone(), InstructionKind::Return),
            ],
        );
        let mut machine = new_machine(
            program(vec![root]),
            "crate::main",
            Vec::new(),
            limits(8, 1, 1, 1, 8),
        );
        let MachineOutcome::Succeeded(value) = drive(&mut machine) else {
            panic!("parsing must not fail the task")
        };
        let expected = expected.map_or_else(LogicalValue::none, |number| {
            LogicalValue::some(
                LogicalValue::float(
                    gantry_core::numeric::GantryFloat::new(number)
                        .unwrap_or_else(|| panic!("finite fixture")),
                ),
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("result: {error:?}"))
        });
        assert_eq!(value, expected);
    }
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
        receiver_mode: None,
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
                    callee: callable("crate::callee"),
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

#[cfg(feature = "durable")]
#[test]
fn shared_receiver_calls_resolve_nested_caller_places_and_recover() {
    let main_path = path("crate::main");
    let method_path = path("crate::Outer::value");
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let method_identity = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let outer_type = TypeDescriptor::declared(path("crate::Outer"));
    let mut callables = vec![
        (
            main_identity,
            Workflow {
                path: main_path,
                parameters: vec![Parameter {
                    name: Arc::from("item"),
                    ty: outer_type.clone(),
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
                            callee: method_identity.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from("item"),
                                path: vec![
                                    ValuePathSegment::StructField("values".to_owned()),
                                    ValuePathSegment::TupleMember(0),
                                ],
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            method_identity,
            Workflow {
                path: method_path,
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
    let program = Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("shared receiver program failed: {error:?}")),
    );
    let item = LogicalValue::structure(
        "crate::Outer",
        vec![(
            "values".to_owned(),
            LogicalValue::tuple(
                vec![
                    LogicalValue::integer(
                        GantryInt::new(7)
                            .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                    ),
                    LogicalValue::integer(
                        GantryInt::new(8)
                            .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                    ),
                ],
                DEFAULT_VALUE_LIMITS,
            )
            .unwrap_or_else(|error| panic!("fixture tuple failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture value failed: {error:?}"));
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![item],
        limits(8, 1, 1, 2, 8),
    );

    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP05".as_slice()));
    let checkpoint = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("shared receiver checkpoint decode failed: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let mut stripped_admission = checkpoint.clone();
    assert!(stripped_admission.test_clear_receiver_admission());
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &stripped_admission.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
    let mut injected_root_admission = checkpoint.clone();
    assert!(injected_root_admission.test_add_receiver_admission_to_root());
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &injected_root_admission.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
    let mut relabeled_old_checkpoint = bytes.clone();
    relabeled_old_checkpoint[..8].copy_from_slice(b"GNTMCP03");
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &relabeled_old_checkpoint),
        Err(crate::MachineRecoveryError::ProgramMismatch)
            | Err(crate::MachineRecoveryError::InvalidEncoding)
    ));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("shared receiver budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("shared receiver recovery failed: {error:?}"));
    assert_eq!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted"))
        ))
    );
}

fn place_initialization_program() -> Arc<MachineProgram> {
    let main_path = path("crate::main");
    let callee_path = path("crate::callee");
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let callee_identity = CanonicalCallableIdentity::free(&callee_path, &[]);
    let mut callables = vec![
        (
            main_identity,
            Workflow {
                path: main_path,
                parameters: vec![Parameter {
                    name: Arc::from("item"),
                    ty: TypeDescriptor::declared(path("crate::Item")),
                    mutable: false,
                    receiver_mode: None,
                }],
                result: TypeDescriptor::UNIT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::UNIT,
                        InstructionKind::Call {
                            callee: callee_identity.clone(),
                            arguments: 0,
                        },
                    ),
                    instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
                ],
            },
        ),
        (
            callee_identity,
            Workflow {
                path: callee_path,
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::UNIT,
                        InstructionKind::Push(LogicalValue::unit()),
                    ),
                    instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
                ],
            },
        ),
    ];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("place-initialization program failed: {error:?}")),
    )
}

fn place_initialization_fixture() -> (Arc<MachineProgram>, Machine) {
    let program = place_initialization_program();
    let item = LogicalValue::structure(
        "crate::Item",
        vec![(
            "field".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture struct failed: {error:?}"));
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![item],
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    (program, machine)
}

/// Builds a program whose `crate::main` enters `crate::Token::consume` through one owned-move
/// caller place, so the callee frame carries a justified staging entry.
#[cfg(feature = "durable")]
fn owned_move_program(
    main_parameter: Parameter,
    receiver_root: &str,
    receiver_path: Vec<ValuePathSegment>,
    callee_result: TypeDescriptor,
    callee: Vec<Instruction>,
) -> Arc<MachineProgram> {
    let main_path = path("crate::main");
    let method_path = path("crate::Token::consume");
    let token_type = TypeDescriptor::declared(path("crate::Token"));
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let method_identity = CanonicalCallableIdentity::inherent(&token_type, "consume", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let mut callables = vec![
        (
            main_identity,
            Workflow {
                path: main_path,
                parameters: vec![main_parameter],
                result: callee_result.clone(),
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        callee_result.clone(),
                        InstructionKind::ReceiverCall {
                            callee: method_identity.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from(receiver_root),
                                path: receiver_path,
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(1, callee_result.clone(), InstructionKind::Return),
                ],
            },
        ),
        (
            method_identity,
            Workflow {
                path: method_path,
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: token_type,
                    mutable: true,
                    receiver_mode: Some(ReceiverMode::Owned),
                }],
                result: callee_result,
                effects: EffectSet::default(),
                instructions: callee,
            },
        ),
    ];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("owned move program failed: {error:?}")),
    )
}

#[cfg(feature = "durable")]
fn token_value(value: i64) -> LogicalValue {
    LogicalValue::structure(
        "crate::Token",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(value)
                    .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture value failed: {error:?}"))
}

#[cfg(feature = "durable")]
fn token_parameter(name: &str) -> Parameter {
    Parameter {
        name: Arc::from(name),
        ty: TypeDescriptor::declared(path("crate::Token")),
        mutable: false,
        receiver_mode: None,
    }
}

#[cfg(feature = "durable")]
fn int_push(site_index: u64, value: i64) -> Instruction {
    instruction(
        site_index,
        TypeDescriptor::INT,
        InstructionKind::Push(LogicalValue::integer(
            GantryInt::new(value).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        )),
    )
}

#[cfg(feature = "durable")]
#[test]
fn place_initialization_round_trips_through_checkpoint_codec() {
    // A legitimate owned-move frame carries exactly one justified staging entry.
    let program = owned_move_program(
        token_parameter("token"),
        "token",
        Vec::new(),
        TypeDescriptor::INT,
        vec![
            int_push(0, 7),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("place-initialization decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);

    // A forged entry on a receiver-less call frame is rejected.
    let (plain, machine) = place_initialization_fixture();
    let mut forged = machine.checkpoint();
    assert!(forged.test_add_place_initialization(
        1,
        "item",
        vec![ValuePathSegment::StructField("field".to_owned())],
    ));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&plain, &forged.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_place_initialization_mismatching_caller_place() {
    let program = owned_move_program(
        token_parameter("token"),
        "token",
        Vec::new(),
        TypeDescriptor::INT,
        vec![
            int_push(0, 7),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_set_place_initialization_path(
        1,
        0,
        vec![ValuePathSegment::StructField("value".to_owned())],
    ));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn checkpoint_without_place_initialization_keeps_existing_magic() {
    let (_, machine) = place_initialization_fixture();
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP03".as_slice()));
}

#[cfg(feature = "durable")]
#[test]
fn checkpoint_with_place_initialization_uses_gntmcp06() {
    let (_, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(1, "item", Vec::new()));
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_initialized_true_place_entry() {
    let (program, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(1, "item", Vec::new()));
    assert!(checkpoint.test_set_place_initialization_initialized(1, 0, true));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_duplicate_place_initialization() {
    let (program, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(1, "item", Vec::new()));
    assert!(checkpoint.test_add_place_initialization(1, "item", Vec::new()));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_unresolvable_place_initialization() {
    let (program, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(1, "missing", Vec::new()));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_place_initialization_on_root_frame() {
    let (program, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(0, "item", Vec::new()));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_place_initialization_with_unknown_struct_field() {
    let (program, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(
        1,
        "item",
        vec![ValuePathSegment::StructField("absent".to_owned())],
    ));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_rejects_place_initialization_with_cross_kind_segment() {
    let (program, machine) = place_initialization_fixture();
    let mut checkpoint = machine.checkpoint();
    assert!(checkpoint.test_add_place_initialization(
        1,
        "item",
        vec![ValuePathSegment::TupleMember(0)],
    ));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes()),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

#[cfg(feature = "durable")]
#[test]
fn validate_accepts_place_initialization_with_nested_declared_field_path() {
    // A nested struct-field receiver place justifies the entry and navigates the staged value.
    let program = owned_move_program(
        Parameter {
            name: Arc::from("hub"),
            ty: TypeDescriptor::declared(path("crate::Hub")),
            mutable: false,
            receiver_mode: None,
        },
        "hub",
        vec![
            ValuePathSegment::StructField("cell".to_owned()),
            ValuePathSegment::StructField("token".to_owned()),
        ],
        TypeDescriptor::INT,
        vec![
            int_push(0, 9),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let cell = LogicalValue::structure(
        "crate::Cell",
        vec![("token".to_owned(), token_value(9))],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture cell failed: {error:?}"));
    let hub = LogicalValue::structure(
        "crate::Hub",
        vec![("cell".to_owned(), cell)],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture hub failed: {error:?}"));
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![hub],
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    assert!(crate::MachineCheckpointV3::decode(&program, &bytes).is_ok());
}

#[cfg(feature = "durable")]
#[test]
fn owned_receiver_call_checkpoint_recovers_without_admission_extension() {
    let main_path = path("crate::main");
    let method_path = path("crate::Counter::bump");
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let method_identity = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "bump", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let mut callables = vec![
        (
            main_identity,
            Workflow {
                path: main_path,
                parameters: Vec::new(),
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::Push(LogicalValue::integer(
                            GantryInt::new(7)
                                .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                        )),
                    ),
                    instruction(
                        1,
                        TypeDescriptor::INT,
                        InstructionKind::ReceiverCall {
                            callee: method_identity.clone(),
                            arguments: 1,
                            source: ReceiverSource::CopiedValue,
                        },
                    ),
                    instruction(2, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            method_identity.clone(),
            Workflow {
                path: method_path,
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: TypeDescriptor::INT,
                    mutable: true,
                    receiver_mode: Some(ReceiverMode::Owned),
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
    let program = Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("owned receiver program failed: {error:?}")),
    );

    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP03".as_slice()));
    let checkpoint = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("owned receiver checkpoint decode failed: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("owned receiver budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("owned receiver recovery failed: {error:?}"));
    assert_eq!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted"))
        ))
    );
}

#[cfg(feature = "durable")]
#[test]
fn first_scope_parameters_coexist_with_let_locals_across_checkpoint_round_trip() {
    let root = workflow(
        "crate::main",
        vec![Parameter {
            name: Arc::from("input"),
            ty: TypeDescriptor::INT,
            mutable: false,
            receiver_mode: None,
        }],
        TypeDescriptor::INT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(
                    GantryInt::new(1)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                )),
            ),
            instruction(
                1,
                TypeDescriptor::INT,
                InstructionKind::Bind {
                    name: Arc::from("local"),
                    ty: TypeDescriptor::INT,
                    mutable: false,
                },
            ),
            instruction(
                2,
                TypeDescriptor::INT,
                InstructionKind::Load(Arc::from("local")),
            ),
            instruction(3, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let program = program(vec![root]);
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![LogicalValue::integer(GantryInt::new(7).unwrap_or_else(
            || unreachable!("fixture integer is admitted"),
        ))],
        limits(8, 1, 1, 2, 8),
    );

    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));

    let checkpoint =
        crate::MachineCheckpointV3::decode(&program, &machine.checkpoint().canonical_bytes())
            .unwrap_or_else(|error| panic!("parameter+local checkpoint decode failed: {error:?}"));

    let mut renamed = checkpoint.clone();
    assert!(renamed.test_rename_parameter_binding("input", "tampered"));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &renamed.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));

    let mut retyped = checkpoint.clone();
    assert!(retyped.test_set_parameter_binding_type("input", TypeDescriptor::BOOL));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &retyped.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));

    let mut remutabled = checkpoint.clone();
    assert!(remutabled.test_set_parameter_binding_mutable("input", true));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &remutabled.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));

    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("parameter+local budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("parameter+local checkpoint recovery failed: {error:?}"));
    assert_eq!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(1).unwrap_or_else(|| unreachable!("fixture integer is admitted"))
        ))
    );
}

#[cfg(feature = "durable")]
#[test]
fn exclusive_receiver_admission_recovery_rejects_tampering_and_resumes_nested_write_through() {
    let main_path = path("crate::main");
    let outer_path = path("crate::Outer::increment");
    let inner_path = path("crate::Int::increment");
    let main = CanonicalCallableIdentity::free(&main_path, &[]);
    let outer_type = TypeDescriptor::declared(path("crate::Outer"));
    let outer = CanonicalCallableIdentity::inherent(&outer_type, "increment", &[])
        .unwrap_or_else(|error| panic!("outer method identity failed: {error}"));
    let inner = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "increment", &[])
        .unwrap_or_else(|error| panic!("inner method identity failed: {error}"));
    let mut callables = vec![
        (
            main,
            Workflow {
                path: main_path,
                parameters: vec![Parameter {
                    name: Arc::from("item"),
                    ty: outer_type.clone(),
                    mutable: true,
                    receiver_mode: None,
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::ReceiverCall {
                            callee: outer.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from("item"),
                                path: Vec::new(),
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            outer,
            Workflow {
                path: outer_path,
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: outer_type.clone(),
                    mutable: true,
                    receiver_mode: Some(ReceiverMode::ExclusivePlace),
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::ReceiverCall {
                            callee: inner.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from("self"),
                                path: vec![ValuePathSegment::StructField("value".to_owned())],
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            inner,
            Workflow {
                path: inner_path,
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: TypeDescriptor::INT,
                    mutable: true,
                    receiver_mode: Some(ReceiverMode::ExclusivePlace),
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::Push(LogicalValue::integer(
                            GantryInt::new(8)
                                .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                        )),
                    ),
                    instruction(
                        1,
                        TypeDescriptor::INT,
                        InstructionKind::Assign {
                            name: Arc::from("self"),
                            path: Vec::new(),
                            target_type: TypeDescriptor::INT,
                        },
                    ),
                    instruction(
                        2,
                        TypeDescriptor::INT,
                        InstructionKind::Load(Arc::from("self")),
                    ),
                    instruction(3, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
    ];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    let program = Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("exclusive receiver program failed: {error:?}")),
    );
    let item = LogicalValue::structure(
        "crate::Outer",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture outer value failed: {error:?}"));
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![item],
        limits(16, 1, 1, 4, 16),
    );
    for _ in 0..2 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
    }
    let checkpoint = machine.checkpoint();
    for tampered in [
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_receiver_admission_parent_mutable(false));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_receiver_admission_callee_mutable(false));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(
                checkpoint.test_set_receiver_admission_path(vec![ValuePathSegment::ListItem(0),])
            );
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(
                checkpoint.test_set_receiver_admission_path(vec![ValuePathSegment::EnumPayload,])
            );
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_receiver_admission_path(Vec::new()));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(
                checkpoint.test_set_receiver_admission_callee_value(LogicalValue::integer(
                    GantryInt::new(6)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                ))
            );
            checkpoint
        },
    ] {
        assert_eq!(
            crate::MachineCheckpointV3::decode(&program, &tampered.canonical_bytes()),
            Err(crate::MachineRecoveryError::ProgramMismatch)
        );
    }
    for _ in 0..2 {
        assert!(matches!(machine.step(), MachineStep::Transition(_)));
    }
    let committed = machine.checkpoint();
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("exclusive budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, committed, budget)
        .unwrap_or_else(|error| panic!("exclusive checkpoint recovery failed: {error:?}"));
    assert_eq!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(8).unwrap_or_else(|| unreachable!("fixture integer is admitted"))
        ))
    );
}

#[test]
fn shared_receiver_admission_rejections_preserve_the_pre_call_instruction_state() {
    let main_path = path("crate::main");
    let method_path = path("crate::Outer::value");
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let method_identity = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let outer_type = TypeDescriptor::declared(path("crate::Outer"));
    let item = LogicalValue::structure(
        "crate::Outer",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture outer value failed: {error:?}"));
    let string = LogicalValue::structure(
        "crate::Outer",
        vec![(
            "value".to_owned(),
            LogicalValue::string("wrong", DEFAULT_VALUE_LIMITS)
                .unwrap_or_else(|error| panic!("fixture string failed: {error:?}")),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture outer value failed: {error:?}"));
    let program_for = |source: ReceiverSource, arguments: usize, prefix: bool| {
        let mut instructions = Vec::new();
        if prefix {
            instructions.push(instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ));
        }
        let call_site = u64::from(prefix);
        instructions.push(instruction(
            call_site,
            TypeDescriptor::INT,
            InstructionKind::ReceiverCall {
                callee: method_identity.clone(),
                arguments,
                source,
            },
        ));
        instructions.push(instruction(
            call_site + 1,
            TypeDescriptor::INT,
            InstructionKind::Return,
        ));
        let mut callables = vec![
            (
                main_identity.clone(),
                Workflow {
                    path: main_path.clone(),
                    parameters: vec![Parameter {
                        name: Arc::from("item"),
                        ty: outer_type.clone(),
                        mutable: false,
                        receiver_mode: None,
                    }],
                    result: TypeDescriptor::INT,
                    effects: EffectSet::default(),
                    instructions,
                },
            ),
            (
                method_identity.clone(),
                Workflow {
                    path: method_path.clone(),
                    parameters: {
                        let mut parameters = vec![Parameter {
                            name: Arc::from("self"),
                            ty: TypeDescriptor::INT,
                            mutable: false,
                            receiver_mode: Some(ReceiverMode::SharedPlace),
                        }];
                        if arguments == 2 {
                            parameters.push(Parameter {
                                name: Arc::from("other"),
                                ty: TypeDescriptor::INT,
                                mutable: false,
                                receiver_mode: None,
                            });
                        }
                        parameters
                    },
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
        Arc::new(
            MachineProgram::with_callable_identities(callables)
                .unwrap_or_else(|error| panic!("shared receiver program failed: {error:?}")),
        )
    };
    let reject = |source, arguments, value, limits, prefix| {
        let program = program_for(source, arguments, prefix);
        let mut machine = new_machine(program, "crate::main", vec![value], limits);
        if prefix {
            assert!(matches!(machine.step(), MachineStep::Transition(_)));
        }
        let before = machine.test_instruction_state();
        assert!(matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::Failure(ref failure))
                if failure.code == RuntimeCode::InternalInvariant
                    || failure.code == RuntimeCode::DeterministicTransitionBudget
                    || failure.code
                        == RuntimeCode::Deterministic(
                            DeterministicEvaluationCode::WorkflowCallDepthLimit
                        )
        ));
        assert_eq!(machine.test_instruction_state(), before);
    };
    reject(
        ReceiverSource::CallerPlace {
            root: Arc::from("missing"),
            path: Vec::new(),
            ownership: OwnershipClass::Copyable,
        },
        1,
        item.clone(),
        limits(8, 1, 1, 2, 8),
        false,
    );
    reject(
        ReceiverSource::CallerPlace {
            root: Arc::from("item"),
            path: vec![ValuePathSegment::TupleMember(0)],
            ownership: OwnershipClass::Copyable,
        },
        1,
        item.clone(),
        limits(8, 1, 1, 2, 8),
        false,
    );
    reject(
        ReceiverSource::CallerPlace {
            root: Arc::from("item"),
            path: vec![ValuePathSegment::StructField("value".to_owned())],
            ownership: OwnershipClass::Copyable,
        },
        1,
        string,
        limits(8, 1, 1, 2, 8),
        false,
    );
    reject(
        ReceiverSource::CallerPlace {
            root: Arc::from("item"),
            path: vec![ValuePathSegment::StructField("value".to_owned())],
            ownership: OwnershipClass::Copyable,
        },
        2,
        item.clone(),
        limits(8, 1, 1, 2, 8),
        false,
    );
    reject(
        ReceiverSource::CallerPlace {
            root: Arc::from("item"),
            path: vec![ValuePathSegment::StructField("value".to_owned())],
            ownership: OwnershipClass::Copyable,
        },
        1,
        item.clone(),
        limits(8, 1, 1, 1, 8),
        false,
    );
    reject(
        ReceiverSource::CallerPlace {
            root: Arc::from("item"),
            path: vec![ValuePathSegment::StructField("value".to_owned())],
            ownership: OwnershipClass::Copyable,
        },
        1,
        item,
        limits(1, 1, 1, 2, 8),
        true,
    );
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_spawn_suspends_until_handle_publication_and_child_completes() {
    let (program, body_identity) = spawn_program();
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let mut root = Machine::new_concurrent_root_with_budget_and_context(
        Arc::clone(&program),
        &path("crate::main"),
        vec![count.clone()],
        execution(),
        machine_limits,
        budget.clone(),
        Some(Arc::from("worker")),
        None,
    )
    .unwrap_or_else(|error| panic!("concurrent root construction failed: {error:?}"));

    let suspension = match root.step() {
        MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn)) => spawn,
        other => panic!("unexpected spawn step: {other:?}"),
    };
    assert_eq!(root.status(), MachineStatus::WaitingTaskControl);
    assert_eq!(root.pending_spawn(), Some(&suspension));
    assert_eq!(suspension.body, body_identity);
    assert_eq!(suspension.occurrence, 0);
    assert_eq!(suspension.inherited_agent.as_deref(), Some("worker"));
    assert_eq!(suspension.parent_session, None);
    assert_eq!(suspension.captures.len(), 1);
    assert_eq!(suspension.captures[0].task_capture().value(), &count);
    assert!(root.task_handle("child").is_none());

    let (child_task_id, child_task_path) = child_task_coordinate();
    let handle =
        DynamicTaskHandleIdentity::from_parts(root_task_identity(execution()), child_task_id);
    assert!(matches!(
        root.complete_spawn(&suspension, handle),
        Ok(MachineLabel::Deterministic { ref kind, .. }) if kind.as_ref() == "spawn-complete"
    ));
    let published = root
        .task_handle("child")
        .unwrap_or_else(|| panic!("spawn completion did not publish its lexical handle"));
    assert_eq!(published.identity(), handle);
    assert_eq!(published.result_type(), &TypeDescriptor::INT);

    let captures = suspension
        .captures
        .iter()
        .map(|capture| capture.task_capture().clone())
        .collect::<Vec<_>>();
    let mut child = Machine::new_concurrent_task_body_with_context(
        program,
        &body_identity,
        &captures,
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        suspension.inherited_agent.clone(),
        None,
    )
    .unwrap_or_else(|error| panic!("child machine construction failed: {error:?}"));
    assert_eq!(child.active_agent(), Some("worker"));
    assert!(matches!(
        child.step(),
        MachineStep::Transition(MachineLabel::Deterministic { ref kind, .. })
            if kind.as_ref() == "variable"
    ));
    assert!(matches!(
        child.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Succeeded(ref value)))
            if value == &count
    ));
    assert!(
        matches!(drive(&mut root), MachineOutcome::Succeeded(ref value) if value == &LogicalValue::unit())
    );
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_join_consumes_handles_before_waiting_and_completes_in_order() {
    let result_type = TypeDescriptor::list(TypeDescriptor::INT);
    let program = joined_int_program(
        InstructionKind::Join {
            handles: vec![Arc::from("first"), Arc::from("second")],
        },
        result_type,
    );
    let machine_limits = limits(32, 1, 1, 1, 32);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut machine = Machine::new_concurrent_root_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("join machine construction failed: {error:?}"));
    complete_fixture_spawn(&mut machine, 0x51);
    complete_fixture_spawn(&mut machine, 0x52);

    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { ref kind, .. })
            if kind.as_ref() == "join-suspended"
    ));
    assert!(machine.task_handle("first").is_none());
    assert!(machine.task_handle("second").is_none());
    let join = machine
        .pending_task_control()
        .and_then(|suspension| suspension.join())
        .map(|(join, all)| {
            assert!(!all);
            join.clone()
        })
        .unwrap_or_else(|| panic!("join suspension missing"));
    assert_eq!(
        join.handles
            .iter()
            .map(|handle| handle.name())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert_eq!(
        machine.complete_join(&join, JoinResolutionV1::Pending(Vec::new())),
        Err(TaskControlCompletionError::JoinPending)
    );
    let values = vec![
        LogicalValue::integer(
            GantryInt::new(1).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ),
        LogicalValue::integer(
            GantryInt::new(2).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ),
    ];
    let expected = LogicalValue::list(values, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("join result construction failed: {error:?}"));
    assert!(matches!(
        machine.complete_join(&join, JoinResolutionV1::Succeeded(expected.clone())),
        Ok(MachineLabel::Deterministic { ref kind, .. }) if kind.as_ref() == "join-complete"
    ));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Succeeded(ref value) if value == &expected
    ));
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_empty_joinall_reduces_directly_to_unit_without_pending_task_control() {
    let empty = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::JoinAll {
                    handles: Vec::new(),
                },
            ),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let machine_limits = limits(16, 1, 1, 1, 16);
    let mut empty_machine = Machine::new_concurrent_root_with_budget_and_context(
        program(vec![empty]),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        ExecutionBudget::new(execution(), machine_limits),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("empty joinall machine construction failed: {error:?}"));
    assert!(matches!(
        empty_machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { ref kind, .. })
            if kind.as_ref() == "joinall-empty"
    ));
    assert!(empty_machine.pending_task_control().is_none());
    assert!(matches!(
        drive(&mut empty_machine),
        MachineOutcome::Succeeded(ref value) if value == &LogicalValue::unit()
    ));
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_detach_completes_with_unit() {
    let program = joined_int_program(
        InstructionKind::Detach {
            handle: Arc::from("first"),
        },
        TypeDescriptor::UNIT,
    );
    let machine_limits = limits(32, 1, 1, 1, 32);
    let mut detach_machine = Machine::new_concurrent_root_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        ExecutionBudget::new(execution(), machine_limits),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("detach machine construction failed: {error:?}"));
    complete_fixture_spawn(&mut detach_machine, 0x61);
    complete_fixture_spawn(&mut detach_machine, 0x62);
    assert!(matches!(detach_machine.step(), MachineStep::Transition(_)));
    let detach = detach_machine
        .pending_task_control()
        .and_then(|suspension| suspension.detach())
        .cloned()
        .unwrap_or_else(|| panic!("detach suspension missing"));
    assert_eq!(detach.handle.name(), "first");
    assert!(detach_machine.task_handle("first").is_none());
    assert!(detach_machine.task_handle("second").is_some());
    detach_machine
        .complete_detach(&detach)
        .unwrap_or_else(|error| panic!("detach completion failed: {error:?}"));
    assert!(matches!(
        drive(&mut detach_machine),
        MachineOutcome::Succeeded(ref value) if value == &LogicalValue::unit()
    ));
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_join_failure_becomes_task_join_failure() {
    let program = joined_int_program(
        InstructionKind::Join {
            handles: vec![Arc::from("first"), Arc::from("second")],
        },
        TypeDescriptor::list(TypeDescriptor::INT),
    );
    let machine_limits = limits(32, 1, 1, 1, 32);
    let mut machine = Machine::new_concurrent_root_with_budget_and_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        ExecutionBudget::new(execution(), machine_limits),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("join machine construction failed: {error:?}"));
    complete_fixture_spawn(&mut machine, 0x71);
    complete_fixture_spawn(&mut machine, 0x72);
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let join = machine
        .pending_task_control()
        .and_then(|suspension| suspension.join())
        .map(|(join, _)| join.clone())
        .unwrap_or_else(|| panic!("join suspension missing"));
    let first_task = join.handles[0].identity().child();
    let second_task = join.handles[1].identity().child();
    let details = TaskJoinFailureV1 {
        category: RuntimeErrorCategory::TaskJoinFailure,
        failures: vec![
            TaskJoinMemberFailureV1 {
                task_id: first_task,
                task_path: Arc::from([Arc::from("first")]),
                failure: TaskJoinMemberFailureKindV1::Cancelled(Arc::from("first-cancelled")),
            },
            TaskJoinMemberFailureV1 {
                task_id: second_task,
                task_path: Arc::from([Arc::from("second")]),
                failure: TaskJoinMemberFailureKindV1::Failed(TaskFailureV1 {
                    category: RuntimeErrorCategory::ExecutorFailure,
                    code: Arc::from("second-failed"),
                    protected_diagnostic: Some(Arc::from("diagnostic:second")),
                }),
            },
        ],
    };
    let label = machine
        .complete_join(&join, JoinResolutionV1::Failed(details.clone()))
        .unwrap_or_else(|error| panic!("join failure completion failed: {error:?}"));
    assert!(matches!(
        label,
        MachineLabel::Failure(ref failure)
            if failure.code == RuntimeCode::Operation(RuntimeErrorCategory::TaskJoinFailure)
                && failure.join_failure.as_ref() == Some(&details)
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Failed(ref failure)))
            if failure.join_failure.as_ref() == Some(&details)
    ));
    assert!(matches!(
        machine.outcome(),
        Some(MachineOutcome::Failed(failure))
            if failure.join_failure.as_ref() == Some(&details)
    ));
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn task_join_failure_details_round_trip_through_checkpoint_and_recovery() {
    let program = joined_int_program(
        InstructionKind::Join {
            handles: vec![Arc::from("first"), Arc::from("second")],
        },
        TypeDescriptor::list(TypeDescriptor::INT),
    );
    let machine_limits = limits(32, 1, 1, 1, 32);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut machine = Machine::new_concurrent_root_with_budget_and_context(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("join machine construction failed: {error:?}"));
    complete_fixture_spawn(&mut machine, 0x91);
    complete_fixture_spawn(&mut machine, 0x92);
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let join = machine
        .pending_task_control()
        .and_then(|suspension| suspension.join())
        .map(|(join, _)| join.clone())
        .unwrap_or_else(|| panic!("join suspension missing"));
    let details = TaskJoinFailureV1 {
        category: RuntimeErrorCategory::TaskJoinFailure,
        failures: join
            .handles
            .iter()
            .enumerate()
            .map(|(index, handle)| TaskJoinMemberFailureV1 {
                task_id: handle.identity().child(),
                task_path: Arc::from([Arc::from(handle.name())]),
                failure: TaskJoinMemberFailureKindV1::Cancelled(Arc::from(format!(
                    "cancelled-{index}"
                ))),
            })
            .collect(),
    };
    machine
        .complete_join(&join, JoinResolutionV1::Failed(details.clone()))
        .unwrap_or_else(|error| panic!("join failure completion failed: {error:?}"));

    let bytes = machine.checkpoint().canonical_bytes();
    let checkpoint = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("join failure checkpoint decode failed: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("join failure checkpoint recovery failed: {error:?}"));
    assert!(matches!(
        recovered.outcome(),
        Some(MachineOutcome::Failed(failure))
            if failure.join_failure.as_ref() == Some(&details)
    ));
    assert!(matches!(
        recovered.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Failed(failure)))
            if failure.join_failure.as_ref() == Some(&details)
    ));
    assert!(matches!(
        recovered.step(),
        MachineStep::Transition(MachineLabel::ForegroundCompletion(MachineOutcome::Failed(
            failure
        ))) if failure.join_failure.as_ref() == Some(&details)
    ));
    assert!(matches!(
        recovered.step(),
        MachineStep::Transition(MachineLabel::TerminalCompletion(MachineOutcome::Failed(
            failure
        ))) if failure.join_failure.as_ref() == Some(&details)
    ));
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn generalized_task_control_checkpoint_round_trips_consumed_join() {
    let program = joined_int_program(
        InstructionKind::JoinAll {
            handles: vec![Arc::from("first"), Arc::from("second")],
        },
        TypeDescriptor::list(TypeDescriptor::INT),
    );
    let machine_limits = limits(32, 1, 1, 1, 32);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let mut machine = Machine::new_concurrent_root_with_budget_and_context(
        Arc::clone(&program),
        &path("crate::main"),
        Vec::new(),
        execution(),
        machine_limits,
        budget.clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("joinall machine construction failed: {error:?}"));
    complete_fixture_spawn(&mut machine, 0x81);
    complete_fixture_spawn(&mut machine, 0x82);
    assert!(matches!(machine.step(), MachineStep::Transition(_)));

    let bytes = machine.checkpoint().canonical_bytes();
    let checkpoint = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("joinall checkpoint decode failed: {error:?}"));
    let recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("joinall checkpoint recovery failed: {error:?}"));
    assert!(recovered.task_handle("first").is_none());
    assert!(recovered.task_handle("second").is_none());
    let (join, all) = recovered
        .pending_task_control()
        .and_then(|suspension| suspension.join())
        .unwrap_or_else(|| panic!("recovered joinall suspension missing"));
    assert!(all);
    assert_eq!(
        join.handles
            .iter()
            .map(|handle| handle.name())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
}

#[cfg(feature = "concurrent")]
#[test]
fn cancelled_spawn_publication_preserves_ordinary_completion_rejection() {
    let (program, _) = spawn_program();
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let mut root = Machine::new_concurrent_root_with_budget_and_context(
        program,
        &path("crate::main"),
        vec![count],
        execution(),
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("concurrent root construction failed: {error:?}"));
    let suspension = match root.step() {
        MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn)) => spawn,
        other => panic!("unexpected spawn step: {other:?}"),
    };
    let (child_task_id, _) = child_task_coordinate();
    let handle =
        DynamicTaskHandleIdentity::from_parts(root_task_identity(execution()), child_task_id);
    assert!(root.cancel("stop").is_some());
    assert_eq!(
        root.complete_spawn(&suspension, handle),
        Err(TaskControlCompletionError::Cancelled)
    );
    assert!(matches!(
        root.complete_cancelled_spawn(&suspension, handle),
        Ok(MachineLabel::Deterministic { ref kind, .. }) if kind.as_ref() == "spawn-complete"
    ));
    assert_eq!(
        root.task_handle("child").map(|handle| handle.identity()),
        Some(handle)
    );
    assert!(root.pending_spawn().is_none());
    assert!(matches!(
        root.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Cancelled(ref reason)))
            if reason.as_ref() == "stop"
    ));
}

#[cfg(feature = "concurrent")]
#[test]
fn machine_spawn_rejects_wrong_handle_owner_and_mistyped_child_capture() {
    let (program, body_identity) = spawn_program();
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(3).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let mut root = Machine::new_concurrent_root_with_budget_and_context(
        Arc::clone(&program),
        &path("crate::main"),
        vec![count],
        execution(),
        machine_limits,
        budget.clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("concurrent root construction failed: {error:?}"));
    let suspension = match root.step() {
        MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn)) => spawn,
        other => panic!("unexpected spawn step: {other:?}"),
    };
    let (child_task_id, child_task_path) = child_task_coordinate();
    let wrong_owner = DynamicTaskHandleIdentity::from_parts(child_task_id, child_task_id);
    assert_eq!(
        root.complete_spawn(&suspension, wrong_owner),
        Err(TaskControlCompletionError::InvalidHandle)
    );
    assert_eq!(root.status(), MachineStatus::WaitingTaskControl);
    assert!(root.task_handle("child").is_none());

    let string = LogicalValue::string("wrong", DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("fixture string failed: {error:?}"));
    let wrong_capture = TaskCaptureV1::new(
        Arc::from("count"),
        TypeDescriptor::STRING,
        false,
        &string,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture capture failed: {error:?}"));
    assert!(matches!(
        Machine::new_concurrent_task_body_with_context(
            program,
            &body_identity,
            &[wrong_capture],
            execution(),
            child_task_id,
            child_task_path,
            machine_limits,
            budget,
            None,
            None,
        ),
        Err(MachineBuildError::ArgumentType)
    ));
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn task_control_checkpoint_recovers_pending_and_published_handle_state() {
    let (program, _) = spawn_program();
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(5).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let mut root = Machine::new_concurrent_root_with_budget_and_context(
        Arc::clone(&program),
        &path("crate::main"),
        vec![count],
        execution(),
        machine_limits,
        budget.clone(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("concurrent root construction failed: {error:?}"));
    let suspension = match root.step() {
        MachineStep::Transition(MachineLabel::TaskControlSuspended(spawn)) => spawn,
        other => panic!("unexpected spawn step: {other:?}"),
    };

    let pending_bytes = root.checkpoint().canonical_bytes();
    assert_eq!(pending_bytes.get(..8), Some(b"GNTMCP04".as_slice()));
    let pending_checkpoint = crate::MachineCheckpointV3::decode(&program, &pending_bytes)
        .unwrap_or_else(|error| panic!("pending checkpoint decode failed: {error:?}"));
    let mut mislabeled_v3 = pending_bytes.clone();
    mislabeled_v3[..8].copy_from_slice(b"GNTMCP03");
    assert_eq!(
        crate::MachineCheckpointV3::decode(&program, &mislabeled_v3),
        Err(crate::MachineRecoveryError::InvalidEncoding)
    );
    let mut changed_capture = pending_checkpoint.clone();
    let other_count = LogicalValue::integer(
        GantryInt::new(6).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    assert!(changed_capture.test_set_pending_spawn_capture_value(0, other_count));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &changed_capture.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
    let mut changed_agent = pending_checkpoint.clone();
    assert!(changed_agent.test_set_pending_spawn_inherited_agent(Some(Arc::from("other"))));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &changed_agent.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
    let mut changed_session = pending_checkpoint.clone();
    let other_session = ProtocolIdentity::from_fresh_material(IdentityKind::Session, [0x24; 32])
        .unwrap_or_else(|error| panic!("invalid fixture session identity: {error}"));
    assert!(changed_session.test_set_pending_spawn_parent_session(Some(other_session)));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &changed_session.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
    let mut changed_occurrence = pending_checkpoint.clone();
    assert!(
        changed_occurrence
            .test_set_pending_spawn_occurrence(suspension.occurrence.saturating_add(1))
    );
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &changed_occurrence.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));

    let mut recovered =
        Machine::recover_from_checkpoint(Arc::clone(&program), pending_checkpoint, budget.clone())
            .unwrap_or_else(|error| panic!("pending checkpoint recovery failed: {error:?}"));
    assert_eq!(recovered.status(), MachineStatus::WaitingTaskControl);
    assert_eq!(recovered.pending_spawn(), Some(&suspension));

    let (child_task_id, _) = child_task_coordinate();
    let handle =
        DynamicTaskHandleIdentity::from_parts(root_task_identity(execution()), child_task_id);
    recovered
        .complete_spawn(&suspension, handle)
        .unwrap_or_else(|error| panic!("recovered spawn completion failed: {error:?}"));
    let published_bytes = recovered.checkpoint().canonical_bytes();
    let published_checkpoint = crate::MachineCheckpointV3::decode(&program, &published_bytes)
        .unwrap_or_else(|error| panic!("published checkpoint decode failed: {error:?}"));
    let published = Machine::recover_from_checkpoint(program, published_checkpoint, budget)
        .unwrap_or_else(|error| panic!("published checkpoint recovery failed: {error:?}"));
    assert_eq!(
        published
            .task_handle("child")
            .map(|task_handle| task_handle.identity()),
        Some(handle)
    );
    assert!(published.pending_spawn().is_none());
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn task_body_shared_receiver_checkpoint_uses_the_task_body_parent_instruction() {
    let root_path = path("crate::main");
    let method_path = path("crate::Outer::value");
    let root = CanonicalCallableIdentity::free(&root_path, &[]);
    let method = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let outer = TypeDescriptor::declared(path("crate::Outer"));
    let body_identity = TaskBodyIdentity::new(root.clone(), site(0));
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::INT,
        vec![
            ExecutableTaskCapture::new(Arc::from("item"), outer.clone(), false)
                .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
        ],
        ExecutableTaskContext::v1(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::ReceiverCall {
                    callee: method.clone(),
                    arguments: 1,
                    source: ReceiverSource::CallerPlace {
                        root: Arc::from("item"),
                        path: vec![ValuePathSegment::StructField("value".to_owned())],
                        ownership: OwnershipClass::Copyable,
                    },
                },
            ),
            instruction(1, TypeDescriptor::INT, InstructionKind::TaskComplete),
        ],
    )
    .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
    let mut callables = vec![
        (
            root,
            Workflow {
                path: root_path,
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::UNIT,
                        InstructionKind::Spawn {
                            handle: ExecutableTaskHandle::new(
                                Arc::from("child"),
                                TypeDescriptor::INT,
                            )
                            .unwrap_or_else(|error| panic!("handle failed: {error:?}")),
                            body: body_identity.clone(),
                        },
                    ),
                    instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
                ],
            },
        ),
        (
            method,
            Workflow {
                path: method_path,
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
    let program = Arc::new(
        MachineProgram::with_task_bodies(callables, vec![body])
            .unwrap_or_else(|error| panic!("task-body shared receiver program failed: {error:?}")),
    );
    let item = LogicalValue::structure(
        "crate::Outer",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture outer value failed: {error:?}"));
    let capture = TaskCaptureV1::new(Arc::from("item"), outer, false, &item, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("fixture capture failed: {error:?}"));
    let machine_limits = limits(16, 1, 1, 2, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut child = Machine::new_concurrent_task_body_with_context(
        Arc::clone(&program),
        &body_identity,
        &[capture],
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("child machine construction failed: {error:?}"));
    assert!(matches!(
        child.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let bytes = child.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP05".as_slice()));
    let checkpoint = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("task-body shared checkpoint decode failed: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(child.budget_checkpoint())
        .unwrap_or_else(|error| panic!("task-body budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("task-body shared recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if value == &LogicalValue::integer(
                GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            )
    ));
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn spawned_body_operation_checkpoint_decodes_and_recovers() {
    let (program, body_identity) = spawn_program_with_body(vec![
        instruction(0, TypeDescriptor::INT, InstructionKind::Operation),
        instruction(1, TypeDescriptor::INT, InstructionKind::TaskComplete),
    ]);
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(5).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let capture = TaskCaptureV1::new(
        Arc::from("count"),
        TypeDescriptor::INT,
        false,
        &count,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture capture failed: {error:?}"));
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut child = Machine::new_concurrent_task_body_with_context(
        Arc::clone(&program),
        &body_identity,
        &[capture],
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("child machine construction failed: {error:?}"));
    let operation = match child.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("unexpected child operation step: {other:?}"),
    };

    let checkpoint = child.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("child checkpoint decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    let recovered_budget = ExecutionBudget::recover_from_checkpoint(child.budget_checkpoint())
        .unwrap_or_else(|error| panic!("child budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, decoded, recovered_budget)
        .unwrap_or_else(|error| panic!("child checkpoint recovery failed: {error:?}"));
    assert_eq!(recovered.status(), MachineStatus::WaitingOperation);
    assert!(matches!(
        recovered.complete_operation(
            operation.identity,
            LogicalValue::integer(
                GantryInt::new(9).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        ),
        Ok(MachineLabel::OperationResult { .. })
    ));
    assert!(matches!(
        recovered.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Succeeded(ref value)))
            if value == &LogicalValue::integer(
                GantryInt::new(9).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            )
    ));
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn task_body_capture_scope_recovery_validates_metadata_and_accepts_committed_writes() {
    let root_path = path("crate::main");
    let root = CanonicalCallableIdentity::free(&root_path, &[]);
    let body_identity = TaskBodyIdentity::new(root.clone(), site(0));
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::INT,
        vec![
            ExecutableTaskCapture::new(Arc::from("count"), TypeDescriptor::INT, true)
                .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
        ],
        ExecutableTaskContext::v1(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(
                    GantryInt::new(9)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                )),
            ),
            instruction(
                1,
                TypeDescriptor::INT,
                InstructionKind::Assign {
                    name: Arc::from("count"),
                    path: Vec::new(),
                    target_type: TypeDescriptor::INT,
                },
            ),
            instruction(
                2,
                TypeDescriptor::INT,
                InstructionKind::Load(Arc::from("count")),
            ),
            instruction(3, TypeDescriptor::INT, InstructionKind::TaskComplete),
        ],
    )
    .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
    let root_workflow = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::INT)
                        .unwrap_or_else(|error| panic!("handle failed: {error:?}")),
                    body: body_identity.clone(),
                },
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let program = Arc::new(
        MachineProgram::with_task_bodies(vec![(root, root_workflow)], vec![body])
            .unwrap_or_else(|error| panic!("capture-scope program failed: {error:?}")),
    );
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(5).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let capture = TaskCaptureV1::new(
        Arc::from("count"),
        TypeDescriptor::INT,
        true,
        &count,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture capture failed: {error:?}"));
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut child = Machine::new_concurrent_task_body_with_context(
        Arc::clone(&program),
        &body_identity,
        &[capture],
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("child machine construction failed: {error:?}"));

    let checkpoint = child.checkpoint();
    crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes())
        .unwrap_or_else(|error| panic!("untampered capture checkpoint failed: {error:?}"));
    for tampered in [
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_rename_task_capture("wrong"));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_task_capture_type(TypeDescriptor::BOOL));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_task_capture_mutable(false));
            checkpoint
        },
    ] {
        assert_eq!(
            crate::MachineCheckpointV3::decode(&program, &tampered.canonical_bytes()),
            Err(crate::MachineRecoveryError::ProgramMismatch)
        );
    }

    assert!(matches!(child.step(), MachineStep::Transition(_)));
    assert!(matches!(child.step(), MachineStep::Transition(_)));
    let committed = child.checkpoint();
    let budget = ExecutionBudget::recover_from_checkpoint(child.budget_checkpoint())
        .unwrap_or_else(|error| panic!("capture budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, committed, budget)
        .unwrap_or_else(|error| panic!("capture checkpoint recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if value == &LogicalValue::integer(
                GantryInt::new(9).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            )
    ));
}

#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn task_body_capture_scope_recovery_accepts_top_level_local_bindings() {
    let root_path = path("crate::main");
    let root = CanonicalCallableIdentity::free(&root_path, &[]);
    let body_identity = TaskBodyIdentity::new(root.clone(), site(0));
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::INT,
        vec![
            ExecutableTaskCapture::new(Arc::from("count"), TypeDescriptor::INT, true)
                .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
        ],
        ExecutableTaskContext::v1(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(
                    GantryInt::new(9)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                )),
            ),
            instruction(
                1,
                TypeDescriptor::INT,
                InstructionKind::Assign {
                    name: Arc::from("count"),
                    path: Vec::new(),
                    target_type: TypeDescriptor::INT,
                },
            ),
            instruction(
                2,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(
                    GantryInt::new(3)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                )),
            ),
            instruction(
                3,
                TypeDescriptor::INT,
                InstructionKind::Bind {
                    name: Arc::from("local"),
                    ty: TypeDescriptor::INT,
                    mutable: false,
                },
            ),
            instruction(
                4,
                TypeDescriptor::INT,
                InstructionKind::Load(Arc::from("count")),
            ),
            instruction(5, TypeDescriptor::INT, InstructionKind::TaskComplete),
        ],
    )
    .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
    let root_workflow = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Spawn {
                    handle: ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::INT)
                        .unwrap_or_else(|error| panic!("handle failed: {error:?}")),
                    body: body_identity.clone(),
                },
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let program = Arc::new(
        MachineProgram::with_task_bodies(vec![(root, root_workflow)], vec![body])
            .unwrap_or_else(|error| panic!("capture-scope program failed: {error:?}")),
    );
    let machine_limits = limits(16, 1, 1, 1, 16);
    let budget = ExecutionBudget::new(execution(), machine_limits);
    let count = LogicalValue::integer(
        GantryInt::new(5).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let capture = TaskCaptureV1::new(
        Arc::from("count"),
        TypeDescriptor::INT,
        true,
        &count,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture capture failed: {error:?}"));
    let (child_task_id, child_task_path) = child_task_coordinate();
    let mut child = Machine::new_concurrent_task_body_with_context(
        Arc::clone(&program),
        &body_identity,
        &[capture],
        execution(),
        child_task_id,
        child_task_path,
        machine_limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("child machine construction failed: {error:?}"));

    for _ in 0..4 {
        assert!(matches!(child.step(), MachineStep::Transition(_)));
    }

    let checkpoint = child.checkpoint();
    let decoded = crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes())
        .unwrap_or_else(|error| panic!("untampered capture checkpoint decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    for tampered in [
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_rename_task_capture("wrong"));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_task_capture_type(TypeDescriptor::BOOL));
            checkpoint
        },
        {
            let mut checkpoint = checkpoint.clone();
            assert!(checkpoint.test_set_task_capture_mutable(false));
            checkpoint
        },
    ] {
        assert_eq!(
            crate::MachineCheckpointV3::decode(&program, &tampered.canonical_bytes()),
            Err(crate::MachineRecoveryError::ProgramMismatch)
        );
    }

    let budget = ExecutionBudget::recover_from_checkpoint(child.budget_checkpoint())
        .unwrap_or_else(|error| panic!("capture budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("capture checkpoint recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(ref value)
            if value == &LogicalValue::integer(
                GantryInt::new(9).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            )
    ));
}

#[cfg(feature = "durable")]
#[test]
fn owned_move_records_place_initialization_and_recovers() {
    let main_path = path("crate::main");
    let method_path = path("crate::Token::consume");
    let token_type = TypeDescriptor::declared(path("crate::Token"));
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let method_identity = CanonicalCallableIdentity::inherent(&token_type, "consume", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let mut callables = vec![
        (
            main_identity,
            Workflow {
                path: main_path,
                parameters: vec![Parameter {
                    name: Arc::from("token"),
                    ty: token_type.clone(),
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
                            callee: method_identity.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from("token"),
                                path: Vec::new(),
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            method_identity.clone(),
            Workflow {
                path: method_path,
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: token_type.clone(),
                    mutable: true,
                    receiver_mode: Some(ReceiverMode::Owned),
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::Push(LogicalValue::integer(
                            GantryInt::new(7)
                                .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                        )),
                    ),
                    instruction(1, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
    ];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    let program = Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("owned move program failed: {error:?}")),
    );
    let token = LogicalValue::structure(
        "crate::Token",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(5).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture value failed: {error:?}"));
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token],
        limits(8, 1, 1, 2, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    let checkpoint = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("owned move checkpoint decode failed: {error:?}"));
    assert_eq!(checkpoint.canonical_bytes(), bytes);
    let mut tampered = checkpoint.clone();
    assert!(tampered.test_set_place_initialization_initialized(1, 0, true));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &tampered.canonical_bytes()),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    let mut stripped = checkpoint.clone();
    assert!(stripped.test_clear_place_initialization());
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &stripped.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("owned move budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, checkpoint, budget)
        .unwrap_or_else(|error| panic!("owned move recovery failed: {error:?}"));
    assert_eq!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted"))
        ))
    );
}

#[cfg(feature = "durable")]
#[test]
fn owned_move_checkpoint_inside_mutating_callee_recovers() {
    // The callee mutates its independent owned receiver, so `self` legitimately differs from the
    // staged caller value; the checkpoint must stay decodable and recover the mutation.
    let program = owned_move_program(
        token_parameter("token"),
        "token",
        Vec::new(),
        TypeDescriptor::INT,
        vec![
            int_push(0, 99),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Assign {
                    name: Arc::from("self"),
                    path: vec![ValuePathSegment::StructField("value".to_owned())],
                    target_type: TypeDescriptor::INT,
                },
            ),
            instruction(
                2,
                TypeDescriptor::declared(path("crate::Token")),
                InstructionKind::Load(Arc::from("self")),
            ),
            instruction(
                3,
                TypeDescriptor::INT,
                InstructionKind::Project(Projection::Field(Arc::from("value"))),
            ),
            instruction(4, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    for _ in 0..3 {
        assert!(matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
    }
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("mutating owned callee checkpoint failed: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("owned move budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(program, decoded, budget)
        .unwrap_or_else(|error| panic!("owned move recovery failed: {error:?}"));
    assert_eq!(
        drive(&mut recovered),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(99).unwrap_or_else(|| unreachable!("fixture integer is admitted"))
        ))
    );
    // An owned move never writes the independent receiver back to the caller place.
    assert_eq!(
        machine.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
    assert_eq!(
        recovered.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
}

#[cfg(feature = "durable")]
#[test]
fn owned_move_unwind_discards_staged_value_without_rollback() {
    let maximum = GantryInt::new(9_007_199_254_740_991)
        .unwrap_or_else(|| unreachable!("maximum Int is admitted"));
    let one = GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted"));
    let main_path = path("crate::main");
    let method_path = path("crate::Token::consume");
    let token_type = TypeDescriptor::declared(path("crate::Token"));
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let method_identity = CanonicalCallableIdentity::inherent(&token_type, "consume", &[])
        .unwrap_or_else(|error| panic!("method identity failed: {error}"));
    let mut callables = vec![
        (
            main_identity,
            Workflow {
                path: main_path,
                parameters: vec![Parameter {
                    name: Arc::from("token"),
                    ty: token_type.clone(),
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
                            callee: method_identity.clone(),
                            arguments: 1,
                            source: ReceiverSource::CallerPlace {
                                root: Arc::from("token"),
                                path: Vec::new(),
                                ownership: OwnershipClass::Copyable,
                            },
                        },
                    ),
                    instruction(
                        1,
                        token_type.clone(),
                        InstructionKind::Load(Arc::from("token")),
                    ),
                    instruction(
                        2,
                        TypeDescriptor::INT,
                        InstructionKind::Project(Projection::Field(Arc::from("value"))),
                    ),
                    instruction(3, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
        (
            method_identity.clone(),
            Workflow {
                path: method_path,
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: token_type.clone(),
                    mutable: true,
                    receiver_mode: Some(ReceiverMode::Owned),
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::INT,
                        InstructionKind::Push(LogicalValue::integer(
                            GantryInt::new(99)
                                .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                        )),
                    ),
                    instruction(
                        1,
                        TypeDescriptor::UNIT,
                        InstructionKind::Assign {
                            name: Arc::from("self"),
                            path: vec![ValuePathSegment::StructField("value".to_owned())],
                            target_type: TypeDescriptor::INT,
                        },
                    ),
                    instruction(
                        2,
                        TypeDescriptor::INT,
                        InstructionKind::Push(LogicalValue::integer(maximum)),
                    ),
                    instruction(
                        3,
                        TypeDescriptor::INT,
                        InstructionKind::Push(LogicalValue::integer(one)),
                    ),
                    instruction(
                        4,
                        TypeDescriptor::INT,
                        InstructionKind::Primitive(Primitive::Add),
                    ),
                    instruction(5, TypeDescriptor::INT, InstructionKind::Return),
                ],
            },
        ),
    ];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    let program = Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("owned move unwind program failed: {error:?}")),
    );
    let token = LogicalValue::structure(
        "crate::Token",
        vec![(
            "value".to_owned(),
            LogicalValue::integer(
                GantryInt::new(5).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
            ),
        )],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture value failed: {error:?}"));
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token],
        limits(16, 1, 1, 2, 16),
    );
    // Advance to the failing primitive with the receiver already mutated: the staging entry stays
    // live at the cut while the independent `self` no longer equals the staged caller value.
    for _ in 0..5 {
        assert!(matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
    }
    let cut = machine.checkpoint();
    let cut_bytes = cut.canonical_bytes();
    assert_eq!(cut_bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    assert!(crate::MachineCheckpointV3::decode(&program, &cut_bytes).is_ok());
    // The failing transition and its unwind outcome are unchanged by the staged move.
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(_))
    ));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Deterministic(DeterministicEvaluationCode::IntegerOverflow)
    ));
    // No rollback and no caller-place write-back: the caller place keeps its original value.
    assert_eq!(
        machine.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
}

/// Admission is decided before the transfer point, so a rejected owned call must leave the caller
/// place initialized and record no staging entry.
#[cfg(feature = "durable")]
#[test]
fn owned_move_admission_failure_acquires_no_staging_entry() {
    let program = owned_move_program(
        token_parameter("token"),
        "token",
        Vec::new(),
        TypeDescriptor::INT,
        vec![
            int_push(0, 7),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::WorkflowCallDepthLimit
                )
    ));
    assert_eq!(
        machine.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
    let bytes = machine.checkpoint().canonical_bytes();
    assert_ne!(
        bytes.get(..8),
        Some(b"GNTMCP06".as_slice()),
        "a rejected admission must not acquire a staging entry"
    );
    assert!(crate::MachineCheckpointV3::decode(&program, &bytes).is_ok());
}

/// Cancellation leaves the interrupted owned move consistent: the caller place keeps its original
/// value, and the terminal checkpoint still reconstructs the staged move without write-back.
#[cfg(feature = "durable")]
#[test]
fn owned_move_cancellation_retains_consistent_staging_without_write_back() {
    let program = owned_move_program(
        token_parameter("token"),
        "token",
        Vec::new(),
        TypeDescriptor::INT,
        vec![
            int_push(0, 7),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP06".as_slice()),
        "the staged move must still be live inside the callee frame"
    );
    assert!(matches!(
        machine.cancel("caller"),
        Some(MachineLabel::Cancellation { .. })
    ));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Cancelled(ref reason)))
            if reason.as_ref() == "caller"
    ));
    assert_eq!(
        machine.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Cancelled(ref reason) if reason.as_ref() == "caller"
    ));
    // The interrupted callee frame retains its staging entry, and the terminal checkpoint still
    // reconstructs every invariant of that interrupted owned move.
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP06".as_slice()));
    assert!(crate::MachineCheckpointV3::decode(&program, &bytes).is_ok());
}

/// The body shared by the owned fixture callees: push `7` and return it.
#[cfg(feature = "durable")]
fn owned_consume_body() -> Vec<Instruction> {
    vec![
        int_push(0, 7),
        instruction(1, TypeDescriptor::INT, InstructionKind::Return),
    ]
}

/// One fixture caller-place receiver call into the fixture `crate::Token` method.
#[cfg(feature = "durable")]
fn receiver_call(site_index: u64, callee: &CanonicalCallableIdentity, root: &str) -> Instruction {
    receiver_call_at_path(site_index, callee, root, Vec::new())
}

/// One fixture caller-place receiver call with an explicit subplace path.
#[cfg(feature = "durable")]
fn receiver_call_at_path(
    site_index: u64,
    callee: &CanonicalCallableIdentity,
    root: &str,
    path: Vec<ValuePathSegment>,
) -> Instruction {
    instruction(
        site_index,
        TypeDescriptor::INT,
        InstructionKind::ReceiverCall {
            callee: callee.clone(),
            arguments: 1,
            source: ReceiverSource::CallerPlace {
                root: Arc::from(root),
                path,
                ownership: OwnershipClass::Copyable,
            },
        },
    )
}

/// Builds a program whose `crate::main` drives caller-place receiver calls into fixture
/// `crate::Token` methods, so caller-frame moved-out marks can be exercised end to end.
#[cfg(feature = "durable")]
fn affine_call_program<F>(
    main_parameters: Vec<Parameter>,
    main_result: TypeDescriptor,
    methods: Vec<(&str, ReceiverMode, Vec<Instruction>)>,
    build_main: F,
) -> Arc<MachineProgram>
where
    F: FnOnce(&[CanonicalCallableIdentity]) -> Vec<Instruction>,
{
    let main_path = path("crate::main");
    let token_type = TypeDescriptor::declared(path("crate::Token"));
    let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
    let identities = methods
        .iter()
        .map(|(name, _, _)| {
            CanonicalCallableIdentity::inherent(&token_type, name, &[])
                .unwrap_or_else(|error| panic!("fixture method identity failed: {error}"))
        })
        .collect::<Vec<_>>();
    let mut callables = vec![(
        main_identity,
        Workflow {
            path: main_path,
            parameters: main_parameters,
            result: main_result,
            effects: EffectSet::default(),
            instructions: build_main(&identities),
        },
    )];
    for ((name, mode, body), identity) in methods.into_iter().zip(identities) {
        callables.push((
            identity,
            Workflow {
                path: path(&format!("crate::Token::{name}")),
                parameters: vec![Parameter {
                    name: Arc::from("self"),
                    ty: token_type.clone(),
                    mutable: matches!(mode, ReceiverMode::Owned | ReceiverMode::ExclusivePlace),
                    receiver_mode: Some(mode),
                }],
                result: TypeDescriptor::INT,
                effects: EffectSet::default(),
                instructions: body,
            },
        ));
    }
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    Arc::new(
        MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("fixture affine call program failed: {error:?}")),
    )
}

/// `crate::main` moves out `token` and then `other`, then reads the moved-out place.
#[cfg(feature = "durable")]
fn two_place_owned_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token"), token_parameter("other")],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                receiver_call(1, &identities[0], "other"),
                instruction(
                    2,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Load(Arc::from("token")),
                ),
                instruction(
                    3,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(4, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// `crate::main` moves out `token` and then reads it without writing it back.
#[cfg(feature = "durable")]
fn owned_then_load_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token")],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                instruction(
                    1,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Load(Arc::from("token")),
                ),
                instruction(
                    2,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(3, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// `crate::main` reinitializes the moved-out place before reading it again.
#[cfg(feature = "durable")]
fn assign_after_owned_move_program() -> Arc<MachineProgram> {
    let token_type = TypeDescriptor::declared(path("crate::Token"));
    affine_call_program(
        vec![Parameter {
            name: Arc::from("token"),
            ty: token_type.clone(),
            mutable: true,
            receiver_mode: None,
        }],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                instruction(
                    1,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Push(token_value(3)),
                ),
                instruction(
                    2,
                    TypeDescriptor::UNIT,
                    InstructionKind::Assign {
                        name: Arc::from("token"),
                        path: Vec::new(),
                        target_type: TypeDescriptor::declared(path("crate::Token")),
                    },
                ),
                instruction(
                    3,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Load(Arc::from("token")),
                ),
                instruction(
                    4,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(5, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// `crate::main` moves out `token` twice through the same owned method.
#[cfg(feature = "durable")]
fn repeat_owned_call_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token")],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                receiver_call(1, &identities[0], "token"),
                instruction(2, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// `crate::main` moves out `token` and then admits it again as a shared receiver place.
#[cfg(feature = "durable")]
fn shared_after_owned_call_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token")],
        TypeDescriptor::INT,
        vec![
            ("consume", ReceiverMode::Owned, owned_consume_body()),
            (
                "inspect",
                ReceiverMode::SharedPlace,
                vec![
                    instruction(
                        0,
                        TypeDescriptor::declared(path("crate::Token")),
                        InstructionKind::Load(Arc::from("self")),
                    ),
                    instruction(
                        1,
                        TypeDescriptor::INT,
                        InstructionKind::Project(Projection::Field(Arc::from("value"))),
                    ),
                    instruction(2, TypeDescriptor::INT, InstructionKind::Return),
                ],
            ),
        ],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                receiver_call(1, &identities[1], "token"),
                instruction(2, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// `crate::main` moves out `token` and is then interrupted while staging the move of `other`.
#[cfg(feature = "durable")]
fn staged_after_moved_out_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token"), token_parameter("other")],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                receiver_call(1, &identities[0], "other"),
                instruction(2, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// Advances a fixture machine through `count` successful deterministic transitions.
#[cfg(feature = "durable")]
fn step_deterministic(machine: &mut Machine, count: usize) {
    for _ in 0..count {
        assert!(matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::Deterministic { .. })
        ));
    }
}

/// The V7 moved-out section is written last, so the bytes from its magic to the end of the
/// checkpoint are exactly that section. These helpers rebuild it byte for byte so the codec
/// negatives below exercise real encodings; every fixture uses empty canonical paths, which keeps
/// the test-local section writer trivial.
#[cfg(feature = "durable")]
const MOVED_OUT_SECTION_MAGIC: &[u8] = b"GNTRMO01";

#[cfg(feature = "durable")]
fn section_offset(bytes: &[u8], magic: &[u8]) -> usize {
    bytes
        .windows(magic.len())
        .position(|window| window == magic)
        .unwrap_or_else(|| panic!("checkpoint must carry the {magic:?} section"))
}

#[cfg(feature = "durable")]
fn moved_out_section(frame_count: u64, frames: &[Vec<&str>]) -> Vec<u8> {
    let mut section = MOVED_OUT_SECTION_MAGIC.to_vec();
    section.extend_from_slice(&frame_count.to_be_bytes());
    for frame in frames {
        section.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        for root in frame {
            section.extend_from_slice(&(root.len() as u64).to_be_bytes());
            section.extend_from_slice(root.as_bytes());
            section.extend_from_slice(&0_u64.to_be_bytes());
        }
    }
    section
}

#[cfg(feature = "durable")]
fn resplice_moved_out_section(bytes: &[u8], section: &[u8]) -> Vec<u8> {
    let offset = section_offset(bytes, MOVED_OUT_SECTION_MAGIC);
    let mut rewritten = bytes[..offset].to_vec();
    rewritten.extend_from_slice(section);
    rewritten
}

/// Resource-origin correspondence must not substitute another executable body at the same task.
#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn resource_origin_correspondence_rejects_substituted_task_bodies() {
    let action_path = path("crate::action");
    let operation = ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::INT,
        action: Some(ExecutableAction {
            path: action_path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &action_path,
                &[],
                &TypeDescriptor::INT,
            ),
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    };
    let instructions = vec![
        instruction(
            0,
            TypeDescriptor::INT,
            InstructionKind::OperationCall {
                operation,
                operands: 0,
            },
        ),
        instruction(1, TypeDescriptor::INT, InstructionKind::TaskComplete),
    ];
    let (base, first_identity) = spawn_program_with_body(instructions.clone());
    let caller = CanonicalCallableIdentity::free(&path("crate::main"), &[]);
    let second_identity = TaskBodyIdentity::new(caller.clone(), site(1));
    let mut bodies = base.task_bodies().to_vec();
    bodies.push(
        ExecutableTaskBody::new(
            second_identity.clone(),
            TypeDescriptor::INT,
            bodies[0].captures().to_vec(),
            ExecutableTaskContext::v1(),
            instructions,
        )
        .unwrap_or_else(|error| panic!("second body: {error:?}")),
    );
    let mut root = base.workflows()[0].clone();
    root.instructions[1] = instruction(
        1,
        TypeDescriptor::UNIT,
        InstructionKind::Spawn {
            handle: ExecutableTaskHandle::new(Arc::from("other"), TypeDescriptor::INT)
                .unwrap_or_else(|error| panic!("handle: {error:?}")),
            body: second_identity.clone(),
        },
    );
    let program = Arc::new(
        MachineProgram::with_task_bodies(vec![(caller, root)], bodies)
            .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let count = LogicalValue::integer(GantryInt::new(5).unwrap_or_else(|| panic!("integer")));
    let capture = TaskCaptureV1::new(
        Arc::from("count"),
        TypeDescriptor::INT,
        false,
        &count,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("capture: {error:?}"));
    let machine_limits = limits(16, 4, 1, 1, 16);
    let (task, task_path) = child_task_coordinate();
    let make = |identity| {
        let mut machine = Machine::new_concurrent_task_body_with_context(
            Arc::clone(&program),
            identity,
            std::slice::from_ref(&capture),
            execution(),
            task,
            Arc::clone(&task_path),
            machine_limits,
            ExecutionBudget::new(execution(), machine_limits),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
        assert!(matches!(
            machine.step(),
            MachineStep::Transition(MachineLabel::OperationPrepared(_))
        ));
        let checkpoint = machine.checkpoint();
        let decoded = crate::MachineCheckpointV3::decode(&program, &checkpoint.canonical_bytes())
            .unwrap_or_else(|error| panic!("checkpoint must independently validate: {error:?}"));
        assert_eq!(decoded, checkpoint);
        checkpoint
    };
    let origin = make(&first_identity);
    let retained = make(&second_identity);
    assert!(origin.retains_resource_origin(&origin));
    assert!(
        !retained.retains_resource_origin(&origin),
        "matching task coordinates and generation cannot substitute an executable task body"
    );
}

/// Pending action checkpoints cannot omit or reuse a resource-generation ordinal.
#[cfg(feature = "durable")]
#[test]
fn pending_action_checkpoint_rejects_missing_or_future_resource_generation() {
    let action_path = path("crate::action");
    let operation = ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(ExecutableAction {
            path: action_path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &action_path,
                &[],
                &TypeDescriptor::UNIT,
            ),
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    };
    let program = program(vec![workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::OperationCall {
                    operation,
                    operands: 0,
                },
            ),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    )]);
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("action budget recovery failed: {error:?}"));

    let subject = machine
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("authenticated action has a subject"));
    let recovered = Machine::recover_from_checkpoint(
        Arc::clone(&program),
        machine.checkpoint(),
        budget.clone(),
    )
    .unwrap_or_else(|error| panic!("untampered action checkpoint must recover: {error:?}"));
    assert_eq!(recovered.pending_resource_subject(), Some(subject));

    let mut missing_generation = machine.checkpoint();
    assert!(missing_generation.test_set_resource_generation(None));
    let origin_record = gantry_ir::ResourceLedger::new(
        gantry_ir::OwnerGeneration::new(4),
        gantry_ir::ResourceState::Usable,
        &[gantry_ir::LivenessRoot::Resource],
        &[],
    )
    .unwrap_or_else(|error| panic!("origin ledger: {error:?}"))
    .durable_record();
    assert!(matches!(
        crate::RecoveredResourceRecord::from_issuing_checkpoint(
            Arc::clone(&program),
            missing_generation.clone(),
            machine.budget_checkpoint(),
            gantry_ir::ResourceCarrier::ReconstructionRecord,
            gantry_ir::OwnerGeneration::new(4),
            origin_record.clone(),
        ),
        Err(crate::ResourceOriginRecoveryError::Machine(_))
    ));
    let missing_recovery =
        Machine::recover_from_checkpoint(Arc::clone(&program), missing_generation, budget.clone());
    assert!(
        missing_recovery.is_err(),
        "a pending action must retain its generation ordinal: {missing_recovery:?}"
    );

    let mut future_generation = machine.checkpoint();
    assert!(future_generation.test_set_resource_generation(Some(budget.snapshot().revision)));
    assert_eq!(
        crate::RecoveredResourceRecord::from_issuing_checkpoint(
            Arc::clone(&program),
            future_generation.clone(),
            machine.budget_checkpoint(),
            gantry_ir::ResourceCarrier::ReconstructionRecord,
            gantry_ir::OwnerGeneration::new(4),
            origin_record,
        )
        .err(),
        Some(crate::ResourceOriginRecoveryError::Machine(
            crate::MachineRecoveryError::InvalidCheckpoint
        ))
    );
    assert!(
        matches!(
            Machine::recover_from_checkpoint(program, future_generation, budget),
            Err(crate::MachineRecoveryError::InvalidCheckpoint)
        ),
        "an ordinal at the budget frontier cannot be reused as an allocation"
    );
}

/// A speculative terminal transition cannot close the authoritative pending resource lease.
#[cfg(feature = "durable")]
#[test]
fn speculative_resource_admission_closes_only_when_the_transition_commits() {
    let action_path = path("crate::action");
    let operation = ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(ExecutableAction {
            path: action_path.clone(),
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &action_path,
                &[],
                &TypeDescriptor::UNIT,
            ),
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    };
    let program = program(vec![workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::OperationCall {
                operation,
                operands: 0,
            },
        )],
    )]);
    let mut authoritative = new_machine(
        Arc::clone(&program),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        authoritative.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let subject = authoritative
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("pending action has a resource subject"));
    let operation = authoritative
        .checkpoint()
        .pending_operation()
        .unwrap_or_else(|| panic!("pending action retains its occurrence"))
        .identity;

    let (mut cancelled_stage, cancelled_guard) = authoritative.clone_durable_projection();
    assert!(cancelled_stage.cancel("speculative cancellation").is_some());
    assert_eq!(
        subject
            .lock_admission()
            .map(|lease| (lease.pending, lease.cancellation_requested)),
        Some((true, false)),
        "uncommitted cancellation cannot revoke authoritative admission"
    );
    drop(cancelled_stage);
    drop(cancelled_guard);
    assert_eq!(
        subject
            .lock_admission()
            .map(|lease| (lease.pending, lease.cancellation_requested)),
        Some((true, false)),
        "rollback preserves both authoritative lease facts"
    );

    let (mut rolled_back, rolled_back_guard) = authoritative.clone_durable_projection();
    let rolled_back_subject = rolled_back
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("projected pending action has a resource subject"));
    rolled_back
        .fail_operation_with_code(operation, RuntimeCode::InternalInvariant)
        .unwrap_or_else(|error| panic!("staged operation failure succeeds: {error:?}"));
    assert_eq!(
        subject.lock_admission().map(|lease| lease.pending),
        Some(true),
        "a speculative terminal transition uses an isolated lease"
    );
    drop(rolled_back);
    drop(rolled_back_guard);
    assert_eq!(
        rolled_back_subject
            .lock_admission()
            .map(|lease| lease.pending),
        Some(false),
        "dropping an uncommitted projection revokes its escaped subject"
    );
    assert_eq!(
        subject.lock_admission().map(|lease| lease.pending),
        Some(true),
        "dropping an uncommitted projection preserves admission"
    );

    let (mut committed, mut committed_guard) = authoritative.clone_durable_projection();
    committed
        .fail_operation_with_code(operation, RuntimeCode::InternalInvariant)
        .unwrap_or_else(|error| panic!("staged operation failure succeeds: {error:?}"));
    authoritative.commit_staged_resource_admission(&mut committed);
    if let Some(guard) = committed_guard.as_mut() {
        guard.disarm();
    }
    assert_eq!(
        subject.lock_admission().map(|lease| lease.pending),
        Some(false),
        "publishing the staged terminal transition closes saved subjects"
    );
    let mut pending = new_machine(
        Arc::clone(&program),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert!(matches!(
        pending.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    let subject = pending
        .pending_resource_subject()
        .unwrap_or_else(|| panic!("pending subject"));
    let (mut cancelled, mut guard) = pending.clone_durable_projection();
    assert!(cancelled.cancel("committed cancellation").is_some());
    pending.commit_staged_resource_admission(&mut cancelled);
    if let Some(guard) = guard.as_mut() {
        guard.disarm();
    }
    assert_eq!(
        subject
            .lock_admission()
            .map(|lease| (lease.pending, lease.cancellation_requested)),
        Some((true, true)),
        "published cancellation closes acquisition but retains pending capacity"
    );
    assert!(matches!(
        cancelled.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(_))
    ));
    assert_eq!(
        subject.lock_admission().map(|lease| lease.pending),
        Some(false)
    );
    for settled in [false, true] {
        let mut authoritative = new_machine(
            Arc::clone(&program),
            "crate::main",
            Vec::new(),
            limits(8, 1, 1, 1, 8),
        );
        assert!(matches!(
            authoritative.step(),
            MachineStep::Transition(MachineLabel::OperationPrepared(_))
        ));
        let subject = authoritative
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("pending subject"));
        let (mut staged, mut guard) = authoritative.clone_durable_projection();
        let mut shared = authoritative.clone();
        assert!(shared.cancel("shared lease revocation").is_some());
        if settled {
            assert!(matches!(
                shared.step(),
                MachineStep::Transition(MachineLabel::TaskSettled(_))
            ));
        }
        authoritative.commit_staged_resource_admission(&mut staged);
        if let Some(guard) = guard.as_mut() {
            guard.disarm();
        }
        assert_eq!(
            subject
                .lock_admission()
                .map(|lease| (lease.pending, lease.cancellation_requested)),
            Some((!settled, true)),
            "staged publication must not reopen a revoked shared lease"
        );
    }
}

/// A normal owned return marks the caller place durably, and the mark survives recovery.
#[cfg(feature = "durable")]
#[test]
fn owned_move_return_marks_caller_place_and_recovers() {
    let program = two_place_owned_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5), token_value(9)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 3);
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP07".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("moved-out checkpoint decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("moved-out budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(Arc::clone(&program), decoded, budget)
        .unwrap_or_else(|error| panic!("moved-out recovery failed: {error:?}"));
    // An owned call on the untouched affine place still succeeds, and the following read of the
    // moved-out place is refused as an internal invariant violation.
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Failed(failure)
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(2)
    ));
    // The transfer is a logical discard: the caller bindings keep their original values.
    assert_eq!(
        machine.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
    assert_eq!(
        machine.test_frame_binding_value(0, "other"),
        Some(token_value(9))
    );
    assert_eq!(
        recovered.test_frame_binding_value(0, "token"),
        Some(token_value(5))
    );
    assert_eq!(
        recovered.test_frame_binding_value(0, "other"),
        Some(token_value(9))
    );
}

/// A read of the moved-out place fails until an assignment makes it readable again.
#[cfg(feature = "durable")]
#[test]
fn owned_move_blocks_load_until_the_place_is_assigned() {
    let program = owned_then_load_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 3);
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP07".as_slice())
    );
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Failed(failure)
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(1)
    ));

    // Reassigning the place clears the mark, so the read succeeds and the checkpoint no longer
    // selects the moved-out wire form.
    let program = assign_after_owned_move_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 5);
    assert_eq!(
        machine.test_frame_binding_value(0, "token"),
        Some(token_value(3))
    );
    let bytes = machine.checkpoint().canonical_bytes();
    assert_ne!(
        bytes.get(..8),
        Some(b"GNTMCP07".as_slice()),
        "an assigned place is no longer moved out"
    );
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("reinitialized checkpoint decode failed: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("reinitialized budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(Arc::clone(&program), decoded, budget)
        .unwrap_or_else(|error| panic!("reinitialized recovery failed: {error:?}"));
    let expected = MachineOutcome::Succeeded(LogicalValue::integer(
        GantryInt::new(3).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    ));
    assert_eq!(drive(&mut recovered), expected);
    assert_eq!(drive(&mut machine), expected);
}

/// A second owned call, or a shared receiver call, on the moved-out place fails closed.
#[cfg(feature = "durable")]
#[test]
fn owned_move_blocks_second_admission_of_the_moved_out_place() {
    let program = repeat_owned_call_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 3);
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP07".as_slice())
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(1)
    ));

    let program = shared_after_owned_call_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 3);
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP07".as_slice())
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(1)
    ));
}

/// The moved-out section round-trips deterministically and rejects malformed encodings.
#[cfg(feature = "durable")]
#[test]
fn moved_out_section_rejects_malformed_encodings() {
    let program = two_place_owned_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5), token_value(9)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 6);
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP07".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("moved-out section decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    let offset = section_offset(&bytes, MOVED_OUT_SECTION_MAGIC);
    assert_eq!(&bytes[offset..offset + 8], MOVED_OUT_SECTION_MAGIC);

    // Truncated section.
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &bytes[..offset + 12]),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Missing section.
    let mut missing = bytes.clone();
    missing[offset..offset + MOVED_OUT_SECTION_MAGIC.len()].copy_from_slice(b"GNTRMO02");
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &missing),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Corrupted frame count.
    let miscounted =
        resplice_moved_out_section(&bytes, &moved_out_section(2, &[vec!["other", "token"]]));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &miscounted),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Corrupted entry count.
    let mut bogus = MOVED_OUT_SECTION_MAGIC.to_vec();
    bogus.extend_from_slice(&1_u64.to_be_bytes());
    bogus.extend_from_slice(&u64::MAX.to_be_bytes());
    let bogus = resplice_moved_out_section(&bytes, &bogus);
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &bogus),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Duplicated entry.
    let duplicated = resplice_moved_out_section(
        &bytes,
        &moved_out_section(1, &[vec!["other", "token", "token"]]),
    );
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &duplicated),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Reordered entries.
    let reordered =
        resplice_moved_out_section(&bytes, &moved_out_section(1, &[vec!["token", "other"]]));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &reordered),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Empty root.
    let empty_root =
        resplice_moved_out_section(&bytes, &moved_out_section(1, &[vec!["", "other"]]));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &empty_root),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Duplicated section.
    let mut doubled = moved_out_section(1, &[vec!["other", "token"]]);
    let copy = doubled.clone();
    doubled.extend_from_slice(&copy);
    let doubled = resplice_moved_out_section(&bytes, &doubled);
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &doubled),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

/// A well-formed moved-out entry without a justifying executed owned call is a program mismatch.
#[cfg(feature = "durable")]
#[test]
fn moved_out_entry_without_owned_call_is_program_mismatch() {
    let (program, machine) = place_initialization_fixture();
    let mut forged = machine.checkpoint();
    assert!(forged.test_add_moved_out(0, "item", Vec::new()));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &forged.canonical_bytes()),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
}

/// The moved-out mark takes precedence over a live staging entry and keeps its section last.
#[cfg(feature = "durable")]
#[test]
fn moved_out_section_follows_the_staged_move_section() {
    let program = staged_after_moved_out_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5), token_value(9)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 4);
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(
        bytes.get(..8),
        Some(b"GNTMCP07".as_slice()),
        "a moved-out mark takes precedence over a live staging entry"
    );
    let staged = section_offset(&bytes, b"GNTSTG01");
    let moved = section_offset(&bytes, MOVED_OUT_SECTION_MAGIC);
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes);
    assert!(
        decoded.is_ok(),
        "staged and moved-out checkpoint must decode: {:?}",
        decoded.err()
    );
    assert!(staged < moved);
    let mut swapped = bytes[..staged].to_vec();
    swapped.extend_from_slice(&bytes[moved..]);
    swapped.extend_from_slice(&bytes[staged..moved]);
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &swapped),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
}

/// The V8 staged-place-origin section is written last, so the bytes from its magic to the end of
/// the checkpoint are exactly that section. These helpers rebuild it byte for byte so the codec
/// negatives below exercise real encodings; the fixtures used here record empty canonical paths,
/// which keeps the test-local section writer trivial.
#[cfg(feature = "durable")]
const PLACE_ORIGINS_SECTION_MAGIC: &[u8] = b"GNTLOA01";

#[cfg(feature = "durable")]
fn place_origins_section(entries: &[Option<&str>]) -> Vec<u8> {
    let mut section = PLACE_ORIGINS_SECTION_MAGIC.to_vec();
    section.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        match entry {
            None => section.push(0),
            Some(root) => {
                section.push(1);
                section.extend_from_slice(&(root.len() as u64).to_be_bytes());
                section.extend_from_slice(root.as_bytes());
                section.extend_from_slice(&0_u64.to_be_bytes());
            }
        }
    }
    section
}

#[cfg(feature = "durable")]
fn resplice_place_origins_section(bytes: &[u8], section: &[u8]) -> Vec<u8> {
    let offset = section_offset(bytes, PLACE_ORIGINS_SECTION_MAGIC);
    let mut rewritten = bytes[..offset].to_vec();
    rewritten.extend_from_slice(section);
    rewritten
}

/// A checkpoint taken between `Load` and `Project` while a moved-out mark is live records the
/// staged place origin, so the resumed machine still refuses the projection of the moved-out
/// subplace instead of serving the stale pre-move value.
#[cfg(feature = "durable")]
#[test]
fn staged_origin_survives_recovery_and_guards_projection() {
    let program = partial_move_token_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    // Four transitions complete the owned move and the fifth loads the enclosing `holder` place,
    // so the checkpoint sits strictly between that `Load` and the following `Project`.
    step_deterministic(&mut machine, 5);
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("staged-origin checkpoint decode failed: {error:?}"));
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("staged-origin budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(Arc::clone(&program), decoded, budget)
        .unwrap_or_else(|error| panic!("staged-origin recovery failed: {error:?}"));
    // The recovered guard still fires at the projection of the moved-out subplace. Without the
    // origin list in the checkpoint the resumed machine served the stale pre-move value here.
    assert!(
        matches!(
            drive(&mut recovered),
            MachineOutcome::Failed(failure)
                if failure.code == RuntimeCode::InternalInvariant && failure.site == site(2)
        ),
        "a recovered machine must refuse the projection of a moved-out subplace"
    );
    assert_eq!(
        bytes.get(..8),
        Some(b"GNTMCP08".as_slice()),
        "a recorded staged origin selects the V8 wire form"
    );
    // The uninterrupted machine fails at the same site, so the cut is faithful.
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Failed(failure)
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(2)
    ));
}

/// A V8 checkpoint carrying staged place origins round-trips canonically, keeps its origin section
/// last, and recovers both the guard and a surviving-sibling projection.
#[cfg(feature = "durable")]
#[test]
fn staged_origin_section_round_trips() {
    let program = partial_move_token_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 5);
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP08".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("staged-origin round-trip decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    // The origin section is present exactly once and last, and it records the loaded `holder`
    // origin above the callee result that carries no origin.
    let origins = section_offset(&bytes, PLACE_ORIGINS_SECTION_MAGIC);
    let expected = place_origins_section(&[None, Some("holder")]);
    assert_eq!(&bytes[origins..], expected.as_slice());
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("staged-origin budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(Arc::clone(&program), decoded, budget)
        .unwrap_or_else(|error| panic!("staged-origin recovery failed: {error:?}"));
    assert!(matches!(
        drive(&mut recovered),
        MachineOutcome::Failed(failure)
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(2)
    ));
}

/// A projected origin path round-trips, and the recovered machine still reads a surviving sibling
/// of a partial move.
#[cfg(feature = "durable")]
#[test]
fn staged_origin_path_round_trips_for_a_surviving_sibling() {
    let program = partial_move_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    // The sixth transition projects the surviving sibling `holder.marker`, so the recorded origin
    // carries a non-empty canonical path above the live `holder.token` moved-out mark.
    step_deterministic(&mut machine, 6);
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP08".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("staged-origin path decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("staged-origin path budget recovery failed: {error:?}"));
    let mut recovered = Machine::recover_from_checkpoint(Arc::clone(&program), decoded, budget)
        .unwrap_or_else(|error| panic!("staged-origin path recovery failed: {error:?}"));
    let expected = MachineOutcome::Succeeded(LogicalValue::integer(
        GantryInt::new(10).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    ));
    assert_eq!(drive(&mut recovered), expected);
    assert_eq!(drive(&mut machine), expected);
}

/// The staged-place-origin section rejects malformed encodings, and a declared count that does not
/// match the staged values is a program mismatch rather than an encoding error.
#[cfg(feature = "durable")]
#[test]
fn staged_origin_section_rejects_malformed_encodings() {
    let program = partial_move_token_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 5);
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP08".as_slice()));
    let offset = section_offset(&bytes, PLACE_ORIGINS_SECTION_MAGIC);

    // Truncated section.
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &bytes[..offset + 12]),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Missing section.
    let mut missing = bytes.clone();
    missing[offset..offset + PLACE_ORIGINS_SECTION_MAGIC.len()].copy_from_slice(b"GNTLOA02");
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &missing),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Duplicated section: the mandatory origin section must be last, so trailing bytes fail.
    let mut doubled = bytes.clone();
    doubled.extend_from_slice(&place_origins_section(&[None, Some("holder")]));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &doubled),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // Empty root in a present origin.
    let empty_root =
        resplice_place_origins_section(&bytes, &place_origins_section(&[None, Some("")]));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &empty_root),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    ));
    // A declared count that disagrees with the staged values.
    let miscounted =
        resplice_place_origins_section(&bytes, &place_origins_section(&[Some("holder")]));
    assert!(matches!(
        crate::MachineCheckpointV3::decode(&program, &miscounted),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    ));
}

/// A machine with no recorded place origin never selects the V8 wire form.
#[cfg(feature = "durable")]
#[test]
fn staged_origin_section_stays_absent_without_a_load() {
    // A live moved-out mark without a staged load keeps the V7 wire form.
    let program = partial_move_token_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 4);
    let moved_out = machine.checkpoint().canonical_bytes();
    assert_eq!(moved_out.get(..8), Some(b"GNTMCP07".as_slice()));
    assert!(
        moved_out
            .windows(PLACE_ORIGINS_SECTION_MAGIC.len())
            .all(|window| window != PLACE_ORIGINS_SECTION_MAGIC),
        "the V7 wire form must not carry the origin section"
    );

    // A live staging entry without a staged load keeps the V6 wire form.
    let program = owned_move_program(
        token_parameter("token"),
        "token",
        Vec::new(),
        TypeDescriptor::INT,
        vec![
            int_push(0, 7),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP06".as_slice())
    );
}

/// A `crate::Holder` fixture value with the given `token.value` and `marker`.
#[cfg(feature = "durable")]
fn holder_value(token: i64, marker: i64) -> LogicalValue {
    LogicalValue::structure(
        "crate::Holder",
        vec![
            ("token".to_owned(), token_value(token)),
            (
                "marker".to_owned(),
                LogicalValue::integer(
                    GantryInt::new(marker)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                ),
            ),
        ],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture holder value failed: {error:?}"))
}

/// `crate::main` partially moves `holder.token` out, then reads the surviving sibling `marker`.
#[cfg(feature = "durable")]
fn partial_move_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![Parameter {
            name: Arc::from("holder"),
            ty: TypeDescriptor::declared(path("crate::Holder")),
            mutable: false,
            receiver_mode: None,
        }],
        TypeDescriptor::INT,
        vec![(
            "consume",
            ReceiverMode::Owned,
            vec![
                instruction(
                    0,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Load(Arc::from("self")),
                ),
                instruction(
                    1,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(2, TypeDescriptor::INT, InstructionKind::Return),
            ],
        )],
        |identities| {
            vec![
                receiver_call_at_path(
                    0,
                    &identities[0],
                    "holder",
                    vec![ValuePathSegment::StructField("token".to_owned())],
                ),
                instruction(
                    1,
                    TypeDescriptor::declared(path("crate::Holder")),
                    InstructionKind::Load(Arc::from("holder")),
                ),
                instruction(
                    2,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("marker"))),
                ),
                instruction(
                    3,
                    TypeDescriptor::INT,
                    InstructionKind::Primitive(Primitive::Add),
                ),
                instruction(4, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// A partial move keeps the enclosing place readable for its surviving sibling subplaces.
#[cfg(feature = "durable")]
#[test]
fn owned_move_allows_reading_surviving_siblings_of_a_partial_move() {
    let program = partial_move_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    // The fixture callee loads, projects, and returns, so the caller place is marked by step four.
    step_deterministic(&mut machine, 4);
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP07".as_slice()));
    assert!(crate::MachineCheckpointV3::decode(&program, &bytes).is_ok());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(10).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ))
    );
}

/// Builds a spawn fixture whose root first moves the captured place out through an owned call.
#[cfg(all(feature = "concurrent", feature = "durable"))]
fn moved_out_capture_program() -> Arc<MachineProgram> {
    let root_path = path("crate::main");
    let caller = CanonicalCallableIdentity::free(&root_path, &[]);
    let body_identity = TaskBodyIdentity::new(caller.clone(), site(1));
    let body = ExecutableTaskBody::new(
        body_identity.clone(),
        TypeDescriptor::INT,
        vec![
            ExecutableTaskCapture::new(Arc::from("count"), TypeDescriptor::INT, false)
                .unwrap_or_else(|error| panic!("invalid fixture capture: {error:?}")),
        ],
        ExecutableTaskContext::v1(),
        vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Load(Arc::from("count")),
            ),
            instruction(1, TypeDescriptor::INT, InstructionKind::TaskComplete),
        ],
    )
    .unwrap_or_else(|error| panic!("invalid fixture task body: {error:?}"));
    let handle = ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::INT)
        .unwrap_or_else(|error| panic!("invalid fixture handle: {error:?}"));
    let consume = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "consume", &[])
        .unwrap_or_else(|error| panic!("fixture method identity failed: {error}"));
    let root = Workflow {
        path: root_path,
        parameters: vec![Parameter {
            name: Arc::from("count"),
            ty: TypeDescriptor::INT,
            mutable: false,
            receiver_mode: None,
        }],
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::ReceiverCall {
                    callee: consume.clone(),
                    arguments: 1,
                    source: ReceiverSource::CallerPlace {
                        root: Arc::from("count"),
                        path: Vec::new(),
                        ownership: OwnershipClass::Copyable,
                    },
                },
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Spawn {
                    handle,
                    body: body_identity.clone(),
                },
            ),
            instruction(
                2,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    };
    let callee = Workflow {
        path: path("crate::Int::consume"),
        parameters: vec![Parameter {
            name: Arc::from("self"),
            ty: TypeDescriptor::INT,
            mutable: true,
            receiver_mode: Some(ReceiverMode::Owned),
        }],
        result: TypeDescriptor::INT,
        effects: EffectSet::default(),
        instructions: vec![
            instruction(
                0,
                TypeDescriptor::INT,
                InstructionKind::Push(LogicalValue::integer(
                    GantryInt::new(7)
                        .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                )),
            ),
            instruction(1, TypeDescriptor::INT, InstructionKind::Return),
        ],
    };
    let mut callables = vec![(caller, root), (consume, callee)];
    callables.sort_by(|left, right| left.0.cmp(&right.0));
    Arc::new(
        MachineProgram::with_task_bodies(callables, vec![body])
            .unwrap_or_else(|error| panic!("moved-out capture program failed: {error:?}")),
    )
}

/// A task capture reads the caller frame, so capturing a moved-out place fails closed.
#[cfg(all(feature = "concurrent", feature = "durable"))]
#[test]
fn capture_of_a_moved_out_place_is_an_invariant_violation() {
    let program = moved_out_capture_program();
    let token = LogicalValue::integer(
        GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token.clone()],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 3);
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP07".as_slice())
    );
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(1)
    ));
    assert_eq!(machine.test_frame_binding_value(0, "count"), Some(token));
}

/// `crate::main` partially moves `holder.token` out and then projects that very subplace.
#[cfg(feature = "durable")]
fn partial_move_token_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![Parameter {
            name: Arc::from("holder"),
            ty: TypeDescriptor::declared(path("crate::Holder")),
            mutable: false,
            receiver_mode: None,
        }],
        TypeDescriptor::declared(path("crate::Token")),
        vec![(
            "consume",
            ReceiverMode::Owned,
            vec![
                instruction(
                    0,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Load(Arc::from("self")),
                ),
                instruction(
                    1,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(2, TypeDescriptor::INT, InstructionKind::Return),
            ],
        )],
        |identities| {
            vec![
                receiver_call_at_path(
                    0,
                    &identities[0],
                    "holder",
                    vec![ValuePathSegment::StructField("token".to_owned())],
                ),
                instruction(
                    1,
                    TypeDescriptor::declared(path("crate::Holder")),
                    InstructionKind::Load(Arc::from("holder")),
                ),
                instruction(
                    2,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Project(Projection::Field(Arc::from("token"))),
                ),
                instruction(
                    3,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Return,
                ),
            ]
        },
    )
}

/// A projection into a moved-out subplace of an enclosing loaded place fails closed, while the
/// projection of a surviving sibling of the same partial move keeps working.
#[cfg(feature = "durable")]
#[test]
fn owned_move_rejects_projection_into_a_moved_out_subplace() {
    let program = partial_move_token_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    // The fixture callee loads, projects, and returns, so the caller place is marked by step four.
    step_deterministic(&mut machine, 4);
    assert_eq!(
        machine.checkpoint().canonical_bytes().get(..8),
        Some(b"GNTMCP07".as_slice())
    );
    // The enclosing place still loads without complaint, and the projection of its moved-out
    // subplace is then refused instead of serving the stale pre-move value.
    assert_eq!(machine.test_value_stack_alignment(), (1, 1));
    step_deterministic(&mut machine, 1);
    assert_eq!(machine.test_value_stack_alignment(), (2, 2));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Failed(failure)
            if failure.code == RuntimeCode::InternalInvariant && failure.site == site(2)
    ));

    // The surviving sibling of the same enclosing place stays readable.
    let program = partial_move_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 4);
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(10).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ))
    );
}

/// `crate::main` admits `token` as a shared receiver place without moving anything out.
#[cfg(feature = "durable")]
fn shared_caller_place_program() -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token")],
        TypeDescriptor::INT,
        vec![(
            "inspect",
            ReceiverMode::SharedPlace,
            vec![
                instruction(
                    0,
                    TypeDescriptor::declared(path("crate::Token")),
                    InstructionKind::Load(Arc::from("self")),
                ),
                instruction(
                    1,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(2, TypeDescriptor::INT, InstructionKind::Return),
            ],
        )],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                instruction(1, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// No legacy version can carry a moved-out mark, so a downgraded V7 checkpoint is rejected
/// instead of silently re-enabling a read of the moved-out place.
#[cfg(feature = "durable")]
#[test]
fn legacy_magic_rejects_a_checkpoint_that_carries_a_moved_out_mark() {
    let program = two_place_owned_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5), token_value(9)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 3);
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP07".as_slice()));
    for magic in [b"GNTMCP03", b"GNTMCP04", b"GNTMCP05", b"GNTMCP06"] {
        let mut downgraded = bytes.clone();
        downgraded[..8].copy_from_slice(magic);
        assert!(
            matches!(
                crate::MachineCheckpointV3::decode(&program, &downgraded),
                Err(crate::MachineRecoveryError::ProgramMismatch)
            ),
            "a {magic:?} relabel of a marked checkpoint must be a program mismatch"
        );
    }
}

/// Programs without an executed owned caller-place call keep decoding under the legacy formats.
#[cfg(feature = "durable")]
#[test]
fn legacy_magic_still_decodes_without_an_executed_owned_caller_place_call() {
    // A shared receiver admission never moves a place out, so no mark can be dropped.
    let program = shared_caller_place_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP05".as_slice()));
    assert!(crate::MachineCheckpointV3::decode(&program, &bytes).is_ok());

    // An owned caller-place call that has not executed yet is still legacy-representable.
    let program = two_place_owned_program();
    let machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5), token_value(9)],
        limits(16, 1, 1, 2, 16),
    );
    let bytes = machine.checkpoint().canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP03".as_slice()));
    assert!(crate::MachineCheckpointV3::decode(&program, &bytes).is_ok());
}

/// The staged value stack and its place-origin stack stay aligned across a call that stages,
/// projects, and pops values, and across a later assignment that pops a loaded value.
#[cfg(feature = "durable")]
#[test]
fn staged_value_stack_keeps_its_place_origins_aligned() {
    for (program, initial, steps) in [
        (partial_move_program(), vec![holder_value(7, 3)], 4_usize),
        (assign_after_owned_move_program(), vec![token_value(5)], 5),
    ] {
        let mut machine = new_machine(
            Arc::clone(&program),
            "crate::main",
            initial,
            limits(16, 1, 1, 2, 16),
        );
        assert_eq!(machine.test_value_stack_alignment(), (0, 0));
        for step in 1..=steps {
            assert!(matches!(
                machine.step(),
                MachineStep::Transition(MachineLabel::Deterministic { .. })
            ));
            let (values, places) = machine.test_value_stack_alignment();
            assert_eq!(
                values, places,
                "the staged value and place stacks desynchronized after step {step}"
            );
        }
    }

    // A value loaded from the enclosing place stays paired with exactly one origin entry while
    // its surviving sibling is projected out of it.
    let program = partial_move_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![holder_value(7, 3)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 5);
    assert_eq!(machine.test_value_stack_alignment(), (2, 2));
    step_deterministic(&mut machine, 1);
    assert_eq!(machine.test_value_stack_alignment(), (2, 2));
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(10).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ))
    );
    assert_eq!(machine.test_value_stack_alignment(), (0, 0));
}

/// One caller-place receiver call whose admission consumes a `MustConsume` place.
#[cfg(feature = "durable")]
fn consuming_receiver_call(
    site_index: u64,
    callee: &CanonicalCallableIdentity,
    root: &str,
) -> Instruction {
    instruction(
        site_index,
        TypeDescriptor::INT,
        InstructionKind::ReceiverCall {
            callee: callee.clone(),
            arguments: 1,
            source: ReceiverSource::CallerPlace {
                root: Arc::from(root),
                path: Vec::new(),
                ownership: OwnershipClass::MustConsume,
            },
        },
    )
}

/// `crate::main` consumes `token` through one `MustConsume` owned admission.
#[cfg(feature = "durable")]
fn must_consume_program(callee_body: Vec<Instruction>) -> Arc<MachineProgram> {
    affine_call_program(
        vec![token_parameter("token")],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, callee_body)],
        |identities| {
            vec![
                consuming_receiver_call(0, &identities[0], "token"),
                instruction(1, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    )
}

/// The V9 obligation section is written last, so the bytes from its magic to the end of the
/// checkpoint are exactly that section.
#[cfg(feature = "durable")]
const CONSUMPTION_OBLIGATION_SECTION_MAGIC: &[u8] = b"GNTMCX01";

#[cfg(feature = "durable")]
fn obligation_entries(entries: &[&str]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for root in entries {
        encoded.extend_from_slice(&(root.len() as u64).to_be_bytes());
        encoded.extend_from_slice(root.as_bytes());
        // Every fixture obligation roots at one whole binding with an empty path.
        encoded.extend_from_slice(&0_u64.to_be_bytes());
    }
    encoded
}

#[cfg(feature = "durable")]
fn consumption_obligation_section(
    frame_count: u64,
    frames: &[&[&str]],
    settled: &[&str],
) -> Vec<u8> {
    let mut section = CONSUMPTION_OBLIGATION_SECTION_MAGIC.to_vec();
    section.extend_from_slice(&frame_count.to_be_bytes());
    for frame in frames {
        section.extend_from_slice(&obligation_entries(frame));
    }
    section.extend_from_slice(&obligation_entries(settled));
    section
}

#[cfg(feature = "durable")]
fn resplice_consumption_obligation_section(bytes: &[u8], section: &[u8]) -> Vec<u8> {
    let offset = section_offset(bytes, CONSUMPTION_OBLIGATION_SECTION_MAGIC);
    let mut rewritten = bytes[..offset].to_vec();
    rewritten.extend_from_slice(section);
    rewritten
}

/// A `MustConsume` owned admission stages one obligation in the callee frame, and a normal return
/// transfers it to the caller frame that owns the consumed place.
#[cfg(feature = "durable")]
#[test]
fn must_consume_admission_stages_and_transfers_the_obligation() {
    let program = must_consume_program(owned_consume_body());
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    let staged = machine
        .test_consumption_obligations(1)
        .unwrap_or_else(|| panic!("the consuming call stages a callee frame"));
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].root.as_ref(), "token");
    assert!(staged[0].path.is_empty());

    step_deterministic(&mut machine, 2);
    assert_eq!(
        machine.test_consumption_obligations(1).map(<[_]>::len),
        None
    );
    let transferred = machine
        .test_consumption_obligations(0)
        .unwrap_or_else(|| panic!("the caller frame owns the consumed place"));
    assert_eq!(transferred.len(), 1);
    assert_eq!(transferred[0].root.as_ref(), "token");
    assert!(machine.settled_consumption_obligations().is_empty());
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ))
    );
}

/// A failure cut discards the frames, so the staged obligation is retained in the machine-level
/// settled list instead of disappearing with them.
#[cfg(feature = "durable")]
#[test]
fn must_consume_obligation_survives_a_failure_cut() {
    let program = must_consume_program(vec![
        instruction(
            0,
            TypeDescriptor::declared(path("crate::Token")),
            InstructionKind::Load(Arc::from("missing")),
        ),
        instruction(1, TypeDescriptor::INT, InstructionKind::Return),
    ]);
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Failed(failure) if failure.code == RuntimeCode::InternalInvariant
    ));
    let settled = machine.settled_consumption_obligations();
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].root(), "token");
    assert!(settled[0].path().is_empty());
    // The frame-level record is drained rather than duplicated.
    assert_eq!(
        machine.test_consumption_obligations(1).map(<[_]>::len),
        Some(0)
    );
}

/// A cancellation discards the frames like a failure does, so the staged obligation is retained in
/// the machine-level settled list instead of disappearing with them.
#[cfg(feature = "durable")]
#[test]
fn must_consume_obligation_survives_a_cancellation_cut() {
    let program = must_consume_program(owned_consume_body());
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    assert!(matches!(
        machine.cancel("caller"),
        Some(MachineLabel::Cancellation { .. })
    ));
    assert!(matches!(
        drive(&mut machine),
        MachineOutcome::Cancelled(ref reason) if reason.as_ref() == "caller"
    ));
    let settled = machine.settled_consumption_obligations();
    assert_eq!(
        settled.len(),
        1,
        "a cancellation settles the staged obligation exactly once"
    );
    assert_eq!(settled[0].root(), "token");
    assert!(settled[0].path().is_empty());
    // The frame-level record is drained rather than duplicated.
    assert_eq!(
        machine.test_consumption_obligations(1).map(<[_]>::len),
        Some(0)
    );
}

/// A successful root return settles the obligation its caller place left unaccounted for, so the
/// evidence survives the terminal cut exactly once.
#[cfg(feature = "durable")]
#[test]
fn must_consume_obligation_survives_a_successful_root_return() {
    let program = must_consume_program(owned_consume_body());
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(7).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ))
    );
    let settled = machine.settled_consumption_obligations();
    assert_eq!(
        settled.len(),
        1,
        "a successful root return settles the transferred obligation exactly once"
    );
    assert_eq!(settled[0].root(), "token");
    assert!(settled[0].path().is_empty());
    // The frame-level record is drained rather than duplicated.
    assert_eq!(
        machine.test_consumption_obligations(0).map(<[_]>::len),
        Some(0)
    );
}

/// A checkpoint carries the obligation section only for a `MustConsume` caller place, and the new
/// wire form round-trips with its obligation intact.
#[cfg(feature = "durable")]
#[test]
fn must_consume_obligation_checkpoint_round_trips_and_stays_absent_without_it() {
    let program = must_consume_program(owned_consume_body());
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    let checkpoint = machine.checkpoint();
    let bytes = checkpoint.canonical_bytes();
    assert_eq!(bytes.get(..8), Some(b"GNTMCP09".as_slice()));
    let decoded = crate::MachineCheckpointV3::decode(&program, &bytes)
        .unwrap_or_else(|error| panic!("obligation checkpoint decode failed: {error:?}"));
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.canonical_bytes(), bytes);
    let budget = ExecutionBudget::recover_from_checkpoint(machine.budget_checkpoint())
        .unwrap_or_else(|error| panic!("obligation budget recovery failed: {error:?}"));
    let recovered = Machine::recover_from_checkpoint(Arc::clone(&program), decoded, budget)
        .unwrap_or_else(|error| panic!("obligation recovery failed: {error:?}"));
    let recovered_obligation = recovered
        .test_consumption_obligations(1)
        .unwrap_or_else(|| panic!("the recovered callee frame keeps its obligation"));
    assert_eq!(recovered_obligation.len(), 1);
    assert_eq!(recovered_obligation[0].root.as_ref(), "token");

    // Without one `MustConsume` admission the older wire form stays current and carries no section.
    let program = two_place_owned_program();
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5), token_value(9)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    let bytes = machine.checkpoint().canonical_bytes();
    assert_ne!(bytes.get(..8), Some(b"GNTMCP09".as_slice()));
    assert!(
        !bytes
            .windows(CONSUMPTION_OBLIGATION_SECTION_MAGIC.len())
            .any(|window| window == CONSUMPTION_OBLIGATION_SECTION_MAGIC)
    );
    assert!(machine.settled_consumption_obligations().is_empty());
}

/// Re-initializing the consumed place makes the obligation accounted for, so the newer wire form is
/// no longer selected and the place is readable again.
#[cfg(feature = "durable")]
#[test]
fn must_consume_obligation_is_discharged_by_reinitialization() {
    let token_type = TypeDescriptor::declared(path("crate::Token"));
    let program = affine_call_program(
        vec![Parameter {
            name: Arc::from("token"),
            ty: token_type.clone(),
            mutable: true,
            receiver_mode: None,
        }],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                instruction(
                    0,
                    TypeDescriptor::INT,
                    InstructionKind::ReceiverCall {
                        callee: identities[0].clone(),
                        arguments: 1,
                        source: ReceiverSource::CallerPlace {
                            root: Arc::from("token"),
                            path: Vec::new(),
                            ownership: OwnershipClass::MustConsume,
                        },
                    },
                ),
                instruction(1, token_type.clone(), InstructionKind::Push(token_value(3))),
                instruction(
                    2,
                    TypeDescriptor::UNIT,
                    InstructionKind::Assign {
                        name: Arc::from("token"),
                        path: Vec::new(),
                        target_type: token_type.clone(),
                    },
                ),
                instruction(
                    3,
                    token_type.clone(),
                    InstructionKind::Load(Arc::from("token")),
                ),
                instruction(
                    4,
                    TypeDescriptor::INT,
                    InstructionKind::Project(Projection::Field(Arc::from("value"))),
                ),
                instruction(5, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    );
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 5);
    assert_eq!(
        machine.test_consumption_obligations(0).map(<[_]>::len),
        Some(0)
    );
    let bytes = machine.checkpoint().canonical_bytes();
    assert_ne!(bytes.get(..8), Some(b"GNTMCP09".as_slice()));
    assert_eq!(
        drive(&mut machine),
        MachineOutcome::Succeeded(LogicalValue::integer(
            GantryInt::new(3).unwrap_or_else(|| unreachable!("fixture integer is admitted")),
        ))
    );
}

/// Structurally impossible obligation sections are rejected as malformed, and an entry that no
/// retained `MustConsume` admission justifies is reported as a program mismatch.
#[cfg(feature = "durable")]
#[test]
fn must_consume_obligation_section_negatives_are_rejected() {
    let program = must_consume_program(owned_consume_body());
    let mut machine = new_machine(
        Arc::clone(&program),
        "crate::main",
        vec![token_value(5)],
        limits(16, 1, 1, 2, 16),
    );
    step_deterministic(&mut machine, 1);
    let bytes = machine.checkpoint().canonical_bytes();

    let duplicated = {
        let mut rewritten = bytes.clone();
        rewritten.extend_from_slice(&consumption_obligation_section(2, &[&[], &["token"]], &[]));
        rewritten
    };
    assert_eq!(
        crate::MachineCheckpointV3::decode(&program, &duplicated),
        Err(crate::MachineRecoveryError::InvalidCheckpoint)
    );
    for section in [
        consumption_obligation_section(2, &[&[], &[""]], &[]),
        consumption_obligation_section(2, &[&[], &["token", "token"]], &[]),
        consumption_obligation_section(1, &[], &[]),
    ] {
        let rewritten = resplice_consumption_obligation_section(&bytes, &section);
        assert_eq!(
            crate::MachineCheckpointV3::decode(&program, &rewritten),
            Err(crate::MachineRecoveryError::InvalidCheckpoint)
        );
    }

    // The same bytes are inconsistent with a program that only reads the caller place.
    let copyable = affine_call_program(
        vec![token_parameter("token")],
        TypeDescriptor::INT,
        vec![("consume", ReceiverMode::Owned, owned_consume_body())],
        |identities| {
            vec![
                receiver_call(0, &identities[0], "token"),
                instruction(1, TypeDescriptor::INT, InstructionKind::Return),
            ]
        },
    );
    assert_eq!(
        crate::MachineCheckpointV3::decode(&copyable, &bytes),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    );

    // A stream that claims the previous version cannot carry the obligation this program owes.
    let mut superseded = bytes.clone();
    superseded[..8].copy_from_slice(b"GNTMCP08");
    assert_eq!(
        crate::MachineCheckpointV3::decode(&program, &superseded),
        Err(crate::MachineRecoveryError::ProgramMismatch)
    );
}
