//! Public executable-IR coverage for source task-control contracts.

use std::sync::Arc;

use gantry::ir::{
    CanonicalCallableIdentity, CanonicalPath, EffectSet, ExecutableTaskBody, ExecutableTaskCapture,
    ExecutableTaskContext, ExecutableTaskHandle, Instruction, InstructionKind, MachineProgram,
    ProgramError, StructuralPosition, TaskBodyIdentity, TaskCompletion, TaskSuspension,
    TypeDescriptor, Workflow,
};
use gantry::value::LogicalValue;

#[test]
fn executable_task_bodies_are_closed_typed_and_handle_separated() {
    let path =
        CanonicalPath::new("crate::work").unwrap_or_else(|error| panic!("path failed: {error}"));
    let caller = CanonicalCallableIdentity::free(&path, &[TypeDescriptor::STRING]);
    let site = position(&[0]);
    let body_id = TaskBodyIdentity::new(caller.clone(), site.clone());
    let handle = ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::STRING)
        .unwrap_or_else(|error| panic!("handle failed: {error:?}"));
    let body = ExecutableTaskBody::new(
        body_id.clone(),
        TypeDescriptor::STRING,
        vec![
            ExecutableTaskCapture::new(Arc::from("count"), TypeDescriptor::INT, false)
                .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
            ExecutableTaskCapture::new(Arc::from("message"), TypeDescriptor::STRING, true)
                .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
        ],
        ExecutableTaskContext::v1(),
        vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(
                    LogicalValue::string("done", gantry::value::DEFAULT_VALUE_LIMITS)
                        .unwrap_or_else(|error| panic!("value failed: {error:?}")),
                ),
            ),
            instruction(1, TypeDescriptor::STRING, InstructionKind::TaskComplete),
        ],
    )
    .unwrap_or_else(|error| panic!("task body failed: {error:?}"));

    let program = MachineProgram::with_task_bodies(
        vec![(
            caller.clone(),
            Workflow {
                path: path.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        TypeDescriptor::UNIT,
                        InstructionKind::Spawn {
                            handle: handle.clone(),
                            body: body_id.clone(),
                        },
                    ),
                    instruction(
                        1,
                        TypeDescriptor::STRING,
                        InstructionKind::Join {
                            handles: vec![Arc::from("child")],
                        },
                    ),
                    instruction(
                        2,
                        TypeDescriptor::UNIT,
                        InstructionKind::JoinAll {
                            handles: Vec::new(),
                        },
                    ),
                    instruction(
                        3,
                        TypeDescriptor::UNIT,
                        InstructionKind::Detach {
                            handle: Arc::from("child"),
                        },
                    ),
                    instruction(4, TypeDescriptor::UNIT, InstructionKind::Return),
                ],
            },
        )],
        vec![body.clone()],
    )
    .unwrap_or_else(|error| panic!("program failed: {error:?}"));

    assert_eq!(program.task_body(&body_id), Some(&body));
    assert_eq!(program.task_bodies(), [body]);
    assert_eq!(handle.name(), "child");
    assert_eq!(handle.result_type(), &TypeDescriptor::STRING);
    assert_eq!(program.task_bodies()[0].captures()[0].name(), "count");
    assert!(program.task_bodies()[0].captures()[1].is_mutable());
    assert_eq!(
        program.task_bodies()[0].context(),
        &ExecutableTaskContext::v1()
    );
    assert!(program.task_bodies()[0].context().inherits_agent());
    assert!(
        program.task_bodies()[0]
            .context()
            .snapshots_active_session()
    );
    assert!(program.task_bodies()[0].context().forks_session());
    assert!(program.task_bodies()[0].context().derives_task_path());
    assert!(
        program.task_bodies()[0]
            .context()
            .derives_recovery_identity()
    );

    let suspension = TaskSuspension::Spawn {
        handle: handle.clone(),
        body: body_id.clone(),
    };
    let detach = TaskSuspension::Detach {
        handle: Arc::from("child"),
    };
    let completion = TaskCompletion::Spawned { handle };
    assert_ne!(format!("{suspension:?}"), format!("{completion:?}"));
    assert_ne!(format!("{detach:?}"), format!("{completion:?}"));

    let other_caller = CanonicalCallableIdentity::free(&path, &[TypeDescriptor::INT]);
    assert_ne!(
        body_id,
        TaskBodyIdentity::new(other_caller, site),
        "the closed enclosing callable must distinguish generic instantiations",
    );
}

#[test]
fn executable_task_body_validation_rejects_noncanonical_artifacts() {
    let path =
        CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("path failed: {error}"));
    let caller = CanonicalCallableIdentity::free(&path, &[]);
    let body_id = TaskBodyIdentity::new(caller.clone(), position(&[0]));
    let body = ExecutableTaskBody::new(
        body_id.clone(),
        TypeDescriptor::UNIT,
        Vec::new(),
        ExecutableTaskContext::v1(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::TaskComplete,
        )],
    )
    .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
    let workflow = Workflow {
        path,
        parameters: Vec::new(),
        result: TypeDescriptor::UNIT,
        effects: EffectSet::default(),
        instructions: vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Return,
        )],
    };

    assert!(matches!(
        MachineProgram::with_task_bodies(
            vec![(caller.clone(), workflow.clone())],
            vec![body.clone(), body],
        ),
        Err(ProgramError::TaskBodyOrder)
    ));

    let missing = TaskBodyIdentity::new(caller.clone(), position(&[9]));
    let invalid_spawn = Workflow {
        instructions: vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Spawn {
                handle: ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::UNIT)
                    .unwrap_or_else(|error| panic!("handle failed: {error:?}")),
                body: missing,
            },
        )],
        ..workflow.clone()
    };
    assert!(matches!(
        MachineProgram::with_task_bodies(vec![(caller, invalid_spawn)], vec![]),
        Err(ProgramError::InvalidTaskBody(_))
    ));

    let orphan_body = ExecutableTaskBody::new(
        TaskBodyIdentity::new(
            CanonicalCallableIdentity::free(&workflow.path, &[]),
            position(&[7]),
        ),
        TypeDescriptor::UNIT,
        Vec::new(),
        ExecutableTaskContext::v1(),
        vec![instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::TaskComplete,
        )],
    )
    .unwrap_or_else(|error| panic!("orphan task body failed: {error:?}"));
    assert!(matches!(
        MachineProgram::with_task_bodies(
            vec![(
                CanonicalCallableIdentity::free(&workflow.path, &[]),
                workflow,
            )],
            vec![orphan_body],
        ),
        Err(ProgramError::TaskBodyReference)
    ));
}

fn instruction(index: u64, ty: TypeDescriptor, kind: InstructionKind) -> Instruction {
    Instruction {
        site: position(&[index]),
        ty,
        kind,
    }
}

fn position(components: &[u64]) -> StructuralPosition {
    StructuralPosition::new(components.to_vec())
        .unwrap_or_else(|error| panic!("position failed: {error}"))
}
