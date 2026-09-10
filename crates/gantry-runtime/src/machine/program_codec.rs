//! Canonical private codec for the analyzer-owned executable program retained by durable start.

use std::sync::Arc;

use gantry_core::value::{ValueLimits, ValuePathSegment};
use gantry_ir::generated::{Effect, OperationSiteKind, RecoveryClass};
use gantry_ir::{
    ActionParameter, AggregateKind, CanonicalCallableIdentity, CanonicalPath, CanonicalSignature,
    Comparison, EffectSet, ExecutableAction, ExecutableOperation, ExecutableTaskBody,
    ExecutableTaskCapture, ExecutableTaskContext, ExecutableTaskHandle, Instruction,
    InstructionKind, LoopPhase, MachineProgram, Parameter, Primitive, Projection, ReceiverMode,
    ReceiverSource, TaskBodyIdentity, TypeDescriptor, Workflow,
};

use super::MachineRecoveryError;
use super::checkpoint_codec::{Reader, Writer};

const MAGIC_V2: &[u8; 8] = b"GNTPRG02";
const MAGIC_V3: &[u8; 8] = b"GNTPRG03";

fn program_uses_successor_wire(program: &MachineProgram) -> bool {
    let has_non_v2_receiver_metadata = program.workflows().iter().any(|workflow| {
        workflow.parameters.iter().any(|parameter| {
            parameter.receiver_mode()
                != if parameter.name.as_ref() == "self" {
                    Some(ReceiverMode::from_v1_mutability(parameter.mutable))
                } else {
                    None
                }
        })
    });
    has_non_v2_receiver_metadata
        || program
            .workflows()
            .iter()
            .flat_map(|workflow| workflow.instructions.iter())
            .chain(
                program
                    .task_bodies()
                    .iter()
                    .flat_map(|body| body.instructions().iter()),
            )
            .any(|instruction| {
                matches!(
                    instruction.kind,
                    InstructionKind::ReceiverCall {
                        source: ReceiverSource::CallerPlace { .. },
                        ..
                    }
                )
            })
}

fn write_receiver_mode(writer: &mut Writer, mode: Option<ReceiverMode>) {
    writer.u8(match mode {
        None => 0,
        Some(ReceiverMode::LocalCopy) => 1,
        Some(ReceiverMode::MutableLocalCopy) => 2,
        Some(ReceiverMode::Owned) => 3,
        Some(ReceiverMode::SharedPlace) => 4,
        Some(ReceiverMode::ExclusivePlace) => 5,
    });
}

fn read_receiver_mode(
    reader: &mut Reader<'_>,
) -> Result<Option<ReceiverMode>, MachineRecoveryError> {
    Ok(match reader.u8()? {
        0 => None,
        1 => Some(ReceiverMode::LocalCopy),
        2 => Some(ReceiverMode::MutableLocalCopy),
        3 => Some(ReceiverMode::Owned),
        4 => Some(ReceiverMode::SharedPlace),
        5 => Some(ReceiverMode::ExclusivePlace),
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    })
}

fn codec_limits() -> ValueLimits {
    ValueLimits::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX)
        .unwrap_or_else(|| unreachable!("positive codec limits are valid"))
}

pub(crate) fn encode_machine_program(program: &MachineProgram) -> Vec<u8> {
    let mut writer = Writer::default();
    let successor = program_uses_successor_wire(program);
    writer.raw(if successor { MAGIC_V3 } else { MAGIC_V2 });
    writer.count(program.workflows().len());
    for (identity, workflow) in program
        .callable_identities()
        .iter()
        .zip(program.workflows())
    {
        writer.string(identity.as_str());
        writer.string(workflow.path.as_str());
        writer.count(workflow.parameters.len());
        for parameter in &workflow.parameters {
            writer.string(&parameter.name);
            writer.string(&parameter.ty.canonical_string());
            writer.boolean(parameter.mutable);
            if successor {
                write_receiver_mode(&mut writer, parameter.receiver_mode());
            }
        }
        writer.string(&workflow.result.canonical_string());
        let effects = workflow.effects.iter().collect::<Vec<_>>();
        writer.count(effects.len());
        for effect in effects {
            writer.string(effect.wire_name());
        }
        writer.count(workflow.instructions.len());
        for instruction in &workflow.instructions {
            writer.position(&instruction.site);
            writer.string(&instruction.ty.canonical_string());
            write_instruction(&mut writer, &instruction.kind);
        }
    }
    writer.count(program.task_bodies().len());
    for body in program.task_bodies() {
        write_task_body(&mut writer, body);
    }
    writer.finish()
}

pub(crate) fn decode_machine_program(bytes: &[u8]) -> Result<MachineProgram, MachineRecoveryError> {
    let mut reader = Reader::new(bytes);
    let successor = match reader.raw(MAGIC_V2.len())? {
        magic if magic == MAGIC_V2 => false,
        magic if magic == MAGIC_V3 => true,
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    };
    let workflow_count = reader.count()?;
    let mut callables = Vec::with_capacity(workflow_count);
    for _ in 0..workflow_count {
        let identity =
            CanonicalCallableIdentity::from_canonical_string(&reader.string()?, u64::MAX)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
        let path = path(&reader.string()?)?;
        let parameter_count = reader.count()?;
        let mut parameters = Vec::with_capacity(parameter_count);
        for _ in 0..parameter_count {
            let name: Arc<str> = Arc::from(reader.string()?);
            let ty = ty(&reader.string()?)?;
            let mutable = reader.boolean()?;
            parameters.push(Parameter {
                receiver_mode: if successor {
                    read_receiver_mode(&mut reader)?
                } else if name.as_ref() == "self" {
                    Some(ReceiverMode::from_v1_mutability(mutable))
                } else {
                    None
                },
                name,
                ty,
                mutable,
            });
        }
        let result = ty(&reader.string()?)?;
        let effect_count = reader.count()?;
        let mut effects = EffectSet::default();
        for _ in 0..effect_count {
            if !effects.insert(effect(&reader.string()?)?) {
                return Err(MachineRecoveryError::InvalidEncoding);
            }
        }
        let instruction_count = reader.count()?;
        let mut instructions = Vec::with_capacity(instruction_count);
        for _ in 0..instruction_count {
            instructions.push(Instruction {
                site: reader.position()?,
                ty: ty(&reader.string()?)?,
                kind: read_instruction(&mut reader, successor)?,
            });
        }
        callables.push((
            identity,
            Workflow {
                path,
                parameters,
                result,
                effects,
                instructions,
            },
        ));
    }
    let body_count = reader.count()?;
    let mut task_bodies = Vec::with_capacity(body_count);
    for _ in 0..body_count {
        task_bodies.push(read_task_body(&mut reader, successor)?);
    }
    if !reader.is_empty() {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    let program = MachineProgram::with_task_bodies(callables, task_bodies)
        .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    if encode_machine_program(&program) != bytes {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    Ok(program)
}

fn write_instruction(writer: &mut Writer, instruction: &InstructionKind) {
    match instruction {
        InstructionKind::Push(value) => {
            writer.u8(0);
            writer.value(value);
        }
        InstructionKind::Load(name) => {
            writer.u8(1);
            writer.string(name);
        }
        InstructionKind::Bind { name, ty, mutable } => {
            writer.u8(2);
            writer.string(name);
            writer.string(&ty.canonical_string());
            writer.boolean(*mutable);
        }
        InstructionKind::Assign {
            name,
            path,
            target_type,
        } => {
            writer.u8(3);
            writer.string(name);
            write_value_path(writer, path);
            writer.string(&target_type.canonical_string());
        }
        InstructionKind::Pop => writer.u8(4),
        InstructionKind::Aggregate { kind, operands } => {
            writer.u8(5);
            write_aggregate(writer, kind);
            writer.usize(*operands);
        }
        InstructionKind::Project(projection) => {
            writer.u8(6);
            write_projection(writer, projection);
        }
        InstructionKind::Primitive(primitive) => {
            writer.u8(7);
            write_primitive(writer, *primitive);
        }
        InstructionKind::EnterScope => writer.u8(8),
        InstructionKind::ExitScope => writer.u8(9),
        InstructionKind::Jump(target) => {
            writer.u8(10);
            writer.usize(*target);
        }
        InstructionKind::Branch {
            when_true,
            when_false,
        } => {
            writer.u8(11);
            writer.usize(*when_true);
            writer.usize(*when_false);
        }
        InstructionKind::BranchOption {
            when_some,
            when_none,
        } => {
            writer.u8(12);
            writer.usize(*when_some);
            writer.usize(*when_none);
        }
        InstructionKind::BranchEnum { arms } => {
            writer.u8(25);
            writer.count(arms.len());
            for (variant, target) in arms {
                writer.string(variant);
                writer.usize(*target);
            }
        }
        InstructionKind::EnterLoop {
            phase,
            source_limit,
        } => {
            writer.u8(13);
            writer.u8(match phase {
                LoopPhase::Condition => 0,
                LoopPhase::Body => 1,
            });
            writer.boolean(source_limit.is_some());
            if let Some(limit) = source_limit {
                writer.u64(*limit);
            }
        }
        InstructionKind::LeaveOccurrence => writer.u8(14),
        InstructionKind::Call { callee, arguments } => {
            writer.u8(15);
            writer.string(callee.as_str());
            writer.usize(*arguments);
        }
        InstructionKind::ReceiverCall {
            callee,
            arguments,
            source: ReceiverSource::CopiedValue,
        } => {
            writer.u8(31);
            writer.string(callee.as_str());
            writer.usize(*arguments);
        }
        InstructionKind::ReceiverCall {
            callee,
            arguments,
            source: ReceiverSource::CallerPlace { root, path },
        } => {
            writer.u8(32);
            writer.string(callee.as_str());
            writer.usize(*arguments);
            writer.string(root);
            write_value_path(writer, path);
        }
        InstructionKind::Return => writer.u8(16),
        InstructionKind::Operation => writer.u8(17),
        InstructionKind::OperationWithOperands { operands } => {
            writer.u8(18);
            writer.usize(*operands);
        }
        InstructionKind::OperationCall {
            operation,
            operands,
        } => {
            writer.u8(19);
            write_operation(writer, operation);
            writer.usize(*operands);
        }
        InstructionKind::EnterAgent(agent) => {
            writer.u8(20);
            writer.string(agent);
        }
        InstructionKind::ExitAgent => writer.u8(21),
        InstructionKind::EnterSession(mode) => {
            writer.u8(22);
            writer.string(mode);
        }
        InstructionKind::ExitSession => writer.u8(23),
        InstructionKind::CancellationCheck => writer.u8(24),
        InstructionKind::Spawn { handle, body } => {
            writer.u8(26);
            writer.string(handle.name());
            writer.string(&handle.result_type().canonical_string());
            write_task_body_identity(writer, body);
        }
        InstructionKind::Join { handles } => {
            writer.u8(27);
            writer.strings(handles);
        }
        InstructionKind::JoinAll { handles } => {
            writer.u8(28);
            writer.strings(handles);
        }
        InstructionKind::Detach { handle } => {
            writer.u8(29);
            writer.string(handle);
        }
        InstructionKind::TaskComplete => writer.u8(30),
    }
}

fn read_instruction(
    reader: &mut Reader<'_>,
    successor: bool,
) -> Result<InstructionKind, MachineRecoveryError> {
    Ok(match reader.u8()? {
        0 => InstructionKind::Push(reader.value(codec_limits())?),
        1 => InstructionKind::Load(Arc::from(reader.string()?)),
        2 => InstructionKind::Bind {
            name: Arc::from(reader.string()?),
            ty: ty(&reader.string()?)?,
            mutable: reader.boolean()?,
        },
        3 => InstructionKind::Assign {
            name: Arc::from(reader.string()?),
            path: read_value_path(reader)?,
            target_type: ty(&reader.string()?)?,
        },
        4 => InstructionKind::Pop,
        5 => InstructionKind::Aggregate {
            kind: read_aggregate(reader)?,
            operands: reader.usize()?,
        },
        6 => InstructionKind::Project(read_projection(reader)?),
        7 => InstructionKind::Primitive(read_primitive(reader)?),
        8 => InstructionKind::EnterScope,
        9 => InstructionKind::ExitScope,
        10 => InstructionKind::Jump(reader.usize()?),
        11 => InstructionKind::Branch {
            when_true: reader.usize()?,
            when_false: reader.usize()?,
        },
        12 => InstructionKind::BranchOption {
            when_some: reader.usize()?,
            when_none: reader.usize()?,
        },
        13 => InstructionKind::EnterLoop {
            phase: match reader.u8()? {
                0 => LoopPhase::Condition,
                1 => LoopPhase::Body,
                _ => return Err(MachineRecoveryError::InvalidEncoding),
            },
            source_limit: reader.boolean()?.then(|| reader.u64()).transpose()?,
        },
        14 => InstructionKind::LeaveOccurrence,
        15 => InstructionKind::Call {
            callee: CanonicalCallableIdentity::from_canonical_string(&reader.string()?, u64::MAX)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
            arguments: reader.usize()?,
        },
        31 => InstructionKind::ReceiverCall {
            callee: CanonicalCallableIdentity::from_canonical_string(&reader.string()?, u64::MAX)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
            arguments: reader.usize()?,
            source: ReceiverSource::CopiedValue,
        },
        32 if successor => InstructionKind::ReceiverCall {
            callee: CanonicalCallableIdentity::from_canonical_string(&reader.string()?, u64::MAX)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
            arguments: reader.usize()?,
            source: ReceiverSource::CallerPlace {
                root: Arc::from(reader.string()?),
                path: read_value_path(reader)?,
            },
        },
        32 => return Err(MachineRecoveryError::InvalidEncoding),
        16 => InstructionKind::Return,
        17 => InstructionKind::Operation,
        18 => InstructionKind::OperationWithOperands {
            operands: reader.usize()?,
        },
        19 => InstructionKind::OperationCall {
            operation: read_operation(reader)?,
            operands: reader.usize()?,
        },
        20 => InstructionKind::EnterAgent(Arc::from(reader.string()?)),
        21 => InstructionKind::ExitAgent,
        22 => InstructionKind::EnterSession(Arc::from(reader.string()?)),
        23 => InstructionKind::ExitSession,
        24 => InstructionKind::CancellationCheck,
        25 => {
            let count = reader.count()?;
            let mut arms = Vec::with_capacity(count);
            for _ in 0..count {
                arms.push((Arc::from(reader.string()?), reader.usize()?));
            }
            InstructionKind::BranchEnum { arms }
        }
        26 => InstructionKind::Spawn {
            handle: ExecutableTaskHandle::new(Arc::from(reader.string()?), ty(&reader.string()?)?)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
            body: read_task_body_identity(reader)?,
        },
        27 => InstructionKind::Join {
            handles: reader.strings()?,
        },
        28 => InstructionKind::JoinAll {
            handles: reader.strings()?,
        },
        29 => InstructionKind::Detach {
            handle: Arc::from(reader.string()?),
        },
        30 => InstructionKind::TaskComplete,
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    })
}

fn write_task_body(writer: &mut Writer, body: &ExecutableTaskBody) {
    write_task_body_identity(writer, body.identity());
    writer.string(&body.result_type().canonical_string());
    writer.count(body.captures().len());
    for capture in body.captures() {
        writer.string(capture.name());
        writer.string(&capture.ty().canonical_string());
        writer.boolean(capture.is_mutable());
    }
    let context = *body.context();
    writer.boolean(context.inherits_agent());
    writer.boolean(context.snapshots_active_session());
    writer.boolean(context.forks_session());
    writer.boolean(context.derives_task_path());
    writer.boolean(context.derives_recovery_identity());
    writer.count(body.instructions().len());
    for instruction in body.instructions() {
        writer.position(&instruction.site);
        writer.string(&instruction.ty.canonical_string());
        write_instruction(writer, &instruction.kind);
    }
}

fn read_task_body(
    reader: &mut Reader<'_>,
    successor: bool,
) -> Result<ExecutableTaskBody, MachineRecoveryError> {
    let identity = read_task_body_identity(reader)?;
    let result_type = ty(&reader.string()?)?;
    let capture_count = reader.count()?;
    let mut captures = Vec::with_capacity(capture_count);
    for _ in 0..capture_count {
        captures.push(
            ExecutableTaskCapture::new(
                Arc::from(reader.string()?),
                ty(&reader.string()?)?,
                reader.boolean()?,
            )
            .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
        );
    }
    if !reader.boolean()?
        || !reader.boolean()?
        || !reader.boolean()?
        || !reader.boolean()?
        || !reader.boolean()?
    {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    let instruction_count = reader.count()?;
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        instructions.push(Instruction {
            site: reader.position()?,
            ty: ty(&reader.string()?)?,
            kind: read_instruction(reader, successor)?,
        });
    }
    ExecutableTaskBody::new(
        identity,
        result_type,
        captures,
        ExecutableTaskContext::v1(),
        instructions,
    )
    .map_err(|_| MachineRecoveryError::InvalidEncoding)
}

fn write_task_body_identity(writer: &mut Writer, identity: &TaskBodyIdentity) {
    writer.string(identity.enclosing_callable().as_str());
    writer.position(identity.spawn_site());
}

fn read_task_body_identity(
    reader: &mut Reader<'_>,
) -> Result<TaskBodyIdentity, MachineRecoveryError> {
    let enclosing_callable =
        CanonicalCallableIdentity::from_canonical_string(&reader.string()?, u64::MAX)
            .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    Ok(TaskBodyIdentity::new(
        enclosing_callable,
        reader.position()?,
    ))
}

fn write_aggregate(writer: &mut Writer, kind: &AggregateKind) {
    match kind {
        AggregateKind::List => writer.u8(0),
        AggregateKind::Tuple => writer.u8(1),
        AggregateKind::Struct { type_name, fields } => {
            writer.u8(2);
            writer.string(type_name);
            writer.count(fields.len());
            for field in fields {
                writer.string(field);
            }
        }
        AggregateKind::Enum {
            type_name,
            variant,
            has_payload,
        } => {
            writer.u8(3);
            writer.string(type_name);
            writer.string(variant);
            writer.boolean(*has_payload);
        }
        AggregateKind::Some => writer.u8(4),
        AggregateKind::None => writer.u8(5),
        AggregateKind::Ok => writer.u8(6),
        AggregateKind::Err => writer.u8(7),
    }
}

fn read_aggregate(reader: &mut Reader<'_>) -> Result<AggregateKind, MachineRecoveryError> {
    Ok(match reader.u8()? {
        0 => AggregateKind::List,
        1 => AggregateKind::Tuple,
        2 => {
            let type_name = Arc::from(reader.string()?);
            let count = reader.count()?;
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                fields.push(Arc::from(reader.string()?));
            }
            AggregateKind::Struct { type_name, fields }
        }
        3 => AggregateKind::Enum {
            type_name: Arc::from(reader.string()?),
            variant: Arc::from(reader.string()?),
            has_payload: reader.boolean()?,
        },
        4 => AggregateKind::Some,
        5 => AggregateKind::None,
        6 => AggregateKind::Ok,
        7 => AggregateKind::Err,
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    })
}

fn write_projection(writer: &mut Writer, value: &Projection) {
    match value {
        Projection::Member(index) => {
            writer.u8(0);
            writer.usize(*index);
        }
        Projection::Field(field) => {
            writer.u8(1);
            writer.string(field);
        }
        Projection::Payload => writer.u8(2),
    }
}
fn read_projection(reader: &mut Reader<'_>) -> Result<Projection, MachineRecoveryError> {
    Ok(match reader.u8()? {
        0 => Projection::Member(reader.usize()?),
        1 => Projection::Field(Arc::from(reader.string()?)),
        2 => Projection::Payload,
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    })
}

fn write_value_path(writer: &mut Writer, value: &[ValuePathSegment]) {
    writer.count(value.len());
    for segment in value {
        match segment {
            ValuePathSegment::ListItem(index) => {
                writer.u8(0);
                writer.usize(*index);
            }
            ValuePathSegment::TupleMember(index) => {
                writer.u8(1);
                writer.usize(*index);
            }
            ValuePathSegment::StructField(field) => {
                writer.u8(2);
                writer.string(field);
            }
            ValuePathSegment::EnumPayload => writer.u8(3),
            ValuePathSegment::OptionValue => writer.u8(4),
            ValuePathSegment::ResultValue => writer.u8(5),
        }
    }
}
fn read_value_path(reader: &mut Reader<'_>) -> Result<Vec<ValuePathSegment>, MachineRecoveryError> {
    let count = reader.count()?;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        result.push(match reader.u8()? {
            0 => ValuePathSegment::ListItem(reader.usize()?),
            1 => ValuePathSegment::TupleMember(reader.usize()?),
            2 => ValuePathSegment::StructField(reader.string()?),
            3 => ValuePathSegment::EnumPayload,
            4 => ValuePathSegment::OptionValue,
            5 => ValuePathSegment::ResultValue,
            _ => return Err(MachineRecoveryError::InvalidEncoding),
        });
    }
    Ok(result)
}

fn write_operation(writer: &mut Writer, value: &ExecutableOperation) {
    writer.string(value.kind.wire_name());
    writer.string(&value.result_type.canonical_string());
    writer.boolean(value.action.is_some());
    if let Some(action) = &value.action {
        writer.string(action.path.as_str());
        writer.string(action.recovery.wire_name());
        writer.count(action.parameters.len());
        for parameter in &action.parameters {
            writer.string(parameter.name());
            writer.string(&parameter.ty().canonical_string());
        }
    }
    writer.strings(&value.template_segments);
    writer.count(value.interpolation_types.len());
    for ty in &value.interpolation_types {
        writer.string(&ty.canonical_string());
    }
    writer.strings(&value.named_input_names);
    writer.count(value.named_input_types.len());
    for ty in &value.named_input_types {
        writer.string(&ty.canonical_string());
    }
    writer.boolean(value.retry_limit.is_some());
    if let Some(limit) = value.retry_limit {
        writer.u64(limit);
    }
    writer.optional_string(value.session_mode.as_deref());
    writer.boolean(value.attempted);
}

fn read_operation(reader: &mut Reader<'_>) -> Result<ExecutableOperation, MachineRecoveryError> {
    let kind = operation_kind(&reader.string()?)?;
    let result_type = ty(&reader.string()?)?;
    let action = if reader.boolean()? {
        let path = path(&reader.string()?)?;
        let recovery = recovery(&reader.string()?)?;
        let count = reader.count()?;
        let mut parameters = Vec::with_capacity(count);
        for _ in 0..count {
            parameters.push(
                ActionParameter::new(&reader.string()?, ty(&reader.string()?)?)
                    .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
            );
        }
        let signature = CanonicalSignature::action(recovery, &path, &parameters, &result_type);
        Some(ExecutableAction {
            path,
            signature,
            recovery,
            parameters,
        })
    } else {
        None
    };
    let template_segments = reader.strings()?;
    let interpolation_count = reader.count()?;
    let mut interpolation_types = Vec::with_capacity(interpolation_count);
    for _ in 0..interpolation_count {
        interpolation_types.push(ty(&reader.string()?)?);
    }
    let named_input_names = reader.strings()?;
    let named_count = reader.count()?;
    let mut named_input_types = Vec::with_capacity(named_count);
    for _ in 0..named_count {
        named_input_types.push(ty(&reader.string()?)?);
    }
    let retry_limit = reader.boolean()?.then(|| reader.u64()).transpose()?;
    let session_mode = reader.optional_string()?.map(Arc::from);
    let attempted = reader.boolean()?;
    Ok(ExecutableOperation {
        kind,
        result_type,
        action,
        template_segments,
        interpolation_types,
        named_input_names,
        named_input_types,
        retry_limit,
        session_mode,
        attempted,
    })
}

fn write_primitive(writer: &mut Writer, value: Primitive) {
    let tag = match value {
        Primitive::Not => 0,
        Primitive::Negate => 1,
        Primitive::Add => 2,
        Primitive::Subtract => 3,
        Primitive::Multiply => 4,
        Primitive::Divide => 5,
        Primitive::Remainder => 6,
        Primitive::Compare(Comparison::Less) => 7,
        Primitive::Compare(Comparison::LessOrEqual) => 8,
        Primitive::Compare(Comparison::Greater) => 9,
        Primitive::Compare(Comparison::GreaterOrEqual) => 10,
        Primitive::Equal => 11,
        Primitive::NotEqual => 12,
        Primitive::IntToFloat => 13,
        Primitive::FloatToInt => 14,
        Primitive::ToString => 15,
        Primitive::ListLength => 16,
        Primitive::StringLength => 17,
        Primitive::StringIsEmpty => 18,
        Primitive::StringContains => 19,
        Primitive::StringStartsWith => 20,
        Primitive::StringEndsWith => 21,
        Primitive::StringTrim => 22,
        Primitive::StringTrimStart => 23,
        Primitive::StringTrimEnd => 24,
        Primitive::StringLowercase => 25,
        Primitive::StringUppercase => 26,
        Primitive::StringReplace => 27,
        Primitive::StringSplit => 28,
        Primitive::StringParseBool => 29,
        Primitive::StringParseInt => 30,
        Primitive::StringParseFloat => 31,
        Primitive::StringListJoin => 32,
    };
    writer.u8(tag);
}
fn read_primitive(reader: &mut Reader<'_>) -> Result<Primitive, MachineRecoveryError> {
    Ok(match reader.u8()? {
        0 => Primitive::Not,
        1 => Primitive::Negate,
        2 => Primitive::Add,
        3 => Primitive::Subtract,
        4 => Primitive::Multiply,
        5 => Primitive::Divide,
        6 => Primitive::Remainder,
        7 => Primitive::Compare(Comparison::Less),
        8 => Primitive::Compare(Comparison::LessOrEqual),
        9 => Primitive::Compare(Comparison::Greater),
        10 => Primitive::Compare(Comparison::GreaterOrEqual),
        11 => Primitive::Equal,
        12 => Primitive::NotEqual,
        13 => Primitive::IntToFloat,
        14 => Primitive::FloatToInt,
        15 => Primitive::ToString,
        16 => Primitive::ListLength,
        17 => Primitive::StringLength,
        18 => Primitive::StringIsEmpty,
        19 => Primitive::StringContains,
        20 => Primitive::StringStartsWith,
        21 => Primitive::StringEndsWith,
        22 => Primitive::StringTrim,
        23 => Primitive::StringTrimStart,
        24 => Primitive::StringTrimEnd,
        25 => Primitive::StringLowercase,
        26 => Primitive::StringUppercase,
        27 => Primitive::StringReplace,
        28 => Primitive::StringSplit,
        29 => Primitive::StringParseBool,
        30 => Primitive::StringParseInt,
        31 => Primitive::StringParseFloat,
        32 => Primitive::StringListJoin,
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    })
}

fn path(value: &str) -> Result<CanonicalPath, MachineRecoveryError> {
    if let Some((receiver, method)) = value
        .strip_prefix('<')
        .and_then(|value| value.split_once(">::"))
    {
        let receiver =
            CanonicalPath::new(receiver).map_err(|_| MachineRecoveryError::InvalidEncoding)?;
        return CanonicalPath::method(&receiver, method)
            .map_err(|_| MachineRecoveryError::InvalidEncoding);
    }
    CanonicalPath::new(value).map_err(|_| MachineRecoveryError::InvalidEncoding)
}
fn ty(value: &str) -> Result<TypeDescriptor, MachineRecoveryError> {
    TypeDescriptor::from_canonical_string(value).map_err(|_| MachineRecoveryError::InvalidEncoding)
}
fn effect(value: &str) -> Result<Effect, MachineRecoveryError> {
    match value {
        "prompt" => Ok(Effect::Prompt),
        "decide" => Ok(Effect::Decide),
        "action(read_only)" => Ok(Effect::ActionReadOnly),
        "action(idempotent)" => Ok(Effect::ActionIdempotent),
        "action(non_idempotent)" => Ok(Effect::ActionNonIdempotent),
        "spawn" => Ok(Effect::Spawn),
        "join" => Ok(Effect::Join),
        "background" => Ok(Effect::Background),
        "session" => Ok(Effect::Session),
        "attempt" => Ok(Effect::Attempt),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}
fn operation_kind(value: &str) -> Result<OperationSiteKind, MachineRecoveryError> {
    match value {
        "prompt" => Ok(OperationSiteKind::Prompt),
        "decide" => Ok(OperationSiteKind::Decide),
        "action" => Ok(OperationSiteKind::Action),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}
fn recovery(value: &str) -> Result<RecoveryClass, MachineRecoveryError> {
    match value {
        "read_only" => Ok(RecoveryClass::ReadOnly),
        "idempotent" => Ok(RecoveryClass::Idempotent),
        "non_idempotent" => Ok(RecoveryClass::NonIdempotent),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gantry_core::numeric::GantryInt;
    use gantry_core::value::LogicalValue;
    use gantry_ir::{
        CanonicalCallableIdentity, CanonicalPath, EffectSet, ExecutableTaskBody,
        ExecutableTaskCapture, ExecutableTaskContext, ExecutableTaskHandle, Instruction,
        InstructionKind, MachineProgram, Parameter, ReceiverMode, ReceiverSource,
        StructuralPosition, TaskBodyIdentity, TypeDescriptor, Workflow,
    };

    use super::{decode_machine_program, encode_machine_program};
    use crate::MachineRecoveryError;

    #[test]
    fn executable_program_codec_round_trips_canonically_and_rejects_corruption() {
        let program = MachineProgram::new(vec![Workflow {
            path: CanonicalPath::new("crate::main")
                .unwrap_or_else(|error| panic!("path failed: {error}")),
            parameters: Vec::new(),
            result: TypeDescriptor::BOOL,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("site failed: {error}")),
                    ty: TypeDescriptor::BOOL,
                    kind: InstructionKind::Push(LogicalValue::boolean(true)),
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site failed: {error}")),
                    ty: TypeDescriptor::BOOL,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program failed: {error:?}"));

        let encoded = encode_machine_program(&program);
        let decoded = decode_machine_program(&encoded)
            .unwrap_or_else(|error| panic!("program decode failed: {error:?}"));
        assert_eq!(decoded, program);
        assert_eq!(encode_machine_program(&decoded), encoded);

        let mut corrupt_magic = encoded.clone();
        corrupt_magic[0] ^= 0xff;
        assert_eq!(
            decode_machine_program(&corrupt_magic),
            Err(MachineRecoveryError::InvalidEncoding)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_machine_program(&trailing),
            Err(MachineRecoveryError::InvalidEncoding)
        );
        let _ = Arc::<[u8]>::from(trailing);
    }

    #[test]
    fn executable_program_codec_preserves_closed_generic_callable_identities() {
        let main_path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("main path failed: {error}"));
        let preserve_path = CanonicalPath::new("crate::preserve")
            .unwrap_or_else(|error| panic!("preserve path failed: {error}"));
        let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
        let preserve_identity =
            CanonicalCallableIdentity::free(&preserve_path, &[TypeDescriptor::STRING]);
        let program = MachineProgram::with_callable_identities(vec![
            (
                main_identity,
                Workflow {
                    path: main_path,
                    parameters: Vec::new(),
                    result: TypeDescriptor::STRING,
                    effects: EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: StructuralPosition::new(vec![0])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::STRING,
                            kind: InstructionKind::Push(
                                LogicalValue::string("retained", super::codec_limits())
                                    .unwrap_or_else(|error| panic!("value failed: {error:?}")),
                            ),
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![1])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::STRING,
                            kind: InstructionKind::Call {
                                callee: preserve_identity.clone(),
                                arguments: 1,
                            },
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![2])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::STRING,
                            kind: InstructionKind::Return,
                        },
                    ],
                },
            ),
            (
                preserve_identity.clone(),
                Workflow {
                    path: preserve_path,
                    parameters: vec![Parameter {
                        name: Arc::from("value"),
                        ty: TypeDescriptor::STRING,
                        mutable: false,
                        receiver_mode: None,
                    }],
                    result: TypeDescriptor::STRING,
                    effects: EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: StructuralPosition::new(vec![0])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::STRING,
                            kind: InstructionKind::Load(Arc::from("value")),
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![1])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::STRING,
                            kind: InstructionKind::Return,
                        },
                    ],
                },
            ),
        ])
        .unwrap_or_else(|error| panic!("generic program failed: {error:?}"));

        let encoded = encode_machine_program(&program);
        let decoded = decode_machine_program(&encoded)
            .unwrap_or_else(|error| panic!("generic program decode failed: {error:?}"));
        assert_eq!(decoded, program);
        assert_eq!(decoded.callable_identities()[1], preserve_identity);
        assert_eq!(encode_machine_program(&decoded), encoded);
    }

    #[test]
    fn executable_program_codec_preserves_receiver_calls() {
        let main_path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("main path failed: {error}"));
        let method_path = CanonicalPath::new("crate::Counter::value")
            .unwrap_or_else(|error| panic!("method path failed: {error}"));
        let main_identity = CanonicalCallableIdentity::free(&main_path, &[]);
        let method_identity =
            CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
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
                        Instruction {
                            site: StructuralPosition::new(vec![0])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::INT,
                            kind: InstructionKind::Push(LogicalValue::integer(
                                GantryInt::new(1)
                                    .unwrap_or_else(|| unreachable!("fixture integer is admitted")),
                            )),
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![1])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::INT,
                            kind: InstructionKind::ReceiverCall {
                                callee: method_identity.clone(),
                                arguments: 1,
                                source: ReceiverSource::CopiedValue,
                            },
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![2])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::INT,
                            kind: InstructionKind::Return,
                        },
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
                        mutable: false,
                        receiver_mode: Some(ReceiverMode::LocalCopy),
                    }],
                    result: TypeDescriptor::INT,
                    effects: EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: StructuralPosition::new(vec![0])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::INT,
                            kind: InstructionKind::Load(Arc::from("self")),
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![1])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::INT,
                            kind: InstructionKind::Return,
                        },
                    ],
                },
            ),
        ];
        callables.sort_by(|left, right| left.0.cmp(&right.0));
        let program = MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("receiver-call program failed: {error:?}"));

        let mut instruction_writer = super::Writer::default();
        super::write_instruction(
            &mut instruction_writer,
            &InstructionKind::ReceiverCall {
                callee: method_identity.clone(),
                arguments: 1,
                source: ReceiverSource::CopiedValue,
            },
        );
        assert_eq!(instruction_writer.finish()[0], 31);
        let encoded = encode_machine_program(&program);
        let decoded = decode_machine_program(&encoded)
            .unwrap_or_else(|error| panic!("receiver-call decode failed: {error:?}"));
        assert_eq!(decoded, program);
        assert_eq!(encode_machine_program(&decoded), encoded);
    }

    #[test]
    fn executable_program_codec_preserves_legacy_call_opcode_programs() {
        let method_path = CanonicalPath::new("crate::Counter::value")
            .unwrap_or_else(|error| panic!("callee path failed: {error}"));
        let method = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
            .unwrap_or_else(|error| panic!("method identity failed: {error}"));
        let caller_path = CanonicalPath::new("crate::caller")
            .unwrap_or_else(|error| panic!("caller path failed: {error}"));
        let caller = CanonicalCallableIdentity::free(&caller_path, &[]);
        let mut callables = vec![
            (
                caller,
                Workflow {
                    path: caller_path,
                    parameters: Vec::new(),
                    result: TypeDescriptor::UNIT,
                    effects: EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: StructuralPosition::new(vec![0])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Call {
                                callee: method.clone(),
                                arguments: 1,
                            },
                        },
                        Instruction {
                            site: StructuralPosition::new(vec![1])
                                .unwrap_or_else(|error| panic!("site failed: {error}")),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Return,
                        },
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
                        receiver_mode: Some(ReceiverMode::LocalCopy),
                    }],
                    result: TypeDescriptor::UNIT,
                    effects: EffectSet::default(),
                    instructions: vec![Instruction {
                        site: StructuralPosition::new(vec![0])
                            .unwrap_or_else(|error| panic!("site failed: {error}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    }],
                },
            ),
        ];
        callables.sort_by(|left, right| left.0.cmp(&right.0));
        let program = MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("legacy-call program failed: {error:?}"));
        let mut instruction_writer = super::Writer::default();
        super::write_instruction(
            &mut instruction_writer,
            &InstructionKind::Call {
                callee: CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
                    .unwrap_or_else(|error| panic!("method identity failed: {error}")),
                arguments: 1,
            },
        );
        assert_eq!(instruction_writer.finish()[0], 15);
        let encoded = encode_machine_program(&program);
        let decoded = decode_machine_program(&encoded)
            .unwrap_or_else(|error| panic!("legacy-call decode failed: {error:?}"));
        assert_eq!(decoded, program);
        assert_eq!(encode_machine_program(&decoded), encoded);
    }

    #[test]
    fn executable_program_codec_selects_v3_for_shared_caller_places_and_rejects_v2_opcode_32() {
        let caller_path = CanonicalPath::new("crate::caller")
            .unwrap_or_else(|error| panic!("caller path failed: {error}"));
        let method_path = CanonicalPath::new("crate::Outer::value")
            .unwrap_or_else(|error| panic!("method path failed: {error}"));
        let caller = CanonicalCallableIdentity::free(&caller_path, &[]);
        let method = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
            .unwrap_or_else(|error| panic!("method identity failed: {error}"));
        let outer = TypeDescriptor::declared(
            CanonicalPath::new("crate::Outer")
                .unwrap_or_else(|error| panic!("outer path failed: {error}")),
        );
        let instruction = |site: u64, ty, kind| Instruction {
            site: StructuralPosition::new(vec![site])
                .unwrap_or_else(|error| panic!("instruction site failed: {error}")),
            ty,
            kind,
        };
        let mut callables = vec![
            (
                caller,
                Workflow {
                    path: caller_path,
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
                                    path: vec![gantry_core::value::ValuePathSegment::StructField(
                                        "value".to_owned(),
                                    )],
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
        let program = MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("shared receiver program failed: {error:?}"));
        let encoded = encode_machine_program(&program);
        assert_eq!(encoded.get(..8), Some(b"GNTPRG03".as_slice()));
        assert!(encoded.contains(&32));
        assert_eq!(decode_machine_program(&encoded), Ok(program.clone()));
        let mut v2 = encoded;
        v2[..8].copy_from_slice(b"GNTPRG02");
        assert_eq!(
            decode_machine_program(&v2),
            Err(MachineRecoveryError::InvalidEncoding)
        );
    }

    #[test]
    fn executable_program_codec_selects_v3_for_an_unused_shared_receiver() {
        let main_path = CanonicalPath::new("crate::main")
            .unwrap_or_else(|error| panic!("main path failed: {error}"));
        let method_path = CanonicalPath::new("crate::Counter::value")
            .unwrap_or_else(|error| panic!("method path failed: {error}"));
        let main = CanonicalCallableIdentity::free(&main_path, &[]);
        let method = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
            .unwrap_or_else(|error| panic!("method identity failed: {error}"));
        let mut callables = vec![
            (
                main,
                Workflow {
                    path: main_path,
                    parameters: Vec::new(),
                    result: TypeDescriptor::UNIT,
                    effects: EffectSet::default(),
                    instructions: vec![Instruction {
                        site: StructuralPosition::new(vec![0])
                            .unwrap_or_else(|error| panic!("main site failed: {error}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    }],
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
                    result: TypeDescriptor::UNIT,
                    effects: EffectSet::default(),
                    instructions: vec![Instruction {
                        site: StructuralPosition::new(vec![0])
                            .unwrap_or_else(|error| panic!("method site failed: {error}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    }],
                },
            ),
        ];
        callables.sort_by(|left, right| left.0.cmp(&right.0));
        let program = MachineProgram::with_callable_identities(callables)
            .unwrap_or_else(|error| panic!("unused shared receiver program failed: {error:?}"));
        let encoded = encode_machine_program(&program);
        assert_eq!(encoded.get(..8), Some(b"GNTPRG03".as_slice()));
        assert_eq!(decode_machine_program(&encoded), Ok(program));
    }

    #[test]
    fn executable_program_codec_scans_task_bodies_for_shared_caller_places() {
        let caller_path = CanonicalPath::new("crate::caller")
            .unwrap_or_else(|error| panic!("caller path failed: {error}"));
        let method_path = CanonicalPath::new("crate::Outer::value")
            .unwrap_or_else(|error| panic!("method path failed: {error}"));
        let caller = CanonicalCallableIdentity::free(&caller_path, &[]);
        let method = CanonicalCallableIdentity::inherent(&TypeDescriptor::INT, "value", &[])
            .unwrap_or_else(|error| panic!("method identity failed: {error}"));
        let body_identity = TaskBodyIdentity::new(
            caller.clone(),
            StructuralPosition::new(vec![0])
                .unwrap_or_else(|error| panic!("spawn site failed: {error}")),
        );
        let outer = TypeDescriptor::declared(
            CanonicalPath::new("crate::Outer")
                .unwrap_or_else(|error| panic!("outer path failed: {error}")),
        );
        let body = ExecutableTaskBody::new(
            body_identity.clone(),
            TypeDescriptor::INT,
            vec![
                ExecutableTaskCapture::new(Arc::from("item"), outer, false)
                    .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
            ],
            ExecutableTaskContext::v1(),
            vec![
                Instruction {
                    site: StructuralPosition::new(vec![0, 0])
                        .unwrap_or_else(|error| panic!("body call site failed: {error}")),
                    ty: TypeDescriptor::INT,
                    kind: InstructionKind::ReceiverCall {
                        callee: method.clone(),
                        arguments: 1,
                        source: ReceiverSource::CallerPlace {
                            root: Arc::from("item"),
                            path: vec![gantry_core::value::ValuePathSegment::StructField(
                                "value".to_owned(),
                            )],
                        },
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![0, 1])
                        .unwrap_or_else(|error| panic!("body completion site failed: {error}")),
                    ty: TypeDescriptor::INT,
                    kind: InstructionKind::TaskComplete,
                },
            ],
        )
        .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
        let instruction = |site: u64, ty, kind| Instruction {
            site: StructuralPosition::new(vec![site])
                .unwrap_or_else(|error| panic!("instruction site failed: {error}")),
            ty,
            kind,
        };
        let mut callables = vec![
            (
                caller,
                Workflow {
                    path: caller_path,
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
                                body: body_identity,
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
        let program = MachineProgram::with_task_bodies(callables, vec![body])
            .unwrap_or_else(|error| panic!("task-body shared receiver program failed: {error:?}"));
        let encoded = encode_machine_program(&program);
        assert_eq!(encoded.get(..8), Some(b"GNTPRG03".as_slice()));
        assert_eq!(decode_machine_program(&encoded), Ok(program));
    }

    #[test]
    fn executable_program_codec_preserves_task_control_bodies() {
        let path = CanonicalPath::new("crate::work")
            .unwrap_or_else(|error| panic!("path failed: {error}"));
        let caller = CanonicalCallableIdentity::free(&path, &[TypeDescriptor::STRING]);
        let spawn_site = StructuralPosition::new(vec![0])
            .unwrap_or_else(|error| panic!("spawn site failed: {error}"));
        let body_identity = TaskBodyIdentity::new(caller.clone(), spawn_site.clone());
        let handle = ExecutableTaskHandle::new(Arc::from("child"), TypeDescriptor::STRING)
            .unwrap_or_else(|error| panic!("handle failed: {error:?}"));
        let body = ExecutableTaskBody::new(
            body_identity.clone(),
            TypeDescriptor::STRING,
            vec![
                ExecutableTaskCapture::new(Arc::from("message"), TypeDescriptor::STRING, true)
                    .unwrap_or_else(|error| panic!("capture failed: {error:?}")),
            ],
            ExecutableTaskContext::v1(),
            vec![
                Instruction {
                    site: StructuralPosition::new(vec![0, 0])
                        .unwrap_or_else(|error| panic!("body value site failed: {error}")),
                    ty: TypeDescriptor::STRING,
                    kind: InstructionKind::Load(Arc::from("message")),
                },
                Instruction {
                    site: StructuralPosition::new(vec![0, 1])
                        .unwrap_or_else(|error| panic!("body return site failed: {error}")),
                    ty: TypeDescriptor::STRING,
                    kind: InstructionKind::TaskComplete,
                },
            ],
        )
        .unwrap_or_else(|error| panic!("task body failed: {error:?}"));
        let instruction = |site: u64, ty, kind| Instruction {
            site: StructuralPosition::new(vec![site])
                .unwrap_or_else(|error| panic!("instruction site failed: {error}")),
            ty,
            kind,
        };
        let program = MachineProgram::with_task_bodies(
            vec![(
                caller,
                Workflow {
                    path,
                    parameters: Vec::new(),
                    result: TypeDescriptor::UNIT,
                    effects: EffectSet::default(),
                    instructions: vec![
                        instruction(
                            0,
                            TypeDescriptor::UNIT,
                            InstructionKind::Spawn {
                                handle,
                                body: body_identity,
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
            vec![body],
        )
        .unwrap_or_else(|error| panic!("task-control program failed: {error:?}"));

        let encoded = encode_machine_program(&program);
        let decoded = decode_machine_program(&encoded)
            .unwrap_or_else(|error| panic!("task-control decode failed: {error:?}"));
        assert_eq!(decoded, program);
        assert_eq!(encode_machine_program(&decoded), encoded);

        let truncated = &encoded[..encoded.len() - 1];
        assert_eq!(
            decode_machine_program(truncated),
            Err(MachineRecoveryError::InvalidEncoding)
        );
    }
}
