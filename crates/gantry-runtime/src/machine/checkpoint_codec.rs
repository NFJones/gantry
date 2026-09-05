//! Canonical binary codecs for task-local machine and execution-budget checkpoints.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::numeric::{GantryFloat, GantryInt};
use gantry_core::portable::{DeterministicEvaluationCode, IdentityKind, RuntimeErrorCategory};
use gantry_core::value::{
    LogicalValue, LogicalValueView, OperationErrorValue, OperationErrorView, ValueLimits,
};
#[cfg(feature = "concurrent")]
use gantry_ir::{CanonicalCallableIdentity, ExecutableTaskHandle, TaskBodyIdentity};
use gantry_ir::{
    CanonicalPath, InstructionKind, MachineProgram, StructuralPosition, TypeDescriptor,
};

use super::{
    Binding, ExecutionBudgetSnapshot, MachineCheckpointV3, MachineFailure, MachineLabel,
    MachineLimits, MachineOutcome, MachineRecoveryError, MachineStatus, OperationOccurrence,
    PendingOperation, RuntimeCode, Scope, SessionCreationModeV1, SessionScopeOccurrence,
    WorkflowFrame, validate_execution_budget_snapshot, validate_machine_checkpoint,
};
#[cfg(feature = "concurrent")]
use super::{
    HandleScope, MachineSpawnSuspension, MachineTaskCapture, MachineTaskHandle, PendingTaskControl,
};
#[cfg(feature = "concurrent")]
use crate::task::{DynamicTaskHandleIdentity, TaskCaptureV1};

const MACHINE_MAGIC: &[u8; 8] = b"GNTMCP03";
const EXECUTION_BUDGET_MAGIC: &[u8; 8] = b"GNTBGT01";
#[cfg(feature = "concurrent")]
const TASK_CONTROL_EXTENSION_MAGIC: &[u8; 8] = b"GNTMTC01";

pub(super) fn encode_execution_budget_snapshot(snapshot: &ExecutionBudgetSnapshot) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.raw(EXECUTION_BUDGET_MAGIC);
    writer.identity(snapshot.execution);
    writer.u64(snapshot.maximum_transitions);
    writer.u64(snapshot.maximum_operations);
    writer.u64(snapshot.remaining_transitions);
    writer.u64(snapshot.remaining_operations);
    writer.u64(snapshot.revision);
    writer.finish()
}

pub(super) fn decode_execution_budget_snapshot(
    bytes: &[u8],
) -> Result<ExecutionBudgetSnapshot, MachineRecoveryError> {
    let mut reader = Reader::new(bytes);
    if reader.raw(EXECUTION_BUDGET_MAGIC.len())? != EXECUTION_BUDGET_MAGIC {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    let snapshot = ExecutionBudgetSnapshot {
        execution: reader.identity(Some(IdentityKind::Execution))?,
        maximum_transitions: reader.u64()?,
        maximum_operations: reader.u64()?,
        remaining_transitions: reader.u64()?,
        remaining_operations: reader.u64()?,
        revision: reader.u64()?,
    };
    if !reader.is_empty() {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    validate_execution_budget_snapshot(&snapshot)?;
    if encode_execution_budget_snapshot(&snapshot) != bytes {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    Ok(snapshot)
}

pub(super) fn encode_machine_checkpoint(checkpoint: &MachineCheckpointV3) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.raw(MACHINE_MAGIC);
    writer.identity(checkpoint.execution);
    writer.identity(checkpoint.task_id);
    writer.strings(&checkpoint.task_path);
    writer.boolean(checkpoint.execution_foreground);
    write_limits(&mut writer, checkpoint.limits);
    writer.count(checkpoint.frames.len());
    for frame in &checkpoint.frames {
        write_frame(&mut writer, frame);
    }
    write_values(
        &mut writer,
        &checkpoint.values,
        checkpoint.limits.value_limits,
    );
    writer.strings(&checkpoint.occurrences);
    writer.string_u64_map(&checkpoint.counters);
    writer.string_u64_map(&checkpoint.source_loop_entries);
    writer.optional_string(checkpoint.agent.as_deref());
    writer.count(checkpoint.agent_stack.len());
    for agent in &checkpoint.agent_stack {
        writer.optional_string(agent.as_deref());
    }
    writer.optional_identity(checkpoint.session);
    writer.count(checkpoint.session_stack.len());
    for session in &checkpoint.session_stack {
        writer.optional_identity(*session);
    }
    writer.u64(checkpoint.remaining_loop_iterations);
    writer.u64(checkpoint.consecutive_transitions);
    write_pending_session(&mut writer, checkpoint.pending_session_scope.as_ref());
    write_pending_operation(
        &mut writer,
        checkpoint.pending_operation.as_ref(),
        checkpoint.limits.value_limits,
    );
    writer.count(checkpoint.pending_labels.len());
    for label in &checkpoint.pending_labels {
        write_label(&mut writer, label, checkpoint.limits.value_limits);
    }
    writer.optional_string(checkpoint.cancellation.as_deref());
    write_status(&mut writer, checkpoint.status);
    write_optional_outcome(
        &mut writer,
        checkpoint.outcome.as_ref(),
        checkpoint.limits.value_limits,
    );
    #[cfg(feature = "concurrent")]
    if checkpoint.task_body.is_some()
        || checkpoint.pending_task_control.is_some()
        || checkpoint
            .frames
            .iter()
            .any(|frame| frame.handle_scopes.iter().any(|scope| !scope.is_empty()))
    {
        write_task_control_extension(&mut writer, checkpoint);
    }
    writer.finish()
}

pub(super) fn decode_machine_checkpoint(
    program: &MachineProgram,
    bytes: &[u8],
) -> Result<MachineCheckpointV3, MachineRecoveryError> {
    let mut reader = Reader::new(bytes);
    if reader.raw(MACHINE_MAGIC.len())? != MACHINE_MAGIC {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    let execution = reader.identity(Some(IdentityKind::Execution))?;
    let task_id = reader.identity(Some(IdentityKind::Task))?;
    let task_path = Arc::from(reader.strings()?);
    let execution_foreground = reader.boolean()?;
    let limits = read_limits(&mut reader)?;
    let frame_count = reader.count()?;
    let mut frames = Vec::new();
    for _ in 0..frame_count {
        frames.push(read_frame(&mut reader, limits.value_limits)?);
    }
    let values = read_values(&mut reader, limits.value_limits)?;
    let occurrences = reader.strings()?;
    let counters = reader.string_u64_map()?;
    let source_loop_entries = reader.string_u64_map()?;
    let agent = reader.optional_string()?.map(Arc::from);
    let agent_count = reader.count()?;
    let mut agent_stack = Vec::new();
    for _ in 0..agent_count {
        agent_stack.push(reader.optional_string()?.map(Arc::from));
    }
    let session = reader.optional_identity(Some(IdentityKind::Session))?;
    let session_count = reader.count()?;
    let mut session_stack = Vec::new();
    for _ in 0..session_count {
        session_stack.push(reader.optional_identity(Some(IdentityKind::Session))?);
    }
    let remaining_loop_iterations = reader.u64()?;
    let consecutive_transitions = reader.u64()?;
    let pending_session_scope = read_pending_session(&mut reader)?;
    let mut pending_operation = read_pending_operation(&mut reader, program, limits.value_limits)?;
    let label_count = reader.count()?;
    let mut pending_labels = VecDeque::new();
    for _ in 0..label_count {
        pending_labels.push_back(read_label(&mut reader, program, limits.value_limits)?);
    }
    let cancellation = reader.optional_string()?.map(Arc::from);
    let status = read_status(&mut reader)?;
    let outcome = read_optional_outcome(&mut reader, limits.value_limits)?;
    #[cfg(feature = "concurrent")]
    let (task_body, pending_task_control) = if reader.is_empty() {
        (None, None)
    } else {
        read_task_control_extension(&mut reader, &mut frames, limits.value_limits)?
    };
    #[cfg(feature = "concurrent")]
    if frames.len() == 1
        && let Some(body_identity) = task_body.as_ref()
        && let Some(pending) = pending_operation.as_mut()
    {
        pending.occurrence.metadata =
            task_body_operation_metadata(program, body_identity, &pending.occurrence.site);
    }
    if !reader.is_empty() {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    let checkpoint = MachineCheckpointV3 {
        execution,
        task_id,
        task_path,
        execution_foreground,
        #[cfg(feature = "concurrent")]
        task_body,
        limits,
        frames,
        values,
        occurrences,
        counters,
        source_loop_entries,
        agent,
        agent_stack,
        session,
        session_stack,
        remaining_loop_iterations,
        consecutive_transitions,
        pending_session_scope,
        pending_operation,
        #[cfg(feature = "concurrent")]
        pending_task_control,
        pending_labels,
        cancellation,
        status,
        outcome,
    };
    validate_machine_checkpoint(program, &checkpoint)?;
    if encode_machine_checkpoint(&checkpoint) != bytes {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    Ok(checkpoint)
}

fn write_limits(writer: &mut Writer, limits: MachineLimits) {
    writer.u64(limits.maximum_deterministic_transitions);
    writer.u64(limits.maximum_operations);
    writer.u64(limits.maximum_loop_iterations);
    writer.u64(limits.maximum_workflow_call_depth);
    writer.u64(limits.deterministic_transition_yield_quantum);
    writer.u64(limits.value_limits.maximum_nesting_depth());
    writer.u64(limits.value_limits.maximum_nodes());
    writer.u64(limits.value_limits.maximum_string_scalars());
    writer.u64(limits.value_limits.maximum_list_items());
}

fn read_limits(reader: &mut Reader<'_>) -> Result<MachineLimits, MachineRecoveryError> {
    let maximum_deterministic_transitions = reader.u64()?;
    let maximum_operations = reader.u64()?;
    let maximum_loop_iterations = reader.u64()?;
    let maximum_workflow_call_depth = reader.u64()?;
    let deterministic_transition_yield_quantum = reader.u64()?;
    let value_limits = ValueLimits::new(reader.u64()?, reader.u64()?, reader.u64()?, reader.u64()?)
        .ok_or(MachineRecoveryError::InvalidCheckpoint)?;
    MachineLimits::new(
        maximum_deterministic_transitions,
        maximum_operations,
        maximum_loop_iterations,
        maximum_workflow_call_depth,
        deterministic_transition_yield_quantum,
        value_limits,
    )
    .ok_or(MachineRecoveryError::InvalidCheckpoint)
}

fn write_frame(writer: &mut Writer, frame: &WorkflowFrame) {
    writer.usize(frame.workflow);
    writer.usize(frame.pc);
    writer.count(frame.scopes.len());
    for scope in &frame.scopes {
        writer.count(scope.len());
        for (name, binding) in scope {
            writer.string(name);
            writer.string(&binding.ty.canonical_string());
            writer.boolean(binding.mutable);
            writer.value(&binding.value);
        }
    }
    writer.usize(frame.stack_base);
    writer.usize(frame.occurrence_base);
    writer.usize(frame.agent_stack_base);
    writer.optional_string(frame.agent_at_entry.as_deref());
    writer.usize(frame.session_stack_base);
    writer.optional_identity(frame.session_at_entry);
}

fn read_frame(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<WorkflowFrame, MachineRecoveryError> {
    let workflow = reader.usize()?;
    let pc = reader.usize()?;
    let scope_count = reader.count()?;
    let mut scopes = Vec::new();
    for _ in 0..scope_count {
        let binding_count = reader.count()?;
        let mut scope = Scope::new();
        for _ in 0..binding_count {
            let name: Arc<str> = Arc::from(reader.string()?);
            let ty = TypeDescriptor::from_canonical_string(&reader.string()?)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
            let mutable = reader.boolean()?;
            let value = reader.value(limits)?;
            if scope.insert(name, Binding { value, ty, mutable }).is_some() {
                return Err(MachineRecoveryError::InvalidEncoding);
            }
        }
        scopes.push(scope);
    }
    Ok(WorkflowFrame {
        workflow,
        pc,
        scopes,
        #[cfg(feature = "concurrent")]
        handle_scopes: (0..scope_count).map(|_| HandleScope::new()).collect(),
        stack_base: reader.usize()?,
        occurrence_base: reader.usize()?,
        agent_stack_base: reader.usize()?,
        agent_at_entry: reader.optional_string()?.map(Arc::from),
        session_stack_base: reader.usize()?,
        session_at_entry: reader.optional_identity(Some(IdentityKind::Session))?,
    })
}

#[cfg(feature = "concurrent")]
fn write_task_control_extension(writer: &mut Writer, checkpoint: &MachineCheckpointV3) {
    writer.raw(TASK_CONTROL_EXTENSION_MAGIC);
    writer.boolean(checkpoint.task_body.is_some());
    if let Some(identity) = &checkpoint.task_body {
        write_task_body_identity(writer, identity);
    }
    writer.count(checkpoint.frames.len());
    for frame in &checkpoint.frames {
        writer.count(frame.handle_scopes.len());
        for scope in &frame.handle_scopes {
            writer.count(scope.len());
            for (name, handle) in scope {
                writer.string(name);
                writer.identity(handle.identity.owner());
                writer.identity(handle.identity.child());
                writer.string(&handle.result_type.canonical_string());
            }
        }
    }
    writer.boolean(checkpoint.pending_task_control.is_some());
    if let Some(pending) = &checkpoint.pending_task_control {
        write_spawn_suspension(writer, &pending.spawn);
    }
}

#[cfg(feature = "concurrent")]
fn read_task_control_extension(
    reader: &mut Reader<'_>,
    frames: &mut [WorkflowFrame],
    limits: ValueLimits,
) -> Result<(Option<TaskBodyIdentity>, Option<PendingTaskControl>), MachineRecoveryError> {
    if reader.raw(TASK_CONTROL_EXTENSION_MAGIC.len())? != TASK_CONTROL_EXTENSION_MAGIC {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    let task_body = reader
        .boolean()?
        .then(|| read_task_body_identity(reader))
        .transpose()?;
    if reader.count()? != frames.len() {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    for frame in frames {
        let scope_count = reader.count()?;
        if scope_count != frame.scopes.len() {
            return Err(MachineRecoveryError::InvalidEncoding);
        }
        let mut handle_scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            let handle_count = reader.count()?;
            let mut scope = HandleScope::new();
            for _ in 0..handle_count {
                let name: Arc<str> = Arc::from(reader.string()?);
                let owner = reader.identity(Some(IdentityKind::Task))?;
                let child = reader.identity(Some(IdentityKind::Task))?;
                let result_type = TypeDescriptor::from_canonical_string(&reader.string()?)
                    .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
                if name.is_empty()
                    || scope
                        .insert(
                            name,
                            MachineTaskHandle {
                                identity: DynamicTaskHandleIdentity::from_parts(owner, child),
                                result_type,
                            },
                        )
                        .is_some()
                {
                    return Err(MachineRecoveryError::InvalidEncoding);
                }
            }
            handle_scopes.push(scope);
        }
        frame.handle_scopes = handle_scopes;
    }
    let pending_task_control = reader
        .boolean()?
        .then(|| read_spawn_suspension(reader, limits))
        .transpose()?
        .map(|spawn| PendingTaskControl { spawn });
    Ok((task_body, pending_task_control))
}

#[cfg(feature = "concurrent")]
fn write_task_body_identity(writer: &mut Writer, identity: &TaskBodyIdentity) {
    writer.string(identity.enclosing_callable().as_str());
    writer.position(identity.spawn_site());
}

#[cfg(feature = "concurrent")]
fn read_task_body_identity(
    reader: &mut Reader<'_>,
) -> Result<TaskBodyIdentity, MachineRecoveryError> {
    let callable = CanonicalCallableIdentity::from_canonical_string(&reader.string()?, u64::MAX)
        .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    Ok(TaskBodyIdentity::new(callable, reader.position()?))
}

#[cfg(feature = "concurrent")]
fn write_spawn_suspension(writer: &mut Writer, spawn: &MachineSpawnSuspension) {
    writer.string(spawn.workflow.as_str());
    writer.position(&spawn.site);
    writer.u64(spawn.occurrence);
    writer.string(spawn.handle.name());
    writer.string(&spawn.handle.result_type().canonical_string());
    write_task_body_identity(writer, &spawn.body);
    writer.count(spawn.captures.len());
    for capture in &spawn.captures {
        let capture = capture.task_capture();
        writer.string(capture.name());
        writer.string(&capture.ty().canonical_string());
        writer.boolean(capture.is_mutable());
        writer.value(capture.value());
    }
    writer.optional_string(spawn.inherited_agent.as_deref());
    writer.optional_identity(spawn.parent_session);
}

#[cfg(feature = "concurrent")]
fn read_spawn_suspension(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<MachineSpawnSuspension, MachineRecoveryError> {
    let workflow =
        CanonicalPath::new(&reader.string()?).map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    let site = reader.position()?;
    let occurrence = reader.u64()?;
    let handle_name: Arc<str> = Arc::from(reader.string()?);
    let handle_type = TypeDescriptor::from_canonical_string(&reader.string()?)
        .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    let handle = ExecutableTaskHandle::new(handle_name, handle_type)
        .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    let body = read_task_body_identity(reader)?;
    let capture_count = reader.count()?;
    let mut captures = Vec::with_capacity(capture_count);
    for _ in 0..capture_count {
        let name: Arc<str> = Arc::from(reader.string()?);
        let ty = TypeDescriptor::from_canonical_string(&reader.string()?)
            .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
        let mutable = reader.boolean()?;
        let value = reader.value(limits)?;
        let capture = TaskCaptureV1::new(name, ty, mutable, &value, limits)
            .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
        captures.push(MachineTaskCapture { capture });
    }
    Ok(MachineSpawnSuspension {
        workflow,
        site,
        occurrence,
        handle,
        body,
        captures,
        inherited_agent: reader.optional_string()?.map(Arc::from),
        parent_session: reader.optional_identity(Some(IdentityKind::Session))?,
    })
}

fn write_values(writer: &mut Writer, values: &[LogicalValue], _limits: ValueLimits) {
    writer.count(values.len());
    for value in values {
        writer.value(value);
    }
}

fn read_values(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<Vec<LogicalValue>, MachineRecoveryError> {
    let count = reader.count()?;
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(reader.value(limits)?);
    }
    Ok(values)
}

fn write_pending_session(writer: &mut Writer, pending: Option<&SessionScopeOccurrence>) {
    writer.boolean(pending.is_some());
    if let Some(pending) = pending {
        writer.string(pending.workflow.as_str());
        writer.position(&pending.site);
        writer.identity(pending.parent_session_id);
        writer.u64(pending.occurrence);
        writer.u8(match pending.mode {
            SessionCreationModeV1::EmbedderRoot => 0,
            SessionCreationModeV1::GantryRoot => 1,
            SessionCreationModeV1::New => 2,
            SessionCreationModeV1::Fork => 3,
        });
    }
}

fn read_pending_session(
    reader: &mut Reader<'_>,
) -> Result<Option<SessionScopeOccurrence>, MachineRecoveryError> {
    if !reader.boolean()? {
        return Ok(None);
    }
    let workflow =
        CanonicalPath::new(&reader.string()?).map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    let site = reader.position()?;
    let parent_session_id = reader.identity(Some(IdentityKind::Session))?;
    let occurrence = reader.u64()?;
    let mode = match reader.u8()? {
        0 => SessionCreationModeV1::EmbedderRoot,
        1 => SessionCreationModeV1::GantryRoot,
        2 => SessionCreationModeV1::New,
        3 => SessionCreationModeV1::Fork,
        _ => return Err(MachineRecoveryError::InvalidEncoding),
    };
    Ok(Some(SessionScopeOccurrence {
        workflow,
        site,
        parent_session_id,
        occurrence,
        mode,
    }))
}

fn write_pending_operation(
    writer: &mut Writer,
    pending: Option<&PendingOperation>,
    _limits: ValueLimits,
) {
    writer.boolean(pending.is_some());
    if let Some(pending) = pending {
        write_occurrence(writer, &pending.occurrence);
        writer.usize(pending.operands);
    }
}

fn read_pending_operation(
    reader: &mut Reader<'_>,
    program: &MachineProgram,
    limits: ValueLimits,
) -> Result<Option<PendingOperation>, MachineRecoveryError> {
    if !reader.boolean()? {
        return Ok(None);
    }
    Ok(Some(PendingOperation {
        occurrence: read_occurrence(reader, program, limits)?,
        operands: reader.usize()?,
    }))
}

fn write_occurrence(writer: &mut Writer, occurrence: &OperationOccurrence) {
    writer.identity(occurrence.identity);
    writer.identity(occurrence.task_id);
    writer.strings(&occurrence.task_path);
    writer.string(occurrence.workflow.as_str());
    writer.position(&occurrence.site);
    writer.strings(&occurrence.dynamic_path);
    writer.string(&occurrence.expected_type.canonical_string());
    write_values(
        writer,
        &occurrence.inputs,
        ValueLimits::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX)
            .unwrap_or_else(|| unreachable!("positive limits")),
    );
    writer.optional_string(occurrence.active_agent.as_deref());
    writer.optional_identity(occurrence.active_session);
}

fn read_occurrence(
    reader: &mut Reader<'_>,
    program: &MachineProgram,
    limits: ValueLimits,
) -> Result<OperationOccurrence, MachineRecoveryError> {
    let identity = reader.identity(Some(IdentityKind::Operation))?;
    let task_id = reader.identity(Some(IdentityKind::Task))?;
    let task_path = Arc::from(reader.strings()?);
    let workflow =
        CanonicalPath::new(&reader.string()?).map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    let site = reader.position()?;
    let dynamic_path = Arc::from(reader.strings()?);
    let expected_type = TypeDescriptor::from_canonical_string(&reader.string()?)
        .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
    let inputs = Arc::from(read_values(reader, limits)?);
    let active_agent = reader.optional_string()?.map(Arc::from);
    let active_session = reader.optional_identity(Some(IdentityKind::Session))?;
    let metadata = program
        .workflow(&workflow)
        .and_then(|workflow| {
            workflow
                .instructions
                .iter()
                .find(|instruction| instruction.site == site)
        })
        .and_then(|instruction| match &instruction.kind {
            InstructionKind::OperationCall { operation, .. } => Some(Arc::new(operation.clone())),
            InstructionKind::Operation | InstructionKind::OperationWithOperands { .. } => None,
            _ => None,
        });
    Ok(OperationOccurrence {
        identity,
        task_id,
        task_path,
        workflow,
        site,
        dynamic_path,
        expected_type,
        metadata,
        inputs,
        active_agent,
        active_session,
    })
}

#[cfg(feature = "concurrent")]
fn task_body_operation_metadata(
    program: &MachineProgram,
    body_identity: &TaskBodyIdentity,
    site: &StructuralPosition,
) -> Option<Arc<gantry_ir::ExecutableOperation>> {
    program
        .task_body(body_identity)
        .and_then(|body| {
            body.instructions()
                .iter()
                .find(|instruction| &instruction.site == site)
        })
        .and_then(|instruction| match &instruction.kind {
            InstructionKind::OperationCall { operation, .. } => Some(Arc::new(operation.clone())),
            InstructionKind::Operation | InstructionKind::OperationWithOperands { .. } => None,
            _ => None,
        })
}

fn write_status(writer: &mut Writer, status: MachineStatus) {
    writer.u8(match status {
        MachineStatus::Running => 0,
        MachineStatus::WaitingSessionScope => 1,
        MachineStatus::WaitingOperation => 2,
        #[cfg(feature = "concurrent")]
        MachineStatus::WaitingTaskControl => 7,
        MachineStatus::YieldRequired => 3,
        MachineStatus::Succeeded => 4,
        MachineStatus::Failed => 5,
        MachineStatus::Cancelled => 6,
    });
}

fn read_status(reader: &mut Reader<'_>) -> Result<MachineStatus, MachineRecoveryError> {
    match reader.u8()? {
        0 => Ok(MachineStatus::Running),
        1 => Ok(MachineStatus::WaitingSessionScope),
        2 => Ok(MachineStatus::WaitingOperation),
        #[cfg(feature = "concurrent")]
        7 => Ok(MachineStatus::WaitingTaskControl),
        3 => Ok(MachineStatus::YieldRequired),
        4 => Ok(MachineStatus::Succeeded),
        5 => Ok(MachineStatus::Failed),
        6 => Ok(MachineStatus::Cancelled),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}

fn write_optional_outcome(
    writer: &mut Writer,
    outcome: Option<&MachineOutcome>,
    limits: ValueLimits,
) {
    writer.boolean(outcome.is_some());
    if let Some(outcome) = outcome {
        write_outcome(writer, outcome, limits);
    }
}

fn read_optional_outcome(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<Option<MachineOutcome>, MachineRecoveryError> {
    reader
        .boolean()?
        .then(|| read_outcome(reader, limits))
        .transpose()
}

pub(crate) fn write_outcome(writer: &mut Writer, outcome: &MachineOutcome, _limits: ValueLimits) {
    match outcome {
        MachineOutcome::Succeeded(value) => {
            writer.u8(0);
            writer.value(value);
        }
        MachineOutcome::Failed(failure) => {
            writer.u8(1);
            write_failure(writer, failure);
        }
        MachineOutcome::Cancelled(reason) => {
            writer.u8(2);
            writer.string(reason);
        }
    }
}

pub(crate) fn read_outcome(
    reader: &mut Reader<'_>,
    limits: ValueLimits,
) -> Result<MachineOutcome, MachineRecoveryError> {
    match reader.u8()? {
        0 => Ok(MachineOutcome::Succeeded(reader.value(limits)?)),
        1 => Ok(MachineOutcome::Failed(read_failure(reader)?)),
        2 => Ok(MachineOutcome::Cancelled(Arc::from(reader.string()?))),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}

fn write_failure(writer: &mut Writer, failure: &MachineFailure) {
    write_runtime_code(writer, failure.code);
    writer.string(failure.workflow.as_str());
    writer.position(&failure.site);
}

fn read_failure(reader: &mut Reader<'_>) -> Result<MachineFailure, MachineRecoveryError> {
    Ok(MachineFailure {
        code: read_runtime_code(reader)?,
        workflow: CanonicalPath::new(&reader.string()?)
            .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
        site: reader.position()?,
    })
}

fn write_runtime_code(writer: &mut Writer, code: RuntimeCode) {
    match code {
        RuntimeCode::Deterministic(code) => {
            writer.u8(0);
            writer.string(code.wire_name());
        }
        RuntimeCode::Operation(category) => {
            writer.u8(1);
            writer.string(category.wire_name());
        }
        RuntimeCode::DeterministicTransitionBudget => writer.u8(2),
        RuntimeCode::OperationBudget => writer.u8(3),
        RuntimeCode::LoopIterationBudget => writer.u8(4),
        RuntimeCode::LoopLimitExhausted => writer.u8(5),
        RuntimeCode::UnsupportedEffect => writer.u8(6),
        RuntimeCode::InternalInvariant => writer.u8(7),
        RuntimeCode::RootSubmissionFailure => writer.u8(8),
    }
}

fn read_runtime_code(reader: &mut Reader<'_>) -> Result<RuntimeCode, MachineRecoveryError> {
    match reader.u8()? {
        0 => DeterministicEvaluationCode::from_wire_name(&reader.string()?)
            .map(RuntimeCode::Deterministic)
            .ok_or(MachineRecoveryError::InvalidEncoding),
        1 => RuntimeErrorCategory::from_wire_name(&reader.string()?)
            .map(RuntimeCode::Operation)
            .ok_or(MachineRecoveryError::InvalidEncoding),
        2 => Ok(RuntimeCode::DeterministicTransitionBudget),
        3 => Ok(RuntimeCode::OperationBudget),
        4 => Ok(RuntimeCode::LoopIterationBudget),
        5 => Ok(RuntimeCode::LoopLimitExhausted),
        6 => Ok(RuntimeCode::UnsupportedEffect),
        7 => Ok(RuntimeCode::InternalInvariant),
        8 => Ok(RuntimeCode::RootSubmissionFailure),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}

fn write_label(writer: &mut Writer, label: &MachineLabel, limits: ValueLimits) {
    match label {
        MachineLabel::Deterministic {
            workflow,
            site,
            kind,
        } => {
            writer.u8(0);
            writer.string(workflow.as_str());
            writer.position(site);
            writer.string(kind);
        }
        MachineLabel::OperationPrepared(occurrence) => {
            writer.u8(1);
            write_occurrence(writer, occurrence);
        }
        MachineLabel::OperationResult { operation } => {
            writer.u8(2);
            writer.identity(*operation);
        }
        #[cfg(feature = "concurrent")]
        MachineLabel::TaskControlSuspended(spawn) => {
            writer.u8(8);
            write_spawn_suspension(writer, spawn);
        }
        MachineLabel::Cancellation { reason } => {
            writer.u8(3);
            writer.string(reason);
        }
        MachineLabel::Failure(failure) => {
            writer.u8(4);
            write_failure(writer, failure);
        }
        MachineLabel::TaskSettled(outcome) => {
            writer.u8(5);
            write_outcome(writer, outcome, limits);
        }
        MachineLabel::ForegroundCompletion(outcome) => {
            writer.u8(6);
            write_outcome(writer, outcome, limits);
        }
        MachineLabel::TerminalCompletion(outcome) => {
            writer.u8(7);
            write_outcome(writer, outcome, limits);
        }
    }
}

fn read_label(
    reader: &mut Reader<'_>,
    program: &MachineProgram,
    limits: ValueLimits,
) -> Result<MachineLabel, MachineRecoveryError> {
    match reader.u8()? {
        0 => Ok(MachineLabel::Deterministic {
            workflow: CanonicalPath::new(&reader.string()?)
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?,
            site: reader.position()?,
            kind: Arc::from(reader.string()?),
        }),
        1 => Ok(MachineLabel::OperationPrepared(read_occurrence(
            reader, program, limits,
        )?)),
        2 => Ok(MachineLabel::OperationResult {
            operation: reader.identity(Some(IdentityKind::Operation))?,
        }),
        #[cfg(feature = "concurrent")]
        8 => Ok(MachineLabel::TaskControlSuspended(read_spawn_suspension(
            reader, limits,
        )?)),
        3 => Ok(MachineLabel::Cancellation {
            reason: Arc::from(reader.string()?),
        }),
        4 => Ok(MachineLabel::Failure(read_failure(reader)?)),
        5 => Ok(MachineLabel::TaskSettled(read_outcome(reader, limits)?)),
        6 => Ok(MachineLabel::ForegroundCompletion(read_outcome(
            reader, limits,
        )?)),
        7 => Ok(MachineLabel::TerminalCompletion(read_outcome(
            reader, limits,
        )?)),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}

#[derive(Default)]
pub(crate) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    pub(crate) fn usize(&mut self, value: usize) {
        self.u64(u64::try_from(value).unwrap_or(u64::MAX));
    }

    pub(crate) fn count(&mut self, value: usize) {
        self.usize(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.raw(value);
    }

    pub(crate) fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub(crate) fn optional_string(&mut self, value: Option<&str>) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.string(value);
        }
    }

    fn identity(&mut self, value: ProtocolIdentity) {
        self.string(&value.to_string());
    }

    fn optional_identity(&mut self, value: Option<ProtocolIdentity>) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.identity(value);
        }
    }

    pub(crate) fn position(&mut self, value: &StructuralPosition) {
        self.count(value.components().len());
        for component in value.components() {
            self.u64(*component);
        }
    }

    pub(super) fn strings(&mut self, values: &[Arc<str>]) {
        self.count(values.len());
        for value in values {
            self.string(value);
        }
    }

    fn string_u64_map(&mut self, values: &BTreeMap<String, u64>) {
        self.count(values.len());
        for (key, value) in values {
            self.string(key);
            self.u64(*value);
        }
    }

    pub(crate) fn value(&mut self, value: &LogicalValue) {
        let encoded = encode_value(value);
        self.bytes(&encoded);
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    pub(crate) fn raw(&mut self, length: usize) -> Result<&'a [u8], MachineRecoveryError> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(MachineRecoveryError::InvalidEncoding)?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, MachineRecoveryError> {
        self.raw(1).map(|bytes| bytes[0])
    }

    pub(crate) fn boolean(&mut self) -> Result<bool, MachineRecoveryError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MachineRecoveryError::InvalidEncoding),
        }
    }

    pub(crate) fn u64(&mut self) -> Result<u64, MachineRecoveryError> {
        let bytes: [u8; 8] = self
            .raw(8)?
            .try_into()
            .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(crate) fn usize(&mut self) -> Result<usize, MachineRecoveryError> {
        usize::try_from(self.u64()?).map_err(|_| MachineRecoveryError::InvalidEncoding)
    }

    pub(crate) fn count(&mut self) -> Result<usize, MachineRecoveryError> {
        let count = self.usize()?;
        if count > self.remaining() {
            return Err(MachineRecoveryError::InvalidEncoding);
        }
        Ok(count)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], MachineRecoveryError> {
        let length = self.usize()?;
        self.raw(length)
    }

    pub(crate) fn string(&mut self) -> Result<String, MachineRecoveryError> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| MachineRecoveryError::InvalidEncoding)
    }

    pub(crate) fn optional_string(&mut self) -> Result<Option<String>, MachineRecoveryError> {
        self.boolean()?.then(|| self.string()).transpose()
    }

    fn identity(
        &mut self,
        expected: Option<IdentityKind>,
    ) -> Result<ProtocolIdentity, MachineRecoveryError> {
        let value = self.string()?;
        expected
            .map_or_else(
                || ProtocolIdentity::parse(&value),
                |kind| ProtocolIdentity::parse_kind(&value, kind),
            )
            .map_err(|_| MachineRecoveryError::InvalidEncoding)
    }

    fn optional_identity(
        &mut self,
        expected: Option<IdentityKind>,
    ) -> Result<Option<ProtocolIdentity>, MachineRecoveryError> {
        self.boolean()?.then(|| self.identity(expected)).transpose()
    }

    pub(crate) fn position(&mut self) -> Result<StructuralPosition, MachineRecoveryError> {
        let count = self.count()?;
        let mut components = Vec::new();
        for _ in 0..count {
            components.push(self.u64()?);
        }
        StructuralPosition::new(components).map_err(|_| MachineRecoveryError::InvalidEncoding)
    }

    pub(super) fn strings(&mut self) -> Result<Vec<Arc<str>>, MachineRecoveryError> {
        let count = self.count()?;
        let mut values = Vec::new();
        for _ in 0..count {
            values.push(Arc::from(self.string()?));
        }
        Ok(values)
    }

    fn string_u64_map(&mut self) -> Result<BTreeMap<String, u64>, MachineRecoveryError> {
        let count = self.count()?;
        let mut values = BTreeMap::new();
        for _ in 0..count {
            let key = self.string()?;
            let value = self.u64()?;
            if values.insert(key, value).is_some() {
                return Err(MachineRecoveryError::InvalidEncoding);
            }
        }
        Ok(values)
    }

    pub(crate) fn value(
        &mut self,
        limits: ValueLimits,
    ) -> Result<LogicalValue, MachineRecoveryError> {
        decode_value(self.bytes()?, limits)
    }
}

enum ValueTask {
    Visit(LogicalValue),
    Build(ValueHeader),
}

enum ValueHeader {
    Unit,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(usize),
    Tuple(usize),
    Struct(String, Vec<String>),
    Enum(String, String, bool),
    None,
    Some,
    Result(bool),
    Decision(bool, String),
    OperationError(OperationErrorValue),
}

fn encode_value(value: &LogicalValue) -> Vec<u8> {
    let mut writer = Writer::default();
    let mut work = vec![ValueTask::Visit(value.clone())];
    while let Some(task) = work.pop() {
        match task {
            ValueTask::Visit(value) => {
                let (header, children) = value_header(&value);
                work.push(ValueTask::Build(header));
                for child in children.into_iter().rev() {
                    work.push(ValueTask::Visit(child));
                }
            }
            ValueTask::Build(header) => write_value_header(&mut writer, header),
        }
    }
    writer.finish()
}

fn value_header(value: &LogicalValue) -> (ValueHeader, Vec<LogicalValue>) {
    match value.view() {
        LogicalValueView::Unit => (ValueHeader::Unit, Vec::new()),
        LogicalValueView::Bool(value) => (ValueHeader::Bool(value), Vec::new()),
        LogicalValueView::Int(value) => (ValueHeader::Int(value.get()), Vec::new()),
        LogicalValueView::Float(value) => (ValueHeader::Float(value.get()), Vec::new()),
        LogicalValueView::String(value) => (ValueHeader::String(value.to_owned()), Vec::new()),
        LogicalValueView::List(length) => (
            ValueHeader::List(length),
            (0..length)
                .filter_map(|index| value.member(index))
                .collect(),
        ),
        LogicalValueView::Tuple(length) => (
            ValueHeader::Tuple(length),
            (0..length)
                .filter_map(|index| value.member(index))
                .collect(),
        ),
        LogicalValueView::Struct {
            type_name,
            field_count,
        } => {
            let fields = (0..field_count)
                .filter_map(|index| value.struct_field(index))
                .collect::<Vec<_>>();
            (
                ValueHeader::Struct(
                    type_name.to_owned(),
                    fields.iter().map(|(name, _)| (*name).to_owned()).collect(),
                ),
                fields.into_iter().map(|(_, value)| value).collect(),
            )
        }
        LogicalValueView::Enum {
            type_name,
            variant,
            has_payload,
        } => (
            ValueHeader::Enum(type_name.to_owned(), variant.to_owned(), has_payload),
            value.payload().into_iter().collect(),
        ),
        LogicalValueView::Option { is_some: false } => (ValueHeader::None, Vec::new()),
        LogicalValueView::Option { is_some: true } => {
            (ValueHeader::Some, value.payload().into_iter().collect())
        }
        LogicalValueView::Result { is_ok } => (
            ValueHeader::Result(is_ok),
            value.payload().into_iter().collect(),
        ),
        LogicalValueView::Decision {
            decision,
            rationale,
        } => (
            ValueHeader::Decision(decision, rationale.to_owned()),
            Vec::new(),
        ),
        LogicalValueView::OperationError(error) => (
            ValueHeader::OperationError(match error {
                OperationErrorView::Declined(message) => {
                    OperationErrorValue::Declined(message.to_owned())
                }
                OperationErrorView::InvalidOutput => OperationErrorValue::InvalidOutput,
                OperationErrorView::ProviderFailure(message) => {
                    OperationErrorValue::ProviderFailure(message.to_owned())
                }
                OperationErrorView::Timeout(message) => {
                    OperationErrorValue::Timeout(message.to_owned())
                }
                OperationErrorView::PolicyDenied(message) => {
                    OperationErrorValue::PolicyDenied(message.to_owned())
                }
                OperationErrorView::Cancelled(message) => {
                    OperationErrorValue::Cancelled(message.to_owned())
                }
                OperationErrorView::UnknownOutcome {
                    operation_id,
                    message,
                } => OperationErrorValue::UnknownOutcome {
                    operation_id: operation_id.to_owned(),
                    message: message.to_owned(),
                },
            }),
            Vec::new(),
        ),
    }
}

fn write_value_header(writer: &mut Writer, header: ValueHeader) {
    match header {
        ValueHeader::Unit => writer.u8(0),
        ValueHeader::Bool(value) => {
            writer.u8(1);
            writer.boolean(value);
        }
        ValueHeader::Int(value) => {
            writer.u8(2);
            writer.raw(&value.to_be_bytes());
        }
        ValueHeader::Float(value) => {
            writer.u8(3);
            writer.u64(value.to_bits());
        }
        ValueHeader::String(value) => {
            writer.u8(4);
            writer.string(&value);
        }
        ValueHeader::List(count) => {
            writer.u8(5);
            writer.count(count);
        }
        ValueHeader::Tuple(count) => {
            writer.u8(6);
            writer.count(count);
        }
        ValueHeader::Struct(type_name, fields) => {
            writer.u8(7);
            writer.string(&type_name);
            writer.count(fields.len());
            for field in fields {
                writer.string(&field);
            }
        }
        ValueHeader::Enum(type_name, variant, has_payload) => {
            writer.u8(8);
            writer.string(&type_name);
            writer.string(&variant);
            writer.boolean(has_payload);
        }
        ValueHeader::None => writer.u8(9),
        ValueHeader::Some => writer.u8(10),
        ValueHeader::Result(true) => writer.u8(11),
        ValueHeader::Result(false) => writer.u8(12),
        ValueHeader::Decision(decision, rationale) => {
            writer.u8(13);
            writer.boolean(decision);
            writer.string(&rationale);
        }
        ValueHeader::OperationError(error) => {
            writer.u8(14);
            write_operation_error(writer, error);
        }
    }
}

fn decode_value(bytes: &[u8], limits: ValueLimits) -> Result<LogicalValue, MachineRecoveryError> {
    let mut reader = Reader::new(bytes);
    let mut values = Vec::new();
    while !reader.is_empty() {
        let (header, child_count) = read_value_header(&mut reader)?;
        let start = values
            .len()
            .checked_sub(child_count)
            .ok_or(MachineRecoveryError::InvalidEncoding)?;
        let children = values.split_off(start);
        values.push(build_value(header, children, limits)?);
    }
    if values.len() != 1 {
        return Err(MachineRecoveryError::InvalidEncoding);
    }
    values.pop().ok_or(MachineRecoveryError::InvalidEncoding)
}

fn read_value_header(
    reader: &mut Reader<'_>,
) -> Result<(ValueHeader, usize), MachineRecoveryError> {
    match reader.u8()? {
        0 => Ok((ValueHeader::Unit, 0)),
        1 => Ok((ValueHeader::Bool(reader.boolean()?), 0)),
        2 => {
            let bytes: [u8; 8] = reader
                .raw(8)?
                .try_into()
                .map_err(|_| MachineRecoveryError::InvalidEncoding)?;
            Ok((ValueHeader::Int(i64::from_be_bytes(bytes)), 0))
        }
        3 => Ok((ValueHeader::Float(f64::from_bits(reader.u64()?)), 0)),
        4 => Ok((ValueHeader::String(reader.string()?), 0)),
        5 => {
            let count = reader.count()?;
            Ok((ValueHeader::List(count), count))
        }
        6 => {
            let count = reader.count()?;
            Ok((ValueHeader::Tuple(count), count))
        }
        7 => {
            let type_name = reader.string()?;
            let count = reader.count()?;
            let mut fields = Vec::new();
            for _ in 0..count {
                fields.push(reader.string()?);
            }
            Ok((ValueHeader::Struct(type_name, fields), count))
        }
        8 => {
            let type_name = reader.string()?;
            let variant = reader.string()?;
            let present = reader.boolean()?;
            Ok((
                ValueHeader::Enum(type_name, variant, present),
                usize::from(present),
            ))
        }
        9 => Ok((ValueHeader::None, 0)),
        10 => Ok((ValueHeader::Some, 1)),
        11 => Ok((ValueHeader::Result(true), 1)),
        12 => Ok((ValueHeader::Result(false), 1)),
        13 => Ok((
            ValueHeader::Decision(reader.boolean()?, reader.string()?),
            0,
        )),
        14 => Ok((
            ValueHeader::OperationError(read_operation_error(reader)?),
            0,
        )),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}

fn build_value(
    header: ValueHeader,
    mut children: Vec<LogicalValue>,
    limits: ValueLimits,
) -> Result<LogicalValue, MachineRecoveryError> {
    let result = match header {
        ValueHeader::Unit => Ok(LogicalValue::unit()),
        ValueHeader::Bool(value) => Ok(LogicalValue::boolean(value)),
        ValueHeader::Int(value) => GantryInt::new(value)
            .map(LogicalValue::integer)
            .ok_or(MachineRecoveryError::InvalidEncoding),
        ValueHeader::Float(value) => GantryFloat::new(value)
            .map(LogicalValue::float)
            .ok_or(MachineRecoveryError::InvalidEncoding),
        ValueHeader::String(value) => {
            LogicalValue::string(value, limits).map_err(|_| MachineRecoveryError::InvalidCheckpoint)
        }
        ValueHeader::List(_) => LogicalValue::list(children, limits)
            .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::Tuple(_) => LogicalValue::tuple(children, limits)
            .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::Struct(type_name, fields) => LogicalValue::structure(
            type_name,
            fields.into_iter().zip(children).collect(),
            limits,
        )
        .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::Enum(type_name, variant, present) => LogicalValue::enumeration(
            type_name,
            variant,
            present.then(|| children.remove(0)),
            limits,
        )
        .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::None => Ok(LogicalValue::none()),
        ValueHeader::Some => LogicalValue::some(children.remove(0), limits)
            .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::Result(true) => LogicalValue::ok(children.remove(0), limits)
            .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::Result(false) => LogicalValue::err(children.remove(0), limits)
            .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
        ValueHeader::Decision(decision, rationale) => {
            LogicalValue::decision(decision, rationale, limits)
                .map_err(|_| MachineRecoveryError::InvalidCheckpoint)
        }
        ValueHeader::OperationError(error) => LogicalValue::operation_error(error, limits)
            .map_err(|_| MachineRecoveryError::InvalidCheckpoint),
    }?;
    result
        .validate(limits)
        .map_err(|_| MachineRecoveryError::InvalidCheckpoint)?;
    Ok(result)
}

fn write_operation_error(writer: &mut Writer, error: OperationErrorValue) {
    match error {
        OperationErrorValue::Declined(message) => {
            writer.u8(0);
            writer.string(&message);
        }
        OperationErrorValue::InvalidOutput => writer.u8(1),
        OperationErrorValue::ProviderFailure(message) => {
            writer.u8(2);
            writer.string(&message);
        }
        OperationErrorValue::Timeout(message) => {
            writer.u8(3);
            writer.string(&message);
        }
        OperationErrorValue::PolicyDenied(message) => {
            writer.u8(4);
            writer.string(&message);
        }
        OperationErrorValue::Cancelled(message) => {
            writer.u8(5);
            writer.string(&message);
        }
        OperationErrorValue::UnknownOutcome {
            operation_id,
            message,
        } => {
            writer.u8(6);
            writer.string(&operation_id);
            writer.string(&message);
        }
    }
}

fn read_operation_error(
    reader: &mut Reader<'_>,
) -> Result<OperationErrorValue, MachineRecoveryError> {
    match reader.u8()? {
        0 => Ok(OperationErrorValue::Declined(reader.string()?)),
        1 => Ok(OperationErrorValue::InvalidOutput),
        2 => Ok(OperationErrorValue::ProviderFailure(reader.string()?)),
        3 => Ok(OperationErrorValue::Timeout(reader.string()?)),
        4 => Ok(OperationErrorValue::PolicyDenied(reader.string()?)),
        5 => Ok(OperationErrorValue::Cancelled(reader.string()?)),
        6 => Ok(OperationErrorValue::UnknownOutcome {
            operation_id: reader.string()?,
            message: reader.string()?,
        }),
        _ => Err(MachineRecoveryError::InvalidEncoding),
    }
}
