//! Indexed executable program contracts consumed by the transition machine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gantry_core::value::{LogicalValue, ValuePathSegment};
use gantry_ir::generated::Effect;
use gantry_ir::{CanonicalPath, EffectSet, StructuralPosition, TypeDescriptor};

use crate::primitive::Primitive;

/// One analyzed workflow parameter copied into a fresh local root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameter {
    /// Exact source binding name.
    pub name: Arc<str>,
    /// Exact analyzed parameter type.
    pub ty: TypeDescriptor,
    /// Whether the callee-local root may be replaced.
    pub mutable: bool,
}

/// Aggregate construction performed after every operand has completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateKind {
    /// Ordered homogeneous List construction.
    List,
    /// Fixed-arity Tuple construction.
    Tuple,
    /// Complete declared Struct construction in declaration-field order.
    Struct {
        /// Canonical declared type name.
        type_name: Arc<str>,
        /// Field names corresponding to stack operands.
        fields: Vec<Arc<str>>,
    },
    /// Declared Enum construction.
    Enum {
        /// Canonical declared type name.
        type_name: Arc<str>,
        /// Selected variant.
        variant: Arc<str>,
        /// Whether one payload operand is required.
        has_payload: bool,
    },
    /// Present Option construction.
    Some,
    /// Absent Option construction.
    None,
    /// Successful Result construction.
    Ok,
    /// Error Result construction.
    Err,
}

/// Deterministic projection from one already evaluated value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Projection {
    /// List or Tuple member.
    Member(usize),
    /// Named Struct field.
    Field(Arc<str>),
    /// Enum, Option, or Result payload.
    Payload,
}

/// Dynamic loop path phase.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LoopPhase {
    /// Condition evaluation.
    Condition,
    /// Body execution; this phase charges loop limits and budgets.
    Body,
}

/// One low-level instruction in deterministic semantic order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstructionKind {
    /// Push one immutable normalized value.
    Push(LogicalValue),
    /// Copy one visible binding onto the value stack.
    Load(Arc<str>),
    /// Atomically introduce one binding after its initializer is complete.
    Bind {
        /// Exact binding name.
        name: Arc<str>,
        /// Exact analyzed binding type.
        ty: TypeDescriptor,
        /// Whether later root replacement is permitted.
        mutable: bool,
    },
    /// Atomically replace one complete mutable root.
    Assign {
        /// Root binding name.
        name: Arc<str>,
        /// Nested path copied before publication.
        path: Vec<ValuePathSegment>,
        /// Exact analyzed type of the replacement expression.
        target_type: TypeDescriptor,
    },
    /// Discard one completed value.
    Pop,
    /// Construct one complete aggregate from the reported number of operands.
    Aggregate {
        /// Aggregate shape.
        kind: AggregateKind,
        /// Number of values consumed in left-to-right order.
        operands: usize,
    },
    /// Project from one completed value.
    Project(Projection),
    /// Apply one deterministic primitive to completed operands.
    Primitive(Primitive),
    /// Enter one nested lexical scope.
    EnterScope,
    /// Leave the innermost lexical scope.
    ExitScope,
    /// Jump to one instruction in the current workflow.
    Jump(usize),
    /// Select one branch from a Bool or Decision and record its dynamic arm.
    Branch {
        /// Program counter for the true arm.
        when_true: usize,
        /// Program counter for the false arm.
        when_false: usize,
    },
    /// Enter one dynamic loop condition or body occurrence.
    EnterLoop {
        /// Condition or body phase.
        phase: LoopPhase,
        /// Optional source body-entry limit; valid only for `Body`.
        source_limit: Option<u64>,
    },
    /// Leave the latest branch or loop occurrence frame.
    LeaveOccurrence,
    /// Call one workflow with the reported number of stack arguments.
    Call {
        /// Canonical callee path.
        callee: CanonicalPath,
        /// Number of completed arguments.
        arguments: usize,
    },
    /// Return one completed value from the current workflow frame.
    Return,
    /// Prepare one logical operation and suspend before host dispatch.
    Operation,
    /// Enter one active-agent dynamic scope.
    EnterAgent(Arc<str>),
    /// Restore the prior active agent.
    ExitAgent,
    /// Enter one active-session dynamic scope.
    EnterSession(Arc<str>),
    /// Restore the prior active session.
    ExitSession,
    /// Explicit cooperative cancellation checkpoint.
    CancellationCheck,
}

/// One instruction tied to its canonical structural site and result type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    /// Canonical structural position independent of source bytes.
    pub site: StructuralPosition,
    /// Static result type retained for traces and operation results.
    pub ty: TypeDescriptor,
    /// Executable operation.
    pub kind: InstructionKind,
}

/// One indexed analyzed workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Workflow {
    /// Canonical workflow path.
    pub path: CanonicalPath,
    /// Declaration-order parameters.
    pub parameters: Vec<Parameter>,
    /// Declared result type.
    pub result: TypeDescriptor,
    /// Transitive analyzed effects.
    pub effects: EffectSet,
    /// Linearized explicit-frame instructions.
    pub instructions: Vec<Instruction>,
}

/// One immutable indexed program for the task-neutral machine.
#[derive(Clone, Debug)]
pub struct MachineProgram {
    workflows: Vec<Workflow>,
    indexes: BTreeMap<CanonicalPath, usize>,
}

impl MachineProgram {
    /// Validates canonical workflow order, instruction targets, and call seams.
    pub fn new(workflows: Vec<Workflow>) -> Result<Self, ProgramError> {
        if workflows.is_empty() {
            return Err(ProgramError::EmptyProgram);
        }
        if workflows
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(ProgramError::WorkflowOrder);
        }
        let indexes = workflows
            .iter()
            .enumerate()
            .map(|(index, workflow)| (workflow.path.clone(), index))
            .collect::<BTreeMap<_, _>>();
        for workflow in &workflows {
            validate_workflow(workflow, &workflows, &indexes)?;
        }
        Ok(Self { workflows, indexes })
    }

    /// Returns workflows in canonical path order.
    #[must_use]
    pub fn workflows(&self) -> &[Workflow] {
        &self.workflows
    }

    /// Resolves one canonical workflow.
    #[must_use]
    pub fn workflow(&self, path: &CanonicalPath) -> Option<&Workflow> {
        self.indexes
            .get(path)
            .and_then(|index| self.workflows.get(*index))
    }

    pub(crate) fn workflow_index(&self, path: &CanonicalPath) -> Option<usize> {
        self.indexes.get(path).copied()
    }

    pub(crate) fn unsupported_effect(&self, root: usize) -> Option<Effect> {
        let mut pending = vec![root];
        let mut visited = BTreeSet::new();
        while let Some(index) = pending.pop() {
            if !visited.insert(index) {
                continue;
            }
            let workflow = &self.workflows[index];
            for effect in workflow.effects.iter() {
                if matches!(effect, Effect::Spawn | Effect::Join | Effect::Background) {
                    return Some(effect);
                }
            }
            for instruction in &workflow.instructions {
                if let InstructionKind::Call { callee, .. } = &instruction.kind
                    && let Some(index) = self.workflow_index(callee)
                {
                    pending.push(index);
                }
            }
        }
        None
    }
}

/// Rejection of malformed executable IR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramError {
    /// No workflow was supplied.
    EmptyProgram,
    /// Workflow paths are duplicated or not canonical-order sorted.
    WorkflowOrder,
    /// One workflow has no executable instructions.
    EmptyWorkflow(CanonicalPath),
    /// A parameter or binding name is empty or duplicated.
    InvalidBinding(CanonicalPath),
    /// Instruction structural sites are duplicated or not ordered.
    InstructionOrder(CanonicalPath),
    /// A jump target is outside its workflow.
    InvalidTarget(CanonicalPath),
    /// A call references no workflow or has the wrong arity.
    InvalidCall(CanonicalPath),
    /// Aggregate metadata and operand count disagree.
    InvalidAggregate(CanonicalPath),
    /// A source loop limit is zero or attached to a condition phase.
    InvalidLoopLimit(CanonicalPath),
}

fn validate_workflow(
    workflow: &Workflow,
    workflows: &[Workflow],
    indexes: &BTreeMap<CanonicalPath, usize>,
) -> Result<(), ProgramError> {
    if workflow.instructions.is_empty() {
        return Err(ProgramError::EmptyWorkflow(workflow.path.clone()));
    }
    let mut names = BTreeSet::new();
    if workflow
        .parameters
        .iter()
        .any(|parameter| parameter.name.is_empty() || !names.insert(parameter.name.as_ref()))
    {
        return Err(ProgramError::InvalidBinding(workflow.path.clone()));
    }
    if workflow
        .instructions
        .windows(2)
        .any(|pair| pair[0].site >= pair[1].site)
    {
        return Err(ProgramError::InstructionOrder(workflow.path.clone()));
    }
    let length = workflow.instructions.len();
    for instruction in &workflow.instructions {
        match &instruction.kind {
            InstructionKind::Jump(target)
            | InstructionKind::Branch {
                when_true: target, ..
            } if *target >= length => {
                return Err(ProgramError::InvalidTarget(workflow.path.clone()));
            }
            InstructionKind::Branch { when_false, .. } if *when_false >= length => {
                return Err(ProgramError::InvalidTarget(workflow.path.clone()));
            }
            InstructionKind::Call { callee, arguments } => {
                let Some(callee) = indexes.get(callee).and_then(|index| workflows.get(*index))
                else {
                    return Err(ProgramError::InvalidCall(workflow.path.clone()));
                };
                if *arguments != callee.parameters.len() {
                    return Err(ProgramError::InvalidCall(workflow.path.clone()));
                }
            }
            InstructionKind::Aggregate { kind, operands } => {
                let valid = match kind {
                    AggregateKind::List => true,
                    AggregateKind::Tuple => *operands >= 2,
                    AggregateKind::Struct { type_name, fields } => {
                        !type_name.is_empty()
                            && fields.len() == *operands
                            && fields.iter().all(|field| !field.is_empty())
                            && fields.windows(2).all(|pair| pair[0] != pair[1])
                    }
                    AggregateKind::Enum {
                        type_name,
                        variant,
                        has_payload,
                    } => {
                        !type_name.is_empty()
                            && !variant.is_empty()
                            && *operands == usize::from(*has_payload)
                    }
                    AggregateKind::Some | AggregateKind::Ok | AggregateKind::Err => *operands == 1,
                    AggregateKind::None => *operands == 0,
                };
                if !valid {
                    return Err(ProgramError::InvalidAggregate(workflow.path.clone()));
                }
            }
            InstructionKind::EnterLoop {
                phase,
                source_limit,
            } if source_limit == &Some(0)
                || matches!(phase, LoopPhase::Condition) && source_limit.is_some() =>
            {
                return Err(ProgramError::InvalidLoopLimit(workflow.path.clone()));
            }
            _ => {}
        }
    }
    Ok(())
}
