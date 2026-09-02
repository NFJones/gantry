//! Indexed executable program contracts consumed by the transition machine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::generated::{Effect, OperationSiteKind, RecoveryClass};
use crate::{
    ActionParameter, CanonicalCallableIdentity, CanonicalPath, CanonicalSignature, EffectSet,
    StructuralPosition, TypeDescriptor,
};
use gantry_core::value::{LogicalValue, ValuePathSegment};

use crate::Primitive;

/// Analyzer-resolved action metadata retained by one executable operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableAction {
    /// Canonical declared action path.
    pub path: CanonicalPath,
    /// Canonical declaration signature.
    pub signature: CanonicalSignature,
    /// Declared recovery class.
    pub recovery: RecoveryClass,
    /// Declaration-order typed parameters.
    pub parameters: Vec<ActionParameter>,
}

/// Typed semantic metadata for one executable integration operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableOperation {
    /// Prompt, decision, or harness-action classification.
    pub kind: OperationSiteKind,
    /// Exact successful operation result type before optional `attempt` wrapping.
    pub result_type: TypeDescriptor,
    /// Action-specific metadata, present only for an action invocation.
    pub action: Option<ExecutableAction>,
    /// Decoded prompt-template literal segments in source order.
    pub template_segments: Vec<Arc<str>>,
    /// Static types of interpolation inputs in source order.
    pub interpolation_types: Vec<TypeDescriptor>,
    /// Named model-input names in source order.
    pub named_input_names: Vec<Arc<str>>,
    /// Static types of named model inputs in source order.
    pub named_input_types: Vec<TypeDescriptor>,
    /// Optional source-level validation retry override.
    pub retry_limit: Option<u64>,
    /// Optional model session directive (`inline`, `fork`, or `new`).
    pub session_mode: Option<Arc<str>>,
    /// Whether source wraps this operation in `attempt`.
    pub attempted: bool,
}

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
    /// Select an Option arm and expose the present payload to that arm.
    BranchOption {
        /// Program counter for the `Some` arm.
        when_some: usize,
        /// Program counter for the `None` arm.
        when_none: usize,
    },
    /// Select one analyzer-validated declared-enum arm by exact variant name.
    BranchEnum {
        /// Distinct variant names and their arm program counters in source order.
        arms: Vec<(Arc<str>, usize)>,
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
        /// Analyzer-selected closed callee identity.
        callee: CanonicalCallableIdentity,
        /// Number of completed arguments.
        arguments: usize,
    },
    /// Return one completed value from the current workflow frame.
    Return,
    /// Prepare one logical operation that has no evaluated input values.
    Operation,
    /// Prepare one logical operation after capturing its completed input values.
    OperationWithOperands {
        /// Number of left-to-right values retained for immutable request capture.
        operands: usize,
    },
    /// Prepare one analyzer-resolved hook operation after capturing its input values.
    OperationCall {
        /// Complete static operation metadata.
        operation: ExecutableOperation,
        /// Number of left-to-right values retained for immutable request capture.
        operands: usize,
    },
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineProgram {
    workflows: Vec<Workflow>,
    callable_identities: Vec<CanonicalCallableIdentity>,
    callable_indexes: BTreeMap<CanonicalCallableIdentity, usize>,
    entry_indexes: BTreeMap<CanonicalPath, usize>,
}

impl MachineProgram {
    /// Validates canonical workflow order, instruction targets, and call seams.
    pub fn new(workflows: Vec<Workflow>) -> Result<Self, ProgramError> {
        let callables = workflows
            .into_iter()
            .map(|workflow| {
                (
                    CanonicalCallableIdentity::free(&workflow.path, &[]),
                    workflow,
                )
            })
            .collect();
        Self::with_callable_identities(callables)
    }

    /// Validates a program whose analyzer assigned every closed callable identity.
    pub fn with_callable_identities(
        callables: Vec<(CanonicalCallableIdentity, Workflow)>,
    ) -> Result<Self, ProgramError> {
        if callables.is_empty() {
            return Err(ProgramError::EmptyProgram);
        }
        if callables.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(ProgramError::WorkflowOrder);
        }
        let callable_identities = callables
            .iter()
            .map(|(identity, _)| identity.clone())
            .collect::<Vec<_>>();
        let workflows = callables
            .into_iter()
            .map(|(_, workflow)| workflow)
            .collect::<Vec<_>>();
        let callable_indexes = callable_identities
            .iter()
            .enumerate()
            .map(|(index, identity)| (identity.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let entry_indexes = workflows
            .iter()
            .enumerate()
            .filter(|(index, workflow)| {
                callable_identities[*index] == CanonicalCallableIdentity::free(&workflow.path, &[])
            })
            .map(|(index, workflow)| (workflow.path.clone(), index))
            .collect::<BTreeMap<_, _>>();
        for workflow in &workflows {
            validate_workflow(workflow, &workflows, &callable_indexes)?;
        }
        Ok(Self {
            workflows,
            callable_identities,
            callable_indexes,
            entry_indexes,
        })
    }

    /// Returns workflows in the same canonical callable-identity order as
    /// [`Self::callable_identities`].
    #[must_use]
    pub fn workflows(&self) -> &[Workflow] {
        &self.workflows
    }

    /// Returns closed callable identities in the same order as [`Self::workflows`].
    #[must_use]
    pub fn callable_identities(&self) -> &[CanonicalCallableIdentity] {
        &self.callable_identities
    }

    /// Resolves one canonical workflow.
    #[must_use]
    pub fn workflow(&self, path: &CanonicalPath) -> Option<&Workflow> {
        self.entry_indexes
            .get(path)
            .and_then(|index| self.workflows.get(*index))
    }

    /// Resolves one analyzer-selected closed callable identity.
    #[must_use]
    pub fn callable(&self, identity: &CanonicalCallableIdentity) -> Option<&Workflow> {
        self.callable_indexes
            .get(identity)
            .and_then(|index| self.workflows.get(*index))
    }

    /// Returns the stable index of one canonical workflow in this program.
    #[must_use]
    pub fn workflow_index(&self, path: &CanonicalPath) -> Option<usize> {
        self.entry_indexes.get(path).copied()
    }

    /// Returns the stable index of one closed callable identity.
    #[must_use]
    pub fn callable_index(&self, identity: &CanonicalCallableIdentity) -> Option<usize> {
        self.callable_indexes.get(identity).copied()
    }

    /// Returns the first reachable effect unsupported by the base sequential profile.
    #[must_use]
    pub fn unsupported_effect(&self, root: usize) -> Option<Effect> {
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
                    && let Some(index) = self.callable_index(callee)
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
    indexes: &BTreeMap<CanonicalCallableIdentity, usize>,
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
            }
            | InstructionKind::BranchOption {
                when_some: target, ..
            } if *target >= length => {
                return Err(ProgramError::InvalidTarget(workflow.path.clone()));
            }
            InstructionKind::Branch { when_false, .. } if *when_false >= length => {
                return Err(ProgramError::InvalidTarget(workflow.path.clone()));
            }
            InstructionKind::BranchOption { when_none, .. } if *when_none >= length => {
                return Err(ProgramError::InvalidTarget(workflow.path.clone()));
            }
            InstructionKind::BranchEnum { arms }
                if arms.is_empty()
                    || arms
                        .iter()
                        .any(|(variant, target)| variant.is_empty() || *target >= length)
                    || !enum_arms_are_unique(arms) =>
            {
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

fn enum_arms_are_unique(arms: &[(Arc<str>, usize)]) -> bool {
    let mut variants = BTreeSet::new();
    arms.iter()
        .all(|(variant, _)| variants.insert(variant.as_ref()))
}
