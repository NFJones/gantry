//! Task-neutral explicit-frame execution for analyzed Gantry programs.
//!
//! This crate owns the one deterministic machine later refined by concurrent
//! scheduling and durable recovery. It contains no host orchestration,
//! executor implementation, hook transport, or journal backend.

mod machine;
mod primitive;
mod program;

pub use machine::{
    Machine, MachineBuildError, MachineFailure, MachineLabel, MachineLimits, MachineOutcome,
    MachineStatus, MachineStep, OperationCompletionError, OperationOccurrence, RuntimeCode,
};
pub use primitive::{Comparison, Primitive};
pub use program::{
    AggregateKind, Instruction, InstructionKind, LoopPhase, MachineProgram, Parameter,
    ProgramError, Projection, Workflow,
};

#[cfg(test)]
mod tests;
