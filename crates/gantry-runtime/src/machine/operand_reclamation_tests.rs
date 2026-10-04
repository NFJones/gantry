//! Test-only observation of place-origin destruction during real value publication.
//!
//! Logical values are dropped before their paired origins. A thread-local observer avoids
//! global test races and adds no fields, callbacks or destruction behavior to production builds.

use std::cell::RefCell;
use std::sync::{Arc, Weak};

use super::*;

/// Unreadable settlement authority must not publish a result or release accepted work.
#[test]
fn unreadable_operation_lease_refuses_settlement_without_mutation() {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let program = Arc::new(
        MachineProgram::new(vec![gantry_ir::Workflow {
            path: root.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: gantry_ir::EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Operation,
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9e; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let operation = match machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation.identity,
        other => panic!("operation: {other:?}"),
    };
    let lease = Arc::clone(
        &machine
            .pending_operation
            .as_ref()
            .unwrap_or_else(|| panic!("pending operation"))
            .resource_admission_open,
    );
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = lease.lock().unwrap_or_else(|_| panic!("fixture lease"));
            panic!("poison settlement authority");
        })
        .is_err()
    );
    let values = machine.values.clone();
    let places = machine.values_places.clone();
    let frames = machine.frames.clone();
    let budget = machine.execution_budget.snapshot();
    #[cfg(feature = "durable")]
    let checkpoint = machine.checkpoint().canonical_bytes();
    assert_eq!(
        machine.complete_operation(operation, LogicalValue::unit()),
        Err(OperationCompletionError::NotWaiting)
    );
    assert_eq!(
        machine.fail_operation_with_code(operation, RuntimeCode::InternalInvariant),
        Err(OperationCompletionError::NotWaiting)
    );
    assert_eq!(machine.values, values);
    assert_eq!(machine.values_places, places);
    assert_eq!(machine.frames, frames);
    assert_eq!(machine.execution_budget.snapshot(), budget);
    assert_eq!(machine.status(), MachineStatus::WaitingOperation);
    assert!(machine.outcome().is_none());
    assert!(machine.pending_operation.is_some());
    assert!(
        lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending,
        "refusal must not close accepted work even on poisoned authority"
    );
    #[cfg(feature = "durable")]
    assert_eq!(machine.checkpoint().canonical_bytes(), checkpoint);
}

/// One scoped observer for a uniquely owned consumed place origin.
struct Probe {
    root: Weak<str>,
    budget: ExecutionBudget,
    observations: Vec<(bool, bool, Option<u64>)>,
}

thread_local! {
    /// Observation is scoped to the executing test thread, never retained in checkpoints.
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
    /// A selected String binding's destruction boundary, without retaining its value.
    static BINDING_PROBE: RefCell<Option<BindingProbe>> = const { RefCell::new(None) };
}

/// Test-only facts identifying one immutable String allocation and shared budget.
struct BindingProbe {
    address: usize,
    budget: ExecutionBudget,
    observations: Vec<Option<u64>>,
}

/// Observes the binding before ordinary field destruction; production bindings have no hook.
impl Drop for Binding {
    fn drop(&mut self) {
        BINDING_PROBE.with(|cell| {
            let mut held = cell.borrow_mut();
            let Some(probe) = held.as_mut() else {
                return;
            };
            if self
                .value
                .as_string()
                .is_none_or(|text| text.as_ptr() as usize != probe.address)
            {
                return;
            }
            probe.observations.push(
                probe
                    .budget
                    .inner
                    .try_lock()
                    .ok()
                    .map(|state| state.revision),
            );
        });
    }
}

/// Scope removal must publish once and reclaim retained bindings after the counter mutex unlocks.
#[test]
fn exited_scope_bindings_are_reclaimed_after_budget_unlock() {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let program = Arc::new(
        MachineProgram::new(vec![gantry_ir::Workflow {
            path: root.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: gantry_ir::EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::ExitScope,
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x96; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let value = LogicalValue::string("é".repeat(10_000), limits.value_limits)
        .unwrap_or_else(|error| panic!("binding value: {error:?}"));
    let address = value
        .as_string()
        .unwrap_or_else(|| panic!("String fixture"))
        .as_ptr() as usize;
    let mut scope = Scope::new();
    scope.insert(
        Arc::from("retained"),
        Binding {
            value,
            ty: TypeDescriptor::STRING,
            mutable: false,
        },
    );
    machine.frames[0].scopes.push(scope);
    #[cfg(feature = "concurrent")]
    machine.frames[0].handle_scopes.push(HandleScope::new());
    BINDING_PROBE.with(|cell| {
        *cell.borrow_mut() = Some(BindingProbe {
            address,
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let observations = BINDING_PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("probe exists"))
            .observations
    });
    assert_eq!(observations, vec![Some(1)]);
    assert!(
        matches!(step, MachineStep::Transition(MachineLabel::Deterministic { kind, .. })
        if kind.as_ref() == "scope-exit")
    );
    assert_eq!(machine.frames[0].scopes.len(), 1);
    #[cfg(feature = "concurrent")]
    assert_eq!(machine.frames[0].handle_scopes.len(), 1);
    assert_eq!(machine.frames[0].pc, 1);
    assert_eq!(machine.execution_budget.snapshot().revision, 1);
}

/// Callable admission must preserve refusal state and reclaim argument origins unlocked.
#[test]
fn call_admission_reclaims_origins_after_unlock_and_preserves_refusals() {
    for variant in 0..3 {
        let root =
            CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error}"));
        let callee =
            CanonicalPath::new("crate::callee").unwrap_or_else(|error| panic!("callee: {error}"));
        let site = |index| {
            StructuralPosition::new(vec![index]).unwrap_or_else(|error| panic!("site: {error}"))
        };
        let program = Arc::new(
            MachineProgram::new(vec![
                gantry_ir::Workflow {
                    path: callee.clone(),
                    parameters: vec![Parameter {
                        name: Arc::from("input"),
                        ty: TypeDescriptor::STRING,
                        mutable: false,
                        receiver_mode: None,
                    }],
                    result: TypeDescriptor::UNIT,
                    effects: gantry_ir::EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: site(0),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Push(LogicalValue::unit()),
                        },
                        Instruction {
                            site: site(1),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Return,
                        },
                    ],
                },
                gantry_ir::Workflow {
                    path: root.clone(),
                    parameters: Vec::new(),
                    result: TypeDescriptor::UNIT,
                    effects: gantry_ir::EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: site(0),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Call {
                                callee: CanonicalCallableIdentity::free(&callee, &[]),
                                arguments: 1,
                            },
                        },
                        Instruction {
                            site: site(1),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Return,
                        },
                    ],
                },
            ])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
        );
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9f; 32])
            .unwrap_or_else(|error| panic!("execution: {error}"));
        let limits = MachineLimits::new(8, 1, 1, 2, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits"));
        let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
            .unwrap_or_else(|error| panic!("machine: {error:?}"));
        let origin: Arc<str> = Arc::from("call-argument-origin");
        let weak = Arc::downgrade(&origin);
        let value = if variant == 2 {
            LogicalValue::unit()
        } else {
            LogicalValue::string("é".repeat(10_000), limits.value_limits)
                .unwrap_or_else(|error| panic!("value: {error:?}"))
        };
        machine.push_staged(
            value,
            Some(LoadedPlace {
                root: origin,
                path: Vec::new(),
            }),
        );
        if variant != 0 {
            let mut budget = machine.execution_budget.lock();
            for _ in 0..8 {
                ExecutionBudget::charge_transition(&mut budget)
                    .unwrap_or_else(|error| panic!("exhaustion: {error:?}"));
            }
        }
        let before = machine.execution_budget.snapshot();
        let frames = (variant != 0).then(|| machine.frames.clone());
        let values = (variant != 0).then(|| machine.values.clone());
        let occurrences = machine.occurrences.clone();
        PROBE.with(|cell| {
            *cell.borrow_mut() = Some(Probe {
                root: weak.clone(),
                budget: machine.execution_budget.clone(),
                observations: Vec::new(),
            })
        });
        let step = machine.step();
        let observations = PROBE.with(|cell| {
            cell.borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("probe"))
                .observations
        });
        if variant == 0 {
            assert_eq!(observations, vec![(true, true, Some(1))]);
            assert!(weak.upgrade().is_none());
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Deterministic {
                kind, workflow, site: actual_site,
            }) if kind.as_ref() == "call" && workflow == root && actual_site == site(0))
            );
            assert_eq!(machine.frames.len(), 2);
            assert_eq!(machine.frames[0].pc, 1);
            assert_eq!(machine.frames[1].pc, 0);
            assert_eq!(
                machine
                    .binding("input")
                    .and_then(|binding| binding.value.as_string())
                    .map(str::len),
                Some(20_000)
            );
            assert!(machine.values.is_empty());
            assert!(machine.values_places.is_empty());
            assert_eq!(machine.execution_budget.snapshot().revision, 1);
        } else {
            let expected = if variant == 1 {
                RuntimeCode::DeterministicTransitionBudget
            } else {
                RuntimeCode::InternalInvariant
            };
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
                if failure.code == expected && failure.workflow == root && failure.site == site(0))
            );
            assert!(observations.is_empty());
            assert_eq!(Some(machine.frames.clone()), frames);
            assert_eq!(Some(machine.values.clone()), values);
            assert_eq!(machine.occurrences, occurrences);
            assert_eq!(machine.execution_budget.snapshot(), before);
            assert!(Weak::ptr_eq(
                &weak,
                &Arc::downgrade(
                    &machine.values_places[0]
                        .as_ref()
                        .unwrap_or_else(|| panic!("origin"))
                        .root
                )
            ));
        }
    }
}

/// A real nonroot return must dispose callee bindings after releasing shared counters.
#[test]
fn returned_callee_bindings_are_reclaimed_after_budget_unlock() {
    assert_return_reclamation(8, false, None);
    assert_return_reclamation(2, false, Some(RuntimeCode::DeterministicTransitionBudget));
    assert_return_reclamation(2, true, Some(RuntimeCode::InternalInvariant));
}

/// Exercises successful restoration and refused returns with independently observed ownership.
fn assert_return_reclamation(
    transitions: u64,
    invalid_result: bool,
    expected: Option<RuntimeCode>,
) {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let callee =
        CanonicalPath::new("crate::callee").unwrap_or_else(|error| panic!("callee: {error:?}"));
    let site = |index| {
        StructuralPosition::new(vec![index]).unwrap_or_else(|error| panic!("site: {error:?}"))
    };
    let instruction = |index, kind| Instruction {
        site: site(index),
        ty: TypeDescriptor::UNIT,
        kind,
    };
    let program = Arc::new(
        MachineProgram::new(vec![
            gantry_ir::Workflow {
                path: callee.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    instruction(0, InstructionKind::Push(LogicalValue::unit())),
                    instruction(1, InstructionKind::Return),
                ],
            },
            gantry_ir::Workflow {
                path: root.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    instruction(
                        0,
                        InstructionKind::Call {
                            callee: CanonicalCallableIdentity::free(&callee, &[]),
                            arguments: 0,
                        },
                    ),
                    instruction(1, InstructionKind::Return),
                ],
            },
        ])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x98; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(
        transitions,
        1,
        1,
        2,
        8,
        gantry_core::value::DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    assert_eq!(machine.frames.len(), 2);
    let value = LogicalValue::string("é".repeat(10_000), limits.value_limits)
        .unwrap_or_else(|error| panic!("value: {error:?}"));
    let address = value
        .as_string()
        .unwrap_or_else(|| panic!("String fixture"))
        .as_ptr() as usize;
    machine
        .frames
        .last_mut()
        .unwrap_or_else(|| panic!("callee frame"))
        .scopes[0]
        .insert(
            Arc::from("retained"),
            Binding {
                value,
                ty: TypeDescriptor::STRING,
                mutable: false,
            },
        );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let before = machine.execution_budget.snapshot();
    if invalid_result {
        machine.values[0] = LogicalValue::boolean(true);
    }
    let frames = expected.map(|_| machine.frames.clone());
    let values = machine.values.clone();
    let places = machine.values_places.clone();
    let occurrences = machine.occurrences.clone();
    let agent = machine.agent.clone();
    let session = machine.session;
    BINDING_PROBE.with(|cell| {
        *cell.borrow_mut() = Some(BindingProbe {
            address,
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let observations = BINDING_PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("probe exists"))
            .observations
    });
    if let Some(code) = expected {
        assert!(
            matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == code && failure.workflow == callee && failure.site == site(1))
        );
        assert!(
            observations.is_empty(),
            "refused return must not reclaim callee bindings"
        );
        assert_eq!(Some(machine.frames.clone()), frames);
        assert_eq!(machine.values, values);
        assert_eq!(machine.values_places, places);
        assert_eq!(machine.occurrences, occurrences);
        assert_eq!(machine.agent, agent);
        assert_eq!(machine.session, session);
        assert_eq!(machine.execution_budget.snapshot(), before);
        return;
    }
    assert_eq!(observations, vec![Some(before.revision + 1)]);
    assert!(
        matches!(step, MachineStep::Transition(MachineLabel::Deterministic { kind, .. }) if kind.as_ref() == "return")
    );
    assert_eq!(machine.frames.len(), 1);
    assert_eq!(machine.frames[0].pc, 1);
    assert_eq!(machine.values, vec![LogicalValue::unit()]);
    assert_eq!(machine.values_places, vec![None]);
    assert_eq!(
        machine.execution_budget.snapshot().revision,
        before.revision + 1
    );
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    assert_eq!(
        machine.execution_budget.snapshot().revision,
        before.revision + 1,
        "root return remains uncharged"
    );
}

/// Refused exits preserve lexical ownership and structural errors precede exhausted budgets.
#[test]
fn refused_scope_exit_preserves_scopes_and_structural_precedence() {
    assert_refused_scope_exit(true, false, RuntimeCode::DeterministicTransitionBudget);
    assert_refused_scope_exit(false, false, RuntimeCode::InternalInvariant);
    #[cfg(feature = "concurrent")]
    assert_refused_scope_exit(true, true, RuntimeCode::InternalInvariant);
}

/// Drives actual ExitScope dispatch with exhausted counters and observed binding ownership.
fn assert_refused_scope_exit(nested: bool, misaligned: bool, expected: RuntimeCode) {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let site = StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
    let program = Arc::new(
        MachineProgram::new(vec![gantry_ir::Workflow {
            path: root.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: gantry_ir::EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: site.clone(),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::ExitScope,
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x97; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    if nested {
        machine.frames[0].scopes.push(Scope::new());
        #[cfg(feature = "concurrent")]
        if !misaligned {
            machine.frames[0].handle_scopes.push(HandleScope::new());
        }
    }
    #[cfg(not(feature = "concurrent"))]
    assert!(!misaligned, "alignment case requires concurrent profile");
    let value = LogicalValue::string("retained scope value", limits.value_limits)
        .unwrap_or_else(|error| panic!("value: {error:?}"));
    let address = value
        .as_string()
        .unwrap_or_else(|| panic!("String fixture"))
        .as_ptr() as usize;
    machine.frames[0]
        .scopes
        .last_mut()
        .unwrap_or_else(|| panic!("scope exists"))
        .insert(
            Arc::from("retained"),
            Binding {
                value,
                ty: TypeDescriptor::STRING,
                mutable: false,
            },
        );
    {
        let mut state = machine.execution_budget.lock();
        for _ in 0..8 {
            ExecutionBudget::charge_transition(&mut state)
                .unwrap_or_else(|error| panic!("exhaust budget: {error:?}"));
        }
    }
    let scopes = machine.frames[0].scopes.clone();
    #[cfg(feature = "concurrent")]
    let handles = machine.frames[0].handle_scopes.clone();
    let before = machine.execution_budget.snapshot();
    let pc = machine.frames[0].pc;
    BINDING_PROBE.with(|cell| {
        *cell.borrow_mut() = Some(BindingProbe {
            address,
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let observations = BINDING_PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("probe exists"))
            .observations
    });
    assert!(
        matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
        if failure.code == expected && failure.workflow == root && failure.site == site)
    );
    assert!(
        observations.is_empty(),
        "a rejected exit must not destroy bindings: {observations:?}"
    );
    assert_eq!(machine.frames[0].scopes, scopes);
    #[cfg(feature = "concurrent")]
    assert_eq!(machine.frames[0].handle_scopes, handles);
    assert_eq!(machine.frames[0].pc, pc);
    assert_eq!(machine.execution_budget.snapshot(), before);
    assert_eq!(
        machine
            .binding("retained")
            .and_then(|binding| binding.value.as_string())
            .map(|text| text.as_ptr() as usize),
        Some(address)
    );
}

/// Test builds observe only the selected origin; ordinary origins keep their normal field drop.
impl Drop for LoadedPlace {
    fn drop(&mut self) {
        PROBE.with(|cell| {
            let mut held = cell.borrow_mut();
            let Some(probe) = held.as_mut() else {
                return;
            };
            if !Weak::ptr_eq(&probe.root, &Arc::downgrade(&self.root)) {
                return;
            }
            let revision = probe
                .budget
                .inner
                .try_lock()
                .ok()
                .map(|state| state.revision);
            probe.observations.push((
                Arc::strong_count(&self.root) == 1,
                revision.is_some(),
                revision,
            ));
        });
    }
}

/// Old locked truncation drops this origin while try_lock fails; deferred disposal must not.
#[test]
fn consumed_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(ReclamationOperation::Primitive);
}

/// Aggregate publication must release consumed origins after unlocking, just like primitives.
#[test]
fn aggregate_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(ReclamationOperation::Aggregate);
}

/// Discard must release consumed values and origins only after counter publication unlocks.
#[test]
fn discarded_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(ReclamationOperation::Discard);
}

/// Binding must retain the consumed origin until its charged publication releases counters.
#[test]
fn bound_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(ReclamationOperation::Binding);
}

/// Boolean branching must retain its consumed origin until counters unlock.
#[test]
fn branched_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(ReclamationOperation::Branch);
}

/// An absent Option must dispose its consumed origin outside shared counters.
#[test]
fn option_branch_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(ReclamationOperation::OptionNone);
}

/// Structural binding refusals precede exhausted counters and preserve staged ownership.
#[test]
fn refused_binding_preserves_operands_scopes_and_precedence() {
    for variant in 0..5 {
        let root =
            CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
        let site =
            StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
        let program = Arc::new(
            MachineProgram::new(vec![gantry_ir::Workflow {
                path: root.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    Instruction {
                        site: site.clone(),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Bind {
                            name: Arc::from("bound"),
                            ty: TypeDescriptor::STRING,
                            mutable: false,
                        },
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![1])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                ],
            }])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
        );
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x99; 32])
            .unwrap_or_else(|error| panic!("execution: {error:?}"));
        let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits"));
        let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
            .unwrap_or_else(|error| panic!("machine: {error:?}"));
        let origin: Arc<str> = Arc::from("refused-binding-origin");
        let weak = Arc::downgrade(&origin);
        if variant != 3 {
            let value = if variant == 2 {
                LogicalValue::unit()
            } else {
                LogicalValue::string("retained input", limits.value_limits)
                    .unwrap_or_else(|error| panic!("value: {error:?}"))
            };
            machine.push_staged(
                value,
                Some(LoadedPlace {
                    root: origin,
                    path: Vec::new(),
                }),
            );
        } else {
            drop(origin);
        }
        if variant == 1 {
            machine.frames[0].scopes[0].insert(
                Arc::from("bound"),
                Binding {
                    value: LogicalValue::unit(),
                    ty: TypeDescriptor::UNIT,
                    mutable: false,
                },
            );
        }
        if variant == 4 {
            machine.frames[0].scopes.clear();
        }
        {
            let mut budget = machine.execution_budget.lock();
            for _ in 0..8 {
                ExecutionBudget::charge_transition(&mut budget)
                    .unwrap_or_else(|error| panic!("exhaustion: {error:?}"));
            }
        }
        let before = machine.execution_budget.snapshot();
        let values = machine.values.clone();
        let scopes = machine.frames[0].scopes.clone();
        let origin_count = machine.values_places.len();
        PROBE.with(|cell| {
            *cell.borrow_mut() = Some(Probe {
                root: weak.clone(),
                budget: machine.execution_budget.clone(),
                observations: Vec::new(),
            })
        });
        let step = machine.step();
        let observations = PROBE.with(|cell| {
            cell.borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("probe"))
                .observations
        });
        let expected = if variant == 0 {
            RuntimeCode::DeterministicTransitionBudget
        } else {
            RuntimeCode::InternalInvariant
        };
        assert!(
            matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == expected && failure.workflow == root && failure.site == site)
        );
        assert!(
            observations.is_empty(),
            "refusal must not dispose the origin"
        );
        assert_eq!(machine.execution_budget.snapshot(), before);
        assert_eq!(machine.values, values);
        assert_eq!(machine.frames[0].scopes, scopes);
        assert_eq!(machine.frames[0].pc, 0);
        assert_eq!(machine.values_places.len(), origin_count);
        if variant != 3 {
            let held = machine.values_places[0]
                .as_ref()
                .unwrap_or_else(|| panic!("origin"));
            assert!(Weak::ptr_eq(&weak, &Arc::downgrade(&held.root)));
        }
    }
}

/// Branch target/occurrence publication is atomic and structural errors precede exhaustion.
#[test]
fn branch_publication_preserves_targets_and_refusal_precedence() {
    for variant in 0..5 {
        let root =
            CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
        let site =
            StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
        let program = Arc::new(
            MachineProgram::new(vec![gantry_ir::Workflow {
                path: root.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    Instruction {
                        site: site.clone(),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Branch {
                            when_true: 1,
                            when_false: 2,
                        },
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![1])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![2])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                ],
            }])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
        );
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9a; 32])
            .unwrap_or_else(|error| panic!("execution: {error:?}"));
        let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits"));
        let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
            .unwrap_or_else(|error| panic!("machine: {error:?}"));
        if variant != 4 {
            machine.push_staged(
                if variant == 3 {
                    LogicalValue::unit()
                } else {
                    LogicalValue::boolean(variant != 1)
                },
                None,
            );
        }
        if variant >= 2 {
            let mut budget = machine.execution_budget.lock();
            for _ in 0..8 {
                ExecutionBudget::charge_transition(&mut budget)
                    .unwrap_or_else(|error| panic!("exhaustion: {error:?}"));
            }
        }
        let before = machine.execution_budget.snapshot();
        let values = machine.values.clone();
        let places = machine.values_places.clone();
        let occurrences = machine.occurrences.clone();
        let step = machine.step();
        if variant < 2 {
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Deterministic {
                workflow, site: actual_site, kind,
            }) if workflow == root && actual_site == site && kind.as_ref() == "branch")
            );
            assert_eq!(machine.frames[0].pc, if variant == 0 { 1 } else { 2 });
            assert_eq!(
                machine.occurrences.last().map(|value| value.as_ref()),
                Some(if variant == 0 {
                    "branch:crate::main:0:0"
                } else {
                    "branch:crate::main:0:1"
                })
            );
            assert!(machine.values.is_empty());
            assert_eq!(
                machine.execution_budget.snapshot().revision,
                before.revision + 1
            );
        } else {
            let expected = if variant == 2 {
                RuntimeCode::DeterministicTransitionBudget
            } else {
                RuntimeCode::InternalInvariant
            };
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
                if failure.code == expected && failure.workflow == root && failure.site == site)
            );
            assert_eq!(machine.values, values);
            assert_eq!(machine.values_places, places);
            assert_eq!(machine.occurrences, occurrences);
            assert_eq!(machine.frames[0].pc, 0);
            assert_eq!(machine.execution_budget.snapshot(), before);
        }
    }
}

/// Option dispatch preserves payload origins and rejects without partial branch publication.
#[test]
fn option_branch_preserves_payload_origins_and_refusal_precedence() {
    for variant in 0..6 {
        let root =
            CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
        let site =
            StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
        let program = Arc::new(
            MachineProgram::new(vec![gantry_ir::Workflow {
                path: root.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    Instruction {
                        site: site.clone(),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::BranchOption {
                            when_some: 1,
                            when_none: 2,
                        },
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![1])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![2])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                ],
            }])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
        );
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9b; 32])
            .unwrap_or_else(|error| panic!("execution: {error:?}"));
        let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits"));
        let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
            .unwrap_or_else(|error| panic!("machine: {error:?}"));
        if variant != 5 {
            let value = match variant {
                1 | 3 => LogicalValue::none(),
                4 => LogicalValue::unit(),
                _ => LogicalValue::some(LogicalValue::unit(), limits.value_limits)
                    .unwrap_or_else(|error| panic!("Some: {error:?}")),
            };
            machine.push_staged(
                value,
                Some(LoadedPlace {
                    root: Arc::from("option-origin"),
                    path: vec![ValuePathSegment::ListItem(0)],
                }),
            );
        }
        if variant >= 2 {
            let mut budget = machine.execution_budget.lock();
            for _ in 0..8 {
                ExecutionBudget::charge_transition(&mut budget)
                    .unwrap_or_else(|error| panic!("exhaustion: {error:?}"));
            }
        }
        let before = machine.execution_budget.snapshot();
        let values = machine.values.clone();
        let places = machine.values_places.clone();
        let occurrences = machine.occurrences.clone();
        let step = machine.step();
        if variant < 2 {
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Deterministic {
                workflow, site: actual_site, kind,
            }) if workflow == root && actual_site == site && kind.as_ref() == "branch")
            );
            assert_eq!(machine.frames[0].pc, if variant == 0 { 1 } else { 2 });
            assert_eq!(
                machine.occurrences.last().map(|value| value.as_ref()),
                Some(if variant == 0 {
                    "branch:crate::main:0:0"
                } else {
                    "branch:crate::main:0:1"
                })
            );
            if variant == 0 {
                assert_eq!(machine.values, vec![LogicalValue::unit()]);
                assert_eq!(
                    machine.values_places,
                    vec![Some(LoadedPlace {
                        root: Arc::from("option-origin"),
                        path: vec![ValuePathSegment::ListItem(0), ValuePathSegment::OptionValue],
                    })]
                );
            } else {
                assert!(machine.values.is_empty());
                assert!(machine.values_places.is_empty());
            }
            assert_eq!(
                machine.execution_budget.snapshot().revision,
                before.revision + 1
            );
        } else {
            let expected = if variant < 4 {
                RuntimeCode::DeterministicTransitionBudget
            } else {
                RuntimeCode::InternalInvariant
            };
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
                if failure.code == expected && failure.workflow == root && failure.site == site)
            );
            assert_eq!(machine.values, values);
            assert_eq!(machine.values_places, places);
            assert_eq!(machine.occurrences, occurrences);
            assert_eq!(machine.frames[0].pc, 0);
            assert_eq!(machine.execution_budget.snapshot(), before);
        }
    }
}

/// Result publication must preserve its payload place and release temporary ownership unlocked.
#[test]
fn result_branch_preserves_payload_origins_and_unlocked_reclamation() {
    for variant in 0..6 {
        let root =
            CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
        let site =
            StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
        let program = Arc::new(
            MachineProgram::new(vec![gantry_ir::Workflow {
                path: root.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    Instruction {
                        site: site.clone(),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::BranchResult {
                            when_ok: 1,
                            when_err: 2,
                        },
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![1])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![2])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                ],
            }])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
        );
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9c; 32])
            .unwrap_or_else(|error| panic!("execution: {error:?}"));
        let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits"));
        let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
            .unwrap_or_else(|error| panic!("machine: {error:?}"));
        let origin: Arc<str> = Arc::from("result-origin");
        let weak = Arc::downgrade(&origin);
        if variant != 5 {
            let value = match variant {
                1 | 3 => LogicalValue::err(LogicalValue::unit(), limits.value_limits),
                4 => Ok(LogicalValue::unit()),
                _ => LogicalValue::ok(LogicalValue::unit(), limits.value_limits),
            }
            .unwrap_or_else(|error| panic!("operand: {error:?}"));
            machine.push_staged(
                value,
                Some(LoadedPlace {
                    root: origin,
                    path: vec![ValuePathSegment::ListItem(0)],
                }),
            );
        } else {
            drop(origin);
        }
        if variant >= 2 {
            let mut budget = machine.execution_budget.lock();
            for _ in 0..8 {
                ExecutionBudget::charge_transition(&mut budget)
                    .unwrap_or_else(|error| panic!("exhaustion: {error:?}"));
            }
        }
        let before = machine.execution_budget.snapshot();
        let values = machine.values.clone();
        let places = machine.values_places.clone();
        let occurrences = machine.occurrences.clone();
        PROBE.with(|cell| {
            *cell.borrow_mut() = Some(Probe {
                root: weak,
                budget: machine.execution_budget.clone(),
                observations: Vec::new(),
            })
        });
        let step = machine.step();
        let observations = PROBE.with(|cell| {
            cell.borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("probe"))
                .observations
        });
        assert!(
            observations.iter().all(|(_, unlocked, _)| *unlocked),
            "Result temporary/consumed origins must be reclaimed unlocked: {observations:?}"
        );
        if variant < 2 {
            assert!(
                !observations.is_empty(),
                "actual dispatch must dispose consumed origins"
            );
            assert!(
                observations
                    .iter()
                    .all(|(_, _, revision)| *revision == Some(1))
            );
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Deterministic {
                workflow, site: actual_site, kind,
            }) if workflow == root && actual_site == site && kind.as_ref() == "branch")
            );
            assert_eq!(machine.frames[0].pc, if variant == 0 { 1 } else { 2 });
            assert_eq!(
                machine.occurrences.last().map(|value| value.as_ref()),
                Some(if variant == 0 {
                    "branch:crate::main:0:0"
                } else {
                    "branch:crate::main:0:1"
                })
            );
            assert_eq!(machine.values, vec![LogicalValue::unit()]);
            assert_eq!(
                machine.values_places,
                vec![Some(LoadedPlace {
                    root: Arc::from("result-origin"),
                    path: vec![ValuePathSegment::ListItem(0), ValuePathSegment::ResultValue],
                })]
            );
            assert_eq!(
                machine.execution_budget.snapshot().revision,
                before.revision + 1
            );
        } else {
            let expected = if variant < 4 {
                RuntimeCode::DeterministicTransitionBudget
            } else {
                RuntimeCode::InternalInvariant
            };
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
                if failure.code == expected && failure.workflow == root && failure.site == site)
            );
            assert_eq!(machine.values, values);
            assert_eq!(machine.values_places, places);
            assert_eq!(machine.occurrences, occurrences);
            assert_eq!(machine.frames[0].pc, 0);
            assert_eq!(machine.execution_budget.snapshot(), before);
        }
    }
}

/// Enum dispatch preserves selected payload origins and reclaims all temporaries unlocked.
#[test]
fn enum_branch_preserves_payload_origins_and_unlocked_reclamation() {
    for variant in 0..7 {
        let root =
            CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
        let site =
            StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
        let program = Arc::new(
            MachineProgram::new(vec![gantry_ir::Workflow {
                path: root.clone(),
                parameters: Vec::new(),
                result: TypeDescriptor::UNIT,
                effects: gantry_ir::EffectSet::default(),
                instructions: vec![
                    Instruction {
                        site: site.clone(),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::BranchEnum {
                            arms: vec![(Arc::from("A"), 1), (Arc::from("B"), 2)],
                        },
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![1])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                    Instruction {
                        site: StructuralPosition::new(vec![2])
                            .unwrap_or_else(|error| panic!("site: {error:?}")),
                        ty: TypeDescriptor::UNIT,
                        kind: InstructionKind::Return,
                    },
                ],
            }])
            .unwrap_or_else(|error| panic!("program: {error:?}")),
        );
        let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9d; 32])
            .unwrap_or_else(|error| panic!("execution: {error:?}"));
        let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("limits"));
        let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
            .unwrap_or_else(|error| panic!("machine: {error:?}"));
        let origin: Arc<str> = Arc::from("enum-origin");
        let weak = Arc::downgrade(&origin);
        if variant != 6 {
            let value = if variant == 5 {
                LogicalValue::unit()
            } else {
                LogicalValue::enumeration(
                    "crate::Choice",
                    if variant == 4 {
                        "Unknown"
                    } else if variant == 1 || variant == 3 {
                        "B"
                    } else {
                        "A"
                    },
                    if variant == 1 || variant == 3 {
                        None
                    } else {
                        Some(LogicalValue::unit())
                    },
                    limits.value_limits,
                )
                .unwrap_or_else(|error| panic!("enum: {error:?}"))
            };
            machine.push_staged(
                value,
                Some(LoadedPlace {
                    root: origin,
                    path: vec![ValuePathSegment::ListItem(0)],
                }),
            );
        } else {
            drop(origin);
        }
        if variant >= 2 {
            let mut budget = machine.execution_budget.lock();
            for _ in 0..8 {
                ExecutionBudget::charge_transition(&mut budget)
                    .unwrap_or_else(|error| panic!("exhaustion: {error:?}"));
            }
        }
        let before = machine.execution_budget.snapshot();
        let values = machine.values.clone();
        let places = machine.values_places.clone();
        let occurrences = machine.occurrences.clone();
        PROBE.with(|cell| {
            *cell.borrow_mut() = Some(Probe {
                root: weak,
                budget: machine.execution_budget.clone(),
                observations: Vec::new(),
            })
        });
        let step = machine.step();
        let observations = PROBE.with(|cell| {
            cell.borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("probe"))
                .observations
        });
        assert!(
            observations.iter().all(|(_, unlocked, _)| *unlocked),
            "Enum temporary/consumed origins must be reclaimed unlocked: {observations:?}"
        );
        if variant < 2 {
            assert!(
                !observations.is_empty(),
                "actual dispatch must dispose consumed origins"
            );
            assert!(
                observations
                    .iter()
                    .all(|(_, _, revision)| *revision == Some(1))
            );
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Deterministic {
                workflow, site: actual_site, kind,
            }) if workflow == root && actual_site == site && kind.as_ref() == "branch")
            );
            assert_eq!(machine.frames[0].pc, if variant == 0 { 1 } else { 2 });
            assert_eq!(
                machine.occurrences.last().map(|value| value.as_ref()),
                Some(if variant == 0 {
                    "branch:crate::main:0:0"
                } else {
                    "branch:crate::main:0:1"
                })
            );
            if variant == 0 {
                assert_eq!(machine.values, vec![LogicalValue::unit()]);
                assert_eq!(
                    machine.values_places,
                    vec![Some(LoadedPlace {
                        root: Arc::from("enum-origin"),
                        path: vec![ValuePathSegment::ListItem(0), ValuePathSegment::EnumPayload],
                    })]
                );
            } else {
                assert!(machine.values.is_empty());
                assert!(machine.values_places.is_empty());
            }
            assert_eq!(
                machine.execution_budget.snapshot().revision,
                before.revision + 1
            );
        } else {
            let expected = if variant < 4 {
                RuntimeCode::DeterministicTransitionBudget
            } else {
                RuntimeCode::InternalInvariant
            };
            assert!(
                matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
                if failure.code == expected && failure.workflow == root && failure.site == site)
            );
            assert_eq!(machine.values, values);
            assert_eq!(machine.values_places, places);
            assert_eq!(machine.occurrences, occurrences);
            assert_eq!(machine.frames[0].pc, 0);
            assert_eq!(machine.execution_budget.snapshot(), before);
        }
    }
}

/// Dispatch variants sharing the same independently observed consumed origin.
#[derive(Clone, Copy)]
enum ReclamationOperation {
    Primitive,
    Aggregate,
    Discard,
    Binding,
    Branch,
    OptionNone,
}

/// Exercises the actual publication dispatch with an independently observed unique origin.
fn assert_consumed_origin_reclamation(operation: ReclamationOperation) {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let site = StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
    let result_type = match operation {
        ReclamationOperation::Aggregate => {
            TypeDescriptor::list(TypeDescriptor::list(TypeDescriptor::UNIT))
        }
        ReclamationOperation::Primitive => TypeDescriptor::INT,
        ReclamationOperation::Discard => TypeDescriptor::UNIT,
        ReclamationOperation::Binding => TypeDescriptor::UNIT,
        ReclamationOperation::Branch => TypeDescriptor::UNIT,
        ReclamationOperation::OptionNone => TypeDescriptor::UNIT,
    };
    let program = Arc::new(
        MachineProgram::new(vec![gantry_ir::Workflow {
            path: root.clone(),
            parameters: Vec::new(),
            result: result_type.clone(),
            effects: gantry_ir::EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: site.clone(),
                    ty: result_type.clone(),
                    kind: match operation {
                        ReclamationOperation::Aggregate => InstructionKind::Aggregate {
                            kind: AggregateKind::List,
                            operands: 1,
                        },
                        ReclamationOperation::Primitive => {
                            InstructionKind::Primitive(Primitive::ListLength)
                        }
                        ReclamationOperation::Discard => InstructionKind::Pop,
                        ReclamationOperation::Binding => InstructionKind::Bind {
                            name: Arc::from("bound"),
                            ty: TypeDescriptor::list(TypeDescriptor::UNIT),
                            mutable: false,
                        },
                        ReclamationOperation::Branch => InstructionKind::Branch {
                            when_true: 1,
                            when_false: 1,
                        },
                        ReclamationOperation::OptionNone => InstructionKind::BranchOption {
                            when_some: 1,
                            when_none: 1,
                        },
                    },
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: result_type,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x94; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let origin: Arc<str> = Arc::from("unique-consumed-origin");
    let weak = Arc::downgrade(&origin);
    let value = LogicalValue::list(
        (0..10_000).map(|_| LogicalValue::unit()).collect(),
        limits.value_limits,
    )
    .unwrap_or_else(|error| panic!("value: {error:?}"));
    let value = if matches!(operation, ReclamationOperation::Branch) {
        LogicalValue::boolean(true)
    } else if matches!(operation, ReclamationOperation::OptionNone) {
        LogicalValue::none()
    } else {
        value
    };
    machine.push_staged(
        value,
        Some(LoadedPlace {
            root: origin,
            path: Vec::new(),
        }),
    );
    PROBE.with(|cell| {
        *cell.borrow_mut() = Some(Probe {
            root: weak.clone(),
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let observations = PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("probe exists"))
            .observations
    });
    assert!(matches!(
        step,
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    if matches!(operation, ReclamationOperation::OptionNone) {
        assert_eq!(
            observations,
            vec![(false, true, Some(1)), (true, true, Some(1))]
        );
    } else {
        assert_eq!(observations, vec![(true, true, Some(1))]);
    }
    assert!(
        weak.upgrade().is_none(),
        "the consumed origin must actually be reclaimed"
    );
    assert_eq!(machine.frames[0].pc, 1);
    if matches!(operation, ReclamationOperation::Aggregate) {
        assert_eq!(machine.values.len(), 1);
        assert_eq!(machine.values[0].view(), LogicalValueView::List(1));
        assert_eq!(
            machine.values[0].member(0).map(|value| value.kind()),
            Some(gantry_core::value::ValueKind::List)
        );
    } else if matches!(operation, ReclamationOperation::Primitive) {
        assert_eq!(
            machine.values,
            vec![LogicalValue::integer(
                GantryInt::new(10_000).unwrap_or_else(|| panic!("canonical length"))
            )]
        );
    }
    if matches!(
        operation,
        ReclamationOperation::Discard
            | ReclamationOperation::Branch
            | ReclamationOperation::OptionNone
    ) {
        assert!(machine.values.is_empty());
        assert!(machine.values_places.is_empty());
    } else if matches!(operation, ReclamationOperation::Binding) {
        assert!(machine.values.is_empty());
        assert!(machine.values_places.is_empty());
        assert_eq!(
            machine
                .binding("bound")
                .map(|binding| binding.value.aggregate_len()),
            Some(Some(10_000))
        );
    } else {
        assert_eq!(machine.values_places, vec![None]);
    }
    assert_eq!(machine.execution_budget.snapshot().revision, 1);
}

/// Projection must retain its extended origin while disposing the source outside shared counters.
#[test]
fn projection_source_and_temporary_origins_are_disposed_after_budget_unlock() {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let program = Arc::new(
        MachineProgram::new(vec![gantry_ir::Workflow {
            path: root.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: gantry_ir::EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: StructuralPosition::new(vec![0])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Project(Projection::Member(0)),
                },
                Instruction {
                    site: StructuralPosition::new(vec![1])
                        .unwrap_or_else(|error| panic!("site: {error:?}")),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x95; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let origin: Arc<str> = Arc::from("projection-source-origin");
    let weak = Arc::downgrade(&origin);
    let value = LogicalValue::list(
        (0..10_000).map(|_| LogicalValue::unit()).collect(),
        limits.value_limits,
    )
    .unwrap_or_else(|error| panic!("value: {error:?}"));
    machine.push_staged(
        value,
        Some(LoadedPlace {
            root: origin,
            path: Vec::new(),
        }),
    );
    PROBE.with(|cell| {
        *cell.borrow_mut() = Some(Probe {
            root: weak.clone(),
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let observations = PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("probe exists"))
            .observations
    });
    assert!(matches!(
        step,
        MachineStep::Transition(MachineLabel::Deterministic { .. })
    ));
    assert!(
        !observations.is_empty(),
        "source origins must actually be disposed"
    );
    assert!(
        observations.iter().all(|(_, unlocked, _)| *unlocked),
        "{observations:?}"
    );
    assert!(
        observations
            .iter()
            .any(|(_, _, revision)| *revision == Some(1))
    );
    assert_eq!(machine.values, vec![LogicalValue::unit()]);
    let place = machine.values_places[0]
        .as_ref()
        .unwrap_or_else(|| panic!("projected origin"));
    assert_eq!(place.root.as_ref(), "projection-source-origin");
    assert_eq!(place.path, vec![ValuePathSegment::ListItem(0)]);
    assert_eq!(machine.frames[0].pc, 1);
    assert_eq!(machine.execution_budget.snapshot().revision, 1);
    assert!(
        weak.upgrade().is_some(),
        "the projected place retains its origin"
    );
    drop(machine);
    assert!(weak.upgrade().is_none());
}

/// Spawned-body completion must release consumed origins only after counter unlocking.
#[cfg(feature = "concurrent")]
#[test]
fn completed_task_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_task_completion_reclamation(8, false, None);
    assert_task_completion_reclamation(1, false, Some(RuntimeCode::DeterministicTransitionBudget));
    assert_task_completion_reclamation(1, true, Some(RuntimeCode::InternalInvariant));
}

/// Drives actual spawned completion with success and conflicting refusal controls.
#[cfg(feature = "concurrent")]
fn assert_task_completion_reclamation(
    transitions: u64,
    invalid_result: bool,
    expected: Option<RuntimeCode>,
) {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let caller = CanonicalCallableIdentity::free(&root, &[]);
    let site = |index| {
        StructuralPosition::new(vec![index]).unwrap_or_else(|error| panic!("site: {error:?}"))
    };
    let body_id = gantry_ir::TaskBodyIdentity::new(caller.clone(), site(0));
    let body = gantry_ir::ExecutableTaskBody::new(
        body_id.clone(),
        TypeDescriptor::UNIT,
        Vec::new(),
        gantry_ir::ExecutableTaskContext::v1(),
        vec![
            Instruction {
                site: site(0),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::Push(LogicalValue::unit()),
            },
            Instruction {
                site: site(1),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::TaskComplete,
            },
        ],
    )
    .unwrap_or_else(|error| panic!("body: {error:?}"));
    let program = Arc::new(
        MachineProgram::with_task_bodies(
            vec![(
                caller,
                gantry_ir::Workflow {
                    path: root.clone(),
                    parameters: Vec::new(),
                    result: TypeDescriptor::UNIT,
                    effects: gantry_ir::EffectSet::default(),
                    instructions: vec![
                        Instruction {
                            site: site(0),
                            ty: TypeDescriptor::UNIT,
                            kind: InstructionKind::Spawn {
                                handle: gantry_ir::ExecutableTaskHandle::new(
                                    Arc::from("child"),
                                    TypeDescriptor::UNIT,
                                )
                                .unwrap_or_else(|error| panic!("handle: {error:?}")),
                                body: body_id.clone(),
                            },
                        },
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
                    ],
                },
            )],
            vec![body],
        )
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x99; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let task_path: Arc<[Arc<str>]> = Arc::from([Arc::from("spawn:crate::main:0:0")]);
    let task = expected_task_identity(execution, &task_path)
        .unwrap_or_else(|error| panic!("task: {error:?}"));
    let limits = MachineLimits::new(
        transitions,
        1,
        1,
        1,
        8,
        gantry_core::value::DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|| panic!("limits"));
    let budget = ExecutionBudget::new(execution, limits);
    let mut machine = Machine::new_concurrent_task_body_with_context(
        program,
        &body_id,
        &[],
        execution,
        task,
        task_path,
        limits,
        budget,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("child machine: {error:?}"));
    assert!(matches!(machine.step(), MachineStep::Transition(_)));
    let origin: Arc<str> = Arc::from("completed-task-origin");
    let weak = Arc::downgrade(&origin);
    machine.values_places[0] = Some(LoadedPlace {
        root: origin,
        path: Vec::new(),
    });
    let before = machine.execution_budget.snapshot();
    if invalid_result {
        machine.values[0] = LogicalValue::boolean(true);
    }
    let frames = expected.map(|_| machine.frames.clone());
    let values = expected.map(|_| machine.values.clone());
    let places = expected.map(|_| machine.values_places.clone());
    PROBE.with(|cell| {
        *cell.borrow_mut() = Some(Probe {
            root: weak.clone(),
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let observations = PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("probe exists"))
            .observations
    });
    if let Some(code) = expected {
        assert!(
            matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == code && failure.workflow == root && failure.site == site(1))
        );
        assert!(
            observations.is_empty(),
            "refused completion must retain operand origins"
        );
        assert_eq!(Some(machine.frames.clone()), frames);
        assert_eq!(Some(machine.values.clone()), values);
        assert_eq!(Some(machine.values_places.clone()), places);
        assert_eq!(machine.execution_budget.snapshot(), before);
        assert!(weak.upgrade().is_some());
        return;
    }
    assert_eq!(observations, vec![(true, true, Some(before.revision + 1))]);
    assert_eq!(
        step,
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Succeeded(
            LogicalValue::unit()
        )))
    );
    assert!(weak.upgrade().is_none());
    assert!(machine.values.is_empty());
    assert!(machine.values_places.is_empty());
    assert_eq!(
        machine.execution_budget.snapshot().revision,
        before.revision + 1
    );
    assert_eq!(
        machine.step(),
        MachineStep::Complete(MachineOutcome::Succeeded(LogicalValue::unit()))
    );
}
/// Assignment construction and consumed-origin disposal must not hold shared counters.
#[test]
fn assignment_staging_and_reclamation_run_outside_budget_lock() {
    assert_assignment_boundary(false, true, false, None);
    assert_assignment_boundary(
        true,
        true,
        false,
        Some(RuntimeCode::DeterministicTransitionBudget),
    );
    assert_assignment_boundary(true, false, false, Some(RuntimeCode::InternalInvariant));
    assert_assignment_boundary(true, true, true, Some(RuntimeCode::InternalInvariant));
}

/// Exercises successful publication and conflicting refusal conditions through actual dispatch.
fn assert_assignment_boundary(
    exhausted: bool,
    mutable: bool,
    invalid_type: bool,
    expected: Option<RuntimeCode>,
) {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let site = |index| {
        StructuralPosition::new(vec![index]).unwrap_or_else(|error| panic!("site: {error:?}"))
    };
    let program = Arc::new(
        MachineProgram::new(vec![gantry_ir::Workflow {
            path: root.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: gantry_ir::EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: site(0),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Assign {
                        name: Arc::from("target"),
                        path: Vec::new(),
                        target_type: TypeDescriptor::STRING,
                    },
                },
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
            ],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let execution = ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x9a; 32])
        .unwrap_or_else(|error| panic!("execution: {error:?}"));
    let limits = MachineLimits::new(8, 1, 1, 1, 8, gantry_core::value::DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|| panic!("limits"));
    let mut machine = Machine::new(program, &root, Vec::new(), execution, limits)
        .unwrap_or_else(|error| panic!("machine: {error:?}"));
    let previous = LogicalValue::string("é".repeat(10_000), limits.value_limits)
        .unwrap_or_else(|error| panic!("previous: {error:?}"));
    let address = previous
        .as_string()
        .unwrap_or_else(|| panic!("String fixture"))
        .as_ptr() as usize;
    machine.frames[0].scopes[0].insert(
        Arc::from("target"),
        Binding {
            value: previous,
            ty: TypeDescriptor::STRING,
            mutable,
        },
    );
    let replacement = LogicalValue::string("replacement", limits.value_limits)
        .unwrap_or_else(|error| panic!("replacement: {error:?}"));
    let origin: Arc<str> = Arc::from("assignment-input-origin");
    let weak = Arc::downgrade(&origin);
    machine.push_staged(
        replacement.clone(),
        Some(LoadedPlace {
            root: origin,
            path: Vec::new(),
        }),
    );
    if invalid_type {
        machine.values[0] = LogicalValue::boolean(true);
    }
    if exhausted {
        let mut state = machine.execution_budget.lock();
        for _ in 0..8 {
            ExecutionBudget::charge_transition(&mut state)
                .unwrap_or_else(|error| panic!("exhaust budget: {error:?}"));
        }
    }
    let before = machine.execution_budget.snapshot();
    let frames = expected.map(|_| machine.frames.clone());
    let values = expected.map(|_| machine.values.clone());
    let places = expected.map(|_| machine.values_places.clone());
    BINDING_PROBE.with(|cell| {
        *cell.borrow_mut() = Some(BindingProbe {
            address,
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    PROBE.with(|cell| {
        *cell.borrow_mut() = Some(Probe {
            root: weak.clone(),
            budget: machine.execution_budget.clone(),
            observations: Vec::new(),
        })
    });
    let step = machine.step();
    let bindings = BINDING_PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("binding probe"))
            .observations
    });
    let origins = PROBE.with(|cell| {
        cell.borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("origin probe"))
            .observations
    });
    if let Some(code) = expected {
        assert!(
            matches!(step, MachineStep::Transition(MachineLabel::Failure(failure))
            if failure.code == code && failure.workflow == root && failure.site == site(0))
        );
        assert!(
            origins.is_empty(),
            "refusal must retain the consumed origin"
        );
        assert!(bindings.iter().all(Option::is_some), "{bindings:?}");
        assert_eq!(Some(machine.frames.clone()), frames);
        assert_eq!(Some(machine.values.clone()), values);
        assert_eq!(Some(machine.values_places.clone()), places);
        assert_eq!(machine.execution_budget.snapshot(), before);
        assert!(weak.upgrade().is_some());
        return;
    }
    assert!(
        !bindings.is_empty(),
        "staged binding copies must be observed"
    );
    assert!(bindings.iter().all(Option::is_some), "{bindings:?}");
    assert_eq!(origins, vec![(true, true, Some(1))]);
    assert!(weak.upgrade().is_none());
    assert!(
        matches!(step, MachineStep::Transition(MachineLabel::Deterministic { kind, .. })
        if kind.as_ref() == "assignment")
    );
    assert_eq!(
        machine.binding("target").map(|binding| &binding.value),
        Some(&replacement)
    );
    assert!(machine.values.is_empty());
    assert!(machine.values_places.is_empty());
    assert_eq!(machine.frames[0].pc, 1);
    assert_eq!(machine.execution_budget.snapshot().revision, 1);
}
