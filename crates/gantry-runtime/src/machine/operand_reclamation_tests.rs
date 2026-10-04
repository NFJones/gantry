//! Test-only observation of place-origin destruction during real value publication.
//!
//! Logical values are dropped before their paired origins. A thread-local observer avoids
//! global test races and adds no fields, callbacks or destruction behavior to production builds.

use std::cell::RefCell;
use std::sync::{Arc, Weak};

use super::*;

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

/// Dispatch variants sharing the same independently observed consumed origin.
#[derive(Clone, Copy)]
enum ReclamationOperation {
    Primitive,
    Aggregate,
    Discard,
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
    assert_eq!(observations, vec![(true, true, Some(1))]);
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
    if matches!(operation, ReclamationOperation::Discard) {
        assert!(machine.values.is_empty());
        assert!(machine.values_places.is_empty());
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
