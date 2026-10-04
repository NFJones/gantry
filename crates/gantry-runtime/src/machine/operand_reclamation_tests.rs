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
