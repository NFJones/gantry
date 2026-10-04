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
    assert_consumed_origin_reclamation(false);
}

/// Aggregate publication must release consumed origins after unlocking, just like primitives.
#[test]
fn aggregate_operand_origins_are_reclaimed_after_budget_unlock() {
    assert_consumed_origin_reclamation(true);
}

/// Exercises the actual publication dispatch with an independently observed unique origin.
fn assert_consumed_origin_reclamation(aggregate: bool) {
    let root = CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("root: {error:?}"));
    let site = StructuralPosition::new(vec![0]).unwrap_or_else(|error| panic!("site: {error:?}"));
    let result_type = if aggregate {
        TypeDescriptor::list(TypeDescriptor::list(TypeDescriptor::UNIT))
    } else {
        TypeDescriptor::INT
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
                    kind: if aggregate {
                        InstructionKind::Aggregate {
                            kind: AggregateKind::List,
                            operands: 1,
                        }
                    } else {
                        InstructionKind::Primitive(Primitive::ListLength)
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
    if aggregate {
        assert_eq!(machine.values.len(), 1);
        assert_eq!(machine.values[0].view(), LogicalValueView::List(1));
        assert_eq!(
            machine.values[0].member(0).map(|value| value.kind()),
            Some(gantry_core::value::ValueKind::List)
        );
    } else {
        assert_eq!(
            machine.values,
            vec![LogicalValue::integer(
                GantryInt::new(10_000).unwrap_or_else(|| panic!("canonical length"))
            )]
        );
    }
    assert_eq!(machine.values_places, vec![None]);
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
