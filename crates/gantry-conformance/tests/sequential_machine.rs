//! Public-facade conformance for the explicit-frame sequential machine.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::identity::ProtocolIdentity;
use gantry::ir::{CanonicalPath, EffectSet, StructuralPosition, TypeDescriptor};
use gantry::numeric::{GantryFloat, GantryInt};
use gantry::portable::{DeterministicEvaluationCode, IdentityKind};
use gantry::runtime::{
    Comparison, Instruction, InstructionKind, LoopPhase, Machine, MachineLabel, MachineLimits,
    MachineOutcome, MachineProgram, MachineStep, OperationCompletionError, Parameter, Primitive,
    Projection, RuntimeCode, Workflow,
};
use gantry::value::{
    DEFAULT_VALUE_LIMITS, LogicalValue, LogicalValueView, ValueLimits, ValuePathSegment,
};
use serde::Deserialize;

const FRAME_EVIDENCE: &str = "crates/gantry-conformance/tests/sequential_machine.rs#public_explicit_frames_calls_and_lifecycle_are_stack_safe";
const VALUE_EVIDENCE: &str = "crates/gantry-conformance/tests/sequential_machine.rs#public_deterministic_values_and_failures_match_the_machine_contract";
const STRING_EVIDENCE: &str = "crates/gantry-conformance/tests/sequential_machine.rs#public_string_primitives_are_exact_bounded_and_nontrimming";
const BUDGET_EVIDENCE: &str = "crates/gantry-conformance/tests/sequential_machine.rs#public_budgets_cancellation_and_dynamic_identities_are_exact";

#[derive(Debug, Deserialize)]
struct EvidenceManifest {
    format: String,
    specification_sha256: String,
    issue: String,
    entries: Vec<EvidenceEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceEntry {
    requirement: String,
    clause: String,
    profile: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct RequirementReview {
    specification_sha256: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    clauses: Vec<ReviewedClause>,
}

#[derive(Debug, Deserialize)]
struct ReviewedClause {
    key: String,
    profile_reviews: Vec<ProfileReview>,
}

#[derive(Debug, Deserialize)]
struct ProfileReview {
    profile: String,
    state: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MachineVectors {
    format: String,
    deep_call_depth: usize,
    branch_operation_path: Vec<String>,
    lifecycle_labels: Vec<String>,
    failure_codes: Vec<String>,
}

#[test]
fn reviewed_sequential_machine_evidence_is_closed() {
    let root = workspace_root();
    let manifest: EvidenceManifest =
        read_json(&root.join("protocol/conformance/sequential-machine-v1.json"));
    let review: RequirementReview = read_json(&root.join("protocol/requirements/reviewed-v1.json"));

    assert_eq!(manifest.format, "gantry.sequential-machine-evidence/v1");
    assert_eq!(manifest.issue, "GNT-RUN-001");
    assert_eq!(manifest.specification_sha256, review.specification_sha256);
    assert!(manifest.entries.windows(2).all(|pair| pair[0] < pair[1]));

    let mut entries = BTreeMap::<(String, String, String), Vec<String>>::new();
    for entry in manifest.entries {
        assert!(matches!(
            entry.evidence.as_str(),
            FRAME_EVIDENCE | VALUE_EVIDENCE | STRING_EVIDENCE | BUDGET_EVIDENCE
        ));
        entries
            .entry((entry.requirement, entry.clause, entry.profile))
            .or_default()
            .push(entry.evidence);
    }

    for ((requirement, clause_key, profile_name), evidence) in entries {
        let clause = review
            .requirements
            .iter()
            .find(|candidate| candidate.id == requirement)
            .and_then(|requirement| {
                requirement
                    .clauses
                    .iter()
                    .find(|clause| clause.key == clause_key)
            })
            .unwrap_or_else(|| panic!("missing {requirement}:{clause_key}"));
        let profile = clause
            .profile_reviews
            .iter()
            .find(|profile| profile.profile == profile_name)
            .unwrap_or_else(|| {
                panic!("missing {profile_name} review for {requirement}:{clause_key}")
            });
        assert_eq!(profile.state, "covered");
        assert_eq!(profile.evidence, evidence);
    }
}

#[test]
fn public_explicit_frames_calls_and_lifecycle_are_stack_safe() {
    let vectors = vectors();
    assert_eq!(vectors.format, "gantry.sequential-machine-vectors/v1");
    let mut workflows = Vec::with_capacity(vectors.deep_call_depth);
    for index in 0..vectors.deep_call_depth {
        let name = format!("crate::f{index:04}");
        let instructions = if index + 1 == vectors.deep_call_depth {
            vec![
                instruction(
                    0,
                    TypeDescriptor::UNIT,
                    InstructionKind::Push(LogicalValue::unit()),
                ),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
            ]
        } else {
            vec![
                instruction(
                    0,
                    TypeDescriptor::UNIT,
                    InstructionKind::Call {
                        callee: path(&format!("crate::f{:04}", index + 1)),
                        arguments: 0,
                    },
                ),
                instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
            ]
        };
        workflows.push(workflow(
            &name,
            Vec::new(),
            TypeDescriptor::UNIT,
            EffectSet::default(),
            instructions,
        ));
    }

    let runtime_program = program(workflows);
    let mut runtime_machine = machine(
        Arc::clone(&runtime_program),
        "crate::f0000",
        Vec::new(),
        limits(20_000, 1, 1, vectors.deep_call_depth as u64, 20_000),
    );
    let (outcome, labels) = drive(&mut runtime_machine);
    assert_eq!(outcome, MachineOutcome::Succeeded(LogicalValue::unit()));
    assert_eq!(terminal_labels(&labels), vectors.lifecycle_labels);

    let mut rejected = machine(
        runtime_program,
        "crate::f0000",
        Vec::new(),
        limits(20_000, 1, 1, vectors.deep_call_depth as u64 - 1, 20_000),
    );
    assert!(matches!(
        drive(&mut rejected).0,
        MachineOutcome::Failed(failure)
            if failure.code
                == RuntimeCode::Deterministic(
                    DeterministicEvaluationCode::WorkflowCallDepthLimit
                )
    ));
}

#[test]
fn public_deterministic_values_and_failures_match_the_machine_contract() {
    let vectors = vectors();
    let failures = failure_programs()
        .into_iter()
        .map(|(expected, workflow, machine_limits)| {
            let mut machine = machine(
                program(vec![workflow]),
                "crate::main",
                Vec::new(),
                machine_limits,
            );
            let MachineOutcome::Failed(failure) = drive(&mut machine).0 else {
                panic!("failure fixture unexpectedly succeeded")
            };
            assert_eq!(failure.code.wire_name(), expected);
            expected.to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(failures, vectors.failure_codes);

    let original = LogicalValue::structure(
        "crate::Item",
        vec![("flag".to_owned(), LogicalValue::boolean(false))],
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|error| panic!("fixture value failed: {error:?}"));
    let retained = original.clone();
    let root = workflow(
        "crate::main",
        vec![Parameter {
            name: Arc::from("item"),
            ty: TypeDescriptor::declared(path("crate::Item")),
            mutable: true,
        }],
        TypeDescriptor::declared(path("crate::Item")),
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            ),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Assign {
                    name: Arc::from("item"),
                    path: vec![ValuePathSegment::StructField("flag".to_owned())],
                    target_type: TypeDescriptor::BOOL,
                },
            ),
            instruction(
                2,
                TypeDescriptor::declared(path("crate::Item")),
                InstructionKind::Load(Arc::from("item")),
            ),
            instruction(
                3,
                TypeDescriptor::declared(path("crate::Item")),
                InstructionKind::Return,
            ),
        ],
    );
    let mut mutation_machine = machine(
        program(vec![root]),
        "crate::main",
        vec![original],
        limits(16, 1, 1, 1, 16),
    );
    let MachineOutcome::Succeeded(updated) = drive(&mut mutation_machine).0 else {
        panic!("atomic-root fixture failed")
    };
    assert_bool_field(&retained, false);
    assert_bool_field(&updated, true);

    assert_bool(
        &run_primitive(
            vec![LogicalValue::boolean(true)],
            Primitive::Not,
            TypeDescriptor::BOOL,
        ),
        false,
    );
    assert_int(
        &run_primitive(vec![integer(7)], Primitive::Negate, TypeDescriptor::INT),
        -7,
    );
    assert_int(
        &run_primitive(
            vec![integer(7), integer(3)],
            Primitive::Subtract,
            TypeDescriptor::INT,
        ),
        4,
    );
    assert_int(
        &run_primitive(
            vec![integer(7), integer(3)],
            Primitive::Multiply,
            TypeDescriptor::INT,
        ),
        21,
    );
    assert_int(
        &run_primitive(
            vec![integer(7), integer(-3)],
            Primitive::Divide,
            TypeDescriptor::INT,
        ),
        -2,
    );
    assert_int(
        &run_primitive(
            vec![integer(7), integer(-3)],
            Primitive::Remainder,
            TypeDescriptor::INT,
        ),
        1,
    );
    assert_float(
        &run_primitive(vec![float(2.5)], Primitive::Negate, TypeDescriptor::FLOAT),
        -2.5,
    );
    for (primitive, expected) in [
        (Primitive::Add, 5.5),
        (Primitive::Subtract, -0.5),
        (Primitive::Multiply, 7.5),
        (Primitive::Divide, 2.5 / 3.0),
    ] {
        assert_float(
            &run_primitive(
                vec![float(2.5), float(3.0)],
                primitive,
                TypeDescriptor::FLOAT,
            ),
            expected,
        );
    }
    assert_eq!(
        run_primitive(
            vec![string("left"), string("right")],
            Primitive::Add,
            TypeDescriptor::STRING,
        )
        .as_string(),
        Some("leftright")
    );
    for (comparison, expected) in [
        (Comparison::Less, true),
        (Comparison::LessOrEqual, true),
        (Comparison::Greater, false),
        (Comparison::GreaterOrEqual, false),
    ] {
        assert_bool(
            &run_primitive(
                vec![integer(2), integer(3)],
                Primitive::Compare(comparison),
                TypeDescriptor::BOOL,
            ),
            expected,
        );
    }
    let pair = LogicalValue::tuple(vec![integer(1), string("x")], DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("fixture tuple failed: {error:?}"));
    assert_bool(
        &run_primitive(
            vec![pair.clone(), pair.clone()],
            Primitive::Equal,
            TypeDescriptor::BOOL,
        ),
        true,
    );
    assert_bool(
        &run_primitive(
            vec![
                pair.clone(),
                LogicalValue::tuple(vec![integer(1), string("y")], DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("fixture tuple failed: {error:?}")),
            ],
            Primitive::NotEqual,
            TypeDescriptor::BOOL,
        ),
        true,
    );
    assert_float(
        &run_primitive(
            vec![integer(7)],
            Primitive::IntToFloat,
            TypeDescriptor::FLOAT,
        ),
        7.0,
    );
    let option_int = TypeDescriptor::option(TypeDescriptor::INT)
        .unwrap_or_else(|error| panic!("invalid option type: {error}"));
    assert!(matches!(
        run_primitive(vec![float(7.0)], Primitive::FloatToInt, option_int.clone(),).view(),
        LogicalValueView::Option { is_some: true }
    ));
    assert!(matches!(
        run_primitive(vec![float(0.5)], Primitive::FloatToInt, option_int).view(),
        LogicalValueView::Option { is_some: false }
    ));
    assert_eq!(
        run_primitive(
            vec![LogicalValue::boolean(true)],
            Primitive::ToString,
            TypeDescriptor::STRING,
        )
        .as_string(),
        Some("true")
    );
    assert_eq!(
        run_primitive(
            vec![integer(-7)],
            Primitive::ToString,
            TypeDescriptor::STRING,
        )
        .as_string(),
        Some("-7")
    );
    assert_eq!(
        run_primitive(
            vec![float(1.5)],
            Primitive::ToString,
            TypeDescriptor::STRING,
        )
        .as_string(),
        Some("1.5")
    );
    assert_int(
        &run_primitive(
            vec![
                LogicalValue::list(vec![integer(1), integer(2)], DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("fixture list failed: {error:?}")),
            ],
            Primitive::ListLength,
            TypeDescriptor::INT,
        ),
        2,
    );

    let short_circuit = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::BOOL,
                InstructionKind::Push(LogicalValue::boolean(true)),
            ),
            instruction(
                1,
                TypeDescriptor::BOOL,
                InstructionKind::Branch {
                    when_true: 3,
                    when_false: 2,
                },
            ),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(
                3,
                TypeDescriptor::UNIT,
                InstructionKind::Push(LogicalValue::unit()),
            ),
            instruction(4, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut short_circuit_machine = machine(
        program(vec![short_circuit]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    assert_eq!(
        drive(&mut short_circuit_machine).0,
        MachineOutcome::Succeeded(LogicalValue::unit())
    );
    assert_eq!(short_circuit_machine.remaining_budgets().1, 1);
}

#[test]
fn public_string_primitives_are_exact_bounded_and_nontrimming() {
    let option_float = TypeDescriptor::option(TypeDescriptor::FLOAT)
        .unwrap_or_else(|error| panic!("invalid option type: {error}"));
    for (source, present) in [("1", true), (" 1", false), ("1 ", false), ("+1", false)] {
        let root = workflow(
            "crate::main",
            Vec::new(),
            option_float.clone(),
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::STRING,
                    InstructionKind::Push(string(source)),
                ),
                instruction(
                    1,
                    option_float.clone(),
                    InstructionKind::Primitive(Primitive::StringParseFloat),
                ),
                instruction(2, option_float.clone(), InstructionKind::Return),
            ],
        );
        let mut machine = machine(
            program(vec![root]),
            "crate::main",
            Vec::new(),
            limits(8, 1, 1, 1, 8),
        );
        let MachineOutcome::Succeeded(value) = drive(&mut machine).0 else {
            panic!("parse fixture failed")
        };
        assert!(matches!(
            value.view(),
            LogicalValueView::Option { is_some } if is_some == present
        ));
    }

    assert_eq!(
        run_string_primitive(vec![string("  Straße\u{2003}")], Primitive::StringTrim),
        "Straße"
    );
    assert_eq!(
        run_string_primitive(vec![string("Straße")], Primitive::StringUppercase),
        "STRASSE"
    );
    assert_eq!(
        run_string_primitive(vec![string("a--b--"), string("--")], Primitive::StringSplit,),
        "[\"a\",\"b\",\"\"]"
    );
    assert_eq!(
        run_string_primitive(
            vec![
                LogicalValue::list(vec![string("a"), string("b")], DEFAULT_VALUE_LIMITS)
                    .unwrap_or_else(|error| panic!("fixture list failed: {error:?}")),
                string("-")
            ],
            Primitive::StringListJoin,
        ),
        "a-b"
    );
    assert_int(
        &run_primitive(
            vec![string("éx")],
            Primitive::StringLength,
            TypeDescriptor::INT,
        ),
        2,
    );
    assert_bool(
        &run_primitive(
            vec![string("")],
            Primitive::StringIsEmpty,
            TypeDescriptor::BOOL,
        ),
        true,
    );
    assert_bool(
        &run_primitive(
            vec![string("abc"), string("b")],
            Primitive::StringContains,
            TypeDescriptor::BOOL,
        ),
        true,
    );
    assert_bool(
        &run_primitive(
            vec![string("abc"), string("a")],
            Primitive::StringStartsWith,
            TypeDescriptor::BOOL,
        ),
        true,
    );
    assert_bool(
        &run_primitive(
            vec![string("abc"), string("c")],
            Primitive::StringEndsWith,
            TypeDescriptor::BOOL,
        ),
        true,
    );
    assert_eq!(
        run_string_primitive(vec![string("  x  ")], Primitive::StringTrimStart),
        "x  "
    );
    assert_eq!(
        run_string_primitive(vec![string("  x  ")], Primitive::StringTrimEnd),
        "  x"
    );
    assert_eq!(
        run_string_primitive(vec![string("Σ")], Primitive::StringLowercase),
        "σ"
    );
    assert_eq!(
        run_string_primitive(
            vec![string("a-a"), string("a"), string("bb")],
            Primitive::StringReplace,
        ),
        "bb-bb"
    );
    let option_bool = TypeDescriptor::option(TypeDescriptor::BOOL)
        .unwrap_or_else(|error| panic!("invalid option type: {error}"));
    assert!(matches!(
        run_primitive(
            vec![string("true")],
            Primitive::StringParseBool,
            option_bool.clone()
        )
        .view(),
        LogicalValueView::Option { is_some: true }
    ));
    assert!(matches!(
        run_primitive(
            vec![string(" true")],
            Primitive::StringParseBool,
            option_bool
        )
        .view(),
        LogicalValueView::Option { is_some: false }
    ));
    let option_int = TypeDescriptor::option(TypeDescriptor::INT)
        .unwrap_or_else(|error| panic!("invalid option type: {error}"));
    assert!(matches!(
        run_primitive(
            vec![string("-7")],
            Primitive::StringParseInt,
            option_int.clone()
        )
        .view(),
        LogicalValueView::Option { is_some: true }
    ));
    assert!(matches!(
        run_primitive(vec![string("-0")], Primitive::StringParseInt, option_int).view(),
        LogicalValueView::Option { is_some: false }
    ));
}

#[test]
fn public_budgets_cancellation_and_dynamic_identities_are_exact() {
    let vectors = vectors();
    let build = || {
        workflow(
            "crate::main",
            Vec::new(),
            TypeDescriptor::BOOL,
            EffectSet::default(),
            vec![
                instruction(
                    0,
                    TypeDescriptor::BOOL,
                    InstructionKind::Push(LogicalValue::boolean(true)),
                ),
                instruction(
                    1,
                    TypeDescriptor::BOOL,
                    InstructionKind::Branch {
                        when_true: 2,
                        when_false: 2,
                    },
                ),
                instruction(2, TypeDescriptor::BOOL, InstructionKind::Operation),
                instruction(3, TypeDescriptor::BOOL, InstructionKind::Return),
            ],
        )
    };
    let identity_program = program(vec![build()]);
    let occurrence = |quantum| {
        let mut machine = machine(
            Arc::clone(&identity_program),
            "crate::main",
            Vec::new(),
            limits(16, 1, 1, 1, quantum),
        );
        loop {
            match machine.step() {
                MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => {
                    break operation;
                }
                MachineStep::Transition(_) => {}
                MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
                other => panic!("unexpected identity fixture step: {other:?}"),
            }
        }
    };
    let frequent = occurrence(1);
    let sparse = occurrence(16);
    assert_eq!(frequent.identity, sparse.identity);
    assert_eq!(
        frequent
            .dynamic_path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vectors.branch_operation_path
    );

    let loop_root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::EnterLoop {
                    phase: LoopPhase::Condition,
                    source_limit: None,
                },
            ),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Pop),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence),
            instruction(4, TypeDescriptor::UNIT, InstructionKind::Jump(0)),
        ],
    );
    let mut loop_identity_machine = machine(
        program(vec![loop_root]),
        "crate::main",
        Vec::new(),
        limits(32, 2, 1, 1, 32),
    );
    let first_loop = next_operation(&mut loop_identity_machine);
    assert_eq!(
        first_loop
            .dynamic_path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        [
            "loop:crate::main:0:condition:0",
            "operation:crate::main:1:-:0",
        ]
    );
    loop_identity_machine
        .complete_operation(first_loop.identity, LogicalValue::unit())
        .unwrap_or_else(|error| panic!("first loop operation failed: {error:?}"));
    let second_loop = next_operation(&mut loop_identity_machine);
    assert_eq!(
        second_loop
            .dynamic_path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        [
            "loop:crate::main:0:condition:1",
            "operation:crate::main:1:-:0",
        ]
    );
    assert_ne!(first_loop.identity, second_loop.identity);

    let callee = workflow(
        "crate::callee",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let caller = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(
                0,
                TypeDescriptor::UNIT,
                InstructionKind::Call {
                    callee: path("crate::callee"),
                    arguments: 0,
                },
            ),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Pop),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Jump(0)),
        ],
    );
    let mut repeated_call_machine = machine(
        program(vec![callee, caller]),
        "crate::main",
        Vec::new(),
        limits(32, 2, 1, 2, 32),
    );
    let first_call = next_operation(&mut repeated_call_machine);
    assert_eq!(
        first_call
            .dynamic_path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["call:crate::main:0:-:0", "operation:crate::callee:0:-:0",]
    );
    repeated_call_machine
        .complete_operation(first_call.identity, LogicalValue::unit())
        .unwrap_or_else(|error| panic!("first call operation failed: {error:?}"));
    let second_call = next_operation(&mut repeated_call_machine);
    assert_eq!(
        second_call
            .dynamic_path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["call:crate::main:0:-:1", "operation:crate::callee:0:-:0",]
    );
    assert_ne!(first_call.identity, second_call.identity);

    let root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut cancellation_machine = machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 1),
    );
    let operation = match cancellation_machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("unexpected cancellation fixture step: {other:?}"),
    };
    assert!(cancellation_machine.cancel("caller").is_some());
    assert!(matches!(
        cancellation_machine.step(),
        MachineStep::Transition(MachineLabel::TaskSettled(MachineOutcome::Cancelled(_)))
    ));
    assert_eq!(
        cancellation_machine.complete_operation(operation.identity, LogicalValue::unit()),
        Err(OperationCompletionError::NotWaiting)
    );

    let transition_root = unit_workflow(vec![
        instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::Push(LogicalValue::unit()),
        ),
        instruction(1, TypeDescriptor::UNIT, InstructionKind::Pop),
    ]);
    let mut transition_machine = machine(
        program(vec![transition_root]),
        "crate::main",
        Vec::new(),
        limits(1, 1, 1, 1, 8),
    );
    assert!(matches!(
        transition_machine.step(),
        MachineStep::Transition(_)
    ));
    assert!(matches!(
        transition_machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::DeterministicTransitionBudget
    ));

    let operation_root = workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(1, TypeDescriptor::UNIT, InstructionKind::Pop),
            instruction(2, TypeDescriptor::UNIT, InstructionKind::Operation),
            instruction(3, TypeDescriptor::UNIT, InstructionKind::Return),
        ],
    );
    let mut operation_machine = machine(
        program(vec![operation_root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    let first = match operation_machine.step() {
        MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => operation,
        other => panic!("unexpected operation budget step: {other:?}"),
    };
    operation_machine
        .complete_operation(first.identity, LogicalValue::unit())
        .unwrap_or_else(|error| panic!("operation completion failed: {error:?}"));
    assert!(matches!(
        operation_machine.step(),
        MachineStep::Transition(_)
    ));
    assert!(matches!(
        operation_machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::OperationBudget
    ));

    let loop_root = unit_workflow(vec![
        instruction(
            0,
            TypeDescriptor::UNIT,
            InstructionKind::EnterLoop {
                phase: LoopPhase::Body,
                source_limit: None,
            },
        ),
        instruction(1, TypeDescriptor::UNIT, InstructionKind::LeaveOccurrence),
        instruction(2, TypeDescriptor::UNIT, InstructionKind::Jump(0)),
    ]);
    let mut loop_machine = machine(
        program(vec![loop_root]),
        "crate::main",
        Vec::new(),
        limits(8, 1, 1, 1, 8),
    );
    for _ in 0..3 {
        assert!(matches!(loop_machine.step(), MachineStep::Transition(_)));
    }
    assert!(matches!(
        loop_machine.step(),
        MachineStep::Transition(MachineLabel::Failure(ref failure))
            if failure.code == RuntimeCode::LoopIterationBudget
    ));

    for invalid in [
        MachineLimits::new(0, 1, 1, 1, 1, DEFAULT_VALUE_LIMITS),
        MachineLimits::new(1, 0, 1, 1, 1, DEFAULT_VALUE_LIMITS),
        MachineLimits::new(1, 1, 0, 1, 1, DEFAULT_VALUE_LIMITS),
        MachineLimits::new(1, 1, 1, 0, 1, DEFAULT_VALUE_LIMITS),
        MachineLimits::new(1, 1, 1, 1, 0, DEFAULT_VALUE_LIMITS),
    ] {
        assert!(invalid.is_none());
    }
}

fn failure_programs() -> Vec<(&'static str, Workflow, MachineLimits)> {
    let maximum = GantryInt::new(9_007_199_254_740_991)
        .unwrap_or_else(|| unreachable!("maximum Int is admitted"));
    let one = GantryInt::new(1).unwrap_or_else(|| unreachable!("one is admitted"));
    let zero = GantryInt::new(0).unwrap_or_else(|| unreachable!("zero is admitted"));
    let float_max =
        GantryFloat::new(f64::MAX).unwrap_or_else(|| unreachable!("maximum Float is finite"));
    let float_zero = GantryFloat::new(0.0).unwrap_or_else(|| unreachable!("zero is finite"));
    let ordinary = limits(16, 1, 1, 1, 16);
    vec![
        failure_case(
            "integer-overflow",
            vec![LogicalValue::integer(maximum), LogicalValue::integer(one)],
            Primitive::Add,
            ordinary,
        ),
        failure_case(
            "integer-division-by-zero",
            vec![LogicalValue::integer(one), LogicalValue::integer(zero)],
            Primitive::Divide,
            ordinary,
        ),
        failure_case(
            "integer-remainder-by-zero",
            vec![LogicalValue::integer(one), LogicalValue::integer(zero)],
            Primitive::Remainder,
            ordinary,
        ),
        failure_case(
            "float-division-by-zero",
            vec![
                LogicalValue::float(float_max),
                LogicalValue::float(float_zero),
            ],
            Primitive::Divide,
            ordinary,
        ),
        failure_case(
            "float-non-finite-result",
            vec![
                LogicalValue::float(float_max),
                LogicalValue::float(float_max),
            ],
            Primitive::Multiply,
            ordinary,
        ),
        projection_failure_case(),
        failure_case(
            "string-empty-pattern",
            vec![string("abc"), string(""), string("x")],
            Primitive::StringReplace,
            ordinary,
        ),
        failure_case(
            "string-empty-separator",
            vec![string("abc"), string("")],
            Primitive::StringSplit,
            ordinary,
        ),
        string_limit_case(),
        list_limit_case(),
    ]
}

fn failure_case(
    code: &'static str,
    values: Vec<LogicalValue>,
    primitive: Primitive,
    limits: MachineLimits,
) -> (&'static str, Workflow, MachineLimits) {
    let mut instructions = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            instruction(
                index as u64,
                TypeDescriptor::UNIT,
                InstructionKind::Push(value),
            )
        })
        .collect::<Vec<_>>();
    instructions.push(instruction(
        instructions.len() as u64,
        TypeDescriptor::UNIT,
        InstructionKind::Primitive(primitive),
    ));
    (code, unit_workflow(instructions), limits)
}

fn projection_failure_case() -> (&'static str, Workflow, MachineLimits) {
    let list = LogicalValue::list(vec![LogicalValue::unit()], DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("fixture list failed: {error:?}"));
    (
        "list-index-out-of-bounds",
        unit_workflow(vec![
            instruction(0, TypeDescriptor::UNIT, InstructionKind::Push(list)),
            instruction(
                1,
                TypeDescriptor::UNIT,
                InstructionKind::Project(Projection::Member(1)),
            ),
        ]),
        limits(8, 1, 1, 1, 8),
    )
}

fn string_limit_case() -> (&'static str, Workflow, MachineLimits) {
    let value_limits = ValueLimits::new(8, 16, 1, 8)
        .unwrap_or_else(|| unreachable!("fixture limits are positive"));
    (
        "string-size-limit",
        unit_workflow(vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(string("a")),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(string("b")),
            ),
            instruction(
                2,
                TypeDescriptor::STRING,
                InstructionKind::Primitive(Primitive::Add),
            ),
        ]),
        MachineLimits::new(8, 1, 1, 1, 8, value_limits)
            .unwrap_or_else(|| unreachable!("fixture limits are positive")),
    )
}

fn list_limit_case() -> (&'static str, Workflow, MachineLimits) {
    let value_limits = ValueLimits::new(8, 16, 8, 1)
        .unwrap_or_else(|| unreachable!("fixture limits are positive"));
    (
        "list-size-limit",
        unit_workflow(vec![
            instruction(
                0,
                TypeDescriptor::STRING,
                InstructionKind::Push(string("a,b")),
            ),
            instruction(
                1,
                TypeDescriptor::STRING,
                InstructionKind::Push(string(",")),
            ),
            instruction(
                2,
                TypeDescriptor::UNIT,
                InstructionKind::Primitive(Primitive::StringSplit),
            ),
        ]),
        MachineLimits::new(8, 1, 1, 1, 8, value_limits)
            .unwrap_or_else(|| unreachable!("fixture limits are positive")),
    )
}

fn unit_workflow(instructions: Vec<Instruction>) -> Workflow {
    workflow(
        "crate::main",
        Vec::new(),
        TypeDescriptor::UNIT,
        EffectSet::default(),
        instructions,
    )
}

fn run_string_primitive(values: Vec<LogicalValue>, primitive: Primitive) -> String {
    let result_type = if matches!(primitive, Primitive::StringSplit) {
        TypeDescriptor::list(TypeDescriptor::STRING)
    } else {
        TypeDescriptor::STRING
    };
    let value = run_primitive(values, primitive, result_type);
    std::str::from_utf8(value.canonical_json().bytes())
        .unwrap_or_else(|error| panic!("canonical output is not UTF-8: {error}"))
        .trim_matches('"')
        .to_owned()
}

fn run_primitive(
    values: Vec<LogicalValue>,
    primitive: Primitive,
    result_type: TypeDescriptor,
) -> LogicalValue {
    let mut instructions = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            instruction(
                index as u64,
                TypeDescriptor::UNIT,
                InstructionKind::Push(value),
            )
        })
        .collect::<Vec<_>>();
    instructions.push(instruction(
        instructions.len() as u64,
        TypeDescriptor::UNIT,
        InstructionKind::Primitive(primitive),
    ));
    instructions.push(instruction(
        instructions.len() as u64,
        TypeDescriptor::UNIT,
        InstructionKind::Return,
    ));
    let last = instructions
        .last_mut()
        .unwrap_or_else(|| unreachable!("return instruction exists"));
    last.ty = result_type.clone();
    let primitive_index = instructions.len() - 2;
    instructions[primitive_index].ty = result_type.clone();
    let root = workflow(
        "crate::main",
        Vec::new(),
        result_type,
        EffectSet::default(),
        instructions,
    );
    let mut machine = machine(
        program(vec![root]),
        "crate::main",
        Vec::new(),
        limits(16, 1, 1, 1, 16),
    );
    let MachineOutcome::Succeeded(value) = drive(&mut machine).0 else {
        panic!("primitive fixture failed")
    };
    value
}

fn integer(value: i64) -> LogicalValue {
    LogicalValue::integer(
        GantryInt::new(value).unwrap_or_else(|| panic!("fixture Int is outside Gantry range")),
    )
}

fn float(value: f64) -> LogicalValue {
    LogicalValue::float(
        GantryFloat::new(value).unwrap_or_else(|| panic!("fixture Float is nonfinite")),
    )
}

fn assert_bool(value: &LogicalValue, expected: bool) {
    assert!(matches!(value.view(), LogicalValueView::Bool(actual) if actual == expected));
}

fn assert_int(value: &LogicalValue, expected: i64) {
    assert!(matches!(value.view(), LogicalValueView::Int(actual) if actual.get() == expected));
}

fn assert_float(value: &LogicalValue, expected: f64) {
    assert!(matches!(value.view(), LogicalValueView::Float(actual) if actual.get() == expected));
}

fn assert_bool_field(value: &LogicalValue, expected: bool) {
    let field = value
        .field("flag")
        .unwrap_or_else(|| panic!("fixture field is missing"));
    assert!(matches!(field.view(), LogicalValueView::Bool(value) if value == expected));
}

fn terminal_labels(labels: &[MachineLabel]) -> Vec<String> {
    labels
        .iter()
        .filter_map(|label| match label {
            MachineLabel::TaskSettled(_) => Some("task-settled".to_owned()),
            MachineLabel::ForegroundCompletion(_) => Some("foreground-completion".to_owned()),
            MachineLabel::TerminalCompletion(_) => Some("terminal-completion".to_owned()),
            _ => None,
        })
        .collect()
}

fn drive(machine: &mut Machine) -> (MachineOutcome, Vec<MachineLabel>) {
    let mut labels = Vec::new();
    for _ in 0..100_000 {
        match machine.step() {
            MachineStep::Transition(label) => labels.push(label),
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            MachineStep::WaitingSessionScope(scope) => {
                panic!("unexpected session-scope wait: {:?}", scope.site)
            }
            MachineStep::WaitingOperation(operation) => {
                panic!("unexpected operation wait: {}", operation.identity)
            }
            MachineStep::Complete(outcome) => return (outcome, labels),
        }
    }
    panic!("machine did not terminate within the fixture bound")
}

fn next_operation(machine: &mut Machine) -> gantry::runtime::OperationOccurrence {
    loop {
        match machine.step() {
            MachineStep::Transition(MachineLabel::OperationPrepared(operation)) => {
                return operation;
            }
            MachineStep::Transition(_) => {}
            MachineStep::YieldRequired => assert!(machine.resume_after_yield()),
            other => panic!("unexpected pre-operation step: {other:?}"),
        }
    }
}

fn machine(
    program: Arc<MachineProgram>,
    root: &str,
    arguments: Vec<LogicalValue>,
    limits: MachineLimits,
) -> Machine {
    Machine::new(program, &path(root), arguments, execution(), limits)
        .unwrap_or_else(|error| panic!("machine construction failed: {error:?}"))
}

fn program(workflows: Vec<Workflow>) -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(workflows)
            .unwrap_or_else(|error| panic!("invalid fixture program: {error:?}")),
    )
}

fn workflow(
    name: &str,
    parameters: Vec<Parameter>,
    result: TypeDescriptor,
    effects: EffectSet,
    instructions: Vec<Instruction>,
) -> Workflow {
    Workflow {
        path: path(name),
        parameters,
        result,
        effects,
        instructions,
    }
}

fn instruction(index: u64, ty: TypeDescriptor, kind: InstructionKind) -> Instruction {
    Instruction {
        site: StructuralPosition::new(vec![index])
            .unwrap_or_else(|error| panic!("invalid fixture site: {error}")),
        ty,
        kind,
    }
}

fn path(name: &str) -> CanonicalPath {
    CanonicalPath::new(name).unwrap_or_else(|error| panic!("invalid fixture path: {error}"))
}

fn limits(
    transitions: u64,
    operations: u64,
    loops: u64,
    depth: u64,
    quantum: u64,
) -> MachineLimits {
    MachineLimits::new(
        transitions,
        operations,
        loops,
        depth,
        quantum,
        DEFAULT_VALUE_LIMITS,
    )
    .unwrap_or_else(|| unreachable!("fixture limits are positive"))
}

fn execution() -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(IdentityKind::Execution, [0x24; 32])
        .unwrap_or_else(|error| panic!("invalid fixture identity: {error}"))
}

fn string(value: &str) -> LogicalValue {
    LogicalValue::string(value, DEFAULT_VALUE_LIMITS)
        .unwrap_or_else(|error| panic!("fixture string failed: {error:?}"))
}

fn vectors() -> MachineVectors {
    read_json(&workspace_root().join("protocol/goldens/sequential-machine-v1.json"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}
