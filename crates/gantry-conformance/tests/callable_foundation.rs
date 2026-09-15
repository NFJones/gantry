//! Callable-value, capture, reuse, and frame-admission evidence.

use std::collections::{BTreeMap, BTreeSet};

use gantry::ir::generated::Effect;
use gantry::ir::generated::TypeKind;
use gantry::ir::{
    BindingFacts, BindingState, CallSettlement, CallableDiagnosticCode, CallableKind,
    CallableLimits, CallableProjection, CallableType, CallableValue, CaptureAccess,
    CaptureCandidate, CaptureClass, CaptureDescriptor, CaptureInference, CaptureMode, CapturePlan,
    EffectSet, OwnershipClass, ReuseState, TypeDescriptor, TypeDescriptorError,
    require_captured_row, resolve_capture_set, resolve_captured_row, union_row,
};

/// Returns the refusal produced by one rejected callable decision.
trait Refused<E> {
    fn refused(self, context: &str) -> E;
}

impl<T, E> Refused<E> for Result<T, E> {
    fn refused(self, context: &str) -> E {
        match self {
            Ok(_) => panic!("{context}: the decision must be refused"),
            Err(error) => error,
        }
    }
}

/// Returns the bounded budgets used by this lane.
fn limits() -> CallableLimits {
    CallableLimits {
        max_parameters: 4,
        max_captures: 4,
        max_name_bytes: 32,
        max_frames: 3,
    }
}

/// Builds one declared effect row.
fn row(effects: &[Effect]) -> EffectSet {
    let mut set = EffectSet::default();
    for effect in effects {
        set.insert(*effect);
    }
    set
}

/// Builds one canonical capture plan.
fn captures(entries: &[(&str, CaptureMode)]) -> CapturePlan {
    let limits = limits();
    let declared: Vec<CaptureDescriptor> = entries
        .iter()
        .map(|(name, mode)| {
            CaptureDescriptor::new(name, *mode, limits)
                .unwrap_or_else(|error| panic!("capture: {error}"))
        })
        .collect();
    CapturePlan::new(declared, limits).unwrap_or_else(|error| panic!("plan: {error}"))
}

/// Returns the canonical declaration facts that derive one capture class.
fn facts(class: CaptureClass) -> BindingFacts {
    match class {
        CaptureClass::FreelyCopyable => BindingFacts::new(
            OwnershipClass::Copyable,
            BindingState::Independent,
            CaptureAccess::ByValue,
        ),
        CaptureClass::PrivateState => BindingFacts::new(
            OwnershipClass::Copyable,
            BindingState::Private,
            CaptureAccess::ByValue,
        ),
        CaptureClass::Affine => BindingFacts::new(
            OwnershipClass::MustConsume,
            BindingState::Independent,
            CaptureAccess::ByValue,
        ),
        CaptureClass::TemporaryLoan => BindingFacts::new(
            OwnershipClass::Copyable,
            BindingState::Independent,
            CaptureAccess::StatementBorrow,
        ),
    }
}

/// Builds one callable value with a single `Int` parameter and result.
fn callable(kind: CallableKind) -> CallableValue {
    CallableValue::new(
        kind,
        vec!["Int".to_owned()],
        "Int",
        captures(&[]),
        row(&[Effect::Prompt]),
        limits(),
    )
    .unwrap_or_else(|error| panic!("callable: {error}"))
}

/// Builds one callable value over explicit components.
fn composed(
    kind: CallableKind,
    parameters: &[&str],
    result: &str,
    entries: &[(&str, CaptureMode)],
    effects: &[Effect],
) -> CallableValue {
    let parameters = parameters
        .iter()
        .map(|parameter| (*parameter).to_owned())
        .collect();
    CallableValue::new(
        kind,
        parameters,
        result,
        captures(entries),
        row(effects),
        limits(),
    )
    .unwrap_or_else(|error| panic!("callable: {error}"))
}

#[test]
fn reuse_kinds_are_distinct_and_carry_reuse_rules() {
    let names: Vec<&str> = CallableKind::ALL
        .iter()
        .map(|kind| kind.canonical_name())
        .collect();
    assert_eq!(names, ["Fn", "FnMut", "FnOnce"]);
    assert!(CallableKind::Function.admits_overlapping_calls());
    assert!(!CallableKind::FunctionMut.admits_overlapping_calls());
    assert!(CallableKind::FunctionMut.requires_exclusive_access());
    assert!(CallableKind::FunctionOnce.consumes_on_admission());
    assert!(!CallableKind::Function.consumes_on_admission());
    assert_eq!(
        CallableKind::from_canonical_name("FnOnce").ok(),
        Some(CallableKind::FunctionOnce)
    );
    let refusal = CallableKind::from_canonical_name("FnPtr").refused("unknown reuse kind");
    assert_eq!(refusal.code(), CallableDiagnosticCode::ShapeRefused);
}

#[test]
fn declared_shape_budgets_refuse_over_budget_values() {
    let tight = CallableLimits {
        max_parameters: 1,
        max_captures: 1,
        max_name_bytes: 3,
        max_frames: 1,
    };
    let empty =
        CapturePlan::new(Vec::new(), tight).unwrap_or_else(|error| panic!("empty plan: {error}"));
    let too_many = CallableValue::new(
        CallableKind::Function,
        vec!["Int".to_owned(), "Int".to_owned()],
        "Int",
        empty.clone(),
        EffectSet::default(),
        tight,
    )
    .refused("over-budget parameter list");
    assert_eq!(too_many.code(), CallableDiagnosticCode::ShapeRefused);
    let long_parameter = CallableValue::new(
        CallableKind::Function,
        vec!["Integer".to_owned()],
        "Int",
        empty.clone(),
        EffectSet::default(),
        tight,
    )
    .refused("over-budget parameter name");
    assert_eq!(long_parameter.code(), CallableDiagnosticCode::ShapeRefused);
    let empty_parameter = CallableValue::new(
        CallableKind::Function,
        vec![String::new()],
        "Int",
        empty.clone(),
        EffectSet::default(),
        tight,
    )
    .refused("unnamed parameter");
    assert_eq!(empty_parameter.code(), CallableDiagnosticCode::ShapeRefused);
    let empty_result = CallableValue::new(
        CallableKind::Function,
        Vec::new(),
        "",
        empty,
        EffectSet::default(),
        tight,
    )
    .refused("empty result type");
    assert_eq!(empty_result.code(), CallableDiagnosticCode::ShapeRefused);
}

#[test]
fn capture_plans_order_bindings_and_refuse_duplicates() {
    let declared = captures(&[("beta", CaptureMode::Move), ("alpha", CaptureMode::Copy)]);
    let reordered = captures(&[("alpha", CaptureMode::Copy), ("beta", CaptureMode::Move)]);
    assert_eq!(
        declared
            .captures()
            .iter()
            .map(CaptureDescriptor::name)
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    assert_eq!(
        declared.canonical_encoding(),
        reordered.canonical_encoding()
    );
    assert!(!declared.is_empty());
    assert!(captures(&[]).is_empty());
    let limits = limits();
    let duplicate = CapturePlan::new(
        vec![
            CaptureDescriptor::new("alpha", CaptureMode::Copy, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
            CaptureDescriptor::new("alpha", CaptureMode::Move, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
        ],
        limits,
    )
    .refused("duplicate capture binding");
    assert_eq!(duplicate.code(), CallableDiagnosticCode::CaptureRefused);
    let unnamed = CaptureDescriptor::new("", CaptureMode::Copy, limits).refused("unnamed capture");
    assert_eq!(unnamed.code(), CallableDiagnosticCode::CaptureRefused);
    let over_budget = CapturePlan::new(
        vec![
            CaptureDescriptor::new("alpha", CaptureMode::Copy, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
            CaptureDescriptor::new("beta", CaptureMode::Copy, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
            CaptureDescriptor::new("gamma", CaptureMode::Copy, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
            CaptureDescriptor::new("delta", CaptureMode::Copy, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
            CaptureDescriptor::new("epsilon", CaptureMode::Copy, limits)
                .unwrap_or_else(|error| panic!("capture: {error}")),
        ],
        limits,
    )
    .refused("over-budget capture plan");
    assert_eq!(over_budget.code(), CallableDiagnosticCode::ShapeRefused);
}

#[test]
fn capture_modes_carry_their_durability_rules() {
    assert_eq!(CaptureMode::ALL.len(), 3);
    assert!(CaptureMode::Copy.is_durable());
    assert!(CaptureMode::Move.is_durable());
    assert!(!CaptureMode::Loan.is_durable());
    assert!(CaptureMode::Move.transfers_ownership());
    assert!(!CaptureMode::Copy.transfers_ownership());
    assert_eq!(
        CaptureMode::from_canonical_name("loan").ok(),
        Some(CaptureMode::Loan)
    );
    assert_eq!(
        CaptureMode::from_canonical_name("borrow")
            .refused("unknown capture mode")
            .code(),
        CallableDiagnosticCode::ShapeRefused
    );
    assert!(!captures(&[("alpha", CaptureMode::Loan)]).is_durable());
    assert!(captures(&[("alpha", CaptureMode::Move)]).is_durable());
}

#[test]
fn diagnostic_spellings_are_frozen_and_distinct() {
    let codes: Vec<&str> = CallableDiagnosticCode::ALL
        .iter()
        .map(|code| code.code())
        .collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(codes[0], "callable-shape-refused");
    assert_eq!(codes[1], "callable-capture-refused");
    assert_eq!(codes[2], "callable-reuse-refused");
    assert_eq!(codes[3], "callable-frame-limit");
    assert_eq!(codes[4], "callable-settlement-refused");
    assert_eq!(codes[5], "callable-effect-erasure");
    assert_eq!(codes[6], "callable-durable-capture");
    assert_eq!(codes[7], "callable-round-trip-loss");
    assert_eq!(codes[8], "callable-type-unadmitted");
    assert_eq!(codes[9], "callable-expression-unadmitted");
    for (index, code) in codes.iter().enumerate() {
        assert!(!codes[index + 1..].contains(code), "{code} is shared");
    }
}

#[test]
fn single_use_admission_consumes_and_refuses_reuse() {
    let mut value = callable(CallableKind::FunctionOnce);
    let admission = value
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    assert_eq!(value.state(), ReuseState::Consumed);
    assert_eq!(value.live_calls(), 1);
    let refusal = value.admit(0, limits()).refused("reuse after consumption");
    assert_eq!(refusal.code(), CallableDiagnosticCode::ReuseRefused);
    value
        .settle(admission, CallSettlement::Completed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    assert_eq!(value.state(), ReuseState::Consumed);
    assert_eq!(value.live_calls(), 0);
}

#[test]
fn mutating_kind_refuses_overlapping_admissions_until_settlement() {
    let mut value = callable(CallableKind::FunctionMut);
    let admission = value
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    let refusal = value
        .admit(1, limits())
        .refused("overlapping exclusive call");
    assert_eq!(refusal.code(), CallableDiagnosticCode::ReuseRefused);
    value
        .settle(admission, CallSettlement::DomainError)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    assert_eq!(value.state(), ReuseState::Live);
    assert!(value.admit(1, limits()).is_ok());
}

#[test]
fn immutable_kind_admits_overlapping_calls_within_the_frame_budget() {
    let mut value = callable(CallableKind::Function);
    let first = value
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    let second = value
        .admit(1, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    assert_eq!(value.live_calls(), 2);
    assert_eq!(first.depth(), 0);
    assert_eq!(second.depth(), 1);
    assert_ne!(first.id(), second.id());
    value
        .settle(second, CallSettlement::Completed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    value
        .settle(first, CallSettlement::Completed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    assert_eq!(value.live_calls(), 0);
    assert_eq!(value.state(), ReuseState::Live);
}

#[test]
fn admission_depth_beyond_the_budget_is_refused_before_any_charge() {
    let tight = CallableLimits {
        max_frames: 1,
        ..limits()
    };
    let mut value = callable(CallableKind::Function);
    let refusal = value
        .admit(1, tight)
        .refused("depth beyond the frame budget");
    assert_eq!(refusal.code(), CallableDiagnosticCode::FrameLimit);
    assert_eq!(value.live_calls(), 0);
    assert!(value.admit(0, tight).is_ok());
}

#[test]
fn settlement_must_match_an_outstanding_admission() {
    let mut value = callable(CallableKind::FunctionMut);
    let admission = value
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    value
        .settle(admission, CallSettlement::Completed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    let repeated = value
        .settle(admission, CallSettlement::Completed)
        .refused("repeated settlement");
    assert_eq!(repeated.code(), CallableDiagnosticCode::SettlementRefused);
    let mut foreign = callable(CallableKind::FunctionMut);
    let unexpected = foreign
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    let mismatched = value
        .settle(unexpected, CallSettlement::Completed)
        .refused("settlement of a foreign admission");
    assert_eq!(mismatched.code(), CallableDiagnosticCode::SettlementRefused);
}

#[test]
fn failure_settlement_poisons_exclusive_kinds_only() {
    assert!(!CallSettlement::Completed.poisons_exclusive_state());
    assert!(!CallSettlement::DomainError.poisons_exclusive_state());
    assert!(CallSettlement::Failed.poisons_exclusive_state());
    assert!(CallSettlement::Cancelled.poisons_exclusive_state());
    let mut mutating = callable(CallableKind::FunctionMut);
    let admission = mutating
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    mutating
        .settle(admission, CallSettlement::Cancelled)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    assert_eq!(mutating.state(), ReuseState::Poisoned);
    assert_eq!(
        mutating.admit(0, limits()).refused("poisoned reuse").code(),
        CallableDiagnosticCode::ReuseRefused
    );
    let mut immutable = callable(CallableKind::Function);
    let admission = immutable
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    immutable
        .settle(admission, CallSettlement::Failed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    assert_eq!(immutable.state(), ReuseState::Live);
    let mut single = callable(CallableKind::FunctionOnce);
    let admission = single
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    single
        .settle(admission, CallSettlement::Failed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    assert_eq!(single.state(), ReuseState::Poisoned);
}

#[test]
fn declared_rows_never_erase_component_effects() {
    let value = composed(
        CallableKind::Function,
        &["Int"],
        "Int",
        &[],
        &[Effect::Prompt, Effect::Spawn],
    );
    let spawn = row(&[Effect::Spawn]);
    let prompt = row(&[Effect::Prompt]);
    assert!(value.row_is_closed(&[spawn, prompt]));
    value
        .require_closed_row(&[prompt, spawn])
        .unwrap_or_else(|error| panic!("row: {error}"));
    let session = row(&[Effect::Session]);
    assert!(!value.row_is_closed(&[session]));
    let refusal = value
        .require_closed_row(&[session])
        .refused("row erasing an effect");
    assert_eq!(refusal.code(), CallableDiagnosticCode::EffectErasure);
    assert_eq!(union_row(&[prompt, spawn]), union_row(&[spawn, prompt]));
    assert_eq!(union_row(&[]), EffectSet::default());
    assert_eq!(value.row(), union_row(&[prompt, spawn]));
}

#[test]
fn capture_rows_compose_from_offered_enclosing_bindings() {
    let value = composed(
        CallableKind::Function,
        &["Int"],
        "Int",
        &[("beta", CaptureMode::Copy), ("alpha", CaptureMode::Copy)],
        &[Effect::Prompt, Effect::Spawn],
    );
    let prompt = row(&[Effect::Prompt]);
    let spawn = row(&[Effect::Spawn]);
    let mut offered = BTreeMap::new();
    offered.insert("alpha", prompt);
    offered.insert("beta", spawn);
    let resolved = resolve_captured_row(&value, &offered)
        .unwrap_or_else(|error| panic!("captured row: {error}"));
    assert_eq!(resolved, union_row(&[prompt, spawn]));

    // A binding that no capture names cannot widen a row.
    let mut widened = offered.clone();
    widened.insert("gamma", row(&[Effect::Session]));
    assert_eq!(
        resolve_captured_row(&value, &widened).unwrap_or_else(|error| panic!("row: {error}")),
        resolved
    );

    // An ordinary captured value contributes no effect.
    let mut plain = BTreeMap::new();
    plain.insert("alpha", EffectSet::default());
    plain.insert("beta", spawn);
    assert_eq!(
        resolve_captured_row(&value, &plain).unwrap_or_else(|error| panic!("row: {error}")),
        spawn
    );

    // A capture that names no offered binding is refused instead of erasing its effect.
    let mut missing = BTreeMap::new();
    missing.insert("alpha", prompt);
    let refusal =
        resolve_captured_row(&value, &missing).refused("capture without an offered binding");
    assert_eq!(refusal.code(), CallableDiagnosticCode::CaptureRefused);
    assert!(refusal.detail().contains("beta"), "{refusal}");

    // A value with no captures composes the empty row.
    assert_eq!(
        resolve_captured_row(&callable(CallableKind::Function), &BTreeMap::new())
            .unwrap_or_else(|error| panic!("row: {error}")),
        EffectSet::default()
    );

    // The declared row must contain the composed component row.
    assert_eq!(
        require_captured_row(&value, &offered).unwrap_or_else(|error| panic!("row: {error}")),
        resolved
    );
    let narrow = composed(
        CallableKind::Function,
        &["Int"],
        "Int",
        &[("beta", CaptureMode::Copy), ("alpha", CaptureMode::Copy)],
        &[Effect::Prompt],
    );
    let refusal = require_captured_row(&narrow, &offered).refused("row erasing a captured effect");
    assert_eq!(refusal.code(), CallableDiagnosticCode::EffectErasure);
}

#[test]
fn canonical_encodings_are_injective_and_order_independent() {
    let split = composed(
        CallableKind::Function,
        &["a", "b"],
        "c",
        &[("alpha", CaptureMode::Copy)],
        &[Effect::Prompt],
    );
    let joined = composed(
        CallableKind::Function,
        &["ab"],
        "c",
        &[("alpha", CaptureMode::Copy)],
        &[Effect::Prompt],
    );
    let widened = composed(
        CallableKind::Function,
        &["ab"],
        "c",
        &[("alpha", CaptureMode::Copy)],
        &[Effect::Prompt, Effect::Spawn],
    );
    let moved = composed(
        CallableKind::Function,
        &["ab"],
        "c",
        &[("alpha", CaptureMode::Move)],
        &[Effect::Prompt],
    );
    let once = composed(
        CallableKind::FunctionOnce,
        &["ab"],
        "c",
        &[("alpha", CaptureMode::Copy)],
        &[Effect::Prompt],
    );
    let identities = [
        split.canonical_encoding(),
        joined.canonical_encoding(),
        widened.canonical_encoding(),
        moved.canonical_encoding(),
        once.canonical_encoding(),
    ];
    for (index, identity) in identities.iter().enumerate() {
        assert!(
            !identities[index + 1..].contains(identity),
            "canonical encodings collide"
        );
    }
    let reordered = composed(
        CallableKind::Function,
        &["ab"],
        "c",
        &[("beta", CaptureMode::Move), ("alpha", CaptureMode::Copy)],
        &[Effect::Prompt],
    );
    let canonical = composed(
        CallableKind::Function,
        &["ab"],
        "c",
        &[("alpha", CaptureMode::Copy), ("beta", CaptureMode::Move)],
        &[Effect::Prompt],
    );
    assert_eq!(
        reordered.canonical_encoding(),
        canonical.canonical_encoding()
    );
    assert_eq!(joined.parameters(), &["ab".to_owned()][..]);
    assert_eq!(joined.result(), "c");
    assert_eq!(joined.kind(), CallableKind::Function);
}

#[test]
fn durable_projection_refuses_ineligible_values() {
    let loaned = composed(
        CallableKind::Function,
        &[],
        "Int",
        &[("alpha", CaptureMode::Loan)],
        &[Effect::Prompt],
    );
    let refusal = loaned
        .durable_projection()
        .refused("loan capture is not durable");
    assert_eq!(refusal.code(), CallableDiagnosticCode::DurableCapture);
    let mut live = composed(
        CallableKind::Function,
        &[],
        "Int",
        &[("alpha", CaptureMode::Move)],
        &[Effect::Prompt],
    );
    let admission = live
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    let refusal = live
        .durable_projection()
        .refused("live call is not durable");
    assert_eq!(refusal.code(), CallableDiagnosticCode::DurableCapture);
    live.settle(admission, CallSettlement::Completed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    let projection = live
        .durable_projection()
        .unwrap_or_else(|error| panic!("projection: {error}"));
    assert_eq!(projection.kind(), CallableKind::Function);
    assert_eq!(projection.result(), "Int");
    assert_eq!(projection.parameters().len(), 0);
    let carried: Vec<(String, CaptureMode)> = vec![("alpha".to_owned(), CaptureMode::Move)];
    assert_eq!(projection.captures(), carried.as_slice());
    assert_eq!(projection.row(), row(&[Effect::Prompt]));
    assert_eq!(projection.identity(), live.canonical_encoding().as_str());
    let mut consumed = callable(CallableKind::FunctionOnce);
    let admission = consumed
        .admit(0, limits())
        .unwrap_or_else(|error| panic!("admission: {error}"));
    consumed
        .settle(admission, CallSettlement::Completed)
        .unwrap_or_else(|error| panic!("settlement: {error}"));
    let refusal = consumed
        .durable_projection()
        .refused("consumed callable has no durable state");
    assert_eq!(refusal.code(), CallableDiagnosticCode::DurableCapture);
}

#[test]
fn rebuilt_projections_refuse_round_trip_loss() {
    let limits = limits();
    let value = composed(
        CallableKind::FunctionMut,
        &["Int"],
        "Int",
        &[("alpha", CaptureMode::Move), ("beta", CaptureMode::Copy)],
        &[Effect::Prompt, Effect::ActionReadOnly],
    );
    let projection = value
        .durable_projection()
        .unwrap_or_else(|error| panic!("projection: {error}"));
    value
        .require_round_trip(&projection)
        .unwrap_or_else(|error| panic!("round trip: {error}"));
    let rebuilt = projection
        .rebuild(limits)
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    assert_eq!(rebuilt.canonical_encoding(), value.canonical_encoding());
    assert_eq!(rebuilt.state(), ReuseState::Live);
    assert_eq!(rebuilt.captures().captures().len(), 2);
    let dropped = CallableProjection::carried(
        CallableKind::FunctionMut,
        vec!["Int".to_owned()],
        "Int",
        vec![("alpha".to_owned(), CaptureMode::Move)],
        row(&[Effect::Prompt, Effect::ActionReadOnly]),
        projection.identity(),
    );
    let refusal = dropped.rebuild(limits).refused("dropped capture");
    assert_eq!(refusal.code(), CallableDiagnosticCode::RoundTripLoss);
    let foreign = CallableProjection::carried(
        CallableKind::FunctionMut,
        vec!["Int".to_owned()],
        "Int",
        vec![("alpha".to_owned(), CaptureMode::Move)],
        row(&[Effect::Prompt, Effect::ActionReadOnly]),
        "0:foreign",
    );
    let refusal = value
        .require_round_trip(&foreign)
        .refused("foreign identity");
    assert_eq!(refusal.code(), CallableDiagnosticCode::RoundTripLoss);
    let altered = CallableProjection::carried(
        CallableKind::FunctionMut,
        vec!["Int".to_owned()],
        "Int",
        vec![
            ("alpha".to_owned(), CaptureMode::Copy),
            ("beta".to_owned(), CaptureMode::Copy),
        ],
        row(&[Effect::Prompt, Effect::ActionReadOnly]),
        projection.identity(),
    );
    let refusal = altered.rebuild(limits).refused("altered capture mode");
    assert_eq!(refusal.code(), CallableDiagnosticCode::RoundTripLoss);
    let reordered = CallableProjection::carried(
        CallableKind::FunctionMut,
        vec!["Int".to_owned()],
        "Int",
        vec![
            ("alpha".to_owned(), CaptureMode::Move),
            ("beta".to_owned(), CaptureMode::Copy),
        ],
        row(&[Effect::Prompt, Effect::ActionReadOnly]),
        projection.identity(),
    );
    assert!(reordered.rebuild(limits).is_ok());
    let extended = CallableProjection::carried(
        CallableKind::FunctionMut,
        vec!["Int".to_owned()],
        "Int",
        vec![
            ("alpha".to_owned(), CaptureMode::Move),
            ("beta".to_owned(), CaptureMode::Copy),
        ],
        row(&[Effect::Prompt, Effect::ActionReadOnly, Effect::Spawn]),
        projection.identity(),
    );
    let refusal = extended.rebuild(limits).refused("extended effect row");
    assert_eq!(refusal.code(), CallableDiagnosticCode::RoundTripLoss);
}

/// The frozen Section 37 clause identifiers.
const CALLABLE_CLAUSES: [&str; 13] = [
    "GNT-37.0-callable-values-and-frame-admission",
    "GNT-37.1-reuse-kinds-and-canonical-shape",
    "GNT-37.2-bounded-logical-frame-admission",
    "GNT-37.3-explicit-captures-and-capture-plans",
    "GNT-37.4-reuse-kinds-and-affine-consumption",
    "GNT-37.5-settlement-and-poisoning",
    "GNT-37.6-exact-effect-rows",
    "GNT-37.7-durable-capture-projection",
    "GNT-37.8-durable-round-trips-and-identity",
    "GNT-37.9-canonical-encoding-and-order-independence",
    "GNT-37.10-direct-call-and-receiver-compatibility",
    "GNT-37.11-refusal-discipline-and-atomicity",
    "GNT-37.12-callable-non-claims",
];

#[test]
fn section_37_anchors_and_nonclaims_are_published() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(CALLABLE_CLAUSES.len(), 13);
    for clause in CALLABLE_CLAUSES {
        assert!(
            spec.contains(&format!("<a id=\"{clause}\"></a>")),
            "{clause} is not published"
        );
        assert!(
            spec.contains(&format!("**[{clause}] ")),
            "{clause} carries no clause text"
        );
    }
    assert_eq!(CallableDiagnosticCode::ALL.len(), 10);
    for code in CallableDiagnosticCode::ALL {
        assert!(
            spec.contains(&format!("`{}`", code.code())),
            "{} is not published",
            code.code()
        );
    }
    assert!(
        spec.contains(
            "closure types are unadmitted except as defined by the Section 37 callable contract"
        ),
        "GNT-3-T-GENERIC-CALL does not record the Section 37 admission"
    );
    assert!(
        spec.contains("`occurrence` field")
            && spec.contains("`annotation` when the refused type is not a component")
            && spec.contains("`nested-component` when it is a component"),
        "GNT-37.0 does not publish the callable type occurrence classes"
    );
}

/// The frozen callable diagnostics with the clause that owns each refusal condition.
const CALLABLE_DIAGNOSTIC_OWNERS: [(&str, &str); 10] = [
    ("callable-shape-refused", "GNT-37.1"),
    ("callable-frame-limit", "GNT-37.2"),
    ("callable-capture-refused", "GNT-37.3"),
    ("callable-reuse-refused", "GNT-37.4"),
    ("callable-settlement-refused", "GNT-37.5"),
    ("callable-effect-erasure", "GNT-37.6"),
    ("callable-durable-capture", "GNT-37.7"),
    ("callable-round-trip-loss", "GNT-37.8"),
    ("callable-type-unadmitted", "GNT-37.0"),
    ("callable-expression-unadmitted", "GNT-37.0"),
];

#[test]
fn frozen_diagnostics_name_their_owning_clause_in_the_specification() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(
        CALLABLE_DIAGNOSTIC_OWNERS.len(),
        CallableDiagnosticCode::ALL.len()
    );
    for (spelling, owner) in CALLABLE_DIAGNOSTIC_OWNERS {
        assert!(
            spec.contains(&format!("`{spelling}` (`{owner}`)")),
            "{spelling} is not published with its owning clause {owner}"
        );
        assert!(
            CALLABLE_CLAUSES
                .iter()
                .any(|clause| clause.starts_with(owner)),
            "{owner} is not a published Section 37 clause"
        );
        assert!(
            CallableDiagnosticCode::ALL
                .iter()
                .any(|code| code.code() == spelling),
            "{spelling} is not a frozen model diagnostic"
        );
    }
}

#[test]
fn callable_types_realize_the_published_identity_tuple() {
    let limits = limits();
    let declared = composed(
        CallableKind::Function,
        &["Int", "Bool"],
        "Text",
        &[("count", CaptureMode::Copy)],
        &[Effect::Prompt],
    );
    let same_shape = composed(CallableKind::Function, &["Int", "Bool"], "Text", &[], &[]);
    assert_eq!(declared.callable_type(), same_shape.callable_type());
    assert_eq!(
        declared.callable_type().canonical_encoding(),
        same_shape.callable_type().canonical_encoding()
    );
    assert_eq!(
        declared.callable_type(),
        CallableType::new(
            CallableKind::Function,
            vec!["Int".to_owned(), "Bool".to_owned()],
            "Text",
            limits,
        )
        .unwrap_or_else(|error| panic!("type: {error}"))
    );
    let expected_parameters = vec!["Int".to_owned(), "Bool".to_owned()];
    assert_eq!(
        declared.callable_type().parameters(),
        expected_parameters.as_slice()
    );
    assert_eq!(declared.callable_type().result(), "Text");
    assert_eq!(declared.callable_type().kind(), CallableKind::Function);

    let departures = [
        (
            "reuse kind",
            composed(
                CallableKind::FunctionMut,
                &["Int", "Bool"],
                "Text",
                &[],
                &[],
            ),
        ),
        (
            "parameter order",
            composed(CallableKind::Function, &["Bool", "Int"], "Text", &[], &[]),
        ),
        (
            "result type",
            composed(CallableKind::Function, &["Int", "Bool"], "Int", &[], &[]),
        ),
    ];
    for (label, value) in departures {
        assert_ne!(
            declared.callable_type().canonical_encoding(),
            value.callable_type().canonical_encoding(),
            "{label} must change the callable identity"
        );
    }
}

#[test]
fn callable_types_refuse_shape_departures_and_over_budget_forms() {
    let limits = limits();
    let declared = CallableType::new(
        CallableKind::Function,
        vec!["Int".to_owned()],
        "Int",
        limits,
    )
    .unwrap_or_else(|error| panic!("type: {error}"));
    let identical = CallableType::new(
        CallableKind::Function,
        vec!["Int".to_owned()],
        "Int",
        limits,
    )
    .unwrap_or_else(|error| panic!("type: {error}"));
    assert!(declared.require_identical(&identical).is_ok());
    assert_eq!(declared, identical);
    assert!(
        declared
            .require_value_shape(&callable(CallableKind::Function))
            .is_ok()
    );

    let departures = [
        ("reuse kind", callable(CallableKind::FunctionOnce)),
        (
            "result type",
            composed(CallableKind::Function, &["Int"], "Bool", &[], &[]),
        ),
        (
            "parameter order",
            composed(CallableKind::Function, &["Bool", "Int"], "Int", &[], &[]),
        ),
    ];
    for (label, value) in departures {
        let refusal = declared.require_value_shape(&value).refused(label);
        assert_eq!(refusal.code(), CallableDiagnosticCode::ShapeRefused);
        let refusal = declared
            .require_identical(&value.callable_type())
            .refused(label);
        assert_eq!(refusal.code(), CallableDiagnosticCode::ShapeRefused);
    }

    let over_budget = CallableType::new(
        CallableKind::Function,
        vec!["Int".to_owned(); 5],
        "Int",
        limits,
    )
    .refused("over-budget parameter list");
    assert_eq!(over_budget.code(), CallableDiagnosticCode::ShapeRefused);
    let long_name = CallableType::new(
        CallableKind::Function,
        vec!["I".repeat(limits.max_name_bytes + 1)],
        "Int",
        limits,
    )
    .refused("over-budget parameter name");
    assert_eq!(long_name.code(), CallableDiagnosticCode::ShapeRefused);
    let unnamed = CallableType::new(CallableKind::Function, vec![String::new()], "Int", limits)
        .refused("unnamed parameter");
    assert_eq!(unnamed.code(), CallableDiagnosticCode::ShapeRefused);
    let no_result = CallableType::new(CallableKind::Function, Vec::new(), "", limits)
        .refused("empty result type");
    assert_eq!(no_result.code(), CallableDiagnosticCode::ShapeRefused);
}

#[test]
fn callable_type_encodings_are_injective_and_projections_agree() {
    let limits = limits();
    let forms = [
        vec!["Int".to_owned()],
        vec!["Int".to_owned(), "Int".to_owned()],
        vec!["In".to_owned(), "t".to_owned()],
        vec!["IntInt".to_owned()],
        vec!["IntIn".to_owned(), "t".to_owned()],
    ];
    let mut encodings = Vec::new();
    for parameters in forms {
        let callable_type = CallableType::new(CallableKind::Function, parameters, "Int", limits)
            .unwrap_or_else(|error| panic!("type: {error}"));
        encodings.push(callable_type.canonical_encoding());
    }
    for (index, encoding) in encodings.iter().enumerate() {
        for (other_index, other) in encodings.iter().enumerate() {
            assert_eq!(
                index == other_index,
                encoding == other,
                "parameter spellings {index} and {other_index} must stay distinct"
            );
        }
    }

    let value = composed(CallableKind::Function, &["Int"], "Int", &[], &[]);
    let value_encoding = value.canonical_encoding();
    let type_encoding = value.callable_type().canonical_encoding();
    assert_ne!(type_encoding, value_encoding);
    assert!(!value_encoding.starts_with(&type_encoding));
    assert!(!type_encoding.starts_with(&value_encoding));

    let durable = composed(
        CallableKind::Function,
        &["Int", "Bool"],
        "Text",
        &[("count", CaptureMode::Copy), ("items", CaptureMode::Move)],
        &[Effect::Prompt],
    );
    let projection = durable
        .durable_projection()
        .unwrap_or_else(|error| panic!("projection: {error}"));
    assert_eq!(projection.callable_type(), durable.callable_type());
    assert!(
        projection
            .callable_type()
            .require_value_shape(&durable)
            .is_ok()
    );
    assert_eq!(
        projection
            .rebuild(limits)
            .unwrap_or_else(|error| panic!("rebuild: {error}"))
            .callable_type(),
        durable.callable_type()
    );
}

#[test]
fn capture_classes_assign_modes_and_require_kinds() {
    let limits = limits();
    assert!(CallableKind::Function < CallableKind::FunctionMut);
    assert!(CallableKind::FunctionMut < CallableKind::FunctionOnce);
    for class in CaptureClass::ALL {
        assert_eq!(CaptureClass::from_facts(facts(class)), class);
        let candidate = CaptureCandidate::from_facts("binding", facts(class), limits)
            .unwrap_or_else(|error| panic!("candidate: {error}"));
        assert_eq!(candidate.name(), "binding");
        assert_eq!(candidate.class(), class);
        let assignment = CaptureInference::infer(&[candidate], false, limits)
            .unwrap_or_else(|error| panic!("assignment: {error}"));
        assert_eq!(assignment.plan().captures().len(), 1);
        assert_eq!(
            assignment.plan().captures()[0].mode(),
            class.assigned_mode()
        );
        assert_eq!(assignment.kind(), class.required_kind());
        assert_eq!(
            CaptureClass::from_canonical_name(class.canonical_name())
                .unwrap_or_else(|error| panic!("class: {error}")),
            class
        );
    }

    let unknown = CaptureClass::from_canonical_name("borrow").refused("unknown capture class");
    assert_eq!(unknown.code(), CallableDiagnosticCode::CaptureRefused);
    let unnamed = CaptureCandidate::from_facts("", facts(CaptureClass::Affine), limits)
        .refused("unnamed binding");
    assert_eq!(unnamed.code(), CallableDiagnosticCode::CaptureRefused);
    let long = CaptureCandidate::from_facts(
        &"b".repeat(limits.max_name_bytes + 1),
        facts(CaptureClass::Affine),
        limits,
    )
    .refused("over-budget binding name");
    assert_eq!(long.code(), CallableDiagnosticCode::ShapeRefused);
}

#[test]
fn assigned_kinds_are_the_weakest_sufficient_kind() {
    let limits = limits();
    let offered = |entries: &[(&str, CaptureClass)]| -> Vec<CaptureCandidate> {
        entries
            .iter()
            .map(|(name, class)| {
                CaptureCandidate::from_facts(name, facts(*class), limits)
                    .unwrap_or_else(|error| panic!("candidate: {error}"))
            })
            .collect()
    };
    let assign = |entries: &[(&str, CaptureClass)], escapes: bool| {
        CaptureInference::infer(&offered(entries), escapes, limits)
            .unwrap_or_else(|error| panic!("assignment: {error}"))
    };

    assert_eq!(assign(&[], false).kind(), CallableKind::Function);
    assert_eq!(
        assign(&[("a", CaptureClass::FreelyCopyable)], false).kind(),
        CallableKind::Function
    );
    assert_eq!(
        assign(&[("a", CaptureClass::PrivateState)], false).kind(),
        CallableKind::FunctionMut
    );
    assert_eq!(
        assign(&[("a", CaptureClass::TemporaryLoan)], false).kind(),
        CallableKind::FunctionMut
    );
    assert_eq!(
        assign(&[("a", CaptureClass::Affine)], false).kind(),
        CallableKind::FunctionOnce
    );
    assert_eq!(
        assign(
            &[
                ("a", CaptureClass::FreelyCopyable),
                ("b", CaptureClass::PrivateState),
            ],
            false
        )
        .kind(),
        CallableKind::FunctionMut
    );
    assert_eq!(
        assign(
            &[
                ("a", CaptureClass::FreelyCopyable),
                ("b", CaptureClass::Affine),
            ],
            false
        )
        .kind(),
        CallableKind::FunctionOnce
    );

    let forward = assign(
        &[
            ("zeta", CaptureClass::Affine),
            ("alpha", CaptureClass::FreelyCopyable),
        ],
        false,
    );
    let reversed = assign(
        &[
            ("alpha", CaptureClass::FreelyCopyable),
            ("zeta", CaptureClass::Affine),
        ],
        false,
    );
    assert_eq!(forward, reversed);
    assert_eq!(
        forward.plan().canonical_encoding(),
        reversed.plan().canonical_encoding()
    );
    let names: Vec<&str> = forward
        .plan()
        .captures()
        .iter()
        .map(CaptureDescriptor::name)
        .collect();
    assert_eq!(names, vec!["alpha", "zeta"]);

    let value = CallableValue::new(
        forward.kind(),
        vec!["Int".to_owned()],
        "Int",
        forward.plan().clone(),
        row(&[Effect::Prompt]),
        limits,
    )
    .unwrap_or_else(|error| panic!("value: {error}"));
    assert!(forward.require_consistent(&value).is_ok());

    let weaker = assign(&[("alpha", CaptureClass::FreelyCopyable)], false);
    let kind_departure = weaker.require_consistent(&value).refused("kind departure");
    assert_eq!(kind_departure.code(), CallableDiagnosticCode::ReuseRefused);
    let other_plan = assign(&[("beta", CaptureClass::Affine)], false);
    let capture_departure = other_plan
        .require_consistent(&value)
        .refused("capture departure");
    assert_eq!(
        capture_departure.code(),
        CallableDiagnosticCode::CaptureRefused
    );
}

#[test]
fn escaping_loans_and_duplicate_or_over_budget_offers_are_refused() {
    let limits = limits();
    let loan = CaptureCandidate::from_facts("outer", facts(CaptureClass::TemporaryLoan), limits)
        .unwrap_or_else(|error| panic!("candidate: {error}"));
    let escaping =
        CaptureInference::infer(std::slice::from_ref(&loan), true, limits).refused("escaping loan");
    assert_eq!(escaping.code(), CallableDiagnosticCode::CaptureRefused);
    assert!(escaping.detail().contains("outer"));
    let local = CaptureInference::infer(&[loan], false, limits)
        .unwrap_or_else(|error| panic!("assignment: {error}"));
    assert_eq!(local.plan().captures()[0].mode(), CaptureMode::Loan);
    assert!(!local.plan().is_durable());

    let repeated = vec![
        CaptureCandidate::from_facts("same", facts(CaptureClass::FreelyCopyable), limits)
            .unwrap_or_else(|error| panic!("candidate: {error}")),
        CaptureCandidate::from_facts("same", facts(CaptureClass::PrivateState), limits)
            .unwrap_or_else(|error| panic!("candidate: {error}")),
    ];
    let duplicate = CaptureInference::infer(&repeated, false, limits).refused("duplicate binding");
    assert_eq!(duplicate.code(), CallableDiagnosticCode::CaptureRefused);

    let over_budget: Vec<CaptureCandidate> = (0..=limits.max_captures)
        .map(|index| {
            CaptureCandidate::from_facts(
                &format!("binding{index}"),
                facts(CaptureClass::FreelyCopyable),
                limits,
            )
            .unwrap_or_else(|error| panic!("candidate: {error}"))
        })
        .collect();
    let budget = CaptureInference::infer(&over_budget, false, limits).refused("over-budget plan");
    assert_eq!(budget.code(), CallableDiagnosticCode::ShapeRefused);

    let mixed = vec![
        CaptureCandidate::from_facts("a", facts(CaptureClass::Affine), limits)
            .unwrap_or_else(|error| panic!("candidate: {error}")),
        CaptureCandidate::from_facts("b", facts(CaptureClass::TemporaryLoan), limits)
            .unwrap_or_else(|error| panic!("candidate: {error}")),
    ];
    let refused =
        CaptureInference::infer(&mixed, true, limits).refused("loan in an escaping callable");
    assert_eq!(refused.code(), CallableDiagnosticCode::CaptureRefused);
}

#[test]
fn capture_classes_follow_declaration_facts() {
    let limits = limits();
    let derived = |ownership, state, access| {
        CaptureClass::from_facts(BindingFacts::new(ownership, state, access))
    };

    // A statement-scoped borrow is a loan whatever the other facts are.
    for ownership in [
        OwnershipClass::Copyable,
        OwnershipClass::AffineDroppable,
        OwnershipClass::MustConsume,
    ] {
        for state in [BindingState::Independent, BindingState::Private] {
            assert_eq!(
                derived(ownership, state, CaptureAccess::StatementBorrow),
                CaptureClass::TemporaryLoan
            );
        }
    }

    // A binding whose ownership class prohibits copying is affine whether or
    // not its state is private, and a privately held copyable binding is private
    // state rather than an independent copy.
    for ownership in [OwnershipClass::AffineDroppable, OwnershipClass::MustConsume] {
        for state in [BindingState::Independent, BindingState::Private] {
            assert_eq!(
                derived(ownership, state, CaptureAccess::ByValue),
                CaptureClass::Affine
            );
        }
    }
    assert_eq!(
        derived(
            OwnershipClass::Copyable,
            BindingState::Private,
            CaptureAccess::ByValue
        ),
        CaptureClass::PrivateState
    );
    assert_eq!(
        derived(
            OwnershipClass::Copyable,
            BindingState::Independent,
            CaptureAccess::ByValue
        ),
        CaptureClass::FreelyCopyable
    );

    // One fact set yields exactly one class, and every class carries facts that
    // derive it, so no caller can claim an unsupported class.
    for class in CaptureClass::ALL {
        let recorded = facts(class);
        assert_eq!(CaptureClass::from_facts(recorded), class);
        let candidate = CaptureCandidate::from_facts("binding", recorded, limits)
            .unwrap_or_else(|error| panic!("candidate: {error}"));
        assert_eq!(candidate.class(), class);
    }

    // The capture set resolved from enclosing bindings is ordered by binding
    // name whatever order the bindings are offered in, and a duplicated binding
    // is still refused when the set is assigned.
    let forward = resolve_capture_set(
        &[
            ("zeta", facts(CaptureClass::Affine)),
            ("alpha", facts(CaptureClass::FreelyCopyable)),
        ],
        limits,
    )
    .unwrap_or_else(|error| panic!("resolve: {error}"));
    let reversed = resolve_capture_set(
        &[
            ("alpha", facts(CaptureClass::FreelyCopyable)),
            ("zeta", facts(CaptureClass::Affine)),
        ],
        limits,
    )
    .unwrap_or_else(|error| panic!("resolve: {error}"));
    assert_eq!(forward, reversed);
    let assignment = CaptureInference::infer(&forward, false, limits)
        .unwrap_or_else(|error| panic!("assignment: {error}"));
    assert_eq!(assignment.kind(), CallableKind::FunctionOnce);
    let names: Vec<&str> = assignment
        .plan()
        .captures()
        .iter()
        .map(CaptureDescriptor::name)
        .collect();
    assert_eq!(names, vec!["alpha", "zeta"]);

    let repeated = resolve_capture_set(
        &[
            ("same", facts(CaptureClass::FreelyCopyable)),
            ("same", facts(CaptureClass::PrivateState)),
        ],
        limits,
    )
    .unwrap_or_else(|error| panic!("resolve: {error}"));
    let duplicate = CaptureInference::infer(&repeated, false, limits).refused("duplicate binding");
    assert_eq!(duplicate.code(), CallableDiagnosticCode::CaptureRefused);

    let loan = resolve_capture_set(&[("outer", facts(CaptureClass::TemporaryLoan))], limits)
        .unwrap_or_else(|error| panic!("resolve: {error}"));
    let escaping = CaptureInference::infer(&loan, true, limits).refused("escaping loan");
    assert_eq!(escaping.code(), CallableDiagnosticCode::CaptureRefused);
}

/// A callable type is one closed type descriptor whose spelling carries its whole
/// identity, and the closed vocabulary names its kind.
#[test]
fn callable_types_join_the_closed_type_vocabulary_with_one_spelling() {
    assert_eq!(TypeKind::Callable.wire_name(), "Callable");
    let declared = CallableType::new(
        CallableKind::FunctionMut,
        vec!["Int".to_owned(), "String".to_owned()],
        "Bool",
        limits(),
    )
    .unwrap_or_else(|error| panic!("type: {error}"));
    let descriptor = TypeDescriptor::callable(
        CallableKind::FunctionMut,
        vec![TypeDescriptor::INT, TypeDescriptor::STRING],
        TypeDescriptor::BOOL,
    );
    assert_eq!(descriptor.kind(), TypeKind::Callable);
    assert_eq!(
        descriptor.canonical_string(),
        "Callable<FnMut,Int,String,Bool>"
    );
    assert_eq!(descriptor.callable_type(), Some(declared.clone()));
    assert!(descriptor.declared_path().is_none());
    assert!(descriptor.primitive_properties().is_none());
    assert!(!descriptor.contains_sealed_boundary());
    assert_eq!(
        descriptor.immediate_members(),
        [
            TypeDescriptor::INT,
            TypeDescriptor::STRING,
            TypeDescriptor::BOOL
        ]
    );
    // The spelling round-trips to the identity it carries.
    let decoded = TypeDescriptor::from_canonical_string(&descriptor.canonical_string())
        .unwrap_or_else(|error| panic!("decode: {error}"));
    assert_eq!(decoded, descriptor);
    assert_eq!(decoded.callable_type(), Some(declared));
    // Distinct reuse kinds, parameter orders, arities, and results never share
    // one spelling.
    let mut spelled = BTreeSet::new();
    for (kind, parameters, result) in [
        (CallableKind::Function, vec!["Int"], "Bool"),
        (CallableKind::FunctionMut, vec!["Int"], "Bool"),
        (CallableKind::FunctionOnce, vec!["Int"], "Bool"),
        (CallableKind::Function, vec!["Bool"], "Int"),
        (CallableKind::Function, Vec::new(), "Int"),
        (CallableKind::Function, vec!["Int", "String"], "Bool"),
    ] {
        let members = parameters
            .iter()
            .map(|name| {
                TypeDescriptor::from_canonical_string(name)
                    .unwrap_or_else(|error| panic!("member {name}: {error}"))
            })
            .collect::<Vec<_>>();
        let result = TypeDescriptor::from_canonical_string(result)
            .unwrap_or_else(|error| panic!("result {result}: {error}"));
        let candidate = TypeDescriptor::callable(kind, members, result);
        assert!(
            spelled.insert(candidate.canonical_string()),
            "two identities shared one spelling"
        );
    }
    // A sealed member position is visible on the descriptor, and a malformed
    // spelling is refused rather than repaired.
    let sealed =
        TypeDescriptor::callable(CallableKind::Function, Vec::new(), TypeDescriptor::DECISION);
    assert!(sealed.contains_sealed_boundary());
    assert_eq!(sealed.canonical_string(), "Callable<Fn,Decision>");
    for malformed in [
        "Callable<Fn>",
        "Callable<Fnn,Int>",
        "Callable<Fn,Int",
        "callable<Fn,Int>",
    ] {
        assert_eq!(
            TypeDescriptor::from_canonical_string(malformed),
            Err(TypeDescriptorError::InvalidCanonicalString),
            "spelling: {malformed}"
        );
    }
}
