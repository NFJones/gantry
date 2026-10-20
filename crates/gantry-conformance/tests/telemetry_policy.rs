//! Conformance for the bounded telemetry policy and admission model of `SPEC.md` Section 48.
//!
//! Every test is a pure function of its own declared records, policies, grants, releases, and sink
//! accounting state. No test reads a clock, process, thread, environment, host path, or live handle,
//! and no test spawns work. The lane exercises the public model only; it does not claim a sink,
//! adapter, queue, source-global behavior, or Section 12 semantic evidence.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    ProjectionKind, ProtectedDataClass, ProtectedValue, ProvenanceOrigin, ProvenanceOriginKind,
    ReleaseDestination, ReleaseProjection, TELEMETRY_CLAUSES, TELEMETRY_NAME_LIMIT,
    TelemetryAdmission, TelemetryContext, TelemetryContextEntry, TelemetryDeliveryClass,
    TelemetryDestinationRelease, TelemetryDiagnosticCode, TelemetryEmitGrant, TelemetryError,
    TelemetryFaultClass, TelemetryField, TelemetryLabel, TelemetryLimit, TelemetryLimitDimension,
    TelemetryLimitSet, TelemetryLimits, TelemetryMetricValue, TelemetryName,
    TelemetryProtectedReference, TelemetryRecord, TelemetryRecordBody, TelemetryRecordKind,
    TelemetrySettlement, TelemetrySinkFault, TelemetrySinkId, TelemetrySinkInstanceId,
    TelemetrySinkPolicy, TelemetrySinkState, TelemetryTraceStatus, telemetry_is_semantic_evidence,
};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming the associated
/// item requires an inference that cannot be resolved and compilation fails. A `Clone`
/// implementation for a pending emit would let one emit be settled twice, which `GNT-48.6` and
/// `GNT-48.7` forbid: an acknowledgement, cancellation, ambiguity, or failure settles one emit once.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_name:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $(
                impl<T: ?Sized + $trait_name> AmbiguousIfImpl<Invalid> for T {}
            )+
            struct Invalid;
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl_any!(gantry::ir::TelemetryEmit: Clone);
assert_not_impl_any!(gantry::ir::TelemetrySinkState: Clone);

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn specification() -> String {
    fs::read_to_string(workspace_root().join("SPEC.md"))
        .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn name(value: &str) -> TelemetryName {
    TelemetryName::new(value).unwrap_or_else(|error| panic!("valid telemetry name: {error}"))
}

fn sink(value: &str) -> TelemetrySinkId {
    TelemetrySinkId::new(value).unwrap_or_else(|error| panic!("valid sink identity: {error}"))
}

fn instance(value: &str) -> TelemetrySinkInstanceId {
    TelemetrySinkInstanceId::new(value)
        .unwrap_or_else(|error| panic!("valid sink instance identity: {error}"))
}

fn label(key: &str, value: &str) -> TelemetryLabel {
    TelemetryLabel::new(name(key), value)
        .unwrap_or_else(|error| panic!("valid telemetry label: {error}"))
}

fn field(key: &str, value: &str) -> TelemetryField {
    TelemetryField::new(name(key), value)
        .unwrap_or_else(|error| panic!("valid telemetry field: {error}"))
}

fn context(key: &str, value: &str) -> TelemetryContext {
    let entry = TelemetryContextEntry::new(name(key), value)
        .unwrap_or_else(|error| panic!("valid telemetry context entry: {error}"));
    TelemetryContext::new(vec![entry])
}

fn log_record(sequence: u64, record_name: &str) -> TelemetryRecord {
    TelemetryRecord::log(sequence, name(record_name), "declared message")
        .unwrap_or_else(|error| panic!("valid log record: {error}"))
}

fn limits_with(apply: impl FnOnce(&mut TelemetryLimitSet)) -> TelemetryLimits {
    let mut set = TelemetryLimitSet::declared();
    apply(&mut set);
    TelemetryLimits::new(set).unwrap_or_else(|error| panic!("valid finite limits: {error}"))
}

fn policy(
    sink: TelemetrySinkId,
    delivery: TelemetryDeliveryClass,
    limits: TelemetryLimits,
    release: Option<TelemetryDestinationRelease>,
) -> TelemetrySinkPolicy {
    TelemetrySinkPolicy::new(sink, delivery, limits, release, 7)
        .unwrap_or_else(|error| panic!("valid sink policy: {error}"))
}

fn required_policy(limits: TelemetryLimits) -> TelemetrySinkPolicy {
    policy(
        sink("sink-a"),
        TelemetryDeliveryClass::Required,
        limits,
        None,
    )
}

fn best_effort_policy(limits: TelemetryLimits) -> TelemetrySinkPolicy {
    policy(
        sink("sink-a"),
        TelemetryDeliveryClass::BestEffort,
        limits,
        None,
    )
}

fn refused<T>(result: Result<T, TelemetryError>, context: &str) -> TelemetryError {
    match result {
        Ok(_) => panic!("{context}: the declared operation must be refused"),
        Err(error) => error,
    }
}

fn assert_atomic_refusal(
    state: &mut TelemetrySinkState,
    policy: &TelemetrySinkPolicy,
    record: &TelemetryRecord,
    expected: TelemetryDiagnosticCode,
) {
    let before = state.snapshot();
    let error = refused(
        state.admit(Some(policy), Some(&TelemetryEmitGrant::granted()), record),
        "a bounded admission refusal",
    );
    assert_eq!(error.code(), expected);
    assert_eq!(
        state.snapshot(),
        before,
        "a refusal never mutates sink accounting"
    );
}

fn protected_value(class: ProtectedDataClass) -> ProtectedValue {
    let origin = ProvenanceOrigin::new(ProvenanceOriginKind::IntegrationBoundary, "fixture")
        .unwrap_or_else(|error| panic!("valid provenance: {error:?}"));
    ProtectedValue::seal(class, origin)
}

fn telemetry_release(
    sink: &TelemetrySinkId,
    class: ProtectedDataClass,
) -> TelemetryDestinationRelease {
    let projection = ReleaseProjection::new(
        ProjectionKind::Redacted,
        class,
        ReleaseDestination::NullTelemetry,
    );
    TelemetryDestinationRelease::new(sink.clone())
        .declare(class, projection)
        .unwrap_or_else(|error| panic!("valid telemetry destination release: {error}"))
}

#[test]
fn telemetry_clauses_and_closed_vocabularies_are_published() {
    assert_eq!(
        TELEMETRY_CLAUSES,
        [
            "GNT-48.0-observe-foundation-scope",
            "GNT-48.1-observe-modules-and-item-rows",
            "GNT-48.2-telemetry-record-kinds-and-explicit-context",
            "GNT-48.3-telemetry-sink-policy-and-finite-limits",
            "GNT-48.4-telemetry-atomic-admission-and-cardinality",
            "GNT-48.5-telemetry-protected-labels-identity-and-release",
            "GNT-48.6-telemetry-required-acknowledgement-and-best-effort",
            "GNT-48.7-telemetry-backpressure-cancellation-and-shutdown",
            "GNT-48.8-telemetry-sink-fault-containment",
            "GNT-48.9-telemetry-evidence-separation-and-non-claims",
        ]
    );
    let specification = specification();
    for clause in TELEMETRY_CLAUSES {
        assert!(
            specification.contains(&format!("<a id=\"{clause}\"></a>")),
            "SPEC.md publishes the anchor {clause}"
        );
        assert!(
            specification.contains(&format!("**[{clause}] ")),
            "SPEC.md publishes clause text for {clause}"
        );
    }
    for rule in [
        "Telemetry is never Section 12 semantic evidence",
        "ambient, task, thread, process, environment, locale, or global context is read",
        "a finite zero is a declared denial of that dimension",
        "A refusal leaves the queue, pending emits, retention count, active-series set, drop count",
        "a telemetry-destination release never declassifies",
        "an ambiguous write is never silently retried",
        "The application owns drain and flush",
        "recursive fault logging is not declared",
    ] {
        assert!(specification.contains(rule), "SPEC.md pins: {rule}");
    }

    for kind in TelemetryRecordKind::ALL {
        assert_eq!(
            TelemetryRecordKind::from_wire_name(kind.wire_name()),
            Some(kind)
        );
        assert_eq!(
            kind.module_name(),
            format!("std.observe::{}", kind.wire_name())
        );
    }
    assert_eq!(TelemetryRecordKind::from_wire_name("event"), None);
    for class in TelemetryDeliveryClass::ALL {
        assert_eq!(
            TelemetryDeliveryClass::from_wire_name(class.wire_name()),
            Some(class)
        );
    }
    assert_eq!(
        TelemetryDeliveryClass::from_wire_name("fire-and-forget"),
        None
    );
    for status in TelemetryTraceStatus::ALL {
        assert_eq!(
            TelemetryTraceStatus::from_wire_name(status.wire_name()),
            Some(status)
        );
    }
    for class in TelemetryFaultClass::ALL {
        assert_eq!(
            TelemetryFaultClass::from_wire_name(class.wire_name()),
            Some(class)
        );
    }
    assert_eq!(TelemetryLimitDimension::ALL.len(), 13);
    let mut dimensions = std::collections::BTreeSet::new();
    for dimension in TelemetryLimitDimension::ALL {
        assert_eq!(
            dimension.index(),
            TelemetryLimitDimension::ALL
                .iter()
                .position(|entry| *entry == dimension)
                .unwrap_or_else(|| panic!("dimension index"))
        );
        assert!(!dimension.wire_name().is_empty());
        assert!(
            dimensions.insert(dimension.wire_name()),
            "each dimension owns one spelling"
        );
    }
    assert_eq!(TelemetryDiagnosticCode::ALL.len(), 24);
    let mut prior_code = None;
    for code in TelemetryDiagnosticCode::ALL {
        assert_eq!(
            TelemetryDiagnosticCode::from_wire_name(code.wire_name()),
            Some(code)
        );
        assert!(TELEMETRY_CLAUSES.contains(&code.clause()));
        assert!(specification.contains(code.wire_name()));
        if let Some(previous) = prior_code {
            assert!(
                previous < code.wire_name(),
                "diagnostic codes sort by wire name"
            );
        }
        prior_code = Some(code.wire_name());
    }
    for clause in [
        "GNT-48.2-telemetry-record-kinds-and-explicit-context",
        "GNT-48.3-telemetry-sink-policy-and-finite-limits",
        "GNT-48.4-telemetry-atomic-admission-and-cardinality",
        "GNT-48.5-telemetry-protected-labels-identity-and-release",
        "GNT-48.7-telemetry-backpressure-cancellation-and-shutdown",
        "GNT-48.8-telemetry-sink-fault-containment",
    ] {
        assert!(
            TelemetryDiagnosticCode::ALL
                .iter()
                .any(|code| code.clause() == clause),
            "clause {clause} owns at least one refusal"
        );
    }
}

#[test]
fn typed_records_and_explicit_context_are_bounded_and_canonical() {
    for invalid in ["", "has space", "caf\u{e9}", "line\nbreak"] {
        assert_eq!(
            TelemetryName::new(invalid).err().map(|error| error.code()),
            Some(TelemetryDiagnosticCode::InvalidIdentity)
        );
    }
    let too_long = "a".repeat(TELEMETRY_NAME_LIMIT + 1);
    assert_eq!(
        TelemetryName::new(too_long).err().map(|error| error.code()),
        Some(TelemetryDiagnosticCode::InvalidIdentity)
    );
    assert_eq!(name("request.latency").as_str(), "request.latency");
    assert!(!name("request.latency").is_empty());

    assert_eq!(
        TelemetryRecord::log(1, name("log"), "")
            .err()
            .map(|error| error.code()),
        Some(TelemetryDiagnosticCode::InvalidRecord)
    );
    assert_eq!(
        TelemetryRecord::log(1, name("log"), "bad\u{0007}message")
            .err()
            .map(|error| error.code()),
        Some(TelemetryDiagnosticCode::InvalidRecord)
    );

    let metric = TelemetryRecord::metric(
        2,
        name("request.count"),
        TelemetryMetricValue::Unsigned(3),
        Some(name("count")),
    );
    assert_eq!(metric.kind(), TelemetryRecordKind::Metric);
    assert_eq!(
        metric.body(),
        &TelemetryRecordBody::Metric {
            value: TelemetryMetricValue::Unsigned(3),
            unit: Some(name("count")),
        }
    );
    let trace = TelemetryRecord::trace(3, name("span"), 42, TelemetryTraceStatus::Ok);
    assert_eq!(trace.kind(), TelemetryRecordKind::Trace);
    assert_eq!(
        trace.body(),
        &TelemetryRecordBody::Trace {
            duration_ns: 42,
            status: TelemetryTraceStatus::Ok,
        }
    );

    let sorted = log_record(4, "log")
        .with_fields(vec![field("z", "last"), field("a", "first")])
        .unwrap_or_else(|error| panic!("valid fields: {error}"));
    assert_eq!(sorted.fields()[0].name().as_str(), "a");
    assert_eq!(sorted.fields()[1].name().as_str(), "z");
    assert_eq!(
        log_record(5, "log")
            .with_fields(vec![field("a", "one"), field("a", "two")])
            .err()
            .map(|error| error.code()),
        Some(TelemetryDiagnosticCode::InvalidRecord)
    );
    let labeled = log_record(6, "log")
        .with_labels(vec![label("zone", "b"), label("region", "a")])
        .unwrap_or_else(|error| panic!("valid labels: {error}"));
    assert_eq!(labeled.labels()[0].name().as_str(), "region");
    assert_eq!(
        log_record(7, "log")
            .with_labels(vec![label("zone", "a"), label("zone", "b")])
            .err()
            .map(|error| error.code()),
        Some(TelemetryDiagnosticCode::InvalidRecord)
    );

    let declared = log_record(8, "log").with_context(context("trace", "abc"));
    assert_eq!(declared.context().depth(), 1);
    assert!(declared.context().bytes() > 0);
    assert!(declared.material_bytes() > 0);
    assert!(!declared.is_section_12_evidence());

    let reference = TelemetryProtectedReference::from_value(&protected_value(
        ProtectedDataClass::RenderedPrompt,
    ));
    assert_eq!(
        log_record(9, "log")
            .with_protected(vec![reference.clone(), reference])
            .err()
            .map(|error| error.code()),
        Some(TelemetryDiagnosticCode::InvalidRecord)
    );
}

#[test]
fn complete_finite_limits_are_required_and_zero_denies_a_dimension() {
    let finite = TelemetryLimits::new(TelemetryLimitSet::declared())
        .unwrap_or_else(|error| panic!("declared limits are finite: {error}"));
    assert_eq!(finite, TelemetryLimits::declared());
    for dimension in TelemetryLimitDimension::ALL {
        let mut set = TelemetryLimitSet::declared();
        match dimension {
            TelemetryLimitDimension::RecordBytes => {
                set.max_record_bytes = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::Fields => set.max_fields = TelemetryLimit::unlimited(),
            TelemetryLimitDimension::FieldBytes => {
                set.max_field_bytes = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::Labels => set.max_labels = TelemetryLimit::unlimited(),
            TelemetryLimitDimension::LabelBytes => {
                set.max_label_bytes = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::ContextDepth => {
                set.max_context_depth = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::ContextBytes => {
                set.max_context_bytes = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::Series => set.max_series = TelemetryLimit::unlimited(),
            TelemetryLimitDimension::Queue => set.max_queue = TelemetryLimit::unlimited(),
            TelemetryLimitDimension::Retention => set.max_retention = TelemetryLimit::unlimited(),
            TelemetryLimitDimension::PendingEmits => {
                set.max_pending_emits = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::ShutdownDrain => {
                set.max_shutdown_drain = TelemetryLimit::unlimited()
            }
            TelemetryLimitDimension::ShutdownTimeout => {
                set.max_shutdown_timeout_us = TelemetryLimit::unlimited()
            }
        }
        let error = refused(TelemetryLimits::new(set), "an unlimited dimension");
        assert_eq!(error.code(), TelemetryDiagnosticCode::UnlimitedPolicy);
        assert!(error.detail().contains(dimension.wire_name()));
    }

    let zero = TelemetryLimits::new(TelemetryLimitSet {
        max_record_bytes: TelemetryLimit::Finite(0),
        max_fields: TelemetryLimit::Finite(0),
        max_field_bytes: TelemetryLimit::Finite(0),
        max_labels: TelemetryLimit::Finite(0),
        max_label_bytes: TelemetryLimit::Finite(0),
        max_context_depth: TelemetryLimit::Finite(0),
        max_context_bytes: TelemetryLimit::Finite(0),
        max_series: TelemetryLimit::Finite(0),
        max_queue: TelemetryLimit::Finite(0),
        max_retention: TelemetryLimit::Finite(0),
        max_pending_emits: TelemetryLimit::Finite(0),
        max_shutdown_drain: TelemetryLimit::Finite(0),
        max_shutdown_timeout_us: TelemetryLimit::Finite(0),
    })
    .unwrap_or_else(|error| panic!("zero is a finite denial: {error}"));
    for dimension in TelemetryLimitDimension::ALL {
        assert_eq!(zero.get(dimension), 0);
    }
}

#[test]
fn sink_policies_are_immutable_and_need_a_positive_bounded_wait() {
    let limits = TelemetryLimits::declared();
    let error = refused(
        TelemetrySinkPolicy::new(
            sink("sink-a"),
            TelemetryDeliveryClass::Required,
            limits,
            None,
            0,
        ),
        "a zero wait bound",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::BackpressureBound);

    let other_release = telemetry_release(&sink("sink-b"), ProtectedDataClass::RenderedPrompt);
    let error = refused(
        TelemetrySinkPolicy::new(
            sink("sink-a"),
            TelemetryDeliveryClass::Required,
            limits,
            Some(other_release),
            7,
        ),
        "a release for another sink",
    );
    assert_eq!(
        error.code(),
        TelemetryDiagnosticCode::ReleaseDestinationMismatch
    );

    let policy = required_policy(limits);
    assert_eq!(policy.sink().as_str(), "sink-a");
    assert_eq!(policy.delivery(), TelemetryDeliveryClass::Required);
    assert_eq!(policy.limits(), limits);
    assert_eq!(policy.wait_bound_us(), 7);
    assert!(!TelemetryEmitGrant::granted().declassifies());
}

#[test]
fn missing_policy_and_withheld_grant_refuse_without_mutation() {
    let record = log_record(1, "log");
    let policy = required_policy(TelemetryLimits::declared());
    let mut absent = TelemetrySinkState::new(instance("state-a"));
    let before = absent.snapshot();
    let error = refused(
        absent.admit(None, Some(&TelemetryEmitGrant::granted()), &record),
        "an absent policy",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::PolicyAbsent);
    assert_eq!(absent.snapshot(), before);

    let mut withheld = TelemetrySinkState::new(instance("state-a"));
    let before = withheld.snapshot();
    let error = refused(
        withheld.admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::withheld()),
            &record,
        ),
        "a withheld grant",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::EmitNotGranted);
    assert_eq!(withheld.snapshot(), before);
    let error = refused(
        withheld.admit(Some(&policy), None, &record),
        "a missing grant",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::EmitNotGranted);
    assert_eq!(withheld.snapshot(), before);
}

#[test]
fn record_field_label_and_context_bounds_refuse_atomically_without_truncation() {
    let record_with_field = log_record(1, "log")
        .with_fields(vec![field("component", "renderer")])
        .unwrap_or_else(|error| panic!("valid field: {error}"));
    let field_bytes = record_with_field.fields()[0].bytes();
    let record_with_label = log_record(2, "log")
        .with_labels(vec![label("region", "west")])
        .unwrap_or_else(|error| panic!("valid label: {error}"));
    let label_bytes = record_with_label.labels()[0].bytes();
    let record_with_context = log_record(3, "log").with_context(context("trace", "abc"));
    let context_bytes = record_with_context.context().bytes();

    let mut state = TelemetrySinkState::new(instance("state-a"));
    let record_bytes = log_record(4, "log").material_bytes();
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_record_bytes = TelemetryLimit::Finite(record_bytes - 1);
        })),
        &log_record(4, "log"),
        TelemetryDiagnosticCode::RecordBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_fields = TelemetryLimit::Finite(0)
        })),
        &record_with_field,
        TelemetryDiagnosticCode::FieldCountBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_field_bytes = TelemetryLimit::Finite(field_bytes - 1);
        })),
        &record_with_field,
        TelemetryDiagnosticCode::FieldByteBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_labels = TelemetryLimit::Finite(0)
        })),
        &record_with_label,
        TelemetryDiagnosticCode::LabelCountBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_label_bytes = TelemetryLimit::Finite(label_bytes - 1);
        })),
        &record_with_label,
        TelemetryDiagnosticCode::LabelByteBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_context_depth = TelemetryLimit::Finite(0);
        })),
        &record_with_context,
        TelemetryDiagnosticCode::ContextBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_context_bytes = TelemetryLimit::Finite(context_bytes - 1);
        })),
        &record_with_context,
        TelemetryDiagnosticCode::ContextBound,
    );

    assert_eq!(record_with_field.fields().len(), 1);
    assert_eq!(record_with_label.labels().len(), 1);
    assert_eq!(record_with_context.context().depth(), 1);
}

#[test]
fn cardinality_and_retention_refuse_instead_of_evicting() {
    let policy = required_policy(limits_with(|set| {
        set.max_series = TelemetryLimit::Finite(1);
        set.max_pending_emits = TelemetryLimit::Finite(4);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let first = log_record(1, "log")
        .with_labels(vec![label("region", "west")])
        .unwrap_or_else(|error| panic!("valid label: {error}"));
    let second = log_record(2, "log")
        .with_labels(vec![label("region", "east")])
        .unwrap_or_else(|error| panic!("valid label: {error}"));
    let admitted = state
        .admit(Some(&policy), Some(&TelemetryEmitGrant::granted()), &first)
        .unwrap_or_else(|error| panic!("the first series is admitted: {error}"));
    assert!(admitted.is_pending());
    assert_eq!(state.active_series(), 1);
    assert_atomic_refusal(
        &mut state,
        &policy,
        &second,
        TelemetryDiagnosticCode::SeriesBound,
    );
    assert_eq!(state.active_series(), 1);
    let repeated = state
        .admit(Some(&policy), Some(&TelemetryEmitGrant::granted()), &first)
        .unwrap_or_else(|error| panic!("an existing series is reused: {error}"));
    assert!(repeated.is_pending());
    assert_eq!(state.active_series(), 1);
    assert_eq!(state.pending_emits(), 2);

    let retention = required_policy(limits_with(|set| {
        set.max_retention = TelemetryLimit::Finite(1);
    }));
    let mut retained = TelemetrySinkState::new(instance("state-a"));
    assert!(retained.retain(Some(&retention), &first).is_ok());
    let before = retained.snapshot();
    let error = refused(retained.retain(Some(&retention), &second), "full retention");
    assert_eq!(error.code(), TelemetryDiagnosticCode::RetentionBound);
    assert_eq!(retained.snapshot(), before);
    assert_eq!(retained.retained(), 1);

    let zero_series = required_policy(limits_with(|set| {
        set.max_series = TelemetryLimit::Finite(0);
    }));
    let mut denied = TelemetrySinkState::new(instance("state-a"));
    assert_atomic_refusal(
        &mut denied,
        &zero_series,
        &first,
        TelemetryDiagnosticCode::SeriesBound,
    );
    assert_eq!(denied.active_series(), 0);
}

#[test]
fn required_delivery_completes_only_at_acknowledgement() {
    let policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(2);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let admission = state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        )
        .unwrap_or_else(|error| panic!("the required emit is admitted: {error}"));
    assert!(admission.is_pending());
    assert!(!admission.is_delivered());
    let emit = match admission {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    assert!(!emit.is_delivered());
    assert_eq!(state.pending_emits(), 1);
    assert_eq!(state.acknowledged(), 0);

    let settlement = emit
        .acknowledge(&mut state)
        .unwrap_or_else(|error| panic!("acknowledge: {error}"));
    assert!(settlement.clone().is_delivered());
    assert!(!settlement.clone().retry_permitted());
    assert_eq!(settlement.business_outcome(), None);
    assert_eq!(state.pending_emits(), 0);
    assert_eq!(state.acknowledged(), 1);
}

#[test]
fn best_effort_reports_queued_or_dropped_and_never_delivers_on_enqueue() {
    let policy = best_effort_policy(limits_with(|set| {
        set.max_queue = TelemetryLimit::Finite(1);
        set.max_pending_emits = TelemetryLimit::Finite(2);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let admission = state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        )
        .unwrap_or_else(|error| panic!("the best-effort emit is queued: {error}"));
    assert!(admission.is_queued());
    assert!(!admission.is_delivered());
    let first = match admission {
        TelemetryAdmission::Queued(emit) => emit,
        _ => panic!("a best-effort admission is queued"),
    };
    assert_eq!(state.queued(), 1);
    assert_eq!(state.pending_emits(), 1);

    let dropped = match state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(2, "log"),
        )
        .unwrap_or_else(|error| panic!("a full queue drops: {error}"))
    {
        TelemetryAdmission::Dropped(receipt) => receipt,
        _ => panic!("a full best-effort queue drops the newest record"),
    };
    assert_eq!(dropped.sequence(), 2);
    assert_eq!(dropped.dropped_total(), 1);
    assert!(!dropped.is_delivered());
    assert_eq!(state.queued(), 1);
    assert_eq!(state.pending_emits(), 1);
    assert_eq!(state.dropped(), 1);

    let second_drop = match state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(3, "log"),
        )
        .unwrap_or_else(|error| panic!("a full queue drops again: {error}"))
    {
        TelemetryAdmission::Dropped(receipt) => receipt,
        _ => panic!("a full best-effort queue drops the newest record"),
    };
    assert_eq!(second_drop.dropped_total(), 2);

    let settlement = first
        .acknowledge(&mut state)
        .unwrap_or_else(|error| panic!("acknowledge: {error}"));
    assert!(settlement.is_delivered());
    assert_eq!(state.queued(), 0);
    assert_eq!(state.pending_emits(), 0);
    assert_eq!(state.acknowledged(), 1);

    let zero_queue = best_effort_policy(limits_with(|set| {
        set.max_queue = TelemetryLimit::Finite(0);
    }));
    let mut denied = TelemetrySinkState::new(instance("state-a"));
    let dropped = match denied
        .admit(
            Some(&zero_queue),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(4, "log"),
        )
        .unwrap_or_else(|error| panic!("a zero queue drops: {error}"))
    {
        TelemetryAdmission::Dropped(receipt) => receipt,
        _ => panic!("a zero queue admits no queued record"),
    };
    assert_eq!(dropped.dropped_total(), 1);
    assert_eq!(denied.queued(), 0);
}

#[test]
fn protected_values_are_not_labels_or_series_and_need_destination_release() {
    let value = protected_value(ProtectedDataClass::RenderedPrompt);
    let reference = TelemetryProtectedReference::from_value(&value);
    let plain = log_record(1, "log");
    let protected = log_record(1, "log")
        .with_protected(vec![reference.clone()])
        .unwrap_or_else(|error| panic!("valid protected reference: {error}"));
    assert_eq!(
        plain.series_key(),
        protected.series_key(),
        "a protected reference never enters series identity"
    );
    assert!(reference.is_protected());
    assert!(!reference.declassified());
    assert_ne!(
        reference.id().as_str(),
        label("component", "renderer").value()
    );

    let no_release = required_policy(TelemetryLimits::declared());
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let before = state.snapshot();
    let error = refused(
        state.admit(
            Some(&no_release),
            Some(&TelemetryEmitGrant::granted()),
            &protected,
        ),
        "a protected reference without release",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::ReleaseRequired);
    assert_eq!(state.snapshot(), before);

    let release = telemetry_release(&sink("sink-a"), ProtectedDataClass::SourceText);
    let wrong_class = policy(
        sink("sink-a"),
        TelemetryDeliveryClass::Required,
        TelemetryLimits::declared(),
        Some(release),
    );
    let before = state.snapshot();
    let error = refused(
        state.admit(
            Some(&wrong_class),
            Some(&TelemetryEmitGrant::granted()),
            &protected,
        ),
        "an undeclared protected class",
    );
    assert_eq!(
        error.code(),
        TelemetryDiagnosticCode::ReleaseClassNotDeclared
    );
    assert_eq!(state.snapshot(), before);

    let release = telemetry_release(&sink("sink-a"), ProtectedDataClass::RenderedPrompt);
    let admitted_policy = policy(
        sink("sink-a"),
        TelemetryDeliveryClass::Required,
        TelemetryLimits::declared(),
        Some(release),
    );
    let admission = state
        .admit(
            Some(&admitted_policy),
            Some(&TelemetryEmitGrant::granted()),
            &protected,
        )
        .unwrap_or_else(|error| panic!("the released reference is admitted: {error}"));
    assert!(admission.is_pending());
    assert!(!reference.declassified());
    match admitted_policy.release() {
        Some(release) => assert!(!release.declassifies()),
        None => panic!("the declared release is retained by the policy"),
    }

    let projection = ReleaseProjection::new(
        ProjectionKind::Redacted,
        ProtectedDataClass::RenderedPrompt,
        ReleaseDestination::OrdinarySource,
    );
    let error = refused(
        TelemetryDestinationRelease::new(sink("sink-a"))
            .declare(ProtectedDataClass::RenderedPrompt, projection),
        "a release to an ordinary-source destination",
    );
    assert_eq!(
        error.code(),
        TelemetryDiagnosticCode::ReleaseDestinationMismatch
    );
}

#[test]
fn required_backpressure_is_bounded_and_settlements_are_terminal() {
    let policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(1);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let first = match state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        )
        .unwrap_or_else(|error| panic!("the first emit is admitted: {error}"))
    {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    let before = state.snapshot();
    let error = refused(
        state.admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(2, "log"),
        ),
        "a full pending set",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::BackpressureBound);
    assert!(error.detail().contains('7'));
    assert_eq!(state.snapshot(), before);

    let cancelled = first
        .cancel(&mut state)
        .unwrap_or_else(|error| panic!("cancel: {error}"));
    assert_eq!(cancelled.clone().sequence(), 1);
    assert!(!cancelled.clone().is_delivered());
    assert!(!cancelled.clone().retry_permitted());
    assert_eq!(cancelled.business_outcome(), None);
    assert_eq!(state.cancelled(), 1);
    assert_eq!(state.pending_emits(), 0);

    let second = match state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(3, "log"),
        )
        .unwrap_or_else(|error| panic!("the next emit is admitted: {error}"))
    {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    let ambiguous = second
        .ambiguous(&mut state)
        .unwrap_or_else(|error| panic!("ambiguous: {error}"));
    assert_eq!(ambiguous.clone().sequence(), 3);
    assert!(!ambiguous.clone().retry_permitted());
    assert!(!ambiguous.is_delivered());
    assert_eq!(state.ambiguous(), 1);
    assert_eq!(state.pending_emits(), 0);
}

#[test]
fn shutdown_is_bounded_and_reports_drained_and_abandoned_emits() {
    let policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(2);
        set.max_shutdown_drain = TelemetryLimit::Finite(1);
        set.max_shutdown_timeout_us = TelemetryLimit::Finite(5_000);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    for sequence in 1..=2 {
        let admission = state
            .admit(
                Some(&policy),
                Some(&TelemetryEmitGrant::granted()),
                &log_record(sequence, "log"),
            )
            .unwrap_or_else(|error| panic!("the emit is admitted: {error}"));
        assert!(admission.is_pending());
    }
    let plan = state
        .begin_shutdown(Some(&policy))
        .unwrap_or_else(|error| panic!("shutdown begins: {error}"));
    assert_eq!(plan.pending_emits(), 2);
    assert_eq!(plan.drain_bound(), 1);
    assert_eq!(plan.timeout_us(), 5_000);
    assert!(!plan.within_bound());
    let before = state.snapshot();
    let error = refused(
        state.admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(3, "log"),
        ),
        "an admission after shutdown begin",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::SinkShutdown);
    assert_eq!(state.snapshot(), before);
    assert_eq!(
        refused(
            state.retain(Some(&policy), &log_record(3, "log")),
            "retention after shutdown"
        )
        .code(),
        TelemetryDiagnosticCode::SinkShutdown
    );
    let settlement = state
        .settle_shutdown(1)
        .unwrap_or_else(|error| panic!("shutdown settles: {error}"));
    assert_eq!(settlement.drained(), 1);
    assert_eq!(settlement.abandoned(), 1);
    assert!(!settlement.within_bound());
    assert_eq!(state.pending_emits(), 0);
    assert_eq!(state.abandoned(), 1);
    assert_eq!(
        refused(state.settle_shutdown(0), "a second shutdown settlement").code(),
        TelemetryDiagnosticCode::ShutdownAlreadySettled
    );

    let mut never = TelemetrySinkState::new(instance("state-a"));
    assert_eq!(
        refused(never.settle_shutdown(0), "settlement before shutdown").code(),
        TelemetryDiagnosticCode::SinkShutdown
    );

    let mut impossible = TelemetrySinkState::new(instance("state-a"));
    let admission = impossible
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(4, "log"),
        )
        .unwrap_or_else(|error| panic!("the emit is admitted: {error}"));
    assert!(admission.is_pending());
    assert!(impossible.begin_shutdown(Some(&policy)).is_ok());
    let before = impossible.snapshot();
    assert_eq!(
        refused(impossible.settle_shutdown(2), "an impossible drained count").code(),
        TelemetryDiagnosticCode::InvalidSettlement
    );
    assert_eq!(impossible.snapshot(), before);

    let zero_drain = required_policy(limits_with(|set| {
        set.max_shutdown_drain = TelemetryLimit::Finite(0);
        set.max_shutdown_timeout_us = TelemetryLimit::Finite(0);
    }));
    let mut denied = TelemetrySinkState::new(instance("state-a"));
    let admission = denied
        .admit(
            Some(&zero_drain),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(5, "log"),
        )
        .unwrap_or_else(|error| panic!("the emit is admitted: {error}"));
    assert!(admission.is_pending());
    let plan = denied
        .begin_shutdown(Some(&zero_drain))
        .unwrap_or_else(|error| panic!("shutdown begins: {error}"));
    assert_eq!(plan.drain_bound(), 0);
    assert_eq!(plan.timeout_us(), 0);
    assert!(!plan.within_bound());
    let settlement = denied
        .settle_shutdown(0)
        .unwrap_or_else(|error| panic!("shutdown settles: {error}"));
    assert_eq!(settlement.abandoned(), 1);
}

#[test]
fn sink_faults_poison_one_instance_and_redact_the_report() {
    let sink_a = sink("sink-a");
    let mut poisoned = TelemetrySinkState::new(instance("state-a"));
    let fault = TelemetrySinkFault::new(sink_a.clone(), TelemetryFaultClass::Panic);
    let receipt = poisoned
        .poison(fault.clone())
        .unwrap_or_else(|error| panic!("poison: {error}"));
    assert_eq!(receipt.fault(), &fault);
    assert!(!receipt.business_outcome_changed());
    assert_eq!(fault.detail(), "<redacted>");
    assert_eq!(fault.class(), TelemetryFaultClass::Panic);
    assert_eq!(fault.sink().as_str(), "sink-a");
    assert!(!fault.is_telemetry_record());

    let poisoned_policy = policy(
        sink_a,
        TelemetryDeliveryClass::Required,
        TelemetryLimits::declared(),
        None,
    );
    let before = poisoned.snapshot();
    let error = refused(
        poisoned.admit(
            Some(&poisoned_policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        ),
        "a poisoned sink",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::SinkPoisoned);
    assert_eq!(poisoned.snapshot(), before);
    assert_eq!(
        refused(
            poisoned.retain(Some(&poisoned_policy), &log_record(1, "log")),
            "poisoned retention",
        )
        .code(),
        TelemetryDiagnosticCode::SinkPoisoned
    );

    let mut healthy = TelemetrySinkState::new(instance("state-b"));
    let healthy_sink = sink("sink-b");
    let healthy_policy = policy(
        healthy_sink,
        TelemetryDeliveryClass::Required,
        TelemetryLimits::declared(),
        None,
    );
    let admission = healthy
        .admit(
            Some(&healthy_policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(2, "log"),
        )
        .unwrap_or_else(|error| panic!("another sink is unaffected: {error}"));
    assert!(admission.is_pending());
    assert!(healthy.poisoned().is_none());
}

#[test]
fn telemetry_is_never_section_12_semantic_evidence() {
    assert!(!telemetry_is_semantic_evidence());
    let record = log_record(1, "log");
    assert!(!record.is_section_12_evidence());
    let policy = required_policy(TelemetryLimits::declared());
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let emit = match state
        .admit(Some(&policy), Some(&TelemetryEmitGrant::granted()), &record)
        .unwrap_or_else(|error| panic!("the emit is admitted: {error}"))
    {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    let settlement: TelemetrySettlement = emit
        .acknowledge(&mut state)
        .unwrap_or_else(|error| panic!("acknowledge: {error}"));
    assert_eq!(settlement.business_outcome(), None);
    assert!(
        specification().contains("Telemetry is never Section 12 semantic evidence"),
        "the specification keeps telemetry outside Section 12 evidence"
    );
}

#[test]
fn zero_dimensions_deny_their_dimension_without_mutation() {
    let record = log_record(1, "log");
    let mut state = TelemetrySinkState::new(instance("state-a"));
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_record_bytes = TelemetryLimit::Finite(0);
        })),
        &record,
        TelemetryDiagnosticCode::RecordBound,
    );
    assert_atomic_refusal(
        &mut state,
        &required_policy(limits_with(|set| {
            set.max_pending_emits = TelemetryLimit::Finite(0)
        })),
        &record,
        TelemetryDiagnosticCode::BackpressureBound,
    );
    let retention = required_policy(limits_with(|set| {
        set.max_retention = TelemetryLimit::Finite(0);
    }));
    let before = state.snapshot();
    assert_eq!(
        refused(state.retain(Some(&retention), &record), "zero retention").code(),
        TelemetryDiagnosticCode::RetentionBound
    );
    assert_eq!(state.snapshot(), before);
}

#[test]
fn release_projection_must_match_its_declared_class() {
    let projection = ReleaseProjection::new(
        ProjectionKind::Redacted,
        ProtectedDataClass::SourceText,
        ReleaseDestination::NullTelemetry,
    );
    let error = refused(
        TelemetryDestinationRelease::new(sink("sink-a"))
            .declare(ProtectedDataClass::RenderedPrompt, projection),
        "a projection naming another protected class",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::ReleaseClassMismatch);
}

#[test]
fn settlements_are_bound_to_the_issuing_state_authority() {
    let policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(4);
    }));
    let mut first = TelemetrySinkState::new(instance("same"));
    let mut second = TelemetrySinkState::new(instance("same"));
    let _second_emit = match second
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(9, "log"),
        )
        .unwrap_or_else(|error| panic!("the foreign emit is admitted: {error}"))
    {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    let mut emit = match first
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        )
        .unwrap_or_else(|error| panic!("the emit is admitted: {error}"))
    {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    let before_second = second.snapshot();

    let rejected = match emit.acknowledge(&mut second) {
        Ok(_) => panic!("a foreign state must refuse acknowledgement"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::InvalidSettlement
    );
    assert_eq!(second.snapshot(), before_second);
    emit = rejected.into_emit();

    let rejected = match emit.cancel(&mut second) {
        Ok(_) => panic!("a foreign state must refuse cancellation"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::InvalidSettlement
    );
    assert_eq!(second.snapshot(), before_second);
    emit = rejected.into_emit();

    let rejected = match emit.ambiguous(&mut second) {
        Ok(_) => panic!("a foreign state must refuse an ambiguous settlement"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::InvalidSettlement
    );
    assert_eq!(second.snapshot(), before_second);
    emit = rejected.into_emit();

    let rejected = match emit.failed(&mut second) {
        Ok(_) => panic!("a foreign state must refuse a failed settlement"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::InvalidSettlement
    );
    assert_eq!(second.snapshot(), before_second);
    emit = rejected.into_emit();

    let mut recreated = TelemetrySinkState::new(instance("same"));
    let before_recreated = recreated.snapshot();
    let rejected = match emit.acknowledge(&mut recreated) {
        Ok(_) => panic!("a recreated state must not accept a stale emit"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::InvalidSettlement
    );
    assert_eq!(recreated.snapshot(), before_recreated);
    let emit = rejected.into_emit();

    let settlement = emit
        .acknowledge(&mut first)
        .unwrap_or_else(|error| panic!("the issuing instance accepts the emit: {error}"));
    assert!(settlement.is_delivered());
    assert_eq!(first.acknowledged(), 1);
    assert_eq!(second.acknowledged(), 0);
    assert_eq!(second.pending_emits(), 1);
    assert_eq!(recreated.acknowledged(), 0);
}

#[test]
fn aggregate_shutdown_retires_live_emits() {
    let policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(1);
        set.max_shutdown_drain = TelemetryLimit::Finite(1);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let emit = match state
        .admit(
            Some(&policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        )
        .unwrap_or_else(|error| panic!("the emit is admitted: {error}"))
    {
        TelemetryAdmission::Pending(emit) => emit,
        _ => panic!("a required admission is pending"),
    };
    assert!(state.begin_shutdown(Some(&policy)).is_ok());
    let settlement = state
        .settle_shutdown(0)
        .unwrap_or_else(|error| panic!("shutdown settles: {error}"));
    assert_eq!(settlement.abandoned(), 1);
    let before = state.snapshot();
    let rejected = match emit.acknowledge(&mut state) {
        Ok(_) => panic!("a retired emit must not settle after shutdown"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::ShutdownAlreadySettled
    );
    assert_eq!(state.snapshot(), before);
}

#[test]
fn sink_state_refuses_policy_replacement_and_foreign_faults() {
    let first_policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(1);
    }));
    let replacement = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(2);
    }));
    let mut state = TelemetrySinkState::new(instance("state-a"));
    let admission = state
        .admit(
            Some(&first_policy),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(1, "log"),
        )
        .unwrap_or_else(|error| panic!("the first policy binds: {error}"));
    assert!(admission.is_pending());
    let before = state.snapshot();
    let error = refused(
        state.admit(
            Some(&replacement),
            Some(&TelemetryEmitGrant::granted()),
            &log_record(2, "log"),
        ),
        "a replacement policy",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::PolicyMismatch);
    assert_eq!(state.snapshot(), before);

    let fault = TelemetrySinkFault::new(sink("sink-b"), TelemetryFaultClass::Panic);
    let before = state.snapshot();
    let error = refused(state.poison(fault), "a foreign fault");
    assert_eq!(error.code(), TelemetryDiagnosticCode::SinkMismatch);
    assert_eq!(state.snapshot(), before);
}

#[test]
fn shutdown_drain_budget_is_enforced_for_aggregate_and_live_settlements() {
    let policy = required_policy(limits_with(|set| {
        set.max_pending_emits = TelemetryLimit::Finite(2);
        set.max_shutdown_drain = TelemetryLimit::Finite(1);
    }));
    let mut aggregate = TelemetrySinkState::new(instance("state-a"));
    for sequence in 1..=2 {
        let admission = aggregate
            .admit(
                Some(&policy),
                Some(&TelemetryEmitGrant::granted()),
                &log_record(sequence, "log"),
            )
            .unwrap_or_else(|error| panic!("the emit is admitted: {error}"));
        assert!(admission.is_pending());
    }
    assert!(aggregate.begin_shutdown(Some(&policy)).is_ok());
    let before = aggregate.snapshot();
    let error = refused(
        aggregate.settle_shutdown(2),
        "an over-budget aggregate drain",
    );
    assert_eq!(error.code(), TelemetryDiagnosticCode::InvalidSettlement);
    assert_eq!(aggregate.snapshot(), before);
    let settlement = aggregate
        .settle_shutdown(1)
        .unwrap_or_else(|error| panic!("the bounded drain settles: {error}"));
    assert_eq!(settlement.drained(), 1);
    assert_eq!(settlement.abandoned(), 1);

    let mut live = TelemetrySinkState::new(instance("state-a"));
    let mut emits = Vec::new();
    for sequence in 1..=2 {
        let admission = live
            .admit(
                Some(&policy),
                Some(&TelemetryEmitGrant::granted()),
                &log_record(sequence, "log"),
            )
            .unwrap_or_else(|error| panic!("the emit is admitted: {error}"));
        emits.push(match admission {
            TelemetryAdmission::Pending(emit) => emit,
            _ => panic!("a required admission is pending"),
        });
    }
    assert!(live.begin_shutdown(Some(&policy)).is_ok());
    let first = emits.remove(0);
    let second = emits.remove(0);
    assert!(
        first
            .acknowledge(&mut live)
            .unwrap_or_else(|error| panic!("the first drain settles: {error}"))
            .is_delivered()
    );
    let before = live.snapshot();
    let rejected = match second.acknowledge(&mut live) {
        Ok(_) => panic!("the drain budget must refuse a second settlement"),
        Err(rejected) => rejected,
    };
    assert_eq!(
        rejected.error().code(),
        TelemetryDiagnosticCode::BackpressureBound
    );
    assert_eq!(live.snapshot(), before);
    assert_eq!(live.shutdown_drained(), 1);
    let settlement = live
        .settle_shutdown(0)
        .unwrap_or_else(|error| panic!("shutdown settles: {error}"));
    assert_eq!(settlement.drained(), 1);
    assert_eq!(settlement.abandoned(), 1);
}

#[test]
fn unicode_control_characters_are_refused() {
    for control in ["\u{0085}", "\u{009b}"] {
        assert_eq!(
            TelemetryRecord::log(1, name("log"), control)
                .err()
                .map(|error| error.code()),
            Some(TelemetryDiagnosticCode::InvalidRecord)
        );
        assert_eq!(
            TelemetryField::new(name("field"), control)
                .err()
                .map(|error| error.code()),
            Some(TelemetryDiagnosticCode::InvalidRecord)
        );
        assert_eq!(
            TelemetryLabel::new(name("label"), control)
                .err()
                .map(|error| error.code()),
            Some(TelemetryDiagnosticCode::InvalidRecord)
        );
        assert_eq!(
            TelemetryContextEntry::new(name("context"), control)
                .err()
                .map(|error| error.code()),
            Some(TelemetryDiagnosticCode::InvalidRecord)
        );
    }
}
