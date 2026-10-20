//! Declared bounded telemetry policy and admission model for `SPEC.md` Section 48.
//!
//! This module publishes the pure decision model behind `GNT-48.2` through `GNT-48.9`: typed
//! log, metric, and trace records; explicit context; immutable per-sink finite limits; atomic
//! admission; protected references and destination-specific release; required acknowledgement
//! versus best-effort queued or dropped outcomes; bounded backpressure; cancellation; shutdown
//! accounting; and sink-fault containment.
//!
//! It is deliberately not a telemetry sink, adapter, queue, background task, host trait, or
//! runtime availability claim. It performs no I/O, reads no clock, process, environment, task, or
//! thread state, and holds no payload byte. Every decision is a deterministic function of explicit
//! records, policies, grants, releases, and admission state. There is no ambient or global context:
//! a context is an explicit ordered declaration supplied with the record.
//!
//! Telemetry is never Section 12 semantic evidence. A [`TelemetryRecord`] is not an event, cannot
//! be converted into one, and every settlement here carries no business or task outcome. Delivery
//! failure and acknowledgement are separate from fixed outcomes, and an ambiguous emit is never
//! silently retried.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::protected::{
    ProtectedDataClass, ProtectedValue, ProtectedValueId, ReleaseDestination, ReleaseProjection,
};

/// The Section 48 clauses implemented by this pure model, in declaration order.
pub const TELEMETRY_CLAUSES: [&str; 10] = [
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
];

/// The largest accepted telemetry name, in bytes.
///
/// A name is ordinary declared metadata rather than payload. The fixed cap lets a record or sink
/// identity be refused before any per-sink limit is consulted, while the per-sink field, label, and
/// context limits remain the only bounds on record content.
pub const TELEMETRY_NAME_LIMIT: usize = 96;

/// One declared telemetry record kind of
/// `GNT-48.2-telemetry-record-kinds-and-explicit-context`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryRecordKind {
    /// One log record with a declared message.
    Log,
    /// One metric record with a declared numeric value and optional unit.
    Metric,
    /// One trace record with a declared duration and status.
    Trace,
}

impl TelemetryRecordKind {
    /// Every declared kind, in canonical order.
    pub const ALL: [Self; 3] = [Self::Log, Self::Metric, Self::Trace];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Metric => "metric",
            Self::Trace => "trace",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }

    /// Returns the declared `std.observe` module that owns this record kind.
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Log => "std.observe::log",
            Self::Metric => "std.observe::metric",
            Self::Trace => "std.observe::trace",
        }
    }
}

/// One validated ordinary telemetry name.
///
/// Names are nonempty ASCII without whitespace or a control character and within
/// [`TELEMETRY_NAME_LIMIT`]. A name is declared metadata, never a protected value and never a
/// payload encoding.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TelemetryName(String);

impl TelemetryName {
    /// Admits one ordinary name.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidIdentity`] for an empty, non-ASCII, whitespace,
    /// control, or over-limit name.
    pub fn new(value: impl Into<String>) -> Result<Self, TelemetryError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidIdentity,
                "a telemetry name is empty",
            ));
        }
        if value.len() > TELEMETRY_NAME_LIMIT {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidIdentity,
                "a telemetry name exceeds its fixed byte limit",
            ));
        }
        if !value.is_ascii() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidIdentity,
                "a telemetry name is not ASCII",
            ));
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidIdentity,
                "a telemetry name contains whitespace or a control character",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the exact declared name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the declared name length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the name is empty, which is never true for an admitted name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One validated ordinary sink identity.
///
/// A sink identity names one declared sink and is never derived from a protected value, a label,
/// or a payload. Two records delivered to different sink identities are distinct obligations even
/// when every other input is equal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TelemetrySinkId(TelemetryName);

impl TelemetrySinkId {
    /// Admits one ordinary sink identity.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidIdentity`] under the same name rules as
    /// [`TelemetryName::new`].
    pub fn new(value: impl Into<String>) -> Result<Self, TelemetryError> {
        Ok(Self(TelemetryName::new(value)?))
    }

    /// Returns the exact declared identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One declared sink instance identity.
///
/// A sink identity names a declared sink; a sink instance identity names one admission/accounting
/// state of that sink. Two states with the same declared sink identity are still distinct
/// instances, and an emit remains bound to the instance that issued it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TelemetrySinkInstanceId(TelemetryName);

impl TelemetrySinkInstanceId {
    /// Admits one ordinary sink instance identity.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidIdentity`] under the same name rules as
    /// [`TelemetryName::new`].
    pub fn new(value: impl Into<String>) -> Result<Self, TelemetryError> {
        Ok(Self(TelemetryName::new(value)?))
    }

    /// Returns the exact declared instance identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One unforgeable issuing-state authority.
///
/// The token has no public constructor and no public accessor for its inner allocation. A state
/// creates exactly one authority; an emit receives a shared reference to it. Equality is pointer
/// equality, so two independently constructed states never share authority even when they declare
/// the same ordinary instance name. The state type is not `Clone`, so a live accounting state
/// cannot be duplicated with the same authority.
#[derive(Clone, Debug)]
struct SinkAuthority(Arc<()>);

impl SinkAuthority {
    fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for SinkAuthority {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SinkAuthority {}

/// One declared ordinary field of a telemetry record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelemetryField {
    name: TelemetryName,
    value: String,
}

impl TelemetryField {
    /// Declares one field name and ordinary text value.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] when the value contains a control
    /// character or is empty.
    pub fn new(name: TelemetryName, value: impl Into<String>) -> Result<Self, TelemetryError> {
        let value = value.into();
        validate_ordinary_text(&value, "a telemetry field value")?;
        Ok(Self { name, value })
    }

    /// Returns the declared field name.
    #[must_use]
    pub const fn name(&self) -> &TelemetryName {
        &self.name
    }

    /// Returns the declared ordinary value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the declared field material length in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64
    }
}

/// One declared ordinary label of a telemetry record.
///
/// Labels participate in series identity. A protected value can never be supplied as a label name
/// or value because no conversion from a protected reference exists.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelemetryLabel {
    name: TelemetryName,
    value: String,
}

impl TelemetryLabel {
    /// Declares one label name and ordinary text value.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] when the value contains a control
    /// character or is empty.
    pub fn new(name: TelemetryName, value: impl Into<String>) -> Result<Self, TelemetryError> {
        let value = value.into();
        validate_ordinary_text(&value, "a telemetry label value")?;
        Ok(Self { name, value })
    }

    /// Returns the declared label name.
    #[must_use]
    pub const fn name(&self) -> &TelemetryName {
        &self.name
    }

    /// Returns the declared ordinary value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the declared label material length in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64
    }
}

/// One explicit context entry of a telemetry record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelemetryContextEntry {
    name: TelemetryName,
    value: String,
}

impl TelemetryContextEntry {
    /// Declares one explicit context name and ordinary text value.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] when the value contains a control
    /// character or is empty.
    pub fn new(name: TelemetryName, value: impl Into<String>) -> Result<Self, TelemetryError> {
        let value = value.into();
        validate_ordinary_text(&value, "a telemetry context value")?;
        Ok(Self { name, value })
    }

    /// Returns the declared context name.
    #[must_use]
    pub const fn name(&self) -> &TelemetryName {
        &self.name
    }

    /// Returns the declared ordinary value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the declared context material length in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64
    }
}

/// One explicit ordered telemetry context.
///
/// The entries are the complete declaration. No ambient, task, thread, process, environment, or
/// global context is consulted, inherited, or implied, and an empty context is the declared root.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TelemetryContext {
    entries: Vec<TelemetryContextEntry>,
}

impl TelemetryContext {
    /// Declares the empty root context.
    #[must_use]
    pub fn root() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Declares one explicit context from its complete entry list.
    #[must_use]
    pub fn new(entries: Vec<TelemetryContextEntry>) -> Self {
        Self { entries }
    }

    /// Returns the declared entries in declaration order.
    #[must_use]
    pub fn entries(&self) -> &[TelemetryContextEntry] {
        &self.entries
    }

    /// Returns the declared context depth.
    #[must_use]
    pub fn depth(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Returns the declared context material length in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.entries.iter().map(TelemetryContextEntry::bytes).sum()
    }
}

/// One declared metric value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryMetricValue {
    /// One signed integer value.
    Integer(i64),
    /// One unsigned integer value.
    Unsigned(u64),
}

/// One declared trace status.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryTraceStatus {
    /// The trace completed without an error.
    Ok,
    /// The trace completed with an error.
    Error,
    /// The trace status was not declared.
    Unset,
}

impl TelemetryTraceStatus {
    /// Every declared status, in canonical order.
    pub const ALL: [Self; 3] = [Self::Ok, Self::Error, Self::Unset];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Unset => "unset",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.wire_name() == value)
    }
}

/// One declared record body, selected by the record kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetryRecordBody {
    /// The body of one log record.
    Log {
        /// The declared ordinary message.
        message: String,
    },
    /// The body of one metric record.
    Metric {
        /// The declared numeric value.
        value: TelemetryMetricValue,
        /// The declared optional unit.
        unit: Option<TelemetryName>,
    },
    /// The body of one trace record.
    Trace {
        /// The declared duration in nanoseconds.
        duration_ns: u64,
        /// The declared status.
        status: TelemetryTraceStatus,
    },
}

/// One declared protection-bearing reference carried by a telemetry record.
///
/// The reference is the canonical protected-value identity and its declared class, never payload
/// bytes, a payload encoding, or a payload-derived digest. The reference stays protected after a
/// telemetry-destination release: no method declassifies it and no conversion to ordinary text
/// exists.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelemetryProtectedReference {
    id: ProtectedValueId,
    class: ProtectedDataClass,
}

impl TelemetryProtectedReference {
    /// Declares one reference from a protected value's canonical identity and class.
    #[must_use]
    pub fn from_value(value: &ProtectedValue) -> Self {
        Self {
            id: value.id().clone(),
            class: value.class(),
        }
    }

    /// Returns the canonical protected-value identity.
    #[must_use]
    pub const fn id(&self) -> &ProtectedValueId {
        &self.id
    }

    /// Returns the declared protected data class.
    #[must_use]
    pub const fn class(&self) -> ProtectedDataClass {
        self.class
    }

    /// Returns whether this reference remains protected, which is always true.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        true
    }

    /// Returns whether a telemetry-destination release declassified this reference, which is never
    /// true.
    #[must_use]
    pub const fn declassified(&self) -> bool {
        false
    }
}

/// One declared telemetry-destination release for one sink.
///
/// The release names the exact sink and carries the Section 15.10 projection accepted for each
/// declared class. It is a declaration record, not an authority instance and not a telemetry emit
/// grant. A release to the null telemetry destination never declassifies the value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryDestinationRelease {
    sink: TelemetrySinkId,
    projections: BTreeMap<ProtectedDataClass, ReleaseProjection>,
}

impl TelemetryDestinationRelease {
    /// Declares one release for the exact sink, initially covering no class.
    #[must_use]
    pub fn new(sink: TelemetrySinkId) -> Self {
        Self {
            sink,
            projections: BTreeMap::new(),
        }
    }

    /// Declares one Section 15.10 projection for one protected class.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::ReleaseDestinationMismatch`] when the projection does
    /// not name the null telemetry destination, and
    /// [`TelemetryDiagnosticCode::InvalidRecord`] when the class is already declared.
    pub fn declare(
        mut self,
        class: ProtectedDataClass,
        projection: ReleaseProjection,
    ) -> Result<Self, TelemetryError> {
        if projection.destination() != ReleaseDestination::NullTelemetry {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::ReleaseDestinationMismatch,
                "a telemetry release must name the null telemetry destination",
            ));
        }
        if projection.class() != class {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::ReleaseClassMismatch,
                "a telemetry projection must name the class it is declared for",
            ));
        }
        if self.projections.insert(class, projection).is_some() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidRecord,
                "a protected class is declared twice for one telemetry release",
            ));
        }
        Ok(self)
    }

    /// Returns the exact sink identity this release names.
    #[must_use]
    pub const fn sink(&self) -> &TelemetrySinkId {
        &self.sink
    }

    /// Returns whether the release authorizes one class for one exact sink.
    #[must_use]
    pub fn authorizes(&self, sink: &TelemetrySinkId, class: ProtectedDataClass) -> bool {
        self.sink == *sink && self.projections.contains_key(&class)
    }

    /// Returns whether this release declassifies protected data, which is never true.
    #[must_use]
    pub const fn declassifies(&self) -> bool {
        false
    }
}

/// One dimension of the immutable per-sink finite limit set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryLimitDimension {
    /// Maximum declared record material bytes.
    RecordBytes,
    /// Maximum declared field count.
    Fields,
    /// Maximum declared field material bytes.
    FieldBytes,
    /// Maximum declared label count.
    Labels,
    /// Maximum declared label material bytes.
    LabelBytes,
    /// Maximum declared context depth.
    ContextDepth,
    /// Maximum declared context material bytes.
    ContextBytes,
    /// Maximum admitted active series.
    Series,
    /// Maximum admitted best-effort queue depth.
    Queue,
    /// Maximum admitted retained records.
    Retention,
    /// Maximum admitted pending emits.
    PendingEmits,
    /// Maximum declared shutdown drain bound.
    ShutdownDrain,
    /// Maximum declared shutdown timeout in microseconds.
    ShutdownTimeout,
}

impl TelemetryLimitDimension {
    /// Every declared dimension, in canonical order.
    pub const ALL: [Self; 13] = [
        Self::RecordBytes,
        Self::Fields,
        Self::FieldBytes,
        Self::Labels,
        Self::LabelBytes,
        Self::ContextDepth,
        Self::ContextBytes,
        Self::Series,
        Self::Queue,
        Self::Retention,
        Self::PendingEmits,
        Self::ShutdownDrain,
        Self::ShutdownTimeout,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::RecordBytes => "record-bytes",
            Self::Fields => "fields",
            Self::FieldBytes => "field-bytes",
            Self::Labels => "labels",
            Self::LabelBytes => "label-bytes",
            Self::ContextDepth => "context-depth",
            Self::ContextBytes => "context-bytes",
            Self::Series => "series",
            Self::Queue => "queue",
            Self::Retention => "retention",
            Self::PendingEmits => "pending-emits",
            Self::ShutdownDrain => "shutdown-drain",
            Self::ShutdownTimeout => "shutdown-timeout",
        }
    }

    /// Returns the canonical index of this dimension.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::RecordBytes => 0,
            Self::Fields => 1,
            Self::FieldBytes => 2,
            Self::Labels => 3,
            Self::LabelBytes => 4,
            Self::ContextDepth => 5,
            Self::ContextBytes => 6,
            Self::Series => 7,
            Self::Queue => 8,
            Self::Retention => 9,
            Self::PendingEmits => 10,
            Self::ShutdownDrain => 11,
            Self::ShutdownTimeout => 12,
        }
    }
}

/// One declared limit value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryLimit {
    /// One finite bound; zero is a finite denial of the dimension.
    Finite(u64),
    /// An unbounded declaration, which is always refused.
    Unlimited,
}

impl TelemetryLimit {
    /// Returns one finite bound.
    #[must_use]
    pub const fn finite(value: u64) -> Self {
        Self::Finite(value)
    }

    /// Returns the unbounded declaration, which no policy accepts.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::Unlimited
    }
}

/// One complete declared limit set before validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryLimitSet {
    /// Maximum declared record material bytes.
    pub max_record_bytes: TelemetryLimit,
    /// Maximum declared field count.
    pub max_fields: TelemetryLimit,
    /// Maximum declared field material bytes.
    pub max_field_bytes: TelemetryLimit,
    /// Maximum declared label count.
    pub max_labels: TelemetryLimit,
    /// Maximum declared label material bytes.
    pub max_label_bytes: TelemetryLimit,
    /// Maximum declared context depth.
    pub max_context_depth: TelemetryLimit,
    /// Maximum declared context material bytes.
    pub max_context_bytes: TelemetryLimit,
    /// Maximum admitted active series.
    pub max_series: TelemetryLimit,
    /// Maximum admitted best-effort queue depth.
    pub max_queue: TelemetryLimit,
    /// Maximum admitted retained records.
    pub max_retention: TelemetryLimit,
    /// Maximum admitted pending emits.
    pub max_pending_emits: TelemetryLimit,
    /// Maximum declared shutdown drain bound.
    pub max_shutdown_drain: TelemetryLimit,
    /// Maximum declared shutdown timeout in microseconds.
    pub max_shutdown_timeout_us: TelemetryLimit,
}

impl TelemetryLimitSet {
    /// Returns the declared finite default set. Every dimension is nonzero except that callers may
    /// declare any finite value, including zero, when they mean to deny that dimension.
    #[must_use]
    pub const fn declared() -> Self {
        Self {
            max_record_bytes: TelemetryLimit::Finite(65_536),
            max_fields: TelemetryLimit::Finite(32),
            max_field_bytes: TelemetryLimit::Finite(1_024),
            max_labels: TelemetryLimit::Finite(16),
            max_label_bytes: TelemetryLimit::Finite(256),
            max_context_depth: TelemetryLimit::Finite(8),
            max_context_bytes: TelemetryLimit::Finite(1_024),
            max_series: TelemetryLimit::Finite(256),
            max_queue: TelemetryLimit::Finite(64),
            max_retention: TelemetryLimit::Finite(256),
            max_pending_emits: TelemetryLimit::Finite(64),
            max_shutdown_drain: TelemetryLimit::Finite(64),
            max_shutdown_timeout_us: TelemetryLimit::Finite(5_000_000),
        }
    }
}

/// One validated immutable finite per-sink limit set.
///
/// Every dimension is present and finite. A zero value is a declared denial of that dimension, not
/// an unbounded or default value. There is no setter and no fallback: later admission uses exactly
/// these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryLimits {
    values: [u64; 13],
}

impl TelemetryLimits {
    /// Validates one complete declared limit set.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::UnlimitedPolicy`] when any dimension is declared
    /// unlimited. A missing dimension is not representable by [`TelemetryLimitSet`].
    pub fn new(set: TelemetryLimitSet) -> Result<Self, TelemetryError> {
        let declared = [
            set.max_record_bytes,
            set.max_fields,
            set.max_field_bytes,
            set.max_labels,
            set.max_label_bytes,
            set.max_context_depth,
            set.max_context_bytes,
            set.max_series,
            set.max_queue,
            set.max_retention,
            set.max_pending_emits,
            set.max_shutdown_drain,
            set.max_shutdown_timeout_us,
        ];
        let mut values = [0_u64; 13];
        for (index, declared) in declared.into_iter().enumerate() {
            match declared {
                TelemetryLimit::Finite(value) => values[index] = value,
                TelemetryLimit::Unlimited => {
                    return Err(TelemetryError::new(
                        TelemetryDiagnosticCode::UnlimitedPolicy,
                        format!(
                            "the telemetry limit {} is declared unlimited",
                            TelemetryLimitDimension::ALL[index].wire_name()
                        ),
                    ));
                }
            }
        }
        Ok(Self { values })
    }

    /// Returns the declared finite default limits.
    #[must_use]
    pub const fn declared() -> Self {
        Self {
            values: [
                65_536, 32, 1_024, 16, 256, 8, 1_024, 256, 64, 256, 64, 64, 5_000_000,
            ],
        }
    }

    /// Returns one dimension's exact finite value.
    #[must_use]
    pub fn get(self, dimension: TelemetryLimitDimension) -> u64 {
        self.values[dimension.index()]
    }

    /// Returns the maximum declared record material bytes.
    #[must_use]
    pub fn max_record_bytes(self) -> u64 {
        self.get(TelemetryLimitDimension::RecordBytes)
    }

    /// Returns the maximum declared field count.
    #[must_use]
    pub fn max_fields(self) -> u64 {
        self.get(TelemetryLimitDimension::Fields)
    }

    /// Returns the maximum declared field material bytes.
    #[must_use]
    pub fn max_field_bytes(self) -> u64 {
        self.get(TelemetryLimitDimension::FieldBytes)
    }

    /// Returns the maximum declared label count.
    #[must_use]
    pub fn max_labels(self) -> u64 {
        self.get(TelemetryLimitDimension::Labels)
    }

    /// Returns the maximum declared label material bytes.
    #[must_use]
    pub fn max_label_bytes(self) -> u64 {
        self.get(TelemetryLimitDimension::LabelBytes)
    }

    /// Returns the maximum declared context depth.
    #[must_use]
    pub fn max_context_depth(self) -> u64 {
        self.get(TelemetryLimitDimension::ContextDepth)
    }

    /// Returns the maximum declared context material bytes.
    #[must_use]
    pub fn max_context_bytes(self) -> u64 {
        self.get(TelemetryLimitDimension::ContextBytes)
    }

    /// Returns the maximum admitted active series.
    #[must_use]
    pub fn max_series(self) -> u64 {
        self.get(TelemetryLimitDimension::Series)
    }

    /// Returns the maximum admitted best-effort queue depth.
    #[must_use]
    pub fn max_queue(self) -> u64 {
        self.get(TelemetryLimitDimension::Queue)
    }

    /// Returns the maximum admitted retained records.
    #[must_use]
    pub fn max_retention(self) -> u64 {
        self.get(TelemetryLimitDimension::Retention)
    }

    /// Returns the maximum admitted pending emits.
    #[must_use]
    pub fn max_pending_emits(self) -> u64 {
        self.get(TelemetryLimitDimension::PendingEmits)
    }

    /// Returns the maximum declared shutdown drain bound.
    #[must_use]
    pub fn max_shutdown_drain(self) -> u64 {
        self.get(TelemetryLimitDimension::ShutdownDrain)
    }

    /// Returns the maximum declared shutdown timeout in microseconds.
    #[must_use]
    pub fn max_shutdown_timeout_us(self) -> u64 {
        self.get(TelemetryLimitDimension::ShutdownTimeout)
    }
}

/// One declared delivery class of a telemetry sink.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryDeliveryClass {
    /// Delivery completes only at one declared sink acknowledgement.
    Required,
    /// Delivery is best-effort and reports queued or dropped at admission.
    BestEffort,
}

impl TelemetryDeliveryClass {
    /// Every declared class, in canonical order.
    pub const ALL: [Self; 2] = [Self::Required, Self::BestEffort];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::BestEffort => "best-effort",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|class| class.wire_name() == value)
    }
}

/// One immutable declared telemetry sink policy.
///
/// The policy binds one ordinary sink identity, one delivery class, one finite limit set, one
/// optional destination release, and one finite positive required-backpressure wait bound. It has
/// no setters, no configuration fallback, and no implicit default; absent policy is refused at
/// admission rather than supplied from ambient state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetrySinkPolicy {
    sink: TelemetrySinkId,
    delivery: TelemetryDeliveryClass,
    limits: TelemetryLimits,
    release: Option<TelemetryDestinationRelease>,
    wait_bound_us: u64,
}

impl TelemetrySinkPolicy {
    /// Declares one immutable per-sink policy.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::BackpressureBound`] when the wait bound is zero, and
    /// [`TelemetryDiagnosticCode::ReleaseDestinationMismatch`] when a release names another sink.
    pub fn new(
        sink: TelemetrySinkId,
        delivery: TelemetryDeliveryClass,
        limits: TelemetryLimits,
        release: Option<TelemetryDestinationRelease>,
        wait_bound_us: u64,
    ) -> Result<Self, TelemetryError> {
        if wait_bound_us == 0 {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::BackpressureBound,
                "a required telemetry wait bound must be finite and positive",
            ));
        }
        if let Some(release) = &release
            && release.sink() != &sink
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::ReleaseDestinationMismatch,
                "a telemetry release names another sink",
            ));
        }
        Ok(Self {
            sink,
            delivery,
            limits,
            release,
            wait_bound_us,
        })
    }

    /// Returns the exact declared sink identity.
    #[must_use]
    pub const fn sink(&self) -> &TelemetrySinkId {
        &self.sink
    }

    /// Returns the declared delivery class.
    #[must_use]
    pub const fn delivery(&self) -> TelemetryDeliveryClass {
        self.delivery
    }

    /// Returns the immutable finite limit set.
    #[must_use]
    pub const fn limits(&self) -> TelemetryLimits {
        self.limits
    }

    /// Returns the declared destination release, when any.
    #[must_use]
    pub const fn release(&self) -> Option<&TelemetryDestinationRelease> {
        self.release.as_ref()
    }

    /// Returns the finite positive required-backpressure wait bound in microseconds.
    #[must_use]
    pub const fn wait_bound_us(&self) -> u64 {
        self.wait_bound_us
    }
}

/// One explicit telemetry emit grant.
///
/// The grant admits attempting an emit and nothing else. It is not a release grant, never
/// satisfies a protected destination release, and never declassifies a protected value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryEmitGrant {
    allowed: bool,
}

impl TelemetryEmitGrant {
    /// Returns the granted emit permission.
    #[must_use]
    pub const fn granted() -> Self {
        Self { allowed: true }
    }

    /// Returns the withheld emit permission.
    #[must_use]
    pub const fn withheld() -> Self {
        Self { allowed: false }
    }

    /// Returns whether the grant admits an emit attempt.
    #[must_use]
    pub const fn allows_emit(self) -> bool {
        self.allowed
    }

    /// Returns whether the grant declassifies protected data, which is never true.
    #[must_use]
    pub const fn declassifies(self) -> bool {
        false
    }
}

/// One typed telemetry record of `GNT-48.2`.
///
/// The record has one declared kind and matching body, ordinary fields and labels, one explicit
/// context, and zero or more protected references. It carries no payload byte and is never an
/// event or semantic evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryRecord {
    sequence: u64,
    kind: TelemetryRecordKind,
    name: TelemetryName,
    body: TelemetryRecordBody,
    fields: Vec<TelemetryField>,
    labels: Vec<TelemetryLabel>,
    context: TelemetryContext,
    protected: Vec<TelemetryProtectedReference>,
}

impl TelemetryRecord {
    /// Declares one log record.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] when the message is empty or contains a
    /// control character.
    pub fn log(
        sequence: u64,
        name: TelemetryName,
        message: impl Into<String>,
    ) -> Result<Self, TelemetryError> {
        let message = message.into();
        validate_ordinary_text(&message, "a log message")?;
        Ok(Self::new(
            sequence,
            TelemetryRecordKind::Log,
            name,
            TelemetryRecordBody::Log { message },
        ))
    }

    /// Declares one metric record.
    #[must_use]
    pub fn metric(
        sequence: u64,
        name: TelemetryName,
        value: TelemetryMetricValue,
        unit: Option<TelemetryName>,
    ) -> Self {
        Self::new(
            sequence,
            TelemetryRecordKind::Metric,
            name,
            TelemetryRecordBody::Metric { value, unit },
        )
    }

    /// Declares one trace record.
    #[must_use]
    pub fn trace(
        sequence: u64,
        name: TelemetryName,
        duration_ns: u64,
        status: TelemetryTraceStatus,
    ) -> Self {
        Self::new(
            sequence,
            TelemetryRecordKind::Trace,
            name,
            TelemetryRecordBody::Trace {
                duration_ns,
                status,
            },
        )
    }

    fn new(
        sequence: u64,
        kind: TelemetryRecordKind,
        name: TelemetryName,
        body: TelemetryRecordBody,
    ) -> Self {
        Self {
            sequence,
            kind,
            name,
            body,
            fields: Vec::new(),
            labels: Vec::new(),
            context: TelemetryContext::root(),
            protected: Vec::new(),
        }
    }

    /// Declares the complete ordinary field set, refusing duplicate names.
    ///
    /// Fields are sorted by name so the record material is canonical. A refusal leaves the record
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] for a duplicate field name.
    pub fn with_fields(mut self, mut fields: Vec<TelemetryField>) -> Result<Self, TelemetryError> {
        fields.sort();
        if fields.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidRecord,
                "a telemetry record declares a duplicate field name",
            ));
        }
        self.fields = fields;
        Ok(self)
    }

    /// Declares the complete ordinary label set, refusing duplicate names.
    ///
    /// Labels are sorted by name so series identity is canonical. A refusal leaves the record
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] for a duplicate label name.
    pub fn with_labels(mut self, mut labels: Vec<TelemetryLabel>) -> Result<Self, TelemetryError> {
        labels.sort();
        if labels.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidRecord,
                "a telemetry record declares a duplicate label name",
            ));
        }
        self.labels = labels;
        Ok(self)
    }

    /// Declares the complete explicit context.
    #[must_use]
    pub fn with_context(mut self, context: TelemetryContext) -> Self {
        self.context = context;
        self
    }

    /// Declares protected references, refusing a duplicate identity.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidRecord`] when one identity appears twice, even
    /// under two classes. A refusal leaves the record unchanged.
    pub fn with_protected(
        mut self,
        mut protected: Vec<TelemetryProtectedReference>,
    ) -> Result<Self, TelemetryError> {
        protected.sort();
        if protected.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidRecord,
                "a telemetry record declares one protected identity twice",
            ));
        }
        self.protected = protected;
        Ok(self)
    }

    /// Returns the caller-declared sequence, which is explicit record metadata.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the declared record kind.
    #[must_use]
    pub const fn kind(&self) -> TelemetryRecordKind {
        self.kind
    }

    /// Returns the declared record name.
    #[must_use]
    pub const fn name(&self) -> &TelemetryName {
        &self.name
    }

    /// Returns the declared matching body.
    #[must_use]
    pub const fn body(&self) -> &TelemetryRecordBody {
        &self.body
    }

    /// Returns the declared ordinary fields in canonical order.
    #[must_use]
    pub fn fields(&self) -> &[TelemetryField] {
        &self.fields
    }

    /// Returns the declared ordinary labels in canonical order.
    #[must_use]
    pub fn labels(&self) -> &[TelemetryLabel] {
        &self.labels
    }

    /// Returns the declared explicit context.
    #[must_use]
    pub const fn context(&self) -> &TelemetryContext {
        &self.context
    }

    /// Returns the declared protected references in canonical order.
    #[must_use]
    pub fn protected(&self) -> &[TelemetryProtectedReference] {
        &self.protected
    }

    /// Returns the declared record material length in bytes.
    ///
    /// This is a deterministic declared size over names, ordinary text, and protected reference
    /// metadata. It is not an encoded wire size and it contains no payload byte.
    #[must_use]
    pub fn material_bytes(&self) -> u64 {
        let mut total = self.name.len() as u64;
        total += match &self.body {
            TelemetryRecordBody::Log { message } => message.len() as u64,
            TelemetryRecordBody::Metric { unit, .. } => {
                8 + unit.as_ref().map_or(0, |unit| unit.len() as u64)
            }
            TelemetryRecordBody::Trace { .. } => 8 + 1,
        };
        total += self.fields.iter().map(TelemetryField::bytes).sum::<u64>();
        total += self.labels.iter().map(TelemetryLabel::bytes).sum::<u64>();
        total += self.context.bytes();
        total += self
            .protected
            .iter()
            .map(|reference| {
                reference.class().wire_name().len() as u64 + reference.id().as_str().len() as u64
            })
            .sum::<u64>();
        total
    }

    /// Returns the canonical series identity over ordinary declared inputs only.
    ///
    /// Protected references never enter series identity: a protected value is not a label, not a
    /// record name, and not a series key. The encoding length-prefixes each part so two different
    /// declarations cannot collide by concatenation.
    #[must_use]
    pub fn series_key(&self) -> TelemetrySeriesKey {
        let mut material = String::new();
        push_series_part(&mut material, self.kind.wire_name());
        push_series_part(&mut material, self.name.as_str());
        for label in &self.labels {
            push_series_part(&mut material, label.name().as_str());
            push_series_part(&mut material, label.value());
        }
        TelemetrySeriesKey(material)
    }

    /// Returns whether this record is Section 12 semantic evidence, which is never true.
    #[must_use]
    pub const fn is_section_12_evidence(&self) -> bool {
        false
    }
}

/// One canonical telemetry series identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TelemetrySeriesKey(String);

impl TelemetrySeriesKey {
    /// Returns the canonical series material.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn push_series_part(out: &mut String, value: &str) {
    out.push_str(&format!("{}:", value.len()));
    out.push_str(value);
}

/// One pending or queued telemetry emit.
///
/// The value is affine: it is consumed by exactly one settlement, so cancellation, acknowledgement,
/// ambiguity, and failure cannot settle one emit twice. It is not delivered until an explicit
/// acknowledgement.
#[derive(Debug)]
pub struct TelemetryEmit {
    sequence: u64,
    sink: TelemetrySinkId,
    instance: TelemetrySinkInstanceId,
    authority: SinkAuthority,
    delivery: TelemetryDeliveryClass,
}

impl TelemetryEmit {
    /// Returns the declared record sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact sink identity.
    #[must_use]
    pub const fn sink(&self) -> &TelemetrySinkId {
        &self.sink
    }

    /// Returns the exact sink instance that issued this emit.
    #[must_use]
    pub const fn instance(&self) -> &TelemetrySinkInstanceId {
        &self.instance
    }

    /// Returns the declared delivery class.
    #[must_use]
    pub const fn delivery(&self) -> TelemetryDeliveryClass {
        self.delivery
    }

    /// Returns whether this emit is already delivered, which is never true before acknowledgement.
    #[must_use]
    pub const fn is_delivered(&self) -> bool {
        false
    }

    /// Settles one required or best-effort emit at a declared sink acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::InvalidSettlement`] when the emit belongs to another
    /// sink instance, [`TelemetryDiagnosticCode::ShutdownAlreadySettled`] after aggregate shutdown
    /// settlement, and [`TelemetryDiagnosticCode::BackpressureBound`] when the shutdown drain
    /// budget is exhausted. Every refusal leaves the state unchanged.
    pub fn acknowledge(
        self,
        state: &mut TelemetrySinkState,
    ) -> Result<TelemetrySettlement, TelemetrySettleError> {
        self.settle(state, SettlementKind::Acknowledged)
    }

    /// Settles one accepted cancellation exactly once.
    ///
    /// # Errors
    ///
    /// Returns the same ownership, shutdown, or drain-bound refusals as [`Self::acknowledge`].
    pub fn cancel(
        self,
        state: &mut TelemetrySinkState,
    ) -> Result<TelemetrySettlement, TelemetrySettleError> {
        self.settle(state, SettlementKind::Cancelled)
    }

    /// Settles one ambiguous write without permitting a retry.
    ///
    /// # Errors
    ///
    /// Returns the same ownership, shutdown, or drain-bound refusals as [`Self::acknowledge`].
    pub fn ambiguous(
        self,
        state: &mut TelemetrySinkState,
    ) -> Result<TelemetrySettlement, TelemetrySettleError> {
        self.settle(state, SettlementKind::Ambiguous)
    }

    /// Settles one terminal delivery failure.
    ///
    /// # Errors
    ///
    /// Returns the same ownership, shutdown, or drain-bound refusals as [`Self::acknowledge`].
    pub fn failed(
        self,
        state: &mut TelemetrySinkState,
    ) -> Result<TelemetrySettlement, TelemetrySettleError> {
        self.settle(state, SettlementKind::Failed)
    }

    fn settle(
        self,
        state: &mut TelemetrySinkState,
        kind: SettlementKind,
    ) -> Result<TelemetrySettlement, TelemetrySettleError> {
        if self.authority != state.authority {
            return Err(TelemetrySettleError::new(
                TelemetryError::new(
                    TelemetryDiagnosticCode::InvalidSettlement,
                    "the emit belongs to another issuing sink state",
                ),
                self,
            ));
        }
        if state.shutdown_complete() {
            return Err(TelemetrySettleError::new(
                TelemetryError::new(
                    TelemetryDiagnosticCode::ShutdownAlreadySettled,
                    "aggregate telemetry shutdown already settled",
                ),
                self,
            ));
        }
        if let Err(error) = state.settle_emit(self.delivery) {
            return Err(TelemetrySettleError::new(error, self));
        }
        let sequence = self.sequence;
        let sink = self.sink;
        Ok(match kind {
            SettlementKind::Acknowledged => {
                state.acknowledged = state.acknowledged.saturating_add(1);
                TelemetrySettlement::Acknowledged { sequence, sink }
            }
            SettlementKind::Cancelled => {
                state.cancelled = state.cancelled.saturating_add(1);
                TelemetrySettlement::Cancelled { sequence, sink }
            }
            SettlementKind::Ambiguous => {
                state.ambiguous = state.ambiguous.saturating_add(1);
                TelemetrySettlement::Ambiguous { sequence, sink }
            }
            SettlementKind::Failed => {
                state.failed = state.failed.saturating_add(1);
                TelemetrySettlement::Failed { sequence, sink }
            }
        })
    }
}

/// One terminal settlement kind requested by a live emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettlementKind {
    Acknowledged,
    Cancelled,
    Ambiguous,
    Failed,
}

/// One refused emit settlement that returns the unsettled affine emit.
///
/// A foreign instance, a completed aggregate shutdown, or an exhausted drain budget refuses
/// without mutating the state and without losing the obligation. The caller may present the same
/// emit to its issuing instance.
#[derive(Debug)]
pub struct TelemetrySettleError {
    error: TelemetryError,
    emit: TelemetryEmit,
}

impl TelemetrySettleError {
    fn new(error: TelemetryError, emit: TelemetryEmit) -> Self {
        Self { error, emit }
    }

    /// Returns the typed refusal.
    #[must_use]
    pub const fn error(&self) -> &TelemetryError {
        &self.error
    }

    /// Returns the still-unsettled emit.
    #[must_use]
    pub fn into_emit(self) -> TelemetryEmit {
        self.emit
    }
}

impl fmt::Display for TelemetrySettleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.error)
    }
}

/// One admission outcome of `GNT-48.4` and `GNT-48.6`.
#[derive(Debug)]
pub enum TelemetryAdmission {
    /// A required emit is pending acknowledgement.
    Pending(TelemetryEmit),
    /// A best-effort emit is queued, which is not delivered.
    Queued(TelemetryEmit),
    /// A best-effort emit was dropped as the newest whole record.
    Dropped(TelemetryDropReceipt),
}

impl TelemetryAdmission {
    /// Returns whether this outcome is a required pending emit.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    /// Returns whether this outcome is a best-effort queued emit.
    #[must_use]
    pub const fn is_queued(&self) -> bool {
        matches!(self, Self::Queued(_))
    }

    /// Returns whether this outcome is a best-effort drop.
    #[must_use]
    pub const fn is_dropped(&self) -> bool {
        matches!(self, Self::Dropped(_))
    }

    /// Returns whether admission delivered the record, which is never true.
    #[must_use]
    pub const fn is_delivered(&self) -> bool {
        false
    }
}

/// One bounded best-effort drop receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryDropReceipt {
    sequence: u64,
    dropped_total: u64,
}

impl TelemetryDropReceipt {
    /// Returns the dropped record sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the bounded cumulative drop count after this drop.
    #[must_use]
    pub const fn dropped_total(self) -> u64 {
        self.dropped_total
    }

    /// Returns whether the dropped record was delivered, which is never true.
    #[must_use]
    pub const fn is_delivered(self) -> bool {
        false
    }
}

/// One terminal emit settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetrySettlement {
    /// The declared sink acknowledged the emit.
    Acknowledged {
        /// The settled record sequence.
        sequence: u64,
        /// The exact sink identity.
        sink: TelemetrySinkId,
    },
    /// An accepted cancellation settled the emit once.
    Cancelled {
        /// The settled record sequence.
        sequence: u64,
        /// The exact sink identity.
        sink: TelemetrySinkId,
    },
    /// The write is ambiguous and is never silently retried.
    Ambiguous {
        /// The settled record sequence.
        sequence: u64,
        /// The exact sink identity.
        sink: TelemetrySinkId,
    },
    /// Delivery terminally failed.
    Failed {
        /// The settled record sequence.
        sequence: u64,
        /// The exact sink identity.
        sink: TelemetrySinkId,
    },
}

impl TelemetrySettlement {
    /// Returns the settled record sequence.
    #[must_use]
    pub fn sequence(self) -> u64 {
        match self {
            Self::Acknowledged { sequence, .. }
            | Self::Cancelled { sequence, .. }
            | Self::Ambiguous { sequence, .. }
            | Self::Failed { sequence, .. } => sequence,
        }
    }

    /// Returns whether this settlement is a delivered acknowledgement.
    #[must_use]
    pub fn is_delivered(self) -> bool {
        matches!(self, Self::Acknowledged { .. })
    }

    /// Returns whether a retry is permitted, which is never true for an ambiguous settlement.
    #[must_use]
    pub fn retry_permitted(self) -> bool {
        false
    }

    /// Returns whether this settlement carries a business or task outcome, which is never true.
    #[must_use]
    pub fn business_outcome(self) -> Option<&'static str> {
        None
    }
}

/// One closed sink fault class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryFaultClass {
    /// A foreign panic was contained at the sink boundary.
    Panic,
    /// A foreign error was contained at the sink boundary.
    Error,
    /// A protocol failure was contained at the sink boundary.
    Protocol,
}

impl TelemetryFaultClass {
    /// Every declared class, in canonical order.
    pub const ALL: [Self; 3] = [Self::Panic, Self::Error, Self::Protocol];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::Error => "error",
            Self::Protocol => "protocol",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|class| class.wire_name() == value)
    }
}

/// One redacted sink-fault report.
///
/// The report names the exact sink and closed fault class only. It carries no payload byte, no
/// backtrace, no payload-derived digest, and no protected content, and it is not a telemetry record,
/// so it cannot be recursively logged through the telemetry sink it describes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetrySinkFault {
    sink: TelemetrySinkId,
    class: TelemetryFaultClass,
}

impl TelemetrySinkFault {
    /// Declares one redacted fault for one exact sink.
    #[must_use]
    pub const fn new(sink: TelemetrySinkId, class: TelemetryFaultClass) -> Self {
        Self { sink, class }
    }

    /// Returns the exact sink identity.
    #[must_use]
    pub const fn sink(&self) -> &TelemetrySinkId {
        &self.sink
    }

    /// Returns the closed fault class.
    #[must_use]
    pub const fn class(&self) -> TelemetryFaultClass {
        self.class
    }

    /// Returns the fixed redacted diagnostic detail.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        "<redacted>"
    }

    /// Returns whether this fault is a telemetry record, which is never true.
    #[must_use]
    pub const fn is_telemetry_record(&self) -> bool {
        false
    }
}

/// One sink-fault containment receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryFaultReceipt {
    fault: TelemetrySinkFault,
}

impl TelemetryFaultReceipt {
    /// Returns the contained fault.
    #[must_use]
    pub const fn fault(&self) -> &TelemetrySinkFault {
        &self.fault
    }

    /// Returns whether the fault changed a fixed business outcome, which is never true.
    #[must_use]
    pub const fn business_outcome_changed(&self) -> bool {
        false
    }
}

/// One bounded shutdown plan returned when shutdown begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryShutdownPlan {
    pending_emits: u64,
    drain_bound: u64,
    timeout_us: u64,
    within_bound: bool,
}

impl TelemetryShutdownPlan {
    /// Returns the pending emit count observed at shutdown start.
    #[must_use]
    pub const fn pending_emits(self) -> u64 {
        self.pending_emits
    }

    /// Returns the declared finite drain bound.
    #[must_use]
    pub const fn drain_bound(self) -> u64 {
        self.drain_bound
    }

    /// Returns the declared finite shutdown timeout in microseconds.
    #[must_use]
    pub const fn timeout_us(self) -> u64 {
        self.timeout_us
    }

    /// Returns whether the pending emits fit the declared drain bound.
    #[must_use]
    pub const fn within_bound(self) -> bool {
        self.within_bound
    }
}

/// One shutdown settlement with explicit drained and abandoned accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryShutdownSettlement {
    drained: u64,
    abandoned: u64,
    within_bound: bool,
}

impl TelemetryShutdownSettlement {
    /// Returns the drained emit count.
    #[must_use]
    pub const fn drained(self) -> u64 {
        self.drained
    }

    /// Returns the abandoned emit count, which is reported rather than silently discarded.
    #[must_use]
    pub const fn abandoned(self) -> u64 {
        self.abandoned
    }

    /// Returns whether the pending emits fit the declared drain bound.
    #[must_use]
    pub const fn within_bound(self) -> bool {
        self.within_bound
    }
}

/// One deterministic admission state of a single declared sink instance.
///
/// This is accounting state, not a queue implementation and not a sink. It stores counts, active
/// series keys, and one redacted poison report; it stores no record, no payload, and no context.
#[derive(Debug, Eq, PartialEq)]
pub struct TelemetrySinkState {
    instance: TelemetrySinkInstanceId,
    authority: SinkAuthority,
    sink: Option<TelemetrySinkId>,
    policy: Option<TelemetrySinkPolicy>,
    queued: u64,
    pending_emits: u64,
    retained: u64,
    active_series: BTreeSet<TelemetrySeriesKey>,
    dropped: u64,
    acknowledged: u64,
    cancelled: u64,
    ambiguous: u64,
    failed: u64,
    abandoned: u64,
    poisoned: Option<TelemetrySinkFault>,
    shutdown: Option<TelemetryShutdownPlan>,
    shutdown_drained: u64,
    shutdown_complete: bool,
}

/// One immutable comparison snapshot of a sink accounting state.
///
/// The snapshot carries declared accounting facts only. It carries no issuing authority and cannot
/// settle an emit, so two snapshots can be compared without duplicating a live obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetrySinkSnapshot {
    instance: TelemetrySinkInstanceId,
    sink: Option<TelemetrySinkId>,
    policy: Option<TelemetrySinkPolicy>,
    queued: u64,
    pending_emits: u64,
    retained: u64,
    active_series: BTreeSet<TelemetrySeriesKey>,
    dropped: u64,
    acknowledged: u64,
    cancelled: u64,
    ambiguous: u64,
    failed: u64,
    abandoned: u64,
    poisoned: Option<TelemetrySinkFault>,
    shutdown: Option<TelemetryShutdownPlan>,
    shutdown_drained: u64,
    shutdown_complete: bool,
}

impl TelemetrySinkState {
    /// Returns an empty sink admission state for one declared sink instance.
    #[must_use]
    pub fn new(instance: TelemetrySinkInstanceId) -> Self {
        Self {
            instance,
            authority: SinkAuthority::new(),
            sink: None,
            policy: None,
            queued: 0,
            pending_emits: 0,
            retained: 0,
            active_series: BTreeSet::new(),
            dropped: 0,
            acknowledged: 0,
            cancelled: 0,
            ambiguous: 0,
            failed: 0,
            abandoned: 0,
            poisoned: None,
            shutdown: None,
            shutdown_drained: 0,
            shutdown_complete: false,
        }
    }

    /// Returns a sink admission state already bound to one immutable policy.
    #[must_use]
    pub fn with_policy(instance: TelemetrySinkInstanceId, policy: TelemetrySinkPolicy) -> Self {
        let mut state = Self::new(instance);
        state.sink = Some(policy.sink().clone());
        state.policy = Some(policy);
        state
    }

    /// Returns one immutable comparison snapshot of this state.
    #[must_use]
    pub fn snapshot(&self) -> TelemetrySinkSnapshot {
        TelemetrySinkSnapshot {
            instance: self.instance.clone(),
            sink: self.sink.clone(),
            policy: self.policy.clone(),
            queued: self.queued,
            pending_emits: self.pending_emits,
            retained: self.retained,
            active_series: self.active_series.clone(),
            dropped: self.dropped,
            acknowledged: self.acknowledged,
            cancelled: self.cancelled,
            ambiguous: self.ambiguous,
            failed: self.failed,
            abandoned: self.abandoned,
            poisoned: self.poisoned.clone(),
            shutdown: self.shutdown,
            shutdown_drained: self.shutdown_drained,
            shutdown_complete: self.shutdown_complete,
        }
    }

    /// Returns the exact sink instance identity.
    #[must_use]
    pub const fn instance(&self) -> &TelemetrySinkInstanceId {
        &self.instance
    }

    /// Returns the immutable policy bound to this state, when any.
    #[must_use]
    pub const fn policy(&self) -> Option<&TelemetrySinkPolicy> {
        self.policy.as_ref()
    }

    /// Returns the declared sink identity bound to this state, when any.
    #[must_use]
    pub const fn sink(&self) -> Option<&TelemetrySinkId> {
        self.sink.as_ref()
    }

    /// Returns the best-effort queue depth.
    #[must_use]
    pub const fn queued(&self) -> u64 {
        self.queued
    }

    /// Returns the unsettled pending emit count.
    #[must_use]
    pub const fn pending_emits(&self) -> u64 {
        self.pending_emits
    }

    /// Returns the retained record count.
    #[must_use]
    pub const fn retained(&self) -> u64 {
        self.retained
    }

    /// Returns the admitted active series count.
    #[must_use]
    pub fn active_series(&self) -> usize {
        self.active_series.len()
    }

    /// Returns the bounded cumulative best-effort drop count.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Returns the acknowledged emit count.
    #[must_use]
    pub const fn acknowledged(&self) -> u64 {
        self.acknowledged
    }

    /// Returns the cancelled emit count.
    #[must_use]
    pub const fn cancelled(&self) -> u64 {
        self.cancelled
    }

    /// Returns the ambiguous emit count.
    #[must_use]
    pub const fn ambiguous(&self) -> u64 {
        self.ambiguous
    }

    /// Returns the terminally failed emit count.
    #[must_use]
    pub const fn failed(&self) -> u64 {
        self.failed
    }

    /// Returns the abandoned emit count reported at shutdown settlement.
    #[must_use]
    pub const fn abandoned(&self) -> u64 {
        self.abandoned
    }

    /// Returns the contained sink fault, when the sink is poisoned.
    #[must_use]
    pub const fn poisoned(&self) -> Option<&TelemetrySinkFault> {
        self.poisoned.as_ref()
    }

    /// Returns the declared shutdown plan, when shutdown has begun.
    #[must_use]
    pub const fn shutdown(&self) -> Option<TelemetryShutdownPlan> {
        self.shutdown
    }

    /// Returns whether shutdown has already settled.
    #[must_use]
    pub const fn shutdown_complete(&self) -> bool {
        self.shutdown_complete
    }

    /// Returns the emit count already settled against the shutdown drain budget.
    #[must_use]
    pub const fn shutdown_drained(&self) -> u64 {
        self.shutdown_drained
    }

    fn check_policy(&self, policy: &TelemetrySinkPolicy) -> Result<(), TelemetryError> {
        if let Some(sink) = &self.sink
            && sink != policy.sink()
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::PolicyMismatch,
                "the bound sink instance refuses a policy for another sink",
            ));
        }
        if let Some(existing) = &self.policy
            && existing != policy
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::PolicyMismatch,
                "the bound sink instance refuses a replacement policy",
            ));
        }
        Ok(())
    }

    fn commit_policy(&mut self, policy: &TelemetrySinkPolicy) {
        if self.sink.is_none() {
            self.sink = Some(policy.sink().clone());
        }
        if self.policy.is_none() {
            self.policy = Some(policy.clone());
        }
    }

    /// Poisons this sink instance and returns its redacted containment receipt.
    ///
    /// A poisoned sink refuses every later admission. The fault is contained here and is not a
    /// telemetry record, so it cannot be recursively logged through this sink. A fault naming
    /// another sink refuses without mutating this instance.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::SinkMismatch`] when the fault names another sink.
    pub fn poison(
        &mut self,
        fault: TelemetrySinkFault,
    ) -> Result<TelemetryFaultReceipt, TelemetryError> {
        if let Some(sink) = &self.sink
            && sink != fault.sink()
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkMismatch,
                "a fault report names another sink instance",
            ));
        }
        if self.sink.is_none() {
            self.sink = Some(fault.sink().clone());
        }
        self.poisoned = Some(fault.clone());
        Ok(TelemetryFaultReceipt { fault })
    }

    /// Admits one record atomically against one declared policy and emit grant.
    ///
    /// Checks run in one declared order: poison, shutdown, policy presence, emit grant, record and
    /// field/label/context bounds, protected destination release, active-series cardinality, then
    /// delivery class. A refusal leaves every counter and the active-series set exactly unchanged.
    /// A best-effort full queue drops the newest whole record and reports one bounded drop; a
    /// required full pending set returns the bounded backpressure descriptor without enqueueing.
    ///
    /// # Errors
    ///
    /// Returns the typed refusal of the first failed check.
    pub fn admit(
        &mut self,
        policy: Option<&TelemetrySinkPolicy>,
        grant: Option<&TelemetryEmitGrant>,
        record: &TelemetryRecord,
    ) -> Result<TelemetryAdmission, TelemetryError> {
        if self.poisoned.is_some() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkPoisoned,
                "a poisoned telemetry sink refuses every admission",
            ));
        }
        if self.shutdown.is_some() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkShutdown,
                "a telemetry sink that began shutdown refuses new records",
            ));
        }
        let Some(policy) = policy else {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::PolicyAbsent,
                "a telemetry sink has no declared immutable policy",
            ));
        };
        self.check_policy(policy)?;
        if grant.is_none_or(|grant| !grant.allows_emit()) {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::EmitNotGranted,
                "the telemetry emit grant does not admit this attempt",
            ));
        }
        let limits = policy.limits();
        if record.material_bytes() > limits.max_record_bytes() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::RecordBound,
                format!(
                    "the record material {} exceeds the declared bound {}",
                    record.material_bytes(),
                    limits.max_record_bytes()
                ),
            ));
        }
        if record.fields().len() as u64 > limits.max_fields() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::FieldCountBound,
                "the declared field count exceeds the sink bound",
            ));
        }
        if record
            .fields()
            .iter()
            .any(|field| field.bytes() > limits.max_field_bytes())
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::FieldByteBound,
                "a declared field exceeds the sink byte bound",
            ));
        }
        if record.labels().len() as u64 > limits.max_labels() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::LabelCountBound,
                "the declared label count exceeds the sink bound",
            ));
        }
        if record
            .labels()
            .iter()
            .any(|label| label.bytes() > limits.max_label_bytes())
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::LabelByteBound,
                "a declared label exceeds the sink byte bound",
            ));
        }
        if record.context().depth() > limits.max_context_depth()
            || record.context().bytes() > limits.max_context_bytes()
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::ContextBound,
                "the declared context exceeds its depth or byte bound",
            ));
        }
        if !record.protected().is_empty() {
            let Some(release) = policy.release() else {
                return Err(TelemetryError::new(
                    TelemetryDiagnosticCode::ReleaseRequired,
                    "a protected telemetry reference needs a destination release",
                ));
            };
            for reference in record.protected() {
                if !release.authorizes(policy.sink(), reference.class()) {
                    return Err(TelemetryError::new(
                        TelemetryDiagnosticCode::ReleaseClassNotDeclared,
                        format!(
                            "the telemetry release does not declare the protected class {}",
                            reference.class().wire_name()
                        ),
                    ));
                }
            }
        }
        let series = record.series_key();
        let new_series = !self.active_series.contains(&series);
        if new_series && self.active_series.len() as u64 >= limits.max_series() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SeriesBound,
                "the new active series exceeds the sink cardinality bound",
            ));
        }
        match policy.delivery() {
            TelemetryDeliveryClass::Required => {
                if self.pending_emits >= limits.max_pending_emits() {
                    return Err(TelemetryError::new(
                        TelemetryDiagnosticCode::BackpressureBound,
                        format!(
                            "required telemetry backpressure is bounded by {} microseconds",
                            policy.wait_bound_us()
                        ),
                    ));
                }
                self.commit_policy(policy);
                self.pending_emits += 1;
                if new_series {
                    self.active_series.insert(series);
                }
                Ok(TelemetryAdmission::Pending(TelemetryEmit {
                    sequence: record.sequence(),
                    sink: policy.sink().clone(),
                    instance: self.instance.clone(),
                    authority: self.authority.clone(),
                    delivery: TelemetryDeliveryClass::Required,
                }))
            }
            TelemetryDeliveryClass::BestEffort => {
                if self.queued >= limits.max_queue()
                    || self.pending_emits >= limits.max_pending_emits()
                {
                    self.commit_policy(policy);
                    self.dropped = self.dropped.saturating_add(1);
                    return Ok(TelemetryAdmission::Dropped(TelemetryDropReceipt {
                        sequence: record.sequence(),
                        dropped_total: self.dropped,
                    }));
                }
                self.commit_policy(policy);
                self.queued += 1;
                self.pending_emits += 1;
                if new_series {
                    self.active_series.insert(series);
                }
                Ok(TelemetryAdmission::Queued(TelemetryEmit {
                    sequence: record.sequence(),
                    sink: policy.sink().clone(),
                    instance: self.instance.clone(),
                    authority: self.authority.clone(),
                    delivery: TelemetryDeliveryClass::BestEffort,
                }))
            }
        }
    }

    /// Retains one record atomically under the declared retention bound.
    ///
    /// Retention is full when the bound is reached; this refuses rather than evicting a previously
    /// retained record. A zero bound denies every retention.
    ///
    /// # Errors
    ///
    /// Returns the typed refusal of the first failed check.
    pub fn retain(
        &mut self,
        policy: Option<&TelemetrySinkPolicy>,
        record: &TelemetryRecord,
    ) -> Result<(), TelemetryError> {
        if self.poisoned.is_some() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkPoisoned,
                "a poisoned telemetry sink refuses every retention",
            ));
        }
        if self.shutdown.is_some() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkShutdown,
                "a telemetry sink that began shutdown refuses new retention",
            ));
        }
        let Some(policy) = policy else {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::PolicyAbsent,
                "a telemetry sink has no declared immutable policy",
            ));
        };
        self.check_policy(policy)?;
        if self.retained >= policy.limits().max_retention() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::RetentionBound,
                format!(
                    "the retention bound {} is full for record {}",
                    policy.limits().max_retention(),
                    record.sequence()
                ),
            ));
        }
        self.commit_policy(policy);
        self.retained += 1;
        Ok(())
    }

    /// Begins bounded shutdown and returns its declared plan.
    ///
    /// New admissions and retentions are refused after this call. The plan reports the pending
    /// emits, the finite drain bound, the finite timeout, and whether the pending set fits the
    /// bound. The application owns the actual drain and flush; this model only declares and
    /// accounts the bound.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::SinkShutdown`] when shutdown already began and
    /// [`TelemetryDiagnosticCode::PolicyAbsent`] when no policy is supplied.
    pub fn begin_shutdown(
        &mut self,
        policy: Option<&TelemetrySinkPolicy>,
    ) -> Result<TelemetryShutdownPlan, TelemetryError> {
        if self.shutdown.is_some() {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkShutdown,
                "telemetry shutdown already began",
            ));
        }
        let Some(policy) = policy else {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::PolicyAbsent,
                "a telemetry sink has no declared immutable policy",
            ));
        };
        self.check_policy(policy)?;
        let plan = TelemetryShutdownPlan {
            pending_emits: self.pending_emits,
            drain_bound: policy.limits().max_shutdown_drain(),
            timeout_us: policy.limits().max_shutdown_timeout_us(),
            within_bound: self.pending_emits <= policy.limits().max_shutdown_drain(),
        };
        self.commit_policy(policy);
        self.shutdown_drained = 0;
        self.shutdown = Some(plan);
        Ok(plan)
    }

    /// Settles bounded shutdown with explicit drained and abandoned accounting.
    ///
    /// Every pending emit is either reported as drained or reported as abandoned. Nothing is
    /// silently discarded and no later settlement is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDiagnosticCode::SinkShutdown`] when shutdown never began,
    /// [`TelemetryDiagnosticCode::ShutdownAlreadySettled`] when it already settled, and
    /// [`TelemetryDiagnosticCode::InvalidSettlement`] when the drained count exceeds the pending
    /// count or the declared shutdown drain bound.
    pub fn settle_shutdown(
        &mut self,
        drained: u64,
    ) -> Result<TelemetryShutdownSettlement, TelemetryError> {
        let Some(plan) = self.shutdown else {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::SinkShutdown,
                "telemetry shutdown never began",
            ));
        };
        if self.shutdown_complete {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::ShutdownAlreadySettled,
                "telemetry shutdown already settled once",
            ));
        }
        if drained > self.pending_emits {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidSettlement,
                "the drained count exceeds the pending emit count",
            ));
        }
        let total_drained = self.shutdown_drained.saturating_add(drained);
        if total_drained > plan.drain_bound {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::InvalidSettlement,
                "the drained count exceeds the declared shutdown drain bound",
            ));
        }
        let abandoned = self.pending_emits - drained;
        self.shutdown_drained = total_drained;
        self.pending_emits = 0;
        self.queued = 0;
        self.abandoned = self.abandoned.saturating_add(abandoned);
        self.shutdown_complete = true;
        Ok(TelemetryShutdownSettlement {
            drained: total_drained,
            abandoned,
            within_bound: plan.within_bound && total_drained <= plan.drain_bound,
        })
    }

    fn settle_emit(&mut self, delivery: TelemetryDeliveryClass) -> Result<(), TelemetryError> {
        if let Some(plan) = self.shutdown
            && self.shutdown_drained >= plan.drain_bound
        {
            return Err(TelemetryError::new(
                TelemetryDiagnosticCode::BackpressureBound,
                "the declared shutdown drain bound is exhausted",
            ));
        }
        self.pending_emits = self.pending_emits.saturating_sub(1);
        if delivery == TelemetryDeliveryClass::BestEffort {
            self.queued = self.queued.saturating_sub(1);
        }
        if self.shutdown.is_some() {
            self.shutdown_drained = self.shutdown_drained.saturating_add(1);
        }
        Ok(())
    }
}

/// The closed telemetry refusal vocabulary of `GNT-48.3` through `GNT-48.8`.
///
/// Every code names exactly one condition and is owned by exactly one clause. The vocabulary is
/// additive to the existing Section 48 declaration diagnostics; it renames or removes none.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TelemetryDiagnosticCode {
    /// Required backpressure is at its finite bound.
    BackpressureBound,
    /// The declared context exceeds a depth or byte bound.
    ContextBound,
    /// No telemetry emit grant admits the attempt.
    EmitNotGranted,
    /// A declared field exceeds the byte bound.
    FieldByteBound,
    /// The declared field count exceeds the bound.
    FieldCountBound,
    /// A declared ordinary identity is malformed.
    InvalidIdentity,
    /// A declared record is malformed.
    InvalidRecord,
    /// A settlement names an impossible count.
    InvalidSettlement,
    /// A declared label exceeds the byte bound.
    LabelByteBound,
    /// The declared label count exceeds the bound.
    LabelCountBound,
    /// The sink has no declared policy.
    PolicyAbsent,
    /// The sink refuses a replacement policy.
    PolicyMismatch,
    /// The declared record material exceeds the bound.
    RecordBound,
    /// A projection names another protected class.
    ReleaseClassMismatch,
    /// A protected class is not declared by the destination release.
    ReleaseClassNotDeclared,
    /// A destination release names another sink or destination.
    ReleaseDestinationMismatch,
    /// A protected reference has no destination release.
    ReleaseRequired,
    /// The retention bound is full.
    RetentionBound,
    /// A new active series exceeds the cardinality bound.
    SeriesBound,
    /// Shutdown already settled.
    ShutdownAlreadySettled,
    /// A fault or policy names another sink.
    SinkMismatch,
    /// The sink is poisoned by a contained fault.
    SinkPoisoned,
    /// The sink began shutdown.
    SinkShutdown,
    /// A declared limit is unlimited.
    UnlimitedPolicy,
}

impl TelemetryDiagnosticCode {
    /// Every declared code, in exact wire-name order.
    pub const ALL: [Self; 24] = [
        Self::BackpressureBound,
        Self::ContextBound,
        Self::EmitNotGranted,
        Self::FieldByteBound,
        Self::FieldCountBound,
        Self::InvalidIdentity,
        Self::InvalidRecord,
        Self::InvalidSettlement,
        Self::LabelByteBound,
        Self::LabelCountBound,
        Self::PolicyAbsent,
        Self::PolicyMismatch,
        Self::RecordBound,
        Self::ReleaseClassMismatch,
        Self::ReleaseClassNotDeclared,
        Self::ReleaseDestinationMismatch,
        Self::ReleaseRequired,
        Self::RetentionBound,
        Self::SeriesBound,
        Self::ShutdownAlreadySettled,
        Self::SinkMismatch,
        Self::SinkPoisoned,
        Self::SinkShutdown,
        Self::UnlimitedPolicy,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::BackpressureBound => "telemetry-backpressure-bound",
            Self::ContextBound => "telemetry-context-bound",
            Self::EmitNotGranted => "telemetry-emit-not-granted",
            Self::FieldByteBound => "telemetry-field-byte-bound",
            Self::FieldCountBound => "telemetry-field-count-bound",
            Self::InvalidIdentity => "telemetry-invalid-identity",
            Self::InvalidRecord => "telemetry-invalid-record",
            Self::InvalidSettlement => "telemetry-invalid-settlement",
            Self::LabelByteBound => "telemetry-label-byte-bound",
            Self::LabelCountBound => "telemetry-label-count-bound",
            Self::PolicyAbsent => "telemetry-policy-absent",
            Self::PolicyMismatch => "telemetry-policy-mismatch",
            Self::RecordBound => "telemetry-record-bound",
            Self::ReleaseClassMismatch => "telemetry-release-class-mismatch",
            Self::ReleaseClassNotDeclared => "telemetry-release-class-not-declared",
            Self::ReleaseDestinationMismatch => "telemetry-release-destination-mismatch",
            Self::ReleaseRequired => "telemetry-release-required",
            Self::RetentionBound => "telemetry-retention-bound",
            Self::SeriesBound => "telemetry-series-bound",
            Self::ShutdownAlreadySettled => "telemetry-shutdown-already-settled",
            Self::SinkMismatch => "telemetry-sink-mismatch",
            Self::SinkPoisoned => "telemetry-sink-poisoned",
            Self::SinkShutdown => "telemetry-sink-shutdown",
            Self::UnlimitedPolicy => "telemetry-unlimited-policy",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.wire_name() == value)
    }

    /// Returns the one Section 48 clause that owns this refusal.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        match self {
            Self::BackpressureBound
            | Self::InvalidSettlement
            | Self::ShutdownAlreadySettled
            | Self::SinkShutdown => "GNT-48.7-telemetry-backpressure-cancellation-and-shutdown",
            Self::ContextBound
            | Self::FieldByteBound
            | Self::FieldCountBound
            | Self::LabelByteBound
            | Self::LabelCountBound
            | Self::RecordBound
            | Self::RetentionBound
            | Self::SeriesBound => "GNT-48.4-telemetry-atomic-admission-and-cardinality",
            Self::EmitNotGranted
            | Self::PolicyAbsent
            | Self::PolicyMismatch
            | Self::UnlimitedPolicy => "GNT-48.3-telemetry-sink-policy-and-finite-limits",
            Self::InvalidIdentity | Self::InvalidRecord => {
                "GNT-48.2-telemetry-record-kinds-and-explicit-context"
            }
            Self::ReleaseClassMismatch
            | Self::ReleaseClassNotDeclared
            | Self::ReleaseDestinationMismatch
            | Self::ReleaseRequired => "GNT-48.5-telemetry-protected-labels-identity-and-release",
            Self::SinkMismatch | Self::SinkPoisoned => "GNT-48.8-telemetry-sink-fault-containment",
        }
    }
}

/// One typed telemetry refusal.
///
/// The detail is ordinary declared metadata and never a protected value, payload byte, or
/// payload-derived digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryError {
    code: TelemetryDiagnosticCode,
    detail: String,
}

impl TelemetryError {
    fn new(code: TelemetryDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the one declared code that owns this refusal.
    #[must_use]
    pub const fn code(&self) -> TelemetryDiagnosticCode {
        self.code
    }

    /// Returns the non-protected explanation of the refused condition.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.wire_name(), self.detail)
    }
}

/// Returns whether a telemetry record is Section 12 semantic evidence, which is never true.
#[must_use]
pub const fn telemetry_is_semantic_evidence() -> bool {
    false
}

fn validate_ordinary_text(value: &str, label: &str) -> Result<(), TelemetryError> {
    if value.is_empty() {
        return Err(TelemetryError::new(
            TelemetryDiagnosticCode::InvalidRecord,
            format!("{label} is empty"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(TelemetryError::new(
            TelemetryDiagnosticCode::InvalidRecord,
            format!("{label} contains a control character"),
        ));
    }
    Ok(())
}
