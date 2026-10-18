//! Declared `std.console` surface model for `SPEC.md` Section 46.
//!
//! This module publishes the canonical module and item rows of the `std.console` family and their
//! exact applicability. It is not a terminal, a descriptor, an adapter, a capability, or a
//! renderer, and it performs no I/O: every decision is a deterministic function of the declared
//! standard-library graph it is handed.

use std::fmt;

use crate::generated::RecoveryClass;
use crate::io::{IoDiagnosticCode, IoError, IoOperation, IoRequest};
use crate::operation::ProgressObservation;
use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 46 clauses implemented by this pure model, in declaration order.
pub const CONSOLE_CLAUSES: [&str; 10] = [
    "GNT-46.0-console-foundation-scope",
    "GNT-46.1-console-modules-and-item-rows",
    "GNT-46.2-console-bounded-operations",
    "GNT-46.3-console-operation-recovery-and-accepted-input",
    "GNT-46.4-console-encoding-and-shutdown-settlement",
    "GNT-46.5-console-terminal-observations",
    "GNT-46.6-console-operation-signatures",
    "GNT-46.7-console-requirement-groups",
    "GNT-46.8-console-authority-admission",
    "GNT-46.9-console-control-and-output-boundary",
];

/// One declared console operation of `GNT-46.2-console-bounded-operations`.
///
/// A console read or write consumes exactly one admitted request of the `std.io` one-call
/// contract; a flush declares no octet quantity. The console publishes no second request contract,
/// no second octet bound, and no second progress vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleOperation {
    /// One bounded console read.
    Read,
    /// One bounded console write.
    Write,
    /// One flush of previously written console output.
    Flush,
}

impl ConsoleOperation {
    /// Every declared operation, in canonical order.
    pub const ALL: [Self; 3] = [Self::Read, Self::Write, Self::Flush];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
        }
    }

    /// Strictly decodes one declared portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.wire_name() == value)
    }

    /// Returns the declared module that owns this operation.
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Read => "std.console::input",
            Self::Write | Self::Flush => "std.console::output",
        }
    }

    /// Returns the declared `std.io` operation this console operation consumes, when any.
    ///
    /// A read or write consumes one admitted request of the
    /// `GNT-45.1-bounded-one-call-io-contract` and publishes exactly the observation
    /// `GNT-45.3-io-progress-derivation` derives from its admitted facts; a flush consumes no
    /// request.
    #[must_use]
    pub const fn io_operation(self) -> Option<IoOperation> {
        match self {
            Self::Read => Some(IoOperation::Read),
            Self::Write => Some(IoOperation::Write),
            Self::Flush => None,
        }
    }

    /// Returns the observation a completed operation publishes without an octet count, when any.
    ///
    /// A completed flush publishes exactly `committed-progress` and no octet count; a read or
    /// write publishes no observation here, because its observation is the derivation of its
    /// admitted `std.io` facts.
    #[must_use]
    pub const fn completed_observation(self) -> Option<ProgressObservation> {
        match self {
            Self::Flush => Some(ProgressObservation::CommittedProgress),
            Self::Read | Self::Write => None,
        }
    }

    /// Returns the declared recovery class of
    /// `GNT-46.3-console-operation-recovery-and-accepted-input`.
    ///
    /// A read consumes a nontransactional input cursor and a write may duplicate output, so both
    /// declare `non_idempotent`; a repeated flush delivers no additional octet, so a flush declares
    /// `idempotent`. No console operation is `read_only`, and the console publishes no
    /// deduplication that would relabel a write.
    #[must_use]
    pub const fn declared_recovery_class(self) -> RecoveryClass {
        match self {
            Self::Read | Self::Write => RecoveryClass::NonIdempotent,
            Self::Flush => RecoveryClass::Idempotent,
        }
    }

    /// Returns whether the operation consumes a nontransactional input cursor.
    #[must_use]
    pub const fn consumes_input_cursor(self) -> bool {
        matches!(self, Self::Read)
    }

    /// Returns whether the operation accepts octets from its caller.
    #[must_use]
    pub const fn accepts_octets(self) -> bool {
        matches!(self, Self::Write)
    }

    /// Returns whether the operation returns octets to its caller.
    #[must_use]
    pub const fn returns_octets(self) -> bool {
        matches!(self, Self::Read)
    }
}

/// One declared console operation's recovery and accepted-input facts
/// (`GNT-46.3-console-operation-recovery-and-accepted-input`).
///
/// The declared recovery class is one member of the landed `read_only`, `idempotent`, and
/// `non_idempotent` vocabulary. A read consumes a nontransactional input cursor, so an accepted read
/// is never replayed, retried, repaired, or deduplicated by the console: only an adapter that owns a
/// replayable or transactional input source and binds the admitted read's stable operation identity
/// to its exact result may retry it. A write may duplicate output for the same reason, while a
/// repeated flush delivers no additional octet and needs no suppression. Effect certainty is not a
/// fact of this model: `GNT-20.6-ambiguous-effect-classification-and-retry-eligibility` derives it
/// from an operation's own admitted facts and admission position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleOperationFacts {
    /// The declared console operation.
    pub operation: ConsoleOperation,
    /// The declared recovery class of the operation.
    pub recovery: RecoveryClass,
    /// Whether the operation consumes a nontransactional input cursor.
    pub consumes_input_cursor: bool,
    /// Whether suppressing a duplicate is an adapter obligation keyed by a stable operation
    /// identity, as `GNT-46.3-console-operation-recovery-and-accepted-input` publishes.
    pub deduplication_is_adapter_owned: bool,
}

/// The declared facts of every console operation, in canonical operation order.
pub const CONSOLE_OPERATION_FACTS: [ConsoleOperationFacts; 3] = [
    ConsoleOperationFacts {
        operation: ConsoleOperation::Read,
        recovery: RecoveryClass::NonIdempotent,
        consumes_input_cursor: true,
        deduplication_is_adapter_owned: true,
    },
    ConsoleOperationFacts {
        operation: ConsoleOperation::Write,
        recovery: RecoveryClass::NonIdempotent,
        consumes_input_cursor: false,
        deduplication_is_adapter_owned: true,
    },
    ConsoleOperationFacts {
        operation: ConsoleOperation::Flush,
        recovery: RecoveryClass::Idempotent,
        consumes_input_cursor: false,
        deduplication_is_adapter_owned: false,
    },
];

/// One declared console envelope rule
/// (`GNT-46.4-console-encoding-and-shutdown-settlement`).
///
/// The rules are published by that clause alone: a console operation carries octets and no second
/// payload vocabulary, decoding belongs to the family that owns it, a protected value is not an
/// octet source, and the console owns no descriptor, background flusher, or work that outlives the
/// access its requester arranged.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleEnvelopeRule {
    /// A console operation carries octets and no second payload vocabulary.
    OctetsOnlyPayload,
    /// Text, scalar, line, and codec decoding is the owning family's, so an encoding error is not a
    /// console category.
    EncodingIsTextFamilyOwned,
    /// A protected value, protected envelope, credential, or key is not an octet source for a
    /// console operation.
    ProtectedValueIsNotAnOctetSource,
    /// Arranging console access belongs to its requester, so the console owns no descriptor and no
    /// work that outlives the access it was granted.
    AccessIsRequesterArranged,
}

impl ConsoleEnvelopeRule {
    /// Every declared rule, in canonical order.
    pub const ALL: [Self; 4] = [
        Self::OctetsOnlyPayload,
        Self::EncodingIsTextFamilyOwned,
        Self::ProtectedValueIsNotAnOctetSource,
        Self::AccessIsRequesterArranged,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::OctetsOnlyPayload => "octets-only-payload",
            Self::EncodingIsTextFamilyOwned => "encoding-is-text-family-owned",
            Self::ProtectedValueIsNotAnOctetSource => "protected-value-is-not-an-octet-source",
            Self::AccessIsRequesterArranged => "access-is-requester-arranged",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.wire_name() == value)
    }
}

/// One declared terminal detection fact of `GNT-46.5-console-terminal-observations`.
///
/// Detection is an observation and not a capability: it carries no terminal handle, no capability
/// grant, no capability family, no escape sequence, and no terminal-control authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleDetection {
    /// The console is attached to a terminal and publishes one dimension observation.
    Attached,
    /// The console is not attached to a terminal and publishes no dimension observation.
    NotAttached,
}

impl ConsoleDetection {
    /// Every declared detection fact, in canonical order.
    pub const ALL: [Self; 2] = [Self::Attached, Self::NotAttached];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Attached => "terminal-attached",
            Self::NotAttached => "terminal-not-attached",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|detection| detection.wire_name() == value)
    }
}

/// The largest column or row count one console dimension observation may declare.
pub const CONSOLE_DIMENSION_BOUND: u32 = 4096;

/// One declared console refusal condition of `GNT-46.5-console-terminal-observations`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleDiagnosticCode {
    /// A presented terminal observation fact lies outside its declared range.
    ObservationInconsistent,
}

impl ConsoleDiagnosticCode {
    /// Every declared code, in exact wire-name order.
    pub const ALL: [Self; 1] = [Self::ObservationInconsistent];

    /// Returns the registered diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservationInconsistent => "console-observation-inconsistent",
        }
    }
}

/// One typed refusal from the console terminal-observation model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsoleError {
    /// A presented dimension count lies outside its declared range.
    ObservationInconsistent {
        /// The presented fact's declared name.
        fact: &'static str,
        /// The observed count exactly as presented.
        observed: u32,
        /// The declared bound that fact admits.
        maximum: u32,
    },
}

impl ConsoleError {
    /// Returns the registered diagnostic code of this refusal.
    #[must_use]
    pub const fn code(&self) -> ConsoleDiagnosticCode {
        match self {
            Self::ObservationInconsistent { .. } => ConsoleDiagnosticCode::ObservationInconsistent,
        }
    }

    /// Returns the declared name of the presented fact.
    #[must_use]
    pub const fn fact(&self) -> &'static str {
        match self {
            Self::ObservationInconsistent { fact, .. } => fact,
        }
    }

    /// Returns the observed count exactly as presented.
    #[must_use]
    pub const fn observed(&self) -> u32 {
        match self {
            Self::ObservationInconsistent { observed, .. } => *observed,
        }
    }

    /// Returns the declared bound the fact admits.
    #[must_use]
    pub const fn maximum(&self) -> u32 {
        match self {
            Self::ObservationInconsistent { maximum, .. } => *maximum,
        }
    }
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservationInconsistent {
                fact,
                observed,
                maximum,
            } => write!(
                formatter,
                "the observed {fact} count {observed} is outside 1..={maximum}"
            ),
        }
    }
}

impl std::error::Error for ConsoleError {}

/// One admitted console dimension observation of `GNT-46.5-console-terminal-observations`:
/// a column count and a row count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleDimensions {
    columns: u32,
    rows: u32,
}

impl ConsoleDimensions {
    /// Admits one dimension observation whose two counts are inside the declared bound.
    ///
    /// A count of zero or a count beyond [`CONSOLE_DIMENSION_BOUND`] is refused under
    /// `console-observation-inconsistent`, naming the observed count and its declared bound,
    /// rather than clamped or defaulted.
    pub fn new(columns: u32, rows: u32) -> Result<Self, ConsoleError> {
        for (fact, observed) in [("column", columns), ("row", rows)] {
            if observed == 0 || observed > CONSOLE_DIMENSION_BOUND {
                return Err(ConsoleError::ObservationInconsistent {
                    fact,
                    observed,
                    maximum: CONSOLE_DIMENSION_BOUND,
                });
            }
        }
        Ok(Self { columns, rows })
    }

    /// Returns the observed column count.
    #[must_use]
    pub const fn columns(self) -> u32 {
        self.columns
    }

    /// Returns the observed row count.
    #[must_use]
    pub const fn rows(self) -> u32 {
        self.rows
    }
}

/// One declared console terminal report of `GNT-46.5-console-terminal-observations`.
///
/// A not-attached console publishes no dimension observation, and the [`Self::detection`] and
/// [`Self::dimensions`] accessors decide the observation from the report alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleTerminalReport {
    /// The console is attached to a terminal and publishes one dimension observation.
    Attached(ConsoleDimensions),
    /// The console is not attached to a terminal and publishes no dimension observation.
    NotAttached,
}

impl ConsoleTerminalReport {
    /// Returns the declared detection fact of this report.
    #[must_use]
    pub const fn detection(self) -> ConsoleDetection {
        match self {
            Self::Attached(_) => ConsoleDetection::Attached,
            Self::NotAttached => ConsoleDetection::NotAttached,
        }
    }

    /// Returns the dimension observation, when the console is attached.
    #[must_use]
    pub const fn dimensions(self) -> Option<ConsoleDimensions> {
        match self {
            Self::Attached(dimensions) => Some(dimensions),
            Self::NotAttached => None,
        }
    }
}

/// The declared semantic mode of every `std.console` item row.
pub const CONSOLE_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.console` item row.
pub const CONSOLE_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// One declared public module of `std.console` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleItemRow {
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public modules of `std.console`, in canonical name order.
///
/// The rows are declared by `GNT-46.1-console-modules-and-item-rows` alone; the family carries no
/// second vocabulary, no terminal handle, and no escape-sequence surface, and every row's
/// applicability is its owning package's application-mode applicability over the library and
/// binary targets. Canonical order is canonical name order: exactly the order
/// `StdPackage::items` publishes.
pub const CONSOLE_ITEMS: [ConsoleItemRow; 4] = [
    ConsoleItemRow {
        name: "std.console::control",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
            "GNT-46.6-console-operation-signatures",
            "GNT-46.7-console-requirement-groups",
            "GNT-46.8-console-authority-admission",
            "GNT-46.9-console-control-and-output-boundary",
        ],
    },
    ConsoleItemRow {
        name: "std.console::input",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
            "GNT-46.2-console-bounded-operations",
            "GNT-46.3-console-operation-recovery-and-accepted-input",
            "GNT-46.4-console-encoding-and-shutdown-settlement",
            "GNT-46.6-console-operation-signatures",
            "GNT-46.7-console-requirement-groups",
            "GNT-46.8-console-authority-admission",
        ],
    },
    ConsoleItemRow {
        name: "std.console::output",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
            "GNT-46.2-console-bounded-operations",
            "GNT-46.3-console-operation-recovery-and-accepted-input",
            "GNT-46.4-console-encoding-and-shutdown-settlement",
            "GNT-46.6-console-operation-signatures",
            "GNT-46.7-console-requirement-groups",
            "GNT-46.8-console-authority-admission",
            "GNT-46.9-console-control-and-output-boundary",
        ],
    },
    ConsoleItemRow {
        name: "std.console::terminal",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
            "GNT-46.5-console-terminal-observations",
            "GNT-46.6-console-operation-signatures",
            "GNT-46.7-console-requirement-groups",
        ],
    },
];

/// Declares the published item surface of `std.console` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and each item takes that package's declared modes
/// and targets, so an item is never applicable outside its own package's applicability
/// (`GNT-34.7-applicability-and-feature-granularity`). A second declaration of one item is refused
/// by the graph rather than merged.
pub fn declare_console_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Console.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_console_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            CONSOLE_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == CONSOLE_ITEMS.len() {
        let row = CONSOLE_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in CONSOLE_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.console` surface as exactly the four declared module rows.
///
/// The declared applicability must be exactly the application semantic mode over the library and
/// binary target kinds, no item outside the four declared rows may exist, and no row may be
/// missing; each violation is refused under its declared diagnostic rather than repaired.
pub fn admit_console_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Console.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_console_surface_package(graph, package)?;
    if CONSOLE_ITEMS
        .iter()
        .any(|row| package.item(row.name).is_none())
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.console item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_console_surface_package(
    graph: &StdGraph,
    package: &StdPackage,
) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(CONSOLE_SURFACE_MODES)
        || package
            .targets()
            .iter()
            .copied()
            .ne(CONSOLE_SURFACE_TARGETS)
    {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::UnsupportedApplicability,
            format!(
                "`{}` must declare exactly the application mode over the library and binary targets",
                package.name()
            ),
        ));
    }
    let owner = package.name();
    if graph.names().iter().any(|name| name.owner() == owner) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            format!("`{owner}` declares a name outside its four declared modules"),
        ));
    }
    let present = CONSOLE_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the four std.console modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != CONSOLE_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.console item surface is partially declared".to_owned(),
        ));
    }
    for row in CONSOLE_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(CONSOLE_SURFACE_MODES)
            || item.targets().iter().copied().ne(CONSOLE_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}

/// The declared version of every console operation identity
/// (`GNT-46.6-console-operation-signatures`).
pub const CONSOLE_SIGNATURE_VERSION: u32 = 1;

/// One declared receiver kind of a console signature
/// (`GNT-46.6-console-operation-signatures`).
///
/// A receiver kind is a declared property of a signature shape: it is not a host handle, a
/// descriptor, a capability, or a loan the console owns.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleReceiver {
    /// The Input receiver loan a console read takes.
    InputLoan,
    /// The Output receiver loan a console write or flush takes.
    OutputLoan,
    /// The observation receiver a terminal inspect takes.
    Observation,
    /// The control receiver a mode change takes.
    Control,
}

impl ConsoleReceiver {
    /// Every declared receiver kind, in canonical order.
    pub const ALL: [Self; 4] = [
        Self::InputLoan,
        Self::OutputLoan,
        Self::Observation,
        Self::Control,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::InputLoan => "input-receiver-loan",
            Self::OutputLoan => "output-receiver-loan",
            Self::Observation => "observation-receiver",
            Self::Control => "control-receiver",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|receiver| receiver.wire_name() == value)
    }
}

/// One declared result shape of a console signature
/// (`GNT-46.6-console-operation-signatures`).
///
/// A result shape is a declared spelling of the value a signature publishes: it is not a runtime
/// carrier, a boundary encoding, or a second payload vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleResultShape {
    /// A chunk of octets or a refusal.
    ChunkOrError,
    /// An accepted-prefix receipt or a refusal.
    AcceptedPrefixReceiptOrError,
    /// Unit or a refusal.
    UnitOrError,
    /// A terminal report or a refusal.
    TerminalReportOrError,
}

impl ConsoleResultShape {
    /// Every declared result shape, in canonical order.
    pub const ALL: [Self; 4] = [
        Self::ChunkOrError,
        Self::AcceptedPrefixReceiptOrError,
        Self::UnitOrError,
        Self::TerminalReportOrError,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ChunkOrError => "chunk-or-error",
            Self::AcceptedPrefixReceiptOrError => "accepted-prefix-receipt-or-error",
            Self::UnitOrError => "unit-or-error",
            Self::TerminalReportOrError => "terminal-report-or-error",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|shape| shape.wire_name() == value)
    }
}

/// One declared console operation signature
/// (`GNT-46.6-console-operation-signatures`).
///
/// The first three declared shapes bind to one operation of the
/// `GNT-46.2-console-bounded-operations` vocabulary; `inspect` and `set_mode` are declared
/// signatures of their module rows and are never members of that vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleSignature {
    /// `input::read(Input receiver loan, bounded request) -> chunk/error`.
    InputRead,
    /// `output::write(Output receiver loan, initialized octets) -> accepted-prefix receipt/error`.
    OutputWrite,
    /// `output::flush(Output receiver loan) -> Unit/error`.
    OutputFlush,
    /// `terminal::inspect(observation receiver) -> terminal report/error`.
    TerminalInspect,
    /// `control::set_mode(control receiver, typed echo/canonical-input flags) -> Unit/error`.
    ControlSetMode,
}

impl ConsoleSignature {
    /// Every declared signature, in canonical declaration order.
    pub const ALL: [Self; 5] = [
        Self::InputRead,
        Self::OutputWrite,
        Self::OutputFlush,
        Self::TerminalInspect,
        Self::ControlSetMode,
    ];

    /// Returns the exact declared operation spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::InputRead => "read",
            Self::OutputWrite => "write",
            Self::OutputFlush => "flush",
            Self::TerminalInspect => "inspect",
            Self::ControlSetMode => "set_mode",
        }
    }

    /// Returns the same exact operation spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact declared operation spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|signature| signature.wire_name() == value)
    }

    /// Returns the declared module that publishes this signature.
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::InputRead => "std.console::input",
            Self::OutputWrite | Self::OutputFlush => "std.console::output",
            Self::TerminalInspect => "std.console::terminal",
            Self::ControlSetMode => "std.console::control",
        }
    }

    /// Returns the declared exact operation identity of this signature.
    ///
    /// The declared spelling is `<module>::<operation>@<version>` with version
    /// [`CONSOLE_SIGNATURE_VERSION`].
    #[must_use]
    pub const fn identity(self) -> &'static str {
        match self {
            Self::InputRead => "std.console::input::read@1",
            Self::OutputWrite => "std.console::output::write@1",
            Self::OutputFlush => "std.console::output::flush@1",
            Self::TerminalInspect => "std.console::terminal::inspect@1",
            Self::ControlSetMode => "std.console::control::set_mode@1",
        }
    }

    /// Returns the declared receiver kind of this signature.
    #[must_use]
    pub const fn receiver(self) -> ConsoleReceiver {
        match self {
            Self::InputRead => ConsoleReceiver::InputLoan,
            Self::OutputWrite | Self::OutputFlush => ConsoleReceiver::OutputLoan,
            Self::TerminalInspect => ConsoleReceiver::Observation,
            Self::ControlSetMode => ConsoleReceiver::Control,
        }
    }

    /// Returns the declared result shape of this signature.
    #[must_use]
    pub const fn result(self) -> ConsoleResultShape {
        match self {
            Self::InputRead => ConsoleResultShape::ChunkOrError,
            Self::OutputWrite => ConsoleResultShape::AcceptedPrefixReceiptOrError,
            Self::OutputFlush | Self::ControlSetMode => ConsoleResultShape::UnitOrError,
            Self::TerminalInspect => ConsoleResultShape::TerminalReportOrError,
        }
    }

    /// Returns the declared recovery class of this signature.
    ///
    /// A read and a write are `non_idempotent`, a flush and a mode change are `idempotent`, and an
    /// inspect is `read_only`. The `read_only` class belongs to the inspect signature only; no
    /// operation of the `ConsoleOperation` vocabulary is `read_only`, and
    /// `GNT-46.3-console-operation-recovery-and-accepted-input` continues to state exactly that.
    #[must_use]
    pub const fn declared_recovery_class(self) -> RecoveryClass {
        match self {
            Self::InputRead | Self::OutputWrite => RecoveryClass::NonIdempotent,
            Self::OutputFlush | Self::ControlSetMode => RecoveryClass::Idempotent,
            Self::TerminalInspect => RecoveryClass::ReadOnly,
        }
    }

    /// Returns the declared operation of the `ConsoleOperation` vocabulary this signature binds.
    ///
    /// An inspect and a set-mode bind no operation of that vocabulary and publish `None`.
    #[must_use]
    pub const fn console_operation(self) -> Option<ConsoleOperation> {
        match self {
            Self::InputRead => Some(ConsoleOperation::Read),
            Self::OutputWrite => Some(ConsoleOperation::Write),
            Self::OutputFlush => Some(ConsoleOperation::Flush),
            Self::TerminalInspect | Self::ControlSetMode => None,
        }
    }

    /// Returns whether this signature declares the two typed control flags.
    #[must_use]
    pub const fn declares_control_flags(self) -> bool {
        matches!(self, Self::ControlSetMode)
    }

    /// Returns whether this signature consumes one admitted `std.io` request.
    #[must_use]
    pub const fn consumes_request(self) -> bool {
        matches!(self, Self::InputRead | Self::OutputWrite)
    }
}

/// The declared signatures the `input` requirement group governs.
const INPUT_GROUP_SIGNATURES: &[ConsoleSignature] = &[ConsoleSignature::InputRead];

/// The declared signatures the `output-flush` requirement group governs.
const OUTPUT_GROUP_SIGNATURES: &[ConsoleSignature] =
    &[ConsoleSignature::OutputWrite, ConsoleSignature::OutputFlush];

/// The declared signatures the `observation` requirement group governs.
const OBSERVATION_GROUP_SIGNATURES: &[ConsoleSignature] = &[ConsoleSignature::TerminalInspect];

/// The declared signatures the `control` requirement group governs.
const CONTROL_GROUP_SIGNATURES: &[ConsoleSignature] = &[ConsoleSignature::ControlSetMode];

/// One declared console requirement group
/// (`GNT-46.7-console-requirement-groups`).
///
/// The four groups are four separately granted groups. No group implies another, so an admitted
/// requirement of one group never satisfies a requirement of another and a grant of one group is
/// never read as a grant of another.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleRequirementGroup {
    /// The group governing `std.console::input::read@1`.
    Input,
    /// The group governing `std.console::output::write@1` and `std.console::output::flush@1`.
    OutputFlush,
    /// The group governing `std.console::terminal::inspect@1`.
    Observation,
    /// The group governing `std.console::control::set_mode@1`.
    Control,
}

impl ConsoleRequirementGroup {
    /// Every declared group, in canonical order.
    pub const ALL: [Self; 4] = [
        Self::Input,
        Self::OutputFlush,
        Self::Observation,
        Self::Control,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::OutputFlush => "output-flush",
            Self::Observation => "observation",
            Self::Control => "control",
        }
    }

    /// Returns the same exact portable spelling as [`Self::wire_name`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.wire_name()
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|group| group.wire_name() == value)
    }

    /// Returns the declared signatures this group governs, in canonical declaration order.
    #[must_use]
    pub const fn signatures(self) -> &'static [ConsoleSignature] {
        match self {
            Self::Input => INPUT_GROUP_SIGNATURES,
            Self::OutputFlush => OUTPUT_GROUP_SIGNATURES,
            Self::Observation => OBSERVATION_GROUP_SIGNATURES,
            Self::Control => CONTROL_GROUP_SIGNATURES,
        }
    }

    /// Returns whether this group implies authority over another declared group.
    ///
    /// The answer is `false` for every ordered pair of declared groups, including a group and
    /// itself: the four groups are separately granted and no ordering of them is an authority
    /// chain.
    #[must_use]
    pub const fn implies_authority_over(self, _other: Self) -> bool {
        false
    }
}

/// One declared console authority refusal condition
/// (`GNT-46.6-console-operation-signatures` through
/// `GNT-46.9-console-control-and-output-boundary`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConsoleAuthorityDiagnosticCode {
    /// A presented signature surface is not the declared surface.
    SignatureUndeclared,
    /// A presented requirement group does not carry the declared identities.
    RequirementGroupInconsistent,
    /// A declared signature was called without an injected grant of its group.
    AuthorityMissing,
    /// A presented grant was not issued for that requester and group.
    AuthorityForged,
    /// An access was presented as an ambient numeric descriptor.
    AmbientDescriptor,
    /// Control-bearing output reached an attached terminal without control authority.
    ControlBearingOutputRefused,
    /// An output was presented to a sink kind this section does not declare.
    SafeOutputUnsupported,
}

impl ConsoleAuthorityDiagnosticCode {
    /// Every declared code, in exact declaration order.
    pub const ALL: [Self; 7] = [
        Self::SignatureUndeclared,
        Self::RequirementGroupInconsistent,
        Self::AuthorityMissing,
        Self::AuthorityForged,
        Self::AmbientDescriptor,
        Self::ControlBearingOutputRefused,
        Self::SafeOutputUnsupported,
    ];

    /// Returns the registered diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignatureUndeclared => "console-signature-undeclared",
            Self::RequirementGroupInconsistent => "console-requirement-group-inconsistent",
            Self::AuthorityMissing => "console-authority-missing",
            Self::AuthorityForged => "console-authority-forged",
            Self::AmbientDescriptor => "console-authority-ambient-descriptor",
            Self::ControlBearingOutputRefused => "console-control-bearing-output-refused",
            Self::SafeOutputUnsupported => "console-safe-output-unsupported",
        }
    }
}

/// One typed refusal from the console signature, group, and authority model.
///
/// Every variant names exactly one declared diagnostic and carries no capability, handle,
/// descriptor number as authority, sanitized octet, or rewritten outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsoleAuthorityError {
    /// A presented signature surface is not exactly the five declared signatures.
    SignatureUndeclared {
        /// The observed operation identity, or `none` when the surface is incomplete.
        observed: String,
        /// The declared operation identity at that position, or `none` when the surface is extra.
        declared: String,
    },
    /// A presented requirement group does not carry the declared identities.
    RequirementGroupInconsistent {
        /// The observed identity.
        observed: String,
        /// The declared identity.
        declared: String,
    },
    /// A declared signature was called without an injected grant of its group.
    AuthorityMissing {
        /// The group whose grant is absent.
        group: ConsoleRequirementGroup,
    },
    /// A presented grant was not issued by the injection for that requester and group.
    AuthorityForged {
        /// The group the presented grant names.
        group: ConsoleRequirementGroup,
        /// The requester the presented grant names.
        requester: &'static str,
        /// The grantor the presented grant names.
        grantor: &'static str,
    },
    /// An access was presented as an ambient numeric descriptor.
    AmbientDescriptor {
        /// The presented descriptor, exactly as presented.
        descriptor: i32,
    },
    /// Control-bearing output reached an attached terminal without control authority.
    ControlBearingOutputRefused {
        /// The presented octets, unchanged: no octet is stripped, replaced, or sanitized.
        preserved_octets: Vec<u8>,
    },
    /// An output was presented to a sink kind this section does not declare.
    SafeOutputUnsupported {
        /// The presented sink spelling.
        sink: &'static str,
    },
}

impl ConsoleAuthorityError {
    /// Returns the registered diagnostic code of this refusal.
    #[must_use]
    pub const fn code(&self) -> ConsoleAuthorityDiagnosticCode {
        match self {
            Self::SignatureUndeclared { .. } => ConsoleAuthorityDiagnosticCode::SignatureUndeclared,
            Self::RequirementGroupInconsistent { .. } => {
                ConsoleAuthorityDiagnosticCode::RequirementGroupInconsistent
            }
            Self::AuthorityMissing { .. } => ConsoleAuthorityDiagnosticCode::AuthorityMissing,
            Self::AuthorityForged { .. } => ConsoleAuthorityDiagnosticCode::AuthorityForged,
            Self::AmbientDescriptor { .. } => ConsoleAuthorityDiagnosticCode::AmbientDescriptor,
            Self::ControlBearingOutputRefused { .. } => {
                ConsoleAuthorityDiagnosticCode::ControlBearingOutputRefused
            }
            Self::SafeOutputUnsupported { .. } => {
                ConsoleAuthorityDiagnosticCode::SafeOutputUnsupported
            }
        }
    }

    /// Returns the requirement group this refusal names, when it names one.
    #[must_use]
    pub const fn group(&self) -> Option<ConsoleRequirementGroup> {
        match self {
            Self::AuthorityMissing { group } | Self::AuthorityForged { group, .. } => Some(*group),
            Self::SignatureUndeclared { .. }
            | Self::RequirementGroupInconsistent { .. }
            | Self::AmbientDescriptor { .. }
            | Self::ControlBearingOutputRefused { .. }
            | Self::SafeOutputUnsupported { .. } => None,
        }
    }

    /// Returns the observed identity this refusal names, when it names one.
    #[must_use]
    pub fn observed(&self) -> Option<&str> {
        match self {
            Self::SignatureUndeclared { observed, .. }
            | Self::RequirementGroupInconsistent { observed, .. } => Some(observed.as_str()),
            Self::AuthorityMissing { .. }
            | Self::AuthorityForged { .. }
            | Self::AmbientDescriptor { .. }
            | Self::ControlBearingOutputRefused { .. }
            | Self::SafeOutputUnsupported { .. } => None,
        }
    }

    /// Returns the declared identity this refusal names, when it names one.
    #[must_use]
    pub fn declared(&self) -> Option<&str> {
        match self {
            Self::SignatureUndeclared { declared, .. }
            | Self::RequirementGroupInconsistent { declared, .. } => Some(declared.as_str()),
            Self::AuthorityMissing { .. }
            | Self::AuthorityForged { .. }
            | Self::AmbientDescriptor { .. }
            | Self::ControlBearingOutputRefused { .. }
            | Self::SafeOutputUnsupported { .. } => None,
        }
    }

    /// Returns the presented descriptor of an ambient-descriptor refusal.
    #[must_use]
    pub const fn descriptor(&self) -> Option<i32> {
        match self {
            Self::AmbientDescriptor { descriptor } => Some(*descriptor),
            Self::SignatureUndeclared { .. }
            | Self::RequirementGroupInconsistent { .. }
            | Self::AuthorityMissing { .. }
            | Self::AuthorityForged { .. }
            | Self::ControlBearingOutputRefused { .. }
            | Self::SafeOutputUnsupported { .. } => None,
        }
    }

    /// Returns the preserved octets of a control-bearing refusal, unchanged.
    #[must_use]
    pub fn preserved_octets(&self) -> Option<&[u8]> {
        match self {
            Self::ControlBearingOutputRefused { preserved_octets } => Some(preserved_octets),
            Self::SignatureUndeclared { .. }
            | Self::RequirementGroupInconsistent { .. }
            | Self::AuthorityMissing { .. }
            | Self::AuthorityForged { .. }
            | Self::AmbientDescriptor { .. }
            | Self::SafeOutputUnsupported { .. } => None,
        }
    }
}

impl fmt::Display for ConsoleAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureUndeclared { observed, declared } => write!(
                formatter,
                "the observed console signature {observed} is not the declared signature {declared}"
            ),
            Self::RequirementGroupInconsistent { observed, declared } => write!(
                formatter,
                "the observed console requirement identity {observed} is not the declared {declared}"
            ),
            Self::AuthorityMissing { group } => write!(
                formatter,
                "no console access is injected for the {} requirement group",
                group.wire_name()
            ),
            Self::AuthorityForged {
                group,
                requester,
                grantor,
            } => write!(
                formatter,
                "the presented {} grant for {requester} was not issued by {grantor}",
                group.wire_name()
            ),
            Self::AmbientDescriptor { descriptor } => write!(
                formatter,
                "the ambient descriptor {descriptor} is not a console access identity"
            ),
            Self::ControlBearingOutputRefused { preserved_octets } => write!(
                formatter,
                "control-bearing output of {} octets was refused byte-preservingly",
                preserved_octets.len()
            ),
            Self::SafeOutputUnsupported { sink } => write!(
                formatter,
                "the console output sink {sink} is not a declared target"
            ),
        }
    }
}

impl std::error::Error for ConsoleAuthorityError {}

/// One typed refusal from one admitted console call of this section.
///
/// A call admits its presented access first and the one admitted `std.io` request it consumes
/// second, so a refusal names exactly one vocabulary: the console authority vocabulary of
/// `GNT-46.8-console-authority-admission` and the output boundary of
/// `GNT-46.9-console-control-and-output-boundary`, or the request vocabulary of one of the two
/// clauses that own it: `GNT-45.1-bounded-one-call-io-contract`, which owns `io-request-bound`,
/// `io-request-kind`, and `io-progress-inapplicable`, and `GNT-45.3-io-progress-derivation`, which
/// owns `io-observation-inconsistent` and `io-outcome-request-mismatch`. A request refusal stays
/// the Section 45 refusal it is: this section mints no console diagnostic for it, restates no
/// Section 45 condition, and adds no second refusal code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsoleCallError {
    /// The presented access, requirement group, or output target was refused by this section.
    Authority(ConsoleAuthorityError),
    /// The presented `std.io` request was refused by `GNT-45.1-bounded-one-call-io-contract` or
    /// `GNT-45.3-io-progress-derivation`.
    Request(IoError),
}

impl ConsoleCallError {
    /// Returns the console authority refusal, when this section owns the refusal.
    #[must_use]
    pub const fn authority(&self) -> Option<&ConsoleAuthorityError> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Request(_) => None,
        }
    }

    /// Returns the `std.io` request refusal, when Section 45 owns the refusal.
    #[must_use]
    pub const fn request(&self) -> Option<&IoError> {
        match self {
            Self::Authority(_) => None,
            Self::Request(error) => Some(error),
        }
    }

    /// Returns the console diagnostic code of this refusal, when this section owns it.
    #[must_use]
    pub const fn console_code(&self) -> Option<ConsoleAuthorityDiagnosticCode> {
        match self {
            Self::Authority(error) => Some(error.code()),
            Self::Request(_) => None,
        }
    }

    /// Returns the Section 45 diagnostic code of this refusal, when Section 45 owns it.
    #[must_use]
    pub fn io_code(&self) -> Option<IoDiagnosticCode> {
        match self {
            Self::Authority(_) => None,
            Self::Request(error) => Some(error.code()),
        }
    }
}

impl From<ConsoleAuthorityError> for ConsoleCallError {
    fn from(error: ConsoleAuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<IoError> for ConsoleCallError {
    fn from(error: IoError) -> Self {
        Self::Request(error)
    }
}

impl fmt::Display for ConsoleCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Request(error) => write!(
                formatter,
                "the presented std.io request was refused under {}",
                error.code().wire_name()
            ),
        }
    }
}

impl std::error::Error for ConsoleCallError {}

/// One console access grant for one requirement group
/// (`GNT-46.8-console-authority-admission`).
///
/// A grant names exactly its group, its requester, and its grantor. It is not a descriptor, a
/// numeric handle, or a capability instance, and it carries no right beyond the group it names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleGrant {
    group: ConsoleRequirementGroup,
    requester: &'static str,
    grantor: &'static str,
}

impl ConsoleGrant {
    /// Returns one grant naming its group, its requester, and its grantor.
    #[must_use]
    pub const fn new(
        group: ConsoleRequirementGroup,
        requester: &'static str,
        grantor: &'static str,
    ) -> Self {
        Self {
            group,
            requester,
            grantor,
        }
    }

    /// Returns the requirement group this grant names.
    #[must_use]
    pub const fn group(self) -> ConsoleRequirementGroup {
        self.group
    }

    /// Returns the requester this grant names.
    #[must_use]
    pub const fn requester(self) -> &'static str {
        self.requester
    }

    /// Returns the grantor this grant names.
    #[must_use]
    pub const fn grantor(self) -> &'static str {
        self.grantor
    }
}

/// The launch-injected access set of one run
/// (`GNT-46.8-console-authority-admission`).
///
/// The injection is the issued set the console compares a presented grant against. It carries no
/// descriptor, numeric handle, terminal instance, or capability generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleAccessInjection {
    grantor: &'static str,
    grants: Vec<ConsoleGrant>,
}

impl ConsoleAccessInjection {
    /// Returns the access set one launch injects.
    ///
    /// This is the only constructor: access is injected by the launch and is never reconstructed
    /// from an ambient numeric descriptor, a standard descriptor number, a process handle, or a
    /// device path.
    #[must_use]
    pub fn from_launch(grantor: &'static str, grants: Vec<ConsoleGrant>) -> Self {
        Self { grantor, grants }
    }

    /// Returns the grantor of this injection.
    #[must_use]
    pub const fn grantor(&self) -> &'static str {
        self.grantor
    }

    /// Returns the issued grants, in injected order.
    #[must_use]
    pub fn grants(&self) -> &[ConsoleGrant] {
        &self.grants
    }

    /// Returns whether this injection issues any grant of one requirement group.
    #[must_use]
    pub fn grants_group(&self, group: ConsoleRequirementGroup) -> bool {
        self.grants.iter().any(|grant| grant.group == group)
    }

    /// Returns the issued control grant of one requester, when the injection issues one.
    #[must_use]
    pub fn control_grant_for(&self, requester: &str) -> Option<ConsoleGrant> {
        self.grants.iter().copied().find(|grant| {
            grant.group == ConsoleRequirementGroup::Control && grant.requester == requester
        })
    }

    /// Admits one presented grant as exactly an issued grant of this injection.
    ///
    /// A presented grant that the injection did not issue for that requester and that group -- a
    /// grant of another grantor, another requester, or another group, or a grant that no group of
    /// the injected set names -- is refused as forged, and is never repaired, widened, or merged
    /// with an issued grant.
    pub fn admit(&self, presented: &ConsoleGrant) -> Result<(), ConsoleAuthorityError> {
        if self.grants.iter().any(|grant| grant == presented) {
            return Ok(());
        }
        Err(ConsoleAuthorityError::AuthorityForged {
            group: presented.group,
            requester: presented.requester,
            grantor: presented.grantor,
        })
    }

    /// Admits the presented grant of one declared call whose signature requires `required`.
    ///
    /// The call names the requirement group of the signature it calls, and the presented grant
    /// must be exactly an issued grant of that group. The refusal precedence is the one
    /// `GNT-46.8-console-authority-admission` declares:
    ///
    /// 1. the required group carries no injected grant, so the call is refused under
    ///    `console-authority-missing`, naming the required group;
    /// 2. the presented grant names another group, so the call is refused under
    ///    `console-requirement-group-inconsistent`, naming the presented group and the required
    ///    group;
    /// 3. the presented grant was not issued for that requester and that group, so the call is
    ///    refused under `console-authority-forged`, naming the group, the requester, and the
    ///    grantor.
    ///
    /// Every step refuses before the call consumes an input cursor, delivers an octet, or
    /// publishes a progress observation, and no refusal is repaired, widened, or merged with an
    /// issued grant.
    pub fn admit_call(
        &self,
        required: ConsoleRequirementGroup,
        presented: &ConsoleGrant,
    ) -> Result<(), ConsoleAuthorityError> {
        if !self.grants_group(required) {
            return Err(ConsoleAuthorityError::AuthorityMissing { group: required });
        }
        if presented.group != required {
            return Err(ConsoleAuthorityError::RequirementGroupInconsistent {
                observed: presented.group.wire_name().to_owned(),
                declared: required.wire_name().to_owned(),
            });
        }
        self.admit(presented)
    }
}

/// One console access identity as presented to one declared signature
/// (`GNT-46.8-console-authority-admission`).
///
/// The identity is admitted for the one requirement group of the signature it is presented to, so
/// an identity of another group is never absorbed into the required group and an ambient numeric
/// descriptor is never an access identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleAccessIdentity {
    /// An access identity issued by the launch injection.
    Injected(ConsoleGrant),
    /// An ambient numeric descriptor presented as access, which is never an access identity.
    AmbientDescriptor(i32),
}

impl ConsoleAccessIdentity {
    /// Admits the presented identity as an issued grant of the required group.
    ///
    /// The required group is the group of the signature the identity is presented to, and it is
    /// the group the refusal precedence of [`ConsoleAccessInjection::admit_call`] decides over. An
    /// ambient numeric descriptor is not an access identity and is refused before any group is
    /// consulted.
    pub fn admit(
        self,
        injection: &ConsoleAccessInjection,
        required: ConsoleRequirementGroup,
    ) -> Result<ConsoleGrant, ConsoleAuthorityError> {
        match self {
            Self::Injected(grant) => {
                injection.admit_call(required, &grant)?;
                Ok(grant)
            }
            Self::AmbientDescriptor(descriptor) => {
                Err(ConsoleAuthorityError::AmbientDescriptor { descriptor })
            }
        }
    }
}

/// The two declared typed control flags of the `control::set_mode` signature
/// (`GNT-46.6-console-operation-signatures`).
///
/// The pair is typed and closed: it carries no raw mode word, numeric mask, ranking, and no
/// platform device convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleControlFlags {
    echo: bool,
    canonical_input: bool,
}

impl ConsoleControlFlags {
    /// The exact declared flag names, in canonical order.
    pub const DECLARED_FLAGS: [&'static str; 2] = ["echo", "canonical-input"];

    /// Returns the two typed flag values one mode change presents.
    #[must_use]
    pub const fn new(echo: bool, canonical_input: bool) -> Self {
        Self {
            echo,
            canonical_input,
        }
    }

    /// Returns the declared `echo` flag value.
    #[must_use]
    pub const fn echo(self) -> bool {
        self.echo
    }

    /// Returns the declared `canonical-input` flag value.
    #[must_use]
    pub const fn canonical_input(self) -> bool {
        self.canonical_input
    }
}

/// The declared control octet: the escape octet
/// (`GNT-46.9-console-control-and-output-boundary`).
pub const CONSOLE_CONTROL_OCTET: u8 = 0x1b;

/// Returns whether the presented octets are control-bearing.
///
/// The decision is over the presented octets alone: it declares no control-sequence grammar, no
/// escape parsing, and no statement about what a terminal would do with the octets.
#[must_use]
pub fn console_octets_carry_control(octets: &[u8]) -> bool {
    octets.contains(&CONSOLE_CONTROL_OCTET)
}

/// One declared console output target
/// (`GNT-46.9-console-control-and-output-boundary`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleOutputTarget {
    /// A redirected or otherwise non-controlling sink: the first declared output target.
    RedirectedNonControlling,
    /// An attached terminal.
    AttachedTerminal,
    /// A sink kind this section does not declare.
    Unsupported(&'static str),
}

impl ConsoleOutputTarget {
    /// Returns whether this target is one of the two declared targets.
    #[must_use]
    pub const fn is_declared(self) -> bool {
        matches!(
            self,
            Self::RedirectedNonControlling | Self::AttachedTerminal
        )
    }
}

/// The accepted-prefix receipt of one admitted console write.
///
/// The receipt counts the accepted octets of the one admitted request the call consumed and
/// publishes no character, scalar, or display-column count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleWriteReceipt {
    accepted_prefix: usize,
}

impl ConsoleWriteReceipt {
    /// Returns the count of accepted octets.
    #[must_use]
    pub const fn accepted_prefix(self) -> usize {
        self.accepted_prefix
    }
}

/// Admits one declared `output::write` call over its grant, request, target, and octets.
///
/// The declared signature is `std.console::output::write@1` of the `output-flush` requirement
/// group, so the presented grant must be an issued grant of that group, and the call consumes
/// exactly one admitted request of `GNT-45.1-bounded-one-call-io-contract` whose declared
/// quantity is the presented octet count. A request Section 45 refuses is refused here under the
/// same Section 45 code: [`IoRequest::write`] already refuses a zero quantity and a quantity
/// above [`crate::io::IO_REQUEST_OCTET_BOUND`], and this call refuses a request of another
/// operation kind or a request whose declared quantity is not the presented octet count. An
/// unsupported sink is refused even for octets that carry no control octet, and control-bearing
/// octets reach an attached terminal only under an injected grant of the control group, otherwise
/// the refusal publishes the presented octets unchanged.
pub fn admit_console_write(
    injection: &ConsoleAccessInjection,
    presented: &ConsoleGrant,
    request: &IoRequest,
    target: ConsoleOutputTarget,
    octets: &[u8],
) -> Result<ConsoleWriteReceipt, ConsoleCallError> {
    injection.admit_call(ConsoleRequirementGroup::OutputFlush, presented)?;
    admit_console_write_request(request, octets)?;
    match target {
        ConsoleOutputTarget::Unsupported(sink) => {
            Err(ConsoleAuthorityError::SafeOutputUnsupported { sink }.into())
        }
        ConsoleOutputTarget::RedirectedNonControlling => Ok(ConsoleWriteReceipt {
            accepted_prefix: octets.len(),
        }),
        ConsoleOutputTarget::AttachedTerminal => {
            if !console_octets_carry_control(octets)
                || injection.control_grant_for(presented.requester).is_some()
            {
                return Ok(ConsoleWriteReceipt {
                    accepted_prefix: octets.len(),
                });
            }
            Err(ConsoleAuthorityError::ControlBearingOutputRefused {
                preserved_octets: octets.to_vec(),
            }
            .into())
        }
    }
}

/// Admits the one `std.io` request an `output::write` call consumes.
///
/// The request is one request the `GNT-45.1-bounded-one-call-io-contract` already admitted, so a
/// zero quantity and a quantity above [`crate::io::IO_REQUEST_OCTET_BOUND`] never reach this
/// decision: [`IoRequest::write`] refuses both under `io-request-bound` before the call exists.
/// What this decision settles is whether the admitted request is the one the presented octets
/// declare. A request of another operation kind is refused under `io-outcome-request-mismatch`,
/// owned by `GNT-45.3-io-progress-derivation`, naming the operation, and a request whose declared
/// quantity is not the presented octet count is refused under the same code naming the `provided`
/// fact, so a console write never delivers octets its admitted request did not declare and never
/// admits a request it does not deliver.
fn admit_console_write_request(request: &IoRequest, octets: &[u8]) -> Result<(), IoError> {
    if request.operation() != IoOperation::Write {
        return Err(IoError::RequestMismatch {
            operation: request.operation(),
            fact: "operation",
        });
    }
    if octets.len() as u128 != u128::from(request.quantity()) {
        return Err(IoError::RequestMismatch {
            operation: IoOperation::Write,
            fact: "provided",
        });
    }
    Ok(())
}

/// One declared flush outcome of the `output::flush` signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleFlushOutcome {
    /// The final flush completed.
    Flushed,
    /// The final flush failed.
    Failed,
}

impl ConsoleFlushOutcome {
    /// Returns whether this outcome is a failure.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// The settlement of one grantor-owned final flush and shutdown
/// (`GNT-46.8-console-authority-admission`).
///
/// The settlement publishes the flush outcome and nothing else. The task outcome is owned outside
/// this model, so the settlement cannot rewrite it, and the settlement does not represent that
/// outcome, report it, or substitute for it: a failed flush never rewrites the fixed task
/// outcome, and no settlement publishes a second task outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleShutdownSettlement {
    flush: ConsoleFlushOutcome,
}

impl ConsoleShutdownSettlement {
    /// Returns the settlement of one final flush.
    #[must_use]
    pub const fn settle(flush: ConsoleFlushOutcome) -> Self {
        Self { flush }
    }

    /// Returns the flush outcome.
    #[must_use]
    pub const fn flush(self) -> ConsoleFlushOutcome {
        self.flush
    }

    /// Returns whether the final flush failed.
    ///
    /// The task outcome is externally owned and is not represented by this settlement.
    #[must_use]
    pub const fn flush_failed(self) -> bool {
        self.flush.is_failure()
    }

    /// Returns whether this settlement rewrote the externally owned task outcome: never.
    ///
    /// The settlement does not carry that outcome, so this accessor publishes the non-rewrite rule
    /// alone and no settlement report of the task outcome.
    #[must_use]
    pub const fn task_outcome_rewritten(self) -> bool {
        false
    }
}

/// Admits one declared `control::set_mode` call over its grant and typed flags.
///
/// The declared signature is `std.console::control::set_mode@1` of the `control` requirement
/// group, so a set-mode requires an injected grant of that group under the refusal precedence of
/// [`ConsoleAccessInjection::admit_call`]. The two typed flags are values and are never read as a
/// capability or as terminal-control authority over any other call.
pub fn admit_console_set_mode(
    injection: &ConsoleAccessInjection,
    presented: &ConsoleGrant,
    _flags: ConsoleControlFlags,
) -> Result<(), ConsoleAuthorityError> {
    injection.admit_call(ConsoleRequirementGroup::Control, presented)
}

/// Declares exactly the five console operation signatures of
/// `GNT-46.6-console-operation-signatures`.
#[must_use]
pub fn declare_console_signatures() -> [ConsoleSignature; 5] {
    ConsoleSignature::ALL
}

/// Admits a presented signature surface as exactly the five declared signatures.
///
/// A missing, partial, extra, duplicated, reordered, or retyped surface is refused under
/// `console-signature-undeclared`, naming the observed identity and the declared identity, rather
/// than repaired, completed, or substituted.
pub fn admit_console_signatures(
    presented: &[ConsoleSignature],
) -> Result<(), ConsoleAuthorityError> {
    for (index, declared) in ConsoleSignature::ALL.into_iter().enumerate() {
        match presented.get(index) {
            Some(observed) if *observed == declared => {}
            Some(observed) => {
                return Err(ConsoleAuthorityError::SignatureUndeclared {
                    observed: observed.identity().to_owned(),
                    declared: declared.identity().to_owned(),
                });
            }
            None => {
                return Err(ConsoleAuthorityError::SignatureUndeclared {
                    observed: "none".to_owned(),
                    declared: declared.identity().to_owned(),
                });
            }
        }
    }
    if let Some(extra) = presented.get(ConsoleSignature::ALL.len()) {
        return Err(ConsoleAuthorityError::SignatureUndeclared {
            observed: extra.identity().to_owned(),
            declared: "none".to_owned(),
        });
    }
    Ok(())
}

/// Declares exactly the four console requirement groups of
/// `GNT-46.7-console-requirement-groups`.
#[must_use]
pub fn declare_console_requirement_groups() -> [ConsoleRequirementGroup; 4] {
    ConsoleRequirementGroup::ALL
}

/// Admits a presented group surface as exactly the four declared groups.
///
/// The surface must carry the declared identities exactly once each and in canonical order; a
/// violation is refused under `console-requirement-group-inconsistent` rather than widened.
pub fn admit_console_requirement_groups(
    presented: &[ConsoleRequirementGroup],
) -> Result<(), ConsoleAuthorityError> {
    console_requirement_identities_are_distinct()?;
    for (index, declared) in ConsoleRequirementGroup::ALL.into_iter().enumerate() {
        match presented.get(index) {
            Some(observed) if *observed == declared => {}
            Some(observed) => {
                return Err(ConsoleAuthorityError::RequirementGroupInconsistent {
                    observed: observed.wire_name().to_owned(),
                    declared: declared.wire_name().to_owned(),
                });
            }
            None => {
                return Err(ConsoleAuthorityError::RequirementGroupInconsistent {
                    observed: "none".to_owned(),
                    declared: declared.wire_name().to_owned(),
                });
            }
        }
    }
    if let Some(extra) = presented.get(ConsoleRequirementGroup::ALL.len()) {
        return Err(ConsoleAuthorityError::RequirementGroupInconsistent {
            observed: extra.wire_name().to_owned(),
            declared: "none".to_owned(),
        });
    }
    Ok(())
}

/// Verifies every declared operation identity belongs to exactly one declared group.
///
/// The five declared identities are distinct, and no identity is governed by two groups or
/// governed by none.
fn console_requirement_identities_are_distinct() -> Result<(), ConsoleAuthorityError> {
    let mut seen: Vec<&str> = Vec::new();
    for group in ConsoleRequirementGroup::ALL {
        for signature in group.signatures() {
            if seen.contains(&signature.identity()) {
                return Err(ConsoleAuthorityError::RequirementGroupInconsistent {
                    observed: signature.identity().to_owned(),
                    declared: "one group per operation identity".to_owned(),
                });
            }
            seen.push(signature.identity());
        }
    }
    for declared in ConsoleSignature::ALL {
        if !seen.contains(&declared.identity()) {
            return Err(ConsoleAuthorityError::RequirementGroupInconsistent {
                observed: "none".to_owned(),
                declared: declared.identity().to_owned(),
            });
        }
    }
    Ok(())
}
