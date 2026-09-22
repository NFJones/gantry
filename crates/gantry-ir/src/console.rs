//! Declared `std.console` surface model for `SPEC.md` Section 46.
//!
//! This module publishes the canonical module and item rows of the `std.console` family and their
//! exact applicability. It is not a terminal, a descriptor, an adapter, a capability, or a
//! renderer, and it performs no I/O: every decision is a deterministic function of the declared
//! standard-library graph it is handed.

use std::fmt;

use crate::generated::RecoveryClass;
use crate::io::IoOperation;
use crate::operation::ProgressObservation;
use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 46 clauses implemented by this pure model, in declaration order.
pub const CONSOLE_CLAUSES: [&str; 6] = [
    "GNT-46.0-console-foundation-scope",
    "GNT-46.1-console-modules-and-item-rows",
    "GNT-46.2-console-bounded-operations",
    "GNT-46.3-console-operation-recovery-and-accepted-input",
    "GNT-46.4-console-encoding-and-shutdown-settlement",
    "GNT-46.5-console-terminal-observations",
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
