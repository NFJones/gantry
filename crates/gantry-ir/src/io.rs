//! Pure common-I/O contract model for `SPEC.md` Section 45.
//!
//! This module publishes the declared operation vocabulary and the versioned one-call request
//! contract of `std.io` with its declared finite octet bound and its progress sets. It is not a
//! runtime reader, writer, or seek handle, an adapter, a scheduler, or a buffer, and it performs
//! no I/O: every decision is a deterministic function of explicit inputs. The module also
//! publishes the declared backpressure fact of `GNT-45.4-io-backpressure-fact`.

use crate::operation::ProgressObservation;
use crate::package::TargetKind;
use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdPackage, StdlibDiagnosticCode,
    StdlibError,
};
use gantry_core::mode::SemanticMode;

/// The Section 45 clauses implemented by this pure model, in declaration order.
pub const IO_CLAUSES: [&str; 5] = [
    "GNT-45.0-common-io-foundation-scope",
    "GNT-45.1-bounded-one-call-io-contract",
    "GNT-45.2-standard-io-modules-and-item-rows",
    "GNT-45.3-io-progress-derivation",
    "GNT-45.4-io-backpressure-fact",
];

/// The declared one-call request-contract version of `GNT-45.1-bounded-one-call-io-contract`.
pub const IO_CONTRACT_VERSION: u64 = 1;

/// The declared semantic mode of every `std.io` item row.
pub const IO_SURFACE_MODES: [SemanticMode; 1] = [SemanticMode::Application];

/// The declared target kinds of every `std.io` item row.
pub const IO_SURFACE_TARGETS: [TargetKind; 2] = [TargetKind::Library, TargetKind::Binary];

/// The greatest octet count one read or write request may ask for.
///
/// The declared bound is a semantic limit of the one-call contract alone: it is not a quota, a
/// resource-accounting contract, a work limit, or a cancellation safe point.
pub const IO_REQUEST_OCTET_BOUND: u64 = 1_048_576;

/// One declared operation kind of the one-call I/O contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoOperation {
    /// One bounded read request.
    Read,
    /// One seek request.
    Seek,
    /// One bounded write request.
    Write,
}

impl IoOperation {
    /// Every declared kind, in canonical order.
    pub const ALL: [Self; 3] = [Self::Read, Self::Seek, Self::Write];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Seek => "seek",
            Self::Write => "write",
        }
    }

    /// Strictly decodes one declared portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.wire_name() == value)
    }

    /// Returns the progress observations this kind admits, in canonical observation order.
    #[must_use]
    pub const fn admissible_progress(self) -> &'static [ProgressObservation] {
        match self {
            Self::Read => &[
                ProgressObservation::CommittedProgress,
                ProgressObservation::Eof,
                ProgressObservation::NotStarted,
                ProgressObservation::ShortRead,
            ],
            Self::Seek => &[
                ProgressObservation::CommittedProgress,
                ProgressObservation::NotStarted,
            ],
            Self::Write => &[
                ProgressObservation::CommittedProgress,
                ProgressObservation::NotStarted,
                ProgressObservation::ShortWrite,
            ],
        }
    }

    /// Returns the canonical logical module name of this operation's one-call contract.
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Read => "std.io::reader",
            Self::Seek => "std.io::seek",
            Self::Write => "std.io::writer",
        }
    }
}

/// The closed refusal set of the Section 45 one-call contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoDiagnosticCode {
    /// A presented observation fact lies outside its declared range.
    ObservationInconsistent,
    /// The presented facts do not belong to the admitted request they are derived for.
    OutcomeRequestMismatch,
    /// A progress observation lies outside its kind's declared set.
    ProgressInapplicable,
    /// A request's declared quantity is zero or beyond the declared octet bound.
    RequestBound,
    /// A presented operation spelling is not declared.
    RequestKind,
}

impl IoDiagnosticCode {
    /// Every declared code, in exact wire-name order.
    pub const ALL: [Self; 5] = [
        Self::ObservationInconsistent,
        Self::OutcomeRequestMismatch,
        Self::ProgressInapplicable,
        Self::RequestBound,
        Self::RequestKind,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ObservationInconsistent => "io-observation-inconsistent",
            Self::OutcomeRequestMismatch => "io-outcome-request-mismatch",
            Self::ProgressInapplicable => "io-progress-inapplicable",
            Self::RequestBound => "io-request-bound",
            Self::RequestKind => "io-request-kind",
        }
    }

    /// Strictly decodes one declared portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.wire_name() == value)
    }
}

/// One refusal of the Section 45 one-call contract; each variant is owned by the clause that
/// declares its code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoError {
    /// A presented observation fact lies outside its declared range.
    ObservationInconsistent {
        /// The operation kind the facts belong to.
        operation: IoOperation,
        /// The presented fact's declared name.
        fact: &'static str,
        /// The observed value exactly as presented.
        observed: u64,
        /// The declared bound or exact value that fact admits.
        maximum: u64,
    },
    /// The presented facts do not belong to the admitted request they are derived for.
    RequestMismatch {
        /// The request's declared operation kind.
        operation: IoOperation,
        /// The presented fact's declared name.
        fact: &'static str,
    },
    /// A read or write request declared a quantity that is zero or beyond the declared bound.
    RequestBound {
        /// The declared operation kind.
        operation: IoOperation,
        /// The observed quantity exactly as presented.
        observed: u64,
        /// The declared finite octet bound.
        maximum: u64,
    },
    /// A presented operation spelling is not a declared kind.
    RequestKind {
        /// The observed spelling exactly as presented.
        observed: String,
    },
    /// A progress observation lies outside its kind's declared admissible set.
    ProgressInapplicable {
        /// The declared operation kind.
        operation: IoOperation,
        /// The observed progress observation.
        observation: ProgressObservation,
    },
}

impl IoError {
    /// Returns the one declared code that owns this refusal.
    #[must_use]
    pub const fn code(&self) -> IoDiagnosticCode {
        match self {
            Self::ObservationInconsistent { .. } => IoDiagnosticCode::ObservationInconsistent,
            Self::RequestMismatch { .. } => IoDiagnosticCode::OutcomeRequestMismatch,
            Self::RequestBound { .. } => IoDiagnosticCode::RequestBound,
            Self::RequestKind { .. } => IoDiagnosticCode::RequestKind,
            Self::ProgressInapplicable { .. } => IoDiagnosticCode::ProgressInapplicable,
        }
    }
}

/// One admitted request of the versioned one-call I/O contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoRequest {
    operation: IoOperation,
    quantity: u64,
}

impl IoRequest {
    /// Admits one read request asking for `octet_count` octets.
    pub fn read(octet_count: u64) -> Result<Self, IoError> {
        Self::bounded(IoOperation::Read, octet_count)
    }

    /// Admits one write request asking for `octet_count` octets.
    pub fn write(octet_count: u64) -> Result<Self, IoError> {
        Self::bounded(IoOperation::Write, octet_count)
    }

    /// Admits one seek request moving to `position`.
    #[must_use]
    pub const fn seek(position: u64) -> Self {
        Self {
            operation: IoOperation::Seek,
            quantity: position,
        }
    }

    /// Admits one request presented under a declared portable operation spelling.
    ///
    /// An undeclared spelling is refused under `io-request-kind`, naming the observed spelling,
    /// rather than inferred, substituted, or guessed.
    pub fn admit_wire(operation: &str, quantity: u64) -> Result<Self, IoError> {
        let kind = IoOperation::from_wire_name(operation).ok_or_else(|| IoError::RequestKind {
            observed: operation.to_owned(),
        })?;
        match kind {
            IoOperation::Read => Self::read(quantity),
            IoOperation::Seek => Ok(Self::seek(quantity)),
            IoOperation::Write => Self::write(quantity),
        }
    }

    /// Returns the declared operation kind.
    #[must_use]
    pub const fn operation(&self) -> IoOperation {
        self.operation
    }

    /// Returns the declared nonnegative logical quantity.
    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }

    /// Derives the one progress observation these facts decide for this admitted request.
    ///
    /// Facts whose operation kind or declared quantity differs from this request are refused
    /// under `io-outcome-request-mismatch` before any observation is derived.
    pub fn derive_progress(&self, outcome: &IoOutcome) -> Result<ProgressObservation, IoError> {
        if outcome.operation() != self.operation {
            return Err(IoError::RequestMismatch {
                operation: self.operation,
                fact: "operation",
            });
        }
        match *outcome {
            IoOutcome::Read { requested, .. } if requested != self.quantity => {
                Err(IoError::RequestMismatch {
                    operation: IoOperation::Read,
                    fact: "requested",
                })
            }
            IoOutcome::Write { provided, .. } if provided != self.quantity => {
                Err(IoError::RequestMismatch {
                    operation: IoOperation::Write,
                    fact: "provided",
                })
            }
            IoOutcome::Seek { target, .. } if target != self.quantity => {
                Err(IoError::RequestMismatch {
                    operation: IoOperation::Seek,
                    fact: "target",
                })
            }
            IoOutcome::Blocked {
                operation,
                quantity,
            } if quantity != self.quantity => Err(IoError::RequestMismatch {
                operation: operation.operation(),
                fact: operation.quantity_fact(),
            }),
            _ => outcome.derive_progress(),
        }
    }

    fn bounded(operation: IoOperation, octet_count: u64) -> Result<Self, IoError> {
        if octet_count == 0 || octet_count > IO_REQUEST_OCTET_BOUND {
            return Err(IoError::RequestBound {
                operation,
                observed: octet_count,
                maximum: IO_REQUEST_OCTET_BOUND,
            });
        }
        Ok(Self {
            operation,
            quantity: octet_count,
        })
    }
}

/// Admits one progress observation for one declared operation kind.
pub fn admit_io_progress(
    operation: IoOperation,
    observation: ProgressObservation,
) -> Result<(), IoError> {
    if operation.admissible_progress().contains(&observation) {
        return Ok(());
    }
    Err(IoError::ProgressInapplicable {
        operation,
        observation,
    })
}

/// One declared public module of `std.io` and the clauses that publish it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoItemRow {
    /// The declared operation whose one-call contract this module owns.
    pub operation: IoOperation,
    /// The canonical logical item name.
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public items of `std.io`, one module per declared operation.
///
/// Each name is the canonical logical spelling of the model's own operation identity
/// ([`IoOperation::module_name`]), so the rows are derived from the operation vocabulary rather
/// than restated beside it, and each row lists every clause that publishes a fact about that
/// item's surface in specification order.
pub const IO_ITEMS: [IoItemRow; 3] = [
    IoItemRow {
        operation: IoOperation::Read,
        name: IoOperation::Read.module_name(),
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-45.0-common-io-foundation-scope",
            "GNT-45.1-bounded-one-call-io-contract",
            "GNT-45.2-standard-io-modules-and-item-rows",
        ],
    },
    IoItemRow {
        operation: IoOperation::Seek,
        name: IoOperation::Seek.module_name(),
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-45.0-common-io-foundation-scope",
            "GNT-45.1-bounded-one-call-io-contract",
            "GNT-45.2-standard-io-modules-and-item-rows",
        ],
    },
    IoItemRow {
        operation: IoOperation::Write,
        name: IoOperation::Write.module_name(),
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-45.0-common-io-foundation-scope",
            "GNT-45.1-bounded-one-call-io-contract",
            "GNT-45.2-standard-io-modules-and-item-rows",
        ],
    },
];

/// Declares the published item surface of `std.io` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and each item takes that package's declared modes
/// and targets, so an item is never applicable outside its own package's applicability
/// (`GNT-34.7-applicability-and-feature-granularity`). A second declaration of one item is refused
/// by the graph rather than merged.
pub fn declare_io_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Io.package_name();
    let (modes, targets, present) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        validate_io_surface_package(graph, package)?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
            IO_ITEMS
                .iter()
                .filter(|row| package.item(row.name).is_some())
                .count(),
        )
    };
    if present == IO_ITEMS.len() {
        let row = IO_ITEMS[0];
        return graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?);
    }
    for row in IO_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Admits an already-declared `std.io` surface as exactly the three declared module rows.
///
/// The declared applicability must be exactly the application semantic mode over the library and
/// binary target kinds, no item outside the three declared rows may exist, and no row may be
/// missing; each violation is refused under its declared diagnostic rather than repaired.
pub fn admit_io_surface(graph: &StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Io.package_name();
    let package = graph.package(&owner).ok_or_else(|| {
        StdlibError::new(
            StdlibDiagnosticCode::UnknownEdge,
            format!("`{owner}` is not declared, so its item surface cannot be admitted"),
        )
    })?;
    validate_io_surface_package(graph, package)?;
    if IO_ITEMS.iter().any(|row| package.item(row.name).is_none()) {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the declared std.io item surface is incomplete".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the declared applicability, the closed item set, and the surface's atomicity.
fn validate_io_surface_package(graph: &StdGraph, package: &StdPackage) -> Result<(), StdlibError> {
    if package.modes().iter().copied().ne(IO_SURFACE_MODES)
        || package.targets().iter().copied().ne(IO_SURFACE_TARGETS)
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
            format!("`{owner}` declares a name outside its three declared modules"),
        ));
    }
    let present = IO_ITEMS
        .iter()
        .filter(|row| package.item(row.name).is_some())
        .count();
    if package.items().len() != present {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "a declared name outside the three std.io modules is refused".to_owned(),
        ));
    }
    if present != 0 && present != IO_ITEMS.len() {
        return Err(StdlibError::new(
            StdlibDiagnosticCode::InvalidNameClassification,
            "the std.io item surface is partially declared".to_owned(),
        ));
    }
    for row in IO_ITEMS {
        let Some(item) = package.item(row.name) else {
            continue;
        };
        if item.class() != row.class || item.tier() != row.tier {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::InvalidNameClassification,
                format!("`{}` does not declare its row's class and tier", row.name),
            ));
        }
        if item.modes().iter().copied().ne(IO_SURFACE_MODES)
            || item.targets().iter().copied().ne(IO_SURFACE_TARGETS)
        {
            return Err(StdlibError::new(
                StdlibDiagnosticCode::UnsupportedApplicability,
                format!("`{}` does not declare its row's applicability", row.name),
            ));
        }
    }
    Ok(())
}

/// One declared kind whose peer can present a backpressure fact.
///
/// A seek is never backpressured by `GNT-45.4-io-backpressure-and-chunk-settlement`: its progress
/// is a function of its declared target and its observed positions alone, so no seek fact is
/// declared here and no other kind, alias, or spelling is admitted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoBackpressure {
    /// A read that observed its peer not ready.
    Read,
    /// A write that observed its peer not ready.
    Write,
}

impl IoBackpressure {
    /// Every declared kind, in canonical order.
    pub const ALL: [Self; 2] = [Self::Read, Self::Write];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Returns the declared operation kind this backpressure kind belongs to.
    #[must_use]
    pub const fn operation(self) -> IoOperation {
        match self {
            Self::Read => IoOperation::Read,
            Self::Write => IoOperation::Write,
        }
    }

    /// Returns the declared fact name one observed quantity of this kind is published under.
    #[must_use]
    pub const fn quantity_fact(self) -> &'static str {
        match self {
            Self::Read => "requested",
            Self::Write => "provided",
        }
    }
}

/// One declared set of facts a single admitted I/O call observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoOutcome {
    /// A read observed its asked-for count, its advance, and its end-of-stream fact.
    Read {
        /// The octet count the read asked for.
        requested: u64,
        /// The octet count the read advanced.
        advanced: u64,
        /// Whether the read observed the end of its stream.
        ended: bool,
    },
    /// A seek observed its declared target, its pre-call position, and its post-call position.
    Seek {
        /// The declared target position.
        target: u64,
        /// The position the call held before it ran.
        from: u64,
        /// The position the call observed after it ran.
        to: u64,
    },
    /// A write observed its provided count and its accepted count.
    Write {
        /// The octet count the write was provided.
        provided: u64,
        /// The octet count the write accepted.
        accepted: u64,
    },
    /// A read or write observed its peer not ready, advancing and accepting no octet.
    Blocked {
        /// The declared kind whose peer was not ready.
        operation: IoBackpressure,
        /// The octet count the call was admitted for.
        quantity: u64,
    },
}

impl IoOutcome {
    /// Returns the declared operation kind these facts belong to.
    #[must_use]
    pub const fn operation(&self) -> IoOperation {
        match self {
            Self::Read { .. } => IoOperation::Read,
            Self::Seek { .. } => IoOperation::Seek,
            Self::Write { .. } => IoOperation::Write,
            Self::Blocked { operation, .. } => operation.operation(),
        }
    }

    /// Returns the declared backpressure witness of this outcome, when it presents one.
    ///
    /// The witness is published separately from the derived progress observation, so no caller
    /// reads a blocker as a completion, as an end of stream, or as a failure.
    #[must_use]
    pub const fn blocked(&self) -> Option<IoBackpressure> {
        match *self {
            Self::Blocked { operation, .. } => Some(operation),
            _ => None,
        }
    }

    /// Derives the one progress observation these admitted facts decide.
    ///
    /// A fact outside its declared range is refused under `io-observation-inconsistent` before
    /// any observation is derived, and the decision is total over admitted facts and preserves
    /// the precedence of `GNT-45.1-bounded-one-call-io-contract`.
    pub fn derive_progress(&self) -> Result<ProgressObservation, IoError> {
        match *self {
            Self::Read {
                requested,
                advanced,
                ended,
            } => {
                if requested == 0 || requested > IO_REQUEST_OCTET_BOUND {
                    return Err(IoError::ObservationInconsistent {
                        operation: IoOperation::Read,
                        fact: "requested",
                        observed: requested,
                        maximum: IO_REQUEST_OCTET_BOUND,
                    });
                }
                if advanced > requested {
                    return Err(IoError::ObservationInconsistent {
                        operation: IoOperation::Read,
                        fact: "advanced",
                        observed: advanced,
                        maximum: requested,
                    });
                }
                if ended {
                    return Ok(ProgressObservation::Eof);
                }
                if advanced == 0 {
                    return Ok(ProgressObservation::NotStarted);
                }
                if advanced == requested {
                    return Ok(ProgressObservation::CommittedProgress);
                }
                Ok(ProgressObservation::ShortRead)
            }
            Self::Write { provided, accepted } => {
                if provided == 0 || provided > IO_REQUEST_OCTET_BOUND {
                    return Err(IoError::ObservationInconsistent {
                        operation: IoOperation::Write,
                        fact: "provided",
                        observed: provided,
                        maximum: IO_REQUEST_OCTET_BOUND,
                    });
                }
                if accepted > provided {
                    return Err(IoError::ObservationInconsistent {
                        operation: IoOperation::Write,
                        fact: "accepted",
                        observed: accepted,
                        maximum: provided,
                    });
                }
                if accepted == provided {
                    return Ok(ProgressObservation::CommittedProgress);
                }
                if accepted == 0 {
                    return Ok(ProgressObservation::NotStarted);
                }
                Ok(ProgressObservation::ShortWrite)
            }
            Self::Blocked {
                operation,
                quantity,
            } => {
                if quantity == 0 || quantity > IO_REQUEST_OCTET_BOUND {
                    return Err(IoError::ObservationInconsistent {
                        operation: operation.operation(),
                        fact: operation.quantity_fact(),
                        observed: quantity,
                        maximum: IO_REQUEST_OCTET_BOUND,
                    });
                }
                Ok(ProgressObservation::NotStarted)
            }
            Self::Seek { target, from, to } => {
                if to != target {
                    return Err(IoError::ObservationInconsistent {
                        operation: IoOperation::Seek,
                        fact: "to",
                        observed: to,
                        maximum: target,
                    });
                }
                if from == target {
                    Ok(ProgressObservation::NotStarted)
                } else {
                    Ok(ProgressObservation::CommittedProgress)
                }
            }
        }
    }
}
