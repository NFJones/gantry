//! Pure common-I/O contract model for `SPEC.md` Section 45.
//!
//! This module publishes the declared operation vocabulary and the versioned one-call request
//! contract of `std.io` with its declared finite octet bound and its progress sets. It is not a
//! runtime reader, writer, or seek handle, an adapter, a scheduler, or a buffer, and it performs
//! no I/O: every decision is a deterministic function of explicit inputs.

use crate::operation::ProgressObservation;

/// The Section 45 clauses implemented by this pure model, in declaration order.
pub const IO_CLAUSES: [&str; 2] = [
    "GNT-45.0-common-io-foundation-scope",
    "GNT-45.1-bounded-one-call-io-contract",
];

/// The declared one-call request-contract version of `GNT-45.1-bounded-one-call-io-contract`.
pub const IO_CONTRACT_VERSION: u64 = 1;

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
}

/// The closed refusal set of the Section 45 one-call contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoDiagnosticCode {
    /// A progress observation lies outside its kind's declared set.
    ProgressInapplicable,
    /// A request's declared quantity is zero or beyond the declared octet bound.
    RequestBound,
    /// A presented operation spelling is not declared.
    RequestKind,
}

impl IoDiagnosticCode {
    /// Every declared code, in exact wire-name order.
    pub const ALL: [Self; 3] = [
        Self::ProgressInapplicable,
        Self::RequestBound,
        Self::RequestKind,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
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

/// One refusal of `GNT-45.1-bounded-one-call-io-contract`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoError {
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
