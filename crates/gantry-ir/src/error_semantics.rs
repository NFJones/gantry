//! Section 38 pure model: the closed failure-channel vocabulary, the frozen diagnostics of the
//! typed error, assertion, panic, and divergence contract, and the clause keys it implements.
//!
//! The model is pure: it carries no source syntax, no runtime state, and no host handle, and
//! every refusal of Section 38 is attributable to exactly one clause key through
//! [`ErrorSemanticsDiagnosticCode::requirement`].

/// The clause keys this model implements, in clause order.
///
/// Every diagnostic of this module names exactly one of these keys, so every refusal of the
/// section is attributable to the clause that owns it.
pub const ERROR_SEMANTICS_CLAUSES: [&str; 5] = [
    "GNT-38.0-error-and-divergence-scope",
    "GNT-38.1-typed-error-propagation",
    "GNT-38.2-assertions-and-panic",
    "GNT-38.3-divergence-and-never",
    "GNT-38.4-boundaries-durability-and-non-claims",
];

/// The closed failure-channel vocabulary of `GNT-38.0-error-and-divergence-scope`.
///
/// Every admitted form carries exactly one channel, and no conversion of this section moves a
/// value from one channel to another.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FailureChannel {
    /// An adapter failure.
    AdapterFailure,
    /// A cancellation.
    Cancellation,
    /// A typed source-level domain error.
    DomainError,
    /// A journal failure.
    JournalFailure,
    /// An operational failure of an integration or of the runtime.
    OperationalFailure,
    /// A policy denial.
    PolicyDenial,
    /// A resource exhaustion.
    ResourceExhaustion,
    /// An unknown external outcome.
    UnknownExternalOutcome,
}

impl FailureChannel {
    /// Every member of the closed vocabulary, in wire-name order.
    pub const ALL: [Self; 8] = [
        Self::AdapterFailure,
        Self::Cancellation,
        Self::DomainError,
        Self::JournalFailure,
        Self::OperationalFailure,
        Self::PolicyDenial,
        Self::ResourceExhaustion,
        Self::UnknownExternalOutcome,
    ];

    /// The wire spelling of this channel.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AdapterFailure => "adapter-failure",
            Self::Cancellation => "cancellation",
            Self::DomainError => "domain-error",
            Self::JournalFailure => "journal-failure",
            Self::OperationalFailure => "operational-failure",
            Self::PolicyDenial => "policy-denial",
            Self::ResourceExhaustion => "resource-exhaustion",
            Self::UnknownExternalOutcome => "unknown-external-outcome",
        }
    }

    /// Decodes one wire spelling, or `None` for a spelling outside the closed vocabulary.
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|channel| channel.wire_name() == value)
    }

    /// Reports whether this channel is the typed domain-error channel.
    pub const fn is_domain_error(self) -> bool {
        matches!(self, Self::DomainError)
    }
}

/// One frozen diagnostic of Section 38, in code order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorSemanticsDiagnosticCode {
    /// A use whose surviving type the completions do not determine.
    DivergenceUnconstrained,
    /// An ambiguous, partial, or channel-widening conversion declaration.
    ErrorConversionRefused,
    /// A propagation operand without exactly one declared conversion.
    ErrorPropagationRefused,
    /// A `Never` position in a boundary declaration.
    NeverBoundaryRefused,
    /// A `Never` component in durable state.
    NeverDurableRefused,
    /// A panic path exceeding the declared logical-frame budget.
    PanicFrameLimit,
    /// An assertion or panic form outside the admitted path.
    PanicPathRefused,
}

impl ErrorSemanticsDiagnosticCode {
    /// Every refusal condition, in wire-name order.
    pub const ALL: [Self; 7] = [
        Self::DivergenceUnconstrained,
        Self::ErrorConversionRefused,
        Self::ErrorPropagationRefused,
        Self::NeverBoundaryRefused,
        Self::NeverDurableRefused,
        Self::PanicFrameLimit,
        Self::PanicPathRefused,
    ];

    /// The wire spelling of this diagnostic.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DivergenceUnconstrained => "divergence-unconstrained",
            Self::ErrorConversionRefused => "error-conversion-refused",
            Self::ErrorPropagationRefused => "error-propagation-refused",
            Self::NeverBoundaryRefused => "never-boundary-refused",
            Self::NeverDurableRefused => "never-durable-refused",
            Self::PanicFrameLimit => "panic-frame-limit",
            Self::PanicPathRefused => "panic-path-refused",
        }
    }

    /// The clause key that owns this diagnostic.
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::ErrorPropagationRefused | Self::ErrorConversionRefused => {
                "GNT-38.1-typed-error-propagation"
            }
            Self::PanicPathRefused | Self::PanicFrameLimit => "GNT-38.2-assertions-and-panic",
            Self::DivergenceUnconstrained => "GNT-38.3-divergence-and-never",
            Self::NeverBoundaryRefused | Self::NeverDurableRefused => {
                "GNT-38.4-boundaries-durability-and-non-claims"
            }
        }
    }

    /// The meaning of this diagnostic.
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::DivergenceUnconstrained => {
                "a divergent expression does not determine the surviving type"
            }
            Self::ErrorConversionRefused => {
                "an error-conversion declaration is ambiguous, partial, or widens a channel"
            }
            Self::ErrorPropagationRefused => {
                "a propagation operand has no exactly one declared conversion"
            }
            Self::NeverBoundaryRefused => "a boundary declaration names the uninhabited type",
            Self::NeverDurableRefused => "durable state would carry a Never component",
            Self::PanicFrameLimit => "a panic path exceeds the declared logical-frame budget",
            Self::PanicPathRefused => "an assertion or panic form leaves the admitted path",
        }
    }

    /// Decodes one wire spelling, or `None` for a spelling outside the closed registry.
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }
}
