//! Pure execution-target, feature, predicate, and artifact-binding model.
//!
//! This module is the machine-checked target model for `GNT-17.0` through
//! `GNT-17.13-runtime-availability-separation`. It extends the target-kind
//! rules of `GNT-16.6-target-kinds` and cites the closed `GNT-3.1` mode
//! vocabulary rather than redefining it: the semantic mode of this model *is*
//! [`SemanticMode`], and a second mode enum would be a second mode.
//!
//! Scope is deliberately narrow. Every rule here is a pure function of its own
//! arguments: this module never reads an environment variable, a host path, a
//! clock, a locale, a discovered service, or a filesystem, and it exposes no
//! constructor that accepts one. That is what
//! `GNT-17.1-target-descriptor` and `GNT-17.2-descriptor-normalization-and-target-facts`
//! require of a descriptor, and what `GNT-17.5-feature-unification` requires of
//! a selected feature solution: the same unordered declarations, requests, and
//! predicates produce the same canonical bytes, the same digests, and the same
//! outcomes under every enumeration order.
//!
//! Three records stay distinct. [`ExecutionTargetDescriptor`] is the versioned
//! closed record of one execution target, [`TargetFactsRecord`] is the
//! `GNT-17.2` identity composition of descriptor version, normalized descriptor
//! digest, and feature-solution digest, and [`TargetArtifactBinding`] is the
//! `GNT-17.11` record of every input one artifact was produced from. The build
//! host is never an input of any of them under
//! `GNT-17.9-build-host-authority`; a recorded build input is recorded
//! elsewhere, as a declared generator input.

// The diagnostics of this module deliberately carry full package identities,
// descriptor digests, and offending names so a rejected target selection
// reports exactly what it disagreed with. Boxing those fields would hide
// identity behind an allocation at every construction and match site, so this
// module answers the size lint explicitly instead of weakening its own
// diagnostics.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gantry_core::mode::SemanticMode;
use gantry_core::protocol::ProtocolVersion;

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::package::{FeatureName, PackageIdentity, SelectedFeatureSet, TargetKind};

/// Domain separator for the canonical target-descriptor encoding.
const DESCRIPTOR_DOMAIN: &str = "gantry.target-descriptor/v1";

/// Domain separator for the canonical selected-feature-solution encoding.
const FEATURE_SOLUTION_DOMAIN: &str = "gantry.target-feature-solution/v1";

/// Domain separator for the canonical target-facts encoding.
const TARGET_FACTS_DOMAIN: &str = "gantry.target-facts/v1";

/// Domain separator for the canonical predicate-outcome encoding.
const PREDICATE_OUTCOME_DOMAIN: &str = "gantry.target-predicate-outcomes/v1";

/// Domain separator for the canonical target artifact-binding encoding.
const ARTIFACT_BINDING_DOMAIN: &str = "gantry.target-artifact-binding/v1";

/// One frozen published diagnostic identity of the target model.
///
/// The codes are frozen: a consumer matches on [`Self::as_str`], and the
/// meanings are the ones registered for the package category. The variant order
/// is the sorted code order, so [`Self::ALL`] is already in the order the
/// registry requires. Every condition of this section that a check can decide
/// has a code here, so unlike the package model this model has no condition
/// without a published code and reports none under another condition's code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetDiagnosticCode {
    /// `target-artifact-binding-mismatch`
    ArtifactBindingMismatch,
    /// `target-artifact-binding-missing-input`
    ArtifactBindingMissingInput,
    /// `target-artifact-binding-property-duplicate`
    ArtifactBindingPropertyDuplicate,
    /// `target-artifact-binding-property-unknown`
    ArtifactBindingPropertyUnknown,
    /// `target-artifact-binding-version-unsupported`
    ArtifactBindingVersionUnsupported,
    /// `target-declaration-invalid`
    DeclarationInvalid,
    /// `target-descriptor-digest-invalid`
    DescriptorDigestInvalid,
    /// `target-descriptor-property-duplicate`
    DescriptorPropertyDuplicate,
    /// `target-descriptor-property-missing`
    DescriptorPropertyMissing,
    /// `target-descriptor-property-unknown`
    DescriptorPropertyUnknown,
    /// `target-descriptor-version-unsupported`
    DescriptorVersionUnsupported,
    /// `target-feature-cycle`
    FeatureCycle,
    /// `target-feature-declaration-duplicate`
    FeatureDeclarationDuplicate,
    /// `target-feature-request-unsatisfiable`
    FeatureRequestUnsatisfiable,
    /// `target-feature-unknown`
    FeatureUnknown,
    /// `target-mode-not-admitted`
    ModeNotAdmitted,
    /// `target-predicate-name-unknown`
    PredicateNameUnknown,
    /// `target-wire-value-unknown`
    WireValueUnknown,
}

impl TargetDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 18] = [
        Self::ArtifactBindingMismatch,
        Self::ArtifactBindingMissingInput,
        Self::ArtifactBindingPropertyDuplicate,
        Self::ArtifactBindingPropertyUnknown,
        Self::ArtifactBindingVersionUnsupported,
        Self::DeclarationInvalid,
        Self::DescriptorDigestInvalid,
        Self::DescriptorPropertyDuplicate,
        Self::DescriptorPropertyMissing,
        Self::DescriptorPropertyUnknown,
        Self::DescriptorVersionUnsupported,
        Self::FeatureCycle,
        Self::FeatureDeclarationDuplicate,
        Self::FeatureRequestUnsatisfiable,
        Self::FeatureUnknown,
        Self::ModeNotAdmitted,
        Self::PredicateNameUnknown,
        Self::WireValueUnknown,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactBindingMismatch => "target-artifact-binding-mismatch",
            Self::ArtifactBindingMissingInput => "target-artifact-binding-missing-input",
            Self::ArtifactBindingPropertyDuplicate => "target-artifact-binding-property-duplicate",
            Self::ArtifactBindingPropertyUnknown => "target-artifact-binding-property-unknown",
            Self::ArtifactBindingVersionUnsupported => {
                "target-artifact-binding-version-unsupported"
            }
            Self::DeclarationInvalid => "target-declaration-invalid",
            Self::DescriptorDigestInvalid => "target-descriptor-digest-invalid",
            Self::DescriptorPropertyDuplicate => "target-descriptor-property-duplicate",
            Self::DescriptorPropertyMissing => "target-descriptor-property-missing",
            Self::DescriptorPropertyUnknown => "target-descriptor-property-unknown",
            Self::DescriptorVersionUnsupported => "target-descriptor-version-unsupported",
            Self::FeatureCycle => "target-feature-cycle",
            Self::FeatureDeclarationDuplicate => "target-feature-declaration-duplicate",
            Self::FeatureRequestUnsatisfiable => "target-feature-request-unsatisfiable",
            Self::FeatureUnknown => "target-feature-unknown",
            Self::ModeNotAdmitted => "target-mode-not-admitted",
            Self::PredicateNameUnknown => "target-predicate-name-unknown",
            Self::WireValueUnknown => "target-wire-value-unknown",
        }
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::ArtifactBindingMismatch => {
                "A recorded artifact binding disagrees with the target inputs it must bind."
            }
            Self::ArtifactBindingMissingInput => {
                "A recorded artifact binding omits one of the inputs it must bind."
            }
            Self::ArtifactBindingPropertyDuplicate => {
                "An artifact-binding record carries one property twice."
            }
            Self::ArtifactBindingPropertyUnknown => {
                "An artifact-binding record carries a property its version does not define."
            }
            Self::ArtifactBindingVersionUnsupported => {
                "An artifact-binding record names a version this implementation does not support."
            }
            Self::DeclarationInvalid => {
                "A declared name of this section is not a legal declaration name."
            }
            Self::DescriptorDigestInvalid => {
                "A digest spelling is not 64 lowercase hexadecimal digits."
            }
            Self::DescriptorPropertyDuplicate => {
                "A target-descriptor record carries one property twice."
            }
            Self::DescriptorPropertyMissing => {
                "A target-descriptor record omits a property its version defines."
            }
            Self::DescriptorPropertyUnknown => {
                "A target-descriptor record carries a property its version does not define."
            }
            Self::DescriptorVersionUnsupported => {
                "A target descriptor names a version this implementation does not support."
            }
            Self::FeatureCycle => "A feature enabling relation is cyclic.",
            Self::FeatureDeclarationDuplicate => "One package instance declares one feature twice.",
            Self::FeatureRequestUnsatisfiable => {
                "No single selected feature solution satisfies the requested feature set."
            }
            Self::FeatureUnknown => {
                "A feature declaration or a requested feature set names a feature the instance does not declare."
            }
            Self::ModeNotAdmitted => {
                "A semantic mode is not admitted for the selected target kind."
            }
            Self::PredicateNameUnknown => {
                "A predicate name is not a member of the sealed predicate vocabulary."
            }
            Self::WireValueUnknown => {
                "A target record carries a field value outside the closed vocabulary of its version."
            }
        }
    }

    /// Returns the requirement anchor this code implements.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::ArtifactBindingMismatch
            | Self::ArtifactBindingMissingInput
            | Self::ArtifactBindingPropertyDuplicate
            | Self::ArtifactBindingPropertyUnknown
            | Self::ArtifactBindingVersionUnsupported => "GNT-17.11-target-artifact-binding",
            Self::DeclarationInvalid | Self::FeatureDeclarationDuplicate => {
                "GNT-17.4-feature-declaration"
            }
            Self::DescriptorDigestInvalid => "GNT-17.2-descriptor-normalization-and-target-facts",
            Self::DescriptorPropertyDuplicate
            | Self::DescriptorPropertyMissing
            | Self::DescriptorPropertyUnknown
            | Self::DescriptorVersionUnsupported
            | Self::WireValueUnknown => "GNT-17.1-target-descriptor",
            Self::FeatureCycle | Self::FeatureUnknown => "GNT-17.4-feature-declaration",
            Self::FeatureRequestUnsatisfiable => "GNT-17.5-feature-unification",
            Self::ModeNotAdmitted => "GNT-17.10-target-selected-mode-admission",
            Self::PredicateNameUnknown => "GNT-17.3-sealed-predicates",
        }
    }
}

/// One rejected target, predicate, feature, or binding condition.
///
/// Every variant is a condition this module can decide and none of them is ever
/// repaired: an unsupported version, an unknown property, an unknown wire
/// value, an unknown predicate name, a feature cycle, an unknown or duplicate
/// feature, an unsatisfiable feature request, a non-canonical digest, an
/// unadmitted mode, a binding mismatch, and a missing binding input are all
/// reported rather than substituted, preferred, or silently discarded, as
/// `GNT-17.12-target-resolution-failure` requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// A recorded binding disagrees with one expected bound input.
    ArtifactBindingMismatch {
        /// The named bound input.
        field: &'static str,
        /// The expected value.
        expected: Arc<str>,
        /// The observed value.
        observed: Arc<str>,
    },
    /// A recorded binding omits a bound input of `GNT-17.11-target-artifact-binding`.
    ArtifactBindingMissingInput {
        /// The omitted bound input.
        input: &'static str,
    },
    /// One artifact-binding-record property recorded twice.
    ArtifactBindingPropertyDuplicate {
        /// The duplicated property name.
        property: Arc<str>,
    },
    /// An artifact-binding-record property this version does not define.
    ArtifactBindingPropertyUnknown {
        /// The unknown property name.
        property: Arc<str>,
    },
    /// An artifact-binding-record version this implementation does not support.
    ArtifactBindingVersionUnsupported {
        /// The unsupported version.
        version: u32,
    },
    /// A declared name that is not a legal declaration name.
    DeclarationInvalid {
        /// The named declaration.
        field: &'static str,
        /// The rejected spelling.
        value: Arc<str>,
    },
    /// A digest that is not 64 lowercase hexadecimal digits.
    DescriptorDigestInvalid {
        /// The rejected digest text.
        value: Arc<str>,
    },
    /// One descriptor-record property recorded twice.
    DescriptorPropertyDuplicate {
        /// The duplicated property name.
        property: Arc<str>,
    },
    /// A descriptor-record property its version defines and the record omits.
    DescriptorPropertyMissing {
        /// The missing property name.
        property: Arc<str>,
    },
    /// A descriptor-record property this version does not define.
    DescriptorPropertyUnknown {
        /// The unknown property name.
        property: Arc<str>,
    },
    /// A descriptor version this implementation does not support.
    DescriptorVersionUnsupported {
        /// The unsupported version.
        version: u32,
    },
    /// A cyclic feature enabling relation, reported as one deterministic cycle.
    FeatureCycle {
        /// The offending names, in enabling order from the cycle's least element.
        cycle: Vec<FeatureName>,
    },
    /// One feature declared twice by one package instance.
    FeatureDeclarationDuplicate {
        /// The duplicated feature name.
        name: FeatureName,
    },
    /// A requested feature set that no single solution satisfies.
    FeatureRequestUnsatisfiable {
        /// The package instance whose unification failed.
        root: Box<PackageIdentity>,
        /// The requested names the instance does not declare, in canonical order.
        requested: Vec<FeatureName>,
    },
    /// A feature name that its declaring package instance does not declare.
    FeatureUnknown {
        /// The unknown feature name.
        name: FeatureName,
    },
    /// A semantic mode the selected target kind does not admit.
    ModeNotAdmitted {
        /// The selected target kind.
        kind: TargetKind,
        /// The unadmitted mode.
        mode: SemanticMode,
    },
    /// A predicate name outside the sealed predicate vocabulary.
    PredicateNameUnknown {
        /// The rejected predicate name.
        name: Arc<str>,
    },
    /// A field value outside the closed vocabulary of its record version.
    WireValueUnknown {
        /// The named field.
        field: &'static str,
        /// The rejected value.
        value: Arc<str>,
    },
}

impl TargetError {
    /// Returns the frozen published diagnostic identity of this condition.
    #[must_use]
    pub const fn code(&self) -> TargetDiagnosticCode {
        match self {
            Self::ArtifactBindingMismatch { .. } => TargetDiagnosticCode::ArtifactBindingMismatch,
            Self::ArtifactBindingMissingInput { .. } => {
                TargetDiagnosticCode::ArtifactBindingMissingInput
            }
            Self::ArtifactBindingPropertyDuplicate { .. } => {
                TargetDiagnosticCode::ArtifactBindingPropertyDuplicate
            }
            Self::ArtifactBindingPropertyUnknown { .. } => {
                TargetDiagnosticCode::ArtifactBindingPropertyUnknown
            }
            Self::ArtifactBindingVersionUnsupported { .. } => {
                TargetDiagnosticCode::ArtifactBindingVersionUnsupported
            }
            Self::DeclarationInvalid { .. } => TargetDiagnosticCode::DeclarationInvalid,
            Self::DescriptorDigestInvalid { .. } => TargetDiagnosticCode::DescriptorDigestInvalid,
            Self::DescriptorPropertyDuplicate { .. } => {
                TargetDiagnosticCode::DescriptorPropertyDuplicate
            }
            Self::DescriptorPropertyMissing { .. } => {
                TargetDiagnosticCode::DescriptorPropertyMissing
            }
            Self::DescriptorPropertyUnknown { .. } => {
                TargetDiagnosticCode::DescriptorPropertyUnknown
            }
            Self::DescriptorVersionUnsupported { .. } => {
                TargetDiagnosticCode::DescriptorVersionUnsupported
            }
            Self::FeatureCycle { .. } => TargetDiagnosticCode::FeatureCycle,
            Self::FeatureDeclarationDuplicate { .. } => {
                TargetDiagnosticCode::FeatureDeclarationDuplicate
            }
            Self::FeatureRequestUnsatisfiable { .. } => {
                TargetDiagnosticCode::FeatureRequestUnsatisfiable
            }
            Self::FeatureUnknown { .. } => TargetDiagnosticCode::FeatureUnknown,
            Self::ModeNotAdmitted { .. } => TargetDiagnosticCode::ModeNotAdmitted,
            Self::PredicateNameUnknown { .. } => TargetDiagnosticCode::PredicateNameUnknown,
            Self::WireValueUnknown { .. } => TargetDiagnosticCode::WireValueUnknown,
        }
    }

    /// Returns the requirement anchor that owns this condition.
    #[must_use]
    pub const fn requirement(&self) -> &'static str {
        self.code().requirement()
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactBindingMismatch {
                field,
                expected,
                observed,
            } => write!(
                formatter,
                "artifact binding input `{field}` is `{observed}` and must bind `{expected}`"
            ),
            Self::ArtifactBindingMissingInput { input } => {
                write!(
                    formatter,
                    "artifact binding omits the bound input `{input}`"
                )
            }
            Self::ArtifactBindingPropertyDuplicate { property } => write!(
                formatter,
                "artifact-binding property `{property}` is recorded twice"
            ),
            Self::ArtifactBindingPropertyUnknown { property } => write!(
                formatter,
                "artifact-binding property `{property}` is not defined by this version"
            ),
            Self::ArtifactBindingVersionUnsupported { version } => write!(
                formatter,
                "artifact-binding version {version} is not supported"
            ),
            Self::DeclarationInvalid { field, value } => {
                write!(formatter, "declared {field} `{value}` is not a legal name")
            }
            Self::DescriptorDigestInvalid { value } => {
                write!(formatter, "digest `{value}` is not lowercase hexadecimal")
            }
            Self::DescriptorPropertyDuplicate { property } => write!(
                formatter,
                "target-descriptor property `{property}` is recorded twice"
            ),
            Self::DescriptorPropertyMissing { property } => write!(
                formatter,
                "target-descriptor record omits the property `{property}`"
            ),
            Self::DescriptorPropertyUnknown { property } => write!(
                formatter,
                "target-descriptor property `{property}` is not defined by this version"
            ),
            Self::DescriptorVersionUnsupported { version } => write!(
                formatter,
                "target-descriptor version {version} is not supported"
            ),
            Self::FeatureCycle { cycle } => {
                formatter.write_str("feature enabling relation is cyclic: ")?;
                write_feature_list(formatter, cycle)
            }
            Self::FeatureDeclarationDuplicate { name } => {
                write!(formatter, "feature `{}` is declared twice", name.as_str())
            }
            Self::FeatureRequestUnsatisfiable { root, requested } => {
                write!(
                    formatter,
                    "package `{}` cannot unify the requested features ",
                    root.as_str()
                )?;
                write_feature_list(formatter, requested)
            }
            Self::FeatureUnknown { name } => {
                write!(formatter, "feature `{}` is not declared", name.as_str())
            }
            Self::ModeNotAdmitted { kind, mode } => write!(
                formatter,
                "the {} target does not admit the {} mode",
                kind.wire_name(),
                mode.wire_name()
            ),
            Self::PredicateNameUnknown { name } => {
                write!(formatter, "predicate `{name}` is not sealed")
            }
            Self::WireValueUnknown { field, value } => write!(
                formatter,
                "{field} value `{value}` is outside the closed vocabulary"
            ),
        }
    }
}

impl std::error::Error for TargetError {}

/// Writes one comma-separated feature-name list.
fn write_feature_list(formatter: &mut fmt::Formatter<'_>, names: &[FeatureName]) -> fmt::Result {
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            formatter.write_str(", ")?;
        }
        formatter.write_str(name.as_str())?;
    }
    Ok(())
}

/// Validates one lowercase hexadecimal SHA-256 digest spelling.
fn validate_digest(value: &str) -> Result<(), TargetError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TargetError::DescriptorDigestInvalid {
            value: Arc::from(value),
        });
    }
    Ok(())
}

/// Validates one declared name that the canonical encodings embed verbatim.
fn validate_declared_name(field: &'static str, value: &str) -> Result<(), TargetError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(TargetError::DeclarationInvalid {
            field,
            value: Arc::from(value),
        });
    }
    Ok(())
}

macro_rules! target_digest_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Decodes one exact lowercase hexadecimal digest.
            pub fn from_hex(value: &str) -> Result<Self, TargetError> {
                validate_digest(value)?;
                Ok(Self(Arc::from(value)))
            }

            /// Encodes one accepted digest.
            #[must_use]
            pub fn from_digest(digest: [u8; 32]) -> Self {
                Self(Arc::from(encode_hex(&digest)))
            }

            /// Returns the exact lowercase hexadecimal digest.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns the same exact lowercase hexadecimal encoding as [`Self::as_str`].
            #[must_use]
            pub fn encode_hex(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

target_digest_type!(
    TargetDescriptorDigest,
    "One normalized descriptor digest over a canonical descriptor encoding (GNT-17.2-descriptor-normalization-and-target-facts)."
);
target_digest_type!(
    FeatureSolutionDigest,
    "One digest of one selected feature solution (GNT-17.5-feature-unification)."
);
target_digest_type!(
    TargetFactsDigest,
    "One digest of the target facts of one package instance (GNT-17.2-descriptor-normalization-and-target-facts)."
);
target_digest_type!(
    PredicateOutcomeDigest,
    "One digest of every evaluated predicate outcome of one selection (GNT-17.11-target-artifact-binding)."
);
target_digest_type!(
    GeneratedOutputHash,
    "One declared hash of one target-dependent generated output (GNT-17.11-target-artifact-binding)."
);
target_digest_type!(
    ToolchainIdentity,
    "The opaque identity of the toolchain that produced an artifact (GNT-17.11-target-artifact-binding).\n\nThe content is deliberately unspecified here: toolchain identity is owned by TOOLCHAIN-001, so this model records the identity opaquely and never interprets it."
);
target_digest_type!(
    TargetArtifactBindingDigest,
    "One digest over the canonical encoding of one target artifact binding (GNT-17.11-target-artifact-binding)."
);

/// The closed architecture vocabulary of descriptor version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Architecture {
    /// The 64-bit `x86_64` architecture.
    X86_64,
    /// The 64-bit `aarch64` architecture.
    Aarch64,
    /// The 64-bit `riscv64` architecture.
    Riscv64,
    /// The 32-bit `wasm32` architecture.
    Wasm32,
}

impl Architecture {
    /// Every architecture of the closed vocabulary, in sorted spelling order.
    pub const ALL: [Self; 4] = [Self::Aarch64, Self::Riscv64, Self::Wasm32, Self::X86_64];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Riscv64 => "riscv64",
            Self::Wasm32 => "wasm32",
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
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// The closed operating-system-family vocabulary of descriptor version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperatingSystemFamily {
    /// A hosted `linux` family.
    Linux,
    /// The `macos` family.
    Macos,
    /// The `windows` family.
    Windows,
    /// A `freestanding` family that hosts no operating system.
    Freestanding,
}

impl OperatingSystemFamily {
    /// Every family of the closed vocabulary, in sorted spelling order.
    pub const ALL: [Self; 4] = [Self::Freestanding, Self::Linux, Self::Macos, Self::Windows];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Freestanding => "freestanding",
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
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// The closed ABI-or-environment vocabulary of descriptor version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AbiEnvironment {
    /// The `gnu` ABI environment.
    Gnu,
    /// The `musl` ABI environment.
    Musl,
    /// The `msvc` ABI environment.
    Msvc,
    /// The `sysv` ABI environment.
    Sysv,
}

impl AbiEnvironment {
    /// Every ABI environment of the closed vocabulary, in sorted spelling order.
    pub const ALL: [Self; 4] = [Self::Gnu, Self::Musl, Self::Msvc, Self::Sysv];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Gnu => "gnu",
            Self::Musl => "musl",
            Self::Msvc => "msvc",
            Self::Sysv => "sysv",
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
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One versioned, closed execution-target descriptor.
///
/// The descriptor records exactly the fields `GNT-17.1-target-descriptor`
/// requires: architecture, operating-system family, ABI or environment,
/// language edition, standard-library contract version, and the cited `GNT-3.1`
/// semantic mode. A host path, a directory or file name, an environment
/// variable, a clock, a locale, a discovered service, a display name, and the
/// build host are deliberately absent: no constructor here accepts one, so no
/// ambient environment fact can enter a descriptor or its digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTargetDescriptor {
    architecture: Architecture,
    operating_system: OperatingSystemFamily,
    abi_environment: AbiEnvironment,
    language_edition: Arc<str>,
    stdlib_contract: ProtocolVersion,
    mode: SemanticMode,
    normalized: Arc<[u8]>,
}

impl ExecutionTargetDescriptor {
    /// The only supported descriptor version.
    pub const VERSION: u32 = 1;

    /// Constructs one descriptor and its single canonical encoding.
    pub fn new(
        architecture: Architecture,
        operating_system: OperatingSystemFamily,
        abi_environment: AbiEnvironment,
        language_edition: &str,
        stdlib_contract: ProtocolVersion,
        mode: SemanticMode,
    ) -> Result<Self, TargetError> {
        validate_declared_name("language edition", language_edition)?;
        let normalized = encode_descriptor(
            architecture,
            operating_system,
            abi_environment,
            language_edition,
            stdlib_contract,
            mode,
        );
        Ok(Self {
            architecture,
            operating_system,
            abi_environment,
            language_edition: Arc::from(language_edition),
            stdlib_contract,
            mode,
            normalized: Arc::from(normalized.into_boxed_slice()),
        })
    }

    /// Returns the descriptor version, which is never a platform version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        Self::VERSION
    }

    /// Returns the selected architecture.
    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Returns the selected operating-system family.
    #[must_use]
    pub const fn operating_system(&self) -> OperatingSystemFamily {
        self.operating_system
    }

    /// Returns the selected ABI or environment.
    #[must_use]
    pub const fn abi_environment(&self) -> AbiEnvironment {
        self.abi_environment
    }

    /// Returns the selected language edition.
    #[must_use]
    pub fn language_edition(&self) -> &str {
        &self.language_edition
    }

    /// Returns the selected standard-library contract version.
    #[must_use]
    pub const fn stdlib_contract(&self) -> ProtocolVersion {
        self.stdlib_contract
    }

    /// Returns the cited `GNT-3.1` semantic mode of this target.
    #[must_use]
    pub const fn mode(&self) -> SemanticMode {
        self.mode
    }

    /// Returns the one canonical byte encoding of this descriptor.
    #[must_use]
    pub fn normalized_bytes(&self) -> &[u8] {
        &self.normalized
    }

    /// Returns the normalized descriptor digest over those canonical bytes.
    #[must_use]
    pub fn digest(&self) -> TargetDescriptorDigest {
        TargetDescriptorDigest::from_digest(digest_fields(DESCRIPTOR_DOMAIN, &[&self.normalized]))
    }

    /// Returns the versioned wire record of this descriptor.
    #[must_use]
    pub fn record(&self) -> TargetDescriptorRecord {
        TargetDescriptorRecord::from_descriptor(self)
    }
}

/// One decoded, versioned, closed target-descriptor record.
///
/// A record that carries a property this version does not define, records one
/// property twice, omits a property this version defines, or names an
/// unsupported version is rejected rather than repaired, and a field value
/// outside the closed vocabulary of its version is invalid rather than ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDescriptorRecord {
    version: u32,
    properties: BTreeMap<Arc<str>, Arc<str>>,
}

impl TargetDescriptorRecord {
    /// The only supported descriptor-record version.
    pub const VERSION: u32 = 1;

    /// The closed property vocabulary of a descriptor record.
    pub const PROPERTIES: [&'static str; 6] = [
        "abi",
        "architecture",
        "edition",
        "os_family",
        "semantic_mode",
        "stdlib_contract",
    ];

    /// Decodes one closed descriptor record, rejecting unknown properties.
    pub fn new(version: u32, properties: &[(&str, &str)]) -> Result<Self, TargetError> {
        if version != Self::VERSION {
            return Err(TargetError::DescriptorVersionUnsupported { version });
        }
        let mut decoded = BTreeMap::new();
        for (key, value) in properties {
            if !Self::PROPERTIES.contains(key) {
                return Err(TargetError::DescriptorPropertyUnknown {
                    property: Arc::from(*key),
                });
            }
            if decoded.insert(Arc::from(*key), Arc::from(*value)).is_some() {
                return Err(TargetError::DescriptorPropertyDuplicate {
                    property: Arc::from(*key),
                });
            }
        }
        Ok(Self {
            version,
            properties: decoded,
        })
    }

    /// Encodes one descriptor as the record of its own version.
    #[must_use]
    pub fn from_descriptor(descriptor: &ExecutionTargetDescriptor) -> Self {
        let mut properties = BTreeMap::new();
        for (key, value) in [
            ("abi", descriptor.abi_environment().wire_name()),
            ("architecture", descriptor.architecture().wire_name()),
            ("edition", descriptor.language_edition()),
            ("os_family", descriptor.operating_system().wire_name()),
            ("semantic_mode", descriptor.mode().wire_name()),
        ] {
            properties.insert(Arc::from(key), Arc::from(value));
        }
        properties.insert(
            Arc::from("stdlib_contract"),
            Arc::from(version_text(descriptor.stdlib_contract()).as_str()),
        );
        Self {
            version: ExecutionTargetDescriptor::VERSION,
            properties,
        }
    }

    /// Returns the record version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns one recorded property value.
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(AsRef::as_ref)
    }

    /// Proves one descriptor of this record, or reports the offending property.
    pub fn descriptor(&self) -> Result<ExecutionTargetDescriptor, TargetError> {
        let architecture = Architecture::from_wire_name(self.required("architecture")?).ok_or(
            TargetError::WireValueUnknown {
                field: "architecture",
                value: Arc::from(self.required("architecture")?),
            },
        )?;
        let operating_system = OperatingSystemFamily::from_wire_name(self.required("os_family")?)
            .ok_or(TargetError::WireValueUnknown {
            field: "os_family",
            value: Arc::from(self.required("os_family")?),
        })?;
        let abi_environment = AbiEnvironment::from_wire_name(self.required("abi")?).ok_or(
            TargetError::WireValueUnknown {
                field: "abi",
                value: Arc::from(self.required("abi")?),
            },
        )?;
        let mode = SemanticMode::from_wire_name(self.required("semantic_mode")?).ok_or(
            TargetError::WireValueUnknown {
                field: "semantic_mode",
                value: Arc::from(self.required("semantic_mode")?),
            },
        )?;
        let stdlib_contract =
            parse_protocol_version("stdlib_contract", self.required("stdlib_contract")?)?;
        ExecutionTargetDescriptor::new(
            architecture,
            operating_system,
            abi_environment,
            self.required("edition")?,
            stdlib_contract,
            mode,
        )
    }

    /// Returns one required property or reports it missing.
    fn required(&self, key: &'static str) -> Result<&str, TargetError> {
        self.property(key)
            .ok_or(TargetError::DescriptorPropertyMissing {
                property: Arc::from(key),
            })
    }
}

/// The closed sealed predicate-name table of `GNT-17.3-sealed-predicates`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetPredicateName {
    /// A predicate that reads exactly one descriptor field.
    DescriptorField,
    /// A predicate that reads exactly one declared feature.
    FeatureEnabled,
}

impl TargetPredicateName {
    /// Every sealed predicate name of the closed table.
    pub const ALL: [Self; 2] = [Self::DescriptorField, Self::FeatureEnabled];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DescriptorField => "descriptor-field",
            Self::FeatureEnabled => "feature-enabled",
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
            .find(|candidate| candidate.wire_name() == value)
    }
}

/// One sealed predicate read of exactly one descriptor field.
///
/// Each member names one descriptor field a predicate may read together with
/// the admitted value the predicate requires of that field, so the vocabulary
/// is closed in both the field and the value, and evaluation reads nothing but
/// the selected descriptor.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetDescriptorField {
    /// The architecture field, required to equal the named architecture.
    Architecture(Architecture),
    /// The operating-system-family field, required to equal the named family.
    OperatingSystemFamily(OperatingSystemFamily),
    /// The ABI-or-environment field, required to equal the named environment.
    AbiEnvironment(AbiEnvironment),
    /// The language-edition field, required to equal the named edition.
    LanguageEdition(Arc<str>),
    /// The standard-library-contract field, required to equal the named version.
    StdlibContract(ProtocolVersion),
    /// The cited semantic-mode field, required to equal the named mode.
    SemanticMode(SemanticMode),
}

impl TargetDescriptorField {
    /// Constructs one language-edition read under its declaration rules.
    pub fn language_edition(value: &str) -> Result<Self, TargetError> {
        validate_declared_name("language edition", value)?;
        if value.contains('=') {
            return Err(TargetError::DeclarationInvalid {
                field: "language edition",
                value: Arc::from(value),
            });
        }
        Ok(Self::LanguageEdition(Arc::from(value)))
    }

    /// Returns the name of the descriptor field this read names.
    #[must_use]
    pub const fn field_name(&self) -> &'static str {
        match self {
            Self::Architecture(_) => "architecture",
            Self::OperatingSystemFamily(_) => "os_family",
            Self::AbiEnvironment(_) => "abi",
            Self::LanguageEdition(_) => "edition",
            Self::StdlibContract(_) => "stdlib_contract",
            Self::SemanticMode(_) => "semantic_mode",
        }
    }

    /// Returns the exact portable spelling of this read.
    #[must_use]
    pub fn wire_name(&self) -> String {
        match self {
            Self::Architecture(value) => format!("architecture={}", value.wire_name()),
            Self::OperatingSystemFamily(value) => format!("os_family={}", value.wire_name()),
            Self::AbiEnvironment(value) => format!("abi={}", value.wire_name()),
            Self::LanguageEdition(value) => format!("edition={value}"),
            Self::StdlibContract(value) => {
                format!("stdlib_contract={}", version_text(*value))
            }
            Self::SemanticMode(value) => format!("semantic_mode={}", value.wire_name()),
        }
    }

    /// Strictly decodes one exact portable spelling.
    pub fn from_wire_name(value: &str) -> Result<Self, TargetError> {
        let (field, argument) = value.split_once('=').ok_or(TargetError::WireValueUnknown {
            field: "descriptor field",
            value: Arc::from(value),
        })?;
        let unknown = |field: &'static str, argument: &str| TargetError::WireValueUnknown {
            field,
            value: Arc::from(argument),
        };
        match field {
            "architecture" => Architecture::from_wire_name(argument)
                .map(Self::Architecture)
                .ok_or_else(|| unknown("architecture", argument)),
            "os_family" => OperatingSystemFamily::from_wire_name(argument)
                .map(Self::OperatingSystemFamily)
                .ok_or_else(|| unknown("os_family", argument)),
            "abi" => AbiEnvironment::from_wire_name(argument)
                .map(Self::AbiEnvironment)
                .ok_or_else(|| unknown("abi", argument)),
            "edition" => Self::language_edition(argument),
            "stdlib_contract" => {
                parse_protocol_version("stdlib_contract", argument).map(Self::StdlibContract)
            }
            "semantic_mode" => SemanticMode::from_wire_name(argument)
                .map(Self::SemanticMode)
                .ok_or_else(|| unknown("semantic_mode", argument)),
            _ => Err(TargetError::WireValueUnknown {
                field: "descriptor field",
                value: Arc::from(field),
            }),
        }
    }

    /// Returns whether the selected descriptor records this required value.
    #[must_use]
    pub fn matches(&self, descriptor: &ExecutionTargetDescriptor) -> bool {
        match self {
            Self::Architecture(value) => descriptor.architecture() == *value,
            Self::OperatingSystemFamily(value) => descriptor.operating_system() == *value,
            Self::AbiEnvironment(value) => descriptor.abi_environment() == *value,
            Self::LanguageEdition(value) => descriptor.language_edition() == value.as_ref(),
            Self::StdlibContract(value) => descriptor.stdlib_contract() == *value,
            Self::SemanticMode(value) => descriptor.mode() == *value,
        }
    }
}

/// One sealed predicate of `GNT-17.3-sealed-predicates`.
///
/// A predicate reads only the listed descriptor fields and the declared
/// features of the declaring package instance. It has no source form, no
/// dependency form, and no build-script form: the only two constructors are the
/// two members of the closed table, and evaluation reads nothing else.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetPredicate {
    /// A read of exactly one descriptor field.
    DescriptorField(TargetDescriptorField),
    /// A read of exactly one declared feature of the declaring instance.
    FeatureEnabled(FeatureName),
}

impl TargetPredicate {
    /// Returns the sealed predicate name of this predicate.
    #[must_use]
    pub const fn name(&self) -> TargetPredicateName {
        match self {
            Self::DescriptorField(_) => TargetPredicateName::DescriptorField,
            Self::FeatureEnabled(_) => TargetPredicateName::FeatureEnabled,
        }
    }

    /// Returns the exact portable spelling of this predicate.
    #[must_use]
    pub fn wire_name(&self) -> String {
        match self {
            Self::DescriptorField(field) => {
                format!("{}:{}", self.name().wire_name(), field.wire_name())
            }
            Self::FeatureEnabled(name) => {
                format!("{}:{}", self.name().wire_name(), name.as_str())
            }
        }
    }

    /// Strictly decodes one predicate of the sealed table.
    ///
    /// A name outside the table is an error rather than an extension point, so
    /// a predicate cannot be defined by source, by a dependency, or by a build
    /// script.
    pub fn decode(name: &str, argument: &str) -> Result<Self, TargetError> {
        match TargetPredicateName::from_wire_name(name) {
            Some(TargetPredicateName::DescriptorField) => {
                TargetDescriptorField::from_wire_name(argument).map(Self::DescriptorField)
            }
            Some(TargetPredicateName::FeatureEnabled) => FeatureName::new(argument)
                .map(Self::FeatureEnabled)
                .map_err(|_| TargetError::DeclarationInvalid {
                    field: "feature",
                    value: Arc::from(argument),
                }),
            None => Err(TargetError::PredicateNameUnknown {
                name: Arc::from(name),
            }),
        }
    }

    /// Evaluates this predicate against one descriptor and one feature set.
    #[must_use]
    pub fn evaluate(
        &self,
        descriptor: &ExecutionTargetDescriptor,
        features: &SelectedFeatureSet,
    ) -> PredicateOutcome {
        let matched = match self {
            Self::DescriptorField(field) => field.matches(descriptor),
            Self::FeatureEnabled(name) => features.as_slice().contains(name),
        };
        PredicateOutcome {
            predicate: self.clone(),
            matched,
        }
    }
}

/// One evaluated predicate and its outcome.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PredicateOutcome {
    /// The evaluated predicate.
    pub predicate: TargetPredicate,
    /// Whether the predicate matched the selected descriptor and features.
    pub matched: bool,
}

impl PredicateOutcome {
    /// Constructs one evaluated outcome.
    #[must_use]
    pub const fn new(predicate: TargetPredicate, matched: bool) -> Self {
        Self { predicate, matched }
    }
}

/// One canonically ordered set of evaluated predicate outcomes.
///
/// The declared set, not its enumeration, is the recorded outcome: the set is
/// sorted and deduplicated by canonical outcome order, so the same outcomes
/// produce the same digest in every evaluation order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PredicateOutcomeSet(Vec<PredicateOutcome>);

impl PredicateOutcomeSet {
    /// Builds one canonical outcome set from outcomes in any order.
    #[must_use]
    pub fn new(outcomes: &[PredicateOutcome]) -> Self {
        let mut outcomes = outcomes.to_vec();
        outcomes.sort();
        outcomes.dedup();
        Self(outcomes)
    }

    /// Evaluates every predicate of one sealed selection in any order.
    #[must_use]
    pub fn evaluate(
        predicates: &[TargetPredicate],
        descriptor: &ExecutionTargetDescriptor,
        features: &SelectedFeatureSet,
    ) -> Self {
        let outcomes = predicates
            .iter()
            .map(|predicate| predicate.evaluate(descriptor, features))
            .collect::<Vec<_>>();
        Self::new(&outcomes)
    }

    /// Returns the empty outcome set of a selection that evaluated none.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the evaluated outcomes in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[PredicateOutcome] {
        &self.0
    }

    /// Returns whether no predicate was evaluated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of distinct evaluated outcomes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the digest over the canonical encoding of these outcomes.
    #[must_use]
    pub fn digest(&self) -> PredicateOutcomeDigest {
        let encoded = encode_predicate_outcomes(self);
        PredicateOutcomeDigest::from_digest(digest_fields(PREDICATE_OUTCOME_DOMAIN, &[&encoded]))
    }
}

/// One declared feature of one package instance (GNT-17.4-feature-declaration).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureDeclaration {
    name: FeatureName,
    default_enabled: bool,
    enables: Vec<FeatureName>,
}

impl FeatureDeclaration {
    /// Constructs one declaration over the closed feature vocabulary.
    pub fn new(name: &str, default_enabled: bool, enables: &[&str]) -> Result<Self, TargetError> {
        let name = FeatureName::new(name).map_err(|_| TargetError::DeclarationInvalid {
            field: "feature",
            value: Arc::from(name),
        })?;
        let mut enabled = Vec::with_capacity(enables.len());
        for enabled_name in enables {
            enabled.push(FeatureName::new(enabled_name).map_err(|_| {
                TargetError::DeclarationInvalid {
                    field: "feature",
                    value: Arc::from(*enabled_name),
                }
            })?);
        }
        enabled.sort();
        enabled.dedup();
        Ok(Self {
            name,
            default_enabled,
            enables: enabled,
        })
    }

    /// Returns the declared feature name.
    #[must_use]
    pub const fn name(&self) -> &FeatureName {
        &self.name
    }

    /// Returns whether the default selection includes this feature.
    #[must_use]
    pub const fn default_enabled(&self) -> bool {
        self.default_enabled
    }

    /// Returns the features this declaration enables, in canonical order.
    #[must_use]
    pub fn enables(&self) -> &[FeatureName] {
        &self.enables
    }
}

/// The closed feature declarations of one package instance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeatureDeclarations(Vec<FeatureDeclaration>);

impl FeatureDeclarations {
    /// Builds one declaration set from declarations in any order.
    ///
    /// A declaration with an unknown feature name, a feature declared twice, or
    /// a cyclic enabling relation is invalid rather than ignored, and the
    /// offending names are reported.
    pub fn new(declarations: &[FeatureDeclaration]) -> Result<Self, TargetError> {
        let mut declarations = declarations.to_vec();
        declarations.sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(pair) = declarations
            .windows(2)
            .find(|pair| pair[0].name == pair[1].name)
        {
            return Err(TargetError::FeatureDeclarationDuplicate {
                name: pair[0].name.clone(),
            });
        }
        let declared = declarations
            .iter()
            .map(|declaration| &declaration.name)
            .collect::<BTreeSet<_>>();
        for declaration in &declarations {
            for enabled in &declaration.enables {
                if !declared.contains(enabled) {
                    return Err(TargetError::FeatureUnknown {
                        name: enabled.clone(),
                    });
                }
            }
        }
        if let Some(cycle) = find_feature_cycle(&declarations) {
            return Err(TargetError::FeatureCycle { cycle });
        }
        Ok(Self(declarations))
    }

    /// Returns the empty declaration set of an instance that declares none.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the declarations in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[FeatureDeclaration] {
        &self.0
    }

    /// Returns whether no feature is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of declared features.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this instance declares the named feature.
    #[must_use]
    pub fn contains(&self, name: &FeatureName) -> bool {
        self.declaration(name).is_some()
    }

    /// Returns the declaration of one feature, when this instance declares it.
    #[must_use]
    pub fn declaration(&self, name: &FeatureName) -> Option<&FeatureDeclaration> {
        self.0
            .binary_search_by(|declaration| declaration.name.cmp(name))
            .ok()
            .and_then(|index| self.0.get(index))
    }

    /// Returns the feature names the default selection includes, in canonical order.
    #[must_use]
    pub fn defaults(&self) -> Vec<FeatureName> {
        self.0
            .iter()
            .filter(|declaration| declaration.default_enabled)
            .map(|declaration| declaration.name.clone())
            .collect()
    }
}

/// Returns one deterministic cycle of the enabling relation, when it has one.
///
/// The search starts at the least declared feature and never leaves a feature
/// below that start, so the cycle it returns is the one whose least member is
/// the least feature that lies on any cycle, and the reported names are stable
/// under every declaration order.
fn find_feature_cycle(declarations: &[FeatureDeclaration]) -> Option<Vec<FeatureName>> {
    let graph = declarations
        .iter()
        .map(|declaration| (&declaration.name, declaration.enables.as_slice()))
        .collect::<BTreeMap<_, _>>();
    for start in graph.keys() {
        let start = (*start).clone();
        let mut path = vec![start.clone()];
        let mut cursor = vec![0_usize];
        let mut on_path = BTreeSet::new();
        on_path.insert(start.clone());
        loop {
            if cursor.is_empty() {
                break;
            }
            let depth = cursor.len() - 1;
            let node = path[depth].clone();
            let children = graph.get(&node).copied().unwrap_or(&[]);
            let mut descended = false;
            while cursor[depth] < children.len() {
                let child = children[cursor[depth]].clone();
                cursor[depth] += 1;
                if child < start || on_path.contains(&child) {
                    if child == start {
                        return Some(path.clone());
                    }
                    continue;
                }
                path.push(child.clone());
                on_path.insert(child);
                cursor.push(0);
                descended = true;
                break;
            }
            if descended {
                continue;
            }
            on_path.remove(&node);
            path.pop();
            cursor.pop();
        }
    }
    None
}

/// One selected feature solution of one package instance.
///
/// Exactly one solution exists per package instance: the selected set is the
/// acyclic closure of the requested features and the declared default selection
/// under the enabling relation, kept as a canonical sorted set. The solution
/// records the package instance it belongs to and exposes no API whose result
/// can depend on traversal order, enumeration order, which dependency requested
/// a feature, or which graph path reached the instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureSolution {
    root: PackageIdentity,
    selected: Vec<FeatureName>,
    digest: FeatureSolutionDigest,
}

impl FeatureSolution {
    /// Unifies one requested feature set into the one solution of one instance.
    ///
    /// A request that names a feature the instance does not declare cannot be
    /// unified, so it is an unsatisfiable request rather than a preference.
    pub fn unify(
        declarations: &FeatureDeclarations,
        requested: &[FeatureName],
        root: &PackageIdentity,
    ) -> Result<Self, TargetError> {
        let mut requested = requested.to_vec();
        requested.sort();
        requested.dedup();
        let undeclared = requested
            .iter()
            .filter(|name| !declarations.contains(name))
            .cloned()
            .collect::<Vec<_>>();
        if !undeclared.is_empty() {
            return Err(TargetError::FeatureRequestUnsatisfiable {
                root: Box::new(root.clone()),
                requested: undeclared,
            });
        }
        let mut pending = requested.clone();
        pending.extend(declarations.defaults());
        let mut selected = BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !selected.insert(name.clone()) {
                continue;
            }
            if let Some(declaration) = declarations.declaration(&name) {
                pending.extend(declaration.enables().iter().cloned());
            }
        }
        let selected = selected.into_iter().collect::<Vec<_>>();
        let digest = FeatureSolutionDigest::from_digest(digest_fields(
            FEATURE_SOLUTION_DOMAIN,
            &[&encode_feature_solution(&selected)],
        ));
        Ok(Self {
            root: root.clone(),
            selected,
            digest,
        })
    }

    /// Returns the package instance this solution belongs to.
    #[must_use]
    pub const fn root(&self) -> &PackageIdentity {
        &self.root
    }

    /// Returns the selected features in canonical order.
    #[must_use]
    pub fn selected(&self) -> &[FeatureName] {
        &self.selected
    }

    /// Returns whether the solution selects the named feature.
    #[must_use]
    pub fn contains(&self, name: &FeatureName) -> bool {
        self.selected.binary_search(name).is_ok()
    }

    /// Iterates the selected feature names in canonical order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.selected.iter().map(FeatureName::as_str)
    }

    /// Returns the digest of this selected feature solution.
    #[must_use]
    pub const fn digest(&self) -> &FeatureSolutionDigest {
        &self.digest
    }
}

/// The `GNT-17.2` target facts of one package instance.
///
/// The facts are exactly the descriptor version, the normalized descriptor
/// digest, and the digest of the selected feature solution, composed with the
/// declared kind and entry-point facts of `GNT-16.6-target-kinds` where those
/// are recorded. They are never derived from a host path, a directory or file
/// name, a filesystem layout, an environment variable, a clock, a locale, a
/// discovered service, or a display name.
///
/// Wiring this record into [`crate::package::PackageIdentityInputs`] is a
/// follow-up: the landed `TargetFactSet` of `crate::package` is deliberately
/// unchanged here, because registering a new identity input also requires the
/// requirements ledger and the canonical identity-encoding cascade to move with
/// it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetFactsRecord {
    descriptor_version: u32,
    descriptor: TargetDescriptorDigest,
    features: FeatureSolutionDigest,
    canonical: Arc<[u8]>,
}

impl TargetFactsRecord {
    /// The only supported descriptor version of a target-facts record.
    pub const VERSION: u32 = ExecutionTargetDescriptor::VERSION;

    /// Composes one target-facts record, rejecting an unsupported version.
    pub fn new(
        descriptor_version: u32,
        descriptor: TargetDescriptorDigest,
        features: FeatureSolutionDigest,
    ) -> Result<Self, TargetError> {
        if descriptor_version != Self::VERSION {
            return Err(TargetError::DescriptorVersionUnsupported {
                version: descriptor_version,
            });
        }
        let canonical = encode_target_facts(descriptor_version, &descriptor, &features);
        Ok(Self {
            descriptor_version,
            descriptor,
            features,
            canonical: Arc::from(canonical.into_boxed_slice()),
        })
    }

    /// Composes the target facts of one descriptor and one selected solution.
    pub fn for_selection(
        descriptor: &ExecutionTargetDescriptor,
        solution: &FeatureSolution,
    ) -> Result<Self, TargetError> {
        Self::new(
            descriptor.version(),
            descriptor.digest(),
            solution.digest().clone(),
        )
    }

    /// Returns the descriptor version these facts record.
    #[must_use]
    pub const fn descriptor_version(&self) -> u32 {
        self.descriptor_version
    }

    /// Returns the normalized descriptor digest these facts record.
    #[must_use]
    pub const fn descriptor_digest(&self) -> &TargetDescriptorDigest {
        &self.descriptor
    }

    /// Returns the feature-solution digest these facts record.
    #[must_use]
    pub const fn feature_solution_digest(&self) -> &FeatureSolutionDigest {
        &self.features
    }

    /// Returns the one canonical byte encoding of these facts.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the digest over those canonical bytes.
    #[must_use]
    pub fn digest(&self) -> TargetFactsDigest {
        TargetFactsDigest::from_digest(digest_fields(TARGET_FACTS_DOMAIN, &[&self.canonical]))
    }

    /// Returns the canonical text form these facts are recorded under.
    ///
    /// The form is `version:descriptor:features` and is exactly the text a
    /// package identity record carries for its `target_selection` property, so
    /// the recorded text and the derived identity never disagree.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{}:{}:{}",
            self.descriptor_version,
            self.descriptor.as_str(),
            self.features.as_str()
        )
    }

    /// Decodes the canonical text form of one target-facts record.
    ///
    /// A text that is not exactly the recorded form is invalid rather than
    /// repaired, and a record whose version this implementation does not support
    /// is reported as unsupported rather than reinterpreted.
    pub fn from_text(value: &str) -> Result<Self, TargetError> {
        let mut parts = value.split(':');
        let (Some(version), Some(descriptor), Some(features)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(TargetError::DeclarationInvalid {
                field: "target_selection",
                value: Arc::from(value),
            });
        };
        if parts.next().is_some() {
            return Err(TargetError::DeclarationInvalid {
                field: "target_selection",
                value: Arc::from(value),
            });
        }
        let version = version
            .parse::<u32>()
            .map_err(|_| TargetError::DeclarationInvalid {
                field: "target_selection",
                value: Arc::from(value),
            })?;
        let descriptor = TargetDescriptorDigest::from_hex(descriptor).map_err(|_| {
            TargetError::DeclarationInvalid {
                field: "target_selection",
                value: Arc::from(value),
            }
        })?;
        let features = FeatureSolutionDigest::from_hex(features).map_err(|_| {
            TargetError::DeclarationInvalid {
                field: "target_selection",
                value: Arc::from(value),
            }
        })?;
        Self::new(version, descriptor, features)
    }
}

/// The explicit target-kind to semantic-mode admission table of `GNT-17.10`.
///
/// The table cites the closed `GNT-3.1` vocabulary and adds no mode. A library
/// declares no entry point under `GNT-16.6-target-kinds`, so durable execution
/// admission is not admitted for a library target; a `test`, `example`, or
/// `benchmark` target is non-shipping and bounded-authority, so only the
/// portable mode is admitted for it; a shipping `binary` target admits the whole
/// closed vocabulary. Exactly one admitted mode participates in the
/// retained-closure analysis and in artifact identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModeAdmission;

impl ModeAdmission {
    /// The explicit admission table, in the landed `GNT-16.6` kind order.
    pub const TABLE: [(TargetKind, &'static [SemanticMode]); 5] = [
        (
            TargetKind::Library,
            &[SemanticMode::Portable, SemanticMode::Application],
        ),
        (
            TargetKind::Binary,
            &[
                SemanticMode::Portable,
                SemanticMode::Application,
                SemanticMode::Durable,
            ],
        ),
        (TargetKind::Test, &[SemanticMode::Portable]),
        (TargetKind::Example, &[SemanticMode::Portable]),
        (TargetKind::Benchmark, &[SemanticMode::Portable]),
    ];

    /// Returns the admitted modes of one target kind, in `GNT-3.1` order.
    #[must_use]
    pub fn admitted_modes(kind: TargetKind) -> &'static [SemanticMode] {
        Self::TABLE
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .map(|(_, modes)| *modes)
            .unwrap_or(&[])
    }

    /// Returns whether one target kind admits one semantic mode.
    #[must_use]
    pub fn admits(kind: TargetKind, mode: SemanticMode) -> bool {
        Self::admitted_modes(kind).contains(&mode)
    }

    /// Admits one mode for one target kind, or reports it unadmitted.
    ///
    /// A mode the selected target kind does not admit fails before semantic
    /// analysis of an executable begins and is never substituted by another
    /// mode or another target.
    pub fn admit_mode(kind: TargetKind, mode: SemanticMode) -> Result<(), TargetError> {
        if Self::admits(kind, mode) {
            return Ok(());
        }
        Err(TargetError::ModeNotAdmitted { kind, mode })
    }
}

/// One declared target-dependent generated output of one artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GeneratedOutput {
    /// The declared output name, which is never a host path.
    pub name: Arc<str>,
    /// The declared hash of the generated output.
    pub hash: GeneratedOutputHash,
}

impl GeneratedOutput {
    /// Validates one declared generated output.
    pub fn new(name: &str, hash: &GeneratedOutputHash) -> Result<Self, TargetError> {
        validate_output_name(name)?;
        Ok(Self {
            name: Arc::from(name),
            hash: hash.clone(),
        })
    }
}

/// The canonically ordered declared generated outputs of one artifact.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneratedOutputSet(Vec<GeneratedOutput>);

impl GeneratedOutputSet {
    /// Builds one canonical output set from declarations in any order.
    ///
    /// The declared set, not its enumeration, is bound by artifact identity; two
    /// declarations that name one output with two different hashes are
    /// contradictory and are rejected rather than repaired.
    pub fn new(outputs: &[GeneratedOutput]) -> Result<Self, TargetError> {
        let mut outputs = outputs.to_vec();
        for output in &outputs {
            validate_output_name(&output.name)?;
            GeneratedOutputHash::from_hex(output.hash.as_str())?;
        }
        outputs.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.hash.cmp(&right.hash))
        });
        for pair in outputs.windows(2) {
            if pair[0].name == pair[1].name && pair[0].hash != pair[1].hash {
                return Err(TargetError::ArtifactBindingMismatch {
                    field: "generated_outputs",
                    expected: Arc::from(pair[0].hash.as_str()),
                    observed: Arc::from(pair[1].hash.as_str()),
                });
            }
        }
        outputs.dedup();
        Ok(Self(outputs))
    }

    /// Returns the empty output set of an artifact that declares none.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the declared outputs in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[GeneratedOutput] {
        &self.0
    }

    /// Returns whether no generated output is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of distinct declared outputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Validates one declared generated-output name.
fn validate_output_name(name: &str) -> Result<(), TargetError> {
    validate_declared_name("generated output", name)?;
    if name.contains([':', ';', '=']) {
        return Err(TargetError::DeclarationInvalid {
            field: "generated output",
            value: Arc::from(name),
        });
    }
    Ok(())
}

/// The declared inputs one artifact must bind (`GNT-17.11-target-artifact-binding`).
///
/// The expected inputs are the selected target kind, the selected descriptor,
/// the selected feature solution, every evaluated predicate outcome, the
/// target-dependent generated outputs, the toolchain identity, and the admitted
/// semantic mode. Changing any of them MUST change artifact identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedInputs {
    kind: TargetKind,
    descriptor: ExecutionTargetDescriptor,
    solution: FeatureSolution,
    outcomes: PredicateOutcomeSet,
    outputs: GeneratedOutputSet,
    toolchain: ToolchainIdentity,
    mode: SemanticMode,
}

impl ExpectedInputs {
    /// Constructs one complete expected-input record.
    ///
    /// The expected mode is the mode the selected target kind admits and the
    /// exact mode the selected descriptor names, so an input record cannot
    /// declare a mode the target does not admit.
    pub fn new(
        kind: TargetKind,
        descriptor: ExecutionTargetDescriptor,
        solution: FeatureSolution,
        outcomes: PredicateOutcomeSet,
        outputs: GeneratedOutputSet,
        toolchain: ToolchainIdentity,
        mode: SemanticMode,
    ) -> Result<Self, TargetError> {
        ModeAdmission::admit_mode(kind, mode)?;
        if descriptor.mode() != mode {
            return Err(TargetError::ArtifactBindingMismatch {
                field: "semantic_mode",
                expected: Arc::from(descriptor.mode().wire_name()),
                observed: Arc::from(mode.wire_name()),
            });
        }
        Ok(Self {
            kind,
            descriptor,
            solution,
            outcomes,
            outputs,
            toolchain,
            mode,
        })
    }

    /// Returns the selected target kind.
    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    /// Returns the selected descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ExecutionTargetDescriptor {
        &self.descriptor
    }

    /// Returns the selected feature solution.
    #[must_use]
    pub const fn solution(&self) -> &FeatureSolution {
        &self.solution
    }

    /// Returns every evaluated predicate outcome of this selection.
    #[must_use]
    pub const fn outcomes(&self) -> &PredicateOutcomeSet {
        &self.outcomes
    }

    /// Returns the declared generated outputs of this selection.
    #[must_use]
    pub const fn outputs(&self) -> &GeneratedOutputSet {
        &self.outputs
    }

    /// Returns the opaque toolchain identity of this selection.
    #[must_use]
    pub const fn toolchain(&self) -> &ToolchainIdentity {
        &self.toolchain
    }

    /// Returns the admitted semantic mode of this selection.
    #[must_use]
    pub const fn mode(&self) -> SemanticMode {
        self.mode
    }

    /// Binds every input of this record into one artifact binding.
    pub fn bind(&self) -> Result<TargetArtifactBinding, TargetError> {
        TargetArtifactBinding::new(
            self.descriptor.version(),
            self.descriptor.digest(),
            self.solution.digest().clone(),
            self.outcomes.digest(),
            self.outputs.clone(),
            self.toolchain.clone(),
            self.mode,
        )
    }
}

/// The record of every target input one artifact was produced from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetArtifactBinding {
    descriptor_version: u32,
    descriptor: TargetDescriptorDigest,
    features: FeatureSolutionDigest,
    predicates: PredicateOutcomeDigest,
    outputs: GeneratedOutputSet,
    toolchain: ToolchainIdentity,
    mode: SemanticMode,
    canonical: Arc<[u8]>,
}

impl TargetArtifactBinding {
    /// Binds every input of one artifact, rejecting an unsupported version.
    pub fn new(
        descriptor_version: u32,
        descriptor: TargetDescriptorDigest,
        features: FeatureSolutionDigest,
        predicates: PredicateOutcomeDigest,
        outputs: GeneratedOutputSet,
        toolchain: ToolchainIdentity,
        mode: SemanticMode,
    ) -> Result<Self, TargetError> {
        if descriptor_version != ExecutionTargetDescriptor::VERSION {
            return Err(TargetError::DescriptorVersionUnsupported {
                version: descriptor_version,
            });
        }
        let canonical = encode_artifact_binding(
            descriptor_version,
            &descriptor,
            &features,
            &predicates,
            &outputs,
            &toolchain,
            mode,
        );
        Ok(Self {
            descriptor_version,
            descriptor,
            features,
            predicates,
            outputs,
            toolchain,
            mode,
            canonical: Arc::from(canonical.into_boxed_slice()),
        })
    }

    /// Returns the bound descriptor version.
    #[must_use]
    pub const fn descriptor_version(&self) -> u32 {
        self.descriptor_version
    }

    /// Returns the bound normalized descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> &TargetDescriptorDigest {
        &self.descriptor
    }

    /// Returns the bound feature-solution digest.
    #[must_use]
    pub const fn feature_solution_digest(&self) -> &FeatureSolutionDigest {
        &self.features
    }

    /// Returns the bound predicate-outcome digest.
    #[must_use]
    pub const fn predicate_outcome_digest(&self) -> &PredicateOutcomeDigest {
        &self.predicates
    }

    /// Returns the bound generated outputs.
    #[must_use]
    pub const fn generated_outputs(&self) -> &GeneratedOutputSet {
        &self.outputs
    }

    /// Returns the bound opaque toolchain identity.
    #[must_use]
    pub const fn toolchain(&self) -> &ToolchainIdentity {
        &self.toolchain
    }

    /// Returns the bound admitted semantic mode.
    #[must_use]
    pub const fn mode(&self) -> SemanticMode {
        self.mode
    }

    /// Returns the one canonical byte encoding of this binding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the digest over those canonical bytes.
    #[must_use]
    pub fn digest(&self) -> TargetArtifactBindingDigest {
        TargetArtifactBindingDigest::from_digest(digest_fields(
            ARTIFACT_BINDING_DOMAIN,
            &[&self.canonical],
        ))
    }

    /// Checks every bound input against one expected-input record.
    ///
    /// A differing input is reported as expected and observed rather than
    /// repaired, in a fixed input order, so a binding is never silently
    /// reconciled with the inputs it disagrees with.
    pub fn check_matches(&self, expected: &ExpectedInputs) -> Result<(), TargetError> {
        let mismatch = |field: &'static str, expected: String, observed: String| {
            Err(TargetError::ArtifactBindingMismatch {
                field,
                expected: Arc::from(expected.as_str()),
                observed: Arc::from(observed.as_str()),
            })
        };
        if self.descriptor_version != expected.descriptor.version() {
            return mismatch(
                "descriptor_version",
                expected.descriptor.version().to_string(),
                self.descriptor_version.to_string(),
            );
        }
        if self.descriptor != expected.descriptor.digest() {
            return mismatch(
                "descriptor_sha256",
                expected.descriptor.digest().as_str().to_owned(),
                self.descriptor.as_str().to_owned(),
            );
        }
        if self.features != *expected.solution.digest() {
            return mismatch(
                "feature_solution_sha256",
                expected.solution.digest().as_str().to_owned(),
                self.features.as_str().to_owned(),
            );
        }
        if self.predicates != expected.outcomes.digest() {
            return mismatch(
                "predicate_outcomes_sha256",
                expected.outcomes.digest().as_str().to_owned(),
                self.predicates.as_str().to_owned(),
            );
        }
        if self.outputs != expected.outputs {
            return mismatch(
                "generated_outputs",
                outputs_text(&expected.outputs),
                outputs_text(&self.outputs),
            );
        }
        if self.toolchain != expected.toolchain {
            return mismatch(
                "toolchain_sha256",
                expected.toolchain.as_str().to_owned(),
                self.toolchain.as_str().to_owned(),
            );
        }
        if self.mode != expected.mode {
            return mismatch(
                "mode",
                expected.mode.wire_name().to_owned(),
                self.mode.wire_name().to_owned(),
            );
        }
        ModeAdmission::admit_mode(expected.kind, self.mode)?;
        Ok(())
    }

    /// Returns the versioned wire record of this binding.
    #[must_use]
    pub fn record(&self) -> TargetArtifactBindingRecord {
        TargetArtifactBindingRecord::from_binding(self)
    }
}

/// One decoded, versioned, closed target artifact-binding record.
///
/// A record that carries a property this version does not define, records one
/// property twice, omits a bound input, or names an unsupported version is
/// rejected rather than repaired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetArtifactBindingRecord {
    version: u32,
    properties: BTreeMap<Arc<str>, Arc<str>>,
}

impl TargetArtifactBindingRecord {
    /// The only supported artifact-binding-record version.
    pub const VERSION: u32 = 1;

    /// The closed property vocabulary of an artifact-binding record.
    pub const PROPERTIES: [&'static str; 7] = [
        "descriptor_sha256",
        "descriptor_version",
        "feature_solution_sha256",
        "generated_outputs",
        "mode",
        "predicate_outcomes_sha256",
        "toolchain_sha256",
    ];

    /// Decodes one closed artifact-binding record, rejecting unknown properties.
    pub fn new(version: u32, properties: &[(&str, &str)]) -> Result<Self, TargetError> {
        if version != Self::VERSION {
            return Err(TargetError::ArtifactBindingVersionUnsupported { version });
        }
        let mut decoded = BTreeMap::new();
        for (key, value) in properties {
            if !Self::PROPERTIES.contains(key) {
                return Err(TargetError::ArtifactBindingPropertyUnknown {
                    property: Arc::from(*key),
                });
            }
            if decoded.insert(Arc::from(*key), Arc::from(*value)).is_some() {
                return Err(TargetError::ArtifactBindingPropertyDuplicate {
                    property: Arc::from(*key),
                });
            }
        }
        Ok(Self {
            version,
            properties: decoded,
        })
    }

    /// Encodes one binding as the record of its own version.
    #[must_use]
    pub fn from_binding(binding: &TargetArtifactBinding) -> Self {
        let descriptor_version = version_number(binding.descriptor_version);
        let generated_outputs = outputs_text(&binding.outputs);
        let properties = [
            ("descriptor_sha256", binding.descriptor.as_str()),
            ("descriptor_version", descriptor_version.as_str()),
            ("feature_solution_sha256", binding.features.as_str()),
            ("generated_outputs", generated_outputs.as_str()),
            ("mode", binding.mode.wire_name()),
            ("predicate_outcomes_sha256", binding.predicates.as_str()),
            ("toolchain_sha256", binding.toolchain.as_str()),
        ];
        Self {
            version: Self::VERSION,
            properties: properties
                .into_iter()
                .map(|(key, value)| (Arc::from(key), Arc::from(value)))
                .collect(),
        }
    }

    /// Returns the record version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns one recorded property value.
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(AsRef::as_ref)
    }

    /// Proves one binding of this record, or reports the missing bound input.
    pub fn binding(&self) -> Result<TargetArtifactBinding, TargetError> {
        let version_text = self.required("descriptor_version")?;
        let descriptor_version =
            version_text
                .parse::<u32>()
                .map_err(|_| TargetError::WireValueUnknown {
                    field: "descriptor_version",
                    value: Arc::from(version_text),
                })?;
        let descriptor = TargetDescriptorDigest::from_hex(self.required("descriptor_sha256")?)?;
        let features = FeatureSolutionDigest::from_hex(self.required("feature_solution_sha256")?)?;
        let predicates =
            PredicateOutcomeDigest::from_hex(self.required("predicate_outcomes_sha256")?)?;
        let toolchain = ToolchainIdentity::from_hex(self.required("toolchain_sha256")?)?;
        let mode = SemanticMode::from_wire_name(self.required("mode")?).ok_or(
            TargetError::WireValueUnknown {
                field: "mode",
                value: Arc::from(self.required("mode")?),
            },
        )?;
        let mut outputs = Vec::new();
        let text = self.required("generated_outputs")?;
        if !text.is_empty() {
            for entry in text.split(';') {
                let (name, hash) =
                    entry
                        .split_once(':')
                        .ok_or(TargetError::DeclarationInvalid {
                            field: "generated output",
                            value: Arc::from(entry),
                        })?;
                outputs.push(GeneratedOutput {
                    name: Arc::from(name),
                    hash: GeneratedOutputHash::from_hex(hash)?,
                });
            }
        }
        TargetArtifactBinding::new(
            descriptor_version,
            descriptor,
            features,
            predicates,
            GeneratedOutputSet::new(&outputs)?,
            toolchain,
            mode,
        )
    }

    /// Returns one required bound input or reports it missing.
    fn required(&self, input: &'static str) -> Result<&str, TargetError> {
        self.property(input)
            .ok_or(TargetError::ArtifactBindingMissingInput { input })
    }
}

/// Returns the canonical decimal text of one record version.
fn version_number(version: u32) -> String {
    version.to_string()
}

/// Returns the canonical `major.minor` text of one protocol version.
fn version_text(version: ProtocolVersion) -> String {
    format!("{}.{}", version.major, version.minor)
}

/// Parses one exact `major.minor` standard-library contract version.
fn parse_protocol_version(
    field: &'static str,
    value: &str,
) -> Result<ProtocolVersion, TargetError> {
    let unknown = || TargetError::WireValueUnknown {
        field,
        value: Arc::from(value),
    };
    let (major, minor) = value.split_once('.').ok_or_else(unknown)?;
    let major = major.parse::<u64>().map_err(|_| unknown())?;
    let minor = minor.parse::<u64>().map_err(|_| unknown())?;
    ProtocolVersion::new(major, minor).map_err(|_| unknown())
}

/// Appends one JSON string literal with the canonical escapes.
fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            scalar if scalar <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", scalar as u32));
            }
            scalar => output.push(scalar),
        }
    }
    output.push('"');
}

/// Returns the one canonical encoding of one descriptor.
fn encode_descriptor(
    architecture: Architecture,
    operating_system: OperatingSystemFamily,
    abi_environment: AbiEnvironment,
    language_edition: &str,
    stdlib_contract: ProtocolVersion,
    mode: SemanticMode,
) -> Vec<u8> {
    let mut output = String::from("{\"abi\":");
    push_json_string(&mut output, abi_environment.wire_name());
    output.push_str(",\"architecture\":");
    push_json_string(&mut output, architecture.wire_name());
    output.push_str(",\"edition\":");
    push_json_string(&mut output, language_edition);
    output.push_str(",\"os_family\":");
    push_json_string(&mut output, operating_system.wire_name());
    output.push_str(",\"semantic_mode\":");
    push_json_string(&mut output, mode.wire_name());
    output.push_str(",\"stdlib_contract\":{\"major\":");
    output.push_str(&stdlib_contract.major.to_string());
    output.push_str(",\"minor\":");
    output.push_str(&stdlib_contract.minor.to_string());
    output.push_str("},\"version_of_record\":");
    output.push_str(&ExecutionTargetDescriptor::VERSION.to_string());
    output.push('}');
    output.into_bytes()
}

/// Returns the one canonical encoding of one selected feature solution.
fn encode_feature_solution(selected: &[FeatureName]) -> Vec<u8> {
    let mut output = String::from("{\"features\":[");
    for (index, name) in selected.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, name.as_str());
    }
    output.push_str(",\"version_of_record\":1}");
    output.into_bytes()
}

/// Returns the one canonical encoding of one target-facts record.
fn encode_target_facts(
    descriptor_version: u32,
    descriptor: &TargetDescriptorDigest,
    features: &FeatureSolutionDigest,
) -> Vec<u8> {
    let mut output = String::from("{\"descriptor_sha256\":");
    push_json_string(&mut output, descriptor.as_str());
    output.push_str(",\"descriptor_version\":");
    output.push_str(&descriptor_version.to_string());
    output.push_str(",\"feature_solution_sha256\":");
    push_json_string(&mut output, features.as_str());
    output.push_str(",\"version_of_record\":1}");
    output.into_bytes()
}

/// Returns the one canonical encoding of one predicate-outcome set.
fn encode_predicate_outcomes(outcomes: &PredicateOutcomeSet) -> Vec<u8> {
    let mut output = String::from("[");
    for (index, outcome) in outcomes.as_slice().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"matched\":");
        output.push_str(if outcome.matched { "true" } else { "false" });
        output.push_str(",\"predicate\":");
        push_json_string(&mut output, &outcome.predicate.wire_name());
        output.push('}');
    }
    output.push(']');
    output.into_bytes()
}

/// Returns the canonical `name:hash` text of one generated-output set.
fn outputs_text(outputs: &GeneratedOutputSet) -> String {
    output_text_from(outputs.as_slice())
}

/// Returns the canonical `name:hash` text of one generated-output list.
fn output_text_from(outputs: &[GeneratedOutput]) -> String {
    let mut output = String::new();
    for (index, entry) in outputs.iter().enumerate() {
        if index > 0 {
            output.push(';');
        }
        output.push_str(&entry.name);
        output.push(':');
        output.push_str(entry.hash.as_str());
    }
    output
}

/// Returns the one canonical encoding of one artifact binding.
fn encode_artifact_binding(
    descriptor_version: u32,
    descriptor: &TargetDescriptorDigest,
    features: &FeatureSolutionDigest,
    predicates: &PredicateOutcomeDigest,
    outputs: &GeneratedOutputSet,
    toolchain: &ToolchainIdentity,
    mode: SemanticMode,
) -> Vec<u8> {
    let mut output = String::from("{\"descriptor_sha256\":");
    push_json_string(&mut output, descriptor.as_str());
    output.push_str(",\"descriptor_version\":");
    output.push_str(&descriptor_version.to_string());
    output.push_str(",\"feature_solution_sha256\":");
    push_json_string(&mut output, features.as_str());
    output.push_str(",\"generated_outputs\":[");
    for (index, entry) in outputs.as_slice().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"hash\":");
        push_json_string(&mut output, entry.hash.as_str());
        output.push_str(",\"name\":");
        push_json_string(&mut output, &entry.name);
        output.push('}');
    }
    output.push_str("],\"mode\":");
    push_json_string(&mut output, mode.wire_name());
    output.push_str(",\"predicate_outcomes_sha256\":");
    push_json_string(&mut output, predicates.as_str());
    output.push_str(",\"toolchain_sha256\":");
    push_json_string(&mut output, toolchain.as_str());
    output.push_str(",\"version_of_record\":1}");
    output.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{
        AbiEnvironment, Architecture, ExecutionTargetDescriptor, FeatureDeclaration,
        FeatureDeclarations, ModeAdmission, OperatingSystemFamily, PredicateOutcome,
        PredicateOutcomeSet, TargetDescriptorField, TargetDescriptorRecord, TargetError,
        TargetPredicate,
    };
    use crate::package::{FeatureName, SelectedFeatureSet, TargetKind};
    use gantry_core::mode::SemanticMode;
    use gantry_core::protocol::ProtocolVersion;

    /// Returns one fixture descriptor under the closed version-1 vocabulary.
    fn descriptor() -> ExecutionTargetDescriptor {
        ExecutionTargetDescriptor::new(
            Architecture::X86_64,
            OperatingSystemFamily::Linux,
            AbiEnvironment::Gnu,
            "2026",
            ProtocolVersion::new(1, 0).unwrap_or_else(|_| unreachable!("fixture version")),
            SemanticMode::Portable,
        )
        .unwrap_or_else(|_| unreachable!("fixture descriptor is well formed"))
    }

    /// Returns one fixture feature name.
    fn feature(name: &str) -> FeatureName {
        FeatureName::new(name).unwrap_or_else(|_| unreachable!("fixture feature name"))
    }

    #[test]
    fn one_descriptor_has_one_canonical_encoding_and_digest() {
        let first = descriptor();
        let second = descriptor();
        assert_eq!(first.normalized_bytes(), second.normalized_bytes());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.version(), ExecutionTargetDescriptor::VERSION);
    }

    #[test]
    fn descriptor_record_round_trips_and_rejects_unknown_properties() {
        let descriptor = descriptor();
        let record = descriptor.record();
        assert_eq!(
            record.descriptor(),
            Ok(descriptor.clone()),
            "a record of a descriptor proves that descriptor"
        );
        assert!(matches!(
            TargetDescriptorRecord::new(1, &[("host_path", "/tmp")]),
            Err(TargetError::DescriptorPropertyUnknown { .. })
        ));
        assert!(matches!(
            TargetDescriptorRecord::new(2, &[]),
            Err(TargetError::DescriptorVersionUnsupported { version: 2 })
        ));
    }

    #[test]
    fn predicate_outcomes_are_canonical_and_read_only_the_selection() {
        let descriptor = descriptor();
        let features = SelectedFeatureSet::new(&["async"])
            .unwrap_or_else(|_| unreachable!("fixture features"));
        let field = TargetDescriptorField::Architecture(Architecture::X86_64);
        let empty = TargetDescriptorField::Architecture(Architecture::Aarch64);
        let outcomes = vec![
            PredicateOutcome::new(TargetPredicate::FeatureEnabled(feature("async")), true),
            PredicateOutcome::new(TargetPredicate::DescriptorField(field), true),
        ];
        let permuted = vec![outcomes[1].clone(), outcomes[0].clone()];
        let set = PredicateOutcomeSet::new(&outcomes);
        assert_eq!(set, PredicateOutcomeSet::new(&permuted));
        assert_eq!(set.digest(), PredicateOutcomeSet::new(&permuted).digest());
        assert!(
            !TargetPredicate::DescriptorField(empty)
                .evaluate(&descriptor, &features)
                .matched
        );
    }

    #[test]
    fn feature_declarations_and_mode_admission_reject_offending_inputs() {
        assert!(matches!(
            FeatureDeclarations::new(&[FeatureDeclaration::new("a", false, &["a"])
                .unwrap_or_else(|_| unreachable!("fixture declaration"))]),
            Err(TargetError::FeatureCycle { .. })
        ));
        assert_eq!(
            FeatureDeclarations::new(&[]),
            Ok(FeatureDeclarations::empty())
        );
        assert_eq!(
            ModeAdmission::admit_mode(TargetKind::Binary, SemanticMode::Durable),
            Ok(())
        );
        assert!(matches!(
            ModeAdmission::admit_mode(TargetKind::Test, SemanticMode::Durable),
            Err(TargetError::ModeNotAdmitted { .. })
        ));
    }
}
