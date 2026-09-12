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
//! Two kinds of entry point are distinguished here, and the distinction is what
//! keeps `GNT-17.2-descriptor-normalization-and-target-facts` honest.
//!
//! A *value* constructor builds a platform value: the descriptor itself, a
//! digest spelling, the language-edition read of a descriptor-field value, and
//! the `GNT-17.2` target-facts composition with its recorded text and version.
//! A platform value stays instance-free, because an
//! [`ExecutionTargetDescriptor`] describes a target rather than a declaration:
//! embedding a declaring instance in one would stop its normalized descriptor
//! digest from describing the target, and two descriptors of one platform would
//! stop being the same target.
//!
//! A *declaration* constructor or wire-record decode takes the declaring
//! [`PackageIdentity`]: a descriptor record, a sealed-predicate decode, a
//! feature declaration set, feature unification, a generated-output
//! declaration, an expected-input record, an artifact binding and its wire
//! record, and mode admission. Every diagnostic those entry points raise carries
//! that instance, as `GNT-17.12-target-resolution-failure` requires, and the
//! instance is never an input of a canonical encoding or of a digest.
//!
//! One condition of `GNT-17.12-target-resolution-failure` is published without a
//! check here: an unresolvable conditional selection. The decision rule of
//! `GNT-17.6-conditional-selection-rule` is not modelled by this module — the
//! declared predicate metadata of `crate::package` records those conditional
//! forms without resolving them — so
//! [`TargetDiagnosticCode::ConditionalSelectionUnresolved`] is registered and
//! anchored, and raised by nothing yet.
//!
//! Three records stay distinct. [`ExecutionTargetDescriptor`] is the versioned
//! closed record of one execution target, [`TargetFactsRecord`] is the
//! `GNT-17.2` identity composition of descriptor version, normalized descriptor
//! digest, and feature-solution digest, and [`TargetArtifactBinding`] is the
//! `GNT-17.11` record of every input one artifact was produced from. The build
//! host is never an input of any of them under
//! `GNT-17.9-build-host-authority`; a recorded build input is recorded
//! elsewhere, as a declared generator input.

// The diagnostics of this module deliberately carry the declaring package
// instance, descriptor digests, and offending names so a rejected target
// selection reports exactly what it disagreed with and against which declaring
// instance. The declaring instance is boxed so one error stays small enough to
// pass by value; the remaining identity and name fields stay inline, because
// boxing those too would hide identity behind an allocation at every
// construction and match site. This module answers the size lint explicitly
// instead of weakening its own diagnostics.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gantry_core::mode::SemanticMode;
use gantry_core::protocol::ProtocolVersion;

use crate::authority::digest_fields;
use crate::manifest::encode_hex;
use crate::package::{FeatureName, PackageIdentity, TargetKind};

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
/// registry requires. Every condition this module decides has its own code here,
/// each code is anchored to the clause that owns the condition it reports, and
/// no condition is reported under another condition's code. One condition of
/// `GNT-17.12-target-resolution-failure` is the deliberate exception: an
/// unresolvable conditional selection is published as
/// [`Self::ConditionalSelectionUnresolved`] but is raised by no entry point of
/// this module, because the published total rule of
/// `GNT-17.6-conditional-selection-rule` that decides it is not modelled here.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetDiagnosticCode {
    /// `target-artifact-binding-digest-invalid`
    ArtifactBindingDigestInvalid,
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
    /// `target-conditional-selection-unresolved`
    ConditionalSelectionUnresolved,
    /// `target-descriptor-digest-invalid`
    DescriptorDigestInvalid,
    /// `target-descriptor-edition-invalid`
    DescriptorEditionInvalid,
    /// `target-descriptor-property-duplicate`
    DescriptorPropertyDuplicate,
    /// `target-descriptor-property-missing`
    DescriptorPropertyMissing,
    /// `target-descriptor-property-unknown`
    DescriptorPropertyUnknown,
    /// `target-descriptor-version-unsupported`
    DescriptorVersionUnsupported,
    /// `target-facts-text-invalid`
    TargetFactsTextInvalid,
    /// `target-facts-version-unsupported`
    TargetFactsVersionUnsupported,
    /// `target-feature-cycle`
    FeatureCycle,
    /// `target-feature-declaration-duplicate`
    FeatureDeclarationDuplicate,
    /// `target-feature-name-invalid`
    FeatureNameInvalid,
    /// `target-feature-request-unsatisfiable`
    FeatureRequestUnsatisfiable,
    /// `target-feature-solution-instance-mismatch`
    FeatureSolutionInstanceMismatch,
    /// `target-feature-unknown`
    FeatureUnknown,
    /// `target-generated-output-name-invalid`
    GeneratedOutputNameInvalid,
    /// `target-mode-not-admitted`
    ModeNotAdmitted,
    /// `target-predicate-name-unknown`
    PredicateNameUnknown,
    /// `target-wire-value-unknown`
    WireValueUnknown,
}

impl TargetDiagnosticCode {
    /// Every published code, in sorted code order.
    pub const ALL: [Self; 25] = [
        Self::ArtifactBindingDigestInvalid,
        Self::ArtifactBindingMismatch,
        Self::ArtifactBindingMissingInput,
        Self::ArtifactBindingPropertyDuplicate,
        Self::ArtifactBindingPropertyUnknown,
        Self::ArtifactBindingVersionUnsupported,
        Self::ConditionalSelectionUnresolved,
        Self::DescriptorDigestInvalid,
        Self::DescriptorEditionInvalid,
        Self::DescriptorPropertyDuplicate,
        Self::DescriptorPropertyMissing,
        Self::DescriptorPropertyUnknown,
        Self::DescriptorVersionUnsupported,
        Self::TargetFactsTextInvalid,
        Self::TargetFactsVersionUnsupported,
        Self::FeatureCycle,
        Self::FeatureDeclarationDuplicate,
        Self::FeatureNameInvalid,
        Self::FeatureRequestUnsatisfiable,
        Self::FeatureSolutionInstanceMismatch,
        Self::FeatureUnknown,
        Self::GeneratedOutputNameInvalid,
        Self::ModeNotAdmitted,
        Self::PredicateNameUnknown,
        Self::WireValueUnknown,
    ];

    /// Returns the exact frozen code spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactBindingDigestInvalid => "target-artifact-binding-digest-invalid",
            Self::ArtifactBindingMismatch => "target-artifact-binding-mismatch",
            Self::ArtifactBindingMissingInput => "target-artifact-binding-missing-input",
            Self::ArtifactBindingPropertyDuplicate => "target-artifact-binding-property-duplicate",
            Self::ArtifactBindingPropertyUnknown => "target-artifact-binding-property-unknown",
            Self::ArtifactBindingVersionUnsupported => {
                "target-artifact-binding-version-unsupported"
            }
            Self::ConditionalSelectionUnresolved => "target-conditional-selection-unresolved",
            Self::DescriptorDigestInvalid => "target-descriptor-digest-invalid",
            Self::DescriptorEditionInvalid => "target-descriptor-edition-invalid",
            Self::DescriptorPropertyDuplicate => "target-descriptor-property-duplicate",
            Self::DescriptorPropertyMissing => "target-descriptor-property-missing",
            Self::DescriptorPropertyUnknown => "target-descriptor-property-unknown",
            Self::DescriptorVersionUnsupported => "target-descriptor-version-unsupported",
            Self::TargetFactsTextInvalid => "target-facts-text-invalid",
            Self::TargetFactsVersionUnsupported => "target-facts-version-unsupported",
            Self::FeatureCycle => "target-feature-cycle",
            Self::FeatureDeclarationDuplicate => "target-feature-declaration-duplicate",
            Self::FeatureNameInvalid => "target-feature-name-invalid",
            Self::FeatureRequestUnsatisfiable => "target-feature-request-unsatisfiable",
            Self::FeatureSolutionInstanceMismatch => "target-feature-solution-instance-mismatch",
            Self::FeatureUnknown => "target-feature-unknown",
            Self::GeneratedOutputNameInvalid => "target-generated-output-name-invalid",
            Self::ModeNotAdmitted => "target-mode-not-admitted",
            Self::PredicateNameUnknown => "target-predicate-name-unknown",
            Self::WireValueUnknown => "target-wire-value-unknown",
        }
    }

    /// Returns the frozen meaning registered for this code.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::ArtifactBindingDigestInvalid => {
                "A digest or identity spelling bound by an artifact binding is not 64 lowercase hexadecimal digits."
            }
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
            Self::ConditionalSelectionUnresolved => {
                "A conditional selection cannot be resolved under the published total rule of its version."
            }
            Self::DescriptorDigestInvalid => {
                "A digest spelling of a target descriptor or of its target facts is not 64 lowercase hexadecimal digits."
            }
            Self::DescriptorEditionInvalid => {
                "A language-edition spelling is not a legal declared edition name."
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
            Self::TargetFactsTextInvalid => {
                "A recorded target-facts text is not the canonical version:descriptor:features form."
            }
            Self::TargetFactsVersionUnsupported => {
                "A target-facts record names a descriptor version this implementation does not support."
            }
            Self::FeatureCycle => "A feature enabling relation is cyclic.",
            Self::FeatureDeclarationDuplicate => "One package instance declares one feature twice.",
            Self::FeatureNameInvalid => {
                "A feature declaration or a sealed predicate argument is not a legal feature name."
            }
            Self::FeatureRequestUnsatisfiable => {
                "No single selected feature solution satisfies the requested feature set."
            }
            Self::FeatureSolutionInstanceMismatch => {
                "An expected-input record binds a feature solution of another package instance."
            }
            Self::FeatureUnknown => {
                "A feature declaration or a requested feature set names a feature the instance does not declare."
            }
            Self::GeneratedOutputNameInvalid => {
                "A declared generated-output name is not a legal declared name."
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
            Self::ArtifactBindingDigestInvalid
            | Self::ArtifactBindingMismatch
            | Self::ArtifactBindingMissingInput
            | Self::ArtifactBindingPropertyDuplicate
            | Self::ArtifactBindingPropertyUnknown
            | Self::ArtifactBindingVersionUnsupported
            | Self::GeneratedOutputNameInvalid => "GNT-17.11-target-artifact-binding",
            Self::ConditionalSelectionUnresolved => "GNT-17.12-target-resolution-failure",
            Self::DescriptorDigestInvalid
            | Self::TargetFactsTextInvalid
            | Self::TargetFactsVersionUnsupported => {
                "GNT-17.2-descriptor-normalization-and-target-facts"
            }
            Self::DescriptorEditionInvalid
            | Self::DescriptorPropertyDuplicate
            | Self::DescriptorPropertyMissing
            | Self::DescriptorPropertyUnknown
            | Self::DescriptorVersionUnsupported
            | Self::WireValueUnknown => "GNT-17.1-target-descriptor",
            Self::FeatureCycle
            | Self::FeatureDeclarationDuplicate
            | Self::FeatureNameInvalid
            | Self::FeatureUnknown => "GNT-17.4-feature-declaration",
            Self::FeatureRequestUnsatisfiable | Self::FeatureSolutionInstanceMismatch => {
                "GNT-17.5-feature-unification"
            }
            Self::ModeNotAdmitted => "GNT-17.10-target-selected-mode-admission",
            Self::PredicateNameUnknown => "GNT-17.3-sealed-predicates",
        }
    }
}

/// One rejected target, predicate, feature, or binding condition.
///
/// Every variant is a condition this module can decide and none of them is ever
/// repaired: an unsupported version, an unknown property, an unknown wire
/// value, an unknown predicate name, an unresolved conditional selection, a
/// feature cycle, an unknown or duplicate feature, an unsatisfiable feature
/// request, a feature name outside the closed vocabulary, a non-canonical
/// digest, a generated-output name outside the declared vocabulary, an
/// unadmitted mode, a binding mismatch, and a missing binding input are all
/// reported rather than substituted, preferred, or silently discarded, as
/// `GNT-17.12-target-resolution-failure` requires.
///
/// Every variant a declaration or wire-record entry point raises carries the
/// declaring `PackageIdentity` as `instance`, so each rendered diagnostic names
/// the instance that declared the rejected form. The variants of the value
/// constructors — a digest spelling, the language edition of a descriptor value,
/// and the text and version of the `GNT-17.2` target-facts record — are
/// instance-free: the values they reject are platform facts or part of the
/// identity composition, which is decoded while proving a package identity,
/// before that identity exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// A digest or identity spelling bound by an artifact binding is not a
    /// lowercase hexadecimal digest.
    ArtifactBindingDigestInvalid {
        /// The rejected digest or identity text.
        value: Arc<str>,
    },
    /// A recorded binding disagrees with one expected bound input.
    ArtifactBindingMismatch {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The named bound input.
        field: &'static str,
        /// The expected value.
        expected: Arc<str>,
        /// The observed value.
        observed: Arc<str>,
    },
    /// A recorded binding omits a bound input of `GNT-17.11-target-artifact-binding`.
    ArtifactBindingMissingInput {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The omitted bound input.
        input: &'static str,
    },
    /// One artifact-binding-record property recorded twice.
    ArtifactBindingPropertyDuplicate {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The duplicated property name.
        property: Arc<str>,
    },
    /// An artifact-binding-record property this version does not define.
    ArtifactBindingPropertyUnknown {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The unknown property name.
        property: Arc<str>,
    },
    /// An artifact-binding-record version this implementation does not support.
    ArtifactBindingVersionUnsupported {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The unsupported version.
        version: u32,
    },
    /// A conditional selection the published total rule cannot resolve.
    ConditionalSelectionUnresolved {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The conditional declaration site whose selection is unresolvable.
        site: Arc<str>,
        /// The canonical guard spellings that left the selection undecided.
        guards: Vec<Arc<str>>,
    },
    /// A descriptor or target-facts digest that is not 64 lowercase hexadecimal digits.
    DescriptorDigestInvalid {
        /// The rejected digest text.
        value: Arc<str>,
    },
    /// A language-edition spelling that is not a legal declared edition name.
    DescriptorEditionInvalid {
        /// The rejected edition spelling.
        value: Arc<str>,
    },
    /// One descriptor-record property recorded twice.
    DescriptorPropertyDuplicate {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The duplicated property name.
        property: Arc<str>,
    },
    /// A descriptor-record property its version defines and the record omits.
    DescriptorPropertyMissing {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The missing property name.
        property: Arc<str>,
    },
    /// A descriptor-record property this version does not define.
    DescriptorPropertyUnknown {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The unknown property name.
        property: Arc<str>,
    },
    /// A descriptor version this implementation does not support.
    DescriptorVersionUnsupported {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The unsupported version.
        version: u32,
    },
    /// A recorded target-facts text that is not the canonical recorded form.
    TargetFactsTextInvalid {
        /// The rejected target-facts text.
        value: Arc<str>,
    },
    /// A target-facts record that names an unsupported descriptor version.
    TargetFactsVersionUnsupported {
        /// The unsupported descriptor version.
        version: u32,
    },
    /// A cyclic feature enabling relation, reported as one deterministic cycle.
    FeatureCycle {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The offending names, in enabling order from the cycle's least element.
        cycle: Vec<FeatureName>,
    },
    /// One feature declared twice by one package instance.
    FeatureDeclarationDuplicate {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The duplicated feature name.
        name: FeatureName,
    },
    /// A feature spelling outside the closed declared feature vocabulary.
    FeatureNameInvalid {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The rejected feature spelling.
        value: Arc<str>,
    },
    /// A requested feature set that no single solution satisfies.
    FeatureRequestUnsatisfiable {
        /// The declaring package instance whose unification failed.
        instance: Box<PackageIdentity>,
        /// The requested names the instance does not declare, in canonical order.
        requested: Vec<FeatureName>,
    },
    /// A feature solution of another package instance than the one that binds it.
    FeatureSolutionInstanceMismatch {
        /// The declaring package instance that refused the solution.
        instance: Box<PackageIdentity>,
        /// The package instance the offered solution belongs to.
        solution: Box<PackageIdentity>,
    },
    /// A feature name that its declaring package instance does not declare.
    FeatureUnknown {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The unknown feature name.
        name: FeatureName,
    },
    /// A declared generated-output name that is not a legal declared name.
    GeneratedOutputNameInvalid {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The rejected generated-output name.
        value: Arc<str>,
    },
    /// A semantic mode the selected target kind does not admit.
    ModeNotAdmitted {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The selected target kind.
        kind: TargetKind,
        /// The unadmitted mode.
        mode: SemanticMode,
    },
    /// A predicate name outside the sealed predicate vocabulary.
    PredicateNameUnknown {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
        /// The rejected predicate name.
        name: Arc<str>,
    },
    /// A field value outside the closed vocabulary of its record version.
    WireValueUnknown {
        /// The declaring package instance.
        instance: Box<PackageIdentity>,
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
            Self::ArtifactBindingDigestInvalid { .. } => {
                TargetDiagnosticCode::ArtifactBindingDigestInvalid
            }
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
            Self::ConditionalSelectionUnresolved { .. } => {
                TargetDiagnosticCode::ConditionalSelectionUnresolved
            }
            Self::DescriptorDigestInvalid { .. } => TargetDiagnosticCode::DescriptorDigestInvalid,
            Self::DescriptorEditionInvalid { .. } => TargetDiagnosticCode::DescriptorEditionInvalid,
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
            Self::TargetFactsTextInvalid { .. } => TargetDiagnosticCode::TargetFactsTextInvalid,
            Self::TargetFactsVersionUnsupported { .. } => {
                TargetDiagnosticCode::TargetFactsVersionUnsupported
            }
            Self::FeatureCycle { .. } => TargetDiagnosticCode::FeatureCycle,
            Self::FeatureDeclarationDuplicate { .. } => {
                TargetDiagnosticCode::FeatureDeclarationDuplicate
            }
            Self::FeatureNameInvalid { .. } => TargetDiagnosticCode::FeatureNameInvalid,
            Self::FeatureRequestUnsatisfiable { .. } => {
                TargetDiagnosticCode::FeatureRequestUnsatisfiable
            }
            Self::FeatureSolutionInstanceMismatch { .. } => {
                TargetDiagnosticCode::FeatureSolutionInstanceMismatch
            }
            Self::FeatureUnknown { .. } => TargetDiagnosticCode::FeatureUnknown,
            Self::GeneratedOutputNameInvalid { .. } => {
                TargetDiagnosticCode::GeneratedOutputNameInvalid
            }
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
        // Every rendered diagnostic names its frozen code first, so a rendered
        // text identifies the condition a consumer matches on, and every
        // condition a declaration or wire record rejects names the declaring
        // instance it rejected the form for.
        formatter.write_str(self.code().as_str())?;
        formatter.write_str(": ")?;
        match self {
            Self::ArtifactBindingDigestInvalid { value } => write!(
                formatter,
                "digest or identity `{value}` is not lowercase hexadecimal"
            ),
            Self::ArtifactBindingMismatch {
                instance,
                field,
                expected,
                observed,
            } => write!(
                formatter,
                "package `{}` binds input `{field}` as `{observed}` and must bind `{expected}`",
                instance.as_str()
            ),
            Self::ArtifactBindingMissingInput { instance, input } => write!(
                formatter,
                "package `{}` omits the bound input `{input}`",
                instance.as_str()
            ),
            Self::ArtifactBindingPropertyDuplicate { instance, property } => write!(
                formatter,
                "package `{}` records artifact-binding property `{property}` twice",
                instance.as_str()
            ),
            Self::ArtifactBindingPropertyUnknown { instance, property } => write!(
                formatter,
                "package `{}` records artifact-binding property `{property}`, which this version does not define",
                instance.as_str()
            ),
            Self::ArtifactBindingVersionUnsupported { instance, version } => write!(
                formatter,
                "package `{}` names unsupported artifact-binding version {version}",
                instance.as_str()
            ),
            Self::ConditionalSelectionUnresolved {
                instance,
                site,
                guards,
            } => {
                write!(
                    formatter,
                    "package `{}` cannot resolve the conditional selection at `{site}` under guards ",
                    instance.as_str()
                )?;
                write_guard_list(formatter, guards)
            }
            Self::DescriptorDigestInvalid { value } => {
                write!(formatter, "digest `{value}` is not lowercase hexadecimal")
            }
            Self::DescriptorEditionInvalid { value } => {
                write!(
                    formatter,
                    "language edition `{value}` is not a legal edition"
                )
            }
            Self::DescriptorPropertyDuplicate { instance, property } => write!(
                formatter,
                "package `{}` records target-descriptor property `{property}` twice",
                instance.as_str()
            ),
            Self::DescriptorPropertyMissing { instance, property } => write!(
                formatter,
                "package `{}` omits the target-descriptor property `{property}` its version defines",
                instance.as_str()
            ),
            Self::DescriptorPropertyUnknown { instance, property } => write!(
                formatter,
                "package `{}` records target-descriptor property `{property}`, which this version does not define",
                instance.as_str()
            ),
            Self::DescriptorVersionUnsupported { instance, version } => write!(
                formatter,
                "package `{}` names unsupported target-descriptor version {version}",
                instance.as_str()
            ),
            Self::TargetFactsTextInvalid { value } => write!(
                formatter,
                "target-facts text `{value}` is not the canonical version:descriptor:features form"
            ),
            Self::TargetFactsVersionUnsupported { version } => write!(
                formatter,
                "target-facts record names unsupported descriptor version {version}"
            ),
            Self::FeatureCycle { instance, cycle } => {
                write!(
                    formatter,
                    "package `{}` has a cyclic feature enabling relation: ",
                    instance.as_str()
                )?;
                write_feature_list(formatter, cycle)
            }
            Self::FeatureDeclarationDuplicate { instance, name } => write!(
                formatter,
                "package `{}` declares feature `{}` twice",
                instance.as_str(),
                name.as_str()
            ),
            Self::FeatureNameInvalid { instance, value } => write!(
                formatter,
                "package `{}` declares `{value}`, which is not a legal feature name",
                instance.as_str()
            ),
            Self::FeatureRequestUnsatisfiable {
                instance,
                requested,
            } => {
                write!(
                    formatter,
                    "package `{}` cannot unify the requested features ",
                    instance.as_str()
                )?;
                write_feature_list(formatter, requested)
            }
            Self::FeatureSolutionInstanceMismatch { instance, solution } => write!(
                formatter,
                "package `{}` cannot bind the feature solution of package `{}`",
                instance.as_str(),
                solution.as_str()
            ),
            Self::FeatureUnknown { instance, name } => write!(
                formatter,
                "package `{}` names feature `{}`, which it does not declare",
                instance.as_str(),
                name.as_str()
            ),
            Self::GeneratedOutputNameInvalid { instance, value } => write!(
                formatter,
                "package `{}` declares generated output `{value}`, which is not a legal declared name",
                instance.as_str()
            ),
            Self::ModeNotAdmitted {
                instance,
                kind,
                mode,
            } => write!(
                formatter,
                "package `{}` selects the {} target, which does not admit the {} mode",
                instance.as_str(),
                kind.wire_name(),
                mode.wire_name()
            ),
            Self::PredicateNameUnknown { instance, name } => write!(
                formatter,
                "package `{}` names predicate `{name}`, which is not sealed",
                instance.as_str()
            ),
            Self::WireValueUnknown {
                instance,
                field,
                value,
            } => write!(
                formatter,
                "package `{}` records the {field} value `{value}`, which is outside the closed vocabulary",
                instance.as_str()
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

/// Writes one comma-separated list of canonical predicate guard spellings.
fn write_guard_list(formatter: &mut fmt::Formatter<'_>, guards: &[Arc<str>]) -> fmt::Result {
    for (index, guard) in guards.iter().enumerate() {
        if index > 0 {
            formatter.write_str(", ")?;
        }
        formatter.write_str(guard)?;
    }
    Ok(())
}

/// Returns whether one spelling is exactly a lowercase hexadecimal SHA-256 digest.
///
/// One predicate decides the spelling because two clauses own the digests it
/// rejects: the descriptor digest and the target-facts digest belong to
/// `GNT-17.2-descriptor-normalization-and-target-facts`, while the toolchain
/// identity, the declared generated-output hashes, the predicate-outcome
/// digests, and the feature-solution digests belong to
/// `GNT-17.11-target-artifact-binding`. Every caller therefore reports the code
/// of the clause that owns the digest it validates, instead of reporting every
/// spelling under one clause's code.
fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns whether one declared name is a legal declared name.
fn is_declared_name(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

/// Returns whether one declared generated-output name embeds no record syntax.
fn is_output_name(name: &str) -> bool {
    is_declared_name(name) && !name.contains([':', ';', '='])
}

macro_rules! target_digest_type {
    ($name:ident, $invalid:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Decodes one exact lowercase hexadecimal digest.
            pub fn from_hex(value: &str) -> Result<Self, TargetError> {
                if !is_hex_digest(value) {
                    return Err(TargetError::$invalid {
                        value: Arc::from(value),
                    });
                }
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
    DescriptorDigestInvalid,
    "One normalized descriptor digest over a canonical descriptor encoding (GNT-17.2-descriptor-normalization-and-target-facts)."
);
target_digest_type!(
    FeatureSolutionDigest,
    ArtifactBindingDigestInvalid,
    "One digest of one selected feature solution (GNT-17.5-feature-unification)."
);
target_digest_type!(
    TargetFactsDigest,
    DescriptorDigestInvalid,
    "One digest of the target facts of one package instance (GNT-17.2-descriptor-normalization-and-target-facts)."
);
target_digest_type!(
    PredicateOutcomeDigest,
    ArtifactBindingDigestInvalid,
    "One digest of every evaluated predicate outcome of one selection (GNT-17.11-target-artifact-binding)."
);
target_digest_type!(
    GeneratedOutputHash,
    ArtifactBindingDigestInvalid,
    "One declared hash of one target-dependent generated output (GNT-17.11-target-artifact-binding)."
);
target_digest_type!(
    ToolchainIdentity,
    ArtifactBindingDigestInvalid,
    "The opaque identity of the toolchain that produced an artifact (GNT-17.11-target-artifact-binding).\n\nThe content is deliberately unspecified here: toolchain identity is owned by TOOLCHAIN-001, so this model records the identity opaquely and never interprets it."
);
target_digest_type!(
    TargetArtifactBindingDigest,
    ArtifactBindingDigestInvalid,
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
    ///
    /// This is a value constructor and takes no declaring instance: a descriptor
    /// describes a target, and its digest MUST keep describing that target. The
    /// edition rule it enforces is owned by `GNT-17.1-target-descriptor` and is
    /// decided over the descriptor value, so it reports that clause's code.
    pub fn new(
        architecture: Architecture,
        operating_system: OperatingSystemFamily,
        abi_environment: AbiEnvironment,
        language_edition: &str,
        stdlib_contract: ProtocolVersion,
        mode: SemanticMode,
    ) -> Result<Self, TargetError> {
        if !is_declared_name(language_edition) || language_edition.contains('=') {
            return Err(TargetError::DescriptorEditionInvalid {
                value: Arc::from(language_edition),
            });
        }
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
    ///
    /// The declaring package instance is required because every rejection of a
    /// descriptor record is a `GNT-17.12-target-resolution-failure` that MUST
    /// name the instance whose record was rejected.
    pub fn new(
        declaring: &PackageIdentity,
        version: u32,
        properties: &[(&str, &str)],
    ) -> Result<Self, TargetError> {
        if version != Self::VERSION {
            return Err(TargetError::DescriptorVersionUnsupported {
                instance: Box::new(declaring.clone()),
                version,
            });
        }
        let mut decoded = BTreeMap::new();
        for (key, value) in properties {
            if !Self::PROPERTIES.contains(key) {
                return Err(TargetError::DescriptorPropertyUnknown {
                    instance: Box::new(declaring.clone()),
                    property: Arc::from(*key),
                });
            }
            if decoded.insert(Arc::from(*key), Arc::from(*value)).is_some() {
                return Err(TargetError::DescriptorPropertyDuplicate {
                    instance: Box::new(declaring.clone()),
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
    ///
    /// The declaring instance is a parameter rather than a field of this record,
    /// because a decoded descriptor still describes a target and never embeds
    /// the instance that declared it.
    pub fn descriptor(
        &self,
        declaring: &PackageIdentity,
    ) -> Result<ExecutionTargetDescriptor, TargetError> {
        let architecture = Architecture::from_wire_name(self.required(declaring, "architecture")?)
            .ok_or(TargetError::WireValueUnknown {
                instance: Box::new(declaring.clone()),
                field: "architecture",
                value: Arc::from(self.required(declaring, "architecture")?),
            })?;
        let operating_system = OperatingSystemFamily::from_wire_name(
            self.required(declaring, "os_family")?,
        )
        .ok_or(TargetError::WireValueUnknown {
            instance: Box::new(declaring.clone()),
            field: "os_family",
            value: Arc::from(self.required(declaring, "os_family")?),
        })?;
        let abi_environment = AbiEnvironment::from_wire_name(self.required(declaring, "abi")?)
            .ok_or(TargetError::WireValueUnknown {
                instance: Box::new(declaring.clone()),
                field: "abi",
                value: Arc::from(self.required(declaring, "abi")?),
            })?;
        let mode = SemanticMode::from_wire_name(self.required(declaring, "semantic_mode")?).ok_or(
            TargetError::WireValueUnknown {
                instance: Box::new(declaring.clone()),
                field: "semantic_mode",
                value: Arc::from(self.required(declaring, "semantic_mode")?),
            },
        )?;
        let stdlib_contract = parse_protocol_version(
            declaring,
            "stdlib_contract",
            self.required(declaring, "stdlib_contract")?,
        )?;
        ExecutionTargetDescriptor::new(
            architecture,
            operating_system,
            abi_environment,
            self.required(declaring, "edition")?,
            stdlib_contract,
            mode,
        )
    }

    /// Returns one required property or reports it missing under one instance.
    fn required(
        &self,
        declaring: &PackageIdentity,
        key: &'static str,
    ) -> Result<&str, TargetError> {
        self.property(key)
            .ok_or(TargetError::DescriptorPropertyMissing {
                instance: Box::new(declaring.clone()),
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
    /// Constructs one language-edition read under the descriptor's edition rules.
    ///
    /// The edition rule is owned by `GNT-17.1-target-descriptor` and is decided
    /// over the descriptor-field value itself, so this one condition is reported
    /// without a declaring instance: the value it rejects is a platform fact,
    /// exactly as in [`ExecutionTargetDescriptor::new`]. Every other rejection
    /// of a predicate decode names the instance that declared the predicate.
    pub fn language_edition(value: &str) -> Result<Self, TargetError> {
        if !is_declared_name(value) || value.contains('=') {
            return Err(TargetError::DescriptorEditionInvalid {
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
    ///
    /// The declaring package instance is required because a descriptor-field
    /// read outside the closed vocabulary is a
    /// `GNT-17.12-target-resolution-failure` that MUST name the instance that
    /// declared the read.
    pub fn from_wire_name(declaring: &PackageIdentity, value: &str) -> Result<Self, TargetError> {
        let (field, argument) = value.split_once('=').ok_or(TargetError::WireValueUnknown {
            instance: Box::new(declaring.clone()),
            field: "descriptor field",
            value: Arc::from(value),
        })?;
        let unknown = |field: &'static str, argument: &str| TargetError::WireValueUnknown {
            instance: Box::new(declaring.clone()),
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
            "stdlib_contract" => parse_protocol_version(declaring, "stdlib_contract", argument)
                .map(Self::StdlibContract),
            "semantic_mode" => SemanticMode::from_wire_name(argument)
                .map(Self::SemanticMode)
                .ok_or_else(|| unknown("semantic_mode", argument)),
            _ => Err(TargetError::WireValueUnknown {
                instance: Box::new(declaring.clone()),
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
    ///
    /// The declaring package instance is required because every rejection here
    /// is a `GNT-17.12-target-resolution-failure` that MUST name the instance
    /// whose predicate was rejected.
    pub fn decode(
        declaring: &PackageIdentity,
        name: &str,
        argument: &str,
    ) -> Result<Self, TargetError> {
        match TargetPredicateName::from_wire_name(name) {
            Some(TargetPredicateName::DescriptorField) => {
                TargetDescriptorField::from_wire_name(declaring, argument)
                    .map(Self::DescriptorField)
            }
            Some(TargetPredicateName::FeatureEnabled) => FeatureName::new(argument)
                .map(Self::FeatureEnabled)
                .map_err(|_| TargetError::FeatureNameInvalid {
                    instance: Box::new(declaring.clone()),
                    value: Arc::from(argument),
                }),
            None => Err(TargetError::PredicateNameUnknown {
                instance: Box::new(declaring.clone()),
                name: Arc::from(name),
            }),
        }
    }

    /// Evaluates this predicate against one descriptor and one solution.
    ///
    /// The declaring [`FeatureSolution`], not a bare selected set, is the read:
    /// a feature predicate reads the declared features of the instance that
    /// declares the predicate, so a caller cannot evaluate a predicate against
    /// another instance's features.
    #[must_use]
    pub fn evaluate(
        &self,
        descriptor: &ExecutionTargetDescriptor,
        solution: &FeatureSolution,
    ) -> PredicateOutcome {
        let matched = match self {
            Self::DescriptorField(field) => field.matches(descriptor),
            Self::FeatureEnabled(name) => solution.contains(name),
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
    ///
    /// The declared features are read through the declaring solution of one
    /// package instance, so a selection cannot be evaluated against another
    /// instance's features.
    #[must_use]
    pub fn evaluate(
        predicates: &[TargetPredicate],
        descriptor: &ExecutionTargetDescriptor,
        solution: &FeatureSolution,
    ) -> Self {
        let outcomes = predicates
            .iter()
            .map(|predicate| predicate.evaluate(descriptor, solution))
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
    ///
    /// A feature declaration is a manifest declaration of one package instance,
    /// so it takes that instance and names it in every diagnostic it raises.
    pub fn new(
        declaring: &PackageIdentity,
        name: &str,
        default_enabled: bool,
        enables: &[&str],
    ) -> Result<Self, TargetError> {
        let name = FeatureName::new(name).map_err(|_| TargetError::FeatureNameInvalid {
            instance: Box::new(declaring.clone()),
            value: Arc::from(name),
        })?;
        let mut enabled = Vec::with_capacity(enables.len());
        for enabled_name in enables {
            enabled.push(FeatureName::new(enabled_name).map_err(|_| {
                TargetError::FeatureNameInvalid {
                    instance: Box::new(declaring.clone()),
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
    ///
    /// The declaring package instance is used for those diagnostics and is not
    /// stored: this set is a pure declaration set, so two instances that declare
    /// the same features hold equal sets, and unification stays the only
    /// operation that binds a set to one instance.
    pub fn new(
        declaring: &PackageIdentity,
        declarations: &[FeatureDeclaration],
    ) -> Result<Self, TargetError> {
        let mut declarations = declarations.to_vec();
        declarations.sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(pair) = declarations
            .windows(2)
            .find(|pair| pair[0].name == pair[1].name)
        {
            return Err(TargetError::FeatureDeclarationDuplicate {
                instance: Box::new(declaring.clone()),
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
                        instance: Box::new(declaring.clone()),
                        name: enabled.clone(),
                    });
                }
            }
        }
        if let Some(cycle) = find_feature_cycle(&declarations) {
            return Err(TargetError::FeatureCycle {
                instance: Box::new(declaring.clone()),
                cycle,
            });
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
                instance: Box::new(root.clone()),
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
    ///
    /// This record is the `GNT-17.2` identity composition rather than a
    /// declaration, so it stays instance-free: it is decoded while proving a
    /// package identity of `GNT-16.1-package-identity`, before that identity
    /// exists, so no instance can be named for a recorded version this build
    /// does not support. A descriptor wire record, whose instance does exist,
    /// reports the descriptor clause's code for the same condition and names
    /// that instance.
    pub fn new(
        descriptor_version: u32,
        descriptor: TargetDescriptorDigest,
        features: FeatureSolutionDigest,
    ) -> Result<Self, TargetError> {
        if descriptor_version != Self::VERSION {
            return Err(TargetError::TargetFactsVersionUnsupported {
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
        let invalid = || TargetError::TargetFactsTextInvalid {
            value: Arc::from(value),
        };
        let mut parts = value.split(':');
        let (Some(version), Some(descriptor), Some(features)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        if parts.next().is_some() {
            return Err(invalid());
        }
        let version = version.parse::<u32>().map_err(|_| invalid())?;
        let descriptor = TargetDescriptorDigest::from_hex(descriptor).map_err(|_| invalid())?;
        let features = FeatureSolutionDigest::from_hex(features).map_err(|_| invalid())?;
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
    /// The declaring package instance is required because an unadmitted mode is
    /// a `GNT-17.10-target-selected-mode-admission` failure of one declared
    /// selection, and its diagnostic names the instance that made it.
    pub fn admit_mode(
        declaring: &PackageIdentity,
        kind: TargetKind,
        mode: SemanticMode,
    ) -> Result<(), TargetError> {
        if Self::admits(kind, mode) {
            return Ok(());
        }
        Err(TargetError::ModeNotAdmitted {
            instance: Box::new(declaring.clone()),
            kind,
            mode,
        })
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
    ///
    /// A generated output is a declaration of one package instance, so it takes
    /// that instance and names it for every declared name it rejects.
    pub fn new(
        declaring: &PackageIdentity,
        name: &str,
        hash: &GeneratedOutputHash,
    ) -> Result<Self, TargetError> {
        validate_output_name(declaring, name)?;
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
    pub fn new(
        declaring: &PackageIdentity,
        outputs: &[GeneratedOutput],
    ) -> Result<Self, TargetError> {
        let mut outputs = outputs.to_vec();
        for output in &outputs {
            validate_output_name(declaring, &output.name)?;
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
                    instance: Box::new(declaring.clone()),
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
fn validate_output_name(declaring: &PackageIdentity, name: &str) -> Result<(), TargetError> {
    if !is_output_name(name) {
        return Err(TargetError::GeneratedOutputNameInvalid {
            instance: Box::new(declaring.clone()),
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
    /// The expected outcomes are derived here, from the ordered predicate list
    /// of the selection and from the declaring solution, so a record can neither
    /// record an outcome no evaluation produces nor evaluate a predicate against
    /// another instance's features. The expected mode is the mode the selected
    /// target kind admits and the exact mode the selected descriptor names, so
    /// an input record cannot declare a mode the target does not admit.
    ///
    // The declaring instance, the selected kind and descriptor, the declaring
    // solution, the declared predicate list, the declared outputs, the toolchain
    // identity, and the mode are the closed input vocabulary of
    // `GNT-17.11-target-artifact-binding`, so the constructor is kept explicit
    // rather than collapsed into a builder that could omit an input.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        declaring: &PackageIdentity,
        kind: TargetKind,
        descriptor: ExecutionTargetDescriptor,
        solution: FeatureSolution,
        predicates: &[TargetPredicate],
        outputs: GeneratedOutputSet,
        toolchain: ToolchainIdentity,
        mode: SemanticMode,
    ) -> Result<Self, TargetError> {
        if solution.root() != declaring {
            return Err(TargetError::FeatureSolutionInstanceMismatch {
                instance: Box::new(declaring.clone()),
                solution: Box::new(solution.root().clone()),
            });
        }
        ModeAdmission::admit_mode(declaring, kind, mode)?;
        if descriptor.mode() != mode {
            return Err(TargetError::ArtifactBindingMismatch {
                instance: Box::new(declaring.clone()),
                field: "semantic_mode",
                expected: Arc::from(descriptor.mode().wire_name()),
                observed: Arc::from(mode.wire_name()),
            });
        }
        let outcomes = PredicateOutcomeSet::evaluate(predicates, &descriptor, &solution);
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
    ///
    /// The outcomes are the ones this record derived from the declared predicate
    /// list, the selected descriptor, and the declaring solution, so they are
    /// exactly the outcomes one evaluation of this selection produces.
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
    ///
    /// The binding is declared for the instance the selected solution belongs
    /// to, which this record proved is the instance that declared it.
    pub fn bind(&self) -> Result<TargetArtifactBinding, TargetError> {
        TargetArtifactBinding::new(
            self.solution.root(),
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
    ///
    /// The declaring package instance is used for the diagnostics of an
    /// unsupported version and is not stored: a binding records the inputs of
    /// one artifact, and the landed `GNT-17.11-target-artifact-binding` encoding
    /// carries no declaring instance, so the instance cannot change any bound
    /// input or any artifact identity.
    // The bound inputs are the closed vocabulary of
    // `GNT-17.11-target-artifact-binding`, so the constructor stays explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        declaring: &PackageIdentity,
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
                instance: Box::new(declaring.clone()),
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
    ///
    /// The comparison is against the outcomes the expected-input record derived
    /// itself, so a binding that records outcomes no evaluation of this
    /// selection produces is reported rather than accepted.
    pub fn check_matches(&self, expected: &ExpectedInputs) -> Result<(), TargetError> {
        let declaring = expected.solution.root();
        let mismatch = |field: &'static str, expected: String, observed: String| {
            Err(TargetError::ArtifactBindingMismatch {
                instance: Box::new(declaring.clone()),
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
        ModeAdmission::admit_mode(declaring, expected.kind, self.mode)?;
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
    ///
    /// The declaring package instance is required because every rejection of an
    /// artifact-binding record is a `GNT-17.12-target-resolution-failure` that
    /// MUST name the instance whose record was rejected.
    pub fn new(
        declaring: &PackageIdentity,
        version: u32,
        properties: &[(&str, &str)],
    ) -> Result<Self, TargetError> {
        if version != Self::VERSION {
            return Err(TargetError::ArtifactBindingVersionUnsupported {
                instance: Box::new(declaring.clone()),
                version,
            });
        }
        let mut decoded = BTreeMap::new();
        for (key, value) in properties {
            if !Self::PROPERTIES.contains(key) {
                return Err(TargetError::ArtifactBindingPropertyUnknown {
                    instance: Box::new(declaring.clone()),
                    property: Arc::from(*key),
                });
            }
            if decoded.insert(Arc::from(*key), Arc::from(*value)).is_some() {
                return Err(TargetError::ArtifactBindingPropertyDuplicate {
                    instance: Box::new(declaring.clone()),
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
    ///
    /// The declaring instance is a parameter rather than a field of this record,
    /// because the record is a wire record and every binding it proves names the
    /// instance that recorded it.
    pub fn binding(
        &self,
        declaring: &PackageIdentity,
    ) -> Result<TargetArtifactBinding, TargetError> {
        let version_text = self.required(declaring, "descriptor_version")?;
        let descriptor_version =
            version_text
                .parse::<u32>()
                .map_err(|_| TargetError::WireValueUnknown {
                    instance: Box::new(declaring.clone()),
                    field: "descriptor_version",
                    value: Arc::from(version_text),
                })?;
        let descriptor =
            TargetDescriptorDigest::from_hex(self.required(declaring, "descriptor_sha256")?)?;
        let features =
            FeatureSolutionDigest::from_hex(self.required(declaring, "feature_solution_sha256")?)?;
        let predicates = PredicateOutcomeDigest::from_hex(
            self.required(declaring, "predicate_outcomes_sha256")?,
        )?;
        let toolchain = ToolchainIdentity::from_hex(self.required(declaring, "toolchain_sha256")?)?;
        let mode = SemanticMode::from_wire_name(self.required(declaring, "mode")?).ok_or(
            TargetError::WireValueUnknown {
                instance: Box::new(declaring.clone()),
                field: "mode",
                value: Arc::from(self.required(declaring, "mode")?),
            },
        )?;
        let mut outputs = Vec::new();
        let text = self.required(declaring, "generated_outputs")?;
        if !text.is_empty() {
            for entry in text.split(';') {
                let (name, hash) = entry.split_once(':').ok_or(TargetError::WireValueUnknown {
                    instance: Box::new(declaring.clone()),
                    field: "generated_outputs",
                    value: Arc::from(entry),
                })?;
                outputs.push(GeneratedOutput {
                    name: Arc::from(name),
                    hash: GeneratedOutputHash::from_hex(hash)?,
                });
            }
        }
        TargetArtifactBinding::new(
            declaring,
            descriptor_version,
            descriptor,
            features,
            predicates,
            GeneratedOutputSet::new(declaring, &outputs)?,
            toolchain,
            mode,
        )
    }

    /// Returns one required bound input or reports it missing under one instance.
    fn required(
        &self,
        declaring: &PackageIdentity,
        input: &'static str,
    ) -> Result<&str, TargetError> {
        self.property(input)
            .ok_or(TargetError::ArtifactBindingMissingInput {
                instance: Box::new(declaring.clone()),
                input,
            })
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
    declaring: &PackageIdentity,
    field: &'static str,
    value: &str,
) -> Result<ProtocolVersion, TargetError> {
    let unknown = || TargetError::WireValueUnknown {
        instance: Box::new(declaring.clone()),
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
        AbiEnvironment, Architecture, ExecutionTargetDescriptor, ExpectedInputs,
        FeatureDeclaration, FeatureDeclarations, FeatureSolution, FeatureSolutionDigest,
        GeneratedOutput, GeneratedOutputHash, GeneratedOutputSet, ModeAdmission,
        OperatingSystemFamily, PredicateOutcome, PredicateOutcomeSet, TargetArtifactBinding,
        TargetDescriptorDigest, TargetDescriptorField, TargetDescriptorRecord, TargetError,
        TargetFactsRecord, TargetPredicate, ToolchainIdentity,
    };
    use crate::package::{
        CanonicalIrDigest, FeatureName, GeneratorInputs, InterfaceDigest, PackageIdentity,
        PackageIdentityInputs, PackageName, PackageSourceIdentity, PackageVersion,
        SelectedFeatureSet, SourceManifestDigest, TargetFactSet, TargetKind,
    };
    use gantry_core::mode::SemanticMode;
    use gantry_core::protocol::ProtocolVersion;

    /// Returns one fixture 64-character lowercase hexadecimal digest text.
    fn digest_text() -> String {
        "0123456789abcdef".repeat(4)
    }

    /// Returns the declaring package instance of one fixture version.
    fn root_of(version: &str) -> PackageIdentity {
        let digest = digest_text();
        PackageIdentity::derive(PackageIdentityInputs::new(
            PackageName::new("app").unwrap_or_else(|_| unreachable!("fixture name is valid")),
            PackageVersion::new(version)
                .unwrap_or_else(|_| unreachable!("fixture version is valid")),
            PackageSourceIdentity::new(
                SourceManifestDigest::from_hex(&digest)
                    .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
                CanonicalIrDigest::from_hex(&digest)
                    .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
            ),
            SelectedFeatureSet::empty(),
            TargetFactSet::empty(),
            TargetFactsRecord::new(
                1,
                TargetDescriptorDigest::from_hex(&digest)
                    .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
                FeatureSolutionDigest::from_hex(&digest)
                    .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
            )
            .unwrap_or_else(|_| unreachable!("fixture selection names its version")),
            InterfaceDigest::from_hex(&digest)
                .unwrap_or_else(|_| unreachable!("fixture digest is lowercase hexadecimal")),
            GeneratorInputs::empty(),
        ))
    }

    /// Returns the fixture declaring package instance of these tests.
    fn root() -> PackageIdentity {
        root_of("1.0.0")
    }

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

    /// Returns the fixture declarations of the declaring instance.
    fn declarations() -> FeatureDeclarations {
        let declaring = root();
        FeatureDeclarations::new(
            &declaring,
            &[
                FeatureDeclaration::new(&declaring, "io", false, &[])
                    .unwrap_or_else(|_| unreachable!("fixture declaration is well formed")),
                FeatureDeclaration::new(&declaring, "sync", true, &["io"])
                    .unwrap_or_else(|_| unreachable!("fixture declaration is well formed")),
                FeatureDeclaration::new(&declaring, "extra", false, &[])
                    .unwrap_or_else(|_| unreachable!("fixture declaration is well formed")),
            ],
        )
        .unwrap_or_else(|_| unreachable!("fixture declarations are acyclic"))
    }

    /// Returns the fixture selected solution of the declaring instance.
    fn solution() -> FeatureSolution {
        FeatureSolution::unify(&declarations(), &[feature("io")], &root())
            .unwrap_or_else(|_| unreachable!("fixture request is declared"))
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
        let declaring = root();
        let descriptor = descriptor();
        let record = descriptor.record();
        assert_eq!(
            record.descriptor(&declaring),
            Ok(descriptor.clone()),
            "a record of a descriptor proves that descriptor"
        );
        assert!(matches!(
            TargetDescriptorRecord::new(&declaring, 1, &[("host_path", "/tmp")]),
            Err(TargetError::DescriptorPropertyUnknown { instance, property })
                if *instance == declaring && property.as_ref() == "host_path"
        ));
        assert!(matches!(
            TargetDescriptorRecord::new(&declaring, 2, &[]),
            Err(TargetError::DescriptorVersionUnsupported { instance, version: 2 })
                if *instance == declaring
        ));
    }

    #[test]
    fn predicate_outcomes_are_canonical_and_read_only_the_selection() {
        let descriptor = descriptor();
        let solution = solution();
        let field = TargetDescriptorField::Architecture(Architecture::X86_64);
        let empty = TargetDescriptorField::Architecture(Architecture::Aarch64);
        let outcomes = vec![
            PredicateOutcome::new(TargetPredicate::FeatureEnabled(feature("sync")), true),
            PredicateOutcome::new(TargetPredicate::DescriptorField(field), true),
        ];
        let permuted = vec![outcomes[1].clone(), outcomes[0].clone()];
        let set = PredicateOutcomeSet::new(&outcomes);
        assert_eq!(set, PredicateOutcomeSet::new(&permuted));
        assert_eq!(set.digest(), PredicateOutcomeSet::new(&permuted).digest());
        assert!(
            !TargetPredicate::DescriptorField(empty)
                .evaluate(&descriptor, &solution)
                .matched
        );
        // A feature predicate reads the declaring solution's selected features,
        // so a declared feature the solution does not select is unmatched.
        assert!(
            !TargetPredicate::FeatureEnabled(feature("extra"))
                .evaluate(&descriptor, &solution)
                .matched
        );
    }

    #[test]
    fn feature_declarations_and_mode_admission_reject_offending_inputs() {
        let declaring = root();
        assert!(matches!(
            FeatureDeclarations::new(
                &declaring,
                &[FeatureDeclaration::new(&declaring, "a", false, &["a"])
                    .unwrap_or_else(|_| unreachable!("fixture declaration"))]
            ),
            Err(TargetError::FeatureCycle { instance, .. }) if *instance == declaring
        ));
        assert_eq!(
            FeatureDeclarations::new(&declaring, &[]),
            Ok(FeatureDeclarations::empty())
        );
        assert_eq!(
            ModeAdmission::admit_mode(&declaring, TargetKind::Binary, SemanticMode::Durable),
            Ok(())
        );
        assert!(matches!(
            ModeAdmission::admit_mode(&declaring, TargetKind::Test, SemanticMode::Durable),
            Err(TargetError::ModeNotAdmitted { .. })
        ));
    }

    #[test]
    fn expected_inputs_derive_their_own_outcomes_and_bind_them() {
        let declaring = root();
        let predicates = [
            TargetPredicate::DescriptorField(TargetDescriptorField::Architecture(
                Architecture::X86_64,
            )),
            TargetPredicate::FeatureEnabled(feature("extra")),
        ];
        let outputs = GeneratedOutputSet::new(
            &declaring,
            &[GeneratedOutput::new(
                &declaring,
                "schema.json",
                &GeneratedOutputHash::from_digest([7_u8; 32]),
            )
            .unwrap_or_else(|_| unreachable!("fixture output name is legal"))],
        )
        .unwrap_or_else(|_| unreachable!("fixture outputs are well formed"));
        let expected = ExpectedInputs::new(
            &declaring,
            TargetKind::Binary,
            descriptor(),
            solution(),
            &predicates,
            outputs,
            ToolchainIdentity::from_digest([9_u8; 32]),
            SemanticMode::Portable,
        )
        .unwrap_or_else(|_| unreachable!("fixture inputs name an admitted mode"));
        assert_eq!(
            expected.outcomes(),
            &PredicateOutcomeSet::evaluate(&predicates, &descriptor(), &solution())
        );
        assert_eq!(expected.outcomes().len(), 2);
        assert_eq!(
            expected
                .bind()
                .unwrap_or_else(|_| unreachable!("fixture binding is well formed"))
                .check_matches(&expected),
            Ok(())
        );
        // A binding that records outcomes no evaluation of this selection
        // produces is reported against the derived outcomes.
        let unproduced = TargetArtifactBinding::new(
            &declaring,
            ExecutionTargetDescriptor::VERSION,
            descriptor().digest(),
            solution().digest().clone(),
            PredicateOutcomeSet::empty().digest(),
            expected.outputs().clone(),
            expected.toolchain().clone(),
            SemanticMode::Portable,
        )
        .unwrap_or_else(|_| unreachable!("fixture binding is well formed"));
        assert!(matches!(
            unproduced.check_matches(&expected),
            Err(TargetError::ArtifactBindingMismatch { field, .. })
                if field == "predicate_outcomes_sha256"
        ));
        // A solution of another instance cannot be bound to this instance.
        let elsewhere = root_of("2.0.0");
        let foreign = FeatureSolution::unify(&declarations(), &[feature("io")], &elsewhere)
            .unwrap_or_else(|_| unreachable!("fixture request is declared"));
        assert!(matches!(
            ExpectedInputs::new(
                &declaring,
                TargetKind::Binary,
                descriptor(),
                foreign,
                &predicates,
                GeneratedOutputSet::empty(),
                ToolchainIdentity::from_digest([9_u8; 32]),
                SemanticMode::Portable,
            ),
            Err(TargetError::FeatureSolutionInstanceMismatch { instance, solution })
                if *instance == declaring && *solution == elsewhere
        ));
    }
}
