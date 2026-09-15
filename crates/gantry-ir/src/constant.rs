//! Pure constant, package-state, and initialization model for `SPEC.md` Section 32.
//!
//! The model records declared constant declarations, declared dependency facts,
//! bounded evaluation work, canonical publication facts, and package-state
//! declarations. It is deliberately not a parser, a formatter, an incremental
//! cache, a linker, a runtime static-storage facility, a host interface, or a
//! durable projection: every decision below is a deterministic function of
//! explicit inputs, and no declaration executes source, observes host state, or
//! acquires authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::TargetKind;
use crate::authority::digest_fields;
use crate::manifest::encode_hex;

/// The Section 32 clauses implemented by this pure model, in declaration order.
pub const CONSTANT_CLAUSES: [&str; 13] = [
    "GNT-32.0-constants-package-state-and-initialization",
    "GNT-32.1-constant-declaration-and-immutability",
    "GNT-32.2-admissible-constant-classes",
    "GNT-32.3-admissible-constant-operations",
    "GNT-32.4-deterministic-bounded-evaluation",
    "GNT-32.5-dependency-ordering-and-cycle-refusal",
    "GNT-32.6-constant-diagnostics",
    "GNT-32.7-atomic-failure-and-no-partial-publication",
    "GNT-32.8-constant-interface-and-artifact-identity",
    "GNT-32.9-sealed-target-and-feature-selection",
    "GNT-32.10-package-load-non-execution",
    "GNT-32.11-application-owned-mutable-state",
    "GNT-32.12-constant-and-package-state-non-claims",
];

/// The inclusive `Int` bound of `GNT-5.1` (`2^53 - 1`).
pub const CONSTANT_INT_LIMIT: i64 = 9_007_199_254_740_991;

/// The maximum admitted canonical path spelling length in bytes.
pub const MAX_CONSTANT_PATH_BYTES: usize = 256;

/// The maximum admitted canonical value encoding length in bytes.
pub const MAX_CONSTANT_VALUE_BYTES: usize = 16_384;

/// A closed admissible constant class of `GNT-32.2-admissible-constant-classes`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantValueClass {
    /// `Bool`.
    Bool,
    /// A declared enum type whose every member is admitted.
    Enum,
    /// Finite `Float`.
    Float,
    /// Exact `Int`.
    Int,
    /// `List<T>` over an admitted member.
    List,
    /// `Option<T>` over an admitted member.
    Option,
    /// `Result<T, E>` over admitted members.
    Result,
    /// `String`.
    String,
    /// A declared struct type whose every member is admitted.
    Struct,
    /// `Tuple<T1, ..., Tn>` over admitted members.
    Tuple,
    /// `Unit`.
    Unit,
}

impl ConstantValueClass {
    /// Every class in exact wire-name order.
    pub const ALL: [Self; 11] = [
        Self::Bool,
        Self::Enum,
        Self::Float,
        Self::Int,
        Self::List,
        Self::Option,
        Self::Result,
        Self::String,
        Self::Struct,
        Self::Tuple,
        Self::Unit,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Enum => "enum",
            Self::Float => "float",
            Self::Int => "int",
            Self::List => "list",
            Self::Option => "option",
            Self::Result => "result",
            Self::String => "string",
            Self::Struct => "struct",
            Self::Tuple => "tuple",
            Self::Unit => "unit",
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

/// One closed reason a class or effect family is refused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantRefusalReason {
    /// Ambient environment, argument, working-directory, or process input.
    AmbientDeploymentInput,
    /// A callable or closure value.
    CallableValue,
    /// A capability, grant, protected reference, or authority token.
    CapabilityValue,
    /// A clock, timer, monotonic instant, or entropy source.
    ClockOrEntropySource,
    /// A collection or iterator family other than `List<T>`.
    CollectionValue,
    /// A live resource, handle, or loan.
    LiveResource,
    /// A model or host operation.
    ModelOrHostOperation,
    /// The sealed model judgment `Decision`.
    SealedModelJudgment,
    /// The sealed operational `OperationError`.
    SealedOperationalError,
    /// A task, channel, or coordination value.
    TaskValue,
}

impl ConstantRefusalReason {
    /// Every refusal reason in exact wire-name order.
    pub const ALL: [Self; 10] = [
        Self::AmbientDeploymentInput,
        Self::CallableValue,
        Self::CapabilityValue,
        Self::ClockOrEntropySource,
        Self::CollectionValue,
        Self::LiveResource,
        Self::ModelOrHostOperation,
        Self::SealedModelJudgment,
        Self::SealedOperationalError,
        Self::TaskValue,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AmbientDeploymentInput => "ambient-deployment-input",
            Self::CallableValue => "callable-value",
            Self::CapabilityValue => "capability-value",
            Self::ClockOrEntropySource => "clock-or-entropy-source",
            Self::CollectionValue => "collection-value",
            Self::LiveResource => "live-resource",
            Self::ModelOrHostOperation => "model-or-host-operation",
            Self::SealedModelJudgment => "sealed-model-judgment",
            Self::SealedOperationalError => "sealed-operational-error",
            Self::TaskValue => "task-value",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.wire_name() == value)
    }
}

/// One closed admissible constant operation of `GNT-32.3-admissible-constant-operations`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantOperation {
    /// Boolean logic over admitted `Bool` operands.
    BooleanLogic,
    /// Comparison over admitted operands.
    Comparison,
    /// An explicit admitted conversion.
    Conversion,
    /// Element projection.
    ElementProjection,
    /// Enum construction.
    EnumConstruction,
    /// Field projection.
    FieldProjection,
    /// Float arithmetic over finite operands.
    FloatArithmetic,
    /// Integer arithmetic over exact operands.
    IntegerArithmetic,
    /// `List` construction.
    ListConstruction,
    /// Literal construction.
    Literal,
    /// `Option` construction.
    OptionConstruction,
    /// Pattern matching over admitted values.
    PatternMatch,
    /// `Result` construction.
    ResultConstruction,
    /// String operation.
    StringOperation,
    /// Struct construction.
    StructConstruction,
    /// Tuple construction.
    TupleConstruction,
}

impl ConstantOperation {
    /// Every operation in exact wire-name order.
    pub const ALL: [Self; 16] = [
        Self::BooleanLogic,
        Self::Comparison,
        Self::Conversion,
        Self::ElementProjection,
        Self::EnumConstruction,
        Self::FieldProjection,
        Self::FloatArithmetic,
        Self::IntegerArithmetic,
        Self::ListConstruction,
        Self::Literal,
        Self::OptionConstruction,
        Self::PatternMatch,
        Self::ResultConstruction,
        Self::StringOperation,
        Self::StructConstruction,
        Self::TupleConstruction,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::BooleanLogic => "boolean-logic",
            Self::Comparison => "comparison",
            Self::Conversion => "conversion",
            Self::ElementProjection => "element-projection",
            Self::EnumConstruction => "enum-construction",
            Self::FieldProjection => "field-projection",
            Self::FloatArithmetic => "float-arithmetic",
            Self::IntegerArithmetic => "integer-arithmetic",
            Self::ListConstruction => "list-construction",
            Self::Literal => "literal",
            Self::OptionConstruction => "option-construction",
            Self::PatternMatch => "pattern-match",
            Self::ResultConstruction => "result-construction",
            Self::StringOperation => "string-operation",
            Self::StructConstruction => "struct-construction",
            Self::TupleConstruction => "tuple-construction",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.wire_name() == value)
    }
}

/// One closed refused constant effect of `GNT-32.3-admissible-constant-operations`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantEffect {
    /// Authority acquisition.
    AuthorityAcquisition,
    /// Capability acquisition.
    CapabilityAcquisition,
    /// Clock observation.
    ClockObservation,
    /// Deployment-input read.
    DeploymentInputRead,
    /// Live-resource operation.
    LiveResourceOperation,
    /// Model operation.
    ModelOperation,
    /// Secure-random draw.
    SecureRandomDraw,
    /// Task operation.
    TaskOperation,
}

impl ConstantEffect {
    /// Every refused effect in exact wire-name order.
    pub const ALL: [Self; 8] = [
        Self::AuthorityAcquisition,
        Self::CapabilityAcquisition,
        Self::ClockObservation,
        Self::DeploymentInputRead,
        Self::LiveResourceOperation,
        Self::ModelOperation,
        Self::SecureRandomDraw,
        Self::TaskOperation,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AuthorityAcquisition => "authority-acquisition",
            Self::CapabilityAcquisition => "capability-acquisition",
            Self::ClockObservation => "clock-observation",
            Self::DeploymentInputRead => "deployment-input-read",
            Self::LiveResourceOperation => "live-resource-operation",
            Self::ModelOperation => "model-operation",
            Self::SecureRandomDraw => "secure-random-draw",
            Self::TaskOperation => "task-operation",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|effect| effect.wire_name() == value)
    }
}

/// The declared admissibility of one constant class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstantAdmissibility {
    /// The class is one of the closed admissible classes.
    Admissible(ConstantValueClass),
    /// The class is refused under one closed refusal reason.
    Refused(ConstantRefusalReason),
}

impl ConstantAdmissibility {
    /// Returns the admissible class, when one is declared.
    #[must_use]
    pub const fn class(self) -> Option<ConstantValueClass> {
        match self {
            Self::Admissible(class) => Some(class),
            Self::Refused(_) => None,
        }
    }
}

/// One declared constant selection of `GNT-32.9-sealed-target-and-feature-selection`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantSelection {
    /// A selection derived from ambient build-host or environment state.
    AmbientBuildHostState,
    /// One sealed feature predicate with its declared activity.
    SealedFeaturePredicate {
        /// Whether the sealed feature predicate selects the declaration.
        active: bool,
    },
    /// One sealed target predicate with its declared activity.
    SealedTargetPredicate {
        /// Whether the sealed target predicate selects the declaration.
        active: bool,
    },
    /// No predicate selects the declaration.
    Unconditional,
}

impl ConstantSelection {
    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AmbientBuildHostState => "ambient-build-host-state",
            Self::SealedFeaturePredicate { .. } => "sealed-feature-predicate",
            Self::SealedTargetPredicate { .. } => "sealed-target-predicate",
            Self::Unconditional => "unconditional",
        }
    }

    /// Returns whether the selection is one of the sealed predicates.
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        matches!(
            self,
            Self::SealedFeaturePredicate { .. } | Self::SealedTargetPredicate { .. }
        )
    }

    /// Returns whether the declaration is selected for evaluation.
    #[must_use]
    pub const fn is_active(self) -> bool {
        match self {
            Self::AmbientBuildHostState => false,
            Self::SealedFeaturePredicate { active } | Self::SealedTargetPredicate { active } => {
                active
            }
            Self::Unconditional => true,
        }
    }
}

/// One declared constant state of `GNT-32.7-atomic-failure-and-no-partial-publication`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantState {
    /// Declared and not yet evaluated.
    Declared,
    /// Evaluated to exactly one canonical value.
    Evaluated,
    /// Refused; no value, interface entry, or artifact contribution exists.
    Refused,
}

impl ConstantState {
    /// Every state in exact wire-name order.
    pub const ALL: [Self; 3] = [Self::Declared, Self::Evaluated, Self::Refused];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Evaluated => "evaluated",
            Self::Refused => "refused",
        }
    }
}

/// One declared package-state class of `GNT-32.10-package-load-non-execution`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PackageStateClass {
    /// A dependency-order startup hook.
    DependencyOrderStartupHook,
    /// An immutable constant.
    ImmutableConstant,
    /// A loader hook.
    LoaderHook,
    /// A mutable package global.
    MutablePackageGlobal,
    /// A source initializer.
    SourceInitializer,
}

impl PackageStateClass {
    /// Every class in exact wire-name order.
    pub const ALL: [Self; 5] = [
        Self::DependencyOrderStartupHook,
        Self::ImmutableConstant,
        Self::LoaderHook,
        Self::MutablePackageGlobal,
        Self::SourceInitializer,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DependencyOrderStartupHook => "dependency-order-startup-hook",
            Self::ImmutableConstant => "immutable-constant",
            Self::LoaderHook => "loader-hook",
            Self::MutablePackageGlobal => "mutable-package-global",
            Self::SourceInitializer => "source-initializer",
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

/// One explicit owner of application state of `GNT-32.11-application-owned-mutable-state`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApplicationStateOwner {
    /// An explicit host capability.
    HostCapability,
    /// A value owned by the application entry.
    MainOwnedValue,
    /// A supervised service task.
    SupervisedServiceTask,
    /// No owner is declared.
    Unowned,
}

impl ApplicationStateOwner {
    /// Every owner in exact wire-name order.
    pub const ALL: [Self; 4] = [
        Self::HostCapability,
        Self::MainOwnedValue,
        Self::SupervisedServiceTask,
        Self::Unowned,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::HostCapability => "host-capability",
            Self::MainOwnedValue => "main-owned-value",
            Self::SupervisedServiceTask => "supervised-service-task",
            Self::Unowned => "unowned",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|owner| owner.wire_name() == value)
    }
}

/// One frozen constant diagnostic of `GNT-32.6-constant-diagnostics`.
///
/// The registry is frozen: each refusal condition owns exactly one spelling, each
/// spelling is anchored to exactly one clause through [`Self::requirement`], and
/// no condition is reported under another condition's spelling.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantDiagnosticCode {
    /// `constant-cycle`
    Cycle,
    /// `constant-inactive-evaluation-refused`
    InactiveEvaluationRefused,
    /// `constant-inadmissible-operation`
    InadmissibleOperation,
    /// `constant-inadmissible-type`
    InadmissibleType,
    /// `constant-interface-identity-mismatch`
    InterfaceIdentityMismatch,
    /// `constant-invalid-conversion`
    InvalidConversion,
    /// `constant-invalid-declaration`
    InvalidDeclaration,
    /// `constant-limit-exceeded`
    LimitExceeded,
    /// `constant-loader-execution-refused`
    LoaderExecutionRefused,
    /// `constant-mutable-package-state-refused`
    MutablePackageStateRefused,
    /// `constant-non-claim-as-guarantee`
    NonClaimAsGuarantee,
    /// `constant-nontermination`
    Nontermination,
    /// `constant-overflow`
    Overflow,
    /// `constant-owner-absent`
    OwnerAbsent,
    /// `constant-partial-publication-refused`
    PartialPublicationRefused,
    /// `constant-unresolved-dependency`
    UnresolvedDependency,
    /// `constant-unsealed-selection-refused`
    UnsealedSelectionRefused,
}

impl ConstantDiagnosticCode {
    /// Every diagnostic in canonical spelling order.
    pub const ALL: [Self; 17] = [
        Self::Cycle,
        Self::InactiveEvaluationRefused,
        Self::InadmissibleOperation,
        Self::InadmissibleType,
        Self::InterfaceIdentityMismatch,
        Self::InvalidConversion,
        Self::InvalidDeclaration,
        Self::LimitExceeded,
        Self::LoaderExecutionRefused,
        Self::MutablePackageStateRefused,
        Self::NonClaimAsGuarantee,
        Self::Nontermination,
        Self::Overflow,
        Self::OwnerAbsent,
        Self::PartialPublicationRefused,
        Self::UnresolvedDependency,
        Self::UnsealedSelectionRefused,
    ];

    /// Returns the frozen diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cycle => "constant-cycle",
            Self::InactiveEvaluationRefused => "constant-inactive-evaluation-refused",
            Self::InadmissibleOperation => "constant-inadmissible-operation",
            Self::InadmissibleType => "constant-inadmissible-type",
            Self::InterfaceIdentityMismatch => "constant-interface-identity-mismatch",
            Self::InvalidConversion => "constant-invalid-conversion",
            Self::InvalidDeclaration => "constant-invalid-declaration",
            Self::LimitExceeded => "constant-limit-exceeded",
            Self::LoaderExecutionRefused => "constant-loader-execution-refused",
            Self::MutablePackageStateRefused => "constant-mutable-package-state-refused",
            Self::NonClaimAsGuarantee => "constant-non-claim-as-guarantee",
            Self::Nontermination => "constant-nontermination",
            Self::Overflow => "constant-overflow",
            Self::OwnerAbsent => "constant-owner-absent",
            Self::PartialPublicationRefused => "constant-partial-publication-refused",
            Self::UnresolvedDependency => "constant-unresolved-dependency",
            Self::UnsealedSelectionRefused => "constant-unsealed-selection-refused",
        }
    }

    /// Strictly decodes one frozen diagnostic spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }

    /// Returns the sole owning requirement clause.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::InvalidDeclaration => CONSTANT_CLAUSES[1],
            Self::InadmissibleType => CONSTANT_CLAUSES[2],
            Self::InadmissibleOperation => CONSTANT_CLAUSES[3],
            Self::LimitExceeded | Self::Nontermination => CONSTANT_CLAUSES[4],
            Self::UnresolvedDependency | Self::Cycle => CONSTANT_CLAUSES[5],
            Self::Overflow | Self::InvalidConversion => CONSTANT_CLAUSES[6],
            Self::PartialPublicationRefused => CONSTANT_CLAUSES[7],
            Self::InterfaceIdentityMismatch => CONSTANT_CLAUSES[8],
            Self::UnsealedSelectionRefused | Self::InactiveEvaluationRefused => CONSTANT_CLAUSES[9],
            Self::LoaderExecutionRefused | Self::MutablePackageStateRefused => CONSTANT_CLAUSES[10],
            Self::OwnerAbsent => CONSTANT_CLAUSES[11],
            Self::NonClaimAsGuarantee => CONSTANT_CLAUSES[12],
        }
    }
}

impl fmt::Display for ConstantDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A typed refusal from the pure constant model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantError {
    code: ConstantDiagnosticCode,
    detail: String,
}

impl ConstantError {
    /// Builds one refusal with its frozen diagnostic and a bounded detail message.
    #[must_use]
    pub fn new(code: ConstantDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen diagnostic code.
    #[must_use]
    pub const fn code(&self) -> ConstantDiagnosticCode {
        self.code
    }

    /// Returns the bounded detail message.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ConstantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for ConstantError {}

/// The four declared nonzero evaluation limits of `GNT-32.4-deterministic-bounded-evaluation`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationLimits {
    fuel: u64,
    depth: u32,
    members: u32,
    encoded_bytes: u64,
}

impl EvaluationLimits {
    /// Declares the four limits; each limit MUST be nonzero.
    pub fn new(
        fuel: u64,
        depth: u32,
        members: u32,
        encoded_bytes: u64,
    ) -> Result<Self, ConstantError> {
        if fuel == 0 || depth == 0 || members == 0 || encoded_bytes == 0 {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::LimitExceeded,
                "every declared evaluation limit must be nonzero",
            ));
        }
        Ok(Self {
            fuel,
            depth,
            members,
            encoded_bytes,
        })
    }

    /// Returns the declared evaluation fuel in steps.
    #[must_use]
    pub const fn fuel(self) -> u64 {
        self.fuel
    }

    /// Returns the declared nesting depth.
    #[must_use]
    pub const fn depth(self) -> u32 {
        self.depth
    }

    /// Returns the declared aggregate member count.
    #[must_use]
    pub const fn members(self) -> u32 {
        self.members
    }

    /// Returns the declared encoded output size in bytes.
    #[must_use]
    pub const fn encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }
}

/// One declared evaluation work record of `GNT-32.4-deterministic-bounded-evaluation`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantWork {
    steps: u64,
    depth: u32,
    members: u32,
    encoded_bytes: u64,
}

impl ConstantWork {
    /// Declares one work record in steps, depth, members, and encoded bytes.
    #[must_use]
    pub const fn new(steps: u64, depth: u32, members: u32, encoded_bytes: u64) -> Self {
        Self {
            steps,
            depth,
            members,
            encoded_bytes,
        }
    }

    /// Returns the declared step count.
    #[must_use]
    pub const fn steps(self) -> u64 {
        self.steps
    }

    /// Returns the declared nesting depth.
    #[must_use]
    pub const fn depth(self) -> u32 {
        self.depth
    }

    /// Returns the declared member count.
    #[must_use]
    pub const fn members(self) -> u32 {
        self.members
    }

    /// Returns the declared encoded size in bytes.
    #[must_use]
    pub const fn encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }

    /// Admits the work record under the declared limits.
    pub fn admit(self, limits: EvaluationLimits) -> Result<(), ConstantError> {
        if self.steps > limits.fuel {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::Nontermination,
                "evaluation fuel was exhausted",
            ));
        }
        if self.depth > limits.depth {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::LimitExceeded,
                "evaluation nesting depth exceeded its declared limit",
            ));
        }
        if self.members > limits.members {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::LimitExceeded,
                "aggregate member count exceeded its declared limit",
            ));
        }
        if self.encoded_bytes > limits.encoded_bytes {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::LimitExceeded,
                "encoded output size exceeded its declared limit",
            ));
        }
        Ok(())
    }
}

/// One declared admissible initializer of `GNT-32.3-admissible-constant-operations`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantExpression {
    path: String,
    operations: Vec<ConstantOperation>,
}

impl ConstantExpression {
    /// Declares one initializer over the closed admissible operation set.
    ///
    /// A refused effect, an empty operation set, and a malformed path are refused.
    pub fn new(
        path: &str,
        operations: &[ConstantOperation],
        effects: &[ConstantEffect],
    ) -> Result<Self, ConstantError> {
        if path.trim().is_empty() || path.len() > MAX_CONSTANT_PATH_BYTES {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                "a constant path must be nonempty and bounded",
            ));
        }
        let refused: BTreeSet<ConstantEffect> = effects.iter().copied().collect();
        if let Some(effect) = refused.iter().next() {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InadmissibleOperation,
                format!(
                    "`{path}` reaches the refused effect `{}`",
                    effect.wire_name()
                ),
            ));
        }
        if operations.is_empty() {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InadmissibleOperation,
                format!("`{path}` declares no admissible operation"),
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            operations: operations.to_vec(),
        })
    }

    /// Returns the declared path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the declared admissible operations.
    #[must_use]
    pub fn operations(&self) -> &[ConstantOperation] {
        &self.operations
    }
}

/// One declared constant of `GNT-32.1-constant-declaration-and-immutability`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantDeclaration {
    path: String,
    class: ConstantValueClass,
    dependencies: BTreeSet<String>,
    exported: bool,
    selection: ConstantSelection,
    state: ConstantState,
}

impl ConstantDeclaration {
    /// Declares one constant over its class, initializer, dependencies, and selection.
    ///
    /// A refused class, an ambient selection, a malformed path, a dependency on the
    /// declaration itself, and an initializer whose path differs are refused.
    pub fn new(
        path: &str,
        admissibility: ConstantAdmissibility,
        expression: &ConstantExpression,
        dependencies: &[&str],
        exported: bool,
        selection: ConstantSelection,
    ) -> Result<Self, ConstantError> {
        if path.trim().is_empty() || path.len() > MAX_CONSTANT_PATH_BYTES {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                "a constant path must be nonempty and bounded",
            ));
        }
        if expression.path() != path {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                format!("`{path}` does not match its initializer path"),
            ));
        }
        let class = match admissibility {
            ConstantAdmissibility::Admissible(class) => class,
            ConstantAdmissibility::Refused(reason) => {
                return Err(ConstantError::new(
                    ConstantDiagnosticCode::InadmissibleType,
                    format!(
                        "`{path}` declares the refused class `{}`",
                        reason.wire_name()
                    ),
                ));
            }
        };
        if !selection.is_sealed() && selection != ConstantSelection::Unconditional {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::UnsealedSelectionRefused,
                format!("`{path}` is selected by ambient build-host state"),
            ));
        }
        let mut declared = BTreeSet::new();
        for dependency in dependencies {
            if *dependency == path {
                return Err(ConstantError::new(
                    ConstantDiagnosticCode::Cycle,
                    format!("`{path}` declares a dependency on itself"),
                ));
            }
            if dependency.trim().is_empty() || dependency.len() > MAX_CONSTANT_PATH_BYTES {
                return Err(ConstantError::new(
                    ConstantDiagnosticCode::InvalidDeclaration,
                    format!("`{path}` declares a malformed dependency"),
                ));
            }
            declared.insert((*dependency).to_owned());
        }
        Ok(Self {
            path: path.to_owned(),
            class,
            dependencies: declared,
            exported,
            selection,
            state: ConstantState::Declared,
        })
    }

    /// Returns the canonical path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the admitted class.
    #[must_use]
    pub const fn class(&self) -> ConstantValueClass {
        self.class
    }

    /// Returns the declared dependencies.
    #[must_use]
    pub fn dependencies(&self) -> &BTreeSet<String> {
        &self.dependencies
    }

    /// Returns whether the constant participates in the public interface.
    #[must_use]
    pub const fn is_exported(&self) -> bool {
        self.exported
    }

    /// Returns the declared selection.
    #[must_use]
    pub const fn selection(&self) -> ConstantSelection {
        self.selection
    }

    /// Returns the declared state.
    #[must_use]
    pub const fn state(&self) -> ConstantState {
        self.state
    }

    /// Marks the declaration evaluated; only [`ConstantPackage`] calls this.
    fn mark_evaluated(&mut self) {
        self.state = ConstantState::Evaluated;
    }

    /// Marks the declaration refused; only [`ConstantPackage`] calls this.
    fn mark_refused(&mut self) {
        self.state = ConstantState::Refused;
    }
}

/// One canonical constant interface entry of `GNT-32.8-constant-interface-and-artifact-identity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantInterfaceEntry {
    path: String,
    class: ConstantValueClass,
    canonical_value: String,
}

impl ConstantInterfaceEntry {
    /// Returns the canonical path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the admitted class.
    #[must_use]
    pub const fn class(&self) -> ConstantValueClass {
        self.class
    }

    /// Returns the canonical encoded value bytes.
    #[must_use]
    pub fn canonical_value(&self) -> &str {
        &self.canonical_value
    }
}

/// One canonical constant interface in canonical path order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantInterface {
    entries: BTreeMap<String, ConstantInterfaceEntry>,
}

impl ConstantInterface {
    /// Returns the entries in canonical path order.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, ConstantInterfaceEntry> {
        &self.entries
    }

    /// Returns the interface identity over the recorded facts only.
    #[must_use]
    pub fn identity(&self) -> ConstantInterfaceIdentity {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(self.entries.len() * 3);
        for entry in self.entries.values() {
            fields.push(entry.path.as_bytes().to_vec());
            fields.push(entry.class.wire_name().as_bytes().to_vec());
            fields.push(entry.canonical_value.as_bytes().to_vec());
        }
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
        ConstantInterfaceIdentity::from_digest(digest_fields(
            "gantry.constant.interface.v1",
            &borrowed,
        ))
    }
}

/// One typed canonical constant-interface identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConstantInterfaceIdentity(Arc<str>);

impl ConstantInterfaceIdentity {
    /// Encodes one accepted digest.
    #[must_use]
    fn from_digest(digest: [u8; 32]) -> Self {
        Self(Arc::from(encode_hex(&digest)))
    }

    /// Returns the exact lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One typed canonical constant-artifact identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConstantArtifactIdentity(Arc<str>);

impl ConstantArtifactIdentity {
    /// Returns the exact lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One published constant artifact binding of `GNT-32.8-constant-interface-and-artifact-identity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantArtifactBinding {
    interface: ConstantInterfaceIdentity,
    targets: Vec<TargetKind>,
    evaluated: Vec<String>,
    identity: ConstantArtifactIdentity,
}

impl ConstantArtifactBinding {
    /// Returns the bound interface identity.
    #[must_use]
    pub const fn interface(&self) -> &ConstantInterfaceIdentity {
        &self.interface
    }

    /// Returns the declared target kinds in canonical order.
    #[must_use]
    pub fn targets(&self) -> &[TargetKind] {
        &self.targets
    }

    /// Returns the evaluated constant paths in canonical order.
    #[must_use]
    pub fn evaluated(&self) -> &[String] {
        &self.evaluated
    }

    /// Returns the artifact identity.
    #[must_use]
    pub const fn identity(&self) -> &ConstantArtifactIdentity {
        &self.identity
    }

    /// Refuses a presented interface identity that differs from the recomputed one.
    pub fn verify_presented_interface(&self, presented: &str) -> Result<(), ConstantError> {
        if presented != self.interface.as_str() {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InterfaceIdentityMismatch,
                format!(
                    "presented interface identity `{presented}` differs from `{}`",
                    self.interface.as_str()
                ),
            ));
        }
        Ok(())
    }
}

/// One declared constant package over its declarations and limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantPackage {
    limits: EvaluationLimits,
    declarations: BTreeMap<String, ConstantDeclaration>,
    externals: BTreeSet<String>,
    values: BTreeMap<String, String>,
    refusals: BTreeMap<String, ConstantDiagnosticCode>,
}

impl ConstantPackage {
    /// Creates an empty package with its declared evaluation limits.
    #[must_use]
    pub fn new(limits: EvaluationLimits) -> Self {
        Self {
            limits,
            declarations: BTreeMap::new(),
            externals: BTreeSet::new(),
            values: BTreeMap::new(),
            refusals: BTreeMap::new(),
        }
    }

    /// Returns the declared evaluation limits.
    #[must_use]
    pub const fn limits(&self) -> EvaluationLimits {
        self.limits
    }

    /// Admits one imported constant path that this package does not evaluate.
    pub fn admit_external(&mut self, path: &str) -> Result<(), ConstantError> {
        if path.trim().is_empty() || path.len() > MAX_CONSTANT_PATH_BYTES {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                "an external constant path must be nonempty and bounded",
            ));
        }
        if self.declarations.contains_key(path) {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                format!("`{path}` is declared in this package"),
            ));
        }
        self.externals.insert(path.to_owned());
        Ok(())
    }

    /// Declares one constant; a duplicate canonical path is refused.
    pub fn declare(&mut self, declaration: ConstantDeclaration) -> Result<(), ConstantError> {
        let path = declaration.path().to_owned();
        if self.declarations.contains_key(&path) {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                format!("`{path}` is declared twice in one package"),
            ));
        }
        self.declarations.insert(path, declaration);
        Ok(())
    }

    /// Returns one declared constant.
    #[must_use]
    pub fn declaration(&self, path: &str) -> Option<&ConstantDeclaration> {
        self.declarations.get(path)
    }

    /// Returns one declared state.
    #[must_use]
    pub fn state(&self, path: &str) -> Option<ConstantState> {
        self.declarations.get(path).map(ConstantDeclaration::state)
    }

    /// Returns the recorded refusal of one declaration.
    #[must_use]
    pub fn refusal(&self, path: &str) -> Option<ConstantDiagnosticCode> {
        self.refusals.get(path).copied()
    }

    /// Returns one deterministic topological evaluation order.
    ///
    /// Unresolved dependencies are refused, and a dependency cycle is refused with
    /// exactly one declared member of the cycle named.
    pub fn evaluation_order(&self) -> Result<Vec<String>, ConstantError> {
        for declaration in self.declarations.values() {
            for dependency in declaration.dependencies() {
                if !self.declarations.contains_key(dependency)
                    && !self.externals.contains(dependency)
                {
                    return Err(ConstantError::new(
                        ConstantDiagnosticCode::UnresolvedDependency,
                        format!(
                            "`{}` declares the unresolved dependency `{dependency}`",
                            declaration.path()
                        ),
                    ));
                }
            }
        }
        let mut emitted: BTreeSet<String> = BTreeSet::new();
        let mut order: Vec<String> = Vec::with_capacity(self.declarations.len());
        while order.len() < self.declarations.len() {
            let mut ready: Option<String> = None;
            for (path, declaration) in &self.declarations {
                if emitted.contains(path) {
                    continue;
                }
                let satisfied = declaration.dependencies().iter().all(|dependency| {
                    !self.declarations.contains_key(dependency) || emitted.contains(dependency)
                });
                if satisfied {
                    ready = Some(path.clone());
                    break;
                }
            }
            match ready {
                Some(path) => {
                    emitted.insert(path.clone());
                    order.push(path);
                }
                None => {
                    let member = self
                        .declarations
                        .keys()
                        .find(|path| !emitted.contains(*path))
                        .cloned()
                        .unwrap_or_default();
                    return Err(ConstantError::new(
                        ConstantDiagnosticCode::Cycle,
                        format!("constant dependency cycle includes `{member}`"),
                    ));
                }
            }
        }
        Ok(order)
    }

    /// Records one evaluation under the declared limits.
    ///
    /// A second evaluation of an immutable constant, an inactive selection, a
    /// refused dependency, a malformed canonical value, and any exceeded limit are
    /// refused, and a refused limit records the declaration's refusal.
    pub fn record_evaluation(
        &mut self,
        path: &str,
        work: ConstantWork,
        canonical_value: &str,
    ) -> Result<(), ConstantError> {
        let (selection, dependencies, state) = {
            let declaration = self.declarations.get(path).ok_or_else(|| {
                ConstantError::new(
                    ConstantDiagnosticCode::UnresolvedDependency,
                    format!("`{path}` names no declared constant"),
                )
            })?;
            (
                declaration.selection(),
                declaration.dependencies().clone(),
                declaration.state(),
            )
        };
        if state != ConstantState::Declared {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                format!("`{path}` is immutable once evaluated or refused"),
            ));
        }
        if !selection.is_active() {
            self.refusals.insert(
                path.to_owned(),
                ConstantDiagnosticCode::InactiveEvaluationRefused,
            );
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InactiveEvaluationRefused,
                format!("`{path}` is not selected and MUST NOT evaluate"),
            ));
        }
        if let Some(refused) = dependencies.iter().find(|dependency| {
            self.declarations
                .get(*dependency)
                .is_some_and(|declaration| declaration.state() == ConstantState::Refused)
        }) {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::PartialPublicationRefused,
                format!("`{path}` depends on the refused constant `{refused}`"),
            ));
        }
        if canonical_value.is_empty() || canonical_value.len() > MAX_CONSTANT_VALUE_BYTES {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                format!("`{path}` has an empty or oversized canonical value"),
            ));
        }
        if let Err(error) = work.admit(self.limits) {
            self.refusals.insert(path.to_owned(), error.code());
            if let Some(declaration) = self.declarations.get_mut(path) {
                declaration.mark_refused();
            }
            return Err(error);
        }
        if let Some(declaration) = self.declarations.get_mut(path) {
            declaration.mark_evaluated();
        }
        self.values
            .insert(path.to_owned(), canonical_value.to_owned());
        Ok(())
    }

    /// Records one refusal for a declared constant.
    pub fn record_refusal(
        &mut self,
        path: &str,
        code: ConstantDiagnosticCode,
    ) -> Result<(), ConstantError> {
        let state = self.state(path).ok_or_else(|| {
            ConstantError::new(
                ConstantDiagnosticCode::UnresolvedDependency,
                format!("`{path}` names no declared constant"),
            )
        })?;
        if state != ConstantState::Declared {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                format!("`{path}` is immutable once evaluated or refused"),
            ));
        }
        self.refusals.insert(path.to_owned(), code);
        if let Some(declaration) = self.declarations.get_mut(path) {
            declaration.mark_refused();
        }
        Ok(())
    }

    /// Returns the canonical interface of every evaluated exported constant.
    ///
    /// A package with any declaration that is not evaluated publishes nothing.
    pub fn interface(&self) -> Result<ConstantInterface, ConstantError> {
        let mut entries: BTreeMap<String, ConstantInterfaceEntry> = BTreeMap::new();
        for (path, declaration) in &self.declarations {
            if declaration.state() != ConstantState::Evaluated {
                return Err(ConstantError::new(
                    ConstantDiagnosticCode::PartialPublicationRefused,
                    format!("`{path}` is not evaluated, so the package publishes nothing"),
                ));
            }
            if !declaration.is_exported() {
                continue;
            }
            let canonical_value = self.values.get(path).cloned().ok_or_else(|| {
                ConstantError::new(
                    ConstantDiagnosticCode::PartialPublicationRefused,
                    format!("`{path}` has no recorded canonical value"),
                )
            })?;
            entries.insert(
                path.clone(),
                ConstantInterfaceEntry {
                    path: path.clone(),
                    class: declaration.class(),
                    canonical_value,
                },
            );
        }
        Ok(ConstantInterface { entries })
    }

    /// Publishes the artifact binding over the interface, targets, and evaluated set.
    pub fn publish(
        &self,
        targets: &[TargetKind],
    ) -> Result<ConstantArtifactBinding, ConstantError> {
        let interface = self.interface()?;
        let identity = interface.identity();
        if targets.is_empty() {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::PartialPublicationRefused,
                "a published constant artifact names at least one target kind",
            ));
        }
        let mut sorted_targets = targets.to_vec();
        sorted_targets.sort_by_key(|kind| kind.wire_name());
        sorted_targets.dedup();
        let evaluated = self
            .declarations
            .iter()
            .filter(|(_, declaration)| declaration.state() == ConstantState::Evaluated)
            .map(|(path, _)| path.clone())
            .collect::<Vec<String>>();
        let class_wire = |class: ConstantValueClass| class.wire_name().as_bytes().to_vec();
        let mut fields: Vec<Vec<u8>> =
            Vec::with_capacity(3 + sorted_targets.len() + evaluated.len());
        fields.push(identity.as_str().as_bytes().to_vec());
        for target in &sorted_targets {
            fields.push(target.wire_name().as_bytes().to_vec());
        }
        for path in &evaluated {
            fields.push(path.as_bytes().to_vec());
            if let Some(declaration) = self.declarations.get(path) {
                fields.push(class_wire(declaration.class()));
            }
        }
        let borrowed = fields.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
        let artifact = ConstantArtifactIdentity(Arc::from(encode_hex(&digest_fields(
            "gantry.constant.artifact.v1",
            &borrowed,
        ))));
        Ok(ConstantArtifactBinding {
            interface: identity,
            targets: sorted_targets,
            evaluated,
            identity: artifact,
        })
    }
}

/// One declared package-load fact of `GNT-32.10-package-load-non-execution`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageLoadFact {
    package: String,
    state_class: PackageStateClass,
}

impl PackageLoadFact {
    /// Declares one package-load fact; any load-time execution or non-constant
    /// package state is refused.
    pub fn new(
        package: &str,
        state_class: PackageStateClass,
        executes_source: bool,
    ) -> Result<Self, ConstantError> {
        admit_package_state(state_class)?;
        if package.trim().is_empty() || package.len() > MAX_CONSTANT_PATH_BYTES {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                "a package name must be nonempty and bounded",
            ));
        }
        if executes_source {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::LoaderExecutionRefused,
                format!("loading `{package}` MUST NOT execute source"),
            ));
        }
        Ok(Self {
            package: package.to_owned(),
            state_class,
        })
    }

    /// Returns the declared package name.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Returns the declared package-state class.
    #[must_use]
    pub const fn state_class(&self) -> PackageStateClass {
        self.state_class
    }
}

/// Admits one package-state class; only an immutable constant is admitted.
pub fn admit_package_state(class: PackageStateClass) -> Result<(), ConstantError> {
    match class {
        PackageStateClass::ImmutableConstant => Ok(()),
        PackageStateClass::MutablePackageGlobal | PackageStateClass::SourceInitializer => {
            Err(ConstantError::new(
                ConstantDiagnosticCode::MutablePackageStateRefused,
                format!("package state `{}` is refused", class.wire_name()),
            ))
        }
        PackageStateClass::LoaderHook | PackageStateClass::DependencyOrderStartupHook => {
            Err(ConstantError::new(
                ConstantDiagnosticCode::LoaderExecutionRefused,
                format!("load-time state `{}` is refused", class.wire_name()),
            ))
        }
    }
}

/// One declared application state of `GNT-32.11-application-owned-mutable-state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationStateDeclaration {
    name: String,
    owner: ApplicationStateOwner,
    mutable: bool,
}

impl ApplicationStateDeclaration {
    /// Declares one application value; mutable state requires one explicit owner.
    pub fn new(
        name: &str,
        owner: ApplicationStateOwner,
        mutable: bool,
    ) -> Result<Self, ConstantError> {
        if name.trim().is_empty() || name.len() > MAX_CONSTANT_PATH_BYTES {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidDeclaration,
                "an application state name must be nonempty and bounded",
            ));
        }
        if mutable && owner == ApplicationStateOwner::Unowned {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::OwnerAbsent,
                format!("mutable application state `{name}` has no owner"),
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            owner,
            mutable,
        })
    }

    /// Returns the declared name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the explicit owner.
    #[must_use]
    pub const fn owner(&self) -> ApplicationStateOwner {
        self.owner
    }

    /// Returns whether the declared value is mutable.
    #[must_use]
    pub const fn is_mutable(&self) -> bool {
        self.mutable
    }
}

/// Admits one exact `Int` constant result within the inclusive `Int` bound.
pub fn checked_int(value: i64) -> Result<i64, ConstantError> {
    match value.checked_abs() {
        Some(absolute) if absolute <= CONSTANT_INT_LIMIT => Ok(value),
        _ => Err(ConstantError::new(
            ConstantDiagnosticCode::Overflow,
            format!("`{value}` is outside the inclusive `Int` range"),
        )),
    }
}

/// Admits one finite `Float` constant result; a non-finite result is refused.
pub fn checked_float(value: f64) -> Result<f64, ConstantError> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(ConstantError::new(
            ConstantDiagnosticCode::Overflow,
            "a non-finite float result is refused",
        ))
    }
}

/// One declared constant conversion of `GNT-32.6-constant-diagnostics`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantConversion {
    from: ConstantValueClass,
    to: ConstantValueClass,
}

impl ConstantConversion {
    /// Declares one conversion; an inexact conversion is refused rather than rounded.
    pub fn new(
        from: ConstantValueClass,
        to: ConstantValueClass,
        exact: bool,
    ) -> Result<Self, ConstantError> {
        if from != to && !exact {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::InvalidConversion,
                format!(
                    "`{}` to `{}` is inexact and is refused",
                    from.wire_name(),
                    to.wire_name()
                ),
            ));
        }
        Ok(Self { from, to })
    }

    /// Returns the source class.
    #[must_use]
    pub const fn from(self) -> ConstantValueClass {
        self.from
    }

    /// Returns the target class.
    #[must_use]
    pub const fn to(self) -> ConstantValueClass {
        self.to
    }
}

/// The closed constant non-claim vocabulary of `GNT-32.12-constant-and-package-state-non-claims`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstantNonClaim {
    /// Incremental or clean-cache equivalence.
    CacheEquivalence,
    /// Compile-time host execution.
    CompileTimeHostExecution,
    /// Constant folding.
    ConstantFolding,
    /// Durable projection of constants.
    DurableProjection,
    /// Evaluation performance.
    EvaluationPerformance,
    /// Formatter behavior.
    FormatterBehavior,
    /// Grammar productions.
    GrammarProduction,
    /// Keyword reservation.
    KeywordReservation,
    /// Linker realization of constants.
    LinkerRealization,
    /// Parser acceptance.
    ParserAcceptance,
    /// Runtime static storage.
    RuntimeStaticStorage,
    /// The absence of host exhaustion that cannot be safely reported.
    UnreportableHostExhaustion,
}

impl ConstantNonClaim {
    /// Every non-claim in exact wire-name order.
    pub const ALL: [Self; 12] = [
        Self::CacheEquivalence,
        Self::CompileTimeHostExecution,
        Self::ConstantFolding,
        Self::DurableProjection,
        Self::EvaluationPerformance,
        Self::FormatterBehavior,
        Self::GrammarProduction,
        Self::KeywordReservation,
        Self::LinkerRealization,
        Self::ParserAcceptance,
        Self::RuntimeStaticStorage,
        Self::UnreportableHostExhaustion,
    ];

    /// Returns the exact portable spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CacheEquivalence => "cache-equivalence",
            Self::CompileTimeHostExecution => "compile-time-host-execution",
            Self::ConstantFolding => "constant-folding",
            Self::DurableProjection => "durable-projection",
            Self::EvaluationPerformance => "evaluation-performance",
            Self::FormatterBehavior => "formatter-behavior",
            Self::GrammarProduction => "grammar-production",
            Self::KeywordReservation => "keyword-reservation",
            Self::LinkerRealization => "linker-realization",
            Self::ParserAcceptance => "parser-acceptance",
            Self::RuntimeStaticStorage => "runtime-static-storage",
            Self::UnreportableHostExhaustion => "unreportable-host-exhaustion",
        }
    }

    /// Strictly decodes one exact portable spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|claim| claim.wire_name() == value)
    }
}

/// The declared constant non-claims of `GNT-32.12-constant-and-package-state-non-claims`.
pub const CONSTANT_NON_CLAIMS: [&str; 12] = [
    "No incremental or clean-cache equivalence: the section declares deterministic evaluation under declared limits and claims no cache relation.",
    "No compile-time host execution: constant evaluation executes no host call, model operation, or adapter.",
    "No constant folding promise: the section admits one closed operation set and claims no optimizer behavior.",
    "No durable projection of constants: no checkpoint, resume, or recovery fact is defined for a constant.",
    "No evaluation performance bound: only declared work limits and refusals are specified.",
    "No formatter behavior: formatting and layout of a declaration remain downstream work.",
    "No grammar production: the section constrains declared facts and promises no syntax production.",
    "No keyword reservation: reserved-word occupancy of a constant spelling is not claimed here.",
    "No linker realization: linking, loading, and interface digests are owned by other sections.",
    "No parser acceptance: source acceptance of a declaration remains downstream work.",
    "No runtime static storage: no process-wide or task-local static exists for a constant.",
    "No freedom from unreportable host exhaustion: resident-memory and CPU exhaustion remain implementation-specific.",
];

/// The declared order of the constant non-claims (`GNT-32.12`).
pub const CONSTANT_NON_CLAIM_ORDER: [ConstantNonClaim; 12] = ConstantNonClaim::ALL;

/// One presented non-claim assertion (`GNT-32.12`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantNonClaimAssertion {
    claim: ConstantNonClaim,
    presented_as_guarantee: bool,
}

impl ConstantNonClaimAssertion {
    /// Records whether one non-claim is presented as a guarantee.
    #[must_use]
    pub const fn new(claim: ConstantNonClaim, presented_as_guarantee: bool) -> Self {
        Self {
            claim,
            presented_as_guarantee,
        }
    }

    /// Returns the non-claim this assertion names.
    #[must_use]
    pub const fn claim(self) -> ConstantNonClaim {
        self.claim
    }

    /// Returns whether the non-claim was presented as a guarantee.
    #[must_use]
    pub const fn presented_as_guarantee(self) -> bool {
        self.presented_as_guarantee
    }
}

/// Refuses any constant non-claim presented as a guarantee.
pub fn check_constant_non_claims(
    assertions: &[ConstantNonClaimAssertion],
) -> Result<(), ConstantError> {
    for assertion in assertions {
        if assertion.presented_as_guarantee() {
            return Err(ConstantError::new(
                ConstantDiagnosticCode::NonClaimAsGuarantee,
                format!(
                    "the non-claim `{}` was presented as a guarantee",
                    assertion.claim().wire_name()
                ),
            ));
        }
    }
    Ok(())
}
