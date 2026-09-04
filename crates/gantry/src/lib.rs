//! Public facade for Gantry, Mezzanine's agent-control language.
//!
//! The facade is the supported Rust API boundary. Feature flags describe which
//! implementation layers are compiled, while profile advertisement includes
//! only layers whose conformance gates have closed.
//!
//! Generic and trait analysis is available through [`AnalyzePackageResult`].
//! Source authors can use the repository's `docs/generics-and-traits.md` guide;
//! runtime and durable APIs consume only analyzer-produced closed descriptors
//! and direct callable identities.

pub mod diagnostic;
#[cfg(feature = "durable")]
mod durable_lifecycle;
#[cfg(feature = "durable")]
mod durable_start;
#[cfg(feature = "evaluator")]
mod interpreter;
#[cfg(feature = "evaluator")]
mod start;
#[cfg(feature = "frontend")]
mod validate;

#[cfg(feature = "durable")]
pub use durable_lifecycle::{
    DurableCancelExecutionResult, DurableExecutionObservation, DurableExecutionWait,
    DurableJournalOwnerState, DurableLifecycleCoordinator, DurableOwnedExecution,
    DurableOwnedExecutionOpenError, DurableQueryExecutionError, DurableQueryExecutionFailure,
    DurableQueryExecutionRequest, DurableQueryExecutionResult, DurableRunFailure,
    DurableShutdownError, DurableShutdownReport,
};
#[cfg(feature = "durable")]
pub use durable_start::{
    DurableResumeExecutionAccepted, DurableResumeExecutionFailure, DurableResumeExecutionRequest,
    DurableResumeExecutionResult, DurableResumeSourceComparison, DurableRetainedArtifacts,
    DurableStartExecutionAccepted, DurableStartExecutionCoordinator, DurableStartExecutionFailure,
    DurableStartExecutionRequest, DurableStartExecutionResult,
};
#[cfg(feature = "analyzer")]
pub use gantry_analysis as analysis;
pub use gantry_core::{
    canonical_json, event, identity, numeric, portable, profile, protocol, schema, source,
    strict_json, timestamp, unicode, value,
};
#[cfg(feature = "frontend")]
pub use gantry_frontend as frontend;
pub use gantry_host as host;
#[cfg(feature = "analyzer")]
pub use gantry_ir as ir;
#[cfg(feature = "frontend")]
pub use gantry_observe as observe;
#[cfg(feature = "evaluator")]
pub use gantry_runtime as runtime;
#[cfg(all(feature = "durable", feature = "test-support"))]
#[doc(hidden)]
pub use interpreter::DurableHandoffTestGate;
#[cfg(feature = "evaluator")]
pub use interpreter::{
    CancelExecutionError, Interpreter, RunExecutionError, ShutdownError, TaskDriver,
    caller_cancellation_reason, root_task_identity,
};
pub use profile::{
    ConformanceProfile, PROFILE_CLAIMS_ENABLED, PROFILE_DEFINITIONS,
    PROFILE_SPECIFICATION_REVISION, PROFILE_SUPERSEDED_SPECIFICATION_REVISION, ProfileDefinition,
};
#[cfg(feature = "evaluator")]
pub use start::{
    ActionMappingRevision, AgentMappingRevision, MappingRevisions, RootSessionProvenance,
    RootSessionSpecification, RootSessionState, StartExecutionAccepted, StartExecutionCoordinator,
    StartExecutionFailure, StartExecutionRequest, StartExecutionResult, ValidatedEntryInput,
};
#[cfg(feature = "analyzer")]
pub use validate::{
    AnalyzePackageArtifacts, AnalyzePackageError, AnalyzePackageGenericFacts,
    AnalyzePackageRequest, AnalyzePackageResult, AnalyzePackageStatus,
};
#[cfg(feature = "frontend")]
pub use validate::{
    ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest, ValidatePackageResult,
};
#[cfg(feature = "analyzer")]
/// Public semantic-analysis coordinator over the shared package-activity services.
pub type AnalyzePackageCoordinator<'a> = ValidatePackageCoordinator<'a>;

/// Facade features compiled into the current build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledFeatures {
    /// Whether the frontend layer is selected.
    pub frontend: bool,
    /// Whether the analyzer layer is selected.
    pub analyzer: bool,
    /// Whether the sequential evaluator layer is selected.
    pub evaluator: bool,
    /// Whether the concurrent evaluator refinement is selected.
    pub concurrent: bool,
    /// Whether the durable runtime refinement is selected.
    pub durable: bool,
}

/// Returns the facade layers selected at compile time.
#[must_use]
pub const fn compiled_features() -> CompiledFeatures {
    CompiledFeatures {
        frontend: cfg!(feature = "frontend"),
        analyzer: cfg!(feature = "analyzer"),
        evaluator: cfg!(feature = "evaluator"),
        concurrent: cfg!(feature = "concurrent"),
        durable: cfg!(feature = "durable"),
    }
}

/// Returns the conformance profiles advertised by this build.
///
/// The evaluator profile advertises its analyzer and frontend prerequisites
/// plus the supported embedding role. Each standalone concurrent or durable
/// refinement advertises its profile when compiled. A build containing both
/// refinements advertises both profiles after the combined conformance gate.
#[must_use]
pub const fn advertised_profiles() -> &'static [ConformanceProfile] {
    if !PROFILE_CLAIMS_ENABLED {
        return &[];
    }
    if cfg!(all(feature = "concurrent", feature = "durable")) {
        &[
            ConformanceProfile::Analyzer,
            ConformanceProfile::ConcurrentEvaluator,
            ConformanceProfile::DurableRuntime,
            ConformanceProfile::Embedding,
            ConformanceProfile::Evaluator,
            ConformanceProfile::Frontend,
        ]
    } else if cfg!(feature = "concurrent") {
        &[
            ConformanceProfile::Analyzer,
            ConformanceProfile::ConcurrentEvaluator,
            ConformanceProfile::Embedding,
            ConformanceProfile::Evaluator,
            ConformanceProfile::Frontend,
        ]
    } else if cfg!(feature = "durable") {
        &[
            ConformanceProfile::Analyzer,
            ConformanceProfile::DurableRuntime,
            ConformanceProfile::Embedding,
            ConformanceProfile::Evaluator,
            ConformanceProfile::Frontend,
        ]
    } else if cfg!(feature = "evaluator") {
        &[
            ConformanceProfile::Analyzer,
            ConformanceProfile::Embedding,
            ConformanceProfile::Evaluator,
            ConformanceProfile::Frontend,
        ]
    } else if cfg!(feature = "analyzer") {
        &[ConformanceProfile::Analyzer, ConformanceProfile::Frontend]
    } else if cfg!(feature = "frontend") {
        &[ConformanceProfile::Frontend]
    } else {
        &[]
    }
}

/// Reports whether this build advertises at least one conformance profile.
#[must_use]
pub const fn advertises_any_profile() -> bool {
    !advertised_profiles().is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        ConformanceProfile, PROFILE_CLAIMS_ENABLED, advertised_profiles, advertises_any_profile,
        compiled_features,
    };

    #[test]
    fn facade_features_preserve_required_implications() {
        let features = compiled_features();

        assert!(!features.analyzer || features.frontend);
        assert!(!features.evaluator || features.analyzer);
        assert!(!features.concurrent || features.evaluator);
        assert!(!features.durable || features.evaluator);
    }

    #[test]
    fn profile_advertisement_is_limited_to_closed_gates() {
        if !PROFILE_CLAIMS_ENABLED {
            assert!(advertised_profiles().is_empty());
            assert!(!advertises_any_profile());
            return;
        }
        if compiled_features().concurrent && compiled_features().durable {
            assert_eq!(
                advertised_profiles(),
                [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::ConcurrentEvaluator,
                    ConformanceProfile::DurableRuntime,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
            );
            assert!(advertises_any_profile());
        } else if compiled_features().concurrent {
            assert_eq!(
                advertised_profiles(),
                [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::ConcurrentEvaluator,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
            );
            assert!(advertises_any_profile());
        } else if compiled_features().durable {
            assert_eq!(
                advertised_profiles(),
                [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::DurableRuntime,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
            );
            assert!(advertises_any_profile());
        } else if compiled_features().evaluator {
            assert_eq!(
                advertised_profiles(),
                [
                    ConformanceProfile::Analyzer,
                    ConformanceProfile::Embedding,
                    ConformanceProfile::Evaluator,
                    ConformanceProfile::Frontend,
                ]
            );
            assert!(advertises_any_profile());
        } else if compiled_features().analyzer {
            assert_eq!(
                advertised_profiles(),
                [ConformanceProfile::Analyzer, ConformanceProfile::Frontend]
            );
            assert!(advertises_any_profile());
        } else if compiled_features().frontend {
            assert_eq!(advertised_profiles(), [ConformanceProfile::Frontend]);
            assert!(advertises_any_profile());
        } else {
            assert!(advertised_profiles().is_empty());
            assert!(!advertises_any_profile());
        }
    }
}
