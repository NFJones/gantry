//! Public facade for Gantry, Mezzanine's agent-control language.
//!
//! The facade is the supported Rust API boundary. Feature flags describe which
//! implementation layers are compiled, while profile advertisement includes
//! only layers whose conformance gates have closed.

pub mod diagnostic;
#[cfg(feature = "frontend")]
mod validate;

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
pub use profile::{ConformanceProfile, PROFILE_DEFINITIONS, ProfileDefinition};
#[cfg(feature = "frontend")]
pub use validate::{
    ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest, ValidatePackageResult,
};

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
/// The frontend profile is advertised only when its implementation is
/// compiled. Later feature flags do not advertise their profiles until their
/// own conformance gates close.
#[must_use]
pub const fn advertised_profiles() -> &'static [ConformanceProfile] {
    if cfg!(feature = "frontend") {
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
        ConformanceProfile, advertised_profiles, advertises_any_profile, compiled_features,
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
    fn profile_advertisement_is_limited_to_the_closed_frontend_gate() {
        if compiled_features().frontend {
            assert_eq!(advertised_profiles(), [ConformanceProfile::Frontend]);
            assert!(advertises_any_profile());
        } else {
            assert!(advertised_profiles().is_empty());
            assert!(!advertises_any_profile());
        }
    }
}
