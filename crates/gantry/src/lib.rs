//! Public facade for Gantry, Mezzanine's agent-control language.
//!
//! The facade is the supported Rust API boundary. Feature flags describe which
//! implementation layers are compiled, while profile advertisement remains
//! empty until the corresponding conformance gate closes.

pub use gantry_core::{identity, portable, profile, protocol, source, timestamp, unicode};
#[cfg(feature = "frontend")]
pub use gantry_frontend as frontend;
pub use gantry_host as host;
pub use profile::{ConformanceProfile, PROFILE_DEFINITIONS, ProfileDefinition};

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

/// Reports whether this bootstrap build advertises a conformance profile.
///
/// Feature selection alone is not conformance evidence. This remains `false`
/// until a later profile gate connects an implemented layer to its reviewed
/// evidence and publication artifacts.
#[must_use]
pub const fn advertises_any_profile() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{advertises_any_profile, compiled_features};

    #[test]
    fn facade_features_preserve_required_implications() {
        let features = compiled_features();

        assert!(!features.analyzer || features.frontend);
        assert!(!features.evaluator || features.analyzer);
        assert!(!features.concurrent || features.evaluator);
        assert!(!features.durable || features.evaluator);
    }

    #[test]
    fn feature_selection_does_not_claim_unimplemented_profiles() {
        assert!(!advertises_any_profile());
    }
}
