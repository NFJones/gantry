//! External smoke tests for the public Gantry facade.

use gantry::{
    ConformanceProfile, PROFILE_CLAIMS_ENABLED, advertised_profiles, advertises_any_profile,
};

#[test]
fn facade_advertises_both_closed_refinements_in_the_combined_build() {
    if !PROFILE_CLAIMS_ENABLED {
        assert!(advertised_profiles().is_empty());
        assert!(!advertises_any_profile());
        return;
    }
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
}
