//! External smoke tests for the public Gantry facade.

use gantry::{ConformanceProfile, advertised_profiles, advertises_any_profile};

#[test]
fn facade_advertises_both_closed_refinements_in_the_combined_build() {
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
