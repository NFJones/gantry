//! External smoke tests for the public Gantry facade.

use gantry::{ConformanceProfile, advertised_profiles, advertises_any_profile};

#[test]
fn facade_advertises_the_closed_concurrent_profiles_and_excludes_durability() {
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
}
