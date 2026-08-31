//! External smoke tests for the public Gantry facade.

use gantry::{ConformanceProfile, advertised_profiles, advertises_any_profile};

#[test]
fn facade_advertises_the_closed_sequential_profiles_and_excludes_later_refinements() {
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
}
