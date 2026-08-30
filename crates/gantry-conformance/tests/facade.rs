//! External smoke tests for the public Gantry facade.

use gantry::{ConformanceProfile, advertised_profiles, advertises_any_profile};

#[test]
fn facade_advertises_exactly_the_closed_analyzer_profile_and_prerequisite() {
    assert_eq!(
        advertised_profiles(),
        [ConformanceProfile::Analyzer, ConformanceProfile::Frontend]
    );
    assert!(advertises_any_profile());
}
