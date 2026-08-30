//! External smoke tests for the public Gantry facade.

use gantry::{ConformanceProfile, advertised_profiles, advertises_any_profile};

#[test]
fn facade_advertises_exactly_the_closed_frontend_profile() {
    assert_eq!(advertised_profiles(), [ConformanceProfile::Frontend]);
    assert!(advertises_any_profile());
}
