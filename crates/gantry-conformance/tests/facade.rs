//! External smoke tests for the public Gantry facade.

use gantry::advertises_any_profile;

#[test]
fn facade_does_not_advertise_an_unimplemented_profile() {
    assert!(!advertises_any_profile());
}
