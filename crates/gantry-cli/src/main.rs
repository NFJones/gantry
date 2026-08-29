//! Command-line entry point for Gantry.

mod services;

/// Starts the Gantry command-line application.
fn main() {
    let _ = services::SystemIdentitySource;
    let _ = services::SystemUtcClock;
    println!("gantry: agent-control language for Mezzanine");
}
