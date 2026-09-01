# Default recipe builds in release mode
default:
    cargo build --locked --workspace --all-targets --all-features --release

# Build (debug)
build:
    cargo build --locked --workspace --all-targets --all-features

# Build (release)
build-release:
    cargo build --locked --workspace --all-targets --all-features --release

# Run Gantry
run *args:
    cargo run -p gantry-cli --bin gantry -- {{args}}

# Type-check without building artifacts
check:
    cargo check --locked --workspace --all-targets --all-features

# Format with rustfmt
fmt:
    cargo fmt --all

# Lint with clippy and deny warnings
clippy:
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Run tests below the short physical system temporary directory.
test:
    canonical_tmp="$(cd /tmp && pwd -P)"; TMPDIR="$canonical_tmp" cargo test --locked --workspace --all-targets --all-features --no-fail-fast --quiet

# Validate the publication lockfile and dependency governance ledger.
governance:
    cargo run --locked -p xtask -- check governance

# Assemble and verify the coherent publishable library package set.
package-check:
    python3 release/verify-package-set.py

# Clean build artifacts
clean:
    cargo clean

# List available recipes
help:
    just --list
