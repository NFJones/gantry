# Default recipe builds in release mode
default:
    cargo build --workspace --all-targets --all-features --release

# Build (debug)
build:
    cargo build --workspace --all-targets --all-features

# Build (release)
build-release:
    cargo build --workspace --all-targets --all-features --release

# Run Gantry
run *args:
    cargo run -p gantry-cli --bin gantry -- {{args}}

# Type-check without building artifacts
check:
    cargo check --workspace --all-targets --all-features

# Format with rustfmt
fmt:
    cargo fmt --all

# Lint with clippy and deny warnings
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run tests below the short physical system temporary directory.
test:
    canonical_tmp="$(cd /tmp && pwd -P)"; TMPDIR="$canonical_tmp" cargo test --workspace --all-targets --all-features --no-fail-fast --quiet

# Clean build artifacts
clean:
    cargo clean

# List available recipes
help:
    just --list
