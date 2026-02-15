# dont-track-me — Rust project recipes

# Build all crates in release mode
build:
    cargo build --release

# Run all tests
test:
    cargo nextest run

# Run clippy with warnings as errors
lint:
    cargo clippy --all-targets -- -D warnings

# Check formatting
fmt:
    cargo fmt --check

# Run lint, fmt, and test in sequence
check: lint fmt test

# Install the CLI binary
install:
    cargo install --path crates/dtm-cli

# Remove build artifacts
clean:
    cargo clean
