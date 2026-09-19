# los-cara — S3-compatible object storage

binary := "lc"
data-dir := "./data"
address := "127.0.0.1:9000"

# Show available recipes
default:
    @just --list

# Build debug binary
build:
    cargo build

# Build optimized release binary
release:
    cargo build --release

# Run all tests (unit + integration)
test:
    cargo test

# Run only fast unit tests
test-unit:
    cargo test --lib

# Run only the AWS SDK integration suite
test-integration:
    cargo test --test integration

# Lint
lint:
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

# Auto-format
fmt:
    cargo fmt

# Fix all warnings in one pass
fix:
    cargo fix --all-targets --allow-dirty
    cargo fmt

# Start the server against ./data (debug build)
serve *ARGS:
    cargo run -- serve --address {{address}} --data {{data-dir}} {{ARGS}}

# Start the release server against ./data
serve-release *ARGS:
    ./target/release/{{binary}} serve --address {{address}} --data {{data-dir}} {{ARGS}}

# Add an access key to the data directory
add-key key secret:
    cargo run -- add-key --data {{data-dir}} --access-key {{key}} --secret-key {{secret}}

# Remove an access key from the data directory
remove-key key:
    cargo run -- remove-key --data {{data-dir}} --access-key {{key}}

# Remove build artifacts
clean:
    cargo clean

# Full check: build, lint, and test
ci:
    cargo build --all-targets
    just lint
    just test
