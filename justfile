# netoproc justfile — task runner for common workflows

# Default recipe: list all available recipes
default:
    @just --list

# Build in debug mode
build:
    cargo build

# Build in release mode
release:
    cargo build --release

# Run cargo check (fast compilation check, no codegen)
check:
    cargo check

# Run unit tests (no sudo required)
test:
    cargo test --lib

# Run all tests including integration tests (requires sudo)
test-all:
    sudo cargo test

# Run a specific test by name
test-one name:
    cargo test {{name}}

# Run clippy linter
clippy:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt --check

# Full lint pass: check + clippy + format check
lint: check clippy fmt-check

# Clean build artifacts
clean:
    cargo clean

# Run netoproc in TUI monitor mode (requires sudo)
run *args:
    sudo cargo run -- {{args}}

# Run netoproc in snapshot mode (requires sudo)
run-snapshot *args:
    sudo cargo run -- --duration 5 {{args}}

# Install netoproc to ~/.cargo/bin and fish completions
install:
    cargo install --path .
    mkdir -p ~/.config/fish/completions
    cp completions/netoproc.fish ~/.config/fish/completions/
    @echo "Installed netoproc and fish completions"
    @echo ""
    @echo "To run without sudo, set up BPF permissions:"
    @echo "  just setup-bpf"

# Generate and open documentation
doc:
    cargo doc --no-deps --open

# Set up BPF permissions (run netoproc without sudo)
setup-bpf:
    sudo bash scripts/install-bpf.sh

# Remove BPF permissions
remove-bpf:
    sudo bash scripts/uninstall-bpf.sh

# Cross-compile check for Linux x86_64 (requires cross)
cross-check:
    cross build --target x86_64-unknown-linux-gnu

# Cross-compile check for Linux aarch64 (requires cross)
cross-check-arm:
    cross build --target aarch64-unknown-linux-gnu

# Run tests and lint in sequence (pre-commit check)
ci: lint test
