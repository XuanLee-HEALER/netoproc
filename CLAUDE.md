# CLAUDE.md — netop Project Instructions

## Project Overview

netop is a macOS-only (26.0+) TUI/CLI tool for per-process network traffic monitoring.
Written in Rust. Requires sudo to run. See netoproc-requirements.md, netoproc-design.md, netoproc-snapshot-tests.md,
netoproc-usage.md for full specifications.

## Toolchain

- **Rust**: edition 2021, stable toolchain
- **Cargo**: build, test, check, clippy, fmt — all via cargo
- **just**: task runner for all common workflows — always prefer `just <recipe>` over raw shell commands

### Preferred Tool Usage

When performing project tasks, **always use `just` recipes or `cargo` commands** instead of:
- Directly reading/writing source files to understand build state — run `cargo check` instead
- Running raw shell commands for build/test/lint — run `just <recipe>` instead
- Manual multi-step processes — define a `just` recipe if one doesn't exist

Priority order:
1. `just <recipe>` — for any defined workflow
2. `cargo <subcommand>` — for Rust-specific operations not covered by just
3. Direct file editing — only when writing or modifying source code
4. Shell commands — only when no cargo/just equivalent exists

## just Recipes (justfile)

The project uses a `justfile` at the project root. Key recipes:

```
just build          # cargo build
just release        # cargo build --release
just test           # cargo test (unit tests, no sudo)
just test-all       # sudo cargo test (all tests including integration)
just check          # cargo check
just clippy         # cargo clippy -- -D warnings
just fmt            # cargo fmt
just fmt-check      # cargo fmt --check
just lint           # check + clippy + fmt-check combined
just clean          # cargo clean
just install        # cargo install --path .
just run            # sudo cargo run
just run-snapshot   # sudo cargo run -- --duration 5
just doc            # cargo doc --no-deps --open
```

Run `just --list` to see all available recipes.

## Code Conventions

- All user-facing text (help, errors, TUI, output) in **English**
- All code identifiers in English, snake_case for functions/variables, CamelCase for types
- Error messages follow the format: `error: <message>` (lowercase, no period)
- Exit codes: 0=success, 1=privilege, 2=BPF, 3=args, 4=fatal (see netoproc-requirements.md §9)
- No `unwrap()` or `expect()` in non-test code — use `?` operator with `NetopError`
- `unsafe` blocks only in FFI boundary code (src/bpf/, src/system/) — never in model/output/tui
- All `#[repr(C)]` structs must have compile-time size assertions
- Prefer `&[u8]` slicing over allocating new `Vec<u8>` for packet parsing

## Architecture Quick Reference

Three-thread streaming model (v0.2.0):
- **BPF capture thread**: blocking read on `/dev/bpfN`, sends `Vec<PacketSummary>` batches via `sync_channel(8)`
- **Process refresh thread**: rebuilds `ProcessTable` every 500ms, publishes via `ArcSwap`
- **Main thread (stats)**: drains packet channel, attributes to processes via `ProcessTable` lookup, accumulates `TrafficStats`
  - Snapshot mode: outputs per-process traffic table after duration expires
  - Monitor mode: bridge thread builds `SystemNetworkState` for TUI; TUI runs in main thread

Key modules: `bpf/`, `system/`, `model/`, `state/`, `output/`, `tui/`
See netoproc-design.md §2 for full module map.

## Testing

```
just test           # unit tests only (no sudo needed)
just test-all       # all tests (requires sudo)
just clippy         # lint check
just lint           # full lint pass (check + clippy + fmt)
```

- Unit tests: `cargo test --lib`
- Integration tests: `sudo cargo test --test '*'`
- Run a specific test: `cargo test <test_name>`
- Tests requiring sudo are gated by runtime root check, not compile-time cfg

## Dependencies (key crates)

clap, ratatui, crossterm, serde, serde_json, arc-swap, crossbeam-channel, libc, thiserror, log, env_logger, rustc-hash

**Not used** (by design): libpcap, tokio, bindgen, nix, hickory-dns
See netoproc-design.md §9 for rationale.

## Common Workflows

### Adding a new module
1. Create the file under the appropriate directory (bpf/, system/, model/, etc.)
2. Add `mod <name>;` to the parent `mod.rs`
3. Run `just check` to verify compilation
4. Add unit tests in the same file or under `tests/unit/`
5. Run `just test` to verify

### Modifying data model
1. Edit structs in `src/model/mod.rs`
2. Update TSV serializer in `src/output/tsv.rs` (column order must match netoproc-requirements.md FR-5.5)
3. Update JSON serializer in `src/output/json.rs`
4. Run `just test` to catch any serialization mismatches
5. If field names changed, update netoproc-requirements.md §7 as the single source of truth

### Running the application
```
just run                                          # TUI mode (default)
sudo cargo run -- --duration 5                    # snapshot mode (TSV, 5 seconds)
sudo cargo run -- --duration 5 --format json      # snapshot JSON
sudo cargo run -- --duration 5 --format pretty    # snapshot human-readable
```
