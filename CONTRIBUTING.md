# Contributing to netoproc

Thank you for considering contributing to netoproc! This document explains how to get started.

## Reporting Bugs

Use the [Bug Report](https://github.com/XuanLee-HEALER/netoproc/issues/new?template=bug_report.yml) issue template. Include:

- Steps to reproduce
- Expected vs actual behavior
- macOS version and architecture (arm64 / x86_64)
- netoproc version (`netoproc --version`)

## Suggesting Features

Use the [Feature Request](https://github.com/XuanLee-HEALER/netoproc/issues/new?template=feature_request.yml) issue template.

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run the full lint suite: `just lint`
5. Run unit tests: `just test`
6. Run integration tests (requires sudo): `just test-all`
7. Commit with a descriptive message (see below)
8. Push to your fork and open a Pull Request

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add IPv6 jumbogram support
fix: correct BPF filter jump offset for UDP
docs: update netoproc-usage.md with new --no-dns flag
refactor: extract packet parsing into BpfPacketIter
test: add IPv6 extension header chaining tests
chore: upgrade clap to v4.5
```

Sign off your commits with `git commit -s` to certify the [Developer Certificate of Origin](https://developercertificate.org/).

## Code Style

- Run `just fmt` before committing
- Run `just clippy` and fix all warnings
- No `unwrap()` or `expect()` in non-test code — use `?` with `NetopError`
- `unsafe` blocks only in FFI boundary code (`src/bpf/`, `src/system/`)
- All user-facing text in English
- Prefer `&[u8]` slicing over allocating new `Vec<u8>` for packet parsing

## Pull Request Checklist

- [ ] `just lint` passes (check + clippy + fmt-check)
- [ ] `just test` passes (unit tests)
- [ ] `just test-all` passes if you modified BPF/system code
- [ ] New code has unit tests
- [ ] Documentation updated if behavior changed
- [ ] Commit messages follow Conventional Commits
- [ ] Commits are signed off (`git commit -s`)

## Project Structure

```text
src/
├── bpf/       # BPF device, packet parsing, filters
├── system/    # macOS system APIs (processes, sockets, DNS config)
├── model/     # Data model, correlation logic
├── state/     # State merging, ArcSwap publisher
├── output/    # TSV and JSON serializers
├── tui/       # Ratatui-based terminal UI
├── cli.rs     # clap argument definitions
├── error.rs   # NetopError type
└── main.rs    # Entry point, thread orchestration
```

See [docs/netoproc-design.md](docs/netoproc-design.md) for architecture details.
