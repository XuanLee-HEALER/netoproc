# netoproc

> Per-process network traffic monitor for macOS

[![CI](https://github.com/XuanLee-HEALER/netoproc/actions/workflows/ci.yml/badge.svg)](https://github.com/XuanLee-HEALER/netoproc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

netoproc is a terminal-based network monitoring tool for macOS that shows per-process, per-socket, per-connection network traffic in real time. It captures packet headers via BPF (Berkeley Packet Filter) and correlates them with process and socket information from macOS system APIs.

Unlike `nettop` (Apple's built-in), netoproc provides per-connection traffic rates, a dedicated DNS observatory, a pipe-friendly snapshot mode for scripting, and htop-style keyboard navigation.

## Prerequisites

- macOS 26.0 (Tahoe) or higher
- [Rust](https://www.rust-lang.org/tools/install) stable toolchain (edition 2024)
- Root privileges (`sudo`) for BPF device access

Install Rust via rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Installation

### Build from source

```bash
git clone https://github.com/XuanLee-HEALER/netoproc.git
cd netoproc
cargo build --release
sudo ./target/release/netoproc
```

### From crates.io (once published)

```bash
cargo install netoproc
```

## Usage

netoproc requires root privileges. Always run with `sudo`:

```bash
# Interactive TUI (default)
sudo netoproc

# Snapshot mode (TSV output)
sudo netoproc snapshot

# Snapshot in JSON
sudo netoproc snapshot --format json

# Monitor a specific interface
sudo netoproc monitor --interface en0

# Filter by process name
sudo netoproc monitor --filter firefox

# Fast refresh (500ms)
sudo netoproc monitor --interval 0.5
```

See [docs/USAGE.md](docs/USAGE.md) for the complete user guide with all options, views, keyboard shortcuts, output formats, and examples.

## Features

- **Four TUI views**: Process, Connection, Interface, DNS
- **Per-connection metrics**: RX/TX rates, RTT, jitter, retransmissions
- **DNS observatory**: Live query log, resolver latency stats
- **Snapshot mode**: TSV and JSON output for scripting and piping
- **Sparkline charts**: Visual traffic trends in the terminal
- **Keyboard navigation**: htop-style filtering, sorting, row expansion

## Architecture

Three-thread model:

- **BPF capture thread**: Reads raw packets from `/dev/bpfN` via Berkeley Packet Filter
- **Stats poller thread**: Correlates packets with processes/sockets, publishes state via `ArcSwap`
- **TUI/snapshot thread**: Renders the interactive display or serializes output

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture documentation.

## Development Setup

```bash
git clone https://github.com/XuanLee-HEALER/netoproc.git
cd netoproc

# Check compilation
just check

# Build (debug mode)
just build

# Run unit tests (no sudo needed)
just test

# Run all tests including integration (requires sudo)
just test-all
```

## Running Tests

```bash
# Unit tests only
just test

# All tests (requires sudo)
just test-all

# Specific test
cargo test test_name

# Lint check
just clippy

# Full lint pass (check + clippy + fmt)
just lint
```

## Linting & Formatting

```bash
# Format code
just fmt

# Format check (CI)
just fmt-check

# Lint with Clippy
just clippy

# Combined lint (check + clippy + fmt-check)
just lint
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT &copy; 2026 Xuan Lee. See [LICENSE](LICENSE) for details.
