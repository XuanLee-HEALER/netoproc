# netoproc

> Per-process network traffic monitor for macOS

[![CI](https://github.com/XuanLee-HEALER/netoproc/actions/workflows/ci.yml/badge.svg)](https://github.com/XuanLee-HEALER/netoproc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

netoproc is a terminal-based network monitoring tool that shows per-process network traffic in real time. It captures packet headers via BPF (Berkeley Packet Filter) and attributes them to processes through socket-level correlation with macOS system APIs.

> **Platform notice**: netoproc has only been tested and verified on **macOS 26.0 (Tahoe)** with Apple Silicon. Other macOS versions may work but are not guaranteed.

## Installation

### From source (recommended)

```bash
git clone https://github.com/XuanLee-HEALER/netoproc.git
cd netoproc
just install
```

### Manual build

```bash
cargo build --release
sudo ./target/release/netoproc
```

### Prerequisites

- macOS 26.0+ (see [Platform Status](#platform-status) below)
- [Rust](https://www.rust-lang.org/tools/install) stable toolchain
- [just](https://github.com/casey/just) task runner (optional but recommended)
- Root privileges (`sudo`) for BPF device access

## Usage

netoproc requires root privileges for BPF device access:

```bash
# Interactive TUI (default)
sudo netoproc

# Snapshot mode — collect for 5 seconds, output TSV
sudo netoproc --duration 5

# Snapshot in JSON format
sudo netoproc --duration 5 --format json

# Human-readable pretty output
sudo netoproc --duration 5 --format pretty

# Monitor a specific interface
sudo netoproc --interface en0

# Filter by process name
sudo netoproc --filter firefox
```

See [docs/netoproc-usage.md](docs/netoproc-usage.md) for the complete user guide.

## Features

- **Per-process traffic**: Attributes network traffic to processes via BPF + socket correlation
- **TUI monitor mode**: Interactive terminal UI with process, connection, interface, and DNS views
- **Snapshot mode**: TSV, JSON, and pretty output for scripting and piping
- **DNS observatory**: Live DNS query log with resolver information
- **Keyboard navigation**: htop-style filtering, sorting, and row selection

## Architecture

Streaming three-thread model:

- **BPF capture threads**: Blocking read on `/dev/bpfN`, batch packets via `sync_channel`
- **Process refresh thread**: Rebuilds process-to-socket table every 500ms via `ArcSwap`
- **Main thread**: Drains packets, attributes to processes, accumulates per-process traffic stats

See [docs/netoproc-design.md](docs/netoproc-design.md) for the full architecture documentation.

## Platform Status

| Platform | Status | Notes |
|----------|--------|-------|
| macOS 26.0+ (Apple Silicon) | **Verified** | Primary development platform |
| macOS 26.0+ (Intel) | Untested | Should work (same BPF APIs) |
| macOS < 26.0 | Untested | May work with older system API differences |
| Linux | Not supported | Planned |
| Windows | Not supported | Planned |

## Roadmap

Priorities for future development:

1. **Cross-platform support** — Linux compatibility (via `AF_PACKET` / eBPF) and Windows support as the top priority
2. **Privilege model** — Reduce the need for full root access; explore capabilities-based approaches on Linux, BPF device group permissions on macOS
3. **UI improvements** — Richer TUI views, per-connection sparklines, configurable layouts, and theme support

## Development

```bash
just build       # debug build
just test        # unit tests (no sudo)
just test-all    # all tests (requires sudo)
just lint        # check + clippy + fmt-check
just install     # cargo install to ~/.cargo/bin
```

Run `just --list` to see all available recipes.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT &copy; 2026 Xuan Lee. See [LICENSE](LICENSE) for details.
