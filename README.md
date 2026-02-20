# netoproc

> Per-process network traffic monitor for macOS and Linux

[![CI](https://github.com/XuanLee-HEALER/netoproc/actions/workflows/ci.yml/badge.svg)](https://github.com/XuanLee-HEALER/netoproc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

netoproc is a terminal-based network monitoring tool that shows per-process network traffic in real time. On macOS it captures packet headers via BPF (Berkeley Packet Filter); on Linux it uses AF_PACKET raw sockets. Traffic is attributed to processes through socket-level correlation with platform-specific system APIs.

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

- macOS 26.0+ or Linux (kernel 3.x+)
- [Rust](https://www.rust-lang.org/tools/install) stable toolchain
- [just](https://github.com/casey/just) task runner (optional but recommended)
- Root privileges (`sudo`) or platform-specific permissions (see [Running without sudo](#running-without-sudo))

## Usage

netoproc requires root privileges (or platform-specific permissions) for packet capture:

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
sudo netoproc --interface en0     # macOS
sudo netoproc --interface eth0    # Linux

# Filter by process name
sudo netoproc --filter firefox
```

See [docs/netoproc-usage.md](docs/netoproc-usage.md) for the complete user guide.

### Running without sudo

netoproc supports running without `sudo` using platform-specific permission setup:

**macOS** — BPF device group permissions:

```bash
just setup-bpf    # one-time setup, requires sudo
# Log out and back in, then:
netoproc           # no sudo needed
```

To remove: `just remove-bpf`

**Linux** — capabilities-based permissions:

```bash
sudo bash scripts/install-linux.sh    # one-time setup
# Log out and back in, then:
netoproc                               # no sudo needed
```

To remove: `sudo bash scripts/uninstall-linux.sh`

> **Note**: Without root, process visibility is limited to the current
> user's processes. Use `sudo netoproc` for full cross-process monitoring.

## Features

- **Per-process traffic**: Attributes network traffic to processes via packet capture + socket correlation
- **TUI monitor mode**: Interactive terminal UI with process, connection, interface, and DNS views
- **Snapshot mode**: TSV, JSON, and pretty output for scripting and piping
- **DNS observatory**: Live DNS query log with resolver information
- **Keyboard navigation**: htop-style filtering, sorting, and row selection

## Architecture

Streaming three-thread model:

- **Capture threads**: Blocking read on platform capture device (macOS: `/dev/bpfN`; Linux: `AF_PACKET` socket), batch packets via `sync_channel`
- **Process refresh thread**: Rebuilds process-to-socket table every 500ms via `ArcSwap`
- **Main thread**: Drains packets, attributes to processes, accumulates per-process traffic stats

See [docs/netoproc-design.md](docs/netoproc-design.md) for the full architecture documentation.

## Platform Status

| Platform | Status | Notes |
|----------|--------|-------|
| macOS 26.0+ (Apple Silicon) | **Verified** | Primary development platform |
| macOS 26.0+ (Intel) | Untested | Should work (same BPF APIs) |
| macOS < 26.0 | Untested | May work with older system API differences |
| Linux x86_64 | **Supported** | AF_PACKET capture, `/proc`-based process attribution |
| Linux aarch64 | Untested | Should work (same AF_PACKET + /proc APIs) |
| Windows | Not supported | Planned |

## Roadmap

Priorities for future development:

1. ~~**Cross-platform support** — Linux compatibility via `AF_PACKET`~~ (done in v0.4.0)
2. ~~**Privilege model** — Reduce the need for full root access; capabilities on Linux, BPF device group permissions on macOS~~ (done — see [Running without sudo](#running-without-sudo))
3. ~~**eBPF capture mode (Phase 1)** — Optional `--capture-mode=ebpf` infrastructure with kernel detection, stub backend, and auto-fallback~~ (done in v0.5.0)
4. **eBPF capture mode (Phase 2)** — Full eBPF kprobe implementation for per-packet PID attribution
5. **Windows support** — via Npcap / WinAPI
6. **UI improvements** — Richer TUI views, per-connection sparklines, configurable layouts, and theme support

## Development

```bash
just build           # debug build
just test            # unit tests (no sudo)
just test-all        # all tests (requires sudo)
just lint            # check + clippy + fmt-check
just cross-check     # cross-compile for Linux x86_64
just cross-check-arm # cross-compile for Linux aarch64
just install         # cargo install to ~/.cargo/bin
```

Cross-compilation requires [cross](https://github.com/cross-rs/cross) and Docker.

Run `just --list` to see all available recipes.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT &copy; 2026 Xuan Lee. See [LICENSE](LICENSE) for details.
