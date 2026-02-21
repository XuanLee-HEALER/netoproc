# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-02-21

### Added

- `PacketSource` trait in `src/capture/mod.rs`: zero-cost generic abstraction over
  platform-specific capture backends with four methods — `interface()`,
  `read_packets_raw()`, `read_dns_messages()`, `capture_stats()`
  - `impl PacketSource for BpfCapture` (macOS)
  - `impl PacketSource for AfPacketCapture` (Linux)
  - `impl PacketSource for RawSocketCapture` (Windows)
  - `CaptureStats` consolidated to `src/capture/mod.rs` (previously duplicated
    across three platform files)
- Windows compatibility test suite:
  - `tests/windows_compat.rs` — 59 tests covering packet parsing, byte-order
    conversion, port annotation, TCP state mapping, bounds checking, and
    Windows-specific algorithm verification; compiled and run on all three platforms
  - `tests/windows_integration.rs` — 17 tests: 12 cross-platform library tests
    (TC-WIN-1..12) + 5 binary CLI tests (TC-WIN-B1..5, exercising `--help`,
    `--version`, invalid args, `--capture-mode=ebpf` warning on Windows)
- GitHub Actions CI pipeline (`.github/workflows/ci.yml`):
  - `fmt` (rustfmt) and `clippy` jobs on `macos-latest`
  - `test` job: macOS unit tests on stable and beta toolchains
  - `test-linux` job (`ubuntu-latest`): Tier 1 — no-privilege tests (unit,
    `linux_proc_parsing`, `windows_compat`, `windows_integration`,
    `enrichment_integration`, `ebpf_integration`); Tier 2 — `sudo -E` tests
    (`linux_integration`, `snapshot_integration`)
  - `test-windows` job (`windows-latest`): unit tests, `windows_compat`,
    `windows_integration`
  - `build` job: macOS release binary artifact upload, gated on all test jobs

### Changed

- `capture_loop`, `dns_capture_loop`, and `process_refresh_loop` in `src/main.rs`
  are now generic functions (`<S: PacketSource>` and `<F: Fn() -> ProcessTable>`),
  monomorphized per platform at compile time with zero runtime overhead; this also
  enables mock injection for testing the attribution pipeline without live capture

## [0.5.0] - 2026-02-21

### Added

- Windows platform support via `#[cfg(target_os = "windows")]` branches, matching
  the module-switching pattern established in v0.4.0:
  - Packet capture via Winsock2 raw sockets with `SIO_RCVALL` control code
    (`src/capture/windows.rs`)
  - Process attribution via `GetExtendedTcpTable` / `GetExtendedUdpTable` +
    Toolhelp32 process snapshot (`src/process/windows.rs`)
  - Interface enumeration and DNS configuration via `GetAdaptersAddresses`
    (`src/system/interface.rs`, `src/system/dns_config.rs`)
  - TCP connection state via `GetExtendedTcpTable`
    (`src/system/connection.rs`)
  - Signal handling via `SetConsoleCtrlHandler`
  - `docs/netoproc-windows-compat.md` — Windows compatibility design document
- eBPF capture mode infrastructure (Phase 1):
  - `--capture-mode=ebpf` flag; on Linux auto-falls back to AF_PACKET with an
    info log when the eBPF backend is unavailable; accepted but has no effect
    on macOS and Windows
  - `netoproc-ebpf-common` workspace crate — shared eBPF/userspace type
    definitions
  - `netoproc-ebpf` workspace crate — eBPF program skeleton (stub; kprobe
    implementation deferred to Phase 2)
  - `EbpfCapture` stub backend (`src/capture/ebpf.rs`) — always returns
    `Err(CaptureDevice)`, triggering AF_PACKET fallback; validates the full
    infrastructure without requiring a loaded eBPF program
  - `tests/ebpf_integration.rs` — cross-platform tests verifying fallback
    behavior and error handling; no root required
  - `docs/netoproc-ebpf-capture-design.md` — eBPF capture design (Phase 1
    infrastructure + Phase 2 kprobe plan)
  - `docs/netoproc-ebpf-linux-research.md` — AF_PACKET vs. eBPF performance
    and correctness analysis

## [0.4.0] - 2026-02-20

### Added

- Linux platform support via `#[cfg(target_os)]` compile-time module switching:
  - `src/packet.rs` and `src/dns.rs`: shared IP/L4 packet parsers and DNS
    wire-format parser extracted from `src/bpf/`, now compiled on all platforms
  - `src/capture/linux.rs`: AF_PACKET raw socket with BPF filter installation,
    500ms read timeout, and promiscuous mode
  - `src/capture/macos.rs`: thin wrapper re-exporting the existing BPF capture
  - `src/process/linux.rs`: parses `/proc/net/tcp[6]` and `/proc/net/udp[6]`
    for socket inodes; maps inodes to PIDs via `/proc/<pid>/fd/` symlinks
  - `src/process/macos.rs`: delegates to existing libproc implementation
- Linux system subsystem implementations:
  - `src/system/connection.rs`: connection listing from `/proc/net/tcp[6]` and
    `/proc/net/udp[6]`
  - `src/system/interface.rs`: interface byte/packet counters from
    `/sys/class/net/<name>/statistics/`
  - `src/system/dns_config.rs`: nameserver and search domain parsing from
    `/etc/resolv.conf`
  - `src/system/process.rs`: process name from `/proc/<pid>/comm`, UID from
    `/proc/<pid>/status`
- Linux capability setup scripts: `scripts/install-linux.sh` (creates
  `netoproc` group, sets `cap_net_raw,cap_net_admin,cap_sys_ptrace+eip`) and
  `scripts/uninstall-linux.sh`
- Integration tests:
  - `tests/linux_proc_parsing.rs` — 27 cross-platform tests parsing static
    `/proc/net/tcp` strings; verify IPv4/IPv6 hex byte-order conversion
  - `tests/linux_integration.rs` — runtime tests requiring root/capabilities
    (AF_PACKET socket creation, filter installation, process table from `/proc`)
- `docs/netoproc-linux-compat.md` — Linux compatibility design and installation
  guide

### Changed

- `--capture-buffer` replaces `--bpf-buffer` as the CLI flag name; `--bpf-buffer`
  is retained as a hidden alias for backward compatibility
- `src/bpf/` module cfg-gated to `target_os = "macos"` only; shared packet and
  DNS parsing code moved to `src/packet.rs` and `src/dns.rs`
- `CaptureDevice` error variant replaces the macOS-specific `BpfDevice` variant
  to provide a cross-platform capture error type

## [0.3.0] - 2026-02-20

### Added

- BPF device group permissions for sudo-free capture on macOS:
  - `scripts/install-bpf.sh` and `scripts/uninstall-bpf.sh` create and remove
    an `access_bpf` user group with launchd-managed `/dev/bpf*` permissions
    (matches Wireshark's approach on macOS)
  - `check_bpf_access()` replaces `check_root()` — accepts root, `access_bpf`
    group membership, or any process that can open `/dev/bpf0`; on failure,
    returns an actionable error message with setup instructions
  - `setup-bpf` / `remove-bpf` justfile recipes
- Unknown traffic enrichment pipeline (`src/enrichment/`):
  - Port annotation table: maps well-known TCP/UDP port numbers to service names
  - IP annotation table: maps cloud provider, CDN, and special-purpose address
    ranges to human-readable labels (ASN-based)
  - Async reverse DNS resolver with per-IP deduplication and TTL-respecting
    caching
- Per-remote-address sub-rows under the "unknown" traffic row in pretty output
  and TUI, showing hostname (if resolved), IP annotation, and per-connection
  byte counts
- `docs/netoproc-macos-permission.md` — macOS BPF permission setup guide
- `docs/netoproc-unknown-enrichment.md` — enrichment pipeline design document

### Changed

- `InsufficientPermission(String)` error variant replaces `NotRoot` to carry an
  actionable diagnostic message and support the broader permission model

## [0.2.0] - 2026-02-19

### Added

- Streaming three-thread architecture: BPF capture thread, process refresh
  thread, and stats main thread replace the previous batch poller model
- `ProcessTable` (`FxHashMap<SocketKey, ProcessInfo>`) with normalized 5-tuple
  keys for efficient per-process packet attribution
- `SocketKey` type with lexicographic normalization and IPv4-mapped-IPv6
  support, ensuring bidirectional connection lookup with a single hash query
- `TrafficStats` per-process traffic accumulator with direction-aware
  rx/tx accounting
- `--duration <seconds>` flag for snapshot mode (replaces `snapshot` subcommand)
- `--monitor` flag as explicit alias for default TUI mode
- `--format pretty` output format with human-readable byte sizes and summary line
- Process refresh thread: rebuilds ProcessTable every 500ms via ArcSwap
- `drain_final()` for snapshot mode: joins BPF threads and drains remaining
  channel data to avoid losing the last 0-500ms of packets
- `rustc-hash` dependency for FxHashMap (faster hashing for short fixed keys)

### Changed

- **BREAKING**: CLI is now flat — `netoproc --duration 5` instead of
  `netoproc snapshot`; `netoproc` (no args) for monitor mode
- **BREAKING**: Snapshot TSV output is now a simple per-process traffic table
  (`pid, process, rx_bytes, tx_bytes, rx_packets, tx_packets`) instead of the
  previous 6-section format
- **BREAKING**: Snapshot JSON output is now an array of per-process traffic
  objects instead of a nested `SystemNetworkState` object
- BPF packet channel changed from per-packet crossbeam `bounded(8192)` to
  batch `sync_channel::<Vec<PacketSummary>>(8)` — each BPF read sends its
  entire batch as one message
- Default BPF buffer size increased from 32 KB to 2 MB
- BPF buffer size limit increased from 1 MB to 16 MB
- Snapshot duration range changed to 1.0-3600.0 seconds

### Removed

- `BIOCIMMEDIATE` ioctl — the kernel now buffers packets until the 500ms read
  timeout fires or the buffer fills, reducing small reads
- `snapshot` and `monitor` subcommands (replaced by `--duration` flag)
- `--interval` flag (monitor mode uses data-driven refresh; snapshot uses
  `--duration`)

## [0.1.0] - 2026-02-18

### Added

- Initial release
- BPF packet capture on macOS with IPv4/IPv6 TCP/UDP filtering
- Per-process, per-socket, per-connection traffic monitoring
- Four TUI views: Process, Connection, Interface, DNS
- Snapshot mode with TSV and JSON output formats
- DNS observatory with query log and resolver statistics
- Process-socket correlation via libproc and sysctl
- Time-series data with multi-level aggregation (100ms/1s/1min)
- Keyboard navigation, filtering, sorting in TUI
- NO_COLOR environment variable support
