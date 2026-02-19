# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
