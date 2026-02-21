# netoproc-requirements.md — netoproc Network Traffic Monitor

## 1. Overview

netop is a sudo-privileged macOS command-line tool that provides real-time, per-process
network traffic monitoring and network subsystem introspection via an interactive TUI
(terminal user interface) or a pipe-friendly snapshot output. It captures packet-level
traffic data using BPF (Berkeley Packet Filter) and correlates it with process, socket,
and connection information from macOS system APIs to produce a unified view of which
processes are communicating with which remote hosts, at what rate, and over which
network interfaces.

Target users: system administrators, network engineers, and developers debugging
connectivity or performance issues on macOS.

## 2. Glossary

| Term | Definition |
|------|-----------|
| BPF | Berkeley Packet Filter. A kernel-level packet capture mechanism accessed via `/dev/bpfN` device files on macOS. |
| pcblist | Protocol Control Block list. A kernel data structure enumerating all TCP or UDP sockets, accessible via `sysctl`. |
| fd | File descriptor. An integer handle to an open file, socket, or device in a Unix process. |
| RTT | Round-Trip Time. The time for a TCP segment to travel to a remote host and for an acknowledgment to return. |
| jitter | The variance in RTT over a time window. High jitter indicates unstable network conditions. |
| retransmission | A TCP segment that was sent again because the original was lost or not acknowledged in time. |
| NXDOMAIN | A DNS response code indicating the queried domain name does not exist. |
| SERVFAIL | A DNS response code indicating the DNS server failed to process the query. |
| sparkline | A compact inline chart rendered using Unicode block characters, showing a data series trend. |
| TSV | Tab-Separated Values. A text format where fields are delimited by tab characters. |
| ring buffer | A fixed-size circular buffer that overwrites the oldest entry when full. |
| 5-tuple | The combination of (protocol, source IP, source port, destination IP, destination port) that uniquely identifies a network connection. |
| SPSC | Single-Producer Single-Consumer. A lock-free queue pattern where exactly one thread writes and one thread reads. |
| mDNS | Multicast DNS. A protocol for name resolution on local networks without a central DNS server (port 5353). |
| EDNS0 | Extension Mechanisms for DNS (RFC 6891). Extends the original DNS protocol with larger message sizes and additional options. |
| conntrack | Connection tracking. A kernel subsystem that tracks the state of network connections for stateful filtering. |
| AF_PACKET / AF_LINK | Address families for raw link-layer access. macOS uses AF_LINK (not AF_PACKET, which is Linux-specific). |
| if_data | A macOS kernel structure containing interface-level traffic statistics (bytes, packets, errors). |
| libproc | A macOS system library providing process inspection APIs (process list, file descriptors, socket info). |
| SystemConfiguration | A macOS framework for querying and monitoring system configuration, including network settings and DNS resolver configuration. |

## 3. System Context

### 3.1 Target Platform

- **Operating System**: macOS 26.0 (Tahoe) or later. No cross-platform support.
- **Architecture**: Apple Silicon (arm64) primary. Intel (x86_64) secondary.
- **Earlier macOS versions**: Not tested, not supported, may work incidentally.

### 3.2 Privilege Model

- netop MUST run as root (via `sudo`).
- If executed without root privileges, netop MUST print an error message to stderr
  and exit immediately with exit code 1.
- No graceful degradation, no capability fallback, no partial functionality mode.
- Root is required for: BPF device access, cross-user process enumeration, raw
  socket information from kernel data structures.

### 3.3 Language and Build

- Language: Rust, edition 2021 or later.
- Minimum Supported Rust Version (MSRV): 1.75.0 or later (to be determined during
  implementation based on dependency requirements).
- Build target: single static binary with no runtime dependencies beyond macOS
  system libraries (libSystem, SystemConfiguration.framework, Security.framework).

### 3.4 External Dependency Policy

- Prefer direct FFI calls to macOS system libraries over shelling out to
  command-line tools.
- Do NOT invoke `lsof`, `netstat`, `nettop`, `scutil`, or any other external
  process for data collection.
- All system data must be obtained through programmatic APIs (syscalls, sysctl,
  libproc, BPF ioctls, SystemConfiguration framework).

## 4. Functional Requirements

### FR-1: Process-Socket Inventory

**FR-1.1**: Enumerate all processes on the system that hold open network sockets.

**FR-1.2**: For each process, report:

- PID (process ID)
- Process name (short name, e.g., "curl")
- Full command line (argv)
- Owning user (UID resolved to username)

**FR-1.3**: For each process, list all network socket file descriptors with:

- fd number
- Protocol: TCP, UDP, or ICMP
- Local address and port (in `addr:port` format; `*` for wildcard/unbound)
- Socket state:
  - TCP: CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED, CLOSE_WAIT,
    LAST_ACK, FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT
  - UDP: BOUND (has local address) or CONNECTED (has remote address)
  - ICMP: OPEN

**FR-1.4**: Data source for process and fd enumeration:

- `proc_listpids(PROC_ALL_PIDS)` to obtain PID list.
- `proc_pidinfo(pid, PROC_PIDLISTFDS)` to obtain fd list per process.
- `proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO)` to obtain socket details.

**FR-1.5**: Cross-reference process socket data with kernel connection tables
obtained via `sysctlbyname("net.inet.tcp.pcblist_n")` and
`sysctlbyname("net.inet.udp.pcblist_n")` to fill in connection details not
directly available from libproc (e.g., TCP state, interface binding).

### FR-2: Per-Connection Traffic Metrics

**FR-2.1**: For each active connection (ESTABLISHED TCP, or active UDP flow),
report:

- Remote address and port
- Direction:
  - **Inbound**: the local port matches a socket in LISTEN state owned by the
    same process (i.e., this is an accepted connection on a server socket).
  - **Outbound**: the connection was initiated by the local process (no
    corresponding LISTEN socket).
- Bound network interface (determined by routing table lookup or interface index
  from kernel connection table).

**FR-2.2**: Traffic rates at three granularities:

- **100ms buckets**: internal computation granularity (not displayed directly).
- **Per-second (1s)**: default display granularity in TUI; default snapshot
  granularity.
- **Per-minute (1min)**: used for sparkline trend visualization.

Rates are reported separately for RX (received) and TX (transmitted), in
bytes per time unit.

**FR-2.3**: Traffic totals: cumulative RX bytes and TX bytes since netop started
monitoring (not since the connection was established — netop cannot know traffic
that occurred before it started).

**FR-2.4**: Connection stability metrics (TCP only):

- **RTT** (smoothed, microseconds): obtained from `TCP_CONNECTION_INFO` via
  `getsockopt`, or inferred from kernel `xtcpcb_n` fields, or estimated from
  BPF-observed SYN/SYN-ACK timing for new connections during monitoring.
- **Jitter** (microseconds): standard deviation of RTT samples over the last
  10-second window.
- **Retransmission count**: cumulative retransmitted segments.
- **Retransmission rate**: retransmissions per second over the last 10-second
  window.

**FR-2.5**: Traffic volume data source: BPF passive capture on `/dev/bpfN`.
Capture Layer 3 (IP) and Layer 4 (TCP/UDP) headers only. No payload capture.
Match each captured packet to a known connection by 5-tuple.

**FR-2.6**: Stability data source: `getsockopt(fd, IPPROTO_TCP,
TCP_CONNECTION_INFO)` polled at 1-second intervals. Note: this is only available
for sockets owned by the netop process itself; for other processes' sockets,
use `xtcpcb_n` kernel struct fields or BPF-based RTT estimation.

### FR-3: Interface Statistics

**FR-3.1**: List all network interfaces with:

- Interface name (e.g., `en0`, `lo0`, `utun3`)
- IPv4 address(es)
- IPv6 address(es)
- Configured DNS servers (per-interface)
- RX byte rate and TX byte rate (per second)
- RX byte total and TX byte total (since netop started)
- RX packet count and TX packet count
- RX error count and TX error count
- Interface status: up/down, link speed (if available)

**FR-3.2**: Data source for interface statistics:

- `getifaddrs()` iterating linked list:
  - `AF_LINK` entries: cast `ifa_data` to `struct if_data` for traffic counters
    (`ifi_ibytes`, `ifi_obytes`, `ifi_ipackets`, `ifi_opackets`, `ifi_ierrors`,
    `ifi_oerrors`).
  - `AF_INET` entries: IPv4 addresses.
  - `AF_INET6` entries: IPv6 addresses.
- Rates computed by diffing consecutive samples divided by elapsed time.

**FR-3.3**: DNS server configuration per interface:

- Data source: `SCDynamicStoreCreate` + `SCDynamicStoreCopyValue` with key
  `"State:/Network/Service/<ServiceID>/DNS"` and global key
  `"State:/Network/Global/DNS"`.
- For each interface, report: list of DNS server addresses, search domains.

### FR-4: DNS Observatory

**FR-4.1**: Resolver inventory: for each network interface with configured DNS
servers, compute and report:

- DNS server address
- Associated interface name
- Average query latency (milliseconds, computed from observed query/response pairs)
- Failure rate (percentage of queries resulting in SERVFAIL, NXDOMAIN, or timeout)
- Total query count observed

**FR-4.2**: Live DNS query monitoring:

- Capture all UDP and TCP traffic on port 53 via BPF filter.
- Parse DNS wire format (RFC 1035) for both queries and responses.

**FR-4.3**: DNS wire format parsing requirements:

- Parse DNS header (12 bytes): transaction ID, flags (QR, OPCODE, RCODE),
  question count, answer count, authority count, additional count.
- Parse question section: QNAME (with label compression per RFC 1035 Section
  4.1.4), QTYPE, QCLASS.
- Parse answer section: extract A (IPv4), AAAA (IPv6), and CNAME record data.
- Handle EDNS0 OPT pseudo-records in additional section (RFC 6891).
- Compression safety: limit pointer follows to 256 to prevent infinite loops
  from malicious packets.

**FR-4.4**: For each observed DNS query, record:

- Timestamp (monotonic clock, millisecond precision)
- Originating process (matched via source port to socket owner, see FR-4.5)
- Query name (e.g., `example.com`)
- Query type (A, AAAA, CNAME, MX, PTR, SRV, TXT, etc.)
- Response: resolved addresses, NXDOMAIN, SERVFAIL, or timeout
- Latency: response timestamp minus query timestamp (milliseconds)
- Resolver used: destination IP address of the query packet

**FR-4.5**: DNS-to-process attribution:

- Match the ephemeral source port of the DNS query packet to an open UDP or TCP
  socket owned by a process (from FR-1 data).
- If the socket has been closed by the time the correlation is attempted, record
  the originating process as "unknown".

### FR-5: Snapshot Mode

**FR-5.1**: Invoked via `sudo netoproc --duration <seconds>`. Collect per-process
traffic data for the specified duration, emit to stdout, then exit.

**FR-5.2**: Default output format: TSV (tab-separated values).

**FR-5.3**: Alternative output format: JSON (selected via `--format json`).

**FR-5.4**: Output constraints:

- No ANSI escape codes.
- No progress indicators, spinners, or interactive prompts.
- No output to stderr except error messages.
- Suitable for piping to `awk`, `cut`, `sort`, `jq`, and other Unix text tools.

**FR-5.5**: TSV schema — a single per-process traffic table:

```text
Columns: pid, process, rx_bytes, tx_bytes, rx_packets, tx_packets
```

- Header row with column names, tab-separated
- Data rows sorted by total traffic (rx_bytes + tx_bytes) descending
- Unknown processes: pid = `-`, process = `unknown`
- No section headers, no comment lines

**FR-5.5a**: Pretty format (`--format pretty`): human-readable table with
formatted byte sizes (B, KiB, MiB, GiB), column headers, and a TOTAL summary
line.

**FR-5.6**: JSON schema: a JSON array of per-process traffic objects. Each
object has fields: `pid` (number or null), `process` (string), `rx_bytes`,
`tx_bytes`, `rx_packets`, `tx_packets` (all numbers). Sorted by total traffic
descending. All field names use snake_case.

**FR-5.7**: Performance target: snapshot collection and output must complete
within 2 seconds on a system with up to 500 processes and 5000 open sockets.

### FR-6: Monitor (TUI) Mode

**FR-6.1**: Invoked via `sudo netop` or `sudo netop monitor`. Launches an
interactive, full-screen, htop-style terminal user interface.

**FR-6.2**: Four switchable views:

1. **Process View**: Table of processes sorted by total traffic, expandable
   rows to show sockets and connections nested under each process.
2. **Connection View**: Flat table of all active connections with traffic
   metrics, sortable by any column.
3. **Interface View**: Card layout, one card per interface showing name,
   addresses, DNS servers, RX/TX rates with sparkline graphs, error counts.
4. **DNS View**: Split layout — top section shows resolver stats table,
   bottom section shows scrolling live query log.

**FR-6.3**: Refresh rate: 1 Hz default. Configurable from 0.1 Hz to 10 Hz
via `--interval` flag.

**FR-6.4**: Sorting: keyboard key to cycle sort column; shift variant to
reverse sort direction. Applicable in Process View and Connection View.

**FR-6.5**: Filtering: interactive text filter bar (activated by `/` key).
Filters match against process name, remote address, or domain name.
Substring match, case-insensitive.

**FR-6.6**: Sparklines: 60-sample history rendered using Unicode block
elements. Displayed in Connection View (per-connection rate) and Interface
View (per-interface rate). One character per sample.

**FR-6.7**: Color scheme:

- Rate-based heat coloring with configurable thresholds:
  - Green: low traffic
  - Yellow: moderate traffic
  - Red: high traffic
- Default thresholds: green < 1 KB/s, yellow 1-100 KB/s, red > 100 KB/s.
- Respect `NO_COLOR` environment variable (disable all colors when set).
- Respect `--no-color` flag.

**FR-6.8**: Keyboard controls:

| Key | Action |
|-----|--------|
| `q`, `Ctrl-C` | Quit |
| `Tab` | Cycle to next view: Process -> Connection -> Interface -> DNS |
| `Shift-Tab` | Cycle to previous view |
| `1` | Jump to Process View |
| `2` | Jump to Connection View |
| `3` | Jump to Interface View |
| `4` | Jump to DNS View |
| `/` | Open filter bar |
| `Esc` | Close filter bar / cancel |
| `s` | Cycle sort column |
| `S` | Reverse sort direction |
| `Up` / `Down` | Navigate rows |
| `Enter` | Expand/collapse row (Process View) |
| `PgUp` / `PgDn` | Scroll by page |
| `Home` / `End` | Jump to top / bottom |
| `?` | Toggle help overlay |

**FR-6.9**: Terminal requirements: minimum 80 columns x 24 rows. If terminal
is smaller, display a warning message instead of the TUI.

## 5. Non-Functional Requirements

### NFR-1: Performance

**NFR-1.1**: BPF capture must not drop packets at sustained 1 Gbps with average
500-byte packets (approximately 250,000 packets per second). Drop rate < 1%.

**NFR-1.2**: TUI render loop must complete within 16ms (60fps capable) even
with 5000 tracked connections.

**NFR-1.3**: Memory usage must not exceed 200 MB RSS with 5000 concurrent
connections and full time-series history retained.

**NFR-1.4**: CPU usage during idle monitoring (no network traffic) must be
less than 2% of one CPU core.

### NFR-2: Reliability

**NFR-2.1**: Process exit: stale process entries must be removed within one
polling cycle (default 1 second).

**NFR-2.2**: Interface up/down: detected and reflected in the interface list
within one polling cycle.

**NFR-2.3**: BPF device unavailability: if all `/dev/bpfN` devices are in use,
report a clear error message to stderr and exit with code 2.

### NFR-3: Security

**NFR-3.1**: Capture packet headers only. Never store, display, or log packet
payload data.

**NFR-3.2**: No network transmission of any captured data. netop is strictly
a local monitoring tool.

**NFR-3.3**: No configuration files, no state files on disk, no log files in
normal operation.

### NFR-4: Usability

**NFR-4.1**: Single binary distribution. No runtime dependencies beyond macOS
system libraries.

**NFR-4.2**: Time from `sudo netop` invocation to first TUI display: less than
1 second.

**NFR-4.3**: Clear, actionable error messages for common failure modes:

- Not running as root
- No BPF devices available
- Insufficient terminal size

## 6. CLI Interface Specification

```text
USAGE:
    sudo netoproc [OPTIONS]

OPTIONS:
    --duration <SECONDS>    Snapshot mode: collect for N seconds then output and exit.
                            Without this flag, monitor (TUI) mode runs by default.
                            Range: 1.0 to 3600.0

    --monitor               Explicitly enter monitor (TUI) mode (default behavior).

    --format <FORMAT>       Output format for snapshot mode [default: tsv]
                            Possible values: tsv, json, pretty
                            Ignored in monitor mode.

    --filter <PATTERN>      Filter output by pattern. Matches against process name,
                            remote address, or domain name. Case-insensitive
                            substring match.

    --interface <IFACE>     Monitor only the specified network interface.
                            Example: --interface en0
                            Default: all interfaces.

    --sort <COLUMN>         Initial sort column for monitor mode.
                            Possible values: traffic, pid, name, connections
                            Default: traffic

    --no-color              Disable colored output. Also activated when
                            the NO_COLOR environment variable is set.

    --no-dns                Disable DNS observatory. Reduces BPF capture load
                            and disables DNS-related output sections.

    --bpf-buffer <BYTES>    BPF kernel buffer size in bytes.
                            Default: 2097152 (2 MB)
                            Range: 4096 to 16777216 (4 KB to 16 MB)

    --version               Print version information and exit.
    --help                  Print help message and exit.
```

## 7. Data Model Specification

The canonical data model. All field names are authoritative and must be used
consistently across TSV column headers, JSON field names, and Rust struct fields.

```text
SystemNetworkState
├── timestamp: u64              // Unix timestamp in milliseconds
├── interfaces: Vec<Interface>
├── processes: Vec<Process>
└── dns: DnsObservatory

Interface
├── name: String                // e.g., "en0", "lo0"
├── ipv4_addresses: Vec<String> // e.g., ["192.168.1.100"]
├── ipv6_addresses: Vec<String> // e.g., ["fe80::1"]
├── dns_servers: Vec<String>    // e.g., ["192.168.1.1", "8.8.8.8"]
├── search_domains: Vec<String> // e.g., ["local", "corp.example.com"]
├── status: InterfaceStatus     // Up | Down
├── rx_bytes_rate: f64          // bytes per second
├── tx_bytes_rate: f64          // bytes per second
├── rx_bytes_total: u64         // cumulative since netop start
├── tx_bytes_total: u64
├── rx_packets: u64
├── tx_packets: u64
├── rx_errors: u64
└── tx_errors: u64

Process
├── pid: u32
├── name: String                // short process name
├── cmdline: String             // full command line (argv joined by spaces)
├── uid: u32
├── username: String
└── sockets: Vec<Socket>

Socket
├── fd: i32
├── protocol: Protocol          // TCP | UDP | ICMP
├── local_addr: String          // "addr:port" or "*:port" or "*:*"
├── state: SocketState          // see FR-1.3 for TCP/UDP/ICMP states
└── connections: Vec<Connection>

Connection
├── remote_addr: String         // "addr:port"
├── direction: Direction        // Inbound | Outbound
├── interface: String           // interface name, e.g., "en0"
├── rx_rate: RateMetrics
├── tx_rate: RateMetrics
├── rx_bytes_total: u64         // cumulative since monitoring start
├── tx_bytes_total: u64
└── stability: Option<ConnectionStability>  // None for UDP, Some for TCP

RateMetrics
├── bytes_per_sec: f64          // 1-second aggregation
└── bytes_per_min: f64          // 1-minute aggregation

ConnectionStability              // TCP only
├── rtt_us: u32                 // smoothed RTT in microseconds
├── jitter_us: u32              // RTT standard deviation in microseconds
├── retransmissions: u64        // cumulative count
└── retransmit_rate: f64        // retransmissions per second (10s window)

DnsObservatory
├── resolvers: Vec<DnsResolver>
└── queries: Vec<DnsQuery>

DnsResolver
├── interface: String           // associated network interface
├── server: String              // DNS server address
├── avg_latency_ms: f64         // average query latency in milliseconds
├── failure_rate_pct: f64       // percentage of failed queries
└── query_count: u64            // total queries observed to this resolver

DnsQuery
├── timestamp_ms: u64           // monotonic timestamp in milliseconds
├── pid: Option<u32>            // None if process attribution failed
├── process: String             // process name or "unknown"
├── query_name: String          // e.g., "example.com"
├── query_type: String          // e.g., "A", "AAAA", "CNAME", "MX"
├── response: String            // resolved address(es), "NXDOMAIN", "SERVFAIL", "timeout"
├── latency_ms: f64             // response time in milliseconds
└── resolver: String            // DNS server address used
```

## 8. Time-Series Storage Specification

### 8.1 Bucket Structure

Each connection and each interface maintains three levels of time-series data:

| Level | Bucket Size | Buffer Capacity | Window Covered | Purpose |
|-------|------------|-----------------|----------------|---------|
| L0 | 100ms | 10 samples | 1 second | Instantaneous rate computation |
| L1 | 1s | 60 samples | 1 minute | TUI display, snapshot output |
| L2 | 1min | 60 samples | 1 hour | Sparkline trend visualization |

### 8.2 Aggregation Rules

- L0 -> L1: Every 10 L0 samples (1 second), compute the **sum** of byte counts
  and push to L1 buffer.
- L1 -> L2: Every 60 L1 samples (1 minute), compute the **sum** of byte counts
  and push to L2 buffer.
- RTT aggregation: **weighted moving average** at each level.
- Jitter aggregation: **maximum** jitter observed in the aggregation window.

### 8.3 Overflow Behavior

- Ring buffers overwrite the oldest entry when full. No dynamic growth.
- Byte counters (u64): wrap at 2^64 (18.4 EB). No practical overflow concern.
- Rate computation must handle counter wrap (subtract with wrapping arithmetic).

### 8.4 Memory Budget

Per connection: 10 + 60 + 60 = 130 samples x 2 (RX + TX) x 8 bytes = 2,080 bytes.
For 5000 connections: approximately 10 MB. Well within the 200 MB RSS limit.

## 9. Error Codes and Exit Behavior

| Exit Code | Condition | Stderr Message Format |
|-----------|-----------|----------------------|
| 0 | Normal termination | (none) |
| 1 | Not running as root | `error: netop requires root privileges. Run with: sudo netop` |
| 2 | BPF device error (all busy or permission denied) | `error: cannot open BPF device: {detail}. Ensure no other capture tools are running.` |
| 3 | Invalid command-line arguments | `error: {clap-generated message}` |
| 4 | Runtime fatal error (unexpected) | `error: fatal: {detail}` |

All error messages are written to stderr. Normal output (snapshot) goes to stdout.
Exit codes are mutually exclusive; the first fatal condition encountered determines
the exit code.

## 10. Constraints and Exclusions

### Explicitly NOT supported

- Linux, Windows, or any non-macOS operating system.
- Running without root/sudo privileges.
- Remote monitoring or agent mode.
- Web UI or HTTP API.
- Historical data export or persistence (no database, no file logging).
- PCAP file import or export.
- Deep packet inspection (Layer 7 / application-layer protocol analysis beyond DNS).
- Configuration files (all configuration via CLI flags).
- IPv6-only systems with no IPv4 stack (IPv6 is supported alongside IPv4).

### Explicitly NOT in scope for initial version

- Container/cgroup awareness (may be added later).
- GeoIP or ASN lookup for remote addresses.
- Custom BPF filter expressions from user input.
- DoH (DNS over HTTPS, port 443) or DoT (DNS over TLS, port 853) monitoring.

## 11. Acceptance Criteria

Each acceptance criterion (AC) maps directly to a functional requirement (FR).

| ID | Requirement | Criterion |
|----|------------|-----------|
| AC-1.1 | FR-1.1 | `sudo netop snapshot --format json \| jq '.processes \| length'` returns a number >= 1 on any macOS system with network activity. |
| AC-1.2 | FR-1.3 | For a process running `nc -l 12345`, `sudo netop snapshot --format json \| jq '.processes[] \| select(.name=="nc") \| .sockets[] \| select(.local_addr=="*:12345")'` returns a result with `state: "LISTEN"`. |
| AC-2.1 | FR-2.1 | During an active `curl` download, a connection entry appears with a non-zero `rx_bytes_sec` and the correct remote address. |
| AC-2.2 | FR-2.2 | After running for 5 seconds, the 1s rate column shows a value consistent with observed traffic volume (within 20% of actual). |
| AC-2.3 | FR-2.4 | For an ESTABLISHED TCP connection, `rtt_us > 0` and `retransmissions >= 0`. |
| AC-3.1 | FR-3.1 | `sudo netop snapshot --format json \| jq '.interfaces[] \| .name'` lists at least `lo0` and one physical interface (e.g., `en0`). |
| AC-3.2 | FR-3.3 | For an interface with DNS configured, `dns_servers` array is non-empty and contains valid IP addresses. |
| AC-4.1 | FR-4.2 | After running `dig example.com`, a DNS query entry appears in `dns_queries` with `query_name: "example.com"`. |
| AC-4.2 | FR-4.4 | DNS query entry includes `latency_ms > 0` and a valid `resolver` address. |
| AC-4.3 | FR-4.5 | DNS query entry includes the correct `pid` and `process` name for the `dig` command. |
| AC-5.1 | FR-5.2 | `sudo netop snapshot` (default TSV) output is parseable by `awk -F'\t'` with consistent column counts per section. |
| AC-5.2 | FR-5.3 | `sudo netop snapshot --format json` output is valid JSON (parseable by `jq .`). |
| AC-5.3 | FR-5.4 | Snapshot output contains no ANSI escape codes (verified by piping through `cat -v`). |
| AC-5.4 | FR-5.7 | `time sudo netop snapshot` completes in under 2 seconds. |
| AC-6.1 | FR-6.1 | `sudo netop` launches a full-screen TUI without errors. |
| AC-6.2 | FR-6.2 | Pressing `Tab` cycles through all four views without crashing. |
| AC-6.3 | FR-6.5 | Typing `/curl` in monitor mode filters the display to show only curl-related entries. |
| AC-6.4 | FR-6.7 | Running with `NO_COLOR=1 sudo netop` produces output without ANSI color codes. |
