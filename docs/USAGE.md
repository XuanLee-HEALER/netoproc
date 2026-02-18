# USAGE.md — netop User Guide

## NAME

netop — real-time per-process network traffic monitor for macOS

## SYNOPSIS

```
sudo netop [OPTIONS] [COMMAND]
```

## DESCRIPTION

netop is a terminal-based network monitoring tool for macOS that shows per-process,
per-socket, per-connection network traffic in real time. It answers three questions
at a glance:

1. **Which processes** are using the network?
2. **Who are they talking to** (remote addresses, DNS lookups)?
3. **How much bandwidth** is each connection consuming?

netop captures packet headers via BPF (Berkeley Packet Filter) and correlates
them with process and socket information from macOS system APIs to produce a
unified view.

Unlike `nettop` (Apple's built-in), netop provides:
- Per-connection traffic rates (not just per-process aggregates)
- A dedicated DNS observatory (query log, resolver performance)
- A pipe-friendly snapshot mode for scripting
- htop-style keyboard navigation and filtering

Unlike `netstat`, netop shows **live traffic rates**, not just connection state.

Unlike `tcpdump`/Wireshark, netop focuses on **who is sending traffic**, not
the packet contents.

## COMMANDS

### `monitor` (default)

Launch the interactive full-screen TUI. This is the default when no command
is specified.

```
sudo netop
sudo netop monitor
sudo netop monitor --interval 0.5
```

The TUI provides four views (Process, Connection, Interface, DNS) that can
be switched with keyboard shortcuts. See **TUI CONTROLS** below.

### `snapshot`

Capture the current network state and print it to stdout, then exit. Designed
for scripting, logging, and piping to other Unix tools.

```
sudo netop snapshot
sudo netop snapshot --format json
sudo netop snapshot --format tsv | column -t -s $'\t'
```

Output contains no ANSI escape codes, no progress indicators, and no
interactive prompts. Suitable for `awk`, `cut`, `sort`, `jq`, and other
text processing tools.

## OPTIONS

```
--format <FORMAT>
    Output format for snapshot mode.
    Values: tsv (default), json
    Ignored in monitor mode.

--interval <SECONDS>
    Polling and refresh interval in seconds.
    Default: 1.0
    Range: 0.1 to 10.0
    Lower values give more responsive updates but increase CPU usage.
    In snapshot mode, this controls the data collection window.

--filter <PATTERN>
    Filter by pattern. Matches against process name, remote address,
    or domain name. Case-insensitive substring match.
    Example: --filter firefox
    Example: --filter 8.8.8.8
    Example: --filter github.com

--interface <IFACE>
    Monitor only the specified network interface.
    Default: all interfaces.
    Example: --interface en0
    Example: --interface lo0

--sort <COLUMN>
    Initial sort column for monitor mode.
    Values: traffic (default), pid, name, connections
    Can be changed interactively in the TUI.

--no-color
    Disable all colored output. Also activated when the NO_COLOR
    environment variable is set (any value).

--no-dns
    Disable the DNS observatory feature. This stops BPF capture of
    port 53 traffic and disables DNS-related output sections.
    Reduces CPU and memory usage slightly.

--bpf-buffer <BYTES>
    BPF kernel buffer size in bytes.
    Default: 32768 (32 KB)
    Range: 4096 (4 KB) to 1048576 (1 MB)
    Increase if you see high packet drop rates on busy networks.

--version
    Print version information and exit.

--help
    Print help message and exit.
```

## PRIVILEGE REQUIREMENTS

netop **requires root privileges**. Always run with `sudo`:

```
sudo netop
```

Running without sudo produces an error and exits immediately:

```
$ netop
error: netop requires root privileges. Run with: sudo netop
```

**Why root is needed:**

- **BPF device access** (`/dev/bpfN`): Packet capture requires opening BPF
  device files, which are restricted to root on macOS.
- **Cross-user process inspection**: Enumerating sockets for all processes
  (not just your own) requires root-level `libproc` access.
- **Kernel data structures**: Reading the TCP/UDP connection tables via
  `sysctl` requires elevated privileges for complete data.

## TUI CONTROLS

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` | Quit netop |
| `Ctrl-C` | Quit netop |
| `Tab` | Cycle to next view: Process → Connection → Interface → DNS → Process |
| `Shift-Tab` | Cycle to previous view |
| `1` | Jump to Process View |
| `2` | Jump to Connection View |
| `3` | Jump to Interface View |
| `4` | Jump to DNS View |
| `/` | Open filter bar (type a pattern, press Enter to apply) |
| `Esc` | Close filter bar without applying, or clear active filter |
| `s` | Cycle sort column forward |
| `S` (Shift-s) | Reverse sort direction (ascending ↔ descending) |
| `↑` / `↓` | Navigate rows up/down |
| `Enter` | Expand or collapse selected row (Process View only) |
| `PgUp` / `PgDn` | Scroll by one page |
| `Home` / `End` | Jump to first / last row |
| `?` | Toggle help overlay |

### Status Bar

The bottom of the screen shows:
- Current view name
- Active filter (if any)
- Sort column and direction
- Refresh interval
- Total monitored connections

## VIEWS

### 1. Process View

The default view. Shows a table of all processes with open network sockets,
sorted by aggregate traffic rate.

```
 PID   Process    User     Sockets  Conns   RX Rate     TX Rate     RX Total    TX Total
 1842  firefox    admin    12       8       ▂▃▅▇ 2.1M   ▁▁▂▃ 340K  128.5 MB    12.3 MB
 2103  curl       admin    1        1       ▇▅▃▁ 512K   ▁▁▁▁  12K  5.2 MB      102 KB
 ...
```

**Columns:**
- `PID`: Process ID
- `Process`: Short process name
- `User`: Owning username
- `Sockets`: Number of open network sockets
- `Conns`: Number of active connections (ESTABLISHED or active UDP flows)
- `RX Rate`: Receive rate with sparkline (bytes/sec, auto-scaled)
- `TX Rate`: Transmit rate with sparkline
- `RX Total`: Total bytes received since netop started
- `TX Total`: Total bytes transmitted since netop started

**Expandable rows**: Press `Enter` on a process to expand it and see its
individual sockets and connections:

```
 1842  firefox    admin    12       8       ▂▃▅▇ 2.1M   ▁▁▂▃ 340K  128.5 MB    12.3 MB
   ├─ fd=5  TCP  192.168.1.100:54321 → 140.82.121.4:443    ESTABLISHED  en0  ↓1.2M ↑200K
   ├─ fd=6  TCP  192.168.1.100:54322 → 151.101.1.69:443    ESTABLISHED  en0  ↓800K ↑140K
   ├─ fd=7  UDP  192.168.1.100:51234 → 192.168.1.1:53      dns query    en0  ↓1K   ↑1K
   └─ fd=8  TCP  *:0                   (no connection)      CLOSED            -     -
```

### 2. Connection View

A flat table of all active connections across all processes, with detailed
traffic metrics.

```
 Process   Local               Remote              Proto  State        Dir   Iface  RX Rate   TX Rate   RTT      Retrans
 firefox   192.168.1.100:54321 140.82.121.4:443    TCP    ESTABLISHED  Out   en0    1.2 MB/s  200 KB/s  12ms     0
 node      *:3000              10.0.0.5:49201      TCP    ESTABLISHED  In    en0    50 KB/s   1.5 MB/s  0.5ms    2
 curl      192.168.1.100:54400 93.184.216.34:443   TCP    ESTABLISHED  Out   en0    512 KB/s  12 KB/s   45ms     0
 ...
```

**Columns:**
- `Process`: Process name (with PID on hover or expansion)
- `Local`: Local address:port
- `Remote`: Remote address:port
- `Proto`: Protocol (TCP, UDP, ICMP)
- `State`: TCP state or UDP state
- `Dir`: Direction — `In` (inbound) or `Out` (outbound)
- `Iface`: Network interface
- `RX Rate`: Receive bytes/sec
- `TX Rate`: Transmit bytes/sec
- `RTT`: Round-trip time (TCP only, displayed as ms)
- `Retrans`: Retransmission count (TCP only)

**Color coding** (default thresholds):
- Green: < 1 KB/s
- Yellow: 1 KB/s – 100 KB/s
- Red: > 100 KB/s

### 3. Interface View

Card layout showing one card per network interface.

```
┌─ en0 (Wi-Fi) ─────────────────── UP ──────────────────────────────────┐
│  IPv4: 192.168.1.100                                                  │
│  IPv6: fe80::1a2b:3c4d:5e6f:7890                                     │
│  DNS:  192.168.1.1, 8.8.8.8                                          │
│                                                                       │
│  RX: ▁▂▃▅▇▇▅▃▂▁▁▂▃▅▇▆▅▃▂▁  2.1 MB/s    Total: 1.2 GB              │
│  TX: ▁▁▁▁▂▃▂▁▁▁▁▁▂▃▃▂▁▁▁▁  340 KB/s    Total: 102 MB              │
│                                                                       │
│  Packets:  RX 1,234,567  TX 234,567    Errors: RX 0  TX 0            │
└───────────────────────────────────────────────────────────────────────┘

┌─ lo0 (Loopback) ──────────────── UP ──────────────────────────────────┐
│  IPv4: 127.0.0.1                                                      │
│  IPv6: ::1                                                            │
│  DNS:  (none)                                                         │
│                                                                       │
│  RX: ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁  12 KB/s     Total: 50 MB               │
│  TX: ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁  12 KB/s     Total: 50 MB               │
│                                                                       │
│  Packets:  RX 50,000  TX 50,000          Errors: RX 0  TX 0          │
└───────────────────────────────────────────────────────────────────────┘
```

**Sparklines**: The horizontal bar charts show 60 samples of 1-minute
aggregated traffic. Each character represents one minute. The block height
represents relative traffic volume within the visible range.

### 4. DNS View

Split layout with resolver statistics at the top and a live query log at the bottom.

**Top: Resolver Statistics**
```
 Interface  Server         Avg Latency  Fail Rate  Queries
 en0        192.168.1.1    12.3 ms      0.5%       1,234
 en0        8.8.8.8        18.7 ms      0.1%       567
 utun3      10.0.0.1       45.2 ms      2.1%       89
```

**Bottom: Live Query Log**
```
 Time      Process   Query                    Type  Response            Latency  Resolver
 12:00:01  firefox   github.com               A     140.82.121.4        12ms     192.168.1.1
 12:00:01  firefox   api.github.com           AAAA  2606:50c0:8003::154 15ms     192.168.1.1
 12:00:02  curl      example.com              A     93.184.216.34       18ms     8.8.8.8
 12:00:03  node      nonexistent.local        A     NXDOMAIN            45ms     10.0.0.1
 12:00:03  unknown   telemetry.example.com    A     203.0.113.50        22ms     192.168.1.1
 ...
```

**Query log columns:**
- `Time`: Wall-clock timestamp (HH:MM:SS)
- `Process`: Process that made the query (or "unknown" if attribution failed)
- `Query`: Domain name queried
- `Type`: DNS query type (A, AAAA, CNAME, MX, PTR, SRV, etc.)
- `Response`: Resolved address(es), NXDOMAIN, or SERVFAIL
- `Latency`: Time from query to response in milliseconds
- `Resolver`: DNS server that handled the query

## SNAPSHOT OUTPUT

### TSV Format (Default)

The TSV output is divided into sections. Each section starts with a comment
line (prefixed with `#`) naming the section, followed by a tab-separated
header row, followed by data rows. Sections are separated by blank lines.

```
# processes
pid	name	user	socket_count	connection_count	rx_bytes_sec	tx_bytes_sec	rx_bytes_total	tx_bytes_total
1842	firefox	admin	12	8	2150400	348160	134742016	12897280
2103	curl	admin	1	1	524288	12288	5452595	104448

# sockets
pid	process	fd	proto	local_addr	state
1842	firefox	5	TCP	192.168.1.100:54321	ESTABLISHED
1842	firefox	6	TCP	192.168.1.100:54322	ESTABLISHED
1842	firefox	8	TCP	*:0	CLOSED
2103	curl	5	TCP	192.168.1.100:54400	ESTABLISHED

# connections
pid	process	fd	proto	local_addr	remote_addr	direction	state	interface	rx_bytes_sec	tx_bytes_sec	rx_bytes_total	tx_bytes_total	rtt_us	jitter_us	retransmissions
1842	firefox	5	TCP	192.168.1.100:54321	140.82.121.4:443	outbound	ESTABLISHED	en0	1258291	204800	67371008	6448640	12000	500	0
1842	firefox	6	TCP	192.168.1.100:54322	151.101.1.69:443	outbound	ESTABLISHED	en0	819200	143360	53477376	5132288	18000	1200	3
2103	curl	5	TCP	192.168.1.100:54400	93.184.216.34:443	outbound	ESTABLISHED	en0	524288	12288	5452595	104448	45000	2000	0

# interfaces
name	ipv4_addr	ipv6_addr	status	rx_bytes_sec	tx_bytes_sec	rx_bytes_total	tx_bytes_total	rx_packets	tx_packets	rx_errors	tx_errors
en0	192.168.1.100	fe80::1a2b:3c4d:5e6f:7890	up	2150400	348160	1288490189	107374182	1234567	234567	0	0
lo0	127.0.0.1	::1	up	12288	12288	52428800	52428800	50000	50000	0	0

# dns_resolvers
interface	server	avg_latency_ms	failure_rate_pct	query_count
en0	192.168.1.1	12.3	0.5	1234
en0	8.8.8.8	18.7	0.1	567

# dns_queries
timestamp_ms	pid	process	query_name	query_type	response	latency_ms	resolver
1739875201000	1842	firefox	github.com	A	140.82.121.4	12.0	192.168.1.1
1739875201050	1842	firefox	api.github.com	AAAA	2606:50c0:8003::154	15.0	192.168.1.1
1739875202000	2103	curl	example.com	A	93.184.216.34	18.0	8.8.8.8
```

**Parsing examples:**

```bash
# Extract just process names and their RX rates
sudo netop snapshot | awk -F'\t' '/^[0-9]/ && section=="processes" {print $2, $6} /^# processes/{section="processes"} /^$/{section=""}'

# Simpler: use JSON format with jq
sudo netop snapshot --format json | jq '.processes[] | {name, rx_rate: .sockets[].connections[].rx_rate.bytes_per_sec}'
```

### JSON Format

A single JSON object matching the SystemNetworkState data model. All field
names use snake_case. Arrays may be empty but are always present. Numeric
values are JSON numbers.

```json
{
  "timestamp": 1739875201000,
  "interfaces": [
    {
      "name": "en0",
      "ipv4_addresses": ["192.168.1.100"],
      "ipv6_addresses": ["fe80::1a2b:3c4d:5e6f:7890"],
      "dns_servers": ["192.168.1.1", "8.8.8.8"],
      "search_domains": ["local"],
      "status": "up",
      "rx_bytes_rate": 2150400.0,
      "tx_bytes_rate": 348160.0,
      "rx_bytes_total": 1288490189,
      "tx_bytes_total": 107374182,
      "rx_packets": 1234567,
      "tx_packets": 234567,
      "rx_errors": 0,
      "tx_errors": 0
    }
  ],
  "processes": [
    {
      "pid": 1842,
      "name": "firefox",
      "cmdline": "/Applications/Firefox.app/Contents/MacOS/firefox",
      "uid": 501,
      "username": "admin",
      "sockets": [
        {
          "fd": 5,
          "protocol": "tcp",
          "local_addr": "192.168.1.100:54321",
          "state": "established",
          "connections": [
            {
              "remote_addr": "140.82.121.4:443",
              "direction": "outbound",
              "interface": "en0",
              "rx_rate": {
                "bytes_per_sec": 1258291.0,
                "bytes_per_min": 75497472.0
              },
              "tx_rate": {
                "bytes_per_sec": 204800.0,
                "bytes_per_min": 12288000.0
              },
              "rx_bytes_total": 67371008,
              "tx_bytes_total": 6448640,
              "stability": {
                "rtt_us": 12000,
                "jitter_us": 500,
                "retransmissions": 0,
                "retransmit_rate": 0.0
              }
            }
          ]
        }
      ]
    }
  ],
  "dns": {
    "resolvers": [
      {
        "interface": "en0",
        "server": "192.168.1.1",
        "avg_latency_ms": 12.3,
        "failure_rate_pct": 0.5,
        "query_count": 1234
      }
    ],
    "queries": [
      {
        "timestamp_ms": 1739875201000,
        "pid": 1842,
        "process": "firefox",
        "query_name": "github.com",
        "query_type": "A",
        "response": "140.82.121.4",
        "latency_ms": 12.0,
        "resolver": "192.168.1.1"
      }
    ]
  }
}
```

## EXAMPLES

### Basic monitoring

```bash
sudo netop
```

Launches the interactive TUI in Process View. Navigate with arrow keys,
press `Tab` to switch views, `q` to quit.

### Snapshot in JSON, find top talkers

```bash
sudo netop snapshot --format json | jq '
  [.processes[] | {
    name: .name,
    rx: ([.sockets[].connections[].rx_bytes_total] | add // 0),
    tx: ([.sockets[].connections[].tx_bytes_total] | add // 0)
  }] | sort_by(.rx) | reverse | .[0:5]'
```

### Monitor a specific interface

```bash
sudo netop monitor --interface en0
```

Only shows traffic and connections on the Wi-Fi interface.

### Filter for a specific process

```bash
sudo netop monitor --filter firefox
```

Only shows processes, connections, and DNS queries matching "firefox".

### Fast refresh for debugging

```bash
sudo netop monitor --interval 0.5
```

Updates the display twice per second for more responsive monitoring.

### TSV snapshot with human-readable formatting

```bash
sudo netop snapshot | column -t -s $'\t'
```

Aligns columns for easy reading in the terminal.

### Monitor without DNS overhead

```bash
sudo netop monitor --no-dns
```

Disables DNS query capture and the DNS view. Useful if you only care about
traffic volume, not DNS activity.

### Pipe TSV to find connections to a specific remote

```bash
sudo netop snapshot | awk -F'\t' '$6 ~ /8\.8\.8\.8/'
```

Finds all connections to Google DNS (8.8.8.8).

### Check DNS resolver performance

```bash
sudo netop snapshot --format json | jq '.dns.resolvers | sort_by(.avg_latency_ms)'
```

Lists DNS resolvers sorted by average latency.

### Continuous logging (append snapshots every 60 seconds)

```bash
while true; do
    sudo netop snapshot --format tsv >> /tmp/netop-log.tsv
    echo "" >> /tmp/netop-log.tsv
    sleep 60
done
```

## INTERPRETING METRICS

### Traffic Rates

Rates are auto-scaled with the following unit thresholds:

| Display | Range |
|---------|-------|
| B/s | 0 – 999 bytes/sec |
| KB/s | 1,000 – 999,999 bytes/sec |
| MB/s | 1,000,000 – 999,999,999 bytes/sec |
| GB/s | 1,000,000,000+ bytes/sec |

Note: these are base-10 units (1 KB = 1000 bytes), consistent with network
bandwidth conventions.

### RTT (Round-Trip Time)

| Range | Interpretation |
|-------|---------------|
| < 1 ms | Loopback or local network |
| 1 – 10 ms | Local network or nearby server |
| 10 – 50 ms | Regional (same continent) |
| 50 – 150 ms | Cross-continent |
| > 150 ms | Distant or congested path |

### Jitter

| Range | Interpretation |
|-------|---------------|
| < 1 ms | Excellent — suitable for real-time audio/video |
| 1 – 5 ms | Good — acceptable for most applications |
| 5 – 20 ms | Fair — may cause quality degradation in VoIP/video |
| > 20 ms | Poor — likely causes noticeable issues in real-time apps |

### Retransmissions

| Rate | Interpretation |
|------|---------------|
| 0% | Normal |
| 0.1 – 1% | Mild congestion or occasional packet loss |
| 1 – 5% | Significant congestion; throughput may be reduced |
| > 5% | Severe — investigate network path for issues |

### DNS Latency

| Range | Interpretation |
|-------|---------------|
| < 5 ms | Local caching resolver (e.g., dnsmasq, systemd-resolved) |
| 5 – 20 ms | LAN resolver (e.g., home router, corporate DNS) |
| 20 – 50 ms | Nearby recursive resolver (e.g., ISP DNS, 8.8.8.8) |
| 50 – 200 ms | Distant resolver or resolver under load |
| > 200 ms | Investigate — possible DNS misconfiguration |

### Sparklines

Sparklines use Unicode block elements to represent data visually:

```
Characters: ▁ ▂ ▃ ▄ ▅ ▆ ▇ █
             (low)       (high)
```

Each character represents one time sample. In the Connection and Process
views, sparklines show 60 seconds of per-second data. In the Interface
view, sparklines show 60 minutes of per-minute data.

The height of each bar is relative to the maximum value in the visible
window (auto-scaled), not an absolute scale.

## TROUBLESHOOTING

| Symptom | Cause | Solution |
|---------|-------|----------|
| `error: netop requires root privileges` | Not running as root | Run with `sudo netop` |
| `error: cannot open BPF device` | All BPF devices in use by other tools | Close Wireshark, tcpdump, or other capture tools |
| No traffic rates shown (all zeros) | BPF not capturing on correct interface | Check `--interface` flag; verify interface is active |
| Missing processes | Process exited before poll cycle | Normal transient behavior |
| DNS queries show "unknown" process | Socket closed before correlation | Normal timing limitation; the DNS query completed but the process closed the socket before the next poll |
| High CPU usage | Very fast refresh rate or heavy traffic | Increase `--interval` (e.g., `--interval 2`) |
| Garbled display | Terminal smaller than 80x24 | Resize terminal window |
| Sparklines not rendering | Terminal does not support Unicode | Use a modern terminal (iTerm2, Terminal.app, Alacritty) |
| Incorrect interface names | Custom network configuration | Use `ifconfig` to find the correct interface name |
| `[no data]` in DNS view | `--no-dns` flag is set | Remove `--no-dns` to enable DNS monitoring |

## ENVIRONMENT VARIABLES

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | If set to any value, disables all colored output. Equivalent to `--no-color`. See https://no-color.org/ |
| `RUST_LOG` | Set to `debug` or `trace` for diagnostic logging to stderr. For development/debugging only. Example: `RUST_LOG=debug sudo netop` |

## FILES

| Path | Description |
|------|-------------|
| `/dev/bpf0` – `/dev/bpf255` | BPF device files (opened for packet capture) |

netop does not create, read, or write any configuration files, log files,
or state files.

## COMPATIBILITY

| Requirement | Minimum |
|------------|---------|
| macOS | 26.0 (Tahoe) |
| Architecture | Apple Silicon (arm64) primary, Intel (x86_64) secondary |
| Terminal | 80 columns x 24 rows minimum, Unicode support |
| Privileges | root (sudo) |

Earlier macOS versions may work but are not tested or supported.

## SEE ALSO

| Tool | Comparison |
|------|-----------|
| `nettop(1)` | Apple's built-in network monitor. Shows per-process aggregate traffic but lacks per-connection rates, DNS observatory, and snapshot mode. |
| `netstat(1)` | Shows connection state (ESTABLISHED, LISTEN, etc.) but no live traffic rates. |
| `tcpdump(1)` | Packet-level capture and display. Shows raw packet contents, not per-process attribution or traffic rates. |
| `lsof(8)` | Lists open files including sockets. Shows connection state but no traffic data. |
| `Activity Monitor.app` | GUI tool with basic per-process network bytes. No per-connection detail or DNS monitoring. |
| `iftop` | Shows per-connection traffic rates but without process attribution. Linux-focused. |
| `nethogs` | Per-process bandwidth monitor. Linux-only, no macOS support. |
| `bandwhich` | Rust-based per-process/connection monitor. Cross-platform but limited macOS support and no DNS observatory. |
