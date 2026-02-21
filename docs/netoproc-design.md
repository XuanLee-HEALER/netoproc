# netoproc-design.md — netoproc Architecture and Design

## 1. Architecture Overview

netop uses a streaming three-thread architecture to separate blocking I/O
(BPF packet capture), process table maintenance, and traffic statistics /
UI rendering into independent execution contexts.

```text
┌─────────────────────────────────────────────────────────────┐
│                    Main Thread (Stats + UI)                   │
│                                                               │
│  Snapshot: drain channel → accumulate TrafficStats → output   │
│  Monitor:  bridge thread builds SystemNetworkState for TUI    │
└─────────────────────────────────────────────────────────────┘
         ▲ sync_channel(8)                ▲ ArcSwap load (lock-free)
         │ Vec<PacketSummary>             │
┌────────┴───────────┐          ┌─────────┴──────────────┐
│  BPF Capture       │          │  Process Refresh       │
│  Thread(s)         │          │  Thread                │
│                    │          │                        │
│  Blocking read on  │          │  Every 500ms:          │
│  /dev/bpfN         │          │  - libproc scan        │
│  Parse packets     │          │  - build ProcessTable  │
│  Set direction     │          │  - ArcSwap store       │
│  Send batch via    │          │                        │
│  sync_channel      │          │                        │
└────────────────────┘          └────────────────────────┘
```

### Why Three Threads

- **BPF Capture**: `read()` on BPF devices is a blocking syscall with a 500ms
  timeout. It must run in its own thread. If monitoring multiple interfaces,
  one thread per interface avoids head-of-line blocking. Each read returns a
  batch of packets sent as `Vec<PacketSummary>` through a bounded channel.
- **Process Refresh**: Building the `ProcessTable` via libproc takes 50-100ms.
  Running it on a dedicated thread (every 500ms) keeps the process table fresh
  without blocking the stats main loop. Uses `ArcSwap` for lock-free publishing.
- **Main Thread (Stats)**: Drains the packet channel, looks up each packet in
  the process table, and accumulates per-process `TrafficStats`. In snapshot
  mode, outputs results after the duration expires. In monitor mode, a bridge
  thread adapts the data for the TUI.

### Snapshot Mode

In snapshot mode, the main thread:

1. Accumulates `HashMap<ProcessKey, TrafficStats>` from packet batches.
2. After the specified duration, calls `drain_final()` to join BPF threads
   and drain remaining channel data.
3. Serializes per-process traffic to TSV, JSON, or pretty format.
4. Exits.

### Monitor Mode

In monitor mode, a bridge thread drains packets, polls system APIs, and
builds `SystemNetworkState` for TUI compatibility. The TUI runs in the
main thread with its existing event loop and views.

## 2. Module Decomposition

```text
src/
├── main.rs                 Entry point: privilege check, CLI parse, mode dispatch
├── cli.rs                  CLI argument definitions (clap derive)
├── privilege.rs            Root UID check, BPF device fd acquisition
├── error.rs                NetopError enum, thiserror derives
│
├── bpf/
│   ├── mod.rs              BPF device manager: open, configure, read loop
│   ├── filter.rs           BPF filter program construction
│   ├── packet.rs           Raw packet parser: Ethernet → IP → TCP/UDP headers
│   └── dns.rs              DNS wire format parser (query, response, name compression)
│
├── system/
│   ├── mod.rs              Orchestrator: poll all system APIs, return raw data
│   ├── process.rs          libproc FFI: PID list, fd list, socket info
│   ├── connection.rs       sysctl pcblist_n parsing, TCP state extraction
│   ├── interface.rs        getifaddrs() wrapper, if_data statistics
│   └── dns_config.rs       SystemConfiguration framework: DNS resolver enumeration
│
├── model/
│   ├── mod.rs              SystemNetworkState and all child structs
│   ├── traffic.rs          SocketKey, ProcessInfo, ProcessKey, TrafficStats, ProcessTable
│   ├── timeseries.rs       RingBuffer<T, N>, aggregation logic
│   └── correlation.rs      Join process↔socket↔connection, DNS→process attribution
│
├── state/
│   ├── mod.rs              SharedState type, ArcSwap wrapper
│   └── merge.rs            Merge BPF packet data with system poll data into model
│
├── output/
│   ├── mod.rs              Snapshot mode dispatcher
│   ├── tsv.rs              TSV serializer (per-process traffic table)
│   ├── json.rs             JSON serializer (per-process traffic array)
│   └── pretty.rs           Human-readable table with formatted sizes
│
└── tui/
    ├── mod.rs              App state, main event loop, view routing
    ├── event.rs            crossterm event handling (key, resize, tick timer)
    ├── views/
    │   ├── process.rs      Process table with expandable rows
    │   ├── connection.rs   Connection flat table
    │   ├── interface.rs    Interface cards with sparklines
    │   └── dns.rs          DNS observatory (resolver table + query log)
    ├── widgets/
    │   ├── sparkline.rs    Inline sparkline using Unicode block elements
    │   ├── rate.rs         Auto-scaling rate display (B/s → KB/s → MB/s → GB/s)
    │   └── filter_bar.rs   Interactive text input for filtering
    └── theme.rs            Color definitions, NO_COLOR support, rate thresholds
```

### Module Responsibilities

**main.rs**: Parses CLI via `cli.rs`. Calls `privilege::check_root()`. Acquires
BPF device fds via `privilege::open_bpf_devices()`. Spawns threads. Dispatches
to TUI event loop or snapshot serializer. Handles clean shutdown (join threads,
restore terminal).

**cli.rs**: Uses `clap` derive macros. Defines `Cli` struct with all flags per
netoproc-requirements.md Section 6. Validates ranges (interval 0.1-10.0, bpf-buffer
4096-1048576). No business logic.

**privilege.rs**: `check_root()` — calls `libc::getuid()`, returns error if
!= 0. `open_bpf_devices(interfaces)` — iterates `/dev/bpf0`..`/dev/bpf255`,
opens with `O_RDONLY`, configures with ioctls. Returns Vec of owned fds.

**error.rs**: Central error type:

```rust
#[derive(Debug, thiserror::Error)]
pub enum NetopError {
    #[error("netop requires root privileges. Run with: sudo netop")]
    NotRoot,
    #[error("cannot open BPF device: {0}. Ensure no other capture tools are running.")]
    BpfDevice(#[source] std::io::Error),
    #[error("sysctl error: {0}")]
    Sysctl(#[source] std::io::Error),
    #[error("libproc error: {0}")]
    Libproc(String),
    #[error("interface enumeration error: {0}")]
    Interface(#[source] std::io::Error),
    #[error("DNS parse error at offset {offset}: {detail}")]
    DnsParse { offset: usize, detail: String },
    #[error("serialization error: {0}")]
    Serialization(#[source] std::io::Error),
    #[error("TUI error: {0}")]
    Tui(#[source] std::io::Error),
    #[error("fatal: {0}")]
    Fatal(String),
}
```

**bpf/mod.rs**: `BpfCapture` struct owns fd, buffer, and filter. Methods:
`new(interface, buffer_size)` — open + configure. `read_packets(&mut self) ->
Vec<PacketSummary>` — blocking read, parse buffer. `stats(&self) -> BpfStats` —
ioctl BIOCGSTATS for drop count. Implements `Drop` to close fd.

**bpf/filter.rs**: Functions to construct `bpf_program` structs.
`traffic_filter()` — accept all IP packets, truncate to header.
`dns_filter()` — accept UDP/TCP with port 53, capture up to 512 bytes.
Output: `Vec<bpf_insn>` that can be passed to BIOCSETF ioctl.

**bpf/packet.rs**: `parse_bpf_buffer(buf: &[u8]) -> Vec<PacketSummary>`.
Iterates `bpf_hdr` entries in the buffer. For each, parses Ethernet header
(14 bytes), then IP header (variable length), then TCP/UDP header (port
extraction only). Returns `PacketSummary { timestamp, protocol, src_ip,
src_port, dst_ip, dst_port, ip_len }`.

**bpf/dns.rs**: `parse_dns(payload: &[u8]) -> Result<DnsMessage, NetopError>`.
Parses DNS header, question section (with name decompression), answer section
(A/AAAA/CNAME records). `DnsMessage { id, is_response, opcode, rcode,
questions: Vec<DnsQuestion>, answers: Vec<DnsAnswer> }`.

**system/process.rs**: `list_processes() -> Vec<RawProcess>`. Calls
`proc_listpids`, then for each PID calls `proc_pidinfo` for fd list, and
`proc_pidfdinfo` for each socket fd. Returns raw data without correlation.

**system/connection.rs**: `list_tcp_connections() -> Vec<RawTcpConnection>`.
Calls `sysctlbyname("net.inet.tcp.pcblist_n")`, parses the `xinpgen`/`xtcpcb_n`
structures. Similarly `list_udp_connections()` for UDP.

**system/interface.rs**: `list_interfaces() -> Vec<RawInterface>`. Calls
`getifaddrs()`, aggregates addresses and `if_data` statistics per interface name.

**system/dns_config.rs**: `list_dns_resolvers() -> Vec<RawDnsResolver>`. Uses
SystemConfiguration `SCDynamicStore` API to query per-service DNS configuration.
Maps service IDs to interface names.

**model/mod.rs**: All data model structs from netoproc-requirements.md Section 7. Derives
`Clone`, `serde::Serialize` (for JSON output). No business logic.

**model/timeseries.rs**: `RingBuffer<const N: usize>` — fixed-size circular
buffer backed by `[u64; N]`. Methods: `push(value)`, `sum()`, `mean()`,
`max()`, `iter()` (newest-first), `len()`, `is_empty()`.
`AggregatedTimeSeries` — wraps L0/L1/L2 ring buffers with automatic
aggregation on push.

**model/correlation.rs**: `correlate(processes: &[RawProcess], tcp:
&[RawTcpConnection], udp: &[RawUdpConnection], packets: &[PacketSummary],
dns_msgs: &[DnsMessage], prev_state: &SystemNetworkState) ->
SystemNetworkState`. The core join logic that combines all data sources into
the unified model. Matches by 5-tuple. Attributes DNS queries to processes
by ephemeral port lookup.

**state/mod.rs**: Type alias `SharedState = arc_swap::ArcSwap<SystemNetworkState>`.
Factory function `new_shared_state() -> Arc<SharedState>`.

**state/merge.rs**: `merge_into_state(current: &SystemNetworkState, new_raw:
RawSystemData, packets: Vec<PacketSummary>) -> SystemNetworkState`. Handles
incremental updates: preserves time-series history from `current`, appends
new samples, removes stale entries, adds new entries.

**output/tsv.rs**: `write_tsv(state: &SystemNetworkState, writer: &mut impl
Write) -> Result<()>`. Writes each section with `#` header comment, column
headers, and tab-separated data rows. Column order exactly as specified in
netoproc-requirements.md FR-5.5.

**output/json.rs**: `write_json(state: &SystemNetworkState, writer: &mut impl
Write) -> Result<()>`. Uses `serde_json::to_writer_pretty`. Field names match
data model.

**tui/mod.rs**: `App` struct holds: current view, sort state, filter state,
scroll position, shared state reference. `run(app: &mut App, state:
Arc<SharedState>) -> Result<()>` — main event loop.

**tui/event.rs**: `EventHandler` — spawns a thread that polls crossterm events
and emits tick events on a channel. `Event` enum: `Key(KeyEvent)`,
`Resize(u16, u16)`, `Tick`.

**tui/views/*.rs**: Each view implements a `render(area: Rect, buf: &mut Buffer,
state: &SystemNetworkState, app_state: &AppState)` function. Views are
stateless renderers; all state lives in `App`.

**tui/widgets/*.rs**: Reusable widget components. `Sparkline` renders a
`&[u64]` as Unicode block characters. `RateDisplay` formats bytes/sec with
auto-scaling units. `FilterBar` renders the text input area.

**tui/theme.rs**: `Theme` struct with color definitions. `fn rate_color(bytes_per_sec: f64) -> Color` applies threshold-based coloring. Checks `NO_COLOR` env var and `--no-color` flag.

## 3. Concurrency Architecture

### 3.1 Thread Model Detail (v0.2.0)

```text
Thread 1: BPF Capture (one per interface)
  let mut pkt_buf = Vec::new();
  loop {
      if SHUTDOWN_REQUESTED { return; }
      cap.read_packets(&mut pkt_buf);   // blocks for up to 500ms
      for pkt in &mut pkt_buf {
          pkt.direction = if local_ips.contains(&pkt.dst_ip) {
              Direction::Inbound
          } else {
              Direction::Outbound
          };
      }
      let batch = std::mem::take(&mut pkt_buf);
      tx.send(batch);   // blocks if channel full (backpressure)
  }

Thread 2: Process Refresh
  loop {
      if SHUTDOWN_REQUESTED { return; }
      thread::sleep(Duration::from_millis(500));
      let new_table = build_process_table();
      process_table.store(Arc::new(new_table));   // ArcSwap atomic swap
  }

Main Thread: Stats + Output
  // Snapshot mode:
  let mut stats: HashMap<ProcessKey, TrafficStats> = HashMap::new();
  while elapsed < duration {
      match pkt_rx.recv_timeout(100ms) {
          Ok(batch) => accumulate_batch(&batch, &process_table, &mut stats),
          Err(Timeout) => continue,
          Err(Disconnected) => break,
      }
  }
  drain_final(&pkt_rx, &process_table, &mut stats, bpf_handles);
  output::write_snapshot(&stats, format, &mut stdout);

  // Monitor mode:
  // Bridge thread flattens batches + uses old merge for TUI compatibility.
  // TUI runs in main thread with existing event loop.
```

### 3.2 Data Sharing: ArcSwap

The `arc_swap` crate provides `ArcSwap<T>`, which allows:

- **Writer** (stats poller): `store(Arc::new(new_state))` — O(1), atomic pointer swap.
- **Reader** (TUI): `load()` — returns a `Guard` that derefs to `&T`. Lock-free,
  wait-free, no contention with writer.

This is preferred over `RwLock` because:

- Readers never block writers (no priority inversion).
- Readers never block each other.
- The cost is one extra `Arc` clone per read (negligible).
- Old states are automatically dropped when all readers release their guards.

### 3.3 BPF-to-Stats Channel

Use `std::sync::mpsc::sync_channel::<Vec<PacketSummary>>(8)` — a bounded channel
of packet batches with capacity 8.

Rationale for batch channel with capacity 8:

- Each BPF `read()` blocks for up to 500ms (read timeout). The resulting batch
  is sent as a single `Vec<PacketSummary>`.
- Capacity 8 = 4 seconds of headroom before backpressure starts.
- When the channel is full, the BPF thread's `send()` blocks, which naturally
  delays the next `read()`. This is correct backpressure behavior — the kernel
  BPF buffer absorbs the delay.
- Unlike the previous per-packet channel, batching avoids channel overhead for
  high packet counts and eliminates the need for drop-oldest semantics.

### 3.4 Shutdown Protocol

Uses a global `AtomicBool` (`SHUTDOWN_REQUESTED`) set by SIGTERM/SIGINT signal
handlers and checked by all threads.

**Snapshot mode (duration expired)**:

1. Main thread detects `elapsed >= duration`.
2. Calls `drain_final()`: sets `SHUTDOWN_REQUESTED = true`, joins BPF threads
   (which drop their `SyncSender`), drains remaining channel data.
3. Outputs final statistics.
4. Sets `SHUTDOWN_REQUESTED = true`, joins process refresh and DNS threads.
5. Exit code 0.

**Monitor mode (Ctrl-C or `q`)**:

1. TUI exits its event loop.
2. Main thread sets `SHUTDOWN_REQUESTED = true`.
3. Joins bridge thread, BPF threads, process refresh thread, DNS thread.
4. Restores terminal state.
5. Exit code 0.

## 4. BPF Subsystem Design

### 4.1 Device Acquisition

```text
fn open_bpf_device() -> Result<OwnedFd, NetopError> {
    for i in 0..256 {
        let path = format!("/dev/bpf{}", i);
        match open(&path, OFlag::O_RDONLY, Mode::empty()) {
            Ok(fd) => return Ok(fd),
            Err(Errno::EBUSY) => continue,  // device in use by another process
            Err(Errno::ENOENT) => break,     // no more BPF devices
            Err(e) => return Err(NetopError::BpfDevice(e.into())),
        }
    }
    Err(NetopError::BpfDevice(io::Error::new(
        io::ErrorKind::AddrInUse,
        "all BPF devices are busy"
    )))
}
```

### 4.2 Device Configuration Sequence

After opening `/dev/bpfN`:

```text
1. BIOCSBLEN(buffer_size)      // Set read buffer size (default 2 MB)
2. BIOCSETIF(interface_name)   // Bind to network interface
3. BIOCSRTIMEOUT(500ms)        // Set read timeout (500ms)
4. BIOCSETF(filter_program)    // Install BPF filter (header-only capture)
5. BIOCPROMISC                 // Enable promiscuous mode (capture all traffic, not just ours)
6. BIOCGBLEN -> actual_size    // Read back actual buffer size (kernel may adjust)
```

The read buffer (`Vec<u8>`) is allocated to `actual_size` after step 6.

> **v0.2.0**: `BIOCIMMEDIATE` is no longer set. Without it, the kernel buffers
> packets until the read timeout (500ms) or the buffer fills, whichever comes
> first. This reduces small reads and matches the batch-oriented channel design.
> The default buffer size is now 2 MB (was 32 KB).

### 4.3 BPF Filter Programs

**General traffic filter** — captures all IPv4 and IPv6 packets, headers only:

```text
// Pseudo-code for BPF filter instructions:
// Accept all IP packets, kernel truncates to BIOCSBLEN (66 bytes for IPv4+TCP max header)
ldh [12]                    // Load EtherType from Ethernet header offset 12
jeq #0x0800, accept, next   // IPv4?
next: jeq #0x86DD, accept, drop  // IPv6?
accept: ret #65535          // Accept, capture up to snaplen
drop: ret #0                // Reject
```

Snap length for general traffic: 66 bytes (14 Ethernet + 20 IPv4 + 32 TCP max
with options). Set via BIOCSBLEN. For IPv6: 14 + 40 + 32 = 86 bytes. Use 96
bytes as a safe maximum.

**DNS filter** — captures packets on port 53 with full DNS payload:

```text
// Accept UDP or TCP packets with src or dst port 53
ldh [12]                         // EtherType
jeq #0x0800, ipv4, drop          // IPv4 only for simplicity (extend for IPv6)
ipv4: ldb [23]                   // IP protocol
jeq #17, udp, tcp_check          // UDP?
tcp_check: jeq #6, tcp, drop     // TCP?
udp: ldh [20]                    // IP flags+fragment offset
jset #0x1FFF, drop, udp_ports    // Drop fragments (can't read ports)
udp_ports: ldh [22]              // UDP src port (IP header assumed 20 bytes, no options check needed for port filter)
// Note: actual offset depends on IP header length. Use IHL field.
// Simplified here; real implementation must compute offset from IHL.
jeq #53, accept_dns, check_dst
check_dst: ldh [24]              // UDP dst port
jeq #53, accept_dns, drop
tcp: // similar logic for TCP ports
accept_dns: ret #512             // Capture up to 512 bytes (enough for most DNS)
drop: ret #0
```

Note: The actual BPF filter implementation must correctly compute TCP/UDP
header offsets using the IP Header Length (IHL) field for IPv4 and the fixed
40-byte header for IPv6.

### 4.4 BPF Buffer Parsing

Each `read()` from a BPF device returns one or more packets packed into the
buffer. The format is:

```text
┌──────────┬────────────┬─────────┬──────────┬────────────┬─────────┐
│ bpf_hdr  │  packet 1  │ padding │ bpf_hdr  │  packet 2  │ padding │ ...
└──────────┴────────────┴─────────┴──────────┴────────────┴─────────┘
```

`bpf_hdr` fields:

- `bh_tstamp`: timestamp (struct timeval)
- `bh_caplen`: captured bytes
- `bh_datalen`: original packet length
- `bh_hdrlen`: total header length (including padding to align packet data)

Advance to next packet: `offset += BPF_WORDALIGN(bpf_hdr.bh_hdrlen + bpf_hdr.bh_caplen)`.
`BPF_WORDALIGN` rounds up to the next 4-byte boundary.

### 4.5 DNS Wire Format Parser

Implements RFC 1035 Section 4 parsing:

```text
DNS Message Format:
┌──────────────────────┐
│      Header (12B)    │  ID, Flags, Counts
├──────────────────────┤
│     Question(s)      │  QNAME, QTYPE, QCLASS
├──────────────────────┤
│     Answer(s)        │  NAME, TYPE, CLASS, TTL, RDATA
├──────────────────────┤
│    Authority(s)      │  (parsed but not used)
├──────────────────────┤
│    Additional(s)     │  EDNS0 OPT record
└──────────────────────┘
```

**Name decompression**: DNS names use a compression scheme where a label can
be a pointer (two bytes starting with `0xC0`) to a previous name in the message.

```rust
fn decompress_name(buf: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut followed_pointer = false;
    let mut end_offset = 0;
    let mut hops = 0;

    loop {
        if hops > 256 { return Err(DnsParse { detail: "compression loop" }); }
        if offset >= buf.len() { return Err(DnsParse { detail: "truncated" }); }

        let len = buf[offset] as usize;
        if len == 0 {
            if !followed_pointer { end_offset = offset + 1; }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            if !followed_pointer { end_offset = offset + 2; }
            offset = ((len & 0x3F) << 8 | buf[offset + 1] as usize);
            followed_pointer = true;
            hops += 1;
            continue;
        }
        // Label
        offset += 1;
        name.push_str(std::str::from_utf8(&buf[offset..offset + len])?);
        name.push('.');
        offset += len;
        hops += 1;
    }

    Ok((name, if followed_pointer { end_offset } else { end_offset }))
}
```

## 5. System API Integration

### 5.1 libproc FFI (process.rs)

Required function signatures (from `<libproc/libproc.h>`):

```rust
extern "C" {
    fn proc_listpids(
        type_: u32,          // PROC_ALL_PIDS = 1
        typeinfo: u32,       // 0
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;              // returns bytes filled, or -1 on error

    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,       // PROC_PIDLISTFDS = 1
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,       // PROC_PIDFDSOCKETINFO = 3
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    fn proc_name(
        pid: c_int,
        buffer: *mut c_char,
        buffersize: u32,
    ) -> c_int;
}
```

Process enumeration strategy:

1. Call `proc_listpids` with a buffer of 4096 PIDs (covers most systems).
   If full, double and retry.
2. For each PID, call `proc_name` to get the short name.
3. Call `proc_pidinfo(PROC_PIDLISTFDS)` to get all fds.
4. Filter for `PROX_FDTYPE_SOCKET` (fd type = 2).
5. For each socket fd, call `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` to get
   `socket_fdinfo` containing: domain (AF_INET/AF_INET6), type (SOCK_STREAM/
   SOCK_DGRAM), protocol, local address, remote address.

**Error handling**: PIDs can vanish between listing and inspection. Silently
skip any PID that returns ESRCH (no such process) or EPERM.

**Performance**: Sequential enumeration of 500 processes with ~10 sockets each
takes approximately 50-100ms. Parallelization is not needed for the initial
version.

### 5.2 sysctl pcblist_n Parsing (connection.rs)

The kernel exposes the full TCP and UDP connection table via sysctl.

```rust
fn list_tcp_connections() -> Result<Vec<RawTcpConnection>> {
    let mut buf_size: usize = 0;
    // First call: get required buffer size
    sysctlbyname("net.inet.tcp.pcblist_n", null_mut(), &mut buf_size, null(), 0);
    let mut buf = vec![0u8; buf_size];
    // Second call: fill buffer
    sysctlbyname("net.inet.tcp.pcblist_n", buf.as_mut_ptr(), &mut buf_size, null(), 0);
    parse_tcppcblist(&buf[..buf_size])
}
```

Buffer structure:

```text
┌──────────────┐
│  xinpgen     │  Generation count header
├──────────────┤
│  xtcpcb_n    │  TCP PCB entry 1
├──────────────┤
│  xtcpcb_n    │  TCP PCB entry 2
├──────────────┤
│  ...         │
├──────────────┤
│  xinpgen     │  Generation count footer (must match header)
└──────────────┘
```

`xtcpcb_n` contains:

- `xt_inp`: Internet PCB with local/remote sockaddr, interface index
- `xt_tp`: TCP state (ESTABLISHED, LISTEN, etc.)
- TCP-specific fields: send window, receive window, RTT estimates (if available)

The generation count header and footer must match; if they differ, the data
changed during read and the operation must be retried.

### 5.3 Interface Statistics (interface.rs)

```rust
fn list_interfaces() -> Result<Vec<RawInterface>> {
    let mut ifaddrs: *mut libc::ifaddrs = null_mut();
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return Err(NetopError::Interface(io::Error::last_os_error()));
    }
    let _guard = scopeguard::guard(ifaddrs, |p| unsafe { libc::freeifaddrs(p) });

    let mut interfaces: HashMap<String, RawInterface> = HashMap::new();
    let mut current = ifaddrs;
    while !current.is_null() {
        let entry = unsafe { &*current };
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        let iface = interfaces.entry(name.to_string()).or_default();

        match entry.ifa_addr.as_ref().map(|a| a.sa_family as i32) {
            Some(AF_LINK) => {
                // Cast ifa_data to if_data, extract byte/packet/error counters
            },
            Some(AF_INET) => {
                // Extract IPv4 address from sockaddr_in
            },
            Some(AF_INET6) => {
                // Extract IPv6 address from sockaddr_in6
            },
            _ => {},
        }
        current = entry.ifa_next;
    }
    Ok(interfaces.into_values().collect())
}
```

### 5.4 DNS Configuration (dns_config.rs)

Uses Apple's SystemConfiguration framework:

```rust
// Pseudo-Rust (actual implementation requires Core Foundation FFI)
fn list_dns_resolvers() -> Result<Vec<RawDnsResolver>> {
    let store = SCDynamicStoreCreate(...);

    // Global DNS configuration
    let global_dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS");
    // global_dns is a CFDictionary with keys: ServerAddresses, SearchDomains

    // Per-service DNS configuration
    let services = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/DNS");
    for service_key in services {
        let dns_dict = SCDynamicStoreCopyValue(store, service_key);
        // Map service ID to interface name via Setup:/Network/Service/<id>/Interface
    }
}
```

Core Foundation types require careful memory management. Use `CFRelease` or
a Rust wrapper that implements `Drop`.

## 6. Data Model Implementation

### 6.1 Rust Struct Definitions

All structs derive `Clone` and `serde::Serialize`. Field names use snake_case
exactly as specified in netoproc-requirements.md Section 7.

```rust
#[derive(Clone, Serialize)]
pub struct SystemNetworkState {
    pub timestamp: u64,
    pub interfaces: Vec<Interface>,
    pub processes: Vec<Process>,
    pub dns: DnsObservatory,
}

#[derive(Clone, Copy, Serialize)]
pub enum Protocol { Tcp, Udp, Icmp }

#[derive(Clone, Copy, Serialize)]
pub enum Direction { Inbound, Outbound }

#[derive(Clone, Copy, Serialize)]
pub enum InterfaceStatus { Up, Down }

#[derive(Clone, Copy, Serialize)]
pub enum SocketState {
    // TCP states
    Closed, Listen, SynSent, SynReceived, Established,
    CloseWait, LastAck, FinWait1, FinWait2, Closing, TimeWait,
    // UDP states
    Bound, Connected,
    // ICMP
    Open,
}
```

### 6.2 RingBuffer Implementation

```rust
pub struct RingBuffer<const N: usize> {
    data: [u64; N],
    head: usize,    // next write position
    count: usize,   // number of valid entries (0..=N)
}

impl<const N: usize> RingBuffer<N> {
    pub const fn new() -> Self {
        Self { data: [0; N], head: 0, count: 0 }
    }

    pub fn push(&mut self, value: u64) {
        self.data[self.head] = value;
        self.head = (self.head + 1) % N;
        if self.count < N { self.count += 1; }
    }

    pub fn sum(&self) -> u64 {
        self.data[..self.count.min(N)].iter().sum()
    }

    pub fn mean(&self) -> f64 {
        if self.count == 0 { return 0.0; }
        self.sum() as f64 / self.count as f64
    }

    pub fn latest(&self) -> Option<u64> {
        if self.count == 0 { return None; }
        let idx = if self.head == 0 { N - 1 } else { self.head - 1 };
        Some(self.data[idx])
    }

    /// Iterate from newest to oldest
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.count).map(move |i| {
            let idx = (self.head + N - 1 - i) % N;
            self.data[idx]
        })
    }
}
```

Stack-allocated, no heap. `sizeof::<RingBuffer<60>>()` = 60 * 8 + 8 + 8 = 496 bytes.

### 6.3 Aggregated Time Series

```rust
pub struct AggregatedTimeSeries {
    l0: RingBuffer<10>,     // 100ms buckets
    l1: RingBuffer<60>,     // 1s buckets
    l2: RingBuffer<60>,     // 1min buckets
    l0_push_count: u32,     // pushes since last L0→L1 aggregation
    l1_push_count: u32,     // pushes since last L1→L2 aggregation
}

impl AggregatedTimeSeries {
    pub fn push_sample(&mut self, value: u64) {
        self.l0.push(value);
        self.l0_push_count += 1;

        if self.l0_push_count >= 10 {
            self.l1.push(self.l0.sum());
            self.l0_push_count = 0;
            self.l1_push_count += 1;

            if self.l1_push_count >= 60 {
                self.l2.push(self.l1.sum());
                self.l1_push_count = 0;
            }
        }
    }

    pub fn rate_per_sec(&self) -> f64 {
        self.l1.latest().unwrap_or(0) as f64
    }

    pub fn sparkline_data(&self) -> Vec<u64> {
        self.l2.iter().collect()
    }
}
```

### 6.4 Correlation Engine

The correlation engine is the most complex component. It joins data from four
sources into the unified `SystemNetworkState`:

```text
Input Sources:
  1. process.rs  → Vec<RawProcess>       (PID, name, uid, socket fds)
  2. connection.rs → Vec<RawTcpConnection>, Vec<RawUdpConnection>
  3. bpf/packet.rs → Vec<PacketSummary>  (5-tuple, byte count, timestamp)
  4. bpf/dns.rs    → Vec<DnsMessage>     (query name, response, latency)

Join Keys:
  process ↔ connection:  match by (local_addr, local_port, remote_addr, remote_port)
                         from socket_fdinfo and pcblist entries
  connection ↔ packet:   match by 5-tuple
  dns_query ↔ process:   match DNS packet src_port to socket local_port
```

**Connection matching algorithm**:

1. Build a `HashMap<FiveTuple, ProcessSocket>` from process socket data.
2. For each packet summary, look up the 5-tuple (try both directions).
3. If found: accumulate bytes into the connection's time series.
4. If not found: accumulate into the "unattributed" counter.

**Direction determination**:

- Maintain a set of `(protocol, local_addr, local_port)` tuples for all LISTEN
  sockets.
- If a connection's local port appears in this LISTEN set, direction = Inbound.
- Otherwise, direction = Outbound.

## 7. FFI Layer Design

### 7.1 Principles

- All C struct representations use `#[repr(C)]` with manual layout.
- No bindgen dependency. All bindings are hand-written.
- Static assertions (`const _: () = assert!(std::mem::size_of::<T>() == EXPECTED)`)
  verify struct sizes at compile time.
- All `unsafe` code is confined to FFI call sites. Public APIs return safe types.
- Pointers from C APIs are validated (null check, bounds check) before dereferencing.

### 7.2 Key FFI Types

```rust
#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: libc::timeval,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: u16,
}

#[repr(C)]
pub struct bpf_insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct bpf_program {
    pub bf_len: u32,
    pub bf_insns: *mut bpf_insn,
}

// BPF ioctl constants (macOS specific)
pub const BIOCSBLEN: libc::c_ulong = ...; // _IOWR('B', 102, u_int)
pub const BIOCSETIF: libc::c_ulong = ...; // _IOW('B', 108, struct ifreq)
pub const BIOCSETF: libc::c_ulong = ...;  // _IOW('B', 103, struct bpf_program)
pub const BIOCIMMEDIATE: libc::c_ulong = ...; // _IOW('B', 112, u_int)
pub const BIOCPROMISC: libc::c_ulong = ...; // _IO('B', 105)
pub const BIOCGSTATS: libc::c_ulong = ...; // _IOR('B', 111, struct bpf_stat)
pub const BIOCGBLEN: libc::c_ulong = ...; // _IOR('B', 102, u_int)
```

### 7.3 libproc Constants

```rust
pub const PROC_ALL_PIDS: u32 = 1;
pub const PROC_PIDLISTFDS: c_int = 1;
pub const PROC_PIDFDSOCKETINFO: c_int = 3;
pub const PROX_FDTYPE_SOCKET: u32 = 2;

#[repr(C)]
pub struct proc_fdinfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}

#[repr(C)]
pub struct socket_fdinfo {
    pub pfi: proc_fileinfo,
    pub psi: socket_info,
}

// socket_info contains: soi_family (AF_INET/AF_INET6), soi_type (SOCK_STREAM/DGRAM),
// soi_protocol, and a union with TCP/UDP-specific info including addresses.
```

### 7.4 Safety Boundary

```text
        ┌─────────────────────────────────────┐
        │          Safe Rust APIs              │
        │                                     │
        │  system/process.rs:                  │
        │    list_processes() -> Vec<Process>  │
        │                                     │
        │  bpf/mod.rs:                         │
        │    BpfCapture::read() -> Vec<Pkt>   │
        ├─────────────────────────────────────┤
        │    unsafe FFI boundary               │
        ├─────────────────────────────────────┤
        │  Raw C calls:                        │
        │    proc_listpids(...)               │
        │    ioctl(fd, BIOCSETF, ...)         │
        │    read(fd, buf, len)               │
        └─────────────────────────────────────┘
```

Each system module wraps the unsafe calls and returns `Result<SafeType, NetopError>`.
Callers never deal with raw pointers or C types.

## 8. Error Handling Strategy

### 8.1 Error Classification

| Category | Examples | Behavior |
|----------|---------|----------|
| Fatal | Not root, no BPF devices | Print error, exit with specific code |
| Transient | BPF read error, process vanished | Log at debug level, skip, continue |
| Data quality | DNS parse failure, truncated packet | Increment error counter, skip packet |
| User | Invalid CLI arguments | Print clap error, exit code 3 |

### 8.2 Error Propagation

- `main.rs`: catches all `NetopError` variants, maps to exit codes per
  netoproc-requirements.md Section 9.
- BPF capture thread: catches transient errors in loop, only propagates fatal.
- Stats poller: catches per-process errors, skips failed processes.
- TUI thread: catches render errors, attempts to restore terminal before exit.

### 8.3 Terminal Restoration

The TUI modifies terminal state (raw mode, alternate screen). On any exit
path — normal, error, or panic — the terminal must be restored:

```rust
fn main() {
    let result = std::panic::catch_unwind(|| run());
    // Restore terminal regardless of panic
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
    match result {
        Ok(Ok(())) => std::process::exit(0),
        Ok(Err(e)) => { eprintln!("error: {}", e); std::process::exit(exit_code(&e)); },
        Err(_) => { eprintln!("error: fatal: unexpected panic"); std::process::exit(4); },
    }
}
```

## 9. Dependency Selection

| Crate | Version | Purpose | Justification |
|-------|---------|---------|---------------|
| `clap` | 4.x | CLI argument parsing | Derive macro, validation, help generation. De facto standard. |
| `ratatui` | 0.28+ | TUI rendering framework | Immediate-mode rendering, widget library, active ecosystem. |
| `crossterm` | 0.28+ | Terminal backend for ratatui | Cross-platform terminal manipulation, event handling. |
| `serde` | 1.x | Serialization framework | Required for JSON output. Derive macro. |
| `serde_json` | 1.x | JSON serializer | `--format json` output. |
| `arc-swap` | 1.x | Lock-free shared state | ArcSwap for writer→reader state publishing. Zero-contention reads. |
| `crossbeam-channel` | 0.5+ | SPSC bounded channel | BPF→poller packet transfer. try_send for non-blocking writes. |
| `libc` | 0.2+ | POSIX type definitions | C type aliases for FFI. Foundational. |
| `thiserror` | 1.x | Error type derivation | Reduces boilerplate for NetopError enum. |
| `log` | 0.4+ | Logging facade | Debug-level logging for development. Silent in normal operation. |
| `env_logger` | 0.11+ | Log output (debug) | Activated via RUST_LOG env var for troubleshooting. |
| `rustc-hash` | 2.x | FxHashMap for ProcessTable | Faster hashing for short fixed-size keys (SocketKey). |

### Explicitly Excluded

| Crate/Library | Reason for exclusion |
|---------------|---------------------|
| `libpcap` / `pcap` | Adds an unnecessary abstraction layer over BPF. We need fine control over buffer sizes, filter installation, and BIOCIMMEDIATE. Direct BPF access is simpler for macOS-only. |
| `hickory-dns` | Full DNS client/resolver stack. We only need query/response parsing (a small subset). Hand-written parser is ~200 lines, avoids 50+ transitive dependencies. |
| `nix` | Provides safe ioctl wrappers, but adds a large dependency for a small number of ioctl calls. Raw `libc::ioctl` with our own safety wrappers is sufficient. |
| `bindgen` | Build-time dependency that requires libclang. Hand-written `#[repr(C)]` structs with size assertions are simpler and faster to compile. |
| `tokio` / `async-std` | Async runtime is unnecessary. Our I/O model is blocking reads (BPF) and periodic polling (sysctl). Threads are the natural fit. |

## 10. Performance Design Decisions

### 10.1 BPF Capture Optimization

- **Buffer size**: 2 MB default (adjustable via `--bpf-buffer`). With
  `BIOCIMMEDIATE` disabled, the kernel buffers packets for up to 500ms. 2 MB
  provides ample space for typical desktop/server traffic during this window.
- **Batch sending**: Each `read()` returns a batch of packets sent as a single
  `Vec<PacketSummary>` through the channel, amortizing channel overhead.
- **Vec reuse**: The BPF capture thread reuses a `Vec` across iterations via
  `std::mem::take`, avoiding per-read heap allocation.
- **Zero-copy parsing**: Parse packet headers directly from the read buffer
  using byte slice indexing. No packet-level heap allocation.

### 10.2 Process Enumeration Caching

- **PID list**: Re-enumerate every 5 seconds (not every poll cycle). New
  processes with sockets appearing within 5 seconds of creation is acceptable.
- **Socket list per PID**: Re-enumerate every 1 second (matches poll interval).
- **Process name/cmdline**: Cached per PID. Only re-fetched if a PID is new.
  Process names do not change during a process's lifetime.

### 10.3 Memory Allocation Strategy

- **TimeSeries**: Stack-allocated arrays. No Vec, no heap allocation per sample.
  `RingBuffer<60>` is 496 bytes on stack.
- **PacketSummary**: Small fixed-size struct (~48 bytes). Channel stores them
  inline (no Box).
- **String interning**: Process names and command lines are stored in the
  `Process` struct. Since `SystemNetworkState` is cloned via `Arc`, strings
  are reference-counted, not deeply cloned.
- **State snapshots**: Created as `Arc<SystemNetworkState>`. The old state is
  dropped when no reader holds a reference. Allocation cost: one `Arc` per
  poll cycle (1/sec).

### 10.4 TUI Rendering

- **ratatui diff rendering**: Only cells that changed since the last frame are
  written to the terminal. Reduces I/O significantly for mostly-static displays.
- **View-specific data preparation**: Each view pre-computes sorted/filtered
  data once per frame, not per-cell.
- **Sparkline rendering**: Pre-computed character lookup table (8 Unicode block
  levels). No per-character computation.

## 11. Key Design Decisions Log

| # | Decision | Choice | Alternatives Considered | Rationale |
|---|----------|--------|------------------------|-----------|
| D1 | Packet capture mechanism | Raw BPF (`/dev/bpfN`) | libpcap, Network Extension framework | Full control over buffer sizes, filters, and immediate mode. No external library dependency. macOS-only so no portability need. |
| D2 | DNS wire format parsing | Hand-written parser | hickory-dns, trust-dns-proto | Minimal code (~200 lines). Avoids 50+ transitive deps. We only need query/response parsing, not resolution. |
| D3 | Shared state between threads | `arc_swap::ArcSwap` | `RwLock<SystemNetworkState>`, channels | Lock-free reads for TUI thread. No reader-writer contention. Writer cost is one atomic swap per second. |
| D4 | BPF→Stats data transfer | Bounded `sync_channel(8)` of `Vec<PacketSummary>` batches | Unbounded channel, per-packet channel, lock-free SPSC ring | Batch sending amortizes channel overhead. Capacity 8 = 4s headroom. Blocking send provides natural backpressure. |
| D5 | TUI framework | ratatui + crossterm | cursive, tui-realm, termion | ratatui is the Rust ecosystem standard. Active maintenance. Immediate mode rendering. crossterm is the recommended backend. |
| D6 | FFI binding generation | Hand-written `#[repr(C)]` | bindgen at build time | Avoids libclang build dependency. Struct layouts are stable on macOS. Size assertions catch errors. |
| D7 | Process enumeration | Sequential, cached | Parallel with rayon | 500 processes take ~50ms sequential. Not worth the complexity of parallelism. Cache PID list for 5s. |
| D8 | Async runtime | None (OS threads) | tokio, async-std | BPF read is blocking. System calls are synchronous. Three threads is the natural model. Async adds complexity with no benefit. |
| D9 | Time series storage | Fixed-size ring buffers on stack | Vec-based, time-indexed HashMap | Constant memory, no allocation, predictable performance. 130 samples per connection is sufficient for ms/s/min granularity. |
| D10 | Configuration | CLI flags only | Config file (TOML/YAML), env vars | Simplicity. A monitoring tool should not require configuration files. All options have sensible defaults. |
| D11 | Error handling | `thiserror` enum | `anyhow`, manual impl | `thiserror` gives specific error types for matching exit codes. `anyhow` is too generic for our needs. |
| D12 | Privilege model | Require root, fail fast | Graceful degradation, capabilities | Simpler code paths. Every feature requires root. Partial functionality would confuse users. |
