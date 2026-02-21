# eBPF Capture Mode Design Document

> Based on the findings from netoproc-ebpf-linux-research.md, this document describes the complete design for adding an eBPF kprobe-based packet capture mode on Linux.
> Intended for direct use by a code agent during implementation.

---

## 1. Design Goals

1. Add a `--capture-mode=auto|ebpf|afpacket` CLI option (Linux only; ignored on macOS)
2. eBPF mode attaches kprobes to socket-layer functions to obtain PID + byte counts directly in kernel space
3. AF_PACKET is retained as both a fallback mechanism and the means for DNS packet capture
4. Pure Rust eBPF framework with no C toolchain dependency (framework TBD for Phase 2; see Section 10)
5. Controlled via the `ebpf` Cargo feature flag for optional compilation

### 1.1 Safety Principles

- The eBPF program uses only **kprobe** (the most conservative attachment method); XDP/TC are not used
- kprobes only read kernel data and **do not modify** any network packets or kernel state
- If eBPF program loading fails, the system **silently falls back** to AF_PACKET without service interruption
- All eBPF map operations enforce reasonable size limits to prevent memory bloat
- Capabilities follow the principle of least privilege

---

## 2. Architecture Overview

### 2.1 Runtime Mode Selection

```text
CLI: --capture-mode=auto (default on Linux)
         |
         v
+---------------------------+
| Auto mode detection logic |
| 1. Check if feature "ebpf"|
|    is compiled in          |
| 2. Check kernel >= 5.8    |
| 3. Check /sys/kernel/btf/ |
|    vmlinux exists          |
| 4. Try loading eBPF prog  |
+------+-----------+--------+
       |           |
   success v    failure v
+----------+  +-----------+
| eBPF     |  | AF_PACKET |
| mode     |  | mode      |
+----------+  +-----------+
```

### 2.2 eBPF Mode Thread Model

```text
+--------------------------------------------------------+
|  Main Thread (Stats + TUI)                             |
|  - Reads per-PID traffic stats from BPF maps           |
|  - Or receives events from ring buffer                 |
|  - No longer needs /proc polling for process           |
|    attribution                                         |
+--------------------+-----------------------------------+
          ^ sync_channel(8) Vec<PacketSummary>
          |                 ^ ArcSwap load
+---------+----------+   +--+---------------------+
|  eBPF Poller Thread |   | Process Refresh       |
|  (replaces capture  |   | (500ms, only provides |
|   thread)           |   |  supplemental process |
|                     |   |  metadata: name, path)|
|  Periodically reads |   |                       |
|  BPF maps and       |   |                       |
|  converts to        |   |                       |
|  PacketSummary+PID  |   |                       |
+---------------------+   +-----------------------+

DNS capture thread (AF_PACKET port 53 filter, unchanged)
```

### 2.3 eBPF Mode vs AF_PACKET Mode Comparison

| Component | AF_PACKET Mode | eBPF Mode |
|-----------|---------------|-----------|
| Packet capture | `recvfrom(AF_PACKET)` | kprobe on `tcp_sendmsg`, etc. |
| Process attribution | `/proc` polling (500ms race window) | Kernel-space `bpf_get_current_pid_tgid()` |
| Data transfer | Raw frame to userspace | BPF PerCpuHashMap (aggregated stats) or ring buffer (events) |
| DNS | AF_PACKET port 53 filter | Retains AF_PACKET (eBPF kprobes cannot access packet content) |
| Direction detection | Local IP matching | `tcp_sendmsg` = outbound, `tcp_recvmsg` = inbound |
| ProcessTable | Full rebuild every 500ms | Used only for supplemental metadata (process name, path, etc.) |

---

## 3. eBPF Program Design

### 3.1 Attachment Points

kprobes are attached to the following kernel functions:

| Function | kprobe/kretprobe | Data Obtained | Description |
|----------|-----------------|---------------|-------------|
| `tcp_sendmsg` | kprobe | PID, sock 5-tuple, requested length | TCP outbound bytes |
| `tcp_recvmsg` | kretprobe | PID, sock 5-tuple, return value (actual bytes) | TCP inbound bytes |
| `udp_sendmsg` | kprobe | PID, sock 5-tuple, requested length | UDP outbound bytes |
| `udp_recvmsg` | kretprobe | PID, sock 5-tuple, return value | UDP inbound bytes |

**Why kprobe instead of tracepoint**:

- `tcp_sendmsg`/`tcp_recvmsg` do not have stable tracepoints
- kprobes are available since kernel 4.1+, offering better compatibility
- While kprobe-attached kernel function signatures may change across versions, these particular functions have extremely stable signatures

### 3.2 Data Structures

#### eBPF Side (Kernel Space)

```rust
// Traffic event key: identifies a (PID, protocol, direction) combination
#[repr(C)]
pub struct TrafficKey {
    pub pid: u32,
    pub proto: u8,       // 6=TCP, 17=UDP
    pub direction: u8,   // 0=TX, 1=RX
    pub _pad: [u8; 2],
}

// Traffic event value: accumulated bytes and packet count
#[repr(C)]
pub struct TrafficValue {
    pub bytes: u64,
    pub packets: u64,
}
```

#### BPF Maps

```rust
// PerCpuHashMap: TrafficKey -> TrafficValue
// Capacity limit: 16384 entries (conservative estimate: ~2048 processes x 2 protocols x 2 directions x 2 headroom)
//
// PerCpuHashMap is used instead of HashMap to eliminate data races on multi-CPU
// systems. Each CPU has its own independent copy of each value, so concurrent
// increments from different CPUs never conflict. No locks or atomic operations
// are needed in the eBPF program. Userspace sums across all CPU copies when
// reading the map.
#[map]
static TRAFFIC_MAP: PerCpuHashMap<TrafficKey, TrafficValue> =
    PerCpuHashMap::with_max_entries(16384, 0);

// PID -> comm mapping (process name cache, reduces /proc reads)
// PerCpuHashMap avoids contention; userspace reads any CPU's copy.
#[map]
static PID_COMM: PerCpuHashMap<u32, [u8; 16]> =
    PerCpuHashMap::with_max_entries(4096, 0);
```

### 3.3 kprobe Handler Logic (Pseudocode)

```rust
// tcp_sendmsg kprobe
fn tcp_sendmsg_probe(ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() >> 32;
    let sock: *const sock = ctx.arg(0);  // First argument is struct sock*
    let size: usize = ctx.arg(2);        // Third argument is send length

    // Read process name
    let mut comm = [0u8; 16];
    bpf_get_current_comm(&mut comm);

    // Update PID_COMM map
    PID_COMM.insert(&(pid as u32), &comm, 0);

    // Update TRAFFIC_MAP
    let key = TrafficKey {
        pid: pid as u32,
        proto: 6, // TCP
        direction: 0, // TX
        _pad: [0; 2],
    };
    // Increment: read current value and add this event's byte count.
    // PerCpuHashMap eliminates contention — each CPU writes to its own
    // value slot, so no locks or atomics are required.
    if let Some(val) = TRAFFIC_MAP.get_ptr_mut(&key) {
        (*val).bytes += size as u64;
        (*val).packets += 1;
    } else {
        let val = TrafficValue { bytes: size as u64, packets: 1 };
        TRAFFIC_MAP.insert(&key, &val, 0);
    }

    0 // Return 0 to continue execution of the original function
}
```

### 3.4 Safety Boundaries

- **Map size limits**: `TRAFFIC_MAP` holds at most 16384 entries; `PID_COMM` holds at most 4096 entries.
  When full, new insertions fail silently without affecting normal operation — only some statistics are lost.
- **kprobe is read-only**: does not modify any kernel state, sock structures, or packet contents.
- **No loops**: the eBPF program contains no loops; the verifier guarantees termination.
- **Error handling**: all map operations check their return values; on failure, `return 0` to continue.

---

## 4. Userspace Integration

### 4.1 Module Structure

```text
src/capture/
├── mod.rs          <- CaptureMode enum + conditional module imports
├── linux.rs        <- AF_PACKET backend + runtime dispatch logic
│                      (PlatformCapture type, open_capture_devices,
│                       check_capture_access, eBPF/AF_PACKET selection)
└── ebpf.rs         <- eBPF backend: detection + loader + BPF map poller

netoproc-ebpf/      <- Standalone eBPF program crate (#![no_std])
├── Cargo.toml
└── src/
    └── main.rs     <- kprobe eBPF programs

netoproc-ebpf-common/ <- Shared #[repr(C)] types between kernel and userspace
├── Cargo.toml
└── src/
    └── lib.rs      <- TrafficKey, TrafficValue, constants
```

### 4.2 capture/ebpf.rs Public API

The eBPF backend exports the **same public function signatures** as `AfPacketCapture`,
so that `capture_loop` and `dns_capture_loop` in `main.rs` can switch seamlessly.

```rust
pub struct EbpfCapture {
    bpf: Ebpf,                    // eBPF program manager (framework TBD)
    traffic_map: MapRef,          // Userspace reference to TRAFFIC_MAP
    pid_comm_map: MapRef,         // Userspace reference to PID_COMM
    interface: String,
    poll_interval: Duration,      // Default 500ms
    last_snapshot: HashMap<TrafficKey, TrafficValue>, // Previous snapshot (for delta computation)
}

impl EbpfCapture {
    /// Load the eBPF program and attach kprobes.
    /// Returns Err on failure; the caller can fall back to AF_PACKET.
    pub fn new(interface: &str) -> Result<Self, NetopError>;

    /// Poll BPF maps and convert delta data into a batch of PacketSummary.
    /// The returned PacketSummary entries include correct direction and approximate byte counts.
    pub fn read_packets(&mut self, out: &mut Vec<PacketSummary>) -> Result<(), NetopError>;
    pub fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError>;

    /// eBPF mode does not capture DNS packet content directly; returns an empty Vec.
    /// DNS is handled by a separate AF_PACKET capture device.
    pub fn read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError>;

    pub fn interface(&self) -> &str;
}
```

### 4.3 capture/mod.rs Layout

```rust
// src/capture/mod.rs

#[derive(Debug, Clone, Copy)]
pub enum FilterKind { Traffic, Dns }

// ---- macOS ----
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

// ---- Linux ----
#[cfg(target_os = "linux")]
mod linux;  // AfPacketCapture (AF_PACKET backend) + runtime dispatch
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;  // EbpfCapture (eBPF backend)
```

### 4.4 Runtime Dispatch (in linux.rs)

Runtime dispatch logic lives directly in `src/capture/linux.rs` alongside the
AF_PACKET implementation. There is no separate `linux_dispatch.rs` file.

```rust
// In src/capture/linux.rs

use crate::cli::CaptureMode;
use crate::error::NetopError;

/// Open capture devices for the specified interfaces.
///
/// The `capture_mode` parameter controls which backend to use:
/// - `Auto`: try eBPF first (if compiled with `ebpf` feature), fall back to AF_PACKET
/// - `Ebpf`: force eBPF, return error if unavailable
/// - `Afpacket`: force AF_PACKET (current default behavior)
pub fn open_capture_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
    capture_mode: CaptureMode,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    match capture_mode {
        CaptureMode::Ebpf => {
            #[cfg(feature = "ebpf")]
            {
                return try_open_ebpf(interfaces, buffer_size, dns_enabled, false);
            }
            #[cfg(not(feature = "ebpf"))]
            {
                return Err(NetopError::EbpfProgram(
                    "eBPF support not compiled in (build with --features ebpf)".to_string(),
                ));
            }
        }
        CaptureMode::Auto => {
            #[cfg(feature = "ebpf")]
            {
                if super::ebpf::ebpf_available() {
                    match try_open_ebpf(interfaces, buffer_size, dns_enabled, true) {
                        Ok(result) => return Ok(result),
                        Err(e) => {
                            log::warn!(
                                "eBPF initialization failed, falling back to AF_PACKET: {e}"
                            );
                        }
                    }
                } else {
                    log::info!("eBPF not available on this kernel, using AF_PACKET");
                }
            }
        }
        CaptureMode::Afpacket => {
            // Fall through to AF_PACKET below
        }
    }

    open_afpacket_devices(interfaces, buffer_size, dns_enabled)
}

/// eBPF availability detection
#[cfg(feature = "ebpf")]
fn ebpf_available() -> bool {
    // 1. Check kernel version >= 5.8
    if !kernel_version_sufficient() {
        log::debug!("Kernel version < 5.8, eBPF not available");
        return false;
    }
    // 2. Check BTF info
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        log::debug!("BTF not available (/sys/kernel/btf/vmlinux missing)");
        return false;
    }
    // 3. Try bpf() syscall (most reliable detection)
    true
}
```

---

## 5. CLI Changes

### 5.1 Additions to src/cli.rs

```rust
/// Capture mode for Linux (ignored on macOS).
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Auto-detect: try eBPF first, fall back to AF_PACKET
    Auto,
    /// Force eBPF kprobe mode (requires kernel 5.8+ with BTF)
    Ebpf,
    /// Force AF_PACKET raw socket mode (works on all Linux kernels)
    Afpacket,
}

// Added to the Cli struct:
/// Linux capture backend (ignored on macOS)
#[arg(long = "capture-mode", default_value = "auto")]
pub capture_mode: CaptureMode,
```

### 5.2 Changes to main.rs

```rust
// Pass capture_mode to open_capture_devices:
let (traffic_captures, dns_capture) = capture::open_capture_devices(
    &interfaces,
    cli.bpf_buffer,
    dns_enabled,
    cli.capture_mode,  // new parameter
)?;
```

The macOS `open_capture_devices` signature is unchanged (it ignores `capture_mode` or does not accept the parameter).

---

## 6. Cargo.toml Changes

```toml
[features]
default = []
# Phase 1: ebpf feature enables detection code and stub backend.
# Phase 2: will add eBPF framework dependency here once finalized.
# Note: aya v0.13 transitively pulls in tokio, which conflicts with the
# project's no-tokio policy. Phase 2 must either use aya without tokio,
# choose an alternative (libbpf-rs), or formally amend the policy.
ebpf = []
```

No aya or aya-log dependencies are added in Phase 1. The `ebpf` feature flag
gates only the detection code (`src/capture/ebpf.rs`) and dispatch logic.
The eBPF framework dependency will be added in Phase 2 once the tokio
conflict is resolved.

**eBPF program crate** (standalone workspace member):

```toml
# netoproc-ebpf/Cargo.toml
[package]
name = "netoproc-ebpf"
version = "0.1.0"
edition = "2021"
description = "eBPF kernel programs for netoproc per-process network monitoring"
publish = false

[dependencies]
aya-ebpf = "0.1"
netoproc-ebpf-common = { path = "../netoproc-ebpf-common" }

[[bin]]
name = "netoproc-ebpf"
path = "src/main.rs"

[profile.dev]
opt-level = 2      # eBPF verifier needs optimized code
panic = "abort"
overflow-checks = false

[profile.release]
lto = true
panic = "abort"
overflow-checks = false
```

**Shared types crate**:

```toml
# netoproc-ebpf-common/Cargo.toml
[package]
name = "netoproc-ebpf-common"
version = "0.1.0"
edition = "2021"

[lib]
# no_std compatible — shared between kernel and userspace
```

The eBPF ELF bytecode is embedded into the main program binary via `include_bytes_aligned!`.

---

## 7. Permission Model

### 7.1 Capabilities Required for eBPF Mode

| Capability | Purpose | Minimum Kernel |
|-----------|---------|---------------|
| `CAP_BPF` | Load eBPF programs | 5.8 |
| `CAP_PERFMON` | Attach kprobes | 5.8 |
| `CAP_NET_RAW` | DNS AF_PACKET (if enabled) | Any |
| `CAP_NET_ADMIN` | Promiscuous mode (if enabled) | Any |
| `CAP_SYS_PTRACE` | Read /proc entries for other users' processes | Any |

### 7.2 install-linux.sh Update

```bash
# Detect kernel version and select capability set
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]; }; then
    # Kernel 5.8+: eBPF mode available
    CAPS="cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon,cap_sys_ptrace+eip"
    echo "Kernel $KERNEL_VERSION supports eBPF: setting cap_bpf,cap_perfmon,cap_sys_ptrace"
else
    # Older kernel: AF_PACKET only
    CAPS="cap_net_raw,cap_net_admin,cap_sys_ptrace+eip"
    echo "Kernel $KERNEL_VERSION: AF_PACKET mode only"
fi

setcap "$CAPS" "$BINARY"
```

---

## 8. Error Handling

### 8.1 New Error Variant

```rust
// Added to src/error.rs
#[error("eBPF program error: {0}")]
EbpfProgram(String),
```

Exit code: maps to 2 (same level as CaptureDevice).

### 8.2 Fallback Strategy

```text
auto mode:
  1. Attempt to load eBPF -> success -> use eBPF
  2. Load fails -> log::warn -> fall back to AF_PACKET
  3. AF_PACKET also fails -> return error

ebpf mode (forced):
  1. Attempt to load eBPF -> success
  2. Load fails -> return EbpfProgram error, no fallback

afpacket mode (forced):
  1. Use AF_PACKET -> success
  2. Fails -> return CaptureDevice error
```

---

## 9. Incremental Implementation Plan

### Phase 1: Scaffolding (current implementation)

- [x] CLI: `--capture-mode` option + `CaptureMode` enum
- [x] `src/capture/ebpf.rs`: eBPF backend scaffolding (detection + stub implementation)
- [x] `src/capture/linux.rs`: runtime dispatch (eBPF/AF_PACKET selection integrated directly)
- [x] `src/error.rs`: new `EbpfProgram` variant
- [x] `Cargo.toml`: `ebpf` feature flag (no aya dependency; see Phase 2)
- [x] `scripts/install-linux.sh`: capability updates
- [x] `netoproc-ebpf/`: standalone eBPF program crate with kprobe handlers
- [x] `netoproc-ebpf-common/`: shared `#[repr(C)]` types (TrafficKey, TrafficValue)
- [x] Compilation verified: `cargo check` passes

### Phase 2: eBPF Program Integration (future)

- [ ] Resolve eBPF framework dependency (aya pulls in tokio; evaluate alternatives or workaround)
- [ ] Add eBPF framework dependency to main crate's `ebpf` feature
- [ ] Implement actual eBPF program loading in `EbpfCapture::try_new()`
- [ ] Implement BPF PerCpuHashMap polling in `EbpfCapture::read_packets()`
- [ ] Integration testing (requires Linux 5.8+ environment)

### Phase 3: Optimization and Polish

- [ ] Ring buffer to replace perf buffer
- [ ] UDP attribution improvements
- [ ] cgroup awareness
- [ ] Performance benchmarking

---

## 10. Key Decision Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| eBPF framework | TBD (Phase 2) | Aya is the preferred candidate (pure Rust, no C dependency, actively maintained), but aya v0.13 transitively pulls in tokio, which conflicts with the project's no-tokio policy. Phase 2 must resolve this conflict (use aya without tokio, switch to libbpf-rs, or formally amend the policy). |
| Attachment method | kprobe | Most conservative approach; available since kernel 4.1+; read-only |
| Data transfer | BPF PerCpuHashMap (polling) | Eliminates data races on multi-CPU systems without locks or atomics. Each CPU has its own value copy; userspace sums across all CPUs when reading. Simpler than ring buffer and well-suited for aggregated statistics. |
| DNS capture | Retains AF_PACKET | kprobes cannot access packet content |
| Default mode | auto | Auto-detects capability; transparent upgrade path |
| Feature flag | `ebpf` (not default) | Conservative strategy; users explicitly opt in |
| Map size limit | 16384 entries | Approximately 2K processes x 8 direction/protocol combinations |
| Minimum kernel | 5.8 | CAP_BPF + ring buffer + mature BTF support |
