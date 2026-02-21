# eBPF Linux Capture Research: Migrating from AF_PACKET to eBPF

> Research objective: Evaluate the feasibility, kernel compatibility, and Rust ecosystem support
> for replacing or supplementing the current AF_PACKET approach with eBPF on Linux,
> and decide between an "optional mode" vs "direct replacement" strategy.

---

## 1. Current Architecture

netoproc v0.4.0 on Linux uses **AF_PACKET raw sockets** for packet capture (`src/capture/linux.rs`),
with process attribution via `/proc/net/tcp[6]` + `/proc/<pid>/fd/` inode-to-PID correlation.

### 1.1 Pain Points of the AF_PACKET Approach

| Issue | Description |
|-------|-------------|
| **Process attribution has race conditions** | TOCTOU window between `/proc/net/tcp` and `/proc/<pid>/fd/`; short-lived connections are easily missed |
| **Weak UDP attribution** | Remote address in `/proc/net/udp` is always `0.0.0.0:0`, making SocketKey matching difficult |
| **No kernel-level PID correlation** | AF_PACKET captures frames at the NIC layer with no process context; relies on userspace `/proc` polling |
| **Outbound packet duplication** | AF_PACKET receives `PACKET_OUTGOING` copies by default; requires extra filtering logic |
| **Limited container support** | `/proc/net/tcp` only shows connections in the current network namespace |

### 1.2 What eBPF Solves

The core advantage of eBPF is **kernel-level process context**. By attaching kprobes to
`tcp_sendmsg`/`tcp_recvmsg`/`udp_sendmsg`/`udp_recvmsg`, an eBPF program can read
`current->pid`, `current->comm`, and cgroup ID directly at the call site,
eliminating the race conditions inherent in the AF_PACKET + `/proc` polling approach.

---

## 2. eBPF Kernel Version Support

### 2.1 Key Features and Minimum Kernel Versions

| eBPF Feature | Minimum Kernel | Description |
|-------------|----------------|-------------|
| `bpf()` syscall + Maps | 3.18 | eBPF infrastructure |
| BPF attach to socket | 3.19 | Socket filter |
| BPF attach to kprobe | **4.1** | For hooking tcp_sendmsg etc. |
| Tail calls | 4.2 | Program chaining |
| BPF attach to tracepoint | 4.7 | More stable than kprobes |
| XDP (eXpress Data Path) | 4.8 | High-performance ingress processing (no process context) |
| BPF attach to perf events | 4.9 | Performance event collection |
| BPF attach to cgroup | 4.10 | cgroup-level socket filtering |
| sock_ops | 4.13 | Socket-level operation callbacks |
| Bounded loops | 5.3 | Loop statement support |
| BPF ring buffer | **5.8** | Efficient kernel→userspace data transfer |
| `CAP_BPF` / `CAP_PERFMON` | **5.8** | Fine-grained permissions replacing root |
| CO-RE (Compile Once Run Everywhere) | ~5.2+ | Requires BTF (`CONFIG_DEBUG_INFO_BTF=y`) |
| BTF kernel type info | ~5.2+ | Prerequisite for CO-RE |
| TCX (TC eXpress) | 6.6 | Next-gen TC attach mechanism |

### 2.2 Actual Requirements for netoproc

netoproc's eBPF approach requires:

1. **kprobe attach** (4.1+): Hook into `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, `udp_recvmsg`
2. **BPF Maps** (3.18+): Kernel-side aggregation of PID → traffic statistics
3. **BPF ring buffer** (5.8+) or **perf buffer** (4.9+): Event delivery to userspace
4. **CO-RE/BTF** (5.2+): Avoid compiling different eBPF programs per kernel version

**Practical minimum: Linux 4.9+** (using perf buffer), **recommended 5.8+** (ring buffer + CAP_BPF).

For CO-RE cross-version compatibility (recommended): minimum **5.2+** (requires BTF).

### 2.3 Mainstream Distribution Kernel Versions

| Distribution | Version | Kernel Version | eBPF Support Level | EOL |
|-------------|---------|---------------|-------------------|-----|
| **RHEL 7** | 7.9 | 3.10 (backport) | Tech Preview only, not recommended | 2024-06 (EOL) |
| **RHEL 8** | 8.2+ | 4.18 (extensive backports) | kprobe/tracepoint available, no BTF | 2029 |
| **RHEL 8** | 8.6+ | 4.18 (more backports) | Minimum version for Cilium etc. | 2029 |
| **RHEL 9** | 9.0+ | 5.14 | Full eBPF support | 2032 |
| **Ubuntu 20.04** | LTS | 5.4 | Basic CO-RE, BTF requires manual enable | 2025-04 |
| **Ubuntu 22.04** | LTS | 5.15 | Full BTF/CO-RE | 2027-04 |
| **Ubuntu 24.04** | LTS | 6.8 | Full-featured | 2029-04 |
| **Debian 11** | Bullseye | 5.10 | Full eBPF | 2026-06 |
| **Debian 12** | Bookworm | 6.1 | Full-featured | 2028 |
| **Fedora 39+** | Rolling | 6.5+ | Full-featured | ~ |
| **Arch** | Rolling | Latest | Full-featured | ~ |
| **SUSE 15 SP4+** | Enterprise | 5.14 | Full eBPF | 2031 |

### 2.4 Key Conclusions

- **RHEL 7 is EOL** — no need to support.
- **RHEL 8** (kernel 4.18) has extensive eBPF backports but **no BTF**, so CO-RE is unavailable. Requires precompiled eBPF programs or runtime compilation.
- **From kernel 5.8 onwards**, all major eBPF features (ring buffer, CAP_BPF, BTF) are fully available.
- **From kernel 5.10 onwards** (Debian 11, RHEL 9, Ubuntu 22.04), eBPF can be considered **universally available across all mainstream distributions**.
- As of 2026, RHEL 8 is the only mainstream platform still within its support lifecycle that lacks BTF.

---

## 3. eBPF vs AF_PACKET Comparison

| Dimension | AF_PACKET | eBPF (kprobe) |
|-----------|-----------|---------------|
| **Process attribution** | Indirect (/proc polling, race conditions) | Direct (kernel-side PID/comm) |
| **UDP attribution** | Difficult (remote=0.0.0.0) | Direct (hook point has full socket info) |
| **Short-lived connection attribution** | Easily missed | Never missed (triggers on every send/recv) |
| **Performance overhead** | Medium-high (full packet copy to userspace) | Low (kernel-side aggregation, only statistics sent) |
| **Container awareness** | None (limited to current namespace) | Yes (cgroup ID, namespace ID) |
| **Full packet data** | Yes | Optional (but adds complexity) |
| **DNS parsing** | Yes (can capture DNS packet content) | Requires additional hook or socket filter |
| **Kernel version requirement** | Linux 2.2+ | 4.9+ (minimum), 5.8+ (recommended) |
| **Implementation complexity** | Low | Medium-high (eBPF program + loader) |
| **Debugging difficulty** | Low | Medium (eBPF verifier constraints) |

### 3.1 Core Advantages of eBPF

1. **Eliminates process attribution race conditions**: This is the biggest improvement. Under AF_PACKET,
   netoproc polls `/proc` every 500ms — connections shorter than 500ms may be entirely attributed to Unknown.
   eBPF kprobes trigger on every socket operation, enabling 100% accurate process attribution.

2. **Lower CPU overhead**: AF_PACKET copies full frames to userspace for parsing. eBPF extracts
   the 5-tuple + PID + byte count directly in the kernel, aggregates via BPF maps,
   and sends only statistics to userspace.

3. **Better UDP support**: Under AF_PACKET, UDP process attribution is nearly guesswork
   (`/proc/net/udp` remote is always 0). eBPF hooks on `udp_sendmsg` can directly read
   the destination address.

### 3.2 Limitations of eBPF

1. **Cannot directly capture full packet content**: The kprobe approach captures socket-level
   statistics (byte counts), not raw network frames. DNS parsing (reading DNS response content)
   still requires AF_PACKET or an additional eBPF socket filter program.

2. **Kernel version constraints**: Lack of BTF on older platforms like RHEL 8 is a practical issue.

3. **Higher development and debugging barrier**: eBPF programs are constrained by the verifier
   (stack size, loops, pointer safety), making the development experience less ergonomic
   than regular userspace code.

---

## 4. Rust eBPF Ecosystem

### 4.1 Available Rust eBPF Frameworks

| Framework | Kernel Code Language | C/LLVM Dependency | Maintenance Status | CO-RE Support | Async Support |
|-----------|---------------------|-------------------|-------------------|--------------|--------------|
| **Aya** | Rust | None | Active (2024-2025) | Yes | tokio + async-std |
| **libbpf-rs** | C | libbpf (C) | Active | Yes | Limited |
| **RedBPF** | Rust | LLVM | **Unmaintained** | Partial | Limited |

### 4.2 Recommendation: Aya

**Aya** is currently the best choice in the Rust eBPF ecosystem:

1. **Pure Rust**: Both kernel-side and userspace code are written in Rust; no C toolchain needed.
2. **No external dependencies**: Does not depend on libbpf, bcc, or LLVM; only `libc` crate.
3. **CO-RE support**: With BTF and musl static linking, achieves true compile-once-run-everywhere.
4. **Production adoption**:
   - Kubernetes SIG's Blixt (Gateway API load balancer)
   - Red Hat's bpfman (eBPF program loading daemon)
   - RustNet (network monitoring TUI, similar goal to netoproc)
5. **Alignment with netoproc**:
   - netoproc is already a pure Rust project with no C dependencies
   - Aya does not introduce new C toolchain dependencies
   - Aya supports kprobe attach, matching our requirements

### 4.3 Reference Projects

| Project | Tech Stack | Description |
|---------|-----------|-------------|
| **RustNet** (`rustnet-monitor`) | Rust + Aya eBPF | Network monitoring TUI, falls back to procfs when eBPF fails |
| **Bandix** | Rust + eBPF | Traffic monitor with DNS + IPv6 support |
| **ayaFlow** | Rust + Aya | K8s network analysis, TC classifier + ring buffer |
| **pktstat-bpf** | Go + eBPF | TC/XDP/KProbe multi-mode traffic monitor |

---

## 5. Strategy Decision: Optional Mode vs Direct Replacement

### 5.1 Conclusion: **Should be an optional mode; AF_PACKET must be retained**

Rationale:

#### Reasons to Retain AF_PACKET

1. **RHEL 8 compatibility**: RHEL 8 (EOL 2029) has kernel 4.18 without BTF; CO-RE is unavailable.
   While precompiled eBPF programs for RHEL 8 are possible, they add significant complexity.
   AF_PACKET works on all Linux versions.

2. **DNS capture requirement**: The eBPF kprobe approach captures socket-level statistics,
   not actual DNS response content. netoproc's DNS parsing feature (reverse domain lookup)
   still requires raw packet capture. Retaining AF_PACKET for DNS capture
   is a reasonable hybrid approach.

3. **Incremental migration**: A full replacement is too risky in one step. Introducing eBPF
   as an optional mode allows gradual validation of correctness, user feedback collection,
   and an informed decision about making it the default.

4. **Graceful fallback**: RustNet's approach is worth emulating — when eBPF loading fails,
   automatically fall back to procfs. netoproc can adopt a similar strategy:
   fall back to AF_PACKET + /proc when eBPF mode fails.

#### Recommended Architecture

```text
┌───────────────────────────────────────────────────────┐
│                  netoproc CLI                          │
│  --capture-mode=auto|ebpf|afpacket                    │
└──────────────────┬────────────────────────────────────┘
                   │
          ┌────────▼────────┐
          │  CaptureBackend  │  (runtime selection)
          │  enum dispatch   │
          └──┬───────────┬──┘
             │           │
    ┌────────▼───┐  ┌───▼──────────┐
    │ eBPF mode  │  │ AF_PACKET    │
    │ (kprobe)   │  │ mode         │
    │            │  │              │
    │ PID: kernel│  │ PID: /proc   │
    │ stats: map │  │ capture: raw │
    │ DNS: needs │  │ DNS: yes     │
    │  extra work│  │              │
    └────────────┘  └──────────────┘
```

**Default behavior (`--capture-mode=auto`)**:

1. Detect kernel version >= 5.8 and BTF available → use eBPF
2. Otherwise → fall back to AF_PACKET

**DNS handling**:

- In eBPF mode, DNS capture can still use AF_PACKET socket filter (port 53 only)
- Or attach an eBPF socket filter to DNS traffic

### 5.2 Implementation Roadmap

#### Phase 1: Basic eBPF kprobe mode

- Introduce `aya` + `aya-ebpf` dependencies
- Write kprobe eBPF program hooking `tcp_sendmsg`/`tcp_recvmsg`
- Userspace reads PID → traffic statistics via BPF map
- `--capture-mode=ebpf` CLI option

#### Phase 2: UDP support + DNS

- Add `udp_sendmsg`/`udp_recvmsg` kprobes
- DNS parsing solution (AF_PACKET fallback or eBPF socket filter)

#### Phase 3: Auto mode + fallback

- Kernel version / BTF detection
- `--capture-mode=auto` as default
- Graceful fallback to AF_PACKET on eBPF load failure

#### Phase 4: Advanced features

- cgroup awareness (container traffic attribution)
- Ring buffer replacing perf buffer (kernel 5.8+)
- Optional XDP fast path

### 5.3 Estimated Cargo.toml Changes

```toml
[target.'cfg(target_os = "linux")'.dependencies]
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

[features]
default = ["ebpf"]
ebpf = ["aya", "aya-log"]
```

Users who do not need eBPF can compile a pure AF_PACKET version with `--no-default-features`.

---

## 6. Permission Model Changes

eBPF mode requires additional capabilities:

| Capability | AF_PACKET Mode | eBPF Mode | Description |
|-----------|---------------|----------|-------------|
| `CAP_NET_RAW` | Required | Required (if DNS uses AF_PACKET) | Create raw sockets |
| `CAP_NET_ADMIN` | Required | Required | Promiscuous mode |
| `CAP_SYS_PTRACE` | Required | No longer needed | eBPF gets PID directly in kernel |
| `CAP_BPF` | Not needed | **Required** (5.8+) | Load eBPF programs |
| `CAP_PERFMON` | Not needed | **Required** (5.8+) | kprobe attach |
| `CAP_SYS_ADMIN` | Not needed | Required (<5.8) | Pre-5.8 substitute for CAP_BPF |

**Kernel 5.8+**: `CAP_BPF + CAP_PERFMON` replaces `CAP_SYS_PTRACE`, providing finer-grained permissions.
**Kernel < 5.8**: Requires `CAP_SYS_ADMIN` (broader permissions, but these older kernels typically require root anyway).

install-linux.sh must be updated accordingly, setting different capabilities based on capture mode.

---

## 7. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| eBPF verifier rejects program | Feature unavailable | Thorough testing + auto fallback to AF_PACKET |
| Kernel API changes (kprobes are unstable) | Incompatibility with specific kernel versions | Use tracepoints (more stable) as alternative hook points |
| Aya crate breaking changes | Compilation failure | Pin Aya version, track upstream |
| RHEL 8 users cannot use eBPF | Downgrade to AF_PACKET | Auto mode detects and falls back automatically |
| Larger build artifacts | Binary size increase | eBPF as feature flag, optional compilation |
| eBPF program must be embedded in binary | Deployment complexity | Aya supports embedding eBPF ELF in Rust binary |

---

## 8. Summary

| Question | Answer |
|----------|--------|
| Do all distributions support eBPF? | **No.** RHEL 8 (4.18) has limited support (no BTF); RHEL 7 is EOL. From kernel 5.10 onwards (Debian 11, RHEL 9, Ubuntu 22.04), eBPF can be considered universally available |
| Optional mode or replacement? | **Optional mode.** Controlled via `--capture-mode=auto\|ebpf\|afpacket`, default auto-detect |
| Recommended Rust framework? | **Aya.** Pure Rust, no external dependencies, actively maintained, production adoption |
| Minimum kernel requirement? | eBPF mode: 5.8+ (recommended), 4.9+ (minimum, limited features); AF_PACKET mode: any Linux |
| DNS capture approach? | Hybrid: eBPF handles process attribution + traffic stats; AF_PACKET (or eBPF socket filter) handles DNS packet content capture |

---

## References

- [BCC Kernel Versions Reference](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [eBPF.io - What is eBPF](https://ebpf.io/what-is-ebpf/)
- [Aya - Rust eBPF Library](https://aya-rs.dev/)
- [eBPF Ecosystem Progress 2024-2025](https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/)
- [Red Hat eBPF in RHEL 7](https://www.redhat.com/en/blog/introduction-ebpf-red-hat-enterprise-linux-7)
- [Cilium System Requirements](https://docs.cilium.io/en/stable/operations/system_requirements/)
- [pktstat-bpf (Go eBPF traffic monitor)](https://github.com/dkorunic/pktstat-bpf)
- [RustNet Monitor](https://crates.io/crates/rustnet-monitor)
- [Microsoft Defender eBPF Sensor Requirements](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf)
- [FOSDEM 2025: Building eBPF with Rust and Aya](https://archive.fosdem.org/2025/events/attachments/fosdem-2025-5534-building-your-ebpf-program-with-rust-and-aya/slides/238267/Building_7AI18W8.pdf)
