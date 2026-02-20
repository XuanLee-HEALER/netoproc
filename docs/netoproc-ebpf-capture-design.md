# eBPF Capture Mode 设计文档

> 基于 netoproc-ebpf-linux-research.md 调研结论，描述在 Linux 端新增 eBPF kprobe 抓包模式的完整设计。
> 供 code agent 直接实现使用。

---

## 1. 设计目标

1. 新增 `--capture-mode=auto|ebpf|afpacket` CLI 选项（Linux only，macOS 忽略）
2. eBPF 模式通过 kprobe 挂载到 socket 层函数，在内核态直接获取 PID + 字节数
3. AF_PACKET 保留作为回退方案和 DNS 包捕获手段
4. Aya 作为 eBPF 框架，纯 Rust，无 C 工具链依赖
5. 通过 Cargo feature flag `ebpf` 控制，可选编译

### 1.1 安全性原则

- eBPF 程序仅使用 **kprobe**（最保守的挂载方式），不使用 XDP/TC
- kprobe 只读取内核数据，**不修改**任何网络包或内核状态
- eBPF 程序加载失败时**静默回退**到 AF_PACKET，不中断服务
- 所有 eBPF map 操作设置合理的大小上限，防止内存膨胀
- 严格遵守 capability 最小权限原则

---

## 2. 架构概览

### 2.1 运行时模式选择

```
CLI: --capture-mode=auto (default on Linux)
         │
         ▼
┌─────────────────────────┐
│ auto 模式检测逻辑        │
│ 1. 检查 feature "ebpf"  │
│    是否编译进来          │
│ 2. 检查 kernel >= 5.8   │
│ 3. 检查 /sys/kernel/btf/│
│    vmlinux 是否存在      │
│ 4. 尝试加载 eBPF prog   │
└──────┬──────────┬───────┘
       │          │
    成功 ▼       失败 ▼
┌──────────┐  ┌───────────┐
│ eBPF 模式 │  │ AF_PACKET │
│           │  │ 模式       │
└──────────┘  └───────────┘
```

### 2.2 eBPF 模式线程模型

```
┌────────────────────────────────────────────────────────┐
│  Main Thread (Stats + TUI)                             │
│  - 从 BPF map 读取 per-PID 流量统计                     │
│  - 或从 ring buffer 接收事件                             │
│  - 不再需要 /proc 轮询做进程归因                          │
└────────────────────┬───────────────────────────────────┘
          ▲ sync_channel(8) Vec<PacketSummary>
          │                 ▲ ArcSwap load
┌─────────┴──────────┐   ┌──┴─────────────────┐
│  eBPF Poller Thread │   │ Process Refresh    │
│  (替代 capture thd) │   │ (500ms, 仅补充     │
│                     │   │  进程名等元信息)    │
│  周期性读取 BPF map │   │                    │
│  转换为 PacketSumm  │   │                    │
│  ary + PID 信息     │   │                    │
└─────────────────────┘   └────────────────────┘

DNS 捕获线程（AF_PACKET port 53 filter，不变）
```

### 2.3 eBPF 模式 vs AF_PACKET 模式对比

| 组件 | AF_PACKET 模式 | eBPF 模式 |
|------|---------------|-----------|
| 包捕获 | `recvfrom(AF_PACKET)` | kprobe on `tcp_sendmsg` 等 |
| 进程归因 | `/proc` 轮询 (500ms 竞态) | 内核态 `bpf_get_current_pid_tgid()` |
| 数据传输 | raw frame → userspace | BPF map (聚合统计) 或 ring buffer (事件) |
| DNS | AF_PACKET port 53 filter | 保持 AF_PACKET（eBPF kprobe 无包内容） |
| 方向判断 | local IP 匹配 | `tcp_sendmsg`=出站, `tcp_recvmsg`=入站 |
| ProcessTable | 每 500ms 全量重建 | 仅用于补充进程名/路径等元信息 |

---

## 3. eBPF 程序设计

### 3.1 挂载点

使用 kprobe 挂载到以下内核函数：

| 函数 | kprobe/kretprobe | 获取数据 | 说明 |
|------|-----------------|---------|------|
| `tcp_sendmsg` | kprobe | PID, sock 5-tuple, 请求长度 | TCP 出站字节 |
| `tcp_recvmsg` | kretprobe | PID, sock 5-tuple, 返回值(实际字节) | TCP 入站字节 |
| `udp_sendmsg` | kprobe | PID, sock 5-tuple, 请求长度 | UDP 出站字节 |
| `udp_recvmsg` | kretprobe | PID, sock 5-tuple, 返回值 | UDP 入站字节 |

**为什么选 kprobe 而非 tracepoint**：
- `tcp_sendmsg`/`tcp_recvmsg` 没有稳定的 tracepoint
- kprobe 在 kernel 4.1+ 即可用，兼容性更好
- 虽然 kprobe 挂载的内核函数签名可能跨版本变化，但这几个函数的签名极其稳定

### 3.2 数据结构

#### eBPF 侧（内核态）

```rust
// 流量事件 key：标识一个 (PID, 协议, 方向) 组合
#[repr(C)]
pub struct TrafficKey {
    pub pid: u32,
    pub proto: u8,       // 6=TCP, 17=UDP
    pub direction: u8,   // 0=TX, 1=RX
    pub _pad: [u8; 2],
}

// 流量事件 value：累计字节和包数
#[repr(C)]
pub struct TrafficValue {
    pub bytes: u64,
    pub packets: u64,
}
```

#### BPF Map

```rust
// HashMap: TrafficKey → TrafficValue
// 容量上限: 16384 entries（保守估计，约 2048 进程 × 2 协议 × 2 方向 × 2 余量）
#[map]
static TRAFFIC_MAP: HashMap<TrafficKey, TrafficValue> = HashMap::with_max_entries(16384, 0);

// PID → comm 映射（进程名缓存，减少 /proc 读取）
#[map]
static PID_COMM: HashMap<u32, [u8; 16]> = HashMap::with_max_entries(4096, 0);
```

### 3.3 kprobe 处理逻辑（伪代码）

```rust
// tcp_sendmsg kprobe
fn tcp_sendmsg_probe(ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() >> 32;
    let sock: *const sock = ctx.arg(0);  // 第一个参数是 struct sock*
    let size: usize = ctx.arg(2);        // 第三个参数是发送长度

    // 读取进程名
    let mut comm = [0u8; 16];
    bpf_get_current_comm(&mut comm);

    // 更新 PID_COMM map
    PID_COMM.insert(&(pid as u32), &comm, 0);

    // 更新 TRAFFIC_MAP
    let key = TrafficKey {
        pid: pid as u32,
        proto: 6, // TCP
        direction: 0, // TX
        _pad: [0; 2],
    };
    // 原子增量：读取当前值，加上本次字节数
    if let Some(val) = TRAFFIC_MAP.get_ptr_mut(&key) {
        (*val).bytes += size as u64;
        (*val).packets += 1;
    } else {
        let val = TrafficValue { bytes: size as u64, packets: 1 };
        TRAFFIC_MAP.insert(&key, &val, 0);
    }

    0 // 返回 0 表示继续执行原函数
}
```

### 3.4 安全边界

- **map 大小限制**：`TRAFFIC_MAP` 最多 16384 条目，`PID_COMM` 最多 4096 条目。
  满时新条目插入失败但不影响正常运行，仅丢失部分统计。
- **kprobe 只读**：不修改任何内核状态，不修改 sock 结构，不修改包内容。
- **无循环**：eBPF 程序中没有循环，verifier 保证终止。
- **错误处理**：所有 map 操作检查返回值，失败时 `return 0` 继续。

---

## 4. 用户态集成

### 4.1 模块结构

```
src/capture/
├── mod.rs          ← 新增 CaptureMode enum + 运行时 dispatch
├── linux.rs        ← 现有 AF_PACKET（不变）
└── ebpf.rs         ← 新增：Aya 加载器 + BPF map 轮询器

netoproc-ebpf/      ← 新增：独立的 eBPF 程序 crate（#![no_std]）
├── Cargo.toml
└── src/
    └── main.rs     ← kprobe eBPF 程序
```

### 4.2 capture/ebpf.rs 公开 API

eBPF 后端需要导出与 `AfPacketCapture` **相同的公开函数签名**，
以便 `main.rs` 中的 `capture_loop` 和 `dns_capture_loop` 能无缝切换。

```rust
pub struct EbpfCapture {
    bpf: Ebpf,                    // Aya 的 eBPF 程序管理器
    traffic_map: MapRef,          // TRAFFIC_MAP 的用户态引用
    pid_comm_map: MapRef,         // PID_COMM 的用户态引用
    interface: String,
    poll_interval: Duration,      // 默认 500ms
    last_snapshot: HashMap<TrafficKey, TrafficValue>, // 上次读取的快照（用于增量计算）
}

impl EbpfCapture {
    /// 加载 eBPF 程序并 attach kprobes。
    /// 失败时返回 Err，调用方可回退到 AF_PACKET。
    pub fn new(interface: &str) -> Result<Self, NetopError>;

    /// 轮询 BPF map，将增量数据转换为 PacketSummary 批次。
    /// 返回的 PacketSummary 已包含正确的方向和大致字节数。
    pub fn read_packets(&mut self, out: &mut Vec<PacketSummary>) -> Result<(), NetopError>;
    pub fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError>;

    /// eBPF 模式不直接捕获 DNS 包内容，返回空 Vec。
    /// DNS 由独立的 AF_PACKET capture 处理。
    pub fn read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError>;

    pub fn interface(&self) -> &str;
}
```

### 4.3 capture/mod.rs 改造

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
mod linux;  // AfPacketCapture (afpacket 后端)

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;  // EbpfCapture (ebpf 后端)

#[cfg(target_os = "linux")]
mod linux_dispatch;  // 运行时 dispatch：选择 afpacket 或 ebpf
#[cfg(target_os = "linux")]
pub use linux_dispatch::*;
```

### 4.4 linux_dispatch.rs（运行时 dispatch）

```rust
// src/capture/linux_dispatch.rs

use crate::cli::CaptureMode;
use crate::error::NetopError;

/// 运行时选择的捕获后端。
pub enum PlatformCapture {
    AfPacket(super::linux::AfPacketCapture),
    #[cfg(feature = "ebpf")]
    Ebpf(super::ebpf::EbpfCapture),
}

pub fn check_capture_access() -> Result<(), NetopError> {
    // 基础权限检查（AF_PACKET socket 探测 + eBPF 能力检测）
    super::linux::check_capture_access()
}

pub fn open_capture_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
    capture_mode: CaptureMode,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    match resolve_capture_mode(capture_mode) {
        ResolvedMode::Ebpf => open_ebpf_devices(interfaces, dns_enabled),
        ResolvedMode::AfPacket => open_afpacket_devices(interfaces, buffer_size, dns_enabled),
    }
}

/// auto 模式的检测逻辑
fn resolve_capture_mode(mode: CaptureMode) -> ResolvedMode {
    match mode {
        CaptureMode::Afpacket => ResolvedMode::AfPacket,
        CaptureMode::Ebpf => {
            #[cfg(feature = "ebpf")]
            { ResolvedMode::Ebpf }
            #[cfg(not(feature = "ebpf"))]
            {
                log::warn!("eBPF feature not compiled in, falling back to AF_PACKET");
                ResolvedMode::AfPacket
            }
        }
        CaptureMode::Auto => {
            #[cfg(feature = "ebpf")]
            {
                if ebpf_available() {
                    log::info!("eBPF support detected, using eBPF capture mode");
                    ResolvedMode::Ebpf
                } else {
                    log::info!("eBPF not available, using AF_PACKET capture mode");
                    ResolvedMode::AfPacket
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ResolvedMode::AfPacket
            }
        }
    }
}

/// 检测 eBPF 是否可用
#[cfg(feature = "ebpf")]
fn ebpf_available() -> bool {
    // 1. 检查内核版本 >= 5.8
    if !kernel_version_sufficient() {
        log::debug!("Kernel version < 5.8, eBPF not available");
        return false;
    }
    // 2. 检查 BTF 信息
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        log::debug!("BTF not available (/sys/kernel/btf/vmlinux missing)");
        return false;
    }
    // 3. 尝试 bpf() 系统调用（最可靠的检测）
    true
}
```

---

## 5. CLI 变更

### 5.1 src/cli.rs 新增

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

// 在 Cli struct 中新增：
/// Linux capture backend (ignored on macOS)
#[arg(long = "capture-mode", default_value = "auto")]
pub capture_mode: CaptureMode,
```

### 5.2 main.rs 变更

```rust
// 在 open_capture_devices 调用处传入 capture_mode：
let (traffic_captures, dns_capture) = capture::open_capture_devices(
    &interfaces,
    cli.bpf_buffer,
    dns_enabled,
    cli.capture_mode,  // 新增参数
)?;
```

macOS 端的 `open_capture_devices` 签名不变（忽略 `capture_mode` 或不接受此参数）。

---

## 6. Cargo.toml 变更

```toml
[features]
default = []
ebpf = ["dep:aya", "dep:aya-log"]

[target.'cfg(target_os = "linux")'.dependencies]
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }
```

**eBPF 程序 crate**（独立 workspace member）：

```toml
# netoproc-ebpf/Cargo.toml
[package]
name = "netoproc-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"

[[bin]]
name = "netoproc-ebpf"
path = "src/main.rs"
```

eBPF ELF 字节码通过 `include_bytes_aligned!` 嵌入主程序二进制。

---

## 7. 权限模型

### 7.1 eBPF 模式所需 capabilities

| Capability | 用途 | 最低内核 |
|-----------|------|---------|
| `CAP_BPF` | 加载 eBPF 程序 | 5.8 |
| `CAP_PERFMON` | attach kprobe | 5.8 |
| `CAP_NET_RAW` | DNS AF_PACKET（如启用） | 任意 |
| `CAP_NET_ADMIN` | 混杂模式（如启用） | 任意 |

### 7.2 install-linux.sh 更新

```bash
# 检测内核版本，选择 capabilities 集合
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]; }; then
    # Kernel 5.8+: eBPF mode available
    CAPS="cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+eip"
    echo "Kernel $KERNEL_VERSION supports eBPF: setting cap_bpf,cap_perfmon"
else
    # Older kernel: AF_PACKET only
    CAPS="cap_net_raw,cap_net_admin,cap_sys_ptrace+eip"
    echo "Kernel $KERNEL_VERSION: AF_PACKET mode only"
fi

setcap "$CAPS" "$BINARY"
```

---

## 8. 错误处理

### 8.1 新增 error variant

```rust
// src/error.rs 新增
#[error("eBPF program error: {0}")]
EbpfProgram(String),
```

exit code: 映射到 2（与 CaptureDevice 同级）。

### 8.2 回退策略

```
auto 模式:
  1. 尝试加载 eBPF → 成功 → 使用 eBPF
  2. 加载失败 → log::warn → 回退 AF_PACKET
  3. AF_PACKET 也失败 → 返回错误

ebpf 模式 (强制):
  1. 尝试加载 eBPF → 成功
  2. 加载失败 → 返回 EbpfProgram 错误，不回退

afpacket 模式 (强制):
  1. 使用 AF_PACKET → 成功
  2. 失败 → 返回 CaptureDevice 错误
```

---

## 9. 渐进式实现计划

### Phase 1：骨架搭建（本次实现）
- [x] CLI: `--capture-mode` 选项 + `CaptureMode` enum
- [x] `src/capture/ebpf.rs`：eBPF 后端骨架（检测 + stub 实现）
- [x] `src/capture/linux_dispatch.rs`：运行时 dispatch
- [x] `src/error.rs`：新增 `EbpfProgram` variant
- [x] `Cargo.toml`：`ebpf` feature flag + aya 依赖
- [x] `scripts/install-linux.sh`：capability 更新
- [x] 编译验证：`cargo check` 通过

### Phase 2：eBPF 程序实现（后续）
- [ ] `netoproc-ebpf/` crate：kprobe eBPF 程序
- [ ] 实际 kprobe attach + BPF map 读取
- [ ] 集成测试（需要 Linux 5.8+ 环境）

### Phase 3：优化与完善
- [ ] ring buffer 替代 perf buffer
- [ ] UDP 归因改进
- [ ] cgroup 感知
- [ ] 性能基准测试

---

## 10. 关键决策记录

| 决策 | 选择 | 理由 |
|------|------|------|
| eBPF 框架 | Aya | 纯 Rust，无 C 依赖，活跃维护 |
| 挂载方式 | kprobe | 最保守，4.1+ 可用，只读 |
| 数据传输 | BPF HashMap (轮询) | 比 ring buffer 简单，适合聚合统计场景 |
| DNS 捕获 | 保留 AF_PACKET | kprobe 无法获取包内容 |
| 默认模式 | auto | 自动检测，无感知升级 |
| Feature flag | `ebpf` (非默认) | 保守策略，用户主动 opt-in |
| Map 大小上限 | 16384 entries | 约 2K 进程 × 8 方向/协议组合 |
| 最低内核 | 5.8 | CAP_BPF + ring buffer + BTF 成熟 |
