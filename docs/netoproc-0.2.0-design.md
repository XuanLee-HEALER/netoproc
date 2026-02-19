# netoproc 0.2.0 设计文档

> 供 code agent 直接实现使用。所有架构决策已在此文档中确定，agent 无需自行决策，严格按照本文档实现。

---

## 1. 概述

0.2.0 的核心变化是将原有的批处理 snapshot 模型改造为**滚动更新的流式架构**，数据层统一为持续运行的三线程模型，表现层根据运行模式决定消费快照的方式。

### 1.1 变更汇总

| 项目 | 0.1.x | 0.2.0 |
|------|-------|-------|
| BPF 读取模式 | `BIOCIMMEDIATE=1`，有包立即返回 | 关闭 BIOCIMMEDIATE，超时 500ms 触发 read |
| 进程表刷新 | 统计时点查询 | 独立线程每 500ms 刷新，写入 `ArcSwap` |
| 线程模型 | 单线程或简单两线程 | BPF 线程 + 进程刷新线程 + 统计线程（主线程） |
| snapshot 语义 | 累积 N 秒后输出 | 固定时间窗口，drain 完毕后输出一次退出 |
| monitor 语义 | 定时刷新 | channel 有数据即更新 UI，Ctrl-C 退出 |

---

## 2. 运行模式语义

### 2.1 Snapshot 模式

**触发方式**：`netoproc --duration <秒数>`，例如 `netoproc --duration 10`

**语义**：
- 程序启动后运行恰好 `duration` 秒的数据采集
- 采集结束后输出**一次**统计结果，然后退出
- 输出内容：在 duration 时间窗口内，每个进程的累计上行/下行字节数、包数，按流量降序排列
- 不进入交互界面，输出为纯文本表格，适合脚本调用和管道

**用户期望**：`netoproc --duration 5` 等价于"给我看过去 5 秒内各进程的流量统计"

**时间精度说明**：由于 BPF read 超时为 500ms，最后一批数据的边界误差在 0~500ms 之间，这是可接受的，实现时不需要对此做补偿。

### 2.2 Monitor 模式

**触发方式**：`netoproc`（无 `--duration` 参数）或 `netoproc --monitor`

**语义**：
- 程序持续运行，展示实时滚动更新的流量统计 TUI 界面
- 每当统计线程处理完一批 channel 数据，立即刷新 UI（数据驱动，而非定时器驱动）
- 由于 BPF read 超时为 500ms，实际 UI 刷新频率约为每 500~800ms 一次
- 按 Ctrl-C 退出，退出前不做额外的最终输出

---

## 3. 三线程运行时架构

### 3.1 总体结构

```
┌─────────────────────────────────────────────────────────────┐
│                        主线程（统计线程）                        │
│                                                             │
│  1. 初始化进程表（ProcessTable）                               │
│  2. 创建 SPSC channel                                        │
│  3. 启动 BPF 线程（传入 channel 写端）                          │
│  4. 启动进程刷新线程（传入 Arc<ArcSwap<ProcessTable>>）          │
│  5. 进入主循环：drain channel → 关联进程 → 生成快照 → 输出/渲染  │
└─────────────────────────────────────────────────────────────┘
         ▲ channel (Vec<PacketSummary>)       ▲ ArcSwap load（无锁读）
         │                                   │
┌────────┴────────┐               ┌──────────┴──────────┐
│   BPF 线程       │               │   进程刷新线程         │
│                 │               │                     │
│ loop {          │               │ loop {              │
│   read() 阻塞   │               │   sleep(500ms)      │
│   解析包        │               │   libproc 扫描       │
│   发送 channel  │               │   arcswap.store()   │
│ }               │               │ }                   │
└─────────────────┘               └─────────────────────┘
```

### 3.2 线程职责详述

#### BPF 线程

- **职责**：持续调用 `read()`，解析原始帧，提取 `PacketSummary`，批量发送到 channel
- **持有资源**：channel 写端（`SyncSender<Vec<PacketSummary>>`）、`BpfCapture` 实例、`Arc<AtomicBool>` shutdown 信号
- **退出条件**：检测到 shutdown 信号为 true 时，退出 loop，写端 drop 导致 channel 关闭
- **发送时机**：每次 `read()` 返回后，将本次解析出的所有 `PacketSummary` 作为一个 `Vec` 整体发送，不做跨 read 的合并
- **错误处理**：read 返回 `EAGAIN` / `EINTR` 时继续循环；其他错误记录日志后退出线程

#### 进程刷新线程

- **职责**：每 500ms 调用 libproc 扫描当前所有进程的 socket 信息，更新进程表
- **持有资源**：`Arc<ArcSwap<ProcessTable>>`、`Arc<AtomicBool>` shutdown 信号
- **进程表内容**：`HashMap<SocketKey, ProcessInfo>`，即五元组到进程信息的映射（见第 8 节数据结构）
- **退出条件**：检测到 shutdown 信号为 true 时退出
- **更新方式**：在锁外构建新的 `ProcessTable`，完成后调用 `arcswap.store()` 原子替换，统计线程读取时完全无锁：

```rust
// 正确做法：锁外构建新表，store 原子替换
let new_table = Arc::new(build_process_table()); // 耗时的 libproc 扫描
process_table.store(new_table);                  // 原子替换，统计线程无感知
```

#### 统计线程（主线程）

- **职责**：drain channel、聚合流量统计、查进程表做关联、生成快照、驱动表现层
- **持有资源**：channel 读端（`Receiver<Vec<PacketSummary>>`）、`Arc<ArcSwap<ProcessTable>>`、流量统计 `HashMap<ProcessKey, TrafficStats>`
- **读取方式**：调用 `process_table.load()` 获取当前快照，完全无锁，不会因进程表刷新而阻塞

---

## 4. BPF 配置变更

### 4.1 关闭 BIOCIMMEDIATE

在 `BpfCapture::new()` 中，**移除**以下代码，不再设置 BIOCIMMEDIATE：

```rust
// 删除这两行
let imm: u32 = 1;
ioctl_set(&fd, BIOCIMMEDIATE, &imm)?;
```

不设置 `BIOCIMMEDIATE` 时，内核默认行为是：缓冲区满**或**超时才返回 read。

### 4.2 读超时配置

读超时维持 500ms 不变：

```rust
let timeout = libc::timeval {
    tv_sec: 0,
    tv_usec: 500_000, // 500ms
};
ioctl_set(&fd, BIOCSRTIMEOUT, &timeout)?;
```

**行为说明**：
- 正常流量下，缓冲区不会在 500ms 内填满，`read()` 每 500ms 超时返回一次
- 流量突发时，缓冲区可能提前填满，`read()` 提前返回，属于正常现象
- 每次 `read()` 返回的数据量不固定，统计线程不应假设固定批次大小

### 4.3 缓冲区大小

默认设为 **2MB**（`buffer_size = 2 * 1024 * 1024`）。关闭 BIOCIMMEDIATE 后，500ms 内的包全部积压在内核缓冲区，2MB 对普通桌面/服务器网络场景足够。可作为配置项暴露给用户，但默认值为 2MB。

---

## 5. 数据流与进程关联

### 5.1 统计线程主循环（伪代码）

```rust
let mut stats: HashMap<ProcessKey, TrafficStats> = HashMap::new();
let start = Instant::now();

loop {
    // 1. 非阻塞 drain channel，取出所有当前可用数据
    let mut batch: Vec<PacketSummary> = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(packets) => batch.extend(packets),
            Err(TryRecvError::Empty) => break,        // 本轮没有更多数据
            Err(TryRecvError::Disconnected) => {      // BPF 线程已退出
                // snapshot 模式：执行最终 drain 并退出（见第6节）
                // monitor 模式：直接退出循环
                goto_shutdown();
            }
        }
    }

    // 2. 关联进程（arcswap load 无锁，获取当前进程表快照）
    if !batch.is_empty() {
        let table = process_table.load(); // 无锁读取，返回 Arc<ProcessTable>
        for pkt in &batch {
            let key = lookup_process(&table, &pkt)
                .map(|info| ProcessKey::Known { pid: info.pid, name: info.name.clone() })
                .unwrap_or(ProcessKey::Unknown);
            stats.entry(key).or_default().add(&pkt);
        }
    }

    // 3. snapshot 模式：检查 duration 是否到期
    if let Some(duration) = snapshot_duration {
        if start.elapsed() >= duration {
            drain_final(&rx, &process_table, &mut stats); // 见第6节
            output_snapshot(&stats);
            break;
        }
    }

    // 4. monitor 模式：有新数据就刷新 UI
    if !batch.is_empty() {
        render_tui(&stats);
    }

    // 5. 检查 Ctrl-C
    if shutdown_signal.load(Ordering::Relaxed) {
        break;
    }

    // 6. 无新数据时短暂 sleep，避免空转
    if batch.is_empty() {
        std::thread::sleep(Duration::from_millis(10));
    }
}
```

### 5.2 进程查找逻辑

进程表构建和包查询时均调用 `SocketKey::new()`，规范化保证同一条连接的两个方向生成相同 key，HashMap 只需查询一次：

```rust
fn lookup_process(table: &ProcessTable, pkt: &PacketSummary) -> Option<ProcessInfo> {
    let key = SocketKey::new(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol as u8);
    table.get(&key).cloned()
}
```

进程表构建时同样使用相同的规范化 key：

```rust
fn build_process_table() -> ProcessTable {
    let mut table = ProcessTable::default();
    for conn in libproc_list_connections() {
        let key = SocketKey::new(conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port, conn.proto);
        table.insert(key, ProcessInfo { pid: conn.pid, name: conn.name });
    }
    table
}

---

## 6. Edge Case 处理

### 6.1 Snapshot 模式最终 drain

当 `start.elapsed() >= duration` 时，channel 中可能还有最后一批尚未消费的数据（BPF 线程最后一次 read 的结果）。必须 drain 完毕再输出，否则会丢失最后 0~500ms 的数据。

实现步骤：

```rust
fn drain_final(
    rx: &Receiver<Vec<PacketSummary>>,
    process_table: &Arc<ArcSwap<ProcessTable>>,
    stats: &mut HashMap<ProcessKey, TrafficStats>,
    shutdown: &Arc<AtomicBool>,
    bpf_thread: JoinHandle<()>,
) {
    // 1. 通知 BPF 线程退出
    shutdown.store(true, Ordering::Relaxed);

    // 2. 等待 BPF 线程退出，确保不再有新数据写入 channel
    //    BPF 线程退出后，tx 被 drop，channel 进入 Disconnected 状态
    bpf_thread.join().ok();

    // 3. 此时 channel 写端已关闭，用 recv_timeout 安全 drain 剩余数据
    //    当 channel 为空且 Disconnected 时，recv_timeout 返回 Err，循环结束
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(packets) => {
                let table = process_table.load(); // 无锁读取
                for pkt in &packets {
                    let key = lookup_process(&table, &pkt)
                        .map(|info| ProcessKey::Known { pid: info.pid, name: info.name.clone() })
                        .unwrap_or(ProcessKey::Unknown);
                    stats.entry(key).or_default().add(&pkt);
                }
            }
            Err(_) => break, // Empty + Disconnected，drain 完毕
        }
    }
}
```

**误差说明**：最终输出的时间窗口实际为 `duration + [0, 500ms]`，由 BPF read 超时决定，可以接受，无需补偿。

### 6.2 进程生命周期短于 500ms

此类进程的流量被计入 `ProcessKey::Unknown`。在输出时，Unknown 条目必须显示，让用户知晓存在无法归因的流量，而非静默丢弃。输出格式示例：

```
PROCESS              RX           TX
chrome (pid 1234)    1.2 MB       340 KB
curl   (pid 5678)    0 B          12 KB
unknown              45 KB        0 B
```

### 6.3 BPF 线程 channel 满（背压）

使用有界 channel，容量为 **8**：

```rust
let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<PacketSummary>>(8);
```

容量 8 的依据：每批数据对应一次 BPF read（约 500ms），8 批 = 4 秒的缓冲余量。若 channel 满，BPF 线程的 `send()` 会阻塞，进而延迟下一次 `read()`。这是合理的背压行为，优先保证统计线程处理完已有数据，而不是无限积压导致内存增长。

### 6.4 Cargo.toml 依赖

需要添加以下依赖：

```toml
[dependencies]
arc-swap = "1"
rustc-hash = "1"   # FxHashMap，对短固定长度 key 哈希性能显著优于标准库 SipHash
```

`FxHashMap` 使用方式：

```rust
use rustc_hash::FxHashMap;
pub type ProcessTable = FxHashMap<SocketKey, ProcessInfo>;
// FxHashMap::default() 即可创建，无需额外配置
```

`ArcSwap` 使用方式：

```rust
use arc_swap::ArcSwap;

// 初始化
let process_table = Arc::new(ArcSwap::from_pointee(build_process_table()));

// 进程刷新线程写入
process_table.store(Arc::new(new_table));

// 统计线程读取（无锁）
let table = process_table.load();
// table 类型为 arc_swap::Guard<Arc<ProcessTable>>，可直接当 &ProcessTable 使用
```

---

## 7. 启动与关闭流程

### 7.1 启动顺序

```
1. 解析命令行参数，确定模式（snapshot/monitor）和 duration 参数
2. 首次调用 libproc，构建初始 ProcessTable
3. 将 ProcessTable 包装为 Arc<ArcSwap<ProcessTable>>
4. 创建 sync_channel(64)，得到 (tx, rx)
5. 创建 Arc<AtomicBool> shutdown_signal，初始值为 false
6. 启动 BPF 线程，传入：tx, Arc::clone(&shutdown_signal)
7. 启动进程刷新线程，传入：Arc::clone(&process_table), Arc::clone(&shutdown_signal)
8. 主线程进入统计主循环（见第5节）
```

### 7.2 关闭流程

**Snapshot 模式（正常到期退出）**：

```
1. duration 到期，统计线程检测到
2. 调用 drain_final()：
   a. 设置 shutdown_signal = true
   b. join BPF 线程
   c. drain channel 剩余数据
3. 设置 shutdown_signal = true（通知进程刷新线程，若 drain_final 已设则跳过）
4. join 进程刷新线程
5. 输出最终统计表格
6. 进程退出（exit code 0）
```

**Monitor 模式（Ctrl-C）**：

```
1. 注册 Ctrl-C handler（使用 ctrlc crate 或 signal-hook）
2. handler 中设置 shutdown_signal = true
3. 统计线程主循环检测到 shutdown_signal，退出循环
4. 设置 shutdown_signal = true（已设则跳过）
5. join BPF 线程
6. join 进程刷新线程
7. 进程退出（不做最终输出，TUI 已在退出循环时清理）
```

---

## 8. 数据结构参考

以下为建议的数据结构定义，字段名可根据项目现有命名风格调整，但语义不变。

```rust
/// 进程标识 key，用于流量统计 HashMap 的 key
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum ProcessKey {
    Known { pid: u32, name: String },
    Unknown,
}

/// 单个进程的流量统计累计值
#[derive(Default, Debug)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl TrafficStats {
    pub fn add(&mut self, pkt: &PacketSummary) {
        match pkt.direction {
            Direction::Inbound => {
                self.rx_bytes += pkt.bytes as u64;
                self.rx_packets += 1;
            }
            Direction::Outbound => {
                self.tx_bytes += pkt.bytes as u64;
                self.tx_packets += 1;
            }
        }
    }
}

/// 进程表：规范化五元组 → 进程信息
/// 使用 FxHashMap 替代标准库 HashMap，对短 key 哈希性能更好
pub type ProcessTable = FxHashMap<SocketKey, ProcessInfo>;

/// 规范化五元组 key，固定 37 字节，栈分配，无对齐填充
///
/// 布局：[ip_a: 16][port_a: 2][ip_b: 16][port_b: 2][proto: 1] = 37 字节
///
/// 规范化规则：构造时对两端点按 (ip, port) 字典序排序，保证
/// (A:1234, B:80) 和 (B:80, A:1234) 生成完全相同的 key，
/// 查询时无需正反向两次查找。
///
/// IPv4 地址统一映射为 IPv4-mapped IPv6（::ffff:x.x.x.x），
/// IPv4 和 IPv6 连接使用同一套布局。
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct SocketKey([u8; 37]);

impl SocketKey {
    pub fn new(ip1: IpAddr, port1: u16, ip2: IpAddr, port2: u16, proto: u8) -> Self {
        // 规范化：较小的端点排在前面
        let (ip_a, port_a, ip_b, port_b) = if (ip_to_bytes(ip1), port1) <= (ip_to_bytes(ip2), port2) {
            (ip1, port1, ip2, port2)
        } else {
            (ip2, port2, ip1, port1)
        };

        let mut buf = [0u8; 37];
        buf[0..16].copy_from_slice(&ip_to_bytes(ip_a));
        buf[16..18].copy_from_slice(&port_a.to_be_bytes());
        buf[18..34].copy_from_slice(&ip_to_bytes(ip_b));
        buf[34..36].copy_from_slice(&port_b.to_be_bytes());
        buf[36] = proto;
        Self(buf)
    }
}

/// IPv4 映射为 IPv4-mapped IPv6，统一 16 字节表示
fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[10] = 0xff;
            buf[11] = 0xff;
            buf[12..16].copy_from_slice(&v4.octets());
            buf
        }
    }
}

/// 进程基本信息
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// BPF 解析出的包摘要（已有，供参考）
pub struct PacketSummary {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub bytes: u32,           // ip_total_len（含 IP 头）
    pub direction: Direction, // 由 BPF 线程根据本机 IP 列表判断
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum Protocol { Tcp, Udp }

#[derive(Clone, Copy, Debug)]
pub enum Direction { Inbound, Outbound }
```

---

## 9. 本版本不涉及的内容

以下内容维持 0.1.x 的实现，本文档不做变更说明：

- TUI 界面布局和渲染细节
- BPF filter 指令（继续使用现有的 IPv4/IPv6 TCP/UDP 过滤规则）
- `parse_bpf_buffer` 的解析逻辑（BPF_WORDALIGN 步进、以太网/IP/TCP/UDP 解析）
- libproc 的具体调用方式（`proc_pidinfo` 等 API）
- 命令行参数解析框架（仅新增 `--duration <秒>` 参数，`--monitor` 作为默认行为的显式别名）
