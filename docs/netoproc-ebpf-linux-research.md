# eBPF Linux 抓包方案调研：从 AF_PACKET 迁移到 eBPF

> 调研目标：评估 Linux 上用 eBPF 替代/补充当前 AF_PACKET 方案的可行性、内核兼容性、Rust 生态支持，
> 以及最终采用"可选模式"还是"直接替换"的策略决策。

---

## 1. 当前架构现状

netoproc v0.4.0 Linux 端采用 **AF_PACKET raw socket** 进行包捕获（`src/capture/linux.rs`），
进程归因则通过 `/proc/net/tcp[6]` + `/proc/<pid>/fd/` 进行 inode-to-PID 关联。

### 1.1 AF_PACKET 方案的痛点

| 问题 | 说明 |
|------|------|
| **进程归因存在竞态** | `/proc/net/tcp` 与 `/proc/<pid>/fd/` 之间存在 TOCTOU 窗口，短生命周期连接易丢失 |
| **UDP 归因能力弱** | `/proc/net/udp` 中 remote 地址始终为 `0.0.0.0:0`，导致 SocketKey 匹配困难 |
| **无内核级 PID 关联** | AF_PACKET 在网卡层捕获帧，完全没有进程上下文，只能靠用户态 polling `/proc` 间接关联 |
| **出站包重复** | AF_PACKET 默认收到 `PACKET_OUTGOING` 副本，需额外逻辑过滤 |
| **容器支持有限** | `/proc/net/tcp` 只显示当前 network namespace 的连接 |

### 1.2 eBPF 能解决什么

eBPF 的核心优势是可以在 **内核态直接获取进程上下文**。通过 kprobe 挂载到
`tcp_sendmsg`/`tcp_recvmsg`/`udp_sendmsg`/`udp_recvmsg` 等内核函数，
eBPF 程序可以在函数调用点直接读取 `current->pid`、`current->comm`、cgroup ID，
消除了 AF_PACKET + `/proc` 轮询方案的竞态问题。

---

## 2. eBPF 内核版本支持调研

### 2.1 关键功能与最低内核版本

| eBPF 功能 | 最低内核版本 | 说明 |
|-----------|------------|------|
| `bpf()` 系统调用 + Maps | 3.18 | eBPF 基础设施 |
| BPF 附加到 socket | 3.19 | socket filter |
| BPF 附加到 kprobe | **4.1** | 用于挂载 tcp_sendmsg 等 |
| Tail calls | 4.2 | 程序链式调用 |
| BPF 附加到 tracepoint | 4.7 | tracepoint 比 kprobe 更稳定 |
| XDP (eXpress Data Path) | 4.8 | 高性能入站处理（无进程上下文） |
| BPF 附加到 perf events | 4.9 | 性能事件采集 |
| BPF 附加到 cgroup | 4.10 | cgroup 级别 socket 过滤 |
| sock_ops | 4.13 | socket 级别操作回调 |
| Bounded loops | 5.3 | 循环语句支持 |
| BPF ring buffer | **5.8** | 高效内核→用户态数据传输 |
| `CAP_BPF` / `CAP_PERFMON` | **5.8** | 细粒度权限替代 root |
| CO-RE (Compile Once Run Everywhere) | ~5.2+ | 需要 BTF 信息 (`CONFIG_DEBUG_INFO_BTF=y`) |
| BTF 内核类型信息 | ~5.2+ | CO-RE 的前置依赖 |
| TCX (TC eXpress) | 6.6 | 新一代 TC attach 方式 |

### 2.2 对 netoproc 的实际需求

netoproc 的 eBPF 方案需要以下功能：

1. **kprobe 附加** (4.1+)：挂载到 `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, `udp_recvmsg`
2. **BPF Maps** (3.18+)：用于内核态聚合 PID → 流量统计
3. **BPF ring buffer** (5.8+) 或 **perf buffer** (4.9+)：将事件传递到用户态
4. **CO-RE/BTF** (5.2+)：避免为每个内核版本编译不同的 eBPF 程序

**实际最低需求：Linux 4.9+**（使用 perf buffer），**推荐 5.8+**（使用 ring buffer + CAP_BPF）。

如果要求 CO-RE 跨版本兼容（推荐），则最低 **5.2+**（需要 BTF）。

### 2.3 主流发行版内核版本对照

| 发行版 | 版本 | 内核版本 | eBPF 支持等级 | EOL |
|--------|------|---------|-------------|-----|
| **RHEL 7** | 7.9 | 3.10 (backport) | 仅 Tech Preview，不推荐 | 2024-06 已 EOL |
| **RHEL 8** | 8.2+ | 4.18 (大量回移) | kprobe/tracepoint 可用，无 BTF | 2029 |
| **RHEL 8** | 8.6+ | 4.18 (更多回移) | Cilium 等工具的最低版本 | 2029 |
| **RHEL 9** | 9.0+ | 5.14 | 完整 eBPF 支持 | 2032 |
| **Ubuntu 20.04** | LTS | 5.4 | 基本 CO-RE，BTF 需手动开启 | 2025-04 |
| **Ubuntu 22.04** | LTS | 5.15 | 完整 BTF/CO-RE | 2027-04 |
| **Ubuntu 24.04** | LTS | 6.8 | 全功能 | 2029-04 |
| **Debian 11** | Bullseye | 5.10 | 完整 eBPF | 2026-06 |
| **Debian 12** | Bookworm | 6.1 | 全功能 | 2028 |
| **Fedora 39+** | Rolling | 6.5+ | 全功能 | ~ |
| **Arch** | Rolling | Latest | 全功能 | ~ |
| **SUSE 15 SP4+** | Enterprise | 5.14 | 完整 eBPF | 2031 |

### 2.4 关键结论

- **RHEL 7 已 EOL**，不需要支持。
- **RHEL 8**（4.18 内核）通过回移支持大量 eBPF 功能，但 **没有 BTF**，CO-RE 无法使用，需要预编译的 eBPF 程序或运行时编译。
- **从 kernel 5.8 开始**，所有主要 eBPF 功能（ring buffer, CAP_BPF, BTF）都已完备。
- **从 kernel 5.10 开始**（Debian 11, RHEL 9, Ubuntu 22.04），可以认为 eBPF **在所有主流发行版上普遍可用**。
- 2026 年时间点上，仍在支持周期内的发行版中 RHEL 8 是唯一没有 BTF 的主流平台。

---

## 3. eBPF vs AF_PACKET 对比

| 维度 | AF_PACKET | eBPF (kprobe) |
|------|-----------|---------------|
| **进程归因** | 间接（/proc 轮询，竞态） | 直接（内核态 PID/comm） |
| **UDP 归因** | 困难（remote=0.0.0.0） | 直接（挂载点有完整 socket 信息） |
| **短连接归因** | 易丢失 | 不丢失（每次 send/recv 都触发） |
| **性能开销** | 中高（全包拷贝到用户态） | 低（内核态聚合，只传统计数据） |
| **容器感知** | 无（限制在 namespace 内） | 有（cgroup ID, namespace ID） |
| **完整包数据** | 有 | 可选（但增加复杂度） |
| **DNS 解析** | 有（可捕获 DNS 包内容） | 需额外挂载点或 socket filter |
| **内核版本要求** | Linux 2.2+ | 4.9+（最低），5.8+（推荐） |
| **实现复杂度** | 低 | 中高（eBPF 程序 + 加载器） |
| **调试难度** | 低 | 中（eBPF verifier 限制） |

### 3.1 eBPF 的核心优势

1. **消除进程归因竞态**：这是最大的改进。AF_PACKET 方案下，netoproc 每 500ms 轮询一次 `/proc`，
   短于 500ms 的连接可能完全归入 Unknown。eBPF kprobe 在每次 socket 操作时触发，
   可以 100% 准确地将流量归因到进程。

2. **更低的 CPU 开销**：AF_PACKET 将完整帧拷贝到用户态再解析，eBPF 在内核态直接提取
   5-tuple + PID + 字节数，通过 BPF map 聚合后只将统计结果发送到用户态。

3. **更好的 UDP 支持**：AF_PACKET 方案下 UDP 进程归因几乎是靠运气（`/proc/net/udp`
   的 remote 始终为 0），eBPF 在 `udp_sendmsg` 挂载点可以直接读取目标地址。

### 3.2 eBPF 的不足

1. **无法直接获取完整包内容**：kprobe 方案获取的是 socket 级别的统计数据（字节数），
   不是原始网络帧。如果需要 DNS 解析（读取 DNS 响应内容），仍需 AF_PACKET 或
   额外的 socket filter eBPF 程序。

2. **内核版本限制**：RHEL 8 等旧平台的 BTF 缺失是实际问题。

3. **开发和调试门槛更高**：eBPF 程序受 verifier 限制（栈大小、循环、指针安全），
   开发体验不如普通用户态代码。

---

## 4. Rust eBPF 生态

### 4.1 可选的 Rust eBPF 框架

| 框架 | 内核代码语言 | C/LLVM 依赖 | 维护状态 | CO-RE 支持 | 异步支持 |
|------|------------|------------|---------|-----------|---------|
| **Aya** | Rust | 无 | 活跃 (2024-2025) | 有 | tokio + async-std |
| **libbpf-rs** | C | libbpf (C) | 活跃 | 有 | 有限 |
| **RedBPF** | Rust | LLVM | **已停止维护** | 部分 | 有限 |

### 4.2 推荐：Aya

**Aya** 是目前 Rust eBPF 生态的最佳选择，原因：

1. **纯 Rust**：内核态和用户态代码都用 Rust 编写，无需 C 工具链。
2. **无外部依赖**：不依赖 libbpf、bcc、LLVM，只需 `libc` crate。
3. **CO-RE 支持**：配合 BTF 和 musl 静态链接，可实现真正的 compile-once-run-everywhere。
4. **生产级采用**：
   - Kubernetes SIG 的 Blixt（Gateway API 负载均衡器）
   - Red Hat 的 bpfman（eBPF 程序加载守护进程）
   - RustNet（网络监控 TUI，和 netoproc 目标类似）
5. **与 netoproc 的契合**：
   - netoproc 已经是纯 Rust 项目，无 C 依赖
   - Aya 不引入新的 C 工具链依赖
   - Aya 支持 kprobe 附加，符合我们的需求

### 4.3 参考项目

| 项目 | 技术栈 | 说明 |
|------|--------|------|
| **RustNet** (`rustnet-monitor`) | Rust + Aya eBPF | 网络监控 TUI，eBPF 失败时回退到 procfs |
| **Bandix** | Rust + eBPF | 流量监控，支持 DNS + IPv6 |
| **ayaFlow** | Rust + Aya | K8s 网络分析，TC classifier + ring buffer |
| **pktstat-bpf** | Go + eBPF | TC/XDP/KProbe 多模式流量监控 |

---

## 5. 策略决策：可选模式 vs 直接替换

### 5.1 结论：**应作为可选模式，不应直接替换 AF_PACKET**

理由如下：

#### 必须保留 AF_PACKET 的原因

1. **RHEL 8 兼容性**：RHEL 8 (EOL 2029) 内核 4.18 无 BTF，CO-RE 不可用。
   虽然可以为 RHEL 8 预编译 eBPF 程序，但增加大量复杂性。
   AF_PACKET 在所有 Linux 版本上都能工作。

2. **DNS 捕获需要**：eBPF kprobe 方案获取的是 socket 级别统计，
   不包含 DNS 响应的具体内容。netoproc 的 DNS 解析功能
   （反向域名查找）仍需原始包捕获。保留 AF_PACKET 用于 DNS 捕获
   是合理的混合方案。

3. **渐进式迁移**：一次性替换风险太大。作为可选模式引入，
   可以逐步验证 eBPF 方案的正确性，收集用户反馈后再决定是否默认化。

4. **容错回退**：RustNet 的做法值得参考——eBPF 加载失败时自动回退到 procfs。
   netoproc 可以采用类似策略：eBPF 模式失败时回退到 AF_PACKET + /proc。

#### 推荐架构

```
┌───────────────────────────────────────────────────────┐
│                  netoproc CLI                          │
│  --capture-mode=auto|ebpf|afpacket                    │
└──────────────────┬────────────────────────────────────┘
                   │
          ┌────────▼────────┐
          │  CaptureBackend  │  (运行时选择)
          │  enum dispatch   │
          └──┬───────────┬──┘
             │           │
    ┌────────▼───┐  ┌───▼──────────┐
    │ eBPF mode  │  │ AF_PACKET    │
    │ (kprobe)   │  │ mode         │
    │            │  │              │
    │ PID: 内核态│  │ PID: /proc   │
    │ 统计: map  │  │ 包捕获: raw  │
    │ DNS: 需    │  │ DNS: 有      │
    │   额外处理 │  │              │
    └────────────┘  └──────────────┘
```

**默认行为 (`--capture-mode=auto`)**：
1. 检测内核版本 >= 5.8 且 BTF 可用 → 使用 eBPF
2. 否则 → 回退到 AF_PACKET

**DNS 处理**：
- eBPF 模式下，DNS 捕获仍可使用 AF_PACKET socket filter（仅用于 port 53）
- 或者通过 eBPF socket filter 挂载到 DNS 流量

### 5.2 实现路线图

#### Phase 1：基础 eBPF kprobe 模式
- 引入 `aya` + `aya-ebpf` 依赖
- 编写 kprobe eBPF 程序挂载 `tcp_sendmsg`/`tcp_recvmsg`
- 用户态通过 BPF map 读取 PID → 流量统计
- `--capture-mode=ebpf` CLI 选项

#### Phase 2：UDP 支持 + DNS
- 添加 `udp_sendmsg`/`udp_recvmsg` kprobe
- DNS 解析方案（AF_PACKET fallback 或 eBPF socket filter）

#### Phase 3：auto 模式 + 回退
- 内核版本 / BTF 检测
- `--capture-mode=auto` 作为默认值
- eBPF 加载失败时优雅回退到 AF_PACKET

#### Phase 4：高级功能
- cgroup 感知（容器流量归因）
- ring buffer 替代 perf buffer（5.8+ 内核）
- 可选的 XDP 加速路径

### 5.3 Cargo.toml 变更预估

```toml
[target.'cfg(target_os = "linux")'.dependencies]
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

[features]
default = ["ebpf"]
ebpf = ["aya", "aya-log"]
```

使用 feature flag，不需要 eBPF 的用户可以 `--no-default-features` 编译纯 AF_PACKET 版本。

---

## 6. 权限模型变更

eBPF 模式需要额外的 capabilities：

| Capability | AF_PACKET 模式 | eBPF 模式 | 说明 |
|-----------|---------------|----------|------|
| `CAP_NET_RAW` | 需要 | 需要（如果 DNS 用 AF_PACKET） | 创建原始 socket |
| `CAP_NET_ADMIN` | 需要 | 需要 | 混杂模式 |
| `CAP_SYS_PTRACE` | 需要 | 不再需要 | eBPF 在内核态直接获取 PID |
| `CAP_BPF` | 不需要 | **需要** (5.8+) | 加载 eBPF 程序 |
| `CAP_PERFMON` | 不需要 | **需要** (5.8+) | kprobe attach |
| `CAP_SYS_ADMIN` | 不需要 | 需要 (<5.8) | 5.8 之前替代 CAP_BPF |

**5.8+ 内核**：`CAP_BPF + CAP_PERFMON` 替代了 `CAP_SYS_PTRACE`，权限粒度更细。
**< 5.8 内核**：需要 `CAP_SYS_ADMIN`（权限更大，但这些旧内核本身也需要 root）。

install-linux.sh 需要相应更新，根据捕获模式设置不同的 capabilities。

---

## 7. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| eBPF verifier 拒绝程序 | 功能不可用 | 充分测试 + auto 回退到 AF_PACKET |
| 内核 API 变更 (kprobe 不稳定) | 特定内核版本不兼容 | 使用 tracepoint（更稳定）作为备选挂载点 |
| Aya crate breaking changes | 编译失败 | 锁定 Aya 版本，跟进上游 |
| RHEL 8 用户无法使用 eBPF | 降级到 AF_PACKET | auto 模式自动检测并回退 |
| 编译产物增大 | 二进制体积增加 | eBPF 作为 feature flag，可选编译 |
| eBPF 程序需要嵌入二进制 | 部署复杂度增加 | Aya 支持将 eBPF ELF 嵌入 Rust 二进制 |

---

## 8. 总结

| 问题 | 回答 |
|------|------|
| 是否所有发行版都支持 eBPF？ | **否**。RHEL 8 (4.18) 支持有限（无 BTF），RHEL 7 已 EOL。从 kernel 5.10 起（Debian 11, RHEL 9, Ubuntu 22.04）可认为普遍可用 |
| 应该可选还是替换？ | **可选模式**。通过 `--capture-mode=auto\|ebpf\|afpacket` 控制，默认 auto 检测 |
| 推荐的 Rust 框架？ | **Aya**。纯 Rust，无外部依赖，活跃维护，生产级采用 |
| 最低内核要求？ | eBPF 模式：5.8+（推荐），4.9+（最低，功能受限）；AF_PACKET 模式：任意 Linux |
| DNS 捕获方案？ | 混合模式：eBPF 负责进程归因 + 流量统计，AF_PACKET（或 eBPF socket filter）负责 DNS 包内容捕获 |

---

## 参考资料

- [BCC Kernel Versions Reference](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [eBPF.io - What is eBPF](https://ebpf.io/what-is-ebpf/)
- [Aya - Rust eBPF Library](https://aya-rs.dev/)
- [eBPF Ecosystem Progress 2024-2025](https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/)
- [Red Hat eBPF in RHEL 7](https://www.redhat.com/en/blog/introduction-ebpf-red-hat-enterprise-linux-7)
- [Cilium System Requirements](https://docs.cilium.io/en/stable/operations/system_requirements/)
- [pktstat-bpf (Go eBPF 流量监控)](https://github.com/dkorunic/pktstat-bpf)
- [RustNet Monitor](https://crates.io/crates/rustnet-monitor)
- [Microsoft Defender eBPF Sensor Requirements](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf)
- [FOSDEM 2025: Building eBPF with Rust and Aya](https://archive.fosdem.org/2025/events/attachments/fosdem-2025-5534-building-your-ebpf-program-with-rust-and-aya/slides/238267/Building_7AI18W8.pdf)
