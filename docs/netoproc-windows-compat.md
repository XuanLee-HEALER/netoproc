# netoproc Windows 兼容设计文档

> v0.5.0 目标：在现有 macOS + Linux cfg 模块切换架构上增加 Windows 支持。

**当前版本**: v0.4.0（macOS + Linux）
**目标版本**: v0.5.0（macOS + Linux + Windows）

---

## 1. 总体策略

### 1.1 改造范围

延续 v0.4.0 的 `#[cfg(target_os)]` 模块切换方案，新增 `target_os = "windows"` 分支。
每个已有的平台抽象点添加 Windows 实现模块，导出相同的公开函数签名。

需要新增 Windows 实现的模块：

| 模块 | macOS | Linux | Windows |
|------|-------|-------|---------|
| 包捕获 | BPF `/dev/bpf*` | AF_PACKET socket | Raw socket + SIO_RCVALL |
| 进程归属 | libproc | /proc/net/tcp + /proc/fd | GetExtendedTcpTable/UdpTable |
| 连接状态 | sysctl pcblist_n | /proc/net/tcp[6] | GetExtendedTcpTable |
| 进程枚举 | libproc (proc_listpids) | /proc/<pid>/stat | CreateToolhelp32Snapshot |
| 网卡信息 | getifaddrs + AF_LINK | getifaddrs + AF_PACKET | GetAdaptersAddresses |
| DNS 配置 | SystemConfiguration | /etc/resolv.conf | GetAdaptersAddresses DNS fields |
| 权限检查 | getuid + /dev/bpf0 access | getuid + AF_PACKET test | IsUserAnAdmin / raw socket test |
| 信号处理 | signal(SIGTERM/SIGINT) | signal(SIGTERM/SIGINT) | SetConsoleCtrlHandler |

不需要改动的代码（~95%）：
- `PacketSummary` / `SocketKey` / `TrafficStats` 数据结构
- 共享的 IP/TCP/UDP/DNS 包解析（packet.rs, dns.rs）
- channel 模型与三线程架构
- TUI 渲染层（ratatui + crossterm 原生支持 Windows）
- snapshot / monitor 模式逻辑
- enrichment（dns_resolver.rs 使用 dns-lookup crate，跨平台）

### 1.2 目录结构变更

```
src/
├── capture/
│   ├── mod.rs          ← 添加 #[cfg(target_os = "windows")] 路由
│   ├── macos.rs
│   ├── linux.rs
│   └── windows.rs      ← 新增：RawSocketCapture
├── process/
│   ├── mod.rs          ← 添加 #[cfg(target_os = "windows")] 路由
│   ├── macos.rs
│   ├── linux.rs
│   └── windows.rs      ← 新增：GetExtendedTcpTable + GetExtendedUdpTable
├── system/
│   ├── process.rs      ← 添加 #[cfg(target_os = "windows")] 段
│   ├── connection.rs   ← 添加 #[cfg(target_os = "windows")] 段
│   ├── interface.rs    ← 添加 #[cfg(target_os = "windows")] 段
│   └── dns_config.rs   ← 添加 #[cfg(target_os = "windows")] 段
├── main.rs             ← 信号处理、接口发现 Windows 分支
└── error.rs            ← 添加 WinApi 错误变体
```

### 1.3 依赖变更

```toml
[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",
    "Win32_Networking_WinSock",
    "Win32_NetworkManagement_IpHelper",
    "Win32_System_Threading",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_Security",
    "Win32_System_Console",
] }
```

### 1.4 交叉编译验证

```bash
# 安装 cross
cargo install cross

# 验证 Windows GNU 目标编译通过
cross build --target x86_64-pc-windows-gnu

# 同时验证 macOS/Linux 不受影响
cargo check  # 当前平台
```

---

## 2. PacketCapture（包捕获）

### 2.1 Windows 方案：Raw Socket + SIO_RCVALL

Windows 没有 BPF 或 AF_PACKET。使用 Winsock2 原始套接字：

```
socket(AF_INET, SOCK_RAW, IPPROTO_IP)
→ bind(interface_ip)
→ WSAIoctl(SIO_RCVALL, RCVALL_ON)  // 接收所有 IP 包
→ recv() 返回完整 IP 包（无以太网头）
```

**关键差异**：
- 收到的是 raw IP 包（无 Ethernet header），使用 `packet::parse_raw_frame()` 解析
- 每个 socket 绑定到一个 interface IP（不是 interface name）
- 需要 Administrator 权限
- IPv4 和 IPv6 需要分别用 AF_INET/AF_INET6 socket

**过滤策略**：
- macOS/Linux 用硬件 BPF filter 在内核层过滤
- Windows 在用户空间做软件过滤（性能略低，但对监控工具可接受）
- Traffic capture：只保留 TCP/UDP/ICMP 包
- DNS capture：只保留 port 53 的包

### 2.2 导出 API（与 macOS/Linux 一致）

```rust
pub type PlatformCapture = RawSocketCapture;
pub struct CaptureStats { pub received: u32, pub dropped: u32 }
pub fn check_capture_access() -> Result<(), NetopError>
pub fn open_capture_devices(...) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError>
pub fn capture_stats(cap: &PlatformCapture) -> Option<CaptureStats>
```

PlatformCapture 实现的方法：
- `read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError>`
- `read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError>`
- `interface(&self) -> &str`

### 2.3 已知限制

- SIO_RCVALL 在某些 Windows 版本（如 Home Edition）可能受限
- 出站包捕获可能不完整（取决于 Windows 版本和网络驱动）
- 无法在同一 socket 上同时捕获 IPv4 和 IPv6（需要两个 socket）
- 本实现先支持 IPv4 捕获，IPv6 可后续扩展

---

## 3. ProcessTable（进程归属）

### 3.1 Windows 方案：IP Helper API

Windows 提供比 Linux/macOS 更直接的 socket-to-PID 映射：

```
GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)
  → MIB_TCPTABLE_OWNER_PID → 每行包含 (local_addr, local_port, remote_addr, remote_port, state, owning_pid)

GetExtendedUdpTable(UDP_TABLE_OWNER_PID)
  → MIB_UDPTABLE_OWNER_PID → 每行包含 (local_addr, local_port, owning_pid)
```

无需 Linux 那样的三步关联（inode → fd → pid），Windows 直接给出 PID。

进程名通过 `CreateToolhelp32Snapshot` + `Process32First/Next` 获取。

### 3.2 TCP 状态映射

Windows MIB_TCP_STATE 枚举值：
```
1=CLOSED, 2=LISTEN, 3=SYN_SENT, 4=SYN_RCVD,
5=ESTAB, 6=FIN_WAIT1, 7=FIN_WAIT2, 8=CLOSE_WAIT,
9=CLOSING, 10=LAST_ACK, 11=TIME_WAIT, 12=DELETE_TCB
```

---

## 4. 系统 API 实现

### 4.1 system/interface.rs

使用 `GetAdaptersAddresses(AF_UNSPEC)` 替代 `getifaddrs`：
- 返回 `IP_ADAPTER_ADDRESSES` 链表
- 包含 IPv4/IPv6 地址、DNS 服务器、接口状态
- 接口统计通过 `GetIfEntry2` 获取（字节/包计数）

### 4.2 system/dns_config.rs

DNS 配置从 `GetAdaptersAddresses` 的 `FirstDnsServerAddress` 链表提取。

### 4.3 system/process.rs

进程枚举使用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Next`。

### 4.4 system/connection.rs

TCP/UDP 连接使用 `GetExtendedTcpTable`/`GetExtendedUdpTable`。

---

## 5. main.rs 变更

### 5.1 信号处理

```rust
#[cfg(windows)]
fn install_signal_handlers() {
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
            Some(ctrl_handler), 1
        );
    }
}

#[cfg(windows)]
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT => {
            SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
            1 // handled
        }
        _ => 0,
    }
}
```

### 5.2 接口发现

Windows 不使用 `libc::IFF_UP`/`libc::IFF_LOOPBACK`。
为 `RawInterface` 添加 `is_loopback()` 方法，在各平台实现中正确设置 flags。
定义共享的 flag 常量：`FLAG_UP = 0x1`, `FLAG_LOOPBACK = 0x8`。

---

## 6. 验证计划

### 6.1 编译验证（在 Linux 环境使用 cross）

```bash
cross build --target x86_64-pc-windows-gnu
```

### 6.2 运行时测试清单（需要 Windows 环境）

- [ ] Raw socket 能正常创建（需要 Administrator）
- [ ] SIO_RCVALL 启用后能收到 IP 包
- [ ] IPv4 包解析正确（使用 parse_raw_frame）
- [ ] GetExtendedTcpTable 返回正确的连接和 PID
- [ ] 进程名通过 CreateToolhelp32Snapshot 正确获取
- [ ] GetAdaptersAddresses 返回接口信息
- [ ] TUI 在 Windows Terminal 中正常渲染
- [ ] Ctrl-C 触发优雅关闭
