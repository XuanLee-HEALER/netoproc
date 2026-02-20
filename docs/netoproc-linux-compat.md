# netoproc Linux 兼容与跨平台抽象设计文档

> 供 code agent 直接实现使用。描述将 macOS 专属代码改造为跨平台架构，并添加 Linux 支持的完整方案。

**实现状态**: v0.4.0 已完成。采用 `#[cfg(target_os)]` 模块切换方案（非 trait + generics），
两套平台模块导出相同的公开函数签名，编译时由 cfg 选择。

---

## 1. 总体策略

### 1.1 改造范围

需要平台隔离的模块只有两个：

| 模块 | macOS | Linux |
|------|-------|-------|
| 包捕获（PacketCapture） | `/dev/bpf*` + ioctl | `AF_PACKET` socket |
| 进程归属（ProcessTable） | `libproc` | `/proc/net/tcp` + `/proc/<pid>/fd/` |

其余所有代码**不需要改动**，包括：
- `PacketSummary` 数据结构
- `SocketKey` 规范化 key
- `TrafficStats` 统计聚合
- channel 模型与三线程架构
- TUI 渲染层
- snapshot / monitor 模式逻辑

### 1.2 实际目录结构（v0.4.0 实现）

```
src/
├── capture/
│   ├── mod.rs        ← cfg 路由 + FilterKind enum
│   ├── macos.rs      ← 封装 BpfCapture，导出为 PlatformCapture
│   └── linux.rs      ← AfPacketCapture（新增），导出为 PlatformCapture
├── process/
│   ├── mod.rs        ← cfg 路由
│   ├── macos.rs      ← 委托 system::process::build_process_table()
│   └── linux.rs      ← /proc 解析实现
├── packet.rs         ← PacketSummary、parse_ethernet 等（从 bpf/packet.rs 提取）
├── dns.rs            ← DNS 线格式解析（从 bpf/dns.rs 提取）
├── bpf/              ← #[cfg(target_os = "macos")] 门控
├── privilege.rs      ← #[cfg(target_os = "macos")] 门控
├── system/
│   ├── process.rs    ← macOS/Linux 各自实现，共享 RawProcess 定义
│   ├── connection.rs ← macOS/Linux 各自实现，共享 RawTcp/UdpConnection
│   ├── interface.rs  ← 共享 getifaddrs，AF_LINK(macOS) / AF_PACKET(Linux) 分支
│   └── dns_config.rs ← macOS CoreFoundation / Linux resolv.conf
└── main.rs
```

**设计决策**：不使用 trait + generics，改用 cfg 模块切换。原因是 main.rs 无需泛型参数化，
每个平台模块导出相同的函数签名即可，代码更简洁。

### 1.3 交叉编译工具链

在 macOS 上开发 Linux 代码，无需 Linux 机器：

```bash
# 添加编译目标
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu

# 安装 cross（通过 Docker 处理 C 库差异）
cargo install cross

# 编译验证（不能运行，但能验证代码是否编译通过）
cross build --release --target x86_64-unknown-linux-gnu
```

**重要**：`cross build` 只验证编译，运行时测试仍需 Linux 机器或虚拟机。建议在有 Linux 环境时做集成测试，日常开发用 `cross build` 验证编译正确性即可。

---

## 2. PacketCapture 抽象

### 2.1 模块路由（实际实现）

```rust
// src/capture/mod.rs — 不使用 trait，用 cfg 模块切换

pub enum FilterKind { Traffic, Dns }

#[cfg(target_os = "macos")] mod macos;
#[cfg(target_os = "macos")] pub use macos::*;

#[cfg(target_os = "linux")] mod linux;
#[cfg(target_os = "linux")] pub use linux::*;
```

两套平台模块导出相同的公开 API：
- `pub type PlatformCapture = ...;`
- `pub struct CaptureStats { ... }`
- `pub fn check_capture_access() -> Result<(), NetopError>`
- `pub fn open_capture_devices(...) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError>`
- `pub fn capture_stats(cap: &PlatformCapture) -> Option<CaptureStats>`

main.rs 中的 `capture_loop()` 直接使用 `PlatformCapture` 类型，无需泛型。

### 2.2 macOS 实现（BpfCapture）

`src/capture/macos.rs` 封装现有 `crate::bpf::BpfCapture`，导出为 `PlatformCapture`。

### 2.3 Linux 实现（AfPacketCapture）

#### 初始化流程

```rust
// src/capture/linux.rs

pub struct AfPacketCapture {
    fd: OwnedFd,
    buffer: Vec<u8>,
    interface: String,
}

impl AfPacketCapture {
    pub fn new(interface: &str, buffer_size: usize, filter: &[sock_filter]) -> Result<Self, NetopError> {
        // 1. 创建 raw socket
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(NetopError::from(io::Error::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // 2. 获取网卡 ifindex
        let ifindex = get_ifindex(interface)?;

        // 3. 绑定到指定网卡
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(NetopError::from(io::Error::last_os_error()));
        }

        // 4. 安装 BPF filter（格式与 macOS 完全相同）
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut _,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };
        if ret < 0 {
            return Err(NetopError::from(io::Error::last_os_error()));
        }

        // 5. 设置读超时 500ms（等价于 macOS 的 BIOCSRTIMEOUT）
        let tv = libc::timeval { tv_sec: 0, tv_usec: 500_000 };
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };

        // 6. 设置接收缓冲区大小
        let buf_size = buffer_size as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            )
        };

        Ok(Self {
            fd,
            buffer: vec![0u8; buffer_size],
            interface: interface.to_string(),
        })
    }
}
```

#### read_packets 实现

AF_PACKET 每次 `recvfrom` 只返回一个包，与 BPF 一次返回多个包不同。在实现内部用循环收集多个包，对外表现和 macOS 版本一致：

```rust
impl PacketCapture for AfPacketCapture {
    fn read_packets(&mut self, out: &mut Vec<PacketSummary>) -> Result<(), NetopError> {
        // 非阻塞地收集当前可用的所有包，直到 EAGAIN 或 500ms 超时
        // 第一次 recvfrom 是阻塞的（等待数据或超时）
        // 后续切换到非阻塞模式榨干缓冲区
        let mut first = true;
        loop {
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr() as *mut libc::c_void,
                    self.buffer.len(),
                    if first { 0 } else { libc::MSG_DONTWAIT }, // 第一次阻塞，后续非阻塞
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) => break, // 缓冲区已空
                    Some(libc::EINTR) => continue,                          // 信号中断，重试
                    _ => return Err(NetopError::from(err)),
                }
            }

            first = false;

            if n == 0 { break; }

            // 每次 recvfrom 返回一个完整的以太网帧，直接解析
            if let Some(summary) = parse_ethernet(&self.buffer[..n as usize]) {
                out.push(summary);
            }
        }
        Ok(())
    }
}
```

#### 获取网卡 ifindex

```rust
fn get_ifindex(interface: &str) -> Result<i32, NetopError> {
    let name = CString::new(interface)
        .map_err(|_| NetopError::InvalidInterface(interface.to_string()))?;
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        Err(NetopError::InvalidInterface(interface.to_string()))
    } else {
        Ok(idx as i32)
    }
}
```

#### ⚠️ Linux 实现的坑

**坑1：收到出站包的副本问题**

AF_PACKET 默认会收到本机发出的包的副本（`PACKET_OUTGOING`），导致出站流量被计算两次。需要过滤掉 `sll_pkttype == PACKET_OUTGOING` 的包，或者在 `recvfrom` 时用 `recvmsg` 获取 `sockaddr_ll` 来判断方向。

推荐做法：用 `recvmsg` 替代 `recvfrom`，从 `sockaddr_ll.sll_pkttype` 判断包方向：

```rust
// sll_pkttype 的值：
// PACKET_HOST      = 0  → 发给本机的包
// PACKET_BROADCAST = 1  → 广播包
// PACKET_MULTICAST = 2  → 多播包
// PACKET_OTHERHOST = 3  → 目标是其他主机（混杂模式下收到）
// PACKET_OUTGOING  = 4  → 本机发出的包（AF_PACKET 特有）
```

**坑2：SO_RCVBUF 实际值是请求值的两倍**

Linux 内核会将 `SO_RCVBUF` 设置的值翻倍（作为系统预留），`getsockopt(SO_RCVBUF)` 读回的值是实际值的两倍。这不影响功能，但日志打印时注意不要误导用户。

**坑3：filter 类型名称差异**

macOS 用 `bpf_insn`，Linux 用 `sock_filter`，但内存布局完全相同（都是 `{ code: u16, jt: u8, jf: u8, k: u32 }`）。filter 指令数组可以直接复用，只需在类型声明上用 cfg 区分：

```rust
#[cfg(target_os = "macos")]
pub type FilterInsn = libc::bpf_insn;

#[cfg(target_os = "linux")]
pub type FilterInsn = libc::sock_filter;
```

**坑4：混杂模式**

macOS 用 `ioctl(BIOCPROMISC)` 开启混杂模式，Linux 用 `setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP)`：

```rust
#[cfg(target_os = "linux")]
fn set_promisc(fd: RawFd, ifindex: i32) {
    let mreq = libc::packet_mreq {
        mr_ifindex: ifindex,
        mr_type: libc::PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as u32,
        )
    };
}
```

---

## 3. ProcessTable 抽象

### 3.1 模块路由（实际实现）

```rust
// src/process/mod.rs — cfg 模块切换，不使用 trait

#[cfg(target_os = "macos")] mod macos;
#[cfg(target_os = "macos")] pub use macos::build_process_table;

#[cfg(target_os = "linux")] pub mod linux;
#[cfg(target_os = "linux")] pub use linux::build_process_table;
```

两套平台模块导出 `pub fn build_process_table() -> ProcessTable`。
main.rs 直接调用 `netoproc::process::build_process_table()`，无需泛型。

### 3.2 macOS 实现

`src/process/macos.rs` 委托到 `crate::system::process::build_process_table()`。

### 3.3 Linux 实现

`src/process/linux.rs` 完整实现 /proc 解析，同时导出 `pub(crate)` 解析助手函数
供 `src/system/connection.rs` 和 `src/system/process.rs` 复用。

#### 数据来源

Linux 没有 libproc，进程和 socket 的关联需要两步：

```
/proc/net/tcp  →  inode → socket 映射
/proc/net/tcp6 →  inode → socket 映射（IPv6）
/proc/net/udp  →  inode → socket 映射
/proc/net/udp6 →  inode → socket 映射

/proc/<pid>/fd/ →  pid → inode 映射（通过 symlink 读取）
/proc/<pid>/comm →  pid → 进程名
```

#### 实现结构

```rust
pub struct ProcFsTable {
    inner: HashMap<SocketKey, ProcessInfo>,
}

impl ProcessTable for ProcFsTable {
    fn refresh(&mut self) -> Result<(), NetopError> {
        // Step 1: 读取 /proc/net/tcp[6] 和 /proc/net/udp[6]
        //         建立 inode → (local_ip, local_port, remote_ip, remote_port) 映射
        let inode_to_socket = read_proc_net()?;

        // Step 2: 遍历 /proc/<pid>/fd/，读取每个 symlink
        //         symlink 格式为 "socket:[inode]"，从中提取 inode
        //         建立 inode → pid 映射
        let inode_to_pid = read_proc_fds()?;

        // Step 3: 读取 /proc/<pid>/comm 获取进程名
        // Step 4: 合并三张表，构建 SocketKey → ProcessInfo
        self.inner = merge_tables(inode_to_socket, inode_to_pid)?;
        Ok(())
    }

    fn lookup(&self, key: &SocketKey) -> Option<&ProcessInfo> {
        self.inner.get(key)
    }

    fn snapshot(&self) -> HashMap<SocketKey, ProcessInfo> {
        self.inner.clone()
    }
}
```

#### /proc/net/tcp 解析

文件格式（每行一个连接）：

```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0  21234 ...
```

关键字段：
- `local_address`：`hex_ip:hex_port`，**小端序**（需要字节反转）
- `rem_address`：同上
- `inode`：第10列（0-indexed），直接用于关联 pid

```rust
fn parse_proc_net_entry(line: &str) -> Option<(u64, SocketAddr, SocketAddr)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 { return None; }

    let local = parse_hex_addr(fields[1])?;
    let remote = parse_hex_addr(fields[2])?;
    let inode: u64 = fields[9].parse().ok()?;

    Some((inode, local, remote))
}

fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (hex_ip, hex_port) = s.split_once(':')?;
    let port = u16::from_str_radix(hex_port, 16).ok()?;

    // IPv4：4字节小端序，需要 u32::from_str_radix 然后 to_be()
    let ip_raw = u32::from_str_radix(hex_ip, 16).ok()?;
    let ip = Ipv4Addr::from(ip_raw.to_be()); // ⚠️ 注意字节序，见坑1

    Some(SocketAddr::new(IpAddr::V4(ip), port))
}
```

#### ⚠️ Linux 实现的坑

**坑1：/proc/net/tcp 的字节序陷阱**

这是 Linux 实现最容易出错的地方。`/proc/net/tcp` 中的 IP 地址是**小端序的十六进制**，但不同架构下字节序含义不同：

- x86_64（小端机器）：`0100007F` 表示 `127.0.0.1`，需要做 `u32::from_str_radix("0100007F", 16)` 然后 `.swap_bytes()` 或者 `.to_be()`
- 验证方法：`0100007F` → `0x0100007F` → swap bytes → `0x7F000001` → `127.0.0.1` ✓

IPv6 格式更复杂，是4个小端序 u32 拼接，解析时需要分段处理：

```rust
fn parse_hex_addr_v6(s: &str) -> Option<Ipv6Addr> {
    // s 形如 "00000000000000000000000001000000"（32个十六进制字符）
    // 每8个字符为一个小端序 u32
    let bytes: Vec<u8> = (0..4)
        .flat_map(|i| {
            let chunk = &s[i*8..(i+1)*8];
            let val = u32::from_str_radix(chunk, 16).unwrap_or(0);
            val.to_be_bytes() // 转换为大端字节
        })
        .collect();
    // ⚠️ 还需要对每个 u32 的字节做反转，而不是对整个地址反转
    // 见 Linux 内核 net/ipv6/proc.c 的格式定义
}
```

**坑2：/proc/<pid>/fd 需要权限**

遍历 `/proc/<pid>/fd/` 需要对应进程的权限或 root。普通用户只能读取自己进程的 fd 目录，其他进程会返回 `EACCES`。

处理方式：遇到权限错误时跳过该进程（`continue`），不要返回错误，这些进程的流量会归入 `Unknown`。这是 nethogs 的相同处理方式。

```rust
fn read_proc_fds() -> Result<HashMap<u64, u32>, NetopError> {
    let mut inode_to_pid = HashMap::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue, // 跳过非数字目录（self、net 等）
        };
        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(fds) => fds,
            Err(_) => continue, // ⚠️ EACCES：没有权限，跳过，不报错
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let s = target.to_string_lossy();
                // symlink 格式："socket:[inode]"
                if let Some(inode_str) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        inode_to_pid.insert(inode, pid);
                    }
                }
            }
        }
    }
    Ok(inode_to_pid)
}
```

**坑3：/proc/net/tcp 只显示同 network namespace 的连接**

容器环境下，`/proc/net/tcp` 只显示当前 network namespace 的连接。跨 namespace 的连接无法通过这个文件枚举。对于 netoproc 的目标场景（监控本机流量），这个限制可以接受，在文档和 README 里注明即可。

**坑4：time-of-check-to-time-of-use（TOCTOU）**

读取 `/proc/net/tcp` 和遍历 `/proc/<pid>/fd/` 之间有时间差，期间进程可能退出，导致 inode 查不到对应 pid。这不是 bug，正常情况下直接跳过即可，这部分流量归入 Unknown。

**坑5：UDP 连接在 /proc/net/udp 中 remote 地址为 0**

UDP 是无连接协议，`/proc/net/udp` 中 `rem_address` 通常是 `00000000:0000`。这意味着 UDP 的 SocketKey 规范化时 remote 端永远是 `0.0.0.0:0`，包捕获时也需要对 UDP 包用相同的规则构造 key（remote 设为 0）才能匹配上。

这和 macOS libproc 的行为一致，不是 Linux 特有问题，但容易漏掉。

---

## 4. 共享的以太网解析层

`parse_ethernet` 函数在两个平台上完全相同，放在 `src/packet.rs` 中，不需要 cfg 隔离：

```rust
// src/packet.rs — 跨平台，无需任何 cfg

pub fn parse_ethernet(frame: &[u8]) -> Option<PacketSummary> {
    if frame.len() < 14 { return None; }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    match ether_type {
        0x0800 => parse_ipv4(&frame[14..]),
        0x86DD => parse_ipv6(&frame[14..]),
        _ => None,
    }
}
```

两个平台拿到原始以太网帧后，都调用同一个 `parse_ethernet`，解析路径完全一致。

---

## 5. Cargo.toml 平台依赖

Linux 和 macOS 可能需要不同的系统库，用 `target` 条件声明：

```toml
[dependencies]
libc = "0.2"
arc-swap = "1"
rustc-hash = "1"

# macOS 专属：如果 libproc 需要额外绑定
[target.'cfg(target_os = "macos")'.dependencies]
# 目前通过 libc 直接调用，无需额外 crate

# Linux 专属：目前通过 libc 直接调用，无需额外 crate
[target.'cfg(target_os = "linux")'.dependencies]
# 留空，按需添加
```

---

## 6. 开发与测试流程

### 6.1 在 macOS 上验证 Linux 代码编译

```bash
# 验证 Linux x86_64 编译通过
cross build --target x86_64-unknown-linux-gnu

# 验证 Linux ARM64 编译通过
cross build --target aarch64-unknown-linux-gnu

# 同时验证 macOS 仍然正常
cargo build
```

### 6.2 cfg 正确性验证

在 macOS 上，Linux 分支的代码不会被编译，编译器不会检查其中的错误。有几种方式缓解：

```bash
# 方式一：用 cross 触发实际的 Linux 编译（最可靠）
cross build --target x86_64-unknown-linux-gnu

# 方式二：用 cargo check 模拟目标平台（不需要 Docker，但不处理 C 库）
cargo check --target x86_64-unknown-linux-gnu
```

### 6.3 运行时测试清单（需要 Linux 环境）

- [ ] AF_PACKET socket 能正常打开（需要 `CAP_NET_RAW` 或 root）
- [ ] filter 安装后只收到 TCP/UDP 包
- [ ] 方向判断正确（Inbound / Outbound 不重复计数）
- [ ] `/proc/net/tcp` IPv4 字节序解析正确（用 `127.0.0.1:port` 的本地连接验证）
- [ ] `/proc/net/tcp6` IPv6 解析正确
- [ ] UDP 连接能正确归因到进程
- [ ] 权限不足时（普通用户）`/proc/<pid>/fd` 访问失败能优雅跳过
- [ ] 进程退出后对应流量归入 Unknown

---

## 7. Linux 权限配置

### 7.1 核心思路

与 macOS 方案对比：

| 机制 | macOS | Linux |
|------|-------|-------|
| 设备权限 | launchd plist 修改 `/dev/bpf*` 组权限 | udev rules 修改 `AF_PACKET` socket 权限（通过 capabilities） |
| 用户组 | `access_bpf` | `netoproc`（自定义组） |
| 一次性配置 | 安装脚本 + launchd | 安装脚本 + udev + setcap |
| 持久性保证 | 系统启动时 launchd 重新执行 | capabilities 写在二进制上，udev 持久化组权限 |

Linux 方案同样是**一次安装，永久生效，运行时零开销**，用户属于正确的组并且二进制有正确的 capabilities 之后，直接运行 `netoproc` 即可。

### 7.2 所需 capabilities 说明

```
cap_net_raw    → 允许创建 AF_PACKET socket（抓包必须）
cap_net_admin  → 允许设置混杂模式（PACKET_ADD_MEMBERSHIP）
cap_sys_ptrace → 允许读取其他进程的 /proc/<pid>/fd/（进程归因必须）
                 不授予此项则只能归因自己的进程，其他流量归入 Unknown
```

权限分级说明（在 README 中体现）：

```
基本模式（cap_net_raw + cap_net_admin）：
  能抓包，只能归因当前用户自己的进程

完整模式（+ cap_sys_ptrace）：
  能归因系统所有进程（推荐，与 macOS 行为一致）
```

推荐安装时直接授予完整模式所需的三个 capabilities，与 macOS 行为对齐。

### 7.3 setcap 持久性说明

`setcap` 将 capabilities 写入二进制文件的扩展属性（xattr），是持久的——系统重启后无需重新执行。但有一个重要限制：**二进制文件被替换（升级）后，capabilities 会丢失**，需要在每次安装/升级后重新执行 `setcap`。安装脚本和包管理器的 post-install hook 都需要包含这一步。

### 7.4 udev rules

udev rules 的作用是在系统启动时将网络设备的访问权限赋予用户组，配合 capabilities 实现无 sudo 运行。对于 `AF_PACKET` socket，Linux 不通过设备文件控制权限（不像 macOS 的 `/dev/bpf*`），权限控制完全由 capabilities 承担，**udev rules 在这里不是必须的**。

但 udev rules 在另一个场景有用：如果未来支持通过 `/dev/net/tun` 或其他设备做包注入，需要通过 udev 控制设备文件权限。当前版本记录这个位置，暂不实现。

### 7.5 install.sh 完整实现

```bash
#!/bin/bash
set -euo pipefail

GROUP_NAME="netoproc"
BINARY_PATH="${1:-$(which netoproc 2>/dev/null || echo '/usr/local/bin/netoproc')}"

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

# 检查是否以 root 运行
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo: sudo bash install.sh"
fi

# 获取实际调用者
TARGET_USER="${SUDO_USER:-$USER}"

# 检查二进制存在
if [ ! -f "$BINARY_PATH" ]; then
    error "Binary not found at $BINARY_PATH. Usage: sudo bash install.sh /path/to/netoproc"
fi

# 检查 setcap 工具存在
if ! command -v setcap &>/dev/null; then
    error "setcap not found. Install libcap2-bin: apt install libcap2-bin / dnf install libcap"
fi

info "Installing netoproc permission configuration..."

# Step 1: 创建用户组（幂等）
if getent group "$GROUP_NAME" &>/dev/null; then
    info "Group '$GROUP_NAME' already exists, skipping creation."
else
    groupadd "$GROUP_NAME"
    success "Created group '$GROUP_NAME'."
fi

# Step 2: 将目标用户加入组（幂等）
if id -nG "$TARGET_USER" | grep -qw "$GROUP_NAME"; then
    info "User '$TARGET_USER' is already in group '$GROUP_NAME', skipping."
else
    usermod -aG "$GROUP_NAME" "$TARGET_USER"
    success "Added user '$TARGET_USER' to group '$GROUP_NAME'."
fi

# Step 3: 设置二进制 capabilities
# cap_net_raw    → AF_PACKET socket（抓包）
# cap_net_admin  → 混杂模式
# cap_sys_ptrace → 读取 /proc/<pid>/fd/（进程归因）
# +eip: effective, inherited, permitted
setcap "cap_net_raw,cap_net_admin,cap_sys_ptrace+eip" "$BINARY_PATH"
success "Set capabilities on $BINARY_PATH."

# Step 4: 验证 capabilities 设置成功
CAP_RESULT=$(getcap "$BINARY_PATH")
if echo "$CAP_RESULT" | grep -q "cap_net_raw"; then
    success "Verified: $CAP_RESULT"
else
    error "Capability verification failed. Please check setcap output."
fi

echo ""
echo "Installation complete."
echo ""
echo "IMPORTANT: You need to log out and log back in for group membership"
echo "to take effect in your current shell session."
echo ""
echo "After re-login, run netoproc without sudo:"
echo "  netoproc"
echo ""
echo "To verify group membership:"
echo "  groups | grep $GROUP_NAME"
```

### 7.6 uninstall.sh

```bash
#!/bin/bash
set -euo pipefail

GROUP_NAME="netoproc"
BINARY_PATH="${1:-$(which netoproc 2>/dev/null || echo '/usr/local/bin/netoproc')}"

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run with sudo: sudo bash uninstall.sh"
fi

# 清除 capabilities
if [ -f "$BINARY_PATH" ]; then
    setcap -r "$BINARY_PATH" 2>/dev/null || true
    success "Removed capabilities from $BINARY_PATH."
fi

# 删除用户组（会自动将所有成员移出该组）
if getent group "$GROUP_NAME" &>/dev/null; then
    groupdel "$GROUP_NAME"
    success "Deleted group '$GROUP_NAME'."
fi

echo ""
echo "Uninstallation complete."
echo "Note: You may need to log out and back in for group changes to take effect."
```

### 7.7 包管理器集成

**apt/deb（post-install）**：

```bash
# debian/postinst
#!/bin/bash
set -e
case "$1" in
    configure)
        # 每次安装或升级都重新设置 capabilities
        setcap "cap_net_raw,cap_net_admin,cap_sys_ptrace+eip" /usr/bin/netoproc
        ;;
esac
```

**rpm/dnf（spec 文件）**：

```spec
%post
setcap "cap_net_raw,cap_net_admin,cap_sys_ptrace+eip" %{_bindir}/netoproc

%postun
if [ $1 -eq 0 ]; then
    setcap -r %{_bindir}/netoproc 2>/dev/null || true
fi
```

### 7.8 升级注意事项

如果用户通过 GitHub Release 手动下载更新二进制，直接替换文件后 capabilities 会丢失（因为 setcap 写在旧文件的 xattr 上，新文件没有继承）。

处理方式：在 README 的升级说明中明确提示用户升级后需要重新运行安装脚本：

```bash
# 升级二进制后重新授权
sudo setcap "cap_net_raw,cap_net_admin,cap_sys_ptrace+eip" $(which netoproc)
# 或者重新运行安装脚本
sudo bash install.sh
```

### 7.9 与 macOS 方案的对比总结

| | macOS | Linux |
|---|---|---|
| 权限持久化机制 | launchd plist（设备文件权限） | setcap（二进制 capabilities xattr） |
| 用户组作用 | 控制 `/dev/bpf*` 读写权限 | 当前版本仅用于标识，capabilities 是实际控制点 |
| 系统重启后 | launchd 自动重新修改 bpf 设备权限 | capabilities 持久，无需重新执行 |
| 二进制升级后 | 无影响（权限在设备文件上） | ⚠️ 需要重新执行 setcap |
| 一次安装操作 | `sudo bash install.sh` | `sudo bash install.sh /path/to/binary` |
| 重新登录要求 | 是（组成员变更） | 是（组成员变更） |

---

## 8. 本文档不涉及的内容

- Windows 支持（`npcap` + WinAPI，后续版本考虑）
- 多网卡同时监控（当前版本每次指定单个 interface）
- 容器 / network namespace 支持
