# netoproc Unknown 流量信息增强设计文档

> 本文档描述反向 DNS 解析与端口/IP 段标注功能的设计与实现，供 code agent 直接使用。
>
> **背景**：macOS 上非 root 运行时，系统守护进程（mDNSResponder、nsurlsessiond 等）的流量无法归因到进程名，统一归入 Unknown。本功能通过远端 IP 的反向 DNS 解析和已知端口/IP 段映射，为 Unknown 流量提供可读的上下文信息，使用户能推断出大部分系统流量的来源。
>
> **适用平台**：macOS（主要场景）、Linux（cap_sys_ptrace 未授权时的降级场景）。

---

## 1. 功能目标

### 1.1 期望的 UI 效果

**改进前**：

```text
PROCESS              RX           TX
chrome (pid 1234)    1.2 MB       340 KB
unknown              890 KB       120 KB
```

**改进后**：

```text
PROCESS              RX           TX
chrome (pid 1234)    1.2 MB       340 KB
unknown (system)     890 KB       120 KB
  └── courier.push.apple.com:443      ↓ 430 KB   Apple 推送通知
  └── 192.168.1.1:53                  ↓ 210 KB   DNS 查询 (mDNSResponder)
  └── time.apple.com:123              ↑ 120 KB   NTP 时间同步
  └── 239.255.255.250:1900            ↑  80 KB   SSDP 设备发现
  └── 17.57.144.83:443                ↓ 170 KB   Apple 服务
```

### 1.2 信息来源优先级

对同一个远端地址，按以下优先级展示：

```text
1. 反向 DNS 域名（最可读，异步获取）
2. 已知 IP 段标注（内置映射表，同步）
3. 已知端口标注（内置映射表，同步）
4. 原始 IP:port（兜底）
```

---

## 2. 架构设计

### 2.1 数据流

Unknown 流量在统计线程中正常聚合，额外维护一张按远端地址分组的连接表，供 UI 展开显示：

```text
统计线程
  ├── HashMap<ProcessKey, TrafficStats>   ← 现有，用于主列表
  └── HashMap<SocketAddr, ConnectionStats> ← 新增，Unknown 流量按远端地址分组

UI 渲染
  ├── 主列表：按进程聚合的流量
  └── Unknown 展开：按远端地址列出，附加 DNS 标注和端口描述
```

### 2.2 新增数据结构

```rust
/// Unknown 流量按远端地址分组的统计
#[derive(Default)]
pub struct ConnectionStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 反向 DNS 查询结果，None 表示尚未查询或查询中，Some(None) 表示查询失败
    pub rdns: Option<Option<String>>,
    /// 端口/IP 段标注（来自内置映射表）
    pub annotation: Option<&'static str>,
}

/// 统计线程持有的完整状态
pub struct StatsState {
    pub by_process: HashMap<ProcessKey, TrafficStats>,
    /// key 是规范化后的远端地址（仅 Unknown 流量）
    pub unknown_by_remote: HashMap<SocketAddr, ConnectionStats>,
}
```

---

## 3. 反向 DNS 解析

### 3.1 设计原则

- **完全异步**：DNS 查询不阻塞统计线程和 UI 渲染
- **结果缓存**：同一 IP 只查询一次，结果永久缓存（进程生命周期内）
- **查询去重**：同一 IP 不发起重复查询（pending 状态期间）
- **超时控制**：单次查询超时 3 秒，超时视为失败，缓存失败结果避免反复重试
- **不影响主流程**：DNS 查询失败时 UI 退化为显示原始 IP，不报错

### 3.2 实现结构

DNS 解析在独立线程池中执行，通过 channel 将结果回传给统计线程：

```text
统计线程
  ├── 发现新的 Unknown 远端 IP
  ├── 检查 dns_cache：未命中则发送查询请求
  │       ↓ dns_query_tx: Sender<IpAddr>
  └── 接收查询结果
          ↑ dns_result_rx: Receiver<(IpAddr, Option<String>)>

DNS 线程池（2个线程，tokio 或 std::thread）
  ├── 接收 dns_query_rx
  ├── 执行系统 DNS 反向查询（lookup_addr）
  └── 发送结果 dns_result_tx
```

```rust
pub struct DnsResolver {
    cache: HashMap<IpAddr, DnsState>,
    query_tx: SyncSender<IpAddr>,
    result_rx: Receiver<(IpAddr, Option<String>)>,
}

enum DnsState {
    Pending,                    // 查询已发出，等待结果
    Resolved(Option<String>),   // 查询完成，None 表示查询失败
}

impl DnsResolver {
    /// 在统计线程的主循环中调用，非阻塞
    pub fn lookup(&mut self, ip: IpAddr) -> Option<&str> {
        match self.cache.get(&ip) {
            Some(DnsState::Resolved(Some(name))) => return Some(name.as_str()),
            Some(DnsState::Resolved(None)) => return None, // 已知查询失败
            Some(DnsState::Pending) => return None,        // 查询中，暂无结果
            None => {
                // 首次遇到，发起查询
                self.cache.insert(ip, DnsState::Pending);
                let _ = self.query_tx.try_send(ip); // 非阻塞发送，失败则跳过
            }
        }
        None
    }

    /// 在统计线程的主循环中调用，收取已完成的查询结果
    pub fn collect_results(&mut self) {
        while let Ok((ip, result)) = self.result_rx.try_recv() {
            self.cache.insert(ip, DnsState::Resolved(result));
        }
    }
}
```

DNS 工作线程（每个 IP 独立线程或线程池均可，推荐固定 2 线程）：

```rust
fn dns_worker(
    query_rx: Receiver<IpAddr>,
    result_tx: SyncSender<(IpAddr, Option<String>)>,
) {
    for ip in query_rx {
        // 使用标准库的同步 DNS 反向查询
        // 在独立线程中调用，不阻塞主线程
        let result = lookup_addr_with_timeout(ip, Duration::from_secs(3));
        let _ = result_tx.send((ip, result));
    }
}

fn lookup_addr_with_timeout(ip: IpAddr, timeout: Duration) -> Option<String> {
    // std::net 没有内置超时，用线程+channel 模拟
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // 构造反向查询地址
        let socket_addr = SocketAddr::new(ip, 0);
        let result = dns_lookup::lookup_addr(&socket_addr.ip()).ok();
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout).ok().flatten()
}
```

**依赖**：使用 `dns-lookup` crate（`dns_lookup::lookup_addr`），封装了平台的系统 DNS 调用：

```toml
[dependencies]
dns-lookup = "2"
```

### 3.3 统计线程主循环集成

```rust
// 在每轮 drain channel 后调用，收取 DNS 结果并触发新查询
dns_resolver.collect_results();

for (remote_addr, conn_stats) in &mut state.unknown_by_remote {
    if conn_stats.rdns.is_none() {
        // 触发查询（幂等，重复调用只查询一次）
        let name = dns_resolver.lookup(remote_addr.ip());
        if name.is_some() {
            // 查询已完成，写入缓存
            conn_stats.rdns = Some(name.map(|s| s.to_string()));
        }
        // 查询中时 rdns 保持 None，UI 显示原始 IP
    }
}
```

---

## 4. 端口与 IP 段标注

### 4.1 内置映射表

标注数据完全内置，无需网络请求，编译时确定，查询为 O(1)。

#### 端口标注

```rust
// src/enrichment/port_annotation.rs

pub fn annotate_port(port: u16, proto: Protocol) -> Option<&'static str> {
    match (proto, port) {
        // DNS
        (_, 53)   => Some("DNS 查询"),
        (_, 5353) => Some("mDNS (mDNSResponder)"),
        // 时间同步
        (_, 123)  => Some("NTP 时间同步"),
        // 网络发现
        (_, 1900) => Some("SSDP 设备发现"),
        (_, 5355) => Some("LLMNR 名称解析"),
        // Apple 服务（端口维度，IP 段维度见下）
        (_, 4443) => Some("Apple 推送通知 (APNs)"),
        (_, 2197) => Some("Apple 推送通知 (APNs 备用)"),
        // 常见协议
        (Protocol::Tcp, 80)   => Some("HTTP"),
        (Protocol::Tcp, 443)  => Some("HTTPS"),
        (Protocol::Tcp, 22)   => Some("SSH"),
        (Protocol::Tcp, 25)   => Some("SMTP"),
        (Protocol::Tcp, 587)  => Some("SMTP (TLS)"),
        (Protocol::Tcp, 993)  => Some("IMAP (TLS)"),
        (Protocol::Tcp, 3306) => Some("MySQL"),
        (Protocol::Tcp, 5432) => Some("PostgreSQL"),
        (Protocol::Tcp, 6379) => Some("Redis"),
        (Protocol::Tcp, 27017)=> Some("MongoDB"),
        _ => None,
    }
}
```

#### IP 段标注

```rust
// src/enrichment/ip_annotation.rs

/// 按前缀长度从长到短排列，优先匹配更精确的前缀
static IP_ANNOTATIONS: &[(&str, u8, &str)] = &[
    // Apple
    ("17.0.0.0",   8,  "Apple 服务"),
    ("17.248.0.0", 16, "Apple CDN"),
    ("17.57.0.0",  16, "Apple 推送/iCloud"),
    // Google
    ("8.8.8.0",    24, "Google DNS"),
    ("8.8.4.0",    24, "Google DNS"),
    ("142.250.0.0",15, "Google 服务"),
    ("172.217.0.0",16, "Google 服务"),
    ("216.58.0.0", 16, "Google 服务"),
    // Cloudflare
    ("1.1.1.0",    24, "Cloudflare DNS"),
    ("1.0.0.0",    24, "Cloudflare DNS"),
    ("104.16.0.0", 12, "Cloudflare CDN"),
    // Akamai
    ("23.0.0.0",   8,  "Akamai CDN"),
    // Amazon AWS
    ("52.0.0.0",   8,  "Amazon AWS"),
    ("54.0.0.0",   8,  "Amazon AWS"),
    // Microsoft
    ("13.64.0.0",  11, "Microsoft Azure"),
    ("40.64.0.0",  10, "Microsoft Azure"),
    // 组播/广播
    ("224.0.0.0",  4,  "组播地址"),
    ("239.255.255.250", 32, "SSDP 组播"),
    // 本地网络
    ("192.168.0.0",16, "本地网络"),
    ("10.0.0.0",   8,  "本地网络"),
    ("172.16.0.0", 12, "本地网络"),
];

pub fn annotate_ip(ip: IpAddr) -> Option<&'static str> {
    let IpAddr::V4(ipv4) = ip else {
        return annotate_ipv6(ip);
    };
    let ip_u32 = u32::from(ipv4);

    // 从最长前缀开始匹配（精确优先）
    let mut sorted: Vec<_> = IP_ANNOTATIONS.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1)); // 按前缀长度降序

    for (prefix_str, prefix_len, label) in &sorted {
        let prefix: Ipv4Addr = prefix_str.parse().ok()?;
        let prefix_u32 = u32::from(prefix);
        let mask = if *prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
        if ip_u32 & mask == prefix_u32 & mask {
            return Some(label);
        }
    }
    None
}

fn annotate_ipv6(ip: IpAddr) -> Option<&'static str> {
    let IpAddr::V6(ipv6) = ip else { return None; };
    let segments = ipv6.segments();
    match segments {
        [0x2001, 0x4860, ..] => Some("Google 服务"),
        [0x2606, 0x4700, ..] => Some("Cloudflare CDN"),
        [0x2400, 0x cb00, ..] => Some("Cloudflare CDN"),
        [0xfe80, ..] => Some("本地链路地址"),
        [0xff02, ..] => Some("组播地址"),
        _ => None,
    }
}
```

### 4.2 组合标注逻辑

对每个远端地址，综合 IP 段和端口两个维度生成最终标注：

```rust
pub fn get_annotation(remote: SocketAddr, proto: Protocol) -> Option<String> {
    let ip_label = annotate_ip(remote.ip());
    let port_label = annotate_port(remote.port(), proto);

    match (ip_label, port_label) {
        (Some(ip), Some(port)) => Some(format!("{} · {}", ip, port)),
        (Some(ip), None)       => Some(ip.to_string()),
        (None, Some(port))     => Some(port.to_string()),
        (None, None)           => None,
    }
}
```

示例输出：

```text
17.57.144.83:443  → "Apple 推送/iCloud · HTTPS"
8.8.8.8:53        → "Google DNS · DNS 查询"
192.168.1.1:53    → "本地网络 · DNS 查询"
239.255.255.250:1900 → "SSDP 组播 · SSDP 设备发现"
```

---

## 5. UI 展示规范

### 5.1 Unknown 条目的展开格式

Unknown 条目在主列表中显示聚合流量，支持展开查看按远端地址分组的明细：

```text
unknown (system)     890 KB    120 KB     [可展开]
  └── courier.push.apple.com:443    ↓ 430 KB   Apple 推送/iCloud · HTTPS
      (查询中...)                   ↓ 210 KB   本地网络 · DNS 查询
  └── 192.168.1.1:53               ↓ 210 KB   本地网络 · DNS 查询
  └── time.apple.com:123           ↑ 120 KB   NTP 时间同步
  └── 17.57.144.83:443             ↓ 170 KB   Apple 推送/iCloud · HTTPS
```

### 5.2 展示优先级

远端地址展示时按以下优先级选择显示内容：

```text
1. 反向 DNS 域名（已解析）：courier.push.apple.com:443
2. DNS 解析中：显示原始 IP，附加"(解析中...)"标注
3. DNS 解析失败/超时：显示原始 IP + IP 段标注
4. 无任何标注：显示原始 IP:port
```

### 5.3 条目排序

Unknown 明细条目按流量（rx+tx）降序排列，只显示流量最高的前 N 条（建议 N=10），避免列表过长：

```rust
let mut entries: Vec<_> = state.unknown_by_remote.iter().collect();
entries.sort_by(|a, b| {
    let a_total = a.1.rx_bytes + a.1.tx_bytes;
    let b_total = b.1.rx_bytes + b.1.tx_bytes;
    b_total.cmp(&a_total)
});
entries.truncate(10);
```

### 5.4 Snapshot 模式输出格式

Snapshot 模式下，Unknown 明细以缩进文本形式输出：

```text
PROCESS                  RX          TX
chrome (pid 1234)        1.2 MB      340 KB
unknown (system)         890 KB      120 KB
  courier.push.apple.com:443   430 KB      0 B     Apple 推送/iCloud · HTTPS
  192.168.1.1:53                 0 B    210 KB     本地网络 · DNS 查询
  time.apple.com:123             0 B    120 KB     NTP 时间同步
  17.57.144.83:443             170 KB      0 B     Apple 推送/iCloud · HTTPS
  (6 more connections...)
```

---

## 6. 平台差异

| | macOS（普通用户） | Linux（cap_sys_ptrace） |
|---|---|---|
| 触发场景 | 系统守护进程流量 | 几乎不触发 |
| Unknown 流量占比 | 较高（系统后台噪声） | 极低（仅极短生命周期进程） |
| 信息增强价值 | 高 | 低，作为兜底保留 |

Linux 上 Unknown 流量主要来自生命周期短于 500ms 的进程（见 0.2.0 设计文档），数量极少，信息增强功能对 Linux 用户基本透明。

---

## 7. 实现顺序建议

1. 先实现端口/IP 段标注（同步，无依赖，容易验证）
2. 再实现 Unknown 流量按远端地址分组的统计
3. 最后接入反向 DNS 异步解析（涉及线程间通信，复杂度最高）
4. UI 展示可以在第2步完成后就开始，DNS 结果通过刷新逐步填入

---

## 8. 不在本文档范围内

- GeoIP 地理位置标注（国家/城市，需要额外数据库，后续版本考虑）
- 主动探测端口服务（banner grabbing，不符合监控工具定位）
- DNS 缓存持久化（跨会话，当前版本仅内存缓存）
