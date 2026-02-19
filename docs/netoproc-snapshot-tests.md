# Snapshot 子命令集成测试用例

基于实际代码逻辑分析，覆盖 `netop snapshot` 从 main() 入口到 stdout 输出的完整链路。

## 执行链路总览

```
main()
  → env_logger::init()
  → catch_unwind(run)
  → 恢复终端状态（disable_raw_mode + LeaveAlternateScreen）
  → exit code 映射

run()
  → Cli::parse()                          [cli.rs]
  → privilege::check_root()               [privilege.rs] — getuid() == 0
  → discover_interfaces(&cli)             [main.rs] — list_interfaces() + 过滤
  → privilege::open_bpf_devices()         [privilege.rs] — 打开 /dev/bpfN
  → state::new_shared_state()             [state/mod.rs] — ArcSwap<empty>
  → 创建 channels (pkt 8192, dns 1024, shutdown 0)
  → spawn BPF capture threads             [main.rs bpf_capture_loop]
  → spawn DNS capture thread              [main.rs dns_capture_loop] ← 当前不工作
  → drop(pkt_tx), drop(dns_tx)
  → spawn poller thread                   [main.rs poller_loop]
  → snapshot 分支: sleep(interval) → shared_state.load() → output::write_snapshot()
  → shutdown: drop(shutdown_tx/rx)
  → join threads                          ← 当前会死锁
  → 返回 Result
```

---

## 一、入口与 CLI 解析

### TC-1.1 snapshot 子命令基本调用
- **输入**: `sudo netop snapshot`
- **预期**: 进程正常退出（exit 0），stdout 有 TSV 输出，stderr 无内容
- **验证点**: 退出码为 0；stdout 非空且包含 `# processes` 等段头

### TC-1.2 snapshot 加 --format json
- **输入**: `sudo netop snapshot --format json`
- **预期**: stdout 输出合法 JSON，可被 `jq .` 解析
- **验证点**: `jq .` 返回 0；JSON 包含 `timestamp`、`processes`、`interfaces`、`dns` 顶级字段

### TC-1.3 snapshot 加 --format tsv（显式）
- **输入**: `sudo netop snapshot --format tsv`
- **预期**: 与 TC-1.1 相同

### TC-1.4 snapshot 加 --interval 参数
- **输入**: `sudo netop snapshot --interval 0.5`
- **预期**: 约 0.5 秒后产出输出并退出（容忍 ±0.3 秒）
- **验证点**: 用 `time` 命令测量总执行时间在 0.2-0.8 秒范围内

### TC-1.5 snapshot 加 --interface 指定接口
- **输入**: `sudo netop snapshot --interface en0`
- **预期**: 正常退出；interfaces 段只包含 en0

### TC-1.6 snapshot 加 --no-dns
- **输入**: `sudo netop snapshot --no-dns`
- **预期**: 正常退出；dns_resolvers 和 dns_queries 段无数据行（只有段头和列头）

### TC-1.7 snapshot 加 --bpf-buffer
- **输入**: `sudo netop snapshot --bpf-buffer 65536`
- **预期**: 正常退出

### TC-1.8 snapshot 加 --filter
- **输入**: `sudo netop snapshot --filter curl`
- **预期**: 正常退出
- **备注**: 当前代码中 snapshot 分支未使用 filter 参数过滤输出，此测试记录当前行为

---

## 二、权限检查链路

### TC-2.1 非 root 运行
- **输入**: `netop snapshot`（不加 sudo）
- **预期**: stderr 输出含 "root privileges"；exit code = 1
- **验证点**: exit code 精确等于 1（对应 NetopError::NotRoot → exit_code 映射）

### TC-2.2 root 运行
- **输入**: `sudo netop snapshot`
- **预期**: 不因权限检查失败；继续执行后续链路
- **代码路径**: `privilege::check_root()` → `libc::getuid() == 0` → Ok(())

---

## 三、接口发现链路

### TC-3.1 自动发现接口
- **输入**: `sudo netop snapshot`（不指定 --interface）
- **预期**: discover_interfaces 返回非空列表（至少有 en0 或 utun 等活跃接口）
- **验证点**: interfaces 段有至少一行数据

### TC-3.2 指定存在的接口
- **输入**: `sudo netop snapshot --interface en0`
- **预期**: 只监听 en0；interfaces 段可能包含多个接口（因 poll_system 不过滤），但 BPF 仅绑定 en0
- **代码路径**: `discover_interfaces` 跳过自动发现，返回 `vec!["en0"]`

### TC-3.3 指定不存在的接口
- **输入**: `sudo netop snapshot --interface nonexist99`
- **预期**: BPF BIOCSETIF ioctl 失败；exit code = 2（NetopError::BpfDevice）
- **验证点**: stderr 含 "BIOCSETIF" 或 "BPF"

### TC-3.4 无活跃接口场景
- **前置**: （难以在真实环境复现，记录为已知逻辑路径）
- **代码路径**: `discover_interfaces` 返回空 vec → `NetopError::Fatal("no network interfaces found")` → exit 4

---

## 四、BPF 设备打开链路

### TC-4.1 正常打开 BPF 设备
- **前置**: 以 root 运行
- **预期**: `privilege::open_bpf_devices` 成功返回 traffic_captures 和 dns_capture
- **代码路径**: `open_bpf_device()` 遍历 /dev/bpf0..255，BIOCSBLEN → BIOCSETIF → BIOCIMMEDIATE → BIOCSETF → BIOCPROMISC → BIOCGBLEN

### TC-4.2 所有 BPF 设备被占用
- **前置**: 大量进程占用 /dev/bpfN
- **预期**: "all BPF devices are busy" → exit 2
- **备注**: 实际环境难以触发（macOS 通常有 256 个 BPF 设备）

### TC-4.3 traffic_captures 为空
- **代码路径**: `traffic_captures.is_empty()` → `NetopError::BpfDevice("failed to open any BPF devices")` → exit 2

---

## 五、线程启动与数据流链路

### TC-5.1 BPF capture 线程能正常启动
- **验证方式**: snapshot 正常退出即说明线程成功启动
- **代码路径**: `thread::Builder::new().name("netop-bpf").spawn(bpf_capture_loop)`

### TC-5.2 DNS capture 线程启动（dns_enabled = true）
- **输入**: `sudo netop snapshot`（默认 --no-dns 为 false）
- **代码路径**: `dns_capture` 为 Some → spawn "netop-dns" 线程
- **已知问题**: dns_capture_loop 不实际解析 DNS 报文（line 217: `let _ = pkt;`），dns_tx channel 永远不发送

### TC-5.3 DNS capture 线程不启动（--no-dns）
- **输入**: `sudo netop snapshot --no-dns`
- **代码路径**: `dns_capture` 为 None → 不 spawn DNS 线程

### TC-5.4 poller 线程能正常启动并至少执行一次
- **已知问题 — 竞态**: snapshot 分支 `thread::sleep(interval)` 后读取 state，但 poller 使用 `crossbeam_channel::tick(interval)` 定时。两者独立计时，poller 可能在 snapshot 读取 state 时还未完成第一次 poll。
- **影响**: snapshot 可能输出 `SystemNetworkState::empty()` —— 全空数据
- **测试方法**: 运行 `sudo netop snapshot --interval 2`，检查 interfaces 段是否有数据。如果偶尔全空则证实竞态。

---

## 六、数据采集与合并链路

### TC-6.1 system::poll_system() 能正常采集数据
- **代码路径**: `poll_system()` → `process::list_processes()` + `connection::list_tcp_connections()` + `connection::list_udp_connections()` + `interface::list_interfaces()` + `dns_config::list_dns_resolvers()`
- **验证点**: poller_loop 不因 system poll 错误而退出（错误时 log::warn 然后 continue）

### TC-6.2 merge_into_state 正确合并数据
- **代码路径**: `merge::merge_into_state()` → `correlation::correlate()`
- **验证点**: 合并后的 state 包含进程、接口、DNS resolver 数据

### TC-6.3 接口数据在 snapshot 中可见
- **输入**: `sudo netop snapshot`
- **预期**: interfaces 段包含至少一个 status=up 的接口，有 rx/tx 字节数
- **验证字段**: name、status、rx_bytes_total、tx_bytes_total

### TC-6.4 进程数据在 snapshot 中可见
- **输入**: 启动 `nc -l 9999 &` 后运行 `sudo netop snapshot`
- **预期**: processes 段包含 nc 进程（pid、name=nc）
- **备注**: 是否有 socket/connection 信息取决于 libproc 能否在 snapshot 时间窗口内枚举到

### TC-6.5 DNS resolver 数据在 snapshot 中可见
- **输入**: `sudo netop snapshot`
- **预期**: dns_resolvers 段包含系统配置的 DNS 服务器（如 8.8.8.8 或路由器地址）
- **备注**: dns_config::list_dns_resolvers() 使用 SystemConfiguration framework；如果查询失败则 unwrap_or_default() 返回空

---

## 七、输出序列化链路

### TC-7.1 TSV 输出结构完整性
- **输入**: `sudo netop snapshot --format tsv`
- **预期**: 输出包含 6 个段，每个段有 `# section_name` 注释行 + 列头行 + 数据行
- **段名**: processes, sockets, connections, interfaces, dns_resolvers, dns_queries
- **验证点**:
  - 6 个 `#` 开头的段头
  - 段之间有空行分隔（5 个空行）
  - 每段的列头行和数据行列数一致

### TC-7.2 TSV 列数一致性
- **输入**: `sudo netop snapshot`
- **验证方法**: 用 awk 验证每段内所有行的 tab 分隔字段数一致
  ```bash
  sudo netop snapshot | awk -F'\t' '/^#/{n=0;next} /^$/{next} {n++; if(n==1){cols=NF} else if(NF!=cols){print "MISMATCH line "NR": "NF" vs "cols}}'
  ```

### TC-7.3 TSV 无 ANSI 转义码
- **输入**: `sudo netop snapshot`
- **验证方法**: `sudo netop snapshot | grep -P '\x1b' | wc -l` 应为 0

### TC-7.4 JSON 输出为合法 JSON
- **输入**: `sudo netop snapshot --format json`
- **验证方法**: `sudo netop snapshot --format json | python3 -m json.tool > /dev/null`

### TC-7.5 JSON 顶级结构
- **输入**: `sudo netop snapshot --format json`
- **预期**: 顶级对象包含 `timestamp`（数字）、`processes`（数组）、`interfaces`（数组）、`dns`（对象含 resolvers 和 queries 数组）

### TC-7.6 JSON 数值类型正确
- **输入**: `sudo netop snapshot --format json`
- **验证方法**: `jq '.processes[0].pid | type'` 应返回 `"number"`（如果有进程）

### TC-7.7 TSV 输出到管道
- **输入**: `sudo netop snapshot | head -1`
- **预期**: 第一行是 `# processes`
- **目的**: 验证 stdout 是正常的文本流，pipe 不影响输出

### TC-7.8 JSON 输出到文件
- **输入**: `sudo netop snapshot --format json > /tmp/netop_test.json && jq . /tmp/netop_test.json`
- **预期**: 文件可被 jq 正常解析

---

## 八、关机/退出链路

### TC-8.1 snapshot 正常退出不挂起 (CRITICAL)
- **输入**: `sudo timeout 10 netop snapshot --interval 1`
- **预期**: 在 ~2 秒内正常退出（interval + 少量开销）
- **已知 BUG**: 当前代码会死锁，原因链：
  1. `bpf_capture_loop` 中 `cap.read_packets()` 调用 `libc::read()` 阻塞
  2. shutdown 信号通过 `drop(shutdown_tx)` 发出
  3. `shutdown.try_recv().is_ok()` 检查的是 Ok 值，但 sender 被 drop 后 try_recv 返回 `Err(Disconnected)` —— is_ok() 为 false
  4. 即使 shutdown 信号检测逻辑正确，BPF read 阻塞时也无法检查 shutdown
  5. `main thread → join(bpf_handles)` 永远等待 → 进程挂死

### TC-8.2 SIGTERM 终止
- **输入**:
  ```bash
  sudo netop snapshot --interval 5 &
  PID=$!
  sleep 1
  kill -TERM $PID
  wait $PID
  ```
- **预期**: 进程在收到 SIGTERM 后立即退出
- **已知 BUG**: 无 signal handler，SIGTERM 的默认行为是终止进程（不清理），但如果线程在阻塞 I/O 中，进程可能不响应

### TC-8.3 SIGINT 终止 (Ctrl-C)
- **输入**: 同 TC-8.2 但用 `kill -INT`
- **预期**: 同 TC-8.2

### TC-8.4 终端状态恢复
- **输入**: 运行 snapshot 后检查终端是否正常
- **预期**: `stty -a` 显示终端仍在正常模式（非 raw mode）
- **代码路径**: `catch_unwind` 后总是执行 `disable_raw_mode()` + `LeaveAlternateScreen`
- **备注**: snapshot 模式不进入 alternate screen，所以这些调用是无害的 no-op

### TC-8.5 panic 时终端恢复
- **代码路径**: `catch_unwind(run)` → Err(panic) → 恢复终端 → exit 4
- **备注**: 此路径不易触发，但逻辑正确

---

## 九、Exit Code 映射

### TC-9.1 成功退出
- **输入**: `sudo netop snapshot`
- **预期**: exit code = 0

### TC-9.2 非 root 退出
- **输入**: `netop snapshot`（不加 sudo）
- **预期**: exit code = 1

### TC-9.3 BPF 设备错误退出
- **输入**: `sudo netop snapshot --interface nonexist99`
- **预期**: exit code = 2

### TC-9.4 panic 退出
- **预期**: exit code = 4
- **代码路径**: catch_unwind Err → exit(4)

---

## 十、已知 BUG 清单

以下 BUG 在代码审查中确认，应在修复后将对应测试用例从"失败"变为"通过"：

### BUG-1: Snapshot 死锁（严重）
- **位置**: `src/main.rs:148-150` (join handles)
- **根因**: BPF 线程阻塞在 `libc::read()` 中，shutdown 信号无法中断。同时 shutdown 检测逻辑错误（`try_recv().is_ok()` 无法检测到 sender drop）。
- **影响**: snapshot 完成输出后进程无限挂起
- **关联测试**: TC-8.1

### BUG-2: Shutdown 信号检测逻辑错误（严重）
- **位置**: `src/main.rs:182` (`shutdown.try_recv().is_ok()`)
- **根因**: shutdown channel 是 `bounded(0)`（rendezvous channel）。shutdown 信号通过 `drop(shutdown_tx)` 发出。`try_recv()` 在 sender 被 drop 后返回 `Err(TryRecvError::Disconnected)`，而 `is_ok()` 判断为 false。
- **修复方向**: 应检查 `try_recv() == Err(Disconnected)` 也作为退出条件：
  ```rust
  match shutdown.try_recv() {
      Ok(()) | Err(TryRecvError::Disconnected) => return,
      Err(TryRecvError::Empty) => {} // 继续
  }
  ```

### BUG-3: BPF 阻塞读取无超时（严重）
- **位置**: `src/bpf/mod.rs:122-128` (`libc::read()`)
- **根因**: `libc::read()` 是阻塞调用，在没有网络流量时会无限阻塞。即使 shutdown 信号检测正确，线程也无法及时响应。
- **修复方向**: 使用 `poll()`/`select()` 加超时包裹 `read()`，或设置 BPF 设备的 read timeout（BIOCSRTIMEOUT ioctl）。

### BUG-4: dns_capture_loop 不工作（中等）
- **位置**: `src/main.rs:204-231`
- **根因**:
  - Line 217: `let _ = pkt;` — 丢弃所有解析出的 PacketSummary，不提取 DNS payload
  - Line 229: `let _ = tx;` — 仅保持 channel alive，从不发送 DnsMessage
  - `BpfCapture::extract_dns_payload()` 存在但从未在 dns_capture_loop 中被调用
- **影响**: dns_queries 段永远为空

### BUG-5: Poller 与 Snapshot 竞态（中等）
- **位置**: `src/main.rs:127-129`
- **根因**: snapshot 分支 `thread::sleep(interval)` 与 poller 的 `crossbeam_channel::tick(interval)` 独立计时。poller 可能在 snapshot 读取 state 时还未完成第一次 merge。
- **影响**: snapshot 可能输出空状态（SystemNetworkState::empty()）
- **修复方向**: snapshot 应等待 poller 至少完成一次更新，或直接在主线程同步执行一次 poll+merge

### BUG-6: 无信号处理（中等）
- **位置**: main.rs 全局
- **根因**: 没有 SIGTERM/SIGINT handler。结合 BUG-1 的死锁，用户无法优雅终止进程。
- **修复方向**: 安装 signal handler，在收到 SIGTERM/SIGINT 时关闭 BPF fd 或设置退出标志

---

## 十一、测试执行环境要求

- **操作系统**: macOS 26.0+
- **权限**: 大部分测试需要 sudo（BPF 设备需要 root）
- **网络**: 至少一个活跃的非 loopback 网络接口（通常 en0）
- **工具**: jq、awk、timeout（或 gtimeout from coreutils）、python3
- **注意**: TC-8.1 在当前代码下会挂起，需用 `timeout` 命令包裹

---

## 十二、测试优先级

| 优先级 | 测试编号 | 说明 |
|--------|---------|------|
| P0 (必须先修) | TC-8.1 | 死锁问题，当前 snapshot 无法正常退出 |
| P0 | TC-8.2, TC-8.3 | 信号处理，保底退出机制 |
| P1 | TC-1.1, TC-1.2 | 基本功能验证 |
| P1 | TC-2.1, TC-2.2 | 权限检查 |
| P1 | TC-9.1-9.3 | Exit code 正确性 |
| P2 | TC-3.1-3.3 | 接口发现 |
| P2 | TC-7.1-7.8 | 输出格式验证 |
| P2 | TC-5.4 | 竞态问题 |
| P3 | TC-1.4-1.8 | 各种 CLI 参数组合 |
| P3 | TC-6.3-6.5 | 数据内容验证 |
