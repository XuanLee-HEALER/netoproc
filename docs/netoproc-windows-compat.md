# netoproc Windows Compatibility Design Document

> v0.5.0 goal: Add Windows support on top of the existing macOS + Linux cfg module-switching architecture.

**Current version**: v0.4.0 (macOS + Linux)
**Target version**: v0.5.0 (macOS + Linux + Windows)

---

## 1. Overall Strategy

### 1.1 Scope of Changes

Extending the v0.4.0 `#[cfg(target_os)]` module-switching pattern with `target_os = "windows"` branches.
Each existing platform abstraction point gains a Windows implementation module, exporting the same public function signatures.

Modules requiring new Windows implementations:

| Module | macOS | Linux | Windows |
|------|-------|-------|---------|
| Packet capture | BPF `/dev/bpf*` | AF_PACKET socket | Raw socket + SIO_RCVALL |
| Process attribution | libproc | /proc/net/tcp + /proc/fd | GetExtendedTcpTable/UdpTable |
| Connection state | sysctl pcblist_n | /proc/net/tcp[6] | GetExtendedTcpTable |
| Process enumeration | libproc (proc_listpids) | /proc/<pid>/stat | CreateToolhelp32Snapshot |
| Interface info | getifaddrs + AF_LINK | getifaddrs + AF_PACKET | GetAdaptersAddresses |
| DNS configuration | SystemConfiguration | /etc/resolv.conf | GetAdaptersAddresses DNS fields |
| Privilege check | getuid + /dev/bpf0 access | getuid + AF_PACKET test | IsUserAnAdmin / raw socket test |
| Signal handling | signal(SIGTERM/SIGINT) | signal(SIGTERM/SIGINT) | SetConsoleCtrlHandler |

Code not requiring changes (~95%):
- `PacketSummary` / `SocketKey` / `TrafficStats` data structures
- Shared IP/TCP/UDP/DNS packet parsing (packet.rs, dns.rs)
- Channel model and three-thread architecture
- TUI rendering layer (ratatui + crossterm natively support Windows)
- Snapshot / monitor mode logic
- Enrichment (dns_resolver.rs uses dns-lookup crate, cross-platform)

### 1.2 Directory Structure Changes

```
src/
├── capture/
│   ├── mod.rs          ← add #[cfg(target_os = "windows")] routing
│   ├── macos.rs
│   ├── linux.rs
│   └── windows.rs      ← new: RawSocketCapture
├── process/
│   ├── mod.rs          ← add #[cfg(target_os = "windows")] routing
│   ├── macos.rs
│   ├── linux.rs
│   └── windows.rs      ← new: GetExtendedTcpTable + GetExtendedUdpTable
├── system/
│   ├── process.rs      ← add #[cfg(target_os = "windows")] section
│   ├── connection.rs   ← add #[cfg(target_os = "windows")] section
│   ├── interface.rs    ← add #[cfg(target_os = "windows")] section
│   └── dns_config.rs   ← add #[cfg(target_os = "windows")] section
├── main.rs             ← signal handling, interface discovery Windows branch
└── error.rs            ← add WinApi error variant
```

### 1.3 Dependency Changes

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

### 1.4 Cross-Compilation Verification

```bash
# Install cross
cargo install cross

# Verify Windows GNU target compiles
cross build --target x86_64-pc-windows-gnu

# Also verify macOS/Linux are unaffected
cargo check  # current platform
```

---

## 2. PacketCapture

### 2.1 Windows Approach: Raw Socket + SIO_RCVALL

Windows has neither BPF nor AF_PACKET. Uses Winsock2 raw sockets:

```
socket(AF_INET, SOCK_RAW, IPPROTO_IP)
→ bind(interface_ip)
→ WSAIoctl(SIO_RCVALL, RCVALL_ON)  // receive all IP packets
→ recv() returns complete IP packets (no Ethernet header)
```

**Key differences**:
- Receives raw IP packets (no Ethernet header), parsed via `packet::parse_raw_frame()`
- Each socket binds to an interface IP (not interface name)
- Requires Administrator privileges
- IPv4 and IPv6 need separate AF_INET/AF_INET6 sockets

**Filtering strategy**:
- macOS/Linux use hardware BPF filters at the kernel level
- Windows performs software filtering in userspace (slightly lower performance, acceptable for a monitoring tool)
- Traffic capture: keep only TCP/UDP/ICMP packets
- DNS capture: keep only port 53 packets

### 2.2 Exported API (consistent with macOS/Linux)

```rust
pub type PlatformCapture = RawSocketCapture;
pub struct CaptureStats { pub received: u32, pub dropped: u32 }
pub fn check_capture_access() -> Result<(), NetopError>
pub fn open_capture_devices(...) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError>
pub fn capture_stats(cap: &PlatformCapture) -> Option<CaptureStats>
```

PlatformCapture methods:
- `read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError>`
- `read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError>`
- `interface(&self) -> &str`

### 2.3 Known Limitations

- SIO_RCVALL may be restricted on some Windows editions (e.g., Home Edition)
- Outbound packet capture may be incomplete (depends on Windows version and network driver)
- Cannot capture both IPv4 and IPv6 on a single socket (requires two sockets)
- This implementation supports IPv4 capture first; IPv6 can be extended later

---

## 3. ProcessTable (Process Attribution)

### 3.1 Windows Approach: IP Helper API

Windows provides more direct socket-to-PID mapping than Linux/macOS:

```
GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)
  → MIB_TCPTABLE_OWNER_PID → each row contains (local_addr, local_port, remote_addr, remote_port, state, owning_pid)

GetExtendedUdpTable(UDP_TABLE_OWNER_PID)
  → MIB_UDPTABLE_OWNER_PID → each row contains (local_addr, local_port, owning_pid)
```

No need for the Linux three-step correlation (inode → fd → pid); Windows directly provides the PID.

Process names are obtained via `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` (Wide API for Unicode support).

### 3.2 TCP State Mapping

Windows MIB_TCP_STATE enum values:
```
1=CLOSED, 2=LISTEN, 3=SYN_SENT, 4=SYN_RCVD,
5=ESTAB, 6=FIN_WAIT1, 7=FIN_WAIT2, 8=CLOSE_WAIT,
9=CLOSING, 10=LAST_ACK, 11=TIME_WAIT, 12=DELETE_TCB
```

---

## 4. System API Implementations

### 4.1 system/interface.rs

Uses `GetAdaptersAddresses(AF_UNSPEC)` instead of `getifaddrs`:
- Returns `IP_ADAPTER_ADDRESSES` linked list
- Contains IPv4/IPv6 addresses, DNS servers, interface status
- Interface statistics via `GetIfEntry2` (byte/packet counters)

### 4.2 system/dns_config.rs

DNS configuration extracted from `GetAdaptersAddresses` `FirstDnsServerAddress` linked list.

### 4.3 system/process.rs

Process enumeration uses `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32FirstW/NextW`.

### 4.4 system/connection.rs

TCP/UDP connections via `GetExtendedTcpTable`/`GetExtendedUdpTable`.

---

## 5. main.rs Changes

### 5.1 Signal Handling

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

### 5.2 Interface Discovery

Windows does not use `libc::IFF_UP`/`libc::IFF_LOOPBACK`.
`RawInterface` has `is_loopback()` method, with platform-specific flag constants:
`FLAG_UP = 0x1`, `FLAG_LOOPBACK = 0x8`.

---

## 6. Verification Plan

### 6.1 Compilation Verification (using cross on Linux)

```bash
cross build --target x86_64-pc-windows-gnu
```

### 6.2 Runtime Test Checklist (requires Windows environment)

- [ ] Raw socket can be created normally (requires Administrator)
- [ ] SIO_RCVALL captures IP packets after enable
- [ ] IPv4 packet parsing is correct (using parse_raw_frame)
- [ ] GetExtendedTcpTable returns correct connections and PIDs
- [ ] Process names correctly obtained via CreateToolhelp32Snapshot
- [ ] GetAdaptersAddresses returns interface information
- [ ] TUI renders correctly in Windows Terminal
- [ ] Ctrl-C triggers graceful shutdown
