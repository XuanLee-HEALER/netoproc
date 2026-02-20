// Windows capture implementation — Raw sockets with SIO_RCVALL.
//
// Windows does not have BPF or AF_PACKET. Instead, we use Winsock2 raw sockets
// with SIO_RCVALL to capture all IP traffic on a bound interface.
//
// Key differences from macOS/Linux:
// - Receives raw IP packets (no Ethernet header) → uses parse_raw_frame()
// - Each socket is bound to an interface IP (not interface name)
// - Software-level filtering (no kernel BPF)
// - Requires Administrator privileges

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use windows_sys::Win32::Networking::WinSock::{
    self as ws, AF_INET, FIONBIO, INVALID_SOCKET, IPPROTO_IP, RCVALL_ON, SIO_RCVALL, SO_RCVTIMEO,
    SOCK_RAW, SOCKET, SOCKET_ERROR, SOL_SOCKET, WSA_FLAG_OVERLAPPED, WSADATA,
};

use crate::dns::DnsMessage;
use crate::error::NetopError;
use crate::packet::{self, PacketSummary};

use super::FilterKind;

// ---------------------------------------------------------------------------
// WSA initialization (one-time global)
// ---------------------------------------------------------------------------

static WSA_INIT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();

fn ensure_wsa_init() -> Result<(), NetopError> {
    let result = WSA_INIT.get_or_init(|| {
        let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
        let ret = unsafe { ws::WSAStartup(0x0202, &mut wsa_data) };
        if ret != 0 {
            Err(format!("WSAStartup failed with error: {ret}"))
        } else {
            Ok(())
        }
    });
    result.clone().map_err(NetopError::WinApi)
}

/// Clean up Winsock resources. Call once during process shutdown.
///
/// Only has effect if `ensure_wsa_init()` succeeded. Safe to call
/// multiple times (only the first call after init has effect).
pub fn wsa_cleanup() {
    if let Some(Ok(())) = WSA_INIT.get() {
        unsafe { ws::WSACleanup() };
    }
}

// ---------------------------------------------------------------------------
// RawSocketCapture
// ---------------------------------------------------------------------------

/// Raw socket capture device for Windows.
///
/// Uses `SIO_RCVALL` to capture all IP traffic on the bound interface.
/// Receives raw IP packets (no Ethernet header), parsed via `parse_raw_frame`.
pub struct RawSocketCapture {
    socket: SOCKET,
    buffer: Vec<u8>,
    interface: String,
    _local_ips: HashSet<IpAddr>,
}

// SAFETY: `SOCKET` is `usize` on Windows (a kernel handle), which is
// inherently `Send`. The remaining fields (`Vec<u8>`, `String`,
// `HashSet<IpAddr>`) are all `Send`. The socket handle is only used via
// `recv`/`closesocket` which are thread-safe Windows APIs.
unsafe impl Send for RawSocketCapture {}

pub type PlatformCapture = RawSocketCapture;

/// Statistics from a capture device (Windows — limited stats available).
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    pub received: u32,
    pub dropped: u32,
}

impl RawSocketCapture {
    /// Create a new raw socket capture device bound to `interface_ip`.
    ///
    /// On Windows, capture devices are bound to an interface IP address
    /// rather than an interface name.
    pub fn new(
        interface_name: &str,
        interface_ip: Ipv4Addr,
        buffer_size: u32,
        _filter_kind: FilterKind,
        local_ips: HashSet<IpAddr>,
    ) -> Result<Self, NetopError> {
        ensure_wsa_init()?;

        // 1. Create raw socket
        let socket = unsafe {
            ws::WSASocketW(
                AF_INET as i32,
                SOCK_RAW,
                IPPROTO_IP,
                std::ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED,
            )
        };
        if socket == INVALID_SOCKET {
            let err = unsafe { ws::WSAGetLastError() };
            return Err(NetopError::CaptureDevice(format!(
                "WSASocket(SOCK_RAW) failed: WSA error {err}"
            )));
        }

        // 2. Bind to interface IP
        let addr = ws::SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: ws::IN_ADDR {
                S_un: ws::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(interface_ip.octets()),
                },
            },
            sin_zero: [0; 8],
        };

        let ret = unsafe {
            ws::bind(
                socket,
                &addr as *const ws::SOCKADDR_IN as *const ws::SOCKADDR,
                std::mem::size_of::<ws::SOCKADDR_IN>() as i32,
            )
        };
        if ret == SOCKET_ERROR {
            let err = unsafe { ws::WSAGetLastError() };
            unsafe { ws::closesocket(socket) };
            return Err(NetopError::CaptureDevice(format!(
                "bind({interface_ip}) failed: WSA error {err}"
            )));
        }

        // 3. Enable SIO_RCVALL (promiscuous mode for raw sockets)
        let mut rcvall_value: u32 = RCVALL_ON as u32;
        let mut bytes_returned: u32 = 0;
        let ret = unsafe {
            ws::WSAIoctl(
                socket,
                SIO_RCVALL,
                &mut rcvall_value as *mut u32 as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if ret == SOCKET_ERROR {
            let err = unsafe { ws::WSAGetLastError() };
            unsafe { ws::closesocket(socket) };
            return Err(NetopError::CaptureDevice(format!(
                "WSAIoctl(SIO_RCVALL) failed: WSA error {err}. \
                 Ensure you are running as Administrator."
            )));
        }

        // 4. Set receive timeout (500ms)
        let timeout: u32 = 500; // milliseconds on Windows
        let ret = unsafe {
            ws::setsockopt(
                socket,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if ret == SOCKET_ERROR {
            log::warn!(
                "SO_RCVTIMEO failed on {}: WSA error {}",
                interface_name,
                unsafe { ws::WSAGetLastError() }
            );
        }

        let buffer = vec![0u8; buffer_size.max(65536) as usize];

        log::info!(
            "Raw socket capture on {} (ip={}, buffer={})",
            interface_name,
            interface_ip,
            buffer.len()
        );

        Ok(Self {
            socket,
            buffer,
            interface: interface_name.to_string(),
            _local_ips: local_ips,
        })
    }

    /// Blocking read of packets, returning raw byte count.
    ///
    /// Receives IP packets (no Ethernet header) and parses them using
    /// `parse_raw_frame`. Software-level filtering is applied based on
    /// the configured `FilterKind`.
    pub fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError> {
        out.clear();
        let mut total_bytes = 0usize;

        // First read: blocking (waits for data or timeout)
        let n = unsafe {
            ws::recv(
                self.socket,
                self.buffer.as_mut_ptr(),
                self.buffer.len() as i32,
                0,
            )
        };

        if n == SOCKET_ERROR {
            let err = unsafe { ws::WSAGetLastError() };
            // WSAETIMEDOUT (10060) or WSAEWOULDBLOCK (10035) = timeout
            if err == 10060 || err == 10035 {
                return Ok(0);
            }
            return Err(NetopError::CaptureDevice(format!(
                "recv on {} failed: WSA error {err}",
                self.interface
            )));
        }

        if n > 0 {
            let data = &self.buffer[..n as usize];
            total_bytes += n as usize;
            if self.matches_traffic_filter(data)
                && let Some(pkt) = packet::parse_raw_frame(data)
            {
                out.push(pkt);
            }
        }

        // Set non-blocking for drain loop
        let mut nonblock: u32 = 1;
        unsafe { ws::ioctlsocket(self.socket, FIONBIO, &mut nonblock) };

        // Drain additional pending packets (non-blocking)
        loop {
            let n = unsafe {
                ws::recv(
                    self.socket,
                    self.buffer.as_mut_ptr(),
                    self.buffer.len() as i32,
                    0,
                )
            };

            if n <= 0 {
                break;
            }

            total_bytes += n as usize;
            let data = &self.buffer[..n as usize];
            if self.matches_traffic_filter(data)
                && let Some(pkt) = packet::parse_raw_frame(data)
            {
                out.push(pkt);
            }
        }

        // Restore blocking mode
        nonblock = 0;
        unsafe { ws::ioctlsocket(self.socket, FIONBIO, &mut nonblock) };

        Ok(total_bytes)
    }

    /// Read packets and extract DNS messages (port 53 traffic).
    pub fn read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError> {
        let mut messages = Vec::new();

        let n = unsafe {
            ws::recv(
                self.socket,
                self.buffer.as_mut_ptr(),
                self.buffer.len() as i32,
                0,
            )
        };

        if n == SOCKET_ERROR {
            let err = unsafe { ws::WSAGetLastError() };
            if err == 10060 || err == 10035 {
                return Ok(messages);
            }
            return Err(NetopError::CaptureDevice(format!(
                "recv on {} failed: WSA error {err}",
                self.interface
            )));
        }

        if n > 0 {
            let data = &self.buffer[..n as usize];
            if let Some(dns_payload) = self.extract_dns_payload(data) {
                match crate::dns::parse_dns(dns_payload) {
                    Ok(msg) => messages.push(msg),
                    Err(e) => log::debug!("DNS parse error: {e}"),
                }
            }
        }

        // Set non-blocking for drain loop
        let mut nonblock: u32 = 1;
        unsafe { ws::ioctlsocket(self.socket, FIONBIO, &mut nonblock) };

        // Drain additional pending packets (non-blocking)
        loop {
            let n = unsafe {
                ws::recv(
                    self.socket,
                    self.buffer.as_mut_ptr(),
                    self.buffer.len() as i32,
                    0,
                )
            };

            if n <= 0 {
                break;
            }

            let data = &self.buffer[..n as usize];
            if let Some(dns_payload) = self.extract_dns_payload(data) {
                match crate::dns::parse_dns(dns_payload) {
                    Ok(msg) => messages.push(msg),
                    Err(e) => log::debug!("DNS parse error: {e}"),
                }
            }
        }

        // Restore blocking mode
        nonblock = 0;
        unsafe { ws::ioctlsocket(self.socket, FIONBIO, &mut nonblock) };

        Ok(messages)
    }

    /// Returns the interface name this capture is bound to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Software-level traffic filter: accept only TCP/UDP/ICMP.
    fn matches_traffic_filter(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                if data.len() < 20 {
                    return false;
                }
                let proto = data[9];
                matches!(proto, 6 | 17 | 1) // TCP, UDP, ICMP
            }
            6 => {
                if data.len() < 40 {
                    return false;
                }
                let next_hdr = data[6];
                // Skip extension headers to find the actual transport protocol
                let (final_proto, _) = packet::skip_ipv6_extension_headers(next_hdr, &data[40..]);
                matches!(final_proto, 6 | 17 | 58) // TCP, UDP, ICMPv6
            }
            _ => false,
        }
    }

    /// Extract DNS payload from a raw IP packet (port 53 UDP/TCP).
    fn extract_dns_payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.is_empty() {
            return None;
        }
        let version = data[0] >> 4;
        let (ip_hdr_len, protocol) = match version {
            4 => {
                if data.len() < 20 {
                    return None;
                }
                let ihl = (data[0] & 0x0F) as usize * 4;
                let proto = data[9];
                (ihl, proto)
            }
            6 => {
                if data.len() < 40 {
                    return None;
                }
                let next_hdr = data[6];
                let (final_proto, ext_offset) =
                    packet::skip_ipv6_extension_headers(next_hdr, &data[40..]);
                (40 + ext_offset, final_proto)
            }
            _ => return None,
        };

        let l4_start = ip_hdr_len;

        match protocol {
            17 => {
                // UDP
                if data.len() < l4_start + 8 {
                    return None;
                }
                let src_port = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                let dst_port = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                if src_port == 53 || dst_port == 53 {
                    Some(&data[l4_start + 8..])
                } else {
                    None
                }
            }
            6 => {
                // TCP
                if data.len() < l4_start + 20 {
                    return None;
                }
                let src_port = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                let dst_port = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                if src_port == 53 || dst_port == 53 {
                    let data_offset = ((data[l4_start + 12] >> 4) as usize) * 4;
                    let payload_start = l4_start + data_offset;
                    if payload_start + 2 < data.len() {
                        // TCP DNS has 2-byte length prefix; skip it
                        Some(&data[payload_start + 2..])
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Drop for RawSocketCapture {
    fn drop(&mut self) {
        unsafe { ws::closesocket(self.socket) };
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check that we have capture device access on Windows.
///
/// Requires Administrator privileges for raw sockets with SIO_RCVALL.
pub fn check_capture_access() -> Result<(), NetopError> {
    ensure_wsa_init()?;

    // Try to create a raw socket to test privileges
    let socket = unsafe {
        ws::WSASocketW(
            AF_INET as i32,
            SOCK_RAW,
            IPPROTO_IP,
            std::ptr::null(),
            0,
            WSA_FLAG_OVERLAPPED,
        )
    };
    if socket == INVALID_SOCKET {
        let err = unsafe { ws::WSAGetLastError() };
        // WSAEACCES (10013) = permission denied
        if err == 10013 {
            return Err(NetopError::InsufficientPermission(
                "netoproc requires Administrator privileges for raw socket access.\n  \
                 Right-click your terminal and select \"Run as administrator\"."
                    .to_string(),
            ));
        }
        return Err(NetopError::CaptureDevice(format!(
            "cannot create raw socket: WSA error {err}"
        )));
    }
    unsafe { ws::closesocket(socket) };
    Ok(())
}

/// Open capture devices for the specified interfaces.
///
/// On Windows, interfaces are identified by name but capture sockets are
/// bound to the interface's IPv4 address. The first IPv4 address is used.
pub fn open_capture_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    let local_ips = collect_local_ips()?;
    let iface_ips = get_interface_ips()?;

    let mut captures = Vec::new();
    for iface in interfaces {
        if let Some(&ip) = iface_ips.get(iface.as_str()) {
            match RawSocketCapture::new(
                iface,
                ip,
                buffer_size,
                FilterKind::Traffic,
                local_ips.clone(),
            ) {
                Ok(cap) => captures.push(cap),
                Err(e) => {
                    log::warn!("Skipping interface {}: {}", iface, e);
                }
            }
        } else {
            log::warn!("Skipping interface {}: no IPv4 address found", iface);
        }
    }

    let dns_capture = if dns_enabled {
        if let Some(iface) = interfaces.first() {
            if let Some(&ip) = iface_ips.get(iface.as_str()) {
                let dns_buf_size = buffer_size.max(65536);
                match RawSocketCapture::new(iface, ip, dns_buf_size, FilterKind::Dns, local_ips) {
                    Ok(cap) => Some(cap),
                    Err(e) => {
                        log::warn!(
                            "DNS capture on {} failed: {} (continuing without DNS)",
                            iface,
                            e
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok((captures, dns_capture))
}

/// Get capture statistics (Windows — no kernel-level stats available).
pub fn capture_stats(_cap: &PlatformCapture) -> Option<CaptureStats> {
    None
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn collect_local_ips() -> Result<HashSet<IpAddr>, NetopError> {
    let interfaces = crate::system::interface::list_interfaces()?;
    let mut ips = HashSet::new();
    for iface in &interfaces {
        for addr in &iface.ipv4_addresses {
            ips.insert(*addr);
        }
        for addr in &iface.ipv6_addresses {
            ips.insert(*addr);
        }
    }
    Ok(ips)
}

/// Get a mapping of interface name → first IPv4 address.
fn get_interface_ips() -> Result<std::collections::HashMap<String, Ipv4Addr>, NetopError> {
    let interfaces = crate::system::interface::list_interfaces()?;
    let mut map = std::collections::HashMap::new();
    for iface in &interfaces {
        if let Some(IpAddr::V4(v4)) = iface.ipv4_addresses.first() {
            map.entry(iface.name.clone()).or_insert(*v4);
        }
    }
    Ok(map)
}
