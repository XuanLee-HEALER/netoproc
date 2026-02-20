// Linux capture implementation — AF_PACKET raw sockets.

use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::dns::DnsMessage;
use crate::error::NetopError;
use crate::packet::{self, PacketSummary};

use super::FilterKind;

// ---------------------------------------------------------------------------
// AF_PACKET constants
// ---------------------------------------------------------------------------

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: i32 = 263;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_MR_PROMISC: u16 = 1;

// BPF filter opcodes (identical layout on Linux and macOS)
const BPF_LD: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;
const BPF_MSH: u16 = 0xa0;
const BPF_IND: u16 = 0x40;
const BPF_LDX: u16 = 0x01;

#[repr(C)]
#[derive(Clone, Copy)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct sock_fprog {
    len: u16,
    filter: *mut sock_filter,
}

#[repr(C)]
struct packet_mreq {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

/// AF_PACKET capture device.
pub struct AfPacketCapture {
    fd: OwnedFd,
    buffer: Vec<u8>,
    interface: String,
    _local_ips: HashSet<IpAddr>,
}

pub type PlatformCapture = AfPacketCapture;

/// Statistics from a capture device (Linux — no kernel-level stats like macOS BPF).
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    pub received: u32,
    pub dropped: u32,
}

impl AfPacketCapture {
    /// Create a new AF_PACKET capture device bound to `interface`.
    pub fn new(
        interface: &str,
        buffer_size: u32,
        filter_kind: FilterKind,
        local_ips: HashSet<IpAddr>,
    ) -> Result<Self, NetopError> {
        // 1. Create raw socket
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (ETH_P_ALL as u32).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(NetopError::CaptureDevice(format!(
                "socket(AF_PACKET) failed: {}",
                io::Error::last_os_error()
            )));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // 2. Get interface index
        let if_index = if_nametoindex(interface)?;

        // 3. Bind to interface
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        #[allow(clippy::unnecessary_cast)]
        {
            sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        }
        sll.sll_ifindex = if_index as i32;

        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(NetopError::CaptureDevice(format!(
                "bind(AF_PACKET, {}) failed: {}",
                interface,
                io::Error::last_os_error()
            )));
        }

        // 4. Install BPF filter
        let filter_insns = match filter_kind {
            FilterKind::Traffic => traffic_filter_ethernet(),
            FilterKind::Dns => dns_filter_ethernet(),
        };
        install_filter(&fd, &filter_insns)?;

        // 5. Set read timeout (500ms)
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 500_000,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            log::warn!(
                "SO_RCVTIMEO failed on {}: {}",
                interface,
                io::Error::last_os_error()
            );
        }

        // 6. Set receive buffer size
        let buf_size = buffer_size.max(4096) as i32;
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            log::warn!(
                "SO_RCVBUF failed on {}: {}",
                interface,
                io::Error::last_os_error()
            );
        }

        // 7. Enable promiscuous mode
        let mreq = packet_mreq {
            mr_ifindex: if_index as i32,
            mr_type: PACKET_MR_PROMISC,
            mr_alen: 0,
            mr_address: [0u8; 8],
        };
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq as *const packet_mreq as *const libc::c_void,
                std::mem::size_of::<packet_mreq>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            log::warn!(
                "PACKET_MR_PROMISC failed on {}: {} (continuing without promiscuous mode)",
                interface,
                io::Error::last_os_error()
            );
        }

        let buffer = vec![0u8; buffer_size.max(4096) as usize];

        log::info!(
            "AF_PACKET capture on {} (if_index={}, buffer={})",
            interface,
            if_index,
            buffer.len()
        );

        Ok(Self {
            fd,
            buffer,
            interface: interface.to_string(),
            _local_ips: local_ips,
        })
    }

    /// Blocking read of packets from the AF_PACKET socket.
    ///
    /// Parsed packet summaries are appended to `out` (which is cleared first).
    pub fn read_packets(&mut self, out: &mut Vec<PacketSummary>) -> Result<(), NetopError> {
        self.read_packets_raw(out).map(|_| ())
    }

    /// Blocking read of packets, returning raw byte count.
    pub fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError> {
        out.clear();
        let mut total_bytes = 0usize;

        // First read: blocking (waits for data or timeout)
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                self.buffer.as_mut_ptr() as *mut libc::c_void,
                self.buffer.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Ok(0);
            }
            return Err(NetopError::CaptureDevice(format!(
                "recvfrom on {} failed: {}",
                self.interface, err
            )));
        }

        if n > 0 {
            let frame = &self.buffer[..n as usize];
            total_bytes += n as usize;
            if let Some(pkt) = packet::parse_ethernet_frame(frame) {
                out.push(pkt);
            }
        }

        // Drain additional pending frames with MSG_DONTWAIT
        loop {
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr() as *mut libc::c_void,
                    self.buffer.len(),
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if n <= 0 {
                break;
            }

            total_bytes += n as usize;
            let frame = &self.buffer[..n as usize];
            if let Some(pkt) = packet::parse_ethernet_frame(frame) {
                out.push(pkt);
            }
        }

        Ok(total_bytes)
    }

    /// Read packets and extract DNS messages.
    pub fn read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError> {
        let mut messages = Vec::new();

        // First read: blocking (waits for data or timeout)
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                self.buffer.as_mut_ptr() as *mut libc::c_void,
                self.buffer.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Ok(messages);
            }
            return Err(NetopError::CaptureDevice(format!(
                "recvfrom on {} failed: {}",
                self.interface, err
            )));
        }

        if n > 0 {
            let frame = &self.buffer[..n as usize];
            if let Some(dns_payload) = extract_dns_payload_ethernet(frame) {
                match crate::dns::parse_dns(dns_payload) {
                    Ok(msg) => messages.push(msg),
                    Err(e) => log::debug!("DNS parse error: {e}"),
                }
            }
        }

        // Drain additional pending frames with MSG_DONTWAIT
        loop {
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr() as *mut libc::c_void,
                    self.buffer.len(),
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if n <= 0 {
                break;
            }

            let frame = &self.buffer[..n as usize];
            if let Some(dns_payload) = extract_dns_payload_ethernet(frame) {
                match crate::dns::parse_dns(dns_payload) {
                    Ok(msg) => messages.push(msg),
                    Err(e) => log::debug!("DNS parse error: {e}"),
                }
            }
        }

        Ok(messages)
    }

    /// Returns the interface name this capture is bound to.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check that we have capture device access on Linux.
pub fn check_capture_access() -> Result<(), NetopError> {
    // Root always has access
    if unsafe { libc::getuid() } == 0 {
        return Ok(());
    }

    // Try to open a test socket to check capabilities
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (ETH_P_ALL as u32).to_be() as i32,
        )
    };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        log::warn!(
            "Running without root: process visibility limited to current user. \
             For full visibility, run with: sudo netoproc"
        );
        return Ok(());
    }

    Err(NetopError::InsufficientPermission(
        "netoproc requires raw socket access. Either:\n  \
         1. Run with sudo: sudo netoproc\n  \
         2. Set up capabilities: sudo bash scripts/install-linux.sh"
            .to_string(),
    ))
}

/// Open capture devices for the specified interfaces.
///
/// The `capture_mode` parameter controls which backend to use:
/// - `Auto`: try eBPF first (if compiled with `ebpf` feature), fall back to AF_PACKET
/// - `Ebpf`: force eBPF, return error if unavailable
/// - `Afpacket`: force AF_PACKET (current default behavior)
pub fn open_capture_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
    capture_mode: crate::cli::CaptureMode,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    use crate::cli::CaptureMode;

    match capture_mode {
        CaptureMode::Ebpf => {
            #[cfg(feature = "ebpf")]
            {
                return try_open_ebpf(interfaces, buffer_size, dns_enabled, false);
            }
            #[cfg(not(feature = "ebpf"))]
            {
                return Err(NetopError::EbpfProgram(
                    "eBPF support not compiled in (build with --features ebpf)".to_string(),
                ));
            }
        }
        CaptureMode::Auto => {
            #[cfg(feature = "ebpf")]
            {
                if super::ebpf::ebpf_available() {
                    match try_open_ebpf(interfaces, buffer_size, dns_enabled, true) {
                        Ok(result) => return Ok(result),
                        Err(e) => {
                            log::warn!(
                                "eBPF initialization failed, falling back to AF_PACKET: {e}"
                            );
                            // Fall through to AF_PACKET below
                        }
                    }
                } else {
                    log::info!("eBPF not available on this kernel, using AF_PACKET");
                }
            }
        }
        CaptureMode::Afpacket => {
            // Fall through to AF_PACKET below
        }
    }

    open_afpacket_devices(interfaces, buffer_size, dns_enabled)
}

/// Open AF_PACKET capture devices (the original implementation).
fn open_afpacket_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    let local_ips = collect_local_ips()?;

    let mut captures = Vec::new();
    for iface in interfaces {
        match AfPacketCapture::new(iface, buffer_size, FilterKind::Traffic, local_ips.clone()) {
            Ok(cap) => captures.push(cap),
            Err(e) => {
                log::warn!("Skipping interface {}: {}", iface, e);
            }
        }
    }

    let dns_capture = if dns_enabled {
        if let Some(iface) = interfaces.first() {
            let dns_buf_size = buffer_size.max(65536);
            match AfPacketCapture::new(iface, dns_buf_size, FilterKind::Dns, local_ips) {
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
    };

    Ok((captures, dns_capture))
}

/// Attempt to open eBPF capture devices.
///
/// The `_allow_fallback` parameter is reserved for Phase 2, where it will
/// control whether eBPF load failures are fatal or trigger AF_PACKET fallback.
#[cfg(feature = "ebpf")]
fn try_open_ebpf(
    interfaces: &[String],
    _buffer_size: u32,
    _dns_enabled: bool,
    _allow_fallback: bool,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    // Phase 1: EbpfCapture::try_new() always returns Err (stub).
    // Phase 2: this will load the eBPF program and return capture devices.
    let iface = interfaces
        .first()
        .ok_or_else(|| NetopError::EbpfProgram("no interfaces to monitor".to_string()))?;

    // Try to create eBPF capture — Phase 1 stub returns Err here.
    let _ebpf = super::ebpf::EbpfCapture::try_new(iface)?;

    // Phase 2: When eBPF works, the traffic capture thread will poll BPF maps
    // instead of reading raw packets. DNS still uses AF_PACKET since kprobes
    // don't capture packet content.
    Err(NetopError::EbpfProgram(
        "eBPF capture device construction not yet implemented".to_string(),
    ))
}

/// Get capture statistics (Linux has no kernel-level BPF stats).
pub fn capture_stats(_cap: &PlatformCapture) -> Option<CaptureStats> {
    None
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn if_nametoindex(name: &str) -> Result<u32, NetopError> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| NetopError::CaptureDevice("invalid interface name".to_string()))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(NetopError::CaptureDevice(format!(
            "if_nametoindex({}) failed: {}",
            name,
            io::Error::last_os_error()
        )));
    }
    Ok(idx)
}

fn install_filter(fd: &OwnedFd, filter: &[sock_filter]) -> Result<(), NetopError> {
    let mut insns = filter.to_vec();
    let prog = sock_fprog {
        len: insns.len() as u16,
        filter: insns.as_mut_ptr(),
    };

    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const sock_fprog as *const libc::c_void,
            std::mem::size_of::<sock_fprog>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(NetopError::CaptureDevice(format!(
            "SO_ATTACH_FILTER failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

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

/// Extract DNS payload from an Ethernet frame (port 53 UDP/TCP).
fn extract_dns_payload_ethernet(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip_start = 14;

    let (ip_hdr_len, protocol) = match ethertype {
        0x0800 => {
            // IPv4
            if data.len() < ip_start + 20 {
                return None;
            }
            let ihl = (data[ip_start] & 0x0F) as usize * 4;
            let proto = data[ip_start + 9];
            (ihl, proto)
        }
        0x86DD => {
            // IPv6
            if data.len() < ip_start + 40 {
                return None;
            }
            let next_hdr = data[ip_start + 6];
            let after_fixed = &data[ip_start + 40..];
            let (final_proto, ext_offset) =
                packet::skip_ipv6_extension_headers(next_hdr, after_fixed);
            (40 + ext_offset, final_proto)
        }
        _ => return None,
    };

    let l4_start = ip_start + ip_hdr_len;

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

// ---------------------------------------------------------------------------
// BPF filter programs for AF_PACKET (Ethernet framing only on Linux)
// ---------------------------------------------------------------------------

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Traffic filter: accept IPv4/IPv6 TCP/UDP, reject everything else.
fn traffic_filter_ethernet() -> Vec<sock_filter> {
    vec![
        // Load EtherType at offset 12
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
        // If IPv4 (0x0800), jump to IPv4 check
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x0800),
        // Load IPv4 protocol at offset 23 (14 + 9)
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23),
        // If TCP (6), accept
        insn(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 6),
        // If UDP (17), accept
        insn(BPF_JMP | BPF_JEQ | BPF_K, 5, 6, 17),
        // Check if IPv6 (0x86DD)
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0x86DD),
        // Load IPv6 next header at offset 20 (14 + 6)
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 20),
        // If TCP (6), accept
        insn(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 6),
        // If UDP (17), accept
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 2, 17),
        // Reject (ICMPv6 = 58 falls through here)
        // Accept: return 65535
        insn(BPF_RET | BPF_K, 0, 0, 0xFFFF),
        // Also accept
        insn(BPF_RET | BPF_K, 0, 0, 0xFFFF),
        // Reject: return 0
        insn(BPF_RET | BPF_K, 0, 0, 0),
    ]
}

/// DNS filter: accept only port 53 traffic (UDP/TCP).
fn dns_filter_ethernet() -> Vec<sock_filter> {
    vec![
        // Load EtherType
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
        // If IPv4
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 8, 0x0800),
        // Load protocol
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23),
        // If TCP or UDP
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 6),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 10, 17),
        // Load IHL to get L4 offset
        insn(BPF_LDX | BPF_MSH | BPF_B, 0, 0, 14),
        // Load dst port (IHL + 14 + 2)
        insn(BPF_LD | BPF_H | BPF_IND, 0, 0, 16),
        // If dst port == 53, accept
        insn(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 53),
        // Load src port (IHL + 14)
        insn(BPF_LD | BPF_H | BPF_IND, 0, 0, 14),
        // If src port == 53, accept
        insn(BPF_JMP | BPF_JEQ | BPF_K, 3, 4, 53),
        // IPv6 check
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x86DD),
        // Load next header
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 20),
        // If TCP or UDP, check port 53 at fixed offset
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 6),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, 17),
        // Load dst port at offset 56 (14+40+2)
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 56),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 53),
        // Load src port at offset 54 (14+40)
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 54),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 53),
        // Accept
        insn(BPF_RET | BPF_K, 0, 0, 0xFFFF),
        // Reject
        insn(BPF_RET | BPF_K, 0, 0, 0),
    ]
}
