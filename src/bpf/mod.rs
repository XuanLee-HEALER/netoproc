pub mod dns;
pub mod filter;
pub mod packet;

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::NetopError;
use crate::packet::PacketSummary;

use self::filter::bpf_insn;

// ---------------------------------------------------------------------------
// BPF ioctl constants (macOS-specific)
// ---------------------------------------------------------------------------

// macOS _IOC encoding: direction bits [31:30] | size [29:16] | group [15:8] | number [7:0]
// Direction constants match <sys/ioccom.h> — already positioned at bits 31:29.
const fn ioc(dir: u32, group: u8, num: u8, size: u32) -> libc::c_ulong {
    (dir | ((size & 0x1FFF) << 16) | ((group as u32) << 8) | num as u32) as libc::c_ulong
}

const IOC_VOID: u32 = 0x20000000;
const IOC_OUT: u32 = 0x40000000;
const IOC_IN: u32 = 0x80000000;
const IOC_INOUT: u32 = IOC_IN | IOC_OUT;

const BIOCSBLEN: libc::c_ulong = ioc(IOC_INOUT, b'B', 102, 4); // _IOWR('B', 102, u_int)
const BIOCSETIF: libc::c_ulong = ioc(IOC_IN, b'B', 108, 32); // _IOW('B', 108, ifreq)
const BIOCSETF: libc::c_ulong = ioc(IOC_IN, b'B', 103, 16); // _IOW('B', 103, bpf_program) — 16 bytes on 64-bit
const BIOCPROMISC: libc::c_ulong = ioc(IOC_VOID, b'B', 105, 0); // _IO('B', 105)
const BIOCGSTATS: libc::c_ulong = ioc(IOC_OUT, b'B', 111, 8); // _IOR('B', 111, bpf_stat)
const BIOCGBLEN: libc::c_ulong = ioc(IOC_OUT, b'B', 102, 4); // _IOR('B', 102, u_int)
const BIOCSRTIMEOUT: libc::c_ulong = ioc(IOC_IN, b'B', 109, 16); // _IOW('B', 109, struct timeval)
const BIOCGDLT: libc::c_ulong = ioc(IOC_OUT, b'B', 106, 4); // _IOR('B', 106, u_int)

// Compile-time verification against known macOS ioctl values.
const _: () = assert!(BIOCSBLEN == 0xC004_4266);
const _: () = assert!(BIOCSETIF == 0x8020_426C);
const _: () = assert!(BIOCSETF == 0x8010_4267);
const _: () = assert!(BIOCPROMISC == 0x2000_4269);
const _: () = assert!(BIOCGSTATS == 0x4008_426F);
const _: () = assert!(BIOCGBLEN == 0x4004_4266);
const _: () = assert!(BIOCSRTIMEOUT == 0x8010_426D);
const _: () = assert!(BIOCGDLT == 0x4004_426A);

// ---------------------------------------------------------------------------
// Data link type (DLT) support
// ---------------------------------------------------------------------------

use crate::packet::LinkType;

const DLT_NULL: u32 = 0; // BSD loopback (4-byte AF header)
const DLT_EN10MB: u32 = 1; // Ethernet
const DLT_RAW: u32 = 12; // Raw IP (no link-layer header)

fn link_type_from_dlt(dlt: u32) -> Option<LinkType> {
    match dlt {
        DLT_EN10MB => Some(LinkType::Ethernet),
        DLT_RAW => Some(LinkType::Raw),
        DLT_NULL => Some(LinkType::Null),
        _ => None,
    }
}

/// Type of BPF filter to install on a capture device.
#[derive(Debug, Clone, Copy)]
pub enum FilterKind {
    /// Accept all IPv4/IPv6 TCP/UDP traffic.
    Traffic,
    /// Accept only DNS traffic (port 53).
    Dns,
}

// ---------------------------------------------------------------------------
// bpf_program FFI struct for BIOCSETF
// ---------------------------------------------------------------------------

#[repr(C)]
struct bpf_program {
    bf_len: u32,
    _pad: u32, // padding for 8-byte alignment of pointer on 64-bit
    bf_insns: *mut bpf_insn,
}

// bpf_stat struct returned by BIOCGSTATS
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct bpf_stat {
    bs_recv: u32,
    bs_drop: u32,
}

const _: () = assert!(std::mem::size_of::<bpf_stat>() == 8);

/// Statistics from a BPF device.
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfStats {
    pub received: u32,
    pub dropped: u32,
}

/// BPF capture device handle.
///
/// Wraps a `/dev/bpfN` file descriptor configured for packet capture.
/// Drop closes the fd automatically via OwnedFd.
pub struct BpfCapture {
    fd: OwnedFd,
    buffer: Vec<u8>,
    interface: String,
    link_type: LinkType,
}

impl BpfCapture {
    /// Open a BPF device, bind to `interface`, and configure for capture.
    ///
    /// The `filter_kind` determines which BPF filter program to install. The
    /// actual filter instructions are selected based on the interface's data
    /// link type (DLT), which is detected after binding.
    pub fn new(
        interface: &str,
        buffer_size: u32,
        filter_kind: FilterKind,
    ) -> Result<Self, NetopError> {
        let fd = open_bpf_device()?;

        // 1. Set buffer size (minimum 4096 to avoid undefined behavior with tiny values)
        let blen = buffer_size.max(4096);
        ioctl_set(&fd, BIOCSBLEN, &blen)?;

        // 2. Bind to interface
        set_interface(&fd, interface)?;

        // 3. Detect data link type (must be after BIOCSETIF)
        let mut dlt: u32 = 0;
        ioctl_get(&fd, BIOCGDLT, &mut dlt)?;
        let link_type = link_type_from_dlt(dlt).ok_or_else(|| {
            NetopError::BpfDevice(format!(
                "unsupported data link type {dlt} on interface {interface}"
            ))
        })?;

        // 4. Set read timeout so blocking reads return periodically,
        // allowing threads to check shutdown signals.
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 500_000, // 500ms
        };
        ioctl_set(&fd, BIOCSRTIMEOUT, &timeout)?;

        // 5. Install BPF filter (selected based on DLT and filter kind)
        let filter_insns = match (filter_kind, link_type) {
            (FilterKind::Traffic, LinkType::Ethernet) => filter::traffic_filter(),
            (FilterKind::Traffic, LinkType::Raw) => filter::traffic_filter_raw(),
            (FilterKind::Traffic, LinkType::Null) => filter::traffic_filter_null(),
            (FilterKind::Dns, LinkType::Ethernet) => filter::dns_filter(),
            (FilterKind::Dns, LinkType::Raw) => filter::dns_filter_raw(),
            (FilterKind::Dns, LinkType::Null) => filter::dns_filter_null(),
        };
        set_filter(&fd, &filter_insns)?;

        // 6. Enable promiscuous mode
        unsafe {
            if libc::ioctl(fd.as_raw_fd(), BIOCPROMISC) != 0 {
                let err = io::Error::last_os_error();
                // Non-fatal: some interfaces don't support promiscuous mode
                log::warn!(
                    "BIOCPROMISC failed on {}: {} (continuing without promiscuous mode)",
                    interface,
                    err
                );
            }
        }

        // 7. Read back actual buffer size
        let mut actual_blen: u32 = 0;
        ioctl_get(&fd, BIOCGBLEN, &mut actual_blen)?;

        let buffer = vec![0u8; actual_blen as usize];

        log::info!(
            "BPF capture on {} (DLT={}, {:?}, buffer={})",
            interface,
            dlt,
            link_type,
            actual_blen
        );

        Ok(Self {
            fd,
            buffer,
            interface: interface.to_string(),
            link_type,
        })
    }

    /// Blocking read of packets from the BPF device.
    ///
    /// Parsed packet summaries are appended to `out` (which is cleared first).
    /// The caller should reuse the same `Vec` across calls to avoid repeated
    /// heap allocation.
    pub fn read_packets(&mut self, out: &mut Vec<PacketSummary>) -> Result<(), NetopError> {
        self.read_packets_raw(out).map(|_| ())
    }

    /// Blocking read of packets from the BPF device, returning raw byte count.
    ///
    /// Returns the number of raw bytes returned by the kernel `read()` call.
    /// This is useful for diagnostics: 0 means timeout with no data,
    /// positive means data was read (check `out` for parsed packet count).
    pub fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError> {
        out.clear();

        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                self.buffer.as_mut_ptr() as *mut libc::c_void,
                self.buffer.len(),
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            return Err(NetopError::BpfDevice(format!(
                "read on /dev/bpf ({}): {}",
                self.interface, err
            )));
        }

        if n == 0 {
            return Ok(0);
        }

        out.extend(packet::BpfPacketIter::new(
            &self.buffer[..n as usize],
            self.link_type,
        ));
        Ok(n as usize)
    }

    /// Extract DNS payload from a raw packet if it's on port 53.
    /// Returns the UDP/TCP payload suitable for `dns::parse_dns()`.
    fn extract_dns_payload(packet_data: &[u8], link_type: LinkType) -> Option<&[u8]> {
        let (ip_hdr_start, ip_hdr_len, protocol) = Self::identify_ip_layer(packet_data, link_type)?;

        let l4_start = ip_hdr_start + ip_hdr_len;

        match protocol {
            17 => {
                // UDP — port 53 check, payload starts at UDP header + 8
                if packet_data.len() < l4_start + 8 {
                    return None;
                }
                let src_port =
                    u16::from_be_bytes([packet_data[l4_start], packet_data[l4_start + 1]]);
                let dst_port =
                    u16::from_be_bytes([packet_data[l4_start + 2], packet_data[l4_start + 3]]);
                if src_port == 53 || dst_port == 53 {
                    Some(&packet_data[l4_start + 8..])
                } else {
                    None
                }
            }
            6 => {
                // TCP — port 53 check, payload starts after TCP header
                if packet_data.len() < l4_start + 20 {
                    return None;
                }
                let src_port =
                    u16::from_be_bytes([packet_data[l4_start], packet_data[l4_start + 1]]);
                let dst_port =
                    u16::from_be_bytes([packet_data[l4_start + 2], packet_data[l4_start + 3]]);
                if src_port == 53 || dst_port == 53 {
                    let data_offset = ((packet_data[l4_start + 12] >> 4) as usize) * 4;
                    let payload_start = l4_start + data_offset;
                    if payload_start < packet_data.len() {
                        // TCP DNS has 2-byte length prefix; skip it
                        let dns_start = if payload_start + 2 < packet_data.len() {
                            payload_start + 2
                        } else {
                            payload_start
                        };
                        Some(&packet_data[dns_start..])
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

    /// Identify the IP layer start, header length, and protocol from a raw frame.
    ///
    /// Returns `(ip_start_offset, ip_header_length, protocol)` or `None` if
    /// the frame is not IPv4/IPv6.
    fn identify_ip_layer(data: &[u8], link_type: LinkType) -> Option<(usize, usize, u8)> {
        match link_type {
            LinkType::Ethernet => {
                if data.len() < 14 {
                    return None;
                }
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                match ethertype {
                    0x0800 => {
                        if data.len() < 14 + 20 {
                            return None;
                        }
                        let ihl = (data[14] & 0x0F) as usize * 4;
                        let proto = data[14 + 9];
                        Some((14, ihl, proto))
                    }
                    0x86DD => {
                        if data.len() < 14 + 40 {
                            return None;
                        }
                        let next_hdr = data[14 + 6];
                        let after_fixed = &data[14 + 40..];
                        let (final_proto, ext_offset) =
                            packet::skip_ipv6_extension_headers(next_hdr, after_fixed);
                        Some((14, 40 + ext_offset, final_proto))
                    }
                    _ => None,
                }
            }
            LinkType::Raw => {
                if data.is_empty() {
                    return None;
                }
                let version = data[0] >> 4;
                match version {
                    4 => {
                        if data.len() < 20 {
                            return None;
                        }
                        let ihl = (data[0] & 0x0F) as usize * 4;
                        let proto = data[9];
                        Some((0, ihl, proto))
                    }
                    6 => {
                        if data.len() < 40 {
                            return None;
                        }
                        let next_hdr = data[6];
                        let after_fixed = &data[40..];
                        let (final_proto, ext_offset) =
                            packet::skip_ipv6_extension_headers(next_hdr, after_fixed);
                        Some((0, 40 + ext_offset, final_proto))
                    }
                    _ => None,
                }
            }
            LinkType::Null => {
                if data.len() < 4 {
                    return None;
                }
                let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                match af {
                    af if af == libc::AF_INET as u32 => {
                        if data.len() < 4 + 20 {
                            return None;
                        }
                        let ihl = (data[4] & 0x0F) as usize * 4;
                        let proto = data[4 + 9];
                        Some((4, ihl, proto))
                    }
                    af if af == libc::AF_INET6 as u32 => {
                        if data.len() < 4 + 40 {
                            return None;
                        }
                        let next_hdr = data[4 + 6];
                        let after_fixed = &data[4 + 40..];
                        let (final_proto, ext_offset) =
                            packet::skip_ipv6_extension_headers(next_hdr, after_fixed);
                        Some((4, 40 + ext_offset, final_proto))
                    }
                    _ => None,
                }
            }
        }
    }

    /// Get BPF device statistics (packets received/dropped by kernel).
    pub fn stats(&self) -> Result<BpfStats, NetopError> {
        let mut stats = bpf_stat::default();
        ioctl_get(&self.fd, BIOCGSTATS, &mut stats)?;
        Ok(BpfStats {
            received: stats.bs_recv,
            dropped: stats.bs_drop,
        })
    }

    /// Read packets from BPF device and extract DNS messages.
    ///
    /// For each captured frame, checks if it contains a DNS payload (port 53),
    /// extracts and parses the DNS wire-format data.
    pub fn read_dns_messages(&mut self) -> Result<Vec<dns::DnsMessage>, NetopError> {
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                self.buffer.as_mut_ptr() as *mut libc::c_void,
                self.buffer.len(),
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            return Err(NetopError::BpfDevice(format!(
                "read on /dev/bpf ({}): {}",
                self.interface, err
            )));
        }

        if n == 0 {
            return Ok(Vec::new());
        }

        let buf = &self.buffer[..n as usize];
        let mut messages = Vec::new();
        let mut offset = 0;

        while offset + std::mem::size_of::<packet::BpfHdr>() <= buf.len() {
            let hdr_ptr = buf[offset..].as_ptr() as *const packet::BpfHdr;
            let (hdr_len, cap_len) = unsafe {
                let hdr = std::ptr::read_unaligned(hdr_ptr);
                (hdr.bh_hdrlen as usize, hdr.bh_caplen as usize)
            };

            if offset + hdr_len + cap_len > buf.len() {
                break;
            }

            let frame = &buf[offset + hdr_len..offset + hdr_len + cap_len];

            if let Some(dns_payload) = Self::extract_dns_payload(frame, self.link_type) {
                match dns::parse_dns(dns_payload) {
                    Ok(msg) => messages.push(msg),
                    Err(e) => log::debug!("DNS parse error: {e}"),
                }
            }

            offset += packet::bpf_wordalign(hdr_len + cap_len);
        }

        Ok(messages)
    }

    /// Returns the interface name this capture is bound to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Returns the raw fd for use with poll/select.
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn open_bpf_device() -> Result<OwnedFd, NetopError> {
    for i in 0..256 {
        let path = format!("/dev/bpf{i}");
        let c_path = std::ffi::CString::new(path.as_str())
            .map_err(|_| NetopError::BpfDevice("invalid BPF device path".to_string()))?;

        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EBUSY) => continue,
            Some(libc::ENOENT) => break,
            Some(libc::EACCES) => {
                // All BPF devices share the same permissions; no point trying others.
                return Err(NetopError::BpfDevice(
                    "permission denied on /dev/bpf*. Run with sudo or set up \
                     BPF permissions: sudo bash scripts/install-bpf.sh"
                        .to_string(),
                ));
            }
            _ => {
                return Err(NetopError::BpfDevice(format!(
                    "open {} failed: {}",
                    path, err
                )));
            }
        }
    }

    Err(NetopError::BpfDevice(
        "all BPF devices are busy".to_string(),
    ))
}

fn set_interface(fd: &OwnedFd, name: &str) -> Result<(), NetopError> {
    // ifreq is a 32-byte struct with the interface name in the first 16 bytes
    let mut ifreq = [0u8; 32];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(15); // IFNAMSIZ-1
    ifreq[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    unsafe {
        if libc::ioctl(fd.as_raw_fd(), BIOCSETIF, ifreq.as_ptr()) != 0 {
            return Err(NetopError::BpfDevice(format!(
                "BIOCSETIF({}) failed: {}",
                name,
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn set_filter(fd: &OwnedFd, filter: &[bpf_insn]) -> Result<(), NetopError> {
    let mut insns = filter.to_vec();
    let prog = bpf_program {
        bf_len: insns.len() as u32,
        _pad: 0,
        bf_insns: insns.as_mut_ptr(),
    };

    unsafe {
        if libc::ioctl(fd.as_raw_fd(), BIOCSETF, &prog as *const bpf_program) != 0 {
            return Err(NetopError::BpfDevice(format!(
                "BIOCSETF failed: {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn ioctl_set<T>(fd: &OwnedFd, request: libc::c_ulong, val: &T) -> Result<(), NetopError> {
    unsafe {
        if libc::ioctl(fd.as_raw_fd(), request, val as *const T) != 0 {
            return Err(NetopError::BpfDevice(format!(
                "ioctl(0x{:x}) failed: {}",
                request,
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn ioctl_get<T>(fd: &OwnedFd, request: libc::c_ulong, val: &mut T) -> Result<(), NetopError> {
    unsafe {
        if libc::ioctl(fd.as_raw_fd(), request, val as *mut T) != 0 {
            return Err(NetopError::BpfDevice(format!(
                "ioctl(0x{:x}) failed: {}",
                request,
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ut_bpf_buffer_min_guard() {
        // Verify the clamping logic: buffer_size.max(4096)
        fn clamp(v: u32) -> u32 {
            v.max(4096)
        }
        assert_eq!(clamp(0), 4096);
        assert_eq!(clamp(1), 4096);
        assert_eq!(clamp(4095), 4096);
        assert_eq!(clamp(4096), 4096);
        assert_eq!(clamp(8192), 8192);
        assert_eq!(clamp(u32::MAX), u32::MAX);
    }
}
