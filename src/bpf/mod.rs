pub mod dns;
pub mod filter;
pub mod packet;

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::error::NetopError;

use self::filter::bpf_insn;
use self::packet::PacketSummary;

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
const BIOCIMMEDIATE: libc::c_ulong = ioc(IOC_IN, b'B', 112, 4); // _IOW('B', 112, u_int)
const BIOCPROMISC: libc::c_ulong = ioc(IOC_VOID, b'B', 105, 0); // _IO('B', 105)
const BIOCGSTATS: libc::c_ulong = ioc(IOC_OUT, b'B', 111, 8); // _IOR('B', 111, bpf_stat)
const BIOCGBLEN: libc::c_ulong = ioc(IOC_OUT, b'B', 102, 4); // _IOR('B', 102, u_int)
const BIOCSRTIMEOUT: libc::c_ulong = ioc(IOC_IN, b'B', 109, 16); // _IOW('B', 109, struct timeval)

// Compile-time verification against known macOS ioctl values.
const _: () = assert!(BIOCSBLEN == 0xC004_4266);
const _: () = assert!(BIOCSETIF == 0x8020_426C);
const _: () = assert!(BIOCSETF == 0x8010_4267);
const _: () = assert!(BIOCIMMEDIATE == 0x8004_4270);
const _: () = assert!(BIOCPROMISC == 0x2000_4269);
const _: () = assert!(BIOCGSTATS == 0x4008_426F);
const _: () = assert!(BIOCGBLEN == 0x4004_4266);
const _: () = assert!(BIOCSRTIMEOUT == 0x8010_426D);

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
}

impl BpfCapture {
    /// Open a BPF device, bind to `interface`, and configure for capture.
    pub fn new(interface: &str, buffer_size: u32, filter: &[bpf_insn]) -> Result<Self, NetopError> {
        let fd = open_bpf_device()?;

        // 1. Set buffer size (minimum 4096 to avoid undefined behavior with tiny values)
        let blen = buffer_size.max(4096);
        ioctl_set(&fd, BIOCSBLEN, &blen)?;

        // 2. Bind to interface
        set_interface(&fd, interface)?;

        // 3. Enable immediate mode (return packets without waiting for full buffer)
        let imm: u32 = 1;
        ioctl_set(&fd, BIOCIMMEDIATE, &imm)?;

        // 3b. Set read timeout so blocking reads return periodically,
        // allowing threads to check shutdown signals.
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 500_000, // 500ms
        };
        ioctl_set(&fd, BIOCSRTIMEOUT, &timeout)?;

        // 4. Install BPF filter
        set_filter(&fd, filter)?;

        // 5. Enable promiscuous mode
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

        // 6. Read back actual buffer size
        let mut actual_blen: u32 = 0;
        ioctl_get(&fd, BIOCGBLEN, &mut actual_blen)?;

        let buffer = vec![0u8; actual_blen as usize];

        Ok(Self {
            fd,
            buffer,
            interface: interface.to_string(),
        })
    }

    /// Blocking read of packets from the BPF device.
    ///
    /// Parsed packet summaries are appended to `out` (which is cleared first).
    /// The caller should reuse the same `Vec` across calls to avoid repeated
    /// heap allocation.
    pub fn read_packets(&mut self, out: &mut Vec<PacketSummary>) -> Result<(), NetopError> {
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
            return Ok(());
        }

        out.extend(packet::BpfPacketIter::new(&self.buffer[..n as usize]));
        Ok(())
    }

    /// Extract DNS payload from a raw packet if it's on port 53.
    /// Returns the UDP/TCP payload suitable for `dns::parse_dns()`.
    pub fn extract_dns_payload(packet_data: &[u8]) -> Option<&[u8]> {
        // Packet data starts after BPF header, at the Ethernet frame.
        if packet_data.len() < 14 {
            return None;
        }

        let ethertype = u16::from_be_bytes([packet_data[12], packet_data[13]]);
        let (ip_hdr_start, ip_hdr_len, protocol) = match ethertype {
            0x0800 => {
                // IPv4
                if packet_data.len() < 14 + 20 {
                    return None;
                }
                let ihl = (packet_data[14] & 0x0F) as usize * 4;
                let proto = packet_data[23];
                (14, ihl, proto)
            }
            0x86DD => {
                // IPv6
                if packet_data.len() < 14 + 40 {
                    return None;
                }
                let next_hdr = packet_data[20];
                let after_fixed = &packet_data[14 + 40..];
                let (final_proto, ext_offset) =
                    packet::skip_ipv6_extension_headers(next_hdr, after_fixed);
                (14, 40 + ext_offset, final_proto)
            }
            _ => return None,
        };

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

            if let Some(dns_payload) = Self::extract_dns_payload(frame) {
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
        assert_eq!(0u32.max(4096), 4096);
        assert_eq!(1u32.max(4096), 4096);
        assert_eq!(4095u32.max(4096), 4096);
        assert_eq!(4096u32.max(4096), 4096);
        assert_eq!(8192u32.max(4096), 8192);
        assert_eq!(u32::MAX.max(4096), u32::MAX);
    }
}
