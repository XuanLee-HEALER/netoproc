use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::error::NetopError;

/// Raw TCP connection from kernel pcblist_n
#[derive(Debug, Clone)]
pub struct RawTcpConnection {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub tcp_state: i32,
    pub if_index: u32,
}

/// Raw UDP "connection" from kernel pcblist_n
#[derive(Debug, Clone)]
pub struct RawUdpConnection {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub if_index: u32,
}

// xinpgen header/footer structure
#[repr(C)]
#[derive(Clone, Copy)]
struct xinpgen {
    xig_len: u32,
    xig_count: u32,
    xig_gen: u64,
    xig_sogen: u64,
}

const _: () = assert!(mem::size_of::<xinpgen>() == 24);

/// List all TCP connections from the kernel
pub fn list_tcp_connections() -> Result<Vec<RawTcpConnection>, NetopError> {
    let buf = sysctl_read("net.inet.tcp.pcblist_n")?;
    parse_tcp_pcblist(&buf)
}

/// List all UDP connections from the kernel
pub fn list_udp_connections() -> Result<Vec<RawUdpConnection>, NetopError> {
    let buf = sysctl_read("net.inet.udp.pcblist_n")?;
    parse_udp_pcblist(&buf)
}

fn sysctl_read(name: &str) -> Result<Vec<u8>, NetopError> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|e| NetopError::Sysctl(std::io::Error::other(e.to_string())))?;

    let mut buf_size: libc::size_t = 0;

    // First call: get required buffer size
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            ptr::null_mut(),
            &mut buf_size,
            ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        return Err(NetopError::Sysctl(std::io::Error::last_os_error()));
    }

    // Add extra space since the data can grow between calls
    buf_size = buf_size * 3 / 2;
    let mut buf = vec![0u8; buf_size];

    // Second call: fill buffer
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut buf_size,
            ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        return Err(NetopError::Sysctl(std::io::Error::last_os_error()));
    }

    buf.truncate(buf_size);
    Ok(buf)
}

fn parse_tcp_pcblist(buf: &[u8]) -> Result<Vec<RawTcpConnection>, NetopError> {
    if buf.len() < mem::size_of::<xinpgen>() {
        return Ok(Vec::new());
    }

    let header: xinpgen = unsafe { ptr::read(buf.as_ptr() as *const xinpgen) };
    let mut connections = Vec::new();
    let mut offset = header.xig_len as usize;

    while offset + mem::size_of::<xinpgen>() <= buf.len() {
        // Check if this is the footer (xinpgen at the end)
        let entry_len = unsafe { ptr::read(buf[offset..].as_ptr() as *const u32) } as usize;

        if entry_len == 0 || offset + entry_len > buf.len() {
            break;
        }

        // If entry_len matches xinpgen size, it's the footer
        if entry_len == mem::size_of::<xinpgen>() as u32 as usize {
            let footer: xinpgen = unsafe { ptr::read(buf[offset..].as_ptr() as *const xinpgen) };
            // Check generation count
            if footer.xig_gen != header.xig_gen {
                // Data changed during read — retry would be ideal,
                // but for now just return what we have
                log::debug!(
                    "TCP pcblist generation count mismatch: {} != {}",
                    header.xig_gen,
                    footer.xig_gen
                );
            }
            break;
        }

        // Parse the xtcpcb_n entry
        // The structure starts with xig_len, then has the inp and tp structs
        // We need to extract: local/remote addresses, ports, state, if_index
        if let Some(conn) = parse_tcp_entry(&buf[offset..offset + entry_len]) {
            connections.push(conn);
        }

        offset += entry_len;
    }

    Ok(connections)
}

fn parse_tcp_entry(data: &[u8]) -> Option<RawTcpConnection> {
    // xtcpcb_n layout (simplified):
    // The exact layout varies by macOS version.
    // Key fields we need to find:
    // - local/remote sockaddr (IPv4 or IPv6)
    // - TCP state
    // - interface index
    //
    // The approach: scan for sockaddr_in/sockaddr_in6 patterns
    // within the pcb entry at known offsets.
    //
    // On macOS, the xtcpcb_n structure contains:
    //   - xt_len (4 bytes)
    //   - xt_kind (4 bytes) = XSO_TCPCB
    //   - ... various fields ...
    //   - xinpcb_n with local and remote sockaddr
    //   - xtcpcb with TCP state

    if data.len() < 64 {
        return None;
    }

    // Skip entries that are too small to contain valid data
    let entry_len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if entry_len < 64 {
        return None;
    }

    // The xinpcb_n contains two sockaddr_storage fields for local and remote
    // and various other fields. The exact offsets depend on macOS version.
    // We scan for the sockaddr pattern (sa_len, sa_family at known positions).

    // For now, we'll use a heuristic approach:
    // Look for sockaddr_in (family=AF_INET=2) or sockaddr_in6 (family=AF_INET6=30)
    // at expected offsets.

    // Typical offsets for macOS (empirically determined):
    // The xinpcb_n starts after the xt header
    // Local and remote addresses are in sockaddr_in or sockaddr_in6 format
    // embedded within the structure.

    // A more robust approach: look for the XSO_INPCB kind marker
    // and parse from there.

    // For the initial implementation, we'll extract connections
    // using the known structure offsets for macOS.
    // The exact pcb parsing is complex and version-dependent.
    // We'll extract what we can and skip entries we can't parse.

    // Try to find local and remote sockaddr
    let local = find_sockaddr_in_data(data, true);
    let remote = find_sockaddr_in_data(data, false);

    if let (Some((laddr, lport)), Some((raddr, rport))) = (local, remote) {
        // TCP state is typically near the end of the entry
        let tcp_state = extract_tcp_state(data);

        Some(RawTcpConnection {
            local_addr: laddr,
            local_port: lport,
            remote_addr: raddr,
            remote_port: rport,
            tcp_state: tcp_state.unwrap_or(0),
            if_index: 0, // Interface index extraction is complex
        })
    } else {
        None
    }
}

fn find_sockaddr_in_data(data: &[u8], is_local: bool) -> Option<(IpAddr, u16)> {
    // In the xtcpcb_n/xinpcb_n structure, there are two embedded
    // sockaddr_in/sockaddr_in6 structures for local and remote addresses.
    // The format is:
    //   sockaddr_in: sa_len=16, sa_family=AF_INET(2), port(2), addr(4), zero(8)
    //   sockaddr_in6: sa_len=28, sa_family=AF_INET6(30), port(2), flow(4), addr(16), scope(4)

    // Search for sockaddr patterns starting from reasonable offsets
    // The first sockaddr is typically the foreign (remote) address,
    // and the second is the local address.
    let mut found_count = 0;
    let target_count = if is_local { 2 } else { 1 };

    let mut offset = 8; // skip xt_len and xt_kind
    while offset + 4 <= data.len() {
        let sa_len = data[offset];
        let sa_family = data[offset + 1];

        if sa_family == 2 && sa_len == 16 && offset + 16 <= data.len() {
            // sockaddr_in
            found_count += 1;
            if found_count == target_count {
                let port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let addr = Ipv4Addr::new(
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                );
                return Some((IpAddr::V4(addr), port));
            }
            offset += sa_len as usize;
            continue;
        }

        if sa_family == 30 && sa_len == 28 && offset + 28 <= data.len() {
            // sockaddr_in6
            found_count += 1;
            if found_count == target_count {
                let port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&data[offset + 8..offset + 24]);
                let addr = Ipv6Addr::from(addr_bytes);
                return Some((IpAddr::V6(addr), port));
            }
            offset += sa_len as usize;
            continue;
        }

        offset += 1;
    }

    None
}

fn extract_tcp_state(data: &[u8]) -> Option<i32> {
    // The TCP state is typically stored as an i32 near the beginning
    // of the xtcpcb portion (after the xinpcb_n part).
    // On macOS, it's often at a specific offset that we'll need to
    // determine empirically. For now, scan backwards from the end
    // looking for valid TCP state values (0-10).

    // Common approach: the TCP state is in the last portion of the entry
    if data.len() >= 12 {
        // Try common offsets for the tcp state
        // This is version-dependent and may need adjustment
        for offset in (data.len().saturating_sub(128)..data.len().saturating_sub(3)).rev() {
            let val = i32::from_ne_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if (0..=10).contains(&val) {
                // Could be a TCP state — but we need more context to be sure
                // For now, return the first plausible value from the end
                return Some(val);
            }
        }
    }

    None
}

fn parse_udp_pcblist(buf: &[u8]) -> Result<Vec<RawUdpConnection>, NetopError> {
    if buf.len() < mem::size_of::<xinpgen>() {
        return Ok(Vec::new());
    }

    let header: xinpgen = unsafe { ptr::read(buf.as_ptr() as *const xinpgen) };
    let mut connections = Vec::new();
    let mut offset = header.xig_len as usize;

    while offset + mem::size_of::<xinpgen>() <= buf.len() {
        let entry_len = unsafe { ptr::read(buf[offset..].as_ptr() as *const u32) } as usize;

        if entry_len == 0 || offset + entry_len > buf.len() {
            break;
        }

        if entry_len == mem::size_of::<xinpgen>() as u32 as usize {
            break;
        }

        if let Some(conn) = parse_udp_entry(&buf[offset..offset + entry_len]) {
            connections.push(conn);
        }

        offset += entry_len;
    }

    Ok(connections)
}

fn parse_udp_entry(data: &[u8]) -> Option<RawUdpConnection> {
    if data.len() < 64 {
        return None;
    }

    let local = find_sockaddr_in_data(data, true);
    let remote = find_sockaddr_in_data(data, false);

    let (laddr, lport) = local.unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let (raddr, rport) = remote.unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

    Some(RawUdpConnection {
        local_addr: laddr,
        local_port: lport,
        remote_addr: raddr,
        remote_port: rport,
        if_index: 0,
    })
}
