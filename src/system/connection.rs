use std::net::IpAddr;

use crate::error::NetopError;

/// Raw TCP connection from kernel
#[derive(Debug, Clone)]
pub struct RawTcpConnection {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub tcp_state: i32,
    pub if_index: u32,
}

/// Raw UDP "connection" from kernel
#[derive(Debug, Clone)]
pub struct RawUdpConnection {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub if_index: u32,
}

// ---------------------------------------------------------------------------
// macOS: sysctl pcblist_n
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ptr;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct xinpgen {
        xig_len: u32,
        xig_count: u32,
        xig_gen: u64,
        xig_sogen: u64,
    }

    const _: () = assert!(mem::size_of::<xinpgen>() == 24);

    pub fn list_tcp_connections() -> Result<Vec<RawTcpConnection>, NetopError> {
        let buf = sysctl_read("net.inet.tcp.pcblist_n")?;
        parse_tcp_pcblist(&buf)
    }

    pub fn list_udp_connections() -> Result<Vec<RawUdpConnection>, NetopError> {
        let buf = sysctl_read("net.inet.udp.pcblist_n")?;
        parse_udp_pcblist(&buf)
    }

    fn sysctl_read(name: &str) -> Result<Vec<u8>, NetopError> {
        let c_name = std::ffi::CString::new(name)
            .map_err(|e| NetopError::Sysctl(std::io::Error::other(e.to_string())))?;

        let mut buf_size: libc::size_t = 0;

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

        buf_size = buf_size * 3 / 2;
        let mut buf = vec![0u8; buf_size];

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
            let entry_len = unsafe { ptr::read(buf[offset..].as_ptr() as *const u32) } as usize;

            if entry_len == 0 || offset + entry_len > buf.len() {
                break;
            }

            if entry_len == mem::size_of::<xinpgen>() as u32 as usize {
                let footer: xinpgen =
                    unsafe { ptr::read(buf[offset..].as_ptr() as *const xinpgen) };
                if footer.xig_gen != header.xig_gen {
                    log::debug!(
                        "TCP pcblist generation count mismatch: {} != {}",
                        header.xig_gen,
                        footer.xig_gen
                    );
                }
                break;
            }

            if let Some(conn) = parse_tcp_entry(&buf[offset..offset + entry_len]) {
                connections.push(conn);
            }

            offset += entry_len;
        }

        Ok(connections)
    }

    fn parse_tcp_entry(data: &[u8]) -> Option<RawTcpConnection> {
        if data.len() < 64 {
            return None;
        }

        let entry_len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if entry_len < 64 {
            return None;
        }

        let local = find_sockaddr_in_data(data, true);
        let remote = find_sockaddr_in_data(data, false);

        if let (Some((laddr, lport)), Some((raddr, rport))) = (local, remote) {
            let tcp_state = extract_tcp_state(data);

            Some(RawTcpConnection {
                local_addr: laddr,
                local_port: lport,
                remote_addr: raddr,
                remote_port: rport,
                tcp_state: tcp_state.unwrap_or(0),
                if_index: 0,
            })
        } else {
            None
        }
    }

    fn find_sockaddr_in_data(data: &[u8], is_local: bool) -> Option<(IpAddr, u16)> {
        let mut found_count = 0;
        let target_count = if is_local { 2 } else { 1 };

        let mut offset = 8;
        while offset + 4 <= data.len() {
            let sa_len = data[offset];
            let sa_family = data[offset + 1];

            if sa_family == 2 && sa_len == 16 && offset + 16 <= data.len() {
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
        if data.len() >= 12 {
            for offset in (data.len().saturating_sub(128)..data.len().saturating_sub(3)).rev() {
                let val = i32::from_ne_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                if (0..=10).contains(&val) {
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
}

#[cfg(target_os = "macos")]
pub use macos_impl::{list_tcp_connections, list_udp_connections};

// ---------------------------------------------------------------------------
// Linux: parse /proc/net/tcp[6] and /proc/net/udp[6]
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn list_tcp_connections() -> Result<Vec<RawTcpConnection>, NetopError> {
    let mut conns = Vec::new();
    for (path, is_v6) in &[("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(content) = std::fs::read_to_string(path) {
            parse_proc_net_tcp(&content, *is_v6, &mut conns);
        }
    }
    Ok(conns)
}

#[cfg(target_os = "linux")]
pub fn list_udp_connections() -> Result<Vec<RawUdpConnection>, NetopError> {
    let mut conns = Vec::new();
    for (path, is_v6) in &[("/proc/net/udp", false), ("/proc/net/udp6", true)] {
        if let Ok(content) = std::fs::read_to_string(path) {
            parse_proc_net_udp(&content, *is_v6, &mut conns);
        }
    }
    Ok(conns)
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(content: &str, is_v6: bool, out: &mut Vec<RawTcpConnection>) {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let parse_addr = if is_v6 {
            crate::process::linux::parse_addr_v6
        } else {
            crate::process::linux::parse_addr_v4
        };

        let (local_addr, local_port) = match parse_addr(fields[1]) {
            Some(v) => v,
            None => continue,
        };
        let (remote_addr, remote_port) = match parse_addr(fields[2]) {
            Some(v) => v,
            None => continue,
        };

        let tcp_state = u8::from_str_radix(fields[3], 16).unwrap_or(0);

        out.push(RawTcpConnection {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            tcp_state: tcp_state as i32,
            if_index: 0,
        });
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_udp(content: &str, is_v6: bool, out: &mut Vec<RawUdpConnection>) {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }

        let parse_addr = if is_v6 {
            crate::process::linux::parse_addr_v6
        } else {
            crate::process::linux::parse_addr_v4
        };

        let (local_addr, local_port) = match parse_addr(fields[1]) {
            Some(v) => v,
            None => continue,
        };
        let (remote_addr, remote_port) = match parse_addr(fields[2]) {
            Some(v) => v,
            None => continue,
        };

        out.push(RawUdpConnection {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            if_index: 0,
        });
    }
}

// ---------------------------------------------------------------------------
// Windows: GetExtendedTcpTable / GetExtendedUdpTable
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn list_tcp_connections() -> Result<Vec<RawTcpConnection>, NetopError> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let mut conns = Vec::new();

    // IPv4 TCP
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size > 0 {
        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if ret == 0 {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
                as *const MIB_TCPROW_OWNER_PID;
            for i in 0..count {
                let row = unsafe { &*rows_ptr.add(i) };
                conns.push(RawTcpConnection {
                    local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    local_port: u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes()),
                    remote_addr: IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
                    remote_port: u16::from_be_bytes((row.dwRemotePort as u16).to_ne_bytes()),
                    tcp_state: row.dwState as i32,
                    if_index: 0,
                });
            }
        }
    }

    // IPv6 TCP
    size = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size > 0 {
        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if ret == 0 {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
                as *const MIB_TCP6ROW_OWNER_PID;
            for i in 0..count {
                let row = unsafe { &*rows_ptr.add(i) };
                conns.push(RawTcpConnection {
                    local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    local_port: u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes()),
                    remote_addr: IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                    remote_port: u16::from_be_bytes((row.dwRemotePort as u16).to_ne_bytes()),
                    tcp_state: row.dwState as i32,
                    if_index: 0,
                });
            }
        }
    }

    Ok(conns)
}

#[cfg(target_os = "windows")]
pub fn list_udp_connections() -> Result<Vec<RawUdpConnection>, NetopError> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
        MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let mut conns = Vec::new();

    // IPv4 UDP
    let mut size: u32 = 0;
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size > 0 {
        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if ret == 0 {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
                as *const MIB_UDPROW_OWNER_PID;
            for i in 0..count {
                let row = unsafe { &*rows_ptr.add(i) };
                conns.push(RawUdpConnection {
                    local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    local_port: u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes()),
                    remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    remote_port: 0,
                    if_index: 0,
                });
            }
        }
    }

    // IPv6 UDP
    size = 0;
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size > 0 {
        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if ret == 0 {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
                as *const MIB_UDP6ROW_OWNER_PID;
            for i in 0..count {
                let row = unsafe { &*rows_ptr.add(i) };
                conns.push(RawUdpConnection {
                    local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    local_port: u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes()),
                    remote_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    remote_port: 0,
                    if_index: 0,
                });
            }
        }
    }

    Ok(conns)
}
