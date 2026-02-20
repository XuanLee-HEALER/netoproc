// Windows process table — uses IP Helper API for socket-to-PID mapping.
//
// Windows provides GetExtendedTcpTable/GetExtendedUdpTable which directly
// return socket → owning PID mappings. This is simpler than Linux (inode
// correlation) or macOS (libproc per-process FD scan).
//
// Process names are obtained via CreateToolhelp32Snapshot.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use crate::model::traffic::{ProcessInfo, ProcessTable, SocketKey};

/// Build a process table mapping normalized socket keys to process info.
///
/// Uses GetExtendedTcpTable and GetExtendedUdpTable to get socket-to-PID
/// mappings, then CreateToolhelp32Snapshot for process names.
pub fn build_process_table() -> ProcessTable {
    let mut table = ProcessTable::default();

    // Build PID → process name map
    let pid_names = build_pid_name_map();

    // TCP IPv4 connections
    if let Some(tcp4) = get_tcp4_table() {
        for row in &tcp4 {
            let local_ip = IpAddr::V4(Ipv4Addr::from(row.local_addr.to_ne_bytes()));
            let remote_ip = IpAddr::V4(Ipv4Addr::from(row.remote_addr.to_ne_bytes()));
            let local_port = u16::from_be_bytes((row.local_port as u16).to_ne_bytes());
            let remote_port = u16::from_be_bytes((row.remote_port as u16).to_ne_bytes());

            let key = SocketKey::new(local_ip, local_port, remote_ip, remote_port, 6);
            let name = pid_names
                .get(&row.pid)
                .cloned()
                .unwrap_or_default();
            table.insert(
                key,
                ProcessInfo {
                    pid: row.pid,
                    name,
                },
            );
        }
    }

    // TCP IPv6 connections
    if let Some(tcp6) = get_tcp6_table() {
        for row in &tcp6 {
            let local_ip = IpAddr::V6(Ipv6Addr::from(row.local_addr));
            let remote_ip = IpAddr::V6(Ipv6Addr::from(row.remote_addr));
            let local_port = u16::from_be_bytes((row.local_port as u16).to_ne_bytes());
            let remote_port = u16::from_be_bytes((row.remote_port as u16).to_ne_bytes());

            let key = SocketKey::new(local_ip, local_port, remote_ip, remote_port, 6);
            let name = pid_names
                .get(&row.pid)
                .cloned()
                .unwrap_or_default();
            table.insert(
                key,
                ProcessInfo {
                    pid: row.pid,
                    name,
                },
            );
        }
    }

    // UDP IPv4 endpoints
    if let Some(udp4) = get_udp4_table() {
        for row in &udp4 {
            let local_ip = IpAddr::V4(Ipv4Addr::from(row.local_addr.to_ne_bytes()));
            let local_port = u16::from_be_bytes((row.local_port as u16).to_ne_bytes());

            let key = SocketKey::new(
                local_ip,
                local_port,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                17,
            );
            let name = pid_names
                .get(&row.pid)
                .cloned()
                .unwrap_or_default();
            table.insert(
                key,
                ProcessInfo {
                    pid: row.pid,
                    name,
                },
            );
        }
    }

    // UDP IPv6 endpoints
    if let Some(udp6) = get_udp6_table() {
        for row in &udp6 {
            let local_ip = IpAddr::V6(Ipv6Addr::from(row.local_addr));
            let local_port = u16::from_be_bytes((row.local_port as u16).to_ne_bytes());

            let key = SocketKey::new(
                local_ip,
                local_port,
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                0,
                17,
            );
            let name = pid_names
                .get(&row.pid)
                .cloned()
                .unwrap_or_default();
            table.insert(
                key,
                ProcessInfo {
                    pid: row.pid,
                    name,
                },
            );
        }
    }

    table
}

// ---------------------------------------------------------------------------
// TCP table helpers
// ---------------------------------------------------------------------------

struct TcpRow4 {
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    pid: u32,
}

struct TcpRow6 {
    local_addr: [u8; 16],
    local_port: u32,
    remote_addr: [u8; 16],
    remote_port: u32,
    pid: u32,
}

struct UdpRow4 {
    local_addr: u32,
    local_port: u32,
    pid: u32,
}

struct UdpRow6 {
    local_addr: [u8; 16],
    local_port: u32,
    pid: u32,
}

fn get_tcp4_table() -> Option<Vec<TcpRow4>> {
    let mut size: u32 = 0;

    // First call: get required buffer size
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0, // no sort
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    if size == 0 {
        return None;
    }

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

    if ret != 0 {
        return None;
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
        as *const MIB_TCPROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*rows_ptr.add(i) };
        result.push(TcpRow4 {
            local_addr: row.dwLocalAddr,
            local_port: row.dwLocalPort,
            remote_addr: row.dwRemoteAddr,
            remote_port: row.dwRemotePort,
            pid: row.dwOwningPid,
        });
    }
    Some(result)
}

fn get_tcp6_table() -> Option<Vec<TcpRow6>> {
    let mut size: u32 = 0;

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

    if size == 0 {
        return None;
    }

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

    if ret != 0 {
        return None;
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
        as *const MIB_TCP6ROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*rows_ptr.add(i) };
        result.push(TcpRow6 {
            local_addr: row.ucLocalAddr,
            local_port: row.dwLocalPort,
            remote_addr: row.ucRemoteAddr,
            remote_port: row.dwRemotePort,
            pid: row.dwOwningPid,
        });
    }
    Some(result)
}

fn get_udp4_table() -> Option<Vec<UdpRow4>> {
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

    if size == 0 {
        return None;
    }

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

    if ret != 0 {
        return None;
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
        as *const MIB_UDPROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*rows_ptr.add(i) };
        result.push(UdpRow4 {
            local_addr: row.dwLocalAddr,
            local_port: row.dwLocalPort,
            pid: row.dwOwningPid,
        });
    }
    Some(result)
}

fn get_udp6_table() -> Option<Vec<UdpRow6>> {
    let mut size: u32 = 0;

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

    if size == 0 {
        return None;
    }

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

    if ret != 0 {
        return None;
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
        as *const MIB_UDP6ROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let row = unsafe { &*rows_ptr.add(i) };
        result.push(UdpRow6 {
            local_addr: row.ucLocalAddr,
            local_port: row.dwLocalPort,
            pid: row.dwOwningPid,
        });
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Process name resolution
// ---------------------------------------------------------------------------

/// Build a PID → process name mapping using CreateToolhelp32Snapshot.
fn build_pid_name_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return map;
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot, &mut entry) } != 0 {
        loop {
            let name = exe_file_to_string(&entry.szExeFile);
            map.insert(entry.th32ProcessID, name);

            if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    map
}

/// Convert PROCESSENTRY32.szExeFile (i8/u8 array) to a Rust String.
fn exe_file_to_string(bytes: &[i8]) -> String {
    let as_u8: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u8, bytes.len()) };
    let len = as_u8.iter().position(|&b| b == 0).unwrap_or(as_u8.len());
    String::from_utf8_lossy(&as_u8[..len]).into_owned()
}
