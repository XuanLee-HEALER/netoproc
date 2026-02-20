// Windows process table — uses IP Helper API for socket-to-PID mapping.
//
// Windows provides GetExtendedTcpTable/GetExtendedUdpTable which directly
// return socket → owning PID mappings. This is simpler than Linux (inode
// correlation) or macOS (libproc per-process FD scan).
//
// Process names are obtained via CreateToolhelp32Snapshot (Wide API).
//
// The `get_*_rows()` functions are shared by process/windows.rs,
// system/process.rs, and system/connection.rs to avoid duplicating
// the ~200-line table fetching pattern across three files.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
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
    for row in get_tcp4_rows() {
        let local_ip = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()));
        let remote_ip = IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()));
        let local_port = u16::from_be(row.dwLocalPort as u16);
        let remote_port = u16::from_be(row.dwRemotePort as u16);

        let key = SocketKey::new(local_ip, local_port, remote_ip, remote_port, 6);
        let name = pid_names.get(&row.dwOwningPid).cloned().unwrap_or_default();
        table.insert(
            key,
            ProcessInfo {
                pid: row.dwOwningPid,
                name,
            },
        );
    }

    // TCP IPv6 connections
    for row in get_tcp6_rows() {
        let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
        let remote_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
        let local_port = u16::from_be(row.dwLocalPort as u16);
        let remote_port = u16::from_be(row.dwRemotePort as u16);

        let key = SocketKey::new(local_ip, local_port, remote_ip, remote_port, 6);
        let name = pid_names.get(&row.dwOwningPid).cloned().unwrap_or_default();
        table.insert(
            key,
            ProcessInfo {
                pid: row.dwOwningPid,
                name,
            },
        );
    }

    // UDP IPv4 endpoints
    for row in get_udp4_rows() {
        let local_ip = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()));
        let local_port = u16::from_be(row.dwLocalPort as u16);

        let key = SocketKey::new(
            local_ip,
            local_port,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            17,
        );
        let name = pid_names.get(&row.dwOwningPid).cloned().unwrap_or_default();
        table.insert(
            key,
            ProcessInfo {
                pid: row.dwOwningPid,
                name,
            },
        );
    }

    // UDP IPv6 endpoints
    for row in get_udp6_rows() {
        let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
        let local_port = u16::from_be(row.dwLocalPort as u16);

        let key = SocketKey::new(
            local_ip,
            local_port,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            0,
            17,
        );
        let name = pid_names.get(&row.dwOwningPid).cloned().unwrap_or_default();
        table.insert(
            key,
            ProcessInfo {
                pid: row.dwOwningPid,
                name,
            },
        );
    }

    table
}

// ---------------------------------------------------------------------------
// Shared table row helpers (used by process, system/process, system/connection)
// ---------------------------------------------------------------------------

pub(crate) fn get_tcp4_rows() -> Vec<MIB_TCPROW_OWNER_PID> {
    let mut size: u32 = 0;

    // First call: get required buffer size
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

    if size == 0 {
        return Vec::new();
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
        log::warn!("GetExtendedTcpTable(AF_INET) failed: error {ret}");
        return Vec::new();
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let header_size = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    if header_size + count * row_size > buffer.len() {
        log::warn!("TCP4 table: dwNumEntries ({count}) exceeds buffer capacity");
        return Vec::new();
    }
    let rows_ptr = buffer.as_ptr().wrapping_add(header_size) as *const MIB_TCPROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(unsafe { *rows_ptr.add(i) });
    }
    result
}

pub(crate) fn get_tcp6_rows() -> Vec<MIB_TCP6ROW_OWNER_PID> {
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
        return Vec::new();
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
        log::warn!("GetExtendedTcpTable(AF_INET6) failed: error {ret}");
        return Vec::new();
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let header_size = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    if header_size + count * row_size > buffer.len() {
        log::warn!("TCP6 table: dwNumEntries ({count}) exceeds buffer capacity");
        return Vec::new();
    }
    let rows_ptr = buffer.as_ptr().wrapping_add(header_size) as *const MIB_TCP6ROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(unsafe { *rows_ptr.add(i) });
    }
    result
}

pub(crate) fn get_udp4_rows() -> Vec<MIB_UDPROW_OWNER_PID> {
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
        return Vec::new();
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
        log::warn!("GetExtendedUdpTable(AF_INET) failed: error {ret}");
        return Vec::new();
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let header_size = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
    if header_size + count * row_size > buffer.len() {
        log::warn!("UDP4 table: dwNumEntries ({count}) exceeds buffer capacity");
        return Vec::new();
    }
    let rows_ptr = buffer.as_ptr().wrapping_add(header_size) as *const MIB_UDPROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(unsafe { *rows_ptr.add(i) });
    }
    result
}

pub(crate) fn get_udp6_rows() -> Vec<MIB_UDP6ROW_OWNER_PID> {
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
        return Vec::new();
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
        log::warn!("GetExtendedUdpTable(AF_INET6) failed: error {ret}");
        return Vec::new();
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let header_size = std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();
    if header_size + count * row_size > buffer.len() {
        log::warn!("UDP6 table: dwNumEntries ({count}) exceeds buffer capacity");
        return Vec::new();
    }
    let rows_ptr = buffer.as_ptr().wrapping_add(header_size) as *const MIB_UDP6ROW_OWNER_PID;

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(unsafe { *rows_ptr.add(i) });
    }
    result
}

// ---------------------------------------------------------------------------
// Process name resolution (Wide API for Unicode support)
// ---------------------------------------------------------------------------

/// Build a PID → process name mapping using CreateToolhelp32Snapshot.
///
/// Uses the Wide (W) API variants to correctly handle non-ASCII process names.
pub(crate) fn build_pid_name_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        log::warn!("CreateToolhelp32Snapshot failed");
        return map;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let name = wide_to_string(&entry.szExeFile);
            map.insert(entry.th32ProcessID, name);

            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    map
}

/// Convert a null-terminated UTF-16 array to a Rust String.
pub(crate) fn wide_to_string(chars: &[u16]) -> String {
    let len = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
    String::from_utf16_lossy(&chars[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_to_string_normal_name() {
        let mut buf = [0u16; 260];
        let name: Vec<u16> = "chrome.exe".encode_utf16().collect();
        buf[..name.len()].copy_from_slice(&name);
        assert_eq!(wide_to_string(&buf), "chrome.exe");
    }

    #[test]
    fn wide_to_string_empty() {
        let buf = [0u16; 260];
        assert_eq!(wide_to_string(&buf), "");
    }

    #[test]
    fn wide_to_string_non_ascii() {
        let mut buf = [0u16; 260];
        let name: Vec<u16> = "测试程序.exe".encode_utf16().collect();
        buf[..name.len()].copy_from_slice(&name);
        assert_eq!(wide_to_string(&buf), "测试程序.exe");
    }

    #[test]
    fn wide_to_string_max_path() {
        let mut buf = [b'A' as u16; 260];
        buf[259] = 0;
        assert_eq!(wide_to_string(&buf).len(), 259);
    }

    #[test]
    fn port_conversion_roundtrip() {
        // Verify the port byte-order conversion for known ports
        for port in [0u16, 1, 22, 53, 80, 443, 8080, 8443, 65535] {
            // Simulate how Windows stores the port: network byte order in DWORD
            let be_bytes = port.to_be_bytes();
            let dw = u32::from_ne_bytes([be_bytes[0], be_bytes[1], 0, 0]);
            let result = u16::from_be(dw as u16);
            assert_eq!(result, port, "port {port} roundtrip failed");
        }
    }

    #[test]
    fn build_process_table_does_not_panic() {
        // On Windows, this calls real APIs. On non-Windows, this test
        // only compiles when targeting Windows.
        let table = build_process_table();
        let _ = table;
    }
}
