// Linux process table — reads /proc to build socket-to-process mapping.
//
// 1. Parse /proc/net/tcp[6] and /proc/net/udp[6] → inode → socket 5-tuple
// 2. Iterate /proc/<pid>/fd/ → readlink → match "socket:[INODE]" → inode → (pid, name)
// 3. Join both maps to build ProcessTable

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::model::traffic::{ProcessInfo, ProcessTable, SocketKey};

/// Build a process table mapping normalized socket keys to process info.
pub fn build_process_table() -> ProcessTable {
    let mut table = ProcessTable::default();

    // Step 1: Parse /proc/net/* to get inode → socket info
    let mut inode_to_socket: HashMap<u64, SocketEntry> = HashMap::new();
    for (path, proto) in &[
        ("/proc/net/tcp", 6u8),
        ("/proc/net/tcp6", 6u8),
        ("/proc/net/udp", 17u8),
        ("/proc/net/udp6", 17u8),
    ] {
        if let Ok(entries) = parse_proc_net(path, *proto) {
            for entry in entries {
                inode_to_socket.insert(entry.inode, entry);
            }
        }
    }

    if inode_to_socket.is_empty() {
        return table;
    }

    // Step 2: Map inodes to PIDs by scanning /proc/<pid>/fd/
    let inode_to_pid = map_inodes_to_pids(&inode_to_socket);

    // Step 3: Join to build ProcessTable
    for (inode, (pid, name)) in &inode_to_pid {
        if let Some(sock) = inode_to_socket.get(inode) {
            let key = SocketKey::new(
                sock.local_addr,
                sock.local_port,
                sock.remote_addr,
                sock.remote_port,
                sock.proto,
            );
            table.insert(
                key,
                ProcessInfo {
                    pid: *pid,
                    name: name.clone(),
                },
            );
        }
    }

    table
}

pub(crate) struct SocketEntry {
    inode: u64,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    proto: u8,
}

/// Parse a /proc/net/* file (tcp, tcp6, udp, udp6).
///
/// Each line after the header has the format:
///   sl  local_address rem_address st tx_queue:rx_queue ... inode ...
///
/// Fields are whitespace-separated. We need fields 1 (local), 2 (remote), 9 (inode).
pub(crate) fn parse_proc_net(path: &str, proto: u8) -> Result<Vec<SocketEntry>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    let is_v6 = path.ends_with('6');
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        let inode_str = fields[9];

        let inode: u64 = match inode_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // inode 0 means no socket
        if inode == 0 {
            continue;
        }

        let (local_addr, local_port) = if is_v6 {
            match parse_addr_v6(local) {
                Some(v) => v,
                None => continue,
            }
        } else {
            match parse_addr_v4(local) {
                Some(v) => v,
                None => continue,
            }
        };

        let (remote_addr, remote_port) = if is_v6 {
            match parse_addr_v6(remote) {
                Some(v) => v,
                None => continue,
            }
        } else {
            match parse_addr_v4(remote) {
                Some(v) => v,
                None => continue,
            }
        };

        entries.push(SocketEntry {
            inode,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            proto,
        });
    }

    Ok(entries)
}

/// Parse an IPv4 address from /proc/net/tcp format: "AABBCCDD:PORT"
///
/// The hex address is in host byte order (little-endian on x86/ARM).
pub(crate) fn parse_addr_v4(s: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    // /proc/net stores IPv4 in host byte order (little-endian on LE systems),
    // but we need network byte order. Use swap_bytes on little-endian.
    let ip = Ipv4Addr::from(raw.swap_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((IpAddr::V4(ip), port))
}

/// Parse an IPv6 address from /proc/net/tcp6 format: "00000000000000000000000001000000:PORT"
///
/// The 32-char hex is 4 groups of 8 chars, each in host byte order.
pub(crate) fn parse_addr_v6(s: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // Parse as 4 x u32, each in host byte order
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let chunk = &addr_hex[i * 8..(i + 1) * 8];
        let raw = u32::from_str_radix(chunk, 16).ok()?;
        let bytes = raw.swap_bytes().to_be_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    let ip = Ipv6Addr::from(octets);
    Some((IpAddr::V6(ip), port))
}

/// Parse a readlink result like "socket:[12345]" → Some(12345)
pub(crate) fn parse_socket_inode(link: &str) -> Option<u64> {
    let s = link.strip_prefix("socket:[")?;
    let s = s.strip_suffix(']')?;
    s.parse().ok()
}

/// Scan /proc/<pid>/fd/ directories to map socket inodes to (pid, name).
fn map_inodes_to_pids(inode_to_socket: &HashMap<u64, SocketEntry>) -> HashMap<u64, (u32, String)> {
    let mut result = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return result,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric directories (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");

        // Read fd directory — may fail with EACCES for other users' processes
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let mut found_socket = false;
        for fd_entry in fd_entries.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };

            let link_str = link.to_string_lossy();
            if let Some(inode) = parse_socket_inode(&link_str)
                && inode_to_socket.contains_key(&inode)
            {
                if !found_socket {
                    found_socket = true;
                }
                let proc_name = read_proc_comm(pid);
                result.insert(inode, (pid, proc_name));
            }
        }
    }

    result
}

/// Read /proc/<pid>/comm to get the process name.
fn read_proc_comm(pid: u32) -> String {
    let path = format!("/proc/{pid}/comm");
    match fs::read_to_string(Path::new(&path)) {
        Ok(s) => s.trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Convert a Linux /proc/net/tcp hex state to our SocketState.
///
/// State values from include/net/tcp_states.h:
///   01=ESTABLISHED, 02=SYN_SENT, 03=SYN_RECV, 04=FIN_WAIT1,
///   05=FIN_WAIT2, 06=TIME_WAIT, 07=CLOSE, 08=CLOSE_WAIT,
///   09=LAST_ACK, 0A=LISTEN, 0B=CLOSING
pub(crate) fn tcp_state_from_hex(hex_state: u8) -> crate::model::SocketState {
    use crate::model::SocketState;
    match hex_state {
        0x01 => SocketState::Established,
        0x02 => SocketState::SynSent,
        0x03 => SocketState::SynReceived,
        0x04 => SocketState::FinWait1,
        0x05 => SocketState::FinWait2,
        0x06 => SocketState::TimeWait,
        0x07 => SocketState::Closed,
        0x08 => SocketState::CloseWait,
        0x09 => SocketState::LastAck,
        0x0A => SocketState::Listen,
        0x0B => SocketState::Closing,
        _ => SocketState::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_loopback() {
        // "0100007F" → 127.0.0.1 (little-endian: 0x7F000001 stored as 0100007F)
        let (addr, port) = parse_addr_v4("0100007F:0035").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 53);
    }

    #[test]
    fn parse_ipv4_any() {
        let (addr, port) = parse_addr_v4("00000000:0050").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_ipv4_real_address() {
        // 192.168.1.100 = C0A80164 in network order
        // In /proc, stored as little-endian: 6401A8C0
        let (addr, port) = parse_addr_v4("6401A8C0:1F90").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_ipv6_loopback() {
        // ::1 in /proc format: each 4-byte group is little-endian
        // ::1 = 00000000 00000000 00000000 01000000
        let (addr, port) = parse_addr_v6("00000000000000000000000001000000:0035").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 53);
    }

    #[test]
    fn parse_ipv6_any() {
        let (addr, port) = parse_addr_v6("00000000000000000000000000000000:0050").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_socket_inode_valid() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("socket:[0]"), Some(0));
        assert_eq!(parse_socket_inode("socket:[999999999]"), Some(999999999));
    }

    #[test]
    fn parse_socket_inode_invalid() {
        assert_eq!(parse_socket_inode("pipe:[12345]"), None);
        assert_eq!(parse_socket_inode("socket:12345"), None);
        assert_eq!(parse_socket_inode("anon_inode:[eventpoll]"), None);
    }

    #[test]
    fn parse_proc_net_tcp_line() {
        // Real /proc/net/tcp line format (slightly simplified)
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 6401A8C0:01BB 0200000A:C350 01 00000000:00000000 02:000006C0 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1
";
        // Write a temp file and parse
        let dir = std::env::temp_dir();
        let path = dir.join("test_proc_net_tcp");
        std::fs::write(&path, content).unwrap();

        let entries = parse_proc_net(path.to_str().unwrap(), 6).unwrap();
        assert_eq!(entries.len(), 2);

        // First entry: 127.0.0.1:53 → 0.0.0.0:0, inode 12345
        assert_eq!(
            entries[0].local_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(entries[0].inode, 12345);
        assert_eq!(entries[0].proto, 6);

        // Second entry: 192.168.1.100:443 → 10.0.0.2:50000, inode 67890
        assert_eq!(
            entries[1].local_addr,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(entries[1].local_port, 443);
        assert_eq!(
            entries[1].remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(entries[1].remote_port, 50000);
        assert_eq!(entries[1].inode, 67890);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tcp_state_mapping() {
        use crate::model::SocketState;
        assert_eq!(tcp_state_from_hex(0x01), SocketState::Established);
        assert_eq!(tcp_state_from_hex(0x0A), SocketState::Listen);
        assert_eq!(tcp_state_from_hex(0x06), SocketState::TimeWait);
        assert_eq!(tcp_state_from_hex(0x08), SocketState::CloseWait);
        assert_eq!(tcp_state_from_hex(0xFF), SocketState::Closed);
    }
}
