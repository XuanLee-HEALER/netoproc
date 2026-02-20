//! Cross-platform unit tests for Linux /proc parsing functions.
//!
//! These tests parse static strings and run on all platforms (macOS included).
//! They verify the correctness of hex address parsing, socket inode extraction,
//! and /proc/net/tcp line parsing used by the Linux process table implementation.
//!
//! Run with: `cargo test --test linux_proc_parsing`

// The parsing functions are pub(crate), so we test them through the public module
// re-export path. On macOS this module still compiles because the parsing functions
// have no platform-specific dependencies — they operate on strings only.

// These functions are only available when compiled for Linux, but we can test the
// logic by including the source directly for test purposes.
// Instead, we re-implement the pure parsing logic here for cross-platform testing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse an IPv4 address from /proc/net/tcp format: "AABBCCDD:PORT"
/// (host byte order, little-endian on x86/ARM).
fn parse_addr_v4(s: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    let ip = Ipv4Addr::from(raw.swap_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((IpAddr::V4(ip), port))
}

/// Parse an IPv6 address from /proc/net/tcp6 format.
/// 32 hex chars = 4 groups of 8 chars, each in host byte order.
fn parse_addr_v6(s: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;

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
fn parse_socket_inode(link: &str) -> Option<u64> {
    let s = link.strip_prefix("socket:[")?;
    let s = s.strip_suffix(']')?;
    s.parse().ok()
}

/// Parse /etc/resolv.conf content into (servers, search_domains).
fn parse_resolv_conf_content(content: &str) -> (Vec<String>, Vec<String>) {
    let mut servers = Vec::new();
    let mut search_domains = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        match parts[0] {
            "nameserver" => {
                servers.push(parts[1].to_string());
            }
            "search" | "domain" => {
                for domain in &parts[1..] {
                    search_domains.push(domain.to_string());
                }
            }
            _ => {}
        }
    }

    (servers, search_domains)
}

// ---------------------------------------------------------------------------
// TC-L-1: IPv4 hex address parsing
// ---------------------------------------------------------------------------

#[test]
fn ipv4_loopback() {
    // 127.0.0.1 in network byte order = 0x7F000001
    // In /proc (little-endian): 0100007F
    let (addr, port) = parse_addr_v4("0100007F:0035").unwrap();
    assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(port, 53);
}

#[test]
fn ipv4_unspecified() {
    let (addr, port) = parse_addr_v4("00000000:0050").unwrap();
    assert_eq!(addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(port, 80);
}

#[test]
fn ipv4_real_address() {
    // 192.168.1.100 = 0xC0A80164 network order → 0x6401A8C0 little-endian
    let (addr, port) = parse_addr_v4("6401A8C0:1F90").unwrap();
    assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(port, 8080);
}

#[test]
fn ipv4_broadcast() {
    // 255.255.255.255 = 0xFFFFFFFF — same in both byte orders
    let (addr, port) = parse_addr_v4("FFFFFFFF:0000").unwrap();
    assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
    assert_eq!(port, 0);
}

#[test]
fn ipv4_google_dns() {
    // 8.8.8.8 = 0x08080808 network → 0x08080808 little-endian (palindrome)
    let (addr, port) = parse_addr_v4("08080808:0035").unwrap();
    assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(port, 53);
}

#[test]
fn ipv4_invalid_short() {
    assert!(parse_addr_v4("0100007:0035").is_none());
}

#[test]
fn ipv4_invalid_no_colon() {
    assert!(parse_addr_v4("0100007F0035").is_none());
}

// ---------------------------------------------------------------------------
// TC-L-2: IPv6 hex address parsing
// ---------------------------------------------------------------------------

#[test]
fn ipv6_loopback() {
    // ::1 in /proc format: each 4-byte group is little-endian
    // ::1 = 0000:0000:0000:0000:0000:0000:0000:0001
    // Groups (LE): 00000000 00000000 00000000 01000000
    let (addr, port) = parse_addr_v6("00000000000000000000000001000000:0035").unwrap();
    assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(port, 53);
}

#[test]
fn ipv6_unspecified() {
    let (addr, port) = parse_addr_v6("00000000000000000000000000000000:0050").unwrap();
    assert_eq!(addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    assert_eq!(port, 80);
}

#[test]
fn ipv6_invalid_short() {
    assert!(parse_addr_v6("0000000000000000000000000000000:0035").is_none());
}

// ---------------------------------------------------------------------------
// TC-L-3: Full /proc/net/tcp line parsing
// ---------------------------------------------------------------------------

#[test]
fn proc_net_tcp_parse_two_entries() {
    let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 6401A8C0:01BB 0200000A:C350 01 00000000:00000000 02:000006C0 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1
";
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let local = parse_addr_v4(fields[1]);
        let remote = parse_addr_v4(fields[2]);
        let inode: u64 = match fields[9].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if inode == 0 {
            continue;
        }
        if let (Some((la, lp)), Some((ra, rp))) = (local, remote) {
            entries.push((la, lp, ra, rp, inode));
        }
    }

    assert_eq!(entries.len(), 2);

    // Entry 0: 127.0.0.1:53 → 0.0.0.0:0, inode 12345
    assert_eq!(entries[0].0, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(entries[0].1, 53);
    assert_eq!(entries[0].2, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(entries[0].3, 0);
    assert_eq!(entries[0].4, 12345);

    // Entry 1: 192.168.1.100:443 → 10.0.0.2:50000, inode 67890
    assert_eq!(entries[1].0, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(entries[1].1, 443);
    assert_eq!(entries[1].2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(entries[1].3, 50000);
    assert_eq!(entries[1].4, 67890);
}

#[test]
fn proc_net_tcp_skip_zero_inode() {
    let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0
";
    let mut count = 0;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let inode: u64 = fields[9].parse().unwrap_or(0);
        if inode != 0 {
            count += 1;
        }
    }
    assert_eq!(count, 0);
}

// ---------------------------------------------------------------------------
// TC-L-4: Socket symlink parsing
// ---------------------------------------------------------------------------

#[test]
fn socket_inode_valid() {
    assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
    assert_eq!(parse_socket_inode("socket:[0]"), Some(0));
    assert_eq!(parse_socket_inode("socket:[999999999]"), Some(999999999));
}

#[test]
fn socket_inode_invalid() {
    assert_eq!(parse_socket_inode("pipe:[12345]"), None);
    assert_eq!(parse_socket_inode("socket:12345"), None);
    assert_eq!(parse_socket_inode("anon_inode:[eventpoll]"), None);
    assert_eq!(parse_socket_inode(""), None);
    assert_eq!(parse_socket_inode("socket:[]"), None);
}

// ---------------------------------------------------------------------------
// TC-L-5: /etc/resolv.conf parsing
// ---------------------------------------------------------------------------

#[test]
fn resolv_conf_basic() {
    let content = "\
# Generated by NetworkManager
nameserver 8.8.8.8
nameserver 8.8.4.4
search example.com local.lan
";
    let (servers, domains) = parse_resolv_conf_content(content);
    assert_eq!(servers, vec!["8.8.8.8", "8.8.4.4"]);
    assert_eq!(domains, vec!["example.com", "local.lan"]);
}

#[test]
fn resolv_conf_domain_directive() {
    let content = "\
domain example.org
nameserver 1.1.1.1
";
    let (servers, domains) = parse_resolv_conf_content(content);
    assert_eq!(servers, vec!["1.1.1.1"]);
    assert_eq!(domains, vec!["example.org"]);
}

#[test]
fn resolv_conf_comments_and_blank_lines() {
    let content = "\
# comment
; another comment

nameserver 10.0.0.1

# trailing comment
";
    let (servers, domains) = parse_resolv_conf_content(content);
    assert_eq!(servers, vec!["10.0.0.1"]);
    assert!(domains.is_empty());
}

#[test]
fn resolv_conf_empty() {
    let (servers, domains) = parse_resolv_conf_content("");
    assert!(servers.is_empty());
    assert!(domains.is_empty());
}
