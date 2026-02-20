//! Cross-platform tests for Windows-specific logic.
//!
//! These tests verify the correctness of algorithms used in the Windows
//! compatibility layer. Where possible, they call actual production code
//! (e.g. packet parsing). For Windows-only APIs gated by `#[cfg(target_os)]`,
//! they necessarily re-implement the key logic so tests can run on any platform.
//!
//! Run with: `cargo test --test windows_compat`

use std::net::{IpAddr, Ipv4Addr};

// ---------------------------------------------------------------------------
// TC-W-1: Port byte order conversion
// ---------------------------------------------------------------------------
//
// Windows IP Helper API stores port numbers as DWORD in network byte order
// (big-endian). The conversion: u16::from_be(dwPort as u16).

/// Simulate Windows API port conversion: network byte order DWORD → host u16.
fn win_port_from_dword(dw_port: u32) -> u16 {
    u16::from_be(dw_port as u16)
}

/// Simulate storing a known port as a Windows DWORD (network byte order in u32).
fn port_to_win_dword(port: u16) -> u32 {
    // Network byte order (BE) port bytes stored in a little-endian u32.
    // On LE: port 80 → BE bytes [0x00, 0x50] → u32 with those bytes in low positions
    // = 0x00005000 on LE, = 0x00000050 on BE.
    let be_bytes = port.to_be_bytes();
    u32::from_ne_bytes([be_bytes[0], be_bytes[1], 0, 0])
}

#[test]
fn tc_w_1_1_port_80() {
    let dw = port_to_win_dword(80);
    assert_eq!(win_port_from_dword(dw), 80);
}

#[test]
fn tc_w_1_2_port_443() {
    let dw = port_to_win_dword(443);
    assert_eq!(win_port_from_dword(dw), 443);
}

#[test]
fn tc_w_1_3_port_53() {
    let dw = port_to_win_dword(53);
    assert_eq!(win_port_from_dword(dw), 53);
}

#[test]
fn tc_w_1_4_port_8080() {
    let dw = port_to_win_dword(8080);
    assert_eq!(win_port_from_dword(dw), 8080);
}

#[test]
fn tc_w_1_5_port_65535() {
    let dw = port_to_win_dword(65535);
    assert_eq!(win_port_from_dword(dw), 65535);
}

#[test]
fn tc_w_1_6_port_0() {
    let dw = port_to_win_dword(0);
    assert_eq!(win_port_from_dword(dw), 0);
}

#[test]
fn tc_w_1_7_port_1() {
    let dw = port_to_win_dword(1);
    assert_eq!(win_port_from_dword(dw), 1);
}

#[test]
fn tc_w_1_8_port_roundtrip_all_common() {
    for port in [
        22, 25, 53, 80, 110, 143, 443, 993, 3306, 5432, 6379, 8080, 8443, 27017,
    ] {
        let dw = port_to_win_dword(port);
        assert_eq!(
            win_port_from_dword(dw),
            port,
            "port {port} roundtrip failed"
        );
    }
}

// ---------------------------------------------------------------------------
// TC-W-2: Traffic filter (raw IP packet protocol filtering)
// ---------------------------------------------------------------------------
//
// The Windows capture layer receives raw IP packets (no Ethernet header).
// It must filter by protocol: accept TCP (6), UDP (17), ICMP/ICMPv6 (1/58).
//
// For IPv6, we use the actual skip_ipv6_extension_headers from packet.rs.

use netoproc::packet::skip_ipv6_extension_headers;

/// Re-implementation of the traffic filter logic from capture/windows.rs.
fn matches_traffic_filter(data: &[u8]) -> bool {
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
            let (final_proto, _) = skip_ipv6_extension_headers(next_hdr, &data[40..]);
            matches!(final_proto, 6 | 17 | 58) // TCP, UDP, ICMPv6
        }
        _ => false,
    }
}

/// Craft a minimal IPv4 packet with given protocol.
fn make_ipv4_packet(proto: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // version=4, IHL=5 (20 bytes)
    pkt[9] = proto;
    pkt
}

/// Craft a minimal IPv6 packet with given next_header.
fn make_ipv6_packet(next_hdr: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x60; // version=6
    pkt[6] = next_hdr;
    pkt
}

#[test]
fn tc_w_2_1_ipv4_tcp_accepted() {
    assert!(matches_traffic_filter(&make_ipv4_packet(6)));
}

#[test]
fn tc_w_2_2_ipv4_udp_accepted() {
    assert!(matches_traffic_filter(&make_ipv4_packet(17)));
}

#[test]
fn tc_w_2_3_ipv4_icmp_accepted() {
    assert!(matches_traffic_filter(&make_ipv4_packet(1)));
}

#[test]
fn tc_w_2_4_ipv4_gre_rejected() {
    assert!(!matches_traffic_filter(&make_ipv4_packet(47)));
}

#[test]
fn tc_w_2_5_ipv6_tcp_accepted() {
    assert!(matches_traffic_filter(&make_ipv6_packet(6)));
}

#[test]
fn tc_w_2_6_ipv6_udp_accepted() {
    assert!(matches_traffic_filter(&make_ipv6_packet(17)));
}

#[test]
fn tc_w_2_7_ipv6_icmpv6_accepted() {
    assert!(matches_traffic_filter(&make_ipv6_packet(58)));
}

#[test]
fn tc_w_2_8_ipv6_gre_rejected() {
    assert!(!matches_traffic_filter(&make_ipv6_packet(47)));
}

#[test]
fn tc_w_2_9_empty_packet_rejected() {
    assert!(!matches_traffic_filter(&[]));
}

#[test]
fn tc_w_2_10_truncated_ipv4_rejected() {
    assert!(!matches_traffic_filter(&[0x45; 10]));
}

#[test]
fn tc_w_2_11_truncated_ipv6_rejected() {
    assert!(!matches_traffic_filter(&[0x60; 20]));
}

#[test]
fn tc_w_2_12_invalid_version_rejected() {
    // Version 3 packet
    let pkt = vec![0x30; 40];
    assert!(!matches_traffic_filter(&pkt));
}

#[test]
fn tc_w_2_13_ipv6_with_hop_by_hop_then_tcp() {
    // IPv6 with Hop-by-Hop (type 0) extension header, then TCP
    let mut pkt = vec![0u8; 48]; // 40 (IPv6) + 8 (ext hdr)
    pkt[0] = 0x60; // version 6
    pkt[6] = 0; // next_header = Hop-by-Hop
    // Extension header starts at byte 40
    pkt[40] = 6; // next_header = TCP
    pkt[41] = 0; // hdr_ext_len = 0 → total 8 bytes
    assert!(matches_traffic_filter(&pkt));
}

#[test]
fn tc_w_2_14_ipv6_with_routing_then_udp() {
    // IPv6 with Routing (type 43) extension header, then UDP
    let mut pkt = vec![0u8; 48]; // 40 (IPv6) + 8 (ext hdr)
    pkt[0] = 0x60; // version 6
    pkt[6] = 43; // next_header = Routing
    pkt[40] = 17; // next_header = UDP
    pkt[41] = 0; // hdr_ext_len = 0
    assert!(matches_traffic_filter(&pkt));
}

#[test]
fn tc_w_2_15_ipv6_with_fragment_then_tcp() {
    // IPv6 with Fragment (type 44) header, then TCP
    let mut pkt = vec![0u8; 48]; // 40 (IPv6) + 8 (fragment hdr)
    pkt[0] = 0x60;
    pkt[6] = 44; // next_header = Fragment
    pkt[40] = 6; // next_header = TCP
    assert!(matches_traffic_filter(&pkt));
}

#[test]
fn tc_w_2_16_ipv6_chained_ext_headers() {
    // Hop-by-Hop → Routing → TCP
    let mut pkt = vec![0u8; 56]; // 40 + 8 + 8
    pkt[0] = 0x60;
    pkt[6] = 0; // Hop-by-Hop
    // First ext header (Hop-by-Hop) at 40
    pkt[40] = 43; // next = Routing
    pkt[41] = 0; // len = 0 → 8 bytes
    // Second ext header (Routing) at 48
    pkt[48] = 6; // next = TCP
    pkt[49] = 0; // len = 0 → 8 bytes
    assert!(matches_traffic_filter(&pkt));
}

// ---------------------------------------------------------------------------
// TC-W-3: DNS payload extraction from raw IP packets
// ---------------------------------------------------------------------------

/// Re-implementation of extract_dns_payload from capture/windows.rs.
fn extract_dns_payload(data: &[u8]) -> Option<&[u8]> {
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
            let (final_proto, ext_offset) = skip_ipv6_extension_headers(next_hdr, &data[40..]);
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

/// Craft a minimal IPv4+UDP DNS request packet (dst port 53).
fn make_dns_udp_request() -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + 4]; // IP + UDP hdr + 4 bytes DNS payload
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[9] = 17; // UDP
    // UDP header at offset 20
    pkt[20] = 0xC0; // src_port high byte (49152)
    pkt[21] = 0x00; // src_port low byte
    pkt[22] = 0x00; // dst_port = 53
    pkt[23] = 0x35;
    // DNS payload starts at 28
    pkt[28] = 0xAB;
    pkt[29] = 0xCD;
    pkt[30] = 0xEF;
    pkt[31] = 0x01;
    pkt
}

/// Craft a minimal IPv4+UDP DNS response packet (src port 53).
fn make_dns_udp_response() -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + 4];
    pkt[0] = 0x45;
    pkt[9] = 17;
    pkt[20] = 0x00; // src_port = 53
    pkt[21] = 0x35;
    pkt[22] = 0xC0; // dst_port = 49152
    pkt[23] = 0x00;
    pkt[28] = 0x12;
    pkt[29] = 0x34;
    pkt[30] = 0x56;
    pkt[31] = 0x78;
    pkt
}

#[test]
fn tc_w_3_1_udp_dns_request() {
    let pkt = make_dns_udp_request();
    let payload = extract_dns_payload(&pkt).expect("should extract DNS payload");
    assert_eq!(payload, &[0xAB, 0xCD, 0xEF, 0x01]);
}

#[test]
fn tc_w_3_2_udp_dns_response() {
    let pkt = make_dns_udp_response();
    let payload = extract_dns_payload(&pkt).expect("should extract DNS payload");
    assert_eq!(payload, &[0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn tc_w_3_3_non_dns_udp_rejected() {
    let mut pkt = vec![0u8; 20 + 8 + 4];
    pkt[0] = 0x45;
    pkt[9] = 17;
    // Ports 8080 → 80 (not DNS)
    pkt[20] = 0x1F;
    pkt[21] = 0x90;
    pkt[22] = 0x00;
    pkt[23] = 0x50;
    assert!(extract_dns_payload(&pkt).is_none());
}

#[test]
fn tc_w_3_4_truncated_packet_rejected() {
    let pkt = vec![0x45; 10]; // Too short for IPv4
    assert!(extract_dns_payload(&pkt).is_none());
}

#[test]
fn tc_w_3_5_ipv6_udp_dns() {
    let mut pkt = vec![0u8; 40 + 8 + 4]; // IPv6 + UDP + payload
    pkt[0] = 0x60; // version 6
    pkt[6] = 17; // UDP
    // UDP header at offset 40
    pkt[40] = 0x00; // src_port = 53
    pkt[41] = 0x35;
    pkt[42] = 0xC0; // dst_port = 49152
    pkt[43] = 0x00;
    // DNS payload at 48
    pkt[48] = 0xDE;
    pkt[49] = 0xAD;
    pkt[50] = 0xBE;
    pkt[51] = 0xEF;
    let payload = extract_dns_payload(&pkt).expect("should extract IPv6 DNS payload");
    assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn tc_w_3_6_empty_packet_rejected() {
    assert!(extract_dns_payload(&[]).is_none());
}

#[test]
fn tc_w_3_7_icmp_ignored() {
    // ICMP packet with port-like data should be ignored
    let pkt = make_ipv4_packet(1); // ICMP
    assert!(extract_dns_payload(&pkt).is_none());
}

// ---------------------------------------------------------------------------
// TC-W-4: Windows TCP state mapping
// ---------------------------------------------------------------------------
//
// Windows MIB_TCP_STATE values differ from Linux/macOS:
// 1=CLOSED, 2=LISTEN, 3=SYN_SENT, ..., 12=DELETE_TCB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Re-implementation of tcp_state_to_socket_state from system/process.rs.
fn win_tcp_state(state: i32) -> SocketState {
    match state {
        1 => SocketState::Closed,
        2 => SocketState::Listen,
        3 => SocketState::SynSent,
        4 => SocketState::SynReceived,
        5 => SocketState::Established,
        6 => SocketState::FinWait1,
        7 => SocketState::FinWait2,
        8 => SocketState::CloseWait,
        9 => SocketState::Closing,
        10 => SocketState::LastAck,
        11 => SocketState::TimeWait,
        _ => SocketState::Closed,
    }
}

#[test]
fn tc_w_4_1_all_valid_states() {
    assert_eq!(win_tcp_state(1), SocketState::Closed);
    assert_eq!(win_tcp_state(2), SocketState::Listen);
    assert_eq!(win_tcp_state(3), SocketState::SynSent);
    assert_eq!(win_tcp_state(4), SocketState::SynReceived);
    assert_eq!(win_tcp_state(5), SocketState::Established);
    assert_eq!(win_tcp_state(6), SocketState::FinWait1);
    assert_eq!(win_tcp_state(7), SocketState::FinWait2);
    assert_eq!(win_tcp_state(8), SocketState::CloseWait);
    assert_eq!(win_tcp_state(9), SocketState::Closing);
    assert_eq!(win_tcp_state(10), SocketState::LastAck);
    assert_eq!(win_tcp_state(11), SocketState::TimeWait);
}

#[test]
fn tc_w_4_2_delete_tcb_maps_to_closed() {
    assert_eq!(win_tcp_state(12), SocketState::Closed);
}

#[test]
fn tc_w_4_3_unknown_states_map_to_closed() {
    assert_eq!(win_tcp_state(0), SocketState::Closed);
    assert_eq!(win_tcp_state(13), SocketState::Closed);
    assert_eq!(win_tcp_state(-1), SocketState::Closed);
    assert_eq!(win_tcp_state(255), SocketState::Closed);
}

// ---------------------------------------------------------------------------
// TC-W-5: Process name extraction from null-terminated wide (u16) array
// ---------------------------------------------------------------------------
//
// Windows PROCESSENTRY32W.szExeFile is a [u16; 260] (MAX_PATH) array.
// The wide_to_string function converts it to a Rust String.

fn wide_to_string(chars: &[u16]) -> String {
    let len = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
    String::from_utf16_lossy(&chars[..len])
}

#[test]
fn tc_w_5_1_normal_exe_name() {
    let mut buf = [0u16; 260];
    let name: Vec<u16> = "chrome.exe".encode_utf16().collect();
    buf[..name.len()].copy_from_slice(&name);
    assert_eq!(wide_to_string(&buf), "chrome.exe");
}

#[test]
fn tc_w_5_2_all_null_returns_empty() {
    let buf = [0u16; 260];
    assert_eq!(wide_to_string(&buf), "");
}

#[test]
fn tc_w_5_3_no_null_terminator() {
    // Fill entire buffer with non-null values
    let buf = [b'A' as u16; 32];
    assert_eq!(wide_to_string(&buf), "A".repeat(32));
}

#[test]
fn tc_w_5_4_embedded_null() {
    let mut buf = [0u16; 260];
    let name: Vec<u16> = "svc".encode_utf16().collect();
    buf[..name.len()].copy_from_slice(&name);
    buf[3] = 0; // null terminator
    buf[4] = b'x' as u16; // should be ignored
    assert_eq!(wide_to_string(&buf), "svc");
}

#[test]
fn tc_w_5_5_non_ascii_unicode() {
    let mut buf = [0u16; 260];
    let name: Vec<u16> = "测试.exe".encode_utf16().collect();
    buf[..name.len()].copy_from_slice(&name);
    assert_eq!(wide_to_string(&buf), "测试.exe");
}

// ---------------------------------------------------------------------------
// TC-W-6: Interface flags (is_up, is_loopback)
// ---------------------------------------------------------------------------

use netoproc::system::interface::RawInterface;

#[test]
fn tc_w_6_1_is_up_with_flag() {
    let iface = RawInterface {
        name: "eth0".into(),
        flags: 0x1, // FLAG_UP
        ..Default::default()
    };
    assert!(iface.is_up());
    assert!(!iface.is_loopback());
}

#[test]
fn tc_w_6_2_is_loopback_with_flag() {
    let iface = RawInterface {
        name: "lo".into(),
        flags: 0x8, // FLAG_LOOPBACK
        ..Default::default()
    };
    assert!(!iface.is_up());
    assert!(iface.is_loopback());
}

#[test]
fn tc_w_6_3_both_flags() {
    let iface = RawInterface {
        name: "lo".into(),
        flags: 0x9, // FLAG_UP | FLAG_LOOPBACK
        ..Default::default()
    };
    assert!(iface.is_up());
    assert!(iface.is_loopback());
}

#[test]
fn tc_w_6_4_no_flags() {
    let iface = RawInterface {
        name: "eth1".into(),
        flags: 0x0,
        ..Default::default()
    };
    assert!(!iface.is_up());
    assert!(!iface.is_loopback());
}

#[test]
fn tc_w_6_5_other_flags_dont_interfere() {
    let iface = RawInterface {
        name: "eth0".into(),
        flags: 0xFFFF, // all bits set
        ..Default::default()
    };
    assert!(iface.is_up());
    assert!(iface.is_loopback());
}

// ---------------------------------------------------------------------------
// TC-W-7: parse_raw_frame works without Ethernet header
// ---------------------------------------------------------------------------
//
// On Windows, raw sockets deliver IP packets without Ethernet framing.
// parse_raw_frame() handles this: it checks the IP version nibble directly.

use netoproc::packet::parse_raw_frame;

/// Build a complete IPv4 TCP packet (SYN to 10.0.0.2:80).
fn make_full_ipv4_tcp() -> Vec<u8> {
    let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
    // IPv4 header
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2] = 0x00; // total length = 40
    pkt[3] = 0x28;
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    // src IP: 192.168.1.100
    pkt[12] = 192;
    pkt[13] = 168;
    pkt[14] = 1;
    pkt[15] = 100;
    // dst IP: 10.0.0.2
    pkt[16] = 10;
    pkt[17] = 0;
    pkt[18] = 0;
    pkt[19] = 2;
    // TCP header at offset 20
    pkt[20] = 0xC0; // src port high (49152)
    pkt[21] = 0x00;
    pkt[22] = 0x00; // dst port = 80
    pkt[23] = 0x50;
    pkt[32] = 0x50; // data offset = 5 (20 bytes)
    pkt
}

/// Build a complete IPv4 UDP packet.
fn make_full_ipv4_udp() -> Vec<u8> {
    let mut pkt = vec![0u8; 28]; // 20 IP + 8 UDP
    pkt[0] = 0x45;
    pkt[2] = 0x00;
    pkt[3] = 0x1C; // total length = 28
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12] = 192;
    pkt[13] = 168;
    pkt[14] = 1;
    pkt[15] = 100;
    pkt[16] = 8;
    pkt[17] = 8;
    pkt[18] = 8;
    pkt[19] = 8;
    // UDP header
    pkt[20] = 0xC0;
    pkt[21] = 0x00;
    pkt[22] = 0x00;
    pkt[23] = 0x35; // dst port 53
    pkt[24] = 0x00;
    pkt[25] = 0x08; // length
    pkt
}

/// Build a minimal IPv6 TCP packet.
fn make_full_ipv6_tcp() -> Vec<u8> {
    let mut pkt = vec![0u8; 60]; // 40 IPv6 + 20 TCP
    pkt[0] = 0x60; // version 6
    pkt[4] = 0x00; // payload length = 20
    pkt[5] = 0x14;
    pkt[6] = 6; // next header = TCP
    pkt[7] = 64; // hop limit
    // src IPv6: ::ffff:192.168.1.100
    pkt[20] = 0xFF;
    pkt[21] = 0xFF;
    pkt[22] = 192;
    pkt[23] = 168;
    pkt[24] = 1;
    pkt[25] = 100;
    // dst IPv6: ::ffff:10.0.0.2
    pkt[36] = 0xFF;
    pkt[37] = 0xFF;
    pkt[38] = 10;
    pkt[39] = 2;
    // TCP header at 40
    pkt[40] = 0xC0;
    pkt[41] = 0x00;
    pkt[42] = 0x01;
    pkt[43] = 0xBB; // dst port 443
    pkt[52] = 0x50; // data offset = 5
    pkt
}

#[test]
fn tc_w_7_1_parse_raw_ipv4_tcp() {
    let pkt = make_full_ipv4_tcp();
    let summary = parse_raw_frame(&pkt).expect("should parse IPv4 TCP");
    assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(summary.src_port, 49152);
    assert_eq!(summary.dst_port, 80);
}

#[test]
fn tc_w_7_2_parse_raw_ipv4_udp() {
    let pkt = make_full_ipv4_udp();
    let summary = parse_raw_frame(&pkt).expect("should parse IPv4 UDP");
    assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(summary.dst_port, 53);
}

#[test]
fn tc_w_7_3_parse_raw_ipv6_tcp() {
    let pkt = make_full_ipv6_tcp();
    let summary = parse_raw_frame(&pkt).expect("should parse IPv6 TCP");
    assert_eq!(summary.src_port, 49152);
    assert_eq!(summary.dst_port, 443);
}

#[test]
fn tc_w_7_4_empty_returns_none() {
    assert!(parse_raw_frame(&[]).is_none());
}

#[test]
fn tc_w_7_5_truncated_returns_none() {
    assert!(parse_raw_frame(&[0x45]).is_none());
    assert!(parse_raw_frame(&[0x60]).is_none());
}

// ---------------------------------------------------------------------------
// TC-W-8: Table row bounds validation
// ---------------------------------------------------------------------------
//
// Verifies the bounds-checking logic that prevents reading past the buffer
// when dwNumEntries is larger than what the buffer can hold.

#[test]
fn tc_w_8_1_bounds_check_rejects_overflow() {
    // Simulate a table buffer where dwNumEntries claims more rows than fit.
    // dwNumEntries = 1000, but buffer is only 16 bytes.
    let mut buffer = vec![0u8; 16];
    let count: u32 = 1000;
    buffer[0..4].copy_from_slice(&count.to_ne_bytes());

    let header_size = std::mem::size_of::<u32>();
    let row_size = 24; // typical row size
    let num_entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    // This is the check from our Windows code
    let fits = header_size + num_entries * row_size <= buffer.len();
    assert!(
        !fits,
        "should reject: claimed 1000 entries in 16-byte buffer"
    );
}

#[test]
fn tc_w_8_2_bounds_check_accepts_valid() {
    let row_size = 24;
    let num_entries = 3usize;
    let header_size = std::mem::size_of::<u32>();
    let buffer_size = header_size + num_entries * row_size;
    let mut buffer = vec![0u8; buffer_size];
    buffer[0..4].copy_from_slice(&(num_entries as u32).to_ne_bytes());

    let entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let fits = header_size + entries * row_size <= buffer.len();
    assert!(fits, "should accept: 3 entries fit exactly");
}

#[test]
fn tc_w_8_3_bounds_check_zero_entries() {
    let mut buffer = vec![0u8; 4];
    buffer[0..4].copy_from_slice(&0u32.to_ne_bytes());

    let entries = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let header_size = std::mem::size_of::<u32>();
    let fits = header_size + entries * 24 <= buffer.len();
    assert!(fits, "zero entries should always fit");
}

// ---------------------------------------------------------------------------
// TC-W-9: IPv4 address from network byte order u32
// ---------------------------------------------------------------------------
//
// Windows stores IPv4 addresses as u32 in network byte order.
// Conversion: Ipv4Addr::from(dwAddr.to_ne_bytes())

fn ipv4_from_win_dword(dw_addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw_addr.to_ne_bytes())
}

#[test]
fn tc_w_9_1_loopback() {
    // 127.0.0.1 in network byte order = 0x7F000001
    // On LE, u32 = 0x0100007F
    let dw = u32::from_ne_bytes([127, 0, 0, 1]);
    assert_eq!(ipv4_from_win_dword(dw), Ipv4Addr::new(127, 0, 0, 1));
}

#[test]
fn tc_w_9_2_google_dns() {
    let dw = u32::from_ne_bytes([8, 8, 8, 8]);
    assert_eq!(ipv4_from_win_dword(dw), Ipv4Addr::new(8, 8, 8, 8));
}

#[test]
fn tc_w_9_3_private_addr() {
    let dw = u32::from_ne_bytes([192, 168, 1, 100]);
    assert_eq!(ipv4_from_win_dword(dw), Ipv4Addr::new(192, 168, 1, 100));
}

#[test]
fn tc_w_9_4_unspecified() {
    assert_eq!(ipv4_from_win_dword(0), Ipv4Addr::UNSPECIFIED);
}

// ---------------------------------------------------------------------------
// TC-W-10: WinApi error variant
// ---------------------------------------------------------------------------

use netoproc::error::NetopError;

#[test]
fn tc_w_10_1_winapi_error_display() {
    let err = NetopError::WinApi("WSAStartup failed with error: 10093".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Windows API error"));
    assert!(msg.contains("10093"));
}

#[test]
fn tc_w_10_2_winapi_error_debug() {
    let err = NetopError::WinApi("test".to_string());
    let debug = format!("{err:?}");
    assert!(debug.contains("WinApi"));
}

// ---------------------------------------------------------------------------
// TC-W-11: parse_null_frame returns None on Windows
// ---------------------------------------------------------------------------

use netoproc::packet::parse_null_frame;

#[test]
fn tc_w_11_1_null_frame_on_non_windows() {
    // On non-Windows, parse_null_frame should handle valid data.
    // On Windows (cfg), it always returns None.
    // This test verifies it doesn't panic on various inputs.
    let _ = parse_null_frame(&[]);
    let _ = parse_null_frame(&[0; 4]);
    let _ = parse_null_frame(&[2, 0, 0, 0]); // AF_INET on LE
}
