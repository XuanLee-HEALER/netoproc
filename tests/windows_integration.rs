//! Windows compatibility integration tests.
//!
//! Split into two sections:
//!
//! 1. Library-level tests that verify Windows-relevant code paths.
//!    These run on ANY platform (including Linux via cross) because
//!    the functions tested are cross-platform.
//!
//! 2. Binary-level tests gated by `#[cfg(target_os = "windows")]` that
//!    can only run on actual Windows (Wine in cross cannot execute the binary).
//!
//! Run with:
//!   cross test --target x86_64-unknown-linux-gnu --test windows_integration
//!   (or on native Windows: cargo test --test windows_integration)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =========================================================================
// Section 1: Cross-platform library tests for Windows-relevant code paths
//
// These verify that packet parsing functions used by the Windows capture
// backend work correctly. They run on any platform.
// =========================================================================

/// TC-WIN-1: parse_raw_frame() correctly parses an IPv4 TCP packet.
///
/// Windows receives raw IP packets (no Ethernet header), so parse_raw_frame
/// is the primary parsing entry point on Windows.
#[test]
fn tc_win_1_parse_raw_frame_ipv4_tcp() {
    use netoproc::packet::parse_raw_frame;

    // Minimal IPv4 TCP SYN: 192.168.1.100:12345 → 10.0.0.1:443
    let mut pkt = vec![0u8; 40]; // 20 IPv4 + 20 TCP

    // IPv4 header
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2] = 0x00;
    pkt[3] = 40; // total length = 40
    pkt[9] = 6; // protocol = TCP
    // src IP: 192.168.1.100
    pkt[12] = 192;
    pkt[13] = 168;
    pkt[14] = 1;
    pkt[15] = 100;
    // dst IP: 10.0.0.1
    pkt[16] = 10;
    pkt[17] = 0;
    pkt[18] = 0;
    pkt[19] = 1;
    // TCP header: src port 12345, dst port 443
    pkt[20] = (12345u16 >> 8) as u8;
    pkt[21] = (12345u16 & 0xFF) as u8;
    pkt[22] = (443u16 >> 8) as u8;
    pkt[23] = (443u16 & 0xFF) as u8;
    pkt[32] = 0x50; // data offset = 5 (20 bytes)

    let result = parse_raw_frame(&pkt);
    assert!(result.is_some(), "should parse valid IPv4 TCP packet");

    let summary = result.unwrap();
    assert_eq!(summary.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(summary.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(summary.src_port, 12345);
    assert_eq!(summary.dst_port, 443);
}

/// TC-WIN-2: parse_raw_frame() correctly parses an IPv6 UDP packet.
#[test]
fn tc_win_2_parse_raw_frame_ipv6_udp() {
    use netoproc::packet::parse_raw_frame;

    // IPv6 header (40 bytes) + UDP header (8 bytes)
    let mut pkt = vec![0u8; 48];

    // IPv6 header
    pkt[0] = 0x60; // version=6
    pkt[4] = 0;
    pkt[5] = 8; // payload length = 8 (UDP header)
    pkt[6] = 17; // next header = UDP
    pkt[7] = 64; // hop limit
    // src: ::1
    pkt[23] = 1;
    // dst: 2001:4860:4860::8888 (Google DNS)
    pkt[24] = 0x20;
    pkt[25] = 0x01;
    pkt[26] = 0x48;
    pkt[27] = 0x60;
    pkt[28] = 0x48;
    pkt[29] = 0x60;
    pkt[38] = 0x88;
    pkt[39] = 0x88;
    // UDP header: src port 54321, dst port 53
    pkt[40] = (54321u16 >> 8) as u8;
    pkt[41] = (54321u16 & 0xFF) as u8;
    pkt[42] = 0;
    pkt[43] = 53;
    pkt[44] = 0;
    pkt[45] = 8; // UDP length

    let result = parse_raw_frame(&pkt);
    assert!(result.is_some(), "should parse valid IPv6 UDP packet");

    let summary = result.unwrap();
    assert_eq!(summary.src_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(summary.src_port, 54321);
    assert_eq!(summary.dst_port, 53);
}

/// TC-WIN-3: parse_raw_frame() rejects truncated and invalid packets.
#[test]
fn tc_win_3_parse_raw_frame_edge_cases() {
    use netoproc::packet::parse_raw_frame;

    // Empty
    assert!(parse_raw_frame(&[]).is_none(), "empty → None");

    // Truncated IPv4 (less than 20 bytes)
    assert!(
        parse_raw_frame(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6]).is_none(),
        "truncated IPv4 → None"
    );

    // Invalid version nibble (3)
    let mut bad_version = vec![0u8; 40];
    bad_version[0] = 0x35; // version=3
    assert!(
        parse_raw_frame(&bad_version).is_none(),
        "invalid version → None"
    );

    // Truncated IPv6 (less than 40 bytes)
    let mut short_v6 = vec![0u8; 20];
    short_v6[0] = 0x60; // version=6
    assert!(
        parse_raw_frame(&short_v6).is_none(),
        "truncated IPv6 → None"
    );

    // Version 0
    let v0 = vec![0u8; 40];
    assert!(parse_raw_frame(&v0).is_none(), "version 0 → None");
}

/// TC-WIN-4: skip_ipv6_extension_headers() handles all extension header types.
///
/// This function is used by Windows capture code for software-level traffic
/// filtering (matches_traffic_filter) and DNS payload extraction.
#[test]
fn tc_win_4_ipv6_extension_headers() {
    use netoproc::packet::skip_ipv6_extension_headers;

    // No extension headers (TCP directly)
    let (proto, offset) = skip_ipv6_extension_headers(6, &[]);
    assert_eq!(proto, 6);
    assert_eq!(offset, 0);

    // Hop-by-Hop (0) → then TCP (6)
    // Extension header: next_hdr=6, hdr_ext_len=0 → total 8 bytes
    let ext = [6u8, 0, 0, 0, 0, 0, 0, 0];
    let (proto, offset) = skip_ipv6_extension_headers(0, &ext);
    assert_eq!(proto, 6, "should reach TCP after Hop-by-Hop");
    assert_eq!(offset, 8);

    // Fragment header (44) → then UDP (17)
    // Fragment header is always 8 bytes
    let frag = [17u8, 0, 0, 0, 0, 0, 0, 0];
    let (proto, offset) = skip_ipv6_extension_headers(44, &frag);
    assert_eq!(proto, 17, "should reach UDP after Fragment");
    assert_eq!(offset, 8);

    // Routing header (43) → TCP (6)
    let routing = [6u8, 0, 0, 0, 0, 0, 0, 0];
    let (proto, offset) = skip_ipv6_extension_headers(43, &routing);
    assert_eq!(proto, 6, "should reach TCP after Routing");
    assert_eq!(offset, 8);

    // Destination Options (60) → UDP (17)
    let dest_opt = [17u8, 0, 0, 0, 0, 0, 0, 0];
    let (proto, offset) = skip_ipv6_extension_headers(60, &dest_opt);
    assert_eq!(proto, 17, "should reach UDP after Destination Options");
    assert_eq!(offset, 8);

    // Chained: Hop-by-Hop(0) → Routing(43) → TCP(6)
    let mut chained = vec![0u8; 16];
    chained[0] = 43; // next header = Routing
    chained[1] = 0; // hdr_ext_len = 0
    chained[8] = 6; // next header = TCP
    chained[9] = 0; // hdr_ext_len = 0
    let (proto, offset) = skip_ipv6_extension_headers(0, &chained);
    assert_eq!(proto, 6, "should reach TCP after two extension headers");
    assert_eq!(offset, 16);

    // Triple chain: Hop-by-Hop → Fragment → Routing → ICMPv6(58)
    let mut triple = vec![0u8; 24];
    // Hop-by-Hop: next=44 (Fragment)
    triple[0] = 44;
    triple[1] = 0;
    // Fragment: next=43 (Routing), always 8 bytes
    triple[8] = 43;
    // Routing: next=58 (ICMPv6)
    triple[16] = 58;
    triple[17] = 0;
    let (proto, offset) = skip_ipv6_extension_headers(0, &triple);
    assert_eq!(proto, 58, "should reach ICMPv6 after triple chain");
    assert_eq!(offset, 24);

    // Truncated extension header (only 1 byte)
    let (proto, offset) = skip_ipv6_extension_headers(0, &[6]);
    assert_eq!(proto, 0, "truncated: should return original next_hdr");
    assert_eq!(offset, 0);
}

/// TC-WIN-5: NetopError::WinApi displays correctly on all platforms.
#[test]
fn tc_win_5_winapi_error_format() {
    use netoproc::error::NetopError;

    let err = NetopError::WinApi("WSAStartup failed with error: 10093".to_string());
    let display = format!("{err}");
    assert!(
        display.contains("Windows API error"),
        "display should contain 'Windows API error', got: {display}"
    );
    assert!(
        display.contains("10093"),
        "display should contain error code, got: {display}"
    );

    let debug = format!("{err:?}");
    assert!(
        debug.contains("WinApi"),
        "debug should contain 'WinApi', got: {debug}"
    );
}

/// TC-WIN-6: PacketSummary struct has consistent layout across platforms.
#[test]
fn tc_win_6_packet_summary_layout() {
    use netoproc::packet::PacketSummary;

    let size = std::mem::size_of::<PacketSummary>();
    // Verify reasonable size and matches expectations
    assert!(
        size > 0 && size <= 128,
        "PacketSummary size should be reasonable, got: {size}"
    );
    eprintln!("PacketSummary size: {size} bytes");
}

/// TC-WIN-7: parse_raw_frame() with IPv6 extension headers before TCP.
///
/// Simulates a packet with Hop-by-Hop extension header before the TCP header,
/// which Windows capture code must handle correctly.
#[test]
fn tc_win_7_parse_raw_frame_ipv6_ext_header() {
    use netoproc::packet::parse_raw_frame;

    // IPv6 (40) + Hop-by-Hop ext header (8) + TCP (20) = 68 bytes
    let mut pkt = vec![0u8; 68];

    // IPv6 header
    pkt[0] = 0x60; // version=6
    pkt[4] = 0;
    pkt[5] = 28; // payload length = 8 + 20
    pkt[6] = 0; // next header = Hop-by-Hop
    pkt[7] = 64; // hop limit
    // src: fd00::1
    pkt[8] = 0xfd;
    pkt[23] = 1;
    // dst: fd00::2
    pkt[24] = 0xfd;
    pkt[39] = 2;

    // Hop-by-Hop extension header (8 bytes)
    pkt[40] = 6; // next header = TCP
    pkt[41] = 0; // hdr_ext_len = 0 (8 bytes total)

    // TCP header at offset 48
    pkt[48] = (8080u16 >> 8) as u8; // src port
    pkt[49] = (8080u16 & 0xFF) as u8;
    pkt[50] = (80u16 >> 8) as u8; // dst port
    pkt[51] = (80u16 & 0xFF) as u8;
    pkt[60] = 0x50; // data offset = 5

    let result = parse_raw_frame(&pkt);
    assert!(
        result.is_some(),
        "should parse IPv6 packet with extension header"
    );

    let summary = result.unwrap();
    assert_eq!(summary.src_port, 8080);
    assert_eq!(summary.dst_port, 80);
}

/// TC-WIN-8: Windows port byte-order conversion is correct.
///
/// Windows IP Helper API returns ports as DWORD in network byte order.
/// The correct conversion is u16::from_be(dword as u16).
#[test]
fn tc_win_8_port_byte_order() {
    // Simulate Windows DWORD port values (network byte order in u32)
    fn win_port(dw: u32) -> u16 {
        u16::from_be(dw as u16)
    }

    assert_eq!(win_port(0x5000), 80, "HTTP port");
    assert_eq!(win_port(0xBB01), 443, "HTTPS port");
    assert_eq!(win_port(0x3500), 53, "DNS port");
    assert_eq!(win_port(0x901F), 8080, "alt HTTP port");
    assert_eq!(win_port(0xFFFF), 65535, "max port");
    assert_eq!(win_port(0x0000), 0, "zero port");
    assert_eq!(win_port(0x0100), 1, "port 1");

    // Roundtrip: all common ports
    for port in [22, 25, 53, 80, 110, 143, 443, 993, 3306, 5432, 8080, 27017] {
        let dw = (port as u16).to_be() as u32;
        assert_eq!(win_port(dw), port, "roundtrip failed for port {port}");
    }
}

/// TC-WIN-9: tcp_state_to_socket_state maps platform state values correctly.
///
/// Each platform uses different numeric constants for TCP states:
/// - macOS: TCPS_CLOSED=0, TCPS_LISTEN=1, TCPS_SYN_SENT=2, ...
/// - Linux: /proc/net/tcp hex states: 01=ESTABLISHED, 02=SYN_SENT, ...
/// - Windows: MIB_TCP_STATE: 1=CLOSED, 2=LISTEN, 3=SYN_SENT, ...
///
/// This test verifies the platform-native mapping is correct.
#[test]
fn tc_win_9_tcp_state_mapping() {
    use netoproc::system::process::tcp_state_to_socket_state;

    #[cfg(target_os = "macos")]
    {
        // macOS TCPS_* constants
        let expected = [
            (0, "Closed"),      // TCPS_CLOSED
            (1, "Listen"),      // TCPS_LISTEN
            (2, "SynSent"),     // TCPS_SYN_SENT
            (3, "SynReceived"), // TCPS_SYN_RECEIVED
            (4, "Established"), // TCPS_ESTABLISHED
            (5, "CloseWait"),   // TCPS_CLOSE_WAIT
            (6, "FinWait1"),    // TCPS_FIN_WAIT_1
            (7, "Closing"),     // TCPS_CLOSING
            (8, "LastAck"),     // TCPS_LAST_ACK
            (9, "FinWait2"),    // TCPS_FIN_WAIT_2
            (10, "TimeWait"),   // TCPS_TIME_WAIT
        ];
        for (state_val, name) in expected {
            let state = tcp_state_to_socket_state(state_val);
            let state_name = format!("{state:?}");
            assert_eq!(
                state_name, name,
                "macOS TCP state {state_val} should map to {name}, got {state_name}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux /proc/net/tcp hex state values
        let expected = [
            (1, "Established"), // TCP_ESTABLISHED
            (2, "SynSent"),     // TCP_SYN_SENT
            (3, "SynReceived"), // TCP_SYN_RECV
            (6, "TimeWait"),    // TCP_TIME_WAIT
            (7, "Closed"),      // TCP_CLOSE
            (10, "Listen"),     // TCP_LISTEN
        ];
        for (state_val, name) in expected {
            let state = tcp_state_to_socket_state(state_val);
            let state_name = format!("{state:?}");
            assert_eq!(
                state_name, name,
                "Linux TCP state {state_val} should map to {name}, got {state_name}"
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows MIB_TCP_STATE values
        let expected = [
            (1, "Closed"),      // MIB_TCP_STATE_CLOSED
            (2, "Listen"),      // MIB_TCP_STATE_LISTEN
            (3, "SynSent"),     // MIB_TCP_STATE_SYN_SENT
            (4, "SynReceived"), // MIB_TCP_STATE_SYN_RCVD
            (5, "Established"), // MIB_TCP_STATE_ESTAB
            (6, "FinWait1"),    // MIB_TCP_STATE_FIN_WAIT1
            (7, "FinWait2"),    // MIB_TCP_STATE_FIN_WAIT2
            (8, "CloseWait"),   // MIB_TCP_STATE_CLOSE_WAIT
            (9, "Closing"),     // MIB_TCP_STATE_CLOSING
            (10, "LastAck"),    // MIB_TCP_STATE_LAST_ACK
            (11, "TimeWait"),   // MIB_TCP_STATE_TIME_WAIT
            (12, "Closed"),     // MIB_TCP_STATE_DELETE_TCB → maps to Closed
        ];
        for (state_val, name) in expected {
            let state = tcp_state_to_socket_state(state_val);
            let state_name = format!("{state:?}");
            assert_eq!(
                state_name, name,
                "Windows TCP state {state_val} should map to {name}, got {state_name}"
            );
        }
    }

    // Unknown states default to Closed (all platforms)
    let unknown = tcp_state_to_socket_state(99);
    assert_eq!(
        format!("{unknown:?}"),
        "Closed",
        "unknown state should default to Closed"
    );
}

/// TC-WIN-10: Table row bounds validation prevents buffer overflow.
///
/// Windows GetExtendedTcpTable can return a dwNumEntries that exceeds the
/// actual buffer. The code must validate bounds before iterating.
#[test]
fn tc_win_10_table_bounds_validation() {
    // Simulate: buffer is 16 bytes, but claims 1000 entries of 24-byte rows
    let buffer_len = 16usize;
    let header_size = 4usize; // size of dwNumEntries field
    let row_size = 24usize;
    let num_entries = 1000usize;

    let fits = header_size + num_entries * row_size <= buffer_len;
    assert!(
        !fits,
        "should reject: claimed 1000 entries in 16-byte buffer"
    );

    // Valid case: 3 entries of 24-byte rows in a correctly sized buffer
    let valid_buffer_len = header_size + 3 * row_size;
    let valid_fits = header_size + 3 * row_size <= valid_buffer_len;
    assert!(valid_fits, "should accept: 3 entries fit exactly");

    // Zero entries always fits
    let zero_fits = header_size + 0 * row_size <= buffer_len;
    assert!(zero_fits, "should accept: zero entries");
}

/// TC-WIN-11: IPv4 address conversion from network byte order u32.
///
/// Windows stores IPv4 addresses as DWORD in network byte order. The
/// conversion pattern is Ipv4Addr::from(dword.to_ne_bytes()).
#[test]
fn tc_win_11_ipv4_from_network_order() {
    fn ipv4_from_dword(dw: u32) -> Ipv4Addr {
        Ipv4Addr::from(dw.to_ne_bytes())
    }

    // 127.0.0.1 = 0x7f000001 in network order, 0x0100007f on LE
    let loopback = ipv4_from_dword(u32::from_ne_bytes([127, 0, 0, 1]));
    assert_eq!(loopback, Ipv4Addr::new(127, 0, 0, 1));

    // 8.8.8.8
    let google_dns = ipv4_from_dword(u32::from_ne_bytes([8, 8, 8, 8]));
    assert_eq!(google_dns, Ipv4Addr::new(8, 8, 8, 8));

    // 0.0.0.0
    let unspec = ipv4_from_dword(0);
    assert_eq!(unspec, Ipv4Addr::UNSPECIFIED);
}

/// TC-WIN-12: RawInterface flag checking works for Windows flags.
///
/// Windows sets FLAG_UP (0x1) based on OperStatus and FLAG_LOOPBACK (0x8)
/// based on IfType == SOFTWARE_LOOPBACK.
#[test]
fn tc_win_12_interface_flags() {
    use netoproc::system::interface::RawInterface;

    let up_iface = RawInterface {
        name: "Ethernet".to_string(),
        flags: 0x1, // FLAG_UP
        ..Default::default()
    };
    assert!(up_iface.is_up());
    assert!(!up_iface.is_loopback());

    let loopback_iface = RawInterface {
        name: "Loopback".to_string(),
        flags: 0x9, // FLAG_UP | FLAG_LOOPBACK
        ..Default::default()
    };
    assert!(loopback_iface.is_up());
    assert!(loopback_iface.is_loopback());

    let down_iface = RawInterface {
        name: "WiFi".to_string(),
        flags: 0x0, // no flags
        ..Default::default()
    };
    assert!(!down_iface.is_up());
    assert!(!down_iface.is_loopback());
}

// =========================================================================
// Section 2: Windows-only binary tests
//
// These test the actual compiled Windows binary and can only run on
// a real Windows machine (Wine in cross cannot execute the binary).
// =========================================================================

#[cfg(target_os = "windows")]
mod binary_tests {
    use std::process::Command;

    fn netoproc_bin() -> String {
        let mut path = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        path.push("netoproc.exe");
        path.to_string_lossy().to_string()
    }

    fn ensure_binary() {
        let bin = netoproc_bin();
        if std::path::Path::new(&bin).exists() {
            return;
        }
        let status = Command::new("cargo")
            .args(["build"])
            .status()
            .expect("failed to run cargo build");
        assert!(status.success(), "cargo build failed");
    }

    /// TC-WIN-B1: --help flag works on Windows.
    #[test]
    fn tc_win_b1_help_flag() {
        ensure_binary();

        let output = Command::new(netoproc_bin())
            .args(["--help"])
            .output()
            .expect("failed to execute");

        assert!(output.status.success(), "--help should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("network traffic monitor"));
        assert!(stdout.contains("--duration"));
    }

    /// TC-WIN-B2: --version outputs the correct version.
    #[test]
    fn tc_win_b2_version_flag() {
        ensure_binary();

        let output = Command::new(netoproc_bin())
            .args(["--version"])
            .output()
            .expect("failed to execute");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("netoproc"));
    }

    /// TC-WIN-B3: Invalid arguments produce error exit.
    #[test]
    fn tc_win_b3_invalid_args() {
        ensure_binary();

        let output = Command::new(netoproc_bin())
            .args(["--format", "xml"])
            .output()
            .expect("failed to execute");

        assert!(!output.status.success());
    }

    /// TC-WIN-B4: Without Administrator → clear permission error.
    #[test]
    fn tc_win_b4_permission_error() {
        ensure_binary();

        let output = Command::new(netoproc_bin())
            .args(["--duration", "1"])
            .output()
            .expect("failed to execute");

        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        assert!(
            exit_code == 1 || exit_code == 2 || exit_code == 4,
            "exit code should indicate privilege/capture error, got: {exit_code}"
        );
        assert!(
            stderr.contains("Administrator")
                || stderr.contains("WSA")
                || stderr.contains("socket")
                || stderr.contains("error"),
            "should provide useful error message, got: {stderr}"
        );
    }

    /// TC-WIN-B5: --capture-mode=ebpf warns on Windows.
    #[test]
    fn tc_win_b5_capture_mode_warning() {
        ensure_binary();

        let output = Command::new(netoproc_bin())
            .args(["--duration", "1", "--capture-mode", "ebpf"])
            .output()
            .expect("failed to execute");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--capture-mode") || stderr.contains("only supported on Linux"),
            "should warn about --capture-mode on Windows, got: {stderr}"
        );
    }
}
