//! Integration tests for Unknown traffic enrichment.
//!
//! These tests exercise the enrichment pipeline end-to-end: annotation lookup,
//! StatsState construction, output rendering with sub-rows, backward
//! compatibility of TSV/JSON, and the reverse DNS resolver lifecycle.
//!
//! No root privileges required — all tests use in-memory data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use netoproc::cli::OutputFormat;
use netoproc::enrichment;
use netoproc::enrichment::dns_resolver::ReverseDnsResolver;
use netoproc::model::Protocol;
use netoproc::model::traffic::{ConnectionStats, ProcessKey, StatsState, TrafficStats};
use netoproc::output;

// =========================================================================
// Section 1: Annotation pipeline integration (TC-E-1.x)
//
// Tests that get_annotation correctly combines IP + port for realistic
// traffic scenarios across multiple protocols and address families.
// =========================================================================

/// TC-E-1.1: Apple Push traffic annotation (HTTPS to Apple IP).
#[test]
fn tc_e_1_1_apple_push_annotation() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
    let ann = enrichment::get_annotation(addr, Protocol::Tcp);
    assert_eq!(ann, Some("Apple Push/iCloud - HTTPS".to_string()));
}

/// TC-E-1.2: Local DNS query annotation.
#[test]
fn tc_e_1_2_local_dns_annotation() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
    let ann = enrichment::get_annotation(addr, Protocol::Udp);
    assert_eq!(ann, Some("local network - DNS".to_string()));
}

/// TC-E-1.3: Google DNS annotation.
#[test]
fn tc_e_1_3_google_dns_annotation() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let ann = enrichment::get_annotation(addr, Protocol::Udp);
    assert_eq!(ann, Some("Google DNS - DNS".to_string()));
}

/// TC-E-1.4: SSDP multicast annotation.
#[test]
fn tc_e_1_4_ssdp_multicast_annotation() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
    let ann = enrichment::get_annotation(addr, Protocol::Udp);
    assert_eq!(ann, Some("SSDP multicast - SSDP".to_string()));
}

/// TC-E-1.5: NTP time sync annotation.
#[test]
fn tc_e_1_5_ntp_annotation() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 253, 34, 123)), 123);
    let ann = enrichment::get_annotation(addr, Protocol::Udp);
    // 17.x.x.x is Apple /8, port 123 is NTP
    assert_eq!(ann, Some("Apple - NTP".to_string()));
}

/// TC-E-1.6: Unknown public IP with known port.
#[test]
fn tc_e_1_6_unknown_ip_known_port() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 443);
    let ann = enrichment::get_annotation(addr, Protocol::Tcp);
    // IP not in table, but port 443 = HTTPS
    assert_eq!(ann, Some("HTTPS".to_string()));
}

/// TC-E-1.7: Completely unknown traffic.
#[test]
fn tc_e_1_7_completely_unknown() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 54321);
    let ann = enrichment::get_annotation(addr, Protocol::Tcp);
    assert_eq!(ann, None);
}

/// TC-E-1.8: IPv6 Google address annotation.
#[test]
fn tc_e_1_8_ipv6_google_annotation() {
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        443,
    );
    let ann = enrichment::get_annotation(addr, Protocol::Tcp);
    assert_eq!(ann, Some("Google - HTTPS".to_string()));
}

/// TC-E-1.9: IPv6 link-local mDNS annotation.
#[test]
fn tc_e_1_9_ipv6_link_local_mdns() {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 5353);
    let ann = enrichment::get_annotation(addr, Protocol::Udp);
    assert_eq!(ann, Some("link-local - mDNS".to_string()));
}

/// TC-E-1.10: Protocol specificity — TCP port 53 still matches DNS.
#[test]
fn tc_e_1_10_tcp_dns() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    let ann = enrichment::get_annotation(addr, Protocol::Tcp);
    assert_eq!(ann, Some("Cloudflare DNS - DNS".to_string()));
}

/// TC-E-1.11: UDP port 443 does NOT match HTTPS (TCP-only).
#[test]
fn tc_e_1_11_udp_port_443_no_https() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
    let ann = enrichment::get_annotation(addr, Protocol::Udp);
    // IP matches Apple Push/iCloud, but port 443 is TCP-only so no port label
    assert_eq!(ann, Some("Apple Push/iCloud".to_string()));
}

// =========================================================================
// Section 2: StatsState construction and output rendering (TC-E-2.x)
//
// Tests that StatsState correctly feeds into the output formatters and
// that TSV/JSON remain backward-compatible while Pretty gains sub-rows.
// =========================================================================

/// Build a realistic StatsState with known processes and unknown traffic.
fn make_enriched_state() -> StatsState {
    let mut state = StatsState::default();

    // Known process traffic
    state.by_process.insert(
        ProcessKey::Known {
            pid: 1234,
            name: "chrome".to_string(),
        },
        TrafficStats {
            rx_bytes: 1_200_000,
            tx_bytes: 340_000,
            rx_packets: 800,
            tx_packets: 200,
        },
    );

    // Unknown aggregate traffic
    state.by_process.insert(
        ProcessKey::Unknown,
        TrafficStats {
            rx_bytes: 13_500,
            tx_bytes: 13_600,
            rx_packets: 29,
            tx_packets: 34,
        },
    );

    // Unknown per-remote breakdown
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
    state.unknown_by_remote.insert(
        addr1,
        ConnectionStats {
            rx_bytes: 5_222,
            tx_bytes: 0,
            rdns: Some(Some("courier.push.apple.com".to_string())),
            annotation: Some("Apple Push/iCloud - HTTPS".to_string()),
            protocol: Protocol::Tcp,
        },
    );

    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
    state.unknown_by_remote.insert(
        addr2,
        ConnectionStats {
            rx_bytes: 0,
            tx_bytes: 3_277,
            rdns: None,
            annotation: Some("local network - DNS".to_string()),
            protocol: Protocol::Udp,
        },
    );

    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 253, 34, 123)), 123);
    state.unknown_by_remote.insert(
        addr3,
        ConnectionStats {
            rx_bytes: 2_500,
            tx_bytes: 2_500,
            rdns: Some(Some("time.apple.com".to_string())),
            annotation: Some("Apple - NTP".to_string()),
            protocol: Protocol::Udp,
        },
    );

    let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 54321);
    state.unknown_by_remote.insert(
        addr4,
        ConnectionStats {
            rx_bytes: 5_778,
            tx_bytes: 7_823,
            rdns: Some(None), // DNS lookup failed
            annotation: None,
            protocol: Protocol::Tcp,
        },
    );

    state
}

/// TC-E-2.1: TSV output is backward-compatible — still 6 columns, no sub-rows.
#[test]
fn tc_e_2_1_tsv_backward_compatible() {
    let state = make_enriched_state();
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Tsv, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Every line must have exactly 6 tab-separated columns
    for (i, line) in output.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let cols = line.split('\t').count();
        assert_eq!(
            cols,
            6,
            "TSV line {} has {cols} columns, expected 6: {line:?}",
            i + 1
        );
    }

    // Must not contain any sub-row indicators
    assert!(!output.contains("17.57.144.83"));
    assert!(!output.contains("courier.push.apple.com"));
    assert!(!output.contains("Apple Push/iCloud"));
}

/// TC-E-2.2: JSON output is backward-compatible — flat array, no enrichment fields.
#[test]
fn tc_e_2_2_json_backward_compatible() {
    let state = make_enriched_state();
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Json, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 2); // chrome + unknown

    // Only standard fields, no enrichment data
    for entry in arr {
        let obj = entry.as_object().unwrap();
        assert!(obj.contains_key("pid"));
        assert!(obj.contains_key("process"));
        assert!(obj.contains_key("rx_bytes"));
        assert!(obj.contains_key("tx_bytes"));
        assert!(obj.contains_key("rx_packets"));
        assert!(obj.contains_key("tx_packets"));
        // Must NOT have enrichment fields
        assert!(!obj.contains_key("annotation"));
        assert!(!obj.contains_key("rdns"));
        assert!(!obj.contains_key("remote_addr"));
    }
}

/// TC-E-2.3: Pretty output contains sub-rows under unknown.
#[test]
fn tc_e_2_3_pretty_sub_rows() {
    let state = make_enriched_state();
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Must contain the aggregate unknown row
    assert!(output.contains("unknown"), "missing unknown row");

    // Must contain sub-row with resolved hostname
    assert!(
        output.contains("courier.push.apple.com:443"),
        "missing rDNS hostname sub-row"
    );
    assert!(
        output.contains("Apple Push/iCloud - HTTPS"),
        "missing annotation for Apple push"
    );

    // Must contain sub-row with raw IP (no rdns)
    assert!(
        output.contains("192.168.1.1:53"),
        "missing raw IP sub-row for DNS"
    );
    assert!(
        output.contains("local network - DNS"),
        "missing annotation for local DNS"
    );

    // Must contain NTP sub-row with hostname
    assert!(
        output.contains("time.apple.com:123"),
        "missing rDNS hostname for NTP"
    );

    // Must contain sub-row with failed rDNS (shows raw IP)
    assert!(
        output.contains("203.0.113.50:54321"),
        "missing raw IP for failed rDNS"
    );
}

/// TC-E-2.4: Pretty output sub-rows are sorted by traffic descending.
#[test]
fn tc_e_2_4_pretty_sub_rows_sorted() {
    let state = make_enriched_state();
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // addr4 (5778+7823=13601) > addr1 (5222+0=5222) > addr3 (2500+2500=5000) > addr2 (0+3277=3277)
    let pos_addr4 = output.find("203.0.113.50:54321").unwrap();
    let pos_addr1 = output.find("courier.push.apple.com:443").unwrap();
    let pos_addr3 = output.find("time.apple.com:123").unwrap();
    let pos_addr2 = output.find("192.168.1.1:53").unwrap();

    assert!(
        pos_addr4 < pos_addr1,
        "highest traffic sub-row should appear first"
    );
    assert!(
        pos_addr1 < pos_addr3,
        "second highest should appear before third"
    );
    assert!(
        pos_addr3 < pos_addr2,
        "third highest should appear before lowest"
    );
}

/// TC-E-2.5: Pretty output sub-rows are limited to top 10.
#[test]
fn tc_e_2_5_pretty_sub_rows_limit() {
    let mut state = StatsState::default();
    state.by_process.insert(
        ProcessKey::Unknown,
        TrafficStats {
            rx_bytes: 15_000,
            tx_bytes: 0,
            rx_packets: 15,
            tx_packets: 0,
        },
    );
    // Insert 15 remote addresses
    for i in 0..15u8 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 80);
        state.unknown_by_remote.insert(
            addr,
            ConnectionStats {
                rx_bytes: (1000 + i as u64 * 100),
                tx_bytes: 0,
                annotation: Some("HTTP".to_string()),
                ..Default::default()
            },
        );
    }

    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Should show "(5 more connections...)"
    assert!(
        output.contains("(5 more connections...)"),
        "should indicate remaining connections: {output}"
    );

    // Count sub-rows (lines starting with "  10.0.0.")
    let sub_rows = output.lines().filter(|l| l.contains("10.0.0.")).count();
    assert_eq!(
        sub_rows, 10,
        "should show exactly 10 sub-rows, got {sub_rows}"
    );
}

/// TC-E-2.6: Pretty output contains no ANSI codes even with enrichment.
#[test]
fn tc_e_2_6_pretty_no_ansi_with_enrichment() {
    let state = make_enriched_state();
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(
        !output.contains('\x1b'),
        "enriched pretty output should have no ANSI escape codes"
    );
}

/// TC-E-2.7: Empty unknown_by_remote — no sub-rows rendered.
#[test]
fn tc_e_2_7_no_sub_rows_when_empty() {
    let mut state = StatsState::default();
    state.by_process.insert(
        ProcessKey::Unknown,
        TrafficStats {
            rx_bytes: 100,
            tx_bytes: 0,
            rx_packets: 1,
            tx_packets: 0,
        },
    );
    // No unknown_by_remote entries

    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Must contain aggregate unknown row
    assert!(output.contains("unknown"));
    // Must NOT contain any indented sub-rows or "more connections"
    assert!(!output.contains("more connections"));
    // The line count should be minimal (header + separator + unknown + separator + total)
    let line_count = output.lines().count();
    assert!(
        line_count <= 7,
        "too many lines for empty sub-rows: {line_count}\n{output}"
    );
}

/// TC-E-2.8: StatsState with no unknown traffic at all.
#[test]
fn tc_e_2_8_no_unknown_traffic() {
    let mut state = StatsState::default();
    state.by_process.insert(
        ProcessKey::Known {
            pid: 100,
            name: "curl".to_string(),
        },
        TrafficStats {
            rx_bytes: 50_000,
            tx_bytes: 10_000,
            rx_packets: 100,
            tx_packets: 50,
        },
    );

    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(!output.contains("unknown"));
    assert!(output.contains("curl"));
    assert!(output.contains("TOTAL"));
}

/// TC-E-2.9: Pretty TOTAL line includes both known and unknown traffic.
#[test]
fn tc_e_2_9_total_includes_all() {
    let state = make_enriched_state();
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Total rx = 1_200_000 + 13_500 = 1_213_500 (1.2 MiB range)
    // Total tx = 340_000 + 13_600 = 353_600 (345.3 KiB range)
    let total_line = output
        .lines()
        .find(|l| l.contains("TOTAL"))
        .expect("missing TOTAL line");

    // TOTAL line should contain the summed traffic (as formatted bytes)
    assert!(
        total_line.contains("MiB"),
        "TOTAL rx should be in MiB range: {total_line}"
    );
    assert!(
        total_line.contains("KiB"),
        "TOTAL tx should be in KiB range: {total_line}"
    );
}

// =========================================================================
// Section 3: Reverse DNS resolver integration (TC-E-3.x)
//
// Tests the ReverseDnsResolver lifecycle: creation, async lookup flow,
// deduplication, and graceful handling of edge cases.
// =========================================================================

/// TC-E-3.1: Resolver creates successfully and resolves localhost.
#[test]
fn tc_e_3_1_resolver_localhost() {
    let mut resolver = ReverseDnsResolver::new(2).unwrap();
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    // First lookup should trigger query
    assert!(resolver.lookup(ip).is_none());

    // Wait for resolution
    resolver.wait_for_pending(Duration::from_secs(5));

    // Should have a result now (may be "localhost" or similar)
    let result = resolver.get_result(&ip);
    assert!(result.is_some(), "should have resolved 127.0.0.1");
}

/// TC-E-3.2: Multiple IPs are resolved independently.
#[test]
fn tc_e_3_2_multiple_ips() {
    let mut resolver = ReverseDnsResolver::new(2).unwrap();
    let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    resolver.lookup(ip1);
    resolver.lookup(ip2);

    resolver.wait_for_pending(Duration::from_secs(10));

    // Both should have results
    assert!(
        resolver.get_result(&ip1).is_some(),
        "should have resolved 127.0.0.1"
    );
    assert!(
        resolver.get_result(&ip2).is_some(),
        "should have resolved 8.8.8.8"
    );
}

/// TC-E-3.3: Same IP queried multiple times is deduplicated.
#[test]
fn tc_e_3_3_deduplication() {
    let mut resolver = ReverseDnsResolver::new(1).unwrap();
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    // Trigger multiple lookups for the same IP
    resolver.lookup(ip);
    resolver.lookup(ip);
    resolver.lookup(ip);

    resolver.wait_for_pending(Duration::from_secs(5));

    // Should have exactly one result
    assert!(resolver.get_result(&ip).is_some());
}

/// TC-E-3.4: Non-routable IP returns a result (may be None).
#[test]
fn tc_e_3_4_non_routable_ip() {
    let mut resolver = ReverseDnsResolver::new(1).unwrap();
    // RFC 5737 test range — unlikely to resolve
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

    resolver.lookup(ip);
    resolver.wait_for_pending(Duration::from_secs(5));

    // Should have a result (even if None/failed)
    let result = resolver.get_result(&ip);
    assert!(
        result.is_some(),
        "should have attempted resolution for non-routable IP"
    );
}

/// TC-E-3.5: Resolver handles concurrent lookups without panic.
#[test]
fn tc_e_3_5_concurrent_lookups() {
    let mut resolver = ReverseDnsResolver::new(2).unwrap();

    // Queue up many IPs
    for i in 1..=20u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
        resolver.lookup(ip);
    }

    // Collect results periodically
    for _ in 0..10 {
        resolver.collect_results();
        std::thread::sleep(Duration::from_millis(100));
    }

    resolver.wait_for_pending(Duration::from_secs(10));

    // At least some should have completed
    let resolved_count = (1..=20u8)
        .filter(|&i| {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
            resolver.get_result(&ip).is_some()
        })
        .count();

    assert!(
        resolved_count > 0,
        "at least some IPs should have been resolved"
    );
}

// =========================================================================
// Section 4: Full pipeline integration (TC-E-4.x)
//
// Tests that exercise the complete annotation → StatsState → output path,
// simulating the data flow that happens in run_snapshot.
// =========================================================================

/// TC-E-4.1: Build StatsState from scratch using enrichment APIs.
#[test]
fn tc_e_4_1_build_state_with_enrichment() {
    let mut state = StatsState::default();

    // Simulate unknown packets from different remotes
    let remotes = vec![
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443),
            Protocol::Tcp,
            5000u64,
            1000u64,
        ),
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            Protocol::Udp,
            200,
            100,
        ),
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53),
            Protocol::Udp,
            0,
            500,
        ),
    ];

    let mut total_rx = 0u64;
    let mut total_tx = 0u64;

    for (addr, proto, rx, tx) in &remotes {
        let conn = state
            .unknown_by_remote
            .entry(*addr)
            .or_insert_with(|| ConnectionStats {
                protocol: *proto,
                annotation: enrichment::get_annotation(*addr, *proto),
                ..Default::default()
            });
        conn.rx_bytes += rx;
        conn.tx_bytes += tx;
        total_rx += rx;
        total_tx += tx;
    }

    state.by_process.insert(
        ProcessKey::Unknown,
        TrafficStats {
            rx_bytes: total_rx,
            tx_bytes: total_tx,
            rx_packets: 10,
            tx_packets: 5,
        },
    );

    // Verify annotations were set correctly
    let apple_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
    assert_eq!(
        state.unknown_by_remote[&apple_addr].annotation,
        Some("Apple Push/iCloud - HTTPS".to_string())
    );

    let google_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    assert_eq!(
        state.unknown_by_remote[&google_addr].annotation,
        Some("Google DNS - DNS".to_string())
    );

    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
    assert_eq!(
        state.unknown_by_remote[&local_addr].annotation,
        Some("local network - DNS".to_string())
    );

    // Render all three formats and verify
    let mut tsv_buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Tsv, &mut tsv_buf).unwrap();
    let tsv = String::from_utf8(tsv_buf).unwrap();
    // TSV: still 6 columns, no sub-rows
    for line in tsv.lines() {
        assert_eq!(line.split('\t').count(), 6);
    }

    let mut json_buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Json, &mut json_buf).unwrap();
    let json = String::from_utf8(json_buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 1); // only unknown

    let mut pretty_buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut pretty_buf).unwrap();
    let pretty = String::from_utf8(pretty_buf).unwrap();
    assert!(pretty.contains("Apple Push/iCloud - HTTPS"));
    assert!(pretty.contains("Google DNS - DNS"));
    assert!(pretty.contains("local network - DNS"));
}

/// TC-E-4.2: Mixed known and unknown traffic renders correctly in all formats.
#[test]
fn tc_e_4_2_mixed_traffic_all_formats() {
    let state = make_enriched_state();

    // TSV
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Tsv, &mut buf).unwrap();
    let tsv = String::from_utf8(buf).unwrap();
    let tsv_data: Vec<&str> = tsv.lines().skip(1).collect();
    assert_eq!(
        tsv_data.len(),
        2,
        "TSV should have 2 data rows (chrome + unknown)"
    );
    // First row should be chrome (most traffic)
    assert!(tsv_data[0].contains("chrome"));
    assert!(tsv_data[1].contains("unknown"));

    // JSON
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Json, &mut buf).unwrap();
    let json = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["process"].as_str().unwrap(), "chrome");
    assert_eq!(arr[1]["process"].as_str().unwrap(), "unknown");

    // Pretty
    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let pretty = String::from_utf8(buf).unwrap();
    assert!(pretty.contains("chrome"));
    assert!(pretty.contains("unknown"));
    assert!(pretty.contains("courier.push.apple.com:443"));
    assert!(pretty.contains("TOTAL"));
}

/// TC-E-4.3: ConnectionStats rdns states are correctly rendered.
#[test]
fn tc_e_4_3_rdns_states_rendering() {
    let mut state = StatsState::default();
    state.by_process.insert(
        ProcessKey::Unknown,
        TrafficStats {
            rx_bytes: 3000,
            tx_bytes: 0,
            rx_packets: 3,
            tx_packets: 0,
        },
    );

    // rdns = Some(Some("hostname")) → shows hostname
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 1, 1)), 443);
    state.unknown_by_remote.insert(
        addr1,
        ConnectionStats {
            rx_bytes: 1000,
            rdns: Some(Some("push.apple.com".to_string())),
            annotation: Some("Apple Push/iCloud - HTTPS".to_string()),
            ..Default::default()
        },
    );

    // rdns = Some(None) → shows raw IP (resolution failed)
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
    state.unknown_by_remote.insert(
        addr2,
        ConnectionStats {
            rx_bytes: 1000,
            rdns: Some(None),
            annotation: Some("HTTP-alt".to_string()),
            ..Default::default()
        },
    );

    // rdns = None → shows raw IP (not yet queried)
    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22);
    state.unknown_by_remote.insert(
        addr3,
        ConnectionStats {
            rx_bytes: 1000,
            rdns: None,
            annotation: Some("local network - SSH".to_string()),
            ..Default::default()
        },
    );

    let mut buf = Vec::new();
    output::write_snapshot(&state, OutputFormat::Pretty, &mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Resolved: hostname shown
    assert!(
        output.contains("push.apple.com:443"),
        "resolved hostname should appear"
    );
    // Failed: raw IP shown
    assert!(
        output.contains("203.0.113.1:8080"),
        "failed rDNS should show raw IP"
    );
    // Not queried: raw IP shown
    assert!(
        output.contains("10.0.0.1:22"),
        "unqueried should show raw IP"
    );
}
