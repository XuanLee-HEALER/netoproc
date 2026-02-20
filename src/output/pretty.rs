use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;

use crate::error::NetopError;
use crate::model::traffic::{ConnectionStats, ProcessKey, StatsState};

/// Write per-process traffic stats in a human-readable table format.
///
/// When Unknown traffic has per-remote details, indented sub-rows are shown
/// below the unknown aggregate row (sorted by traffic, top 10).
pub fn write_pretty(state: &StatsState, writer: &mut impl Write) -> Result<(), NetopError> {
    write_pretty_inner(state, writer).map_err(NetopError::Serialization)
}

fn write_pretty_inner(state: &StatsState, w: &mut impl Write) -> Result<(), std::io::Error> {
    let stats = &state.by_process;

    // Sort by total traffic descending.
    let mut entries: Vec<_> = stats.iter().collect();
    entries.sort_by(|a, b| {
        let total_a = a.1.rx_bytes + a.1.tx_bytes;
        let total_b = b.1.rx_bytes + b.1.tx_bytes;
        total_b.cmp(&total_a)
    });

    writeln!(w, "Per-Process Network Traffic")?;
    writeln!(w, "{}", "=".repeat(78))?;
    writeln!(
        w,
        "{:<8} {:<24} {:>12} {:>12} {:>10} {:>10}",
        "PID", "PROCESS", "RX", "TX", "RX_PKT", "TX_PKT"
    )?;
    writeln!(w, "{}", "-".repeat(78))?;

    for (key, traffic) in &entries {
        let (pid_str, name) = match key {
            ProcessKey::Known { pid, name } => (pid.to_string(), name.as_str()),
            ProcessKey::Unknown => ("-".to_string(), "unknown"),
        };
        writeln!(
            w,
            "{:<8} {:<24} {:>12} {:>12} {:>10} {:>10}",
            pid_str,
            truncate(name, 24),
            format_bytes(traffic.rx_bytes),
            format_bytes(traffic.tx_bytes),
            traffic.rx_packets,
            traffic.tx_packets,
        )?;

        // Render Unknown sub-rows.
        if **key == ProcessKey::Unknown && !state.unknown_by_remote.is_empty() {
            write_unknown_sub_rows(w, &state.unknown_by_remote)?;
        }
    }

    if entries.is_empty() {
        writeln!(w, "(no traffic captured)")?;
    }

    writeln!(w, "{}", "-".repeat(78))?;

    // Summary line.
    let total_rx: u64 = stats.values().map(|s| s.rx_bytes).sum();
    let total_tx: u64 = stats.values().map(|s| s.tx_bytes).sum();
    let total_rx_pkt: u64 = stats.values().map(|s| s.rx_packets).sum();
    let total_tx_pkt: u64 = stats.values().map(|s| s.tx_packets).sum();
    writeln!(
        w,
        "{:<8} {:<24} {:>12} {:>12} {:>10} {:>10}",
        "",
        "TOTAL",
        format_bytes(total_rx),
        format_bytes(total_tx),
        total_rx_pkt,
        total_tx_pkt,
    )?;

    Ok(())
}

/// Render indented sub-rows for Unknown traffic, sorted by total traffic descending.
fn write_unknown_sub_rows(
    w: &mut impl Write,
    unknown_by_remote: &HashMap<SocketAddr, ConnectionStats>,
) -> Result<(), std::io::Error> {
    let mut remotes: Vec<_> = unknown_by_remote.iter().collect();
    remotes.sort_by(|a, b| {
        let total_a = a.1.rx_bytes + a.1.tx_bytes;
        let total_b = b.1.rx_bytes + b.1.tx_bytes;
        total_b.cmp(&total_a)
    });

    let show_count = remotes.len().min(10);
    for (addr, conn) in &remotes[..show_count] {
        let label = format_remote_label(addr, conn);
        let annotation = conn.annotation.as_deref().unwrap_or("");
        writeln!(
            w,
            "  {:<30} {:>12} {:>12}       {}",
            truncate(&label, 30),
            format_bytes(conn.rx_bytes),
            format_bytes(conn.tx_bytes),
            annotation,
        )?;
    }

    let remaining = remotes.len().saturating_sub(10);
    if remaining > 0 {
        writeln!(w, "  ({remaining} more connections...)")?;
    }

    Ok(())
}

/// Format the remote address label, using reverse DNS hostname if available.
fn format_remote_label(addr: &SocketAddr, conn: &ConnectionStats) -> String {
    match &conn.rdns {
        Some(Some(hostname)) => format!("{hostname}:{}", addr.port()),
        _ => addr.to_string(),
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::model::traffic::TrafficStats;

    fn make_state() -> StatsState {
        let mut state = StatsState::default();
        state.by_process.insert(
            ProcessKey::Known {
                pid: 3556,
                name: "verge-mihomo".to_string(),
            },
            TrafficStats {
                rx_bytes: 50000,
                tx_bytes: 12000,
                rx_packets: 100,
                tx_packets: 50,
            },
        );
        state.by_process.insert(
            ProcessKey::Known {
                pid: 11598,
                name: "Code Helper".to_string(),
            },
            TrafficStats {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
            },
        );
        state
    }

    #[test]
    fn pretty_contains_header() {
        let state = make_state();
        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Per-Process Network Traffic"));
        assert!(output.contains("PID"));
        assert!(output.contains("PROCESS"));
        assert!(output.contains("RX"));
        assert!(output.contains("TX"));
    }

    #[test]
    fn pretty_sorted_by_traffic() {
        let state = make_state();
        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // verge-mihomo has traffic, Code Helper has 0.
        let pos_verge = output.find("verge-mihomo").unwrap();
        let pos_code = output.find("Code Helper").unwrap();
        assert!(
            pos_verge < pos_code,
            "verge-mihomo should appear before Code Helper"
        );
    }

    #[test]
    fn pretty_empty_stats() {
        let state = StatsState::default();
        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("(no traffic captured)"));
    }

    #[test]
    fn pretty_no_ansi_codes() {
        let state = make_state();
        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            !output.contains('\x1b'),
            "pretty output should have no ANSI escape codes"
        );
    }

    #[test]
    fn pretty_summary_line() {
        let state = make_state();
        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("TOTAL"));
    }

    #[test]
    fn pretty_format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GiB");
    }

    #[test]
    fn pretty_truncate() {
        assert_eq!(truncate("short", 24), "short");
        assert_eq!(
            truncate(
                "this is a very long process name that should be truncated",
                24
            ),
            "this is a very long p..."
        );
    }

    #[test]
    fn pretty_unknown_process() {
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

        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("unknown"));
        assert!(output.contains("-"));
    }

    #[test]
    fn pretty_unknown_sub_rows() {
        let mut state = StatsState::default();
        state.by_process.insert(
            ProcessKey::Unknown,
            TrafficStats {
                rx_bytes: 13500,
                tx_bytes: 13600,
                rx_packets: 29,
                tx_packets: 34,
            },
        );
        // Add remote connections
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
        state.unknown_by_remote.insert(
            addr1,
            ConnectionStats {
                rx_bytes: 5222,
                tx_bytes: 0,
                annotation: Some("Apple Push/iCloud - HTTPS".to_string()),
                ..Default::default()
            },
        );
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        state.unknown_by_remote.insert(
            addr2,
            ConnectionStats {
                rx_bytes: 0,
                tx_bytes: 3277,
                annotation: Some("local network - DNS".to_string()),
                ..Default::default()
            },
        );

        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Sub-rows appear
        assert!(output.contains("17.57.144.83:443"));
        assert!(output.contains("Apple Push/iCloud - HTTPS"));
        assert!(output.contains("192.168.1.1:53"));
        assert!(output.contains("local network - DNS"));
    }

    #[test]
    fn pretty_unknown_sub_rows_with_rdns() {
        let mut state = StatsState::default();
        state.by_process.insert(
            ProcessKey::Unknown,
            TrafficStats {
                rx_bytes: 1000,
                tx_bytes: 0,
                rx_packets: 1,
                tx_packets: 0,
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
        state.unknown_by_remote.insert(
            addr,
            ConnectionStats {
                rx_bytes: 1000,
                tx_bytes: 0,
                rdns: Some(Some("courier.push.apple.com".to_string())),
                annotation: Some("Apple Push/iCloud - HTTPS".to_string()),
                ..Default::default()
            },
        );

        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Should show hostname instead of IP
        assert!(output.contains("courier.push.apple.com:443"));
    }

    #[test]
    fn pretty_unknown_sub_rows_limited_to_10() {
        let mut state = StatsState::default();
        state.by_process.insert(
            ProcessKey::Unknown,
            TrafficStats {
                rx_bytes: 15000,
                tx_bytes: 0,
                rx_packets: 15,
                tx_packets: 0,
            },
        );
        for i in 0..15u8 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 80);
            state.unknown_by_remote.insert(
                addr,
                ConnectionStats {
                    rx_bytes: 1000,
                    tx_bytes: 0,
                    ..Default::default()
                },
            );
        }

        let mut buf = Vec::new();
        write_pretty(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("(5 more connections...)"));
    }
}
