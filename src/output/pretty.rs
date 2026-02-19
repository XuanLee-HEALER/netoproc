use std::collections::HashMap;
use std::io::Write;

use crate::error::NetopError;
use crate::model::traffic::{ProcessKey, TrafficStats};

/// Write per-process traffic stats in a human-readable table format.
pub fn write_pretty(
    stats: &HashMap<ProcessKey, TrafficStats>,
    writer: &mut impl Write,
) -> Result<(), NetopError> {
    write_pretty_inner(stats, writer).map_err(NetopError::Serialization)
}

fn write_pretty_inner(
    stats: &HashMap<ProcessKey, TrafficStats>,
    w: &mut impl Write,
) -> Result<(), std::io::Error> {
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

    fn make_stats() -> HashMap<ProcessKey, TrafficStats> {
        let mut stats = HashMap::new();
        stats.insert(
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
        stats.insert(
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
        stats
    }

    #[test]
    fn pretty_contains_header() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_pretty(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Per-Process Network Traffic"));
        assert!(output.contains("PID"));
        assert!(output.contains("PROCESS"));
        assert!(output.contains("RX"));
        assert!(output.contains("TX"));
    }

    #[test]
    fn pretty_sorted_by_traffic() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_pretty(&stats, &mut buf).unwrap();
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
        let stats = HashMap::new();
        let mut buf = Vec::new();
        write_pretty(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("(no traffic captured)"));
    }

    #[test]
    fn pretty_no_ansi_codes() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_pretty(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            !output.contains('\x1b'),
            "pretty output should have no ANSI escape codes"
        );
    }

    #[test]
    fn pretty_summary_line() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_pretty(&stats, &mut buf).unwrap();
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
        let mut stats = HashMap::new();
        stats.insert(
            ProcessKey::Unknown,
            TrafficStats {
                rx_bytes: 100,
                tx_bytes: 0,
                rx_packets: 1,
                tx_packets: 0,
            },
        );

        let mut buf = Vec::new();
        write_pretty(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("unknown"));
        assert!(output.contains("-"));
    }
}
