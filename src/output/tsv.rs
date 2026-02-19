use std::collections::HashMap;
use std::io::Write;

use crate::error::NetopError;
use crate::model::traffic::{ProcessKey, TrafficStats};

/// Write per-process traffic stats as TSV.
///
/// Output: header row + data rows sorted by total traffic descending.
/// Columns are tab-separated: pid, process, rx_bytes, tx_bytes, rx_packets, tx_packets.
pub fn write_tsv(
    stats: &HashMap<ProcessKey, TrafficStats>,
    writer: &mut impl Write,
) -> Result<(), NetopError> {
    // Sort by total traffic descending.
    let mut entries: Vec<_> = stats.iter().collect();
    entries.sort_by(|a, b| {
        let total_a = a.1.rx_bytes + a.1.tx_bytes;
        let total_b = b.1.rx_bytes + b.1.tx_bytes;
        total_b.cmp(&total_a)
    });

    writeln!(
        writer,
        "pid\tprocess\trx_bytes\ttx_bytes\trx_packets\ttx_packets"
    )
    .map_err(NetopError::Serialization)?;

    for (key, stats) in &entries {
        let (pid_str, name) = match key {
            ProcessKey::Known { pid, name } => (pid.to_string(), name.as_str()),
            ProcessKey::Unknown => ("-".to_string(), "unknown"),
        };
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}\t{}",
            pid_str,
            escape_tsv(name),
            stats.rx_bytes,
            stats.tx_bytes,
            stats.rx_packets,
            stats.tx_packets,
        )
        .map_err(NetopError::Serialization)?;
    }

    Ok(())
}

/// Escape tabs and newlines in a string for TSV output.
fn escape_tsv(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stats() -> HashMap<ProcessKey, TrafficStats> {
        let mut stats = HashMap::new();
        stats.insert(
            ProcessKey::Known {
                pid: 1234,
                name: "curl".to_string(),
            },
            TrafficStats {
                rx_bytes: 50000,
                tx_bytes: 10000,
                rx_packets: 100,
                tx_packets: 50,
            },
        );
        stats.insert(
            ProcessKey::Known {
                pid: 5678,
                name: "chrome".to_string(),
            },
            TrafficStats {
                rx_bytes: 1200000,
                tx_bytes: 340000,
                rx_packets: 800,
                tx_packets: 200,
            },
        );
        stats.insert(
            ProcessKey::Unknown,
            TrafficStats {
                rx_bytes: 45000,
                tx_bytes: 0,
                rx_packets: 30,
                tx_packets: 0,
            },
        );
        stats
    }

    // UT-7.1: Empty stats produces header only
    #[test]
    fn ut_7_1_empty_stats() {
        let stats = HashMap::new();
        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("pid\tprocess\trx_bytes"));
    }

    // UT-7.2: Correct column count
    #[test]
    fn ut_7_2_column_count() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        for line in output.lines() {
            assert_eq!(
                line.split('\t').count(),
                6,
                "Expected 6 columns in: {:?}",
                line
            );
        }
    }

    // UT-7.3: Sorted by total traffic descending
    #[test]
    fn ut_7_3_sorted_by_traffic() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let data_lines: Vec<&str> = output.lines().skip(1).collect();
        // chrome (1.54M) > curl (60K) > unknown (45K)
        assert!(data_lines[0].contains("chrome"));
        assert!(data_lines[1].contains("curl"));
        assert!(data_lines[2].contains("unknown"));
    }

    // UT-7.4: Unknown process shows "-" for PID
    #[test]
    fn ut_7_4_unknown_pid() {
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
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let data_line = output.lines().nth(1).unwrap();
        assert!(data_line.starts_with("-\tunknown"));
    }

    // UT-7.5: Tab in process name is escaped
    #[test]
    fn ut_7_5_tab_escape() {
        let mut stats = HashMap::new();
        stats.insert(
            ProcessKey::Known {
                pid: 1,
                name: "foo\tbar".to_string(),
            },
            TrafficStats {
                rx_bytes: 100,
                tx_bytes: 0,
                rx_packets: 1,
                tx_packets: 0,
            },
        );

        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let data_line = output.lines().nth(1).unwrap();
        assert_eq!(data_line.split('\t').count(), 6);
        assert!(data_line.contains("foo bar"));
    }

    // UT-7.6: No ANSI codes
    #[test]
    fn ut_7_6_no_ansi() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            !output.contains('\x1B'),
            "Output contains ANSI escape codes"
        );
    }

    // UT-7.7: No trailing whitespace
    #[test]
    fn ut_7_7_no_trailing_whitespace() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        for line in output.lines() {
            assert!(
                !line.ends_with(' ') && !line.ends_with('\t'),
                "Trailing whitespace in line: {:?}",
                line
            );
        }
    }

    // UT-7.8: Column order matches spec
    #[test]
    fn ut_7_8_column_order() {
        let stats = HashMap::new();
        let mut buf = Vec::new();
        write_tsv(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let header = output.lines().next().unwrap();
        assert_eq!(
            header,
            "pid\tprocess\trx_bytes\ttx_bytes\trx_packets\ttx_packets"
        );
    }

    // UT-7.9: Newline escape
    #[test]
    fn ut_7_9_newline_escape() {
        let result = escape_tsv("line1\nline2");
        assert!(!result.contains('\n'));
        assert_eq!(result, "line1 line2");
    }
}
