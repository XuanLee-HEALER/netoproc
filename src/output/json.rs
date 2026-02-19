use std::collections::HashMap;
use std::io::Write;

use serde::Serialize;

use crate::error::NetopError;
use crate::model::traffic::{ProcessKey, TrafficStats};

#[derive(Serialize)]
struct ProcessTrafficRow {
    pid: Option<u32>,
    process: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

/// Write per-process traffic stats as a JSON array.
///
/// Output: `[{"pid": 1234, "process": "chrome", "rx_bytes": ...}, ...]`
/// sorted by total traffic descending.
pub fn write_json(
    stats: &HashMap<ProcessKey, TrafficStats>,
    writer: &mut impl Write,
) -> Result<(), NetopError> {
    let mut rows: Vec<ProcessTrafficRow> = stats
        .iter()
        .map(|(key, stats)| {
            let (pid, name) = match key {
                ProcessKey::Known { pid, name } => (Some(*pid), name.clone()),
                ProcessKey::Unknown => (None, "unknown".to_string()),
            };
            ProcessTrafficRow {
                pid,
                process: name,
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
                rx_packets: stats.rx_packets,
                tx_packets: stats.tx_packets,
            }
        })
        .collect();

    // Sort by total traffic descending.
    rows.sort_by(|a, b| {
        let total_a = a.rx_bytes + a.tx_bytes;
        let total_b = b.rx_bytes + b.tx_bytes;
        total_b.cmp(&total_a)
    });

    serde_json::to_writer_pretty(&mut *writer, &rows)
        .map_err(|e| NetopError::Serialization(std::io::Error::other(e.to_string())))?;
    writeln!(writer).map_err(NetopError::Serialization)?;

    Ok(())
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
        stats
    }

    // UT-8.1: Empty stats produces valid JSON (empty array)
    #[test]
    fn ut_8_1_empty_stats() {
        let stats = HashMap::new();
        let mut buf = Vec::new();
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.as_array().unwrap().is_empty());
    }

    // UT-8.2: Round-trip (serialize then check structure)
    #[test]
    fn ut_8_2_round_trip() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);

        // First entry should be chrome (most traffic)
        assert_eq!(arr[0]["process"].as_str().unwrap(), "chrome");
        assert_eq!(arr[0]["pid"].as_u64().unwrap(), 5678);
        assert_eq!(arr[0]["rx_bytes"].as_u64().unwrap(), 1200000);
    }

    // UT-8.3: Field names are snake_case
    #[test]
    fn ut_8_3_snake_case() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("\"rx_bytes\""));
        assert!(output.contains("\"tx_bytes\""));
        assert!(output.contains("\"rx_packets\""));
        assert!(output.contains("\"tx_packets\""));
        assert!(!output.contains("\"rxBytes\""));
    }

    // UT-8.4: Numeric fields are JSON numbers
    #[test]
    fn ut_8_4_numeric_fields() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed[0]["pid"].is_number());
        assert!(parsed[0]["rx_bytes"].is_number());
        assert!(parsed[0]["tx_bytes"].is_number());
    }

    // UT-8.5: Unknown process has null pid
    #[test]
    fn ut_8_5_unknown_null_pid() {
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
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed[0]["pid"].is_null());
        assert_eq!(parsed[0]["process"].as_str().unwrap(), "unknown");
    }

    // UT-8.6: Large u64 values serialize correctly
    #[test]
    fn ut_8_6_large_u64() {
        let mut stats = HashMap::new();
        stats.insert(
            ProcessKey::Known {
                pid: 1,
                name: "big".to_string(),
            },
            TrafficStats {
                rx_bytes: u64::MAX,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
            },
        );

        let mut buf = Vec::new();
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed[0]["rx_bytes"].as_u64().unwrap(), u64::MAX);
    }

    // UT-8.7: Sorted by total traffic descending
    #[test]
    fn ut_8_7_sorted_by_traffic() {
        let stats = make_stats();
        let mut buf = Vec::new();
        write_json(&stats, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        // chrome (1.54M) should be before curl (60K)
        assert_eq!(arr[0]["process"].as_str().unwrap(), "chrome");
        assert_eq!(arr[1]["process"].as_str().unwrap(), "curl");
    }
}
