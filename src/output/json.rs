use std::io::Write;

use crate::error::NetopError;
use crate::model::SystemNetworkState;

/// Write the system network state as JSON to the given writer.
pub fn write_json(state: &SystemNetworkState, writer: &mut impl Write) -> Result<(), NetopError> {
    serde_json::to_writer_pretty(writer, state)
        .map_err(|e| NetopError::Serialization(std::io::Error::other(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::timeseries::AggregatedTimeSeries;
    use crate::model::*;

    fn empty_state() -> SystemNetworkState {
        SystemNetworkState::empty()
    }

    fn state_with_data() -> SystemNetworkState {
        SystemNetworkState {
            timestamp: 1000,
            interfaces: vec![Interface {
                name: "en0".to_string(),
                ipv4_addresses: vec!["192.168.1.100".to_string()],
                ipv6_addresses: vec![],
                dns_servers: vec!["8.8.8.8".to_string()],
                search_domains: vec![],
                status: InterfaceStatus::Up,
                rx_bytes_rate: 1024.5,
                tx_bytes_rate: 512.3,
                rx_bytes_total: 100000,
                tx_bytes_total: 50000,
                rx_packets: 200,
                tx_packets: 100,
                rx_errors: 0,
                tx_errors: 0,
                rx_timeseries: AggregatedTimeSeries::new(),
                tx_timeseries: AggregatedTimeSeries::new(),
            }],
            processes: vec![Process {
                pid: 1234,
                name: "curl".to_string(),
                cmdline: "curl https://example.com".to_string(),
                uid: 501,
                username: "user".to_string(),
                sockets: vec![Socket {
                    fd: 3,
                    protocol: Protocol::Tcp,
                    local_addr: "192.168.1.100:54321".to_string(),
                    state: SocketState::Established,
                    connections: vec![
                        Connection {
                            remote_addr: "93.184.216.34:443".to_string(),
                            direction: Direction::Outbound,
                            interface: "en0".to_string(),
                            rx_rate: RateMetrics {
                                bytes_per_sec: 1024.0,
                                bytes_per_min: 61440.0,
                            },
                            tx_rate: RateMetrics {
                                bytes_per_sec: 256.0,
                                bytes_per_min: 15360.0,
                            },
                            rx_bytes_total: 50000,
                            tx_bytes_total: 10000,
                            stability: Some(ConnectionStability {
                                rtt_us: 15000,
                                jitter_us: 2000,
                                retransmissions: 3,
                                retransmit_rate: 0.01,
                            }),
                            rx_timeseries: AggregatedTimeSeries::new(),
                            tx_timeseries: AggregatedTimeSeries::new(),
                        },
                        Connection {
                            remote_addr: "10.0.0.1:80".to_string(),
                            direction: Direction::Outbound,
                            interface: "en0".to_string(),
                            rx_rate: RateMetrics::default(),
                            tx_rate: RateMetrics::default(),
                            rx_bytes_total: 0,
                            tx_bytes_total: 0,
                            stability: None, // UDP-like, no stability
                            rx_timeseries: AggregatedTimeSeries::new(),
                            tx_timeseries: AggregatedTimeSeries::new(),
                        },
                    ],
                }],
            }],
            dns: DnsObservatory {
                resolvers: vec![DnsResolver {
                    interface: "global".to_string(),
                    server: "8.8.8.8".to_string(),
                    avg_latency_ms: 12.5,
                    failure_rate_pct: 0.1,
                    query_count: 42,
                }],
                queries: vec![],
            },
        }
    }

    // UT-8.1: Empty state produces valid JSON with empty arrays
    #[test]
    fn ut_8_1_empty_state() {
        let mut buf = Vec::new();
        write_json(&empty_state(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["processes"].as_array().unwrap().is_empty());
        assert!(parsed["interfaces"].as_array().unwrap().is_empty());
        assert!(parsed["dns"]["resolvers"].as_array().unwrap().is_empty());
        assert!(parsed["dns"]["queries"].as_array().unwrap().is_empty());
    }

    // UT-8.2: Round-trip (serialize then check structure)
    #[test]
    fn ut_8_2_round_trip() {
        let state = state_with_data();
        let mut buf = Vec::new();
        write_json(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["timestamp"].as_u64().unwrap(), 1000);
        assert_eq!(parsed["processes"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["processes"][0]["pid"].as_u64().unwrap(), 1234);
        assert_eq!(parsed["processes"][0]["name"].as_str().unwrap(), "curl");
        assert_eq!(parsed["interfaces"][0]["name"].as_str().unwrap(), "en0");
    }

    // UT-8.3: Field names are snake_case
    #[test]
    fn ut_8_3_snake_case() {
        let mut buf = Vec::new();
        write_json(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Check that key field names are snake_case
        assert!(output.contains("\"rx_bytes_rate\""));
        assert!(output.contains("\"tx_bytes_rate\""));
        assert!(output.contains("\"rx_bytes_total\""));
        assert!(output.contains("\"bytes_per_sec\""));
        assert!(output.contains("\"bytes_per_min\""));
        assert!(output.contains("\"ipv4_addresses\""));
        assert!(output.contains("\"search_domains\""));
        assert!(output.contains("\"query_count\""));
        assert!(output.contains("\"remote_addr\""));

        // No camelCase variants
        assert!(!output.contains("\"rxBytesRate\""));
        assert!(!output.contains("\"bytesPerSec\""));
    }

    // UT-8.4: Numeric fields are JSON numbers
    #[test]
    fn ut_8_4_numeric_fields() {
        let mut buf = Vec::new();
        write_json(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        // pid should be a number, not a string
        assert!(parsed["processes"][0]["pid"].is_number());
        // fd should be a number
        assert!(parsed["processes"][0]["sockets"][0]["fd"].is_number());
        // timestamp should be a number
        assert!(parsed["timestamp"].is_number());
        // rx_bytes_total should be a number
        assert!(parsed["interfaces"][0]["rx_bytes_total"].is_number());
    }

    // UT-8.5: Optional fields (stability: null for connections without it)
    #[test]
    fn ut_8_5_optional_stability() {
        let mut buf = Vec::new();
        write_json(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let conns = &parsed["processes"][0]["sockets"][0]["connections"];

        // First connection has stability
        assert!(conns[0]["stability"].is_object());
        assert!(conns[0]["stability"]["rtt_us"].is_number());

        // Second connection has null stability
        assert!(conns[1]["stability"].is_null());
    }

    // UT-8.6: Large u64 values serialize correctly
    #[test]
    fn ut_8_6_large_u64() {
        let mut state = empty_state();
        state.interfaces.push(Interface {
            name: "lo0".to_string(),
            rx_bytes_total: u64::MAX,
            tx_bytes_total: u64::MAX,
            ..Default::default()
        });

        let mut buf = Vec::new();
        write_json(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            parsed["interfaces"][0]["rx_bytes_total"].as_u64().unwrap(),
            u64::MAX
        );
    }

    // UT-8.7: Float precision is reasonable
    #[test]
    fn ut_8_7_float_precision() {
        let mut buf = Vec::new();
        write_json(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rate = parsed["interfaces"][0]["rx_bytes_rate"].as_f64().unwrap();
        assert!((rate - 1024.5).abs() < 0.001);
    }
}
