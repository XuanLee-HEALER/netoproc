use std::io::Write;

use crate::error::NetopError;
use crate::model::SystemNetworkState;

/// Write the system network state as TSV to the given writer.
///
/// Output contains 6 sections per REQUIREMENTS.md FR-5.5:
/// processes, sockets, connections, interfaces, dns_resolvers, dns_queries.
/// Each section has a comment header, column header, and data rows.
/// Sections are separated by a blank line.
pub fn write_tsv(state: &SystemNetworkState, writer: &mut impl Write) -> Result<(), NetopError> {
    write_tsv_inner(state, writer).map_err(NetopError::Serialization)
}

fn write_tsv_inner(state: &SystemNetworkState, w: &mut impl Write) -> Result<(), std::io::Error> {
    // Section 1: processes
    writeln!(w, "# processes")?;
    writeln!(
        w,
        "pid\tname\tuser\tsocket_count\tconnection_count\trx_bytes_sec\ttx_bytes_sec\trx_bytes_total\ttx_bytes_total"
    )?;
    for proc in &state.processes {
        let socket_count = proc.sockets.len();
        let connection_count: usize = proc.sockets.iter().map(|s| s.connections.len()).sum();
        let (rx_sec, tx_sec, rx_total, tx_total) = aggregate_process_traffic(proc);
        writeln!(
            w,
            "{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}",
            proc.pid,
            escape_tsv(&proc.name),
            escape_tsv(&proc.username),
            socket_count,
            connection_count,
            rx_sec,
            tx_sec,
            rx_total,
            tx_total,
        )?;
    }

    // Blank line between sections
    writeln!(w)?;

    // Section 2: sockets
    writeln!(w, "# sockets")?;
    writeln!(w, "pid\tprocess\tfd\tproto\tlocal_addr\tstate")?;
    for proc in &state.processes {
        for sock in &proc.sockets {
            writeln!(
                w,
                "{}\t{}\t{}\t{}\t{}\t{}",
                proc.pid,
                escape_tsv(&proc.name),
                sock.fd,
                sock.protocol,
                escape_tsv(&sock.local_addr),
                sock.state,
            )?;
        }
    }

    writeln!(w)?;

    // Section 3: connections
    writeln!(w, "# connections")?;
    writeln!(
        w,
        "pid\tprocess\tfd\tproto\tlocal_addr\tremote_addr\tdirection\tstate\tinterface\trx_bytes_sec\ttx_bytes_sec\trx_bytes_total\ttx_bytes_total\trtt_us\tjitter_us\tretransmissions"
    )?;
    for proc in &state.processes {
        for sock in &proc.sockets {
            for conn in &sock.connections {
                let (rtt, jitter, retrans) = match &conn.stability {
                    Some(s) => (
                        s.rtt_us.to_string(),
                        s.jitter_us.to_string(),
                        s.retransmissions.to_string(),
                    ),
                    None => (String::new(), String::new(), String::new()),
                };
                writeln!(
                    w,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{}",
                    proc.pid,
                    escape_tsv(&proc.name),
                    sock.fd,
                    sock.protocol,
                    escape_tsv(&sock.local_addr),
                    escape_tsv(&conn.remote_addr),
                    conn.direction,
                    sock.state,
                    escape_tsv(&conn.interface),
                    conn.rx_rate.bytes_per_sec,
                    conn.tx_rate.bytes_per_sec,
                    conn.rx_bytes_total,
                    conn.tx_bytes_total,
                    rtt,
                    jitter,
                    retrans,
                )?;
            }
        }
    }

    writeln!(w)?;

    // Section 4: interfaces
    writeln!(w, "# interfaces")?;
    writeln!(
        w,
        "name\tipv4_addr\tipv6_addr\tstatus\trx_bytes_sec\ttx_bytes_sec\trx_bytes_total\ttx_bytes_total\trx_packets\ttx_packets\trx_errors\ttx_errors"
    )?;
    for iface in &state.interfaces {
        let ipv4 = iface.ipv4_addresses.join(",");
        let ipv6 = iface.ipv6_addresses.join(",");
        writeln!(
            w,
            "{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{}\t{}",
            escape_tsv(&iface.name),
            escape_tsv(&ipv4),
            escape_tsv(&ipv6),
            iface.status,
            iface.rx_bytes_rate,
            iface.tx_bytes_rate,
            iface.rx_bytes_total,
            iface.tx_bytes_total,
            iface.rx_packets,
            iface.tx_packets,
            iface.rx_errors,
            iface.tx_errors,
        )?;
    }

    writeln!(w)?;

    // Section 5: dns_resolvers
    writeln!(w, "# dns_resolvers")?;
    writeln!(
        w,
        "interface\tserver\tavg_latency_ms\tfailure_rate_pct\tquery_count"
    )?;
    for resolver in &state.dns.resolvers {
        writeln!(
            w,
            "{}\t{}\t{:.2}\t{:.2}\t{}",
            escape_tsv(&resolver.interface),
            escape_tsv(&resolver.server),
            resolver.avg_latency_ms,
            resolver.failure_rate_pct,
            resolver.query_count,
        )?;
    }

    writeln!(w)?;

    // Section 6: dns_queries
    writeln!(w, "# dns_queries")?;
    writeln!(
        w,
        "timestamp_ms\tpid\tprocess\tquery_name\tquery_type\tresponse\tlatency_ms\tresolver"
    )?;
    for query in &state.dns.queries {
        let pid_str = match query.pid {
            Some(pid) => pid.to_string(),
            None => String::new(),
        };
        writeln!(
            w,
            "{}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{}",
            query.timestamp_ms,
            pid_str,
            escape_tsv(&query.process),
            escape_tsv(&query.query_name),
            escape_tsv(&query.query_type),
            escape_tsv(&query.response),
            query.latency_ms,
            escape_tsv(&query.resolver),
        )?;
    }

    Ok(())
}

pub(crate) fn aggregate_process_traffic(proc: &crate::model::Process) -> (f64, f64, u64, u64) {
    let mut rx_sec = 0.0;
    let mut tx_sec = 0.0;
    let mut rx_total = 0u64;
    let mut tx_total = 0u64;

    for sock in &proc.sockets {
        for conn in &sock.connections {
            rx_sec += conn.rx_rate.bytes_per_sec;
            tx_sec += conn.tx_rate.bytes_per_sec;
            rx_total += conn.rx_bytes_total;
            tx_total += conn.tx_bytes_total;
        }
    }

    (rx_sec, tx_sec, rx_total, tx_total)
}

/// Escape tabs and newlines in a string for TSV output.
fn escape_tsv(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::timeseries::AggregatedTimeSeries;
    use crate::model::*;

    fn empty_state() -> SystemNetworkState {
        SystemNetworkState::empty()
    }

    fn state_with_one_process() -> SystemNetworkState {
        SystemNetworkState {
            timestamp: 1000,
            interfaces: vec![Interface {
                name: "en0".to_string(),
                ipv4_addresses: vec!["192.168.1.100".to_string()],
                ipv6_addresses: vec!["fe80::1".to_string()],
                dns_servers: vec!["8.8.8.8".to_string()],
                search_domains: vec![],
                status: InterfaceStatus::Up,
                rx_bytes_rate: 1024.0,
                tx_bytes_rate: 512.0,
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
                    connections: vec![Connection {
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
                    }],
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
                queries: vec![DnsQuery {
                    timestamp_ms: 1000000,
                    pid: Some(1234),
                    process: "curl".to_string(),
                    query_name: "example.com".to_string(),
                    query_type: "A".to_string(),
                    response: "93.184.216.34".to_string(),
                    latency_ms: 12.5,
                    resolver: "8.8.8.8".to_string(),
                }],
            },
        }
    }

    // UT-7.1: Empty state has section headers and column headers but no data rows
    #[test]
    fn ut_7_1_empty_state() {
        let mut buf = Vec::new();
        write_tsv(&empty_state(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("# processes"));
        assert!(output.contains("# sockets"));
        assert!(output.contains("# connections"));
        assert!(output.contains("# interfaces"));
        assert!(output.contains("# dns_resolvers"));
        assert!(output.contains("# dns_queries"));

        assert!(output.contains("pid\tname\tuser"));

        // No data rows in any section
        for section in output.split("\n\n") {
            let lines: Vec<&str> = section.lines().collect();
            if !lines.is_empty() && lines[0].starts_with('#') {
                assert!(
                    lines.len() <= 2,
                    "Section should have no data rows: {:?}",
                    lines
                );
            }
        }
    }

    // UT-7.2: One process, one connection - correct column counts
    #[test]
    fn ut_7_2_one_process() {
        let mut buf = Vec::new();
        write_tsv(&state_with_one_process(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let sections = parse_sections(&output);
        let processes = &sections["processes"];
        assert_eq!(processes.header.split('\t').count(), 9);
        assert_eq!(processes.rows.len(), 1);
        assert_eq!(processes.rows[0].split('\t').count(), 9);
    }

    // UT-7.3: All 6 sections present
    #[test]
    fn ut_7_3_all_sections() {
        let mut buf = Vec::new();
        write_tsv(&state_with_one_process(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let sections = parse_sections(&output);
        assert!(sections.contains_key("processes"));
        assert!(sections.contains_key("sockets"));
        assert!(sections.contains_key("connections"));
        assert!(sections.contains_key("interfaces"));
        assert!(sections.contains_key("dns_resolvers"));
        assert!(sections.contains_key("dns_queries"));
    }

    // UT-7.4: Blank lines between sections
    #[test]
    fn ut_7_4_blank_lines() {
        let mut buf = Vec::new();
        write_tsv(&state_with_one_process(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.lines().collect();
        let blank_count = lines.iter().filter(|l| l.is_empty()).count();
        // 5 blank lines separating 6 sections
        assert_eq!(blank_count, 5);
    }

    // UT-7.5: Tab in process name is escaped
    #[test]
    fn ut_7_5_tab_escape() {
        let mut state = empty_state();
        state.processes.push(Process {
            pid: 1,
            name: "foo\tbar".to_string(),
            cmdline: String::new(),
            uid: 0,
            username: "root".to_string(),
            sockets: vec![],
        });

        let mut buf = Vec::new();
        write_tsv(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let sections = parse_sections(&output);
        let processes = &sections["processes"];
        assert_eq!(processes.rows.len(), 1);
        assert_eq!(processes.rows[0].split('\t').count(), 9);
        assert!(processes.rows[0].contains("foo bar"));
    }

    // UT-7.6: Newline in command line is escaped
    #[test]
    fn ut_7_6_newline_escape() {
        let result = escape_tsv("line1\nline2");
        assert!(!result.contains('\n'));
        assert_eq!(result, "line1 line2");
    }

    // UT-7.7: IPv6 address formatting
    #[test]
    fn ut_7_7_ipv6_format() {
        let mut state = empty_state();
        state.processes.push(Process {
            pid: 1,
            name: "server".to_string(),
            cmdline: String::new(),
            uid: 0,
            username: "root".to_string(),
            sockets: vec![Socket {
                fd: 5,
                protocol: Protocol::Tcp,
                local_addr: "[::1]:8080".to_string(),
                state: SocketState::Listen,
                connections: vec![],
            }],
        });

        let mut buf = Vec::new();
        write_tsv(&state, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("[::1]:8080"));
    }

    // UT-7.8: Column order matches spec
    #[test]
    fn ut_7_8_column_order() {
        let mut buf = Vec::new();
        write_tsv(&empty_state(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let sections = parse_sections(&output);

        assert_eq!(
            sections["processes"].header,
            "pid\tname\tuser\tsocket_count\tconnection_count\trx_bytes_sec\ttx_bytes_sec\trx_bytes_total\ttx_bytes_total"
        );
        assert_eq!(
            sections["sockets"].header,
            "pid\tprocess\tfd\tproto\tlocal_addr\tstate"
        );
        assert_eq!(
            sections["connections"].header,
            "pid\tprocess\tfd\tproto\tlocal_addr\tremote_addr\tdirection\tstate\tinterface\trx_bytes_sec\ttx_bytes_sec\trx_bytes_total\ttx_bytes_total\trtt_us\tjitter_us\tretransmissions"
        );
        assert_eq!(
            sections["interfaces"].header,
            "name\tipv4_addr\tipv6_addr\tstatus\trx_bytes_sec\ttx_bytes_sec\trx_bytes_total\ttx_bytes_total\trx_packets\ttx_packets\trx_errors\ttx_errors"
        );
        assert_eq!(
            sections["dns_resolvers"].header,
            "interface\tserver\tavg_latency_ms\tfailure_rate_pct\tquery_count"
        );
        assert_eq!(
            sections["dns_queries"].header,
            "timestamp_ms\tpid\tprocess\tquery_name\tquery_type\tresponse\tlatency_ms\tresolver"
        );
    }

    // UT-7.9: No trailing whitespace
    #[test]
    fn ut_7_9_no_trailing_whitespace() {
        let mut buf = Vec::new();
        write_tsv(&state_with_one_process(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        for line in output.lines() {
            assert!(
                !line.ends_with(' ') && !line.ends_with('\t'),
                "Trailing whitespace in line: {:?}",
                line
            );
        }
    }

    // UT-7.10: No ANSI codes
    #[test]
    fn ut_7_10_no_ansi() {
        let mut buf = Vec::new();
        write_tsv(&state_with_one_process(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            !output.contains('\x1B'),
            "Output contains ANSI escape codes"
        );
    }

    // UT-7.11: Consistent column counts per section (parseable by awk)
    #[test]
    fn ut_7_11_consistent_columns() {
        let mut buf = Vec::new();
        write_tsv(&state_with_one_process(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let sections = parse_sections(&output);
        for (name, section) in &sections {
            let expected_cols = section.header.split('\t').count();
            for (i, row) in section.rows.iter().enumerate() {
                let actual_cols = row.split('\t').count();
                assert_eq!(
                    actual_cols, expected_cols,
                    "Section '{}' row {} has {} columns, expected {}",
                    name, i, actual_cols, expected_cols
                );
            }
        }
    }

    // --- Test helpers ---

    struct Section {
        header: String,
        rows: Vec<String>,
    }

    fn parse_sections(output: &str) -> std::collections::HashMap<String, Section> {
        let mut sections = std::collections::HashMap::new();
        let mut current_name = String::new();
        let mut current_header = String::new();
        let mut current_rows = Vec::new();

        for line in output.lines() {
            if let Some(name) = line.strip_prefix("# ") {
                if !current_name.is_empty() {
                    sections.insert(
                        current_name.clone(),
                        Section {
                            header: current_header.clone(),
                            rows: current_rows.clone(),
                        },
                    );
                }
                current_name = name.to_string();
                current_header.clear();
                current_rows.clear();
            } else if line.is_empty() {
                continue;
            } else if current_header.is_empty() {
                current_header = line.to_string();
            } else {
                current_rows.push(line.to_string());
            }
        }

        if !current_name.is_empty() {
            sections.insert(
                current_name,
                Section {
                    header: current_header,
                    rows: current_rows,
                },
            );
        }

        sections
    }
}
