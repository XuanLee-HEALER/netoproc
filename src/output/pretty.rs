use std::io::Write;

use crate::error::NetopError;
use crate::model::{
    Connection, Direction, Interface, Process, Socket, SocketState, SystemNetworkState,
};
use crate::output::tsv::aggregate_process_traffic;
use crate::tui::widgets::rate::{format_bytes, format_rate};

/// Write a human-readable, process-organized tree view of the system network state.
///
/// Output is plain text (no ANSI colors) with Unicode box-drawing characters,
/// designed to work well with `less` and `/pattern` search.
pub fn write_pretty(state: &SystemNetworkState, writer: &mut impl Write) -> Result<(), NetopError> {
    write_pretty_inner(state, writer).map_err(NetopError::Serialization)
}

fn write_pretty_inner(
    state: &SystemNetworkState,
    w: &mut impl Write,
) -> Result<(), std::io::Error> {
    write_processes_section(state, w)?;
    writeln!(w)?;
    write_interfaces_section(state, w)?;
    writeln!(w)?;
    write_dns_section(state, w)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

fn write_processes_section(
    state: &SystemNetworkState,
    w: &mut impl Write,
) -> Result<(), std::io::Error> {
    let count = state.processes.len();
    writeln!(
        w,
        "\u{256e}\u{2500} Processes ({count}) \u{2500}{:\u{2500}<width$}",
        "",
        width = 40
    )?;

    // Sort processes by aggregate traffic rate (rx+tx) descending.
    let mut sorted: Vec<&Process> = state.processes.iter().collect();
    sorted.sort_by(|a, b| {
        let (a_rx, a_tx, _, _) = aggregate_process_traffic(a);
        let (b_rx, b_tx, _, _) = aggregate_process_traffic(b);
        let b_total = b_rx + b_tx;
        let a_total = a_rx + a_tx;
        b_total
            .partial_cmp(&a_total)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for proc in &sorted {
        write_process(proc, w)?;
    }

    Ok(())
}

fn write_process(proc: &Process, w: &mut impl Write) -> Result<(), std::io::Error> {
    let socket_count = proc.sockets.len();
    let conn_count: usize = proc.sockets.iter().map(|s| s.connections.len()).sum();
    let (rx_sec, tx_sec, rx_total, tx_total) = aggregate_process_traffic(proc);

    writeln!(
        w,
        "{} (PID {}, {}) \u{2014} {} sockets, {} connections",
        proc.name, proc.pid, proc.username, socket_count, conn_count
    )?;
    writeln!(
        w,
        "  rx: {}  tx: {}  total: {} rx / {} tx",
        format_rate(rx_sec),
        format_rate(tx_sec),
        format_bytes(rx_total),
        format_bytes(tx_total),
    )?;

    let num_sockets = proc.sockets.len();
    for (i, sock) in proc.sockets.iter().enumerate() {
        let is_last_sock = i == num_sockets - 1;
        write_socket(sock, is_last_sock, w)?;
    }

    writeln!(w)?;
    Ok(())
}

fn write_socket(sock: &Socket, is_last: bool, w: &mut impl Write) -> Result<(), std::io::Error> {
    let branch = if is_last {
        "\u{2514}\u{2500}"
    } else {
        "\u{251c}\u{2500}"
    };
    let continuation = if is_last { "  " } else { "\u{2502} " };

    if sock.connections.is_empty() {
        // Listening/bound socket with no connections — single line.
        writeln!(
            w,
            "  {branch} [{proto}] {addr} {state}",
            proto = sock.protocol,
            addr = sock.local_addr,
            state = sock.state,
        )?;
    } else if sock.state == SocketState::Listen || sock.state == SocketState::Bound {
        // Listening socket with inbound connections.
        writeln!(
            w,
            "  {branch} [{proto}] {addr} {state}",
            proto = sock.protocol,
            addr = sock.local_addr,
            state = sock.state,
        )?;
        let num_conns = sock.connections.len();
        for (j, conn) in sock.connections.iter().enumerate() {
            let is_last_conn = j == num_conns - 1;
            let conn_branch = if is_last_conn {
                "\u{2514}\u{2500}"
            } else {
                "\u{251c}\u{2500}"
            };
            let arrow = direction_arrow(conn);
            writeln!(
                w,
                "  {continuation}  {conn_branch} {arrow} {remote} {state}  rx: {rx}  tx: {tx}",
                remote = conn.remote_addr,
                state = sock.state,
                rx = format_rate(conn.rx_rate.bytes_per_sec),
                tx = format_rate(conn.tx_rate.bytes_per_sec),
            )?;
        }
    } else {
        // Outbound or single connection — show on the socket line itself.
        for (j, conn) in sock.connections.iter().enumerate() {
            let actual_branch = if j == 0 {
                branch
            } else if is_last && j == sock.connections.len() - 1 {
                "  \u{2514}\u{2500}"
            } else {
                &format!("  {continuation}\u{251c}\u{2500}")
            };

            let arrow = direction_arrow(conn);
            if j == 0 {
                writeln!(
                    w,
                    "  {actual_branch} [{proto}] {local} {arrow} {remote} {state}",
                    proto = sock.protocol,
                    local = sock.local_addr,
                    remote = conn.remote_addr,
                    state = sock.state,
                )?;
                // Print rate on a continuation line if non-zero.
                if conn.rx_rate.bytes_per_sec > 0.0 || conn.tx_rate.bytes_per_sec > 0.0 {
                    writeln!(
                        w,
                        "  {continuation}        rx: {}  tx: {}",
                        format_rate(conn.rx_rate.bytes_per_sec),
                        format_rate(conn.tx_rate.bytes_per_sec),
                    )?;
                }
            } else {
                writeln!(
                    w,
                    "  {actual_branch} {arrow} {remote} {state}  rx: {rx}  tx: {tx}",
                    remote = conn.remote_addr,
                    state = sock.state,
                    rx = format_rate(conn.rx_rate.bytes_per_sec),
                    tx = format_rate(conn.tx_rate.bytes_per_sec),
                )?;
            }
        }
    }

    Ok(())
}

fn direction_arrow(conn: &Connection) -> &'static str {
    match conn.direction {
        Direction::Outbound => "\u{2192}",
        Direction::Inbound => "\u{2190}",
    }
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

fn write_interfaces_section(
    state: &SystemNetworkState,
    w: &mut impl Write,
) -> Result<(), std::io::Error> {
    let count = state.interfaces.len();
    writeln!(
        w,
        "\u{256e}\u{2500} Interfaces ({count}) \u{2500}{:\u{2500}<width$}",
        "",
        width = 39
    )?;

    let (active, inactive): (Vec<&Interface>, Vec<&Interface>) = state
        .interfaces
        .iter()
        .partition(|i| i.rx_bytes_total > 0 || i.tx_bytes_total > 0);

    for iface in &active {
        write_interface(iface, w)?;
    }

    if !inactive.is_empty() {
        writeln!(w, "  ({} more with no traffic)", inactive.len())?;
    }

    Ok(())
}

fn write_interface(iface: &Interface, w: &mut impl Write) -> Result<(), std::io::Error> {
    let ip = iface.ipv4_addresses.first().cloned().unwrap_or_default();

    writeln!(
        w,
        "{name:<12}{ip:<17}{status:<6}rx: {rx_total} ({rx_rate})  tx: {tx_total} ({tx_rate})",
        name = iface.name,
        status = iface.status,
        rx_total = format_bytes(iface.rx_bytes_total),
        rx_rate = format_rate(iface.rx_bytes_rate),
        tx_total = format_bytes(iface.tx_bytes_total),
        tx_rate = format_rate(iface.tx_bytes_rate),
    )?;

    // Second line: IPv6, packet/error counts.
    let ipv6 = iface
        .ipv6_addresses
        .first()
        .map(|a| truncate_ipv6(a))
        .unwrap_or_default();

    if !ipv6.is_empty() || iface.rx_packets > 0 {
        writeln!(
            w,
            "{:12}{ipv6:<17}      pkts: {rx_pkts}/{tx_pkts}  err: {rx_err}/{tx_err}",
            "",
            rx_pkts = iface.rx_packets,
            tx_pkts = iface.tx_packets,
            rx_err = iface.rx_errors,
            tx_err = iface.tx_errors,
        )?;
    }

    Ok(())
}

/// Truncate long IPv6 addresses for display (keep first 12 chars + "...").
fn truncate_ipv6(addr: &str) -> String {
    if addr.len() > 15 {
        format!("{}...", &addr[..12])
    } else {
        addr.to_string()
    }
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

fn write_dns_section(state: &SystemNetworkState, w: &mut impl Write) -> Result<(), std::io::Error> {
    writeln!(
        w,
        "\u{256e}\u{2500} DNS \u{2500}{:\u{2500}<width$}",
        "",
        width = 51
    )?;

    writeln!(w, "Resolvers:")?;
    if state.dns.resolvers.is_empty() {
        writeln!(w, "  (none)")?;
    } else {
        for r in &state.dns.resolvers {
            writeln!(
                w,
                "  {} \u{2192} {}  ({} queries, {:.1}ms avg, {:.1}% fail)",
                r.interface, r.server, r.query_count, r.avg_latency_ms, r.failure_rate_pct,
            )?;
        }
    }

    writeln!(w)?;
    writeln!(w, "Recent Queries:")?;
    if state.dns.queries.is_empty() {
        writeln!(w, "  (none)")?;
    } else {
        let display_count = state.dns.queries.len().min(20);
        for q in state.dns.queries.iter().take(display_count) {
            let pid_str = match q.pid {
                Some(pid) => format!("PID {pid}"),
                None => "?".to_string(),
            };
            writeln!(
                w,
                "  {} {} ({}) \u{2192} {} ({}, {:.1}ms, via {})",
                q.query_type,
                q.query_name,
                pid_str,
                q.response,
                q.process,
                q.latency_ms,
                q.resolver,
            )?;
        }
        if state.dns.queries.len() > display_count {
            writeln!(
                w,
                "  ... and {} more",
                state.dns.queries.len() - display_count
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::timeseries::AggregatedTimeSeries;
    use crate::model::*;

    fn state_with_data() -> SystemNetworkState {
        SystemNetworkState {
            timestamp: 1000,
            interfaces: vec![
                Interface {
                    name: "en0".to_string(),
                    ipv4_addresses: vec!["192.168.3.12".to_string()],
                    ipv6_addresses: vec!["fe80::c77:abcd:ef01:2345".to_string()],
                    dns_servers: vec![],
                    search_domains: vec![],
                    status: InterfaceStatus::Up,
                    rx_bytes_rate: 1200.0,
                    tx_bytes_rate: 340.0,
                    rx_bytes_total: 2_100_000_000,
                    tx_bytes_total: 336_000_000,
                    rx_packets: 1_760_640,
                    tx_packets: 745_472,
                    rx_errors: 0,
                    tx_errors: 0,
                    rx_timeseries: AggregatedTimeSeries::new(),
                    tx_timeseries: AggregatedTimeSeries::new(),
                },
                Interface {
                    name: "lo0".to_string(),
                    ipv4_addresses: vec!["127.0.0.1".to_string()],
                    ipv6_addresses: vec![],
                    dns_servers: vec![],
                    search_domains: vec![],
                    status: InterfaceStatus::Up,
                    rx_bytes_rate: 0.0,
                    tx_bytes_rate: 0.0,
                    rx_bytes_total: 0,
                    tx_bytes_total: 0,
                    rx_packets: 0,
                    tx_packets: 0,
                    rx_errors: 0,
                    tx_errors: 0,
                    rx_timeseries: AggregatedTimeSeries::new(),
                    tx_timeseries: AggregatedTimeSeries::new(),
                },
            ],
            processes: vec![
                Process {
                    pid: 3556,
                    name: "verge-mihomo".to_string(),
                    cmdline: String::new(),
                    uid: 0,
                    username: "root".to_string(),
                    sockets: vec![
                        Socket {
                            fd: 10,
                            protocol: Protocol::Tcp,
                            local_addr: "127.0.0.1:7897".to_string(),
                            state: SocketState::Listen,
                            connections: vec![],
                        },
                        Socket {
                            fd: 11,
                            protocol: Protocol::Tcp,
                            local_addr: "192.168.3.12:53181".to_string(),
                            state: SocketState::Established,
                            connections: vec![Connection {
                                remote_addr: "64.64.252.128:443".to_string(),
                                direction: Direction::Outbound,
                                interface: "en0".to_string(),
                                rx_rate: RateMetrics {
                                    bytes_per_sec: 500.0,
                                    bytes_per_min: 30000.0,
                                },
                                tx_rate: RateMetrics {
                                    bytes_per_sec: 120.0,
                                    bytes_per_min: 7200.0,
                                },
                                rx_bytes_total: 50000,
                                tx_bytes_total: 12000,
                                stability: None,
                                rx_timeseries: AggregatedTimeSeries::new(),
                                tx_timeseries: AggregatedTimeSeries::new(),
                            }],
                        },
                    ],
                },
                Process {
                    pid: 11598,
                    name: "Code Helper".to_string(),
                    cmdline: String::new(),
                    uid: 501,
                    username: "mouselee".to_string(),
                    sockets: vec![Socket {
                        fd: 20,
                        protocol: Protocol::Tcp,
                        local_addr: "198.18.0.1:59349".to_string(),
                        state: SocketState::Established,
                        connections: vec![Connection {
                            remote_addr: "198.18.0.235:443".to_string(),
                            direction: Direction::Outbound,
                            interface: "utun1024".to_string(),
                            rx_rate: RateMetrics {
                                bytes_per_sec: 0.0,
                                bytes_per_min: 0.0,
                            },
                            tx_rate: RateMetrics {
                                bytes_per_sec: 0.0,
                                bytes_per_min: 0.0,
                            },
                            rx_bytes_total: 0,
                            tx_bytes_total: 0,
                            stability: None,
                            rx_timeseries: AggregatedTimeSeries::new(),
                            tx_timeseries: AggregatedTimeSeries::new(),
                        }],
                    }],
                },
            ],
            dns: DnsObservatory {
                resolvers: vec![DnsResolver {
                    interface: "global".to_string(),
                    server: "223.6.6.6".to_string(),
                    avg_latency_ms: 0.0,
                    failure_rate_pct: 0.0,
                    query_count: 0,
                }],
                queries: vec![],
            },
        }
    }

    #[test]
    fn pretty_contains_section_headers() {
        let mut buf = Vec::new();
        write_pretty(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Processes (2)"));
        assert!(output.contains("Interfaces (2)"));
        assert!(output.contains("DNS"));
    }

    #[test]
    fn pretty_processes_sorted_by_traffic() {
        let mut buf = Vec::new();
        write_pretty(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // verge-mihomo has traffic, Code Helper has 0 — verge should appear first.
        let pos_verge = output.find("verge-mihomo").unwrap();
        let pos_code = output.find("Code Helper").unwrap();
        assert!(
            pos_verge < pos_code,
            "verge-mihomo should appear before Code Helper"
        );
    }

    #[test]
    fn pretty_inactive_interfaces_collapsed() {
        let mut buf = Vec::new();
        write_pretty(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // lo0 has 0 traffic — should be collapsed into summary.
        assert!(output.contains("1 more with no traffic"));
        // en0 should appear as a full line.
        assert!(output.contains("en0"));
    }

    #[test]
    fn pretty_no_ansi_codes() {
        let mut buf = Vec::new();
        write_pretty(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            !output.contains('\x1b'),
            "pretty output should have no ANSI escape codes"
        );
    }

    #[test]
    fn pretty_empty_state() {
        let mut buf = Vec::new();
        write_pretty(&SystemNetworkState::empty(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Processes (0)"));
        assert!(output.contains("Interfaces (0)"));
        assert!(output.contains("(none)"));
    }

    #[test]
    fn pretty_dns_resolvers_shown() {
        let mut buf = Vec::new();
        write_pretty(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("223.6.6.6"));
        assert!(output.contains("Recent Queries:"));
        assert!(output.contains("(none)"));
    }

    #[test]
    fn pretty_connection_arrows() {
        let mut buf = Vec::new();
        write_pretty(&state_with_data(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Outbound connection should have → arrow.
        assert!(output.contains("\u{2192}"));
    }
}
