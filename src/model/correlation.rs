use std::collections::HashMap;
use std::net::IpAddr;

use crate::dns::DnsMessage;
use crate::model::{
    Connection, Direction, DnsObservatory, DnsQuery, DnsResolver, Interface, InterfaceStatus,
    Process, Protocol, RateMetrics, Socket, SocketState, SystemNetworkState,
};
use crate::packet::PacketSummary;
use crate::system::connection::{RawTcpConnection, RawUdpConnection};
use crate::system::dns_config::RawDnsResolver;
use crate::system::interface::RawInterface;
use crate::system::process::{self, RawProcess, RawSocket};

/// A 5-tuple identifying a connection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FiveTuple {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
}

/// Association between a process and a socket.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ProcessSocket {
    pid: u32,
    name: String,
    uid: u32,
    fd: i32,
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    state: SocketState,
    direction: Direction,
}

/// Set of listening endpoints for direction determination.
#[derive(Default)]
struct ListenSet {
    entries: HashMap<(Protocol, u16), bool>, // (protocol, local_port) -> is_listening
}

impl ListenSet {
    fn add(&mut self, protocol: Protocol, port: u16) {
        self.entries.insert((protocol, port), true);
    }

    fn is_listening(&self, protocol: Protocol, port: u16) -> bool {
        self.entries.contains_key(&(protocol, port))
    }
}

/// Correlate all raw data sources into a unified SystemNetworkState.
#[allow(clippy::too_many_arguments)]
pub fn correlate(
    raw_processes: &[RawProcess],
    raw_tcp: &[RawTcpConnection],
    _raw_udp: &[RawUdpConnection],
    raw_interfaces: &[RawInterface],
    raw_dns_resolvers: &[RawDnsResolver],
    packets: &[PacketSummary],
    dns_messages: &[DnsMessage],
    prev_state: &SystemNetworkState,
) -> SystemNetworkState {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 1. Build listen set and process-socket index
    let mut listen_set = ListenSet::default();
    let mut five_tuple_map: HashMap<FiveTuple, ProcessSocket> = HashMap::new();

    for proc in raw_processes {
        for sock in &proc.sockets {
            let protocol = raw_protocol_to_model(sock);
            let state = raw_state_to_model(sock);

            if state == SocketState::Listen {
                listen_set.add(protocol, sock.local_port);
            }

            // Register 5-tuples for sockets that have remote endpoints
            if let (Some(local_addr), Some(remote_addr)) = (sock.local_addr, sock.remote_addr)
                && (sock.remote_port > 0 || sock.local_port > 0)
            {
                let direction = if listen_set.is_listening(protocol, sock.local_port) {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };

                let tuple = FiveTuple {
                    protocol,
                    local_addr,
                    local_port: sock.local_port,
                    remote_addr,
                    remote_port: sock.remote_port,
                };

                five_tuple_map.insert(
                    tuple,
                    ProcessSocket {
                        pid: proc.pid,
                        name: proc.name.clone(),
                        uid: proc.uid,
                        fd: sock.fd,
                        protocol,
                        local_addr,
                        local_port: sock.local_port,
                        state,
                        direction,
                    },
                );
            }
        }
    }

    // 2. Also index connections from sysctl (these provide connections for processes we may not be able to inspect)
    // Build a map from (local_addr, local_port, remote_addr, remote_port) → tcp_state
    let mut tcp_conn_map: HashMap<(IpAddr, u16, IpAddr, u16), i32> = HashMap::new();
    for conn in raw_tcp {
        tcp_conn_map.insert(
            (
                conn.local_addr,
                conn.local_port,
                conn.remote_addr,
                conn.remote_port,
            ),
            conn.tcp_state,
        );
    }

    // 3. Accumulate packet bytes per 5-tuple
    let mut bytes_rx: HashMap<FiveTuple, u64> = HashMap::new();
    let mut bytes_tx: HashMap<FiveTuple, u64> = HashMap::new();

    for pkt in packets {
        // Try forward direction: this packet's dst matches our local addr
        let forward = FiveTuple {
            protocol: pkt.protocol,
            local_addr: pkt.dst_ip,
            local_port: pkt.dst_port,
            remote_addr: pkt.src_ip,
            remote_port: pkt.src_port,
        };

        if five_tuple_map.contains_key(&forward) {
            *bytes_rx.entry(forward).or_insert(0) += pkt.ip_len as u64;
            continue;
        }

        // Try reverse direction: this packet's src matches our local addr
        let reverse = FiveTuple {
            protocol: pkt.protocol,
            local_addr: pkt.src_ip,
            local_port: pkt.src_port,
            remote_addr: pkt.dst_ip,
            remote_port: pkt.dst_port,
        };

        if five_tuple_map.contains_key(&reverse) {
            *bytes_tx.entry(reverse).or_insert(0) += pkt.ip_len as u64;
        }
    }

    // 4. Build process list with connections
    let mut process_map: HashMap<u32, ProcessBuilder> = HashMap::new();

    for proc in raw_processes {
        let builder = process_map
            .entry(proc.pid)
            .or_insert_with(|| ProcessBuilder {
                pid: proc.pid,
                name: proc.name.clone(),
                uid: proc.uid,
                sockets: HashMap::new(),
            });

        for sock in &proc.sockets {
            let protocol = raw_protocol_to_model(sock);
            let state = raw_state_to_model(sock);
            let local_addr_str = format_addr_port(sock.local_addr, sock.local_port);

            let socket_key = (sock.fd, protocol);
            let socket_entry = builder
                .sockets
                .entry(socket_key)
                .or_insert_with(|| SocketBuilder {
                    fd: sock.fd,
                    protocol,
                    local_addr: local_addr_str,
                    state,
                    connections: Vec::new(),
                });

            // Add connection if there's a remote endpoint
            if let (Some(local_addr), Some(remote_addr)) = (sock.local_addr, sock.remote_addr)
                && sock.remote_port > 0
            {
                let tuple = FiveTuple {
                    protocol,
                    local_addr,
                    local_port: sock.local_port,
                    remote_addr,
                    remote_port: sock.remote_port,
                };

                let direction = if listen_set.is_listening(protocol, sock.local_port) {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };

                let remote_addr_str = format_addr_port(Some(remote_addr), sock.remote_port);

                // Look up previous totals for this connection
                let (prev_rx_total, prev_tx_total) =
                    find_prev_connection(prev_state, proc.pid, sock.fd, &remote_addr_str);

                let rx = bytes_rx.get(&tuple).copied().unwrap_or(0);
                let tx = bytes_tx.get(&tuple).copied().unwrap_or(0);

                let rx_total = prev_rx_total + rx;
                let tx_total = prev_tx_total + tx;

                // Rate = bytes captured this tick (tick interval ~1s in monitor mode)
                let rx_rate = RateMetrics {
                    bytes_per_sec: rx as f64,
                    bytes_per_min: rx as f64 * 60.0,
                };
                let tx_rate = RateMetrics {
                    bytes_per_sec: tx as f64,
                    bytes_per_min: tx as f64 * 60.0,
                };

                socket_entry.connections.push(Connection {
                    remote_addr: remote_addr_str,
                    direction,
                    interface: String::new(),
                    rx_rate,
                    tx_rate,
                    rx_bytes_total: rx_total,
                    tx_bytes_total: tx_total,
                    stability: None,
                });
            }
        }
    }

    let processes: Vec<Process> = process_map
        .into_values()
        .map(|pb| {
            let sockets = pb
                .sockets
                .into_values()
                .map(|sb| Socket {
                    fd: sb.fd,
                    protocol: sb.protocol,
                    local_addr: sb.local_addr,
                    state: sb.state,
                    connections: sb.connections,
                })
                .collect();
            Process {
                pid: pb.pid,
                name: pb.name,
                cmdline: String::new(),
                uid: pb.uid,
                username: uid_to_username(pb.uid),
                sockets,
            }
        })
        .collect();

    // 5. Build interfaces
    let interfaces = build_interfaces(raw_interfaces, raw_dns_resolvers, prev_state);

    // 6. Build DNS observatory
    let dns = build_dns_observatory(raw_dns_resolvers, dns_messages, &five_tuple_map, prev_state);

    SystemNetworkState {
        timestamp,
        interfaces,
        processes,
        dns,
        unknown_details: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Builder types for accumulating correlated data
// ---------------------------------------------------------------------------

struct ProcessBuilder {
    pid: u32,
    name: String,
    uid: u32,
    sockets: HashMap<(i32, Protocol), SocketBuilder>,
}

struct SocketBuilder {
    fd: i32,
    protocol: Protocol,
    local_addr: String,
    state: SocketState,
    connections: Vec<Connection>,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn raw_protocol_to_model(sock: &RawSocket) -> Protocol {
    match sock.sock_type {
        1 => Protocol::Tcp,  // SOCK_STREAM
        2 => Protocol::Udp,  // SOCK_DGRAM
        _ => Protocol::Icmp, // fallback
    }
}

fn raw_state_to_model(sock: &RawSocket) -> SocketState {
    if let Some(tcp_state) = sock.tcp_state {
        process::tcp_state_to_socket_state(tcp_state)
    } else {
        // UDP/other
        if sock.remote_port > 0 {
            SocketState::Connected
        } else {
            SocketState::Bound
        }
    }
}

fn format_addr_port(addr: Option<IpAddr>, port: u16) -> String {
    match addr {
        Some(IpAddr::V4(v4)) => format!("{v4}:{port}"),
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        None => format!("*:{port}"),
    }
}

fn uid_to_username(uid: u32) -> String {
    // Use getpwuid to resolve username
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return uid.to_string();
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    name.to_string_lossy().into_owned()
}

fn find_prev_connection(
    prev_state: &SystemNetworkState,
    pid: u32,
    fd: i32,
    remote_addr: &str,
) -> (u64, u64) {
    for proc in &prev_state.processes {
        if proc.pid != pid {
            continue;
        }
        for sock in &proc.sockets {
            if sock.fd != fd {
                continue;
            }
            for conn in &sock.connections {
                if conn.remote_addr == remote_addr {
                    return (conn.rx_bytes_total, conn.tx_bytes_total);
                }
            }
        }
    }

    (0, 0)
}

fn build_interfaces(
    raw_interfaces: &[RawInterface],
    raw_dns_resolvers: &[RawDnsResolver],
    prev_state: &SystemNetworkState,
) -> Vec<Interface> {
    let mut interfaces = Vec::new();

    for raw in raw_interfaces {
        // Find previous interface state for rate computation
        let prev = prev_state.interfaces.iter().find(|i| i.name == raw.name);

        // Compute delta from previous totals (rate = delta per tick, ~1s interval)
        let prev_rx = prev.map(|p| p.rx_bytes_total).unwrap_or(0);
        let prev_tx = prev.map(|p| p.tx_bytes_total).unwrap_or(0);

        let rx_delta = raw.ifi_ibytes.saturating_sub(prev_rx);
        let tx_delta = raw.ifi_obytes.saturating_sub(prev_tx);

        // Find DNS servers for this interface
        let mut dns_servers = Vec::new();
        let mut search_domains = Vec::new();
        for resolver in raw_dns_resolvers {
            if resolver.interface == "global" || resolver.interface == raw.name {
                dns_servers.extend(resolver.server_addresses.iter().cloned());
                search_domains.extend(resolver.search_domains.iter().cloned());
            }
        }

        let status = if raw.flags & libc::IFF_UP as u32 != 0 {
            InterfaceStatus::Up
        } else {
            InterfaceStatus::Down
        };

        interfaces.push(Interface {
            name: raw.name.clone(),
            ipv4_addresses: raw.ipv4_addresses.iter().map(|a| a.to_string()).collect(),
            ipv6_addresses: raw.ipv6_addresses.iter().map(|a| a.to_string()).collect(),
            dns_servers,
            search_domains,
            status,
            rx_bytes_rate: rx_delta as f64,
            tx_bytes_rate: tx_delta as f64,
            rx_bytes_total: raw.ifi_ibytes,
            tx_bytes_total: raw.ifi_obytes,
            rx_packets: raw.ifi_ipackets,
            tx_packets: raw.ifi_opackets,
            rx_errors: raw.ifi_ierrors,
            tx_errors: raw.ifi_oerrors,
        });
    }

    interfaces
}

fn build_dns_observatory(
    raw_dns_resolvers: &[RawDnsResolver],
    dns_messages: &[DnsMessage],
    _five_tuple_map: &HashMap<FiveTuple, ProcessSocket>,
    prev_state: &SystemNetworkState,
) -> DnsObservatory {
    // Build resolver list
    let mut resolvers: Vec<DnsResolver> = Vec::new();
    for raw in raw_dns_resolvers {
        for server in &raw.server_addresses {
            // Find previous stats for this resolver
            let prev = prev_state
                .dns
                .resolvers
                .iter()
                .find(|r| r.server == *server && r.interface == raw.interface);

            resolvers.push(DnsResolver {
                interface: raw.interface.clone(),
                server: server.clone(),
                avg_latency_ms: prev.map(|p| p.avg_latency_ms).unwrap_or(0.0),
                failure_rate_pct: prev.map(|p| p.failure_rate_pct).unwrap_or(0.0),
                query_count: prev.map(|p| p.query_count).unwrap_or(0),
            });
        }
    }

    // Collect new DNS queries from intercepted messages
    let mut queries: Vec<DnsQuery> = prev_state.dns.queries.clone();
    let max_queries = 1000; // Keep last N queries

    for msg in dns_messages {
        if msg.is_response {
            // This is a DNS response
            for question in &msg.questions {
                let response_str = if !msg.answers.is_empty() {
                    msg.answers
                        .iter()
                        .map(|a| a.rdata.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    format!("{:?}", msg.rcode)
                };

                queries.push(DnsQuery {
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0),
                    pid: None,
                    process: String::new(),
                    query_name: question.name.clone(),
                    query_type: format!("{:?}", question.qtype),
                    response: response_str,
                    latency_ms: 0.0,
                    resolver: String::new(),
                });
            }
        }
    }

    // Trim to max queries
    if queries.len() > max_queries {
        let trim = queries.len() - max_queries;
        queries.drain(..trim);
    }

    DnsObservatory { resolvers, queries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // TCP state constants differ between platforms.
    // macOS uses BSD TCPS_* values; Linux uses /proc/net/tcp hex values.
    #[cfg(target_os = "macos")]
    const TCP_STATE_LISTEN: i32 = 1;
    #[cfg(target_os = "macos")]
    const TCP_STATE_ESTABLISHED: i32 = 4;

    #[cfg(target_os = "linux")]
    const TCP_STATE_LISTEN: i32 = 0x0A;
    #[cfg(target_os = "linux")]
    const TCP_STATE_ESTABLISHED: i32 = 0x01;

    fn make_raw_process(pid: u32, name: &str, sockets: Vec<RawSocket>) -> RawProcess {
        RawProcess {
            pid,
            name: name.to_string(),
            uid: 501,
            sockets,
        }
    }

    fn make_raw_socket(
        fd: i32,
        local_port: u16,
        remote_port: u16,
        tcp_state: Option<i32>,
    ) -> RawSocket {
        RawSocket {
            fd,
            family: 2,    // AF_INET
            sock_type: 1, // SOCK_STREAM (TCP)
            protocol: 6,  // IPPROTO_TCP
            local_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            local_port,
            remote_addr: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            remote_port,
            tcp_state,
        }
    }

    fn make_packet(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        ip_len: u16,
    ) -> PacketSummary {
        PacketSummary {
            timestamp: 1000000,
            protocol: Protocol::Tcp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            ip_len,
            direction: Direction::Outbound,
        }
    }

    // UT-6.1: Empty inputs produce empty state
    #[test]
    fn ut_6_1_empty_inputs() {
        let state = correlate(
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &SystemNetworkState::empty(),
        );
        assert!(state.processes.is_empty());
        assert!(state.interfaces.is_empty());
        assert!(state.dns.resolvers.is_empty());
    }

    // UT-6.2: Single process with one TCP socket
    #[test]
    fn ut_6_2_single_process() {
        let sock = make_raw_socket(3, 12345, 80, Some(TCP_STATE_ESTABLISHED)); // ESTABLISHED
        let proc = make_raw_process(100, "curl", vec![sock]);
        let state = correlate(
            &[proc],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &SystemNetworkState::empty(),
        );
        assert_eq!(state.processes.len(), 1);
        assert_eq!(state.processes[0].pid, 100);
        assert_eq!(state.processes[0].name, "curl");
        assert!(!state.processes[0].sockets.is_empty());
    }

    // UT-6.3: Packet matched to connection (RX direction)
    #[test]
    fn ut_6_3_packet_rx_match() {
        let sock = make_raw_socket(3, 12345, 80, Some(TCP_STATE_ESTABLISHED));
        let proc = make_raw_process(100, "curl", vec![sock]);

        // Packet: remote → local (RX)
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            1500,
        );

        let state = correlate(
            &[proc],
            &[],
            &[],
            &[],
            &[],
            &[pkt],
            &[],
            &SystemNetworkState::empty(),
        );

        let conn = &state.processes[0].sockets[0].connections[0];
        assert_eq!(conn.rx_bytes_total, 1500);
        assert_eq!(conn.tx_bytes_total, 0);
    }

    // UT-6.4: Packet matched to connection (TX direction)
    #[test]
    fn ut_6_4_packet_tx_match() {
        let sock = make_raw_socket(3, 12345, 80, Some(TCP_STATE_ESTABLISHED));
        let proc = make_raw_process(100, "curl", vec![sock]);

        // Packet: local → remote (TX)
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
            500,
        );

        let state = correlate(
            &[proc],
            &[],
            &[],
            &[],
            &[],
            &[pkt],
            &[],
            &SystemNetworkState::empty(),
        );

        let conn = &state.processes[0].sockets[0].connections[0];
        assert_eq!(conn.tx_bytes_total, 500);
        assert_eq!(conn.rx_bytes_total, 0);
    }

    // UT-6.5: Direction detection — LISTEN socket → inbound
    #[test]
    fn ut_6_5_direction_inbound() {
        // Create a listening socket and a connected socket on the same port
        let listen_sock = RawSocket {
            fd: 3,
            family: 2,
            sock_type: 1,
            protocol: 6,
            local_addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            local_port: 8080,
            remote_addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            remote_port: 0,
            tcp_state: Some(TCP_STATE_LISTEN),
        };
        let conn_sock = RawSocket {
            fd: 4,
            family: 2,
            sock_type: 1,
            protocol: 6,
            local_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            local_port: 8080,
            remote_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            remote_port: 54321,
            tcp_state: Some(TCP_STATE_ESTABLISHED),
        };
        let proc = make_raw_process(200, "nginx", vec![listen_sock, conn_sock]);

        let state = correlate(
            &[proc],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &SystemNetworkState::empty(),
        );

        // Find the socket with the connection
        let socket_with_conn = state.processes[0]
            .sockets
            .iter()
            .find(|s| !s.connections.is_empty());
        assert!(socket_with_conn.is_some());
        assert_eq!(
            socket_with_conn.unwrap().connections[0].direction,
            Direction::Inbound
        );
    }

    // UT-6.6: Direction detection — no LISTEN → outbound
    #[test]
    fn ut_6_6_direction_outbound() {
        let sock = make_raw_socket(3, 54321, 443, Some(TCP_STATE_ESTABLISHED));
        let proc = make_raw_process(100, "chrome", vec![sock]);

        let state = correlate(
            &[proc],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &SystemNetworkState::empty(),
        );

        let conn = &state.processes[0].sockets[0].connections[0];
        assert_eq!(conn.direction, Direction::Outbound);
    }

    // UT-6.7: Interface data is preserved
    #[test]
    fn ut_6_7_interface_data() {
        let raw_iface = RawInterface {
            name: "en0".to_string(),
            ipv4_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))],
            ipv6_addresses: vec![],
            ifi_ibytes: 1000,
            ifi_obytes: 500,
            ifi_ipackets: 10,
            ifi_opackets: 5,
            ifi_ierrors: 0,
            ifi_oerrors: 0,
            flags: libc::IFF_UP as u32,
        };

        let state = correlate(
            &[],
            &[],
            &[],
            &[raw_iface],
            &[],
            &[],
            &[],
            &SystemNetworkState::empty(),
        );

        assert_eq!(state.interfaces.len(), 1);
        assert_eq!(state.interfaces[0].name, "en0");
        assert_eq!(state.interfaces[0].rx_bytes_total, 1000);
        assert_eq!(state.interfaces[0].tx_bytes_total, 500);
        assert_eq!(state.interfaces[0].status, InterfaceStatus::Up);
    }

    // UT-6.8: Multiple packets accumulate correctly
    #[test]
    fn ut_6_8_packet_accumulation() {
        let sock = make_raw_socket(3, 12345, 80, Some(TCP_STATE_ESTABLISHED));
        let proc = make_raw_process(100, "curl", vec![sock]);

        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let remote = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        let pkts = vec![
            make_packet(remote, 80, local, 12345, 1000), // RX
            make_packet(remote, 80, local, 12345, 500),  // RX
            make_packet(local, 12345, remote, 80, 200),  // TX
        ];

        let state = correlate(
            &[proc],
            &[],
            &[],
            &[],
            &[],
            &pkts,
            &[],
            &SystemNetworkState::empty(),
        );

        let conn = &state.processes[0].sockets[0].connections[0];
        assert_eq!(conn.rx_bytes_total, 1500);
        assert_eq!(conn.tx_bytes_total, 200);
    }

    // UT-6.9: DNS resolvers are included
    #[test]
    fn ut_6_9_dns_resolvers() {
        let resolver = RawDnsResolver {
            interface: "global".to_string(),
            server_addresses: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            search_domains: vec!["example.com".to_string()],
        };

        let state = correlate(
            &[],
            &[],
            &[],
            &[],
            &[resolver],
            &[],
            &[],
            &SystemNetworkState::empty(),
        );

        assert_eq!(state.dns.resolvers.len(), 2);
        assert_eq!(state.dns.resolvers[0].server, "8.8.8.8");
        assert_eq!(state.dns.resolvers[1].server, "8.8.4.4");
    }

    // UT-6.10: Cumulative totals preserved across state transitions
    #[test]
    fn ut_6_10_totals_preserved() {
        let sock = make_raw_socket(3, 12345, 80, Some(TCP_STATE_ESTABLISHED));

        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let remote = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        // First tick: 1000 bytes RX
        let proc1 = make_raw_process(100, "curl", vec![sock.clone()]);
        let pkt1 = make_packet(remote, 80, local, 12345, 1000);
        let state1 = correlate(
            std::slice::from_ref(&proc1),
            &[],
            &[],
            &[],
            &[],
            &[pkt1],
            &[],
            &SystemNetworkState::empty(),
        );

        // Second tick: 500 bytes RX, using state1 as prev
        let pkt2 = make_packet(remote, 80, local, 12345, 500);
        let proc2 = make_raw_process(100, "curl", vec![sock]);
        let state2 = correlate(&[proc2], &[], &[], &[], &[], &[pkt2], &[], &state1);

        let conn = &state2.processes[0].sockets[0].connections[0];
        // Total should be cumulative
        assert_eq!(conn.rx_bytes_total, 1500);
    }
}
