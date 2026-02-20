use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use rustc_hash::FxHashMap;

use crate::model::{Direction, Protocol};
use crate::packet::PacketSummary;

/// Normalized 5-tuple key for socket-to-process mapping.
///
/// Layout: `[ip_a: 16][port_a: 2][ip_b: 16][port_b: 2][proto: 1]` = 37 bytes.
///
/// Normalization: endpoints are sorted lexicographically by `(ip_bytes, port)`,
/// so `(A:1234, B:80)` and `(B:80, A:1234)` produce the same key.
///
/// IPv4 addresses are mapped to IPv4-mapped IPv6 (`::ffff:x.x.x.x`).
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct SocketKey([u8; 37]);

impl SocketKey {
    pub fn new(ip1: IpAddr, port1: u16, ip2: IpAddr, port2: u16, proto: u8) -> Self {
        let b1 = ip_to_bytes(ip1);
        let b2 = ip_to_bytes(ip2);

        let (ip_a, port_a, ip_b, port_b) = if (b1, port1) <= (b2, port2) {
            (b1, port1, b2, port2)
        } else {
            (b2, port2, b1, port1)
        };

        let mut buf = [0u8; 37];
        buf[0..16].copy_from_slice(&ip_a);
        buf[16..18].copy_from_slice(&port_a.to_be_bytes());
        buf[18..34].copy_from_slice(&ip_b);
        buf[34..36].copy_from_slice(&port_b.to_be_bytes());
        buf[36] = proto;
        Self(buf)
    }
}

/// Convert an IP address to a 16-byte representation.
/// IPv4 is mapped to IPv4-mapped IPv6 (`::ffff:x.x.x.x`).
fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[10] = 0xff;
            buf[11] = 0xff;
            buf[12..16].copy_from_slice(&v4.octets());
            buf
        }
    }
}

/// Basic process information stored in the process table.
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// Process identifier used as key in the traffic stats map.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum ProcessKey {
    Known { pid: u32, name: String },
    Unknown,
}

/// Cumulative traffic statistics for a single process.
#[derive(Default, Debug, Clone)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl TrafficStats {
    pub fn add(&mut self, pkt: &PacketSummary) {
        match pkt.direction {
            Direction::Inbound => {
                self.rx_bytes += pkt.ip_len as u64;
                self.rx_packets += 1;
            }
            Direction::Outbound => {
                self.tx_bytes += pkt.ip_len as u64;
                self.tx_packets += 1;
            }
        }
    }
}

/// Per-remote-address stats for Unknown traffic.
#[derive(Default, Debug, Clone)]
pub struct ConnectionStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Reverse DNS state: None = not queried, Some(None) = failed, Some(Some(name)) = resolved.
    pub rdns: Option<Option<String>>,
    pub annotation: Option<String>,
    pub protocol: Protocol,
}

/// Composite stats state: per-process traffic plus Unknown per-remote breakdown.
#[derive(Default)]
pub struct StatsState {
    pub by_process: HashMap<ProcessKey, TrafficStats>,
    pub unknown_by_remote: HashMap<SocketAddr, ConnectionStats>,
}

/// Process table: normalized 5-tuple -> process info.
/// Uses FxHashMap for better hash performance on short fixed-length keys.
pub type ProcessTable = FxHashMap<SocketKey, ProcessInfo>;

/// Look up which process owns a packet by constructing a SocketKey from the packet's 5-tuple.
pub fn lookup_process<'a>(table: &'a ProcessTable, pkt: &PacketSummary) -> Option<&'a ProcessInfo> {
    let proto = match pkt.protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmp => 1,
    };
    let key = SocketKey::new(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, proto);
    table.get(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ut_socket_key_normalization: same key regardless of endpoint order
    #[test]
    fn ut_socket_key_normalization() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let k1 = SocketKey::new(ip_a, 1234, ip_b, 80, 6);
        let k2 = SocketKey::new(ip_b, 80, ip_a, 1234, 6);
        assert_eq!(k1, k2);
    }

    // ut_socket_key_ipv4_mapped: IPv4 addr produces same key as its mapped IPv6 form
    #[test]
    fn ut_socket_key_ipv4_mapped() {
        let v4_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v6_a = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        let v4_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6_b = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));

        let k1 = SocketKey::new(v4_a, 80, v4_b, 1234, 6);
        let k2 = SocketKey::new(v6_a, 80, v6_b, 1234, 6);
        assert_eq!(k1, k2);
    }

    // ut_socket_key_different_proto: same IPs/ports but different protocol -> different key
    #[test]
    fn ut_socket_key_different_proto() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let tcp = SocketKey::new(ip_a, 80, ip_b, 1234, 6);
        let udp = SocketKey::new(ip_a, 80, ip_b, 1234, 17);
        assert_ne!(tcp, udp);
    }

    // ut_traffic_stats_add_inbound
    #[test]
    fn ut_traffic_stats_add_inbound() {
        let mut stats = TrafficStats::default();
        let pkt = PacketSummary {
            timestamp: 0,
            protocol: Protocol::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 443,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_port: 54321,
            ip_len: 1500,
            direction: Direction::Inbound,
        };
        stats.add(&pkt);
        assert_eq!(stats.rx_bytes, 1500);
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.tx_bytes, 0);
        assert_eq!(stats.tx_packets, 0);
    }

    // ut_traffic_stats_add_outbound
    #[test]
    fn ut_traffic_stats_add_outbound() {
        let mut stats = TrafficStats::default();
        let pkt = PacketSummary {
            timestamp: 0,
            protocol: Protocol::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 54321,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 443,
            ip_len: 200,
            direction: Direction::Outbound,
        };
        stats.add(&pkt);
        assert_eq!(stats.tx_bytes, 200);
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.rx_packets, 0);
    }

    // ut_process_key_known_eq
    #[test]
    fn ut_process_key_known_eq() {
        let k1 = ProcessKey::Known {
            pid: 123,
            name: "curl".to_string(),
        };
        let k2 = ProcessKey::Known {
            pid: 123,
            name: "curl".to_string(),
        };
        assert_eq!(k1, k2);
    }

    // ut_process_key_unknown
    #[test]
    fn ut_process_key_unknown() {
        let k1 = ProcessKey::Unknown;
        let k2 = ProcessKey::Unknown;
        assert_eq!(k1, k2);

        let known = ProcessKey::Known {
            pid: 1,
            name: "a".to_string(),
        };
        assert_ne!(k1, known);
    }

    // ut_lookup_process_found
    #[test]
    fn ut_lookup_process_found() {
        let mut table = ProcessTable::default();
        let key = SocketKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            54321,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            6,
        );
        table.insert(
            key,
            ProcessInfo {
                pid: 100,
                name: "curl".to_string(),
            },
        );

        let pkt = PacketSummary {
            timestamp: 0,
            protocol: Protocol::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 443,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_port: 54321,
            ip_len: 100,
            direction: Direction::Inbound,
        };

        let result = lookup_process(&table, &pkt);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pid, 100);
    }

    // ut_lookup_process_not_found
    #[test]
    fn ut_lookup_process_not_found() {
        let table = ProcessTable::default();
        let pkt = PacketSummary {
            timestamp: 0,
            protocol: Protocol::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            src_port: 80,
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            dst_port: 9999,
            ip_len: 100,
            direction: Direction::Outbound,
        };

        assert!(lookup_process(&table, &pkt).is_none());
    }
}
