pub mod dns_resolver;
pub mod ip_annotation;
pub mod port_annotation;

use std::net::SocketAddr;

use crate::model::Protocol;

/// Get a combined annotation for a remote address and protocol.
///
/// Combines IP annotation and port annotation into a single label.
/// Examples: "Apple Push/iCloud - HTTPS", "Google DNS - DNS", "local network"
pub fn get_annotation(remote: SocketAddr, proto: Protocol) -> Option<String> {
    let ip_label = ip_annotation::annotate_ip(remote.ip());
    let port_label = port_annotation::annotate_port(remote.port(), proto);

    match (ip_label, port_label) {
        (Some(ip), Some(port)) => Some(format!("{ip} - {port}")),
        (Some(ip), None) => Some(ip.to_string()),
        (None, Some(port)) => Some(port.to_string()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn both_ip_and_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let result = get_annotation(addr, Protocol::Udp);
        assert_eq!(result, Some("Google DNS - DNS".to_string()));
    }

    #[test]
    fn ip_only() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 9999);
        let result = get_annotation(addr, Protocol::Tcp);
        assert_eq!(result, Some("Apple Push/iCloud".to_string()));
    }

    #[test]
    fn port_only() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 443);
        let result = get_annotation(addr, Protocol::Tcp);
        assert_eq!(result, Some("HTTPS".to_string()));
    }

    #[test]
    fn neither() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 12345);
        let result = get_annotation(addr, Protocol::Tcp);
        assert_eq!(result, None);
    }

    #[test]
    fn apple_https() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83)), 443);
        let result = get_annotation(addr, Protocol::Tcp);
        assert_eq!(result, Some("Apple Push/iCloud - HTTPS".to_string()));
    }

    #[test]
    fn local_dns() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        let result = get_annotation(addr, Protocol::Udp);
        assert_eq!(result, Some("local network - DNS".to_string()));
    }
}
