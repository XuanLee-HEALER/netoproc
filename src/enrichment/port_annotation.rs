use crate::model::Protocol;

/// Return a human-readable label for a well-known port, or None if unknown.
///
/// Protocol-specific ports (e.g. HTTP/443 is TCP-only) only match the correct protocol.
pub fn annotate_port(port: u16, proto: Protocol) -> Option<&'static str> {
    match (port, proto) {
        // DNS — TCP and UDP
        (53, Protocol::Tcp | Protocol::Udp) => Some("DNS"),
        // mDNS — UDP only (mDNSResponder)
        (5353, Protocol::Udp) => Some("mDNS"),
        // NTP — UDP only
        (123, Protocol::Udp) => Some("NTP"),
        // SSDP — UDP only
        (1900, Protocol::Udp) => Some("SSDP"),
        // LLMNR — UDP only
        (5355, Protocol::Udp) => Some("LLMNR"),
        // Apple Push Notification Service — TCP only
        (2197, Protocol::Tcp) => Some("APNs"),
        (5223, Protocol::Tcp) => Some("APNs"),
        // HTTP/HTTPS — TCP only
        (80, Protocol::Tcp) => Some("HTTP"),
        (443, Protocol::Tcp) => Some("HTTPS"),
        (8080, Protocol::Tcp) => Some("HTTP-alt"),
        (8443, Protocol::Tcp) => Some("HTTPS-alt"),
        // SSH — TCP only
        (22, Protocol::Tcp) => Some("SSH"),
        // SMTP — TCP only
        (25, Protocol::Tcp) => Some("SMTP"),
        (587, Protocol::Tcp) => Some("SMTP"),
        (465, Protocol::Tcp) => Some("SMTPS"),
        // IMAP — TCP only
        (993, Protocol::Tcp) => Some("IMAPS"),
        (143, Protocol::Tcp) => Some("IMAP"),
        // POP3 — TCP only
        (995, Protocol::Tcp) => Some("POP3S"),
        (110, Protocol::Tcp) => Some("POP3"),
        // Database — TCP only
        (3306, Protocol::Tcp) => Some("MySQL"),
        (5432, Protocol::Tcp) => Some("PostgreSQL"),
        (6379, Protocol::Tcp) => Some("Redis"),
        (27017, Protocol::Tcp) => Some("MongoDB"),
        // DHCP — UDP only
        (67, Protocol::Udp) => Some("DHCP"),
        (68, Protocol::Udp) => Some("DHCP"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tcp_ports() {
        assert_eq!(annotate_port(80, Protocol::Tcp), Some("HTTP"));
        assert_eq!(annotate_port(443, Protocol::Tcp), Some("HTTPS"));
        assert_eq!(annotate_port(22, Protocol::Tcp), Some("SSH"));
        assert_eq!(annotate_port(3306, Protocol::Tcp), Some("MySQL"));
        assert_eq!(annotate_port(5432, Protocol::Tcp), Some("PostgreSQL"));
    }

    #[test]
    fn known_udp_ports() {
        assert_eq!(annotate_port(53, Protocol::Udp), Some("DNS"));
        assert_eq!(annotate_port(5353, Protocol::Udp), Some("mDNS"));
        assert_eq!(annotate_port(123, Protocol::Udp), Some("NTP"));
        assert_eq!(annotate_port(1900, Protocol::Udp), Some("SSDP"));
        assert_eq!(annotate_port(67, Protocol::Udp), Some("DHCP"));
    }

    #[test]
    fn dns_both_protocols() {
        assert_eq!(annotate_port(53, Protocol::Tcp), Some("DNS"));
        assert_eq!(annotate_port(53, Protocol::Udp), Some("DNS"));
    }

    #[test]
    fn tcp_only_ports_reject_udp() {
        assert_eq!(annotate_port(80, Protocol::Udp), None);
        assert_eq!(annotate_port(443, Protocol::Udp), None);
        assert_eq!(annotate_port(22, Protocol::Udp), None);
        assert_eq!(annotate_port(3306, Protocol::Udp), None);
    }

    #[test]
    fn udp_only_ports_reject_tcp() {
        assert_eq!(annotate_port(5353, Protocol::Tcp), None);
        assert_eq!(annotate_port(123, Protocol::Tcp), None);
        assert_eq!(annotate_port(1900, Protocol::Tcp), None);
    }

    #[test]
    fn unknown_port() {
        assert_eq!(annotate_port(12345, Protocol::Tcp), None);
        assert_eq!(annotate_port(0, Protocol::Udp), None);
        assert_eq!(annotate_port(65535, Protocol::Tcp), None);
    }

    #[test]
    fn icmp_always_none() {
        assert_eq!(annotate_port(80, Protocol::Icmp), None);
        assert_eq!(annotate_port(53, Protocol::Icmp), None);
    }
}
