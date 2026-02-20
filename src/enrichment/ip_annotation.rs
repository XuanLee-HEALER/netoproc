use std::net::IpAddr;

/// Pre-computed IPv4 CIDR annotation entry: (prefix_value, prefix_len, label).
///
/// `prefix_value` is the network address as a u32 with host bits zeroed.
/// Entries are sorted by prefix_len descending (longest match first).
static IPV4_ANNOTATIONS: &[(u32, u8, &str)] = &[
    // /32 — specific hosts
    (0xEFFF_FFFA, 32, "SSDP multicast"), // 239.255.255.250
    // /24 — narrow ranges
    (0x0808_0800, 24, "Google DNS"),     // 8.8.8.0/24
    (0x0808_0400, 24, "Google DNS"),     // 8.8.4.0/24
    (0x0101_0100, 24, "Cloudflare DNS"), // 1.1.1.0/24
    (0x0100_0000, 24, "Cloudflare DNS"), // 1.0.0.0/24
    // /16 — medium ranges
    (0x1139_0000, 16, "Apple Push/iCloud"), // 17.57.0.0/16
    (0x11F8_0000, 16, "Apple Push/iCloud"), // 17.248.0.0/16
    (0xACD9_0000, 16, "Google"),            // 172.217.0.0/16
    (0xD83A_0000, 16, "Google"),            // 216.58.0.0/16
    (0xC0A8_0000, 16, "local network"),     // 192.168.0.0/16
    // /15 — slightly wider
    (0x8EFA_0000, 15, "Google"), // 142.250.0.0/15
    // /12 — medium-wide
    (0x6810_0000, 12, "Cloudflare CDN"), // 104.16.0.0/12
    (0xAC10_0000, 12, "local network"),  // 172.16.0.0/12
    // /11
    (0x0D40_0000, 11, "Azure"), // 13.64.0.0/11
    // /10
    (0x2840_0000, 10, "Azure"), // 40.64.0.0/10
    // /8 — wide ranges
    (0x1100_0000, 8, "Apple"),         // 17.0.0.0/8
    (0x1700_0000, 8, "Akamai"),        // 23.0.0.0/8
    (0x3400_0000, 8, "AWS"),           // 52.0.0.0/8
    (0x3600_0000, 8, "AWS"),           // 54.0.0.0/8
    (0x0A00_0000, 8, "local network"), // 10.0.0.0/8
    // /4 — multicast
    (0xE000_0000, 4, "multicast"), // 224.0.0.0/4
];

/// IPv6 segment-based annotation entry: (first_segment, label).
/// Matches on the first 16 bits of the IPv6 address.
static IPV6_FIRST_SEGMENT: &[(u16, &str)] = &[(0xfe80, "link-local"), (0xff02, "multicast")];

/// IPv6 two-segment annotation entry: (seg0, seg1, label).
/// Matches on the first 32 bits of the IPv6 address.
static IPV6_TWO_SEGMENTS: &[(u16, u16, &str)] = &[
    (0x2001, 0x4860, "Google"),
    (0x2606, 0x4700, "Cloudflare"),
    (0x2400, 0xcb00, "Cloudflare"),
    (0x2620, 0x0149, "Akamai"),
];

/// Return a human-readable label for an IP address based on known CIDR ranges.
pub fn annotate_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => annotate_ipv4(u32::from(v4)),
        IpAddr::V6(v6) => annotate_ipv6(v6.segments()),
    }
}

fn annotate_ipv4(addr: u32) -> Option<&'static str> {
    for &(prefix, len, label) in IPV4_ANNOTATIONS {
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        if addr & mask == prefix {
            return Some(label);
        }
    }
    None
}

fn annotate_ipv6(segments: [u16; 8]) -> Option<&'static str> {
    // Try two-segment match first (more specific).
    for &(s0, s1, label) in IPV6_TWO_SEGMENTS {
        if segments[0] == s0 && segments[1] == s1 {
            return Some(label);
        }
    }
    // Then try first-segment match.
    for &(s0, label) in IPV6_FIRST_SEGMENT {
        if segments[0] == s0 {
            return Some(label);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn google_dns() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(annotate_ip(ip), Some("Google DNS"));
        let ip2 = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        assert_eq!(annotate_ip(ip2), Some("Google DNS"));
    }

    #[test]
    fn cloudflare_dns() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(annotate_ip(ip), Some("Cloudflare DNS"));
        let ip2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        assert_eq!(annotate_ip(ip2), Some("Cloudflare DNS"));
    }

    #[test]
    fn apple_specific_ranges() {
        // 17.57.x.x -> Apple Push/iCloud (more specific)
        let ip = IpAddr::V4(Ipv4Addr::new(17, 57, 144, 83));
        assert_eq!(annotate_ip(ip), Some("Apple Push/iCloud"));
        // 17.248.x.x -> Apple Push/iCloud
        let ip2 = IpAddr::V4(Ipv4Addr::new(17, 248, 1, 1));
        assert_eq!(annotate_ip(ip2), Some("Apple Push/iCloud"));
        // 17.x.x.x (not 57/248) -> Apple (broader /8)
        let ip3 = IpAddr::V4(Ipv4Addr::new(17, 1, 1, 1));
        assert_eq!(annotate_ip(ip3), Some("Apple"));
    }

    #[test]
    fn longest_prefix_wins() {
        // 17.57.1.1 should match /16 "Apple Push/iCloud" before /8 "Apple"
        let ip = IpAddr::V4(Ipv4Addr::new(17, 57, 1, 1));
        assert_eq!(annotate_ip(ip), Some("Apple Push/iCloud"));
    }

    #[test]
    fn local_networks() {
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some("local network")
        );
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some("local network")
        );
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            Some("local network")
        );
    }

    #[test]
    fn ssdp_multicast() {
        let ip = IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250));
        assert_eq!(annotate_ip(ip), Some("SSDP multicast"));
    }

    #[test]
    fn generic_multicast() {
        // Not SSDP-specific multicast
        let ip = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
        assert_eq!(annotate_ip(ip), Some("multicast"));
    }

    #[test]
    fn cloud_providers() {
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(52, 1, 2, 3))),
            Some("AWS")
        );
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(54, 200, 1, 1))),
            Some("AWS")
        );
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(13, 65, 1, 1))),
            Some("Azure")
        );
        assert_eq!(
            annotate_ip(IpAddr::V4(Ipv4Addr::new(40, 100, 1, 1))),
            Some("Azure")
        );
    }

    #[test]
    fn unknown_ipv4() {
        // Random public IP
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(annotate_ip(ip), None);
    }

    #[test]
    fn ipv6_google() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        assert_eq!(annotate_ip(ip), Some("Google"));
    }

    #[test]
    fn ipv6_cloudflare() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        assert_eq!(annotate_ip(ip), Some("Cloudflare"));
        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 1));
        assert_eq!(annotate_ip(ip2), Some("Cloudflare"));
    }

    #[test]
    fn ipv6_link_local() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(annotate_ip(ip), Some("link-local"));
    }

    #[test]
    fn ipv6_multicast() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(annotate_ip(ip), Some("multicast"));
    }

    #[test]
    fn ipv6_unknown() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0, 0, 0, 0, 0, 1));
        assert_eq!(annotate_ip(ip), None);
    }
}
