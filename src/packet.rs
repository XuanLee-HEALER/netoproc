// Shared packet types and IP/L4 parsers.
//
// Platform-agnostic: used by both macOS BPF and Linux AF_PACKET capture paths.
// Parses Ethernet + IPv4/IPv6 + TCP/UDP/ICMP headers from raw capture buffers.
// See netoproc-design.md §4.4 and §7.2 for specification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::{Direction, Protocol};

// ---------------------------------------------------------------------------
// Data link type
// ---------------------------------------------------------------------------

/// Data link type of a capture device.
///
/// Determines the link-layer framing used by the interface, which affects
/// both the filter program and the packet parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet (DLT_EN10MB = 1): 14-byte header, EtherType at offset 12.
    Ethernet,
    /// Raw IP (DLT_RAW = 12): no link-layer header, IP starts at offset 0.
    /// Used by macOS `utun*` (tunnel) interfaces.
    Raw,
    /// Null/Loopback (DLT_NULL = 0): 4-byte AF header in host byte order.
    /// Used by macOS `lo0`.
    Null,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Ethernet
const ETH_HLEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

// IPv4
const IPV4_MIN_HLEN: usize = 20;
const IPV4_PROTO_OFFSET: usize = 9;
const IPV4_TOTAL_LEN_OFFSET: usize = 2;
const IPV4_FLAGS_FRAG_OFFSET: usize = 6;
const IPV4_SRC_OFFSET: usize = 12;
const IPV4_DST_OFFSET: usize = 16;

// IPv6
const IPV6_HLEN: usize = 40;
const IPV6_PAYLOAD_LEN_OFFSET: usize = 4;
const IPV6_NEXT_HDR_OFFSET: usize = 6;
const IPV6_SRC_OFFSET: usize = 8;
const IPV6_DST_OFFSET: usize = 24;

// L4 protocol numbers
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

// IPv6 extension header protocol numbers
const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTIONS: u8 = 60;

// TCP/UDP port header length (src_port + dst_port = 4 bytes)
const L4_PORT_HLEN: usize = 4;

// ---------------------------------------------------------------------------
// PacketSummary
// ---------------------------------------------------------------------------

/// Summarized information extracted from a single captured packet.
#[derive(Debug, Clone)]
pub struct PacketSummary {
    /// Timestamp in microseconds since epoch.
    pub timestamp: u64,
    /// Transport-layer protocol.
    pub protocol: Protocol,
    /// Source IP address (v4 or v6).
    pub src_ip: IpAddr,
    /// Source port (0 for ICMP).
    pub src_port: u16,
    /// Destination IP address (v4 or v6).
    pub dst_ip: IpAddr,
    /// Destination port (0 for ICMP).
    pub dst_port: u16,
    /// IP total length from the original (not captured) packet.
    pub ip_len: u16,
    /// Packet direction relative to the local host.
    pub direction: Direction,
}

// ---------------------------------------------------------------------------
// Single-packet parsing
// ---------------------------------------------------------------------------

/// Parses a single raw packet into a [`PacketSummary`].
///
/// The `link_type` determines how the link-layer header is interpreted:
/// - [`LinkType::Ethernet`]: 14-byte Ethernet header, EtherType at offset 12
/// - [`LinkType::Raw`]: no link-layer header, IP version from first nibble
/// - [`LinkType::Null`]: 4-byte AF header in host byte order
///
/// Returns `None` if the packet is:
/// - Too short (truncated at any layer)
/// - Not IPv4 or IPv6 (e.g. ARP, VLAN-tagged)
/// - A non-first IPv4 fragment
/// - Using an unsupported transport protocol
pub fn parse_single_packet(data: &[u8], link_type: LinkType) -> Option<PacketSummary> {
    match link_type {
        LinkType::Ethernet => parse_ethernet_frame(data),
        LinkType::Raw => parse_raw_frame(data),
        LinkType::Null => parse_null_frame(data),
    }
}

/// Parse an Ethernet-framed packet (DLT_EN10MB).
pub fn parse_ethernet_frame(data: &[u8]) -> Option<PacketSummary> {
    if data.len() < ETH_HLEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let l3_data = &data[ETH_HLEN..];

    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(l3_data),
        ETHERTYPE_IPV6 => parse_ipv6(l3_data),
        _ => None,
    }
}

/// Parse a raw IP packet (DLT_RAW) — no link-layer header.
pub fn parse_raw_frame(data: &[u8]) -> Option<PacketSummary> {
    if data.is_empty() {
        return None;
    }
    let version = data[0] >> 4;
    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => None,
    }
}

/// Parse a DLT_NULL framed packet — 4-byte AF header in host byte order.
pub fn parse_null_frame(data: &[u8]) -> Option<PacketSummary> {
    if data.len() < 4 {
        return None;
    }
    let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let l3_data = &data[4..];
    match af {
        af if af == libc::AF_INET as u32 => parse_ipv4(l3_data),
        af if af == libc::AF_INET6 as u32 => parse_ipv6(l3_data),
        _ => None,
    }
}

/// Parse an IPv4 packet from the start of the IP header.
fn parse_ipv4(data: &[u8]) -> Option<PacketSummary> {
    if data.len() < IPV4_MIN_HLEN {
        return None;
    }

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HLEN {
        return None;
    }
    if data.len() < ihl {
        return None;
    }

    // Total length from the IP header (original packet size).
    let ip_total_len =
        u16::from_be_bytes([data[IPV4_TOTAL_LEN_OFFSET], data[IPV4_TOTAL_LEN_OFFSET + 1]]);

    // Fragment check: flags + fragment offset at bytes 6-7.
    let flags_frag = u16::from_be_bytes([
        data[IPV4_FLAGS_FRAG_OFFSET],
        data[IPV4_FLAGS_FRAG_OFFSET + 1],
    ]);
    if (flags_frag & 0x1FFF) != 0 {
        // Non-first fragment — skip.
        return None;
    }

    let proto_byte = data[IPV4_PROTO_OFFSET];

    let src_ip = IpAddr::V4(Ipv4Addr::new(
        data[IPV4_SRC_OFFSET],
        data[IPV4_SRC_OFFSET + 1],
        data[IPV4_SRC_OFFSET + 2],
        data[IPV4_SRC_OFFSET + 3],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        data[IPV4_DST_OFFSET],
        data[IPV4_DST_OFFSET + 1],
        data[IPV4_DST_OFFSET + 2],
        data[IPV4_DST_OFFSET + 3],
    ));

    let l4_data = &data[ihl..];

    parse_l4(proto_byte, l4_data, src_ip, dst_ip, ip_total_len)
}

/// Skip IPv6 extension headers, returning `(final_next_hdr, offset_into_data)`.
///
/// `next_hdr` is the Next Header value from the fixed IPv6 header (or previous
/// extension header). `data` starts at the first byte after the fixed 40-byte
/// IPv6 header.
///
/// Recognized extension headers: Hop-by-Hop (0), Routing (43), Fragment (44),
/// Destination Options (60). The function loops until it reaches a non-extension
/// protocol (e.g. TCP, UDP, ICMPv6) or runs out of data.
pub fn skip_ipv6_extension_headers(mut next_hdr: u8, data: &[u8]) -> (u8, usize) {
    let mut offset = 0;
    loop {
        match next_hdr {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTIONS => {
                // Need at least 2 bytes: next_hdr + hdr_ext_len
                if offset + 2 > data.len() {
                    return (next_hdr, offset);
                }
                let hdr_ext_len = data[offset + 1] as usize;
                let total_len = (hdr_ext_len + 1) * 8;
                if offset + total_len > data.len() {
                    return (next_hdr, offset);
                }
                next_hdr = data[offset];
                offset += total_len;
            }
            EXT_FRAGMENT => {
                // Fragment header is always 8 bytes
                if offset + 8 > data.len() {
                    return (next_hdr, offset);
                }
                next_hdr = data[offset];
                offset += 8;
            }
            _ => return (next_hdr, offset),
        }
    }
}

/// Parse an IPv6 packet from the start of the IP header.
fn parse_ipv6(data: &[u8]) -> Option<PacketSummary> {
    if data.len() < IPV6_HLEN {
        return None;
    }

    let payload_len = u16::from_be_bytes([
        data[IPV6_PAYLOAD_LEN_OFFSET],
        data[IPV6_PAYLOAD_LEN_OFFSET + 1],
    ]);
    // IP "total length" equivalent for IPv6: header + payload.
    let ip_total_len = (IPV6_HLEN as u16).saturating_add(payload_len);

    let next_hdr = data[IPV6_NEXT_HDR_OFFSET];

    let src_bytes: [u8; 16] = data[IPV6_SRC_OFFSET..IPV6_SRC_OFFSET + 16]
        .try_into()
        .ok()?;
    let dst_bytes: [u8; 16] = data[IPV6_DST_OFFSET..IPV6_DST_OFFSET + 16]
        .try_into()
        .ok()?;

    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let after_fixed = &data[IPV6_HLEN..];
    let (final_proto, ext_offset) = skip_ipv6_extension_headers(next_hdr, after_fixed);
    let l4_data = &after_fixed[ext_offset..];

    parse_l4(final_proto, l4_data, src_ip, dst_ip, ip_total_len)
}

/// Parse the transport layer (TCP/UDP/ICMP) and construct a [`PacketSummary`].
fn parse_l4(
    proto_byte: u8,
    l4_data: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_len: u16,
) -> Option<PacketSummary> {
    match proto_byte {
        PROTO_TCP | PROTO_UDP => {
            if l4_data.len() < L4_PORT_HLEN {
                return None;
            }
            let src_port = u16::from_be_bytes([l4_data[0], l4_data[1]]);
            let dst_port = u16::from_be_bytes([l4_data[2], l4_data[3]]);
            let protocol = if proto_byte == PROTO_TCP {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            Some(PacketSummary {
                timestamp: 0,
                protocol,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                ip_len,
                direction: Direction::Outbound,
            })
        }
        PROTO_ICMP | PROTO_ICMPV6 => Some(PacketSummary {
            timestamp: 0,
            protocol: Protocol::Icmp,
            src_ip,
            src_port: 0,
            dst_ip,
            dst_port: 0,
            ip_len,
            direction: Direction::Outbound,
        }),
        _ => None,
    }
}

// ===========================================================================
// Unit tests — TESTING.md UT-2
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PacketBuilder — helper for constructing raw test packets
    // -----------------------------------------------------------------------

    /// A builder for constructing raw Ethernet/IP/L4 packets for testing.
    struct PacketBuilder {
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ethertype: u16,
        // IPv4 fields
        src_ipv4: Ipv4Addr,
        dst_ipv4: Ipv4Addr,
        // IPv6 fields
        src_ipv6: Ipv6Addr,
        dst_ipv6: Ipv6Addr,
        // IP version (4 or 6)
        ip_version: u8,
        // L4 protocol number
        l4_proto: u8,
        src_port: u16,
        dst_port: u16,
        // IPv4 options (extra bytes after the standard 20-byte header)
        ip_options: Vec<u8>,
        // IPv4 fragment offset (13-bit value, combined with flags)
        fragment_offset: u16,
        // Extra L4 payload bytes
        l4_payload: Vec<u8>,
        // IPv6 extension headers: Vec of (next_hdr_type, raw_bytes_including_next_hdr_and_len)
        ipv6_ext_headers: Vec<(u8, Vec<u8>)>,
    }

    impl PacketBuilder {
        fn new() -> Self {
            Self {
                src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                dst_mac: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
                ethertype: ETHERTYPE_IPV4,
                src_ipv4: Ipv4Addr::new(10, 0, 0, 1),
                dst_ipv4: Ipv4Addr::new(10, 0, 0, 2),
                src_ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                dst_ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                ip_version: 4,
                l4_proto: PROTO_TCP,
                src_port: 12345,
                dst_port: 80,
                ip_options: Vec::new(),
                fragment_offset: 0,
                l4_payload: Vec::new(),
                ipv6_ext_headers: Vec::new(),
            }
        }

        fn ethertype(mut self, et: u16) -> Self {
            self.ethertype = et;
            self
        }

        fn ipv4(mut self, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
            self.ip_version = 4;
            self.ethertype = ETHERTYPE_IPV4;
            self.src_ipv4 = src;
            self.dst_ipv4 = dst;
            self
        }

        fn ipv6(mut self, src: Ipv6Addr, dst: Ipv6Addr) -> Self {
            self.ip_version = 6;
            self.ethertype = ETHERTYPE_IPV6;
            self.src_ipv6 = src;
            self.dst_ipv6 = dst;
            self
        }

        fn protocol(mut self, proto: u8) -> Self {
            self.l4_proto = proto;
            self
        }

        fn ports(mut self, src: u16, dst: u16) -> Self {
            self.src_port = src;
            self.dst_port = dst;
            self
        }

        fn ip_options(mut self, opts: Vec<u8>) -> Self {
            self.ip_options = opts;
            self
        }

        fn fragment_offset(mut self, offset: u16) -> Self {
            self.fragment_offset = offset;
            self
        }

        /// Add an IPv6 extension header. `hdr_type` is the extension header
        /// protocol number, and `raw` is the complete raw bytes of the header
        /// (including the next_hdr and length fields — the next_hdr byte will
        /// be overwritten to chain to the next header or the L4 protocol).
        fn ipv6_ext_header(mut self, hdr_type: u8, raw: Vec<u8>) -> Self {
            self.ipv6_ext_headers.push((hdr_type, raw));
            self
        }

        /// Build the raw packet bytes.
        fn build(&self) -> Vec<u8> {
            let mut pkt = Vec::new();

            // --- Ethernet header (14 bytes) ---
            pkt.extend_from_slice(&self.dst_mac);
            pkt.extend_from_slice(&self.src_mac);
            pkt.extend_from_slice(&self.ethertype.to_be_bytes());

            match self.ip_version {
                4 => self.build_ipv4(&mut pkt),
                6 => self.build_ipv6(&mut pkt),
                _ => {}
            }

            pkt
        }

        fn build_ipv4(&self, pkt: &mut Vec<u8>) {
            let ihl = (IPV4_MIN_HLEN + self.ip_options.len()) / 4;
            let ip_hdr_len = ihl * 4;

            // Build L4 header first so we can compute total length.
            let l4_hdr = self.build_l4();
            let total_len = (ip_hdr_len + l4_hdr.len()) as u16;

            // Byte 0: version (4) + IHL
            pkt.push(0x40 | (ihl as u8));
            // Byte 1: DSCP/ECN
            pkt.push(0x00);
            // Bytes 2-3: total length
            pkt.extend_from_slice(&total_len.to_be_bytes());
            // Bytes 4-5: identification
            pkt.extend_from_slice(&0u16.to_be_bytes());
            // Bytes 6-7: flags + fragment offset
            pkt.extend_from_slice(&self.fragment_offset.to_be_bytes());
            // Byte 8: TTL
            pkt.push(64);
            // Byte 9: protocol
            pkt.push(self.l4_proto);
            // Bytes 10-11: header checksum (0 for testing)
            pkt.extend_from_slice(&0u16.to_be_bytes());
            // Bytes 12-15: src IP
            pkt.extend_from_slice(&self.src_ipv4.octets());
            // Bytes 16-19: dst IP
            pkt.extend_from_slice(&self.dst_ipv4.octets());
            // IP options
            pkt.extend_from_slice(&self.ip_options);

            // L4 header + payload
            pkt.extend_from_slice(&l4_hdr);
        }

        fn build_ipv6(&self, pkt: &mut Vec<u8>) {
            let l4_hdr = self.build_l4();

            // Build extension header chain with correct next_hdr chaining.
            let mut ext_bytes = Vec::new();
            let mut ext_headers = self.ipv6_ext_headers.clone();
            for i in 0..ext_headers.len() {
                // Set the next_hdr byte of each extension header to point to the next one,
                // or to the L4 protocol for the last extension header.
                let next = if i + 1 < ext_headers.len() {
                    ext_headers[i + 1].0
                } else {
                    self.l4_proto
                };
                ext_headers[i].1[0] = next;
                ext_bytes.extend_from_slice(&ext_headers[i].1);
            }

            let payload_len = (ext_bytes.len() + l4_hdr.len()) as u16;

            // The first next_hdr in the fixed header points to the first ext header
            // or to the L4 protocol if no ext headers.
            let first_next_hdr = if let Some((hdr_type, _)) = ext_headers.first() {
                *hdr_type
            } else {
                self.l4_proto
            };

            // Bytes 0-3: version(6) + traffic class + flow label
            pkt.push(0x60);
            pkt.push(0x00);
            pkt.push(0x00);
            pkt.push(0x00);
            // Bytes 4-5: payload length
            pkt.extend_from_slice(&payload_len.to_be_bytes());
            // Byte 6: next header
            pkt.push(first_next_hdr);
            // Byte 7: hop limit
            pkt.push(64);
            // Bytes 8-23: src IPv6
            pkt.extend_from_slice(&self.src_ipv6.octets());
            // Bytes 24-39: dst IPv6
            pkt.extend_from_slice(&self.dst_ipv6.octets());

            // Extension headers
            pkt.extend_from_slice(&ext_bytes);

            // L4 header + payload
            pkt.extend_from_slice(&l4_hdr);
        }

        fn build_l4(&self) -> Vec<u8> {
            let mut l4 = Vec::new();
            match self.l4_proto {
                PROTO_TCP => {
                    // Minimal TCP header: 20 bytes
                    l4.extend_from_slice(&self.src_port.to_be_bytes());
                    l4.extend_from_slice(&self.dst_port.to_be_bytes());
                    // seq number (4 bytes)
                    l4.extend_from_slice(&0u32.to_be_bytes());
                    // ack number (4 bytes)
                    l4.extend_from_slice(&0u32.to_be_bytes());
                    // data offset (5 << 4) + reserved + flags
                    l4.push(0x50);
                    l4.push(0x02); // SYN
                    // window
                    l4.extend_from_slice(&65535u16.to_be_bytes());
                    // checksum
                    l4.extend_from_slice(&0u16.to_be_bytes());
                    // urgent pointer
                    l4.extend_from_slice(&0u16.to_be_bytes());
                }
                PROTO_UDP => {
                    // UDP header: 8 bytes
                    l4.extend_from_slice(&self.src_port.to_be_bytes());
                    l4.extend_from_slice(&self.dst_port.to_be_bytes());
                    // length
                    let udp_len = (8 + self.l4_payload.len()) as u16;
                    l4.extend_from_slice(&udp_len.to_be_bytes());
                    // checksum
                    l4.extend_from_slice(&0u16.to_be_bytes());
                }
                PROTO_ICMP | PROTO_ICMPV6 => {
                    // ICMP: type(1) + code(1) + checksum(2) + rest(4) = 8 bytes
                    l4.push(8); // type: echo request
                    l4.push(0); // code
                    l4.extend_from_slice(&0u16.to_be_bytes()); // checksum
                    l4.extend_from_slice(&0u32.to_be_bytes()); // rest of header
                }
                _ => {}
            }
            l4.extend_from_slice(&self.l4_payload);
            l4
        }
    }

    // -----------------------------------------------------------------------
    // UT-2.1: Ethernet + IPv4 + TCP standard packet
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_1_ipv4_tcp() {
        let pkt = PacketBuilder::new()
            .ipv4(
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(93, 184, 216, 34),
            )
            .protocol(PROTO_TCP)
            .ports(54321, 443)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(s.dst_ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(s.src_port, 54321);
        assert_eq!(s.dst_port, 443);
        // ip_len = 20 (IP hdr) + 20 (TCP hdr) = 40
        assert_eq!(s.ip_len, 40);
    }

    // -----------------------------------------------------------------------
    // UT-2.2: Ethernet + IPv4 + UDP
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_2_ipv4_udp() {
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(8, 8, 8, 8))
            .protocol(PROTO_UDP)
            .ports(12345, 53)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Udp);
        assert_eq!(s.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(s.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(s.src_port, 12345);
        assert_eq!(s.dst_port, 53);
        // ip_len = 20 (IP hdr) + 8 (UDP hdr) = 28
        assert_eq!(s.ip_len, 28);
    }

    // -----------------------------------------------------------------------
    // UT-2.3: Ethernet + IPv6 + TCP
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_3_ipv6_tcp() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_TCP)
            .ports(10000, 8080)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_ip, IpAddr::V6(src));
        assert_eq!(s.dst_ip, IpAddr::V6(dst));
        assert_eq!(s.src_port, 10000);
        assert_eq!(s.dst_port, 8080);
        // ip_len = 40 (IPv6 hdr) + 20 (TCP hdr) = 60
        assert_eq!(s.ip_len, 60);
    }

    // -----------------------------------------------------------------------
    // UT-2.4: Ethernet + IPv6 + UDP
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_4_ipv6_udp() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_UDP)
            .ports(5353, 5353)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Udp);
        assert_eq!(s.src_ip, IpAddr::V6(src));
        assert_eq!(s.dst_ip, IpAddr::V6(dst));
        assert_eq!(s.src_port, 5353);
        assert_eq!(s.dst_port, 5353);
        // ip_len = 40 (IPv6 hdr) + 8 (UDP hdr) = 48
        assert_eq!(s.ip_len, 48);
    }

    // -----------------------------------------------------------------------
    // UT-2.5: IPv4 with options (IHL=6, 24-byte IP header)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_5_ipv4_options_ihl6() {
        let options = vec![0x01, 0x01, 0x01, 0x01]; // NOP padding
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(172, 16, 0, 1), Ipv4Addr::new(172, 16, 0, 2))
            .protocol(PROTO_TCP)
            .ports(1234, 5678)
            .ip_options(options)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_port, 1234);
        assert_eq!(s.dst_port, 5678);
        // ip_len = 24 (IP hdr with options) + 20 (TCP hdr) = 44
        assert_eq!(s.ip_len, 44);
    }

    // -----------------------------------------------------------------------
    // UT-2.7: Truncated: less than Ethernet header (10 bytes) -> None
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_7_truncated_less_than_ethernet() {
        let data = vec![0u8; 10];
        assert!(parse_single_packet(&data, LinkType::Ethernet).is_none());
    }

    // -----------------------------------------------------------------------
    // UT-2.10: Non-IP EtherType (ARP, 0x0806) -> None
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_10_arp_ethertype() {
        let pkt = PacketBuilder::new().ethertype(0x0806).build();
        assert!(parse_single_packet(&pkt, LinkType::Ethernet).is_none());
    }

    // -----------------------------------------------------------------------
    // UT-2.12: ICMP packet -> proto: Icmp, ports = 0
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_12_icmp() {
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(8, 8, 4, 4))
            .protocol(PROTO_ICMP)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Icmp);
        assert_eq!(s.src_port, 0);
        assert_eq!(s.dst_port, 0);
    }

    // -----------------------------------------------------------------------
    // UT-2.13: IPv4 fragment (non-first) -> None
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_13_ipv4_fragment() {
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .protocol(PROTO_TCP)
            .ports(80, 12345)
            .fragment_offset(185)
            .build();

        assert!(parse_single_packet(&pkt, LinkType::Ethernet).is_none());
    }

    // -----------------------------------------------------------------------
    // IPv6 extension header tests
    // -----------------------------------------------------------------------

    fn build_ext_header_8bytes(hdr_type: u8) -> (u8, Vec<u8>) {
        let mut raw = vec![0u8; 8];
        raw[1] = 0; // hdr_ext_len = 0 → total = (0+1)*8 = 8 bytes
        (hdr_type, raw)
    }

    #[test]
    fn ut_ipv6_hop_by_hop_then_tcp() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let (hdr_type, raw) = build_ext_header_8bytes(EXT_HOP_BY_HOP);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_TCP)
            .ports(10000, 80)
            .ipv6_ext_header(hdr_type, raw)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some(), "should parse IPv6 with Hop-by-Hop + TCP");
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_port, 10000);
        assert_eq!(s.dst_port, 80);
    }

    #[test]
    fn ut_ipv6_chained_ext_headers() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let (hop_type, hop_raw) = build_ext_header_8bytes(EXT_HOP_BY_HOP);
        let (rt_type, rt_raw) = build_ext_header_8bytes(EXT_ROUTING);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_TCP)
            .ports(22, 9999)
            .ipv6_ext_header(hop_type, hop_raw)
            .ipv6_ext_header(rt_type, rt_raw)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(
            result.is_some(),
            "should parse IPv6 with Hop-by-Hop + Routing + TCP"
        );
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_port, 22);
        assert_eq!(s.dst_port, 9999);
    }
}
