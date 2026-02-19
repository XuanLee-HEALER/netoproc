// Raw packet header parser for BPF buffer data.
//
// Parses Ethernet + IPv4/IPv6 + TCP/UDP/ICMP headers from raw BPF capture buffers.
// See netoproc-design.md §4.4 and §7.2 for specification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::{Direction, Protocol};

use super::LinkType;

// ---------------------------------------------------------------------------
// FFI: BPF header as returned by /dev/bpfN reads
// ---------------------------------------------------------------------------

/// 32-bit timeval as used by the macOS kernel in `struct bpf_hdr`.
///
/// The kernel's `bpf_hdr` uses `struct timeval32` (`{int32_t, int32_t}` = 8 bytes),
/// NOT the 64-bit `struct timeval` (`{long, int32_t}` = 16 bytes on 64-bit).
/// This has been consistent across all macOS versions (XNU uses `timeval32` in
/// `bsd/net/bpf.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Timeval32 {
    tv_sec: i32,
    tv_usec: i32,
}

/// BPF packet header as defined in `<net/bpf.h>`.
///
/// Layout: `timeval32`(8) + `caplen`(4) + `datalen`(4) + `hdrlen`(2) = 18 bytes,
/// padded to 20 bytes (4-byte alignment due to `u32` members).
#[repr(C)]
pub struct BpfHdr {
    bh_tstamp: Timeval32,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: u16,
}

// Compile-time size assertion.
// bpf_hdr = timeval32(8) + caplen(4) + datalen(4) + hdrlen(2) + padding(2) = 20.
const _: () = assert!(std::mem::size_of::<BpfHdr>() == 20);

// ---------------------------------------------------------------------------
// BPF_WORDALIGN — round up to next 4-byte boundary
// ---------------------------------------------------------------------------

/// Rounds `x` up to the next 4-byte boundary, matching the kernel `BPF_WORDALIGN` macro.
#[inline]
pub const fn bpf_wordalign(x: usize) -> usize {
    (x + 3) & !3
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
// Buffer parsing
// ---------------------------------------------------------------------------

/// Streaming iterator over BPF buffer entries, yielding [`PacketSummary`] items.
///
/// Lazily parses each `bpf_hdr` entry from a raw BPF read buffer, avoiding
/// intermediate `Vec` allocation. Unparseable packets are silently skipped.
pub struct BpfPacketIter<'a> {
    buf: &'a [u8],
    pos: usize,
    link_type: LinkType,
}

impl<'a> BpfPacketIter<'a> {
    pub fn new(buf: &'a [u8], link_type: LinkType) -> Self {
        Self {
            buf,
            pos: 0,
            link_type,
        }
    }
}

impl<'a> Iterator for BpfPacketIter<'a> {
    type Item = PacketSummary;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos + std::mem::size_of::<BpfHdr>() > self.buf.len() {
                return None;
            }

            let hdr_ptr = self.buf[self.pos..].as_ptr() as *const BpfHdr;
            let (hdr_len, cap_len, tv_sec, tv_usec) = unsafe {
                let hdr = std::ptr::read_unaligned(hdr_ptr);
                (
                    hdr.bh_hdrlen as usize,
                    hdr.bh_caplen as usize,
                    hdr.bh_tstamp.tv_sec as i64,
                    hdr.bh_tstamp.tv_usec as i64,
                )
            };

            if self.pos + hdr_len + cap_len > self.buf.len() {
                return None;
            }

            let pkt_data = &self.buf[self.pos + hdr_len..self.pos + hdr_len + cap_len];
            self.pos += bpf_wordalign(hdr_len + cap_len);

            if let Some(mut summary) = parse_single_packet(pkt_data, self.link_type) {
                summary.timestamp = (tv_sec as u64)
                    .saturating_mul(1_000_000)
                    .saturating_add(tv_usec as u64);
                return Some(summary);
            }
            // Unparseable packet — skip and try next
        }
    }
}

/// Iterates over all `bpf_hdr` entries in a raw BPF read buffer and parses each
/// contained packet into a [`PacketSummary`].
///
/// Packets that cannot be parsed (unsupported EtherType, truncated, fragments, etc.)
/// are silently skipped.
///
/// This is a convenience wrapper around [`BpfPacketIter`].
pub fn parse_bpf_buffer(buf: &[u8], link_type: LinkType) -> Vec<PacketSummary> {
    BpfPacketIter::new(buf, link_type).collect()
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
fn parse_ethernet_frame(data: &[u8]) -> Option<PacketSummary> {
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
fn parse_raw_frame(data: &[u8]) -> Option<PacketSummary> {
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
fn parse_null_frame(data: &[u8]) -> Option<PacketSummary> {
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
pub(crate) fn skip_ipv6_extension_headers(mut next_hdr: u8, data: &[u8]) -> (u8, usize) {
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
        // 4 bytes of IP options (IHL goes from 5 to 6)
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
    // UT-2.6: IPv4 with options (IHL=15, max 60-byte IP header)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_6_ipv4_options_ihl15() {
        // 40 bytes of IP options (IHL goes from 5 to 15, max)
        let options = vec![0x01; 40]; // NOP padding
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 10, 10, 1), Ipv4Addr::new(10, 10, 10, 2))
            .protocol(PROTO_UDP)
            .ports(9999, 8888)
            .ip_options(options)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Udp);
        assert_eq!(s.src_port, 9999);
        assert_eq!(s.dst_port, 8888);
        // ip_len = 60 (IP hdr with max options) + 8 (UDP hdr) = 68
        assert_eq!(s.ip_len, 68);
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
    // UT-2.8: Truncated: Ethernet + partial IP (20 bytes total) -> None
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_8_truncated_partial_ip() {
        // 14 bytes of Ethernet + 6 bytes of IP = 20 bytes total.
        // Not enough for a full IPv4 header (needs 14 + 20 = 34).
        let mut data = vec![0u8; 20];
        // Set EtherType to IPv4
        data[12] = 0x08;
        data[13] = 0x00;
        // Set version+IHL byte for IPv4 (version=4, IHL=5)
        data[14] = 0x45;
        assert!(parse_single_packet(&data, LinkType::Ethernet).is_none());
    }

    // -----------------------------------------------------------------------
    // UT-2.9: Truncated: IP ok, partial TCP -> None
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_9_truncated_partial_tcp() {
        // Build a valid packet and then truncate the TCP header.
        let full_pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .protocol(PROTO_TCP)
            .ports(1111, 2222)
            .build();

        // ETH(14) + IPv4(20) + 2 bytes of TCP (not enough for ports)
        let truncated = &full_pkt[..14 + 20 + 2];
        assert!(parse_single_packet(truncated, LinkType::Ethernet).is_none());
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
    // UT-2.11: VLAN-tagged frame -> None (skip in initial version)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_11_vlan_tagged() {
        let pkt = PacketBuilder::new()
            .ethertype(0x8100) // 802.1Q VLAN tag
            .build();

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
        assert_eq!(s.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(s.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)));
    }

    // -----------------------------------------------------------------------
    // UT-2.13: IPv4 fragment (non-first) -> None
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_13_ipv4_fragment() {
        // Fragment offset of 185 (in 8-byte units) — non-first fragment.
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .protocol(PROTO_TCP)
            .ports(80, 12345)
            .fragment_offset(185) // non-zero fragment offset
            .build();

        assert!(parse_single_packet(&pkt, LinkType::Ethernet).is_none());
    }

    // -----------------------------------------------------------------------
    // UT-2.14: Minimum valid IPv4+TCP (54 bytes)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_2_14_minimum_valid_ipv4_tcp() {
        // Minimum: ETH(14) + IPv4(20) + TCP(20) = 54 bytes
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8))
            .protocol(PROTO_TCP)
            .ports(1, 2)
            .build();

        assert_eq!(pkt.len(), 54);
        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(s.dst_ip, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(s.src_port, 1);
        assert_eq!(s.dst_port, 2);
        assert_eq!(s.ip_len, 40);
    }

    // -----------------------------------------------------------------------
    // Additional: parse_bpf_buffer with synthetic BPF records
    // -----------------------------------------------------------------------
    #[test]
    fn test_parse_bpf_buffer_single_record() {
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .protocol(PROTO_TCP)
            .ports(8080, 80)
            .build();

        let hdr_len = std::mem::size_of::<BpfHdr>() as u16;
        let cap_len = pkt.len() as u32;

        // Build a BPF buffer with one record matching the kernel's bpf_hdr layout.
        // The kernel uses timeval32 {i32 tv_sec, i32 tv_usec} = 8 bytes.
        let mut buf = Vec::new();

        // bh_tstamp: tv_sec=1000, tv_usec=500 (timeval32: two i32 fields)
        let tv_sec: i32 = 1000;
        let tv_usec: i32 = 500;
        buf.extend_from_slice(&tv_sec.to_ne_bytes());
        buf.extend_from_slice(&tv_usec.to_ne_bytes());
        // bh_caplen
        buf.extend_from_slice(&cap_len.to_ne_bytes());
        // bh_datalen
        buf.extend_from_slice(&cap_len.to_ne_bytes());
        // bh_hdrlen
        buf.extend_from_slice(&hdr_len.to_ne_bytes());
        // Pad to hdr_len
        while buf.len() < hdr_len as usize {
            buf.push(0);
        }
        // Append packet data
        buf.extend_from_slice(&pkt);

        let results = parse_bpf_buffer(&buf, LinkType::Ethernet);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].timestamp, 1000 * 1_000_000 + 500);
        assert_eq!(results[0].protocol, Protocol::Tcp);
        assert_eq!(results[0].src_port, 8080);
        assert_eq!(results[0].dst_port, 80);
    }

    #[test]
    fn test_parse_bpf_buffer_empty() {
        let results = parse_bpf_buffer(&[], LinkType::Ethernet);
        assert!(results.is_empty());
    }

    /// Helper: wrap a raw packet into a BPF buffer record (BpfHdr + packet data),
    /// appending to `buf`. Uses timeval32 layout matching the macOS kernel.
    fn append_bpf_record(buf: &mut Vec<u8>, pkt: &[u8], tv_sec: i32, tv_usec: i32) {
        let hdr_len = std::mem::size_of::<BpfHdr>() as u16;
        let cap_len = pkt.len() as u32;
        let record_start = buf.len();

        buf.extend_from_slice(&tv_sec.to_ne_bytes());
        buf.extend_from_slice(&tv_usec.to_ne_bytes());
        buf.extend_from_slice(&cap_len.to_ne_bytes());
        buf.extend_from_slice(&cap_len.to_ne_bytes());
        buf.extend_from_slice(&hdr_len.to_ne_bytes());
        // Pad to hdr_len
        while buf.len() - record_start < hdr_len as usize {
            buf.push(0);
        }
        buf.extend_from_slice(pkt);
        // Pad to BPF word alignment (4 bytes)
        let total = hdr_len as usize + cap_len as usize;
        let aligned = bpf_wordalign(total);
        while buf.len() - record_start < aligned {
            buf.push(0);
        }
    }

    #[test]
    fn test_bpf_packet_iter_two_records() {
        let tcp_pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .protocol(PROTO_TCP)
            .ports(8080, 80)
            .build();
        let udp_pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 4))
            .protocol(PROTO_UDP)
            .ports(1234, 53)
            .build();

        let mut buf = Vec::new();
        append_bpf_record(&mut buf, &tcp_pkt, 1000, 0);
        append_bpf_record(&mut buf, &udp_pkt, 2000, 500);

        let mut iter = BpfPacketIter::new(&buf, LinkType::Ethernet);
        let first = iter.next().expect("should yield TCP packet");
        assert_eq!(first.protocol, Protocol::Tcp);
        assert_eq!(first.src_port, 8080);
        assert_eq!(first.timestamp, 1000 * 1_000_000);

        let second = iter.next().expect("should yield UDP packet");
        assert_eq!(second.protocol, Protocol::Udp);
        assert_eq!(second.src_port, 1234);
        assert_eq!(second.timestamp, 2000 * 1_000_000 + 500);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_bpf_wordalign() {
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(1), 4);
        assert_eq!(bpf_wordalign(2), 4);
        assert_eq!(bpf_wordalign(3), 4);
        assert_eq!(bpf_wordalign(4), 4);
        assert_eq!(bpf_wordalign(5), 8);
        assert_eq!(bpf_wordalign(28), 28);
        assert_eq!(bpf_wordalign(29), 32);
    }

    // -----------------------------------------------------------------------
    // Additional: ICMPv6 over IPv6
    // -----------------------------------------------------------------------
    #[test]
    fn test_ipv6_icmpv6() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_ICMPV6)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Icmp);
        assert_eq!(s.src_port, 0);
        assert_eq!(s.dst_port, 0);
        assert_eq!(s.src_ip, IpAddr::V6(src));
        assert_eq!(s.dst_ip, IpAddr::V6(dst));
    }

    // -----------------------------------------------------------------------
    // Additional: unsupported L4 protocol (e.g., GRE = 47)
    // -----------------------------------------------------------------------
    #[test]
    fn test_unsupported_l4_protocol() {
        let pkt = PacketBuilder::new()
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .protocol(47) // GRE
            .build();

        assert!(parse_single_packet(&pkt, LinkType::Ethernet).is_none());
    }

    // -----------------------------------------------------------------------
    // IPv6 extension header tests
    // -----------------------------------------------------------------------

    /// Build a minimal Hop-by-Hop or Routing or Dest Options extension header.
    /// Length is `(hdr_ext_len + 1) * 8` bytes, with hdr_ext_len = 0 → 8 bytes.
    fn build_ext_header_8bytes(hdr_type: u8) -> (u8, Vec<u8>) {
        // 8 bytes: next_hdr(1) + hdr_ext_len(0)(1) + padding(6)
        let mut raw = vec![0u8; 8];
        raw[1] = 0; // hdr_ext_len = 0 → total = (0+1)*8 = 8 bytes
        (hdr_type, raw)
    }

    /// Build a Fragment extension header (always 8 bytes).
    fn build_fragment_header() -> (u8, Vec<u8>) {
        // 8 bytes: next_hdr(1) + reserved(1) + frag_offset+flags(2) + identification(4)
        let raw = vec![0u8; 8];
        (EXT_FRAGMENT, raw)
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
    fn ut_ipv6_routing_then_udp() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let (hdr_type, raw) = build_ext_header_8bytes(EXT_ROUTING);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_UDP)
            .ports(5353, 5353)
            .ipv6_ext_header(hdr_type, raw)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some(), "should parse IPv6 with Routing + UDP");
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Udp);
        assert_eq!(s.src_port, 5353);
        assert_eq!(s.dst_port, 5353);
    }

    #[test]
    fn ut_ipv6_fragment_then_tcp() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let (hdr_type, raw) = build_fragment_header();

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_TCP)
            .ports(443, 8080)
            .ipv6_ext_header(hdr_type, raw)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(result.is_some(), "should parse IPv6 with Fragment + TCP");
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Tcp);
        assert_eq!(s.src_port, 443);
        assert_eq!(s.dst_port, 8080);
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

    #[test]
    fn ut_ipv6_dest_options_then_udp() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let (hdr_type, raw) = build_ext_header_8bytes(EXT_DEST_OPTIONS);

        let pkt = PacketBuilder::new()
            .ipv6(src, dst)
            .protocol(PROTO_UDP)
            .ports(1234, 5678)
            .ipv6_ext_header(hdr_type, raw)
            .build();

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        assert!(
            result.is_some(),
            "should parse IPv6 with Dest Options + UDP"
        );
        let s = result.unwrap();
        assert_eq!(s.protocol, Protocol::Udp);
        assert_eq!(s.src_port, 1234);
        assert_eq!(s.dst_port, 5678);
    }

    #[test]
    fn ut_ipv6_truncated_ext_header() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Build a packet manually with a Hop-by-Hop header that claims
        // hdr_ext_len=0 (8 bytes) but only provide 4 bytes of data after
        // the fixed IPv6 header.
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // dst mac
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
        pkt.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        // IPv6 fixed header
        pkt.push(0x60);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.extend_from_slice(&4u16.to_be_bytes()); // payload_len = 4
        pkt.push(EXT_HOP_BY_HOP); // next header = Hop-by-Hop
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        // Truncated Hop-by-Hop: only 4 bytes (needs 8)
        pkt.extend_from_slice(&[PROTO_TCP, 0, 0, 0]);

        let result = parse_single_packet(&pkt, LinkType::Ethernet);
        // Should fail because extension header is truncated and we can't reach L4
        assert!(
            result.is_none(),
            "truncated extension header should return None"
        );
    }
}
