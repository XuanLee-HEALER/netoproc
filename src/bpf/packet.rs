// macOS BPF buffer parsing — iterates over bpf_hdr entries.
//
// The cross-platform packet parsers (PacketSummary, parse_single_packet, etc.)
// live in crate::packet. This file contains only macOS-specific BPF buffer
// structures and iteration logic.

pub use crate::packet::{
    LinkType, PacketSummary, parse_ethernet_frame, parse_single_packet, skip_ipv6_extension_headers,
};

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

// ===========================================================================
// Unit tests — BPF buffer iteration (macOS-specific)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use std::net::Ipv4Addr;

    // Re-use the PacketBuilder from crate::packet tests is not possible,
    // so we use raw packet construction here.

    fn build_simple_tcp_pkt() -> Vec<u8> {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let src_port: u16 = 8080;
        let dst_port: u16 = 80;
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // dst mac
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
        // IPv4 header (20 bytes, IHL=5)
        pkt.push(0x45); // version + IHL
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length = 20+20
        pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
        pkt.extend_from_slice(&0u16.to_be_bytes()); // flags+frag
        pkt.push(64); // TTL
        pkt.push(6); // protocol = TCP
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent
        pkt
    }

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
    fn test_parse_bpf_buffer_single_record() {
        let pkt = build_simple_tcp_pkt();
        let mut buf = Vec::new();
        append_bpf_record(&mut buf, &pkt, 1000, 500);

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

    #[test]
    fn test_bpf_packet_iter_two_records() {
        let pkt = build_simple_tcp_pkt();
        let mut buf = Vec::new();
        append_bpf_record(&mut buf, &pkt, 1000, 0);
        append_bpf_record(&mut buf, &pkt, 2000, 500);

        let mut iter = BpfPacketIter::new(&buf, LinkType::Ethernet);
        let first = iter.next().expect("should yield first packet");
        assert_eq!(first.protocol, Protocol::Tcp);
        assert_eq!(first.timestamp, 1000 * 1_000_000);

        let second = iter.next().expect("should yield second packet");
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
}
