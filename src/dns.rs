// DNS wire format parser — RFC 1035 Section 4 implementation.
//
// Parses DNS header, question section (with name decompression), answer section
// (A, AAAA, CNAME, MX), and gracefully skips EDNS0 OPT records in the
// additional section.

use crate::error::NetopError;

/// Maximum number of pointer hops allowed during name decompression.
/// Prevents infinite loops from malicious compression pointers.
const MAX_COMPRESSION_HOPS: usize = 256;

/// Maximum allowed label length per RFC 1035 Section 2.3.4.
const MAX_LABEL_LENGTH: usize = 63;

/// DNS header size in bytes.
const HEADER_SIZE: usize = 12;

// DNS record type constants.
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_MX: u16 = 15;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;

/// DNS response codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl Rcode {
    fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            n => Self::Other(n),
        }
    }
}

impl std::fmt::Display for Rcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoError => write!(f, "NOERROR"),
            Self::FormErr => write!(f, "FORMERR"),
            Self::ServFail => write!(f, "SERVFAIL"),
            Self::NXDomain => write!(f, "NXDOMAIN"),
            Self::NotImp => write!(f, "NOTIMP"),
            Self::Refused => write!(f, "REFUSED"),
            Self::Other(n) => write!(f, "RCODE({})", n),
        }
    }
}

/// DNS record type as parsed from wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    OPT,
    Other(u16),
}

impl RecordType {
    fn from_u16(val: u16) -> Self {
        match val {
            TYPE_A => Self::A,
            TYPE_CNAME => Self::CNAME,
            TYPE_MX => Self::MX,
            TYPE_AAAA => Self::AAAA,
            TYPE_OPT => Self::OPT,
            n => Self::Other(n),
        }
    }

    #[allow(dead_code)]
    fn to_u16(self) -> u16 {
        match self {
            Self::A => TYPE_A,
            Self::AAAA => TYPE_AAAA,
            Self::CNAME => TYPE_CNAME,
            Self::MX => TYPE_MX,
            Self::OPT => TYPE_OPT,
            Self::Other(n) => n,
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::CNAME => write!(f, "CNAME"),
            Self::MX => write!(f, "MX"),
            Self::OPT => write!(f, "OPT"),
            Self::Other(n) => write!(f, "TYPE({})", n),
        }
    }
}

/// A single DNS question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: u16,
}

/// A single DNS answer (or authority/additional) resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: RecordType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: String,
}

/// A fully parsed DNS message.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: Rcode,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

/// Parse a DNS message from its wire format representation.
///
/// The `payload` should begin at the DNS header (i.e., the UDP payload for
/// standard DNS-over-UDP, or the TCP payload after the 2-byte length prefix
/// has been stripped for DNS-over-TCP).
pub fn parse_dns(payload: &[u8]) -> Result<DnsMessage, NetopError> {
    if payload.len() < HEADER_SIZE {
        return Err(NetopError::DnsParse {
            offset: 0,
            detail: "truncated DNS header".to_string(),
        });
    }

    // -- Header (12 bytes) --
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let nscount = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    let arcount = u16::from_be_bytes([payload[10], payload[11]]) as usize;

    let is_response = (flags >> 15) & 1 == 1;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = Rcode::from_u8((flags & 0x0F) as u8);

    let mut offset = HEADER_SIZE;

    // -- Question section --
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (name, new_offset) = decompress_name(payload, offset)?;
        offset = new_offset;

        if offset + 4 > payload.len() {
            return Err(NetopError::DnsParse {
                offset,
                detail: "truncated question section".to_string(),
            });
        }

        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion {
            name,
            qtype: RecordType::from_u16(qtype),
            qclass,
        });
    }

    // -- Answer section --
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (answer, new_offset) = parse_resource_record(payload, offset)?;
        offset = new_offset;
        answers.push(answer);
    }

    // -- Authority section (skip) --
    for _ in 0..nscount {
        let (_, new_offset) = parse_resource_record(payload, offset)?;
        offset = new_offset;
    }

    // -- Additional section (handle EDNS0 OPT gracefully) --
    for _ in 0..arcount {
        // We still parse the record to advance the offset, but we only keep
        // non-OPT records. OPT records are silently discarded.
        let (record, new_offset) = parse_resource_record(payload, offset)?;
        offset = new_offset;
        if record.rtype != RecordType::OPT {
            // Additional records that are not OPT are ignored for our purposes
            // but we could collect them if needed in the future.
            let _ = record;
        }
    }

    Ok(DnsMessage {
        id,
        is_response,
        opcode,
        rcode,
        questions,
        answers,
    })
}

/// Parse a resource record (answer, authority, or additional) starting at `offset`.
/// Returns the parsed record and the offset immediately after the record.
fn parse_resource_record(buf: &[u8], offset: usize) -> Result<(DnsAnswer, usize), NetopError> {
    let (name, mut offset) = decompress_name(buf, offset)?;

    if offset + 10 > buf.len() {
        return Err(NetopError::DnsParse {
            offset,
            detail: "truncated resource record header".to_string(),
        });
    }

    let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
    let ttl = u32::from_be_bytes([
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
    offset += 10;

    if offset + rdlength > buf.len() {
        return Err(NetopError::DnsParse {
            offset,
            detail: "truncated resource record rdata".to_string(),
        });
    }

    let record_type = RecordType::from_u16(rtype);
    let rdata = parse_rdata(buf, offset, rdlength, record_type)?;
    offset += rdlength;

    Ok((
        DnsAnswer {
            name,
            rtype: record_type,
            rclass,
            ttl,
            rdata,
        },
        offset,
    ))
}

/// Parse the RDATA portion of a resource record into a human-readable string.
fn parse_rdata(
    buf: &[u8],
    offset: usize,
    rdlength: usize,
    rtype: RecordType,
) -> Result<String, NetopError> {
    match rtype {
        RecordType::A => {
            if rdlength != 4 {
                return Err(NetopError::DnsParse {
                    offset,
                    detail: format!("A record rdata length {} != 4", rdlength),
                });
            }
            Ok(format!(
                "{}.{}.{}.{}",
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3]
            ))
        }
        RecordType::AAAA => {
            if rdlength != 16 {
                return Err(NetopError::DnsParse {
                    offset,
                    detail: format!("AAAA record rdata length {} != 16", rdlength),
                });
            }
            let mut groups = [0u16; 8];
            for i in 0..8 {
                groups[i] = u16::from_be_bytes([buf[offset + i * 2], buf[offset + i * 2 + 1]]);
            }
            // Use standard Rust IPv6 formatting for proper zero-compression.
            let addr = std::net::Ipv6Addr::new(
                groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6],
                groups[7],
            );
            Ok(addr.to_string())
        }
        RecordType::CNAME => {
            let (name, _) = decompress_name(buf, offset)?;
            Ok(name)
        }
        RecordType::MX => {
            if rdlength < 3 {
                return Err(NetopError::DnsParse {
                    offset,
                    detail: "MX record rdata too short".to_string(),
                });
            }
            let preference = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let (exchange, _) = decompress_name(buf, offset + 2)?;
            Ok(format!("{} {}", preference, exchange))
        }
        RecordType::OPT => {
            // OPT pseudo-record: rdata is opaque; represent as hex or empty.
            Ok(String::new())
        }
        RecordType::Other(_) => {
            // Unknown record type: represent rdata as hex.
            let hex: Vec<String> = buf[offset..offset + rdlength]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            Ok(hex.join(""))
        }
    }
}

/// Decompress a DNS name starting at `offset` in `buf`.
///
/// Follows RFC 1035 Section 4.1.4 name compression. Returns the fully
/// qualified domain name (with trailing dot) and the offset in the buffer
/// immediately after the name field (i.e., where the next field begins).
///
/// If the name uses compression pointers, the returned offset points past
/// the *first* pointer encountered, not past the target of the pointer.
fn decompress_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), NetopError> {
    let mut name = String::new();
    let mut followed_pointer = false;
    let mut end_offset = 0;
    let mut hops = 0usize;

    loop {
        if hops > MAX_COMPRESSION_HOPS {
            return Err(NetopError::DnsParse {
                offset,
                detail: "compression loop".to_string(),
            });
        }

        if offset >= buf.len() {
            return Err(NetopError::DnsParse {
                offset,
                detail: "truncated name".to_string(),
            });
        }

        let len = buf[offset] as usize;

        if len == 0 {
            // Root label — end of name.
            if !followed_pointer {
                end_offset = offset + 1;
            }
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes).
            if offset + 1 >= buf.len() {
                return Err(NetopError::DnsParse {
                    offset,
                    detail: "truncated compression pointer".to_string(),
                });
            }
            if !followed_pointer {
                end_offset = offset + 2;
            }
            let pointer = ((len & 0x3F) << 8) | (buf[offset + 1] as usize);
            offset = pointer;
            followed_pointer = true;
            hops += 1;
            continue;
        }

        if len > MAX_LABEL_LENGTH {
            return Err(NetopError::DnsParse {
                offset,
                detail: format!(
                    "label length {} exceeds maximum of {}",
                    len, MAX_LABEL_LENGTH
                ),
            });
        }

        // Regular label.
        offset += 1;

        if offset + len > buf.len() {
            return Err(NetopError::DnsParse {
                offset,
                detail: "truncated label".to_string(),
            });
        }

        let label =
            std::str::from_utf8(&buf[offset..offset + len]).map_err(|_| NetopError::DnsParse {
                offset,
                detail: "invalid UTF-8 in label".to_string(),
            })?;

        name.push_str(label);
        name.push('.');
        offset += len;
        hops += 1;
    }

    // An empty name (root only) is represented as ".".
    if name.is_empty() {
        name.push('.');
    }

    let _ = followed_pointer;
    Ok((name, end_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Helper: encode a domain name in DNS wire format (no compression).
    // "example.com" -> [7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
    // "." (root) -> [0]
    // ---------------------------------------------------------------
    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if name == "." || name.is_empty() {
            out.push(0);
            return out;
        }
        let stripped = name.strip_suffix('.').unwrap_or(name);
        for label in stripped.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    // ---------------------------------------------------------------
    // Helper: build a DNS query packet.
    // qtype is a raw u16 value (1=A, 28=AAAA, 15=MX, etc.)
    // ---------------------------------------------------------------
    fn build_dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&id.to_be_bytes()); // ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Flags: QR=0, OPCODE=0, RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
        // Question
        pkt.extend_from_slice(&encode_name(name));
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        pkt
    }

    // ---------------------------------------------------------------
    // Helper: build a DNS response packet.
    //
    // `questions` is a list of (name, qtype) pairs.
    // `answers` is a list of (name, rtype, rdata_bytes) tuples where
    //   rdata_bytes is the raw RDATA octets.
    // ---------------------------------------------------------------
    fn build_dns_response(
        id: u16,
        rcode: u8,
        questions: &[(&str, u16)],
        answers: &[(&str, u16, &[u8])],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&id.to_be_bytes());
        let flags: u16 = 0x8180 | (rcode as u16 & 0x0F); // QR=1, RD=1, RA=1
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&(questions.len() as u16).to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Questions
        for (name, qtype) in questions {
            pkt.extend_from_slice(&encode_name(name));
            pkt.extend_from_slice(&qtype.to_be_bytes());
            pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        }
        // Answers
        for (name, rtype, rdata) in answers {
            pkt.extend_from_slice(&encode_name(name));
            pkt.extend_from_slice(&rtype.to_be_bytes()); // TYPE
            pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
            pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL=300
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
            pkt.extend_from_slice(rdata);
        }
        pkt
    }

    // ---------------------------------------------------------------
    // Helper: build a DNS response with additional section records.
    // ---------------------------------------------------------------
    fn build_dns_response_with_additional(
        id: u16,
        rcode: u8,
        questions: &[(&str, u16)],
        answers: &[(&str, u16, &[u8])],
        additional: &[(&str, u16, u16, &[u8])], // (name, rtype, rclass, rdata)
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&id.to_be_bytes());
        let flags: u16 = 0x8180 | (rcode as u16 & 0x0F);
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&(additional.len() as u16).to_be_bytes()); // ARCOUNT
        // Questions
        for (name, qtype) in questions {
            pkt.extend_from_slice(&encode_name(name));
            pkt.extend_from_slice(&qtype.to_be_bytes());
            pkt.extend_from_slice(&1u16.to_be_bytes());
        }
        // Answers
        for (name, rtype, rdata) in answers {
            pkt.extend_from_slice(&encode_name(name));
            pkt.extend_from_slice(&rtype.to_be_bytes());
            pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
            pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL=300
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            pkt.extend_from_slice(rdata);
        }
        // Additional
        for (name, rtype, rclass, rdata) in additional {
            pkt.extend_from_slice(&encode_name(name));
            pkt.extend_from_slice(&rtype.to_be_bytes());
            pkt.extend_from_slice(&rclass.to_be_bytes());
            pkt.extend_from_slice(&0u32.to_be_bytes()); // TTL=0
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            pkt.extend_from_slice(rdata);
        }
        pkt
    }

    // =====================================================================
    // UT-1.1: Standard A query, no compression
    // =====================================================================
    #[test]
    fn ut_1_1_standard_a_query() {
        let pkt = build_dns_query(0x1234, "example.com", TYPE_A);
        let msg = parse_dns(&pkt).unwrap();
        assert!(!msg.is_response);
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.opcode, 0);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com.");
        assert_eq!(msg.questions[0].qtype, RecordType::A);
        assert_eq!(msg.questions[0].qclass, 1);
        assert!(msg.answers.is_empty());
    }

    // =====================================================================
    // UT-1.2: A response with single answer
    // =====================================================================
    #[test]
    fn ut_1_2_a_response_single_answer() {
        let rdata: [u8; 4] = [93, 184, 216, 34]; // 93.184.216.34
        let pkt = build_dns_response(
            0xABCD,
            0, // NOERROR
            &[("example.com", TYPE_A)],
            &[("example.com", TYPE_A, &rdata)],
        );
        let msg = parse_dns(&pkt).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.id, 0xABCD);
        assert_eq!(msg.rcode, Rcode::NoError);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com.");
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "example.com.");
        assert_eq!(msg.answers[0].rtype, RecordType::A);
        assert_eq!(msg.answers[0].rdata, "93.184.216.34");
        assert_eq!(msg.answers[0].ttl, 300);
    }

    // =====================================================================
    // UT-1.3: Compressed name (single pointer)
    // =====================================================================
    #[test]
    fn ut_1_3_compressed_name_single_pointer() {
        // Build a response where the answer name uses a pointer back to the
        // question name at offset 12.
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: response
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question: example.com at offset 12
        pkt.extend_from_slice(&encode_name("example.com"));
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // Answer: name is a pointer to offset 12 (0xC00C)
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
        pkt.extend_from_slice(&120u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        pkt.extend_from_slice(&[1, 2, 3, 4]); // RDATA

        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "example.com.");
        assert_eq!(msg.answers[0].rdata, "1.2.3.4");
    }

    // =====================================================================
    // UT-1.4: Doubly compressed name (pointer chain)
    // =====================================================================
    #[test]
    fn ut_1_4_doubly_compressed_name() {
        // Tests double compression: a pointer that leads to a label+pointer chain.
        // Layout:
        //   Question: "com." inline at offset 12  (3 "com" 0)
        //   Answer 1: name = "example" + ptr→12 = "example.com." (single compression)
        //   Answer 2: name = ptr→(answer 1 name offset) → resolves through label+ptr chain
        //   This is double compression: ptr → "example" → ptr → "com" → root
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x0002u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: response
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question at offset 12: "com."
        assert_eq!(pkt.len(), 12);
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0); // root — offset 16
        pkt.extend_from_slice(&TYPE_A.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS
        // Question section ends at offset 21

        // Answer 1 at offset 21: name = "example" + ptr→12 = "example.com."
        let ans1_name_offset = pkt.len(); // 21
        assert_eq!(ans1_name_offset, 21);
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.extend_from_slice(&[0xC0, 12]); // pointer to "com." at offset 12
        // After name: offset 31
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS
        pkt.extend_from_slice(&60u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        pkt.extend_from_slice(&[10, 0, 0, 1]); // RDATA
        // Answer 1 ends at offset 45

        // Answer 2 at offset 45: name = ptr→21 (double compression!)
        // Resolves: ptr→21 → "example" → ptr→12 → "com" → root = "example.com."
        pkt.extend_from_slice(&[0xC0, ans1_name_offset as u8]); // pointer to offset 21
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS
        pkt.extend_from_slice(&120u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        pkt.extend_from_slice(&[10, 0, 0, 2]); // RDATA

        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "com.");
        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].name, "example.com.");
        assert_eq!(msg.answers[0].rdata, "10.0.0.1");
        // Answer 2 name went through double compression
        assert_eq!(msg.answers[1].name, "example.com.");
        assert_eq!(msg.answers[1].rdata, "10.0.0.2");
    }

    // =====================================================================
    // UT-1.5: Malicious compression loop -> Err within bounded time (<1ms)
    // =====================================================================
    #[test]
    fn ut_1_5_compression_loop() {
        // Create a packet where offset 12 has a pointer to offset 12 (self-loop).
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x0003u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Query
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question name at offset 12: pointer to offset 12 (self-referencing)
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        // QTYPE and QCLASS (won't be reached, but include them for completeness)
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        let start = std::time::Instant::now();
        let result = parse_dns(&pkt);
        let elapsed = start.elapsed();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("compression loop"),
            "expected 'compression loop' in error, got: {}",
            err
        );
        assert!(
            elapsed.as_millis() < 1,
            "loop detection took {}ms, expected <1ms",
            elapsed.as_millis()
        );
    }

    // =====================================================================
    // UT-1.6: Truncated packet (header only) -> Err with "truncated"
    // =====================================================================
    #[test]
    fn ut_1_6_truncated_packet() {
        // A 12-byte header with QDCOUNT=1 but no question section.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0004u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(pkt.len(), 12);

        let result = parse_dns(&pkt);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("truncated"),
            "expected 'truncated' in error, got: {}",
            err
        );
    }

    // =====================================================================
    // UT-1.6b: Packet shorter than header -> Err with "truncated"
    // =====================================================================
    #[test]
    fn ut_1_6b_packet_shorter_than_header() {
        let pkt = [0u8; 6]; // only 6 bytes, header needs 12
        let result = parse_dns(&pkt);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("truncated"));
    }

    // =====================================================================
    // UT-1.7: AAAA query and response
    // =====================================================================
    #[test]
    fn ut_1_7_aaaa_query_and_response() {
        // Query
        let query = build_dns_query(0x0007, "example.com", TYPE_AAAA);
        let msg = parse_dns(&query).unwrap();
        assert!(!msg.is_response);
        assert_eq!(msg.questions[0].qtype, RecordType::AAAA);

        // Response: 2606:2800:0220:0001:0000:0000:0000:0000
        let rdata: [u8; 16] = [
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let response = build_dns_response(
            0x0007,
            0,
            &[("example.com", TYPE_AAAA)],
            &[("example.com", TYPE_AAAA, &rdata)],
        );
        let msg = parse_dns(&response).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].rtype, RecordType::AAAA);
        // Rust's Ipv6Addr formats this with zero-compression.
        assert_eq!(msg.answers[0].rdata, "2606:2800:220:1::");
    }

    // =====================================================================
    // UT-1.8: NXDOMAIN response (rcode=3)
    // =====================================================================
    #[test]
    fn ut_1_8_nxdomain() {
        let pkt = build_dns_response(
            0x0008,
            3, // NXDOMAIN
            &[("nonexistent.example.com", TYPE_A)],
            &[], // no answers
        );
        let msg = parse_dns(&pkt).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.rcode, Rcode::NXDomain);
        assert!(msg.answers.is_empty());
    }

    // =====================================================================
    // UT-1.9: SERVFAIL response (rcode=2)
    // =====================================================================
    #[test]
    fn ut_1_9_servfail() {
        let pkt = build_dns_response(
            0x0009,
            2, // SERVFAIL
            &[("example.com", TYPE_A)],
            &[],
        );
        let msg = parse_dns(&pkt).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.rcode, Rcode::ServFail);
    }

    // =====================================================================
    // UT-1.10: EDNS0 OPT record in additional section
    // =====================================================================
    #[test]
    fn ut_1_10_edns0_opt() {
        // OPT record: name="." (root), type=OPT(41), class=4096 (UDP size),
        // TTL=0, RDLENGTH=0
        let pkt = build_dns_response_with_additional(
            0x0010,
            0,
            &[("example.com", TYPE_A)],
            &[("example.com", TYPE_A, &[1, 2, 3, 4])],
            &[(".", TYPE_OPT, 4096, &[])], // OPT pseudo-RR
        );
        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].rdata, "1.2.3.4");
        // OPT record should be skipped gracefully; no error.
    }

    // =====================================================================
    // UT-1.11: Multiple questions in one query
    // =====================================================================
    #[test]
    fn ut_1_11_multiple_questions() {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x0011u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Query, RD=1
        pkt.extend_from_slice(&2u16.to_be_bytes()); // QDCOUNT=2
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // Question 1: example.com A
        pkt.extend_from_slice(&encode_name("example.com"));
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // Question 2: example.org AAAA
        pkt.extend_from_slice(&encode_name("example.org"));
        pkt.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.questions.len(), 2);
        assert_eq!(msg.questions[0].name, "example.com.");
        assert_eq!(msg.questions[0].qtype, RecordType::A);
        assert_eq!(msg.questions[1].name, "example.org.");
        assert_eq!(msg.questions[1].qtype, RecordType::AAAA);
    }

    // =====================================================================
    // UT-1.12: CNAME response (CNAME -> A chain)
    // =====================================================================
    #[test]
    fn ut_1_12_cname_response() {
        // Response with two answers: a CNAME and an A record.
        // www.example.com CNAME -> example.com, then example.com A -> 93.184.216.34
        let cname_rdata = encode_name("example.com");
        let a_rdata: [u8; 4] = [93, 184, 216, 34];

        let pkt = build_dns_response(
            0x0012,
            0,
            &[("www.example.com", TYPE_A)],
            &[
                ("www.example.com", TYPE_CNAME, &cname_rdata),
                ("example.com", TYPE_A, &a_rdata),
            ],
        );

        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].rtype, RecordType::CNAME);
        assert_eq!(msg.answers[0].rdata, "example.com.");
        assert_eq!(msg.answers[1].rtype, RecordType::A);
        assert_eq!(msg.answers[1].rdata, "93.184.216.34");
    }

    // =====================================================================
    // UT-1.13: MX query and response
    // =====================================================================
    #[test]
    fn ut_1_13_mx_query_and_response() {
        // Query
        let query = build_dns_query(0x0013, "example.com", TYPE_MX);
        let msg = parse_dns(&query).unwrap();
        assert_eq!(msg.questions[0].qtype, RecordType::MX);

        // Response: MX preference=10, exchange=mail.example.com
        let mut mx_rdata = Vec::new();
        mx_rdata.extend_from_slice(&10u16.to_be_bytes()); // preference
        mx_rdata.extend_from_slice(&encode_name("mail.example.com")); // exchange

        let response = build_dns_response(
            0x0013,
            0,
            &[("example.com", TYPE_MX)],
            &[("example.com", TYPE_MX, &mx_rdata)],
        );
        let msg = parse_dns(&response).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].rtype, RecordType::MX);
        assert_eq!(msg.answers[0].rdata, "10 mail.example.com.");
    }

    // =====================================================================
    // UT-1.14: Empty name (root ".")
    // =====================================================================
    #[test]
    fn ut_1_14_empty_name_root() {
        // A query for the root domain ".".
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x0014u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // Question: root name = single zero byte
        pkt.push(0x00); // root label
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, ".");
    }

    // =====================================================================
    // UT-1.15: Maximum-length label (63 bytes)
    // =====================================================================
    #[test]
    fn ut_1_15_max_length_label() {
        // Create a label with exactly 63 characters.
        let label = "a".repeat(63);
        let name = format!("{}.com", label);

        let pkt = build_dns_query(0x0015, &name, TYPE_A);
        let msg = parse_dns(&pkt).unwrap();
        assert_eq!(msg.questions[0].name, format!("{}.", name));
    }

    // =====================================================================
    // UT-1.16: Label exceeding 63 bytes -> parse error
    // =====================================================================
    #[test]
    fn ut_1_16_label_exceeding_63_bytes() {
        // Manually construct a packet with a 64-byte label.
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x0016u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        // Question name with 64-byte label (invalid)
        pkt.push(64); // label length = 64 (exceeds max of 63)
        pkt.extend_from_slice(&[b'x'; 64]);
        pkt.push(0); // root
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        let result = parse_dns(&pkt);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("label length"),
            "expected 'label length' in error, got: {}",
            err
        );
    }
}
