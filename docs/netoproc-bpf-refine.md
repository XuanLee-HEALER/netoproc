# BPF Module Technical Documentation

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [macOS BPF Device Model](#2-macos-bpf-device-model)
3. [ioctl Constants and Encoding](#3-ioctl-constants-and-encoding)
4. [BPF Header and Buffer Layout](#4-bpf-header-and-buffer-layout)
5. [BPF Filter Programs](#5-bpf-filter-programs)
6. [Packet Parsing Pipeline](#6-packet-parsing-pipeline)
7. [IPv6 Extension Header Traversal](#7-ipv6-extension-header-traversal)
8. [Streaming Iterator](#8-streaming-iterator)
9. [DNS Capture and Parsing](#9-dns-capture-and-parsing)
10. [Performance Optimizations](#10-performance-optimizations)
11. [Known Limitations](#11-known-limitations)
12. [Pitfalls Encountered](#12-pitfalls-encountered)

---

## 1. Architecture Overview

The BPF module (`src/bpf/`) is responsible for raw packet
capture on macOS. It consists of four files:

```text
src/bpf/
├── mod.rs      # BpfCapture handle, ioctl wrappers
├── packet.rs   # BpfHdr, BpfPacketIter, parsers
├── filter.rs   # Classic BPF filter programs
└── dns.rs      # DNS wire format parser (RFC 1035)
```

### Data Flow

```text
/dev/bpfN ──read()──> raw buffer
  ──BpfPacketIter──> PacketSummary
  ──extract_dns──> dns::parse_dns ──> DnsMessage
```

Two separate `BpfCapture` instances are opened per
monitored interface:

| Capture | Filter           | Snap   | Output          |
|---------|------------------|--------|-----------------|
| Traffic | `traffic_filter` | 65535  | `PacketSummary` |
| DNS     | `dns_filter`     | 512    | `DnsMessage`    |

Both feed into crossbeam channels consumed by the stats
poller thread, which merges them into
`SystemNetworkState` published via `ArcSwap`.

---

## 2. macOS BPF Device Model

### Device Files

macOS exposes BPF devices as `/dev/bpf0` through
`/dev/bpf255`. Each device can be bound to one network
interface at a time. Opening is done via
`open(O_RDONLY)`, scanning sequentially until finding
one that isn't `EBUSY`:

```rust
for i in 0..256 {
    let fd = open(format!("/dev/bpf{i}"), O_RDONLY);
    match error {
        EBUSY  => continue,  // in use
        ENOENT => break,     // no more devices
        _      => return Err,
    }
}
```

### Device Configuration Sequence

After opening, the device is configured through a
series of `ioctl` calls in strict order:

1. **BIOCSBLEN** — Set kernel buffer size (before bind)
2. **BIOCSETIF** — Bind to a network interface
3. **BIOCSRTIMEOUT** — Set read timeout (500ms)
4. **BIOCSETF** — Install packet filter program
5. **BIOCPROMISC** — Enable promiscuous mode (non-fatal)
6. **BIOCGBLEN** — Read back actual buffer size

The order matters: `BIOCSBLEN` must come before
`BIOCSETIF`. The kernel may silently adjust the buffer
size, so we always read back with `BIOCGBLEN` to
allocate the correct userspace buffer.

> **v0.2.0 change**: `BIOCIMMEDIATE` is no longer set.
> Without it, the kernel buffers packets until the read
> timeout (500ms) fires or the buffer fills, whichever
> comes first. This reduces the number of small reads
> and better matches the streaming batch architecture.
> The default buffer size has been increased from 32 KB
> to **2 MB** to accommodate the 500ms batching window.

### Buffer Size Guard

The buffer size has a minimum floor of 4096 bytes:

```rust
let blen = buffer_size.max(4096);
```

Passing 0 or tiny values to `BIOCSBLEN` causes undefined
behavior on some macOS versions. The 4096 minimum is
sufficient for any single Ethernet frame (max 1518 bytes
standard, ~9000 jumbo) plus the BPF header.

---

## 3. ioctl Constants and Encoding

macOS ioctl numbers are encoded using `_IOC` macros
from `<sys/ioccom.h>`:

```text
Bits [31:30] = direction (IN/OUT/INOUT/VOID)
Bits [29:16] = parameter size (13 bits)
Bits [15:8]  = group character ('B' = 0x42)
Bits [7:0]   = command number
```

The `ioc()` helper computes these at compile time:

```rust
const fn ioc(
    dir: u32, group: u8, num: u8, size: u32,
) -> c_ulong {
    (dir
        | ((size & 0x1FFF) << 16)
        | ((group as u32) << 8)
        | num as u32) as c_ulong
}
```

Direction constants:

- `IOC_VOID`  = `0x20000000` — no parameter
- `IOC_OUT`   = `0x40000000` — kernel to user
- `IOC_IN`    = `0x80000000` — user to kernel
- `IOC_INOUT` = `0xC0000000` — bidirectional

### Compile-Time Verification

Every ioctl constant is verified against known macOS
values:

```rust
const _: () = assert!(BIOCSBLEN == 0xC004_4266);
const _: () = assert!(BIOCSETIF == 0x8020_426C);
// ... etc
```

This catches encoding bugs at compile time.

### ioctl Summary

| Constant        | Value        | Dir   | Description       |
|-----------------|--------------|-------|-------------------|
| `BIOCSBLEN`     | `0xC0044266` | INOUT | Set buffer length |
| `BIOCGBLEN`     | `0x40044266` | OUT   | Get buffer length |
| `BIOCSETIF`     | `0x8020426C` | IN    | Bind to interface |
| `BIOCSETF`      | `0x80104267` | IN    | Set filter        |
| `BIOCIMMEDIATE` | `0x80044270` | IN    | Immediate mode    |
| `BIOCPROMISC`   | `0x20004269` | VOID  | Promiscuous mode  |
| `BIOCGSTATS`    | `0x4008426F` | OUT   | Get statistics    |
| `BIOCSRTIMEOUT` | `0x8010426D` | IN    | Set read timeout  |

---

## 4. BPF Header and Buffer Layout

### BpfHdr Structure

Each packet in the BPF read buffer is prefixed by a
`bpf_hdr`:

```rust
#[repr(C)]
pub struct BpfHdr {
    pub bh_tstamp:  libc::timeval, // 16 bytes
    pub bh_caplen:  u32,           // captured len
    pub bh_datalen: u32,           // original len
    pub bh_hdrlen:  u16,           // header + pad
}
// Total: 32 bytes (6 bytes struct padding)
```

**Critical note**: On macOS (both arm64 and x86_64),
`timeval` uses 64-bit members:
`{ tv_sec: i64, tv_usec: i64 }` = 16 bytes. This
differs from 32-bit Linux where `timeval` is 8 bytes.
A compile-time assertion enforces the expected 32-byte
size.

### Buffer Memory Layout

A single `read()` from `/dev/bpfN` returns zero or more
records packed sequentially:

```text
+----------------------+----------------+---------+
| BpfHdr (32 bytes)    | Packet Data    | Padding |
| bh_hdrlen=32         | bh_caplen bytes| to 4B   |
| bh_caplen=N          |                | align   |
+----------------------+----------------+---------+
| BpfHdr (32 bytes)    | Packet Data    | Padding |
| ...                  | ...            |         |
+----------------------+----------------+---------+
```

### BPF_WORDALIGN

Records are padded to 4-byte alignment using the
`BPF_WORDALIGN` macro:

```rust
pub const fn bpf_wordalign(x: usize) -> usize {
    (x + 3) & !3
}
```

To advance to the next record:
`offset += bpf_wordalign(bh_hdrlen + bh_caplen)`.

**Pitfall**: `bh_hdrlen` already includes struct
padding between the header and packet data. The
packet data starts at `offset + bh_hdrlen`, not at
`offset + sizeof(BpfHdr)`. Always use `bh_hdrlen`
for the header length.

### Read Safety

The BPF header must be read with `read_unaligned`
because it may not be aligned to 8 bytes (the
`timeval` alignment requirement) within the buffer:

```rust
let hdr = std::ptr::read_unaligned(hdr_ptr);
```

Using a direct dereference would be undefined behavior
on unaligned addresses.

---

## 5. BPF Filter Programs

### Classic BPF Instruction Set

Each instruction is 8 bytes:

```rust
#[repr(C)]
pub struct bpf_insn {
    pub code: u16, // opcode = class | size | mode
    pub jt:   u8,  // jump-true offset (relative)
    pub jf:   u8,  // jump-false offset (relative)
    pub k:    u32, // immediate/offset constant
}
```

Jump offsets are **relative to PC+1** (the next
instruction), not absolute. So `jt=0` means
"fall through", `jt=1` means "skip 1 instruction".

### Traffic Filter (11 instructions)

Accepts IPv4/IPv6 packets carrying TCP or UDP.
Rejects ICMP, OSPF, ARP, and all other protocols at
the kernel level before they reach userspace.

```text
  [0]  ldh  [12]               ; EtherType
  [1]  jeq  #0x0800 jt=0 jf=3 ; IPv4? else [5]
  [2]  ldb  [23]               ; IPv4 protocol
  [3]  jeq  #6      jt=5 jf=0 ; TCP? accept
  [4]  jeq  #17     jt=4 jf=5 ; UDP? accept/drop
  [5]  jeq  #0x86DD jt=0 jf=4 ; IPv6? else drop
  [6]  ldb  [20]               ; IPv6 Next Header
  [7]  jeq  #6      jt=1 jf=0 ; TCP? accept
  [8]  jeq  #17     jt=0 jf=1 ; UDP? accept/drop
  [9]  ret  #65535             ; ACCEPT
  [10] ret  #0                 ; DROP
```

Jump offset calculation example for instruction `[4]`:

- Current PC = 4, next PC = 5
- `jt=4`: jump to 5+4 = 9 (accept)
- `jf=5`: jump to 5+5 = 10 (drop)

### DNS Filter (14 instructions)

Accepts only IPv4 UDP/TCP packets with source or
destination port 53. Notable features:

- Uses `BPF_MSH` (`ldx 4*([14]&0xf)`) to compute
  IPv4 header length dynamically
- Uses indirect addressing (`ldh [x+14]`) for port
  checks relative to the variable-length IP header
- Includes fragment check (`jset #0x1FFF`) to skip
  non-first fragments (which lack L4 headers)
- Snap length is 512 bytes

```text
  [0]  ldh  [12]               ; EtherType
  [1]  jeq  #0x0800 jt=0 jf=11; IPv4? else drop
  [2]  ldb  [23]               ; IP protocol
  [3]  jeq  #17     jt=1 jf=0 ; UDP? frag check
  [4]  jeq  #6      jt=2 jf=8 ; TCP? port check
  [5]  ldh  [20]               ; IP flags+frag
  [6]  jset #0x1FFF jt=6 jf=0 ; fragment? drop
  [7]  ldx  4*([14]&0xf)      ; X = IP hdr len
  [8]  ldh  [x+14]            ; source port
  [9]  jeq  #53     jt=2 jf=0 ; DNS src? accept
  [10] ldh  [x+16]            ; dest port
  [11] jeq  #53     jt=0 jf=1 ; DNS dst? accept
  [12] ret  #512              ; ACCEPT
  [13] ret  #0                ; DROP
```

### Test Infrastructure: BPF VM

The filter module includes a complete classic BPF
virtual machine (`execute_filter()`) for unit testing.
It supports the full instruction subset used by both
filters: LD, LDX, ST, STX, ALU, JMP, and RET. This
allows filter correctness to be verified entirely in
userspace without needing a real BPF device.

---

## 6. Packet Parsing Pipeline

### Layer Model

```text
Raw BPF Buffer
  +- BpfHdr -> timestamp, caplen, datalen
    +- Ethernet (14 bytes) -> EtherType
      +- IPv4 (20-60 bytes) -> protocol, IPs
      |   +- TCP/UDP/ICMP -> ports
      +- IPv6 (40 bytes + ext headers) -> IPs
          +- Extension headers (0..N) -> skip
            +- TCP/UDP/ICMPv6 -> ports
```

### PacketSummary

The output of packet parsing:

```rust
pub struct PacketSummary {
    pub timestamp: u64,     // usec since epoch
    pub protocol:  Protocol,// Tcp | Udp | Icmp
    pub src_ip:    IpAddr,
    pub src_port:  u16,     // 0 for ICMP
    pub dst_ip:    IpAddr,
    pub dst_port:  u16,     // 0 for ICMP
    pub ip_len:    u16,     // original IP len
}
```

### Parsing Rules

Packets are silently dropped (`None`) in these cases:

- Truncated at any layer (Ethernet, IP, L4)
- Unknown EtherType (not `0x0800` or `0x86DD`)
- IPv4 IHL < 5 (invalid minimum header length)
- Non-first IPv4 fragment (offset != 0)
- Unknown L4 protocol (not TCP/UDP/ICMP/ICMPv6)

The `ip_len` field uses the IP header's total length,
not `bh_caplen`, so byte accounting remains accurate
even when BPF truncates the capture.

---

## 7. IPv6 Extension Header Traversal

### Problem

The IPv6 fixed header's `Next Header` field may point
to an extension header rather than directly to TCP/UDP.
Without traversal, any IPv6 packet with extension
headers would fail to parse.

### Extension Header Types

| Type                | Proto | Size                     |
|---------------------|-------|--------------------------|
| Hop-by-Hop Options  | 0     | (hdr_ext_len + 1) * 8    |
| Routing             | 43    | (hdr_ext_len + 1) * 8    |
| Fragment            | 44    | Fixed 8 bytes            |
| Destination Options | 60    | (hdr_ext_len + 1) * 8    |

### Implementation

```rust
pub(crate) fn skip_ipv6_extension_headers(
    mut next_hdr: u8,
    data: &[u8],
) -> (u8, usize) {
    let mut offset = 0;
    loop {
        match next_hdr {
            EXT_HOP_BY_HOP
            | EXT_ROUTING
            | EXT_DEST_OPTIONS => {
                if offset + 2 > data.len() {
                    return (next_hdr, offset);
                }
                let ext_len = data[offset + 1] as usize;
                let total = (ext_len + 1) * 8;
                if offset + total > data.len() {
                    return (next_hdr, offset);
                }
                next_hdr = data[offset];
                offset += total;
            }
            EXT_FRAGMENT => {
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
```

The function is called both in `parse_ipv6()` (for
traffic parsing) and in `extract_dns_payload()` (for
DNS extraction), ensuring consistent handling.

### Design Decisions

- **Truncation safety**: If data runs out mid-header,
  the function returns the current state rather than
  panicking. The caller will fail to parse L4.
- **No AH/ESP support**: Authentication Header (51)
  and ESP (50) are not traversed. These are rare and
  would require different parsing logic.
- **Fragment header**: Always 8 bytes regardless of
  `hdr_ext_len`. Per RFC 2460 Section 4.5.

---

## 8. Streaming Iterator

### Motivation

The original `parse_bpf_buffer()` collected all packets
into an intermediate `Vec<PacketSummary>` before
returning. For a typical BPF read returning dozens of
packets, this meant unnecessary heap allocation on
every read cycle.

### Design

`BpfPacketIter` is a standard
`Iterator<Item = PacketSummary>` that lazily parses
packets from a BPF buffer:

```rust
pub struct BpfPacketIter<'a> {
    buf: &'a [u8],
    pos: usize,
}
```

Key behaviors:

- **Lazy**: Each `next()` parses one BPF record
- **Skip unparseable**: Failed packets are silently
  skipped; the iterator advances to the next record
- **Zero allocation**: Borrows the buffer slice

The original `parse_bpf_buffer()` is retained as a
thin wrapper for backward compatibility:

```rust
pub fn parse_bpf_buffer(
    buf: &[u8],
) -> Vec<PacketSummary> {
    BpfPacketIter::new(buf).collect()
}
```

### Integration with read_packets

The `read_packets` method uses the iterator with a
reusable output Vec:

```rust
pub fn read_packets(
    &mut self,
    out: &mut Vec<PacketSummary>,
) -> Result<(), NetopError> {
    out.clear();
    // ... libc::read into self.buffer ...
    out.extend(
        BpfPacketIter::new(&self.buffer[..n as usize])
    );
    Ok(())
}
```

The caller (in `main.rs`) creates the Vec once
outside the loop:

```rust
let mut pkt_buf = Vec::new();
loop {
    cap.read_packets(&mut pkt_buf)?;
    for pkt in pkt_buf.drain(..) {
        tx.send(pkt)?;
    }
}
```

This eliminates per-read heap allocation entirely.
The Vec's internal buffer grows to steady-state size
after a few iterations and never shrinks.

---

## 9. DNS Capture and Parsing

### Separate BPF Device

DNS capture uses a dedicated BPF device with
`dns_filter()` installed. This is separate from the
traffic capture device because:

1. DNS needs port-level filtering (port 53)
2. DNS needs a smaller snap length (512 vs 65535)
3. DNS needs full payload for wire format parsing

### DNS Payload Extraction

`extract_dns_payload()` processes raw Ethernet frames:

1. Parse Ethernet header to determine EtherType
2. For IPv4: extract IHL, protocol
3. For IPv6: parse fixed header + skip ext headers
4. Check if L4 protocol is UDP (17) or TCP (6)
5. Check if source or destination port is 53
6. For UDP: payload starts at UDP header + 8 bytes
7. For TCP: skip TCP header + 2-byte DNS length prefix

### DNS Wire Format Parser

`dns.rs` implements RFC 1035 Section 4 parsing:

- **Header** (12 bytes): ID, flags, section counts
- **Question section**: Name decompression + QTYPE
- **Answer/Authority/Additional**: Resource records
- **Supported types**: A, AAAA, CNAME, MX, OPT
- **Name compression**: RFC 1035 Section 4.1.4 with
  256-hop limit to prevent infinite loops

---

## 10. Performance Optimizations

### Summary of Optimizations

| Optimization            | Impact                 |
|-------------------------|------------------------|
| Vec reuse               | No per-read heap alloc |
| `BpfPacketIter`         | No intermediate Vec    |
| TCP/UDP protocol filter | Less kernel-user data  |
| 500ms read timeout      | Graceful shutdown      |
| 2 MB default buffer     | 500ms batching window  |

### Why Not eBPF?

macOS does not support eBPF. Classic BPF (cBPF) is the
only kernel-level packet filtering available. The
instruction set is limited but sufficient for our needs.

---

## 11. Known Limitations

### Traffic Filter IPv4 Protocol Offset

The traffic filter checks the IPv4 protocol byte at
absolute offset 23 (`ETH(14) + PROTO(9) = 23`). This
assumes a standard 20-byte IPv4 header with no IP
options. If IP options are present, offset 23 would
point into the options rather than the protocol field.

**Why acceptable**: IP options are extremely rare.
Packets with IP options would pass through the filter
unfiltered (the protocol check sees a random byte),
but the userspace parser handles variable-length IPv4
headers correctly via the IHL field. Such packets
consume buffer space but are parsed correctly.

### IPv6 Extension Header in Traffic Filter

The traffic filter checks IPv6 Next Header at offset
20 (`ETH(14) + NEXT_HDR(6) = 20`). If the first
Next Header is an extension header (e.g., Hop-by-Hop
= 0), the filter may incorrectly drop a valid
TCP/UDP packet or accept a non-TCP/UDP one.

**Mitigation**: Extension header traversal is done in
userspace by `skip_ipv6_extension_headers()`.
Incorrectly accepted packets are dropped by the
parser; incorrectly rejected packets are a minor data
loss acceptable for monitoring purposes.

### DNS Filter: IPv4 Only

The DNS filter only handles IPv4. IPv6 DNS packets
are dropped at the BPF level. This was a deliberate
simplification; IPv6 DNS could be added but would
roughly double the filter length.

### VLAN-Tagged Frames

802.1Q VLAN-tagged frames (`EtherType 0x8100`) shift
all offsets by 4 bytes and are not handled. Both the
BPF filter and the parser will silently reject them.

### No Fragmented DNS

The DNS filter rejects IP fragments. A DNS response
split across multiple fragments will be lost. In
practice, DNS responses exceeding the path MTU
typically use TCP or EDNS0 with a smaller UDP payload.

---

## 12. Pitfalls Encountered

### 1. BpfHdr Size on macOS

The `bpf_hdr` struct is 32 bytes on macOS, not 18
bytes as documented in some BSD references. This is
because macOS uses 64-bit `timeval`
(`{i64, i64}` = 16 bytes) even on 32-bit builds. The
compile-time assertion
`assert!(size_of::<BpfHdr>() == 32)` catches this.

### 2. bpf_program Struct Alignment

The `bpf_program` FFI struct (for `BIOCSETF`) needs
explicit padding on 64-bit:

```rust
#[repr(C)]
struct bpf_program {
    bf_len:   u32,
    _pad:     u32,        // for pointer alignment
    bf_insns: *mut bpf_insn,
}
```

Without `_pad`, the pointer would be at offset 4
(misaligned on 64-bit), causing `BIOCSETF` to read
garbage.

### 3. BPF Jump Offset Calculation

BPF jump offsets are relative to `PC + 1`, not to the
current instruction. This is the most common source
of errors when writing filters by hand. Example:

```text
At PC=4: jeq #17 jt=4 jf=5
  jt target = (4+1) + 4 = 9
  jf target = (4+1) + 5 = 10
```

Every jump in both filters was manually verified
against the target instruction index.

### 4. BPF_WORDALIGN vs bh_hdrlen

The packet data starts at `offset + bh_hdrlen`, and
the next record starts at
`offset + BPF_WORDALIGN(bh_hdrlen + bh_caplen)`.
Using `sizeof(BpfHdr)` instead of `bh_hdrlen` would
be wrong because `bh_hdrlen` includes padding between
the header and packet data that may vary.

### 5. IPv6 Extension Header Chaining

Each extension header's first byte is the Next Header
field pointing to the next header in the chain. When
building test packets with multiple extension headers,
the chaining must be done correctly: the last
extension header's Next Header points to the L4
protocol, and each preceding header points to the
next extension header's type.

The `PacketBuilder` handles this automatically:

```rust
for i in 0..ext_headers.len() {
    let next = if i + 1 < ext_headers.len() {
        ext_headers[i + 1].0 // next ext hdr type
    } else {
        self.l4_proto         // final: L4 proto
    };
    ext_headers[i].1[0] = next;
}
```

### 6. Fragment Header Fixed Size

Unlike other IPv6 extension headers whose size is
`(hdr_ext_len + 1) * 8`, the Fragment header is always
exactly 8 bytes. Using the generic size formula on a
Fragment header would read the fragment offset/flags
field as a length, computing a wildly wrong size.

### 7. read_unaligned for BpfHdr

BPF records in the buffer are 4-byte aligned (via
`BPF_WORDALIGN`), but `BpfHdr` contains `timeval`
which requires 8-byte alignment. Using a direct
pointer cast and dereference would be undefined
behavior. Always use `std::ptr::read_unaligned`.

### 8. DNS TCP Length Prefix

DNS over TCP prepends a 2-byte length prefix to the
DNS message (RFC 1035 Section 4.2.2). The
`extract_dns_payload()` function must skip these 2
bytes before passing data to `parse_dns()`. Missing
this causes the parser to interpret the length bytes
as the transaction ID, corrupting the entire parse.

### 9. Read Timeout for Graceful Shutdown

Without `BIOCSRTIMEOUT`, a `read()` on the BPF device
blocks indefinitely until a packet arrives. With
capture threads blocked in `read()`, the process cannot
shut down cleanly on `SIGTERM`/`SIGINT`. The 500ms
timeout causes `read()` to return periodically with
`n == 0`, allowing threads to check the
`SHUTDOWN_REQUESTED` flag and exit.
