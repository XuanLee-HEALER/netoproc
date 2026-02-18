//! BPF filter program construction.
//!
//! Provides functions to build classic BPF instruction programs (as `Vec<bpf_insn>`)
//! for use with the macOS `BIOCSETF` ioctl. Two filters are provided:
//!
//! - [`traffic_filter`]: Accepts all IPv4 and IPv6 packets (for general traffic monitoring).
//! - [`dns_filter`]: Accepts only UDP/TCP packets with source or destination port 53.

// ---------------------------------------------------------------------------
// FFI type: BPF instruction
// ---------------------------------------------------------------------------

/// A single classic BPF instruction, matching the kernel `struct bpf_insn`.
///
/// The layout is:
/// - `code` (u16): opcode composed of class | size | mode
/// - `jt`   (u8):  jump-true offset (relative, for conditional jumps)
/// - `jf`   (u8):  jump-false offset (relative, for conditional jumps)
/// - `k`    (u32): generic constant (immediate value, memory offset, etc.)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct bpf_insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Compile-time size assertion: bpf_insn must be exactly 8 bytes.
const _: () = assert!(std::mem::size_of::<bpf_insn>() == 8);

// ---------------------------------------------------------------------------
// BPF instruction constants (classic BPF, same on macOS)
// ---------------------------------------------------------------------------

// Instruction classes
const BPF_LD: u16 = 0x00;
#[allow(dead_code)]
const BPF_LDX: u16 = 0x01;
#[allow(dead_code)]
const BPF_ST: u16 = 0x02;
#[allow(dead_code)]
const BPF_STX: u16 = 0x03;
#[allow(dead_code)]
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
#[allow(dead_code)]
const BPF_MISC: u16 = 0x07;

// LD/LDX sizes
#[allow(dead_code)]
const BPF_W: u16 = 0x00; // word (32-bit)
const BPF_H: u16 = 0x08; // half-word (16-bit)
const BPF_B: u16 = 0x10; // byte

// LD/LDX modes
const BPF_ABS: u16 = 0x20; // absolute offset into packet
const BPF_IND: u16 = 0x40; // indirect offset (X + k)
#[allow(dead_code)]
const BPF_MEM: u16 = 0x60; // scratch memory load
#[allow(dead_code)]
const BPF_IMM: u16 = 0x00; // immediate value (for LDX)
const BPF_MSH: u16 = 0xa0; // IP header length hack: 4*(data[k] & 0xf)

// JMP operations
#[allow(dead_code)]
const BPF_JA: u16 = 0x00; // unconditional jump
const BPF_JEQ: u16 = 0x10; // jump if A == k
#[allow(dead_code)]
const BPF_JGT: u16 = 0x20; // jump if A > k
const BPF_JSET: u16 = 0x40; // jump if A & k != 0

// Operand source
const BPF_K: u16 = 0x00; // constant operand

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Construct a single `bpf_insn` with the given fields.
fn insn(code: u16, jt: u8, jf: u8, k: u32) -> bpf_insn {
    bpf_insn { code, jt, jf, k }
}

// ---------------------------------------------------------------------------
// Public filter constructors
// ---------------------------------------------------------------------------

/// Build a BPF program that accepts IPv4/IPv6 packets carrying TCP or UDP,
/// rejecting everything else (ICMP, OSPF, ARP, etc.).
///
/// Note: The IPv4 protocol check at offset 23 assumes no IP options (standard
/// 20-byte header). Packets with IP options may have the protocol byte at a
/// different offset, but BPF classic does not support variable-offset loads
/// without LDX+MSH. Since IP options are extremely rare in practice and such
/// packets would still be parsed correctly by the userspace parser (just not
/// filtered at the BPF level), this is an acceptable trade-off.
///
/// Equivalent pseudo-assembly:
/// ```text
///   [0]  ldh  [12]              ; EtherType
///   [1]  jeq  #0x0800  jt=0 jf=3  ; IPv4 → [2], else → [5]
///   [2]  ldb  [23]              ; IPv4 protocol (offset 14+9=23)
///   [3]  jeq  #6      jt=5 jf=0  ; TCP → [9] accept, else → [4]
///   [4]  jeq  #17     jt=4 jf=5  ; UDP → [9] accept, else → [10] drop
///   [5]  jeq  #0x86DD jt=0 jf=4  ; IPv6 → [6], else → [10] drop
///   [6]  ldb  [20]              ; IPv6 Next Header (offset 14+6=20)
///   [7]  jeq  #6      jt=1 jf=0  ; TCP → [9] accept, else → [8]
///   [8]  jeq  #17     jt=0 jf=1  ; UDP → [9] accept, else → [10] drop
///   [9]  ret  #65535            ; accept
///   [10] ret  #0                ; drop
/// ```
pub fn traffic_filter() -> Vec<bpf_insn> {
    vec![
        // [0] Load EtherType
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
        // [1] IPv4? fall through to [2]; else jump +3 to [5]
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x0800),
        // [2] Load IPv4 protocol byte (offset 14+9=23)
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23),
        // [3] TCP(6)? jump +5 to [9] accept; else fall to [4]
        insn(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 6),
        // [4] UDP(17)? jump +4 to [9] accept; else jump +5 to [10] drop
        insn(BPF_JMP | BPF_JEQ | BPF_K, 4, 5, 17),
        // [5] IPv6? fall through to [6]; else jump +4 to [10] drop
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, 0x86DD),
        // [6] Load IPv6 Next Header (offset 14+6=20)
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 20),
        // [7] TCP(6)? jump +1 to [9] accept; else fall to [8]
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 6),
        // [8] UDP(17)? jump +0 to [9] accept; else jump +1 to [10] drop
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 17),
        // [9] Accept — return snaplen
        insn(BPF_RET | BPF_K, 0, 0, 65535),
        // [10] Drop — return 0
        insn(BPF_RET | BPF_K, 0, 0, 0),
    ]
}

/// Build a BPF program that accepts IPv4 UDP or TCP packets where either the
/// source port or the destination port is 53 (DNS).
///
/// The filter correctly handles variable-length IPv4 headers by using the
/// `BPF_MSH` instruction to compute `4 * (packet[14] & 0x0f)` and store the
/// result in the X register. TCP/UDP port offsets are then addressed as
/// `[X + 14]` (source port) and `[X + 16]` (destination port), where 14 is
/// the Ethernet header length.
///
/// Accepted packets get a snap length of 512 bytes (sufficient for most DNS
/// messages). Non-matching packets are rejected with a return value of 0.
///
/// Equivalent pseudo-assembly:
/// ```text
///   [0]  ldh  [12]                    ; EtherType
///   [1]  jeq  #0x0800, +0, drop       ; IPv4? else drop
///   [2]  ldb  [23]                    ; IP protocol byte
///   [3]  jeq  #17, udp_frag, +0       ; UDP?
///   [4]  jeq  #6, ports, drop         ; TCP? else drop
///   [5]  ldh  [20]                    ; IP flags + fragment offset
///   [6]  jset #0x1FFF, drop, +0       ; fragment? drop if yes
///   [7]  ldx  4*([14]&0xf)            ; X = IP header length
///   [8]  ldh  [x+14]                  ; src port
///   [9]  jeq  #53, accept, +0         ; DNS src?
///   [10] ldh  [x+16]                  ; dst port
///   [11] jeq  #53, accept, drop       ; DNS dst?
///   [12] ret  #512                    ; accept
///   [13] ret  #0                      ; drop
/// ```
pub fn dns_filter() -> Vec<bpf_insn> {
    // Instruction indices (for computing jump offsets):
    //  0: ldh [12]
    //  1: jeq 0x0800
    //  2: ldb [23]
    //  3: jeq 17 (UDP)
    //  4: jeq 6 (TCP)
    //  5: ldh [20]          -- UDP fragment check
    //  6: jset 0x1FFF       -- fragment offset test
    //  7: ldx 4*([14]&0xf)  -- load IP header length
    //  8: ldh [x+14]        -- src port
    //  9: jeq 53 (src)
    // 10: ldh [x+16]        -- dst port
    // 11: jeq 53 (dst)
    // 12: ret #512          -- accept
    // 13: ret #0            -- drop

    vec![
        // [0] Load EtherType
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
        // [1] If EtherType == 0x0800 (IPv4), continue; else drop
        //     jt = 0 (fall through to [2]), jf = 11 (jump to [13] drop)
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 11, 0x0800),
        // [2] Load IP protocol (byte at offset 23 = 14 eth + 9 protocol field)
        insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23),
        // [3] If protocol == 17 (UDP), jump to fragment check [5]; else check TCP
        //     jt = 1 (jump to [5]), jf = 0 (fall through to [4])
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 17),
        // [4] If protocol == 6 (TCP), jump to port check [7]; else drop
        //     jt = 2 (jump to [7]), jf = 8 (jump to [13] drop)
        insn(BPF_JMP | BPF_JEQ | BPF_K, 2, 8, 6),
        // [5] Load IP flags + fragment offset (half-word at offset 20 = 14 + 6)
        insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 20),
        // [6] If fragment offset bits are set (A & 0x1FFF != 0), drop; else continue
        //     jt = 6 (jump to [13] drop), jf = 0 (fall through to [7])
        insn(BPF_JMP | BPF_JSET | BPF_K, 6, 0, 0x1FFF),
        // [7] Load IP header length into X: X = 4 * (packet[14] & 0x0f)
        insn(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 14),
        // [8] Load source port: half-word at [X + 14]
        insn(BPF_LD | BPF_H | BPF_IND, 0, 0, 14),
        // [9] If src port == 53, accept; else check dst port
        //     jt = 2 (jump to [12] accept), jf = 0 (fall through to [10])
        insn(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 53),
        // [10] Load destination port: half-word at [X + 16]
        insn(BPF_LD | BPF_H | BPF_IND, 0, 0, 16),
        // [11] If dst port == 53, accept; else drop
        //     jt = 0 (jump to [12] accept), jf = 1 (jump to [13] drop)
        insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 53),
        // [12] Accept — capture up to 512 bytes
        insn(BPF_RET | BPF_K, 0, 0, 512),
        // [13] Drop
        insn(BPF_RET | BPF_K, 0, 0, 0),
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal BPF virtual machine for filter simulation
    // -----------------------------------------------------------------------

    /// Execute a classic BPF filter program against a packet byte slice.
    ///
    /// Returns the value from the `RET` instruction:
    /// - 0 means the packet is rejected.
    /// - A positive value means the packet is accepted (the value is the
    ///   snap length, i.e. how many bytes to capture).
    ///
    /// The VM supports the instruction subset used by [`traffic_filter`] and
    /// [`dns_filter`]: LD (ABS, IND, MEM, IMM), LDX (IMM, MSH, MEM),
    /// ST, STX, JMP (JA, JEQ, JGT, JSET with K), and RET.
    fn execute_filter(program: &[bpf_insn], packet: &[u8]) -> u32 {
        let mut a: u32 = 0; // accumulator
        let mut x: u32 = 0; // index register
        let mut mem: [u32; 16] = [0; 16]; // scratch memory
        let mut pc: usize = 0;

        while pc < program.len() {
            let inst = program[pc];
            let class = inst.code & 0x07;
            let size = inst.code & 0x18;
            let mode = inst.code & 0xe0;

            match class {
                // LD — load into accumulator
                0x00 => {
                    // BPF_LD
                    match mode {
                        0x20 => {
                            // BPF_ABS — load from packet at absolute offset k
                            let off = inst.k as usize;
                            a = match size {
                                0x00 => {
                                    // BPF_W — 32-bit
                                    if off + 4 > packet.len() {
                                        return 0;
                                    }
                                    u32::from_be_bytes([
                                        packet[off],
                                        packet[off + 1],
                                        packet[off + 2],
                                        packet[off + 3],
                                    ])
                                }
                                0x08 => {
                                    // BPF_H — 16-bit
                                    if off + 2 > packet.len() {
                                        return 0;
                                    }
                                    u16::from_be_bytes([packet[off], packet[off + 1]]) as u32
                                }
                                0x10 => {
                                    // BPF_B — 8-bit
                                    if off >= packet.len() {
                                        return 0;
                                    }
                                    packet[off] as u32
                                }
                                _ => return 0,
                            };
                        }
                        0x40 => {
                            // BPF_IND — load from packet at offset X + k
                            let off = (x + inst.k) as usize;
                            a = match size {
                                0x00 => {
                                    if off + 4 > packet.len() {
                                        return 0;
                                    }
                                    u32::from_be_bytes([
                                        packet[off],
                                        packet[off + 1],
                                        packet[off + 2],
                                        packet[off + 3],
                                    ])
                                }
                                0x08 => {
                                    if off + 2 > packet.len() {
                                        return 0;
                                    }
                                    u16::from_be_bytes([packet[off], packet[off + 1]]) as u32
                                }
                                0x10 => {
                                    if off >= packet.len() {
                                        return 0;
                                    }
                                    packet[off] as u32
                                }
                                _ => return 0,
                            };
                        }
                        0x60 => {
                            // BPF_MEM — load from scratch memory
                            let idx = (inst.k as usize) & 0x0f;
                            a = mem[idx];
                        }
                        0x00 => {
                            // BPF_IMM — load immediate
                            a = inst.k;
                        }
                        _ => return 0,
                    }
                }
                // LDX — load into X register
                0x01 => {
                    match mode {
                        0x00 => {
                            // BPF_IMM
                            x = inst.k;
                        }
                        0xa0 => {
                            // BPF_MSH — x = 4 * (packet[k] & 0x0f)
                            let off = inst.k as usize;
                            if off >= packet.len() {
                                return 0;
                            }
                            x = ((packet[off] & 0x0f) as u32) * 4;
                        }
                        0x60 => {
                            // BPF_MEM
                            let idx = (inst.k as usize) & 0x0f;
                            x = mem[idx];
                        }
                        _ => return 0,
                    }
                }
                // ST — store A to scratch memory
                0x02 => {
                    let idx = (inst.k as usize) & 0x0f;
                    mem[idx] = a;
                }
                // STX — store X to scratch memory
                0x03 => {
                    let idx = (inst.k as usize) & 0x0f;
                    mem[idx] = x;
                }
                // ALU
                0x04 => {
                    let src = if inst.code & 0x08 != 0 { x } else { inst.k };
                    let op = inst.code & 0xf0;
                    a = match op {
                        0x00 => a.wrapping_add(src), // ADD
                        0x10 => a.wrapping_sub(src), // SUB
                        0x20 => a.wrapping_mul(src), // MUL
                        0x30 => {
                            if src == 0 {
                                return 0;
                            }
                            a / src
                        } // DIV
                        0x40 => a | src,             // OR
                        0x50 => a & src,             // AND
                        0x60 => a << src,            // LSH
                        0x70 => a >> src,            // RSH
                        0x80 => {
                            // NEG (unary)
                            (-(a as i32)) as u32
                        }
                        _ => return 0,
                    };
                }
                // JMP
                0x05 => {
                    let op = inst.code & 0xf0;
                    match op {
                        0x00 => {
                            // BPF_JA — unconditional jump forward by k instructions.
                            // Semantics: new_pc = current_pc + 1 + k.
                            // Since pc += 1 happens at end of loop, we add k here.
                            pc += inst.k as usize;
                        }
                        0x10 => {
                            // BPF_JEQ
                            let cmp = if inst.code & 0x08 != 0 { x } else { inst.k };
                            if a == cmp {
                                pc += inst.jt as usize;
                            } else {
                                pc += inst.jf as usize;
                            }
                        }
                        0x20 => {
                            // BPF_JGT
                            let cmp = if inst.code & 0x08 != 0 { x } else { inst.k };
                            if a > cmp {
                                pc += inst.jt as usize;
                            } else {
                                pc += inst.jf as usize;
                            }
                        }
                        0x30 => {
                            // BPF_JGE
                            let cmp = if inst.code & 0x08 != 0 { x } else { inst.k };
                            if a >= cmp {
                                pc += inst.jt as usize;
                            } else {
                                pc += inst.jf as usize;
                            }
                        }
                        0x40 => {
                            // BPF_JSET
                            let cmp = if inst.code & 0x08 != 0 { x } else { inst.k };
                            if a & cmp != 0 {
                                pc += inst.jt as usize;
                            } else {
                                pc += inst.jf as usize;
                            }
                        }
                        _ => return 0,
                    }
                }
                // RET
                0x06 => {
                    // BPF_K: return constant; BPF_A (0x10): return accumulator
                    if inst.code & 0x18 == 0x10 {
                        return a;
                    }
                    return inst.k;
                }
                // MISC
                0x07 => {
                    let misc_op = inst.code & 0xf8;
                    match misc_op {
                        0x00 => x = a, // TAX: transfer A to X
                        0x80 => a = x, // TXA: transfer X to A
                        _ => return 0,
                    }
                }
                _ => return 0,
            }
            pc += 1;
        }
        // Fell off the end without a RET — reject.
        0
    }

    // -----------------------------------------------------------------------
    // Packet construction helpers
    // -----------------------------------------------------------------------

    /// Build a minimal Ethernet frame with the given EtherType and payload.
    fn build_ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(14 + payload.len());
        // Destination MAC (6 bytes)
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Source MAC (6 bytes)
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        // EtherType (2 bytes, big-endian)
        pkt.extend_from_slice(&ethertype.to_be_bytes());
        // Payload
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build a minimal IPv4 header (20 bytes, no options) with the given
    /// protocol number. The total length field is set to `20 + payload.len()`.
    fn build_ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + payload.len()) as u16;
        let mut hdr = Vec::with_capacity(20 + payload.len());
        // Version (4) + IHL (5) = 0x45
        hdr.push(0x45);
        // DSCP / ECN
        hdr.push(0x00);
        // Total length
        hdr.extend_from_slice(&total_len.to_be_bytes());
        // Identification
        hdr.extend_from_slice(&[0x00, 0x01]);
        // Flags (0) + Fragment offset (0)
        hdr.extend_from_slice(&[0x00, 0x00]);
        // TTL
        hdr.push(64);
        // Protocol
        hdr.push(protocol);
        // Header checksum (0 = not computed; fine for filter testing)
        hdr.extend_from_slice(&[0x00, 0x00]);
        // Source IP
        hdr.extend_from_slice(&src);
        // Destination IP
        hdr.extend_from_slice(&dst);
        // Payload (L4 header + data)
        hdr.extend_from_slice(payload);
        hdr
    }

    /// Build a minimal IPv4 header with IP options.
    /// `ihl` is the IHL value (5..=15). Options are zero-padded.
    fn build_ipv4_with_options(
        protocol: u8,
        src: [u8; 4],
        dst: [u8; 4],
        ihl: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let hdr_len = (ihl as usize) * 4;
        let total_len = (hdr_len + payload.len()) as u16;
        let mut hdr = Vec::with_capacity(hdr_len + payload.len());
        // Version (4) + IHL
        hdr.push(0x40 | (ihl & 0x0f));
        // DSCP / ECN
        hdr.push(0x00);
        // Total length
        hdr.extend_from_slice(&total_len.to_be_bytes());
        // Identification
        hdr.extend_from_slice(&[0x00, 0x01]);
        // Flags (0) + Fragment offset (0)
        hdr.extend_from_slice(&[0x00, 0x00]);
        // TTL
        hdr.push(64);
        // Protocol
        hdr.push(protocol);
        // Header checksum
        hdr.extend_from_slice(&[0x00, 0x00]);
        // Source IP
        hdr.extend_from_slice(&src);
        // Destination IP
        hdr.extend_from_slice(&dst);
        // Options (zero-padded to fill IHL * 4 - 20 bytes)
        let options_len = hdr_len - 20;
        hdr.extend(std::iter::repeat(0u8).take(options_len));
        // Payload
        hdr.extend_from_slice(payload);
        hdr
    }

    /// Build a minimal UDP header (8 bytes) with the given ports.
    fn build_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()) as u16;
        let mut hdr = Vec::with_capacity(8 + payload.len());
        hdr.extend_from_slice(&src_port.to_be_bytes());
        hdr.extend_from_slice(&dst_port.to_be_bytes());
        hdr.extend_from_slice(&length.to_be_bytes());
        // Checksum (0 = not computed)
        hdr.extend_from_slice(&[0x00, 0x00]);
        hdr.extend_from_slice(payload);
        hdr
    }

    /// Build a minimal TCP header (20 bytes, no options) with the given ports.
    fn build_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        // Data offset: 5 (20 bytes / 4), in upper nibble of byte 12
        hdr[12] = 0x50;
        hdr
    }

    /// Build a complete Ethernet + IPv4 + TCP packet.
    fn build_ipv4_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let tcp = build_tcp(src_port, dst_port);
        let ip = build_ipv4(6, src_ip, dst_ip, &tcp);
        build_ethernet(0x0800, &ip)
    }

    /// Build a complete Ethernet + IPv4 + UDP packet.
    fn build_ipv4_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let udp = build_udp(src_port, dst_port, &[]);
        let ip = build_ipv4(17, src_ip, dst_ip, &udp);
        build_ethernet(0x0800, &ip)
    }

    /// Build a minimal Ethernet + IPv6 packet with an arbitrary next header/protocol.
    fn build_ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let payload_len = payload.len() as u16;
        let mut ipv6 = Vec::with_capacity(40 + payload.len());
        ipv6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        ipv6.extend_from_slice(&payload_len.to_be_bytes());
        ipv6.push(next_header);
        ipv6.push(64);
        // Source address (::1)
        ipv6.extend_from_slice(&[0; 15]);
        ipv6.push(1);
        // Destination address (::2)
        ipv6.extend_from_slice(&[0; 15]);
        ipv6.push(2);
        ipv6.extend_from_slice(payload);
        build_ethernet(0x86DD, &ipv6)
    }

    /// Build a minimal Ethernet + IPv6 + TCP packet.
    fn build_ipv6_tcp_packet() -> Vec<u8> {
        let tcp = build_tcp(12345, 443);
        let payload_len = tcp.len() as u16;
        let mut ipv6 = Vec::with_capacity(40 + tcp.len());
        // Version (6) + traffic class + flow label
        ipv6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        // Payload length
        ipv6.extend_from_slice(&payload_len.to_be_bytes());
        // Next header (6 = TCP)
        ipv6.push(6);
        // Hop limit
        ipv6.push(64);
        // Source address (::1)
        ipv6.extend_from_slice(&[0; 15]);
        ipv6.push(1);
        // Destination address (::2)
        ipv6.extend_from_slice(&[0; 15]);
        ipv6.push(2);
        // TCP payload
        ipv6.extend_from_slice(&tcp);
        build_ethernet(0x86DD, &ipv6)
    }

    /// Build a minimal ARP packet.
    fn build_arp_packet() -> Vec<u8> {
        // ARP is EtherType 0x0806. The content does not matter for filter testing.
        let arp_payload = vec![0u8; 28]; // minimal ARP is 28 bytes
        build_ethernet(0x0806, &arp_payload)
    }

    // -----------------------------------------------------------------------
    // UT-3.1: Traffic filter returns non-empty Vec
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_1_traffic_filter_non_empty() {
        let filter = traffic_filter();
        assert!(!filter.is_empty());
        assert!(filter.len() <= 4096, "filter exceeds BPF_MAXINSNS (4096)");
    }

    // -----------------------------------------------------------------------
    // UT-3.2: DNS filter returns valid instructions, last is ret
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_2_dns_filter_valid_instructions_last_is_ret() {
        let filter = dns_filter();
        assert!(!filter.is_empty());
        assert!(filter.len() <= 4096, "filter exceeds BPF_MAXINSNS (4096)");

        // Last instruction must be a RET
        let last = filter.last().unwrap();
        assert_eq!(last.code & 0x07, BPF_RET, "last instruction must be a RET");
    }

    // -----------------------------------------------------------------------
    // UT-3.3: Traffic filter accepts IPv4
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_3_traffic_filter_accepts_ipv4() {
        let filter = traffic_filter();
        let pkt = build_ipv4_tcp_packet([192, 168, 1, 1], [93, 184, 216, 34], 54321, 443);
        let result = execute_filter(&filter, &pkt);
        assert!(
            result > 0,
            "traffic filter must accept IPv4 packets, got ret={result}"
        );
        assert_eq!(result, 65535);
    }

    // -----------------------------------------------------------------------
    // UT-3.4: Traffic filter accepts IPv6
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_4_traffic_filter_accepts_ipv6() {
        let filter = traffic_filter();
        let pkt = build_ipv6_tcp_packet();
        let result = execute_filter(&filter, &pkt);
        assert!(
            result > 0,
            "traffic filter must accept IPv6 packets, got ret={result}"
        );
        assert_eq!(result, 65535);
    }

    // -----------------------------------------------------------------------
    // UT-3.5: Traffic filter rejects ARP
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_5_traffic_filter_rejects_arp() {
        let filter = traffic_filter();
        let pkt = build_arp_packet();
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "traffic filter must reject ARP packets");
    }

    // -----------------------------------------------------------------------
    // UT-3.6: DNS filter accepts UDP port 53 (dst)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_6_dns_filter_accepts_udp_dst_53() {
        let filter = dns_filter();
        let pkt = build_ipv4_udp_packet([10, 0, 0, 1], [8, 8, 8, 8], 51234, 53);
        let result = execute_filter(&filter, &pkt);
        assert!(
            result > 0,
            "DNS filter must accept UDP dst=53, got ret={result}"
        );
        assert_eq!(result, 512);
    }

    // -----------------------------------------------------------------------
    // UT-3.7: DNS filter accepts UDP port 53 (src)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_7_dns_filter_accepts_udp_src_53() {
        let filter = dns_filter();
        let pkt = build_ipv4_udp_packet([8, 8, 8, 8], [10, 0, 0, 1], 53, 51234);
        let result = execute_filter(&filter, &pkt);
        assert!(
            result > 0,
            "DNS filter must accept UDP src=53, got ret={result}"
        );
        assert_eq!(result, 512);
    }

    // -----------------------------------------------------------------------
    // UT-3.8: DNS filter rejects UDP port 80
    // -----------------------------------------------------------------------
    #[test]
    fn ut_3_8_dns_filter_rejects_udp_port_80() {
        let filter = dns_filter();
        let pkt = build_ipv4_udp_packet([10, 0, 0, 1], [93, 184, 216, 34], 54321, 80);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "DNS filter must reject UDP with port 80");
    }

    // -----------------------------------------------------------------------
    // Additional filter tests (beyond the required UT-3.x)
    // -----------------------------------------------------------------------

    #[test]
    fn dns_filter_accepts_tcp_dst_53() {
        let filter = dns_filter();
        let tcp = build_tcp(51234, 53);
        let ip = build_ipv4(6, [10, 0, 0, 1], [8, 8, 8, 8], &tcp);
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 512, "DNS filter must accept TCP dst=53");
    }

    #[test]
    fn dns_filter_accepts_tcp_src_53() {
        let filter = dns_filter();
        let tcp = build_tcp(53, 51234);
        let ip = build_ipv4(6, [8, 8, 8, 8], [10, 0, 0, 1], &tcp);
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 512, "DNS filter must accept TCP src=53");
    }

    #[test]
    fn dns_filter_rejects_non_ipv4() {
        let filter = dns_filter();
        // IPv6 packet — the DNS filter only handles IPv4 per design
        let pkt = build_ipv6_tcp_packet();
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "DNS filter must reject non-IPv4 packets");
    }

    #[test]
    fn dns_filter_rejects_icmp() {
        let filter = dns_filter();
        // ICMP (protocol 1) is neither UDP (17) nor TCP (6)
        let icmp_payload = vec![0u8; 8]; // minimal ICMP header
        let ip = build_ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &icmp_payload);
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "DNS filter must reject ICMP packets");
    }

    #[test]
    fn dns_filter_rejects_ip_fragment() {
        let filter = dns_filter();
        // Build a UDP packet but set the fragment offset to a non-zero value.
        let udp = build_udp(53, 51234, &[]);
        let mut ip = build_ipv4(17, [8, 8, 8, 8], [10, 0, 0, 1], &udp);
        // The flags+fragment offset field is at IP header bytes [6..8].
        // Set fragment offset to 100 (any non-zero value triggers reject).
        ip[6] = 0x00;
        ip[7] = 0x64; // fragment offset = 100
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "DNS filter must reject IP fragments");
    }

    #[test]
    fn dns_filter_handles_ip_options() {
        let filter = dns_filter();
        // Build an IPv4 packet with IHL=6 (24-byte IP header, 4 bytes of options)
        // containing a UDP segment with dst port 53.
        let udp = build_udp(51234, 53, &[]);
        let ip = build_ipv4_with_options(17, [10, 0, 0, 1], [8, 8, 8, 8], 6, &udp);
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(
            result, 512,
            "DNS filter must handle variable IP header length (IHL=6)"
        );
    }

    // -----------------------------------------------------------------------
    // Traffic filter: accepts IPv4 UDP
    // -----------------------------------------------------------------------
    #[test]
    fn ut_traffic_filter_accepts_ipv4_udp() {
        let filter = traffic_filter();
        let pkt = build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 65535, "traffic filter must accept IPv4 UDP");
    }

    // -----------------------------------------------------------------------
    // Traffic filter: accepts IPv6 UDP
    // -----------------------------------------------------------------------
    #[test]
    fn ut_traffic_filter_accepts_ipv6_udp() {
        let filter = traffic_filter();
        let pkt = build_ipv6_packet(17, &build_udp(5353, 5353, &[]));
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 65535, "traffic filter must accept IPv6 UDP");
    }

    // -----------------------------------------------------------------------
    // Traffic filter: rejects ICMP (IPv4, protocol 1)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_traffic_filter_rejects_icmp() {
        let filter = traffic_filter();
        let icmp_payload = vec![0u8; 8];
        let ip = build_ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &icmp_payload);
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "traffic filter must reject ICMP packets");
    }

    // -----------------------------------------------------------------------
    // Traffic filter: rejects OSPF (IPv4, protocol 89)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_traffic_filter_rejects_ospf() {
        let filter = traffic_filter();
        let ospf_payload = vec![0u8; 24];
        let ip = build_ipv4(89, [10, 0, 0, 1], [10, 0, 0, 2], &ospf_payload);
        let pkt = build_ethernet(0x0800, &ip);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "traffic filter must reject OSPF packets");
    }

    // -----------------------------------------------------------------------
    // Traffic filter: rejects ICMPv6 (IPv6, next_hdr=58)
    // -----------------------------------------------------------------------
    #[test]
    fn ut_traffic_filter_rejects_ipv6_icmpv6() {
        let filter = traffic_filter();
        let icmpv6_payload = vec![0u8; 8];
        let pkt = build_ipv6_packet(58, &icmpv6_payload);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "traffic filter must reject ICMPv6 packets");
    }

    #[test]
    fn traffic_filter_rejects_random_ethertype() {
        let filter = traffic_filter();
        let pkt = build_ethernet(0x1234, &[0u8; 20]);
        let result = execute_filter(&filter, &pkt);
        assert_eq!(result, 0, "traffic filter must reject unknown EtherType");
    }

    #[test]
    fn bpf_insn_size_is_8_bytes() {
        assert_eq!(std::mem::size_of::<bpf_insn>(), 8);
    }

    #[test]
    fn bpf_insn_alignment() {
        // Alignment should be at most 4 bytes (u32 is the largest field after packing)
        assert!(std::mem::align_of::<bpf_insn>() <= 4);
    }

    #[test]
    fn insn_helper_constructs_correctly() {
        let i = insn(0x1234, 5, 6, 0x789ABCDE);
        assert_eq!(i.code, 0x1234);
        assert_eq!(i.jt, 5);
        assert_eq!(i.jf, 6);
        assert_eq!(i.k, 0x789ABCDE);
    }
}
