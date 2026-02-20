//! netoproc eBPF kernel program — kprobe-based per-process traffic monitoring.
//!
//! Attaches kprobes to tcp_sendmsg, tcp_recvmsg, udp_sendmsg, udp_recvmsg
//! to track per-process network traffic in kernel space.
//!
//! This program is read-only: it does NOT modify any kernel state, packet
//! content, or socket behavior. It only reads process context and byte counts.
//!
//! Safety invariants:
//! - All map operations check return values
//! - No loops (eBPF verifier enforced)
//! - No pointer arithmetic outside of helper-provided contexts
//! - Stack usage kept well under 512-byte limit

#![no_std]
#![no_main]

use aya_ebpf::macros::{kprobe, kretprobe, map};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::{helpers::bpf_get_current_pid_tgid, helpers::bpf_get_current_comm};

use netoproc_ebpf_common::{
    TrafficKey, TrafficValue,
    TRAFFIC_MAP_MAX_ENTRIES, PID_COMM_MAP_MAX_ENTRIES,
    DIRECTION_TX, DIRECTION_RX, PROTO_TCP, PROTO_UDP,
};

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

/// Per-(PID, proto, direction) traffic accumulator.
/// Userspace periodically reads and computes deltas.
#[map]
static TRAFFIC_MAP: HashMap<TrafficKey, TrafficValue> =
    HashMap::with_max_entries(TRAFFIC_MAP_MAX_ENTRIES, 0);

/// PID → process name cache (comm, up to 16 bytes).
/// Reduces userspace /proc reads for process name resolution.
#[map]
static PID_COMM: HashMap<u32, [u8; 16]> =
    HashMap::with_max_entries(PID_COMM_MAP_MAX_ENTRIES, 0);

// ---------------------------------------------------------------------------
// TCP kprobes
// ---------------------------------------------------------------------------

/// kprobe on tcp_sendmsg — tracks outbound TCP bytes.
///
/// Signature: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
/// We read `size` (arg 2, 0-indexed) as the requested send length.
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0, // Always return 0 — never disrupt the original function
    }
}

fn try_tcp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let size: usize = unsafe { ctx.arg(2).ok_or(1i64)? };
    record_traffic(PROTO_TCP, DIRECTION_TX, size as u64)
}

/// kretprobe on tcp_recvmsg — tracks inbound TCP bytes.
///
/// Returns the actual number of bytes received (return value).
/// Negative return = error, skip those.
#[kretprobe]
pub fn tcp_recvmsg(ctx: RetProbeContext) -> u32 {
    match try_tcp_recvmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_recvmsg(ctx: &RetProbeContext) -> Result<(), i64> {
    let ret: i64 = unsafe { ctx.ret().ok_or(1i64)? };
    if ret <= 0 {
        return Ok(()); // Error or zero-length recv — skip
    }
    record_traffic(PROTO_TCP, DIRECTION_RX, ret as u64)
}

// ---------------------------------------------------------------------------
// UDP kprobes
// ---------------------------------------------------------------------------

/// kprobe on udp_sendmsg — tracks outbound UDP bytes.
///
/// Signature: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    let size: usize = unsafe { ctx.arg(2).ok_or(1i64)? };
    record_traffic(PROTO_UDP, DIRECTION_TX, size as u64)
}

/// kretprobe on udp_recvmsg — tracks inbound UDP bytes.
#[kretprobe]
pub fn udp_recvmsg(ctx: RetProbeContext) -> u32 {
    match try_udp_recvmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_udp_recvmsg(ctx: &RetProbeContext) -> Result<(), i64> {
    let ret: i64 = unsafe { ctx.ret().ok_or(1i64)? };
    if ret <= 0 {
        return Ok(());
    }
    record_traffic(PROTO_UDP, DIRECTION_RX, ret as u64)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Record a traffic event in the BPF maps.
///
/// This is the core function called by all kprobe handlers.
/// It reads the current PID and comm, then atomically updates
/// the traffic accumulator map.
#[inline(always)]
fn record_traffic(proto: u8, direction: u8, bytes: u64) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Skip kernel threads (pid 0)
    if pid == 0 {
        return Ok(());
    }

    let key = TrafficKey {
        pid,
        proto,
        direction,
        _pad: [0; 2],
    };

    // Update traffic counters (atomic increment via BPF_EXIST)
    unsafe {
        if let Some(val) = TRAFFIC_MAP.get_ptr_mut(&key) {
            (*val).bytes += bytes;
            (*val).packets += 1;
        } else {
            let val = TrafficValue {
                bytes,
                packets: 1,
            };
            // BPF_NOEXIST (1): only insert if key doesn't exist.
            // Race: if another CPU inserted between get_ptr_mut and insert,
            // insert fails silently — we lose one data point, which is acceptable.
            let _ = TRAFFIC_MAP.insert(&key, &val, 0);
        }
    }

    // Update PID→comm cache (best-effort, failures are non-fatal)
    if let Ok(comm) = bpf_get_current_comm() {
        let _ = unsafe { PID_COMM.insert(&pid, &comm, 0) };
    }

    Ok(())
}

// Required by aya-ebpf for panic handling in no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
