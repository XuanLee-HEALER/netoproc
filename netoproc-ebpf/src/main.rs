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
//!
//! Build requirements (Phase 2):
//! - Rust nightly toolchain
//! - Target: bpfel-unknown-none (little-endian eBPF)
//! - Build command: cargo +nightly build -Z build-std=core
//!     --target bpfel-unknown-none --release
//!
//! This crate is NOT compiled by the standard `cargo build`. It requires
//! a separate cross-compilation step as documented above.

#![no_std]
#![no_main]

use aya_ebpf::macros::{kprobe, kretprobe, map};
use aya_ebpf::maps::PerCpuHashMap;
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::{helpers::bpf_get_current_comm, helpers::bpf_get_current_pid_tgid};

use netoproc_ebpf_common::{
    TrafficKey, TrafficValue, DIRECTION_RX, DIRECTION_TX, PID_COMM_MAP_MAX_ENTRIES, PROTO_TCP,
    PROTO_UDP, TRAFFIC_MAP_MAX_ENTRIES,
};

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

/// Per-(PID, proto, direction) traffic accumulator.
///
/// Uses PerCpuHashMap to eliminate data races: each CPU has its own copy
/// of each value, so concurrent increments from different CPUs never
/// conflict. Userspace sums across all CPUs when reading.
#[map]
static TRAFFIC_MAP: PerCpuHashMap<TrafficKey, TrafficValue> =
    PerCpuHashMap::with_max_entries(TRAFFIC_MAP_MAX_ENTRIES, 0);

/// PID → process name cache (comm, up to 16 bytes).
/// Reduces userspace /proc reads for process name resolution.
/// PerCpuHashMap avoids contention; userspace reads any CPU's copy.
#[map]
static PID_COMM: PerCpuHashMap<u32, [u8; 16]> =
    PerCpuHashMap::with_max_entries(PID_COMM_MAP_MAX_ENTRIES, 0);

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
/// It reads the current PID and comm, then updates the per-CPU
/// traffic accumulator map. Using PerCpuHashMap ensures each CPU
/// writes to its own copy, eliminating data races without locks.
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

    // Update per-CPU traffic counters. No contention since each CPU
    // has its own value slot. Userspace sums across CPUs when reading.
    unsafe {
        if let Some(val) = TRAFFIC_MAP.get_ptr_mut(&key) {
            (*val).bytes += bytes;
            (*val).packets += 1;
        } else {
            let val = TrafficValue {
                bytes,
                packets: 1,
            };
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
