//! Shared data structures between eBPF kernel programs and userspace.
//!
//! These types must be `#[repr(C)]` to ensure consistent memory layout
//! across kernel and userspace. Both sides must agree on the exact
//! byte layout of map keys and values.

#![no_std]

/// Key for the per-PID traffic accumulator map.
///
/// Tracks bytes per (pid, protocol, direction) combination.
/// Total map capacity: 16384 entries (~2K processes × 2 protos × 2 dirs × 2x headroom).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrafficKey {
    /// Process ID (kernel tgid).
    pub pid: u32,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub proto: u8,
    /// Direction: 0 = TX (send), 1 = RX (recv).
    pub direction: u8,
    /// Padding for alignment.
    pub _pad: [u8; 2],
}

/// Value for the per-PID traffic accumulator map.
///
/// Accumulated bytes and packet counts since program load.
/// Userspace computes deltas by snapshotting and diffing.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrafficValue {
    /// Total bytes transferred.
    pub bytes: u64,
    /// Total number of send/recv calls.
    pub packets: u64,
}

/// Maximum number of entries in the traffic map.
///
/// Conservative limit: ~2048 processes × 2 protocols × 2 directions × 2 headroom.
/// Each entry is 16 bytes (key) + 16 bytes (value) = 32 bytes.
/// Total worst-case memory: 16384 × 32 = 512 KB.
pub const TRAFFIC_MAP_MAX_ENTRIES: u32 = 16384;

/// Maximum number of entries in the PID→comm name cache map.
pub const PID_COMM_MAP_MAX_ENTRIES: u32 = 4096;

/// Direction constants for TrafficKey.direction.
pub const DIRECTION_TX: u8 = 0;
pub const DIRECTION_RX: u8 = 1;

/// Protocol constants for TrafficKey.proto.
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// Compile-time size assertions to catch layout mismatches early.
const _: () = assert!(core::mem::size_of::<TrafficKey>() == 8);
const _: () = assert!(core::mem::size_of::<TrafficValue>() == 16);

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficValue {}
