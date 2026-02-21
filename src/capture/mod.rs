// Platform-abstracted packet capture.
//
// On macOS: wraps BpfCapture from src/bpf/.
// On Linux: uses AF_PACKET raw sockets.
// On Windows: uses Winsock2 raw sockets with SIO_RCVALL.
//
// All platforms export:
//   - PlatformCapture type
//   - PacketSource trait (implemented by PlatformCapture)
//   - check_capture_access() -> Result<(), NetopError>
//   - open_capture_devices(...) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError>

use crate::dns::DnsMessage;
use crate::error::NetopError;
use crate::packet::PacketSummary;

/// Type of filter to install on a capture device.
#[derive(Debug, Clone, Copy)]
pub enum FilterKind {
    /// Accept all IPv4/IPv6 TCP/UDP traffic.
    Traffic,
    /// Accept only DNS traffic (port 53).
    Dns,
}

/// Statistics from a capture device.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    pub received: u32,
    pub dropped: u32,
}

/// Platform-agnostic interface for packet capture devices.
///
/// Implemented by each platform's concrete capture type (`BpfCapture` on
/// macOS, `AfPacketCapture` on Linux, `RawSocketCapture` on Windows).
/// Using generics (`<S: PacketSource>`) instead of trait objects (`dyn
/// PacketSource`) keeps dispatch zero-cost: each instantiation is
/// monomorphized to the single concrete type used on that platform.
pub trait PacketSource {
    /// Returns the interface name this capture device is bound to.
    fn interface(&self) -> &str;

    /// Blocking read of packets.
    ///
    /// Clears `out`, blocks until data arrives or a timeout (~500 ms), then
    /// appends parsed `PacketSummary` entries. Returns the number of raw bytes
    /// read (0 on timeout with no data).
    fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError>;

    /// Blocking read of DNS messages.
    ///
    /// Only meaningful on capture devices opened with `FilterKind::Dns`.
    fn read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError>;

    /// Kernel-level capture statistics, if available.
    ///
    /// Returns `None` on platforms that do not expose drop counters.
    fn capture_stats(&self) -> Option<CaptureStats>;
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;
