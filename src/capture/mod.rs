// Platform-abstracted packet capture.
//
// On macOS: wraps BpfCapture from src/bpf/.
// On Linux: uses AF_PACKET raw sockets.
//
// Both platforms export:
//   - PlatformCapture type
//   - check_capture_access() -> Result<(), NetopError>
//   - open_capture_devices(...) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError>

/// Type of filter to install on a capture device.
#[derive(Debug, Clone, Copy)]
pub enum FilterKind {
    /// Accept all IPv4/IPv6 TCP/UDP traffic.
    Traffic,
    /// Accept only DNS traffic (port 53).
    Dns,
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
