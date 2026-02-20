// macOS capture implementation — wraps BpfCapture from src/bpf/.

use crate::bpf::{BpfCapture, BpfStats};
use crate::error::NetopError;

pub type PlatformCapture = BpfCapture;

/// Statistics from a capture device.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    pub received: u32,
    pub dropped: u32,
}

impl From<BpfStats> for CaptureStats {
    fn from(s: BpfStats) -> Self {
        Self {
            received: s.received,
            dropped: s.dropped,
        }
    }
}

/// Check that we have capture device access.
pub fn check_capture_access() -> Result<(), NetopError> {
    crate::privilege::check_bpf_access()
}

/// Open capture devices for the specified interfaces.
pub fn open_capture_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    crate::privilege::open_bpf_devices(interfaces, buffer_size, dns_enabled)
}

/// Get capture statistics (macOS BPF kernel stats).
pub fn capture_stats(cap: &PlatformCapture) -> Option<CaptureStats> {
    cap.stats().ok().map(CaptureStats::from)
}
