// macOS capture implementation — wraps BpfCapture from src/bpf/.

use crate::bpf::{BpfCapture, BpfStats};
use crate::dns::DnsMessage;
use crate::error::NetopError;
use crate::packet::PacketSummary;

use super::{CaptureStats, PacketSource};

pub type PlatformCapture = BpfCapture;

impl From<BpfStats> for CaptureStats {
    fn from(s: BpfStats) -> Self {
        Self {
            received: s.received,
            dropped: s.dropped,
        }
    }
}

impl PacketSource for BpfCapture {
    fn interface(&self) -> &str {
        BpfCapture::interface(self)
    }

    fn read_packets_raw(&mut self, out: &mut Vec<PacketSummary>) -> Result<usize, NetopError> {
        BpfCapture::read_packets_raw(self, out)
    }

    fn read_dns_messages(&mut self) -> Result<Vec<DnsMessage>, NetopError> {
        BpfCapture::read_dns_messages(self)
    }

    fn capture_stats(&self) -> Option<CaptureStats> {
        self.stats().ok().map(CaptureStats::from)
    }
}

/// Check that we have capture device access.
pub fn check_capture_access() -> Result<(), NetopError> {
    crate::privilege::check_bpf_access()
}

/// Open capture devices for the specified interfaces.
///
/// On macOS, `_capture_mode` is ignored — BPF is the only backend.
pub fn open_capture_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
    _capture_mode: crate::cli::CaptureMode,
) -> Result<(Vec<PlatformCapture>, Option<PlatformCapture>), NetopError> {
    crate::privilege::open_bpf_devices(interfaces, buffer_size, dns_enabled)
}
