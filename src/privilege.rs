use crate::bpf::{BpfCapture, FilterKind};
use crate::error::NetopError;

/// Check that we have BPF device access.
///
/// Three outcomes:
/// - UID 0 (root): pass immediately.
/// - Non-root with read access to `/dev/bpf0` (e.g. `access_bpf` group member):
///   pass with a warning about limited process visibility.
/// - Neither: return `InsufficientPermission` with guidance.
pub fn check_bpf_access() -> Result<(), NetopError> {
    // Root always has access.
    if unsafe { libc::getuid() } == 0 {
        return Ok(());
    }

    // Check if we can read /dev/bpf0 (group permission via access_bpf).
    let path = std::ffi::CString::new("/dev/bpf0")
        .map_err(|_| NetopError::Fatal("invalid path".to_string()))?;
    if unsafe { libc::access(path.as_ptr(), libc::R_OK) } == 0 {
        log::warn!(
            "Running without root: process visibility limited to current user. \
             For full visibility, run with: sudo netoproc"
        );
        return Ok(());
    }

    Err(NetopError::InsufficientPermission(
        "netoproc requires BPF device access. Either:\n  \
         1. Run with sudo: sudo netoproc\n  \
         2. Set up BPF permissions: sudo bash scripts/install-bpf.sh"
            .to_string(),
    ))
}

/// Open BPF capture devices for the specified interfaces.
///
/// Opens one traffic capture device per interface. If DNS is enabled,
/// also opens a DNS-specific capture device on the first interface.
///
/// The appropriate BPF filter is selected automatically based on each
/// interface's data link type (Ethernet, Raw IP, or Null/Loopback).
pub fn open_bpf_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
) -> Result<(Vec<BpfCapture>, Option<BpfCapture>), NetopError> {
    let mut captures = Vec::new();
    for iface in interfaces {
        match BpfCapture::new(iface, buffer_size, FilterKind::Traffic) {
            Ok(cap) => captures.push(cap),
            Err(e) => {
                // Log and skip interfaces with unsupported DLTs or other errors,
                // as long as we have at least one working capture.
                log::warn!("Skipping interface {}: {}", iface, e);
            }
        }
    }

    let dns_capture = if dns_enabled {
        if let Some(iface) = interfaces.first() {
            // Use larger buffer for DNS since we need full payloads
            let dns_buf_size = buffer_size.max(65536);
            match BpfCapture::new(iface, dns_buf_size, FilterKind::Dns) {
                Ok(cap) => Some(cap),
                Err(e) => {
                    log::warn!(
                        "DNS capture on {} failed: {} (continuing without DNS)",
                        iface,
                        e
                    );
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok((captures, dns_capture))
}
