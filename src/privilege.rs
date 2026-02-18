use crate::bpf::BpfCapture;
use crate::bpf::filter;
use crate::error::NetopError;

/// Check that we are running as root. BPF device access requires root.
pub fn check_root() -> Result<(), NetopError> {
    if unsafe { libc::getuid() } != 0 {
        return Err(NetopError::NotRoot);
    }
    Ok(())
}

/// Open BPF capture devices for the specified interfaces.
///
/// Opens one traffic capture device per interface. If DNS is enabled,
/// also opens a DNS-specific capture device on the first interface.
pub fn open_bpf_devices(
    interfaces: &[String],
    buffer_size: u32,
    dns_enabled: bool,
) -> Result<(Vec<BpfCapture>, Option<BpfCapture>), NetopError> {
    let traffic_filter = filter::traffic_filter();
    let dns_filter_prog = filter::dns_filter();

    let mut captures = Vec::new();
    for iface in interfaces {
        let cap = BpfCapture::new(iface, buffer_size, &traffic_filter)?;
        captures.push(cap);
    }

    let dns_capture = if dns_enabled {
        if let Some(iface) = interfaces.first() {
            // Use larger buffer for DNS since we need full payloads
            let dns_buf_size = buffer_size.max(65536);
            Some(BpfCapture::new(iface, dns_buf_size, &dns_filter_prog)?)
        } else {
            None
        }
    } else {
        None
    };

    Ok((captures, dns_capture))
}
