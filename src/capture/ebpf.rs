// eBPF capture backend — kprobe-based per-process network traffic monitoring.
//
// This module provides an eBPF-based alternative to AF_PACKET for Linux.
// It attaches kprobes to tcp_sendmsg/tcp_recvmsg/udp_sendmsg/udp_recvmsg
// to capture per-process traffic statistics directly in kernel space.
//
// Requires: Linux kernel 5.8+, BTF enabled, CAP_BPF + CAP_PERFMON.
//
// Phase 1: detection + stub implementation (returns to AF_PACKET fallback).
// Phase 2: actual kprobe eBPF program loading and BPF map polling.

use std::path::Path;

use crate::error::NetopError;

// ---------------------------------------------------------------------------
// eBPF availability detection
// ---------------------------------------------------------------------------

/// Check if the running kernel supports eBPF with the features we need.
///
/// Requirements:
/// 1. Kernel version >= 5.8 (CAP_BPF, ring buffer, mature BTF)
/// 2. BTF type information available (/sys/kernel/btf/vmlinux)
///
/// This is a conservative check — we require both conditions to avoid
/// subtle runtime failures on partially-supported kernels.
pub fn ebpf_available() -> bool {
    if !kernel_version_sufficient() {
        log::debug!("ebpf: kernel version < 5.8, not available");
        return false;
    }

    if !btf_available() {
        log::debug!("ebpf: BTF not available (/sys/kernel/btf/vmlinux missing)");
        return false;
    }

    log::debug!("ebpf: kernel and BTF checks passed");
    true
}

/// Parse the kernel version from /proc/version and check >= 5.8.
fn kernel_version_sufficient() -> bool {
    let version = match std::fs::read_to_string("/proc/version") {
        Ok(v) => v,
        Err(_) => return false,
    };

    parse_kernel_version(&version)
        .map(|(major, minor)| major > 5 || (major == 5 && minor >= 8))
        .unwrap_or(false)
}

/// Extract (major, minor) from a kernel version string.
///
/// Expected format: "Linux version X.Y.Z-..."
/// Searches for the "version" keyword then parses the following token,
/// which avoids misparsing on non-standard `/proc/version` strings
/// like `"Linux (compiled by user.name) version 5.15.0"`.
fn parse_kernel_version(version_str: &str) -> Option<(u32, u32)> {
    let tokens: Vec<&str> = version_str.split_whitespace().collect();

    // Find the "version" keyword and take the next token.
    let version_part = tokens
        .iter()
        .position(|&t| t.eq_ignore_ascii_case("version"))
        .and_then(|i| tokens.get(i + 1))?;

    let mut parts = version_part.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_str = parts.next()?;
    // Minor might be "8" or "8-arch1" — take only the numeric prefix.
    let minor: u32 = minor_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;

    Some((major, minor))
}

/// Check if BTF (BPF Type Format) info is available for the running kernel.
fn btf_available() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

// ---------------------------------------------------------------------------
// EbpfCapture — stub implementation for Phase 1
// ---------------------------------------------------------------------------

/// eBPF-based capture device (Phase 1: stub).
///
/// In Phase 2, this will hold the loaded Aya eBPF program, map references,
/// and polling state. For now, it serves as the type that the dispatch layer
/// can reference, with `try_new()` always returning an error to trigger
/// AF_PACKET fallback.
pub struct EbpfCapture {
    _interface: String,
}

impl EbpfCapture {
    /// Attempt to create an eBPF capture device.
    ///
    /// Phase 1: always returns Err to trigger AF_PACKET fallback in auto mode.
    /// Phase 2: will load the eBPF program, attach kprobes, and return Ok.
    pub fn try_new(_interface: &str) -> Result<Self, NetopError> {
        Err(NetopError::EbpfProgram(
            "eBPF capture not yet implemented (Phase 1 stub)".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_version_standard() {
        let v = "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-060)";
        assert_eq!(parse_kernel_version(v), Some((5, 15)));
    }

    #[test]
    fn parse_kernel_version_arch() {
        let v = "Linux version 6.7.1-arch1-1 (linux@archlinux)";
        assert_eq!(parse_kernel_version(v), Some((6, 7)));
    }

    #[test]
    fn parse_kernel_version_rhel() {
        let v = "Linux version 4.18.0-513.24.1.el8_9.x86_64 (mockbuild@x86-064)";
        assert_eq!(parse_kernel_version(v), Some((4, 18)));
    }

    #[test]
    fn parse_kernel_version_insufficient() {
        // 5.7 is below our 5.8 threshold
        let v = "Linux version 5.7.0-generic";
        let (major, minor) = parse_kernel_version(v).unwrap();
        assert!(!(major > 5 || (major == 5 && minor >= 8)));
    }

    #[test]
    fn parse_kernel_version_sufficient() {
        let v = "Linux version 5.8.0-generic";
        let (major, minor) = parse_kernel_version(v).unwrap();
        assert!(major > 5 || (major == 5 && minor >= 8));
    }

    #[test]
    fn parse_kernel_version_6x() {
        let v = "Linux version 6.1.0-17-amd64 (debian-kernel@lists.debian.org)";
        let (major, minor) = parse_kernel_version(v).unwrap();
        assert!(major > 5 || (major == 5 && minor >= 8));
        assert_eq!((major, minor), (6, 1));
    }

    #[test]
    fn parse_kernel_version_non_standard_proc_version() {
        // B4 regression test: "version" keyword not at expected position
        let v = "Linux (compiled by user.name) version 5.15.0-generic";
        assert_eq!(parse_kernel_version(v), Some((5, 15)));
    }

    #[test]
    fn parse_kernel_version_empty_string() {
        assert_eq!(parse_kernel_version(""), None);
    }

    #[test]
    fn parse_kernel_version_no_version_keyword() {
        assert_eq!(parse_kernel_version("Linux 5.15.0-generic"), None);
    }

    #[test]
    fn parse_kernel_version_version_at_end() {
        // "version" present but no token follows
        assert_eq!(parse_kernel_version("Linux version"), None);
    }

    #[test]
    fn parse_kernel_version_non_numeric() {
        assert_eq!(parse_kernel_version("Linux version abc.def"), None);
    }

    #[test]
    fn ebpf_capture_stub_returns_error() {
        let result = EbpfCapture::try_new("eth0");
        assert!(result.is_err());
    }
}
