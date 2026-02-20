//! eBPF feature integration tests (Linux-only).
//!
//! These tests verify the eBPF detection, CLI flags, and fallback behavior.
//! Split into two groups:
//!
//! 1. Tests that work without the `ebpf` feature flag (default compilation)
//! 2. Tests gated by `#[cfg(feature = "ebpf")]` that need `--features ebpf`
//!
//! Run with:
//!   cross test --target x86_64-unknown-linux-gnu --test ebpf_integration
//!   cross test --target x86_64-unknown-linux-gnu --test ebpf_integration --features ebpf

#![cfg(target_os = "linux")]

use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn netoproc_bin() -> String {
    let mut path = std::env::current_exe()
        .unwrap()
        .parent() // deps/
        .unwrap()
        .parent() // debug/
        .unwrap()
        .to_path_buf();
    path.push("netoproc");
    path.to_string_lossy().to_string()
}

fn ensure_binary() {
    let bin = netoproc_bin();
    if std::path::Path::new(&bin).exists() {
        return;
    }
    let status = Command::new("cargo")
        .args(["build"])
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "cargo build failed");
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

macro_rules! require_root {
    () => {
        if !is_root() {
            eprintln!("SKIPPED: requires root");
            return;
        }
    };
}

// =========================================================================
// Section 1: Tests that work without --features ebpf
// =========================================================================

/// TC-EB-1: --capture-mode=afpacket explicitly selects AF_PACKET, works normally.
#[test]
fn tc_eb_1_afpacket_explicit_mode() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--capture-mode", "afpacket"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "--capture-mode=afpacket failed: exit={}, stderr={}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pid\tprocess"),
        "missing TSV header with --capture-mode=afpacket"
    );
}

/// TC-EB-2: --capture-mode=ebpf without the ebpf feature flag fails with clear error.
///
/// When compiled without `--features ebpf`, the binary should reject
/// `--capture-mode=ebpf` with an error mentioning "not compiled in".
#[cfg(not(feature = "ebpf"))]
#[test]
fn tc_eb_2_ebpf_mode_without_feature() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--capture-mode", "ebpf"])
        .output()
        .expect("failed to execute");

    assert!(
        !output.status.success(),
        "--capture-mode=ebpf should fail without ebpf feature"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not compiled") || stderr.contains("ebpf"),
        "error should mention 'not compiled' or 'ebpf', got: {stderr}"
    );
}

/// TC-EB-3: --capture-mode=auto without ebpf feature works (pure AF_PACKET).
#[test]
fn tc_eb_3_auto_mode_without_feature() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--capture-mode", "auto"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "--capture-mode=auto should work (AF_PACKET fallback): exit={}, stderr={}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// TC-EB-4: netoproc-ebpf-common types have correct size on Linux.
///
/// Verifies that the #[repr(C)] structs shared between kernel and userspace
/// have the expected byte layout. This catches alignment or padding differences
/// between the host (macOS/cross) and the Linux target.
#[test]
fn tc_eb_4_common_types_layout() {
    assert_eq!(
        std::mem::size_of::<netoproc_ebpf_common::TrafficKey>(),
        8,
        "TrafficKey should be 8 bytes"
    );
    assert_eq!(
        std::mem::size_of::<netoproc_ebpf_common::TrafficValue>(),
        16,
        "TrafficValue should be 16 bytes"
    );

    // Verify field alignment: TrafficKey.pid at offset 0, proto at 4, direction at 5
    let key = netoproc_ebpf_common::TrafficKey {
        pid: 0x12345678,
        proto: 6,
        direction: 1,
        _pad: [0; 2],
    };
    let bytes: [u8; 8] = unsafe { std::mem::transmute(key) };
    // pid is u32 at offset 0 (native endian)
    let pid = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(pid, 0x12345678);
    // proto at offset 4
    assert_eq!(bytes[4], 6);
    // direction at offset 5
    assert_eq!(bytes[5], 1);
}

// =========================================================================
// Section 2: Tests that require --features ebpf
// =========================================================================

/// TC-EB-5: ebpf_available() reads /proc/version without crashing.
///
/// On the cross Docker container, /proc/version exists and is readable.
/// The function should return a boolean without panicking.
#[cfg(feature = "ebpf")]
#[test]
fn tc_eb_5_ebpf_available_runtime() {
    use netoproc::capture::ebpf;

    // Should return a bool without crashing, regardless of kernel version.
    let available = ebpf::ebpf_available();
    eprintln!("ebpf_available() = {available}");

    // Verify /proc/version exists and is readable (sanity check).
    let version = std::fs::read_to_string("/proc/version");
    assert!(version.is_ok(), "/proc/version should be readable");
    eprintln!("/proc/version = {:?}", version.unwrap().trim());
}

/// TC-EB-6: --capture-mode=ebpf with feature flag returns stub error.
///
/// Phase 1 stub always returns Err, so --capture-mode=ebpf should fail
/// with an error mentioning "not yet implemented" or "stub".
#[cfg(feature = "ebpf")]
#[test]
fn tc_eb_6_ebpf_mode_stub_error() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--capture-mode", "ebpf"])
        .output()
        .expect("failed to execute");

    assert!(
        !output.status.success(),
        "--capture-mode=ebpf should fail in Phase 1 (stub)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not yet implemented")
            || stderr.contains("stub")
            || stderr.contains("eBPF"),
        "error should mention eBPF stub status, got: {stderr}"
    );
}

/// TC-EB-7: --capture-mode=auto with ebpf feature falls back to AF_PACKET.
///
/// Since the eBPF stub always returns Err, auto mode should detect this
/// and fall back to AF_PACKET, producing normal output.
#[cfg(feature = "ebpf")]
#[test]
fn tc_eb_7_auto_mode_ebpf_fallback() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .env("RUST_LOG", "info")
        .args(["--duration", "1", "--capture-mode", "auto"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "--capture-mode=auto should succeed via AF_PACKET fallback: exit={}, stderr={}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pid\tprocess"),
        "auto mode should produce normal TSV output after fallback"
    );

    // With RUST_LOG=info, stderr should show the fallback decision.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mentions_fallback = stderr.contains("AF_PACKET")
        || stderr.contains("fallback")
        || stderr.contains("not available");
    if !mentions_fallback {
        eprintln!(
            "note: expected fallback log message in stderr, got:\n{}",
            stderr
        );
    }
}

/// TC-EB-8: EbpfCapture::try_new() returns a meaningful error.
#[cfg(feature = "ebpf")]
#[test]
fn tc_eb_8_ebpf_capture_error_message() {
    use netoproc::capture::ebpf::EbpfCapture;

    let err_msg = match EbpfCapture::try_new("eth0") {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("EbpfCapture::try_new() should return Err in Phase 1 stub"),
    };
    assert!(
        err_msg.contains("not yet implemented") || err_msg.contains("stub"),
        "error should explain this is a Phase 1 stub, got: {err_msg}"
    );
}
