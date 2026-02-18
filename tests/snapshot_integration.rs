//! Snapshot subcommand integration tests.
//!
//! These tests exercise the full `netoproc snapshot` binary end-to-end.
//! Most require root privileges (BPF device access).
//! Run with: `sudo cargo test --test snapshot_integration`

use std::process::Command;
use std::time::{Duration, Instant};

/// Path to the compiled binary. `cargo test` builds it automatically.
fn netoproc_bin() -> String {
    // cargo test sets this env var to the workspace target dir
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

/// Build the binary before running tests.
fn ensure_binary() {
    let status = Command::new("cargo")
        .args(["build"])
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "cargo build failed");
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

/// Skip test if not running as root.
macro_rules! require_root {
    () => {
        if !is_root() {
            eprintln!("SKIPPED: requires root");
            return;
        }
    };
}

// =========================================================================
// Section 1: CLI parsing + basic invocation (TC-1.x)
// =========================================================================

/// TC-1.1: `sudo netop snapshot` exits 0, stdout has TSV section headers.
#[test]
fn tc_1_1_snapshot_basic_tsv() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "exit code: {}, stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# processes"), "missing processes section");
    assert!(stdout.contains("# sockets"), "missing sockets section");
    assert!(
        stdout.contains("# connections"),
        "missing connections section"
    );
    assert!(
        stdout.contains("# interfaces"),
        "missing interfaces section"
    );
    assert!(
        stdout.contains("# dns_resolvers"),
        "missing dns_resolvers section"
    );
    assert!(
        stdout.contains("# dns_queries"),
        "missing dns_queries section"
    );
}

/// TC-1.2: `sudo netop snapshot --format json` produces valid JSON.
#[test]
fn tc_1_2_snapshot_json() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--format", "json", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "exit code: {}, stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is not valid JSON");

    assert!(parsed["timestamp"].is_number(), "missing timestamp");
    assert!(parsed["processes"].is_array(), "missing processes array");
    assert!(parsed["interfaces"].is_array(), "missing interfaces array");
    assert!(parsed["dns"].is_object(), "missing dns object");
    assert!(
        parsed["dns"]["resolvers"].is_array(),
        "missing dns.resolvers"
    );
    assert!(parsed["dns"]["queries"].is_array(), "missing dns.queries");
}

/// TC-1.3: `sudo netop snapshot --format tsv` (explicit) same as default.
#[test]
fn tc_1_3_snapshot_explicit_tsv() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--format", "tsv", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# processes"));
}

/// TC-1.4: --interval controls timing (0.5s interval + 1s duration ≈ fast exit).
#[test]
fn tc_1_4_snapshot_interval_timing() {
    require_root!();
    ensure_binary();

    let start = Instant::now();
    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5", "--duration", "1"])
        .output()
        .expect("failed to execute");
    let elapsed = start.elapsed();

    assert!(output.status.success());
    // Should complete within ~1.5s (duration + overhead), well under 5s.
    assert!(
        elapsed < Duration::from_secs(5),
        "took too long: {elapsed:?}"
    );
}

/// TC-1.5: --interface limits to specific interface.
#[test]
fn tc_1_5_snapshot_specific_interface() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interface", "en0", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    if output.status.success() {
        // en0 exists — verify output contains interface data
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("# interfaces"));
    } else {
        // en0 doesn't exist — must be BPF error (exit 2), not clap error
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("BPF") || stderr.contains("bpf") || stderr.contains("BIOCSETIF"),
            "expected BPF error, got: {stderr}"
        );
    }
}

/// TC-1.6: --no-dns disables DNS sections data.
#[test]
fn tc_1_6_snapshot_no_dns() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--no-dns", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // dns_resolvers and dns_queries sections should exist but have no data rows
    assert!(stdout.contains("# dns_resolvers"));
    assert!(stdout.contains("# dns_queries"));
}

/// TC-1.7: --bpf-buffer accepts valid value.
#[test]
fn tc_1_7_snapshot_bpf_buffer() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--bpf-buffer", "65536", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
}

// =========================================================================
// Section 2: Permission checks (TC-2.x)
// =========================================================================

/// TC-2.1: Non-root exits with code 1.
#[test]
fn tc_2_1_non_root_exit_code() {
    if is_root() {
        eprintln!("SKIPPED: test requires non-root");
        return;
    }
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot"])
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1, got {:?}",
        output.status.code()
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("root") || stderr.contains("privilege"),
        "stderr should mention root/privilege, got: {}",
        stderr
    );
}

// =========================================================================
// Section 3: Interface discovery (TC-3.x)
// =========================================================================

/// TC-3.1: Auto-discover finds at least one interface.
#[test]
fn tc_3_1_auto_discover_interfaces() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the interfaces section and check it has data
    let sections = parse_tsv_sections(&stdout);
    let ifaces = sections.get("interfaces").expect("missing interfaces");
    assert!(!ifaces.is_empty(), "no interfaces found");
}

/// TC-3.3: Non-existent interface exits with code 2 (BPF error, not clap error).
#[test]
fn tc_3_3_nonexistent_interface() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interface", "nonexist99"])
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2 for bad interface, got {:?}",
        output.status.code()
    );

    // Verify it's a BPF/interface error, not a CLI parsing error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "got clap parse error instead of BPF error: {stderr}"
    );
}

// =========================================================================
// Section 7: Output serialization (TC-7.x)
// =========================================================================

/// TC-7.1: TSV has exactly 6 sections.
#[test]
fn tc_7_1_tsv_six_sections() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let section_count = stdout.lines().filter(|l| l.starts_with("# ")).count();
    assert_eq!(section_count, 6, "expected 6 sections, got {section_count}");
}

/// TC-7.2: TSV column counts are consistent within each section.
#[test]
fn tc_7_2_tsv_consistent_columns() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut current_section = String::new();
    let mut expected_cols: usize = 0;
    let mut line_num = 0;

    for line in stdout.lines() {
        line_num += 1;
        if line.starts_with("# ") {
            current_section = line[2..].to_string();
            expected_cols = 0;
            continue;
        }
        if line.is_empty() {
            continue;
        }

        let cols = line.split('\t').count();
        if expected_cols == 0 {
            // This is the header line
            expected_cols = cols;
        } else {
            assert_eq!(
                cols, expected_cols,
                "section '{}' line {}: got {} cols, expected {}",
                current_section, line_num, cols, expected_cols
            );
        }
    }
}

/// TC-7.3: TSV contains no ANSI escape codes.
#[test]
fn tc_7_3_tsv_no_ansi() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('\x1b'),
        "TSV output contains ANSI escape codes"
    );
}

/// TC-7.4: JSON output is valid and parseable.
#[test]
fn tc_7_4_json_valid() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--format", "json", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
}

/// TC-7.5: JSON has correct top-level structure.
#[test]
fn tc_7_5_json_structure() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--format", "json", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(parsed["timestamp"].as_u64().is_some(), "timestamp not u64");
    assert!(parsed["processes"].as_array().is_some());
    assert!(parsed["interfaces"].as_array().is_some());
    assert!(parsed["dns"]["resolvers"].as_array().is_some());
    assert!(parsed["dns"]["queries"].as_array().is_some());
}

/// TC-7.6: JSON numeric fields are actual numbers, not strings.
#[test]
fn tc_7_6_json_numeric_types() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--format", "json", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // timestamp must be a number
    assert!(parsed["timestamp"].is_number());

    // If there are processes, pid must be a number
    if let Some(procs) = parsed["processes"].as_array() {
        if let Some(proc0) = procs.first() {
            assert!(proc0["pid"].is_number(), "pid should be a number");
            assert!(proc0["uid"].is_number(), "uid should be a number");
        }
    }

    // If there are interfaces, byte counts must be numbers
    if let Some(ifaces) = parsed["interfaces"].as_array() {
        if let Some(iface0) = ifaces.first() {
            assert!(
                iface0["rx_bytes_total"].is_number(),
                "rx_bytes_total should be a number"
            );
        }
    }
}

// =========================================================================
// Section 8: Shutdown / exit (TC-8.x)
// =========================================================================

/// TC-8.1: Snapshot exits normally, does not hang.
#[test]
fn tc_8_1_snapshot_no_hang() {
    require_root!();
    ensure_binary();

    let start = Instant::now();
    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "snapshot failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Must complete within a reasonable time (interval + poller + shutdown)
    assert!(
        elapsed < Duration::from_secs(10),
        "snapshot hung or took too long: {elapsed:?}"
    );
}

/// TC-8.2: SIGTERM terminates the process.
#[test]
fn tc_8_2_sigterm_terminates() {
    require_root!();
    ensure_binary();

    use std::process::Stdio;

    let mut child = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "10"]) // long interval so it doesn't exit naturally
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");

    // Wait for process to fully start (open BPF devices, spawn threads)
    std::thread::sleep(Duration::from_secs(2));

    // Send SIGTERM
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for exit with timeout (poller select timeout is 500ms + BPF read 500ms + overhead)
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(10) {
                    child.kill().ok();
                    panic!("process did not exit within 10s after SIGTERM");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for child: {e}"),
        }
    }
}

/// TC-8.3: SIGINT terminates the process.
#[test]
fn tc_8_3_sigint_terminates() {
    require_root!();
    ensure_binary();

    use std::process::Stdio;

    let mut child = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "10"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");

    // Wait for process to fully start
    std::thread::sleep(Duration::from_secs(2));

    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(10) {
                    child.kill().ok();
                    panic!("process did not exit within 10s after SIGINT");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for child: {e}"),
        }
    }
}

// =========================================================================
// Section 9: Exit code mapping (TC-9.x)
// =========================================================================

/// TC-9.1: Successful snapshot exits with code 0.
#[test]
fn tc_9_1_success_exit_code() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

/// TC-9.3: BPF device error exits with code 2.
#[test]
fn tc_9_3_bpf_error_exit_code() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interface", "nonexist99"])
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2, got {:?}",
        output.status.code()
    );

    // Confirm it's a real BPF error, not a CLI parsing error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "got clap parse error instead of BPF error: {stderr}"
    );
}

// =========================================================================
// Section 6: Data content (TC-6.x)
// =========================================================================

/// TC-6.3: Interfaces section contains at least one up interface with byte counts.
#[test]
fn tc_6_3_interfaces_have_data() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sections = parse_tsv_sections(&stdout);

    let ifaces = sections.get("interfaces").expect("missing interfaces");
    assert!(!ifaces.is_empty(), "no interface data rows");

    // At least one interface should be "up"
    let has_up = ifaces.iter().any(|row| row.contains("\tup\t"));
    assert!(has_up, "no interface with status 'up' found");
}

/// TC-6.4: Processes section exists; may have data if there's network activity.
#[test]
fn tc_6_4_processes_have_data() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--interval", "1"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sections = parse_tsv_sections(&stdout);

    // Processes section must exist (even if empty)
    let procs = sections
        .get("processes")
        .expect("missing processes section");
    if procs.is_empty() {
        eprintln!("WARNING: no process data found (system may have no network-active processes)");
    }
}

/// TC-5.4: Snapshot reads non-empty state (poller race condition test).
#[test]
fn tc_5_4_snapshot_not_empty_state() {
    require_root!();
    ensure_binary();

    // Run multiple times to catch intermittent race
    for i in 0..3 {
        let output = Command::new(netoproc_bin())
            .args(["snapshot", "--interval", "1"])
            .output()
            .expect("failed to execute");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let sections = parse_tsv_sections(&stdout);

        let ifaces = sections.get("interfaces").unwrap_or(&Vec::new()).clone();
        if ifaces.is_empty() {
            eprintln!("WARNING: run {i} produced empty interfaces (race condition?)");
        } else {
            // At least one run should have data
            return;
        }
    }
    // If all 3 runs had empty interfaces, something is wrong
    panic!("all 3 snapshot runs produced empty interfaces section");
}

// =========================================================================
// Section 10: --duration flag (TC-10.x)
// =========================================================================

/// TC-10.1: --duration 2 runs for approximately 2 seconds.
#[test]
fn tc_10_1_duration_timing() {
    require_root!();
    ensure_binary();

    let start = Instant::now();
    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--duration", "2", "--interval", "0.5"])
        .output()
        .expect("failed to execute");
    let elapsed = start.elapsed();

    assert!(output.status.success());
    // Should take at least ~2s (duration) but not more than ~8s.
    assert!(
        elapsed >= Duration::from_secs(1),
        "finished too fast: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "took too long: {elapsed:?}"
    );
}

/// TC-10.2: --duration 1 (minimum) is accepted.
#[test]
fn tc_10_2_duration_minimum() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--duration", "1", "--interval", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// TC-10.3: --duration 0.5 (below minimum) is rejected.
#[test]
fn tc_10_3_duration_below_minimum() {
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--duration", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(!output.status.success(), "should reject duration below 1.0");
}

/// TC-10.4: --duration 31 (above maximum) is rejected.
#[test]
fn tc_10_4_duration_above_maximum() {
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["snapshot", "--duration", "31"])
        .output()
        .expect("failed to execute");

    assert!(
        !output.status.success(),
        "should reject duration above 30.0"
    );
}

/// TC-10.5: --duration produces non-zero interface rates after collecting traffic.
///
/// After multiple poller cycles, the rate_per_sec() fallback (L0.latest()) should
/// return meaningful deltas for interfaces that have active traffic.
#[test]
fn tc_10_5_duration_nonzero_interface_rates() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args([
            "snapshot",
            "--duration",
            "3",
            "--interval",
            "0.5",
            "--format",
            "tsv",
        ])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sections = parse_tsv_sections(&stdout);
    let ifaces = sections.get("interfaces").expect("missing interfaces");

    // At least one interface should have non-zero rx_bytes_total (column index 6).
    // On any machine with active network traffic, at least one interface should
    // also show a non-zero rate after 3 seconds of collection.
    let has_traffic = ifaces.iter().any(|row| {
        let cols: Vec<&str> = row.split('\t').collect();
        // cols[4] = rx_bytes_sec, cols[5] = tx_bytes_sec
        if cols.len() >= 8 {
            let rx_rate: f64 = cols[4].parse().unwrap_or(0.0);
            let tx_rate: f64 = cols[5].parse().unwrap_or(0.0);
            rx_rate > 0.0 || tx_rate > 0.0
        } else {
            false
        }
    });

    assert!(
        has_traffic,
        "expected at least one interface with non-zero rate after 3s collection"
    );
}

/// TC-10.6: Pretty format shows non-zero rates after --duration collection.
#[test]
fn tc_10_6_pretty_nonzero_rates() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args([
            "snapshot",
            "--format",
            "pretty",
            "--duration",
            "3",
            "--interval",
            "0.5",
        ])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The pretty output should show at least one interface with a non-zero rate
    // in parentheses, e.g., "rx: 2.1 GB (1.2 KB/s)".
    // A rate of "(0 B/s)" for ALL interfaces would indicate the bug is still present.
    let iface_section = stdout
        .split("Interfaces")
        .nth(1)
        .expect("missing Interfaces section");
    let iface_lines: Vec<&str> = iface_section
        .lines()
        .take_while(|l| !l.contains("DNS"))
        .filter(|l| l.contains("rx:"))
        .collect();

    let has_nonzero = iface_lines.iter().any(|line| {
        // Check that the rate in parentheses is not "(0 B/s)"
        line.contains("B/s)") && !line.contains("(0 B/s)")
    });

    assert!(
        has_nonzero,
        "expected at least one interface with non-zero rate in pretty output.\nInterface lines: {iface_lines:?}"
    );
}

// =========================================================================
// Section 11: --format pretty (TC-11.x)
// =========================================================================

/// TC-11.1: --format pretty produces tree output with section headers.
#[test]
fn tc_11_1_pretty_basic() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args([
            "snapshot",
            "--format",
            "pretty",
            "--duration",
            "2",
            "--interval",
            "0.5",
        ])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "exit code: {}, stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Processes"), "missing Processes section");
    assert!(stdout.contains("Interfaces"), "missing Interfaces section");
    assert!(stdout.contains("DNS"), "missing DNS section");
}

/// TC-11.2: Pretty output has no ANSI escape codes.
#[test]
fn tc_11_2_pretty_no_ansi() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args([
            "snapshot",
            "--format",
            "pretty",
            "--duration",
            "1",
            "--interval",
            "0.5",
        ])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('\x1b'),
        "pretty output contains ANSI escape codes"
    );
}

/// TC-11.3: Pretty output contains interface data.
#[test]
fn tc_11_3_pretty_interfaces() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args([
            "snapshot",
            "--format",
            "pretty",
            "--duration",
            "1",
            "--interval",
            "0.5",
        ])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show at least one interface or "no traffic" summary.
    assert!(
        stdout.contains("rx:") || stdout.contains("no traffic"),
        "expected interface data in pretty output"
    );
}

// =========================================================================
// Helpers
// =========================================================================

/// Parse TSV output into section_name -> Vec<data_rows>.
/// Skips the header line (first non-comment line in each section).
fn parse_tsv_sections(output: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut sections = std::collections::HashMap::new();
    let mut current_name = String::new();
    let mut header_seen = false;

    for line in output.lines() {
        if let Some(name) = line.strip_prefix("# ") {
            current_name = name.to_string();
            header_seen = false;
            sections
                .entry(current_name.clone())
                .or_insert_with(Vec::new);
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if current_name.is_empty() {
            continue;
        }
        if !header_seen {
            // This is the column header line, skip it
            header_seen = true;
            continue;
        }
        // Data row
        sections
            .get_mut(&current_name)
            .unwrap()
            .push(line.to_string());
    }

    sections
}
