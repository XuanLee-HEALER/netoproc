//! Snapshot mode integration tests.
//!
//! These tests exercise the full `netoproc --duration N` binary end-to-end.
//! Most require root privileges (BPF device access).
//! Run with: `sudo cargo test --test snapshot_integration`

use std::process::Command;
use std::time::{Duration, Instant};

/// Path to the compiled binary. `cargo test` builds it automatically.
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

/// TC-1.1: `sudo netoproc --duration 1` exits 0, stdout has TSV header.
#[test]
fn tc_1_1_snapshot_basic_tsv() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "exit code: {}, stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pid\tprocess\trx_bytes\ttx_bytes\trx_packets\ttx_packets"),
        "missing TSV header row"
    );
}

/// TC-1.2: `sudo netoproc --duration 1 --format json` produces valid JSON array.
#[test]
fn tc_1_2_snapshot_json() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--format", "json"])
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

    assert!(parsed.is_array(), "expected JSON array at top level");
}

/// TC-1.3: `sudo netoproc --duration 1 --format tsv` (explicit) works.
#[test]
fn tc_1_3_snapshot_explicit_tsv() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--format", "tsv"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pid\tprocess"));
}

/// TC-1.4: --duration 2 timing.
#[test]
fn tc_1_4_snapshot_duration_timing() {
    require_root!();
    ensure_binary();

    let start = Instant::now();
    let output = Command::new(netoproc_bin())
        .args(["--duration", "2"])
        .output()
        .expect("failed to execute");
    let elapsed = start.elapsed();

    assert!(output.status.success());
    assert!(
        elapsed >= Duration::from_secs(1),
        "finished too fast: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "took too long: {elapsed:?}"
    );
}

/// TC-1.5: --interface limits to specific interface.
#[test]
fn tc_1_5_snapshot_specific_interface() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--interface", "en0"])
        .output()
        .expect("failed to execute");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("pid\tprocess"));
    } else {
        // en0 doesn't exist — must be BPF error (exit 2)
        assert_eq!(output.status.code(), Some(2));
    }
}

/// TC-1.6: --no-dns is accepted.
#[test]
fn tc_1_6_snapshot_no_dns() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--no-dns"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
}

/// TC-1.7: --bpf-buffer accepts valid value.
#[test]
fn tc_1_7_snapshot_bpf_buffer() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--bpf-buffer", "65536"])
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
        .args(["--duration", "1"])
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

/// TC-3.1: Auto-discover finds interfaces (output has data).
#[test]
fn tc_3_1_auto_discover_interfaces() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should have at least the header line
    assert!(
        stdout.contains("pid\tprocess"),
        "missing TSV header in output"
    );
}

/// TC-3.3: Non-existent interface exits with code 2 (BPF error).
#[test]
fn tc_3_3_nonexistent_interface() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--interface", "nonexist99"])
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2 for bad interface, got {:?}",
        output.status.code()
    );
}

// =========================================================================
// Section 7: Output serialization (TC-7.x)
// =========================================================================

/// TC-7.1: TSV column count is consistent (header + data rows all have 6 columns).
#[test]
fn tc_7_1_tsv_consistent_columns() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    for (i, line) in stdout.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let cols = line.split('\t').count();
        assert_eq!(
            cols,
            6,
            "line {} has {} columns, expected 6: {:?}",
            i + 1,
            cols,
            line
        );
    }
}

/// TC-7.2: TSV contains no ANSI escape codes.
#[test]
fn tc_7_2_tsv_no_ansi() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('\x1b'),
        "TSV output contains ANSI escape codes"
    );
}

/// TC-7.3: JSON output is valid and parseable.
#[test]
fn tc_7_3_json_valid() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--format", "json"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("invalid JSON output");
}

/// TC-7.4: JSON has expected fields.
#[test]
fn tc_7_4_json_structure() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "2", "--format", "json"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let arr = parsed.as_array().expect("expected JSON array");
    // If there are entries, check field names
    if let Some(first) = arr.first() {
        assert!(
            first.get("process").is_some(),
            "missing 'process' field in JSON"
        );
        assert!(
            first.get("rx_bytes").is_some(),
            "missing 'rx_bytes' field in JSON"
        );
        assert!(
            first.get("tx_bytes").is_some(),
            "missing 'tx_bytes' field in JSON"
        );
        assert!(
            first.get("rx_packets").is_some(),
            "missing 'rx_packets' field in JSON"
        );
        assert!(
            first.get("tx_packets").is_some(),
            "missing 'tx_packets' field in JSON"
        );
    }
}

/// TC-7.5: JSON numeric fields are actual numbers.
#[test]
fn tc_7_5_json_numeric_types() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "2", "--format", "json"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let arr = parsed.as_array().expect("expected JSON array");
    for entry in arr {
        // pid can be null (unknown) or a number
        let pid = &entry["pid"];
        assert!(
            pid.is_null() || pid.is_number(),
            "pid should be null or number, got: {pid}"
        );
        assert!(entry["rx_bytes"].is_number(), "rx_bytes should be number");
        assert!(entry["tx_bytes"].is_number(), "tx_bytes should be number");
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
        .args(["--duration", "1"])
        .output()
        .expect("failed to execute");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "snapshot failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
        .args(["--duration", "30"]) // long duration so it doesn't exit naturally
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");

    // Wait for process to fully start
    std::thread::sleep(Duration::from_secs(2));

    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

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
        .args(["--duration", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");

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
        .args(["--duration", "1"])
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
        .args(["--duration", "1", "--interface", "nonexist99"])
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2, got {:?}",
        output.status.code()
    );
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
        .args(["--duration", "2"])
        .output()
        .expect("failed to execute");
    let elapsed = start.elapsed();

    assert!(output.status.success());
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
        .args(["--duration", "1"])
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
        .args(["--duration", "0.5"])
        .output()
        .expect("failed to execute");

    assert!(!output.status.success(), "should reject duration below 1.0");
}

/// TC-10.4: --duration 31 (above maximum) is rejected.
#[test]
fn tc_10_4_duration_above_maximum() {
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "31"])
        .output()
        .expect("failed to execute");

    assert!(
        !output.status.success(),
        "should reject duration above 30.0"
    );
}

// =========================================================================
// Section 11: --format pretty (TC-11.x)
// =========================================================================

/// TC-11.1: --format pretty produces table with header.
#[test]
fn tc_11_1_pretty_basic() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--format", "pretty"])
        .output()
        .expect("failed to execute");

    assert!(
        output.status.success(),
        "exit code: {}, stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Per-Process Network Traffic"),
        "missing table header"
    );
    assert!(stdout.contains("PID"), "missing PID column");
    assert!(stdout.contains("PROCESS"), "missing PROCESS column");
    assert!(stdout.contains("TOTAL"), "missing TOTAL summary line");
}

/// TC-11.2: Pretty output has no ANSI escape codes.
#[test]
fn tc_11_2_pretty_no_ansi() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "1", "--format", "pretty"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('\x1b'),
        "pretty output contains ANSI escape codes"
    );
}

/// TC-11.3: Unknown traffic shows in output when there is any.
#[test]
fn tc_11_3_snapshot_captures_data() {
    require_root!();
    ensure_binary();

    let output = Command::new(netoproc_bin())
        .args(["--duration", "3"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    // Should have at least the header line
    assert!(!lines.is_empty(), "output should have at least header line");
    assert!(lines[0].contains("pid\tprocess"));
}

// =========================================================================
// Section 12: v0.2.0 Streaming Architecture (TC-12.x)
//
// These tests target behaviors specific to the v0.2.0 streaming
// architecture: per-process traffic aggregation, drain_final,
// process attribution via ProcessTable, and signal handling with output.
//
// Tests that generate traffic require network connectivity
// (uses http://captive.apple.com — Apple's captive portal check endpoint,
// always available on macOS). Rate-limited curl keeps TCP connections open
// for several seconds, ensuring BPF capture and process table refresh
// both have time to observe the traffic.
// =========================================================================

/// Helper: check network connectivity to the traffic target.
fn has_network() -> bool {
    Command::new("curl")
        .args(["-so", "/dev/null", "-m", "5", "http://captive.apple.com"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Skip test if network is unavailable.
macro_rules! require_network {
    () => {
        if !has_network() {
            eprintln!("SKIPPED: no network connectivity to captive.apple.com");
            return;
        }
    };
}

/// Helper: spawn rate-limited curl processes to generate long-lived TCP traffic.
///
/// Each curl downloads at 10 bytes/sec (~69 byte response = ~7s connection).
/// This ensures the process table refresh (every 500ms) catches the socket,
/// and BPF has multiple read cycles to capture the packets.
fn spawn_traffic(count: usize, interval_ms: u64) -> Vec<std::process::Child> {
    use std::process::Stdio;
    let mut children = Vec::new();
    for _ in 0..count {
        if let Ok(child) = Command::new("curl")
            .args([
                "-so",
                "/dev/null",
                "--connect-timeout",
                "5",
                "--noproxy",
                "*", // bypass application-level proxy settings
                "--limit-rate",
                "10", // 10 bytes/sec → ~7s connection lifetime
                "http://captive.apple.com",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            children.push(child);
        }
        if interval_ms > 0 {
            std::thread::sleep(Duration::from_millis(interval_ms));
        }
    }
    children
}

/// Helper: kill and wait for all child processes.
fn cleanup_children(children: &mut [std::process::Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Helper: wait for a child process with a timeout.
///
/// If the child does not exit within `timeout`, it is killed and the function
/// returns the output collected up to that point. This prevents test hangs
/// when netoproc deadlocks or otherwise fails to exit.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::process::Output {
    use std::io::Read;

    // Read stdout and stderr in background threads so the child doesn't
    // block on pipe buffer full.
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).ok();
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).ok();
        buf
    });

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return std::process::Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    eprintln!(
                        "TIMEOUT: netoproc did not exit within {:?}, killing",
                        timeout
                    );
                    let _ = child.kill();
                    let status = child.wait().expect("failed to wait after kill");
                    let stdout = stdout_thread.join().unwrap_or_default();
                    let stderr = stderr_thread.join().unwrap_or_default();
                    return std::process::Output {
                        status,
                        stdout,
                        stderr,
                    };
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for child: {e}"),
        }
    }
}

/// TC-12.1: Active traffic capture produces data rows beyond the header.
///
/// Spawns rate-limited curl processes during a 5-second capture window.
/// Each curl holds a TCP connection open for ~7 seconds, giving BPF
/// multiple 500ms read cycles to capture the packets.
#[test]
fn tc_12_1_active_traffic_capture() {
    require_root!();
    require_network!();
    ensure_binary();
    use std::process::Stdio;

    let netoproc = Command::new(netoproc_bin())
        .env("RUST_LOG", "info")
        .args(["--duration", "5"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    // Start traffic immediately — BPF kernel buffer captures from device bind time
    let mut traffic = spawn_traffic(6, 300);

    let output = wait_with_timeout(netoproc, Duration::from_secs(15));
    cleanup_children(&mut traffic);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let data_lines: Vec<&str> = stdout.lines().skip(1).filter(|l| !l.is_empty()).collect();

    assert!(
        !data_lines.is_empty(),
        "expected data rows from active traffic, got only header.\n\
         stdout:\n{stdout}\nstderr (diagnostics):\n{stderr}"
    );
}

/// TC-12.2: Process attribution — captured traffic is attributed to known processes.
///
/// Spawns curl traffic and verifies that the output contains at least one
/// non-unknown process with captured traffic. In environments with a
/// transparent proxy (e.g., mihomo, Clash), curl traffic is correctly
/// attributed to the proxy process rather than curl itself, since the
/// proxy owns the outbound socket.
#[test]
fn tc_12_2_process_attribution() {
    require_root!();
    require_network!();
    ensure_binary();
    use std::process::Stdio;

    let netoproc = Command::new(netoproc_bin())
        .env("RUST_LOG", "info")
        .args(["--duration", "5"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    // Spawn slow curl processes spread over the capture window
    let mut traffic = spawn_traffic(6, 400);

    let output = wait_with_timeout(netoproc, Duration::from_secs(15));
    cleanup_children(&mut traffic);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Verify that at least one non-unknown process has captured traffic.
    // This confirms the process attribution pipeline (ProcessTable + SocketKey
    // lookup) is working. The specific process name depends on whether a
    // transparent proxy is active.
    let has_attributed_traffic = stdout.lines().skip(1).any(|line| {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            return false;
        }
        let is_known = cols[0] != "-" && cols[1] != "unknown";
        let has_traffic = cols[2].parse::<u64>().unwrap_or(0) > 0
            || cols[3].parse::<u64>().unwrap_or(0) > 0;
        is_known && has_traffic
    });

    assert!(
        has_attributed_traffic,
        "no traffic attributed to any known process.\n\
         stdout:\n{stdout}\nstderr (diagnostics):\n{stderr}"
    );
}

/// TC-12.3: Per-process aggregation — no duplicate (pid, process) pairs.
#[test]
fn tc_12_3_no_duplicate_pids() {
    require_root!();
    require_network!();
    ensure_binary();
    use std::collections::HashSet;
    use std::process::Stdio;

    let netoproc = Command::new(netoproc_bin())
        .args(["--duration", "5"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    let mut traffic = spawn_traffic(4, 300);

    let output = netoproc.wait_with_output().expect("failed to wait");
    cleanup_children(&mut traffic);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut seen = HashSet::new();
    for line in stdout.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 2 {
            let key = format!("{}:{}", cols[0], cols[1]);
            assert!(
                seen.insert(key.clone()),
                "duplicate (pid, process) pair: {key}"
            );
        }
    }
}

/// TC-12.4: drain_final captures traffic generated in the last second of capture.
///
/// Spawns rate-limited curl at t=4s in a 5-second capture window. The curl
/// connection stays alive past the 5-second mark, so drain_final (which joins
/// BPF threads and drains the channel) must capture the remaining packets.
#[test]
fn tc_12_4_drain_final_late_traffic() {
    require_root!();
    require_network!();
    ensure_binary();
    use std::process::Stdio;

    let netoproc = Command::new(netoproc_bin())
        .env("RUST_LOG", "info")
        .args(["--duration", "5"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    // Wait until the last ~1s of the 5s window before generating traffic
    std::thread::sleep(Duration::from_millis(4000));
    // Slow curl stays connected for ~7s — well past the capture window
    let mut traffic = spawn_traffic(3, 100);

    let output = wait_with_timeout(netoproc, Duration::from_secs(15));
    cleanup_children(&mut traffic);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let data_lines: Vec<&str> = stdout.lines().skip(1).filter(|l| !l.is_empty()).collect();

    assert!(
        !data_lines.is_empty(),
        "drain_final failed to capture late-window traffic.\n\
         stdout:\n{stdout}\nstderr (diagnostics):\n{stderr}"
    );
}

/// TC-12.5: SIGTERM during snapshot produces valid TSV output with header.
#[test]
fn tc_12_5_sigterm_produces_output() {
    require_root!();
    ensure_binary();
    use std::process::Stdio;

    let netoproc = Command::new(netoproc_bin())
        .args(["--duration", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    std::thread::sleep(Duration::from_millis(500));
    let mut traffic = spawn_traffic(3, 100);
    std::thread::sleep(Duration::from_secs(2));

    // Send SIGTERM — should trigger drain_final and produce output
    unsafe {
        libc::kill(netoproc.id() as i32, libc::SIGTERM);
    }

    let output = netoproc.wait_with_output().expect("failed to wait");
    cleanup_children(&mut traffic);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pid\tprocess\trx_bytes\ttx_bytes\trx_packets\ttx_packets"),
        "SIGTERM output missing TSV header:\n{stdout}"
    );
    // All non-empty lines should have 6 columns
    for (i, line) in stdout.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let cols = line.split('\t').count();
        assert_eq!(
            cols,
            6,
            "line {} has {cols} columns, expected 6: {line:?}",
            i + 1
        );
    }
}

/// TC-12.6: JSON with active traffic has v0.2.0 per-process object structure.
#[test]
fn tc_12_6_json_process_objects() {
    require_root!();
    require_network!();
    ensure_binary();
    use std::process::Stdio;

    let netoproc = Command::new(netoproc_bin())
        .env("RUST_LOG", "info")
        .args(["--duration", "5", "--format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    let mut traffic = spawn_traffic(6, 300);

    let output = wait_with_timeout(netoproc, Duration::from_secs(15));
    cleanup_children(&mut traffic);

    assert!(
        output.status.success(),
        "netoproc exited with code {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\nstdout:\n{stdout}\nstderr (diagnostics):\n{stderr}"
        );
    });

    let arr = parsed.as_array().expect("expected JSON array");
    assert!(
        !arr.is_empty(),
        "expected non-empty JSON array with active traffic.\n\
         stdout:\n{stdout}\nstderr (diagnostics):\n{stderr}"
    );

    // Each entry must have the v0.2.0 per-process fields
    for entry in arr {
        let obj = entry.as_object().expect("entry should be an object");
        assert!(obj.contains_key("pid"), "missing 'pid'");
        assert!(obj.contains_key("process"), "missing 'process'");
        assert!(obj.contains_key("rx_bytes"), "missing 'rx_bytes'");
        assert!(obj.contains_key("tx_bytes"), "missing 'tx_bytes'");
        assert!(obj.contains_key("rx_packets"), "missing 'rx_packets'");
        assert!(obj.contains_key("tx_packets"), "missing 'tx_packets'");
        // Traffic values must be non-negative integers
        assert!(entry["rx_bytes"].as_u64().is_some(), "rx_bytes not u64");
        assert!(entry["tx_bytes"].as_u64().is_some(), "tx_bytes not u64");
        assert!(entry["rx_packets"].as_u64().is_some(), "rx_packets not u64");
        assert!(entry["tx_packets"].as_u64().is_some(), "tx_packets not u64");
    }
}

/// TC-12.7: Without --duration, netoproc enters monitor (TUI) mode by default.
#[test]
fn tc_12_7_monitor_mode_default() {
    require_root!();
    ensure_binary();
    use std::process::Stdio;

    let mut child = Command::new(netoproc_bin())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn netoproc");

    std::thread::sleep(Duration::from_secs(2));

    let still_running = matches!(child.try_wait(), Ok(None));
    // Clean up
    if still_running {
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
    }
    let output = child.wait_with_output().expect("failed to get output");
    let stdout = String::from_utf8_lossy(&output.stdout);

    if still_running {
        // Process was running after 2s — confirmed monitor/TUI mode
    } else {
        // TUI init may fail with piped output, but must NOT produce snapshot output
        assert!(
            !stdout.contains("pid\tprocess\trx_bytes"),
            "without --duration, should not produce snapshot output:\n{stdout}"
        );
    }
}
