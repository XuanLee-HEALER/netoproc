use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "netoproc",
    version,
    about = "Per-process network traffic monitor for macOS"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Launch interactive TUI (default when no subcommand given)
    Monitor(MonitorArgs),
    /// Capture current state and output to stdout
    Snapshot(SnapshotArgs),
}

/// Arguments shared by all capture modes.
#[derive(Args, Debug, Clone)]
pub struct CaptureArgs {
    /// Polling/refresh interval in seconds [default: 1.0]
    #[arg(long, default_value_t = 1.0, value_parser = validate_interval)]
    pub interval: f64,

    /// Monitor only the specified network interface
    #[arg(long)]
    pub interface: Option<String>,

    /// Disable DNS observatory
    #[arg(long)]
    pub no_dns: bool,

    /// BPF kernel buffer size in bytes [default: 32768]
    #[arg(long, default_value_t = 32768, value_parser = validate_bpf_buffer)]
    pub bpf_buffer: u32,
}

impl Default for CaptureArgs {
    fn default() -> Self {
        Self {
            interval: 1.0,
            interface: None,
            no_dns: false,
            bpf_buffer: 32768,
        }
    }
}

/// Arguments specific to monitor (TUI) mode.
#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    #[command(flatten)]
    pub capture: CaptureArgs,

    /// Initial sort column
    #[arg(long, default_value = "traffic")]
    pub sort: SortColumn,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Filter output by pattern (matches process name, remote address, or domain)
    #[arg(long)]
    pub filter: Option<String>,
}

/// Arguments specific to snapshot mode.
#[derive(Args, Debug, Clone)]
pub struct SnapshotArgs {
    #[command(flatten)]
    pub capture: CaptureArgs,

    /// Output format [default: tsv]
    #[arg(long, default_value = "tsv")]
    pub format: OutputFormat,

    /// How long to collect traffic data before producing output, in seconds [default: 5.0]
    #[arg(long, default_value_t = 5.0, value_parser = validate_duration)]
    pub duration: f64,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Tsv,
    Json,
    Pretty,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Traffic,
    Pid,
    Name,
    Connections,
}

fn validate_interval(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;
    if val < 0.1 {
        Err("interval must be at least 0.1 seconds".to_string())
    } else if val > 10.0 {
        Err("interval must be at most 10.0 seconds".to_string())
    } else {
        Ok(val)
    }
}

fn validate_duration(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;
    if val < 1.0 {
        Err("duration must be at least 1.0 seconds".to_string())
    } else if val > 30.0 {
        Err("duration must be at most 30.0 seconds".to_string())
    } else {
        Ok(val)
    }
}

fn validate_bpf_buffer(s: &str) -> Result<u32, String> {
    let val: u32 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid integer"))?;
    if val < 4096 {
        Err("bpf-buffer must be at least 4096 bytes".to_string())
    } else if val > 1_048_576 {
        Err("bpf-buffer must be at most 1048576 bytes".to_string())
    } else {
        Ok(val)
    }
}

/// Flattened CLI configuration after resolving subcommand variants.
///
/// Field names mirror the old flat Cli struct so main.rs changes are minimal.
pub struct ResolvedCli {
    pub interval: f64,
    pub interface: Option<String>,
    pub no_dns: bool,
    pub bpf_buffer: u32,
    pub format: OutputFormat,
    pub sort: SortColumn,
    pub no_color: bool,
    pub filter: Option<String>,
    pub duration: f64,
    snapshot: bool,
}

impl ResolvedCli {
    pub fn is_monitor(&self) -> bool {
        !self.snapshot
    }
}

impl Cli {
    /// Resolve subcommand variants into a flat configuration struct.
    pub fn resolve(self) -> ResolvedCli {
        match self.command {
            Some(Command::Snapshot(s)) => ResolvedCli {
                interval: s.capture.interval,
                interface: s.capture.interface,
                no_dns: s.capture.no_dns,
                bpf_buffer: s.capture.bpf_buffer,
                format: s.format,
                sort: SortColumn::Traffic,
                no_color: false,
                filter: None,
                duration: s.duration,
                snapshot: true,
            },
            Some(Command::Monitor(m)) => ResolvedCli {
                interval: m.capture.interval,
                interface: m.capture.interface,
                no_dns: m.capture.no_dns,
                bpf_buffer: m.capture.bpf_buffer,
                format: OutputFormat::Tsv,
                sort: m.sort,
                no_color: m.no_color,
                filter: m.filter,
                duration: 0.0,
                snapshot: false,
            },
            None => ResolvedCli {
                interval: 1.0,
                interface: None,
                no_dns: false,
                bpf_buffer: 32768,
                format: OutputFormat::Tsv,
                sort: SortColumn::Traffic,
                no_color: false,
                filter: None,
                duration: 0.0,
                snapshot: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn resolved(args: &[&str]) -> ResolvedCli {
        parse(args).unwrap().resolve()
    }

    // UT-9.1: No arguments → defaults (monitor mode)
    #[test]
    fn test_no_arguments() {
        let cli = resolved(&["netoproc"]);
        assert!(cli.is_monitor());
        assert_eq!(cli.interval, 1.0);
        assert_eq!(cli.format, OutputFormat::Tsv);
    }

    // UT-9.2: Monitor explicit
    #[test]
    fn test_monitor_explicit() {
        let cli = resolved(&["netoproc", "monitor"]);
        assert!(cli.is_monitor());
    }

    // UT-9.3: Snapshot
    #[test]
    fn test_snapshot() {
        let cli = resolved(&["netoproc", "snapshot"]);
        assert!(!cli.is_monitor());
    }

    // UT-9.4: Snapshot with JSON (flags after subcommand)
    #[test]
    fn test_snapshot_json() {
        let cli = resolved(&["netoproc", "snapshot", "--format", "json"]);
        assert_eq!(cli.format, OutputFormat::Json);
        assert!(!cli.is_monitor());
    }

    // UT-9.5: Snapshot with TSV
    #[test]
    fn test_snapshot_tsv() {
        let cli = resolved(&["netoproc", "snapshot", "--format", "tsv"]);
        assert_eq!(cli.format, OutputFormat::Tsv);
    }

    // UT-9.6: Invalid format
    #[test]
    fn test_invalid_format() {
        let result = parse(&["netoproc", "snapshot", "--format", "xml"]);
        assert!(result.is_err());
    }

    // UT-9.7: Interval valid (on monitor subcommand)
    #[test]
    fn test_interval_valid() {
        let cli = resolved(&["netoproc", "monitor", "--interval", "0.5"]);
        assert_eq!(cli.interval, 0.5);
    }

    // UT-9.7b: Interval valid (on snapshot subcommand)
    #[test]
    fn test_interval_valid_snapshot() {
        let cli = resolved(&["netoproc", "snapshot", "--interval", "0.5"]);
        assert_eq!(cli.interval, 0.5);
    }

    // UT-9.8: Interval too low
    #[test]
    fn test_interval_too_low() {
        let result = parse(&["netoproc", "monitor", "--interval", "0.05"]);
        assert!(result.is_err());
    }

    // UT-9.9: Interval too high
    #[test]
    fn test_interval_too_high() {
        let result = parse(&["netoproc", "monitor", "--interval", "15"]);
        assert!(result.is_err());
    }

    // UT-9.10: Filter flag (monitor only)
    #[test]
    fn test_filter_flag() {
        let cli = resolved(&["netoproc", "monitor", "--filter", "curl"]);
        assert_eq!(cli.filter, Some("curl".to_string()));
    }

    // UT-9.11: Interface flag (shared capture arg)
    #[test]
    fn test_interface_flag() {
        let cli = resolved(&["netoproc", "snapshot", "--interface", "en0"]);
        assert_eq!(cli.interface, Some("en0".to_string()));
    }

    // UT-9.12: No-color flag (monitor only)
    #[test]
    fn test_no_color_flag() {
        let cli = resolved(&["netoproc", "monitor", "--no-color"]);
        assert!(cli.no_color);
    }

    // UT-9.13: No-dns flag (shared capture arg)
    #[test]
    fn test_no_dns_flag() {
        let cli = resolved(&["netoproc", "snapshot", "--no-dns"]);
        assert!(cli.no_dns);
    }

    // UT-9.14: BPF buffer valid
    #[test]
    fn test_bpf_buffer_valid() {
        let cli = resolved(&["netoproc", "snapshot", "--bpf-buffer", "65536"]);
        assert_eq!(cli.bpf_buffer, 65536);
    }

    // UT-9.15: BPF buffer too small
    #[test]
    fn test_bpf_buffer_too_small() {
        let result = parse(&["netoproc", "snapshot", "--bpf-buffer", "1024"]);
        assert!(result.is_err());
    }

    // UT-9.16: BPF buffer too large
    #[test]
    fn test_bpf_buffer_too_large() {
        let result = parse(&["netoproc", "snapshot", "--bpf-buffer", "2000000"]);
        assert!(result.is_err());
    }

    // UT-9.17: Sort flag (monitor only)
    #[test]
    fn test_sort_flag() {
        let cli = resolved(&["netoproc", "monitor", "--sort", "pid"]);
        assert_eq!(cli.sort, SortColumn::Pid);
    }

    // UT-9.18: Invalid sort value
    #[test]
    fn test_invalid_sort_value() {
        let result = parse(&["netoproc", "monitor", "--sort", "invalid"]);
        assert!(result.is_err());
    }

    // UT-9.19: --format is snapshot-only, not accepted on monitor
    #[test]
    fn test_format_not_on_monitor() {
        let result = parse(&["netoproc", "monitor", "--format", "json"]);
        assert!(result.is_err());
    }

    // UT-9.20: --sort is monitor-only, not accepted on snapshot
    #[test]
    fn test_sort_not_on_snapshot() {
        let result = parse(&["netoproc", "snapshot", "--sort", "pid"]);
        assert!(result.is_err());
    }

    // UT-9.21: Snapshot with --format pretty
    #[test]
    fn test_snapshot_pretty() {
        let cli = resolved(&["netoproc", "snapshot", "--format", "pretty"]);
        assert_eq!(cli.format, OutputFormat::Pretty);
        assert!(!cli.is_monitor());
    }

    // UT-9.22: Duration default is 5.0
    #[test]
    fn test_duration_default() {
        let cli = resolved(&["netoproc", "snapshot"]);
        assert_eq!(cli.duration, 5.0);
    }

    // UT-9.23: Duration valid value
    #[test]
    fn test_duration_valid() {
        let cli = resolved(&["netoproc", "snapshot", "--duration", "10"]);
        assert_eq!(cli.duration, 10.0);
    }

    // UT-9.24: Duration too low (<1)
    #[test]
    fn test_duration_too_low() {
        let result = parse(&["netoproc", "snapshot", "--duration", "0.5"]);
        assert!(result.is_err());
    }

    // UT-9.25: Duration too high (>30)
    #[test]
    fn test_duration_too_high() {
        let result = parse(&["netoproc", "snapshot", "--duration", "60"]);
        assert!(result.is_err());
    }

    // UT-9.26: Duration is snapshot-only, not accepted on monitor
    #[test]
    fn test_duration_not_on_monitor() {
        let result = parse(&["netoproc", "monitor", "--duration", "5"]);
        assert!(result.is_err());
    }
}
