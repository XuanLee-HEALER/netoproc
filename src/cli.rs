use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "netoproc",
    version,
    about = "Per-process network traffic monitor for macOS and Linux"
)]
pub struct Cli {
    /// Snapshot mode: collect for N seconds then output and exit.
    /// Without this flag, monitor (TUI) mode runs by default.
    #[arg(long, value_parser = validate_duration)]
    pub duration: Option<f64>,

    /// Explicitly enter monitor (TUI) mode (default behavior)
    #[arg(long)]
    pub monitor: bool,

    /// Output format for snapshot mode
    #[arg(long, default_value = "tsv")]
    pub format: OutputFormat,

    /// Monitor only the specified network interface
    #[arg(long)]
    pub interface: Option<String>,

    /// Disable DNS observatory
    #[arg(long)]
    pub no_dns: bool,

    /// Capture buffer size in bytes
    #[arg(long = "capture-buffer", alias = "bpf-buffer", default_value_t = 2_097_152, value_parser = validate_capture_buffer)]
    pub bpf_buffer: u32,

    /// Initial sort column (monitor mode)
    #[arg(long, default_value = "traffic")]
    pub sort: SortColumn,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Filter by pattern
    #[arg(long)]
    pub filter: Option<String>,
}

impl Cli {
    /// Returns true if this invocation is snapshot mode.
    pub fn is_snapshot(&self) -> bool {
        self.duration.is_some()
    }

    /// Returns true if this invocation is monitor (TUI) mode.
    pub fn is_monitor(&self) -> bool {
        !self.is_snapshot()
    }

    /// Returns the snapshot duration, defaulting to 5.0 if in snapshot mode.
    pub fn snapshot_duration(&self) -> f64 {
        self.duration.unwrap_or(5.0)
    }
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

fn validate_capture_buffer(s: &str) -> Result<u32, String> {
    let val: u32 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid integer"))?;
    if val < 4096 {
        Err("capture-buffer must be at least 4096 bytes".to_string())
    } else if val > 16_777_216 {
        Err("capture-buffer must be at most 16777216 bytes (16MB)".to_string())
    } else {
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn parsed(args: &[&str]) -> Cli {
        parse(args).unwrap()
    }

    // UT-9.1: No arguments -> monitor mode (default)
    #[test]
    fn test_no_arguments() {
        let cli = parsed(&["netoproc"]);
        assert!(cli.is_monitor());
        assert!(!cli.is_snapshot());
        assert_eq!(cli.format, OutputFormat::Tsv);
    }

    // UT-9.2: --monitor explicit
    #[test]
    fn test_monitor_explicit() {
        let cli = parsed(&["netoproc", "--monitor"]);
        assert!(cli.is_monitor());
    }

    // UT-9.3: --duration triggers snapshot mode
    #[test]
    fn test_snapshot_with_duration() {
        let cli = parsed(&["netoproc", "--duration", "5"]);
        assert!(cli.is_snapshot());
        assert!(!cli.is_monitor());
        assert_eq!(cli.snapshot_duration(), 5.0);
    }

    // UT-9.4: Snapshot with JSON format
    #[test]
    fn test_snapshot_json() {
        let cli = parsed(&["netoproc", "--duration", "5", "--format", "json"]);
        assert_eq!(cli.format, OutputFormat::Json);
        assert!(cli.is_snapshot());
    }

    // UT-9.5: Snapshot with TSV format (explicit)
    #[test]
    fn test_snapshot_tsv() {
        let cli = parsed(&["netoproc", "--duration", "3", "--format", "tsv"]);
        assert_eq!(cli.format, OutputFormat::Tsv);
    }

    // UT-9.6: Invalid format
    #[test]
    fn test_invalid_format() {
        let result = parse(&["netoproc", "--format", "xml"]);
        assert!(result.is_err());
    }

    // UT-9.7: Interface flag
    #[test]
    fn test_interface_flag() {
        let cli = parsed(&["netoproc", "--interface", "en0"]);
        assert_eq!(cli.interface, Some("en0".to_string()));
    }

    // UT-9.8: No-dns flag
    #[test]
    fn test_no_dns_flag() {
        let cli = parsed(&["netoproc", "--no-dns"]);
        assert!(cli.no_dns);
    }

    // UT-9.9: Capture buffer valid
    #[test]
    fn test_bpf_buffer_valid() {
        let cli = parsed(&["netoproc", "--capture-buffer", "65536"]);
        assert_eq!(cli.bpf_buffer, 65536);
    }

    // UT-9.10: Capture buffer too small
    #[test]
    fn test_bpf_buffer_too_small() {
        let result = parse(&["netoproc", "--capture-buffer", "1024"]);
        assert!(result.is_err());
    }

    // UT-9.11: Capture buffer too large (>16MB)
    #[test]
    fn test_bpf_buffer_too_large() {
        let result = parse(&["netoproc", "--capture-buffer", "17000000"]);
        assert!(result.is_err());
    }

    // UT-9.12: Sort flag
    #[test]
    fn test_sort_flag() {
        let cli = parsed(&["netoproc", "--sort", "pid"]);
        assert_eq!(cli.sort, SortColumn::Pid);
    }

    // UT-9.13: Invalid sort value
    #[test]
    fn test_invalid_sort_value() {
        let result = parse(&["netoproc", "--sort", "invalid"]);
        assert!(result.is_err());
    }

    // UT-9.14: No-color flag
    #[test]
    fn test_no_color_flag() {
        let cli = parsed(&["netoproc", "--no-color"]);
        assert!(cli.no_color);
    }

    // UT-9.15: Filter flag
    #[test]
    fn test_filter_flag() {
        let cli = parsed(&["netoproc", "--filter", "curl"]);
        assert_eq!(cli.filter, Some("curl".to_string()));
    }

    // UT-9.16: Snapshot with --format pretty
    #[test]
    fn test_snapshot_pretty() {
        let cli = parsed(&["netoproc", "--duration", "5", "--format", "pretty"]);
        assert_eq!(cli.format, OutputFormat::Pretty);
        assert!(cli.is_snapshot());
    }

    // UT-9.17: Duration default when in snapshot mode
    #[test]
    fn test_duration_default() {
        let cli = parsed(&["netoproc", "--duration", "5"]);
        assert_eq!(cli.snapshot_duration(), 5.0);
    }

    // UT-9.18: Duration valid value
    #[test]
    fn test_duration_valid() {
        let cli = parsed(&["netoproc", "--duration", "10"]);
        assert_eq!(cli.duration, Some(10.0));
    }

    // UT-9.19: Duration too low (<1)
    #[test]
    fn test_duration_too_low() {
        let result = parse(&["netoproc", "--duration", "0.5"]);
        assert!(result.is_err());
    }

    // UT-9.20: Duration too high (>30)
    #[test]
    fn test_duration_too_high() {
        let result = parse(&["netoproc", "--duration", "60"]);
        assert!(result.is_err());
    }

    // UT-9.21: Capture buffer default is 2MB
    #[test]
    fn test_bpf_buffer_default() {
        let cli = parsed(&["netoproc"]);
        assert_eq!(cli.bpf_buffer, 2_097_152);
    }

    // UT-9.22: All flags combined
    #[test]
    fn test_all_flags_combined() {
        let cli = parsed(&[
            "netoproc",
            "--duration",
            "5",
            "--format",
            "json",
            "--interface",
            "en0",
            "--no-dns",
            "--capture-buffer",
            "65536",
            "--no-color",
            "--filter",
            "curl",
        ]);
        assert!(cli.is_snapshot());
        assert_eq!(cli.format, OutputFormat::Json);
        assert_eq!(cli.interface, Some("en0".to_string()));
        assert!(cli.no_dns);
        assert_eq!(cli.bpf_buffer, 65536);
        assert!(cli.no_color);
        assert_eq!(cli.filter, Some("curl".to_string()));
    }
}
