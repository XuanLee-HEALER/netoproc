/// Formats a byte-rate (bytes per second) into a human-readable string with
/// auto-scaling units (base-10 / SI-like: 1 KB = 1000 bytes).
///
/// Output examples: `"0 B/s"`, `"512 B/s"`, `"1.5 KB/s"`, `"23.4 MB/s"`, `"1.2 GB/s"`.
pub fn format_rate(bytes_per_sec: f64) -> String {
    const KB: f64 = 1_000.0;
    const MB: f64 = 1_000_000.0;
    const GB: f64 = 1_000_000_000.0;

    if bytes_per_sec < KB {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < MB {
        format!("{:.1} KB/s", bytes_per_sec / KB)
    } else if bytes_per_sec < GB {
        format!("{:.1} MB/s", bytes_per_sec / MB)
    } else {
        format!("{:.1} GB/s", bytes_per_sec / GB)
    }
}

/// Formats a total byte count into a human-readable string with auto-scaling
/// units (base-10 / SI-like: 1 KB = 1000 bytes).
///
/// Output examples: `"0 B"`, `"512 B"`, `"1.5 KB"`, `"23.4 MB"`, `"1.2 GB"`.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1_000.0;
    const MB: f64 = 1_000_000.0;
    const GB: f64 = 1_000_000_000.0;

    let b = bytes as f64;

    if b < KB {
        format!("{} B", bytes)
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else {
        format!("{:.1} GB", b / GB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_rate ----

    #[test]
    fn rate_zero() {
        assert_eq!(format_rate(0.0), "0 B/s");
    }

    #[test]
    fn rate_bytes_range() {
        assert_eq!(format_rate(512.0), "512 B/s");
        assert_eq!(format_rate(999.0), "999 B/s");
    }

    #[test]
    fn rate_kilobytes() {
        assert_eq!(format_rate(1_000.0), "1.0 KB/s");
        assert_eq!(format_rate(1_500.0), "1.5 KB/s");
        assert_eq!(format_rate(999_999.0), "1000.0 KB/s");
    }

    #[test]
    fn rate_megabytes() {
        assert_eq!(format_rate(1_000_000.0), "1.0 MB/s");
        assert_eq!(format_rate(23_400_000.0), "23.4 MB/s");
    }

    #[test]
    fn rate_gigabytes() {
        assert_eq!(format_rate(1_000_000_000.0), "1.0 GB/s");
        assert_eq!(format_rate(1_200_000_000.0), "1.2 GB/s");
    }

    // ---- format_bytes ----

    #[test]
    fn bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn bytes_small() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(999), "999 B");
    }

    #[test]
    fn bytes_kilobytes() {
        assert_eq!(format_bytes(1_000), "1.0 KB");
        assert_eq!(format_bytes(1_500), "1.5 KB");
    }

    #[test]
    fn bytes_megabytes() {
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(23_400_000), "23.4 MB");
    }

    #[test]
    fn bytes_gigabytes() {
        assert_eq!(format_bytes(1_000_000_000), "1.0 GB");
        assert_eq!(format_bytes(1_200_000_000), "1.2 GB");
    }
}
