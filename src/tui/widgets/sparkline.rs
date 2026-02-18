/// Unicode block characters used for sparkline rendering, from lowest to highest.
const BLOCKS: [char; 8] = [
    '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}',
];

/// Renders a sequence of `u64` data points as a Unicode sparkline string.
///
/// The output has exactly `width` characters. If `data` has more points than
/// `width`, only the last `width` values are used. If `data` has fewer, the
/// string is left-padded with spaces.
///
/// Each value is mapped to one of the 8 Unicode block characters (▁▂▃▄▅▆▇█)
/// proportionally between 0 and the maximum value in the visible window. A
/// value of 0 when the max is also 0 renders as the lowest block (▁).
pub fn sparkline_string(data: &[u64], width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    // Take the last `width` data points (or fewer if data is shorter).
    let visible: &[u64] = if data.len() > width {
        &data[data.len() - width..]
    } else {
        data
    };

    let max_val = visible.iter().copied().max().unwrap_or(0);

    let mut result = String::with_capacity(width * 4); // UTF-8 block chars are 3 bytes

    // Left-pad with spaces if data is shorter than width
    let padding = width.saturating_sub(visible.len());
    for _ in 0..padding {
        result.push(' ');
    }

    for &val in visible {
        if max_val == 0 {
            result.push(BLOCKS[0]);
        } else {
            // Map value to block index 0..7
            let idx = ((val as f64 / max_val as f64) * 7.0).round() as usize;
            let idx = idx.min(7);
            result.push(BLOCKS[idx]);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data() {
        let s = sparkline_string(&[], 5);
        assert_eq!(s, "     ");
        assert_eq!(s.chars().count(), 5);
    }

    #[test]
    fn zero_width() {
        let s = sparkline_string(&[1, 2, 3], 0);
        assert_eq!(s, "");
    }

    #[test]
    fn all_zeros() {
        let s = sparkline_string(&[0, 0, 0], 3);
        assert_eq!(s, "▁▁▁");
    }

    #[test]
    fn single_value() {
        let s = sparkline_string(&[100], 5);
        // Should be 4 spaces + 1 block
        assert_eq!(s.chars().count(), 5);
        assert_eq!(s.chars().last(), Some('█'));
    }

    #[test]
    fn ascending() {
        let s = sparkline_string(&[0, 1, 2, 3, 4, 5, 6, 7], 8);
        assert_eq!(s, "▁▂▃▄▅▆▇█");
    }

    #[test]
    fn truncates_to_width() {
        let data: Vec<u64> = (0..20).collect();
        let s = sparkline_string(&data, 5);
        // Should only use last 5 values: 15, 16, 17, 18, 19
        assert_eq!(s.chars().count(), 5);
    }

    #[test]
    fn uniform_values_are_max_block() {
        let s = sparkline_string(&[42, 42, 42], 3);
        // All equal and nonzero => all map to index 7 (█)
        assert_eq!(s, "███");
    }
}
