use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use crate::model::SystemNetworkState;

/// Format a byte rate (bytes/sec) into a human-readable string with auto-scaling.
fn fmt_rate(bps: f64) -> String {
    if bps < 1.0 {
        "0 B/s".to_string()
    } else if bps < 1024.0 {
        format!("{:.0} B/s", bps)
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else if bps < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bps / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", bps / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format a byte count into a human-readable string with auto-scaling.
fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Aggregated per-process row data for display.
struct ProcessRow {
    pid: u32,
    name: String,
    username: String,
    sockets: usize,
    conns: usize,
    rx_rate: f64,
    tx_rate: f64,
    rx_total: u64,
    tx_total: u64,
}

/// Render the process table view.
///
/// Columns: PID | Process | User | Sockets | Conns | RX Rate | TX Rate | RX Total | TX Total
///
/// `filter` is a case-insensitive substring match on the process name.
/// `selected` is the zero-based index of the highlighted row.
pub fn render(
    frame: &mut Frame,
    area: Rect,
    state: &SystemNetworkState,
    filter: &str,
    selected: usize,
) {
    let filter_lower = filter.to_lowercase();

    // Build aggregated rows, applying the filter.
    let mut rows: Vec<ProcessRow> = state
        .processes
        .iter()
        .filter(|p| filter.is_empty() || p.name.to_lowercase().contains(&filter_lower))
        .map(|p| {
            let sockets = p.sockets.len();
            let conns: usize = p.sockets.iter().map(|s| s.connections.len()).sum();
            let rx_rate: f64 = p
                .sockets
                .iter()
                .flat_map(|s| &s.connections)
                .map(|c| c.rx_rate.bytes_per_sec)
                .sum();
            let tx_rate: f64 = p
                .sockets
                .iter()
                .flat_map(|s| &s.connections)
                .map(|c| c.tx_rate.bytes_per_sec)
                .sum();
            let rx_total: u64 = p
                .sockets
                .iter()
                .flat_map(|s| &s.connections)
                .map(|c| c.rx_bytes_total)
                .sum();
            let tx_total: u64 = p
                .sockets
                .iter()
                .flat_map(|s| &s.connections)
                .map(|c| c.tx_bytes_total)
                .sum();

            ProcessRow {
                pid: p.pid,
                name: p.name.clone(),
                username: p.username.clone(),
                sockets,
                conns,
                rx_rate,
                tx_rate,
                rx_total,
                tx_total,
            }
        })
        .collect();

    // Sort by TX rate descending (most active processes first).
    rows.sort_by(|a, b| {
        b.tx_rate
            .partial_cmp(&a.tx_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("PID", header_style)),
        Cell::from(Span::styled("Process", header_style)),
        Cell::from(Span::styled("User", header_style)),
        Cell::from(Span::styled("Sockets", header_style)),
        Cell::from(Span::styled("Conns", header_style)),
        Cell::from(Span::styled("RX Rate", header_style)),
        Cell::from(Span::styled("TX Rate", header_style)),
        Cell::from(Span::styled("RX Total", header_style)),
        Cell::from(Span::styled("TX Total", header_style)),
    ]);

    let selected_style = Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default();

    let table_rows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let style = if i == selected {
                selected_style
            } else {
                normal_style
            };
            Row::new(vec![
                Cell::from(r.pid.to_string()),
                Cell::from(r.name.clone()),
                Cell::from(r.username.clone()),
                Cell::from(r.sockets.to_string()),
                Cell::from(r.conns.to_string()),
                Cell::from(fmt_rate(r.rx_rate)),
                Cell::from(fmt_rate(r.tx_rate)),
                Cell::from(fmt_bytes(r.rx_total)),
                Cell::from(fmt_bytes(r.tx_total)),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        ratatui::layout::Constraint::Length(8),  // PID
        ratatui::layout::Constraint::Min(12),    // Process
        ratatui::layout::Constraint::Length(10), // User
        ratatui::layout::Constraint::Length(8),  // Sockets
        ratatui::layout::Constraint::Length(7),  // Conns
        ratatui::layout::Constraint::Length(12), // RX Rate
        ratatui::layout::Constraint::Length(12), // TX Rate
        ratatui::layout::Constraint::Length(10), // RX Total
        ratatui::layout::Constraint::Length(10), // TX Total
    ];

    let table = Table::new(table_rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Processes "))
        .row_highlight_style(selected_style);

    frame.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_rate_zero() {
        assert_eq!(fmt_rate(0.0), "0 B/s");
    }

    #[test]
    fn test_fmt_rate_bytes() {
        assert_eq!(fmt_rate(512.0), "512 B/s");
    }

    #[test]
    fn test_fmt_rate_kb() {
        assert_eq!(fmt_rate(2048.0), "2.0 KB/s");
    }

    #[test]
    fn test_fmt_rate_mb() {
        assert_eq!(fmt_rate(5.0 * 1024.0 * 1024.0), "5.0 MB/s");
    }

    #[test]
    fn test_fmt_rate_gb() {
        assert_eq!(fmt_rate(2.5 * 1024.0 * 1024.0 * 1024.0), "2.5 GB/s");
    }

    #[test]
    fn test_fmt_bytes_zero() {
        assert_eq!(fmt_bytes(0), "0 B");
    }

    #[test]
    fn test_fmt_bytes_kb() {
        assert_eq!(fmt_bytes(2048), "2.0 KB");
    }

    #[test]
    fn test_fmt_bytes_mb() {
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn test_fmt_bytes_gb() {
        // 2 GB
        assert_eq!(fmt_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }
}
