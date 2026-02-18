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

/// A single flattened connection row for display.
struct ConnectionRow {
    process: String,
    local: String,
    remote: String,
    proto: String,
    state: String,
    direction: String,
    interface: String,
    rx_rate: f64,
    tx_rate: f64,
    rx_total: u64,
    tx_total: u64,
}

/// Render the connection table view.
///
/// Columns: Process | Local | Remote | Proto | State | Dir | Iface | RX Rate | TX Rate | RX Total | TX Total
///
/// Each row is one connection, flattened from process -> socket -> connection.
/// `filter` is a case-insensitive substring match on process name.
/// `selected` is the zero-based index of the highlighted row.
pub fn render(
    frame: &mut Frame,
    area: Rect,
    state: &SystemNetworkState,
    filter: &str,
    selected: usize,
) {
    let filter_lower = filter.to_lowercase();

    // Flatten process -> socket -> connection into rows.
    let mut rows: Vec<ConnectionRow> = Vec::new();

    for proc in &state.processes {
        if !filter.is_empty() && !proc.name.to_lowercase().contains(&filter_lower) {
            continue;
        }

        for sock in &proc.sockets {
            for conn in &sock.connections {
                rows.push(ConnectionRow {
                    process: proc.name.clone(),
                    local: sock.local_addr.clone(),
                    remote: conn.remote_addr.clone(),
                    proto: sock.protocol.to_string(),
                    state: sock.state.to_string(),
                    direction: conn.direction.to_string(),
                    interface: if conn.interface.is_empty() {
                        "-".to_string()
                    } else {
                        conn.interface.clone()
                    },
                    rx_rate: conn.rx_rate.bytes_per_sec,
                    tx_rate: conn.tx_rate.bytes_per_sec,
                    rx_total: conn.rx_bytes_total,
                    tx_total: conn.tx_bytes_total,
                });
            }
        }
    }

    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("Process", header_style)),
        Cell::from(Span::styled("Local", header_style)),
        Cell::from(Span::styled("Remote", header_style)),
        Cell::from(Span::styled("Proto", header_style)),
        Cell::from(Span::styled("State", header_style)),
        Cell::from(Span::styled("Dir", header_style)),
        Cell::from(Span::styled("Iface", header_style)),
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
                Cell::from(r.process.clone()),
                Cell::from(r.local.clone()),
                Cell::from(r.remote.clone()),
                Cell::from(r.proto.clone()),
                Cell::from(r.state.clone()),
                Cell::from(r.direction.clone()),
                Cell::from(r.interface.clone()),
                Cell::from(fmt_rate(r.rx_rate)),
                Cell::from(fmt_rate(r.tx_rate)),
                Cell::from(fmt_bytes(r.rx_total)),
                Cell::from(fmt_bytes(r.tx_total)),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        ratatui::layout::Constraint::Length(14), // Process
        ratatui::layout::Constraint::Min(18),    // Local
        ratatui::layout::Constraint::Min(18),    // Remote
        ratatui::layout::Constraint::Length(6),  // Proto
        ratatui::layout::Constraint::Length(13), // State
        ratatui::layout::Constraint::Length(9),  // Dir
        ratatui::layout::Constraint::Length(7),  // Iface
        ratatui::layout::Constraint::Length(12), // RX Rate
        ratatui::layout::Constraint::Length(12), // TX Rate
        ratatui::layout::Constraint::Length(10), // RX Total
        ratatui::layout::Constraint::Length(10), // TX Total
    ];

    let table = Table::new(table_rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Connections "),
        )
        .row_highlight_style(selected_style);

    frame.render_widget(table, area);
}
