use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};

use crate::model::{InterfaceStatus, SystemNetworkState};

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

/// Render the interface card-style view.
///
/// Each interface gets its own bordered block showing:
/// - Name and status
/// - IPv4 / IPv6 addresses
/// - RX/TX rates and totals
/// - Packet counts and errors
/// - Sparklines for RX/TX history
pub fn render(frame: &mut Frame, area: Rect, state: &SystemNetworkState) {
    if state.interfaces.is_empty() {
        let block = Block::default().borders(Borders::ALL).title(" Interfaces ");
        let paragraph = Paragraph::new("No interfaces found")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(paragraph, area);
        return;
    }

    // Each interface card needs roughly 10 rows: border top, status, IPs, rates, totals,
    // packets, errors, sparkline RX, sparkline TX, border bottom.
    let card_height: u16 = 12;
    let iface_count = state.interfaces.len();

    let constraints: Vec<Constraint> = state
        .interfaces
        .iter()
        .enumerate()
        .map(|(i, _)| {
            if i < iface_count - 1 {
                Constraint::Length(card_height)
            } else {
                // Last card takes remaining space.
                Constraint::Min(card_height)
            }
        })
        .collect();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    for (i, iface) in state.interfaces.iter().enumerate() {
        if i >= chunks.len() {
            break;
        }
        render_interface_card(frame, chunks[i], iface);
    }
}

/// Render a single interface card.
fn render_interface_card(frame: &mut Frame, area: Rect, iface: &crate::model::Interface) {
    let status_color = match iface.status {
        InterfaceStatus::Up => Color::Green,
        InterfaceStatus::Down => Color::Red,
    };

    let title = format!(" {} [{}] ", iface.name, iface.status);
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        title,
        Style::default()
            .fg(status_color)
            .add_modifier(Modifier::BOLD),
    ));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Split inner area: top for text info, bottom for sparklines.
    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Text info lines
            Constraint::Min(1),    // RX sparkline
            Constraint::Min(1),    // TX sparkline
        ])
        .split(inner);

    // Build info lines.
    let label_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let value_style = Style::default().fg(Color::White);

    let ipv4_str = if iface.ipv4_addresses.is_empty() {
        "-".to_string()
    } else {
        iface.ipv4_addresses.join(", ")
    };

    let ipv6_str = if iface.ipv6_addresses.is_empty() {
        "-".to_string()
    } else {
        iface.ipv6_addresses.join(", ")
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  IPv4: ", label_style),
            Span::styled(ipv4_str, value_style),
        ]),
        Line::from(vec![
            Span::styled("  IPv6: ", label_style),
            Span::styled(ipv6_str, value_style),
        ]),
        Line::from(vec![
            Span::styled("  Rate: ", label_style),
            Span::styled(
                format!(
                    "RX {} / TX {}",
                    fmt_rate(iface.rx_bytes_rate),
                    fmt_rate(iface.tx_bytes_rate)
                ),
                value_style,
            ),
        ]),
        Line::from(vec![
            Span::styled(" Total: ", label_style),
            Span::styled(
                format!(
                    "RX {} / TX {}",
                    fmt_bytes(iface.rx_bytes_total),
                    fmt_bytes(iface.tx_bytes_total)
                ),
                value_style,
            ),
        ]),
        Line::from(vec![
            Span::styled("  Pkts: ", label_style),
            Span::styled(
                format!(
                    "RX {} / TX {}  Errors: RX {} / TX {}",
                    iface.rx_packets, iface.tx_packets, iface.rx_errors, iface.tx_errors
                ),
                value_style,
            ),
        ]),
    ];

    let info = Paragraph::new(lines);
    frame.render_widget(info, content_chunks[0]);

    // RX sparkline
    let rx_data: Vec<u64> = iface.rx_timeseries.sparkline_data();
    // Reverse so newest is on the right
    let rx_display: Vec<u64> = rx_data.into_iter().rev().collect();
    let rx_sparkline = Sparkline::default()
        .block(Block::default().title(Span::styled("RX", Style::default().fg(Color::Green))))
        .data(&rx_display)
        .style(Style::default().fg(Color::Green));
    frame.render_widget(rx_sparkline, content_chunks[1]);

    // TX sparkline
    let tx_data: Vec<u64> = iface.tx_timeseries.sparkline_data();
    let tx_display: Vec<u64> = tx_data.into_iter().rev().collect();
    let tx_sparkline = Sparkline::default()
        .block(Block::default().title(Span::styled("TX", Style::default().fg(Color::Blue))))
        .data(&tx_display)
        .style(Style::default().fg(Color::Blue));
    frame.render_widget(tx_sparkline, content_chunks[2]);
}
