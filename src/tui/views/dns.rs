use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use crate::model::SystemNetworkState;

/// Render the DNS split-layout view.
///
/// Top half: resolver table (Interface | Server | Avg Latency | Fail% | Queries)
/// Bottom half: query log (Time | PID | Process | Query | Type | Response | Latency | Resolver)
///
/// `selected` is the zero-based index of the highlighted row in the query log.
pub fn render(frame: &mut Frame, area: Rect, state: &SystemNetworkState, selected: usize) {
    // Split area into top (resolvers) and bottom (queries).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_resolvers(frame, chunks[0], state);
    render_queries(frame, chunks[1], state, selected);
}

/// Render the resolver table in the top half.
fn render_resolvers(frame: &mut Frame, area: Rect, state: &SystemNetworkState) {
    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("Interface", header_style)),
        Cell::from(Span::styled("Server", header_style)),
        Cell::from(Span::styled("Avg Latency", header_style)),
        Cell::from(Span::styled("Fail %", header_style)),
        Cell::from(Span::styled("Queries", header_style)),
    ]);

    let rows: Vec<Row> = state
        .dns
        .resolvers
        .iter()
        .map(|r| {
            let latency_str = if r.avg_latency_ms > 0.0 {
                format!("{:.1} ms", r.avg_latency_ms)
            } else {
                "-".to_string()
            };

            let fail_str = if r.failure_rate_pct > 0.0 {
                format!("{:.1}%", r.failure_rate_pct)
            } else {
                "0%".to_string()
            };

            Row::new(vec![
                Cell::from(r.interface.clone()),
                Cell::from(r.server.clone()),
                Cell::from(latency_str),
                Cell::from(fail_str),
                Cell::from(r.query_count.to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12), // Interface
        Constraint::Min(16),    // Server
        Constraint::Length(12), // Avg Latency
        Constraint::Length(8),  // Fail %
        Constraint::Length(9),  // Queries
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" DNS Resolvers "),
    );

    frame.render_widget(table, area);
}

/// Render the query log table in the bottom half.
fn render_queries(frame: &mut Frame, area: Rect, state: &SystemNetworkState, selected: usize) {
    let header_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("Time", header_style)),
        Cell::from(Span::styled("PID", header_style)),
        Cell::from(Span::styled("Process", header_style)),
        Cell::from(Span::styled("Query", header_style)),
        Cell::from(Span::styled("Type", header_style)),
        Cell::from(Span::styled("Response", header_style)),
        Cell::from(Span::styled("Latency", header_style)),
        Cell::from(Span::styled("Resolver", header_style)),
    ]);

    let selected_style = Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default();

    // Show queries in reverse chronological order (newest first).
    let rows: Vec<Row> = state
        .dns
        .queries
        .iter()
        .rev()
        .enumerate()
        .map(|(i, q)| {
            let style = if i == selected {
                selected_style
            } else {
                normal_style
            };

            let time_str = format_timestamp_ms(q.timestamp_ms);

            let pid_str = match q.pid {
                Some(pid) => pid.to_string(),
                None => "-".to_string(),
            };

            let latency_str = if q.latency_ms > 0.0 {
                format!("{:.1} ms", q.latency_ms)
            } else {
                "-".to_string()
            };

            let resolver_str = if q.resolver.is_empty() {
                "-".to_string()
            } else {
                q.resolver.clone()
            };

            Row::new(vec![
                Cell::from(time_str),
                Cell::from(pid_str),
                Cell::from(q.process.clone()),
                Cell::from(q.query_name.clone()),
                Cell::from(q.query_type.clone()),
                Cell::from(q.response.clone()),
                Cell::from(latency_str),
                Cell::from(resolver_str),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(10), // Time
        Constraint::Length(7),  // PID
        Constraint::Length(14), // Process
        Constraint::Min(20),    // Query
        Constraint::Length(6),  // Type
        Constraint::Min(16),    // Response
        Constraint::Length(10), // Latency
        Constraint::Length(16), // Resolver
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" DNS Queries "),
        )
        .row_highlight_style(selected_style);

    frame.render_widget(table, area);
}

/// Format a millisecond timestamp into HH:MM:SS for display.
fn format_timestamp_ms(ts_ms: u64) -> String {
    let total_secs = ts_ms / 1000;
    let hours = (total_secs / 3600) % 24;
    let minutes = (total_secs / 60) % 60;
    let seconds = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp_ms() {
        // 12:30:45 => 45045 seconds => 45045000 ms
        assert_eq!(format_timestamp_ms(45_045_000), "12:30:45");
    }

    #[test]
    fn test_format_timestamp_ms_zero() {
        assert_eq!(format_timestamp_ms(0), "00:00:00");
    }

    #[test]
    fn test_format_timestamp_ms_wraps_24h() {
        // 25 hours => should wrap to 01:00:00
        let ms = 25 * 3600 * 1000;
        assert_eq!(format_timestamp_ms(ms), "01:00:00");
    }
}
