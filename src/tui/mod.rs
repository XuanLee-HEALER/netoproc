pub mod event;
pub mod theme;
pub mod views;
pub mod widgets;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossterm::ExecutableCommand;
use crossterm::event::{KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Tabs};

use crate::cli::SortColumn;
use crate::error::NetopError;
use crate::model::SystemNetworkState;

use self::event::{Event, EventHandler};
use self::views::View;
use self::widgets::FilterBar;

const MIN_COLS: u16 = 80;
const MIN_ROWS: u16 = 24;

/// TUI application state.
pub struct App {
    pub current_view: View,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub filter_bar: FilterBar,
    pub scroll_position: usize,
    pub should_quit: bool,
    pub show_help: bool,
    pub no_color: bool,
}

impl App {
    pub fn new(sort_column: SortColumn, no_color: bool, initial_filter: Option<&str>) -> Self {
        let mut filter_bar = FilterBar::new();
        if let Some(pattern) = initial_filter {
            filter_bar.activate();
            for ch in pattern.chars() {
                filter_bar.handle_key(crossterm::event::KeyEvent::new(
                    KeyCode::Char(ch),
                    KeyModifiers::NONE,
                ));
            }
            filter_bar.deactivate();
        }

        let no_color = no_color || std::env::var("NO_COLOR").is_ok();

        Self {
            current_view: View::Process,
            sort_column,
            sort_ascending: false,
            filter_bar,
            scroll_position: 0,
            should_quit: false,
            show_help: false,
            no_color,
        }
    }

    fn filter_text(&self) -> &str {
        self.filter_bar.pattern().unwrap_or("")
    }
}

/// Run the interactive TUI event loop.
///
/// This takes ownership of the terminal and runs until the user quits.
/// The `shared_state` is read on each tick for the latest network data.
pub fn run_tui(
    shared_state: Arc<ArcSwap<SystemNetworkState>>,
    interval: Duration,
    sort_column: SortColumn,
    no_color: bool,
    initial_filter: Option<&str>,
    shutdown: &AtomicBool,
) -> Result<(), NetopError> {
    // Check terminal size before entering alternate screen.
    let (cols, rows) = crossterm::terminal::size().map_err(|e| {
        NetopError::Tui(io::Error::other(format!("cannot query terminal size: {e}")))
    })?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err(NetopError::Tui(io::Error::other(format!(
            "terminal too small ({cols}x{rows}), minimum {MIN_COLS}x{MIN_ROWS}"
        ))));
    }

    // Enter raw mode + alternate screen.
    enable_raw_mode().map_err(|e| NetopError::Tui(io::Error::other(e.to_string())))?;
    io::stdout()
        .execute(EnterAlternateScreen)
        .map_err(|e| NetopError::Tui(io::Error::other(e.to_string())))?;

    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| NetopError::Tui(io::Error::other(e.to_string())))?;

    let mut app = App::new(sort_column, no_color, initial_filter);
    let events = EventHandler::new(interval);

    let result = run_event_loop(&mut terminal, &mut app, &events, &shared_state, shutdown);

    // Restore terminal regardless of success/failure.
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);

    result
}

fn run_event_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut App,
    events: &EventHandler,
    shared_state: &Arc<ArcSwap<SystemNetworkState>>,
    shutdown: &AtomicBool,
) -> Result<(), NetopError> {
    loop {
        // Render current state.
        let state = shared_state.load();
        terminal
            .draw(|frame| render(frame, app, &state))
            .map_err(|e| NetopError::Tui(io::Error::other(e.to_string())))?;

        if app.should_quit {
            return Ok(());
        }

        // Wait for next event.
        match events.next() {
            Ok(Event::Key(key)) => {
                // Filter bar captures keys when active.
                if app.filter_bar.is_active() {
                    app.filter_bar.handle_key(key);
                    continue;
                }
                handle_key(app, key);
            }
            Ok(Event::Resize(_, _)) => {
                // ratatui handles resize automatically on next draw.
            }
            Ok(Event::Tick) => {
                if shutdown.load(Ordering::Relaxed) {
                    app.should_quit = true;
                }
            }
            Err(_) => {
                // Channel disconnected — exit.
                app.should_quit = true;
            }
        }
    }
}

fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) {
    match key.code {
        // Quit
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }

        // View switching
        KeyCode::Tab => {
            app.current_view = app.current_view.next();
            app.scroll_position = 0;
        }
        KeyCode::BackTab => {
            app.current_view = app.current_view.prev();
            app.scroll_position = 0;
        }
        KeyCode::Char('1') => {
            app.current_view = View::Process;
            app.scroll_position = 0;
        }
        KeyCode::Char('2') => {
            app.current_view = View::Connection;
            app.scroll_position = 0;
        }
        KeyCode::Char('3') => {
            app.current_view = View::Interface;
            app.scroll_position = 0;
        }
        KeyCode::Char('4') => {
            app.current_view = View::Dns;
            app.scroll_position = 0;
        }

        // Filter
        KeyCode::Char('/') => {
            app.filter_bar.activate();
        }

        // Sort
        KeyCode::Char('s') => {
            app.sort_column = match app.sort_column {
                SortColumn::Traffic => SortColumn::Pid,
                SortColumn::Pid => SortColumn::Name,
                SortColumn::Name => SortColumn::Connections,
                SortColumn::Connections => SortColumn::Traffic,
            };
        }
        KeyCode::Char('S') => {
            app.sort_ascending = !app.sort_ascending;
        }

        // Navigation
        KeyCode::Up => {
            app.scroll_position = app.scroll_position.saturating_sub(1);
        }
        KeyCode::Down => {
            app.scroll_position = app.scroll_position.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.scroll_position = app.scroll_position.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.scroll_position = app.scroll_position.saturating_add(20);
        }
        KeyCode::Home => {
            app.scroll_position = 0;
        }
        KeyCode::End => {
            app.scroll_position = usize::MAX;
        }

        // Help overlay
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
        }

        // Escape closes help
        KeyCode::Esc => {
            if app.show_help {
                app.show_help = false;
            }
        }

        _ => {}
    }
}

fn render(frame: &mut ratatui::Frame, app: &App, state: &SystemNetworkState) {
    let size = frame.area();

    // Check terminal size.
    if size.width < MIN_COLS || size.height < MIN_ROWS {
        let msg = format!(
            "Terminal too small ({0}x{1}). Minimum: {MIN_COLS}x{MIN_ROWS}. Please resize.",
            size.width, size.height
        );
        let paragraph = Paragraph::new(msg)
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL).title("netoproc"));
        frame.render_widget(paragraph, size);
        return;
    }

    // Layout: tab bar (3 lines) + filter bar (3 lines) + content (rest).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Length(3), // Filter bar
            Constraint::Min(10),   // Content area
        ])
        .split(size);

    // Tab bar.
    render_tabs(frame, chunks[0], app);

    // Filter bar.
    let filter_widget = app.filter_bar.widget();
    frame.render_widget(filter_widget, chunks[1]);

    // Content area — dispatch to current view.
    let filter = app.filter_text();
    let selected = app.scroll_position;
    match app.current_view {
        View::Process => {
            views::process::render(frame, chunks[2], state, filter, selected);
        }
        View::Connection => {
            views::connection::render(frame, chunks[2], state, filter, selected);
        }
        View::Interface => {
            views::interface::render(frame, chunks[2], state);
        }
        View::Dns => {
            views::dns::render(frame, chunks[2], state, selected);
        }
    }

    // Help overlay on top of everything.
    if app.show_help {
        render_help_overlay(frame, size);
    }
}

fn render_tabs(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let titles: Vec<Line<'_>> = [View::Process, View::Connection, View::Interface, View::Dns]
        .iter()
        .map(|v| {
            let style = if *v == app.current_view {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Line::from(Span::styled(v.title(), style))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" netoproc "))
        .select(app.current_view.index())
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::raw(" | "));

    frame.render_widget(tabs, area);
}

fn render_help_overlay(frame: &mut ratatui::Frame, area: Rect) {
    // Center the help box.
    let help_width = 50u16.min(area.width.saturating_sub(4));
    let help_height = 20u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(help_width)) / 2;
    let y = (area.height.saturating_sub(help_height)) / 2;
    let help_area = Rect::new(x, y, help_width, help_height);

    let help_text = vec![
        Line::from(Span::styled(
            "Keyboard Shortcuts",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from("  q / Ctrl-C    Quit"),
        Line::from("  Tab           Next view"),
        Line::from("  Shift-Tab     Previous view"),
        Line::from("  1-4           Jump to view"),
        Line::from("  /             Open filter"),
        Line::from("  Esc           Close filter/help"),
        Line::from("  s             Cycle sort column"),
        Line::from("  S             Reverse sort"),
        Line::from("  Up/Down       Navigate rows"),
        Line::from("  PgUp/PgDn     Page scroll"),
        Line::from("  Home/End      Jump to top/bottom"),
        Line::from("  ?             Toggle this help"),
        Line::from(""),
        Line::from(Span::styled(
            "Press ? or Esc to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let help = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Help ")
            .style(Style::default().bg(Color::Black)),
    );

    frame.render_widget(Clear, help_area);
    frame.render_widget(help, help_area);
}
