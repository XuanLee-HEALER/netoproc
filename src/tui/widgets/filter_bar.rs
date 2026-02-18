use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// A text-input widget for filtering the process/connection list.
///
/// When active, it captures keyboard input and updates the filter pattern.
/// The pattern can be retrieved with `pattern()` for use by the calling view.
pub struct FilterBar {
    input: String,
    active: bool,
}

impl FilterBar {
    /// Creates a new, empty, inactive filter bar.
    pub fn new() -> Self {
        Self {
            input: String::new(),
            active: false,
        }
    }

    /// Returns the current filter pattern, or `None` if the input is empty.
    pub fn pattern(&self) -> Option<&str> {
        if self.input.is_empty() {
            None
        } else {
            Some(&self.input)
        }
    }

    /// Returns whether the filter bar is currently capturing input.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Activates the filter bar so it begins capturing key events.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivates the filter bar. Does **not** clear the current input.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Handles a key event while the filter bar is active.
    ///
    /// Returns `true` if the event was consumed (i.e. the filter bar is
    /// active and processed the key), `false` otherwise.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if !self.active {
            return false;
        }

        match key.code {
            KeyCode::Char(c) => {
                // Ctrl+U clears the input
                if c == 'u' && key.modifiers.contains(KeyModifiers::CONTROL) {
                    self.input.clear();
                } else {
                    self.input.push(c);
                }
                true
            }
            KeyCode::Backspace => {
                self.input.pop();
                true
            }
            KeyCode::Esc => {
                self.input.clear();
                self.active = false;
                true
            }
            KeyCode::Enter => {
                // Confirm filter and deactivate input mode
                self.active = false;
                true
            }
            _ => true, // consume but ignore other keys while active
        }
    }

    /// Returns a `Paragraph` widget suitable for rendering in a ratatui layout.
    ///
    /// When active, the block border is highlighted and a cursor indicator is
    /// shown. When inactive with a filter, it displays the filter text.
    pub fn widget(&self) -> Paragraph<'_> {
        let (label, style, border_style) = if self.active {
            (
                "Filter: ",
                Style::default().fg(Color::Yellow),
                Style::default().fg(Color::Yellow),
            )
        } else if self.input.is_empty() {
            (
                "Press / to filter",
                Style::default().fg(Color::DarkGray),
                Style::default().fg(Color::DarkGray),
            )
        } else {
            (
                "Filter: ",
                Style::default().fg(Color::Green),
                Style::default().fg(Color::Green),
            )
        };

        let cursor = if self.active { "_" } else { "" };

        let line = Line::from(vec![
            Span::styled(label, style),
            Span::styled(
                self.input.as_str(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(cursor, Style::default().fg(Color::Yellow)),
        ]);

        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title("Filter"),
        )
    }
}

impl Default for FilterBar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key_event(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn key_event_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn initial_state() {
        let bar = FilterBar::new();
        assert!(!bar.is_active());
        assert_eq!(bar.pattern(), None);
    }

    #[test]
    fn activate_deactivate() {
        let mut bar = FilterBar::new();
        bar.activate();
        assert!(bar.is_active());
        bar.deactivate();
        assert!(!bar.is_active());
    }

    #[test]
    fn typing_characters() {
        let mut bar = FilterBar::new();
        bar.activate();
        bar.handle_key(key_event(KeyCode::Char('h')));
        bar.handle_key(key_event(KeyCode::Char('i')));
        assert_eq!(bar.pattern(), Some("hi"));
    }

    #[test]
    fn backspace_removes_last() {
        let mut bar = FilterBar::new();
        bar.activate();
        bar.handle_key(key_event(KeyCode::Char('a')));
        bar.handle_key(key_event(KeyCode::Char('b')));
        bar.handle_key(key_event(KeyCode::Backspace));
        assert_eq!(bar.pattern(), Some("a"));
    }

    #[test]
    fn backspace_on_empty_is_fine() {
        let mut bar = FilterBar::new();
        bar.activate();
        bar.handle_key(key_event(KeyCode::Backspace));
        assert_eq!(bar.pattern(), None);
    }

    #[test]
    fn escape_clears_and_deactivates() {
        let mut bar = FilterBar::new();
        bar.activate();
        bar.handle_key(key_event(KeyCode::Char('x')));
        bar.handle_key(key_event(KeyCode::Esc));
        assert!(!bar.is_active());
        assert_eq!(bar.pattern(), None);
    }

    #[test]
    fn enter_deactivates_but_keeps_text() {
        let mut bar = FilterBar::new();
        bar.activate();
        bar.handle_key(key_event(KeyCode::Char('f')));
        bar.handle_key(key_event(KeyCode::Enter));
        assert!(!bar.is_active());
        assert_eq!(bar.pattern(), Some("f"));
    }

    #[test]
    fn inactive_does_not_consume() {
        let mut bar = FilterBar::new();
        let consumed = bar.handle_key(key_event(KeyCode::Char('a')));
        assert!(!consumed);
        assert_eq!(bar.pattern(), None);
    }

    #[test]
    fn ctrl_u_clears_input() {
        let mut bar = FilterBar::new();
        bar.activate();
        bar.handle_key(key_event(KeyCode::Char('a')));
        bar.handle_key(key_event(KeyCode::Char('b')));
        bar.handle_key(key_event_ctrl(KeyCode::Char('u')));
        assert_eq!(bar.pattern(), None);
        assert!(bar.is_active()); // still active
    }

    #[test]
    fn widget_returns_paragraph() {
        let bar = FilterBar::new();
        // Just verify it doesn't panic
        let _p = bar.widget();
    }
}
