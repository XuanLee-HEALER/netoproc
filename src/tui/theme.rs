use ratatui::style::{Color, Modifier, Style};

/// Color theme for TUI rendering.
///
/// Respects the NO_COLOR convention: when `no_color` is true, all color
/// methods return `Color::Reset` / unstyled values.
pub struct Theme {
    pub no_color: bool,
}

impl Theme {
    pub fn new(no_color: bool) -> Self {
        Self { no_color }
    }

    /// Returns a color representing the severity of a network rate.
    ///
    /// - Green  when `bytes_per_sec` < 1024
    /// - Yellow when 1024 <= `bytes_per_sec` <= 102400
    /// - Red    when `bytes_per_sec` > 102400
    ///
    /// If `no_color` is set, always returns `Color::Reset`.
    pub fn rate_color(&self, bytes_per_sec: f64) -> Color {
        if self.no_color {
            return Color::Reset;
        }
        if bytes_per_sec < 1024.0 {
            Color::Green
        } else if bytes_per_sec <= 102_400.0 {
            Color::Yellow
        } else {
            Color::Red
        }
    }

    /// Style for table/column headers: bold, cyan foreground.
    pub fn header_style(&self) -> Style {
        if self.no_color {
            return Style::default().add_modifier(Modifier::BOLD);
        }
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for the currently selected / highlighted row.
    pub fn selected_style(&self) -> Style {
        if self.no_color {
            return Style::default().add_modifier(Modifier::REVERSED);
        }
        Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    }

    /// Normal (unselected) row style.
    pub fn normal_style(&self) -> Style {
        if self.no_color {
            return Style::default();
        }
        Style::default().fg(Color::Gray)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_color_green_below_threshold() {
        let theme = Theme::new(false);
        assert_eq!(theme.rate_color(0.0), Color::Green);
        assert_eq!(theme.rate_color(500.0), Color::Green);
        assert_eq!(theme.rate_color(1023.9), Color::Green);
    }

    #[test]
    fn rate_color_yellow_in_middle() {
        let theme = Theme::new(false);
        assert_eq!(theme.rate_color(1024.0), Color::Yellow);
        assert_eq!(theme.rate_color(50_000.0), Color::Yellow);
        assert_eq!(theme.rate_color(102_400.0), Color::Yellow);
    }

    #[test]
    fn rate_color_red_above_threshold() {
        let theme = Theme::new(false);
        assert_eq!(theme.rate_color(102_401.0), Color::Red);
        assert_eq!(theme.rate_color(1_000_000.0), Color::Red);
    }

    #[test]
    fn no_color_always_reset() {
        let theme = Theme::new(true);
        assert_eq!(theme.rate_color(0.0), Color::Reset);
        assert_eq!(theme.rate_color(50_000.0), Color::Reset);
        assert_eq!(theme.rate_color(1_000_000.0), Color::Reset);
    }

    #[test]
    fn header_style_colored() {
        let theme = Theme::new(false);
        let expected = Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        assert_eq!(theme.header_style(), expected);
    }

    #[test]
    fn header_style_no_color() {
        let theme = Theme::new(true);
        let expected = Style::default().add_modifier(Modifier::BOLD);
        assert_eq!(theme.header_style(), expected);
    }

    #[test]
    fn selected_style_colored() {
        let theme = Theme::new(false);
        let expected = Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD);
        assert_eq!(theme.selected_style(), expected);
    }

    #[test]
    fn selected_style_no_color() {
        let theme = Theme::new(true);
        let expected = Style::default().add_modifier(Modifier::REVERSED);
        assert_eq!(theme.selected_style(), expected);
    }

    #[test]
    fn normal_style_colored() {
        let theme = Theme::new(false);
        let expected = Style::default().fg(Color::Gray);
        assert_eq!(theme.normal_style(), expected);
    }

    #[test]
    fn normal_style_no_color() {
        let theme = Theme::new(true);
        assert_eq!(theme.normal_style(), Style::default());
    }
}
