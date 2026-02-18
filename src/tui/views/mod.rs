pub mod connection;
pub mod dns;
pub mod interface;
pub mod process;

/// The four navigable TUI views.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Process,
    Connection,
    Interface,
    Dns,
}

impl View {
    /// Human-readable title for the tab bar.
    pub fn title(&self) -> &str {
        match self {
            Self::Process => "Processes",
            Self::Connection => "Connections",
            Self::Interface => "Interfaces",
            Self::Dns => "DNS",
        }
    }

    /// Zero-based index (matches tab ordering).
    pub fn index(&self) -> usize {
        match self {
            Self::Process => 0,
            Self::Connection => 1,
            Self::Interface => 2,
            Self::Dns => 3,
        }
    }

    /// Convert a zero-based index back into a View, if valid.
    pub fn from_index(i: usize) -> Option<Self> {
        match i {
            0 => Some(Self::Process),
            1 => Some(Self::Connection),
            2 => Some(Self::Interface),
            3 => Some(Self::Dns),
            _ => None,
        }
    }

    /// Cycle to the next view (wraps around).
    pub fn next(&self) -> Self {
        Self::from_index((self.index() + 1) % 4).unwrap_or(Self::Process)
    }

    /// Cycle to the previous view (wraps around).
    pub fn prev(&self) -> Self {
        Self::from_index((self.index() + 3) % 4).unwrap_or(Self::Dns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_roundtrip() {
        for i in 0..4 {
            let v = View::from_index(i).unwrap();
            assert_eq!(v.index(), i);
        }
    }

    #[test]
    fn test_view_from_index_invalid() {
        assert!(View::from_index(4).is_none());
        assert!(View::from_index(99).is_none());
    }

    #[test]
    fn test_view_next_wraps() {
        assert_eq!(View::Process.next(), View::Connection);
        assert_eq!(View::Connection.next(), View::Interface);
        assert_eq!(View::Interface.next(), View::Dns);
        assert_eq!(View::Dns.next(), View::Process);
    }

    #[test]
    fn test_view_titles() {
        assert_eq!(View::Process.title(), "Processes");
        assert_eq!(View::Connection.title(), "Connections");
        assert_eq!(View::Interface.title(), "Interfaces");
        assert_eq!(View::Dns.title(), "DNS");
    }
}
