use crossterm::event::{self, KeyEvent};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Events produced by the TUI event loop.
#[derive(Debug)]
pub enum Event {
    /// A keyboard event from crossterm.
    Key(KeyEvent),
    /// Terminal window was resized to (columns, rows).
    Resize(u16, u16),
    /// Periodic tick for UI refresh.
    Tick,
}

/// Asynchronous event handler.
///
/// Spawns a background thread that polls crossterm for keyboard/resize events
/// and emits `Event::Tick` at a configurable interval. The main thread reads
/// events via `next()`.
pub struct EventHandler {
    rx: mpsc::Receiver<Event>,
    _handle: thread::JoinHandle<()>,
}

impl EventHandler {
    /// Creates a new `EventHandler` with the given tick rate.
    ///
    /// The background thread will poll crossterm events and send `Event::Tick`
    /// whenever `tick_rate` elapses without any input event.
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::channel();

        let handle = thread::Builder::new()
            .name("netoproc-event".into())
            .spawn(move || {
                let mut last_tick = Instant::now();
                loop {
                    // Time remaining until next tick
                    let timeout = tick_rate
                        .checked_sub(last_tick.elapsed())
                        .unwrap_or(Duration::ZERO);

                    // Poll crossterm for events within the timeout window
                    if event::poll(timeout).unwrap_or(false) {
                        match event::read() {
                            Ok(event::Event::Key(key)) => {
                                if tx.send(Event::Key(key)).is_err() {
                                    // Receiver dropped — main thread shut down
                                    return;
                                }
                            }
                            Ok(event::Event::Resize(w, h)) => {
                                if tx.send(Event::Resize(w, h)).is_err() {
                                    return;
                                }
                            }
                            // Ignore mouse, focus, and paste events
                            Ok(_) => {}
                            Err(_) => {}
                        }
                    }

                    // Emit a tick if the interval has elapsed
                    if last_tick.elapsed() >= tick_rate {
                        if tx.send(Event::Tick).is_err() {
                            return;
                        }
                        last_tick = Instant::now();
                    }
                }
            })
            .expect("failed to spawn event handler thread");

        Self {
            rx,
            _handle: handle,
        }
    }

    /// Blocks until the next event is available.
    pub fn next(&self) -> Result<Event, mpsc::RecvError> {
        self.rx.recv()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_event_fires() {
        // Use a very short tick rate so the test completes quickly.
        let handler = EventHandler::new(Duration::from_millis(10));

        // We should receive a Tick event within a reasonable timeout.
        let event = handler.rx.recv_timeout(Duration::from_secs(1));
        assert!(event.is_ok());
        match event.unwrap() {
            Event::Tick => {} // expected
            Event::Key(_) => panic!("unexpected key event"),
            Event::Resize(_, _) => {} // possible on some terminals
        }
    }
}
