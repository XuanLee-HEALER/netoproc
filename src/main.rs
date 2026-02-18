use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use clap::Parser;
use crossbeam_channel::{Receiver, Sender, bounded, select};

use netoproc::bpf::BpfCapture;
use netoproc::bpf::dns::DnsMessage;
use netoproc::bpf::packet::PacketSummary;
use netoproc::cli::{Cli, ResolvedCli};
use netoproc::error::NetopError;
use netoproc::output;
use netoproc::privilege;
use netoproc::state::{self, merge};
use netoproc::system;

/// Global shutdown flag, set by signal handlers.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
    }
}

/// Exit codes per REQUIREMENTS.md §9
fn exit_code(err: &NetopError) -> i32 {
    match err {
        NetopError::NotRoot => 1,
        NetopError::BpfDevice(_) => 2,
        NetopError::Tui(_) => 4,
        NetopError::Fatal(_) => 4,
        _ => 4,
    }
}

fn main() {
    env_logger::init();

    let cli = Cli::parse().resolve();
    let is_tui = cli.is_monitor();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(cli)));

    // Restore terminal state only if TUI mode was used (snapshot never enters alternate screen).
    if is_tui {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen);
    }

    match result {
        Ok(Ok(())) => std::process::exit(0),
        Ok(Err(e)) => {
            eprintln!("error: {e}");
            std::process::exit(exit_code(&e));
        }
        Err(_) => {
            eprintln!("error: fatal: unexpected panic");
            std::process::exit(4);
        }
    }
}

fn run(cli: ResolvedCli) -> Result<(), NetopError> {
    // 0. Install signal handlers for graceful shutdown.
    install_signal_handlers();

    // 1. Check root.
    privilege::check_root()?;

    // 2. Determine interfaces to monitor.
    let interfaces = discover_interfaces(&cli)?;
    if interfaces.is_empty() {
        return Err(NetopError::Fatal("no network interfaces found".to_string()));
    }

    // 3. Open BPF devices.
    let dns_enabled = !cli.no_dns;
    let (traffic_captures, dns_capture) =
        privilege::open_bpf_devices(&interfaces, cli.bpf_buffer, dns_enabled)?;

    if traffic_captures.is_empty() {
        return Err(NetopError::BpfDevice(
            "failed to open any BPF devices".to_string(),
        ));
    }

    // 4. Initialize shared state.
    let shared_state = state::new_shared_state();

    // 5. Set up channels.
    let (pkt_tx, pkt_rx): (Sender<PacketSummary>, Receiver<PacketSummary>) = bounded(8192);
    let (dns_tx, dns_rx): (Sender<DnsMessage>, Receiver<DnsMessage>) = bounded(1024);
    let (shutdown_tx, shutdown_rx): (Sender<()>, Receiver<()>) = bounded(0);
    let (ready_tx, ready_rx): (Sender<()>, Receiver<()>) = bounded(1);

    // 6. Spawn BPF capture threads.
    let mut handles = Vec::new();

    for mut cap in traffic_captures {
        let tx = pkt_tx.clone();
        let sd = shutdown_rx.clone();
        let h = thread::Builder::new()
            .name("netoproc-bpf".into())
            .spawn(move || {
                bpf_capture_loop(&mut cap, &tx, &sd);
            })
            .map_err(|e| NetopError::Fatal(format!("spawn bpf thread: {e}")))?;
        handles.push(h);
    }
    drop(pkt_tx); // only capture threads hold senders

    // Spawn DNS capture thread if enabled.
    if let Some(mut dns_cap) = dns_capture {
        let tx = dns_tx.clone();
        let sd = shutdown_rx.clone();
        let h = thread::Builder::new()
            .name("netoproc-dns".into())
            .spawn(move || {
                dns_capture_loop(&mut dns_cap, &tx, &sd);
            })
            .map_err(|e| NetopError::Fatal(format!("spawn dns thread: {e}")))?;
        handles.push(h);
    }
    drop(dns_tx);

    // 7. Spawn stats poller thread.
    let interval = Duration::from_secs_f64(cli.interval);
    let state_for_poller = Arc::clone(&shared_state);
    let poller_handle = thread::Builder::new()
        .name("netoproc-poller".into())
        .spawn(move || {
            poller_loop(
                &state_for_poller,
                &pkt_rx,
                &dns_rx,
                interval,
                Some(ready_tx),
            );
        })
        .map_err(|e| NetopError::Fatal(format!("spawn poller thread: {e}")))?;

    // 8. Run TUI or snapshot.
    let result = if !cli.is_monitor() {
        // Snapshot mode: wait for poller to complete at least one cycle, then
        // continue collecting BPF traffic for the remaining duration so that
        // rate metrics have enough samples to be meaningful.
        let duration = Duration::from_secs_f64(cli.duration);
        let timeout = duration + Duration::from_secs(3);
        let _ = ready_rx.recv_timeout(timeout);
        let remaining = duration.saturating_sub(Duration::from_secs_f64(cli.interval));
        if !remaining.is_zero() {
            thread::sleep(remaining);
        }
        let state = shared_state.load();
        output::write_snapshot(&state, cli.format, &mut io::stdout().lock())
    } else {
        // Monitor mode: run TUI.
        netoproc::tui::run_tui(
            shared_state,
            interval,
            cli.sort,
            cli.no_color,
            cli.filter.as_deref(),
        )
    };

    // 9. Shutdown: signal all threads to stop.
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    drop(shutdown_tx);
    drop(shutdown_rx);

    // Wait for threads to finish (BPF read timeout ensures they return promptly).
    for h in handles {
        let _ = h.join();
    }
    let _ = poller_handle.join();

    result
}

/// Discover which network interfaces to monitor.
fn discover_interfaces(cli: &ResolvedCli) -> Result<Vec<String>, NetopError> {
    if let Some(ref iface) = cli.interface {
        return Ok(vec![iface.clone()]);
    }

    // Get all active interfaces from system API.
    let raw = system::interface::list_interfaces()?;
    let active: Vec<String> = raw
        .into_iter()
        .filter(|i| {
            // Filter out loopback and down interfaces.
            let is_up = (i.flags & libc::IFF_UP as u32) != 0;
            let is_loopback = (i.flags & libc::IFF_LOOPBACK as u32) != 0;
            is_up && !is_loopback
        })
        .map(|i| i.name)
        .collect();

    Ok(active)
}

/// Check if shutdown has been requested via signal or channel disconnect.
fn should_shutdown(shutdown: &Receiver<()>) -> bool {
    if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        return true;
    }
    match shutdown.try_recv() {
        Ok(()) | Err(crossbeam_channel::TryRecvError::Disconnected) => true,
        Err(crossbeam_channel::TryRecvError::Empty) => false,
    }
}

/// BPF capture thread: blocking read loop, sends packets to channel.
fn bpf_capture_loop(cap: &mut BpfCapture, tx: &Sender<PacketSummary>, shutdown: &Receiver<()>) {
    let mut pkt_buf = Vec::new(); // reused across iterations
    loop {
        if should_shutdown(shutdown) {
            return;
        }

        match cap.read_packets(&mut pkt_buf) {
            Ok(()) => {
                for pkt in pkt_buf.drain(..) {
                    if tx.send(pkt).is_err() {
                        return; // receiver dropped
                    }
                }
            }
            Err(e) => {
                log::warn!("BPF read error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// DNS capture thread: reads packets, parses DNS payloads, sends to channel.
fn dns_capture_loop(cap: &mut BpfCapture, tx: &Sender<DnsMessage>, shutdown: &Receiver<()>) {
    loop {
        if should_shutdown(shutdown) {
            return;
        }

        match cap.read_dns_messages() {
            Ok(messages) => {
                for msg in messages {
                    if tx.send(msg).is_err() {
                        return; // receiver dropped
                    }
                }
            }
            Err(e) => {
                log::warn!("DNS BPF read error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Stats poller thread: drains packet channel, polls system APIs, merges state.
fn poller_loop(
    shared_state: &state::SharedState,
    pkt_rx: &Receiver<PacketSummary>,
    dns_rx: &Receiver<DnsMessage>,
    interval: Duration,
    ready_tx: Option<Sender<()>>,
) {
    let ticker = crossbeam_channel::tick(interval);

    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return;
        }

        // Wait for tick or channel disconnect.
        select! {
            recv(ticker) -> _ => {},
            default(Duration::from_millis(500)) => {},
        }

        // Drain all pending packets.
        let mut packets: Vec<PacketSummary> = Vec::new();
        loop {
            match pkt_rx.try_recv() {
                Ok(pkt) => packets.push(pkt),
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    // All senders dropped — time to exit.
                    return;
                }
            }
        }

        // Drain DNS messages.
        let mut dns_messages: Vec<DnsMessage> = Vec::new();
        loop {
            match dns_rx.try_recv() {
                Ok(msg) => dns_messages.push(msg),
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        }

        // Poll system APIs.
        let raw = match system::poll_system() {
            Ok(data) => data,
            Err(e) => {
                log::warn!("System poll error: {e}");
                continue;
            }
        };

        // Merge into new state.
        let prev = shared_state.load();
        let new_state = merge::merge_into_state(
            &prev,
            &raw.processes,
            &raw.tcp_connections,
            &raw.udp_connections,
            &raw.interfaces,
            &raw.dns_resolvers,
            &packets,
            &dns_messages,
        );

        // Publish atomically.
        shared_state.store(Arc::new(new_state));

        // Signal that at least one cycle has completed.
        if let Some(ref tx) = ready_tx {
            let _ = tx.try_send(());
        }
    }
}
