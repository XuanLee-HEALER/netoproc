use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use clap::Parser;
use crossbeam_channel::{Receiver, Sender, bounded, select};

use netoproc::bpf::BpfCapture;
use netoproc::bpf::dns::DnsMessage;
use netoproc::bpf::packet::PacketSummary;
use netoproc::cli::Cli;
use netoproc::error::NetopError;
use netoproc::model::Direction;
use netoproc::model::traffic::{ProcessKey, ProcessTable, TrafficStats, lookup_process};
use netoproc::output;
use netoproc::privilege;
use netoproc::state::{self, merge};
use netoproc::system;
use netoproc::system::process::build_process_table;

/// Global shutdown flag, set by signal handlers.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
}

/// Exit codes per netoproc-requirements.md §9
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

    let cli = Cli::parse();
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

fn run(cli: Cli) -> Result<(), NetopError> {
    // 0. Install signal handlers for graceful shutdown.
    install_signal_handlers();

    // 1. Check root.
    privilege::check_root()?;

    // 2. Determine interfaces to monitor.
    let interfaces = discover_interfaces(&cli)?;
    if interfaces.is_empty() {
        return Err(NetopError::Fatal("no network interfaces found".to_string()));
    }
    log::info!("Monitoring interfaces: {:?}", interfaces);

    // 3. Collect local IPs for packet direction determination.
    let local_ips = collect_local_ips()?;
    log::info!("Local IPs: {} addresses", local_ips.len());

    // 4. Open BPF devices.
    let dns_enabled = !cli.no_dns;
    let (traffic_captures, dns_capture) =
        privilege::open_bpf_devices(&interfaces, cli.bpf_buffer, dns_enabled)?;

    if traffic_captures.is_empty() {
        return Err(NetopError::BpfDevice(
            "failed to open any BPF devices".to_string(),
        ));
    }
    log::info!(
        "Opened {} traffic capture device(s), DNS: {}",
        traffic_captures.len(),
        dns_capture.is_some()
    );

    // 5. Build initial process table.
    let process_table: Arc<ArcSwap<ProcessTable>> =
        Arc::new(ArcSwap::from_pointee(build_process_table()));

    // 6. Set up packet channel.
    // Capacity 8: each batch fills during a 500ms BPF read timeout,
    // so 8 batches = 4s of headroom before backpressure starts.
    let (pkt_tx, pkt_rx) = mpsc::sync_channel::<Vec<PacketSummary>>(8);

    // DNS channel (crossbeam, used by monitor mode bridge).
    let (dns_tx, dns_rx): (Sender<DnsMessage>, Receiver<DnsMessage>) = bounded(1024);

    // 7. Spawn BPF capture threads.
    let mut bpf_handles = Vec::new();

    for mut cap in traffic_captures {
        let tx = pkt_tx.clone();
        let ips = local_ips.clone();
        let h = thread::Builder::new()
            .name("netoproc-bpf".into())
            .spawn(move || {
                bpf_capture_loop(&mut cap, &tx, &ips);
            })
            .map_err(|e| NetopError::Fatal(format!("spawn bpf thread: {e}")))?;
        bpf_handles.push(h);
    }
    drop(pkt_tx); // only capture threads hold senders

    // Spawn DNS capture thread if enabled.
    let mut dns_handle = None;
    if let Some(mut dns_cap) = dns_capture {
        let tx = dns_tx.clone();
        let h = thread::Builder::new()
            .name("netoproc-dns".into())
            .spawn(move || {
                dns_capture_loop(&mut dns_cap, &tx);
            })
            .map_err(|e| NetopError::Fatal(format!("spawn dns thread: {e}")))?;
        dns_handle = Some(h);
    }
    drop(dns_tx);

    // 8. Spawn process refresh thread (refreshes ProcessTable every 500ms).
    let pt_for_refresh = Arc::clone(&process_table);
    let refresh_handle = thread::Builder::new()
        .name("netoproc-refresh".into())
        .spawn(move || {
            process_refresh_loop(&pt_for_refresh);
        })
        .map_err(|e| NetopError::Fatal(format!("spawn refresh thread: {e}")))?;

    // 9. Run snapshot or monitor mode.
    let result;
    if cli.is_snapshot() {
        result = run_snapshot(&cli, pkt_rx, &process_table, bpf_handles);
    } else {
        result = run_monitor(&cli, pkt_rx, &dns_rx, &process_table);
        // After TUI exits, join BPF threads.
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
        for h in bpf_handles {
            let _ = h.join();
        }
    }

    // 10. Shutdown remaining threads.
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    let _ = refresh_handle.join();
    if let Some(h) = dns_handle {
        let _ = h.join();
    }

    result
}

// ---------------------------------------------------------------------------
// Interface discovery
// ---------------------------------------------------------------------------

/// Discover which network interfaces to monitor.
fn discover_interfaces(cli: &Cli) -> Result<Vec<String>, NetopError> {
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

/// Collect all local IP addresses for packet direction determination.
fn collect_local_ips() -> Result<HashSet<IpAddr>, NetopError> {
    let interfaces = system::interface::list_interfaces()?;
    let mut ips = HashSet::new();
    for iface in &interfaces {
        for addr in &iface.ipv4_addresses {
            ips.insert(*addr);
        }
        for addr in &iface.ipv6_addresses {
            ips.insert(*addr);
        }
    }
    Ok(ips)
}

// ---------------------------------------------------------------------------
// Snapshot mode
// ---------------------------------------------------------------------------

/// Snapshot mode: accumulate per-process traffic for the specified duration, then output.
fn run_snapshot(
    cli: &Cli,
    pkt_rx: mpsc::Receiver<Vec<PacketSummary>>,
    process_table: &Arc<ArcSwap<ProcessTable>>,
    bpf_handles: Vec<thread::JoinHandle<()>>,
) -> Result<(), NetopError> {
    let duration = Duration::from_secs_f64(cli.snapshot_duration());
    let start = Instant::now();
    let mut stats: HashMap<ProcessKey, TrafficStats> = HashMap::new();
    let mut batch_count: u64 = 0;
    let mut packet_count: u64 = 0;

    // Accumulate traffic stats for the specified duration.
    while start.elapsed() < duration {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        match pkt_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(batch) => {
                batch_count += 1;
                packet_count += batch.len() as u64;
                accumulate_batch(&batch, process_table, &mut stats);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    log::info!(
        "Accumulation: {} batches, {} packets, {} processes in {:.1}s",
        batch_count,
        packet_count,
        stats.len(),
        start.elapsed().as_secs_f64()
    );

    // Drain remaining packets: signal BPF threads, join, drain channel.
    drain_final(&pkt_rx, process_table, &mut stats, bpf_handles);

    log::info!(
        "After drain: {} processes, {} total entries",
        stats.len(),
        stats
            .values()
            .map(|s| s.rx_packets + s.tx_packets)
            .sum::<u64>()
    );

    // Output results.
    output::write_snapshot(&stats, cli.format, &mut io::stdout().lock())
}

/// Signal BPF threads to stop, join them, then drain any remaining packets.
fn drain_final(
    pkt_rx: &mpsc::Receiver<Vec<PacketSummary>>,
    process_table: &Arc<ArcSwap<ProcessTable>>,
    stats: &mut HashMap<ProcessKey, TrafficStats>,
    bpf_handles: Vec<thread::JoinHandle<()>>,
) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);

    // Join BPF threads so all senders are dropped.
    for h in bpf_handles {
        let _ = h.join();
    }

    // Drain remaining packets from channel.
    while let Ok(batch) = pkt_rx.try_recv() {
        accumulate_batch(&batch, process_table, stats);
    }
}

/// Attribute a batch of packets to processes and accumulate traffic stats.
fn accumulate_batch(
    batch: &[PacketSummary],
    process_table: &Arc<ArcSwap<ProcessTable>>,
    stats: &mut HashMap<ProcessKey, TrafficStats>,
) {
    let table = process_table.load();
    for pkt in batch {
        let key = match lookup_process(&table, pkt) {
            Some(info) => ProcessKey::Known {
                pid: info.pid,
                name: info.name.clone(),
            },
            None => ProcessKey::Unknown,
        };
        stats.entry(key).or_default().add(pkt);
    }
}

// ---------------------------------------------------------------------------
// Monitor mode (TUI)
// ---------------------------------------------------------------------------

/// Monitor mode: spawn a stats bridge thread, run TUI in main thread.
fn run_monitor(
    cli: &Cli,
    pkt_rx: mpsc::Receiver<Vec<PacketSummary>>,
    dns_rx: &Receiver<DnsMessage>,
    process_table: &Arc<ArcSwap<ProcessTable>>,
) -> Result<(), NetopError> {
    // Shared state for TUI compatibility (bridge — Phase 7 will replace this).
    let shared_state = state::new_shared_state();

    // Spawn stats bridge thread: drains packets, polls system APIs,
    // builds SystemNetworkState for TUI.
    let state_for_bridge = Arc::clone(&shared_state);
    let pt = Arc::clone(process_table);
    let dns = dns_rx.clone();
    let bridge_handle = thread::Builder::new()
        .name("netoproc-stats".into())
        .spawn(move || {
            monitor_stats_loop(pkt_rx, &dns, &pt, &state_for_bridge);
        })
        .map_err(|e| NetopError::Fatal(format!("spawn stats thread: {e}")))?;

    // Run TUI in main thread.
    let tui_result = netoproc::tui::run_tui(
        shared_state,
        Duration::from_secs(1),
        cli.sort,
        cli.no_color,
        cli.filter.as_deref(),
    );

    // TUI exited — signal shutdown so bridge thread stops.
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    let _ = bridge_handle.join();

    tui_result
}

/// Stats bridge thread for monitor mode.
///
/// Drains packet batches, flattens them, polls system APIs, and uses the old
/// merge path to build `SystemNetworkState` for TUI compatibility.
/// Phase 7 will replace this with direct `TrafficStats` rendering in the TUI.
fn monitor_stats_loop(
    pkt_rx: mpsc::Receiver<Vec<PacketSummary>>,
    dns_rx: &Receiver<DnsMessage>,
    _process_table: &Arc<ArcSwap<ProcessTable>>,
    shared_state: &state::SharedState,
) {
    let ticker = crossbeam_channel::tick(Duration::from_secs(1));

    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return;
        }

        // Wait for tick.
        select! {
            recv(ticker) -> _ => {},
            default(Duration::from_millis(500)) => {},
        }

        // Drain packet batches and flatten for old merge path.
        let mut packets = Vec::new();
        loop {
            match pkt_rx.try_recv() {
                Ok(batch) => packets.extend(batch),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // Drain DNS messages.
        let mut dns_messages = Vec::new();
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

        // Build state using old merge path (TUI compatibility bridge).
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
        shared_state.store(Arc::new(new_state));
    }
}

// ---------------------------------------------------------------------------
// BPF capture thread
// ---------------------------------------------------------------------------

/// BPF capture thread: blocking read loop, sends packet batches to channel.
///
/// Each BPF read blocks for up to 500ms (configured via BIOCSRTIMEOUT).
/// Packets in each batch have their `direction` field set based on local IPs.
fn bpf_capture_loop(
    cap: &mut BpfCapture,
    tx: &mpsc::SyncSender<Vec<PacketSummary>>,
    local_ips: &HashSet<IpAddr>,
) {
    let iface = cap.interface().to_string();
    let mut pkt_buf = Vec::new(); // reused across iterations
    let mut eagain_count: u64 = 0;
    let mut empty_ok_count: u64 = 0;
    let mut data_read_count: u64 = 0;
    let mut total_packets: u64 = 0;
    let mut parse_empty_count: u64 = 0;

    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            break;
        }

        match cap.read_packets_raw(&mut pkt_buf) {
            Ok(0) => {
                // read() returned 0 bytes — timeout with empty buffer.
                empty_ok_count += 1;
            }
            Ok(n) => {
                data_read_count += 1;
                if pkt_buf.is_empty() {
                    // read() returned data but parser produced no packets.
                    parse_empty_count += 1;
                    log::debug!("BPF {}: read {} bytes, parsed 0 packets", iface, n);
                } else {
                    total_packets += pkt_buf.len() as u64;
                    // Set direction based on local IPs.
                    for pkt in &mut pkt_buf {
                        pkt.direction = if local_ips.contains(&pkt.dst_ip) {
                            Direction::Inbound
                        } else {
                            Direction::Outbound
                        };
                    }
                    // Send batch using non-blocking try_send with shutdown check.
                    // A blocking send() here would deadlock: after the accumulation
                    // loop exits, drain_final() joins BPF threads while no one
                    // consumes from the channel. If the channel is full, send()
                    // blocks forever and the join never completes.
                    let mut batch = std::mem::take(&mut pkt_buf);
                    loop {
                        match tx.try_send(batch) {
                            Ok(()) => break,
                            Err(mpsc::TrySendError::Full(returned)) => {
                                if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                                    return;
                                }
                                batch = returned;
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => {
                                log::info!(
                                    "BPF {} exit: eagain={}, empty_ok={}, data_reads={} (parse_empty={}), packets={}",
                                    iface,
                                    eagain_count,
                                    empty_ok_count,
                                    data_read_count,
                                    parse_empty_count,
                                    total_packets
                                );
                                return;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Resource temporarily unavailable") {
                    eagain_count += 1;
                    continue;
                }
                log::warn!("BPF read error on {}: {}", iface, e);
            }
        }
    }

    // Log BPF kernel stats for this device before exiting.
    match cap.stats() {
        Ok(st) => log::info!(
            "BPF {} exit: eagain={}, empty_ok={}, data_reads={} (parse_empty={}), packets={}, kernel_recv={}, kernel_drop={}",
            iface,
            eagain_count,
            empty_ok_count,
            data_read_count,
            parse_empty_count,
            total_packets,
            st.received,
            st.dropped
        ),
        Err(_) => log::info!(
            "BPF {} exit: eagain={}, empty_ok={}, data_reads={} (parse_empty={}), packets={}",
            iface,
            eagain_count,
            empty_ok_count,
            data_read_count,
            parse_empty_count,
            total_packets
        ),
    }
}

// ---------------------------------------------------------------------------
// DNS capture thread
// ---------------------------------------------------------------------------

/// DNS capture thread: reads packets, parses DNS payloads, sends to channel.
///
/// Uses `try_send` instead of blocking `send` to avoid deadlock: in snapshot
/// mode, nobody reads from `dns_rx`, so the bounded channel fills up. A
/// blocking `send` would block forever, preventing the thread from exiting
/// when `SHUTDOWN_REQUESTED` is set.
fn dns_capture_loop(cap: &mut BpfCapture, tx: &Sender<DnsMessage>) {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return;
        }

        match cap.read_dns_messages() {
            Ok(messages) => {
                for msg in messages {
                    match tx.try_send(msg) {
                        Ok(()) => {}
                        Err(crossbeam_channel::TrySendError::Full(_)) => {
                            // Channel full — drop this message. In snapshot mode,
                            // nobody consumes DNS messages; in monitor mode, the
                            // bridge thread drains periodically so this is rare.
                            break;
                        }
                        Err(crossbeam_channel::TrySendError::Disconnected(_)) => return,
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Resource temporarily unavailable") {
                    continue; // EAGAIN — BPF read timeout, normal
                }
                log::warn!("DNS BPF read error: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Process refresh thread
// ---------------------------------------------------------------------------

/// Process refresh thread: rebuilds the ProcessTable every 500ms.
fn process_refresh_loop(process_table: &Arc<ArcSwap<ProcessTable>>) {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return;
        }
        thread::sleep(Duration::from_millis(500));
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            return;
        }
        let new_table = build_process_table();
        process_table.store(Arc::new(new_table));
    }
}
