use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::error::NetopError;

/// State of a reverse DNS lookup for a single IP.
enum RdnsState {
    Pending,
    Resolved(Option<String>),
}

/// Asynchronous reverse DNS resolver using worker threads.
///
/// Lookups are non-blocking: `lookup()` triggers a query on first call and
/// returns `None` until the result arrives. Call `collect_results()` periodically
/// to drain completed lookups.
pub struct ReverseDnsResolver {
    cache: HashMap<IpAddr, RdnsState>,
    query_tx: crossbeam_channel::Sender<IpAddr>,
    result_rx: mpsc::Receiver<(IpAddr, Option<String>)>,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl ReverseDnsResolver {
    /// Create a new resolver with `n_workers` background lookup threads.
    pub fn new(n_workers: usize) -> Result<Self, NetopError> {
        let (query_tx, query_rx) = crossbeam_channel::bounded::<IpAddr>(64);
        let (result_tx, result_rx) = mpsc::sync_channel::<(IpAddr, Option<String>)>(64);

        let mut workers = Vec::with_capacity(n_workers);
        for i in 0..n_workers {
            let rx = query_rx.clone();
            let tx = result_tx.clone();
            let h = thread::Builder::new()
                .name(format!("netoproc-rdns-{i}"))
                .spawn(move || {
                    rdns_worker(rx, tx);
                })
                .map_err(|e| NetopError::Fatal(format!("spawn rdns worker: {e}")))?;
            workers.push(h);
        }

        Ok(Self {
            cache: HashMap::new(),
            query_tx,
            result_rx,
            _workers: workers,
        })
    }

    /// Trigger a reverse DNS lookup for `ip` if not already queried.
    ///
    /// Returns the resolved hostname if available, `None` otherwise.
    pub fn lookup(&mut self, ip: IpAddr) -> Option<&str> {
        if !self.cache.contains_key(&ip) {
            // New IP — enqueue for resolution.
            if self.query_tx.try_send(ip).is_ok() {
                self.cache.insert(ip, RdnsState::Pending);
            }
            return None;
        }

        match self.cache.get(&ip) {
            Some(RdnsState::Resolved(Some(name))) => Some(name.as_str()),
            _ => None,
        }
    }

    /// Drain completed DNS results from worker threads (non-blocking).
    pub fn collect_results(&mut self) {
        while let Ok((ip, result)) = self.result_rx.try_recv() {
            self.cache.insert(ip, RdnsState::Resolved(result));
        }
    }

    /// Wait up to `timeout` for any remaining in-flight queries to complete.
    pub fn wait_for_pending(&mut self, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            self.collect_results();
            let all_resolved = self
                .cache
                .values()
                .all(|s| matches!(s, RdnsState::Resolved(_)));
            if all_resolved {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        // Final drain.
        self.collect_results();
    }

    /// Get the resolved hostname for an IP if available.
    pub fn get_result(&self, ip: &IpAddr) -> Option<Option<&str>> {
        match self.cache.get(ip) {
            Some(RdnsState::Resolved(Some(name))) => Some(Some(name.as_str())),
            Some(RdnsState::Resolved(None)) => Some(None),
            _ => None,
        }
    }
}

/// Worker thread: reads IPs from the work queue, performs reverse DNS lookup,
/// sends results back. Exits when the query channel is dropped.
fn rdns_worker(
    rx: crossbeam_channel::Receiver<IpAddr>,
    tx: mpsc::SyncSender<(IpAddr, Option<String>)>,
) {
    while let Ok(ip) = rx.recv() {
        let result = resolve_with_timeout(ip, Duration::from_secs(3));
        if tx.send((ip, result)).is_err() {
            return; // result channel closed
        }
    }
}

/// Perform a reverse DNS lookup with a timeout.
///
/// Spawns a thread for the blocking `lookup_addr` call and waits up to `timeout`.
fn resolve_with_timeout(ip: IpAddr, timeout: Duration) -> Option<String> {
    let (tx, rx) = mpsc::sync_channel(1);

    // Spawn a short-lived thread for the blocking lookup.
    let handle = thread::Builder::new()
        .name("rdns-query".into())
        .spawn(move || {
            let result = dns_lookup::lookup_addr(&ip).ok();
            let _ = tx.send(result);
        });

    match handle {
        Ok(_) => rx.recv_timeout(timeout).unwrap_or_default(),
        Err(_) => None, // thread spawn failure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn resolver_creation() {
        let resolver = ReverseDnsResolver::new(1);
        assert!(resolver.is_ok());
    }

    #[test]
    fn lookup_returns_none_initially() {
        let mut resolver = ReverseDnsResolver::new(1).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        // First lookup triggers the query but returns None immediately.
        assert!(resolver.lookup(ip).is_none());
    }

    #[test]
    fn collect_results_drains() {
        let mut resolver = ReverseDnsResolver::new(1).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        resolver.lookup(ip);

        // Wait for the worker to finish.
        resolver.wait_for_pending(Duration::from_secs(5));

        // After collecting, the result should be available.
        let result = resolver.get_result(&ip);
        assert!(result.is_some()); // Some(Some("localhost")) or Some(None) depending on system
    }

    #[test]
    fn dedup_same_ip() {
        let mut resolver = ReverseDnsResolver::new(1).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        resolver.lookup(ip);
        resolver.lookup(ip); // should not enqueue again
        resolver.lookup(ip); // should not enqueue again

        // Only one query should have been sent.
        resolver.wait_for_pending(Duration::from_secs(5));
        assert!(resolver.get_result(&ip).is_some());
    }
}
