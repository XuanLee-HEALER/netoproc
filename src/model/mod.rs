pub mod correlation;
pub mod traffic;

use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct SystemNetworkState {
    pub timestamp: u64,
    pub interfaces: Vec<Interface>,
    pub processes: Vec<Process>,
    pub dns: DnsObservatory,
}

impl SystemNetworkState {
    pub fn empty() -> Self {
        Self {
            timestamp: 0,
            interfaces: Vec::new(),
            processes: Vec::new(),
            dns: DnsObservatory::default(),
        }
    }
}

impl Default for SystemNetworkState {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Serialize, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Copy, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceStatus {
    Up,
    Down,
}

#[derive(Clone, Copy, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SocketState {
    // TCP states
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    // UDP states
    Bound,
    Connected,
    // ICMP
    Open,
}

impl std::fmt::Display for SocketState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "CLOSED"),
            Self::Listen => write!(f, "LISTEN"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RECEIVED"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::FinWait1 => write!(f, "FIN_WAIT_1"),
            Self::FinWait2 => write!(f, "FIN_WAIT_2"),
            Self::Closing => write!(f, "CLOSING"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::Bound => write!(f, "BOUND"),
            Self::Connected => write!(f, "CONNECTED"),
            Self::Open => write!(f, "OPEN"),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
        }
    }
}

impl std::fmt::Display for InterfaceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Up => write!(f, "up"),
            Self::Down => write!(f, "down"),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Interface {
    pub name: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub status: InterfaceStatus,
    pub rx_bytes_rate: f64,
    pub tx_bytes_rate: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            name: String::new(),
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            status: InterfaceStatus::Down,
            rx_bytes_rate: 0.0,
            tx_bytes_rate: 0.0,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub uid: u32,
    pub username: String,
    pub sockets: Vec<Socket>,
}

#[derive(Clone, Serialize)]
pub struct Socket {
    pub fd: i32,
    pub protocol: Protocol,
    pub local_addr: String,
    pub state: SocketState,
    pub connections: Vec<Connection>,
}

#[derive(Clone, Serialize)]
pub struct Connection {
    pub remote_addr: String,
    pub direction: Direction,
    pub interface: String,
    pub rx_rate: RateMetrics,
    pub tx_rate: RateMetrics,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub stability: Option<ConnectionStability>,
}

#[derive(Clone, Serialize, Default)]
pub struct RateMetrics {
    pub bytes_per_sec: f64,
    pub bytes_per_min: f64,
}

#[derive(Clone, Serialize)]
pub struct ConnectionStability {
    pub rtt_us: u32,
    pub jitter_us: u32,
    pub retransmissions: u64,
    pub retransmit_rate: f64,
}

#[derive(Clone, Serialize, Default)]
pub struct DnsObservatory {
    pub resolvers: Vec<DnsResolver>,
    pub queries: Vec<DnsQuery>,
}

#[derive(Clone, Serialize)]
pub struct DnsResolver {
    pub interface: String,
    pub server: String,
    pub avg_latency_ms: f64,
    pub failure_rate_pct: f64,
    pub query_count: u64,
}

#[derive(Clone, Serialize)]
pub struct DnsQuery {
    pub timestamp_ms: u64,
    pub pid: Option<u32>,
    pub process: String,
    pub query_name: String,
    pub query_type: String,
    pub response: String,
    pub latency_ms: f64,
    pub resolver: String,
}
