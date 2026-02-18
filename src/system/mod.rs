pub mod connection;
pub mod dns_config;
pub mod interface;
pub mod process;

use crate::error::NetopError;

use self::connection::{RawTcpConnection, RawUdpConnection};
use self::dns_config::RawDnsResolver;
use self::interface::RawInterface;
use self::process::RawProcess;

/// Bundle of raw data from all system APIs
pub struct RawSystemData {
    pub processes: Vec<RawProcess>,
    pub tcp_connections: Vec<RawTcpConnection>,
    pub udp_connections: Vec<RawUdpConnection>,
    pub interfaces: Vec<RawInterface>,
    pub dns_resolvers: Vec<RawDnsResolver>,
}

/// Poll all system APIs and return raw data
pub fn poll_system() -> Result<RawSystemData, NetopError> {
    let processes = process::list_processes()?;
    let tcp_connections = connection::list_tcp_connections()?;
    let udp_connections = connection::list_udp_connections()?;
    let interfaces = interface::list_interfaces()?;
    let dns_resolvers = dns_config::list_dns_resolvers().unwrap_or_default();

    Ok(RawSystemData {
        processes,
        tcp_connections,
        udp_connections,
        interfaces,
        dns_resolvers,
    })
}
