use crate::dns::DnsMessage;
use crate::model::SystemNetworkState;
use crate::model::correlation::correlate;
use crate::packet::PacketSummary;
use crate::system::connection::{RawTcpConnection, RawUdpConnection};
use crate::system::dns_config::RawDnsResolver;
use crate::system::interface::RawInterface;
use crate::system::process::RawProcess;

/// Merge raw system data and captured packets into a new SystemNetworkState.
///
/// Takes the previous state for time-series continuity and produces a new
/// complete snapshot.
#[allow(clippy::too_many_arguments)]
pub fn merge_into_state(
    prev: &SystemNetworkState,
    processes: &[RawProcess],
    tcp_connections: &[RawTcpConnection],
    udp_connections: &[RawUdpConnection],
    interfaces: &[RawInterface],
    dns_resolvers: &[RawDnsResolver],
    packets: &[PacketSummary],
    dns_messages: &[DnsMessage],
) -> SystemNetworkState {
    correlate(
        processes,
        tcp_connections,
        udp_connections,
        interfaces,
        dns_resolvers,
        packets,
        dns_messages,
        prev,
    )
}
