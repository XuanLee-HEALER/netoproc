use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::NetopError;

/// Raw interface data from getifaddrs
#[derive(Debug, Clone, Default)]
pub struct RawInterface {
    pub name: String,
    pub ipv4_addresses: Vec<IpAddr>,
    pub ipv6_addresses: Vec<IpAddr>,
    pub flags: u32,
    pub ifi_ibytes: u64,
    pub ifi_obytes: u64,
    pub ifi_ipackets: u64,
    pub ifi_opackets: u64,
    pub ifi_ierrors: u64,
    pub ifi_oerrors: u64,
}

impl RawInterface {
    pub fn is_up(&self) -> bool {
        (self.flags & libc::IFF_UP as u32) != 0
    }
}

// if_data structure for AF_LINK entries on macOS
// This contains interface-level traffic statistics
#[repr(C)]
#[derive(Clone, Copy)]
struct if_data {
    ifi_type: u8,
    ifi_typelen: u8,
    ifi_physical: u8,
    ifi_addrlen: u8,
    ifi_hdrlen: u8,
    ifi_recvquota: u8,
    ifi_xmitquota: u8,
    ifi_unused1: u8,
    ifi_mtu: u32,
    ifi_metric: u32,
    ifi_baudrate: u32,
    ifi_ipackets: u32,
    ifi_ierrors: u32,
    ifi_opackets: u32,
    ifi_oerrors: u32,
    ifi_collisions: u32,
    ifi_ibytes: u32,
    ifi_obytes: u32,
    ifi_imcasts: u32,
    ifi_omcasts: u32,
    ifi_iqdrops: u32,
    ifi_noproto: u32,
    ifi_recvtiming: u32,
    ifi_xmittiming: u32,
    ifi_lastchange: libc::timeval,
    ifi_unused2: u32,
    ifi_hwassist: u32,
    ifi_reserved1: u32,
    ifi_reserved2: u32,
}

// On macOS 64-bit, if_data64 is used when available
// For simplicity we use the 32-bit counters and note potential wrap
// A more robust implementation would use if_data64

/// Enumerate all network interfaces and their statistics
pub fn list_interfaces() -> Result<Vec<RawInterface>, NetopError> {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return Err(NetopError::Interface(std::io::Error::last_os_error()));
    }

    // Ensure freeifaddrs is called on all exit paths
    let result = collect_interfaces(ifaddrs);

    unsafe { libc::freeifaddrs(ifaddrs) };

    result
}

fn collect_interfaces(ifaddrs: *mut libc::ifaddrs) -> Result<Vec<RawInterface>, NetopError> {
    let mut interfaces: HashMap<String, RawInterface> = HashMap::new();
    let mut current = ifaddrs;

    while !current.is_null() {
        let entry = unsafe { &*current };
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();

        let iface = interfaces
            .entry(name.clone())
            .or_insert_with(|| RawInterface {
                name: name.clone(),
                ..Default::default()
            });

        iface.flags = entry.ifa_flags;

        if !entry.ifa_addr.is_null() {
            let sa_family = unsafe { (*entry.ifa_addr).sa_family } as i32;

            match sa_family {
                libc::AF_LINK => {
                    // Extract if_data counters
                    if !entry.ifa_data.is_null() {
                        let data = unsafe { &*(entry.ifa_data as *const if_data) };
                        iface.ifi_ibytes = data.ifi_ibytes as u64;
                        iface.ifi_obytes = data.ifi_obytes as u64;
                        iface.ifi_ipackets = data.ifi_ipackets as u64;
                        iface.ifi_opackets = data.ifi_opackets as u64;
                        iface.ifi_ierrors = data.ifi_ierrors as u64;
                        iface.ifi_oerrors = data.ifi_oerrors as u64;
                    }
                }
                libc::AF_INET => {
                    // Extract IPv4 address
                    let sa_in = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                    let addr_bytes = sa_in.sin_addr.s_addr.to_ne_bytes();
                    let addr =
                        Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
                    iface.ipv4_addresses.push(IpAddr::V4(addr));
                }
                libc::AF_INET6 => {
                    // Extract IPv6 address
                    let sa_in6 = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                    let addr = Ipv6Addr::from(sa_in6.sin6_addr.s6_addr);
                    iface.ipv6_addresses.push(IpAddr::V6(addr));
                }
                _ => {}
            }
        }

        current = entry.ifa_next;
    }

    Ok(interfaces.into_values().collect())
}
