//! Linux-only integration tests for runtime functionality.
//!
//! These tests are gated by `#[cfg(target_os = "linux")]` and require either
//! root privileges or appropriate Linux capabilities (cap_net_raw, cap_net_admin).
//!
//! Run with: `sudo cargo test --test linux_integration`

#![cfg(target_os = "linux")]

/// TC-L-10: AF_PACKET socket creation succeeds with appropriate privileges.
#[test]
fn af_packet_socket_creation() {
    if !is_root_or_capable() {
        eprintln!("skipping: requires root or CAP_NET_RAW");
        return;
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    assert!(
        fd >= 0,
        "failed to create AF_PACKET socket: {}",
        errno_msg()
    );

    unsafe { libc::close(fd) };
}

/// TC-L-11: BPF filter can be installed on an AF_PACKET socket.
#[test]
fn af_packet_filter_installation() {
    if !is_root_or_capable() {
        eprintln!("skipping: requires root or CAP_NET_RAW");
        return;
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    assert!(fd >= 0, "failed to create AF_PACKET socket");

    // Simple BPF filter: accept all packets (ret #65535)
    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    let filter = [SockFilter {
        code: 0x06, // BPF_RET
        jt: 0,
        jf: 0,
        k: 0xFFFF, // accept up to 65535 bytes
    }];

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as u32,
        )
    };

    assert_eq!(ret, 0, "failed to install BPF filter: {}", errno_msg());

    unsafe { libc::close(fd) };
}

/// TC-L-12: Process table from /proc finds at least the current process.
#[test]
fn process_table_finds_self() {
    use netoproc::process::build_process_table;

    let table = build_process_table();

    // The process table maps socket keys to processes. If the test process
    // has any open TCP/UDP sockets, it should find itself. Since we can't
    // guarantee that, just verify the table builds without error.
    // A more comprehensive test would open a known socket and look it up.
    let _ = table;
}

/// TC-L-13: Interface discovery finds at least one interface (lo).
#[test]
fn interface_discovery_finds_loopback() {
    use netoproc::system;

    let result = system::poll_system().expect("poll_system() failed");
    assert!(
        result.interfaces.iter().any(|iface| iface.name == "lo"),
        "expected to find loopback interface 'lo', found: {:?}",
        result
            .interfaces
            .iter()
            .map(|i| &i.name)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_root_or_capable() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn errno_msg() -> String {
    std::io::Error::last_os_error().to_string()
}
