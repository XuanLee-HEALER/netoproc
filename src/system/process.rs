use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::NetopError;

// libproc constants
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;

// Socket families
const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;

// Socket types
const SOCK_STREAM: i32 = 1;
#[allow(dead_code)]
const SOCK_DGRAM: i32 = 2;

// TCP states from the kernel
const TCPS_CLOSED: i32 = 0;
const TCPS_LISTEN: i32 = 1;
const TCPS_SYN_SENT: i32 = 2;
const TCPS_SYN_RECEIVED: i32 = 3;
const TCPS_ESTABLISHED: i32 = 4;
const TCPS_CLOSE_WAIT: i32 = 5;
const TCPS_FIN_WAIT_1: i32 = 6;
const TCPS_CLOSING: i32 = 7;
const TCPS_LAST_ACK: i32 = 8;
const TCPS_FIN_WAIT_2: i32 = 9;
const TCPS_TIME_WAIT: i32 = 10;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct proc_fdinfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}

const _: () = assert!(mem::size_of::<proc_fdinfo>() == 8);

// proc_fileinfo is part of socket_fdinfo
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct proc_fileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

// in_sockinfo — matches macOS <sys/proc_info.h> (80 bytes)
// Contains foreign/local addresses as unions of in4in6_addr/in6_addr (16 bytes each).
// IPv4 addresses are in in4in6 format: 12 bytes padding + 4 bytes IPv4 address.
#[repr(C)]
#[derive(Clone, Copy)]
struct in_sockinfo {
    insi_fport: i32, // foreign port (network byte order in lower 16 bits)
    insi_lport: i32, // local port (network byte order in lower 16 bits)
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8, // INI_IPV4 = 0x1, INI_IPV6 = 0x2
    insi_ip_ttl: u8,
    _rfu_1: u32,          // reserved (compiler inserts 2 bytes padding before this)
    insi_faddr: [u8; 16], // foreign address (union: in4in6_addr or in6_addr)
    insi_laddr: [u8; 16], // local address (union: in4in6_addr or in6_addr)
    _tail: [u8; 16],      // insi_v4 (1 byte) + padding + insi_v6 (12 bytes)
}

const _: () = assert!(mem::size_of::<in_sockinfo>() == 80);

// tcp_sockinfo — matches macOS <sys/proc_info.h> (120 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct tcp_sockinfo {
    tcpsi_ini: in_sockinfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    _rfu_1: u32, // reserved
    tcpsi_tp: u64,
}

const _: () = assert!(mem::size_of::<tcp_sockinfo>() == 120);

// socket_info — matches macOS <sys/proc_info.h> (768 bytes)
// soi_stat is struct vinfo_stat (136 bytes) — treated as opaque blob since we don't need its fields.
// soi_proto is the union of tcp_sockinfo, in_sockinfo, un_sockinfo, etc. (528 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct socket_info {
    _soi_stat: [u8; 136], // opaque vinfo_stat
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: sockbuf_info,
    soi_snd: sockbuf_info,
    soi_kind: i32,
    _rfu_1: u32, // reserved
    soi_proto: [u8; 528],
}

const _: () = assert!(mem::size_of::<socket_info>() == 768);

#[repr(C)]
#[derive(Clone, Copy)]
struct sockbuf_info {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

const _: () = assert!(mem::size_of::<proc_fileinfo>() == 24);

// socket_fdinfo as returned by proc_pidfdinfo (792 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct socket_fdinfo {
    pfi: proc_fileinfo,
    psi: socket_info,
}

const _: () = assert!(mem::size_of::<socket_fdinfo>() == 792);

unsafe extern "C" {
    fn proc_listpids(
        type_: u32,
        typeinfo: u32,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;

    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;

    fn proc_pidfdinfo(
        pid: libc::c_int,
        fd: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;

    fn proc_name(pid: libc::c_int, buffer: *mut libc::c_char, buffersize: u32) -> libc::c_int;
}

/// Raw process data collected from libproc
#[derive(Debug, Clone)]
pub struct RawProcess {
    pub pid: u32,
    pub name: String,
    pub uid: u32,
    pub sockets: Vec<RawSocket>,
}

/// Raw socket info from proc_pidfdinfo
#[derive(Debug, Clone)]
pub struct RawSocket {
    pub fd: i32,
    pub family: i32,    // AF_INET or AF_INET6
    pub sock_type: i32, // SOCK_STREAM, SOCK_DGRAM, etc.
    pub protocol: i32,  // IPPROTO_TCP, IPPROTO_UDP, etc.
    pub local_addr: Option<IpAddr>,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: u16,
    pub tcp_state: Option<i32>,
}

/// Enumerate all processes with their network sockets
pub fn list_processes() -> Result<Vec<RawProcess>, NetopError> {
    let pids = list_pids()?;
    let mut processes = Vec::new();

    for pid in pids {
        match get_process_info(pid) {
            Ok(Some(proc)) => processes.push(proc),
            Ok(None) => {} // process vanished or has no sockets
            Err(_) => {}   // skip processes we can't inspect (ESRCH, EPERM)
        }
    }

    Ok(processes)
}

fn list_pids() -> Result<Vec<i32>, NetopError> {
    let mut buf_size = 4096 * mem::size_of::<i32>();
    let mut buffer: Vec<i32> = vec![0; buf_size / mem::size_of::<i32>()];

    loop {
        let ret = unsafe {
            proc_listpids(
                PROC_ALL_PIDS,
                0,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buf_size as libc::c_int,
            )
        };

        if ret <= 0 {
            return Err(NetopError::Libproc("proc_listpids failed".to_string()));
        }

        let bytes_returned = ret as usize;
        let count = bytes_returned / mem::size_of::<i32>();

        if count >= buffer.len() {
            // Buffer might be too small, double it
            buf_size *= 2;
            buffer.resize(buf_size / mem::size_of::<i32>(), 0);
            continue;
        }

        buffer.truncate(count);
        return Ok(buffer);
    }
}

fn get_process_name(pid: i32) -> String {
    let mut name_buf = [0u8; 256];
    let ret = unsafe {
        proc_name(
            pid,
            name_buf.as_mut_ptr() as *mut libc::c_char,
            name_buf.len() as u32,
        )
    };
    if ret > 0 {
        let cstr = unsafe { CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char) };
        cstr.to_string_lossy().into_owned()
    } else {
        String::new()
    }
}

fn get_process_info(pid: i32) -> Result<Option<RawProcess>, NetopError> {
    let name = get_process_name(pid);

    // Get file descriptor list
    let fds = match list_fds(pid) {
        Ok(fds) => fds,
        Err(_) => return Ok(None), // process vanished
    };

    // Filter for socket fds and get socket info
    let mut sockets = Vec::new();
    for fd_info in &fds {
        if fd_info.proc_fdtype == PROX_FDTYPE_SOCKET
            && let Ok(Some(sock)) = get_socket_info(pid, fd_info.proc_fd)
        {
            // Only include network sockets (AF_INET, AF_INET6)
            if sock.family == AF_INET || sock.family == AF_INET6 {
                sockets.push(sock);
            }
        }
    }

    if sockets.is_empty() {
        return Ok(None);
    }

    // Get process UID
    let uid = get_process_uid(pid);

    Ok(Some(RawProcess {
        pid: pid as u32,
        name,
        uid,
        sockets,
    }))
}

fn get_process_uid(pid: i32) -> u32 {
    // Use getpwuid or read from proc_bsdinfo
    // For simplicity, we'll use a basic approach
    #[repr(C)]
    struct proc_bsdinfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        _rest: [u8; 92], // rest of the 136-byte struct
    }
    const _: () = assert!(mem::size_of::<proc_bsdinfo>() == 136);

    const PROC_PIDTBSDINFO: i32 = 3;
    let mut info: proc_bsdinfo = unsafe { mem::zeroed() };
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            mem::size_of::<proc_bsdinfo>() as libc::c_int,
        )
    };
    if ret > 0 { info.pbi_uid } else { 0 }
}

fn list_fds(pid: i32) -> Result<Vec<proc_fdinfo>, NetopError> {
    let buf_size = 4096 * mem::size_of::<proc_fdinfo>();
    let mut buffer: Vec<u8> = vec![0; buf_size];

    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buf_size as libc::c_int,
        )
    };

    if ret <= 0 {
        let errno = std::io::Error::last_os_error();
        let raw_errno = errno.raw_os_error().unwrap_or(0);
        // ESRCH (3) = process doesn't exist, EPERM (1) = no permission
        if raw_errno == 3 || raw_errno == 1 {
            return Ok(Vec::new());
        }
        return Err(NetopError::Libproc(format!(
            "proc_pidinfo(PROC_PIDLISTFDS) failed for pid {pid}: {errno}"
        )));
    }

    let count = ret as usize / mem::size_of::<proc_fdinfo>();
    let mut fds = Vec::with_capacity(count);

    for i in 0..count {
        let offset = i * mem::size_of::<proc_fdinfo>();
        let fd_info: proc_fdinfo =
            unsafe { std::ptr::read(buffer[offset..].as_ptr() as *const proc_fdinfo) };
        fds.push(fd_info);
    }

    Ok(fds)
}

fn get_socket_info(pid: i32, fd: i32) -> Result<Option<RawSocket>, NetopError> {
    let mut info: socket_fdinfo = unsafe { mem::zeroed() };

    let ret = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            &mut info as *mut _ as *mut libc::c_void,
            mem::size_of::<socket_fdinfo>() as libc::c_int,
        )
    };

    if ret <= 0 {
        return Ok(None); // socket may have closed
    }

    let family = info.psi.soi_family;
    let sock_type = info.psi.soi_type;
    let protocol = info.psi.soi_protocol;

    let (local_addr, local_port, remote_addr, remote_port, tcp_state) =
        if family == AF_INET || family == AF_INET6 {
            if sock_type == SOCK_STREAM {
                // TCP — read from tcp_sockinfo union
                let tcp: tcp_sockinfo =
                    unsafe { std::ptr::read(info.psi.soi_proto.as_ptr() as *const tcp_sockinfo) };
                let (la, lp) = extract_address(&tcp.tcpsi_ini, family, true);
                let (ra, rp) = extract_address(&tcp.tcpsi_ini, family, false);
                (la, lp, ra, rp, Some(tcp.tcpsi_state))
            } else {
                // UDP or other — read from in_sockinfo union
                let inp: in_sockinfo =
                    unsafe { std::ptr::read(info.psi.soi_proto.as_ptr() as *const in_sockinfo) };
                let (la, lp) = extract_address(&inp, family, true);
                let (ra, rp) = extract_address(&inp, family, false);
                (la, lp, ra, rp, None)
            }
        } else {
            return Ok(None);
        };

    Ok(Some(RawSocket {
        fd,
        family,
        sock_type,
        protocol,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        tcp_state,
    }))
}

fn extract_address(inp: &in_sockinfo, family: i32, is_local: bool) -> (Option<IpAddr>, u16) {
    let port = if is_local {
        (inp.insi_lport as u16).to_be()
    } else {
        (inp.insi_fport as u16).to_be()
    };

    let addr_bytes = if is_local {
        &inp.insi_laddr
    } else {
        &inp.insi_faddr
    };

    let addr = if family == AF_INET {
        // IPv4: last 4 bytes of the 16-byte union (in4in6 format)
        // IPv4 in in4in6 format is at bytes 12..16 of the 16-byte address field
        let ip_bytes = [
            addr_bytes[12],
            addr_bytes[13],
            addr_bytes[14],
            addr_bytes[15],
        ];
        let ip = Ipv4Addr::from(ip_bytes);
        Some(IpAddr::V4(ip))
    } else if family == AF_INET6 {
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(addr_bytes);
        let ip = Ipv6Addr::from(ip_bytes);
        Some(IpAddr::V6(ip))
    } else {
        None
    };

    (addr, port)
}

/// Convert kernel TCP state to our SocketState
pub fn tcp_state_to_socket_state(state: i32) -> crate::model::SocketState {
    use crate::model::SocketState;
    match state {
        TCPS_CLOSED => SocketState::Closed,
        TCPS_LISTEN => SocketState::Listen,
        TCPS_SYN_SENT => SocketState::SynSent,
        TCPS_SYN_RECEIVED => SocketState::SynReceived,
        TCPS_ESTABLISHED => SocketState::Established,
        TCPS_CLOSE_WAIT => SocketState::CloseWait,
        TCPS_FIN_WAIT_1 => SocketState::FinWait1,
        TCPS_CLOSING => SocketState::Closing,
        TCPS_LAST_ACK => SocketState::LastAck,
        TCPS_FIN_WAIT_2 => SocketState::FinWait2,
        TCPS_TIME_WAIT => SocketState::TimeWait,
        _ => SocketState::Closed,
    }
}
