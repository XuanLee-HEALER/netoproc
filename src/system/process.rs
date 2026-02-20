use std::net::IpAddr;

use crate::error::NetopError;

/// Raw process data collected from the system
#[derive(Debug, Clone)]
pub struct RawProcess {
    pub pid: u32,
    pub name: String,
    pub uid: u32,
    pub sockets: Vec<RawSocket>,
}

/// Raw socket info
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

// ---------------------------------------------------------------------------
// macOS: libproc-based process enumeration
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::ffi::CStr;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const PROC_ALL_PIDS: u32 = 1;
    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;

    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 30;
    const SOCK_STREAM: i32 = 1;

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

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct proc_fileinfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct in_sockinfo {
        insi_fport: i32,
        insi_lport: i32,
        insi_gencnt: u64,
        insi_flags: u32,
        insi_flow: u32,
        insi_vflag: u8,
        insi_ip_ttl: u8,
        _rfu_1: u32,
        insi_faddr: [u8; 16],
        insi_laddr: [u8; 16],
        _tail: [u8; 16],
    }

    const _: () = assert!(mem::size_of::<in_sockinfo>() == 80);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct tcp_sockinfo {
        tcpsi_ini: in_sockinfo,
        tcpsi_state: i32,
        tcpsi_timer: [i32; 4],
        tcpsi_mss: i32,
        tcpsi_flags: u32,
        _rfu_1: u32,
        tcpsi_tp: u64,
    }

    const _: () = assert!(mem::size_of::<tcp_sockinfo>() == 120);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct socket_info {
        _soi_stat: [u8; 136],
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
        _rfu_1: u32,
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

    pub fn list_processes() -> Result<Vec<RawProcess>, NetopError> {
        let pids = list_pids()?;
        let mut processes = Vec::new();

        for pid in pids {
            match get_process_info(pid) {
                Ok(Some(proc_info)) => processes.push(proc_info),
                Ok(None) => {}
                Err(_) => {}
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

        let fds = match list_fds(pid) {
            Ok(fds) => fds,
            Err(_) => return Ok(None),
        };

        let mut sockets = Vec::new();
        for fd_info in &fds {
            if fd_info.proc_fdtype == PROX_FDTYPE_SOCKET
                && let Ok(Some(sock)) = get_socket_info(pid, fd_info.proc_fd)
                && (sock.family == AF_INET || sock.family == AF_INET6)
            {
                sockets.push(sock);
            }
        }

        if sockets.is_empty() {
            return Ok(None);
        }

        let uid = get_process_uid(pid);

        Ok(Some(RawProcess {
            pid: pid as u32,
            name,
            uid,
            sockets,
        }))
    }

    fn get_process_uid(pid: i32) -> u32 {
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
            _rest: [u8; 92],
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
            return Ok(None);
        }

        let family = info.psi.soi_family;
        let sock_type = info.psi.soi_type;
        let protocol = info.psi.soi_protocol;

        let (local_addr, local_port, remote_addr, remote_port, tcp_state) = if family == AF_INET
            || family == AF_INET6
        {
            if sock_type == SOCK_STREAM {
                let tcp: tcp_sockinfo =
                    unsafe { std::ptr::read(info.psi.soi_proto.as_ptr() as *const tcp_sockinfo) };
                let (la, lp) = extract_address(&tcp.tcpsi_ini, family, true);
                let (ra, rp) = extract_address(&tcp.tcpsi_ini, family, false);
                (la, lp, ra, rp, Some(tcp.tcpsi_state))
            } else {
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

    pub fn build_process_table() -> crate::model::traffic::ProcessTable {
        use crate::model::traffic::{ProcessInfo, ProcessTable, SocketKey};

        let mut table = ProcessTable::default();

        let processes = match list_processes() {
            Ok(procs) => procs,
            Err(e) => {
                log::warn!("build_process_table: list_processes failed: {e}");
                return table;
            }
        };

        for proc_info in &processes {
            for sock in &proc_info.sockets {
                let (local_addr, remote_addr) = match (sock.local_addr, sock.remote_addr) {
                    (Some(la), Some(ra)) => (la, ra),
                    _ => continue,
                };

                let proto = match sock.sock_type {
                    SOCK_STREAM => 6u8,
                    _ => 17u8,
                };

                let key = SocketKey::new(
                    local_addr,
                    sock.local_port,
                    remote_addr,
                    sock.remote_port,
                    proto,
                );
                table.insert(
                    key,
                    ProcessInfo {
                        pid: proc_info.pid,
                        name: proc_info.name.clone(),
                    },
                );
            }
        }

        table
    }

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
}

#[cfg(target_os = "macos")]
pub use macos_impl::{build_process_table, list_processes, tcp_state_to_socket_state};

// ---------------------------------------------------------------------------
// Linux: /proc-based process enumeration
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    pub fn list_processes() -> Result<Vec<RawProcess>, NetopError> {
        // Step 1: Parse /proc/net/* to get inode → socket info
        let mut inode_to_socket: HashMap<u64, SocketInfo> = HashMap::new();
        for (path, proto, is_v6) in &[
            ("/proc/net/tcp", 6i32, false),
            ("/proc/net/tcp6", 6i32, true),
            ("/proc/net/udp", 17i32, false),
            ("/proc/net/udp6", 17i32, true),
        ] {
            if let Ok(content) = fs::read_to_string(path) {
                parse_proc_net_sockets(&content, *proto, *is_v6, &mut inode_to_socket);
            }
        }

        if inode_to_socket.is_empty() {
            return Ok(Vec::new());
        }

        // Step 2: Scan /proc/<pid>/fd/ to map inodes to PIDs
        let mut pid_sockets: HashMap<u32, Vec<u64>> = HashMap::new();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let pid: u32 = match name_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let fd_dir = entry.path().join("fd");
            let fd_entries = match fs::read_dir(&fd_dir) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for fd_entry in fd_entries.flatten() {
                let link = match fs::read_link(fd_entry.path()) {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                let link_str = link.to_string_lossy();
                if let Some(inode) = crate::process::linux::parse_socket_inode(&link_str)
                    && inode_to_socket.contains_key(&inode)
                {
                    pid_sockets.entry(pid).or_default().push(inode);
                }
            }
        }

        // Step 3: Build RawProcess list
        let mut processes = Vec::new();
        for (pid, inodes) in &pid_sockets {
            let name = read_proc_comm(*pid);
            let uid = read_proc_uid(*pid);

            let mut sockets = Vec::new();
            for inode in inodes {
                if let Some(info) = inode_to_socket.get(inode) {
                    sockets.push(RawSocket {
                        fd: -1,
                        family: if info.local_addr.is_ipv4() { 2 } else { 10 },
                        sock_type: if info.proto == 6 { 1 } else { 2 },
                        protocol: info.proto,
                        local_addr: Some(info.local_addr),
                        local_port: info.local_port,
                        remote_addr: Some(info.remote_addr),
                        remote_port: info.remote_port,
                        tcp_state: info.tcp_state,
                    });
                }
            }

            if !sockets.is_empty() {
                processes.push(RawProcess {
                    pid: *pid,
                    name,
                    uid,
                    sockets,
                });
            }
        }

        Ok(processes)
    }

    struct SocketInfo {
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        proto: i32,
        tcp_state: Option<i32>,
    }

    fn parse_proc_net_sockets(
        content: &str,
        proto: i32,
        is_v6: bool,
        out: &mut HashMap<u64, SocketInfo>,
    ) {
        let parse_addr = if is_v6 {
            crate::process::linux::parse_addr_v6
        } else {
            crate::process::linux::parse_addr_v4
        };

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let (local_addr, local_port) = match parse_addr(fields[1]) {
                Some(v) => v,
                None => continue,
            };
            let (remote_addr, remote_port) = match parse_addr(fields[2]) {
                Some(v) => v,
                None => continue,
            };

            let inode: u64 = match fields[9].parse() {
                Ok(v) if v > 0 => v,
                _ => continue,
            };

            let tcp_state = if proto == 6 {
                u8::from_str_radix(fields[3], 16).ok().map(|s| s as i32)
            } else {
                None
            };

            out.insert(
                inode,
                SocketInfo {
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    proto,
                    tcp_state,
                },
            );
        }
    }

    fn read_proc_comm(pid: u32) -> String {
        let path = format!("/proc/{pid}/comm");
        fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn read_proc_uid(pid: u32) -> u32 {
        let path = format!("/proc/{pid}/status");
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("Uid:")
                    && let Some(uid_str) = rest.split_whitespace().next()
                {
                    return uid_str.parse().unwrap_or(0);
                }
            }
        }
        0
    }

    pub fn build_process_table() -> crate::model::traffic::ProcessTable {
        // Delegate to the process module's implementation
        crate::process::build_process_table()
    }

    pub fn tcp_state_to_socket_state(state: i32) -> crate::model::SocketState {
        crate::process::linux::tcp_state_from_hex(state as u8)
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::{build_process_table, list_processes, tcp_state_to_socket_state};

// ---------------------------------------------------------------------------
// Windows: IP Helper + Toolhelp32 process enumeration
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID,
        MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
        TH32CS_SNAPPROCESS,
    };

    pub fn list_processes() -> Result<Vec<RawProcess>, NetopError> {
        let pid_names = build_pid_name_map();
        let mut pid_sockets: HashMap<u32, Vec<RawSocket>> = HashMap::new();

        // TCP IPv4
        if let Some(rows) = get_tcp4_rows() {
            for row in rows {
                let local_addr = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()));
                let remote_addr = IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()));
                let local_port = u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes());
                let remote_port = u16::from_be_bytes((row.dwRemotePort as u16).to_ne_bytes());

                pid_sockets
                    .entry(row.dwOwningPid)
                    .or_default()
                    .push(RawSocket {
                        fd: -1,
                        family: 2, // AF_INET
                        sock_type: 1, // SOCK_STREAM
                        protocol: 6, // TCP
                        local_addr: Some(local_addr),
                        local_port,
                        remote_addr: Some(remote_addr),
                        remote_port,
                        tcp_state: Some(row.dwState as i32),
                    });
            }
        }

        // TCP IPv6
        if let Some(rows) = get_tcp6_rows() {
            for row in rows {
                let local_addr = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
                let remote_addr = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
                let local_port = u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes());
                let remote_port = u16::from_be_bytes((row.dwRemotePort as u16).to_ne_bytes());

                pid_sockets
                    .entry(row.dwOwningPid)
                    .or_default()
                    .push(RawSocket {
                        fd: -1,
                        family: 23, // AF_INET6 on Windows
                        sock_type: 1,
                        protocol: 6,
                        local_addr: Some(local_addr),
                        local_port,
                        remote_addr: Some(remote_addr),
                        remote_port,
                        tcp_state: Some(row.dwState as i32),
                    });
            }
        }

        // UDP IPv4
        if let Some(rows) = get_udp4_rows() {
            for row in rows {
                let local_addr = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()));
                let local_port = u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes());

                pid_sockets
                    .entry(row.dwOwningPid)
                    .or_default()
                    .push(RawSocket {
                        fd: -1,
                        family: 2,
                        sock_type: 2, // SOCK_DGRAM
                        protocol: 17, // UDP
                        local_addr: Some(local_addr),
                        local_port,
                        remote_addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                        remote_port: 0,
                        tcp_state: None,
                    });
            }
        }

        // UDP IPv6
        if let Some(rows) = get_udp6_rows() {
            for row in rows {
                let local_addr = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
                let local_port = u16::from_be_bytes((row.dwLocalPort as u16).to_ne_bytes());

                pid_sockets
                    .entry(row.dwOwningPid)
                    .or_default()
                    .push(RawSocket {
                        fd: -1,
                        family: 23,
                        sock_type: 2,
                        protocol: 17,
                        local_addr: Some(local_addr),
                        local_port,
                        remote_addr: Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                        remote_port: 0,
                        tcp_state: None,
                    });
            }
        }

        let mut processes = Vec::new();
        for (pid, sockets) in pid_sockets {
            if sockets.is_empty() {
                continue;
            }
            let name = pid_names.get(&pid).cloned().unwrap_or_default();
            processes.push(RawProcess {
                pid,
                name,
                uid: 0, // Windows doesn't have Unix UIDs
                sockets,
            });
        }

        Ok(processes)
    }

    fn get_tcp4_rows() -> Option<Vec<MIB_TCPROW_OWNER_PID>> {
        let mut size: u32 = 0;
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if ret != 0 {
            return None;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
            as *const MIB_TCPROW_OWNER_PID;

        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            result.push(unsafe { *rows_ptr.add(i) });
        }
        Some(result)
    }

    fn get_tcp6_rows() -> Option<Vec<MIB_TCP6ROW_OWNER_PID>> {
        let mut size: u32 = 0;
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if ret != 0 {
            return None;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
            as *const MIB_TCP6ROW_OWNER_PID;

        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            result.push(unsafe { *rows_ptr.add(i) });
        }
        Some(result)
    }

    fn get_udp4_rows() -> Option<Vec<MIB_UDPROW_OWNER_PID>> {
        let mut size: u32 = 0;
        unsafe {
            GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if ret != 0 {
            return None;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
            as *const MIB_UDPROW_OWNER_PID;

        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            result.push(unsafe { *rows_ptr.add(i) });
        }
        Some(result)
    }

    fn get_udp6_rows() -> Option<Vec<MIB_UDP6ROW_OWNER_PID>> {
        let mut size: u32 = 0;
        unsafe {
            GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if ret != 0 {
            return None;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let rows_ptr = buffer.as_ptr().wrapping_add(std::mem::size_of::<u32>())
            as *const MIB_UDP6ROW_OWNER_PID;

        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            result.push(unsafe { *rows_ptr.add(i) });
        }
        Some(result)
    }

    fn build_pid_name_map() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return map;
        }

        let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if unsafe { Process32First(snapshot, &mut entry) } != 0 {
            loop {
                let name = exe_file_to_string(&entry.szExeFile);
                map.insert(entry.th32ProcessID, name);
                if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }

        unsafe { CloseHandle(snapshot) };
        map
    }

    fn exe_file_to_string(bytes: &[i8]) -> String {
        let as_u8: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u8, bytes.len()) };
        let len = as_u8.iter().position(|&b| b == 0).unwrap_or(as_u8.len());
        String::from_utf8_lossy(&as_u8[..len]).into_owned()
    }

    pub fn build_process_table() -> crate::model::traffic::ProcessTable {
        crate::process::build_process_table()
    }

    /// Map Windows MIB_TCP_STATE values to our SocketState enum.
    ///
    /// Windows values: 1=CLOSED, 2=LISTEN, 3=SYN_SENT, 4=SYN_RCVD,
    /// 5=ESTAB, 6=FIN_WAIT1, 7=FIN_WAIT2, 8=CLOSE_WAIT,
    /// 9=CLOSING, 10=LAST_ACK, 11=TIME_WAIT, 12=DELETE_TCB
    pub fn tcp_state_to_socket_state(state: i32) -> crate::model::SocketState {
        use crate::model::SocketState;
        match state {
            1 => SocketState::Closed,
            2 => SocketState::Listen,
            3 => SocketState::SynSent,
            4 => SocketState::SynReceived,
            5 => SocketState::Established,
            6 => SocketState::FinWait1,
            7 => SocketState::FinWait2,
            8 => SocketState::CloseWait,
            9 => SocketState::Closing,
            10 => SocketState::LastAck,
            11 => SocketState::TimeWait,
            _ => SocketState::Closed,
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::{build_process_table, list_processes, tcp_state_to_socket_state};
