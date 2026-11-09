//! Sockets and their processes from libproc, the way lsof finds them: every
//! pid's file descriptors, and for each socket its addresses and TCP state.
//! Seeing other users' processes needs root.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use netwatch_common::{PROTO_TCP, PROTO_UDP};

use crate::procs::{OwnerCache, ProcSock, Scan};

const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const INI_IPV4: u8 = 0x1;

/// `struct socket_fdinfo` and the offsets read from it (checked against the SDK's
/// <sys/proc_info.h>): psi.soi_so, soi_family, soi_kind, soi_proto, and inside
/// soi_proto (an in_sockinfo, or a tcp_sockinfo starting with one) the ports,
/// address family flags, addresses and TCP state.
const SOCKET_FDINFO_SIZE: usize = 792;
const SOI_SO: usize = 160;
const SOI_FAMILY: usize = 184;
const SOI_KIND: usize = 256;
const SOI_PROTO: usize = 264;
const INSI_FPORT: usize = 0;
const INSI_LPORT: usize = 4;
const INSI_VFLAG: usize = 24;
const INSI_FADDR: usize = 32;
const INSI_LADDR: usize = 48;
const TCPSI_STATE: usize = 80;

fn i32_at(b: &[u8], i: usize) -> i32 {
    i32::from_ne_bytes(b[i..i + 4].try_into().expect("4 bytes"))
}

/// macOS TSI_S_* (sys/proc_info.h) to the Linux numbering /proc/net/tcp uses.
fn linux_tcp_state(tsi: i32) -> u8 {
    match tsi {
        1 => 0x0a,  // LISTEN
        2 => 0x02,  // SYN_SENT
        3 => 0x03,  // SYN_RECEIVED
        4 => 0x01,  // ESTABLISHED
        5 => 0x08,  // CLOSE_WAIT
        6 => 0x04,  // FIN_WAIT_1
        7 => 0x0b,  // CLOSING
        8 => 0x09,  // LAST_ACK
        9 => 0x05,  // FIN_WAIT_2
        10 => 0x06, // TIME_WAIT
        _ => 0x07,  // CLOSED
    }
}

fn addr_at(b: &[u8], off: usize, v4: bool) -> IpAddr {
    if v4 {
        // struct in4in6_addr: 12 bytes of padding, then the in_addr.
        IpAddr::V4(Ipv4Addr::new(
            b[off + 12],
            b[off + 13],
            b[off + 14],
            b[off + 15],
        ))
    } else {
        let a: [u8; 16] = b[off..off + 16].try_into().expect("16 bytes");
        let v6 = Ipv6Addr::from(a);
        v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
    }
}

/// Parses a socket_fdinfo; `inode` is the kernel's socket handle, the same in
/// every process that shares the socket.
fn parse_socket(b: &[u8]) -> Option<ProcSock> {
    let family = i32_at(b, SOI_FAMILY);
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return None;
    }
    let kind = i32_at(b, SOI_KIND);
    let proto = match kind {
        SOCKINFO_TCP => PROTO_TCP,
        SOCKINFO_IN => PROTO_UDP,
        _ => return None,
    };
    let ini = SOI_PROTO;
    let v4 = b[ini + INSI_VFLAG] & INI_IPV4 != 0;
    let lport = u16::from_be(i32_at(b, ini + INSI_LPORT) as u16);
    let rport = u16::from_be(i32_at(b, ini + INSI_FPORT) as u16);
    let local = addr_at(b, ini + INSI_LADDR, v4);
    let remote = addr_at(b, ini + INSI_FADDR, v4);
    let state = if proto == PROTO_TCP {
        linux_tcp_state(i32_at(b, ini + TCPSI_STATE))
    } else if remote.is_unspecified() {
        0x07 // unconnected, as Linux shows UDP sockets
    } else {
        0x01
    };
    Some(ProcSock {
        proto,
        local,
        lport,
        remote,
        rport,
        state,
        inode: u64::from_ne_bytes(b[SOI_SO..SOI_SO + 8].try_into().ok()?),
    })
}

fn pids() -> Vec<i32> {
    // SAFETY: a NULL buffer asks for the count.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut v = vec![0i32; n as usize + 64];
    let bytes = (v.len() * size_of::<i32>()) as libc::c_int;
    // SAFETY: v holds `bytes` bytes.
    let n = unsafe { libc::proc_listallpids(v.as_mut_ptr().cast(), bytes) };
    v.truncate(n.max(0) as usize);
    v.retain(|&p| p > 0);
    v
}

fn socket_fds(pid: i32) -> Vec<i32> {
    // SAFETY: a NULL buffer asks for the size.
    let size =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Vec::new();
    }
    let n = size as usize / size_of::<libc::proc_fdinfo>() + 16;
    let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(n);
    // SAFETY: the buffer has capacity for n entries; the kernel reports how many bytes it wrote.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            (n * size_of::<libc::proc_fdinfo>()) as libc::c_int,
        )
    };
    if got <= 0 {
        return Vec::new();
    }
    // SAFETY: the kernel initialised `got` bytes of whole proc_fdinfo entries.
    unsafe { fds.set_len(got as usize / size_of::<libc::proc_fdinfo>()) };
    fds.iter()
        .filter(|f| f.proc_fdtype == PROX_FDTYPE_SOCKET)
        .map(|f| f.proc_fd)
        .collect()
}

fn socket_info(pid: i32, fd: i32) -> Option<ProcSock> {
    // u64 storage keeps the buffer aligned for the kernel's copy.
    let mut buf = [0u64; SOCKET_FDINFO_SIZE / 8];
    // SAFETY: buf is SOCKET_FDINFO_SIZE bytes, what PROC_PIDFDSOCKETINFO writes.
    let n = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            buf.as_mut_ptr().cast(),
            SOCKET_FDINFO_SIZE as libc::c_int,
        )
    };
    if n as usize != SOCKET_FDINFO_SIZE {
        return None;
    }
    // SAFETY: plain bytes view of the initialised buffer.
    let b = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), SOCKET_FDINFO_SIZE) };
    parse_socket(b)
}

/// Every internet socket with the pids holding it (first one first).
fn all_sockets() -> Vec<(ProcSock, u32)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for pid in pids() {
        for fd in socket_fds(pid) {
            if let Some(s) = socket_info(pid, fd) {
                // A socket shared after fork is listed once, like /proc/net does.
                if seen.insert((s.inode, s.proto)) {
                    out.push((s, pid as u32));
                }
            }
        }
    }
    out
}

/// Internet sockets, as procs::sockets() returns them on Linux.
pub fn sockets() -> Vec<ProcSock> {
    all_sockets().into_iter().map(|(s, _)| s).collect()
}

pub fn scan(cache: &mut OwnerCache, now: i64) -> Scan {
    let socks = all_sockets()
        .into_iter()
        .map(|(s, pid)| {
            let owner = cache.owner(pid, None, now);
            (s, owner)
        })
        .collect();
    Scan {
        socks,
        // No Docker bridges here: Docker Desktop runs its containers in a VM.
        containers: HashMap::new(),
    }
}

/// (proto, local port) -> pid, for owners the capture header didn't give.
pub fn port_owners() -> HashMap<(u8, u16), u32> {
    all_sockets()
        .into_iter()
        .map(|(s, pid)| ((s.proto, s.lport), pid))
        .collect()
}

/// (name, executable path) of a running process; None if it is gone.
pub fn describe(pid: u32) -> Option<(String, Option<String>)> {
    let pid = pid as i32;
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: path has the size passed.
    let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    let exe = (n > 0).then(|| String::from_utf8_lossy(&path[..n as usize]).into_owned());
    let mut name = [0u8; 64];
    // SAFETY: name has the size passed.
    let n = unsafe { libc::proc_name(pid, name.as_mut_ptr().cast(), name.len() as u32) };
    let name = (n > 0).then(|| String::from_utf8_lossy(&name[..n as usize]).into_owned());
    match (name, exe) {
        (Some(n), exe) => Some((n, exe)),
        (None, Some(e)) => {
            let base = e.rsplit('/').next().unwrap_or(&e).to_string();
            Some((base, Some(e)))
        }
        (None, None) => None,
    }
}

/// The outermost app bundle in a path: helpers of "Google Chrome.app" belong to it.
pub fn app_bundle(exe: &str) -> Option<String> {
    exe.split('/')
        .find_map(|seg| seg.strip_suffix(".app"))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_fdinfo_layout() {
        let mut b = vec![0u8; SOCKET_FDINFO_SIZE];
        b[SOI_SO..SOI_SO + 8].copy_from_slice(&0xdead_beefu64.to_ne_bytes());
        b[SOI_FAMILY..SOI_FAMILY + 4].copy_from_slice(&libc::AF_INET.to_ne_bytes());
        b[SOI_KIND..SOI_KIND + 4].copy_from_slice(&SOCKINFO_TCP.to_ne_bytes());
        let ini = SOI_PROTO;
        b[ini + INSI_LPORT..ini + INSI_LPORT + 4]
            .copy_from_slice(&(443u16.to_be() as i32).to_ne_bytes());
        b[ini + INSI_FPORT..ini + INSI_FPORT + 4]
            .copy_from_slice(&(51000u16.to_be() as i32).to_ne_bytes());
        b[ini + INSI_VFLAG] = INI_IPV4;
        b[ini + INSI_LADDR + 12..ini + INSI_LADDR + 16].copy_from_slice(&[192, 168, 1, 20]);
        b[ini + INSI_FADDR + 12..ini + INSI_FADDR + 16].copy_from_slice(&[203, 0, 113, 7]);
        b[ini + TCPSI_STATE..ini + TCPSI_STATE + 4].copy_from_slice(&4i32.to_ne_bytes());
        let s = parse_socket(&b).unwrap();
        assert_eq!(
            (
                s.proto,
                s.local.to_string(),
                s.lport,
                s.remote.to_string(),
                s.rport,
                s.state,
                s.inode
            ),
            (
                PROTO_TCP,
                "192.168.1.20".into(),
                443,
                "203.0.113.7".into(),
                51000,
                0x01,
                0xdead_beef
            )
        );
    }

    #[test]
    fn this_process_sockets_are_found() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let uport = u.local_addr().unwrap().port();
        let me = std::process::id();
        let socks = all_sockets();
        let tcp = socks
            .iter()
            .find(|(s, _)| s.proto == PROTO_TCP && s.lport == port)
            .expect("listener");
        assert!(tcp.0.listening());
        assert_eq!((tcp.1, tcp.0.local.to_string()), (me, "127.0.0.1".into()));
        let udp = socks
            .iter()
            .find(|(s, _)| s.proto == PROTO_UDP && s.lport == uport)
            .expect("udp");
        assert!(udp.0.listening());
        let (name, exe) = describe(me).unwrap();
        assert!(!name.is_empty() && exe.is_some());
    }

    #[test]
    fn app_bundles() {
        assert_eq!(
            app_bundle("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper").as_deref(),
            Some("Google Chrome")
        );
        assert_eq!(app_bundle("/usr/sbin/sshd"), None);
    }
}
