//! Socket options: the store `setsockopt` writes and `getsockopt` reads, with
//! the kernel's validation (net/core/sock.c `sk_setsockopt`/`sk_getsockopt`,
//! net/ipv4/tcp.c `do_tcp_*sockopt`, net/ipv4/ip_sockglue.c,
//! net/ipv6/ipv6_sockglue.c).
//!
//! The buffer sizes are the virtual kernel's sysctl defaults, doubled on set
//! for the kernel's bookkeeping as `sock_setsockopt` doubles them; timeouts
//! are kept in jiffies of the virtual kernel's `HZ` (1000), so a value reads
//! back as the kernel rounds it. The privileged options answer what an
//! unprivileged caller gets.

use std::ffi::c_int;

#[cfg(target_os = "linux")]
use super::Creds;
use super::abi::*;
use super::{Proto, Socket, addr};
use crate::uaccess;
use crate::{EACCES, EINVAL, ENODEV, EOPNOTSUPP, EPERM};

/// The virtual kernel's `HZ`.
const HZ: u64 = 1000;
/// `MAX_SCHEDULE_TIMEOUT` in jiffies: no timeout.
const FOREVER: u64 = i64::MAX as u64;
/// `sysctl_wmem_max`/`sysctl_rmem_max`: the most `SO_SNDBUF`/`SO_RCVBUF` take.
const BUFFER_MAX: i32 = 212_992;
/// `SOCK_MIN_SNDBUF`/`SOCK_MIN_RCVBUF`.
const MIN_SNDBUF: i32 = 4608;
const MIN_RCVBUF: i32 = 2304;
/// `wmem_default`/`rmem_default`, and TCP's `tcp_wmem[1]`/`tcp_rmem[1]`.
const DEFAULT_BUFFER: i32 = 212_992;
const TCP_SNDBUF: i32 = 16_384;
const TCP_RCVBUF: i32 = 131_072;
/// `tcp_rmem[2]`: the most a TCP receive buffer grows to unlocked.
const TCP_RMEM_MAX: i32 = 6_291_456;
/// `TCP_MSS_DEFAULT`: `TCP_MAXSEG` before any path is known.
const TCP_MSS_DEFAULT: i32 = 536;

/// One socket's options.
#[derive(Clone)]
pub(crate) struct Options {
    pub(crate) reuseaddr: bool,
    pub(crate) reuseport: bool,
    pub(crate) keepalive: bool,
    pub(crate) broadcast: bool,
    pub(crate) dontroute: bool,
    pub(crate) oobinline: bool,
    pub(crate) passcred: bool,
    #[cfg(target_os = "linux")]
    pub(crate) priority: i32,
    /// `SO_LINGER`: on, and the time in jiffies.
    pub(crate) linger: (bool, u64),
    /// `SO_RCVTIMEO`/`SO_SNDTIMEO` in jiffies ([`FOREVER`]: none).
    pub(crate) rcvtimeo: u64,
    pub(crate) sndtimeo: u64,
    pub(crate) rcvbuf: i32,
    /// `SOCK_RCVBUF_LOCK`: `SO_RCVBUF` fixed the receive buffer.
    pub(crate) rcvbuf_locked: bool,
    pub(crate) sndbuf: i32,
    pub(crate) rcvlowat: i32,
    /// `SO_BINDTODEVICE`: the interface index, 0 for none.
    pub(crate) bound_if: u32,
    pub(crate) nodelay: bool,
    #[cfg(target_os = "linux")]
    pub(crate) cork: bool,
    pub(crate) keepidle: i32,
    pub(crate) keepintvl: i32,
    pub(crate) keepcnt: i32,
    #[cfg(target_os = "linux")]
    pub(crate) user_timeout: i32,
    pub(crate) maxseg: i32,
    pub(crate) v6only: bool,
    #[cfg(target_os = "macos")]
    pub(crate) nosigpipe: bool,
    /// The IP-level and UDP options (Linux).
    #[cfg(target_os = "linux")]
    pub(crate) ip: IpOptions,
}

/// An inet socket's IP-, IPv6- and UDP-level options: what its sends carry
/// and which ancillary data its receives report.
#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
pub(crate) struct IpOptions {
    /// `IP_TOS`: the type of service an IPv4 send carries.
    pub(crate) tos: u8,
    /// `IP_TTL`: -1 for the default.
    pub(crate) ttl: i32,
    pub(crate) recv_tos: bool,
    pub(crate) pktinfo: bool,
    pub(crate) mtu_discover: i32,
    /// `IPV6_TCLASS`: the traffic class an IPv6 send carries.
    pub(crate) tclass: u8,
    pub(crate) recv_tclass: bool,
    pub(crate) recv_pktinfo6: bool,
    pub(crate) mtu_discover6: i32,
    pub(crate) dontfrag: bool,
    /// `IPV6_UNICAST_HOPS`: -1 for the default.
    pub(crate) hops: i32,
    /// `UDP_SEGMENT`: the segment size a send is cut into, 0 for none.
    pub(crate) gso: u16,
}

/// The TTL and hop limit a socket reports without one set
/// (`net.ipv4.ip_default_ttl`, the loopback route's hop limit).
#[cfg(target_os = "linux")]
const DEFAULT_TTL: i32 = 64;

impl Options {
    pub(crate) fn new(family: i32, ty: i32) -> Options {
        let tcp = (family == AF_INET || family == AF_INET6) && ty == SOCK_STREAM;
        Options {
            reuseaddr: false,
            reuseport: false,
            keepalive: false,
            broadcast: false,
            dontroute: false,
            oobinline: false,
            passcred: false,
            #[cfg(target_os = "linux")]
            priority: 0,
            linger: (false, 0),
            rcvtimeo: FOREVER,
            sndtimeo: FOREVER,
            rcvbuf: if tcp { TCP_RCVBUF } else { DEFAULT_BUFFER },
            rcvbuf_locked: false,
            sndbuf: if tcp { TCP_SNDBUF } else { DEFAULT_BUFFER },
            rcvlowat: 1,
            bound_if: 0,
            nodelay: false,
            #[cfg(target_os = "linux")]
            cork: false,
            keepidle: 7200,
            keepintvl: 75,
            keepcnt: 9,
            #[cfg(target_os = "linux")]
            user_timeout: 0,
            maxseg: 0,
            v6only: false,
            #[cfg(target_os = "linux")]
            ip: IpOptions {
                ttl: -1,
                hops: -1,
                mtu_discover: PMTUDISC_WANT,
                mtu_discover6: PMTUDISC_WANT,
                ..IpOptions::default()
            },
            #[cfg(target_os = "macos")]
            nosigpipe: false,
        }
    }

    /// The receive timeout in virtual nanoseconds, `None` for none.
    pub(crate) fn recv_timeout(&self) -> Option<u64> {
        timeout_nanos(self.rcvtimeo)
    }

    /// The send timeout in virtual nanoseconds, `None` for none.
    pub(crate) fn send_timeout(&self) -> Option<u64> {
        timeout_nanos(self.sndtimeo)
    }

    /// Darwin's `SO_NOSIGPIPE`.
    pub(crate) fn nosigpipe(&self) -> bool {
        #[cfg(target_os = "macos")]
        return self.nosigpipe;
        #[cfg(not(target_os = "macos"))]
        return false;
    }
}

fn timeout_nanos(jiffies: u64) -> Option<u64> {
    (jiffies != FOREVER).then(|| jiffies.saturating_mul(1_000_000_000 / HZ))
}

/// A `struct timeval`'s seconds and microseconds from its guest bytes.
fn timeval(bytes: &[u8]) -> (i64, i64) {
    let sec = i64::from_ne_bytes(bytes[..8].try_into().expect("eight bytes"));
    #[cfg(target_os = "macos")]
    let usec = i64::from(i32::from_ne_bytes(
        bytes[8..12].try_into().expect("four bytes"),
    ));
    #[cfg(not(target_os = "macos"))]
    let usec = i64::from_ne_bytes(bytes[8..16].try_into().expect("eight bytes"));
    (sec, usec)
}

fn timeval_bytes(sec: i64, usec: i64) -> Vec<u8> {
    let mut bytes = vec![0u8; TIMEVAL_LEN];
    bytes[..8].copy_from_slice(&sec.to_ne_bytes());
    #[cfg(target_os = "macos")]
    bytes[8..12].copy_from_slice(&(usec as i32).to_ne_bytes());
    #[cfg(not(target_os = "macos"))]
    bytes[8..16].copy_from_slice(&usec.to_ne_bytes());
    bytes
}

/// `sock_set_timeout`: a timeval into jiffies (rounding microseconds up), a
/// microsecond field outside a second `EDOM`, a negative time an immediate
/// timeout.
fn set_timeout(slot: &mut u64, bytes: &[u8]) -> Result<(), c_int> {
    let (sec, usec) = timeval(bytes);
    if !(0..1_000_000).contains(&usec) {
        return Err(EDOM);
    }
    if sec < 0 {
        *slot = 0;
        return Ok(());
    }
    *slot = if sec == 0 && usec == 0 {
        FOREVER
    } else {
        (sec as u64)
            .saturating_mul(HZ)
            .saturating_add((usec as u64).div_ceil(1_000_000 / HZ))
    };
    Ok(())
}

/// `sock_get_timeout`.
fn get_timeout(jiffies: u64) -> Vec<u8> {
    if jiffies == FOREVER {
        return timeval_bytes(0, 0);
    }
    timeval_bytes(
        (jiffies / HZ) as i64,
        ((jiffies % HZ) * 1_000_000 / HZ) as i64,
    )
}

/// What `getsockopt` reads off the socket's family state.
pub(crate) struct Facts {
    pub(crate) listening: bool,
    #[cfg(target_os = "linux")]
    pub(crate) peer_creds: Creds,
}

fn int(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes(bytes[..4].try_into().expect("four bytes"))
}

fn is_inet(socket: &Socket) -> bool {
    matches!(socket.proto, Proto::Inet(_))
}

fn is_tcp(socket: &Socket) -> bool {
    is_inet(socket) && socket.ty == SOCK_STREAM
}

/// Whether an inet socket has a local port (`inet_num`).
fn bound(socket: &Socket) -> bool {
    match &socket.proto {
        Proto::Inet(inet) => inet.local.is_some_and(|local| local.port != 0),
        _ => false,
    }
}

/// `setsockopt(level, name)` with `len` bytes at the guest's `value`.
pub(crate) fn set(
    socket: &mut Socket,
    level: c_int,
    name: c_int,
    value: usize,
    len: usize,
) -> Result<(), c_int> {
    let read = |n: usize| uaccess::read_bytes(value, n);
    if level == SOL_SOCKET {
        return set_socket(socket, name, len, read);
    }
    match &socket.proto {
        Proto::Unix(_) => Err(EOPNOTSUPP),
        #[cfg(target_os = "linux")]
        Proto::Netlink(_) => Err(ENOPROTOOPT),
        Proto::Inet(_) if level == SOL_TCP && is_tcp(socket) => set_tcp(socket, name, len, read),
        Proto::Inet(_) if level == SOL_IPV6 && socket.family == AF_INET6 => {
            set_ipv6(socket, name, len, read)
        }
        #[cfg(target_os = "linux")]
        Proto::Inet(_) if level == SOL_IP => set_ip(socket, name, len, read),
        #[cfg(target_os = "linux")]
        Proto::Inet(_) if level == SOL_UDP && !is_tcp(socket) => set_udp(socket, name, len, read),
        Proto::Inet(_) => Err(ENOPROTOOPT),
    }
}

/// `do_ip_setsockopt` for the modeled options: an `int`, or a single byte
/// when that is all the caller passed.
#[cfg(target_os = "linux")]
fn set_ip(
    socket: &mut Socket,
    name: c_int,
    len: usize,
    read: impl Fn(usize) -> Result<Vec<u8>, c_int>,
) -> Result<(), c_int> {
    let val = match len {
        0 => 0,
        1..4 => i32::from(read(1)?[0]),
        _ => int(&read(4)?),
    };
    let stream = is_tcp(socket);
    let ip = &mut socket.opts.ip;
    match name {
        // A stream keeps its own ECN bits (`__ip_sock_set_tos`).
        IP_TOS if stream => ip.tos = (val as u8 & !0x3) | (ip.tos & 0x3),
        IP_TOS => ip.tos = val as u8,
        IP_TTL if len < 1 || (val != -1 && !(1..=255).contains(&val)) => return Err(EINVAL),
        IP_TTL => ip.ttl = val,
        IP_RECVTOS => ip.recv_tos = val != 0,
        IP_PKTINFO => ip.pktinfo = val != 0,
        IP_MTU_DISCOVER if !(0..=PMTUDISC_OMIT).contains(&val) => return Err(EINVAL),
        IP_MTU_DISCOVER => ip.mtu_discover = val,
        _ => return Err(ENOPROTOOPT),
    }
    Ok(())
}

/// `udp_lib_setsockopt` for `UDP_SEGMENT`.
#[cfg(target_os = "linux")]
fn set_udp(
    socket: &mut Socket,
    name: c_int,
    len: usize,
    read: impl Fn(usize) -> Result<Vec<u8>, c_int>,
) -> Result<(), c_int> {
    if len < 4 {
        return Err(EINVAL);
    }
    let val = int(&read(4)?);
    match name {
        UDP_SEGMENT => {
            socket.opts.ip.gso = u16::try_from(val).map_err(|_| EINVAL)?;
            Ok(())
        }
        _ => Err(ENOPROTOOPT),
    }
}

fn set_socket(
    socket: &mut Socket,
    name: c_int,
    len: usize,
    read: impl Fn(usize) -> Result<Vec<u8>, c_int>,
) -> Result<(), c_int> {
    if name == SO_BINDTODEVICE_OPT {
        return set_bindtodevice(socket, len, read);
    }
    if len < 4 {
        return Err(EINVAL);
    }
    let val = int(&read(4)?);
    let on = val != 0;
    let tcp = is_tcp(socket);
    let opts = &mut socket.opts;
    match name {
        SO_DEBUG if on => return Err(EACCES),
        SO_DEBUG => {}
        SO_REUSEADDR => opts.reuseaddr = on,
        SO_REUSEPORT if on && !matches!(socket.proto, Proto::Inet(_)) => return Err(EOPNOTSUPP),
        SO_REUSEPORT => opts.reuseport = on,
        SO_DONTROUTE => opts.dontroute = on,
        SO_BROADCAST => opts.broadcast = on,
        SO_KEEPALIVE => opts.keepalive = on,
        SO_OOBINLINE => opts.oobinline = on,
        SO_SNDBUF => opts.sndbuf = (val.clamp(0, BUFFER_MAX) * 2).max(MIN_SNDBUF),
        SO_RCVBUF => {
            opts.rcvbuf = (val.clamp(0, BUFFER_MAX) * 2).max(MIN_RCVBUF);
            opts.rcvbuf_locked = true;
        }
        SO_RCVLOWAT => {
            let val = if val < 0 { i32::MAX } else { val };
            // `tcp_set_rcvlowat`: half the receive buffer once `SO_RCVBUF`
            // locked it, else half `tcp_rmem`'s maximum. (It also grows an
            // unlocked buffer to hold the mark; the model keeps its size.)
            let val = match (tcp, opts.rcvbuf_locked) {
                (true, true) => val.min(opts.rcvbuf >> 1),
                (true, false) => val.min(TCP_RMEM_MAX >> 1),
                (false, _) => val,
            };
            opts.rcvlowat = val.max(1);
        }
        SO_LINGER => {
            if len < 8 {
                return Err(EINVAL);
            }
            let linger = read(8)?;
            let seconds = int(&linger[4..]) as u32 as u64;
            opts.linger = (int(&linger) != 0, seconds.saturating_mul(HZ).min(FOREVER));
        }
        SO_RCVTIMEO | SO_SNDTIMEO => {
            if len < TIMEVAL_LEN {
                return Err(EINVAL);
            }
            let bytes = read(TIMEVAL_LEN)?;
            let slot = if name == SO_RCVTIMEO {
                &mut opts.rcvtimeo
            } else {
                &mut opts.sndtimeo
            };
            set_timeout(slot, &bytes)?;
        }
        #[cfg(target_os = "linux")]
        SO_PASSCRED => opts.passcred = on,
        #[cfg(target_os = "linux")]
        SO_PRIORITY if (0..=6).contains(&val) => opts.priority = val,
        // Above 6 needs CAP_NET_RAW or CAP_NET_ADMIN; the rest need
        // CAP_NET_ADMIN outright.
        #[cfg(target_os = "linux")]
        SO_PRIORITY | SO_MARK | SO_RCVBUFFORCE | SO_SNDBUFFORCE => return Err(EPERM),
        #[cfg(target_os = "linux")]
        SO_BINDTOIFINDEX => bind_to_index(socket, val)?,
        #[cfg(target_os = "macos")]
        SO_NOSIGPIPE => opts.nosigpipe = on,
        _ => return Err(ENOPROTOOPT),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const SO_BINDTODEVICE_OPT: c_int = SO_BINDTODEVICE;
/// Darwin has no `SO_BINDTODEVICE`: a value no option has.
#[cfg(target_os = "macos")]
const SO_BINDTODEVICE_OPT: c_int = -1;

/// `sock_setbindtodevice`: at most `IFNAMSIZ - 1` bytes of a name, an empty
/// one unbinding; a name no interface has is `ENODEV`.
fn set_bindtodevice(
    socket: &mut Socket,
    len: usize,
    read: impl Fn(usize) -> Result<Vec<u8>, c_int>,
) -> Result<(), c_int> {
    let bytes = read(len.min(IFNAMSIZ - 1))?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let index = if end == 0 {
        0
    } else {
        let name = std::str::from_utf8(&bytes[..end]).map_err(|_| ENODEV)?;
        super::iface::by_name(name).ok_or(ENODEV)?.index
    };
    bind_to_index(socket, index as i32)
}

/// `sock_bindtoindex_locked`: rebinding a bound socket needs CAP_NET_RAW.
fn bind_to_index(socket: &mut Socket, index: i32) -> Result<(), c_int> {
    if socket.opts.bound_if != 0 {
        return Err(EPERM);
    }
    if index < 0 {
        return Err(EINVAL);
    }
    socket.opts.bound_if = index as u32;
    Ok(())
}

fn set_tcp(
    socket: &mut Socket,
    name: c_int,
    len: usize,
    read: impl Fn(usize) -> Result<Vec<u8>, c_int>,
) -> Result<(), c_int> {
    if len < 4 {
        return Err(EINVAL);
    }
    let val = int(&read(4)?);
    let opts = &mut socket.opts;
    match name {
        TCP_NODELAY => opts.nodelay = val != 0,
        #[cfg(target_os = "linux")]
        TCP_CORK => opts.cork = val != 0,
        TCP_KEEPIDLE | TCP_KEEPINTVL if !(1..=32767).contains(&val) => return Err(EINVAL),
        TCP_KEEPIDLE => opts.keepidle = val,
        TCP_KEEPINTVL => opts.keepintvl = val,
        TCP_KEEPCNT if !(1..=127).contains(&val) => return Err(EINVAL),
        TCP_KEEPCNT => opts.keepcnt = val,
        TCP_MAXSEG if val != 0 && !(88..=32767).contains(&val) => return Err(EINVAL),
        TCP_MAXSEG => opts.maxseg = val,
        #[cfg(target_os = "linux")]
        TCP_QUICKACK => {}
        #[cfg(target_os = "linux")]
        TCP_USER_TIMEOUT if val < 0 => return Err(EINVAL),
        #[cfg(target_os = "linux")]
        TCP_USER_TIMEOUT => opts.user_timeout = val,
        _ => return Err(ENOPROTOOPT),
    }
    Ok(())
}

fn set_ipv6(
    socket: &mut Socket,
    name: c_int,
    len: usize,
    read: impl Fn(usize) -> Result<Vec<u8>, c_int>,
) -> Result<(), c_int> {
    if name == IPV6_V6ONLY {
        if len < 4 || bound(socket) {
            return Err(EINVAL);
        }
        socket.opts.v6only = int(&read(4)?) != 0;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // `do_ipv6_setsockopt` reads an `int` when there is room for one and
        // takes 0 otherwise; every modeled option but `IPV6_DONTFRAG` then
        // refuses the short value.
        if len < 4 && name != IPV6_DONTFRAG {
            return Err(EINVAL);
        }
        let val = if len < 4 { 0 } else { int(&read(4)?) };
        let stream = is_tcp(socket);
        let ip = &mut socket.opts.ip;
        match name {
            IPV6_TCLASS if !(-1..=0xff).contains(&val) => return Err(EINVAL),
            // RFC 3542 6.5: -1 is the default class, 0; a stream keeps its
            // own ECN bits.
            IPV6_TCLASS if stream => ip.tclass = (val.max(0) as u8 & !0x3) | (ip.tclass & 0x3),
            IPV6_TCLASS => ip.tclass = val.max(0) as u8,
            IPV6_RECVTCLASS => ip.recv_tclass = val != 0,
            IPV6_RECVPKTINFO => ip.recv_pktinfo6 = val != 0,
            IPV6_MTU_DISCOVER if !(0..=PMTUDISC_OMIT).contains(&val) => return Err(EINVAL),
            IPV6_MTU_DISCOVER => ip.mtu_discover6 = val,
            IPV6_DONTFRAG => ip.dontfrag = val != 0,
            IPV6_UNICAST_HOPS if !(-1..=255).contains(&val) => return Err(EINVAL),
            IPV6_UNICAST_HOPS => ip.hops = val,
            _ => return Err(ENOPROTOOPT),
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    Err(ENOPROTOOPT)
}

/// `getsockopt(level, name)` into the guest's `value`, `*len_ptr` bytes of
/// room in and the value's length out.
pub(crate) fn get(
    socket: &mut Socket,
    facts: Facts,
    level: c_int,
    name: c_int,
    value: usize,
    len_ptr: usize,
) -> Result<(), c_int> {
    let len = addr::read_len(len_ptr)?;
    let answer = if level == SOL_SOCKET {
        if len < 0 {
            return Err(EINVAL);
        }
        let answer = get_socket(socket, facts, name)?;
        // `sock_getbindtodevice`: the whole name or `EINVAL`.
        #[cfg(target_os = "linux")]
        if name == SO_BINDTODEVICE && answer.len() > len as usize {
            return Err(EINVAL);
        }
        answer
    } else {
        match &socket.proto {
            Proto::Unix(_) => return Err(EOPNOTSUPP),
            #[cfg(target_os = "linux")]
            Proto::Netlink(_) => return Err(ENOPROTOOPT),
            Proto::Inet(_) if level == SOL_TCP && is_tcp(socket) => get_tcp(socket, name)?,
            Proto::Inet(_) if level == SOL_IPV6 && socket.family == AF_INET6 => {
                get_ipv6(socket, name)?
            }
            #[cfg(target_os = "linux")]
            Proto::Inet(_) if level == SOL_UDP && !is_tcp(socket) => get_udp(socket, name)?,
            // `do_ip_getsockopt`: a negative room is `EINVAL`; a value that
            // fits a byte, asked for with less room than an `int`, is one
            // byte.
            #[cfg(target_os = "linux")]
            Proto::Inet(_) if level == SOL_IP => {
                if len < 0 {
                    return Err(EINVAL);
                }
                let val = get_ip(socket, name)?;
                if len < 4 && len > 0 && (0..=255).contains(&val) {
                    uaccess::write_bytes(value, &[val as u8])?;
                    return uaccess::write(len_ptr, &1i32);
                }
                int_bytes(val)
            }
            // `do_ip_getsockopt`: an IPv4 socket's own level, and every
            // other one, is answered by the IP layer.
            Proto::Inet(_) if level == SOL_IP => return Err(ENOPROTOOPT),
            Proto::Inet(_) if socket.family == AF_INET6 => return Err(ENOPROTOOPT),
            Proto::Inet(_) => return Err(EOPNOTSUPP),
        }
    };
    // The int-valued protocol levels take `min(len, sizeof(int))` as unsigned,
    // so a negative room there is a whole int.
    let room = if len >= 0 {
        (len as usize).min(answer.len())
    } else {
        answer.len()
    };
    uaccess::write_bytes(value, &answer[..room])?;
    uaccess::write(len_ptr, &(room as i32))
}

fn int_bytes(value: i32) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

fn get_socket(socket: &mut Socket, facts: Facts, name: c_int) -> Result<Vec<u8>, c_int> {
    let opts = &socket.opts;
    Ok(match name {
        SO_DEBUG => int_bytes(0),
        SO_DONTROUTE => int_bytes(opts.dontroute.into()),
        SO_BROADCAST => int_bytes(opts.broadcast.into()),
        SO_SNDBUF => int_bytes(opts.sndbuf),
        SO_RCVBUF => int_bytes(opts.rcvbuf),
        SO_REUSEADDR => int_bytes(opts.reuseaddr.into()),
        SO_REUSEPORT => int_bytes(opts.reuseport.into()),
        SO_KEEPALIVE => int_bytes(opts.keepalive.into()),
        SO_TYPE => int_bytes(socket.ty),
        SO_ERROR => int_bytes(socket.take_error().unwrap_or(0)),
        SO_OOBINLINE => int_bytes(opts.oobinline.into()),
        SO_LINGER => {
            let mut bytes = i32::from(opts.linger.0).to_ne_bytes().to_vec();
            bytes.extend(((opts.linger.1 / HZ) as i32).to_ne_bytes());
            bytes
        }
        SO_RCVTIMEO => get_timeout(opts.rcvtimeo),
        SO_SNDTIMEO => get_timeout(opts.sndtimeo),
        SO_RCVLOWAT => int_bytes(opts.rcvlowat),
        SO_SNDLOWAT => int_bytes(1),
        SO_ACCEPTCONN => int_bytes(facts.listening.into()),
        #[cfg(target_os = "linux")]
        SO_PROTOCOL => int_bytes(socket.protocol),
        #[cfg(target_os = "linux")]
        SO_DOMAIN => int_bytes(socket.family),
        #[cfg(target_os = "linux")]
        SO_PRIORITY => int_bytes(opts.priority),
        #[cfg(target_os = "linux")]
        SO_MARK => int_bytes(0),
        #[cfg(target_os = "linux")]
        SO_PASSCRED => int_bytes(opts.passcred.into()),
        #[cfg(target_os = "linux")]
        SO_PEERCRED => facts.peer_creds.bytes().to_vec(),
        #[cfg(target_os = "linux")]
        SO_BINDTOIFINDEX => int_bytes(opts.bound_if as i32),
        #[cfg(target_os = "linux")]
        SO_BINDTODEVICE => {
            if opts.bound_if == 0 {
                return Ok(Vec::new());
            }
            let name = super::iface::by_index(opts.bound_if)
                .map(|interface| interface.name)
                .ok_or(ENODEV)?;
            let mut bytes = name.as_bytes().to_vec();
            bytes.push(0);
            bytes
        }
        #[cfg(target_os = "macos")]
        SO_NOSIGPIPE => int_bytes(opts.nosigpipe.into()),
        _ => return Err(ENOPROTOOPT),
    })
}

fn get_tcp(socket: &Socket, name: c_int) -> Result<Vec<u8>, c_int> {
    let opts = &socket.opts;
    Ok(int_bytes(match name {
        TCP_NODELAY => opts.nodelay.into(),
        #[cfg(target_os = "linux")]
        TCP_CORK => opts.cork.into(),
        TCP_KEEPIDLE => opts.keepidle,
        TCP_KEEPINTVL => opts.keepintvl,
        TCP_KEEPCNT => opts.keepcnt,
        TCP_MAXSEG if opts.maxseg != 0 => opts.maxseg,
        TCP_MAXSEG => TCP_MSS_DEFAULT,
        #[cfg(target_os = "linux")]
        TCP_QUICKACK => 1,
        #[cfg(target_os = "linux")]
        TCP_USER_TIMEOUT => opts.user_timeout,
        _ => return Err(ENOPROTOOPT),
    }))
}

fn get_ipv6(socket: &Socket, name: c_int) -> Result<Vec<u8>, c_int> {
    if name == IPV6_V6ONLY {
        return Ok(int_bytes(socket.opts.v6only.into()));
    }
    #[cfg(target_os = "linux")]
    {
        let ip = &socket.opts.ip;
        Ok(int_bytes(match name {
            IPV6_TCLASS => i32::from(ip.tclass),
            IPV6_RECVTCLASS => ip.recv_tclass.into(),
            IPV6_RECVPKTINFO => ip.recv_pktinfo6.into(),
            IPV6_MTU_DISCOVER => ip.mtu_discover6,
            IPV6_DONTFRAG => ip.dontfrag.into(),
            IPV6_UNICAST_HOPS if ip.hops < 0 => DEFAULT_TTL,
            IPV6_UNICAST_HOPS => ip.hops,
            _ => return Err(ENOPROTOOPT),
        }))
    }
    #[cfg(target_os = "macos")]
    Err(ENOPROTOOPT)
}

/// An IP-level option's value (`do_ip_getsockopt`).
#[cfg(target_os = "linux")]
fn get_ip(socket: &Socket, name: c_int) -> Result<i32, c_int> {
    let ip = &socket.opts.ip;
    Ok(match name {
        IP_TOS => i32::from(ip.tos),
        IP_TTL if ip.ttl < 0 => DEFAULT_TTL,
        IP_TTL => ip.ttl,
        IP_RECVTOS => ip.recv_tos.into(),
        IP_PKTINFO => ip.pktinfo.into(),
        IP_MTU_DISCOVER => ip.mtu_discover,
        _ => return Err(ENOPROTOOPT),
    })
}

/// `udp_lib_getsockopt` for `UDP_SEGMENT`.
#[cfg(target_os = "linux")]
fn get_udp(socket: &Socket, name: c_int) -> Result<Vec<u8>, c_int> {
    match name {
        UDP_SEGMENT => Ok(int_bytes(i32::from(socket.opts.ip.gso))),
        _ => Err(ENOPROTOOPT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_round_to_jiffies_and_refuse_a_microsecond_past_a_second() {
        let mut slot = FOREVER;
        set_timeout(&mut slot, &timeval_bytes(2, 0)).unwrap();
        assert_eq!(get_timeout(slot), timeval_bytes(2, 0));
        set_timeout(&mut slot, &timeval_bytes(0, 1500)).unwrap();
        assert_eq!(get_timeout(slot), timeval_bytes(0, 2000));
        assert_eq!(
            set_timeout(&mut slot, &timeval_bytes(0, 1_000_000)),
            Err(EDOM)
        );
        assert_eq!(set_timeout(&mut slot, &timeval_bytes(0, -1)), Err(EDOM));
        set_timeout(&mut slot, &timeval_bytes(0, 0)).unwrap();
        assert_eq!(timeout_nanos(slot), None);
        set_timeout(&mut slot, &timeval_bytes(-1, 0)).unwrap();
        assert_eq!(timeout_nanos(slot), Some(0));
    }

    #[test]
    fn defaults_are_the_virtual_kernels_sysctls() {
        let tcp = Options::new(AF_INET, SOCK_STREAM);
        assert_eq!((tcp.sndbuf, tcp.rcvbuf), (TCP_SNDBUF, TCP_RCVBUF));
        let udp = Options::new(AF_INET, SOCK_DGRAM);
        assert_eq!((udp.sndbuf, udp.rcvbuf), (DEFAULT_BUFFER, DEFAULT_BUFFER));
        assert_eq!(udp.recv_timeout(), None);
    }
}
