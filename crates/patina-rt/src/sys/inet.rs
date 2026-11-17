//! `AF_INET`/`AF_INET6` stream sockets on the supervisor's wire.
//!
//! The guest's descriptor is a real `AF_UNIX` stream socket. Its kernel peer is a socket the
//! supervisor holds (its "hidden end"); the supervisor moves bytes between hidden ends at
//! virtual times. Everything the guest does to its descriptor (readiness, partial reads,
//! `EAGAIN`, `epoll`, `dup`, `fork`, `close`) is the kernel's; this module answers what a unix
//! socket would answer differently from TCP: creation, addresses, `bind`/`listen`/`connect`/
//! `accept`, options, and the TCP error conventions (`ECONNRESET`, `EPIPE` + `SIGPIPE`).
//!
//! The socket's key is its virtual inode number; its state lives in the control region
//! (`proto::wire::WireTab`), shared by every process. After a send, a close or a shutdown the
//! runtime leaves a "sent" mark there; the supervisor reads the marked hidden ends at its next
//! step (every park, yield and request is one).

use super::io::{self, Deadline, Got, IovCursor, Kind, Waiter, POLLERR, POLLHUP, POLLIN};
use super::*;
use proto::ctl::{Op, PARK_IN, PARK_OUT, WIRE_BIND, WIRE_LISTEN};
use proto::vfs::{VINO_BASE, VINO_CAP};
use proto::wire::*;

const AF_UNIX: u64 = 1;
const AF_NETLINK: u64 = 16;
const AF_PACKET: u64 = 17;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const IPPROTO_UDP: u64 = 17;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const IPPROTO_TCP: u64 = 6;
const SOL_SOCKET: i32 = 1;
const SOL_IP: i32 = 0;
const SOL_IPV6: i32 = 41;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_OOB: u64 = 1;

const EPIPE: i64 = 32;
const ENOTSOCK: i64 = 88;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EAFNOSUPPORT: i64 = 97;
const EADDRNOTAVAIL: i64 = 99;
const ENETUNREACH: i64 = 101;
const ECONNABORTED: i64 = 103;
const ECONNRESET: i64 = 104;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const EALREADY: i64 = 114;
const EINPROGRESS: i64 = 115;
const ENOPROTOOPT: i64 = 92;

pub(super) fn tab() -> &'static mut WireTab {
    unsafe { WireTab::at(crate::state::ctl_base()) }
}

pub(super) fn sock(i: usize) -> &'static mut WSock {
    &mut tab().socks[i]
}

/// Table index of the socket open on `fd` (any socket), None for other objects.
pub(super) fn idx_of(fd: i64) -> Option<usize> {
    let st = super::fs::fstat_raw(fd)?;
    if proto::abi::stat::mode(&st) & 0o170000 != 0o140000 {
        return None;
    }
    let i = (crate::vino::of(st[0], st[1]) - VINO_BASE) as usize;
    (i < VINO_CAP).then_some(i)
}

/// Index of the wire socket open on `fd`, if it is one.
pub fn wire_idx(fd: i64) -> Option<usize> {
    idx_of(fd).filter(|&i| sock(i).family != 0)
}

/// Index of the UDP socket open on `fd`, if it is one. Allocates no virtual inode number
/// (a wire socket has had one since it was made), so asking about any other descriptor
/// leaves the run as it was.
pub fn dgram_idx(fd: i64) -> Option<usize> {
    let st = super::fs::fstat_raw(fd)?;
    if proto::abi::stat::mode(&st) & 0o170000 != 0o140000 {
        return None;
    }
    let i = (crate::vino::find(st[0], st[1])? - VINO_BASE) as usize;
    (i < VINO_CAP && sock(i).family != 0 && is_dgram(i)).then_some(i)
}

/// Is wire socket `i` a datagram (UDP) socket?
pub fn is_dgram(i: usize) -> bool {
    sock(i).flags & WF_DGRAM != 0
}

/// Bytes or a close may be waiting at the hidden end of socket `i`.
pub fn mark(i: usize) {
    tab().mark(i);
}

/// Descriptors were closed in bulk (`close_range`): read every hidden end at the next step.
pub fn mark_all() {
    tab().scan_all = 1;
}

pub(super) fn sup(op: Op, a: [u64; 6]) -> i64 {
    crate::sup::call_sup(op, a).ret
}

pub(super) fn refuse(what: &[u8]) {
    unsafe { proto::vfs::Vfs::at(crate::state::ctl_base()) }.refuse(what);
}

// ---- addresses ----

/// (port, address kind) of a guest `sockaddr_in`/`sockaddr_in6`, or -errno.
pub(super) fn parse_addr(
    family: u16,
    addr: u64,
    len: u64,
    connect: bool,
) -> Result<(u16, u8), i64> {
    if addr == 0 {
        return Err(-e::EFAULT);
    }
    if len < 2 {
        return Err(-e::EINVAL);
    }
    let fam = unsafe { *(addr as *const u16) };
    let b = |i: u64| unsafe { *((addr + i) as *const u8) };
    let port = u16::from_be_bytes([b(2), b(3)]);
    let unknown = if connect {
        -ENETUNREACH
    } else {
        -EADDRNOTAVAIL
    };
    let kind4 = |a: [u8; 4]| -> Result<u8, i64> {
        match a {
            [0, 0, 0, 0] => Ok(ADDR_ANY),
            [127, 0, 0, 1] => Ok(ADDR_LOOP4),
            [10, 0, 0, 1] => Ok(ADDR_HOST4),
            _ => Err(unknown),
        }
    };
    match (family, fam) {
        (AF_INET, 2) => {
            if len < 16 {
                return Err(-e::EINVAL);
            }
            let k = kind4([b(4), b(5), b(6), b(7)])?;
            Ok((
                port,
                if connect && k == ADDR_ANY {
                    ADDR_LOOP4
                } else {
                    k
                },
            ))
        }
        (AF_INET6, 10) => {
            if len < 24 {
                return Err(-e::EINVAL);
            }
            let mut a = [0u8; 16];
            for (i, x) in a.iter_mut().enumerate() {
                *x = b(8 + i as u64);
            }
            let k = if a == [0; 16] {
                ADDR_ANY
            } else if a[..15] == [0; 15] && a[15] == 1 {
                ADDR_LOOP6
            } else if a[..10] == [0; 10] && a[10] == 0xff && a[11] == 0xff {
                kind4([a[12], a[13], a[14], a[15]])?
            } else {
                return Err(unknown);
            };
            Ok((
                port,
                if connect && k == ADDR_ANY {
                    ADDR_LOOP6
                } else {
                    k
                },
            ))
        }
        (AF_INET6, 2) if !connect => Err(-EAFNOSUPPORT),
        (_, 0) if connect => Err(-EAFNOSUPPORT), // AF_UNSPEC (disconnect) is not supported
        _ => Err(if connect { -EAFNOSUPPORT } else { -e::EINVAL }),
    }
}

/// Write the address `(kind, port)` as the socket's family sees it to `addr`/`*alen`.
pub(super) fn put_addr(family: u16, kind: u8, port: u16, addr: u64, alen: u64) -> i64 {
    if addr == 0 || alen == 0 {
        return 0;
    }
    let mut out = [0u8; 28];
    let n = if family == AF_INET {
        out[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        out[4..8].copy_from_slice(&match kind {
            ADDR_LOOP4 | ADDR_LOOP6 => [127, 0, 0, 1],
            ADDR_HOST4 => [10, 0, 0, 1],
            _ => [0, 0, 0, 0],
        });
        16
    } else {
        out[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        let a: [u8; 16] = match kind {
            ADDR_LOOP6 => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ADDR_LOOP4 => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
            ADDR_HOST4 => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1],
            _ => [0; 16],
        };
        out[8..24].copy_from_slice(&a);
        28
    };
    let cap = match get::<u32>(alen) {
        Ok(c) => c as usize,
        Err(e) => return e,
    };
    if (cap as i32) < 0 {
        return -e::EINVAL;
    }
    let m = cap.min(n);
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), addr as *mut u8, m) };
    match put(alen, n as u32) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ---- creation ----

fn socket(call: &mut dyn Call) -> Action {
    let [dom, ty, proto_, ..] = args(call);
    let family = dom as u16;
    let base = ty & !(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if base == SOCK_DGRAM {
        if proto_ != 0 && proto_ != IPPROTO_UDP {
            // ICMP echo, UDP-Lite: no wire.
            refuse(b"socket:dgram-proto");
            return Action::Return(-EPROTONOSUPPORT);
        }
        return super::udp::socket(call, family, ty);
    }
    if base != SOCK_STREAM {
        // Raw sockets: no wire. Refused with an errno so that the program can fall back.
        refuse(b"socket:raw");
        return Action::Return(-ESOCKTNOSUPPORT);
    }
    if proto_ != 0 && proto_ != IPPROTO_TCP {
        return Action::Return(-EPROTONOSUPPORT);
    }
    let fd = unsafe {
        sc3(
            nr::SOCKET,
            AF_UNIX,
            SOCK_STREAM | (ty & (SOCK_NONBLOCK | SOCK_CLOEXEC)),
            0,
        )
    };
    host_check(call, fd);
    if fd < 0 {
        return Action::Return(fd);
    }
    super::unixsock::fix_bufs(fd);
    let Some(i) = idx_of(fd) else {
        crate::sup::host_error(-e::EIO, nr::SOCKET, proto::ctl::HE_RUNTIME_ASSERT);
    };
    *sock(i) = WSock {
        family,
        ..WSock::default()
    };
    sup(Op::WireSocket, [i as u64, family as u64, 0, 0, 0, 0]);
    Action::Return(fd)
}

/// Bind the real socket to `@patina-l-<port>`.
fn real_bind(fd: i64, port: u16) -> i64 {
    let (a, n) = abstract_addr(LISTEN_PREFIX, Some(port as u64));
    unsafe { sc3(nr::BIND, fd as u64, a.as_ptr() as u64, n as u64) }
}

fn bind_to(fd: i64, i: usize, port: u16, kind: u8) -> i64 {
    let s = *sock(i);
    if s.state != WS_NEW {
        return -e::EINVAL;
    }
    let r = sup(
        Op::WireBind,
        [i as u64, port as u64, kind as u64, WIRE_BIND, 0, 0],
    );
    if r < 0 {
        return r;
    }
    let b = real_bind(fd, r as u16);
    if b < 0 {
        crate::sup::host_error(b, nr::BIND, proto::ctl::HE_SYSCALL);
    }
    let s = sock(i);
    s.state = WS_BOUND;
    s.lport = r as u16;
    s.laddr = kind;
    0
}

fn bind(call: &mut dyn Call, i: usize) -> i64 {
    let [fd, addr, len, ..] = args(call);
    let (port, kind) = match parse_addr(sock(i).family, addr, len, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    bind_to(fd as i32 as i64, i, port, kind)
}

fn listen(call: &mut dyn Call, i: usize) -> i64 {
    let [fd, backlog, ..] = args(call);
    let fd = fd as i32 as i64;
    if sock(i).state == WS_NEW {
        let r = bind_to(fd, i, 0, ADDR_ANY);
        if r < 0 {
            return r;
        }
    }
    let st = sock(i).state;
    if st != WS_BOUND && st != WS_LISTEN {
        return -e::EINVAL;
    }
    let r = unsafe { sc2(nr::LISTEN, fd as u64, backlog) };
    host_check(call, r);
    if r == 0 && st != WS_LISTEN {
        let s = *sock(i);
        let r = sup(
            Op::WireBind,
            [i as u64, s.lport as u64, s.laddr as u64, WIRE_LISTEN, 0, 0],
        );
        if r < 0 {
            return r;
        }
        sock(i).state = WS_LISTEN;
        io::bump();
    }
    r
}

// ---- connect ----

static ZERO: [u8; 4096] = [0; 4096];

/// Fill the socket's send buffer after the preamble so that the kernel does not report it
/// writable before the virtual handshake (the supervisor discards these bytes). Returns the
/// padding's length.
fn pad(fd: i64, pre: &[u64; 2]) -> i64 {
    let mut iov = [[0u64; 2]; 17];
    iov[0] = [pre.as_ptr() as u64, PREAMBLE_LEN as u64];
    for v in iov.iter_mut().skip(1) {
        *v = [ZERO.as_ptr() as u64, ZERO.len() as u64];
    }
    let msg = [0u64, 0, iov.as_ptr() as u64, 17, 0, 0, 0];
    let r = unsafe {
        sc3(
            nr::SENDMSG,
            fd as u64,
            msg.as_ptr() as u64,
            MSG_DONTWAIT | MSG_NOSIGNAL,
        )
    };
    if r < PREAMBLE_LEN as i64 {
        crate::sup::host_error(
            if r < 0 { r } else { -e::EIO },
            nr::SENDMSG,
            proto::ctl::HE_SYSCALL,
        );
    }
    let mut total = r - PREAMBLE_LEN as i64;
    let msg = [0u64, 0, iov.as_ptr() as u64 + 16, 16, 0, 0, 0];
    loop {
        let r = unsafe {
            sc3(
                nr::SENDMSG,
                fd as u64,
                msg.as_ptr() as u64,
                MSG_DONTWAIT | MSG_NOSIGNAL,
            )
        };
        if r <= 0 {
            break;
        }
        total += r;
    }
    total
}

fn connect(call: &mut dyn Call, i: usize) -> i64 {
    let [fd, addr, len, ..] = args(call);
    let fd = fd as i32 as i64;
    let s = *sock(i);
    match s.state {
        WS_CONNECTING => return -EALREADY,
        WS_CONNECTED => return -EISCONN,
        WS_LISTEN => return -e::EINVAL,
        // The real socket is still connected to its closed hidden end: a second connect on
        // the same socket after a failure is not supported.
        WS_FAILED => halt(call),
        _ => {}
    }
    let (port, kind) = match parse_addr(s.family, addr, len, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if s.family == AF_INET && kind == ADDR_LOOP6 {
        return -EAFNOSUPPORT;
    }
    let nonblock = io::nonblocking(fd);
    // The real connect to the wire listener: queued at once (the supervisor accepts it in
    // its step), so it cannot wait; non-blocking for this call only.
    let (wa, wn) = abstract_addr(WIRE_NAME, None);
    if !nonblock {
        io::set_nonblock(fd, true);
    }
    let r = unsafe { sc3(nr::CONNECT, fd as u64, wa.as_ptr() as u64, wn as u64) };
    if r < 0 {
        crate::sup::host_error(r, nr::CONNECT, proto::ctl::HE_SYSCALL);
    }
    let vino = i as u64 + VINO_BASE;
    let pre = [PREAMBLE_MAGIC, vino];
    let padding = if nonblock {
        pad(fd, &pre)
    } else {
        let w = unsafe {
            sc6(
                nr::SENDTO,
                fd as u64,
                pre.as_ptr() as u64,
                PREAMBLE_LEN as u64,
                MSG_DONTWAIT | MSG_NOSIGNAL,
                0,
                0,
            )
        };
        if w != PREAMBLE_LEN as i64 {
            crate::sup::host_error(
                if w < 0 { w } else { -e::EIO },
                nr::SENDTO,
                proto::ctl::HE_SYSCALL,
            );
        }
        io::set_nonblock(fd, false);
        0
    };
    let r = sup(
        Op::WireConnect,
        [
            i as u64,
            port as u64,
            kind as u64,
            padding as u64,
            nonblock as u64,
            0,
        ],
    );
    io::bump();
    if r < 0 {
        return r;
    }
    if nonblock {
        return -EINPROGRESS;
    }
    let mut w = Waiter::new(fd, PARK_OUT, nr::CONNECT);
    w.nonblock = Some(false);
    w.deadline = Deadline::SndTimeo;
    let g = w.run(|| match sock(i).state {
        WS_CONNECTED => Some(0),
        WS_FAILED => Some(-(take_err(fd, i) as i64)),
        _ => None,
    });
    let r = match g {
        Got::Done(r) => r,
        Got::TimedOut => -EINPROGRESS,
        Got::Interrupted => -e::EINTR,
        Got::WouldBlock => -EINPROGRESS,
    };
    w.finish(r)
}

/// The pending error of socket `i` (cleared), and the real socket's (also cleared).
fn take_err(fd: i64, i: usize) -> u16 {
    let s = sock(i);
    let e = s.err;
    s.err = 0;
    let mut v: i32 = 0;
    let mut l: u32 = 4;
    unsafe {
        sc6(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET as u64,
            4,
            &mut v as *mut i32 as u64,
            &mut l as *mut u32 as u64,
            0,
        )
    };
    e
}

/// A reset not yet reported to the guest: report it once (TCP's `sk_err` = `ECONNRESET`).
fn take_reset(fd: i64, i: usize) -> bool {
    let s = sock(i);
    if s.flags & WF_RESET == 0 {
        return false;
    }
    s.flags &= !WF_RESET;
    take_err(fd, i);
    true
}

// ---- accept ----

fn accept(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let flags = if call.nr() == nr::ACCEPT4 { a[3] } else { 0 };
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return -e::EINVAL;
    }
    if sock(i).state != WS_LISTEN {
        return -e::EINVAL;
    }
    let mut w = Waiter::new(fd, PARK_IN, call.nr());
    let g = w.run(|| {
        if io::poll1(fd, POLLIN) & (POLLIN | POLLERR | POLLHUP) == 0 {
            return None;
        }
        io::eagain(unsafe { sc4(nr::ACCEPT4, fd as u64, 0, 0, flags) })
    });
    let r = io::result(g, -e::EAGAIN);
    if r < 0 {
        return w.finish(r);
    }
    super::unixsock::fix_bufs(r);
    // The kernel's peer name is the supervisor's `@patina-c-<id>`: never shown to the guest.
    let mut sa = [0u8; 110];
    let mut sl: u32 = 110;
    let p = unsafe {
        sc3(
            nr::GETPEERNAME,
            r as u64,
            sa.as_mut_ptr() as u64,
            &mut sl as *mut u32 as u64,
        )
    };
    let id = if p == 0 {
        parse_abstract(&sa, sl as usize, CONN_PREFIX)
    } else {
        None
    };
    let (Some(id), Some(n)) = (id, idx_of(r)) else {
        unsafe { sc1(nr::CLOSE, r as u64) };
        return w.finish(-ECONNABORTED);
    };
    let family = sock(i).family;
    *sock(n) = WSock {
        family,
        ..WSock::default()
    };
    let q = sup(Op::WireAccepted, [id, n as u64, family as u64, 0, 0, 0]);
    io::bump();
    if q < 0 {
        unsafe { sc1(nr::CLOSE, r as u64) };
        return w.finish(q);
    }
    let s = *sock(n);
    let pr = put_addr(family, s.raddr, s.rport, a[1], a[2]);
    if pr < 0 {
        return w.finish(pr);
    }
    w.finish(r)
}

// ---- names and options ----

fn names(call: &mut dyn Call, i: usize, peer: bool) -> i64 {
    let [_, addr, alen, ..] = args(call);
    let s = *sock(i);
    if peer {
        if s.state != WS_CONNECTED {
            return -ENOTCONN;
        }
        put_addr(s.family, s.raddr, s.rport, addr, alen)
    } else {
        put_addr(s.family, s.laddr, s.lport, addr, alen)
    }
}

fn key(level: i32, name: i32) -> i32 {
    level << 16 | name
}

/// Options that are recorded and read back, with no effect on the wire.
fn recorded(level: i32, name: i32) -> bool {
    match level {
        // SO_DEBUG SO_REUSEADDR SO_DONTROUTE SO_BROADCAST SO_SNDBUF SO_RCVBUF SO_KEEPALIVE
        // SO_OOBINLINE SO_NO_CHECK SO_PRIORITY SO_LINGER SO_REUSEPORT SO_BINDTODEVICE SO_MARK
        // SO_BUSY_POLL SO_INCOMING_CPU SO_ZEROCOPY
        SOL_SOCKET => matches!(
            name,
            1 | 2 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 15 | 25 | 36 | 46 | 49 | 60
        ),
        // TCP_NODELAY TCP_MAXSEG TCP_CORK TCP_KEEPIDLE TCP_KEEPINTVL TCP_KEEPCNT TCP_SYNCNT
        // TCP_LINGER2 TCP_DEFER_ACCEPT TCP_WINDOW_CLAMP TCP_QUICKACK TCP_CONGESTION
        // TCP_USER_TIMEOUT TCP_FASTOPEN TCP_NOTSENT_LOWAT TCP_FASTOPEN_CONNECT
        6 => matches!(
            name,
            1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 12 | 13 | 18 | 23 | 25 | 30
        ),
        // IP_TOS IP_TTL IP_RECVERR IP_MTU_DISCOVER IP_FREEBIND IP_BIND_ADDRESS_NO_PORT
        SOL_IP => matches!(name, 1 | 2 | 11 | 10 | 15 | 24),
        // IPV6_UNICAST_HOPS IPV6_RECVERR IPV6_MTU_DISCOVER IPV6_V6ONLY IPV6_TCLASS
        SOL_IPV6 => matches!(name, 16 | 25 | 23 | 26 | 67),
        _ => false,
    }
}

/// Default values read back for options never set.
fn default_opt(level: i32, name: i32) -> i32 {
    match (level, name) {
        (SOL_SOCKET, 7) | (SOL_SOCKET, 8) => 131_072, // SO_SNDBUF / SO_RCVBUF (doubled 65,536)
        (6, 2) => 65_483,                             // TCP_MAXSEG on loopback
        (6, 4) => 7200,                               // TCP_KEEPIDLE
        (6, 5) => 75,                                 // TCP_KEEPINTVL
        (6, 6) => 9,                                  // TCP_KEEPCNT
        (6, 7) => 6,                                  // TCP_SYNCNT
        (6, 8) => 60,                                 // TCP_LINGER2
        (6, 10) => 0,                                 // TCP_WINDOW_CLAMP
        (6, 12) => 1,                                 // TCP_QUICKACK
        (SOL_IP, 2) | (SOL_IPV6, 16) => 64,           // TTL / hop limit
        _ => 0,
    }
}

fn unknown_opt(level: i32, name: i32) -> i64 {
    WireTab::inc(&tab().counters.unknown_opts, 1);
    let mut b = *b"sockopt:L000:N000";
    let mut put3 = |at: usize, v: i32| {
        let v = v.clamp(0, 999) as u8 as u32;
        b[at] = b'0' + (v / 100) as u8;
        b[at + 1] = b'0' + (v / 10 % 10) as u8;
        b[at + 2] = b'0' + (v % 10) as u8;
    };
    put3(9, level);
    put3(14, name);
    refuse(&b);
    -ENOPROTOOPT
}

pub(super) fn setsockopt(call: &mut dyn Call, i: usize) -> i64 {
    let [fd, level, name, val, len, ..] = args(call);
    let (level, name) = (level as i32, name as i32);
    let dgram = is_dgram(i);
    if dgram && level == 6 {
        return -ENOPROTOOPT; // TCP options on a UDP socket: what Linux answers
    }
    // Timeouts are the blocking I/O park deadlines, read back from the real socket; SO_RCVLOWAT is real.
    if level == SOL_SOCKET && matches!(name, 18 | 20 | 21 | 66 | 67) {
        let r = raw(call);
        host_check(call, r);
        return r;
    }
    if !recorded(level, name) {
        return unknown_opt(level, name);
    }
    if level == SOL_IPV6 && sock(i).family != AF_INET6 {
        return -ENOPROTOOPT;
    }
    if val == 0 {
        return -e::EFAULT;
    }
    let v = if level == SOL_SOCKET && name == 13 {
        // SO_LINGER: struct linger { onoff, linger }; the timeout is recorded beside it.
        if len < 8 {
            return -e::EINVAL;
        }
        let l = unsafe { *(val as *const [i32; 2]) };
        sock(i).set_opt(key(-1, 13), l[1]);
        l[0]
    } else if level == 6 && name == 13 {
        0 // TCP_CONGESTION: a name; accepted, reads back "cubic"
    } else {
        if len < 4 {
            return -e::EINVAL;
        }
        unsafe { *(val as *const i32) }
    };
    let v = if level == SOL_SOCKET && (name == 7 || name == 8) {
        // UDP: an unprivileged request is capped at rmem_max/wmem_max before doubling.
        let v = if dgram { v.clamp(0, DGRAM_BUF_MAX) } else { v };
        v.saturating_mul(2).max(4608)
    } else {
        v
    };
    if level == SOL_IPV6 && name == 26 {
        if sock(i).state != WS_NEW {
            return -e::EINVAL;
        }
        let s = sock(i);
        if v != 0 {
            s.flags |= WF_V6ONLY;
        } else {
            s.flags &= !WF_V6ONLY;
        }
    }
    if !sock(i).set_opt(key(level, name), v) {
        return unknown_opt(level, name);
    }
    let _ = fd;
    0
}

pub(super) fn getsockopt(call: &mut dyn Call, i: usize) -> i64 {
    let [fd, level, name, val, lenp, ..] = args(call);
    let fd = fd as i32 as i64;
    let (level, name) = (level as i32, name as i32);
    let s = *sock(i);
    let dgram = is_dgram(i);
    if dgram && level == 6 {
        return -ENOPROTOOPT;
    }
    let cap = match get::<u32>(lenp) {
        Ok(c) => c as i32,
        Err(e) => return e,
    };
    if cap < 0 {
        return -e::EINVAL;
    }
    let out = |bytes: &[u8]| -> i64 {
        let n = (cap as usize).min(bytes.len());
        if val == 0 && n > 0 {
            return -e::EFAULT;
        }
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), val as *mut u8, n) };
        match put(lenp, n as u32) {
            Ok(()) => 0,
            Err(e) => e,
        }
    };
    let int = |v: i32| out(&v.to_ne_bytes());
    match (level, name) {
        (SOL_SOCKET, 4) if dgram => int(super::udp::take_err(i) as i32),
        (SOL_SOCKET, 3) if dgram => int(SOCK_DGRAM as i32),
        (SOL_SOCKET, 38) if dgram => int(IPPROTO_UDP as i32),
        (SOL_SOCKET, 7 | 8) if dgram => int(s.opt(key(level, name)).unwrap_or(DGRAM_BUF_DEFAULT)),
        (SOL_SOCKET, 4) => {
            // SO_ERROR: the wire's pending error (a failed connect); a reset not yet reported.
            let e = if s.err != 0 {
                take_err(fd, i) as i32
            } else if take_reset(fd, i) {
                ECONNRESET as i32
            } else {
                take_err(fd, i);
                0
            };
            int(e)
        }
        (SOL_SOCKET, 3) => int(SOCK_STREAM as i32), // SO_TYPE
        (SOL_SOCKET, 39) => int(s.family as i32),   // SO_DOMAIN
        (SOL_SOCKET, 38) => int(IPPROTO_TCP as i32), // SO_PROTOCOL
        (SOL_SOCKET, 30) => int((s.state == WS_LISTEN) as i32), // SO_ACCEPTCONN
        (SOL_SOCKET, 18 | 20 | 21 | 66 | 67) => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        (SOL_SOCKET, 13) => {
            let mut b = [0u8; 8];
            b[..4].copy_from_slice(&s.opt(key(SOL_SOCKET, 13)).unwrap_or(0).to_ne_bytes());
            b[4..].copy_from_slice(&s.opt(key(-1, 13)).unwrap_or(0).to_ne_bytes());
            out(&b)
        }
        (6, 13) => out(b"cubic\0"),
        (SOL_IPV6, _) if s.family != AF_INET6 => -ENOPROTOOPT,
        (l, n) if recorded(l, n) => int(s.opt(key(l, n)).unwrap_or_else(|| default_opt(l, n))),
        (l, n) => unknown_opt(l, n),
    }
}

fn shutdown(call: &mut dyn Call, i: usize) -> i64 {
    let s = *sock(i);
    if call.arg(1) > 2 {
        return -e::EINVAL;
    }
    match s.state {
        WS_CONNECTED => {}
        WS_LISTEN if call.arg(1) == 1 => return 0,
        WS_LISTEN => halt(call),
        _ => return -ENOTCONN,
    }
    let r = raw(call);
    host_check(call, r);
    if r == 0 {
        mark(i);
        io::bump();
    }
    r
}

// ---- data ----

/// After a send attempt on socket `i`: mark it for the supervisor; `EPIPE` raises the
/// virtual `SIGPIPE` unless the guest asked for `MSG_NOSIGNAL`.
fn sent(i: usize, r: i64, nosignal: bool) -> i64 {
    if r > 0 {
        mark(i);
    } else if r == -EPIPE && !nosignal {
        super::sig::raise_thread(super::sig::SIGPIPE);
    }
    r
}

/// Before a send: a socket that is not connected, or a reset not yet reported.
fn send_check(fd: i64, i: usize) -> Option<i64> {
    match sock(i).state {
        WS_CONNECTED | WS_CONNECTING => {}
        _ => return Some(-EPIPE),
    }
    take_reset(fd, i).then_some(-ECONNRESET)
}

/// After a receive returned `r`: the end of the stream after a reset reports `ECONNRESET` once.
fn received(fd: i64, i: usize, r: i64) -> i64 {
    if (r == 0 || r == -ECONNRESET) && take_reset(fd, i) {
        return -ECONNRESET;
    }
    r
}

fn recv_check(i: usize) -> Option<i64> {
    match sock(i).state {
        WS_CONNECTED | WS_CONNECTING => None,
        _ => Some(-ENOTCONN),
    }
}

fn sender(fd: i64, nr: u64, flags: u64) -> Waiter {
    let mut w = Waiter::new(fd, PARK_OUT, nr);
    w.deadline = Deadline::SndTimeo;
    if flags & MSG_DONTWAIT != 0 {
        w.nonblock = Some(true);
    }
    w
}

fn receiver(fd: i64, nr: u64, flags: u64) -> Waiter {
    let mut w = Waiter::new(fd, PARK_IN, nr);
    w.deadline = Deadline::RcvTimeo;
    if flags & MSG_DONTWAIT != 0 {
        w.nonblock = Some(true);
    }
    w
}

/// Send `cnt` iovec entries at `iov` (the guest's address is ignored, as TCP does).
fn send_iov(fd: i64, i: usize, nr: u64, iov: u64, cnt: u64, flags: u64) -> i64 {
    if let Some(r) = send_check(fd, i) {
        return sent(i, r, flags & MSG_NOSIGNAL != 0);
    }
    if flags & MSG_OOB != 0 {
        refuse(b"MSG_OOB");
        return -e::EOPNOTSUPP;
    }
    let mut w = sender(fd, nr, flags);
    let f = (flags & !(MSG_WAITALL)) | MSG_DONTWAIT | MSG_NOSIGNAL;
    let r = io::write_all(&mut w, iov, cnt, |p, n| {
        let m = [0u64, 0, p, n, 0, 0, 0];
        let r = unsafe { sc3(nr::SENDMSG, fd as u64, m.as_ptr() as u64, f) };
        if r > 0 {
            mark(i);
        }
        r
    });
    w.finish(sent(i, r, flags & MSG_NOSIGNAL != 0))
}

fn sendto(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let one = [a[1], a[2]];
    send_iov(
        a[0] as i32 as i64,
        i,
        nr::SENDTO,
        one.as_ptr() as u64,
        1,
        a[3],
    )
}

fn sendmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let msg = a[1];
    if msg == 0 {
        return -e::EFAULT;
    }
    let (iov, cnt, ctll) = unsafe {
        (
            *((msg + 16) as *const u64),
            *((msg + 24) as *const u64),
            *((msg + 40) as *const u64),
        )
    };
    if ctll != 0 {
        // The wire copies bytes, not ancillary data (SCM_RIGHTS over TCP does not exist).
        return -e::EINVAL;
    }
    send_iov(a[0] as i32 as i64, i, nr::SENDMSG, iov, cnt, a[2])
}

fn sendmmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let vlen = a[2].min(1024);
    let mut done = 0u64;
    while done < vlen {
        let m = a[1] + done * 64;
        let (iov, cnt, ctll) = unsafe {
            (
                *((m + 16) as *const u64),
                *((m + 24) as *const u64),
                *((m + 40) as *const u64),
            )
        };
        let r = if ctll != 0 {
            -e::EINVAL
        } else {
            send_iov(a[0] as i32 as i64, i, nr::SENDMMSG, iov, cnt, a[3])
        };
        if r < 0 {
            return if done > 0 { done as i64 } else { r };
        }
        unsafe { *((m + 56) as *mut u32) = r as u32 };
        done += 1;
    }
    done as i64
}

/// recvfrom: the address is never filled (TCP leaves it alone and reports length 0).
fn recvfrom(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    if let Some(r) = recv_check(i) {
        return r;
    }
    if a[3] & MSG_OOB != 0 {
        refuse(b"MSG_OOB");
        return -e::EINVAL;
    }
    let mut w = receiver(fd, nr::RECVFROM, a[3]);
    let waitall = a[3] & MSG_WAITALL != 0 && a[3] & MSG_DONTWAIT == 0;
    let f = (a[3] & !MSG_WAITALL) | MSG_DONTWAIT;
    let mut total = 0u64;
    let r = loop {
        let off = total;
        let g = w.run(|| {
            io::eagain(unsafe { sc6(nr::RECVFROM, fd as u64, a[1] + off, a[2] - off, f, 0, 0) })
        });
        match g {
            Got::Done(r) if r > 0 => {
                total += r as u64;
                if f & 2 == 0 {
                    io::bump(); // not MSG_PEEK: buffer space changed
                }
                if !waitall || total >= a[2] || f & 2 != 0 {
                    break total as i64;
                }
            }
            Got::Done(r) => {
                break if total > 0 {
                    total as i64
                } else {
                    received(fd, i, r)
                }
            }
            g => {
                break if total > 0 {
                    total as i64
                } else {
                    io::result(g, -e::EAGAIN)
                }
            }
        }
    };
    if r >= 0 && a[4] != 0 && a[5] != 0 {
        let _ = put(a[5], 0u32);
    }
    w.finish(r)
}

/// recvmsg: `msg_name` is hidden from the kernel for the call and reported with length 0.
fn recvmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let msg = a[1];
    if msg == 0 {
        return -e::EFAULT;
    }
    if let Some(r) = recv_check(i) {
        return r;
    }
    if a[2] & MSG_OOB != 0 {
        refuse(b"MSG_OOB");
        return -e::EINVAL;
    }
    let (name, iov, cnt) = unsafe {
        (
            *(msg as *const u64),
            *((msg + 16) as *const u64),
            *((msg + 24) as *const u64),
        )
    };
    let peek = a[2] & 2 != 0;
    let waitall = a[2] & MSG_WAITALL != 0 && a[2] & MSG_DONTWAIT == 0 && !peek;
    let f = (a[2] & !MSG_WAITALL) | MSG_DONTWAIT;
    unsafe { *(msg as *mut u64) = 0 };
    let mut w = receiver(fd, nr::RECVMSG, a[2]);
    let g = w.run(|| io::eagain(unsafe { sc3(nr::RECVMSG, fd as u64, msg, f) }));
    let mut r = match g {
        Got::Done(r) if r > 0 => r,
        Got::Done(r) => received(fd, i, r),
        g => io::result(g, -e::EAGAIN),
    };
    if r > 0 && !peek {
        io::bump();
    }
    if r > 0 && waitall {
        let mut cur = IovCursor::new(iov, cnt);
        cur.advance(r as u64);
        let mut win = [[0u64; 2]; io::WIN];
        while !cur.done() {
            let n = cur.window(&mut win);
            let m = [0u64, 0, win.as_ptr() as u64, n, 0, 0, 0];
            let g =
                w.run(|| io::eagain(unsafe { sc3(nr::RECVMSG, fd as u64, m.as_ptr() as u64, f) }));
            match g {
                Got::Done(k) if k > 0 => {
                    r += k;
                    cur.advance(k as u64);
                    io::bump();
                }
                _ => break,
            }
        }
    }
    unsafe {
        *(msg as *mut u64) = name;
        *((msg + 8) as *mut u32) = 0;
    }
    w.finish(r)
}

/// read/write/readv/writev/preadv2/pwritev2 on a wire socket: blocking I/O's attempt path, with TCP's
/// conventions around it.
pub fn rw(call: &mut dyn Call, i: usize) -> i64 {
    if is_dgram(i) {
        return super::udp::rw(call, i);
    }
    let fd = call.arg(0) as i32 as i64;
    let write = matches!(call.nr(), nr::WRITE | nr::WRITEV | nr::PWRITEV2);
    if write {
        if let Some(r) = send_check(fd, i) {
            return sent(i, r, false);
        }
        let r = io::rw(call, Kind::Sock);
        sent(i, r, false)
    } else {
        if let Some(r) = recv_check(i) {
            return r;
        }
        let r = io::rw(call, Kind::Sock);
        received(fd, i, r)
    }
}

/// sendfile(out = wire socket, in, offset, count): the real call on a description made
/// non-blocking for the call only, parking while the socket is full; continued to the full
/// count like a blocking send.
pub fn sendfile(call: &mut dyn Call, i: usize) -> i64 {
    if is_dgram(i) {
        refuse(b"sendfile:udp");
        return -e::EINVAL;
    }
    let [out, inp, off, count, ..] = args(call);
    let fd = out as i32 as i64;
    if let Some(r) = send_check(fd, i) {
        return sent(i, r, false);
    }
    let guest_nb = io::nonblocking(fd);
    let mut w = Waiter::new(fd, PARK_OUT, nr::SENDFILE);
    w.deadline = Deadline::SndTimeo;
    w.nonblock = Some(guest_nb);
    let mut total = 0u64;
    let r = loop {
        let left = count - total;
        let g = w.run(|| {
            if !guest_nb {
                io::set_nonblock(fd, true);
            }
            let r = unsafe { sc4(nr::SENDFILE, out, inp, off, left) };
            if !guest_nb {
                io::set_nonblock(fd, false);
            }
            io::eagain(r)
        });
        match g {
            Got::Done(r) if r > 0 => {
                total += r as u64;
                mark(i);
                io::bump();
                if total >= count {
                    break total as i64;
                }
            }
            Got::Done(r) => break if total > 0 { total as i64 } else { r },
            g => {
                break if total > 0 {
                    total as i64
                } else {
                    io::result(g, -e::EAGAIN)
                }
            }
        }
    };
    w.finish(sent(i, r, false))
}

// ---- dispatch ----

/// `socket` of family `AF_INET`/`AF_INET6`, or of the families that are refused.
pub fn socket_call(call: &mut dyn Call) -> Option<Action> {
    match call.arg(0) {
        2 | 10 => Some(socket(call)),
        AF_NETLINK | AF_PACKET => {
            refuse(if call.arg(0) == AF_NETLINK {
                b"socket:netlink"
            } else {
                b"socket:packet"
            });
            Some(Action::Return(-EAFNOSUPPORT))
        }
        _ => None,
    }
}

/// A call on wire socket `i` (descriptor in argument 0).
pub fn handle(call: &mut dyn Call, i: usize) -> Action {
    if is_dgram(i) {
        return super::udp::handle(call, i);
    }
    let r = match call.nr() {
        nr::BIND => bind(call, i),
        nr::LISTEN => listen(call, i),
        nr::CONNECT => connect(call, i),
        nr::ACCEPT | nr::ACCEPT4 => accept(call, i),
        nr::GETSOCKNAME => names(call, i, false),
        nr::GETPEERNAME => names(call, i, true),
        nr::SETSOCKOPT => setsockopt(call, i),
        nr::GETSOCKOPT => getsockopt(call, i),
        nr::SHUTDOWN => shutdown(call, i),
        nr::SENDTO => sendto(call, i),
        nr::SENDMSG => sendmsg(call, i),
        nr::SENDMMSG => sendmmsg(call, i),
        nr::RECVFROM => recvfrom(call, i),
        nr::RECVMSG => recvmsg(call, i),
        _ => return stop_here(call),
    };
    Action::Return(r)
}

/// An `AF_UNIX` address naming the wire's reserved abstract names (`@patina-...`).
pub fn reserved_unix_name(addr: u64, len: u64) -> bool {
    if addr == 0 || len < 3 + RESERVED_PREFIX.len() as u64 {
        return false;
    }
    let b = |i: u64| unsafe { *((addr + i) as *const u8) };
    if b(0) as u64 != AF_UNIX || b(1) != 0 || b(2) != 0 {
        return false;
    }
    RESERVED_PREFIX
        .iter()
        .enumerate()
        .all(|(k, &c)| b(3 + k as u64) == c)
}

#[allow(dead_code)]
const _: () = assert!(ENOTSOCK > 0);
