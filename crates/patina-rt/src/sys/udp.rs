//! `AF_INET`/`AF_INET6` datagram (UDP) sockets on the supervisor's wire.
//!
//! The guest's descriptor is a real `AF_UNIX` `SOCK_SEQPACKET` socket connected, at creation,
//! to a hidden end the supervisor accepts on `@patina-udp` (the first packet names the
//! socket). A send writes the payload as one packet and asks the supervisor to take it now
//! (`UdpSend`, with the destination), so every datagram is stamped at the virtual time of its
//! send and none waits in a kernel buffer. The supervisor writes each delivered datagram
//! behind a header naming its source (`proto::wire::DGRAM_HDR`); this module reads the header
//! into its own buffer and the payload into the guest's, so the guest sees the payload, its
//! length and its source, never a unix address. Readiness, blocking (the attempt and park of
//! `io::Waiter`), `MSG_PEEK` and truncation are the kernel's, on the packet.
//!
//! State shared by every process (bound port, peer, pending error, queued charge) is the
//! socket's `WSock` entry, flag `WF_DGRAM`.

use super::inet::{put_addr, refuse, sock, sup};

/// `inet::parse_addr` for a datagram socket. Datagrams do not cross nodes (yet): a node's own
/// address is the supervisor's `ADDR_HOST4` in the node's port space, another node's address
/// is unreachable (refused, recorded).
fn parse_addr(family: u16, addr: u64, len: u64, connect: bool) -> Result<(u16, u8), i64> {
    let (port, kind) = super::inet::parse_addr(family, addr, len, connect)?;
    match addr_node(kind) {
        Some(n) if n == crate::state::proc().node => Ok((port, ADDR_HOST4)),
        Some(_) => {
            refuse(b"udp:other-node");
            Err(-ENETUNREACH)
        }
        None => Ok((port, kind)),
    }
}

/// The address kind a datagram socket's guest sees for the supervisor's `kind`.
fn shown(kind: u8) -> u8 {
    if kind == ADDR_HOST4 {
        node_addr(crate::state::proc().node)
    } else {
        kind
    }
}
use super::io::{self, Deadline, Waiter};
use super::*;
use proto::ctl::{Op, PARK_IN, UDP_REUSEADDR, UDP_REUSEPORT, UDP_V6ONLY};
use proto::vfs::VINO_BASE;
use proto::wire::*;

const AF_UNIX: u64 = 1;
const SOCK_SEQPACKET: u64 = 5;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const SOL_SOCKET: u64 = 1;
const MSG_OOB: u64 = 1;
const MSG_PEEK: u64 = 2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_MORE: u64 = 0x8000;
const MSG_ERRQUEUE: u64 = 0x2000;
const MSG_WAITFORONE: u64 = 0x10000;

const EPIPE: i64 = 32;
const EMSGSIZE: i64 = 90;
const EOPNOTSUPP: i64 = 95;
const ENETUNREACH: i64 = 101;
const ENOTCONN: i64 = 107;
const EDESTADDRREQ: i64 = 89;
const EAFNOSUPPORT: i64 = 97;

/// Iovec entries a datagram may be gathered from or scattered to (more: refused).
const IOV_MAX: usize = 64;
/// The guest end's send buffer: room for the largest datagram as one packet.
const SNDBUF: u32 = 131_072;

// ---- creation ----

/// `socket(AF_INET[6], SOCK_DGRAM, 0 | IPPROTO_UDP)`.
pub fn socket(call: &mut dyn Call, family: u16, ty: u64) -> Action {
    let fd = unsafe {
        sc3(
            nr::SOCKET,
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_NONBLOCK | (ty & SOCK_CLOEXEC),
            0,
        )
    };
    host_check(call, fd);
    if fd < 0 {
        return Action::Return(fd);
    }
    let v = SNDBUF;
    unsafe {
        sc6(
            nr::SETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            7,
            &v as *const u32 as u64,
            4,
            0,
        )
    };
    let (a, n) = abstract_addr(UDP_NAME, None);
    let r = unsafe { sc3(nr::CONNECT, fd as u64, a.as_ptr() as u64, n as u64) };
    if r < 0 {
        crate::sup::host_error(r, nr::CONNECT, proto::ctl::HE_SYSCALL);
    }
    let Some(i) = super::inet::idx_of(fd) else {
        crate::sup::host_error(-e::EIO, nr::SOCKET, proto::ctl::HE_RUNTIME_ASSERT);
    };
    let pre = [UDP_MAGIC, i as u64 + VINO_BASE];
    let w = unsafe {
        sc6(
            nr::SENDTO,
            fd as u64,
            pre.as_ptr() as u64,
            16,
            MSG_DONTWAIT | MSG_NOSIGNAL,
            0,
            0,
        )
    };
    if w != 16 {
        crate::sup::host_error(
            if w < 0 { w } else { -e::EIO },
            nr::SENDTO,
            proto::ctl::HE_SYSCALL,
        );
    }
    if ty & SOCK_NONBLOCK == 0 {
        io::set_nonblock(fd, false);
    }
    *sock(i) = WSock {
        family,
        flags: WF_DGRAM,
        ..WSock::default()
    };
    sup(Op::UdpSocket, [i as u64, family as u64, 0, 0, 0, 0]);
    Action::Return(fd)
}

// ---- addresses ----

fn bind_flags(i: usize) -> u64 {
    let s = sock(i);
    let on = |k: i32| s.opt(k).unwrap_or(0) != 0;
    (if on(1 << 16 | 2) { UDP_REUSEADDR } else { 0 })
        | (if on(1 << 16 | 15) { UDP_REUSEPORT } else { 0 })
        | (if s.flags & WF_V6ONLY != 0 {
            UDP_V6ONLY
        } else {
            0
        })
}

/// Bind to `port` (0: an ephemeral port from the run's counter) at address kind `kind`.
fn bind_to(i: usize, port: u16, kind: u8) -> i64 {
    let r = sup(
        Op::UdpBind,
        [i as u64, port as u64, kind as u64, bind_flags(i), 0, 0],
    );
    if r < 0 {
        return r;
    }
    let s = sock(i);
    s.lport = r as u16;
    s.laddr = kind;
    if s.state == WS_NEW {
        s.state = WS_BOUND;
    }
    0
}

/// Linux binds an unbound datagram socket to an ephemeral port at its first send or connect.
fn autobind(i: usize) -> i64 {
    if sock(i).lport != 0 {
        return 0;
    }
    bind_to(i, 0, ADDR_ANY)
}

fn bind(call: &mut dyn Call, i: usize) -> i64 {
    let [_, addr, len, ..] = args(call);
    let s = *sock(i);
    let (port, kind) = match parse_addr(s.family, addr, len, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if s.lport != 0 {
        return -e::EINVAL;
    }
    if s.flags & WF_V6ONLY != 0 && matches!(kind, ADDR_LOOP4 | ADDR_HOST4) {
        return -e::EINVAL;
    }
    let r = bind_to(i, port, kind);
    if r == 0 {
        let s = sock(i);
        if port != 0 {
            s.flags |= WF_USER_PORT;
        }
        if kind != ADDR_ANY {
            s.flags |= WF_USER_ADDR;
        }
    }
    r
}

/// A destination address from the guest: (port, kind), or -errno. Broadcast and multicast
/// destinations are refused (recorded) as unreachable: the virtual host has no such route.
fn dest(i: usize, addr: u64, len: u64) -> Result<(u16, u8), i64> {
    let s = *sock(i);
    if addr != 0 && len >= 8 {
        let fam = get::<u16>(addr)?;
        let b4 = get::<[u8; 4]>(addr + 4)?;
        let multi = match (fam, s.family) {
            (2, AF_INET) => b4[0] >= 224,
            (10, AF_INET6) if len >= 24 => {
                let a = get::<[u8; 16]>(addr + 8)?;
                a[0] == 0xff
                    || (a[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && a[12] >= 224)
            }
            _ => false,
        };
        if multi {
            refuse(b"udp:multicast-or-broadcast");
            return Err(-ENETUNREACH);
        }
    }
    let (port, kind) = parse_addr(s.family, addr, len, true)?;
    if s.family == AF_INET && kind == ADDR_LOOP6 {
        return Err(-EAFNOSUPPORT);
    }
    if s.flags & WF_V6ONLY != 0 && matches!(kind, ADDR_LOOP4 | ADDR_HOST4) {
        return Err(-ENETUNREACH);
    }
    Ok((port, kind))
}

fn connect(call: &mut dyn Call, i: usize) -> i64 {
    let [_, addr, len, ..] = args(call);
    if addr != 0 && len >= 2 && get::<u16>(addr) == Ok(0) {
        // AF_UNSPEC: dissolve the association. An address or port the guest did not bind
        // goes back to unbound, as Linux does.
        let s = sock(i);
        s.rport = 0;
        s.raddr = 0;
        if s.flags & WF_USER_ADDR == 0 {
            s.laddr = ADDR_ANY;
        }
        let keep = s.flags & WF_USER_PORT != 0;
        if !keep {
            s.lport = 0;
        }
        s.state = if s.lport != 0 { WS_BOUND } else { WS_NEW };
        let s = *s;
        sup(
            Op::UdpConnect,
            [i as u64, 0, 0, 0, s.laddr as u64, keep as u64],
        );
        return 0;
    }
    let (port, kind) = match dest(i, addr, len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let r = autobind(i);
    if r < 0 {
        return r;
    }
    let s = sock(i);
    if s.laddr == ADDR_ANY {
        s.laddr = kind; // the source address the route chose
    }
    s.state = WS_CONNECTED;
    s.rport = port;
    s.raddr = kind;
    let s = *s;
    sup(
        Op::UdpConnect,
        [i as u64, port as u64, kind as u64, 1, s.laddr as u64, 0],
    );
    0
}

fn names(call: &mut dyn Call, i: usize, peer: bool) -> i64 {
    let [_, addr, alen, ..] = args(call);
    let s = *sock(i);
    if peer {
        if s.state != WS_CONNECTED {
            return -ENOTCONN;
        }
        put_addr(s.family, shown(s.raddr), s.rport, addr, alen)
    } else {
        put_addr(s.family, shown(s.laddr), s.lport, addr, alen)
    }
}

/// The pending error (an ICMP-style `ECONNREFUSED`), cleared.
pub fn take_err(i: usize) -> i64 {
    let s = sock(i);
    let e = s.err as i64;
    s.err = 0;
    e
}

fn shutdown(call: &mut dyn Call, i: usize) -> i64 {
    let how = call.arg(1);
    if how > 2 {
        return -e::EINVAL;
    }
    let s = sock(i);
    if how != 1 {
        s.flags |= WF_SHUT_RD;
    }
    if how != 0 {
        s.flags |= WF_SHUT_WR;
    }
    io::bump(); // a parked reader returns 0
    if how != 1 {
        // A thread in poll or epoll waits on the descriptor itself: make it readable.
        sup(Op::UdpConnect, [i as u64, 0, 0, 2, 0, 0]);
    }
    // Linux applies it to an unconnected socket too (to wake its readers) but answers ENOTCONN.
    if s.state != WS_CONNECTED {
        -ENOTCONN
    } else {
        0
    }
}

// ---- data ----

/// The guest iovec array at `iov` (`cnt` entries) copied into `out[1..]`: (entries, bytes).
fn gather(iov: u64, cnt: u64, out: &mut [[u64; 2]; IOV_MAX + 1]) -> Result<(usize, u64), i64> {
    if cnt > 1024 {
        return Err(-EMSGSIZE);
    }
    if cnt as usize > IOV_MAX {
        refuse(b"udp:iovec>64");
        return Err(-EMSGSIZE);
    }
    let mut total = 0u64;
    for k in 0..cnt as usize {
        let v = get::<[u64; 2]>(iov + k as u64 * 16)?;
        if (v[1] as i64) < 0 {
            return Err(-e::EINVAL);
        }
        total += v[1];
        out[k + 1] = v;
    }
    Ok((cnt as usize, total))
}

/// One datagram from the guest's iovec to `to` (None: the connected peer).
fn send_iov(
    fd: i64,
    i: usize,
    nr: u64,
    iov: u64,
    cnt: u64,
    to: Option<(u64, u64)>,
    flags: u64,
) -> i64 {
    if flags & MSG_OOB != 0 {
        return -EOPNOTSUPP;
    }
    if flags & MSG_MORE != 0 {
        refuse(b"udp:MSG_MORE");
        return -EOPNOTSUPP;
    }
    let s = *sock(i);
    if s.flags & WF_SHUT_WR != 0 {
        if flags & MSG_NOSIGNAL == 0 {
            super::sig::raise_thread(super::sig::SIGPIPE);
        }
        return -EPIPE;
    }
    let (port, kind) = match to {
        Some((addr, len)) if addr != 0 => match dest(i, addr, len) {
            Ok(v) => v,
            Err(e) => return e,
        },
        _ if s.state == WS_CONNECTED => (s.rport, s.raddr),
        _ => return -EDESTADDRREQ,
    };
    if port == 0 {
        return -e::EINVAL;
    }
    let mut kiov = [[0u64; 2]; IOV_MAX + 1];
    let (n, len) = match gather(iov, cnt, &mut kiov) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let max = if s.family == AF_INET {
        DGRAM_MAX4
    } else {
        DGRAM_MAX6
    };
    if len > max as u64 {
        return -EMSGSIZE;
    }
    // An error a connected socket was sent (port unreachable) is reported by the next call.
    if s.err != 0 {
        return -take_err(i);
    }
    let r = autobind(i);
    if r < 0 {
        return r;
    }
    let m = [0u64, 0, kiov.as_ptr() as u64 + 16, n as u64, 0, 0, 0];
    let r = unsafe {
        sc3(
            nr::SENDMSG,
            fd as u64,
            m.as_ptr() as u64,
            MSG_DONTWAIT | MSG_NOSIGNAL,
        )
    };
    if r == -e::EFAULT {
        return r;
    }
    if r != len as i64 {
        crate::sup::host_error(
            if r < 0 { r } else { -e::EIO },
            nr::SENDMSG,
            proto::ctl::HE_SYSCALL,
        );
    }
    sup(
        Op::UdpSend,
        [i as u64, port as u64, kind as u64, len, nr, 0],
    );
    len as i64
}

/// What one received datagram was.
#[derive(Default)]
struct Got1 {
    /// Payload bytes of the datagram (more than were copied when it was truncated).
    len: u64,
    copied: u64,
    kind: u8,
    port: u16,
}

/// Take (or with `MSG_PEEK` look at) the next datagram into the guest's iovec. `Ok(None)`:
/// nothing is queued; an error the socket holds is returned first.
fn recv1(
    fd: i64,
    i: usize,
    kiov: &mut [[u64; 2]; IOV_MAX + 1],
    n: usize,
    cap: u64,
    flags: u64,
) -> Result<Option<Got1>, i64> {
    loop {
        if sock(i).err != 0 {
            return Err(-take_err(i));
        }
        if sock(i).flags & WF_SHUT_RD != 0 {
            return Ok(Some(Got1::default()));
        }
        let mut hdr = [0u64; 2];
        kiov[0] = [hdr.as_mut_ptr() as u64, DGRAM_HDR as u64];
        let m = [0u64, 0, kiov.as_ptr() as u64, n as u64 + 1, 0, 0, 0];
        let r = unsafe {
            sc3(
                nr::RECVMSG,
                fd as u64,
                m.as_ptr() as u64,
                (flags & MSG_PEEK) | MSG_DONTWAIT | MSG_TRUNC,
            )
        };
        if r == -e::EAGAIN {
            return Ok(None);
        }
        let kind = hdr[0] & 0xff;
        let plen = hdr[1] >> 32;
        let peek = flags & MSG_PEEK != 0;
        if r < 0 {
            if r == -e::EFAULT && !peek && kind == DG_DATA {
                // The kernel took the datagram and failed to copy it: it is gone.
                uncharge(i, plen);
            }
            return Err(r);
        }
        if (r as usize) < DGRAM_HDR {
            crate::sup::host_error(-e::EIO, nr::RECVMSG, proto::ctl::HE_RUNTIME_ASSERT);
        }
        if kind == DG_ERR {
            if peek {
                // Not the guest's data: take it out of the queue.
                let h = [hdr.as_mut_ptr() as u64, DGRAM_HDR as u64];
                let m = [0u64, 0, h.as_ptr() as u64, 1, 0, 0, 0];
                unsafe { sc3(nr::RECVMSG, fd as u64, m.as_ptr() as u64, MSG_DONTWAIT) };
            }
            // The marker is gone from the queue: another may be queued, and a held delivery
            // behind it can go on.
            sock(i).marks &= !MARK_QUEUED;
            io::bump();
            continue; // the error itself is `err`, reported above if still pending
        }
        let len = r as u64 - DGRAM_HDR as u64;
        if !peek {
            uncharge(i, len);
        }
        return Ok(Some(Got1 {
            len,
            copied: len.min(cap),
            kind: (hdr[0] >> 8) as u8,
            port: (hdr[0] >> 16) as u16,
        }));
    }
}

fn uncharge(i: usize, len: u64) {
    let s = sock(i);
    s.rq = s.rq.saturating_sub(dgram_charge(len as usize));
    io::bump(); // the receive queue has room: a held delivery can go on
}

fn receiver(fd: i64, nr: u64, flags: u64) -> Waiter {
    let mut w = Waiter::new(fd, PARK_IN, nr);
    w.deadline = Deadline::RcvTimeo;
    if flags & MSG_DONTWAIT != 0 {
        w.nonblock = Some(true);
    }
    w
}

/// Receive one datagram into `iov`; returns the result and what was received.
fn recv_iov(w: &mut Waiter, fd: i64, i: usize, iov: u64, cnt: u64, flags: u64) -> (i64, Got1) {
    if flags & MSG_OOB != 0 {
        return (-e::EINVAL, Got1::default());
    }
    if flags & MSG_ERRQUEUE != 0 {
        // No error queue is kept (IP_RECVERR is recorded only): always empty.
        return (-e::EAGAIN, Got1::default());
    }
    let mut kiov = [[0u64; 2]; IOV_MAX + 1];
    let (n, cap) = match gather(iov, cnt, &mut kiov) {
        Ok(v) => v,
        Err(e) => return (e, Got1::default()),
    };
    let mut got = Got1::default();
    let g = w.run(|| match recv1(fd, i, &mut kiov, n, cap, flags) {
        Ok(None) => None,
        Ok(Some(d)) => {
            let r = if flags & MSG_TRUNC != 0 {
                d.len
            } else {
                d.copied
            };
            got = d;
            Some(r as i64)
        }
        Err(e) => Some(e),
    });
    (io::result(g, -e::EAGAIN), got)
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
        Some((a[4], a[5])),
        a[3],
    )
}

/// The fields of a guest `msghdr`: name, namelen, iov, iovlen.
fn msghdr(m: u64) -> Result<(u64, u64, u64, u64), i64> {
    let h = get::<[u64; 7]>(m)?;
    Ok((h[0], h[1] & 0xffff_ffff, h[2], h[3]))
}

fn sendmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let (name, nlen, iov, cnt) = match msghdr(a[1]) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if get::<u64>(a[1] + 40) != Ok(0) {
        // Ancillary data (IP_PKTINFO, UDP_SEGMENT, ...): not modelled.
        refuse(b"udp:cmsg");
        return -e::EINVAL;
    }
    send_iov(
        a[0] as i32 as i64,
        i,
        nr::SENDMSG,
        iov,
        cnt,
        Some((name, nlen)),
        a[2],
    )
}

fn sendmmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let vlen = a[2].min(1024);
    let mut done = 0u64;
    while done < vlen {
        let m = a[1] + done * 64;
        let r = match msghdr(m) {
            Ok((name, nlen, iov, cnt)) => {
                if get::<u64>(m + 40) != Ok(0) {
                    refuse(b"udp:cmsg");
                    -e::EINVAL
                } else {
                    send_iov(fd, i, nr::SENDMMSG, iov, cnt, Some((name, nlen)), a[3])
                }
            }
            Err(e) => e,
        };
        if r < 0 {
            return if done > 0 { done as i64 } else { r };
        }
        if put(m + 56, r as u32).is_err() {
            return if done > 0 { done as i64 } else { -e::EFAULT };
        }
        done += 1;
    }
    done as i64
}

fn recvfrom(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let one = [a[1], a[2]];
    let mut w = receiver(fd, nr::RECVFROM, a[3]);
    let (r, got) = recv_iov(&mut w, fd, i, one.as_ptr() as u64, 1, a[3]);
    if r >= 0 && a[4] != 0 && a[5] != 0 {
        let pr = put_addr(sock(i).family, shown(got.kind), got.port, a[4], a[5]);
        if pr < 0 {
            return w.finish(pr);
        }
    }
    w.finish(r)
}

/// Fill a guest `msghdr` after a receive: the source, no ancillary data, `MSG_TRUNC`.
fn msg_out(i: usize, m: u64, got: &Got1) -> i64 {
    let (name, ..) = match msghdr(m) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if name != 0 {
        let r = put_addr(sock(i).family, shown(got.kind), got.port, name, m + 8);
        if r < 0 {
            return r;
        }
    } else if put(m + 8, 0u32).is_err() {
        return -e::EFAULT;
    }
    let flags = if got.len > got.copied {
        MSG_TRUNC as i32
    } else {
        0
    };
    if put(m + 40, 0u64).is_err() || put(m + 48, flags).is_err() {
        return -e::EFAULT;
    }
    0
}

fn recvmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let (_, _, iov, cnt) = match msghdr(a[1]) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut w = receiver(fd, nr::RECVMSG, a[2]);
    let (r, got) = recv_iov(&mut w, fd, i, iov, cnt, a[2]);
    if r >= 0 {
        let e = msg_out(i, a[1], &got);
        if e < 0 {
            return w.finish(e);
        }
    }
    w.finish(r)
}

/// recvmmsg: the first datagram as the call's blocking mode says, the rest only if queued
/// (returns once at least one arrived, as with `MSG_WAITFORONE`). The timeout is a virtual
/// deadline for the first.
fn recvmmsg(call: &mut dyn Call, i: usize) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let vlen = a[2].min(1024);
    let flags = a[3] & !MSG_WAITFORONE;
    let mut w = receiver(fd, nr::RECVMMSG, flags);
    if a[4] != 0 {
        match super::time::read_timespec(a[4]) {
            Ok(ns) => w.deadline = Deadline::after(ns),
            Err(e) => return e,
        }
    }
    let mut done = 0u64;
    while done < vlen {
        let m = a[1] + done * 64;
        let (_, _, iov, cnt) = match msghdr(m) {
            Ok(v) => v,
            Err(e) => return if done > 0 { done as i64 } else { e },
        };
        if done > 0 {
            w.nonblock = Some(true);
        }
        let (r, got) = recv_iov(&mut w, fd, i, iov, cnt, flags);
        if r < 0 {
            return w.finish(if done > 0 { done as i64 } else { r });
        }
        let e = msg_out(i, m, &got);
        if e < 0 || put(m + 56, r as u32).is_err() {
            return w.finish(if done > 0 { done as i64 } else { e.min(-1) });
        }
        done += 1;
    }
    w.finish(done as i64)
}

/// read/readv/preadv2 and write/writev/pwritev2 on a datagram socket: one datagram each,
/// without addresses (a write needs a connected peer).
pub fn rw(call: &mut dyn Call, i: usize) -> i64 {
    set_class(call, proto::table::Class::Attempt);
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let one = [a[1], a[2]];
    let p1 = one.as_ptr() as u64;
    let (write, iov, cnt, flags) = match call.nr() {
        nr::READ => (false, p1, 1, 0),
        nr::WRITE => (true, p1, 1, 0),
        nr::READV => (false, a[1], a[2], 0),
        nr::WRITEV => (true, a[1], a[2], 0),
        nr::PREADV2 | nr::PWRITEV2 if a[3] as i64 == -1 => (
            call.nr() == nr::PWRITEV2,
            a[1],
            a[2],
            if a[5] & io::RWF_NOWAIT != 0 {
                MSG_DONTWAIT
            } else {
                0
            },
        ),
        _ => {
            set_class(call, proto::table::Class::Pass);
            return raw(call); // an explicit offset: ESPIPE
        }
    };
    if write {
        return send_iov(fd, i, call.nr(), iov, cnt, None, flags);
    }
    let mut w = receiver(fd, call.nr(), flags);
    let (r, _) = recv_iov(&mut w, fd, i, iov, cnt, flags);
    w.finish(r)
}

/// `ioctl(FIONREAD)`: the payload length of the next datagram (0 when none).
pub fn fionread(fd: i64, i: usize, out: u64) -> i64 {
    let mut kiov = [[0u64; 2]; IOV_MAX + 1];
    // A pending error stays pending (Linux's SIOCINQ leaves sk_err alone).
    let err = core::mem::replace(&mut sock(i).err, 0);
    let n = match recv1(fd, i, &mut kiov, 0, 0, MSG_PEEK) {
        Ok(Some(g)) => g.len,
        Ok(None) => 0,
        Err(_) => 0,
    };
    sock(i).err = err;
    match put(out, n as i32) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// A call on datagram socket `i`.
pub fn handle(call: &mut dyn Call, i: usize) -> Action {
    let r = match call.nr() {
        nr::BIND => bind(call, i),
        nr::CONNECT => connect(call, i),
        // listen, accept: not for datagram sockets.
        nr::LISTEN | nr::ACCEPT | nr::ACCEPT4 => -EOPNOTSUPP,
        nr::GETSOCKNAME => names(call, i, false),
        nr::GETPEERNAME => names(call, i, true),
        nr::SETSOCKOPT => super::inet::setsockopt(call, i),
        nr::GETSOCKOPT => super::inet::getsockopt(call, i),
        nr::SHUTDOWN => shutdown(call, i),
        nr::SENDTO => sendto(call, i),
        nr::SENDMSG => sendmsg(call, i),
        nr::SENDMMSG => sendmmsg(call, i),
        nr::RECVFROM => recvfrom(call, i),
        nr::RECVMSG => recvmsg(call, i),
        nr::RECVMMSG => recvmmsg(call, i),
        _ => return stop_here(call),
    };
    Action::Return(r)
}
