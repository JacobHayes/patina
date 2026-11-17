//! `AF_UNIX` sockets: pass-through kernel objects with attempt semantics. Every call
//! that could wait is made in a form that cannot (`MSG_DONTWAIT`, a zero-timeout `poll`
//! before `accept4`, a connect on a description made non-blocking for that one call) and
//! parks until the I/O generation moves. Buffer sizes are fixed at creation. Other families
//! end the run (`AF_INET`/`AF_INET6`: the network wire).

use super::io::{self, Deadline, Got, IovCursor, Kind, Waiter, POLLERR, POLLHUP, POLLIN};
use super::*;
use proto::ctl::{PARK_IN, PARK_OUT};
use proto::layout::FD_HIDDEN_MIN;

const AF_UNIX: u64 = 1;
const SOL_SOCKET: u64 = 1;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const SCM_RIGHTS: i32 = 1;
const SO_TYPE: u64 = 3;
const SOCK_STREAM: i32 = 1;
const EADDRINUSE: i64 = 98;
const ENOSPC: i64 = 28;
const ENOPROTOOPT: i64 = 92;
/// SO_SNDBUF / SO_RCVBUF requested at creation (the kernel doubles it). Below any
/// plausible `wmem_max`/`rmem_max`, so the host's limits do not change the result.
pub const SOCK_BUF: u32 = 65_536;

pub fn fix_bufs(fd: i64) {
    let v = SOCK_BUF;
    for opt in [SO_SNDBUF, SO_RCVBUF] {
        unsafe {
            sc6(
                nr::SETSOCKOPT,
                fd as u64,
                SOL_SOCKET,
                opt,
                &v as *const u32 as u64,
                4,
                0,
            )
        };
    }
}

fn is_stream(fd: i64) -> bool {
    let mut t: i32 = 0;
    let mut len: u32 = 4;
    let r = unsafe {
        sc6(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_TYPE,
            &mut t as *mut i32 as u64,
            &mut len as *mut u32 as u64,
            0,
        )
    };
    r == 0 && t == SOCK_STREAM
}

fn socket(call: &mut dyn Call) -> Action {
    if call.arg(0) != AF_UNIX {
        return stop_here(call);
    }
    let r = raw(call);
    host_check(call, r);
    if r >= 0 {
        fix_bufs(r);
    }
    Action::Return(r)
}

fn socketpair(call: &mut dyn Call) -> Action {
    if call.arg(0) != AF_UNIX {
        return stop_here(call);
    }
    let r = raw(call);
    host_check(call, r);
    if r == 0 {
        if let Ok(sv) = get::<[i32; 2]>(call.arg(3)) {
            fix_bufs(sv[0] as i64);
            fix_bufs(sv[1] as i64);
        }
    }
    Action::Return(r)
}

/// bind: an autobind request (the address is the family only) gets "\0" + five hex digits
/// from a run counter instead of the kernel's random choice.
fn bind(call: &mut dyn Call) -> i64 {
    let [fd, addr, len, ..] = args(call);
    if len == 2 && addr != 0 && unsafe { *(addr as *const u16) } as u64 == AF_UNIX {
        let io = &ctl().io;
        loop {
            let n = io.autobind_next.load(Relaxed);
            if n > 0xfffff {
                return -ENOSPC;
            }
            io.autobind_next.store(n + 1, Relaxed);
            let mut sa = [0u8; 8];
            sa[0] = AF_UNIX as u8;
            for i in 0..5 {
                let d = ((n >> (4 * (4 - i))) & 0xf) as u8;
                sa[3 + i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
            }
            let r = unsafe { sc3(nr::BIND, fd, sa.as_ptr() as u64, 8) };
            if r != -EADDRINUSE {
                return r;
            }
        }
    }
    let r = raw(call);
    // A path name (not abstract, not autobind) makes a socket node in the filesystem: it is a
    // creation for the virtual time table and the operation log, as mknod is.
    if r == 0 && addr != 0 && len > 2 && len <= 110 && unsafe { *((addr + 2) as *const u8) } != 0 {
        let mut p = [0u8; 109];
        let n = (len - 2) as usize;
        unsafe { core::ptr::copy_nonoverlapping((addr + 2) as *const u8, p.as_mut_ptr(), n) };
        super::fs::created_elsewhere(p.as_ptr() as u64);
    }
    r
}

fn accept(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let flags = if call.nr() == nr::ACCEPT4 { a[3] } else { 0 };
    let mut w = Waiter::new(fd, PARK_IN, call.nr());
    let g = w.run(|| {
        if io::poll1(fd, POLLIN) & (POLLIN | POLLERR | POLLHUP) == 0 {
            // Not listening, a bad descriptor or nothing pending: accept4 decides the first
            // two without waiting; for the third, wait.
            let st = io::kind_of(fd);
            if st != Some(Kind::Sock) || !listening(fd) {
                return Some(unsafe { sc4(nr::ACCEPT4, a[0], a[1], a[2], flags) });
            }
            return None;
        }
        io::eagain(unsafe { sc4(nr::ACCEPT4, a[0], a[1], a[2], flags) })
    });
    let r = io::result(g, -e::EAGAIN);
    if r >= 0 {
        fix_bufs(r);
        io::bump();
    }
    w.finish(r)
}

fn listening(fd: i64) -> bool {
    const SO_ACCEPTCONN: u64 = 30;
    let mut v: i32 = 0;
    let mut len: u32 = 4;
    let r = unsafe {
        sc6(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_ACCEPTCONN,
            &mut v as *mut i32 as u64,
            &mut len as *mut u32 as u64,
            0,
        )
    };
    r == 0 && v != 0
}

/// connect: the only call with no non-blocking form but the description's flag. Under one
/// turn no other guest thread can observe the flag while it is set.
fn connect(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    if io::nonblocking(fd) {
        let r = raw(call);
        if r == 0 {
            io::bump();
        }
        return r;
    }
    let mut w = Waiter::new(fd, PARK_OUT, nr::CONNECT);
    w.nonblock = Some(false);
    w.deadline = Deadline::SndTimeo;
    let g = w.run(|| {
        let s = io::set_nonblock(fd, true);
        if s < 0 {
            return Some(s);
        }
        let r = unsafe { sc3(nr::CONNECT, a[0], a[1], a[2]) };
        io::set_nonblock(fd, false);
        // EINPROGRESS is not used by AF_UNIX; EAGAIN is a full backlog.
        io::eagain(r)
    });
    let r = io::result(g, -e::EAGAIN);
    if r == 0 {
        io::bump();
    }
    w.finish(r)
}

/// Label a run that sends an `AF_UNIX` socket in `SCM_RIGHTS` (bucket D: a cycle of
/// in-flight descriptors is released by the kernel's garbage-collector worker, asynchronously).
fn note_unix_in_flight(fd: i64) {
    const SO_DOMAIN: u64 = 39;
    let mut d: i32 = 0;
    let mut len: u32 = 4;
    let r = unsafe {
        sc6(
            nr::GETSOCKOPT,
            fd as u64,
            SOL_SOCKET,
            SO_DOMAIN,
            &mut d as *mut i32 as u64,
            &mut len as *mut u32 as u64,
            0,
        )
    };
    if r == 0 && d as u64 == AF_UNIX {
        let s = &ctl().stats.unix_sockets_sent;
        s.store(s.load(Relaxed) + 1, Relaxed);
    }
}

/// A hidden descriptor named in SCM_RIGHTS answers EBADF.
fn hidden_rights(msg: u64) -> bool {
    if msg == 0 {
        return false;
    }
    let (ctlp, ctll) = unsafe { (*((msg + 32) as *const u64), *((msg + 40) as *const u64)) };
    if ctlp == 0 {
        return false;
    }
    let mut off = 0u64;
    while off + 16 <= ctll {
        let h = ctlp + off;
        let (len, level, ty) = unsafe {
            (
                *(h as *const u64),
                *((h + 8) as *const i32),
                *((h + 12) as *const i32),
            )
        };
        if len < 16 {
            break;
        }
        if level == SOL_SOCKET as i32 && ty == SCM_RIGHTS {
            for i in 0..(len - 16) / 4 {
                let fd = unsafe { *((h + 16 + i * 4) as *const i32) };
                if fd >= FD_HIDDEN_MIN {
                    return true;
                }
                note_unix_in_flight(fd as i64);
            }
        }
        off += (len + 7) & !7;
    }
    false
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

/// sendto(fd, buf, len, flags, addr, alen): the remainder of a stream send continues.
fn sendto(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let mut w = sender(fd, nr::SENDTO, a[3]);
    let one = [a[1], a[2]];
    let r = io::write_all(&mut w, one.as_ptr() as u64, 1, |p, _| {
        let [b, l] = unsafe { *(p as *const [u64; 2]) };
        unsafe { sc6(nr::SENDTO, a[0], b, l, a[3] | MSG_DONTWAIT, a[4], a[5]) }
    });
    w.finish(r)
}

/// sendmsg: the first attempt sends the guest's message whole (with its control data);
/// a stream remainder continues without control data or name.
fn sendmsg(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let msg = a[1];
    if hidden_rights(msg) {
        return -e::EBADF;
    }
    if msg == 0 {
        return -e::EFAULT;
    }
    let mut w = sender(fd, nr::SENDMSG, a[2]);
    let (iov, cnt) = unsafe { (*((msg + 16) as *const u64), *((msg + 24) as *const u64)) };
    // The window the cursor builds lives on the runtime stack, so `p == iov` only for the
    // first attempt (repeated as long as it would block).
    let r = io::write_all(&mut w, iov, cnt, |p, n| {
        if p == iov {
            return unsafe { sc3(nr::SENDMSG, a[0], msg, a[2] | MSG_DONTWAIT) };
        }
        let m = [0u64, 0, p, n, 0, 0, 0];
        unsafe { sc3(nr::SENDMSG, a[0], m.as_ptr() as u64, a[2] | MSG_DONTWAIT) }
    });
    w.finish(r)
}

/// sendmmsg(fd, vec, vlen, flags): blocking until every message is sent.
fn sendmmsg(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let vlen = a[2].min(1024);
    for i in 0..vlen {
        if hidden_rights(a[1] + i * 64) {
            return -e::EBADF;
        }
    }
    let mut w = sender(fd, nr::SENDMMSG, a[3]);
    let mut done = 0u64;
    while done < vlen {
        let g = w.run(|| {
            io::eagain(unsafe {
                sc4(
                    nr::SENDMMSG,
                    a[0],
                    a[1] + done * 64,
                    vlen - done,
                    a[3] | MSG_DONTWAIT,
                )
            })
        });
        match g {
            Got::Done(r) if r > 0 => {
                done += r as u64;
                io::bump();
            }
            Got::Done(r) => return w.finish(if done > 0 { done as i64 } else { r }),
            g => {
                return w.finish(if done > 0 {
                    done as i64
                } else {
                    io::result(g, -e::EAGAIN)
                })
            }
        }
    }
    w.finish(done as i64)
}

/// recvfrom: one attempt delivers; MSG_WAITALL on a stream continues to the full count.
fn recvfrom(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let mut w = receiver(fd, nr::RECVFROM, a[3]);
    let waitall = a[3] & MSG_WAITALL != 0 && a[3] & MSG_DONTWAIT == 0 && is_stream(fd);
    let mut total = 0u64;
    loop {
        let off = total;
        let g = w.run(|| {
            io::eagain(unsafe {
                sc6(
                    nr::RECVFROM,
                    a[0],
                    a[1] + off,
                    a[2] - off,
                    a[3] | MSG_DONTWAIT,
                    a[4],
                    a[5],
                )
            })
        });
        match g {
            Got::Done(r) if r > 0 => {
                total += r as u64;
                io::bump();
                if !waitall || total >= a[2] {
                    return w.finish(total as i64);
                }
            }
            Got::Done(r) => return w.finish(if total > 0 { total as i64 } else { r }),
            g => {
                return w.finish(if total > 0 {
                    total as i64
                } else {
                    io::result(g, -e::EAGAIN)
                })
            }
        }
    }
}

/// recvmsg: as recvfrom; a MSG_WAITALL remainder continues without control data.
fn recvmsg(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let msg = a[1];
    let mut w = receiver(fd, nr::RECVMSG, a[2]);
    let g = w.run(|| io::eagain(unsafe { sc3(nr::RECVMSG, a[0], msg, a[2] | MSG_DONTWAIT) }));
    let r = match g {
        Got::Done(r) => r,
        g => return w.finish(io::result(g, -e::EAGAIN)),
    };
    if r <= 0 {
        return w.finish(r);
    }
    io::bump();
    if a[2] & MSG_WAITALL == 0 || !is_stream(fd) {
        return w.finish(r);
    }
    let (iov, cnt) = unsafe { (*((msg + 16) as *const u64), *((msg + 24) as *const u64)) };
    let mut cur = IovCursor::new(iov, cnt);
    cur.advance(r as u64);
    let mut total = r;
    let mut win = [[0u64; 2]; io::WIN];
    while !cur.done() {
        let n = cur.window(&mut win);
        let m = [0u64, 0, win.as_ptr() as u64, n, 0, 0, 0];
        let g = w.run(|| {
            io::eagain(unsafe {
                sc3(
                    nr::RECVMSG,
                    a[0],
                    m.as_ptr() as u64,
                    (a[2] & !MSG_WAITALL) | MSG_DONTWAIT,
                )
            })
        });
        match g {
            Got::Done(r) if r > 0 => {
                total += r;
                cur.advance(r as u64);
                io::bump();
            }
            _ => break,
        }
    }
    w.finish(total)
}

/// recvmmsg(fd, vec, vlen, flags, timeout): returns once at least one message arrived.
fn recvmmsg(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let mut w = receiver(fd, nr::RECVMMSG, a[3]);
    if a[4] != 0 {
        match super::time::read_timespec(a[4]) {
            Ok(ns) => w.deadline = Deadline::after(ns),
            Err(e) => return e,
        }
    }
    let g = w.run(|| {
        io::eagain(unsafe { sc6(nr::RECVMMSG, a[0], a[1], a[2], a[3] | MSG_DONTWAIT, 0, 0) })
    });
    let r = io::result(g, -e::EAGAIN);
    if r > 0 {
        io::bump();
    }
    w.finish(r)
}

// Socket options of sockets that are not wire sockets (AF_UNIX): an allowlist on
// SOL_SOCKET. Each answer is a function of the socket's own history in the sandbox (buffer
// sizes and timeouts the guest set, or the kernel's defaults for the namespace; peer
// credentials are the namespace's pid and fixed ids). Anything else is refused with
// ENOPROTOOPT and recorded: before, a denylist let new options through, and SO_COOKIE,
// SO_NETNS_COOKIE (host-global counters), receive timestamps (host clock), peer pidfds,
// SO_PEERGROUPS (the launcher's groups), SO_PEERSEC (LSM labels), SO_MEMINFO, SO_INCOMING_CPU
// and SO_INCOMING_NAPI_ID (host state) were each found and handled one at a time.
const SOL_SOCKET_SET: &[u64] = &[
    2,  // SO_REUSEADDR
    5,  // SO_DONTROUTE
    6,  // SO_BROADCAST
    7,  // SO_SNDBUF
    8,  // SO_RCVBUF
    9,  // SO_KEEPALIVE
    10, // SO_OOBINLINE
    12, // SO_PRIORITY
    13, // SO_LINGER
    15, // SO_REUSEPORT
    16, // SO_PASSCRED
    18, // SO_RCVLOWAT
    19, // SO_SNDLOWAT
    20, // SO_RCVTIMEO_OLD
    21, // SO_SNDTIMEO_OLD
    42, // SO_PEEK_OFF
    66, // SO_RCVTIMEO_NEW
    67, // SO_SNDTIMEO_NEW
];
/// Read-only options, on top of every settable one.
const SOL_SOCKET_GET: &[u64] = &[
    3,  // SO_TYPE
    4,  // SO_ERROR
    17, // SO_PEERCRED
    30, // SO_ACCEPTCONN
    38, // SO_PROTOCOL
    39, // SO_DOMAIN
];

fn listed_opt(get: bool, level: u64, name: u64) -> bool {
    level == SOL_SOCKET
        && (SOL_SOCKET_SET.contains(&name) || (get && SOL_SOCKET_GET.contains(&name)))
}

/// A socket option call on a descriptor that is not a socket goes to the kernel (ENOTSOCK).
fn is_socket(fd: u64) -> bool {
    super::fs::fstat_raw(fd as i32 as i64).is_some_and(|st| st[3] as u32 & 0o170000 == 0o140000)
}

pub fn handle(call: &mut dyn Call) -> Action {
    let r = match call.nr() {
        nr::SOCKET => return socket(call),
        nr::SOCKETPAIR => return socketpair(call),
        nr::BIND => bind(call),
        nr::ACCEPT | nr::ACCEPT4 => accept(call),
        nr::CONNECT => connect(call),
        nr::SENDTO => sendto(call),
        nr::SENDMSG => sendmsg(call),
        nr::SENDMMSG => sendmmsg(call),
        nr::RECVFROM => recvfrom(call),
        nr::RECVMSG => recvmsg(call),
        nr::RECVMMSG => recvmmsg(call),
        nr::SETSOCKOPT | nr::GETSOCKOPT
            if !listed_opt(call.nr() == nr::GETSOCKOPT, call.arg(1), call.arg(2))
                && is_socket(call.arg(0)) =>
        {
            // Recorded as sockopt:LEVEL:NAME.
            let mut pre = [0u8; 24];
            pre[..8].copy_from_slice(b"sockopt:");
            let n = 8 + crate::path::fmt_dec(&mut pre[8..], call.arg(1) & 0xffff_ffff);
            let name = call.arg(2) & 0xffff_ffff;
            refuse_request(call, &pre[..n], name, false, -ENOPROTOOPT)
        }
        // listen, shutdown, setsockopt change what others see; names and options are queries.
        nr::LISTEN | nr::SHUTDOWN | nr::SETSOCKOPT => {
            let r = raw(call);
            host_check(call, r);
            if r == 0 {
                io::bump();
            }
            r
        }
        nr::GETSOCKNAME | nr::GETPEERNAME | nr::GETSOCKOPT => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        _ => return stop_here(call),
    };
    Action::Return(r)
}
