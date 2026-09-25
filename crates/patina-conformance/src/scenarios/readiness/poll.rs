//! readiness/poll — poll(2) and ppoll(2) readiness bits by descriptor kind
//! (poll(2); fs/select.c `do_sys_poll`, the one core under both,
//! net/ipv4/tcp.c `tcp_poll`, net/core/datagram.c `datagram_poll`,
//! fs/pipe.c `pipe_poll`, fs/eventfd.c `eventfd_poll`):
//!
//! * every zero-timeout readiness below is asked through both calls, which
//!   answer alike;
//! * a bound UDP socket is writable, and readable once a datagram arrives;
//! * a listener is readable once a connection is pending;
//! * a connected TCP socket reports `POLLRDHUP` (with `POLLIN`) once its peer
//!   shut down writing, and `POLLHUP` once both directions are shut;
//! * a TCP stream is readable only once `SO_RCVLOWAT` bytes are queued
//!   (`tcp_poll`), yet a non-blocking receive takes fewer (`tcp_recvmsg`
//!   stops at any data once it may not wait); a blocking peek below the mark
//!   waits for it, here until its `SO_RCVTIMEO` (`sock_rcvlowat` is the
//!   peek's target too; the mark's caps are net/sockopt's);
//! * unconnected stream sockets are `POLLOUT|POLLHUP`, a datagram socket
//!   `POLLOUT`, an idle listener nothing;
//! * a pipe's read end is readable once written and `POLLHUP` once its
//!   writer closed, its write end writable; an eventfd is writable, and
//!   readable once written;
//! * a closed descriptor reports `POLLNVAL`, a negative one is ignored;
//! * a wait with nothing ready, and one with no descriptors, is a timed
//!   sleep of the clock, in `poll`'s milliseconds and `ppoll`'s timespec
//!   alike (the faulting arrays are readiness/poll_fault).
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").
//!
//! The generic (arm64) table has no `poll` row: there the syscall vehicle
//! issues `ppoll` (glibc's own spelling) and the libc vehicle calls glibc's
//! `poll`.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, SockAddr};
use crate::scenarios::net::{int, timeval};
use libc::*;
use patina_dst_syscalls::Syscall;

/// How long a poll waits for an event already caused (loopback delivers
/// within the causing call; the bound only keeps a slow host honest).
const WAIT_MS: i32 = 5_000;

/// The bits a revents field is recorded with.
const SHOWN: i16 = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDHUP | POLLPRI;

/// Readiness right now: `poll` and `ppoll` with a zero timeout both answer
/// `expected` per slot, and count the slots with any bit.
fn ready(p: &Probe, label: &str, fds: &[(i32, i16)], expected: &[i16]) {
    let count = expected.iter().filter(|revents| **revents != 0).count() as i64;
    let (n, by_poll) = p.poll(fds, 0, SHOWN);
    let (m, by_ppoll) = p.ppoll(fds, Some(0));
    p.check(
        label,
        n == count && by_poll == expected && m == count && by_ppoll == expected,
    );
}

pub fn run(p: &Probe) {
    // ---- sockets ----
    let u = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("a UDP socket", u >= 0);
    p.require("bind it", p.bind_to(u, &SockAddr::v4(0)) == 0);
    let (_, addr_u, _) = p.name_of(u, false, 128);
    let addr_u = addr_u.expect("getsockname u");
    ready(
        p,
        "a bound UDP socket is writable, not readable",
        &[(u, POLLIN | POLLOUT)],
        &[POLLOUT],
    );
    let v = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a sender", v >= 0);
    p.require("bind the sender", p.bind_to(v, &SockAddr::v4(0)) == 0);
    p.check("send a datagram", p.send_to(v, b"d", 0, Some(&addr_u)) == 1);
    let (n, revents) = p.poll(&[(u, POLLIN)], WAIT_MS, SHOWN);
    p.check("the datagram arrives", n == 1 && revents == vec![POLLIN]);
    ready(
        p,
        "with a datagram queued it is readable too",
        &[(u, POLLIN | POLLOUT)],
        &[POLLIN | POLLOUT],
    );
    p.recv_from(u, 8, 0, false);

    let l = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a listener", l >= 0);
    p.require("bind the listener", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.require("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");
    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a client", c >= 0);
    p.require("connect", p.connect_to(c, &addr_l) == 0);
    let (n, revents) = p.poll(&[(l, POLLIN)], WAIT_MS, SHOWN);
    p.check(
        "a pending connection makes the listener readable",
        n == 1 && revents == vec![POLLIN],
    );
    let (s, _) = p.accept_from(l, 0, false, false);
    p.require("accept4", s >= 0);
    ready(
        p,
        "an idle connection reports nothing asked",
        &[(s, POLLIN | POLLRDHUP)],
        &[0],
    );
    p.check("the peer shuts down writing", p.shutdown(c, SHUT_WR) == 0);
    let (n, revents) = p.poll(&[(s, POLLIN | POLLRDHUP)], WAIT_MS, SHOWN);
    p.check(
        "POLLIN|POLLRDHUP once the peer shut down writing",
        n == 1 && revents == vec![POLLIN | POLLRDHUP],
    );
    p.check("shut down writing here too", p.shutdown(s, SHUT_WR) == 0);
    let (n, revents) = p.poll(&[(s, POLLIN | POLLRDHUP)], WAIT_MS, SHOWN);
    p.check(
        "POLLHUP once both directions are shut",
        n == 1 && revents == vec![POLLIN | POLLRDHUP | POLLHUP],
    );

    // ---- a stream's receive low-water mark ----
    let lc = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a second client", lc >= 0);
    p.require("connect it", p.connect_to(lc, &addr_l) == 0);
    let (ls, _) = p.accept_from(l, 0, false, false);
    p.require("accept it", ls >= 0);
    p.check(
        "SO_RCVLOWAT 4 on the server",
        p.setsockopt_bytes(ls, SOL_SOCKET, SO_RCVLOWAT, &int(4), 4, "4") == 0,
    );
    p.send_to(lc, b"ab", 0, None);
    ready(
        p,
        "two bytes queued are not readable",
        &[(ls, POLLIN)],
        &[0],
    );
    let (n, data) = p.recv(ls, 16, MSG_DONTWAIT);
    p.check(
        "a non-blocking receive takes them all the same",
        n == 2 && data == b"ab",
    );
    p.send_to(lc, b"cdef", 0, None);
    let (n, revents) = p.poll(&[(ls, POLLIN)], WAIT_MS, SHOWN);
    p.check("four are", n == 1 && revents == vec![POLLIN]);
    let (n, data) = p.recv(ls, 16, 0);
    p.check("a receive takes them", n == 4 && data == b"cdef");
    p.check(
        "SO_RCVTIMEO 50 ms on the server",
        p.setsockopt_bytes(ls, SOL_SOCKET, SO_RCVTIMEO, &timeval(0, 50_000), 16, "50ms") == 0,
    );
    p.send_to(lc, b"gh", 0, None);
    let (_, before) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    let (n, data) = p.recv(ls, 16, MSG_PEEK);
    let (_, after) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    p.check(
        "a blocking peek below the mark waits out its timeout, then answers what is queued",
        n == 2 && data == b"gh" && after - before >= 50_000_000,
    );
    let (n, _) = p.recv(ls, 16, MSG_DONTWAIT);
    p.check("the peeked bytes are still queued", n == 2);
    for fd in [lc, ls] {
        p.close(fd);
    }

    // A stream socket that never connected is writable and hung up
    // (`unix_poll`, `tcp_poll` on TCP_CLOSE); a listener reports nothing
    // once its connection was accepted; a datagram socket is writable.
    let us = p.socket(AF_UNIX, SOCK_STREAM, 0);
    let uq = p.socket(AF_UNIX, SOCK_SEQPACKET, 0);
    let ud = p.socket(AF_UNIX, SOCK_DGRAM, 0);
    let ts = p.socket(AF_INET, SOCK_STREAM, 0);
    let all = POLLIN | POLLOUT | POLLRDHUP | POLLPRI;
    p.require(
        "four unconnected sockets",
        us >= 0 && uq >= 0 && ud >= 0 && ts >= 0,
    );
    ready(
        p,
        "unconnected streams are POLLOUT|POLLHUP, a datagram socket POLLOUT",
        &[(us, all), (uq, all), (ud, all), (ts, all)],
        &[
            POLLOUT | POLLHUP,
            POLLOUT | POLLHUP,
            POLLOUT,
            POLLOUT | POLLHUP,
        ],
    );
    ready(
        p,
        "a listener with nothing pending reports nothing",
        &[(l, all)],
        &[0],
    );
    for fd in [us, uq, ud, ts] {
        p.close(fd);
    }

    // ---- a pipe and an eventfd ----
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    ready(p, "an empty pipe is not readable", &[(rd, POLLIN)], &[0]);
    p.write(wr, b"x");
    ready(
        p,
        "a written pipe is readable, its write end writable",
        &[(rd, POLLIN), (wr, POLLOUT)],
        &[POLLIN, POLLOUT],
    );
    p.read(rd, 8);
    let ef = p.eventfd2(0, EFD_NONBLOCK);
    p.require("eventfd2", ef >= 0);
    ready(
        p,
        "a fresh eventfd is writable only",
        &[(ef, POLLIN | POLLOUT)],
        &[POLLOUT],
    );
    p.write(ef, &1u64.to_ne_bytes());
    ready(
        p,
        "a written eventfd is readable and writable",
        &[(ef, POLLIN | POLLOUT)],
        &[POLLIN | POLLOUT],
    );

    // ---- descriptors that are not there, and timed waits ----
    let x = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a socket to close", x >= 0);
    p.close(x);
    ready(
        p,
        "a closed descriptor reports POLLNVAL, a negative one is ignored",
        &[(x, POLLIN), (-1, POLLIN), (u, POLLOUT)],
        &[POLLNVAL, 0, POLLOUT],
    );
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    let (n, _) = p.poll(&[], 2, SHOWN);
    p.check("poll with no descriptors is a timed sleep", n == 0);
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "that advanced the clock by at least the timeout",
        after - before >= 2_000_000,
    );
    let (n, _) = p.ppoll(&[], Some(1_000_000));
    p.check("ppoll with no descriptors is a sleep", n == 0);
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    let (n, _) = p.ppoll(&[(rd, POLLIN)], Some(2_000_000));
    p.check("a timed ppoll with nothing ready returns 0", n == 0);
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the timed wait advanced the clock by at least the timeout",
        after - before >= 2_000_000,
    );
    p.check("close the pipe's writer", p.close(wr) == 0);
    ready(
        p,
        "a pipe with no writer reports POLLHUP",
        &[(rd, POLLIN)],
        &[POLLHUP],
    );

    for fd in [u, v, l, c, s, rd, ef] {
        p.close(fd);
    }
    crate::scenarios::net::check_allocated_port(p, &addr_u);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/poll",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_poll,
        Syscall::N_ppoll,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_shutdown,
        Syscall::N_setsockopt,
        Syscall::N_clock_gettime,
        Syscall::N_pipe2,
        Syscall::N_eventfd2,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
    ],
    symbols: &[
        "poll",
        "ppoll",
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "sendto",
        "recvfrom",
        "recv",
        "shutdown",
        "setsockopt",
        "clock_gettime",
        "pipe2",
        "eventfd",
        "read",
        "write",
        "close",
    ],
    ..DEFAULTS
};
