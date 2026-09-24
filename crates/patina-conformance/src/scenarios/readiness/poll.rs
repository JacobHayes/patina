//! readiness/poll — poll(2) over sockets (poll(2); fs/select.c
//! `do_sys_poll`, net/ipv4/tcp.c `tcp_poll`, net/core/datagram.c
//! `datagram_poll`):
//!
//! * a bound UDP socket is writable, and readable once a datagram arrives;
//! * a listener is readable once a connection is pending;
//! * a connected TCP socket reports `POLLRDHUP` (with `POLLIN`) once its peer
//!   shut down writing, and `POLLHUP` once both directions are shut;
//! * a closed descriptor reports `POLLNVAL`, a negative one is ignored; no
//!   descriptors is a timed sleep of the clock (the faulting arrays are
//!   readiness/poll_fault).
//!
//! The generic (arm64) table has no `poll` row: there the syscall vehicle
//! issues `ppoll` (glibc's own spelling) and the libc vehicle calls glibc's
//! `poll`.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{Probe, SockAddr};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// How long a poll waits for an event already caused (loopback delivers
/// within the causing call; the bound only keeps a slow host honest).
const WAIT_MS: i32 = 5_000;

/// The bits a revents field is recorded with.
const SHOWN: i16 = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDHUP | POLLPRI;

pub fn run(p: &Probe) {
    let u = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("a UDP socket", u >= 0);
    p.check("bind it", p.bind_to(u, &SockAddr::v4(0)) == 0);
    let (_, addr_u, _) = p.name_of(u, false, 128);
    let addr_u = addr_u.expect("getsockname u");
    let (n, revents) = p.poll(&[(u, POLLIN | POLLOUT)], 0, SHOWN);
    p.check(
        "a bound UDP socket is writable, not readable",
        n == 1 && revents == vec![POLLOUT],
    );
    let v = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a sender", v >= 0);
    p.check("bind the sender", p.bind_to(v, &SockAddr::v4(0)) == 0);
    p.check("send a datagram", p.send_to(v, b"d", 0, Some(&addr_u)) == 1);
    let (n, revents) = p.poll(&[(u, POLLIN)], WAIT_MS, SHOWN);
    p.check("the datagram arrives", n == 1 && revents == vec![POLLIN]);
    let (n, revents) = p.poll(&[(u, POLLIN | POLLOUT)], 0, SHOWN);
    p.check(
        "with a datagram queued it is readable too",
        n == 1 && revents == vec![POLLIN | POLLOUT],
    );
    p.recv_from(u, 8, 0, false);

    let l = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a listener", l >= 0);
    p.check("bind the listener", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.check("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");
    let (n, _) = p.poll(&[(l, POLLIN)], 0, SHOWN);
    p.check("a listener with nothing pending is not readable", n == 0);
    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a client", c >= 0);
    p.check("connect", p.connect_to(c, &addr_l) == 0);
    let (n, revents) = p.poll(&[(l, POLLIN)], WAIT_MS, SHOWN);
    p.check(
        "a pending connection makes the listener readable",
        n == 1 && revents == vec![POLLIN],
    );
    let (s, _) = p.accept_from(l, 0, false, false);
    p.require("accept4", s >= 0);
    let (n, revents) = p.poll(&[(s, POLLIN | POLLRDHUP)], 0, SHOWN);
    p.check(
        "an idle connection reports nothing asked",
        n == 0 && revents == vec![0],
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

    let x = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a socket to close", x >= 0);
    p.close(x);
    let (n, revents) = p.poll(&[(x, POLLIN), (-1, POLLIN), (u, POLLOUT)], 0, SHOWN);
    p.check(
        "a closed descriptor reports POLLNVAL, a negative one is ignored",
        n == 2 && revents == vec![POLLNVAL, 0, POLLOUT],
    );
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    let (n, _) = p.poll(&[], 2, SHOWN);
    p.check("no descriptors is a timed sleep", n == 0);
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "that advanced the clock by at least the timeout",
        after - before >= 2_000_000,
    );

    for fd in [u, v, l, c, s] {
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
        #[cfg(not(target_arch = "x86_64"))]
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
        Syscall::N_clock_gettime,
        Syscall::N_close,
    ],
    symbols: &[
        "poll",
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "sendto",
        "recvfrom",
        "shutdown",
        "clock_gettime",
        "close",
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::NetworkReadiness),
        vehicles: Vehicle::ALL,
        what: "poll reports the peer's SHUT_WR as POLLHUP without POLLRDHUP (the readiness core's socket readiness: POLLHUP on read EOF alone), where tcp_poll reports POLLIN|POLLRDHUP for a half-closed peer and POLLHUP only once both directions are shut",
        failure: Failure::Differs(&[
            Difference::field(34, "poll", "fields.revents0", Observed::Int(17)),
            Difference::check(35, "POLLIN|POLLRDHUP once the peer shut down writing"),
            Difference::field(38, "poll", "fields.revents0", Observed::Int(25)),
            Difference::check(39, "POLLHUP once both directions are shut"),
        ]),
    }],
    ..DEFAULTS
};
