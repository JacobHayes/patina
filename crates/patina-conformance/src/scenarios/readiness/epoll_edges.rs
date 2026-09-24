//! readiness/epoll_edges — epoll over sockets: edge-triggered arrival
//! semantics, `EPOLLRDHUP`, `EPOLLEXCLUSIVE`, and the `epoll_pwait` /
//! `epoll_pwait2` rows, plus the legacy `epoll_create` and `eventfd` rows
//! (epoll(7), epoll_ctl(2), epoll_wait(2); fs/eventpoll.c):
//!
//! * edge-triggered, every ARRIVAL is an edge: a second datagram (or a
//!   second write on a stream) reports the socket again although the first
//!   was never read (each wakeup re-queues the item, `ep_poll_callback`);
//!   without a new arrival nothing is reported; level-triggered reports as
//!   long as data is queued;
//! * a pending connection makes a listener readable; `EPOLLRDHUP` reports
//!   the peer's `SHUT_WR`;
//! * `EPOLLEXCLUSIVE` is accepted on `EPOLL_CTL_ADD` only: with
//!   `EPOLLONESHOT` it is `EINVAL`, on `EPOLL_CTL_MOD` `EINVAL`, and an
//!   exclusive item cannot be modified at all (`EINVAL`);
//! * `epoll_pwait` with a mask of another size than the kernel's sigset is
//!   `EINVAL`; `epoll_pwait2` takes a timespec (NULL waits without bound,
//!   nanoseconds reaching a second are `EINVAL`) and times out on the
//!   clock;
//! * x86_64 only: `epoll_create(size)` refuses a size of 0 or less with
//!   `EINVAL` and otherwise ignores it; the legacy `eventfd(initval)` row
//!   takes no flags (a blocking descriptor) and holds the initial count.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{Probe, SIGSET_BYTES, SockAddr, neg};
use crate::signals::one_set;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// The events recorded before the `EPOLLEXCLUSIVE` section: the x86_64-only
/// legacy rows add 18.
const EXCLUSIVE_AT: usize = if cfg!(target_arch = "x86_64") {
    105
} else {
    87
};

/// How long a wait for an event already caused may take.
const WAIT_MS: i32 = 5_000;

pub fn run(p: &Probe) {
    let usr1 = one_set(SIGUSR1);
    let ep = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("epoll_create1", ep >= 0);

    // ---- datagrams, edge-triggered ----
    let u = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a UDP socket", u >= 0);
    p.check("bind it", p.bind_to(u, &SockAddr::v4(0)) == 0);
    let (_, addr_u, _) = p.name_of(u, false, 128);
    let addr_u = addr_u.expect("getsockname u");
    let v = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a sender", v >= 0);
    p.check("bind the sender", p.bind_to(v, &SockAddr::v4(0)) == 0);
    p.check(
        "watch it edge-triggered for input",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, u, (EPOLLIN | EPOLLET) as u32, 1) == 0,
    );
    p.check(
        "nothing arrived: nothing reported",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    p.send_to(v, b"a", 0, Some(&addr_u));
    let (n, events) = p.epoll_pwait(ep, 8, WAIT_MS, None, SIGSET_BYTES as usize);
    p.check(
        "the first datagram is an edge",
        n == 1 && events == vec![(1, EPOLLIN as u32)],
    );
    p.check(
        "reported once",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    p.send_to(v, b"b", 0, Some(&addr_u));
    let (n, _) = p.epoll_pwait(ep, 8, WAIT_MS, None, SIGSET_BYTES as usize);
    p.check(
        "a second arrival is a new edge though the first was never read",
        n == 1,
    );
    p.check(
        "and again only once",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    p.recv_from(u, 8, 0, false);
    p.check(
        "reading one of two datagrams is no edge",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    p.check(
        "level-triggered",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, u, EPOLLIN as u32, 1) == 0,
    );
    p.check(
        "reports the datagram still queued",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 1,
    );
    p.check(
        "and again",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 1,
    );
    p.recv_from(u, 8, 0, false);
    p.check(
        "until it is read",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    p.check(
        "stop watching it",
        p.epoll_ctl(ep, EPOLL_CTL_DEL, u, 0, 0) == 0,
    );

    // ---- a stream ----
    let l = p.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    p.require("a listener", l >= 0);
    p.check("bind the listener", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.check("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");
    p.check(
        "watch the listener",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, l, EPOLLIN as u32, 2) == 0,
    );
    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a client", c >= 0);
    p.check("connect", p.connect_to(c, &addr_l) == 0);
    let (n, events) = p.epoll_pwait(ep, 8, WAIT_MS, None, SIGSET_BYTES as usize);
    p.check(
        "a pending connection makes the listener readable",
        n == 1 && events == vec![(2, EPOLLIN as u32)],
    );
    let (s, _) = p.accept_from(l, SOCK_NONBLOCK, false, false);
    p.require("accept4", s >= 0);
    p.check(
        "watch the connection edge-triggered with EPOLLRDHUP",
        p.epoll_ctl(
            ep,
            EPOLL_CTL_ADD,
            s,
            (EPOLLIN | EPOLLRDHUP | EPOLLET) as u32,
            3,
        ) == 0,
    );
    p.check(
        "nothing arrived on it",
        p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    p.send_to(c, b"x", 0, None);
    let (n, events) = p.epoll_pwait(ep, 8, WAIT_MS, None, SIGSET_BYTES as usize);
    p.check(
        "stream bytes are an edge",
        n == 1 && events == vec![(3, EPOLLIN as u32)],
    );
    p.send_to(c, b"y", 0, None);
    let (n, _) = p.epoll_pwait(ep, 8, WAIT_MS, None, SIGSET_BYTES as usize);
    p.check("more bytes, unread, are a new edge", n == 1);
    let (n, data, _) = p.recv_from(s, 8, 0, false);
    p.check("both are queued", n == 2 && data == b"xy");
    p.check("the peer shuts down writing", p.shutdown(c, SHUT_WR) == 0);
    let (n, events) = p.epoll_pwait(ep, 8, WAIT_MS, None, SIGSET_BYTES as usize);
    p.check(
        "EPOLLRDHUP reports it (with EPOLLIN: EOF is readable)",
        n == 1 && events == vec![(3, (EPOLLIN | EPOLLRDHUP) as u32)],
    );

    // ---- the masked and timespec waits ----
    let ef = p.eventfd2(0, EFD_NONBLOCK);
    p.require("an eventfd", ef >= 0);
    p.check(
        "watch it",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ef, EPOLLIN as u32, 4) == 0,
    );
    p.write(ef, &1u64.to_ne_bytes());
    let (n, events) = p.epoll_pwait(ep, 8, 0, Some(&usr1), SIGSET_BYTES as usize);
    p.check(
        "the eventfd reports, under a mask",
        n == 1 && events == vec![(4, EPOLLIN as u32)],
    );
    p.check(
        "epoll_pwait with another sigset size is EINVAL",
        p.epoll_pwait(ep, 8, 0, Some(&usr1), 4).0 == neg(EINVAL),
    );
    let (n, _) = p.epoll_pwait2(ep, 8, None);
    p.check("epoll_pwait2 with no timeout answers a ready item", n == 1);
    let (n, _) = p.epoll_pwait2(ep, 8, Some((0, 0)));
    p.check("and with a zero timeout", n == 1);
    p.check(
        "epoll_pwait2 with nanoseconds reaching a second is EINVAL",
        p.epoll_pwait2(ep, 8, Some((0, 1_000_000_000))).0 == neg(EINVAL),
    );
    p.read(ef, 8);
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "a timed epoll_pwait2 with nothing ready answers 0",
        p.epoll_pwait2(ep, 8, Some((0, 2_000_000))).0 == 0,
    );
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the clock advanced by at least the timeout",
        after - before >= 2_000_000,
    );

    #[cfg(target_arch = "x86_64")]
    {
        p.check(
            "epoll_create(0) is EINVAL",
            i64::from(p.epoll_create(0)) == neg(EINVAL),
        );
        let old = p.epoll_create(1);
        p.check("epoll_create(1) ignores its size", old >= 0);
        p.check("without close-on-exec", p.fcntl(old, F_GETFD, 0) == 0);
        let legacy = p.eventfd(3);
        p.check("the legacy eventfd row", legacy >= 0);
        p.check(
            "takes no flags: a blocking descriptor",
            p.fcntl(legacy, F_GETFL, 0) == i64::from(O_RDWR),
        );
        let (n, data) = p.read(legacy, 8);
        p.check(
            "holding its initial count",
            n == 8 && data == 3u64.to_ne_bytes(),
        );
        p.check(
            "an old-style epoll instance watches it",
            p.epoll_ctl(old, EPOLL_CTL_ADD, legacy, EPOLLOUT as u32, 9) == 0,
        );
        let (n, events) = p.epoll_pwait(old, 8, 0, None, SIGSET_BYTES as usize);
        p.check(
            "a drained eventfd is writable",
            n == 1 && events == vec![(9, EPOLLOUT as u32)],
        );
        p.close(legacy);
        p.close(old);
    }

    // ---- EPOLLEXCLUSIVE (last on purpose: a runtime that refuses the flag
    // fails closed here, after everything above) ----
    let ex = p.eventfd2(0, EFD_NONBLOCK);
    p.require("an eventfd", ex >= 0);
    p.check(
        "EPOLLEXCLUSIVE with EPOLLONESHOT is EINVAL",
        p.epoll_ctl(
            ep,
            EPOLL_CTL_ADD,
            ex,
            (EPOLLIN | EPOLLEXCLUSIVE | EPOLLONESHOT) as u32,
            5,
        ) == neg(EINVAL),
    );
    p.check(
        "EPOLLEXCLUSIVE on ADD",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ex, (EPOLLIN | EPOLLEXCLUSIVE) as u32, 5) == 0,
    );
    p.check(
        "an exclusive item cannot be modified",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ex, EPOLLIN as u32, 5) == neg(EINVAL),
    );
    p.check(
        "EPOLLEXCLUSIVE on MOD is EINVAL",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, s, (EPOLLIN | EPOLLEXCLUSIVE) as u32, 3) == neg(EINVAL),
    );
    p.write(ex, &1u64.to_ne_bytes());
    let (n, events) = p.epoll_pwait(ep, 8, 0, None, SIGSET_BYTES as usize);
    p.check(
        "the exclusive item reports",
        n == 1 && events == vec![(5, EPOLLIN as u32)],
    );

    for fd in [u, v, l, c, s, ef, ex, ep] {
        p.close(fd);
    }
    crate::scenarios::net::check_allocated_port(p, &addr_u);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/epoll_edges",
    run,
    covers: &[
        Syscall::N_epoll_pwait,
        Syscall::N_epoll_pwait2,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_create,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_eventfd,
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        Syscall::N_eventfd2,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_shutdown,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_fcntl,
        Syscall::N_clock_gettime,
        Syscall::N_close,
    ],
    symbols: &[
        "epoll_pwait",
        "epoll_create1",
        "epoll_ctl",
        "eventfd",
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "sendto",
        "recvfrom",
        "shutdown",
        "read",
        "write",
        "fcntl",
        "clock_gettime",
        "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "edge-triggered delivery re-arms on a readiness TRANSITION only (lib.rs epoll scan), where the kernel re-queues the item on every arrival (ep_poll_callback): a second datagram or stream write that arrives before the first is read is no new edge",
            failure: Failure::Differs(&[
                Difference::field(18, "epoll_pwait", "fields.events", Observed::Json(r#"[]"#)),
                Difference::field(18, "epoll_pwait", "ret", Observed::Int(0)),
                Difference::check(
                    19,
                    "a second arrival is a new edge though the first was never read",
                ),
                Difference::field(58, "epoll_pwait", "fields.events", Observed::Json(r#"[]"#)),
                Difference::field(58, "epoll_pwait", "ret", Observed::Int(0)),
                Difference::check(59, "more bytes, unread, are a new edge"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "EPOLLRDHUP is never reported for a peer's SHUT_WR (lib.rs epoll scan), where tcp_poll reports EPOLLIN|EPOLLRDHUP",
            failure: Failure::Differs(&[
                Difference::field(64, "epoll_pwait", "fields.events", Observed::Json(r#"[]"#)),
                Difference::field(64, "epoll_pwait", "ret", Observed::Int(0)),
                Difference::check(65, "EPOLLRDHUP reports it (with EPOLLIN: EOF is readable)"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "EPOLLEXCLUSIVE is an unmodeled flag: epoll_ctl fails closed (lib.rs patina_epoll_ctl) where the kernel accepts it on ADD and refuses it with EINVAL on MOD or with EPOLLONESHOT",
            failure: Failure::Stops {
                events: EXCLUSIVE_AT,
                ending: Ending::Signal(libc::SIGABRT),
                diagnostic: "epoll_ctl events 0x50000001 carry unmodeled flags",
            },
        },
    ],
    ..DEFAULTS
};
