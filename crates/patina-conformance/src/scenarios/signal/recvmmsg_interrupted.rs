//! signal/recvmmsg_interrupted — a `recvmmsg` a handler interrupts
//! (`do_recvmmsg`): once a datagram was received the call answers the
//! count, and the interrupted receive's error is left pending on the socket
//! (`sk_err`), where the next receive reports it. That error is the one the
//! receive itself had: `ERESTARTSYS` for a socket with no `SO_RCVTIMEO`
//! (6.8 hands it to user space as errno 512, whatever `SA_RESTART`), `EINTR`
//! for one with a timeout; it comes before any datagram queued since, over
//! `AF_UNIX` and loopback UDP alike. With nothing received yet the call itself is
//! interrupted: restarted under `SA_RESTART` (its own timeout argument does
//! not make it `EINTR`; it is re-read), `EINTR` without it.
//!
//! Each helper sends a second datagram after its kill and is joined before
//! the socket is read again, so the reads after the call are ordered; a call
//! that wrongly kept waiting receives that datagram too.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::probe::{Probe, SockAddr, neg};
use crate::scenarios::net::timeval;
use crate::signals as support;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::thread;

/// `ERESTARTSYS` (`include/linux/errno.h`), which no libc names.
const ERESTARTSYS: i32 = 512;

/// A helper that interrupts the main thread's wait, then sends `late` to `fd`.
fn interrupt_then_send(p: &Probe, main_tid: pid_t, pid: pid_t, fd: c_int, late: &[u8]) {
    support::kill_when_parked(p, main_tid, pid, SIGUSR1);
    support::short_pause();
    unsafe { send(fd, late.as_ptr().cast(), late.len(), 0) };
}

/// Two connected datagram sockets of `family`: `AF_UNIX`, or `AF_INET`
/// over loopback.
fn datagram_pair(p: &Probe, family: c_int) -> [c_int; 2] {
    if family == AF_UNIX {
        let (r, pair) = p.socketpair(AF_UNIX, SOCK_DGRAM, 0);
        p.require("datagram socketpair", r == 0);
        return pair;
    }
    let [a, b] = [0; 2].map(|_| p.socket(AF_INET, SOCK_DGRAM, 0));
    p.require("udp sockets", a >= 0 && b >= 0);
    for fd in [a, b] {
        p.require("bind", p.bind_to(fd, &SockAddr::v4(0)) == 0);
    }
    let name = |fd| p.name_of(fd, false, 128).1.expect("getsockname");
    let (at_a, at_b) = (name(a), name(b));
    p.require("connect a", p.connect_to(a, &at_b) == 0);
    p.require("connect b", p.connect_to(b, &at_a) == 0);
    [a, b]
}

/// A datagram pair of `family` with "one" queued for `a`, interrupted in a
/// two-message `recvmmsg`: answers the call's result and the next two
/// receives.
fn one_of_two(p: &Probe, main_tid: pid_t, pid: pid_t, family: c_int, rcvtimeo: bool) -> [i64; 3] {
    let [a, b] = datagram_pair(p, family);
    if rcvtimeo {
        p.check(
            "set SO_RCVTIMEO to 5 s",
            p.setsockopt_bytes(a, SOL_SOCKET, SO_RCVTIMEO, &timeval(5, 0), 16, "{5, 0}") == 0,
        );
    }
    p.check("queue one datagram", p.send(b, b"one", 0) == 3);
    let (n, got) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then_send(p, main_tid, pid, b, b"two"));
        p.recvmmsg(a, &[8, 8], 0, None)
    });
    p.check(
        "the datagram received before the interruption is answered",
        n != 1 || got[0].data == b"one",
    );
    let (pending, _) = p.recv(a, 8, MSG_DONTWAIT);
    let (next, _) = p.recv(a, 8, MSG_DONTWAIT);
    p.close(a);
    p.close(b);
    [n, pending, next]
}

pub fn run(p: &Probe) {
    support::reset();
    let pid = p.getpid() as pid_t;
    let main_tid = support::gettid();

    support::install(SIGUSR1, SA_RESTART, false);
    p.check(
        "interrupted after one datagram: the count, then ERESTARTSYS pending, then the later datagram",
        one_of_two(p, main_tid, pid, AF_UNIX, false) == [1, neg(ERESTARTSYS), 3],
    );
    p.check(
        "with SO_RCVTIMEO the pending error is EINTR",
        one_of_two(p, main_tid, pid, AF_UNIX, true) == [1, neg(EINTR), 3],
    );
    support::install(SIGUSR1, 0, false);
    p.check(
        "without SA_RESTART the pending error is still ERESTARTSYS",
        one_of_two(p, main_tid, pid, AF_UNIX, false) == [1, neg(ERESTARTSYS), 3],
    );
    p.check(
        "over loopback UDP the same: the pending error before the later datagram",
        one_of_two(p, main_tid, pid, AF_INET, false) == [1, neg(ERESTARTSYS), 3],
    );

    support::install(SIGUSR1, SA_RESTART, false);
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_DGRAM, 0);
    p.require("datagram socketpair", r == 0);
    let (n, got) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then_send(p, main_tid, pid, b, b"late"));
        p.recvmmsg(a, &[8], 0, Some((5, 0)))
    });
    p.check(
        "with nothing received a recvmmsg with a timeout restarts under SA_RESTART",
        n == 1 && got[0].data == b"late",
    );
    support::install(SIGUSR1, 0, false);
    let n = thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.recvmmsg(a, &[8], 0, Some((5, 0))).0
    });
    p.check(
        "with nothing received and no SA_RESTART it is EINTR",
        n == neg(EINTR),
    );
    p.close(a);
    p.close(b);
    p.check(
        "every interruption ran the handler once",
        support::count() == 6,
    );
    support::install_disposition(SIGUSR1, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/recvmmsg_interrupted",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_connect,
        Syscall::N_getsockname,
        Syscall::N_setsockopt,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_recvmmsg,
        Syscall::N_close,
        Syscall::N_kill,
    ],
    symbols: &[
        "getpid",
        "socketpair",
        "socket",
        "bind",
        "connect",
        "getsockname",
        "setsockopt",
        "send",
        "recv",
        "recvmmsg",
        "close",
        "kill",
        "sigaction",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
