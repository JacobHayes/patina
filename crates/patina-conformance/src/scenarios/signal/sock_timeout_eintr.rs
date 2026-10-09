//! signal/sock_timeout_eintr — a socket wait with a timeout is never
//! restarted: `sock_intr_errno` answers `EINTR` for one with a finite
//! `SO_RCVTIMEO`/`SO_SNDTIMEO` and `ERESTARTSYS` (restarted under
//! `SA_RESTART`) only for one that waits forever. A receive, an accept and
//! a send with a timeout, interrupted under `SA_RESTART`, each fail `EINTR`;
//! the same receive with no timeout restarts and completes on a later send.
//! A loopback TCP receive answers the same: `EINTR` with a timeout, and
//! restarted without one.
//!
//! The receive helpers send after their kill, so a receive that wrongly
//! restarts completes instead of waiting out its timeout.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::probe::{Probe, SockAddr, neg};
use crate::scenarios::net::timeval;
use crate::signals as support;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::thread;

/// A helper that interrupts the main thread's wait, then sends `late` to `fd`.
fn interrupt_then_send(p: &Probe, main_tid: pid_t, pid: pid_t, fd: c_int, late: &[u8]) {
    support::kill_when_parked(p, main_tid, pid, SIGUSR1);
    support::short_pause();
    unsafe { send(fd, late.as_ptr().cast(), late.len(), 0) };
}

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_RESTART, false);
    let pid = p.getpid() as pid_t;
    let main_tid = support::gettid();
    let five = timeval(5, 0);

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("stream socketpair", r == 0);
    p.check(
        "set SO_RCVTIMEO to 5 s",
        p.setsockopt_bytes(a, SOL_SOCKET, SO_RCVTIMEO, &five, 16, "{5, 0}") == 0,
    );
    let (n, _) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then_send(p, main_tid, pid, b, b"late"));
        p.recv(a, 8, 0)
    });
    p.check(
        "a receive with SO_RCVTIMEO is EINTR even under SA_RESTART",
        n == neg(EINTR),
    );
    p.close(a);
    p.close(b);

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("stream socketpair", r == 0);
    let (n, data) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then_send(p, main_tid, pid, b, b"late"));
        p.recv(a, 8, 0)
    });
    p.check(
        "a receive with no timeout restarts under SA_RESTART and completes on the later send",
        n == 4 && data == b"late",
    );
    p.close(a);
    p.close(b);

    let l = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("tcp listener", l >= 0);
    p.require("bind", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.require("listen", p.listen(l, 1) == 0);
    let (r, at, _) = p.name_of(l, false, 128);
    p.require("getsockname", r == 0 && at.is_some());
    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("tcp client", c >= 0);
    p.require("connect", p.connect_to(c, &at.unwrap()) == 0);
    let (s, _) = p.accept_from(l, 0, false, false);
    p.require("accept", s >= 0);
    let (n, data) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then_send(p, main_tid, pid, c, b"late"));
        p.recv(s, 8, 0)
    });
    p.check(
        "a TCP receive with no timeout restarts under SA_RESTART and completes on the later send",
        n == 4 && data == b"late",
    );
    p.check(
        "set the TCP socket's SO_RCVTIMEO to 5 s",
        p.setsockopt_bytes(s, SOL_SOCKET, SO_RCVTIMEO, &five, 16, "{5, 0}") == 0,
    );
    let (n, _) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then_send(p, main_tid, pid, c, b"late"));
        p.recv(s, 8, 0)
    });
    p.check(
        "a TCP receive with SO_RCVTIMEO is EINTR even under SA_RESTART",
        n == neg(EINTR),
    );
    for fd in [s, c, l] {
        p.close(fd);
    }

    let listener = p.socket(AF_UNIX, SOCK_STREAM, 0);
    p.require("socket", listener >= 0);
    let path = p.unix_path("timeout.sock");
    p.require(
        "bind",
        p.bind_to(listener, &SockAddr::UnixPath(path.clone())) == 0,
    );
    p.require("listen", p.listen(listener, 1) == 0);
    p.check(
        "set the listener's SO_RCVTIMEO to 5 s",
        p.setsockopt_bytes(listener, SOL_SOCKET, SO_RCVTIMEO, &five, 16, "{5, 0}") == 0,
    );
    let (accepted, _) = thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.accept_from(listener, 0, false, false)
    });
    p.check(
        "an accept with SO_RCVTIMEO is EINTR even under SA_RESTART",
        i64::from(accepted) == neg(EINTR),
    );
    p.close(listener);
    p.unlink(&path);

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("stream socketpair", r == 0);
    let chunk = [0u8; 4096];
    p.rec.quiet(|| while p.send(a, &chunk, MSG_DONTWAIT) > 0 {});
    p.check(
        "set SO_SNDTIMEO to 5 s",
        p.setsockopt_bytes(a, SOL_SOCKET, SO_SNDTIMEO, &five, 16, "{5, 0}") == 0,
    );
    let n = thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.send(a, b"x", 0)
    });
    p.check(
        "a send with SO_SNDTIMEO into a full buffer is EINTR even under SA_RESTART",
        n == neg(EINTR),
    );
    p.close(a);
    p.close(b);
    p.check(
        "every interrupted wait ran the handler once",
        support::count() == 6,
    );
    support::install_disposition(SIGUSR1, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/sock_timeout_eintr",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_accept4,
        Syscall::N_connect,
        Syscall::N_getsockname,
        Syscall::N_setsockopt,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_close,
        Syscall::N_kill,
    ],
    symbols: &[
        "getpid",
        "socketpair",
        "socket",
        "bind",
        "listen",
        "accept4",
        "connect",
        "getsockname",
        "setsockopt",
        "send",
        "recv",
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
