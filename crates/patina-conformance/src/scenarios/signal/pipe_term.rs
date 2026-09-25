//! signal/pipe_term — SIGPIPE from a modeled write: with a handler installed
//! the handler runs before the write returns `EPIPE` (fs/pipe.c pipe_write:
//! send_sig(SIGPIPE) then -EPIPE, delivered on the return to user mode); on
//! a socketpair `MSG_NOSIGNAL` suppresses it (net/unix/af_unix.c) and a
//! plain send does not, and a TCP send on an unconnected socket is `EPIPE`
//! with no signal under `MSG_NOSIGNAL` (net/ipv4/tcp.c tcp_sendmsg_locked,
//! net/core/stream.c sk_stream_error); `SIG_IGN` turns it into a bare
//! `EPIPE`; and `SIG_DFL` ends the process by SIGPIPE (the `__termination`
//! line).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGPIPE, 0, false);
    let (r, fds) = p.pipe2(0);
    p.require("pipe", r == 0);
    p.close(fds[0]);
    p.check(
        "write to a reader-less pipe is EPIPE",
        p.write(fds[1], b"x") == neg(EPIPE),
    );
    p.check(
        "the SIGPIPE handler ran before the write returned",
        support::count() == 1,
    );
    p.close(fds[1]);

    let (r, pair) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("socketpair", r == 0);
    p.close(pair[1]);
    p.check(
        "MSG_NOSIGNAL send to a closed peer is EPIPE",
        p.sendto(pair[0], b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    p.check("MSG_NOSIGNAL suppressed SIGPIPE", support::count() == 1);
    p.check(
        "a plain send to a closed peer is EPIPE",
        p.sendto(pair[0], b"x", 0, None) == neg(EPIPE),
    );
    p.check("the plain send raised SIGPIPE", support::count() == 2);
    p.close(pair[0]);

    let s = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("tcp socket", s >= 0);
    p.check(
        "MSG_NOSIGNAL send on an unconnected TCP socket is EPIPE",
        p.sendto(s, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    p.check(
        "MSG_NOSIGNAL suppressed SIGPIPE on TCP",
        support::count() == 2,
    );
    p.close(s);

    support::install_disposition(SIGPIPE, SIG_IGN);
    let (r, fds) = p.pipe2(0);
    p.require("pipe", r == 0);
    p.close(fds[0]);
    p.check(
        "with SIGPIPE ignored the write is a bare EPIPE",
        p.write(fds[1], b"x") == neg(EPIPE),
    );
    p.check("no handler ran", support::count() == 2);

    support::install_disposition(SIGPIPE, SIG_DFL);
    p.require(
        "SIGPIPE is at its default disposition",
        support::disposition(SIGPIPE) == "SIG_DFL",
    );
    p.dies_by(SIGPIPE);
    p.write(fds[1], b"x");
    p.check("unreachable: a SIG_DFL SIGPIPE write returned", false);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/pipe_term",
    run,
    covers: &[
        Syscall::N_pipe2,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_socketpair,
        Syscall::N_socket,
        Syscall::N_sendto,
    ],
    symbols: &[
        "pipe2",
        "write",
        "close",
        "socketpair",
        "socket",
        "sendto",
        "sigaction",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::thread(SIGPIPE),
            Generation::thread(SIGPIPE),
            Generation::thread(SIGPIPE),
            Generation::thread(SIGPIPE),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
