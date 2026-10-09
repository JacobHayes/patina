//! signal/partial_progress — a blocking transfer that a handler interrupts
//! after part of it moved answers what moved, even under `SA_RESTART`: the
//! kernel restarts only a call that transferred nothing (`pipe_write`'s
//! `if (!ret) ret = -ERESTARTSYS`, `unix_stream_sendmsg`'s `sent ? : err`,
//! `unix_stream_read_generic`'s `copied ? : err` for `MSG_WAITALL`). A
//! `sendmmsg` whose message went only in part answers that message and
//! ends there (`msg_data_left`).
//!
//! Each helper, after its kill, waits for the call to return and then keeps
//! the other side moving (it drains the pipe or socket to end-of-file, or
//! sends the rest of what `MSG_WAITALL` waits for); its wait is bounded, so a
//! call that wrongly restarts completes with the whole length instead of
//! hanging. A stream send's partial count depends on the host's socket
//! buffer, so only its relation to the length is observed.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::probe::{Outgoing, Probe};
use crate::signals as support;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Read `fd` until end-of-file, unobserved.
fn drain(fd: c_int) {
    let mut buf = [0u8; 4096];
    while unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
}

/// Once the main thread is parked, interrupt it; once its call returned (or
/// the bounded wait ends), run `then`.
fn interrupt_then(
    p: &Probe,
    main_tid: pid_t,
    pid: pid_t,
    returned: &AtomicBool,
    then: impl FnOnce(),
) {
    support::kill_when_parked(p, main_tid, pid, SIGUSR1);
    support::wait_until(Duration::from_millis(1), || returned.load(Ordering::SeqCst));
    then();
}

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_RESTART, false);
    let pid = p.getpid() as pid_t;
    let main_tid = support::gettid();
    let big = vec![0x5a_u8; 1 << 20];

    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe", r == 0);
    let capacity = p.fcntl(wr, F_GETPIPE_SZ, 0);
    p.require("the pipe's capacity is below the write", (1..100_000).contains(&capacity));
    let returned = AtomicBool::new(false);
    let wrote = thread::scope(|scope| {
        scope.spawn(|| interrupt_then(p, main_tid, pid, &returned, || drain(rd)));
        let wrote = p.write(wr, &big[..100_000]);
        returned.store(true, Ordering::SeqCst);
        p.close(wr);
        wrote
    });
    p.check(
        "a pipe write a handler interrupts after it filled the pipe answers the bytes written",
        wrote == capacity,
    );
    p.close(rd);

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("stream socketpair", r == 0);
    let returned = AtomicBool::new(false);
    let sent = thread::scope(|scope| {
        scope.spawn(|| interrupt_then(p, main_tid, pid, &returned, || drain(b)));
        let sent = p.rec.quiet(|| p.send(a, &big, 0));
        returned.store(true, Ordering::SeqCst);
        p.shutdown(a, SHUT_WR);
        sent
    });
    p.check(
        "a stream send a handler interrupts after it filled the buffer answers the bytes sent",
        sent > 0 && (sent as usize) < big.len(),
    );
    p.close(a);
    p.close(b);

    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("stream socketpair", r == 0);
    p.check("queue three bytes", p.send(b, b"xyz", 0) == 3);
    let returned = AtomicBool::new(false);
    let (n, data) = thread::scope(|scope| {
        scope.spawn(|| {
            interrupt_then(p, main_tid, pid, &returned, || unsafe {
                send(b, b"4567890".as_ptr().cast(), 7, 0);
            })
        });
        let received = p.recv(a, 10, MSG_WAITALL);
        returned.store(true, Ordering::SeqCst);
        received
    });
    p.check(
        "a MSG_WAITALL receive a handler interrupts answers the bytes it had",
        n == 3 && data == b"xyz",
    );
    p.close(a);
    p.close(b);
    let (r, [a, b]) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    p.require("stream socketpair", r == 0);
    let returned = AtomicBool::new(false);
    let (n, lens) = thread::scope(|scope| {
        scope.spawn(|| interrupt_then(p, main_tid, pid, &returned, || drain(b)));
        let batch = [
            Outgoing {
                data: &big,
                to: None,
            },
            Outgoing {
                data: b"tail",
                to: None,
            },
        ];
        let sent = p.rec.quiet(|| p.sendmmsg(a, &batch, 0));
        returned.store(true, Ordering::SeqCst);
        p.shutdown(a, SHUT_WR);
        sent
    });
    p.check(
        "a sendmmsg whose first message a handler interrupted answers that message alone",
        n == 1 && lens[0] > 0 && (lens[0] as usize) < big.len(),
    );
    p.close(a);
    p.close(b);
    p.check(
        "every interrupted transfer ran the handler once",
        support::count() == 4,
    );
    support::install_disposition(SIGUSR1, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/partial_progress",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_pipe2,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_fcntl,
        Syscall::N_socketpair,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_sendmmsg,
        Syscall::N_shutdown,
        Syscall::N_kill,
    ],
    symbols: &[
        "getpid",
        "pipe2",
        "write",
        "close",
        "fcntl",
        "socketpair",
        "send",
        "recv",
        "sendmmsg",
        "shutdown",
        "kill",
        "sigaction",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
