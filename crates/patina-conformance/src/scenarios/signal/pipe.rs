//! signal/pipe — SIGPIPE default action for pipe writes, ignored SIGPIPE turning
//! the write into EPIPE, and MSG_NOSIGNAL suppressing SIGPIPE on socket sends.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use crate::vehicle::fold_errno;
use libc::*;

fn default_sigpipe_status(p: &Probe) -> c_int {
    let mut fds = [0; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let child = p.fork_child(
        || fold_errno(unsafe { fork() } as i64),
        || unsafe {
            close(fds[0]);
            signal(SIGPIPE, SIG_DFL);
            let _ = write(fds[1], b"x".as_ptr() as *const _, 1);
            99
        },
    );
    unsafe {
        close(fds[0]);
        close(fds[1]);
    }
    child.wait()
}

pub fn run(p: &Probe) {
    let status = default_sigpipe_status(p);
    p.rec
        .event("wait_status", 0)
        .arg("case", "SIGPIPE")
        .field("signaled", WIFSIGNALED(status))
        .field("termsig", WTERMSIG(status))
        .field("core", WCOREDUMP(status))
        .emit();
    p.check(
        "default SIGPIPE terminates without core",
        WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE && !WCOREDUMP(status),
    );

    unsafe {
        signal(SIGPIPE, SIG_IGN);
    }
    let (r, fds) = p.pipe2(0);
    p.require("pipe", r == 0);
    p.close(fds[0]);
    p.check(
        "ignored SIGPIPE makes pipe write return EPIPE",
        p.write(fds[1], b"x") == neg(EPIPE),
    );
    p.close(fds[1]);

    let s = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("tcp socket", s >= 0);
    p.check(
        "MSG_NOSIGNAL makes socket send return EPIPE without a signal",
        p.sendto(s, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    p.close(s);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/pipe",
    run,
    covers: &[
        Syscall::N_pipe2,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_socket,
        Syscall::N_sendto,
    ],
    symbols: &["pipe2", "write", "close", "socket", "sendto", "signal"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "fork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: process spawn reached under patina: fork; the process class is a deterministic-runtime non-goal; failing closed",
        },
    }],
    ..DEFAULTS
};
