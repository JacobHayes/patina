//! readiness/ppoll — ppoll over pipes and an eventfd: readiness bits, POLLHUP,
//! POLLNVAL, ignored negative descriptors, and a timed wait on the clock.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::Probe;
use libc::*;

pub fn run(p: &Probe) {
    let (r, fds) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    let [rd, wr] = fds;
    let (n, revents) = p.ppoll(&[(rd, POLLIN)], Some(0));
    p.check(
        "an empty pipe is not readable",
        n == 0 && revents == vec![0],
    );
    p.write(wr, b"x");
    let (n, revents) = p.ppoll(&[(rd, POLLIN)], Some(0));
    p.check(
        "after a write it is readable",
        n == 1 && revents == vec![POLLIN],
    );
    let (n, revents) = p.ppoll(&[(rd, POLLIN), (wr, POLLOUT)], Some(0));
    p.check(
        "both ends report",
        n == 2 && revents == vec![POLLIN, POLLOUT],
    );
    p.read(rd, 8);
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    let (n, _) = p.ppoll(&[(rd, POLLIN)], Some(2_000_000));
    p.check("a timed wait with nothing ready returns 0", n == 0);
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the timed wait advanced the clock by at least the timeout",
        after - before >= 2_000_000,
    );
    let (n, revents) = p.ppoll(&[(4000, POLLIN)], Some(0));
    p.check(
        "a closed descriptor reports POLLNVAL",
        n == 1 && revents == vec![POLLNVAL],
    );
    let (n, revents) = p.ppoll(&[(-1, POLLIN)], Some(0));
    p.check(
        "a negative descriptor is ignored",
        n == 0 && revents == vec![0],
    );
    let (n, _) = p.ppoll(&[], Some(1_000_000));
    p.check("ppoll with no descriptors is a sleep", n == 0);
    p.check("close the writer", p.close(wr) == 0);
    let (n, revents) = p.ppoll(&[(rd, POLLIN)], Some(0));
    p.check(
        "a pipe with no writer reports POLLHUP",
        n == 1 && revents == vec![POLLHUP],
    );

    let ef = p.eventfd2(0, EFD_NONBLOCK);
    p.require("eventfd2", ef >= 0);
    let (n, revents) = p.ppoll(&[(ef, POLLIN | POLLOUT)], Some(0));
    p.check(
        "a fresh eventfd is writable only",
        n == 1 && revents == vec![POLLOUT],
    );
    p.write(ef, &1u64.to_ne_bytes());
    let (n, revents) = p.ppoll(&[(ef, POLLIN | POLLOUT)], Some(0));
    p.check(
        "a written eventfd is readable and writable",
        n == 1 && revents == vec![POLLIN | POLLOUT],
    );
    p.close(ef);
    p.close(rd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/ppoll",
    run,
    covers: &[
        Syscall::N_ppoll,
        Syscall::N_pipe2,
        Syscall::N_eventfd2,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_clock_gettime,
    ],
    symbols: &[
        "ppoll",
        "pipe2",
        "eventfd",
        "read",
        "write",
        "close",
        "clock_gettime",
    ],
    ..DEFAULTS
};
