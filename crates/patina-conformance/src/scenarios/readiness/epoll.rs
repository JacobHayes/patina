//! readiness/epoll — epoll_create1 / epoll_ctl / epoll_wait / eventfd2:
//! interest-list errnos, level- vs edge-triggered delivery, EPOLLONESHOT,
//! counter and semaphore eventfds, pipe readiness and HUP, and a timed wait on
//! the clock.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let ep = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("epoll_create1", ep >= 0);
    p.check(
        "epoll_create1 with an unknown flag is EINVAL",
        i64::from(p.epoll_create1(0x1234)) == neg(EINVAL),
    );
    let ef = p.eventfd2(0, EFD_NONBLOCK | EFD_CLOEXEC);
    p.require("eventfd2", ef >= 0);
    p.check(
        "eventfd2 with an unknown flag is EINVAL",
        i64::from(p.eventfd2(0, 0x1234)) == neg(EINVAL),
    );

    p.check(
        "EPOLL_CTL_ADD",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ef, EPOLLIN as u32, 7) == 0,
    );
    p.check(
        "adding twice is EEXIST",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ef, EPOLLIN as u32, 7) == neg(EEXIST),
    );
    p.check(
        "EPOLL_CTL_MOD",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, (EPOLLIN | EPOLLOUT) as u32, 8) == 0,
    );
    let (n, events) = p.epoll_wait(ep, 8, 0);
    p.check(
        "a fresh counter eventfd is writable, not readable",
        n == 1 && events == vec![(8, EPOLLOUT as u32)],
    );
    p.check(
        "MOD back to EPOLLIN",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, EPOLLIN as u32, 7) == 0,
    );
    p.check(
        "nothing ready: timeout 0 returns 0",
        p.epoll_wait(ep, 8, 0).0 == 0,
    );
    p.check(
        "write 1 to the eventfd",
        p.write(ef, &1u64.to_ne_bytes()) == 8,
    );
    let (n, events) = p.epoll_wait(ep, 8, 0);
    p.check(
        "the eventfd is readable with its data",
        n == 1 && events == vec![(7, EPOLLIN as u32)],
    );
    p.check(
        "level-triggered: reported again",
        p.epoll_wait(ep, 8, 0).0 == 1,
    );
    let (n, data) = p.read(ef, 8);
    p.check(
        "read returns the counter and resets it",
        n == 8 && data == 1u64.to_ne_bytes(),
    );
    p.check("drained: not reported", p.epoll_wait(ep, 8, 0).0 == 0);
    p.check(
        "a non-blocking read of an empty eventfd is EAGAIN",
        p.read(ef, 8).0 == neg(EAGAIN),
    );
    p.check(
        "a short eventfd read is EINVAL",
        p.read(ef, 4).0 == neg(EINVAL),
    );
    p.check(
        "writing u64::MAX is EINVAL",
        p.write(ef, &u64::MAX.to_ne_bytes()) == neg(EINVAL),
    );
    p.write(ef, &3u64.to_ne_bytes());
    p.write(ef, &2u64.to_ne_bytes());
    let (n, data) = p.read(ef, 8);
    p.check(
        "writes accumulate into the counter",
        n == 8 && data == 5u64.to_ne_bytes(),
    );

    p.check(
        "MOD to edge-triggered",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, (EPOLLIN | EPOLLET) as u32, 7) == 0,
    );
    p.write(ef, &1u64.to_ne_bytes());
    p.check(
        "edge-triggered: reported once",
        p.epoll_wait(ep, 8, 0).0 == 1,
    );
    p.check(
        "edge-triggered: not reported again without a new edge",
        p.epoll_wait(ep, 8, 0).0 == 0,
    );
    p.write(ef, &1u64.to_ne_bytes());
    p.check(
        "edge-triggered: a new write without draining is a new edge",
        p.epoll_wait(ep, 8, 0).0 == 1,
    );
    p.read(ef, 8);
    p.check(
        "MOD back to level-triggered",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, EPOLLIN as u32, 7) == 0,
    );

    p.check(
        "EPOLL_CTL_DEL",
        p.epoll_ctl(ep, EPOLL_CTL_DEL, ef, 0, 0) == 0,
    );
    p.check(
        "deleting twice is ENOENT",
        p.epoll_ctl(ep, EPOLL_CTL_DEL, ef, 0, 0) == neg(ENOENT),
    );
    p.check(
        "MOD of an unregistered descriptor is ENOENT",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, EPOLLIN as u32, 7) == neg(ENOENT),
    );
    p.check(
        "an unknown op is EINVAL",
        p.epoll_ctl(ep, 99, ef, EPOLLIN as u32, 7) == neg(EINVAL),
    );
    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o640);
    p.require("open a regular file", file >= 0);
    p.check(
        "adding the epoll descriptor to itself is EINVAL",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ep, EPOLLIN as u32, 1) == neg(EINVAL),
    );
    p.check(
        "adding a closed descriptor is EBADF",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, 4000, EPOLLIN as u32, 1) == neg(EBADF),
    );
    p.check(
        "epoll_ctl on a non-epoll descriptor is EINVAL",
        p.epoll_ctl(ef, EPOLL_CTL_ADD, ep, EPOLLIN as u32, 1) == neg(EINVAL),
    );
    p.check(
        "a non-epoll descriptor with an unpollable target is EPERM",
        p.epoll_ctl(ef, EPOLL_CTL_ADD, file, EPOLLIN as u32, 1) == neg(EPERM),
    );
    p.check(
        "epoll_wait with maxevents 0 is EINVAL",
        p.epoll_wait(ep, 0, 0).0 == neg(EINVAL),
    );
    p.check(
        "epoll_wait on a closed descriptor is EBADF",
        p.epoll_wait(4000, 8, 0).0 == neg(EBADF),
    );
    p.check(
        "epoll_wait on a non-epoll descriptor is EINVAL",
        p.epoll_wait(ef, 8, 0).0 == neg(EINVAL),
    );

    let es = p.eventfd2(3, EFD_SEMAPHORE | EFD_NONBLOCK);
    p.require("semaphore eventfd", es >= 0);
    let mut ones = 0;
    for _ in 0..3 {
        let (n, data) = p.read(es, 8);
        ones += i32::from(n == 8 && data == 1u64.to_ne_bytes());
    }
    p.check("EFD_SEMAPHORE hands out one unit per read", ones == 3);
    p.check(
        "the semaphore is empty afterwards",
        p.read(es, 8).0 == neg(EAGAIN),
    );

    let (r, fds) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    let [rd, wr] = fds;
    p.check(
        "ADD the pipe read end",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN as u32, 1) == 0,
    );
    p.check(
        "ADD the pipe write end",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, wr, EPOLLOUT as u32, 2) == 0,
    );
    let (n, events) = p.epoll_wait(ep, 8, 0);
    p.check(
        "an empty pipe: only the writer is ready",
        n == 1 && events == vec![(2, EPOLLOUT as u32)],
    );
    p.write(wr, b"x");
    let (n, events) = p.epoll_wait(ep, 8, 0);
    p.check(
        "after a write both ends are ready",
        n == 2 && events == vec![(1, EPOLLIN as u32), (2, EPOLLOUT as u32)],
    );
    let (n, events) = p.epoll_wait(ep, 1, 0);
    p.check("maxevents caps the delivery", n == 1 && events.len() == 1);
    p.check("close the writer", p.close(wr) == 0);
    let (n, events) = p.epoll_wait(ep, 8, 0);
    p.check(
        "closing the writer removes its interest and hangs up the reader",
        n == 1 && events == vec![(1, (EPOLLIN | EPOLLHUP) as u32)],
    );
    p.read(rd, 8);
    let (n, events) = p.epoll_wait(ep, 8, 0);
    p.check(
        "a drained hung-up pipe still reports EPOLLHUP",
        n == 1 && events == vec![(1, EPOLLHUP as u32)],
    );
    p.check(
        "DEL the reader",
        p.epoll_ctl(ep, EPOLL_CTL_DEL, rd, 0, 0) == 0,
    );

    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "a timed wait with nothing ready returns 0",
        p.epoll_wait(ep, 8, 2).0 == 0,
    );
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the timed wait advanced the clock by at least the timeout",
        after - before >= 2_000_000,
    );
    for fd in [es, rd] {
        p.close(fd);
    }
    // Last on purpose: a runtime that traps on a regular-file interest or on
    // EPOLLONESHOT dies here, after everything above has been recorded.
    p.check(
        "adding a regular file is EPERM",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, file, EPOLLIN as u32, 1) == neg(EPERM),
    );
    p.check(
        "ADD the eventfd back",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ef, EPOLLIN as u32, 7) == 0,
    );
    p.check(
        "MOD to EPOLLONESHOT",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, (EPOLLIN | EPOLLONESHOT) as u32, 7) == 0,
    );
    p.write(ef, &1u64.to_ne_bytes());
    p.check("oneshot: reported once", p.epoll_wait(ep, 8, 0).0 == 1);
    p.check(
        "oneshot: disarmed until re-armed",
        p.epoll_wait(ep, 8, 0).0 == 0,
    );
    p.check(
        "re-arm with MOD",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, ef, EPOLLIN as u32, 7) == 0,
    );
    p.check("re-armed: reported", p.epoll_wait(ep, 8, 0).0 == 1);
    p.close(file);
    p.close(ef);
    p.close(ep);
    p.check(
        "epoll_wait on the closed epoll descriptor is EBADF",
        p.epoll_wait(ep, 8, 0).0 == neg(EBADF),
    );

    // Zero creation flags must preserve readiness and caller userdata too.
    let ef = p.eventfd2(0, 0);
    p.require("zero-flags eventfd2", ef >= 0);
    let ep = p.epoll_create1(0);
    p.require("zero-flags epoll_create1", ep >= 0);
    p.check(
        "zero-flags EPOLL_CTL_ADD",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ef, EPOLLIN as u32, 0xC0FFEE) == 0,
    );
    p.check(
        "zero-flags eventfd write",
        p.write(ef, &1u64.to_ne_bytes()) == 8,
    );
    let (n, events) = p.epoll_wait(ep, 4, 0);
    p.check(
        "zero-flags eventfd readiness preserves data",
        n == 1 && events == vec![(0xC0FFEE, EPOLLIN as u32)],
    );
    p.close(ef);
    p.close(ep);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/epoll",
    run,
    covers: &[
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_wait,
        Syscall::N_eventfd2,
        Syscall::N_pipe2,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_openat,
        Syscall::N_clock_gettime,
    ],
    symbols: &[
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "eventfd",
        "pipe2",
        "read",
        "write",
        "close",
        "openat",
        "clock_gettime",
    ],
    ..DEFAULTS
};
