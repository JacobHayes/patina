//! readiness/inotify — an inotify instance as a readiness source (inotify(7),
//! epoll(7); fs/notify/inotify/inotify_user.c `inotify_poll`): the rows
//! themselves are fs/inotify's; this is the reactor side.
//!
//! * with nothing queued the instance is neither readable to `ppoll`,
//!   `pselect6` nor `epoll`;
//! * a queued event makes it readable to all three (level-triggered: again
//!   and again until read);
//! * an edge-triggered interest reports one queued event once, and a second
//!   event queued before any read is a new edge;
//! * reading every queued event makes it quiet again.
//!
//! Needs an inotify instance and watch within the caller's limits.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{AT_FDCWD, Probe, SIGSET_BYTES, Sets};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let root = p.dir();
    let fd = p.inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    p.require("an inotify instance", fd >= 0);
    p.check(
        "watch the run directory for creations",
        p.inotify_add_watch(fd, &root, IN_CREATE) > 0,
    );
    let ep = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("an epoll instance", ep >= 0);
    p.check(
        "watch the instance level-triggered",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, fd, EPOLLIN as u32, 1) == 0,
    );
    let read_set = Sets {
        read: &[fd],
        ..Sets::default()
    };
    let (n, _) = p.ppoll(&[(fd, POLLIN)], Some(0));
    p.check("nothing queued: ppoll reports nothing", n == 0);
    let (n, _) = p.pselect6(fd + 1, read_set, Some((0, 0)), None, SIGSET_BYTES as usize);
    p.check("nothing queued: pselect6 reports nothing", n == 0);
    p.check(
        "nothing queued: epoll reports nothing",
        p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize).0 == 0,
    );

    let a = p.openat(AT_FDCWD, &format!("{root}/a"), O_WRONLY | O_CREAT, 0o600);
    p.require("create a file", a >= 0);
    p.close(a);
    let (n, revents) = p.ppoll(&[(fd, POLLIN)], Some(0));
    p.check(
        "a queued event: ppoll reports POLLIN",
        n == 1 && revents == vec![POLLIN],
    );
    let (n, ready) = p.pselect6(fd + 1, read_set, Some((0, 0)), None, SIGSET_BYTES as usize);
    p.check(
        "a queued event: pselect6 reports it readable",
        n == 1 && ready.read == [true],
    );
    let (n, events) = p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize);
    p.check(
        "a queued event: epoll reports EPOLLIN",
        n == 1 && events == vec![(1, EPOLLIN as u32)],
    );
    p.check(
        "level-triggered: again",
        p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize).0 == 1,
    );
    let (n, _) = p.inotify_read(fd, 4096);
    p.check("read the queued event", n > 0);
    p.check(
        "drained: epoll reports nothing",
        p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize).0 == 0,
    );

    p.check(
        "watch it edge-triggered",
        p.epoll_ctl(ep, EPOLL_CTL_MOD, fd, (EPOLLIN | EPOLLET) as u32, 1) == 0,
    );
    let b = p.openat(AT_FDCWD, &format!("{root}/b"), O_WRONLY | O_CREAT, 0o600);
    p.require("create another file", b >= 0);
    p.close(b);
    p.check(
        "edge-triggered: the event is an edge",
        p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize).0 == 1,
    );
    p.check(
        "reported once",
        p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize).0 == 0,
    );
    let c = p.openat(AT_FDCWD, &format!("{root}/c"), O_WRONLY | O_CREAT, 0o600);
    p.require("create a third file", c >= 0);
    p.close(c);
    p.check(
        "a second event before any read is a new edge",
        p.epoll_pwait(ep, 4, 0, None, SIGSET_BYTES as usize).0 == 1,
    );
    let (n, events) = p.inotify_read(fd, 4096);
    p.check("both events are read at once", n > 0 && events.len() == 2);
    let (n, _) = p.ppoll(&[(fd, POLLIN)], Some(0));
    p.check("drained: quiet again", n == 0);
    p.close(ep);
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/inotify",
    run,
    covers: &[
        Syscall::N_inotify_init1,
        Syscall::N_inotify_add_watch,
        Syscall::N_read,
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        Syscall::N_epoll_pwait,
        Syscall::N_ppoll,
        Syscall::N_pselect6,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "ppoll",
        "pselect",
        "openat",
        "close",
    ],
    needs: &[Need::Inotify],
    ..DEFAULTS
};
