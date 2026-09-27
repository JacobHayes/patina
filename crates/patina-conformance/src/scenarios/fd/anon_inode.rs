//! fd/anon_inode — what the stat family answers for a descriptor on 6.8's
//! one anonymous inode (fs/anon_inodes.c, fs/libfs.c `alloc_anon_inode`):
//! an eventfd, a timerfd, a signalfd, an epoll instance, an inotify
//! instance, a pidfd (pidfs came in 6.9) and a Landlock ruleset (in
//! sys/landlock, which needs Landlock) are files on the SAME inode, which
//! boot made:
//!
//! * `fstat` of each answers it: root's, `0600` with no file-type bits, one
//!   link, empty, on an anonymous device (major 0), made no later than the
//!   process started, and every kind the same inode on the same device;
//! * `statx` and `newfstatat` of the descriptor (`AT_EMPTY_PATH`) answer the
//!   same node, and anon_inodefs records no birth time.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, StatView};
use libc::*;
use patina_dst_syscalls::Syscall;

/// The node fields two answers about one node share.
fn same_node(a: &StatView, b: &StatView) -> bool {
    (a.kind, a.perm, a.nlink, a.size, a.uid, a.gid, a.ino, a.dev)
        == (b.kind, b.perm, b.nlink, b.size, b.uid, b.gid, b.ino, b.dev)
}

pub fn run(p: &Probe) {
    let (_, started) = p.rec.quiet(|| p.clock_gettime(CLOCK_REALTIME));
    // Time passes before the first use, so a node stamped then is later.
    std::thread::sleep(std::time::Duration::from_millis(1));
    let mut usr1 = crate::signals::empty_set();
    // SAFETY: a valid set.
    unsafe { sigaddset(&mut usr1, SIGUSR1) };
    let descriptors = [
        ("an eventfd", p.eventfd2(0, EFD_CLOEXEC)),
        ("a timerfd", p.timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)),
        ("a signalfd", p.signalfd4(-1, &usr1, SFD_CLOEXEC)),
        ("an epoll instance", p.epoll_create1(EPOLL_CLOEXEC)),
        ("an inotify instance", p.inotify_init1(IN_CLOEXEC)),
        ("a pidfd", p.pidfd_open(p.getpid() as i32, 0)),
    ];
    for (what, fd) in descriptors {
        p.require(&format!("{what} opens"), fd >= 0);
    }

    let (r, first) = p.fstat(descriptors[0].1);
    p.require("fstat of an eventfd answers", r == 0);
    let first = first.expect("an answered fstat has a view");
    p.check(
        "it is root's 0600 with no file type, one link, empty",
        first.kind == "unknown"
            && first.perm == 0o600
            && first.nlink == 1
            && first.size == 0
            && (first.uid, first.gid) == (0, 0),
    );
    p.check("on an anonymous device", major(first.dev) == 0);
    p.check(
        "made no later than the process started",
        first.mtime_ns <= started && first.ctime_ns <= started,
    );
    for (what, fd) in &descriptors[1..] {
        let (r, view) = p.fstat(*fd);
        p.check(
            &format!("fstat of {what} answers the same inode"),
            r == 0 && view.is_some_and(|view| same_node(&view, &first)),
        );
    }

    let fd = descriptors[0].1;
    let (r, view, _) = p.statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS | STATX_BTIME);
    p.check(
        "statx of the descriptor answers it too, with no birth time",
        r == 0 && view.is_some_and(|view| same_node(&view, &first) && view.btime_ns.is_none()),
    );
    let (r, view) = p.newfstatat(fd, "", AT_EMPTY_PATH);
    p.check(
        "and newfstatat of it",
        r == 0 && view.is_some_and(|view| same_node(&view, &first)),
    );

    for (_, fd) in descriptors {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fd/anon_inode",
    run,
    covers: &[
        Syscall::N_fstat,
        Syscall::N_statx,
        Syscall::N_newfstatat,
        Syscall::N_eventfd2,
        Syscall::N_timerfd_create,
        Syscall::N_signalfd4,
        Syscall::N_epoll_create1,
        Syscall::N_inotify_init1,
        Syscall::N_pidfd_open,
        Syscall::N_close,
    ],
    symbols: &[
        "fstat",
        "statx",
        "fstatat",
        "eventfd",
        "signalfd",
        "epoll_create1",
        "pidfd_open",
        "close",
    ],
    ..DEFAULTS
};
