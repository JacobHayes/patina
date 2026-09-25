//! fs/inotify — inotify_init / inotify_init1 / inotify_add_watch /
//! inotify_rm_watch and the events a watch delivers (inotify(7),
//! fs/notify/inotify/inotify_user.c). init1 takes IN_NONBLOCK and IN_CLOEXEC
//! and refuses any other bit (EINVAL). add_watch returns a positive watch
//! descriptor, the same one again for an inode already watched (the new mask
//! replacing the old), EEXIST for IN_MASK_CREATE on a watched inode, EINVAL
//! for IN_MASK_ADD with IN_MASK_CREATE, an empty mask, or a descriptor that is
//! not an inotify instance, ENOTDIR for IN_ONLYDIR on a file, ENOENT for a
//! missing path. Events carry the watch descriptor, the mask, a name padded
//! to a multiple of the event header (a file watch's event has none), and a
//! cookie shared by a rename's IN_MOVED_FROM/IN_MOVED_TO pair; a read with no
//! event is EAGAIN on a non-blocking instance and a buffer too small for the
//! next event is EINVAL; FIONREAD reports the bytes queued. rm_watch queues
//! IN_IGNORED and is EINVAL for a descriptor not watched; a watched
//! directory's removal queues IN_DELETE_SELF then IN_IGNORED. Needs an inotify
//! instance and watch within the caller's limits.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, IoctlArg, Probe, neg};
use libc::*;

/// The bytes one event with `name` takes: the 16-byte header and, when there
/// is a name, the name NUL-terminated and padded to a multiple of the header's
/// size (fs/notify/inotify/inotify_user.c round_event_name_len).
fn event_bytes(name: &str) -> i64 {
    const HEADER: usize = std::mem::size_of::<inotify_event>();
    let padded = if name.is_empty() {
        0
    } else {
        (name.len() + 1).div_ceil(HEADER) * HEADER
    };
    (HEADER + padded) as i64
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let watched = format!("{root}/w");
    let existing = format!("{watched}/existing");
    p.check("mkdirat w", p.mkdirat(AT_FDCWD, &watched, 0o755) == 0);
    let fd = p.openat(AT_FDCWD, &existing, O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create w/existing", fd >= 0);

    // ---- instances ---------------------------------------------------------
    #[cfg(target_arch = "x86_64")]
    {
        let legacy = p.inotify_init();
        p.check("inotify_init returns a descriptor", legacy >= 0);
        p.check(
            "inotify_init sets no descriptor flag",
            p.fcntl(legacy, F_GETFD, 0) == 0,
        );
        p.close(legacy);
    }
    let ino = p.inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    p.require("inotify_init1", ino >= 0);
    p.check(
        "IN_CLOEXEC sets FD_CLOEXEC",
        p.fcntl(ino, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.check(
        "IN_NONBLOCK sets O_NONBLOCK",
        p.fcntl(ino, F_GETFL, 0) & i64::from(O_NONBLOCK) != 0,
    );
    p.check(
        "inotify_init1 with an unknown flag is EINVAL",
        i64::from(p.inotify_init1(1)) == neg(EINVAL),
    );

    // ---- watches -----------------------------------------------------------
    let wd = p.inotify_add_watch(ino, &watched, IN_MODIFY);
    p.check("a watch descriptor is positive", wd > 0);
    let events = IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF;
    p.check(
        "watching the same inode again returns the same descriptor",
        p.inotify_add_watch(ino, &watched, events) == wd,
    );
    p.check(
        "IN_MASK_CREATE on a watched inode is EEXIST",
        i64::from(p.inotify_add_watch(ino, &watched, IN_CREATE | IN_MASK_CREATE)) == neg(EEXIST),
    );
    p.check(
        "IN_MASK_ADD with IN_MASK_CREATE is EINVAL",
        i64::from(p.inotify_add_watch(ino, &watched, IN_CREATE | IN_MASK_ADD | IN_MASK_CREATE))
            == neg(EINVAL),
    );
    p.check(
        "an empty mask is EINVAL",
        i64::from(p.inotify_add_watch(ino, &watched, 0)) == neg(EINVAL),
    );
    p.check(
        "IN_ONLYDIR on a file is ENOTDIR",
        i64::from(p.inotify_add_watch(ino, &existing, IN_MODIFY | IN_ONLYDIR)) == neg(ENOTDIR),
    );
    p.check(
        "a missing path is ENOENT",
        i64::from(p.inotify_add_watch(ino, &format!("{root}/missing"), IN_MODIFY)) == neg(ENOENT),
    );
    p.check(
        "a descriptor that is not an inotify instance is EINVAL",
        i64::from(p.inotify_add_watch(fd, &watched, IN_MODIFY)) == neg(EINVAL),
    );
    p.check(
        "a closed descriptor is EBADF",
        i64::from(p.inotify_add_watch(4000, &watched, IN_MODIFY)) == neg(EBADF),
    );
    p.check(
        "nothing queued: a non-blocking read is EAGAIN",
        p.inotify_read(ino, 4096).0 == neg(EAGAIN),
    );

    // ---- events ------------------------------------------------------------
    let new = format!("{watched}/new");
    let created = p.openat(AT_FDCWD, &new, O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create w/new", created >= 0);
    p.close(created);
    p.check(
        "renameat new -> renamed",
        p.renameat(AT_FDCWD, &new, AT_FDCWD, &format!("{watched}/renamed")) == 0,
    );
    p.check(
        "unlinkat renamed",
        p.unlinkat(AT_FDCWD, &format!("{watched}/renamed"), 0) == 0,
    );
    let queued_bytes = event_bytes("new") * 2 + event_bytes("renamed") * 2;
    let (r, queued) = p.ioctl(ino, FIONREAD, "FIONREAD", IoctlArg::Out);
    p.check(
        "FIONREAD reports the four queued events' bytes",
        r == 0 && queued.map(i64::from) == Some(queued_bytes),
    );
    p.check(
        "a buffer smaller than the next event is EINVAL",
        p.inotify_read(ino, event_bytes("new") as usize - 1).0 == neg(EINVAL),
    );
    let (r, got) = p.inotify_read(ino, 4096);
    p.check("four events' bytes", r == queued_bytes);
    let described: Vec<(u32, &str)> = got
        .iter()
        .map(|event| (event.mask, event.name.as_str()))
        .collect();
    p.check(
        "create, the rename pair, delete, in order",
        described
            == [
                (IN_CREATE, "new"),
                (IN_MOVED_FROM, "new"),
                (IN_MOVED_TO, "renamed"),
                (IN_DELETE, "renamed"),
            ],
    );
    p.check(
        "every event names the directory's watch",
        got.iter().all(|event| event.wd == wd),
    );
    p.check(
        "the rename's two halves share one nonzero cookie; the others have none",
        got.len() == 4
            && got[1].cookie != 0
            && got[1].cookie == got[2].cookie
            && got[0].cookie == 0
            && got[3].cookie == 0,
    );

    // ---- a file watch, removal ---------------------------------------------
    let file_wd = p.inotify_add_watch(ino, &existing, IN_MODIFY);
    p.check(
        "a second inode gets a second descriptor",
        file_wd > 0 && file_wd != wd,
    );
    p.check("modify w/existing", p.write(fd, b"x") == 1);
    let (r, got) = p.inotify_read(ino, 4096);
    p.check(
        "a file watch reports IN_MODIFY without a name",
        r == event_bytes("")
            && got.len() == 1
            && got[0].wd == file_wd
            && got[0].mask == IN_MODIFY
            && got[0].name.is_empty(),
    );
    p.check("inotify_rm_watch", p.inotify_rm_watch(ino, file_wd) == 0);
    let (_, got) = p.inotify_read(ino, 4096);
    p.check(
        "removing a watch queues IN_IGNORED",
        got.len() == 1 && got[0].wd == file_wd && got[0].mask == IN_IGNORED,
    );
    p.check(
        "removing it again is EINVAL",
        p.inotify_rm_watch(ino, file_wd) == neg(EINVAL),
    );
    p.check(
        "an unknown watch descriptor is EINVAL",
        p.inotify_rm_watch(ino, -1) == neg(EINVAL),
    );
    p.check(
        "rm_watch on a descriptor that is not an instance is EINVAL",
        p.inotify_rm_watch(fd, wd) == neg(EINVAL),
    );
    p.check(
        "rm_watch on a closed descriptor is EBADF",
        p.inotify_rm_watch(4000, wd) == neg(EBADF),
    );
    p.close(fd);
    p.check("unlinkat existing", p.unlinkat(AT_FDCWD, &existing, 0) == 0);
    p.check(
        "unlinkat the watched directory",
        p.unlinkat(AT_FDCWD, &watched, AT_REMOVEDIR) == 0,
    );
    let (_, got) = p.inotify_read(ino, 4096);
    let masks: Vec<u32> = got.iter().map(|event| event.mask).collect();
    p.check(
        "the directory's removal: IN_DELETE of its entry, IN_DELETE_SELF, IN_IGNORED",
        masks == [IN_DELETE, IN_DELETE_SELF, IN_IGNORED] && got.iter().all(|event| event.wd == wd),
    );
    p.close(ino);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/inotify",
    run,
    // The shim defines none of the inotify wrappers, so their libc spelling
    // would be `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_inotify_init,
        Syscall::N_inotify_init1,
        Syscall::N_inotify_add_watch,
        Syscall::N_inotify_rm_watch,
        Syscall::N_read,
        Syscall::N_ioctl,
        Syscall::N_fcntl,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_renameat,
        Syscall::N_unlinkat,
        Syscall::N_mkdirat,
        Syscall::N_close,
    ],
    needs: &[Need::Inotify],
    kernel_floor: Some(KernelFloor {
        release: "4.18",
        why: "IN_MASK_CREATE",
    }),
    gaps: &[
        #[cfg(target_arch = "x86_64")]
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::KERNEL,
            what: "the inotify rows are unmodeled Trap rows (the readiness arc models them over the reactor): the first inotify_init aborts",
            failure: Failure::Stops {
                events: 3,
                ending: Ending::Signal(6),
                diagnostic: "unsupported syscall inotify_init",
            },
        },
        #[cfg(not(target_arch = "x86_64"))]
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::KERNEL,
            what: "the inotify rows are unmodeled Trap rows (the readiness arc models them over the reactor): the first inotify_init1 aborts",
            failure: Failure::Stops {
                events: 3,
                ending: Ending::Signal(6),
                diagnostic: "unsupported syscall inotify_init1",
            },
        },
    ],
    ..DEFAULTS
};
