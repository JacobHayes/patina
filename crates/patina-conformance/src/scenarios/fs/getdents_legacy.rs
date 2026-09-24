//! fs/getdents_legacy — the x86_64 legacy getdents row (getdents(2), `struct
//! linux_dirent`: the type in each record's last byte, after the name's
//! padding; fs/readdir.c filldir): the same entry set, `.`/`..` and d_type per
//! kind as getdents64, 0 at the end, a rewind through lseek, EINVAL for a
//! buffer too small for one record, ENOTDIR for a file, EBADF for a closed
//! descriptor. The generic (arm64) table has no such row.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let fd = p.openat(
        AT_FDCWD,
        &format!("{root}/a"),
        O_WRONLY | O_CREAT | O_EXCL,
        0o640,
    );
    p.require("create a", fd >= 0);
    p.close(fd);
    p.check(
        "mkdirat sub",
        p.mkdirat(AT_FDCWD, &format!("{root}/sub"), 0o750) == 0,
    );
    p.check(
        "symlinkat l -> a",
        p.symlinkat("a", AT_FDCWD, &format!("{root}/l")) == 0,
    );
    p.check(
        "mknodat a FIFO",
        p.mknodat(AT_FDCWD, &format!("{root}/p"), S_IFIFO | 0o640, 0) == 0,
    );

    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the directory", dirfd >= 0);
    let (r, entries) = p.getdents(dirfd, 4096);
    p.check("getdents returns bytes", r > 0);
    let has = |name: &str, kind: u8| entries.iter().any(|(n, k)| n == name && *k == kind);
    p.check("the regular file is DT_REG", has("a", DT_REG));
    p.check("the subdirectory is DT_DIR", has("sub", DT_DIR));
    p.check("the symlink is DT_LNK", has("l", DT_LNK));
    p.check("the FIFO is DT_FIFO", has("p", DT_FIFO));
    p.check(
        "'.' and '..' are DT_DIR",
        has(".", DT_DIR) && has("..", DT_DIR),
    );
    p.check("every entry exactly once", entries.len() == 6);
    p.check(
        "a second call at the end returns 0",
        p.getdents(dirfd, 4096).0 == 0,
    );
    p.check("lseek rewinds", p.lseek(dirfd, 0, SEEK_SET) == 0);
    let (r, again) = p.getdents(dirfd, 4096);
    p.check(
        "after the rewind the same entries come back",
        r > 0 && again == entries,
    );
    p.lseek(dirfd, 0, SEEK_SET);
    p.check(
        "a buffer too small for one record is EINVAL",
        p.getdents(dirfd, 16).0 == neg(EINVAL),
    );
    let file = p.openat(AT_FDCWD, &format!("{root}/a"), O_RDONLY, 0);
    p.require("open a", file >= 0);
    p.check(
        "getdents on a file is ENOTDIR",
        p.getdents(file, 4096).0 == neg(ENOTDIR),
    );
    p.check(
        "getdents on a closed descriptor is EBADF",
        p.getdents(4000, 4096).0 == neg(EBADF),
    );
    p.close(file);
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/getdents_legacy",
    run,
    covers: &[
        Syscall::N_getdents,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_lseek,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_mknodat,
    ],
    symbols: &[
        "syscall",
        "openat",
        "close",
        "lseek",
        "mkdirat",
        "symlinkat",
        "mknodat",
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: Vehicle::ALL,
        what: "the legacy getdents row is unmodeled (getdents64 is): the first getdents aborts",
        failure: Failure::Stops {
            events: 9,
            ending: Ending::Signal(6),
            diagnostic: "unsupported syscall getdents",
        },
    }],
    ..DEFAULTS
};
