//! fs/getdents — getdents64 over a directory descriptor: the entry set, `.`
//! and `..`, d_type per kind, the cursor (EOF and rewind through lseek), and
//! the errno vocabulary. The libc door is glibc's `getdents64`, which the shim
//! does not define (see `crate::vehicle`).

#[cfg(target_arch = "aarch64")]
use crate::catalog::ARM64_OPEN_FLAGS;
use crate::catalog::{Arc, DEFAULTS, DISPATCHER, Gap, LIBC, RUST_PANIC, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::vehicle::GETDENTS64_UNRESOLVED;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    for name in ["a", "b"] {
        let fd = p.openat(
            AT_FDCWD,
            &format!("{root}/{name}"),
            O_WRONLY | O_CREAT | O_EXCL,
            0o640,
        );
        p.require("create file", fd >= 0);
        p.close(fd);
    }
    p.check(
        "mkdirat sub",
        p.mkdirat(AT_FDCWD, &format!("{root}/sub"), 0o750) == 0,
    );
    p.check(
        "symlinkat l -> a",
        p.symlinkat("a", AT_FDCWD, &format!("{root}/l")) == 0,
    );

    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the directory", dirfd >= 0);
    let (r, entries) = p.getdents64(dirfd, 4096);
    p.check("getdents64 returns bytes", r > 0);
    let has = |name: &str, kind: u8| entries.iter().any(|(n, k)| n == name && *k == kind);
    p.check(
        "regular files are DT_REG",
        has("a", DT_REG) && has("b", DT_REG),
    );
    p.check("the subdirectory is DT_DIR", has("sub", DT_DIR));
    p.check("the symlink is DT_LNK", has("l", DT_LNK));
    p.check(
        "'.' and '..' are listed as DT_DIR",
        has(".", DT_DIR) && has("..", DT_DIR),
    );
    p.check("every entry exactly once", entries.len() == 6);
    let (r, _) = p.getdents64(dirfd, 4096);
    p.check("a second call at the end returns 0", r == 0);
    p.check(
        "lseek to 0 rewinds the directory",
        p.lseek(dirfd, 0, SEEK_SET) == 0,
    );
    let (r, again) = p.getdents64(dirfd, 4096);
    p.check(
        "after the rewind the same entries come back",
        r > 0 && again == entries,
    );
    p.lseek(dirfd, 0, SEEK_SET);
    let (r, _) = p.getdents64(dirfd, 16);
    p.check(
        "a buffer too small for one entry is EINVAL",
        r == neg(EINVAL),
    );

    let file = p.openat(AT_FDCWD, &format!("{root}/a"), O_RDONLY, 0);
    p.require("open a", file >= 0);
    let (r, _) = p.getdents64(file, 4096);
    p.check("getdents64 on a file is ENOTDIR", r == neg(ENOTDIR));
    let (r, _) = p.getdents64(4000, 4096);
    p.check(
        "getdents64 on a closed descriptor is EBADF",
        r == neg(EBADF),
    );

    p.check(
        "unlinkat a",
        p.unlinkat(AT_FDCWD, &format!("{root}/a"), 0) == 0,
    );
    p.lseek(dirfd, 0, SEEK_SET);
    let (r, after) = p.getdents64(dirfd, 4096);
    p.check(
        "an unlinked entry is no longer listed",
        r > 0 && !after.iter().any(|(n, _)| n == "a") && after.len() == 5,
    );
    p.close(file);
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/getdents",
    run,
    covers: &[
        Syscall::N_getdents64,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_lseek,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_unlinkat,
    ],
    symbols: &[
        "getdents64",
        "openat",
        "close",
        "lseek",
        "mkdirat",
        "symlinkat",
        "unlinkat",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: LIBC,
            what: "the libc symbol getdents64 is not interposed (registry symbol row getdents64: Absent; C readdir is the only door), so the libc door does not resolve",
            failure: Failure::Stops {
                events: 9,
                ending: Ending::Exit(RUST_PANIC),
                diagnostic: GETDENTS64_UNRESOLVED,
            },
        },
        #[cfg(target_arch = "x86_64")]
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: DISPATCHER,
            what: "the getdents64 row lists no `.` or `..` entry (sud/fs.rs sys_getdents64 iterates the patina_read_dir snapshot, which has neither)",
            failure: Failure::Differs(&[
                Difference::field(
                    9,
                    "getdents64",
                    "fields.entries",
                    Observed::Json(r#"["a:8","b:8","l:10","sub:4"]"#),
                ),
                Difference::field(9, "getdents64", "ret", Observed::Int(96)),
                Difference::field(
                    20,
                    "getdents64",
                    "fields.entries",
                    Observed::Json(r#"["a:8","b:8","l:10","sub:4"]"#),
                ),
                Difference::field(20, "getdents64", "ret", Observed::Int(96)),
                Difference::field(
                    33,
                    "getdents64",
                    "fields.entries",
                    Observed::Json(r#"["b:8","l:10","sub:4"]"#),
                ),
                Difference::field(33, "getdents64", "ret", Observed::Int(72)),
                Difference::check(14, "'.' and '..' are listed as DT_DIR"),
                Difference::check(15, "every entry exactly once"),
                Difference::check(34, "an unlinked entry is no longer listed"),
            ]),
        },
        #[cfg(target_arch = "aarch64")]
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: DISPATCHER,
            what: ARM64_OPEN_FLAGS,
            failure: Failure::Differs(&[
                Difference::field(8, "openat", "errno", Observed::Str("ENOSYS")),
                Difference::field(8, "openat", "ret", Observed::Int(-1)),
            ]),
        },
        #[cfg(target_arch = "aarch64")]
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: DISPATCHER,
            what: ARM64_OPEN_FLAGS,
            failure: Failure::Stops {
                events: 9,
                ending: Ending::Exit(RUST_PANIC),
                diagnostic: "fs/getdents: cannot continue: open the directory",
            },
        },
    ],
    ..DEFAULTS
};
