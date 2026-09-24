//! fs/statvfs — glibc's POSIX filesystem statistics, `statvfs`/`fstatvfs`
//! and their large-file spellings `statvfs64`/`fstatvfs64` (glibc sysdeps/unix/sysv/linux/statvfs.c, internal_statvfs.c:
//! statfs(2) converted to `struct statvfs`). The sizes and counts are the
//! host filesystem's business, so they are checked by relation: by path and
//! by descriptor they describe one filesystem alike, and agree with
//! `statfs` (block and fragment size, block count, `f_namemax` =
//! `f_namelen`, `f_fsid` = statfs's two `f_fsid` words packed high:low as
//! glibc's internal_statvfs.c packs them); the kernel's own answers compare
//! exactly: `f_namemax` is NAME_MAX and `ST_RDONLY` is clear. The
//! descriptor spelling accepts an `O_PATH` descriptor (fstatfs(2) resolves
//! it with `fdget_raw`). A missing name is ENOENT, a path through a file
//! ENOTDIR, a closed descriptor EBADF.
//!
//! libc only, and through `dlsym`: the registry lists the symbols `Absent`
//! (the shim does not define them), so the probe binary cannot import them
//! (the pre-run audit would refuse the whole binary). Under patina `dlsym`
//! finds none: the shim's `__wrap_dlsym` routes only its entropy names.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{AT_FDCWD, Probe, Statfs, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

type StatvfsFn = unsafe extern "C" fn(*const c_char, *mut statvfs64) -> c_int;
type FstatvfsFn = unsafe extern "C" fn(c_int, *mut statvfs64) -> c_int;

/// What the path and descriptor spellings name.
enum By<'a> {
    Path(&'a str),
    Fd(i32),
}

/// One call, recorded with the members every filesystem answers alike.
fn call(p: &Probe, op: &str, f: (StatvfsFn, FstatvfsFn), by: By<'_>) -> (i64, statvfs64) {
    // SAFETY: an all-zero statvfs64 is a valid value.
    let mut st: statvfs64 = unsafe { std::mem::zeroed() };
    let r = match by {
        By::Path(path) => {
            let c = std::ffi::CString::new(path).expect("no interior NUL");
            // SAFETY: a NUL-terminated path and a live statvfs64.
            unsafe { (f.0)(c.as_ptr(), &mut st) }
        }
        // SAFETY: a live statvfs64.
        By::Fd(fd) => unsafe { (f.1)(fd, &mut st) },
    };
    let r = fold_errno(r.into());
    let builder = p.rec.event(op, r);
    let builder = match by {
        By::Path(path) => builder.arg("path", path),
        By::Fd(fd) => builder
            .arg("fd", fd)
            .norm("args.fd", crate::observe::Norm::Relative("fd")),
    };
    let builder = if r == 0 {
        builder
            .field("namemax", st.f_namemax)
            .field("rdonly", st.f_flag & ST_RDONLY != 0)
    } else {
        builder
    };
    builder.emit();
    (r, st)
}

/// statfs's two `f_fsid` words as glibc packs them into `statvfs`'s one
/// (internal_statvfs.c: the second word high, the first low; verified on
/// glibc 2.39 over ext4, whose second word is non-zero).
fn packed_fsid(fs: &Statfs) -> u64 {
    (u64::from(fs.f_fsid[1] as u32) << 32) | u64::from(fs.f_fsid[0] as u32)
}

/// The members one filesystem's statistics keep between two calls.
fn identity(st: &statvfs64) -> (u64, u64, u64, u64, u64) {
    (
        st.f_bsize,
        st.f_frsize,
        st.f_blocks,
        st.f_fsid,
        st.f_namemax,
    )
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    let location = p.openat(AT_FDCWD, &root, O_PATH | O_DIRECTORY, 0);
    p.require("open the run directory O_PATH", location >= 0);
    let (r, fs) = p.statfs(&root, false);
    p.require("statfs the run directory", r == 0);
    let fs: Statfs = fs.unwrap();

    let found: Vec<_> = ["statvfs", "fstatvfs", "statvfs64", "fstatvfs64"]
        .iter()
        .map(|symbol| p.resolve(symbol))
        .collect();
    p.require(
        "the statvfs symbols resolve",
        found.iter().all(Option::is_some),
    );
    // SAFETY: glibc's definitions, by their documented types (on a 64-bit
    // target `struct statvfs` is `struct statvfs64`).
    let pair = |at: usize| unsafe {
        (
            std::mem::transmute::<*mut c_void, StatvfsFn>(found[at].unwrap()),
            std::mem::transmute::<*mut c_void, FstatvfsFn>(found[at + 1].unwrap()),
        )
    };
    for (by_name, by_fd_name, f) in [
        ("statvfs", "fstatvfs", pair(0)),
        ("statvfs64", "fstatvfs64", pair(2)),
    ] {
        let (r, by_path) = call(p, by_name, f, By::Path(&root));
        p.check(
            &format!("{by_name}: f_namemax is NAME_MAX and ST_RDONLY is clear"),
            r == 0 && by_path.f_namemax == NAME_MAX as u64 && by_path.f_flag & ST_RDONLY == 0,
        );
        p.check(
            &format!("{by_name}: the path's statistics agree with statfs"),
            r == 0
                && by_path.f_bsize == fs.f_bsize as u64
                && by_path.f_frsize == fs.f_frsize as u64
                && by_path.f_blocks == fs.f_blocks
                && by_path.f_namemax == fs.f_namelen as u64
                && by_path.f_fsid == packed_fsid(&fs),
        );
        let (r, by_fd) = call(p, by_fd_name, f, By::Fd(fd));
        p.check(
            &format!("{by_fd_name}: the descriptor's describe the same filesystem"),
            r == 0 && identity(&by_fd) == identity(&by_path),
        );
        let (r, by_location) = call(p, by_fd_name, f, By::Fd(location));
        p.check(
            &format!("{by_fd_name}: an O_PATH descriptor's too"),
            r == 0 && identity(&by_location) == identity(&by_path),
        );
        p.check(
            &format!("{by_name}: a missing name is ENOENT"),
            call(p, by_name, f, By::Path(&format!("{root}/missing"))).0 == neg(ENOENT),
        );
        p.check(
            &format!("{by_name}: a path through a file is ENOTDIR"),
            call(p, by_name, f, By::Path(&format!("{file}/x"))).0 == neg(ENOTDIR),
        );
        p.check(
            &format!("{by_fd_name}: a closed number is EBADF"),
            call(p, by_fd_name, f, By::Fd(4000)).0 == neg(EBADF),
        );
    }
    p.close(fd);
    p.close(location);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/statvfs",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_statfs,
        Syscall::N_fstatfs,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "statvfs",
        "fstatvfs",
        "statvfs64",
        "fstatvfs64",
        "statfs",
        "openat",
        "close",
    ],
    resolves: &["statvfs", "fstatvfs", "statvfs64", "fstatvfs64"],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines none of statvfs, fstatvfs, statvfs64, fstatvfs64 (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds none (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the gap lifts only once the shim both defines them and routes them there, or the scenario imports them directly",
            failure: Failure::Differs(&[
                Difference::field(3, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(4, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(5, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(6, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "with none resolved the scenario cannot continue",
            failure: Failure::Stops {
                events: 7,
                ending: Ending::Exit(101),
                diagnostic: "fs/statvfs: cannot continue: the statvfs symbols resolve",
            },
        },
    ],
    ..DEFAULTS
};
