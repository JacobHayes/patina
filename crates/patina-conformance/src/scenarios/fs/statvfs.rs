//! fs/statvfs — glibc's POSIX filesystem statistics, `statvfs`/`fstatvfs`
//! and their large-file spellings `statvfs64`/`fstatvfs64` (glibc sysdeps/unix/sysv/linux/statvfs.c, internal_statvfs.c:
//! statfs(2) converted to `struct statvfs`). The sizes and counts are the
//! host filesystem's business, so they are checked by relation: by path and
//! by descriptor they describe one filesystem alike, and agree with
//! `statfs` (block and fragment size, block count, `f_namemax` =
//! `f_namelen`, `f_fsid` = statfs's two `f_fsid` words packed high:low as
//! glibc's internal_statvfs.c packs them, `f_type` — glibc 2.39's new member —
//! statfs's, `f_flag` statfs's `f_flags` without `ST_VALID`, the free and
//! file counts statfs's, `f_favail` = `f_ffree`); the kernel's own answers compare
//! exactly: `f_namemax` is NAME_MAX and `ST_RDONLY` is clear. The
//! descriptor spelling accepts an `O_PATH` descriptor (fstatfs(2) resolves
//! it with `fdget_raw`). A missing name is ENOENT, a path through a file
//! ENOTDIR, a closed descriptor EBADF.
//!
//! libc only: glibc's four symbols, imported (the shim defines them).

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, Statfs, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

/// glibc 2.39's `struct statvfs` (= `struct statvfs64` on a 64-bit target),
/// bits/statvfs.h: the `libc` crate hides the 2.39 `f_type` member inside its
/// spare words.
#[repr(C)]
#[derive(Clone, Copy)]
struct Statvfs {
    f_bsize: c_ulong,
    f_frsize: c_ulong,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: c_ulong,
    f_flag: c_ulong,
    f_namemax: c_ulong,
    f_type: c_uint,
    f_spare: [c_int; 5],
}

const _: () = assert!(std::mem::size_of::<Statvfs>() == std::mem::size_of::<statvfs64>());

type StatvfsFn = unsafe extern "C" fn(*const c_char, *mut Statvfs) -> c_int;
type FstatvfsFn = unsafe extern "C" fn(c_int, *mut Statvfs) -> c_int;

/// `statvfs` into glibc 2.39's layout.
unsafe extern "C" fn plain_by_path(path: *const c_char, st: *mut Statvfs) -> c_int {
    // SAFETY: the caller's NUL-terminated path and live Statvfs, glibc's layout.
    unsafe { statvfs(path, st.cast()) }
}

/// `fstatvfs` into the same layout.
unsafe extern "C" fn plain_by_fd(fd: c_int, st: *mut Statvfs) -> c_int {
    // SAFETY: the caller's live Statvfs, glibc's layout.
    unsafe { fstatvfs(fd, st.cast()) }
}

/// `statvfs64` into the same layout.
unsafe extern "C" fn wide_by_path(path: *const c_char, st: *mut Statvfs) -> c_int {
    // SAFETY: the caller's NUL-terminated path and live Statvfs, glibc's layout.
    unsafe { statvfs64(path, st.cast()) }
}

/// `fstatvfs64` into the same layout.
unsafe extern "C" fn wide_by_fd(fd: c_int, st: *mut Statvfs) -> c_int {
    // SAFETY: the caller's live Statvfs, glibc's layout.
    unsafe { fstatvfs64(fd, st.cast()) }
}

/// statfs(2)'s `ST_VALID`, which glibc clears from `f_flag`.
const ST_VALID: u64 = 0x0020;

/// What the path and descriptor spellings name.
enum By<'a> {
    Path(&'a str),
    Fd(i32),
}

/// One call, recorded with the members every filesystem answers alike.
fn call(p: &Probe, op: &str, f: (StatvfsFn, FstatvfsFn), by: By<'_>) -> (i64, Statvfs) {
    // SAFETY: an all-zero Statvfs is a valid value.
    let mut st: Statvfs = unsafe { std::mem::zeroed() };
    let r = match by {
        By::Path(path) => {
            let c = std::ffi::CString::new(path).expect("no interior NUL");
            // SAFETY: a NUL-terminated path and a live Statvfs.
            unsafe { (f.0)(c.as_ptr(), &mut st) }
        }
        // SAFETY: a live Statvfs.
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
fn identity(st: &Statvfs) -> (u64, u64, u64, u64, u64, u32) {
    (
        st.f_bsize,
        st.f_frsize,
        st.f_blocks,
        st.f_fsid,
        st.f_namemax,
        st.f_type,
    )
}

/// glibc's conversion of the members that move with any writer on the host
/// (free counts, and XFS's inode total): judged on a statvfs taken between
/// two identical statfs answers of the path, unrecorded, so the number of
/// tries leaves no trace in the stream. Under patina the first try settles.
fn counts_agree(f: StatvfsFn, path: &str) -> bool {
    let c = std::ffi::CString::new(path).expect("no interior NUL");
    let statfs_of = || {
        // SAFETY: an all-zero statfs is a valid value.
        let mut fs: statfs = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a live statfs.
        let r = unsafe { statfs(c.as_ptr(), &mut fs) };
        (r == 0).then_some((fs.f_bfree, fs.f_bavail, fs.f_files, fs.f_ffree))
    };
    for _ in 0..64 {
        let before = statfs_of();
        // SAFETY: an all-zero Statvfs is a valid value.
        let mut st: Statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a live Statvfs.
        let r = unsafe { f(c.as_ptr(), &mut st) };
        let after = statfs_of();
        if before.is_some() && before == after {
            return r == 0
                && before == Some((st.f_bfree, st.f_bavail, st.f_files, st.f_ffree))
                && st.f_favail == st.f_ffree;
        }
    }
    false
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

    for (by_name, by_fd_name, f) in [
        (
            "statvfs",
            "fstatvfs",
            (plain_by_path as StatvfsFn, plain_by_fd as FstatvfsFn),
        ),
        (
            "statvfs64",
            "fstatvfs64",
            (wide_by_path as StatvfsFn, wide_by_fd as FstatvfsFn),
        ),
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
        p.check(
            &format!("{by_name}: f_type is statfs's, f_flag its f_flags without ST_VALID"),
            r == 0
                && by_path.f_type == fs.f_type as u32
                && by_path.f_flag == fs.f_flags as u64 ^ ST_VALID,
        );
        p.check(
            &format!("{by_name}: the counts are statfs's, f_favail its f_ffree"),
            counts_agree(f.0, &root),
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
    ..DEFAULTS
};
