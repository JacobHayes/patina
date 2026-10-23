//! fs/fortify — glibc's `_FORTIFY_SOURCE` spellings of the file calls
//! (`__open_2`, `__open64_2`, `__openat_2`, `__openat64_2`, `__read_chk`,
//! `__pread_chk`, `__pread64_chk`, `__readlink_chk`, `__readlinkat_chk`;
//! glibc io/open_2.c, openat_2.c, debug/read_chk.c, pread_chk.c,
//! readlink_chk.c) and its exported internal names (`__open`, `__open64`,
//! `__read`, `__write`), which C built with `-D_FORTIFY_SOURCE` and older
//! objects import in place of `open`, `read`, `pread` and `readlink`. Within
//! the buffer size the compiler knew they answer exactly what the plain call
//! answers:
//!
//! * `__open`/`__open64` create and open, `O_EXCL` on an existing name is
//!   `EEXIST`; `__open_2`/`__open64_2` open without a mode (`ENOENT` for a
//!   missing name) and `__openat_2`/`__openat64_2` relative to a directory
//!   descriptor (`EBADF` for a closed one);
//! * `__write` writes and `__read` and `__read_chk` read on from the
//!   descriptor's offset to EOF; `__pread_chk`/`__pread64_chk` read at an
//!   offset without moving it (`ESPIPE` on a pipe, `EINVAL` for a negative
//!   offset); `__read` of a closed number is `EBADF`, `__write` through a
//!   read-only descriptor `EBADF`;
//! * `__readlink_chk`/`__readlinkat_chk` read a symlink's target (`EINVAL`
//!   for a file).
//!
//! The overflow path (`__chk_fail`, `__fortify_fail`: SIGABRT before any
//! syscall) is not exercised: observing it needs a forked child, which patina
//! refuses by design; the shim's own fortify aborts are cargo-patina's
//! native_signals `raw::guest_ended_runs_finalize_their_traces`.
//!
//! libc only: glibc's symbols, imported (the shim defines them; the `libc`
//! crate declares none of them).

use crate::catalog::{DEFAULTS, Scenario};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

type Open2 = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type Openat2 = unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int;
type Open = unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int;
type Read = unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t;
type Write = unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t;
type ReadChk = unsafe extern "C" fn(c_int, *mut c_void, size_t, size_t) -> ssize_t;
type PreadChk = unsafe extern "C" fn(c_int, *mut c_void, size_t, off64_t, size_t) -> ssize_t;
type ReadlinkChk = unsafe extern "C" fn(*const c_char, *mut c_char, size_t, size_t) -> ssize_t;
type ReadlinkatChk =
    unsafe extern "C" fn(c_int, *const c_char, *mut c_char, size_t, size_t) -> ssize_t;

unsafe extern "C" {
    fn __open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn __open64(path: *const c_char, flags: c_int, ...) -> c_int;
    fn __open_2(path: *const c_char, flags: c_int) -> c_int;
    fn __open64_2(path: *const c_char, flags: c_int) -> c_int;
    fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn __read(fd: c_int, buf: *mut c_void, len: size_t) -> ssize_t;
    fn __write(fd: c_int, buf: *const c_void, len: size_t) -> ssize_t;
    fn __read_chk(fd: c_int, buf: *mut c_void, len: size_t, buflen: size_t) -> ssize_t;
    fn __pread_chk(
        fd: c_int,
        buf: *mut c_void,
        len: size_t,
        offset: off64_t,
        buflen: size_t,
    ) -> ssize_t;
    fn __pread64_chk(
        fd: c_int,
        buf: *mut c_void,
        len: size_t,
        offset: off64_t,
        buflen: size_t,
    ) -> ssize_t;
    fn __readlink_chk(
        path: *const c_char,
        buf: *mut c_char,
        len: size_t,
        buflen: size_t,
    ) -> ssize_t;
    fn __readlinkat_chk(
        dirfd: c_int,
        path: *const c_char,
        buf: *mut c_char,
        len: size_t,
        buflen: size_t,
    ) -> ssize_t;
}

/// Every buffer the compiler would know: 16 bytes.
const BUFLEN: usize = 16;

fn cstr(text: &str) -> CString {
    CString::new(text).expect("no interior NUL")
}

/// An event for an open: the mode it passed (with `O_CREAT`), the new
/// descriptor normalized.
fn opened(p: &Probe, op: &str, path: &str, flags: i32, mode: Option<u32>, r: i64) -> i32 {
    let builder = p.rec.event(op, r).arg("path", path).arg("flags", flags);
    let builder = match mode {
        Some(mode) => builder.arg("mode", mode),
        None => builder,
    };
    builder.norm("ret", Norm::Relative("fd")).emit();
    r as i32
}

/// An event for a read: the bytes it answered.
fn read_event(p: &Probe, op: &str, fd: i32, len: usize, r: i64, buf: &[u8]) {
    let builder = p
        .rec
        .event(op, r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("len", len);
    let builder = if r >= 0 {
        builder.field(
            "data",
            String::from_utf8_lossy(&buf[..r as usize]).into_owned(),
        )
    } else {
        builder
    };
    builder.emit();
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let (open, open64): (Open, Open) = (__open, __open64);
    let (open_2, open64_2, openat_2, openat64_2): (Open2, Open2, Openat2, Openat2) =
        (__open_2, __open64_2, __openat_2, __openat64_2);
    let (read, write, read_chk): (Read, Write, ReadChk) = (__read, __write, __read_chk);
    let (pread_chk, pread64_chk): (PreadChk, PreadChk) = (__pread_chk, __pread64_chk);
    let (readlink_chk, readlinkat_chk): (ReadlinkChk, ReadlinkatChk) =
        (__readlink_chk, __readlinkat_chk);
    let file = format!("{root}/f");
    let c_file = cstr(&file);

    // ---- the opens -----------------------------------------------------------
    let flags = O_RDWR | O_CREAT | O_EXCL;
    // SAFETY: a NUL-terminated path; the mode, with O_CREAT.
    let r = fold_errno(unsafe { open(c_file.as_ptr(), flags, 0o640 as c_uint) }.into());
    let fd = opened(p, "__open", &file, flags, Some(0o640), r);
    p.require("__open creates f", fd >= 0);
    let (r, st) = p.newfstatat(AT_FDCWD, &file, 0);
    p.check(
        "with the mode passed after the flags",
        r == 0 && st.is_some_and(|st| st.kind == "reg" && st.perm == 0o640),
    );
    // SAFETY: as above.
    let r = fold_errno(unsafe { open64(c_file.as_ptr(), flags, 0o640 as c_uint) }.into());
    p.check(
        "__open64 O_EXCL on an existing name is EEXIST",
        i64::from(opened(p, "__open64", &file, flags, Some(0o640), r)) == neg(EEXIST),
    );
    // SAFETY: a NUL-terminated path; no O_CREAT, so no mode.
    let r = fold_errno(unsafe { open64(c_file.as_ptr(), O_RDONLY) }.into());
    let reader = opened(p, "__open64", &file, O_RDONLY, None, r);
    p.require("__open64 opens f read-only", reader >= 0);
    // SAFETY: as above.
    let r = fold_errno(unsafe { open_2(c_file.as_ptr(), O_RDONLY) }.into());
    let second = opened(p, "__open_2", &file, O_RDONLY, None, r);
    p.check("__open_2 opens f", second >= 0);
    let missing = format!("{root}/missing");
    let c_missing = cstr(&missing);
    // SAFETY: as above.
    let r = fold_errno(unsafe { open64_2(c_missing.as_ptr(), O_RDONLY) }.into());
    p.check(
        "__open64_2 of a missing name is ENOENT",
        i64::from(opened(p, "__open64_2", &missing, O_RDONLY, None, r)) == neg(ENOENT),
    );
    let dir = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dir >= 0);
    let c_f = cstr("f");
    // SAFETY: a directory descriptor and a NUL-terminated name.
    let r = fold_errno(unsafe { openat_2(dir, c_f.as_ptr(), O_RDONLY) }.into());
    let third = opened(p, "__openat_2", "f", O_RDONLY, None, r);
    p.check("__openat_2 opens f relative to the directory", third >= 0);
    // SAFETY: a closed number and a NUL-terminated name.
    let r = fold_errno(unsafe { openat64_2(4000, c_f.as_ptr(), O_RDONLY) }.into());
    p.check(
        "__openat64_2 relative to a closed number is EBADF",
        i64::from(opened(p, "__openat64_2", "f", O_RDONLY, None, r)) == neg(EBADF),
    );
    // SAFETY: as above, relative to the directory.
    let r = fold_errno(unsafe { openat64_2(dir, c_f.as_ptr(), O_RDONLY) }.into());
    let fourth = opened(p, "__openat64_2", "f", O_RDONLY, None, r);
    p.check("__openat64_2 opens f", fourth >= 0);

    // ---- reads and writes -----------------------------------------------------
    let data = b"hello world";
    // SAFETY: a live buffer of its length.
    let r = fold_errno(unsafe { write(fd, data.as_ptr().cast(), data.len()) } as i64);
    p.rec
        .event("__write", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("len", data.len())
        .emit();
    p.check("__write writes", r == 11);
    let mut buf = [0u8; BUFLEN];
    // SAFETY: a 16-byte buffer, asked for 5.
    let r = fold_errno(unsafe { read(reader, buf.as_mut_ptr().cast(), 5) } as i64);
    read_event(p, "__read", reader, 5, r, &buf);
    p.check(
        "__read reads from the start",
        r == 5 && buf[..5] == *b"hello",
    );
    // SAFETY: a 16-byte buffer, asked for 16 of its 16.
    let r = fold_errno(unsafe { read_chk(reader, buf.as_mut_ptr().cast(), BUFLEN, BUFLEN) } as i64);
    read_event(p, "__read_chk", reader, BUFLEN, r, &buf);
    p.check(
        "__read_chk reads on from the offset",
        r == 6 && buf[..6] == *b" world",
    );
    // SAFETY: as above.
    let r = fold_errno(unsafe { read_chk(reader, buf.as_mut_ptr().cast(), BUFLEN, BUFLEN) } as i64);
    read_event(p, "__read_chk", reader, BUFLEN, r, &buf);
    p.check("__read_chk at EOF reads nothing", r == 0);
    let pread = |op: &str, f: PreadChk, fd: i32, len: usize, offset: i64| {
        let mut buf = [0u8; BUFLEN];
        // SAFETY: a 16-byte buffer, asked for at most 16.
        let r = fold_errno(unsafe { f(fd, buf.as_mut_ptr().cast(), len, offset, BUFLEN) } as i64);
        read_event(p, op, fd, len, r, &buf);
        (r, buf)
    };
    let (r, got) = pread("__pread_chk", pread_chk, second, 5, 6);
    p.check(
        "__pread_chk reads at an offset",
        r == 5 && got[..5] == *b"world",
    );
    let (r, got) = pread("__pread64_chk", pread64_chk, second, 5, 0);
    p.check("__pread64_chk too", r == 5 && got[..5] == *b"hello");
    // SAFETY: a 16-byte buffer, asked for 5.
    let r = fold_errno(unsafe { read(second, buf.as_mut_ptr().cast(), 5) } as i64);
    read_event(p, "__read", second, 5, r, &buf);
    p.check("neither moved the offset", r == 5 && buf[..5] == *b"hello");
    p.check(
        "__pread_chk at a negative offset is EINVAL",
        pread("__pread_chk", pread_chk, second, 5, -1).0 == neg(EINVAL),
    );
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "__pread64_chk on a pipe is ESPIPE",
        pread("__pread64_chk", pread64_chk, rd, 5, 0).0 == neg(ESPIPE),
    );
    // SAFETY: a 16-byte buffer, asked for 5.
    let r = fold_errno(unsafe { read(4000, buf.as_mut_ptr().cast(), 5) } as i64);
    read_event(p, "__read", 4000, 5, r, &buf);
    p.check("__read of a closed number is EBADF", r == neg(EBADF));
    // SAFETY: a live buffer of its length.
    let r = fold_errno(unsafe { write(reader, data.as_ptr().cast(), data.len()) } as i64);
    p.rec
        .event("__write", r)
        .arg("fd", reader)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("len", data.len())
        .emit();
    p.check(
        "__write through a read-only descriptor is EBADF",
        r == neg(EBADF),
    );

    // ---- readlink ------------------------------------------------------------
    let link = format!("{root}/l");
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    let readlink = |op: &str, path: &str, r: i64, buf: &[u8]| {
        p.rec
            .event(op, r)
            .arg("path", path)
            .arg("len", BUFLEN)
            .field(
                "target",
                String::from_utf8_lossy(&buf[..r.max(0) as usize]).into_owned(),
            )
            .emit();
        r
    };
    let mut target = [0u8; BUFLEN];
    let c_link = cstr(&link);
    // SAFETY: a NUL-terminated path and a 16-byte buffer, asked for 16.
    let r = fold_errno(unsafe {
        readlink_chk(c_link.as_ptr(), target.as_mut_ptr().cast(), BUFLEN, BUFLEN)
    } as i64);
    p.check(
        "__readlink_chk reads the target",
        readlink("__readlink_chk", &link, r, &target) == 1 && target[0] == b'f',
    );
    // SAFETY: as above.
    let r = fold_errno(unsafe {
        readlink_chk(c_file.as_ptr(), target.as_mut_ptr().cast(), BUFLEN, BUFLEN)
    } as i64);
    p.check(
        "__readlink_chk of a file is EINVAL",
        readlink("__readlink_chk", &file, r, &target) == neg(EINVAL),
    );
    let c_l = cstr("l");
    // SAFETY: a directory descriptor, a NUL-terminated name and a 16-byte
    // buffer, asked for 16.
    let r = fold_errno(unsafe {
        readlinkat_chk(
            dir,
            c_l.as_ptr(),
            target.as_mut_ptr().cast(),
            BUFLEN,
            BUFLEN,
        )
    } as i64);
    p.check(
        "__readlinkat_chk reads it relative to the directory",
        readlink("__readlinkat_chk", "l", r, &target) == 1 && target[0] == b'f',
    );

    for fd in [fd, reader, second, third, fourth, dir, rd, wr] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/fortify",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_pread64,
        Syscall::N_readlinkat,
        Syscall::N_symlinkat,
        Syscall::N_pipe2,
        Syscall::N_close,
        Syscall::N_newfstatat,
    ],
    symbols: &[
        "__open",
        "__open64",
        "__open_2",
        "__open64_2",
        "__openat_2",
        "__openat64_2",
        "__read",
        "__write",
        "__read_chk",
        "__pread_chk",
        "__pread64_chk",
        "__readlink_chk",
        "__readlinkat_chk",
        "openat",
        "symlinkat",
        "pipe2",
        "close",
        "fstatat",
    ],
    ..DEFAULTS
};
