//! glibc's large-file spellings of the file rows (`open64`, `stat64`,
//! `lseek64`, …): the symbols a program built with `_FILE_OFFSET_BITS=64`
//! (or Rust's std and rustix on 64-bit Linux) imports in place of the plain
//! names. On a 64-bit target each is the plain call with the same types, so
//! it answers exactly what the plain row does. libc only; each event is named
//! for the symbol it went through.

use super::{Probe, StatView, Statfs, cstr, printable};
use crate::observe::{Id, Norm};
use crate::vehicle::fold_errno;
use libc::c_int;
use serde_json::Value;

// The 64-bit layouts are the plain ones on every 64-bit Linux target.
const _: () = assert!(size_of::<libc::stat>() == size_of::<libc::stat64>());
const _: () = assert!(size_of::<Statfs>() == size_of::<libc::statfs64>());

// glibc exports `fcntl64` (2.28); the libc crate does not declare it.
unsafe extern "C" {
    fn fcntl64(fd: c_int, cmd: c_int, ...) -> c_int;
}

/// What a `stat64`-family call names: a path (`stat64`, followed), a link
/// itself (`lstat64`), a descriptor (`fstat64`), or `fstatat64(dirfd, path,
/// flags)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatBy<'a> {
    Path(&'a str),
    Link(&'a str),
    Fd(i32),
    At(i32, &'a str, i32),
}

impl Probe {
    pub fn open64(&self, path: &str, flags: i32, mode: u32) -> i32 {
        let c = cstr(path);
        // SAFETY: a NUL-terminated path; the mode is read only with O_CREAT.
        let result = fold_errno(unsafe { libc::open64(c.as_ptr(), flags, mode) }.into());
        self.rec
            .event("open64", result)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mode", mode)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn openat64(&self, dirfd: i32, path: &str, flags: i32, mode: u32) -> i32 {
        let c = cstr(path);
        // SAFETY: a NUL-terminated path; the mode is read only with O_CREAT.
        let result = fold_errno(unsafe { libc::openat64(dirfd, c.as_ptr(), flags, mode) }.into());
        let builder = self.rec.event("openat64", result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mode", mode)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// The `stat64` family; `null` passes a NULL buffer.
    pub fn stat64(&self, by: StatBy<'_>, null: bool) -> (i64, Option<StatView>) {
        // SAFETY: an all-zero stat is a valid value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let buf: *mut libc::stat64 = if null {
            std::ptr::null_mut()
        } else {
            (&mut st as *mut libc::stat).cast()
        };
        let (op, path) = match by {
            StatBy::Path(path) => ("stat64", Some(path)),
            StatBy::Link(path) => ("lstat64", Some(path)),
            StatBy::Fd(_) => ("fstat64", None),
            StatBy::At(_, path, _) => ("fstatat64", Some(path)),
        };
        let c = path.map(cstr);
        let c_path = c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        // SAFETY: a NUL-terminated path and a stat64-sized buffer (or NULL).
        let result = fold_errno(i64::from(unsafe {
            match by {
                StatBy::Path(_) => libc::stat64(c_path, buf),
                StatBy::Link(_) => libc::lstat64(c_path, buf),
                StatBy::Fd(fd) => libc::fstat64(fd, buf),
                StatBy::At(dirfd, _, flags) => libc::fstatat64(dirfd, c_path, buf, flags),
            }
        }));
        let builder = self.rec.event(op, result);
        let builder = match by {
            StatBy::Path(path) | StatBy::Link(path) => builder.arg("path", path),
            StatBy::Fd(fd) => self.fd_arg(builder, "fd", fd),
            StatBy::At(dirfd, path, flags) => self
                .fd_arg(builder, "dirfd", dirfd)
                .arg("path", path)
                .arg("flags", flags),
        };
        let builder = builder.arg("buf", if null { "NULL" } else { "buf" });
        let view = (result == 0 && !null).then(|| Self::view_of(&st));
        match &view {
            Some(view) => self.stat_fields(builder, view).emit(),
            None => builder.emit(),
        }
        (result, view)
    }

    /// `statfs64(path)`, recorded like `statfs`.
    pub fn statfs64(&self, path: &str) -> (i64, Option<Statfs>) {
        let c = cstr(path);
        let mut st = Statfs::default();
        // SAFETY: a NUL-terminated path and a statfs64-sized buffer.
        let result = fold_errno(i64::from(unsafe {
            libc::statfs64(c.as_ptr(), (&mut st as *mut Statfs).cast())
        }));
        let builder = self.rec.event("statfs64", result).arg("path", path);
        self.statfs64_emit(builder, result, st)
    }

    /// `fstatfs64(fd)`, recorded like `fstatfs`.
    pub fn fstatfs64(&self, fd: i32) -> (i64, Option<Statfs>) {
        let mut st = Statfs::default();
        // SAFETY: a statfs64-sized buffer.
        let result = fold_errno(i64::from(unsafe {
            libc::fstatfs64(fd, (&mut st as *mut Statfs).cast())
        }));
        let builder = self.rec.event("fstatfs64", result);
        let builder = self.fd_arg(builder, "fd", fd);
        self.statfs64_emit(builder, result, st)
    }

    fn statfs64_emit(
        &self,
        builder: crate::record::EventBuilder<'_>,
        result: i64,
        st: Statfs,
    ) -> (i64, Option<Statfs>) {
        if result == 0 {
            self.statfs_fields(builder, &st).emit();
            (result, Some(st))
        } else {
            builder.emit();
            (result, None)
        }
    }

    /// `preadv64(fd, one buffer per length, offset)`; the segments read.
    pub fn preadv64(&self, fd: i32, lens: &[usize], offset: i64) -> (i64, Vec<Vec<u8>>) {
        let mut buffers: Vec<Vec<u8>> = lens.iter().map(|&len| vec![0u8; len]).collect();
        let iov: Vec<libc::iovec> = buffers
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            })
            .collect();
        // SAFETY: every iovec names a live buffer of its length.
        let result =
            fold_errno(
                unsafe { libc::preadv64(fd, iov.as_ptr(), iov.len() as c_int, offset) } as i64,
            );
        let mut remaining = result.max(0) as usize;
        for buf in &mut buffers {
            let filled = remaining.min(buf.len());
            buf.truncate(filled);
            remaining -= filled;
        }
        let builder = self.rec.event("preadv64", result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("lens", lens.to_vec())
            .arg("offset", offset);
        let builder = if result >= 0 {
            builder.field(
                "segments",
                Value::Array(buffers.iter().map(|b| Value::from(printable(b))).collect()),
            )
        } else {
            builder
        };
        builder.emit();
        (result, buffers)
    }

    /// `pwritev64(fd, segments, offset)`.
    pub fn pwritev64(&self, fd: i32, segments: &[&[u8]], offset: i64) -> i64 {
        let iov: Vec<libc::iovec> = segments
            .iter()
            .map(|segment| libc::iovec {
                iov_base: segment.as_ptr() as *mut libc::c_void,
                iov_len: segment.len(),
            })
            .collect();
        // SAFETY: every iovec names a live buffer of its length, only read.
        let result =
            fold_errno(
                unsafe { libc::pwritev64(fd, iov.as_ptr(), iov.len() as c_int, offset) } as i64,
            );
        let builder = self.rec.event("pwritev64", result);
        self.fd_arg(builder, "fd", fd)
            .arg(
                "lens",
                segments
                    .iter()
                    .map(|segment| segment.len())
                    .collect::<Vec<_>>(),
            )
            .arg("offset", offset)
            .emit();
        result
    }

    pub fn lseek64(&self, fd: i32, offset: i64, whence: i32) -> i64 {
        // SAFETY: plain values.
        let result = fold_errno(unsafe { libc::lseek64(fd, offset, whence) });
        let builder = self.rec.event("lseek64", result);
        self.fd_arg(builder, "fd", fd)
            .arg("offset", offset)
            .arg("whence", whence)
            .emit();
        result
    }

    pub fn ftruncate64(&self, fd: i32, len: i64) -> i64 {
        // SAFETY: plain values.
        let result = fold_errno(unsafe { libc::ftruncate64(fd, len) }.into());
        let builder = self.rec.event("ftruncate64", result);
        self.fd_arg(builder, "fd", fd).arg("len", len).emit();
        result
    }

    pub fn truncate64(&self, path: &str, len: i64) -> i64 {
        let c = cstr(path);
        // SAFETY: a NUL-terminated path.
        let result = fold_errno(unsafe { libc::truncate64(c.as_ptr(), len) }.into());
        self.rec
            .event("truncate64", result)
            .arg("path", path)
            .arg("len", len)
            .emit();
        result
    }

    pub fn fallocate64(&self, fd: i32, mode: i32, offset: i64, len: i64) -> i64 {
        // SAFETY: plain values.
        let result = fold_errno(unsafe { libc::fallocate64(fd, mode, offset, len) }.into());
        let builder = self.rec.event("fallocate64", result);
        self.fd_arg(builder, "fd", fd)
            .arg("mode", mode)
            .arg("offset", offset)
            .arg("len", len)
            .emit();
        result
    }

    /// `posix_fallocate64`, which returns its error number rather than
    /// setting errno; recorded in the kernel convention.
    pub fn posix_fallocate64(&self, fd: i32, offset: i64, len: i64) -> i64 {
        // SAFETY: plain values.
        let result = -i64::from(unsafe { libc::posix_fallocate64(fd, offset, len) });
        let builder = self.rec.event("posix_fallocate64", result);
        self.fd_arg(builder, "fd", fd)
            .arg("offset", offset)
            .arg("len", len)
            .emit();
        result
    }

    /// `fcntl64(fd, cmd, arg)` for the integer-argument commands.
    pub fn fcntl64(&self, fd: i32, cmd: i32, arg: i64) -> i64 {
        // SAFETY: an integer-argument command.
        let result = fold_errno(unsafe { fcntl64(fd, cmd, arg) }.into());
        let builder = self.rec.event("fcntl64", result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("cmd", cmd)
            .arg("arg", arg);
        let builder = if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
            builder.norm("ret", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        result
    }

    /// `fcntl64(fd, cmd, &flock)` for a lock command over `len` bytes from
    /// `start` (`len` 0: to the end of the file, whatever it grows to) with
    /// lock type `kind`; returns the `flock64` the call leaves. A GETLK's
    /// answer records the conflicting lock (its range and owner pid,
    /// normalized) or `l_type` `F_UNLCK`.
    pub fn fcntl64_lock(
        &self,
        fd: i32,
        cmd: i32,
        kind: i16,
        start: i64,
        len: i64,
    ) -> (i64, libc::flock64) {
        // SAFETY: an all-zero flock is a valid value (and `l_pid` 0, as the
        // OFD commands require).
        let mut lock: libc::flock64 = unsafe { std::mem::zeroed() };
        lock.l_type = kind;
        lock.l_whence = libc::SEEK_SET as i16;
        lock.l_start = start;
        lock.l_len = len;
        // SAFETY: a lock command with a live flock64.
        let result =
            fold_errno(unsafe { fcntl64(fd, cmd, &mut lock as *mut libc::flock64) }.into());
        let builder = self.rec.event("fcntl64", result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("cmd", cmd)
            .arg("l_type", kind)
            .arg("l_start", start)
            .arg("l_len", len)
            .field("l_type", lock.l_type);
        let conflict = result == 0
            && (cmd == libc::F_GETLK || cmd == libc::F_OFD_GETLK)
            && lock.l_type != libc::F_UNLCK as i16;
        let builder = if conflict {
            builder
                .field("l_start", lock.l_start)
                .field("l_len", lock.l_len)
                .field("l_pid", lock.l_pid)
                .norm("fields.l_pid", Norm::Identity(Id::Process))
        } else {
            builder
        };
        builder.emit();
        (result, lock)
    }
}
