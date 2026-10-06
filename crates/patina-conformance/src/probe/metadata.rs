//! Filesystem metadata, notification, cache, and handle rows.

use super::*;

impl Probe {
    // ---- timestamps, ownership, sizes ----------------------------------------

    /// One `utimensat` time argument: `Set(sec, nsec)`, `Now` (`UTIME_NOW`),
    /// or `Omit` (`UTIME_OMIT`). Recorded by name so a stream says what was
    /// asked without an absolute value.
    fn timespec_of(time: TimeArg) -> libc::timespec {
        match time {
            TimeArg::Set(sec, nsec) => libc::timespec {
                tv_sec: sec,
                tv_nsec: nsec,
            },
            TimeArg::Now => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_NOW,
            },
            TimeArg::Omit => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        }
    }

    fn time_args<'a>(
        &self,
        builder: EventBuilder<'a>,
        times: Option<[TimeArg; 2]>,
    ) -> EventBuilder<'a> {
        match times {
            None => builder.arg("times", "NULL"),
            Some([atime, mtime]) => builder
                .arg("atime", atime.label())
                .arg("mtime", mtime.label()),
        }
    }

    /// `utimensat`; a `None` path is the `futimens` shape (the descriptor's
    /// own times), a `None` times pointer sets both to now.
    pub fn utimensat(
        &self,
        dirfd: i32,
        path: Option<&str>,
        times: Option<[TimeArg; 2]>,
        flags: i32,
    ) -> i64 {
        let c = path.map(cstr);
        let spec = times.map(|[a, m]| [Self::timespec_of(a), Self::timespec_of(m)]);
        let result = self.call(
            Syscall::N_utimensat,
            [
                dirfd as i64,
                c.as_ref().map_or(0, |c| c.as_ptr() as i64),
                spec.as_ref().map_or(0, |s| s.as_ptr() as i64),
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_utimensat, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path.unwrap_or("NULL"))
            .arg("flags", flags);
        self.time_args(builder, times).emit();
        result
    }

    /// `utime(2)`: whole seconds, or `None` for now/now. An x86_64 legacy row;
    /// the generic table's shape is `utimensat(AT_FDCWD, path, times, 0)`.
    pub fn utime(&self, path: &str, times: Option<(i64, i64)>) -> i64 {
        let c = cstr(path);
        let buf = times.map(|(actime, modtime)| libc::utimbuf { actime, modtime });
        let buf_ptr = buf.as_ref().map_or(0, |b| b as *const libc::utimbuf as i64);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_utime, [c.as_ptr() as i64, buf_ptr, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let spec = times.map(|(actime, modtime)| {
                [
                    Self::timespec_of(TimeArg::Set(actime, 0)),
                    Self::timespec_of(TimeArg::Set(modtime, 0)),
                ]
            });
            let spec_ptr = spec.as_ref().map_or(0, |s| s.as_ptr() as i64);
            // SAFETY: a NUL-terminated path and a utimbuf or NULL.
            self.legacy(
                || unsafe { libc::utime(c.as_ptr(), buf_ptr as *const libc::utimbuf) } as i64,
                Syscall::N_utimensat,
                [AT_FDCWD as i64, c.as_ptr() as i64, spec_ptr, 0, 0, 0],
            )
        };
        let builder = self.rec.event("utime", result).arg("path", path);
        let builder = match times {
            None => builder.arg("times", "NULL"),
            Some((actime, modtime)) => builder.arg("actime", actime).arg("modtime", modtime),
        };
        builder.emit();
        result
    }

    fn timeval_pair(times: Option<[(i64, i64); 2]>) -> Option<[libc::timeval; 2]> {
        times.map(|[(asec, ausec), (msec, musec)]| {
            [
                libc::timeval {
                    tv_sec: asec,
                    tv_usec: ausec,
                },
                libc::timeval {
                    tv_sec: msec,
                    tv_usec: musec,
                },
            ]
        })
    }

    /// Two timevals as the timespecs `utimensat` takes (the generic table's
    /// shape of `utimes`/`futimesat`).
    #[cfg(not(target_arch = "x86_64"))]
    fn timespecs_of_timevals(times: Option<[(i64, i64); 2]>) -> Option<[libc::timespec; 2]> {
        const NANOS_PER_MICRO: i64 = 1_000;
        times.map(|[(asec, ausec), (msec, musec)]| {
            [
                Self::timespec_of(TimeArg::Set(asec, ausec * NANOS_PER_MICRO)),
                Self::timespec_of(TimeArg::Set(msec, musec * NANOS_PER_MICRO)),
            ]
        })
    }

    fn timeval_args<'a>(
        &self,
        builder: EventBuilder<'a>,
        times: Option<[(i64, i64); 2]>,
    ) -> EventBuilder<'a> {
        match times {
            None => builder.arg("times", "NULL"),
            Some([(asec, ausec), (msec, musec)]) => builder
                .arg("atime", format!("{asec}.{ausec:06}"))
                .arg("mtime", format!("{msec}.{musec:06}")),
        }
    }

    /// `utimes(2)`: microsecond times, or `None` for now/now. An x86_64 legacy
    /// row; the generic table's shape is `utimensat`.
    pub fn utimes(&self, path: &str, times: Option<[(i64, i64); 2]>) -> i64 {
        let c = cstr(path);
        let tv = Self::timeval_pair(times);
        let tv_ptr = tv.as_ref().map_or(0, |t| t.as_ptr() as i64);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_utimes, [c.as_ptr() as i64, tv_ptr, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let spec = Self::timespecs_of_timevals(times);
            let spec_ptr = spec.as_ref().map_or(0, |s| s.as_ptr() as i64);
            // SAFETY: a NUL-terminated path and two timevals or NULL.
            self.legacy(
                || unsafe { libc::utimes(c.as_ptr(), tv_ptr as *const libc::timeval) } as i64,
                Syscall::N_utimensat,
                [AT_FDCWD as i64, c.as_ptr() as i64, spec_ptr, 0, 0, 0],
            )
        };
        let builder = self.rec.event("utimes", result).arg("path", path);
        self.timeval_args(builder, times).emit();
        result
    }

    /// glibc's `lutimes(3)`: `utimes` of a symlink itself (no row of its own;
    /// glibc issues `utimensat(AT_FDCWD, path, …, AT_SYMLINK_NOFOLLOW)`).
    /// libc only.
    pub fn lutimes(&self, path: &str, times: Option<[(i64, i64); 2]>) -> i64 {
        let c = cstr(path);
        let tv = Self::timeval_pair(times);
        let tv_ptr = tv.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
        // SAFETY: a NUL-terminated path and two timevals or NULL.
        let result =
            crate::vehicle::fold_errno(unsafe { libc::lutimes(c.as_ptr(), tv_ptr) }.into());
        let builder = self.rec.event("lutimes", result).arg("path", path);
        self.timeval_args(builder, times).emit();
        result
    }

    /// glibc's `futimes(3)`: `utimes` of a descriptor (glibc issues
    /// `utimensat(fd, NULL, …, 0)`). libc only.
    pub fn futimes(&self, fd: i32, times: Option<[(i64, i64); 2]>) -> i64 {
        let tv = Self::timeval_pair(times);
        let tv_ptr = tv.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
        // SAFETY: two timevals or NULL.
        let result = crate::vehicle::fold_errno(unsafe { libc::futimes(fd, tv_ptr) }.into());
        let builder = self.rec.event("futimes", result);
        let builder = self.fd_arg(builder, "fd", fd);
        self.timeval_args(builder, times).emit();
        result
    }

    /// `futimesat(2)`: `utimes` with a dirfd. An x86_64 legacy row; the
    /// generic table's shape is `utimensat(dirfd, …)`.
    pub fn futimesat(&self, dirfd: i32, path: &str, times: Option<[(i64, i64); 2]>) -> i64 {
        let c = cstr(path);
        let tv = Self::timeval_pair(times);
        let tv_ptr = tv.as_ref().map_or(0, |t| t.as_ptr() as i64);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_futimesat,
            [dirfd as i64, c.as_ptr() as i64, tv_ptr, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let spec = Self::timespecs_of_timevals(times);
            let spec_ptr = spec.as_ref().map_or(0, |s| s.as_ptr() as i64);
            // SAFETY: a NUL-terminated path and two timevals or NULL.
            self.legacy(
                || unsafe {
                    crate::vehicle::futimesat(dirfd, c.as_ptr(), tv_ptr as *const libc::timeval)
                } as i64,
                Syscall::N_utimensat,
                [dirfd as i64, c.as_ptr() as i64, spec_ptr, 0, 0, 0],
            )
        };
        let builder = self.rec.event("futimesat", result);
        let builder = self.fd_arg(builder, "dirfd", dirfd).arg("path", path);
        self.timeval_args(builder, times).emit();
        result
    }

    fn id_arg<'a>(&self, builder: EventBuilder<'a>, kind: Id, id: u32) -> EventBuilder<'a> {
        let key = kind.name();
        if id == u32::MAX {
            builder.arg(key, "-1")
        } else {
            builder
                .arg(key, id)
                .norm(&format!("args.{key}"), Norm::Identity(kind))
        }
    }

    /// `chown`/`lchown`: `u32::MAX` is `-1`. x86_64 legacy rows; the generic
    /// table's shape is `fchownat(AT_FDCWD, …)`.
    pub fn chown(&self, path: &str, uid: u32, gid: u32, follow: bool) -> i64 {
        let c = cstr(path);
        let op = if follow { "chown" } else { "lchown" };
        #[cfg(target_arch = "x86_64")]
        let result = {
            let row = if follow {
                Syscall::N_chown
            } else {
                Syscall::N_lchown
            };
            self.call(row, [c.as_ptr() as i64, uid as i64, gid as i64, 0, 0, 0])
        };
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe {
                if follow {
                    libc::chown(c.as_ptr(), uid, gid)
                } else {
                    libc::lchown(c.as_ptr(), uid, gid)
                }
            } as i64,
            Syscall::N_fchownat,
            [
                AT_FDCWD as i64,
                c.as_ptr() as i64,
                uid as i64,
                gid as i64,
                if follow {
                    0
                } else {
                    libc::AT_SYMLINK_NOFOLLOW as i64
                },
                0,
            ],
        );
        let builder = self.rec.event(op, result).arg("path", path);
        let builder = self.id_arg(builder, Id::User, uid);
        self.id_arg(builder, Id::Group, gid).emit();
        result
    }

    pub fn fchown(&self, fd: i32, uid: u32, gid: u32) -> i64 {
        let result = self.call(
            Syscall::N_fchown,
            [fd as i64, uid as i64, gid as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_fchown, result);
        let builder = self.fd_arg(builder, "fd", fd);
        let builder = self.id_arg(builder, Id::User, uid);
        self.id_arg(builder, Id::Group, gid).emit();
        result
    }

    pub fn fchownat(&self, dirfd: i32, path: &str, uid: u32, gid: u32, flags: i32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_fchownat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                uid as i64,
                gid as i64,
                flags as i64,
                0,
            ],
        );
        let builder = self.event(Syscall::N_fchownat, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags);
        let builder = self.id_arg(builder, Id::User, uid);
        self.id_arg(builder, Id::Group, gid).emit();
        result
    }

    /// `access`. An x86_64 legacy row; the generic table's shape is
    /// `faccessat(AT_FDCWD, …)`.
    pub fn access(&self, path: &str, mode: i32) -> i64 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_access,
            [c.as_ptr() as i64, mode as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::access(c.as_ptr(), mode) } as i64,
            Syscall::N_faccessat,
            [AT_FDCWD as i64, c.as_ptr() as i64, mode as i64, 0, 0, 0],
        );
        self.rec
            .event("access", result)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    /// `faccessat` (`flagged`: the `faccessat2` row, the only one that carries
    /// flags to the kernel).
    pub fn faccessat(&self, dirfd: i32, path: &str, mode: i32, flags: i32, flagged: bool) -> i64 {
        let sys = if flagged {
            Syscall::N_faccessat2
        } else {
            Syscall::N_faccessat
        };
        let c = cstr(path);
        let result = self.call(
            sys,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                mode as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(sys, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .arg("flags", flags)
            .emit();
        result
    }

    pub fn truncate(&self, path: &str, len: i64) -> i64 {
        let c = cstr(path);
        let result = self.call(Syscall::N_truncate, [c.as_ptr() as i64, len, 0, 0, 0, 0]);
        self.event(Syscall::N_truncate, result)
            .arg("path", path)
            .arg("len", len)
            .emit();
        result
    }

    pub fn ftruncate(&self, fd: i32, len: i64) -> i64 {
        let result = self.call(Syscall::N_ftruncate, [fd as i64, len, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_ftruncate, result);
        self.fd_arg(builder, "fd", fd).arg("len", len).emit();
        result
    }

    pub fn fallocate(&self, fd: i32, mode: i32, offset: i64, len: i64) -> i64 {
        let result = self.call(
            Syscall::N_fallocate,
            [fd as i64, mode as i64, offset, len, 0, 0],
        );
        let builder = self.event(Syscall::N_fallocate, result);
        self.fd_arg(builder, "fd", fd)
            .arg("mode", mode)
            .arg("offset", offset)
            .arg("len", len)
            .emit();
        result
    }

    // ---- filesystem statistics -------------------------------------------------

    /// The `statfs` members every filesystem answers the same way; the rest
    /// (type, sizes, counts, fsid) are the host filesystem's business and are
    /// left to the scenario's relation checks.
    pub(super) fn statfs_fields<'a>(
        &self,
        builder: EventBuilder<'a>,
        st: &Statfs,
    ) -> EventBuilder<'a> {
        builder
            .field("namelen", st.f_namelen)
            .field("st_valid", st.f_flags & ST_VALID != 0)
            .field("rdonly", st.f_flags & libc::ST_RDONLY as i64 != 0)
    }

    /// `statfs(path)`; `null` passes a NULL buffer.
    pub fn statfs(&self, path: &str, null: bool) -> (i64, Option<Statfs>) {
        let c = cstr(path);
        let mut st = Statfs::default();
        let buf = if null {
            0
        } else {
            &mut st as *mut Statfs as i64
        };
        let result = self.call(Syscall::N_statfs, [c.as_ptr() as i64, buf, 0, 0, 0, 0]);
        let builder = self
            .event(Syscall::N_statfs, result)
            .arg("path", path)
            .arg("buf", if null { "NULL" } else { "buf" });
        let ok = result >= 0 && !null;
        if ok {
            self.statfs_fields(builder, &st).emit();
        } else {
            builder.emit();
        }
        (result, ok.then_some(st))
    }

    pub fn fstatfs(&self, fd: i32, null: bool) -> (i64, Option<Statfs>) {
        let mut st = Statfs::default();
        let buf = if null {
            0
        } else {
            &mut st as *mut Statfs as i64
        };
        let result = self.call(Syscall::N_fstatfs, [fd as i64, buf, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_fstatfs, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("buf", if null { "NULL" } else { "buf" });
        let ok = result >= 0 && !null;
        if ok {
            self.statfs_fields(builder, &st).emit();
        } else {
            builder.emit();
        }
        (result, ok.then_some(st))
    }

    /// `ustat(dev, ubuf)` (x86_64 only; the generic table has no row). The
    /// device number is the host's, so it is recorded by `label`.
    #[cfg(target_arch = "x86_64")]
    pub fn ustat(&self, dev: u64, label: &str, null: bool) -> i64 {
        let mut buf = [0u8; 64];
        let pointer = if null { 0 } else { buf.as_mut_ptr() as i64 };
        let result = self.call(Syscall::N_ustat, [dev as i64, pointer, 0, 0, 0, 0]);
        self.event(Syscall::N_ustat, result)
            .arg("dev", label)
            .arg("buf", if null { "NULL" } else { "buf" })
            .emit();
        result
    }

    // ---- extended attributes ---------------------------------------------------

    fn xattr_row(target: XattrTarget<'_>, path: Syscall, link: Syscall, fd: Syscall) -> Syscall {
        match target {
            XattrTarget::Path(_) | XattrTarget::NullPath => path,
            XattrTarget::Link(_) => link,
            XattrTarget::Fd(_) => fd,
        }
    }

    /// The first argument of an xattr row (a path or a descriptor), recorded.
    fn xattr_target<'a>(
        &self,
        builder: EventBuilder<'a>,
        target: XattrTarget<'_>,
    ) -> EventBuilder<'a> {
        match target {
            XattrTarget::Path(path) | XattrTarget::Link(path) => builder.arg("path", path),
            XattrTarget::Fd(fd) => self.fd_arg(builder, "fd", fd),
            XattrTarget::NullPath => builder.arg("path", "NULL"),
        }
    }

    fn xattr_call(&self, row: Syscall, target: XattrTarget<'_>, rest: [i64; 4]) -> i64 {
        let path = match target {
            XattrTarget::Path(path) | XattrTarget::Link(path) => Some(cstr(path)),
            XattrTarget::Fd(_) | XattrTarget::NullPath => None,
        };
        let first = match (&path, target) {
            (Some(c), _) => c.as_ptr() as i64,
            (None, XattrTarget::Fd(fd)) => fd as i64,
            (None, XattrTarget::NullPath) => 0,
            (None, _) => unreachable!("a path target has a path"),
        };
        self.call(row, [first, rest[0], rest[1], rest[2], rest[3], 0])
    }

    /// `setxattr`/`lsetxattr`/`fsetxattr`; a `None` value is a NULL pointer
    /// with `size` still passed.
    pub fn setxattr(
        &self,
        target: XattrTarget<'_>,
        name: &str,
        value: Option<&[u8]>,
        size: usize,
        flags: i32,
    ) -> i64 {
        let row = Self::xattr_row(
            target,
            Syscall::N_setxattr,
            Syscall::N_lsetxattr,
            Syscall::N_fsetxattr,
        );
        let c = cstr(name);
        let result = self.xattr_call(
            row,
            target,
            [
                c.as_ptr() as i64,
                value.map_or(0, |v| v.as_ptr() as i64),
                size as i64,
                flags as i64,
            ],
        );
        let builder = self.xattr_target(self.event(row, result), target);
        builder
            .arg("name", name)
            .arg("value", value.map_or("NULL".to_string(), printable))
            .arg("size", size)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `getxattr`/`lgetxattr`/`fgetxattr` into a `size`-byte buffer (`size` 0
    /// asks for the value's length); the value is recorded.
    pub fn getxattr(&self, target: XattrTarget<'_>, name: &str, size: usize) -> (i64, Vec<u8>) {
        let row = Self::xattr_row(
            target,
            Syscall::N_getxattr,
            Syscall::N_lgetxattr,
            Syscall::N_fgetxattr,
        );
        let c = cstr(name);
        let mut buf = vec![0u8; size.max(1)];
        let result = self.xattr_call(
            row,
            target,
            [c.as_ptr() as i64, buf.as_mut_ptr() as i64, size as i64, 0],
        );
        let value = if result >= 0 && size > 0 {
            buf[..result as usize].to_vec()
        } else {
            Vec::new()
        };
        let builder = self.xattr_target(self.event(row, result), target);
        let builder = builder.arg("name", name).arg("size", size);
        let builder = if result >= 0 && size > 0 {
            builder.field("value", printable(&value))
        } else {
            builder
        };
        builder.emit();
        (result, value)
    }

    /// `listxattr`/`llistxattr`/`flistxattr` into a `size`-byte buffer; the
    /// names are recorded sorted (listing order is the filesystem's).
    pub fn listxattr(&self, target: XattrTarget<'_>, size: usize) -> (i64, Vec<String>) {
        let row = Self::xattr_row(
            target,
            Syscall::N_listxattr,
            Syscall::N_llistxattr,
            Syscall::N_flistxattr,
        );
        let mut buf = vec![0u8; size.max(1)];
        let result = self.xattr_call(row, target, [buf.as_mut_ptr() as i64, size as i64, 0, 0]);
        let mut names: Vec<String> = if result > 0 && size > 0 {
            buf[..result as usize]
                .split(|&b| b == 0)
                .filter(|name| !name.is_empty())
                .map(|name| String::from_utf8_lossy(name).into_owned())
                .collect()
        } else {
            Vec::new()
        };
        names.sort();
        let builder = self.xattr_target(self.event(row, result), target);
        let builder = builder.arg("size", size);
        let builder = if result >= 0 && size > 0 {
            builder.field("names", names.clone())
        } else {
            builder
        };
        builder.emit();
        (result, names)
    }

    pub fn removexattr(&self, target: XattrTarget<'_>, name: &str) -> i64 {
        let row = Self::xattr_row(
            target,
            Syscall::N_removexattr,
            Syscall::N_lremovexattr,
            Syscall::N_fremovexattr,
        );
        let c = cstr(name);
        let result = self.xattr_call(row, target, [c.as_ptr() as i64, 0, 0, 0]);
        self.xattr_target(self.event(row, result), target)
            .arg("name", name)
            .emit();
        result
    }

    // ---- inotify -------------------------------------------------------------

    /// `inotify_init()` (x86_64 only; the generic table spells it
    /// `inotify_init1(0)`).
    #[cfg(target_arch = "x86_64")]
    pub fn inotify_init(&self) -> i32 {
        let result = self.call(Syscall::N_inotify_init, [0; 6]);
        self.event(Syscall::N_inotify_init, result)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn inotify_init1(&self, flags: i32) -> i32 {
        let result = self.call(Syscall::N_inotify_init1, [flags as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_inotify_init1, result)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `inotify_add_watch`; the watch descriptor is an allocated number.
    pub fn inotify_add_watch(&self, fd: i32, path: &str, mask: u32) -> i32 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_inotify_add_watch,
            [fd as i64, c.as_ptr() as i64, mask as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_inotify_add_watch, result);
        self.fd_arg(builder, "fd", fd)
            .arg("path", path)
            .arg("mask", mask)
            .norm("ret", Norm::Relative("wd"))
            .emit();
        result as i32
    }

    pub fn inotify_rm_watch(&self, fd: i32, wd: i32) -> i64 {
        let result = self.call(
            Syscall::N_inotify_rm_watch,
            [fd as i64, wd as i64, 0, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_inotify_rm_watch, result);
        let builder = self.fd_arg(builder, "fd", fd).arg("wd", wd);
        let builder = if wd > 0 {
            builder.norm("args.wd", Norm::Relative("wd"))
        } else {
            builder
        };
        builder.emit();
        result
    }

    /// A `read` of an inotify descriptor, decoded: per event its watch
    /// descriptor (an allocated number), mask, name, and whether a cookie was
    /// set (cookie values are the kernel's business; the scenario checks
    /// their relations).
    pub fn inotify_read(&self, fd: i32, bufsize: usize) -> (i64, Vec<InotifyEvent>) {
        const HEADER: usize = std::mem::size_of::<libc::inotify_event>();
        let mut buf = vec![0u8; bufsize];
        let result = self.call(
            Syscall::N_read,
            [fd as i64, buf.as_mut_ptr() as i64, bufsize as i64, 0, 0, 0],
        );
        let mut events = Vec::new();
        let mut offset = 0usize;
        let total = result.max(0) as usize;
        while offset + HEADER <= total {
            let word = |at: usize| {
                u32::from_ne_bytes([
                    buf[offset + at],
                    buf[offset + at + 1],
                    buf[offset + at + 2],
                    buf[offset + at + 3],
                ])
            };
            let len = word(12) as usize;
            let name = &buf[offset + HEADER..(offset + HEADER + len).min(total)];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            events.push(InotifyEvent {
                wd: word(0) as i32,
                mask: word(4),
                cookie: word(8),
                name: String::from_utf8_lossy(&name[..end]).into_owned(),
            });
            offset += HEADER + len;
        }
        let builder = self.rec.event("read", result);
        let mut builder = self.fd_arg(builder, "fd", fd).arg("len", bufsize);
        if result >= 0 {
            builder = builder.field("count", events.len());
            for (index, event) in events.iter().enumerate() {
                builder = builder
                    .field(&format!("wd{index}"), event.wd)
                    .norm(&format!("fields.wd{index}"), Norm::Relative("wd"))
                    .field(&format!("mask{index}"), format!("{:#x}", event.mask))
                    .field(&format!("name{index}"), event.name.as_str())
                    .field(&format!("cookie{index}"), event.cookie != 0);
            }
        }
        builder.emit();
        (result, events)
    }

    // ---- page-cache advice -------------------------------------------------------

    pub fn readahead(&self, fd: i32, offset: i64, count: usize) -> i64 {
        self.fd_ints(
            Syscall::N_readahead,
            fd,
            &["offset", "count"],
            &[offset, count as i64],
        )
    }

    /// `fadvise64(fd, offset, len, advice)` (the generic table's
    /// `fadvise64_64`, same argument order on a 64-bit kernel).
    pub fn fadvise64(&self, fd: i32, offset: i64, len: i64, advice: i32) -> i64 {
        self.fd_ints(
            Syscall::N_fadvise64,
            fd,
            &["offset", "len", "advice"],
            &[offset, len, advice as i64],
        )
    }

    /// `cachestat(fd, range, out, flags)`; `None` range/out pass NULL. The
    /// counters are returned for the scenario's relation checks, never
    /// recorded.
    pub fn cachestat(
        &self,
        fd: i32,
        range: Option<(u64, u64)>,
        out: bool,
        flags: u32,
    ) -> (i64, Cachestat) {
        let span = range.map(|(off, len)| [off, len]);
        let mut stat = Cachestat::default();
        let result = self.call(
            Syscall::N_cachestat,
            [
                fd as i64,
                span.as_ref().map_or(0, |s| s.as_ptr() as i64),
                if out {
                    &mut stat as *mut Cachestat as i64
                } else {
                    0
                },
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.fd_arg(self.event(Syscall::N_cachestat, result), "fd", fd);
        let builder = match range {
            Some((off, len)) => builder.arg("off", off).arg("len", len),
            None => builder.arg("range", "NULL"),
        };
        builder
            .arg("out", if out { "buf" } else { "NULL" })
            .arg("flags", flags)
            .emit();
        (result, stat)
    }

    // ---- file handles --------------------------------------------------------

    /// `name_to_handle_at(dirfd, path, handle, mount_id, flags)` with a handle
    /// buffer declaring `handle_bytes`. Returns the result, the handle bytes
    /// the kernel reported (the required size on EOVERFLOW), the handle
    /// (type then bytes) and the mount id. Sizes, handles and mount ids are
    /// the filesystem's business: only whether a size was reported is
    /// recorded, and the declared size is compared by relation because a
    /// scenario may declare the size the filesystem reported; the scenario
    /// checks the rest.
    pub fn name_to_handle_at(
        &self,
        dirfd: i32,
        path: &str,
        handle_bytes: u32,
        flags: i32,
    ) -> (i64, u32, Vec<u8>, i32) {
        const HANDLE_BYTES: usize = FileHandle::MAX as usize;
        let c = cstr(path);
        let mut handle = FileHandle::declaring(handle_bytes);
        let mut mount_id: i32 = 0;
        let result = self.call(
            Syscall::N_name_to_handle_at,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                &mut handle as *mut FileHandle as i64,
                &mut mount_id as *mut i32 as i64,
                flags as i64,
                0,
            ],
        );
        let reported = handle.bytes;
        let mut identity = handle.kind.to_ne_bytes().to_vec();
        if result >= 0 {
            identity.extend_from_slice(&handle.data[..(reported as usize).min(HANDLE_BYTES)]);
        }
        let builder = self.event(Syscall::N_name_to_handle_at, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("handle_bytes", handle_bytes)
            .norm("args.handle_bytes", Norm::Relative("handle_bytes"))
            .arg("flags", flags);
        let builder = if result == neg(libc::EOVERFLOW) {
            builder.field(
                "size_reported",
                reported > 0 && reported <= HANDLE_BYTES as u32,
            )
        } else {
            builder
        };
        builder.emit();
        (result, reported, identity, mount_id)
    }
}
