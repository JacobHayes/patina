//! Filesystem path and namespace rows.

use super::*;

impl Probe {
    // ---- filesystem ---------------------------------------------------------

    pub fn openat(&self, dirfd: i32, path: &str, flags: i32, mode: u32) -> i32 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_openat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                flags as i64,
                mode as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_openat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mode", mode)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn close(&self, fd: i32) -> i64 {
        let result = self.call(Syscall::N_close, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_close, result);
        self.fd_arg(builder, "fd", fd).emit();
        result
    }

    pub fn write(&self, fd: i32, data: &[u8]) -> i64 {
        let result = self.call(
            Syscall::N_write,
            [fd as i64, data.as_ptr() as i64, data.len() as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_write, result);
        self.fd_arg(builder, "fd", fd).arg("len", data.len()).emit();
        result
    }

    pub fn read(&self, fd: i32, len: usize) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let result = self.call(
            Syscall::N_read,
            [fd as i64, buf.as_mut_ptr() as i64, len as i64, 0, 0, 0],
        );
        let data = if result >= 0 {
            buf.truncate(result as usize);
            buf
        } else {
            Vec::new()
        };
        let builder = self.event(Syscall::N_read, result);
        let builder = self.fd_arg(builder, "fd", fd).arg("len", len);
        let builder = if result >= 0 {
            builder.field("data", printable(&data))
        } else {
            builder
        };
        builder.emit();
        (result, data)
    }

    pub fn lseek(&self, fd: i32, offset: i64, whence: i32) -> i64 {
        let result = self.call(
            Syscall::N_lseek,
            [fd as i64, offset, whence as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_lseek, result);
        self.fd_arg(builder, "fd", fd)
            .arg("offset", offset)
            .arg("whence", whence)
            .emit();
        result
    }

    // `st_nlink`/`stx_nlink` are u64 on x86_64 and u32 on aarch64: the cast is
    // a widening on one arch and identity on the other.
    #[allow(clippy::unnecessary_cast)]
    pub(super) fn view_of(st: &libc::stat) -> StatView {
        StatView {
            kind: kind_of(st.st_mode),
            perm: st.st_mode & 0o7777,
            nlink: st.st_nlink as u64,
            size: st.st_size,
            uid: st.st_uid,
            gid: st.st_gid,
            ino: st.st_ino,
            dev: st.st_dev,
            atime_ns: st.st_atime as i128 * 1_000_000_000 + st.st_atime_nsec as i128,
            mtime_ns: st.st_mtime as i128 * 1_000_000_000 + st.st_mtime_nsec as i128,
            ctime_ns: st.st_ctime as i128 * 1_000_000_000 + st.st_ctime_nsec as i128,
            btime_ns: None,
            blocks: st.st_blocks as i64,
        }
    }

    pub fn fstat(&self, fd: i32) -> (i64, Option<StatView>) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_fstat,
            [fd as i64, &mut st as *mut libc::stat as i64, 0, 0, 0, 0],
        );
        let view = (result >= 0).then(|| Self::view_of(&st));
        let builder = self.event(Syscall::N_fstat, result);
        let builder = self.fd_arg(builder, "fd", fd);
        match &view {
            Some(view) => self.stat_fields(builder, view).emit(),
            None => builder.emit(),
        }
        (result, view)
    }

    pub fn newfstatat(&self, dirfd: i32, path: &str, flags: i32) -> (i64, Option<StatView>) {
        let c = cstr(path);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_newfstatat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                &mut st as *mut libc::stat as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let view = (result >= 0).then(|| Self::view_of(&st));
        let builder = self.event(Syscall::N_newfstatat, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags);
        match &view {
            Some(view) => self.stat_fields(builder, view).emit(),
            None => builder.emit(),
        }
        (result, view)
    }

    /// `statx`; the raw returned mask is recorded for diagnosis and compared
    /// through a mask of the requested and recorded fields' validity bits.
    /// Struct members are recorded through the shared stat view.
    #[allow(clippy::unnecessary_cast)]
    pub fn statx(
        &self,
        dirfd: i32,
        path: &str,
        flags: i32,
        mask: u32,
    ) -> (i64, Option<StatView>, u32) {
        let c = cstr(path);
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_statx,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                flags as i64,
                mask as i64,
                &mut stx as *mut libc::statx as i64,
                0,
            ],
        );
        let view = (result >= 0).then(|| StatView {
            kind: kind_of(stx.stx_mode as u32),
            perm: stx.stx_mode as u32 & 0o7777,
            nlink: stx.stx_nlink as u64,
            size: stx.stx_size as i64,
            uid: stx.stx_uid,
            gid: stx.stx_gid,
            ino: stx.stx_ino,
            dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
            atime_ns: stx.stx_atime.tv_sec as i128 * 1_000_000_000 + stx.stx_atime.tv_nsec as i128,
            mtime_ns: stx.stx_mtime.tv_sec as i128 * 1_000_000_000 + stx.stx_mtime.tv_nsec as i128,
            ctime_ns: stx.stx_ctime.tv_sec as i128 * 1_000_000_000 + stx.stx_ctime.tv_nsec as i128,
            btime_ns: (stx.stx_mask & libc::STATX_BTIME != 0).then(|| {
                stx.stx_btime.tv_sec as i128 * 1_000_000_000 + stx.stx_btime.tv_nsec as i128
            }),
            blocks: stx.stx_blocks as i64,
        });
        let builder = self.event(Syscall::N_statx, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mask", mask);
        match &view {
            Some(view) => {
                // statx(2): the returned mask may carry validity bits the call
                // did not request; the bits compared are the requested ones and
                // those of every field recorded here (values compare regardless).
                let recorded = libc::STATX_TYPE
                    | libc::STATX_MODE
                    | libc::STATX_NLINK
                    | libc::STATX_UID
                    | libc::STATX_GID
                    | libc::STATX_INO
                    | libc::STATX_BTIME
                    | if view.kind == "dir" {
                        0
                    } else {
                        libc::STATX_SIZE
                    };
                self.stat_fields(builder, view)
                    .field("mask", stx.stx_mask)
                    .norm("fields.mask", Norm::Mask(u64::from(mask | recorded)))
                    .field("btime_present", stx.stx_mask & libc::STATX_BTIME != 0)
                    .emit()
            }
            None => builder.emit(),
        }
        (result, view, stx.stx_mask)
    }

    /// One listing call over `bufsize` bytes through `row`: `getdents64`, or
    /// x86_64's legacy `getdents`. Entries decoded as `name:type` and recorded
    /// SORTED (listing order is the host's business).
    pub fn getdents(&self, row: Syscall, fd: i32, bufsize: usize) -> (i64, Vec<(String, u8)>) {
        let mut buf = vec![0u8; bufsize];
        let result = self.call(
            row,
            [fd as i64, buf.as_mut_ptr() as i64, bufsize as i64, 0, 0, 0],
        );
        let records = &buf[..result.max(0) as usize];
        let decoded = match row {
            // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen;
            // u8 d_type; char d_name[]; }
            Syscall::N_getdents64 => decode_dirents(records, 19, |record| record[18]),
            // struct linux_dirent { unsigned long d_ino; unsigned long d_off;
            // unsigned short d_reclen; char d_name[]; /* pad; char d_type */ }
            #[cfg(target_arch = "x86_64")]
            Syscall::N_getdents => decode_dirents(records, 18, |record| record[record.len() - 1]),
            other => panic!("{}: not a directory listing row", other.name()),
        };
        let mut entries: Vec<(String, u8)> = decoded
            .into_iter()
            .map(|entry| (entry.name, entry.kind))
            .collect();
        entries.sort();
        let rendered: Vec<Value> = entries
            .iter()
            .map(|(name, kind)| Value::from(format!("{name}:{kind}")))
            .collect();
        let builder = self.event(row, result);
        let builder = self.fd_arg(builder, "fd", fd).arg("bufsize", bufsize);
        let builder = if result >= 0 {
            builder.field("entries", Value::Array(rendered))
        } else {
            builder
        };
        builder.emit();
        (result, entries)
    }

    pub fn mkdirat(&self, dirfd: i32, path: &str, mode: u32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_mkdirat,
            [dirfd as i64, c.as_ptr() as i64, mode as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_mkdirat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    pub fn unlinkat(&self, dirfd: i32, path: &str, flags: i32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_unlinkat,
            [dirfd as i64, c.as_ptr() as i64, flags as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_unlinkat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags)
            .emit();
        result
    }

    pub fn renameat(&self, olddirfd: i32, old: &str, newdirfd: i32, new: &str) -> i64 {
        let co = cstr(old);
        let cn = cstr(new);
        let result = self.call(
            Syscall::N_renameat,
            [
                olddirfd as i64,
                co.as_ptr() as i64,
                newdirfd as i64,
                cn.as_ptr() as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_renameat, result);
        let builder = self.fd_arg(builder, "olddirfd", olddirfd).arg("old", old);
        // rename(2): a nonempty destination directory is EEXIST or ENOTEMPTY
        // (ENOTDIR, a directory onto a file, is not among them).
        self.fd_arg(builder, "newdirfd", newdirfd)
            .arg("new", new)
            .norm("errno", Norm::Alternatives(&["EEXIST", "ENOTEMPTY"]))
            .emit();
        result
    }

    pub fn symlinkat(&self, target: &str, dirfd: i32, path: &str) -> i64 {
        let ct = cstr(target);
        let cp = cstr(path);
        let result = self.call(
            Syscall::N_symlinkat,
            [
                ct.as_ptr() as i64,
                dirfd as i64,
                cp.as_ptr() as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self
            .event(Syscall::N_symlinkat, result)
            .arg("target", target);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .emit();
        result
    }

    pub fn readlinkat(&self, dirfd: i32, path: &str, bufsize: usize) -> (i64, String) {
        self.readlinkat_with_buffer(dirfd, path, bufsize, bufsize)
    }

    /// `readlinkat` with a register-sized argument and a separately bounded
    /// backing buffer, for kernel ABIs that narrow `bufsize` before copying.
    pub fn readlinkat_with_buffer(
        &self,
        dirfd: i32,
        path: &str,
        bufsize: usize,
        buffer_size: usize,
    ) -> (i64, String) {
        let c = cstr(path);
        let mut buf = vec![0u8; buffer_size.max(1)];
        let result = self.call(
            Syscall::N_readlinkat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                buf.as_mut_ptr() as i64,
                bufsize as i64,
                0,
                0,
            ],
        );
        let target = if result >= 0 {
            String::from_utf8_lossy(&buf[..result as usize]).into_owned()
        } else {
            String::new()
        };
        let builder = self.event(Syscall::N_readlinkat, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("bufsize", bufsize);
        let builder = if result >= 0 {
            builder.field("target", target.as_str())
        } else {
            builder
        };
        builder.emit();
        (result, target)
    }

    pub fn linkat(&self, olddirfd: i32, old: &str, newdirfd: i32, new: &str, flags: i32) -> i64 {
        let co = cstr(old);
        let cn = cstr(new);
        let result = self.call(
            Syscall::N_linkat,
            [
                olddirfd as i64,
                co.as_ptr() as i64,
                newdirfd as i64,
                cn.as_ptr() as i64,
                flags as i64,
                0,
            ],
        );
        let builder = self.event(Syscall::N_linkat, result);
        let builder = self.fd_arg(builder, "olddirfd", olddirfd).arg("old", old);
        self.fd_arg(builder, "newdirfd", newdirfd)
            .arg("new", new)
            .arg("flags", flags)
            .emit();
        result
    }

    // ---- the working directory and the umask --------------------------------

    /// `getcwd` into a `size`-byte buffer. Success is recorded as `ret` 0 on
    /// every vehicle (glibc answers a pointer, the kernel a length) with the
    /// directory in `fields.path`; `size` is an argument so ERANGE is legible.
    pub fn getcwd(&self, size: usize) -> (i64, String) {
        let mut buf = vec![0u8; size.max(1)];
        let result = self.call(
            Syscall::N_getcwd,
            [buf.as_mut_ptr() as i64, size as i64, 0, 0, 0, 0],
        );
        let path = if result >= 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..end]).into_owned()
        } else {
            String::new()
        };
        let normalized = if result >= 0 { 0 } else { result };
        let builder = self.event(Syscall::N_getcwd, normalized).arg("size", size);
        let builder = if result >= 0 {
            builder.field("path", path.as_str())
        } else {
            builder
        };
        builder.emit();
        (normalized, path)
    }

    pub fn chdir(&self, path: &str) -> i64 {
        let c = cstr(path);
        let result = self.call(Syscall::N_chdir, [c.as_ptr() as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_chdir, result)
            .arg("path", path)
            .emit();
        result
    }

    pub fn fchdir(&self, fd: i32) -> i64 {
        let result = self.call(Syscall::N_fchdir, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_fchdir, result);
        self.fd_arg(builder, "fd", fd).emit();
        result
    }

    /// `umask`: the previous mask is the result (never an errno).
    pub fn umask(&self, mask: u32) -> i64 {
        let result = self.call(Syscall::N_umask, [mask as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_umask, result)
            .arg("mask", mask)
            .emit();
        result
    }

    pub fn mknodat(&self, dirfd: i32, path: &str, mode: u32, dev: u64) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_mknodat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                mode as i64,
                dev as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_mknodat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .arg("dev", dev)
            .emit();
        result
    }

    // ---- the legacy path rows ------------------------------------------------
    //
    // x86_64 keeps the pre-`*at` numbers; the generic (arm64) table has none of
    // them, and there the kernel shape is the `*at` row with `AT_FDCWD`
    // (glibc's own spelling) while the libc vehicle calls the same wrapper.

    /// `open(2)`; the result is a descriptor.
    pub fn open(&self, path: &str, flags: i32, mode: u32) -> i32 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_open,
            [c.as_ptr() as i64, flags as i64, mode as i64, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) } as i64,
            Syscall::N_openat,
            [
                AT_FDCWD as i64,
                c.as_ptr() as i64,
                flags as i64,
                mode as i64,
                0,
                0,
            ],
        );
        self.rec
            .event("open", result)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mode", mode)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `creat(2)`: `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
    pub fn creat(&self, path: &str, mode: u32) -> i32 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_creat,
            [c.as_ptr() as i64, mode as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::creat(c.as_ptr(), mode) } as i64,
            Syscall::N_openat,
            [
                AT_FDCWD as i64,
                c.as_ptr() as i64,
                (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as i64,
                mode as i64,
                0,
                0,
            ],
        );
        self.rec
            .event("creat", result)
            .arg("path", path)
            .arg("mode", mode)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `stat(2)` (`follow`) or `lstat(2)`, recorded like `newfstatat`.
    pub fn stat(&self, path: &str, follow: bool) -> (i64, Option<StatView>) {
        let c = cstr(path);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let buf = &mut st as *mut libc::stat as i64;
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            if follow {
                Syscall::N_stat
            } else {
                Syscall::N_lstat
            },
            [c.as_ptr() as i64, buf, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path and a stat buffer.
            || unsafe {
                if follow {
                    libc::stat(c.as_ptr(), buf as *mut libc::stat)
                } else {
                    libc::lstat(c.as_ptr(), buf as *mut libc::stat)
                }
            } as i64,
            Syscall::N_newfstatat,
            [
                AT_FDCWD as i64,
                c.as_ptr() as i64,
                buf,
                if follow {
                    0
                } else {
                    libc::AT_SYMLINK_NOFOLLOW as i64
                },
                0,
                0,
            ],
        );
        let view = (result >= 0).then(|| Self::view_of(&st));
        let builder = self
            .rec
            .event(if follow { "stat" } else { "lstat" }, result)
            .arg("path", path);
        match &view {
            Some(view) => self.stat_fields(builder, view).emit(),
            None => builder.emit(),
        }
        (result, view)
    }

    /// `rename(2)`; a nonempty destination directory is one of rename(2)'s
    /// documented pair, as for `renameat`. The pair is declared on every call,
    /// but no other rename outcome is EEXIST or ENOTEMPTY, so it loosens
    /// nothing else (EISDIR, ENOTDIR, EINVAL still compare exactly).
    pub fn rename(&self, old: &str, new: &str) -> i64 {
        let co = cstr(old);
        let cn = cstr(new);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_rename,
            [co.as_ptr() as i64, cn.as_ptr() as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: NUL-terminated paths.
            || unsafe { libc::rename(co.as_ptr(), cn.as_ptr()) } as i64,
            Syscall::N_renameat,
            [
                AT_FDCWD as i64,
                co.as_ptr() as i64,
                AT_FDCWD as i64,
                cn.as_ptr() as i64,
                0,
                0,
            ],
        );
        self.rec
            .event("rename", result)
            .arg("old", old)
            .arg("new", new)
            .norm("errno", Norm::Alternatives(&["EEXIST", "ENOTEMPTY"]))
            .emit();
        result
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> i64 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_mkdir,
            [c.as_ptr() as i64, mode as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::mkdir(c.as_ptr(), mode) } as i64,
            Syscall::N_mkdirat,
            [AT_FDCWD as i64, c.as_ptr() as i64, mode as i64, 0, 0, 0],
        );
        self.rec
            .event("mkdir", result)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    /// `rmdir(2)`: `unlinkat(AT_FDCWD, path, AT_REMOVEDIR)` in the generic table.
    pub fn rmdir(&self, path: &str) -> i64 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_rmdir, [c.as_ptr() as i64, 0, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::rmdir(c.as_ptr()) } as i64,
            Syscall::N_unlinkat,
            [
                AT_FDCWD as i64,
                c.as_ptr() as i64,
                libc::AT_REMOVEDIR as i64,
                0,
                0,
                0,
            ],
        );
        self.rec.event("rmdir", result).arg("path", path).emit();
        result
    }

    pub fn unlink(&self, path: &str) -> i64 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_unlink, [c.as_ptr() as i64, 0, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::unlink(c.as_ptr()) } as i64,
            Syscall::N_unlinkat,
            [AT_FDCWD as i64, c.as_ptr() as i64, 0, 0, 0, 0],
        );
        self.rec.event("unlink", result).arg("path", path).emit();
        result
    }

    pub fn link(&self, old: &str, new: &str) -> i64 {
        let co = cstr(old);
        let cn = cstr(new);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_link,
            [co.as_ptr() as i64, cn.as_ptr() as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: NUL-terminated paths.
            || unsafe { libc::link(co.as_ptr(), cn.as_ptr()) } as i64,
            Syscall::N_linkat,
            [
                AT_FDCWD as i64,
                co.as_ptr() as i64,
                AT_FDCWD as i64,
                cn.as_ptr() as i64,
                0,
                0,
            ],
        );
        self.rec
            .event("link", result)
            .arg("old", old)
            .arg("new", new)
            .emit();
        result
    }

    pub fn symlink(&self, target: &str, path: &str) -> i64 {
        let ct = cstr(target);
        let cp = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_symlink,
            [ct.as_ptr() as i64, cp.as_ptr() as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: NUL-terminated paths.
            || unsafe { libc::symlink(ct.as_ptr(), cp.as_ptr()) } as i64,
            Syscall::N_symlinkat,
            [
                ct.as_ptr() as i64,
                AT_FDCWD as i64,
                cp.as_ptr() as i64,
                0,
                0,
                0,
            ],
        );
        self.rec
            .event("symlink", result)
            .arg("target", target)
            .arg("path", path)
            .emit();
        result
    }

    pub fn readlink(&self, path: &str, bufsize: usize) -> (i64, String) {
        self.readlink_with_buffer(path, bufsize, bufsize)
    }

    /// `readlink` with a register-sized argument and a separately bounded
    /// backing buffer.
    pub fn readlink_with_buffer(
        &self,
        path: &str,
        bufsize: usize,
        buffer_size: usize,
    ) -> (i64, String) {
        let c = cstr(path);
        let mut buf = vec![0u8; buffer_size.max(1)];
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_readlink,
            [
                c.as_ptr() as i64,
                buf.as_mut_ptr() as i64,
                bufsize as i64,
                0,
                0,
                0,
            ],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let ptr = buf.as_mut_ptr();
            self.legacy(
                // SAFETY: a NUL-terminated path and a buffer of `bufsize` bytes.
                || unsafe { libc::readlink(c.as_ptr(), ptr as *mut libc::c_char, bufsize) } as i64,
                Syscall::N_readlinkat,
                [
                    AT_FDCWD as i64,
                    c.as_ptr() as i64,
                    ptr as i64,
                    bufsize as i64,
                    0,
                    0,
                ],
            )
        };
        let target = if result >= 0 {
            String::from_utf8_lossy(&buf[..result as usize]).into_owned()
        } else {
            String::new()
        };
        let builder = self
            .rec
            .event("readlink", result)
            .arg("path", path)
            .arg("bufsize", bufsize);
        let builder = if result >= 0 {
            builder.field("target", target.as_str())
        } else {
            builder
        };
        builder.emit();
        (result, target)
    }

    /// `chmod(2)`: `fchmodat(AT_FDCWD, path, mode)` in the generic table.
    pub fn chmod(&self, path: &str, mode: u32) -> i64 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_chmod,
            [c.as_ptr() as i64, mode as i64, 0, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::chmod(c.as_ptr(), mode) } as i64,
            Syscall::N_fchmodat,
            [AT_FDCWD as i64, c.as_ptr() as i64, mode as i64, 0, 0, 0],
        );
        self.rec
            .event("chmod", result)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    pub fn mknod(&self, path: &str, mode: u32, dev: u64) -> i64 {
        let c = cstr(path);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_mknod,
            [c.as_ptr() as i64, mode as i64, dev as i64, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a NUL-terminated path.
            || unsafe { libc::mknod(c.as_ptr(), mode, dev) } as i64,
            Syscall::N_mknodat,
            [
                AT_FDCWD as i64,
                c.as_ptr() as i64,
                mode as i64,
                dev as i64,
                0,
                0,
            ],
        );
        self.rec
            .event("mknod", result)
            .arg("path", path)
            .arg("mode", mode)
            .arg("dev", dev)
            .emit();
        result
    }

    // ---- permission bits and renameat2 ----------------------------------------

    pub fn fchmod(&self, fd: i32, mode: u32) -> i64 {
        self.fd_ints(Syscall::N_fchmod, fd, &["mode"], &[mode as i64])
    }

    /// `fchmodat(dirfd, path, mode)`: the kernel row has no flags argument.
    pub fn fchmodat(&self, dirfd: i32, path: &str, mode: u32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_fchmodat,
            [dirfd as i64, c.as_ptr() as i64, mode as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_fchmodat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    /// `fchmodat2(dirfd, path, mode, flags)`, the row that carries flags.
    pub fn fchmodat2(&self, dirfd: i32, path: &str, mode: u32, flags: i32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Syscall::N_fchmodat2,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                mode as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_fchmodat2, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `renameat2`. With neither `RENAME_NOREPLACE` nor `RENAME_EXCHANGE` a
    /// nonempty destination directory is one of rename(2)'s documented pair
    /// (the filesystem chooses); with either flag the refusals are the VFS's
    /// own and compare exactly.
    pub fn renameat2(&self, olddirfd: i32, old: &str, newdirfd: i32, new: &str, flags: u32) -> i64 {
        let co = cstr(old);
        let cn = cstr(new);
        let result = self.call(
            Syscall::N_renameat2,
            [
                olddirfd as i64,
                co.as_ptr() as i64,
                newdirfd as i64,
                cn.as_ptr() as i64,
                flags as i64,
                0,
            ],
        );
        let builder = self.event(Syscall::N_renameat2, result);
        let builder = self.fd_arg(builder, "olddirfd", olddirfd).arg("old", old);
        let builder = self
            .fd_arg(builder, "newdirfd", newdirfd)
            .arg("new", new)
            .arg("flags", flags);
        let vfs_judged = flags & (libc::RENAME_NOREPLACE | libc::RENAME_EXCHANGE) != 0;
        let builder = if vfs_judged {
            builder
        } else {
            builder.norm("errno", Norm::Alternatives(&["EEXIST", "ENOTEMPTY"]))
        };
        builder.emit();
        result
    }

    // ---- openat2 -------------------------------------------------------------

    /// `openat2(dirfd, path, how, size)`: `how` is `(flags, mode, resolve)`
    /// followed by `trailing` in the next u64 (read by the kernel only when
    /// `size` covers it), in a zeroed page-sized buffer, so any `size` up to a
    /// page is readable memory and a larger one is refused unread.
    ///
    /// A lookup scoped by `RESOLVE_BENEATH` or `RESOLVE_IN_ROOT` answers
    /// EAGAIN when a rename or mount anywhere on the system races one of its
    /// `..` steps, and openat2(2) tells the caller to retry: v6.8 fs/namei.c
    /// `handle_dots` returns -EAGAIN under `LOOKUP_IS_SCOPED` when
    /// `mount_lock` or `rename_lock` moved since `path_init` sampled
    /// `nd->m_seq`/`nd->r_seq`. Such an answer is retried here, unrecorded,
    /// up to [`SCOPED_LOOKUP_ATTEMPTS`] times, and only the final one is
    /// recorded. The retry keys on the scoping bits alone: `RESOLVE_CACHED`'s
    /// EAGAIN (fs/open.c `build_open_flags`, with O_CREAT/O_TRUNC/O_TMPFILE)
    /// is an answer, not a race, and an unscoped call is never retried.
    pub fn openat2(
        &self,
        dirfd: i32,
        path: &str,
        how: (u64, u64, u64),
        size: usize,
        trailing: u64,
    ) -> i32 {
        let c = cstr(path);
        let mut buf = vec![0u64; page_size().div_ceil(8).max(4)];
        buf[0] = how.0;
        buf[1] = how.1;
        buf[2] = how.2;
        buf[3] = trailing;
        let scoped = how.2 & (libc::RESOLVE_BENEATH | libc::RESOLVE_IN_ROOT) != 0;
        let mut attempts = 0;
        let result = loop {
            attempts += 1;
            let result = self.call(
                Syscall::N_openat2,
                [
                    dirfd as i64,
                    c.as_ptr() as i64,
                    buf.as_ptr() as i64,
                    size as i64,
                    0,
                    0,
                ],
            );
            if !(scoped && result == neg(libc::EAGAIN) && attempts < SCOPED_LOOKUP_ATTEMPTS) {
                break result;
            }
        };
        let builder = self.event(Syscall::N_openat2, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", how.0)
            .arg("mode", how.1)
            .arg("resolve", how.2)
            .arg("size", size)
            .arg("trailing", trailing)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    // ---- directory listings ------------------------------------------------------

    /// One `getdents64` call decoded with each entry's `d_off` cookie, in the
    /// filesystem's order. Only the byte count and the number of entries are
    /// recorded: which entries a partial buffer holds, and the cookies, are
    /// the filesystem's business; the scenario checks their relations.
    pub fn getdents64_cookies(&self, fd: i32, bufsize: usize) -> (i64, Vec<Dirent>) {
        let mut buf = vec![0u8; bufsize];
        let result = self.call(
            Syscall::N_getdents64,
            [fd as i64, buf.as_mut_ptr() as i64, bufsize as i64, 0, 0, 0],
        );
        let entries = decode_dirents(&buf[..result.max(0) as usize], 19, |record| record[18]);
        let builder = self.event(Syscall::N_getdents64, result);
        let builder = self.fd_arg(builder, "fd", fd).arg("bufsize", bufsize);
        let builder = if result >= 0 {
            builder.field("count", entries.len())
        } else {
            builder
        };
        builder.emit();
        (result, entries)
    }
}
