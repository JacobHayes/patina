//! The probe-facing API: one method per row. Each method issues the call
//! through the probe's vehicle, records a typed event with the row's
//! normalizations, and returns the kernel-style result (`-errno` on failure) plus
//! whatever the probe needs to continue. Probes never format events by hand.

use crate::observe::{EventBuilder, Norm, Recorder};
use crate::vehicle::{Args, Sys, Vehicle};
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

pub const AT_FDCWD: i32 = libc::AT_FDCWD;

/// A libc spelling of a row, registered by the one probe that links it.
pub type LibcSpelling = fn(Args) -> i64;

/// The kernel's `rt_sigaction` struct on x86_64 (NOT glibc's `struct
/// sigaction`, whose field order differs): handler, flags, restorer, then the
/// 8-byte mask. A raw registration needs `SA_RESTORER` with a restorer the
/// kernel can return through, which a probe reads back from a libc-installed
/// action (`Probe::rt_sigaction_query`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelSigaction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

/// The kernel's `SA_RESTORER` flag bit (glibc hides it from `sa_flags`).
pub const SA_RESTORER: u64 = 0x0400_0000;

/// The action flags a probe compares (the kernel adds `SA_RESTORER`, which is
/// the restorer's business, not the disposition's).
pub const SA_FLAGS_COMPARED: u64 = (libc::SA_SIGINFO
    | libc::SA_RESTART
    | libc::SA_NODEFER
    | libc::SA_RESETHAND
    | libc::SA_ONSTACK) as u64;

/// One time argument of the `utimensat` family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeArg {
    /// An explicit `(tv_sec, tv_nsec)`.
    Set(i64, i64),
    /// `UTIME_NOW`.
    Now,
    /// `UTIME_OMIT`.
    Omit,
}

impl TimeArg {
    fn label(self) -> String {
        match self {
            TimeArg::Set(sec, nsec) => format!("{sec}.{nsec:09}"),
            TimeArg::Now => "UTIME_NOW".to_string(),
            TimeArg::Omit => "UTIME_OMIT".to_string(),
        }
    }
}

/// A negative errno in the kernel convention.
pub fn neg(errno: i32) -> i64 {
    -(errno as i64)
}

pub struct Probe {
    pub id: &'static str,
    pub vehicle: Vehicle,
    pub rec: Recorder,
    strict: bool,
    /// libc spellings registered by the probe for rows the shared table does
    /// not link (see `vehicle::libc_symbol`).
    libc_overrides: Mutex<HashMap<Sys, LibcSpelling>>,
}

/// The stat members the probes compare (kind and permissions split out of
/// `st_mode`; identity and inode fields normalized by the recorder).
#[derive(Clone, Debug)]
pub struct StatView {
    pub kind: &'static str,
    pub perm: u32,
    pub nlink: u64,
    pub size: i64,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    /// The timestamps, for the probe's own relation checks; never recorded
    /// as fields (absolute times are the host's business, and no
    /// normalization relates two entries' times).
    pub atime_ns: i128,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    /// `statx` only: the birth time when the mask reports one.
    pub btime_ns: Option<i128>,
}

fn kind_of(mode: u32) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFREG => "reg",
        libc::S_IFDIR => "dir",
        libc::S_IFLNK => "lnk",
        libc::S_IFIFO => "fifo",
        libc::S_IFSOCK => "sock",
        libc::S_IFCHR => "chr",
        libc::S_IFBLK => "blk",
        _ => "unknown",
    }
}

fn cstr(text: &str) -> CString {
    CString::new(text).expect("no interior NUL in probe paths")
}

fn printable(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.chars().count() > 64 {
        format!("{}…", text.chars().take(64).collect::<String>())
    } else {
        text.into_owned()
    }
}

fn sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
    let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    raw.sin_family = libc::AF_INET as libc::sa_family_t;
    raw.sin_port = addr.port().to_be();
    raw.sin_addr = libc::in_addr {
        s_addr: u32::from(*addr.ip()).to_be(),
    };
    raw
}

fn decode_sockaddr_in(raw: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr)),
        u16::from_be(raw.sin_port),
    )
}

impl Probe {
    pub fn new(id: &'static str, vehicle: Vehicle, strict: bool) -> Probe {
        Probe {
            id,
            vehicle,
            rec: Recorder::new(),
            strict,
            libc_overrides: Mutex::new(HashMap::new()),
        }
    }

    /// Register the libc spelling of a row whose symbol only this probe may
    /// link (`f` returns the kernel convention; use `vehicle::fold_errno`).
    pub fn register_libc(&self, sys: Sys, f: LibcSpelling) {
        self.libc_overrides
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(sys, f);
    }

    /// The bin-name spelling of the probe id (`fs/open_rw` → `fs-open_rw`).
    pub fn bin_name(&self) -> String {
        self.id.replace('/', "-")
    }

    /// A fresh scratch directory for this probe, created with std (unobserved)
    /// so a leftover from an earlier run never shows up in the stream. `/tmp`
    /// exists both on the host and in patina's initial image.
    pub fn scratch(&self) -> String {
        let root = format!("/tmp/syscall-conformance/{}", self.bin_name());
        self.rec.quiet(|| {
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create scratch dir");
        });
        root
    }

    /// A semantic property. Natively (`--strict`) a false check panics; under
    /// patina it is recorded (`op: check`, `ret: 0`) and the probe continues so
    /// the rest of the stream still carries information.
    pub fn check(&self, label: &str, ok: bool) -> bool {
        let ok = if std::env::var("PATINA_PROBE_BREAK")
            .ok()
            .is_some_and(|wanted| wanted == self.id || wanted == format!("{}:{label}", self.id))
        {
            !ok
        } else {
            ok
        };
        self.rec
            .event("check", if ok { 1 } else { 0 })
            .arg("label", label)
            .emit();
        if self.strict && !ok {
            panic!("{}: check failed: {label}", self.id);
        }
        ok
    }

    /// A precondition the scenario cannot continue without.
    pub fn require(&self, label: &str, ok: bool) {
        if !ok {
            panic!("{}: cannot continue: {label}", self.id);
        }
    }

    pub fn call_observed(&self, sys: Sys, args: Args) -> i64 {
        let result = self.call(sys, args);
        self.event(sys, result).emit();
        result
    }

    pub fn call_unrecorded(&self, sys: Sys, args: Args) -> i64 {
        self.call(sys, args)
    }

    pub fn record_result(&self, sys: Sys, result: i64) {
        self.event(sys, result).emit();
    }

    fn call(&self, sys: Sys, args: Args) -> i64 {
        if self.vehicle == Vehicle::Libc {
            let registered = self
                .libc_overrides
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&sys)
                .copied();
            if let Some(f) = registered {
                return f(args);
            }
        }
        self.vehicle.call(sys, args)
    }

    fn event(&self, sys: Sys, result: i64) -> EventBuilder<'_> {
        self.rec.event(sys.name(), result)
    }

    fn fd_arg<'a>(&self, builder: EventBuilder<'a>, key: &str, fd: i32) -> EventBuilder<'a> {
        if fd == AT_FDCWD {
            builder.arg(key, "AT_FDCWD")
        } else {
            builder
                .arg(key, fd)
                .norm(&format!("args.{key}"), Norm::Relative("fd"))
        }
    }

    fn stat_fields<'a>(&self, builder: EventBuilder<'a>, view: &StatView) -> EventBuilder<'a> {
        let builder = builder
            .field("kind", view.kind)
            .field("perm", view.perm)
            .field("nlink", view.nlink);
        // A directory's st_size is the filesystem's business (6 on XFS, 4096 on
        // ext4, 40+ on tmpfs); every other kind's size is a kernel fact.
        let builder = if view.kind == "dir" {
            builder
        } else {
            builder.field("size", view.size)
        };
        builder
            .field("uid", view.uid)
            .norm("fields.uid", Norm::Identity)
            .field("gid", view.gid)
            .norm("fields.gid", Norm::Identity)
            .field("ino", view.ino)
            .norm("fields.ino", Norm::Inode)
    }

    // ---- filesystem ---------------------------------------------------------

    pub fn openat(&self, dirfd: i32, path: &str, flags: i32, mode: u32) -> i32 {
        let c = cstr(path);
        let result = self.call(
            Sys::Openat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                flags as i64,
                mode as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Openat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mode", mode)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn close(&self, fd: i32) -> i64 {
        let result = self.call(Sys::Close, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Sys::Close, result);
        self.fd_arg(builder, "fd", fd).emit();
        result
    }

    pub fn write(&self, fd: i32, data: &[u8]) -> i64 {
        let result = self.call(
            Sys::Write,
            [fd as i64, data.as_ptr() as i64, data.len() as i64, 0, 0, 0],
        );
        let builder = self.event(Sys::Write, result);
        self.fd_arg(builder, "fd", fd).arg("len", data.len()).emit();
        result
    }

    pub fn read(&self, fd: i32, len: usize) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let result = self.call(
            Sys::Read,
            [fd as i64, buf.as_mut_ptr() as i64, len as i64, 0, 0, 0],
        );
        let data = if result >= 0 {
            buf.truncate(result as usize);
            buf
        } else {
            Vec::new()
        };
        let builder = self.event(Sys::Read, result);
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
        let result = self.call(Sys::Lseek, [fd as i64, offset, whence as i64, 0, 0, 0]);
        let builder = self.event(Sys::Lseek, result);
        self.fd_arg(builder, "fd", fd)
            .arg("offset", offset)
            .arg("whence", whence)
            .emit();
        result
    }

    // `st_nlink`/`stx_nlink` are u64 on x86_64 and u32 on aarch64: the cast is
    // a widening on one arch and identity on the other.
    #[allow(clippy::unnecessary_cast)]
    fn view_of(st: &libc::stat) -> StatView {
        StatView {
            kind: kind_of(st.st_mode),
            perm: st.st_mode & 0o7777,
            nlink: st.st_nlink as u64,
            size: st.st_size,
            uid: st.st_uid,
            gid: st.st_gid,
            ino: st.st_ino,
            atime_ns: st.st_atime as i128 * 1_000_000_000 + st.st_atime_nsec as i128,
            mtime_ns: st.st_mtime as i128 * 1_000_000_000 + st.st_mtime_nsec as i128,
            ctime_ns: st.st_ctime as i128 * 1_000_000_000 + st.st_ctime_nsec as i128,
            btime_ns: None,
        }
    }

    pub fn fstat(&self, fd: i32) -> (i64, Option<StatView>) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let result = self.call(
            Sys::Fstat,
            [fd as i64, &mut st as *mut libc::stat as i64, 0, 0, 0, 0],
        );
        let view = (result >= 0).then(|| Self::view_of(&st));
        let builder = self.event(Sys::Fstat, result);
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
            Sys::Newfstatat,
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
        let builder = self.event(Sys::Newfstatat, result);
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

    /// `statx`; the returned mask is recorded raw (which bits a kernel fills is
    /// a conformance fact), the struct members through the shared stat view.
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
            Sys::Statx,
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
            atime_ns: stx.stx_atime.tv_sec as i128 * 1_000_000_000 + stx.stx_atime.tv_nsec as i128,
            mtime_ns: stx.stx_mtime.tv_sec as i128 * 1_000_000_000 + stx.stx_mtime.tv_nsec as i128,
            ctime_ns: stx.stx_ctime.tv_sec as i128 * 1_000_000_000 + stx.stx_ctime.tv_nsec as i128,
            btime_ns: (stx.stx_mask & libc::STATX_BTIME != 0).then(|| {
                stx.stx_btime.tv_sec as i128 * 1_000_000_000 + stx.stx_btime.tv_nsec as i128
            }),
        });
        let builder = self.event(Sys::Statx, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags)
            .arg("mask", mask);
        match &view {
            Some(view) => self
                .stat_fields(builder, view)
                .field("mask", stx.stx_mask)
                .field("btime_present", stx.stx_mask & libc::STATX_BTIME != 0)
                .emit(),
            None => builder.emit(),
        }
        (result, view, stx.stx_mask)
    }

    /// One `getdents64` call over `bufsize` bytes; entries decoded as
    /// `name:type` and recorded SORTED (listing order is the host's business).
    pub fn getdents64(&self, fd: i32, bufsize: usize) -> (i64, Vec<(String, u8)>) {
        let mut buf = vec![0u8; bufsize];
        let result = self.call(
            Sys::Getdents64,
            [fd as i64, buf.as_mut_ptr() as i64, bufsize as i64, 0, 0, 0],
        );
        let mut entries = Vec::new();
        if result > 0 {
            let mut offset = 0usize;
            let total = result as usize;
            while offset + 19 < total {
                // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
                let reclen = u16::from_ne_bytes([buf[offset + 16], buf[offset + 17]]) as usize;
                let d_type = buf[offset + 18];
                let name_bytes = &buf[offset + 19..offset + reclen];
                let end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                entries.push((
                    String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
                    d_type,
                ));
                if reclen == 0 {
                    break;
                }
                offset += reclen;
            }
        }
        entries.sort();
        let rendered: Vec<Value> = entries
            .iter()
            .map(|(name, kind)| Value::from(format!("{name}:{kind}")))
            .collect();
        let builder = self.event(Sys::Getdents64, result);
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
            Sys::Mkdirat,
            [dirfd as i64, c.as_ptr() as i64, mode as i64, 0, 0, 0],
        );
        let builder = self.event(Sys::Mkdirat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    pub fn unlinkat(&self, dirfd: i32, path: &str, flags: i32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Sys::Unlinkat,
            [dirfd as i64, c.as_ptr() as i64, flags as i64, 0, 0, 0],
        );
        let builder = self.event(Sys::Unlinkat, result);
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
            Sys::Renameat,
            [
                olddirfd as i64,
                co.as_ptr() as i64,
                newdirfd as i64,
                cn.as_ptr() as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Renameat, result);
        let builder = self.fd_arg(builder, "olddirfd", olddirfd).arg("old", old);
        self.fd_arg(builder, "newdirfd", newdirfd)
            .arg("new", new)
            .emit();
        result
    }

    pub fn symlinkat(&self, target: &str, dirfd: i32, path: &str) -> i64 {
        let ct = cstr(target);
        let cp = cstr(path);
        let result = self.call(
            Sys::Symlinkat,
            [
                ct.as_ptr() as i64,
                dirfd as i64,
                cp.as_ptr() as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Symlinkat, result).arg("target", target);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .emit();
        result
    }

    pub fn readlinkat(&self, dirfd: i32, path: &str, bufsize: usize) -> (i64, String) {
        let c = cstr(path);
        let mut buf = vec![0u8; bufsize.max(1)];
        let result = self.call(
            Sys::Readlinkat,
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
        let builder = self.event(Sys::Readlinkat, result);
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
            Sys::Linkat,
            [
                olddirfd as i64,
                co.as_ptr() as i64,
                newdirfd as i64,
                cn.as_ptr() as i64,
                flags as i64,
                0,
            ],
        );
        let builder = self.event(Sys::Linkat, result);
        let builder = self.fd_arg(builder, "olddirfd", olddirfd).arg("old", old);
        self.fd_arg(builder, "newdirfd", newdirfd)
            .arg("new", new)
            .arg("flags", flags)
            .emit();
        result
    }

    // ---- descriptors --------------------------------------------------------

    pub fn pipe2(&self, flags: i32) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let result = self.call(
            Sys::Pipe2,
            [fds.as_mut_ptr() as i64, flags as i64, 0, 0, 0, 0],
        );
        let builder = self.event(Sys::Pipe2, result).arg("flags", flags);
        let builder = if result >= 0 {
            builder
                .field("read_end", fds[0])
                .norm("fields.read_end", Norm::Relative("fd"))
                .field("write_end", fds[1])
                .norm("fields.write_end", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        (result, fds)
    }

    pub fn dup(&self, fd: i32) -> i64 {
        let result = self.call(Sys::Dup, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Sys::Dup, result);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result
    }

    /// `dup2(oldfd, newfd)`. The result IS `newfd` on success (a number the
    /// probe chose, not one the kernel allocated), so it is recorded raw; both
    /// arguments are descriptors and normalized as such — `newfd` when it names
    /// something at the time of the call.
    pub fn dup2(&self, oldfd: i32, newfd: i32) -> i64 {
        let result = self.call(Sys::Dup2, [oldfd as i64, newfd as i64, 0, 0, 0, 0]);
        let builder = self.event(Sys::Dup2, result);
        self.fd_arg(builder, "oldfd", oldfd)
            .arg("newfd", newfd)
            .emit();
        result
    }

    /// `dup3(oldfd, newfd, flags)`; recorded like `dup2`.
    pub fn dup3(&self, oldfd: i32, newfd: i32, flags: i32) -> i64 {
        let result = self.call(
            Sys::Dup3,
            [oldfd as i64, newfd as i64, flags as i64, 0, 0, 0],
        );
        let builder = self.event(Sys::Dup3, result);
        self.fd_arg(builder, "oldfd", oldfd)
            .arg("newfd", newfd)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `close_range(first, last, flags)`: the bounds are numbers the probe
    /// chose, recorded raw. The differ's `fd` namespace retires nothing here
    /// (it retires on `close` events), so a probe closes the range's members
    /// through `close_range` only when it never reuses them observably.
    pub fn close_range(&self, first: u32, last: u32, flags: u32) -> i64 {
        let result = self.call(
            Sys::CloseRange,
            [first as i64, last as i64, flags as i64, 0, 0, 0],
        );
        self.event(Sys::CloseRange, result)
            .arg("first", first)
            .arg("last", last)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `fcntl` with an integer argument. `F_DUPFD*` results are descriptors and
    /// normalized as such; every other result is recorded raw.
    pub fn fcntl(&self, fd: i32, cmd: i32, arg: i64) -> i64 {
        let result = self.call(Sys::Fcntl, [fd as i64, cmd as i64, arg, 0, 0, 0]);
        let builder = self.event(Sys::Fcntl, result);
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

    pub fn flock(&self, fd: i32, operation: i32) -> i64 {
        let result = self.call(Sys::Flock, [fd as i64, operation as i64, 0, 0, 0, 0]);
        let builder = self.event(Sys::Flock, result);
        self.fd_arg(builder, "fd", fd)
            .arg("operation", operation)
            .emit();
        result
    }

    // ---- time ---------------------------------------------------------------

    pub fn clock_gettime(&self, clock: i32) -> (i64, i128) {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = self.call(
            Sys::ClockGettime,
            [
                clock as i64,
                &mut ts as *mut libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let ns = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
        let builder = self.event(Sys::ClockGettime, result).arg("clock", clock);
        let builder = if result >= 0 {
            builder
                .field("ns", ns as i64)
                .norm("fields.ns", Norm::Monotonic)
        } else {
            builder
        };
        builder.emit();
        (result, ns)
    }

    pub fn gettimeofday(&self) -> (i64, i128) {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let result = self.call(
            Sys::Gettimeofday,
            [&mut tv as *mut libc::timeval as i64, 0, 0, 0, 0, 0],
        );
        let us = tv.tv_sec as i128 * 1_000_000 + tv.tv_usec as i128;
        let builder = self.event(Sys::Gettimeofday, result);
        let builder = if result >= 0 {
            builder
                .field("us", us as i64)
                .norm("fields.us", Norm::Monotonic)
                .field("usec_in_range", (0..1_000_000).contains(&tv.tv_usec))
        } else {
            builder
        };
        builder.emit();
        (result, us)
    }

    pub fn nanosleep(&self, sec: i64, nsec: i64) -> i64 {
        let req = libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let mut rem = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let result = self.call(
            Sys::Nanosleep,
            [
                &req as *const libc::timespec as i64,
                &mut rem as *mut libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Sys::Nanosleep, result)
            .arg("sec", sec)
            .arg("nsec", nsec)
            .emit();
        result
    }

    pub fn clock_nanosleep(&self, clock: i32, flags: i32, sec: i64, nsec: i64) -> i64 {
        let req = libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let result = self.call(
            Sys::ClockNanosleep,
            [
                clock as i64,
                flags as i64,
                &req as *const libc::timespec as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self
            .event(Sys::ClockNanosleep, result)
            .arg("clock", clock)
            .arg("flags", flags);
        // An absolute deadline is a clock reading, so it is not a stable arg.
        let builder = if flags & libc::TIMER_ABSTIME != 0 {
            builder.arg("absolute", true)
        } else {
            builder.arg("sec", sec).arg("nsec", nsec)
        };
        builder.emit();
        result
    }

    // ---- entropy ------------------------------------------------------------

    pub fn getrandom(&self, len: usize, flags: u32) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let result = self.call(
            Sys::Getrandom,
            [buf.as_mut_ptr() as i64, len as i64, flags as i64, 0, 0, 0],
        );
        if result >= 0 {
            buf.truncate(result as usize);
        } else {
            buf.clear();
        }
        let builder = self
            .event(Sys::Getrandom, result)
            .arg("len", len)
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("nonzero", buf.iter().any(|&b| b != 0))
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    // ---- network ------------------------------------------------------------

    fn addr_args<'a>(
        &self,
        builder: EventBuilder<'a>,
        key: &str,
        addr: SocketAddrV4,
    ) -> EventBuilder<'a> {
        let builder = builder
            .arg(&format!("{key}_ip"), addr.ip().to_string())
            .arg(&format!("{key}_port"), addr.port());
        if addr.port() != 0 {
            builder.norm(&format!("args.{key}_port"), Norm::Relative("port"))
        } else {
            builder
        }
    }

    fn addr_fields<'a>(
        &self,
        builder: EventBuilder<'a>,
        key: &str,
        addr: SocketAddrV4,
    ) -> EventBuilder<'a> {
        let builder = builder
            .field(&format!("{key}_ip"), addr.ip().to_string())
            .field(&format!("{key}_port"), addr.port());
        if addr.port() != 0 {
            builder.norm(&format!("fields.{key}_port"), Norm::Relative("port"))
        } else {
            builder
        }
    }

    pub fn socket(&self, domain: i32, kind: i32, protocol: i32) -> i32 {
        let result = self.call(
            Sys::Socket,
            [domain as i64, kind as i64, protocol as i64, 0, 0, 0],
        );
        self.event(Sys::Socket, result)
            .arg("domain", domain)
            .arg("type", kind)
            .arg("protocol", protocol)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn bind(&self, fd: i32, addr: SocketAddrV4) -> i64 {
        let raw = sockaddr_in(addr);
        let result = self.call(
            Sys::Bind,
            [
                fd as i64,
                &raw as *const libc::sockaddr_in as i64,
                std::mem::size_of::<libc::sockaddr_in>() as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Bind, result);
        let builder = self.fd_arg(builder, "fd", fd);
        self.addr_args(builder, "addr", addr).emit();
        result
    }

    /// `bind` with a caller-chosen family/length (for the error rows).
    pub fn bind_raw(&self, fd: i32, family: i32, len: usize) -> i64 {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        raw.sin_family = family as libc::sa_family_t;
        let result = self.call(
            Sys::Bind,
            [
                fd as i64,
                &raw as *const libc::sockaddr_in as i64,
                len as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Bind, result);
        self.fd_arg(builder, "fd", fd)
            .arg("family", family)
            .arg("addrlen", len)
            .emit();
        result
    }

    pub fn listen(&self, fd: i32, backlog: i32) -> i64 {
        let result = self.call(Sys::Listen, [fd as i64, backlog as i64, 0, 0, 0, 0]);
        let builder = self.event(Sys::Listen, result);
        self.fd_arg(builder, "fd", fd)
            .arg("backlog", backlog)
            .emit();
        result
    }

    pub fn connect(&self, fd: i32, addr: SocketAddrV4) -> i64 {
        let raw = sockaddr_in(addr);
        let result = self.call(
            Sys::Connect,
            [
                fd as i64,
                &raw as *const libc::sockaddr_in as i64,
                std::mem::size_of::<libc::sockaddr_in>() as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Connect, result);
        let builder = self.fd_arg(builder, "fd", fd);
        self.addr_args(builder, "addr", addr).emit();
        result
    }

    pub fn accept4(&self, fd: i32, flags: i32) -> (i32, Option<SocketAddrV4>) {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let result = self.call(
            Sys::Accept4,
            [
                fd as i64,
                &mut raw as *mut libc::sockaddr_in as i64,
                &mut len as *mut libc::socklen_t as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let peer = (result >= 0).then(|| decode_sockaddr_in(&raw));
        let builder = self.event(Sys::Accept4, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"));
        match peer {
            Some(peer) => self
                .addr_fields(builder, "peer", peer)
                .field("addrlen", len)
                .emit(),
            None => builder.emit(),
        }
        (result as i32, peer)
    }

    pub fn sendto(&self, fd: i32, data: &[u8], flags: i32, addr: Option<SocketAddrV4>) -> i64 {
        let raw = addr.map(sockaddr_in);
        let (ptr, len) = match &raw {
            Some(raw) => (
                raw as *const libc::sockaddr_in as i64,
                std::mem::size_of::<libc::sockaddr_in>() as i64,
            ),
            None => (0, 0),
        };
        let result = self.call(
            Sys::Sendto,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                flags as i64,
                ptr,
                len,
            ],
        );
        let builder = self.event(Sys::Sendto, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("len", data.len())
            .arg("flags", flags);
        match addr {
            Some(addr) => self.addr_args(builder, "addr", addr).emit(),
            None => builder.arg("addr", Value::Null).emit(),
        }
        result
    }

    pub fn recvfrom(
        &self,
        fd: i32,
        len: usize,
        flags: i32,
        want_addr: bool,
    ) -> (i64, Vec<u8>, Option<SocketAddrV4>) {
        let mut buf = vec![0u8; len];
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut alen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let (aptr, lptr) = if want_addr {
            (
                &mut raw as *mut libc::sockaddr_in as i64,
                &mut alen as *mut libc::socklen_t as i64,
            )
        } else {
            (0, 0)
        };
        let result = self.call(
            Sys::Recvfrom,
            [
                fd as i64,
                buf.as_mut_ptr() as i64,
                len as i64,
                flags as i64,
                aptr,
                lptr,
            ],
        );
        if result >= 0 {
            buf.truncate(result as usize);
        } else {
            buf.clear();
        }
        let src = (result >= 0 && want_addr).then(|| decode_sockaddr_in(&raw));
        let builder = self.event(Sys::Recvfrom, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("len", len)
            .arg("flags", flags)
            .arg("want_addr", want_addr);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        match src {
            Some(src) => self.addr_fields(builder, "src", src).emit(),
            None => builder.emit(),
        }
        (result, buf, src)
    }

    fn name_call(&self, sys: Sys, fd: i32) -> (i64, Option<SocketAddrV4>) {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let result = self.call(
            sys,
            [
                fd as i64,
                &mut raw as *mut libc::sockaddr_in as i64,
                &mut len as *mut libc::socklen_t as i64,
                0,
                0,
                0,
            ],
        );
        let addr = (result >= 0).then(|| decode_sockaddr_in(&raw));
        let builder = self.event(sys, result);
        let builder = self.fd_arg(builder, "fd", fd);
        match addr {
            Some(addr) => self
                .addr_fields(builder, "addr", addr)
                .field("addrlen", len)
                .emit(),
            None => builder.emit(),
        }
        (result, addr)
    }

    pub fn getsockname(&self, fd: i32) -> (i64, Option<SocketAddrV4>) {
        self.name_call(Sys::Getsockname, fd)
    }

    pub fn getpeername(&self, fd: i32) -> (i64, Option<SocketAddrV4>) {
        self.name_call(Sys::Getpeername, fd)
    }

    pub fn shutdown(&self, fd: i32, how: i32) -> i64 {
        let result = self.call(Sys::Shutdown, [fd as i64, how as i64, 0, 0, 0, 0]);
        let builder = self.event(Sys::Shutdown, result);
        self.fd_arg(builder, "fd", fd).arg("how", how).emit();
        result
    }

    pub fn setsockopt_int(&self, fd: i32, level: i32, name: i32, value: i32) -> i64 {
        let result = self.call(
            Sys::Setsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                &value as *const i32 as i64,
                std::mem::size_of::<i32>() as i64,
                0,
            ],
        );
        let builder = self.event(Sys::Setsockopt, result);
        self.fd_arg(builder, "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("value", value)
            .emit();
        result
    }

    pub fn getsockopt_int(&self, fd: i32, level: i32, name: i32) -> (i64, i32) {
        let mut value: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        let result = self.call(
            Sys::Getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                &mut value as *mut i32 as i64,
                &mut len as *mut libc::socklen_t as i64,
                0,
            ],
        );
        let builder = self.event(Sys::Getsockopt, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("level", level)
            .arg("name", name);
        let builder = if result >= 0 {
            builder.field("value", value).field("optlen", len)
        } else {
            builder
        };
        builder.emit();
        (result, value)
    }

    // ---- readiness ----------------------------------------------------------

    pub fn epoll_create1(&self, flags: i32) -> i32 {
        let result = self.call(Sys::EpollCreate1, [flags as i64, 0, 0, 0, 0, 0]);
        self.event(Sys::EpollCreate1, result)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn epoll_ctl(&self, epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i64 {
        let mut event = libc::epoll_event { events, u64: data };
        let result = self.call(
            Sys::EpollCtl,
            [
                epfd as i64,
                op as i64,
                fd as i64,
                &mut event as *mut libc::epoll_event as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::EpollCtl, result);
        let builder = self.fd_arg(builder, "epfd", epfd).arg("op", op);
        self.fd_arg(builder, "fd", fd)
            .arg("events", events)
            .arg("data", data)
            .emit();
        result
    }

    /// `epoll_wait`; the delivered set is recorded sorted by `data` (arrival
    /// order is the host's business).
    pub fn epoll_wait(&self, epfd: i32, maxevents: i32, timeout_ms: i32) -> (i64, Vec<(u64, u32)>) {
        let mut events: Vec<libc::epoll_event> =
            vec![libc::epoll_event { events: 0, u64: 0 }; maxevents.max(1) as usize];
        let result = self.call(
            Sys::EpollWait,
            [
                epfd as i64,
                events.as_mut_ptr() as i64,
                maxevents as i64,
                timeout_ms as i64,
                0,
                0,
            ],
        );
        let mut delivered: Vec<(u64, u32)> = if result > 0 {
            events[..result as usize]
                .iter()
                .map(|event| (event.u64, event.events))
                .collect()
        } else {
            Vec::new()
        };
        delivered.sort();
        let rendered: Vec<Value> = delivered
            .iter()
            .map(|(data, mask)| Value::from(format!("{data}:{mask:#x}")))
            .collect();
        let builder = self.event(Sys::EpollWait, result);
        let builder = self
            .fd_arg(builder, "epfd", epfd)
            .arg("maxevents", maxevents)
            .arg("timeout_ms", timeout_ms);
        let builder = if result >= 0 {
            builder.field("events", Value::Array(rendered))
        } else {
            builder
        };
        builder.emit();
        (result, delivered)
    }

    pub fn eventfd2(&self, initval: u32, flags: i32) -> i32 {
        let result = self.call(Sys::Eventfd2, [initval as i64, flags as i64, 0, 0, 0, 0]);
        self.event(Sys::Eventfd2, result)
            .arg("initval", initval)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `ppoll` over `(fd, events)` pairs with an optional relative timeout;
    /// revents recorded per slot.
    pub fn ppoll(&self, fds: &[(i32, i16)], timeout_ns: Option<i64>) -> (i64, Vec<i16>) {
        let mut pollfds: Vec<libc::pollfd> = fds
            .iter()
            .map(|&(fd, events)| libc::pollfd {
                fd,
                events,
                revents: 0,
            })
            .collect();
        let timeout = timeout_ns.map(|ns| libc::timespec {
            tv_sec: ns / 1_000_000_000,
            tv_nsec: ns % 1_000_000_000,
        });
        let timeout_ptr = timeout
            .as_ref()
            .map_or(0, |ts| ts as *const libc::timespec as i64);
        let result = self.call(
            Sys::Ppoll,
            [
                pollfds.as_mut_ptr() as i64,
                pollfds.len() as i64,
                timeout_ptr,
                0,
                std::mem::size_of::<libc::sigset_t>() as i64,
                0,
            ],
        );
        let revents: Vec<i16> = pollfds.iter().map(|p| p.revents).collect();
        let mut builder = self.event(Sys::Ppoll, result).arg("nfds", fds.len());
        for (index, &(fd, events)) in fds.iter().enumerate() {
            builder = self
                .fd_arg(builder, &format!("fd{index}"), fd)
                .arg(&format!("events{index}"), events);
        }
        builder = match timeout_ns {
            Some(ns) => builder.arg("timeout_ns", ns),
            None => builder.arg("timeout_ns", Value::Null),
        };
        if result >= 0 {
            for (index, revent) in revents.iter().enumerate() {
                builder = builder.field(&format!("revents{index}"), *revent);
            }
        }
        builder.emit();
        (result, revents)
    }

    // ---- threads ------------------------------------------------------------

    pub fn futex(
        &self,
        word: &std::sync::atomic::AtomicU32,
        op: i32,
        value: u32,
        timeout_ns: Option<i64>,
    ) -> i64 {
        let timeout = timeout_ns.map(|ns| libc::timespec {
            tv_sec: ns / 1_000_000_000,
            tv_nsec: ns % 1_000_000_000,
        });
        let timeout_ptr = timeout
            .as_ref()
            .map_or(0, |ts| ts as *const libc::timespec as i64);
        let result = self.call(
            Sys::Futex,
            [
                word.as_ptr() as i64,
                op as i64,
                value as i64,
                timeout_ptr,
                0,
                0,
            ],
        );
        let builder = self
            .event(Sys::Futex, result)
            .arg("op", op)
            .arg("value", value);
        match timeout_ns {
            Some(ns) => builder.arg("timeout_ns", ns).emit(),
            None => builder.arg("timeout_ns", Value::Null).emit(),
        }
        result
    }

    // ---- identity -----------------------------------------------------------

    pub fn getpid(&self) -> i64 {
        let result = self.call(Sys::Getpid, [0; 6]);
        self.event(Sys::Getpid, result)
            .norm("ret", Norm::Identity)
            .emit();
        result
    }

    pub fn getuid(&self) -> i64 {
        let result = self.call(Sys::Getuid, [0; 6]);
        self.event(Sys::Getuid, result)
            .norm("ret", Norm::Identity)
            .emit();
        result
    }

    pub fn getgid(&self) -> i64 {
        let result = self.call(Sys::Getgid, [0; 6]);
        self.event(Sys::Getgid, result)
            .norm("ret", Norm::Identity)
            .emit();
        result
    }

    pub fn gettid(&self) -> i64 {
        let result = self.call(Sys::Gettid, [0; 6]);
        self.event(Sys::Gettid, result)
            .norm("ret", Norm::Identity)
            .emit();
        result
    }

    pub fn getppid(&self) -> i64 {
        let result = self.call(Sys::Getppid, [0; 6]);
        self.event(Sys::Getppid, result)
            .norm("ret", Norm::Identity)
            .emit();
        result
    }

    pub fn getpgid(&self, pid: i32) -> i64 {
        let result = self.call(Sys::Getpgid, [pid as i64, 0, 0, 0, 0, 0]);
        self.event(Sys::Getpgid, if result >= 0 { 0 } else { result })
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity)
            .field("positive", result > 0)
            .emit();
        result
    }

    pub fn getsid(&self, pid: i32) -> i64 {
        let result = self.call(Sys::Getsid, [pid as i64, 0, 0, 0, 0, 0]);
        self.event(Sys::Getsid, if result >= 0 { 0 } else { result })
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity)
            .field("positive", result > 0)
            .emit();
        result
    }

    pub fn kill(&self, pid: i32, sig: i32) -> i64 {
        let result = self.call(Sys::Kill, [pid as i64, sig as i64, 0, 0, 0, 0]);
        self.event(Sys::Kill, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity)
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn tkill(&self, tid: i32, sig: i32) -> i64 {
        let result = self.call(Sys::Tkill, [tid as i64, sig as i64, 0, 0, 0, 0]);
        self.event(Sys::Tkill, result)
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity)
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> i64 {
        let result = self.call(
            Sys::Tgkill,
            [tgid as i64, tid as i64, sig as i64, 0, 0, 0],
        );
        self.event(Sys::Tgkill, result)
            .arg("tgid", tgid)
            .norm("args.tgid", Norm::Identity)
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity)
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn rt_sigprocmask(
        &self,
        how: i32,
        set: Option<&libc::sigset_t>,
        old: Option<&mut libc::sigset_t>,
        sigset_size: usize,
    ) -> i64 {
        let result = self.call(
            Sys::RtSigprocmask,
            [
                how as i64,
                set.map_or(0, |s| s as *const libc::sigset_t as i64),
                old.map_or(0, |s| s as *mut libc::sigset_t as i64),
                sigset_size as i64,
                0,
                0,
            ],
        );
        self.event(Sys::RtSigprocmask, result)
            .arg("how", how)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn rt_sigpending(&self, set: &mut libc::sigset_t, sigset_size: usize) -> i64 {
        let result = self.call(
            Sys::RtSigpending,
            [set as *mut libc::sigset_t as i64, sigset_size as i64, 0, 0, 0, 0],
        );
        self.event(Sys::RtSigpending, result)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn rt_sigtimedwait(
        &self,
        set: &libc::sigset_t,
        info: Option<&mut libc::siginfo_t>,
        timeout_ns: Option<i64>,
        sigset_size: usize,
    ) -> i64 {
        let timeout = timeout_ns.map(|ns| libc::timespec {
            tv_sec: ns / 1_000_000_000,
            tv_nsec: ns % 1_000_000_000,
        });
        let info_ptr = info
            .as_ref()
            .map_or(0, |i| (*i as *const libc::siginfo_t).cast_mut() as i64);
        let result = self.call(
            Sys::RtSigtimedwait,
            [
                set as *const libc::sigset_t as i64,
                info_ptr,
                timeout
                    .as_ref()
                    .map_or(0, |ts| ts as *const libc::timespec as i64),
                sigset_size as i64,
                0,
                0,
            ],
        );
        // The queued payload is only meaningful (and only kernel-filled) for
        // SI_QUEUE; every other code records 0 so the field is stable.
        let si_int = info
            .as_ref()
            .filter(|i| result > 0 && i.si_code == libc::SI_QUEUE)
            .map_or(0, |i| unsafe { i.si_value().sival_ptr as usize as i32 });
        self.event(Sys::RtSigtimedwait, result)
            .arg("timeout_ns", timeout_ns.map_or(Value::Null, Value::from))
            .arg("sigset_size", sigset_size)
            .field("si_signo", info.as_ref().map_or(0, |i| i.si_signo))
            .field("si_code", info.as_ref().map_or(0, |i| i.si_code))
            .field("si_int", si_int)
            .emit();
        result
    }

    pub fn rt_sigsuspend(&self, set: &libc::sigset_t, sigset_size: usize) -> i64 {
        let result = self.call(
            Sys::RtSigsuspend,
            [set as *const libc::sigset_t as i64, sigset_size as i64, 0, 0, 0, 0],
        );
        self.event(Sys::RtSigsuspend, result)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn signalfd4(&self, fd: i32, set: &libc::sigset_t, flags: i32) -> i32 {
        let result = self.call(
            Sys::Signalfd4,
            [
                fd as i64,
                set as *const libc::sigset_t as i64,
                8,
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Signalfd4, result).arg("flags", flags);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn signalfd(&self, fd: i32, set: &libc::sigset_t) -> i32 {
        let result = self.call(
            Sys::Signalfd,
            [
                fd as i64,
                set as *const libc::sigset_t as i64,
                8,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Signalfd, result);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn sigaltstack(
        &self,
        new: Option<&libc::stack_t>,
        old: Option<&mut libc::stack_t>,
    ) -> i64 {
        let old_ptr = old
            .as_ref()
            .map_or(0, |s| (*s as *const libc::stack_t).cast_mut() as i64);
        let result = self.call(
            Sys::Sigaltstack,
            [
                new.map_or(0, |s| s as *const libc::stack_t as i64),
                old_ptr,
                0,
                0,
                0,
                0,
            ],
        );
        let flags = old.as_ref().map_or(-1, |s| s.ss_flags);
        self.event(Sys::Sigaltstack, result)
            .field("old_flags", flags)
            .emit();
        result
    }

    pub fn rt_sigaction_raw(&self, signum: i32, size: usize) -> i64 {
        let result = self.call(Sys::RtSigaction, [signum as i64, 0, 0, size as i64, 0, 0]);
        self.event(Sys::RtSigaction, result)
            .arg("signum", signum)
            .arg("sigset_size", size)
            .emit();
        result
    }

    pub fn rt_sigqueueinfo(&self, pid: i32, sig: i32, info: &libc::siginfo_t) -> i64 {
        let result = self.call(
            Sys::RtSigqueueinfo,
            [pid as i64, sig as i64, info as *const libc::siginfo_t as i64, 0, 0, 0],
        );
        self.event(Sys::RtSigqueueinfo, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity)
            .arg("sig", sig)
            .arg("si_code", info.si_code)
            .emit();
        result
    }

    pub fn rt_tgsigqueueinfo(&self, tgid: i32, tid: i32, sig: i32, info: &libc::siginfo_t) -> i64 {
        let result = self.call(
            Sys::RtTgsigqueueinfo,
            [
                tgid as i64,
                tid as i64,
                sig as i64,
                info as *const libc::siginfo_t as i64,
                0,
                0,
            ],
        );
        self.event(Sys::RtTgsigqueueinfo, result)
            .arg("tgid", tgid)
            .norm("args.tgid", Norm::Identity)
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity)
            .arg("sig", sig)
            .arg("si_code", info.si_code)
            .emit();
        result
    }

    pub fn set_tid_address(&self, ptr: *mut i32) -> i64 {
        let result = self.call(Sys::SetTidAddress, [ptr as i64, 0, 0, 0, 0, 0]);
        self.event(Sys::SetTidAddress, result)
            .norm("ret", Norm::Identity)
            .emit();
        result
    }

    pub fn prctl(&self, option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
        let result = self.call(
            Sys::Prctl,
            [option as i64, a2 as i64, a3 as i64, a4 as i64, a5 as i64, 0],
        );
        self.event(Sys::Prctl, result).arg("option", option).emit();
        result
    }

    pub fn wait4(&self, pid: i32, options: i32) -> (i64, i32) {
        let mut status = 0;
        let result = self.call(
            Sys::Wait4,
            [pid as i64, &mut status as *mut i32 as i64, options as i64, 0, 0, 0],
        );
        self.event(Sys::Wait4, result)
            .arg("pid", pid)
            .arg("options", options)
            .field("status", status)
            .emit();
        (result, status)
    }

    pub fn waitid(&self, idtype: i32, id: u32, options: i32) -> (i64, i32) {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = self.call(
            Sys::Waitid,
            [
                idtype as i64,
                id as i64,
                &mut info as *mut libc::siginfo_t as i64,
                options as i64,
                0,
                0,
            ],
        );
        self.event(Sys::Waitid, result)
            .arg("idtype", idtype)
            .arg("id", id)
            .arg("options", options)
            .field("si_signo", info.si_signo)
            .field("si_code", info.si_code)
            .emit();
        (result, info.si_code)
    }

    // ---- the working directory and the umask --------------------------------

    /// `getcwd` into a `size`-byte buffer. Success is recorded as `ret` 0 on
    /// every vehicle (glibc answers a pointer, the kernel a length) with the
    /// directory in `fields.path`; `size` is an argument so ERANGE is legible.
    pub fn getcwd(&self, size: usize) -> (i64, String) {
        let mut buf = vec![0u8; size.max(1)];
        let result = self.call(
            Sys::Getcwd,
            [buf.as_mut_ptr() as i64, size as i64, 0, 0, 0, 0],
        );
        let path = if result >= 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..end]).into_owned()
        } else {
            String::new()
        };
        let normalized = if result >= 0 { 0 } else { result };
        let builder = self.event(Sys::Getcwd, normalized).arg("size", size);
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
        let result = self.call(Sys::Chdir, [c.as_ptr() as i64, 0, 0, 0, 0, 0]);
        self.event(Sys::Chdir, result).arg("path", path).emit();
        result
    }

    pub fn fchdir(&self, fd: i32) -> i64 {
        let result = self.call(Sys::Fchdir, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Sys::Fchdir, result);
        self.fd_arg(builder, "fd", fd).emit();
        result
    }

    /// `umask`: the previous mask is the result (never an errno).
    pub fn umask(&self, mask: u32) -> i64 {
        let result = self.call(Sys::Umask, [mask as i64, 0, 0, 0, 0, 0]);
        self.event(Sys::Umask, result).arg("mask", mask).emit();
        result
    }

    pub fn mknodat(&self, dirfd: i32, path: &str, mode: u32, dev: u64) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Sys::Mknodat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                mode as i64,
                dev as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Mknodat, result);
        self.fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("mode", mode)
            .arg("dev", dev)
            .emit();
        result
    }

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
            Sys::Utimensat,
            [
                dirfd as i64,
                c.as_ref().map_or(0, |c| c.as_ptr() as i64),
                spec.as_ref().map_or(0, |s| s.as_ptr() as i64),
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Utimensat, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path.unwrap_or("NULL"))
            .arg("flags", flags);
        self.time_args(builder, times).emit();
        result
    }

    /// `utime(2)`: whole seconds, or `None` for now/now.
    pub fn utime(&self, path: &str, times: Option<(i64, i64)>) -> i64 {
        let c = cstr(path);
        let buf = times.map(|(actime, modtime)| libc::utimbuf { actime, modtime });
        let result = self.call(
            Sys::Utime,
            [
                c.as_ptr() as i64,
                buf.as_ref().map_or(0, |b| b as *const libc::utimbuf as i64),
                0,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Utime, result).arg("path", path);
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

    /// `utimes(2)`: microsecond times, or `None` for now/now.
    pub fn utimes(&self, path: &str, times: Option<[(i64, i64); 2]>) -> i64 {
        let c = cstr(path);
        let tv = Self::timeval_pair(times);
        let result = self.call(
            Sys::Utimes,
            [
                c.as_ptr() as i64,
                tv.as_ref().map_or(0, |t| t.as_ptr() as i64),
                0,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Utimes, result).arg("path", path);
        self.timeval_args(builder, times).emit();
        result
    }

    /// `futimesat(2)`: `utimes` with a dirfd.
    pub fn futimesat(&self, dirfd: i32, path: &str, times: Option<[(i64, i64); 2]>) -> i64 {
        let c = cstr(path);
        let tv = Self::timeval_pair(times);
        let result = self.call(
            Sys::Futimesat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                tv.as_ref().map_or(0, |t| t.as_ptr() as i64),
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Sys::Futimesat, result);
        let builder = self.fd_arg(builder, "dirfd", dirfd).arg("path", path);
        self.timeval_args(builder, times).emit();
        result
    }

    fn id_arg<'a>(&self, builder: EventBuilder<'a>, key: &str, id: u32) -> EventBuilder<'a> {
        if id == u32::MAX {
            builder.arg(key, "-1")
        } else {
            builder
                .arg(key, id)
                .norm(&format!("args.{key}"), Norm::Identity)
        }
    }

    /// `chown`/`lchown` (x86_64 legacy rows): `u32::MAX` is `-1`.
    pub fn chown(&self, path: &str, uid: u32, gid: u32, follow: bool) -> i64 {
        let sys = if follow { Sys::Chown } else { Sys::Lchown };
        let c = cstr(path);
        let result = self.call(sys, [c.as_ptr() as i64, uid as i64, gid as i64, 0, 0, 0]);
        let builder = self.event(sys, result).arg("path", path);
        let builder = self.id_arg(builder, "uid", uid);
        self.id_arg(builder, "gid", gid).emit();
        result
    }

    pub fn fchown(&self, fd: i32, uid: u32, gid: u32) -> i64 {
        let result = self.call(Sys::Fchown, [fd as i64, uid as i64, gid as i64, 0, 0, 0]);
        let builder = self.event(Sys::Fchown, result);
        let builder = self.fd_arg(builder, "fd", fd);
        let builder = self.id_arg(builder, "uid", uid);
        self.id_arg(builder, "gid", gid).emit();
        result
    }

    pub fn fchownat(&self, dirfd: i32, path: &str, uid: u32, gid: u32, flags: i32) -> i64 {
        let c = cstr(path);
        let result = self.call(
            Sys::Fchownat,
            [
                dirfd as i64,
                c.as_ptr() as i64,
                uid as i64,
                gid as i64,
                flags as i64,
                0,
            ],
        );
        let builder = self.event(Sys::Fchownat, result);
        let builder = self
            .fd_arg(builder, "dirfd", dirfd)
            .arg("path", path)
            .arg("flags", flags);
        let builder = self.id_arg(builder, "uid", uid);
        self.id_arg(builder, "gid", gid).emit();
        result
    }

    /// `access` (x86_64 legacy row).
    pub fn access(&self, path: &str, mode: i32) -> i64 {
        let c = cstr(path);
        let result = self.call(Sys::Access, [c.as_ptr() as i64, mode as i64, 0, 0, 0, 0]);
        self.event(Sys::Access, result)
            .arg("path", path)
            .arg("mode", mode)
            .emit();
        result
    }

    /// `faccessat` (`flagged`: the `faccessat2` row, the only one that carries
    /// flags to the kernel).
    pub fn faccessat(&self, dirfd: i32, path: &str, mode: i32, flags: i32, flagged: bool) -> i64 {
        let sys = if flagged {
            Sys::Faccessat2
        } else {
            Sys::Faccessat
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
        let result = self.call(Sys::Truncate, [c.as_ptr() as i64, len, 0, 0, 0, 0]);
        self.event(Sys::Truncate, result)
            .arg("path", path)
            .arg("len", len)
            .emit();
        result
    }

    pub fn ftruncate(&self, fd: i32, len: i64) -> i64 {
        let result = self.call(Sys::Ftruncate, [fd as i64, len, 0, 0, 0, 0]);
        let builder = self.event(Sys::Ftruncate, result);
        self.fd_arg(builder, "fd", fd).arg("len", len).emit();
        result
    }

    pub fn fallocate(&self, fd: i32, mode: i32, offset: i64, len: i64) -> i64 {
        let result = self.call(Sys::Fallocate, [fd as i64, mode as i64, offset, len, 0, 0]);
        let builder = self.event(Sys::Fallocate, result);
        self.fd_arg(builder, "fd", fd)
            .arg("mode", mode)
            .arg("offset", offset)
            .arg("len", len)
            .emit();
        result
    }

    // ---- the virtual ABI level ----------------------------------------------

    /// A number the vendored table lists but the virtual ABI level lacks
    /// (`fchroot`, 472, since Linux 7.3). What is under test is the row's
    /// absence, so the arguments are recorded verbatim and never interpreted.
    pub fn fchroot(&self, fd: i32, flags: u32) -> i64 {
        let result = self.call(Sys::Fchroot, [fd as i64, flags as i64, 0, 0, 0, 0]);
        self.event(Sys::Fchroot, result)
            .arg("fd", fd)
            .arg("flags", flags)
            .emit();
        result
    }

    // ---- signals, threads and process rows (the signals family) -------------

    /// Announce that the probe's next act ends the process on `signal`
    /// (`SIG_DFL` termination). The blessing accepts a signal death only when
    /// this is the last recorded event, and the recorded `__termination` line
    /// must then agree with the announcement on both sides.
    pub fn dies_by(&self, signal: i32) {
        self.rec
            .event(crate::expect::EXPECT_DEATH_OP, 0)
            .arg("signal", signal)
            .emit();
    }

    /// `pause`: returns only when a handled signal was delivered (`-EINTR`).
    pub fn pause(&self) -> i64 {
        let result = self.call(Sys::Pause, [0; 6]);
        self.event(Sys::Pause, result).emit();
        result
    }

    pub fn socketpair(&self, domain: i32, kind: i32, protocol: i32) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let result = self.call(
            Sys::Socketpair,
            [
                domain as i64,
                kind as i64,
                protocol as i64,
                fds.as_mut_ptr() as i64,
                0,
                0,
            ],
        );
        let builder = self
            .event(Sys::Socketpair, result)
            .arg("domain", domain)
            .arg("type", kind)
            .arg("protocol", protocol);
        let builder = if result >= 0 {
            builder
                .field("first", fds[0])
                .norm("fields.first", Norm::Relative("fd"))
                .field("second", fds[1])
                .norm("fields.second", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        (result, fds)
    }

    /// The raw `exit` row (one thread ends; the process lives while others
    /// run). The event is recorded BEFORE the call, which never returns.
    pub fn exit_thread(&self, code: i32) -> ! {
        self.event(Sys::Exit, 0).arg("code", code).emit();
        self.call(Sys::Exit, [code as i64, 0, 0, 0, 0, 0]);
        unreachable!("exit returned")
    }

    /// `exit_group`: the whole process ends with `code`. Recorded before the
    /// call, which never returns.
    pub fn exit_group(&self, code: i32) -> ! {
        self.event(Sys::ExitGroup, 0).arg("code", code).emit();
        self.call(Sys::ExitGroup, [code as i64, 0, 0, 0, 0, 0]);
        unreachable!("exit_group returned")
    }

    /// `nanosleep` recording whether an interrupted sleep reported a remaining
    /// time inside `(0, request]` (the kernel fills `rem` on `EINTR`; a
    /// completed sleep leaves it alone). Returns the result and `rem` in ns.
    pub fn nanosleep_rem(&self, sec: i64, nsec: i64) -> (i64, i64) {
        let req = libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let mut rem = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        let result = self.call(
            Sys::Nanosleep,
            [
                &req as *const libc::timespec as i64,
                &mut rem as *mut libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let request_ns = sec * 1_000_000_000 + nsec;
        let rem_ns = rem.tv_sec * 1_000_000_000 + rem.tv_nsec;
        let builder = self
            .event(Sys::Nanosleep, result)
            .arg("sec", sec)
            .arg("nsec", nsec);
        let builder = if result == neg(libc::EINTR) {
            builder.field("remain_in_range", rem_ns > 0 && rem_ns <= request_ns)
        } else {
            builder
        };
        builder.emit();
        (result, rem_ns)
    }

    /// `clock_nanosleep` (relative unless `TIMER_ABSTIME`) with the same
    /// remaining-time observation as [`Self::nanosleep_rem`]; for an absolute
    /// sleep the kernel leaves `rem` untouched, recorded as `remain_untouched`.
    pub fn clock_nanosleep_rem(&self, clock: i32, flags: i32, sec: i64, nsec: i64) -> (i64, i64) {
        let req = libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let mut rem = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        let result = self.call(
            Sys::ClockNanosleep,
            [
                clock as i64,
                flags as i64,
                &req as *const libc::timespec as i64,
                &mut rem as *mut libc::timespec as i64,
                0,
                0,
            ],
        );
        let request_ns = sec * 1_000_000_000 + nsec;
        let rem_ns = rem.tv_sec * 1_000_000_000 + rem.tv_nsec;
        let absolute = flags & libc::TIMER_ABSTIME != 0;
        let builder = self
            .event(Sys::ClockNanosleep, result)
            .arg("clock", clock)
            .arg("flags", flags);
        let builder = if absolute {
            builder.arg("absolute", true)
        } else {
            builder.arg("sec", sec).arg("nsec", nsec)
        };
        let builder = if result == neg(libc::EINTR) {
            if absolute {
                builder.field("remain_untouched", rem.tv_sec == -1 && rem.tv_nsec == -1)
            } else {
                builder.field("remain_in_range", rem_ns > 0 && rem_ns <= request_ns)
            }
        } else {
            builder
        };
        builder.emit();
        (result, rem_ns)
    }

    /// Raw `rt_sigaction(signum, act, oldact, 8)` with the KERNEL struct
    /// layout. Records which pointers were passed and, on success with an
    /// `oldact`, the previous action's compared flags and whether it was
    /// `SIG_DFL`/`SIG_IGN`/a handler (`old_kind`), never a code address.
    pub fn rt_sigaction_install(
        &self,
        signum: i32,
        act: Option<&KernelSigaction>,
        old: Option<&mut KernelSigaction>,
    ) -> i64 {
        let old_ptr = old
            .as_ref()
            .map_or(0, |o| (*o as *const KernelSigaction).cast_mut() as i64);
        let result = self.call(
            Sys::RtSigaction,
            [
                signum as i64,
                act.map_or(0, |a| a as *const KernelSigaction as i64),
                old_ptr,
                8,
                0,
                0,
            ],
        );
        let builder = self
            .event(Sys::RtSigaction, result)
            .arg("signum", signum)
            .arg("has_act", act.is_some())
            .arg("has_oldact", old.is_some());
        let builder = match (result, old) {
            (0, Some(old)) => builder
                .field(
                    "old_kind",
                    match old.handler {
                        0 => "SIG_DFL",
                        1 => "SIG_IGN",
                        _ => "handler",
                    },
                )
                .field("old_flags", old.flags & SA_FLAGS_COMPARED)
                .field("old_has_restorer", old.flags & SA_RESTORER != 0 && old.restorer != 0),
            _ => builder,
        };
        builder.emit();
        result
    }

    /// Query an action raw (`act = NULL`), returning it for the probe's own
    /// use (the restorer a raw install needs).
    pub fn rt_sigaction_query(&self, signum: i32) -> (i64, KernelSigaction) {
        let mut old = KernelSigaction::default();
        let result = self.rt_sigaction_install(signum, None, Some(&mut old));
        (result, old)
    }

    /// A probe-side observation with no kernel call behind it: an ordering
    /// mark (`helper_kill` right before a helper thread signals the main
    /// thread) or a fact a handler recorded. `fields` are recorded verbatim.
    pub fn mark(&self, op: &str, fields: &[(&str, Value)]) {
        let mut builder = self.rec.event(op, 0);
        for (key, value) in fields {
            builder = builder.field(key, value.clone());
        }
        builder.emit();
    }
}
