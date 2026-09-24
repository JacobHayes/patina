//! The scenario-facing API: one method per row. Each method issues the call
//! through the scenario's vehicle, records a typed event with the row's
//! normalizations, and returns the kernel-style result (`-errno` on failure) plus
//! whatever the scenario needs to continue. Scenarios never format events by
//! hand.

use crate::observe::{EXPECT_DEATH_OP, Id, Norm};
use crate::record::{EventBuilder, Recorder};
use crate::vehicle::{Args, Vehicle, errno_name};
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

pub const AT_FDCWD: i32 = libc::AT_FDCWD;

/// The kernel's `sigset_t` size (`_NSIG / 8`), the size argument of every
/// `rt_sig*` row and `ppoll`.
pub const SIGSET_BYTES: i64 = 8;

/// How long a scenario waits for a child process it forked before it kills
/// the child and fails.
pub const CHILD_DEADLINE: Duration = Duration::from_secs(30);

/// The kernel's `rt_sigaction` struct on x86_64 (NOT glibc's `struct
/// sigaction`, whose field order differs): handler, flags, restorer, then the
/// 8-byte mask. A raw registration needs `SA_RESTORER` with a restorer the
/// kernel can return through, which a scenario reads back from a libc-installed
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

/// The `SA_RESTORER` bit of every action glibc installs on this architecture:
/// set on x86_64 (glibc's own `__restore_rt`); clear on arm64, whose kernel
/// returns from a handler through the vDSO trampoline.
pub const GLIBC_RESTORER: u64 = if cfg!(target_arch = "x86_64") {
    SA_RESTORER
} else {
    0
};

/// The action flags a scenario compares (the kernel adds `SA_RESTORER`, which is
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
    /// The scenario name (`fs/open_rw`).
    pub name: &'static str,
    pub vehicle: Vehicle,
    pub rec: Recorder,
    /// A failed check panics (the native oracle run); otherwise it is recorded
    /// and the scenario continues, so one wrong answer under patina is one
    /// difference rather than a lost stream.
    strict: bool,
    /// The directory this run owns: every path a scenario touches is under it.
    dir: String,
}

/// A forked child a scenario reaps within [`CHILD_DEADLINE`]; dropped
/// unreaped (a scenario that panicked first), it is killed and reaped.
pub struct OwnedChild<'a> {
    probe: &'a Probe,
    pid: Option<libc::pid_t>,
}

impl OwnedChild<'_> {
    /// The child's wait status. Past [`CHILD_DEADLINE`] the child is killed
    /// and the scenario fails.
    pub fn wait(mut self) -> i32 {
        let pid = self.pid.take().expect("an owned child is reaped once");
        let deadline = Instant::now() + CHILD_DEADLINE;
        let mut status = 0;
        loop {
            // SAFETY: `pid` is this process's own positive, unreaped child.
            let reaped = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if reaped == pid {
                return status;
            }
            if reaped < 0 {
                panic!(
                    "{}: waitpid({pid}): {}",
                    self.probe.name,
                    errno_name(crate::vehicle::errno())
                );
            }
            if Instant::now() >= deadline {
                reap(pid);
                panic!(
                    "{}: child {pid} outlived {CHILD_DEADLINE:?}; killed",
                    self.probe.name
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for OwnedChild<'_> {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            reap(pid);
        }
    }
}

/// Kill and reap one positive child pid.
fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: `pid` is a positive child of this process, not yet reaped.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
}

/// The stat members scenarios compare (kind and permissions split out of
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
    /// The timestamps, for the scenario's own relation checks; never recorded
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
    CString::new(text).expect("no interior NUL in scenario paths")
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
    pub fn new(name: &'static str, vehicle: Vehicle, strict: bool, dir: String) -> Probe {
        Probe {
            name,
            vehicle,
            rec: Recorder::new(),
            strict,
            dir,
        }
    }

    /// The directory this run owns, created (unobserved) on first use. The
    /// harness hands the same path to the native and the patina runs; under
    /// patina it exists only in the virtual filesystem.
    pub fn dir(&self) -> String {
        self.rec.quiet(|| {
            std::fs::create_dir_all(&self.dir).expect("create the run directory");
        });
        self.dir.clone()
    }

    /// A semantic property. Under `strict` a false check panics; otherwise it
    /// is recorded (`op: check`, `ret: 0`) and the scenario continues.
    pub fn check(&self, label: &str, ok: bool) -> bool {
        self.rec
            .event(crate::observe::CHECK_OP, if ok { 1 } else { 0 })
            .arg("label", label)
            .emit();
        if self.strict && !ok {
            panic!("{}: check failed: {label}", self.name);
        }
        ok
    }

    /// A precondition the scenario cannot continue without.
    pub fn require(&self, label: &str, ok: bool) {
        if !ok {
            panic!("{}: cannot continue: {label}", self.name);
        }
    }

    pub fn call_observed(&self, row: Syscall, args: Args) -> i64 {
        let result = self.call(row, args);
        self.event(row, result).emit();
        result
    }

    pub fn call_unrecorded(&self, row: Syscall, args: Args) -> i64 {
        self.call(row, args)
    }

    pub fn record_result(&self, row: Syscall, result: i64) {
        self.event(row, result).emit();
    }

    fn call(&self, row: Syscall, args: Args) -> i64 {
        self.vehicle.call(row, args)
    }

    /// A legacy row the generic (arm64) table lacks: the libc vehicle calls
    /// glibc's wrapper (`libc_door`, libc convention), the syscall vehicle the
    /// kernel shape glibc itself issues there (`row` with `args`).
    #[cfg(not(target_arch = "x86_64"))]
    fn legacy(&self, libc_door: impl FnOnce() -> i64, row: Syscall, args: Args) -> i64 {
        match self.vehicle {
            Vehicle::Libc => crate::vehicle::fold_errno(libc_door()),
            Vehicle::Syscall => self.call(row, args),
        }
    }

    fn event(&self, row: Syscall, result: i64) -> EventBuilder<'_> {
        self.rec.event(row.name(), result)
    }

    /// Fork a child process this scenario owns. `fork` (the libc wrapper, or
    /// a row through the vehicle) returns the kernel-style result; a failed
    /// fork is refused before anything can wait (a wait for pid -1 would reap
    /// any child). The child runs `child` and exits with its result.
    pub fn fork_child(
        &self,
        fork: impl FnOnce() -> i64,
        child: impl FnOnce() -> i32,
    ) -> OwnedChild<'_> {
        let pid = fork();
        if pid < 0 {
            panic!("{}: fork failed: {}", self.name, errno_name((-pid) as i32));
        }
        if pid == 0 {
            let code = child();
            // SAFETY: the forked child ends here, running no parent-owned
            // destructors or exit handlers.
            unsafe { libc::_exit(code) }
        }
        OwnedChild {
            probe: self,
            pid: Some(pid as libc::pid_t),
        }
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
            .norm("fields.uid", Norm::Identity(Id::User))
            .field("gid", view.gid)
            .norm("fields.gid", Norm::Identity(Id::Group))
            .field("ino", view.ino)
            .norm("fields.ino", Norm::Inode)
    }

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
            atime_ns: stx.stx_atime.tv_sec as i128 * 1_000_000_000 + stx.stx_atime.tv_nsec as i128,
            mtime_ns: stx.stx_mtime.tv_sec as i128 * 1_000_000_000 + stx.stx_mtime.tv_nsec as i128,
            ctime_ns: stx.stx_ctime.tv_sec as i128 * 1_000_000_000 + stx.stx_ctime.tv_nsec as i128,
            btime_ns: (stx.stx_mask & libc::STATX_BTIME != 0).then(|| {
                stx.stx_btime.tv_sec as i128 * 1_000_000_000 + stx.stx_btime.tv_nsec as i128
            }),
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

    /// One `getdents64` call over `bufsize` bytes; entries decoded as
    /// `name:type` and recorded SORTED (listing order is the host's business).
    pub fn getdents64(&self, fd: i32, bufsize: usize) -> (i64, Vec<(String, u8)>) {
        let mut buf = vec![0u8; bufsize];
        let result = self.call(
            Syscall::N_getdents64,
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
        let builder = self.event(Syscall::N_getdents64, result);
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
        let c = cstr(path);
        let mut buf = vec![0u8; bufsize.max(1)];
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

    // ---- descriptors --------------------------------------------------------

    pub fn pipe2(&self, flags: i32) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let result = self.call(
            Syscall::N_pipe2,
            [fds.as_mut_ptr() as i64, flags as i64, 0, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_pipe2, result).arg("flags", flags);
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
        let result = self.call(Syscall::N_dup, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_dup, result);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result
    }

    /// `dup2(oldfd, newfd)`. The result IS `newfd` on success (a number the
    /// probe chose, not one the kernel allocated), so it is recorded raw; both
    /// arguments are descriptors and normalized as such — `newfd` when it names
    /// something at the time of the call.
    ///
    /// The generic (arm64) table has no `dup2` row: there the kernel shape is
    /// glibc's — `fcntl(oldfd, F_GETFL)` validating equal numbers, else
    /// `dup3(oldfd, newfd, 0)` — and only the libc vehicle calls `dup2` itself.
    pub fn dup2(&self, oldfd: i32, newfd: i32) -> i64 {
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_dup2, [oldfd as i64, newfd as i64, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: plain descriptor numbers.
            || unsafe { libc::dup2(oldfd, newfd) } as i64,
            if oldfd == newfd {
                Syscall::N_fcntl
            } else {
                Syscall::N_dup3
            },
            if oldfd == newfd {
                [oldfd as i64, libc::F_GETFL as i64, 0, 0, 0, 0]
            } else {
                [oldfd as i64, newfd as i64, 0, 0, 0, 0]
            },
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = if oldfd == newfd && result >= 0 {
            i64::from(newfd)
        } else {
            result
        };
        let builder = self.rec.event("dup2", result);
        self.fd_arg(builder, "oldfd", oldfd)
            .arg("newfd", newfd)
            .emit();
        result
    }

    /// `dup3(oldfd, newfd, flags)`; recorded like `dup2`.
    pub fn dup3(&self, oldfd: i32, newfd: i32, flags: i32) -> i64 {
        let result = self.call(
            Syscall::N_dup3,
            [oldfd as i64, newfd as i64, flags as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_dup3, result);
        self.fd_arg(builder, "oldfd", oldfd)
            .arg("newfd", newfd)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `close_range(first, last, flags)`: the bounds are numbers the scenario
    /// chose, recorded raw. The comparison's `fd` namespace retires nothing here
    /// (it retires on `close` events), so a scenario closes the range's members
    /// through `close_range` only when it never reuses them observably.
    pub fn close_range(&self, first: u32, last: u32, flags: u32) -> i64 {
        let result = self.call(
            Syscall::N_close_range,
            [first as i64, last as i64, flags as i64, 0, 0, 0],
        );
        self.event(Syscall::N_close_range, result)
            .arg("first", first)
            .arg("last", last)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `fcntl` with an integer argument. `F_DUPFD*` results are descriptors and
    /// normalized as such; every other result is recorded raw.
    pub fn fcntl(&self, fd: i32, cmd: i32, arg: i64) -> i64 {
        let result = self.call(Syscall::N_fcntl, [fd as i64, cmd as i64, arg, 0, 0, 0]);
        let builder = self.event(Syscall::N_fcntl, result);
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
        let result = self.call(Syscall::N_flock, [fd as i64, operation as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_flock, result);
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
            Syscall::N_clock_gettime,
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
        let builder = self
            .event(Syscall::N_clock_gettime, result)
            .arg("clock", clock);
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
            Syscall::N_gettimeofday,
            [&mut tv as *mut libc::timeval as i64, 0, 0, 0, 0, 0],
        );
        let us = tv.tv_sec as i128 * 1_000_000 + tv.tv_usec as i128;
        let builder = self.event(Syscall::N_gettimeofday, result);
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
        let mut rem = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = self.call(
            Syscall::N_nanosleep,
            [
                &req as *const libc::timespec as i64,
                &mut rem as *mut libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_nanosleep, result)
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
            Syscall::N_clock_nanosleep,
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
            .event(Syscall::N_clock_nanosleep, result)
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
            Syscall::N_getrandom,
            [buf.as_mut_ptr() as i64, len as i64, flags as i64, 0, 0, 0],
        );
        if result >= 0 {
            buf.truncate(result as usize);
        } else {
            buf.clear();
        }
        let builder = self
            .event(Syscall::N_getrandom, result)
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
            Syscall::N_socket,
            [domain as i64, kind as i64, protocol as i64, 0, 0, 0],
        );
        self.event(Syscall::N_socket, result)
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
            Syscall::N_bind,
            [
                fd as i64,
                &raw as *const libc::sockaddr_in as i64,
                std::mem::size_of::<libc::sockaddr_in>() as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_bind, result);
        let builder = self.fd_arg(builder, "fd", fd);
        self.addr_args(builder, "addr", addr).emit();
        result
    }

    /// `bind` with a caller-chosen family/length (for the error rows).
    pub fn bind_raw(&self, fd: i32, family: i32, len: usize) -> i64 {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        raw.sin_family = family as libc::sa_family_t;
        let result = self.call(
            Syscall::N_bind,
            [
                fd as i64,
                &raw as *const libc::sockaddr_in as i64,
                len as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_bind, result);
        self.fd_arg(builder, "fd", fd)
            .arg("family", family)
            .arg("addrlen", len)
            .emit();
        result
    }

    pub fn listen(&self, fd: i32, backlog: i32) -> i64 {
        let result = self.call(Syscall::N_listen, [fd as i64, backlog as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_listen, result);
        self.fd_arg(builder, "fd", fd)
            .arg("backlog", backlog)
            .emit();
        result
    }

    pub fn connect(&self, fd: i32, addr: SocketAddrV4) -> i64 {
        let raw = sockaddr_in(addr);
        let result = self.call(
            Syscall::N_connect,
            [
                fd as i64,
                &raw as *const libc::sockaddr_in as i64,
                std::mem::size_of::<libc::sockaddr_in>() as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_connect, result);
        let builder = self.fd_arg(builder, "fd", fd);
        self.addr_args(builder, "addr", addr).emit();
        result
    }

    pub fn accept4(&self, fd: i32, flags: i32) -> (i32, Option<SocketAddrV4>) {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let result = self.call(
            Syscall::N_accept4,
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
        let builder = self.event(Syscall::N_accept4, result);
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
            Syscall::N_sendto,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                flags as i64,
                ptr,
                len,
            ],
        );
        let builder = self.event(Syscall::N_sendto, result);
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
            Syscall::N_recvfrom,
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
        let builder = self.event(Syscall::N_recvfrom, result);
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

    fn name_call(&self, row: Syscall, fd: i32) -> (i64, Option<SocketAddrV4>) {
        let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let result = self.call(
            row,
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
        let builder = self.event(row, result);
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
        self.name_call(Syscall::N_getsockname, fd)
    }

    pub fn getpeername(&self, fd: i32) -> (i64, Option<SocketAddrV4>) {
        self.name_call(Syscall::N_getpeername, fd)
    }

    pub fn shutdown(&self, fd: i32, how: i32) -> i64 {
        let result = self.call(Syscall::N_shutdown, [fd as i64, how as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_shutdown, result);
        self.fd_arg(builder, "fd", fd).arg("how", how).emit();
        result
    }

    pub fn setsockopt_int(&self, fd: i32, level: i32, name: i32, value: i32) -> i64 {
        let result = self.call(
            Syscall::N_setsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                &value as *const i32 as i64,
                std::mem::size_of::<i32>() as i64,
                0,
            ],
        );
        let builder = self.event(Syscall::N_setsockopt, result);
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
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                &mut value as *mut i32 as i64,
                &mut len as *mut libc::socklen_t as i64,
                0,
            ],
        );
        let builder = self.event(Syscall::N_getsockopt, result);
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
        let result = self.call(Syscall::N_epoll_create1, [flags as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_epoll_create1, result)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn epoll_ctl(&self, epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i64 {
        let mut event = libc::epoll_event { events, u64: data };
        let result = self.call(
            Syscall::N_epoll_ctl,
            [
                epfd as i64,
                op as i64,
                fd as i64,
                &mut event as *mut libc::epoll_event as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_epoll_ctl, result);
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
        let args = [
            epfd as i64,
            events.as_mut_ptr() as i64,
            maxevents as i64,
            timeout_ms as i64,
            0,
            0,
        ];
        // The generic (arm64) table has no `epoll_wait` row: there the kernel
        // shape is `epoll_pwait` with a NULL sigmask, and only the libc vehicle
        // calls glibc's `epoll_wait`.
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_epoll_wait, args);
        #[cfg(not(target_arch = "x86_64"))]
        let result = match self.vehicle {
            // SAFETY: the buffer holds `maxevents` entries.
            Vehicle::Libc => crate::vehicle::fold_errno(unsafe {
                libc::epoll_wait(epfd, events.as_mut_ptr(), maxevents, timeout_ms)
            } as i64),
            Vehicle::Syscall => self.call(Syscall::N_epoll_pwait, args),
        };
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
        let builder = self.rec.event("epoll_wait", result);
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
        let result = self.call(
            Syscall::N_eventfd2,
            [initval as i64, flags as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_eventfd2, result)
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
            Syscall::N_ppoll,
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
        let mut builder = self.event(Syscall::N_ppoll, result).arg("nfds", fds.len());
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
            Syscall::N_futex,
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
            .event(Syscall::N_futex, result)
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
        let result = self.call(Syscall::N_getpid, [0; 6]);
        self.event(Syscall::N_getpid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn getuid(&self) -> i64 {
        let result = self.call(Syscall::N_getuid, [0; 6]);
        self.event(Syscall::N_getuid, result)
            .norm("ret", Norm::Identity(Id::User))
            .emit();
        result
    }

    pub fn getgid(&self) -> i64 {
        let result = self.call(Syscall::N_getgid, [0; 6]);
        self.event(Syscall::N_getgid, result)
            .norm("ret", Norm::Identity(Id::Group))
            .emit();
        result
    }

    pub fn gettid(&self) -> i64 {
        let result = self.call(Syscall::N_gettid, [0; 6]);
        self.event(Syscall::N_gettid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn getppid(&self) -> i64 {
        let result = self.call(Syscall::N_getppid, [0; 6]);
        self.event(Syscall::N_getppid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn getpgid(&self, pid: i32) -> i64 {
        let result = self.call(Syscall::N_getpgid, [pid as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_getpgid, if result >= 0 { 0 } else { result })
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .field("positive", result > 0)
            .emit();
        result
    }

    pub fn getsid(&self, pid: i32) -> i64 {
        let result = self.call(Syscall::N_getsid, [pid as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_getsid, if result >= 0 { 0 } else { result })
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .field("positive", result > 0)
            .emit();
        result
    }

    pub fn kill(&self, pid: i32, sig: i32) -> i64 {
        let result = self.call(Syscall::N_kill, [pid as i64, sig as i64, 0, 0, 0, 0]);
        self.event(Syscall::N_kill, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn tkill(&self, tid: i32, sig: i32) -> i64 {
        let result = self.call(Syscall::N_tkill, [tid as i64, sig as i64, 0, 0, 0, 0]);
        self.event(Syscall::N_tkill, result)
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> i64 {
        let result = self.call(
            Syscall::N_tgkill,
            [tgid as i64, tid as i64, sig as i64, 0, 0, 0],
        );
        self.event(Syscall::N_tgkill, result)
            .arg("tgid", tgid)
            .norm("args.tgid", Norm::Identity(Id::Process))
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity(Id::Process))
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
            Syscall::N_rt_sigprocmask,
            [
                how as i64,
                set.map_or(0, |s| s as *const libc::sigset_t as i64),
                old.map_or(0, |s| s as *mut libc::sigset_t as i64),
                sigset_size as i64,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigprocmask, result)
            .arg("how", how)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn rt_sigpending(&self, set: &mut libc::sigset_t, sigset_size: usize) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigpending,
            [
                set as *mut libc::sigset_t as i64,
                sigset_size as i64,
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigpending, result)
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
            Syscall::N_rt_sigtimedwait,
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
        self.event(Syscall::N_rt_sigtimedwait, result)
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
            Syscall::N_rt_sigsuspend,
            [
                set as *const libc::sigset_t as i64,
                sigset_size as i64,
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigsuspend, result)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn signalfd4(&self, fd: i32, set: &libc::sigset_t, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_signalfd4,
            [
                fd as i64,
                set as *const libc::sigset_t as i64,
                8,
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_signalfd4, result).arg("flags", flags);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    #[cfg(target_arch = "x86_64")]
    pub fn signalfd(&self, fd: i32, set: &libc::sigset_t) -> i32 {
        let result = self.call(
            Syscall::N_signalfd,
            [fd as i64, set as *const libc::sigset_t as i64, 8, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_signalfd, result);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn sigaltstack(&self, new: Option<&libc::stack_t>, old: Option<&mut libc::stack_t>) -> i64 {
        let old_ptr = old
            .as_ref()
            .map_or(0, |s| (*s as *const libc::stack_t).cast_mut() as i64);
        let result = self.call(
            Syscall::N_sigaltstack,
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
        self.event(Syscall::N_sigaltstack, result)
            .field("old_flags", flags)
            .emit();
        result
    }

    pub fn rt_sigaction_raw(&self, signum: i32, size: usize) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigaction,
            [signum as i64, 0, 0, size as i64, 0, 0],
        );
        self.event(Syscall::N_rt_sigaction, result)
            .arg("signum", signum)
            .arg("sigset_size", size)
            .emit();
        result
    }

    pub fn rt_sigqueueinfo(&self, pid: i32, sig: i32, info: &libc::siginfo_t) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigqueueinfo,
            [
                pid as i64,
                sig as i64,
                info as *const libc::siginfo_t as i64,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigqueueinfo, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .arg("si_code", info.si_code)
            .emit();
        result
    }

    pub fn rt_tgsigqueueinfo(&self, tgid: i32, tid: i32, sig: i32, info: &libc::siginfo_t) -> i64 {
        let result = self.call(
            Syscall::N_rt_tgsigqueueinfo,
            [
                tgid as i64,
                tid as i64,
                sig as i64,
                info as *const libc::siginfo_t as i64,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_tgsigqueueinfo, result)
            .arg("tgid", tgid)
            .norm("args.tgid", Norm::Identity(Id::Process))
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .arg("si_code", info.si_code)
            .emit();
        result
    }

    pub fn set_tid_address(&self, ptr: *mut i32) -> i64 {
        let result = self.call(Syscall::N_set_tid_address, [ptr as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_set_tid_address, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn prctl(&self, option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
        let result = self.call(
            Syscall::N_prctl,
            [option as i64, a2 as i64, a3 as i64, a4 as i64, a5 as i64, 0],
        );
        self.event(Syscall::N_prctl, result)
            .arg("option", option)
            .emit();
        result
    }

    pub fn wait4(&self, pid: i32, options: i32) -> (i64, i32) {
        let mut status = 0;
        let result = self.call(
            Syscall::N_wait4,
            [
                pid as i64,
                &mut status as *mut i32 as i64,
                options as i64,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_wait4, result)
            .arg("pid", pid)
            .arg("options", options)
            .field("status", status)
            .emit();
        (result, status)
    }

    pub fn waitid(&self, idtype: i32, id: u32, options: i32) -> (i64, i32) {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_waitid,
            [
                idtype as i64,
                id as i64,
                &mut info as *mut libc::siginfo_t as i64,
                options as i64,
                0,
                0,
            ],
        );
        self.event(Syscall::N_waitid, result)
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

    // ---- the virtual ABI level ----------------------------------------------

    /// A number the vendored table lists but the virtual ABI level lacks
    /// (`fchroot`, 472, since Linux 7.3). What is under test is the row's
    /// absence, so the arguments are recorded verbatim and never interpreted.
    pub fn fchroot(&self, fd: i32, flags: u32) -> i64 {
        let result = self.call(Syscall::N_fchroot, [fd as i64, flags as i64, 0, 0, 0, 0]);
        self.event(Syscall::N_fchroot, result)
            .arg("fd", fd)
            .arg("flags", flags)
            .emit();
        result
    }

    // ---- signals, threads and process rows (the signals family) -------------

    /// Announce that the scenario's next act ends the process on `signal`
    /// (`SIG_DFL` termination). A native signal death is an oracle only when
    /// this is the last recorded event, and the patina run must then end the
    /// same way.
    pub fn dies_by(&self, signal: i32) {
        self.rec
            .event(EXPECT_DEATH_OP, 0)
            .arg("signal", signal)
            .emit();
    }

    /// `pause`: returns only when a handled signal was delivered (`-EINTR`).
    /// An x86_64 legacy row; the generic table's shape is `ppoll` over no
    /// descriptors.
    pub fn pause(&self) -> i64 {
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_pause, [0; 6]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: no arguments.
            || unsafe { libc::pause() } as i64,
            Syscall::N_ppoll,
            [0, 0, 0, 0, SIGSET_BYTES, 0],
        );
        self.rec.event("pause", result).emit();
        result
    }

    pub fn socketpair(&self, domain: i32, kind: i32, protocol: i32) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let result = self.call(
            Syscall::N_socketpair,
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
            .event(Syscall::N_socketpair, result)
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
        self.event(Syscall::N_exit, 0).arg("code", code).emit();
        self.call(Syscall::N_exit, [code as i64, 0, 0, 0, 0, 0]);
        unreachable!("exit returned")
    }

    /// `exit_group`: the whole process ends with `code`. Recorded before the
    /// call, which never returns.
    pub fn exit_group(&self, code: i32) -> ! {
        self.event(Syscall::N_exit_group, 0)
            .arg("code", code)
            .emit();
        self.call(Syscall::N_exit_group, [code as i64, 0, 0, 0, 0, 0]);
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
            Syscall::N_nanosleep,
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
            .event(Syscall::N_nanosleep, result)
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
            Syscall::N_clock_nanosleep,
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
            .event(Syscall::N_clock_nanosleep, result)
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
            Syscall::N_rt_sigaction,
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
            .event(Syscall::N_rt_sigaction, result)
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
                .field(
                    "old_has_restorer",
                    old.flags & SA_RESTORER != 0 && old.restorer != 0,
                ),
            _ => builder,
        };
        builder.emit();
        result
    }

    /// Query an action raw (`act = NULL`), returning it for the scenario's own
    /// use (the restorer a raw install needs).
    pub fn rt_sigaction_query(&self, signum: i32) -> (i64, KernelSigaction) {
        let mut old = KernelSigaction::default();
        let result = self.rt_sigaction_install(signum, None, Some(&mut old));
        (result, old)
    }

    /// A scenario-side observation with no kernel call behind it: an ordering
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
