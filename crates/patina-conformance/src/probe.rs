//! The scenario-facing API: one method per row. Each method issues the call
//! through the scenario's vehicle, records a typed event with the row's
//! normalizations, and returns the kernel-style result (`-errno` on failure) plus
//! whatever the scenario needs to continue. Scenarios never format events by
//! hand.

use crate::observe::{EXPECT_DEATH_OP, EXPECT_EXIT_OP, Id, Norm};
use crate::record::{EventBuilder, Recorder};
use crate::vehicle::{Args, Vehicle, errno_name};
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::ffi::CString;
use std::time::{Duration, Instant};

// The memory and IPC rows (`impl Probe` blocks and their argument types).
mod ipc;
mod memory;
pub use ipc::{Deadline, Key, MsgArg, Notify, SemArg, ShmArg, UNKNOWN_IPC_CMD, Window, perm_mode};
pub use memory::{ANON, At, MapSpec, RW, Region, UNKNOWN_MAP_FLAG};
// The directory-stream API (libc only).
mod dirent;
pub use dirent::{Dir, DirEntry, ReadSpelling};
// glibc's large-file (`*64`) spellings of the file rows (libc only).
mod lfs;
pub use lfs::StatBy;
// The timer, identity, scheduling and limit rows.
mod identity;
mod timers;
pub use identity::{
    CAPABILITY_V3, CapData, Cred, GetRlimit64, GroupsSize, INFINITY, SCHED_ATTR_SIZE_VER0,
    SCHED_ATTR_SIZE_VER1, SchedAttr, SetRlimit64, Shown, Sysinfo, Uts, Who,
};
pub use timers::{
    Arm, ClockArg, Count, MISSING_PID, Micros, Res, SI_KERNEL, SI_TIMER, SetTo, Sigev, Spec,
    TimerId, Tms, Usage, micros, ms, ms_us, spec_ns,
};

pub const AT_FDCWD: i32 = libc::AT_FDCWD;

/// The kernel's `sigset_t` size (`_NSIG / 8`), the size argument of every
/// `rt_sig*` row and `ppoll`.
pub const SIGSET_BYTES: i64 = 8;

/// How long a scenario waits for a child process it forked before it kills
/// the child and fails.
pub const CHILD_DEADLINE: Duration = Duration::from_secs(30);

/// How many times [`Probe::openat2`] issues a `RESOLVE_BENEATH` or
/// `RESOLVE_IN_ROOT` lookup that a system-wide rename or mount raced (EAGAIN)
/// before it records that answer.
const SCOPED_LOOKUP_ATTEMPTS: u32 = 64;

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

/// The host's page size (`sysconf(_SC_PAGESIZE)`): 4 KiB on x86_64, 4, 16 or
/// 64 KiB on arm64.
pub fn page_size() -> usize {
    // SAFETY: sysconf reads a constant.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).expect("sysconf(_SC_PAGESIZE) answers")
}

/// `FUTEX_WAIT` on a word private to the process (the op std's locks use).
pub const FUTEX_WAIT_PRIVATE: i32 = libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG;
/// `FUTEX_WAKE` on a word private to the process.
pub const FUTEX_WAKE_PRIVATE: i32 = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;

/// A pid past `PID_MAX_LIMIT` (4194304 on 64-bit): no process has it.
pub const NO_SUCH_PID: i32 = 0x3fff_ffff;

/// A descriptor number a scenario never opens (below the 1024 limit the
/// runs share, far above what any scenario holds).
pub const CLOSED_FD: i32 = 4000;

/// A negative errno in the kernel convention.
pub const fn neg(errno: i32) -> i64 {
    -(errno as i64)
}

/// An iovec argument that is not a plain list of buffers: the refusal shapes
/// of the vectored rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IovShape {
    /// A NULL vector pointer with this count.
    Null(i64),
    /// This many zero-length segments (the vector itself is valid memory, so
    /// only the count is judged).
    Empty(i64),
    /// One segment whose length is negative as an `ssize_t`.
    NegativeLength,
}

impl IovShape {
    fn label(self) -> String {
        match self {
            IovShape::Null(count) => format!("NULL x{count}"),
            IovShape::Empty(count) => format!("empty x{count}"),
            IovShape::NegativeLength => "negative-length".to_string(),
        }
    }
}

/// The third argument of an `ioctl` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoctlArg {
    /// No argument (0).
    None,
    /// A pointer to this int (`FIONBIO`, `FIOASYNC`).
    In(i32),
    /// A pointer to a zeroed 64-byte buffer the request may fill; its first
    /// int is recorded (`FIONREAD`).
    Out,
    /// A NULL pointer.
    Null,
}

/// What an xattr row names: a path (followed), a link itself (the `l*`
/// rows), or a descriptor (the `f*` rows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrTarget<'a> {
    Path(&'a str),
    Link(&'a str),
    Fd(i32),
    /// A NULL path, through the followed path rows.
    NullPath,
}

/// One decoded `struct inotify_event`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InotifyEvent {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub name: String,
}

/// One decoded directory entry with its `d_off` cookie (a filesystem-chosen
/// position, never recorded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dirent {
    pub name: String,
    pub kind: u8,
    pub off: i64,
}

/// The `cachestat` counters (page counts; never recorded, they are the host
/// page cache's business).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Cachestat {
    pub nr_cache: u64,
    pub nr_dirty: u64,
    pub nr_writeback: u64,
    pub nr_evicted: u64,
    pub nr_recently_evicted: u64,
}

/// `struct file_handle` with room for the largest handle (MAX_HANDLE_SZ).
#[repr(C)]
pub struct FileHandle {
    pub bytes: u32,
    pub kind: i32,
    pub data: [u8; FileHandle::MAX as usize],
}

impl FileHandle {
    pub const MAX: u32 = libc::MAX_HANDLE_SZ as u32;

    /// A zeroed handle declaring `bytes` of room.
    pub fn declaring(bytes: u32) -> FileHandle {
        FileHandle {
            bytes,
            kind: 0,
            data: [0; FileHandle::MAX as usize],
        }
    }
}

/// The kernel's 64-bit `struct statfs` (x86_64 and the generic table alike;
/// glibc's is the same layout). The libc crate hides `f_flags` in private
/// spare words, so the probe spells the struct itself.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}

const _: () = assert!(std::mem::size_of::<Statfs>() == std::mem::size_of::<libc::statfs>());

/// `statfs(2)`'s `ST_VALID`: set in every `f_flags` the kernel reports
/// (`statfs_by_dentry` → `calculate_f_flags`).
pub const ST_VALID: i64 = 0x0020;

/// The kernel's `O_LARGEFILE` bit, which a 64-bit kernel forces into every
/// open (`force_o_largefile`) and `F_GETFL` reports. The libc crate's
/// constant is glibc's userspace spelling (0 on x86_64), so it is spelled
/// here per architecture (x86's 0o100000; arm64's own 0o400000).
#[cfg(target_arch = "x86_64")]
pub const KERNEL_O_LARGEFILE: i64 = 0o100000;
#[cfg(target_arch = "aarch64")]
pub const KERNEL_O_LARGEFILE: i64 = 0o400000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("KERNEL_O_LARGEFILE: spell this architecture's kernel O_LARGEFILE");

/// A `readv`-family read: `(result, the bytes each segment received)`.
pub type SegmentsRead = (i64, Vec<Vec<u8>>);

pub struct Probe {
    /// The scenario name (`fs/rw`).
    pub name: &'static str,
    pub vehicle: Vehicle,
    pub rec: Recorder,
    /// A failed check panics (the native oracle run); otherwise it is recorded
    /// and the scenario continues, so one wrong answer under patina is one
    /// difference rather than a lost stream.
    strict: bool,
    /// The directory this run owns: every path a scenario touches is under it.
    dir: String,
    /// Answer every row past the virtual ABI level with the declared ENOSYS
    /// instead of issuing it: the native run on a host kernel that implements
    /// such a row, whose own answer is not the oracle for a virtual kernel
    /// that lacks it (`--declared-absent`).
    declared_absent: bool,
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
    /// The device, for a scenario's own use (ustat's argument); never
    /// recorded (the host's device numbers are its business).
    pub dev: u64,
    /// The timestamps, for the scenario's own relation checks; never recorded
    /// as fields (absolute times are the host's business, and no
    /// normalization relates two entries' times).
    pub atime_ns: i128,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    /// `statx` only: the birth time when the mask reports one.
    pub btime_ns: Option<i128>,
    /// The allocated 512-byte units, for the scenario's own checks; never
    /// recorded as a field (allocation is the filesystem's business: a
    /// directory's, or a file's past four extents on ext4, differs by
    /// filesystem).
    pub blocks: i64,
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

/// A vectored read's buffers: one of each length, and one iovec naming each.
fn read_vector(lens: &[usize]) -> (Vec<Vec<u8>>, Vec<libc::iovec>) {
    let mut buffers: Vec<Vec<u8>> = lens.iter().map(|&len| vec![0u8; len]).collect();
    let iov = buffers
        .iter_mut()
        .map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        })
        .collect();
    (buffers, iov)
}

/// A vectored write's iovecs, one naming each segment (only read through).
fn write_vector(segments: &[&[u8]]) -> Vec<libc::iovec> {
    segments
        .iter()
        .map(|segment| libc::iovec {
            iov_base: segment.as_ptr() as *mut libc::c_void,
            iov_len: segment.len(),
        })
        .collect()
}

/// Cut `buffers` to what a vectored read answering `result` filled, in
/// order, and render them as the event's `segments` field.
fn filled(buffers: &mut [Vec<u8>], result: i64) -> Value {
    let mut remaining = result.max(0) as usize;
    for buf in buffers.iter_mut() {
        let filled = remaining.min(buf.len());
        buf.truncate(filled);
        remaining -= filled;
    }
    Value::Array(buffers.iter().map(|b| Value::from(printable(b))).collect())
}

/// The lengths of a vectored write's segments.
fn lens_of(segments: &[&[u8]]) -> Vec<usize> {
    segments.iter().map(|segment| segment.len()).collect()
}

mod filesystem;
mod io;
mod metadata;
mod process;
mod readiness;
mod time;
// The network rows (`impl Probe` block and its types).
mod net;
pub use net::{
    ARPHRD_LOOPBACK, AddrInfo, Control, IFNAMSIZ, IFREQ, IfAnswer, IfField, Incoming, NlMsg,
    OptionShown, Outgoing, Ready, Received, RecvSpec, SIOCATMARK, SIOCGIFADDR, SIOCGIFBRDADDR,
    SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFMTU, SIOCGIFNAME,
    SIOCGIFNETMASK, SOCKADDR_UN, SUN_PATH, Sets, SockAddr, attributes, eai_name, family_name, nl,
};

impl Probe {
    pub fn new(name: &'static str, vehicle: Vehicle, strict: bool, dir: String) -> Probe {
        Probe {
            name,
            vehicle,
            rec: Recorder::new(),
            strict,
            dir,
            declared_absent: false,
        }
    }

    /// Substitute the declared ENOSYS for every row past the virtual ABI
    /// level (see the field).
    pub fn with_declared_absent(mut self, declared_absent: bool) -> Probe {
        self.declared_absent = declared_absent;
        self
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

    /// Sleep 20 ms: filesystem timestamps are coarse (a clock tick), and a
    /// pause this long separates two stamps natively and moves the virtual
    /// clock under patina.
    pub fn tick(&self) {
        self.nanosleep(0, 20_000_000);
    }

    /// `openat(AT_FDCWD, path, flags, 0o644)`, which the scenario cannot
    /// continue without.
    pub fn open_or_stop(&self, path: &str, flags: i32) -> i32 {
        let fd = self.openat(AT_FDCWD, path, flags, 0o644);
        self.require("open", fd >= 0);
        fd
    }

    /// Create the empty file `path` with `mode` (`O_EXCL`), and close it.
    pub fn create(&self, path: &str, mode: u32) {
        let fd = self.openat(
            AT_FDCWD,
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            mode,
        );
        self.require("create a file", fd >= 0);
        self.close(fd);
    }

    /// `fstat(fd)`, which the scenario cannot continue without.
    pub fn fstat_or_stop(&self, fd: i32) -> StatView {
        let (r, st) = self.fstat(fd);
        self.require("fstat", r == 0 && st.is_some());
        st.unwrap()
    }

    /// `newfstatat(AT_FDCWD, path, flags)`, which the scenario cannot
    /// continue without.
    pub fn stat_or_stop(&self, path: &str, flags: i32) -> StatView {
        let (r, st) = self.newfstatat(AT_FDCWD, path, flags);
        self.require("newfstatat", r == 0 && st.is_some());
        st.unwrap()
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
        if self.declared_absent && past_virtual_abi(row) {
            return neg(libc::ENOSYS);
        }
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
}

/// Whether `row` is past the virtual ABI level (its registry disposition is
/// `Absent`): the virtual kernel answers it ENOSYS by declaration.
fn past_virtual_abi(row: Syscall) -> bool {
    patina_dst_syscalls::SYSCALLS.iter().any(|entry| {
        entry.id == row && entry.disposition == patina_dst_syscalls::Disposition::Absent
    })
}

/// Decode directory records: `d_ino` (8 bytes), `d_off` (8), `d_reclen` (2),
/// then the name from `name_at`; `kind` reads the type from one record.
fn decode_dirents(bytes: &[u8], name_at: usize, kind: impl Fn(&[u8]) -> u8) -> Vec<Dirent> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + name_at < bytes.len() {
        let off = i64::from_ne_bytes(bytes[offset + 8..offset + 16].try_into().expect("8 bytes"));
        let reclen = u16::from_ne_bytes([bytes[offset + 16], bytes[offset + 17]]) as usize;
        if reclen == 0 || offset + reclen > bytes.len() {
            break;
        }
        let record = &bytes[offset..offset + reclen];
        let name = &record[name_at..];
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        entries.push(Dirent {
            name: String::from_utf8_lossy(&name[..end]).into_owned(),
            kind: kind(record),
            off,
        });
        offset += reclen;
    }
    entries
}
