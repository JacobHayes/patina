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

/// A negative errno in the kernel convention.
pub fn neg(errno: i32) -> i64 {
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
    /// The glibc wrappers the libc vehicle has resolved, by row (addresses).
    wrappers: std::sync::Mutex<Vec<(Syscall, usize)>>,
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

// The network rows past the IPv4 core (`impl Probe` block and its types).
mod net;
pub use net::{
    ARPHRD_LOOPBACK, AddrInfo, Control, IFNAMSIZ, IFREQ, IfAnswer, IfField, Incoming, NlMsg,
    OptionShown, Outgoing, Ready, Received, RecvSpec, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF,
    SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFMTU, SIOCGIFNAME, SIOCGIFNETMASK,
    SOCKADDR_UN, SUN_PATH, Sets, SockAddr, attributes, eai_name, family_name, nl,
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
            wrappers: std::sync::Mutex::new(Vec::new()),
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
        if self.vehicle == Vehicle::Libc {
            if let Some(symbol) = crate::vehicle::wrapper(row) {
                let address = self.wrapper_address(row, symbol);
                // SAFETY: glibc's definition of the row's wrapper; the
                // scenario owns every pointer in `args`.
                return unsafe { crate::vehicle::wrapper_door(row, address, args) };
            }
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

    /// glibc's wrapper `symbol` for `row`, resolved through `dlsym` at the
    /// row's first call on the libc vehicle. The lookup is not recorded, so
    /// the native streams of every vehicle still agree; the shim defines none
    /// of these wrappers, so under patina it answers NULL and the scenario
    /// stops here, by name.
    fn wrapper_address(&self, row: Syscall, symbol: &str) -> *mut libc::c_void {
        let known = self
            .wrappers
            .lock()
            .unwrap()
            .iter()
            .find(|(bound, _)| *bound == row)
            .map(|(_, address)| *address);
        if let Some(address) = known {
            return address as *mut libc::c_void;
        }
        let address = self.rec.quiet(|| self.resolve(symbol));
        self.require(&format!("glibc's {symbol} resolves"), address.is_some());
        let address = address.unwrap();
        self.wrappers.lock().unwrap().push((row, address as usize));
        address
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
            dev: st.st_dev,
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
            dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
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

    /// `pipe(fds)`, or a NULL array (`null`). An x86_64 legacy row; the
    /// generic table's shape is `pipe2(fds, 0)`, and only the libc vehicle
    /// calls `pipe` itself there.
    pub fn pipe(&self, null: bool) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let array = if null { 0 } else { fds.as_mut_ptr() as i64 };
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_pipe, [array, 0, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a two-int array, or NULL.
            || unsafe { libc::pipe(array as *mut i32) } as i64,
            Syscall::N_pipe2,
            [array, 0, 0, 0, 0, 0],
        );
        let builder = self
            .rec
            .event("pipe", result)
            .arg("fds", if null { "NULL" } else { "fds" });
        let builder = if result >= 0 && !null {
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
    //
    // The IPv4 core; every other family, the message rows, options beyond one
    // int, interfaces, netlink and readiness over sockets are in `net`.

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

    /// A row whose first argument is a descriptor and whose others are plain
    /// integers the scenario chose, recorded under `names`.
    fn fd_ints(&self, row: Syscall, fd: i32, names: &[&str], values: &[i64]) -> i64 {
        let mut args = [fd as i64, 0, 0, 0, 0, 0];
        args[1..=values.len()].copy_from_slice(values);
        let result = self.call(row, args);
        let mut builder = self.fd_arg(self.event(row, result), "fd", fd);
        for (name, value) in names.iter().zip(values) {
            builder = builder.arg(name, *value);
        }
        builder.emit();
        result
    }

    /// A row past the virtual ABI level, issued with plain integer arguments
    /// recorded verbatim (NULL pointers as 0): what is under test is the
    /// number's absence, so nothing is interpreted.
    pub fn absent(&self, row: Syscall, args: &[(&str, i64)]) -> i64 {
        let mut raw = [0i64; 6];
        for (slot, (_, value)) in raw.iter_mut().zip(args) {
            *slot = *value;
        }
        let result = self.call(row, raw);
        let mut builder = self.event(row, result);
        for (name, value) in args {
            builder = builder.arg(name, *value);
        }
        builder.emit();
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
        let c = cstr(path);
        let mut buf = vec![0u8; bufsize.max(1)];
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

    // ---- positional and vectored I/O ------------------------------------------

    /// `pread64(fd, len, offset)`; the bytes read are recorded.
    pub fn pread64(&self, fd: i32, len: usize, offset: i64) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let result = self.call(
            Syscall::N_pread64,
            [fd as i64, buf.as_mut_ptr() as i64, len as i64, offset, 0, 0],
        );
        buf.truncate(result.max(0) as usize);
        let builder = self.event(Syscall::N_pread64, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("len", len)
            .arg("offset", offset);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    pub fn pwrite64(&self, fd: i32, data: &[u8], offset: i64) -> i64 {
        let result = self.call(
            Syscall::N_pwrite64,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                offset,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_pwrite64, result);
        self.fd_arg(builder, "fd", fd)
            .arg("len", data.len())
            .arg("offset", offset)
            .emit();
        result
    }

    /// The trailing arguments of the vectored rows: the position of the
    /// positional ones (`pos_l`; `pos_h` is 0, ignored by a 64-bit kernel) and
    /// the `RWF_*` flags of the `*v2` ones.
    fn vectored_args(
        fd: i32,
        iov: i64,
        count: i64,
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> Args {
        [
            fd as i64,
            iov,
            count,
            offset.unwrap_or(0),
            0,
            flags.unwrap_or(0) as i64,
        ]
    }

    fn vectored_event(
        &self,
        row: Syscall,
        result: i64,
        fd: i32,
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> EventBuilder<'_> {
        let builder = self.fd_arg(self.event(row, result), "fd", fd);
        let builder = match offset {
            Some(offset) => builder.arg("offset", offset),
            None => builder,
        };
        match flags {
            Some(flags) => builder.arg("flags", flags),
            None => builder,
        }
    }

    /// `readv`, `preadv` or `preadv2` into segments of `lens` bytes; what each
    /// segment received is recorded in order.
    pub fn readv_row(
        &self,
        row: Syscall,
        fd: i32,
        lens: &[usize],
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> SegmentsRead {
        let (mut buffers, iov) = read_vector(lens);
        let result = self.call(
            row,
            Self::vectored_args(fd, iov.as_ptr() as i64, iov.len() as i64, offset, flags),
        );
        let segments = filled(&mut buffers, result);
        let builder = self
            .vectored_event(row, result, fd, offset, flags)
            .arg("lens", lens.to_vec());
        let builder = if result >= 0 {
            builder.field("segments", segments)
        } else {
            builder
        };
        builder.emit();
        (result, buffers)
    }

    /// `writev`, `pwritev` or `pwritev2` of `segments`, in order.
    pub fn writev_row(
        &self,
        row: Syscall,
        fd: i32,
        segments: &[&[u8]],
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> i64 {
        let iov = write_vector(segments);
        let result = self.call(
            row,
            Self::vectored_args(fd, iov.as_ptr() as i64, iov.len() as i64, offset, flags),
        );
        let lens = lens_of(segments);
        self.vectored_event(row, result, fd, offset, flags)
            .arg("lens", lens)
            .emit();
        result
    }

    /// A vectored row (`readv`…`pwritev2`, `vmsplice`) over one of the
    /// refusal shapes of its vector.
    pub fn iov_shape(
        &self,
        row: Syscall,
        fd: i32,
        shape: IovShape,
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> i64 {
        let mut scratch = [0u8; 8];
        let (iov, count): (Vec<libc::iovec>, i64) = match shape {
            IovShape::Null(count) => (Vec::new(), count),
            // At least one entry, so even a negative count (judged before the
            // vector is read) hands the kernel a valid pointer.
            IovShape::Empty(count) => (
                (0..count.clamp(1, 2 * libc::UIO_MAXIOV as i64))
                    .map(|_| libc::iovec {
                        iov_base: scratch.as_mut_ptr().cast(),
                        iov_len: 0,
                    })
                    .collect(),
                count,
            ),
            IovShape::NegativeLength => (
                vec![libc::iovec {
                    iov_base: scratch.as_mut_ptr().cast(),
                    iov_len: usize::MAX,
                }],
                1,
            ),
        };
        let pointer = if matches!(shape, IovShape::Null(_)) {
            0
        } else {
            iov.as_ptr() as i64
        };
        let args = if row == Syscall::N_vmsplice {
            [fd as i64, pointer, count, flags.unwrap_or(0) as i64, 0, 0]
        } else {
            Self::vectored_args(fd, pointer, count, offset, flags)
        };
        let result = self.call(row, args);
        self.vectored_event(row, result, fd, offset, flags)
            .arg("iov", shape.label())
            .emit();
        result
    }

    // ---- durability ----------------------------------------------------------

    pub fn fsync(&self, fd: i32) -> i64 {
        self.fd_ints(Syscall::N_fsync, fd, &[], &[])
    }

    pub fn fdatasync(&self, fd: i32) -> i64 {
        self.fd_ints(Syscall::N_fdatasync, fd, &[], &[])
    }

    /// `sync(2)`: never fails; the kernel row answers 0.
    pub fn sync(&self) -> i64 {
        let result = self.call(Syscall::N_sync, [0; 6]);
        self.event(Syscall::N_sync, result).emit();
        result
    }

    pub fn syncfs(&self, fd: i32) -> i64 {
        self.fd_ints(Syscall::N_syncfs, fd, &[], &[])
    }

    pub fn sync_file_range(&self, fd: i32, offset: i64, nbytes: i64, flags: u32) -> i64 {
        self.fd_ints(
            Syscall::N_sync_file_range,
            fd,
            &["offset", "nbytes", "flags"],
            &[offset, nbytes, flags as i64],
        )
    }

    // ---- ioctl ---------------------------------------------------------------

    /// `ioctl(fd, request, arg)`; `name` is the request's name, recorded
    /// beside its number. An `Out` argument's first int is recorded.
    pub fn ioctl(&self, fd: i32, request: u64, name: &str, arg: IoctlArg) -> (i64, Option<i32>) {
        let mut out = [0u8; 64];
        let input: i32 = match arg {
            IoctlArg::In(value) => value,
            _ => 0,
        };
        let pointer = match arg {
            IoctlArg::None | IoctlArg::Null => 0,
            IoctlArg::In(_) => &input as *const i32 as i64,
            IoctlArg::Out => out.as_mut_ptr() as i64,
        };
        let result = self.call(
            Syscall::N_ioctl,
            [fd as i64, request as i64, pointer, 0, 0, 0],
        );
        let value = (result >= 0 && arg == IoctlArg::Out)
            .then(|| i32::from_ne_bytes([out[0], out[1], out[2], out[3]]));
        let builder = self.event(Syscall::N_ioctl, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("request", name)
            .arg("number", request)
            .arg(
                "arg",
                match arg {
                    IoctlArg::None => "none".to_string(),
                    IoctlArg::In(value) => format!("&{value}"),
                    IoctlArg::Out => "out".to_string(),
                    IoctlArg::Null => "NULL".to_string(),
                },
            );
        let builder = match value {
            Some(value) => builder.field("value", value),
            None => builder,
        };
        builder.emit();
        (result, value)
    }

    // ---- filesystem statistics -------------------------------------------------

    /// The `statfs` members every filesystem answers the same way; the rest
    /// (type, sizes, counts, fsid) are the host filesystem's business and are
    /// left to the scenario's relation checks.
    fn statfs_fields<'a>(&self, builder: EventBuilder<'a>, st: &Statfs) -> EventBuilder<'a> {
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
            XattrTarget::Path(_) => path,
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
        }
    }

    fn xattr_call(&self, row: Syscall, target: XattrTarget<'_>, rest: [i64; 4]) -> i64 {
        let path = match target {
            XattrTarget::Path(path) | XattrTarget::Link(path) => Some(cstr(path)),
            XattrTarget::Fd(_) => None,
        };
        let first = match (&path, target) {
            (Some(c), _) => c.as_ptr() as i64,
            (None, XattrTarget::Fd(fd)) => fd as i64,
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

    // ---- openat2 -------------------------------------------------------------

    /// `openat2(dirfd, path, how, size)`: `how` is `(flags, mode, resolve)`
    /// followed by `trailing` in the next u64 (read by the kernel only when
    /// `size` covers it), in a zeroed page-sized buffer, so any `size` up to a
    /// page is readable memory and a larger one is refused unread.
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

    // ---- in-kernel copies ------------------------------------------------------

    fn offset_arg<'a>(
        builder: EventBuilder<'a>,
        key: &str,
        offset: Option<i64>,
    ) -> EventBuilder<'a> {
        match offset {
            Some(offset) => builder.arg(key, offset),
            None => builder.arg(key, "NULL"),
        }
    }

    /// `copy_file_range`; a `Some` offset is passed by pointer and its value
    /// after the call is returned and recorded.
    pub fn copy_file_range(
        &self,
        fd_in: i32,
        off_in: Option<i64>,
        fd_out: i32,
        off_out: Option<i64>,
        len: usize,
        flags: u32,
    ) -> (i64, Option<i64>, Option<i64>) {
        self.two_offsets(
            Syscall::N_copy_file_range,
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            flags,
        )
    }

    /// `splice`, shaped like `copy_file_range`.
    pub fn splice(
        &self,
        fd_in: i32,
        off_in: Option<i64>,
        fd_out: i32,
        off_out: Option<i64>,
        len: usize,
        flags: u32,
    ) -> (i64, Option<i64>, Option<i64>) {
        self.two_offsets(
            Syscall::N_splice,
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            flags,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn two_offsets(
        &self,
        row: Syscall,
        fd_in: i32,
        off_in: Option<i64>,
        fd_out: i32,
        off_out: Option<i64>,
        len: usize,
        flags: u32,
    ) -> (i64, Option<i64>, Option<i64>) {
        let mut pos_in = off_in.unwrap_or(0);
        let mut pos_out = off_out.unwrap_or(0);
        let result = self.call(
            row,
            [
                fd_in as i64,
                off_in.map_or(0, |_| &mut pos_in as *mut i64 as i64),
                fd_out as i64,
                off_out.map_or(0, |_| &mut pos_out as *mut i64 as i64),
                len as i64,
                flags as i64,
            ],
        );
        let after_in = off_in.map(|_| pos_in);
        let after_out = off_out.map(|_| pos_out);
        let builder = self.fd_arg(self.event(row, result), "fd_in", fd_in);
        let builder = Self::offset_arg(builder, "off_in", off_in);
        let builder = self.fd_arg(builder, "fd_out", fd_out);
        let builder = Self::offset_arg(builder, "off_out", off_out)
            .arg("len", len)
            .arg("flags", flags);
        let builder = match after_in {
            Some(pos) => builder.field("off_in_after", pos),
            None => builder,
        };
        let builder = match after_out {
            Some(pos) => builder.field("off_out_after", pos),
            None => builder,
        };
        builder.emit();
        (result, after_in, after_out)
    }

    /// `sendfile(out_fd, in_fd, offset, count)`; a `Some` offset is passed by
    /// pointer and its value after the call returned and recorded.
    pub fn sendfile(
        &self,
        out_fd: i32,
        in_fd: i32,
        offset: Option<i64>,
        count: usize,
    ) -> (i64, Option<i64>) {
        let mut pos = offset.unwrap_or(0);
        let result = self.call(
            Syscall::N_sendfile,
            [
                out_fd as i64,
                in_fd as i64,
                offset.map_or(0, |_| &mut pos as *mut i64 as i64),
                count as i64,
                0,
                0,
            ],
        );
        let after = offset.map(|_| pos);
        let builder = self.fd_arg(self.event(Syscall::N_sendfile, result), "out_fd", out_fd);
        let builder = self.fd_arg(builder, "in_fd", in_fd);
        let builder = Self::offset_arg(builder, "offset", offset).arg("count", count);
        let builder = match after {
            Some(pos) => builder.field("offset_after", pos),
            None => builder,
        };
        builder.emit();
        (result, after)
    }

    pub fn tee(&self, fd_in: i32, fd_out: i32, len: usize, flags: u32) -> i64 {
        let result = self.call(
            Syscall::N_tee,
            [fd_in as i64, fd_out as i64, len as i64, flags as i64, 0, 0],
        );
        let builder = self.fd_arg(self.event(Syscall::N_tee, result), "fd_in", fd_in);
        self.fd_arg(builder, "fd_out", fd_out)
            .arg("len", len)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `vmsplice` of `segments` into a pipe's write end.
    pub fn vmsplice(&self, fd: i32, segments: &[&[u8]], flags: u32) -> i64 {
        let iov = write_vector(segments);
        let result = self.call(
            Syscall::N_vmsplice,
            [
                fd as i64,
                iov.as_ptr() as i64,
                iov.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let lens = lens_of(segments);
        self.fd_arg(self.event(Syscall::N_vmsplice, result), "fd", fd)
            .arg("lens", lens)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `vmsplice` from a pipe's read end into segments of `lens` bytes (the
    /// copy-out direction).
    pub fn vmsplice_read(&self, fd: i32, lens: &[usize], flags: u32) -> SegmentsRead {
        let (mut buffers, iov) = read_vector(lens);
        let result = self.call(
            Syscall::N_vmsplice,
            [
                fd as i64,
                iov.as_ptr() as i64,
                iov.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let segments = filled(&mut buffers, result);
        let builder = self
            .fd_arg(self.event(Syscall::N_vmsplice, result), "fd", fd)
            .arg("lens", lens.to_vec())
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("segments", segments)
        } else {
            builder
        };
        builder.emit();
        (result, buffers)
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

    // ---- entropy edge ----------------------------------------------------------

    /// `getrandom(NULL, len, flags)`.
    pub fn getrandom_null(&self, len: usize, flags: u32) -> i64 {
        let result = self.call(Syscall::N_getrandom, [0, len as i64, flags as i64, 0, 0, 0]);
        self.event(Syscall::N_getrandom, result)
            .arg("buf", "NULL")
            .arg("len", len)
            .arg("flags", flags)
            .emit();
        result
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
