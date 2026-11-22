//! What a guest path or descriptor names.
//!
//! Two questions, answered separately:
//!
//! * `classify(dirfd, path)`: the `/proc`, `/sys`, `/dev` policy of
//!   the table, decided on the lexically normalised absolute path
//!   (relative paths with `..` are resolved against the real base directory).
//!   It is exact because the runtime resolves symlinks itself before any handler
//!   runs (`resolve`): a path that reaches the policy's ground through a
//!   symlink or a relative name arrives here as that absolute path.
//! * `mount_of(st_dev)`: which mount an object that was actually reached lies
//!   on (its identity and times).

use crate::raw::*;
use core::cell::UnsafeCell;

/// Per-process (per image) runtime state of the files modules. Only the thread
/// holding the turn runs runtime code, so plain mutable statics are safe.
pub struct Global<T>(UnsafeCell<T>);
unsafe impl<T> Sync for Global<T> {}
impl<T> Global<T> {
    pub const fn new(v: T) -> Global<T> {
        Global(UnsafeCell::new(v))
    }
    #[allow(clippy::mut_from_ref)]
    pub fn get(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

pub const PATH_MAX: usize = 4096;

/// Where an object lives, by the mount it was found on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountClass {
    /// A tmpfs created by the sandbox (`/`, `/dev`, `/work`, `/tmp`): fresh, sandbox history only.
    Tmpfs,
    /// `proc`.
    Proc,
    /// `sysfs` (not mounted by the launcher today; listed for completeness).
    Sys,
    /// Host device nodes bound into `/dev` (devtmpfs) and `devpts`.
    DevNodes,
    /// Read-only host files (`/usr`, `/guest`, `/in`, `/etc` data): host-stable.
    HostRo,
}

#[derive(Clone, Copy)]
pub struct Mount {
    pub id: u64,
    /// `st_dev` encoding of the mount's device.
    pub dev: u64,
    pub class: MountClass,
    /// Mount point (NUL-padded) and whether it is `/work`.
    pub point: [u8; 64],
    pub work: bool,
}

pub const MAX_MOUNTS: usize = 64;

pub struct Mounts {
    pub m: [Mount; MAX_MOUNTS],
    pub n: usize,
}

const EMPTY: Mount = Mount {
    id: 0,
    dev: 0,
    class: MountClass::HostRo,
    point: [0; 64],
    work: false,
};
static MOUNTS: Global<Mounts> = Global::new(Mounts {
    m: [EMPTY; MAX_MOUNTS],
    n: 0,
});

pub fn mounts() -> &'static mut Mounts {
    MOUNTS.get()
}

pub fn dev_major(d: u64) -> u64 {
    ((d >> 8) & 0xfff) | ((d >> 32) & !0xfff)
}
pub fn dev_minor(d: u64) -> u64 {
    (d & 0xff) | ((d >> 12) & !0xff)
}
pub fn makedev(ma: u64, mi: u64) -> u64 {
    ((ma & 0xfff) << 8) | ((ma & !0xfff) << 32) | (mi & 0xff) | ((mi & !0xff) << 12)
}

/// Index of the mount with device `dev` (the first one in mountinfo order).
pub fn mount_index(dev: u64) -> Option<usize> {
    let t = mounts();
    t.m[..t.n].iter().position(|m| m.dev == dev)
}

pub fn mount_of(dev: u64) -> Option<&'static Mount> {
    mount_index(dev).map(|i| &mounts().m[i])
}

/// Is `dev` the guest's durable working tree (`/work`)?
pub fn is_work(dev: u64) -> bool {
    mount_of(dev).is_some_and(|m| m.work)
}

/// Build the mount table from the kernel's mountinfo (read by the runtime itself).
pub fn read_mounts() {
    let mut buf = [0u8; 32768];
    let n = crate::loader::read_file(b"/proc/self/mountinfo\0", &mut buf);
    let t = mounts();
    t.n = 0;
    for line in buf[..n].split(|&c| c == b'\n') {
        if line.is_empty() || t.n == MAX_MOUNTS {
            continue;
        }
        let mut f = line.split(|&c| c == b' ');
        let id = dec(f.next().unwrap_or(b""));
        let _parent = f.next();
        let mm = f.next().unwrap_or(b"");
        let colon = mm.iter().position(|&c| c == b':').unwrap_or(mm.len());
        let (ma, mi) = (dec(&mm[..colon]), dec(mm.get(colon + 1..).unwrap_or(b"")));
        let _root = f.next();
        let point = f.next().unwrap_or(b"");
        // fstype follows the " - " separator.
        let mut fstype: &[u8] = b"";
        let mut it = f.skip_while(|w| *w != b"-");
        let _ = it.next();
        if let Some(t) = it.next() {
            fstype = t;
        }
        let class = match fstype {
            b"proc" => MountClass::Proc,
            b"sysfs" => MountClass::Sys,
            b"devtmpfs" | b"devpts" => MountClass::DevNodes,
            b"tmpfs" if ma == 0 => MountClass::Tmpfs,
            _ => MountClass::HostRo,
        };
        let mut p = [0u8; 64];
        let l = point.len().min(63);
        p[..l].copy_from_slice(&point[..l]);
        t.m[t.n] = Mount {
            id,
            dev: makedev(ma, mi),
            class,
            point: p,
            // Each machine's own disk (main's is hidden under a machine's).
            work: point == crate::state::work_path(),
        };
        t.n += 1;
    }
}

pub fn dec(s: &[u8]) -> u64 {
    let mut v = 0u64;
    for &c in s {
        if !c.is_ascii_digit() {
            break;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    v
}

// ---- path policy ----

/// A synthesised `/proc` or `/sys` file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Synth {
    Maps = 1,
    Smaps,
    Stat,
    Status,
    Statm,
    Cgroup,
    Mountinfo,
    Mounts,
    Cmdline,
    Environ,
    Comm,
    Cpuinfo,
    Meminfo,
    SysStat,
    Uptime,
    Loadavg,
    Version,
    Osrelease,
    PidMax,
    Uuid,
    BootId,
    Overcommit,
    CpuOnline,
    CpuPossible,
    CpuPresent,
    ThpEnabled,
    ThpDefrag,
    ThpPmdSize,
    ThpShmem,
    NgroupsMax,
    Filesystems,
    /// The directory `/proc/self/task`: the run's threads of this process.
    Task,
    /// `/proc/sys/net/core/somaxconn` (Go reads it for its listen backlog).
    Somaxconn,
    /// The directory `/proc`: the files the policy lists, `self` and this process's id.
    ProcDir,
    /// The directory `/proc/self` (also `/proc/<own pid>`): the files the policy lists.
    SelfDir,
    /// The directory `/proc/self/fd`: the program's own descriptors.
    FdDir,
}

impl Synth {
    /// A directory the policy hands out (`sys::procfs`): its relative names are policed as the
    /// paths they name (`dir_base`), it lists only what the policy allows, and it never
    /// becomes the working directory.
    pub fn is_dir(self) -> bool {
        matches!(
            self,
            Synth::Task | Synth::ProcDir | Synth::SelfDir | Synth::FdDir
        )
    }
    pub fn from_u8(v: u8) -> Option<Synth> {
        SYNTH_PATHS
            .iter()
            .find(|(_, s)| *s as u8 == v)
            .map(|(_, s)| *s)
    }
    /// The path the guest sees for it (readlink of `/proc/self/fd/N`).
    pub fn path(self) -> &'static [u8] {
        SYNTH_PATHS
            .iter()
            .find(|(_, s)| *s == self)
            .map(|(p, _)| *p)
            .unwrap_or(b"/proc")
    }
}

/// Files under `/proc/self/` (also `/proc/<own pid>/`).
pub const SELF_SYNTH: &[(&[u8], Synth)] = &[
    (b"maps", Synth::Maps),
    (b"smaps", Synth::Smaps),
    (b"stat", Synth::Stat),
    (b"status", Synth::Status),
    (b"statm", Synth::Statm),
    (b"cgroup", Synth::Cgroup),
    (b"mountinfo", Synth::Mountinfo),
    (b"mounts", Synth::Mounts),
    (b"cmdline", Synth::Cmdline),
    (b"environ", Synth::Environ),
    (b"comm", Synth::Comm),
    (b"task", Synth::Task),
    (b"fd", Synth::FdDir),
];

/// Absolute paths of the global synthesised files (the first entry per kind
/// is the name shown by readlink).
pub const SYNTH_PATHS: &[(&[u8], Synth)] = &[
    (b"/proc/self/maps", Synth::Maps),
    (b"/proc/self/smaps", Synth::Smaps),
    (b"/proc/self/stat", Synth::Stat),
    (b"/proc/self/status", Synth::Status),
    (b"/proc/self/statm", Synth::Statm),
    (b"/proc/self/cgroup", Synth::Cgroup),
    (b"/proc/self/mountinfo", Synth::Mountinfo),
    (b"/proc/self/mounts", Synth::Mounts),
    (b"/proc/self/cmdline", Synth::Cmdline),
    (b"/proc/self/environ", Synth::Environ),
    (b"/proc/self/comm", Synth::Comm),
    (b"/proc/self/task", Synth::Task),
    (b"/proc/self/fd", Synth::FdDir),
    (b"/proc/self", Synth::SelfDir),
    (b"/proc", Synth::ProcDir),
    (b"/proc/mounts", Synth::Mounts),
    (b"/proc/cpuinfo", Synth::Cpuinfo),
    (b"/proc/meminfo", Synth::Meminfo),
    (b"/proc/stat", Synth::SysStat),
    (b"/proc/uptime", Synth::Uptime),
    (b"/proc/loadavg", Synth::Loadavg),
    (b"/proc/version", Synth::Version),
    (b"/proc/filesystems", Synth::Filesystems),
    (b"/proc/sys/kernel/osrelease", Synth::Osrelease),
    (b"/proc/sys/kernel/pid_max", Synth::PidMax),
    (b"/proc/sys/kernel/random/uuid", Synth::Uuid),
    (b"/proc/sys/kernel/random/boot_id", Synth::BootId),
    (b"/proc/sys/kernel/ngroups_max", Synth::NgroupsMax),
    (b"/proc/sys/vm/overcommit_memory", Synth::Overcommit),
    (b"/proc/sys/net/core/somaxconn", Synth::Somaxconn),
    (b"/sys/devices/system/cpu/online", Synth::CpuOnline),
    (b"/sys/devices/system/cpu/possible", Synth::CpuPossible),
    (b"/sys/devices/system/cpu/present", Synth::CpuPresent),
    (
        b"/sys/kernel/mm/transparent_hugepage/enabled",
        Synth::ThpEnabled,
    ),
    (
        b"/sys/kernel/mm/transparent_hugepage/defrag",
        Synth::ThpDefrag,
    ),
    (
        b"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
        Synth::ThpPmdSize,
    ),
    (
        b"/sys/kernel/mm/transparent_hugepage/shmem_enabled",
        Synth::ThpShmem,
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Not a policy path: the kernel answers; the result is checked by its mount.
    Plain,
    /// `/proc/self/exe`: the guest image.
    SelfExe,
    /// `/proc/self/fd/N`, `/dev/fd/N`, `/dev/stdin` etc.: the descriptor's file.
    SelfFd(i64),
    /// Synthesised by the runtime.
    Synth(Synth),
    /// `/dev/urandom`, `/dev/random`: entropy.
    Random,
    /// `/dev/tty`, `/dev/console`: no terminal (`ENXIO`).
    NoTty,
    /// `/dev/ptmx`, `/dev/pts/*`: `ENOENT`, not recorded (the policy lists them).
    NoPty,
    /// Anything else under `/proc`, `/sys`, `/dev`: `ENOENT`, recorded in `outcome.refused`.
    Hidden,
}

/// A path buffer on the caller's stack.
pub struct PathBuf {
    pub b: [u8; PATH_MAX],
    pub n: usize,
}

impl PathBuf {
    pub const fn new() -> PathBuf {
        PathBuf {
            b: [0; PATH_MAX],
            n: 0,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
    fn push(&mut self, s: &[u8]) -> bool {
        if self.n + s.len() >= PATH_MAX {
            return false;
        }
        self.b[self.n..self.n + s.len()].copy_from_slice(s);
        self.n += s.len();
        true
    }
}

const AT_FDCWD: i64 = -100;

/// The real path of `dirfd` (or the working directory) by the runtime's own calls.
fn base_dir(dirfd: i64, out: &mut PathBuf) -> bool {
    let r = if dirfd == AT_FDCWD {
        unsafe { sc2(nr::GETCWD, out.b.as_mut_ptr() as u64, PATH_MAX as u64) } // length incl. NUL
    } else {
        let mut lp = [0u8; 32];
        let mut l = 0;
        for &c in b"/proc/self/fd/" {
            lp[l] = c;
            l += 1;
        }
        l += fmt_dec(&mut lp[l..], dirfd as u64);
        lp[l] = 0;
        let r = unsafe {
            sc4(
                nr::READLINKAT,
                AT_FDCWD as u64,
                lp.as_ptr() as u64,
                out.b.as_mut_ptr() as u64,
                PATH_MAX as u64 - 1,
            )
        };
        if r > 0 {
            r + 1
        } else {
            r
        }
    };
    if r <= 0 {
        return false;
    }
    out.n = (r - 1) as usize;
    out.n > 0 && out.b[0] == b'/'
}

pub fn fmt_dec(out: &mut [u8], mut v: u64) -> usize {
    let mut t = [0u8; 20];
    let mut n = 0;
    loop {
        t[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        out[i] = t[n - 1 - i];
    }
    n
}

/// Lexically normalise `p` (absolute) into `out`: no `.`, `..` or repeated `/`.
pub fn normalise(p: &[u8], out: &mut PathBuf) {
    out.n = 0;
    for comp in p.split(|&c| c == b'/') {
        match comp {
            b"" | b"." => {}
            b".." => {
                while out.n > 0 && out.b[out.n - 1] != b'/' {
                    out.n -= 1;
                }
                out.n = out.n.saturating_sub(1);
            }
            c => {
                if !(out.push(b"/") && out.push(c)) {
                    return;
                }
            }
        }
    }
    if out.n == 0 {
        out.push(b"/");
    }
    out.b[out.n] = 0;
}

/// The normalised absolute path of `(dirfd, p)` whatever its form, or of the descriptor
/// `dirfd` itself when `p` is empty (fault records name their object with it).
pub fn full(dirfd: i64, p: &[u8], out: &mut PathBuf) -> bool {
    if p.first() == Some(&b'/') {
        normalise(p, out);
        return true;
    }
    let mut base = PathBuf::new();
    if !base_dir(dirfd, &mut base) {
        return false;
    }
    if !p.is_empty() && !(base.push(b"/") && base.push(p)) {
        return false;
    }
    normalise(base.as_bytes(), out);
    true
}

fn has_dotdot(p: &[u8]) -> bool {
    p.split(|&c| c == b'/').any(|c| c == b"..")
}

/// The policy path of `dirfd` when it is a directory the policy handed out (`Synth::is_dir`):
/// a name relative to it is policed as that path joined with the name.
pub fn dir_base(dirfd: i64) -> Option<&'static [u8]> {
    if dirfd == AT_FDCWD {
        return None;
    }
    crate::sys::procfs::kind_of(dirfd)
        .filter(|k| k.is_dir())
        .map(|k| k.path())
}

/// The normalised absolute path for `(dirfd, p)`, when it can be policy-relevant.
/// Relative paths without `..` stay relative to a directory the guest could only
/// have opened outside `/proc` and `/sys`: a directory handed out there names its entries by
/// its own policy path (`dir_base`: `<tid>/mem` from `/proc/self/task` is policed as
/// `/proc/self/task/<tid>/mem`), and none can be the working directory (`chdir`, `fchdir`).
/// `resolve` gives handlers such names already joined, with `AT_FDCWD`.
pub fn absolute(dirfd: i64, p: &[u8], out: &mut PathBuf) -> bool {
    if p.first() == Some(&b'/') {
        normalise(p, out);
        return true;
    }
    if p.is_empty() {
        return false;
    }
    if let Some(d) = dir_base(dirfd) {
        let mut base = PathBuf::new();
        if !(base.push(d) && base.push(b"/") && base.push(p)) {
            return false;
        }
        normalise(base.as_bytes(), out);
        return true;
    }
    if !has_dotdot(p) {
        return false;
    }
    let mut base = PathBuf::new();
    if !base_dir(dirfd, &mut base) {
        return false;
    }
    if !(base.push(b"/") && base.push(p)) {
        return false;
    }
    normalise(base.as_bytes(), out);
    true
}

fn own_pid() -> i64 {
    crate::state::thread().pid as i64
}

/// `/proc/self/<rest>` or `/proc/<own pid>/<rest>`: `<rest>`.
fn proc_self_rest(s: &[u8]) -> Option<&[u8]> {
    if s == b"/proc/self" {
        return Some(b"");
    }
    if let Some(r) = s.strip_prefix(b"/proc/self/") {
        return Some(r);
    }
    let r = s.strip_prefix(b"/proc/")?;
    let n = r.iter().position(|&c| c == b'/').unwrap_or(r.len());
    if n == 0 || !r[..n].iter().all(|c| c.is_ascii_digit()) || dec(&r[..n]) as i64 != own_pid() {
        return None;
    }
    Some(if n < r.len() { &r[n + 1..] } else { b"" })
}

fn fd_number(s: &[u8]) -> Option<i64> {
    if s.is_empty() || s.len() > 9 || !s.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(dec(s) as i64)
}

/// The policy for a normalised absolute path.
pub fn policy(s: &[u8]) -> Kind {
    let under = |p: &[u8]| s == p || (s.len() > p.len() && s.starts_with(p) && s[p.len()] == b'/');
    // The host trees the supervisor copies from (/.patina/prog, /.patina/copy, /.patina/in).
    if under(b"/.patina") {
        return Kind::Hidden;
    }
    if !(under(b"/proc") || under(b"/sys") || under(b"/dev")) {
        return Kind::Plain;
    }
    if let Some(rest) = proc_self_rest(s) {
        if rest.is_empty() {
            return Kind::Synth(Synth::SelfDir);
        }
        if rest == b"exe" {
            return Kind::SelfExe;
        }
        if let Some(n) = rest.strip_prefix(b"fd/").and_then(fd_number) {
            return Kind::SelfFd(n);
        }
        for (name, k) in SELF_SYNTH {
            if rest == *name {
                return Kind::Synth(*k);
            }
        }
        return Kind::Hidden;
    }
    for (p, k) in SYNTH_PATHS {
        if s == *p {
            return Kind::Synth(*k);
        }
    }
    if let Some(n) = s.strip_prefix(b"/dev/fd/").and_then(fd_number) {
        return Kind::SelfFd(n);
    }
    match s {
        b"/dev/stdin" => return Kind::SelfFd(0),
        b"/dev/stdout" => return Kind::SelfFd(1),
        b"/dev/stderr" => return Kind::SelfFd(2),
        b"/dev/null" | b"/dev/zero" | b"/dev/full" => return Kind::Plain,
        b"/dev/urandom" | b"/dev/random" => return Kind::Random,
        b"/dev/tty" | b"/dev/console" => return Kind::NoTty,
        b"/dev/ptmx" => return Kind::NoPty,
        _ => {}
    }
    if under(b"/dev/pts") {
        return Kind::NoPty;
    }
    if under(b"/dev/shm") {
        return Kind::Plain;
    }
    Kind::Hidden
}

/// Classify `(dirfd, path)`. A null path (`futimens` style) is `Plain`.
pub fn classify(dirfd: i64, p: u64, norm: &mut PathBuf) -> Kind {
    norm.n = 0;
    if p == 0 {
        return Kind::Plain;
    }
    let s = unsafe { crate::loader::cstr(p as *const u8) };
    if !absolute(dirfd, s, norm) {
        return Kind::Plain;
    }
    policy(norm.as_bytes())
}

/// Record an absolute path an `execve` (`what` = `MISSING_EXEC`) or `open` found missing,
/// for the launcher's hint about paths the sandbox lacks.
pub fn missing(what: u8, path: &PathBuf) {
    let v = unsafe { proto::vfs::Vfs::at(crate::state::ctl_base()) };
    v.miss(what, path.as_bytes());
}

/// Record a refusal (shown in `outcome.refused`).
pub fn refuse(what: &[u8]) {
    let v = unsafe { proto::vfs::Vfs::at(crate::state::ctl_base()) };
    v.refuse(what);
}
