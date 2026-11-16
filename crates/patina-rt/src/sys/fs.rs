//! Paths, directories, metadata, timestamps.
//!
//! Every path-taking call first goes through the `/proc`, `/sys`, `/dev`
//! policy (`crate::path`). Calls that reach the kernel are then checked by
//! what they reached (the mount of the result). Successful mutating calls on
//! a sandbox tmpfs update the virtual time table and, on `/work`, are reported
//! to `after_mutation` (the durability tracker's input).

use super::*;
use crate::path::{self, Kind, MountClass, PathBuf};
use crate::state::proc;
use crate::vtime::{self, Which};
use proto::layout::*;

pub const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_DIRECT: u64 = 0o40000;
const O_DIRECTORY: u64 = 0o200000;
const O_CLOEXEC: u64 = 0o2000000;
const O_TMPFILE: u64 = 0o20000000 | O_DIRECTORY;
const RENAME_EXCHANGE: u64 = 2;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

// ---- the durability tracker's hook (faults attaches the operation log) ----

/// What an attribute change changed (the resulting mode and owner as `stat` reports
/// them after the call, and the extended attribute's name and value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attr<'a> {
    Meta { mode: u32, uid: u32, gid: u32 },
    Times,
    XattrSet { name: &'a [u8], value: &'a [u8] },
    XattrRemove { name: &'a [u8] },
}

/// Where the bytes of a write are, right after the call.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data {
    /// A guest buffer.
    Buf(u64),
    /// A guest iovec array and its count.
    Iov(u64, u64),
    /// Only in the file (copy_file_range, sendfile, splice): read it back from this
    /// descriptor at (offset, length).
    InFile(i64),
}

/// One successful mutating call on `/work`, with exactly the fields of the
/// operation record table (`proto::oplog`). Inode numbers are tmpfs numbers.
/// Names point into guest memory and are valid only during the call.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum FsOp<'a> {
    Create {
        parent: u64,
        name: &'a [u8],
        ino: u64,
        mode: u32,
        kind: u32,
    },
    Mkdir {
        parent: u64,
        name: &'a [u8],
        ino: u64,
        mode: u32,
    },
    Symlink {
        parent: u64,
        name: &'a [u8],
        ino: u64,
        target: &'a [u8],
    },
    Link {
        parent: u64,
        name: &'a [u8],
        ino: u64,
    },
    Unlink {
        parent: u64,
        name: &'a [u8],
        ino: u64,
        nlink_left: u64,
    },
    Rmdir {
        parent: u64,
        name: &'a [u8],
        ino: u64,
        nlink_left: u64,
    },
    Rename {
        old_parent: u64,
        old_name: &'a [u8],
        new_parent: u64,
        new_name: &'a [u8],
        ino: u64,
        replaced: u64,
        flags: u64,
    },
    Write {
        ino: u64,
        offset: u64,
        len: u64,
        data: Data,
    },
    Truncate {
        ino: u64,
        size: u64,
    },
    Fallocate {
        ino: u64,
        mode: u64,
        offset: u64,
        len: u64,
    },
    SetAttr {
        ino: u64,
        what: Attr<'a>,
    },
    MmapDirty {
        ino: u64,
        offset: u64,
        len: u64,
        data: u64,
    },
    Fsync {
        ino: u64,
        data_only: bool,
    },
    FsyncDir {
        ino: u64,
    },
    FsyncFail {
        ino: u64,
    },
    Sync,
    Close {
        ino: u64,
        truncated_to_zero: bool,
    },
}

/// Called after each successful mutating call on `/work`: the operation log.
pub fn after_mutation(op: &FsOp) {
    crate::oplog::record(op);
}

// ---- raw helpers ----

pub type St = [u64; 18];

pub fn fstatat_raw(dirfd: i64, p: u64, flags: u64) -> Option<St> {
    let mut st: St = [0; 18];
    let r = unsafe { sc4(262, dirfd as u64, p, st.as_mut_ptr() as u64, flags) };
    (r == 0).then_some(st)
}

pub fn fstat_raw(fd: i64) -> Option<St> {
    let mut st: St = [0; 18];
    let r = unsafe { sc2(5, fd as u64, st.as_mut_ptr() as u64) };
    (r == 0).then_some(st)
}

fn mode_of(st: &St) -> u32 {
    st[3] as u32
}

/// Virtual time key of an inode on a sandbox tmpfs.
pub fn vkey(st: &St) -> Option<u64> {
    let i = path::mount_index(st[0])?;
    (path::mounts().m[i].class == MountClass::Tmpfs)
        .then(|| vtime::key(VDEV_MOUNT_BASE + i as u64, st[1]))
}

fn touch(st: &Option<St>, w: Which) {
    if let Some(k) = st.as_ref().and_then(vkey) {
        vtime::touch(k, w);
    }
}

fn on_work(st: &Option<St>) -> bool {
    st.as_ref().is_some_and(|s| path::is_work(s[0]))
}

unsafe fn cs<'a>(p: u64) -> &'a [u8] {
    if p == 0 {
        &[]
    } else {
        crate::loader::cstr(p as *const u8)
    }
}

/// Split a path into (directory part, last component), ignoring trailing slashes.
fn split(p: &[u8]) -> (Option<&[u8]>, &[u8]) {
    let mut end = p.len();
    while end > 1 && p[end - 1] == b'/' {
        end -= 1;
    }
    let p = &p[..end];
    match p.iter().rposition(|&c| c == b'/') {
        None => (None, p),
        Some(0) => (Some(b"/"), &p[1..]),
        Some(i) => (Some(&p[..i]), &p[i + 1..]),
    }
}

/// `stat` of the directory that holds the last component of `p`.
fn parent_stat(dirfd: i64, p: &[u8]) -> Option<St> {
    let (dir, _) = split(p);
    let mut b = [0u8; path::PATH_MAX];
    let d = dir.unwrap_or(b".");
    if d.len() >= b.len() {
        return None;
    }
    b[..d.len()].copy_from_slice(d);
    fstatat_raw(dirfd, b.as_ptr() as u64, 0)
}

fn name_of(p: &[u8]) -> &[u8] {
    split(p).1
}

/// A node created by a call outside this module (`bind` of an `AF_UNIX` socket to a path,
/// `p` a NUL-terminated path relative to the working directory): the creation's times, and a
/// `Create` record when it is on `/work`, as `mknod` gets.
pub fn created_elsewhere(p: u64) {
    let ps = unsafe { cs(p) };
    let st = fstatat_raw(AT_FDCWD, p, AT_SYMLINK_NOFOLLOW);
    let parent = parent_stat(AT_FDCWD, ps);
    touch(&st, Which::Create);
    touch(&parent, Which::Modify);
    if on_work(&st) {
        let s = st.unwrap();
        let mode = mode_of(&s);
        let pino = parent.map(|p| p[1]).unwrap_or(0);
        after_mutation(&FsOp::Create {
            parent: pino,
            name: name_of(ps),
            ino: s[1],
            mode: mode & 0o7777,
            kind: mode & S_IFMT,
        });
    }
}

/// `open(O_CREAT)` without `O_EXCL` follows a dangling symlink in the last component and
/// creates its target. Resolve that chain into `buf` (the path of the file that was created,
/// relative to `dirfd`); returns its length, or None when the last component is no symlink.
fn created_through_symlink(dirfd: i64, p: &[u8], buf: &mut [u8; path::PATH_MAX]) -> Option<usize> {
    const READLINKAT: u64 = 267;
    let mut cur = [0u8; path::PATH_MAX];
    if p.len() >= cur.len() {
        return None;
    }
    cur[..p.len()].copy_from_slice(p);
    let mut n = p.len();
    let mut followed = false;
    for _ in 0..40 {
        cur[n] = 0;
        let st = fstatat_raw(dirfd, cur.as_ptr() as u64, 0x100)?;
        if mode_of(&st) & S_IFMT != 0o120000 {
            break;
        }
        let mut t = [0u8; path::PATH_MAX];
        let l = unsafe {
            sc4(
                READLINKAT,
                dirfd as u64,
                cur.as_ptr() as u64,
                t.as_mut_ptr() as u64,
                t.len() as u64 - 1,
            )
        };
        if l <= 0 {
            return None;
        }
        let t = &t[..l as usize];
        let mut next = [0u8; path::PATH_MAX];
        let m = if t[0] == b'/' {
            next[..t.len()].copy_from_slice(t);
            t.len()
        } else {
            let dir = split(&cur[..n]).0;
            let mut m = 0;
            if let Some(d) = dir {
                if d.len() + 1 + t.len() >= next.len() {
                    return None;
                }
                next[..d.len()].copy_from_slice(d);
                m = d.len();
                if d != b"/" {
                    next[m] = b'/';
                    m += 1;
                }
            }
            if m + t.len() >= next.len() {
                return None;
            }
            next[m..m + t.len()].copy_from_slice(t);
            m + t.len()
        };
        cur = next;
        n = m;
        followed = true;
    }
    if !followed {
        return None;
    }
    buf[..n].copy_from_slice(&cur[..n]);
    Some(n)
}

fn dirfd_arg(call: &dyn Call, i: Option<usize>) -> i64 {
    match i {
        Some(i) => call.arg(i) as i32 as i64,
        None => AT_FDCWD,
    }
}

// ---- policy front ----

/// Result of the policy for one path argument.
enum Front {
    /// Pass to the kernel (possibly with a substituted path pointer).
    Go(Kind),
    /// Answered without the kernel.
    Done(i64),
}

/// The errno for a policy path the call may not touch (and record it when the list does not name it).
fn deny_policy(k: Kind, norm: &PathBuf) -> i64 {
    match k {
        Kind::NoTty => -e::ENXIO,
        Kind::NoPty => -e::ENOENT,
        Kind::SelfFd(_) => -e::ENOENT,
        _ => {
            path::refuse(norm.as_bytes());
            -e::ENOENT
        }
    }
}

/// Policy for a call that only reads names (stat, access, readlink, xattr reads).
fn front_read(k: Kind, norm: &PathBuf) -> Front {
    match k {
        Kind::Hidden | Kind::NoPty => Front::Done(deny_policy(k, norm)),
        Kind::SelfFd(n) if n >= FD_HIDDEN_MIN as i64 => Front::Done(-e::ENOENT),
        _ => Front::Go(k),
    }
}

/// Policy for a call that changes names or attributes: only plain paths and the
/// descriptor links reach the kernel.
fn front_write(k: Kind, norm: &PathBuf) -> Front {
    match k {
        Kind::Plain | Kind::Random => Front::Go(k),
        Kind::SelfFd(n) if n < FD_HIDDEN_MIN as i64 => Front::Go(k),
        Kind::Synth(_) | Kind::SelfExe => Front::Done(-e::EACCES),
        _ => Front::Done(deny_policy(k, norm)),
    }
}

fn guest_path_ptr() -> u64 {
    proc().guest_path.as_ptr() as u64
}

// ---- open ----

const RDEV_RANDOM: u64 = (1 << 8) | 8;
const RDEV_URANDOM: u64 = (1 << 8) | 9;
const RDEV_TTY: u64 = 5 << 8;
const RDEV_CONSOLE: u64 = (5 << 8) | 1;
const RDEV_PTMX: u64 = (5 << 8) | 2;

fn open(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let mut a = args(call);
    // (dirfd index, path index, flags)
    let (di, pi) = match nr {
        257 | 437 => (Some(0), 1),
        _ => (None, 0),
    };
    let mut flags = match nr {
        2 => a[1],
        85 => O_CREAT | 1 | O_TRUNC,
        257 => a[2],
        _ => {
            if a[2] == 0 || a[3] < 24 {
                return -e::EINVAL;
            }
            unsafe { *(a[2] as *const u64) }
        }
    };
    let dirfd = dirfd_arg(call, di);
    let mut norm = PathBuf::new();
    let k = path::classify(dirfd, a[pi], &mut norm);
    match k {
        Kind::Hidden | Kind::NoPty | Kind::NoTty => return deny_policy(k, &norm),
        Kind::Synth(s) => {
            set_class(call, Class::Virt);
            if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC) != 0 {
                return -e::EACCES;
            }
            if flags & O_DIRECTORY != 0 && s != path::Synth::Task {
                return -e::ENOTDIR;
            }
            return super::procfs::open(s, flags & O_CLOEXEC != 0);
        }
        Kind::SelfFd(n) if n >= FD_HIDDEN_MIN as i64 => return -e::ENOENT,
        Kind::SelfExe => {
            set_class(call, Class::Virt);
            a[pi] = guest_path_ptr();
        }
        Kind::Random => set_class(call, Class::Virt),
        _ => {}
    }
    if flags & O_DIRECT != 0 {
        // tmpfs has no direct I/O path worth modelling; the flag is dropped and the fact recorded.
        flags &= !O_DIRECT;
        path::refuse(b"O_DIRECT");
        match nr {
            2 => a[1] = flags,
            257 => a[2] = flags,
            437 => unsafe { *(a[2] as *mut u64) = flags },
            _ => {}
        }
    }
    let pstr = unsafe { cs(a[pi]) };
    let tmpfile = flags & O_TMPFILE == O_TMPFILE;
    let creat = flags & O_CREAT != 0 && !tmpfile;
    let existed = creat && (flags & O_EXCL == 0) && fstatat_raw(dirfd, a[pi], 0).is_some();
    let r = if let Some(r) = super::io::fifo_open(nr, &a, dirfd, pi, flags) {
        r // a FIFO without O_NONBLOCK: attempts plus park
    } else if nr == 85 {
        unsafe { sc4(257, AT_FDCWD as u64, a[0], O_CREAT | 1 | O_TRUNC, a[1]) }
    } else {
        unsafe { sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
    };
    host_check(call, r);
    if r < 0 {
        return r;
    }
    let st = fstat_raw(r);
    if let Some(s) = &st {
        let rdev = s[5];
        if s[3] as u32 & S_IFMT == 0o020000 {
            if rdev == RDEV_TTY
                || rdev == RDEV_CONSOLE
                || rdev == RDEV_PTMX
                || path::mount_of(s[0]).is_some_and(|m| m.point.starts_with(b"/dev/pts"))
            {
                unsafe { sc1(nr::CLOSE, r as u64) };
                return -e::ENXIO;
            }
            if rdev == RDEV_RANDOM || rdev == RDEV_URANDOM {
                set_class(call, Class::Virt);
                proc().set_urandom(r, true);
            }
        }
    }
    if let Kind::SelfFd(n) = k {
        if let Some(sk) = super::procfs::kind_of(n) {
            super::procfs::mark(r, Some(sk));
        }
    }
    if on_work(&st) && st.is_some_and(|s| mode_of(&s) & S_IFMT == S_IFREG) {
        crate::oplog::opened(r, st.unwrap()[1]);
    }
    // Timestamps and the operation record.
    if tmpfile {
        touch(&st, Which::Create);
        if on_work(&st) {
            // An unnamed inode: later writes and a `linkat` refer to it.
            let s = st.unwrap();
            after_mutation(&FsOp::Create {
                parent: 0,
                name: b"",
                ino: s[1],
                mode: mode_of(&s) & 0o7777,
                kind: mode_of(&s) & S_IFMT,
            });
        }
    } else if creat && !existed {
        touch(&st, Which::Create);
        let mut via = [0u8; path::PATH_MAX];
        let pstr = match created_through_symlink(dirfd, pstr, &mut via) {
            Some(n) => &via[..n],
            None => pstr,
        };
        let parent = parent_stat(dirfd, pstr);
        touch(&parent, Which::Modify);
        if on_work(&st) {
            let s = st.unwrap();
            after_mutation(&FsOp::Create {
                parent: parent.map(|p| p[1]).unwrap_or(0),
                name: name_of(pstr),
                ino: s[1],
                mode: mode_of(&s) & 0o7777,
                kind: mode_of(&s) & S_IFMT,
            });
        }
    } else if flags & O_TRUNC != 0
        && flags & O_ACCMODE != 0
        && st.is_some_and(|s| mode_of(&s) & S_IFMT == S_IFREG)
    {
        touch(&st, Which::Modify);
        if on_work(&st) {
            after_mutation(&FsOp::Truncate {
                ino: st.unwrap()[1],
                size: 0,
            });
        }
    }
    r
}

// ---- stat family ----

/// Device number reported for objects that live on no mount of the sandbox
/// (pipes, sockets, anonymous inodes, memfds).
pub const VDEV_ANON: u64 = VDEV_MOUNT_BASE - 2;

/// The identity and times the guest sees for a real `(dev, ino)`.
pub struct Ident {
    pub dev: u64,
    pub ino: u64,
    /// None: host-stable, pass the kernel's times.
    pub times: Option<proto::vfs::VtEntry>,
}

pub fn ident(dev: u64, ino: u64) -> Ident {
    match path::mount_index(dev) {
        Some(i) if path::dev_major(dev) == 0 => {
            let m = &path::mounts().m[i];
            let vminor = VDEV_MOUNT_BASE + i as u64;
            let ino = if m.class == MountClass::Proc {
                crate::vino::of(dev, ino)
            } else {
                ino
            };
            let times = if m.class == MountClass::Tmpfs {
                vtime::get(vtime::key(vminor, ino))
            } else {
                vtime::get(0)
            };
            Ident {
                dev: path::makedev(0, vminor),
                ino,
                times: Some(times),
            }
        }
        // A host filesystem bound into the sandbox (/usr): its device number is the host
        // disk's, so it reads as the mount's index too; inode numbers and times are the
        // host files' (host-stable, A), atime as mtime (see `rewrite_stat`).
        Some(i) => Ident {
            dev: path::makedev(0, VDEV_MOUNT_BASE + i as u64),
            ino,
            times: None,
        },
        None if path::dev_major(dev) == 0 => Ident {
            dev: path::makedev(0, VDEV_ANON),
            ino: crate::vino::of(dev, ino),
            times: Some(vtime::get(0)),
        },
        None => Ident {
            dev,
            ino,
            times: None,
        },
    }
}

const NS: u64 = 1_000_000_000;

/// Rewrite a kernel `struct stat` (144 bytes) in guest memory.
pub fn rewrite_stat(p: u64) {
    let w = p as *mut u64;
    unsafe {
        let id = ident(*w, *w.add(1));
        *w = id.dev;
        *w.add(1) = id.ino;
        if let Some(t) = id.times {
            for (k, v) in [(9, t.atime), (11, t.mtime), (13, t.ctime)] {
                *w.add(k) = v / NS;
                *w.add(k + 1) = v % NS;
            }
        } else {
            // Host file: its atime is not host-stable (reading it moves it, `relatime`
            // at most once a day), so it reads as the mtime.
            *w.add(9) = *w.add(11);
            *w.add(10) = *w.add(12);
            // Its owner: the user namespace shows the launcher's own uid and gid as the
            // sandbox's 1000 and every other id as the overflow id, so which host files read
            // as 1000 depends on who launched the run. Every host file reads as the overflow id.
            let ids = p as *mut u32;
            *ids.add(7) = OVERFLOW_ID;
            *ids.add(8) = OVERFLOW_ID;
        }
    }
}

/// The id an unmapped uid or gid reads as in a user namespace (`/proc/sys/kernel/overflowuid`).
const OVERFLOW_ID: u32 = 65534;

/// Rewrite a `struct statx` (256 bytes) in guest memory.
pub fn rewrite_statx(p: u64) {
    const STATX_BTIME: u32 = 0x800;
    const STATX_MNT_ID: u32 = 0x1000;
    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
    unsafe {
        let b = p as *mut u8;
        let mask = b as *mut u32;
        let pino = b.add(32) as *mut u64;
        let dmaj = b.add(136) as *mut u32;
        let dmin = b.add(140) as *mut u32;
        let mnt = b.add(144) as *mut u64;
        let id = ident(path::makedev(*dmaj as u64, *dmin as u64), *pino);
        *dmaj = path::dev_major(id.dev) as u32;
        *dmin = path::dev_minor(id.dev) as u32;
        *pino = id.ino;
        // Mount ids are host-global counters: report the mount's index (+1) instead.
        if *mask & (STATX_MNT_ID | STATX_MNT_ID_UNIQUE) != 0 {
            let idx = path::mounts().m[..path::mounts().n]
                .iter()
                .position(|m| m.id == *mnt)
                .map(|i| i as u64 + 1)
                .unwrap_or(0);
            *mnt = idx;
            *mask = (*mask & !STATX_MNT_ID_UNIQUE) | if idx != 0 { STATX_MNT_ID } else { 0 };
        }
        if id.times.is_none() {
            // Host file: atime reads as the mtime, owner as the overflow id (see `rewrite_stat`).
            *(b.add(64) as *mut u64) = *(b.add(112) as *const u64);
            *(b.add(72) as *mut u32) = *(b.add(120) as *const u32);
            *(b.add(20) as *mut u32) = OVERFLOW_ID;
            *(b.add(24) as *mut u32) = OVERFLOW_ID;
        }
        if let Some(t) = id.times {
            for (off, v) in [
                (64usize, t.atime),
                (80, t.btime),
                (96, t.ctime),
                (112, t.mtime),
            ] {
                if off == 80 && *mask & STATX_BTIME == 0 {
                    continue;
                }
                *(b.add(off) as *mut u64) = v / NS;
                *(b.add(off + 8) as *mut u32) = (v % NS) as u32;
            }
        }
    }
}

fn stat_call(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let mut a = args(call);
    // (dirfd index, path index, buffer index, flags)
    let (di, pi, bi, flags) = match nr {
        4 => (None, Some(0), 1, 0),
        6 => (None, Some(0), 1, AT_SYMLINK_NOFOLLOW),
        5 => (Some(0), None, 1, AT_EMPTY_PATH),
        262 => (Some(0), Some(1), 2, a[3]),
        _ => (Some(0), Some(1), 4, a[2]),
    };
    let dirfd = dirfd_arg(call, di);
    let empty =
        pi.is_none() || (flags & AT_EMPTY_PATH != 0 && unsafe { cs(a[pi.unwrap()]) }.is_empty());
    // A synthesised file, by descriptor or by path.
    let mut norm = PathBuf::new();
    let k = if empty {
        Kind::Plain
    } else {
        path::classify(dirfd, a[pi.unwrap()], &mut norm)
    };
    let synth = if empty {
        super::procfs::kind_of(dirfd)
    } else if let Kind::Synth(s) = k {
        Some(s)
    } else {
        None
    };
    if let Some(s) = synth {
        set_class(call, Class::Virt);
        if a[bi] == 0 {
            return -e::EFAULT;
        }
        return if nr == 332 {
            super::procfs::fake_statx(s, a[bi])
        } else {
            super::procfs::fake_stat(s, a[bi])
        };
    }
    if !empty {
        match front_read(k, &norm) {
            Front::Done(r) => return r,
            Front::Go(Kind::SelfExe) => {
                set_class(call, Class::Virt);
                a[pi.unwrap()] = guest_path_ptr();
            }
            Front::Go(Kind::NoTty) | Front::Go(_) => {}
        }
    }
    let r = unsafe { sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    host_check(call, r);
    if r != 0 {
        return r;
    }
    if nr == 332 {
        rewrite_statx(a[bi]);
    } else {
        rewrite_stat(a[bi]);
    }
    if matches!(k, Kind::Plain) && synth.is_none() {
        set_class(call, Class::Rewrite);
    }
    r
}

// ---- statfs ----

fn statfs_call(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let a = args(call);
    let buf = a[1];
    let st = if nr == 138 {
        if let Some(s) = super::procfs::kind_of(a[0] as i32 as i64) {
            set_class(call, Class::Virt);
            let _ = s;
            return super::procfs::fake_statfs(buf);
        }
        fstat_raw(a[0] as i32 as i64)
    } else {
        let mut norm = PathBuf::new();
        let k = path::classify(AT_FDCWD, a[0], &mut norm);
        match k {
            Kind::Synth(_) => {
                set_class(call, Class::Virt);
                return super::procfs::fake_statfs(buf);
            }
            _ => {
                if let Front::Done(r) = front_read(k, &norm) {
                    return r;
                }
            }
        }
        fstatat_raw(AT_FDCWD, a[0], 0)
    };
    let r = raw(call);
    host_check(call, r);
    if r != 0 {
        return r;
    }
    let w = buf as *mut u64;
    let class = st.and_then(|s| path::mount_of(s[0])).map(|m| m.class);
    unsafe {
        *w.add(7) = 0; // f_fsid: random per superblock
        if class != Some(MountClass::Tmpfs) {
            // Free counts of host and kernel filesystems change outside the sandbox.
            *w.add(2) = 1 << 24;
            *w.add(3) = 1 << 23;
            *w.add(4) = 1 << 23;
            *w.add(5) = 1 << 22;
            *w.add(6) = 1 << 21;
        } else {
            // tmpfs without nr_inodes= sizes its inode limit from the host's RAM, which a
            // ballooned VM changes between runs: keep the used count, fix the limit.
            const FILES: u64 = 1 << 20;
            let used = (*w.add(5)).saturating_sub(*w.add(6));
            *w.add(5) = FILES;
            *w.add(6) = FILES.saturating_sub(used);
        }
    }
    r
}

// ---- readlink ----

fn copy_out(buf: u64, size: u64, s: &[u8]) -> i64 {
    if buf == 0 {
        return -e::EFAULT;
    }
    if size as i64 <= 0 {
        return -e::EINVAL;
    }
    let n = s.len().min(size as usize);
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), buf as *mut u8, n) };
    n as i64
}

fn readlink(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let (di, pi, bi, li) = if nr == 89 {
        (None, 0, 1, 2)
    } else {
        (Some(0), 1, 2, 3)
    };
    let dirfd = dirfd_arg(call, di);
    let (buf, size) = (call.arg(bi), call.arg(li));
    let mut norm = PathBuf::new();
    let k = path::classify(dirfd, call.arg(pi), &mut norm);
    match k {
        Kind::SelfExe => {
            set_class(call, Class::Virt);
            return copy_out(buf, size, proc().guest_path());
        }
        Kind::Synth(_) => return -e::EINVAL,
        Kind::SelfFd(n) if n < FD_HIDDEN_MIN as i64 => {
            if let Some(s) = super::procfs::kind_of(n) {
                set_class(call, Class::Virt);
                return copy_out(buf, size, s.path());
            }
            let mut t = [0u8; path::PATH_MAX];
            let r = unsafe {
                sc4(
                    89,
                    norm.b.as_ptr() as u64,
                    t.as_mut_ptr() as u64,
                    t.len() as u64,
                    0,
                )
            };
            if r < 0 {
                return r;
            }
            let s = &t[..r as usize];
            // pipe:[N] and socket:[N] carry host-global inode numbers.
            for pre in [&b"pipe:["[..], &b"socket:["[..]] {
                if s.starts_with(pre) {
                    set_class(call, Class::Rewrite);
                    let v = crate::vino::of_fd(n).unwrap_or(0);
                    let mut o = [0u8; 48];
                    o[..pre.len()].copy_from_slice(pre);
                    let mut l = pre.len() + path::fmt_dec(&mut o[pre.len()..], v);
                    o[l] = b']';
                    l += 1;
                    return copy_out(buf, size, &o[..l]);
                }
            }
            return copy_out(buf, size, s);
        }
        _ => {}
    }
    if let Front::Done(r) = front_read(k, &norm) {
        return r;
    }
    let r = raw(call);
    host_check(call, r);
    r
}

// ---- access, xattr reads, chdir ----

fn read_path_call(call: &mut dyn Call, di: Option<usize>, pi: usize) -> i64 {
    let nr = call.nr();
    let mut a = args(call);
    let dirfd = dirfd_arg(call, di);
    let mut norm = PathBuf::new();
    let k = path::classify(dirfd, a[pi], &mut norm);
    match k {
        Kind::Synth(_) => {
            set_class(call, Class::Virt);
            return match nr {
                // access: readable, nothing else
                21 | 269 | 439 => {
                    let mode = a[pi + 1];
                    if mode & 3 != 0 {
                        -e::EACCES
                    } else {
                        0
                    }
                }
                80 => -e::ENOTDIR,
                _ => -e::EOPNOTSUPP,
            };
        }
        Kind::SelfExe => {
            set_class(call, Class::Virt);
            a[pi] = guest_path_ptr();
        }
        _ => {
            if let Front::Done(r) = front_read(k, &norm) {
                return r;
            }
        }
    }
    let r = unsafe { sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    host_check(call, r);
    r
}

// ---- mutating path calls ----

/// Names a mutating call touches: (dirfd, path pointer) pairs.
fn name_args(nr: u64, a: &[u64; 6]) -> ([(i64, u64); 2], usize) {
    let fd = |i: usize| a[i] as i32 as i64;
    let none = (AT_FDCWD, 0);
    match nr {
        83 | 133 | 87 | 84 | 90 | 92 | 94 | 76 | 132 | 235 | 188 | 189 | 197 | 198 => {
            ([(AT_FDCWD, a[0]), none], 1)
        }
        258 | 259 | 263 | 268 | 452 | 260 | 261 | 280 | 463 | 466 => ([(fd(0), a[1]), none], 1),
        82 | 86 => ([(AT_FDCWD, a[0]), (AT_FDCWD, a[1])], 2),
        264 | 316 | 265 => ([(fd(0), a[1]), (fd(2), a[3])], 2),
        88 => ([(AT_FDCWD, a[1]), none], 1),
        266 => ([(fd(1), a[2]), none], 1),
        _ => ([none, none], 0),
    }
}

/// Flags of a call that decide whether its last component is followed.
fn nofollow(nr: u64, a: &[u64; 6]) -> bool {
    match nr {
        94 | 189 | 198 => true,
        260 => a[4] & AT_SYMLINK_NOFOLLOW != 0,
        280 => a[3] & AT_SYMLINK_NOFOLLOW != 0,
        452 => a[3] & AT_SYMLINK_NOFOLLOW != 0,
        463 | 466 => a[2] & AT_SYMLINK_NOFOLLOW != 0,
        _ => false,
    }
}

const UTIME_NOW: u64 = (1 << 30) - 1;
const UTIME_OMIT: u64 = (1 << 30) - 2;

/// The (atime, mtime) a utime-family call names (None = leave unchanged).
fn utimes_of(nr: u64, a: &[u64; 6]) -> (Option<u64>, Option<u64>) {
    let now = vtime::now();
    let p = match nr {
        132 | 235 => a[1],
        261 | 280 => a[2],
        _ => 0,
    };
    if p == 0 {
        return (Some(now), Some(now));
    }
    unsafe {
        let w = p as *const u64;
        match nr {
            132 => (Some(*w * NS), Some(*w.add(1) * NS)),
            235 | 261 => (
                Some(*w * NS + *w.add(1) * 1000),
                Some(*w.add(2) * NS + *w.add(3) * 1000),
            ),
            _ => {
                let one = |s: u64, ns: u64| match ns {
                    UTIME_NOW => Some(now),
                    UTIME_OMIT => None,
                    _ => Some(s.wrapping_mul(NS).wrapping_add(ns)),
                };
                (one(*w, *w.add(1)), one(*w.add(2), *w.add(3)))
            }
        }
    }
}

fn mutate(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let a = args(call);
    let (names, nn) = name_args(nr, &a);
    // Policy on every name (utimensat with a null path names its descriptor).
    for &(d, p) in &names[..nn] {
        if p == 0 {
            continue;
        }
        let mut norm = PathBuf::new();
        let k = path::classify(d, p, &mut norm);
        if let Front::Done(r) = front_write(k, &norm) {
            return r;
        }
    }
    let empty_fd = |_d: i64, p: u64| p == 0 || unsafe { cs(p) }.is_empty();
    let nf = if nofollow(nr, &a) {
        AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    // Before the call: the objects that will lose or change a name.
    let (d0, p0) = names[0];
    let obj_before = |d: i64, p: u64| fstatat_raw(d, p, AT_SYMLINK_NOFOLLOW);
    let mut before = [None, None];
    match nr {
        87 | 84 | 263 => before[0] = obj_before(d0, p0),
        82 | 264 | 316 => {
            before[0] = obj_before(d0, p0);
            before[1] = obj_before(names[1].0, names[1].1);
        }
        _ => {}
    }
    let r = raw(call);
    host_check(call, r);
    if r < 0 {
        return r;
    }
    let ps = unsafe { cs(p0) };
    match nr {
        // creations
        83 | 258 | 133 | 259 | 88 | 266 => {
            let st = fstatat_raw(d0, p0, AT_SYMLINK_NOFOLLOW);
            let parent = parent_stat(d0, ps);
            touch(&st, Which::Create);
            touch(&parent, Which::Modify);
            if on_work(&st) {
                let s = st.unwrap();
                let (pino, ino, name) = (parent.map(|p| p[1]).unwrap_or(0), s[1], name_of(ps));
                let mode = mode_of(&s);
                after_mutation(&match nr {
                    83 | 258 => FsOp::Mkdir {
                        parent: pino,
                        name,
                        ino,
                        mode: mode & 0o7777,
                    },
                    88 | 266 => FsOp::Symlink {
                        parent: pino,
                        name,
                        ino,
                        target: unsafe { cs(a[0]) },
                    },
                    _ => FsOp::Create {
                        parent: pino,
                        name,
                        ino,
                        mode: mode & 0o7777,
                        kind: mode & S_IFMT,
                    },
                });
            }
        }
        // removals
        87 | 84 | 263 => {
            let parent = parent_stat(d0, ps);
            touch(&parent, Which::Modify);
            let t = before[0];
            if let Some(s) = &t {
                let left = if mode_of(s) & S_IFMT == S_IFDIR {
                    0
                } else {
                    s[2].saturating_sub(1)
                };
                if left > 0 {
                    touch(&t, Which::Change);
                }
                if on_work(&t) {
                    let (pino, name) = (parent.map(|p| p[1]).unwrap_or(0), name_of(ps));
                    let rmdir = nr == 84 || (nr == 263 && a[2] & AT_REMOVEDIR != 0);
                    after_mutation(&if rmdir {
                        FsOp::Rmdir {
                            parent: pino,
                            name,
                            ino: s[1],
                            nlink_left: 0,
                        }
                    } else {
                        FsOp::Unlink {
                            parent: pino,
                            name,
                            ino: s[1],
                            nlink_left: left,
                        }
                    });
                }
            }
        }
        // renames
        82 | 264 | 316 => {
            let (d1, p1) = names[1];
            let ns = unsafe { cs(p1) };
            let op = parent_stat(d0, ps);
            let np = parent_stat(d1, ns);
            touch(&op, Which::Modify);
            touch(&np, Which::Modify);
            touch(&before[0], Which::Change);
            touch(&before[1], Which::Change);
            if on_work(&before[0]) {
                let flags = if nr == 316 { a[4] } else { 0 };
                let replaced = if flags & RENAME_EXCHANGE != 0 {
                    before[1].map(|s| s[1]).unwrap_or(0)
                } else {
                    before[1].map(|s| s[1]).unwrap_or(0)
                };
                after_mutation(&FsOp::Rename {
                    old_parent: op.map(|p| p[1]).unwrap_or(0),
                    old_name: name_of(ps),
                    new_parent: np.map(|p| p[1]).unwrap_or(0),
                    new_name: name_of(ns),
                    ino: before[0].unwrap()[1],
                    replaced,
                    flags,
                });
            }
        }
        // links
        86 | 265 => {
            let (d1, p1) = names[1];
            let ns = unsafe { cs(p1) };
            let st = fstatat_raw(d1, p1, AT_SYMLINK_NOFOLLOW);
            let np = parent_stat(d1, ns);
            touch(&st, Which::Change);
            touch(&np, Which::Modify);
            if on_work(&st) {
                after_mutation(&FsOp::Link {
                    parent: np.map(|p| p[1]).unwrap_or(0),
                    name: name_of(ns),
                    ino: st.unwrap()[1],
                });
            }
        }
        // attribute changes and truncation by path
        _ => {
            let st = if empty_fd(d0, p0) {
                if p0 == 0 && d0 == AT_FDCWD {
                    None
                } else {
                    fstat_raw(d0)
                }
            } else {
                fstatat_raw(d0, p0, nf)
            };
            let what = match nr {
                90 | 268 | 452 | 92 | 94 | 260 => st.as_ref().map(meta_of),
                188 | 189 | 463 | 197 | 198 | 466 => Some(xattr_of(nr, &a)),
                132 | 235 | 261 | 280 => Some(Attr::Times),
                _ => None,
            };
            match what {
                Some(Attr::Times) => {
                    if let Some(k) = st.as_ref().and_then(vkey) {
                        let (at, mt) = utimes_of(nr, &a);
                        vtime::set(k, at, mt);
                    }
                }
                Some(_) => touch(&st, Which::Change),
                None => touch(&st, Which::Modify), // truncate
            }
            if on_work(&st) {
                let ino = st.unwrap()[1];
                after_mutation(&match what {
                    Some(w) => FsOp::SetAttr { ino, what: w },
                    None => FsOp::Truncate { ino, size: a[1] },
                });
            }
        }
    }
    r
}

/// Mode and owner as `stat` reports them (after the call).
fn meta_of(st: &St) -> Attr<'static> {
    Attr::Meta {
        mode: mode_of(st) & 0o7777,
        uid: (st[3] >> 32) as u32,
        gid: st[4] as u32,
    }
}

/// The extended attribute a set/remove call names: (path or fd) forms by syscall number.
fn xattr_of(nr: u64, a: &[u64; 6]) -> Attr<'static> {
    let bytes = |p: u64, n: u64| -> &'static [u8] {
        if p == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) }
        }
    };
    match nr {
        // setxattr(path, name, value, size, flags), fsetxattr(fd, ...)
        188..=190 => Attr::XattrSet {
            name: unsafe { cs(a[1]) },
            value: bytes(a[2], a[3]),
        },
        // setxattrat(dfd, path, at_flags, name, struct xattr_args { value, size, flags }, usize)
        463 => {
            let (v, n) = if a[4] != 0 {
                unsafe { (*(a[4] as *const u64), *((a[4] + 8) as *const u32) as u64) }
            } else {
                (0, 0)
            };
            Attr::XattrSet {
                name: unsafe { cs(a[3]) },
                value: bytes(v, n),
            }
        }
        466 => Attr::XattrRemove {
            name: unsafe { cs(a[3]) },
        },
        _ => Attr::XattrRemove {
            name: unsafe { cs(a[1]) },
        },
    }
}

/// Attribute and size changes through a descriptor (fchmod, fchown, ftruncate,
/// fallocate, fsetxattr, fremovexattr): the descriptor's inode.
pub fn fd_mutation(call: &mut dyn Call, r: i64) {
    if r < 0 {
        return;
    }
    let nr = call.nr();
    let a = args(call);
    let st = fstat_raw(a[0] as i32 as i64);
    let w = match nr {
        77 | 285 => Which::Modify,
        _ => Which::Change,
    };
    touch(&st, w);
    if on_work(&st) {
        let ino = st.unwrap()[1];
        after_mutation(&match nr {
            91 | 93 => FsOp::SetAttr {
                ino,
                what: meta_of(st.as_ref().unwrap()),
            },
            77 => FsOp::Truncate { ino, size: a[1] },
            285 => FsOp::Fallocate {
                ino,
                mode: a[1],
                offset: a[2],
                len: a[3],
            },
            _ => FsOp::SetAttr {
                ino,
                what: xattr_of(nr, &a),
            },
        });
    }
}

pub fn handle(call: &mut dyn Call) -> Action {
    let r = match call.nr() {
        2 | 85 | 257 | 437 => open(call),
        4 | 5 | 6 | 262 | 332 => stat_call(call),
        137 | 138 => statfs_call(call),
        89 | 267 => readlink(call),
        21 | 80 | 191 | 192 | 194 | 195 => read_path_call(call, None, 0),
        269 | 439 | 464 | 465 => read_path_call(call, Some(0), 1),
        83 | 258 | 133 | 259 | 87 | 84 | 263 | 82 | 264 | 316 | 86 | 265 | 88 | 266 | 90 | 268
        | 452 | 92 | 94 | 260 | 76 | 132 | 235 | 261 | 280 | 188 | 189 | 197 | 198 | 463 | 466 => {
            mutate(call)
        }
        217 | 78 => {
            let r = raw(call);
            host_check(call, r);
            if r > 0 && super::procfs::kind_of(call.arg(0) as i32 as i64).is_some() {
                set_class(call, Class::Rewrite);
                super::procfs::rewrite_dents(call.arg(1), r, call.nr() == 78);
            }
            r
        }
        79 | 81 | 95 => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        _ => return stop_here(call),
    };
    Action::Return(r)
}

/// Build the mount table (called by the loader at every image start).
pub fn read_mounts() {
    path::read_mounts();
    let (t, p) = (path::mounts(), proc());
    p.nmounts = t.n.min(p.mounts.len());
    for i in 0..p.nmounts {
        p.mounts[i] = (t.m[i].id, t.m[i].dev);
    }
}
