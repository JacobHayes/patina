//! Filesystem state shared by every guest process and read by the launcher:
//! the virtual time table, virtual inode numbers and refused paths
//!.
//!
//! It lives in the control region after the thread slots, so every process of
//! a run sees one table (a file's times must not depend on which process
//! changed it). Written only by whoever holds the turn.

use crate::ctl::{CTL_HEADER_SIZE, MAX_THREADS};

/// Byte offset of `Vfs` in the control region (after the slots, 1 MiB aligned).
pub const VFS_OFFSET: usize =
    (CTL_HEADER_SIZE + MAX_THREADS * core::mem::size_of::<crate::ctl::Slot>() + 0xF_FFFF)
        & !0xF_FFFF;

/// Capacity of the virtual time table (open addressing). A run that changes
/// more sandbox inodes than this ends as `infra`.
pub const VT_CAP: usize = 1 << 17;
/// Virtual inode numbers handed out (pipes, sockets, anonymous inodes, memfds).
pub const VINO_CAP: usize = 1 << 14;
/// First virtual inode number.
pub const VINO_BASE: u64 = 0x10_0000;
pub const REFUSED_CAP: usize = 64;
pub const REFUSED_LEN: usize = 120;
/// Paths a guest could not find, kept for the launcher's hint (`Vfs::missing`).
pub const MISSING_CAP: usize = 32;
pub const MISSING_LEN: usize = 256;
/// The first byte of a missing entry: what the guest tried to do with the path.
pub const MISSING_EXEC: u8 = b'x';
pub const MISSING_OPEN: u8 = b'o';
/// Guest paths the sandbox makes itself: a path under one is never the host's. (`/tmp` is
/// the sandbox's too, but a host path under it can be mounted there: only `/tmp` itself is.)
/// A file missing under one is not kept (a program probes many there); a program is (one run by
/// name, looked for along PATH).
pub const SANDBOX_ROOTS: [&str; 12] = [
    "/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc", "/proc", "/sys", "/dev", "/work", "/guest",
    "/.patina",
];

/// Is `p` `dir` or under it?
pub fn under(p: &[u8], dir: &[u8]) -> bool {
    p == dir || (p.starts_with(dir) && p.get(dir.len()) == Some(&b'/'))
}

/// Times of one sandbox inode, realtime nanoseconds. `key` 0 is an empty entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VtEntry {
    /// `vdev_minor << 48 | ino`.
    pub key: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub btime: u64,
}

/// A real `(st_dev, st_ino)` and the virtual number it was given (index + `VINO_BASE`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VinoEntry {
    pub dev: u64,
    pub ino: u64,
}

#[repr(C)]
pub struct Vfs {
    pub vt_used: u64,
    pub vino_used: u64,
    /// Number of distinct refusals recorded (at most `REFUSED_CAP` are kept).
    pub refused_used: u64,
    pub _pad: u64,
    /// NUL-padded refused paths (or flags such as `O_DIRECT`), in first-seen order.
    pub refused: [[u8; REFUSED_LEN]; REFUSED_CAP],
    pub missing_used: u64,
    pub _pad2: u64,
    /// Absolute paths an `execve` or `open` found missing (`ENOENT`), each after a byte saying
    /// which (`MISSING_EXEC`, `MISSING_OPEN`), NUL-padded, first-seen order. Paths longer than
    /// an entry are not kept. Read only by the launcher, which keeps those the host has.
    pub missing: [[u8; MISSING_LEN]; MISSING_CAP],
    pub vino: [VinoEntry; VINO_CAP],
    pub vt: [VtEntry; VT_CAP],
}

pub const VFS_SIZE: usize = core::mem::size_of::<Vfs>();

impl Vfs {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut Vfs {
        &mut *(ctl_base.add(VFS_OFFSET) as *mut Vfs)
    }
    /// Refused entries as byte strings.
    pub fn refused(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let n = (self.refused_used as usize).min(REFUSED_CAP);
        self.refused[..n].iter().map(|e| {
            let l = e.iter().position(|&c| c == 0).unwrap_or(REFUSED_LEN);
            &e[..l]
        })
    }
    /// Missing entries: (what, path).
    pub fn missing(&self) -> impl Iterator<Item = (u8, &[u8])> + '_ {
        let n = (self.missing_used as usize).min(MISSING_CAP);
        self.missing[..n].iter().map(|e| {
            let l = e.iter().position(|&c| c == 0).unwrap_or(MISSING_LEN);
            (e[0], &e[1..l])
        })
    }
    /// Record a missing path once (first-seen order).
    pub fn miss(&mut self, what: u8, path: &[u8]) {
        if path.len() + 1 >= MISSING_LEN || path.first() != Some(&b'/') {
            return;
        }
        if what != MISSING_EXEC
            && (path == b"/tmp" || SANDBOX_ROOTS.iter().any(|r| under(path, r.as_bytes())))
        {
            return;
        }
        let n = (self.missing_used as usize).min(MISSING_CAP);
        for e in &self.missing[..n] {
            let l = e.iter().position(|&c| c == 0).unwrap_or(MISSING_LEN);
            if e[0] == what && &e[1..l] == path {
                return;
            }
        }
        if n < MISSING_CAP {
            self.missing[n] = [0; MISSING_LEN];
            self.missing[n][0] = what;
            self.missing[n][1..=path.len()].copy_from_slice(path);
            self.missing_used += 1;
        }
    }
    /// Record a refusal once (first-seen order); longer strings are cut.
    pub fn refuse(&mut self, what: &[u8]) {
        let n = (self.refused_used as usize).min(REFUSED_CAP);
        let w = &what[..what.len().min(REFUSED_LEN)];
        for e in &self.refused[..n] {
            let l = e.iter().position(|&c| c == 0).unwrap_or(REFUSED_LEN);
            if &e[..l] == w {
                return;
            }
        }
        if n < REFUSED_CAP {
            self.refused[n] = [0; REFUSED_LEN];
            self.refused[n][..w.len()].copy_from_slice(w);
        }
        self.refused_used += 1;
    }
}
