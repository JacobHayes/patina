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
