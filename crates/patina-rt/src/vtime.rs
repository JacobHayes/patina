//! The virtual time table: `(atime, mtime, ctime, btime)`
//! of every sandbox-tmpfs inode the guest changed, keyed by the inode's virtual
//! device and its tmpfs inode number, kept in the control region so that all
//! processes of a run share it. The kernel's own timestamps on these
//! filesystems are never shown to the guest; an inode without an entry (the
//! initial tree, directories the sandbox made) reads as the virtual epoch.

use crate::state::ctl;
use core::sync::atomic::Ordering::Relaxed;
use proto::layout::{FILE_EPOCH_S, REALTIME_EPOCH_S, VCLOCK_BOOT_NS, VDEV_MOUNT_BASE};
use proto::vfs::{Vfs, VtEntry, VT_CAP};

const NS: u64 = 1_000_000_000;

/// What a call did to an inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    /// A new inode: every time is now.
    Create,
    /// Data change, or a directory gaining or losing a name: mtime and ctime.
    Modify,
    /// Attribute change, or a name change of the inode itself: ctime.
    Change,
}

fn vfs() -> &'static mut Vfs {
    unsafe { Vfs::at(crate::state::ctl_base()) }
}

/// Virtual realtime, nanoseconds since 1970: the machine's own (its clock offset added), as the
/// times a machine writes on its files are.
pub fn now() -> u64 {
    (ctl().vclock_ns.load(Relaxed) - VCLOCK_BOOT_NS + REALTIME_EPOCH_S * NS)
        .saturating_add_signed(crate::state::clock_offset())
}

pub fn epoch() -> u64 {
    FILE_EPOCH_S * NS
}

/// The table's key of inode `ino` on the mount with virtual minor `vdev_minor` (below 256): a
/// machine's mounts are numbered in its own mount table, so the machine is part of the key (0 for
/// main, and in a run without machines).
pub fn key(vdev_minor: u64, ino: u64) -> u64 {
    const _: () = assert!(VDEV_MOUNT_BASE + crate::path::MAX_MOUNTS as u64 <= proto::vfs::VT_WORK);
    (crate::state::machine() as u64) << 56 | (vdev_minor & 0xff) << 48 | (ino & 0xffff_ffff_ffff)
}

fn slot(key: u64, insert: bool) -> Option<&'static mut VtEntry> {
    if key == 0 {
        return None;
    }
    let v = vfs();
    let i = match v.vt_find(key)? {
        Ok(i) => return Some(&mut v.vt[i]),
        Err(_) if !insert => return None,
        Err(i) if (v.vt_used as usize) < VT_CAP * 3 / 4 => i,
        Err(_) => {
            // Full of entries: drop those of inodes nothing can reach (deleted, and no
            // descriptor or mapping left). Their numbers are never reused, so no value the
            // program can read changes. If what is left is still over half the table, the
            // program keeps that many changed inodes reachable: a named limit.
            crate::sup::call_sup(proto::ctl::Op::VtReclaim, [0; 6]);
            if v.vt_used as usize > VT_CAP / 2 {
                crate::sup::capacity(proto::ctl::LIMIT_VTIME, (VT_CAP / 2) as u64);
            }
            v.vt_find(key)?.err()?
        }
    };
    v.vt_used += 1;
    let e = epoch();
    v.vt[i] = VtEntry {
        key,
        atime: e,
        mtime: e,
        ctime: e,
        btime: e,
        gone_dev: 0,
    };
    Some(&mut v.vt[i])
}

/// Whether the inode still has a name: `gone_dev` is its real device once it has none
/// (`VtEntry::gone_dev`), 0 while it has one. An inode without an entry needs none.
pub fn names(key: u64, gone_dev: u64) {
    if let Some(e) = slot(key, false) {
        e.gone_dev = gone_dev;
    }
}

/// Record that the current call did `which` to the inode.
pub fn touch(key: u64, which: Which) {
    let t = now();
    if let Some(e) = slot(key, true) {
        match which {
            Which::Create => {
                *e = VtEntry {
                    key,
                    atime: t,
                    mtime: t,
                    ctime: t,
                    btime: t,
                    gone_dev: 0,
                };
            }
            Which::Modify => {
                e.mtime = t;
                e.ctime = t;
            }
            Which::Change => e.ctime = t,
        }
    }
}

/// Times of the inode (the virtual epoch for an inode never changed in this run).
pub fn get(key: u64) -> VtEntry {
    let found = if key == 0 { None } else { slot(key, false) };
    match found {
        Some(e) => *e,
        None => {
            let e = epoch();
            VtEntry {
                key,
                atime: e,
                mtime: e,
                ctime: e,
                btime: e,
                gone_dev: 0,
            }
        }
    }
}

/// `utimensat`: set the named times (None = leave), ctime becomes now.
pub fn set(key: u64, atime: Option<u64>, mtime: Option<u64>) {
    let t = now();
    if let Some(e) = slot(key, true) {
        if let Some(a) = atime {
            e.atime = a;
        }
        if let Some(m) = mtime {
            e.mtime = m;
        }
        e.ctime = t;
    }
}
