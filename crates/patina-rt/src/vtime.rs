//! The virtual time table: `(atime, mtime, ctime, btime)`
//! of every sandbox-tmpfs inode the guest changed, keyed by the inode's virtual
//! device and its tmpfs inode number, kept in the control region so that all
//! processes of a run share it. The kernel's own timestamps on these
//! filesystems are never shown to the guest; an inode without an entry (the
//! initial tree, directories the sandbox made) reads as the virtual epoch.

use crate::state::ctl;
use core::sync::atomic::Ordering::Relaxed;
use proto::layout::{FILE_EPOCH_S, REALTIME_EPOCH_S, VCLOCK_BOOT_NS};
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

/// Virtual realtime, nanoseconds since 1970.
pub fn now() -> u64 {
    ctl().vclock_ns.load(Relaxed) - VCLOCK_BOOT_NS + REALTIME_EPOCH_S * NS
}

pub fn epoch() -> u64 {
    FILE_EPOCH_S * NS
}

pub fn key(vdev_minor: u64, ino: u64) -> u64 {
    (vdev_minor << 48) | (ino & 0xffff_ffff_ffff)
}

fn slot(key: u64, insert: bool) -> Option<&'static mut VtEntry> {
    if key == 0 {
        return None;
    }
    let v = vfs();
    let mut i = (proto::draw::mix64(key) as usize) & (VT_CAP - 1);
    for _ in 0..VT_CAP {
        let k = v.vt[i].key;
        if k == key {
            return Some(&mut v.vt[i]);
        }
        if k == 0 {
            if !insert {
                return None;
            }
            if v.vt_used as usize >= VT_CAP * 3 / 4 {
                crate::sup::host_error(-(crate::raw::e::ENOMEM), 0, proto::ctl::HE_RUNTIME_ASSERT);
            }
            v.vt_used += 1;
            let e = epoch();
            v.vt[i] = VtEntry {
                key,
                atime: e,
                mtime: e,
                ctime: e,
                btime: e,
            };
            return Some(&mut v.vt[i]);
        }
        i = (i + 1) & (VT_CAP - 1);
    }
    None
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
