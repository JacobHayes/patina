//! Virtual inode numbers for objects whose real numbers come from host-global
//! counters: pipes, sockets, anonymous inodes (eventfd, epoll, ...) and memfds
//! (memfd numbers come from a per-CPU batch of the kernel's internal
//! mount). Numbers are handed out in first-seen order, keyed by the real
//! `(st_dev, st_ino)`, in the control region so that every process of a run
//! agrees (a pipe is shared across `fork`). the network wire uses `of_fd` as the socket key.

use proto::nr;
use proto::vfs::{Vfs, VinoEntry, VINO_BASE, VINO_CAP};

fn vfs() -> &'static mut Vfs {
    unsafe { Vfs::at(crate::state::ctl_base()) }
}

/// The virtual number of the object `(dev, ino)`, allocating one at first sight.
pub fn of(dev: u64, ino: u64) -> u64 {
    let v = vfs();
    let n = v.vino_used as usize;
    // Newest first: recently created objects are the ones being looked at.
    for i in (0..n).rev() {
        let e = v.vino[i];
        if e.dev == dev && e.ino == ino {
            return VINO_BASE + i as u64;
        }
    }
    if n == VINO_CAP {
        crate::sup::capacity(proto::ctl::LIMIT_VINO, VINO_CAP as u64);
    }
    v.vino[n] = VinoEntry { dev, ino };
    v.vino_used += 1;
    VINO_BASE + n as u64
}

/// The virtual number of `(dev, ino)` if it has one; allocates nothing.
pub fn find(dev: u64, ino: u64) -> Option<u64> {
    let v = vfs();
    (0..v.vino_used as usize)
        .rev()
        .find(|&i| v.vino[i].dev == dev && v.vino[i].ino == ino)
        .map(|i| VINO_BASE + i as u64)
}

/// The virtual number of the object open on `fd` (None if `fd` is not open).
#[allow(dead_code)] // the interface the network wire keys sockets by
pub fn of_fd(fd: i64) -> Option<u64> {
    let mut st = [0u64; 18];
    let r = unsafe { crate::raw::sc2(nr::FSTAT, fd as u64, st.as_mut_ptr() as u64) };
    if r != 0 {
        return None;
    }
    Some(of(st[0], st[1]))
}
