//! `Op::VtReclaim`: drop the virtual time table's entries for inodes nothing can reach.
//!
//! An entry is dropped only when its inode has lost its last name (`VtEntry::gone_dev`, set by
//! the runtime at the unlink, `rmdir` or rename that removed it) and no thread of the sandbox
//! has a descriptor, a mapping or its working directory there. Such an inode is gone for good
//! (tmpfs never reuses an inode number), so no value a program can read changes. A thread
//! whose descriptors cannot be listed makes the pass drop nothing. Not seen: a descriptor in flight in an `SCM_RIGHTS`
//! message whose sender has closed its own copy.

use proto::ctl::Ctl;
use proto::vfs::{Vfs, VtEntry, VT_CAP};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;

/// Every `(st_dev, st_ino)` a thread of the sandbox holds open, mapped or as its working
/// directory; None when one thread's could not be read. Each thread is read on its own (under
/// `/proc/PID/task`): a process whose first thread has exited shows no descriptors or
/// mappings at `/proc/PID`, and a thread may have its own descriptor table.
fn held() -> Option<HashSet<(u64, u64)>> {
    let me = std::process::id().to_string();
    let mut out = HashSet::new();
    let gone = |e: &std::io::Error| e.raw_os_error() == Some(libc::ENOENT);
    for p in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = p.file_name();
        let pid = name.to_string_lossy();
        if !pid.bytes().all(|b| b.is_ascii_digit()) || pid == me {
            continue;
        }
        let tasks = match std::fs::read_dir(p.path().join("task")) {
            Ok(t) => t,
            Err(e) if gone(&e) => continue,
            Err(_) => return None,
        };
        for t in tasks.flatten() {
            let dir = t.path();
            match std::fs::read_dir(dir.join("fd")) {
                Ok(fds) => {
                    for f in fds.flatten() {
                        if let Ok(m) = std::fs::metadata(f.path()) {
                            out.insert((m.dev(), m.ino()));
                        }
                    }
                }
                Err(e) if gone(&e) => continue,
                Err(_) => return None,
            }
            if let Ok(m) = std::fs::metadata(dir.join("cwd")) {
                out.insert((m.dev(), m.ino()));
            }
            let maps = match std::fs::read_to_string(dir.join("maps")) {
                Ok(m) => m,
                Err(e) if gone(&e) => continue,
                Err(_) => return None,
            };
            for line in maps.lines() {
                // address perms offset major:minor inode [path]
                let mut f = line.split_ascii_whitespace().skip(3);
                let (Some(dev), Some(ino)) = (f.next(), f.next()) else {
                    continue;
                };
                let Some((ma, mi)) = dev.split_once(':') else {
                    continue;
                };
                let (Ok(ma), Ok(mi), Ok(ino)) = (
                    u32::from_str_radix(ma, 16),
                    u32::from_str_radix(mi, 16),
                    ino.parse::<u64>(),
                ) else {
                    continue;
                };
                if ino != 0 {
                    out.insert((libc::makedev(ma, mi), ino));
                }
            }
        }
    }
    Some(out)
}

/// Rebuild the table without the unreachable entries.
pub fn reclaim(ctl: &Ctl) {
    let v = unsafe { Vfs::at(ctl as *const Ctl as *mut u8) };
    let Some(held) = held() else {
        return;
    };
    let keep: Vec<VtEntry> =
        v.vt.iter()
            .filter(|e| e.key != 0)
            .filter(|e| e.gone_dev == 0 || held.contains(&(e.gone_dev, e.key & 0xffff_ffff_ffff)))
            .copied()
            .collect();
    if keep.len() == v.vt_used as usize {
        return;
    }
    v.vt.fill(VtEntry::default());
    for e in &keep {
        let Some(Err(i)) = v.vt_find(e.key) else {
            unreachable!("a key appears twice, or the table is full");
        };
        v.vt[i] = *e;
    }
    v.vt_used = keep.len() as u64;
    debug_assert!(keep.len() <= VT_CAP);
}
