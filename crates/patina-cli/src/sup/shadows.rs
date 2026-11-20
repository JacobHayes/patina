//! The shadow stores' supervisor half (`proto::oplog::Shadows`): they are made at each
//! incarnation's start (`create`), the records the supervisor appends keep them as the
//! runtime's do (`apply`, from `crash::append`), and the slots of files no process maps are
//! freed (`reclaim`).
//!
//! Trust: the table is in the control region, which a stray store of the program could
//! change. A wrong inode in it makes the wrong store compared or kept, so records the log
//! lacks or holds twice (with the file's true bytes), which the end-of-run self-check reports;
//! the supervisor touches only its own stores (a slot index below `SHADOW_SLOTS`), at offsets
//! a record or a work file's size gives.

use proto::ctl::Ctl;
use proto::layout::FD_SHADOWS;
use proto::oplog::{effect, Dur, Effect, OpKind, Shadows, FALLOC_PUNCH_HOLE, SHADOW_SLOTS};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;

/// The stores: a memfd per slot at `FD_SHADOWS + k`, inherited by the guests (not
/// close-on-exec).
pub fn create() -> Result<(), String> {
    for k in 0..SHADOW_SLOTS as i32 {
        unsafe {
            let fd = libc::memfd_create(c"patina-shadow".as_ptr(), 0);
            if fd < 0 || libc::dup2(fd, FD_SHADOWS + k) != FD_SHADOWS + k {
                return Err(format!("shadow store: {}", std::io::Error::last_os_error()));
            }
            libc::close(fd);
        }
    }
    Ok(())
}

/// The table in the control region: shared memory the guests change too (`&Ctl` is a view of
/// the region, not an owner of its bytes), changed here only while every guest is stopped.
#[allow(clippy::mut_from_ref)]
fn table(ctl: &Ctl) -> &mut Shadows {
    unsafe { &mut Dur::at(ctl as *const Ctl as *mut u8).shadows }
}

pub fn in_use(ctl: &Ctl) -> bool {
    table(ctl).used != 0
}

pub fn reclaim_asked(ctl: &Ctl) -> bool {
    table(ctl).reclaim != 0
}

fn store(k: usize) -> i32 {
    FD_SHADOWS + k as i32
}

fn err(what: &str) -> String {
    format!("shadow store: {what}: {}", std::io::Error::last_os_error())
}

fn stat(fd: i32) -> Result<libc::stat, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(err("fstat"));
    }
    Ok(st)
}

/// What slot `k`'s store holds now, for the table's count.
fn note(s: &mut Shadows, k: usize) -> Result<(), String> {
    let st = stat(store(k))?;
    s.held(k, st.st_blocks as u64 * 512);
    Ok(())
}

/// `[off, off + len)` of slot `k`'s store reads as zeros: cut where it reaches the end,
/// else punched. Neither extends the store.
fn zero(k: usize, off: u64, len: u64) -> Result<(), String> {
    let size = stat(store(k))?.st_size as u64;
    if off >= size {
        return Ok(());
    }
    let r = if off.saturating_add(len) >= size {
        unsafe { libc::ftruncate(store(k), off as i64) }
    } else {
        unsafe {
            libc::fallocate(
                store(k),
                (FALLOC_PUNCH_HOLE as i32) | libc::FALLOC_FL_KEEP_SIZE,
                off as i64,
                len as i64,
            )
        }
    };
    if r != 0 {
        return Err(err("zero"));
    }
    Ok(())
}

/// Empty slot `k` and give it back; on an error the slot is kept as it was.
fn free(s: &mut Shadows, k: usize) -> Result<(), String> {
    zero(k, 0, u64::MAX)?;
    s.ino[k] = 0;
    s.used = s.used.saturating_sub(1);
    s.held(k, 0);
    Ok(())
}

/// `buf.len()` bytes of slot `k`'s store at file offset `off` (zeros past its end).
pub fn read(k: usize, off: u64, buf: &mut [u8]) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        let r = unsafe {
            libc::pread(
                store(k),
                buf[done..].as_mut_ptr() as *mut _,
                buf.len() - done,
                (off + done as u64) as i64,
            )
        };
        if r < 0 {
            return Err(err("read"));
        }
        if r == 0 {
            buf[done..].fill(0);
            break;
        }
        done += r as usize;
    }
    Ok(())
}

pub fn slot_of(ctl: &Ctl, ino: u64) -> Option<usize> {
    table(ctl).slot_of(ino)
}

/// A record the supervisor appended (`crash::append`): its inode's store follows, as for the
/// runtime's records (`rt::oplog::shadow_apply`).
pub fn apply(ctl: &Ctl, kind: OpKind, ino: u64, a: &[u64; 6], data: &[u8]) -> Result<(), String> {
    let s = table(ctl);
    let Some(k) = s.slot_of(ino) else {
        return Ok(());
    };
    match effect(kind, a) {
        Effect::None => Ok(()),
        Effect::New => free(s, k),
        Effect::Zero { off, len } => {
            zero(k, off, len)?;
            note(s, k)
        }
        Effect::Data { off, .. } => {
            let mut done = 0;
            while done < data.len() {
                let r = unsafe {
                    libc::pwrite(
                        store(k),
                        data[done..].as_ptr() as *const _,
                        data.len() - done,
                        (off + done as u64) as i64,
                    )
                };
                if r <= 0 {
                    return Err(err("write"));
                }
                done += r as usize;
            }
            note(s, k)
        }
    }
}

/// Inodes of the work tree (`work_dev`) some process of the sandbox maps shared, from every
/// thread's `/proc/PID/task/TID/maps` (a process whose first thread has exited shows no
/// mappings at `/proc/PID`); None when one could not be read.
fn mapped(work_dev: u64) -> Option<HashSet<u64>> {
    let me = std::process::id().to_string();
    let gone =
        |e: &std::io::Error| matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH));
    let mut out = HashSet::new();
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
            let maps = match std::fs::read_to_string(t.path().join("maps")) {
                Ok(m) => m,
                Err(e) if gone(&e) => continue,
                Err(_) => return None,
            };
            for line in maps.lines() {
                // address perms offset major:minor inode [path]
                let mut f = line.split_ascii_whitespace().skip(1);
                let (Some(perms), Some(dev), Some(ino)) = (f.next(), f.nth(1), f.next()) else {
                    continue;
                };
                if perms.as_bytes().get(3) != Some(&b's') {
                    continue;
                }
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
                if libc::makedev(ma, mi) == work_dev {
                    out.insert(ino);
                }
            }
        }
    }
    Some(out)
}

/// Free the slots of inodes no process maps: their files hold what the log holds, and a
/// later mapping fills a new slot from the file. A thread whose mappings cannot be read
/// makes the pass free nothing. Every guest is stopped at a boundary or in the kernel: the
/// mappings do not change while they are read. Which slots are freed when changes no record
/// (only how much memory the store holds, and when a full table is reported).
pub fn reclaim(ctl: &Ctl, work: &std::path::Path) {
    let s = table(ctl);
    s.reclaim = 0;
    if s.used == 0 {
        return;
    }
    let Ok(work_dev) = std::fs::metadata(work).map(|m| m.dev()) else {
        return;
    };
    let Some(held) = mapped(work_dev) else {
        return;
    };
    for k in 0..SHADOW_SLOTS {
        let ino = s.ino[k];
        if ino != 0 && !held.contains(&ino) && free(s, k).is_err() {
            return;
        }
    }
}
