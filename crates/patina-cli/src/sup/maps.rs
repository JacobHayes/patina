//! Shared mappings of processes that end without their runtime: a `SIGKILL` (`kill_now`), the
//! end of the run (`finish`) and a crash point (`Op::CrashPoint`); and of every process at a
//! `sync` or `syncfs` (`Op::MapsSync`).
//!
//! The runtime logs the stores made through a process's `MAP_SHARED` mappings of work-tree
//! files when the process unmaps, syncs or exits (`rt::oplog`, `MmapDirty`). A process that
//! ends otherwise leaves its stores in the page cache, as on Linux, where a later `fsync` by
//! another process makes them durable; so they reach the log at the point it ends, here,
//! from the table of tracked mappings the runtime keeps (`proto::oplog::SharedMaps`): each
//! mapped page of the file is compared with its window in the shadow store (`shadows`), what
//! the log holds of it, and a page that differs is logged with the file's bytes (which keeps
//! the window, `crash::append`).
//!
//! Determinism: the supervisor holds the turn, so no guest code runs (the one exception, a
//! stall with guest code holding the turn, skips that process): the table, the windows and
//! the files do not change while they are read, and the records land at this point of the
//! global order, with the current sequence number, the same in every run.
//!
//! Trust: the table is the target's memory, which a stray store of the program could change.
//! It only chooses what is compared. Each entry's file is the target's own open file
//! (`pidfd_getfd` of its descriptor: no reopen, so no permission check, no open of a device or
//! a FIFO), and must be a regular file of the work tree with the entry's inode; what is read is
//! bounded by the file's size; the bytes logged are the file's, read
//! through a description the program itself opened. A damaged table can add or omit records
//! of the target's own work files, with their true contents, and nothing else.

use proto::ctl::Ctl;
use proto::layout::{PAGE, RT_BASE, RT_REGION_END};
use proto::oplog::{OpKind, SharedMap, SharedMaps, MAX_SHARED_MAPS, SHARED_MAPS_SIZE};
use std::sync::atomic::Ordering::Relaxed;

/// Pages compared per read, and at most per record: a long run is logged as several
/// records, so what the supervisor holds in memory is bounded.
const CHUNK: u64 = 64 * PAGE;

/// One pass over processes that end together (a page logged for one mapping is in its window
/// for the next).
pub struct Pass<'a> {
    ctl: &'a Ctl,
    work_dev: Result<u64, String>,
    seq: u64,
}

/// Read `buf.len()` bytes of process `pid` at `addr`.
fn read_mem(pid: i32, addr: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut _,
        iov_len: buf.len(),
    };
    let r = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if r as usize != buf.len() {
        return Err(std::io::Error::from_raw_os_error(libc::EFAULT));
    }
    Ok(())
}

fn page_up(x: u64) -> u64 {
    x.saturating_add(PAGE - 1) & !(PAGE - 1)
}

/// The data runs of `[off, off + end)` of `fd`, as page-aligned offsets from `off`.
fn data_runs(fd: i32, off: u64, end: u64) -> Vec<(u64, u64)> {
    let mut out = vec![];
    let mut pos = 0;
    while pos < end {
        let d = unsafe { libc::lseek(fd, (off + pos) as i64, libc::SEEK_DATA) };
        if d < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENXIO) {
                // No hole information: every page may hold data.
                out.push((pos, end));
            }
            break;
        }
        let h = unsafe { libc::lseek(fd, d, libc::SEEK_HOLE) };
        let dl = (d as u64 - off) & !(PAGE - 1);
        if dl >= end {
            break;
        }
        let hl = if h < 0 {
            end
        } else {
            page_up(h as u64 - off).min(end)
        };
        out.push((dl.max(pos), hl));
        pos = hl.max(pos + PAGE);
    }
    out
}

impl<'a> Pass<'a> {
    /// A pass whose records carry sequence number `seq` (the point of the order they land at).
    pub fn new(ctl: &'a Ctl, work: &std::path::Path, seq: u64) -> Pass<'a> {
        use std::os::unix::fs::MetadataExt;
        Pass {
            ctl,
            work_dev: std::fs::metadata(work)
                .map(|m| m.dev())
                .map_err(|e| format!("{}: {e}", work.display())),
            seq,
        }
    }

    /// Log what process `pid`'s tracked mappings hold that the log does not. A process that
    /// is gone, or never started an image, has nothing to log; a table that cannot be read
    /// otherwise (the host refuses `process_vm_readv`) is an error, as is a failed write to
    /// the log.
    pub fn process(&mut self, pid: i32) -> Result<(), String> {
        let addr = self.ctl.maps_table.load(Relaxed);
        if addr < RT_BASE || addr.saturating_add(SHARED_MAPS_SIZE as u64) > RT_REGION_END {
            return Ok(());
        }
        let work_dev = self.work_dev.clone()?;
        let mut t: SharedMaps = unsafe { std::mem::zeroed() };
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(&mut t as *mut SharedMaps as *mut u8, SHARED_MAPS_SIZE)
        };
        if let Err(e) = read_mem(pid, addr, bytes) {
            if e.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(format!(
                "reading the shared mappings of guest process {pid} (process_vm_readv): {e}"
            ));
        }
        let n = t.n.min(MAX_SHARED_MAPS);
        if n == 0 {
            return Ok(());
        }
        let pidfd = match crate::sys::pidfd_open(pid) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
            Err(e) => return Err(format!("pidfd_open of guest process {pid}: {e}")),
        };
        let r = t.m[..n]
            .iter()
            .try_for_each(|m| self.mapping(pid, pidfd, work_dev, m));
        unsafe { libc::close(pidfd) };
        r
    }

    fn mapping(
        &mut self,
        pid: i32,
        pidfd: i32,
        work_dev: u64,
        m: &SharedMap,
    ) -> Result<(), String> {
        if m.len == 0 || !(0..=i32::MAX as i64).contains(&m.fd) || m.off & (PAGE - 1) != 0 {
            return Ok(());
        }
        // The target's own open file description (its descriptor `m.fd`, which the runtime
        // keeps for the mapping): nothing is opened.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, m.fd as i32, 0) };
        if fd < 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                // Gone, or no such descriptor (a damaged entry): nothing to log.
                Some(libc::ESRCH) | Some(libc::EBADF) => Ok(()),
                _ => Err(format!(
                    "pidfd_getfd of guest process {pid}: {}",
                    std::io::Error::last_os_error()
                )),
            };
        }
        let fd = fd as i32;
        let r = self.file(pid, fd, work_dev, m);
        unsafe { libc::close(fd) };
        r
    }

    fn file(&mut self, pid: i32, fd: i32, work_dev: u64, m: &SharedMap) -> Result<(), String> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0
            || st.st_mode & libc::S_IFMT != libc::S_IFREG
            || st.st_dev != work_dev
            || st.st_ino != m.ino
        {
            return Ok(());
        }
        // A tracked mapping's inode has a slot (slots are freed only when nothing maps the
        // inode); only a damaged entry has none.
        let Some(k) = super::shadows::slot_of(self.ctl, m.ino) else {
            return Ok(());
        };
        let end = m.off.saturating_add(m.len).min(st.st_size as u64);
        if m.off >= end {
            return Ok(());
        }
        // A run of differing pages not yet logged: its file offset and bytes.
        let mut run: Option<(u64, Vec<u8>)> = None;
        let mut fbuf = vec![0u8; CHUNK as usize];
        let mut sbuf = vec![0u8; CHUNK as usize];
        for (lo, hi) in data_runs(fd, m.off, page_up(end - m.off)) {
            let hi = hi.min(end - m.off);
            let mut p = lo;
            while p < hi {
                let n = CHUNK.min(hi - p);
                let (f, s) = (&mut fbuf[..n as usize], &mut sbuf[..n as usize]);
                let got = unsafe {
                    libc::pread(fd, f.as_mut_ptr() as *mut _, f.len(), (m.off + p) as i64)
                };
                if got != n as isize {
                    break; // the file is shorter than its size said: nothing more in this run
                }
                super::shadows::read(k, m.off + p, s)?;
                let mut q = 0;
                while q < n {
                    let k = PAGE.min(n - q) as usize;
                    let at = m.off + p + q;
                    let r = q as usize..q as usize + k;
                    if f[r.clone()] != s[r.clone()] {
                        match &mut run {
                            Some((start, b))
                                if *start + b.len() as u64 == at && (b.len() as u64) < CHUNK =>
                            {
                                b.extend_from_slice(&f[r])
                            }
                            _ => {
                                self.emit(pid, m.ino, run.take())?;
                                run = Some((at, f[r].to_vec()));
                            }
                        }
                    } else {
                        self.emit(pid, m.ino, run.take())?;
                    }
                    q += k as u64;
                }
                p += n;
            }
        }
        self.emit(pid, m.ino, run.take())
    }

    fn emit(&self, pid: i32, ino: u64, run: Option<(u64, Vec<u8>)>) -> Result<(), String> {
        let Some((off, b)) = run else { return Ok(()) };
        super::crash::append(
            self.ctl,
            OpKind::MmapDirty,
            ino,
            [off, b.len() as u64, 0, 0, 0, 0],
            &b,
            self.seq,
            pid as u32,
        )
    }
}
