//! System V shared memory in the supervisor: one table for the run, as the kernel's IPC
//! namespace. Each segment's memory is a memfd the supervisor holds; a runtime attaching it
//! opens `/proc/1/fd/N` (the supervisor is PID 1) and maps that. Ids are made as a fresh IPC
//! namespace makes them (`ipc_idr_alloc`: the index cycles through the free ones, the sequence
//! number, times 32768, grows when it wraps), so they are functions of the calls made; times
//! are virtual.
//!
//! The kernel's lifetime rules: `IPC_RMID` marks a segment (its key becomes private, mode gets
//! `SHM_DEST`) and it goes at its last detach; `fork` copies a process's attachments, `execve`
//! and exit detach them. A segment outlives the processes that made it: a process crash
//! (`--faults kill`) keeps the table and the memory for the next boot (written to
//! `FD_SHM` at the end of the boot), a machine crash starts with none.

use proto::ctl::*;
use std::collections::BTreeMap;

const SEQ_MULT: i64 = 32768;
const SHM_DEST: u32 = 0o1000;
const ENOENT: i64 = 2;
const EINVAL: i64 = 22;
const EEXIST: i64 = 17;
const ENOMEM: i64 = 12;
const ENOSPC: i64 = 28;
/// The kernel's defaults for a fresh IPC namespace.
const SHMMNI: usize = 4096;
const SHMMAX: u64 = u64::MAX - (1 << 24);

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Meta {
    key: i32,
    size: u64,
    /// Permission bits and `SHM_DEST`.
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    cpid: i32,
    lpid: i32,
    /// Virtual monotonic ns (0: never).
    atime: u64,
    dtime: u64,
    ctime: u64,
    nattch: u64,
}

struct Seg {
    meta: Meta,
    /// The supervisor's memfd holding the memory.
    fd: i32,
}

pub struct Shm {
    segs: BTreeMap<i64, Seg>,
    /// Attachments per process: segment id → count.
    att: BTreeMap<i32, BTreeMap<i64, u64>>,
    seq: i64,
    /// The last index given (-1: none yet).
    last: i64,
}

impl Default for Shm {
    fn default() -> Shm {
        Shm {
            segs: BTreeMap::new(),
            att: BTreeMap::new(),
            seq: 0,
            last: -1,
        }
    }
}

fn memfd(size: u64) -> Option<i32> {
    let fd = unsafe { libc::memfd_create(c"patina-shm".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    if unsafe { libc::ftruncate(fd, size as i64) } != 0 {
        unsafe { libc::close(fd) };
        return None;
    }
    Some(fd)
}

impl Shm {
    /// The next index, as `idr_alloc_cyclic` gives it below `max(in use * 3/2, 64)`.
    fn next_index(&mut self) -> Option<i64> {
        let max = (self.segs.len() as i64 * 3 / 2).max(64).min(SHMMNI as i64);
        let used = |i: i64| self.segs.keys().any(|id| id % SEQ_MULT == i);
        let start = if self.last + 1 >= max {
            0
        } else {
            self.last + 1
        };
        let idx = (start..max).chain(0..start).find(|&i| !used(i))?;
        if idx <= self.last {
            self.seq = (self.seq + 1) % (i32::MAX as i64 / SEQ_MULT);
        }
        self.last = idx;
        Some(idx)
    }

    /// `shmget(key, size, flags)` from process `pid` running as `uid`/`gid`.
    pub fn get(
        &mut self,
        pid: i32,
        key: i32,
        size: u64,
        flags: u64,
        ids: (u32, u32),
        now: u64,
    ) -> i64 {
        const IPC_CREAT: u64 = 0o1000;
        const IPC_EXCL: u64 = 0o2000;
        if key != 0 {
            if let Some((&id, s)) = self.segs.iter().find(|(_, s)| s.meta.key == key) {
                if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                    return -EEXIST;
                }
                if size > s.meta.size {
                    return -EINVAL;
                }
                return id;
            }
            if flags & IPC_CREAT == 0 {
                return -ENOENT;
            }
        }
        if size == 0 || size > SHMMAX {
            return -EINVAL;
        }
        let Some(fd) = memfd(size) else {
            return -ENOMEM;
        };
        let Some(idx) = self.next_index() else {
            unsafe { libc::close(fd) };
            return -ENOSPC;
        };
        let id = self.seq * SEQ_MULT + idx;
        let (uid, gid) = ids;
        self.segs.insert(
            id,
            Seg {
                meta: Meta {
                    key,
                    size,
                    mode: (flags & 0o777) as u32,
                    uid,
                    gid,
                    cuid: uid,
                    cgid: gid,
                    cpid: pid,
                    ctime: now,
                    ..Meta::default()
                },
                fd,
            },
        );
        id
    }

    /// `shmat`: the segment's size and the supervisor's descriptor of its memory; the
    /// attachment counts from now (`detach` undoes it if the mapping fails).
    pub fn attach(&mut self, pid: i32, id: i64, now: u64) -> Result<(u64, i32), i64> {
        let s = self.segs.get_mut(&id).ok_or(-EINVAL)?;
        s.meta.nattch += 1;
        s.meta.atime = now;
        s.meta.lpid = pid;
        *self.att.entry(pid).or_default().entry(id).or_default() += 1;
        Ok((s.meta.size, s.fd))
    }

    /// `shmdt` (or the end of an attachment at exit or exec).
    pub fn detach(&mut self, pid: i32, id: i64, now: u64) -> i64 {
        let Some(n) = self.att.get_mut(&pid).and_then(|m| m.get_mut(&id)) else {
            return -EINVAL;
        };
        *n -= 1;
        if *n == 0 {
            self.att.get_mut(&pid).unwrap().remove(&id);
        }
        if let Some(s) = self.segs.get_mut(&id) {
            s.meta.nattch -= 1;
            s.meta.dtime = now;
            s.meta.lpid = pid;
        }
        self.reap(id);
        0
    }

    fn reap(&mut self, id: i64) {
        if let Some(s) = self.segs.get(&id) {
            if s.meta.mode & SHM_DEST != 0 && s.meta.nattch == 0 {
                unsafe { libc::close(s.fd) };
                self.segs.remove(&id);
            }
        }
    }

    /// Every attachment of `pid` ends (exit, `execve`).
    pub fn gone(&mut self, pid: i32, now: u64) {
        let Some(m) = self.att.remove(&pid) else {
            return;
        };
        for (id, n) in m {
            if let Some(s) = self.segs.get_mut(&id) {
                s.meta.nattch -= n;
                s.meta.dtime = now;
                s.meta.lpid = pid;
            }
            self.reap(id);
        }
    }

    /// `fork`: the child has the parent's attachments.
    pub fn forked(&mut self, parent: i32, child: i32) {
        let Some(m) = self.att.get(&parent).cloned() else {
            return;
        };
        for (&id, &n) in &m {
            if let Some(s) = self.segs.get_mut(&id) {
                s.meta.nattch += n;
            }
        }
        self.att.insert(child, m);
    }

    /// `shmctl`: `IPC_RMID`, `IPC_SET` [uid, gid, mode], `IPC_STAT` (the words written to
    /// `out`: see `stat_words`).
    pub fn ctl(&mut self, id: i64, cmd: u64, a: [u64; 3], now: u64, out: &mut [u64; 16]) -> i64 {
        let Some(s) = self.segs.get_mut(&id) else {
            return -EINVAL;
        };
        match cmd {
            SHMCTL_RMID => {
                s.meta.mode |= SHM_DEST;
                s.meta.key = 0;
                self.reap(id);
                0
            }
            SHMCTL_SET => {
                s.meta.uid = a[0] as u32;
                s.meta.gid = a[1] as u32;
                s.meta.mode = (s.meta.mode & !0o777) | (a[2] as u32 & 0o777);
                s.meta.ctime = now;
                0
            }
            SHMCTL_STAT => {
                *out = stat_words(&s.meta, id);
                0
            }
            _ => -EINVAL,
        }
    }

    /// The table for the next boot after a process crash: nothing is attached any
    /// more (every process died at once), so marked segments are gone and the others were
    /// detached now.
    pub fn save(&self, now: u64) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&(self.seq as u64).to_le_bytes());
        b.extend_from_slice(&(self.last as u64).to_le_bytes());
        let kept = self
            .segs
            .iter()
            .filter(|(_, s)| s.meta.mode & SHM_DEST == 0);
        b.extend_from_slice(&(kept.clone().count() as u64).to_le_bytes());
        for (&id, s) in kept {
            let mut m = s.meta;
            if m.nattch > 0 {
                m.dtime = now;
            }
            for v in [
                id as u64,
                m.key as u32 as u64,
                m.size,
                m.mode as u64,
                m.uid as u64 | (m.gid as u64) << 32,
                m.cuid as u64 | (m.cgid as u64) << 32,
                m.cpid as u32 as u64 | (m.lpid as u32 as u64) << 32,
                m.atime,
                m.dtime,
                m.ctime,
            ] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            let mut data = vec![0u8; m.size as usize];
            let mut done = 0;
            while done < data.len() {
                let r = unsafe {
                    libc::pread(
                        s.fd,
                        data[done..].as_mut_ptr() as *mut _,
                        data.len() - done,
                        done as i64,
                    )
                };
                if r <= 0 {
                    break;
                }
                done += r as usize;
            }
            b.extend_from_slice(&data);
        }
        b
    }

    /// The table `save` wrote (an empty buffer: none).
    pub fn restore(b: &[u8]) -> Result<Shm, String> {
        let mut sh = Shm::default();
        if b.is_empty() {
            return Ok(sh);
        }
        let mut at = 0usize;
        fn take<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], String> {
            let w = b
                .get(*at..*at + n)
                .ok_or("shared memory state is cut short")?;
            *at += n;
            Ok(w)
        }
        let word = |at: &mut usize| -> Result<u64, String> {
            Ok(u64::from_le_bytes(take(b, at, 8)?.try_into().unwrap()))
        };
        sh.seq = word(&mut at)? as i64;
        sh.last = word(&mut at)? as i64;
        let n = word(&mut at)?;
        for _ in 0..n {
            let w: Vec<u64> = (0..10).map(|_| word(&mut at)).collect::<Result<_, _>>()?;
            let meta = Meta {
                key: w[1] as u32 as i32,
                size: w[2],
                mode: w[3] as u32,
                uid: w[4] as u32,
                gid: (w[4] >> 32) as u32,
                cuid: w[5] as u32,
                cgid: (w[5] >> 32) as u32,
                cpid: w[6] as u32 as i32,
                lpid: (w[6] >> 32) as u32 as i32,
                atime: w[7],
                dtime: w[8],
                ctime: w[9],
                nattch: 0,
            };
            let id = w[0] as i64;
            let data = take(b, &mut at, meta.size as usize)?;
            let fd = memfd(meta.size).ok_or("memfd for shared memory")?;
            let mut done = 0;
            while done < data.len() {
                let r = unsafe {
                    libc::pwrite(
                        fd,
                        data[done..].as_ptr() as *const _,
                        data.len() - done,
                        done as i64,
                    )
                };
                if r <= 0 {
                    return Err("writing shared memory state".into());
                }
                done += r as usize;
            }
            sh.segs.insert(id, Seg { meta, fd });
        }
        Ok(sh)
    }
}

/// `IPC_STAT` as words for the runtime: [key, uid, gid, cuid, cgid, mode, seq, size, atime,
/// dtime, ctime (virtual ns), cpid, lpid, nattch].
fn stat_words(m: &Meta, id: i64) -> [u64; 16] {
    let mut w = [0u64; 16];
    w[0] = m.key as u32 as u64;
    w[1] = m.uid as u64;
    w[2] = m.gid as u64;
    w[3] = m.cuid as u64;
    w[4] = m.cgid as u64;
    w[5] = m.mode as u64;
    w[6] = (id / SEQ_MULT) as u64;
    w[7] = m.size;
    w[8] = m.atime;
    w[9] = m.dtime;
    w[10] = m.ctime;
    w[11] = m.cpid as u32 as u64;
    w[12] = m.lpid as u32 as u64;
    w[13] = m.nattch;
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_keys_and_removal() {
        let mut s = Shm::default();
        let a = s.get(10, 0, 100, 0o600, (1000, 1000), 5);
        let b = s.get(10, 7, 100, 0o1600, (1000, 1000), 5);
        assert_eq!((a, b), (0, 1));
        assert_eq!(s.get(11, 7, 50, 0, (1000, 1000), 5), b);
        assert_eq!(s.get(11, 7, 200, 0, (1000, 1000), 5), -EINVAL);
        assert_eq!(s.get(11, 7, 50, 0o3000, (1000, 1000), 5), -EEXIST);
        assert_eq!(s.get(11, 8, 50, 0, (1000, 1000), 5), -ENOENT);
        s.attach(10, b, 6).unwrap();
        s.forked(10, 12);
        let mut out = [0; 16];
        s.ctl(b, SHMCTL_STAT, [0; 3], 6, &mut out);
        assert_eq!(out[13], 2);
        assert_eq!(s.ctl(b, SHMCTL_RMID, [0; 3], 7, &mut out), 0);
        // Marked: its key is private now, the segment stays while attached.
        assert_eq!(s.get(11, 7, 50, 0, (1000, 1000), 8), -ENOENT);
        s.gone(10, 9);
        assert!(s.segs.contains_key(&b));
        assert_eq!(s.detach(12, b, 10), 0);
        assert!(!s.segs.contains_key(&b));
        // Indexes cycle: the next is 2, not the freed 1.
        assert_eq!(s.get(10, 0, 1, 0, (1000, 1000), 11), 2);
    }

    #[test]
    fn indexes_wrap_with_the_next_sequence() {
        let mut s = Shm::default();
        let mut out = [0; 16];
        for i in 0..64 {
            let id = s.get(10, 0, 1, 0, (1000, 1000), 1);
            assert_eq!(id, i);
            s.ctl(id, SHMCTL_RMID, [0; 3], 1, &mut out);
        }
        assert_eq!(s.get(10, 0, 1, 0, (1000, 1000), 1), SEQ_MULT);
    }

    #[test]
    fn save_and_restore() {
        let mut s = Shm::default();
        let a = s.get(10, 42, 10, 0o1600, (1000, 1000), 5);
        let gone = s.get(10, 43, 10, 0o1600, (1000, 1000), 5);
        s.attach(10, a, 6).unwrap();
        s.attach(10, gone, 6).unwrap();
        let mut out = [0; 16];
        s.ctl(gone, SHMCTL_RMID, [0; 3], 7, &mut out);
        let fd = s.segs[&a].fd;
        unsafe { libc::pwrite(fd, b"hello".as_ptr() as *const _, 5, 0) };
        let b = s.save(8);
        let r = Shm::restore(&b).unwrap();
        assert_eq!(r.segs.len(), 1);
        assert_eq!(r.segs[&a].meta.nattch, 0);
        assert_eq!(r.segs[&a].meta.key, 42);
        let mut got = [0u8; 5];
        unsafe { libc::pread(r.segs[&a].fd, got.as_mut_ptr() as *mut _, 5, 0) };
        assert_eq!(&got, b"hello");
        assert_eq!((r.seq, r.last), (s.seq, s.last));
    }
}
