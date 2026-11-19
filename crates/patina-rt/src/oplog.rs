//! The durability tracker's runtime half: one operation
//! record per successful mutating call on `/work`, appended after the kernel call returned
//! while holding the turn, plus the sync-class calls, `close`, shared file mappings and the
//! failed-fsync error generations. The records go to descriptor 3002 (fixed size) and their
//! bytes to 3003, at the offsets kept in the control region, by `pwrite` (so no descriptor
//! offset is shared between processes).
//!
//! After every record a crash point is offered (`inject::crash_point`).

use crate::path::{self, Global};
use crate::raw::*;
use crate::state::{ctl, thread};
use crate::sys::fs::{fstat_raw, Attr, Data, FsOp};
use core::sync::atomic::Ordering::Relaxed;
use proto::layout::*;
use proto::oplog::*;

fn dur() -> &'static mut Dur {
    unsafe { Dur::at(crate::state::ctl_base()) }
}

fn pwrite_all(fd: i32, mut off: u64, s: &[u8]) {
    let mut done = 0usize;
    while done < s.len() {
        let r = unsafe {
            sc4(
                nr::PWRITE64,
                fd as u64,
                s.as_ptr() as u64 + done as u64,
                (s.len() - done) as u64,
                off,
            )
        };
        if r <= 0 {
            crate::sup::log_write_failed(r, nr::PWRITE64);
        }
        done += r as usize;
        off += r as u64;
    }
}

/// Where a record's bytes come from.
enum Src<'a> {
    Bytes(&'a [u8]),
    /// A guest iovec array (pointer, count), `len` bytes in total.
    Iov(u64, u64),
    /// Read back from a descriptor at an offset (copy_file_range, sendfile, splice targets).
    File(i64, u64),
}

/// `fd` if it is open for reading, else a new read-only descriptor of the same file.
fn readable(fd: i64) -> i64 {
    const O_ACCMODE: i64 = 3;
    const O_WRONLY: i64 = 1;
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, 3) }; // fcntl F_GETFL
    if fl >= 0 && fl & O_ACCMODE != O_WRONLY {
        return fd;
    }
    let mut p = *b"/proc/self/fd/0000000000\0";
    let mut n = fd as u64;
    let mut i = 23;
    loop {
        p[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
        i -= 1;
    }
    // Shift the digits to follow the prefix.
    let digits = 24 - i;
    p.copy_within(i..24, 14);
    p[14 + digits] = 0;
    let r = unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            p.as_ptr() as u64,
            0o2000000,
            0,
        )
    }; // O_RDONLY|O_CLOEXEC
    if r < 0 {
        crate::sup::host_error(r, nr::OPENAT, proto::ctl::HE_RUNTIME_ASSERT);
    }
    r
}

/// Append data pieces to `oplog.data`; returns (offset, length).
fn put_data(pieces: &[Src], len_hint: u64) -> (u64, u64) {
    let c = ctl();
    let start = c.opdata_len.load(Relaxed);
    let mut off = start;
    for p in pieces {
        match *p {
            Src::Bytes(b) => {
                pwrite_all(FD_OPLOG_DATA, off, b);
                off += b.len() as u64;
            }
            Src::Iov(iov, cnt) => {
                let mut left = len_hint;
                for i in 0..cnt.min(1024) {
                    if left == 0 {
                        break;
                    }
                    let [base, l] = unsafe { *((iov + i * 16) as *const [u64; 2]) };
                    let n = l.min(left);
                    let s = unsafe { core::slice::from_raw_parts(base as *const u8, n as usize) };
                    pwrite_all(FD_OPLOG_DATA, off, s);
                    off += n;
                    left -= n;
                }
            }
            Src::File(fd, foff) => {
                // The target of copy_file_range/sendfile is often write-only: read it back
                // through a read-only descriptor of the same file (via /proc/self/fd).
                let rfd = readable(fd);
                let mut buf = [0u8; 16384];
                let mut left = len_hint;
                let mut at = foff;
                while left > 0 {
                    let n = left.min(buf.len() as u64);
                    let r = unsafe { sc4(nr::PREAD64, rfd as u64, buf.as_mut_ptr() as u64, n, at) };
                    if r <= 0 {
                        // The file is shorter than the call said: record zeros (cannot happen on tmpfs).
                        crate::sup::host_error(r, nr::PREAD64, proto::ctl::HE_RUNTIME_ASSERT);
                    }
                    pwrite_all(FD_OPLOG_DATA, off, &buf[..r as usize]);
                    off += r as u64;
                    at += r as u64;
                    left -= r as u64;
                }
                if rfd != fd {
                    unsafe { sc1(nr::CLOSE, rfd as u64) };
                }
            }
        }
    }
    c.opdata_len.store(off, Relaxed);
    (start, off - start)
}

fn put_rec(kind: OpKind, ino: u64, a: [u64; 6], data: (u64, u64)) {
    let c = ctl();
    let ts = thread();
    let rec = OpRec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        kind: kind as u32,
        pid: ts.pid as u32,
        ino,
        a,
        data_off: data.0,
        data_len: data.1,
    };
    let off = c.oplog_len.load(Relaxed);
    pwrite_all(FD_OPLOG_META, off, rec.as_bytes());
    c.oplog_len.store(off + OPREC_SIZE as u64, Relaxed);
}

/// Append one record and offer a crash point after it.
fn append(kind: OpKind, ino: u64, a: [u64; 6], pieces: &[Src], len_hint: u64) {
    let data = if pieces.is_empty() {
        (ctl().opdata_len.load(Relaxed), 0)
    } else {
        put_data(pieces, len_hint)
    };
    put_rec(kind, ino, a, data);
    crate::inject::crash_point();
}

/// The `Crash` record that ends the log of a crashed incarnation (no crash point after it).
pub fn append_crash(kind: u64) {
    let d = (ctl().opdata_len.load(Relaxed), 0);
    put_rec(OpKind::Crash, 0, [kind, 0, 0, 0, 0, 0], d);
}

/// The tracker's input: called by `sys::fs::after_mutation` for each successful mutating
/// call on `/work`.
pub fn record(op: &FsOp) {
    match *op {
        FsOp::Create {
            parent,
            name,
            ino,
            mode,
            kind,
        } => append(
            OpKind::Create,
            ino,
            [parent, mode as u64, kind as u64, 0, 0, 0],
            &[Src::Bytes(name)],
            0,
        ),
        FsOp::Mkdir {
            parent,
            name,
            ino,
            mode,
        } => append(
            OpKind::Mkdir,
            ino,
            [parent, mode as u64, 0, 0, 0, 0],
            &[Src::Bytes(name)],
            0,
        ),
        FsOp::Symlink {
            parent,
            name,
            ino,
            target,
        } => append(
            OpKind::Symlink,
            ino,
            [parent, name.len() as u64, 0, 0, 0, 0],
            &[Src::Bytes(name), Src::Bytes(target)],
            0,
        ),
        FsOp::Link { parent, name, ino } => append(
            OpKind::Link,
            ino,
            [parent, 0, 0, 0, 0, 0],
            &[Src::Bytes(name)],
            0,
        ),
        FsOp::Unlink {
            parent,
            name,
            ino,
            nlink_left,
        } => append(
            OpKind::Unlink,
            ino,
            [parent, nlink_left, 0, 0, 0, 0],
            &[Src::Bytes(name)],
            0,
        ),
        FsOp::Rmdir {
            parent,
            name,
            ino,
            nlink_left,
        } => append(
            OpKind::Rmdir,
            ino,
            [parent, nlink_left, 0, 0, 0, 0],
            &[Src::Bytes(name)],
            0,
        ),
        FsOp::Rename {
            old_parent,
            old_name,
            new_parent,
            new_name,
            ino,
            replaced,
            flags,
        } => append(
            OpKind::Rename,
            ino,
            [
                old_parent,
                new_parent,
                replaced,
                flags,
                old_name.len() as u64,
                0,
            ],
            &[Src::Bytes(old_name), Src::Bytes(new_name)],
            0,
        ),
        FsOp::Write {
            ino,
            offset,
            len,
            data,
        } => {
            let src = match data {
                Data::Buf(p) => {
                    Src::Bytes(unsafe { core::slice::from_raw_parts(p as *const u8, len as usize) })
                }
                Data::Iov(iov, cnt) => Src::Iov(iov, cnt),
                Data::InFile(fd) => Src::File(fd, offset),
            };
            let f = &ctl().faults;
            f.work_bytes
                .store(f.work_bytes.load(Relaxed) + len, Relaxed);
            append(OpKind::Write, ino, [offset, len, 0, 0, 0, 0], &[src], len);
            maps_changed(ino, offset, len, Change::Data);
        }
        FsOp::Truncate { ino, size } => {
            append(OpKind::Truncate, ino, [size, 0, 0, 0, 0, 0], &[], 0);
            maps_changed(ino, size, u64::MAX, Change::Zero);
        }
        FsOp::Fallocate {
            ino,
            mode,
            offset,
            len,
        } => {
            append(OpKind::Fallocate, ino, [mode, offset, len, 0, 0, 0], &[], 0);
            if mode & 2 != 0 {
                maps_changed(ino, offset, len, Change::Zero);
            }
        }
        FsOp::SetAttr { ino, what } => match what {
            Attr::Meta { mode, uid, gid } => append(
                OpKind::SetAttr,
                ino,
                [mode as u64, uid as u64, gid as u64, 1, 0, 0],
                &[],
                0,
            ),
            Attr::XattrSet { name, value } => append(
                OpKind::XattrSet,
                ino,
                [name.len() as u64, 0, 0, 0, 0, 0],
                &[Src::Bytes(name), Src::Bytes(value)],
                0,
            ),
            Attr::XattrRemove { name } => {
                append(OpKind::XattrRemove, ino, [0; 6], &[Src::Bytes(name)], 0)
            }
            // Times live in the virtual time table; they are neither compared nor modelled.
            Attr::Times => {}
        },
        FsOp::MmapDirty {
            ino,
            offset,
            len,
            data,
        } => {
            let s = unsafe { core::slice::from_raw_parts(data as *const u8, len as usize) };
            append(
                OpKind::MmapDirty,
                ino,
                [offset, len, 0, 0, 0, 0],
                &[Src::Bytes(s)],
                0,
            );
        }
        FsOp::Fsync { ino, data_only } => append(
            OpKind::Fsync,
            ino,
            [data_only as u64 * FSYNC_DATA_ONLY, 0, 0, 0, 0, 0],
            &[],
            0,
        ),
        FsOp::FsyncDir { ino } => append(OpKind::FsyncDir, ino, [0; 6], &[], 0),
        FsOp::FsyncFail { ino } => append(OpKind::FsyncFail, ino, [0; 6], &[], 0),
        FsOp::Sync => append(OpKind::Sync, 0, [0; 6], &[], 0),
        FsOp::Close { ino, .. } => append(OpKind::Close, ino, [0; 6], &[], 0),
    }
}

// ---- per-process descriptor state: the writeback error generation each descriptor has seen ----

struct Fds {
    seen: [u32; FD_HIDDEN_MIN as usize],
    sync_seen: u64,
}

static FDS: Global<Fds> = Global::new(Fds {
    seen: [0; FD_HIDDEN_MIN as usize],
    sync_seen: 0,
});

fn seen(fd: i64) -> Option<&'static mut u32> {
    (0..FD_HIDDEN_MIN as i64)
        .contains(&fd)
        .then(|| &mut FDS.get().seen[fd as usize])
}

/// A `/work` file was opened at `fd`: it sees only errors that happen from now on
/// (Linux samples the mapping's error sequence at open).
pub fn opened(fd: i64, ino: u64) {
    if crate::state::in_vfork_child() {
        return; // the table is the parent's; the child's image after execve starts fresh
    }
    if let Some(s) = seen(fd) {
        *s = dur().gen(ino) as u32;
    }
}

/// `dup` family: the duplicate starts with what its source has seen (each reports once:
/// the documented deviation from per-description reporting).
pub fn dup_fd(src: i64, dst: i64) {
    if crate::state::in_vfork_child() {
        return;
    }
    let v = seen(src).map(|s| *s).unwrap_or(0);
    if let Some(d) = seen(dst) {
        *d = v;
    }
}

// ---- shared file mappings ----

const MAX_MAPS: usize = 128;

#[derive(Clone, Copy)]
struct Map {
    addr: u64,
    len: u64,
    ino: u64,
    off: u64,
    /// Runtime copy of what the tracker has recorded for the mapped range.
    shadow: u64,
    shadow_len: u64,
    /// Hidden duplicate of the descriptor (for the current file size).
    fd: i64,
}

struct Maps {
    m: [Map; MAX_MAPS],
    n: usize,
}

const NOMAP: Map = Map {
    addr: 0,
    len: 0,
    ino: 0,
    off: 0,
    shadow: 0,
    shadow_len: 0,
    fd: -1,
};
static MAPS: Global<Maps> = Global::new(Maps {
    m: [NOMAP; MAX_MAPS],
    n: 0,
});

fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

fn file_size(fd: i64) -> u64 {
    fstat_raw(fd).map(|st| st.size()).unwrap_or(0)
}

/// Address space of shadows given back, by address, adjacent ranges joined: a new shadow
/// takes the first that fits before taking fresh address space. A range that finds the list
/// full is given up (its memory is unmapped all the same).
struct FreeShadows {
    r: [(u64, u64); MAX_FREE],
    n: usize,
}
const MAX_FREE: usize = 64;
static FREE: Global<FreeShadows> = Global::new(FreeShadows {
    r: [(0, 0); MAX_FREE],
    n: 0,
});

/// A mapping's shadow: private anonymous memory that holds pages only where something was
/// copied in (a sparse file mapped large costs what it holds, not what it spans).
fn new_shadow(len: u64) -> u64 {
    let l = page_up(len);
    let f = FREE.get();
    let a = match (0..f.n).find(|&i| f.r[i].1 >= l) {
        Some(i) => {
            let a = f.r[i].0;
            f.r[i] = (a + l, f.r[i].1 - l);
            if f.r[i].1 == 0 {
                f.r.copy_within(i + 1..f.n, i);
                f.n -= 1;
            }
            a
        }
        None => crate::state::priv_alloc(l, PAGE),
    };
    let r = unsafe {
        sc6(
            nr::MMAP,
            a,
            l,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
            u64::MAX,
            0,
        )
    };
    if r as u64 != a {
        crate::sup::host_error(r, nr::MMAP, proto::ctl::HE_SYSCALL);
    }
    a
}

/// Give back `[a, a + l)` of a shadow: its memory and its address space.
fn free_shadow(a: u64, l: u64) {
    if l == 0 {
        return;
    }
    unsafe { sc2(nr::MUNMAP, a, l) };
    let f = FREE.get();
    let i = (0..f.n).find(|&i| f.r[i].0 > a).unwrap_or(f.n);
    let joins_prev = i > 0 && f.r[i - 1].0 + f.r[i - 1].1 == a;
    let joins_next = i < f.n && a + l == f.r[i].0;
    match (joins_prev, joins_next) {
        (true, true) => {
            f.r[i - 1].1 += l + f.r[i].1;
            f.r.copy_within(i + 1..f.n, i);
            f.n -= 1;
        }
        (true, false) => f.r[i - 1].1 += l,
        (false, true) => f.r[i] = (a, l + f.r[i].1),
        (false, false) if f.n < MAX_FREE => {
            f.r.copy_within(i..f.n, i + 1);
            f.r[i] = (a, l);
            f.n += 1;
        }
        (false, false) => {}
    }
}

/// Bytes of the mapping that lie inside the file (reading beyond would fault).
fn valid_len(m: &Map) -> u64 {
    m.len.min(file_size(m.fd).saturating_sub(m.off))
}

/// The first `v` bytes of mapping `m` as runs of whole pages, in order: `f(lo, hi, data)`,
/// offsets in the mapping; `data` false for pages that lie wholly in a hole of the file. A
/// hole is never read through the mapping: on tmpfs that would allocate its pages (charged to
/// the file system and the process) and change the file's block count.
fn page_runs(m: &Map, v: u64, mut f: impl FnMut(u64, u64, bool)) {
    const SEEK_CUR: u64 = 1;
    const SEEK_DATA: u64 = 3;
    const SEEK_HOLE: u64 = 4;
    let fd = m.fd as u64;
    // The descriptor shares the program's file offset: put it back.
    let cur = unsafe { sc3(nr::LSEEK, fd, 0, SEEK_CUR) };
    let end = page_up(v);
    let mut pos = 0;
    while pos < end {
        let d = unsafe { sc3(nr::LSEEK, fd, m.off + pos, SEEK_DATA) };
        if d == -e::ENXIO {
            f(pos, end, false);
            break;
        }
        if d < 0 {
            // No hole information: every page may hold data.
            f(pos, end, true);
            break;
        }
        let h = unsafe { sc3(nr::LSEEK, fd, d as u64, SEEK_HOLE) };
        let dl = (d as u64 - m.off) & !(PAGE - 1);
        let hl = if h < 0 {
            end
        } else {
            page_up(h as u64 - m.off).min(end)
        };
        if dl >= end {
            f(pos, end, false);
            break;
        }
        if dl > pos {
            f(pos, dl, false);
        }
        f(dl.max(pos), hl, true);
        pos = hl.max(pos + PAGE);
    }
    if cur >= 0 {
        unsafe { sc3(nr::LSEEK, fd, cur as u64, 0) };
    }
}

/// Bring the shadow of `m` to the file's contents (a new mapping, after `mremap`): copy what
/// the file holds; its holes read as the shadow's untouched zeros.
fn fill_shadow(m: &Map) {
    let v = valid_len(m);
    page_runs(m, v, |lo, hi, data| {
        let hi = hi.min(v);
        if data && hi > lo {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (m.addr + lo) as *const u8,
                    (m.shadow + lo) as *mut u8,
                    (hi - lo) as usize,
                )
            };
        }
    });
}

/// Zero `[a, a + n)` of a shadow: the whole pages are given back (anonymous memory reads
/// back as zeros), only the partial ones at the ends are written.
fn zero_shadow(base: u64, a: u64, n: u64) {
    const MADV_DONTNEED: u64 = 4;
    let (lo, hi) = (page_up(a), (a + n) & !(PAGE - 1));
    if lo >= hi {
        unsafe { core::ptr::write_bytes((base + a) as *mut u8, 0, n as usize) };
        return;
    }
    unsafe {
        core::ptr::write_bytes((base + a) as *mut u8, 0, (lo - a) as usize);
        core::ptr::write_bytes((base + hi) as *mut u8, 0, (a + n - hi) as usize);
        sc3(nr::MADVISE, base + lo, hi - lo, MADV_DONTNEED);
    }
}

const F_DUPFD_CLOEXEC: u64 = 1030;
const HIDDEN_DUP_BASE: u64 = 3100;

/// After a successful `mmap`: track `MAP_SHARED` mappings of `/work` regular files opened
/// for writing (`mprotect` can add `PROT_WRITE` later), and record `MmapShared`.
pub fn on_mmap(addr: u64, len: u64, flags: u64, fd: i64, off: u64) {
    if crate::state::in_vfork_child() {
        return;
    }
    if flags & 0x03 != 0x01 && flags & 0x03 != 0x03 {
        return; // not MAP_SHARED / MAP_SHARED_VALIDATE
    }
    if flags & 0x20 != 0 {
        return; // MAP_ANONYMOUS: the descriptor argument is not read (it may be any number)
    }
    let Some(st) = fstat_raw(fd) else { return };
    if !path::is_work(st.dev()) || st.mode() & 0o170000 != 0o100000 {
        return;
    }
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, 3) }; // F_GETFL
    if fl < 0 || fl & 3 != 2 {
        return; // not O_RDWR: the mapping can never be written
    }
    let t = MAPS.get();
    if t.n == MAX_MAPS {
        crate::sup::capacity(proto::ctl::LIMIT_SHARED_MAPS, MAX_MAPS as u64);
    }
    let hfd = unsafe { sc3(nr::FCNTL, fd as u64, F_DUPFD_CLOEXEC, HIDDEN_DUP_BASE) };
    if hfd < 0 {
        crate::sup::host_error(hfd, nr::FCNTL, proto::ctl::HE_SYSCALL);
    }
    let shadow = new_shadow(len);
    let m = Map {
        addr,
        len,
        ino: st.ino(),
        off,
        shadow,
        shadow_len: page_up(len),
        fd: hfd,
    };
    fill_shadow(&m);
    t.m[t.n] = m;
    t.n += 1;
    append(OpKind::MmapShared, st.ino(), [off, len, 0, 0, 0, 0], &[], 0);
}

/// Record the pages of mapping `i` that differ from the tracker's view (`MmapDirty`), and
/// take them into the view. Only pages that hold data are compared: a hole of the file reads
/// as zeros, as the tracker's view of it does (a truncation or a punched hole zeroed it), so
/// the shadow's pages there are given back.
fn flush(i: usize) {
    let m = MAPS.get().m[i];
    let v = valid_len(&m);
    page_runs(&m, v, |lo, hi, data| {
        if !data {
            return zero_shadow(m.shadow, lo, hi - lo);
        }
        flush_run(i, &m, lo, hi.min(v));
    });
}

/// `flush` over `[lo, v)` of mapping `i`, pages that may hold data.
fn flush_run(i: usize, m: &Map, lo: u64, v: u64) {
    let mut p = lo;
    while p < v {
        let n = PAGE.min(v - p);
        let differs = |q: u64, n: u64| unsafe {
            core::slice::from_raw_parts((m.addr + q) as *const u8, n as usize)
                != core::slice::from_raw_parts((m.shadow + q) as *const u8, n as usize)
        };
        if !differs(p, n) {
            p += n;
            continue;
        }
        // A run of differing pages.
        let start = p;
        while p < v && differs(p, PAGE.min(v - p)) {
            p += PAGE.min(v - p);
        }
        let len = p - start;
        unsafe {
            core::ptr::copy_nonoverlapping(
                (m.addr + start) as *const u8,
                (m.shadow + start) as *mut u8,
                len as usize,
            )
        };
        record(&FsOp::MmapDirty {
            ino: m.ino,
            offset: m.off + start,
            len,
            data: m.addr + start,
        });
        maps_changed_except(m.ino, m.off + start, len, Change::Data, i);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    /// New bytes in the file: copy them from the mapping (it shows the page cache).
    Data,
    /// Truncation or hole: the range reads as zeros.
    Zero,
}

fn maps_changed(ino: u64, off: u64, len: u64, how: Change) {
    maps_changed_except(ino, off, len, how, usize::MAX)
}

/// Bring every tracked view of `ino` up to date for a change the log already holds.
fn maps_changed_except(ino: u64, off: u64, len: u64, how: Change, skip: usize) {
    let t = MAPS.get();
    for i in 0..t.n {
        let m = t.m[i];
        if i == skip || m.ino != ino {
            continue;
        }
        let lo = off.max(m.off);
        let hi = off.saturating_add(len).min(m.off + m.len);
        if lo >= hi {
            continue;
        }
        let (a, n) = (lo - m.off, hi - lo);
        match how {
            Change::Zero => zero_shadow(m.shadow, a, n),
            Change::Data => {
                let v = valid_len(&m);
                let n = n.min(v.saturating_sub(a));
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (m.addr + a) as *const u8,
                        (m.shadow + a) as *mut u8,
                        n as usize,
                    )
                };
            }
        }
    }
}

fn overlaps(m: &Map, addr: u64, len: u64) -> bool {
    addr < m.addr + m.len && addr.saturating_add(len) > m.addr
}

fn drop_map(i: usize) {
    let t = MAPS.get();
    let m = t.m[i];
    free_shadow(m.shadow, m.shadow_len);
    unsafe { sc1(nr::CLOSE, m.fd as u64) };
    t.m[i] = t.m[t.n - 1];
    t.n -= 1;
}

/// Before `munmap(addr, len)`: flush the mappings it touches and stop tracking them
/// (a partial unmap keeps the remaining part tracked).
pub fn on_munmap(addr: u64, len: u64) {
    if addr & (PAGE - 1) != 0 {
        return; // the kernel refuses it: nothing is unmapped
    }
    let len = page_up(len);
    let mut i = 0;
    while i < MAPS.get().n {
        let m = MAPS.get().m[i];
        if !overlaps(&m, addr, len) {
            i += 1;
            continue;
        }
        flush(i);
        let (lo, hi) = (addr.max(m.addr), (addr + len).min(m.addr + m.len));
        if lo == m.addr && hi == m.addr + m.len {
            drop_map(i);
            continue;
        }
        // The shadow of the unmapped part goes with it.
        let t = MAPS.get();
        if lo == m.addr {
            // the head goes: keep the tail
            let cut = hi - m.addr;
            free_shadow(m.shadow, cut);
            t.m[i].addr = hi;
            t.m[i].len -= cut;
            t.m[i].off += cut;
            t.m[i].shadow += cut;
            t.m[i].shadow_len -= cut;
        } else {
            // keep the head; a hole in the middle splits the mapping in two
            t.m[i].len = lo - m.addr;
            t.m[i].shadow_len = lo - m.addr;
            let split = hi < m.addr + m.len && t.n < MAX_MAPS;
            let gone_to = if split { hi - m.addr } else { m.shadow_len };
            free_shadow(m.shadow + (lo - m.addr), gone_to - (lo - m.addr));
            if split {
                let cut = hi - m.addr;
                let hfd = unsafe { sc3(nr::FCNTL, m.fd as u64, F_DUPFD_CLOEXEC, HIDDEN_DUP_BASE) };
                let n = t.n;
                t.m[n] = Map {
                    addr: hi,
                    len: m.len - cut,
                    ino: m.ino,
                    off: m.off + cut,
                    shadow: m.shadow + cut,
                    shadow_len: m.shadow_len - cut,
                    fd: hfd,
                };
                t.n += 1;
            }
        }
        i += 1;
    }
}

/// `mremap`: flush and stop tracking the old range; track the new one.
pub fn on_mremap_before(addr: u64, len: u64) -> Option<(u64, u64, i64)> {
    let t = MAPS.get();
    let i = (0..t.n).find(|&i| t.m[i].addr == addr)?;
    flush(i);
    let m = t.m[i];
    let hfd = unsafe { sc3(nr::FCNTL, m.fd as u64, F_DUPFD_CLOEXEC, HIDDEN_DUP_BASE) };
    let _ = len;
    drop_map(i);
    Some((m.off, m.ino, hfd))
}

pub fn on_mremap_after(new: u64, newlen: u64, prev: Option<(u64, u64, i64)>, ok: bool) {
    let Some((off, ino, hfd)) = prev else { return };
    if !ok || hfd < 0 {
        if hfd >= 0 {
            unsafe { sc1(nr::CLOSE, hfd as u64) };
        }
        return;
    }
    let t = MAPS.get();
    if t.n == MAX_MAPS {
        return;
    }
    let shadow = new_shadow(newlen);
    let m = Map {
        addr: new,
        len: newlen,
        ino,
        off,
        shadow,
        shadow_len: page_up(newlen),
        fd: hfd,
    };
    fill_shadow(&m);
    t.m[t.n] = m;
    t.n += 1;
}

/// Flush every tracked mapping (process exit, `sync`).
pub fn flush_all() {
    for i in 0..MAPS.get().n {
        flush(i);
    }
}

fn flush_ino(ino: u64) {
    for i in 0..MAPS.get().n {
        if MAPS.get().m[i].ino == ino {
            flush(i);
        }
    }
}

/// `msync(addr, len, flags)` after the kernel validated it: record the dirty pages; with
/// `MS_SYNC` the data of each file is synced (a sync-class call, which can fail).
pub fn on_msync(addr: u64, len: u64, flags: u64) -> i64 {
    const MS_SYNC: u64 = 4;
    let mut inos = [0u64; 8];
    let mut ni = 0;
    let t = MAPS.get();
    for i in 0..t.n {
        if overlaps(&t.m[i], addr, len) && ni < inos.len() && !inos[..ni].contains(&t.m[i].ino) {
            inos[ni] = t.m[i].ino;
            ni += 1;
        }
    }
    if ni == 0 {
        return 0;
    }
    if flags & MS_SYNC != 0 {
        crate::inject::crash_point();
    }
    for i in 0..MAPS.get().n {
        if overlaps(&MAPS.get().m[i], addr, len) {
            flush(i);
        }
    }
    if flags & MS_SYNC == 0 {
        return 0;
    }
    let mut r = 0;
    for &ino in &inos[..ni] {
        if let Some(by) = crate::inject::sync_fails() {
            fail(
                ino,
                nr::MSYNC,
                crate::inject::Who::Kind(proto::faults::Obj::File),
                by,
            );
            r = -e::EIO;
        } else {
            append(
                OpKind::Fsync,
                ino,
                [FSYNC_DATA_ONLY | FSYNC_MSYNC, 0, 0, 0, 0, 0],
                &[],
                0,
            );
        }
    }
    r
}

const AT_FDCWD_: i64 = -100;

/// An injected writeback failure on `ino` (0: everything, for `syncfs`), named by `who`,
/// caused by the class `by` (`proto::faults::SYNC_BY_*`).
fn fail(ino: u64, nr: u64, who: crate::inject::Who, by: u64) {
    let d = dur();
    if ino != 0 && d.bump(ino).is_none() {
        crate::sup::capacity(
            proto::ctl::LIMIT_FSYNC_FAILURES,
            proto::oplog::ERRGEN_CAP as u64,
        );
    }
    d.sync_gen += 1;
    crate::inject::note(
        nr,
        proto::faults::INJ_FSYNC_EIO,
        proto::faults::FClass::Sync as u64,
        ino,
        by,
        who,
    );
    append(OpKind::FsyncFail, ino, [0; 6], &[], 0);
}

/// The fsync family: durability is the tracker's; the kernel is never asked (on tmpfs it
/// would do nothing). `fsync`/`fdatasync` on a `/work` file or directory, `sync_file_range`,
/// `sync`, `syncfs`.
pub fn sync_call(nr: u64, a: [u64; 6]) -> i64 {
    const F_GETFD: u64 = 1;
    if nr == nr::SYNC {
        // sync(2) reports nothing.
        crate::inject::crash_point();
        flush_all();
        append(OpKind::Sync, 0, [0; 6], &[], 0);
        return 0;
    }
    let fd = a[0] as i32 as i64;
    if unsafe { sc2(nr::FCNTL, fd as u64, F_GETFD) } < 0 {
        return -e::EBADF;
    }
    if nr == nr::SYNC_FILE_RANGE && a[3] & !7 != 0 {
        return -e::EINVAL;
    }
    if nr == nr::SYNCFS {
        crate::inject::crash_point();
        flush_all();
        if let Some(by) = crate::inject::sync_fails() {
            fail(0, nr, crate::inject::Who::At(AT_FDCWD_, work_cstr()), by);
            FDS.get().sync_seen = dur().sync_gen;
            return -e::EIO;
        }
        let g = dur().sync_gen;
        let report = FDS.get().sync_seen < g;
        FDS.get().sync_seen = g;
        append(OpKind::Sync, 0, [0; 6], &[], 0);
        return if report { -e::EIO } else { 0 };
    }
    let Some(st) = fstat_raw(fd) else {
        return -e::EBADF;
    };
    if !path::is_work(st.dev()) {
        return 0;
    }
    let ino = st.ino();
    let dir = st.mode() & 0o170000 == 0o040000;
    crate::inject::crash_point();
    if !dir {
        flush_ino(ino);
    }
    if let Some(by) = crate::inject::sync_fails() {
        let o = if dir {
            proto::faults::Obj::Path
        } else {
            proto::faults::Obj::File
        };
        fail(ino, nr, crate::inject::Who::Fd(fd, o), by);
        if let Some(s) = seen(fd) {
            *s = dur().gen(ino) as u32;
        }
        return -e::EIO;
    }
    if dir {
        append(OpKind::FsyncDir, ino, [0; 6], &[], 0);
        return 0;
    }
    let data_only = if nr == nr::FDATASYNC {
        FSYNC_DATA_ONLY
    } else {
        0
    };
    let g = dur().gen(ino) as u32;
    if let Some(s) = seen(fd) {
        if *s < g {
            // An earlier failed writeback, not yet reported to this descriptor: report it
            // once. The pages written since were written back; nothing is committed.
            *s = g;
            crate::inject::note(
                nr,
                proto::faults::INJ_FSYNC_REPORT,
                proto::faults::FClass::Sync as u64,
                ino,
                0,
                crate::inject::Who::Fd(fd, proto::faults::Obj::File),
            );
            append(
                OpKind::Fsync,
                ino,
                [data_only | FSYNC_NO_COMMIT, 0, 0, 0, 0, 0],
                &[],
                0,
            );
            return -e::EIO;
        }
    }
    let flags = if nr == nr::SYNC_FILE_RANGE {
        FSYNC_DATA_ONLY | FSYNC_NO_COMMIT
    } else {
        data_only
    };
    append(OpKind::Fsync, ino, [flags, 0, 0, 0, 0, 0], &[], 0);
    0
}

/// Before `close(fd)`: the inode, when it is a `/work` regular file.
pub fn before_close(fd: i64) -> Option<u64> {
    let st = fstat_raw(fd)?;
    (path::is_work(st.dev()) && st.mode() & 0o170000 == 0o100000).then_some(st.ino())
}

/// After a successful `close`: the `Close` record (the materialiser derives
/// "truncated to zero and rewritten" for `auto_da_alloc` itself).
pub fn closed(ino: u64) {
    record(&FsOp::Close {
        ino,
        truncated_to_zero: false,
    });
}

/// The process is exiting: record what its shared mappings still hold unrecorded.
/// Also before `execve` (the image's mappings go away). Not in a vfork child: the tracked
/// mappings are the parent's, which keeps them.
pub fn on_exit() {
    if crate::state::in_vfork_child() {
        return;
    }
    flush_all();
}

/// The work tree's path as a C string (the launcher leaves room for the NUL).
fn work_cstr() -> u64 {
    let w = &crate::state::config().work;
    if w[0] == 0 {
        c"/work".as_ptr() as u64
    } else {
        w.as_ptr() as u64
    }
}
