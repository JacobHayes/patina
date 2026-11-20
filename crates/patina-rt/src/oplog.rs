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
    let r = crate::fdlim::transient(|| unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            p.as_ptr() as u64,
            0o2000000,
            0,
        )
    }); // O_RDONLY|O_CLOEXEC
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
        kind: proto::oplog::tag_kind(kind as u32, crate::state::node()),
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
    shadow_apply(kind, ino, &a, data);
    if effect(kind, &a) == Effect::New && dur().new_inode(skey(ino)).is_none() {
        crate::sup::capacity(proto::ctl::LIMIT_FSYNC_FAILURES, ERRGEN_CAP as u64);
    }
    crate::inject::crash_point();
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
            let f = crate::state::faults();
            f.work_bytes
                .store(f.work_bytes.load(Relaxed) + len, Relaxed);
            append(OpKind::Write, ino, [offset, len, 0, 0, 0, 0], &[src], len);
        }
        FsOp::Truncate { ino, size } => {
            append(OpKind::Truncate, ino, [size, 0, 0, 0, 0, 0], &[], 0)
        }
        FsOp::Fallocate {
            ino,
            mode,
            offset,
            len,
        } => append(OpKind::Fallocate, ino, [mode, offset, len, 0, 0, 0], &[], 0),
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

// ---- per-process descriptor state: each descriptor's open file description ----
//
// Linux keeps a write-back error sample in each open file description (`struct file`), which
// `dup` and `fork` share. The runtime names a description by a key it gives at open (shared by
// the run, `Dur::new_desc`), keeps per descriptor the key and the samples taken at open, and a
// description that reports writes its advanced samples to `Dur::descs`, where every descriptor
// of it (in this process or another) reads them. Hidden duplicates the runtime keeps for
// tracked mappings carry their description too, so `msync` reports to the mapping's.

#[derive(Clone, Copy)]
struct Desc {
    /// The description's key (0: none).
    key: u64,
    /// The inode key it is open on (a stale entry names another).
    ino: u64,
    /// The samples of the inode's and the disk's error sequences taken at open.
    file: u64,
    disk: u64,
}

const NODESC: Desc = Desc {
    key: 0,
    ino: 0,
    file: 0,
    disk: 0,
};

static FDS: Global<[Desc; FD_LIMIT as usize]> = Global::new([NODESC; FD_LIMIT as usize]);

fn slot_fd(fd: i64) -> Option<&'static mut Desc> {
    (0..FD_LIMIT as i64)
        .contains(&fd)
        .then(|| &mut FDS.get()[fd as usize])
}

/// A new description on work inode `ino`, sampled as an opener samples.
fn new_desc(ino: u64) -> Desc {
    let k = skey(ino);
    let d = dur();
    Desc {
        key: d.new_desc(crate::state::node()),
        ino: k,
        file: d.sample(k),
        disk: d.sb_sample(crate::state::node()),
    }
}

/// A `/work` file or directory was opened at `fd`: a new description, which reports an error
/// nobody has seen yet and none that was seen (Linux 4.16 and later sample the mapping's
/// error sequence at open as 0 while it is unseen).
pub fn opened(fd: i64, ino: u64) {
    if crate::state::in_vfork_child() {
        return; // the table is the parent's; the child's image after execve starts fresh
    }
    if let Some(s) = slot_fd(fd) {
        *s = new_desc(ino);
    }
}

/// `dup` family (and the runtime's hidden duplicates): the same description. A work file or
/// directory the runtime did not see opened is taken as opened now, so both name one.
pub fn dup_fd(src: i64, dst: i64) {
    if crate::state::in_vfork_child() {
        return;
    }
    let mut v = slot_fd(src).map(|s| *s).unwrap_or(NODESC);
    if v.key == 0 {
        if let Some(st) = fstat_raw(src) {
            if path::is_work(st.dev()) && matches!(st.mode() as u64 & S_IFMT, S_IFREG | S_IFDIR) {
                v = desc_at(src, st.ino());
            }
        }
    }
    if let Some(d) = slot_fd(dst) {
        *d = v;
    }
}

/// `fd` was closed.
pub fn closed_fd(fd: i64) {
    if crate::state::in_vfork_child() {
        return;
    }
    if let Some(d) = slot_fd(fd) {
        *d = NODESC;
    }
}

/// The description at `fd`, open on work inode `ino`. A descriptor the runtime did not see
/// opened (one inherited across `execve`, or received in a message) is taken as opened now.
fn desc_at(fd: i64, ino: u64) -> Desc {
    match slot_fd(fd) {
        Some(d) if d.key != 0 && d.ino == skey(ino) => *d,
        _ => {
            let d = new_desc(ino);
            if !crate::state::in_vfork_child() {
                if let Some(s) = slot_fd(fd) {
                    *s = d;
                }
            }
            d
        }
    }
}

/// `file_check_and_advance_wb_err`: does the inode's error sequence differ from what the
/// description at `fd` has seen? If so, it is reported now: the description advances and
/// the value is seen.
fn report_file(fd: i64, ino: u64) -> bool {
    let mut d = desc_at(fd, ino);
    let dd = dur();
    let shared = dd.desc(d.key);
    let v = dd.seq(d.ino);
    if d.file.max(shared[0]) == v {
        return false;
    }
    if dd.mark_seen(d.ino).is_none() {
        crate::sup::capacity(proto::ctl::LIMIT_FSYNC_FAILURES, ERRGEN_CAP as u64);
    }
    d.file = v;
    d.disk = d.disk.max(shared[1]);
    dd.set_desc(d.key, [d.file, d.disk]);
    keep(fd, d);
    true
}

/// Store the description at `fd` back (its samples advanced).
fn keep(fd: i64, d: Desc) {
    if !crate::state::in_vfork_child() {
        if let Some(s) = slot_fd(fd) {
            *s = d;
        }
    }
}

/// `syncfs`'s `errseq_check_and_advance` on the disk's sequence, for the description at `fd`.
fn report_disk(fd: i64, ino: u64) -> bool {
    let mut d = desc_at(fd, ino);
    let node = crate::state::node();
    let dd = dur();
    let shared = dd.desc(d.key);
    let v = dd.sb_seq(node);
    if d.disk.max(shared[1]) == v {
        return false;
    }
    dd.sb_mark_seen(node);
    d.file = d.file.max(shared[0]);
    d.disk = v;
    dd.set_desc(d.key, [d.file, d.disk]);
    keep(fd, d);
    true
}

// ---- the shadow store: what the log holds of each mapped work file ----

fn shadows() -> &'static mut Shadows {
    &mut dur().shadows
}

/// The shadow table's key of this process's work inode `ino` (`proto::oplog::node_key`).
fn skey(ino: u64) -> u64 {
    proto::oplog::node_key(ino, crate::state::node())
}

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_DATA: u64 = 3;
const SEEK_HOLE: u64 = 4;
const FALLOC_FL_KEEP_SIZE: u64 = 1;
const O_PATH: i64 = 0o10000000;

/// Bytes compared or copied per read. Only one thread runs runtime code at a time; a flush's
/// buffers and a copy's are apart because a flush appends records, which copy.
const CHUNK: usize = 64 << 10;
static FILE_BUF: Global<[u8; CHUNK]> = Global::new([0; CHUNK]);
static WIN_BUF: Global<[u8; CHUNK]> = Global::new([0; CHUNK]);
static COPY_BUF: Global<[u8; CHUNK]> = Global::new([0; CHUNK]);

fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

fn file_size(fd: i64) -> u64 {
    fstat_raw(fd).map(|st| st.size()).unwrap_or(0)
}

/// Read `b.len()` bytes of `fd` at `off`; a file that ends first or a failed read is a host
/// error (no record is ever made of bytes that were not read).
fn pread_exact(fd: i64, b: &mut [u8], off: u64) {
    let mut done = 0usize;
    while done < b.len() {
        let r = unsafe {
            sc4(
                nr::PREAD64,
                fd as u64,
                b.as_mut_ptr() as u64 + done as u64,
                (b.len() - done) as u64,
                off + done as u64,
            )
        };
        if r <= 0 {
            crate::sup::host_error(r, nr::PREAD64, proto::ctl::HE_RUNTIME_ASSERT);
        }
        done += r as usize;
    }
}

/// Slot `k`'s store (`proto::oplog::Shadows`).
fn store(k: usize) -> u64 {
    (FD_SHADOWS as usize + k) as u64
}

fn store_write(k: usize, off: u64, s: &[u8]) {
    let mut done = 0usize;
    while done < s.len() {
        let r = unsafe {
            sc4(
                nr::PWRITE64,
                store(k),
                s.as_ptr() as u64 + done as u64,
                (s.len() - done) as u64,
                off + done as u64,
            )
        };
        if r <= 0 {
            crate::sup::host_error(r, nr::PWRITE64, proto::ctl::HE_SYSCALL);
        }
        done += r as usize;
    }
}

/// `b.len()` bytes of slot `k`'s store at `off`: zeros past its end.
fn store_read(k: usize, b: &mut [u8], off: u64) {
    let mut done = 0usize;
    while done < b.len() {
        let r = unsafe {
            sc4(
                nr::PREAD64,
                store(k),
                b.as_mut_ptr() as u64 + done as u64,
                (b.len() - done) as u64,
                off + done as u64,
            )
        };
        if r < 0 {
            crate::sup::host_error(r, nr::PREAD64, proto::ctl::HE_SYSCALL);
        }
        if r == 0 {
            b[done..].fill(0);
            return;
        }
        done += r as usize;
    }
}

/// What slot `k`'s store holds now, for the table's count.
fn store_note(k: usize) {
    if let Some(st) = fstat_raw(store(k) as i64) {
        shadows().held(k, st.blocks() * 512);
    }
}

/// `[off, off + len)` of slot `k`'s store reads as zeros: cut where it reaches the end, else
/// punched. Neither extends the store.
fn store_zero(k: usize, off: u64, len: u64) {
    let Some(st) = fstat_raw(store(k) as i64) else {
        crate::sup::host_error(-e::EBADF, nr::FSTAT, proto::ctl::HE_SYSCALL)
    };
    let size = st.size();
    if off >= size {
        return;
    }
    let (r, n) = if off.saturating_add(len) >= size {
        (unsafe { sc2(nr::FTRUNCATE, store(k), off) }, nr::FTRUNCATE)
    } else {
        let r = unsafe {
            sc4(
                nr::FALLOCATE,
                store(k),
                FALLOC_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                off,
                len,
            )
        };
        (r, nr::FALLOCATE)
    };
    if r < 0 {
        crate::sup::host_error(r, n, proto::ctl::HE_SYSCALL);
    }
    store_note(k);
}

/// `[from, from + len)` of `fd` into slot `k`'s store at `to`.
fn store_copy(fd: i64, from: u64, k: usize, to: u64, len: u64) {
    let b = COPY_BUF.get();
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK as u64) as usize;
        pread_exact(fd, &mut b[..n], from + done);
        store_write(k, to + done, &b[..n]);
        done += n as u64;
    }
    store_note(k);
}

fn free_slot(k: usize) {
    let s = shadows();
    s.ino[k] = 0;
    s.used -= 1;
    store_zero(k, 0, u64::MAX);
}

/// After a record was appended for `ino` (its bytes at `data` in `oplog.data`): its store
/// follows (`proto::oplog::Shadows`, the invariant; the supervisor's appends do the same).
fn shadow_apply(kind: OpKind, ino: u64, a: &[u64; 6], data: (u64, u64)) {
    let Some(k) = shadows().slot_of(skey(ino)) else {
        return;
    };
    match effect(kind, a) {
        Effect::None => {}
        Effect::New => free_slot(k),
        Effect::Zero { off, len } => store_zero(k, off, len),
        Effect::Data { off, .. } => store_copy(FD_OPLOG_DATA as i64, data.0, k, off, data.1),
    }
}

/// The data runs of `[lo, hi)` of the file open at `fd` (page-aligned file offsets): `f(a, b)`
/// for each, in order, page-aligned. A hole is never read: on tmpfs that would allocate its
/// pages (charged to the file system and the process) and change the file's block count. A
/// file system without hole information is all data. `fd` may be the program's descriptor: its
/// offset is put back.
fn data_runs(fd: i64, lo: u64, hi: u64, mut f: impl FnMut(u64, u64)) {
    let fd_ = fd as u64;
    let cur = unsafe { sc3(nr::LSEEK, fd_, 0, SEEK_CUR) };
    let mut pos = lo;
    while pos < hi {
        let d = unsafe { sc3(nr::LSEEK, fd_, pos, SEEK_DATA) };
        if d == -e::ENXIO {
            break;
        }
        if d < 0 {
            f(pos, hi);
            break;
        }
        let d = (d as u64 & !(PAGE - 1)).max(pos);
        if d >= hi {
            break;
        }
        let h = unsafe { sc3(nr::LSEEK, fd_, d, SEEK_HOLE) };
        let end = if h < 0 { hi } else { page_up(h as u64).min(hi) };
        let end = end.max(d + PAGE).min(hi);
        f(d, end);
        pos = end;
    }
    if cur >= 0 {
        unsafe { sc3(nr::LSEEK, fd_, cur as u64, SEEK_SET) };
    }
}

/// Record the pages of `[lo, hi)` of the work inode `ino` (slot `k`, open for reading at `fd`;
/// `lo` page-aligned) whose bytes differ from what the log holds: one `MmapDirty` per run of
/// differing pages within a run of the file's data, with the file's bytes. Every process's
/// stores through a `MAP_SHARED` mapping are the file's bytes (the page cache), so this logs
/// them whichever process made them.
fn flush_file(fd: i64, k: usize, ino: u64, lo: u64, hi: u64) {
    let v = hi.min(file_size(fd));
    if lo >= v {
        return;
    }
    data_runs(fd, lo, page_up(v), |a, b| {
        let b = b.min(v);
        let (fb, wb) = (FILE_BUF.get(), WIN_BUF.get());
        let mut run: Option<u64> = None;
        let mut p = a;
        while p < b {
            let n = (b - p).min(CHUNK as u64) as usize;
            pread_exact(fd, &mut fb[..n], p);
            store_read(k, &mut wb[..n], p);
            let mut q = 0;
            while q < n {
                let m = (PAGE as usize).min(n - q);
                let differs = fb[q..q + m] != wb[q..q + m];
                let at = p + q as u64;
                match (differs, run) {
                    (true, None) => run = Some(at),
                    (false, Some(s)) => {
                        dirty(fd, ino, s, at);
                        run = None;
                    }
                    _ => {}
                }
                q += m;
            }
            p += n as u64;
        }
        if let Some(s) = run {
            dirty(fd, ino, s, b);
        }
    });
}

fn dirty(fd: i64, ino: u64, lo: u64, hi: u64) {
    append(
        OpKind::MmapDirty,
        ino,
        [lo, hi - lo, 0, 0, 0, 0],
        &[Src::File(fd, lo)],
        hi - lo,
    );
}

/// A tracked mapping of `ino` (open at `fd`) is being made: its slot, made and filled from the
/// file when it has none. No slot means no process maps the inode (slots are freed only when
/// none does), so the file holds what the log holds.
fn slot_for(ino: u64, fd: i64) -> usize {
    if let Some(k) = shadows().slot_of(skey(ino)) {
        return k;
    }
    let k = match shadows().free_slot() {
        Some(k) => k,
        None => {
            crate::sup::call_sup(proto::ctl::Op::ShadowReclaim, [0; 6]);
            shadows().free_slot().unwrap_or_else(|| {
                crate::sup::capacity(proto::ctl::LIMIT_MAPPED_FILES, SHADOW_SLOTS as u64)
            })
        }
    };
    // A free slot's store is empty (freed by truncation); made so again, as the fill writes
    // only the file's data runs.
    store_zero(k, 0, u64::MAX);
    let s = shadows();
    s.ino[k] = skey(ino);
    s.used += 1;
    let size = file_size(fd);
    data_runs(fd, 0, page_up(size), |a, b| {
        let b = b.min(size);
        if b > a {
            store_copy(fd, a, k, a, b - a);
        }
    });
    k
}

/// `fd` if it can be read, else a new read-only descriptor of the same file (closed with
/// `done`); None for an `O_PATH` descriptor, which reads nothing.
fn reader(fd: i64) -> Option<i64> {
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, 3) }; // F_GETFL
    (fl >= 0 && fl & O_PATH == 0).then(|| readable(fd))
}

fn done(fd: i64, rfd: i64) {
    if rfd != fd {
        unsafe { sc1(nr::CLOSE, rfd as u64) };
    }
}

/// Whether any work file has a shadow: the write-family calls look at nothing else when none
/// does.
pub fn shadows_in_use() -> bool {
    shadows().used != 0
}

/// Before a call that writes `count` bytes to `fd` at `off` (its position when None). `append`:
/// Some(true) writes at the end (`RWF_APPEND`), Some(false) at `off` (`RWF_NOAPPEND`), None
/// as the descriptor's `O_APPEND` says. The pages it will write that hold stores not yet logged
/// (any process's, through a mapping) are logged first, whole, so the log has them before the
/// write's record, as the page cache had them before the write. Logged after it, a page would
/// carry the write's bytes and the crash model could keep the write without the stores, a
/// state Linux cannot reach (writeback writes whole pages).
pub fn before_write(fd: i64, off: Option<u64>, count: u64, append: Option<bool>) {
    if shadows().used == 0 || count == 0 {
        return;
    }
    let Some(st) = fstat_raw(fd) else { return };
    if !path::is_work(st.dev()) || st.mode() & 0o170000 != 0o100000 {
        return;
    }
    let Some(k) = shadows().slot_of(skey(st.ino())) else {
        return;
    };
    const O_APPEND: i64 = 0o2000;
    let append = append.unwrap_or_else(|| unsafe { sc2(nr::FCNTL, fd as u64, 3) } & O_APPEND != 0);
    let lo = if append {
        st.size()
    } else {
        match off {
            Some(o) => o,
            None => {
                let pos = unsafe { sc3(nr::LSEEK, fd as u64, 0, SEEK_CUR) };
                if pos < 0 {
                    return;
                }
                pos as u64
            }
        }
    };
    let Some(rfd) = reader(fd) else { return };
    // Whole pages: writeback writes a page with every store on it.
    flush_file(
        rfd,
        k,
        st.ino(),
        lo & !(PAGE - 1),
        page_up(lo.saturating_add(count)),
    );
    done(fd, rfd);
}

/// Bytes an iovec array of the program's (`iov`, `cnt` entries) describes, read before the
/// kernel has looked at it: None when the kernel will refuse it (more than `IOV_MAX` entries,
/// or an entry that cannot be read).
pub fn iov_bytes(iov: u64, cnt: u64) -> Option<u64> {
    if cnt > 1024 {
        return None;
    }
    let mut t = 0u64;
    for i in 0..cnt {
        let [_, l] = crate::guest::get::<[u64; 2]>(iov.wrapping_add(i * 16)).ok()?;
        t = t.saturating_add(l);
    }
    Some(t)
}

// ---- shared file mappings ----

const MAX_MAPS: usize = MAX_SHARED_MAPS;
type Map = SharedMap;

const NOMAP: Map = Map {
    addr: 0,
    len: 0,
    ino: 0,
    off: 0,
    fd: -1,
};
/// The process's tracked mappings; the supervisor reads them when the process ends without
/// this runtime (`proto::oplog::SharedMaps`).
static MAPS: Global<SharedMaps> = Global::new(SharedMaps {
    m: [NOMAP; MAX_MAPS],
    n: 0,
});

/// Tell the supervisor where this image keeps its tracked mappings (at each image's start).
/// The image before it, if any, had its own mappings: whatever slots they kept are looked at
/// before the next request.
pub fn publish_maps() {
    ctl()
        .maps_table
        .store(MAPS.get() as *const SharedMaps as u64, Relaxed);
    if shadows().used != 0 {
        shadows().reclaim = 1;
    }
}

const F_DUPFD_CLOEXEC: u64 = 1030;
const HIDDEN_DUP_BASE: u64 = proto::layout::FD_RT_DYN as u64;

fn track(addr: u64, len: u64, ino: u64, off: u64, hfd: i64) {
    let t = MAPS.get();
    if t.n == MAX_MAPS {
        crate::sup::capacity(proto::ctl::LIMIT_SHARED_MAPS, MAX_MAPS as u64);
    }
    slot_for(ino, hfd);
    t.m[t.n] = Map {
        addr,
        len,
        ino,
        off,
        fd: hfd,
    };
    t.n += 1;
}

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
    let hfd = crate::fdlim::raised(|| unsafe {
        sc3(nr::FCNTL, fd as u64, F_DUPFD_CLOEXEC, HIDDEN_DUP_BASE)
    });
    if hfd < 0 {
        crate::sup::host_error(hfd, nr::FCNTL, proto::ctl::HE_SYSCALL);
    }
    desc_at(fd, st.ino());
    dup_fd(fd, hfd);
    track(addr, len, st.ino(), off, hfd);
    append(OpKind::MmapShared, st.ino(), [off, len, 0, 0, 0, 0], &[], 0);
}

/// Record the pages of mapping `i` that differ from what the log holds (`MmapDirty`).
fn flush(i: usize) {
    let m = MAPS.get().m[i];
    if let Some(k) = shadows().slot_of(skey(m.ino)) {
        flush_file(m.fd, k, m.ino, m.off, m.off.saturating_add(m.len));
    }
}

fn overlaps(m: &Map, addr: u64, len: u64) -> bool {
    addr < m.addr + m.len && addr.saturating_add(len) > m.addr
}

/// Stop tracking mapping `i`: its slot is looked at before the next request (another process
/// may still map the file).
fn drop_map(i: usize) {
    let t = MAPS.get();
    unsafe { sc1(nr::CLOSE, t.m[i].fd as u64) };
    t.m[i] = t.m[t.n - 1];
    t.n -= 1;
    shadows().reclaim = 1;
}

/// Before `munmap(addr, len)`: flush the mappings it may unmap (harmless when the kernel
/// then refuses the call).
pub fn on_munmap(addr: u64, len: u64) {
    if addr & (PAGE - 1) != 0 {
        return; // the kernel refuses it: nothing is unmapped
    }
    for i in 0..MAPS.get().n {
        if overlaps(&MAPS.get().m[i], addr, len) {
            flush(i);
        }
    }
}

/// After a `munmap(addr, len)` the kernel made (only then: one it refuses, as of length 0,
/// unmaps nothing): stop tracking the mappings it removed (a partial unmap keeps the remaining
/// part tracked).
pub fn on_munmap_done(addr: u64, len: u64) {
    let len = page_up(len);
    let mut i = 0;
    while i < MAPS.get().n {
        let m = MAPS.get().m[i];
        if !overlaps(&m, addr, len) {
            i += 1;
            continue;
        }
        let (lo, hi) = (addr.max(m.addr), (addr + len).min(m.addr + m.len));
        if lo == m.addr && hi == m.addr + m.len {
            drop_map(i);
            continue;
        }
        let t = MAPS.get();
        if lo == m.addr {
            // the head goes: keep the tail
            let cut = hi - m.addr;
            t.m[i].addr = hi;
            t.m[i].len -= cut;
            t.m[i].off += cut;
        } else {
            // keep the head; a hole in the middle splits the mapping in two
            t.m[i].len = lo - m.addr;
            if hi < m.addr + m.len {
                if t.n == MAX_MAPS {
                    // The tail would go untracked and its stores unlogged.
                    crate::sup::capacity(proto::ctl::LIMIT_SHARED_MAPS, MAX_MAPS as u64);
                }
                let cut = hi - m.addr;
                let hfd = crate::fdlim::raised(|| unsafe {
                    sc3(nr::FCNTL, m.fd as u64, F_DUPFD_CLOEXEC, HIDDEN_DUP_BASE)
                });
                if hfd < 0 {
                    crate::sup::host_error(hfd, nr::FCNTL, proto::ctl::HE_SYSCALL);
                }
                dup_fd(m.fd, hfd);
                let n = t.n;
                t.m[n] = Map {
                    addr: hi,
                    len: m.len - cut,
                    ino: m.ino,
                    off: m.off + cut,
                    fd: hfd,
                };
                t.n += 1;
            }
        }
        i += 1;
    }
}

/// What `on_mremap_before` set aside: the old mapping, its descriptor kept.
pub struct Remap {
    addr: u64,
    len: u64,
    ino: u64,
    off: u64,
    fd: i64,
}

/// `mremap` (`flags`): flush and stop tracking the old range; track the new one. Only a
/// whole tracked mapping is moved or resized: a part of one (which would leave the rest
/// untracked, or the tracked range stale), a copy (`old_size` 0) or a move that keeps the old
/// range mapped (`MREMAP_DONTUNMAP`) ends the run `unsupported` rather than lose its stores.
pub fn on_mremap_before(addr: u64, len: u64, flags: u64) -> Option<Remap> {
    const MREMAP_DONTUNMAP: u64 = 4;
    let t = MAPS.get();
    let part = (0..t.n).any(|i| {
        let m = &t.m[i];
        overlaps(m, addr, len.max(1))
            && (addr != m.addr || page_up(len) != page_up(m.len) || flags & MREMAP_DONTUNMAP != 0)
    });
    if part && addr & (PAGE - 1) == 0 {
        crate::sup::stop(nr::MREMAP, addr);
    }
    let i = (0..t.n).find(|&i| t.m[i].addr == addr)?;
    flush(i);
    let m = t.m[i];
    // The entry goes; its descriptor stays for the mapping's new (or, on failure, old) place.
    t.m[i] = t.m[t.n - 1];
    t.n -= 1;
    Some(Remap {
        addr: m.addr,
        len: m.len,
        ino: m.ino,
        off: m.off,
        fd: m.fd,
    })
}

/// After the `mremap`: track the mapping where it now is (where it was, when the call failed).
pub fn on_mremap_after(new: u64, newlen: u64, prev: Option<Remap>, ok: bool) {
    let Some(r) = prev else { return };
    if ok {
        track(new, newlen, r.ino, r.off, r.fd);
    } else {
        track(r.addr, r.len, r.ino, r.off, r.fd);
    }
}

/// Flush every tracked mapping (process exit).
pub fn flush_all() {
    for i in 0..MAPS.get().n {
        flush(i);
    }
}

/// `sync`, `syncfs`: every shadowed file's unlogged stores are logged. When the caller maps
/// every shadowed file it compares each whole file itself (the file is every process's
/// stores); else the supervisor compares every process's mappings (`Op::MapsSync`), as at a
/// crash point.
fn flush_everything() {
    let s = shadows();
    let t = MAPS.get();
    let others = s
        .ino
        .iter()
        // Only this node's files: another machine's page cache is not this one's to sync.
        .any(|&key| {
            key != 0
                && key >> 56 == crate::state::node() as u64
                && !t.m[..t.n].iter().any(|m| skey(m.ino) == key)
        });
    if others {
        crate::sup::call_sup(proto::ctl::Op::MapsSync, [thread().seq, 0, 0, 0, 0, 0]);
        return;
    }
    // Each file this process maps, whole: another process may map (and have stored to) a
    // part of it this one does not.
    for i in 0..t.n {
        let m = t.m[i];
        if t.m[..i].iter().any(|p| p.ino == m.ino) {
            continue;
        }
        if let Some(k) = s.slot_of(skey(m.ino)) {
            flush_file(m.fd, k, m.ino, 0, u64::MAX);
        }
    }
}

/// `fsync` family on the work file `ino` open at `fd`: whatever any process stored through a
/// mapping of it is logged before the sync.
fn flush_whole(fd: i64, ino: u64) {
    let Some(k) = shadows().slot_of(skey(ino)) else {
        return;
    };
    let Some(rfd) = reader(fd) else { return };
    flush_file(rfd, k, ino, 0, u64::MAX);
    done(fd, rfd);
}

/// After a successful `madvise(MADV_REMOVE)`: the range of each tracked mapping it covers is a
/// hole punched in the file (`Fallocate`).
pub fn on_madv_remove(addr: u64, len: u64) {
    let t = MAPS.get();
    for i in 0..t.n {
        let m = t.m[i];
        let (lo, hi) = (
            addr.max(m.addr),
            addr.saturating_add(page_up(len)).min(m.addr + m.len),
        );
        if lo < hi {
            record(&FsOp::Fallocate {
                ino: m.ino,
                mode: FALLOC_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                offset: m.off + (lo - m.addr),
                len: hi - lo,
            });
        }
    }
}

/// `msync(addr, len, flags)` after the kernel validated it: record the dirty pages; with
/// `MS_SYNC` each mapped file is synced (`vfs_fsync_range` on the mapping's description, in
/// address order, stopping at the first error), which can fail and reports a pending error.
pub fn on_msync(addr: u64, len: u64, flags: u64) -> i64 {
    const MS_SYNC: u64 = 4;
    // (description, inode, the mapping's hidden descriptor), one per description, in the
    // order the mappings were made.
    let mut files = [(0u64, 0u64, 0i64); 8];
    let mut ni = 0;
    let t = MAPS.get();
    for i in 0..t.n {
        let m = t.m[i];
        if !overlaps(&m, addr, len) {
            continue;
        }
        let key = desc_at(m.fd, m.ino).key;
        if ni < files.len() && !files[..ni].iter().any(|f| f.0 == key) {
            files[ni] = (key, m.ino, m.fd);
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
    for &(_, ino, hfd) in &files[..ni] {
        if let Some(by) = crate::inject::sync_fails() {
            fail(
                ino,
                nr::MSYNC,
                crate::inject::Who::Kind(proto::faults::Obj::File),
                by,
            );
            report_file(hfd, ino);
            return -e::EIO;
        }
        if report_file(hfd, ino) {
            reported(
                nr::MSYNC,
                ino,
                crate::inject::Who::Kind(proto::faults::Obj::File),
            );
            append(
                OpKind::Fsync,
                ino,
                [FSYNC_DATA_ONLY | FSYNC_NO_COMMIT, 0, 0, 0, 0, 0],
                &[],
                0,
            );
            return -e::EIO;
        }
        append(
            OpKind::Fsync,
            ino,
            [FSYNC_DATA_ONLY | FSYNC_MSYNC, 0, 0, 0, 0, 0],
            &[],
            0,
        );
    }
    0
}

const AT_FDCWD_: i64 = -100;

/// An injected write-back failure on `ino` (0: the whole disk, for `syncfs`), named by `who`,
/// caused by the class `by` (`proto::faults::SYNC_BY_*`): the pages it held fail
/// (`FsyncFail`: never durable unless written again) and the error waits in the inode's
/// error sequence (and the disk's) for the calls that report it.
fn fail(ino: u64, nr: u64, who: crate::inject::Who, by: u64) {
    let d = dur();
    if ino == 0 {
        d.fail_wide(crate::state::node());
    } else if d.fail(skey(ino)).is_none() {
        crate::sup::capacity(
            proto::ctl::LIMIT_FSYNC_FAILURES,
            proto::oplog::ERRGEN_CAP as u64,
        );
    }
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

/// An earlier write-back failure reported now (an `Injected` record of kind
/// `INJ_FSYNC_REPORT`).
fn reported(nr: u64, ino: u64, who: crate::inject::Who) {
    crate::inject::note(
        nr,
        proto::faults::INJ_FSYNC_REPORT,
        proto::faults::FClass::Sync as u64,
        ino,
        0,
        who,
    );
}

const S_IFMT: u64 = 0o170000;
const S_IFREG: u64 = 0o100000;
const S_IFDIR: u64 = 0o040000;
const S_IFLNK: u64 = 0o120000;
const S_IFBLK: u64 = 0o060000;
const SYNC_FILE_RANGE_WAIT_BEFORE: u64 = 1;
const SYNC_FILE_RANGE_WRITE: u64 = 2;
const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;

/// The fsync family: durability is the tracker's; the kernel is never asked (on tmpfs it
/// would do nothing). `fsync`/`fdatasync` on a `/work` file or directory, `sync_file_range`,
/// `sync`, `syncfs`. Which call may be given the injected failure, which reports a pending
/// one, and what each records: ARCHITECTURE.md, "The fsync-error model".
pub fn sync_call(nr: u64, a: [u64; 6]) -> i64 {
    const F_GETFL: u64 = 3;
    if nr == nr::SYNC {
        // sync(2) reports nothing.
        crate::inject::crash_point();
        flush_everything();
        append(OpKind::Sync, 0, [0; 6], &[], 0);
        return 0;
    }
    let fd = a[0] as i32 as i64;
    // `fdget`: a closed descriptor or an `O_PATH` one is EBADF.
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, F_GETFL) };
    if fl < 0 || fl & O_PATH != 0 {
        return -e::EBADF;
    }
    if nr == nr::SYNC_FILE_RANGE {
        let (off, n) = (a[1] as i64, a[2] as i64);
        let end = off.wrapping_add(n);
        if a[3] & !7 != 0 || off < 0 || end < 0 || end < off {
            return -e::EINVAL;
        }
    }
    let Some(st) = fstat_raw(fd) else {
        return -e::EBADF;
    };
    let fmt = st.mode() as u64 & S_IFMT;
    let work = path::is_work(st.dev());
    let ino = st.ino();
    if nr == nr::SYNCFS {
        if !work {
            return 0;
        }
        crate::inject::crash_point();
        flush_everything();
        let failed = if let Some(by) = crate::inject::sync_fails() {
            fail(0, nr, crate::inject::Who::At(AT_FDCWD_, work_cstr()), by);
            true
        } else {
            append(OpKind::Sync, 0, [0; 6], &[], 0);
            false
        };
        // `sync_filesystem`'s error first; the disk's sequence is checked and advanced either way.
        let pending = report_disk(fd, ino);
        if pending && !failed {
            reported(nr, 0, crate::inject::Who::At(AT_FDCWD_, work_cstr()));
        }
        return if failed || pending { -e::EIO } else { 0 };
    }
    if nr == nr::SYNC_FILE_RANGE {
        if !matches!(fmt, S_IFREG | S_IFDIR | S_IFLNK | S_IFBLK) {
            return -e::ESPIPE;
        }
    } else if !matches!(fmt, S_IFREG | S_IFDIR | S_IFBLK) {
        // A pipe, socket, character device or anonymous inode has no `fsync`.
        return -e::EINVAL;
    }
    if !work {
        return 0;
    }
    let dir = fmt == S_IFDIR;
    let obj = if dir {
        proto::faults::Obj::Path
    } else {
        proto::faults::Obj::File
    };
    let who = crate::inject::Who::Fd(fd, obj);
    if nr == nr::SYNC_FILE_RANGE {
        let flags = a[3];
        if flags & SYNC_FILE_RANGE_WAIT_BEFORE != 0 && report_file(fd, ino) {
            reported(nr, ino, who);
            return -e::EIO;
        }
        if flags & SYNC_FILE_RANGE_WRITE != 0 {
            // Starts write-back and, without WAIT_AFTER, does not wait for it: a failure of
            // that write-back is recorded on the inode and reported by a later call that waits.
            crate::inject::crash_point();
            if !dir {
                flush_whole(fd, ino);
            }
            if let Some(by) = crate::inject::sync_fails() {
                fail(ino, nr, who, by);
            } else if !dir {
                append(
                    OpKind::Fsync,
                    ino,
                    [FSYNC_DATA_ONLY | FSYNC_NO_COMMIT, 0, 0, 0, 0, 0],
                    &[],
                    0,
                );
            }
        }
        if flags & SYNC_FILE_RANGE_WAIT_AFTER != 0 && report_file(fd, ino) {
            reported(nr, ino, who);
            return -e::EIO;
        }
        return 0;
    }
    crate::inject::crash_point();
    if !dir {
        flush_whole(fd, ino);
    }
    if let Some(by) = crate::inject::sync_fails() {
        fail(ino, nr, who, by);
        report_file(fd, ino);
        return -e::EIO;
    }
    fsync_rest(
        nr,
        fd,
        ino,
        dir,
        if nr == nr::FDATASYNC {
            FSYNC_DATA_ONLY
        } else {
            0
        },
    )
}

/// `fsync`/`fdatasync` once write-back succeeded: report a pending error (the pages are
/// written back, nothing is committed), else commit.
fn fsync_rest(nr: u64, fd: i64, ino: u64, dir: bool, data_only: u64) -> i64 {
    if report_file(fd, ino) {
        let obj = if dir {
            proto::faults::Obj::Path
        } else {
            proto::faults::Obj::File
        };
        reported(nr, ino, crate::inject::Who::Fd(fd, obj));
        if !dir {
            append(
                OpKind::Fsync,
                ino,
                [data_only | FSYNC_NO_COMMIT, 0, 0, 0, 0, 0],
                &[],
                0,
            );
        }
        return -e::EIO;
    }
    if dir {
        append(OpKind::FsyncDir, ino, [0; 6], &[], 0);
    } else {
        append(OpKind::Fsync, ino, [data_only, 0, 0, 0, 0, 0], &[], 0);
    }
    0
}

/// After a write of `len > 0` bytes to the work file `ino` at `fd` through a description with
/// `O_SYNC`/`O_DSYNC` (`fl`, from `F_GETFL`) or with `RWF_SYNC`/`RWF_DSYNC` (`rwf`): the
/// kernel's `generic_write_sync` syncs what was written (as `fsync` or `fdatasync`); a
/// failure is the call's result.
pub fn write_sync(call_nr: u64, fd: i64, ino: u64, fl: i64, rwf: u64) -> i64 {
    const O_DSYNC: i64 = 0o10000;
    const O_SYNC_ONLY: i64 = 0o4000000; // __O_SYNC
    const RWF_DSYNC: u64 = 2;
    const RWF_SYNC: u64 = 4;
    let dsync = fl & O_DSYNC != 0 || rwf & (RWF_DSYNC | RWF_SYNC) != 0;
    if !dsync {
        return 0;
    }
    let full = fl & O_SYNC_ONLY != 0 || rwf & RWF_SYNC != 0;
    crate::inject::crash_point();
    flush_whole(fd, ino);
    if let Some(by) = crate::inject::sync_fails_sub(proto::faults::SUB_WSYNC_ERR_FIRE) {
        fail(
            ino,
            call_nr,
            crate::inject::Who::Fd(fd, proto::faults::Obj::File),
            by,
        );
        report_file(fd, ino);
        return -e::EIO;
    }
    fsync_rest(
        call_nr,
        fd,
        ino,
        false,
        if full { 0 } else { FSYNC_DATA_ONLY },
    )
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

/// The process is exiting (`exit`, `exit_group`, a thread's `exit`, a signal's default
/// action): record what its shared mappings still hold unrecorded. Also before `execve` (the
/// image's mappings go away). Not in a vfork child: the tracked mappings are the parent's,
/// which keeps them. An end the runtime does not see (a `SIGKILL`, the end of the run, a
/// crash) is logged by the supervisor from the same table (`sup::maps`).
pub fn on_exit() {
    if crate::state::in_vfork_child() {
        return;
    }
    flush_all();
}

/// The work tree's path as a C string (the launcher leaves room for the NUL).
fn work_cstr() -> u64 {
    let w = crate::state::work_path();
    if w == b"/work" {
        c"/work".as_ptr() as u64
    } else {
        // NUL-padded in the control region (`Config::work`, `NodeTab::work`).
        w.as_ptr() as u64
    }
}
