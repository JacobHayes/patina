//! Boundary log: a shared file mapping at `state::log_base`, appended under the turn.

use crate::path::PathBuf;
use crate::raw::*;
use crate::resolve::Paths;
use crate::state::{ctl, proc};
use core::sync::atomic::Ordering::*;
use proto::layout::*;
use proto::rec::{chain, hash_bytes, Hasher, Rec, PATH_BYTES, REC_SIZE};
use proto::table::{Len, Out, Row};

fn ensure(len: u64) {
    let c = ctl();
    let p = proc();
    if len <= p.log_mapped {
        return;
    }
    let mut cap = c.log_cap.load(Relaxed);
    while len > cap {
        let newcap = cap + log_grow_step(cap);
        grow(cap, newcap);
        c.log_cap.store(newcap, Relaxed);
        cap = newcap;
    }
    let r = unsafe {
        sc6(
            nr::MMAP,
            crate::state::log_base() + p.log_mapped,
            cap - p.log_mapped,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED_NOREPLACE,
            FD_LOG as u64,
            p.log_mapped,
        )
    };
    if r as u64 != crate::state::log_base() + p.log_mapped {
        crate::sup::host_error(r, nr::MMAP, proto::ctl::HE_SYSCALL);
    }
    p.log_mapped = cap;
}

/// Extend the log file from `cap` to `newcap` bytes, its blocks allocated now: a full host
/// filesystem is then a failed call here (`disk-full`), never a SIGBUS at a later store
/// through the mapping. A filesystem without `fallocate` gets a sparse extension.
fn grow(cap: u64, newcap: u64) {
    let r = unsafe { sc4(nr::FALLOCATE, FD_LOG as u64, 0, cap, newcap - cap) };
    if r == -e::EOPNOTSUPP {
        let r = unsafe { sc2(nr::FTRUNCATE, FD_LOG as u64, newcap) };
        if r < 0 {
            crate::sup::log_write_failed(r, nr::FTRUNCATE);
        }
    } else if r < 0 {
        crate::sup::log_write_failed(r, nr::FALLOCATE);
    }
}

/// Whether one more record would take the run's logs past `Config::log_limit`. The limit
/// counts records and logged bytes, never time: the same seed stops at the same record.
pub fn over_limit() -> bool {
    let c = ctl();
    c.log_used() + REC_SIZE as u64 > c.config.log_limit
}

pub fn append(rec: &Rec) {
    // cost measurement only: `RUSTFLAGS="--cfg patina_nolog"` builds a runtime that writes no
    // boundary record (and hashes no buffer). Never the default; digests are then meaningless.
    #[cfg(patina_nolog)]
    {
        let _ = rec;
        return;
    }
    #[allow(unreachable_code)]
    let c = ctl();
    if over_limit() {
        crate::sup::log_limit();
    }
    let off = c.log_len.load(Relaxed);
    ensure(off + REC_SIZE as u64);
    unsafe {
        core::ptr::copy_nonoverlapping(
            rec.as_bytes().as_ptr(),
            (crate::state::log_base() + off) as *mut u8,
            REC_SIZE,
        );
    }
    c.log_len.store(off + REC_SIZE as u64, Relaxed);
    c.log_hash
        .store(chain(c.log_hash.load(Relaxed), rec), Relaxed);
}

/// Hash `n` guest bytes at `p`. Memory the guest named but cannot be read (a call that wrote
/// nothing through a dangling pointer, as `getgroups(0, p)`) hashes as a marker: the runtime
/// never faults on a guest pointer (`guest.rs`).
fn hash_guest(h: &mut Hasher, p: u64, n: u64) {
    if crate::guest::each(p, n, |b| h.update(b)).is_err() {
        h.update(b"\0EFAULT");
    }
}

/// Hash `n` `struct epoll_event`s at `p`: each one's `events` and `data`, never the padding
/// between them (arm64), which the kernel neither reads nor writes. Packed records (x86_64)
/// are their fields, hashed as one range.
fn hash_epoll(h: &mut Hasher, p: u64, n: u64) {
    use proto::abi::epoll::{DATA, PACKED, SIZE};
    if PACKED {
        return hash_guest(h, p, n * SIZE as u64);
    }
    for i in 0..n {
        let e = p + i * SIZE as u64;
        let (Ok(events), Ok(data)) = (
            crate::guest::get::<[u8; 4]>(e),
            crate::guest::get::<[u8; 8]>(e + DATA as u64),
        ) else {
            h.update(b"\0EFAULT");
            return;
        };
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&events);
        b[4..].copy_from_slice(&data);
        h.update(&b);
    }
}

/// The C strings a call's inputs named, kept as the hash read them (`log_paths`).
struct Kept {
    s: [PathBuf; 2],
    /// Per string: the argument it is (`Paths::NONE`: none kept), and whether it was cut.
    arg: [u8; 2],
    cut: [bool; 2],
    /// C strings met so far: the first is `STR_PATH`, the second `STR_PATH2`.
    met: usize,
}

/// Hash the guest buffers described by `bufs` (output side: after the call).
pub fn hash_bufs(bufs: &[Out], args: &[u64; 6], ret: i64) -> u64 {
    hash_keep(bufs, args, ret, None)
}

/// `hash_bufs`, keeping each C string's bytes in `keep` from the same read.
fn hash_keep(bufs: &[Out], args: &[u64; 6], ret: i64, mut keep: Option<&mut Kept>) -> u64 {
    if bufs.is_empty() || ret < 0 {
        return 0;
    }
    let mut h = Hasher::new();
    for b in bufs {
        let p = args[b.arg as usize];
        if p == 0 {
            continue;
        }
        match b.len {
            Len::Ret { .. } => hash_guest(&mut h, p, ret as u64),
            Len::Arg(i) => hash_guest(&mut h, p, args[i as usize]),
            Len::Fixed(n) => hash_guest(&mut h, p, n as u64),
            Len::RetTimes { size, .. } => hash_guest(&mut h, p, ret as u64 * size as u64),
            Len::EpollEvents { .. } => hash_epoll(&mut h, p, ret as u64),
            Len::EpollEvent => hash_epoll(&mut h, p, 1),
            Len::ArgTimes { arg, size } => hash_guest(&mut h, p, args[arg as usize] * size as u64),
            Len::CStr => match (crate::guest::strlen(p, PATH_BYTES), keep.as_deref_mut()) {
                (Ok(n), None) => hash_guest(&mut h, p, n as u64),
                (Ok(n), Some(k)) => {
                    let j = k.met.min(1);
                    k.met += 1;
                    let buf = &mut k.s[j];
                    buf.n = 0;
                    let read = crate::guest::each(p, n as u64, |b| {
                        h.update(b);
                        buf.b[buf.n..buf.n + b.len()].copy_from_slice(b);
                        buf.n += b.len();
                    });
                    if read.is_err() {
                        h.update(b"\0EFAULT");
                    } else {
                        k.arg[j] = b.arg;
                        // No NUL within the bytes kept: a longer string.
                        k.cut[j] = n == PATH_BYTES;
                    }
                }
                (Err(_), k) => {
                    if let Some(k) = k {
                        k.met += 1;
                    }
                    h.update(b"\0EFAULT")
                }
            },
            Len::IovRet { .. } | Len::MsgIovRet => {
                let mut left = ret as u64;
                let (iov, n) = match b.len {
                    Len::IovRet { cnt } => (p, args[cnt as usize]),
                    _ => match (
                        crate::guest::get::<u64>(p + 16),
                        crate::guest::get::<u64>(p + 24),
                    ) {
                        (Ok(iov), Ok(n)) => (iov, n),
                        _ => {
                            h.update(b"\0EFAULT");
                            continue;
                        }
                    },
                };
                for i in 0..n.min(1024) {
                    if left == 0 {
                        break;
                    }
                    let Ok([base, len]) = crate::guest::get::<[u64; 2]>(iov + i * 16) else {
                        h.update(b"\0EFAULT");
                        break;
                    };
                    let n = len.min(left);
                    hash_guest(&mut h, base, n);
                    left -= n;
                }
            }
            // `refs` only (`proto::table::Row::ins` refuses them at compile time).
            Len::Mmsg { .. }
            | Len::Indirect { .. }
            | Len::FdSet { .. }
            | Len::SigPair
            | Len::XattrArgs { .. }
            | Len::Command
            | Len::Futex
            | Len::StrVec => {}
        }
    }
    h.finish()
}

/// Record a completed trap. The record holds the arguments as the guest passed them
/// (`Call::guest_args`), never a runtime buffer a handler substituted, and the hashes read
/// the guest's own memory.
pub fn trap(row: &Row, call: &dyn crate::trap::Call, ret: i64) {
    #[cfg(patina_nolog)]
    {
        let _ = (row, call, ret);
        return;
    }
    #[allow(unreachable_code)]
    let nr = call.nr();
    // Only the registers the call reads (`proto::table::nargs`): the others are zero here, in
    // the record and for the hashes (a pointer the call ignores names nothing).
    let args = &proto::table::nargs::used_args(nr, &call.guest_args());
    let c = ctl();
    if c.config.log_paths != 0 && row.group != proto::table::Group::Sdk {
        trap_paths(row, call, ret, args);
    } else {
        trap_plain(row, call, ret, args);
    }
    if c.config.observe != 0 {
        observe(row, nr, args, ret);
    }
}

/// `trap` without `log_paths`: the record, and an SDK call's strings.
fn trap_plain(row: &Row, call: &dyn crate::trap::Call, ret: i64, args: &[u64; 6]) {
    let nr = call.nr();
    let ts = crate::state::thread();
    let c = ctl();
    // Inputs are read only when the kernel did not report the pointer bad.
    let in_hash = if row.group == proto::table::Group::Sdk {
        crate::sys::sdk::take_hash()
    } else if ret == -e::EFAULT {
        0
    } else {
        hash_bufs(row.ins, args, ret.max(0))
    };
    let rec = Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::Trap as u8,
        class: ts.eff_class,
        nr: nr as u32,
        args: *args,
        ret,
        out_hash: hash_bufs(row.outs, args, ret),
        in_hash,
    };
    append(&rec);
    if row.group == proto::table::Group::Sdk {
        crate::sys::sdk::log_strings();
    }
}

/// `patina explain`'s observation (`Config::observe`) of a data call that moved bytes: after
/// its records, the first `OBS_BYTES` it moved, its descriptor, the descriptor's file type and,
/// for a socket on the wire, its connection and ends (`Rec::observed`). Read through the guest
/// copy from the buffer the call's hash just read (fault-safe, bounded; an unreadable buffer
/// keeps no bytes), so it reads nothing the record did not; a `fstat` of the descriptor and a
/// look at the wire's table change nothing the program can see. Appended without entering the
/// hash chain, exempt from the log limit, and only while the window has room for every record
/// the limit still allows: an observation never changes which record a run ends at.
#[inline(never)]
fn observe(row: &Row, nr: u64, args: &[u64; 6], ret: i64) {
    use proto::rec::{OBS_BYTES, OBS_RECS};
    if ret <= 0
        || !matches!(
            nr,
            nr::READ
                | nr::WRITE
                | nr::PREAD64
                | nr::PWRITE64
                | nr::READV
                | nr::WRITEV
                | nr::PREADV
                | nr::PWRITEV
                | nr::PREADV2
                | nr::PWRITEV2
                | nr::SENDTO
                | nr::SENDMSG
                | nr::RECVFROM
                | nr::RECVMSG
        )
    {
        return;
    }
    let c = ctl();
    // One observation, and slack for what a run's last trap and the supervisor write past the
    // limit (`Str` records of the call that reaches it, the end records).
    let room = OBS_RECS as u64 * REC_SIZE as u64 + OBS_SLACK;
    if c.log_len.load(Relaxed) + room + c.config.log_limit > proto::layout::LOG_MAX {
        return;
    }
    // The moved bytes: argument 1 of every data call, its input (a write) or output (a read).
    let Some(b) = row.ins.iter().chain(row.outs).find(|b| {
        b.arg == 1 && matches!(b.len, Len::Ret { .. } | Len::IovRet { .. } | Len::MsgIovRet)
    }) else {
        return;
    };
    let mut buf = [0u8; OBS_BYTES];
    let want = (ret as u64).min(OBS_BYTES as u64) as usize;
    let kept = head(b, args, want, &mut buf);
    let fd = args[0] as i64;
    let ftype = crate::sys::fs::fstat_raw(fd).map_or(0, |st| (st.mode() >> 12) as u64 & 0xf);
    let wire = crate::sys::inet::observed(fd).unwrap_or_default();
    let ts = crate::state::thread();
    let head = [args[0], ftype, wire[0], wire[1], wire[2], wire[3]];
    for r in Rec::observed(
        ts.seq,
        c.vclock_ns.load(Relaxed),
        ts.slot as u16,
        ts.pid as i64,
        head,
        &buf[..kept],
        ret as usize > kept,
    ) {
        append_unchained(&r);
    }
}

/// Up to `want` bytes of the buffer `b` describes into `out`, as the hash reads them; the bytes
/// copied (0 when the buffer cannot be read).
fn head(b: &Out, args: &[u64; 6], want: usize, out: &mut [u8]) -> usize {
    let p = args[b.arg as usize];
    let mut n = 0usize;
    let mut take = |base: u64, len: u64| -> bool {
        let k = (len as usize).min(want - n);
        if k == 0 {
            return true;
        }
        if crate::guest::read(base, &mut out[n..n + k]).is_err() {
            return false;
        }
        n += k;
        n < want
    };
    match b.len {
        // Not past the buffer the program gave (a datagram `recvfrom` with `MSG_TRUNC`
        // returns more than it holds).
        Len::Ret { max } => {
            take(p, (want as u64).min(args[max as usize]));
        }
        Len::IovRet { .. } | Len::MsgIovRet => {
            let (iov, cnt) = match b.len {
                Len::IovRet { cnt } => (p, args[cnt as usize]),
                _ => match (
                    crate::guest::get::<u64>(p + 16),
                    crate::guest::get::<u64>(p + 24),
                ) {
                    (Ok(iov), Ok(cnt)) => (iov, cnt),
                    _ => return 0,
                },
            };
            for i in 0..cnt.min(1024) {
                let Ok([base, len]) = crate::guest::get::<[u64; 2]>(iov + i * 16) else {
                    break;
                };
                if !take(base, len) {
                    break;
                }
            }
        }
        _ => {}
    }
    n
}

/// Room an observation leaves in the log's mapping beyond the log limit and itself.
const OBS_SLACK: u64 = 1 << 20;

/// Append a record outside the hash chain and the log limit (an observation).
fn append_unchained(rec: &Rec) {
    let c = ctl();
    let off = c.log_len.load(Relaxed);
    ensure(off + REC_SIZE as u64);
    unsafe {
        core::ptr::copy_nonoverlapping(
            rec.as_bytes().as_ptr(),
            (crate::state::log_base() + off) as *mut u8,
            REC_SIZE,
        );
    }
    c.log_len.store(off + REC_SIZE as u64, Relaxed);
    c.log_exempt.fetch_add(REC_SIZE as u64, Relaxed);
}

/// `trap` with `log_paths`: the record, then each C string the call read (as the hash read
/// it, once), the path each walked argument resolved to, and `execve`'s arguments.
#[inline(never)]
fn trap_paths(row: &Row, call: &dyn crate::trap::Call, ret: i64, args: &[u64; 6]) {
    use proto::rec::*;
    let ts = crate::state::thread();
    let c = ctl();
    let mut kept = Kept {
        s: [PathBuf::new(), PathBuf::new()],
        arg: [Paths::NONE; 2],
        cut: [false; 2],
        met: 0,
    };
    // Inputs are read only when the kernel did not report the pointer bad.
    let in_hash = if ret == -e::EFAULT {
        0
    } else {
        hash_keep(row.ins, args, ret.max(0), Some(&mut kept))
    };
    append(&Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::Trap as u8,
        class: ts.eff_class,
        nr: call.nr() as u32,
        args: *args,
        ret,
        out_hash: hash_bufs(row.outs, args, ret),
        in_hash,
    });
    if ret == -e::EFAULT {
        return;
    }
    let paths = call.paths_ref();
    for j in 0..2 {
        if kept.arg[j] == Paths::NONE {
            continue;
        }
        strs(STR_PATH + j as u8, kept.s[j].as_bytes(), kept.cut[j]);
        if let Some(r) = paths.logged(kept.arg[j] as usize) {
            strs(STR_RESOLVED + j as u8, r, false);
        }
    }
    let argv = match call.nr() {
        nr::EXECVE => args[1],
        nr::EXECVEAT => args[2],
        _ => return,
    };
    log_argv(argv);
}

/// `execve`'s arguments, each one string (at most `ARGV_MAX` of them, `ARGV_BYTES` in all,
/// `PATH_BYTES` each); `STR_ARGV_CUT` after them when some were left out. An argument that
/// cannot be read ends the list there.
fn log_argv(argv: u64) {
    use proto::rec::*;
    if argv == 0 {
        return;
    }
    let mut buf = PathBuf::new();
    let mut total = 0usize;
    for i in 0..=ARGV_MAX as u64 {
        let Ok(p) = crate::guest::get::<u64>(argv + 8 * i) else {
            return;
        };
        if p == 0 {
            return;
        }
        let Ok(n) = crate::guest::strlen(p, PATH_BYTES) else {
            return;
        };
        if i as usize == ARGV_MAX || total + n > ARGV_BYTES {
            strs(STR_ARGV_CUT, b"", false);
            return;
        }
        buf.n = 0;
        let ok = crate::guest::each(p, n as u64, |b| {
            buf.b[buf.n..buf.n + b.len()].copy_from_slice(b);
            buf.n += b.len();
        });
        if ok.is_err() {
            return;
        }
        strs(STR_ARGV, buf.as_bytes(), n == PATH_BYTES);
        total += n;
    }
}

/// Append the `Str` records of `s` after the current call's record (`proto::RecKind::Str`).
pub fn strs(which: u8, s: &[u8], cut: bool) {
    let ts = crate::state::thread();
    let vclock_ns = ctl().vclock_ns.load(Relaxed);
    for r in Rec::strs(
        ts.seq,
        vclock_ns,
        ts.slot as u16,
        ts.pid as i64,
        which,
        s,
        cut,
    ) {
        append(&r);
    }
}

/// Record an emulated instruction (`nr` is the instruction code).
pub fn insn(code: u32, rip: u64, val: u64) {
    let ts = crate::state::thread();
    let c = ctl();
    let rec = Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::InsnEmulation as u8,
        class: 0,
        nr: code,
        args: [rip, 0, 0, 0, 0, 0],
        ret: val as i64,
        out_hash: hash_bytes(0, &val.to_le_bytes()),
        in_hash: 0,
    };
    append(&rec);
}

/// Record a synchronous fault forwarded to the guest's disposition.
pub fn fault(sig: u64, info: &[u64; 16], rip: u64) {
    let ts = crate::state::thread();
    let c = ctl();
    let rec = Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::Fault as u8,
        class: 0,
        nr: sig as u32,
        args: [rip, info[1] & 0xffff_ffff, info[2], 0, 0, 0],
        ret: 0,
        out_hash: 0,
        in_hash: 0,
    };
    append(&rec);
}
