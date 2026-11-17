//! Boundary log: a shared file mapping at `state::log_base`, appended under the turn.

use crate::raw::*;
use crate::state::{ctl, proc};
use core::sync::atomic::Ordering::*;
use proto::layout::*;
use proto::rec::{chain, hash_bytes, Hasher, Rec, REC_SIZE};
use proto::table::{Len, Out, Row};

fn ensure(len: u64) {
    let c = ctl();
    let p = proc();
    if len <= p.log_mapped {
        return;
    }
    let mut cap = c.log_cap.load(Relaxed);
    if len > cap {
        let newcap = cap + LOG_STEP;
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

/// Hash the guest buffers described by `bufs` (output side: after the call).
pub fn hash_bufs(bufs: &[Out], args: &[u64; 6], ret: i64) -> u64 {
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
            Len::ArgTimes { arg, size } => hash_guest(&mut h, p, args[arg as usize] * size as u64),
            Len::CStr => match crate::guest::strlen(p, 4096) {
                Ok(n) => hash_guest(&mut h, p, n as u64),
                Err(_) => h.update(b"\0EFAULT"),
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
            | Len::Fcntl
            | Len::Ioctl
            | Len::Prctl
            | Len::ArchPrctl
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
    let args = &call.guest_args();
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
        // Only the registers the call reads (`proto::table::nargs`).
        args: proto::table::nargs::used_args(nr, args),
        ret,
        out_hash: hash_bufs(row.outs, args, ret),
        in_hash,
    };
    append(&rec);
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
