//! Boundary log: a shared file mapping at `LOG_ADDR`, appended under the turn.

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
        let r = unsafe { sc2(nr::FTRUNCATE, FD_LOG as u64, newcap) };
        if r < 0 {
            crate::sup::host_error(r, nr::FTRUNCATE, proto::ctl::HE_SYSCALL);
        }
        c.log_cap.store(newcap, Relaxed);
        cap = newcap;
    }
    let r = unsafe {
        sc6(
            nr::MMAP,
            LOG_ADDR + p.log_mapped,
            cap - p.log_mapped,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED_NOREPLACE,
            FD_LOG as u64,
            p.log_mapped,
        )
    };
    if r as u64 != LOG_ADDR + p.log_mapped {
        crate::sup::host_error(r, nr::MMAP, proto::ctl::HE_SYSCALL);
    }
    p.log_mapped = cap;
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
    let off = c.log_len.load(Relaxed);
    ensure(off + REC_SIZE as u64);
    unsafe {
        core::ptr::copy_nonoverlapping(
            rec.as_bytes().as_ptr(),
            (LOG_ADDR + off) as *mut u8,
            REC_SIZE,
        );
    }
    c.log_len.store(off + REC_SIZE as u64, Relaxed);
    c.log_hash
        .store(chain(c.log_hash.load(Relaxed), rec), Relaxed);
}

unsafe fn bytes<'a>(p: u64, n: u64) -> &'a [u8] {
    core::slice::from_raw_parts(p as *const u8, n as usize)
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
        unsafe {
            match b.len {
                Len::Ret => h.update(bytes(p, ret as u64)),
                Len::Arg(i) => h.update(bytes(p, args[i as usize])),
                Len::Fixed(n) => h.update(bytes(p, n as u64)),
                Len::RetTimes(n) => h.update(bytes(p, ret as u64 * n as u64)),
                Len::ArgTimes { arg, size } => h.update(bytes(p, args[arg as usize] * size as u64)),
                Len::CStr => {
                    let mut n = 0;
                    while n < 4096 && *((p + n) as *const u8) != 0 {
                        n += 1;
                    }
                    h.update(bytes(p, n));
                }
                Len::IovRet { .. } | Len::MsgIovRet => {
                    let mut left = ret as u64;
                    let (iov, n) = match b.len {
                        Len::IovRet { cnt } => (p as *const [u64; 2], args[cnt as usize]),
                        _ => (
                            *((p + 16) as *const u64) as *const [u64; 2],
                            *((p + 24) as *const u64),
                        ),
                    };
                    for i in 0..n.min(1024) {
                        if left == 0 {
                            break;
                        }
                        let [base, len] = *iov.add(i as usize);
                        let n = len.min(left);
                        h.update(bytes(base, n));
                        left -= n;
                    }
                }
            }
        }
    }
    h.finish()
}

/// Record a completed trap.
pub fn trap(row: &Row, nr: u64, args: &[u64; 6], ret: i64) {
    #[cfg(patina_nolog)]
    {
        let _ = (row, nr, args, ret);
        return;
    }
    #[allow(unreachable_code)]
    let ts = crate::state::thread();
    let c = ctl();
    // Inputs are read only when the kernel did not report the pointer bad.
    let in_hash = if ret == -e::EFAULT {
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
