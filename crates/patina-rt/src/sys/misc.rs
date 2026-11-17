//! Randomness, credentials and identity, system information.

use super::*;
use crate::state::config;
use proto::{fill_from, Stream};

const NS: u64 = 1_000_000_000;

/// struct sysinfo (112 bytes): constants, the virtual uptime, the configured memory.
fn sysinfo(p: u64) -> i64 {
    if p == 0 {
        return -e::EFAULT;
    }
    let mut b = [0u8; 112];
    let up = ctl().vclock_ns.load(Relaxed) / NS;
    b[0..8].copy_from_slice(&up.to_le_bytes());
    b[32..40].copy_from_slice(&(16u64 << 30).to_le_bytes()); // totalram
    b[40..48].copy_from_slice(&(12u64 << 30).to_le_bytes()); // freeram
    b[80..82].copy_from_slice(&1u16.to_le_bytes()); // procs
    b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
    crate::guest::write(p, &b).err().unwrap_or(0)
}

/// struct rusage (144 bytes): user time is the thread's CPU time (`ThreadState::cpu_ns`), everything else 0.
fn getrusage(call: &mut dyn Call) -> i64 {
    let (who, p) = (call.arg(0) as i32, call.arg(1));
    if !matches!(who, -1..=1) {
        return -e::EINVAL;
    }
    if p == 0 {
        return -e::EFAULT;
    }
    let ns = if who == -1 { 0 } else { call.thread().cpu_ns() };
    let mut w = [0u64; 18];
    w[0] = ns / NS;
    w[1] = ns % NS / 1000;
    crate::guest::put(p, w).err().unwrap_or(0)
}

/// Write `len` bytes of the entropy stream for draw `seq` to guest memory at `buf`: `len`,
/// the bytes written before a fault, or `-EFAULT`.
pub fn write_entropy(seq: u64, buf: u64, len: u64) -> i64 {
    let mut off = 0u64;
    let mut chunk = [0u8; 512];
    while off < len {
        let k = (len - off).min(chunk.len() as u64) as usize;
        fill_from(
            config().seed,
            Stream::Entropy,
            seq,
            off / 8,
            &mut chunk[..k],
        );
        if let Err(e) = crate::guest::write(buf + off, &chunk[..k]) {
            return if off == 0 { e } else { off as i64 };
        }
        off += k as u64;
    }
    len as i64
}

pub fn handle(call: &mut dyn Call) -> Action {
    let r = match call.nr() {
        nr::GETRANDOM => {
            let (buf, len) = (call.arg(0), call.arg(1));
            if buf == 0 && len != 0 {
                return Action::Return(-e::EFAULT);
            }
            write_entropy(call.thread().seq, buf, len)
        }
        nr::SYSINFO => sysinfo(call.arg(0)),
        nr::GETRUSAGE => getrusage(call),
        // get_mempolicy: the default policy, no nodes.
        nr::GET_MEMPOLICY => {
            let (mode, mask, maxnode) = (call.arg(0), call.arg(1), call.arg(2));
            let r = if mode != 0 { put(mode, 0i32) } else { Ok(()) };
            let r = r.and_then(|()| {
                if mask != 0 && maxnode != 0 {
                    crate::guest::zero(mask, (maxnode.div_ceil(64) * 8) as usize)
                } else {
                    Ok(())
                }
            });
            r.err().unwrap_or(0)
        }
        // Supplementary groups: the launcher's are inherited and cannot be dropped
        // without a capability (unmapped ones read as the overflow id, so their number shows).
        // The guest's list is the namespace's primary group alone.
        nr::GETGROUPS => {
            let (size, list) = (call.arg(0) as i32, call.arg(1));
            if size < 0 {
                -e::EINVAL
            } else if size == 0 {
                1
            } else {
                let gid = unsafe { crate::raw::sc0(nr::GETGID) } as u32;
                match put(list, gid) {
                    Ok(()) => 1,
                    Err(r) => r,
                }
            }
        }
        // Credentials and identity: confined by the user and UTS namespaces.
        nr::SETUID
        | nr::SETGID
        | nr::SETREUID
        | nr::SETREGID
        | nr::SETGROUPS
        | nr::SETRESUID
        | nr::GETRESUID
        | nr::SETRESGID
        | nr::GETRESGID
        | nr::SETFSUID
        | nr::SETFSGID
        | nr::CAPGET
        | nr::CAPSET
        | nr::SETHOSTNAME
        | nr::SETDOMAINNAME => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        _ => return stop_here(call),
    };
    Action::Return(r)
}
