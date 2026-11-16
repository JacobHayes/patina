//! Randomness, credentials and identity, system information.

use super::*;
use crate::state::config;
use proto::{fill, Stream};

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
    unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), p as *mut u8, 112) };
    0
}

/// struct rusage (144 bytes): user time is the thread's trap charges, everything else 0.
fn getrusage(call: &mut dyn Call) -> i64 {
    let (who, p) = (call.arg(0) as i32, call.arg(1));
    if !matches!(who, -1..=1) {
        return -e::EINVAL;
    }
    if p == 0 {
        return -e::EFAULT;
    }
    let ns = if who == -1 {
        0
    } else {
        call.thread().traps * config().trap_charge_ns
    };
    let mut w = [0u64; 18];
    w[0] = ns / NS;
    w[1] = ns % NS / 1000;
    unsafe { core::ptr::copy_nonoverlapping(w.as_ptr() as *const u8, p as *mut u8, 144) };
    0
}

pub fn handle(call: &mut dyn Call) -> Action {
    let r = match call.nr() {
        318 => {
            let (buf, len) = (call.arg(0), call.arg(1));
            if buf == 0 && len != 0 {
                return Action::Return(-e::EFAULT);
            }
            let seq = call.thread().seq;
            let s = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };
            fill(config().seed, Stream::Entropy, seq, s);
            len as i64
        }
        99 => sysinfo(call.arg(0)),
        98 => getrusage(call),
        // get_mempolicy: the default policy, no nodes.
        239 => {
            let (mode, mask, maxnode) = (call.arg(0), call.arg(1), call.arg(2));
            if mode != 0 {
                unsafe { *(mode as *mut i32) = 0 };
            }
            if mask != 0 && maxnode != 0 {
                let bytes = maxnode.div_ceil(64) * 8;
                unsafe { core::ptr::write_bytes(mask as *mut u8, 0, bytes as usize) };
            }
            0
        }
        // Supplementary groups: the launcher's are inherited and cannot be dropped
        // without a capability (unmapped ones read as the overflow id, so their number shows).
        // The guest's list is the namespace's primary group alone.
        115 => {
            let (size, list) = (call.arg(0) as i32, call.arg(1));
            if size < 0 {
                -e::EINVAL
            } else if size == 0 {
                1
            } else {
                let gid = unsafe { crate::raw::sc0(104) } as u32;
                match put(list, gid) {
                    Ok(()) => 1,
                    Err(r) => r,
                }
            }
        }
        // Credentials and identity: confined by the user and UTS namespaces.
        105 | 106 | 113 | 114 | 116..=120 | 122 | 123 | 125 | 126 | 170 | 171 => {
            let r = raw(call);
            host_check(call, r);
            r
        }
        _ => return stop_here(call),
    };
    Action::Return(r)
}
