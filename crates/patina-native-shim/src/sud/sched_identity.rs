//! SUD rows — scheduling and per-run identity: `futex` (the scheduler park/wake
//! the libc `syscall(2)` interposer also decodes) and `getrandom` (the seeded
//! entropy source). The constant identity rows (`getpid`, uids, `gettid`,
//! `sched_yield`) are answered inline by the dispatcher.

use super::*;

pub(super) fn sys_futex(args: [u64; 6]) -> i64 {
    let uaddr = args[0] as usize;
    let futex_op = args[1];
    let val = args[2] as u32;
    let timeout = args[3] as *const Timespec;
    let op = futex_op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET {
        if timeout.is_null() {
            // SAFETY: no dereference of `uaddr` here; the runtime treats it as a key.
            return ret_i32(unsafe { patina_futex_wait(uaddr, val) });
        }
        // FUTEX_WAIT: relative CLOCK_MONOTONIC. FUTEX_WAIT_BITSET: absolute,
        // CLOCK_REALTIME iff FUTEX_CLOCK_REALTIME — mirrors the C `syscall()` path.
        let absolute = op == FUTEX_WAIT_BITSET;
        let clock = if absolute && futex_op & FUTEX_CLOCK_REALTIME != 0 {
            PATINA_CLOCK_REALTIME
        } else {
            PATINA_CLOCK_MONOTONIC
        };
        let timeout_nanos = match read_timespec_nanos(timeout) {
            Ok(nanos) => nanos,
            Err(errno) => return errno,
        };
        // SAFETY: `uaddr` is treated as a key by the runtime.
        return ret_i32(unsafe {
            patina_futex_wait_timed(uaddr, val, clock, absolute as c_int, timeout_nanos)
        });
    }
    if op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET {
        // SAFETY: `uaddr` is a key; `val` is the wake count.
        return ret_i32(unsafe { patina_futex_wake(uaddr, val as c_int) });
    }
    -ENOSYS
}

pub(super) fn sys_getrandom(buf: u64, len: u64, flags: u64) -> i64 {
    // SAFETY: `buf`/`len` describe a guest buffer.
    let count = unsafe { patina_getrandom(buf as *mut c_void, len as usize, flags as u32) };
    if count < 0 {
        // SAFETY: plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        count as i64
    }
}
