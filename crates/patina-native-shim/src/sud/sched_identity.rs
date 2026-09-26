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
    let val3 = args[5] as u32;
    let op = futex_op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let private = futex_op & FUTEX_PRIVATE_FLAG != 0;
    if op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET {
        // FUTEX_WAIT: relative CLOCK_MONOTONIC. FUTEX_WAIT_BITSET: absolute,
        // CLOCK_REALTIME iff FUTEX_CLOCK_REALTIME — mirrors the C `syscall()` path.
        let absolute = op == FUTEX_WAIT_BITSET;
        let timeout_nanos = match (!timeout.is_null()).then(|| read_timespec_nanos(timeout)) {
            Some(Err(errno)) => return errno,
            Some(Ok(nanos)) => Some(nanos),
            None => None,
        };
        // FUTEX_WAIT waits by any bit, FUTEX_WAIT_BITSET by `val3`: an empty
        // bitset is EINVAL once the timeout is read (`__futex_wait`).
        let bitset = if absolute { val3 } else { u32::MAX };
        if bitset == 0 {
            return -EINVAL;
        }
        let Some(timeout_nanos) = timeout_nanos else {
            // No dereference of `uaddr` here; the runtime treats it as a key.
            return ret_i32(crate::thread::futex_wait(uaddr, val, private, bitset));
        };
        let clock = if absolute && futex_op & FUTEX_CLOCK_REALTIME != 0 {
            PATINA_CLOCK_REALTIME
        } else {
            PATINA_CLOCK_MONOTONIC
        };
        // `uaddr` is treated as a key by the runtime.
        return ret_i32(crate::thread::futex_wait_timed(
            uaddr,
            val,
            clock,
            absolute as c_int,
            timeout_nanos,
            private,
            bitset,
        ));
    }
    if op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET {
        let bitset = if op == FUTEX_WAKE { u32::MAX } else { val3 };
        return crate::thread::futex2::multiplexed_wake(uaddr, private, val as i32, bitset);
    }
    if op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE {
        // The timeout argument carries the requeue count (`val2`).
        let cmpval = (op == FUTEX_CMP_REQUEUE).then_some(val3);
        let counts = (val as i32, args[3] as u32 as i32);
        return crate::thread::futex2::multiplexed_requeue(
            uaddr,
            args[4] as usize,
            private,
            counts,
            cmpval,
        );
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
