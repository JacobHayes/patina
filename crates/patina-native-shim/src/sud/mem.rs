//! SUD rows — memory: the mapping, protection, locking and limit rows route
//! into the one memory model (`crate::mem`, the same `patina_*` entries the C
//! interposers call); the rows that only advise or ask about the residency of
//! process-local memory pass through to the host kernel via the glibc
//! `syscall(2)` host alias (never the interposed `syscall`).

use super::*;

pub(super) fn sys_mmap(args: [u64; 6]) -> i64 {
    // SAFETY: the model validates every argument the kernel would.
    unsafe {
        patina_mmap(
            args[0] as usize,
            args[1] as usize,
            args[2] as c_int,
            args[3] as c_int,
            arg_fd(args[4]) as c_int,
            args[5] as i64,
        )
    }
}

pub(super) fn sys_munmap(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe { patina_munmap(args[0] as usize, args[1] as usize) }
}

pub(super) fn sys_mremap(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe {
        patina_mremap(
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
        )
    }
}

pub(super) fn sys_msync(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe { patina_msync(args[0] as usize, args[1] as usize, args[2] as c_int) }
}

pub(super) fn sys_mprotect(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe { patina_mprotect(args[0] as usize, args[1] as usize, args[2] as c_int) }
}

/// `getrlimit(2)`: the limit (`EINVAL` for an unknown resource first), then
/// its copy out (`EFAULT`).
pub(super) fn sys_getrlimit(resource: u64, out: u64) -> i64 {
    let mut limit = crate::limits::Rlimit { cur: 0, max: 0 };
    // SAFETY: a local out-buffer.
    let result = unsafe { patina_prlimit(0, resource as u32, std::ptr::null(), &mut limit) };
    if result != 0 {
        return result;
    }
    if out == 0 {
        return -EFAULT;
    }
    // SAFETY: the guest's `struct rlimit`, non-null.
    unsafe { (out as *mut crate::limits::Rlimit).write_unaligned(limit) };
    0
}

/// `setrlimit(2)`: the new limit is copied in first (`EFAULT`).
pub(super) fn sys_setrlimit(resource: u64, new: u64) -> i64 {
    if new == 0 {
        return -EFAULT;
    }
    // SAFETY: the guest's `struct rlimit`, non-null.
    unsafe { patina_prlimit(0, resource as u32, new as *const _, std::ptr::null_mut()) }
}

/// Pass a process-local memory syscall through to the host kernel via the glibc
/// `syscall(2)` vehicle, in the raw ABI.
pub(super) fn mem_passthrough(nr: i64, args: [u64; 6]) -> i64 {
    crate::mem::host_number(nr, args.map(|arg| arg as usize))
}
