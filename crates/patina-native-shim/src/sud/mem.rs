//! SUD rows — process-local memory: anonymous `mmap` and the `munmap`/
//! `mprotect`/`madvise`/`mremap`/`brk` pass-through to the host kernel via the
//! glibc `syscall(2)` host alias (never the interposed `syscall`).

use super::*;

pub(super) fn sys_mmap(nr: i64, args: [u64; 6]) -> i64 {
    let flags = args[3];
    let fd = args[4] as i64;
    if flags & MAP_ANONYMOUS == 0 || fd != -1 {
        crate::trap_fatal(
            "SUD trapped a file-backed mmap: mapping a descriptor into memory bypasses the \
             deterministic filesystem. Only MAP_ANONYMOUS mappings (fd == -1) are process-local \
             and passed through",
        );
    }
    mem_passthrough(nr, args)
}

/// Pass a process-local memory syscall through to the host kernel via the glibc
/// `syscall(2)` vehicle. The wrapper returns `-1` and sets `errno` on failure;
/// reshape that into the raw `-errno` the syscall return register carries.
pub(super) fn mem_passthrough(nr: i64, args: [u64; 6]) -> i64 {
    // SAFETY: process-local memory management; the arguments are the guest's own
    // and the vehicle is glibc's `syscall` wrapper resolved as a host alias.
    let result = unsafe {
        crate::sud_host_syscall(
            nr as c_long,
            args[0] as c_long,
            args[1] as c_long,
            args[2] as c_long,
            args[3] as c_long,
            args[4] as c_long,
            args[5] as c_long,
        )
    };
    if result == -1 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .map(|e| e as i64)
            .unwrap_or(EIO);
        -errno
    } else {
        result as i64
    }
}
