//! Raw system calls. The runtime has exactly one system-call instruction, in `patina_syscall`
//! (`arch`), and the seccomp filter lets through only that one (`entry::install_filter`); one
//! anywhere else, the runtime's text included, traps.
//!
//! The stub checks after the call that it runs on a runtime stack (every runtime stack is in
//! the runtime's region: the alternate stacks, and the start-up stack in `.bss`). Program code
//! that jumps to the instruction runs on its own stack, so the call reaches the kernel once,
//! then the stub stops at an undefined instruction before any program code sees the result,
//! and the fault entry ends the run (`fault::on_fault`, `CONTAIN_STUB`). A program that sets
//! its stack pointer into the runtime's region first is not stopped: that is deliberate, and
//! out of scope.

pub use crate::arch::{sc6, stub_escape, stub_ip};

#[inline(always)]
pub unsafe fn sc0(n: u64) -> i64 {
    sc6(n, 0, 0, 0, 0, 0, 0)
}
#[inline(always)]
pub unsafe fn sc1(n: u64, a: u64) -> i64 {
    sc6(n, a, 0, 0, 0, 0, 0)
}
#[inline(always)]
pub unsafe fn sc2(n: u64, a: u64, b: u64) -> i64 {
    sc6(n, a, b, 0, 0, 0, 0)
}
#[inline(always)]
pub unsafe fn sc3(n: u64, a: u64, b: u64, c: u64) -> i64 {
    sc6(n, a, b, c, 0, 0, 0)
}
#[inline(always)]
pub unsafe fn sc4(n: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    sc6(n, a, b, c, d, 0, 0)
}

pub use proto::nr;

#[allow(dead_code)]
pub mod e {
    pub const EPERM: i64 = 1;
    pub const ENOENT: i64 = 2;
    pub const EIO: i64 = 5;
    pub const EBADF: i64 = 9;
    pub const ENOMEM: i64 = 12;
    pub const EFAULT: i64 = 14;
    pub const EEXIST: i64 = 17;
    pub const EINVAL: i64 = 22;
    pub const ENOTTY: i64 = 25;
    pub const ENOSYS: i64 = 38;
    pub const ENXIO: i64 = 6;
    pub const EAGAIN: i64 = 11;
    pub const EACCES: i64 = 13;
    pub const ENOTDIR: i64 = 20;
    pub const EOPNOTSUPP: i64 = 95;
    pub const ETIMEDOUT: i64 = 110;
    pub const EINTR: i64 = 4;
    pub const ESRCH: i64 = 3;
    pub const E2BIG: i64 = 7;
    pub const ENOEXEC: i64 = 8;
    pub const EISDIR: i64 = 21;
    pub const ENAMETOOLONG: i64 = 36;
    pub const ELOOP: i64 = 40;
    pub const EFBIG: i64 = 27;
    pub const ENOSPC: i64 = 28;
    pub const EDQUOT: i64 = 122;
}

pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_NORESERVE: u64 = 0x4000;
pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

pub fn write_all(fd: u64, s: &[u8]) {
    let mut off = 0;
    while off < s.len() {
        let r = unsafe {
            sc3(
                nr::WRITE,
                fd,
                s.as_ptr() as u64 + off as u64,
                (s.len() - off) as u64,
            )
        };
        if r <= 0 {
            return;
        }
        off += r as usize;
    }
}

pub unsafe fn futex_wait(addr: *const u32, val: u32) -> i64 {
    // FUTEX_WAIT (shared: the word lives in a memfd mapped by several processes)
    sc4(nr::FUTEX, addr as u64, 0, val as u64, 0)
}

pub unsafe fn futex_wake(addr: *const u32, n: u32) -> i64 {
    sc3(nr::FUTEX, addr as u64, 1, n as u64)
}
