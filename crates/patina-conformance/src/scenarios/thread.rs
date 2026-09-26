pub mod cond;
pub mod exit;
pub mod futex;
pub mod futex2;
pub mod lifecycle;
pub mod main_exit;
pub mod mutex;
pub mod pthread_kill;
pub mod robust_list;
pub mod rseq;
pub mod rwlock;
pub mod tid_clear;
#[cfg(target_arch = "x86_64")]
pub mod tls;
#[cfg(target_arch = "x86_64")]
pub mod tls_cpu;

/// The thread pointer glibc installed for the calling thread (x86_64: the
/// TCB's self pointer at `%fs:0`; aarch64: `tpidr_el0`).
pub(crate) fn thread_pointer() -> usize {
    let tp: usize;
    // SAFETY: reads the thread pointer (a load through the FS base glibc
    // installed, or a system register read).
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!("mov {}, fs:0", out(reg) tp, options(nostack, readonly));
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nostack, nomem));
    }
    tp
}
