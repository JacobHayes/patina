// The allocator (`allocator.rs`) that also asks through the raw `getcpu`
// instruction: a direct-syscall site, which runs where syscall-user-dispatch
// traps it.
#[path = "../allocator.rs"]
mod allocator;

/// The CPU through the raw `getcpu` instruction.
fn raw_cpu() -> Option<i64> {
    Some(raw::getcpu())
}

fn main() {
    allocator::main();
}

#[cfg(target_arch = "x86_64")]
mod raw {
    /// The CPU through the raw `getcpu` instruction.
    pub fn getcpu() -> i64 {
        let mut cpu: u32 = u32::MAX;
        let ret: i64;
        unsafe {
            std::arch::asm!("syscall", inlateout("rax") 309i64 => ret,
                 in("rdi") &mut cpu as *mut u32, in("rsi") 0usize, in("rdx") 0usize,
                 out("rcx") _, out("r11") _, options(nostack));
        }
        if ret == 0 { i64::from(cpu) } else { ret }
    }
}

#[cfg(target_arch = "aarch64")]
mod raw {
    /// The CPU through the raw `getcpu` instruction.
    pub fn getcpu() -> i64 {
        let mut cpu: u32 = u32::MAX;
        let ret: i64;
        unsafe {
            std::arch::asm!("svc #0", in("x8") 168i64,
                 inlateout("x0") &mut cpu as *mut u32 as i64 => ret,
                 in("x1") 0usize, in("x2") 0usize, options(nostack));
        }
        if ret == 0 { i64::from(cpu) } else { ret }
    }
}
