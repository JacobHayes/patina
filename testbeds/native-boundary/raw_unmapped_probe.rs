use std::arch::asm;
fn main() {
    #[cfg(target_arch = "x86_64")]
    let nr: i64 = 169; // reboot
    #[cfg(target_arch = "aarch64")]
    let nr: i64 = 142; // reboot
    let ret: i64;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("syscall", inlateout("rax") nr => ret, in("rdi") 0, in("rsi") 0, in("rdx") 0, in("r10") 0, out("rcx") _, out("r11") _, options(nostack));
        #[cfg(target_arch = "aarch64")]
        asm!("svc #0", in("x8") nr, inlateout("x0") 0i64 => ret, in("x1") 0, in("x2") 0, in("x3") 0, options(nostack));
    }
    println!("UNMAPPED_RET={ret}"); // unreachable: dispatch aborts before returning
}
