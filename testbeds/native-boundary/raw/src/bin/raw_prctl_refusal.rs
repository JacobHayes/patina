// Class pairing: signals process-state prctl option validation.
use std::arch::asm;
fn main() {
    let option = match std::env::args().nth(1).as_deref() {
        Some("unsupported") => u32::MAX as i64,
        Some("privileged") => 22, // PR_SET_SECCOMP must never reach the host.
        _ => panic!("expected unsupported or privileged"),
    };
    let result: i64;
    unsafe {
        asm!("syscall", inlateout("rax") 157i64 => result, in("rdi") option,
        in("rsi") 1i64, in("rdx") 0i64, in("r10") 0i64, in("r8") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    assert_eq!(result, -22, "unmodeled prctl must refuse with EINVAL");
    println!("PRCTL_REFUSED errno=22");
}
