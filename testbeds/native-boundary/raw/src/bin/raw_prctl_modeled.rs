// Class pairing: signals-family prctl process-state tests, through inline SUD.
use std::arch::asm;
fn main() {
    let name = b"patina\0";
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") 157i64 => r, in("rdi") 15i64,
        in("rsi") name.as_ptr() as i64, in("rdx") 0i64, in("r10") 0i64, in("r8") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    assert_eq!(r, 0);
    println!("PR_SET_NAME_RET={r}");
}
