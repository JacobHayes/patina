// The seccomp strict mode patina stops at by name, through prctl and
// seccomp(2). Class pairing: proc/seccomp, which never enters strict mode.
use std::arch::asm;
fn main() {
    // (syscall number, three arguments)
    let (nr, a1, a2, a3): (i64, i64, i64, i64) = match std::env::args().nth(1).as_deref() {
        // PR_SET_SECCOMP, SECCOMP_MODE_STRICT and a filter strict mode ignores.
        Some("prctl-strict") => (157, 22, 1, 1),
        // seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL).
        Some("seccomp-strict") => (317, 0, 0, 0),
        _ => panic!("expected prctl-strict or seccomp-strict"),
    };
    let result: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => result, in("rdi") a1,
        in("rsi") a2, in("rdx") a3, in("r10") 0i64, in("r8") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    panic!("the strict-mode request returned {result}");
}
