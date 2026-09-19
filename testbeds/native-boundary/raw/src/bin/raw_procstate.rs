use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0,
        out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn main() {
    let pid = unsafe { sc(39, 0) };
    let uid = unsafe { sc(102, 0) };
    let mut utsname = [0u8; 390];
    let uname_rc = unsafe { sc(63, utsname.as_mut_ptr() as i64) };
    assert_eq!(pid, 1, "getpid");
    assert_eq!(uid, 1000, "getuid");
    assert_eq!(uname_rc, -i64::from(libc::ENOSYS), "uname");
    println!("RAW_PROCSTATE pid={pid} uid={uid} uname_rc={uname_rc}");
}
