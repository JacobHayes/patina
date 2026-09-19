use std::arch::asm;
use std::os::fd::AsRawFd;
fn main() {
    let f = std::fs::File::create("/fcntl-parity.txt").expect("create");
    let fd = f.as_raw_fd();
    const FCNTL: i64 = 72;
    const F_GETFL: i64 = 3;
    let raw: i64;
    unsafe {
        asm!("syscall", inlateout("rax") FCNTL => raw, in("rdi") fd as i64,
        in("rsi") F_GETFL, in("rdx") 0i64, in("r10") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    assert_eq!(
        raw, 0o100001,
        "raw fcntl(F_GETFL) must be O_WRONLY|O_LARGEFILE, got {raw}"
    );
    unsafe extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    let lib = unsafe { fcntl(fd, 3) };
    assert_eq!(
        lib as i64, raw,
        "libc fcntl(F_GETFL) must agree with the raw syscall, got {lib}"
    );
    println!("FCNTL_PARITY raw={raw} libc={lib}");
}
