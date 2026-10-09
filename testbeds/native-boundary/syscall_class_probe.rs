// syscall(2) of an identity query or of a system call that enters the
// kernel, 10 000 times: under Patina the first is charged as the identity
// query it is (user time only), as its trapped raw instruction is, and the
// second as a system call. The argument names which.
use std::ffi::c_long;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

#[cfg(target_arch = "x86_64")]
const NUMBERS: [(&str, c_long); 2] = [("getpid", 39), ("getuid", 102)];
#[cfg(target_arch = "aarch64")]
const NUMBERS: [(&str, c_long); 2] = [("getpid", 172), ("getuid", 174)];

fn main() {
    let which = std::env::args().nth(1).unwrap();
    let (_, number) = NUMBERS.into_iter().find(|(name, _)| *name == which).unwrap();
    for _ in 0..10_000 {
        // SAFETY: neither call takes an argument.
        std::hint::black_box(unsafe { syscall(number) });
    }
    println!("NATIVE_SYSCALL_CLASS_RESULT done={which}");
}
