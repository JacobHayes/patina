// The raw calls patina stops at by name: a seccomp mode (through prctl and
// seccomp(2)), the sandboxing and privileged rows the registry traps, and the
// pseudoterminal multiplexer. Class pairing: raw_probes, which holds the
// answers of the same facilities that do not stop.
use std::arch::asm;

unsafe fn sc(nr: i64, a: [i64; 4]) -> i64 {
    let result: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => result, in("rdi") a[0],
        in("rsi") a[1], in("rdx") a[2], in("r10") a[3], in("r8") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    result
}

fn main() {
    let door = std::env::args().nth(1).unwrap_or_default();
    let ptmx = c"/dev/ptmx";
    // PR_SET_SECCOMP, SECCOMP_MODE_STRICT and a filter strict mode ignores.
    let (nr, a) = match door.as_str() {
        "prctl-strict" => (157, [22, 1, 1, 0]),
        // seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL).
        "seccomp-strict" => (317, [0, 0, 0, 0]),
        // landlock_create_ruleset(NULL, 0, 0): building a ruleset.
        "landlock-ruleset" => (444, [0, 0, 0, 0]),
        "ptrace" => (101, [0, 0, 0, 0]),
        "mount" => (165, [0, 0, 0, 0]),
        "bpf" => (321, [0, 0, 0, 0]),
        "perf-event-open" => (298, [0, 0, 0, 0]),
        "userfaultfd" => (323, [0, 0, 0, 0]),
        "unshare" => (272, [0, 0, 0, 0]),
        "mq-open" => (240, [0, 0, 0, 0]),
        // openat(AT_FDCWD, "/dev/ptmx", O_RDWR).
        "ptmx" => (257, [-100, ptmx.as_ptr() as i64, 2, 0]),
        _ => panic!("unknown door {door}"),
    };
    let result = unsafe { sc(nr, a) };
    panic!("{door} returned {result}");
}
