// The answers patina gives for the facilities it does not model, as far as
// libraries probe them: the Landlock ABI version, seccomp action
// availability, no seccomp mode, a controlling-terminal-less /dev/tty, the
// stdio ioctl refusal, and the one-node memory policy.
use std::arch::asm;

unsafe fn sc(nr: i64, a: [i64; 6]) -> i64 {
    let result: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => result, in("rdi") a[0],
        in("rsi") a[1], in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5],
        out("rcx") _, out("r11") _, options(nostack));
    }
    result
}

const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ENXIO: i64 = 6;
const EOPNOTSUPP: i64 = 95;

fn main() {
    let landlock = unsafe { sc(444, [0, 0, 1, 0, 0, 0]) };
    let allow = 0x7fff_0000u32;
    let unknown = 0x1234_0000u32;
    let action = |op: i64, flags: i64, action: &u32| unsafe {
        sc(317, [op, flags, action as *const u32 as i64, 0, 0, 0])
    };
    let allow_avail = action(2, 0, &allow);
    let unknown_avail = action(2, 0, &unknown);
    let flagged = action(2, 1, &allow);
    let bad_op = action(99, 0, &allow);
    let pr_seccomp = unsafe { sc(157, [21, 0, 0, 0, 0, 0]) };
    let tty = unsafe { sc(257, [-100, c"/dev/tty".as_ptr() as i64, 2, 0, 0, 0]) };
    // TCGETS on the standard input, which is a pipe or file, never a terminal.
    let mut termios = [0u8; 64];
    let tcgets = unsafe { sc(16, [0, 0x5401, termios.as_mut_ptr() as i64, 0, 0, 0]) };
    // get_mempolicy(&mode, NULL, 0, NULL, 0): the default policy.
    let mut mode = -1i32;
    let policy = unsafe { sc(239, [&mut mode as *mut i32 as i64, 0, 0, 0, 0, 0]) };
    // set_mempolicy(MPOL_BIND, node 1): another node is invalid.
    let other = 2u64;
    let bind_other = unsafe { sc(238, [2, &other as *const u64 as i64, 64, 0, 0, 0]) };
    let node0 = 1u64;
    let bind_node0 = unsafe { sc(238, [2, &node0 as *const u64 as i64, 64, 0, 0, 0]) };
    assert_eq!(landlock, 4, "landlock abi");
    assert_eq!(allow_avail, 0, "seccomp allow");
    assert_eq!(unknown_avail, -EOPNOTSUPP, "seccomp unknown action");
    assert_eq!(flagged, -EINVAL, "seccomp flag");
    assert_eq!(bad_op, -EINVAL, "seccomp operation");
    assert_eq!(pr_seccomp, 0, "PR_GET_SECCOMP");
    assert_eq!(tty, -ENXIO, "/dev/tty");
    assert_eq!(tcgets, -ENOTTY, "TCGETS on stdin");
    assert_eq!((policy, mode), (0, 0), "get_mempolicy");
    assert_eq!(bind_other, -EINVAL, "set_mempolicy other node");
    assert_eq!(bind_node0, 0, "set_mempolicy node 0");
    // The policy set is the policy read back, mode and node mask.
    let mut set_mode = -1i32;
    let mut set_mask = 0u64;
    let reread = unsafe {
        sc(
            239,
            [&mut set_mode as *mut i32 as i64, &mut set_mask as *mut u64 as i64, 64, 0, 0, 0],
        )
    };
    assert_eq!((reread, set_mode, set_mask), (0, 2, 1), "get_mempolicy after set");
    println!("RAW_PROBES landlock+seccomp+prctl+tty+stdio+mempolicy ok");
}
