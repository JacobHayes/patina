//! thread/tls — the x86_64 thread-area and segment rows a 64-bit task
//! reaches (arch/x86/kernel/process_64.c `do_arch_prctl_64`,
//! arch/x86/kernel/ldt.c `sys_modify_ldt`), as 6.8 answers them:
//!
//! * `set_thread_area` and `get_thread_area` are 32-bit rows: the 64-bit
//!   table lists their numbers without an entry point, so they answer
//!   `ENOSYS`;
//! * `arch_prctl(ARCH_GET_FS)` reports the thread pointer glibc installed
//!   (the TCB's self pointer at `%fs:0`), and setting it to itself answers
//!   0 and changes nothing; `ARCH_GET_GS` reports no GS base; CPUID does
//!   not fault (`ARCH_GET_CPUID` 1); an unknown code is `EINVAL` and a NULL
//!   out-pointer `EFAULT`. The shadow-stack codes answer what they answer
//!   with no feature enabled, whatever the CPU (arch/x86/kernel/shstk.c
//!   `shstk_prctl`): the status reports no feature, two features at once or
//!   none are `EINVAL`, a lock answers 0, and then a locked feature is
//!   `EPERM` before anything else (enabling or disabling one is the CPU's
//!   answer, which patina's unit tests pin). The answers that are the CPU's
//!   as much as the kernel's (a base past the user address space, setting
//!   the CPUID mode) are `thread/tls_cpu`'s, which needs the virtual
//!   machine's CPU;
//! * `modify_ldt` returns an `int` in a zero-extended register (the kernel
//!   casts its result to `unsigned int`), so its errors reach the caller as
//!   positive values, not `-errno`: an unknown function is `ENOSYS` so
//!   encoded, a write of the wrong size `EINVAL`. Reading a task's LDT
//!   before it has one answers 0 bytes; reading the default LDT zeroes and
//!   answers at most 128 bytes (a 64-bit kernel's size for it); writing an
//!   empty entry gives the task an LDT, which a read then answers in full,
//!   zero-filling what lies past its one zeroed entry.
//!
//! The libc vehicle goes through glibc's `arch_prctl` and `modify_ldt`
//! (`modify_ldt`'s `int` widened as the register holds it) and `syscall(2)`
//! for the thread-area rows, which glibc does not wrap. The generic (arm64)
//! table has none of these rows.

use super::thread_pointer;
use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `ARCH_*` codes (arch/x86/include/uapi/asm/prctl.h).
pub(super) const ARCH_SET_FS: i64 = 0x1002;
const ARCH_GET_FS: i64 = 0x1003;
const ARCH_GET_GS: i64 = 0x1004;
const ARCH_GET_CPUID: i64 = 0x1011;
/// The shadow-stack codes and features (arch/x86/include/uapi/asm/prctl.h).
const ARCH_SHSTK_ENABLE: i64 = 0x5001;
const ARCH_SHSTK_DISABLE: i64 = 0x5002;
const ARCH_SHSTK_LOCK: i64 = 0x5003;
const ARCH_SHSTK_STATUS: i64 = 0x5005;
const ARCH_SHSTK_SHSTK: i64 = 1 << 0;
const ARCH_SHSTK_WRSS: i64 = 1 << 1;
/// A code `arch_prctl` does not define.
const ARCH_UNKNOWN: i64 = 0x9999;
/// `modify_ldt` functions: read, write (the modern form), read the default.
const LDT_READ: i64 = 0;
const LDT_WRITE: i64 = 0x11;
const LDT_READ_DEFAULT: i64 = 2;
/// A function `modify_ldt` does not define.
const LDT_UNKNOWN: i64 = 99;
/// What a 64-bit kernel reads of the default LDT: at most 128 zero bytes.
const DEFAULT_LDT_BYTES: usize = 128;
/// `sizeof(struct user_desc)`.
const USER_DESC_BYTES: i64 = 16;
/// `struct user_desc`'s flag bits (the fourth word): `read_exec_only`
/// (bit 3) and `seg_not_present` (bit 5), with every other one clear.
const EMPTY_ENTRY_FLAGS: u8 = (1 << 3) | (1 << 5);

/// `-errno` as `modify_ldt` returns it: the `int` in a zero-extended
/// register.
fn ldt_error(errno: i32) -> i64 {
    i64::from((-errno) as u32)
}

pub(super) fn arch_prctl(p: &Probe, code: i64, arg: i64, what: &str) -> i64 {
    p.observed(
        Syscall::N_arch_prctl,
        [code, arg, 0, 0, 0, 0],
        &[("code", code.into()), ("arg", what.into())],
    )
}

fn modify_ldt(p: &Probe, func: i64, buf: &mut [u8], count: i64) -> i64 {
    p.observed(
        Syscall::N_modify_ldt,
        [func, buf.as_mut_ptr() as i64, count, 0, 0, 0],
        &[("func", func.into()), ("bytecount", count.into())],
    )
}

pub fn run(p: &Probe) {
    for row in [Syscall::N_set_thread_area, Syscall::N_get_thread_area] {
        let mut desc = [0u8; USER_DESC_BYTES as usize];
        let r = p.observed(
            row,
            [desc.as_mut_ptr() as i64, 0, 0, 0, 0, 0],
            &[("u_info", "zeroed".into())],
        );
        p.check(
            &format!("{} is ENOSYS for a 64-bit task", row.name()),
            r == neg(ENOSYS),
        );
    }

    let mut fs = 0u64;
    p.check(
        "ARCH_GET_FS answers 0",
        arch_prctl(p, ARCH_GET_FS, &mut fs as *mut u64 as i64, "out") == 0,
    );
    p.check(
        "the FS base is the thread pointer glibc installed",
        fs == thread_pointer() as u64,
    );
    p.check(
        "setting the FS base to itself answers 0",
        arch_prctl(p, ARCH_SET_FS, fs as i64, "current-fs") == 0,
    );
    let mut again = 0u64;
    p.check(
        "and leaves it where it was",
        arch_prctl(p, ARCH_GET_FS, &mut again as *mut u64 as i64, "out") == 0
            && again == fs
            && thread_pointer() as u64 == fs,
    );
    let mut gs = u64::MAX;
    p.check(
        "the task has no GS base",
        arch_prctl(p, ARCH_GET_GS, &mut gs as *mut u64 as i64, "out") == 0 && gs == 0,
    );
    p.check(
        "CPUID does not fault",
        arch_prctl(p, ARCH_GET_CPUID, 0, "none") == 1,
    );
    for (what, code, arg, arg_what, errno) in [
        ("an unknown code is EINVAL", ARCH_UNKNOWN, 0, "none", EINVAL),
        (
            "a NULL out-pointer is EFAULT",
            ARCH_GET_FS,
            0,
            "null",
            EFAULT,
        ),
    ] {
        p.check(what, arch_prctl(p, code, arg, arg_what) == neg(errno));
    }

    let mut features = u64::MAX;
    p.check(
        "the shadow-stack status reports no feature",
        arch_prctl(
            p,
            ARCH_SHSTK_STATUS,
            &mut features as *mut u64 as i64,
            "out",
        ) == 0
            && features == 0,
    );
    for (what, code, arg, arg_what) in [
        (
            "two features at once are EINVAL",
            ARCH_SHSTK_ENABLE,
            ARCH_SHSTK_SHSTK | ARCH_SHSTK_WRSS,
            "shstk|wrss",
        ),
        (
            "disabling no feature is EINVAL",
            ARCH_SHSTK_DISABLE,
            0,
            "none",
        ),
    ] {
        p.check(what, arch_prctl(p, code, arg, arg_what) == neg(EINVAL));
    }
    // Locked first, the shadow stack is never enabled, on any CPU.
    p.check(
        "locking the shadow stack answers 0",
        arch_prctl(p, ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK, "shstk") == 0,
    );
    p.check(
        "enabling a locked feature is EPERM",
        arch_prctl(p, ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK, "shstk") == neg(EPERM),
    );

    let mut buf = [0xaau8; 64];
    p.check(
        "a task without an LDT reads 0 bytes of it",
        modify_ldt(p, LDT_READ, &mut buf, 64) == 0 && buf == [0xaa; 64],
    );
    let mut default = [0xaau8; DEFAULT_LDT_BYTES + 32];
    let asked = default.len() as i64;
    p.check(
        "reading the default LDT answers at most 128 bytes",
        modify_ldt(p, LDT_READ_DEFAULT, &mut default, asked) == DEFAULT_LDT_BYTES as i64,
    );
    p.check(
        "and zeroes those, no more",
        default[..DEFAULT_LDT_BYTES].iter().all(|&b| b == 0)
            && default[DEFAULT_LDT_BYTES..].iter().all(|&b| b == 0xaa),
    );
    p.check(
        "an unknown function is ENOSYS, as a zero-extended int",
        modify_ldt(p, LDT_UNKNOWN, &mut buf, 64) == ldt_error(ENOSYS),
    );
    p.check(
        "a write of the wrong size is EINVAL, as a zero-extended int",
        modify_ldt(p, LDT_WRITE, &mut buf, 1) == ldt_error(EINVAL),
    );
    // Entry 0 in the form the kernel reads as empty (`LDT_empty`: base and
    // limit zero, read-exec-only, not present), which it stores as a zeroed
    // descriptor: harmless to the task, which never loads a selector from
    // its LDT.
    let mut empty = [0u8; USER_DESC_BYTES as usize];
    empty[12] = EMPTY_ENTRY_FLAGS;
    p.check(
        "writing an empty entry answers 0",
        modify_ldt(p, LDT_WRITE, &mut empty, USER_DESC_BYTES) == 0,
    );
    let mut ldt = [0xaau8; 64];
    p.check(
        "the task now has an LDT: a read answers the size asked, zero-filled past its one zeroed entry",
        modify_ldt(p, LDT_READ, &mut ldt, 64) == 64 && ldt == [0; 64],
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/tls",
    run,
    vehicles: Vehicle::ALL,
    covers: &[
        Syscall::N_set_thread_area,
        Syscall::N_get_thread_area,
        Syscall::N_arch_prctl,
        Syscall::N_modify_ldt,
    ],
    symbols: &["arch_prctl", "modify_ldt"],
    ..DEFAULTS
};
