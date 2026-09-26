//! The x86_64 thread-pointer rows: `arch_prctl` (arch/x86/kernel/process_64.c
//! `do_arch_prctl_64`, then process.c `do_arch_prctl_common`) and
//! `modify_ldt` (arch/x86/kernel/ldt.c).
//!
//! The FS base is not the guest's alone. It is the thread pointer glibc's TCB
//! and the shim's own thread-locals (the current task, the frame flags, the
//! panic scope, the thread registrations) resolve through, so a guest that
//! moved it would have the shim schedule the wrong task or corrupt its own
//! state. Nothing here moves it: `ARCH_SET_FS` to another base, and any LDT
//! write that would store a usable descriptor (an FS selector a plain `mov`
//! loads comes from the LDT), stop the run by name, as the pre-run audit
//! refuses the instructions that would do the same with no syscall (category
//! `thread-pointer`). An LDT write the kernel stores as an all-zero
//! descriptor, which no selector load accepts, goes to the host. What only
//! reads (the FS and GS bases, the LDT) is the host kernel's on the calling
//! thread, and so is a GS base, which neither glibc nor the shim uses in user
//! space. The virtual CPU has no CPUID faulting, so `cpuid` never faults and
//! the mode cannot be set.

use super::*;

/// `arch_prctl` codes (arch/x86/include/uapi/asm/prctl.h).
const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;
const ARCH_GET_CPUID: i32 = 0x1011;
const ARCH_SET_CPUID: i32 = 0x1012;
/// The codes 6.8 (Ubuntu's configuration) answers that are not modeled: the
/// xstate permissions (`ARCH_GET_XCOMP_SUPP` .. `ARCH_REQ_XCOMP_GUEST_PERM`),
/// mapping a vDSO (`ARCH_MAP_VDSO_32`, `ARCH_MAP_VDSO_64`; the x32 one is not
/// configured) and shadow stacks (`ARCH_SHSTK_ENABLE` .. `ARCH_SHSTK_STATUS`).
/// Linear address masking (`0x4001`..`0x4004`) is not configured either, so
/// those codes are `EINVAL` like any other.
const UNMODELED_CODES: [(std::ops::RangeInclusive<i32>, &str); 3] = [
    (0x1021..=0x1025, "the xstate permission codes"),
    (0x2002..=0x2003, "mapping a vDSO"),
    (0x5001..=0x5005, "the shadow stack codes"),
];

/// `TASK_SIZE_MAX` with 4-level paging, the virtual machine's: a base at or
/// past it is `EPERM`.
const TASK_SIZE_MAX: u64 = 0x7fff_ffff_f000;

/// `modify_ldt` functions.
const LDT_READ: i32 = 0;
const LDT_WRITE_OLD: i32 = 1;
const LDT_READ_DEFAULT: i32 = 2;
const LDT_WRITE: i32 = 0x11;
/// `LDT_ENTRIES`: the most entries an LDT holds.
const LDT_ENTRIES: u32 = 8192;
/// `struct user_desc`: entry number, base, limit, then the flag bits.
#[repr(C)]
#[derive(Clone, Copy)]
struct UserDesc {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    flags: u32,
}
/// `user_desc`'s `contents` (bits 1-2), `read_exec_only` (bit 3) and
/// `seg_not_present` (bit 5).
const CONTENTS_SHIFT: u32 = 1;
const CONTENTS_MASK: u32 = 3;
const READ_EXEC_ONLY: u32 = 1 << 3;
const SEG_NOT_PRESENT: u32 = 1 << 5;
/// The bits `LDT_empty` reads: `seg_32bit` through `useable` (not `lm`).
const LDT_EMPTY_BITS: u32 = 0x7f;
/// `contents` 3: a conforming code segment (`fill_ldt`'s type 1100), which
/// only a not-present entry in the modern form may hold.
const CONTENTS_CODE: u32 = 3;

/// Stop the run: `what` would move the thread pointer.
fn refuse(what: &str) -> ! {
    crate::trap_fatal(&format!(
        "thread-pointer: {what} refused: the shim finds its own per-thread state through the \
         thread pointer, so no guest may move it (the pre-run audit refuses wrfsbase and FS \
         selector loads for the same reason); keep the thread pointer glibc installs"
    ))
}

/// The host kernel's answer for the calling thread: `-errno` on failure.
fn host(nr: i64, args: [u64; 6]) -> i64 {
    crate::mem::host_number(nr, args.map(|arg| arg as usize))
}

/// `arch_prctl(code, arg2)`: the code is the kernel's `int`.
pub(super) fn sys_arch_prctl(nr: i64, a: [u64; 6]) -> i64 {
    let code = a[0] as i32;
    let arg = a[1];
    let passed = [code as u32 as u64, arg, 0, 0, 0, 0];
    match code {
        ARCH_GET_FS | ARCH_GET_GS => host(nr, passed),
        // The virtual CPU has no CPUID faulting (`X86_FEATURE_CPUID_FAULT`):
        // `cpuid` never faults, and `set_cpuid_mode` refuses before it looks
        // at the argument.
        ARCH_GET_CPUID => 1,
        ARCH_SET_CPUID => -i64::from(errno::ENODEV),
        ARCH_SET_GS if arg >= TASK_SIZE_MAX => -i64::from(errno::EPERM),
        ARCH_SET_GS => host(nr, passed),
        ARCH_SET_FS if arg >= TASK_SIZE_MAX => -i64::from(errno::EPERM),
        ARCH_SET_FS => {
            let mut current = 0u64;
            let read = host(
                nr,
                [ARCH_GET_FS as u64, &raw mut current as u64, 0, 0, 0, 0],
            );
            if read != 0 {
                crate::trap_fatal(&format!(
                    "arch_prctl(ARCH_GET_FS) for the calling thread failed ({read})"
                ));
            }
            if arg == current {
                0
            } else {
                refuse(&format!("arch_prctl(ARCH_SET_FS, {arg:#x})"))
            }
        }
        _ => match UNMODELED_CODES
            .iter()
            .find(|(codes, _)| codes.contains(&code))
        {
            Some((_, what)) => crate::trap_fatal(&format!(
                "arch_prctl({code:#x}): {what} are not modeled; failing closed"
            )),
            None => -i64::from(errno::EINVAL),
        },
    }
}

/// `-errno` as `modify_ldt` returns it: its `int` result in a zero-extended
/// register.
fn ldt_error(code: u32) -> i64 {
    i64::from((-(code as i32)) as u32)
}

/// `modify_ldt(func, ptr, bytecount)`: the function is the kernel's `int`.
pub(super) fn sys_modify_ldt(nr: i64, a: [u64; 6]) -> i64 {
    let func = a[0] as i32;
    match func {
        LDT_READ | LDT_READ_DEFAULT => host(nr, [func as u32 as u64, a[1], a[2], 0, 0, 0]),
        LDT_WRITE_OLD | LDT_WRITE => write_ldt(nr, a[1], a[2], func == LDT_WRITE_OLD),
        _ => ldt_error(errno::ENOSYS),
    }
}

/// `write_ldt`'s checks before it changes the LDT: the size, the copy, the
/// entry number, and the code-segment rule (16-bit segments are allowed:
/// `CONFIG_X86_16BIT`). An entry the kernel clears (its `memset` case: the
/// old form with base and limit 0, or `LDT_empty`) goes to the host from the
/// copy judged here, never re-read from the guest; any other would store a
/// descriptor a selector load could use, and is refused.
fn write_ldt(nr: i64, ptr: u64, bytecount: u64, old_mode: bool) -> i64 {
    if bytecount != std::mem::size_of::<UserDesc>() as u64 {
        return ldt_error(errno::EINVAL);
    }
    let Ok(desc) = crate::uaccess::read::<UserDesc>(ptr as usize) else {
        return ldt_error(errno::EFAULT);
    };
    if desc.entry_number >= LDT_ENTRIES {
        return ldt_error(errno::EINVAL);
    }
    if (desc.flags >> CONTENTS_SHIFT) & CONTENTS_MASK == CONTENTS_CODE
        && (old_mode || desc.flags & SEG_NOT_PRESENT == 0)
    {
        return ldt_error(errno::EINVAL);
    }
    let clears = (old_mode && desc.base_addr == 0 && desc.limit == 0)
        || (desc.base_addr == 0
            && desc.limit == 0
            && desc.flags & LDT_EMPTY_BITS == READ_EXEC_ONLY | SEG_NOT_PRESENT);
    if clears {
        let func = if old_mode { LDT_WRITE_OLD } else { LDT_WRITE };
        return host(
            nr,
            [func as u64, &raw const desc as u64, bytecount, 0, 0, 0],
        );
    }
    refuse(&format!(
        "modify_ldt({:#x}) writing LDT entry {}",
        if old_mode { LDT_WRITE_OLD } else { LDT_WRITE },
        desc.entry_number
    ))
}
