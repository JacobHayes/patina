//! SUD rows — memory: the mapping, protection, locking and limit rows route
//! into the one memory model (`crate::mem`, the same `patina_*` entries the C
//! interposers call); the rows that only advise or ask about the residency of
//! process-local memory pass through to the host kernel via the glibc
//! `syscall(2)` host alias (never the interposed `syscall`).

use super::*;

pub(super) fn sys_mmap(args: [u64; 6]) -> i64 {
    // SAFETY: the model validates every argument the kernel would.
    unsafe {
        patina_mmap(
            args[0] as usize,
            args[1] as usize,
            args[2] as c_int,
            args[3] as c_int,
            arg_fd(args[4]) as c_int,
            args[5] as i64,
        )
    }
}

pub(super) fn sys_munmap(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe { patina_munmap(args[0] as usize, args[1] as usize) }
}

pub(super) fn sys_mremap(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe {
        patina_mremap(
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
        )
    }
}

pub(super) fn sys_msync(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe { patina_msync(args[0] as usize, args[1] as usize, args[2] as c_int) }
}

pub(super) fn sys_mprotect(args: [u64; 6]) -> i64 {
    // SAFETY: as above.
    unsafe { patina_mprotect(args[0] as usize, args[1] as usize, args[2] as c_int) }
}

/// `getrlimit(2)`: the limit (`EINVAL` for an unknown resource first), then
/// its copy out (`EFAULT`).
pub(super) fn sys_getrlimit(resource: u64, out: u64) -> i64 {
    let mut limit = crate::limits::Rlimit { cur: 0, max: 0 };
    // SAFETY: a local out-buffer.
    let result = unsafe { patina_prlimit(0, resource as u32, std::ptr::null(), &mut limit) };
    if result != 0 {
        return result;
    }
    if out == 0 {
        return -EFAULT;
    }
    // SAFETY: the guest's `struct rlimit`, non-null.
    unsafe { (out as *mut crate::limits::Rlimit).write_unaligned(limit) };
    0
}

/// `setrlimit(2)`: the new limit is copied in first (`EFAULT`).
pub(super) fn sys_setrlimit(resource: u64, new: u64) -> i64 {
    if new == 0 {
        return -EFAULT;
    }
    // SAFETY: the guest's `struct rlimit`, non-null.
    unsafe { patina_prlimit(0, resource as u32, new as *const _, std::ptr::null_mut()) }
}

/// Pass a process-local memory syscall through to the host kernel via the glibc
/// `syscall(2)` vehicle, in the raw ABI.
pub(super) fn mem_passthrough(nr: i64, args: [u64; 6]) -> i64 {
    crate::mem::host_number(nr, args.map(|arg| arg as usize))
}

// ---- the virtual CPU's memory features ------------------------------------
//
// The virtual machine's CPU has neither memory protection keys nor user
// shadow stacks, on every host, so its answers never depend on the host's
// CPU. Keys are hardware state the guest reaches without a syscall
// (`rdpkru`/`wrpkru`), so no host's keys could stand in for them; a shadow
// stack is a feature some hosts have and others lack. The rows answer as the
// pinned 6.8 kernel does on such a CPU (x86_64: `OSPKE` and `USER_SHSTK`
// clear; aarch64's 6.8 builds neither feature's rows).

/// The protection-key allocation map of 6.8 on a CPU without
/// `X86_FEATURE_OSPKE`. `init_new_context` (arch/x86/include/asm/
/// mmu_context.h) marks key 0 allocated and the execute-only key -1 only
/// when `OSPKE` is enabled; without it the map and `execute_only_pkey` stay
/// the zeroes `mm_alloc` (kernel/fork.c) leaves at exec. With
/// `arch_max_pkey() == 1` (arch/x86/include/asm/pkeys.h), then:
///
/// - the first `pkey_alloc` takes key 0 (`mm_pkey_alloc`: map 0 is not the
///   full mask 1), `arch_set_user_pkey_access` refuses it (`EINVAL`,
///   arch/x86/kernel/fpu/xstate.c), and the `mm_pkey_free` that follows
///   fails (`mm_pkey_is_allocated(0)` is false, since 0 is the
///   execute-only key), so key 0 stays taken: `EINVAL`;
/// - every later one finds the map full: `ENOSPC`;
/// - no key is ever allocated to a user interface: `pkey_free` is always
///   `EINVAL`, and `pkey_mprotect` takes key -1 alone (`mm/mprotect.c`
///   `do_mprotect_pkey`: its earlier checks, then `EINVAL`).
#[derive(Default)]
struct Pkeys {
    /// `mm_pkey_alloc` took key 0: the map is full.
    key0_taken: std::sync::atomic::AtomicBool,
}

/// `PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE`.
const PKEY_ACCESS_MASK: u64 = 0x3;

impl Pkeys {
    fn alloc(&self, flags: u64, rights: u64) -> i64 {
        if flags != 0 || rights & !PKEY_ACCESS_MASK != 0 {
            return -EINVAL;
        }
        if self
            .key0_taken
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            -(errno::ENOSPC as i64)
        } else {
            -EINVAL
        }
    }

    fn free(&self, _key: i32) -> i64 {
        -EINVAL
    }

    /// `pkey_mprotect`: plain `mprotect` for key -1; for any other key,
    /// `do_mprotect_pkey`'s checks before the key's, then the key's `EINVAL`.
    fn mprotect(&self, args: [u64; 6]) -> i64 {
        const PROT_GROWSDOWN: u64 = 0x0100_0000;
        const PROT_GROWSUP: u64 = 0x0200_0000;
        let (start, len, prot, key) = (args[0], args[1], args[2], args[3] as i32);
        if key == -1 {
            return sys_mprotect(args);
        }
        let page = crate::mem::PAGE as u64;
        if prot & (PROT_GROWSDOWN | PROT_GROWSUP) == PROT_GROWSDOWN | PROT_GROWSUP
            || start % page != 0
        {
            return -EINVAL;
        }
        if len == 0 {
            return 0;
        }
        let rounded = len.wrapping_add(page - 1) & !(page - 1);
        if start.wrapping_add(rounded) <= start {
            return -(errno::ENOMEM as i64);
        }
        -EINVAL
    }
}

/// The process's key map (one address space).
static PKEYS: Pkeys = Pkeys {
    key0_taken: std::sync::atomic::AtomicBool::new(false),
};

/// `pkey_alloc(flags, rights)` ([`Pkeys`]); aarch64's 6.8 does not build
/// `ARCH_HAS_PKEYS`: `ENOSYS`, as for the other key rows.
pub(super) fn sys_pkey_alloc(args: [u64; 6]) -> i64 {
    if cfg!(not(target_arch = "x86_64")) {
        return -ENOSYS;
    }
    PKEYS.alloc(args[0], args[1])
}

/// `pkey_free(key)` ([`Pkeys`]): no key is ever one to free.
pub(super) fn sys_pkey_free(args: [u64; 6]) -> i64 {
    if cfg!(not(target_arch = "x86_64")) {
        return -ENOSYS;
    }
    PKEYS.free(args[0] as i32)
}

/// `pkey_mprotect(start, len, prot, key)` ([`Pkeys`]).
pub(super) fn sys_pkey_mprotect(args: [u64; 6]) -> i64 {
    if cfg!(not(target_arch = "x86_64")) {
        return -ENOSYS;
    }
    PKEYS.mprotect(args)
}

/// `map_shadow_stack` (`arch/x86/kernel/shstk.c`): `EOPNOTSUPP` before any
/// argument is looked at, as 6.8 answers without `X86_FEATURE_USER_SHSTK`.
/// aarch64's 6.8 has no shadow stacks: `ENOSYS`.
pub(super) fn sys_map_shadow_stack(_: [u64; 6]) -> i64 {
    if cfg!(target_arch = "x86_64") {
        -EOPNOTSUPP
    } else {
        -ENOSYS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key rows in sequence, as 6.8 answers them on a CPU without
    /// `OSPKE`: the first allocation takes key 0 and still fails `EINVAL`,
    /// every later one is `ENOSPC`; no key frees; only key -1 tags a page.
    #[test]
    fn protection_keys_answer_as_a_cpu_without_them() {
        let keys = Pkeys::default();
        let page = crate::mem::PAGE as u64;
        let rows: [(&str, i64, i64); 8] = [
            ("an unknown flag", keys.alloc(1, 0), -EINVAL),
            ("unknown rights", keys.alloc(0, 0x10), -EINVAL),
            ("the first allocation", keys.alloc(0, 0), -EINVAL),
            (
                "a later allocation",
                keys.alloc(0, 2),
                -(errno::ENOSPC as i64),
            ),
            ("an unknown flag, later", keys.alloc(1, 0), -EINVAL),
            ("freeing key 0", keys.free(0), -EINVAL),
            ("freeing key 1", keys.free(1), -EINVAL),
            (
                "key 0 tags nothing",
                keys.mprotect([page, page, 3, 0, 0, 0]),
                -EINVAL,
            ),
        ];
        for (what, answer, expected) in rows {
            assert_eq!(answer, expected, "{what}");
        }
        // Checks before the key's: a zero length answers 0, a wrapping range
        // ENOMEM.
        assert_eq!(keys.mprotect([page, 0, 3, 5, 0, 0]), 0, "a zero length");
        let wraps = [!(page - 1), 2 * page, 3, 5, 0, 0];
        assert_eq!(
            keys.mprotect(wraps),
            -(errno::ENOMEM as i64),
            "a wrapping range"
        );
    }
}
