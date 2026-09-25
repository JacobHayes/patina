//! The virtual process's resource limits: `getrlimit`/`setrlimit` (C door)
//! and `getrlimit`/`setrlimit`/`prlimit64` (SUD rows) all answer from one
//! table of the 16 Linux resources, never from the host's ulimits.
//!
//! Every resource starts at the value a fresh process on a stock kernel
//! inherits from `init` (`include/asm-generic/resource.h` `INIT_RLIMITS`), on
//! the virtual machine's size where the kernel derives one. The identity is
//! unprivileged (no `CAP_SYS_RESOURCE`), so `do_prlimit`'s rule holds for
//! every resource: any limit may be lowered, a soft limit may rise to its hard
//! limit, and raising a hard limit is `EPERM`.
//!
//! Enforced: `RLIMIT_NOFILE` (the descriptor table's `EMFILE` bound and the
//! `poll` size bound), `RLIMIT_MEMLOCK` (page-lock accounting, `src/mem/`) and
//! `RLIMIT_MSGQUEUE` (POSIX message-queue accounting, `src/thread/ipc.rs`).
//! The rest are kept and reported: nothing in the virtual process consumes
//! CPU time, stack, core dumps or processes against them yet.

use crate::SpinMutex;
use std::ffi::c_int;

// The resources with a starting value of their own; `RLIMIT_CPU`, `FSIZE`,
// `DATA`, `RSS`, `AS`, `LOCKS` and `RTTIME` start unlimited.
const RLIMIT_STACK: u32 = 3;
const RLIMIT_CORE: u32 = 4;
const RLIMIT_NPROC: u32 = 6;
pub(crate) const RLIMIT_NOFILE: u32 = 7;
pub(crate) const RLIMIT_MEMLOCK: u32 = 8;
const RLIMIT_SIGPENDING: u32 = 11;
pub(crate) const RLIMIT_MSGQUEUE: u32 = 12;
pub(crate) const RLIMIT_NICE: u32 = 13;
pub(crate) const RLIMIT_RTPRIO: u32 = 14;
const RLIM_NLIMITS: usize = 16;
const RLIM_INFINITY: u64 = u64::MAX;

/// `_STK_LIM`: the soft stack limit, 8 MiB.
const STACK_SOFT: u64 = 8 << 20;
/// `INR_OPEN_CUR` is the descriptor table's starting bound
/// (`fdtable::RLIMIT_NOFILE`); `INR_OPEN_MAX` the hard limit.
const NOFILE_HARD: u64 = 4096;
/// `MLOCK_LIMIT`: 8 MiB since 5.16.
const MEMLOCK_DEFAULT: u64 = 8 << 20;
/// `MQ_BYTES_MAX`: 819200 bytes of POSIX message queues.
const MSGQUEUE_DEFAULT: u64 = 819_200;
/// The virtual machine's memory: 4 GiB (what `sysinfo` reports, and what
/// the limits the kernel sizes from memory are sized from).
pub(crate) const MACHINE_MEMORY: u64 = 4 << 30;
/// `set_max_threads` on the virtual machine (4 GiB of 4 KiB pages, 16 KiB
/// thread stacks: `max_threads` 32768) gives `RLIMIT_NPROC` and
/// `RLIMIT_SIGPENDING` `max_threads / 2`.
const THREADS_HALF: u64 = 16_384;
/// `fs.nr_open`: the highest `RLIMIT_NOFILE` a hard limit may name.
const NR_OPEN: u64 = crate::registry::KERNEL_CONFIG.nr_open;

/// `struct rlimit64`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

const fn limit(cur: u64, max: u64) -> Rlimit {
    Rlimit { cur, max }
}

/// `INIT_RLIMITS`, indexed by resource.
const INITIAL: [Rlimit; RLIM_NLIMITS] = {
    let mut limits = [limit(RLIM_INFINITY, RLIM_INFINITY); RLIM_NLIMITS];
    limits[RLIMIT_STACK as usize] = limit(STACK_SOFT, RLIM_INFINITY);
    limits[RLIMIT_CORE as usize] = limit(0, RLIM_INFINITY);
    limits[RLIMIT_NPROC as usize] = limit(THREADS_HALF, THREADS_HALF);
    limits[RLIMIT_NOFILE as usize] = limit(crate::fdtable::RLIMIT_NOFILE as u64, NOFILE_HARD);
    limits[RLIMIT_MEMLOCK as usize] = limit(MEMLOCK_DEFAULT, MEMLOCK_DEFAULT);
    limits[RLIMIT_SIGPENDING as usize] = limit(THREADS_HALF, THREADS_HALF);
    limits[RLIMIT_MSGQUEUE as usize] = limit(MSGQUEUE_DEFAULT, MSGQUEUE_DEFAULT);
    limits[RLIMIT_NICE as usize] = limit(0, 0);
    limits[RLIMIT_RTPRIO as usize] = limit(0, 0);
    limits
};

/// The guest's limits, then init's: `prlimit64` reaches init too (it runs
/// as the same user), and changes there change nothing the guest sees.
static LIMITS: SpinMutex<[[Rlimit; RLIM_NLIMITS]; 2]> = SpinMutex::new([INITIAL, INITIAL]);
const GUEST: usize = 0;
const INIT: usize = 1;

/// The guest's soft limit of `resource` now.
pub(crate) fn soft(resource: u32) -> u64 {
    LIMITS.lock()[GUEST][resource as usize].cur
}

/// `do_prlimit` on the table: `old` is the limit before, `new` replaces it.
fn exchange(
    limits: &mut [Rlimit; RLIM_NLIMITS],
    resource: u32,
    new: Option<Rlimit>,
) -> Result<Rlimit, c_int> {
    let Some(slot) = limits.get_mut(resource as usize) else {
        return Err(crate::EINVAL);
    };
    let old = *slot;
    if let Some(new) = new {
        if new.cur > new.max {
            return Err(crate::EINVAL);
        }
        if resource == RLIMIT_NOFILE && new.max > NR_OPEN {
            return Err(crate::EPERM);
        }
        // Raising a hard limit needs `CAP_SYS_RESOURCE`.
        if new.max > old.max {
            return Err(crate::EPERM);
        }
        *slot = new;
    }
    Ok(old)
}

/// `prlimit64(2)` for the virtual process: the old limit into `old` when
/// non-NULL, then `new` when non-NULL. 0 or `-errno`.
///
/// # Safety
/// `new` must be NULL or readable, `old` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_prlimit(
    pid: c_int,
    resource: u32,
    new: *const Rlimit,
    old: *mut Rlimit,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: per this function's contract.
    let new = (!new.is_null()).then(|| unsafe { new.read_unaligned() });
    let process = match pid {
        0 => GUEST,
        pid => match crate::identity::lookup(pid) {
            Some((crate::identity::Process::Guest, _)) => GUEST,
            Some((crate::identity::Process::Init, _)) => INIT,
            None => return -i64::from(crate::ESRCH),
        },
    };
    let result = exchange(&mut LIMITS.lock()[process], resource, new);
    let previous = match result {
        Ok(previous) => previous,
        Err(errno) => return -i64::from(errno),
    };
    if let (Some(new), RLIMIT_NOFILE, GUEST) = (new, resource, process) {
        crate::set_fd_limit(new.cur);
    }
    if !old.is_null() {
        // SAFETY: per this function's contract.
        unsafe { old.write_unaligned(previous) };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_resource_follows_the_unprivileged_rule() {
        let mut limits = INITIAL;
        for resource in 0..RLIM_NLIMITS as u32 {
            let initial = INITIAL[resource as usize];
            // Lower both, then raise the soft limit back up to the hard one.
            let lower = limit(initial.cur.min(initial.max / 2), initial.max / 2);
            assert_eq!(exchange(&mut limits, resource, Some(lower)), Ok(initial));
            let raised = limit(lower.max, lower.max);
            assert_eq!(exchange(&mut limits, resource, Some(raised)), Ok(lower));
            // The hard limit never rises again.
            if lower.max != initial.max {
                assert_eq!(
                    exchange(&mut limits, resource, Some(initial)),
                    Err(crate::EPERM)
                );
            }
            assert_eq!(exchange(&mut limits, resource, None), Ok(raised));
        }
        assert_eq!(exchange(&mut limits, 16, None), Err(crate::EINVAL));
    }

    #[test]
    fn a_soft_limit_above_the_hard_one_is_invalid_before_anything_else() {
        let mut limits = INITIAL;
        assert_eq!(
            exchange(&mut limits, RLIMIT_CORE, Some(limit(2, 1))),
            Err(crate::EINVAL)
        );
        assert_eq!(
            exchange(&mut limits, RLIMIT_NOFILE, Some(limit(1, NR_OPEN + 1))),
            Err(crate::EPERM)
        );
        assert_eq!(limits, INITIAL);
        // Disabling core dumps, as daemons do at start.
        assert_eq!(
            exchange(&mut limits, RLIMIT_CORE, Some(limit(0, 0))),
            Ok(limit(0, RLIM_INFINITY))
        );
    }
}
