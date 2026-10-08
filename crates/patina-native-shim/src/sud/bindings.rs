//! Registry rows bound to their syscall handlers.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// A routed row's handler: the syscall number and its six argument registers
/// in, the raw return value out (`-errno` on failure). The number is passed so
/// the memory pass-through can hand the host kernel the exact number it trapped.
type Handler = fn(i64, [u64; 6]) -> i64;

/// The handler bound to each routed registry row, by row name. Dispatch is
/// GENERATED from `registry::SYSCALLS` (the [`DISPATCH`] index below is built
/// from the rows for this arch at compile time), so there is no second list of
/// numbers here — only the adapter from registers to the `sys_*` signature.
/// [`build_dispatch`] refuses to compile a `Modeled`/`Passthrough` row without
/// exactly one binding, a `Trap`/`Absent` row with one, or a binding that names
/// no row; `tests::bindings_match_the_registry_rows` reports the same
/// conditions by name.
///
/// fd/dirfd registers go through [`arg_fd`]; `AT_FDCWD` and any negative fd are
/// 32-bit `int`s the kernel reads from the low register bits.
use crate::registry::Syscall;

pub(super) const BINDINGS: &[(Syscall, Handler)] = &[
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_select, |_, a| {
        sys_select(a[0], a[1], a[2], a[3], a[4], None)
    }),
    (Syscall::N_pselect6, |_, a| {
        sys_select(a[0], a[1], a[2], a[3], a[4], Some(a[5]))
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_signalfd, |_, a| unsafe {
        // SAFETY: `a[1]` is the guest pointer to the 8-byte signal set;
        // `patina_signalfd` reads it through `uaccess` after checking the size.
        crate::thread::signals::fd::patina_signalfd(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as usize,
            0,
        )
    }),
    (Syscall::N_signalfd4, |_, a| unsafe {
        // SAFETY: `a[1]` is the guest pointer to the 8-byte signal set;
        // `patina_signalfd` reads it through `uaccess` after checking the size.
        crate::thread::signals::fd::patina_signalfd(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as usize,
            a[3] as i32,
        )
    }),
    // ---- time ----
    (Syscall::N_clock_gettime, |_, a| {
        sys_clock_gettime(a[0], a[1] as *mut Timespec)
    }),
    (Syscall::N_clock_getres, |_, a| {
        sys_clock_getres(a[0], a[1] as *mut Timespec)
    }),
    (Syscall::N_gettimeofday, |_, a| {
        sys_gettimeofday(a[0] as *mut Timeval, a[1] as *mut [i32; 2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_time, |_, a| sys_time(a[0] as *mut i64)),
    // Guest pointers, copied through `uaccess` by the entries.
    (Syscall::N_settimeofday, |_, a| {
        crate::clocks::settimeofday(a[0] as *const [i64; 2], a[1] as *const [i32; 2])
    }),
    (Syscall::N_clock_settime, |_, a| {
        crate::clocks::clock_settime(a[0] as c_int, a[1] as *const Timespec)
    }),
    (Syscall::N_adjtimex, |_, a| {
        crate::clocks::adjtimex(a[0] as *mut crate::clocks::Timex)
    }),
    (Syscall::N_clock_adjtime, |_, a| {
        crate::clocks::clock_adjtime(a[0] as c_int, a[1] as *mut crate::clocks::Timex)
    }),
    // ---- the process's timers (`thread::timers`) ----
    (Syscall::N_getitimer, |_, a| {
        crate::thread::timers::getitimer(a[0] as i32, a[1] as *mut _)
    }),
    (Syscall::N_setitimer, |_, a| {
        crate::thread::timers::setitimer(a[0] as i32, a[1] as *const _, a[2] as *mut _)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_alarm, |_, a| {
        crate::thread::timers::alarm(a[0] as u32)
    }),
    (Syscall::N_timer_create, |_, a| {
        crate::thread::timers::timer_create(a[0] as i32, a[1] as *const _, a[2] as *mut i32)
    }),
    (Syscall::N_timer_settime, |_, a| {
        crate::thread::timers::timer_settime(
            a[0] as i32,
            a[1] as i32,
            a[2] as *const _,
            a[3] as *mut _,
        )
    }),
    (Syscall::N_timer_gettime, |_, a| {
        crate::thread::timers::timer_gettime(a[0] as i32, a[1] as *mut _)
    }),
    (Syscall::N_timer_getoverrun, |_, a| {
        crate::thread::timers::timer_getoverrun(a[0] as i32)
    }),
    (Syscall::N_timer_delete, |_, a| {
        crate::thread::timers::timer_delete(a[0] as i32)
    }),
    // ---- inotify ----
    (Syscall::N_inotify_init1, |_, a| {
        crate::thread::inotify::init1(a[0] as i32)
    }),
    // SAFETY: `a[1]` is the guest's path pointer (NULL is `EFAULT`).
    (Syscall::N_inotify_add_watch, |_, a| unsafe {
        crate::thread::inotify::add_watch(arg_fd(a[0]) as c_int, a[1] as *const c_char, a[2] as u32)
    }),
    (Syscall::N_inotify_rm_watch, |_, a| {
        crate::thread::inotify::rm_watch(arg_fd(a[0]) as c_int, a[1] as i32)
    }),
    (Syscall::N_timerfd_create, |_, a| {
        crate::thread::timers::timerfd_create(a[0] as i32, a[1] as c_int)
    }),
    (Syscall::N_timerfd_settime, |_, a| {
        crate::thread::timers::timerfd_settime(
            arg_fd(a[0]) as c_int,
            a[1] as i32,
            a[2] as usize,
            a[3] as usize,
        )
    }),
    (Syscall::N_timerfd_gettime, |_, a| {
        crate::thread::timers::timerfd_gettime(arg_fd(a[0]) as c_int, a[1] as usize)
    }),
    (Syscall::N_times, |_, a| {
        crate::clocks::times(a[0] as *mut [i64; 4])
    }),
    (Syscall::N_getrusage, |_, a| {
        crate::clocks::getrusage(
            crate::abi::reg::int(a[0]),
            crate::abi::reg::ptr::<crate::clocks::Rusage>(a[1]),
        )
    }),
    // ---- identity: the one unprivileged identity (`crate::identity`) ----
    (Syscall::N_getuid, |_, _| {
        i64::from(crate::identity::credential().uid)
    }),
    (Syscall::N_geteuid, |_, _| {
        i64::from(crate::identity::credential().uid)
    }),
    (Syscall::N_getgid, |_, _| {
        i64::from(crate::identity::credential().gid)
    }),
    (Syscall::N_getegid, |_, _| {
        i64::from(crate::identity::credential().gid)
    }),
    // SAFETY: the identity core consumes these guest addresses with its uaccess checks.
    (Syscall::N_getresuid, |_, a| unsafe {
        crate::identity::getres(
            crate::identity::Id::User,
            a[0] as *mut u32,
            a[1] as *mut u32,
            a[2] as *mut u32,
        )
    }),
    // SAFETY: the identity core consumes these guest addresses with its uaccess checks.
    (Syscall::N_getresgid, |_, a| unsafe {
        crate::identity::getres(
            crate::identity::Id::Group,
            a[0] as *mut u32,
            a[1] as *mut u32,
            a[2] as *mut u32,
        )
    }),
    (Syscall::N_setuid, |_, a| {
        crate::identity::set(crate::identity::Id::User, a[0] as u32)
    }),
    (Syscall::N_setgid, |_, a| {
        crate::identity::set(crate::identity::Id::Group, a[0] as u32)
    }),
    (Syscall::N_setreuid, |_, a| {
        crate::identity::set_many(crate::identity::Id::User, &[a[0] as u32, a[1] as u32])
    }),
    (Syscall::N_setregid, |_, a| {
        crate::identity::set_many(crate::identity::Id::Group, &[a[0] as u32, a[1] as u32])
    }),
    (Syscall::N_setresuid, |_, a| {
        crate::identity::set_many(
            crate::identity::Id::User,
            &[a[0] as u32, a[1] as u32, a[2] as u32],
        )
    }),
    (Syscall::N_setresgid, |_, a| {
        crate::identity::set_many(
            crate::identity::Id::Group,
            &[a[0] as u32, a[1] as u32, a[2] as u32],
        )
    }),
    (Syscall::N_setfsuid, |_, _| {
        crate::identity::set_fs(crate::identity::Id::User)
    }),
    (Syscall::N_setfsgid, |_, _| {
        crate::identity::set_fs(crate::identity::Id::Group)
    }),
    // SAFETY: the identity core copies the guest list through its uaccess checks.
    (Syscall::N_getgroups, |_, a| unsafe {
        crate::identity::getgroups(a[0] as i32, a[1] as *mut u32)
    }),
    (Syscall::N_setgroups, |_, _| crate::identity::setgroups()),
    // SAFETY: capget validates and copies both guest structures through uaccess.
    (Syscall::N_capget, |_, a| unsafe {
        crate::identity::capget(a[0] as *mut _, a[1] as *mut _)
    }),
    // SAFETY: capset validates and copies both guest structures through uaccess.
    (Syscall::N_capset, |_, a| unsafe {
        crate::identity::capset(
            crate::identity::credential(),
            a[0] as *mut _,
            a[1] as *const _,
        )
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_getpgrp, |_, _| crate::identity::getpgrp()),
    (Syscall::N_setpgid, |_, a| {
        crate::identity::setpgid(a[0] as i32, a[1] as i32)
    }),
    (Syscall::N_setsid, |_, _| crate::identity::setsid()),
    // ---- privileged: the virtual credential's capability checks
    // (`privileged`) ----
    (Syscall::N_sethostname, |nr, a| {
        privileged::answer(nr, privileged::set_uts_name, a)
    }),
    (Syscall::N_setdomainname, |nr, a| {
        privileged::answer(nr, privileged::set_uts_name, a)
    }),
    (Syscall::N_mount, |nr, a| {
        privileged::answer(nr, privileged::mount, a)
    }),
    (Syscall::N_umount2, |nr, a| {
        privileged::answer(nr, privileged::umount2, a)
    }),
    (Syscall::N_pivot_root, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_open_tree, |nr, a| {
        privileged::answer(nr, privileged::open_tree, a)
    }),
    (Syscall::N_move_mount, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_fsopen, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_fsconfig, |nr, a| {
        privileged::answer(nr, privileged::fsconfig, a)
    }),
    (Syscall::N_fsmount, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_fspick, |nr, a| {
        privileged::answer(nr, privileged::may_mount, a)
    }),
    (Syscall::N_mount_setattr, |nr, a| {
        privileged::answer(nr, privileged::mount_setattr, a)
    }),
    (Syscall::N_acct, |nr, a| {
        privileged::answer(nr, privileged::acct, a)
    }),
    (Syscall::N_vhangup, |nr, a| {
        privileged::answer(nr, privileged::vhangup, a)
    }),
    (Syscall::N_swapon, |nr, a| {
        privileged::answer(nr, privileged::swapon, a)
    }),
    (Syscall::N_swapoff, |nr, a| {
        privileged::answer(nr, privileged::swapoff, a)
    }),
    (Syscall::N_reboot, |nr, a| {
        privileged::answer(nr, privileged::boot, a)
    }),
    (Syscall::N_kexec_load, |nr, a| {
        privileged::answer(nr, privileged::boot, a)
    }),
    (Syscall::N_kexec_file_load, |nr, a| {
        privileged::answer(nr, privileged::boot, a)
    }),
    (Syscall::N_init_module, |nr, a| {
        privileged::answer(nr, privileged::module, a)
    }),
    (Syscall::N_finit_module, |nr, a| {
        privileged::answer(nr, privileged::module, a)
    }),
    (Syscall::N_delete_module, |nr, a| {
        privileged::answer(nr, privileged::module, a)
    }),
    (Syscall::N_quotactl, |nr, a| {
        privileged::answer(nr, privileged::quotactl, a)
    }),
    (Syscall::N_quotactl_fd, |nr, a| {
        privileged::answer(nr, privileged::quotactl_fd, a)
    }),
    (Syscall::N_chroot, |nr, a| {
        privileged::answer(nr, privileged::chroot, a)
    }),
    (Syscall::N_syslog, |nr, a| {
        privileged::answer(nr, privileged::syslog, a)
    }),
    (Syscall::N_perf_event_open, |nr, a| {
        privileged::answer(nr, privileged::perf_event_open, a)
    }),
    (Syscall::N_bpf, |nr, a| {
        privileged::answer(nr, privileged::bpf, a)
    }),
    (Syscall::N_userfaultfd, |nr, a| {
        privileged::answer(nr, privileged::userfaultfd, a)
    }),
    (Syscall::N_ptrace, |nr, a| {
        privileged::answer(nr, privileged::ptrace, a)
    }),
    (Syscall::N_unshare, |nr, a| {
        privileged::answer(nr, privileged::unshare, a)
    }),
    (Syscall::N_setns, |nr, a| {
        privileged::answer(nr, privileged::setns, a)
    }),
    (Syscall::N_seccomp, |nr, a| {
        privileged::answer(nr, privileged::seccomp, a)
    }),
    (Syscall::N_landlock_create_ruleset, |nr, a| {
        privileged::answer(nr, privileged::landlock_create_ruleset, a)
    }),
    (Syscall::N_landlock_add_rule, |nr, a| {
        privileged::answer(nr, privileged::landlock_add_rule, a)
    }),
    (Syscall::N_landlock_restrict_self, |nr, a| {
        privileged::answer(nr, privileged::landlock_restrict_self, a)
    }),
    (Syscall::N_lsm_list_modules, |nr, a| {
        privileged::answer(nr, privileged::lsm_list_modules, a)
    }),
    (Syscall::N_lsm_get_self_attr, |nr, a| {
        privileged::answer(nr, privileged::lsm_get_self_attr, a)
    }),
    (Syscall::N_lsm_set_self_attr, |nr, a| {
        privileged::answer(nr, privileged::lsm_set_self_attr, a)
    }),
    (Syscall::N_add_key, |nr, a| {
        privileged::answer(nr, privileged::add_key, a)
    }),
    (Syscall::N_request_key, |nr, a| {
        privileged::answer(nr, privileged::request_key, a)
    }),
    (Syscall::N_keyctl, |nr, a| {
        privileged::answer(nr, privileged::keyctl, a)
    }),
    (Syscall::N_statmount, |nr, a| {
        privileged::answer(nr, privileged::statmount, a)
    }),
    (Syscall::N_listmount, |nr, a| {
        privileged::answer(nr, privileged::listmount, a)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_iopl, |nr, a| {
        privileged::answer(nr, privileged::iopl, a)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_ioperm, |nr, a| {
        privileged::answer(nr, privileged::ioperm, a)
    }),
    // SAFETY: uname writes its guest result through uaccess.
    (Syscall::N_uname, |_, a| unsafe {
        crate::identity::uname(
            crate::abi::reg::ptr::<crate::identity::Utsname>(a[0]),
            crate::thread::sched::persona(),
        )
    }),
    // SAFETY: sysinfo writes its guest result through uaccess.
    (Syscall::N_sysinfo, |_, a| unsafe {
        crate::identity::sysinfo(crate::abi::reg::ptr::<crate::identity::Sysinfo>(a[0]))
    }),
    // ---- scheduling attributes, affinity and persona (`thread::sched`) ----
    (Syscall::N_personality, |_, a| {
        crate::abi::raw(crate::thread::sched::personality(a[0] as u32))
    }),
    (Syscall::N_getpriority, |_, a| {
        crate::abi::raw(crate::thread::sched::getpriority(a[0] as i32, a[1] as i32))
    }),
    (Syscall::N_setpriority, |_, a| {
        crate::abi::raw(crate::thread::sched::setpriority(
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
        ))
    }),
    (Syscall::N_sched_setparam, |_, a| {
        // SAFETY: the syscall argument is sched_setparam's guest `sched_param` input.
        crate::abi::raw(unsafe {
            crate::thread::sched::setscheduler_param(a[0] as i32, None, a[1] as *const i32)
        })
    }),
    (Syscall::N_sched_getparam, |_, a| {
        // SAFETY: the syscall argument is sched_getparam's guest output buffer.
        crate::abi::raw(unsafe { crate::thread::sched::getparam(a[0] as i32, a[1] as *mut i32) })
    }),
    (Syscall::N_sched_setscheduler, |_, a| {
        // SAFETY: the syscall argument is sched_setscheduler's guest `sched_param` input.
        crate::abi::raw(unsafe {
            crate::thread::sched::setscheduler_param(
                a[0] as i32,
                Some(a[1] as i32),
                a[2] as *const i32,
            )
        })
    }),
    (Syscall::N_sched_getscheduler, |_, a| {
        crate::abi::raw(crate::thread::sched::getscheduler(a[0] as i32))
    }),
    (Syscall::N_sched_get_priority_max, |_, a| {
        crate::abi::raw(crate::thread::sched::priority_bound(a[0] as i32, true))
    }),
    (Syscall::N_sched_get_priority_min, |_, a| {
        crate::abi::raw(crate::thread::sched::priority_bound(a[0] as i32, false))
    }),
    (Syscall::N_sched_rr_get_interval, |_, a| {
        crate::abi::raw(crate::thread::sched::rr_interval(
            a[0] as i32,
            a[1] as *mut Timespec,
        ))
    }),
    (Syscall::N_sched_setattr, |_, a| {
        // SAFETY: the syscall argument is sched_setattr's guest attr input/output buffer.
        crate::abi::raw(unsafe {
            crate::thread::sched::setattr(a[0] as i32, a[1] as *mut u8, a[2] as u32)
        })
    }),
    (Syscall::N_sched_getattr, |_, a| {
        // SAFETY: the syscall argument is sched_getattr's guest output buffer.
        crate::abi::raw(unsafe {
            crate::thread::sched::getattr(a[0] as i32, a[1] as *mut u8, a[2] as u32, a[3] as u32)
        })
    }),
    (Syscall::N_sched_setaffinity, |_, a| {
        // SAFETY: the syscall argument is sched_setaffinity's guest cpu mask input.
        crate::abi::raw(unsafe {
            crate::thread::sched::setaffinity(
                crate::abi::reg::int(a[0]),
                crate::abi::reg::uint(a[1]),
                crate::abi::reg::ptr::<libc::c_ulong>(a[2])
                    .cast::<u8>()
                    .cast_const(),
            )
        })
    }),
    (Syscall::N_sched_getaffinity, |_, a| {
        // SAFETY: the syscall argument is sched_getaffinity's guest cpu mask output.
        crate::abi::raw(unsafe {
            crate::thread::sched::getaffinity(
                crate::abi::reg::int(a[0]),
                crate::abi::reg::uint(a[1]),
                crate::abi::reg::ptr::<libc::c_ulong>(a[2]).cast::<u8>(),
            )
        })
    }),
    (Syscall::N_getcpu, |_, a| {
        // SAFETY: both syscall arguments are optional writable u32 outputs.
        crate::abi::raw(unsafe { crate::thread::sched::getcpu(a[0] as *mut u32, a[1] as *mut u32) })
    }),
    (Syscall::N_ioprio_set, |_, a| {
        crate::abi::raw(crate::thread::sched::ioprio_set(
            a[0] as i32,
            a[1] as i32,
            a[2] as i32,
        ))
    }),
    (Syscall::N_ioprio_get, |_, a| {
        crate::abi::raw(crate::thread::sched::ioprio_get(a[0] as i32, a[1] as i32))
    }),
    (Syscall::N_nanosleep, |_, a| {
        sys_nanosleep(a[0] as *const Timespec, a[1] as *mut Timespec)
    }),
    (Syscall::N_clock_nanosleep, |_, a| {
        sys_clock_nanosleep(a[0], a[1], a[2] as *const Timespec, a[3] as *mut Timespec)
    }),
    // ---- sync / sched / identity / entropy ----
    (Syscall::N_futex, |_, a| sys_futex(a)),
    (Syscall::N_futex_wait, |_, a| {
        crate::thread::futex2::futex_wait(a)
    }),
    (Syscall::N_futex_wake, |_, a| {
        crate::thread::futex2::futex_wake(a)
    }),
    (Syscall::N_futex_requeue, |_, a| {
        crate::thread::futex2::futex_requeue(a)
    }),
    (Syscall::N_futex_waitv, |_, a| {
        crate::thread::futex2::futex_waitv(a)
    }),
    (Syscall::N_getrandom, |_, a| sys_getrandom(a[0], a[1], a[2])),
    (Syscall::N_sched_yield, |_, _| {
        ret_i32(crate::process::patina_sched_yield())
    }),
    (Syscall::N_gettid, |_, _| {
        crate::process::patina_thread_id() as i64
    }),
    // SAFETY: the guest keeps clear_child_tid writable until its task exits.
    (Syscall::N_set_tid_address, |_, a| unsafe {
        crate::thread::signals::patina_set_tid_address(a[0] as *mut i32)
    }),
    (Syscall::N_exit, |_, a| {
        crate::thread::signals::patina_raw_exit(a[0] as c_int)
    }),
    (Syscall::N_exit_group, |_, a| {
        crate::thread::signals::patina_raw_exit_group(a[0] as c_int)
    }),
    // ---- memory: the mapping rows go through the one mapping model (a file
    // mapping is a view of the file's page cache); the rest is process-local
    // and passed through to the host kernel via the glibc `syscall(2)` HOST
    // ALIAS (never the interposed `syscall`).
    (Syscall::N_mmap, |_, a| sys_mmap(a)),
    (Syscall::N_munmap, |_, a| sys_munmap(a)),
    (Syscall::N_mremap, |_, a| sys_mremap(a)),
    (Syscall::N_msync, |_, a| sys_msync(a)),
    (Syscall::N_mprotect, |_, a| sys_mprotect(a)),
    (Syscall::N_pkey_mprotect, |_, a| sys_pkey_mprotect(a)),
    (Syscall::N_pkey_alloc, |_, a| sys_pkey_alloc(a)),
    (Syscall::N_pkey_free, |_, a| sys_pkey_free(a)),
    (Syscall::N_map_shadow_stack, |_, a| sys_map_shadow_stack(a)),
    (Syscall::N_madvise, mem_passthrough),
    (Syscall::N_brk, mem_passthrough),
    (Syscall::N_mincore, mem_passthrough),
    (Syscall::N_mlock, |_, a| {
        crate::mem::patina_mlock(a[0] as usize, a[1] as usize, 0)
    }),
    (Syscall::N_mlock2, |_, a| {
        crate::mem::patina_mlock(a[0] as usize, a[1] as usize, a[2] as u32)
    }),
    (Syscall::N_munlock, |_, a| {
        crate::mem::patina_munlock(a[0] as usize, a[1] as usize)
    }),
    (Syscall::N_mlockall, |_, a| {
        crate::mem::patina_mlockall(a[0] as c_int)
    }),
    (Syscall::N_munlockall, |_, _| {
        crate::mem::patina_munlockall()
    }),
    // ---- resource limits: the virtual kernel's (`crate::mem`) ----
    (Syscall::N_getrlimit, |_, a| sys_getrlimit(a[0], a[1])),
    (Syscall::N_setrlimit, |_, a| sys_setrlimit(a[0], a[1])),
    // SAFETY: prlimit copies its optional guest limit structures through uaccess.
    (Syscall::N_prlimit64, |_, a| unsafe {
        crate::limits::patina_prlimit(a[0] as c_int, a[1] as u32, a[2] as *const _, a[3] as *mut _)
    }),
    (Syscall::N_remap_file_pages, mem_passthrough),
    // SAFETY: memfd_create reads the guest name through uaccess.
    (Syscall::N_memfd_create, |_, a| unsafe {
        ret_i32(crate::mem::patina_memfd_create(
            a[0] as *const c_char,
            a[1] as u32,
        ))
    }),
    (Syscall::N_memfd_secret, |_, a| {
        ret_i32(crate::mem::patina_memfd_secret(a[0] as u32))
    }),
    // ---- System V IPC: the one-process model (`thread::ipc`) ----
    (Syscall::N_shmget, |_, a| {
        crate::thread::ipc::shmget(a[0] as i32, a[1] as usize, a[2] as i32)
    }),
    (Syscall::N_shmat, |_, a| {
        crate::thread::ipc::shmat(a[0] as i32, a[1] as usize, a[2] as i32)
    }),
    (Syscall::N_shmdt, |_, a| {
        crate::thread::ipc::shmdt(a[0] as usize)
    }),
    // SAFETY: shmctl accesses the guest control structure through uaccess.
    (Syscall::N_shmctl, |_, a| unsafe {
        crate::thread::ipc::shmctl(a[0] as i32, a[1] as i32, a[2] as *mut _)
    }),
    (Syscall::N_semget, |_, a| {
        crate::thread::ipc::semget(a[0] as i32, a[1] as i32, a[2] as i32)
    }),
    (Syscall::N_semop, |_, a| {
        crate::thread::ipc::semtimedop(
            a[0] as i32,
            a[1] as *const _,
            a[2] as usize,
            std::ptr::null(),
        )
    }),
    (Syscall::N_semtimedop, |_, a| {
        crate::thread::ipc::semtimedop(
            a[0] as i32,
            a[1] as *const _,
            a[2] as usize,
            a[3] as *const _,
        )
    }),
    // SAFETY: semctl copies guest arguments through uaccess.
    (Syscall::N_semctl, |_, a| unsafe {
        crate::thread::ipc::semctl(a[0] as i32, a[1] as i32, a[2] as i32, a[3] as usize)
    }),
    (Syscall::N_msgget, |_, a| {
        crate::thread::ipc::msgget(a[0] as i32, a[1] as i32)
    }),
    // SAFETY: msgsnd copies the guest message through uaccess.
    (Syscall::N_msgsnd, |_, a| unsafe {
        crate::thread::ipc::msgsnd(a[0] as i32, a[1] as *const u8, a[2] as usize, a[3] as i32)
    }),
    // SAFETY: msgrcv copies the guest message through uaccess.
    (Syscall::N_msgrcv, |_, a| unsafe {
        crate::thread::ipc::msgrcv(
            a[0] as i32,
            a[1] as *mut u8,
            a[2] as usize,
            a[3] as i64,
            a[4] as i32,
        )
    }),
    // SAFETY: msgctl accesses the guest control structure through uaccess.
    (Syscall::N_msgctl, |_, a| unsafe {
        crate::thread::ipc::msgctl(a[0] as i32, a[1] as i32, a[2] as *mut _)
    }),
    // ---- POSIX message queues: the one-process model (`thread::ipc`) ----
    // SAFETY: mq_open reads both guest inputs through uaccess.
    (Syscall::N_mq_open, |_, a| unsafe {
        crate::thread::ipc::mq_open(
            a[0] as *const c_char,
            a[1] as i32,
            a[2] as u32,
            a[3] as *const _,
        )
    }),
    // SAFETY: mq_unlink reads the guest name through uaccess.
    (Syscall::N_mq_unlink, |_, a| unsafe {
        crate::thread::ipc::mq_unlink(a[0] as *const c_char)
    }),
    // SAFETY: mq_timedsend copies its message and timeout through uaccess.
    (Syscall::N_mq_timedsend, |_, a| unsafe {
        crate::thread::ipc::mq_timedsend(
            arg_fd(a[0]) as c_int,
            a[1] as *const u8,
            a[2] as usize,
            a[3] as u32,
            a[4] as *const _,
        )
    }),
    // SAFETY: mq_timedreceive copies its message, priority and timeout through uaccess.
    (Syscall::N_mq_timedreceive, |_, a| unsafe {
        crate::thread::ipc::mq_timedreceive(
            arg_fd(a[0]) as c_int,
            a[1] as *mut u8,
            a[2] as usize,
            a[3] as *mut u32,
            a[4] as *const _,
        )
    }),
    // SAFETY: mq_notify copies the guest notification structure through uaccess.
    (Syscall::N_mq_notify, |_, a| unsafe {
        crate::thread::ipc::mq_notify(arg_fd(a[0]) as c_int, a[1] as *const _)
    }),
    // SAFETY: mq_getsetattr copies its guest attributes through uaccess.
    (Syscall::N_mq_getsetattr, |_, a| unsafe {
        crate::thread::ipc::mq_getsetattr(arg_fd(a[0]) as c_int, a[1] as *const _, a[2] as *mut _)
    }),
    // ---- memory policy on the one memory node (`crate::numa`) ----
    // SAFETY: set_mempolicy validates and copies the guest node mask through uaccess.
    (Syscall::N_set_mempolicy, |_, a| unsafe {
        crate::numa::set_mempolicy(a[0] as i32, a[1] as *const u64, a[2])
    }),
    // SAFETY: get_mempolicy writes optional guest results through uaccess.
    (Syscall::N_get_mempolicy, |_, a| unsafe {
        crate::numa::get_mempolicy(
            a[0] as *mut i32,
            a[1] as *mut u64,
            a[2],
            a[3] as usize,
            a[4],
        )
    }),
    // SAFETY: mbind validates and copies the guest node mask through uaccess.
    (Syscall::N_mbind, |_, a| unsafe {
        crate::numa::mbind(
            a[0] as usize,
            a[1] as usize,
            a[2] as i32,
            a[3] as *const u64,
            a[4],
            a[5] as u32,
        )
    }),
    // SAFETY: move_pages accesses page, node and status arrays through uaccess.
    (Syscall::N_move_pages, |_, a| unsafe {
        crate::numa::move_pages(
            a[0] as i32,
            a[1] as usize,
            a[2] as *const usize,
            a[3] as *const i32,
            a[4] as *mut i32,
            a[5] as i32,
        )
    }),
    // SAFETY: migrate_pages validates and copies both guest node masks through uaccess.
    (Syscall::N_migrate_pages, |_, a| unsafe {
        crate::numa::migrate_pages(a[0] as i32, a[1], a[2] as *const u64, a[3] as *const u64)
    }),
    (Syscall::N_set_mempolicy_home_node, |_, a| {
        crate::numa::set_mempolicy_home_node(a[0] as usize, a[1] as usize, a[2], a[3])
    }),
    (Syscall::N_membarrier, |_, a| {
        crate::mem::membarrier(a[0] as c_int, a[1] as u32, a[2] as c_int)
    }),
    // ---- signals / process rows owned by the signals conformance family ----
    // `rt_sigaction` for SIGSYS would replace the dispatch handler: fatal.
    // SAFETY: the signal action core copies guest structures through uaccess.
    (Syscall::N_rt_sigaction, |_, a| unsafe {
        patina_signal_action(
            a[0] as i32,
            a[1] as *const Action,
            a[2] as *mut Action,
            a[3] as usize,
        )
    }),
    // SAFETY: the signal mask core copies guest sets through uaccess.
    (Syscall::N_rt_sigprocmask, |_, a| unsafe {
        patina_signal_mask(
            a[0] as i32,
            a[1] as *const u64,
            a[2] as *mut u64,
            a[3] as usize,
        )
    }),
    // Both vehicles answer a guest's `rt_sigreturn` before dispatch (the
    // SIGSYS handler and the `syscall(2)` entry resume at the host's own
    // `rt_sigreturn` with the guest's stack pointer, `c/posix/init.c`): it
    // changes control flow, which no return value can.
    (Syscall::N_rt_sigreturn, |nr, _| {
        crate::trap_fatal(&format!(
            "rt_sigreturn (nr {nr}) reached the dispatcher: both vehicles answer it first"
        ))
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_arch_prctl, thread_pointer::sys_arch_prctl),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_modify_ldt, thread_pointer::sys_modify_ldt),
    (Syscall::N_set_robust_list, |_, a| {
        crate::thread::registrations::set_robust_list(a[0] as usize, a[1] as usize)
    }),
    (Syscall::N_pidfd_open, |_, a| {
        pidfd::sys_pidfd_open(a[0], a[1])
    }),
    (Syscall::N_pidfd_getfd, |nr, a| {
        privileged::answer(nr, privileged::pidfd_getfd, a)
    }),
    (Syscall::N_pidfd_send_signal, |_, a| {
        pidfd::sys_pidfd_send_signal(a)
    }),
    (Syscall::N_process_mrelease, |_, a| {
        pidfd::sys_process_mrelease(a[0], a[1])
    }),
    (Syscall::N_process_madvise, |nr, a| {
        privileged::answer(nr, privileged::process_madvise, a)
    }),
    (Syscall::N_process_vm_readv, |nr, a| {
        privileged::answer(nr, privileged::process_vm_readv, a)
    }),
    (Syscall::N_process_vm_writev, |nr, a| {
        privileged::answer(nr, privileged::process_vm_writev, a)
    }),
    (Syscall::N_rseq, |_, a| {
        crate::thread::registrations::rseq(a[0] as usize, a[1] as u32, a[2] as i32, a[3] as u32)
    }),
    (Syscall::N_get_robust_list, |nr, a| {
        privileged::answer(nr, privileged::get_robust_list, a)
    }),
    (Syscall::N_kcmp, |nr, a| {
        privileged::answer(nr, privileged::kcmp, a)
    }),
    // No restart block is ever pending (the registry row says why).
    (Syscall::N_restart_syscall, |_, _| -EINTR),
    // SAFETY: signal_pending writes the guest set through uaccess.
    (Syscall::N_rt_sigpending, |_, a| unsafe {
        patina_signal_pending(a[0] as *mut u8, a[1] as usize)
    }),
    // SAFETY: signal_altstack copies optional guest stacks through uaccess.
    (Syscall::N_sigaltstack, |_, a| unsafe {
        patina_signal_altstack(a[0] as *const Stack, a[1] as *mut Stack)
    }),
    // SAFETY: this thread-targeted signal carries no guest siginfo pointer.
    (Syscall::N_tkill, |_, a| unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: None,
                tid: a[0] as i32,
            },
            a[1] as i32,
            GenerationInfo::Thread,
        )
    }),
    // SAFETY: generate_signal copies the optional queued guest info through uaccess.
    (Syscall::N_rt_sigqueueinfo, |_, a| unsafe {
        generate_signal(
            GenerationTarget::Process { pid: a[0] as i32 },
            a[1] as i32,
            GenerationInfo::Queued(a[2] as *const Info),
        )
    }),
    // SAFETY: generate_signal copies the optional queued guest info through uaccess.
    (Syscall::N_rt_tgsigqueueinfo, |_, a| unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: Some(a[0] as i32),
                tid: a[1] as i32,
            },
            a[2] as i32,
            GenerationInfo::Queued(a[3] as *const Info),
        )
    }),
    #[cfg(target_arch = "x86_64")]
    // SAFETY: pause passes only null optional buffers to the signal wait core.
    (Syscall::N_pause, |_, _| unsafe {
        patina_signal_wait(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            8,
            WaitMode::Pause,
        )
    }),
    // SAFETY: the signal wait core copies the guest mask through uaccess.
    (Syscall::N_rt_sigsuspend, |_, a| unsafe {
        patina_signal_wait(
            a[0] as *const u64,
            std::ptr::null_mut(),
            std::ptr::null(),
            a[1] as usize,
            WaitMode::Suspend,
        )
    }),
    // SAFETY: the signal wait core copies its guest set, info and timeout through uaccess.
    (Syscall::N_rt_sigtimedwait, |_, a| unsafe {
        patina_signal_wait(
            a[0] as *const u64,
            a[1] as *mut Info,
            a[2] as *const crate::thread::signals::Timespec,
            a[3] as usize,
            WaitMode::Dequeue,
        )
    }),
    (Syscall::N_kill, |_, a| sys_kill(a[0] as i64, a[1] as i64)),
    (Syscall::N_tgkill, |_, a| {
        sys_tgkill(a[0] as i64, a[1] as i64, a[2] as i64)
    }),
    (Syscall::N_wait4, |_, a| sys_wait4(a[0], a[2])),
    (Syscall::N_waitid, |_, a| sys_waitid(a[0], a[1], a[3])),
    (Syscall::N_getpgid, |_, a| {
        crate::identity::getpgid(a[0] as i32)
    }),
    (Syscall::N_getsid, |_, a| {
        crate::identity::getsid(a[0] as i32)
    }),
    // ---- fd I/O ----
    (Syscall::N_read, |_, a| sys_read(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_write, |_, a| sys_write(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_close, |_, a| sys_close(arg_fd(a[0]))),
    (Syscall::N_lseek, |_, a| {
        sys_lseek(arg_fd(a[0]), a[1] as i64, a[2])
    }),
    (Syscall::N_pread64, |_, a| {
        sys_pread(arg_fd(a[0]), a[1], a[2], a[3] as i64)
    }),
    (Syscall::N_pwrite64, |_, a| {
        sys_pwrite(arg_fd(a[0]), a[1], a[2], a[3] as i64)
    }),
    (Syscall::N_readv, |_, a| {
        sys_readv(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_writev, |_, a| {
        sys_writev(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_preadv, |_, a| {
        sys_preadv(arg_fd(a[0]), a[1], a[2], a[3] as i64, 0)
    }),
    (Syscall::N_pwritev, |_, a| {
        sys_pwritev(arg_fd(a[0]), a[1], a[2], a[3] as i64, 0)
    }),
    (Syscall::N_preadv2, |_, a| {
        sys_preadv2(arg_fd(a[0]), a[1], a[2], a[3] as i64, a[5])
    }),
    (Syscall::N_pwritev2, |_, a| {
        sys_pwritev2(arg_fd(a[0]), a[1], a[2], a[3] as i64, a[5])
    }),
    (Syscall::N_fsync, |_, a| sys_fsync(arg_fd(a[0]))),
    (Syscall::N_fdatasync, |_, a| sys_fsync(arg_fd(a[0]))),
    (Syscall::N_ftruncate, |_, a| {
        sys_ftruncate(arg_fd(a[0]), a[1] as i64)
    }),
    (Syscall::N_fallocate, |_, a| {
        sys_fallocate(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64)
    }),
    (Syscall::N_flock, |_, a| {
        sys_flock(arg_fd(a[0]), a[1] as i64)
    }),
    (Syscall::N_dup, |_, a| sys_dup(arg_fd(a[0]))),
    (Syscall::N_dup3, |_, a| {
        sys_dup3(arg_fd(a[0]), arg_fd(a[1]), a[2])
    }),
    (Syscall::N_close_range, |_, a| {
        sys_close_range(a[0], a[1], a[2])
    }),
    (Syscall::N_fcntl, |_, a| sys_fcntl(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_ioctl, |_, a| sys_ioctl(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_pipe2, |_, a| sys_pipe2(a[0], a[1])),
    // ---- filesystem ----
    (Syscall::N_openat, |_, a| {
        sys_openat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_openat2, |_, a| {
        sys_openat2(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_fstat, |_, a| sys_fstat(arg_fd(a[0]), a[1])),
    (Syscall::N_newfstatat, |_, a| {
        sys_newfstatat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_statx, |_, a| {
        sys_statx(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_statfs, |_, a| sys_statfs(a[0], a[1])),
    (Syscall::N_name_to_handle_at, |_, a| {
        sys_name_to_handle_at(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    // ---- extended attributes ----
    (Syscall::N_getxattr, |_, a| {
        sys_getxattr(a[0], a[1], a[2], a[3], true)
    }),
    (Syscall::N_lgetxattr, |_, a| {
        sys_getxattr(a[0], a[1], a[2], a[3], false)
    }),
    (Syscall::N_fgetxattr, |_, a| {
        sys_fgetxattr(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_listxattr, |_, a| {
        sys_listxattr(a[0], a[1], a[2], true)
    }),
    (Syscall::N_llistxattr, |_, a| {
        sys_listxattr(a[0], a[1], a[2], false)
    }),
    (Syscall::N_flistxattr, |_, a| {
        sys_flistxattr(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_setxattr, |_, a| {
        sys_setxattr(a[0], a[1], a[2], a[3], a[4], true)
    }),
    (Syscall::N_lsetxattr, |_, a| {
        sys_setxattr(a[0], a[1], a[2], a[3], a[4], false)
    }),
    (Syscall::N_fsetxattr, |_, a| {
        sys_fsetxattr(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_removexattr, |_, a| {
        sys_removexattr(a[0], a[1], true)
    }),
    (Syscall::N_lremovexattr, |_, a| {
        sys_removexattr(a[0], a[1], false)
    }),
    (Syscall::N_fremovexattr, |_, a| {
        sys_fremovexattr(arg_fd(a[0]), a[1])
    }),
    // ---- in-kernel copies ----
    (Syscall::N_copy_file_range, |_, a| {
        // SAFETY: copy_file_range copies optional guest offsets through uaccess.
        ret_isize(unsafe {
            crate::transfer::patina_copy_file_range(
                arg_fd(a[0]) as c_int,
                a[1] as *mut i64,
                arg_fd(a[2]) as c_int,
                a[3] as *mut i64,
                a[4] as usize,
                a[5] as u32,
            )
        })
    }),
    (Syscall::N_sendfile, |_, a| {
        // SAFETY: sendfile copies its optional guest offset through uaccess.
        ret_isize(unsafe {
            crate::transfer::patina_sendfile(
                arg_fd(a[0]) as c_int,
                arg_fd(a[1]) as c_int,
                a[2] as *mut i64,
                a[3] as usize,
            )
        })
    }),
    (Syscall::N_splice, |_, a| {
        // SAFETY: splice copies its optional guest offsets through uaccess.
        ret_isize(unsafe {
            crate::transfer::patina_splice(
                arg_fd(a[0]) as c_int,
                a[1] as *mut i64,
                arg_fd(a[2]) as c_int,
                a[3] as *mut i64,
                a[4] as usize,
                a[5] as u32,
            )
        })
    }),
    (Syscall::N_tee, |_, a| {
        ret_isize(crate::transfer::patina_tee(
            arg_fd(a[0]) as c_int,
            arg_fd(a[1]) as c_int,
            a[2] as usize,
            a[3] as u32,
        ))
    }),
    (Syscall::N_vmsplice, |_, a| {
        // SAFETY: vmsplice copies the guest iovec array through uaccess.
        ret_isize(unsafe {
            crate::transfer::patina_vmsplice(
                arg_fd(a[0]) as c_int,
                (a[1] as *const c_void).cast(),
                a[2] as i64,
                a[3] as u32,
            )
        })
    }),
    // ---- page-cache advice and writeback ----
    (
        Syscall::N_sync,
        |_, _| ret_i32(crate::advice::patina_sync()),
    ),
    (Syscall::N_syncfs, |_, a| {
        ret_i32(crate::advice::patina_syncfs(arg_fd(a[0]) as c_int))
    }),
    (Syscall::N_sync_file_range, |_, a| {
        ret_i32(crate::advice::patina_sync_file_range(
            arg_fd(a[0]) as c_int,
            a[1] as i64,
            a[2] as i64,
            a[3] as u32,
        ))
    }),
    (Syscall::N_readahead, |_, a| {
        ret_i32(crate::advice::patina_readahead(
            arg_fd(a[0]) as c_int,
            a[1] as i64,
            a[2] as usize,
        ))
    }),
    (Syscall::N_fadvise64, |_, a| {
        ret_i32(crate::advice::patina_fadvise(
            arg_fd(a[0]) as c_int,
            a[1] as i64,
            a[2] as i64,
            a[3] as c_int,
        ))
    }),
    (Syscall::N_cachestat, |_, a| {
        crate::advice::cachestat(
            arg_fd(a[0]) as c_int,
            a[1] as usize,
            a[2] as usize,
            a[3] as u32,
        )
    }),
    (Syscall::N_fstatfs, |_, a| sys_fstatfs(arg_fd(a[0]), a[1])),
    (Syscall::N_getdents64, |_, a| {
        sys_getdents64(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_mkdirat, |_, a| {
        sys_mkdirat(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_mknodat, |_, a| {
        sys_mknodat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_unlinkat, |_, a| {
        sys_unlinkat(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_symlinkat, |_, a| {
        sys_symlinkat(a[0], arg_fd(a[1]), a[2])
    }),
    (Syscall::N_readlinkat, |_, a| {
        sys_readlinkat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_linkat, |_, a| {
        sys_linkat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], a[4])
    }),
    (Syscall::N_renameat, |_, a| {
        sys_renameat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], 0)
    }),
    (Syscall::N_renameat2, |_, a| {
        sys_renameat(arg_fd(a[0]), a[1], arg_fd(a[2]), a[3], a[4])
    }),
    // `faccessat` carries no flags in the kernel ABI; `faccessat2` adds them.
    // rustix tries `faccessat2` first and falls back to `faccessat` on ENOSYS,
    // so BOTH are routed — a soft deny on `faccessat2` would print its
    // diagnostic on every `..` component a capability-based guest walks.
    (Syscall::N_faccessat, |_, a| {
        sys_faccessat(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_faccessat2, |_, a| {
        sys_faccessat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    // The working directory and the umask: process state the shim keeps, the
    // same state the C getcwd/chdir/fchdir/umask interposers use.
    (Syscall::N_getcwd, |_, a| sys_getcwd(a[0], a[1])),
    (Syscall::N_chdir, |_, a| sys_chdir(a[0])),
    (Syscall::N_fchdir, |_, a| sys_fchdir(arg_fd(a[0]))),
    (Syscall::N_umask, |_, a| sys_umask(a[0])),
    // Same shape for `fchmodat`/`fchmodat2`.
    (Syscall::N_fchmod, |_, a| sys_fchmod(arg_fd(a[0]), a[1])),
    (Syscall::N_fchmodat, |_, a| {
        sys_fchmodat(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_fchmodat2, |_, a| {
        sys_fchmodat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    // Timestamps, ownership and sizes: the same `patina_*` entries the C
    // utimensat/chown/truncate families call.
    (Syscall::N_utimensat, |_, a| {
        sys_utimensat(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_fchownat, |_, a| {
        sys_fchownat(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_fchown, |_, a| {
        sys_fchown(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_truncate, |_, a| sys_truncate(a[0], a[1] as i64)),
    // ---- network: the shared socket entries, argument for argument ----
    (Syscall::N_socket, |_, a| sys_socket(a[0], a[1], a[2])),
    (Syscall::N_socketpair, |_, a| {
        sys_socketpair(a[0], a[1], a[2], a[3])
    }),
    (Syscall::N_bind, |_, a| sys_bind(arg_fd(a[0]), a[1], a[2])),
    (Syscall::N_listen, |_, a| sys_listen(arg_fd(a[0]), a[1])),
    (Syscall::N_connect, |_, a| {
        sys_connect(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_accept, |_, a| {
        sys_accept(arg_fd(a[0]), a[1], a[2], 0)
    }),
    (Syscall::N_accept4, |_, a| {
        sys_accept(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_sendto, |_, a| {
        sys_sendto(arg_fd(a[0]), a[1], a[2], a[3], a[4], a[5])
    }),
    (Syscall::N_recvfrom, |_, a| {
        sys_recvfrom(arg_fd(a[0]), a[1], a[2], a[3], a[4], a[5])
    }),
    (Syscall::N_sendmsg, |_, a| {
        sys_sendmsg(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_recvmsg, |_, a| {
        sys_recvmsg(arg_fd(a[0]), a[1], a[2])
    }),
    (Syscall::N_sendmmsg, |_, a| {
        sys_sendmmsg(arg_fd(a[0]), a[1], a[2], a[3])
    }),
    (Syscall::N_recvmmsg, |_, a| {
        sys_recvmmsg(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_shutdown, |_, a| sys_shutdown(arg_fd(a[0]), a[1])),
    (Syscall::N_getsockname, |_, a| {
        sys_name(arg_fd(a[0]), a[1], a[2], false)
    }),
    (Syscall::N_getpeername, |_, a| {
        sys_name(arg_fd(a[0]), a[1], a[2], true)
    }),
    (Syscall::N_setsockopt, |_, a| {
        sys_setsockopt(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    (Syscall::N_getsockopt, |_, a| {
        sys_getsockopt(arg_fd(a[0]), a[1], a[2], a[3], a[4])
    }),
    // ---- readiness ----
    (Syscall::N_epoll_create1, |_, a| sys_epoll_create1(a[0])),
    (Syscall::N_epoll_ctl, |_, a| {
        sys_epoll_ctl(arg_fd(a[0]), a[1] as i64, arg_fd(a[2]), a[3])
    }),
    (Syscall::N_epoll_pwait, |_, a| {
        sys_epoll_pwait(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64, a[4], a[5])
    }),
    (Syscall::N_epoll_pwait2, |_, a| {
        sys_epoll_pwait2(arg_fd(a[0]), a[1], a[2] as i64, a[3], a[4], a[5])
    }),
    (Syscall::N_eventfd2, |_, a| sys_eventfd2(a[0], a[1] as i64)),
    (Syscall::N_ppoll, |_, a| {
        sys_ppoll(a[0], a[1], a[2], a[3], a[4])
    }),
    // ---- process: the ONLY prctl option routed is PR_GET_AUXV ----
    (Syscall::N_prctl, |_, a| {
        sys_prctl(a[0], a[1], a[2], a[3], a[4])
    }),
    // ---- x86_64 legacy aliases (route to the SAME modern handler) ----
    // rustix's linux_raw backend and hand-written asm reach for the legacy
    // non-`*at` forms on x86_64; each is exactly its modern form with dirfd =
    // AT_FDCWD (and, for `creat`, synthesized flags). Only the x86_64 table
    // lists these rows, so their identities, and these bindings, exist only
    // there; the ones with a decode of their own bind a handler from
    // `x86_64.rs`.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_open, |_, a| {
        sys_openat(AT_FDCWD, a[0], a[1], a[2])
    }),
    // `creat(path, mode)` is `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`: the
    // mode is the SECOND argument here, not the third.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_creat, |_, a| {
        sys_openat(AT_FDCWD, a[0], O_CREAT | O_WRONLY | O_TRUNC, a[1])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_stat, |_, a| {
        sys_newfstatat(AT_FDCWD, a[0], a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_lstat, |_, a| {
        sys_newfstatat(AT_FDCWD, a[0], a[1], AT_SYMLINK_NOFOLLOW)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_unlink, |_, a| sys_unlinkat(AT_FDCWD, a[0], 0)),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_rmdir, |_, a| {
        sys_unlinkat(AT_FDCWD, a[0], AT_REMOVEDIR)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_mkdir, |_, a| sys_mkdirat(AT_FDCWD, a[0], a[1])),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_mknod, |_, a| {
        sys_mknodat(AT_FDCWD, a[0], a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_rename, |_, a| {
        sys_renameat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_link, |_, a| {
        sys_linkat(AT_FDCWD, a[0], AT_FDCWD, a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_symlink, |_, a| {
        sys_symlinkat(a[0], AT_FDCWD, a[1])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_readlink, |_, a| {
        sys_readlinkat(AT_FDCWD, a[0], a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_access, |_, a| {
        sys_faccessat(AT_FDCWD, a[0], a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_chmod, |_, a| {
        sys_fchmodat(AT_FDCWD, a[0], a[1], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_chown, |_, a| {
        sys_fchownat(AT_FDCWD, a[0], a[1], a[2], 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_lchown, |_, a| {
        sys_fchownat(AT_FDCWD, a[0], a[1], a[2], AT_SYMLINK_NOFOLLOW)
    }),
    // The pre-utimensat time rows: whole seconds (`utime`), microseconds
    // (`utimes`, `futimesat`), each decoded onto the one set-times entry.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_utime, |_, a| sys_utime(a[0], a[1])),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_utimes, |_, a| {
        sys_futimesat(AT_FDCWD, a[0], a[1])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_futimesat, |_, a| {
        sys_futimesat(arg_fd(a[0]), a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_dup2, |_, a| sys_dup2(arg_fd(a[0]), arg_fd(a[1]))),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_ustat, |_, a| sys_ustat(a[0], a[1])),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_sysfs, |_, a| {
        crate::volume::sysfs(a[0], a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_getdents, |_, a| {
        sys_getdents(arg_fd(a[0]), a[1], a[2])
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_pipe, |_, a| sys_pipe2(a[0], 0)),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_eventfd, |_, a| sys_eventfd2(a[0], 0)),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_inotify_init, |_, _| {
        crate::thread::inotify::init1(0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_epoll_create, |_, a| sys_epoll_create(a[0])),
    // `epoll_wait` is `epoll_pwait` with no signal mask, in the kernel too.
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_epoll_wait, |_, a| {
        sys_epoll_pwait(arg_fd(a[0]), a[1], a[2] as i64, a[3] as i64, 0, 0)
    }),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_poll, |_, a| {
        sys_poll(a[0], a[1], a[2] as i32 as i64)
    }),
];
