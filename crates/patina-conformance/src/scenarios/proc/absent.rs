//! proc/absent — removed syscall numbers (fifteen on x86_64, two on the
//! generic table) are byte-identical ENOSYS, not modeled traps or host
//! escapes.

use crate::catalog::{DEFAULTS, Scenario};

use crate::probe::{Probe, neg};
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    for row in [
        #[cfg(target_arch = "x86_64")]
        Syscall::N__sysctl,
        Syscall::N_nfsservctl,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_vserver,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_security,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_tuxcall,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_afs_syscall,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_getpmsg,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_putpmsg,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_ctl_old,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_wait_old,
        Syscall::N_lookup_dcookie,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_create_module,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_query_module,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_get_kernel_syms,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_uselib,
    ] {
        let result = p.call_observed(row, [0; 6]);
        p.check(
            &format!("{} is ENOSYS", row.name()),
            result == neg(libc::ENOSYS),
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/absent",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N__sysctl,
        Syscall::N_nfsservctl,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_vserver,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_security,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_tuxcall,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_afs_syscall,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_getpmsg,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_putpmsg,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_ctl_old,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_wait_old,
        Syscall::N_lookup_dcookie,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_create_module,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_query_module,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_get_kernel_syms,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_uselib,
    ],
    symbols: &["syscall"],
    ..DEFAULTS
};
