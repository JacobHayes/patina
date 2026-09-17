//! proc/absent — removed x86_64 syscall numbers are byte-identical ENOSYS, not
//! modeled traps or host escapes.

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::calls::{neg, Probe};
    use syscall_conformance::vehicle::Sys;

    pub fn run(p: &Probe) {
        for sys in [
            Sys::Sysctl,
            Sys::Nfsservctl,
            Sys::Vserver,
            Sys::Security,
            Sys::Tuxcall,
            Sys::AfsSyscall,
            Sys::Getpmsg,
            Sys::Putpmsg,
            Sys::EpollCtlOld,
            Sys::EpollWaitOld,
            Sys::LookupDcookie,
            Sys::CreateModule,
            Sys::QueryModule,
            Sys::GetKernelSyms,
            Sys::Uselib,
        ] {
            let result = p.call_observed(sys, [0; 6]);
            p.check(&format!("{} is ENOSYS", sys.name()), result == neg(libc::ENOSYS));
        }
    }
}

syscall_conformance::probe_main!("proc/absent", scenario::run);
