//! abi/newer-than-virtual — a number the vendored table lists but the virtual
//! ABI level predates (`fchroot`, 472, first in Linux 7.3; the registry row is
//! `Absent`) answers ENOSYS through every vehicle, exactly as a kernel of the
//! declared level does — never a trap, never the host's newer semantics.
//! Natively the host kernel must lack the number too: the host gate marks the
//! probe HOST-UNAVAILABLE on a kernel that implements it.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe, AT_FDCWD};

    pub fn run(p: &Probe) {
        let r = p.fchroot(AT_FDCWD, 0);
        p.check(
            "a number past the virtual ABI level is ENOSYS",
            r == neg(ENOSYS),
        );
        // The number is judged before its arguments: a kernel that implements
        // it would answer EBADF here.
        let r = p.fchroot(-1, 0);
        p.check("ENOSYS regardless of the arguments", r == neg(ENOSYS));
    }
}

syscall_conformance::probe_main!("abi/newer-than-virtual", scenario::run);
