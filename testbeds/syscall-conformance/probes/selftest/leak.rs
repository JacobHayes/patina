//! selftest/leak — the planted host-syscall escape for the strace leak leg: a
//! bare `openat("/etc/hostname")` through `syscall(2)` (every arch). Built
//! natively only; `run.sh --selftest` runs it under the leak leg's strace
//! invocation and requires the filter to flag it. Never blessed, never run
//! under patina.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{Probe, AT_FDCWD};

    pub fn run(p: &Probe) {
        let fd = p.openat(AT_FDCWD, "/etc/hostname", O_RDONLY, 0);
        if fd >= 0 {
            p.close(fd);
        }
    }
}

syscall_conformance::probe_main!("selftest/leak", scenario::run);
