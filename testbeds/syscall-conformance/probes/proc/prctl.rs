//! proc/prctl — the process-local prctl options (man 2 prctl): PR_SET_NAME
//! truncation to 15 bytes, PR_SET/GET_PDEATHSIG (a signal number, EINVAL past
//! SIGRTMAX), PR_SET/GET_DUMPABLE (only 0 or 1 settable; 2 is EINVAL),
//! PR_SET_NO_NEW_PRIVS (only 1, with zero trailing arguments; sticky),
//! PR_SET/GET_TIMERSLACK (0 restores the 50 µs default), and EINVAL (not
//! ENOSYS) for an unknown option.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::ffi::CStr;
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        let long = b"abcdefghijklmnopQRST\0";
        p.check(
            "PR_SET_NAME accepts a long name",
            p.prctl(PR_SET_NAME, long.as_ptr() as u64, 0, 0, 0) == 0,
        );
        let mut name = [0 as c_char; 16];
        p.check(
            "PR_GET_NAME reads the truncated name",
            p.prctl(PR_GET_NAME, name.as_mut_ptr() as u64, 0, 0, 0) == 0,
        );
        let got = unsafe { CStr::from_ptr(name.as_ptr()) }.to_bytes().to_vec();
        p.rec
            .event("prctl_name", 0)
            .field("name", String::from_utf8_lossy(&got).as_ref())
            .emit();
        p.check(
            "PR_SET_NAME truncates to 15 bytes plus NUL",
            got == b"abcdefghijklmno",
        );

        p.check(
            "PR_SET_PDEATHSIG SIGTERM",
            p.prctl(PR_SET_PDEATHSIG, SIGTERM as u64, 0, 0, 0) == 0,
        );
        let mut pdeath = 0i32;
        p.check(
            "PR_GET_PDEATHSIG reads it back",
            p.prctl(PR_GET_PDEATHSIG, &mut pdeath as *mut i32 as u64, 0, 0, 0) == 0
                && pdeath == SIGTERM,
        );
        p.check(
            "PR_SET_PDEATHSIG past SIGRTMAX is EINVAL",
            p.prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0) == neg(EINVAL),
        );
        p.check(
            "PR_SET_PDEATHSIG 0 clears it",
            p.prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) == 0,
        );
        p.check(
            "PR_GET_PDEATHSIG reads 0 after the clear",
            p.prctl(PR_GET_PDEATHSIG, &mut pdeath as *mut i32 as u64, 0, 0, 0) == 0 && pdeath == 0,
        );
        p.check(
            "PR_GET_PDEATHSIG with a NULL pointer is EFAULT",
            p.prctl(PR_GET_PDEATHSIG, 0, 0, 0, 0) == neg(EFAULT),
        );

        p.check(
            "PR_GET_DUMPABLE starts at 1",
            p.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1,
        );
        p.check(
            "PR_SET_DUMPABLE 2 is EINVAL (not settable through prctl)",
            p.prctl(PR_SET_DUMPABLE, 2, 0, 0, 0) == neg(EINVAL),
        );
        p.check(
            "PR_SET_DUMPABLE 0",
            p.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0,
        );
        p.check(
            "PR_GET_DUMPABLE reads 0",
            p.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0,
        );
        p.check(
            "PR_SET_DUMPABLE 1 restores it",
            p.prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0,
        );

        p.check(
            "PR_GET_NO_NEW_PRIVS starts at 0",
            p.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0,
        );
        p.check(
            "PR_SET_NO_NEW_PRIVS 0 is EINVAL (only 1 can be set)",
            p.prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == neg(EINVAL),
        );
        p.check(
            "PR_SET_NO_NEW_PRIVS 1 with a nonzero trailing argument is EINVAL",
            p.prctl(PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0) == neg(EINVAL),
        );
        p.check(
            "PR_SET_NO_NEW_PRIVS 1",
            p.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
        );
        p.check(
            "PR_GET_NO_NEW_PRIVS reads 1",
            p.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1,
        );
        p.check(
            "PR_SET_NO_NEW_PRIVS 0 is still EINVAL (sticky)",
            p.prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == neg(EINVAL),
        );

        p.check(
            "PR_GET_TIMERSLACK starts at the 50 µs default",
            p.prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50_000,
        );
        p.check(
            "PR_SET_TIMERSLACK accepts a value",
            p.prctl(PR_SET_TIMERSLACK, 123456, 0, 0, 0) == 0,
        );
        p.check(
            "PR_GET_TIMERSLACK reads it back",
            p.prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 123456,
        );
        p.check(
            "PR_SET_TIMERSLACK 0 restores the default",
            p.prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0) == 0,
        );
        p.check(
            "PR_GET_TIMERSLACK reads the default again",
            p.prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50_000,
        );
        p.require(
            "unknown prctl option is EINVAL",
            p.prctl(0x7fff_ffff, 0, 0, 0, 0) == neg(EINVAL),
        );
    }
}

syscall_conformance::probe_main!("proc/prctl", scenario::run);
