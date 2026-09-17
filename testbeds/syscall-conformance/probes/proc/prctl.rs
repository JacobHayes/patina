//! proc/prctl — modeled process-local prctl options: name truncation,
//! PDEATHSIG, dumpable, no_new_privs, timerslack, and unknown-option EINVAL.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::ffi::CStr;
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        let long = b"abcdefghijklmnopQRST\0";
        p.check("PR_SET_NAME accepts a long name", p.prctl(PR_SET_NAME, long.as_ptr() as u64, 0, 0, 0) == 0);
        let mut name = [0i8; 16];
        p.check("PR_GET_NAME reads the truncated name", p.prctl(PR_GET_NAME, name.as_mut_ptr() as u64, 0, 0, 0) == 0);
        let got = unsafe { CStr::from_ptr(name.as_ptr()) }.to_bytes().to_vec();
        p.rec.event("prctl_name", 0).field("name", String::from_utf8_lossy(&got).as_ref()).emit();
        p.check("PR_SET_NAME truncates to 15 bytes plus NUL", got == b"abcdefghijklmno");

        p.check("PR_SET_PDEATHSIG SIGTERM", p.prctl(PR_SET_PDEATHSIG, SIGTERM as u64, 0, 0, 0) == 0);
        let mut pdeath = 0i32;
        p.check("PR_GET_PDEATHSIG reads it back", p.prctl(PR_GET_PDEATHSIG, &mut pdeath as *mut i32 as u64, 0, 0, 0) == 0 && pdeath == SIGTERM);
        p.check("PR_SET_DUMPABLE 0", p.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
        p.check("PR_GET_DUMPABLE reads 0", p.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
        p.check("PR_SET_NO_NEW_PRIVS 1", p.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        p.check("PR_GET_NO_NEW_PRIVS reads 1", p.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
        p.check("PR_SET_TIMERSLACK accepts a value", p.prctl(PR_SET_TIMERSLACK, 123456, 0, 0, 0) == 0);
        p.check("PR_GET_TIMERSLACK reads it back", p.prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 123456);
        p.require("unknown prctl option is EINVAL", p.prctl(0x7fff_ffff, 0, 0, 0, 0) == neg(EINVAL));
    }
}

syscall_conformance::probe_main!("proc/prctl", scenario::run);
