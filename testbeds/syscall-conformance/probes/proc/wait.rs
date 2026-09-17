//! proc/wait — childless wait4/waitid answers: ECHILD, WNOHANG, and invalid
//! option EINVAL.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        p.check("wait4(-1) without children is ECHILD", p.wait4(-1, 0).0 == neg(ECHILD));
        p.check("wait4(-1,WNOHANG) without children is ECHILD", p.wait4(-1, WNOHANG).0 == neg(ECHILD));
        p.check("waitid(P_ALL) without children is ECHILD", p.waitid(P_ALL as i32, 0, WEXITED).0 == neg(ECHILD));
        p.check("waitid WNOHANG without children is ECHILD", p.waitid(P_ALL as i32, 0, WEXITED | WNOHANG).0 == neg(ECHILD));
        p.check("waitid invalid options are EINVAL", p.waitid(P_ALL as i32, 0, 0x4000_0000).0 == neg(EINVAL));
    }
}

syscall_conformance::probe_main!("proc/wait", scenario::run);
