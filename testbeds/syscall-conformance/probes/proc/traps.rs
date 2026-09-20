//! proc/traps — process-creating/replacing rows are harmless native calls here
//! but must be named process traps under patina.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::ffi::CString;
    use syscall_conformance::calls::{neg, Probe};
    use syscall_conformance::vehicle::Sys;

    pub fn run(p: &Probe) {
        if Sys::Fork.has_number() {
            unsafe {
                let r = p.call_unrecorded(Sys::Fork, [0; 6]);
                if r == 0 { _exit(0); }
                let mut st = 0;
                waitpid(r as pid_t, &mut st, 0);
                p.rec.event("fork", 0).emit();
            }
            p.check("fork child exited cleanly", true);
        } else {
            eprintln!("proc/traps: SKIPPED 1 fork row (no architecture number)");
        }

        p.check("clone with impossible flags is EINVAL", p.call_observed(Sys::Clone, [!0, 0, 0, 0, 0, 0]) == neg(EINVAL));
        p.check("clone3 with null args and size 0 is EINVAL", p.call_observed(Sys::Clone3, [0, 0, 0, 0, 0, 0]) == neg(EINVAL));
        let missing = CString::new("/tmp/syscall-conformance/no-such-exec").unwrap();
        let argv: [*const c_char; 2] = [missing.as_ptr(), std::ptr::null()];
        let envp: [*const c_char; 1] = [std::ptr::null()];
        p.check("execve missing path is ENOENT", p.call_observed(Sys::Execve, [missing.as_ptr() as i64, argv.as_ptr() as i64, envp.as_ptr() as i64, 0, 0, 0]) == neg(ENOENT));
        p.check("execveat missing path is ENOENT", p.call_observed(Sys::Execveat, [AT_FDCWD as i64, missing.as_ptr() as i64, argv.as_ptr() as i64, envp.as_ptr() as i64, 0, 0]) == neg(ENOENT));
    }
}

syscall_conformance::probe_main!("proc/traps", scenario::run);
