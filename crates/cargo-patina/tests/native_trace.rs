//! Whole-run containment of ordinary std, on BOTH Linux architectures.
//! macOS has no whole-run trace: ktrace cannot separate loader from guest, so
//! the static audit and instruction scan are its containment evidence.
#![cfg(target_os = "linux")]
mod common;

mod linux {
    use super::*;

    use common::native::*;
    use std::process::Command;

    const TRACE_SET: &str = concat!(
        "trace=%file,%network,%desc,%memory,%clock,nanosleep,gettimeofday,futex,",
        "rt_sigaction,rt_sigprocmask,rt_sigreturn,sigaltstack,sched_yield,",
        "exit_group,exit,getrandom,process_vm_readv,process_vm_writev"
    );

    #[test]
    fn std_whole_run_and_planted_openat_use_identical_filter() {
        assert_success(Command::new("strace").arg("--version").output().unwrap());
        let clean = Guest::assert_build("std_probe.rs");
        let leak = assert_build_c_guest("escape_syscall_probe.c", CLink::Unlinked);
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("strace.log");
        let trace_and_filter = |binary: &std::path::Path| {
            // Cargo's loader search paths are not needed by these standalone guests.
            let out = assert_success(
                Command::new("strace")
                    .args(["-f", "-s", "4096", "-e", TRACE_SET, "-o"])
                    .arg(&trace)
                    .arg(binary)
                    .env_remove("LD_LIBRARY_PATH")
                    .env("PATINA_RT_MODE", "seeded")
                    .env("PATINA_RT_SEED", "9")
                    .output()
                    .unwrap(),
            );
            let denied = assert_success(
                Command::new("awk")
                    .arg("-f")
                    .arg(guest_source("containment.awk"))
                    .arg(&trace)
                    .output()
                    .unwrap(),
            )
            .stdout;
            (out, denied)
        };
        let (_, denied) = trace_and_filter(&leak.binary);
        assert!(
            text(&denied)
                .lines()
                .any(|l| l.starts_with("openat(") && l.contains("\"/etc/hostname\"")),
            "planted escape not caught by filter: {}",
            text(&denied)
        );
        let (out, denied) = trace_and_filter(&clean.binary);
        assert_exact_line(&out.stdout, "PATINA_STRACE_MARKER");
        assert_eq!(text(&denied), "", "syscalls escaped deterministic boundary");
    }
}
