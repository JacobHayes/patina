//! Whole-run containment of ordinary std, on BOTH Linux architectures.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use std::io::Write;

#[cfg(target_os = "linux")]
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
        let available = Command::new("strace").arg("--version").output();
        match available {
            Ok(out) => {
                assert_success(out);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                assert_ne!(
                    std::env::var("PATINA_REQUIRE_STRACE").as_deref(),
                    Ok("1"),
                    "PATINA_REQUIRE_STRACE=1 but strace is missing"
                );
                // Bypass libtest capture: the unmet runtime proof is visible even
                // on a successful ordinary cargo test.
                writeln!(
                    std::io::stderr(),
                    "SKIPPED native_trace: strace not installed; no runtime containment evidence"
                )
                .unwrap();
                return;
            }
            Err(e) => panic!("strace discovery: {e}"),
        }
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
                    .env("PATINA_MODE", "seeded")
                    .env("PATINA_SEED", "9")
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

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;

    #[test]
    fn ktrace_requirement_is_explicitly_unsupported() {
        assert_ne!(
            std::env::var("PATINA_REQUIRE_KTRACE").as_deref(),
            Ok("1"),
            concat!(
                "PATINA_REQUIRE_KTRACE=1: macOS whole-run containment cannot be verified: ",
                "ktrace lacks decoded path context and a pre-main/post-init boundary"
            )
        );
        let reason = concat!(
            "SKIPPED native_trace: macOS ktrace cannot separate loader from guest; ",
            "static audit and instruction scan are the containment evidence"
        );
        writeln!(std::io::stderr(), "{reason}").unwrap();
    }
}
