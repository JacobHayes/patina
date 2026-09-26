//! Patina-only containment, with planted failures beside the positive controls.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;
#[cfg(target_os = "linux")]
const RESERVED_SIGNAL_DIAGNOSTIC: &str =
    "reserved signal registration would disable deterministic containment";

#[test]
fn audit_rejects_unlinked_raw_syscall_or_thread_escape() {
    let escape = assert_build_c_guest("escape_probe.c", CLink::Unlinked);
    assert_refused(
        escape.command("audit", &[]),
        &["not built with `cargo patina build`"],
    );
    let out = assert_refused(escape.command("audit", &["--raw"]), &["PATINA_RAW_AUDIT"]);
    let error = text(&out.stderr);
    assert!(
        error.contains("direct-syscall") || error.contains("unmanaged-thread"),
        "{error}"
    );
}

#[test]
fn audit_rejects_unknown_import() {
    let unknown = assert_build_c_guest("unknown_import_probe.c", CLink::Unlinked);
    assert_refused(unknown.command("audit", &["--raw"]), &["unknown-import"]);
}

#[test]
fn audit_rejects_shared_memory_import() {
    let ipc = assert_build_c_guest("shared_ipc_refusal_probe.c", CLink::Unlinked);
    assert_refused(ipc.command("audit", &["--raw"]), &["shared-memory-ipc"]);
}

#[test]
fn prerun_refuses_shm_open_and_hatch_warns() {
    let g = Guest::assert_build("gate_refusal_probe.rs");
    let out = g.assert_run_refused(1, &["shm_open", "shared-memory-ipc"]);
    assert!(!text(&out.stdout).contains("GATE_REFUSAL_RAN"));
    let hatch = g.assert_run_success(1, &["--allow-unsupported-symbols", "all"]);
    assert_eq!(text(&hatch.stdout), "GATE_REFUSAL_RAN\n");
    assert!(text(&hatch.stderr).contains("WARNING"));
}

// A guest that writes the thread pointer itself is refused before it runs, by
// class and by instruction, on each architecture's own encodings.
#[test]
fn thread_pointer_writes_are_refused_by_name() {
    let g = Guest::assert_build("thread_pointer_probe.rs");
    let out = g.assert_run_refused(1, &["thread-pointer"]);
    assert!(!text(&out.stdout).contains("THREAD_POINTER_PROBE_RAN"));
    let audit = assert_refused(g.command("audit", &["--format", "json"]), &[]);
    let envelope: serde_json::Value = serde_json::from_str(text(&audit.stdout).trim())
        .unwrap_or_else(|error| panic!("audit JSON: {error}: {}", text(&audit.stdout)));
    assert_eq!(envelope["exit_code"], 2, "{envelope:#}");
    let mut mnemonics: Vec<_> = envelope["finding_details"]
        .as_array()
        .expect("finding_details")
        .iter()
        .filter(|detail| detail["category"] == "thread-pointer")
        .map(|detail| detail["mnemonic"].as_str().unwrap_or_default())
        .collect();
    mnemonics.sort();
    let expected: &[&str] = if cfg!(target_arch = "x86_64") {
        &["mov fs", "wrfsbase"]
    } else {
        &["msr tpidr_el0"]
    };
    assert_eq!(mnemonics, expected);
}

// The syscall doors to the same effect: moving the FS base with
// arch_prctl(ARCH_SET_FS), and writing an LDT descriptor an FS selector load
// could use, stop the run by name.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn thread_pointer_syscalls_are_refused_by_name() {
    let g = assert_build_c_guest("thread_pointer_syscalls.c", CLink::PosixShim);
    for (case, refused) in [
        ("tp-set-fs", "thread-pointer: arch_prctl(ARCH_SET_FS, "),
        (
            "tp-write-ldt",
            "thread-pointer: modify_ldt(0x11) writing LDT entry 0 refused",
        ),
    ] {
        g.assert_internal_fatal(&[case], &[refused]);
    }
}

#[test]
fn original_envp_is_scrubbed() {
    let g = assert_build_c_guest("envp_probe.c", CLink::PosixShim);
    let out = assert_standalone_success(
        &g.binary,
        &[],
        &[
            ("PATINA_MODE", "seeded"),
            ("PATINA_SEED", "9"),
            ("PATINA_ENVP_CANARY", "leak"),
            ("ENVP_CANARY", "leak"),
        ],
    );
    assert_eq!(
        text(&out.stdout),
        "NATIVE_ENVP_RESULT count=0 first=<none>\n"
    );
}

#[test]
fn host_environment_canaries_never_enter_guest_or_replay() {
    let g = Guest::assert_build("env_probe.rs");
    g.assert_audit_clean();
    let trace = g.dir.path().join("env.patina");
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        common::invoke_in_with_env(common::native_workspace(), args, envs).stdout
    };
    let bin = g.binary.to_str().unwrap();
    let first = run(
        &["run", bin, "--seed", "3"],
        &[("PATINA_ENV_CANARY_HOST", "one")],
    );
    assert_eq!(text(&first), "NATIVE_ENV_RESULT vars=0\n");
    assert_eq!(
        first,
        run(&["run", bin, "--seed", "3"], &[("CANARY_HOST", "two")])
    );
    assert_eq!(
        first,
        run(
            &[
                "run",
                bin,
                "--seed",
                "3",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "env-v1"
            ],
            &[("CANARY_HOST", "one")]
        )
    );
    assert_eq!(
        first,
        run(
            &[
                "replay",
                bin,
                trace.to_str().unwrap(),
                "--fingerprint",
                "env-v1"
            ],
            &[("CANARY_HOST", "two")]
        )
    );
}

#[test]
fn dlsym_routes_the_shim_definitions_and_no_host_name() {
    let g = Guest::assert_build("dlsym_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(1, &[]);
    let fields = assert_fields(
        &out,
        "NATIVE_DLSYM_ENTROPY ",
        &["link", "getrandom", "getentropy"],
    );
    assert_eq!(
        fields["link"],
        if cfg!(target_os = "linux") {
            "wrapped"
        } else {
            "table-only"
        }
    );
    assert_lower_hex(fields["getrandom"], 48);
    assert_lower_hex(fields["getentropy"], 48);
    g.assert_seed_variation(&[1, 2], &[]);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Write;

    #[test]
    fn audit_reports_sud_marker_and_kernel_requirement() {
        let g = Guest::assert_build("raw_syscall_probe.rs");
        let audit = g.assert_audit_clean();
        let audit = format!("{}{}", text(&audit.stdout), text(&audit.stderr));
        assert!(audit.contains("SUD-managed"), "{audit}");
        assert!(audit.contains("refused on kernels without it"), "{audit}");
    }

    #[test]
    fn unmarked_raw_syscall_is_refused() {
        let planted = assert_build_c_guest("planted_raw.c", CLink::Unlinked);
        assert_refused(planted.command("audit", &["--raw"]), &["direct-syscall"]);
    }

    #[test]
    fn raw_syscalls_are_virtualized_or_refused_before_execution() {
        let g = Guest::assert_build("raw_syscall_probe.rs");
        if kernel_supports(KernelFeature::Sud) {
            let out = g.assert_seeded_record_replay_identity(5, &[]);
            let fields = assert_fields(&out, "RAW_SUD_RESULT ", &["fs", "rand", "threads_virtual"]);
            assert_eq!(fields["fs"], "sud");
            assert_lower_hex(fields["rand"], 16);
            assert_eq!(fields["threads_virtual"], "true");
            g.assert_seed_variation(&[1, 2, 3, 4], &[]);
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
            let trace = g.dir.path().join("invalid.patina");
            std::fs::write(&trace, []).unwrap();
            assert_refused(
                g.command("replay", &[trace.to_str().unwrap()]),
                &["lacks syscall-user-dispatch"],
            );
        }
    }

    #[test]
    fn unmapped_raw_syscall_aborts_with_named_diagnostic() {
        let g = Guest::assert_build("raw_unmapped_probe.rs");
        if kernel_supports(KernelFeature::Sud) {
            let out = g.assert_run_refused(1, &["SUD trapped syscall number 4095"]);
            assert!(!text(&out.stdout).contains("UNMAPPED_RET="));
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
        }
    }

    #[test]
    fn sud_scrubs_vdso_auxv() {
        if !kernel_supports(KernelFeature::Sud) {
            writeln!(
                std::io::stderr(),
                "SKIPPED sud_scrubs_vdso_auxv: host lacks syscall-user-dispatch"
            )
            .unwrap();
            return;
        }
        let g = Guest::assert_build("auxv_probe.rs");
        assert_eq!(
            text(&g.assert_run_success(1, &[]).stdout),
            "AUXV_SYSINFO_EHDR=0\n"
        );
    }

    #[test]
    fn sigsys_registration_is_refused_on_every_kernel() {
        let g = Guest::assert_build("sigsys_probe.rs");
        g.assert_run_refused(1, &[RESERVED_SIGNAL_DIAGNOSTIC]);
        #[cfg(target_arch = "x86_64")]
        if let Some(c) = sud_c_guest("signals/signal_boundary.c") {
            for door in ["reserved-sys-libc", "reserved-sys-raw"] {
                c.assert_internal_fatal(&[door], &[RESERVED_SIGNAL_DIAGNOSTIC]);
            }
        }
    }

    #[test]
    fn at_random_is_seeded_on_every_kernel() {
        let g = Guest::assert_build("at_random_probe.rs");
        let out = g.assert_seed_repeatability(1, 2, &[]);
        assert_lower_hex(assert_unique_line_payload(&out, "AT_RANDOM="), 32);
        g.assert_seed_variation(&[1, 2], &[]);
    }

    #[cfg(target_arch = "x86_64")]
    mod x86_64 {
        use super::*;

        #[test]
        fn vsyscall_materialization_is_refused() {
            let g = assert_build_c_guest("vsyscall_probe.c", CLink::Unlinked);
            assert_refused(g.command("audit", &["--raw"]), &["vsyscall"]);
        }

        #[test]
        fn tsc_reads_answer_from_virtual_clock() {
            let g = Guest::assert_build("tsc_probe.rs");
            let audit = g.assert_audit_clean();
            let audit = text(&audit.stdout);
            assert!(audit.contains("TSC-trap-managed, 2 sites"), "{audit}");
            assert_eq!(
                audit.lines().filter(|l| l.contains("instruction@")).count(),
                2
            );
            if kernel_supports(KernelFeature::Tsc) {
                let ran = g.assert_run_success(7, &[]);
                assert!(text(&ran.stderr).contains("timestamp-counter instruction site(s)"));
                assert_eq!(
                    text(&ran.stdout),
                    concat!(
                        "TSC step=0 rdtsc=0 rdtscp=0 aux=0\n",
                        "TSC step=1 rdtsc=5000000 rdtscp=5000000 aux=0\n",
                        "TSC step=2 rdtsc=10000000 rdtscp=10000000 aux=0\n",
                        "TSC total_ticks=15000000\n",
                    )
                );
                assert_eq!(ran.stdout, g.assert_run_success(7, &[]).stdout);
                let trace = g.assert_record_replay_identity(7, &[], &ran.stdout);
                let trace = std::fs::read_to_string(trace).unwrap();
                let values: Vec<serde_json::Value> = trace
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                assert!(values.iter().any(|v| json_contains(v, "tsc", &true.into())));
                assert!(
                    values
                        .iter()
                        .any(|v| json_contains(v, "kind", &"clock_now".into())
                            && json_contains(v, "clock", &"monotonic".into()))
                );
            } else {
                g.assert_run_refused(7, &["cpu-nondeterminism"]);
            }
        }

        #[test]
        fn rdrand_is_refused_on_every_kernel() {
            let rdrand = Guest::assert_build("rdrand_probe.rs");
            rdrand.assert_run_refused(1, &["untrappable anywhere", "cannot clear one"]);
        }

        #[test]
        fn tsc_sleep_jitter_moves_counter() {
            let g = Guest::assert_build("tsc_probe.rs");
            if kernel_supports(KernelFeature::Tsc) {
                let baseline = g.assert_run_success(1, &[]).stdout;
                let flags = ["--sleep-jitter-nanos", "0..4000000"];
                let jittered = g.assert_seed_repeatability(1, 2, &flags);
                assert_ne!(jittered, baseline);
                g.assert_seed_variation(&[1, 2], &flags);
            } else {
                g.assert_run_refused(1, &["cpu-nondeterminism"]);
            }
        }

        #[test]
        fn genuine_segv_is_not_swallowed() {
            let g = Guest::assert_build("tsc_segv_probe.rs");
            if kernel_supports(KernelFeature::Tsc) {
                let out = g.assert_run_refused(1, &["PATINA_INFRA native_run signal=11"]);
                assert!(!text(&out.stdout).contains("SURVIVED THE FAULT"));
            } else {
                g.assert_run_refused(1, &["cpu-nondeterminism"]);
            }
        }

        #[test]
        fn sigsegv_handler_hijack_is_refused() {
            let g = Guest::assert_build("tsc_hijack_probe.rs");
            if kernel_supports(KernelFeature::Tsc) {
                g.assert_run_refused(1, &[RESERVED_SIGNAL_DIAGNOSTIC]);
                if let Some(c) = sud_c_guest("signals/signal_boundary.c") {
                    for door in ["reserved-segv-libc", "reserved-segv-raw"] {
                        c.assert_internal_fatal(&[door], &[RESERVED_SIGNAL_DIAGNOSTIC]);
                    }
                }
            } else {
                g.assert_run_refused(1, &["cpu-nondeterminism"]);
            }
        }

        fn json_contains(
            value: &serde_json::Value,
            key: &str,
            expected: &serde_json::Value,
        ) -> bool {
            match value {
                serde_json::Value::Object(map) => {
                    map.get(key) == Some(expected)
                        || map.values().any(|v| json_contains(v, key, expected))
                }
                serde_json::Value::Array(items) => {
                    items.iter().any(|v| json_contains(v, key, expected))
                }
                _ => false,
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;

    #[test]
    fn os_unfair_lock_foreign_unlock_aborts() {
        let g = Guest::assert_build("os_unfair_lock_misuse_probe.rs");
        let out = g.assert_run_refused(1, &["os_unfair_lock_unlock"]);
        assert!(!text(&out.stdout).contains("OS_UNFAIR_LOCK_MISUSE_SURVIVED"));
    }
}
