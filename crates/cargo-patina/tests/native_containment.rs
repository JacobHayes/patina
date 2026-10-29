//! Patina-only containment, with planted failures beside the positive controls.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
#[path = "native_containment/layout.rs"]
mod layout;
use common::native::*;

/// The raw audit refuses a stock program's escapes by class: a raw syscall
/// or an unmanaged thread, an unknown import and a shared-memory import; the
/// plain audit refuses a binary `cargo patina build` did not make. On Linux a
/// raw syscall outside the shim is refused before it runs, without blaming a
/// kernel that has syscall-user-dispatch, and on x86_64 a vsyscall
/// materialization is refused.
#[test]
fn raw_audit_refuses_each_unlinked_escape_class() {
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
    for (source, class) in [
        ("unknown_import_probe.c", "unknown-import"),
        ("shared_ipc_refusal_probe.c", "shared-memory-ipc"),
    ] {
        let g = assert_build_c_guest(source, CLink::Unlinked);
        assert_refused(g.command("audit", &["--raw"]), &[class]);
    }
    #[cfg(target_os = "linux")]
    {
        let planted = assert_build_c_guest("planted_raw.c", CLink::Unlinked);
        assert_refused(planted.command("audit", &["--raw"]), &["direct-syscall"]);
        let output = assert_refused(planted.command("run", &[]), &["direct-syscall"]);
        assert_eq!(output.status.code(), Some(2));
        if kernel_supports(KernelFeature::Sud) {
            let diagnostic = format!("{}{}", text(&output.stdout), text(&output.stderr));
            assert!(
                !diagnostic.contains("kernel lacks syscall-user-dispatch"),
                "SUD-capable host was blamed for a non-shim binary:\n{diagnostic}"
            );
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let g = assert_build_c_guest("vsyscall_probe.c", CLink::Unlinked);
        assert_refused(g.command("audit", &["--raw"]), &["vsyscall"]);
    }
}

/// glibc's aliases of names the shim interposes (`__mmap`, `__munmap`) are
/// different linker symbols the shim does not define: they bind into libc and
/// are refused by name instead of letting libc's own text map past the mapping
/// model. A `.symver`-pinned `dlsym@GLIBC_…` reference reaches around the
/// shim's `-Wl,--wrap=dlsym`, which rewrites only unversioned references. The
/// probe's reference is weak, as the shim's own `dlsym` import is, so only its
/// version tells it apart: the binding audit resolves it by that version into
/// libc's own resolver and refuses it before it can resolve a host symbol.
#[cfg(target_os = "linux")]
#[test]
fn prerun_refuses_interposer_aliases_and_a_versioned_dlsym_bypass() {
    let g = Guest::assert_build("versioned_dlsym_probe.rs");
    let diagnostics = [
        "__mmap",
        "__munmap",
        "dlsym@GLIBC_",
        "dynamic-loading",
        "libc.so.6",
    ];
    let out = g.assert_run_refused(1, &diagnostics);
    assert!(!text(&out.stdout).contains("VERSIONED_DLSYM_ESCAPED"));
    assert_refused(g.command("audit", &[]), &diagnostics);
}

/// A versioned reference to a name the shim interposes is no bypass: whether
/// the linker binds `mmap@GLIBC_…` to the executable's own `mmap` (GNU ld) or
/// leaves an import (lld), the loader resolves it to the shim's exported
/// definition before libc's. The guest audits clean and its call is bound to the
/// shim on every linker; refusing it would refuse a contained guest.
#[cfg(target_os = "linux")]
#[test]
fn versioned_interposer_reference_binds_to_the_shim() {
    let check = |g: Guest| {
        g.assert_audit_clean();
        let out = g.assert_run_success(1, &[]);
        assert_exact_line(&out.stdout, "VERSIONED_MMAP_BOUND=shim");
    };
    check(Guest::assert_build("versioned_mmap_probe.rs"));
    // x86-64 links with rustc's lld by default and can also link with GNU ld,
    // aarch64's default, so this host covers both shapes.
    if cfg!(target_arch = "x86_64") {
        check(Guest::assert_build_with(
            "versioned_mmap_probe.rs",
            &[
                "--",
                "-C",
                "linker-features=-lld",
                "-C",
                "link-self-contained=-linker",
            ],
        ));
    }
}

#[test]
fn prerun_refuses_shm_open_and_hatch_warns() {
    let g = Guest::assert_build("gate_refusal_probe.rs");
    let out = g.assert_run_refused(1, &["shm_open", "shared-memory-ipc"]);
    assert!(!text(&out.stdout).contains("GATE_REFUSAL_RAN"));
    // A replay re-checks the gate, so the hatch run is a plain seeded one.
    let hatch = assert_success(g.command(
        "run",
        &["--seed", "1", "--allow-unsupported-symbols", "all"],
    ));
    assert_eq!(text(&hatch.stdout), "GATE_REFUSAL_RAN\n");
    assert!(text(&hatch.stderr).contains("WARNING"));
}

/// An undefined weak reference is NULL only when no library the loader
/// searches defines it. One to a libc export Patina neither interposes nor
/// classifies binds to the host's code at load, so it is refused by name, with
/// the library it binds to, before it runs; one to a hook no loaded library
/// defines stays inert, is listed as such, and runs its fallback.
#[test]
fn a_weak_reference_is_inert_only_when_no_loaded_library_defines_it() {
    let bound = assert_build_c_guest_with_flags(
        "weak_import_probe.c",
        CLink::PosixShim,
        &["-DWEAK_LIBC_EXPORT"],
    );
    let host = if cfg!(target_os = "linux") {
        "libc.so.6"
    } else {
        "getloadavg"
    };
    let out = bound.assert_run_refused(1, &["getloadavg", host]);
    assert!(!text(&out.stdout).contains("WEAK_HOOK"));
    assert_refused(bound.command("audit", &[]), &["getloadavg", host]);

    // ld64 refuses to link a weak reference no dylib defines, so the inert
    // half is ELF's.
    if !cfg!(target_os = "linux") {
        return;
    }
    let inert = assert_build_c_guest("weak_import_probe.c", CLink::PosixShim);
    let audit = inert.assert_audit_clean();
    assert!(text(&audit.stderr).contains("patina_probe_absent_hook"));
    let out = inert.assert_run_success(1, &[]);
    assert_exact_line(&out.stdout, "WEAK_HOOK absent");
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
            ("PATINA_RT_MODE", "seeded"),
            ("PATINA_RT_SEED", "9"),
            ("PATINA_ENVP_CANARY", "leak"),
            ("ENVP_CANARY", "leak"),
        ],
    );
    assert_eq!(
        text(&out.stdout),
        "NATIVE_ENVP_RESULT count=0 first=<none>\n"
    );
}

fn initial_stack_map(entries: usize) -> std::collections::BTreeMap<String, String> {
    (0..entries)
        .map(|i| (format!("STACK_{i:04}"), format!("value={i}")))
        .collect()
}

// Unlike the supervised runs, this controls the guest's actual exec-time
// array size. The three controls plus a reservation marker take four slots;
// padding fills the remainder. The sentinel receives that original count via
// argv.
fn direct_initial_stack(
    guest: &Guest,
    capacity: usize,
    marker: Option<&str>,
    map: &std::collections::BTreeMap<String, String>,
    sentinel: bool,
) -> std::process::Output {
    use patina_dst_runtime::{ENV_GUEST_ENV, ENV_INITIAL_STACK, ENV_MODE, ENV_SEED};
    let mut env = vec![
        (ENV_MODE.to_owned(), "seeded".to_owned()),
        (ENV_SEED.to_owned(), "9".to_owned()),
        (
            ENV_GUEST_ENV.to_owned(),
            serde_json::to_string(map).unwrap(),
        ),
    ];
    if let Some(marker) = marker {
        env.push((ENV_INITIAL_STACK.to_owned(), marker.to_owned()));
    }
    assert!(capacity >= env.len(), "capacity must include the controls");
    for slot in env.len()..capacity {
        env.push((format!("_PATINA_ENVP_SLOT_{slot}"), String::new()));
    }
    let args: Vec<_> = if sentinel {
        vec!["sentinel".to_owned(), env.len().to_string()]
    } else {
        map.iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect()
    };
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    let env: Vec<_> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    standalone_output(&guest.binary, &args, &env)
}

/// Every startup environment reader must agree (`initial_stack_env.c` walks
/// from argv rather than trusting `environ`), and removing entries must keep
/// the platform trailer, not just hide host getenv.
///
/// Supervised, an empty and a many-entry map reach the guest whole, in a
/// recording and its flag-free replay. Direct reserved launches measure this
/// binary's actual trailer and run with zero, one and many surplus slots. A
/// map that exactly fills or exceeds the original array, one slot short, or
/// an invalid marker refuses, each with a positive twin that changes only
/// that input; plenty of space alone is not a reservation: an unmarked
/// nonempty map refuses rather than publish inconsistent argv/envp/environ
/// views, while an unmarked empty map runs.
#[test]
fn the_initial_stack_environment_is_whole_or_refused() {
    use std::os::unix::process::ExitStatusExt;
    // Match the product link's dead-section removal: otherwise the C link
    // retains unused std archive sections and their unrelated host imports.
    let flags = if cfg!(target_os = "linux") {
        &["-Wl,--gc-sections"][..]
    } else {
        &["-Wl,-dead_strip"][..]
    };
    let g = assert_build_c_guest_with_flags("initial_stack_env.c", CLink::PosixShim, flags);
    for entries in [0, 128] {
        let expected: Vec<_> = initial_stack_map(entries)
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        let trace = g.dir.path().join(format!("stack-{entries}.patina"));
        let run = |replay: bool| {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
            command
                .env_clear()
                .arg(if replay { "replay" } else { "run" })
                .arg(&g.binary);
            if replay {
                command.arg(&trace);
            } else {
                command.args(["--seed", "9"]);
                for entry in &expected {
                    command.arg("--env").arg(entry);
                }
                command.arg("--record").arg(&trace);
            }
            command.args(["--fingerprint", "initial-stack-env"]);
            if !replay {
                command.arg("--").args(&expected);
            }
            assert_success(
                common::output_with_deadline(&mut command, std::time::Duration::from_secs(60))
                    .expect("initial-stack guest exceeded 60s"),
            )
        };
        let recorded = run(false);
        assert_eq!(
            text(&recorded.stdout),
            format!("INITIAL_STACK_ENV entries={entries}\n")
        );
        assert_eq!(recorded.stdout, run(true).stdout);
    }

    let sentinel = |output: std::process::Output| {
        assert_eq!(output.status.code(), Some(42), "{output:?}");
        let slots: usize =
            assert_unique_line_payload(&output.stdout, "INITIAL_STACK_TRAILER slots=")
                .parse()
                .expect("positive trailer slot count");
        slots
    };
    let refused = |output: std::process::Output| {
        assert_eq!(output.status.signal(), Some(libc::SIGABRT), "{output:?}");
    };
    let trailer_slots = sentinel(direct_initial_stack(
        &g,
        4,
        None,
        &initial_stack_map(0),
        true,
    ));
    assert!(trailer_slots > 0);
    for entries in [4, 128] {
        let map = initial_stack_map(entries);
        for surplus in [0, 1, patina_dst_runtime::NATIVE_INITIAL_STACK_TRAILER_SLOTS] {
            let capacity = entries + trailer_slots + surplus;
            let out = assert_success(direct_initial_stack(&g, capacity, Some("1"), &map, false));
            assert_eq!(
                text(&out.stdout),
                format!("INITIAL_STACK_ENV entries={entries}\n")
            );
        }
        let required = entries + trailer_slots;
        refused(direct_initial_stack(&g, 4, Some("1"), &map, true));
        refused(direct_initial_stack(
            &g,
            required - 1,
            Some("1"),
            &map,
            true,
        ));
        // Changing only the capacity by one slot crosses the refusal boundary.
        assert_eq!(
            sentinel(direct_initial_stack(&g, required, Some("1"), &map, true)),
            trailer_slots
        );
        refused(direct_initial_stack(
            &g,
            required,
            Some("invalid"),
            &map,
            true,
        ));
        refused(direct_initial_stack(&g, required, None, &map, true));
    }
    let empty = initial_stack_map(0);
    assert_eq!(
        sentinel(direct_initial_stack(&g, trailer_slots, None, &empty, true)),
        trailer_slots
    );
}

/// The host's environment never reaches the guest: whatever canary the host
/// holds, the guest's environment is empty and its own, in a recording and in
/// a replay under another host canary.
#[test]
fn host_environment_canaries_never_enter_guest_or_replay() {
    let g = Guest::assert_build("env_probe.rs");
    g.assert_audit_clean();
    let trace = g.dir.path().join("env.patina");
    let trace = trace.to_str().unwrap();
    let bin = g.binary.to_str().unwrap();
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        common::invoke_in_with_env(common::native_workspace(), args, envs).stdout
    };
    let recorded = run(
        &[
            "run",
            bin,
            "--seed",
            "3",
            "--record",
            trace,
            "--fingerprint",
            "env-v1",
        ],
        &[("PATINA_ENV_CANARY_HOST", "one"), ("CANARY_HOST", "one")],
    );
    assert_eq!(text(&recorded), "NATIVE_ENV_RESULT vars=0\n");
    assert_eq!(
        recorded,
        run(
            &["replay", bin, trace, "--fingerprint", "env-v1"],
            &[("CANARY_HOST", "two")]
        )
    );
}

#[test]
fn dlsym_routes_the_shim_definitions_and_no_host_name() {
    let g = Guest::assert_build("dlsym_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_run_success(1, &[]).stdout;
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
    if cfg!(target_os = "linux") {
        assert_lower_hex(fields["getrandom"], 48);
    } else {
        assert_eq!(fields["getrandom"], "absent");
    }
    assert_lower_hex(fields["getentropy"], 48);
    g.assert_seed_variation(&[1, 2], &[]);
}

/// The captured streams are written through to the host as the guest
/// writes them: a host reader that went away is the host's, never the
/// guest's, so the SIGPIPE it raises neither runs the guest's handler (which
/// would run inside shim code) nor ends the run.
#[cfg(target_os = "linux")]
#[test]
fn a_host_reader_that_went_away_raises_no_guest_sigpipe() {
    use std::os::fd::{FromRawFd, OwnedFd};
    let g = assert_build_c_guest("signals/fault_routing.c", CLink::PosixShim);
    let mut ends = [0; 2];
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    let (reader, writer) =
        unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    drop(reader);
    let output = std::process::Command::new(&g.binary)
        .env_clear()
        .arg("host-pipe")
        .envs([("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "1")])
        .stdout(writer)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(text(&output.stderr).contains("SURVIVED"), "{output:?}");
}

/// `signals/shim_fault.c` over a shim built with `planted-faults`, with the
/// private signal stack's budget report (`signals/private_budget.c`) linked
/// in.
#[cfg(target_os = "linux")]
fn planted_guest() -> Guest {
    let budget = guest_source("signals/private_budget.c");
    assert_build_c_guest_with_flags(
        "signals/shim_fault.c",
        CLink::PosixShimPlanted,
        &[budget.to_str().unwrap()],
    )
}

/// A fault in the shim's own code (planted in a shim entry) is the shim's on
/// every Linux arch, for SIGSEGV, SIGBUS and SIGILL alike: a named stop that
/// takes the signal's default action, never the guest's handler for it.
///
/// Shim code that reaches the shim's own boundary from inside a dispatch
/// (planted, in the dispatch of the guest's own call: `syscall(2)`, which
/// holds the thread around it, or `prctl(2)`, which holds nothing) is a named
/// stop before its call is serviced as the guest's: through the `syscall(2)`
/// door, which the unsealed archive binds shim code's own call to, on every Linux arch,
/// and as a raw syscall instruction, where the host has syscall-user-dispatch.
/// Guest code a shim entry calls nests instead
/// (`native_workloads::cpus::an_allocator_making_system_calls_runs_threads`).
///
/// Each plant says so on stderr before it acts, so an earlier death cannot
/// pass; a serviced reentry writes a marker of its own.
#[cfg(target_os = "linux")]
#[test]
fn shim_faults_are_named_stops_never_the_guests() {
    use std::os::unix::process::ExitStatusExt;
    let g = planted_guest();
    let env = [("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "1")];
    for (case, sig) in [("segv", 11), ("bus", 7), ("ill", 4)] {
        let output = standalone_output(&g.binary, &[case], &env);
        assert_eq!(output.status.signal(), Some(sig), "{case}: {output:?}");
        assert!(
            text(&output.stderr).contains("PATINA_PLANTED_FAULT"),
            "{case}: {output:?}"
        );
    }
    let mut kinds = vec!["door"];
    if cfg!(target_arch = "x86_64") && kernel_supports(KernelFeature::Sud) {
        kinds.push("trap");
    }
    for kind in kinds {
        for outer in ["held", "unheld"] {
            let case = format!("{kind} {outer}");
            let output = standalone_output(&g.binary, &[kind, outer], &env);
            assert_eq!(output.status.signal(), Some(6), "{case}: {output:?}");
            let stderr = text(&output.stderr);
            assert!(
                stderr.contains("PATINA_PLANTED_REENTRY"),
                "{case}: {output:?}"
            );
            assert!(
                !stderr.contains("PATINA_PLANTED_SERVICED"),
                "{case}: {output:?}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Write;

    /// The audit names the SUD-managed raw syscall sites and the kernel
    /// requirement. With syscall-user-dispatch the raw syscalls are served
    /// from the virtual kernel (seeded entropy, virtual threads); without it
    /// the run is refused before anything executes, and a replay's empty
    /// trace is refused before the guest launches.
    #[test]
    fn raw_syscalls_are_virtualized_or_refused_before_execution() {
        let g = Guest::assert_build("raw_syscall_probe.rs");
        let audit = g.assert_audit_clean();
        let audit = format!("{}{}", text(&audit.stdout), text(&audit.stderr));
        assert!(audit.contains("SUD-managed"), "{audit}");
        assert!(audit.contains("refused on kernels without it"), "{audit}");
        if kernel_supports(KernelFeature::Sud) {
            let out = g.assert_run_success(5, &[]).stdout;
            let fields = assert_fields(&out, "RAW_SUD_RESULT ", &["fs", "rand", "threads_virtual"]);
            assert_eq!(fields["fs"], "sud");
            assert_lower_hex(fields["rand"], 16);
            assert_eq!(fields["threads_virtual"], "true");
            g.assert_seed_variation(&[1, 2], &[]);
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
            let trace = g.dir.path().join("invalid.patina");
            std::fs::write(&trace, []).unwrap();
            assert_refused(
                g.command("replay", &[trace.to_str().unwrap()]),
                &["incomplete trace"],
            );
        }
    }

    /// A runtime with small thread stacks makes raw syscalls on stacks of a
    /// few KiB. The syscall trap's frame and dispatch take none of the
    /// guest's stack, recording included: on the main thread and a second
    /// one, raw syscalls with the stack pointer at the top of a 2 KiB stack
    /// write nothing below it, and record and replay print the same.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn trapped_raw_syscalls_leave_a_small_stack_untouched() {
        let g = Guest::assert_build("small_stack_probe.rs");
        if !kernel_supports(KernelFeature::Sud) {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
            return;
        }
        let out = g.assert_run_success(1, &[]).stdout;
        for who in ["main", "thread"] {
            let fields = assert_fields(
                &out,
                &format!("{who}: "),
                &["pid", "tid", "entropy", "clock", "written", "overrun"],
            );
            assert_eq!((fields["written"], fields["overrun"]), ("0", "0"), "{who}");
        }
        assert!(
            text(&out).ends_with("SMALL_STACK_PROBE_OK\n"),
            "{}",
            text(&out)
        );
    }

    /// Class detector for the private signal stack's per-level budget
    /// (`thread/signals/frames.rs`): a trap lands at the top of a level and
    /// everything the shim runs for it stays there, so the depth stop is the
    /// handler count on every host, recording or not, only while a level's
    /// use fits. The guest (over a shim built with `planted-faults`) fills
    /// three levels with a sentinel and, recording, makes syscalls, takes a
    /// signal whose handler makes them, and a nested one inside it: each
    /// level must use at most half its budget, and the page above the nested
    /// handler's level is a guard exactly while it runs. x86_64 makes them as raw
    /// instructions the syscall trap serves; every other arch through
    /// glibc's `syscall(2)`, so there a level holds a delivery's frames.
    #[test]
    fn private_signal_stack_levels_fit_their_budget() {
        if cfg!(target_arch = "x86_64") && !kernel_supports(KernelFeature::Sud) {
            return;
        }
        let (output, _) = planted_guest().record_standalone(&["budget"]);
        assert!(output.status.success(), "{output:?}");
        let fields = assert_fields(&output.stdout, "PRIVATE_BUDGET ", &["level", "used"]);
        let level: usize = fields["level"].parse().unwrap();
        let used: Vec<usize> = fields["used"]
            .split(',')
            .map(|used| used.parse().unwrap())
            .collect();
        let measurement = format!(
            "private signal stack ({}, recording): levels used {used:?} B of {level} B each",
            std::env::consts::ARCH
        );
        eprintln!("{measurement}");
        if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
            writeln!(
                std::fs::OpenOptions::new().append(true).open(path).unwrap(),
                "{measurement}\n"
            )
            .unwrap();
        }
        // The outer and nested deliveries each land in a level of their own
        // (and, on x86_64, the inner handler's trapped syscalls in a third).
        assert!(
            used.len() == 3 && used.iter().filter(|used| **used > 1024).count() >= 2,
            "vacuous measurement: {measurement}"
        );
        assert!(
            used.iter().all(|used| 2 * used <= level),
            "a level needs margin: {measurement}"
        );
        // The level above a running handler's is guarded, and only while it
        // runs.
        assert_exact_line(&output.stdout, "PRIVATE_GUARD inside=EFAULT after=readable");
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

    /// What the kernel hands a process at exec is the virtual kernel's on
    /// every kernel: AT_RANDOM is seeded, and where syscall-user-dispatch
    /// traps raw syscalls the vDSO's auxv entry is scrubbed. A guest's SIGSYS
    /// action is virtual too, through libc and, under SUD, the raw door; a
    /// guest SIGSYS is a named stop.
    #[test]
    fn auxv_and_sigsys_are_virtual_on_every_kernel() {
        let g = Guest::assert_build("auxv_probe.rs");
        let out = g.assert_run_success(1, &[]).stdout;
        assert_lower_hex(assert_unique_line_payload(&out, "AT_RANDOM="), 32);
        assert_exact_line(&out, "SIGSYS guest action roundtrip");
        if kernel_supports(KernelFeature::Sud) {
            assert_exact_line(&out, "AUXV_SYSINFO_EHDR=0");
        }
        g.assert_seed_variation(&[1, 2], &[]);
        #[cfg(target_arch = "x86_64")]
        if let Some(c) = sud_c_guest("signals/signal_boundary.c") {
            for door in ["reserved-sys-libc", "reserved-sys-raw"] {
                assert_standalone_success(
                    &c.binary,
                    &[door],
                    &[("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "1")],
                );
            }
            use std::os::unix::process::ExitStatusExt;
            let output = standalone_output(
                &c.binary,
                &["guest-sigsys"],
                &[("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "1")],
            );
            assert_eq!(output.status.signal(), Some(6), "{output:?}");
            assert!(
                output.stderr.starts_with(b"SIGSYS registered\n"),
                "{output:?}"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    mod x86_64 {
        use super::*;

        /// The counter reads answer from the virtual monotonic clock: each
        /// step's reads lie between the monotonic readings around them
        /// (calls cost virtual time, so no read equals another), a step's
        /// reads lie at least the 5 ms sleep before the next's, and the trace
        /// records them as monotonic clock reads. Seeded sleep jitter moves
        /// the counter with the clock.
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
            if !kernel_supports(KernelFeature::Tsc) {
                g.assert_run_refused(7, &["cpu-nondeterminism"]);
                return;
            }
            let (ran, trace) = g.assert_recorded(7, &[]);
            let out = text(&ran.stdout);
            let field = |line: &str, key: &str| -> u64 {
                let start = line.find(key).unwrap() + key.len();
                line[start..]
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap()
            };
            let steps: Vec<[u64; 4]> = out
                .lines()
                .filter(|line| line.starts_with("TSC step="))
                .map(|line| {
                    assert!(line.ends_with(" aux=0"), "{out}");
                    ["before=", "rdtsc=", "rdtscp=", "after="].map(|key| field(line, key))
                })
                .collect();
            assert_eq!(steps.len(), 3, "{out}");
            for [before, plain, with_aux, after] in &steps {
                assert!(
                    before <= plain && plain <= with_aux && with_aux <= after,
                    "{out}"
                );
            }
            for pair in steps.windows(2) {
                assert!(pair[1][1] >= pair[0][2] + 5_000_000, "{out}");
            }
            let total = field(out.lines().last().unwrap(), "total_ticks=");
            assert!(total >= 15_000_000, "{out}");
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
            let flags = ["--sleep-jitter-nanos", "0..4000000"];
            assert_ne!(g.assert_run_success(7, &flags).stdout, ran.stdout);
            g.assert_seed_variation(&[1, 2], &flags);
        }

        #[test]
        fn rdrand_is_refused_on_every_kernel() {
            let rdrand = Guest::assert_build("rdrand_probe.rs");
            rdrand.assert_run_refused(1, &["untrappable anywhere", "cannot clear one"]);
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

        /// Small native-capable alternate stacks need no room for a second
        /// kernel frame: the counter trap's frame and the runtime are on the
        /// private stack. A counter read on a minimal alternate stack (an
        /// autodisarmed one too) leaves the guest's stack whole, and a counter
        /// read inside a handler on such a stack takes none of it. The TSC
        /// mechanism predates SUD: its stack setup does not depend on the SUD
        /// probe having published the auxiliary vector.
        #[test]
        fn counter_reads_on_a_minimal_altstack_preserve_the_guest_stack() {
            use std::os::unix::process::ExitStatusExt;
            if !kernel_supports(KernelFeature::Tsc) {
                return;
            }
            let source = "signals/counter_small.c";
            let native = assert_build_c_guest(source, CLink::Unlinked);
            assert_standalone_success(&native.binary, &["native-frame"], &[]);
            let patina = assert_build_c_guest(source, CLink::PosixShim);
            let env = [("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "7")];
            let without_sud = assert_build_c_guest(source, CLink::PosixShimWithoutSud);
            for (g, case) in [
                (&patina, "read-fault"),
                (&patina, "read-fault-autodisarm"),
                (&without_sud, "read-fault-nosud"),
            ] {
                let output = standalone_output(&g.binary, &[case], &env);
                assert_eq!(output.status.signal(), Some(11), "{case}: {output:?}");
                assert_eq!(output.stdout, b"COUNTERS ANSWERED\n");
                assert!(output.stderr.is_empty(), "{case}: {output:?}");
            }
            for suffix in ["", "-autodisarm", "-check", "-autodisarm-check"] {
                assert_standalone_success(
                    &native.binary,
                    &[&format!("handler-counter-native{suffix}")],
                    &[],
                );
                let output = assert_standalone_success(
                    &patina.binary,
                    &[&format!("handler-counter{suffix}")],
                    &env,
                );
                assert_eq!(output.stdout, b"HANDLER COUNTERS ANSWERED\n");
            }
        }

        /// A guest SIGSEGV handler, through either door, is the guest's own
        /// action: the trap keeps the host disposition, so the counter read
        /// after the registration is still answered from the virtual clock
        /// and never reaches the handler.
        #[test]
        fn sigsegv_handler_cannot_take_over_the_counter_trap() {
            let g = Guest::assert_build("tsc_hijack_probe.rs");
            if kernel_supports(KernelFeature::Tsc) {
                assert_eq!(
                    text(&g.assert_run_success(1, &[]).stdout),
                    "HIJACK answered=true handler_calls=0\n"
                );
                if let Some(c) = sud_c_guest("signals/signal_boundary.c") {
                    for door in ["reserved-segv-libc", "reserved-segv-raw"] {
                        let (output, _) = c.record_standalone(&[door]);
                        assert!(output.status.success(), "{door}: {output:?}");
                    }
                }
            } else {
                g.assert_run_refused(1, &["cpu-nondeterminism"]);
            }
        }

        /// A counter read the trap does not answer (here a REX-prefixed
        /// `rdtsc`, which the CPU executes as one) is a named stop: natively
        /// it reads the counter and runs on, so the guest's handler must not
        /// get it as a SIGSEGV.
        #[test]
        fn a_counter_read_the_trap_declines_is_a_named_stop() {
            use std::os::unix::process::ExitStatusExt;
            if !kernel_supports(KernelFeature::Tsc) {
                return;
            }
            let native = assert_build_c_guest("signals/segv_routing.c", CLink::Unlinked);
            let patina = assert_build_c_guest("signals/segv_routing.c", CLink::PosixShim);
            assert_standalone_success(&native.binary, &["prefixed"], &[]);
            let env = [("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "7")];
            let output = standalone_output(&patina.binary, &["prefixed"], &env);
            assert_eq!(output.status.signal(), Some(6), "{output:?}");
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

/// Every reference in the program's load set is judged by the image it binds
/// to: application libraries are audited as the executable is, and what the
/// loader would run before the shim's containment is refused before it can.
#[cfg(target_os = "linux")]
mod load_set {
    use super::*;
    use std::path::{Path, PathBuf};

    /// `lib<stem>.so` in `dir`, named by that soname and finding its own
    /// dependencies in `dir`.
    fn library(name: &str, dir: &Path, flags: &[&str]) -> PathBuf {
        let stem = Path::new(name).file_stem().unwrap().to_str().unwrap();
        let soname = format!("-Wl,-soname,lib{stem}.so");
        let rpath = format!("-Wl,-rpath,{}", dir.display());
        let mut all = vec![soname.as_str(), rpath.as_str()];
        all.extend_from_slice(flags);
        assert_build_c_library(name, dir, &all)
    }

    /// `main` over the POSIX layer, linked against `library`, plus `flags`.
    fn guest_over(main: &str, library: &Path, flags: &[&str]) -> Guest {
        let rpath = format!("-Wl,-rpath,{}", library.parent().unwrap().display());
        let mut all = vec![library.to_str().unwrap(), rpath.as_str()];
        all.extend_from_slice(flags);
        assert_build_c_guest_with_flags(main, CLink::PosixShim, &all)
    }

    fn assert_refused_before_running(g: &Guest, diagnostics: &[&str], marker: &str) {
        let out = g.assert_run_refused(1, diagnostics);
        let seen = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(!seen.contains(marker), "{marker} ran:\n{seen}");
        assert!(!seen.contains("LOAD_SET_MAIN"), "{seen}");
        let out = assert_refused(g.command("audit", &[]), diagnostics);
        let seen = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(!seen.contains(marker), "{marker} ran:\n{seen}");
    }

    /// A library two links from the executable that calls a libc export is
    /// refused naming that library and libc.
    #[test]
    fn a_transitive_library_binding_into_libc_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let b = library("load_set_chain_b.c", dir.path(), &[]);
        let a = library("load_set_chain_a.c", dir.path(), &[b.to_str().unwrap()]);
        let g = guest_over("load_set_main.c", &a, &[]);
        assert_refused_before_running(
            &g,
            &["libload_set_chain_b.so", "getloadavg", "libc.so.6"],
            "LOAD_SET_MAIN",
        );
    }

    /// A library's `write` binds to the shim's definition the executable
    /// exports, so it runs and replays deterministically; with the
    /// executable's exports hidden by a version script it binds to libc's
    /// instead, around the shim, and is refused.
    #[test]
    fn a_librarys_modeled_io_runs_through_the_shim_and_is_refused_around_it() {
        let dir = tempfile::tempdir().unwrap();
        let io = library("load_set_io.c", dir.path(), &[]);
        let contained = guest_over("load_set_main.c", &io, &[]);
        contained.assert_audit_clean();
        let out = contained.assert_run_success(1, &[]);
        assert_exact_line(&out.stdout, "LOAD_SET_IO");
        let script = dir.path().join("hide.map");
        std::fs::write(&script, "{ global: main; local: *; };\n").unwrap();
        let version_script = format!("-Wl,--version-script={}", script.display());
        let hidden = guest_over("load_set_main.c", &io, &[version_script.as_str()]);
        assert_refused_before_running(
            &hidden,
            &["libload_set_io.so", "write", "libc.so.6"],
            "LOAD_SET_IO",
        );
    }

    /// A library's weak `dlsym` is a guest resolver: the executable's own
    /// vehicle admits only the executable's reference.
    #[test]
    fn a_librarys_weak_resolver_reference_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let lib = library("load_set_weak_dlsym.c", dir.path(), &[]);
        let g = guest_over("load_set_main.c", &lib, &[]);
        assert_refused_before_running(
            &g,
            &["libload_set_weak_dlsym.so", "dlsym", "dynamic-loading"],
            "LOAD_SET_MAIN",
        );
    }

    /// A weak reference libc defines binds there, so it is judged by the
    /// effect policy rather than listed as inert.
    #[test]
    fn a_weak_reference_libc_defines_is_host_bound_not_inert() {
        let g = assert_build_c_guest("weak_thread_atexit_probe.c", CLink::PosixShim);
        let audit = g.assert_audit_clean();
        assert!(
            !text(&audit.stderr).contains("__cxa_thread_atexit_impl"),
            "{}",
            text(&audit.stderr)
        );
        let out = g.assert_run_success(1, &[]);
        assert_exact_line(&out.stdout, "THREAD_ATEXIT bound");
    }

    /// What the loader runs before the shim's preinit entry is refused before
    /// the loader runs at all: an rtld-audit module (it would run even while
    /// the load set is listed), a library initialized first, and an IFUNC
    /// resolver the executable's relocation calls.
    #[test]
    fn code_the_loader_runs_before_containment_is_refused_before_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let module = assert_build_c_library("load_set_audit_module.c", dir.path(), &[]);
        let audit = format!("-Wl,--audit={}", module.display());
        let audited =
            assert_build_c_guest_with_flags("weak_import_probe.c", CLink::PosixShim, &[&audit]);
        assert_refused_before_running(&audited, &["DT_AUDIT"], "AUDIT_MODULE_RAN");

        let first = library("load_set_initfirst.c", dir.path(), &["-Wl,-z,initfirst"]);
        let g = guest_over("load_set_main.c", &first, &[]);
        assert_refused_before_running(
            &g,
            &["libload_set_initfirst.so", "DF_1_INITFIRST"],
            "INITFIRST_RAN",
        );

        let g = assert_build_c_guest("load_set_ifunc.c", CLink::PosixShim);
        assert_refused_before_running(&g, &["ifunc-resolver"], "IFUNC_RESOLVER_RAN");
    }
}

// Code that runs before `__libc_start_main`: a shared library's constructor
// (from `_dl_init`, before the executable's own constructors) and a guest's
// own `.preinit_array` entry. Containment is armed from the shim's preinit
// entry, which must be the executable's only one.
#[cfg(target_os = "linux")]
mod early_init {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    /// A CPU other than the virtual CPU 0 this process may run on.
    fn allowed_cpu_other_than_zero() -> Option<usize> {
        // SAFETY: an all-zero cpu_set_t is empty; sched_getaffinity fills it.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::cpu_set_t>();
        // SAFETY: `set` is a writable cpu_set_t of `size` bytes.
        if unsafe { libc::sched_getaffinity(0, size, &mut set) } != 0 {
            return None;
        }
        // SAFETY: `set` is initialized and every index is within CPU_SETSIZE.
        (1..libc::CPU_SETSIZE as usize).find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
    }

    /// An inline syscall or counter read in a library constructor is refused
    /// by the pre-run audit, which scans the library's code; run without the
    /// gate, it lies outside the main executable's text: a named stop, never
    /// a host effect. A library constructor already reads the virtual CPU
    /// from glibc's rseq area, even on a host CPU other than 0, and a library
    /// doing only that audits clean.
    #[test]
    fn library_constructor_escapes_stop_by_name() {
        let libs = tempfile::tempdir().unwrap();
        let library = assert_build_c_library("dso_ctor_escape.c", libs.path(), &[]);
        let rpath = format!("-Wl,-rpath,{}", libs.path().display());
        let flags = [library.to_str().unwrap(), rpath.as_str()];
        let g = assert_build_c_guest_with_flags("dso_ctor_probe.c", CLink::PosixShim, &flags);
        assert_refused(
            g.command("audit", &[]),
            &["libdso_ctor_escape.so", "direct-syscall"],
        );
        let rseq_libs = tempfile::tempdir().unwrap();
        let rseq_library = assert_build_c_library(
            "dso_ctor_escape.c",
            rseq_libs.path(),
            &["-DDSO_CTOR_RSEQ_ONLY"],
        );
        let rseq_rpath = format!("-Wl,-rpath,{}", rseq_libs.path().display());
        let rseq = assert_build_c_guest_with_flags(
            "dso_ctor_probe.c",
            CLink::PosixShim,
            &[rseq_library.to_str().unwrap(), rseq_rpath.as_str()],
        );
        rseq.assert_audit_clean();
        if kernel_supports(KernelFeature::Sud) {
            g.assert_internal_fatal(
                &["syscall"],
                &["SUD: trapped a syscall outside the main executable text"],
            );
        }
        if cfg!(target_arch = "x86_64") && kernel_supports(KernelFeature::Tsc) {
            g.assert_internal_fatal(
                &["rdtsc"],
                &["timestamp-counter read the trap does not answer"],
            );
        }
        let Some(cpu) = allowed_cpu_other_than_zero() else {
            eprintln!("library constructor rseq: no allowed CPU but 0, not run");
            return;
        };
        let mut command = Command::new("taskset");
        command
            .env_clear()
            .arg("-c")
            .arg(cpu.to_string())
            .arg(&rseq.binary)
            .arg("rseq")
            .envs([("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "1")]);
        let out = common::output_with_deadline(&mut command, Duration::from_secs(20))
            .expect("rseq probe exceeded 20s");
        let out = assert_success(out);
        assert_eq!(
            text(&out.stdout),
            "DSO_CTOR_RESULT mode=rseq ran=1 value=0 main_cpu=0\n"
        );
    }

    // A guest's own preinit entry would run before the shim's (link order):
    // the audit refuses it before anything runs.
    #[test]
    fn guest_preinit_entry_is_refused() {
        let g = Guest::assert_build("preinit_entry_probe.rs");
        let out = g.assert_run_refused(1, &["early-init"]);
        assert!(!text(&out.stdout).contains("PREINIT_ENTRY_RAN"));
        assert_refused(g.command("audit", &[]), &["early-init"]);
        // The loader finds the array through the dynamic table, whatever its
        // section is named, and so does the audit.
        let renamed = g.dir.path().join("renamed");
        assert_success(
            Command::new("objcopy")
                .arg("--rename-section")
                .arg(".preinit_array=.renamed_init")
                .arg(&g.binary)
                .arg(&renamed)
                .output()
                .unwrap(),
        );
        let renamed = Guest {
            dir: tempfile::tempdir().unwrap(),
            binary: renamed,
        };
        assert_refused(renamed.command("audit", &[]), &["early-init"]);
    }

    /// Stripping the symbol table leaves the marker the shim keeps beside its
    /// entry: the shim's entry is still attributed (also through a collecting
    /// link), and a guest's own entry is still refused. The shim also proves
    /// its entry's place at run time from its own loaded code, trusting
    /// nothing the binary says: an entry beside it stops the run before that
    /// entry runs.
    #[test]
    fn stripped_guests_keep_their_attribution() {
        let clean = assert_build_c_guest_with_flags(
            "envp_probe.c",
            CLink::PosixShim,
            &["-s", "-Wl,--gc-sections"],
        );
        let audit = clean.command("audit", &["--raw"]);
        let report = format!("{}{}", text(&audit.stdout), text(&audit.stderr));
        assert!(!report.contains("early-init"), "{report}");
        let entry = guest_source("preinit_entry_probe.c");
        let foreign = assert_build_c_guest_with_flags(
            "envp_probe.c",
            CLink::PosixShim,
            &["-s", entry.to_str().unwrap()],
        );
        // Linked after the shim's object here, so the second entry.
        assert_refused(
            foreign.command("audit", &["--raw"]),
            &["preinit_array[1] (early-init)"],
        );
        foreign.assert_internal_fatal(
            &[],
            &["early-init: the executable's preinit array holds an entry beside the shim's"],
        );
    }

    /// Set a linked ELF's `DT_PREINIT_ARRAYSZ` to 0: the loader then runs no
    /// preinit entry, and the audit, reading the same table, sees none.
    fn empty_the_preinit_array(binary: &std::path::Path) {
        use object::read::elf::{Dyn, FileHeader, ProgramHeader};
        let mut bytes = std::fs::read(binary).unwrap();
        let header = object::elf::FileHeader64::<object::Endianness>::parse(&*bytes).unwrap();
        let endian = header.endian().unwrap();
        let dynamic = header
            .program_headers(endian, &*bytes)
            .unwrap()
            .iter()
            .find(|segment| segment.p_type(endian) == object::elf::PT_DYNAMIC)
            .expect("a dynamically linked guest");
        let start = dynamic.p_offset(endian) as usize;
        let entries = dynamic.dynamic(endian, &*bytes).unwrap().unwrap();
        let index = entries
            .iter()
            .position(|entry| entry.d_tag(endian) == object::elf::DT_PREINIT_ARRAYSZ)
            .expect("DT_PREINIT_ARRAYSZ");
        let value = start + index * 16 + 8;
        bytes[value..value + 8].fill(0);
        std::fs::write(binary, bytes).unwrap();
    }

    /// Remove a linked ELF's section-header table, which the loader never
    /// reads: the image still runs.
    fn drop_section_headers(binary: &std::path::Path) {
        let mut bytes = std::fs::read(binary).unwrap();
        bytes[0x28..0x30].fill(0); // e_shoff
        bytes[0x3c..0x40].fill(0); // e_shnum, e_shstrndx
        std::fs::write(binary, bytes).unwrap();
    }

    /// Crafted images the audit cannot see through still stop by name. With
    /// its preinit array emptied the shim's entry never runs: the audit sees
    /// no early-init entry, and the door stops the run. Without section
    /// headers the audit would see no imports and scan no code: the run and
    /// the audit refuse it before anything runs, the shim's guests and a stock
    /// program alike.
    #[test]
    fn crafted_images_the_audit_cannot_see_through_stop_by_name() {
        let g = assert_build_c_guest("envp_probe.c", CLink::PosixShim);
        empty_the_preinit_array(&g.binary);
        let audit = g.command("audit", &[]);
        let report = format!("{}{}", text(&audit.stdout), text(&audit.stderr));
        assert!(!report.contains("early-init"), "{report}");
        g.assert_internal_fatal(
            &[],
            &["early-init: the loader ran the executable's preinit array without the shim's entry"],
        );
        for link in [CLink::PosixShim, CLink::Unlinked] {
            let g = assert_build_c_guest("envp_probe.c", link);
            drop_section_headers(&g.binary);
            let out = g.assert_run_refused(1, &["without section headers"]);
            assert!(!text(&out.stdout).contains("NATIVE_ENVP_RESULT"));
            assert_refused(g.command("audit", &["--raw"]), &["without section headers"]);
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
