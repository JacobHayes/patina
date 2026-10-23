//! Native pre-run escape detection, deny traps, and live interposer guards.

#[cfg(test)]
mod tests {
    use super::super::*;

    // A guest importing a macOS Security-framework symbol that the shim does NOT
    // deny-trap is classified `macos-framework` and refused with a determinism note
    // that names the host-trust-store problem and the explicit allow path. `audit`
    // reports the same class. The representative is `SecTrustEvaluateWithError`,
    // deliberately NOT one of the enumerated dormant rustls-native-certs symbols
    // (`SecTrustSettingsCopy*`, `SecCertificateCopyData`, the `CF*` helpers): those
    // are now shim-defined (honest returns or documented traps) and drop off the
    // import table, so a still-refused (non-enumerated) framework symbol is what
    // exercises the pre-run refusal path.
    // macOS-only: the Security framework and its symbols do not exist on Linux (there
    // the import is a bare unknown, still denied).
    #[cfg(target_os = "macos")]
    #[test]
    fn native_gate_classifies_and_refuses_a_security_framework_symbol() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("sec.rs");
        fs::write(
            &source,
            r#"use std::ffi::c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTrustEvaluateWithError(trust: *const c_void, error: *mut *const c_void) -> bool;
}
fn main() {
    let mut error: *const c_void = std::ptr::null();
    let ok = unsafe { SecTrustEvaluateWithError(std::ptr::null(), &mut error) };
    println!("SEC ok={ok}");
}
"#,
        )
        .unwrap();
        let bin = directory.path().join("sec-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(!refused.status.success());
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("macos-framework"),
            "missing macos-framework class:\n{stderr}"
        );
        assert!(
            stderr.contains("keychain") || stderr.contains("trust store"),
            "missing host-trust-store determinism note:\n{stderr}"
        );
        assert!(
            stderr.contains("--allow-unsupported-symbols"),
            "missing explicit allow path:\n{stderr}"
        );

        let audited = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["audit", bin.to_str().unwrap()],
        );
        assert!(!audited.status.success());
        assert!(
            String::from_utf8_lossy(&audited.stderr).contains("macos-framework"),
            "audit did not report the macos-framework class:\n{}",
            String::from_utf8_lossy(&audited.stderr)
        );
    }

    // A guest that LINKS the enumerated dormant native-trust-root / host-inventory
    // surface (`SecTrustSettingsCopyCertificates` + `CFRelease` + `IOServiceMatching`)
    // but never reaches it — the references sit behind a runtime-false branch so they
    // are real imports the linker must resolve — RUNS to completion. Those symbols are
    // now shim-defined (honest deterministic returns): a strong def binds each
    // reference at link (dropping it off the import table), so the pre-run gate passes
    // whether the path is dormant (here) or live (the conversion tests above). This is
    // the Issue-1/Issue-2 fix: an unrelated scenario no longer needs
    // `--allow-unsupported-symbols` just because the binary links optional TLS-trust /
    // host-inventory code. macOS-only (the symbols are Darwin framework/Mach names).
    #[cfg(target_os = "macos")]
    #[test]
    fn native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("dormant.rs");
        fs::write(
            &source,
            r#"use std::ffi::c_void;
#[link(name = "Security", kind = "framework")]
#[link(name = "CoreFoundation", kind = "framework")]
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn SecTrustSettingsCopyCertificates(domain: i32, out: *mut *const c_void) -> i32;
    fn CFRelease(cf: *const c_void);
    fn IOServiceMatching(name: *const u8) -> *mut c_void;
}
fn main() {
    // A runtime-false branch keeps the three symbols as real imports (the linker
    // must resolve them) without ever calling them.
    if std::hint::black_box(false) {
        let mut out: *const c_void = std::ptr::null();
        unsafe { SecTrustSettingsCopyCertificates(0, &mut out) };
        unsafe { CFRelease(out) };
        let _ = unsafe { IOServiceMatching(b"x\0".as_ptr()) };
    }
    println!("DORMANT_PATH_OK");
}
"#,
        )
        .unwrap();
        let bin = directory.path().join("dormant-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            ran.status.success(),
            "a guest with only a DORMANT framework path must run:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("DORMANT_PATH_OK"),
            "the dormant-path guest must reach its marker:\nstdout:\n{}",
            String::from_utf8_lossy(&ran.stdout)
        );
    }

    // Task #52 ("fails later" must be visible up front): a guest that references a
    // deny-trap-armed symbol behind a runtime-false branch passes both the import
    // audit and the pre-run gate (the shim strong-def drops the symbol off the import
    // table), so nothing today warns that a call would abort. `audit` AND `run` now
    // print a non-blocking stderr note naming EXACTLY the referenced armed symbol and
    // its class, so the "fails later" contract is visible before the guest launches —
    // while the dormant guest still runs to completion (the note never blocks).
    // The note's precision relies on the final link dead-stripping an *unreferenced*
    // trap so a defined match means the guest genuinely references it. Only ld64 can do
    // that (atom granularity), so this test is macOS-only: on ELF every libc-shadowing
    // definition is auto-exported to `.dynsym` (that export is what lets the shim
    // interpose glibc-internal calls at all) and a dynamic-exported symbol is a
    // permanent GC root, so the ELF note truthfully reports the full armed union
    // instead (see `native_deny_trap_armed`).
    #[cfg(target_os = "macos")]
    #[test]
    fn native_audit_and_run_note_a_referenced_deny_trap_symbol() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("armed.rs");
        fs::write(
        &source,
        r#"use std::ffi::c_void;
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceGetMatchingServices(master: u32, matching: *const c_void, existing: *mut u32) -> i32;
}
fn main() {
    // A runtime-false branch keeps IOServiceGetMatchingServices a real reference
    // the linker resolves (so the trap symbol is defined) without ever calling it.
    if std::hint::black_box(false) {
        let mut it: u32 = 0;
        let _ = unsafe { IOServiceGetMatchingServices(0, std::ptr::null(), &mut it) };
    }
    println!("ARMED_DORMANT_OK");
}
"#,
    )
    .unwrap();
        let bin = directory.path().join("armed-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        // audit: succeeds (exit 0), and the note names exactly the referenced symbol.
        let audited = invoke(workspace, &["audit", bin.to_str().unwrap()]);
        let audit_stderr = String::from_utf8_lossy(&audited.stderr);
        assert!(
            audit_stderr.contains("deny-trap armed")
                && audit_stderr.contains("IOServiceGetMatchingServices (host-introspection)"),
            "audit must note the referenced deny-trap symbol up front:\n{audit_stderr}"
        );

        // run: the same note, and the dormant guest still runs to completion.
        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let run_stderr = String::from_utf8_lossy(&ran.stderr);
        assert!(
            run_stderr.contains("IOServiceGetMatchingServices (host-introspection)"),
            "run must note the referenced deny-trap symbol up front:\n{run_stderr}"
        );
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("ARMED_DORMANT_OK"),
            "the note is non-blocking: the dormant-path guest must still run to completion:\nstdout:\n{}",
            String::from_utf8_lossy(&ran.stdout)
        );
    }

    // The negative: a guest that references NO deny-trap symbol emits NO note at audit
    // or at run — the note must not be noise on an ordinary binary. macOS-gated for
    // the same dead-strip reason as the positive case above.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_audit_and_run_emit_no_deny_trap_note_when_none_referenced() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("plain.rs");
        fs::write(
            &source,
            r#"fn main() { println!("PLAIN_OK"); }
"#,
        )
        .unwrap();
        let bin = directory.path().join("plain-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let audited = invoke(workspace, &["audit", bin.to_str().unwrap()]);
        assert!(
            !String::from_utf8_lossy(&audited.stderr).contains("deny-trap armed"),
            "audit must emit no deny-trap note for a guest that references none:\n{}",
            String::from_utf8_lossy(&audited.stderr)
        );

        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert!(
            !String::from_utf8_lossy(&ran.stderr).contains("deny-trap armed"),
            "run must emit no deny-trap note for a guest that references none:\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("PLAIN_OK"),
            "the plain guest must run to completion"
        );
    }

    // The live-interposer guard's detection logic, proven both directions on a real
    // binary (macOS-gated because it only needs to build one; the Linux gc-safety
    // invariant is checked in `native_run_dlopen_is_a_deny_trap_and_release_strips_debug_asserts`). A guest that calls
    // `printf` links+defines it, so the guard confirms a present interposer and, with a
    // name no binary defines, flags an absent one — the assertion is non-vacuous.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_live_interposer_guard_detects_presence_and_absence() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("printer.rs");
        fs::write(
            &source,
            r#"unsafe extern "C" {
    fn printf(format: *const u8, ...) -> i32;
}
fn main() {
    unsafe { printf(b"HELLO\n\0".as_ptr()); }
}
"#,
        )
        .unwrap();
        let bin = directory.path().join("printer-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let bytes = fs::read(&bin).unwrap();
        assert!(
            patina_dst_target::native_missing_live_interposers(&bytes, &["printf"])
                .unwrap()
                .is_empty(),
            "a referenced interposer must be reported present"
        );
        assert_eq!(
            patina_dst_target::native_missing_live_interposers(
                &bytes,
                &["patina_absent_marker_xyz"]
            )
            .unwrap(),
            vec!["patina_absent_marker_xyz".to_string()],
            "the guard must flag a name the binary does not define"
        );
    }

    // The can-fail companion to the dormant test: a guest that ACTUALLY reaches one
    // of the still-trapped host-introspection symbols aborts deterministically with
    // the deny-trap diagnostic naming the symbol. The honest entry points now return
    // real values (IOServiceMatching -> NULL, host_statistics64 -> fixed stats, ...),
    // so the symbols that remain deny-traps are the helpers those honest returns make
    // unreachable by construction — `IOServiceGetMatchingServices` is one (reached
    // only with a non-NULL matching dictionary, which IOServiceMatching never yields).
    // It is shim-defined, so the pre-run gate passes (it is no longer an import) and
    // the runtime deny-trap is what fires when a guest genuinely calls it — the
    // distinct guarantee this proves, mirroring
    // `native_run_deny_trap_aborts_a_guest_that_actually_spawns`. Run twice with the
    // same seed and assert byte-identical output (determinism).
    #[cfg(target_os = "macos")]
    #[test]
    fn native_run_deny_trap_aborts_a_guest_that_reaches_host_introspection() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("trap.rs");
        fs::write(
        &source,
        r#"use std::ffi::c_void;
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceGetMatchingServices(master: u32, matching: *const c_void, existing: *mut u32) -> i32;
}
fn main() {
    println!("BEFORE_INTROSPECTION");
    if std::hint::black_box(true) {
        let mut it: u32 = 0;
        let _ = unsafe { IOServiceGetMatchingServices(0, std::ptr::null(), &mut it) };
    }
    println!("AFTER_INTROSPECTION");
}
"#,
    )
    .unwrap();
        let bin = directory.path().join("trap-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let run_once = || {
            invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                workspace,
                &["run", bin.to_str().unwrap(), "--seed", "1"],
            )
        };
        let first = run_once();
        assert!(
            !first.status.success(),
            "a guest that reaches IOServiceGetMatchingServices must abort under the deny-trap"
        );
        let first_stderr = String::from_utf8_lossy(&first.stderr).into_owned();
        let first_stdout = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            first_stderr
                .contains("host-introspection reached under patina: IOServiceGetMatchingServices"),
            "the deny-trap must name the reached host-introspection symbol:\n{first_stderr}"
        );
        assert!(
            first_stdout.contains("BEFORE_INTROSPECTION"),
            "the guest must run up to the introspection call:\n{first_stdout}"
        );
        assert!(
            !first_stdout.contains("AFTER_INTROSPECTION"),
            "the guest must not continue past the deny-trap:\n{first_stdout}"
        );

        // Determinism: a second identical-seed run produces byte-identical output.
        let second = run_once();
        assert_eq!(
            first_stdout,
            String::from_utf8_lossy(&second.stdout),
            "deny-trap stdout is not deterministic across runs"
        );
        assert_eq!(
            first_stderr,
            String::from_utf8_lossy(&second.stderr),
            "deny-trap stderr is not deterministic across runs"
        );
    }

    // One uninterposed symbol per escape class in a single guest. Taking each as a
    // pointer forces the undefined import, so the pre-run gate must refuse the whole
    // binary before it runs. This is the gate-level per-class proof: if any class's
    // end-to-end detection path rots (a symbol dropped from the deny lists, or the
    // gate stops enumerating it), the corresponding label vanishes and the test
    // fails. Two classes have no plantable member here and are covered elsewhere:
    // `environment` (getenv/setenv/... are all interposed, so no shim-linked binary
    // can import an uninterposed one) and `unmanaged-thread` (pthread_create is
    // interposed; the C `escape_probe.c` used by native_containment imports it and
    // native-audit rejects it as `unmanaged-thread`).
    //
    // The `process` representative is `killpg`, deliberately NOT a spawn-family
    // symbol (`fork`/`posix_spawn*`/`waitpid`/...) nor `kill`: the spawn family is now
    // shim-*defined* deny-traps (they abort deterministically if reached) and `kill`
    // is a shim-defined deterministic-model interposer (existence-probe / ESRCH), so
    // none of them appears as an import and could exercise the gate. `killpg` stays
    // uninterposed — the process class is a deterministic-runtime non-goal — so it
    // remains an undefined import the gate must flag as `process`.
    //
    // The `unmanaged-sync` representative is the Mach `semaphore_wait`, NOT
    // `os_unfair_lock_*`: os_unfair_lock is now shim-interposed (routed through
    // DetScheduler), so it is a defined symbol and no longer appears as an import.
    // `semaphore_wait` stays uninterposed (the shim's baton reaches the real Mach
    // semaphore through the host-alias `dlsym`, never a public strong def), so it
    // remains an undefined import the gate must flag as `unmanaged-sync`.
    // Linux interposes every public signal-wait representative; Darwin does
    // not interpose sigsuspend. glibc's exported __sigsuspend alias remains an
    // import and normalizes to the same signals-timers classifier entry.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SIGNALS_TIMERS_IMPORT: &str = r#"
unsafe extern "C" {
    #[cfg_attr(target_os = "linux", link_name = "__sigsuspend")]
    #[cfg_attr(target_os = "macos", link_name = "sigsuspend")]
    fn signals_timers_escape(mask: *const u8) -> i32;
}
"#;

    #[cfg(target_os = "macos")]
    const ESCAPE_CLASSES_SOURCE: &str = r#"
unsafe extern "C" {
    // acct: process accounting to a file, refused by decision (privileged,
    // kernel-global) -- the filesystem-class representative. (`link`, then
    // `pwritev`, then `truncate` served here before; all three are now routed
    // through the deterministic filesystem, so none is an escape.)
    fn acct(path: *const u8) -> i32;
    fn gethostbyname(name: *const u8) -> *mut u8;
    fn select(n: i32, r: *mut u8, w: *mut u8, e: *mut u8, t: *mut u8) -> i32;
    fn semaphore_wait(s: u32) -> i32;
    // time() is modeled; tzset still reads the host timezone database.
    fn tzset();
    fn arc4random() -> u32;
    fn killpg(pgrp: i32, sig: i32) -> i32;
    // dlopen/dlclose are deny-traps; dlopen_preflight stays a refused import.
    fn dlopen_preflight(path: *const u8) -> bool;
    fn shm_open(name: *const u8, oflag: i32) -> i32;
    fn syscall(number: i64) -> i64;
}
fn main() {
    let ptrs: &[*const ()] = &[
        acct as *const (), gethostbyname as *const (), select as *const (),
        semaphore_wait as *const (), tzset as *const (), arc4random as *const (),
        killpg as *const (), dlopen_preflight as *const (), shm_open as *const (),
        signals_timers_escape as *const (), syscall as *const (),
    ];
    let mut acc = 0usize;
    for p in ptrs { acc ^= *p as usize; }
    std::process::exit((acc & 1) as i32);
}
"#;

    // Gate-level per-class detection: native-run refuses a guest reaching one
    // uninterposed symbol of each class, naming every class. Demonstrably able to
    // fail — it depends on the run being refused with each label present.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_run_prerun_gate_refuses_every_escape_class() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("escape_classes.rs");
        fs::write(
            &source,
            format!("{SIGNALS_TIMERS_IMPORT}{ESCAPE_CLASSES_SOURCE}"),
        )
        .unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("escape-classes");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            !refused.status.success(),
            "the gate must refuse a guest reaching uninterposed escape-class symbols"
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        for class in [
            "(filesystem)",
            "(network)",
            "(wait-multiplex)",
            "(unmanaged-sync)",
            "(time)",
            "(entropy)",
            "(process)",
            "(dynamic-loading)",
            "(shared-memory-ipc)",
            "(signals-timers)",
            "(direct-syscall)",
        ] {
            assert!(
                stderr.contains(class),
                "the gate denial must name the {class} class:\n{stderr}"
            );
        }
        assert!(
            !String::from_utf8_lossy(&refused.stdout).contains("escape"),
            "the guest must not run"
        );
    }

    // Class pairing: the default-deny import gate and symbol normalization.
    // Shares the signal-family representative with the macOS per-class guest.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_run_prerun_gate_refuses_signals_timers_escape() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("signals_escape.rs");
        fs::write(
            &source,
            format!(
                "{SIGNALS_TIMERS_IMPORT}\nfn main() {{\n\
                 std::hint::black_box(signals_timers_escape as *const ());\n\
                 println!(\"guest ran\");\n}}\n"
            ),
        )
        .unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("signals-escape");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let refused = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            !refused.status.success(),
            "the import gate must refuse the guest"
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(stderr.contains("sigsuspend (signals-timers)"), "{stderr}");
        assert!(!String::from_utf8_lossy(&refused.stdout).contains("guest ran"));
    }

    // Part B: the pre-run default-deny gate refuses to run a binary reaching an
    // uninterposed blocking symbol (naming and categorizing it), the escape hatch
    // downgrades it to a loud warning and runs, and a partial allow list still fails
    // closed on the remaining symbol. This gate is demonstrably able to fail: the
    // first assertion depends on the run being rejected.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("planted_escape.rs");
        fs::write(&source, PLANTED_ESCAPE_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("planted-escape");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let exe = env!("CARGO_BIN_EXE_cargo-patina");

        // (1) Default-deny: refuses to run, names and categorizes the symbols, and
        // the guest never executes.
        let denied = invoke_unchecked(
            exe,
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert!(
            !denied.status.success(),
            "the pre-run gate must refuse the planted escape"
        );
        let denied_err = String::from_utf8_lossy(&denied.stderr);
        assert!(
            denied_err.contains("semaphore_wait") && denied_err.contains("unmanaged-sync"),
            "denial must name and categorize the symbol:\n{denied_err}"
        );
        assert!(
            !String::from_utf8_lossy(&denied.stdout).contains("planted escape ran"),
            "the guest must not run when the gate denies it"
        );

        // (2) Escape hatch: downgrades to a prominent warning and runs.
        let allowed = invoke_unchecked(
            exe,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--allow-unsupported-symbols",
                "all",
            ],
        );
        assert!(
            allowed.status.success(),
            "the escape hatch must let the guest run:\n{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        assert!(
            String::from_utf8_lossy(&allowed.stdout).contains("planted escape ran"),
            "the guest must run under the escape hatch"
        );
        assert!(
            String::from_utf8_lossy(&allowed.stderr).contains("WARNING"),
            "the escape hatch must warn prominently"
        );

        // (3) A partial allow list still fails closed on the un-allowed symbol.
        let partial = invoke_unchecked(
            exe,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--allow-unsupported-symbols",
                "semaphore_wait",
            ],
        );
        assert!(
            !partial.status.success(),
            "a partial allow list must still fail closed"
        );
        assert!(
            String::from_utf8_lossy(&partial.stderr).contains("semaphore_signal"),
            "the remaining un-allowed symbol must be named"
        );
    }

    // A guest that actually CALLS a process-spawn symbol under Patina. Once the shim
    // deny-trap stubs (task #15 shim portion) land, `fork` is shim-*defined* — so the
    // pre-run audit passes (it is no longer an import), the guest runs, and the call
    // aborts deterministically with the deny-trap diagnostic. This is the can-fail
    // proof for the deny-trap disposition: distinct from the pre-run gate (which
    // refuses a guest that merely *imports* an uninterposed spawn symbol), this
    // asserts the *runtime* guard fires for a guest that reaches one.
    #[cfg(target_os = "macos")]
    const PLANTED_SPAWN_SOURCE: &str = r#"
unsafe extern "C" {
    fn fork() -> i32;
}
fn main() {
    println!("before spawn");
    unsafe {
        fork();
    }
    println!("after spawn");
}
"#;

    // `fork` is now shim-defined (a deny-trap in the staged `patina_posix.c`), so the pre-run
    // gate passes this binary (fork is no longer an import) and the runtime deny-trap
    // is what fires when the guest reaches fork — the distinct guarantee this proves.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_run_deny_trap_aborts_a_guest_that_actually_spawns() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("planted_spawn.rs");
        fs::write(&source, PLANTED_SPAWN_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("planted-spawn");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let ran = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &["run", bin.to_str().unwrap(), "--seed", "1"],
        );
        // The audit passes (fork is shim-defined, not an import), the guest starts,
        // and the fork() call aborts deterministically.
        assert!(
            !ran.status.success(),
            "a guest that reaches fork must abort under the deny-trap"
        );
        let stderr = String::from_utf8_lossy(&ran.stderr);
        assert!(
            stderr.contains("process spawn reached under patina: fork"),
            "the deny-trap must name the reached spawn symbol:\n{stderr}"
        );
        let stdout = String::from_utf8_lossy(&ran.stdout);
        assert!(
            stdout.contains("before spawn"),
            "the guest must run up to the spawn attempt"
        );
        assert!(
            !stdout.contains("after spawn"),
            "the guest must not continue past the deny-trap"
        );
    }

    // The dynamic-loading surface an extension loader links (`libloading`:
    // `dlopen`, `dlerror`, `dlclose`), reached only when the guest is asked to
    // load something; `assert` reaches a `debug_assert!` instead.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const EXTENSION_LOADER_SOURCE: &str = r#"
use std::ffi::{c_char, c_int, c_void};
unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlerror() -> *mut c_char;
    fn dlclose(handle: *mut c_void) -> c_int;
}
fn main() {
    println!("BEFORE_LOAD");
    if std::env::args().any(|arg| arg == "assert") {
        debug_assert!(false, "SINGLE_SOURCE_DEBUG_ASSERT");
    }
    if std::env::args().any(|arg| arg == "--load") {
        let handle = unsafe { dlopen(c"libpatina-extension.so".as_ptr(), 2) };
        if handle.is_null() {
            let _ = unsafe { dlerror() };
        } else {
            unsafe { dlclose(handle) };
        }
    }
    println!("AFTER_LOAD");
}
"#;

    // `dlopen`/`dlclose` are deny-traps: a guest that links them runs, and one
    // that calls `dlopen` aborts deterministically, naming it. Paired with the
    // registry gate `deny_rows_agree_with_patina_target`.
    //
    // The default build is debug, so a `debug_assert!` is a live failure oracle;
    // `run --release` on a single `.rs` source reprofiles the guest itself, not
    // only the shim, so the same assert is compiled out.
    //
    // On ELF the printf family, the stdout/stderr sentinels, and the
    // deterministic-IO interposers are reached through glibc-internal paths a
    // defined/undefined scan cannot see, so the guest references none of them
    // directly, yet every one must survive the link.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_run_dlopen_is_a_deny_trap_and_release_strips_debug_asserts() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("extension_loader.rs");
        fs::write(&source, EXTENSION_LOADER_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("extension-loader");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        #[cfg(target_os = "linux")]
        {
            let missing = patina_dst_target::native_missing_live_interposers(
                &fs::read(&bin).unwrap(),
                patina_dst_target::NATIVE_LINUX_LIVE_INTERPOSERS,
            )
            .unwrap();
            assert!(
                missing.is_empty(),
                "the link dropped load-bearing interposer(s) from the emitted ELF: {missing:?}"
            );
        }
        let run = |target: &Path, release: bool, mode: &str| {
            let mut args = vec!["run"];
            if release {
                args.push("--release");
            }
            args.extend([target.to_str().unwrap(), "--seed", "1", "--", mode]);
            invoke_unchecked(env!("CARGO_BIN_EXE_cargo-patina"), workspace, &args)
        };
        let stdout = |output: &Output| String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = |output: &Output| String::from_utf8_lossy(&output.stderr).into_owned();

        let dormant = run(&bin, false, "dormant");
        assert!(
            dormant.status.success(),
            "a guest that only links dlopen must run:\nstderr:\n{}",
            stderr(&dormant)
        );
        assert!(stdout(&dormant).contains("AFTER_LOAD"));

        let load = run(&bin, false, "--load");
        assert!(
            !load.status.success(),
            "a guest that calls dlopen must abort"
        );
        assert!(
            stderr(&load).contains("reached under patina: dlopen"),
            "the deny-trap must name dlopen:\n{}",
            stderr(&load)
        );
        assert!(stdout(&load).contains("BEFORE_LOAD"), "{}", stdout(&load));
        assert!(!stdout(&load).contains("AFTER_LOAD"), "{}", stdout(&load));

        let debug = run(&bin, false, "assert");
        assert!(
            !debug.status.success() && stderr(&debug).contains("SINGLE_SOURCE_DEBUG_ASSERT"),
            "the default build must fire the debug_assert:\nstderr:\n{}",
            stderr(&debug)
        );
        let release = run(&source, true, "assert");
        assert!(
            release.status.success() && stdout(&release).contains("AFTER_LOAD"),
            "single-source run --release must compile out the debug_assert:\nstderr:\n{}",
            stderr(&release)
        );
    }
}
