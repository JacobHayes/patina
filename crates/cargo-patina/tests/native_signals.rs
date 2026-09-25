//! Real C/raw doors paired with the signals state/wait and fatal-policy detectors.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

#[cfg(target_os = "linux")]
fn assert_interruptible_wait(case: &str) {
    let g = assert_build_c_guest("signals/blocking_readiness.c", CLink::PosixShim);
    let output = assert_standalone_success(
        &g.binary,
        &[case],
        &[("PATINA_MODE", "seeded"), ("PATINA_SEED", "7")],
    );
    assert_eq!(output.stdout, b"NATIVE_SIGNAL_READINESS_OK\n");
}

#[cfg(target_os = "linux")]
#[test]
fn libc_poll_is_eintr_even_with_sa_restart() {
    assert_interruptible_wait("poll");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_ppoll_restores_mask_and_preserves_timeout_on_eintr() {
    assert_interruptible_wait("ppoll");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_select_writes_remaining_timeout_on_eintr() {
    assert_interruptible_wait("select");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_pselect_restores_mask_and_preserves_timeout_on_eintr() {
    assert_interruptible_wait("pselect");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_epoll_pwait_restores_mask_on_eintr() {
    assert_interruptible_wait("epoll");
}
#[cfg(target_os = "linux")]
#[test]
fn libc_sleep_returns_remaining_seconds_on_signal() {
    assert_interruptible_wait("sleep");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod raw {
    use super::*;
    use patina_dst_trace::TraceBundle;
    use std::os::unix::process::ExitStatusExt;

    fn assert_state(case: &str) {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        let (output, trace) = g.record_standalone(&[case]);
        assert_success(output);
        TraceBundle::load(&trace).expect("successful state probe finalizes its trace");
    }

    #[test]
    fn prctl_libc_and_raw_share_one_state() {
        assert_state("prctl");
    }
    #[test]
    fn libc_tgkill_and_tkill_deliver_registered_handler() {
        assert_state("handler");
    }
    #[test]
    fn libc_and_raw_masks_cannot_block_reserved_signals() {
        assert_state("masks");
    }
    #[test]
    fn nested_raw_handler_cannot_undo_outer_unblock() {
        assert_state("nested-unblock");
    }
    #[test]
    fn sigwait_retries_after_unrelated_handler() {
        assert_state("sigwait");
    }
    #[test]
    fn libc_sigsuspend_handler_sees_safe_temporary_mask() {
        assert_state("suspend-libc");
    }
    #[test]
    fn raw_sigsuspend_handler_sees_safe_temporary_mask() {
        assert_state("suspend-raw");
    }

    #[test]
    fn guest_abort_finalizes_trace_before_host_abort() {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        let (output, trace) = g.record_standalone(&["guest-abort"]);
        assert_eq!(output.status.signal(), Some(6), "{}", text(&output.stderr));
        TraceBundle::load(&trace).expect("guest abort finalizes its trace");
    }

    /// glibc's `_FORTIFY_SOURCE` file failures are guest aborts, as `abort`
    /// is: glibc's exact diagnostic on stderr, SIGABRT, a finalized trace.
    /// Every `_chk` past its buffer is `__chk_fail`; every `__open*_2` that
    /// needs a mode is `__fortify_fail` naming its call (glibc io/open_2.c,
    /// open64_2.c, openat_2.c, openat64_2.c).
    #[test]
    fn fortify_failures_are_guest_aborts() {
        const OVERFLOW: &str = "*** buffer overflow detected ***: terminated";
        const CASES: [(&str, &str); 9] = [
            ("__read_chk", OVERFLOW),
            ("__pread_chk", OVERFLOW),
            ("__pread64_chk", OVERFLOW),
            ("__readlink_chk", OVERFLOW),
            ("__readlinkat_chk", OVERFLOW),
            (
                "__open_2",
                "*** invalid open call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
            (
                "__open64_2",
                "*** invalid open64 call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
            (
                "__openat_2",
                "*** invalid openat call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
            (
                "__openat64_2",
                "*** invalid openat64 call: O_CREAT or O_TMPFILE without mode ***: terminated",
            ),
        ];
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        for (symbol, diagnostic) in CASES {
            let (output, trace) = g.record_standalone(&[&format!("fortify-{symbol}")]);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.signal(), Some(6), "{symbol}: {stderr}");
            assert!(
                stderr.lines().any(|line| line == diagnostic),
                "{symbol}: no {diagnostic:?} line in {stderr}"
            );
            TraceBundle::load(&trace)
                .unwrap_or_else(|error| panic!("{symbol}: the abort left no trace: {error}"));
        }
    }

    fn assert_internal_fatal(case: &str, diagnostic: &str) {
        let Some(g) = sud_c_guest("signals/signal_boundary.c") else {
            return;
        };
        g.assert_internal_fatal(&[case], &[diagnostic]);
    }
    #[test]
    fn internal_c_trap_leaves_trace_incomplete() {
        assert_internal_fatal("internal-c", "process spawn reached under patina: fork");
    }
    #[test]
    fn internal_raw_trap_leaves_trace_incomplete() {
        assert_internal_fatal("internal-rust", "SUD trapped syscall number 999999");
    }
    #[test]
    fn context_locked_refusal_never_reenters_the_scheduler() {
        assert_internal_fatal("internal-context-active", "no custom operation open");
    }

    #[test]
    fn nested_custom_op_fatal_leaves_trace_incomplete() {
        assert_internal_fatal("internal-context", "may not nest or be left unclosed");
    }
}

// Class pairing: internal Rust panic and guest abort must use different fatal
// vehicles. Fault injection is confined to a scratch copy of the real shim;
// the production export and its real ownership guard are both exercised.
#[test]
fn internal_rust_panic_never_finalizes_an_invalid_trace() {
    use patina_dst_trace::TraceBundle;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::Command;
    fn copy_tree(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    for strategy in ["unwind", "abort"] {
        let dir = tempfile::tempdir().unwrap();
        let workspace = common::native_workspace();
        let shim = dir.path().join("crates/patina-native-shim");
        copy_tree(&workspace.join("crates/patina-native-shim"), &shim);
        let mut manifest = std::fs::read_to_string(workspace.join("Cargo.toml")).unwrap();
        let members = manifest.find("members = [").unwrap();
        let end = members + manifest[members..].find(']').unwrap() + 1;
        manifest.replace_range(members..end, "members = [\"crates/patina-native-shim\"]");
        // Dependencies retain their declared paths; only the shim is copied/mutated.
        manifest = manifest.replace(
            "path = \"crates/",
            &format!("path = \"{}/crates/", workspace.display()),
        );
        std::fs::write(dir.path().join("Cargo.toml"), manifest).unwrap();
        std::fs::copy(workspace.join("Cargo.lock"), dir.path().join("Cargo.lock")).unwrap();
        let source = shim.join("src/lib.rs");
        let source_text = std::fs::read_to_string(&source).unwrap();
        let anchor = "pub unsafe extern \"C\" fn patina_clock_now(clock_id: u32, nanos: *mut u64) -> c_int {\n    let _panic_scope = crate::panic_boundary::PanicScope::enter();";
        assert_eq!(
            source_text.matches(anchor).count(),
            1,
            "one production ABI guard injection site"
        );
        // A valid argument singles out the explicit query, not startup's clock reads.
        let planted = format!(
            "{anchor}\n    if clock_id == 1 {{ panic!(\"planted internal Rust panic\"); }}"
        );
        std::fs::write(source, source_text.replace(anchor, &planted)).unwrap();
        let target = dir.path().join("build");
        let built = assert_success(
            Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args([
                    "rustc",
                    "--lib",
                    "--offline",
                    "--message-format=json",
                    "-p",
                    "patina-dst-native-shim",
                    "--manifest-path",
                ])
                .arg(dir.path().join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&target)
                .args(["--", "-C", &format!("panic={strategy}")])
                .output()
                .unwrap(),
        );
        // Cargo can redirect intermediates separately from target-dir. Consume
        // its artifact messages rather than guessing where dependency rlibs live.
        let dependency_dirs: std::collections::BTreeSet<std::path::PathBuf> = text(&built.stdout)
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("Cargo artifact JSON")
            })
            .filter(|message| message["reason"] == "compiler-artifact")
            .flat_map(|message| {
                message["filenames"]
                    .as_array()
                    .expect("artifact filenames")
                    .iter()
                    .filter_map(|name| {
                        let path = Path::new(name.as_str().expect("artifact path"));
                        (path.extension().is_some_and(|ext| ext == "rlib"))
                            .then(|| path.parent().unwrap().to_owned())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            !dependency_dirs.is_empty(),
            "non-vacuous dependency artifacts"
        );
        let binary = dir.path().join("panic-guest");
        let posix = common::compile_posix_object(dir.path());
        let mut cc = common::c_compiler();
        cc.arg("-I")
            .arg(shim.join("include"))
            .arg(guest_source("signals/internal_panic.c"))
            .arg(posix)
            .arg(target.join("debug/libpatina_dst_native_shim.a"));
        if cfg!(target_os = "linux") {
            cc.arg("-Wl,--wrap=dlsym");
        }
        assert_success(cc.arg("-o").arg(&binary).output().unwrap());
        let guest = Guest { dir, binary };
        let (output, trace) = guest.record_standalone(&[]);
        assert_eq!(output.status.signal(), Some(6), "{}", text(&output.stderr));
        assert!(
            text(&output.stderr).contains("planted internal Rust panic"),
            "{}",
            text(&output.stderr)
        );
        if let Ok(bundle) = TraceBundle::load(&trace) {
            bundle
                .validate()
                .expect("RED control: the pre-hook trace is complete and valid");
            panic!(
                "internal Rust panic finalized a complete valid trace ({} timelines)",
                bundle.timelines.len()
            );
        }
        // Replacing the hook cannot turn an internal unwind into guest abort.
        let vehicle = guest.dir.path().join("guest_panic.rs");
        let code = std::fs::read_to_string(guest_source("signals/guest_panic.rs")).unwrap();
        std::fs::write(
            &vehicle,
            format!("extern crate patina_dst_native_shim;\n{code}").replace("//!", "//"),
        )
        .unwrap();
        let binary = guest.dir.path().join("replacement-hook-guest");
        // Native libraries precede the compiler/system runtimes. A late
        // link-arg object can leave libc or outlined atomic helpers unresolved.
        let posix_archive = guest.dir.path().join("libpatina_test_posix.a");
        assert_success(
            Command::new("ar")
                .arg("crs")
                .arg(&posix_archive)
                .arg(guest.dir.path().join("patina_posix.o"))
                .output()
                .unwrap(),
        );
        let mut rustc = Command::new("rustc");
        rustc
            .arg("--edition=2024")
            .args(["-C", &format!("panic={strategy}")])
            .arg(&vehicle)
            .arg("--extern")
            .arg(format!(
                "patina_dst_native_shim={}",
                target
                    .join("debug/libpatina_dst_native_shim.rlib")
                    .display()
            ))
            .arg("-L")
            .arg(format!("native={}", guest.dir.path().display()))
            .args(["-l", "static=patina_test_posix"])
            .arg("-o")
            .arg(&binary);
        for directory in dependency_dirs {
            rustc
                .arg("-L")
                .arg(format!("dependency={}", directory.display()));
        }
        if cfg!(target_os = "linux") {
            rustc.args(["-C", "link-arg=-Wl,--wrap=dlsym"]);
        }
        assert_success(rustc.output().unwrap());
        let replacement = Guest {
            dir: guest.dir,
            binary,
        };
        let diagnostics: &[&str] = if strategy == "unwind" {
            &["patina native shim panic: unwinding an owned boundary"]
        } else if cfg!(target_os = "linux") {
            &["patina native shim panic: aborting an owned boundary"]
        } else {
            // Darwin has no guest abort interposer. With a replaced hook and
            // panic=abort, libc aborts directly: signal + incomplete trace are
            // the contract, not the Linux interposer's diagnostic.
            &[]
        };
        replacement.assert_internal_fatal(&["replace-internal"], diagnostics);
    }
}

#[test]
fn guest_panics_remain_catchable_in_main_and_callbacks() {
    let guest = Guest::assert_build("signals/guest_panic.rs");
    for mode in ["prior", "replace"] {
        let (output, trace) = guest.record_standalone(&[mode]);
        let output = assert_success(output);
        assert_exact_line(
            &output.stdout,
            if cfg!(target_os = "linux") {
                "GUEST_PANICS_CAUGHT=4"
            } else {
                "GUEST_PANICS_CAUGHT=2"
            },
        );
        patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .validate()
            .unwrap();
    }
}

// Class pairing: Linux interruption cases above plus the shared process/time
// adapters. This deliberately requires no raw-syscall or signal-delivery support.
#[test]
fn portable_process_answers_and_uninterrupted_sleep_replay() {
    let guest = assert_build_c_guest("signals/process_sleep.c", CLink::PosixShim);
    let (first, trace) = guest.record_standalone(&[]);
    assert_exact_line(&assert_success(first).stdout, "PROCESS_SLEEP_OK");
    let bytes = std::fs::read(&trace).unwrap();
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
    let (second, _) = guest.record_standalone(&[]);
    assert_exact_line(&assert_success(second).stdout, "PROCESS_SLEEP_OK");
    assert_eq!(bytes, std::fs::read(&trace).unwrap(), "record identity");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .env_clear()
        .args(["-c", "exec 3<\"$1\"; shift; exec \"$@\"", "native-boundary"])
        .arg(&trace)
        .arg(&guest.binary)
        .envs([
            ("PATINA_MODE", "replay"),
            ("PATINA_TRACE_FD", "3"),
            ("PATINA_FINGERPRINT", "native-boundary"),
        ]);
    let replay = common::output_with_deadline(&mut command, std::time::Duration::from_secs(20))
        .expect("standalone replay exceeded 20s");
    assert_exact_line(&assert_success(replay).stdout, "PROCESS_SLEEP_OK");
}
