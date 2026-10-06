//! Shim markers, trap manageability, and linked containment capabilities tests.

use super::*;
use crate::NativeEscape;
use crate::import_policy::{NativeFormat, NativeImportDecision, native_import_decision};
use crate::instruction_scan::FAR_TRANSFER_CATEGORY;
use crate::provenance::NativeProvenance;
use crate::report::render_compat_mode_note;
use crate::tests::{instruction_finding, module_importing};
use crate::wasi::WASI_PREVIEW1_MODULE;

#[test]
fn sud_manageability_is_instruction_direct_syscall_only() {
    // The SUD audit downgrade applies to raw inline syscall *instruction*
    // findings and nothing else. A by-name `syscall` import is already
    // interposed/refused on its own terms, and `cpu-nondeterminism` register
    // reads (rdtsc/mrs CNTVCT) cannot be trapped by SUD — downgrading either
    // would silently widen the gate. RED: flip any arm below and the
    // downgrade would admit an untappable escape.
    for mnemonic in ["syscall", "svc"] {
        assert!(native_escape_is_sud_manageable(&instruction_finding(
            "direct-syscall",
            mnemonic
        )));
    }
    // The i386 entries are direct syscalls SUD traps but the shim refuses
    // (wrong `si_arch`), so they keep refusing, and the refusal says why.
    for mnemonic in ["int 0x80", "sysenter"] {
        let compat = instruction_finding("direct-syscall", mnemonic);
        assert!(!native_escape_is_sud_manageable(&compat), "{mnemonic}");
        assert!(render_compat_mode_note(&[compat]).is_some(), "{mnemonic}");
    }
    assert!(render_compat_mode_note(&[instruction_finding("direct-syscall", "syscall")]).is_none());
    assert!(
        render_compat_mode_note(&[instruction_finding(FAR_TRANSFER_CATEGORY, "ljmp")]).is_some()
    );
    let no_mnemonic = NativeEscape::new(
        "instruction@.text+0x42".into(),
        "direct-syscall",
        vec![NativeProvenance::unknown()],
    );
    assert!(!native_escape_is_sud_manageable(&no_mnemonic));
    let by_name = NativeEscape::new(
        "syscall".into(),
        "direct-syscall",
        vec![NativeProvenance::unknown()],
    );
    assert!(!native_escape_is_sud_manageable(&by_name));
    let register_read = NativeEscape::new(
        "instruction@.text+0x42".into(),
        "cpu-nondeterminism",
        vec![NativeProvenance::unknown()],
    );
    assert!(!native_escape_is_sud_manageable(&register_read));
}

#[test]
fn tsc_manageability_is_the_timestamp_counter_only() {
    // The TSC trap answers exactly two instructions from the virtual clock.
    for mnemonic in ["rdtsc", "rdtscp"] {
        assert!(
            native_escape_is_tsc_manageable(&instruction_finding("cpu-nondeterminism", mnemonic)),
            "{mnemonic} is trap-managed"
        );
    }
    // The rest of the shared `cpu-nondeterminism` category is NOT: no
    // mechanism traps a hardware entropy read or the arm64 system counter, so
    // downgrading any of them would turn a refusal into a silent host escape.
    // RED: widen the predicate to the whole category and these fail.
    for mnemonic in ["rdrand", "rdseed", "cntvct"] {
        assert!(
            !native_escape_is_tsc_manageable(&instruction_finding("cpu-nondeterminism", mnemonic)),
            "{mnemonic} is untrappable and must keep refusing"
        );
    }
    // A finding with no mnemonic (import, vsyscall immediate, undecodable
    // instruction) is never downgraded, and neither is a raw syscall — that
    // one belongs to the SUD split, and the two must not cross.
    let no_mnemonic = NativeEscape::new(
        "instruction@.text+0x42".into(),
        "cpu-nondeterminism",
        vec![NativeProvenance::unknown()],
    );
    assert!(!native_escape_is_tsc_manageable(&no_mnemonic));
    assert!(!native_escape_is_tsc_manageable(&instruction_finding(
        "direct-syscall",
        "syscall"
    )));
    assert!(!native_escape_is_sud_manageable(&instruction_finding(
        "cpu-nondeterminism",
        "rdtsc"
    )));
    // A by-name import that happens to be called `rdtsc` is a symbol, not an
    // instruction the trap can reach.
    let by_name = NativeEscape::new(
        "rdtsc".into(),
        "cpu-nondeterminism",
        vec![NativeProvenance::unknown()],
    )
    .with_mnemonic("rdtsc");
    assert!(!native_escape_is_tsc_manageable(&by_name));
}

#[test]
fn tsc_marker_detection_fails_closed_on_unparseable_input() {
    // A malformed binary must never be treated as trap-capable: the marker
    // probe returns an error, not `false`-as-capable or `true`.
    assert!(native_binary_has_tsc_marker(b"not an object file").is_err());
}

#[test]
fn sud_marker_detection_fails_closed_on_unparseable_input() {
    // A malformed binary must never be treated as SUD-capable: the marker
    // check is a downgrade precondition, so parse failure ⇒ error, not false.
    assert!(native_binary_has_sud_marker(b"not an object file").is_err());
}

#[test]
fn shim_control_plane_allows_only_the_vehicle() {
    let allow = shim_control_plane_symbols();
    #[cfg(target_os = "macos")]
    {
        // Under the host-alias doctrine the macOS control plane is a single
        // symbol: the `dlsym` resolution primitive.
        assert_eq!(
            native_import_decision("_dlsym", NativeFormat::MachO, &allow),
            NativeImportDecision::Allowed,
            "the dlsym resolution primitive should pass the baked control-plane set"
        );
        // The former named vehicles are no longer allowlisted: the shim
        // resolves them at runtime, so a guest importing one is now DENIED
        // rather than riding a name-based allowance. This is the structural
        // fix for the dispatch-semaphore Parker escape class.
        for (symbol, category) in [
            ("_semaphore_wait", "unmanaged-sync"),
            ("_semaphore_signal", "unmanaged-sync"),
            ("_dispatch_semaphore_wait", "unmanaged-sync"),
            ("_read$NOCANCEL", "filesystem"),
            ("_write$NOCANCEL", "filesystem"),
        ] {
            assert_eq!(
                native_import_decision(symbol, NativeFormat::MachO, &allow),
                NativeImportDecision::Denied(category),
                "former vehicle {symbol} must now fail closed as {category}"
            );
        }
        // Non-vehicle escapes stay denied as before.
        assert_eq!(
            native_import_decision("_read", NativeFormat::MachO, &allow),
            NativeImportDecision::Denied("filesystem")
        );
        assert_eq!(
            native_import_decision("open", NativeFormat::MachO, &allow),
            NativeImportDecision::Denied("filesystem")
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        // The Linux control plane is now a single symbol — the `dlsym`
        // resolution primitive (reached through `-Wl,--wrap=dlsym` as
        // `__real_dlsym`) — matching macOS.
        assert_eq!(
            native_import_decision("dlsym", NativeFormat::Elf, &allow),
            NativeImportDecision::Allowed,
            "the dlsym resolution primitive should pass the baked control-plane set"
        );
        // The former named vehicles were swept off the import table (the shim
        // resolves the real host `read`/`write`/`sem_*`/`pthread_create` through
        // `dlsym` at runtime), so a guest importing one is now DENIED rather than
        // riding a name-based allowance — the structural fix for the sem_* escape
        // class, now extended to `pthread_create` (which no longer needs a
        // `--wrap` residue, so an unmanaged-thread import fails closed here too).
        for symbol in [
            "sem_wait",
            "sem_post",
            "sem_init",
            "__read",
            "__write",
            "pthread_create",
        ] {
            assert!(
                matches!(
                    native_import_decision(symbol, NativeFormat::Elf, &allow),
                    NativeImportDecision::Denied(_)
                ),
                "swept vehicle {symbol} must now fail closed"
            );
        }
        assert_eq!(
            native_import_decision("open", NativeFormat::Elf, &allow),
            NativeImportDecision::Denied("filesystem")
        );
    }
}

// Non-vacuity guard for the host-alias static check's predicate. Planted
// escape-surface names (the pre-doctrine shim's own vehicles, and a generic
// filesystem escape) must be reported as violations against the real
// control-plane allowance; the sanctioned `dlsym` resolution primitive and
// effect-free / Rust-mangled internals must not. This is the pure classifier
// half of the check that `cargo-patina/tests/shim_host_alias.rs` applies to the shim's
// compiled objects — if a future edit made `shim_host_alias_violation` go
// silent, this fails before the object scan could pass vacuously.
#[test]
fn shim_host_alias_violation_flags_planted_vehicle_names() {
    let allow = shim_control_plane_symbols();
    // The exact names the pre-doctrine shim named as undefined externals,
    // which the static check must catch (red state), plus a generic escape.
    // Note: `mach_task_self_`/`pthread_create_suspended_np` classify as
    // `unknown-import` (not a named escape class), so the object scan catches
    // the pre-doctrine baton through its `semaphore_*` and `read/write$NOCANCEL`
    // references — enough to go red — while the post-doctrine shim names none
    // of them at all.
    for (symbol, category) in [
        ("_semaphore_create", "unmanaged-sync"),
        ("_semaphore_wait", "unmanaged-sync"),
        ("_semaphore_signal", "unmanaged-sync"),
        ("_read$NOCANCEL", "filesystem"),
        ("_write$NOCANCEL", "filesystem"),
        ("_open", "filesystem"),
        ("_clock_gettime", "time"),
        ("_getentropy", "entropy"),
    ] {
        assert_eq!(
            shim_host_alias_violation(symbol, true, &allow),
            Some(category),
            "planted vehicle/escape {symbol} must be a host-alias violation"
        );
    }
    // The sanctioned resolution primitive and effect-free / mangled
    // internals are not violations (green state).
    for symbol in [
        "_dlsym",
        "_memcpy",
        "_strlen",
        "_rust_eh_personality",
        "__ZN4core3fmt9Formatter3pad17h0123456789abcdefE",
        "__RNvMsa_NtCs0_4core3fmtNtB5_9Formatter3pad",
    ] {
        assert_eq!(
            shim_host_alias_violation(symbol, true, &allow),
            None,
            "{symbol} must not be reported as a host-alias violation"
        );
    }
}

#[test]
fn deny_trap_armed_scan_fails_closed_on_a_foreign_input() {
    // A non-native (here, wasm) blob must fail closed rather than report clean:
    // either a native-format rejection or a parse rejection, never `Ok`.
    let wasm = module_importing(WASI_PREVIEW1_MODULE, "random_get");
    assert!(
        native_deny_trap_armed(&wasm).is_err(),
        "a foreign input must never be reported as carrying no armed surface"
    );
}

#[test]
fn live_interposer_scan_fails_closed_on_a_foreign_input() {
    // The guard must never report a foreign blob as fully satisfying the
    // required set (which would read as "all interposers present"); a
    // non-native input is an error, not an empty missing-list.
    let wasm = module_importing(WASI_PREVIEW1_MODULE, "random_get");
    assert!(
        native_missing_live_interposers(&wasm, NATIVE_LINUX_LIVE_INTERPOSERS).is_err(),
        "a foreign input must fail closed, never report zero missing interposers"
    );
}
