//! Native symbol normalization, allowlists, and escape classification tests.

use super::*;
use crate::instruction_scan::aarch64_instruction_category;
use std::collections::BTreeSet;
#[test]
fn classifies_known_native_escape_symbols() {
    assert_eq!(
        native_escape_category(normalize_native_symbol("_open")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_pthread_create")),
        Some("unmanaged-thread")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_os_unfair_lock_lock")),
        Some("unmanaged-sync")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("___ulock_wait")),
        Some("unmanaged-sync")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_read$NOCANCEL")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("__write")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_dup2")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_openat")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_unlinkat")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_renameat")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("renameat2")),
        Some("filesystem")
    );
    // Hard links and the openat-traversal directory stream: a raw import of
    // either (a prebuilt binary the shim strong defs did not absorb) is a host
    // filesystem escape, not a bare unknown import.
    assert_eq!(
        native_escape_category(normalize_native_symbol("_linkat")),
        Some("filesystem")
    );
    assert_eq!(
        native_escape_category(normalize_native_symbol("_fdopendir")),
        Some("filesystem")
    );
    assert_eq!(native_escape_category("malloc"), None);
    // macOS CoreFoundation / Security framework symbols (the rustls-native-certs
    // surface) classify as `macos-framework` rather than a bare unknown import,
    // so the gate can attach the host-trust-store determinism note.
    for symbol in [
        "_CFArrayCreate",
        "_CFStringGetLength",
        "_CFDataGetBytePtr",
        "_kCFAllocatorDefault",
        "_kCFTypeArrayCallBacks",
        "_SecCertificateCopyData",
        "_SecTrustSettingsCopyCertificates",
    ] {
        assert_eq!(
            native_escape_category(normalize_native_symbol(symbol)),
            Some("macos-framework"),
            "{symbol} should classify as macos-framework"
        );
    }
    // The prefix rule is a refinement of the unknown fallback only: a plain
    // libc/Rust name near those prefixes stays unclassified (deny as
    // unknown-import), and a real classification always wins. `secure_getenv`
    // starts with a lowercase `sec` (never the Apple `Sec` framework prefix)
    // and is a real environment-class symbol, so it classifies as such — not as
    // `macos-framework` and not as unknown.
    assert_eq!(native_escape_category("close"), Some("filesystem"));
    assert_eq!(native_escape_category("secure_getenv"), Some("environment"));
    assert_eq!(
        aarch64_instruction_category(0xd400_0001),
        Some(("direct-syscall", "svc"))
    );
    assert_eq!(
        aarch64_instruction_category(0xd53b_e040),
        Some(("cpu-nondeterminism", "cntvct"))
    );
    // The x86-64 boundary-aware scan is covered in `x86_scan::tests`.
}

#[test]
fn classifies_native_import_decisions() {
    let empty = BTreeSet::new();
    assert_eq!(
        native_import_decision("definitely_not_known", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("malloc", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("malloc", NativeFormat::Elf, &empty),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("__errno_location", NativeFormat::Elf, &empty),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("__errno_location", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("__error", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("dyld_stub_binder", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("dyld_stub_binder", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("open", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("filesystem")
    );
    assert_eq!(
        native_import_decision("_read$NOCANCEL", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("filesystem")
    );
    assert_eq!(
        native_import_decision("_Unwind_Resume", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    // Shim control-plane vehicles must NOT pass by default: they spawn or
    // block host threads outside the scheduler when imported by unmanaged
    // binaries. The validation scripts --allow them per audited binary.
    // libdispatch semaphores are normally *defined* (interposed) so they
    // never reach the import table, but if one ever did it is classified as
    // a blocking escape, not a bare unknown import.
    assert_eq!(
        native_import_decision("_dispatch_semaphore_wait", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unmanaged-sync")
    );
    // The Mach-semaphore baton vehicle: an unmanaged binary reaching it
    // directly is a blocking escape unless the caller --allows it.
    assert_eq!(
        native_import_decision("_semaphore_wait", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unmanaged-sync")
    );
    assert_eq!(
        native_import_decision("_pthread_create_suspended_np", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("sem_wait", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    // Directory reads are host effects not yet categorized; descriptor
    // duplication is modeled by the POSIX layer and categorized filesystem.
    assert_eq!(
        native_import_decision("_opendir", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("dup", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("filesystem")
    );
    assert_eq!(
        native_import_decision("gettid", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );

    // Pure libm math is known-safe on both formats with no `--allow`: the
    // MRE's `_pow` (and the rest of the pure math surface) resolves as an
    // undefined libm import that used to land in `unknown-import` and block
    // the run. It is now allowlisted — but ONLY the explicitly-listed pure
    // functions, never an effectful symbol that merely looks math-adjacent.
    for symbol in ["pow", "sqrtf", "hypot", "fma", "nearbyint", "llround"] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::MachO, &empty),
            NativeImportDecision::Allowed,
            "{symbol} is pure libm and must be known-safe on Mach-O"
        );
        assert_eq!(
            native_import_decision(symbol, NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "{symbol} is pure libm and must be known-safe on ELF"
        );
    }
    // The `_pow` alias form (Mach-O underscore decoration) normalizes onto the
    // same entry, so the exact symbol the MRE audit reported is now cleared.
    assert_eq!(
        native_import_decision("_pow", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    // Guard: genuinely-effectful symbols that share the math neighborhood must
    // NOT be swept in by the libm allowance. `random`/`drand48` draw from a
    // host PRNG; `system` spawns a process; `srand` mutates PRNG state. The
    // explicit-list discipline keeps all of them denied.
    assert_eq!(
        native_import_decision("random", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("random", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("drand48", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("srand", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("system", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("process")
    );

    let mut allow = BTreeSet::new();
    allow.insert("definitely_not_known".into());
    allow.insert("read".into());
    assert_eq!(
        native_import_decision("definitely_not_known", NativeFormat::MachO, &allow),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("_read$NOCANCEL", NativeFormat::MachO, &allow),
        NativeImportDecision::Allowed
    );
}

// aws-lc / DataFusion pure-compute surface: formatting/parsing/search over
// caller memory, the thread-local FP rounding env, and base-10 exp are
// allowlisted with NO `--allow` on both formats. These resolve to host libc as
// pure functions with no boundary effect; the shim's own interposed
// `fprintf`/`__assert_rtn` also format through `vsnprintf`.
#[test]
fn allowlists_aws_lc_and_datafusion_pure_compute() {
    let empty = BTreeSet::new();
    for symbol in [
        "bsearch",
        "vsnprintf",
        "sscanf",
        "fegetround",
        "fesetround",
        "exp10",
    ] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::MachO, &empty),
            NativeImportDecision::Allowed,
            "{symbol} is aws-lc/DataFusion pure-compute and must be known-safe on Mach-O"
        );
        assert_eq!(
            native_import_decision(symbol, NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "{symbol} is aws-lc/DataFusion pure-compute and must be known-safe on ELF"
        );
    }
    // The EXACT Mach-O import string DataFusion's audit reports for base-10 exp
    // is `___exp10` (C name `__exp10`, plus the Mach-O leading underscore).
    // normalize_native_symbol strips ALL leading underscores onto `exp10`, so
    // the observed symbol is cleared.
    assert_eq!(
        normalize_native_symbol("___exp10"),
        "exp10",
        "the ___exp10 Mach-O import must normalize onto the exp10 allowlist entry"
    );
    assert_eq!(
        native_import_decision("___exp10", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    // The `_vsnprintf`/`_bsearch` Mach-O underscore forms normalize onto the
    // same entries, so the exact audit-reported symbols are cleared.
    assert_eq!(
        native_import_decision("_vsnprintf", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    assert_eq!(
        native_import_decision("_bsearch", NativeFormat::MachO, &empty),
        NativeImportDecision::Allowed
    );
    // Guard: effectful stdio/parse neighbors that touch a real stream must NOT
    // be swept in — the explicit-list discipline keeps them denied. (`fprintf`,
    // `sprintf`, `fscanf`, `snprintf`, `scanf`, `printf` are not on the pure
    // list; `fprintf`/`__assert_rtn` are interposed by strong shim defs, and a
    // NON-shim binary importing `fprintf` raw stays denied here.)
    for symbol in ["fprintf", "sprintf", "fscanf", "scanf", "printf"] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::MachO, &empty),
            NativeImportDecision::Denied("unknown-import"),
            "{symbol} touches a real stream and must stay denied"
        );
    }
}

// The Linux tikv-jemallocator MRE audit surface: the classification half of
// the 12 imports the glibc build carries. The PURE/memory ones are allowlisted
// (cleared with no `--allow`); the effectful ones classify as their escape
// class for defense-in-depth (they are interposed by strong defs in
// `patina_posix.c`, so they drop off a shim-linked binary's import table, but a
// NON-shim binary importing them raw must still read as the right class, never
// slip through). The remaining four (`sched_getcpu`/`sched_setaffinity`/
// `pthread_sigmask`/`pthread_getname_np`) are interposed-only strong defs, like
// `issetugid` — not classified here, denied as `unknown-import` for a non-shim
// binary (fail-safe) and defined for a shim binary (verified by the Linux audit).
#[test]
fn classifies_linux_jemalloc_audit_surface() {
    let empty = BTreeSet::new();
    // Pure / process-local-memory imports: known-safe with no `--allow`.
    for symbol in ["mmap", "mmap64", "sbrk", "strcpy", "strncpy"] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "{symbol} must be known-safe on ELF"
        );
    }
    // The glibc `__`-prefixed pure helpers normalize (leading underscores
    // stripped) onto their allowlist entries.
    for symbol in ["__ctype_b_loc", "__sched_cpucount"] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "{symbol} (pure compute) must be known-safe on ELF"
        );
    }
    // Effectful imports classify as their escape class (interposed by strong
    // defs; this is the non-shim-binary defense-in-depth).
    assert_eq!(
        native_import_decision("creat", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("filesystem")
    );
    assert_eq!(
        native_import_decision("secure_getenv", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("environment")
    );
    // `sched_getcpu` (live CPU id) must NOT be mistaken for the pure
    // `__sched_cpucount`: it is interposed to a constant, and a non-shim import
    // stays denied rather than allowlisted.
    assert_eq!(
        native_import_decision("sched_getcpu", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
}

// The 20-crate ecosystem-audit symbol batch (task #42): two known-safe
// allowlist additions and two classification-only refinements. RED by
// construction — before the batch, `__cxa_atexit`/`strtol` were denied,
// `localtime_r`/`tzset` were `unknown-import`, and the whole host-
// introspection surface was `unknown-import`.
#[test]
fn classifies_ecosystem_audit_symbol_batch() {
    let empty = BTreeSet::new();

    // Tier 1 — known-safe allowlist additions, resolving on the exact format
    // the scout MREs surfaced them (and their normalized underscore forms).
    // `__cxa_atexit` is the macOS finalizer registrar (Mach-O `___cxa_atexit`
    // normalizes to `cxa_atexit`), mirroring the ELF `cxa_atexit` entry.
    for symbol in ["___cxa_atexit", "_cxa_atexit", "cxa_atexit"] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::MachO, &empty),
            NativeImportDecision::Allowed,
            "{symbol} (macOS finalizer registrar) must be known-safe on Mach-O"
        );
    }
    assert_eq!(
        native_import_decision("cxa_atexit", NativeFormat::Elf, &empty),
        NativeImportDecision::Allowed,
        "the ELF cxa_atexit entry this mirrors must stay known-safe"
    );
    // `strtol` is a pure caller-memory numeric parse on the common list, so
    // BOTH Mach-O `_strtol` and ELF `strtol` resolve.
    for (symbol, format) in [
        ("_strtol", NativeFormat::MachO),
        ("strtol", NativeFormat::MachO),
        ("strtol", NativeFormat::Elf),
    ] {
        assert_eq!(
            native_import_decision(symbol, format, &empty),
            NativeImportDecision::Allowed,
            "{symbol} (pure numeric parse) must be known-safe on {format:?}"
        );
    }

    // Tier 2 — classification-only refinements: the decision stays REFUSE,
    // only the label sharpens from `unknown-import` to a named class.
    // `localtime_r`/`tzset` are host-timezone-dependent time conversion on
    // BOTH formats (Mach-O `_localtime_r`, ELF `localtime_r`).
    for (symbol, format) in [
        ("_localtime_r", NativeFormat::MachO),
        ("localtime_r", NativeFormat::Elf),
        ("_tzset", NativeFormat::MachO),
        ("tzset", NativeFormat::Elf),
    ] {
        assert_eq!(
            native_import_decision(symbol, format, &empty),
            NativeImportDecision::Denied("time"),
            "{symbol} must classify as time (still denied) on {format:?}"
        );
    }

    // The new `host-introspection` class over a representative sample of the
    // Mach/BSD/IOKit host-state surface (from the sysinfo/mimalloc MREs),
    // including one member of each IOKit namespace prefix.
    for symbol in [
        "_sysctl",
        "_task_info",
        "_proc_pidinfo",
        "_vm_page_size",
        "_mach_host_self",
        "_host_statistics64",
        "_IOServiceMatching",
        "_IORegistryEntryGetName",
        "_IOIteratorNext",
        "_IOObjectRelease",
    ] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::MachO, &empty),
            NativeImportDecision::Denied("host-introspection"),
            "{symbol} should report the host-introspection class"
        );
    }

    // RED-guards.
    // (1) A classification is NOT an allowance: `sysctlbyname` stays DENIED.
    assert_eq!(
        native_import_decision("_sysctlbyname", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("host-introspection"),
        "sysctlbyname must stay denied — the class must never relax the deny"
    );
    // (2) The IOKit prefixes are namespace-scoped, not a bare `IO`: an
    // arbitrary user symbol starting `IO` must NOT match (no overreach).
    assert!(!is_host_introspection_symbol("IOWidget"));
    assert_eq!(
        native_import_decision("_IOWidget", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("unknown-import"),
        "a user IO* symbol must not be captured by the IOKit prefixes"
    );
    // (3) The `strtol` allowlist is exact, not a prefix: the sibling
    // `strtoul` (not in the batch) stays denied as an unknown import.
    for format in [NativeFormat::MachO, NativeFormat::Elf] {
        assert_eq!(
            native_import_decision("strtoul", format, &empty),
            NativeImportDecision::Denied("unknown-import"),
            "strtoul is not on the list; the strtol allowlist must be exact"
        );
    }
}

// Per-class detection proof: every escape class in the taxonomy
// (ESCAPE-CLASSES.md) classifies a representative symbol, and that symbol is
// actually DENIED end to end (not silently allowlisted). Red-before/
// green-after: deleting a class's deny list, or allowlisting its symbol,
// fails this. One row per class keeps the gate's coverage non-vacuous.
#[test]
fn every_escape_class_is_detected_and_denied() {
    // (class label, a representative symbol, its binary format)
    let rows: &[(&str, &str, NativeFormat)] = &[
        ("filesystem", "open", NativeFormat::Elf),
        ("network", "socket", NativeFormat::Elf),
        ("wait-multiplex", "kqueue", NativeFormat::MachO),
        ("wait-multiplex", "epoll_create1", NativeFormat::Elf),
        ("wait-multiplex", "epoll_ctl", NativeFormat::Elf),
        ("shared-memory-ipc", "eventfd", NativeFormat::Elf),
        ("unmanaged-sync", "os_unfair_lock_lock", NativeFormat::MachO),
        (
            "unmanaged-sync",
            "dispatch_semaphore_wait",
            NativeFormat::MachO,
        ),
        ("unmanaged-sync", "semaphore_wait", NativeFormat::MachO),
        ("time", "clock_gettime", NativeFormat::Elf),
        ("entropy", "arc4random", NativeFormat::MachO),
        ("unmanaged-thread", "pthread_create", NativeFormat::Elf),
        ("process", "posix_spawn", NativeFormat::Elf),
        ("signals-timers", "setitimer", NativeFormat::Elf),
        ("shared-memory-ipc", "shm_open", NativeFormat::Elf),
        ("environment", "setenv", NativeFormat::Elf),
        ("dynamic-loading", "dlopen", NativeFormat::Elf),
        ("direct-syscall", "syscall", NativeFormat::Elf),
    ];
    let empty = BTreeSet::new();
    for (class, symbol, format) in rows {
        assert_eq!(
            native_escape_category(symbol),
            Some(*class),
            "symbol {symbol} should classify as {class}"
        );
        assert_eq!(
            native_import_decision(symbol, *format, &empty),
            NativeImportDecision::Denied(class),
            "symbol {symbol} ({class}) must be denied by default (not allowlisted)"
        );
    }
}

// Pure-compute host symbols are known-safe with no `--allow`: they read or
// write only caller-owned memory (Darwin byte-pattern fills; POSIX
// signal-set bit manipulation) and carry no boundary effect. This is the
// audit-side half of the allowance-removal pivot proven against a real-world
// file-walking CLI: the process-spawn and host-state-query members of such a
// binary's old allow list become
// shim-*defined* (so they drop off the import table entirely), while these
// pure-compute members are cleared here instead of being interposed.
#[test]
fn pure_compute_symbols_are_known_safe() {
    let empty = BTreeSet::new();
    // Darwin memory fills are Mach-O-only libc intrinsics.
    for symbol in ["memset_pattern4", "memset_pattern8", "memset_pattern16"] {
        assert_eq!(
            native_import_decision(symbol, NativeFormat::MachO, &empty),
            NativeImportDecision::Allowed,
            "{symbol} is a pure caller-memory fill and must be known-safe"
        );
    }
    // Signal-set construction is pure on both formats.
    for format in [NativeFormat::MachO, NativeFormat::Elf] {
        for symbol in [
            "sigemptyset",
            "sigfillset",
            "sigaddset",
            "sigdelset",
            "sigismember",
        ] {
            assert_eq!(
                native_import_decision(symbol, format, &empty),
                NativeImportDecision::Allowed,
                "{symbol} only manipulates a caller-owned sigset_t and must be known-safe"
            );
        }
    }
    // But the thread signal-mask mutator and blocking signal waits stay
    // denied — clearing the pure set ops must not widen to delivery state.
    assert_eq!(
        native_import_decision("sigsuspend", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("signals-timers")
    );
    assert_eq!(
        native_import_decision("sigprocmask", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    // Compiler-rt 128-bit integer arithmetic is pure register/stack math on
    // both formats, with and without the leading-underscore decoration the
    // linker leaves on the import (Linux surfaces `__umodti3` from libgcc).
    for format in [NativeFormat::MachO, NativeFormat::Elf] {
        for symbol in [
            "__ashlti3",
            "__ashrti3",
            "__divti3",
            "__lshrti3",
            "__modti3",
            "__muloti4",
            "__multi3",
            "__udivmodti4",
            "__udivti3",
            "__umodti3",
            "umodti3",
        ] {
            assert_eq!(
                native_import_decision(symbol, format, &empty),
                NativeImportDecision::Allowed,
                "{symbol} is pure compiler-rt integer arithmetic and must be known-safe"
            );
        }
    }
    // Pure libm math is a function of its floating-point operands with no
    // boundary effect, on both formats. Sample across each sub-family so a
    // dropped line is caught. `f64`/`f32` method lowering (`powf`, `hypot`,
    // the rounding family) reaches these as undefined libm imports.
    for format in [NativeFormat::MachO, NativeFormat::Elf] {
        for symbol in [
            "pow",
            "powf",
            "exp",
            "log2",
            "sin",
            "cosf",
            "atan2",
            "tanh",
            "acosh",
            "sqrt",
            "cbrt",
            "hypot",
            "fmod",
            "fma",
            "ldexp",
            "frexp",
            "modf",
            "ceil",
            "floorf",
            "round",
            "rint",
            "nearbyint",
            "fabs",
            "copysign",
            "fmax",
            "fminf",
            "lround",
            "llrint",
        ] {
            assert_eq!(
                native_import_decision(symbol, format, &empty),
                NativeImportDecision::Allowed,
                "{symbol} is pure libm and carries no boundary effect"
            );
        }
    }
    // The libm allowance is explicit, not a prefix match: effectful symbols in
    // the same neighborhood stay refused. `random`/`drand48` are PRNG draws;
    // `system` spawns a process.
    assert_eq!(
        native_import_decision("random", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import")
    );
    assert_eq!(
        native_import_decision("system", NativeFormat::MachO, &empty),
        NativeImportDecision::Denied("process")
    );
}

// glibc alias generations. glibc ships a per-C-standard-generation alias for
// the handful of functions whose semantics changed between standards, and the
// COMPILER picks the alias: `<stdio.h>` redirects a C23 build's `sscanf` to
// `__isoc23_sscanf`, a C99 build's `scanf` to `__isoc99_scanf`. The import
// table therefore carries a name the base allowlist never matches, and the
// audit refused `__isoc23_sscanf` (aws-lc, Linux) even though plain `sscanf`
// has been known-safe all along — a pure spelling artifact, not a real escape.
// Normalizing the generation away audits the alias as the base symbol.
#[test]
fn normalizes_glibc_alias_generations_onto_the_base_symbol() {
    let empty = BTreeSet::new();
    for (alias, base) in [
        ("__isoc23_sscanf", "sscanf"),
        ("__isoc99_sscanf", "sscanf"),
        ("__isoc23_strtol", "strtol"),
        ("__isoc99_scanf", "scanf"),
    ] {
        assert_eq!(
            normalize_native_symbol(alias),
            base,
            "{alias} must normalize onto its base symbol"
        );
    }
    // The two the real aws-lc/shim surface carries clear with NO `--allow`,
    // because their base symbols are already known-safe pure compute.
    for alias in ["__isoc23_sscanf", "__isoc99_sscanf", "__isoc23_strtol"] {
        assert_eq!(
            native_import_decision(alias, NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "{alias} normalizes onto a known-safe base and must not need an allowance"
        );
    }
    // Normalization is not laundering: the generation prefix is stripped and
    // then the BASE symbol is classified, so an alias of an effectful base
    // stays denied under the base's own class.
    assert_eq!(
        native_import_decision("__isoc99_scanf", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("unknown-import"),
        "`scanf` touches a real stream, so its C99 alias must stay denied"
    );
    assert_eq!(
        native_import_decision("__isoc23_open", NativeFormat::Elf, &empty),
        NativeImportDecision::Denied("filesystem"),
        "an alias of a classified escape must report the base symbol's class"
    );
    // Only a real `isoc<digits>_` generation prefix is stripped; a symbol that
    // merely starts with the letters is untouched.
    for symbol in ["isocline_init", "isoc_sscanf", "isoc23sscanf", "isoc23_"] {
        assert_eq!(
            normalize_native_symbol(symbol),
            symbol,
            "{symbol} is not a glibc generation alias and must be left alone"
        );
    }
}

// ld.so's rseq layout words locate an area the virtual kernel owns; Darwin
// has no rseq, hence ELF-only.
#[test]
fn admits_glibcs_rseq_layout_words_on_elf_only() {
    let empty = BTreeSet::new();
    for word in ["__rseq_offset", "__rseq_size", "__rseq_flags"] {
        assert_eq!(
            native_import_decision(word, NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "{word}: the rseq area it locates is virtual"
        );
        assert_eq!(
            native_import_decision(word, NativeFormat::MachO, &empty),
            NativeImportDecision::Denied("unknown-import"),
            "{word}: Darwin has no rseq"
        );
    }
}

// The `assert()` failure hooks are shim definitions on both platforms
// (glibc's `__assert_fail`, Darwin's `__assert_rtn`): a shim-linked guest
// binds to them and never imports them. libc's own hook writes through
// libc's `stderr`, which in a guest is the shim's sentinel, so an import
// means the link lost the definition — refused, not known-safe.
#[test]
fn an_imported_assert_failure_hook_is_refused() {
    let empty = BTreeSet::new();
    for format in [NativeFormat::Elf, NativeFormat::MachO] {
        assert_eq!(
            native_import_decision("__assert_fail", format, &empty),
            NativeImportDecision::Denied("unknown-import"),
        );
    }
}
