//! Native symbol normalization, allowlists, and escape classification tests.

use super::*;
use std::collections::BTreeSet;

fn decide(symbol: &str, format: NativeFormat) -> NativeImportDecision {
    native_import_decision(symbol, format, &BTreeSet::new())
}

/// Mach-O decoration (leading underscores, `$NOCANCEL`) normalizes onto the
/// base name before classification. Apple's framework prefixes classify as
/// `macos-framework`; a lowercase lookalike keeps its own class.
#[test]
fn decorated_symbols_classify_as_their_base_name() {
    for (symbol, class) in [
        ("_read$NOCANCEL", "filesystem"),
        ("__write", "filesystem"),
        ("___ulock_wait", "unmanaged-sync"),
        ("_linkat", "filesystem"),
        ("_fdopendir", "filesystem"),
        ("_CFArrayCreate", "macos-framework"),
        ("_kCFAllocatorDefault", "macos-framework"),
        ("_SecTrustSettingsCopyCertificates", "macos-framework"),
        ("secure_getenv", "environment"),
    ] {
        assert_eq!(
            native_escape_category(normalize_native_symbol(symbol)),
            Some(class),
            "{symbol}"
        );
    }
    assert_eq!(native_escape_category("malloc"), None);
}

/// Some runtime support symbols are known-safe on one format only, an
/// unclassified name is an `unknown-import`, and an explicit allowance clears
/// both an unknown name and a classified escape (matched after normalization).
#[test]
fn import_decisions_depend_on_format_and_the_allow_set() {
    use NativeFormat::{Elf, MachO};
    use NativeImportDecision::{Allowed, Denied};
    for (symbol, format, expected) in [
        ("definitely_not_known", MachO, Denied("unknown-import")),
        ("__errno_location", Elf, Allowed),
        ("__errno_location", MachO, Denied("unknown-import")),
        ("__error", MachO, Allowed),
        ("dyld_stub_binder", MachO, Allowed),
        ("dyld_stub_binder", Elf, Denied("unknown-import")),
        (
            "_pthread_create_suspended_np",
            MachO,
            Denied("unknown-import"),
        ),
        ("_opendir", MachO, Denied("unknown-import")),
        ("gettid", Elf, Denied("unknown-import")),
        ("___exp10", MachO, Allowed),
        ("_pow", MachO, Allowed),
    ] {
        assert_eq!(decide(symbol, format), expected, "{symbol} on {format:?}");
    }
    let allow = BTreeSet::from(["definitely_not_known".to_owned(), "read".to_owned()]);
    assert_eq!(
        native_import_decision("definitely_not_known", MachO, &allow),
        Allowed
    );
    assert_eq!(
        native_import_decision("_read$NOCANCEL", MachO, &allow),
        Allowed
    );
}

/// The pure-compute allowlist is an exact list, not a prefix or neighbourhood
/// match: effectful neighbours of allowed names stay refused, under their own
/// escape class where they have one. A classification never relaxes a deny.
#[test]
fn the_pure_compute_allowlist_does_not_capture_effectful_neighbours() {
    use NativeFormat::{Elf, MachO};
    for (symbol, format) in [
        ("sscanf", Elf),
        ("strtol", MachO),
        ("pow", Elf),
        ("sigemptyset", Elf),
        ("__umodti3", Elf),
        ("memset_pattern4", MachO),
        ("_malloc_zone_malloc", MachO),
        ("_random", MachO),
        ("mmap", Elf),
        ("__ctype_b_loc", Elf),
    ] {
        assert_eq!(
            decide(symbol, format),
            NativeImportDecision::Allowed,
            "{symbol} on {format:?}"
        );
    }
    for (symbol, format, class) in [
        // Stream I/O beside the pure formatting and parsing entries.
        ("fprintf", MachO, "unknown-import"),
        ("printf", MachO, "unknown-import"),
        ("__isoc99_scanf", Elf, "unknown-import"),
        ("strtoul", Elf, "unknown-import"),
        // PRNG state and draws beside libm, and process spawning.
        ("drand48", MachO, "unknown-import"),
        ("random", Elf, "unknown-import"),
        ("srand", Elf, "unknown-import"),
        ("_srandom", MachO, "unknown-import"),
        ("_initstate", MachO, "unknown-import"),
        ("_srandomdev", MachO, "entropy"),
        ("system", MachO, "process"),
        // Signal delivery state beside the pure sigset operations.
        ("sigsuspend", Elf, "signals-timers"),
        ("sigprocmask", Elf, "unknown-import"),
        // A live CPU id beside the pure `__sched_cpucount`.
        ("sched_getcpu", Elf, "unknown-import"),
        ("creat", Elf, "filesystem"),
        ("_statfs", MachO, "filesystem"),
        ("_fsctl", MachO, "filesystem"),
        // Host-dependent time conversion and host introspection.
        ("_localtime_r", MachO, "time"),
        ("tzset", Elf, "time"),
        ("_sysctlbyname", MachO, "host-introspection"),
        ("_task_info", MachO, "host-introspection"),
        ("_IOServiceMatching", MachO, "host-introspection"),
        ("_gethostuuid", MachO, "host-introspection"),
        // The IOKit prefixes are namespace-scoped, not a bare `IO`.
        ("_IOWidget", MachO, "unknown-import"),
    ] {
        assert_eq!(
            decide(symbol, format),
            NativeImportDecision::Denied(class),
            "{symbol} on {format:?}"
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
        ("shared-memory-ipc", "msgrcv", NativeFormat::MachO),
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

// A name the shim interposes is admitted only as itself: an alias libc
// exports beside it normalizes onto it but is a different linker symbol the
// shim does not define, so it would run libc's own text. Aliases of the
// pure entries share their effect and stay admitted; `_exit` is its own
// listed entry, not an alias of `exit`.
#[test]
fn aliases_of_interposed_names_are_refused() {
    let empty = BTreeSet::new();
    let decide = |symbol, format| native_import_decision(symbol, format, &empty);
    for alias in [
        "__mmap",
        "__munmap",
        "__mprotect",
        "__madvise",
        "__sigaction",
        "__exit",
        "libc_start_main",
    ] {
        assert_ne!(
            decide(alias, NativeFormat::Elf),
            NativeImportDecision::Allowed,
            "{alias}"
        );
    }
    for name in [
        "mmap",
        "munmap",
        "sigaction",
        "exit",
        "_exit",
        "__libc_start_main",
        "__errno_location",
        "__isoc23_sscanf",
        "__stack_chk_fail",
    ] {
        assert_eq!(
            decide(name, NativeFormat::Elf),
            NativeImportDecision::Allowed,
            "{name}"
        );
    }
    // Mach-O spells C `exit` as `_exit` and C `_exit` as `__exit`; `_exit`
    // is listed as itself, so only its exact C name is admitted.
    for (name, admitted) in [("_exit", true), ("__exit", true), ("___exit", false)] {
        assert_eq!(
            decide(name, NativeFormat::MachO) == NativeImportDecision::Allowed,
            admitted,
            "{name}"
        );
    }
}
