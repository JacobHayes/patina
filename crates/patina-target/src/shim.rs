//! Shim markers, trap manageability, and linked containment capabilities.

use crate::import_policy::{
    NativeFormat, NativeImportDecision, UNKNOWN_IMPORT_CATEGORY, native_import_decision,
    normalize_native_symbol,
};
use crate::{NativeEscape, TargetError};
use object::{Object, ObjectSymbol};
use std::collections::{BTreeMap, BTreeSet};

/// The shim's control-plane entry symbol, defined (`#[no_mangle] extern "C"`)
/// only in a `cargo patina build` binary — the packaged startup constructor
/// calls it, so it is present and not dead-stripped. Its *defined* presence is
/// the marker that a native binary was linked against the shim staticlib: a
/// stock `cargo build` output has no such symbol. Mach-O decorates it with a
/// leading underscore (`_patina_init_from_env`), which `normalize_native_symbol`
/// strips, so the same name matches on both formats.
const SHIM_CONTROL_PLANE_MARKER: &str = "patina_init_from_env";

/// Whether a native binary was linked against the Patina shim staticlib, judged
/// by the *defined* presence of the shim control-plane marker
/// ([`SHIM_CONTROL_PLANE_MARKER`]) in its symbol table. A stock `cargo build`
/// binary does not define it and returns `false`; auditing such a binary raw
/// reports unsatisfied libc imports (`open`, `clock_gettime`, `pthread_mutex_*`,
/// ...) — the whole surface the shim *interposes* once linked — not the true
/// post-interposition residual, which misleads badly. Callers use this to fail
/// closed (refuse, or demand an explicit `--raw`) on a non-shim-linked binary.
///
/// Fails closed on a parse error or an unsupported binary format so a
/// malformed/foreign input is never silently treated as shim-linked.
pub fn native_binary_is_shim_linked(bytes: &[u8]) -> Result<bool, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    // Reject non-native formats up front; the marker only means anything for a
    // Mach-O/ELF native binary.
    NativeFormat::from_binary(file.format())?;
    Ok(file.symbols().chain(file.dynamic_symbols()).any(|symbol| {
        symbol.is_definition()
            && symbol
                .name()
                .map(|name| normalize_native_symbol(name) == SHIM_CONTROL_PLANE_MARKER)
                .unwrap_or(false)
    }))
}

/// The shim's SUD dispatch entry symbol, defined only when a dispatch-capable
/// shim (one that arms syscall-user-dispatch and services SIGSYS) is linked.
/// Its *defined* presence in the symbol table is condition (a) of the
/// `direct-syscall` instruction-finding audit downgrade: an older shim without
/// SUD does not define it, so its raw-syscall binaries keep today's refusal.
/// This is the exact marker the SIGSYS handler calls (`patina_sud_dispatch`),
/// so it can never be present without the dispatcher being linked.
const SUD_DISPATCH_MARKER: &str = "patina_sud_dispatch";

/// Whether a native binary carries the shim's SUD dispatch marker
/// ([`SUD_DISPATCH_MARKER`]) as a *defined* symbol — i.e. a dispatch-capable
/// shim is linked. Used by the audit to decide whether a `direct-syscall`
/// instruction finding may be downgraded to "SUD-managed" (the live kernel probe
/// is the second condition; see `cargo-patina`). Fails closed on a parse error
/// or unsupported format, so a malformed input is never treated as SUD-capable.
pub fn native_binary_has_sud_marker(bytes: &[u8]) -> Result<bool, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    NativeFormat::from_binary(file.format())?;
    Ok(file.symbols().chain(file.dynamic_symbols()).any(|symbol| {
        symbol.is_definition()
            && symbol
                .name()
                .map(|name| normalize_native_symbol(name) == SUD_DISPATCH_MARKER)
                .unwrap_or(false)
    }))
}

/// Whether a denied native escape is a `direct-syscall` finding that
/// syscall-user-dispatch can trap and route — i.e. a raw inline `syscall`/`svc`
/// *instruction* (`instruction@…`), as opposed to a `cpu-nondeterminism`
/// register read (`rdtsc`/`mrs CNTVCT`), which SUD cannot trap and which still
/// refuses. This is the escape set the SUD audit downgrade applies to.
///
/// The decision reads the decoded [`NativeEscape::mnemonic`]: the x86-64
/// 32-bit entries (`int 0x80`, `sysenter`) are `direct-syscall` too. SUD
/// traps them where the kernel has IA32 emulation, but they arrive with the i386
/// syscall ABI, which the shim's handler refuses (it accepts only its own arch's
/// `si_arch`); elsewhere they fault. Downgrading them would admit a binary the
/// run then aborts, so they stay refusals.
pub fn native_escape_is_sud_manageable(escape: &NativeEscape) -> bool {
    escape.category == "direct-syscall"
        && escape.symbol.starts_with("instruction@")
        && matches!(escape.mnemonic, Some("syscall" | "svc"))
}

/// The shim's timestamp-counter trap entry symbol, defined only when a shim that
/// arms `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` and services the resulting SIGSEGV is
/// linked. Its *defined* presence is condition (a) of the `rdtsc`/`rdtscp` audit
/// downgrade, exactly as [`SUD_DISPATCH_MARKER`] is for raw syscalls: an older
/// shim without the trap does not define it, so its rdtsc binaries keep today's
/// refusal. This is the symbol the SIGSEGV handler calls, so it can never be
/// present without the handler's dispatcher being linked.
const TSC_TRAP_MARKER: &str = "patina_tsc_dispatch";

/// Whether a native binary carries the shim's timestamp-counter trap marker
/// ([`TSC_TRAP_MARKER`]) as a *defined* symbol — i.e. a trap-capable shim is
/// linked. Used by the audit to decide whether an `rdtsc`/`rdtscp` finding may be
/// downgraded to "trap-managed" (the live platform probe is the second
/// condition; see `cargo-patina`). Fails closed on a parse error or unsupported
/// format, so a malformed input is never treated as trap-capable.
pub fn native_binary_has_tsc_marker(bytes: &[u8]) -> Result<bool, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    NativeFormat::from_binary(file.format())?;
    Ok(file.symbols().chain(file.dynamic_symbols()).any(|symbol| {
        symbol.is_definition()
            && symbol
                .name()
                .map(|name| normalize_native_symbol(name) == TSC_TRAP_MARKER)
                .unwrap_or(false)
    }))
}

/// Whether a denied native escape is a timestamp-counter read the shim's TSC trap
/// can intercept and answer from the virtual clock — i.e. an `rdtsc`/`rdtscp`
/// *instruction* finding (`instruction@…`).
///
/// This is the `cpu-nondeterminism` counterpart of
/// [`native_escape_is_sud_manageable`], and it is deliberately narrower than its
/// category: `rdrand`/`rdseed`/`mrs RNDR`/`mrs RNDRRS` (hardware entropy) and
/// `mrs CNTVCT_EL0` (the arm64 system counter) share the `cpu-nondeterminism`
/// label but no mechanism traps them, so they stay refusals. The decision reads the decoded
/// [`NativeEscape::mnemonic`], so a finding that carries none — a symbol import, a
/// `vsyscall` immediate, an `undecodable-instruction` — is never downgraded.
///
/// Manageability is a property of the *finding*; whether the trap is actually
/// armable here is the caller's second condition (x86-64 Linux, `PR_SET_TSC`
/// present, and the marker above).
pub fn native_escape_is_tsc_manageable(escape: &NativeEscape) -> bool {
    escape.category == "cpu-nondeterminism"
        && escape.symbol.starts_with("instruction@")
        && matches!(escape.mnemonic, Some("rdtsc" | "rdtscp"))
}

/// A native symbol the shim strong-defines as a *deny-trap*: merely LINKING it is
/// inert (the strong def binds the guest reference at link, so the symbol drops
/// off the import table and both `audit` and the pre-run gate PASS), but the first
/// CALL aborts the run deterministically with a diagnostic naming the symbol. This
/// is the "fails later" surface — a determinism guarantee that is invisible to an
/// import-table audit because the whole point of the deny-trap is to leave the
/// import table clean. `(symbol, class)`, where `class` is the same escape
/// category the pre-run gate prints for the equivalent un-interposed surface
/// (`process`/`macos-framework`/`host-introspection`).
pub type NativeDenyTrapSymbol = (&'static str, &'static str);

/// The enumerated deny-trap-armed symbols the native shim (`c/patina_posix.c`)
/// strong-defines: the process-spawn/identity family (`patina_process_trap`), the
/// macOS CoreFoundation/Security framework helpers left unreachable by the honest
/// empty-trust-store / UTC-timezone models (`PATINA_FRAMEWORK_TRAP`), and the
/// IOKit registry walk left unreachable by `IOServiceMatching` returning NULL
/// (`PATINA_INTROSPECTION_TRAP`).
///
/// This is the UNION across platforms. A given binary only *defines* the members
/// its target actually compiles — the framework/introspection set is
/// `__APPLE__`-only, `pidfd_*`/`posix_spawn_file_actions_addchdir*` are
/// `__linux__`-only — so [`native_deny_trap_armed`] reports exactly the
/// platform-correct subset by intersecting this union with the binary's real
/// symbol table (macOS ld64 further narrows it to the *referenced* traps; ELF
/// structurally cannot — see [`native_deny_trap_armed`]).
/// The data-symbol bindings the shim also defines (`kCFAllocator*`,
/// `mach_task_self_`, ...) are deliberately absent: reading a data symbol does not
/// abort, so it is not deny-trap armed.
///
/// SINGLE SOURCE OF TRUTH: the native shim's symbol registry
/// (`patina_dst_native_shim::registry::SYMBOLS`) carries one `Deny(class)` row
/// per trap, and `cargo-patina/tests/syscall_registry.rs` asserts three-way
/// agreement — this list, those rows, and the trap-calling definitions parsed
/// from the shim's C — so a trap converted to a real model (or a new one) must
/// move all three in lockstep or the gate fails closed.
const NATIVE_DENY_TRAP_SYMBOLS: &[NativeDenyTrapSymbol] = &[
    // process (patina_process_trap): spawn/exec/wait.
    ("execvp", "process"),
    ("fork", "process"),
    ("pidfd_getpid", "process"),
    ("pidfd_spawnp", "process"),
    ("posix_spawn_file_actions_addchdir", "process"),
    ("posix_spawn_file_actions_addchdir_np", "process"),
    ("posix_spawn_file_actions_adddup2", "process"),
    ("posix_spawn_file_actions_destroy", "process"),
    ("posix_spawn_file_actions_init", "process"),
    ("posix_spawnattr_destroy", "process"),
    ("posix_spawnattr_init", "process"),
    ("posix_spawnattr_setflags", "process"),
    ("posix_spawnattr_setpgroup", "process"),
    ("posix_spawnattr_setsigdefault", "process"),
    ("posix_spawnp", "process"),
    // host-introspection (patina_native_trap explicit sites + PATINA_INTROSPECTION_TRAP):
    // IOKit registry walk, unreachable while IOServiceMatching returns NULL.
    ("IOIteratorNext", "host-introspection"),
    ("IOObjectRelease", "host-introspection"),
    ("IORegistryEntryCreateCFProperty", "host-introspection"),
    ("IORegistryEntryGetName", "host-introspection"),
    ("IOServiceGetMatchingServices", "host-introspection"),
    // macos-framework (PATINA_FRAMEWORK_TRAP): CoreFoundation/Security helpers
    // downstream of the honest empty-trust-store / UTC-timezone models.
    ("CFArrayGetValueAtIndex", "macos-framework"),
    ("CFDataGetBytePtr", "macos-framework"),
    ("CFDataGetBytes", "macos-framework"),
    ("CFDataGetLength", "macos-framework"),
    ("CFDataGetTypeID", "macos-framework"),
    ("CFDictionaryGetValueIfPresent", "macos-framework"),
    ("CFEqual", "macos-framework"),
    ("CFGetTypeID", "macos-framework"),
    ("CFNumberGetValue", "macos-framework"),
    ("CFRetain", "macos-framework"),
    ("CFStringCreateWithBytesNoCopy", "macos-framework"),
    ("CFStringCreateWithCStringNoCopy", "macos-framework"),
    ("CFStringGetBytes", "macos-framework"),
    ("CFStringGetLength", "macos-framework"),
    ("SecCertificateCopyData", "macos-framework"),
    ("SecCopyErrorMessageString", "macos-framework"),
    ("SecTrustSettingsCopyTrustSettings", "macos-framework"),
];

/// The enumerated deny-trap-armed shim symbols (union across platforms). See
/// [`NATIVE_DENY_TRAP_SYMBOLS`]. Query this to render the "fails later" note, or
/// to test membership; use [`native_deny_trap_armed`] to scan an actual binary.
pub fn native_deny_trap_symbols() -> &'static [NativeDenyTrapSymbol] {
    NATIVE_DENY_TRAP_SYMBOLS
}

/// A deny-trap-armed symbol found DEFINED in a scanned native binary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeDenyTrap {
    pub symbol: String,
    pub class: &'static str,
}

/// Scan a shim-linked native binary's DEFINED symbol table for deny-trap-armed
/// shim symbols ([`native_deny_trap_symbols`]), returning the matches sorted by
/// symbol.
///
/// Why *defined* symbols, and why this is precise rather than noise: the deny-trap
/// strong def drops the symbol off the *import* table, so a defined match is the
/// only post-link evidence the binary carries the armed surface at all. The naive
/// worry is that every shim-linked binary defines the whole shim object and so
/// would report identically — and on ELF that is exactly what happens, by
/// STRUCTURAL necessity: the linker auto-exports every executable definition that
/// shadows a libc symbol to `.dynsym` (that export is what lets the shim interpose
/// glibc-internal calls at all), and a dynamic-exported symbol is a permanent GC
/// root, so no sectioning or `--gc-sections` arrangement can drop an unreferenced
/// trap (empirically confirmed: per-function-sectioned traps survived the link in
/// `.dynsym`). Suppressing the export (hidden visibility / dynamic lists) would
/// let a shared-library-internal call to a trapped symbol ESCAPE the trap — a
/// weakened runtime guarantee — so ELF deliberately reports the truthful full
/// armed union. On macOS, ld64 dead-strips at atom granularity and two-level
/// namespace means no `.dynsym`-style root, so a trap symbol survives essentially
/// iff the guest (transitively) references it — the note is precise there. A binary
/// whose target did not compile a given member simply never defines it, so the
/// platform-correct subset falls out for free. Fails closed on a parse error or a
/// non-native format (a foreign input is never reported as clean).
pub fn native_deny_trap_armed(bytes: &[u8]) -> Result<Vec<NativeDenyTrap>, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    // Only a native (Mach-O/ELF) binary carries these; refuse a foreign format so
    // it is never silently treated as carrying no armed surface.
    NativeFormat::from_binary(file.format())?;
    let armed: BTreeMap<&'static str, &'static str> =
        NATIVE_DENY_TRAP_SYMBOLS.iter().copied().collect();
    let mut found: BTreeMap<&'static str, &'static str> = BTreeMap::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if !symbol.is_definition() {
            continue;
        }
        let Ok(name) = symbol.name() else { continue };
        let normalized = normalize_native_symbol(name);
        if let Some((canonical, class)) = armed.get_key_value(normalized) {
            found.insert(*canonical, *class);
        }
    }
    Ok(found
        .into_iter()
        .map(|(symbol, class)| NativeDenyTrap {
            symbol: symbol.to_owned(),
            class,
        })
        .collect())
}

/// Load-bearing Linux shim interposers that MUST survive every guest link even
/// when the guest references NONE of them directly (normalized names, ELF).
///
/// These are reached through paths a defined/undefined-reference scan cannot see —
/// the `printf` family and the `stdout`/`stderr` sentinel globals are what keep
/// glibc's OWN internal stdio away from the sentinel `FILE` handles (an
/// un-interposed glibc `printf` aborts on the sentinel), and the deterministic-IO
/// interposers (`open`/`read`/`write`/`close`, `pthread_create`) are the runtime's
/// containment surface. If any future link change (gc flags, sectioning,
/// visibility, object staging) dropped one, a determinism hole (host stdio leak or
/// the sentinel abort) would reopen SILENTLY; [`native_missing_live_interposers`]
/// turns that into a loud, fail-closed check.
pub const NATIVE_LINUX_LIVE_INTERPOSERS: &[&str] = &[
    "printf",
    "fprintf",
    "vfprintf",
    "fputs",
    "fwrite",
    "puts",
    "putchar",
    "fputc",
    "stdout",
    "stderr",
    "open",
    "read",
    "write",
    "close",
    "pthread_create",
];

/// The names in `required` that the native binary `bytes` does NOT define
/// (normalized, sorted). An empty result means every required interposer survived
/// the link. Fails closed on a foreign/unparseable format (never reports a
/// non-native blob as fully satisfied). This is the guard that turns "the link
/// dropped a load-bearing interposer" from a silent determinism hole into a loud
/// failure; see [`NATIVE_LINUX_LIVE_INTERPOSERS`].
pub fn native_missing_live_interposers(
    bytes: &[u8],
    required: &[&str],
) -> Result<Vec<String>, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    NativeFormat::from_binary(file.format())?;
    let defined: BTreeSet<String> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter(|symbol| symbol.is_definition())
        .filter_map(|symbol| symbol.name().ok())
        .map(|name| normalize_native_symbol(name).to_owned())
        .collect();
    Ok(required
        .iter()
        .filter(|name| !defined.contains(**name))
        .map(|name| (*name).to_owned())
        .collect())
}

/// The shim's own host control-plane symbols the pre-run gate tolerates in a
/// `cargo patina native-build` binary for the current platform.
///
/// Under the host-alias doctrine (see the native shim's `hostapi` module and
/// ARCHITECTURE.md "Host-alias doctrine") the shim reaches every host vehicle —
/// the trace-fd descriptor I/O, the managed host-thread creation vehicle, and
/// the execution-baton semaphore — by resolving it at runtime through
/// `dlsym(RTLD_NEXT, ...)`, so none of those vehicle *names* appears in the
/// guest binary's import table. On macOS the whole set therefore collapses to
/// the single resolution primitive, `dlsym`: a guest importing `semaphore_wait`,
/// `pthread_create_suspended_np`, `read$NOCANCEL`, ... is now DENIED rather than
/// riding a name-based allowance. The residual `dlsym` allowance is the honest
/// near-empty remainder: static reachability cannot soundly deny it (std has its
/// own `dlsym`-probing paths and address-taken-`main` swallows the call-graph
/// closure, so a reachable-`dlsym`-denial would reject every std guest), so it
/// stays — adversarial-shaped and far narrower than the pre-doctrine nine-vehicle
/// allowance. A build-time redirect (rewriting non-shim objects' `dlsym`
/// references while the shim keeps the real resolver) is the closure candidate,
/// tracked separately.
///
/// Linux is swept onto the same table through `-Wl,--wrap=dlsym`: the shim
/// interposes `dlsym` for guest/std code (`__wrap_dlsym`) while reaching the real
/// glibc resolver through the wrap alias `__real_dlsym`, so `__read`/`__write`/
/// `sem_*` — and `pthread_create`, interposed by a plain strong def whose real
/// creator is resolved through the same table (no `--wrap=pthread_create`) —
/// all leave the guest import table. Its residue is therefore the single `dlsym`
/// resolution primitive, matching macOS.
///
/// BOTH the pre-run gate in `native-run` AND standalone `audit` bake this set in
/// through cargo-patina's single `effective_native_allow` constructor, so the
/// surface `audit` reports is exactly the surface `run` enforces (a guest
/// importing anything else on the blocking/effect surface still fails closed).
/// Auditing the shim's own `dlsym` control-plane vehicle as "denied" while `run`
/// silently permits it was a reported audit/run disparity; auditing against the
/// same effective allow set removes it. Default-deny stays provable: this set is
/// the fixed, near-empty `{dlsym}` control-plane residue, and every real escape
/// symbol outside it is still denied by both paths.
pub fn shim_control_plane_symbols() -> BTreeSet<String> {
    #[cfg(target_os = "macos")]
    const SYMBOLS: &[&str] = &[
        // The single host-alias resolution primitive. Every trace-fd, baton, and
        // thread-creation vehicle is resolved through it at runtime, so it is the
        // only shim host-control-plane name left in the import table.
        "dlsym",
    ];
    #[cfg(not(target_os = "macos"))]
    const SYMBOLS: &[&str] = &[
        // The host-alias resolution primitive, reached through `-Wl,--wrap=dlsym`
        // as `__real_dlsym`. Every trace-fd, baton-semaphore, and host-thread
        // creation vehicle is resolved through it at runtime
        // (`dlsym(RTLD_NEXT, ...)`), so `__read`/`__write`/`sem_*`/`pthread_create`
        // no longer appear in the guest import table; guest and std `dlsym`
        // references bind to the shim's `__wrap_dlsym`, which resolves only its
        // deterministic entropy routing table. So, as on macOS,
        // the whole control plane collapses to the single `dlsym` primitive.
        "dlsym",
    ];
    SYMBOLS.iter().map(|symbol| (*symbol).to_owned()).collect()
}

/// Whether `symbol` — an undefined external in one of the native shim's *own*
/// object files — is a host-alias-doctrine violation, given the shim's declared
/// control-plane `allow` set (normally [`shim_control_plane_symbols`]).
///
/// Returns the escape category for a *classified* escape-surface symbol
/// (filesystem, network, time, entropy, blocking-sync, ...) that the shim names
/// directly and has not declared, and `None` otherwise. This is the exact
/// per-symbol decision the guest-binary import audit uses, so the shim is held
/// to the same standard it enforces on guests and the two can never diverge —
/// the static `cargo-patina/tests/shim_host_alias.rs` scan feeds every
/// undefined external of the shim's objects through here and fails on any
/// `Some(_)`. `unknown-import` is deliberately *not* a violation here: it covers
/// Rust-mangled internal references (which resolve to other Rust objects at
/// final link, never a host library) and any genuinely-unknown host symbol,
/// which the guest pre-run audit denies separately if it is ever undeclared.
/// `macho` selects the Mach-O vs ELF format-specific allowlists.
pub fn shim_host_alias_violation(
    symbol: &str,
    macho: bool,
    allow: &BTreeSet<String>,
) -> Option<&'static str> {
    let format = if macho {
        NativeFormat::MachO
    } else {
        NativeFormat::Elf
    };
    match native_import_decision(symbol, format, allow) {
        NativeImportDecision::Denied(category) if category != UNKNOWN_IMPORT_CATEGORY => {
            Some(category)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
