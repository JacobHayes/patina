//! Target metadata and fail-closed import auditing.
//!
//! Internal crate: the analysis behind `cargo patina audit` and the pre-run
//! default-deny gate. It parses native (Mach-O/ELF) and `wasm32-wasip1`
//! artifacts, classifies every externally resolved import against the
//! interposed/known-safe allowlists, and reports the residual effect surface —
//! an unknown import is a refusal, never a silent escape. Adopters drive this
//! through the CLI; see [ARCHITECTURE.md] for the containment story.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind,
    SymbolIndex, SymbolKind,
};
use wasmparser::{Parser, Payload};

pub const WASI_PREVIEW1_TARGET: &str = "wasm32-wasip1";
pub const WASI_PREVIEW1_MODULE: &str = "wasi_snapshot_preview1";

/// Preview 1 imports implemented by the deterministic host adapter.
pub const SUPPORTED_PREVIEW1_IMPORTS: &[&str] = &[
    "args_get",
    "args_sizes_get",
    "clock_res_get",
    "clock_time_get",
    "environ_get",
    "environ_sizes_get",
    "fd_advise",
    "fd_allocate",
    "fd_close",
    "fd_datasync",
    "fd_fdstat_get",
    "fd_fdstat_set_flags",
    "fd_fdstat_set_rights",
    "fd_filestat_get",
    "fd_filestat_set_size",
    "fd_filestat_set_times",
    "fd_pread",
    "fd_prestat_dir_name",
    "fd_prestat_get",
    "fd_pwrite",
    "fd_read",
    "fd_readdir",
    "fd_renumber",
    "fd_seek",
    "fd_sync",
    "fd_tell",
    "fd_write",
    "path_create_directory",
    "path_filestat_get",
    "path_filestat_set_times",
    "path_link",
    "path_open",
    "path_readlink",
    "path_remove_directory",
    "path_rename",
    "path_symlink",
    "path_unlink_file",
    "poll_oneoff",
    "proc_exit",
    "proc_raise",
    "random_get",
    "sched_yield",
    "sock_accept",
    "sock_recv",
    "sock_send",
    "sock_shutdown",
];

/// The cooperative-SUT SDK import module a patina-built wasm guest links
/// against (the wasm mirror of the native shim's C ABI).
pub const PATINA_SDK_MODULE: &str = "patina_sdk";

/// SDK imports implemented by the deterministic WASI host. Allowlisted
/// UNCONDITIONALLY (not gated on `--buggify`): the import surface is a
/// link-time fact of a patina-built module, while whether buggify fires is a
/// run-time decision — sites are inert when disabled, mirroring native. The
/// security posture of the audit is unchanged: this module's effect surface is
/// a strict subset of what preview1 already grants (`rng` is the same seeded
/// entropy as `random_get`; every other function only mutates sandboxed SDK
/// state — site registries, assertion counters, lifecycle marks — with no
/// host effect). A module built without `cfg(patina)` carries none of these
/// imports.
pub const SUPPORTED_PATINA_SDK_IMPORTS: &[&str] = &[
    "buggify",
    "buggify_delay",
    "buggify_knob",
    "always",
    "sometimes",
    "reachable",
    "is_simulated",
    "rng",
    "lifecycle_setup_complete",
    "lifecycle_event",
    // The verdict ABI. Its effect surface is a structured record in the host's
    // own run state plus a diagnostic line — strictly less than `fd_write`
    // already grants.
    "verdict",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasiAudit {
    pub imports: Vec<WasmImport>,
}

/// The `object` value for a site whose defining object the linked image does not
/// record. Mach-O keeps a per-address object/archive-member map, so this is rare
/// there; ELF only records object identity for an input file's *local* symbols,
/// so every global symbol legitimately lands here (see [`NativeProvenanceIndex`]).
const UNKNOWN_OBJECT: &str = "unknown";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeProvenance {
    /// Compact object/archive-member label (`libfoo-<hash>.rlib(member.o)` on
    /// Mach-O, the codegen-unit object name on ELF), or [`UNKNOWN_OBJECT`] when
    /// the linked image no longer carries enough information.
    pub object: String,
    /// Rust crate name recovered from an rlib/member name or a Rust symbol.
    pub crate_name: Option<String>,
    /// Function/data symbol containing the reference or instruction site.
    pub containing_symbol: Option<String>,
    /// Native section containing the reference or instruction site.
    pub section: Option<String>,
}

impl NativeProvenance {
    pub fn unknown() -> Self {
        Self {
            object: UNKNOWN_OBJECT.into(),
            crate_name: None,
            containing_symbol: None,
            section: None,
        }
    }

    /// Whether this names nothing actionable: no object, no crate, no containing
    /// symbol. The section is deliberately not part of the judgement — it is the
    /// one field every site can fill in, so counting it as attribution turned
    /// each unattributable reference into its own `provenance=unknown` group
    /// instead of collapsing them into one.
    pub fn is_unknown(&self) -> bool {
        self.object == UNKNOWN_OBJECT
            && self.crate_name.is_none()
            && self.containing_symbol.is_none()
    }

    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if let Some(crate_name) = &self.crate_name {
            parts.push(format!("crate={crate_name}"));
        }
        if self.object != UNKNOWN_OBJECT {
            parts.push(format!("object={}", self.object));
        }
        if parts.is_empty() {
            return "provenance=unknown".into();
        }
        format!("provenance={}", parts.join(" "))
    }

    pub fn site_label(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(symbol) = &self.containing_symbol {
            parts.push(format!("symbol={symbol}"));
        }
        if let Some(section) = &self.section {
            parts.push(format!("section={section}"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEscape {
    pub symbol: String,
    pub category: &'static str,
    pub provenance: Vec<NativeProvenance>,
    /// For an *instruction* finding, the decoded mnemonic (`rdtsc`, `rdtscp`,
    /// `rdrand`, `rdseed`, `syscall`, `svc`, `cntvct`); `None` for a symbol,
    /// immediate, or undecodable finding.
    ///
    /// The category alone cannot decide manageability: `cpu-nondeterminism`
    /// covers both the timestamp counter (trappable via `PR_SET_TSC` on x86-64
    /// Linux) and the RNG/system-counter reads (`rdrand`/`rdseed`/`mrs CNTVCT`),
    /// which no mechanism traps. [`native_escape_is_tsc_manageable`] reads this
    /// field to keep the two apart, so an escape carrying no mnemonic is never
    /// downgraded.
    pub mnemonic: Option<&'static str>,
}

impl NativeEscape {
    fn new(symbol: String, category: &'static str, provenance: Vec<NativeProvenance>) -> Self {
        Self {
            symbol,
            category,
            provenance: normalize_provenance(provenance),
            mnemonic: None,
        }
    }

    /// Attach the decoded mnemonic of an instruction finding (see
    /// [`NativeEscape::mnemonic`]).
    fn with_mnemonic(mut self, mnemonic: &'static str) -> Self {
        self.mnemonic = Some(mnemonic);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAudit {
    pub imports: Vec<String>,
    /// Imports the undefined-weak rule cleared: see [`render_inert_weak_imports`].
    pub inert_weak_imports: Vec<String>,
}

/// Render the "inert weak imports" heading for an audit's
/// [`NativeAudit::inert_weak_imports`], or `None` when there are none.
///
/// These are not allowed imports; they are references that cannot reach the host
/// at all, and the audit reports them so the surface stays visible rather than
/// disappearing into the clean-audit case.
pub fn render_inert_weak_imports(imports: &[String]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut output = String::from(
        "inert weak imports (undefined weak: resolve to NULL, the referencing code takes its \
         guarded fallback — not a host door):",
    );
    for import in imports {
        output.push_str("\n  ");
        output.push_str(import);
    }
    Some(output)
}

impl NativeAudit {
    /// Audit native imports and reject every symbol that is not explicitly
    /// caller-allowed or classified as safe for the binary's native format.
    pub fn audit(bytes: &[u8], allow: &BTreeSet<String>) -> Result<Self, TargetError> {
        let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
        let format = NativeFormat::from_binary(file.format())?;
        let mut imports = file
            .imports()
            .map_err(TargetError::NativeParse)?
            .into_iter()
            .map(|import| String::from_utf8_lossy(import.name()).into_owned())
            .collect::<Vec<_>>();
        imports.sort();
        imports.dedup();
        let provenance = NativeProvenanceIndex::new(&file);
        let import_provenance = collect_import_provenance(&file, bytes, &provenance);
        let inert_weak = inert_weak_symbols(&file);
        let mut inert_weak_imports = Vec::new();
        let mut denied = Vec::new();
        for symbol in &imports {
            let NativeImportDecision::Denied(category) =
                native_import_decision(symbol, format, allow)
            else {
                continue;
            };
            if category == UNKNOWN_IMPORT_CATEGORY
                && inert_weak.contains(normalize_native_symbol(symbol))
            {
                inert_weak_imports.push(symbol.clone());
                continue;
            }
            denied.push(NativeEscape::new(
                symbol.clone(),
                category,
                import_provenance
                    .get(symbol)
                    .cloned()
                    .unwrap_or_else(|| vec![NativeProvenance::unknown()]),
            ));
        }
        denied.extend(scan_forbidden_instructions(&file, &provenance)?);
        if !denied.is_empty() {
            return Err(TargetError::UnsupportedNativeImports(denied));
        }
        Ok(Self {
            imports,
            inert_weak_imports,
        })
    }
}

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
pub fn native_escape_is_sud_manageable(escape: &NativeEscape) -> bool {
    escape.category == "direct-syscall" && escape.symbol.starts_with("instruction@")
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
/// category: `rdrand`/`rdseed` (hardware entropy) and `mrs CNTVCT_EL0` (the arm64
/// system counter) share the `cpu-nondeterminism` label but no mechanism traps
/// them, so they stay refusals. The decision reads the decoded
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

/// The refusal note for `cpu-nondeterminism` *instruction* findings that are
/// blocked, or `None` when the blocked set has none.
///
/// Two things were previously left unsaid at a refusal, and both misled:
///
/// 1. an instruction finding has no symbol name, so `--allow <symbol>` can never
///    clear one — the finding's "symbol" is a `.text` offset;
/// 2. `rdtsc`/`rdtscp` ARE trap-managed on x86-64 Linux, so the same binary that
///    is refused here runs contained there, while `rdrand`/`rdseed`/`mrs CNTVCT`
///    are refused everywhere because no mechanism traps them.
///
/// The note names which of the two the blocked findings are, by mnemonic, so the
/// operator is told whether a different platform (or a rebuild) is the fix.
pub fn render_cpu_nondeterminism_note(blocked: &[NativeEscape]) -> Option<String> {
    let instructions: Vec<&NativeEscape> = blocked
        .iter()
        .filter(|escape| {
            escape.category == "cpu-nondeterminism" && escape.symbol.starts_with("instruction@")
        })
        .collect();
    if instructions.is_empty() {
        return None;
    }
    let trappable: BTreeSet<&str> = instructions
        .iter()
        .filter(|escape| native_escape_is_tsc_manageable(escape))
        .filter_map(|escape| escape.mnemonic)
        .collect();
    let untrappable: BTreeSet<&str> = instructions
        .iter()
        .filter(|escape| !native_escape_is_tsc_manageable(escape))
        .filter_map(|escape| escape.mnemonic)
        .collect();

    let mut note = String::from(
        "note: the cpu-nondeterminism finding(s) above are INSTRUCTIONS, not imports: each names a \
         .text offset, so --allow <symbol> cannot clear one (there is no symbol to allow).",
    );
    if !trappable.is_empty() {
        note.push_str(&format!(
            " The {} site(s) read the timestamp counter, which the shim traps into the virtual \
             clock via prctl(PR_SET_TSC) — but only on x86-64 Linux with a trap-capable shim \
             linked. Here the trap is unavailable, so they are refused: run on x86-64 Linux, or \
             rebuild the guest without the inline timestamp read.",
            trappable.into_iter().collect::<Vec<_>>().join("/")
        ));
    }
    if !untrappable.is_empty() {
        note.push_str(&format!(
            " The {} site(s) are unallowable AND untrappable anywhere: no mechanism intercepts a \
             hardware entropy read or the arm64 system counter, so the deterministic runtime can \
             neither model nor contain them. The only fix is to remove the instruction — use the \
             interposed entropy/clock entry points (getrandom/clock_gettime) instead.",
            untrappable.into_iter().collect::<Vec<_>>().join("/")
        ));
    }
    Some(note)
}

/// The note naming the `rdtsc`/`rdtscp` sites the TSC trap manages for a run that
/// proceeds — the counterpart of the SUD-managed note, emitted by both the audit
/// and the pre-run gate so a contained escape is visible rather than silent.
pub fn render_tsc_managed_note(managed: &[NativeEscape], subject: &str) -> Option<String> {
    if managed.is_empty() {
        return None;
    }
    Some(format!(
        "patina: {} timestamp-counter instruction site(s) in {subject} are trap-managed: \
         rdtsc/rdtscp raise SIGSEGV via prctl(PR_SET_TSC) and are answered from the run's virtual \
         clock (1 GHz nominal, so a tick is a virtual nanosecond). These are contained, not \
         escapes — the run stays deterministic.",
        managed.len()
    ))
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
/// `__APPLE__`-only, `pidfd_*`/`waitid`/`posix_spawn_file_actions_addchdir*` are
/// `__linux__`-only — so [`native_deny_trap_armed`] reports exactly the
/// platform-correct subset by intersecting this union with the binary's real
/// symbol table (macOS ld64 further narrows it to the *referenced* traps; ELF
/// structurally cannot — see [`native_deny_trap_armed`]).
/// The data-symbol bindings the shim also defines (`kCFAllocator*`,
/// `mach_task_self_`, ...) are deliberately absent: reading a data symbol does not
/// abort, so it is not deny-trap armed.
///
/// SINGLE SOURCE OF TRUTH: the `deny_trap_symbols_track_the_shim_c_source` test
/// parses `patina_posix.c` and asserts this list equals exactly its trap-calling
/// definitions, so when a trap is converted to a real model (or a new one is
/// added) in the C, this list must move in lockstep or the test fails closed.
const NATIVE_DENY_TRAP_SYMBOLS: &[NativeDenyTrapSymbol] = &[
    // process (patina_process_trap): spawn/exec/wait/identity mutation.
    ("chdir", "process"),
    ("chroot", "process"),
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
    ("setgid", "process"),
    ("setgroups", "process"),
    ("setpgid", "process"),
    ("setsid", "process"),
    ("setuid", "process"),
    ("waitid", "process"),
    ("waitpid", "process"),
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
/// the static `validate-native-shim.sh` "host-alias" section feeds every
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

/// The category of a denied import that matches no named escape class.
const UNKNOWN_IMPORT_CATEGORY: &str = "unknown-import";

/// The normalized names this binary references *only* through undefined weak
/// bindings — the references an undefined-weak import can be judged inert on.
///
/// An undefined weak reference is the C way of asking "is this hook present?":
/// if nothing supplies a definition it resolves to NULL and the referencing code
/// takes its guarded fallback path (aws-lc's `OPENSSL_memory_alloc`/`_free`/
/// `_get_size`/`_realloc` allocator-override hooks and `sdallocx`). A NULL that
/// is never called is not a door to the host, so refusing one is a false
/// positive.
///
/// The rule is only as sound as its disqualifiers, and both are computed over the
/// WHOLE audited closure — every static and dynamic symbol, definitions included:
///
/// * a name the closure **defines** anywhere is removed. The weak reference then
///   binds to that real code, which is exactly the classification path's job.
/// * a name with any **strong** undefined reference is removed. A strong
///   reference must be bound for the process to start, so the weak sibling rides
///   along to whatever definition satisfies it.
///
/// Callers apply this only to imports that match no named escape class (see
/// [`UNKNOWN_IMPORT_CATEGORY`]); that narrowing is load-bearing, not cosmetic.
/// "Undefined" means undefined *in this image*, and the dynamic linker still
/// searches the loaded libraries — so a weak undefined `open` binds to libc's
/// `open` at load time and runs. The classified names are precisely the ones a
/// loaded library defines, so a weak binding may never rescue one.
fn inert_weak_symbols(file: &object::File<'_>) -> BTreeSet<String> {
    let mut weak_undefined: BTreeSet<String> = BTreeSet::new();
    let mut disqualified: BTreeSet<String> = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let normalized = normalize_native_symbol(name).to_owned();
        // Anything that is not an undefined *weak* reference disqualifies the
        // name: a definition binds it, and a strong reference forces a binding.
        // Judged on the negative so an exotic binding (common, absolute, a format
        // the reader classifies as neither) also disqualifies — fail closed.
        if symbol.is_undefined() && symbol.is_weak() {
            weak_undefined.insert(normalized);
        } else {
            disqualified.insert(normalized);
        }
    }
    weak_undefined
        .difference(&disqualified)
        .cloned()
        .collect::<BTreeSet<_>>()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeFormat {
    MachO,
    Elf,
}

impl NativeFormat {
    fn from_binary(format: BinaryFormat) -> Result<Self, TargetError> {
        match format {
            BinaryFormat::MachO => Ok(Self::MachO),
            BinaryFormat::Elf => Ok(Self::Elf),
            _ => Err(TargetError::UnsupportedNativeFormat(format)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeImportDecision {
    Allowed,
    Denied(&'static str),
}

fn native_import_decision(
    symbol: &str,
    format: NativeFormat,
    allow: &BTreeSet<String>,
) -> NativeImportDecision {
    let normalized = normalize_native_symbol(symbol);
    if allow.contains(symbol) || allow.contains(normalized) {
        return NativeImportDecision::Allowed;
    }
    if native_allowlisted_import(normalized, format) {
        return NativeImportDecision::Allowed;
    }
    NativeImportDecision::Denied(
        native_escape_category(normalized).unwrap_or(UNKNOWN_IMPORT_CATEGORY),
    )
}

fn native_allowlisted_import(symbol: &str, format: NativeFormat) -> bool {
    common_native_allowlisted_import(symbol)
        || match format {
            NativeFormat::MachO => macho_native_allowlisted_import(symbol),
            NativeFormat::Elf => elf_native_allowlisted_import(symbol),
        }
}

fn normalize_provenance(mut provenance: Vec<NativeProvenance>) -> Vec<NativeProvenance> {
    if provenance.is_empty() {
        return vec![NativeProvenance::unknown()];
    }
    // Collapse every unattributable site to the one canonical `unknown`, so a
    // set of them dedups to a single entry and is then dropped outright when any
    // attributed site exists for the same symbol.
    for entry in &mut provenance {
        if entry.is_unknown() {
            *entry = NativeProvenance::unknown();
        }
    }
    provenance.sort();
    provenance.dedup();
    if provenance.len() > 1 {
        provenance.retain(|entry| !entry.is_unknown());
    }
    if provenance.is_empty() {
        vec![NativeProvenance::unknown()]
    } else {
        provenance
    }
}

#[derive(Clone, Debug)]
struct AddressProvenance {
    address: u64,
    size: u64,
    object_path: Option<String>,
    archive_member: Option<String>,
    symbol: Option<String>,
}

struct NativeProvenanceIndex {
    entries: Vec<AddressProvenance>,
}

impl NativeProvenanceIndex {
    fn new(file: &object::File<'_>) -> Self {
        let mut entries = Vec::new();

        // Mach-O keeps STAB-derived object/archive-member provenance. The object
        // crate exposes it as an address map, so preserve it before falling back
        // to the generic symbol table below.
        let object_map = file.object_map();
        for entry in object_map.symbols() {
            let object = entry.object(&object_map);
            entries.push(AddressProvenance {
                address: entry.address(),
                size: entry.size(),
                object_path: Some(bytes_to_string(object.path())),
                archive_member: object.member().map(bytes_to_string),
                symbol: Some(bytes_to_string(entry.name())),
            });
        }

        // The generic symbol table: the only source of a containing symbol on
        // ELF, and the fallback for a Mach-O image whose object map was stripped.
        //
        // ELF also carries STT_FILE markers naming each input object, but their
        // reach is narrow and easy to overstate. A file symbol is itself local,
        // and ELF requires every local symbol to precede the first global, so a
        // marker only names the input object of the LOCAL symbols that follow it
        // — the run ends at the first global, after which no marker applies to
        // anything. Carrying the marker forward regardless attributed every
        // global symbol in the image to whichever file symbol happened to come
        // last (`crtstuff.c`, `ucmpti2.c`, ...), which is wrong for essentially
        // every Rust symbol, and produced groups as self-contradictory as
        // `crate=leaker_a object=crtstuff.c`. So the association stops at the
        // local run; a global's object is genuinely not recorded in a linked ELF
        // and degrades to `unknown`, with `crate=` still recovered from the
        // symbol's own mangling.
        let mut current_file = None;
        for symbol in file.symbols() {
            if symbol.kind() == SymbolKind::File {
                current_file = symbol
                    .name()
                    .ok()
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned);
                continue;
            }
            if !symbol.is_local() {
                current_file = None;
            }
            if !symbol.is_definition() || symbol.address() == 0 {
                continue;
            }
            if !matches!(
                symbol.kind(),
                SymbolKind::Text | SymbolKind::Label | SymbolKind::Data | SymbolKind::Unknown
            ) {
                continue;
            }
            entries.push(AddressProvenance {
                address: symbol.address(),
                size: symbol.size(),
                object_path: current_file.clone(),
                archive_member: None,
                symbol: symbol.name().ok().map(str::to_owned),
            });
        }

        entries.sort_by_key(|entry| (entry.address, entry.size));
        Self { entries }
    }

    fn for_address(&self, address: u64, section: Option<&str>) -> NativeProvenance {
        let mut best = None;
        for entry in &self.entries {
            if entry.address > address {
                break;
            }
            if address_in_entry(address, entry) {
                best = match best {
                    None => Some(entry),
                    Some(prev) if entry_better(entry, prev) => Some(entry),
                    Some(prev) => Some(prev),
                };
            }
        }

        let Some(entry) = best else {
            let mut unknown = NativeProvenance::unknown();
            unknown.section = section.map(str::to_owned);
            return unknown;
        };

        let object = entry
            .object_path
            .as_deref()
            .map(|path| compact_object_label(path, entry.archive_member.as_deref()))
            .unwrap_or_else(|| "unknown".into());
        let crate_name = entry
            .object_path
            .as_deref()
            .and_then(|path| crate_name_from_object(path, entry.archive_member.as_deref()))
            .or_else(|| {
                entry
                    .archive_member
                    .as_deref()
                    .and_then(crate_name_from_object_member)
            })
            .or_else(|| entry.symbol.as_deref().and_then(crate_name_from_symbol));

        NativeProvenance {
            object,
            crate_name,
            containing_symbol: entry.symbol.clone(),
            section: section.map(str::to_owned),
        }
    }
}

fn address_in_entry(address: u64, entry: &AddressProvenance) -> bool {
    if entry.size == 0 {
        address == entry.address
    } else {
        address >= entry.address && address < entry.address.saturating_add(entry.size)
    }
}

/// Which of two entries containing the same address describes it more precisely.
/// The tightest container wins: a smaller sized symbol is nested inside a larger
/// one, and a sized symbol beats a zero-size label (which matched only because it
/// sits exactly on the address). Object provenance breaks ties between equally
/// precise entries only — ranking it first let a bare label outrank the function
/// that actually contains the site.
fn entry_better(candidate: &AddressProvenance, current: &AddressProvenance) -> bool {
    match (candidate.size, current.size) {
        (0, 0) => candidate.object_path.is_some() && current.object_path.is_none(),
        (0, _) => false,
        (_, 0) => true,
        (candidate_size, current_size) if candidate_size != current_size => {
            candidate_size < current_size
        }
        _ => candidate.object_path.is_some() && current.object_path.is_none(),
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The compact label for a defining object, or [`UNKNOWN_OBJECT`] when the
/// sources produce no name at all.
///
/// The empty case is a real one, not defensive padding: an ELF STT_FILE marker
/// can carry an empty name, and a marker whose name is empty was rendered as a
/// bare `object=` with nothing after it — an "attribution" naming nothing, which
/// is the arm64 flavor of the same wrong answer x86_64 gave by borrowing a
/// neighbor's marker. Nothing downstream should have to distinguish an empty
/// object from an absent one, so an empty label never leaves this function.
fn compact_object_label(path: &str, member: Option<&str>) -> String {
    let file = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    let label = match member {
        Some(member) if !member.is_empty() => format!("{file}({member})"),
        _ => file.to_string(),
    };
    if label.is_empty() {
        UNKNOWN_OBJECT.to_string()
    } else {
        label
    }
}

fn crate_name_from_object(path: &str, member: Option<&str>) -> Option<String> {
    let file = Path::new(path).file_name()?.to_str()?;
    crate_name_from_archive(file)
        .or_else(|| member.and_then(crate_name_from_object_member))
        .or_else(|| crate_name_from_codegen_unit(file))
        .or_else(|| crate_name_from_source_path(path))
}

/// The crate behind an ELF STT_FILE marker. rustc names each codegen unit
/// `<crate>.<hash>-cgu.<n>` (`std.1e3c4ec04c5261a9-cgu.0`), and that name is what
/// the linker copies into the file symbol, so it is the ELF counterpart of a
/// Mach-O archive member. Local-crate codegen units are named by hash alone and
/// carry no crate, which this rejects rather than inventing one.
fn crate_name_from_codegen_unit(file: &str) -> Option<String> {
    let (crate_name, rest) = file.split_once('.')?;
    let (hash, index) = rest.rsplit_once("-cgu.")?;
    let valid = !crate_name.is_empty()
        && crate_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !crate_name.starts_with(|byte: char| byte.is_ascii_digit())
        && !hash.is_empty()
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit());
    valid.then(|| crate_name.to_owned())
}

fn crate_name_from_archive(file: &str) -> Option<String> {
    let stem = file.strip_suffix(".rlib")?;
    let stem = stem.strip_prefix("lib").unwrap_or(stem);
    strip_hash_suffix(stem).map(str::to_owned)
}

fn crate_name_from_object_member(member: &str) -> Option<String> {
    let file = Path::new(member)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(member);
    let stem = file.strip_suffix(".o").unwrap_or(file);
    strip_hash_suffix(stem).map(str::to_owned)
}

fn crate_name_from_source_path(path: &str) -> Option<String> {
    let mut prev = None;
    for component in Path::new(path).components() {
        let text = component.as_os_str().to_str()?;
        if text == "src" {
            return prev.map(str::to_owned);
        }
        prev = Some(text);
    }
    None
}

fn strip_hash_suffix(stem: &str) -> Option<&str> {
    let (prefix, suffix) = stem.rsplit_once('-').unwrap_or((stem, ""));
    if suffix.len() >= 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(prefix)
    } else if !stem.is_empty() {
        Some(stem)
    } else {
        None
    }
}

fn crate_name_from_symbol(symbol: &str) -> Option<String> {
    let stripped = symbol.trim_start_matches('_');
    let demangled = rustc_demangle::try_demangle(stripped)
        .or_else(|_| rustc_demangle::try_demangle(symbol))
        .ok()?;
    crate_name_from_demangled_path(&format!("{demangled:#}"))
}

/// The defining crate at the head of a demangled Rust path. A free path starts
/// with the crate outright (`std::io::copy`), but an inherent- or trait-impl
/// method starts with the impl header instead
/// (`<std::os::unix::process::Child as ChildExt>::kill_process_group`), and impl
/// methods dominate a real binary's symbol table — refusing to look past the
/// header left `crate=` unrecoverable for most of it. The leading type
/// punctuation is peeled, then the head identifier is accepted only when a `::`
/// follows it, so a generic parameter or primitive (`<T as ...>`, `<u32 as ...>`)
/// is rejected instead of being reported as a crate.
fn crate_name_from_demangled_path(path: &str) -> Option<String> {
    let mut rest = path.trim_start();
    loop {
        let peeled = ['<', '&', '*', '(', '[']
            .iter()
            .find_map(|prefix| rest.strip_prefix(*prefix))
            .or_else(|| {
                ["mut ", "const ", "dyn ", "impl "]
                    .iter()
                    .find_map(|prefix| rest.strip_prefix(*prefix))
            });
        match peeled {
            Some(peeled) => rest = peeled.trim_start(),
            None => break,
        }
    }

    let end =
        rest.find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))?;
    let (name, tail) = rest.split_at(end);
    if !tail.starts_with("::") || name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    Some(name.to_owned())
}

fn collect_import_provenance(
    file: &object::File<'_>,
    bytes: &[u8],
    provenance: &NativeProvenanceIndex,
) -> BTreeMap<String, Vec<NativeProvenance>> {
    let mut origins: BTreeMap<String, BTreeSet<NativeProvenance>> = BTreeMap::new();
    collect_section_relocation_provenance(file, provenance, &mut origins);

    let targets = collect_import_targets(file, bytes);
    if !targets.is_empty() {
        collect_import_xref_provenance(file, provenance, &targets, &mut origins);
    }

    origins
        .into_iter()
        .map(|(symbol, set)| (symbol, normalize_provenance(set.into_iter().collect())))
        .collect()
}

fn collect_section_relocation_provenance(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    for section in file.sections() {
        let section_name = section.name().ok();
        for (offset, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Some(symbol) = file
                .symbol_by_index(index)
                .ok()
                .and_then(|symbol| symbol.name().ok().map(str::to_owned))
            else {
                continue;
            };
            let address = section.address().saturating_add(offset);
            insert_origin(
                origins,
                &symbol,
                provenance.for_address(address, section_name),
            );
        }
    }
}

fn collect_import_targets(file: &object::File<'_>, bytes: &[u8]) -> BTreeMap<u64, String> {
    let mut targets = BTreeMap::new();
    collect_elf_import_targets(file, &mut targets);
    collect_macho_import_targets(file, bytes, &mut targets);
    targets
}

fn collect_elf_import_targets(file: &object::File<'_>, targets: &mut BTreeMap<u64, String>) {
    if !matches!(file.format(), BinaryFormat::Elf) {
        return;
    }

    let dyn_symbols = file
        .dynamic_symbols()
        .filter_map(|symbol| {
            symbol
                .name()
                .ok()
                .map(|name| (symbol.index().0, name.to_owned()))
        })
        .collect::<BTreeMap<usize, String>>();

    // A dynamic relocation only names an import at the address it patches, and
    // for a code reference that address is a GOT slot. Relocations landing
    // elsewhere (`.data.rel.ro` function-pointer tables and the like) are data
    // that happens to hold the address, not a call site, so treating them as
    // reference targets attributed unrelated code to the symbol.
    let got_ranges = file
        .sections()
        .filter_map(|section| {
            matches!(section.name().ok()?, ".got" | ".got.plt" | ".plt.got").then(|| {
                (
                    section.address(),
                    section.address().saturating_add(section.size()),
                )
            })
        })
        .collect::<Vec<_>>();
    let mut got_slots: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(relocations) = file.dynamic_relocations() {
        for (address, relocation) in relocations {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Some(symbol) = dyn_symbols.get(&index.0).cloned() else {
                continue;
            };
            if !got_ranges
                .iter()
                .any(|(start, end)| address >= *start && address < *end)
            {
                continue;
            }
            got_slots.insert(address, symbol);
        }
    }

    targets.extend(
        got_slots
            .iter()
            .map(|(address, symbol)| (*address, symbol.clone())),
    );
    collect_elf_plt_targets(file, &got_slots, targets);
}

/// Map each PLT stub address to the import it forwards to, so a `call foo@plt`
/// attributes to `foo`.
///
/// The stub is decoded, not counted: every entry indirects through its own GOT
/// slot, and that slot's dynamic relocation already names the symbol. Deriving
/// the mapping positionally instead — Nth stub gets the Nth jump slot — holds
/// only if the relocation list and the stub table correspond one to one, and they
/// routinely do not: `.got` GLOB_DAT entries for address-taken imports have no
/// stub at all, and glibc's ifuncs add IRELATIVE relocations that carry no
/// symbol. Each such entry shifts the rest of the table, so a single one
/// misattributes every call after it to the wrong import.
fn collect_elf_plt_targets(
    file: &object::File<'_>,
    got_slots: &BTreeMap<u64, String>,
    targets: &mut BTreeMap<u64, String>,
) {
    // Both architectures use 16-byte stubs. The section's leading header entry
    // (and the aarch64 header's second half) indirects through a reserved
    // `.got.plt` word that carries no symbol relocation, so it finds no match and
    // needs no special case.
    const ENTRY_SIZE: usize = 16;
    if got_slots.is_empty() {
        return;
    }
    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt") {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        for (index, entry) in data.chunks(ENTRY_SIZE).enumerate() {
            let address = section.address() + (index * ENTRY_SIZE) as u64;
            let Some(slot) = decode_plt_stub_slot(file.architecture(), entry, address) else {
                continue;
            };
            let Some(symbol) = got_slots.get(&slot) else {
                continue;
            };
            targets.insert(address, symbol.clone());
        }
    }
}

/// The GOT slot a single PLT stub jumps through, or `None` when the entry is not
/// a recognizable stub for this architecture.
fn decode_plt_stub_slot(
    architecture: Architecture,
    entry: &[u8],
    entry_address: u64,
) -> Option<u64> {
    match architecture {
        // `jmp *disp32(%rip)`, at whatever offset the endbr64/bnd prefixes of the
        // entry's flavor leave it.
        Architecture::X86_64 => (0..entry.len().saturating_sub(5)).find_map(|offset| {
            (entry[offset] == 0xff && entry[offset + 1] == 0x25).then(|| {
                let displacement =
                    i32::from_le_bytes(entry[offset + 2..offset + 6].try_into().expect("4 bytes"));
                (entry_address + offset as u64 + 6).wrapping_add_signed(i64::from(displacement))
            })
        }),
        // `adrp x16, <page>` followed by `ldr x17, [x16, #<offset>]`.
        Architecture::Aarch64 => {
            let instructions = entry
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("chunk has four bytes")))
                .collect::<Vec<_>>();
            instructions
                .windows(2)
                .enumerate()
                .find_map(|(index, pair)| {
                    let (register, page) =
                        aarch64_adrp_target(pair[0], entry_address + (index * 4) as u64)?;
                    aarch64_ldr_unsigned_target(pair[1], register, page)
                })
        }
        _ => None,
    }
}

fn collect_macho_import_targets(
    file: &object::File<'_>,
    bytes: &[u8],
    targets: &mut BTreeMap<u64, String>,
) {
    match file {
        object::File::MachO32(_) => collect_macho_import_targets_for::<
            object::macho::MachHeader32<object::Endianness>,
        >(bytes, 4, targets),
        object::File::MachO64(_) => collect_macho_import_targets_for::<
            object::macho::MachHeader64<object::Endianness>,
        >(bytes, 8, targets),
        _ => {}
    }
}

fn collect_macho_import_targets_for<Mach>(
    bytes: &[u8],
    pointer_size: u64,
    targets: &mut BTreeMap<u64, String>,
) where
    Mach: object::read::macho::MachHeader,
{
    use object::endian::U32;
    use object::read::ReadRef;
    use object::read::macho::{Nlist, Section, Segment};

    let Ok(header) = Mach::parse(bytes, 0) else {
        return;
    };
    let Ok(endian) = header.endian() else {
        return;
    };
    let Ok(mut commands) = header.load_commands(endian, bytes, 0) else {
        return;
    };

    let mut symtab = None;
    let mut dysymtab = None;
    let mut sections = Vec::new();
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(command)) = command.symtab() {
            symtab = Some(command);
        }
        if let Ok(Some(command)) = command.dysymtab() {
            dysymtab = Some(command);
        }
        if let Ok(Some((segment, section_data))) = Mach::Segment::from_command(command) {
            if let Ok(segment_sections) = segment.sections(endian, section_data) {
                for section in segment_sections {
                    let section_type = section.section_type(endian);
                    if matches!(
                        section_type,
                        object::macho::S_NON_LAZY_SYMBOL_POINTERS
                            | object::macho::S_LAZY_SYMBOL_POINTERS
                            | object::macho::S_SYMBOL_STUBS
                    ) {
                        let entry_size = if section_type == object::macho::S_SYMBOL_STUBS {
                            u64::from(section.reserved2(endian)).max(1)
                        } else {
                            pointer_size
                        };
                        sections.push((
                            section.addr(endian).into(),
                            section.size(endian).into(),
                            section.reserved1(endian),
                            entry_size,
                        ));
                    }
                }
            }
        }
    }

    let (Some(symtab), Some(dysymtab)) = (symtab, dysymtab) else {
        return;
    };
    let Ok(symbols) = symtab.symbols::<Mach, _>(endian, bytes) else {
        return;
    };
    let indirect_offset = u64::from(dysymtab.indirectsymoff.get(endian));
    let indirect_count = dysymtab.nindirectsyms.get(endian) as usize;
    let Ok(indirect) = bytes.read_slice_at::<U32<Mach::Endian>>(indirect_offset, indirect_count)
    else {
        return;
    };

    for (address, size, first_indirect, entry_size) in sections {
        if entry_size == 0 {
            continue;
        }
        let count = size / entry_size;
        for index in 0..count {
            let indirect_index = first_indirect as usize + index as usize;
            let Some(symbol_index) = indirect.get(indirect_index) else {
                continue;
            };
            let symbol_index = symbol_index.get(endian);
            if symbol_index & object::macho::INDIRECT_SYMBOL_LOCAL != 0
                || symbol_index & object::macho::INDIRECT_SYMBOL_ABS != 0
            {
                continue;
            }
            let Ok(symbol) = symbols.symbol(SymbolIndex(symbol_index as usize)) else {
                continue;
            };
            let Ok(name) = symbol.name(endian, symbols.strings()) else {
                continue;
            };
            targets.insert(address + index * entry_size, bytes_to_string(name));
        }
    }
}

fn collect_import_xref_provenance(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
    targets: &BTreeMap<u64, String>,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        let section_name = section.name().ok();
        match file.architecture() {
            Architecture::Aarch64 => scan_aarch64_import_xrefs(
                data,
                section.address(),
                section_name,
                targets,
                provenance,
                origins,
            ),
            Architecture::X86_64 => scan_x86_64_import_xrefs(
                data,
                section.address(),
                section_name,
                targets,
                provenance,
                origins,
            ),
            _ => {}
        }
    }
}

fn scan_aarch64_import_xrefs(
    data: &[u8],
    section_address: u64,
    section_name: Option<&str>,
    targets: &BTreeMap<u64, String>,
    provenance: &NativeProvenanceIndex,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    let instructions = data
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("chunk has four bytes")))
        .collect::<Vec<_>>();
    for (index, instruction) in instructions.iter().copied().enumerate() {
        let pc = section_address + index as u64 * 4;
        if let Some(target) = aarch64_branch_target(instruction, pc) {
            if let Some(symbol) = targets.get(&target) {
                insert_origin(origins, symbol, provenance.for_address(pc, section_name));
            }
        }
        let Some((register, page)) = aarch64_adrp_target(instruction, pc) else {
            continue;
        };
        let Some(next) = instructions.get(index + 1).copied() else {
            continue;
        };
        if let Some(target) = aarch64_ldr_unsigned_target(next, register, page) {
            if let Some(symbol) = targets.get(&target) {
                insert_origin(origins, symbol, provenance.for_address(pc, section_name));
            }
        }
    }
}

fn aarch64_branch_target(instruction: u32, pc: u64) -> Option<u64> {
    if instruction & 0x7c00_0000 != 0x1400_0000 {
        return None;
    }
    let offset = sign_extend((instruction & 0x03ff_ffff) as u64, 26) << 2;
    Some(pc.wrapping_add_signed(offset))
}

fn aarch64_adrp_target(instruction: u32, pc: u64) -> Option<(u32, u64)> {
    if instruction & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo = ((instruction >> 29) & 0x3) as u64;
    let immhi = ((instruction >> 5) & 0x7ffff) as u64;
    let imm = sign_extend((immhi << 2) | immlo, 21) << 12;
    let page = (pc & !0xfff).wrapping_add_signed(imm);
    Some((instruction & 0x1f, page))
}

fn aarch64_ldr_unsigned_target(instruction: u32, base_register: u32, page: u64) -> Option<u64> {
    if instruction & 0xffc0_0000 != 0xf940_0000 {
        return None;
    }
    let rn = (instruction >> 5) & 0x1f;
    if rn != base_register {
        return None;
    }
    let imm = u64::from((instruction >> 10) & 0x0fff) * 8;
    Some(page + imm)
}

fn scan_x86_64_import_xrefs(
    data: &[u8],
    section_address: u64,
    section_name: Option<&str>,
    targets: &BTreeMap<u64, String>,
    provenance: &NativeProvenanceIndex,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    let mut offset = 0usize;
    while offset < data.len() {
        // Undecodable bytes end the walk. That costs attribution for the rest of
        // the section, never a refusal: the forbidden-instruction scan runs the
        // same decoder over the same bytes and reports the undecodable site as a
        // finding in its own right, so the audit still fails closed there.
        let Some((len, reference)) = x86_scan::decode_reference(&data[offset..]) else {
            break;
        };
        if let Some(displacement) = reference {
            let target = (section_address + (offset + len) as u64)
                .wrapping_add_signed(i64::from(displacement));
            if let Some(symbol) = targets.get(&target) {
                insert_origin(
                    origins,
                    symbol,
                    provenance.for_address(section_address + offset as u64, section_name),
                );
            }
        }
        offset += len;
    }
}

fn insert_origin(
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
    symbol: &str,
    provenance: NativeProvenance,
) {
    origins
        .entry(symbol.to_string())
        .or_default()
        .insert(provenance);
}

fn sign_extend(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn scan_forbidden_instructions(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
) -> Result<Vec<NativeEscape>, TargetError> {
    // Fail closed on any architecture whose ISA this containment scan cannot
    // decode. A `_ => {}` default arm on the per-section match below silently
    // PASSED unsupported-arch binaries — every instruction unexamined — which is
    // exactly the vacuous-gate failure mode the default-deny doctrine forbids: a
    // forbidden `syscall`/`rdtsc`/`mrs` in a riscv64/s390x/... guest would sail
    // through with zero scanning. Refuse the whole scan up front (before touching
    // sections, so even a text-less binary of an undecodable arch is refused),
    // and keep the section-level match exhaustive so adding a new supported arch
    // forces an explicit decoder here rather than defaulting to a silent pass.
    let architecture = file.architecture();
    match architecture {
        Architecture::Aarch64 | Architecture::X86_64 => {}
        _ => return Err(TargetError::UnsupportedNativeArchitecture(architecture)),
    }
    let mut escapes = Vec::new();
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let data = section.data().map_err(TargetError::NativeParse)?;
        let name = section.name().unwrap_or("<text>");
        match architecture {
            Architecture::Aarch64 => {
                for (index, instruction) in data.chunks_exact(4).enumerate() {
                    let instruction =
                        u32::from_le_bytes(instruction.try_into().expect("chunk has four bytes"));
                    if let Some((category, mnemonic)) = aarch64_instruction_category(instruction) {
                        let offset = index * 4;
                        escapes.push(
                            NativeEscape::new(
                                format!("instruction@{name}+0x{offset:x}"),
                                category,
                                vec![
                                    provenance
                                        .for_address(section.address() + offset as u64, Some(name)),
                                ],
                            )
                            .with_mnemonic(mnemonic),
                        );
                    }
                }
            }
            Architecture::X86_64 => {
                x86_scan::scan(data, name, section.address(), provenance, &mut escapes);
                scan_vsyscall_references(data, name, section.address(), provenance, &mut escapes);
            }
            // Unreachable: the guard above refuses every other architecture. Kept
            // explicit (never a silent `_ => {}`) so a newly-supported arch must be
            // wired into both the guard and a real decoder here.
            _ => unreachable!("unsupported architectures are refused before the section scan"),
        }
    }
    Ok(escapes)
}

/// Refuse a binary whose text materializes an address inside the x86-64 legacy
/// vsyscall page (`0xffffffffff600000..+0x1000`) as a 64-bit immediate. That
/// page's three entries (`gettimeofday`/`time`/`getcpu`) are KERNEL-EMULATED at
/// a fixed address with NO `syscall` instruction — invisible to both the
/// instruction scan and syscall-user-dispatch — so a caller that reads the wall
/// clock or a real CPU id through it escapes determinism entirely. Unlike an
/// auxv key (a bare integer, undetectable), the full 64-bit page address is a
/// reliable immediate signal: the fixed 6 high bytes `60 ff ff ff ff ff` (LE)
/// plus the top nibble of the low-12-bit page offset being zero is a ~2^-52
/// per-offset false-positive, effectively never a coincidence. A `vsyscall`
/// finding is NOT `direct-syscall`, so it is never SUD-downgradable — it always
/// refuses (see [`native_escape_is_sud_manageable`]). SUD-DESIGN.md §6.3.
fn scan_vsyscall_references(
    data: &[u8],
    name: &str,
    section_address: u64,
    provenance: &NativeProvenanceIndex,
    escapes: &mut Vec<NativeEscape>,
) {
    // Little-endian encoding of any address in [0xffffffffff600000, +0x1000):
    //   b[7..2] == [0xff,0xff,0xff,0xff,0xff,0x60]  (bytes 2..8)
    //   b[1] high nibble == 0                       (page offset < 0x1000)
    // b[0] is unconstrained (the low byte of the offset).
    if data.len() < 8 {
        return;
    }
    for offset in 0..=data.len() - 8 {
        let w = &data[offset..offset + 8];
        if w[2] == 0x60
            && w[3] == 0xff
            && w[4] == 0xff
            && w[5] == 0xff
            && w[6] == 0xff
            && w[7] == 0xff
            && (w[1] & 0xf0) == 0
        {
            escapes.push(NativeEscape::new(
                format!("immediate@{name}+0x{offset:x}"),
                "vsyscall",
                vec![provenance.for_address(section_address + offset as u64, Some(name))],
            ));
        }
    }
}

/// The forbidden aarch64 opcodes as `(category, mnemonic)`: `svc #0` (a raw
/// supervisor call) and `mrs Xt, CNTVCT_EL0` (the virtual system counter — the
/// arm64 analogue of `rdtsc`, and unlike `rdtsc` NOT trappable, so it carries a
/// mnemonic only for the message, never for a downgrade; see
/// [`native_escape_is_tsc_manageable`]).
fn aarch64_instruction_category(instruction: u32) -> Option<(&'static str, &'static str)> {
    if instruction & 0xffe0_001f == 0xd400_0001 {
        Some(("direct-syscall", "svc"))
    } else if instruction & !0x1f == 0xd53b_e040 {
        Some(("cpu-nondeterminism", "cntvct"))
    } else {
        None
    }
}

/// x86-64 forbidden-instruction scan, instruction-boundary-aware.
///
/// The aarch64 ISA is fixed-width, so its scan decodes aligned 4-byte words and
/// cannot desync. x86-64 is variable-length: a byte-sliding scan that tested
/// every offset matched the forbidden opcode bytes (`0f 05` syscall, `0f 31`
/// rdtsc, `0f c7 /6` rdrand) *inside* longer instructions' ModRM/SIB/
/// displacement/immediate bytes and flooded the audit with false positives — an
/// ordinary `mov`/`lea`/`movups` whose operand encoding happens to contain those
/// bytes. This module walks real instruction boundaries with a length decoder
/// and only tests the opcode at a genuine boundary, matching the aarch64 scan's
/// precision.
///
/// Soundness (this is a containment gate, so a *false negative* — a real
/// `syscall` slipping past — is the dangerous direction): the decoder fails
/// CLOSED. Any byte sequence it cannot confidently measure — an unmapped/invalid
/// opcode, a truncated tail, or an EVEX (AVX-512) prefix — yields an
/// `undecodable-instruction` finding naming the offset and stops the walk, so the
/// binary is refused rather than silently scanned past a length guess. The legacy
/// three-byte maps (`0f 38`/`0f 3a`) *are* length-decoded: default codegen emits
/// them (the `sha2` crate's x86 backend uses `pshufb`/`palignr`/`pblendw` and the
/// SHA extensions `sha256rnds2`/`sha256msg1`/`sha256msg2`), and — like VEX below —
/// none of their opcodes are forbidden (`syscall`/`rdtsc`/`rdrand`/`rdseed` live
/// only in the legacy two-byte `0f` map), so measuring them cannot hide a
/// forbidden instruction. VEX (AVX/AVX2, both the two-byte `c5` and three-byte
/// `c4` forms) is length-decoded for the same reason — default codegen emits it
/// (`vmovdqa`/`vzeroupper`/...) and its opcodes are never forbidden, so it is
/// measured only to reach the next real boundary. Because
/// every real instruction advances the cursor to its true successor, a forbidden
/// opcode embedded in another instruction's operand is never at a tested
/// boundary. The length decoder is proven against `objdump -d` boundaries over
/// real probe binaries (see `x86_decoder_matches_objdump_corpus`).
mod x86_scan {
    /// Immediate-operand width classes. Widths that depend on the effective
    /// operand/address size are resolved from the `0x66`/`0x67`/REX.W prefixes.
    #[derive(Clone, Copy)]
    enum Imm {
        None,
        /// Exactly N bytes (rel8/rel32 fold in here — near branches are a fixed
        /// width in 64-bit mode; `enter`'s `iw,ib` is a single 3-byte immediate).
        Fixed(u8),
        /// Operand-size immediate: 2 bytes with a `0x66` prefix, else 4.
        Z,
        /// 8 bytes with REX.W, else `Z` (the `mov r64, imm64` family).
        V,
        /// Address-size memory offset: 4 bytes with `0x67`, else 8.
        Moffs,
        /// `f6 /r`: an imm8 only when ModRM.reg selects TEST (0 or 1).
        Group3Byte,
        /// `f7 /r`: an immZ only when ModRM.reg selects TEST (0 or 1).
        Group3Z,
    }

    /// A forbidden opcode as `(escape category, decoded mnemonic)`. The mnemonic
    /// rides along to the finding so the audit can tell `rdtsc`/`rdtscp` (trap-
    /// manageable on x86-64 Linux) from `rdrand`/`rdseed` (never manageable),
    /// which share the `cpu-nondeterminism` category.
    type Forbidden = (&'static str, &'static str);

    struct OpAttr {
        modrm: bool,
        imm: Imm,
        /// A forbidden opcode fixed by the opcode bytes alone (syscall, rdtsc).
        cat: Option<Forbidden>,
        /// `0f c7` (group 9): rdrand (ModRM.reg 6) / rdseed (ModRM.reg 7) vs
        /// cmpxchg8b is a reg decision resolved after the ModRM byte is read.
        group9: bool,
        /// `0f 01` (group 7): rdtscp is `mod=3, reg=7, rm=1` — the rest of the
        /// group (sgdt/sidt/lgdt/invlpg/swapgs/…) is not forbidden, so this too
        /// is a decision resolved after the ModRM byte is read.
        group7: bool,
    }

    enum Step {
        Insn { len: usize, cat: Option<Forbidden> },
        Undecodable,
    }

    /// Walk `data` (a `.text` section) instruction by instruction, pushing a
    /// finding for each forbidden opcode at a real boundary and one
    /// `undecodable-instruction` finding (then stopping) if the decoder cannot
    /// measure an instruction.
    pub(super) fn scan(
        data: &[u8],
        name: &str,
        section_address: u64,
        provenance: &super::NativeProvenanceIndex,
        escapes: &mut Vec<super::NativeEscape>,
    ) {
        let mut offset = 0usize;
        while offset < data.len() {
            match decode_one(&data[offset..]) {
                Step::Insn { len, cat } => {
                    if let Some((category, mnemonic)) = cat {
                        escapes.push(
                            super::NativeEscape::new(
                                format!("instruction@{name}+0x{offset:x}"),
                                category,
                                vec![
                                    provenance
                                        .for_address(section_address + offset as u64, Some(name)),
                                ],
                            )
                            .with_mnemonic(mnemonic),
                        );
                    }
                    // Every instruction consumes at least its opcode byte, so
                    // `len >= 1`; the guard only defends the loop invariant.
                    if len == 0 {
                        break;
                    }
                    offset += len;
                }
                Step::Undecodable => {
                    escapes.push(super::NativeEscape::new(
                        format!("instruction@{name}+0x{offset:x}"),
                        "undecodable-instruction",
                        vec![provenance.for_address(section_address + offset as u64, Some(name))],
                    ));
                    break;
                }
            }
        }
    }

    /// Decode the instruction at `b[0]` into its length and, when it references a
    /// fixed address, the displacement encoding that reference. Direct near
    /// branches (`call`/`jmp rel32`) and RIP-relative memory operands share one
    /// rule — the target is the address of the *next* instruction plus the
    /// displacement — so both come back through the same value.
    ///
    /// References are only read at real instruction boundaries. Sliding the same
    /// byte patterns over every offset in `.text` instead reads four displacement
    /// bytes out of the middle of unrelated instructions, and any of those that
    /// happens to land on a GOT slot attributes an import to a function that
    /// never referenced it.
    pub(super) fn decode_reference(b: &[u8]) -> Option<(usize, Option<i32>)> {
        let len = match decode_one(b) {
            Step::Insn { len, .. } if len > 0 => len,
            _ => return None,
        };
        let insn = b.get(..len)?;

        let mut p = 0usize;
        while matches!(
            insn.get(p).copied(),
            Some(0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65)
        ) {
            p += 1;
        }
        if matches!(insn.get(p).copied(), Some(0x40..=0x4F)) {
            p += 1;
        }

        let displacement = |at: usize| -> Option<i32> {
            insn.get(at..at + 4)
                .map(|bytes| i32::from_le_bytes(bytes.try_into().expect("four bytes")))
        };
        // A ModRM of mod=00, rm=101 is the RIP-relative form, and rm=101 takes no
        // SIB byte, so its disp32 follows the ModRM directly.
        let rip_relative = |modrm: u8| modrm & 0xC7 == 0x05;
        let reference = match insn.get(p).copied() {
            Some(0xE8 | 0xE9) => displacement(p + 1),
            // `call`/`jmp` through a RIP-relative slot: ModRM.reg 2 and 4.
            Some(0xFF) => match insn.get(p + 1).copied() {
                Some(modrm) if rip_relative(modrm) && matches!((modrm >> 3) & 7, 2 | 4) => {
                    displacement(p + 2)
                }
                _ => None,
            },
            // `mov reg, [rip+disp]` / `lea reg, [rip+disp]`: the address-taken form.
            Some(0x8B | 0x8D) => match insn.get(p + 1).copied() {
                Some(modrm) if rip_relative(modrm) => displacement(p + 2),
                _ => None,
            },
            _ => None,
        };
        Some((len, reference))
    }

    /// Decode the length of the single instruction at `b[0]`, and whether its
    /// opcode is forbidden. Returns `Undecodable` for anything the length rules
    /// below do not cover (fail closed).
    fn decode_one(b: &[u8]) -> Step {
        let mut p = 0usize;
        let mut o66 = false;
        let mut a67 = false;
        let mut rexw = false;
        // Legacy prefixes, any order. Only `0x66`/`0x67` change a length (via the
        // effective operand/address size); lock/rep/segment do not.
        loop {
            match b.get(p) {
                Some(0x66) => o66 = true,
                Some(0x67) => a67 = true,
                Some(0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65) => {}
                _ => break,
            }
            p += 1;
            if p > 14 {
                return Step::Undecodable; // absurd prefix run
            }
        }
        // REX must immediately precede the opcode in 64-bit mode.
        if let Some(&r) = b.get(p) {
            if (0x40..=0x4F).contains(&r) {
                rexw = r & 0x08 != 0;
                p += 1;
            }
        }
        let op = match b.get(p) {
            Some(&x) => x,
            None => return Step::Undecodable,
        };
        p += 1;
        let attr = if op == 0x0F {
            let op2 = match b.get(p) {
                Some(&x) => x,
                None => return Step::Undecodable,
            };
            p += 1;
            if op2 == 0x38 || op2 == 0x3A {
                // Legacy three-byte opcode maps (SSSE3/SSE4.1/SSE4.2/SHA-NI): the
                // third byte is the real opcode, always followed by a ModRM.
                // Default codegen *does* emit these — e.g. the `sha2` crate's x86
                // backend uses `pshufb`/`palignr`/`pblendw`/`pinsrd` and the SHA
                // extensions `sha256rnds2`/`sha256msg1`/`sha256msg2` (`0f 38 cb/cc/
                // cd`) — so they must be length-decoded, not declined. No opcode in
                // either map is forbidden: `syscall`/`rdtsc`/`rdrand`/`rdseed` live
                // only in the legacy `0f` (two-byte) map, so measuring these can
                // never hide a forbidden instruction. Length rules mirror the VEX
                // `0f 38`/`0f 3a` maps decoded below: `0f 38` ops carry no
                // immediate, `0f 3a` ops carry an imm8.
                if b.get(p).is_none() {
                    return Step::Undecodable; // truncated: no third opcode byte
                }
                p += 1; // consume the third opcode byte
                OpAttr {
                    modrm: true,
                    imm: if op2 == 0x3A {
                        Imm::Fixed(1)
                    } else {
                        Imm::None
                    },
                    cat: Option::None,
                    group9: false,
                    group7: false,
                }
            } else {
                match two_byte(op2) {
                    Some(a) => a,
                    None => return Step::Undecodable,
                }
            }
        } else if op == 0xC5 {
            // Two-byte VEX: one prefix byte (`R.vvvv.L.pp`), then an opcode in the
            // implied `0f` map.
            if b.get(p).is_none() {
                return Step::Undecodable;
            }
            p += 1;
            let opc = match b.get(p) {
                Some(&x) => x,
                None => return Step::Undecodable,
            };
            p += 1;
            match vex_body(1, opc) {
                Some((modrm, imm)) => OpAttr {
                    modrm,
                    imm,
                    cat: Option::None,
                    group9: false,
                    group7: false,
                },
                None => return Step::Undecodable,
            }
        } else if op == 0xC4 {
            // Three-byte VEX: two prefix bytes; the low 5 bits of the first pick
            // the implied opcode map (1=`0f`, 2=`0f 38`, 3=`0f 3a`).
            let b1 = match b.get(p) {
                Some(&x) => x,
                None => return Step::Undecodable,
            };
            p += 1;
            if b.get(p).is_none() {
                return Step::Undecodable;
            }
            p += 1;
            let opc = match b.get(p) {
                Some(&x) => x,
                None => return Step::Undecodable,
            };
            p += 1;
            match vex_body(b1 & 0x1F, opc) {
                Some((modrm, imm)) => OpAttr {
                    modrm,
                    imm,
                    cat: Option::None,
                    group9: false,
                    group7: false,
                },
                None => return Step::Undecodable,
            }
        } else if op == 0x62 {
            return Step::Undecodable; // EVEX (AVX-512): non-default, fail closed
        } else {
            match one_byte(op) {
                Some(a) => a,
                None => return Step::Undecodable,
            }
        };
        let mut cat = attr.cat;
        let mut imm = attr.imm;
        if attr.modrm {
            let m = match b.get(p) {
                Some(&x) => x,
                None => return Step::Undecodable,
            };
            p += 1;
            let md = m >> 6;
            let reg = (m >> 3) & 7;
            let rm = m & 7;
            // group 9 (`0f c7`): ModRM.reg 6 is RDRAND, reg 7 is RDSEED. Both are
            // hardware entropy reads — `cpu-nondeterminism` with NO manageability
            // (no mechanism traps them; they stay refusals, unlike the timestamp
            // counter). Neither is guarded on `mod == 3` (the true register-form
            // encoding), keeping the historical reg==6 test's shape: the memory
            // forms of this group are privileged VMX instructions that fault in
            // user mode, so the looser test costs nothing and cannot go blind.
            if attr.group9 {
                if reg == 6 {
                    cat = Some(("cpu-nondeterminism", "rdrand"));
                } else if reg == 7 {
                    cat = Some(("cpu-nondeterminism", "rdseed"));
                }
            }
            // group 7 (`0f 01`): `mod=3, reg=7, rm=1` is RDTSCP — the timestamp
            // counter plus IA32_TSC_AUX. `rm=0` at the same reg is SWAPGS
            // (privileged) and every other encoding is a descriptor-table op, so
            // the exact triple is required.
            if attr.group7 && md == 3 && reg == 7 && rm == 1 {
                cat = Some(("cpu-nondeterminism", "rdtscp"));
            }
            // group 3 (`f6`/`f7`): only TEST (reg 0 or 1) carries an immediate.
            imm = match imm {
                Imm::Group3Byte if reg <= 1 => Imm::Fixed(1),
                Imm::Group3Z if reg <= 1 => Imm::Z,
                Imm::Group3Byte | Imm::Group3Z => Imm::None,
                other => other,
            };
            // ModRM memory forms pull a SIB byte and/or a displacement.
            if md != 3 {
                if rm == 4 {
                    let sib = match b.get(p) {
                        Some(&x) => x,
                        None => return Step::Undecodable,
                    };
                    p += 1;
                    if md == 0 && (sib & 7) == 5 {
                        p += 4; // SIB with no base register: disp32
                    } else {
                        p += disp_len(md);
                    }
                } else if md == 0 && rm == 5 {
                    p += 4; // RIP-relative disp32
                } else {
                    p += disp_len(md);
                }
            }
        }
        p += imm_len(imm, o66, rexw, a67);
        if p > b.len() {
            return Step::Undecodable; // instruction runs past the section end
        }
        Step::Insn { len: p, cat }
    }

    fn disp_len(md: u8) -> usize {
        match md {
            1 => 1,
            2 => 4,
            _ => 0,
        }
    }

    fn imm_len(imm: Imm, o66: bool, rexw: bool, a67: bool) -> usize {
        match imm {
            Imm::None => 0,
            Imm::Fixed(n) => n as usize,
            Imm::Z => {
                if o66 {
                    2
                } else {
                    4
                }
            }
            Imm::V => {
                if rexw {
                    8
                } else if o66 {
                    2
                } else {
                    4
                }
            }
            Imm::Moffs => {
                if a67 {
                    4
                } else {
                    8
                }
            }
            // Resolved to a concrete width during ModRM processing; never here.
            Imm::Group3Byte | Imm::Group3Z => 0,
        }
    }

    fn attr(modrm: bool, imm: Imm) -> Option<OpAttr> {
        Some(OpAttr {
            modrm,
            imm,
            cat: None,
            group9: false,
            group7: false,
        })
    }

    /// One-byte opcode attributes. `None` = fail closed (opcodes invalid in
    /// 64-bit mode, which valid code never emits). Prefix bytes and `0x0f` are
    /// consumed by the caller and never reach here.
    fn one_byte(op: u8) -> Option<OpAttr> {
        use Imm::*;
        match op {
            // ALU r/m forms (add/or/adc/sbb/and/sub/xor/cmp), the `xx0..=xx3` rows.
            0x00 | 0x01 | 0x02 | 0x03 | 0x08 | 0x09 | 0x0A | 0x0B | 0x10 | 0x11 | 0x12 | 0x13
            | 0x18 | 0x19 | 0x1A | 0x1B | 0x20 | 0x21 | 0x22 | 0x23 | 0x28 | 0x29 | 0x2A | 0x2B
            | 0x30 | 0x31 | 0x32 | 0x33 | 0x38 | 0x39 | 0x3A | 0x3B => attr(true, None),
            // ALU AL, imm8 / eAX, immZ.
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => attr(false, Fixed(1)),
            0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => attr(false, Z),
            // Invalid in 64-bit mode (push/pop seg, bcd math, pusha/popa, bound,
            // callf/jmpf, aam/aad/salc, into): fail closed.
            0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F | 0x27 | 0x2F | 0x37 | 0x3F | 0x60
            | 0x61 | 0x82 | 0x9A | 0xCE | 0xD4 | 0xD5 | 0xD6 | 0xEA => Option::None,
            0x50..=0x5F => attr(false, None),     // push/pop r64
            0x63 => attr(true, None),             // movsxd
            0x68 => attr(false, Z),               // push immZ
            0x69 => attr(true, Z),                // imul r, r/m, immZ
            0x6A => attr(false, Fixed(1)),        // push imm8
            0x6B => attr(true, Fixed(1)),         // imul r, r/m, imm8
            0x6C..=0x6F => attr(false, None),     // ins/outs
            0x70..=0x7F => attr(false, Fixed(1)), // Jcc rel8
            0x80 => attr(true, Fixed(1)),         // grp1 Eb, Ib
            0x81 => attr(true, Z),                // grp1 Ev, Iz
            0x83 => attr(true, Fixed(1)),         // grp1 Ev, Ib (sign-extended)
            0x84..=0x87 => attr(true, None),      // test / xchg
            0x88..=0x8E => attr(true, None),      // mov / lea
            0x8F => attr(true, None),             // grp1a pop Ev
            0x90..=0x97 => attr(false, None),     // xchg eAX (0x90 nop)
            0x98 | 0x99 | 0x9B | 0x9C | 0x9D | 0x9E | 0x9F => attr(false, None), // cbw..lahf
            0xA0..=0xA3 => attr(false, Moffs),    // mov AL/eAX, moffs
            0xA4..=0xA7 => attr(false, None),     // movs / cmps
            0xA8 => attr(false, Fixed(1)),        // test AL, imm8
            0xA9 => attr(false, Z),               // test eAX, immZ
            0xAA..=0xAF => attr(false, None),     // stos / lods / scas
            0xB0..=0xB7 => attr(false, Fixed(1)), // mov r8, imm8
            0xB8..=0xBF => attr(false, V),        // mov r, immV
            0xC0 | 0xC1 => attr(true, Fixed(1)),  // grp2 shift Eb/Ev, imm8
            0xC2 => attr(false, Fixed(2)),        // ret imm16
            0xC3 => attr(false, None),            // ret
            0xC6 => attr(true, Fixed(1)),         // grp11 mov Eb, Ib
            0xC7 => attr(true, Z),                // grp11 mov Ev, Iz
            0xC8 => attr(false, Fixed(3)),        // enter iw, ib
            0xC9 => attr(false, None),            // leave
            0xCA => attr(false, Fixed(2)),        // retf imm16
            0xCB | 0xCC => attr(false, None),     // retf / int3
            0xCD => attr(false, Fixed(1)),        // int imm8
            0xCF => attr(false, None),            // iret
            0xD0..=0xD3 => attr(true, None),      // grp2 shift by 1 / CL
            0xD7 => attr(false, None),            // xlat
            0xD8..=0xDF => attr(true, None),      // x87 (always ModRM, no immediate)
            0xE0..=0xE3 => attr(false, Fixed(1)), // loop / jcxz rel8
            0xE4..=0xE7 => attr(false, Fixed(1)), // in/out imm8
            0xE8 | 0xE9 => attr(false, Fixed(4)), // call / jmp rel32 (fixed in 64-bit)
            0xEB => attr(false, Fixed(1)),        // jmp rel8
            0xEC..=0xEF => attr(false, None),     // in/out DX
            0xF1 | 0xF4 | 0xF5 => attr(false, None), // int1 / hlt / cmc
            0xF6 => attr(true, Group3Byte),       // grp3 Eb
            0xF7 => attr(true, Group3Z),          // grp3 Ev
            0xF8..=0xFD => attr(false, None),     // clc..std
            0xFE => attr(true, None),             // grp4 inc/dec Eb
            0xFF => attr(true, None),             // grp5
            // Prefixes (consumed by the caller) and any hole: fail closed.
            _ => Option::None,
        }
    }

    /// Two-byte (`0f xx`) opcode attributes. `None` = fail closed. The forbidden
    /// opcodes are `0f 05` (syscall), `0f 31` (rdtsc), `0f 01 f9` (rdtscp,
    /// resolved from ModRM by the caller) and `0f c7 /6`, `/7` (rdrand, rdseed,
    /// likewise resolved from ModRM.reg).
    fn two_byte(op2: u8) -> Option<OpAttr> {
        use Imm::*;
        match op2 {
            0x05 => Some(OpAttr {
                modrm: false,
                imm: None,
                cat: Some(("direct-syscall", "syscall")),
                group9: false,
                group7: false,
            }),
            0x31 => Some(OpAttr {
                modrm: false,
                imm: None,
                cat: Some(("cpu-nondeterminism", "rdtsc")),
                group9: false,
                group7: false,
            }),
            // Group 7 (`0f 01`): rdtscp is the `mod=3, reg=7, rm=1` form. The
            // group's length rules are unchanged (ModRM, no immediate) — it was
            // already measured correctly by the `0x00..=0x03` arm below; the
            // group7 flag only adds the classification the old table lacked, so
            // an `rdtscp` guest is no longer scanned past as an ordinary
            // instruction.
            0x01 => Some(OpAttr {
                modrm: true,
                imm: None,
                cat: Option::None,
                group9: false,
                group7: true,
            }),
            0xC7 => Some(OpAttr {
                modrm: true,
                imm: None,
                cat: Option::None,
                group9: true,
                group7: false,
            }),
            // No ModRM, no immediate (clts/syscall-family/cpuid/push-pop-seg/
            // bswap/rsm/...).
            0x06
            | 0x07
            | 0x08
            | 0x09
            | 0x0B
            | 0x0E
            | 0x30
            | 0x32
            | 0x33
            | 0x34
            | 0x35
            | 0x37
            | 0x77
            | 0xA0
            | 0xA1
            | 0xA2
            | 0xA8
            | 0xA9
            | 0xAA
            | 0xC8..=0xCF => attr(false, None),
            // Jcc rel32 (fixed in 64-bit).
            0x80..=0x8F => attr(false, Fixed(4)),
            // ModRM + imm8 (pshuf/shift-group/shld/shrd/bt-group/cmp*/insert/
            // extract/shuf; `0f 0f` 3DNow carries its opcode in the trailing imm8).
            0x0F | 0x70 | 0x71 | 0x72 | 0x73 | 0xA4 | 0xAC | 0xBA | 0xC2 | 0xC4 | 0xC5 | 0xC6 => {
                attr(true, Fixed(1))
            }
            // ModRM, no immediate (the bulk of the 0F map: SSE2/MMX, cmov, setcc,
            // movzx/movsx, bit ops, xadd, cmpxchg, ...).
            // (`0x01` — group 7, which carries rdtscp — is matched above with the
            // same length rules and an added classification.)
            0x00
            | 0x02
            | 0x03
            | 0x0D
            | 0x10..=0x1F
            | 0x20..=0x23
            | 0x28..=0x2F
            | 0x40..=0x4F
            | 0x50..=0x6F
            | 0x74..=0x76
            | 0x78
            | 0x79
            | 0x7C..=0x7F
            | 0x90..=0x9F
            | 0xA3
            | 0xA5
            | 0xAB
            | 0xAD
            | 0xAE
            | 0xAF
            | 0xB0..=0xB9
            | 0xBB..=0xBF
            | 0xC0
            | 0xC1
            | 0xC3
            | 0xD0..=0xDF
            | 0xE0..=0xEF
            | 0xF0..=0xFF => attr(true, None),
            // Reserved / invalid 0F opcodes, and the three-byte escapes the caller
            // has already peeled off: fail closed.
            _ => Option::None,
        }
    }

    /// VEX instruction body attributes `(modrm, imm)` for the implied opcode
    /// `map` (1 = `0f`, 2 = `0f 38`, 3 = `0f 3a`) and `op`. VEX opcodes are never
    /// forbidden, so no category is returned; this only measures length. Unknown
    /// maps fail closed. The immediate rules follow the map: nearly every VEX
    /// `0f`-map op is `(modrm, no-imm)`, except `vzeroupper`/`vzeroall` (`0f 77`,
    /// no ModRM) and the imm8-bearing shuffle/compare/insert/extract group; `0f
    /// 38` ops carry no immediate; `0f 3a` ops carry an imm8.
    fn vex_body(map: u8, op: u8) -> Option<(bool, Imm)> {
        match map {
            1 => {
                let modrm = op != 0x77; // vzeroupper / vzeroall take no ModRM
                let imm = match op {
                    0x70 | 0x71 | 0x72 | 0x73 | 0xC2 | 0xC4 | 0xC5 | 0xC6 => Imm::Fixed(1),
                    _ => Imm::None,
                };
                Some((modrm, imm))
            }
            2 => Some((true, Imm::None)), // 0f 38: ModRM, no immediate
            3 => Some((true, Imm::Fixed(1))), // 0f 3a: ModRM + imm8
            _ => Option::None,            // reserved VEX map: fail closed
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Decode one instruction, panicking if the decoder fails closed. Returns
        /// `(length, forbidden_category)`, dropping the mnemonic (the mnemonic is
        /// asserted directly by the tests that care).
        fn decode(b: &[u8]) -> (usize, Option<&'static str>) {
            (decode_full(b).0, decode_full(b).1.map(|(cat, _)| cat))
        }

        /// As [`decode`], keeping the `(category, mnemonic)` pair intact.
        fn decode_full(b: &[u8]) -> (usize, Option<Forbidden>) {
            match decode_one(b) {
                Step::Insn { len, cat } => (len, cat),
                Step::Undecodable => panic!("decoder failed closed on {b:02x?}"),
            }
        }

        fn scan_test(data: &[u8], escapes: &mut Vec<super::super::NativeEscape>) {
            let provenance = super::super::NativeProvenanceIndex {
                entries: Vec::new(),
            };
            scan(data, ".text", 0, &provenance, escapes);
        }

        #[test]
        fn measures_representative_instruction_lengths() {
            // (bytes, expected length) across the length-determining features.
            let cases: &[(&[u8], usize)] = &[
                (&[0x90], 1),                                // nop
                (&[0xc3], 1),                                // ret
                (&[0x0f, 0x05], 2),                          // syscall
                (&[0x0f, 0x31], 2),                          // rdtsc
                (&[0x48, 0x89, 0xe5], 3),                    // mov rbp, rsp (REX.W + ModRM reg)
                (&[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0], 8),  // mov rax,[disp32] (SIB, no base)
                (&[0x48, 0x8d, 0x3d, 0, 0, 0, 0], 7),        // lea rdi,[rip+disp32]
                (&[0xe8, 0, 0, 0, 0], 5),                    // call rel32
                (&[0xeb, 0x00], 2),                          // jmp rel8
                (&[0x0f, 0x84, 0, 0, 0, 0], 6),              // je rel32
                (&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], 10), // mov rax, imm64 (REX.W imm)
                (&[0xb8, 1, 2, 3, 4], 5),                    // mov eax, imm32
                (&[0x66, 0xb8, 1, 2], 4),                    // mov ax, imm16 (0x66 shrinks imm)
                (&[0x68, 1, 2, 3, 4], 5),                    // push imm32
                (&[0x83, 0xc0, 0x01], 3),                    // add eax, imm8 (grp1 Ib)
                (&[0x81, 0xc0, 1, 2, 3, 4], 6),              // add eax, imm32 (grp1 Iz)
                (&[0xf6, 0xc0, 0x01], 3),                    // test al, imm8 (grp3 reg 0 → imm8)
                (&[0xf6, 0xd8], 2),                          // neg al (grp3 reg 3 → no imm)
                (&[0xf7, 0xc0, 1, 2, 3, 4], 6),              // test eax, imm32 (grp3 reg 0)
                (&[0xf7, 0xd8], 2),                          // neg eax (grp3 reg 3 → no imm)
                (&[0x0f, 0xc7, 0xf0], 3),                    // rdrand eax (grp9 reg 6)
                (&[0x48, 0x0f, 0xc7, 0x08], 4),              // cmpxchg8b [rax] (grp9 reg 1)
                (&[0xc8, 1, 2, 3], 4),                       // enter iw, ib
                (&[0x0f, 0x1f, 0x44, 0x00, 0x00], 5),        // 5-byte nop (ModRM+SIB+disp8)
            ];
            for (bytes, expected) in cases {
                let (len, _) = decode(bytes);
                assert_eq!(len, *expected, "length for {bytes:02x?}");
            }
        }

        #[test]
        fn flags_real_forbidden_opcodes_at_a_boundary() {
            assert_eq!(decode(&[0x0f, 0x05]).1, Some("direct-syscall"));
            assert_eq!(decode(&[0x0f, 0x31]).1, Some("cpu-nondeterminism"));
            assert_eq!(decode(&[0x0f, 0xc7, 0xf0]).1, Some("cpu-nondeterminism")); // rdrand
            // group 9 reg != 6 (cmpxchg8b) is not forbidden.
            assert_eq!(decode(&[0x48, 0x0f, 0xc7, 0x08]).1, None);
        }

        /// The two counter/entropy reads the opcode table did not classify.
        /// `rdtscp` (`0f 01 f9`) was measured as an ordinary group-7 instruction
        /// and scanned straight past — a guest reading the timestamp counter
        /// through it audited CLEAN, which is the false-negative direction this
        /// containment gate must never take. `rdseed` (`0f c7 /7`) was the same
        /// blind spot one ModRM.reg over from `rdrand`. RED: drop either arm from
        /// the decoder and this test fails with `None`.
        #[test]
        fn classifies_rdtscp_and_rdseed() {
            // rdtscp: mod=3, reg=7, rm=1. Length is unchanged at 3 bytes.
            assert_eq!(
                decode_full(&[0x0f, 0x01, 0xf9]).1,
                Some(("cpu-nondeterminism", "rdtscp"))
            );
            assert_eq!(decode(&[0x0f, 0x01, 0xf9]).0, 3);
            // rdseed eax: `0f c7 /7`, ModRM f8.
            assert_eq!(
                decode_full(&[0x0f, 0xc7, 0xf8]).1,
                Some(("cpu-nondeterminism", "rdseed"))
            );
            // Neighbours in the same groups stay unforbidden: `swapgs`
            // (`0f 01 f8`, reg 7 / rm 0) and the memory forms of group 7
            // (`sgdt [rax]`, reg 0) are not counter reads.
            assert_eq!(decode(&[0x0f, 0x01, 0xf8]).1, None);
            assert_eq!(decode(&[0x0f, 0x01, 0x00]).1, None);
            // And the mnemonic rides onto the finding, since the audit's
            // manageability split reads it rather than the shared category.
            let mut escapes = Vec::new();
            scan_test(
                &[0x0f, 0x31, 0x0f, 0x01, 0xf9, 0x0f, 0xc7, 0xf8],
                &mut escapes,
            );
            let found: Vec<_> = escapes
                .iter()
                .map(|escape| (escape.category, escape.mnemonic))
                .collect();
            assert_eq!(
                found,
                vec![
                    ("cpu-nondeterminism", Some("rdtsc")),
                    ("cpu-nondeterminism", Some("rdtscp")),
                    ("cpu-nondeterminism", Some("rdseed")),
                ]
            );
        }

        #[test]
        fn walks_past_forbidden_bytes_embedded_in_operands() {
            // `mov rax, 0x0f31000f05` — the immediate contains both the `0f 05`
            // (syscall) and `0f 31` (rdtsc) byte pairs, but they are operand data,
            // not instruction boundaries. A boundary-aware scan flags neither; the
            // old byte-slide flagged both.
            let mut escapes = Vec::new();
            let text = [0x48, 0xb8, 0x05, 0x0f, 0x00, 0x31, 0x0f, 0x00, 0x00, 0x00];
            scan_test(&text, &mut escapes);
            assert!(
                escapes.is_empty(),
                "operand-embedded opcode bytes must not be flagged: {escapes:?}"
            );
            // The same forbidden bytes at a real boundary (a `syscall` after a nop)
            // must still be caught.
            let mut escapes = Vec::new();
            scan_test(&[0x90, 0x0f, 0x05], &mut escapes);
            assert_eq!(escapes.len(), 1);
            assert_eq!(escapes[0].category, "direct-syscall");
            assert_eq!(escapes[0].symbol, "instruction@.text+0x1");
        }

        #[test]
        fn fails_closed_on_undecodable_bytes() {
            // An EVEX prefix (0x62) and a reserved 0F opcode (0f 04) are both
            // declined; the scan emits an `undecodable-instruction` finding naming
            // the offset rather than skipping past a length guess.
            for bytes in [&[0x62, 0xf1, 0x7c, 0x48][..], &[0x0f, 0x04][..]] {
                let mut escapes = Vec::new();
                scan_test(bytes, &mut escapes);
                assert_eq!(escapes.len(), 1, "should fail closed on {bytes:02x?}");
                assert_eq!(escapes[0].category, "undecodable-instruction");
                assert_eq!(escapes[0].symbol, "instruction@.text+0x0");
            }
        }

        #[test]
        fn measures_vex_avx_instruction_lengths() {
            // VEX (AVX/AVX2) is the encoding the corpus check surfaced; default
            // codegen emits it, so it must be length-decoded rather than declined.
            let cases: &[(&[u8], usize)] = &[
                (&[0xc5, 0xf8, 0x77], 3), // vzeroupper (2-byte VEX, no ModRM)
                (&[0xc5, 0xfd, 0x6f, 0x44, 0x24, 0x20], 6), // vmovdqa ymm0,[rsp+0x20] (SIB+disp8)
                (&[0xc5, 0xfd, 0xd7, 0xc0], 4), // vpmovmskb eax,ymm0 (reg ModRM)
                (&[0xc5, 0xfc, 0x57, 0xc0], 4), // vxorps ymm0,ymm0,ymm0
                (&[0xc4, 0xe2, 0x7d, 0x00, 0xc1], 5), // 3-byte VEX, 0f38 map, no imm
                (&[0xc4, 0xe3, 0x7d, 0x46, 0xc1, 0x20], 6), // vperm2i128 (0f3a map, imm8)
            ];
            for (bytes, expected) in cases {
                let (len, cat) = decode(bytes);
                assert_eq!(len, *expected, "length for {bytes:02x?}");
                assert_eq!(cat, None, "VEX opcodes are never forbidden: {bytes:02x?}");
            }
        }

        #[test]
        fn decodes_legacy_three_byte_maps() {
            // The exact bytes the `sha2` x86 backend carries (used by guests for
            // an applied-sequence digest). Before the 0f 38/0f 3a
            // maps were length-decoded these all failed closed, refusing the binary
            // at the first `palignr` (`.text+0x42929`). Lengths are objdump-verified.
            let cases: &[(&[u8], usize)] = &[
                (&[0x66, 0x45, 0x0f, 0x3a, 0x0f, 0xec, 0x08], 7), // palignr (0f 3a 0f, imm8)
                (&[0x66, 0x44, 0x0f, 0x3a, 0x0e, 0xe0, 0xf0], 7), // pblendw (0f 3a 0e, imm8)
                (&[0x66, 0x0f, 0x3a, 0x22, 0xe1, 0x00], 6),       // pinsrd  (0f 3a 22, imm8)
                (&[0x66, 0x0f, 0x38, 0x00, 0xfd], 5),             // pshufb  (0f 38 00, no imm)
                (&[0x41, 0x0f, 0x38, 0xcb, 0xdd], 5),             // sha256rnds2 (0f 38 cb)
                (&[0x41, 0x0f, 0x38, 0xcc, 0xfe], 5),             // sha256msg1  (0f 38 cc)
                (&[0x41, 0x0f, 0x38, 0xcd, 0xf0], 5),             // sha256msg2  (0f 38 cd)
            ];
            for (bytes, expected) in cases {
                let (len, cat) = decode(bytes);
                assert_eq!(len, *expected, "length for {bytes:02x?}");
                assert_eq!(
                    cat, None,
                    "three-byte-map opcodes are never forbidden: {bytes:02x?}"
                );
            }
        }

        #[test]
        fn forbidden_opcode_after_three_byte_map_is_still_caught() {
            // Decoding the 0f 38/0f 3a maps must not blunt the forbidden scan: a
            // `syscall` at the real boundary immediately after a `palignr` (the
            // encoding that used to halt the walk) must still be flagged, and the
            // walk must land on it at exactly the right offset (7 = palignr's len).
            let mut escapes = Vec::new();
            let text = [
                0x66, 0x45, 0x0f, 0x3a, 0x0f, 0xec, 0x08, // palignr (7 bytes)
                0x0f, 0x05, // syscall at offset 7
            ];
            scan_test(&text, &mut escapes);
            assert_eq!(escapes.len(), 1, "{escapes:?}");
            assert_eq!(escapes[0].category, "direct-syscall");
            assert_eq!(escapes[0].symbol, "instruction@.text+0x7");
        }

        // Ground-truth corpus check: the length decoder must reproduce objdump's
        // instruction boundaries exactly over a real `.text`, or it could desync
        // (a wrong length silently steps over a real instruction — the same
        // false-negative failure the byte-slide had). Ignored by default because
        // it needs an x86-64 ELF and its `objdump -d -j .text` output; run in the
        // amd64 container over the real std/glibc probe binaries:
        //   PATINA_X86_CORPUS_ELF=/path/guest \
        //   PATINA_X86_CORPUS_OBJDUMP=/path/guest.objdump \
        //   cargo test -p patina-dst-target -- --ignored x86_decoder_matches_objdump
        #[test]
        #[ignore = "requires an x86-64 ELF + objdump corpus; run in the amd64 container"]
        fn x86_decoder_matches_objdump_corpus() {
            use object::{Object, ObjectSection};
            use std::collections::BTreeSet;

            let elf_path = std::env::var("PATINA_X86_CORPUS_ELF")
                .expect("set PATINA_X86_CORPUS_ELF to an x86-64 ELF");
            let objdump_path = std::env::var("PATINA_X86_CORPUS_OBJDUMP")
                .expect("set PATINA_X86_CORPUS_OBJDUMP to its `objdump -d -j .text` output");
            let bytes = std::fs::read(&elf_path).expect("read ELF");
            let file = object::File::parse(&*bytes).expect("parse ELF");
            let text = file
                .sections()
                .find(|s| s.name() == Ok(".text"))
                .expect(".text section");
            let base = text.address();
            let data = text.data().expect(".text data");

            // Golden boundaries: the address at the start of every objdump
            // instruction line (`  <hexaddr>:\t<bytes>\t<mnemonic>`), restricted to
            // this `.text`. Lines like `<addr> <name>:` (labels) and `\t...`
            // (elided zero runs) are not instruction starts and are skipped.
            //
            // GNU objdump wraps an instruction longer than 7 bytes onto a
            // continuation line — `  <hexaddr>:\t<more bytes>` with NO trailing
            // mnemonic — whose address is an interior byte, not a real boundary
            // (e.g. an 8-byte `cmpq [rip+d32],imm8` prints 7 bytes on its address
            // line and the 8th on a `+7:` continuation). Those must be skipped or
            // they inflate the golden set with phantom boundaries the decoder (which
            // treats the whole thing as one instruction) correctly lacks. A real
            // instruction line always has a second tab before the mnemonic; a
            // continuation line has only bytes, so require `rest` to contain a tab.
            let objdump = std::fs::read_to_string(&objdump_path).expect("read objdump");
            let mut golden = BTreeSet::new();
            for line in objdump.lines() {
                let trimmed = line.trim_start();
                if let Some((addr_hex, rest)) = trimmed.split_once(":\t") {
                    let is_instruction_line = rest.contains('\t');
                    if addr_hex.bytes().all(|c| c.is_ascii_hexdigit()) && is_instruction_line {
                        if let Ok(addr) = u64::from_str_radix(addr_hex, 16) {
                            if addr >= base && addr < base + data.len() as u64 {
                                golden.insert(addr);
                            }
                        }
                    }
                }
            }
            assert!(
                golden.len() > 100,
                "objdump corpus looks too small ({} boundaries) — wrong file? \
                 (a real std `.text` has ~10^6; even a tiny probe has hundreds)",
                golden.len()
            );
            let first = *golden.iter().next().unwrap();
            let last = *golden.iter().next_back().unwrap();

            // Walk the decoder and collect its boundaries as absolute addresses.
            let mut decoded = BTreeSet::new();
            let mut offset = 0usize;
            while offset < data.len() {
                let addr = base + offset as u64;
                match decode_one(&data[offset..]) {
                    Step::Insn { len, .. } => {
                        if addr >= first && addr <= last {
                            decoded.insert(addr);
                        }
                        assert!(len > 0);
                        offset += len;
                    }
                    Step::Undecodable => panic!(
                        "decoder failed closed at {addr:#x} (offset {offset:#x}); \
                         the corpus should be fully decodable — bytes {:02x?}",
                        &data[offset..(offset + 8).min(data.len())]
                    ),
                }
            }

            // Over objdump's covered range the two boundary sets must be identical.
            // A decoder boundary objdump lacks means we split one instruction in
            // two; a missing one means we merged/overran two — either is a desync.
            let extra: Vec<_> = decoded.difference(&golden).take(5).collect();
            let missing: Vec<_> = golden.difference(&decoded).take(5).collect();
            assert!(
                extra.is_empty() && missing.is_empty(),
                "boundary mismatch vs objdump: {} extra {:#x?}, {} missing {:#x?}",
                decoded.difference(&golden).count(),
                extra,
                golden.difference(&decoded).count(),
                missing,
            );
            eprintln!(
                "x86 decoder matched objdump on {} instruction boundaries [{:#x}..={:#x}]",
                golden.len(),
                first,
                last
            );
        }
    }
}

/// Reduce a native import to its canonical name so alias forms such as Mach-O
/// underscore prefixes, glibc `__`-prefixed aliases, glibc C-standard generation
/// aliases, and Darwin `$NOCANCEL` variants are audited against the same
/// allowlist entry.
fn normalize_native_symbol(symbol: &str) -> &str {
    let symbol = symbol.trim_start_matches('_');
    let symbol = strip_glibc_alias_generation(symbol);
    symbol.strip_suffix("$NOCANCEL").unwrap_or(symbol)
}

/// Strip glibc's C-standard *generation* prefix (`isoc23_`, `isoc99_`, ...,
/// leading underscores already removed) so the base symbol is what gets
/// classified.
///
/// glibc keeps a separate alias for each function whose signature or semantics
/// changed between C standards, and the *compiler* chooses which one the object
/// references: a C23 build's `sscanf` becomes `__isoc23_sscanf`, a C99 build's
/// `scanf` becomes `__isoc99_scanf`. The name in the import table is therefore a
/// build-configuration artifact of the same libc entry point, and auditing it
/// verbatim refused symbols whose base has been known-safe all along (aws-lc's
/// `__isoc23_sscanf` on glibc).
///
/// This is normalization, not an allowance: the base symbol still goes through
/// the full classification path, so an alias of an effectful entry point
/// (`__isoc99_scanf`) is denied under the base's own class. The prefix must be
/// `isoc` + at least one digit + `_` + a non-empty base, so an ordinary symbol
/// that merely starts with those letters is untouched.
fn strip_glibc_alias_generation(symbol: &str) -> &str {
    let Some(rest) = symbol.strip_prefix("isoc") else {
        return symbol;
    };
    let generation = rest.bytes().take_while(u8::is_ascii_digit).count();
    if generation == 0 {
        return symbol;
    }
    match rest[generation..].strip_prefix('_') {
        Some(base) if !base.is_empty() => base,
        _ => symbol,
    }
}

fn common_native_allowlisted_import(symbol: &str) -> bool {
    // Allocator entry points only mutate the process-local heap. Patina does
    // not virtualize addresses, so these host-deferred calls have no boundary
    // effect except deterministic success/failure for the same allocation load.
    const ALLOCATOR: &[&str] = &[
        "aligned_alloc",
        "calloc",
        "free",
        "malloc",
        "malloc_size",
        "malloc_usable_size",
        "posix_memalign",
        "realloc",
    ];
    // Compiler and libc memory/string intrinsics read or write only caller-owned
    // memory. The *_chk forms add bounds checks before doing the same work.
    const MEMORY_AND_STRING: &[&str] = &[
        "bcmp",
        "bzero",
        "gai_strerror",
        "memchr",
        "memcmp",
        "memcpy",
        "memcpy_chk",
        "memmove",
        "memmove_chk",
        "memrchr",
        "memset",
        "memset_chk",
        "stpcpy",
        "strcasecmp",
        "strcat_chk",
        "strchr",
        "strcmp",
        // Plain and fortified string copies: write only into the caller-owned
        // destination buffer (the fortified `_chk` forms add a compile-time bound),
        // a pure caller-memory operation exactly like `memcpy`, no boundary effect.
        "strcpy",
        "strcpy_chk",
        "strerror_r",
        "strlen",
        "strncasecmp",
        "strncmp",
        "strncpy",
        "strncpy_chk",
        "strnlen",
        "strrchr",
        // Numeric parse of a caller-owned NUL-terminated string into an integer,
        // optionally writing an end pointer back into caller memory. Pure
        // caller-memory read/compute with no boundary effect, same family as the
        // `strlen`/`strcmp` intrinsics above. Both Mach-O `_strtol` and ELF
        // `strtol` normalize onto this common entry. (`strtoul` and the other
        // radix/float parsers are deliberately NOT here — this is an exact list,
        // never a prefix, so an unlisted parser stays denied as `unknown-import`.)
        "strtol",
    ];
    // Compiler-rt/libgcc 128-bit integer arithmetic intrinsics: pure functions
    // of their register/stack operands with no boundary effect. Rust u128/i128
    // math lowers to these; macOS resolves them statically from
    // compiler-builtins, but Linux GCC-compiled objects (the shim's C half) and
    // some codegen paths leave them as undefined imports resolved from libgcc,
    // where the default-deny audit would otherwise refuse them (caught live:
    // the buggify PRF's `u128 %` surfaced `__umodti3` on aarch64 Linux only).
    const COMPILER_ARITHMETIC: &[&str] = &[
        "ashlti3",
        "ashrti3",
        "divti3",
        "lshrti3",
        "modti3",
        "muloti4",
        "multi3",
        "udivmodti4",
        "udivti3",
        "umodti3",
    ];
    // Abort/exit paths terminate the process rather than observing host state;
    // they are used by Rust panic/abort and explicit process-exit glue.
    const TERMINATION: &[&str] = &["abort", "exit"];
    // Stack-protector checks compare process-local canaries and fail closed.
    const STACK_PROTECTOR: &[&str] = &["stack_chk_fail", "stack_chk_guard"];
    // These pthread helpers expose only the current managed host-thread handle
    // or configure thread/lock attributes in caller-owned memory. Creation and
    // synchronization are provided by Patina interposers, not by these helpers.
    const PTHREAD_LOCAL_HELPERS: &[&str] = &[
        "pthread_attr_destroy",
        "pthread_attr_getguardsize",
        "pthread_attr_getstack",
        "pthread_attr_init",
        "pthread_attr_setstacksize",
        "pthread_equal",
        "pthread_getspecific",
        "pthread_key_create",
        "pthread_key_delete",
        "pthread_mutexattr_destroy",
        "pthread_mutexattr_init",
        "pthread_mutexattr_settype",
        "pthread_self",
        "pthread_setname_np",
        "pthread_setspecific",
    ];
    // Unwind/personality routines walk in-process frames or transfer control to
    // language runtimes; they do not perform host I/O, time, entropy, or waits.
    const UNWIND_AND_PERSONALITY: &[&str] = &["gxx_personality_v0", "rust_eh_personality"];
    // Signal registration is used by Rust's panic/stack-overflow diagnostics;
    // Patina does not deliver ambient host signals into guest execution, so
    // installation is deterministic and delivery happens only on faults.
    const SIGNAL_DIAGNOSTICS: &[&str] = &["sigaction", "sigaltstack", "signal"];
    // The environment pointer itself is startup glue referenced by libc/std
    // runtime setup. The native shim scrubs the ambient host storage at startup
    // and repoints this at an array built from the deterministic guest env map,
    // so direct environ readers see exactly what the getenv interposer answers.
    const ENVIRONMENT_STORAGE: &[&str] = &["environ"];
    // Process-local virtual-memory management backs the allocator, thread
    // stacks, and guard pages; mappings are not guest-observable effects.
    // `madvise` only hints the kernel about process-local pages (the allocator
    // and memory-mapped readers use it), with no boundary effect.
    const PROCESS_LOCAL_MEMORY: &[&str] = &["madvise", "mprotect", "munmap"];
    // Pure signal-set construction: these read or write only a caller-owned
    // `sigset_t`, performing bit manipulation with no host effect. They pair
    // with the already-allowlisted `sigaction`/`signal` registration — a guest
    // builds a mask to hand to a registration call, and Patina delivers no
    // ambient signals, so the mask is inert. The thread-mask *mutators*
    // (`sigprocmask`/`pthread_sigmask`) and blocking waits (`sigwait`,
    // `sigsuspend`, on the `signals-timers` deny list) are deliberately NOT
    // here: they change delivery state or block, unlike these pure set ops.
    const SIGNAL_SET_MANIPULATION: &[&str] = &[
        "sigemptyset",
        "sigfillset",
        "sigaddset",
        "sigdelset",
        "sigismember",
    ];
    // Pure libm math: each is a mathematical function of its floating-point
    // argument(s) — the pointer-out variants (`frexp`/`modf`) write only the
    // caller-owned integer/fraction slot the caller passed. None reads host time,
    // draws entropy, touches a descriptor, blocks, or otherwise crosses the
    // boundary Patina models. Some set `errno` (`ERANGE`/`EDOM`) or raise IEEE
    // floating-point flags on out-of-domain inputs; neither is a host effect
    // Patina observes, so the result stays deterministic for the same operands.
    // Rust's `f64`/`f32` methods (`powf`, `hypot`, `exp`, the rounding family,
    // ...) lower to these; on macOS they resolve as undefined libm imports
    // (`_pow`, ...) that the default-deny audit would otherwise refuse. This is
    // an EXPLICIT list only — no prefix/glob matching, which could mask an
    // effectful symbol that merely shares a math-looking name. It covers the
    // pure, no-boundary-effect math surface only: `random`/`drand48` (PRNG
    // draws), `time`, and CoreFoundation/Security-framework math helpers are
    // deliberately NOT here and stay refused.
    const MATH_LIBM: &[&str] = &[
        // Powers, exponentials, logarithms.
        "pow",
        "powf",
        "exp",
        "expf",
        // Base-10 exponential (DataFusion's numeric SQL expression code reaches
        // it). macOS libm spells it `__exp10` (Mach-O import `___exp10`) and glibc
        // spells it `exp10`; `normalize_native_symbol` strips ALL leading
        // underscores, so both forms arrive here as the single entry `exp10`.
        "exp10",
        "exp2",
        "exp2f",
        "expm1",
        "expm1f",
        "log",
        "logf",
        "log2",
        "log2f",
        "log10",
        "log10f",
        "log1p",
        "log1pf",
        // Trigonometric and inverse-trigonometric.
        "sin",
        "sinf",
        "cos",
        "cosf",
        "tan",
        "tanf",
        "asin",
        "asinf",
        "acos",
        "acosf",
        "atan",
        "atanf",
        "atan2",
        "atan2f",
        // Hyperbolic and inverse-hyperbolic.
        "sinh",
        "sinhf",
        "cosh",
        "coshf",
        "tanh",
        "tanhf",
        "asinh",
        "asinhf",
        "acosh",
        "acoshf",
        "atanh",
        "atanhf",
        // Roots and magnitude combinations.
        "sqrt",
        "sqrtf",
        "cbrt",
        "cbrtf",
        "hypot",
        "hypotf",
        // Remainder and fused multiply-add.
        "fmod",
        "fmodf",
        "fma",
        "fmaf",
        // Decomposition (the pointer-out slot is caller-owned).
        "ldexp",
        "ldexpf",
        "frexp",
        "frexpf",
        "modf",
        "modff",
        // Rounding and truncation.
        "ceil",
        "ceilf",
        "floor",
        "floorf",
        "trunc",
        "truncf",
        "round",
        "roundf",
        "rint",
        "rintf",
        "nearbyint",
        "nearbyintf",
        "lround",
        "lroundf",
        "llround",
        "llroundf",
        "lrint",
        "lrintf",
        "llrint",
        "llrintf",
        // Sign and min/max.
        "fabs",
        "fabsf",
        "copysign",
        "copysignf",
        "fmin",
        "fminf",
        "fmax",
        "fmaxf",
    ];
    // Pure formatting/parsing and generic search over CALLER-OWNED memory, in the
    // C locale (the deterministic environment carries no LC_* so the locale is
    // fixed). `vsnprintf` formats into the caller's buffer; `sscanf` parses the
    // caller's NUL-terminated string; `bsearch` binary-searches a caller array
    // with a caller-supplied comparator. None reads host time/entropy, touches a
    // descriptor, or blocks — a pure caller-memory computation like the
    // `memcpy`/`strtol` intrinsics above (aws-lc and DataFusion reach them). An
    // EXPLICIT list, never a prefix: the effectful stdio `*printf`/`*scanf`
    // variants that touch a real stream stay refused. The `_chk` forms
    // (`vsnprintf_chk`/`snprintf_chk`) are the fortified bounds-checked entries
    // libc lowers a constant-sized buffer onto — the same "add bounds checks
    // before doing the same work" family as the already-listed `memcpy_chk`; the
    // shim's own C layer formats through them in its interposed `fprintf`/
    // `__assert_rtn`, and dead-stripping keeps only the ones a guest reaches.
    const FORMAT_PARSE_SEARCH: &[&str] = &[
        "bsearch",
        "snprintf_chk",
        "sscanf",
        "vsnprintf",
        "vsnprintf_chk",
    ];
    // Floating-point rounding-mode environment. `fegetround`/`fesetround` read
    // and set the CURRENT-THREAD FP rounding mode — thread-local, process-local
    // CPU state, not a boundary Patina models — so they are deterministic for a
    // given call sequence (aws-lc/DataFusion numeric code sets a rounding mode
    // around a computation). No host effect crosses the runtime boundary.
    const FLOAT_ENVIRONMENT: &[&str] = &["fegetround", "fesetround"];
    symbol.starts_with("Unwind_")
        || ALLOCATOR.contains(&symbol)
        || MEMORY_AND_STRING.contains(&symbol)
        || COMPILER_ARITHMETIC.contains(&symbol)
        || TERMINATION.contains(&symbol)
        || STACK_PROTECTOR.contains(&symbol)
        || PTHREAD_LOCAL_HELPERS.contains(&symbol)
        || UNWIND_AND_PERSONALITY.contains(&symbol)
        || SIGNAL_DIAGNOSTICS.contains(&symbol)
        || ENVIRONMENT_STORAGE.contains(&symbol)
        || PROCESS_LOCAL_MEMORY.contains(&symbol)
        || SIGNAL_SET_MANIPULATION.contains(&symbol)
        || MATH_LIBM.contains(&symbol)
        || FORMAT_PARSE_SEARCH.contains(&symbol)
        || FLOAT_ENVIRONMENT.contains(&symbol)
}

fn macho_native_allowlisted_import(symbol: &str) -> bool {
    // Darwin errno is thread-local process state. The shim sets errno after
    // deterministic boundary failures; the host accessor only returns its slot.
    const ERRNO: &[&str] = &["error"];
    // dyld and TLS startup binders are fixed process image/startup glue. They
    // may be consulted by Rust diagnostics, but do not perform boundary ops.
    const STARTUP_AND_IMAGE_GLUE: &[&str] = &[
        "dyld_get_image_header",
        "dyld_get_image_name",
        "dyld_get_image_vmaddr_slide",
        "dyld_image_count",
        "dyld_stub_binder",
        "tlv_atexit",
        "tlv_bootstrap",
    ];
    // Rust/libSystem finalizer registration for thread-local and process-local
    // destructors; registration is process-local and deterministic. `cxa_atexit`
    // (Mach-O `___cxa_atexit`) is the C++/`__attribute__((destructor))` finalizer
    // registrar — same process-local family as `atexit`/`tlv_atexit`, mirroring
    // the ELF `cxa_atexit` entry on `STARTUP_AND_TLS_GLUE` (a C custom allocator's
    // static init reaches it). Registration only records a callback in
    // process-local storage; nothing crosses the boundary Patina models.
    const FINALIZERS: &[&str] = &["atexit", "cxa_atexit"];
    // Darwin's 64-bit mmap import backs the allocator and thread stacks;
    // mprotect/munmap live on the common list.
    const PROCESS_LOCAL_MEMORY: &[&str] = &["mmap"];
    // Darwin libc byte-pattern fills: write a repeating 4/8/16-byte pattern into
    // a caller-owned buffer. Pure caller-memory writes, exactly like the common
    // `memset`/`memcpy` intrinsics but Darwin-only (a byte-oriented regex matcher
    // reaches `memset_pattern16`), so they carry no boundary effect.
    const MEMORY_FILL: &[&str] = &["memset_pattern4", "memset_pattern8", "memset_pattern16"];
    // Read-only stack-extent queries used by Rust's stack-overflow guard. The
    // control-plane thread vehicle (pthread_create_suspended_np, thread_resume,
    // dispatch semaphores) is deliberately NOT allowlisted here: those symbols
    // are the shim's own host mechanism and are `--allow`ed per audited binary
    // by the validation scripts, so an unmanaged binary importing them to
    // spawn or block outside the scheduler still fails the audit.
    const STACK_EXTENT_HELPERS: &[&str] = &["pthread_get_stackaddr_np", "pthread_get_stacksize_np"];
    // Darwin stack-growth probe: `___chkstk_darwin` (compiler-inserted before a
    // large stack frame — tikv-jemallocator's init frames reach it) merely touches
    // successive stack guard pages to fault-in / overflow-check the callee's own
    // stack. Pure caller-stack access with no boundary effect and a value-free,
    // deterministic outcome (it either returns or the process dies on a genuine
    // stack overflow, exactly as native), so it is known-safe.
    const STACK_PROBE: &[&str] = &["chkstk_darwin"];
    // Returns pointers to in-process environment and argument-vector storage.
    // The shim scrubs environ at startup; argv is the supervisor-controlled
    // program arguments (native-run sets them and clears the child environment),
    // so `std::env::args()` reading them stays deterministic. These accessors
    // only hand back those pointers — no host effect.
    const ARGV_ENV_STORAGE: &[&str] = &["NSGetEnviron", "NSGetArgc", "NSGetArgv"];

    ERRNO.contains(&symbol)
        || MEMORY_FILL.contains(&symbol)
        || STARTUP_AND_IMAGE_GLUE.contains(&symbol)
        || FINALIZERS.contains(&symbol)
        || PROCESS_LOCAL_MEMORY.contains(&symbol)
        || STACK_EXTENT_HELPERS.contains(&symbol)
        || STACK_PROBE.contains(&symbol)
        || ARGV_ENV_STORAGE.contains(&symbol)
}

fn elf_native_allowlisted_import(symbol: &str) -> bool {
    // glibc errno is thread-local process state. The shim sets errno after
    // deterministic boundary failures; the host accessor only returns its slot.
    const ERRNO: &[&str] = &["errno_location"];
    // ELF/glibc startup, TLS, and finalizer glue with process-local effects.
    const STARTUP_AND_TLS_GLUE: &[&str] = &[
        "cxa_atexit",
        "cxa_finalize",
        "cxa_thread_atexit_impl",
        "gmon_start",
        "gmon_start__",
        "libc_start_main",
        "tls_get_addr",
    ];
    // Optional transactional-memory clone-table hooks are weak process startup
    // glue emitted by GCC/LLVM; absence or no-op presence has no boundary effect.
    const CLONE_TABLE_GLUE: &[&str] = &["deregisterTMCloneTable", "registerTMCloneTable"];
    // Fixed-at-process-start metadata reads: the auxiliary vector and the
    // running glibc's version string. Constant for a given host+binary, and the
    // trace fingerprint already pins the toolchain/host pairing.
    const FIXED_PROCESS_METADATA: &[&str] = &["getauxval", "gnu_get_libc_version"];
    // Backtrace metadata walks already-loaded ELF program headers.
    const BACKTRACE_IMAGE_GLUE: &[&str] = &["dl_iterate_phdr"];
    // Process-local memory extent. `mmap`/`mmap64` are the same 64-bit mapping on
    // an LP64 glibc (a guest built against plain `mmap` imports that name; the
    // allocator backs its arenas with it); `sbrk` adjusts the program break — both
    // grow only this process's own address space, exactly like the allocator's
    // `mmap` on macOS. `mprotect`/`munmap` live on the common list. Addresses are
    // never virtualized (like `malloc`/`mmap` pointers), so they carry no
    // cross-boundary effect; `mmap`'s invisible `MAP_SHARED` flag is the documented
    // residual (see the coverage matrix), unchanged by adding the plain alias.
    const PROCESS_LOCAL_MEMORY: &[&str] = &["mmap", "mmap64", "sbrk"];
    // Pure in-register byte-order conversion; referenced by the shim's own
    // sockaddr translation.
    const BYTE_ORDER: &[&str] = &["htonl", "htons", "ntohl", "ntohs"];
    // Pure, boundary-effect-free glibc compute helpers. `__ctype_b_loc` returns a
    // pointer to the current locale's constant ctype classification table (behind
    // `isalpha`/`isdigit`/…) — a read-only table, constant for the C locale, no host
    // state read. `__sched_cpucount` is `CPU_COUNT`: it pops the set bits of a
    // caller-owned `cpu_set_t`, pure arithmetic over caller memory (distinct from
    // `sched_getcpu`, which reads the live CPU id and IS interposed to a constant).
    const PURE_COMPUTE: &[&str] = &["ctype_b_loc", "sched_cpucount"];
    // glibc-only pthread introspection: reads the current thread's attributes
    // for Rust's stack-overflow guard. The XPG strerror_r alias is the pure
    // message formatter behind std::io::Error display.
    const GLIBC_THREAD_AND_ERROR_HELPERS: &[&str] = &["pthread_getattr_np", "xpg_strerror_r"];
    // glibc's `assert()` failure hook (aws-lc's asserts lower onto it). It is
    // reached only once an assertion has ALREADY failed, and its whole body is
    // "print the failed expression to stderr, then `abort()`" — the same terminal,
    // value-free outcome as `abort` itself, which is known-safe under TERMINATION
    // above. No host state flows back into the guest, because there is no guest
    // left to read it: the process is over, loudly and at a reproducible point.
    // Honest residual (diagnostic only): Darwin's counterpart `__assert_rtn` is a
    // strong shim def that routes the message to the CAPTURED stderr sink before
    // aborting, so it is never an import there; glibc's stays libc's own, and its
    // message may land on the real stderr instead of the captured sink.
    const ASSERT_FAILURE: &[&str] = &["assert_fail"];

    symbol.starts_with("ITM_")
        || ERRNO.contains(&symbol)
        || STARTUP_AND_TLS_GLUE.contains(&symbol)
        || CLONE_TABLE_GLUE.contains(&symbol)
        || FIXED_PROCESS_METADATA.contains(&symbol)
        || BACKTRACE_IMAGE_GLUE.contains(&symbol)
        || PROCESS_LOCAL_MEMORY.contains(&symbol)
        || BYTE_ORDER.contains(&symbol)
        || PURE_COMPUTE.contains(&symbol)
        || GLIBC_THREAD_AND_ERROR_HELPERS.contains(&symbol)
        || ASSERT_FAILURE.contains(&symbol)
}

/// Classify a denied import into a guest-escape *class* for error quality and
/// for the per-class detection proof. Purely a labeling function: it never
/// gates (allow and the effect-free allowlist are consulted first, so a symbol
/// only reaches here once it is already denied), so growing these lists cannot
/// introduce a false positive — it only sharpens `unknown-import` into a named
/// class.
///
/// The lists are organized by the escape taxonomy documented in
/// `crates/patina-target/ESCAPE-CLASSES.md`, whose coverage matrix maps each
/// class to its detection mechanism, planted test, and honest residual gaps.
/// Symbols the shim *interposes* (`open`, `clock_gettime`, `dispatch_semaphore_*`,
/// pthread sync, ...) are *defined* in a shim-linked binary and so never appear
/// as imports; they are still classified here so that a build which somehow left
/// one unresolved is reported as its escape class rather than a bare unknown
/// import (defense in depth).
fn native_escape_category(symbol: &str) -> Option<&'static str> {
    // (f) Filesystem: path and descriptor I/O. Routed through the deterministic
    // filesystem when interposed; a raw import is a host filesystem escape.
    const FILESYSTEM: &[&str] = &[
        "open",
        "open64",
        "openat",
        "creat",
        "read",
        "readv",
        "preadv",
        "preadv64",
        "write",
        "writev",
        "pwritev",
        "pwritev64",
        "pread",
        "pwrite",
        "close",
        "dup",
        "dup2",
        "dup3",
        "fsync",
        "fdatasync",
        "lseek",
        "ftruncate",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "mkdir",
        "rmdir",
        "stat",
        "stat64",
        "statx",
        "lstat",
        "lstat64",
        "fstat",
        "fstat64",
        "fcntl",
        "getcwd",
        "realpath",
        "readlink",
        "symlink",
        "link",
        "linkat",
        "fdopendir",
    ];
    // (f) Network: BSD sockets. Modeled over SimNet when interposed.
    const NETWORK: &[&str] = &[
        "socket",
        "bind",
        "listen",
        "accept",
        "accept4",
        "connect",
        "send",
        "sendto",
        "sendmsg",
        "recv",
        "recvfrom",
        "recvmsg",
        "shutdown",
        "getaddrinfo",
        "getnameinfo",
        "gethostbyname",
        // Interface-index lookup (a host networking utility stack — hyper-util —
        // links it dormant). The shim deny-traps it (dropped from a shim-linked
        // import table); classified so a raw non-shim import reads as `network`
        // rather than a bare unknown import.
        "if_nametoindex",
    ];
    // (a) Blocking/scheduling — readiness multiplexing. A host `poll`/`select`/
    // `kqueue`/`epoll` wait blocks the calling thread outside the scheduler.
    // The kqueue family (macOS) and the epoll family (Linux) are interposed by
    // the deterministic readiness reactors, so a shim-linked binary defines
    // them; they stay classified so a raw non-shim import reads as a
    // wait-multiplex escape rather than a bare unknown import.
    const WAIT_MULTIPLEX: &[&str] = &[
        "poll",
        "ppoll",
        "select",
        "pselect",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "kevent",
        "kevent64",
        "kqueue",
    ];
    // (a) Blocking/scheduling — locks, semaphores, and futex-like waits. Patina
    // routes managed synchronization through the interposed pthread/dispatch
    // layer; any of these reached raw would block a host thread off-scheduler.
    // Normalized (leading underscores stripped) forms.
    const BLOCKING_SYNC: &[&str] = &[
        "os_unfair_lock_lock",
        "os_unfair_lock_unlock",
        "os_unfair_lock_trylock",
        "ulock_wait",
        "ulock_wait2",
        "ulock_wake",
        "psynch_mutexwait",
        "psynch_mutexdrop",
        "psynch_cvwait",
        "psynch_cvsignal",
        "psynch_cvbroad",
        // libdispatch semaphores back std's Darwin thread `Parker`
        // (`thread::park`/`park_timeout` and the `mpsc`/`mpmc`/`Once` paths on
        // it). The shim interposes them, so they are normally *defined*, not
        // imported; classify them so a build that leaves one unresolved reads as
        // a blocking escape, not a bare unknown import.
        "dispatch_semaphore_create",
        "dispatch_semaphore_wait",
        "dispatch_semaphore_signal",
        // Mach semaphores are the shim's own execution-baton vehicle on macOS,
        // now reached through the host-alias table (`dlsym`) rather than a named
        // import, so they never appear as a guest import. Classify the whole
        // family — including `semaphore_create`, whose omission previously left
        // the pre-doctrine baton's create call unclassified — so an unmanaged
        // binary reaching any of them directly is reported as a blocking escape.
        "semaphore_create",
        "semaphore_wait",
        "semaphore_signal",
        "semaphore_timedwait",
        // Darwin 14+ public futex surface, in case a future std lowers parking
        // to it: it must be interposed, never allowed to block a host thread.
        "os_sync_wait_on_address",
        "os_sync_wait_on_address_with_timeout",
        "os_sync_wake_by_address_any",
        "os_sync_wake_by_address_all",
    ];
    // (b) Time: any host clock read or blocking sleep must come from the virtual
    // clock. Interposed forms are defined; a raw import reads host time.
    const TIME: &[&str] = &[
        "clock_gettime",
        "clock_gettime_nsec_np",
        "gettimeofday",
        "time",
        "nanosleep",
        "clock_nanosleep",
        "usleep",
        "sleep",
        "mach_absolute_time",
        "mach_continuous_time",
        "mach_wait_until",
        // Broken-down local-time conversion and its timezone-table primer. Both
        // read the host's timezone database / `TZ` to render a `time_t` into a
        // `struct tm` (or seed the global `tzname`/`timezone`), so the result
        // varies by where the run happens — a host-timezone-dependent time read.
        // Cross-platform (Mach-O `_localtime_r`, ELF `localtime_r`). Classified
        // only: a raw import is still refused; a deterministic runtime must feed
        // conversions a fixed virtual zone, never the host's.
        "localtime_r",
        "tzset",
    ];
    // (c) Entropy: deterministic bytes come from the seeded RNG; a raw import
    // draws real host entropy.
    const ENTROPY: &[&str] = &[
        "getentropy",
        "getrandom",
        "arc4random",
        "arc4random_buf",
        "arc4random_uniform",
        "CCRandomGenerateBytes",
        "SecRandomCopyBytes",
        "RAND_bytes",
    ];
    // (e) Process: spawning, signalling, and reaping processes. A documented
    // non-goal — but the gate must still DETECT reachability and refuse.
    const PROCESS: &[&str] = &[
        "fork",
        "vfork",
        "execve",
        "execv",
        "execvp",
        "execvP",
        "execvpe",
        "execl",
        "execlp",
        "execle",
        "fexecve",
        "posix_spawn",
        "posix_spawnp",
        "system",
        "popen",
        "kill",
        "killpg",
        "waitpid",
        "wait",
        "wait3",
        "wait4",
        "waitid",
        "getpid",
        "getppid",
        "uname",
    ];
    // (h) Signals and timers: sources of asynchronous, wall-clock-driven wakeups
    // that would perturb the deterministic schedule. (Bare `sigaction`/`signal`
    // registration stays on the allowlist — Patina delivers no ambient signals —
    // but timer-arming and signal-*waiting* are escapes.)
    const SIGNALS_TIMERS: &[&str] = &[
        "setitimer",
        "getitimer",
        "alarm",
        "ualarm",
        "timer_create",
        "timer_settime",
        "timer_delete",
        "sigsuspend",
        "sigwait",
        "sigwaitinfo",
        "sigtimedwait",
        "pause",
    ];
    // (g) Shared memory and IPC: channels to other address spaces or the kernel
    // that escape the single-process deterministic model.
    // (`mmap` is deliberately absent: it is allowlisted as process-local memory
    // and the audit cannot see its `MAP_SHARED` flag — that residual is
    // documented in the coverage matrix, not papered over with a dead label.)
    // `pipe`/`pipe2`/`socketpair` are the IN-PROCESS slice of class g: both ends
    // stay inside the one guest (an async runtime's IO-driver / signal self-pipe),
    // so they are now INTERPOSED as deterministic in-memory channels (strong shim
    // defs — see `c/patina_posix.c` and ESCAPE-CLASSES.md row g) and drop off a
    // shim-linked binary's import table. They stay classified here — exactly like
    // the interposed `os_unfair_lock_*`/`dispatch_semaphore_*` above — so a NON-
    // shim binary that imports one raw still reads as a class-g escape rather than
    // a bare unknown import. `eventfd`/`eventfd2` (Linux, mio's Waker vehicle)
    // joined that in-process interposed slice — a single 64-bit counter inside
    // the one guest — and follow the same stay-classified convention. The
    // cross-process members (`shm_open`/`mach_*`/`mq_*`) are NOT interposed and
    // stay refused.
    const SHARED_MEMORY_IPC: &[&str] = &[
        "shm_open",
        "shm_unlink",
        "mach_msg",
        "mach_msg2",
        "mach_msg_overwrite",
        "mach_port_allocate",
        "mach_port_insert_right",
        "mach_port_deallocate",
        "bootstrap_look_up",
        "mq_open",
        "mq_send",
        "mq_receive",
        "mq_timedreceive",
        "pipe",
        "pipe2",
        "socketpair",
        "eventfd",
        "eventfd2",
    ];
    // Environment reads and mutation. Reads and guest-driven mutation are
    // modeled deterministically by the native shim, which owns the guest env map
    // and the environ array published from it; `putenv` stays fail-closed
    // because its entry aliases caller-owned memory. Either way an UNINTERPOSED
    // member would reach the host environment, so the whole family is classified.
    const ENVIRONMENT: &[&str] = &[
        "getenv",
        "secure_getenv",
        "setenv",
        "unsetenv",
        "putenv",
        "clearenv",
    ];
    // Dynamic loading can pull in arbitrary uninterposed host code.
    const DYNAMIC: &[&str] = &["dlopen", "dlsym", "dlclose", "dlmopen"];
    // (d) Thread lifecycle: anything that mints a new runnable host context must
    // go through the managed `pthread_create` vehicle, not these.
    const THREADING: &[&str] = &[
        "pthread_create",
        "pthread_create_from_mach_thread_np",
        "bsdthread_create",
        "thread_create",
        "thread_create_running",
    ];
    // Direct kernel entry by name (the libc wrapper). Inlined syscall
    // *instructions* are caught separately by `scan_forbidden_instructions`.
    const SYSCALL: &[&str] = &["syscall", "__syscall", "syscall_chk"];
    let classified = [
        (FILESYSTEM, "filesystem"),
        (NETWORK, "network"),
        (WAIT_MULTIPLEX, "wait-multiplex"),
        (BLOCKING_SYNC, "unmanaged-sync"),
        (TIME, "time"),
        (ENTROPY, "entropy"),
        (PROCESS, "process"),
        (SIGNALS_TIMERS, "signals-timers"),
        (SHARED_MEMORY_IPC, "shared-memory-ipc"),
        (ENVIRONMENT, "environment"),
        (DYNAMIC, "dynamic-loading"),
        (THREADING, "unmanaged-thread"),
        (SYSCALL, "direct-syscall"),
    ]
    .into_iter()
    .find_map(|(symbols, category)| symbols.contains(&symbol).then_some(category));
    // (i) macOS system frameworks: CoreFoundation and Security. These are NOT
    // interposed. The Security-framework subset (`SecTrustSettingsCopy*`,
    // `SecCertificateCopyData`, `SecCopyErrorMessageString`) reads the host
    // keychain / system trust store — mutable host state that varies by machine
    // and over time — so a run that reaches it is not reproducible; the
    // CoreFoundation helpers (`CFArray*`/`CFString*`/`CFData*`/`kCF*`) are the
    // data-structure plumbing those calls require and travel with them.
    // `rustls-native-certs`, `security-framework`, and any native TLS trust-root
    // loader pull in this surface. A named class over the bare `unknown-import`
    // it would otherwise fall to, so the gate can attach a determinism-specific
    // refusal note. Matched by Apple's reserved framework prefixes as a REFINEMENT
    // of the unknown fallback (a real classification above always wins), so it can
    // never relax a decision — these symbols are denied either way.
    classified
        .or_else(|| is_macos_framework_symbol(symbol).then_some("macos-framework"))
        .or_else(|| is_host_introspection_symbol(symbol).then_some("host-introspection"))
}

/// Whether a normalized import name reads host CPU/memory/hardware/process state
/// through the macOS Mach/BSD/IOKit introspection surface (`sysctl`,
/// `getrusage`, `task_info`, `host_statistics64`, `proc_pidinfo`, the IOKit
/// registry walk, ...). These are NOT interposed and read live per-host,
/// per-run machine state — core counts, memory pressure, thermal/battery/device
/// inventory, per-process resource usage — so a run that reaches one is not
/// reproducible across hosts or even across runs on one host. `sysinfo`,
/// `num_cpus`-style probes, and hardware-inventory crates pull in this surface.
///
/// Like [`is_macos_framework_symbol`], this is a fail-closed REFINEMENT of the
/// bare `unknown-import` fallback (a real classification above always wins, and
/// these symbols are denied either way), so it can only sharpen the label and
/// drive the determinism note — never relax a decision. The IOKit members are
/// matched by their reserved entry-point prefixes (`IOService`/`IORegistry`/
/// `IOIterator`/`IOObject`) rather than a bare `IO` prefix: `IO` alone would
/// capture arbitrary user symbols that merely start with those two letters
/// (`IOWidget`, ...), whereas the four namespace prefixes cover the whole
/// observed IOKit surface without that overreach. Everything else is an exact
/// list.
fn is_host_introspection_symbol(symbol: &str) -> bool {
    // macOS Mach/BSD host- and process-state reads. Exact names (no prefix), so
    // an unrelated symbol that merely shares a stem stays unclassified.
    const HOST_STATE: &[&str] = &[
        "sysctl",
        "sysctlbyname",
        "getrusage",
        "task_info",
        "mach_task_self_",
        "mach_host_self",
        "host_statistics64",
        "host_processor_info",
        "vm_page_size",
        "vm_deallocate",
        "proc_listallpids",
        "proc_pidinfo",
        "proc_pid_rusage",
        "proc_pidpath",
    ];
    HOST_STATE.contains(&symbol)
        || symbol.starts_with("IOService")
        || symbol.starts_with("IORegistry")
        || symbol.starts_with("IOIterator")
        || symbol.starts_with("IOObject")
}

/// Whether a normalized import name is a macOS CoreFoundation (`CF`/`kCF`) or
/// Security (`Sec`/`kSec`) framework symbol. These are Apple-reserved framework
/// prefixes, so the match does not collide with Rust or libc names in practice,
/// and it stays fail-closed regardless: such symbols are already denied as
/// `unknown-import`, so classifying them only sharpens the label (and drives the
/// gate's determinism-warning note), never relaxes the deny.
fn is_macos_framework_symbol(symbol: &str) -> bool {
    symbol.starts_with("CF")
        || symbol.starts_with("kCF")
        || symbol.starts_with("Sec")
        || symbol.starts_with("kSec")
}

impl WasiAudit {
    pub fn audit(bytes: &[u8]) -> Result<Self, TargetError> {
        let mut imports = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            if let Payload::ImportSection(reader) = payload.map_err(TargetError::Parse)? {
                for group in reader {
                    for import in group.map_err(TargetError::Parse)? {
                        let (_, import) = import.map_err(TargetError::Parse)?;
                        imports.push(WasmImport {
                            module: import.module.into(),
                            name: import.name.into(),
                        });
                    }
                }
            }
        }
        fn import_is_supported(import: &WasmImport) -> bool {
            match import.module.as_str() {
                WASI_PREVIEW1_MODULE => SUPPORTED_PREVIEW1_IMPORTS.contains(&import.name.as_str()),
                PATINA_SDK_MODULE => SUPPORTED_PATINA_SDK_IMPORTS.contains(&import.name.as_str()),
                _ => false,
            }
        }
        let unsupported = imports
            .iter()
            .filter(|import| !import_is_supported(import))
            .cloned()
            .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            return Err(TargetError::UnsupportedImports(unsupported));
        }
        Ok(Self { imports })
    }
}

pub fn render_native_escapes_grouped(escapes: &[NativeEscape]) -> String {
    let mut groups: BTreeMap<String, Vec<(&NativeEscape, NativeProvenance)>> = BTreeMap::new();
    for escape in escapes {
        let provenance = if escape.provenance.is_empty() {
            vec![NativeProvenance::unknown()]
        } else {
            escape.provenance.clone()
        };
        for origin in provenance {
            groups
                .entry(origin.label())
                .or_default()
                .push((escape, origin));
        }
    }

    let mut groups = groups.into_iter().collect::<Vec<_>>();
    groups.sort_by(|(left_label, left), (right_label, right)| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left_label.cmp(right_label))
    });

    let mut output = String::from("unsupported native imports:");
    if groups.is_empty() {
        return output;
    }
    for (label, findings) in groups {
        output.push('\n');
        output.push_str(&format!(
            "  {label} ({} finding{})",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        ));
        for (finding, origin) in findings {
            output.push('\n');
            output.push_str(&format!("    {} ({})", finding.symbol, finding.category));
            if let Some(site) = origin.site_label() {
                output.push_str(&format!(" [{site}]"));
            }
        }
    }
    output
}

#[derive(Debug)]
pub enum TargetError {
    Parse(wasmparser::BinaryReaderError),
    NativeParse(object::Error),
    UnsupportedImports(Vec<WasmImport>),
    UnsupportedNativeFormat(BinaryFormat),
    UnsupportedNativeArchitecture(Architecture),
    UnsupportedNativeImports(Vec<NativeEscape>),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "failed to parse WebAssembly module: {error}"),
            Self::NativeParse(error) => write!(f, "failed to parse native object: {error}"),
            Self::UnsupportedImports(imports) => {
                write!(f, "unsupported WebAssembly imports:")?;
                for import in imports {
                    write!(f, " {}::{}", import.module, import.name)?;
                }
                Ok(())
            }
            Self::UnsupportedNativeFormat(format) => {
                write!(
                    f,
                    "unsupported native binary format {format:?}; expected Mach-O or ELF"
                )
            }
            Self::UnsupportedNativeArchitecture(architecture) => {
                write!(
                    f,
                    "refusing to certify native binary: the forbidden-instruction \
containment scan cannot decode architecture {architecture:?}; supported architectures are Aarch64 \
and X86_64. Passing it would leave every instruction unexamined (a vacuous gate), so the audit/run \
fails closed"
                )
            }
            Self::UnsupportedNativeImports(imports) => {
                f.write_str(&render_native_escapes_grouped(imports))
            }
        }
    }
}

impl std::error::Error for TargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::NativeParse(error) => Some(error),
            Self::UnsupportedImports(_)
            | Self::UnsupportedNativeFormat(_)
            | Self::UnsupportedNativeArchitecture(_)
            | Self::UnsupportedNativeImports(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

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
    fn sud_manageability_is_instruction_direct_syscall_only() {
        // The SUD audit downgrade applies to raw inline syscall *instruction*
        // findings and nothing else. A by-name `syscall` import is already
        // interposed/refused on its own terms, and `cpu-nondeterminism` register
        // reads (rdtsc/mrs CNTVCT) cannot be trapped by SUD — downgrading either
        // would silently widen the gate. RED: flip any arm below and the
        // downgrade would admit an untappable escape.
        let trappable = NativeEscape::new(
            "instruction@.text+0x42".into(),
            "direct-syscall",
            vec![NativeProvenance::unknown()],
        );
        assert!(native_escape_is_sud_manageable(&trappable));
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

    /// Build an instruction finding with a decoded mnemonic, as the scan does.
    fn instruction_finding(category: &'static str, mnemonic: &'static str) -> NativeEscape {
        NativeEscape::new(
            "instruction@.text+0x42".into(),
            category,
            vec![NativeProvenance::unknown()],
        )
        .with_mnemonic(mnemonic)
    }

    #[test]
    fn tsc_manageability_is_the_timestamp_counter_only() {
        // The TSC trap answers exactly two instructions from the virtual clock.
        for mnemonic in ["rdtsc", "rdtscp"] {
            assert!(
                native_escape_is_tsc_manageable(&instruction_finding(
                    "cpu-nondeterminism",
                    mnemonic
                )),
                "{mnemonic} is trap-managed"
            );
        }
        // The rest of the shared `cpu-nondeterminism` category is NOT: no
        // mechanism traps a hardware entropy read or the arm64 system counter, so
        // downgrading any of them would turn a refusal into a silent host escape.
        // RED: widen the predicate to the whole category and these fail.
        for mnemonic in ["rdrand", "rdseed", "cntvct"] {
            assert!(
                !native_escape_is_tsc_manageable(&instruction_finding(
                    "cpu-nondeterminism",
                    mnemonic
                )),
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
    fn cpu_nondeterminism_note_names_allowability_and_trappability() {
        // No instruction findings: no note (a by-name cpu-nondeterminism import
        // is answered by the ordinary symbol machinery).
        let by_name = NativeEscape::new(
            "sched_getcpu".into(),
            "cpu-nondeterminism",
            vec![NativeProvenance::unknown()],
        );
        assert!(render_cpu_nondeterminism_note(&[by_name]).is_none());

        // A blocked timestamp read: say it is trappable elsewhere, and that
        // --allow cannot clear an instruction finding.
        let note =
            render_cpu_nondeterminism_note(&[instruction_finding("cpu-nondeterminism", "rdtscp")])
                .expect("a blocked instruction finding must carry a note");
        assert!(note.contains("--allow <symbol> cannot clear one"), "{note}");
        assert!(note.contains("rdtscp"), "{note}");
        assert!(note.contains("PR_SET_TSC"), "{note}");

        // A blocked entropy read: say it is untrappable anywhere, so the operator
        // is not sent hunting for a platform that would run it.
        let note = render_cpu_nondeterminism_note(&[
            instruction_finding("cpu-nondeterminism", "rdrand"),
            instruction_finding("cpu-nondeterminism", "cntvct"),
        ])
        .expect("a blocked instruction finding must carry a note");
        assert!(note.contains("untrappable anywhere"), "{note}");
        assert!(note.contains("cntvct/rdrand"), "{note}");
        assert!(!note.contains("PR_SET_TSC"), "{note}");
    }

    #[test]
    fn vsyscall_reference_scan_detects_the_page_and_refuses_it() {
        // A `movabs rax, 0xffffffffff600000` (48 b8 <imm64>) — materializing the
        // vsyscall gettimeofday entry — is caught by the immediate signal.
        let mut text = vec![0x48u8, 0xb8];
        text.extend_from_slice(&0xffffffffff600000u64.to_le_bytes());
        let provenance = NativeProvenanceIndex {
            entries: Vec::new(),
        };
        let mut escapes = Vec::new();
        scan_vsyscall_references(&text, ".text", 0, &provenance, &mut escapes);
        assert_eq!(
            escapes.len(),
            1,
            "vsyscall immediate must be found: {escapes:?}"
        );
        assert_eq!(escapes[0].category, "vsyscall");
        // A `vsyscall` finding is never SUD-downgradable (kernel-emulated, no
        // syscall instruction), so it always refuses.
        assert!(!native_escape_is_sud_manageable(&escapes[0]));

        // The `time` entry at +0x400 is also on the page and caught.
        let mut text2 = vec![0x48u8, 0xb8];
        text2.extend_from_slice(&0xffffffffff600400u64.to_le_bytes());
        let mut escapes2 = Vec::new();
        scan_vsyscall_references(&text2, ".text", 0, &provenance, &mut escapes2);
        assert_eq!(escapes2.len(), 1, "vsyscall time entry must be found");

        // RED control: ordinary text (including a nearby-but-not-on-page address)
        // yields no finding — the detector is not a blanket 0xff... matcher.
        let mut clean = vec![0x48u8, 0xb8];
        clean.extend_from_slice(&0xffffffffff700000u64.to_le_bytes()); // wrong page
        clean.extend_from_slice(&[0x90; 16]); // nops
        let mut none = Vec::new();
        scan_vsyscall_references(&clean, ".text", 0, &provenance, &mut none);
        assert!(none.is_empty(), "off-page address must not match: {none:?}");
    }

    #[test]
    fn sud_marker_detection_fails_closed_on_unparseable_input() {
        // A malformed binary must never be treated as SUD-capable: the marker
        // check is a downgrade precondition, so parse failure ⇒ error, not false.
        assert!(native_binary_has_sud_marker(b"not an object file").is_err());
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

    /// Build a minimal but well-formed little-endian ELF64 for `e_machine`, with
    /// a single `ALLOC|EXECINSTR` PROGBITS `.text` section carrying a few bytes
    /// plus a `.shstrtab`. Just enough for `object::File::parse` to report the
    /// architecture and a real `SectionKind::Text` section — the `.text` bytes
    /// are the executable code a silent-pass scanner would skip.
    fn minimal_executable_elf64(e_machine: u16) -> Vec<u8> {
        let text: [u8; 8] = [0x00; 8];
        // ".text" name at byte 1, ".shstrtab" name at byte 7.
        let shstr: &[u8] = b"\0.text\0.shstrtab\0";
        let text_off = 64u64;
        let shstr_off = text_off + text.len() as u64;
        let shoff = {
            let end = shstr_off + shstr.len() as u64;
            (end + 7) & !7 // section header table is 8-aligned
        };

        let mut elf = Vec::new();
        // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, SysV ABI, padding.
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        elf.extend_from_slice(&[0u8; 8]);
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        elf.extend_from_slice(&e_machine.to_le_bytes()); // e_machine
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_shstrndx -> .shstrtab
        assert_eq!(elf.len(), 64, "ELF64 header is 64 bytes");

        elf.extend_from_slice(&text); // .text data at offset 64
        elf.extend_from_slice(shstr); // .shstrtab data at offset 72
        while (elf.len() as u64) < shoff {
            elf.push(0);
        }

        let mut push_shdr =
            |name: u32, typ: u32, flags: u64, offset: u64, size: u64, addralign: u64| {
                elf.extend_from_slice(&name.to_le_bytes());
                elf.extend_from_slice(&typ.to_le_bytes());
                elf.extend_from_slice(&flags.to_le_bytes());
                elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
                elf.extend_from_slice(&offset.to_le_bytes());
                elf.extend_from_slice(&size.to_le_bytes());
                elf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
                elf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
                elf.extend_from_slice(&addralign.to_le_bytes());
                elf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
            };
        push_shdr(0, 0, 0, 0, 0, 0); // 0: SHN_UNDEF
        // 1: .text — SHT_PROGBITS(1), SHF_ALLOC|SHF_EXECINSTR (0x2|0x4).
        push_shdr(1, 1, 0x2 | 0x4, text_off, text.len() as u64, 4);
        // 2: .shstrtab — SHT_STRTAB(3).
        push_shdr(7, 3, 0, shstr_off, shstr.len() as u64, 1);

        elf
    }

    // Default-deny for architectures the containment scan cannot decode.
    // `scan_forbidden_instructions` once had a `_ => {}` arm that SILENTLY passed
    // any binary whose ISA it could not decode: a riscv64/s390x guest — including
    // one carrying a forbidden `ecall`/`svc` in `.text` — sailed through with zero
    // instructions examined, exactly the vacuous-gate failure mode the default-deny
    // doctrine forbids. Feed the scanner a hand-built minimal ELF of such an
    // architecture, WITH a real executable `.text` section, and assert both the
    // private scanner and the public `NativeAudit::audit` gate fail closed with a
    // loud, structured error that names the architecture and the supported set.
    // Red-before/green-after: with the old `_ => {}` arm the scan returns
    // `Ok(vec![])` and the audit `Ok(_)`, so both assertions below fail.
    #[test]
    fn refuses_binaries_of_undecodable_architectures() {
        use object::{Architecture, Object, ObjectSection, SectionKind};

        const EM_S390: u16 = 22;
        const EM_RISCV: u16 = 243;
        for (machine, label) in [(EM_RISCV, "riscv"), (EM_S390, "s390")] {
            let elf = minimal_executable_elf64(machine);

            // The scenario is the live one: object reports a non-decodable arch and
            // a genuine executable text section (the bytes the old arm skipped).
            let parsed = object::File::parse(&*elf).expect("hand-built ELF must parse");
            assert!(
                !matches!(
                    parsed.architecture(),
                    Architecture::Aarch64 | Architecture::X86_64
                ),
                "{label}: test arch must be one the scanner cannot decode, got {:?}",
                parsed.architecture()
            );
            assert!(
                parsed.sections().any(|s| s.kind() == SectionKind::Text),
                "{label}: the synthetic ELF must carry an executable .text section"
            );

            // Private scanner refuses.
            let provenance = NativeProvenanceIndex::new(&parsed);
            let scan = scan_forbidden_instructions(&parsed, &provenance);
            assert!(
                matches!(scan, Err(TargetError::UnsupportedNativeArchitecture(_))),
                "{label}: scan must refuse an undecodable arch, got {scan:?}"
            );

            // Public gate refuses end to end.
            let err = NativeAudit::audit(&elf, &BTreeSet::new())
                .expect_err("audit must fail closed on an undecodable arch");
            assert!(
                matches!(err, TargetError::UnsupportedNativeArchitecture(_)),
                "{label}: audit error must be UnsupportedNativeArchitecture, got {err:?}"
            );
            let message = err.to_string();
            assert!(
                message.contains("cannot decode architecture")
                    && message.contains("Aarch64")
                    && message.contains("X86_64")
                    && message.contains("fails closed"),
                "{label}: error must name the arch, the supported set, and fail closed: {message}"
            );
        }
    }

    // Supported architectures still scan (not swept up by the arch guard): a
    // native binary built for the host — Aarch64 on macOS, X86_64 on Linux —
    // decodes cleanly. The existing per-class and objdump-corpus tests cover the
    // decoders themselves; this asserts the guard itself does not reject a
    // supported arch. `scans_supported_arch_binary` builds nothing (no toolchain
    // dependence): it hand-builds a supported-arch ELF the same way and asserts
    // the scan does NOT return the arch error.
    #[test]
    fn scans_supported_arch_binary_without_arch_refusal() {
        const EM_X86_64: u16 = 62;
        const EM_AARCH64: u16 = 183;
        for (machine, label) in [(EM_X86_64, "x86_64"), (EM_AARCH64, "aarch64")] {
            let elf = minimal_executable_elf64(machine);
            let parsed = object::File::parse(&*elf).expect("hand-built ELF must parse");
            let provenance = NativeProvenanceIndex::new(&parsed);
            let scan = scan_forbidden_instructions(&parsed, &provenance);
            assert!(
                !matches!(scan, Err(TargetError::UnsupportedNativeArchitecture(_))),
                "{label}: a supported arch must not be refused by the arch guard, got {scan:?}"
            );
            // The .text here is all-zero, which decodes to no forbidden opcode on
            // either supported ISA, so the scan succeeds with no findings.
            assert_eq!(
                scan.expect("supported arch scans").len(),
                0,
                "{label}: zeroed .text yields no forbidden-instruction findings"
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
    // half of the check that `validate-native-shim.sh` applies to the shim's
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
    fn accepts_supported_preview1_imports() {
        let bytes = module_importing(WASI_PREVIEW1_MODULE, "random_get");
        let audit = WasiAudit::audit(&bytes).unwrap();
        assert_eq!(audit.imports[0].name, "random_get");
    }

    #[test]
    fn rejects_unknown_modules_and_unsupported_wasi_calls() {
        let host = WasiAudit::audit(&module_importing("host", "escape")).unwrap_err();
        assert!(matches!(host, TargetError::UnsupportedImports(_)));
        let wasi = WasiAudit::audit(&module_importing(
            WASI_PREVIEW1_MODULE,
            "nonexistent_import",
        ))
        .unwrap_err();
        assert!(wasi.to_string().contains("nonexistent_import"));
    }

    fn module_importing(module: &str, name: &str) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        // One () -> () function type.
        bytes.extend([1, 4, 1, 0x60, 0, 0]);
        let mut import = vec![1, module.len() as u8];
        import.extend(module.as_bytes());
        import.push(name.len() as u8);
        import.extend(name.as_bytes());
        import.extend([0, 0]); // function import, type index 0
        bytes.push(2);
        bytes.push(import.len() as u8);
        bytes.extend(import);
        bytes
    }

    /// Read the first double-quoted string literal at the start of `after` (which
    /// must begin at the opening quote), returning `(contents, rest_after_quote)`.
    /// `None` when `after` does not begin with a `"` (e.g. a `#name` macro
    /// stringization), which is exactly how the parser skips the `patina_native_trap`
    /// macro *definition* while catching its literal call sites.
    fn read_quoted(after: &str) -> Option<(&str, &str)> {
        let rest = after.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some((&rest[..end], &rest[end + 1..]))
    }

    /// The single string-literal argument of the first `prefix("…")` call on
    /// `line`, if any (`patina_process_trap("fork")` → `fork`).
    fn one_literal_arg(line: &str, prefix: &str) -> Option<String> {
        let idx = line.find(prefix)?;
        let (arg, _) = read_quoted(&line[idx + prefix.len()..])?;
        Some(arg.to_owned())
    }

    /// The `(class, symbol)` of the first `patina_native_trap("class", "symbol")`
    /// call on `line`. Returns `None` when either argument is not a string literal,
    /// which skips the macro definition `patina_native_trap("…", #name)`.
    fn native_trap_args(line: &str) -> Option<(String, String)> {
        let idx = line.find("patina_native_trap(")?;
        let after = &line[idx + "patina_native_trap(".len()..];
        let (class, rest) = read_quoted(after)?;
        let rest = rest.trim_start().strip_prefix(',')?.trim_start();
        let (symbol, _) = read_quoted(rest)?;
        Some((class.to_owned(), symbol.to_owned()))
    }

    /// The identifier argument of a `MACRO(Ident)` invocation at the start of a
    /// trimmed `line`, e.g. `PATINA_FRAMEWORK_TRAP(CFArrayCreate)` → `CFArrayCreate`.
    fn macro_invocation_arg(line: &str, macro_name: &str) -> Option<String> {
        let rest = line.strip_prefix(macro_name)?.strip_prefix('(')?;
        let end = rest.find(')')?;
        let ident = &rest[..end];
        (!ident.is_empty() && ident.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .then(|| ident.to_owned())
    }

    /// Parse every deny-trap-calling definition out of the shim C source into a
    /// `(symbol, class)` set: the two trap macros' invocations, the explicit
    /// `patina_native_trap` sites, and the `patina_process_trap` sites. The macro
    /// class is fixed by the macro (its body calls `patina_native_trap` with that
    /// literal class), so it is attached here.
    fn parse_c_deny_traps(source: &str) -> BTreeSet<(String, String)> {
        let mut set = BTreeSet::new();
        for raw in source.lines() {
            let line = raw.trim_start();
            // Skip preprocessor lines so the macro `#define`/`#undef` are ignored;
            // real invocations sit at column 0 with no leading `#`.
            if !line.starts_with('#') {
                if let Some(symbol) = macro_invocation_arg(line, "PATINA_FRAMEWORK_TRAP") {
                    set.insert((symbol, "macos-framework".to_owned()));
                    continue;
                }
                if let Some(symbol) = macro_invocation_arg(line, "PATINA_INTROSPECTION_TRAP") {
                    set.insert((symbol, "host-introspection".to_owned()));
                    continue;
                }
            }
            if let Some(symbol) = one_literal_arg(line, "patina_process_trap(") {
                set.insert((symbol, "process".to_owned()));
            }
            if let Some((class, symbol)) = native_trap_args(line) {
                set.insert((symbol, class));
            }
        }
        set
    }

    // SINGLE SOURCE OF TRUTH guard: `NATIVE_DENY_TRAP_SYMBOLS` must equal exactly
    // the set of trap-calling definitions in `c/patina_posix.c`. Reading the C via
    // an include_str! keeps the guard hermetic without a dependency edge onto the
    // shim crate. When a concurrent change converts a trap to a real model (the
    // symbol's trap body is removed) or adds a new trap, this fails until the
    // constant is updated in lockstep — so the "fails later" note can never quietly
    // drift from what the shim actually arms.
    #[test]
    fn deny_trap_symbols_track_the_shim_c_source() {
        const C_SOURCE: &str = include_str!("../../patina-native-shim/c/patina_posix.c");
        let parsed = parse_c_deny_traps(C_SOURCE);
        let declared: BTreeSet<(String, String)> = NATIVE_DENY_TRAP_SYMBOLS
            .iter()
            .map(|(symbol, class)| ((*symbol).to_owned(), (*class).to_owned()))
            .collect();
        let missing: Vec<_> = parsed.difference(&declared).collect();
        let extra: Vec<_> = declared.difference(&parsed).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "NATIVE_DENY_TRAP_SYMBOLS drifted from c/patina_posix.c.\n  \
             in the C but NOT in the constant (add them): {missing:?}\n  \
             in the constant but NOT in the C (a trap became a real model? remove them): {extra:?}",
        );
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

    /// Build an ELF image whose symbol table has the shape a linker produces: a
    /// run of local symbols, each introduced by the STT_FILE marker naming its
    /// input object, and then the global symbols — which follow the whole local
    /// run and therefore sit under no marker at all.
    ///
    /// `locals` is `(file, symbol, address, size)`; `globals` is
    /// `(symbol, address, size)`.
    fn elf_with_symbol_runs(
        locals: &[(&str, &str, u64, u64)],
        globals: &[(&str, u64, u64)],
    ) -> Vec<u8> {
        use object::write::{Object as WriteObject, Symbol as WriteSymbol, SymbolSection};
        use object::{Endianness, SymbolFlags, SymbolScope};

        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        object.append_section_data(text, &[0x90; 0x200], 16);

        let mut current_file = None;
        for (file, symbol, address, size) in locals {
            if current_file != Some(*file) {
                current_file = Some(*file);
                object.add_symbol(WriteSymbol {
                    name: file.as_bytes().to_vec(),
                    value: 0,
                    size: 0,
                    kind: SymbolKind::File,
                    scope: SymbolScope::Compilation,
                    weak: false,
                    section: SymbolSection::None,
                    flags: SymbolFlags::None,
                });
            }
            object.add_symbol(WriteSymbol {
                name: symbol.as_bytes().to_vec(),
                value: *address,
                size: *size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Compilation,
                weak: false,
                section: SymbolSection::Section(text),
                flags: SymbolFlags::None,
            });
        }
        for (symbol, address, size) in globals {
            object.add_symbol(WriteSymbol {
                name: symbol.as_bytes().to_vec(),
                value: *address,
                size: *size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(text),
                flags: SymbolFlags::None,
            });
        }
        object.write().expect("synthesized ELF is writable")
    }

    // The ELF root cause. A STT_FILE marker names the input object of the LOCAL
    // symbols that follow it, and ELF puts every local before the first global,
    // so no marker reaches a global symbol. Carrying the last one forward anyway
    // stamped every global in the image with whichever object happened to be last
    // in the local run — the `object=crtstuff.c` / `object=ucmpti2.c` findings, up
    // to and including groups that contradicted themselves
    // (`crate=leaker_a object=crtstuff.c`). Locals keep their real object;
    // globals report no object rather than a borrowed one.
    #[test]
    fn elf_file_symbols_never_reach_past_their_own_local_run() {
        let bytes = elf_with_symbol_runs(
            &[
                ("shim.c", "shim_helper", 0x10, 0x10),
                ("ucmpti2.c", "builtin_helper", 0x30, 0x10),
            ],
            &[("_RNvCslpz1a3WbgXx_8leaker_a4addr", 0x80, 0x10)],
        );
        let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
        let index = NativeProvenanceIndex::new(&file);

        let local = index.for_address(0x18, Some(".text"));
        assert_eq!(local.object, "shim.c");
        assert_eq!(local.containing_symbol.as_deref(), Some("shim_helper"));

        let last_local = index.for_address(0x38, Some(".text"));
        assert_eq!(last_local.object, "ucmpti2.c");

        // The regression pin: this global follows `ucmpti2.c` in the table but
        // belongs to neither file symbol.
        let global = index.for_address(0x88, Some(".text"));
        assert_eq!(
            global.object, UNKNOWN_OBJECT,
            "a global symbol must not inherit the last file symbol in the table"
        );
        assert_eq!(global.crate_name.as_deref(), Some("leaker_a"));
        assert_eq!(
            global.containing_symbol.as_deref(),
            Some("_RNvCslpz1a3WbgXx_8leaker_a4addr")
        );
        assert_eq!(
            global.label(),
            "provenance=crate=leaker_a",
            "an unrecorded object is omitted, never rendered as a borrowed one"
        );
    }

    // Nested symbols: the tightest container names the site. This is the shape a
    // linked ELF really produces — a global function laid out inside the span of
    // a local region symbol, which is the one that carries an object — and
    // ranking object provenance ahead of precision made the enclosing region win,
    // naming a symbol that merely surrounds the site instead of the function
    // holding it.
    #[test]
    fn elf_containing_symbol_is_the_tightest_enclosing_symbol() {
        let bytes = elf_with_symbol_runs(
            &[("shim.c", "outer_region", 0x10, 0x80)],
            &[("_RNvCslpz1a3WbgXx_8leaker_a4addr", 0x40, 0x10)],
        );
        let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
        let index = NativeProvenanceIndex::new(&file);
        assert_eq!(
            index
                .for_address(0x44, Some(".text"))
                .containing_symbol
                .as_deref(),
            Some("_RNvCslpz1a3WbgXx_8leaker_a4addr")
        );
        assert_eq!(
            index
                .for_address(0x20, Some(".text"))
                .containing_symbol
                .as_deref(),
            Some("outer_region")
        );
    }

    // Each stub is mapped by the slot it jumps through, not by its position in
    // the table. The two here jump through slots in the opposite order to their
    // position, so a positional mapping and a decoded one cannot agree — which is
    // the failure that had every `call foo@plt` site in a real binary attributed
    // to an unrelated import, and imports reported as referenced from functions
    // (`fputs`, `puts`) that never touched them.
    #[test]
    fn plt_entries_map_by_the_slot_they_jump_through_not_by_position() {
        use object::write::{Object as WriteObject, StandardSegment};
        use object::{Endianness, SectionKind};

        // Entry 0 is a reserved header that is not a stub at all; entry 1 jumps
        // through the higher slot and entry 2 through the lower one.
        let mut plt = vec![0xcc; 16];
        plt.extend_from_slice(&[0xff, 0x25]);
        plt.extend_from_slice(&0x3ff2_i32.to_le_bytes());
        plt.extend_from_slice(&[0xcc; 10]);
        plt.extend_from_slice(&[0xff, 0x25]);
        plt.extend_from_slice(&0x3fda_i32.to_le_bytes());
        plt.extend_from_slice(&[0xcc; 10]);

        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section = object.add_section(
            object.segment_name(StandardSegment::Text).to_vec(),
            b".plt".to_vec(),
            SectionKind::Text,
        );
        object.append_section_data(section, &plt, 16);
        let bytes = object.write().expect("synthesized ELF is writable");
        let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
        let base = file
            .sections()
            .find(|section| section.name() == Ok(".plt"))
            .expect("the .plt section survives the round trip")
            .address();

        let higher = base + 0x16 + 0x3ff2;
        let lower = base + 0x26 + 0x3fda;
        assert!(
            higher > lower,
            "the fixture only discriminates if slot order is the reverse of entry order"
        );
        let got_slots = BTreeMap::from([
            (lower, "lower_slot".to_owned()),
            (higher, "higher_slot".to_owned()),
        ]);

        let mut targets = BTreeMap::new();
        collect_elf_plt_targets(&file, &got_slots, &mut targets);
        assert_eq!(
            targets,
            BTreeMap::from([
                (base + 0x10, "higher_slot".to_owned()),
                (base + 0x20, "lower_slot".to_owned()),
            ]),
            "counting entries off against slot order would swap these two"
        );
    }

    // PLT stubs are decoded through their own GOT slot rather than counted off
    // positionally, so an entry that carries no symbol relocation (a reserved
    // header word, an ifunc's IRELATIVE) cannot shift the rest of the table onto
    // the wrong imports.
    #[test]
    fn plt_stubs_resolve_through_the_got_slot_they_jump_through() {
        // `jmp *0x2fda(%rip)` at 0x1020: RIP after the 6-byte instruction is
        // 0x1026, so the slot is 0x4000.
        let mut lazy = vec![0xff, 0x25];
        lazy.extend_from_slice(&0x2fda_i32.to_le_bytes());
        assert_eq!(
            decode_plt_stub_slot(Architecture::X86_64, &lazy, 0x1020),
            Some(0x4000)
        );

        // A `.plt.sec` entry: `endbr64` then `bnd jmp *0x2fd1(%rip)`. The jump
        // starts at offset 5, so RIP is 0x1020 + 5 + 6 = 0x102b.
        let mut endbr = vec![0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25];
        endbr.extend_from_slice(&0x2fd5_i32.to_le_bytes());
        assert_eq!(
            decode_plt_stub_slot(Architecture::X86_64, &endbr, 0x1020),
            Some(0x4000)
        );

        // aarch64: `adrp x16, 0x4000` then `ldr x17, [x16, #0x18]`.
        let aarch64: Vec<u8> = [0xf000_0010_u32, 0xf940_0e11]
            .iter()
            .flat_map(|instruction| instruction.to_le_bytes())
            .collect();
        assert_eq!(
            decode_plt_stub_slot(Architecture::Aarch64, &aarch64, 0x1000),
            Some(0x4018)
        );

        // Padding is not a stub.
        assert_eq!(
            decode_plt_stub_slot(Architecture::X86_64, &[0xcc; 16], 0x1020),
            None
        );
    }

    // Import references are read at instruction boundaries, so displacement bytes
    // sitting inside another instruction's operand are never mistaken for one.
    // The planted `movabs` below carries the exact encoding of a RIP-relative
    // load of `phantom_import` in its 8-byte immediate: a scan that matched the
    // pattern at every byte offset reported that import as referenced from
    // whatever function contained these bytes.
    #[test]
    fn import_xrefs_ignore_reference_bytes_embedded_in_an_operand() {
        const SECTION: u64 = 0x1000;
        let mut data = vec![0x48, 0xb8];
        // imm64 = `mov rax, [rip+0xff8]` as data — resolving, if decoded at
        // offset 2, to 0x1008 + 0xff8 = 0x2000.
        data.extend_from_slice(&[0x8b, 0x05, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00]);
        // A genuine `mov rax, [rip+0x1fef]` at a real boundary (offset 0xa):
        // 0x1011 + 0x1fef = 0x3000.
        data.extend_from_slice(&[0x48, 0x8b, 0x05, 0xef, 0x1f, 0x00, 0x00]);

        let targets = BTreeMap::from([
            (0x2000_u64, "phantom_import".to_owned()),
            (0x3000_u64, "real_import".to_owned()),
        ]);
        let file = elf_with_symbol_runs(&[("caller.c", "caller", SECTION, 0x40)], &[]);
        let file = object::File::parse(&*file).expect("synthesized ELF parses");
        let index = NativeProvenanceIndex::new(&file);

        let mut origins = BTreeMap::new();
        scan_x86_64_import_xrefs(
            &data,
            SECTION,
            Some(".text"),
            &targets,
            &index,
            &mut origins,
        );
        assert_eq!(
            origins.keys().collect::<Vec<_>>(),
            vec!["real_import"],
            "only the reference at a real instruction boundary counts"
        );
    }

    // Impl methods dominate a real symbol table, and their demangled form starts
    // with the impl header rather than the crate. Reading only the first `::`
    // segment left `crate=` empty for most of a binary — every `std` finding in
    // the reproduction came through as `provenance=` with an object alone.
    #[test]
    fn crate_name_recovers_from_impl_method_and_generic_symbols() {
        assert_eq!(
            crate_name_from_symbol("_RNvCslpz1a3WbgXx_8leaker_a4addr").as_deref(),
            Some("leaker_a")
        );
        assert_eq!(
            crate_name_from_symbol(
                "_RNvXs1_NtNtNtCs2AWtUsOyxgP_3std2os4unix7processNtNtBb_7process5ChildNtB5_8ChildExt18kill_process_group"
            )
            .as_deref(),
            Some("std")
        );

        // Direct path cases, including the ones that must NOT yield a crate: a
        // generic parameter and a primitive are not crates.
        assert_eq!(
            crate_name_from_demangled_path("std::io::Write::write_all").as_deref(),
            Some("std")
        );
        assert_eq!(
            crate_name_from_demangled_path("<alloc::vec::Vec<T> as core::ops::Drop>::drop")
                .as_deref(),
            Some("alloc")
        );
        assert_eq!(
            crate_name_from_demangled_path("*const std::ffi::c_void::method").as_deref(),
            Some("std")
        );
        assert_eq!(
            crate_name_from_demangled_path("<T as core::fmt::Debug>::fmt"),
            None
        );
        assert_eq!(
            crate_name_from_demangled_path("<u32 as core::fmt::Display>::fmt"),
            None
        );
        assert_eq!(crate_name_from_demangled_path("{{closure}}"), None);
    }

    // An object with no name is not attribution. An ELF file symbol may carry an
    // empty name, and rendering that produced a bare `object=` with nothing after
    // it — the arm64 flavor of the same wrong answer x86_64 gave by borrowing the
    // last marker in the table. Both the marker and the label collapse to
    // `unknown` instead.
    #[test]
    fn an_empty_object_name_is_reported_as_unknown_not_as_an_empty_label() {
        assert_eq!(compact_object_label("", None), UNKNOWN_OBJECT);
        assert_eq!(compact_object_label("", Some("")), UNKNOWN_OBJECT);
        assert_eq!(compact_object_label("libfoo.rlib", Some("")), "libfoo.rlib");

        let bytes = elf_with_symbol_runs(
            &[("", "unnamed_file_local", 0x10, 0x10)],
            &[("_RNvCslpz1a3WbgXx_8leaker_a4addr", 0x80, 0x10)],
        );
        let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
        let index = NativeProvenanceIndex::new(&file);
        for address in [0x18, 0x88] {
            let provenance = index.for_address(address, Some(".text"));
            assert_eq!(
                provenance.object, UNKNOWN_OBJECT,
                "an empty file symbol names no object at {address:#x}"
            );
            assert!(
                !provenance.label().contains("object="),
                "an unnamed object must not be rendered at all: {}",
                provenance.label()
            );
        }
    }

    // rustc names each codegen unit `<crate>.<hash>-cgu.<n>`, and that name is
    // what the linker copies into the ELF file symbol — the readable half of
    // ELF's object identity. Local-crate units are named by hash alone and must
    // not be mined for a crate name.
    #[test]
    fn codegen_unit_names_yield_a_crate_only_when_they_carry_one() {
        assert_eq!(
            crate_name_from_codegen_unit("std.1e3c4ec04c5261a9-cgu.0").as_deref(),
            Some("std")
        );
        assert_eq!(
            crate_name_from_codegen_unit("compiler_builtins.fb155c23557db162-cgu.000").as_deref(),
            Some("compiler_builtins")
        );
        assert_eq!(
            crate_name_from_codegen_unit("9hzrs7df61h1scw4v1u1kzqy5"),
            None
        );
        assert_eq!(crate_name_from_codegen_unit("crtstuff.c"), None);
        assert_eq!(crate_name_from_codegen_unit("patina_posix.c"), None);
    }

    // A section name is the one field every site can fill in, so counting it as
    // attribution kept each unattributable reference as its own
    // `provenance=unknown` group instead of collapsing into one — and kept those
    // groups alive alongside the real ones.
    #[test]
    fn section_only_provenance_collapses_and_yields_to_real_attribution() {
        let site = |section: &str| NativeProvenance {
            object: UNKNOWN_OBJECT.into(),
            crate_name: None,
            containing_symbol: None,
            section: Some(section.into()),
        };
        assert_eq!(
            normalize_provenance(vec![site(".text"), site(".data")]),
            vec![NativeProvenance::unknown()]
        );

        let attributed = NativeProvenance {
            object: "libfoo-1234abcd.rlib(foo.o)".into(),
            crate_name: Some("foo".into()),
            containing_symbol: Some("foo::bar".into()),
            section: Some(".text".into()),
        };
        assert_eq!(
            normalize_provenance(vec![site(".text"), attributed.clone()]),
            vec![attributed]
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

    // glibc's `assert()` failure hook. It is reached only after an assertion has
    // already failed, and its whole body is "write a diagnostic to stderr, then
    // `abort()`" — a terminal path, the same deterministic outcome as the
    // already-known-safe `abort`, with no value flowing back into the guest.
    // Darwin's counterpart `__assert_rtn` is a strong shim def (it routes the
    // diagnostic to the captured stderr sink before aborting) so it never appears
    // as an import there; glibc's stays libc's, hence ELF-only.
    #[test]
    fn classifies_the_glibc_assert_failure_hook_as_known_safe() {
        let empty = BTreeSet::new();
        assert_eq!(
            native_import_decision("__assert_fail", NativeFormat::Elf, &empty),
            NativeImportDecision::Allowed,
            "glibc's assert hook is a terminate-with-diagnostic path, not an escape"
        );
        assert_eq!(
            native_import_decision("__assert_fail", NativeFormat::MachO, &empty),
            NativeImportDecision::Denied("unknown-import"),
            "Darwin has no `__assert_fail`; the row must stay ELF-only"
        );
    }

    /// Build a dynamically-linked-shaped ELF64 x86_64 executable carrying a
    /// `.dynsym` (what `imports()` reads) and a `.symtab` (the rest of the audited
    /// closure). Each entry is `(name, weak, defined)`.
    fn elf_with_symbol_bindings(
        dynamic: &[(&str, bool, bool)],
        statics: &[(&str, bool, bool)],
    ) -> Vec<u8> {
        // (symbols, strings) for one ELF64 symbol table, index 0 being the
        // mandatory null entry.
        fn table(symbols: &[(&str, bool, bool)]) -> (Vec<u8>, Vec<u8>) {
            let mut strings = vec![0u8];
            let mut entries = vec![0u8; 24];
            for (name, weak, defined) in symbols {
                let st_name = strings.len() as u32;
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
                // st_info = (bind << 4) | type; STB_WEAK(2)/STB_GLOBAL(1), STT_FUNC(2).
                let st_info = (if *weak { 2u8 } else { 1u8 } << 4) | 2;
                // A definition lives in .text (section 1); a reference is SHN_UNDEF.
                let (st_shndx, st_size): (u16, u64) = if *defined { (1, 4) } else { (0, 0) };
                entries.extend_from_slice(&st_name.to_le_bytes());
                entries.push(st_info);
                entries.push(0); // st_other
                entries.extend_from_slice(&st_shndx.to_le_bytes());
                entries.extend_from_slice(&0u64.to_le_bytes()); // st_value
                entries.extend_from_slice(&st_size.to_le_bytes());
            }
            (entries, strings)
        }

        let text = [0x90u8; 16]; // nops: nothing the instruction scan forbids
        let shstr: &[u8] = b"\0.text\0.dynsym\0.dynstr\0.symtab\0.strtab\0.shstrtab\0";
        let (dynsym, dynstr) = table(dynamic);
        let (symtab, strtab) = table(statics);
        let align8 = |value: u64| (value + 7) & !7;

        let text_off = 64u64;
        let dynsym_off = text_off + text.len() as u64;
        let dynstr_off = dynsym_off + dynsym.len() as u64;
        let symtab_off = align8(dynstr_off + dynstr.len() as u64);
        let strtab_off = symtab_off + symtab.len() as u64;
        let shstr_off = strtab_off + strtab.len() as u64;
        let shoff = align8(shstr_off + shstr.len() as u64);

        let mut elf = Vec::new();
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        elf.extend_from_slice(&[0u8; 8]);
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        elf.extend_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&7u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&6u16.to_le_bytes()); // e_shstrndx -> .shstrtab
        assert_eq!(elf.len(), 64, "ELF64 header is 64 bytes");

        elf.extend_from_slice(&text);
        elf.extend_from_slice(&dynsym);
        elf.extend_from_slice(&dynstr);
        while (elf.len() as u64) < symtab_off {
            elf.push(0);
        }
        elf.extend_from_slice(&symtab);
        elf.extend_from_slice(&strtab);
        elf.extend_from_slice(shstr);
        while (elf.len() as u64) < shoff {
            elf.push(0);
        }

        #[allow(clippy::too_many_arguments)]
        let mut push_shdr = |name: u32,
                             typ: u32,
                             flags: u64,
                             offset: u64,
                             size: u64,
                             link: u32,
                             info: u32,
                             addralign: u64,
                             entsize: u64| {
            elf.extend_from_slice(&name.to_le_bytes());
            elf.extend_from_slice(&typ.to_le_bytes());
            elf.extend_from_slice(&flags.to_le_bytes());
            elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
            elf.extend_from_slice(&offset.to_le_bytes());
            elf.extend_from_slice(&size.to_le_bytes());
            elf.extend_from_slice(&link.to_le_bytes());
            elf.extend_from_slice(&info.to_le_bytes());
            elf.extend_from_slice(&addralign.to_le_bytes());
            elf.extend_from_slice(&entsize.to_le_bytes());
        };
        push_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0); // 0: SHN_UNDEF
        // 1: .text — SHT_PROGBITS(1), SHF_ALLOC|SHF_EXECINSTR.
        push_shdr(1, 1, 0x2 | 0x4, text_off, text.len() as u64, 0, 0, 4, 0);
        // 2: .dynsym — SHT_DYNSYM(11), linked to .dynstr, one local (the null entry).
        push_shdr(7, 11, 0x2, dynsym_off, dynsym.len() as u64, 3, 1, 8, 24);
        // 3: .dynstr — SHT_STRTAB(3).
        push_shdr(15, 3, 0x2, dynstr_off, dynstr.len() as u64, 0, 0, 1, 0);
        // 4: .symtab — SHT_SYMTAB(2), linked to .strtab.
        push_shdr(23, 2, 0, symtab_off, symtab.len() as u64, 5, 1, 8, 24);
        // 5: .strtab — SHT_STRTAB(3).
        push_shdr(31, 3, 0, strtab_off, strtab.len() as u64, 0, 0, 1, 0);
        // 6: .shstrtab — SHT_STRTAB(3).
        push_shdr(39, 3, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0);

        elf
    }

    // The fixture itself must present the shape the rule reasons about, or every
    // assertion below would be vacuous: the undefined entries have to reach
    // `imports()`, and the weak/defined bits have to survive the round trip.
    #[test]
    fn symbol_binding_fixture_presents_real_weak_and_defined_bindings() {
        let bytes = elf_with_symbol_bindings(
            &[("weak_undef", true, false), ("strong_undef", false, false)],
            &[("weak_def", true, true)],
        );
        let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
        let imports: Vec<String> = file
            .imports()
            .expect("imports parse")
            .into_iter()
            .map(|import| String::from_utf8_lossy(import.name()).into_owned())
            .collect();
        assert_eq!(imports, vec!["weak_undef", "strong_undef"]);
        let weak: Vec<(String, bool, bool)> = file
            .dynamic_symbols()
            .chain(file.symbols())
            .filter_map(|symbol| symbol.name().ok().filter(|name| !name.is_empty()))
            .zip(
                file.dynamic_symbols()
                    .chain(file.symbols())
                    .filter(|symbol| symbol.name().is_ok_and(|name| !name.is_empty()))
                    .map(|symbol| (symbol.is_weak(), symbol.is_definition())),
            )
            .map(|(name, (weak, defined))| (name.to_owned(), weak, defined))
            .collect();
        assert_eq!(
            weak,
            vec![
                ("weak_undef".to_owned(), true, false),
                ("strong_undef".to_owned(), false, false),
                ("weak_def".to_owned(), true, true),
            ]
        );
    }

    // Undefined weak imports are inert. aws-lc references its allocator-override
    // hooks (`OPENSSL_memory_alloc`/`_free`/`_get_size`/`_realloc`) and `sdallocx`
    // weakly: nothing in the link defines them, so each resolves to NULL and the
    // referencing code takes its guarded default path. A NULL that cannot be
    // called is not a door to the host, so refusing them is a false positive —
    // they are reported under their own heading instead, keeping the surface
    // visible without demanding an `--allow` that would ALSO clear a real
    // definition of the same name if one ever appeared.
    #[test]
    fn undefined_weak_imports_are_inert_not_refused() {
        let hooks = [
            "OPENSSL_memory_alloc",
            "OPENSSL_memory_free",
            "OPENSSL_memory_get_size",
            "OPENSSL_memory_realloc",
            "sdallocx",
        ];
        let dynamic: Vec<(&str, bool, bool)> =
            hooks.iter().map(|name| (*name, true, false)).collect();
        let bytes = elf_with_symbol_bindings(&dynamic, &[]);
        let audit = NativeAudit::audit(&bytes, &BTreeSet::new())
            .expect("undefined weak imports must not refuse the audit");
        assert_eq!(
            audit.inert_weak_imports, hooks,
            "each rescued import must be reported under the inert-weak heading"
        );
        for hook in hooks {
            assert!(
                audit.imports.iter().any(|import| import == hook),
                "{hook} must stay listed among the imports"
            );
        }
        let rendered =
            render_inert_weak_imports(&audit.inert_weak_imports).expect("a non-empty list renders");
        assert!(
            rendered.starts_with("inert weak imports"),
            "the heading must name the class: {rendered}"
        );
        assert!(
            rendered.contains("sdallocx") && rendered.contains("resolve to NULL"),
            "the note must list the symbols and say why they are inert: {rendered}"
        );
        assert_eq!(
            render_inert_weak_imports(&[]),
            None,
            "an empty list emits no heading"
        );
    }

    // Fail-closed guard 1 (planted): the rule keys on "nothing in the audited
    // closure defines it". Plant a definition of the same name elsewhere in the
    // closure and the weak reference is live again — it now binds to real code —
    // so it must fall back to the full classification path and refuse. Without the
    // definition check, this fixture audits clean: that is the leak.
    #[test]
    fn a_defined_weak_symbol_keeps_the_full_classification_path() {
        let bytes = elf_with_symbol_bindings(
            &[("host_side_door", true, false)],
            &[("host_side_door", true, true)],
        );
        let error = NativeAudit::audit(&bytes, &BTreeSet::new())
            .expect_err("a weak symbol the closure DEFINES must not be treated as inert");
        let TargetError::UnsupportedNativeImports(denied) = error else {
            panic!("expected an unsupported-import refusal, got {error:?}");
        };
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].symbol, "host_side_door");
        assert_eq!(denied[0].category, "unknown-import");
    }

    // Fail-closed guard 2: the rule is about weak bindings only. A STRONG
    // undefined import is exactly today's escape — the dynamic linker must bind it
    // to a real definition or the process will not start — so it is untouched.
    #[test]
    fn a_strong_undefined_import_is_untouched_by_the_weak_rule() {
        let bytes = elf_with_symbol_bindings(&[("host_side_door", false, false)], &[]);
        let error = NativeAudit::audit(&bytes, &BTreeSet::new())
            .expect_err("a strong undefined import must still refuse");
        let TargetError::UnsupportedNativeImports(denied) = error else {
            panic!("expected an unsupported-import refusal, got {error:?}");
        };
        assert_eq!(denied[0].symbol, "host_side_door");
    }

    // Fail-closed guard 3: the rule is narrowed to symbols with no known escape
    // class, and that narrowing is load-bearing rather than cosmetic. An undefined
    // weak reference is NULL only while nothing defines it — and the dynamic
    // linker searches the loaded libraries too, so a weak undefined `open` binds
    // to libc's `open` at load and runs. Exactly the classified names are the ones
    // a loaded library defines, so a weak binding never rescues one.
    #[test]
    fn a_weak_undefined_import_of_a_classified_escape_still_refuses() {
        for (symbol, category) in [("open", "filesystem"), ("socket", "network")] {
            let bytes = elf_with_symbol_bindings(&[(symbol, true, false)], &[]);
            let error = NativeAudit::audit(&bytes, &BTreeSet::new()).expect_err(
                "a weak reference to a symbol the loaded libraries define must still refuse",
            );
            let TargetError::UnsupportedNativeImports(denied) = error else {
                panic!("expected an unsupported-import refusal, got {error:?}");
            };
            assert_eq!(denied[0].symbol, symbol);
            assert_eq!(denied[0].category, category);
        }
    }

    // The acceptance shape the three rules above were built for: the exact
    // seven-symbol residual a glibc `slatedb-dst --features aws` build carries
    // (aws-lc-sys), auditing clean with an EMPTY allow set. The bindings are the
    // ones aws-lc's own source produces — `crypto/mem.c` declares the five hooks
    // through `WEAK_SYMBOL_FUNC`, which on ELF is `__attribute__((weak))` with no
    // definition in the closure — and the two glibc entry points are ordinary
    // strong references.
    #[test]
    fn the_aws_lc_import_residual_audits_clean_with_no_allowance() {
        let weak_hooks = [
            "OPENSSL_memory_alloc",
            "OPENSSL_memory_free",
            "OPENSSL_memory_get_size",
            "OPENSSL_memory_realloc",
            "sdallocx",
        ];
        let mut dynamic: Vec<(&str, bool, bool)> =
            weak_hooks.iter().map(|name| (*name, true, false)).collect();
        dynamic.push(("__isoc23_sscanf", false, false));
        dynamic.push(("__assert_fail", false, false));

        let bytes = elf_with_symbol_bindings(&dynamic, &[]);
        let audit = NativeAudit::audit(&bytes, &BTreeSet::new())
            .expect("the aws-lc residual must audit clean with zero --allow");
        assert_eq!(
            audit.inert_weak_imports, weak_hooks,
            "the five weak hooks are inert; the two glibc symbols are known-safe, not inert"
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
}
