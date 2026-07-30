//! Target metadata and fail-closed import auditing.

use std::collections::BTreeSet;
use std::fmt;

use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionKind};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEscape {
    pub symbol: String,
    pub category: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAudit {
    pub imports: Vec<String>,
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
        let mut denied = imports
            .iter()
            .filter_map(
                |symbol| match native_import_decision(symbol, format, allow) {
                    NativeImportDecision::Allowed => None,
                    NativeImportDecision::Denied(category) => Some(NativeEscape {
                        symbol: symbol.clone(),
                        category,
                    }),
                },
            )
            .collect::<Vec<_>>();
        denied.extend(scan_forbidden_instructions(&file)?);
        if !denied.is_empty() {
            return Err(TargetError::UnsupportedNativeImports(denied));
        }
        Ok(Self { imports })
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

/// Whether a shim-linked native binary installs a custom `#[global_allocator]`
/// in place of the default (System) allocator.
///
/// Signature: every Rust binary defines the allocator-ABI entry `__rust_alloc`.
/// With the DEFAULT allocator, rustc additionally emits the `__rdl_alloc` shim
/// (mangled `___rustc::__rdl_alloc`) that `__rust_alloc` forwards to; installing a
/// custom `#[global_allocator]` instead points `__rust_alloc` straight at the
/// user allocator and OMITS `__rdl_alloc`. So a defined `__rust_alloc` with NO
/// defined `__rdl_alloc` is the marker of a custom global allocator. Matched as a
/// substring of the (v0-mangled) defined-symbol names so it is independent of the
/// leading-underscore decoration and the exact mangling prefix.
///
/// This is load-bearing for the pre-run gate: the shim's synchronization
/// interposers allocate through the global allocator (the lock table registers
/// each lock lazily on first touch), so a custom allocator whose OWN lazy
/// initialization takes an interposed lock re-enters the half-initialized
/// allocator while the shim holds its non-reentrant runtime lock and DEADLOCKS
/// before `main`. tikv-jemallocator hits this exactly: `malloc_init_hard` →
/// `os_unfair_lock` → the shim's `os_unfair_lock` interposer → BTreeMap allocate →
/// jemalloc `malloc` → `malloc_init_hard` (a self-deadlock, silent pre-main hang).
/// The gate refuses the whole class up front rather than let that reach a sweep.
///
/// Fails closed on a parse error or unsupported format so a malformed/foreign
/// input is never silently treated as the default allocator.
pub fn native_binary_installs_custom_global_allocator(bytes: &[u8]) -> Result<bool, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    NativeFormat::from_binary(file.format())?;
    let mut defines_rust_alloc = false;
    let mut defines_default_shim = false;
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if !symbol.is_definition() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        // `__rust_alloc` also matches `__rust_alloc_zeroed`/`__rust_alloc_error_handler`
        // and `__rdl_alloc` also matches `__rdl_alloc_zeroed` — either member of a
        // family is a sufficient presence signal.
        if name.contains("__rust_alloc") {
            defines_rust_alloc = true;
        }
        if name.contains("__rdl_alloc") {
            defines_default_shim = true;
        }
    }
    Ok(defines_rust_alloc && !defines_default_shim)
}

/// Whether a denied native escape is a `direct-syscall` finding that
/// syscall-user-dispatch can trap and route — i.e. a raw inline `syscall`/`svc`
/// *instruction* (`instruction@…`), as opposed to a `cpu-nondeterminism`
/// register read (`rdtsc`/`mrs CNTVCT`), which SUD cannot trap and which still
/// refuses. This is the escape set the SUD audit downgrade applies to.
pub fn native_escape_is_sud_manageable(escape: &NativeEscape) -> bool {
    escape.category == "direct-syscall" && escape.symbol.starts_with("instruction@")
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
        // references bind to the shim's neutering `__wrap_dlsym`. So, as on macOS,
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
        NativeImportDecision::Denied(category) if category != "unknown-import" => Some(category),
        _ => None,
    }
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
    NativeImportDecision::Denied(native_escape_category(normalized).unwrap_or("unknown-import"))
}

fn native_allowlisted_import(symbol: &str, format: NativeFormat) -> bool {
    common_native_allowlisted_import(symbol)
        || match format {
            NativeFormat::MachO => macho_native_allowlisted_import(symbol),
            NativeFormat::Elf => elf_native_allowlisted_import(symbol),
        }
}

fn scan_forbidden_instructions(file: &object::File<'_>) -> Result<Vec<NativeEscape>, TargetError> {
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
                    let category = aarch64_instruction_category(instruction);
                    if let Some(category) = category {
                        escapes.push(NativeEscape {
                            symbol: format!("instruction@{name}+0x{:x}", index * 4),
                            category,
                        });
                    }
                }
            }
            Architecture::X86_64 => {
                x86_scan::scan(data, name, &mut escapes);
                scan_vsyscall_references(data, name, &mut escapes);
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
fn scan_vsyscall_references(data: &[u8], name: &str, escapes: &mut Vec<NativeEscape>) {
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
            escapes.push(NativeEscape {
                symbol: format!("immediate@{name}+0x{offset:x}"),
                category: "vsyscall",
            });
        }
    }
}

fn aarch64_instruction_category(instruction: u32) -> Option<&'static str> {
    if instruction & 0xffe0_001f == 0xd400_0001 {
        Some("direct-syscall")
    } else if instruction & !0x1f == 0xd53b_e040 {
        Some("cpu-nondeterminism")
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

    struct OpAttr {
        modrm: bool,
        imm: Imm,
        /// A forbidden opcode fixed by the opcode bytes alone (syscall, rdtsc).
        cat: Option<&'static str>,
        /// `0f c7` (group 9): rdrand (ModRM.reg 6) vs cmpxchg8b is a reg decision
        /// resolved after the ModRM byte is read.
        group9: bool,
    }

    enum Step {
        Insn {
            len: usize,
            cat: Option<&'static str>,
        },
        Undecodable,
    }

    /// Walk `data` (a `.text` section) instruction by instruction, pushing a
    /// finding for each forbidden opcode at a real boundary and one
    /// `undecodable-instruction` finding (then stopping) if the decoder cannot
    /// measure an instruction.
    pub(super) fn scan(data: &[u8], name: &str, escapes: &mut Vec<super::NativeEscape>) {
        let mut offset = 0usize;
        while offset < data.len() {
            match decode_one(&data[offset..]) {
                Step::Insn { len, cat } => {
                    if let Some(category) = cat {
                        escapes.push(super::NativeEscape {
                            symbol: format!("instruction@{name}+0x{offset:x}"),
                            category,
                        });
                    }
                    // Every instruction consumes at least its opcode byte, so
                    // `len >= 1`; the guard only defends the loop invariant.
                    if len == 0 {
                        break;
                    }
                    offset += len;
                }
                Step::Undecodable => {
                    escapes.push(super::NativeEscape {
                        symbol: format!("instruction@{name}+0x{offset:x}"),
                        category: "undecodable-instruction",
                    });
                    break;
                }
            }
        }
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
            // group 9 (`0f c7`): ModRM.reg 6 is RDRAND (reg 7 RDSEED is not
            // currently classified; keep parity with the historical reg==6 test).
            if attr.group9 && reg == 6 {
                cat = Some("cpu-nondeterminism");
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

    /// Two-byte (`0f xx`) opcode attributes. `None` = fail closed. The three
    /// forbidden opcodes are `0f 05` (syscall), `0f 31` (rdtsc), and `0f c7 /6`
    /// (rdrand, resolved from ModRM.reg by the caller).
    fn two_byte(op2: u8) -> Option<OpAttr> {
        use Imm::*;
        match op2 {
            0x05 => Some(OpAttr {
                modrm: false,
                imm: None,
                cat: Some("direct-syscall"),
                group9: false,
            }),
            0x31 => Some(OpAttr {
                modrm: false,
                imm: None,
                cat: Some("cpu-nondeterminism"),
                group9: false,
            }),
            0xC7 => Some(OpAttr {
                modrm: true,
                imm: None,
                cat: Option::None,
                group9: true,
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
            0x00..=0x03
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
        /// `(length, forbidden_category)`.
        fn decode(b: &[u8]) -> (usize, Option<&'static str>) {
            match decode_one(b) {
                Step::Insn { len, cat } => (len, cat),
                Step::Undecodable => panic!("decoder failed closed on {b:02x?}"),
            }
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

        #[test]
        fn walks_past_forbidden_bytes_embedded_in_operands() {
            // `mov rax, 0x0f31000f05` — the immediate contains both the `0f 05`
            // (syscall) and `0f 31` (rdtsc) byte pairs, but they are operand data,
            // not instruction boundaries. A boundary-aware scan flags neither; the
            // old byte-slide flagged both.
            let mut escapes = Vec::new();
            let text = [0x48, 0xb8, 0x05, 0x0f, 0x00, 0x31, 0x0f, 0x00, 0x00, 0x00];
            scan(&text, ".text", &mut escapes);
            assert!(
                escapes.is_empty(),
                "operand-embedded opcode bytes must not be flagged: {escapes:?}"
            );
            // The same forbidden bytes at a real boundary (a `syscall` after a nop)
            // must still be caught.
            let mut escapes = Vec::new();
            scan(&[0x90, 0x0f, 0x05], ".text", &mut escapes);
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
                scan(bytes, ".text", &mut escapes);
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
            scan(&text, ".text", &mut escapes);
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
/// underscore prefixes, glibc `__`-prefixed aliases, and Darwin `$NOCANCEL`
/// variants are audited against the same allowlist entry.
fn normalize_native_symbol(symbol: &str) -> &str {
    let symbol = symbol.trim_start_matches('_');
    symbol.strip_suffix("$NOCANCEL").unwrap_or(symbol)
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
        "strcpy_chk",
        "strerror_r",
        "strlen",
        "strncasecmp",
        "strncmp",
        "strncpy_chk",
        "strnlen",
        "strrchr",
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
    // runtime setup. The native shim scrubs the live storage at startup, so
    // direct environ readers see an empty deterministic environment.
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
    // destructors; registration is process-local and deterministic.
    const FINALIZERS: &[&str] = &["atexit"];
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
    // glibc's 64-bit mmap alias; mprotect/munmap live on the common list.
    const PROCESS_LOCAL_MEMORY: &[&str] = &["mmap64"];
    // Pure in-register byte-order conversion; referenced by the shim's own
    // sockaddr translation.
    const BYTE_ORDER: &[&str] = &["htonl", "htons", "ntohl", "ntohs"];
    // glibc-only pthread introspection: reads the current thread's attributes
    // for Rust's stack-overflow guard. The XPG strerror_r alias is the pure
    // message formatter behind std::io::Error display.
    const GLIBC_THREAD_AND_ERROR_HELPERS: &[&str] = &["pthread_getattr_np", "xpg_strerror_r"];

    symbol.starts_with("ITM_")
        || ERRNO.contains(&symbol)
        || STARTUP_AND_TLS_GLUE.contains(&symbol)
        || CLONE_TABLE_GLUE.contains(&symbol)
        || FIXED_PROCESS_METADATA.contains(&symbol)
        || BACKTRACE_IMAGE_GLUE.contains(&symbol)
        || PROCESS_LOCAL_MEMORY.contains(&symbol)
        || BYTE_ORDER.contains(&symbol)
        || GLIBC_THREAD_AND_ERROR_HELPERS.contains(&symbol)
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
    // Environment mutation/reads; the deterministic environment is empty and
    // immutable.
    const ENVIRONMENT: &[&str] = &["getenv", "setenv", "unsetenv", "putenv"];
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
    classified.or_else(|| is_macos_framework_symbol(symbol).then_some("macos-framework"))
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
                write!(f, "unsupported native imports:")?;
                for import in imports {
                    write!(f, " {} ({})", import.symbol, import.category)?;
                }
                Ok(())
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
        // unknown-import), and a real classification always wins.
        assert_eq!(native_escape_category("close"), Some("filesystem"));
        assert_eq!(native_escape_category("secure_getenv"), None);
        assert_eq!(
            aarch64_instruction_category(0xd400_0001),
            Some("direct-syscall")
        );
        assert_eq!(
            aarch64_instruction_category(0xd53b_e040),
            Some("cpu-nondeterminism")
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
        let trappable = NativeEscape {
            symbol: "instruction@.text+0x42".into(),
            category: "direct-syscall",
        };
        assert!(native_escape_is_sud_manageable(&trappable));
        let by_name = NativeEscape {
            symbol: "syscall".into(),
            category: "direct-syscall",
        };
        assert!(!native_escape_is_sud_manageable(&by_name));
        let register_read = NativeEscape {
            symbol: "instruction@.text+0x42".into(),
            category: "cpu-nondeterminism",
        };
        assert!(!native_escape_is_sud_manageable(&register_read));
    }

    #[test]
    fn vsyscall_reference_scan_detects_the_page_and_refuses_it() {
        // A `movabs rax, 0xffffffffff600000` (48 b8 <imm64>) — materializing the
        // vsyscall gettimeofday entry — is caught by the immediate signal.
        let mut text = vec![0x48u8, 0xb8];
        text.extend_from_slice(&0xffffffffff600000u64.to_le_bytes());
        let mut escapes = Vec::new();
        scan_vsyscall_references(&text, ".text", &mut escapes);
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
        scan_vsyscall_references(&text2, ".text", &mut escapes2);
        assert_eq!(escapes2.len(), 1, "vsyscall time entry must be found");

        // RED control: ordinary text (including a nearby-but-not-on-page address)
        // yields no finding — the detector is not a blanket 0xff... matcher.
        let mut clean = vec![0x48u8, 0xb8];
        clean.extend_from_slice(&0xffffffffff700000u64.to_le_bytes()); // wrong page
        clean.extend_from_slice(&[0x90; 16]); // nops
        let mut none = Vec::new();
        scan_vsyscall_references(&clean, ".text", &mut none);
        assert!(none.is_empty(), "off-page address must not match: {none:?}");
    }

    #[test]
    fn sud_marker_detection_fails_closed_on_unparseable_input() {
        // A malformed binary must never be treated as SUD-capable: the marker
        // check is a downgrade precondition, so parse failure ⇒ error, not false.
        assert!(native_binary_has_sud_marker(b"not an object file").is_err());
    }

    #[test]
    fn custom_global_allocator_detection_fails_closed_on_unparseable_input() {
        // The custom-global-allocator gate refuses a class that DEADLOCKS pre-main,
        // so an input it cannot parse must be an error (the caller refuses), never
        // a silent `false` that would let a foreign/corrupt binary skip the check.
        // (Positive/negative discrimination on real Mach-O/ELF binaries is covered
        // end-to-end by cargo-patina's `native_run_and_audit_refuse_a_custom_global_allocator`.)
        assert!(native_binary_installs_custom_global_allocator(b"not an object file").is_err());
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
            let scan = scan_forbidden_instructions(&parsed);
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
            let scan = scan_forbidden_instructions(&parsed);
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
}
