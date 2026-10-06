//! Native symbol normalization, allowlists, and escape classification.

use crate::TargetError;
use object::BinaryFormat;
use std::collections::BTreeSet;

/// The category of a denied import that matches no named escape class.
pub(super) const UNKNOWN_IMPORT_CATEGORY: &str = "unknown-import";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeFormat {
    MachO,
    Elf,
}

impl NativeFormat {
    pub(super) fn from_binary(format: BinaryFormat) -> Result<Self, TargetError> {
        match format {
            BinaryFormat::MachO => Ok(Self::MachO),
            BinaryFormat::Elf => Ok(Self::Elf),
            _ => Err(TargetError::UnsupportedNativeFormat(format)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeImportDecision {
    Allowed,
    Denied(&'static str),
}

/// Whether the pre-run audit lets an ELF guest import `symbol` with no
/// `--allow`: an allowlisted known-safe import, rather than a refusal.
pub fn native_elf_import_allowed(symbol: &str) -> bool {
    native_import_decision(symbol, NativeFormat::Elf, &BTreeSet::new())
        == NativeImportDecision::Allowed
}

pub(super) fn native_import_decision(
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

/// Reduce a native import to its canonical name so alias forms such as Mach-O
/// underscore prefixes, glibc `__`-prefixed aliases, glibc C-standard generation
/// aliases, and Darwin `$NOCANCEL` variants are audited against the same
/// allowlist entry.
pub(super) fn normalize_native_symbol(symbol: &str) -> &str {
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
        // Substring and span searches over caller-owned NUL-terminated strings:
        // pure reads returning a pointer or a length, the same caller-memory
        // family as `strchr`/`strlen` (SQLite's LIKE/JSON/int parsers and
        // mimalloc's option parsing import them).
        "strcspn",
        "strspn",
        "strstr",
        // Numeric parse of a caller-owned NUL-terminated string into an integer,
        // optionally writing an end pointer back into caller memory. Pure
        // caller-memory read/compute with no boundary effect, same family as the
        // `strlen`/`strcmp` intrinsics above. Both Mach-O `_strtol` and ELF
        // `strtol` normalize onto this common entry. (`strtoul` and the other
        // radix/float parsers are deliberately NOT here — this is an exact list,
        // never a prefix, so an unlisted parser stays denied as `unknown-import`.)
        "strtol",
        // In-place sort of a caller-owned array through a caller-supplied
        // comparator: it reads and permutes only caller memory and takes no
        // boundary effect of its own. The comparator is guest code, which meets
        // the boundary on its own terms if it does anything effectful; the sort
        // ORDER for equal elements is implementation-defined but stable for one
        // libc build, and a run is always replayed against the same libc.
        "qsort",
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
    // `_pthread_cleanup_push`/`_pthread_cleanup_pop` link and unlink a
    // caller-owned cleanup record in the calling thread's chain, which glibc's
    // unwind runs when the thread exits (the exit itself is interposed).
    const PTHREAD_LOCAL_HELPERS: &[&str] = &[
        "pthread_attr_destroy",
        "pthread_attr_getguardsize",
        "pthread_attr_getstack",
        "pthread_attr_init",
        "pthread_attr_setstacksize",
        "pthread_cleanup_pop",
        "pthread_cleanup_push",
        "pthread_condattr_destroy",
        "pthread_condattr_init",
        "pthread_condattr_setclock",
        "pthread_equal",
        "pthread_getspecific",
        "pthread_key_create",
        "pthread_key_delete",
        "pthread_mutexattr_destroy",
        "pthread_mutexattr_init",
        "pthread_mutexattr_settype",
        "pthread_rwlockattr_destroy",
        "pthread_rwlockattr_init",
        "pthread_rwlockattr_setkind_np",
        "pthread_self",
        "pthread_setname_np",
        "pthread_setspecific",
    ];
    // Unwind/personality routines walk in-process frames or transfer control to
    // language runtimes; they do not perform host I/O, time, entropy, or waits.
    const UNWIND_AND_PERSONALITY: &[&str] = &["gxx_personality_v0", "rust_eh_personality"];
    // Signal registration is used by Rust's panic/stack-overflow diagnostics;
    // Patina does not deliver ambient host signals into guest execution, so
    // installation is deterministic; admitted delivery comes from faults or
    // the platform's modeled self-signal entry, never an allowed host raise.
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
    // builds a mask to hand to a registration call. Construction itself has
    // no delivery effect. The thread-mask *mutators*
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
    // cross-boundary effect. These entries now cover only a guest linked WITHOUT
    // the POSIX layer (the C-ABI staticlib mode): with it, the shim's strong
    // `mmap`/`mmap64`/`munmap` definitions take these names off the import table
    // entirely and model a mapping of a VIRTUAL descriptor as a file copy with
    // write-back, so the `MAP_SHARED` residual the coverage matrix used to record
    // is closed there rather than merely documented.
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
    // ld.so's restartable-sequence layout words (`__rseq_offset`, `__rseq_size`,
    // `__rseq_flags`): constants of the loaded glibc naming where each thread's
    // rseq area sits from the thread pointer. The area itself is the virtual
    // kernel's: the shim takes glibc's registration off the host at every
    // task's start, so what a guest reads through them is the virtual CPU,
    // never a host CPU id.
    const RSEQ_LAYOUT: &[&str] = &["rseq_offset", "rseq_size", "rseq_flags"];

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
        || RSEQ_LAYOUT.contains(&symbol)
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
        "mkdirat",
        "rmdir",
        "stat",
        "stat64",
        "statx",
        "lstat",
        "lstat64",
        "fstat",
        "fstat64",
        "fcntl",
        // The working directory and the umask are modeled process state in
        // the shim (one resolver serves every path row), so these are
        // shim-defined like the rest; classified for the same defense-in-depth
        // reason.
        "getcwd",
        "chdir",
        "fchdir",
        "umask",
        "realpath",
        "readlink",
        "readlinkat",
        "symlink",
        "symlinkat",
        "link",
        "linkat",
        "fdopendir",
        // Permission bits ARE modeled (a mode per entry, enforced against the
        // one non-root guest identity), so the chmod family is shim-defined
        // like everything above it; the names stay classified for the
        // defense-in-depth reason at the top of this function.
        "chmod",
        "fchmod",
        "fchmodat",
        // Named pipes ARE modeled (a FIFO entry in the deterministic
        // filesystem, opened onto the same in-process pipe machinery an
        // anonymous `pipe` uses), so the mkfifo/mknod family is shim-defined
        // too. `mknod` is interposed for its FIFO type only; every other type
        // it can name is refused there, not here.
        "mkfifo",
        "mkfifoat",
        "mknod",
        "mknodat",
        // Timestamps, ownership and sizes ARE modeled (a four-timestamp inode
        // model on the virtual clock, ownership as a comparison against the
        // one identity, sizes by name and by descriptor), so the utimensat,
        // chown, truncate and fallocate families are shim-defined too.
        "truncate",
        "truncate64",
        "chown",
        "fchown",
        "lchown",
        "fchownat",
        "utime",
        "utimes",
        "lutimes",
        "futimes",
        "futimesat",
        "utimensat",
        "futimens",
        "fallocate",
        "fallocate64",
        "posix_fallocate",
        "posix_fallocate64",
        // `acct(2)` turns on process accounting to a file — a privileged,
        // kernel-global effect (CAP_SYS_PACCT). The Linux shim defines it
        // (answered from the virtual credential: `EPERM`); on macOS it is not
        // interposed, so a reference there is a host filesystem escape and is
        // LABELED here. It is the planted filesystem representative of the
        // macOS gate-level e2e (`native_run_prerun_gate_refuses_every_escape_class`).
        "acct",
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
        "sendmmsg",
        "recv",
        "recvfrom",
        "recvmsg",
        "recvmmsg",
        "shutdown",
        "getaddrinfo",
        "getnameinfo",
        "gethostbyname",
        // Interface lookups (a host networking utility stack — hyper-util —
        // links `if_nametoindex` dormant). The shim answers them from the
        // virtual interface table; classified so a raw non-shim import reads as
        // `network` rather than a bare unknown import.
        "if_nametoindex",
        "getifaddrs",
        "freeifaddrs",
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
    // Environment reads and mutation. The native shim runs glibc's environment
    // functions over the process's own `environ`, which starts as the run's
    // deterministic startup map. An UNINTERPOSED member would reach the host
    // environment, so the whole family is classified.
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
    // *instructions* are caught separately by `scan_instruction_classes`.
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

#[cfg(test)]
mod tests;
