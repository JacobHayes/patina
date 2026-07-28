//! Target metadata and fail-closed import auditing.

use std::collections::BTreeSet;
use std::fmt;

use object::{Architecture, BinaryFormat, Object, ObjectSection, SectionKind};
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
/// `sem_*` leave the guest import table there too. Its residue is two symbols:
/// `dlsym` (the resolution primitive) and `pthread_create` (the wrap-contained
/// managed thread-creation vehicle — guest calls bind to `__wrap_pthread_create`,
/// so allowing the name cannot escape, unlike the swept `sem_*`/`__read`).
///
/// The pre-run gate in `native-run` bakes this set in (a guest importing
/// anything else on the blocking/effect surface still fails closed), while
/// standalone `native-audit` keeps requiring explicit `--allow` so its
/// default-deny path stays provable.
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
        // as `__real_dlsym`. Every trace-fd and baton-semaphore vehicle is
        // resolved through it at runtime (`dlsym(RTLD_NEXT, ...)`), so `__read`/
        // `__write`/`sem_*` no longer appear in the guest import table; guest and
        // std `dlsym` references bind to the shim's neutering `__wrap_dlsym`.
        "dlsym",
        // Managed host-thread creation vehicle: the real import left behind by
        // `-Wl,--wrap=pthread_create`. It stays a named residue because it is
        // wrap-contained — guest `pthread_create` binds to the managed
        // `__wrap_pthread_create`, so allowing the name cannot grant an escape,
        // unlike the swept `sem_*`/`__read`/`__write` where the name *was* the
        // vehicle.
        "pthread_create",
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
    let mut escapes = Vec::new();
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let data = section.data().map_err(TargetError::NativeParse)?;
        let name = section.name().unwrap_or("<text>");
        match file.architecture() {
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
                for index in 0..data.len().saturating_sub(1) {
                    let category = x86_instruction_category(&data[index..]);
                    if let Some(category) = category {
                        escapes.push(NativeEscape {
                            symbol: format!("instruction@{name}+0x{index:x}"),
                            category,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(escapes)
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

fn x86_instruction_category(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x0f, 0x05]) {
        Some("direct-syscall")
    } else if bytes.starts_with(&[0x0f, 0x31])
        || (bytes.starts_with(&[0x0f, 0xc7])
            && bytes.get(2).is_some_and(|modrm| modrm & 0x38 == 0x30))
    {
        Some("cpu-nondeterminism")
    } else {
        None
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
    // `memset`/`memcpy` intrinsics but Darwin-only (ripgrep's `grep-matcher`
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
        "rename",
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
    // `kqueue` wait blocks the calling thread outside the scheduler.
    const WAIT_MULTIPLEX: &[&str] = &[
        "poll",
        "ppoll",
        "select",
        "pselect",
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
    [
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
    .find_map(|(symbols, category)| symbols.contains(&symbol).then_some(category))
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
        assert_eq!(native_escape_category("malloc"), None);
        assert_eq!(
            aarch64_instruction_category(0xd400_0001),
            Some("direct-syscall")
        );
        assert_eq!(
            aarch64_instruction_category(0xd53b_e040),
            Some("cpu-nondeterminism")
        );
        assert_eq!(
            x86_instruction_category(&[0x0f, 0x05]),
            Some("direct-syscall")
        );
        assert_eq!(
            x86_instruction_category(&[0x0f, 0x31]),
            Some("cpu-nondeterminism")
        );
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
    // audit-side half of the ripgrep allowance-removal pivot: the process-spawn
    // and host-state-query members of that binary's old allow list become
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
            // The Linux control plane is now two symbols: the `dlsym` resolution
            // primitive (reached through `-Wl,--wrap=dlsym` as `__real_dlsym`) and
            // the wrap-contained `pthread_create` thread-creation vehicle.
            for symbol in ["dlsym", "pthread_create"] {
                assert_eq!(
                    native_import_decision(symbol, NativeFormat::Elf, &allow),
                    NativeImportDecision::Allowed,
                    "vehicle symbol {symbol} should pass the baked control-plane set"
                );
            }
            // The former named vehicles were swept off the import table (the shim
            // resolves the real host `read`/`write`/`sem_*` through `dlsym` at
            // runtime), so a guest importing one is now DENIED rather than riding a
            // name-based allowance — the structural fix for the sem_* escape class.
            for symbol in ["sem_wait", "sem_post", "sem_init", "__read", "__write"] {
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
