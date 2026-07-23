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
    const PROCESS_LOCAL_MEMORY: &[&str] = &["mprotect", "munmap"];
    symbol.starts_with("Unwind_")
        || ALLOCATOR.contains(&symbol)
        || MEMORY_AND_STRING.contains(&symbol)
        || TERMINATION.contains(&symbol)
        || STACK_PROTECTOR.contains(&symbol)
        || PTHREAD_LOCAL_HELPERS.contains(&symbol)
        || UNWIND_AND_PERSONALITY.contains(&symbol)
        || SIGNAL_DIAGNOSTICS.contains(&symbol)
        || ENVIRONMENT_STORAGE.contains(&symbol)
        || PROCESS_LOCAL_MEMORY.contains(&symbol)
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
    // Read-only stack-extent queries used by Rust's stack-overflow guard. The
    // control-plane thread vehicle (pthread_create_suspended_np, thread_resume,
    // dispatch semaphores) is deliberately NOT allowlisted here: those symbols
    // are the shim's own host mechanism and are `--allow`ed per audited binary
    // by the validation scripts, so an unmanaged binary importing them to
    // spawn or block outside the scheduler still fails the audit.
    const STACK_EXTENT_HELPERS: &[&str] = &["pthread_get_stackaddr_np", "pthread_get_stacksize_np"];
    // Returns a pointer to in-process environment storage; the shim scrubs the
    // storage at startup before guest code can observe it.
    const ENVIRONMENT_STORAGE: &[&str] = &["NSGetEnviron"];

    ERRNO.contains(&symbol)
        || STARTUP_AND_IMAGE_GLUE.contains(&symbol)
        || FINALIZERS.contains(&symbol)
        || PROCESS_LOCAL_MEMORY.contains(&symbol)
        || STACK_EXTENT_HELPERS.contains(&symbol)
        || ENVIRONMENT_STORAGE.contains(&symbol)
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

fn native_escape_category(symbol: &str) -> Option<&'static str> {
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
    const NETWORK_OR_WAIT: &[&str] = &[
        "socket",
        "bind",
        "listen",
        "accept",
        "connect",
        "send",
        "sendto",
        "recv",
        "recvfrom",
        "shutdown",
        "getaddrinfo",
        "poll",
        "ppoll",
        "select",
        "pselect",
        "epoll_wait",
        "kevent",
    ];
    const TIME_ENTROPY: &[&str] = &[
        "clock_gettime",
        "gettimeofday",
        "nanosleep",
        "clock_nanosleep",
        "usleep",
        "mach_absolute_time",
        "getentropy",
        "getrandom",
        "arc4random",
        "arc4random_buf",
        "CCRandomGenerateBytes",
        "SecRandomCopyBytes",
    ];
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
        "pause",
    ];
    const ENVIRONMENT: &[&str] = &["getenv", "setenv", "unsetenv", "putenv"];
    const DYNAMIC: &[&str] = &["dlopen", "dlsym", "dlclose"];
    const THREADING: &[&str] = &["pthread_create"];
    // Non-pthread blocking sync primitives. Patina manages threads through the
    // interposed pthread layer; if a future std lowered `Mutex`/`Condvar` to
    // these host primitives instead, a shim-linked binary would import them
    // unmanaged and must fail the audit rather than silently block a host thread
    // outside the scheduler. Normalized (leading underscores stripped) forms.
    const UNMANAGED_SYNC: &[&str] = &[
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
    ];
    const SYSCALL: &[&str] = &["syscall", "__syscall"];
    [
        (FILESYSTEM, "filesystem"),
        (NETWORK_OR_WAIT, "network-or-wait"),
        (TIME_ENTROPY, "time/entropy"),
        (PROCESS, "process"),
        (ENVIRONMENT, "environment"),
        (DYNAMIC, "dynamic-loading"),
        (THREADING, "unmanaged-thread"),
        (UNMANAGED_SYNC, "unmanaged-sync"),
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
        let unsupported = imports
            .iter()
            .filter(|import| {
                import.module != WASI_PREVIEW1_MODULE
                    || !SUPPORTED_PREVIEW1_IMPORTS.contains(&import.name.as_str())
            })
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
        assert_eq!(
            native_import_decision("_dispatch_semaphore_wait", NativeFormat::MachO, &empty),
            NativeImportDecision::Denied("unknown-import")
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
