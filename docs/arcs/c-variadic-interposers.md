# Arc: C-variadic interposers in Rust

Status: port implemented, 2026-10-06. Rust 1.99 remains the workspace pin and
minimum version. Focused acceptance and the full landing battery are distinct
validation tiers.

## Decision and ownership

The guest's ordinary variadic libc entries are guarded, non-generic Rust
`extern "C"` functions under `src/variadic/`. Their decoders consume only the
arguments required by the command, option or flags. Fixed adapters move with
the doors where Rust can express the flag, errno and platform layout contract
without depending on C-only machinery. This changes implementation ownership
within the existing supported guest surface ([scope](../SCOPE.md)); it does
not add models or relax refusals.

| Family | Rust ownership and argument contract |
|---|---|
| fcntl, fcntl64 | Both variadic doors, shared decoding, status-flag and errno translation, and platform flock conversion. Queries and refused commands consume no unused argument; setters consume promoted int; lock and owner queries preserve pointer types. GETLK uses the existing uaccess boundary and writes fields without reading caller padding. |
| mremap | Variadic door and errno adapter. Only MREMAP_FIXED consumes the optional destination. DONTUNMAP without FIXED does not supply a fifth argument. The mapping model remains shared with the raw-syscall door. |
| open, openat, open64, openat64, __open, __open64 | Six doors and the shared fixed flag/mode adapter. O_CREAT or all of O_TMPFILE requires a mode; other opens read none. O_TMPFILE retains its existing ENOSYS refusal. C creat and fortify wrappers use the Rust fixed adapter. |
| ioctl | Door and command-specific decoding. Linux request truncation precedes classification. The explicit request table distinguishes pointer, promoted int, unsigned-long and absent payloads; IOC bits do not infer a C argument type. |
| ptrace | Linux door and errno/PEEK-result adapter. TRACEME consumes nothing; ATTACH consumes pid; SEIZE consumes its address/options; PEEK uses a local result word and reads no unused data argument. Signal delivery precedes errno conversion. The current model refuses PEEK with ESRCH because no process is traced. |
| prctl | Linux door and option-specific pointer/unsigned-long decoding. Required reserved words remain part of the contract. SECCOMP reads a filter pointer only in filter mode. Queries and refused options consume nothing unused. The existing SUD model and signal-before-errno ordering remain shared. |
| printf, fprintf, patina_stream_printf | Variadic doors pass their FILE*/format and VaList through a fixed C bridge. The modeled C stream engine owns formatting, buffering and captured writes. |
| syscall | Linux architecture-specific raw capture and guest-SP restoration assembly reside in the Rust module. A fixed Rust entry receives raw machine words and reaches the shared dispatcher. The guest sigreturn layout adapter is Rust-owned too. There is no C six-word variadic decoder. |

At the end of this port the C stdio engine remains: its `vsnprintf` formatting, `va_copy` sizing
pass, heap fallback, stream locks and private FILE state form one implementation.
Reimplementing printf formatting in Rust would add a second formatter.
The follow-on [C reduction arc](c-to-rust.md) instead moves the stream engine
to Rust while retaining libc formatting through a private vsnprintf alias. The
bridge reaches `patina_stream_vprintf`, never host `vfprintf` with a modeled
FILE pointer. Internal-linkage helpers shared by code that remains C stay with
that engine and the existing fortify wrappers.

Acting cancellation, thread-exit and cleanup frames remain C because glibc
forced unwind crosses them. Host-resolution vehicles retain their private host
bindings. The umbrella and unrelated C interposers are outside this port. No
ported flag, errno or flock adapter remains in C merely because it used to be
next to a variadic definition.

## Archive extraction and route aliases

`c/patina_posix.c` includes its C slices as one translation unit. A C alias
attribute cannot name a definition in a Rust object. Migrated Linux dlsym
routes therefore refer to hidden `patina_route_<name>` assembly aliases beside
the Rust definitions, rather than cross-object C aliases.

The guest archive uses the common `POSIX_RUST_FLAGS` recipe:
`--cfg=patina_posix_exports` and `-Ccodegen-units=1`. The unique
`patina_variadic_link` anchor, public definitions and assembly aliases share
one object by construction. The C constructor's private unresolved reference
extracts that object even when an earlier libc/libSystem already supplied the
public spelling. Public definitions stay strong. No whole-archive link is
needed, and unrelated bundled std/dependency members are not forced in.

Dependency rlibs, shim unit tests and bare prefixed-ABI archives omit the
private cfg. A Cargo feature is unsuitable for this isolation: feature
unification or an all-features build could interpose the runner's host calls.
POSIX and prefixed acceptance archives use separate build directories. The
source bundle embeds the new Rust modules recursively.

The alternate daybreak design was evaluated. Its hidden aliases and Linux C
dlsym table can extract the corresponding Rust member; a Linux debug probe with
16 codegen units retained both fcntl spellings. That result is insufficient to
remove the single-codegen-unit invariant. The alternative supplies no equivalent
private extraction reference on Darwin, whose routing table contains only the
entropy pair. If an earlier library resolves the public name, there is no
remaining reason to extract that member. In addition, global_asm alone does not
guarantee co-location after future module or codegen partition changes.

The anchor plus one-codegen-unit contract therefore remains. Removing it needs
an equally explicit extraction mechanism and debug/optimized evidence on both
ELF and Mach-O. Darwin coverage concerns calls from the linked guest; libSystem
internal two-level bindings are not claimed to be interposed. One codegen unit
may affect build time; it is a deliberate correctness constraint.

## ABI, panic and cancellation contracts

`VaList::next_arg` reads the promoted C type. Cloning performs va_copy and Drop
performs va_end. Ordinary doors do not reconstruct lists from integer slots,
cast variadic functions to fixed signatures or forward opaque pointer-sized
values back through public interposers. Aliases share private decoders.

| ABI | Argument detail |
|---|---|
| Linux x86_64 | VaList accounts for register-save and overflow areas; pointers remain pointers. Linux mode_t is unsigned int. |
| Linux aarch64 | VaList follows the Linux register-save/stack ABI, not Darwin's. Linux mode_t is unsigned int. |
| macOS arm64 | Anonymous arguments are stack-passed. Darwin's 16-bit mode_t promotes to int; the decoder reads c_int and then converts. |

`syscall` is a machine-word ABI boundary, not an ordinary VaList decoder. Its
assembly captures the architecture's register/stack words without issuing six
Rust next_arg reads for a caller that supplied fewer operands. The fixed Rust
entry preserves shared syscall dispatch and errno/signal adaptation. The
rt_sigreturn path preserves the original guest stack pointer and resumes the
private host vehicle; it never replays a signal frame in the shim.

Every new exported Rust function begins with
`let _panic_scope = crate::panic_boundary::PanicScope::enter();`.
The scope owns decoding as well as the model call. With panic=unwind, the shim
hook private-aborts; if a guest replaces the hook, the owned scope aborts during
unwind. With panic=abort, no Drop is promised: the hook handles the original
case and the owned abort boundary contains the replaced-hook case. All panic
cases require host SIGABRT and an incomplete trace.

The fcntl waiting commands and all six open spellings check cancellation
immediately after entering that scope. Pending cancellation refuses by name;
these Rust frames never initiate glibc forced unwind. The shared cancellation
inventory includes the glibc internal open aliases. Compiled ABI guests exercise
pending cancellation at these doors; review checks the entry order. Acting
cancellation frames are not converted to Rust C ABI, and C-unwind is not used
as a substitute for proving callback and cleanup ownership.

The compiler checks known runtime-symbol signatures. Exports use the correct C
ABI, variadic signature, return type and non-generic definition without blanket
lint allowances. The static panic-scope rule checks explicit exports, with no
new exceptions; shared CLI variadic bindings have compiler-checked types.

## Acceptance and limits

`native_abi::variadic` compiles C guests for every argument category each family
uses: absent, promoted scalar, pointer and optional. Separate calls cover each
applicable spelling. The guests retain the existing model refusals and test
cancellation names and Linux dlsym pointer identity.

`variadic::matrix::every_variadic_family_contains_panics_and_detects_wrong_arguments`
uses the existing `test-panic` feature. A family/fault selector arms one
compiled-in fault after startup. Operand mutations select a wrong argument slot against a distinct caller-supplied
sentinel, or narrow the full unsigned-long INOTIFY_IOC_SETNEXTWD operand. Each
must fail the same semantic assertion whose control passed. The terminal-int
probe opens a TIOCGPTPEER peer with O_RDWR followed by an O_RDONLY sentinel,
then checks F_GETFL's access mode; shifted or zeroed flags change the result.
Every family also runs the unwind/abort ×
original/replaced-hook panic matrix. Tests exercise the compiled implementation;
there is no source patching or source-text assertion.

The same matrix inspects native shim archive members with nm in debug and
opt-level=3 builds. Every migrated spelling must have exactly one strong Rust
definition and zero C definitions. Linux aliases must share the definition's
object and address and have ELF STV_HIDDEN visibility. Native-member inspection
avoids Apple nm's inability to read the newer LLVM bitcode bundled in Rust std;
the final guest link separately exercises the full archive. The combined C/Rust
registry gate rejects unregistered or duplicate definitions and carries a
planted duplicate detector.

Linux x86_64 executes all families. macOS arm64 executes common
fcntl/open/ioctl/stdio families and verifies Linux-only mremap/ptrace/prctl/syscall
absence through the registry. Linux arm64 cross-clippy is compilation evidence;
this port supplies no Linux arm64 runtime claim. Focused end-of-port gates cover
host and both arm64 clippy targets, structural rules, shim library tests, native
ABI/raw/signal and registry targets, formatting, file size and CLI flag drift.
The coordinator runs the full landing battery separately.

These ABI tests do not extend a model's supported operations, prove libSystem
internal interposition or replace the wider syscall conformance suite. The
follow-on C reduction arc reclassifies the engine and host-resolution vehicles;
forced-unwind frames remain deliberate boundaries.
