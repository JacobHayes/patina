# Arc: C-variadic interposers in Rust

Status: design and uncommitted `fcntl`/`fcntl64` spike, 2026-10-06.
The remaining port is a later round. Rust 1.99 is already the workspace pin
and minimum version; this change does not raise either.

## 1. Decision

Move the **variadic entry points** to guarded, non-generic Rust `extern "C"`
functions. Retain fixed C adapters for platform structures and the modeled
stdio engine. Do not rewrite formatting or syscall models during this port.
The `syscall` machine entry is the exception: retain the restoration assembly,
introduce raw ABI argument capture, then enter a fixed-argument Rust dispatcher.

This changes implementation ownership, not the supported guest surface
([scope](../SCOPE.md)). A correct Rust `VaList` decoder must not reproduce a
C wrapper's unconditional read of arguments the caller did not supply.

| Question | Decision and code evidence |
|---|---|
| Scope | Port the listed ordinary variadic definitions, including printf wrappers. `stdio.c:patina_stream_vprintf` actually formats with **vsnprintf**, then writes through Patina streams; `vfprintf` is itself interposed. Forward into that modeled helper, never host vfprintf with sentinel `FILE*`. |
| Linkage | Keep strong public symbols; isolate Rust exports to the guest archive. `native_build.rs` passes POSIX object before staticlib and adds Linux libc again afterward. Add a unique C→Rust extraction anchor; do not rely on unresolved public names or whole-archive. |
| Panic/unwind | Every Rust export begins with `PanicScope::enter()`. Ordinary shim panics remain internal fatals. Preserve C frames through which acting pthread cancellation/exit unwinds; changing their language is a separate design. |
| Lints | Correct C ABI, variadic signature, return type and non-generic definitions are sanctioned; no blanket lint allowance. `open` is checked by the runtime-symbol lint; fcntl/printf are not in its current canonical list. |
| Registry/gates/bundle | Existing fcntl rows retain platform, syscall association and `Partial` status. Judge combined C+Rust definitions, reject duplicate public definitions, preserve hidden dlsym routes. The source bundle recursively includes new Rust files automatically. |
| Host aliases | Call existing private model entries or hidden fixed adapters. Any actual host function goes through the existing resolved host table; never `libc::fcntl`, `libc::open`, public vfprintf, or another public interposer. |
| Platforms | Execute Linux x86_64 and macOS arm64; cross-clippy Linux arm64. Darwin stack varargs require genuinely variadic declarations on both ends. Cross-clippy is not arm64 Linux runtime evidence. |

## 2. Link contract

Current shape: `c/patina_posix.c` includes its family slices as **one translation
unit**. Static helpers are shared inside it; `shim_build.rs` stages the sources
and compiles one `patina_posix.o`. C alias attributes can only alias definitions
in that translation unit. Moving just the definition breaks those aliases.

Spike shape:

- `src/variadic.rs` defines `fcntl`, Linux `fcntl64`, and the unique
  `patina_variadic_link` anchor. The C constructor references the anchor, forcing
  archive extraction even when an earlier libc/libSystem has supplied fcntl.
- Guest-only compilation uses `cargo rustc --lib` with `POSIX_RUST_FLAGS`:
  `--cfg=patina_posix_exports`, `-Ccodegen-units=1`. One codegen unit makes the
  anchor, function definitions and assembly aliases share an object. This is an
  explicit build invariant, not an assumption about rustc's partitioner.
- Linux hidden `patina_route_fcntl`/`patina_route_fcntl64` aliases are assembled
  beside the Rust definitions. `dlsym.c` declares these external hidden entries
  in its existing assembly-alias group; its C alias macro no longer defines them.
- The runner's dependency rlib, shim unit tests and bare prefixed-ABI archives
  omit the private cfg. A Cargo feature would unify into the runner and allow
  all-features builds to interpose their own host operations. Tests keep POSIX
  and prefixed archives in different build directories.
- No public fcntl definition is weak. Existing weak bootstrap hooks
  (`patina_sud_arm_thread`, `patina_tsc_arm_thread`, resolver hooks) retain their
  separate override contract. Duplicate public definitions are a gate failure.
- No whole-archive/force-load switch is needed. Applying it to the full Rust
  archive would also force bundled std/dependency objects into the guest link.
- Darwin's main image/static guest calls resolve to the extracted definitions;
  libSystem's internal calls keep their two-level bindings. This port does not
  claim dyld interposition inside libSystem ([Apple namespace documentation][apple]).

The single-codegen-unit requirement can affect build time. Before removing it,
replace the extraction/alias mechanism with an equally explicit invariant and
prove debug/release symbol identity on both object formats. Do not remove the
anchor because a particular guest happens to pull the same member indirectly.

## 3. ABI and panic contract

`VaList::next_arg` reads the promoted type; cloning performs va_copy and Drop
performs va_end. Never rebuild a list from integer slots or cast a variadic
function to a fixed signature. In the spike, fcntl64 shares the decoder rather
than forwarding an opaque pointer-sized value back through public fcntl.
Queries, unknown commands and named refusals consume no unused arguments.

| ABI | Relevant detail |
|---|---|
| Linux x86_64 | VaList accounts for register-save and overflow areas; pointer arguments must remain pointers. Linux mode_t is unsigned int. |
| Linux aarch64 | AAPCS64 has its own register-save/stack layout; use VaList, never the Darwin layout. Linux mode_t is unsigned int. |
| macOS arm64 | Anonymous arguments go on the stack. Darwin's 16-bit mode_t promotes to **int**, so read c_int and then convert; reading mode_t directly is wrong. |

`panic_boundary.rs` installs the hook at POSIX startup and tracks ownership
with TLS. The old C fcntl called guarded Rust model entries; the new outer guard
also owns argument decoding. With panic=unwind the hook private-aborts; if a
guest replaces it, the owned guard's Drop private-aborts during unwinding.
With panic=abort no Drop is promised: the hook handles normal cases, and the
Linux abort boundary recognizes an owned panic after hook replacement. Darwin
then aborts through libc. All cases must leave an incomplete trace.

`core.c:patina_exit_thread`, `thread_sync.c`'s guest start trampoline and
`init.c`'s cleanup-record notes deliberately keep glibc forced unwind outside
Rust frames. `fcntl` only calls `PATINA_CANCEL_POINT`: pending cancellation
**refuses by name**, never calls the acting-cancellation path. Keeping its fixed
adapter preserves this under both panic strategies. Do not port an acting
cancellation frame to plain Rust C ABI, or assume C-unwind alone fixes callback
ownership and cleanup ([Rust unwind contract][unwind]).

Rust 1.98's deny-by-default `invalid_runtime_symbol_definitions` validates known
runtime symbols; 1.99's [implementation][runtime-lint] checks ABI, variadicness,
arity and return shape, with finer type checks in the suspicious-symbol lint.
Use `#[unsafe(no_mangle)] unsafe extern "C" fn open(path: *const c_char,
flags: c_int, args: ...) -> c_int`, not a Rust-ABI function or a blanket allow.
`no_mangle_generic_items` became a **hard error in 1.99** ([release notes][release]);
C-variadic does not mean Rust-generic. Standalone probes compiled the correct
open/fcntl/printf signatures with warnings denied and rejected both a wrong
open signature and a generic unmangled fcntl.

## 4. Ordered remaining port

| Order | Functions | Retained helper / principal risk |
|---|---|---|
| 0 — spike | fcntl, fcntl64 | Rust owns both variadic definitions and one decoder. Hidden fixed `patina_fcntl_impl` retains flags, errno, record-lock translation and command-dependent cancellation refusals. No C variadic definition remains. |
| 1 | mremap | Keep mapping model; resolve optional fifth-argument rules against libc/kernel before porting. Current C reads it for FIXED **or DONTUNMAP**; do not assume that overread is a valid contract. |
| 2 | open, openat, open64, openat64, __open, __open64 | Retain fixed openat/path adapter initially. Correct promoted mode, O_CREAT/O_TMPFILE arity, fortify aliases and cancellation names. Do not recreate aliases by calling public open. |
| 3 | ioctl | Classify each modeled request's pointer, scalar or absent payload; current unconditional pointer fetch is not a safe Rust template. Preserve kernel request-width truncation. |
| 4 | ptrace | Request-specific argument presence and pid promotion; preserve PEEK's returned word, errno clearing and signal-delivery order. |
| 5 | prctl | Option-specific arity and unsigned-long widths; replace the current unconditional four-word read, retaining the one SUD dispatcher and signal-result adapter. |
| 6 | printf, fprintf, patina_stream_printf | Add a hidden fixed VaList-taking bridge to `patina_stream_vprintf`. Preserve va_copy for sizing/formatting, heap fallback, stream locking, errno and captured output. No host-vfprintf alias. |
| 7 | patina_libc_syscall | Retain rt_sigreturn's guest-SP assembly tail path and introduce raw ABI argument capture (today assembly tail-jumps into the C decoder). Replace the C six-word read with architecture-specific assembly capture feeding an explicit fixed Rust machine-word entry; do not port unconditional next_arg six times. |

What stays C: the umbrella and unrelated interposers; platform layout adapters;
modeled FILE/stream machinery and its vsnprintf use; host-resolution vehicles;
thread-start/cleanup/acting-cancellation frames. Assembly remains for raw syscall
capture and guest-stack restoration. Each later wave must exercise optional,
scalar and pointer arguments on all claimed platforms, with symbol and
panic-boundary checks before deleting its C definition.

## 5. Gate changes and spike evidence

- `symbols.rs`: language-neutral inventory; no invented language field or new
  syscall row. `syscall_registry` accepts registered Rust exports, rejects
  duplicate C/Rust public definitions and duplicate unmangled Rust definitions.
  A planted duplicate fcntl fails the detector; weak prefixed overrides remain.
- Cancellation gate follows fcntl/fcntl64 into the fixed adapter. C calls prove
  both names still refuse pending cancellation. Existing dlsym-list lint covers
  the assembly-alias group; runtime pointer equality checks the aliases.
- Keep the incoming ast-grep boundary rule broad enough for **all** exported
  Rust functions, including unprefixed variadic names. The old patina-prefix
  source scan alone does not cover these doors.
- `cargo-patina/build.rs` recursively embeds `src/variadic.rs`, updated C and
  the build script; no filename list edit is required. Rebuild cargo-patina.
  All archive builders use the same exported `POSIX_RUST_FLAGS` recipe.
- `native_abi::variadic` uses a compiled-in planted-faults hook, not mutated
  production source. It checks original/replaced hooks under unwind/abort and
  requires SIGABRT with an unloadable trace. Its C guest checks F_SETFD/F_GETFD,
  F_GETFL, F_DUPFD, record-lock pointers, fcntl64 and dlsym address identity.

Observed targeted evidence (full landing battery deliberately not run):

| Check | Result |
|---|---|
| Existing native e2e record-lock guest | Linux x86_64 and macOS arm64 pass; repeat/record/replay assertions retained. |
| Existing Linux native_raw fcntl tests | Both status-flag and record-lock libc/raw parity pass. |
| Existing POSIX descriptor guest | Linux pass. |
| Variadic C argument/alias/cancellation probe | Linux pass; macOS argument probe pass. |
| Real fcntl-frame panic matrix | Linux and macOS: unwind/abort × original/replaced hook pass. |
| Registry / host-alias / source-route gates | Linux 10 / 5 / 2 tests pass; macOS registry 9 tests pass. |
| Clippy, actual variadic module enabled, warnings denied | Host x86_64 Linux, aarch64 Linux, aarch64 Darwin pass. |
| nm of debug and opt-level=3 guest staticlibs plus POSIX object | Exactly one strong Rust fcntl and fcntl64; zero C definitions; Linux route aliases present. Runtime test checks address identity. |
| rustc signature probes | Correct exports compile; invalid open and generic unmangled export fail. |
| Formatting / file-size / doc flag-drift gates | Pass. |

Logs and standalone probes are in the requested
`/cache/jacobhayes/patina-syscall-arc/cvariadic-astra/` scratch directory.
macOS execution uses the supplied `mac-test` helper. Linux arm64 execution,
remaining entry points, and the full landing gate remain later-round evidence.

[apple]: https://developer.apple.com/library/archive/documentation/Porting/Conceptual/PortingUnix/compiling/compiling.html
[unwind]: https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding
[runtime-lint]: https://github.com/rust-lang/rust/blob/1.99.0/compiler/rustc_lint/src/runtime_symbols.rs
[release]: https://github.com/rust-lang/rust/releases/tag/1.99.0

## Port evidence

The mremap door and its errno adapter are Rust-owned. Only MREMAP_FIXED
consumes the optional destination: DONTUNMAP without FIXED lets the kernel
choose the address. Its C guest exercises both absent forms and fixed placement.
The explicitly armed test-panic hook supports boundary panic and payload mutation
without patching product source. Linux-only doors retain their platform scope;
Darwin checks their absence through the registry while running the common doors.

The alternate daybreak diff was evaluated: its global_asm aliases and the
Linux C routing table can extract the defining member (a 16-codegen-unit
Linux debug probe also retains both fcntl symbols). It supplies no equivalent
private extraction reference on Darwin, where the routing table has only the
entropy pair. An earlier library satisfying the public name therefore removes
the reason to extract that archive member. Nor does global_asm itself enforce
co-location with definitions after module/codegen partition changes. Retain the
explicit anchor plus one-codegen-unit contract. The acceptance matrix inspects
native Rust object members with nm in debug and opt-level=3 builds on ELF and
Mach-O; extracting those members avoids Apple nm's inability to parse newer
LLVM bitcode bundled in Rust's standard library.

The fcntl fixed adapter is also Rust-owned: libc's platform flock layouts are
expressible directly, and no shared C helper requires the adapter to stay.
Status flags, errno and record-lock translation move together. Guest record
memory uses the existing uaccess boundary, with field-only writes on GETLK.
The cancellation rule now follows the Rust export and its waiting-command check.

All six open doors and the shared fixed flag/mode adapter are Rust-owned.
Linux reads an unsigned mode; Darwin reads the promoted int. Creation and
O_TMPFILE require the operand (O_TMPFILE remains the existing ENOSYS refusal).
The glibc internal aliases now share cancellation refusal with public opens;
the cancellation inventory and generated Rust entry rules cover every spelling.
Creat and fortify wrappers call the fixed Rust adapter; C retains its shared
fortify-stop helper and no duplicate open flag translation.

The ioctl door is Rust-owned. It truncates Linux requests before classifying
operands, distinguishes explicit integer and pointer operations (rather than
inferring types from IOC encoding), and reads nothing for absent or refused
payloads. The generic and terminal guests cover both the common descriptor
operations and Linux's scalar terminal requests.

Ptrace's Linux door and errno/PEEK-result adapter are Rust-owned. TRACEME reads
nothing; ATTACH reads only pid; SEIZE reads its address/options; PEEK retains
its local output word and never reads an unused caller data argument. Signal
delivery still precedes libc errno conversion. The existing model refuses
PEEK with ESRCH because no process is traced; no successful tracing is claimed.

Prctl's Linux door consumes option-specific unsigned-long or pointer arguments.
Options whose reserved words are part of the contract retain those reads;
queries and refused options consume nothing unused. SECCOMP consumes a filter
pointer only in filter mode. The shared SUD model and signal-before-errno order
are retained, including the existing signal-result adapter's error conversion.

Printf, fprintf and the internal assertion formatter now enter guarded Rust
variadic doors and pass a platform VaList into a hidden fixed C bridge. C owns
the sentinel FILE layouts, stream locks/buffering and vsnprintf engine, including
va_copy and heap fallback. The internal formatter takes a FILE sentinel instead
of exposing the C-only stream layout. No host vfprintf is called.

Syscall now captures all six machine words in architecture assembly owned by
Rust, then enters a guarded fixed Rust dispatcher. There is no C or Rust
six-item VaList read. The guest-SP sigreturn branch and its libc layout adapter
move together; the raw-trap C handler calls that same guarded adapter.

The ioctl scalar category distinguishes promoted int terminal operands from the
full unsigned-long INOTIFY_IOC_SETNEXTWD value. Its high bits reach the existing
model's range check; a compiled guest reproduces EINVAL for 0x100000001UL and a
valid explicit watch id. A compiled width-narrowing failpoint must make the
same oversized-word semantic assertion fail with exit 40.
