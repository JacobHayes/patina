# Arc: shrinking the native C shim

Status: design complete; environment, entropy and memory adapters are Rust, 2026-10-06.
Focused evidence below is separate from the full landing battery.

## Decision and inventory

Move ordinary ABI adapters and state to Rust. Keep small C frames where their
absence of Rust cleanup/ownership is part of the contract. This changes
implementation ownership of existing surface, not supported operations
([scope](../SCOPE.md)). It supersedes the previous arc's blanket retention of
the stdio engine and host-resolution vehicles.

Counts below are the pre-spike physical lines in `c/posix/`: **8,379** total.
“All” includes every function, static, typedef, macro and conditional definition
in that file. Split files use the exhaustive exceptions below; every item not
listed as Stay C is Move to Rust. `stdio` is a separate evaluation with the
result **Move to Rust**, not an unclassified remainder.

| File | Lines | Decision, mechanism | Main risk to preserve |
|---|---:|---|---|
| fs.c | 1,441 | Move all: fixed open/fortify adapters, directories, metadata, paths, xattrs, timestamps; platform `libc` types or asserted `repr(C)` layouts | stat/stat64/dirent differences, padding, uaccess, directory ownership |
| init.c | 1,325 | Split: Rust startup, host resolution, auxv/maps parser, trap decoding and assembly; C callback frames below | startup ordering, signal stacks, nonlocal returns |
| darwin.c | 707 | Move all: Mach/sysctl/identity adapters, globals, generated framework/introspection refusals | Darwin sizes, symbol spellings and two-level bindings |
| stdio.c | 701 | Move all: Rust stream engine and sentinels, private libc formatter | buffering/error/lock behavior, VaList ABI |
| signal_process.c | 632 | Move all: signal/process adapters, spawn refusals, TLS diagnostics, exit door | reserved signals, delivery-before-errno, existing callback restrictions |
| fd_io.c | 607 | Move all: descriptor/vector/terminal/PTY adapters and fortify entries | pointer ranges, promoted widths, cancellation refusals |
| net.c | 564 | Move all: socket adapters, resolver/interface lists and their storage | sockaddr/addrinfo/ifaddrs layouts, allocator ownership |
| sched_identity.c | 399 | Move all: identity, resource/clock adapters, passwd state and limits | target widths, model identity, no host fallback |
| thread_sync.c | 355 | Split: Rust sync adapters and once state; C unwind sandwiches below | guest callback/cleanup lifetime |
| env.c | 349 | **Moved in spike**: `src/posix_env.rs`, private bridges to remaining C | initial stack, borrowed strings, teardown lock |
| readiness.c | 327 | Move all: poll/select/epoll/kqueue and fortify adapters | packed epoll fields, fd sets, deadline/mask ordering |
| time.c | 267 | Split: Rust calculation and conversion; C cancellation and clock stores below | guest fault ownership, remaining time and errno |
| core.c | 261 | Split: Rust error/deny/fortify/lock helpers and four ZSTD hook definitions; C cancellation glue below | early fatal recursion, nested ownership |
| dlsym.c | 169 | Split: Rust route table, `__wrap_dlsym`, dlerror TLS; same-object aliases stay beside residual C definitions | pointer identity, private resolver, no host answer |
| privileged.c | 118 | Move all: typed dispatch adapters | signed word conversion, refusal names |
| mem.c | 91 | Move all: raw-result/errno adapters over existing Rust model | allocator bootstrap, no allocation/host recursion |
| entropy.c | 66 | Move all: fixed exports and internal implementations | Darwin private identities, deterministic bytes |
| patina_posix.c | generated | Stay C: generated include-only translation unit for the retained C seams; Rust build data already owns its generation | extraction and shared internal linkage |
| include/patina_native.h | 1,258 | Generate from Rust ABI definitions; no handwritten duplicate contracts | cfg, constants, callback types, guest/internal separation |

### Exact split boundaries

Each row classifies the named function as a whole; “reduce” means its eventual C
body calls Rust preparation/completion helpers, with those Rust calls finished
before invoking anything that can leave nonlocally. Linux-only exceptions do
not retain their Darwin definitions.

| File / function or machinery | Decision | Concrete reason / mechanism |
|---|---|---|
| core: `patina_exit_thread`, `patina_act_on_cancel`, `PATINA_CANCEL_ENTER`, `PATINA_CANCEL_LEAVE` | Stay C | Invoke host pthread_exit only after model calls return; glibc forced unwind crosses these frames. |
| core: everything else, including `PATINA_CANCEL_POINT`, `patina_internal_lock/unlock`, `fail_int/size`, `patina_at`, `signal_result`, `patina_posix_deny`, `patina_fortify_fail`, `patina_chk_fail` | Move | Typed private helpers; pending cancellation refusal does not unwind. Retain only includes/prototypes required to compile C seams. |
| thread_sync (Linux): `patina_thread_body`, `pthread_exit`, `pthread_cancel`, `pthread_setcancelstate`, `pthread_setcanceltype`, `pthread_testcancel` | Stay C, reduce | Start routine or an acting cancellation can force-unwind these frames; Rust model calls must already have returned. |
| thread_sync (Linux): `pthread_once` | Stay C, reduce | Owns the cleanup record across `init_routine`; guest pthread_exit/cancellation resets the once state during unwinding. |
| thread_sync: `patina_once_reset`, once registry/state/locking, all remaining functions and Darwin variants | Move | Rust state machine and returning cleanup callback; keep cleanup record storage and guest invocation in the Linux C caller. Darwin exit/cancel retains its current refusal contract. |
| time (Linux): `nanosleep`, `clock_nanosleep`, `sleep` | Stay C, reduce | Acting cancellation surrounds a Rust sleep call. Keep only entry/leave and final result handling in C. |
| time (Linux): `patina_vdso_store`, `patina_clock_gettime_libc`, `clock_gettime`, `__clock_gettime`, `clock_getres` | Stay C, reduce | vDSO-compatible stores intentionally fault outside shim ownership. A live Rust export guard would turn the caller's SIGSEGV into a shim fault; a handler can also siglongjmp over that store. Keep outer/store seam; move clock decisions/calculation. |
| time: `time`, `patina_gettimeofday`, `gettimeofday`, `__gettimeofday` (where defined) | Stay C, reduce | These also store into caller memory after Rust model calls return. Preserve their outside-scope fault/handler behavior; move clock calculation. Extend the existing libc-fault detector before shrinking these seams. |
| time: `patina_nanosleep`, `localtime_r`, `patina_timeval_from_nanos`, Darwin clock/sleep variants | Move | Shared model calls plus target libc field conversion under their valid-buffer contracts. No acting cancellation in the private sleep calculation. |
| init (Linux): `patina_main_wrapper`, `__libc_start_main` | Stay C, reduce | Main wrapper holds glibc cleanup record across guest main. Keep the host start-main invocation in C too: do not rely on an optimizer tail call to remove a guarded Rust frame. |
| init (Linux): `patina_fault_front`, `patina_tsc_sigsegv`, `patina_guest_signal`, `patina_run_guest_handler`, `patina_tsc_take_real_fault` | Stay C, reduce | Guest/displaced signal handlers can siglongjmp or restore context. Keep their frame/canary storage and callback sandwich; move routing, decode and bookkeeping into returning Rust helpers. |
| init: `patina_fault_stop` | Stay C | Emergency path reached from those C frames uses only pre-resolved host calls. A named exported Rust bridge must enter PanicScope, touching TLS/panic state on a path that must avoid both; retain the direct call rather than adding a separate unguarded callback channel. Do not add a guard exception. |
| dlsym: `PATINA_ROUTE_ALIAS` expansions for retained C definitions | Stay C, generated | GNU alias targets must be in the same translation unit. Emit only residual C aliases after their definitions in the umbrella; do not alias a C definition from a Rust object. |
| dlsym: `patina_dlsym_route`, `patina_dlerror_set`, `__wrap_dlsym`, `dlerror`, TLS storage, table/entry generation and all other macros | Move | Rust-generated route table references hidden aliases; generate Rust assembly aliases beside Rust definitions and typed extern references to remaining C aliases. |
| init: all remaining functions, data and machinery | Move | Includes `patina_main_exited`, cleanup resolver/push/pop helpers, SUD decode/arming, TSC/front setup, auxv/maps parser, constructor/finalizer, host aliases and stack-switch assembly. Keep helper calls returning before C invokes guests; never move a guest callback into the helper. |

This is a **frame-lifetime** decision, not a claim that Rust cannot express
foreign unwinding. The [Rust Reference](https://doc.rust-lang.org/reference/items/functions.html#unwinding)
permits ordinary foreign unwinds through the appropriate `C-unwind` boundary,
but explicitly excludes forced unwind from that table.
[RFC 2945](https://github.com/rust-lang/rfcs/blob/main/text/2945-c-unwind-abi.md#frame-deallocation-and-forced-unwinding)
distinguishes plain-old-frames (POFs) from frames with observable cleanup:
non-POF deallocation is undefined; its POF case is not a blanket safety promise.
A live `PanicScope` has observable Drop behavior and is non-POF. Neither spelling
`C-unwind` nor suspending ownership removes that destructor. Keep these tiny
C frames instead of weakening the export rule. Existing signal-delivery
restrictions (including pthread_exit from a delivered handler) remain in force.

## Shared machinery and invariants

- **One C translation unit.** The umbrella is generated by `build_support.rs`,
  not a tracked source file. Internal-linkage helpers currently cross slices.
  The required C system includes/prototypes stay with the residual seams;
  Rust callers use target bindings. Move a helper with its users where possible; otherwise introduce one hidden,
  guarded fixed Rust bridge, declared in internal C glue. Delete the old body.
  Once both users are Rust, use module visibility rather than an ABI bridge.
- **Extraction and link order.** Preserve the guest-only `patina_posix_exports`
  cfg, `POSIX_RUST_FLAGS`, single codegen unit and unique
  `patina_variadic_link` anchor. The anchor's name stays until its eventual
  atomic rename across all callers; do not add a second anchor. A private C
  constructor reference extracts the Rust object even after libc/libSystem has
  satisfied public references. If the constructor moves, keep an explicit
  linker-undefined anchor root: `#[used]` alone does not extract an archive
  member. Verify debug/optimized ELF and Mach-O links; no whole-archive shortcut.
- **Aliases and dynamic lookup.** A C alias cannot target another object.
  Moved definitions carry Rust `global_asm!` hidden `patina_route_*` aliases;
  generated routing uses declarations for them. Retained C definitions keep
  same-translation-unit aliases, referenced by the eventual Rust table. The
  spike extends the existing Rust-alias path. Guest lookup remains registry-only; host lookup uses Linux
  `__real_dlsym` with the existing `--wrap=dlsym`, or Darwin's private resolver.
  Function pointers retain exact signatures, including variadics.
- **Host aliases.** Shim internals reach host effects through the private
  resolved table, never public interposable names. Calls to shim implementations
  use module paths/hidden aliases. Pure memory/string operations and the libc
  allocator keep their existing contracts; do not route guest-owned allocations
  through a guest Rust global allocator. Fortify `__*_chk` definitions need no C:
  guard, validate sizes/modes, call a private implementation, preserve fatal behavior.
- **Sections/platforms.** Constructor/destructor tables are Rust `#[used]`
  statics with `#[unsafe(link_section = ".init_array.00101")]` on ELF (preserving
  today's priority 101 and the priority-99 pre-init refusal probe),
  `.fini_array` for destructor tables, and Mach-O `__DATA,__mod_init_func`/`__mod_term_func`, preserving ordering.
  Darwin interposition tuples are expressible as `repr(C)` pointer pairs in
  `__DATA,__interpose` with `#[used]`. There is no such table in today's C;
  do not introduce it just to port strong exports. Two-level libSystem internal
  bindings remain outside the linked-guest interposition claim. Keep private
  aliases and test real Mach-O guest links, not Linux approximations.
- **Layouts.** Prefer existing target `libc` definitions. Where absent, use
  explicit `repr(C)`/packed target types with Rust size/alignment/offset asserts
  paired with C `_Static_assert` against system headers on each target. This
  includes stat/stat64, dirent, sockaddr, epoll and Darwin Mach/CRT structures.
  Write fields without reading uninitialized padding; preserve uaccess rather
  than making references to untrusted guest buffers. Opaque pthread objects are
  address keys, not new Rust-owned mutexes. The initial stack remains raw storage.
- **Guards.** Every exported Rust function, including a private C bridge,
  starts with `let _panic_scope = crate::panic_boundary::PanicScope::enter();`.
  `scripts/structure/` enforces entry and reserved-binding lifetime; no macro
  exports, exceptions or early guard consumption. Ordinary cancellation refusal
  checks follow the guard and precede decoding. Regenerate their structural
  rules as each cancellation door moves.

| Panic strategy / hook | Required outcome |
|---|---|
| unwind / installed shim hook | Private host SIGABRT, incomplete trace |
| unwind / guest replacement | Owned scope aborts on unwind; same result |
| abort / installed shim hook | Hook private-aborts; no reliance on Drop |
| abort / guest replacement | Owned abort boundary contains std abort; same result |

Guest callback panics retain their existing guest ownership contract; forced
unwind is not a Rust panic to catch. Extend compiled failpoint coverage for each
new boundary family, using the existing matrix and class-level export/registry
checks, never patched source. The environment spike adds no new panic mechanism;
its new guards are structurally checked and the existing matrix is rerun.

## stdio: move the engine, retain libc formatting

`stdio.c` has no C-language requirement. Keep Patina's stream semantics and
translate its state machine to Rust; do not implement a second formatter.
Resolve a **private host vsnprintf** before use, with the exact signature
`unsafe extern "C" fn(*mut c_char, usize, *const c_char, VaList<'_>) -> c_int`.
The pinned compiler's [VaList contract](https://doc.rust-lang.org/stable/core/ffi/struct.VaList.html)
provides platform ABI compatibility, clone as va_copy and Drop as va_end.

Clone before the first 512-byte stack-buffer pass; if the result requires heap
storage, use the unconsumed clone for the second pass. Preserve negative returns,
ENOMEM, errno (including `%m`), and current `%n`/two-pass behavior. The host
formatter receives only a byte buffer, format and VaList, **never** a modeled
FILE pointer. Neither host vfprintf nor the public interposed printf family is
an internal vehicle. This retains the existing libc locale/formatting dependency;
it does not establish a new determinism claim about ambient locale/extensions.

Move sentinel globals (`stdout`/`stderr`, Darwin `__stdoutp`/`__stderrp`), stream
buffers, recursive scheduler locks, put/overflow/flush/error logic, all fixed
writers/fortify entries and the registered flush/salvage callbacks together.
Sentinels are identity tokens, not libc FILE objects to dereference. Preserve
buffer sizes and caller-buffer borrowing, descriptor redirection, staged writes,
partial failures, errno preservation and lock-free teardown. Remove
`patina_format_bridge` once the variadic doors call the Rust engine privately.
Acceptance must cover short/long formatting, promoted integer/pointer/floating
arguments, repeat/replay, stream failure/teardown, aliases and the panic matrix
on Linux and macOS. This engine port is recommended, not part of the spike.

## Header: one Rust ABI source

Generate `patina_native.h` with pinned **cbindgen**, from an explicit Rust ABI
export set, rather than writing a new partial Rust parser. Its
[configuration](https://github.com/mozilla/cbindgen/blob/main/docs.md) supports
C layout types, renames and cfg-to-preprocessor mappings. Consolidate ABI types,
constants and callback aliases where needed; generation must consume the actual
signatures, not another handwritten schema. Keep names and signedness unchanged.

Separate the guest header from generated internal POSIX bridge declarations;
keep only C-owned cleanup/frame declarations handwritten in the small internal
header. Exclude guest-only ambient libc exports from the prefixed guest ABI.
Map Linux/Darwin and arch cfgs explicitly; cover function-pointer nullability,
noreturn returns, integer constants, comments and C++ extern guards. Ordinary
C headers already declare platform libc APIs; do not regenerate those layouts
into the guest header.

Generate into OUT_DIR and compare byte-for-byte with the checked-in distributable
header; fail on drift, never rewrite the checkout during a consumer build.
Stage/embed exactly that generated artifact for cargo-patina and packaging.
Compile C and C++ consumers and layout/signature assertions on all three ABIs;
plant a changed Rust signature/constant in generator fixtures to prove drift
fails. Replace Rust-to-Rust redeclarations with typed module calls where possible.
Generator compatibility with Rust 1.99 syntax/cfgs must be demonstrated before
switching the build. The current header is unchanged by this spike.

## Waves and expected C remainder

1. **Foundation (spike now):** environment ownership, hidden bridges and routes,
   archive ownership proof. Next establish generated ABI headers/layout checks.
2. **Ordinary adapters:** entropy, memory, privileged, scheduler/identity,
   fd I/O, readiness, network, filesystem and signal/process adapters. Carry
   fixed fortify entries and shared error helpers with their callers; preserve
   cancellation refusal and fault-ownership distinctions.
3. **stdio and platform glue:** complete stream engine/private formatter,
   Darwin adapters/globals, dlsym routes/TLS. Split Rust modules by concern,
   keeping every new file below 1,500 lines.
4. **Startup and lifecycle:** constructor/finalizer and host aliases, auxv/maps,
   SUD/TSC decode and assembly, once state and clock calculation. Reduce C to
   the exact cancellation, callback, emergency-fatal and clock-store seams above.
   Re-run cancellation, cleanup, signal-stack/nonlocal-return, fault, startup,
   panic and native acceptance suites after each boundary changes.

Expected end state: **400–650 physical C implementation/glue lines**, including
minimal includes/comments and the generated umbrella, versus 8,379 today before
the spike (about 92–95% less). This is an estimate, not a code-size target worth
weakening safety for. The generated public header remains roughly its current
size and is counted separately; generation removes duplicate authorship, not
the C guest ABI. No ordinary formatter, errno adapter, resolver or host-alias
vehicle stays C merely because it started there.

## Spike evidence

The whole `env.c` implementation moved to `src/posix_env.rs`; staging no longer
includes it. A private guarded setter replaces init.c's direct assignment to
the saved host envp. Existing constructor and localtime callers use hidden Rust
bridges. The module uses CRT accessors on Darwin, a native-word auxv walk on
Linux, libc allocation for C-compatible ownership, raw guest pointers, and the
same scheduler mutex/teardown policy. No host environment fallback was added.

| Check | Linux x86_64 | macOS arm64 |
|---|---|---|
| `cargo test -p cargo-patina --test native_abi` | 45 passed | 27 passed |
| `cargo test -p cargo-patina --test native_containment` | 40 passed | 18 passed |
| `cargo test -p cargo-patina --test end_to_end native_env` | 4 passed | 4 passed |
| Existing debug/unwind and optimized/abort nm matrix | Six environment spellings: one strong Rust definition each, none C; hidden routes share address/object | Four applicable spellings: one strong Rust definition each, none C |

A separate nm pass over the Linux conformance archive and C object also
verifies all six private environment bridges: one strong Rust definition each,
none C.
The macOS runs used the supplied remote mac-test helper against this workspace.
The guest tests cover environment/putenv aliasing, startup stack and capacity
refusals, host canaries, repeat/replay, deferred initialization, and Linux
teardown. The existing variadic panic/mutation matrix passes on both platforms.

Guest-export-enabled clippy passes with warnings denied on host,
`aarch64-unknown-linux-gnu` and `aarch64-apple-darwin`:
`cargo clippy -p patina-dst-native-shim --lib [--target TARGET] -- --cfg=patina_posix_exports -D warnings`.
Cross-clippy is compilation evidence, not Linux arm64 execution.
`scripts/check-structure.sh` passes including its detector fixtures; shim library
unit tests pass (302), as do syscall registry (9) and host-alias checks (5).
`mise run smoke` passes (WASI validation, the native suites, three ecosystem
testbeds, and Linux/WASI cross-target smoke). Focused `native_conformance`
`proc_environ` and `time_localtime` each pass on Ubuntu 24.04/glibc 2.39,
kernel 6.8: native comparison and Patina repeat/replay, not a report-only
foreign-host result. Formatting, file-size and CLI flag-drift gates pass.
All local Cargo/mise invocations use the required low-CPU wrapper and cache
scratch directory; `target` remains an mbx symlink. The spike leaves **8,038**
physical C lines (349 removed, eight private-bridge declaration/comment lines
added). The full landing battery is deliberately not run in this design round.

## Wave 2 ownership

`entropy.c` is now `src/posix/entropy.rs`, including the private Darwin lookup
entries. Shared `fail_int`/`fail_size` errno adapters are guarded hidden Rust
bridges while remaining C callers exist. The guest-export cfg and unique archive
anchor are unchanged.

`mem.c` is now the Linux-only `src/posix/memory.rs`. Pointer-valued raw
results retain the kernel failure range (-4095 through -1), and allocator
bootstrap continues through the existing private host memory model.

`privileged.c` is now `src/posix/privileged.rs`. The adapters retain signed
syscall-word conversions and reboot magic values. Shared `signal_result`
is a hidden guarded Rust bridge and delivers pending signals before errno.

`sched_identity.c` is now `src/posix/sched_identity.rs`, including passwd
iteration and resource-limit adapters. Darwin platform glue still uses its
physical-memory constant, declared beside the retained C headers.

`readiness.c` is now `src/posix/readiness.rs` and its platform modules, with platform reactors
and fixed fortify entries. Shared fortify failures are hidden guarded Rust
bridges; Darwin poll uses a private returning C sleep bridge until wave 4.
