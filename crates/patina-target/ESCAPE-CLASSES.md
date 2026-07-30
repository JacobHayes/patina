# Guest-escape classes and the detection gate's coverage

A "guest escape" is any path by which a guest running under Patina reaches host
behavior the deterministic runtime does not model — blocking a real thread,
reading host time or entropy, spawning a context, touching another address
space — thereby breaking determinism silently.

Detection is **symbol-reachability**: `cargo patina audit` (and the
`run` pre-run default-deny gate that reuses it) enumerate every
externally-resolved symbol the guest imports and refuse anything that is neither
**interposed** (defined by the shim, so it never appears as an import) nor
**known-safe** (an explicitly listed effect-free host-deferred symbol) nor
caller-`--allow`ed. Anything else fails closed; known host-effect names are
labeled with their escape *class* (below) for error quality. This is a
symbol-level gate by design — it does **not** disassemble the binary — so raw
inlined instructions and flag-dependent behavior are residuals covered (or
honestly not covered) elsewhere; see "Residual gaps".

The class lists live in `native_escape_category` (labeling) and the
interposed/allowlisted sets in `native_allowlisted_import` /
`shim_control_plane_symbols` (gating), all in `crates/patina-target/src/lib.rs`.

## Coverage matrix

| # | Escape class | Representative host symbols | How the deterministic runtime handles the supported surface | Detection mechanism | Permanent test |
|---|---|---|---|---|---|
| a | **Blocking / scheduling** | `os_unfair_lock_*`, `__ulock_wait/wake`, `__psynch_*`, `dispatch_semaphore_*`, mach `semaphore_wait/signal`, `os_sync_wait_on_address`; readiness: `poll`/`select`/`kqueue`/`kevent`/`epoll_*` | pthread mutex/cond, **`os_unfair_lock_*`** (macOS, lazily registered in the mutex table since the bare `u32` has no init call; misuse — recursive lock or foreign unlock — aborts loudly), the dispatch-semaphore Parker, and Linux futex are **interposed** and routed through `DetScheduler` (+ virtual clock for timed waits); `poll` is interposed for the modeled cases; **`kqueue`/`kevent`/`kevent64`** (macOS) are **interposed** by a deterministic in-process readiness reactor (EVFILT_READ/WRITE over virtual pipe/socketpair and SimNet socket fds, an EVFILT_USER Waker, EVFILT_TIMER on the virtual clock; multi-fd fan-in parks on the baton, deterministic `(ident, filter)` event order, no trace events of its own — unmodeled filters and readiness on real host descriptors fail closed loudly); **`epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_pwait`** (Linux) are **interposed** by the mirror frontend over the same readiness core (one interest per fd over the virtual pipe/socketpair, eventfd, and SimNet socket fds; EPOLLET latches keyed on per-direction *arrival sequences* so an edge re-fires per arrival exactly as the kernel does — mio's undrained eventfd Waker depends on it; millisecond timeouts on the virtual clock; deterministic fd-order events; kernel-faithful EEXIST/ENOENT from `epoll_ctl`; unmodeled event flags, non-NULL `epoll_pwait` sigmasks, and non-virtual descriptors fail closed loudly; the syscall-shaped `patina_epoll_*`/`patina_eventfd` entry points are ready for the future syscall-user-dispatch SIGSYS dispatcher) — so mio/tokio's IO driver runs under the scheduler on both platforms | symbol audit → `unmanaged-sync` / `wait-multiplex`; any uninterposed blocking symbol is an import → denied | `every_escape_class_is_detected_and_denied` (unit); `native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol` (Mach `semaphore_wait`, still uninterposed) + `validate-native-shim.sh` os_unfair_lock contention accepted & misuse aborts, plus the kqueue reactor legs (raw EVFILT_READ/USER/timeout, macOS) and the epoll reactor legs (raw EPOLLET partial-drain/re-arrival edge, eventfd wakeup, virtual-clock timeout, Linux) and a real tokio socketpair ping-pong on BOTH platforms, seed-stable and replay-identical (e2e) |
| b | **Time** | `clock_gettime`, `clock_gettime_nsec_np`, `gettimeofday`, `mach_absolute_time`, `mach_continuous_time`, `nanosleep`, `clock_nanosleep`, `usleep`, `mach_wait_until`; host-timezone conversion `localtime_r`, `tzset` | the clock reads/sleeps are all interposed → virtual clock (`clock_gettime_nsec_np` shares `clock_gettime`'s clock-id mapping, returning nanoseconds directly). `localtime_r`/`tzset` render a `time_t` through the host timezone database / `TZ` (cross-platform, e.g. the `time` crate's local-offset lookup), so they read where the run happens: **not interposed → refused**, classified `time` so the refusal names the host-timezone problem rather than a bare unknown import | symbol audit → `time` | `every_escape_class_is_detected_and_denied`; `classifies_ecosystem_audit_symbol_batch` (localtime_r/tzset on both formats); `validate-native-shim.sh` clock_gettime_nsec_np e2e |
| c | **Entropy** | `getentropy`, `getrandom`, `arc4random*`, `CCRandomGenerateBytes`, `SecRandomCopyBytes` | interposed → seeded RNG | symbol audit → `entropy` | `every_escape_class_is_detected_and_denied` |
| d | **Thread lifecycle** | `pthread_create`, `pthread_create_from_mach_thread_np`, `bsdthread_create`, `thread_create` | `pthread_create` is interposed by a strong def and spawns a managed task via a distinct non-interposed vehicle (macOS `pthread_create_suspended_np`; Linux the real glibc `pthread_create` resolved through `dlsym(RTLD_NEXT, ...)`) | symbol audit → `unmanaged-thread` | `every_escape_class_is_detected_and_denied`; `validate-native-shim.sh` escape-probe (`grep unmanaged-thread`) |
| e | **Process** | `fork`, `vfork`, `exec*`, `posix_spawn*`, `system`, `popen`, `kill`, `waitpid`, ... | **non-goal**, handled two ways. The subprocess-spawn family a real guest actually links (`fork`, `posix_spawnp`, `posix_spawn_file_actions_*`, `posix_spawnattr_*`, `execvp`, `waitpid`, `setsid`, `setgid`, `setuid`, `setpgid`, `setgroups`, `chdir`, `chroot` — a subprocess-spawning CLI guest via `std::process` plus a command-runner helper — plus `kill`, since signalling a process is the same non-goal) is **deny-trap interposed**: a strong shim def that `abort()`s deterministically with a diagnostic if ever reached. It drops off the import table (no allowance needed) AND a genuine spawn fails loud + reproducible instead of escaping silently — a reachability audit cannot clear these (they are statically wired, runtime-flag-dormant; see "Why symbol-reachability…"). The rest (`vfork`/`exec*`/`system`/`popen`/`killpg`/…), which no supported guest links, stay uninterposed and import-audited. | uninterposed members → symbol audit → `process`; interposed family → **runtime deny-trap** | `native_run_deny_trap_aborts_a_guest_that_actually_spawns` (a guest reaching `fork` aborts, naming it); `native_run_prerun_gate_refuses_every_escape_class` (`killpg`, uninterposed); `native_build_package_audits_records_and_fails_closed`; the audited CLI guest runs allowance-free |
| f | **Filesystem / network** | `open`/`openat`/`read`/`write`/`stat`/`fcntl`/`unlinkat`/`renameat`/...; `socket`/`bind`/`connect`/`send`/`recv`/... | interposed → deterministic FS and SimNet (the `*at` family models `AT_FDCWD` — a plain path — and fails closed on a real dirfd, since the deterministic FS is path-based) | symbol audit → `filesystem` / `network` | `every_escape_class_is_detected_and_denied`; `classifies_native_import_decisions`; `validate-native-shim.sh` openat/renameat/unlinkat e2e |
| g | **Shared memory / IPC** | in-process: `pipe`, `pipe2`, `socketpair`, `eventfd`/`eventfd2`; cross-process: `shm_open`, `shm_unlink`, `mach_msg*`, `mach_port_*`, `bootstrap_look_up`, `mq_*` | **split by whether the escape leaves the address space.** `pipe`/`pipe2`/`socketpair` — both endpoints live inside the one guest process (an async runtime's IO-driver / signal self-pipe wakeup), so there is no cross-address-space escape: they are **interposed** as deterministic in-memory byte channels (bounded 64 KiB buffers, EOF on peer close, `EPIPE` — never `SIGPIPE` — on a broken write, `O_NONBLOCK`/`EWOULDBLOCK` honored; `dup`/`F_DUPFD[_CLOEXEC]` alias an endpoint refcounted — std's `try_clone`, e.g. tokio's signal driver cloning a socketpair end — so EOF/`EPIPE` appear only once the LAST fd of a side closes) wired to the SAME scheduler baton / waiter machinery the virtual sockets use, so reads/writes are scheduler-visible and deterministic given the schedule (no trace events of their own — like the futex/mutex words). AF_UNIX/SOCK_STREAM only; other domains/types fail closed. `eventfd`/`eventfd2` (Linux, mio's Waker vehicle) joined the in-process slice: **interposed** as a deterministic 64-bit counter (read returns-and-resets, `EFD_SEMAPHORE` decrements, `EFD_NONBLOCK` → `EAGAIN` on zero reads, `EFD_CLOEXEC` a no-op; a write that would overflow fails closed loudly instead of modeling blocked writers) wired into the same readiness core so the epoll reactor watches it. The **cross-process** members (`shm_open`/`mach_*`/`mq_*`) genuinely reach another address space or the kernel and stay **refused**. | interposed members → not an import (strong def); cross-process members → symbol audit → `shared-memory-ipc` (still classified so a raw non-shim import reads as an escape) | `every_escape_class_is_detected_and_denied` (`shm_open`, `eventfd`); `validate-native-shim.sh` pipe/socketpair round-trip, EOF/EPIPE, `O_NONBLOCK`, and dup-alias legs, the eventfd wakeup leg (Linux) + the still-refused `shm_open` sibling (both platforms) |
| h | **Signals / timers** | `setitimer`, `timer_create/settime`, `alarm`, `ualarm`, `sigsuspend`, `sigwait`, `sigtimedwait`, `pause` | not modeled → refused. (`sigaction`/`signal`/`sigaltstack` *registration* stays allowlisted for non-SIGSYS signals — Patina delivers no ambient signals — but timer-arming and signal-waiting are escapes. **SIGSYS is the exception**: under SUD the SIGSYS handler IS the deterministic containment, so on Linux `sigaction`/`signal` are interposed by strong defs that forward every other signal to the real glibc registration and **refuse SIGSYS loudly** — a guest may not re-register the dispatch handler. The raw door, a trapped `rt_sigaction(SIGSYS)`, is fatal in the SUD dispatch table.) The refusal splits by *why*: signal *delivery*/waiting is principled — ambient host signals would perturb the schedule — but timer-*arming* (`timer_settime`, `setitimer`) is merely not-yet-built: a virtual-clock-driven timer (fire at deterministic virtual time N, the same clock behind `nanosleep` and the reactors' `EVFILT_TIMER`/`epoll_wait` timeouts) is in-model and a deliberate roadmap item, not a never | symbol audit → `signals-timers` | `every_escape_class_is_detected_and_denied` |
| — | **Environment** | `getenv`, `setenv`, `unsetenv`, `putenv` | interposed → empty, immutable deterministic environment | symbol audit → `environment` | `every_escape_class_is_detected_and_denied` |
| — | **Dynamic loading** | `dlopen`, `dlsym`, `dlclose` | `dlopen`/`dlclose` refused. `dlsym`: **Linux** interposed to resolve nothing (deterministic NULL for any guest call). **macOS** it is the shim's own host-alias resolution primitive (`dlsym(RTLD_NEXT, ...)`), so it is baked into `shim_control_plane_symbols` and tolerated as control-plane — see the honest-residual note below | symbol audit → `dynamic-loading` (Linux: also interposed) | `every_escape_class_is_detected_and_denied` |
| — | **Direct syscall (by name)** | `syscall`, `__syscall` | Linux `syscall` interposed (FUTEX routed, else fail-closed). Raw *inline* syscall instructions have no symbol and are refused by the instruction scan; `cargo patina build` injects `--cfg rustix_use_libc` so the most common emitter (rustix's default Linux backend) compiles to interposable libc imports instead. | symbol audit → `direct-syscall`; instruction scan → `instruction@…` findings | `every_escape_class_is_detected_and_denied` |
| — | **Direct syscall (raw inline instruction, SUD-managed)** | `syscall`/`svc` opcodes emitted inline (rustix's default linux_raw backend, hand-written asm) | **Linux syscall-user-dispatch (SUD), slice 1, x86_64.** The shim arms `PR_SET_SYSCALL_USER_DISPATCH` (allowed region = glibc's executable segment, NULL selector) at `__libc_start_main` and in every managed thread's trampoline, installs a `SIGSYS` handler, and scrubs `AT_SYSINFO_EHDR` from the auxv (so vDSO-resolving crates fall back to trappable raw syscalls). A trapped syscall is decoded and routed into the same `patina_*` entry points the C interposers use (clock/futex/read/write/openat/close/lseek/getrandom/sched_yield/gettid/exit; mmap-family anon pass-through; `set_robust_list`/`rseq`/`membarrier` → ENOSYS; everything else → named fatal abort). The audit **downgrades** a `direct-syscall` *instruction* finding from refuse → run **iff** (a) the binary defines the `patina_sud_dispatch` marker AND (b) a live `prctl` probe says the kernel has SUD (x86_64 ≥ 5.11); it is reported relabeled `direct-syscall (SUD-managed)`, never silent. No-SUD kernel (notably arm64) or no marker ⇒ today's refusal, with a hint pointing at `--cfg rustix_use_libc` / x86_64. `cpu-nondeterminism` register reads are NOT SUD-manageable and still refuse. | instruction scan → `instruction@…` finding, downgraded to `direct-syscall (SUD-managed)` when marker + kernel probe pass | `validate-native-shim.sh` SUD legs (raw-syscall probe SUD-managed + seed-stable + record/replay on x86_64; refusal + hint on no-SUD arm64; unmapped-syscall named abort; auxv canary; marker-gating; SIGSYS-hijack) |
| — | **Host-state query** | `isatty`, `gethostname`, `getpwuid_r`, `__NSGetExecutablePath`, `issetugid`; Linux: `sched_getcpu`, `sched_setaffinity`, `pthread_getname_np`, `pthread_sigmask` | interposed → fixed deterministic values so guest output cannot depend on where, on which core, or as whom, it ran. `isatty` → "not a terminal" (returns 0, `errno = ENOTTY`); `gethostname` → the constant `"patina"`; `getpwuid_r` → deterministic "no such user" (`*result = NULL`, returns 0 — the guest environment is emptied so std's home-dir lookup cleanly `None`s); `__NSGetExecutablePath` → fails so `current_exe()` is a deterministic `Err` rather than leaking the host path (a future guest needing `current_exe() → Ok` should get a fixed *virtual* path, never the host's); `issetugid` → 0 (never a set-id binary). Linux glibc, reached by a custom global allocator's init: `sched_getcpu` → 0 (the live CPU id is host-scheduling nondeterminism; pinning it makes per-CPU arena selection deterministic — distinct from the pure `__sched_cpucount`/`CPU_COUNT` popcount, which is allowlisted); `sched_setaffinity` → deterministic no-op success (affinity is inert under the single-baton scheduler); `pthread_getname_np` → a fixed empty name; `pthread_sigmask` → forwarded to the real mask op with SIGSYS **stripped** from any block/setmask set, so a guest can never disarm the SUD SIGSYS dispatcher (parity with the `sigaction(SIGSYS)` hardening). All are strong C defs, so none appears as an import. | not an import (strong def) | `validate-native-shim.sh` (linked guests query `isatty`); `classifies_linux_jemalloc_audit_surface` (unit — `sched_getcpu` stays denied for a non-shim binary, not confused with the pure `__sched_cpucount`); the Linux tikv-jemallocator MRE audits clean and runs deterministically |
| — | **Stack-growth probe (macOS)** | `___chkstk_darwin` | **known-safe.** A compiler-inserted probe that touches successive stack guard pages before a large frame (an allocator's init frames reach it). Pure caller-stack access, no boundary effect, value-free deterministic outcome (return, or a genuine stack-overflow death exactly as native). | import audit → allowlisted | `classifies_known_native_escape_symbols` region / the tikv-jemallocator MRE audits clean |
| — | **Host-state registration** | `pthread_atfork` (fork-handler registration pulled in by Rust std / libc thread & once machinery — e.g. a multi-thread guest) | interposed → **no-op returning 0**: the registration is ignored. Sound because the entire fork/exec process class (row **e**) is a deterministic-runtime non-goal the audit denies, so a registered handler could never run; the call has no boundary effect. A strong C definition binds the guest reference and the libc symbol drops off the import table, so the pre-run gate has nothing to flag and the run's determinism claim is unqualified. Being shim-defined, it never appears as an import. | not an import (strong def) | a multi-thread guest under `run-patina.sh` links it and runs allowance-free |
| — | **Positional file I/O** | `pread`, `pwrite` (a guest's `read_exact_at`/`write_all_at`; the offset-loop `libc::pread`/`libc::pwrite`) | interposed → `patina_p{read,write}` → the runtime's `fs_read_at`/`fs_write_at`, serviced as **one** positional driver operation (`FsDriver::read_at`/`write_at`) that saves, seeks, reads/writes, and restores the cursor **within a single driver call** — atomic w.r.t. the scheduler, so it is cursor-independent even when threads share the fd. A caller-side seek+read emulation would be unsound under preemption; this reaches the driver as one op instead. `write_at` counts toward the `--fs-crash-at write:N` ordinal and is crash-losable exactly like a cursor write; `read_at` fires no crash. Being shim-defined, neither appears as an import. | not an import (strong def) | `patina-dst-abi` tag/offset pins; `patina-dst-fs-crash::positional_write_is_crash_losable_exactly_like_a_cursor_write` |
| — | **Advisory file lock** | `flock` (a guest's whole-file `File::try_lock` / `try_lock_shared` on open) | interposed → **per-inode lock table** (`patina_flock`). The lock is keyed on the descriptor's deterministic-fs inode (from the recorded fd-metadata path, so it reconstructs identically under replay), and conflicts are resolved against that identity: `LOCK_EX` conflicts with any lock held on another descriptor of the same file, `LOCK_SH` only with a held `LOCK_EX`. A lone opener always acquires (a single `LOCK_EX\|LOCK_NB` on open), but a *second* open of the same path contends faithfully — `LOCK_NB` reports `EWOULDBLOCK`, exactly the path a single-opener database guest surfaces as an "already open" error. The lock clears on `LOCK_UN` and on `close` (deterministic fd numbers are never reused, so no stale entry survives). Simplifications, sound for the supported surface: a *blocking* request that would contend fails closed with `EDEADLK` rather than parking a real thread (the single-baton scheduler does not model advisory-lock waiting, and std's `File::try_lock*` is always `LOCK_NB`); dup'd descriptors are tracked independently rather than sharing one open-file-description lock. Being shim-defined, `flock` never appears as an import. | not an import (strong def) | `native_flock_contends_on_a_second_open_and_releases_on_close` (e2e: second open → `EWOULDBLOCK`, close releases) |
| — | **Host introspection (macOS Mach/BSD/IOKit)** | `sysctl`/`sysctlbyname`, `getrusage`, `task_info`, `mach_task_self_`, `mach_host_self`, `host_statistics64`, `host_processor_info`, `vm_page_size`, `vm_deallocate`, `proc_listallpids`/`proc_pidinfo`/`proc_pid_rusage`/`proc_pidpath`; IOKit `IOServiceMatching`/`IOServiceGetMatchingServices`/`IOIteratorNext`/`IOObjectRelease`/`IORegistryEntryCreateCFProperty`/`IORegistryEntryGetName` — the `sysinfo` / `num_cpus` / hardware-inventory surface | **split by whether a normal startup reaches the symbol** (generalizing the process-spawn deny-trap doctrine, row e). The **dormant** hardware-inventory surface a `sysinfo`/`num_cpus` guest LINKS but a scenario need not reach — `host_statistics64`/`host_processor_info`, `mach_host_self`, `proc_listallpids`/`proc_pidinfo`/`proc_pid_rusage`/`proc_pidpath`, `vm_deallocate`, the whole IOKit registry walk (`IOServiceMatching`/`IOServiceGetMatchingServices`/`IOIteratorNext`/`IOObjectRelease`/`IORegistryEntryCreateCFProperty`/`IORegistryEntryGetName`), plus the data symbols `mach_task_self_`/`vm_page_size`/`kIOMasterPortDefault` (fixed deterministic values — a data read cannot be trapped) — is now **deny-trap interposed** (macOS): a strong shim def binds each reference at link so it drops off the import table (the pre-run gate passes when the path is dormant) and `abort()`s deterministically naming the symbol at first call. Only the **live-path** members a normal startup actually reaches — `sysctl`/`sysctlbyname`/`getrusage`/`task_info` — stay uninterposed and **refused** pre-run (a strong def would silently swallow a path startup uses; a deterministic interposer is a tier-3 item). Both read host CPU/memory/hardware/process state — nondeterministic across hosts and runs: **interpose-or-refuse, never allowlist.** Classification is unchanged and stays load-bearing: `host-introspection` (the exact Mach/BSD name list plus the IOKit prefixes `IOService`/`IORegistry`/`IOIterator`/`IOObject` — deliberately not a bare `IO`) labels a raw import from a **prebuilt non-shim binary**, which links no shim so nothing drops off — it always refuses. Fail-closed either way. | enumerated members → not an import (deny-trap) → **runtime abort**; live-path members / prebuilt-raw → import audit → `host-introspection` | `native_run_deny_trap_aborts_a_guest_that_reaches_host_introspection` (macOS e2e — a guest reaching `IOServiceMatching` aborts, naming it, byte-identical across runs) + `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (a dormant `sysinfo`-shaped path runs allowance-free); `classifies_ecosystem_audit_symbol_batch` (unit — representative Mach/BSD/IOKit sample classifies; `sysctlbyname` stays denied; a user `IOWidget` does NOT match; `IO`-prefix overreach guarded); the sysinfo MRE now audits to only its live-path residual (`sysctl`/`sysctlbyname`) |
| — | **macOS system frameworks (CoreFoundation / Security)** | `CFArrayCreate`/`CFStringGetLength`/`CFDataGetBytePtr`/`kCFAllocatorDefault`/`kCFTypeArrayCallBacks`; `SecCertificateCopyData`/`SecTrustSettingsCopyCertificates`/`SecCopyErrorMessageString` — the `rustls-native-certs` / `security-framework` / `chrono`-timezone / native TLS trust-root surface | **enumerated dormant symbols deny-trap at call time; the remainder refuse pre-run** (generalizing the process-spawn deny-trap doctrine, row e). The enumerated dormant surface — the CoreFoundation helpers (`CFArray*`/`CFString*`/`CFData*`/`CFTimeZone*`/`CFRetain`/`CFRelease`/`CFEqual`/`CFNumberGetValue`/`CFDictionaryGetValueIfPresent`/`CFGetTypeID`), the Security readers (`SecTrustSettingsCopy*`/`SecCertificateCopyData`/`SecCopyErrorMessageString`), plus the data symbols `kCFAllocatorDefault`/`kCFAllocatorNull`/`kCFTypeArrayCallBacks` (fixed values — a data read cannot be trapped) — is now **deny-trap interposed** (macOS): a strong shim def binds each reference at link so a binary that merely LINKS the optional TLS-trust / timezone path RUNS (the symbol drops off the import table), and a genuine call `abort()`s deterministically naming the symbol. Any **non-enumerated** `CF*`/`kCF*`/`Sec*`/`kSec*` symbol, and every framework symbol in a **prebuilt non-shim binary** (which links no shim), stays **refused** pre-run. The Security readers touch the host keychain / system trust store — mutable per-machine, per-time host state — so a run reaching one is not reproducible; the CoreFoundation helpers are the plumbing those calls require. Classification is unchanged and stays load-bearing: `macos-framework` (Apple-reserved prefixes `CF`/`kCF`/`Sec`/`kSec`) labels the still-refused remainder with a determinism note naming the host-trust-store problem and the `--allow-unsupported-symbols` allow path (qualified determinism). Fail-closed either way. | enumerated members → not an import (deny-trap) → **runtime abort**; remainder / prebuilt-raw → import audit → `macos-framework` | `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (macOS e2e — a dormant `rustls-native-certs`-shaped path with `SecTrustSettingsCopyCertificates`+`CFRelease`+`IOServiceMatching` runs allowance-free); `native_gate_classifies_and_refuses_a_security_framework_symbol` (macOS e2e — a non-enumerated `SecTrustEvaluateWithError` still refuses with note + audit/run parity); `classifies_known_native_escape_symbols` (unit — the certs surface classifies); the chrono MRE now audits CLEAN and the certs MRE runs allowance-free |

Beyond the per-class classifier unit test (`every_escape_class_is_detected_and_denied`),
the batched end-to-end test `native_run_prerun_gate_refuses_every_escape_class`
(cargo-patina `tests/end_to_end.rs`) builds one guest that reaches an
uninterposed symbol of each plantable class and asserts `native-run` refuses it
pre-exec with every class label present — so no class's end-to-end gate path can
rot silently. (`environment` and `unmanaged-thread` have no plantable
shim-linked member; see the table's residual column.)

Interposed-and-supported surfaces never appear as imports (they are *defined* by
the shim), so they are automatically not flagged — this includes `setsockopt`
`SO_RCVTIMEO`, `sched_yield`, the dispatch-semaphore Parker, positional
`pread`/`pwrite`, the advisory `flock`, and the whole FS/time/entropy/pthread
surface.

Two pure, effect-free symbols surfaced by the ecosystem audit sweep are
**known-safe allowlist** additions (they clear with no `--allow`, exactly like
`memcpy`/`strlen`):

- **`__cxa_atexit`** (macOS finalizer registrar, Mach-O `___cxa_atexit`) — a
  process-local destructor registration in the same family as `atexit` /
  `__tlv_atexit`, mirroring the ELF `cxa_atexit` entry the shim already
  allowlists. Registration only records a callback in process-local storage; no
  boundary effect. A C custom allocator's static init reaches it.
- **`strtol`** (Mach-O `_strtol` / ELF `strtol`) — a pure caller-memory numeric
  parse, same family as the `memcmp`/`strlen` memory-and-string intrinsics.
  Exact list, never a prefix: the sibling `strtoul` is deliberately **not**
  added and stays denied as `unknown-import`.

Both are covered by `classifies_ecosystem_audit_symbol_batch`.

## Why symbol-reachability, not static call-graph reachability

The gate audits the guest's *flat undefined-import list*. A natural refinement
is to make it call-graph-aware — clear a flagged import if no path from an
entrypoint reaches it — so that a binary which merely *links* an escape symbol
without a live path to it need not carry an allowance. We investigated this
against a real-world file-walking CLI we audited (its old allow list named 27
subprocess-spawn and host-query symbols) and rejected it: a **sound** call-graph
pass clears **zero** of them, so the refinement is all cost and no benefit. Two
independent reasons, each verified on the built guest (arm64 Mach-O), documented
so nobody re-attempts the static pass without new information:

1. **The dormant code is statically wired.** the guest's subprocess spawn is
   reachable from the Rust entry by **direct calls alone** — an unbroken `bl`
   chain from `main` through the search worker and a command-reader builder into
   `std::process::Command::spawn`, whose unix `spawn` ends in `bl _fork` /
   `bl _posix_spawnp`. Every edge is a direct branch. Only a **runtime flag**
   selects the subprocess path at run time, and static reachability cannot prove a
   flag is never set. These symbols are *runtime*-unreachable for a plain search,
   not *statically* unreachable.
2. **Sound indirect-call handling swallows the whole program.** A conservative
   analysis must treat any reachable indirect call (function pointer, trait
   object vtable) as potentially reaching **any** address-taken function. In a
   Rust binary `main` itself is address-taken — it is handed to `lang_start` as a
   function pointer — so the moment the closure admits one indirect call (every
   real binary has many), the entire live call graph reachable from `main`
   becomes reachable, spawn path included. Tightening the address-taken
   heuristic does not help: the direct-call chain in (1) already reaches spawn.

The consequence is that "cleared by unreachability" would be a fiction here.
The honest dispositions are per-symbol and stay at the symbol level:

- **Process-spawn family** (`fork`, `posix_spawn*`, `execvp`, `waitpid`,
  `setsid`/`setgid`/`setuid`/`setpgid`/`setgroups`, `chdir`, `chroot`, and
  `kill`) —
  **deny-trap interposition**: a strong shim C definition that aborts
  deterministically with a diagnostic if ever reached. The process class is a
  deterministic-runtime non-goal, so a guest that genuinely spawns must fail
  loudly and reproducibly, never escape silently. Being shim-*defined*, these
  drop off the import table, so the audit needs no allowance for them — and the
  run gains a *runtime* guarantee the old allow list never had (see row **e**).
- **Dormant framework / host-introspection families** (the enumerated
  `rustls-native-certs` CoreFoundation/Security surface, the `chrono` timezone
  `CFTimeZone*` surface, and the `sysinfo` Mach/BSD/IOKit host-inventory surface,
  incl. `if_nametoindex`) — the SAME **deny-trap interposition** generalized to the
  dormant TLS-trust / timezone / hardware-inventory paths a large binary commonly
  LINKS but a scenario need not reach. A strong shim def (macOS-gated where the
  symbols are Darwin-only) binds each reference at link so the dormant-path binary
  RUNS (the symbol drops off the import table) and a genuine call aborts
  deterministically naming it; the un-trappable data symbols
  (`kCFAllocator*`/`kCFTypeArrayCallBacks`/`mach_task_self_`/`vm_page_size`/
  `kIOMasterPortDefault`) get fixed deterministic values. This is what unblocks an
  unrelated scenario without the whole-run `--allow-unsupported-symbols`
  determinism downgrade (native audit/run blockers Issues 1–2). Only the enumerated
  dormant symbols move from refusal to trap; the live-path members a normal startup
  reaches (`sysctl`/`sysctlbyname`/`getrusage`/`task_info`) and every non-enumerated
  framework/Mach symbol stay refused (see rows for host-introspection and macOS
  frameworks).
- **Host-state queries** (`gethostname`, `getpwuid_r`, `__NSGetExecutablePath`) —
  interposed to fixed deterministic values, exactly like `isatty`/`confstr`
  (host-state-query row).
- **Pure compute** (`memset_pattern4/8/16`, `sigemptyset`/`sigfillset`/
  `sigaddset`/`sigdelset`/`sigismember`) — added to the known-safe allowlist:
  they touch only caller-owned memory (a byte pattern buffer; a `sigset_t`) with
  no boundary effect (`pure_compute_symbols_are_known_safe`).
- **`dlsym`** — reconciled with the host-alias doctrine, not with this pivot:
  on macOS `dlsym(RTLD_NEXT, ...)` is now the shim's own host-vehicle resolution
  primitive, so it is baked into `shim_control_plane_symbols` and the pre-run
  gate tolerates it as control-plane rather than as an escape — it drops off the
  CLI guest's allow list for that reason, not because it is interposed to nothing.
  **What a guest `dlsym` *call* does, per platform (the honest residual):** on
  **Linux** the shim defines `dlsym` (strong interposer) so any guest call
  resolves nothing — deterministic. On **macOS** `dlsym` is *not* interposed: a
  guest call reaches the real dyld resolver (nondeterministic), so a guest whose
  own code reaches `dlsym` is a real escape. Interposing `dlsym` on macOS is
  infeasible while the shim uses it for resolution — a strong-def interposer in
  the guest image would capture the shim's own `dlsym(RTLD_NEXT, ...)` calls
  (`__interpose`/`DYLD_INTERPOSE` does not swap same-image callers, verified), so
  the shim would lose its resolver. Static **reachability** does not close it
  either: address-taken-`main` swallows the call-graph closure (see "Why
  symbol-reachability, not static call-graph reachability" above) and std itself
  has `dlsym`-probing paths, so a reachable-`dlsym`-denial would reject every std
  guest. So the residual **stays** as stated here — honest, adversarial-shaped
  (an accidental escape would need a guest to literally `dlsym` an uninterposed
  name), and strictly *narrower* than the pre-doctrine state, which allow-listed
  the nine far more dangerous baton/spawn/trace vehicles (`semaphore_wait`,
  `pthread_create_suspended_np`, `read$NOCANCEL`, ...) that a guest could import
  directly; those are all denied now. The process-spawn family narrows it further
  still: those symbols are now strong shim defs (deny-traps), and `dlsym` searches
  the main image first (`RTLD_DEFAULT`/`RTLD_NEXT` from the guest), so a guest
  `dlsym("fork")` / `dlsym("posix_spawnp")` resolves to the shim's deny-trap and
  aborts deterministically rather than reaching the real spawn — the spawn slice
  of the residual is closed for free by the deny-traps, leaving only a guest
  `dlsym` of a blocked symbol the shim does *not* strong-def (e.g. `kill`).
  Closing that remainder was investigated in task #18 with a build-time,
  not runtime, mechanism candidate: `cargo patina` controls the link, so a guest
  object's undefined `dlsym` reference could be redirected at build time (e.g.
  `llvm-objcopy --redefine-sym` on non-shim objects → a `patina_guest_dlsym`
  deny/route definition) while the shim's own objects keep the real resolver —
  caller discrimination at link time, no runtime bootstrap. **Outcome: not
  implemented, by measurement.** The mechanism is a no-op for every real Rust
  guest on macOS, because *nothing but the shim references `dlsym` at all*:
    - the guest **user object** (`rustc --emit=obj` with the native cfgs) has no
      undefined `_dlsym` — neither the user code nor the std generics
      monomorphized into it reach it;
    - **no sysroot rlib** does either — a scan of `libstd`/`libcore`/`liballoc`/…
      finds zero `dlsym` references, so macOS std never dynamically resolves a
      symbol (the glibc `__pthread_get_minstack` probe that motivates the Linux
      interposer is Linux-only);
    - the *only* undefined `_dlsym` in a linked guest comes from
      `libpatina_dst_native_shim.a` — the sanctioned `dlsym(RTLD_NEXT, ...)` resolver.

  A call requires the symbol reference, and only the shim has it, so the shim is
  the sole `dlsym` caller at runtime — a sound static conclusion, not a sampled
  one. The residual therefore only manifests if a guest **hand-writes a `dlsym`
  call in its own source**; for such a guest the redirect *would* fire (its
  `.o` carries the `_dlsym` reference), but delivering it means splitting the
  clean single `rustc` compile+link into emit-objects → objcopy → **manual
  relink** (reproducing rustc's full link line by hand), and the toolchain does
  not even ship `llvm-objcopy`/`rust-objcopy` by default (it needs the
  `llvm-tools` component) — real pipeline risk to the testbeds for zero
  measured benefit. So the honest, adversarial-shaped residual **stays**, now
  strictly narrower than before: not merely "narrower than the pre-doctrine
  nine-vehicle allowance", but "measurably unreachable by any guest that does not
  literally write `dlsym(...)` itself".

The net effect on the audited CLI guest is the allow list emptying to nothing
while the gate stays fail-closed for any *new* unsupported import — strictly better than the
named downgrade on both axes (unqualified audit **and** a runtime spawn guard).

## Residual gaps (honest, symbol audit cannot see these)

Symbol reachability cannot observe behavior that never resolves a symbol. These
are **out of scope for this gate by design** (we do not disassemble for
data-flow); where another mechanism covers them it is named, otherwise the gap
is stated plainly:

1. **Raw syscall instructions inlined in the binary** (`svc #0` / `syscall`).
   Covered on **Linux** by the whole-run `strace` containment pass in
   `validate-native-shim.sh` (every file/net/clock/entropy/descriptor syscall in
   the run must match the loader/std prelude shape) and partially by
   `scan_forbidden_instructions` (aarch64/x86_64 syscall opcodes are rejected at
   audit time). **Honestly absent on macOS**: per the ktrace calibration
   (VALIDATION.md), no root-capable SIP-compatible whole-run tracer can separate
   the loader prelude from post-init guest syscalls, so an inlined post-init raw
   syscall on macOS is not caught by a runtime gate — static instruction scanning
   plus the import audit are the macOS evidence.
2. **Commpage / vDSO time reads.** `mach_absolute_time` and `clock_gettime` fast
   paths can read a kernel-mapped page without a syscall or an import. Covered by
   the libc-interposition probes (the interposed `clock_gettime`/`mach_absolute_time`
   are what std actually calls), not by the audit; a hand-rolled commpage reader
   that bypasses libc is a residual.
3. **Instruction-level entropy / time** (`rdrand`/`rdtsc` on x86_64, `RNDR`/`MRS`
   on aarch64, raw `svc`/`syscall`). `scan_forbidden_instructions` rejects the
   `rdrand` and `rdtsc` x86 encodings, the aarch64 `RNDR` random-register read,
   and the `svc`/`syscall` opcodes it knows; other encodings (e.g. `rdseed`) are
   a residual.
4. **Flag-dependent behavior of an allowlisted symbol.** `mmap(MAP_SHARED)` is a
   genuine IPC channel, but `mmap` is allowlisted as process-local memory and the
   audit cannot see the `MAP_SHARED` flag. Stated, not papered over: `mmap` is
   deliberately **not** in the `shared-memory-ipc` list (it would be a dead label,
   since the allowlist wins first).
5. **Interposed-but-unsupported symbols.** A symbol the shim *defines* to
   fail-closed at runtime (e.g. `pthread_cancel`, `setenv`/`unsetenv`/`putenv`,
   and any not-yet-modeled interposer) is not an import, so the symbol audit
   cannot distinguish it from a fully-modeled one. These do not escape silently —
   they return `ENOSYS` with a loud `patina: … failing closed` diagnostic at call
   time (`patina_posix_deny`) — but the *pre-run* gate does not flag them. This is
   why `pthread_rwlock_*` was made a real deterministic implementation rather than
   left as an `ENOSYS` stub: a commonly-reached primitive should be supported, not
   silently pass the gate and then fail at runtime.

## Escape hatch

`native-run --allow-unsupported-symbols <all|name,...>` downgrades matching
denials to a loud stderr warning and records them in a `<trace>.unsupported-symbols`
sidecar next to a `--record` trace, so a run that knowingly tolerates unsupported
surface (never reached by the scenario) is visibly qualified. A partial list
still fails closed on the un-listed symbols.
