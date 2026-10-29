# Guest-escape classes and the detection gate's coverage

**Threat model: accidental escape.** Patina is a determinism tool, not a
security sandbox. A guest is the user's own program built by an ordinary
toolchain (gcc, clang, rustc; GNU ld, gold or lld; PIE, static, stripped,
section-collecting and sanitizer builds included): whatever such a build produces
is contained or fails closed by name. A hand-crafted image (forged markers or
symbols, dynamic tags inconsistent with its sections, a `_start` that skips
`__libc_start_main`) is out of scope, as is a direct launch that bypasses
`cargo patina run`: the pre-run gate is the containment boundary for imports,
so a library function the shim does not define reaches a guest only as an
import the gate refuses. Residuals below that need such a crafted image say so.

A "guest escape" is any path by which a guest running under Patina reaches host
behavior the deterministic runtime does not model — blocking a real thread,
reading host time or entropy, spawning a context, touching another address
space — thereby breaking determinism silently.

Detection is **symbol-reachability**: `cargo patina audit` (and the
`run` pre-run default-deny gate that reuses it) enumerate every
externally-resolved symbol the guest and its application libraries reference,
judge each by the image the loader binds it to (see "Load-set bindings"
below), and refuse any that binds into host code unless it is
**known-safe** (an explicitly listed effect-free host-deferred symbol) or
caller-`--allow`ed. A reference bound to a definition the shim links into the
executable (**interposed**) is contained by where it binds, not by its name: an
alias libc exports beside an interposed function (glibc's `__mmap`) binds into
libc, runs libc's own text, and is refused even though it normalizes onto the
interposed name. Anything else fails closed; known host-effect names are
labeled with their escape *class* (below) for error quality. Diagnostics also
group findings by recovered provenance — the defining object, the crate, and the
symbol containing the reference; `provenance=unknown` means the image carries no
attributable context for that site. This is a symbol-level gate by
design — it does **not** disassemble the binary for call-graph reachability — so
raw inlined instructions and flag-dependent behavior are residuals covered (or
honestly not covered) elsewhere; see "Residual gaps".

How much provenance a finding can carry is a property of the binary format, and
the two formats differ:

- **Mach-O** keeps a per-address object map, so a finding names the defining
  archive member outright: `crate=foo object=libfoo-<hash>.rlib(foo.o)`.
- **ELF** records object identity only through STT_FILE markers, and a marker
  covers the *local* symbols of one input object, ending at the first global
  symbol. A crate's public function is global, so its defining object is
  genuinely absent from the linked image; those findings report the crate
  (recovered from the symbol's own mangling) and the containing symbol, with no
  object.

Provenance is never guessed to close that gap. Carrying an ELF file marker past
its local run stamps every global symbol with whichever object happened to be
last in the symbol table — the bug that had findings claiming a C translation
unit as a Rust crate's defining object (`crate=leaker_a object=crtstuff.c`). An
unrecoverable object is reported as unknown instead.

The class lists live in `native_escape_category` (labeling) and the
known-safe sets in `native_allowlisted_import` (gating), both in
`crates/patina-target/src/import_policy.rs`; where a reference binds is
`crates/patina-target/src/bindings.rs`. `shim_control_plane_symbols` (the seal,
and macOS gating) lives in `crates/patina-target/src/shim.rs`.

## Coverage matrix

| # | Escape class | Representative host symbols | How the deterministic runtime handles the supported surface | Detection mechanism | Permanent test |
|---|---|---|---|---|---|
| a | **Blocking / scheduling** | `os_unfair_lock_*`, `__ulock_wait/wake`, `__psynch_*`, `dispatch_semaphore_*`, mach `semaphore_wait/signal`, `os_sync_wait_on_address`; readiness: `poll`/`select`/`kqueue`/`kevent`/`epoll_*` | pthread mutex/cond, **`os_unfair_lock_*`** (macOS, lazily registered in the mutex table since the bare `u32` has no init call; misuse — recursive lock or foreign unlock — aborts loudly), the dispatch-semaphore Parker, and Linux futex are **interposed** and routed through `DetScheduler` (+ virtual clock for timed waits); `poll` is interposed for the modeled cases; **`kqueue`/`kevent`/`kevent64`** (macOS) are **interposed** by a deterministic in-process readiness reactor (EVFILT_READ/WRITE over virtual pipe/socketpair and SimNet socket fds, an EVFILT_USER Waker, EVFILT_TIMER on the virtual clock; multi-fd fan-in parks on the baton, deterministic `(ident, filter)` event order, no trace events of its own — unmodeled filters and readiness on real host descriptors fail closed loudly); **`epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_pwait`** (Linux) are **interposed** by the mirror frontend over the same readiness core (one interest per fd over the virtual pipe/socketpair, eventfd, and SimNet socket fds; EPOLLET latches keyed on per-direction *arrival sequences* so an edge re-fires per arrival exactly as the kernel does — mio's undrained eventfd Waker depends on it; millisecond timeouts on the virtual clock; deterministic fd-order events; kernel-faithful EEXIST/ENOENT from `epoll_ctl`; unmodeled event flags and non-virtual descriptors fail closed loudly; `epoll_pwait` uses the shared temporary-mask model; libc and SUD share the readiness and eventfd models) — so mio/tokio's IO driver runs under the scheduler on both platforms | symbol audit → `unmanaged-sync` / `wait-multiplex`; any uninterposed blocking symbol is an import → denied | `every_escape_class_is_detected_and_denied` (unit); `native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol` (Mach `semaphore_wait`, still uninterposed) + `native_workloads::os_unfair_lock_contention_is_repeatable`, `native_containment::os_unfair_lock_foreign_unlock_aborts`, `native_abi::darwin::{kqueue_reports_fields_and_wakes_reader,kqueue_user_events_wake_and_timeout_exactly}`, `native_abi::linux::epoll_and_eventfd_wake_latch_and_time_out_exactly`, and `native_workloads::tokio_signal_parking_lot_rustix_use_product_backend` |
| b | **Time** | `clock_gettime`, `clock_gettime_nsec_np`, `gettimeofday`, `mach_absolute_time`, `mach_continuous_time`, `nanosleep`, `clock_nanosleep`, `usleep`, `mach_wait_until`; host-timezone conversion `localtime_r`, `tzset` | the clock reads/sleeps are all interposed → virtual clock (`clock_gettime_nsec_np` shares `clock_gettime`'s clock-id mapping, returning nanoseconds directly). `localtime_r`/`tzset` render a `time_t` through the host timezone database / `TZ` (cross-platform, e.g. the `time` crate's local-offset lookup), so they read where the run happens: `localtime_r` is interposed (glibc's `TZ` rules over the virtual machine, which ships no zoneinfo: a POSIX rule string, UTC for an unset or empty `TZ`, and a named refusal for a zoneinfo file the guest planted where glibc would read it); `tzset` is **not interposed → refused**, classified `time` so the refusal names the host-timezone problem rather than a bare unknown import | symbol audit → `time` | `every_escape_class_is_detected_and_denied`; `the_pure_compute_allowlist_does_not_capture_effectful_neighbours` (`localtime_r`/`tzset` classify `time`); `native_abi::darwin::clock_nsec_matches_clock_gettime` |
| c | **Entropy** | `getentropy`, `getrandom`, `arc4random*`, `CCRandomGenerateBytes`, `SecRandomCopyBytes`; `/dev/urandom` and `/dev/random` fallback reads | interposed or modeled device → seeded RNG. Entropy is reached four ways and each funnels into the same `patina_entropy` stream: the public interposers (`getentropy` on both platforms, `getrandom` on Linux, `CCRandomGenerateBytes` on Darwin), the raw `SYS_getrandom` path (the `syscall` interposer and the SUD dispatch table), reads of the modeled `/dev/urandom` and `/dev/random` devices (`memdev.rs`), and — because the `getrandom` crate resolves its Linux backend dynamically rather than by linking — the **`dlsym` routing table** (see the dynamic-loading row). `/dev/random` is deliberately **not** modeled: with the routing table in place nothing reaches it (the `getrandom` crate polls it only from the `use_file` fallback it now never takes, and `std` opens it only when the `getrandom` weak symbol is absent, which the shim always defines), so it stays an ordinary absent path in the deterministic FS rather than speculative surface | symbol audit → `entropy` for raw imports; deterministic FS/device path for `/dev/urandom` | `every_escape_class_is_detected_and_denied`; `native_workloads::{rand_rng_is_seeded_and_replayable,urandom_device_is_seeded_and_replayable}` and `native_containment::dlsym_routes_only_seeded_entropy` |
| d | **Thread lifecycle** | `pthread_create`, `pthread_create_from_mach_thread_np`, `bsdthread_create`, `thread_create` | `pthread_create` is interposed by a strong def and spawns a managed task via a distinct non-interposed vehicle (macOS `pthread_create_suspended_np`; Linux the real glibc `pthread_create` resolved through `dlsym(RTLD_NEXT, ...)`) | symbol audit → `unmanaged-thread` | `every_escape_class_is_detected_and_denied`; `native_containment::raw_audit_refuses_each_unlinked_escape_class` (planted raw-syscall/pthread C binary) |
| e | **Process** | `fork`, `vfork`, `exec*`, `posix_spawn*`, `system`, `popen`, `kill`, `waitpid`, ... | Subprocess creation remains a **non-goal**: the linked spawn family is deny-trap interposed, and uninterposed siblings remain import-audited. Linux `kill`/`killpg` and task-directed generation use the virtual signal model (self/group 0/±1, missing targets ESRCH); signal 0 only probes existence. Childless waitpid/waitid return ECHILD rather than touching the host. macOS retains its signal-0 liveness model. | uninterposed members → symbol audit → `process`; spawn family → runtime deny-trap; Linux self-signals → deterministic model | `native_run_deny_trap_aborts_a_guest_that_actually_spawns`; `native_harness_import_refusal_has_no_trace` (`system`, uninterposed, refused before launch); `native_build_package_audits_records_and_fails_closed`; frozen signals-family process/generation tests; macOS `native_run_prerun_gate_refuses_every_escape_class` still plants uninterposed `killpg` |
| f | **Filesystem / network** | `open`/`openat`/`read`/`write`/`stat`/`fcntl`/`unlinkat`/`renameat`/...; `socket`/`bind`/`connect`/`send`/`recv`/... | interposed → deterministic FS and SimNet. Read-only directory opens return deterministic directory fds: `fstat` reports `S_IFDIR`, ordinary reads/writes still fail closed, and `fsync` on the fd is the CrashFs namespace-durability barrier. Every path resolves through one resolver in the shim: the modeled working directory for `AT_FDCWD` (`getcwd`/`chdir`/`fchdir` are modeled process state, not process-class traps), a Patina-issued directory descriptor's node otherwise, `..` and symlinks walked as the kernel walks them; the umask is modeled process state applied before the driver; unknown real dirfds still fail closed rather than escaping to the host. Metadata a guest can change is modeled, not synthesized: every entry carries atime/mtime/ctime/btime stamped by the kernel's rules from the virtual clock the runtime hands each driver operation (`FsClock`; `relatime` by default), the owner is the one modeled identity read through a single accessor (`chown`/`fchown`/`lchown`/`fchownat` accept its ids or -1 and answer `EPERM` for any other), and sizes change by name (`truncate`) and by descriptor (`ftruncate`, `fallocate`) as recorded operations. `acct(2)` — process accounting to a file, a privileged kernel-global effect — is defined on Linux (answered from the virtual credential: `EPERM`) and left uninterposed on macOS, where it is the class's planted representative in the gate e2e. | symbol audit → `filesystem` / `network` | `every_escape_class_is_detected_and_denied`; `decorated_symbols_classify_as_their_base_name`; `native_abi::posix_descriptors_paths_and_environment_are_virtualized`; `native_directory_fsync_guards_namespace_durability_and_replays` |
| g | **Shared memory / IPC** | in-process: `pipe`, `pipe2`, `socketpair`, `eventfd`/`eventfd2`; cross-process: `shm_open`, `shm_unlink`, `mach_msg*`, `mach_port_*`, `bootstrap_look_up`, `mq_*` | **split by whether the escape leaves the address space.** `pipe`/`pipe2`/`socketpair` — both endpoints live inside the one guest process (an async runtime's IO-driver / signal self-pipe wakeup), so there is no cross-address-space escape: they are **interposed**: a pipe as a deterministic in-memory byte channel (bounded 64 KiB buffer, writes up to `PIPE_BUF` atomic, EOF on peer close, `EPIPE` on a broken write, preceded on Linux by modeled SIGPIPE unless MSG_NOSIGNAL suppresses it, `O_NONBLOCK`/`EWOULDBLOCK` honored; `dup`/`F_DUPFD[_CLOEXEC]` alias an endpoint refcounted — std's `try_clone`, e.g. tokio's signal driver cloning a socketpair end — so EOF/`EPIPE` appear only once the LAST fd of a side closes), a socketpair as two connected AF_UNIX sockets of the shim's socket model (stream, datagram or seqpacket; other families `EOPNOTSUPP`), both wired to the SAME scheduler baton / waiter machinery, so reads/writes are scheduler-visible and deterministic given the schedule (no trace events of their own — like the futex/mutex words). `eventfd`/`eventfd2` (Linux, mio's Waker vehicle) joined the in-process slice: **interposed** as a deterministic 64-bit counter (read returns-and-resets, `EFD_SEMAPHORE` decrements, `EFD_NONBLOCK` → `EAGAIN` on zero reads, `EFD_CLOEXEC` a no-op; a write that would overflow fails closed loudly instead of modeling blocked writers) wired into the same readiness core so the epoll reactor watches it. The **cross-process** members (`shm_open`/`mach_*`/`mq_*`) genuinely reach another address space or the kernel and stay **refused** as libc symbols. On Linux the kernel rows beneath them are modeled with single-process semantics (System V shared memory, semaphores and message queues, through glibc's wrappers — interposed as doors into the model, and on macOS refused as `shared-memory-ipc` — or the rows; POSIX message queues through `syscall(2)` or a raw instruction), and `mmap` is interposed: a `MAP_SHARED` mapping is host anonymous memory no second process can attach (process creation is a named trap) or a view of a modeled file's page cache. | interposed members → not an import (strong def); cross-process members → symbol audit → `shared-memory-ipc` (still classified so a raw non-shim import reads as an escape) | `every_escape_class_is_detected_and_denied` (`shm_open`, `eventfd`); `native_abi::pipes_and_socketpairs_wake_alias_and_refuse_to_block` (EPIPE without SIGPIPE under Rust std's ignored-SIGPIPE disposition), shim unit `a_broken_pipe_or_socket_generates_sigpipe_before_epipe` (`MSG_NOSIGNAL`) and the frozen `signal/pipe_term` probe (generation, `MSG_NOSIGNAL` and default death), `native_abi::linux::epoll_and_eventfd_wake_latch_and_time_out_exactly`, and `native_containment::prerun_refuses_shm_open_and_hatch_warns` |
| h | **Signals / timers** | `sigaction`, `sigprocmask`, `sigaltstack`, `sigsuspend`, `sigwait`, `sigtimedwait`, `pause`, `signalfd`; `setitimer`, `timer_create/settime`, `alarm`, `ualarm` | Linux registrations, masks, self-generation, waits and signalfd are modeled in one Rust state machine on both libc and SUD doors; their rows, and the timer rows, copy guest pointers through `uaccess`, answering `EFAULT` as 6.8 does. Pending state and recipients are deterministic; kernel frames only carry selected deliveries. SIGSYS registrations stay virtual and queries report the guest action, never the host containment action; guest SIGSYS generation is a named refusal (no modeled kernel effect raises it); every shim handler's kernel frame is on a private per-thread stack and a guest's handler runs on the stack its action asks for, with its alternate stack kept virtually (6.8 rules); under the x86_64 counter trap a SIGSEGV registration is the guest's virtual action, which the trap runs for each fault it does not answer (a counter read it does not answer, or a SIGSEGV while shim code owns the thread, is a named stop instead); on every Linux arch SIGBUS, SIGFPE, SIGILL and SIGTRAP, and SIGSEGV where the trap is not armed, reach the guest's virtual action through a front handler, which makes a fault in the shim's own code a named stop too (macOS guest handlers remain the host's). SIGSYS, and SIGSEGV under the trap, are stripped from every host mask, an action's `sa_mask` included (a guest reads SIGSYS back unblocked); SIGSEGV's block under the trap is kept virtually, also inside a front-routed handler whose `sa_mask` names it, and where a `siglongjmp` may have left a handler that blocked it the answer is a named stop. Ambient external signals remain outside the model. Linux timers run on the virtual clock and CPU time behind the SUD rows and `syscall(2)` (interval timers, POSIX timers, timer descriptors); their libc wrappers (`setitimer`, `alarm`, `timer_create`, …) define no shim symbol and stay import-refused. macOS retains registration allowances and refuses signal waiting/timer arming. | strong modeled definitions; remaining imports → `signals-timers`; unmodeled raw rows → named traps | frozen signals family gate, production-entry state/wait tests, typed `native_signals` C adapter test |
| — | **Environment** | `getenv`, `secure_getenv`, `setenv`, `unsetenv`, `putenv`, `clearenv` | interposed → glibc's environment functions over the process's own `environ`, which starts as the deterministic startup map native `run --env` supplies (empty by default, recorded in trace metadata); `putenv` inserts the caller's own string, aliased as glibc keeps it | symbol audit → `environment` | `every_escape_class_is_detected_and_denied` |
| — | **Dynamic loading** | `dlopen`, `dlsym`, `dlclose`, `dlmopen`, `dlopen_preflight` | `dlopen`/`dlclose` are **deny-traps** on both platforms: extension loaders (`libloading`, linked unconditionally by `turso_core`) leave them in a guest that never loads anything, so linking them is inert and a call aborts naming the symbol. Loading host code is never modeled. glibc's own loads (NSS modules, iconv's gconv modules, the unwinder's `libgcc_s`) call its internal `__libc_dlopen_mode`, never the interposable name, and no library in a guest's load set imports `dlopen`, so the trap cannot capture them; under patina an internal load of an object the process has not already mapped stops at the DSO-syscall fatal (its first `openat` comes from ld.so) before anything maps. `dlmopen`/`dlopen_preflight` stay refused imports, and macOS `dlerror` is known-safe (it reports the last failed host `dlsym`). `dlsym`: **Linux** interposed, and it can never return a *host* symbol. It answers from one **routing table** (`src/posix/dlsym.rs`) — every name the shim defines as a libc contract (the registry's `Modeled`/`Partial` Linux rows, held to it by a drift test), mapped to hidden aliases of the shim's own definitions — and NULL for every other name (host-only names, deny-trapped escapes, the control plane), so std's optional-symbol probing still falls back to defaults. The table is not an allowance: it lists symbols this shim already defines, so it hands back the code the static linker would have bound the caller to (the very address) and cannot widen what the guest can reach. Flat NULL was the *less* contained answer, because the `getrandom` crate reads NULL as "this kernel has no getrandom" and falls back to opening and `poll()`ing `/dev/random`. **macOS** `dlsym` is the shim's own host-alias resolution primitive (`dlsym(RTLD_NEXT, ...)`), so it is baked into `shim_control_plane_symbols` and tolerated as control-plane — see the honest-residual note below | symbol audit → `dynamic-loading` for raw imports; `dlopen`/`dlclose` → runtime deny-trap (Linux `dlsym`: interposed) | `every_escape_class_is_detected_and_denied`; `native_run_dlopen_is_a_deny_trap_and_release_strips_debug_asserts` (links → runs, calls → aborts by name, both platforms); conformance `proc/dl`; `native_containment::dlsym_routes_the_shim_definitions_and_no_host_name` (the routing table is a distinct symbol, so the routed-resolve / everything-else-NULL / seeded-bytes assertions run on **both** platforms, with the real `dlsym` round trip asserted on Linux) |
| — | **Direct syscall (by name)** | `syscall`, `__syscall` | Linux `syscall` interposed by an assembly entry: every number reaches the one dispatcher a trapped raw syscall reaches (the same registry rows: modeled, soft-denied, or a named fatal for an unmodeled one), except `rt_sigreturn`, which a guest's own signal restorer issues and which resumes at the host kernel's `rt_sigreturn` from glibc text with the caller's stack pointer, the frame's saved mask stripped of the containment signals first. Raw *inline* syscall instructions have no symbol and are refused by the instruction scan; `cargo patina build` injects `--cfg rustix_use_libc` so the most common emitter (rustix's default Linux backend) compiles to interposable libc imports instead. | symbol audit → `direct-syscall`; instruction scan → `instruction@…` findings | `every_escape_class_is_detected_and_denied` |
| — | **Direct syscall (raw inline instruction, SUD-managed)** | `syscall`/`svc` opcodes emitted inline (rustix's default linux_raw backend, hand-written asm) | **Linux syscall-user-dispatch (SUD), x86_64.** The shim arms `PR_SET_SYSCALL_USER_DISPATCH` (allowed region = glibc's executable segment, NULL selector) at `__libc_start_main` and in every managed thread's trampoline, installs a `SIGSYS` handler, and scrubs `AT_SYSINFO_EHDR` from the auxv (so vDSO-resolving crates fall back to trappable raw syscalls). A trapped syscall is decoded and routed into the same `patina_*` entry points the C interposers use (clock/futex/read/write/openat/close/lseek/getrandom/sched_yield/gettid/exit; the mapping rows through the one mapping model, the other process-local memory rows passed through; the System V and POSIX message queue rows through the one-process IPC model; `set_robust_list`/`get_robust_list`/`rseq` through the per-task registration model; every unmodeled row → named fatal abort). The audit **downgrades** a `direct-syscall` *instruction* finding from refuse → run **iff** (a) the binary defines the `patina_sud_dispatch` marker AND (b) a live `prctl` probe says the kernel has SUD (x86_64 ≥ 5.11); it is reported relabeled `direct-syscall (SUD-managed)`, never silent. The x86-64 i386 entries `int 0x80` (`cd 80`) and `sysenter` (`0f 34`) are `direct-syscall` instruction findings too, but they are **never** downgraded: where the kernel has IA32 emulation (Ubuntu's default; `sysenter` only on Intel) SUD traps them, yet they arrive with the i386 syscall ABI (`si_arch = AUDIT_ARCH_I386`), which the shim's handler aborts on, and elsewhere they fault (SIGSEGV, or SIGILL for `sysenter` on AMD), so the audit refuses them up front on every kernel, with a note saying why. No-SUD kernel (notably arm64) or no marker ⇒ today's refusal, with a hint pointing at `--cfg rustix_use_libc` / x86_64. `cpu-nondeterminism` counter/entropy reads are NOT SUD-manageable (SUD sees syscalls only); the timestamp counter has its own trap in the next row, and the rest still refuse. | instruction scan → `instruction@…` finding carrying the decoded mnemonic (`syscall`, `svc`, `int 0x80`, `sysenter`), downgraded to `direct-syscall (SUD-managed)` when marker + kernel probe pass and the mnemonic is `syscall`/`svc` | `native_containment::{raw_audit_refuses_each_unlinked_escape_class,raw_syscalls_are_virtualized_or_refused_before_execution,unmapped_raw_syscall_aborts_with_named_diagnostic,trapped_raw_syscalls_leave_a_small_stack_untouched,auxv_and_sigsys_are_virtual_on_every_kernel}`; patina-target unit `flags_real_forbidden_opcodes_at_a_boundary` (the i386 entries and their `int`/`sysexit`/`sysret` neighbours), `sud_manageability_is_instruction_direct_syscall_only` |
| — | **CPU nondeterminism (raw inline instruction)** | `rdtsc`/`rdtscp` (x86-64 timestamp counter), `rdrand`/`rdseed` (x86-64 hardware entropy), `mrs Xt, CNTVCT_EL0` and its FEAT_ECV self-synchronising twin `mrs Xt, CNTVCTSS_EL0` (arm64 system counter; the physical `CNTPCT`/`CNTPCTSS` reads are disabled at EL0 by Linux and raise SIGILL), `mrs Xt, RNDR`/`RNDRRS` (arm64 hardware entropy, FEAT_RNG) — all emitted inline by a guest that reaches for the counter directly (`core::arch`, hand-written asm, a fast-clock crate) | **split by whether a trap exists.** The *timestamp counter* is trap-managed on x86-64 Linux: the shim arms `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` at `__libc_start_main` and in every managed thread's trampoline, so `rdtsc`/`rdtscp` raise a synchronous `SIGSEGV`, and the handler answers them from the run's virtual monotonic clock through the SAME `patina_clock_now` entry point the C interposers use — one tick per virtual nanosecond (a nominal 1 GHz invariant TSC), `IA32_TSC_AUX` fixed at 0, and the read recorded as the ordinary `clock_now` operation, so a counter read and a `clock_gettime` are the same op in the trace. Arming is recorded in the trace's `tsc` metadata field and reconciled fail-closed on replay. A counter read the trap does not answer (outside the main executable's text, or in a prefixed encoding) is a named stop, and so is a SIGSEGV while shim code owns the thread, so the guest's handler never sees either; the trap's signal frame is on the shim's private stack, so a counter read takes none of the guest's stack. Every other SIGSEGV goes where the kernel would send it under the guest's own (virtual) SIGSEGV action, so a genuine segmentation fault reaches the guest's handler or kills the process as natively. Everything else in this class is **untrappable**: no mechanism intercepts a hardware entropy read or the arm64 system counter, so `rdrand`/`rdseed`/`CNTVCT`/`CNTVCTSS`/`RNDR`/`RNDRRS` stay refusals on every platform. | instruction scan → `instruction@…` finding carrying the decoded mnemonic; `rdtsc`/`rdtscp` are downgraded to `cpu-nondeterminism (TSC-trap-managed)` **iff** (a) the binary defines the `patina_tsc_dispatch` marker AND (b) a live `prctl(PR_GET_TSC)` probe says this platform can arm the trap — never silently; every other mnemonic keeps refusing, and the refusal names the class as unallowable (an instruction finding has no symbol for `--allow`) and untrappable | `native_containment::{tsc_reads_answer_from_virtual_clock,rdrand_is_refused_on_every_kernel,genuine_segv_is_not_swallowed,sigsegv_handler_cannot_take_over_the_counter_trap,counter_reads_on_a_minimal_altstack_preserve_the_guest_stack,shim_faults_are_named_stops_never_the_guests}`; shim unit `a_prefixed_encoding_is_not_answered_but_is_known_for_a_counter_read`; patina-target unit tests `flags_real_forbidden_opcodes_at_a_boundary`, `classifies_aarch64_system_register_accesses`, `tsc_manageability_is_the_timestamp_counter_only`, `cpu_nondeterminism_note_names_allowability_and_trappability` |
| — | **Versioned-symbol bypass (Linux ELF)** | a `.symver`-pinned reference to the `-Wl,--wrap=dlsym` resolver: `dlsym@GLIBC_2.2.5`/`dlvsym@…`; a pinned reference to a name the shim defines but the executable does not export (`mmap@GLIBC_2.2.5`) | **refused, no trap.** `-Wl,--wrap=dlsym` rewrites only *unversioned* references; `.symver` keeps the version requirement, so the reference stays an undefined import that binds to libc's real resolver past the restricted one. No pass of its own catches it: the load-set binding audit (the next row) resolves every versioned reference by glibc's version rules, so a pinned `dlsym` binds into libc and is refused as `dynamic-loading`, and a pinned `mmap` binds to the executable's own exported definition (a definition at the global version index satisfies any version) when there is one, and otherwise into libc, refused by its class and marked as going around the executable's definition. The one admitted host binding of a resolver is the shim's own host-alias vehicle: the **executable's** weak `dlsym` at exactly `GLIBC_2.34`, glibc's default `dlsym` version since 2.34 (`SHIM_DLSYM_VERSION`), in a shim-linked binary; a library's `dlsym`, a strong pin, another version and `dlvsym` are guest resolvers. An exact `--allow name@version` clears one binding. Out of the accidental-escape model: a guest weak reference pinned to `dlsym@GLIBC_2.34` itself merges with the shim's at link time into one dynamic symbol. **macOS** has no GNU symbol versioning (its `dlsym` residual is in the Dynamic-loading row) | load-set binding audit → the binding's class (`dynamic-loading`, ...) | `native_containment::prerun_refuses_interposer_aliases_and_a_versioned_dlsym_bypass`, `native_containment::versioned_interposer_reference_binds_to_the_shim`; unit `native_audit::tests::{a_versioned_reference_binds_by_its_version_and_the_shim_vehicle_alone_passes,an_exact_versioned_allowance_clears_only_that_finding,a_dynamic_version_table_without_its_section_is_unauditable}` |
| — | **Host identity (raw inline instruction, visible — not refused)** | `cpuid` (x86-64), emitted wherever code branches on what CPU it is running on: glibc ifunc resolvers selecting a `memcpy`/`strlen`, `std`'s `is_x86_feature_detected!`, hand-rolled feature probes, and fast-clock crates choosing an implementation (`fastant` reads leaf `0x80000007` bit 8 to pick its timestamp-counter path over the `SystemTime` fallback); and `rdpkru`/`wrpkru` (x86-64), the thread's protection-key rights register (the `mem/pkeys` conformance probe reads it) | **unmanaged, and reported anyway** — the one instruction class that informs rather than refuses. Refusing is not available: `cpuid` is near-universal in real x86-64 binaries, so a refusal would refuse essentially every guest, and it is not an escape from a single run's determinism either — feature bits are constant on a host, so repeats, seed variation, and record/replay are all unaffected. What it costs is **cross-host reproducibility**: where those bits guard behavior, the same guest at the same seed can take a different code path on a different host, and until this slice the report said nothing about it (the fastant probe measured 11 `cpuid` sites by `objdump` in a binary whose 2 `rdtsc` sites the audit did report). Reporting is therefore the whole disposition: name the sites, say the run is deterministic here and not portable there, and let the operator pin the host. The bits `cpuid` shows include the host's PKU, OSPKE and user-shadow-stack (CET_SS) bits, which the virtual CPU declares absent (its protection-key rows and `map_shadow_stack`/`ARCH_SHSTK_*` answer as 6.8 on a CPU without them), and `xgetbv` (not decoded) reports the PKRU state component in XCR0 likewise: code gated on those bits meets the rows' refusals and falls back. `rdpkru`/`wrpkru` contradict the declared CPU outright, so the report says so: a host with keys answers its default rights (the same on every such host), one without raises `SIGILL`; a `wrpkru` that revokes key 0 only faults the guest. Refusing them is not available either: `--allow` cannot clear an instruction finding, so the refusal would refuse the conformance probe whole. **Escalation path**, if a run must be portable rather than merely reproducible: Linux `arch_prctl(ARCH_SET_CPUID, 0)` faults `CPUID` on capable Intel parts, so the SUD/TSC trap pattern extends to it — the handler would answer from a fixed synthetic feature-bit model instead of the host's. That is a deferred slice (Intel-only, and a synthetic model has to be built), deliberately not started here; patina's virtual CPU declares no CPUID faulting today (`ARCH_SET_CPUID` answers `ENODEV`), so taking it also changes that declared answer. **aarch64** has the same shape and no row yet: `mrs Xt, MIDR_EL1`/`REVIDR_EL1`/`ID_AA64ISAR*` are identity/feature reads (EL0 access is kernel-emulated on Linux), so they belong in this class when the arm64 decoder learns them; they are not decoded today, which is a stated residual, not a claim of absence | instruction scan → `instruction@…` finding carrying mnemonic `cpuid` and category `host-identity`, which `NativeAudit::audit` keeps OUT of the denied set (so the exit code never moves) and the report prints under its own heading on **every** audit outcome — clean, trap-managed, and refused — plus a JSON `finding_details` row with `disposition: unmanaged-visible` | `flags_real_forbidden_opcodes_at_a_boundary` and `cpuid_sites_are_reported_without_refusing_the_binary` (patina-target unit: decode row, enumeration, non-refusal, rdtsc neighbour unchanged); `audit_reports_host_identity_reads_without_refusing_them` (cargo-patina e2e: heading, site offsets, exit 0, JSON detail rows, and the sites still reported alongside a refusal) |
| — | **Thread pointer (raw inline instruction)** | x86-64 `wrfsbase` (`f3 [REX.W] 0f ae /2`, register form) and the FS selector loads `mov fs, r/m` (`8e /4`), `pop fs` (`0f a1`), `lfs` (`0f b4`); aarch64 `msr tpidr_el0, Xt` (`0xd51bd040 \| Rt`). Emitted by hand-written asm, or a coroutine/green-thread runtime that installs its own TLS block | **refused, no trap.** The thread pointer is not guest-only state: the shim is linked into the guest and resolves its own thread-locals (the current task, the frame flags, the panic scope) through it, as glibc's TCB does. A guest that moves it makes the shim read another block as its task state, so it schedules the wrong task or corrupts its own state, or it impersonates another task's TLS. The syscall doors, `arch_prctl(ARCH_SET_FS)` to another base and a `modify_ldt` write that would store a usable descriptor (an LDT entry is what an FS selector load reads; an entry the kernel stores zeroed is passed to the host), stop the run by name (`thread-pointer`, `src/sud/thread_pointer.rs`) for the same reason; these instructions do the same with no syscall, which only the static scan can see. Neighbours that are **not** findings, and why: `rdfsbase`/`rdgsbase` and `mrs Xt, TPIDR_EL0` read the pointer, which `arch_prctl(ARCH_GET_FS)` and every TLS access already give the guest; `wrgsbase` and the GS selector loads move GS, which neither glibc nor the shim uses in user space on x86-64 (the thread/tls design passes `ARCH_SET_GS` through for the same reason); `msr TPIDRRO_EL0` is UNDEFINED at EL0 (SIGILL); `msr TPIDR2_EL0` is the SME lazy-ZA-save pointer, not a TLS base (glibc 2.39's own `__libc_arm_za_disable` zeroes it). **Where glibc 2.39 writes the pointer:** in a dynamic link (every `cargo patina build` guest) ld.so installs the main thread's pointer (`TLS_INIT_TP` in rtld: two `msr tpidr_el0` sites in `ld-linux-aarch64.so.1`, two `arch_prctl(ARCH_SET_FS)` syscalls in `ld-linux-x86-64.so.2`, no `wrfsbase` anywhere) and new threads get theirs from `clone3(CLONE_SETTLS)`; the audit scans the guest executable, never its interpreter or `libc.so.6`, so no glibc site is in the scanned image and no allowlist is needed. A static glibc image carries glibc's own `msr tpidr_el0` in `__libc_setup_tls` (aarch64); it is reported and refused like any other site, as such images already are for their inline `svc`, and an operator can clear it by name with `--allow-unsupported-symbols __libc_setup_tls` | instruction scan → `instruction@…` finding with category `thread-pointer` and the decoded mnemonic (`wrfsbase`, `mov fs`, `pop fs`, `lfs`, `msr tpidr_el0`, also in the JSON `finding_details` row), refused by the audit and the pre-run gate with a note naming the instructions; no marker or probe downgrades it, and the only way past it is the `--allow-unsupported-symbols` hatch | patina-target unit: `classifies_thread_pointer_writes` (x86 encodings, reads/GS/group-15 neighbours including memory-form `repz ldmxcsr`), `classifies_aarch64_system_register_accesses` (every Xt, the TPIDRRO/TPIDR2/read neighbours), `aarch64_thread_pointer_write_is_refused_by_name` (scanner on bytes through `NativeAudit::audit`, the note); cargo-patina e2e: `native_containment::thread_pointer_writes_are_refused_by_name` (planted Rust guest, `.byte`/`.inst` forms, refused by run and audit by mnemonic on each arch) |
| — | **Far transfer (raw inline instruction)** | x86-64 `lcall`/`ljmp` through memory (`ff /3`, `ff /5`), `lret` (`cb`, `ca iw`) and `iret` (`cf`), under any prefix. Emitted by hand-written mode-switching asm (a 32-bit thunk); compilers never emit them for user-space 64-bit code (GCC's `__attribute__((interrupt))` emits `iretq`, for kernel/bare-metal handlers only) | **refused, no trap.** Each loads CS from a selector the guest chooses, and a 32-bit code selector (Linux's `__USER32_CS`) switches the CPU to compatibility mode. There the 64-bit decoder no longer describes the code that runs: a thread-pointer write, an entropy read or an i386 syscall in it can decode as something else. Refusing the transfer keeps every instruction the scan approves in the mode it was decoded in. The direct far forms `lcall`/`ljmp ptr16:32` (`9a`/`ea`) are invalid in 64-bit mode and already fail closed as `undecodable-instruction`. Not findings: near `call`/`jmp`/`ret` and the rest of group 5. aarch64 has no counterpart, since an EL0 process cannot switch to AArch32 without an exec. None of these instructions appears in glibc 2.39 (`libc.so.6`, `ld.so`, `libc.a`), `python3.12` or `git`. Across 2,193 host x86-64 ELFs the only such bytes are in Go binaries, and they are data, not code: Go's `crypto/internal/boring/sig` marker functions (`StandardCrypto`, in every binary that links `crypto/sha1` or `crypto/tls`; `BoringCrypto`; `FIPSOnly`), each a `jmp` over 29 fixed bytes that `rsc.io/goversion` searches for, then the `ret` it lands on. Decoded as instructions, `StandardCrypto`'s data reads `…; push %rcx; lret $0xa956; lret` and `FIPSOnly`'s has an undecodable `ce`. The scan matches a marker at an instruction boundary by all 32 of its bytes and steps over the data as the `jmp` does, so decoding resumes at the `ret`; the site is reported as an informational `go-build-marker` finding (the audit's "Go build markers" heading, with its containing symbol), never as a refusal. A sequence short of any one byte is decoded as code like any other. Go binaries also carry raw `syscall`s, which the SUD row covers | instruction scan → `instruction@…` finding with category `far-transfer` and the decoded mnemonic (`lcall`, `ljmp`, `lret`, `iret`), refused by the audit and the pre-run gate with a note (shared with `int 0x80`/`sysenter`) naming them; no marker or probe downgrades it | patina-target unit `flags_real_forbidden_opcodes_at_a_boundary` (the far forms, and the near group-5 and `ret` neighbours) and `go_build_markers_are_reported_and_their_data_is_stepped_over` (each marker skipped, a following `lret` still refused, an altered marker decoded as code) |
| — | **Pre-constructor code (Linux)** | a preinit-array entry of the executable's own (a `#[link_section = ".preinit_array"]` static, a C `section(".preinit_array")` pointer); a sanitizer runtime's (`__asan_init`, `__tsan_init`, …) | **refused, no trap.** glibc's `_dl_init` runs the executable's preinit array before every shared library's constructor, and the shim arms its containment from one entry there (`patina_preinit`, `c/posix/init.c`). Entries run in link order and a guest's objects precede the shim's, so another entry would run uncontained. The audit reads the array as the loader does, from the dynamic table (`DT_PREINIT_ARRAY`), and as static startup does, from every `SHT_PREINIT_ARRAY` section by type, and attributes each entry by its relocation or stored address: any entry that is not the shim's, or cannot be attributed to it, is refused as `early-init` (the shim's entry is known by its symbol or, in a symbol-stripped image, by the `.patina.preinit` marker beside it); that attribution reads what the binary says about itself, so the shim also proves it at run time from its own loaded code: its entry stops the run when the linker's array holds anything beside it, and the `__libc_start_main` door stops a dynamically linked run whose loader never ran it (`early-init` named stops); a sanitizer runtime's initializer is refused as `sanitizer-runtime`, since that runtime interposes the allocator, threads and signals the shim models and issues its own raw syscalls. Shared libraries' constructors run after it, contained where the kernel has SUD: an inline syscall or counter read there is outside the main executable's text and stops by name, and they read the virtual CPU from glibc's rseq area (residual 11 covers kernels without SUD). A shared library's own `DT_PREINIT_ARRAY` is ignored by glibc, natively as under Patina. An ELF without section headers (or, dynamically linked, without a dynamic symbol table) is refused outright: the import audit and the scan read them | pre-run audit → `early-init`, `sanitizer-runtime`; unauditable ELF → refusal | `native_containment::early_init::*` |
| — | **Host-state query** | `isatty`, `gethostname`, `getpwuid_r`, `__NSGetExecutablePath`, `issetugid`; Linux: `getpwnam_r`, `sched_getcpu`, `sched_setaffinity`, `pthread_getname_np`, `pthread_sigmask`; the group database `getgrgid_r`, `getgrnam_r`, `getgrouplist` | interposed → fixed deterministic values so guest output cannot depend on where, on which core, or as whom, it ran. `isatty` → the virtual machine's answer, never the host's: glibc's `TCGETS` through the ioctl row, 1 only for the virtual pseudoterminals (Linux), otherwise 0 with that row's errno (`ENOTTY` for the captured streams, files and pipes; Darwin: "not a terminal" for every descriptor); `gethostname` → the constant `"patina"`; `getpwuid_r` (and the Linux `getpwnam_r` lookup and `getpwent` walk) → the virtual machine's passwd database, Ubuntu 24.04's container image's (`registry::PASSWD`: root first, uid 1000 `ubuntu` with home `/home/ubuntu`), read into the caller's entry and buffer as glibc's files module does (std's home-dir lookup with `HOME` unset therefore answers `/home/ubuntu`, never the host user's home); `__NSGetExecutablePath` → fails so `current_exe()` is a deterministic `Err` rather than leaking the host path (a future guest needing `current_exe() → Ok` should get a fixed *virtual* path, never the host's); `issetugid` → 0 (never a set-id binary). Linux glibc, reached by a custom global allocator's init: `sched_getcpu` → 0 (the live CPU id is host-scheduling nondeterminism; pinning it makes per-CPU arena selection deterministic — distinct from the pure `__sched_cpucount`/`CPU_COUNT` popcount, which is allowlisted); `sched_setaffinity` → deterministic no-op success (affinity is inert under the single-baton scheduler); `pthread_getname_np` → a fixed empty name; `pthread_sigmask` → the shared per-task virtual mask, with SIGSYS and armed SIGSEGV stripped from host masks so a guest cannot disarm containment (armed SIGSEGV's block is kept virtually). All are strong C defs, so none appears as an import. The group database is not modeled: its three lookups are **deny-traps** (`host-introspection`; Go's `os/user` links them whether or not it calls them), so linking them is inert and a call aborts naming the symbol rather than reading the host's groups through NSS. | not an import (strong def) | `native_workloads::std_runs_seeded_and_replayable_but_not_standalone` (linked std guest; not an explicit isatty-value assertion); `the_pure_compute_allowlist_does_not_capture_effectful_neighbours` (unit — `sched_getcpu` stays denied for a non-shim binary, not confused with the pure `__sched_cpucount`); the Linux tikv-jemallocator MRE audits clean and runs deterministically |
| — | **Stack-growth probe (macOS)** | `___chkstk_darwin` | **known-safe.** A compiler-inserted probe that touches successive stack guard pages before a large frame (an allocator's init frames reach it). Pure caller-stack access, no boundary effect, value-free deterministic outcome (return, or a genuine stack-overflow death exactly as native). | import audit → allowlisted | the tikv-jemallocator MRE audits clean |
| — | **Host-state registration** | `pthread_atfork` (fork-handler registration pulled in by Rust std / libc thread & once machinery — e.g. a multi-thread guest) | interposed → **no-op returning 0**: the registration is ignored. Sound because the entire fork/exec process class (row **e**) is a deterministic-runtime non-goal the audit denies, so a registered handler could never run; the call has no boundary effect. A strong C definition binds the guest reference and the libc symbol drops off the import table, so the pre-run gate has nothing to flag and the run's determinism claim is unqualified. Being shim-defined, it never appears as an import. | not an import (strong def) | a multi-thread guest under `run-patina.sh` links it and runs allowance-free |
| — | **Positional file I/O** | `pread`, `pwrite` (a guest's `read_exact_at`/`write_all_at`; the offset-loop `libc::pread`/`libc::pwrite`); the vectored `preadv`, `pwritev` (`preadv64`/`pwritev64` on Linux — a database backend batching a transaction's WAL frames in ONE `pwritev`) | interposed → `patina_p{read,write}` → the runtime's `fs_read_at`/`fs_write_at`, serviced as **one** positional driver operation (`FsDriver::read_at`/`write_at`) that saves, seeks, reads/writes, and restores the cursor **within a single driver call** — atomic w.r.t. the scheduler, so it is cursor-independent even when threads share the fd. A caller-side seek+read emulation would be unsound under preemption; this reaches the driver as one op instead. `write_at` is a crash point and is crash-losable exactly like a cursor write; `read_at` is no crash point. The vectored forms loop per `iovec` over the SAME positional ops at an advancing offset and, like `readv`/`writev`, stop at the first short or failed transfer (an injected short write surfaces to a vectored caller as a short total); a socket or stdio fd is `ESPIPE`. Being shim-defined, none appears as an import. | not an import (strong def) | `patina-dst-abi` tag/offset pins; `patina-dst-fs-crash::positional_write_is_crash_losable_exactly_like_a_cursor_write`; `native_fs_surface_answers_from_the_deterministic_filesystem` (e2e, its positional leg: one `pwritev` of two frames lands at the offset with the cursor untouched, `preadv` reads them back across two buffers, short at EOF, `ESPIPE` on stdout) |
| — | **Advisory file lock** | `flock` (a guest's whole-file `File::try_lock` / `try_lock_shared` on open); `fcntl` record locks `F_GETLK`/`F_SETLK`/`F_SETLKW` (rustix `fcntl_lock` — the open-time whole-file lock a storage engine such as turso takes) and the Linux `F_OFD_*` variants | interposed → **per-description lock table**. The lock belongs to the open file DESCRIPTION (a `dup` of the holder shares it and can release it; closing one number of a dup'd pair keeps it) and is keyed on the deterministic-fs inode the description is open on (from the recorded fd-metadata path, so it reconstructs identically under replay); conflicts are resolved against that identity: `LOCK_EX` conflicts with any lock held on another description of the same file, `LOCK_SH` only with a held `LOCK_EX`. A lone opener always acquires (a single `LOCK_EX\|LOCK_NB` on open), but a *second* open of the same path contends faithfully — `LOCK_NB` reports `EWOULDBLOCK`, exactly the path a single-opener database guest surfaces as an "already open" error. The lock clears on `LOCK_UN` and with the description's last number (descriptions are never reused, so no stale entry survives a number's reuse). One simplification, sound for the supported surface: a *blocking* request that would contend fails closed with `EDEADLK` rather than parking a real thread (the single-baton scheduler does not model advisory-lock waiting, and std's `File::try_lock*` is always `LOCK_NB`). A non-file description (a socket, an eventfd) locks as its own identity, as each is its own inode on Linux. POSIX record locks are process-scoped, and a run is ONE process: they never conflict with locks the same process already holds (POSIX merges them, and any close releases them all), so on an open regular fd `F_SETLK`/`F_SETLKW` succeed and `F_GETLK` reports the range `F_UNLCK` — exactly the lone opener's view on the host (left unmodeled the lock was `ENOSYS` and the engine aborted at unlock). Descriptor validity there is a descriptor-table check only — a record lock does no I/O, so it never consults the fault-eligible driver lookup (an injected `EIO` on an unlock would be a fabricated failure mode); a bogus lock type is `EINVAL`, a number that names nothing `EBADF`, and — `fcntl_setlk`'s access-mode check — a read lock on a write-only description or a write lock on a read-only one `EBADF`. Linux open-file-description locks DO conflict across descriptions in one process, so a whole-file `F_OFD_SETLK`/`F_OFD_SETLKW` routes to this same per-inode table (`LOCK_NB` for the non-blocking command); a byte-range OFD lock and `F_OFD_GETLK` stay a soft `ENOSYS` rather than a fabricated answer. The SUD `fcntl` row mirrors the C arm exactly. Being shim-defined, neither `flock` nor `fcntl` appears as an import. | not an import (strong def) | `native_fs_surface_answers_from_the_deterministic_filesystem` (e2e, its `flock` leg: second open → `EWOULDBLOCK` in libc `errno` — the shim keeps its own thread-local errno, so a C entry forwarding a `patina_*` result must `fail_int` it, close releases); its record-lock leg: `F_SETLK`/`F_SETLKW` 0, `F_GETLK` → `F_UNLCK`, bogus type `EINVAL`, a read lock on write-only stdout `EBADF`; Linux: a second open's whole-file `F_OFD_SETLK` contends `EAGAIN`, byte-range / `F_OFD_GETLK` `ENOSYS`, release lets it retry) |
| — | **Filesystem volume metadata** | `statfs`/`fstatfs` (`statfs64`/`fstatfs64` on Linux) — a storage engine probing whether a path's filesystem supports its multi-process coordination (turso's shared-WAL probe on every open; SQLite's Darwin `unixOpen`, which fails every open whose `fstatfs` fails, and its lock-style probe) | interposed → the virtual filesystem answers as ONE constant volume for any path or descriptor that resolves through the same lookup `stat`/`fstat` use: on Linux an ext4-like volume (`EXT4_SUPER_MAGIC`, 4 KiB blocks, 255-byte names), on macOS a local, writable, case-sensitive APFS volume at `/` (`f_fstypename` `apfs`, `MNT_LOCAL` without `MNT_RDONLY`, the same block geometry, `f_fsid` the device `stat` reports beside the type) whose pipes, sockets and kqueues are `EINVAL` as XNU's `file_vnode` answers; a missing path is `ENOENT`, a bad descriptor `EBADF`. The profile is a constant, so it is identical on record and replay and on every host; left unmodeled the call reached the HOST with a virtual path or descriptor and the engine refused to open at all. Being shim-defined, neither appears as an import. Darwin's `fsctl`, which SQLite's AFP locking reaches only on an afpfs volume, is a deny-trap (`filesystem`). | not an import (strong def) | `native_fs_surface_answers_from_the_deterministic_filesystem` (e2e, its Linux volume leg: magic / block size / name length, `ENOENT`, `fstatfs` parity, `EBADF`); `darwin_statfs_describes_the_one_volume` (e2e, macOS: type name, local and writable flags, block size against `st_blksize`, `f_fsid` against `st_dev`, path/descriptor/directory/root parity, `ENOENT`, `ENOTDIR`, `EINVAL` for a pipe, `EBADF`) |
| — | **Host introspection (macOS Mach/BSD/IOKit)** | `sysctl`/`sysctlbyname`, `getrusage`, `task_info`, `mach_task_self_`, `mach_host_self`, `host_statistics64`, `host_processor_info`, `vm_page_size`, `vm_deallocate`, `proc_listallpids`/`proc_pidinfo`/`proc_pid_rusage`/`proc_pidpath`; IOKit `IOServiceMatching`/`IOServiceGetMatchingServices`/`IOIteratorNext`/`IOObjectRelease`/`IORegistryEntryCreateCFProperty`/`IORegistryEntryGetName` — the `sysinfo` / `num_cpus` / hardware-inventory surface | **split by whether a normal startup reaches the symbol** (generalizing the process-spawn deny-trap doctrine, row e). The hardware-inventory surface a `sysinfo`/`num_cpus` guest links — `host_statistics64`/`host_processor_info`, `mach_host_self`, `proc_listallpids`/`proc_pidinfo`/`proc_pid_rusage`/`proc_pidpath`, `vm_deallocate`, `IOServiceMatching`, plus the data symbols `mach_task_self_`/`vm_page_size`/`kIOMasterPortDefault` (fixed deterministic values — a data read cannot be trapped) — is now **deterministic-model interposed** (macOS): a runtime abort is not "support", so where the API admits an honest answer the strong shim def returns it and a guest that EXERCISES the inventory runs deterministically (a locked-down host with an empty inventory). `mach_host_self` → fixed synthetic port; `host_statistics64(HOST_VM_INFO64)` → fixed 8 GiB VM stats; `host_processor_info(PROCESSOR_CPU_LOAD_INFO)` → a an idle load block per virtual CPU (so `System::cpus().len()` is the run's `--cpus`, consistent with `sysctl HW_NCPU`); `proc_listallpids` → the guest and init; `proc_pidpath`/`proc_pidinfo`/`proc_pid_rusage` → the guest's fixed identity (init: `EPERM`) / graceful "not modeled" degradation; `IOServiceMatching` → `NULL` (sysinfo reports CPU frequency unknown); `vm_deallocate` → `KERN_SUCCESS` no-op. The IOKit registry-walk helpers the `NULL` `IOServiceMatching` makes unreachable — `IOServiceGetMatchingServices`/`IOIteratorNext`/`IOObjectRelease`/`IORegistryEntryCreateCFProperty`/`IORegistryEntryGetName` — stay **deny-trap interposed** (each documented unreachable-by-construction; a genuine direct call `abort()`s deterministically naming the symbol). Only the **live-path** members a normal startup actually reaches — `sysctl`/`sysctlbyname`/`getrusage`/`task_info` — stay uninterposed and **refused** pre-run (a strong def would silently swallow a path startup uses; a deterministic interposer is a tier-3 item). Both read host CPU/memory/hardware/process state — nondeterministic across hosts and runs: **interpose-or-refuse, never allowlist.** Classification is unchanged and stays load-bearing: `host-introspection` (the exact Mach/BSD name list plus the IOKit prefixes `IOService`/`IORegistry`/`IOIterator`/`IOObject` — deliberately not a bare `IO`) labels a raw import from a **prebuilt non-shim binary**, which links no shim so nothing drops off — it always refuses. Fail-closed either way. | converted members → not an import → **deterministic model**; unreachable IOKit helpers → not an import (deny-trap) → **runtime abort**; live-path members / prebuilt-raw → import audit → `host-introspection` | `host_inventory_surface_is_deterministic` (macOS e2e — a guest exercising `mach_host_self`/`host_statistics64`/`host_processor_info`/`vm_deallocate`/`proc_listallpids`/`IOServiceMatching` prints `vm=0 cpu=0 ncpu=4 pids=2 iokit_null=true` at the default `--cpus`, byte-identical) + `native_run_deny_trap_aborts_a_guest_that_reaches_host_introspection` (macOS e2e — a guest reaching the still-trapped `IOServiceGetMatchingServices` aborts, naming it, byte-identical) + `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (a dormant `sysinfo`-shaped path runs allowance-free); `the_pure_compute_allowlist_does_not_capture_effectful_neighbours` (unit — representative Mach/BSD/IOKit sample classifies; `sysctlbyname` stays denied; a user `IOWidget` does NOT match; `IO`-prefix overreach guarded); the real `sysinfo` `System::new_all()` MRE runs to completion (`cpus=4` at the default `--cpus`) with only its live-path audit residual (`sysctl`/`sysctlbyname`) |
| — | **macOS system frameworks (CoreFoundation / Security)** | `CFArrayCreate`/`CFStringGetLength`/`CFDataGetBytePtr`/`kCFAllocatorDefault`/`kCFTypeArrayCallBacks`; `SecCertificateCopyData`/`SecTrustSettingsCopyCertificates`/`SecCopyErrorMessageString` — the `rustls-native-certs` / `security-framework` / `chrono`-timezone / native TLS trust-root surface | **enumerated dormant symbols deny-trap at call time; the remainder refuse pre-run** (generalizing the process-spawn deny-trap doctrine, row e). The enumerated dormant surface — the CoreFoundation helpers (`CFArray*`/`CFString*`/`CFData*`/`CFTimeZone*`/`CFRetain`/`CFRelease`/`CFEqual`/`CFNumberGetValue`/`CFDictionaryGetValueIfPresent`/`CFGetTypeID`), the Security readers (`SecTrustSettingsCopy*`/`SecCertificateCopyData`/`SecCopyErrorMessageString`), plus the data symbols `kCFAllocatorDefault`/`kCFAllocatorNull`/`kCFTypeArrayCallBacks` (fixed values — a data read cannot be trapped) — is now split between **deterministic-model** and **deny-trap** interposition (macOS): a strong shim def binds each reference at link so a binary that merely LINKS the optional TLS-trust / timezone path RUNS (the symbol drops off the import table), and where the API admits an honest answer the def RETURNS it so a guest that EXERCISES the path also runs deterministically. `SecTrustSettingsCopyCertificates` → `errSecNoTrustSettings` (so `rustls-native-certs`'s `load_native_certs()` yields zero certs/zero errors — a locked-down host); the empty-array helpers it then drives (`CFArrayCreate`/`CFArrayGetCount`/`CFRelease`, on synthetic tokens) are honest; the timezone path `CFTimeZoneResetSystem`/`CFTimeZoneCopySystem`/`CFTimeZoneGetName`/`CFStringGetCStringPtr` reports `UTC` (the single fixed timezone the runtime models, matching `localtime_r`), so `iana-time-zone`/`chrono::Local` resolve UTC deterministically. The per-cert / error-format / string-builder helpers those honest returns make unreachable — `SecCertificateCopyData`/`SecTrustSettingsCopyTrustSettings`/`SecCopyErrorMessageString`, `CFArrayGetValueAtIndex`, `CFRetain`, `CFEqual`/`CFNumberGetValue`/`CFDictionaryGetValueIfPresent`/`CFGetTypeID`, `CFString{CreateWithBytesNoCopy,CreateWithCStringNoCopy,GetBytes,GetLength}`, the `CFData*` accessors — stay **deny-trap interposed** (each documented unreachable-by-construction; a genuine call `abort()`s deterministically naming the symbol). Any **non-enumerated** `CF*`/`kCF*`/`Sec*`/`kSec*` symbol, and every framework symbol in a **prebuilt non-shim binary** (which links no shim), stays **refused** pre-run. The Security readers touch the host keychain / system trust store — mutable per-machine, per-time host state — so a run reaching one is not reproducible; the CoreFoundation helpers are the plumbing those calls require. Classification is unchanged and stays load-bearing: `macos-framework` (Apple-reserved prefixes `CF`/`kCF`/`Sec`/`kSec`) labels the still-refused remainder with a determinism note naming the host-trust-store problem and the `--allow-unsupported-symbols` allow path (qualified determinism). Fail-closed either way. | converted members → not an import → **deterministic model**; unreachable helpers → not an import (deny-trap) → **runtime abort**; remainder / prebuilt-raw → import audit → `macos-framework` | `native_trust_root_surface_is_deterministically_empty` (macOS e2e — the `SecTrustSettingsCopyCertificates`+empty-`CFArray` sequence prints `certs=0 errors=0`, byte-identical) + `local_timezone_surface_reports_utc` (macOS e2e — the `CFTimeZone*`/`CFStringGetCStringPtr` sequence prints `tz=UTC`, byte-identical) + `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (a dormant `rustls-native-certs`-shaped path runs allowance-free); `native_gate_classifies_and_refuses_a_security_framework_symbol` (macOS e2e — a non-enumerated `SecTrustEvaluateWithError` still refuses with note + audit/run parity); `decorated_symbols_classify_as_their_base_name` (unit — the certs surface classifies); the real `rustls-native-certs` `load_native_certs()` MRE runs to completion (`certs=0 errors=0`) and the chrono MRE audits CLEAN |
| — | **Load-set bindings (Linux ELF)**: a reference that binds into host code | a weak reference to a libc export nothing interposes (`getloadavg`), which binds to libc's code at load; a library's own call into libc (`libfoo.so: getloadavg`), however far from the executable; a library's `write` bound past an executable whose version script hid the shim's; a library's weak `dlsym`. Inert by the same rule: aws-lc's allocator-override hooks `OPENSSL_memory_*` and `sdallocx`, which nothing defines | **refused by name, or inert.** The pre-run gate and `audit` enumerate the images the program's loader maps (`PT_INTERP --list` under the guest's empty environment) and judge every reference of the executable and of every application library by where the loader binds it: the first image in search order (the executable, then dependencies breadth-first) defining the name at an acceptable version. Bound to an audited image (the executable, the shim's doors in it, an application library) it is contained; a weak reference no image defines is NULL and listed under `inert weak imports`; bound into a host image (the loader, glibc's own libraries, the vDSO) it runs host code and is admitted only by the effect allowlist, by name, with the provider named in the refusal; a strong reference nothing defines, or a provider that defines the name outside the modeled version subset (`crate::bindings`), is refused by name. No list of names decides containment. Application libraries' code is scanned as the executable's is, so a C++ guest over the shared `libstdc++` is refused for that library's own host bindings (`setlocale`, `fopen`, ...) and its `rdrand`; link it `-static-libstdc++`. Refused before the loader runs anything: `DT_AUDIT`/`DT_DEPAUDIT` (audit modules run even while listing), filter objects, a host preload list (`/etc/ld.so.preload`, searched before every dependency) and an image the loader maps that no dependency names; refused before the guest runs: a library linked `-z initfirst` and an IFUNC resolver in an audited image, both of which run before the shim's preinit entry. Each library's digest joins the gate's verdict key and the trace's build identity, so a replay against another libc is refused. **macOS** does not resolve dylibs yet: every Mach-O import is judged by name as one binding into a dylib, so a weak import is refused rather than inert, and a dylib's own references are not audited (tracked) | load-set binding audit → the binding's class, `unresolved-import`, `undecidable-binding`, `early-init`; **inert** listed | `native_containment::{a_weak_reference_is_inert_only_when_no_loaded_library_defines_it,load_set::*}`; unit `native_audit::tests::*` |

Beyond the per-class classifier unit test, a batched end-to-end test builds one guest that reaches an
uninterposed symbol of each plantable class and asserts `native-run` refuses it
pre-exec with every class label present — so no class's end-to-end gate path can
rot silently. (`environment` and `unmanaged-thread` have no plantable
shim-linked member; see the table's residual column.)

Interposed-and-supported surfaces never appear as imports (they are *defined* by
the shim), so they are automatically not flagged — this includes `setsockopt`
`SO_RCVTIMEO`, `sched_yield`, the dispatch-semaphore Parker, positional
`pread`/`pwrite`/`preadv`/`pwritev`, the advisory `flock` and `fcntl` record
locks, `statfs`/`fstatfs`, and the whole FS/time/entropy/pthread surface.

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

SQLite's Darwin build (the amalgamation's `__APPLE__` code: zone malloc, AFP and
proxy locking) surfaced four more known-safe groups:

- **`atoi`** — `strtol` in base 10 with no end pointer.
- **`__strlcpy_chk`, `__strlcat_chk`** — the fortified bounded copy and append:
  caller memory only, like `strcpy_chk`.
- **`malloc_create_zone`, `malloc_default_zone`, `malloc_set_zone_name`,
  `malloc_zone_malloc`, `malloc_zone_realloc`, `malloc_zone_free`** (Mach-O) —
  libmalloc's zone interface, the process heap exactly as `malloc` is.
- **`random`** (Mach-O) — libc's generator over process-local state, with a
  fixed initial state. The one host input it could take, `srandomdev`'s seed,
  is the shim's: `srandomdev` draws it from the run's entropy stream and seeds
  libc through its own `srandom`. Its reseeding siblings (`srandom`,
  `initstate`, `setstate`) stay refused.

The same sweep's `gethostuuid` is modeled (the machine's fixed UUID), and
`srandomdev` labels as `entropy` and `gethostuuid` as `host-introspection` when
a binary without the shim imports them. Same-seed draws are identical,
another seed's differ, and the UUID is fixed.

The glibc side of the same sweep also met **`__assert_fail`**, glibc's
`assert()` failure hook, which aws-lc's asserts lower onto. It is not
known-safe: libc's hook writes through libc's `stderr`, and in a shim-linked
guest that global is the shim's sentinel, so the hook crashed on it. The shim
defines it instead (glibc's message on the stream, then a guest `abort`), as it
defines Darwin's `__assert_rtn`, so neither is an import of a linked guest, and
an import of either means the link lost the definition: `unknown-import`.

And three data words ld.so exports, once the shim took over the area they
describe:

- **`__rseq_offset`, `__rseq_size`, `__rseq_flags`** (ELF only) — where each
  thread's restartable-sequence area sits from the thread pointer, its size
  and its flags, set by ld.so before any constructor and constant after. The
  area itself is the virtual kernel's: every thread's host registration is
  taken over when its task starts, so the area reads the virtual CPU and the
  host never writes it. The shim cannot define these words (ld.so owns them),
  so they are audit entries rather than symbol rows.

### Normalization: glibc C-standard alias generations

glibc keeps a distinct alias for every function whose signature or semantics
changed between C standards, and the *compiler* picks which one the object
references: a C23 build's `sscanf` becomes `__isoc23_sscanf`, a C99 build's
`scanf` becomes `__isoc99_scanf`. The name in the import table is a
build-configuration artifact of the same libc entry point, so the audit strips
the `isoc<digits>_` generation before lookup and classifies the base symbol.

This is normalization in the same family as the Mach-O leading underscore and the
Darwin `$NOCANCEL` suffix — not an allowance. The base still goes through the
full classification path, so `__isoc99_scanf` stays denied (`scanf` touches a real
stream) and `__isoc23_open` reports `filesystem`, not a bare unknown import. It
retires one workaround: the shim's `getaddrinfo` hand-rolled its numeric-service
parser to avoid `strtol` resolving to the then-refused `__isoc23_strtol`. That
reason is gone; the parser stays only because a digits-only parse is
locale-independent, which `strtol` is not.

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

- **Process-spawn family** (`fork`, `posix_spawn*`, `execvp`) —
  **deny-trap interposition**: a strong shim C definition that aborts
  deterministically with a diagnostic if ever reached. The process class is a
  deterministic-runtime non-goal, so a guest that genuinely spawns must fail
  loudly and reproducibly, never escape silently. Being shim-*defined*, these
  drop off the import table, so the audit needs no allowance for them — and the
  run gains a *runtime* guarantee (see row **e**).
  The credential and session calls a spawn helper makes on the way
  (`setsid`/`setgid`/`setuid`/`setpgid`/`setgroups`) are not part of it:
  they are modeled against the one unprivileged identity (the own ids and the
  own group succeed and change nothing; everything else is refused as the
  kernel refuses an unprivileged caller). So is `chroot`, which answers as the
  kernel answers the virtual credential (on Linux the path checks, then
  `EPERM`; on macOS `EPERM` first, as XNU checks the superuser before the
  path).
- **Framework / host-introspection families** (the `rustls-native-certs`
  CoreFoundation/Security surface, the `chrono` timezone `CFTimeZone*` surface, and
  the `sysinfo` Mach/BSD/IOKit host-inventory surface, incl. `if_nametoindex`) —
  interposition generalized to the TLS-trust / timezone / hardware-inventory paths a
  large binary commonly links. A strong shim def (macOS-gated where the symbols are
  Darwin-only) binds each reference at link so the binary RUNS whether the path is
  dormant OR live (the symbol drops off the import table), and — because a runtime
  abort is not "support" — wherever the API admits an honest deterministic answer
  the def **returns it** (`deterministic-model` interposition): empty native trust
  roots (`load_native_certs()` → 0 certs), a UTC `chrono::Local`, a fixed 1-CPU /
  8 GiB / single-process `sysinfo` inventory, `if_nametoindex` → `ENXIO`. The
  helpers those honest returns make unreachable by construction stay **deny-trap**
  interposed (each documented; a genuine call aborts deterministically naming it);
  the un-trappable data symbols
  (`kCFAllocator*`/`kCFTypeArrayCallBacks`/`mach_task_self_`/`vm_page_size`/
  `kIOMasterPortDefault`) get fixed deterministic values. This is what unblocks an
  unrelated scenario without the whole-run `--allow-unsupported-symbols`
  determinism downgrade (native audit/run blockers Issues 1–2) AND lets a guest that
  genuinely exercises the surface run deterministically. The live-path members a
  normal startup reaches (`sysctl`/`sysctlbyname`/`getrusage`/`task_info`) and every
  non-enumerated framework/Mach symbol stay refused (see rows for host-introspection
  and macOS frameworks).
- **Host-state queries** (`gethostname`, `getpwuid_r`, `__NSGetExecutablePath`) —
  interposed to the virtual machine's fixed values, exactly like `isatty`/`confstr`
  (host-state-query row).
- **Pure compute** (`memset_pattern4/8/16`, `sigemptyset`/`sigfillset`/
  `sigaddset`/`sigdelset`/`sigismember`) — added to the known-safe allowlist:
  they touch only caller-owned memory (a byte pattern buffer; a `sigset_t`) with
  no boundary effect.
- **`dlsym`** — reconciled with the host-alias doctrine, not with this pivot:
  on macOS `dlsym(RTLD_NEXT, ...)` is now the shim's own host-vehicle resolution
  primitive, so it is baked into `shim_control_plane_symbols` and the pre-run
  gate tolerates it as control-plane rather than as an escape — it drops off the
  CLI guest's allow list for that reason, not because it is interposed to nothing.
  **What a guest `dlsym` *call* does, per platform (the honest residual):** on
  **Linux** the shim interposes `dlsym` (via `-Wl,--wrap=dlsym`), so a guest call
  resolves either nothing or one of the shim's own implementations from the
  routing table — never a host symbol, and
  deterministic either way. `--wrap` rewrites only *unversioned* references,
  though: a `.symver`-pinned `dlsym@GLIBC_…` stays an undefined versioned import
  the loader binds to the real resolver, around the wrap. The version-aware audit
  closes that by refusing any GLIBC-versioned undefined import of the resolver, or
  of an interposed name the executable does not export (the
  Versioned-symbol-bypass row), admitting only the shim's own
  weak `dlsym@GLIBC_2.34` vehicle. On **macOS** `dlsym` is *not* interposed: a
  guest call reaches the real dyld resolver (nondeterministic), so a guest whose
  own code reaches `dlsym` is a real escape. Interposing `dlsym` on macOS is
  infeasible while the shim uses it for resolution — a strong-def interposer in
  the guest image would capture the shim's own `dlsym(RTLD_NEXT, ...)` calls
  (`__interpose`/`DYLD_INTERPOSE` does not swap same-image callers, verified), so
  the shim would lose its resolver. Static **reachability** does not close it
  either: address-taken-`main` swallows the call-graph closure (see "Why
  symbol-reachability, not static call-graph reachability" above) and std itself
  has `dlsym`-probing paths, so a reachable-`dlsym`-denial would reject every std
  guest. So the residual stays: the spawn family is strong shim defs
  (deny-traps) and `dlsym` searches the main image first, so a guest
  `dlsym("fork")` resolves to the deny-trap and aborts deterministically. What
  remains is a guest `dlsym` of a blocked symbol the shim does *not* strong-def
  (e.g. macOS `killpg`). That needs a guest that hand-writes `dlsym(...)`: no
  user object or sysroot rlib references `dlsym` on macOS, so the shim's own
  `dlsym(RTLD_NEXT, ...)` resolver is the only caller in an ordinary guest. A
  link-time redirect of guest `dlsym` references is not implemented: it would
  replace the single `rustc` compile+link with a manual relink and require
  `llvm-tools`, for no measured benefit.

The net effect on the audited CLI guest is the allow list emptying to nothing
while the gate stays fail-closed for any *new* unsupported import — strictly better than the
named downgrade on both axes (unqualified audit **and** a runtime spawn guard).

## Executable sections containing code and data

Relocatable ELF (`ET_REL`, normally `.o`) inputs always refuse with a named
reason: an object file is not a runnable guest. This applies even without CFI
or `.rela.eh_frame`; ordinary objects also carry unresolved unwind relocations.
Link an executable before audit/run.

The x86-64 ELF instruction scan trusts **declared code extents**, not that every
byte in an executable section is an instruction. It scans each defined function
symbol's sized range and each `.eh_frame` FDE range from its own start. Both
sources contribute; neither can shrink the other's coverage. Overlapping ranges
are scanned independently and duplicate findings are coalesced. Defined NOTYPE
labels (including labels inside operands) and zero-sized functions establish
independent entries: scan to each containing declaration's end, or to the next
known entry/section end in a gap. An internal label does not extend its function
into trailing data. A truncated/undecodable instruction
inside any range refuses, even after a `ret`; a later function is still scanned
from its own start. Invalid range metadata, unresolved function section indices,
indirect FDE addresses and relocations targeting `.eh_frame` refuse rather than
falling back to a narrower source or mistaking pointer storage for code. REL/RELA
tables are read fallibly, including dynamic targets; malformed tables and packed
relocation formats (RELR/CREL/Android) refuse because their effect on unwind
storage is not established here. There are no dependency names, recognized strings or
skip-on-decode-error rules in this policy.

A section may omit uncovered gaps only if it has a nonzero-sized STT_FUNC in
ordinary `.symtab`. Without one, the old whole-section fail-closed walk is added
alongside independent entry walks. FDEs and `.dynsym` exports alone are not a
code inventory: ordinary C/assembly and Go toolchains leave functions without
unwind records. Stripped code/data mixtures can therefore refuse, as they did
before range scanning. Source-first native builds preserve the final artifact's
symbols for audit and execution; prebuilt inputs are audited as supplied.
Mach-O keeps its whole-section policy.

Where gaps are omitted, that admits compiler-generated alignment and assembly
metadata but **does not prove gaps unreachable**. Lying or too-short function
sizes, omitted functions in otherwise symbol-bearing sections, jumps/fallthrough
into gaps or operands at undeclared entries, and runtime-generated code remain
static-discovery residuals. A future detector may close them; they are not safe
by definition.
This is a bounded audit for compiler/linker output, not an adversarial native-code
validator. It also trusts ELF section metadata to agree with the loaded image;
contradictory program-header/dynamic-loader tables are not reconciled here.
Runtime backstops do not make the metadata assumption sound:

| Instruction class | Residual in unscanned gaps/operands or runtime-generated code |
|---|---|
| x86 raw `syscall` | Active SUD in a supported x86-64 Linux shim intercepts it regardless of static discovery. The i386 `int 0x80`/`sysenter` ABI aborts rather than being modeled. Startup before traps, other platforms and unshimmed raw audits do not have this guarantee. |
| x86 `rdtsc`/`rdtscp` | Active `PR_SET_TSC` in the x86-64 Linux shim traps reads: supported main-executable sites are virtualized; out-of-image/generated counter sites are named stops. No protection before arming or on other platforms. |
| x86 `rdrand`/`rdseed` | No runtime trap. An executed unscanned instruction can read host entropy. |
| TLS-base writes and x86 far transfers | No runtime trap. Unscanned code can change the shim's TLS base or enter a mode the decoder does not describe. |
| `cpuid`/PKRU | Visible-not-refused where discovered, unmanaged at runtime; unscanned sites also lose that diagnostic. |
| x86 vsyscall address | The separate address-pattern detector still examines the entire text section, including gaps. SUD cannot trap vsyscall; computed addresses and generated code remain outside this static pattern detector. |
| aarch64 `svc`, counter/entropy reads and TLS writes | Unchanged: every aligned word in text is scanned, ignoring function metadata. Data words can falsely match opcodes, but cannot desynchronize the next word. Counter/entropy/TLS accesses have no trap; raw `svc` is not SUD-managed on arm64. |

These limits complement the existing jump-into-operands, shared-library and
runtime-generated-code limits below. A clean instruction audit never proves
arbitrary code is deterministic.

## Residual gaps (honest, symbol audit cannot see these)

Symbol reachability cannot observe behavior that never resolves a symbol. These
are **out of scope for this gate by design** (we do not disassemble for
data-flow); where another mechanism covers them it is named, otherwise the gap
is stated plainly:

1. **Raw syscall instructions inlined in the binary** (`svc #0` / `syscall`).
   Covered on **Linux** by the whole-run `strace` containment pass in
   `native_trace::std_whole_run_and_planted_openat_use_identical_filter` (every file/net/clock/entropy/descriptor syscall in
   the run must match the loader/std prelude shape) and partially by
   `scan_instruction_classes` (aarch64/x86_64 syscall opcodes are rejected at
   audit time). **Honestly absent on macOS**: per VALIDATION.md
   (Known gaps), no root-capable SIP-compatible whole-run tracer can separate
   the loader prelude from post-init guest syscalls, so an inlined post-init raw
   syscall on macOS is not caught by a runtime gate — static instruction scanning
   plus the import audit are the macOS evidence.
2. **Commpage / vDSO time reads.** `mach_absolute_time` and `clock_gettime` fast
   paths can read a kernel-mapped page without a syscall or an import. Covered by
   the libc-interposition probes (the interposed `clock_gettime`/`mach_absolute_time`
   are what std actually calls), not by the audit; a hand-rolled commpage reader
   that bypasses libc is a residual.
3. **Instruction-level entropy / time** (`rdrand`/`rdseed`/`rdtsc`/`rdtscp` on
   x86_64, `mrs CNTVCT_EL0`/`CNTVCTSS_EL0` and `mrs RNDR`/`RNDRRS` on aarch64, raw
   `svc`/`syscall`). `scan_instruction_classes` decodes all of these:
   `rdtsc`/`rdtscp` are trap-managed on x86-64 Linux,
   `rdrand`/`rdseed`/`CNTVCT`/`CNTVCTSS`/`RNDR`/`RNDRRS` refuse everywhere, and
   `cpuid` is reported visible-not-refused (host-identity). Thread-pointer writes
   (`wrfsbase`, FS selector loads, `msr tpidr_el0`) are refused in the same scan.
   The i386 syscall entries (`int 0x80`, `sysenter`) and the far transfers
   that could switch to 32-bit code are refused when discovered too. The
   declared-code policy above bounds x86-64 ELF coverage. Other residuals are encodings
   the decoder does not know, which refuse only when they sit at a decode
   boundary the scan reaches; a switch to 32-bit code with no far-transfer
   instruction (a signal handler that rewrites the saved CS in its `ucontext`
   before `rt_sigreturn`); instructions reached only by a jump into the middle
   of another instruction, which the linear sweep never decodes (a guest built
   to hide an instruction can do this; ordinary compiler output does not); code
   outside the scanned images: on Linux the scan reads the executable and every
   application library its loader maps, not glibc's own libraries, the loader or
   the vDSO (the host's code); on macOS it reads the executable alone, not its
   dylibs; and code created at run time (JIT output,
   pages made executable after load), which no static scan sees.
   The conservative counterpart is executable-section data: native crypto
   assembly can put an attribution string after a function's return, outside
   its symbol extent but inside `.text`. The linear sweep decodes that data and
   may stop with `undecodable-instruction`, refusing otherwise ordinary HTTP/TLS
   test harnesses before any test runs. `text_metadata_probe.rs` in the native
   boundary testbed is a native-passing, audit-refused reduction. This is a
   known limit: do not skip symbol gaps, unknown bytes, or named dependency
   functions without a containment design that accounts for reachable code.
   For the classes
   no trap backs (thread-pointer writes, far transfers, `rdrand`/`rdseed`/
   `CNTVCT`/`CNTVCTSS`/`RNDR`) that last case has no run-time backstop either.
4. **Flag-dependent behavior of an allowlisted symbol.** `mmap` is
   allowlisted as process-local memory and the audit cannot see its
   `MAP_SHARED` flag. A guest linked with the POSIX layer binds `mmap` to the
   shim on both platforms (anonymous memory is the host's; a mapping of a
   descriptor is a view of a modeled file's page cache). The allowlist entry
   covers a guest linked without it (the C-ABI staticlib mode), whose mapping
   of a descriptor number the host happens to have open is not refused by any
   gate. Stated, not papered over: `mmap` is deliberately **not** in the
   `shared-memory-ipc` list (it would be a dead label, since the allowlist
   wins first).
5. **Interposed-but-unsupported symbols.** A symbol the shim *defines* to
   fail-closed at runtime (e.g. macOS `pthread_cancel`
   and any not-yet-modeled interposer) is not an import, so the symbol audit
   cannot distinguish it from a fully-modeled one. These do not escape silently —
   they return `ENOSYS` with a loud `patina: … failing closed` diagnostic at call
   time (`patina_posix_deny`) — but the *pre-run* gate does not flag them. This is
   why `pthread_rwlock_*` was made a real deterministic implementation rather than
   left as an `ENOSYS` stub, and why the environment functions (`putenv`
   included) were later modeled over `environ` rather than left refusing: a
   commonly-reached primitive should be supported, not silently pass the gate
   and then fail at runtime. A member stays fail-closed only when the semantics
   genuinely cannot be modeled.
   Timestamp/ownership mutation on named FIFO endpoints reaches retained inode
   state, including after unlink; anonymous pipe/socket/stream descriptors
   without modeled filesystem inodes refuse loudly instead of dropping effects.
   Timestamps are signed: a pre-epoch or out-of-range time is truncated to the
   filesystem's range, as the kernel does. Allocation is untracked: st_blocks and
   stx_blocks count a file's length, and SEEK_DATA/SEEK_HOLE see no holes.
   The symbol registry (`crates/patina-syscalls/src/symbols.rs`) enumerates
   this surface: every public symbol the shim defines carries a status —
   `Modeled`, `Partial` (a subset modeled, the rest refuses loudly),
   `Deny(class)` (the deny-traps), `ControlPlane`. A spelling the shim does not
   define has no row, and a guest importing it is audit-refused.
   `cargo patina syscalls` prints the registry, and an object-scan gate fails
   when a symbol is defined without a row or a row names a symbol the shim does
   not define — so the shim's public surface is enumerated and cannot grow
   silently.

   Linux key retention is similarly bounded, not host passthrough: the run has
   an empty session and an initially empty per-run persistent ring, supporting
   the Rust keyutils password lifecycle. Invalidation removes every link and
   frees the key and quota immediately, choosing 6.8's immediate-collection
   interleaving. User/user-session/thread rings, all joins, UNLINK, SEARCH with a
   destination, arbitrary nested rings, unsupported keyctl operations (SETPERM
   and SET_TIMEOUT included), persistent expiry, last-process-holder collection
   and revoked-key collection after gc_delay stop by name. `sys/keys_session` supplies the live oracle and strace check;
   `native_workloads::keyutils_password_lifecycle_is_isolated_and_replayable`
   plants host-session canaries, proves the native guest fails on them, and
   checks virtual fresh-run absence and repeat/replay.
   No host key or serial is read. See the
   [source evidence](../../testbeds/native-boundary/keyring-keyutils/README.md).

6. **Host-identity reads on aarch64.** The x86-64 half is covered — `cpuid` is
   decoded and reported under the host-identity row above — but the arm64
   analogues (`mrs Xt, MIDR_EL1`, `REVIDR_EL1`, and the `ID_AA64ISAR*` feature
   registers, whose EL0 reads Linux emulates) are not decoded, so an arm64 guest
   branching on which core it runs on is as silent today as `cpuid` was. Same
   class and same disposition when it lands — reported, not refused. Stated here
   rather than left implied by the row's x86-only examples.

7. **Host memory management under guest memory (Linux).** Page residency is
   the host's decision. The shim removes what it can — transparent huge pages
   are disabled at startup (`PR_SET_THP_DISABLE`), locks are the shim's own
   bookkeeping against a virtual `RLIMIT_MEMLOCK`, the hugetlb pool is
   virtually empty — but host reclaim and swap can still evict a page the
   guest touched, so `mincore` (a passthrough on the guest's own memory) and
   the residency `move_pages` reports can read a page absent that a quiet host
   would show present. A guest branching on residency is deterministic on a
   host with memory to spare, not under memory pressure.

8. **Host descriptors behind guest mappings.** Every page cache (one per
   mapped file) and, on Linux, every System V segment is a host page file the
   shim holds: a memfd on Linux, an unlinked file in the per-user temporary
   directory on macOS. So the host's `RLIMIT_NOFILE` bounds how many a guest
   can have at once, and on macOS the temporary directory's volume bounds
   their size. On Linux the shim raises the host soft limit to the hard limit
   at start; on macOS it leaves the soft limit as the host set it. A page
   file the host still refuses, or cannot grow, stops the run by name — the
   guest never sees the host's `EMFILE` or `ENOSPC` where the modeled kernel
   would succeed. A host with a low limit therefore runs fewer mappings, and
   says so, rather than answering differently.

   On macOS two more answers are the host's or refused. Mappings are in the
   host's pages, 16 KiB on Apple silicon, while the virtual machine's page
   (`sysconf(_SC_PAGESIZE)`, `vm_page_size`) is 4 KiB: a file mapping at an
   offset or fixed address that is not a multiple of the host page is the
   host's `EINVAL`, and a file's zero-filled tail before `SIGBUS` runs to the
   end of a host page. `msync(MS_KILLPAGES)` over a shared file view is
   refused by name (`ENOSYS`): it would discard the view's changed pages for
   what the host last wrote of the page file, on the host's schedule.

9. **Control transferred into glibc's executable segment (Linux).** SUD's
   allowed region is glibc's text, where the shim's own host calls run, so a
   syscall instruction there is not trapped. A guest that jumps into that
   segment (an indirect jump, or a crafted signal frame whose saved
   instruction pointer lands there) runs whatever host syscall it finds
   unfiltered. That is adversarial-only: legitimate code reaches glibc's
   syscalls through its exported functions, which the shim interposes, and a
   frame's return address is legitimately inside glibc (the shim's own host
   call), so it cannot be filtered by address.

10. **During relocation (Linux).** The shim arms SUD, the timestamp-counter
    trap, the rseq takeover and the fault front from the main executable's
    `.preinit_array`, which glibc's `_dl_init` runs before any shared
    library's constructor (the pre-constructor row above). Code that runs
    earlier is contained by none of them: ld.so itself, and IFUNC resolvers
    (the executable's and its libraries'), which ld.so calls while it applies
    relocations. A resolver could read the timestamp counter or issue an
    untrapped raw syscall; compilers emit resolvers that only read CPU
    features.

11. **Host-library code without SUD (Linux).** The pre-run scan reads the
    executable and every application library the loader maps (the compiler
    runtimes `libstdc++` and `libgcc_s`, third-party and application
    libraries), from the images the program's own loader lists, so an inline
    syscall in any of them is refused before the guest runs. It does not read
    glibc's own libraries, the loader or the vDSO: that code is the host's,
    reached only through the imports the effect policy admits by name. Where
    the kernel has no SUD (arm64 kernels up to 6.18, x86-64 before 5.11), a
    host library's syscall inside an admitted call is not trapped, which is
    the allowed region on every kernel. A library the loader maps from another
    path at run time than at the audit (a changed `/etc/ld.so.cache`) is
    caught by its digest in the verdict key and the trace identity, not
    re-scanned in flight.

12. **Host addresses.** A pointer's value is host state that no import names.
    The supervisor removes what the kernel decides (ARCHITECTURE.md, "Address
    layout"): randomization is off, the Linux stack limit is the modeled one,
    and the initial stack has one size in every mode, and the shim refuses a
    run whose host ignored the request
    (`native_containment::layout`). A host that forbids the request refuses
    the run unless the operator passes `--allow-randomized-address-layout`,
    which keeps the host's layout and qualifies the run (see below).
    On Linux the runtime allocates from an arena of its own, off the guest's
    heap, so heap and mapping addresses are the same in a seeded run, a
    recording and its replay. On Darwin, libmalloc randomizes the heap from
    exec-time kernel entropy, and the runtime shares it. A guest that branches
    on a heap address is deterministic on Linux and not at all on Darwin
    (VALIDATION.md, Known gaps).

## Escape hatch

`native-run --allow-unsupported-symbols <all|name,...>` downgrades matching
denials to a loud stderr warning and records them in a `<trace>.unsupported-symbols`
sidecar next to a `--record` trace, so a run that knowingly tolerates unsupported
surface (never reached by the scenario) is visibly qualified. A partial list
still fails closed on the un-listed symbols.

`--allow-randomized-address-layout` (every native verb that launches a guest:
`run`, `replay`, `test`, and `campaign` with its reproduce
commands) is the hatch for a host that forbids turning address-space
randomization off, such as Docker's default seccomp profile. The guest keeps
the host's layout, so its addresses are host state again (residual 12). The
run prints a warning, its result envelope carries a `randomized_address_layout`
qualification, and its trace records `address_layout: randomized`. A replay
must pass the flag exactly when the recording did, and for a trace that
predates the field, whose guest also ran randomized.
