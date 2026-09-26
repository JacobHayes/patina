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
interposed/allowlisted sets in `native_allowlisted_import` /
`shim_control_plane_symbols` (gating), all in `crates/patina-target/src/lib.rs`.

## Coverage matrix

| # | Escape class | Representative host symbols | How the deterministic runtime handles the supported surface | Detection mechanism | Permanent test |
|---|---|---|---|---|---|
| a | **Blocking / scheduling** | `os_unfair_lock_*`, `__ulock_wait/wake`, `__psynch_*`, `dispatch_semaphore_*`, mach `semaphore_wait/signal`, `os_sync_wait_on_address`; readiness: `poll`/`select`/`kqueue`/`kevent`/`epoll_*` | pthread mutex/cond, **`os_unfair_lock_*`** (macOS, lazily registered in the mutex table since the bare `u32` has no init call; misuse — recursive lock or foreign unlock — aborts loudly), the dispatch-semaphore Parker, and Linux futex are **interposed** and routed through `DetScheduler` (+ virtual clock for timed waits); `poll` is interposed for the modeled cases; **`kqueue`/`kevent`/`kevent64`** (macOS) are **interposed** by a deterministic in-process readiness reactor (EVFILT_READ/WRITE over virtual pipe/socketpair and SimNet socket fds, an EVFILT_USER Waker, EVFILT_TIMER on the virtual clock; multi-fd fan-in parks on the baton, deterministic `(ident, filter)` event order, no trace events of its own — unmodeled filters and readiness on real host descriptors fail closed loudly); **`epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_pwait`** (Linux) are **interposed** by the mirror frontend over the same readiness core (one interest per fd over the virtual pipe/socketpair, eventfd, and SimNet socket fds; EPOLLET latches keyed on per-direction *arrival sequences* so an edge re-fires per arrival exactly as the kernel does — mio's undrained eventfd Waker depends on it; millisecond timeouts on the virtual clock; deterministic fd-order events; kernel-faithful EEXIST/ENOENT from `epoll_ctl`; unmodeled event flags and non-virtual descriptors fail closed loudly; `epoll_pwait` uses the shared temporary-mask model; libc and SUD use the same `patina_epoll_*`/`patina_eventfd` entries) — so mio/tokio's IO driver runs under the scheduler on both platforms | symbol audit → `unmanaged-sync` / `wait-multiplex`; any uninterposed blocking symbol is an import → denied | `every_escape_class_is_detected_and_denied` (unit); `native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol` (Mach `semaphore_wait`, still uninterposed) + `native_workloads::os_unfair_lock_contention_is_repeatable`, `native_containment::os_unfair_lock_foreign_unlock_aborts`, `native_abi::darwin::{kqueue_reports_fields_and_wakes_reader,kqueue_user_events_wake_and_timeout_exactly}`, `native_abi::linux::{epoll_wakes_readers_and_refires_edges,eventfd_writer_wakes_epoll_waiter,epoll_timeout_advances_exact_virtual_time}`, and `native_workloads::tokio_signal_parking_lot_rustix_use_product_backend` |
| b | **Time** | `clock_gettime`, `clock_gettime_nsec_np`, `gettimeofday`, `mach_absolute_time`, `mach_continuous_time`, `nanosleep`, `clock_nanosleep`, `usleep`, `mach_wait_until`; host-timezone conversion `localtime_r`, `tzset` | the clock reads/sleeps are all interposed → virtual clock (`clock_gettime_nsec_np` shares `clock_gettime`'s clock-id mapping, returning nanoseconds directly). `localtime_r`/`tzset` render a `time_t` through the host timezone database / `TZ` (cross-platform, e.g. the `time` crate's local-offset lookup), so they read where the run happens: `localtime_r` is interposed (glibc's `TZ` rules over the virtual machine, which ships no zoneinfo: a POSIX rule string, UTC for an unset or empty `TZ`, and a named refusal for a zoneinfo file the guest planted where glibc would read it); `tzset` is **not interposed → refused**, classified `time` so the refusal names the host-timezone problem rather than a bare unknown import | symbol audit → `time` | `every_escape_class_is_detected_and_denied`; `classifies_ecosystem_audit_symbol_batch` (localtime_r/tzset on both formats); `native_abi::darwin::clock_nsec_matches_clock_gettime` |
| c | **Entropy** | `getentropy`, `getrandom`, `arc4random*`, `CCRandomGenerateBytes`, `SecRandomCopyBytes`; `/dev/urandom` fallback reads | interposed or modeled device → seeded RNG. Entropy is reached four ways and each funnels into the same `patina_entropy` stream: the public interposers (`getentropy` on both platforms, `getrandom` on Linux, `CCRandomGenerateBytes` on Darwin), the raw `SYS_getrandom` path (the `syscall` interposer and the SUD dispatch table), reads of the modeled `/dev/urandom` device, and — because the `getrandom` crate resolves its Linux backend dynamically rather than by linking — the **`dlsym` routing table** (see the dynamic-loading row). `/dev/random` is deliberately **not** modeled: with the routing table in place nothing reaches it (the `getrandom` crate polls it only from the `use_file` fallback it now never takes, and `std` opens it only when the `getrandom` weak symbol is absent, which the shim always defines), so it stays an ordinary absent path in the deterministic FS rather than speculative surface | symbol audit → `entropy` for raw imports; deterministic FS/device path for `/dev/urandom` | `every_escape_class_is_detected_and_denied`; `native_workloads::{rand_rng_is_seeded_and_replayable,urandom_device_is_seeded_and_replayable}` and `native_containment::dlsym_routes_only_seeded_entropy` |
| d | **Thread lifecycle** | `pthread_create`, `pthread_create_from_mach_thread_np`, `bsdthread_create`, `thread_create` | `pthread_create` is interposed by a strong def and spawns a managed task via a distinct non-interposed vehicle (macOS `pthread_create_suspended_np`; Linux the real glibc `pthread_create` resolved through `dlsym(RTLD_NEXT, ...)`) | symbol audit → `unmanaged-thread` | `every_escape_class_is_detected_and_denied`; `native_containment::audit_rejects_unlinked_raw_syscall_or_thread_escape` (planted raw-syscall/pthread C binary) |
| e | **Process** | `fork`, `vfork`, `exec*`, `posix_spawn*`, `system`, `popen`, `kill`, `waitpid`, ... | Subprocess creation remains a **non-goal**: the linked spawn family is deny-trap interposed, and uninterposed siblings remain import-audited. Linux `kill`/`killpg` and task-directed generation use the virtual signal model (self/group 0/±1, missing targets ESRCH); signal 0 only probes existence. Childless waitpid/waitid return ECHILD rather than touching the host. macOS retains its signal-0 liveness model. | uninterposed members → symbol audit → `process`; spawn family → runtime deny-trap; Linux self-signals → deterministic model | `native_run_deny_trap_aborts_a_guest_that_actually_spawns`; `run_package_dir_and_prebuilt_gate_deny_the_same_symbol` (`system`, uninterposed); `native_build_package_audits_records_and_fails_closed`; frozen signals-family process/generation tests; macOS `native_run_prerun_gate_refuses_every_escape_class` still plants uninterposed `killpg` |
| f | **Filesystem / network** | `open`/`openat`/`read`/`write`/`stat`/`fcntl`/`unlinkat`/`renameat`/...; `socket`/`bind`/`connect`/`send`/`recv`/... | interposed → deterministic FS and SimNet. Read-only directory opens return deterministic directory fds: `fstat` reports `S_IFDIR`, ordinary reads/writes still fail closed, and `fsync` on the fd is the CrashFs namespace-durability barrier. Every path resolves through one resolver in the shim: the modeled working directory for `AT_FDCWD` (`getcwd`/`chdir`/`fchdir` are modeled process state, not process-class traps), a Patina-issued directory descriptor's node otherwise, `..` and symlinks walked as the kernel walks them; the umask is modeled process state applied before the driver; unknown real dirfds still fail closed rather than escaping to the host. Metadata a guest can change is modeled, not synthesized: every entry carries atime/mtime/ctime/btime stamped by the kernel's rules from the virtual clock the runtime hands each driver operation (`FsClock`; `relatime` by default), the owner is the one modeled identity read through a single accessor (`chown`/`fchown`/`lchown`/`fchownat` accept its ids or -1 and answer `EPERM` for any other), and sizes change by name (`truncate`) and by descriptor (`ftruncate`, `fallocate`) as recorded operations. `acct(2)` — process accounting to a file, a privileged kernel-global effect — is defined on Linux (answered from the virtual credential: `EPERM`) and left uninterposed on macOS, where it is the class's planted representative in the gate e2e. | symbol audit → `filesystem` / `network` | `every_escape_class_is_detected_and_denied`; `classifies_native_import_decisions`; `native_abi::posix_at_paths_resolve_relative_to_directory_fds`; `native_directory_fsync_guards_namespace_durability_and_replays` |
| g | **Shared memory / IPC** | in-process: `pipe`, `pipe2`, `socketpair`, `eventfd`/`eventfd2`; cross-process: `shm_open`, `shm_unlink`, `mach_msg*`, `mach_port_*`, `bootstrap_look_up`, `mq_*` | **split by whether the escape leaves the address space.** `pipe`/`pipe2`/`socketpair` — both endpoints live inside the one guest process (an async runtime's IO-driver / signal self-pipe wakeup), so there is no cross-address-space escape: they are **interposed**: a pipe as a deterministic in-memory byte channel (bounded 64 KiB buffer, writes up to `PIPE_BUF` atomic, EOF on peer close, `EPIPE` on a broken write, preceded on Linux by modeled SIGPIPE unless MSG_NOSIGNAL suppresses it, `O_NONBLOCK`/`EWOULDBLOCK` honored; `dup`/`F_DUPFD[_CLOEXEC]` alias an endpoint refcounted — std's `try_clone`, e.g. tokio's signal driver cloning a socketpair end — so EOF/`EPIPE` appear only once the LAST fd of a side closes), a socketpair as two connected AF_UNIX sockets of the shim's socket model (stream, datagram or seqpacket; other families `EOPNOTSUPP`), both wired to the SAME scheduler baton / waiter machinery, so reads/writes are scheduler-visible and deterministic given the schedule (no trace events of their own — like the futex/mutex words). `eventfd`/`eventfd2` (Linux, mio's Waker vehicle) joined the in-process slice: **interposed** as a deterministic 64-bit counter (read returns-and-resets, `EFD_SEMAPHORE` decrements, `EFD_NONBLOCK` → `EAGAIN` on zero reads, `EFD_CLOEXEC` a no-op; a write that would overflow fails closed loudly instead of modeling blocked writers) wired into the same readiness core so the epoll reactor watches it. The **cross-process** members (`shm_open`/`mach_*`/`mq_*`) genuinely reach another address space or the kernel and stay **refused** as libc symbols. On Linux the kernel rows beneath them are modeled with single-process semantics (System V shared memory, semaphores and message queues; POSIX message queues through `syscall(2)` or a raw instruction), and `mmap` is interposed: a `MAP_SHARED` mapping is host anonymous memory no second process can attach (process creation is a named trap) or a view of a modeled file's page cache. | interposed members → not an import (strong def); cross-process members → symbol audit → `shared-memory-ipc` (still classified so a raw non-shim import reads as an escape) | `every_escape_class_is_detected_and_denied` (`shm_open`, `eventfd`); `native_abi::{pipe_reader_is_woken_by_writer_thread,socketpair_transfers_in_both_directions,nonblocking_pipes_return_eagain,pipe_aliases_keep_channels_alive}`, `native_abi::closed_pipe_returns_epipe_without_sigpipe` (Rust std's ignored-SIGPIPE disposition), Linux `msg_nosignal_suppresses_sigpipe` and the frozen `signal/pipe_term` probe (generation, `MSG_NOSIGNAL` and default death), `native_abi::linux::eventfd_writer_wakes_epoll_waiter`, and `native_containment::prerun_refuses_shm_open_and_hatch_warns` |
| h | **Signals / timers** | `sigaction`, `sigprocmask`, `sigaltstack`, `sigsuspend`, `sigwait`, `sigtimedwait`, `pause`, `signalfd`; `setitimer`, `timer_create/settime`, `alarm`, `ualarm` | Linux registrations, masks, self-generation, waits and signalfd are modeled in one Rust state machine on both libc and SUD doors. Pending state and recipients are deterministic; kernel frames only carry selected deliveries. SIGSYS and armed SIGSEGV registrations are named fatal refusals and those signals are stripped from host masks. Ambient external signals remain outside the model. Linux timers run on the virtual clock and CPU time behind the SUD rows and `syscall(2)` (interval timers, POSIX timers, timer descriptors); their libc wrappers (`setitimer`, `alarm`, `timer_create`, …) define no shim symbol and stay import-refused. macOS retains registration allowances and refuses signal waiting/timer arming. | strong modeled definitions; remaining imports → `signals-timers`; unmodeled raw rows → named traps | frozen signals family gate, production-entry state/wait tests, typed `native_signals` C adapter test |
| — | **Environment** | `getenv`, `secure_getenv`, `setenv`, `unsetenv`, `putenv`, `clearenv` | interposed → glibc's environment functions over the process's own `environ`, which starts as the deterministic startup map native `run --env` supplies (empty by default, recorded in trace metadata); `putenv` inserts the caller's own string, aliased as glibc keeps it | symbol audit → `environment` | `every_escape_class_is_detected_and_denied` |
| — | **Dynamic loading** | `dlopen`, `dlsym`, `dlclose` | `dlopen`/`dlclose` refused. `dlsym`: **Linux** interposed, and it can never return a *host* symbol. It answers from one **routing table** (`c/posix/dlsym.c`) — every name the shim defines as a libc contract (the registry's `Modeled`/`Partial` Linux rows, held to it by a drift test), mapped to hidden aliases of the shim's own definitions — and NULL for every other name (host-only names, deny-trapped escapes, the control plane), so std's optional-symbol probing still falls back to defaults. The table is not an allowance: it lists symbols this shim already defines, so it hands back the code the static linker would have bound the caller to (the very address) and cannot widen what the guest can reach. Flat NULL was the *less* contained answer, because the `getrandom` crate reads NULL as "this kernel has no getrandom" and falls back to opening and `poll()`ing `/dev/random`. **macOS** `dlsym` is the shim's own host-alias resolution primitive (`dlsym(RTLD_NEXT, ...)`), so it is baked into `shim_control_plane_symbols` and tolerated as control-plane — see the honest-residual note below | symbol audit → `dynamic-loading` (Linux: also interposed) | `every_escape_class_is_detected_and_denied`; `native_containment::dlsym_routes_the_shim_definitions_and_no_host_name` (the routing table is a distinct symbol, so the routed-resolve / everything-else-NULL / seeded-bytes assertions run on **both** platforms, with the real `dlsym` round trip asserted on Linux) |
| — | **Direct syscall (by name)** | `syscall`, `__syscall` | Linux `syscall` interposed by an assembly entry: every number reaches the one dispatcher a trapped raw syscall reaches (the same registry rows: modeled, soft-denied, or a named fatal for an unmodeled one), except `rt_sigreturn`, which a guest's own signal restorer issues and which resumes at the host kernel's `rt_sigreturn` from glibc text with the caller's stack pointer, the frame's saved mask stripped of the containment signals first. Raw *inline* syscall instructions have no symbol and are refused by the instruction scan; `cargo patina build` injects `--cfg rustix_use_libc` so the most common emitter (rustix's default Linux backend) compiles to interposable libc imports instead. | symbol audit → `direct-syscall`; instruction scan → `instruction@…` findings | `every_escape_class_is_detected_and_denied` |
| — | **Direct syscall (raw inline instruction, SUD-managed)** | `syscall`/`svc` opcodes emitted inline (rustix's default linux_raw backend, hand-written asm) | **Linux syscall-user-dispatch (SUD), slice 1, x86_64.** The shim arms `PR_SET_SYSCALL_USER_DISPATCH` (allowed region = glibc's executable segment, NULL selector) at `__libc_start_main` and in every managed thread's trampoline, installs a `SIGSYS` handler, and scrubs `AT_SYSINFO_EHDR` from the auxv (so vDSO-resolving crates fall back to trappable raw syscalls). A trapped syscall is decoded and routed into the same `patina_*` entry points the C interposers use (clock/futex/read/write/openat/close/lseek/getrandom/sched_yield/gettid/exit; the mapping rows through the one mapping model, the other process-local memory rows passed through; the System V and POSIX message queue rows through the one-process IPC model; `set_robust_list`/`get_robust_list`/`rseq` through the per-task registration model; every unmodeled row → named fatal abort). The audit **downgrades** a `direct-syscall` *instruction* finding from refuse → run **iff** (a) the binary defines the `patina_sud_dispatch` marker AND (b) a live `prctl` probe says the kernel has SUD (x86_64 ≥ 5.11); it is reported relabeled `direct-syscall (SUD-managed)`, never silent. The x86-64 i386 entries `int 0x80` (`cd 80`) and `sysenter` (`0f 34`) are `direct-syscall` instruction findings too, but they are **never** downgraded: where the kernel has IA32 emulation (Ubuntu's default; `sysenter` only on Intel) SUD traps them, yet they arrive with the i386 syscall ABI (`si_arch = AUDIT_ARCH_I386`), which the shim's handler aborts on, and elsewhere they fault (SIGSEGV, or SIGILL for `sysenter` on AMD), so the audit refuses them up front on every kernel, with a note saying why. No-SUD kernel (notably arm64) or no marker ⇒ today's refusal, with a hint pointing at `--cfg rustix_use_libc` / x86_64. `cpu-nondeterminism` counter/entropy reads are NOT SUD-manageable (SUD sees syscalls only); the timestamp counter has its own trap in the next row, and the rest still refuse. | instruction scan → `instruction@…` finding carrying the decoded mnemonic (`syscall`, `svc`, `int 0x80`, `sysenter`), downgraded to `direct-syscall (SUD-managed)` when marker + kernel probe pass and the mnemonic is `syscall`/`svc` | `native_containment::{audit_reports_sud_marker_and_kernel_requirement,unmarked_raw_syscall_is_refused,raw_syscalls_are_virtualized_or_refused_before_execution,unmapped_raw_syscall_aborts_with_named_diagnostic,sud_scrubs_vdso_auxv,sigsys_registration_is_refused_on_every_kernel,at_random_is_seeded_on_every_kernel}`; patina-target unit `flags_real_forbidden_opcodes_at_a_boundary` (the i386 entries and their `int`/`sysexit`/`sysret` neighbours), `sud_manageability_is_instruction_direct_syscall_only` |
| — | **CPU nondeterminism (raw inline instruction)** | `rdtsc`/`rdtscp` (x86-64 timestamp counter), `rdrand`/`rdseed` (x86-64 hardware entropy), `mrs Xt, CNTVCT_EL0` and its FEAT_ECV self-synchronising twin `mrs Xt, CNTVCTSS_EL0` (arm64 system counter; the physical `CNTPCT`/`CNTPCTSS` reads are disabled at EL0 by Linux and raise SIGILL), `mrs Xt, RNDR`/`RNDRRS` (arm64 hardware entropy, FEAT_RNG) — all emitted inline by a guest that reaches for the counter directly (`core::arch`, hand-written asm, a fast-clock crate) | **split by whether a trap exists.** The *timestamp counter* is trap-managed on x86-64 Linux: the shim arms `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` at `__libc_start_main` and in every managed thread's trampoline, so `rdtsc`/`rdtscp` raise a synchronous `SIGSEGV`, and the handler answers them from the run's virtual monotonic clock through the SAME `patina_clock_now` entry point the C interposers use — one tick per virtual nanosecond (a nominal 1 GHz invariant TSC), `IA32_TSC_AUX` fixed at 0, and the read recorded as the ordinary `clock_now` operation, so a counter read and a `clock_gettime` are the same op in the trace. Arming is recorded in the trace's `tsc` metadata field and reconciled fail-closed on replay. Any other faulting instruction falls through to the previous disposition, so a genuine segmentation fault still kills the process; a guest `sigaction`/`signal` on SIGSEGV is refused while armed. Everything else in this class is **untrappable**: no mechanism intercepts a hardware entropy read or the arm64 system counter, so `rdrand`/`rdseed`/`CNTVCT`/`CNTVCTSS`/`RNDR`/`RNDRRS` stay refusals on every platform. | instruction scan → `instruction@…` finding carrying the decoded mnemonic; `rdtsc`/`rdtscp` are downgraded to `cpu-nondeterminism (TSC-trap-managed)` **iff** (a) the binary defines the `patina_tsc_dispatch` marker AND (b) a live `prctl(PR_GET_TSC)` probe says this platform can arm the trap — never silently; every other mnemonic keeps refusing, and the refusal names the class as unallowable (an instruction finding has no symbol for `--allow`) and untrappable | `native_containment::{tsc_reads_answer_from_virtual_clock,tsc_sleep_jitter_moves_counter,rdrand_is_refused_on_every_kernel,genuine_segv_is_not_swallowed,sigsegv_handler_hijack_is_refused}`; patina-target unit tests `classifies_rdtscp_and_rdseed`, `classifies_aarch64_system_register_accesses`, `tsc_manageability_is_the_timestamp_counter_only`, `cpu_nondeterminism_note_names_allowability_and_trappability` |
| — | **Host identity (raw inline instruction, visible — not refused)** | `cpuid` (x86-64), emitted wherever code branches on what CPU it is running on: glibc ifunc resolvers selecting a `memcpy`/`strlen`, `std`'s `is_x86_feature_detected!`, hand-rolled feature probes, and fast-clock crates choosing an implementation (`fastant` reads leaf `0x80000007` bit 8 to pick its timestamp-counter path over the `SystemTime` fallback) | **unmanaged, and reported anyway** — the one instruction class that informs rather than refuses. Refusing is not available: `cpuid` is near-universal in real x86-64 binaries, so a refusal would refuse essentially every guest, and it is not an escape from a single run's determinism either — feature bits are constant on a host, so repeats, seed variation, and record/replay are all unaffected. What it costs is **cross-host reproducibility**: where those bits guard behavior, the same guest at the same seed can take a different code path on a different host, and until this slice the report said nothing about it (the fastant probe measured 11 `cpuid` sites by `objdump` in a binary whose 2 `rdtsc` sites the audit did report). Reporting is therefore the whole disposition: name the sites, say the run is deterministic here and not portable there, and let the operator pin the host. **Escalation path**, if a run must be portable rather than merely reproducible: Linux `arch_prctl(ARCH_SET_CPUID, 0)` faults `CPUID` on capable Intel parts, so the SUD/TSC trap pattern extends to it — the handler would answer from a fixed synthetic feature-bit model instead of the host's. That is a deferred slice (Intel-only, and a synthetic model has to be built), deliberately not started here; patina's virtual CPU declares no CPUID faulting today (`ARCH_SET_CPUID` answers `ENODEV`), so taking it also changes that declared answer. **aarch64** has the same shape and no row yet: `mrs Xt, MIDR_EL1`/`REVIDR_EL1`/`ID_AA64ISAR*` are identity/feature reads (EL0 access is kernel-emulated on Linux), so they belong in this class when the arm64 decoder learns them; they are not decoded today, which is a stated residual, not a claim of absence | instruction scan → `instruction@…` finding carrying mnemonic `cpuid` and category `host-identity`, which `NativeAudit::audit` keeps OUT of the denied set (so the exit code never moves) and the report prints under its own heading on **every** audit outcome — clean, trap-managed, and refused — plus a JSON `finding_details` row with `disposition: unmanaged-visible` | `classifies_cpuid_as_host_identity` and `cpuid_sites_are_reported_without_refusing_the_binary` (patina-target unit: decode row, enumeration, non-refusal, rdtsc neighbour unchanged); `audit_reports_host_identity_reads_without_refusing_them` (cargo-patina e2e: heading, site offsets, exit 0, JSON detail rows, and the sites still reported alongside a refusal) |
| — | **Thread pointer (raw inline instruction)** | x86-64 `wrfsbase` (`f3 [REX.W] 0f ae /2`, register form) and the FS selector loads `mov fs, r/m` (`8e /4`), `pop fs` (`0f a1`), `lfs` (`0f b4`); aarch64 `msr tpidr_el0, Xt` (`0xd51bd040 \| Rt`). Emitted by hand-written asm, or a coroutine/green-thread runtime that installs its own TLS block | **refused, no trap.** The thread pointer is not guest-only state: the shim is linked into the guest and resolves its own thread-locals (the current task, the frame flags, the panic scope) through it, as glibc's TCB does. A guest that moves it makes the shim read another block as its task state, so it schedules the wrong task or corrupts its own state, or it impersonates another task's TLS. The syscall doors, `arch_prctl(ARCH_SET_FS)` to another base and a `modify_ldt` write that would store a usable descriptor (an LDT entry is what an FS selector load reads; an entry the kernel stores zeroed is passed to the host), stop the run by name (`thread-pointer`, `src/sud/thread_pointer.rs`) for the same reason; these instructions do the same with no syscall, which only the static scan can see. Neighbours that are **not** findings, and why: `rdfsbase`/`rdgsbase` and `mrs Xt, TPIDR_EL0` read the pointer, which `arch_prctl(ARCH_GET_FS)` and every TLS access already give the guest; `wrgsbase` and the GS selector loads move GS, which neither glibc nor the shim uses in user space on x86-64 (the thread/tls design passes `ARCH_SET_GS` through for the same reason); `msr TPIDRRO_EL0` is UNDEFINED at EL0 (SIGILL); `msr TPIDR2_EL0` is the SME lazy-ZA-save pointer, not a TLS base (glibc 2.39's own `__libc_arm_za_disable` zeroes it). **Where glibc 2.39 writes the pointer:** in a dynamic link (every `cargo patina build` guest) ld.so installs the main thread's pointer (`TLS_INIT_TP` in rtld: two `msr tpidr_el0` sites in `ld-linux-aarch64.so.1`, two `arch_prctl(ARCH_SET_FS)` syscalls in `ld-linux-x86-64.so.2`, no `wrfsbase` anywhere) and new threads get theirs from `clone3(CLONE_SETTLS)`; the audit scans the guest executable, never its interpreter or `libc.so.6`, so no glibc site is in the scanned image and no allowlist is needed. A static glibc image carries glibc's own `msr tpidr_el0` in `__libc_setup_tls` (aarch64); it is reported and refused like any other site, as such images already are for their inline `svc`, and an operator can clear it by name with `--allow-unsupported-symbols __libc_setup_tls` | instruction scan → `instruction@…` finding with category `thread-pointer` and the decoded mnemonic (`wrfsbase`, `mov fs`, `pop fs`, `lfs`, `msr tpidr_el0`, also in the JSON `finding_details` row), refused by the audit and the pre-run gate with a note naming the instructions; no marker or probe downgrades it, and the only way past it is the `--allow-unsupported-symbols` hatch | patina-target unit: `classifies_thread_pointer_writes` (x86 encodings, reads/GS/group-15 neighbours including memory-form `repz ldmxcsr`), `classifies_aarch64_system_register_accesses` (every Xt, the TPIDRRO/TPIDR2/read neighbours), `aarch64_thread_pointer_write_is_refused_by_name` (scanner on bytes through `NativeAudit::audit`, the note); cargo-patina e2e: `native_containment::thread_pointer_writes_are_refused_by_name` (planted Rust guest, `.byte`/`.inst` forms, refused by run and audit by mnemonic on each arch) |
| — | **Far transfer (raw inline instruction)** | x86-64 `lcall`/`ljmp` through memory (`ff /3`, `ff /5`), `lret` (`cb`, `ca iw`) and `iret` (`cf`), under any prefix. Emitted by hand-written mode-switching asm (a 32-bit thunk); compilers never emit them for user-space 64-bit code (GCC's `__attribute__((interrupt))` emits `iretq`, for kernel/bare-metal handlers only) | **refused, no trap.** Each loads CS from a selector the guest chooses, and a 32-bit code selector (Linux's `__USER32_CS`) switches the CPU to compatibility mode. There the 64-bit decoder no longer describes the code that runs: a thread-pointer write, an entropy read or an i386 syscall in it can decode as something else. Refusing the transfer keeps every instruction the scan approves in the mode it was decoded in. The direct far forms `lcall`/`ljmp ptr16:32` (`9a`/`ea`) are invalid in 64-bit mode and already fail closed as `undecodable-instruction`. Not findings: near `call`/`jmp`/`ret` and the rest of group 5. aarch64 has no counterpart, since an EL0 process cannot switch to AArch32 without an exec. None of these instructions appears in glibc 2.39 (`libc.so.6`, `ld.so`, `libc.a`), `python3.12` or `git`. Across 2,193 host x86-64 ELFs the only sites the scan reports are in Go binaries: the `crypto/internal/boring/sig.StandardCrypto` marker function (a `jmp` over 29 fixed bytes for `rsc.io/goversion`), which decodes at its real function boundary as `…; push %rcx; lret $0xa956` and then `lret`. Every Go release carries it, current Go included, in any binary that links `crypto/sha1` or `crypto/tls`. Today those binaries are refused earlier anyway (raw `syscall`s, and Go 1.27's AVX-512 garbage collector code stops the walk as undecodable), so the rule adds no refusal. It is a **known Go-support blocker**, together with the sibling `FIPSOnly` marker, whose `ce` byte is undecodable: the intended remedy is an exact-bytes skip of these marker functions (reported visibly, not dropped silently), not dropping the far-transfer rules. Until then, `--allow-unsupported-symbols crypto/internal/boring/sig.StandardCrypto.abi0` clears it by containing symbol in an unstripped Go binary | instruction scan → `instruction@…` finding with category `far-transfer` and the decoded mnemonic (`lcall`, `ljmp`, `lret`, `iret`), refused by the audit and the pre-run gate with a note (shared with `int 0x80`/`sysenter`) naming them; no marker or probe downgrades it | patina-target unit `flags_real_forbidden_opcodes_at_a_boundary` (the far forms, and the near group-5 and `ret` neighbours) |
| — | **Host-state query** | `isatty`, `gethostname`, `getpwuid_r`, `__NSGetExecutablePath`, `issetugid`; Linux: `sched_getcpu`, `sched_setaffinity`, `pthread_getname_np`, `pthread_sigmask` | interposed → fixed deterministic values so guest output cannot depend on where, on which core, or as whom, it ran. `isatty` → "not a terminal" (returns 0, `errno = ENOTTY`); `gethostname` → the constant `"patina"`; `getpwuid_r` (and the Linux `getpwent` walk) → the virtual machine's passwd database, Ubuntu 24.04's container image's (`registry::PASSWD`: root first, uid 1000 `ubuntu` with home `/home/ubuntu`), read into the caller's entry and buffer as glibc's files module does (std's home-dir lookup with `HOME` unset therefore answers `/home/ubuntu`, never the host user's home); `__NSGetExecutablePath` → fails so `current_exe()` is a deterministic `Err` rather than leaking the host path (a future guest needing `current_exe() → Ok` should get a fixed *virtual* path, never the host's); `issetugid` → 0 (never a set-id binary). Linux glibc, reached by a custom global allocator's init: `sched_getcpu` → 0 (the live CPU id is host-scheduling nondeterminism; pinning it makes per-CPU arena selection deterministic — distinct from the pure `__sched_cpucount`/`CPU_COUNT` popcount, which is allowlisted); `sched_setaffinity` → deterministic no-op success (affinity is inert under the single-baton scheduler); `pthread_getname_np` → a fixed empty name; `pthread_sigmask` → the shared per-task virtual mask, with SIGSYS and armed SIGSEGV stripped from host masks so a guest cannot disarm containment. All are strong C defs, so none appears as an import. | not an import (strong def) | `native_workloads::std_runs_seeded_and_replayable_but_not_standalone` (linked std guest; not an explicit isatty-value assertion); `classifies_linux_jemalloc_audit_surface` (unit — `sched_getcpu` stays denied for a non-shim binary, not confused with the pure `__sched_cpucount`); the Linux tikv-jemallocator MRE audits clean and runs deterministically |
| — | **Stack-growth probe (macOS)** | `___chkstk_darwin` | **known-safe.** A compiler-inserted probe that touches successive stack guard pages before a large frame (an allocator's init frames reach it). Pure caller-stack access, no boundary effect, value-free deterministic outcome (return, or a genuine stack-overflow death exactly as native). | import audit → allowlisted | `classifies_known_native_escape_symbols` region / the tikv-jemallocator MRE audits clean |
| — | **Host-state registration** | `pthread_atfork` (fork-handler registration pulled in by Rust std / libc thread & once machinery — e.g. a multi-thread guest) | interposed → **no-op returning 0**: the registration is ignored. Sound because the entire fork/exec process class (row **e**) is a deterministic-runtime non-goal the audit denies, so a registered handler could never run; the call has no boundary effect. A strong C definition binds the guest reference and the libc symbol drops off the import table, so the pre-run gate has nothing to flag and the run's determinism claim is unqualified. Being shim-defined, it never appears as an import. | not an import (strong def) | a multi-thread guest under `run-patina.sh` links it and runs allowance-free |
| — | **Positional file I/O** | `pread`, `pwrite` (a guest's `read_exact_at`/`write_all_at`; the offset-loop `libc::pread`/`libc::pwrite`); the vectored `preadv`, `pwritev` (`preadv64`/`pwritev64` on Linux — a database backend batching a transaction's WAL frames in ONE `pwritev`) | interposed → `patina_p{read,write}` → the runtime's `fs_read_at`/`fs_write_at`, serviced as **one** positional driver operation (`FsDriver::read_at`/`write_at`) that saves, seeks, reads/writes, and restores the cursor **within a single driver call** — atomic w.r.t. the scheduler, so it is cursor-independent even when threads share the fd. A caller-side seek+read emulation would be unsound under preemption; this reaches the driver as one op instead. `write_at` counts toward the `--fs-crash-at write:N` ordinal and is crash-losable exactly like a cursor write; `read_at` fires no crash. The vectored forms loop per `iovec` over the SAME positional ops at an advancing offset and, like `readv`/`writev`, stop at the first short or failed transfer (an injected short write surfaces to a vectored caller as a short total); a socket or stdio fd is `ESPIPE`. Being shim-defined, none appears as an import. | not an import (strong def) | `patina-dst-abi` tag/offset pins; `patina-dst-fs-crash::positional_write_is_crash_losable_exactly_like_a_cursor_write`; `native_positional_vectored_io_round_trips_through_the_deterministic_fs` (e2e: one `pwritev` of two frames lands at the offset with the cursor untouched, `preadv` reads them back across two buffers, short at EOF, `ESPIPE` on stdout) |
| — | **Advisory file lock** | `flock` (a guest's whole-file `File::try_lock` / `try_lock_shared` on open); `fcntl` record locks `F_GETLK`/`F_SETLK`/`F_SETLKW` (rustix `fcntl_lock` — the open-time whole-file lock a storage engine such as turso takes) and the Linux `F_OFD_*` variants | interposed → **per-description lock table** (`patina_flock`). The lock belongs to the open file DESCRIPTION (a `dup` of the holder shares it and can release it; closing one number of a dup'd pair keeps it) and is keyed on the deterministic-fs inode the description is open on (from the recorded fd-metadata path, so it reconstructs identically under replay); conflicts are resolved against that identity: `LOCK_EX` conflicts with any lock held on another description of the same file, `LOCK_SH` only with a held `LOCK_EX`. A lone opener always acquires (a single `LOCK_EX\|LOCK_NB` on open), but a *second* open of the same path contends faithfully — `LOCK_NB` reports `EWOULDBLOCK`, exactly the path a single-opener database guest surfaces as an "already open" error. The lock clears on `LOCK_UN` and with the description's last number (descriptions are never reused, so no stale entry survives a number's reuse). One simplification, sound for the supported surface: a *blocking* request that would contend fails closed with `EDEADLK` rather than parking a real thread (the single-baton scheduler does not model advisory-lock waiting, and std's `File::try_lock*` is always `LOCK_NB`). A non-file description (a socket, an eventfd) locks as its own identity, as each is its own inode on Linux. POSIX record locks are process-scoped, and a run is ONE process: they never conflict with locks the same process already holds (POSIX merges them, and any close releases them all), so on an open regular fd `F_SETLK`/`F_SETLKW` succeed and `F_GETLK` reports the range `F_UNLCK` — exactly the lone opener's view on the host (left unmodeled the lock was `ENOSYS` and the engine aborted at unlock). Descriptor validity there is a descriptor-table check only — a record lock does no I/O, so it never consults the fault-eligible driver lookup (an injected `EIO` on an unlock would be a fabricated failure mode); a bogus lock type is `EINVAL`, a number that names nothing `EBADF`, and — `fcntl_setlk`'s access-mode check — a read lock on a write-only description or a write lock on a read-only one `EBADF`. Linux open-file-description locks DO conflict across descriptions in one process, so a whole-file `F_OFD_SETLK`/`F_OFD_SETLKW` routes to this same per-inode table (`LOCK_NB` for the non-blocking command); a byte-range OFD lock and `F_OFD_GETLK` stay a soft `ENOSYS` rather than a fabricated answer. The SUD `fcntl` row mirrors the C arm exactly. Being shim-defined, neither `flock` nor `fcntl` appears as an import. | not an import (strong def) | `native_flock_contends_on_a_second_open_and_releases_on_close` (e2e: second open → `EWOULDBLOCK` in libc `errno` — the shim keeps its own thread-local errno, so a C entry forwarding a `patina_*` result must `fail_int` it, close releases); `native_fcntl_record_locks_are_modeled_for_the_lone_opener` (e2e: `F_SETLK`/`F_SETLKW` 0, `F_GETLK` → `F_UNLCK`, bogus type `EINVAL`, a read lock on write-only stdout `EBADF`; Linux: a second open's whole-file `F_OFD_SETLK` contends `EAGAIN`, byte-range / `F_OFD_GETLK` `ENOSYS`, release lets it retry); `native_raw::fcntl_record_locks_match_libc` (raw syscall and libc agree) |
| — | **Filesystem volume metadata (Linux)** | `statfs`/`fstatfs` (`statfs64`/`fstatfs64`) — a storage engine probing whether a path's filesystem supports its multi-process coordination (turso's shared-WAL probe on every open) | interposed → the virtual filesystem answers as ONE constant ext4-like volume (`EXT4_SUPER_MAGIC`, 4 KiB blocks, 255-byte names) for any path or descriptor that resolves through the same metadata lookup `stat`/`fstat` use; a missing path is `ENOENT`, a bad descriptor `EBADF`. The profile is a constant, so it is identical on record and replay and on every host; left unmodeled the call reached the HOST with a virtual path and the engine refused to open at all. Being shim-defined, neither appears as an import. | not an import (strong def) | `native_statfs_answers_as_one_virtual_volume` (e2e, Linux: magic / block size / name length, `ENOENT`, `fstatfs` parity, `EBADF`) |
| — | **Host introspection (macOS Mach/BSD/IOKit)** | `sysctl`/`sysctlbyname`, `getrusage`, `task_info`, `mach_task_self_`, `mach_host_self`, `host_statistics64`, `host_processor_info`, `vm_page_size`, `vm_deallocate`, `proc_listallpids`/`proc_pidinfo`/`proc_pid_rusage`/`proc_pidpath`; IOKit `IOServiceMatching`/`IOServiceGetMatchingServices`/`IOIteratorNext`/`IOObjectRelease`/`IORegistryEntryCreateCFProperty`/`IORegistryEntryGetName` — the `sysinfo` / `num_cpus` / hardware-inventory surface | **split by whether a normal startup reaches the symbol** (generalizing the process-spawn deny-trap doctrine, row e). The hardware-inventory surface a `sysinfo`/`num_cpus` guest links — `host_statistics64`/`host_processor_info`, `mach_host_self`, `proc_listallpids`/`proc_pidinfo`/`proc_pid_rusage`/`proc_pidpath`, `vm_deallocate`, `IOServiceMatching`, plus the data symbols `mach_task_self_`/`vm_page_size`/`kIOMasterPortDefault` (fixed deterministic values — a data read cannot be trapped) — is now **deterministic-model interposed** (macOS): a runtime abort is not "support", so where the API admits an honest answer the strong shim def returns it and a guest that EXERCISES the inventory runs deterministically (a locked-down host with an empty inventory). `mach_host_self` → fixed synthetic port; `host_statistics64(HOST_VM_INFO64)` → fixed 8 GiB VM stats; `host_processor_info(PROCESSOR_CPU_LOAD_INFO)` → a single-CPU load block (so `System::cpus().len()==1`, consistent with `sysctl HW_NCPU=1`); `proc_listallpids` → the guest and init; `proc_pidpath`/`proc_pidinfo`/`proc_pid_rusage` → the guest's fixed identity (init: `EPERM`) / graceful "not modeled" degradation; `IOServiceMatching` → `NULL` (sysinfo reports CPU frequency unknown); `vm_deallocate` → `KERN_SUCCESS` no-op. The IOKit registry-walk helpers the `NULL` `IOServiceMatching` makes unreachable — `IOServiceGetMatchingServices`/`IOIteratorNext`/`IOObjectRelease`/`IORegistryEntryCreateCFProperty`/`IORegistryEntryGetName` — stay **deny-trap interposed** (each documented unreachable-by-construction; a genuine direct call `abort()`s deterministically naming the symbol). Only the **live-path** members a normal startup actually reaches — `sysctl`/`sysctlbyname`/`getrusage`/`task_info` — stay uninterposed and **refused** pre-run (a strong def would silently swallow a path startup uses; a deterministic interposer is a tier-3 item). Both read host CPU/memory/hardware/process state — nondeterministic across hosts and runs: **interpose-or-refuse, never allowlist.** Classification is unchanged and stays load-bearing: `host-introspection` (the exact Mach/BSD name list plus the IOKit prefixes `IOService`/`IORegistry`/`IOIterator`/`IOObject` — deliberately not a bare `IO`) labels a raw import from a **prebuilt non-shim binary**, which links no shim so nothing drops off — it always refuses. Fail-closed either way. | converted members → not an import → **deterministic model**; unreachable IOKit helpers → not an import (deny-trap) → **runtime abort**; live-path members / prebuilt-raw → import audit → `host-introspection` | `host_inventory_surface_is_deterministic` (macOS e2e — a guest exercising `mach_host_self`/`host_statistics64`/`host_processor_info`/`vm_deallocate`/`proc_listallpids`/`IOServiceMatching` prints `vm=0 cpu=0 ncpu=1 pids=2 iokit_null=true`, byte-identical) + `native_run_deny_trap_aborts_a_guest_that_reaches_host_introspection` (macOS e2e — a guest reaching the still-trapped `IOServiceGetMatchingServices` aborts, naming it, byte-identical) + `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (a dormant `sysinfo`-shaped path runs allowance-free); `classifies_ecosystem_audit_symbol_batch` (unit — representative Mach/BSD/IOKit sample classifies; `sysctlbyname` stays denied; a user `IOWidget` does NOT match; `IO`-prefix overreach guarded); the real `sysinfo` `System::new_all()` MRE runs to completion (`cpus=1`) with only its live-path audit residual (`sysctl`/`sysctlbyname`) |
| — | **macOS system frameworks (CoreFoundation / Security)** | `CFArrayCreate`/`CFStringGetLength`/`CFDataGetBytePtr`/`kCFAllocatorDefault`/`kCFTypeArrayCallBacks`; `SecCertificateCopyData`/`SecTrustSettingsCopyCertificates`/`SecCopyErrorMessageString` — the `rustls-native-certs` / `security-framework` / `chrono`-timezone / native TLS trust-root surface | **enumerated dormant symbols deny-trap at call time; the remainder refuse pre-run** (generalizing the process-spawn deny-trap doctrine, row e). The enumerated dormant surface — the CoreFoundation helpers (`CFArray*`/`CFString*`/`CFData*`/`CFTimeZone*`/`CFRetain`/`CFRelease`/`CFEqual`/`CFNumberGetValue`/`CFDictionaryGetValueIfPresent`/`CFGetTypeID`), the Security readers (`SecTrustSettingsCopy*`/`SecCertificateCopyData`/`SecCopyErrorMessageString`), plus the data symbols `kCFAllocatorDefault`/`kCFAllocatorNull`/`kCFTypeArrayCallBacks` (fixed values — a data read cannot be trapped) — is now split between **deterministic-model** and **deny-trap** interposition (macOS): a strong shim def binds each reference at link so a binary that merely LINKS the optional TLS-trust / timezone path RUNS (the symbol drops off the import table), and where the API admits an honest answer the def RETURNS it so a guest that EXERCISES the path also runs deterministically. `SecTrustSettingsCopyCertificates` → `errSecNoTrustSettings` (so `rustls-native-certs`'s `load_native_certs()` yields zero certs/zero errors — a locked-down host); the empty-array helpers it then drives (`CFArrayCreate`/`CFArrayGetCount`/`CFRelease`, on synthetic tokens) are honest; the timezone path `CFTimeZoneResetSystem`/`CFTimeZoneCopySystem`/`CFTimeZoneGetName`/`CFStringGetCStringPtr` reports `UTC` (the single fixed timezone the runtime models, matching `localtime_r`), so `iana-time-zone`/`chrono::Local` resolve UTC deterministically. The per-cert / error-format / string-builder helpers those honest returns make unreachable — `SecCertificateCopyData`/`SecTrustSettingsCopyTrustSettings`/`SecCopyErrorMessageString`, `CFArrayGetValueAtIndex`, `CFRetain`, `CFEqual`/`CFNumberGetValue`/`CFDictionaryGetValueIfPresent`/`CFGetTypeID`, `CFString{CreateWithBytesNoCopy,CreateWithCStringNoCopy,GetBytes,GetLength}`, the `CFData*` accessors — stay **deny-trap interposed** (each documented unreachable-by-construction; a genuine call `abort()`s deterministically naming the symbol). Any **non-enumerated** `CF*`/`kCF*`/`Sec*`/`kSec*` symbol, and every framework symbol in a **prebuilt non-shim binary** (which links no shim), stays **refused** pre-run. The Security readers touch the host keychain / system trust store — mutable per-machine, per-time host state — so a run reaching one is not reproducible; the CoreFoundation helpers are the plumbing those calls require. Classification is unchanged and stays load-bearing: `macos-framework` (Apple-reserved prefixes `CF`/`kCF`/`Sec`/`kSec`) labels the still-refused remainder with a determinism note naming the host-trust-store problem and the `--allow-unsupported-symbols` allow path (qualified determinism). Fail-closed either way. | converted members → not an import → **deterministic model**; unreachable helpers → not an import (deny-trap) → **runtime abort**; remainder / prebuilt-raw → import audit → `macos-framework` | `native_trust_root_surface_is_deterministically_empty` (macOS e2e — the `SecTrustSettingsCopyCertificates`+empty-`CFArray` sequence prints `certs=0 errors=0`, byte-identical) + `local_timezone_surface_reports_utc` (macOS e2e — the `CFTimeZone*`/`CFStringGetCStringPtr` sequence prints `tz=UTC`, byte-identical) + `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (a dormant `rustls-native-certs`-shaped path runs allowance-free); `native_gate_classifies_and_refuses_a_security_framework_symbol` (macOS e2e — a non-enumerated `SecTrustEvaluateWithError` still refuses with note + audit/run parity); `classifies_known_native_escape_symbols` (unit — the certs surface classifies); the real `rustls-native-certs` `load_native_certs()` MRE runs to completion (`certs=0 errors=0`) and the chrono MRE audits CLEAN |
| — | **Undefined weak import (inert, not an escape)** | aws-lc's allocator-override hooks `OPENSSL_memory_alloc`/`OPENSSL_memory_free`/`OPENSSL_memory_get_size`/`OPENSSL_memory_realloc`, and `sdallocx` | **inert: reported, never refused.** An undefined weak reference is the C way of asking "is this hook present?" — nothing in the link supplies a definition, so it resolves to NULL and the referencing code takes its guarded fallback (aws-lc uses its ordinary allocator). A NULL that is never called reaches no host behavior, so refusing it is a false positive, and an `--allow` for it would be worse than the finding: the allowance is by NAME, so it would go on clearing the symbol if a future dependency ever DEFINED it. The rule is therefore computed from bindings, not names, and both disqualifiers are evaluated over the whole audited closure (static and dynamic symbol tables): a name the closure **defines** anywhere, or one carrying any **strong** undefined reference, is not inert and takes the full classification path. It is further narrowed to imports matching no named escape class — "undefined" means undefined *in this image*, and the dynamic linker still searches the loaded libraries, so a weak undefined `open` would bind to libc's `open` and run. The classified names are exactly the ones a loaded library defines. | import audit → **inert**, listed under the report's own `inert weak imports` heading (the surface stays visible; it is not folded into the clean case) | `undefined_weak_imports_are_inert_not_refused` (unit), plus three planted fail-closed guards that each fail if the corresponding disqualifier is dropped: `a_defined_weak_symbol_keeps_the_full_classification_path`, `a_strong_undefined_import_is_untouched_by_the_weak_rule`, `a_weak_undefined_import_of_a_classified_escape_still_refuses`; `symbol_binding_fixture_presents_real_weak_and_defined_bindings` pins the fixture against vacuity |

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
`pread`/`pwrite`/`preadv`/`pwritev`, the advisory `flock` and `fcntl` record
locks, Linux `statfs`/`fstatfs`, and the whole FS/time/entropy/pthread surface.

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

The glibc side of the same sweep also met **`__assert_fail`**, glibc's
`assert()` failure hook, which aws-lc's asserts lower onto. It is not
known-safe: libc's hook writes through libc's `stderr`, and in a shim-linked
guest that global is the shim's sentinel, so the hook crashed on it. The shim
defines it instead (glibc's message on the stream, then a guest `abort`), as it
defines Darwin's `__assert_rtn`, so neither is an import of a linked guest, and
an import of either means the link lost the definition: `unknown-import`
(`an_imported_assert_failure_hook_is_refused`).

And three data words ld.so exports, once the shim took over the area they
describe:

- **`__rseq_offset`, `__rseq_size`, `__rseq_flags`** (ELF only) — where each
  thread's restartable-sequence area sits from the thread pointer, its size
  and its flags, set by ld.so before any constructor and constant after. The
  area itself is the virtual kernel's: every thread's host registration is
  taken over when its task starts, so the area reads the virtual CPU and the
  host never writes it. The shim cannot define these words (ld.so owns them),
  so they are audit entries rather than symbol rows.
  (`admits_glibcs_rseq_layout_words_on_elf_only`.)

### Normalization: glibc C-standard alias generations

glibc keeps a distinct alias for every function whose signature or semantics
changed between C standards, and the *compiler* picks which one the object
references: a C23 build's `sscanf` becomes `__isoc23_sscanf`, a C99 build's
`scanf` becomes `__isoc99_scanf`. The name in the import table is a
build-configuration artifact of the same libc entry point, so the audit strips
the `isoc<digits>_` generation before lookup and classifies the base symbol
(`normalizes_glibc_alias_generations_onto_the_base_symbol`).

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
  run gains a *runtime* guarantee the old allow list never had (see row **e**).
  The credential and session calls a spawn helper makes on the way
  (`setsid`/`setgid`/`setuid`/`setpgid`/`setgroups`) are no longer part of it:
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
  no boundary effect (`pure_compute_symbols_are_known_safe`).
- **`dlsym`** — reconciled with the host-alias doctrine, not with this pivot:
  on macOS `dlsym(RTLD_NEXT, ...)` is now the shim's own host-vehicle resolution
  primitive, so it is baked into `shim_control_plane_symbols` and the pre-run
  gate tolerates it as control-plane rather than as an escape — it drops off the
  CLI guest's allow list for that reason, not because it is interposed to nothing.
  **What a guest `dlsym` *call* does, per platform (the honest residual):** on
  **Linux** the shim interposes `dlsym` (via `-Wl,--wrap=dlsym`), so a guest call
  resolves either nothing or one of the shim's own implementations from the
  routing table — never a host symbol, and
  deterministic either way. On **macOS** `dlsym` is *not* interposed: a
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
  `dlsym` of a blocked symbol the shim does *not* strong-def (e.g. macOS `killpg`).
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
   `native_trace::std_whole_run_and_planted_openat_use_identical_filter` (every file/net/clock/entropy/descriptor syscall in
   the run must match the loader/std prelude shape) and partially by
   `scan_instruction_classes` (aarch64/x86_64 syscall opcodes are rejected at
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
3. **Instruction-level entropy / time** (`rdrand`/`rdseed`/`rdtsc`/`rdtscp` on
   x86_64, `mrs CNTVCT_EL0`/`CNTVCTSS_EL0` and `mrs RNDR`/`RNDRRS` on aarch64, raw
   `svc`/`syscall`). `scan_instruction_classes` decodes all of these:
   `rdtsc`/`rdtscp` are trap-managed on x86-64 Linux,
   `rdrand`/`rdseed`/`CNTVCT`/`CNTVCTSS`/`RNDR`/`RNDRRS` refuse everywhere, and
   `cpuid` is reported visible-not-refused (host-identity). Thread-pointer writes
   (`wrfsbase`, FS selector loads, `msr tpidr_el0`) are refused in the same scan.
   The i386 syscall entries (`int 0x80`, `sysenter`) and the far transfers
   that could switch to 32-bit code are refused too. The residual is encodings
   the decoder does not know, which refuse only when they sit at a decode
   boundary the scan reaches; a switch to 32-bit code with no far-transfer
   instruction (a signal handler that rewrites the saved CS in its `ucontext`
   before `rt_sigreturn`); instructions reached only by a jump into the middle
   of another instruction, which the linear sweep never decodes (a guest built
   to hide an instruction can do this; ordinary compiler output does not); code
   outside the scanned image: the scan reads the guest executable, not the shared libraries it links
   against (normally only glibc's own); and code created at run time (JIT output,
   pages made executable after load), which no static scan sees. For the classes
   no trap backs (thread-pointer writes, far transfers, `rdrand`/`rdseed`/
   `CNTVCT`/`CNTVCTSS`/`RNDR`) that last case has no run-time backstop either.
4. **Flag-dependent behavior of an allowlisted symbol (macOS).** `mmap` is
   allowlisted as process-local memory and the audit cannot see its
   `MAP_SHARED` flag. On Linux the shim interposes `mmap` (a shared mapping is
   process-local anonymous memory or a view of a modeled file's page cache);
   on macOS `mmap` is not interposed, and a mapping of a descriptor number the
   host happens to have open is not refused by any gate. Stated, not papered
   over: `mmap` is deliberately **not** in the `shared-memory-ipc` list (it
   would be a dead label, since the allowlist wins first).
5. **Interposed-but-unsupported symbols.** A symbol the shim *defines* to
   fail-closed at runtime (e.g. `pthread_cancel`
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
   Pre-epoch and overflowing timestamp inputs remain an explicit EINVAL gap in
   the unsigned-nanosecond ABI. Allocation extents are also unmodeled: statx
   omits BLOCKS instead of claiming allocation derived from file length.
   The symbol registry (`crates/patina-native-shim/src/registry/symbols.rs`)
   enumerates this surface: every public symbol the shim defines carries a
   status — `Modeled`, `Partial` (a subset modeled, the rest refuses loudly),
   `Deny(class)` (the deny-traps), `ControlPlane` — and the known ABI spellings
   the shim does NOT define at all carry `Absent` (`__clock_gettime`,
   `clock_getres`, …), which a guest importing them reaches the host through or
   is audit-refused on. `cargo patina syscalls` prints it, and an object-scan
   gate fails when a symbol is defined without a row or an `Absent` row gains a
   definition — so the pre-run gate's blind spot is at least enumerated and
   cannot grow silently.

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

8. **Host descriptors behind guest mappings (Linux).** Every page cache (one
   per mapped file) and every System V segment is a host memfd the shim holds,
   so the host's `RLIMIT_NOFILE` bounds how many a guest can have at once. The
   shim raises the host soft limit to the hard limit at start, and a memfd the
   host still refuses stops the run by name — the guest never sees the host's
   `EMFILE` where the modeled kernel would succeed. A host with a low hard
   limit therefore runs fewer mappings, and says so, rather than answering
   differently.

9. **Control transferred into glibc's executable segment (Linux).** SUD's
   allowed region is glibc's text, where the shim's own host calls run, so a
   syscall instruction there is not trapped. A guest that jumps into that
   segment (an indirect jump, or a crafted signal frame whose saved
   instruction pointer lands there) runs whatever host syscall it finds
   unfiltered. That is adversarial-only: legitimate code reaches glibc's
   syscalls through its exported functions, which the shim interposes, and a
   frame's return address is legitimately inside glibc (the shim's own host
   call), so it cannot be filtered by address.

10. **Before `__libc_start_main` (Linux).** SUD, the timestamp-counter trap
    and the rseq takeover are armed from the `__libc_start_main` wrapper, so
    code that runs earlier, in `_dl_init` (a `DT_PREINIT_ARRAY` entry or a
    shared library's constructor), is contained by none of them: it could read
    a host CPU id from glibc's rseq area, as it could issue an untrapped raw
    syscall.

## Escape hatch

`native-run --allow-unsupported-symbols <all|name,...>` downgrades matching
denials to a loud stderr warning and records them in a `<trace>.unsupported-symbols`
sidecar next to a `--record` trace, so a run that knowingly tolerates unsupported
surface (never reached by the scenario) is visibly qualified. A partial list
still fails closed on the un-listed symbols.
