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
| a | **Blocking / scheduling** | `os_unfair_lock_*`, `__ulock_wait/wake`, `__psynch_*`, `dispatch_semaphore_*`, mach `semaphore_wait/signal`, `os_sync_wait_on_address`; readiness: `poll`/`select`/`kqueue`/`kevent`/`epoll_wait` | pthread mutex/cond, the dispatch-semaphore Parker, and Linux futex are **interposed** and routed through `DetScheduler` (+ virtual clock for timed waits); `poll` is interposed for the modeled cases | symbol audit → `unmanaged-sync` / `wait-multiplex`; any uninterposed blocking symbol is an import → denied | `every_escape_class_is_detected_and_denied` (unit); `native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol` + `validate-native-shim.sh` planted `os_unfair_lock` (e2e) |
| b | **Time** | `clock_gettime`, `gettimeofday`, `mach_absolute_time`, `mach_continuous_time`, `nanosleep`, `clock_nanosleep`, `usleep`, `mach_wait_until` | all interposed → virtual clock | symbol audit → `time` | `every_escape_class_is_detected_and_denied` |
| c | **Entropy** | `getentropy`, `getrandom`, `arc4random*`, `CCRandomGenerateBytes`, `SecRandomCopyBytes` | interposed → seeded RNG | symbol audit → `entropy` | `every_escape_class_is_detected_and_denied` |
| d | **Thread lifecycle** | `pthread_create`, `pthread_create_from_mach_thread_np`, `bsdthread_create`, `thread_create` | `pthread_create` is interposed by a strong def and spawns a managed task via a distinct non-interposed vehicle (macOS `pthread_create_suspended_np`; Linux the real glibc `pthread_create` resolved through `dlsym(RTLD_NEXT, ...)`) | symbol audit → `unmanaged-thread` | `every_escape_class_is_detected_and_denied`; `validate-native-shim.sh` escape-probe (`grep unmanaged-thread`) |
| e | **Process** | `fork`, `vfork`, `exec*`, `posix_spawn*`, `system`, `popen`, `kill`, `waitpid`, ... | **non-goal**, handled two ways. The subprocess-spawn family a real guest actually links (`fork`, `posix_spawnp`, `posix_spawn_file_actions_*`, `posix_spawnattr_*`, `execvp`, `waitpid`, `pipe`, `setsid`, `setgid`, `setuid`, `setpgid`, `setgroups`, `chdir`, `chroot` — ripgrep via std::process + grep-cli) is **deny-trap interposed**: a strong shim def that `abort()`s deterministically with a diagnostic if ever reached. It drops off the import table (no allowance needed) AND a genuine spawn fails loud + reproducible instead of escaping silently — a reachability audit cannot clear these (they are statically wired, runtime-flag-dormant; see "Why symbol-reachability…"). The rest (`vfork`/`exec*`/`system`/`popen`/`kill`/…), which no supported guest links, stay uninterposed and import-audited. | uninterposed members → symbol audit → `process`; interposed family → **runtime deny-trap** | `native_run_deny_trap_aborts_a_guest_that_actually_spawns` (a guest reaching `fork` aborts, naming it); `native_run_prerun_gate_refuses_every_escape_class` (`kill`, uninterposed); `native_build_package_audits_records_and_fails_closed`; ripgrep rung runs allowance-free |
| f | **Filesystem / network** | `open`/`read`/`write`/`stat`/`fcntl`/...; `socket`/`bind`/`connect`/`send`/`recv`/... | interposed → deterministic FS and SimNet | symbol audit → `filesystem` / `network` | `every_escape_class_is_detected_and_denied`; `classifies_native_import_decisions` |
| g | **Shared memory / IPC** | `shm_open`, `shm_unlink`, `mach_msg*`, `mach_port_*`, `bootstrap_look_up`, `mq_*`, `pipe`, `socketpair`, `eventfd` | not modeled → refused | symbol audit → `shared-memory-ipc` | `every_escape_class_is_detected_and_denied` |
| h | **Signals / timers** | `setitimer`, `timer_create/settime`, `alarm`, `ualarm`, `sigsuspend`, `sigwait`, `sigtimedwait`, `pause` | not modeled → refused. (`sigaction`/`signal`/`sigaltstack` *registration* stays allowlisted — Patina delivers no ambient signals — but timer-arming and signal-waiting are escapes) | symbol audit → `signals-timers` | `every_escape_class_is_detected_and_denied` |
| — | **Environment** | `getenv`, `setenv`, `unsetenv`, `putenv` | interposed → empty, immutable deterministic environment | symbol audit → `environment` | `every_escape_class_is_detected_and_denied` |
| — | **Dynamic loading** | `dlopen`, `dlsym`, `dlclose` | `dlopen`/`dlclose` refused. `dlsym`: **Linux** interposed to resolve nothing (deterministic NULL for any guest call). **macOS** it is the shim's own host-alias resolution primitive (`dlsym(RTLD_NEXT, ...)`), so it is baked into `shim_control_plane_symbols` and tolerated as control-plane — see the honest-residual note below | symbol audit → `dynamic-loading` (Linux: also interposed) | `every_escape_class_is_detected_and_denied` |
| — | **Direct syscall (by name)** | `syscall`, `__syscall` | Linux `syscall` interposed (FUTEX routed, else fail-closed) | symbol audit → `direct-syscall` | `every_escape_class_is_detected_and_denied` |
| — | **Host-state query** | `isatty`, `gethostname`, `getpwuid_r`, `__NSGetExecutablePath` | interposed → fixed deterministic values so guest output cannot depend on where, or as whom, it ran. `isatty` → "not a terminal" (returns 0, `errno = ENOTTY`); `gethostname` → the constant `"patina"`; `getpwuid_r` → deterministic "no such user" (`*result = NULL`, returns 0 — the guest environment is emptied so std's home-dir lookup cleanly `None`s); `__NSGetExecutablePath` → fails so `current_exe()` is a deterministic `Err` rather than leaking the host path (a future guest needing `current_exe() → Ok` should get a fixed *virtual* path, never the host's). All are strong C defs, so none appears as an import. | not an import (strong def) | `validate-native-shim.sh` (linked guests query `isatty`); ripgrep rung links all four and runs allowance-free |
| — | **Host-state registration** | `pthread_atfork` (fork-handler registration pulled in by Rust std / libc thread & once machinery — e.g. the raft rung's 4-thread guest) | interposed → **no-op returning 0**: the registration is ignored. Sound because the entire fork/exec process class (row **e**) is a deterministic-runtime non-goal the audit denies, so a registered handler could never run; the call has no boundary effect. A strong C definition binds the guest reference and the libc symbol drops off the import table, so the pre-run gate has nothing to flag and the run's determinism claim is unqualified. Being shim-defined, it never appears as an import. | not an import (strong def) | raft rung `run-patina.sh` (4-thread guest links it and runs allowance-free) |
| — | **Positional file I/O** | `pread`, `pwrite` (redb's `read_exact_at`/`write_all_at`; the offset-loop `libc::pread`/`libc::pwrite`) | interposed → `patina_p{read,write}` → the runtime's `fs_read_at`/`fs_write_at`, serviced as **one** positional driver operation (`FsDriver::read_at`/`write_at`) that saves, seeks, reads/writes, and restores the cursor **within a single driver call** — atomic w.r.t. the scheduler, so it is cursor-independent even when threads share the fd. A caller-side seek+read emulation would be unsound under preemption; this reaches the driver as one op instead. `write_at` counts toward the `--fs-crash-at write:N` ordinal and is crash-losable exactly like a cursor write; `read_at` fires no crash. Being shim-defined, neither appears as an import. | not an import (strong def) | `patina-abi` tag/offset pins; `patina-fs-crash::positional_write_is_crash_losable_exactly_like_a_cursor_write`; redb rung `run-patina.sh` |
| — | **Advisory file lock** | `flock` (redb's whole-file `File::try_lock` / `try_lock_shared` on open) | interposed → **per-inode lock table** (`patina_flock`). The lock is keyed on the descriptor's deterministic-fs inode (from the recorded fd-metadata path, so it reconstructs identically under replay), and conflicts are resolved against that identity: `LOCK_EX` conflicts with any lock held on another descriptor of the same file, `LOCK_SH` only with a held `LOCK_EX`. A lone opener always acquires (redb's single `LOCK_EX\|LOCK_NB` on open), but a *second* open of the same path contends faithfully — `LOCK_NB` reports `EWOULDBLOCK`, exactly the path redb surfaces as `DatabaseError::DatabaseAlreadyOpen`. The lock clears on `LOCK_UN` and on `close` (deterministic fd numbers are never reused, so no stale entry survives). Simplifications, sound for the supported surface: a *blocking* request that would contend fails closed with `EDEADLK` rather than parking a real thread (the single-baton scheduler does not model advisory-lock waiting, and std's `File::try_lock*` is always `LOCK_NB`); dup'd descriptors are tracked independently rather than sharing one open-file-description lock. Being shim-defined, `flock` never appears as an import. | not an import (strong def) | `native_flock_contends_on_a_second_open_and_releases_on_close` (e2e: second open → `EWOULDBLOCK`, close releases); redb rung `run-patina.sh` (single opener acquires through the lock) |

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

## Why symbol-reachability, not static call-graph reachability

The gate audits the guest's *flat undefined-import list*. A natural refinement
is to make it call-graph-aware — clear a flagged import if no path from an
entrypoint reaches it — so that a binary which merely *links* an escape symbol
without a live path to it need not carry an allowance. We investigated this
against the real ripgrep testbed (its old allow list named 27 subprocess-spawn
and host-query symbols) and rejected it: a **sound** call-graph pass clears
**zero** of them, so the refinement is all cost and no benefit. Two independent
reasons, each verified on the built `rg` (arm64 Mach-O), documented so nobody
re-attempts the static pass without new information:

1. **The dormant code is statically wired.** ripgrep's subprocess spawn is
   reachable from the Rust entry by **direct calls alone** — a `bl` chain
   `rg::main → rg::run → SearchWorker::<W>::search →
   grep_cli::process::CommandReaderBuilder::build → std::process::Command::spawn`,
   whose unix `spawn` ends in `bl _fork` / `bl _posix_spawnp`. Every edge is a
   direct branch. Only a **runtime flag** (`--pre`/`-z`) selects the preprocessor
   path at run time, and static reachability cannot prove a flag is never set.
   These symbols are *runtime*-unreachable for a plain search, not *statically*
   unreachable.
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

- **Process-spawn family** (`fork`, `posix_spawn*`, `execvp`, `waitpid`, `pipe`,
  `setsid`/`setgid`/`setuid`/`setpgid`/`setgroups`, `chdir`, `chroot`) —
  **deny-trap interposition**: a strong shim C definition that aborts
  deterministically with a diagnostic if ever reached. The process class is a
  deterministic-runtime non-goal, so a guest that genuinely spawns must fail
  loudly and reproducibly, never escape silently. Being shim-*defined*, these
  drop off the import table, so the audit needs no allowance for them — and the
  run gains a *runtime* guarantee the old allow list never had (see row **e**).
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
  ripgrep allow list for that reason, not because it is interposed to nothing.
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
      `libpatina_native_shim.a` — the sanctioned `dlsym(RTLD_NEXT, ...)` resolver.

  A call requires the symbol reference, and only the shim has it, so the shim is
  the sole `dlsym` caller at runtime — a sound static conclusion, not a sampled
  one. The residual therefore only manifests if a guest **hand-writes a `dlsym`
  call in its own source**; for such a guest the redirect *would* fire (its
  `.o` carries the `_dlsym` reference), but delivering it means splitting the
  clean single `rustc` compile+link into emit-objects → objcopy → **manual
  relink** (reproducing rustc's full link line by hand), and the toolchain does
  not even ship `llvm-objcopy`/`rust-objcopy` by default (it needs the
  `llvm-tools` component) — real pipeline risk to all four testbeds for zero
  measured benefit. So the honest, adversarial-shaped residual **stays**, now
  strictly narrower than before: not merely "narrower than the pre-doctrine
  nine-vehicle allowance", but "measurably unreachable by any guest that does not
  literally write `dlsym(...)` itself".

The net effect on ripgrep is the allow list emptying to nothing while the gate
stays fail-closed for any *new* unsupported import — strictly better than the
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
