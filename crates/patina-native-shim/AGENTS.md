# Native shim agent guidance

Read the root `AGENTS.md`, `ARCHITECTURE.md`, `VALIDATION.md`, and
`crates/patina-target/ESCAPE-CLASSES.md` before changing this crate.

## Doctrine

- The shim's own host access must use private resolved aliases (`host_*` style),
  not public interposable symbols. The guest and shim may use the same native
  primitive only when the shim reaches the real host entry through the alias
  table and guest calls still bind to the interposer.
- A shared symbol allowance is not a fix. If a host effect escapes, first add or
  harden detection so the class fails loudly, then model, interpose, or deny-trap
  the specific surface.
- Dynamic resolution (`dlsym` on Linux) is a second, non-static path into libc:
  the guest never imports the name, so the pre-run audit cannot see it. It
  answers every name the shim defines as a libc contract (the registry's
  `Modeled`/`Partial` rows; `build_support.rs` generates the routing header
  from the symbol inventory) and NULL otherwise — never a
  deny-trapped name, a control-plane entry or a host entry. The table returns
  the code the static linker would have bound the caller to, and never a
  public interposable symbol: the pointers handed out are hidden aliases of the
  definitions, resolved when the shim is linked, so they equal the definitions'
  addresses and cannot be rebound at load time. Returning NULL is not
  automatically the conservative answer: for a symbol the shim models, NULL sends
  the caller down a *less* modeled fallback (this is exactly how `rand::rng()`
  ended up polling the unmodeled `/dev/random` on Linux).
- Interposer semantics should match the public path they replace. Raw-syscall
  dispatch, SUD handling, and C ABI entry points should route through the same
  runtime behavior as the corresponding POSIX interposer whenever possible.
- There is ONE descriptor table (`src/fdtable.rs`), and every guest number goes
  through it. A real guest mixes the two doors in one object's lifetime:
  `cap-std` opens its base directory through std (libc → the C interposer) and
  then does every later operation on it with raw syscalls (→ SUD). Anything a
  descriptor means — its kind, its open file description, its `FD_CLOEXEC`
  bit, where it points — therefore lives in that table, and the universal
  `patina_*` entries (`patina_read`/`patina_close`/`patina_dup3`/…) resolve the
  number and dispatch on its kind, so neither the C layer nor a SUD row decides
  anything by descriptor class: `patina_fd_kind` is the one oracle for the few
  calls whose meaning depends on the kind. A number-range scheme, a per-class
  fd counter, or a class-membership probe is a descriptor one door cannot
  resolve; `close(2)`-then-`open` giving number 2 to a file, `dup2` over a
  standard stream, and lowest-free reuse are the kernel's behavior and the
  table's. Class tables (sockets, pipe ends, eventfds, reactor registries) are
  keyed by an internal handle the guest never sees; guest numbers are never
  recorded. Add a kind by adding an `FdKind` variant: every dispatch site
  matches without a wildcard, so the compiler lists what the new kind must do.
- A descriptor names a NODE, not a name. The shim keeps only what the filesystem
  cannot answer — which descriptors are directories — and asks the filesystem
  where a descriptor's node is now (`fs_fd_path`). A name cached beside a
  descriptor goes stale exactly where it matters: a rename detaches the
  descriptor, and a symlink planted at the vacated name silently captures every
  later resolution through it, which is the redirect a capability handle exists
  to prevent. Shim-side bookkeeping that shadows namespace state is a second
  filesystem model, and the two will disagree. The working directory is held
  the same way — a path-only driver handle, never a string — so `getcwd` asks
  the filesystem for its current name and answers `ENOENT` once it is unlinked.
- There is ONE path resolver (`src/paths.rs`), and every `patina_*` entry that
  takes a `(dirfd, path)` pair goes through it, so the C interposers and the SUD
  rows are two spellings of one resolution: the working directory for
  `AT_FDCWD`, a directory descriptor's node otherwise, `.`/`..` applied to the
  resolved directory AFTER symlink expansion (never lexically across a link),
  symlinks walked to the kernel's 40-hop `ELOOP`, `ENAMETOOLONG` at
  `PATH_MAX`/`NAME_MAX`, `ENOTDIR` for a component through a non-directory, and
  the trailing-slash rule. `openat2`'s `RESOLVE_*` restrictions are rules of
  that same walk (the scope's root bounds `..` and absolute symlinks, a symlink
  met under `NO_SYMLINKS` is `ELOOP`), never a second resolver. The driver keeps
  its strict canonical-only contract underneath (it refuses `..` and an
  intermediate symlink), which is defense in depth, not a second resolver.
  Resolution costs one driver `metadata` on the common path and walks component
  by component only when that lookup cannot decide (a missing name, a refusal, a
  `..`); the resolved entry's KIND is what the open entry routes on, so a
  directory opened without `O_DIRECTORY` is still a directory descriptor. The
  umask is process state applied by the creating entries before the driver call,
  so the driver stores — and the trace records — the mode the kernel would.
- Metadata a guest can CHANGE has to be modeled, not synthesized. `st_mode` was a
  per-kind constant until a sandbox's own test suite needed `EACCES` to be
  distinguishable from `NotFound`; permission bits now live on the entry, change
  through interposed `chmod`/`fchmod`/`fchmodat` as recorded boundary operations,
  and are ENFORCED against the one non-root identity the runtime models. A
  fabricated constant is not a neutral default — it is an answer the guest will
  act on. The owner and the timestamps followed: `st_uid`/`st_gid` are the ONE
  modeled identity read through one accessor (`patina_uid`/`patina_gid`, the
  same value `getuid` answers), never a per-entry field, and `chown` is a
  comparison against it (its own ids or -1 succeed, with the kernel's
  setuid/setgid kill and a `ctime` move through the one mode entry; anything
  else is `EPERM`); every entry carries atime/mtime/ctime/btime stamped by the
  kernel's rules from the virtual clock the runtime hands each driver operation
  (`FsClock`, read unrecorded — the value is a function of the recorded sleeps,
  so replay reproduces it without a second trace op per fs call), and
  `UTIME_NOW` resolves after modeled latency to that same instant before it crosses the recorded boundary. The runtime fixes atime policy to relatime; there is no unrecorded runtime policy knob. The
  remaining synthesized fields (device numbers, the statx mount id) are the same
  hazard waiting for the guest that reads them.
- An ARGUMENT the guest supplied is not a synthesized field's smaller cousin —
  dropping it is the same bug. Every creating call carries its mode across the
  boundary (`open`'s third argument, `openat`'s, `creat`'s, `mkdir`/`mkdirat`'s,
  `mkfifo`'s), and the driver applies the modeled umask exactly where a kernel
  applies the process umask. Reconstructing a "typical" mode on the far side
  looks right for the `0o666`/`0o777` callers and silently wrong for the caller
  who asked for `0o400` — and permission enforcement then judges every later
  open against the invented value. Read the variadic mode only when the flags
  say the kernel would: `open` needs its third argument for `O_CREAT` or
  `O_TMPFILE`, and otherwise must record no mode at all rather than whatever
  happened to be in the register.
- A descriptor answers metadata from the FILESYSTEM, not from a copy taken when
  it was opened. `fstat` on a FIFO endpoint — the one descriptor class the
  filesystem does not hold a handle for — asks the driver about the endpoint's
  INODE, so a `chmod` after the open is visible and a hard-linked FIFO reports
  its real link count. A snapshot beside the descriptor is the same stale-cache
  bug as a cached path, one field over. There is no window where a copy answers
  instead: a descriptor is a REFERENCE on the node, so unlinking the last name
  leaves the node fully alive behind it (link count 0, live mode) and `fchmod`
  through the endpoint still reaches it. A reference the filesystem cannot see
  has to be handed to it — `fs_retain_inode` when the pipe channel behind a FIFO
  comes into existence, `fs_release_inode` when it is reclaimed — because "the
  filesystem forgot the node while the guest was still holding it" is
  indistinguishable, from the guest's side, from corruption.
- A FLAG the guest supplied is not free to conflate either. `O_PATH` and
  `O_RDONLY|O_DIRECTORY` are two different opens: the first opens nothing (the
  kernel charges nothing on the entry, and the descriptor resolves `*at` paths
  and answers `fstat` but can never be read), the second opens the directory for
  reading and costs `r`. Collapsing them charged the wrong bit on the hot path of
  every capability guest — `cap-primitives` spends most of its opens on `O_PATH`
  — and pushed the `r` check onto the LISTING, where a `chmod` after the open
  could still reach a walk already under way. Access is charged where the kernel
  charges it: once, at open. That is also why directory iteration takes a
  DESCRIPTOR (`patina_read_dir(fd, …)`) rather than a path, and why the libc
  `opendir` mints its own descriptor first instead of reading a name — the fd is
  what the permission decision was made about, and `dirfd()` on the result is
  then a real descriptor rather than a refusal.
- An entry whose NAME is filesystem state and whose BYTES are not gets ONE model
  for each half, and they stay apart. A FIFO's name lives in the deterministic
  filesystem (created, stat-ed, listed, chmod-ed, renamed, hard-linked, unlinked
  like any other) while its transfer reuses the SAME in-process pipe channel an
  anonymous `pipe`/`socketpair` uses — keyed by the entry's INODE, so two openers
  of one named pipe meet, a rename cannot split them, and a second hard link is
  a second name for the same pipe rather than a second pipe. That last property
  is why the FIFO table is inode-backed like the file table rather than holding
  its own private metadata: an identity two subsystems agree on has to be ONE
  identity, and a link table that cannot see a kind is a link table that refuses
  it. A second pipe implementation
  behind a filesystem descriptor would have to re-derive blocking, EOF and
  `EPIPE`, and the two would drift; conversely, letting the driver hold the bytes
  would make a crash model responsible for data no real FIFO ever persists. The
  seam is the one branch in `patina_openat`: the driver judges existence,
  resolution and permissions and then declines to hand back a descriptor, and the
  caller reads the refused entry's kind on the failure path only.
- A file mapping is a VIEW of the file's page cache, never a copy: the page
  cache of a mapped file is a host memfd the shim holds (`src/mem/cache.rs`),
  which `MAP_SHARED` views map directly and `MAP_PRIVATE` views map
  copy-on-write, so every view and the shim itself (through `pread`/`pwrite`
  on the memfd) see one set of bytes and the kernel's shmem rules answer for
  them. The filesystem stays the store the crash model judges: the descriptor
  funnels write back the pages views changed before a read (through the
  write-back driver op write seals do not refuse), mirror a write, truncation
  or allocation into the page cache after the filesystem accepts it, and
  `msync(MS_SYNC)`/`fsync`/`syncfs` make the stores durable. The hooks
  (`mem::reading`, `written`, `written_at_cursor`, `resized`, `allocated`,
  `syncing`, `syncing_all`, `released`, `crashed`) are called from `lib.rs`,
  `transfer.rs`, `iov.rs` and `advice.rs`; a new funnel that reads or changes a
  regular file's bytes has to call them too, or a mapping of that file goes
  stale. The address-space rows (`mmap`, `munmap`, `mremap`, `mprotect`, fixed
  placements) keep the view table — and the System V attachments, page locks
  and range memory policies it also holds (`src/mem/ranges.rs`) — in step with
  the host's.
- Nothing the host decides about memory may reach the guest as an answer: page
  locks are bookkeeping against the shim's own `RLIMIT_MEMLOCK` (never a host
  `mlock`, whose answer depends on the host's limit), the hugetlb pool is
  virtually empty, THP is disabled at startup so residency is per page, and a
  host memfd the shim cannot get (its descriptor limit) is a named fatal, not
  the guest's `EMFILE`.
  What stays host-decided (reclaim and swap evicting a page `mincore` reports)
  is listed in `crates/patina-target/ESCAPE-CLASSES.md`.
- Model a rendezvous the way the kernel models it, counters and all. A blocking
  FIFO open waits for the PARTNER'S OPEN COUNTER to move, not for a partner to
  still be there (`fs/pipe.c:fifo_open`); waiting on presence loses the writer
  that opens and closes again before the reader is scheduled, which is precisely
  the interleaving a cooperative scheduler makes reachable. The park is the
  ordinary baton park, so the wake is another task's call and a FIFO nobody opens
  for writing is a deadlock report rather than a hang.
- When a syscall has an old and a new form the ecosystem probes in sequence
  (`faccessat`/`faccessat2`, `stat`/`statx`), model BOTH. Denying the newer one
  is technically fail-closed but the deny diagnostic then prints on every call in
  a hot loop, which is its own kind of nondeterminism-shaped noise. Reserve the
  named deny for a form with no modeled fallback (`O_PATH|O_NOFOLLOW` on a
  symlink, which names a link entry nothing here has a descriptor for).
- Bootstrap and reentrancy paths are load-bearing. Avoid allocations, locks, or
  formatting in early-init/fatal paths unless the path is proven safe under the
  custom allocator and host-collection rules.
- An entry point that can answer WITHOUT reaching `ensure_runtime` must consult
  the stored init-error state. Otherwise a failed initialization is a refusal the
  guest never sees: it runs on fabricated values and exits 0, or spins. Two such
  paths exist. The shim-bootstrap window is the larger one, and it does not close
  when initialization fails — the private bootstrap flag is cleared only by a successful
  install — so enter it only through `in_shim_bootstrap`, which makes the check
  for you; the flag is private to that predicate's module. Captured stdio is the other: it
  accepts bytes with no context installed, and shutdown then drops them. When
  adding an entry point, ask what it answers with no runtime installed; if it
  answers at all, call `abort_if_init_failed` and give it a leg in the
  cargo-patina e2e that drives each such path through a mismatched
  `--fingerprint` replay.
- Test the reentrancy, not just the answer. Aborting is not free on these paths:
  the diagnostic write flushes captured stdio, which deallocates through the
  guest's global allocator, which can come straight back through an interposed
  lock. A shim-internal call arriving while a shim spinlock is held must never be
  the one that triggers the abort.
- A trap handler must contain a determinism escape without swallowing anything
  else. Both traps (`SIGSYS` for syscall-user-dispatch, `SIGSEGV` for the
  timestamp counter) decode at the faulting IP and act only on encodings they
  fully recognize. Every other `SIGSEGV` goes where the kernel would send it
  under the guest's own (virtual) action (`src/thread/signals/fault.rs`): the
  guest's handler runs from the trap's frame, or the default action takes the
  fault, and a genuine segmentation fault still kills the process at the true
  address. A handler that "helpfully" resumes on an unrecognized fault would
  step the guest past an instruction it never executed. The trap takes the
  thread for the shim first (`patina_trap_enter`), so a `SIGSEGV` while shim
  code owns it (an entry, a shim lock held, the trap's own glue) is a named
  stop, never handed to the guest. `SIGBUS`, and `SIGSEGV` where the trap is not
  armed, get the same from a front handler on every Linux arch
  (`patina_fault_front`), whose host action carries the guest action's flags,
  mask and restorer; macOS guest handlers are still the host's own.
- Installing a signal handler at init changes what Rust std does later. std
  installs its stack-overflow `SIGSEGV`/`SIGBUS` handlers only over `SIG_DFL`
  (`sys::pal::unix::stack_overflow::init`), so `sigaction` reports the guest's
  virtual `SIGSEGV` action, not the trap's.
- Every shim-owned host handler (SIGSYS, the counter trap, the front handler)
  is `SA_ONSTACK`, and each managed thread registers a guarded private stack
  (`src/thread/signals/frames.rs`, armed from `patina_fault_front_installed`
  on the main thread and from `thread_prelude` on the others, before guest
  code) `SS_AUTODISARM` as its host alternate stack: kernel frames are never
  on a guest stack. The guest's alternate stack is virtual. The front handler
  is the host action of every signal the guest has a handler for, and runs
  it through `patina_call_guest_handler` on the stack its action asks for,
  with the host registration naming a free level of the private stack while
  it runs (its own frames fit its level, `PATINA_FRAME_MARGIN` included).
  Running handlers are re-derived at each trap from guest code and before a
  libc door delivers (`resync`), never counted: a `siglongjmp` skips every
  return path. The private stack is
  fixed levels; a running handler owns its level and the registration names
  the highest free one. Free a level only on proof that cannot be faked (the
  slot word overwritten, or a later delivery overlapping the slot): never on a
  stack pointer, since a handler may be suspended in a coroutine on any stack.
  `release` clears the records with the mapping. The page above each owned
  level is a guard (`sync_guards`) whenever the record set changes. Any
  handler the shim installs later (the watchdog's sampler) is `SA_ONSTACK`
  too. The level budget, checked by
  `private_signal_stack_levels_fit_their_budget`, keeps the handler cap, not
  the host, deciding the depth stop. A frame built over another not yet entered is resolved
  to what that one interrupted (`patina_interrupted_sp`). The guest's handler
  returns into the shim, never into its `sa_restorer`. Internal stops reset
  SIGABRT to its default first (`host_abort`): a front-routed guest SIGABRT
  handler must never run inside a stopping shim. Unmapping skips a private
  stack the thread is running on (raw `exit` served by the syscall trap).
  A handler's libc-door calls still run shim code on the handler's own stack;
  only trap-door entries are private. So a Rust stack overflow prints std's
  report, but std's `abort` through the shim then overflows std's 8 KiB signal
  stack: the run dies of SIGSEGV (a named shim fault) where natively SIGABRT.
  Check this interaction before adding any new handler.
- A trap that the audit cleared a binary against must fail CLOSED at arming
  time. The gate decides "this binary is trap-managed here" from a marker plus a
  live platform probe; if arming then quietly did not happen, a contained escape
  becomes a silent one. Arming failures abort loudly rather than continuing
  unarmed.

## Signal boundaries

- Panic ownership suspension does not remove a Rust frame or its destructors.
  A C callee cannot make a guarded Rust caller safe across guest siglongjmp or
  context restoration. Before moving an adapter, trace model calls through
  sched_point, blocking resume and SUD dispatch as well as its explicit delivery
  helper. The follow-up audit in `docs/arcs/c-to-rust.md` records the existing
  model/delivery lifetime blocker; passing guest tests does not establish this
  Rust language invariant.

- `raise` is a modeled entry on both platforms, not an audit allowance. Darwin's
  `thread/signals_darwin.rs` records generation for the baton holder before the
  private current-thread vehicle delivers an unblocked ordinary handler. It
  releases locks and suspends panic ownership first. Deferred/siginfo delivery,
  reserved SIGSYS and default process stops remain named refusals. Do not replace
  this with host `raise` (which may fall back to process-directed delivery), or
  admit host siginfo fields. Pair changes with `native_signals::self_raise_*`
  and the audited compute-watchdog guest, retaining the actual raise probe.

- `host_abort` / `patina_host_abort` are private internal-fatal vehicles. They
  never finalize a trace. Guest `abort` raises SIGABRT through the virtual
  kernel (the handler runs, then the default disposition); fatal default
  dispositions finalize exactly once, then use the private host vehicle; never call public `abort`
  while holding shim locks. Rust ABI entries claim a thread-local panic scope;
  guest callbacks suspend it. POSIX startup installs the policy independently of
  Context; bare prefixed-C links have no guest abort interposer and do not install
  it or require host aliases just to initialize. The production hook writes
  directly to host stderr and private-aborts shim panics, delegating guest panics
  to the previous hook.
  Unwinding owned scopes and panic-time abort preserve this refusal if a guest
  replaces the hook. Libtest retains its own hook. Add an entry scope to every
  new Rust export and suspend it around guest callbacks.
- `thread/signals` owns dispositions, pending sets, generation and delivery.
  `thread/readiness` owns poll/select/epoll waits and uses only the signal wait /
  temporary-mask hooks. Park sites supply typed `Wait` registrations; diagnostic
  reason strings must not decide cleanup or restart policy. Pthread waits retain
  semantic queue position during a handler, then resume transparently without
  EINTR or a second wake if an ordinary grant arrived meanwhile. A handler that
  would itself park on a pthread wait while interrupting one is a named fatal
  refusal, before enqueue or notification changes (also after an outer grant).
- A guest's alternate stack is shim state per host thread with 6.8's rules
  (`frames.rs`); the host's is the private stack. Raw actions report the
  caller's exact flags/restorer; libc actions use the glibc restorer captured
  at initialization. A guest's `SIGSYS` action is stored
  and queried virtually, never installed on the host; guest SIGSYS generation
  stops by name (seccomp enforcement is not modeled). A `SIGSEGV` action under
  the counter trap stays virtual, and every mask
  a guest installs loses both on the host; SIGSEGV's block is kept virtually
  instead (`src/thread/signals/fault.rs`). A handler can still add
  them to its frame's saved mask: a guest restorer's frame is stripped before the
  kernel's `rt_sigreturn`, but glibc's restorer (and arm64's kernel trampoline)
  returns with no trap, so the delivery point strips the restored mask again once
  the frames return, naming the change once per run on stderr. Until then a
  sibling handler of the same batch runs with them blocked, and a raw syscall
  there dies by `SIGSYS`. Ordinary no-pending syscall returns perform no host
  signal queries; frame fixups read only explicitly dirtied mask/stack fields.
  Frame release preserves both dirty bits across nested SIGSYS fixups.
- A guest's own restorer returns through the host kernel's `rt_sigreturn`:
  the SIGSYS handler and the assembly `syscall(2)` entry both resume at
  glibc's real `syscall(2)` with the guest's stack pointer, never replaying a
  frame in the shim. The frame's saved mask loses the containment signals
  first. Anything that re-enters `syscall(2)` must keep that entry's stack
  pointer contract. `restart_syscall` answers `EINTR`: no restart block is
  ever pending (waits a handler interrupts end at their own resumption).
  A pidfd (`FdKind::Pidfd`, `src/sud/pidfd.rs`) names the guest's process or
  init by its virtual pid; `pidfd_send_signal` generates through
  `generate_signal` like `kill`, never a host signal.
- `cargo-patina/tests/native_signals.rs` and `native_containment.rs` use the
  shared `tests/common` builder and `testbeds/native-boundary/signals/` guests
  to build fresh strong C interposers and execute real
  inline SUD calls. It detects libc/raw state splits, reserved-signal damage,
  unrelated-handler sigwait interruption, and internal-fatal trace finalization.
  The signals unit harness checks exactly one selected child test and, for
  ordinary isolated bodies, one passed test. Lifecycle tests instead assert
  their deliberate exit status. Keep the planted-body-failure and empty-filter
  detector paired with this harness.

## Layout: families, the registry, and the vendored tables

- The staged `patina_posix.c` is ONE translation unit assembled from the
  ordered family inventory in `build_support.rs`. The build script generates
  both its includes and `POSIX_C_FAMILY_SOURCES` from that inventory, so every
  included slice is exported for installed builds. Slices share headers and
  static helpers and are not compiled separately. System headers belong in
  `posix/core.c`; compilation checks the assembled translation unit.
  The same build script generates the Linux dlsym routes from the complete
  symbol inventory, including architecture metadata. Its versioned metadata
  comes from the normal syscalls dependency's build output; the shim does not
  compile the full syscalls crate again as a host build dependency.
- Every ordinary exported Rust function starts with
  `let _panic_scope = crate::panic_boundary::PanicScope::enter();`. The AST lint
  checks explicit function definitions and skips attribute comments.
  Keep exports explicit rather than hiding them in macros. It reserves
  `_panic_scope`: no other reference may drop, move, capture, or expose the guard.
  The gate tests every rule against valid and invalid syntax fixtures before
  scanning Rust files under the crate; external module paths are not checked.
  Abort and the three stack/trap ownership primitives implement ownership
  themselves; a normal guard would change their
  behavior. The unit-test-only fake host resolver is also exempt.
  The `test-panic` feature adds an armed clock-panic failpoint and its control
  export for the unwind/abort acceptance test. Production builds omit both.
  `ThreadError::into_posix` returns an opaque errno; convert it explicitly to
  `c_int` for pthread/error plumbing, and use `fail` for transfer-count errors.
- The time and identity models are Rust modules both doors call:
  `src/clocks.rs` (every clock id decoded once, CPU time, the clock-setting
  rows, `times`/`getrusage`), `src/identity.rs` (credentials, groups,
  capabilities, process group and session, `uname`, `sysinfo`),
  `src/thread/sched.rs` (per-thread scheduling attributes, affinity,
  I/O priority, persona) and `src/thread/timers.rs` (interval timers, POSIX
  timers, timer descriptors). A timer expires where virtual time is next
  observed (`timers::fire_due`, called from signal delivery and the rows that
  read timers or pending signals) and while every task waits
  (`ThreadRuntime::next_task`); a new path that waits on the scheduler has to
  go through `block`/`block_timed` so idle time reaches the timers.
- The memory and IPC models are Rust modules both doors call: `src/mem/`
  (mappings and page caches in `mod.rs`, `cache.rs`, `ranges.rs`;
  `memfd_create` and seals in `memfd.rs`; `membarrier` in `barrier.rs`),
  `src/numa.rs` (memory policy on one node), `src/limits.rs` (the 16
  resource limits `getrlimit`/`setrlimit`/`prlimit64` answer, read by the
  descriptor table, lock accounting and message queues) and `src/thread/ipc.rs` (System V
  IPC and POSIX message queues, which block on the scheduler and so live with
  the thread runtime; every wait settles through `wait_on`).
- `src/sud/` is the SUD dispatcher: `mod.rs` holds the shared constants, the
  `patina_*` externs, the handler BINDINGS, and the dispatch index generated
  from the registry; the `sys_*` handlers live in per-family modules
  (`time`, `sched_identity`, `fd_io`, `fs`, `mem`, `signal_process`, `net`,
  `readiness`). The privileged rows are checks, not handlers: `privileged/`
  holds each row's pre-capability checks over the virtual credential
  (`identity::credential`) and the declared kernel configuration
  (`registry::KERNEL_CONFIG`), in the kernel's order, and `privileged::answer`
  turns a granted capability or an unmodeled path into a named fatal; the
  x86-only port rows there are `cfg`-gated. A handler for a row only one arch's table lists lives in that
  arch's module (`x86_64`: `dup2`, `poll`, `utime`, …), compiled only where
  the registry gives the row an identity. A family module holds only handlers
  every Linux table binds, so an arch-only handler there is dead code, a
  `-D warnings` error, on the other arch.
- `src/registry/` re-exports the dependency-free `patina-dst-syscalls` crate.
  Its `generated.rs` owns cfg-native identities, numbers and immutable provenance;
  `linux.rs` owns exhaustive typed runtime dispositions; `symbols.rs` describes
  the separate libc surface. SUD binds typed identities, never copied numbers.
- Refresh with `scripts/refresh-syscalls.py` (pinned reproduction by default;
  explicit apply replaces one artifact atomically). No upstream raw files are
  vendored and normal builds neither parse nor fetch source tables.

Rules that follow:

- Routing a number = flipping its row's disposition AND adding a `BINDINGS`
  entry in `src/sud/mod.rs` in the same change. A `Modeled`/`Passthrough` row
  without a binding, a `Trap`/`Absent` row with one, or a binding that names no
  row is a compile error (`build_dispatch`); the by-name twin is
  `sud::tests::bindings_match_the_registry_rows`.
- A new C or Rust interposer needs a `SymbolRow` (platform, the rows it serves, a
  status); the object-scan gate (`cargo-patina/tests/syscall_registry.rs`)
  fails on an unlisted definition, a stale row, or an `Absent` row that gained
  a definition. A deny-trap needs a `Deny(class)` row AND its entry in
  `patina-target`'s deny-trap list; the gate holds the C sites, the rows, and
  that list in three-way agreement.
- The libc `syscall(2)` interposer (`src/variadic/`) forwards EVERY ordinary number into
  `patina_sud_dispatch`: never add a number-specific branch there; add the row
  and binding instead, so the three vehicles cannot disagree.
- Reasoning strings are the diagnostic a guest sees on a trap; keep them
  one-line, present-tense, and honest about what is modeled today.

Rust variadic entry points live under `src/variadic/`, enabled only by the
private `patina_posix_exports` compiler cfg on the guest archive build. Keep it
off dependency rlibs, unit tests and bare prefixed-ABI links. Guest archive
builds use one codegen unit: the extraction anchor and Linux assembly aliases
must share the definitions' object. The C constructor references the anchor;
Linux dlsym routes use hidden aliases, never cross-object C alias attributes.
A successful many-codegen-unit build does not replace this extraction contract,
especially on Darwin, where the Linux routing table is absent.

Read optional arguments only when the command or flags consume them, using the
promoted C type. The open doors consume a mode for `O_CREAT` or all of
`O_TMPFILE`; Darwin's mode promotes to int. Pointer operands stay pointers.
Ioctl scalar widths are request-specific too: terminal requests take promoted
int, but INOTIFY_IOC_SETNEXTWD needs its full unsigned-long range check. Keep
oversized operands in the argument-category guest and compiled mutation matrix.
Fixed flag, errno and expressible layout translation belongs alongside the Rust
door. The fcntl/open cancellation check immediately follows the panic guard;
it refuses pending cancellation by name and never initiates forced unwind.
Compiled C guests in `native_abi::variadic` exercise pending cancellation at
the fcntl waiting commands and open doors; entry order is reviewed.

The modeled stdio engine lives in `src/posix/stdio.rs`; Rust printf doors pass
`VaList` directly to it. It formats byte buffers with a private resolved host
vsnprintf, cloning the arguments before the stack pass for the heap fallback.
The [C reduction design](../../docs/arcs/c-to-rust.md) also moves host-resolution
vehicles. Retain its enumerated cancellation, cleanup,
nonlocal-callback, emergency-fatal and guest-fault-store C seams. Environment
ownership is already Rust (`src/posix_env.rs`) in the guest-only archive. Linux's
syscall assembly captures raw machine words for the fixed Rust entry; it must
not decode six fictitious variadic arguments or lose the guest-SP sigreturn
path. New doors must satisfy the export guard without exceptions and extend
the compiled ABI acceptance cases. See [the design](../../docs/arcs/c-variadic-interposers.md).

## Source bundle and `links`

`cargo-patina` does not build this crate from a source checkout: it embeds the
shim's whole workspace dependency closure (this crate and the eleven runtime
crates beneath it) at its own build time and unpacks it into a per-user cache
when a guest is built, so an installed binary is self-sufficient (see
ARCHITECTURE.md "Native (linked shim)" and `crates/cargo-patina/build.rs`).

- Every closure crate declares `links = "<package-name>"` and carries a build
  script whose only job is `cargo:src_dir=$CARGO_MANIFEST_DIR`. Cargo exposes
  that to the build script of every DIRECT dependent as `DEP_<PKG>_SRC_DIR`,
  which is how `cargo-patina`'s build script learns where each crate's source
  is — the one documented channel for that, and it works the same in-tree, from
  the crates.io registry checkout, and from a git checkout. `cargo-patina`
  depends directly on all twelve crates for this reason alone; do not "clean
  up" the ones it does not otherwise use.
- `links` has a side effect: cargo refuses two versions of a `links` crate in
  one dependency graph. For a runtime with one global context that is the
  desired outcome — two runtimes in one process would be two contexts — so keep
  the declaration; the value is a name, not a native library.
- A crate added to or removed from the closure (`cargo metadata` on
  `patina-dst-native-shim`) must be added to or removed from the `links` set,
  `cargo-patina`'s direct dependencies, and the `SHIM_PACKAGES` table in its
  build script together; the build script fails loudly on a missing
  `DEP_*_SRC_DIR`.
- The embedded manifests are normalized (workspace inheritance resolved,
  closure deps repointed to sibling paths, dev-deps dropped). A new kind of
  workspace-inherited key (`[lints] workspace = true`, say) is refused at build
  time rather than shipped broken; extend the normalizer deliberately.
- The unpacked bundle carries no toolchain pin or version-manager config and
  must never gain one at build time. Native builds materialize the guest
  compiler from its sysroot, verify its full identity from the guest and bundle
  directories, and drive both builds with that absolute compiler. Cargo comes
  from that sysroot unless explicitly supplied; relative `RUSTC`/`CARGO` paths
  are anchored to the guest directory. Operators do not need an ambient
  toolchain override merely because the bundle lives outside their pinned tree.
  Unqueryable or unverifiable compilers still refuse before compilation; never
  fall back to the cache directory's ambient compiler.

## Change checklist

- Keep C and Rust ABI signatures in lockstep. Variadic libc functions must be
  declared variadically on the host side; do not hand-declare a fixed argument
  form for a variadic function. A `patina_*` entry point has THREE declarations
  — the Rust definition, `include/patina_native.h`, and the SUD dispatcher's
  `extern` block — and changing an argument list means changing all three; the
  compiler catches two of them and the third is a link-time surprise.
- After editing `build_support.rs`, a slice under `c/posix/`, or related
  embedded C sources, rebuild `cargo-patina`; validating with a stale runner is
  an accidental false green.
- Guest binaries pick a shim change up on their own: the flags `cargo patina
  build` injects carry a hash of the shim link inputs' bytes, so Cargo relinks
  the guest whenever this crate (or the runtime beneath it) is rebuilt. A guest
  still showing the old behavior after a rebuilt `cargo-patina` is a real
  result, not a stale build.
- Run targeted shim tests and `mise run check:native-abi` for first feedback on a
  native interposition change; run `mise run check` for the full native typed
  targets, ecosystem testbeds and landing evidence. If the change can affect WASI or cross-target behavior,
  also run `scripts/validate-wasi.sh` and `scripts/smoke-cross-target.sh`.
- OS- or architecture-specific paths must be executed on that OS/arch before
  being described as working; cross-clippy/cross-builds are useful, but not
  execution evidence.
- The shim reads the guest's own environment — `/proc/self/maps` for the SUD
  region, the binary's mapped NAME — so a probe's FILE NAME is part of its
  input. One was named `libc-at-probe` and the legacy-glibc basename match
  (`libc-`) counted it as a second libc segment, which refused the run at
  arming time with a diagnostic about glibc's segments. The match now requires
  the version digit, but when a fresh probe fails in a way its source cannot
  explain, suspect the ambient facts (name, path, size, layout) before the
  code.

Darwin inventory is separate from Linux runtime rows. The generated native
Darwin module preserves BSD/Mach/ARM namespace, subcodes, guarded alternatives
and invalid slots. Never infer runtime support or observed errno from a source
declaration. Raw-entry coverage and C symbol status remain distinct.

When moving Darwin libc adapters, inspect the header's symbol spelling with
the packaged C feature macros. For example, `_DARWIN_C_SOURCE` makes allocating
`realpath` bind `realpath$DARWIN_EXTSN`. Pair the existing compiled-object
registry gate with the real C caller; a Rust export of the plain name can
compile and link while the caller still reaches libSystem.
