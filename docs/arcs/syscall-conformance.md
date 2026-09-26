# Arc: Linux x86_64 syscall conformance — every number dispositioned, every model host-checked

Status: revised architecture approved; migration requires bounded parent review.

## Revised contract (supersedes conflicting decisions below)

The design sections below record how the arc was planned (§4 describes the
current scenarios); they are not an authorization to retain foreign-target
inspection, vendored-source parsing, or blessed host answers. The approved
replacement has these boundaries:

- A small dependency-light shared registry crate owns generated syscall identities
  and immutable upstream provenance. Only the active OS/architecture module is
  compiled. Its native `Syscall` metadata has a total `number()`; architecture-only
  variants do not exist on other targets. Darwin identity includes namespace and
  platform subcode, preserving guarded alternatives, holes and invalid slots.
  Linux identity is never borrowed to describe a Darwin ABI.
- An explicit standard-library Python maintainer generator discovers official
  stable Linux and numeric XNU releases, downloads immutable sources into temporary
  storage, validates them, and atomically replaces one checked-in Rust artifact.
  Normal builds are offline and neither parse nor fetch upstream sources. The
  baseline Linux pair has one coherent revision; refresh refuses a stable-release
  downgrade that would drop newer mainline entries. Human support metadata and
  runtime handler bindings remain separate, keyed by generated types rather than
  duplicated syscall numbers or name joins.
- Conformance is a normal root-workspace test package depending on the pure
  registry, not shim source imports or a full runtime linked into the native
  oracle. Runtime dispositions are not the observation oracle. CLI inspection
  reports the compiled target only; foreign selectors and host/reference JSON
  exchanges are removed, not retained as compatibility paths.
- The same reviewed handwritten scenario runs against the live host kernel and
  Patina. Raw observations and OS/kernel/capability facts are run artifacts, not
  committed environment-specific golden answers. Reviewed semantic comparisons
  admit only permitted variation; record/replay remains strictly identical.
  Synthetic comparator fixtures test permitted variation and wrong outcomes,
  never implement a second handwritten kernel. The existing nonempty-directory
  rename errno and statx validity-mask rules retain meaningful negative controls.
- Every generated entry requires an exhaustive typed mapping to a reviewed probe
  or reasoned exclusion. No accepted pending/unwritten state, blanket exception,
  or catch-all for future entries exists. Shared reason categories are acceptable
  with explicit per-entry classification. Existing scenario execution evidence
  may justify several identities; matching names alone does not prove coverage.
  Reserved/invalid entries and destructive global native effects admit honest
  exclusions. Missing runtime support or a missing probe is not a safety reason.
- A safe probe still executes natively when Patina lacks its implementation.
  Expected Patina failures require the specific known refusal or semantic failure;
  arbitrary nonzero exit is not an xfail and unexpected success fails the gate.
  Probe requirements and runtime capability observations are separate from static
  identity. Unsupported, permission-blocked and unexpected host failures differ.
  Missing host capability limits native comparison, not automatically simulation.
- Native probes are trusted, reviewed, unprivileged subprocesses using bounded
  per-run owned resources and deadlines. Cleanup validates positive PIDs or uses
  the existing direct process-group API. No global destructive effect, unowned
  file/process access, privilege change, VM, or sandbox framework is introduced.
  Temporary directories and timeouts are not a security sandbox for arbitrary code.
- Trace obligations survive as each scenario's declared trace facts. There is no
  tamper-proofing manifest: the coordinator reviews scenario and gap diffs at
  landing. Host libtest retains normal concurrency; deterministic guest
  serialization is independent. Default reports are quiet summaries with
  retained logs.

### Bounded migration and acceptance

1. Establish the shared active-target registry, typed support/dispatch seams,
   maintainer generator, and migrated CLI consumers/tests/docs. This includes
   replacing the conformance host/reference JSON exchange and shared foreign-name
   manifest validation with typed target-local probe associations and cfg
   boundaries: removing selectors cannot leave ordinary conformance commands
   broken. Vehicle-number detectors compare actual adapters to the pure registry,
   not shim source imports. Preserve runtime semantics and source pins. Report
   inherited coverage debt honestly; registry compilation is not a claim of
   exhaustive conformance.
2. Move the conformance engine into the root workspace, replace ordinary blessing
   with live differential observations, and preserve capability, precise-failure,
   safety, comparator and frozen-trace contracts.
3. Review every entry's actual exercised probe coverage or explicit exclusion.
   Coverage acceptance remains red until complete; no grandfathered allowlist or
   bypass makes it green. Newly required gate regressions need parent review
   before public intermediate landing.

The installed host-conformance command is a separate distribution-boundary
checkpoint. Any eventual command shares this engine, but must not recursively
invoke Cargo in a way that requires an installed user's missing repository.
No self-sufficient public command is claimed by the workspace migration.
### Implementation checkpoint

Steps 1 and 2 are implemented. The pure registry crate (`crates/patina-syscalls`)
owns identities and dispositions only; the scenarios declare what they cover. They
live in `crates/patina-conformance` and run as ordinary tests
(`crates/cargo-patina/tests/native_conformance.rs`, §4) against the live host
kernel, with no committed expectations, blessing, manifest or frozen-path gate.
Step 3 is open: `mise run conformance:coverage` lists every registry entry of
the target that no scenario covers and no exclusion accounts for, and exits 1
while any remain; it is a local report, not part of `mise run check` or CI.

The durable artifacts are the registry in code and the conformance scenarios.

## 1. Problem

The native shim models the std-shaped core well, but nothing says which of the
kernel's syscall numbers are *deliberately* unsupported. The SUD dispatcher
routes 109 of the x86_64 numbers and answers every other one with a generic
fatal trap; the C interposer layer covers ~250 libc symbols with no mechanical
link to the syscall rows they serve, so the two layers drift (statfs, getcwd,
umask, sched_getaffinity exist in C only; rt_sigprocmask writes `oldset` in C
and not in SUD). Glibc-internal syscalls never trap (SUD's allowed region is
glibc's text), so every libc-only symbol the shim does not strong-define
reaches the host kernel: `copy_file_range` (std `fs::copy`), `fopen`/`mkstemp`/
`realpath`/`scandir`/`shm_open`/`sem_*` all escape today, some of them past the
audit. And no gate compares patina's answers with the host kernel's, so a
"bug" found in a guest may be a patina divergence.

## 2. Decisions (user, 2026-09-08)

1. **Unit of exhaustiveness** = the kernel syscall table per (os, arch), with
   the libc/pthread symbol surface as a second layer mapped onto those rows.
2. **Registry as code, not a static doc.** The SUD dispatch table becomes a
   declarative registry whose rows drive dispatch, `cargo patina syscalls`
   output, and a completeness gate against the vendored upstream table.
3. **Exclusions are narrow.** Only process lifecycle (fork/vfork/exec/wait/
   clone-as-process) and privileged/kernel-config (ptrace/seccomp/bpf/mount/
   modules/keys/landlock/…) stay fatal traps. Cross-process IPC is modeled with
   single-process semantics. Host-network escape stays refused, but SimNet is
   expanded so the guest sees a kernel-shaped network. Signals get a faithful
   model, not a stop-gap. Host identity becomes knob-driven virtual state.
   cwd is modeled. A unified Linux-like fd table is a foundation.
4. **Soft-deny ENOSYS only where ENOSYS is a real kernel outcome callers already
   probe for** (membarrier until the memory+ipc arc models it,
   cachestat, io_uring and Linux AIO, removed numbers). Every stop-gap row
   names the arc that closes it.
5. **Oracle = the host kernel.** Probes are self-checking Rust programs that
   also emit typed observation events; the same binary runs natively, under
   patina, and under patina replay, and the event streams must match except for
   declared, reasoned divergences. Three vehicles per probe (libc symbol, glibc
   `syscall(2)`, inline-asm `syscall`) must agree under patina.
6. **io_uring** gets its own follow-up arc; async signal delivery is part of
   this arc's signal family (D1–D7 below).
7. **No review checkpoints**; run end to end, report at the end. Fable 5.1
   builders in jj workspaces, at most four concurrent, one battery lane.

## 3. The registry (`crates/patina-native-shim/src/registry/`)

```text
crates/patina-native-shim/
  abi/linux/syscall_64.tbl    vendored upstream x86_64 table (mainline snapshot;
                              scripts/refresh-syscall-tables.sh diffs/refreshes)
  abi/linux/syscall.tbl       vendored generic table (arm64 uses it since 6.11)
  abi/darwin/                 pinned XNU BSD/Mach/ARM64 reference sources
  src/registry/darwin.rs      guarded source inventory, independent of Linux models
  src/registry/table.rs       the table parser and the per-arch ABI-column rule
  src/registry/syscalls.rs    const SYSCALLS: &[SyscallRow]
  src/registry/symbols.rs     const SYMBOLS: &[SymbolRow]
  src/sud/mod.rs              BINDINGS (row name → handler) and the dispatch index
                              generated from the rows at compile time
```

`SyscallRow { name, nr: Nr { x86_64: Option<u32>, aarch64: Option<u32> }, family,
disposition, reasoning, closes_in: Option<&str>, since: Option<&str> }` (the handler binding lives in `sud`, by row name). `VIRTUAL_ABI`
is the kernel release the virtual kernel declares; a row whose `since` is newer
is `Absent`. Dispositions:

| disposition | meaning | gate |
|---|---|---|
| `Modeled(handler)` | routed to a runtime entry; semantics host-checked | a probe exists and passes natively + patina + replay, all vehicles |
| `Passthrough` | process-local memory only (mmap anon, mprotect, madvise, brk, mremap, mlock*) | probe asserts no fs/net/clock/entropy reach; strace leak gate |
| `Constant(v)` | deterministic fixed answer (pids, uids, identity) | probe pins the value; expectation declares the host divergence |
| `SoftDeny(errno)` | real kernel outcome callers already handle | probe asserts the errno and the fallback path works |
| `Trap(class)` | named deterministic abort | probe asserts the exact diagnostic |
| `Absent` | number not in this kernel ABI (removed/never implemented) → ENOSYS byte-identical to the host | probe asserts ENOSYS |

The dispatch function is generated from the rows (a match built by macro or a
sorted array + binary search — the builder chooses; the requirement is that a
row without a handler cannot compile as `Modeled`). Tests: (a) every number in
the vendored table for the arch has exactly one row; (b) every row's number
exists in the table; (c) the rows a conformance scenario covers are not
`Absent` and the rows it asserts absent are (`patina-dst-conformance` catalog
tests), and `mise run conformance:coverage` reports rows no scenario covers;
(d) every `SymbolRow` names a symbol the compiled shim
objects define (scanned with the `object` crate as `shim_host_alias.rs` does)
and every defined public symbol has a row; (e) the audit classification lists
in `patina-target` agree with the registry (an interposed symbol is never in a
deny list; a `Trap` symbol is in the deny-trap list).

`cargo patina syscalls [--format json]` prints the
table with dispositions and reasoning (`patina.syscalls/v3`), so humans and
agents inspect the live registry, never a doc. `syscall(2)` (the glibc wrapper)
forwards into the same dispatcher instead of its two-number allowlist.

## 4. The conformance scenarios (`crates/patina-conformance/`)

- A scenario is a plain Rust function over the `Probe` call API
  (`src/scenarios/<family>/<name>.rs`): it issues its calls through one of
  three vehicles — the glibc symbol, glibc's `syscall(2)`, or the inline
  `syscall` instruction (x86_64 only) — asserts the semantic properties it pins
  with `check`, and writes one typed JSON event per observed call. Every
  scenario is built into one probe binary (`conformance-probe <scenario>
  --vehicle V --dir D`). Rows are the registry's typed `Syscall` identities, so
  a row the architecture lacks cannot be issued: on arm64 a legacy row's libc
  door stays and `syscall(2)` issues the generic table's kernel shape (glibc's
  own), and a row with no shape there (`fork`, legacy `signalfd`, most removed
  numbers) is an x86_64-only section.
- Each scenario is one `#[test]` in
  `crates/cargo-patina/tests/native_conformance.rs`: per vehicle, the native
  run (the host kernel is the oracle) must pass and agree with the scenario's
  first vehicle; the `cargo patina run` observation of the same run is compared
  with it field by field. Normalization is typed and declared at the call site
  (`relative` descriptors and ports, `inode`, `identity`, `monotonic`, `mask`,
  documented `alternatives` such as rename(2)'s EEXIST/ENOTEMPTY); the statx
  mask compares requested and recorded fields' validity bits only.
- A gap (`catalog::Gap`, pending with its arc, or by design) is a strict
  expected failure: `Failure::Differs` names every differing field with the
  exact patina value, `Failure::Stops` the exact event count, ending and
  diagnostic. Another failure fails the test, and so does a gap patina no
  longer shows. Gaps are per vehicle and per target (cfg).
- The patina run judged is the recorded one (a plain run of the same seed
  observes the same, checked on a few scenarios); one that completes is
  replayed (identical streams
  and endings; the scenario's recorded-trace facts, e.g. its exact
  `signal_generated` sequence), and run directly under strace with the
  default-deny leak filter (`leak.rs`; the one allowance is a signal to the
  calling thread itself); a native signal death is re-checked on the
  shim-linked binary's own wait status.
- A scenario declares the rows it covers and the rows it asserts absent (past
  the virtual ABI level); a host kernel predating a covered row or the
  scenario's kernel floor makes the scenario not run, printed with the reason —
  as does a host capability the scenario declares it needs and the host lacks
  (on the run directory's filesystem: user xattrs, file handles, whiteouts; in
  the caller's limits or privileges: inotify, lockable pages, an unprivileged
  caller; in the hardware or kernel configuration: protection keys, shadow
  stacks, secret memory, SysV and POSIX IPC, one NUMA node), a host without SUD
  for the raw vehicle under patina, or one without strace for the leak run. A
  host kernel implementing an asserted-absent row stays an oracle: the native
  run answers that row with its declared ENOSYS and only that row's native
  observation is not run (`PATINA_REQUIRE_HOST_ORACLE=1`,
  `PATINA_REQUIRE_SUD=1` and `PATINA_REQUIRE_STRACE=1`, set in CI, turn those
  into failures). The scenarios assert one pinned system, Ubuntu 24.04: its GA
  kernel (Ubuntu's 6.8 build, `VIRTUAL_ABI`) and its glibc (2.39,
  `host::PINNED_GLIBC`); a bump is an explicit, wholesale migration. Only a
  host with both (kernel release `6.8.*`, glibc `2.39`) is authoritative:
  elsewhere a failed native check, a native-versus-patina difference or a gap
  that no longer matches prints `DIVERGES (host H, pinned P)` and joins
  `$GITHUB_STEP_SUMMARY` without failing (`PATINA_REQUIRE_PINNED_KERNEL=1`
  judges any host strictly), while disagreeing native vehicles, replay, trace
  facts, strace and crashes fail everywhere. Every run owns a
  temporary directory and runs under a deadline; a scenario's forked children
  are reaped within one.
- The tests run in the full workspace suite (`mise run check`, CI on Linux
  x86_64 and arm64, the MSRV suite) and not in `check:fast`; streams and logs
  are kept under the target dir's `conformance/<scenario>/<vehicle>/`.

## 5. Foundations (serial where they touch the same code)

| id | foundation | why first |
|---|---|---|
| F0 | registry-as-code; vendored tables; `syscalls` verb; `syscall(2)` forwarding; split `sud.rs` into per-family modules and `patina_posix.c` into per-family C files (pure moves) | every builder appends rows; per-family files let four builders land without conflicts |
| F1 | conformance testbed skeleton + probes for today's modeled rows (clock, open/read/write/stat, dirs, pipes, sockets, epoll) — their host diffs are the first findings | detection before fixes |
| F2 | unified guest fd table in the shim (lowest-free, holes, kind + cloexec per entry, description refcount); driver `Fd`s become internal handles; stdin as a kind (EOF default); dup/dup2/dup3/F_DUPFD/close_range; EMFILE via RLIMIT_NOFILE | select, SCM_RIGHTS, memfd, mq, timerfd, signalfd all need real numbers; today 0x4000_0000 ranges encode kind |
| F3 | path resolver + cwd model in one Rust helper used by C and SUD (`..`, symlink walk, 40 hops, ELOOP/ENAMETOOLONG); chdir/fchdir/getcwd; umask as shim state; errno vocabulary (EPERM, ENODATA, ERANGE, E2BIG, EOPNOTSUPP, EBUSY, ESPIPE, EXDEV) | every fs row resolves through it |

## 6. Families (parallel after F0–F3; each builder: probes red → model → probes green → registry rows flipped)

- **fs**: chown family; utimensat/futimens/utimes/utime; truncate; fallocate;
  statfs/fstatfs/statvfs (SUD rows + one virtual volume); xattr family
  (per-inode map); sync/syncfs/sync_file_range; readahead/fadvise (no-op);
  `access(X_OK)` honors the bit; O_TMPFILE → EOPNOTSUPP until the /proc tree,
  then anonymous inode; copy_file_range/sendfile/splice/tee/vmsplice over
  `patina_read`/`patina_write`; timestamps (`FsClock` on driver ops, relatime);
  st_uid/st_gid from the identity knob; real `d_ino`;
  libc-only holes strong-defined: fopen family, mkstemp/mkdtemp/tmpfile,
  realpath, scandir, statvfs, remove; ustat/sysfs/name_to_handle_at constants;
  cachestat ENOSYS.
- **memory + ipc**: MAP_SHARED coherence with fs-mem (whole-file flush at read
  boundaries while a writable shared mapping is live); memfd_create + seals;
  shm_open/unlink over `/dev/shm` in fs-mem; SysV shm (host memfd-backed
  aliases via host aliases), sem (with SEM_UNDO bookkeeping), msg; POSIX mq
  (fd-backed, blocking on the scheduler) and named/unnamed `sem_*`
  interposers (the baton keeps its host-alias `sem_*`; guest symbols route to
  the scheduler); mincore/mlock constants; Linux AIO soft-deny (a kernel
  built without AIO, §7); membarrier modeled (single process: QUERY reports the modeled
  commands, the rest are ordered no-ops with the kernel's exact validation), its
  SoftDeny(ENOSYS) a stop-gap until then. Its scenarios are `mem/*` and `ipc/*`, one per row group,
  within one process and its threads; the hardware- and limit-dependent ones
  (protection keys, shadow stacks, secret memory, lockable pages, one NUMA
  node, SysV and POSIX IPC) declare host needs, and a behaviour newer than its
  row (self `process_madvise`, `MREMAP_DONTUNMAP`, …) a kernel floor. The
  POSIX `shm_*`/`sem_*`/`mq_*` symbols have no registry rows yet: the probe
  cannot import a wrapper the shim leaves undefined (the pre-run audit would
  refuse it), so the scenarios drive the kernel rows under them.
  Status: file mappings map a per-file page cache (a host memfd; page-granular
  write-back before a read, mirroring after a write) in one model behind both
  doors; `memfd_create` and seals live in fs-mem (trace format 10); System V
  shm/sem/msg and POSIX mq are modeled for one process and its threads,
  blocking on the scheduler, and every `mem/*` and `ipc/*` scenario passes; NUMA
  answers for one node; resource limits are a 16-resource virtual table and
  locking is bookkeeping against its `RLIMIT_MEMLOCK`; no hugetlb pages are
  configured and THP is off;
  `mincore`/`remap_file_pages` pass through; `membarrier` is modeled. The
  virtual CPU has neither protection keys nor user shadow stacks, so those rows
  answer as 6.8 does on a CPU without them (`ByDesign` against a host that has
  them).
  `memfd_secret` is a filesystem file whose bytes only a shared mapping of its
  page cache reaches, the descriptor funnels refusing the rest. Left as named
  traps: the libc
  `shm_*`/`sem_*`/`mq_*` and SysV wrappers (still refused by the
  audit). Scenarios for the resource limits other than `RLIMIT_MEMLOCK` come
  with the time + identity family. Locking and populating need
  `MADV_POPULATE_*` (Linux 5.14, SUD needs 5.11): on an older host the first
  populate stops the run by name, since no fallback is exact (touching pages
  cannot write-fault a private page without changing it, and a host `mlock`
  answers from the host's limit). Known divergences, each narrower than a
  scenario reaches: `brk` is host-direct in glibc, so under
  `mlockall(MCL_FUTURE)` heap growth is neither locked nor refused (the kernel
  refuses it past the limit, `EAGAIN` from `do_brk_flags`); a mapping the
  shim's allocator makes for itself is never locked by `MCL_FUTURE`;
  `mlockall(MCL_CURRENT)` is a named deny (the kernel answers from `total_vm`,
  unreadable without `/proc`); a `MAP_HUGETLB|MAP_NORESERVE` mapping is judged
  at base-page granularity by `munmap`/`mremap`/`mprotect`, and `mlock`
  charges its pages where `mlock_fixup` skips hugetlb; `mlock` of an
  execute-only page answers `ENOMEM` (the kernel populates it with
  `FOLL_FORCE`); `fstat` on a POSIX queue
  descriptor answers `EBADF` (the kernel's is an 80-byte `S_IFREG` inode);
  `move_pages` answers node 0 for a page only ever read, where the kernel's
  zero page answers `-EFAULT`; residency under host reclaim and the host
  descriptor behind each mapped file are residuals 7 and 8 of
  `crates/patina-target/ESCAPE-CLASSES.md`.
- **time + timers + sched + identity**: timerfd (fd kind on the virtual clock);
  setitimer/getitimer/alarm; timer_create family (SIGEV_SIGNAL through the
  signal model, SIGEV_THREAD as a managed task); times; clock_getres; virtual
  CPU time := baton-held virtual time; adjtimex/settimeofday → EPERM; sched_*
  as constants (SCHED_OTHER, prio 0, affinity = virtual cpu set); prlimit64/
  getrlimit/setrlimit/getrusage/sysinfo raw rows; uname modeled; virtual
  `/proc` and `/sys` subtree (cpuinfo, meminfo, stat, self/{exe,maps,status,
  cgroup,mountinfo,auxv}, sys/devices/system/cpu/online, fs/cgroup cpu.max),
  `/etc/localtime`, hostname — all from one `--host-*` knob group recorded in
  the fingerprint; getcpu; personality; syslog → EPERM. Its scenarios are
  `time/*` (clocks, resolution, interval and POSIX timers, timerfd, CPU
  time, the refused clock-setting rows), `sched/*`, `cred/*`, `sys/*`
  (uname, sysinfo, personality, rlimits, hostname) and `proc/ids`'s
  group and session rows;
  `sys/sysfs` exercises the fs family's `sysfs` row, which lists the
  filesystem types the virtual kernel registers.
  What is the host's — its wall clock, CPU set, hard limits, supplementary
  groups, kernel release, node name, memory, uptime, CPU-time figures — is
  compared by relation, never by value; a timer is waited on with a bounded
  `rt_sigtimedwait`/`ppoll`, never a timing assertion; a model answering
  constants fails: CPU time advances across a bounded spin and the CPU-time
  timers fire, remaining times drop across a sleep, and expiration counts
  reach the whole periods measured since arming. Nice 0, the default
  persona, `CONFIG_SYSFS_SYSCALL` and high-resolution timers are detected
  needs. The rows whose
  unprivileged answer is what capabilities bypass (set*id, groups, caps,
  priority raises, realtime policies, hard-limit raises, clock setting, the
  kernel log) need an unprivileged caller and are reported not run as root.
  Status: the clocks decode every clock id once (`src/clocks.rs`), the timers
  run on the virtual clock and CPU time (`src/thread/timers.rs`, timer
  descriptors an `FdKind`), the identity rows answer an unprivileged caller
  in a two-process pid namespace (init pid 1, root's; the guest pid 2; each
  with its own credential, which checks against it read;
  `src/identity.rs`), and per-thread scheduling attributes follow
  `__sched_setscheduler` (`src/thread/sched.rs`), all behind both doors;
  virtual CPU time is a 1 ms modeled startup cost plus the advance-on-spin
  rescues charged to the baton holder, and idle time advances to a timer's
  deadline. The node name is the run's `--hostname` (default `patina`,
  recorded in the trace), and `sethostname`/`setdomainname` answer the
  unprivileged `EPERM`. Every scenario of the family runs without a gap;
  `proc/ids` declares `kill(-1, 0)` a
  by-design difference, since the two-process tree has no process for it to
  reach. The `--host-*` knob group beyond the node name and the virtual
  `/proc`/`/sys` tree are not built.
- **signals + threads + process** (spec and suggested order M1–M5:
  [syscall-conformance-signals.md](syscall-conformance-signals.md)): D1 state in `ThreadRuntime` (dispositions,
  per-task mask, pending sets, altstack); D2 generation records a trace op and
  delivery happens only on the baton-holding task at syscall return / sched
  points / blocking-call resume; D3 kernel-built frames (`host_tgkill` to self
  with the virtual mask installed) so SA_* semantics and `rt_sigreturn` are the
  kernel's; D4 default actions terminate through the real signal (verdict
  records `termination`); D5 EINTR/SA_RESTART per call; D6 thread rows
  (`set_tid_address`, per-thread raw `exit`, main-thread exit while others
  run); D7 C/SUD divergences closed (out-params written); sigwait/sigtimedwait/
  sigsuspend/pause/signalfd; kill/tkill/tgkill/raise/abort/SIGPIPE; SIGSTOP →
  named trap; wait4/waitid → ECHILD; raw CLONE_THREAD → named trap; removed
  numbers → ENOSYS; prctl option table.
- **network + readiness**: AF_INET6; AF_UNIX stream/dgram/seqpacket (path in
  fs-mem, abstract namespace); SCM_RIGHTS after F2; sockopt table (bookkeeping
  vs SimNet-acting); MSG_PEEK/DONTWAIT/NOSIGNAL/TRUNC; sendmmsg/recvmmsg;
  pending connect (EINPROGRESS → SO_ERROR); interface table (`lo` + `eth0`/24,
  no default route → ENETUNREACH; `--net-default-route`) serving getifaddrs,
  SIOCGIF*, AF_NETLINK RTM_GETLINK/GETADDR; UDP-to-nowhere = drop + counter
  (a connected socket then reports the port-unreachable answer as
  ECONNREFUSED, as the loopback kernel does);
  SHUT_RD keeps queued data; epoll ET arrival counters; select/pselect6 over
  the reactor; inotify from the runtime fs funnel; fanotify → named trap.
  Its scenarios are `net/*` and `readiness/*`, one per row group. The native
  oracle is the host's loopback stack only — `127.0.0.1`, `::1`, AF_UNIX
  paths under the run directory and abstract names derived from it, the
  kernel's rtnetlink — so nothing leaves the host, and an off-table
  destination (patina's ENETUNREACH) is never exercised. Host-allocated
  values (ports, netlink port ids, autobind names) compare as labels,
  host-configured ones (the buffer sizes the kernel doubles, MTUs, every
  interface but `lo`) by relation; the virtual table's `eth0` is never
  compared. IPv6 on `lo`, an unprivileged caller and an unprivileged
  fanotify group are declared needs. The privileged network operations (raw
  and packet sockets, `SO_PRIORITY` above 6, `SO_MARK`, `SO_RCVBUFFORCE`,
  rebinding `SO_BINDTODEVICE`, another process's `SCM_CREDENTIALS`) are
  asserted as the EPERM an unprivileged caller gets, not excluded. The
  scenarios reach `getifaddrs`/`freeifaddrs` and the
  `__recv_chk`/`__recvfrom_chk`/`__poll_chk`/`__ppoll_chk` fortify spellings
  through `dlsym`, which under patina answers the shim's own definitions
  (c/posix/dlsym.c), so each is defined in the shim and routed there.
  `uname`, `gethostname` and `res_init` are host identity (the time +
  identity family).
  Status: one socket model (`thread/net.rs` and `thread/net/*`) behind both
  doors — every socket row is a `patina_sock_*` entry that copies guest
  memory through `uaccess` (`process_vm_readv`/`writev` on Linux, the Mach
  VM calls on Darwin: EFAULT, never a fault in the shim; a host that refuses
  the vehicle refuses the run by name at install) and answers the kernel's
  errno order; the C interposers are one-line calls. A send is copied in as
  the protocol takes it (a record once its size is judged, a stream a
  piece at a time), never allocated whole up front. AF_INET and AF_INET6
  (dual-stack wildcard binds, `IPV6_V6ONLY`) run over SimNet with shared
  `SO_REUSEADDR`/`SO_REUSEPORT` bindings, datagram autobind, a connected
  datagram socket found by its whole 4-tuple, the port-unreachable answer as
  ECONNREFUSED on a connected socket, the EINPROGRESS connect, AF_UNSPEC
  disconnect and a reset reported once, then end-of-file; UDP sockets take
  `IP_TOS`/`IPV6_TCLASS`, `IP_PKTINFO`/`IPV6_PKTINFO` (sent and received),
  the hop limits, the RFC 2292 numbers `ip6_datagram_send_ctl` still takes
  and `UDP_SEGMENT` (net/ipctl). AF_UNIX stream, datagram and
  seqpacket sockets (filesystem nodes with their write permission, abstract
  names, autobind, socketpairs as sockets, SCM_RIGHTS/SCM_CREDENTIALS,
  SO_PEERCRED, a listener's unaccepted connections reset when it closes) and
  AF_NETLINK route sockets (RTM_GETLINK/RTM_GETADDR over the interface
  table) are the shim's own; raw and packet sockets are EPERM.
  sendmsg/recvmsg/sendmmsg/recvmmsg, the option store (`SO_RCVLOWAT`
  included), `SIOCINQ` and the `SIOCGIF*` requests, getaddrinfo over numeric
  hosts and the host table, if_nametoindex and getifaddrs are modeled.
  Readiness is each object's kernel poll mask: poll/ppoll/select/pselect6
  read it (select normalizes its timeval as `kern_select` does), and epoll
  keeps a ready list — FIFO by wakeup, level-triggered items re-queued at the
  tail, edge-triggered ones re-queued on each wakeup their source makes (an
  arrival, a receive that frees room for a writer, a condition rising),
  EPOLLEXCLUSIVE validated (its wake-one is "one or more": every instance
  sees the event). Pipe writes of at most `PIPE_BUF` bytes are atomic. Trace
  format 12 adds `net_bind_shared`, `net_connect`, `net_mark` and the
  unreachable send disposition. Left: urgent data (`MSG_OOB` on a stream is
  EOPNOTSUPP, so select's exception set stays empty), `--net-default-route`
  (no default route: off-table is ENETUNREACH), inotify (still a trap),
  fanotify (a named trap by design), the `SIOCGIF*` requests and every
  IP-level control message on macOS (the latter a named fatal), UDP-Lite
  (a named fatal), `UDP_GRO` (receive coalescing), `UDP_CORK`, `UDP_ENCAP`
  and `UDP_NO_CHECK6_TX`/`RX` (each answers ENOPROTOOPT, where 6.8 takes
  it), IP options, `IP_PROTOCOL`, IPv6 flow labels and extension
  headers (named fatals), a packet-information interface index (checked to
  exist, not routed by: the virtual network delivers by address), and wakeups between two epoll scans are queued in
  descriptor order (the model keeps no clock across sources).
- **process lifecycle** (data only): every row `Trap(class)` with its
  one-line reasoning in the registry; `execve`/`set_tid_address` pre-arm
  rows documented as never-trapping.
- **privileged** (user decision, superseding §2.3 for these rows): a
  privileged row answers what the kernel answers an unprivileged caller,
  not a fatal trap. Each row declares the capability the kernel checks and
  the checks that come before it; one virtual credential (uid/gid/groups and
  capability sets; today uid 1000 with none) decides the answer, and a
  capability granted but not modeled is a named fatal. Rows the kernel
  allows an unprivileged caller (keyrings, Landlock, the LSM attribute
  calls, `statmount`/`listmount`, `open_tree` without a clone, seccomp with
  `no_new_privs`) get a real model; rows whose answer is host configuration
  (`perf_event_paranoid`, `unprivileged_bpf_disabled`,
  `vm.unprivileged_userfaultfd`, Yama, the distribution's user-namespace
  policy) take one fixed, declared configuration. The scenarios assert only
  arguments harmless even to a caller whose capability check passed (a bad
  reboot magic, an empty module image, a filesystem type that does not
  exist) and never restrict or kill the probe (no successful
  `landlock_restrict_self` or seccomp install; no namespace is created or
  joined). **Landed** (capability-gated and host-configuration rows): the
  credential (`identity::Credential`), the registry's `capabilities` field,
  the checks in `src/sud/privileged/`, the declared configuration
  (`patina_dst_syscalls::KERNEL_CONFIG`) and the shim's glibc wrappers
  (`c/posix/privileged.c`, `chroot` included); `fs/mount`, `fs/mount_api`,
  `fs/open_tree`, `sys/admin`, `sys/quota`, `sys/ioport`, `sys/root`,
  `sys/perf`, `sys/bpf`, `proc/ptrace`, `proc/namespaces` (the caller's
  `/proc/self/ns/*` files), `proc/seccomp` (its queries, and its mode
  checks up to the named fatal that entering a mode is) and `sys/landlock`
  (rulesets as a descriptor kind; enforcing one is a named fatal),
  `sys/lsm` (the declared stack, capability, Landlock and Yama) and
  `sys/keys` (the process keyring and its `user` keys) run without a gap.
  **Open**: named fatals where the model ends: unsharing filesystem
  state, descriptors or the
  semaphore undo list from other threads, registering a `userfaultfd`
  range (the descriptor and its handshake are modeled: `mem/userfaultfd`
  runs without a gap), non-array BPF map types, detaching a BPF
  program from its attach point; and the rows still `Trap(privileged)`:
  fanotify. `statmount`/`listmount` read the virtual mount table
  (`fs/mount_query` runs without a gap).

## 7. Why the exclusions stay excluded

- **Process lifecycle.** A second process is outside the scheduler, the trace
  and the fs model; the guest's contract is "one process". `wait*` answers
  ECHILD (the exact childless-kernel answer, cannot hide an escape).
- **Privileged / kernel-config** no longer stay excluded: they answer as the
  kernel answers an unprivileged caller (§6, privileged). Removed numbers
  answer ENOSYS because the kernel cannot answer anything else.
- **Host-network escape.** Any address outside the virtual interface table is
  ENETUNREACH; that is a model answer, not a hole.
- **io_uring and Linux AIO.** The virtual kernel is built without both
  (`CONFIG_IO_URING=n`, `CONFIG_AIO=n`): all nine rows (`io_uring_setup`,
  `io_uring_enter`, `io_uring_register`, `io_setup`, `io_destroy`,
  `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents`) are
  SoftDeny(ENOSYS), which tokio-uring, liburing's feature checks,
  mio/monoio and libaio users probe for and fall back from. The host has
  real rings, so `asyncio/io_uring` and `asyncio/aio` pin the ENOSYS
  answers as by-design differences, and keep asserting the kernel's
  answers (a ring's parameters and opcode probe, a no-op round trip; AIO
  on a file and a cancellable poll). A submission/completion ring model
  over the readiness reactor would be its own arc, not started and with no
  arc doc yet; it would turn those differences into the scenarios' targets.

## 8. Sequencing and landing

F0 ∥ F1 → F2 → F3 → {fs, memory+ipc, time+identity, signals, network} in
parallel (≤4 builders, one battery lane) → io_uring arc doc → arm64 table
rows (numbers already in `mod nr`; probes gain the `svc` vehicle) → macOS
table parse. One targeted jj commit per builder, pushed in batches, CI as the
confirmation layer; shim/runtime diffs also run the macOS ladder on jrh-mini.
Doc updates ride each commit: ARCHITECTURE native-shim list, ESCAPE-CLASSES
residual 5, VALIDATION gate taxonomy, testbeds/README row, `llms.txt` verb map.

## Cross-platform entry inventory

`patina.syscalls/v3` is one target-local report contract for Linux x86_64,
Linux aarch64, and Darwin aarch64. Darwin x86_64 is explicitly unavailable.
Common fields are `os`, `arch`, `scope`, `sources`, `metadata`, `rows`,
`symbols`, and `summary`. Row identity is `(namespace, nr, subcode)`; `variants`
retain source entry names, conditions, and table status. Linux runtime fields
(`disposition`, `family`, `reasoning`, `closes_in`, `since`) live under the
row's `linux` object, and its virtual ABI lives at
`metadata.linux.virtual_abi`. Reports contain only the selected target's rows.

Darwin references one pinned XNU revision (`registry/darwin.rs::REVISION`). Its
BSD slots, Mach table slots (negative selectors), ARM special time traps, and
ARM platform selector/subcodes are inventoried, including conditional alternatives,
obsolete/invalid slots, and Mach slots shadowed by ARM dispatch. Mach table slot
0 is not selected by the negative-trap route; slots 3/4 are shadowed by ARM time
traps. `nosys`, `enosys`, `invalid`, and `removed` describe source declarations,
not observed native errno or a Patina runtime disposition. Build guards remain
visible rather than guessing the running host's configuration. The ARM64 Mach
47 branch is explicitly identified; platform subcodes use x3.

Darwin rows say raw entries are `not-interposed`; C symbol statuses are a separate
layer. Explicit Darwin mappings are checked against parsed entries, while shared
symbols carrying Linux semantic associations are reported as not mapped on Darwin
rather than guessed by name. No Linux ABI date or disposition is borrowed. This
inventory does not expand runtime support or establish whole-run containment.
MIG message IDs, commpage APIs, and unassigned selectors are outside this
kernel-entry inventory, not silently counted as supported syscalls.

The parsers refuse malformed/unknown row syntax, duplicate selectors, missing
slots, and lost conditional alternatives. Inventory mutation tests plant dropped
rows/variants and changed namespace/number/status. These are the class-level
pairing for individual source-row regression pins. Refresh reads the pinned
revision and source list from the registry; changing that reference is deliberate
and reviewed, not an ambient kernel-version update.
