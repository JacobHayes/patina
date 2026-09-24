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
   probe for** (openat2, rseq, membarrier, cachestat, io_uring until its arc,
   removed numbers). Every stop-gap row names the arc that closes it.
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
- A patina run that completes is also recorded and replayed (identical streams
  and endings; the scenario's recorded-trace facts, e.g. its exact
  `signal_generated` sequence), and run directly under strace with the
  default-deny leak filter (`leak.rs`; the one allowance is a signal to the
  calling thread itself); a native signal death is re-checked on the
  shim-linked binary's own wait status.
- A scenario declares the rows it covers and the rows it asserts absent (past
  the virtual ABI level); a host kernel predating a covered row, or
  implementing an asserted-absent one, makes the scenario not run, printed with
  the reason — as does a host without SUD for the raw vehicle under patina or
  without strace for the leak run (`PATINA_REQUIRE_HOST_ORACLE=1`,
  `PATINA_REQUIRE_SUD=1` and `PATINA_REQUIRE_STRACE=1`, set in CI, turn those
  into failures). Every run owns a
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
  the scheduler); mincore/mlock constants; Linux AIO soft-deny (closes in the
  io_uring arc).
- **time + timers + sched + identity**: timerfd (fd kind on the virtual clock);
  setitimer/getitimer/alarm; timer_create family (SIGEV_SIGNAL through the
  signal model, SIGEV_THREAD as a managed task); times; clock_getres; virtual
  CPU time := baton-held virtual time; adjtimex/settimeofday → EPERM; sched_*
  as constants (SCHED_OTHER, prio 0, affinity = virtual cpu set); prlimit64/
  getrlimit/setrlimit/getrusage/sysinfo raw rows; uname modeled; virtual
  `/proc` and `/sys` subtree (cpuinfo, meminfo, stat, self/{exe,maps,status,
  cgroup,mountinfo,auxv}, sys/devices/system/cpu/online, fs/cgroup cpu.max),
  `/etc/localtime`, hostname — all from one `--host-*` knob group recorded in
  the fingerprint; getcpu; personality; syslog → EPERM.
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
  SIOCGIF*, AF_NETLINK RTM_GETLINK/GETADDR; UDP-to-nowhere = drop + counter;
  SHUT_RD keeps queued data; epoll ET arrival counters; select/pselect6 over
  the reactor; inotify from the runtime fs funnel; fanotify → named trap.
- **process lifecycle + privileged** (data only): every row `Trap(class)` with
  its one-line reasoning in the registry; `execve`/`arch_prctl`/`set_tid_address`
  pre-arm rows documented as never-trapping.

## 7. Why the exclusions stay excluded

- **Process lifecycle.** A second process is outside the scheduler, the trace
  and the fs model; the guest's contract is "one process". `wait*` answers
  ECHILD (the exact childless-kernel answer, cannot hide an escape).
- **Privileged / kernel-config.** They change kernel state or need `CAP_*`;
  nothing a DST guest legitimately needs. Removed numbers answer ENOSYS because
  the kernel cannot answer anything else.
- **Host-network escape.** Any address outside the virtual interface table is
  ENETUNREACH; that is a model answer, not a hole.
- **io_uring.** A submission/completion ring model over the readiness reactor
  is its own arc (`docs/arcs/io-uring.md`, queued after this one); until then
  `io_uring_setup` → ENOSYS, which tokio/mio/monoio probe for.

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
