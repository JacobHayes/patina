# Arc: Linux x86_64 syscall conformance — every number dispositioned, every model host-checked

Status: design approved 2026-09-08 (user briefing); foundations in flight.
Scouting evidence (file:line inventories per family, native strace demand
ranking, prior art) lives outside the repo at
`/cache/jacobhayes/patina-syscall-arc/reports/` — it is a snapshot that rots;
the durable artifacts are the registry in code and the conformance testbed.

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
  abi/darwin/syscalls.master  vendored xnu table (parsed by a later arc; present so the
                              (os, arch) keying is real from day one)
  src/registry/table.rs       the table parser and the per-arch ABI-column rule
  src/registry/syscalls.rs    const SYSCALLS: &[SyscallRow]
  src/registry/symbols.rs     const SYMBOLS: &[SymbolRow]
  src/sud/mod.rs              BINDINGS (row name → handler) and the dispatch index
                              generated from the rows at compile time
```

`SyscallRow { name, nr: Nr { x86_64: Option<u32>, aarch64: Option<u32> }, family,
disposition, reasoning, closes_in: Option<&str>, probe: Option<&str>, since:
Option<&str> }` (the handler binding lives in `sud`, by row name). `VIRTUAL_ABI`
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
exists in the table; (c) every probe id a row names exists in the conformance testbed and covers
that row, every row the testbed's manifest names exists with the matching
disposition, and a `Modeled` row without a probe is reported (a failure under
`PATINA_CONFORMANCE_STRICT=1`); (d) every `SymbolRow` names a symbol the compiled shim
objects define (scanned with the `object` crate as `shim_host_alias.rs` does)
and every defined public symbol has a row; (e) the audit classification lists
in `patina-target` agree with the registry (an interposed symbol is never in a
deny list; a `Trap` symbol is in the deny-trap list).

`cargo patina syscalls [--os linux] [--arch x86_64] [--format json]` prints the
table with dispositions and reasoning (`patina.syscalls/v1`), so humans and
agents inspect the live registry, never a doc. `syscall(2)` (the glibc wrapper)
forwards into the same dispatcher instead of its two-number allowlist.

## 4. The conformance testbed (`testbeds/syscall-conformance/`)

- `probes/<family>/<probe>.rs`: one binary per probe, ordinary `std` + `libc`
  + `rustix` (both backends) + inline asm. A probe is a scripted scenario with
  `assert!`s on semantic properties (must pass natively) and an `observe!`
  macro that appends typed events to a JSONL stream on a dedicated fd:
  `{"op":"openat","args":{...},"ret":3,"errno":null,"fields":{"st_mode":...}}`.
- `--vehicle libc|syscall|raw` selects how the probe issues its calls; the
  probe body is written once against a small `Vehicle` trait. `raw` is
  `cfg(all(target_os="linux", target_arch="x86_64"))` until the arm64 `svc`
  variant lands; macOS never has it.
- Normalization is typed, per field, declared in the probe (`normalize:
  monotonic | relative | pid | inode | mask(bits)`), never regex over text.
- `run.sh --mode native|patina|replay --vehicle … [--bless] [--selftest]`;
  expectations at `expected/<probe>.<os>-<arch>.jsonl` with a header recording
  the oracle kernel (`uname -r`) and glibc that blessed them, plus a
  `divergences.toml` listing every declared host≠patina field with a reason.
  An undeclared divergence fails. The native leg asserts the host kernel is at
  least the blessed version and marks a probe host-unavailable (not failed)
  when the host lacks a syscall the virtual ABI level has.
- Selftests: a planted divergence proves the differ fails; a planted missing
  row proves the registry gate fails; a planted raw `openat("/etc/hostname")`
  proves the strace leak gate fails (reusing `validate-native-shim.sh`'s
  filter).
- Ladder: `run.sh --fast` (native + patina, libc vehicle) in `check:fast`;
  the three-vehicle + replay leg in `mise run check` and CI (Linux x86_64 and
  the arm64 job with `raw` skipped by cfg).

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
  st_uid/st_gid from the identity knob; real `d_ino` and `.`/`..` entries;
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
- **signals + threads + process**: D1 state in `ThreadRuntime` (dispositions,
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
