# Evidence

What the syscall-trap engine (`crates/patina-cli/ENGINE.md`) has been shown to do, one line
per result. All measured 2026-11-12 to 2026-11-16 on one host: a KVM guest, Linux 7.0,
24 vCPUs (AMD), run directories on XFS. The scripts behind each claim are `./check evidence`
and the `area` tier of each test directory.

## Determinism

The claim: a seed and an input give one boundary log, whatever the host does. Checked by
repeating each (workload, seed, faults) cell under varied host conditions (`patina verify
--vary repeat,cpu,load,aslr,sandbox,parallel,env,time`) and comparing digests.

| Check | Result |
|---|---|
| Final matrix: 29 workloads and attack guests x seeds 1-5 x faults off/on, 2,030 comparisons, ~15,000 runs | 1,985 identical; 20 bucket D (insn-probe under `cpu`/`parallel`, by design); 19 B6 `internal` (by design); 6 B13 (fixed, re-run 210/210 identical) |
| Soaks: W2, W6, W9 (W9 with crashes), 1,000 runs each, faults on, under `load` and `parallel` | one digest each |
| Time variant: 26 workloads and guests, runs 600 s apart | 26/26 identical |
| Seeds: every concurrent workload, 10 seeds | 10/10 distinct digests |
| `rows29` guest (29 rows no other run reached), seed 1, every variant but `time` | identical |
| Table strength (`patina table`) | 227 C, 158 A over 385 known syscalls |

The list of difference kinds did not plateau: new kinds appeared up to the last matrix. Run
the protocol again after any change to the engine, kernel, host or filesystem. A campaign
runs each seed once; repeating runs buys nothing per run.

### The thirteen differences found, and how each ended

| | What differed | Kind | Ended |
|---|---|---|---|
| B1 | `SO_COOKIE` on `AF_UNIX` | host-global counter | socket options are an allowlist; others `ENOPROTOOPT`, recorded |
| B2 | `SO_NETNS_COOKIE` | host-global counter | as B1 |
| B3 | `SO_TIMESTAMP*` cmsgs (host clock), `SO_PEERPIDFD` | host clock | as B1 |
| B4 | launcher umask reached the guest | inherited process state | every inherited item reset from one list (`sup/inherit.rs`) |
| B5 | launcher `RLIMIT_FSIZE` enforced underneath | inherited process state | rlimits fixed; fsize below the minimum ends `internal` |
| B6 | `F_SETPIPE_SZ` refused once the uid's pipe pages ran out | per-user host accounting | a refused size ends `internal` (limit, below) |
| B7 | `readlink` through a `/work` symlink to `/proc/1` | host names via a policy bypass | every path argument resolved against the policy first |
| B8 | `net-chunk-max` moved unrelated delivery draws | fault-plan coupling (engine bug) | own sub-key; split is an `Injected` record |
| B9 | host file atime moved by `relatime` | host clock through metadata | guest files are tmpfs copies; `/usr` atime reads as mtime |
| B10 | XFS speculative preallocation in stdout's block count | deferred kernel work | stdio are memfds |
| B11 | stdout extent count by writeback timing | deferred kernel work | stdio are memfds |
| B12 | `MADV_COLLAPSE` 0 or `EAGAIN` by huge-page availability | host resource | answers `EINVAL`, recorded |
| B13 | wire step read sockets of a process the kernel was still tearing down | async kernel work read before its barrier (engine bug) | exit barrier first in the step |

### Bucket D: detected only on replay, by design

| Entry | Label |
|---|---|
| JIT code (anonymous executable memory) is not scanned for `rdrand`/`rdseed` | `unscanned_exec_mappings` |
| Core identity: `cpuid` APIC fields, `rdpid`, `lsl` CPU number (shown: insn-probe, 20 comparisons; no workload) | `insn_scan.rdpid_sites`; others show as a divergence |
| XSAVE in-use bits (`xgetbv(1)`, FP headers) (argued; never varied) | none |
| In-flight descriptors freed by unix-socket GC (shown: scmrights) | `unix_sockets_in_flight` |
| Changes to host files under `/usr` | none; replay diverges at the first read |
| Per-user pipe accounting (B6) | run ends `internal` |

### Containment

Determinism of a cooperative or buggy guest holds; containment of a hostile one does not.
C1: one store into the read-write control region moves supervisor decisions (open). C2: a
jump to a `syscall` instruction in runtime text makes real, unrecorded calls (open,
architectural). C3 (stdout a host file) and C4 (supervisor descriptors writable through
`/proc/1/fd`) are closed.

## Finding bugs: storage

fjall 3.1.13 under the harness (`tests/guests/fjall-harness`), crash models from the
operation log; rate = seeds that reproduce / seeds run.

| Finding | Rate |
|---|---|
| F1 | 11/300 |
| F2 | 1/1,000 (seed 634) |
| F3 | 12/600 |
| F4 (a failed fsync, then a good one) | 2/1,000 |
| F5 | 56/100 |
| F6 | 1/1,000 |

SQLite: `synchronous=FULL`/WAL and `EXTRA`/DELETE kept every acknowledged row, 500/500;
`FULL`/DELETE lost acknowledged rows under `posix-strict` in 274/500 (allowed by POSIX, not
by ext4-ordered). W1 (`--crash machine:5`): correct version 500/500 under both models; planted
bug A (no fsync before the ack) caught 233/500 under ext4-ordered, 330/500 under posix-strict;
bug B caught 315/500 under posix-strict only.

## Finding bugs: syscall-free races and spin-waits

| Check | Result |
|---|---|
| W4 and go-sweep at 24 CPUs, `pmu = true` | 100/100 ok |
| W4 at 24 CPUs without `pmu = true` | stalls in 176/200 seeds |
| Spin table (every language's spin-wait), `pmu = true` | 0 stalls in 300 seeds |
| Largest measured skid | 425 branches (margin 1,024) |

## Costs

| What | Cost |
|---|---|
| Trap answered in the runtime | 0.75 µs |
| Trap with a supervisor hand-off | ~2.85 µs (round trip ~2.3 µs) |
| Start-up, static guest / `python3 -c pass` | 5.0 ms / 14.66 ms |
| W1 against Patina 0.5.0 | 15.5 ms vs 35.3 ms |
| W9 against Patina 0.5.0 | 31.5 ms vs 27.6 ms |
| W9 with crashes and filesystem faults | 38.9 ms per run, 148.6 runs/s (1.92x no-fault) |
| Crash materialisation | ~3 ms per MB of log |
| `fork`+`execve`+`wait` of a dynamic program | 1.5 ms (native 0.38 ms; mostly the instruction scan) |
| `pmu = true` | ~17 µs per trap, 3-6 ms per preemption, W1-W9 wall x1.2 to x4.0 |
| `--mount DIR:/guest:copy` copy into tmpfs | ~0.3 ms per MB |

## Known limits

Not implemented (run ends `unsupported` or the call is refused): `timer_create`,
`ITIMER_VIRTUAL`/`ITIMER_PROF`; UDP, raw, netlink and packet sockets; `sched_*` policy calls
and `get`/`setpriority`; anything outside Linux x86_64.

- The CPU count a guest sees defaults to 24.
- Syscall-free spin-waits stall without `pmu = true` (stock Go with GOMAXPROCS >= 3 in most seeds).
  `pmu = true` needs `CAP_PERFMON` and an exposed PMU; Intel's event is untested; a skid past
  the margin ends `internal`; a guest reading its own text during a hop sees `int3`. A lost
  update inside one read-modify-write instruction cannot be found by any preemption.
- `preempt-permille = 0` livelocks Go (it polls the clock forever).
- Per-user pipe accounting is shared by every sandbox of the uid: 9 parallel guests with 500
  pipes each end `internal`.
- The virtual inode table holds 16,384 objects; the next ends `internal`. The virtual
  `RLIMIT_NOFILE` is not enforced (`EMFILE` at the real limit, 4,091). A launcher
  `RLIMIT_FSIZE` below the boundary log's size kills `patina` with no outcome.
- Stdio are held in memory up to `PATINA_STDIO_MAX` each (1 GiB).
- Busy many-waiter workloads re-attempt often (16-thread ring: 7.4 attempts per blocking call).
- Bad guest pointers in path strings and futex words are a runtime fault (`internal`), not
  `EFAULT`; a signal frame on an unmapped guest stack likewise.
- Network differences from TCP a guest can see: no `POLLERR` on reset; `EPIPE` without a round
  trip; socket buffer and TCP options recorded and inert; `MSG_OOB` refused; no source
  address from `recvfrom`; one `connect` per socket; a reset in the accept queue fails
  `accept` with `ECONNABORTED`.
- Blocking-I/O gaps: `sendfile`/`copy_file_range`/`splice` with a socket or pipe side answer
  `EINVAL`; `F_SETLKW` deadlock detection is absent; `ppoll`/`pselect6`/`epoll_pwait` masks
  are not applied; `poll` restarts with the full timeout.
- Processes: another process's `/proc/<pid>` is refused (`ps` sees nothing); `fork` or a thread
  `clone` inside a vfork child ends the run; `wait4` rusage is zero; unusual `clone` flag sets
  end the run.
- Instruction scanning: 256 candidates per mapping, 4,096 patched sites per process; shared
  executable file mappings are not scanned (labelled).
- Storage: the ext4 model treats preallocated holes as in place (more generous than ext4);
  F4's state has not been produced on a real device; the materialiser holds the whole log in
  memory; `/tmp` is not tracked; the initial tree has no times (virtual epoch).
- Go `os/exec` deadlocks when an injected `EIO` hits its status-pipe read (Linux never does
  that).
- W8's `sockets all` mode fails every seed under network faults (it checks exact transfers).
- Every result is from one host; a second kernel, filesystem or CPU model is unchecked.

## The SDK channel

The four SDKs share one guest script (`tests/guests/sdk`), checked by `tests/sdk/01-languages`
and `02-points` (quick, together under 1 s).

- **Inert outside Patina.** Under `strace`, each of the C, Rust, Go and Python guests makes
  exactly one call of system call `0x7061` for the whole script, answered `-1 ENOSYS`; every
  later SDK call is a load and a branch. In a Docker 29.1.3 container with the default seccomp
  profile (kernel 7.0.0), a static probe got `-1 ENOSYS` (errno 38) and the C, Go and Python
  guests ran their script unchanged and exited 0.
- **Violation.** In each language a failed `always` ends the run `violation` with
  `must-hold: balance -1`, the code after it does not run, and the boundary log ends with the
  `patina_sdk` trap followed by `SdkViolation`. `patina verify --runs 2` of that run is
  identical.
- **Accounting and declared sites.** The four languages produce equal site tables (minus
  source locations) and equal decisions at seed 5; a site declared but never reached is in the
  table with `evaluated: 0` and its location.
- **Keyed decisions.** The same seed gives the same decision bits; enabling a second point
  leaves the first's bits unchanged; another seed differs; a forced rate of 1000 fires every
  time and 0 never; a `sometimes` holds on some seeds of 1..8 and not others; forked and
  exec'd children report into the same table; with `faults-after-setup` a point is silent
  before `setup-complete` and fires after. Red/green: keying a point's firing by the global
  sequence number instead of its own count fails `02-points` ("a second point moved the first
  one's decisions"); not ending the run on a failed `always` fails `01-languages`.
- **Cost of a passing assertion under Patina.** A tight loop of trivial arithmetic with a
  passing `always` each iteration, best of three `wall_ms`:

  | Guest | 10M plain | 10M with assert | 100M plain | 100M with assert |
  |---|---|---|---|---|
  | C | 16 | 16 | 64 | 69 |
  | Rust | 16 | 16 | 67 | 67 |
  | Go | 16 | 16 | 66 | 73 |

  The assertion traps once; afterwards it is one load and a branch (Go's `Check` inlines).
  Python natively, 1M iterations: 0.09 s plain, 0.12 s with the assertion.
- **Example.** `examples/ledger` under `--buggify`, seeds 1..6: seeds 1 and 5 end
  `violation` with `ledger-sorted`, the rest `ok`.
