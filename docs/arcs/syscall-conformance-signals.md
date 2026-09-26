# Signals + threads + process: the family spec

Status: landed. The family's scenarios are `signal/*`, `thread/*` and `proc/*`
in `crates/patina-conformance`; no pending gap remains, and the fork-based
child oracles carry by-design gaps. The runtime was built against the order §4
suggests. Parent arc: [syscall-conformance.md](syscall-conformance.md) §6
"signals + threads + process", §7. Every claim below about Linux is
host-checked by a scenario against the live host kernel; the kernel is the
oracle, this text is the index.

## As landed: implementation deltas

The numbered design below records the original plan. These deltas describe the
implementation; they do not change the scenarios or the required unit tests.

- `pidfd_send_signal(self)` is not a generation door: virtual pidfds do not exist,
  and `pidfd_send_signal` is a final `process` trap. This is a deliberate limit,
  not a claim of self-pidfd support.
- `TaskSignals` has neither an `altstack` mirror nor an `in_delivery` flag. The
  host kernel owns each task's alternate stack; host masks describe legitimate
  nested delivery. Enclosing SIGSYS mask/stack dirty bits survive inner-frame
  fixups by save-and-OR-back around kernel frame release.
- Blocking syscall resumption uses typed `Resumed::{Normal, Restart, Eintr}`
  rather than `Step::Interrupted`. Per-call restart and timeout rules still apply.
- Pthread join, mutex/rwlock and condition waits deliver handlers without EINTR,
  retain their semantic queues and resume the original wait/deadline unless
  already granted. A handler interrupting such a wait may acquire uncontended
  locks, but another blocking pthread wait is refused before queue mutation or
  condvar unlock with `signal handler blocked on a pthread wait while interrupting
  one: not modeled`. There is no nested pthread-wait stack.
- A handler with the caller's own restorer returns through it: its
  `rt_sigreturn` (SUD-trapped, or a tail call into the shim's `syscall(2)`
  entry) resumes at the host's `rt_sigreturn` from glibc text with the guest's
  stack pointer, after the containment signals are taken out of the frame's
  mask (`signal/restorer`). `restart_syscall` answers `EINTR`
  (`do_no_restart_syscall`): no restart block is ever pending, because the
  kernel leaves one only after interrupting a wait without running a handler
  (a stop or a tracer), and a default Stop is a named trap, an ignored signal
  never interrupts and no tracer exists. Waits a handler interrupts end at
  their own resumption, in the shim (`signal/restart`).
- Explicit Linux guest abort finalizes a healthy trace. Internal fatal paths and
  shim-owned Rust panics use host diagnostics/private abort and cannot finalize
  through that guest interposer. POSIX startup installs the ownership-scoped
  panic policy; guest callbacks suspend ownership, preserving caught guest
  panics. Guard-unwind and panic-time abort checks protect against hook replacement.

The conformance tests and the full landing battery are the acceptance checks.
Ambient host signals, nonlocal handler escape and macOS runtime behavior are not
proved by the Linux signal detectors; see `VALIDATION.md` for the evidence scope.

## 1. Rows: the Linux semantics the scenarios pin

Citations: `man 7 signal` (default actions, restart rule), `man 2 <row>`, and
`kernel/signal.c` / `kernel/sys.c` / `kernel/fork.c` / `fs/signalfd.c` /
`fs/pipe.c` / `arch/x86/kernel/signal.c` / `kernel/entry/common.c` function
names where the behaviour is subtle. "Probe" names the scenario(s) that pin
the row; every scenario runs through every vehicle unless noted.

### 1.1 Generation

| row | semantics | kernel | probe |
|---|---|---|---|
| `kill(pid, sig)` | `pid > 0` the process (or thread id) named — the guest (pid 2) or the pid namespace's init (pid 1, which takes nothing: no handlers, and the kernel drops what its namespace sends it by default, so the call answers 0); `0` the caller's process group; `-1` every process but init and the caller, of which there are none (`ESRCH`); another negative number the group it negates; `sig == 0` probes (delivers nothing); `sig < 0` or `> 64` → `EINVAL`; an absent pid → `ESRCH`. A signal to self is delivered before `kill` returns (the pending signal is handled on the return to user mode) with `si_code = SI_USER`, `si_pid`/`si_uid` the sender's (the guest's pid 2, uid 1000). | `kill_something_info`, `group_send_sig_info`, `__send_signal_locked` | `signal/basic`, `proc/ids` |
| `tkill(tid, sig)`, `tgkill(tgid, tid, sig)` | thread-directed: queued to THAT thread's private pending set and handled on that thread; to self, before the call returns, `si_code = SI_TKILL`; `tid <= 0` (`tgkill`: or `tgid <= 0`) → `EINVAL`; no such thread, or a thread outside `tgid` → `ESRCH`; a dead tid → `ESRCH`. | `do_tkill`, `do_send_specific` | `signal/basic` |
| `rt_sigqueueinfo(pid, sig, info)`, `rt_tgsigqueueinfo(tgid, tid, sig, info)` | queue `info` (SI_QUEUE with `si_value`); a nonnegative `si_code` (or `SI_TKILL`) is refused with `EPERM` ONLY when the target is another process — to the caller's own thread group it is accepted; `sig` out of range → `EINVAL`; absent pid/tid → `ESRCH`. `si_pid`/`si_uid` are whatever the sender wrote (glibc's `sigqueue` fills its own). | `do_rt_sigqueueinfo`, `do_rt_tgsigqueueinfo` (`task_pid_vnr(current) != pid` / `task_tgid_vnr(current) != tgid`) | `signal/queue`, `signal/wait` |
| SIGPIPE from a write | `write` to a pipe with no readers: `send_sig(SIGPIPE, current)` then `-EPIPE`, so a handler runs before the write returns `EPIPE`; a stream-socket send to a closed peer likewise unless `MSG_NOSIGNAL`; `SIG_IGN` leaves a bare `EPIPE`; `SIG_DFL` ends the process by SIGPIPE. | `pipe_write` (fs/pipe.c), `unix_stream_sendmsg` (net/unix/af_unix.c) | `signal/pipe_term` |
| queueing | a realtime signal (34..64) queues every instance FIFO with its payload; a standard signal coalesces to one pending instance while already pending (`legacy_queue`); a `SIG_IGN`/default-ignore signal that is not blocked is dropped at generation (`sig_ignored`), but a BLOCKED one is queued (so `sigwait`/signalfd can take it). | `__send_signal_locked`, `legacy_queue`, `sig_ignored` | `signal/queue` |

### 1.2 Dispositions, masks, pending

| row | semantics | kernel | probe |
|---|---|---|---|
| `rt_sigaction(sig, act, oldact, 8)` | installs `act` (kernel layout: handler, `sa_flags`, `sa_restorer`, 8-byte mask) and writes the previous action to `oldact` — including `SA_RESTORER` and the restorer glibc registered; `sig` outside 1..64, `sigsetsize != 8`, or `act != NULL` for SIGKILL/SIGSTOP → `EINVAL`; registration without `SA_RESTORER` is accepted (the restorer matters at frame setup); installing `SIG_IGN` (or the default for an ignore-class signal) flushes that signal from the pending queues. Both doors (libc `sigaction`/`signal` and the raw row) read and write ONE disposition table. | `do_sigaction` (`copy k_sigaction` both ways, `flush_sigqueue_mask`) | `signal/raw_action`, `signal/basic` |
| `rt_sigprocmask(how, set, oldset, 8)` | per THREAD; `how` not in `SIG_BLOCK`/`SIG_UNBLOCK`/`SIG_SETMASK` → `EINVAL`; `sigsetsize != 8` → `EINVAL`; SIGKILL/SIGSTOP cannot be blocked; a `set == NULL` call only reads; a signal that became deliverable by the change is handled BEFORE the call returns (recalc_sigpending → handled on the return to user mode); several standard signals unblocked at once are dequeued lowest-numbered first and one frame is set up per signal before the return to user mode, so the handlers RUN in reverse order, each inner one under the outer frame's mask. | `sigprocmask`, `set_current_blocked`, `exit_to_user_mode_loop` → `arch_do_signal_or_restart` (one frame per iteration), `next_signal` | `signal/mask`, `signal/per_thread` |
| `rt_sigpending(set, size)` | `(private ∪ shared pending) ∩ blocked` of the CALLING thread; `size > sizeof(sigset_t)` → `EINVAL` (a smaller size copies that many bytes). A thread-directed signal pending for another thread is not in it. | `do_sigpending` | `signal/mask`, `signal/per_thread` |
| dequeue order | the thread's private pending set is searched before the shared one; within a set the lowest-numbered signal first (synchronous fault signals first); within one realtime number FIFO. | `dequeue_signal`, `next_signal` | `signal/queue` |
| `sigaltstack(ss, old_ss)` | per thread; `ss_flags` not in {0, `SS_DISABLE`, `SS_AUTODISARM`} → `EINVAL`; `ss_size < MINSIGSTKSZ` → `ENOMEM`; any change while executing on the stack → `EPERM`; `old_ss` reports the current stack with `SS_ONSTACK` set while on it and `SS_DISABLE` when none; a `SA_ONSTACK` handler runs with its stack pointer inside the range. | `do_sigaltstack`, `on_sig_stack`, `get_sigframe` | `signal/altstack` |
| handler frame | while a handler runs the thread's mask is `blocked ∪ sa_mask ∪ {sig}` (the signal itself unless `SA_NODEFER`), so a same-signal raise inside the handler is delivered after `rt_sigreturn`; `SA_NODEFER` nests; `SA_RESETHAND` restores `SIG_DFL` before the handler runs; `SA_SIGINFO` passes the queued `siginfo`. | `handle_signal`, `signal_setup_done`, `get_signal` (`SA_ONESHOT`) | `signal/handler_flags`, `signal/basic` |

### 1.3 Waiting for signals

| row | semantics | kernel | probe |
|---|---|---|---|
| `pause()` | parks until a signal is DELIVERED (a handler ran, or the process is terminated); returns `-1`/`EINTR` after the handler, never before a signal exists (`ERESTARTNOHAND`: restarted transparently only when no handler ran). | `sys_pause` | `signal/block` |
| `rt_sigsuspend(mask, 8)` | atomically installs `mask` (minus SIGKILL/SIGSTOP) and parks until a signal not in it is delivered; returns `-1`/`EINTR` after the handler with the previous mask restored; a signal the temporary mask still blocks only becomes pending. | `sigsuspend`, `set_restore_sigmask` | `signal/block` |
| `rt_sigtimedwait(set, info, timeout, 8)` | dequeues a pending signal in `set` (blocked or not) without running a handler and returns its number with `siginfo` (`SI_USER`, `SI_TKILL`, `SI_QUEUE` + payload); none pending: `timeout == NULL` parks until one is generated; a timeout parks until then or fails `EAGAIN` after it elapses (the clock advanced by at least the timeout); a signal outside `set` with a handler interrupts it with `EINTR` after the handler; `sigsetsize != 8` or a malformed timespec → `EINVAL`. | `do_sigtimedwait` | `signal/mask`, `signal/wait`, `signal/block`, `signal/queue` |
| `signalfd(fd, mask, 8)`, `signalfd4(fd, mask, 8, flags)` | a descriptor that dequeues signals in `mask` that are pending for the reader (blocked ones — an unblocked handled signal is delivered to the handler, never to the fd); `read` fills 128-byte `signalfd_siginfo` records (`ssi_signo`, `ssi_code`, `ssi_pid`, `ssi_uid`, `ssi_int`); a buffer shorter than one record → `EINVAL`; `SFD_NONBLOCK` → `EAGAIN` when nothing matches, else the read parks until something does; readable for epoll/poll exactly while a matching signal is pending; `signalfd4(fd, mask)` replaces the mask of an existing signalfd; flags outside `SFD_NONBLOCK|SFD_CLOEXEC` → `EINVAL`; `signalfd` (282) is `signalfd4` with flags 0 (no CLOEXEC). | `signalfd_dequeue`, `signalfd_poll` (`next_signal(&pending, &mask)`), `do_signalfd4` | `signal/wait`, `signal/block` |

### 1.4 Interruption and restart (`man 7 signal`, `arch/x86/kernel/signal.c handle_signal`)

When a handler runs while the thread is inside a blocking call, the kernel's
return code decides:

| blocked in | rule | probe |
|---|---|---|
| `read`/`write`/`recv`/`send`/`accept`/`connect` on a modeled pipe/socket/eventfd | `-ERESTARTSYS`: restarted when the handler has `SA_RESTART`, else `EINTR`; a restarted read completes on the later write | `signal/eintr` (read; the rule is the same table entry for every `ERESTARTSYS` row) |
| `futex(FUTEX_WAIT)` without a timeout | `-ERESTARTSYS` (restart under `SA_RESTART`, re-checking the word) | `signal/eintr` |
| `futex(FUTEX_WAIT)` with a timeout | `-ERESTART_RESTARTBLOCK` → `EINTR` whenever a handler ran, regardless of `SA_RESTART` | `signal/eintr` |
| `nanosleep`, relative `clock_nanosleep` | `-ERESTART_RESTARTBLOCK` → `EINTR`; `rem` is filled with the unslept time, `0 < rem <= request` | `signal/eintr` |
| absolute `clock_nanosleep` (`TIMER_ABSTIME`) | `-ERESTARTNOHAND` → `EINTR`; `rem` is not written | `signal/eintr` |
| `epoll_wait`/`epoll_pwait`/`poll`/`ppoll`/`select`/`pselect6` | `EINTR`, never restarted | `signal/eintr` (epoll_wait) |
| `pause`, `rt_sigsuspend`, `rt_sigtimedwait` | `EINTR` after a handler (`ERESTARTNOHAND`) | `signal/block`, `signal/mask` |
| `wait4`/`waitid` | `ERESTARTSYS` (no children exist, so `ECHILD` before any wait) | `proc/wait` |

### 1.5 Default actions (`man 7 signal`)

| class | signals | virtual kernel | probe |
|---|---|---|---|
| Term | SIGHUP SIGINT SIGKILL SIGPIPE SIGALRM SIGTERM SIGUSR1 SIGUSR2 SIGPROF SIGVTALRM SIGSTKFLT SIGIO SIGPWR, realtime | the process ends BY THAT SIGNAL (`waitpid` reports `WTERMSIG`), after the run is finalized (§2.6); no core flag | `signal/handler_flags`, `signal/pipe_term` |
| Core | SIGQUIT SIGILL SIGABRT SIGFPE SIGSEGV SIGBUS SIGSYS SIGTRAP SIGXCPU SIGXFSZ | ends by that signal; the wait status's core flag is set when the kernel dumped (`do_coredump` → `group_exit_code |= 0x80`) — what the host's core sink does (this host: an apport pipe pattern, which dumps regardless of `RLIMIT_CORE`); the virtual kernel dies through the real signal so the same host answers the same | `signal/core_term` |
| Ign | SIGCHLD SIGURG SIGWINCH | dropped at generation unless blocked (§1.1) | — (state only) |
| Cont | SIGCONT | nothing is stopped: dropped | — |
| Stop | SIGSTOP SIGTSTP SIGTTIN SIGTTOU | a stop with nobody to continue it is a guaranteed hang: a named fatal trap (`SIGTSTP`/`SIGTTIN`/`SIGTTOU` run a handler when one is installed) | — (a trap, exercised by the shim's unit test) |

### 1.6 Threads and process rows

| row | semantics | kernel | probe |
|---|---|---|---|
| `set_tid_address(ptr)` | records `ptr` for the calling thread and returns its tid; when that thread exits the kernel writes 0 to `*ptr` and `futex_wake`s it (`FUTEX_BITSET_MATCH_ANY`) | `sys_set_tid_address`, `mm_release` (kernel/fork.c) | `thread/tid_clear` |
| `set_robust_list(head, 24)`, `get_robust_list(pid, &head, &len)` | per-thread head, glibc's from each thread's start; any length but 24 is `EINVAL`; `get` of the caller (0) or a live tid writes 24 then the head (`EFAULT` for either), `ESRCH` for no such thread, `EPERM` for init; at exit, after the thread-local destructors, the list is walked before clear-child-tid, and an owned word gains `FUTEX_OWNER_DIED` and wakes one waiter by its shared key (a `FUTEX_WAIT_PRIVATE` waiter stays parked) | `kernel/futex/syscalls.c`, `exit_robust_list`, `handle_futex_death` | `thread/robust_list` |
| `rseq(area, len, flags, sig)` | per-thread registration, glibc's from each thread's start (taken off the host); another area or length `EINVAL`, another signature `EPERM`, the same `EBUSY`; unregistering checks area, length, then signature; a new one needs 32 bytes, 32-byte alignment, a user range; the area names the one virtual CPU (0) | `sys_rseq`, `rseq_update_cpu_node_id`, `rseq_reset_rseq_cpu_node_id` | `thread/rseq` |
| `exit(code)` (60) | ends the CALLING thread only; the process lives while another thread runs and its `exit_group` sets the status; no atexit handlers run | `do_exit` vs `do_group_exit` | `thread/main_exit` |
| `exit_group(code)` (231) | ends every thread; the process exit status is `code` | `do_group_exit` | `thread/main_exit` |
| `wait4`/`waitid` | a process without children: `ECHILD` (also with `WNOHANG`); `waitid` options outside `WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED|__WNOTHREAD|__WCLONE|__WALL`, or none of `WEXITED|WSTOPPED|WCONTINUED` → `EINVAL` | `do_wait`, `kernel_waitid` | `proc/wait` |
| `prctl` | `PR_SET_NAME` stores 15 bytes + NUL (`PR_GET_NAME` reads them back); `PR_SET_PDEATHSIG` takes a signal number (0 clears; `> 64` → `EINVAL`), `PR_GET_PDEATHSIG` writes it (`EFAULT` for a bad pointer); `PR_SET_DUMPABLE` accepts 0 or 1 only (2 → `EINVAL`), `PR_GET_DUMPABLE` starts at 1; `PR_SET_NO_NEW_PRIVS` accepts exactly `(1, 0, 0, 0)` (`0` → `EINVAL`, a nonzero trailing argument → `EINVAL`) and is sticky; `PR_SET_TIMERSLACK` with 0 restores the 50 000 ns default, `PR_GET_TIMERSLACK` returns the current value; an unknown option → `EINVAL` (not `ENOSYS`) | `sys_prctl` (kernel/sys.c) | `proc/prctl` |
| removed numbers | `_sysctl`, `nfsservctl`, `vserver`, `security`, `tuxcall`, `afs_syscall`, `getpmsg`, `putpmsg`, `epoll_ctl_old`, `epoll_wait_old`, `lookup_dcookie`, `create_module`, `query_module`, `get_kernel_syms`, `uselib`: `ENOSYS` (the table lists them without an implementation). Registry disposition: `SoftDeny(ENOSYS)` — the parent arc's §2.4 class for removed numbers; `Absent` is reserved by the registry's own rule test for numbers newer than the virtual ABI | `sys_ni_syscall` | `proc/absent` |
| `getpgid`/`getsid`/`kill(0|-1, 0)`/`tgkill(pid, pid, 0)` | the one virtual process is its own group leader and session leader (pgid = sid = 1); the probes succeed | — | `proc/ids` |
| `fork`/`clone`/`clone3`/`execve`/`execveat` | process-lifecycle traps BY DESIGN ([syscall-conformance.md](syscall-conformance.md) §7): a named abort with the pinned diagnostic; the fork-based child oracles (`signal/default` through glibc's `fork()`, libc vehicle only; `proc/traps` through the row) keep running natively, are declared `by design:` aborts at the fork's event, and the same facts are pinned in-process by `signal/core_term`, `signal/pipe_term`, `signal/handler_flags`, `thread/main_exit`, `thread/tid_clear` | — | those two (prefix + pinned abort) |
| `pthread_kill(t, sig)` (libc only) | glibc: `tgkill` on the target's tid; returns the error number (`EINVAL` past SIGRTMAX); signal 0 probes | — | `thread/pthread_kill` (libc vehicle) |

## 2. The design, at file:line of this tree

Verified against the tree at `mzntnszl 30f0c9d3` (the lineage head the design
was made on).

### 2.1 Where the runtime stands

- Scheduling: `enum Step { Continue, Switch(TaskId) }` (`crates/patina-native-shim/src/lib.rs:6978`) — no interrupted outcome. `ThreadRuntime::block` (`:7257`) and `block_timed` (`:7275`) park through `RealScheduler`, run `settle_rescued` (`:7300`), and hand off in `switch_and_park` (`:7126`). `sched_point` (`:7408`) yields at every boundary op. `managed_sleep` (`:7449`) parks a sleep on the virtual clock; the C `nanosleep`/`clock_nanosleep` (`c/posix/time.c:67`, `:97`) and the SUD rows (`src/sud/time.rs:94`, `:111`) call `patina_sleep_until` (`lib.rs:3631`) and never see a remaining time.
- Blocking paths that park: `pipe_read` (`lib.rs:10354`), `pipe_write` (`:10439`), `eventfd_read` (`:10738`), `patina_net_accept` (`:8851`), `net_stream_send` (`:9158`), `net_recvfrom` (`:9269`), `net_stream_recv` (`:9455`), `patina_epoll_wait` (`:12312`, waiters via `register_readiness_waiters` `:11078` / `unregister_readiness_waiters` `:11145`), `patina_futex_wait` (`:12454`), `patina_futex_wait_timed` (`:12490`), and the sleep above. Each pushes itself on one primitive's waiter list, parks, and on resume clears `timed_out` (`:7154`).
- Signal state: none. The C door forwards `sigaction`/`signal` to the real glibc registration (`c/posix/signal_process.c:51`, `:77`), `pthread_sigmask` to the real mask with SIGSYS (and the TSC SIGSEGV) stripped (`:132`), answers `pause` with `ENOSYS` (`:13`) and `kill(self, sig)` with a deny line + `ENOSYS` (`:340`). The SUD door: `sys_rt_sigaction` ignores `act`/`oldact` (`src/sud/signal_process.rs:32`), `rt_sigprocmask`/`sigaltstack` are success no-ops that write nothing (registry rows `src/registry/syscalls.rs:172`, `:1254`), and `rt_sigpending`/`rt_sigtimedwait`/`rt_sigqueueinfo`/`rt_sigsuspend`/`kill`/`tkill`/`tgkill`/`pause`/`signalfd*`/`rt_tgsigqueueinfo`/`set_tid_address`/`wait4`/`waitid`/`getpgid`/`getsid` are named `Trap` rows (`:1218`, `:1227`, `:1236`, `:1245`, `:619`, `:1876`, `:2188`, `:354`, `:2643`, `:2709`, `:2788`, `:2040`, `:610`, `:2306`, `:1164`, `:1191`). `sys_prctl` traps everything but `PR_GET_AUXV` (`src/sud/signal_process.rs:103`); the C `prctl` (`c/posix/sched_identity.c`) answers `ENOSYS` for the options the family models. A raw `exit` from any thread ends the whole process through `patina_exit` (`src/sud/mod.rs` binding for `exit`; `lib.rs:5698`).
- Doors: the raw door is the SIGSYS handler `patina_sud_sigsys` (`c/posix/init.c:365`), which decodes the registers, calls `patina_sud_dispatch` (`src/sud/mod.rs:686` → `dispatch` `:1084`), writes RAX (`init.c:420`) and returns through `rt_sigreturn`; glibc's `syscall(2)` is interposed into the same dispatcher (`init.c:31`). The C door has no universal epilogue: `fail_int`/`fail_size` (`c/posix/core.c:102`, `:107`) serve some interposers and the rest return directly.
- Host aliases: `hostapi` (`lib.rs:735`, resolved once through `dlsym(RTLD_NEXT)`), `patina_real_sigaction` and the pthread_sigmask alias in `c/posix/signal_process.c`; the host-alias doctrine (shim internals never call a public interposable symbol) applies to every new host vehicle below.
- Trace: `Operation` (`crates/patina-abi/src/lib.rs:763`) has `TaskPark`/`TaskParkTimed`/`TaskWake`/`TaskComplete`/`SchedulerNext` (`:972`–`:992`) and no signal op; `TRACE_FORMAT_VERSION = 8` (`crates/patina-trace/src/lib.rs:79`) with the fixed `MIGRATIONS` chain (`:2187`). The runtime records `task_park` (`crates/patina-runtime/src/lib.rs:5959`), `task_park_timed` (`:5979`), `task_wake` (`:6027`) and `scheduler_next` (`:6104`, deadlock rescue).
- Supervisor: `cargo-patina` observes the guest's wait status (`native_child_status`, `crates/cargo-patina/src/lib.rs:7111`) and reports `guest_exit { code, signal, signal_name }` in the `patina.result/v1` envelope (`crates/cargo-patina/src/output.rs:483`, `:1004`); it does not report the core flag.

### 2.2 State (per process and per task, owned by `ThreadRuntime`)

```text
SignalRuntime {
  actions:  [SigAction; 65],                  // handler | SIG_DFL | SIG_IGN, sa_flags, sa_mask, restorer — process-wide
  shared:   PendingSet,                       // process-directed instances
  tasks:    BTreeMap<TaskId, TaskSignals { mask: SigSet, private: PendingSet, altstack: StackSpec,
                                           clear_child_tid: Option<usize>, in_delivery: bool }>,
  signalfds: BTreeMap<FdHandle, SigSet>,      // an fd kind on the unified fd table (F2)
  next_seq: u64,
}
PendingSet = per signal number: standard → at most one SignalInstance; realtime → VecDeque (FIFO)
SignalInstance { seq, sig, code, pid: 1, uid: 1000, value }
```

- The mask is per task and INHERITED at spawn from the creator's virtual mask (the kernel's clone semantics; glibc's `pthread_create` blocks everything around `clone3` and the child restores the parent's mask from glibc text, which the shim never sees — so the virtual copy must be seeded at `patina_thread_create` (`lib.rs:7569`) and the host thread's mask set to match in `thread_trampoline` (`:7497`) before the routine runs).
- SIGSYS and (while the TSC trap is armed) SIGSEGV are reserved: a guest registration is a named fatal on both doors (today's C refusal is a soft `EPERM`; align to fatal), and both are stripped from every mask installed on the host.
- The host mask is authoritative for the running thread (glibc-internal `rt_sigprocmask` from `siglongjmp`/`abort`/`pthread_create` runs in the allowed region and never reaches the shim): every delivery point re-reads it (`host_sigprocmask(SIG_BLOCK, NULL, &cur)`) into the virtual copy before deciding what is deliverable; the virtual copy is what other tasks consult (target selection) and what the raw rows report.
- The raw rows write their out-parameters (`oldact`, `oldset`, `old_ss`, `siginfo`, `rem`) — the D7 door-parity closure. Inside the SIGSYS handler a raw `rt_sigprocmask`/`rt_sigsuspend`/`sigaltstack` must also write the new mask/stack into the SIGSYS frame's `uc_sigmask`/`uc_stack` (`init.c:397` has the `ucontext_t`), because `rt_sigreturn` re-installs them.

### 2.3 Generation (never delivers; never a host signal)

`kill`/`tkill`/`tgkill`/`rt_sigqueueinfo`/`rt_tgsigqueueinfo`/`pidfd_send_signal(self)` on both doors, and the broken-pipe path of `pipe_write` (`lib.rs:10439`, the `BrokenPipe` arm — generation must run with the `ThreadRuntime` lock RELEASED, the round-6 self-deadlock), call one Rust entry under the runtime lock:

1. validate (`EINVAL`/`ESRCH`/`EPERM` per §1.1); `sig == 0` returns;
2. if the action is `SIG_IGN` or a default-ignore class and no target task blocks it → drop (recorded as generated, §2.7);
3. `seq = next_seq++`; record `Operation::SignalGenerated` (§2.7);
4. enqueue: thread-directed → the target task's `private`; process-directed → `shared` (standard signals coalesce);
5. choose the target deterministically (`complete_signal`'s policy made deterministic): thread-directed → that task; process-directed → the MAIN task (the thread-group leader — the task `kill(pid)` names, which `complete_signal` tries first with `wants_signal`) if it has not exited and does not block the signal, else the lowest `TaskId` that does not block it, else nobody (it stays shared-pending until an unmask). Which task generated it plays no part: a helper thread's `kill(getpid(), …)` interrupts the main thread's blocking call, as every helper-based probe relies on (`signal/one_wake` pins both branches);
6. if the chosen task is parked in an interruptible wait (the `BlockedTask` record below), unlink it from the primitive's waiter list, mark it `Interrupted(seq)`, and `RealScheduler.wake(task)` with the lock dropped (the `wake_all` shape, `lib.rs:8577`); a running/runnable task needs nothing — it reaches a delivery point;
7. a signalfd whose mask covers the signal is now readable: drain its readiness waiters exactly as a pipe write does.

### 2.4 Delivery points and kernel-built frames (D2/D3)

Delivery = "the baton-holding task runs `deliver_pending_for_current_task`": re-read the host mask; while a deliverable instance exists (private before shared, lowest number first, FIFO within a number) and `!in_delivery`: dequeue it and act on the disposition (§2.5, §2.6). Exactly four points:

1. **C epilogue** — every interposer that can generate or unmask returns through one epilogue (`core.c` gains `patina_return_int`/`patina_return_size` beside `fail_int`/`fail_size`; the sweep must cover the direct-return interposers, or a `kill(self)` through the libc door delivers late). This is what makes `kill(getpid())`/`raise` synchronous, as the kernel is.
2. **SUD tail** — the tail of `patina_sud_dispatch` (`src/sud/mod.rs:686`), before the C handler writes RAX; it serves the raw door and glibc's `syscall(2)` alike.
3. **`sched_point`** (`lib.rs:7408`) — before yielding and after being resumed: the asynchronous point for a cross-task signal that found the target running.
4. **blocking-call resume** — a call parked through `block`/`block_timed` returns `Step::Interrupted(seq)` (the new variant; interruption is derived in the shim from the mark set at generation, never added to `patina-sched-det`), runs delivery, then applies §1.4 with the action's `SA_RESTART` read from `actions[sig]` at that moment.

`BlockedTask { class: BlockClass, locs: Vec<WaiterLoc>, deadline }` is registered by every parking path listed in §2.1 before `scheduler.park` and removed on resume, so generation can unlink a waiter without draining whole queues (`patina_signal_interrupt_all` — the rejected round's wake-everything primitive — must not exist). A timed sleep interrupted early has its timer deregistered (`task_wake` already does, `runtime/src/lib.rs:6027`) and computes `rem = deadline - virtual now`.

**Frames are the kernel's.** A handler is invoked by signalling the calling host thread itself from a delivery point: install the virtual mask minus the reserved signals on the host, then `rt_tgsigqueueinfo(host_pid, host_tid, sig, &siginfo)` with the VIRTUAL siginfo (`si_code` `SI_USER`/`SI_TKILL`/`SI_QUEUE`, `si_pid = 1`, `si_uid = 1000`, `si_value`) — a nonnegative `si_code` to one's own thread group is accepted (§1.1) — so the kernel builds the frame (honouring `SA_SIGINFO`, `SA_ONSTACK` on the host-forwarded altstack, `sa_mask`, `SA_NODEFER`, `SA_RESETHAND` — the shim mirrors the reset into `actions` — and glibc's restorer), the handler runs on the same host thread under the baton, and `rt_sigreturn` runs from glibc's text. `SA_SIGINFO si_pid == getpid()` holds because the siginfo carries the virtual identity; a plain `tgkill` would leak the host pid into it. Several deliverable signals at one point are queued on the host while blocked and released with ONE host `sigprocmask`, so the kernel stacks the frames in its own order (`signal/mask`'s reverse-order and frame-mask checks). The leak filter allows exactly this vehicle: `tgkill`/`tkill`/`rt_tgsigqueueinfo` whose target is the calling thread, any signal, and nothing else (`crates/patina-conformance/src/leak.rs`, `self_directed`).

**The SUD vehicle.** Delivery runs inside the SIGSYS handler. For a raw syscall issued from inside a nested guest handler to trap normally, the SIGSYS handler is installed with `SA_NODEFER` (a synchronous SIGSYS while SIGSYS is blocked is force-delivered as SIG_DFL and kills the process), the dispatch re-entry guard (`with_dispatch_guard`) admits re-entry only while a guest handler is running, and the guest handler's frame is built by the kernel on top of the SIGSYS frame (or on the altstack under `SA_ONSTACK`). The alternative — the scout's RIP-redirect stub that delivers after `rt_sigreturn` on the guest's own stack — is acceptable only if the stub preserves the complete register file the guest's inline `syscall` did not declare clobbered (everything but `rax`/`rcx`/`r11`, including the vector registers and the 128-byte red zone), which is exactly a signal frame; the probes decide, the design does not.

### 2.5 Waits that park on the scheduler

`pause`, `rt_sigsuspend`, `rt_sigtimedwait` (NULL timeout, or a virtual-clock deadline), `sigwait`/`sigwaitinfo`/`sigtimedwait` wrappers, and a blocking signalfd `read` park with `BlockClass::{Pause, SigSuspend, SigWait, SignalfdRead}`; generation wakes them per §2.3 step 6 (a `SigWait` on a matching signal consumes it at resume without running a handler; a handled signal outside the set delivers and the call returns `EINTR`). With nothing else runnable and no timer, the deadlock rescue's `Deadlock` error (`patina-sched-det`) is the honest outcome of a `pause` nobody will ever end.

### 2.6 Default actions

At a delivery point, `SIG_DFL` for a Term/Core signal: `patina_shutdown` (`lib.rs:3057`: finalize the trace, flush captured stdio), restore `SIG_DFL` on the host for the signal through the sigaction alias, unblock it, and signal the calling thread with it. The kernel then terminates the process by that signal — the supervisor's `waitpid` reports `WTERMSIG` and (for Core) the core flag — and `cargo-patina` reports it in `guest_exit` with a new `core: bool` field from `ExitStatusExt::core_dumped()`, which the harness reads. Traps keep `abort()` (SIGABRT). Stop-class → named trap; ignore/cont-class → dropped at generation (§1.1). SIGKILL to self is not catchable: finalize, then the real SIGKILL.

### 2.7 Trace and replay

`Operation::SignalGenerated { seq: u64, sig: u8, target: Process | Task(TaskId), code: i32, value: i64 }` with `Outcome::Unit`, recorded through the runtime at generation (a boundary op that reconciles on replay); `TRACE_FORMAT_VERSION` 8 → 9 with an identity migration appended to `MIGRATIONS`, a `format-9` fixture, and the ABI's serde round-trip test. What is recorded, exactly: ONE op per successful generating call with `sig != 0` — `kill`/`rt_sigqueueinfo` (`target = Process`), `tkill`/`tgkill`/`rt_tgsigqueueinfo`/`pthread_kill` and each SIGPIPE a modeled write or send raises (`target = Task`) — in generation order, on every door; a call that fails validation and a `sig == 0` probe record nothing; a signal that is then coalesced, ignored or left pending is still recorded. As the supervisor reports it (`cargo patina trace events --format json`, schema `patina.trace.events/v1`) the op is an event with `"kind": "signal_generated"` whose `operation` carries an integer `sig` and a `target` that is the string `"process"` or an object naming the task (`{"task": N}`) — serde's default shape for the enum above. The family gate reads exactly that (§5): per probe, the recorded ops must be the probe's generations, in order. Delivery is NOT recorded: it is a pure function of the recorded generations, the recorded scheduler ops (`TaskPark`/`TaskWake`/`SchedulerNext` already reconcile the wake of an interrupted task) and the delivery points the baton holder reaches. A generated-but-dropped signal (ignored) is still recorded, so a replay that generates a different sequence mismatches on it.

### 2.8 Threads

`set_tid_address` stores the word per task and returns the managed tid; `thread_finish` (`lib.rs:7528`) writes 0 and `patina_futex_wake`s it (the host kernel clears glibc's own `pd->tid`, never the guest's word — the raw row never reached it). A raw `exit` from a managed non-main task runs `thread_finish` and ends the host thread; from the main task it marks the root task completed and leaves the process to the remaining tasks, whose `exit_group` ends it with their status (`patina_exit`, `lib.rs:5698`, must not run atexit for a raw `exit_group` — kernel semantics; the natural-return path keeps today's chain). `pthread_kill` is a strong-def wrapper over the `tgkill` model with the `pthread_t → TaskId` map (`ThreadRuntime.handles`); `raise`, `sigwait`, `sigwaitinfo`, `sigtimedwait`, `sigsuspend`, `sigqueue`, `sigprocmask`, `sigpending`, `siginterrupt`, `killpg`, `psignal`/`strsignal` are the remaining wrappers, each a symbol row flipped from `Absent` honestly (a wrapper the shim does not define stays `Absent`, and the probe that needs it stays libc-only).

## 3. The harness contract the scenarios rely on

- Every run (`crates/cargo-patina/tests/native_conformance.rs`) is its own process group under a deadline, and each supervisor's observed outcome is compared — `waitpid` natively, `guest_exit` (signal and core flag) from the `cargo patina … --format json` envelope under patina, record and replay.
- A scenario that means to die announces it (`Probe::dies_by(signal)`, the `expect_death` event) as its last act; any other native signal death is no oracle.
- Gaps: `Failure::Differs` names every difference a scenario still shows with its exact patina value; `Failure::Stops` pins the event count, the ending and the diagnostic of a by-design death.
- The recorded run's trace is read back through `cargo patina trace events --format json`; a scenario's `trace` facts (§4) are checked against it.
- A scenario whose native run dies by a signal is also run DIRECTLY — the shim-linked binary, no `cargo patina`, no strace — and its wait status (signal and core flag) must be the native one: an exit code a supervisor translates into "signaled", or a core flag the envelope invents, does not survive it.
- One stream, many threads: `Recorder::quiet` suspends recording for the CALLING thread only, so a helper's unrecorded wake never swallows an event of the thread under test; a worker that records does so in its own turn (a phase handoff while the main thread waits unrecorded), so the stream's order never depends on which thread the scheduler runs first.
- Ordering evidence: every helper thread waits until the main thread is asleep in its blocking call (`/proc/self/task/<tid>/stat` state `S` natively; the virtual kernel has no `/proc`, so under patina it is a virtual-time pause and the scheduler's order is deterministic) and records a `helper_kill` mark immediately before it signals, so a wait that returned early is an ordering difference, and the handler count at return is checked.

## 4. The work, in its suggested order: scope, probes, DESIGN OBLIGATIONS, traps

The family was built against one done-condition: (a) every `pending: signals — …` gap gone with the scenarios green, AND (b) every design obligation below held.

M1..M5 are the SUGGESTED ORDER of work, not separate gates; the `M<k>` in each pending reason names the step that closes it. The order is the dependency order, and the reasons are these:

- **M1 first** because it needs none of the delivery machinery: it proves the loop (both doors over one entry, honest registry rows, the gate's work lines shrinking) on rows whose answers are tables.
- **M2 before M3** because a wait can only be interrupted by a signal that can be generated, queued, masked and delivered. State is PER TASK from the first line of M2 — a process-global model passes M2's single-threaded probes and is then a rewrite, not an extension, at M3 and M5 — and the `SignalGenerated` trace op and the format bump land here because every later step records through them.
- **M3 before M4** because the default actions fire at the same delivery points the waits resume through, and SIGPIPE is a generation from inside `pipe_write`, which needs M3's lock-order and interruption rules to exist.
- **M4 before M5** because a thread's exit and the process's exit share the finalize path M4 builds, and thread-directed delivery is M3's target-and-wake rule with the choice already made.

A different order that reaches the same PASS is the builder's call; what is not negotiable is the end state.

Why (b) exists: green scenarios are necessary, not sufficient. A process-global C model that fires a host signal at generation time — the host kernel as the pending queue, no per-task state, no trace op — passes every single-threaded M2 scenario on every vehicle, replay included. The obligations are what such a pass skips:

- **unit tests** — named tests in their crates' suites; the third column below is what each test's SUBSTANCE is reviewed against. A test that asserts less than its row says is a defect, not a pass.
- **trace facts** — each scenario's `trace` declaration, checked against the trace its patina run RECORDED (§2.7): the `signal_generated` ops are exactly the scenario's generations in order (`<sig>:p` process-directed, `<sig>:t` thread-directed), and, where stated, at most one `task_wake` directly follows a generation.

### M1 — process rows (no delivery machinery)

Scope: `prctl` option table on both doors with the kernel's validation (§1.6); `wait4`/`waitid` → `ECHILD`/`EINVAL` on both doors (the C `waitpid`/`waitid` traps become answers; `posix_spawn*` traps stay); the fifteen removed numbers → `SoftDeny(ENOSYS)`; `getpgid`/`getsid` → the virtual 1; `kill(0|-1, 0)`, `tgkill(pid, pid, 0)` probe the process; registry dispositions and reasoning honest.

Probes: `proc/prctl`, `proc/wait`, `proc/absent`, `proc/ids` (their pending entries deleted); `proc/traps` stays a by-design abort with its pinned SUD diagnostic.

Obligations:

| crate | test (its path is this, or ends in `::` + this) | what it must assert |
|---|---|---|
| `patina-dst-native-shim` | `sud::signal_process::tests::prctl_no_new_privs_accepts_only_one_with_zero_tail` | PR_SET_NO_NEW_PRIVS answers 0 only for (1, 0, 0, 0): 0 is EINVAL, a nonzero trailing argument is EINVAL, and once set PR_GET reads 1 and setting 0 is still EINVAL — through the one entry both doors call. |
| `patina-dst-native-shim` | `sud::signal_process::tests::prctl_dumpable_refuses_two` | PR_SET_DUMPABLE accepts 0 and 1 and refuses 2 (and every other value) with EINVAL; PR_GET_DUMPABLE starts at 1 and reads back what was set. |
| `patina-dst-native-shim` | `sud::signal_process::tests::prctl_pdeathsig_range` | PR_SET_PDEATHSIG accepts 0..=64 (0 clears) and refuses 65 with EINVAL; PR_GET_PDEATHSIG writes the stored value and is EFAULT for a null pointer. |
| `patina-dst-native-shim` | `sud::signal_process::tests::prctl_timerslack_zero_restores_default` | PR_GET_TIMERSLACK starts at 50000; a set value reads back; PR_SET_TIMERSLACK 0 restores 50000. |
| `patina-dst-native-shim` | `sud::signal_process::tests::wait_rows_answer_echild_and_einval` | wait4 and waitid answer ECHILD for a childless process (with and without WNOHANG) and waitid answers EINVAL for unknown option bits or none of WEXITED|WSTOPPED|WCONTINUED. |


Traps: answering `ENOSYS` where the kernel answers `EINVAL`; flipping a row to `Modeled` on one door only; handing `wait4` to the host.

### M2 — signal state and synchronous self-delivery

Scope: §2.2 state, PER TASK from the first line (masks, private pending, altstack; inherited mask at spawn); `rt_sigaction` on both doors over one table with `oldact` and the host forward; `rt_sigprocmask`/`rt_sigpending`/`sigaltstack` per task with out-parameters and the SIGSYS-frame `ucontext` writes; generation §2.3 for `kill`/`tkill`/`tgkill`/`rt_sigqueueinfo`/`rt_tgsigqueueinfo` with the kernel's errno vocabulary, recording `SignalGenerated` (§2.7, trace format 8 → 9 with the migration and a fixture); delivery points 1–3 of §2.4 with kernel-built frames via self-directed `rt_tgsigqueueinfo` carrying the virtual siginfo, from a DELIVERY POINT, never from generation; `SA_NODEFER`/`sa_mask`/`SA_RESETHAND`/`SA_ONSTACK`; delivery on unmask including the stacked-frame order; the zero-timeout dequeue (private before shared, lowest first, FIFO).

Probes: `signal/basic`, `signal/raw_action`, `signal/queue` (one table: generated signals and their dequeue order with payloads), `signal/mask` (delivery on the unblocking call), `signal/altstack`, `signal/per_thread` (two threads taking turns: a worker's block must not stop the main thread's own `kill(self)`; the main thread's `tgkill` to the blocking worker stays the worker's until the worker unblocks; altstack per thread; inherited mask), `signal/handler_flags` (default deferral, `SA_NODEFER`, `SA_RESETHAND`).

Obligations:

| crate | test (its path is this, or ends in `::` + this) | what it must assert |
|---|---|---|
| `patina-dst-abi` | `signal_generated_round_trips_and_mismatches` | Operation::SignalGenerated serializes with the tag `signal_generated` and its seq/sig/target/code/value fields, deserializes to an equal value, and two ops differing in seq, sig or target compare unequal (so replay reconciliation mismatches). |
| `patina-dst-trace` | `signal_operations_fixture_decodes_and_replays` | A committed current-format trace carrying signal_generated decodes, re-encodes byte-for-byte and replays. |
| `patina-dst-native-shim` | `signal_state_is_per_task` | With two tasks in one ThreadRuntime, blocking a signal on task A leaves task B's mask unchanged, a thread-directed instance queued to A is absent from B's pending set, and each task's altstack is its own. |
| `patina-dst-native-shim` | `mask_is_inherited_at_spawn` | A task spawned while its creator blocks a signal starts with that signal blocked in its virtual mask and with no private pending signals and no altstack. |
| `patina-dst-native-shim` | `same_task_kill_delivers_at_syscall_return` | A process-directed generation by the running task with the signal unblocked records SignalGenerated, enqueues, wakes nobody, and the delivery point at that call's return dequeues it for the handler — generation itself invokes no handler and issues no host signal. |
| `patina-dst-native-shim` | `unmask_delivers_pending_before_return` | A signal generated while blocked stays pending (no delivery at the generating call's return); the rt_sigprocmask that unblocks it reaches a delivery point that dequeues it before that call returns, for both SIG_UNBLOCK and SIG_SETMASK. |
| `patina-dst-native-shim` | `stacked_delivery_releases_frames_with_one_host_unblock` | When several signals become deliverable at one delivery point they are all queued on the host while blocked and released by ONE host mask change, in dequeue order (lowest first), never one host signal per instance with a handler run in between. |
| `patina-dst-native-shim` | `raw_rt_sigaction_installs_and_reports_oldact` | The raw rt_sigaction entry stores handler, flags, mask and restorer in the one action table the libc door reads, writes the previous action (SA_RESTORER and restorer included) to oldact, and flushes pending instances when SIG_IGN is installed. |
| `patina-dst-native-shim` | `sigaltstack_is_per_task_and_forwarded` | sigaltstack stores the stack per task, writes old_ss from that task's state, answers ENOMEM/EINVAL/EPERM as the kernel, and forwards the accepted stack to the host for the calling host thread. |
| `patina-dst-native-shim` | `dequeue_private_before_shared_lowest_first_fifo` | Dequeue takes the task's private pending set before the shared one, the lowest signal number within a set, FIFO within one realtime number with payloads intact, and coalesces a standard signal already pending. |
| `patina-dst-native-shim` | `generation_never_takes_the_runtime_lock_twice` | Generation reached from a path that holds the ThreadRuntime lock (the broken-pipe arm of pipe_write) trips the lock-order assertion; every shipped generation path runs with the lock released. |
| `patina-dst-native-shim` | `reserved_signals_are_stripped_from_every_host_mask` | Every mask the shim installs on the host — at delivery, at spawn, from rt_sigprocmask/rt_sigsuspend on both doors — has SIGSYS (and SIGSEGV while the TSC trap is armed) removed, and a guest registration for them is the named fatal on both doors. |

- Recorded traces (format ≥ 9; `signal_generated` ops, in order): `signal/basic` [10:p 10:t 10:t 10:t 10:t]; `signal/raw_action` [10:p 10:p]; `signal/queue` [34:p 34:p 34:t 10:p 10:p 35:p 34:p 34:p 12:p 10:p 34:p 34:t]; `signal/altstack` [10:p]; `signal/per_thread` [10:p 10:t].

Traps: a process-global C model — `static` mask/pending/altstack objects in `c/posix/signal_process.c` with a host `rt_tgsigqueueinfo` fired at GENERATION, which lets the host kernel be the pending queue and replays without any trace op: every behaviour-only single-threaded probe passes it; delivering directly from the C `kill` interposer; a global `SIGNAL_STATE`; `tgkill` with the host pid leaking into `si_pid`; forwarding `rt_sigqueueinfo`/`rt_sigpending` to the host (the round-4 leak legs); an allowlist by signal name or uid in a leak filter.

### M3 — blocking waits, delivery on resume, the restart rule

Scope: `Step::Interrupted` and `BlockedTask` registration on every parking path (§2.1); the target rule of §2.3 step 5 (leader first) and generation waking EXACTLY the chosen task (step 6); delivery point 4; §1.4 for every row with `nanosleep`/`clock_nanosleep` `rem` from the virtual clock (both doors pass the pointer down), `epoll_wait`/`ppoll` never restarted, `futex` timed vs untimed; `pause`/`rt_sigsuspend`/`rt_sigtimedwait` (NULL timeout and virtual-clock timeout) park (§2.5); `signalfd`/`signalfd4` as an fd kind on the unified table with `read`, `SFD_NONBLOCK`, `SFD_CLOEXEC`, mask replacement, readiness exactly while pending, and a blocking read that parks; the single-task timed futex wait answering `ETIMEDOUT` after the virtual timeout.

Probes: `signal/mask`, `signal/eintr`, `signal/wait`, `signal/block`, `signal/one_wake` (a worker parked in a read that BLOCKS the signal is neither failed nor woken while the leader is interrupted; then the leader blocks it and the worker is the one interrupted), `thread/futex`.

Obligations:

| crate | test (its path is this, or ends in `::` + this) | what it must assert |
|---|---|---|
| `patina-dst-native-shim` | `process_directed_signal_picks_the_leader_when_unblocked_else_lowest_unblocked` | For a process-directed generation the chosen task is the main task when it does not block the signal, else the lowest TaskId that does not, else nobody (it stays shared-pending) — independent of which task generated it. |
| `patina-dst-native-shim` | `generation_wakes_only_the_chosen_parked_task` | With two tasks parked in registered waits, a generation records at most one TaskWake — for the chosen task — and leaves the other parked and on its waiter list. |
| `patina-dst-native-shim` | `interrupted_waiter_is_unlinked_before_wake` | The chosen task is removed from its primitive's waiter list (pipe, futex, readiness, sleep timer) before it is woken, so a later data wake neither finds nor double-wakes it. |
| `patina-dst-native-shim` | `sa_restart_restarts_pipe_read` | A pipe read resumed as Step::Interrupted by a handler installed with SA_RESTART re-enters the wait and returns the byte written later. |
| `patina-dst-native-shim` | `no_sa_restart_pipe_read_is_eintr` | The same read without SA_RESTART returns EINTR after the handler's delivery point. |
| `patina-dst-native-shim` | `nanosleep_interrupted_reports_remaining_and_never_restarts` | An interrupted sleep returns EINTR even under SA_RESTART with remaining = deadline - virtual now, 0 < remaining <= request, on both doors' out-pointers. |
| `patina-dst-native-shim` | `absolute_clock_nanosleep_leaves_rem_untouched` | An interrupted TIMER_ABSTIME clock_nanosleep returns EINTR and does not write rem. |
| `patina-dst-native-shim` | `epoll_wait_is_eintr_even_with_sa_restart` | A readiness wait resumed as interrupted returns EINTR regardless of SA_RESTART and leaves no readiness waiter registered. |
| `patina-dst-native-shim` | `timed_futex_wait_is_eintr_under_a_handler` | A FUTEX_WAIT with a timeout interrupted by a handler is EINTR regardless of SA_RESTART; without a timeout it restarts under SA_RESTART and is EINTR otherwise. |
| `patina-dst-native-shim` | `sigsuspend_parks_until_an_unblocked_signal` | rt_sigsuspend installs its mask and parks; a signal the temporary mask blocks only becomes pending; one it does not wakes the task, which returns EINTR with the previous mask restored; pause and a NULL-timeout rt_sigtimedwait park the same way. |
| `patina-dst-native-shim` | `signalfd_readable_iff_matching_pending` | A signalfd's readiness is true exactly while a signal in its mask is pending for the reader; a read dequeues without running a handler; a blocking read parks until generation. |
| `patina-dst-runtime` | `signal_wake_records_task_wake_before_scheduler_next` | Record then replay of task_park, task_wake, scheduler_next consumes the three ops in that order. |
| `patina-dst-runtime` | `early_signal_wake_deregisters_timed_sleep` | Waking a task parked with a deadline before it fires deregisters the timer: the deadlock rescue does not wake it again. |

- Recorded traces (format ≥ 9; `signal_generated` ops, in order): `signal/mask` [12:p 10:p 10:t 12:p 10:p], ≤1 `task_wake` per generation; `signal/eintr` [10:p 10:p 10:p 10:p 10:p 10:p 10:p 10:p 10:p], ≤1 `task_wake` per generation; `signal/wait` [34:p 34:p 12:p 34:p]; `signal/block` [10:p 12:p 10:p 12:p 12:p 12:p 10:p], ≤1 `task_wake` per generation; `signal/one_wake` [10:p 10:p], ≤1 `task_wake` per generation; `thread/futex` [(none)].

Traps: returning `EINTR`/`EAGAIN` immediately from a wait (the rejected round's `sys_rt_sigsuspend`/`sys_pause`); a host-thread sleep fallback in `pipe_read` (round 4); waking every parked task (`patina_signal_interrupt_all`) — including the quiet form where the extra task re-checks and re-parks, which no probe sees and the recorded trace does (`max_wakes_per_generation`); a signalfd backed by a host fd; `SA_RESTART` applied to `nanosleep`/`epoll_wait`; choosing the generating task as the target.

### M4 — default actions, termination, SIGPIPE

Scope: §2.6 on both doors; `guest_exit.core` in the `cargo-patina` envelope (`GuestExit` gains `core` from the wait status; the harness reads it); SIGPIPE from `pipe_write` and the socketpair send path with `MSG_NOSIGNAL` honoured and `SIG_IGN` → bare `EPIPE`; Stop-class named trap; `abort()` finalizes then aborts through the host alias.

Probes: `signal/core_term`, `signal/pipe_term`, `signal/handler_flags` — through every vehicle, including the DIRECT run whose `waitpid` must read the native signal and core flag; `signal/default` (libc vehicle only) stays a by-design abort with the pinned C diagnostic.

Obligations:

| crate | test (its path is this, or ends in `::` + this) | what it must assert |
|---|---|---|
| `cargo-patina` | `guest_exit_reports_the_core_flag` | The patina.result/v1 envelope's guest_exit carries core: true|false taken from the child's wait status (ExitStatusExt::core_dumped) whenever signal is present, and no core key for a normal exit. |
| `cargo-patina` | `default_terminate_finalizes_then_dies_by_the_signal` | End to end: a guest that sends itself a SIG_DFL SIGTERM under `run --record` leaves a COMPLETE trace, the child's wait status is signaled 15 (not an exit code), and replay reproduces the same death. |
| `patina-dst-native-shim` | `broken_pipe_generates_sigpipe_before_epipe` | A write to a reader-less pipe records a thread-directed SignalGenerated for SIGPIPE with the runtime lock released, then answers EPIPE; with SIG_IGN the generation is recorded and dropped. |
| `patina-dst-native-shim` | `msg_nosignal_suppresses_sigpipe` | A socketpair send to a closed peer with MSG_NOSIGNAL answers EPIPE and records no generation; without the flag it records one. |
| `patina-dst-native-shim` | `sigstop_to_self_is_a_named_trap` | A default-action Stop-class signal reaching delivery is the named fatal trap; SIGTSTP/SIGTTIN/SIGTTOU with a handler run the handler. |

- Recorded traces (format ≥ 9; `signal_generated` ops, in order): `signal/core_term` [6:p]; `signal/handler_flags` [10:p 10:p 10:p 10:p 12:p 12:p]; `signal/pipe_term` [13:t 13:t 13:t 13:t].

Traps: `exit(128 + sig)` instead of dying by the signal, with or without a supervisor that translates it back (the direct run reads `exited 143`); a `core` the envelope hardcodes per signal; copying the expected termination into the observed stream (the frozen harness refuses; the gate's selftest plants it); terminating before the trace is finalized (no complete trace → no replay leg → the trace obligation is unmet).

### M5 — threads

Scope: thread-directed delivery to the named task with the handler on that task's host thread; delivery on the target's unmask; `pthread_kill` (and the other wrappers of §2.8) as strong defs with honest symbol rows; `set_tid_address` per task with the exit-time clear + futex wake; per-thread raw `exit` and main-thread exit while a worker runs; `exit_group` without atexit.

Probes: `thread/pthread_kill`, `thread/tid_clear`, `thread/main_exit`.

Obligations:

| crate | test (its path is this, or ends in `::` + this) | what it must assert |
|---|---|---|
| `patina-dst-native-shim` | `thread_directed_signal_targets_only_that_task` | tgkill/tkill queue to the named task's private set, choose that task alone for the wake, and deliver at ITS next delivery point; the generating task neither runs the handler nor is marked interrupted. |
| `patina-dst-native-shim` | `pending_for_a_blocking_task_is_invisible_to_another_tasks_sigpending` | A thread-directed signal pending for a task that blocks it is absent from every other task's rt_sigpending and is delivered when that task unblocks. |
| `patina-dst-native-shim` | `set_tid_address_is_cleared_and_woken_at_thread_finish` | set_tid_address returns the managed tid and records the word per task; thread_finish writes 0 to it and futex-wakes its waiters. |
| `patina-dst-native-shim` | `raw_exit_from_main_keeps_the_process_alive` | A raw exit from the main task completes that task only; the process ends with the status of a later exit_group from another task, and a raw exit_group runs no atexit handlers. |

- Recorded traces (format ≥ 9; `signal_generated` ops, in order): `thread/pthread_kill` [10:t 10:t], libc only; `thread/tid_clear` [(none)]; `thread/main_exit` [(none)].

Traps: validating the tid and then delivering on the caller (defect 4 of the review); `pthread_exit`/raw `exit` folded onto process exit; handing the guest's `set_tid_address` word to the host kernel.

Done: every pending gap gone, every obligation held, the by-design gaps intact, and `mise run check` green.

### What is NOT mechanically checkable (the vet's list)

- **Where the host signal is sent from.** The frame vehicle (`rt_tgsigqueueinfo`/`tgkill` to self) is legitimate at a delivery point and the shortcut at generation; the syscall is the same, so no grep separates them. It is held indirectly: the trace obligation (generation must record an op, so it goes through the runtime), `same_task_kill_delivers_at_syscall_return` and `stacked_delivery_releases_frames_with_one_host_unblock` (substance for the vet), and `signal/per_thread`/`signal/one_wake`.
- **Whether a unit test asserts what its row says.** A suite sees a name and a pass.
- **Process-global signal state, in C or in Rust, under any name.** No grep names it reliably; it is held by `signal_state_is_per_task`, `signal/per_thread`, `signal/one_wake` and the vet.
- **Host passthrough of a modeled row** (`wait4`, `rt_sigpending`, `rt_sigtimedwait`, `set_tid_address` handed to the host). The strace leak run's filter sees the syscalls it lists; the registry's dispositions and reasoning strings are the vet's.
- **`exit(128 + sig)` as source text.** `128 +` is legitimate in `cargo-patina`'s exit-code mapping; the direct-run `waitpid` check is the mechanical form.
- **No duplicated logic across the C and SUD doors, no compat shims, honest reasoning strings.** Phase D.

## 5. Where the oracle lives

The family's scenarios, their by-design gaps and their trace facts are in
`crates/patina-conformance/src/scenarios/{signal,thread,proc}/`; the unit-test
obligations are ordinary tests of their crates. Changing a scenario, a gap or a
trace fact is a reviewed diff like any other; there is no frozen manifest.
