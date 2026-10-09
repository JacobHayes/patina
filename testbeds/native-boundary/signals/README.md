# Native signal boundary guests

`blocking_readiness.c` exercises the libc adapters for poll, ppoll, select,
pselect, epoll_pwait and sleep. A helper generates SIGUSR1 only after the main
thread parks; assertions pin EINTR despite SA_RESTART, mask restoration and
libc timeout-output conventions.

The typed `cargo-patina` integration test `native_signals` compiles it with the
current shim and requires every named wait case to succeed. Rust state/restart
detectors and the signals-family conformance scenarios supply the complementary
raw-door, trace/replay and host-oracle evidence.

`signal_boundary.c` supplies independent named cases for libc/raw prctl state,
handler visibility through tgkill/tkill, reserved masks (SIGSYS stripped,
SIGSEGV's block kept virtually while counter reads still trap, including
handler-time temporary masks), and sigwait retry after an unrelated handler.
The `native_signals` target also records guest abort and C/raw/internal-context
fatal paths: guest abort must publish a complete trace; each internal fatal
must leave it incomplete, and an internal fatal never runs the guest's SIGABRT
handler. The internal-context case nests a custom operation.
`native_containment` owns libc/raw SIGSYS registration/query round trips: the
guest action stays virtual, a raw syscall still returns the virtual pid without
calling it, and explicit guest SIGSYS generation aborts after registration. The
unit detector also verifies the host action is unchanged. It also owns, under
the timestamp-counter trap, the SIGSEGV cases: a registration through either
door leaves the counter read answered and the handler unrun. These inline raw cases require x86_64 Linux SUD;
missing capability is reported explicitly and `PATINA_REQUIRE_SUD=1` makes
missing evidence fatal.

`segv_routing.c` gives a guest its own SIGSEGV handler: an `SA_ONSTACK` one
catches a stack overflow on its alternate stack and an access fault, leaving
both by `siglongjmp`; an `SA_RESETHAND` one receives a raised SIGSEGV with
the sender's code; one edits the faulting context to resume past the store;
one that blocks SIGSEGV faults inside itself or re-raises it, as does a
SIGFPE (arm64: SIGTRAP) handler whose `sa_mask` blocks every signal; and a pending
SIGSEGV meets a pending SIGUSR1 in 6.8's frame order, also when the SIGSEGV
handler leaves by `siglongjmp` or resets SIGUSR1's action; repeated
`SA_NODEFER` signals run as often, in the order and under the saved masks
6.8 gives them; and a handler whose `sa_mask` blocks SIGSEGV reads it back
blocked on an `SS_AUTODISARM` alternate stack above the stack it was
delivered from; handlers on alternate stacks with room for one delivery and
little more run, and so do timer handlers between counter reads. `native_signals`
runs it natively as the oracle and under the shim, and requires the same output
and deaths (on an ordinary stack the nested fault is a named stop instead). Its
`route-cost` case measures what a delivery takes of the handler's stack above
its frame, for a raised signal, a fault and a SIGSEGV: natively the kernel's
frame, under the shim the same few bytes on every route.

`small_stack.c` sends signals by tgkill from a 2 KiB stack to handlers on
the alternate stacks they registered: `native_signals` requires them to run
inside those bounds, told so by `sigaltstack` and `uc_stack`, to nest, to
leave by `siglongjmp` thousands of times, to swapcontext to coroutines (on a
mapping, or on a local array of a frame above the handler) that make syscalls
and come back, to return out of order, to nest by `siglongjmp` into an outer
handler, and a dead thread's destructor to make one (past what the shim
tracks, 70 suspended or left handlers stop by name),
printing what they print natively, through the raw trap and (`-libc`, every
arch) glibc's `syscall(2)`. `private_budget.c` (over a `planted-faults` shim)
measures each recording level of the shim's private signal stack against its
budget, and checks the guard above a running handler's level.
`../small_stack_probe.rs` (in `native_containment`) records and replays raw
syscalls made on a 2 KiB stack and requires nothing written below it.

`shim_fault.c` calls a fault planted in a shim entry (`patina_planted_fault`,
in a shim built with the `planted-faults` feature) under a guest handler for
the signal: a SIGSEGV, a SIGBUS and a SIGILL, which `native_containment` requires to be
named stops that take the default action, never the handler, on every Linux
arch.

`fault_routing.c` covers the other signals an instruction raises, whose host
disposition is the shim's fault front handler: in `swap-escape` a raised trap
signal's frame runs the action its dequeue captured after an earlier handler of
its batch installed a new one, and leaves by `siglongjmp`; a genuine trap right
after must run the new action under the new action's mask. Its `die-*` cases
take a fault under the default action (SIGBUS, `__builtin_trap`, and on x86_64
SIGFPE and `int3`) after writing a line to descriptors 1 and 2 and leaving one
in C `stdout`'s buffer, and `die-blocked` takes the SIGBUS on a thread that
blocks every signal, so the kernel takes it with no handler at all.
`native_signals` runs it natively as the oracle and under the shim and
requires the same output and exit: the written lines kept, the buffered one
lost.

`frame_mask.c` has a handler add SIGSYS and SIGSEGV to its frame's saved mask,
returning through glibc's restorer and (x86_64) through the guest's own raw
and `syscall(2)` stubs; a raw syscall and a timestamp-counter read must still
be answered afterwards. Its `sa-mask` case installs a handler whose `sa_mask`
blocks every signal, and the handler's own first counter read and raw syscall
must be answered while it runs. `native_signals` runs it natively as the oracle and
under the shim, and requires the same output.

`frame_abandon.c` (over a `planted-faults` shim) has handlers leave by
`siglongjmp` from every kind of delivery: a fault in guest code (the clean
control), `raise`, an unblocking `pthread_sigmask`, `sigsuspend`, a blocked
`read` and a yield that another thread signals, a signal a returning SIGSEGV
handler held back, a timer expiring during counter reads, a raw `tgkill`,
`abort`, and a SIGSEGV handler inside an `atexit` handler. Each reports the
shim scopes still counted beneath guest code after the jumps and the handlers
that ran over a shim Rust frame (`docs/arcs/signal-frame-safety.md`).
`native_signals` requires 0 for both natively, for the control, and for the
cases the exit of a trap handler delivers (the counter reads on x86_64, the
held-back signal: `c/posix/delivery.c`), and pins every other case as a gap
until its delivery returns to C first, among them a timer due at a counter
read inside a handler `raise` ran: its delivery is made as `raise`'s own,
over the frames `raise` left suspended, never released from C over them.
`drive_under_scope.c` drives a delivery from inside a shim entry (a planted
control): its first step stops the run by name. `held_back_escape.c` has a
fault handler whose mask blocks SIGUSR2 raise it and leave by `siglongjmp`
to a context that unblocks it (glibc restores that mask with its own system
call): `native_signals` requires SIGUSR2's handler to have run by the next
delivery point, where natively it ran at the restore.

`thread_registrations.c` holds the per-thread kernel registration cases:
`robust-exit` has a thread register a robust list and exit, and requires the
exit walk to mark only the word the thread owned `FUTEX_OWNER_DIED`;
`robust-wake` has shared, private and pending-operation waiters on a dying
owner's words and prints which the walk woke; `robust-dtor` releases a robust
lock from a thread-local destructor (run natively as the oracle too); and
`robust-new` asks `get_robust_list` about threads just created, over several
seeds and runs. `rseq-sentinel` reads the main thread's and two threads' rseq
areas through `__rseq_offset`, requires each registered and naming the CPU
`sched_getcpu` answers, and writes a sentinel to their CPU fields that must
survive a handled signal (the host kernel rewrites a registered area at every
delivery), so a host registration left behind is caught on every run.

Every case uses `cargo-patina/tests/common` for compilation and process-group
deadlines. `native_raw` separately owns prctl modeled/unsupported/privileged
options and ppoll timeout writeback plus pipe readiness 0→1/revents.
