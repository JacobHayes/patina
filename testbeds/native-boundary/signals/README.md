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
must leave it incomplete. The internal-context case nests a custom operation.
`native_containment` owns the libc/raw SIGSYS registration refusals and, under
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
delivered from. `native_signals` runs it
natively as the oracle and under the shim, and requires the same output and
deaths (on an ordinary stack the nested fault is a named stop instead, as is
a fault handler on an alternate stack too small for the shim's fault route
below the kernel's frame). Its
`alarm` cases, in `native_containment`, fire a timer while counter reads taken
on the alternate stack are served off it, on an ordinary stack and on one too
small to leave a nested frame room: natively both run on, and under the shim
each is a named stop, since no guest code runs during such a read.

`shim_fault.c` calls a fault planted in a shim entry (`patina_planted_fault`,
in a shim built with the `planted-faults` feature) under a guest handler for
the signal: a SIGSEGV, a SIGBUS and a SIGILL, which `native_containment` requires to be
named stops that take the default action, never the handler, on every Linux
arch.

`frame_mask.c` has a handler add SIGSYS and SIGSEGV to its frame's saved mask,
returning through glibc's restorer and (x86_64) through the guest's own raw
and `syscall(2)` stubs; a raw syscall and a timestamp-counter read must still
be answered afterwards. Its `sa-mask` case installs a handler whose `sa_mask`
blocks every signal, and the handler's own first counter read and raw syscall
must be answered while it runs. `native_signals` runs it natively as the oracle and
under the shim, and requires the same output.

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
