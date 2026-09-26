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
handler visibility through tgkill/tkill, reserved mask stripping (including
handler-time temporary masks), and sigwait retry after an unrelated handler.
The `native_signals` target also records guest abort and C/raw/internal-context
fatal paths: guest abort must publish a complete trace; each internal fatal
must leave it incomplete. The internal-context case nests a custom operation.
`native_containment` owns the libc/raw SIGSYS and armed-SIGSEGV registration
refusals, alongside its existing Rust `signal(handler)` guests. These inline
raw cases require x86_64 Linux SUD; missing capability is reported explicitly
and `PATINA_REQUIRE_SUD=1` makes missing evidence fatal.

`frame_mask.c` has a handler add SIGSYS and SIGSEGV to its frame's saved mask,
returning through glibc's restorer and (x86_64) through the guest's own raw
and `syscall(2)` stubs; a raw syscall and a timestamp-counter read must still
be answered afterwards. `native_signals` runs it natively as the oracle and
under the shim, and requires the same output.

`thread_registrations.c` holds the per-thread kernel registration cases:
`robust-exit` has a thread register a robust list and exit, and requires the
exit walk to mark only the word the thread owned `FUTEX_OWNER_DIED`;
`robust-wake` has shared, private and pending-operation waiters on a dying
owner's words and prints which the walk woke; `robust-dtor` releases a robust
lock from a thread-local destructor (run natively as the oracle too); and
`robust-new` asks `get_robust_list` about threads just created, over several
seeds and runs.

Every case uses `cargo-patina/tests/common` for compilation and process-group
deadlines. `native_raw` separately owns prctl modeled/unsupported/privileged
options and ppoll timeout writeback plus pipe readiness 0→1/revents.
