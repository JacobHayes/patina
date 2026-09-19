# Native signal boundary guests

`blocking_readiness.c` exercises the libc adapters for poll, ppoll, select,
pselect, epoll_pwait and sleep. A helper generates SIGUSR1 only after the main
thread parks; assertions pin EINTR despite SA_RESTART, mask restoration and
libc timeout-output conventions.

The typed `cargo-patina` integration test `native_signals` compiles it with the
current shim and requires every named wait case to succeed. Rust state/restart
detectors and the frozen syscall-conformance family supply the complementary
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

Every case uses `cargo-patina/tests/common` for compilation and process-group
deadlines. `native_raw` separately owns prctl modeled/unsupported/privileged
options and ppoll timeout writeback plus pipe readiness 0→1/revents.
