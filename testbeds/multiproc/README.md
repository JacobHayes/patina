# multiproc — native process oracles and pending Patina gaps

These are Patina's own synthetic process workloads. The native leg runs the
real host kernel and checks the result inside each guest. The Patina leg pins
its first current refusal by name; a pending gap is evidence of containment,
not evidence that Patina supports processes. An unexpected success, a different
refusal, an unrelated abort, a failed build or a timeout fails the battery.

```sh
testbeds/multiproc/run-patina.sh --help
testbeds/multiproc/run-patina.sh --selftest
testbeds/multiproc/run-patina.sh
```

The classifier selftest is build-free and exercises each fixture's expectation,
including planted success, wrong boundary, missing envelope, mismatched status
and unrelated runtime failure. It also runs the timeout-cleanup detectors: an
orphan in a separate process group retains capture pipes after its leader exits,
and a planted capture holder exhausts both deadlines. Each guest also accepts `--help`. Native guests
receive a scratch directory; the Rust workloads additionally receive their own
executable path for workers. The runner discovers binaries from Cargo compiler
artifact messages and uses `TMPDIR` for temporary binaries and run data. It
honors the check runner's target isolation without selecting a target directory.

| Guest | Native invariant | Current x86_64 Linux Patina refusal |
|---|---|---|
| `spawn-wait` | sequential self-spawns succeed and are reaped | `posix_spawnattr_init` |
| `fanout` | parallel children produce checked stdout and stderr through pipes | `posix_spawnattr_init` |
| `pipeline` | producer, transformer and consumer transfer and check the complete payload | `posix_spawnattr_init` |
| `forkwait-c` | C fork-per-test exit and abort statuses survive wait | `fork` |
| `forkwait-cxx` | real iostream initialization and C++ exit/abort status checks | pre-run audit: `_ZSt4cout` (`unknown-import`) |
| `buildlike` | workers read source files and write derived objects; parent checks digests | `posix_spawnattr_init` |
| `sigchld` | SIGCHLD handler reaps with WNOHANG; timer kills a parked process group | `fork` |
| `failed-exec-enoent` | ENOENT preserves CLOEXEC fds, signal disposition and sibling thread | `execvp` |
| `failed-exec-eacces` | EACCES preserves CLOEXEC fds, signal disposition and sibling thread | `execvp` |
| `failed-exec-e2big` | E2BIG preserves CLOEXEC fds, signal disposition and sibling thread | `execvp` |
| `early-death` | immediately exited child is reaped once, then ECHILD | `fork` |
| `atfork-lock` | parent and child callbacks repair the inherited held mutex | `fork` |
| `fd-sharing` | child advances the shared offset and sets shared O_NONBLOCK | `fork` |
| `last-writer-eof` | writer death releases its description and reader sees EOF | `fork` |
| `epipe-sigpipe` | child write with no readers produces EPIPE and SIGPIPE | `fork` |
| `queued-signals` | a parked child receives queued real-time payloads and sender identity | pre-run audit: `__libc_current_sigrtmin` (`unknown-import`) |
| `shared-futex` | kernel wake acknowledges a queued waiter on an inherited shared word | `fork` |

C and C++ guests compile into separate objects linked to thin Rust launchers,
so the packaged native build uses Patina's normal shim. Each binary carries only
its own fixture object. C++ keeps the real iostream dependency; its earlier
refusal is intentional and must be migrated when that surface changes. Neither
that refusal nor the realtime-signal helper refusal is bypassed with an allowance.

Runtime process doors currently report the symbol in captured stderr and an
actual SIGABRT in the result envelope, without a dedicated process refusal class.
The classifier reads that symbol token and the exit disposition, without pinning
the surrounding prose. Pre-run gaps pair the run's `native_prerun_audit` class
with the audit's structured symbol finding. Native success relies on guest
assertions, not on printed result lines or operation counts. Each guest emits an
`MP_RESULT` digest for later benchmark consumption. Timed-out commands are
terminated through their own process group and pinned session-member handles,
including orphans in a different group. Descendant handles also cover new sessions
while the leader lives. Capture draining and leader reaping have deadlines; an
escaped capture holder cannot hang cleanup. The timeout regression pins pair
with that single bounded-wait authority.

The first baseline covers x86_64 Linux. The runner emits a loud `NOT RUN` on
other hosts; arm64 and Darwin expectations need separate evidence before being
claimed. The full local check and routine x86_64 Linux CI run the battery, while
the fast check runs only the classifier selftest. These guests are foundations
for future fork, exec, spawn, signal and shared-memory support, not green
multi-process feature tests.
