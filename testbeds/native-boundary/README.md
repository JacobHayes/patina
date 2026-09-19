# Native boundary acceptance guests

Rust integration tests in `crates/cargo-patina/tests/` compile these guests.
Each guest's internal assertions and its harness assertions form the proof.

| Cargo test target | Proof | Platforms |
|---|---|---|
| `native_abi` | Prefixed C crash/checkpoint and env protocol; POSIX fd/env/path ABI; pipe/socketpair wakeups; reactor fields and exact virtual deadlines | Linux x86_64 + arm64, macOS; epoll/eventfd Linux-only, kqueue/nsec Darwin-only |
| `native_containment` | Import/instruction refusals, host env/envp isolation, dlsym routing, SUD arming/refusal, auxv, SIGSYS, TSC, real faults and handler protection | Both OSes; SUD/auxv Linux; TSC/vsyscall x86_64 Linux |
| `native_workloads` | std, independent entropy sources, locks/timers, UDP/TCP, tokio signal driver + parking_lot + product-selected rustix backend | Linux x86_64 + arm64, macOS |
| `native_raw` | Mixed raw/libc descriptor parity, legacy syscall aliases, exact virtual identity, soft refusals, prctl state/refusals, raw ppoll timeout writeback and pipe readiness | x86_64 Linux; unsupported SUD executes refusal assertions |
| `native_signals` | C readiness EINTR/mask/timeout contracts; libc/raw signal state, sigwait retry, guest abort versus internal-fatal trace finalization | Linux; inline raw cases x86_64 with SUD |
| `native_trace` | Whole-run std syscall containment and a planted host open through the same filter; explicit unsupported-ktrace policy | strace on both Linux architectures; static containment evidence on macOS |

All six targets run in `mise run check` and the workspace-test CI jobs:
Linux stable/MSRV on both architectures, macOS stable. They are **not** in
`check:fast`. That tier retains `shim_host_alias`'s compiled-object scan and
planted leak, and `test_support`'s parsing/deadline checks.

```sh
mise run check:native-abi
mise exec -- cargo test -p cargo-patina --test native_abi pipe_aliases_keep_channels_alive
mise exec -- cargo test -p cargo-patina --test native_containment rdrand_is_refused_on_every_kernel
mise exec -- cargo test -p cargo-patina --test native_workloads condvar_waits_use_exact_virtual_deadlines
```

`check:native-abi` selects the ABI target; Cargo's test-name filter selects one
behaviour. `end_to_end::native_build_package_audits_records_and_fails_closed`
owns package/path-dependency/build-script/ambiguous-bin coverage in the full gate.

## Builds and assertions

`tests/common` owns CLI invocation, concurrent output capture with process-group
deadlines, compiler selection and shim-object compilation. `common/native.rs`
provides explicit assertion helpers. Record/replay checks compare full stdout,
two complete traces, flag-free replay, and a mismatched-fingerprint refusal.
Entropy sources vary independently. POSIX startup sees host canaries so an
empty guest `environ` demonstrates isolation, not an empty input environment.

`rand-rng/`, `tokio/`, and `raw/` are locked standalone packages. The build
helper explicitly places their Cargo artifacts under the integration test's
target base, beside the profile (`native-guests/<package>/`), including plain
`cargo test` runs without an inherited `CARGO_TARGET_DIR`. No package-local
`target/` directory is used. Single-file guests inherit the caller's shim build
location without an override.
Tokio supplies no rustix configuration override: the product selects raw on
SUD targets and injects `rustix_use_libc` elsewhere.

`mise run check`, `mise run smoke`, and CI run the FIFO/rustix-default/cap-std
workloads through `scripts/check-native-testbeds.sh`. Its independent kernel
probe requires each SUD workload's exact `branch=sud` receipt on a capable
host; child success or a false-negative capability skip is insufficient.
Unsupported hosts must emit the expected counted skip. `PATINA_REQUIRE_SUD=1`
requires live SUD in both Rust tests and the wrapper, and is set on x86_64 Linux
CI rows; a filtered capability probe is a failure, not a green refusal. The wrapper's selftest
plants a false-negative probe, a duplicate receipt and a failed child.

## Coverage boundaries

Syscall conformance owns host-equivalent fd/fs/readiness semantics, including
pipe alias lifetimes, duplex socketpairs, creation permissions, FIFO transfers,
and zero-flags epoll/eventfd readiness with exact userdata. The raw readiness
probe also runs explicitly in x86_64 MSRV CI. Oracle expectations currently
exist only on x86_64 Linux; portable ABI tests, scheduler park/wake tests and
exact virtual deadlines remain separate. No pending or whole-probe divergence
is credited as native acceptance evidence.

The class-level checks are the import/instruction gates, `shim_host_alias`,
`native_trace`'s planted whole-run escape, host-oracle probes and runtime
scheduler/clock/trace invariants. Patina-specific identity/ENOSYS/auxv pins do
not claim host equivalence.

The std tracing filter has a narrow loader contract. Cargo's injected
`LD_LIBRARY_PATH` is removed for direct guest exec; no extra directory accesses
are allowlisted. Conformance has its own broader signal/process filter.
`PATINA_REQUIRE_STRACE=1` fails when strace is missing and is set on every Linux
CI row. `PATINA_REQUIRE_KTRACE=1` fails on macOS because ktrace lacks decoded
paths and a usable initialization boundary. Unsupported tracing is visibly
reported, not claimed as runtime containment. Unsupported SUD/TSC capabilities
execute pre-run refusal assertions. The SUD-only vDSO property reports missing
evidence without building a substitute guest; requiring SUD makes absence fatal.
