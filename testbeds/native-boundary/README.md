# Native boundary acceptance guests

Rust integration tests in `crates/cargo-patina/tests/` compile these guests.
Each guest's internal assertions and its harness assertions form the proof.

| Cargo test target | Proof | Platforms |
|---|---|---|
| `native_abi` | Prefixed C crash/checkpoint and env protocol; POSIX fd/env/path ABI; C stdio at the edges of a run (teardown, a refusal, the first write, a failed `assert`) and its buffering modes against the host; pipe/socketpair wakeups; reactor fields and exact virtual deadlines | Linux x86_64 + arm64, macOS; epoll/eventfd Linux-only, kqueue/nsec Darwin-only |
| `native_containment` | Import/instruction refusals (thread-pointer writes included, and their `arch_prctl`/`modify_ldt` doors, x86_64), host env/envp isolation, dlsym routing, SUD arming/refusal, auxv, SIGSYS, TSC, real faults and handler protection | Both OSes; SUD/auxv Linux; TSC/vsyscall x86_64 Linux |
| `native_workloads` | std, the virtual realtime epoch and node name (defaults, `--realtime-epoch`, `--hostname`), independent entropy sources, locks/timers (a timer and a wait ending at one instant: interval timer vs `nanosleep`, timer descriptor vs `poll`, Linux; a mutex relocked before the first thread is a deadlock, Linux), thread names independent of the binary's file name (Linux), UDP/TCP, tokio signal driver + parking_lot + product-selected rustix backend; Linux keyutils credentials (empty per-run rings, host canaries, password lifecycle) | Linux x86_64 + arm64, macOS |
| `native_raw` | Mixed raw/libc descriptor parity, legacy syscall aliases, exact virtual identity, soft refusals, prctl state/refusals, raw ppoll timeout writeback and pipe readiness | x86_64 Linux; unsupported SUD executes refusal assertions |
| `native_signals` | Linux C readiness EINTR/mask/timeout contracts, libc/raw signal state, sigwait retry and guest-abort finalization; Linux/macOS internal-panic ownership, catchable guest panics and process/sleep repeat/replay | Linux + macOS shared cases; interruption Linux-only; inline raw cases x86_64 Linux with SUD |
| `native_trace` | Whole-run std syscall containment and a planted host open through the same filter; explicit unsupported-ktrace policy | strace on both Linux architectures; static containment evidence on macOS |
| `end_to_end` | `text_metadata_probe.rs`: native-return assertion, declared executable-text metadata refusal, and absent trace facts in the libtest result; portable import-refusal companion | Metadata Linux x86_64; import refusal Linux + macOS |

All seven targets run in `mise run check` and the workspace-test CI jobs:
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
`initial_stack_env.c` is the startup-layout class detector: it walks from argv
rather than trusting `environ`, compares the exact requested map and pointer
identity, then checks Linux auxv against libc or Darwin's apple-string vector.
The launcher tests cover empty, single-entry and many-entry maps, repeats and
flag-free replay. Direct reserved launches measure this binary's actual trailer
and exercise zero, one and many surplus slots. Short-capacity and invalid-marker
refusals have sufficient-capacity and valid-marker positive twins that exit 42.
An unreserved nonempty map refuses; the same map with a reservation succeeds.
`envp_probe.c` separately retains the unreserved direct protocol's empty-envp
contract (no initial-trailer guarantee). These tests are enabled on macOS;
macOS arm64 execution is pending landing verification.

`rand-rng/`, `tokio/`, `raw/`, and [`keyring-keyutils/`](keyring-keyutils/README.md) are locked standalone packages. The build
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

### Call-free compute

`compute_watchdog.rs` plants main- and worker-thread atomic spins with a runnable
peer, plus a spin that holds the guest allocator. The latter detects allocating
or deallocating on the asynchronous stop path. `single` and `parked` run the same
long compute with no runnable peer (the latter uses a mutex/condvar handshake,
never a synchronization sleep). `finite` keeps a peer runnable while doing
finite call-free work: it must complete below a raised bound, but recording with
a short bound and replaying with a long bound must both stop. A partial stderr
line before the spin pins fresh-line diagnostic framing. `native_workloads` requires named known-limit
findings, an interrupted PC, valid and identical repeated terminal traces, and
replay with the same task/prefix despite a much larger host bound. These are
runtime-limit tests, not host-equivalence claims.

### Small signal stacks

`signals/frame_size.h` measures a delivered kernel frame on a large, aligned
alternate stack and restores the previous action, mask, and registration.
`segv_routing.c` and `counter_small.c` add their intended headroom to that
measurement, aligning the final top down (never adding slack). Calibration is
repeated in each process; these guests do not change extended-state permissions
afterward. `AT_MINSIGSTKSZ` can include unrequested AMX tile state and is only a
diagnostic, not a sizing oracle. The `frame-size` cases and CI test summary
report the measured/advertised sizes and CPU flags.

The native runs still prove the small handlers fit. Shim runs require the same
named stops and exact counter/restoration results as before. A test-only C
mutation moves the Rust route ahead of admission; the short-stack detector
rejects it on both Linux architectures. The compiler-frame/route-write budget
check also self-tests a structural ban on pre-admission Rust calls, including
leaves that might otherwise happen to fit in the remaining space.

## Executable-section metadata refusal

`text_metadata_probe.rs` places neutral REX-prefix-range bytes after a return
but **inside the function's declared `.size`**. Its native test calls `probe()`
and asserts the function returns 42; the Linux x86-64 instruction audit refuses
the unreachable data as `undecodable-instruction`. The `end_to_end` target's
`native_harness_audit_refusal_does_not_advertise_a_trace` test owns this limit
and asserts the result has no trace facts, even with an older file present.
Its portable class pairing is `native_harness_import_refusal_has_no_trace`.

Data outside declared functions is a different case: symbol-bearing ELF
sections may omit inter-function gaps. The positive counterpart is
`native_source_builds_preserve_auditable_code_boundaries`, which audits and runs
that layout, including an internal NOTYPE label bounded by its function's end.
Neither case justifies skipping undecodable bytes inside a range; see the
escape taxonomy for the metadata policy and residuals.

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
