# syscall-conformance — the host-oracle conformance harness

The kernel is the oracle. Every `probes/<family>/<name>.rs` binary is a
self-checking scenario over a slice of the Linux syscall ABI; it issues its
calls through one of three **vehicles** and writes one typed JSON event per
observed call on stdout. The same binary runs natively (the host kernel
answers), under `cargo patina run` (patina answers), and under `cargo patina
replay`, and the event streams must agree except for the divergences declared
in `divergences.toml`. Design: `docs/arcs/syscall-conformance.md` §4.

```sh
testbeds/syscall-conformance/run.sh                 # every probe, every mode, every vehicle
testbeds/syscall-conformance/run.sh --fast          # native + patina, libc vehicle (check:fast)
testbeds/syscall-conformance/run.sh --mode patina --vehicle raw --probe fs/open_rw
testbeds/syscall-conformance/run.sh --selftest      # prove every gate can fail
testbeds/syscall-conformance/run.sh --bless         # re-record expected/ on THIS host
testbeds/syscall-conformance/run.sh --help
testbeds/syscall-conformance/gate.sh --family signals                 # the frozen-oracle family gate
testbeds/syscall-conformance/gate.sh --selftest     # prove the gate can fail
```

## The frozen oracle and the family gate

A family whose runtime is built after its probes (the signals family:
`docs/arcs/syscall-conformance-signals.md`) is FROZEN before the builder
starts. `frozen.toml` records, per family, the probe ids it owns, the oracle's
`paths` (its probes and expectations, the harness sources, `run.sh`,
`probes.toml`, the manifests, `gate.sh`, `frozen.toml`), the exact declaration
set its probes may carry in `divergences.toml` — `pending: <family> — …`
entries the builder may only DELETE, and `by design:` aborts that stay — and
the design obligations below. There is one gate and one outcome:
`gate.sh --family <f>` prints what is left as plain lines, then one verdict
line, `FAMILY_GATE <f>: PASS|FAIL`. It passes when:

1. the frozen paths carry no uncommitted change (`jj diff --name-only --
   <paths>` is empty; `git status` where there is no jj repo). Version control
   is the tamper evidence: a builder never commits, the coordinator lands;
2. the declaration rule (`conform gate`: nothing new, relabeled or re-scoped;
   no by-design entry removed; no pending entry left);
3. rustfmt, clippy `-D warnings`, the registry cross-gate;
4. the full `run.sh` is green;
5. the family's design obligations hold.

Every step runs; the work lines name the probes still pending or differing,
the required unit tests missing, ignored or failing, and the trace facts unmet
(each step's full log is under `$CARGO_TARGET_DIR/conformance/gate`, defaulting
under `../../target/testbeds/syscall-conformance`). The gate is the
progress report and the definition of done; a family's spec may suggest an
order of work (the signals family's M1..M5), but there are no partial gates.

### Design obligations

Green probes are necessary, not sufficient: a shallow model can satisfy
behaviour-only probes (a process-global C signal model that fires a host signal
at generation time passes every single-threaded signal probe on every leg,
replay included, with no per-task state and no trace op). So `frozen.toml`
carries what such a pass skips, and the gate prints every unmet one as a work
line (`unit test missing: patina-dst-native-shim
unmask_delivers_pending_before_return`):

| kind | what the gate checks |
|---|---|
| `unit-test` (`crate`, `test`, `asserts`) | exactly one test of the crate has that path — or ends in `::<test>`, so the module layout stays the builder's — is not `#[ignore]`d, and passes when run alone (`cargo test -p <crate> -- --exact <path>`). `asserts` is what the test must assert: the gate checks existence and passing, the final vet checks substance against that sentence |
| `trace` (`probe`, `format_version_min`, `signal_generated`, `max_wakes_per_generation`) | from the trace the probe's replay leg RECORDED, as `cargo patina trace info\|events --format json` reports it (`run.sh` dumps both next to the leg): the format version, the `signal_generated` ops — exactly the probe's generations, in order, `<sig>:p` process-directed or `<sig>:t` thread-directed — and at most N `task_wake` ops directly after a generation. No recorded trace (the probe is still declared, or its replay leg failed) is unmet |

Run the gate early and often — its lines are the work that is left.
`gate.sh --selftest` proves each mechanism can refuse, beside a control that
passes: a frozen-path edit (in a scratch checkout), a relabeled declaration, a
required test that is missing, ignored, failing, or filtered to zero executions
(a real scratch crate), a recorded trace with no `signal_generated` op for a generating probe,
and a termination that was not observed — or is `exited 143` where the blessing
died by SIGTERM — refused by the differ. A passing serial test with raw child
stderr is a positive control: verdicts are read from stdout only, never merged
with compiler diagnostics. Nonzero cargo status still refuses, and failures
retain both streams for diagnosis.

## Filesystem attribute coverage

`fs/times`, `fs/owner`, and `fs/size` include zero-count I/O and EOF after
truncation, missing-name/closed-fd OMIT, empty-path timestamps, symlink chown,
retained FIFO timestamps/ownership before and after unlink, checked time-range
conversion, fallocate overflow, ZERO_RANGE, and truthful statx allocation masks.
The literal libc null-path call is checked separately from the futimens adapter.
Wide timestamps are an explicit EINVAL divergence (Linux can clamp them);
unmodeled allocation accounting leaves STATX_BLOCKS absent. Actual crash
reconstruction and positive-latency record/replay are driver/runtime unit gates,
not claims made by a host process that cannot crash the virtual filesystem.

## Signals, threads and process coverage

`signal/*`, `thread/*` and `proc/*` are the signals family's oracle (the spec:
`docs/arcs/syscall-conformance-signals.md` §1 names the Linux fact each probe
pins). Their helper threads wait until the main thread is asleep in its
blocking call (`/proc/self/task/<tid>/stat` natively; a virtual-time pause
under patina, which has no `/proc`) and record a `helper_kill` mark
immediately before they signal, so a wait that returned early (`pause`, `rt_sigsuspend`, a
blocking `rt_sigtimedwait` or signalfd read, a `read` restarted under
`SA_RESTART`) shows up as an ordering divergence, and every handler records the
tid it ran on (`gettid()` inside the handler) so thread-directed delivery is
pinned to the thread, not to a count. The fork-based child oracles
(`signal/default`, `signal/pipe`, `signal/nested`, `thread/lifecycle`,
`proc/traps`) run natively and are declared `by design:` aborts at the fork's
event with the trap's diagnostic pinned; the same facts are pinned in-process by
`signal/default_term`, `signal/core_term`, `signal/pipe_term`,
`signal/resethand_term`, `thread/main_exit` and `thread/tid_clear`.
Two probes exist because a single-threaded probe cannot tell per-task state
from process-global state, or a targeted wake from a wake-all:
`signal/per_thread` (two threads, no signal crossing them: a worker's block
must not stop the main thread's own `kill(self)`; private pending, altstack
and the inherited mask are per thread) and `signal/one_wake` (a worker parked
in a read that blocks the signal is neither failed nor woken while the leader
is interrupted; then the roles swap).
`thread/pthread_kill` is libc-only (`probe_main!(…, libc)`).
The shared handler state lives in `src/signals.rs`.

## Proving a probe can fail

`PATINA_PROBE_BREAK=<probe>` (or `<probe>:<check label>`) inverts the outcome of
that probe's `check` events, so `run.sh --mode native --probe <probe>` goes red
against the host oracle. Every new probe's report pastes that red leg once; the
variable is never set by `run.sh` itself.

## The registry and the manifest

`probes.toml` says which rows and symbols each probe covers; the registry
(`crates/patina-native-shim/src/registry/`) says which probe covers each row.
The two are gated against each other both ways, and the prelude refuses a
manifest naming a non-row (`conform check-manifest`). The virtual kernel ABI
level (`registry::VIRTUAL_ABI`) and each row's first kernel (`since`) reach the
harness through `cargo patina syscalls --format json` (dumped to
`$CARGO_TARGET_DIR/conformance/registry.json`), so an expectation header and the host
gate can never disagree with the registry. `abi/newer-than-virtual` is the
probe for the rule: a number past the level (`fchroot`, 472, Linux 7.3) is
`ENOSYS` through every vehicle, and natively the host must lack it too.

## Vehicles

| `--vehicle` | how the call is issued | what it exercises under patina |
|---|---|---|
| `libc` | the glibc symbol of the same name (`openat`, `fstatat`, …) | the C interposer layer (`crates/patina-native-shim/c/`) |
| `syscall` | glibc's `syscall(2)` with the `libc::SYS_*` number | the shim's `syscall` interposer |
| `raw` | an inline-asm `syscall` instruction (x86_64 Linux only) | the SUD dispatcher (`sud.rs`) |

A probe body is written once against `Probe` (`src/calls.rs`), which records
every call with the row's normalizations. Rows whose libc symbol the shim does
not interpose today (`getdents64`, `ppoll`) live in their own probes and link
that symbol only there (`Probe::register_libc`), so the pre-run audit refuses
just that probe rather than every binary. A probe with no kernel-row shape
for a vehicle (a pthread wrapper) names the vehicles it runs through
(`probe_main!("thread/pthread_kill", scenario::run, libc)`) and exits 4 for
the others before recording anything; the runner counts those legs as skips.

## Modes and legs

| `--mode` | leg | what must hold |
|---|---|---|
| `native` | the plain binary with `--strict` under `conform supervise` | the normalized stream — including the `__termination` line the supervisor appended from `waitpid` — equals `expected/<probe>.<os>-<arch>.jsonl` exactly; host kernel ≥ the blessing kernel; a host lacking an exercised row's number, or implementing a row the probe asserts `absent`, is `HOST-UNAVAILABLE` (counted, not failed) |
| `patina` | `cargo patina run … --seed 1 --format json -- --vehicle V` under `conform supervise` | the guest stream is unpacked from the `patina.result/v1` envelope and its `guest_exit` becomes the `__termination` line; every field difference from the blessing is declared in `divergences.toml`, and every declaration still diverges (a stale one fails) |
| `replay` | `run --record --format json` then `replay --format json` | the two guest streams (termination included) are byte-identical and the recorded one passes the patina diff |
| `leak` | the shim-linked binary directly under `strace`; a probe blessed to die by a signal is also run DIRECTLY (no `cargo patina`, no strace) and its `waitpid` outcome — signal and core flag — must be the blessed one, so an exit code a supervisor translates into "signaled" does not pass | zero host syscalls outside the loader prelude (the local `run.sh` default-deny filter (a separate filter from `native-boundary/containment.awk`, but expanded for conformance), trace set widened to `%process,%signal,%ipc`) plus the ONE signal allowance — `tgkill`/`tkill`/`rt_tgsigqueueinfo` whose target is the calling thread itself, any signal number, never a name list, never a uid, never a process-directed `kill` — and the process ends the way the blessing says (strace re-raises the tracee's terminating signal on itself) |

Every leg runs in its own process group under a wall-clock timeout
(`PATINA_CONFORMANCE_LEG_TIMEOUT` seconds, default 60): on expiry the group is
killed and the leg fails loudly with the probe's stderr tail. Every leg is a
`PASS`, a `FAIL` (with the differ's lines and the probe's stderr), or a counted
`SKIP`; the script exits 1 on any failure and prints `CONFORMANCE_LEGS_RAN …`
only after every leg passed. Off Linux, on an unblessed platform, or without
SUD for the raw vehicle it prints a counted `SKIPPED`/`SKIP` line — never a
silent green.

### The termination line

The one event the harness itself appends to every stream is how the probe
process ENDED, as the supervisor observed it — never as the expectation says:

```json
{"seq":5,"op":"__termination","args":{},"ret":0,"errno":null,"fields":{"core":false,"kind":"signaled","signal":15},"norm":{}}
```

`kind` is `exited` (with `code`) or `signaled` (with `signal` and the wait
status's `core` flag — `null` when the supervisor cannot report it, which is
what `cargo patina`'s envelope reports until the runtime carries it, and then a
declared divergence on `fields.core`). Natively it comes from `waitpid`; under
patina and replay from the envelope's `guest_exit`. It is compared like any
other event and declarable as `op = "__termination"`. A probe whose last act
ends the process on purpose records `Probe::dies_by(signal)` (`expect_death`)
first; the blessing refuses a signal death that was not announced, a failed
check, and a nonzero exit.

Two host properties a probe can observe are pinned by `run.sh` so the native
oracle and the virtual kernel start from the same process state: standard
input is `/dev/null` (a probe reading fd 0 sees EOF on both sides, and never
blocks on a terminal) and `RLIMIT_NOFILE` is 1024 (`ulimit -S -n`), the
virtual kernel's own limit (`patina_fd_limit`), so `EMFILE` and the
`F_DUPFD`/`dup2` bounds fall at one number natively and under patina.

## Events, normalization, checks

```json
{"seq":3,"op":"openat","args":{"dirfd":"AT_FDCWD","flags":66,"mode":420,"path":"/tmp/syscall-conformance/fs-open_rw/data"},
 "ret":3,"errno":null,"fields":{},"norm":{"ret":"relative:fd"}}
```

`ret` is the kernel result (`-1` with `errno` named on failure), `fields` the
struct members the probe chose, and `norm` the typed per-field normalization
the differ applies before comparing (never regex over text):

| tag | meaning |
|---|---|
| `relative:<ns>` | an allocated number (descriptor, port): replaced by the label of the event that introduced it (`fd@57`), so identity relations survive and magnitudes do not; a `close` retires a descriptor number |
| `inode` | inode identity, same labeling (`ino@5`) |
| `identity` | pid/uid/gid, same labeling (`id@0`) |
| `monotonic` | a clock reading: `mono:first`, `mono:>=`, `mono:-` relative to the previous reading of the same op/field |
| `mask:0oNNN` | keep only these bits |

Semantic properties are `p.check(label, cond)` events (`op: check`, `ret`
1/0). Natively (`--strict`) a false check panics; under patina it is recorded
and the probe continues, so one wrong answer becomes one declared field
divergence rather than a lost stream. `p.require` marks the few preconditions
a scenario cannot continue without.

## Expectations and divergences

`expected/<probe>.<os>-<arch>.jsonl` starts with a header naming the oracle:

```json
{"header":{"schema":"patina.conformance/v1","probe":"fs/open_rw","os":"linux","arch":"x86_64",
 "kernel":"6.8.0-139-generic","glibc":"2.39","virtual_abi":"6.8"}}
```

`virtual_abi` is the kernel ABI level patina's virtual kernel claims
(`registry::VIRTUAL_ABI`, read from `cargo patina syscalls --format json` in
the prelude along with each row's `since`; the manifest carries neither). Re-record with `--bless` on a host whose kernel is at
least what the other blessings name; the other two vehicles must then agree
natively (the runner checks). A platform with no expectation file is skipped
loudly (`UNBLESSED`); `linux-aarch64` needs a bless on an aarch64 host.

`divergences.toml` declares each host≠patina field with a reason:

```toml
[[divergence]]
probe  = "fs/open_rw"
op     = "openat"          # or "*"
field  = "errno"           # op | ret | errno | args.<k> | fields.<k>
seq    = 55                # optional; `seqs = [..]` for a set; `label = "…"` for check events
reason = "pending: F3 — a component through a regular file answers ENOENT, not ENOTDIR (…)"
```

`kind = "abort"` (with `seq`) declares a probe that dies inside patina at that
event — the recorded prefix is still compared (both fatal paths flush the
captured streams first), the termination must be a signal death, `stderr =
"…"` (optional) pins the diagnostic the leg's stderr must carry, and the replay
leg is skipped as for a probe-level declaration, since the death leaves no
trace; `kind = "probe"` declares a probe that cannot be compared at all (an
audit refusal, or a probe that dies before its first event); `kind =
"pending"` declares a probe that is not conformant yet — every difference it
still shows (a death, lost events, a field, the termination) is covered and
LISTED in the leg's output, and it is STALE the moment the probe passes
cleanly (the frozen-family form is `pending: <family> — M<k>: …`, §"The frozen
oracle"). Every kind is self-cleaning: a declaration the stream no longer
needs fails the leg as STALE, so the file is always exactly the current gap.
`vehicle = "…"` scopes a declaration to one vehicle.

## Selftests

`run.sh --selftest` proves each gate can fail, on synthetic streams through the
same differ the legs use (`conform selftest`): a planted divergence (native and
patina), a planted stale divergence, planted event-count drift in both
directions, a failed check, a probe that dies, planted stale probe-level and
abort-level declarations, a planted wrong termination and a stream or
expectation without one, an unreported core flag, a blessing of an unannounced
signal death, a pending declaration that covers and one gone stale, an abort
whose pinned diagnostic is absent, the frozen declaration rule's refusals (new,
relabeled, removed by-design, a pending entry left), the host gate's refusals
(host-unavailable in both directions — a kernel lacking an exercised row, a
kernel implementing an `absent` one — and too-old), a manifest naming a
non-row or a row of the wrong kind, plus the controls that
must pass; the strace leak gate against a planted `openat("/etc/hostname")`
(`probes/selftest/leak.rs`) under the leg's exact `strace` invocation and
filter, and the bounds of the self-signal allowance on synthetic strace lines
(a `tgkill` to another thread, a process-directed `kill`, a `rt_sigpending`
and a `signalfd4` are denied); and the leg timeout against a planted
never-returning process group (killed, recorded as a `timeout` termination).

## Adding a probe

1. Add `probes/<family>/<name>.rs` (see any existing one) and its `[[bin]]`
   (`name = "<family>-<name>"`) to `Cargo.toml`.
2. Add `[probe."<family>/<name>"]` to `probes.toml` with the kernel rows it
   exercises (`syscalls`), the rows it asserts `ENOSYS` for because their
   `since` is past the virtual ABI level (`absent`), and the libc symbols the
   `libc` vehicle goes through (`symbols`); every name must be a registry row,
   and the row's `probe` field must name this probe back
   (`crates/patina-native-shim/src/registry/`, gated by
   `cargo test -p cargo-patina --test syscall_registry`).
3. `run.sh --bless --probe <family>/<name>`, then `run.sh --mode patina --probe …`
   and declare what it finds in `divergences.toml` with a `pending: <family>`
   reason and the responsible shim code (for a frozen family, a
   `kind = "pending"` entry, in `frozen.toml` too).
4. Paste the red leg (`PATINA_PROBE_BREAK`) in the report.

Layout: `src/vehicle.rs` (vehicles, numbers, errno names), `src/observe.rs`
(events, recorder, normalization tags), `src/calls.rs` (the probe API),
`src/signals.rs` (the signal probes' shared handler state), `src/expect.rs`
(normalizer, differ, termination, host gate, frozen rule, selftest),
`src/bin/conform.rs` (the CLI `run.sh`/`gate.sh` drive: `supervise`, `diff`,
`gate`, …; positional arguments only), `probes.toml`, `divergences.toml`,
`frozen.toml`, `gate.sh`, `expected/`.
