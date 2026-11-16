# Guide

How to run a program under Patina, find bugs in it, and read what Patina found. Every flag
is in `patina COMMAND --help`; this guide shows how they fit together. The examples use the
programs in [examples/](../examples/README.md), run from the repository root.

## Running a program

```sh
patina run --seed 7 -- ./myprog --port 8080
```

Everything after `--` is the program and its arguments. A program given by a path is copied
into the run as `/guest/NAME`; a bare name (`python3`, `sh`) is looked up on the guest's
`PATH` (`/guest:/usr/local/bin:/usr/bin:/bin`). The host's `/usr` is visible read-only, so
system interpreters and shared libraries work.

The program starts in `/work`, an empty writable directory that is also its `HOME`. Nothing
else of the host is visible unless you give it:

| Flag | What the program gets |
|---|---|
| `--mount SRC:DST` | a host file or directory, read-only, at `DST` |
| `--mount SRC:DST:copy` | a copy of a host directory at `DST` |
| `--work DIR` | `/work` starts as a copy of `DIR` |
| `--stdin FILE` | standard input |
| `--env K=V` | one environment variable (the rest is fixed: `PATH`, `HOME`, `LANG`, `TZ`, `PATINA=1`) |
| `--cpus N` | the CPU count it sees (default 4, whatever the host has) |

The guest sees no network beyond itself: a connection to another host fails with
`Network is unreachable`, and DNS finds nothing. Servers and clients must run in the same
program or in programs it starts.

`patina run` prints the outcome and the run directory; when the run is not ok, also the last
lines of the program's stderr and the faults injected, and any calls Patina refused (the
program got an error code for them). The program's full output is in the run directory
(`--out`, default `patina-out/run-SEED`, replaced on each run):

| File | Content |
|---|---|
| `run.json` | the seed, the resolved settings, the program's path and SHA-256 |
| `result.json` | the outcome and everything measured (below) |
| `inc-0/stdout`, `inc-0/stderr` | the program's output; `inc-1/` and on after a crash and restart |
| `inc-0/boundary.log` | every system call and decision, for replay and `patina log` |

### A configuration file

`patina.toml` in the current directory (or `--config FILE`) holds the same settings; flags
override it, and an unknown key is an error. `--config RUNDIR/run.json` takes every setting
of an earlier run.

```toml
[run]
cmd = ["./acklog"]
cpus = 2

[faults]
crash = "machine:10"
preset = "disk"
fsync-error-permille = 0
```

With that file, `patina sweep --seeds 1..50 --out patina-out/toml` needs no other arguments.

## Sweeps

A sweep runs many seeds, in parallel, each a normal `patina run`, and groups the failures
by what failed.

```sh
patina sweep --seeds 1..200 --crash machine --out patina-out/acklog -- ./acklog
```

| Flag | Effect |
|---|---|
| `--seeds 1..200,250` | an inclusive range, a list, or both |
| `-j N` | runs at once (default half the CPUs, at most 8) |
| `--out DIR` | where runs go (default `patina-out/sweep`) |
| `--keep fail\|all\|none` | whose logs to keep; `run.json` and `result.json` always stay |
| `--max-findings N`, `--budget SECONDS` | stop early |
| `--cases FILE` | one run per line of FILE per seed (below) |

A sweep directory holds one sweep. It records the program's SHA-256, the command and the
resolved settings (`sweep.json`); the same sweep run again resumes, running only the runs it
lacks (more seeds, or after an interrupt), and any other sweep replaces the directory. Edit,
rebuild and rerun the same command: the old runs never mix with the new.

Each group in the summary is one signature: the outcome, what stopped the run, and its first
line of evidence (the failed `always` label with the first line of its detail, the panic or
assertion line or else the last line of stderr, the blocked waits). What names the failure is kept: the exit status, the
signal, the label. Numbers in the program's text (line and column numbers, addresses, ids,
counts, durations) become `N`, so one bug over many seeds is one group. Absolute paths keep
their last three components, in signatures and SDK labels alike (a label made from a source
path is the same in every checkout). A sweep announces each
new group with its lowest seed and replays that seed once; a replay that differs makes the
group `nondeterministic`. `patina report DIR...` prints the same summary for any run
directories and writes `report.json`. A replay or a minimized run is written inside the run
it comes from, so it never counts as one of the sweep's runs.

### Test runners: `--cases`

A test suite is many tests, best run each alone. `--cases FILE` runs every line of FILE once
per seed, each its own run. A line is a whole command: the program and its arguments, quoted
as in a shell (no variables or globs), so one file can name several test programs. Empty
lines and lines starting with `#` are skipped.

```sh
cat tests.txt
```

```text
python3 -m unittest test_store.Store.test_write
python3 -m unittest test_store.Store.test_counter
```

```sh
patina sweep --seeds 1..10 --cases tests.txt --mount .:/guest --env PYTHONPATH=/guest
```

```text
patina sweep: 20 runs, 10 findings in 1 group, 10 ok   (0.3s, 8 jobs)
outcomes: failure 10, ok 10

[python3 -m unittest test_store.Store.test_counter] failure exit: AssertionError: N != N; exit 1
  10 of 20 runs   first: seed 1   replayed: identical
  rerun:  patina run --seed 1 --env PYTHONPATH=/guest --mount /tmp/casedemo:/guest -- python3 -m unittest test_store.Store.test_counter
  replay: patina replay /tmp/casedemo/patina-out/sweep/seed-1/2-test_store.Store.test_counter
```

Given a command after `--`, a line is instead put in place of `{}` in it: `--cases names.txt
-- python3 -m unittest {}` runs the same. Each (case, seed) is its own run directory,
`OUT/seed-N/K-NAME`: K the case's position in the file, NAME a short form of its last word
that is not an option; the file `case` there and the report hold the whole line. With whole-command lines, a
rebuilt program reruns only its own cases when the sweep runs again.

A compiled test binary lists its tests; turning the list into lines is one loop. For the
test binaries `cargo test --no-run` builds (the same works for any runner that lists and
selects tests by name):

```sh
for b in $(cargo test --no-run --message-format=json | jq -r 'select(.profile.test and .executable) | .executable'); do
  "$b" --list --format terse | sed -n "s|: test\$||; s|^|$b --exact |p"
done > tests.txt
patina sweep --seeds 1..5 --cases tests.txt
```

## Faults

Faults are drawn from the seed like everything else. A preset turns on a class with rates
that are ranges; each seed picks a value in each range, so one sweep covers gentle and harsh
settings.

| Preset | Settings |
|---|---|
| `--faults disk` | `fs-error-permille=0..5 fs-short-permille=0..20 fsync-error-permille=0..3 fs-delay-permille=0..20` |
| `--faults net` | `net-delay-ms=0..50 net-chunk-max=1..65536 net-reset-permille=5..50 net-connect-refuse-permille=0..10` |
| `--faults all` | both, plus `mem-error-permille=0..2` |

`--fault KEY=VALUE` sets one key and replaces the preset's value for it; `patina run --help`
lists every key. Disk faults act on files under `/work`, pipes and unix sockets; an injected
error is one Linux can return for that call on that object. Network faults act on TCP
connections: a reset is drawn on each piece of data a program sends, so a long-lived (keep-alive)
connection meets one; a refusal or timeout is drawn once per connect. `mem-limit-mb=N` makes
memory requests past N MiB fail with `ENOMEM`. `result.json`'s `faults.counts` gives per
class the calls (or sends, connections, deliveries) it was drawn on and the faults it
injected; `faults.injected` is their sum.

A failing group says which fault classes were injected in every failing run, and in none:

```text
violation always: journal-intact: N bytes
  12 of 20 runs   first: seed 2   replayed: identical
  faults in every failing run: fs-short      in none: fs-error, fsync-error
```

`patina minimize RUNDIR` drops and halves a failing run's fault settings while the run still
fails the same way. It prints each try (`without fs-short-permille=0..20: still fails`,
`fs-error-permille=40 -> 20: no longer fails`), the settings it kept, and last the command
that reruns the reduced run (written to `RUNDIR/minimized`).

### Crashes

`--crash machine` crashes the whole program at a seed-chosen point and starts it again with
the same arguments, on what had reached the disk: data never synced may be gone, renames and
creations may be undone. `--crash process` kills the processes but keeps what they wrote, as
an operating system does when a program dies. The default rate is 3 per mille per crash
point (`--crash machine:10` for 10); `machine-at:SEQ` crashes at one boundary record.

A program under `--crash` must be restartable: on start, it recovers its state from `/work`
and checks it. `PATINA_INCARNATION=K` is set after the K-th restart. `examples/acklog-c`
shows the shape:

```text
$ patina run --seed 3 --crash machine -- ./acklog
violation (always): acked-records-kept: 23 acknowledged, 0 stored
faults injected: 1 (crash 1)
last injected:
  seq 124 t=100000ms crash kind=machine object=/work/data.log lost: 0 missing, 1 changed, 0 back
```

What survives a machine crash follows `ext4-ordered` by default; `[faults] fs-model =
"posix-strict"` allows everything POSIX allows, which loses more.

## The SDK

Without the SDK, Patina finds what makes a program exit nonzero, die, hang or deadlock. The
SDK adds invariants and fault points. It is one reserved system call: outside Patina the
kernel answers `ENOSYS` and every SDK call becomes a load and a branch, so it ships in
production builds without flags.

| Call | Meaning |
|---|---|
| `always(cond, label)` | must hold; a false one ends the run `violation` |
| `sometimes(cond, label)`, `reachable(label)` | should hold or be reached in some run of a sweep |
| `buggify(label)` | a fault point: true on seed-chosen evaluations under `--buggify` |
| `knob(label, default, lo, hi)` | a seed-chosen value under `--buggify` |

Under `--buggify` each point is active in about a quarter of runs and fires on about a
quarter of its evaluations; `--fault point:LABEL=PERMILLE` fixes one point's rate. A sweep in
which a `sometimes` never held, a `reachable` was never hit, or (under `--buggify`) a
`buggify` point never fired is `vacuous` unless the label is allowed with `--allow-unmet
LABEL`. The summary gives a count per kind and the first five labels; `report.json` lists
all of them, with every `always` never evaluated.

**Rust**: `patina-dst = { path = "PATINA/crates/patina" }` in `Cargo.toml`.

```rust
if patina_dst::buggify!("batch-commit") && !ledger.is_empty() { /* the rare path */ }
patina_dst::always!(ledger.is_sorted(), "ledger-sorted", "after {entry}");
```

**C and C++**: `cc -I PATINA/sdk/c`, one header.

```c
#include "patina.h"
PATINA_ALWAYS(acked <= stored, "acked-records-kept", detail);
```

**Go**: pure Go, no cgo; `go.mod` requires `github.com/JacobHayes/patina/go/patina`
(`examples/bank-go/go.mod` points it at a checkout).

```go
var balanceMatches = patina.Always("balance-matches-deposits")
balanceMatches.Check(balance == deposits, "balance ", balance, ", deposits ", deposits)
```

**Python**: one file, `sdk/python/patina.py`; copy it next to the program or put its
directory on `PYTHONPATH`.

```python
INTACT = patina.Always("journal-intact")
INTACT.check(got == expected, f"{len(got)} bytes")
```

Other languages can speak the wire directly; `sdk/c/patina.h` documents it.

## Reading a result

Start with the summary line and the program's `stderr`. Then `result.json`:

```text
$ jq '{outcome, stop, message, signature, incarnations, crashes: [.crashes[].kind]}' patina-out/run-3/result.json
{
  "outcome": "violation",
  "stop": "always",
  "message": "acked-records-kept: 23 acknowledged, 0 stored",
  "signature": "violation always: acked-records-kept: N acknowledged, N stored",
  "incarnations": 2,
  "crashes": [
    "machine"
  ]
}
```

Other fields: `faults` (the resolved plan, per class how many calls it could act on and how
many it hit, and the last 20 injected), `sdk` (every declared site, evaluated and held
counts), `refused` (calls answered with an error because Patina does not model them),
`sched`, `counters`, `digest`, `wall_ms`.

For storage bugs, `patina log ops RUNDIR/inc-0` lists every change to `/work` in order. In the
acklog run the record write to `data.log` (ino 2) has no fsync before the acknowledgement's:

```text
     4 seq=52       vt=100000048000   pid=2   Write       ino=2      off=0 len=8
     5 seq=53       vt=100000049000   pid=2   Write       ino=3      off=0 len=8
     6 seq=54       vt=100000050000   pid=2   Fsync       ino=3      flags=0
```

`patina log dump LOG --from SEQ --to SEQ` prints the boundary log; `patina log diff A B`
names the first record where two logs differ.

## Replay and verify

`patina replay RUNDIR` runs the program again with the run's settings, into `RUNDIR/replay`,
and compares every boundary record. It refuses a program whose SHA-256 changed. `identical` means the bug is
reproduced exactly; a difference ends `nondeterministic` and names the first differing
record, which is a Patina bug.

`patina verify` runs one seed several times while changing the host (the CPU it runs on,
address randomization, background load) and checks the runs are identical:

```text
$ patina verify --seed 3 --runs 3 --vary cpu,aslr,load --crash machine -- ./acklog
run 0: cpu 8 aslr off load on env base violation 629a8e811d421b90 switches 0
run 1: cpu 16 aslr on load on env base violation 629a8e811d421b90 switches 0
run 2: cpu 0 aslr off load on env base violation 629a8e811d421b90 switches 0
identical: 3 runs in /tmp/patina/patina-out/verify-3
```

## Scheduling

One thread of the program runs at a time; the seed picks the next one at each scheduling
point. The points are every system call, every `pause` instruction (the hint in spin locks),
and spin-waits Patina detects: a thread that computes for 20 ms without a system call is
stepped until it is found looping without changing anything, and yields there.

A thread that computes for 10 s of CPU time without reaching a scheduling point, while
another thread is waiting to run, ends the run `unsupported` with stop `compute-stall`. The
cause is a spin-wait whose loop changes state on each pass (a counter, a timestamp) and has
no system call or `pause`. `--preempt branches` also preempts after a seed-chosen number of
branches; it needs an AMD Zen 5 CPU with its PMU exposed (not in most virtual machines) and
`CAP_PERFMON` (`sudo setcap cap_perfmon+ep $(command -v patina)`), and its seeds reproduce
only on that CPU family. `patina doctor` says which of the three is missing.

## CI on GitHub Actions

Patina runs on the `ubuntu-24.04` runner after two setup lines. A job that sweeps a Rust
program:

```yaml
jobs:
  patina:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: { repository: JacobHayes/patina, path: patina-src }
      - run: |
          sudo apt-get install -y bubblewrap
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - run: cd patina-src && cargo install --locked --path crates/patina-cli
      - run: patina doctor
      - run: cargo build && patina sweep --seeds 1..200 -- target/debug/myprog
```

`patina doctor` on that runner:

```text
ok    bwrap                              /usr/bin/bwrap (bubblewrap 0.9.0)
ok    user namespaces                    bwrap creates the sandbox (user, pid, net, mount namespaces; tmpfs)
ok    sandbox run                        a run of /usr/bin/true is ok (166 ms)
off   branch counters (pmu, optional)    not supported on this CPU, GenuineIntel family 0x6 model 0xad (supported: AMD Zen 5)
info  cpu_model                          Intel(R) Xeon(R) 6975P-C
info  kernel                             7.0.0-1014-aws
this host can run patina
```

The sweep's exit status fails the job on a finding (1) or when Patina could not do what was
asked (2). Upload `patina-out` as an artifact to keep the failing runs; a run directory
replays only with the same program binary, so keep the binary with it.
