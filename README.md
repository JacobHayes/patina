# Patina

**Weather your code into a fine protective patina — before production does.**

Patina runs a Linux program many times, each run under a seed that decides thread
order, the clock, randomness, and which disk, network and crash faults the program meets.
The same seed gives the same run, so a bug that shows up once in a thousand runs becomes a
seed you can replay as often as you like. Your program runs unmodified: no rebuild, no
special linking, any language.

Patina is experimental. Linux x86_64 or arm64 (arm64: kernel 6.12 or newer, 4 KiB pages). It
needs `bwrap` (bubblewrap) and unprivileged user namespaces.

Changes in 0.12: triage of a checker's findings, and branch counters on arm64. A finding can
carry its grouping key (`LABEL [KEY]: detail`), `patina recheck` judges kept runs again with an
edited checker, and `--only-case` runs one case
([the guide](docs/GUIDE.md#judging-again)); `--preempt branches` works on the Arm Neoverse N2.

## Install

```sh
curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh
```

This installs one static binary, `~/.local/bin/patina` (`--prefix DIR` for another place),
and runs `patina doctor`, which checks the host and prints the fix for anything missing. The
last line should read `this host can run patina`. On Ubuntu 24.04 the two fixes are:

```sh
sudo apt-get install -y bubblewrap
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

Its first line names the release it installs. A release's own copy
(`releases/download/vX.Y.Z/install.sh`) installs that release; `--version X.Y.Z` picks any.

Root works too (the guest sees what it would for the user sudo was run by); in a container,
see [the guide](docs/GUIDE.md#as-root-and-in-a-container) for the options it needs. Patina
does not run on macOS itself. On an Apple Silicon Mac, run it in a Linux arm64 VM with 4 KiB
pages and a 6.12 or newer kernel, and check with `patina doctor` there. This is verified in one
VM product (Tart, Ubuntu 24.04 with the 7.0 kernel); UTM, Parallels, VMware Fusion, Lima,
OrbStack and Docker Desktop are not yet confirmed.

From a checkout instead, with Rust (rustup reads the pinned toolchain from
`rust-toolchain.toml`): `cargo install --locked --path crates/patina-cli`.

## First run

Give Patina any program and its arguments after `--`. `examples/quickstart` is a small Rust
program that runs three jobs on threads and checks their results come back in job order.

```sh
git clone https://github.com/JacobHayes/patina /tmp/patina
cd /tmp/patina/examples/quickstart && cargo build
patina run -- target/debug/jobs fixed
```

```text
ok (exit): the program exited 0
guest: exit 0
run directory: /tmp/patina/examples/quickstart/patina-out/run-0
replay: patina replay /tmp/patina/examples/quickstart/patina-out/run-0
```

The program's own output is in the run directory: `patina-out/run-0/inc-0/stdout` and
`stderr`. Now run 20 seeds of the version with the bug:

```sh
patina sweep --seeds 1..20 -- target/debug/jobs
```

```text
patina sweep: 20 runs, 14 findings in 1 group, 6 ok   (0.2s, 8 jobs)
outcomes: failure 14, ok 6

failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101
  14 of 20 runs   first: seed 1   replayed: identical
  rerun:  patina run --seed 1 -- /tmp/patina/examples/quickstart/target/debug/jobs
  replay: patina replay /tmp/patina/examples/quickstart/patina-out/sweep/seed-1
```

Each group is one bug: its signature, how many runs hit it, and the lowest seed among them.
Patina already replayed that seed once and got the same run. `patina run --seed 1 -- target/debug/jobs`
prints the outcome with the tail of the program's stderr; the run directory holds all of it:

```sh
cat patina-out/sweep/seed-1/inc-0/stderr
```

```text
thread 'main' (2) panicked at src/main.rs:28:5:
assertion `left == right` failed: results out of job order
  left: [2, 1, 3]
 right: [1, 2, 3]
```

`patina replay DIR` runs the seed again, into `DIR/replay`, and compares every system call
with the recorded one. Fix the code, rebuild, and run the same sweep command: a sweep
directory (`--out`, default `patina-out/sweep`) holds one sweep, so a changed program or
setting replaces it, and the same sweep with more seeds runs only the new ones.

## What works

Any Linux executable built for the host (x86_64 or arm64): static or dynamic, Rust, C, C++,
Go, Python, shell scripts and the programs they start. Threads, `fork`, `exec`, pipes, files, timers, signals and TCP and
UDP on localhost all run, decided by the seed. The program sees a fixed machine: 4 CPUs, one clock
that starts at the same time every run, an empty writable `/work` as its working directory.

What it does not do: network sockets other than TCP and UDP, multicast and broadcast (the
call fails with an error, and `patina run` lists it under `refused:`), DNS beyond
`/etc/hosts`, connections to anything outside the run, and macOS hosts. A call Patina does not
model ends the run `unsupported` and names it. [ARCHITECTURE.md](ARCHITECTURE.md#limits)
lists the limits.

Deeper search: a program rebuilt with coverage flags and Patina's hook file (or a Python
program run with `python3 -m patina`) also switches threads and moves the clock inside its own
computation, so races with no system call in them are found. [The guide](docs/GUIDE.md#deeper-search-rebuilt-code) has the details.

```text
C, C++  clang -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime, plus sdk/c/patina_compute.c
Rust    patina-dst with features = ["compute"]; the guide's RUSTFLAGS; cargo build --target x86_64-unknown-linux-gnu (arm64: aarch64-unknown-linux-gnu)
Go      import _ "github.com/JacobHayes/patina/go/patina/compute"; CGO_ENABLED=0 go build -gcflags=all=-d=libfuzzer
Python  no rebuild (3.12+): sdk/python on PYTHONPATH, then python3 -m patina app.py
```

## Outcomes

Every run ends in one outcome; the exit status of `patina` follows from it.

| Outcome | Exit | Meaning |
|---|---|---|
| `ok` | 0 | the program exited 0, or with a status `--ok-exit` names (stop `ok-exit`), and broke no invariant |
| `violation` | 1 | an invariant failed: an SDK `always`, or the `--check` command |
| `liveness` | 1 | every thread blocked, or the virtual time limit passed |
| `failure` | 1 | the program exited nonzero, with a status `--ok-exit` does not name |
| `crash` | 1 | the program died on a signal |
| `unsupported` | 2 | the program did something Patina does not model (stop `exec`: an image the kernel would run that Patina does not load, such as a 32-bit program), or never finished and filled the log to `--log-limit` (stop `log-limit`); the message names it |
| `timeout` | 2 | the wall-time limit passed |
| `nondeterministic` | 2 | a replay differed from its run: a Patina bug, please report it |
| `internal` | 2 | Patina failed, or the host refused a resource |
| `vacuous` | 2 | a sweep's fault, SDK check or `--check` never had anything to act on, or a finding a known file requires (`!ID`) did not appear |
| `error` | 2 | the command could not be carried out: the program cannot run, as `execve` would refuse it (stop `exec`: not executable, a `#!` interpreter missing, not an image of this architecture), or the `--check` command failed (stop `check`) or answered otherwise on replay (`check-unstable`) |

## Where next

- [examples/README.md](examples/README.md): one bug each found by scheduling, by an SDK fault
  point, by disk faults, by crashes and by network faults, in Rust, Python, C and Go.
- [docs/GUIDE.md](docs/GUIDE.md): sweeps, faults, crashes, the SDK, reading a result,
  replay, CI.
- [ARCHITECTURE.md](ARCHITECTURE.md): how it works and its limits.
- `patina --help`, `patina COMMAND --help`: every flag of your build.
