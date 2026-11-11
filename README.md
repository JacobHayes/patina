# Patina

**Weather your code into a fine protective patina — before production does.**

Patina runs an ordinary program in a simulated world where time, randomness,
thread scheduling, the filesystem and the network are all decided by one
number, the seed. The same seed always gives the same run, so a bug that shows
up once in a thousand runs becomes a seed you can replay as often as you like.
This is deterministic simulation testing (DST), known from FoundationDB and
Antithesis, done by linking a deterministic layer under the standard library:
your code needs no rewrite.

Patina is experimental. Its commands, its SDK and its trace format will change.

## Install

```sh
curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh
```

That checks the download against the release's checksums and installs
`~/.local/bin/patina`. With [mise](https://mise.jdx.dev/):
`mise use -g github:JacobHayes/patina`.

Releases are built for Linux (x86_64 and arm64) and macOS (Apple silicon).
Patina compiles its runtime with your toolchain the first time you use it, so
the machine also needs Rust 1.99 or newer and a C compiler (`cc`). Inside
Docker, run the container with `--security-opt seccomp=unconfined`: Patina
turns off address-space randomization for the program it runs, which Docker's
default profile forbids.

## First run

Five minutes: a small library with a bug that ordinary tests miss, found by
Patina running the tests the library already has.

**1. Make a library.**

```sh
cargo new --lib jobs && cd jobs
```

**2. Write the library.** It runs jobs on threads and promises their results
in job order. Put this in `src/lib.rs`:

```rust
use std::sync::mpsc;
use std::thread;

/// Run every job on its own thread and return the results in job order.
pub fn run_all(jobs: Vec<fn() -> u64>) -> Vec<u64> {
    let (sender, receiver) = mpsc::channel();
    for job in jobs {
        let sender = sender.clone();
        thread::spawn(move || sender.send(job()).unwrap());
    }
    drop(sender);
    receiver.iter().collect() // BUG: this is the order the jobs finished in
}
```

**3. Write an ordinary test.** Put this in `tests/order.rs`. `cargo test`
passes it nearly every time, because the first thread usually finishes first.

```rust
#[test]
fn results_come_back_in_job_order() {
    let results = jobs::run_all(vec![|| 1, || 2, || 3]);
    assert_eq!(results, [1, 2, 3]);
}
```

**4. Run the suite under Patina.**

```sh
patina test --seeds 20
```

`patina test` builds each test target once, then runs every test in a
simulated world of its own, once for each of 20 *seeds*. Each seed decides,
among other things, which thread runs when. The first build is slow: it
compiles Patina's runtime. Then the summary names each test that did not
pass, why, and the seed it failed on (with your own paths, and perhaps
another seed):

```text
patina test: 1 test(s) in 2 target(s); built in 10.3s, ran in 0.4s (12 job(s), seeds 0..20)
  failure               1

failure          jobs --test order results_come_back_in_job_order (seed 0)
    panicked at tests/order.rs:4:5: assertion `left == right` failed
    rerun:  patina test . -p jobs --test order results_come_back_in_job_order --exact --seed 0
    replay: patina replay /home/you/jobs/target/patina/dst/jobs/test/order/guest /home/you/jobs/target/patina/dst/jobs/test/order/traces/results_come_back_in_job_order.seed-0.patina

patina: FINDING in the guest [failure]: 1 of 1 did not pass
```

It takes the selection `cargo test` takes (`-p`, `--workspace`, `--lib`,
`--test NAME`, a name filter, `--exact`), and exits 0 when every test passed,
1 on a finding and 2 when a test could not run under Patina.

## A failing seed, and how to replay it

A failure under Patina is a *seed*, and the seed is the whole bug report.
Patina ran the failing seed a second time and recorded it. The recording is
the *trace*: a file that holds every decision the simulated world made.

**5. Replay it.** Copy the `patina replay` line from your own output. It runs
the same program against the trace and fails the same way every time:

```text
  left: [1, 3, 2]
 right: [1, 2, 3]
patina: FINDING in the guest [failure]: the guest panicked, or a test in it failed (guest exit 101)
```

The `rerun:` line builds the test again and runs that one seed: use it after
you change the code. Here the fix is to join the threads in job order. With
it, `patina test --seeds 20` passes all 20 seeds.

```rust
pub fn run_all(jobs: Vec<fn() -> u64>) -> Vec<u64> {
    let workers: Vec<_> = jobs.into_iter().map(thread::spawn).collect();
    workers.into_iter().map(|worker| worker.join().unwrap()).collect()
}
```

## What programs work

Patina runs a program in a closed world. Three rules follow from that.

- **The program must be self-contained.** There is no real network, disk or
  clock behind the simulated ones. A file the program reads must be written by
  the program, or mounted read-only with `--mount`. A connection to a database
  or another service outside the process finds nothing there.
- **The program must finish.** A test body finishes; so does a `main` that
  does its work and returns.
- **A server needs its clients in the same process.** Start the server on one
  thread and drive it from another, as a test does. A server that only waits
  for connections ends as `liveness`: every thread is blocked, because nothing
  in the simulated world will ever connect.

Patina refuses what it does not model instead of letting it reach the real
machine: the run ends as `unsupported` and names what it met. Loading code at
run time (`dlopen`) is refused.

On Linux a program may start itself again, and a test may start its package's
own binaries, which `patina test` builds for the simulation too.
`std::process::Command` works, with pipes, captured output, signals and exit
statuses; each process is simulated in the same run and replays. Other
programs (`cargo`, `git`, a shell), `system`, `popen`, plain `fork`, a process
started by a child, and crash-restart runs that start processes are refused,
and macOS runs one process. The guide says more.

A dependency can link an instruction or import that its tests never run (a
CPU random-number instruction in a crypto library). The whole target is then
refused, and `patina test --allow SYMBOL` admits it; the result says it ran so.

One limit is quiet: Patina switches threads where a thread reaches the
operating system (a lock it waits for, a sleep, a read, a write) and at the
end of each 1 ms slice of computation. A race between threads that only
compute, inside one slice, needs denser scheduling points (`run
--yield-stride N`); see the guide.

What each platform runs today:

| Platform | Runs | Does not run |
|---|---|---|
| Linux x86_64 | Rust, Go and Python programs, and the C code they link. | |
| Linux arm64 | Rust and Python programs, and the C code they link. | Go programs. Code that makes system calls without going through the C library is refused. |
| macOS (Apple silicon) | Rust programs, and the C code they link. | Go and Python programs. Refused: code that makes system calls without going through the C library, shared libraries that do I/O, and C++ on the system C++ library. A signal other than one the program raises on itself, and interval timers (`alarm`, `setitimer`), stop the run. |

On macOS Rust and C programs are built plain, without the compute meter
(instrumented builds are Linux-only), so a program that computes without end
stops only at the host-time backstop, an inconclusive timeout.

On macOS heap addresses differ between runs of one seed, so a program that
depends on pointer values can differ too. On Linux the program sees one fixed
kernel, Ubuntu 24.04's 6.8, whatever the host runs.

## Outcomes and exit codes

Every `run`, `test`, `replay` and `campaign` ends in exactly one outcome, which
decides the exit status of `patina`. Your program's own exit status is
reported, never passed through.

| Outcome | Exit | Meaning |
|---|---|---|
| `ok` | 0 | The run finished and nothing was found. |
| `violation` | 1 | An invariant your program declared did not hold (an `always!`, a `violation` verdict). |
| `liveness` | 1 | The program stopped making progress: every thread is blocked, or a watchdog fired. |
| `failure` | 1 | The program exited nonzero: a panic, a failed assertion, its own error status. |
| `crash` | 1 | The program died on a signal: `abort()`, a segmentation fault. |
| `unsupported` | 2 | The program did something Patina does not model. The message names it. |
| `timeout` | 2 | The run did not finish within a bound. Inconclusive. |
| `nondeterministic` | 2 | Two runs that should agree did not. A bug in Patina: please report it. |
| `internal` | 2 | Patina itself failed, or the host killed the run. |
| `vacuous` | 2 | A fault a campaign was asked to inject had nothing to act on. |
| `error` | 2 | The command could not be carried out: a usage error, a failed build, a missing file. |

So the exit status is 0 for clean, 1 for a finding in your program, and 2 when
Patina could not do what was asked, which alone is not evidence of a bug in
your program. `--format json` reports the outcome as `result`, with what
stopped the run as `stop`.

## Where to go next

- [TUTORIAL.md](./TUTORIAL.md): a whole program. Mark a rare path, state an
  invariant, sweep seeds, replay and render the failure.
- [docs/GUIDE.md](./docs/GUIDE.md): every command, fault injection, the SDK,
  recording and replay, and current limits.
- [USAGE-MODES.md](./USAGE-MODES.md): the SDK in Rust, Go and Python.
- `patina --help` and `patina <command> --help`: the flags of your version.
- [VALIDATION.md](./VALIDATION.md), [ARCHITECTURE.md](./ARCHITECTURE.md) and
  [INTENTS.md](./INTENTS.md): what is tested, how Patina works, and why.
- [docs/skills/patina-dst.md](./docs/skills/patina-dst.md) and `llms.txt`: the
  same ground for coding agents.
