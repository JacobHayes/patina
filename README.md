# Patina

**Weather your code into a fine protective patina — before production does.**

Patina runs a Linux program many times, each run under a seed that decides thread order, the
clock, randomness, and which disk, network and crash faults the program meets. The same seed
gives the same run, so a bug that shows up once in a thousand runs becomes a seed you can replay
as often as you like. Your program runs unmodified: no rebuild, no special linking, any
language. Patina is experimental; it runs on Linux x86_64 and arm64.

## Install

```sh
curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh
```

This installs one static binary, `~/.local/bin/patina` (`--prefix DIR` for another place), and
runs `patina doctor`, which checks the host and prints the fix for anything missing; its last
line should read `this host can run patina`. Ubuntu 24.04 and later admit the sandbox only with
an AppArmor profile, installed once as root: the installer prints the command and runs it if
you agree. The release's Debian package installs `/usr/bin/patina` with its profile. From a
checkout, with Rust: `cargo install --locked --path crates/patina-cli`.

## First run

Give Patina any program and its arguments after `--`. `examples/quickstart` is a small Rust
program that runs three jobs on threads and checks their results come back in job order.

<!-- transcript first-run
dir: /tmp/patina/examples/quickstart
setup: mkdir -p target/debug && cp "$GUESTS/examples/jobs" target/debug/
skip: 2
-->
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

Now 20 seeds of the version with the bug:

<!-- transcript first-sweep
dir: /tmp/patina/examples/quickstart
exit: 1
-->
```sh
patina sweep --seeds 1..20 -- target/debug/jobs
```

```text
new: failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101   (seed 1: patina replay /tmp/patina/examples/quickstart/patina-out/sweep/seed-1)
sweep: replaying the first seed of 1 finding
sweep: 167.3 KiB kept in /tmp/patina/examples/quickstart/patina-out/sweep
patina sweep: 20 runs, 11 findings in 1 group, 9 ok   (0.5s, 8 jobs)
outcomes: failure 11, ok 9

failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101
  11 of 20 runs   first: seed 1   replayed: identical
  example: panicked at src/main.rs:28:5: assertion `left == right` failed: results out of job order
  rerun:  patina run --seed 1 -- /tmp/patina/examples/quickstart/target/debug/jobs
  replay: patina replay /tmp/patina/examples/quickstart/patina-out/sweep/seed-1
  explain: patina explain /tmp/patina/examples/quickstart/patina-out/sweep/seed-1
```

Each group is one bug: its signature, how many runs hit it, and the lowest seed, already replayed
once with the same result. Its `rerun:` line reproduces it; `patina explain` tells the run as a
story.

## Next

Run `patina guide`. It is the documentation, built into the binary so it always matches the
version you run: the workflow from the first run to a reported finding, then one topic at a
time (`patina guide --list`). The same pages are in [docs/guide](docs/guide/core.md).
[examples/](examples/README.md) has one small program per kind of bug.

For coding agents, `patina skill ~/.agents/skills` (or the skills directory your agent reads)
writes a small skill that tells the agent when to use Patina and to start from `patina guide`.
