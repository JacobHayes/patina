# Patina tutorial: a whole program

The [README](./README.md) found a bug in a library through one test. This
tutorial takes a program with a `main`, marks a rare path in it, states an
invariant, and then finds, replays and renders the failure. It takes about ten
minutes.

You need `patina` on `PATH` ([install it](./README.md#install)), Rust and a C
compiler. The finished project is [examples/ledger](./examples/ledger), and
the output shown here is what these commands print for it on Linux x86_64.

## 1. A program with a rare path

Make a package `ledger` with these four files.

`Cargo.toml`:

```toml
[package]
name = "ledger"
version = "0.1.0"
edition = "2021"

[dependencies]
patina-dst = { git = "https://github.com/JacobHayes/patina", tag = "v0.5.0" }

[dev-dependencies]
patina-dst = { git = "https://github.com/JacobHayes/patina", tag = "v0.5.0", features = ["macros"] }
```

`src/lib.rs`:

```rust
/// Append `entry` to the ledger. Entries arrive in increasing order, and the
/// ledger must keep them that way.
pub fn commit(ledger: &mut Vec<u64>, entry: u64) {
    // A rare path: Patina takes it on seed-chosen runs. In an ordinary build
    // `buggify!` is always false.
    if patina_dst::buggify!("batch-commit") && !ledger.is_empty() {
        let last = ledger.len() - 1;
        ledger.push(entry);
        ledger.swap(last, last + 1); // BUG: the batch path swaps two entries
    } else {
        ledger.push(entry);
    }
    patina_dst::always!(ledger.is_sorted(), "ledger-sorted");
}
```

`src/main.rs`:

```rust
fn main() {
    let mut ledger = Vec::new();
    for entry in 0..8 {
        ledger::commit(&mut ledger, entry);
    }
    println!("ledger: {ledger:?}");
}
```

`tests/sorted.rs` (used in step 7):

```rust
#[patina_dst::test(seeds = 20, buggify)]
fn the_ledger_stays_sorted() {
    let mut ledger = Vec::new();
    for entry in 0..8 {
        ledger::commit(&mut ledger, entry);
    }
}
```

Two SDK macros carry the tutorial.

`buggify!("batch-commit")` is a *fault site*: a place where something rare
may happen. Under Patina it is true on some runs, chosen by the seed. It
stands for the path your tests never take: the retry, the batch, the timeout.

`always!(condition, "ledger-sorted")` is an *invariant*. Under Patina a false
condition ends the run as a `violation` that names the label.

Outside Patina both are inert, so the program ships with them in place:

```text
$ cargo run
ledger: [0, 1, 2, 3, 4, 5, 6, 7]
```

## 2. Build it for Patina

```text
$ patina build . --output ledger-guest
PATINA_BUILD output=ledger-guest
```

`build` compiles the package with Patina's runtime linked underneath it. The
result is the *guest*: the program as Patina runs it. The first build also
compiles the runtime itself, which takes a while and prints Cargo's progress.

## 3. Run seeds until one fails

`run` takes a seed. `--buggify` arms the fault sites; without it they stay
false.

```text
$ patina run ./ledger-guest --seed 0 --buggify
ledger: [0, 1, 2, 3, 4, 5, 6, 7]
```

Add `--verbose` to see what Patina reports about the run: the calls it would
refuse, and, with `--buggify`, a `PATINA_SDK_REPORT` line that counts how often
each site was reached and fired.

On seed 0 the rare path was not taken. Try more seeds, and stop at the first
that fails:

```sh
for seed in 0 1 2 3 4 5 6 7; do
  patina run ./ledger-guest --seed $seed --buggify || break
done
```

Seeds 0 to 4 print the sorted ledger. Seed 5 does not:

```text
PATINA_VERDICT seq=0 kind=violation label="ledger-sorted" detail="src/lib.rs:13"
patina: FINDING in the guest [violation]: violation of "ledger-sorted" src/lib.rs:13 (guest killed by SIGABRT)
patina: reproduce: patina run ./ledger-guest --seed 5 --buggify
```

The run ended as a `violation`, and `patina` exited with status 1. The last
line is the command that gives this exact run again. Which seeds fail depends
on the build, so yours may not be 5.

## 4. Record it, and replay it

`--record` writes the run's *trace*: every decision the simulated world made.

```text
$ patina run ./ledger-guest --seed 5 --buggify --record bug.patina
PATINA_VERDICT seq=0 kind=violation label="ledger-sorted" detail="src/lib.rs:13"
patina: FINDING in the guest [violation]: violation of "ledger-sorted" src/lib.rs:13 (guest killed by SIGABRT)
patina: reproduce: patina replay ./ledger-guest bug.patina
```

`replay` needs no seed and no flags, because the trace holds them. It prints
what the recording printed:

```text
$ patina replay ./ledger-guest bug.patina
PATINA_VERDICT seq=0 kind=violation label="ledger-sorted" detail="src/lib.rs:13"
patina: FINDING in the guest [violation]: violation of "ledger-sorted" src/lib.rs:13 (guest killed by SIGABRT)
patina: reproduce: patina replay ./ledger-guest bug.patina
```

A trace belongs to the guest that recorded it. Replay it against a guest that
differs by one byte, or with another build of `patina`, and the replay is
refused before the program starts. To carry a failure to another machine,
carry the `patina run ... --seed` command instead.

## 5. Look at the trace

`trace info` summarizes a trace. These are some of its lines:

```text
$ patina trace info bug.patina
trace: bug.patina
format_version: 28
fingerprint: patina-native+instrumented+buggify
root_seed: 5
guest_argv: []
timelines: main (1 events)
buggify: {"activation_permille":250,"active_sites":["batch-commit","ledger-sorted"],"cutoff_nanos":300000000000,"fire_permille":250} (per-evaluation firings are re-derived from the seed, not recorded)
next: `patina trace events bug.patina` for the event stream
```

`--render` writes the trace as a page you can open in a browser. It works on
a replay, and on a run with or without `--record`. The command prints what it
printed before, and one more line:

```text
$ patina replay ./ledger-guest bug.patina --render bug.html
PATINA_RENDER output=bug.html
```

This program does little the simulated world can see, so its page is short. A
program with threads, files or sockets gets a lane for each thread, with its
events.

## 6. Let a campaign sweep for you

A *campaign* runs many *generations*. Each generation is one run with its own
seed, and with `--vary buggify` its own odds for the fault sites.

```text
$ patina campaign ./ledger-guest --vary buggify --gens 20 --out-dir ledger-out
PATINA_CAMPAIGN_START artifact=./ledger-guest generations=20 seed_start=0 out=/home/you/ledger/ledger-out
PATINA_CAMPAIGN_GEN generation=0 seed=5133223892554006150 class=violation NOVEL verify=replay:reproduced
PATINA_CAMPAIGN_GEN generation=1 seed=9597900870906850753 class=violation
[... one line for each failing generation ...]
== campaign summary ==
generations=20 failures=16 novel_signatures=1
  class ok                 4
  class violation          16
-- failure signatures --
  [violation] count=16 first_gen=0 seed=5133223892554006150
      signature: violation|verdict kind=violation label=ledger-sorted|
      reproduce: patina replay ./ledger-guest /home/you/ledger/ledger-out/failures/generation-0.patina
      trace:     /home/you/ledger/ledger-out/failures/generation-0.patina
      verify:    replay reproduced
[... coverage reports ...]
PATINA_CAMPAIGN_COMPLETE generations=20 failures=16 novel=1 result=violation attribution=guest
patina: FINDING in the guest [violation]: 16 of 20 generation(s) did not end clean; the signatures above say how
```

Sixteen generations failed, and all sixteen are one bug: the campaign groups
failures by *signature*, here the label of the violated invariant. It replayed
the first one to check that it reproduces, and kept a trace for each under
`ledger-out/failures/`. The `reproduce:` line replays it. The campaign exited
with status 1.

The out-dir holds the campaign's state. Give the same command again and
nothing runs: it reports the same result. Ask for more generations and it
runs only the missing ones:

```text
$ patina campaign ./ledger-guest --vary buggify --gens 40 --out-dir ledger-out
PATINA_CAMPAIGN_RESUME out=/home/you/ledger/ledger-out done=20 target=40 artifact=./ledger-guest sha256=96ac69fce15c6f37b2df320a4abedb04e000842949482dae3f649e5bb2d5f8cc
```

A command for another guest or with other settings is refused: use a new
`--out-dir` for a new campaign.

## 7. Keep it as a test

`tests/sorted.rs` from step 1 runs the same check from plain `cargo test`.
The arguments of `#[patina_dst::test]` are the flags of `patina test`, with
`_` for `-`; a misspelled one does not compile.

`cargo test` fails on the same seed. Among its output:

```text
patina dst test failed: sorted::the_ledger_stays_sorted
patina test: 1 test(s) in 1 target(s); built in 0.5s, ran in 0.6s (12 job(s), seeds 0..20)
  violation             1

violation        ledger --test sorted the_ledger_stays_sorted (seed 5)
    violation of "ledger-sorted" src/lib.rs:13
    rerun:  patina test /home/you/ledger -p ledger --test sorted the_ledger_stays_sorted --exact --seed 5 --fault-all-tests --buggify
    replay: patina replay /home/you/ledger/target/patina/dst/ledger/test/sorted/guest /home/you/ledger/target/patina/dst/ledger/test/sorted/traces/the_ledger_stays_sorted.seed-5.patina

patina: FINDING in the guest [violation]: 1 of 1 did not pass
```

The attribute runs `patina test` for its own test. `patina test --seeds 20`
in the package runs the same check, with the buggify its attribute names, and
every other test beside it fault-free: a test gets only the faults it asks
for. `--fault-all-tests --buggify` would turn buggify on for every test.

Now fix the bug: delete the two lines that take `last` and swap. `cargo test`
passes, and the test stays as a guard: every `cargo test` runs it across 20
seeds.

## 8. Read results from a script

Every command takes `--format json` and then prints one JSON object on one
line. For the failing run, laid out here with most fields left out:

```text
$ patina run ./ledger-guest --seed 5 --buggify --format json
{
    "result": "violation",
    "attribution": "guest",
    "exit_code": 1,
    "seed": 5,
    "guest_exit": {"code": 134, "core": true, "signal": 6, "signal_name": "SIGABRT"},
    "reproduce": "patina run ./ledger-guest --seed 5 --buggify --format json",
    ...
}
```

`result` is the outcome, `attribution` says whose move it is, and `exit_code`
is the status `patina` exits with. The README's
[outcome table](./README.md#outcomes-and-exit-codes) lists every value. A run
that did not end clean also has a `stop` that says what stopped it.

## Where to go next

- Inject faults the program did not mark. `--fs-error-permille 50` fails five
  in a hundred filesystem calls; there are flags for short writes, crashes,
  network drops and delays, and DNS. `patina run --help` lists them, and
  [docs/GUIDE.md](./docs/GUIDE.md) explains them.
- Reduce a campaign failure to the fewest faults that still cause it:
  `patina minimize --generation 0 --out-dir ledger-out`.
- Test a server: put the server and its clients in one test or one `main`. A
  guest runs in a closed world, and it has to finish. See
  [What programs work](./README.md#what-programs-work).
- Go and Python programs: [USAGE-MODES.md](./USAGE-MODES.md).
- A larger example: `testbeds/workq`, a durable work queue tested through
  crashes, network faults and fault sites.
