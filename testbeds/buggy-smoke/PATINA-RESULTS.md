# buggy-smoke under Patina — results

Rung 1 of the Patina-on-testbeds campaign. This records what actually happens
when the std-pure `buggy-smoke` canary runs under Patina's deterministic runtime
via the native (linked-shim) path, and what it proves about Patina.

- **Host:** macOS 26.5.2, arm64. Date: 2026-07-26.
- **Path exercised:** `cargo patina native-build` (cfg(patina)/cfg(dst) + POSIX
  shim, linked below the guest) then `cargo patina native-run` (deterministic
  runtime driven through the `PATINA_*` env protocol). The guest source is
  unchanged and 100% std-pure.

## Rung gate: Patina must FIND all six planted bugs

The rung passes only when Patina produces a **deterministic failing run**
(`BUG_CAUGHT` / nonzero exit) for **every** `--bug` mode, with the exact
command + seed + trace hash recorded here and reproducible. Every "runs clean
but doesn't catch the bug" state is a Patina gap this campaign must close — not
an acceptable terminal result.

### Bug-finding scorecard — **6 / 6 caught, allowance-free** (2026-07-26, post tasks #10 + #11 + #12)

Reproduce with `./testbeds/buggy-smoke/find-bugs.sh` (exits 0 at 6/6). Every
catch is byte-identical across 3 recorded repeats and **replays exactly**. Runs
need **no** `--allow-unsupported-symbols` — the guest passes the pre-run audit
clean (see the resolved audit note). All six run on a **single `--yield-points`
build** (simplest wiring; verified by task #12): every command is
`cargo patina native-run <yield.patina> …`.

| Bug | Capability | Deterministic failing command → detail | Seed | Trace SHA-256 (16) |
| --- | --- | --- | --- | --- |
| `unlucky-byte` | Seeded entropy | `--seed 21 -- --bug unlucky-byte` → `derived=0x00 stored=0` | 21 | `8bd67c3ea589f8c7` |
| `deadlock` | Scheduler + virtual-clock rescue (#10) | `--seed 0 -- --bug deadlock --iters 64` → `watchdog-timeout` | 0 | `196e4191628d0e25` |
| `no-fsync` | CrashFs durability (#11) | `--fs-crash-at close:1 --seed 0 -- --bug no-fsync --iters 32` → `lost-durable-records committed=0 expected=32` | 0 | `8334e51a0cd6e725` |
| `tight-deadline` | Clock latency (#11) | `--sleep-jitter-nanos 8000000..12000000 --seed 0 -- --bug tight-deadline --iters 10` → `elapsed-ms=155 budget-ms=100` | 0 | `328b33fe1ffd0af9` |
| `udp-order` | SimNet reorder + deterministic recv timeout (#11) | `--net-jitter-nanos 0..1000000 --seed 0 -- --bug udp-order --iters 64` → `out-of-order got=16 want=0` | 0 | `ef547b347b2907cd` |
| `lost-update` | Deterministic preemption of an atomics-only RMW race (#12) | `--seed 0 -- --bug lost-update --iters 2` → `lost=1 expected=4` | 0 | `7c463dcd40a50422` |

All six are deterministic (byte-identical across 3 repeats) and replay to the
identical `BUG_CAUGHT`/exit under `replay`. `lost-update` trips at **every**
seed 0..40; seed 3 gives `697d8d49c967127d` (the coordinator's independent record).

**Single-build policy + a finding.** All six run on one `--yield-points` build;
`find-bugs.sh` **sweeps** each bug for its first catching seed rather than
hardcoding, because the basic-block yield instrumentation **reshapes the schedule
space** — e.g. `deadlock` catches at **seed 0** here but at **seed 1** on the
plain build (seed 1 is CLEAN under instrumentation). That seed shift is expected
evidence that the yield points change which interleavings are explored. The build
prints its provenance line:

```
PATINA_NATIVE_BUILD_YIELD_POINTS instrumentation=llvm-sancov-trace-pc-guard scheduler-hook=patina_sched_yield fingerprint-suffix=+yieldpoints
```

`--yield-points` uses stable `-C` sancov flags (**no `RUSTC_BOOTSTRAP`**) and the
native (non-Patina) path is unaffected. The `+yieldpoints` trace fingerprint
suffix means these traces **never cross-replay against a plain binary** — I
verified both directions fail closed (exit 2, aborts), matching the
`native_yield_points_trace_fails_closed_against_plain_binary` test. All hashes
here therefore differ from the earlier plain-build era (e.g. `unlucky-byte`
`8bd67c3e…` vs plain `e2e2bf52…`; `no-fsync` also changed once when `temp_dir`
became interposed — see audit note). `run-patina.sh` deliberately keeps the
**plain** build to exercise the clean-mode behavior and the vacuous-schedule
diagnostic.

**Audit note (task #10) — RESOLVED.** Earlier this guest was refused by the
pre-run default-deny audit for three uninterposed symbols; both halves are now
fixed and **no allowance is needed**:

- `__NSGetArgc` / `__NSGetArgv` (startup argv accessors, `std::env::args`) are
  **known-safe-listed** — they are read-once, non-blocking, no time/scheduling.
- `_confstr` (`env::temp_dir()` → `_CS_DARWIN_USER_TEMP_DIR`) is now
  **interposed**, so `temp_dir` is virtual and deterministic across hosts. This
  is why `no-fsync`'s trace hash changed.

Determinism is now **unqualified**: byte-identical traces with zero allowances.

**`lost-update` — escalation RESOLVED by task #12 (deterministic preemption).**
The root cause I escalated: the cooperative DetScheduler only switches at
*interposed* boundaries, but std `RwLock`'s read/write **fast path is
atomics-only** (no shim call → no boundary), and workers never contend (each runs
its whole loop to completion before the next starts), so the read-modify-write
window `read()→drop→write()` had **zero reachable interleavings** at any seed
(~580 seeds tried, incl. `--stress`, pre- and post-Parker). Task #12 closes it
two ways:

1. **Reachability** — the `--yield-points` build inserts basic-block yield points,
   making the atomics-only window schedulable; the race now trips deterministically
   (`lost=1 expected=4`) at every seed.
2. **Detection (default-on)** — multi-task runs emit a `PATINA_SCHEDULE_REPORT`
   on stderr, and the *plain* `lost-update` build now prints a **vacuous schedule
   exploration** warning and stays CLEAN:

   ```
   PATINA_SCHEDULE_REPORT tasks_spawned=3 max_concurrent=3 total_boundaries=20 vacuous_threads=2 ...
   PATINA WARNING: vacuous schedule exploration — 2 spawned thread(s) ... ran to
   completion with no more scheduling boundaries than thread spawn/join alone ...
   their internal interleavings are UNREACHABLE at any seed and a clean result here
   does NOT mean the concurrency was tested. Rebuild with `--yield-points` ...
   ```

   So a "clean" multithreaded run can no longer silently mean "nothing was
   explorable" — exactly the false-confidence failure the canary exists to catch.

## What is verified

- **Bug-finding: 6/6** deterministic catches, allowance-free (table above);
  `find-bugs.sh` exits 0.
- **Determinism**: every catch byte-identical across 3 repeats (hashes above);
  the earlier seed-sweep determinism table below still holds for the non-failing
  schedules.
- **Replay**: all six catches replay to the identical outcome; a `--` section
  that does not match the recorded guest arguments is rejected up front
  (`guest-argument mismatch`), naming both argv lists.
- **Perf**: measured, incl. the instrumented (`--yield-points`) vs plain cost for
  `lost-update` (see Performance).
- **No Patina crates modified by this rung** — the fixes are tasks #10/#11/#12.
  `run-patina.sh` (regression, allowance-free, green) and `find-bugs.sh` (the
  6/6 gate) are the self-checking scripts.

## Reproducing

All commands assume the Patina workspace root and a release `cargo-patina`.

```sh
cd /Users/jacobhayes/src/github.com/JacobHayes/patina
cargo build --release -p cargo-patina          # embeds the shim C
PATINA=target/release/cargo-patina

# One instrumented guest catches all six (shim staticlib builds from inside the
# workspace). No run-time allowance needed -- it passes the pre-run audit clean.
"$PATINA" patina native-build testbeds/buggy-smoke --output /tmp/bs-yield.patina --release --yield-points
BIN=/tmp/bs-yield.patina

"$PATINA" patina native-run "$BIN" --seed 21 -- --bug unlucky-byte                                    # trips
"$PATINA" patina native-run "$BIN" --seed 0  -- --bug deadlock --iters 64                             # trips
"$PATINA" patina native-run "$BIN" --fs-crash-at close:1 --seed 0 -- --bug no-fsync --iters 32        # trips
"$PATINA" patina native-run "$BIN" --sleep-jitter-nanos 8000000..12000000 --seed 0 -- --bug tight-deadline --iters 10   # trips
"$PATINA" patina native-run "$BIN" --net-jitter-nanos 0..1000000 --seed 0 -- --bug udp-order --iters 64                 # trips
"$PATINA" patina native-run "$BIN" --seed 0  -- --bug lost-update --iters 2                           # trips (lost=1 expected=4)

# The plain build (drop --yield-points) is what run-patina.sh uses for the
# clean-mode / determinism / replay checks and the vacuous-schedule diagnostic.
```

The whole rung is automated and self-checking:

```sh
./testbeds/buggy-smoke/find-bugs.sh       # the 6/6 bug-finding gate; exits 0 at 6/6
./testbeds/buggy-smoke/run-patina.sh      # clean/determinism/replay regression; exits nonzero on any regression
```

## Per-mode outcomes: native vs Patina

| Mode | Native (baseline) | Patina @ seed 1 | Patina swept | Verdict |
| --- | --- | --- | --- | --- |
| `lost-update` | EITHER; trips reliably under `--stress` | `CLEAN` | `CLEAN` at **every** seed 0..200 (`--iters 100`), seeds 1..8 `--stress`, seeds 1..8 `--iters 5` — never trips | Runs clean+deterministic; **bug not surfaced** (soundness gap, below) |
| `deadlock` | `CLEAN` within watchdog | **HANGS** | — | **Does not run** (structural Parker bug, below) |
| `no-fsync` | `CLEAN` | `CLEAN` | deterministic | Runs clean+deterministic; not *triggerable* (no CrashFs knobs — expected) |
| `tight-deadline` | `CLEAN` | `CLEAN` | deterministic | Runs clean+deterministic; not *triggerable* (no clock-latency knob — expected) |
| `udp-order` | `CLEAN` | **ERROR** `timeout-setup-failed=...(os error 42)` | — | **Does not run clean** (fail-closed `SO_RCVTIMEO`, below) |
| `unlucky-byte` | EITHER (1/256; native first hit seed 15) | `CLEAN` | **TRIPS at seed 21**: `BUG_CAUGHT ... derived=0x00 stored=0` | **Caught by Patina** (seeded entropy) ✅ |

Commands behind the table:

```sh
# per-mode at seed 1
for m in "no-fsync --iters 32" "tight-deadline --iters 10" "udp-order --iters 64" \
         "deadlock --iters 64" "lost-update --iters 100" "unlucky-byte"; do
  "$PATINA" patina native-run "$BIN" --seed 1 -- --bug $m
done
# unlucky-byte sweep — first tripping seed
for s in $(seq 0 300); do
  "$PATINA" patina native-run "$BIN" --seed $s -- --bug unlucky-byte >/dev/null 2>&1 \
    || { echo "trip at $s"; break; }
done
# lost-update never trips under Patina (checked 0..200, --stress, tiny iters)
for s in $(seq 0 200); do
  "$PATINA" patina native-run "$BIN" --seed $s -- --bug lost-update --iters 100 >/dev/null 2>&1 \
    || echo "trip at $s"
done
```

## Determinism

Each invocation was recorded 3× with `--record`; the SHA-256 of the trace file
and the captured stdout/stderr + exit code were compared across the 3 repeats.
**Every case: byte-identical traces, identical output.** Trace hashes also
differ across seeds, confirming the seed genuinely drives execution (not
vacuous). stderr is deterministic too — `no-fsync`'s `db-path=` line pins to
`buggy-smoke-wal-1` because the pid is virtualized to 1.

Command:

```sh
for i in 1 2 3; do
  "$PATINA" patina native-run "$BIN" --record /tmp/t_$i.patina --seed 1 -- --bug unlucky-byte
done
shasum -a 256 /tmp/t_1.patina /tmp/t_2.patina /tmp/t_3.patina   # three identical hashes
```

Trace SHA-256 (repeat #1; #1==#2==#3 verified for all):

| Mode | Seed | Trace SHA-256 |
| --- | --- | --- |
| unlucky-byte | 1 | `7c78287c4520c1d65905404a7302af205fc388883ae4f37f7464bbb3ce9c911c` |
| unlucky-byte | 2 | `ac363165de0306bcd7f120a99dce70bbeef9309528abcc42846f85353bf9f705` |
| unlucky-byte | 3 | `eb8841df7365b823c2361715ddf73506749529eb8ab6d0c5f865798f9430c84c` |
| unlucky-byte | 4 | `183634e02a5cc98dcdaaa3a2eef499ff6600d26b9071a43f4ae2661c81f969fb` |
| unlucky-byte | 5 | `bab5af5283c2b3840450e1a395ce1254d91f2ecacaa36afe9c8497f326e22363` |
| lost-update (`--iters 100`) | 1 | `43abd95dbd35f2a5b380488fae95ad1a770f7fd7a34ac1cada10df67185f7f61` |
| lost-update (`--iters 100`) | 2 | `ffd588f78dd4cbabff5cea3a9a450e570bf3af384207f7f0f48b1c976ec71965` |
| lost-update (`--iters 100`) | 3 | `276f698e2d5913f591d11d36ff29cfe4b5755d8c50d8d280a27913ae64f13bb3` |
| lost-update (`--iters 100`) | 4 | `4801440738b041ad0b2692fad89eeff04bd2e7a102c86974a64ec512a5883d74` |
| lost-update (`--iters 100`) | 5 | `5e3ac3f680224501938a665bf4222bb3d128cf3533aed2e3ed9bf7bccbcb9abe` |
| no-fsync (`--iters 32`) | 1 | `17fbd1c27ac365d09abf8db1a5a9d9eba7da5f3327cc2b1bb73aaf4d9f85bef7` |
| tight-deadline (`--iters 10`) | 1 | `c9833d31859dea058fd6e00d247011c5a3377bbd1059aaed25553af569d49010` |
| unlucky-byte (**trip**) | 21 | `e2e2bf52ff380794c4a06056ebafb222da32f9a57eb931e576c85703e77fd6c8` |

## Replay

```sh
# Record a trip, then strictly replay it (replay restores the seed AND the
# guest arguments from the trace, so no `--` section is re-passed).
"$PATINA" patina native-run "$BIN" --record /tmp/trip.patina --seed 21 -- --bug unlucky-byte
"$PATINA" patina replay "$BIN" /tmp/trip.patina
```

- Record: `BUG_CAUGHT bug=unlucky-byte detail=derived=0x00 stored=0` (exit 1).
- Replay: **identical** stdout and exit code.
- CLEAN traces replay CLEAN as well.
- **Strictness (negative control):** replaying the trip trace against different
  program args is rejected —
  `patina native shim fatal: trace operation mismatch at 0: expected EntropyFill { len: 16 }, got TaskSpawn { label: "main" }` (nonzero exit).
  So replay is genuinely strict, not a no-op.

## Performance (native binary vs same source under Patina)

Wall time, release builds, warm-up run discarded, median of 5. "native" is
`testbeds/buggy-smoke/target/release/buggy-smoke`; "patina" is
`cargo patina native-run buggy-smoke.patina` (both are direct binary execs — no
`cargo` in the hot path). Timed with `time.perf_counter()` around
`subprocess.run`.

| Workload | Native median | Patina median | Ratio (patina/native) |
| --- | --- | --- | --- |
| `lost-update --iters 1000000` (2 threads) | 0.0303 s | 0.0153 s | **0.5×** |
| `no-fsync --iters 50000` (FS-heavy) | 0.0500 s | 0.0085 s | **0.2×** |
| `tight-deadline --iters 40` (real 40×5 ms sleeps) | 0.2929 s | 0.0070 s | **0.02×** |

Patina is at parity-or-faster on these workloads, which is expected and
informative rather than a low-overhead claim: it **serializes** real threads
(removing cross-core contention/join cost that dominates `lost-update`),
replaces real disk I/O with the **in-memory FS** (`no-fsync`), and advances a
**virtual clock** so paced `thread::sleep`s cost nothing (`tight-deadline`,
~42× faster). None of these workloads is dominated by per-boundary-op
interposition overhead, so they don't isolate it; a raw-syscall microbench would
be needed to measure that and is out of scope for this rung.

**Instrumentation cost — `--yield-points` vs plain, scaled by work (campaign cost
model).** `lost-update --iters N` (2 threads), median of 5, same source; patina
plain build vs `--yield-points` build:

| `--iters` | plain (s) | `--yield-points` (s) | yield / plain |
| --- | --- | --- | --- |
| 10 | 0.0048 | 0.0045 | **0.9×** |
| 100 | 0.0046 | 0.0071 | 1.5× |
| 1000 | 0.0043 | 0.0314 | 7.2× |
| 10000 | 0.0046 | 0.2679 | 58.9× |

The instrumentation is **near-parity at tiny workloads** (both are process-startup
bound) and its cost **grows with instrumented work** — the plain time stays flat
(~5 ms startup) while the yield-points time scales roughly linearly with basic
blocks executed (0.031 s → 0.268 s from 1k→10k iters, ~8.5×/decade). So the ratio
inflates mainly because the plain baseline is startup-dominated. Practical read
for the campaign: reserve `--yield-points` for the data-race hunt on
short/bounded workloads; the plain build catches the scheduler/crash/latency/net/
entropy bugs cheaply and *flags* vacuous concurrency for everything else. (A prior
three-way point at `--iters 1000000`: native 0.0019 s / plain 0.0042 s / no
instrumented run — that size is impractical under `--yield-points`.)

## Patina changes made

**None by this rung.** No files under `crates/` were modified here. The five bugs
that did not initially catch were diagnosed and escalated, not hacked around; the
fixes landed as tasks **#10** (Parker interpose + pre-run audit + argv known-safe
/ `confstr` interpose), **#11** (CrashFs / clock-jitter / net reorder-drop /
`SO_RCVTIMEO` knobs), and **#12** (`--yield-points` preemption + vacuous-schedule
detector). Testbed-only edits by this rung:

- `testbeds/buggy-smoke/find-bugs.sh` — the 6/6 bug-finding gate (two builds,
  allowance-free; exits 0 at 6/6).
- `testbeds/buggy-smoke/run-patina.sh` — clean/determinism/replay regression
  script (allowance-free; exits nonzero on any regression).
- `testbeds/buggy-smoke/PATINA-RESULTS.md` — this file.

## Issues found — all RESOLVED (historical diagnosis below)

> The three issues below were the original diagnosis that drove the fixes. All
> are now **resolved** — see the scorecard: `deadlock` (task #10), `udp-order`
> (task #11), `lost-update` (task #12). The specs in the following section were
> consumed by those tasks. Kept for provenance.

### 1. `deadlock` hangs — macOS thread Parker (`park_timeout`) is not interposed (STRUCTURAL)

The `deadlock` mode hangs forever under Patina (CPU idle — genuinely parked, not
spinning: ~9M cycles then quiescent). Stack sample of the hung guest:

- **main** → `mpmc::recv_timeout` → `std::thread::Thread::park_timeout` →
  `_dispatch_semaphore_wait_slow` → **`semaphore_timedwait_trap`** — a *real*
  host dispatch-semaphore timed wait, **not** routed through the shim.
- **worker A / worker B** → `patina_mutex_lock`/`patina_mutex_unlock` →
  `switch_and_park` — correctly interposed and genuinely deadlocked in the
  planted AB/BA lock-order inversion.

Root cause: the shim interposes pthread mutex/cond and (Linux) futex, but std's
thread **Parker** on macOS is backed by a `dispatch_semaphore`
(`park`/`park_timeout`/`unpark`), which the shim does not intercept —
`crates/patina-native-shim/c/patina_posix.c` has no `dispatch_semaphore_*`
interposition, and the shim itself *uses* dispatch semaphores for its own baton
(`crates/patina-native-shim/src/lib.rs:1807`+). So any guest that blocks via the
thread Parker — notably `std::sync::mpsc`/`mpmc` `recv`/`recv_timeout` — escapes
both the scheduler and the virtual clock. The main thread never yields the
scheduler baton, so the deadlock-rescue path
(`crates/patina-runtime/src/lib.rs:1255`) never sees an all-parked state and its
virtual deadline never fires; because the virtual clock is frozen, the "5s"
timeout re-parks on the real clock indefinitely.

Minimal std-pure repro (no mutexes, no deadlock — just a channel timeout):

```sh
cat > /tmp/park_repro.rs <<'EOF'
use std::sync::mpsc;
use std::time::{Duration, Instant};
fn main() {
    let (_tx, rx) = mpsc::channel::<()>();
    let start = Instant::now();
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => println!("GOT-MSG"),
        Err(_) => println!("TIMED-OUT after virtual {:?}", start.elapsed()),
    }
}
EOF
"$PATINA" patina native-build /tmp/park_repro.rs --output /tmp/park_repro.patina --release
timeout 8 "$PATINA" patina native-run /tmp/park_repro.patina --seed 1   # HANGS (should print TIMED-OUT instantly)
```

Expected under a correct virtual clock: `recv_timeout` expires at the virtual
deadline and prints `TIMED-OUT` immediately. Fixing this means interposing the
macOS Parker (distinguishing guest Parker semaphores from the shim's own baton
semaphores) and routing timed park through `task_park_timed`. That is a
structural shim change, left to the owner of that work (tracked separately as
the "macOS Parker escape" task).

### 2. `udp-order` errors at `set_read_timeout` — SimNet socket timeouts are fail-closed (POLICY / missing knob)

`UdpSocket::set_read_timeout(Some(2s))` lowers to `setsockopt(SO_RCVTIMEO)` with
a nonzero timeval, which the shim rejects with `ENOPROTOOPT` (os error 42) —
`crates/patina-native-shim/c/patina_posix.c:1466` only accepts a *zero* timeval;
nonzero socket timeouts are deliberately fail-closed (documented at
`crates/patina-native-shim/src/lib.rs:2559`). So the guest reports
`BUG_CAUGHT ... timeout-setup-failed=...` and never reaches the reorder/drop
assertion. This is not a crash and not the planted bug — it's an unsupported
operation. Triggering the real `udp-order` bug would need (a) virtual-clock-backed
`SO_RCVTIMEO` acceptance in the shim + a SimNet receive-timeout, and (b) a SimNet
reorder/drop fault surface reachable from a std-pure guest (a `native-run` fault
knob or explicit-Context topology). Left as a noted gap, not implemented.

### 3. `lost-update` never reproduces — atomics-only RMW window is unschedulable (SOUNDNESS GAP)

`lost-update` runs CLEAN under Patina at **every** seed and parameterization
tested (seeds 0..200 at `--iters 100`; seeds 1..8 under `--stress` with 8
threads; seeds 1..8 at `--iters 5`), even though `--stress` trips *reliably*
natively. Root cause: the bug's race window is between dropping the read lock and
taking the write lock, but std `RwLock`'s uncontended path is **atomics-only** —
the shim's `pthread_rwlock_*` are `ENOSYS` stubs
(`crates/patina-native-shim/c/patina_posix.c:1216`+) and go unused, confirming
std never calls them (the guest would panic on `ENOSYS` otherwise; it doesn't).
With no interposed boundary inside the read-modify-write, and a **cooperative**
scheduler that only interleaves at interposed boundaries, each increment runs
atomically and threads serialize. Not a crash — clean and deterministic — but
the bug is not caught.

**Confirmed toolchain call chain (rustc 1.96.0, aarch64-apple-darwin).** `nm` on
the stress binary shows std's **queue-based** `RwLock`
(`std::sys::sync::rwlock::queue::RwLock::{lock_contended, unlock_contended,
read_unlock_contended}`) and the **darwin `Parker`**
(`std::sys::sync::thread_parking::darwin::Parker`) whose backing symbols are the
three undefined `_dispatch_semaphore_{create,wait,signal}`. So the *uncontended*
read/write path is atomics-only (no boundary), but the **contended** write
acquire is `RwLock::write() → lock_contended → thread::park (darwin Parker) →
dispatch_semaphore_wait` — the **same** Parker path task #10 is interposing.

**Therefore this is NOT a permanent soundness gap — it is blocked on task #10.**
Under `--stress` (8 threads) the write lock is heavily contended, so post-fix the
`lock_contended` park becomes a visible deterministic scheduling boundary sitting
*after* a thread has read `current` and dropped its read guard. A schedule that
switches at that boundary lets a second thread read the same `current` before the
first writes — the classic lost update. Plan once #10 lands: sweep seeds (and/or
`explore`) under `--stress` until a schedule trips `BUG_CAUGHT lost=... expected=...`,
then record the deterministic failing command + trace hash here. If it is *still*
unreachable post-fix (e.g. the window contains genuinely zero interposed
boundaries at some thread count), escalate with the exact window and the minimal
scheduler capability needed (seed-driven yield injection at existing boundaries
vs. instrumented-std preemption) as a blocking task.

---

## Specs for the blocked bugs (handed to tasks #10 / #11)

These are the precise surfaces the two implementation agents need. This rung does
not implement them (task #10 owns `crates/patina-native-shim` + the audit; task
#11 owns the experiment-plane fault knobs); it consumes them for verification.

### `udp-order` — **branch 3 (spec)**: deterministic recv timeout + reorder/drop

Not soundness-blocked. The building blocks already exist:
`patina-net-sim` exposes `recv(socket, now) -> Option<Datagram>` and
`next_delivery(socket, now) -> Option<u64>` (earliest future arrival), and the
shim's `patina_net_recvfrom` (`crates/patina-native-shim/src/lib.rs:3172`)
already timed-parks a blocking receive via
`block_timed(me, "net-recv", Monotonic, next_delivery_deadline)` with the
existing virtual-clock timer queue and `mark_timed_out` path.

1. **`setsockopt(SO_RCVTIMEO)`** (`patina_posix.c:1466`): store a nonzero timeout
   on the socket instead of returning `ENOPROTOOPT`. (Also `SO_SNDTIMEO` → no-op
   accept; TCP not required this round.)
2. **`recvfrom`**: park until `min(next_delivery, recv_deadline)` where
   `recv_deadline = park_entry_now + read_timeout`. If the read-timeout deadline
   is reached first, return `EAGAIN`/`EWOULDBLOCK` (std maps to
   `WouldBlock`/`TimedOut`, which `udp-order` reports as `drop-or-timeout`).
   **Tie-break (deterministic):** at equal virtual timestamps, **delivery wins** —
   a datagram deliverable exactly at the deadline is returned, not a timeout.
3. **Reorder/drop:** wrap SimNet in `patina-wrapper-latency` `LatencyNet`
   (seeded `jitter_nanos` already reorders — see its
   `seeded_jitter_repeats_and_can_reorder_packets` test) and/or
   `patina-wrapper-fault` `FaultNet` (`drop_one_in`), selected by new env knobs
   read in `init_from_env`.
4. **Trace:** the recv outcome (delivered datagram vs timeout) must be a recorded
   op so replay is exact.
5. **Test:** (a) same virtual-instant timeout across runs; (b) a planted case
   where the timeout path actually fires (non-vacuous).

Findable once landed: a seed where reorder delivers seq out of order →
`BUG_CAUGHT out-of-order got=... want=...`, or drop → `drop-or-timeout`.

### `no-fsync` — CrashFs is wired; a crash **trigger** is missing

`CrashFs::default()` is already the native FS driver
(`crates/patina-native-shim/src/lib.rs:568`, `torn_write_probability = 1.0`), and
the runtime exposes `Context::fs_crash()` → `Operation::FsCrash` →
`filesystem.crash()` (`crates/patina-runtime/src/lib.rs:1073`). The gap: a
std-pure guest that writes-without-fsync, closes the file, then reopens+verifies
**in the same process** never calls `fs_crash()`, so the reopen sees the live
(complete) image → CLEAN. Needed: a **crash-injection trigger** reachable from
env, e.g. `PATINA_FS_CRASH_ON_CLOSE=1` (fire `crash()` when a file with unsynced
writes is closed) or `PATINA_FS_CRASH_AT_OP=<n>` (fire after the nth fs op).
Since the records were never fsynced, the injected `crash()` drops them and the
inline `verify_db` sees `BUG_CAUGHT lost-durable-records committed=k expected=n`.
Test: same crash point + torn set across runs; non-vacuous (a synced control
stays CLEAN).

### `tight-deadline` — needs a **new** clock-latency capability (none exists)

Confirmed: there is no clock latency/jitter wrapper anywhere in `crates/`
(`patina-wrapper-latency` is network-only). `ClockDriver` is tiny
(`now`, `sleep_until` — `crates/patina-driver-api/src/lib.rs:95`). Needed: a
`LatencyClock<D>` wrapper (or a `VirtualClock` option) that, on each
`sleep_until`, advances the monotonic deadline by an extra **seeded** amount
(`PATINA_CLOCK_JITTER_NANOS` / per-sleep jitter). With ~1ms extra per 5ms paced
step, 10 steps overrun the 2× budget so the guest's `elapsed <= budget` assertion
trips → `BUG_CAUGHT elapsed-ms=... budget-ms=...`. Wire the wrapper in
`init_from_env` behind the env knob. Test: deterministic elapsed across runs;
non-vacuous (zero jitter stays CLEAN, matching today).
