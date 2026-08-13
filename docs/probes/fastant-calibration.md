# fastant calibrating-guest demo — report

> **Status: resolved (2026-08-13).** All three consequences below were acted on
> by the advance-on-spin slice (`IMPLEMENTATION.md` slice 9, `docs/DECISIONS.md`,
> `ARCHITECTURE.md` "Virtual time"). The wedge is gone: the UNPATCHED fastant
> guest now runs to completion in about a second on x86-64 Linux and derives
> exactly 1 GHz, so the leg-3 numbers below — obtained by hand-patching the
> vendored crate — are reproducible without the patch. Consequence (1) is
> answered by advance-on-spin plus the frozen-clock churn abort rather than by a
> watchdog arm; (2) by flushing a truncated-but-valid trace before a
> runtime-initiated stop; (3) by rewording the audit and gate notes. Everything
> below is preserved as the original finding, and the "Runnable on x86-64 Linux"
> quotes are the OLD wording it argued against.
>
> One thing here is still open: the **secondary finding** on `CPUID` (unaudited,
> untrapped host read) is untouched.

Report-only. No repo changes, no git/jj state changes. All execution in two
Tensorlake x86-64 Linux sandboxes, both terminated (proof at the end).

- patina tree: **026269f** (`custom-ops: value typing decided`), the tip of the
  team-lead working copy's `main`. Release `cargo-patina` rebuilt in both
  sandboxes.
- Guest dependency: **fastant 0.1.11** (checksum `2e825441bfb2d831…`), vendored
  from the host with `cargo vendor` and copied in; no sandbox egress needed.
- Sandbox A `0rn7cqu5mdiynxrrfg13o` (from base snapshot `omw1e61sbliouitngmkqh`)
  — the standalone fastant guest.
- Sandbox B `db69vpqrwzkcsix3mpspj` (from SlateDB snapshot `ywnndioh9vk1kka0j5hty`)
  — the bonus SlateDB/foyer leg.

---

## Headline

**The 1 GHz mapping is exactly right, and a real calibrating guest cannot reach
it.** When calibration is allowed to run, fastant derives *exactly* 1 GHz,
`nanos_per_cycle` is *exactly* 1.0, and a 5 ms virtual sleep reads back as
exactly 5,000,000 ns — the design intent confirmed to the digit. But fastant's
calibration is a **busy-wait on wall-clock progress inside a pre-main
constructor**, and under virtual time that loop never terminates. Both the
standalone guest and the real SlateDB corpus with `foyer` wedge in the same
seven-frame stack, before `main`, at 100% CPU.

The audit says this guest is fine. The run never starts. That gap is the
finding.

---

## Leg-by-leg verdicts

| Leg | Verdict |
|---|---|
| 1. Build a fastant guest | PASS — builds and runs natively; real host calibration derives 2.4005 GHz |
| 2. Audit → TSC-trap-managed, exit 0 | **PASS** — 2 sites, exit 0 |
| 3a. Same-seed double runs byte-identical | **PASS** (3/3 identical, incl. printed elapsed values) |
| 3b. Calibration derives ~exactly 1 GHz | **PASS — exactly, zero error** |
| 3c. record → replay identity | **PASS** (byte-identical, plain and jittered) |
| 3d. Seed variation under sleep jitter | **PASS** (3 seeds differ; each reproducible) |
| 4. Calibration wedges under virtual time | **REAL FINDING — CONFIRMED**, characterized below |
| 5. Bonus: SlateDB + foyer audit | **PASS — exit 0**, single fastant site TSC-trap-managed |

Legs 3a–3d required getting past the wedge; see "How legs 3a–3d were obtained".

---

## Leg 1 — baseline (no patina), sandbox A

```
fastant::is_tsc_available = true
fastant anchor offset at start = 20089733ns
w1: requested=5000000ns fastant=5107508ns std=5108449ns rdtsc_delta=12260836
w1: derived nanos_per_cycle=0.416570941818323 cycles_per_second=2400551501.828289
w2: requested=1000000ns fastant=1060271ns std=1060382ns rdtsc_delta=2545152
w2: derived nanos_per_cycle=0.4165845497636291 cycles_per_second=2400473086.5976715
w3: requested=250000ns fastant=310696ns std=310749ns rdtsc_delta=745976
w3: derived nanos_per_cycle=0.4164959730607955 cycles_per_second=2400983598.1151996
total fastant elapsed = 6503906ns
as_unix_nanos(now) = 1786601467502613483
```

Real calibration on the host: ~2.4005 GHz, jitter in the sixth significant
figure, host Unix epoch. The 20 ms anchor offset is the calibration cost — two
outer iterations of a ≥10 ms measurement window.

## Leg 2 — audit, sandbox A

`cargo patina audit ./Cargo.toml` → **exit 0**:

```
cpu-nondeterminism (TSC-trap-managed, 2 sites): inline rdtsc/rdtscp answered from
the run's virtual clock via prctl(PR_SET_TSC). Runnable on x86-64 Linux; refused
everywhere else (macOS, arm64) — rebuild the guest without the inline counter read
for those.
  instruction@.text+0xa30    provenance=crate=fastant-demo …__rdtsc…fastant_demo
  instruction@.text+0x5650   provenance=crate=fastant     …__rdtsc…fastant
```

Two sites — the demo's own probe read and fastant's. Both downgraded from
refusal to managed, exactly as the slice intends. The per-finding provenance
correctly attributes the second to the `fastant` crate.

---

## Leg 4 — THE FINDING: calibration wedges before `main`

`cargo patina run ./Cargo.toml --seed 1` never produces a line of guest output.
Killed at 90 s (`rc=124`), guest process `patina-guest` pegged at **99.8% CPU**.
gdb attach, sandbox A:

```
Program received signal SIGSEGV, Segmentation fault.
core::core_arch::x86::rdtsc::_rdtsc () at …/core_arch/src/x86/rdtsc.rs:26
#0  core::core_arch::x86::rdtsc::_rdtsc ()
#1  fastant::tsc_now::tsc ()                     at src/tsc_now.rs:202
#2  fastant::tsc_now::monotonic_with_tsc ()      at src/tsc_now.rs:192
#3  fastant::tsc_now::_cycles_per_sec ()         at src/tsc_now.rs:169
#4  fastant::tsc_now::cycles_per_sec (anchor=…)  at src/tsc_now.rs:151
#5  fastant::tsc_now::TSCLevel::get ()           at src/tsc_now.rs:74
#6  fastant::tsc_now::init ()                    at src/tsc_now.rs:26
#7  fastant::tsc_now::___init___ctor::___init___ctor () at src/tsc_now.rs:24
#8  call_init (…) at ../csu/libc-start.c:145
#9  __libc_start_main_impl (main=… <patina_main_wrapper>, …)
#11 _start ()
```

### Where it spins, and what it waits on

`fastant-0.1.11/src/tsc_now.rs:160-184`:

```rust
loop {
    let (t1, tsc1) = monotonic_with_tsc();
    loop {
        let (t2, tsc2) = monotonic_with_tsc();   // 169  ← the spin
        last_monotonic = t2;
        last_tsc = tsc2;
        let elapsed_nanos = (t2 - t1).as_nanos();
        if elapsed_nanos > 10_000_000 {          // 173  ← the exit condition
            cycles_per_sec = (tsc2 - tsc1) as f64 * 1e9 / elapsed_nanos as f64;
            break;
        }
    }
    …
}
```

The inner loop waits for **10 ms of monotonic-clock progress** and does nothing
to cause it — no `sleep`, no `yield`, no syscall that blocks. Under patina the
virtual monotonic clock advances only when the runtime advances it, so
`elapsed_nanos` is 0 on every iteration and the exit condition is unreachable.
Each iteration issues two `ClockNow` boundary ops (one `Instant::now()`, one
trapped `rdtsc`), so the loop is pure churn at frozen virtual time.

This is *correct* patina behavior — it is the documented parity property in
`crates/patina-native-shim/src/tsc.rs` ("a guest spin-waiting on `rdtsc` deltas
without yielding hangs exactly as one spinning on `Instant::now` deltas does").
The finding is not that the model is wrong; it is that this shape is common in
exactly the crates a DST user wants to instrument, and it is invisible to every
detector patina currently has.

### Three consequences worth acting on

**(1) The liveness watchdog structurally cannot fire here.** The watchdog
accumulates a no-progress window measured *in virtual nanoseconds*
(`crates/patina-runtime/src/lib.rs`, `operation_is_progress` — `ClockNow` counts
as non-progress, and the doc says it catches a run that "only spins on
timers/parks *while virtual time marches on*"). Here virtual time does not march
on, so the window never grows. Verified, not inferred:

```
cargo patina run ./Cargo.toml --seed 1 --liveness-watchdog=1000000
→ still running at 60 s, rc=124
```

A 1 ms virtual budget did not fire against a 60-second hang. A frozen-clock
churn arm — *N consecutive non-progress ops with zero virtual-time advance* —
would catch this class and cannot be expressed with the current virtual-time
window.

**(2) `--budget` is today's only backstop, and it is loud and correct.**

```
cargo patina run ./Cargo.toml --seed 1 --budget 200000
→ patina: step budget of 200000 boundary operations was exhausted; the run is stopped
  PATINA_INFRA native_run signal=6   (rc=134)
```

Good failure, but it is opt-in and the user has to already suspect a wedge. Note
the trace does not survive it: `--record` with a budget abort yields
`trace=incomplete … "empty trace file; record finalization did not complete"`, so
the one artifact that would explain the wedge is exactly what you lose.

**(3) The audit's diagnostic overclaims.** It says the guest is "Runnable on
x86-64 Linux" and the sites are "contained, not escapes — the run stays
deterministic." Both statements are true about *determinism* and false about
*runnability*: the run is deterministic in the sense that it hangs identically
every time. Worth softening the wording, or splitting manageable-and-runnable
from manageable-but-may-not-progress.

### Design input for the clock model

The wedge is a *calibration* wedge specifically, and calibration is a
recognizable pattern: measure a counter against the OS clock over a fixed
wall-clock window at startup. Options, roughly in increasing intrusiveness:

- **Do nothing; document it.** The mapping is right; a guest that busy-waits on
  the clock is a guest that busy-waits on the clock. Cheapest, and consistent
  with fail-closed doctrine — but the failure is a hang, which is the one mode
  doctrine says to avoid ("a refusal or a named abort, never a silent…").
  At minimum this should become a *named* abort via a frozen-clock churn
  detector (consequence 1), not a hang.
- **Advance virtual time on a spin.** e.g. after K consecutive `ClockNow` ops
  with no other boundary op, advance the clock by a token amount. This unwedges
  calibration *and* keeps the counter self-consistent (the same clock feeds both
  sides, so the derived frequency stays exactly 1 GHz — see leg 3b, which is
  precisely this experiment done by hand). It is a real semantic change though:
  it makes `Instant::now()` non-idempotent and would need to be recorded.
- **Recognize and short-circuit calibration.** Too guest-specific; rejected.

The middle option is attractive because the leg-3b measurement shows the answer
is *invariant to how time advances*: whatever the increment, both sides of the
ratio come from the same clock, so the guest derives 1 GHz exactly.

---

## How legs 3a–3d were obtained

To answer the calibration question at all, the busy-wait has to terminate. I
made **one deliberate, clearly-labelled change** to the vendored fastant: a
`std::thread::sleep(Duration::from_micros(500))` at the top of the inner loop at
`tsc_now.rs:169` — i.e. exactly the virtual-time-friendly wait an
upstream-compatible fix would use. Nothing else changed; the calibration
arithmetic is untouched. This variant lives in the sandbox as
`fastant-demo-yield` and is the source of every number in legs 3a–3d. The
unpatched guest is the one that wedges, and that is the honest primary result.

### Leg 3b — calibration derives exactly 1 GHz

```
fastant::is_tsc_available = true
fastant anchor offset at start = 21000000ns
w1: requested=5000000ns fastant=5000000ns std=5000000ns rdtsc_delta=5000000
w1: derived nanos_per_cycle=1 cycles_per_second=1000000000
w2: requested=1000000ns fastant=1000000ns std=1000000ns rdtsc_delta=1000000
w2: derived nanos_per_cycle=1 cycles_per_second=1000000000
w3: requested=250000ns fastant=250000ns std=250000ns rdtsc_delta=250000
w3: derived nanos_per_cycle=1 cycles_per_second=1000000000
total fastant elapsed = 6250000ns
as_unix_nanos(now) = 27250000
```

Every claim in the brief's leg (b) holds exactly, not approximately:

- Derived `cycles_per_second` = **1,000,000,000**; `nanos_per_cycle` = **1**.
- A 5 ms virtual sleep reads as **5,000,000 ns** through `fastant::Instant`.
- `fastant` elapsed == `std::time::Instant` elapsed == raw `rdtsc` delta, in all
  three windows. The counter and the clock a guest calibrates it against are the
  same object, so the derived frequency has zero error by construction.
- The 21 ms anchor offset is 42 × 500 µs of virtual sleep — the calibration's own
  cost, now paid in virtual time.

### Leg 3a — same-seed determinism (3 runs, prebuilt artifact)

```
bdb608210685ca2cf194182b95c125c7  /tmp/A1.out
bdb608210685ca2cf194182b95c125c7  /tmp/A2.out
bdb608210685ca2cf194182b95c125c7  /tmp/A3.out
```

Byte-identical including every printed elapsed value and the derived frequency.

### Leg 3c — record → replay identity

```
cargo patina run <artifact> --seed 7 --record /tmp/fastant.trace   → rc 0
cargo patina replay <artifact> /tmp/fastant.trace                  → rc 0
bdb608210685ca2cf194182b95c125c7  /tmp/A1.out     (recorded run)
bdb608210685ca2cf194182b95c125c7  /tmp/rep.out    (replay)
```

Trace metadata confirms both traps recorded:
`{"root_seed":7,"sud":true,"tsc":true,…}`, 202 events, virtual span 27.25 ms,
`format_version: 4`. The jittered pair replays identically too
(`41ace79023e2ad5597d0137319da567f` for the recorded run and the replay).

### Leg 3d — seed variation

Without jitter, three seeds are byte-identical (`bdb60821…` ×3) — correct: the
guest makes no seeded decisions. With `--sleep-jitter-nanos 0..200000` the three
seeds diverge and each reproduces:

```
bba955145455e2df3ab2621a5ceaa56a  seed 7  + jitter
41ace79023e2ad5597d0137319da567f  seed 99 + jitter   ← repeat run: identical
8b4fa3e6f4dc058ceb3a25bc15a53b8e  seed 12345 + jitter
```

Seed 99's output — note the calibration still derives exactly 1 GHz while every
measured value moved:

```
fastant anchor offset at start = 20473678ns
w1: requested=5000000ns fastant=5163019ns std=5163019ns rdtsc_delta=5163019
w1: derived nanos_per_cycle=1 cycles_per_second=1000000000
w2: requested=1000000ns fastant=1106436ns std=1106436ns rdtsc_delta=1106436
w3: requested=250000ns fastant=383769ns std=383769ns rdtsc_delta=383769
```

Jitter perturbs the sleeps; the counter/clock identity is unaffected. That is
the strongest single piece of evidence that the mapping is structurally right
rather than coincidentally right.

---

## Secondary finding: CPUID is an unaudited, untrapped host read

fastant decides *whether to use the TSC path at all* from `CPUID` —
`has_invariant_tsc()` reads leaf `0x80000007` bit 8 (`tsc_now.rs:128-139`).
Patina neither traps nor audits `CPUID` (no `ARCH_SET_CPUID` anywhere in the
shim; the only mention of `cpuid` in `patina-target` is an instruction-length
comment). A probe built and run in sandbox A, under patina versus bare:

```
=== UNDER PATINA ===                        === BARE (host) ===
vendor = "GenuineIntel"                     vendor = "GenuineIntel"
cpuid.1.eax = 0x000c06f2                    cpuid.1.eax = 0x000c06f2
max ext leaf = 0x80000008                   max ext leaf = 0x80000008
0x80000007.edx = 0x00000100 invariant=true  0x80000007.edx = 0x00000100 invariant=true
```

Identical — the guest reads the host's real CPU identity through the sandbox.
`cargo patina audit` on that probe exits 0 with **no** instruction finding,
while `objdump` counts **11 `cpuid` sites** in the same binary (against 2
`rdtsc` sites, both of which the audit did find).

Why it matters beyond hygiene: in this exact guest, CPUID is the branch that
selects between fastant's TSC path and its `SystemTime` fallback. On a host
whose invariant-TSC bit is clear, the same guest at the same seed takes a
different code path — and patina reports the run as deterministic either way.
That is a cross-host reproducibility hole in the class patina exists to close.
It is a narrower problem than `rdtsc` (feature bits are near-constant within a
fleet) but it is the same shape, and unlike `rdtsc` it is currently invisible to
the audit. Linux supports `arch_prctl(ARCH_SET_CPUID, 0)` for CPUID faulting on
capable Intel parts, so the SUD/TSC trap pattern would extend to it; the cheaper
first step is simply to add `cpuid` to the audited instruction set so it stops
being silent.

---

## Leg 5 (bonus) — SlateDB with `foyer`, sandbox B

Setup: cleaned SlateDB snapshot, patina updated from `21ff309` to **026269f**
(`git fetch` over HTTPS works unauthenticated from the sandbox; note `origin/main`
was already ahead at `5653d94` — I pinned to the team-lead tip for consistency),
release `cargo-patina` rebuilt. `foyer` added to `slatedb-dst`'s slatedb feature
list. Build env `RUSTUP_TOOLCHAIN=1.97.1`, `RUSTFLAGS="--cfg tokio_unstable"`.

**Audit: exit 0**, one finding, zero `--allow`, 72 s:

```
cpu-nondeterminism (TSC-trap-managed, 1 site): …
  instruction@.text+0xdb93f0 (cpu-nondeterminism)
    provenance=crate=fastant object=fastant.485b83a44fc94a6c-cgu.0
      [symbol=…__rdtsc…fastant section=.text]
AUDIT_RC=0
```

**The full-feature-space closure the arc was after: confirmed.** The last
SlateDB all-features refusal is now a managed finding, and the aws side was
already closed on this corpus at `314c68b`.

### …and the same closure is where the wedge bites hardest

`cargo patina run . --target native --seed 1 -- determinism 1 200` — the family
the audit actually measured, and the one that arms the trap — **hangs**. Killed
at 240 s, no guest output at all (`SLATEDB_PATINA_START` never prints), guest
process at 100% CPU. gdb attach in sandbox B gives the identical seven-frame
stack, frame for frame:

```
#3  fastant::tsc_now::_cycles_per_sec ()  at src/tsc_now.rs:169
#6  fastant::tsc_now::init ()             at src/tsc_now.rs:26
#7  fastant::tsc_now::___init___ctor::___init___ctor () at src/tsc_now.rs:24
#8  call_init (…) at ../csu/libc-start.c:145
```

So on the real corpus the audit's "Runnable on x86-64 Linux" is, today, wrong:
the audit passes and the native run never reaches `main`. Fixing the diagnostic
wording plus adding the frozen-clock churn arm would turn this from a silent
240-second hang into a named refusal that points at the calibration ctor.

### The cargo (in-process) family is unaffected — and unprotected

SlateDB's dogfooding actually runs in the **cargo** family
(`cargo patina run --bin patina_campaign -- determinism 5 200`), which is
in-process and has no shim, so `PR_SET_TSC` is never armed. There fastant
calibrates against the *real* host clock and the run completes normally. Two
same-seed runs are byte-identical once the guest's own `tracing` subscriber
timestamps are stripped (those are real wall-clock strings the guest formats
itself, not a patina decision):

```
84d4520d57de9cf083a551552cd8136b  run 1 (timestamps stripped)
84d4520d57de9cf083a551552cd8136b  run 2 (timestamps stripped)
```

Stated precisely: in this scenario the host TSC reads did **not** propagate into
observable divergence. That is not the same as safe — in the cargo family
fastant's `rdtsc` is a genuine unmanaged host-clock read that the trap does not
cover and that the native-family audit's "trap-managed" downgrade does not
describe. Two follow-ups fall out:

- The audit builds and classifies a **native** artifact even when the package's
  real execution family is cargo. The manageability verdict should be scoped to
  the family that will actually run, or say which family it assumed.
- Passing a source path positionally to `run` leaks it into guest argv: `patina
  run ./Cargo.toml --seed 1` reached the guest as `argv[1] = "./Cargo.toml"`
  (`Error: unknown scenario "./Cargo.toml"`), and `run . -- determinism` arrived
  as `. -- determinism` (`invalid seed "--"`). The cargo-family form
  (`run --bin NAME -- ARGS`) is clean. Looks like a routing bug in the
  source-first path for packages that take positional arguments.

---

## Reproduction

Guest sources are on the host at
`/private/tmp/claude-501/-Users-jacobhayes-src-github-com-JacobHayes-patina/03237c20-0d0e-45ac-92fe-641b8afcc924/scratchpad/fastant-demo/`
(`Cargo.toml`, `Cargo.lock`, `src/main.rs`, `.cargo/config.toml`, `vendor/` — 21
vendored crates, self-contained). Packed as `fastant-demo.tgz` alongside. The
one-line yield patch that produces the `fastant-demo-yield` variant is at
`vendor/fastant/src/tsc_now.rs:169` — insert
`std::thread::sleep(std::time::Duration::from_micros(500));` as the first
statement of the inner loop, and blank the `files` map in
`vendor/fastant/.cargo-checksum.json`.

## Sandbox termination proof

```
$ tl sbx terminate 0rn7cqu5mdiynxrrfg13o   → 0rn7cqu5mdiynxrrfg13o
$ tl sbx terminate db69vpqrwzkcsix3mpspj   → db69vpqrwzkcsix3mpspj
$ sleep 30 && tl sbx ls
No sandboxes found.
```

Checkpoint rows re-listed after termination and unchanged — both protected
snapshots intact, nothing added or removed:

```
ywnndioh9vk1kka0j5hty  completed  filesystem  11763.3 MB  2026-08-07 12:09
omw1e61sbliouitngmkqh  completed  filesystem   1878.9 MB  2026-08-06 10:36
b22lzifm9tftgtejxpr82  failed     filesystem           -  2026-08-06 09:21
suspend-s2b3drju2tohox50q4bko-…  completed  memory  13893.9 MB  2026-08-03 08:58
suspend-vb9oerc6j4iv5sy65u362-…  completed  memory   4857.0 MB  2026-08-01 02:17
```
