# guided-efficacy

An **efficacy** gate for `cargo patina campaign --guided` (coverage-depth arc,
wave E). Wave E's *correctness* — determinism, resume/tear reproducibility,
fail-closed refusals — is proven by `campaign --selftest` and the end-to-end
suite. This testbed answers the separate question those cannot: does the
selection policy actually reach a hard target in fewer generations than uniform
sampling?

## The fixture

`staircase.rs` nests three stages behind three campaign fault knobs — fs-error
permille, fs-short rate, sleep-jitter ceiling — that live in **different bytes**
of the generation-derivation hash. That is the shape a mutation operator is
supposed to exploit: a child that keeps its ancestor's fs-error byte and re-rolls
the rest starts one step up the stair. Each stage calls into its own function, so
reaching a deeper stage covers a whole function's worth of new edges — the
novelty signal `--guided` steers by.

`run.sh` reports generations-to-`stage_three` per seed base for both modes, and
exits 1 if guided was slower on any seed base. It first proves the staircase is
reachable at all (knobs at their ceiling must reach stage three), so a run cannot
pass vacuously by measuring an unreachable target.

## Measured results

Generations until `stage_three` first has a covered edge; lower is better. `>100`
means the budget ran out.

**Before the fix** (bootstrap generation eligible as an ancestor):

| seed base | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| unguided | 40 | 20 | 20 | 20 | 90 | 10 |
| guided | 50 | 20 | 20 | 20 | >100 | 30 |

Never faster; slower on **three** of six seed bases.

**After excluding the bootstrap generation from the ancestor pool:**

| seed base | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| unguided | 40 | 20 | 20 | 20 | 90 | 10 |
| guided | >100 | 20 | 20 | 20 | >100 | 10 |

Slower on **two** of six, tied on four, never faster. The exclusion is right on
principle and improved the aggregate (three slower became two), but it does not
earn efficacy: `run.sh` still exits 1.

**WASI depth shape, same fixture compiled to `wasm32-wasip1`** (block 5, budget
150; the depth signal is hostcall kinds + fuel high-water rather than edges):

| seed base | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| unguided | 40 | 15 | 5 | 15 | >150 | 5 |
| guided | 115 | 15 | 15 | 15 | **50** | 5 |

Slower on two, tied on three, and **faster on one** — seed 4, where the unguided
sweep never reached the target inside the budget at all and guidance found it at
generation 50. The bootstrap fix improved this shape too (three slower became
two).

A recency-decayed weighting was then composed on top (older discoveries decay so
the pool follows the frontier). It changed the outcome on **zero** seed bases, so
it was not kept — unproven machinery is cruft. Rarity weighting (prefer ancestors
that opened rare edges) is **structurally unavailable**: it needs the cumulative
per-edge hit arrays, which cannot be rewound to a generation boundary, and that
rewind is exactly what makes a resumed guided campaign re-derive identically.
Trading the determinism contract away to chase an unmeasured gain is not a deal
worth taking.

### Verdict

`--guided` has **no consistent measured advantage** over the default sweep. The
honest summary across both signals is high variance rather than uniform loss: it
is usually a tie, it sometimes costs a lot (native seed 0, WASI seed 0), and it
occasionally wins the hard case outright (WASI seed 4, where the unguided sweep
never reached the target and guidance did). It is correct — deterministic,
resume-reproducible, and honest about what it steered — but on this evidence it
does not reliably pay for itself, so the default sweep remains the recommendation.

The leading hypothesis is that the novelty signal is only weakly correlated with
progress toward any particular target: most new edges here come from incidental
fault-injection variety rather than from climbing the staircase, so concentrating
the budget near past discoveries usually starves the exploration that actually
finds the target — and pays off only when uniform exploration happens to be
stuck. Testing that properly needs a fixture whose coverage growth *is* the
search target.

## What the first measurement found

The original cause was the ancestor weighting. Over a 60-generation guided run
the novelty log was `[[0, 88], [4, 13], [24, 1], [41, 40]]` — generation 0
"opened" 88 edges — and the ancestor chosen was:

    34x generation 0,  5x generation 4,  3x generation 41,  0x generation 24

Generation 0's 88 edges are the program's *baseline* coverage (`main`, startup,
the fault loops), not a discovery, so weighting by raw new-edge count made the
bootstrap generation permanently dominant: ~81% of the exploitation budget
resampled around one arbitrary configuration. That is fixed — the bootstrap is
excluded from the pool, pinned by the `guided-bootstrap-excluded-from-pool`
selftest class — and the same run now picks only genuine discoveries (19x gen 9,
17x gen 4, 1x gen 17).

### Excluded data

One unguided WASI-depth data point was discarded: its campaign children were
killed by the host under memory pressure (several batteries running
concurrently), leaving that run truncated rather than complete. Excluding it was
a judgement call, and it is recorded here because excluded data is part of the
record. It affected only the WASI shape, not the native tables above.

### A measurement trap worth knowing

An intermediate run of this gate produced numbers identical to the pre-fix table
because the `cargo-patina` binary under `--patina` had not rebuilt after the
source change. Verify the policy is live before trusting a table — the cheapest
check is the ancestor distribution:

    cargo patina campaign <guest> --gens 60 --faults --guided --progress-every 1 \
        --out-dir /tmp/x | grep -o 'guided=exploit:[0-9]*' | sort | uniq -c

## Running it

    testbeds/guided-efficacy/run.sh --seeds 6

Manual gate, deliberately not wired into `mise run check`: a full run is roughly
1200 native campaign generations (minutes, not seconds), which does not belong in
the landing ladder. Re-run it by hand when the selection policy changes.
