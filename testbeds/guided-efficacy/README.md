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

## Measured result (2026-08-06, 6 seed bases, block 10, budget 100)

| seed base | unguided | guided |
|---|---|---|
| 0 | 40 | 50 |
| 1 | 20 | 20 |
| 2 | 20 | 20 |
| 3 | 20 | 20 |
| 4 | 90 | not reached |
| 5 | 10 | 30 |

**Guidance was never faster, and was slower on three of six seed bases.** The
same shape held on a WASI depth fixture (guided slower on 3 of 6 comparable seed
bases, tied on 3).

## Why — and the fix this gate is waiting on

The cause is the ancestor-selection weighting, not the guidance machinery. Over a
60-generation guided run the novelty log was
`[[0, 88], [4, 13], [24, 1], [41, 40]]` — generation 0 "opened" 88 edges — and the
ancestor actually chosen was:

    34x generation 0,  5x generation 4,  3x generation 41,  0x generation 24

Generation 0's 88 edges are the program's *baseline* coverage (`main`, startup,
the fault loops), not a discovery. Weighting fitness by raw new-edge count
therefore makes the bootstrap generation permanently dominant, and ~81% of the
exploitation budget is spent resampling near one arbitrary configuration —
strictly worse than sampling independently.

Candidate fixes, to be judged by re-running this gate:

1. Give the bootstrap generation weight zero — treat its coverage as the baseline
   so the pool holds only genuine discoveries.
2. Weight by recency as well as size, so the pool tracks the frontier rather than
   accumulating everything ever found.
3. Prefer ancestors that opened *rare* edges over ones that opened many.

Until one of those lands, `--guided` is honest about what it does (it steers, and
reports that it steered) but has no measured advantage over the default sweep.

## Provenance

Measured against the tip binary at the time (`--guided` present); the harness has
not been re-run since. Re-run it before trusting the table above:

    testbeds/guided-efficacy/run.sh --seeds 6
