# Advisors for search, minimization, and triage

**Status: design proposal.** This document describes direction and evaluation,
not an implemented advisor API. Start with a light integration outside the
runtime; expand only where measured results justify it.

## Bottom line

Patina can use **pluggable advisors** to find failures with fewer runs, narrow
reproductions with fewer attempts, and prioritize investigation. Advisors combine
code context with execution evidence to recommend what to try next. Patina keeps
control of legal actions, deterministic execution, replay, and correctness oracles.

The first experiment is an external Rust controller that selects batches of
ordinary Patina runs. Compare a Jev-backed exploration advisor with seeded search,
existing coverage-guided search, and a simple heuristic using Patina's existing
testbeds. Record recommendations and outcomes locally so we can assess quality,
cost, and reproducibility. No hosted provider belongs in the runtime, and no model
judgment replaces a finding or changes a pass/fail verdict.

The broader direction includes site-directed exploration, trace-prefix branching,
minimization guidance, and failure triage. These are separate advisor roles, not
requirements to implement one universal planner immediately.

## Why advisors

Seeded exploration provides diversity but can spend substantial effort on runs
that teach us little. Patina's existing guided campaigns select and mutate prior
runs using coverage/depth novelty. An advisor could add semantic hypotheses:
which fault combination might reach an unmet property, which sequence might
violate an invariant, or which reduction is likely to preserve a failure.

This is a complement to measured selection, not a replacement for it. Retain an
explicit allocation for seeded exploration so an advisor's preferences cannot
exclude regions of the search space. A model's confidence is not an observed
probability of discovering a bug.

TypeSafe's [Jev announcement](https://typesafe.ai/blog/introducing-system-one-models-and-jev)
motivates the experiment: bounded typed decisions may be cheap and fast enough
to use between batches or reduction attempts. Its [API](https://docs.typesafe.ai/api.md)
returns choices, rubric scores, and yes/no probabilities rather than arbitrary
generated action scripts. Schema correctness does not imply semantic correctness;
published model comparisons do not establish effectiveness on Patina workloads.
The advisor boundary should also support ordinary algorithms and other models.

## Use cases and objectives

An **objective** describes the measurable work to accomplish, within a budget.
“Find bugs” is a useful overall goal but usually too broad for one recommendation.
The controller supplies the objective and permitted scope; an advisor can propose
subtargets and explore/exploit allocations within that scope.

| Role | Example objective | Recommendation | Authority retained by Patina |
|---|---|---|---|
| Exploration | Find new confirmed failures within a run/time budget | Next batch, fault knobs, seed allocation, promising ancestors | Valid configuration and actual execution outcomes |
| Site-directed exploration | Reach a site, satisfy a `sometimes!`, or falsify an `always!` | Targeted configurations or legal action sequences | Site observations and invariant verdicts |
| Branch targeting | Explore alternatives near a promising execution moment | Parent prefix, branch point, suffix experiment | Prefix identity, legal interventions, replay compatibility |
| Minimization | Reduce a reproduction under a declared size/cost metric | Order candidate reductions | Failure oracle confirms every accepted reduction |
| Triage | Prioritize distinct findings for investigation | Ranking and suggested relationships | Original findings, signatures, and artifacts remain intact |

### Site-directed search

A focused evidence packet could include the source around a site and its callers,
observed reach/satisfaction/fault activity, previous attempts, nearby coverage,
and controls actually available to the experiment.

For example: “commit an operation, lose its acknowledgment, then retry the same
request.” That is a hypothesis about reaching a duplicate-processing invariant,
not a verdict. A domain-aware harness can express those actions directly; generic
network-fault knobs only approximate them.

The targets differ:

- `always!`: seek an execution that makes the condition false without changing
  the assertion or its meaning.
- `sometimes!`: seek a satisfying execution; distinguish reaching the site from
  satisfying its condition.
- `buggify!`: explore behavior downstream of permitted fault activation/firing,
  not merely maximize the number of fires.

Candidate plans need not be a fixed catalog. Code can construct bounded choices
or legal sequences from the current capabilities. Dependent actions must be
validated together: independently plausible model choices do not necessarily
form a valid experiment. Arbitrary synthesis of new code is outside this initial
advisor proposal.

Changing fault knobs between campaign batches is a form of experiment selection.
Changing them during one execution is a stronger capability requiring explicit,
recorded intervention semantics. Begin with the former.

### Optional domain-specific scenarios

A simulated service can expose a code-defined action vocabulary. For checkout,
that might permit committing a charge, suppressing its response, then receiving
a retry. An advisor selects a legal scenario; deterministic service code executes
it and an invariant checks that the retry does not charge twice.

This is useful for application-level protocols, but not necessary for general
campaign guidance. Protocol semantics and guest-specific actions belong in the
harness or an extension, never hardcoded into core Patina.

## Determinism and authority

**Advisor calls must not become an unrecorded input to execution.** A hosted
model's answer is not derived from Patina's seed. Neither a model identifier nor
a sampling setting establishes that repeated calls return the same answer.

The design separates planning from execution:

1. Construct a bounded request from recorded evidence and permitted actions.
2. Obtain and validate a recommendation outside guest execution.
3. Persist the recommendation and concrete selected experiment before running it.
4. Execute with explicit seeds, configuration, and deterministic policies.
5. Associate measured outcomes with the decision that selected the experiment.

Reproducing saved work consumes the saved decision, not a new advisor call. A
fresh planning session may propose different experiments; it is a new planning
history, not a reproduction of the old one. Seed-only execution reproducibility
continues to require the same build, configuration, policies, and effect boundary.
A seed alone cannot reconstruct a history of external recommendations.

For future branching, the conceptual identity is:

> Parent trace + timeline + operation T + intervention plan + suffix seed +
> compatible build and policy identity.

Replay reconstructs the prefix; the suffix follows the recorded plan. A suffix
seed does not itself specify which knobs change, when they take effect, or which
random streams and state continue. Those semantics must be explicit. Branching
need not mean restoring a memory snapshot; replaying the prefix is sufficient
where the runtime supports it.

Two records serve different purposes: the execution trace reproduces what a run
did; the planning ledger reproduces which experiment was selected and from what
evidence. Native replay currently refuses branching, while Cargo-package and
WASI replay expose it. Native branch support is outside the first integration;
this proposal does not claim that the existing branch surface supports arbitrary
site interventions or mid-run policy replacement.

Advisors cannot weaken an audit, downgrade a refusal, waive coverage obligations,
change an oracle, or erase a finding. Invalid recommendations and provider errors
are explicit failures of advisor mode, not silent switches to another policy.
An intentional seeded exploration allocation is separate from error handling.

## Existing evidence and deferred visibility

Patina already exposes useful code-level evidence despite its low-level execution
boundary:

- The site inventory locates Rust oracle/assertion/fault sites and joins source
  identities with runtime or campaign observations.
- Instrumented native runs provide edge counters. Offline coverage reporting
  attributes PCs to function symbols and provides crate/module rollups.
- Campaign artifacts carry coverage or depth novelty, site observations, fault
  activity/vacuity, outcomes, and failure signatures.
- Execution traces describe boundary operations and their recorded outcomes.

These are not arbitrary local-variable capture, symbolic path conditions, or a
complete ordered source-level execution history. Current native symbolization is
function-symbol based, not a general DWARF debugger. WASI's hostcall/fuel depth
signal is explicitly weaker than edge coverage.

**Deferred:** richer value observations, source-line attribution, ordered site
occurrences aligned with trace moments, domain-state summaries, and reusable
site-directed branch interventions. Start with existing metadata and matching
source context. Any added observations must have explicit cost and deterministic
semantics. Source evidence must be identified against the build that ran.

## Extension direction

Use **Advisor** as the umbrella term, with distinct exploration, minimization,
and triage roles. Each role has its own objectives and legal proposals; shared
recording conventions need not imply one universal action interface.

The conceptual contract is small:

> Objective + evidence references/context + allowed actions + budget
> → recommendation → validation and execution → observed outcome.

Prefer a typed Rust interface with explicit registration in the initial external
controller. A Jev adapter can be a separate crate, potentially developed in this
repository, without becoming a dependency of the runtime. Other users should be
able to implement advisors in their own crates. Keep model-specific setup and
source/log transmission opt-in.

**Packaging is open, not a commitment to IPC.** A Rust crate linked into a
controller gives us ordinary trait-based composition with no messaging system.
Installing a crate separately cannot add implementations to an already-built
binary. Automatic discovery in stock `cargo patina` would therefore require an
additional mechanism—such as an executable protocol or a deliberately designed
dynamic-loading boundary. Ordinary Rust traits do not provide a stable binary
plugin ABI. Do not introduce that complexity before proving the integration's
value and deciding whether no-rebuild installation is a requirement.

The initial controller can use Patina's existing CLI/artifact surfaces without
first adding plugin loading to the CLI. Let the prototype inform a small shared
API rather than freeze a broad extension framework upfront.

## Local evidence for quality and return on effort

Keep the dataset local by default. This is not a telemetry service or a training
pipeline. The immediate purposes are evaluating advisor quality, explaining
choices, measuring cost, reproducing work, and improving the search process.

Reuse ordinary artifacts instead of duplicating them:

| Reuse or reference | Record additionally because execution traces do not establish it |
|---|---|
| Seeds/configuration, run outcomes, coverage/site reports, failure artifacts | Objective, allowed candidate set, and the exact context presented or immutable references sufficient to reconstruct it |
| Trace operations and results | Advisor/model/request version, recommendation and predictions |
| Existing build/artifact identities | Selected proposal, selection rule, known randomized selection probabilities, and ordering/batch boundaries |
| Existing replay/reproduction information | Advisor overhead, rejected proposals/errors, and links from decisions to measured outcomes |

Derived coverage/signature summaries can be reconstructed from retained source
artifacts if the derivation version is recorded. Do not infer historical
recommendations or discarded alternatives from the winning execution: that
information is absent from the trace.

Record unsuccessful and uncertain attempts as well as findings. Distinguish no
novelty, site progress, confirmed violation, refusal, infrastructure failure, and
successful/failed reduction. Unchosen candidates have no observed outcome and
must not be labeled failures. Advisor answer probabilities are not selection
probabilities unless the selection policy actually uses them that way.

Use a compact ledger with references to retained artifacts. Local storage still
has limits: report missing, deleted, or resource-limited traces explicitly and do
not promise recovery from an artifact that was never retained. Source and logs
sent to a hosted advisor leave the local machine only by explicit configuration.

Future learned policies may benefit from these records, but model training is
not an initial deliverable. Richer observations should be motivated first by
quality assessment and demonstrated search value.

## Evaluation: extend the existing testbeds

Do not create a competing testbed system. Expand existing fixtures and their
metadata into a reusable discovery and minimization benchmark.

Existing planted-bug checks already provide part of the foundation. For example,
`pubsub/run-patina.sh` requires its pinned lost-wakeup, framing, and stale-timeout
failures to be detected and replayed; checkout's selftest requires its planted
double-charge outcome. Those checks should continue to fail if the defect or its
detector disappears. A benchmark adds a different question: how efficiently can
a strategy discover the defect **without receiving its known trigger**?

For each benchmark case, identify the bug class, vulnerable and healthy/fixed
modes, deterministic oracle, known reproduction, required capabilities, and
allowed search space. Some existing fixtures already supply these; add missing
pieces rather than assume every fixture has the complete contract. Include
multi-step cases, no-bug controls, and explicit unreachable targets. Separate
held-out bug families from examples used to tune prompts and policies.

### Discovery

Compare:

1. Unguided seeded exploration.
2. Existing coverage/depth-guided exploration.
3. A simple deterministic heuristic using the available evidence.
4. Advisor-guided exploration, with model/configuration variants when useful.

Use paired starting conditions, multiple seed bases, and declared run/time
budgets. Measure confirmed distinct bugs, runs and total wall time to discovery,
success within budget, site/coverage progress, vacuity, and total advisor cost.
Include context preparation and API latency. Report unsuccessful budget-limited
runs, not just averages over successes. Source supplied to an advisor must not
leak pinned trigger seeds or benchmark-only bug annotations.

Existing guidance is a baseline, not an assumed improvement:
`testbeds/guided-efficacy` documents a no-advantage result that blocks an efficacy
claim. Apply the same honesty to model guidance.

### Minimization

Start strategies from the same failing artifacts with the same oracle and
permitted reducers. Measure attempts, total wall time, and final reproduction
size/complexity under a common budget. Faster termination at a larger reproducer
is not automatically better. Every accepted reduction must preserve the defined
failure; retain existing non-vacuity and failure-identity requirements.

### Correctness before efficacy

Offline checks must prove that recommendations actually alter selected work,
invalid actions are rejected, saved decisions reproduce without the provider,
and restart/resume does not silently regenerate or skip decisions. Planted-bug
and healthy controls remain deterministic gates. Hosted-model efficacy runs are
separate measurements; changing model behavior must not make ordinary correctness
checks depend on a live service.

Advance beyond the experiment only if improvement over inexpensive baselines
survives repeated trials and overhead accounting. If it does not, retain the
measurement and narrow or stop the integration.

## Scope and open questions

**First:** external Rust controller, ordinary run batches, existing evidence plus
source, local decision ledger, and comparative discovery evaluation. Site-aware
objectives can guide whole-run configurations without requiring native branching.

**Next, if useful:** minimization ordering and triage using the same evidence
principles; site-directed branching once execution support and intervention
semantics are established.

**Deferred:** richer state capture, native branching work, dynamic plugin loading,
online advisor calls in guest execution, new service-model frameworks, and model
training infrastructure.

Before implementation, resolve:

- Is compile-time Rust registration sufficient, or is installing an advisor into
  an unchanged stock CLI an essential product requirement?
- Which existing guest and multi-step bug provide the first fair comparison?
- Which measurable objective and legal candidate vocabulary are small enough for
  the first controller?
- What overhead and discovery improvement would justify expanding the integration?

## Grounding

- [Patina intent](../INTENTS.md): seeds, deterministic policies, and fail-closed execution.
- [Architecture](../ARCHITECTURE.md): experiment plane, drivers, and trace model.
- [Implementation status](../IMPLEMENTATION.md): exploration and campaign behavior.
- [Testbeds](../testbeds/README.md): existing guests and planted-failure conventions.
- [`campaign.rs`](../crates/cargo-patina/src/campaign.rs),
  [`sites.rs`](../crates/cargo-patina/src/sites.rs),
  [`coverage.rs`](../crates/cargo-patina/src/coverage.rs), and
  [`help.rs`](../crates/cargo-patina/src/help.rs): current evidence and CLI capability boundaries.
