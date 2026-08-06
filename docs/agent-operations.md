# Agent operations

This document turns prior project-specific agent lessons into shared operating
rules. It is intentionally tool-agnostic and safe to commit. Machine-specific
commands, local VM/sandbox recipes, model preferences, and VCS-tool workflows
belong in the gitignored `AGENTS.local.md` at the repository root.

## Design and decision handling

- For genuinely open design choices, ask concise, structured questions instead
  of burying options in a long report. Put the recommendation first, state the
  trade-offs, and batch related choices so the user can steer the work.
- Long design documents are for implementers. User review should start with a
  short overview, the real file path, and explicit open questions.
- Once a design is approved, later phases named by that design remain owned by
  the implementer/coordinator. Do not leave approved "phase 2" work as an
  unowned future prompt unless the user explicitly parks it.
- Let the latest understood intent win. Do not preserve obsolete behavior because
  of path dependency, sunk cost, or hypothetical future users; remove old aliases,
  shims, docs, and callers in the same change unless a real compatibility need is
  explicit.
- Batch approvals the way you batch questions. A phase or wave brief should
  collect the pre-authorizations its planned actions need (pushes, spend,
  irreversible steps) in one decision point, rather than interrupting once per
  action; per-action asks are for genuinely new scope.

## Status and evidence

- Never answer "is it running?" or "what is the status?" from memory. Check a
  fresh source of truth first: process state, log tail, CI status, output files,
  modified times, or the owning tool's status command. Report observations
  separately from inference.
- Quote measurements only when they were measured. Label estimates as estimates,
  and prefer instrumenting recurring loops over guessing.
- Size agent work in agent-sized units. Human-duration language in plans is
  usually misleading unless it is backed by measured wall-clock evidence.

## Verification ladder

- Use the cheapest check that can catch the expected failure first, and encode
  recurring check sequences as one command or script. A prose checklist is not a
  gate.
- `mise run check:fast` is an inner-loop tier, not landing evidence. `mise run
  check` is the default landing gate. For runtime/shim/trace/target changes, the
  native/WASI/cross-target validation scripts are part of the evidence, not
  optional cleanup.
- A green gate is only evidence if it can fail. Selftests and planted fixtures
  should prove classifiers, drift detectors, default-deny audits, and vacuity
  checks actually bite.
- For docs-only changes that mention CLI flags, run `scripts/check-flag-drift.sh`
  at minimum. If a doc or script mentions a Patina flag, it must come from the
  generated CLI registry rather than memory.
- Keep commits targeted and linear, but avoid wasting CI with rapid-fire pushes
  for commits that are ready back-to-back. If a batch is ready together, push it
  once; if the next commit will not be ready soon, push the current one and watch
  it.

## Delegation, scouting, and review

- Keep one writer for a given checkout or file set. Use read-only reviewers and
  scouts freely, but avoid multiple agents editing the same workspace unless the
  work is deliberately isolated.
- Worker briefs should include a final-report contract: changed files, commands
  run with exit codes, validation evidence, residual risks, surprises, and any
  VCS-affecting commands.
- The coordinator owns VCS integration. Builders should not run state-changing
  VCS commands unless explicitly asked; tool-specific checkpoint exceptions
  belong in local workflow notes.
- While a builder fixes one rung of a failure class, run read-only scouts for the
  next rungs instead of discovering one failure per CI round. Batch scout findings
  into a single implementation brief.
- Verify delegated work before trusting it. Read the diff, confirm the claimed
  commands really ran, and rerun proportionate checks in the integrated tree.
- Long-lived agents accumulate context cost and stale assumptions. When a worker
  has many rounds of history, restart with a fresh, self-contained handoff brief
  instead of continuing to append corrections.
- Check delegated progress through the owning tool's status surface, saved
  artifacts, or filtered summaries. Do not ingest raw session transcripts or
  large tool outputs just to see whether an agent is moving.

## Isolation and shared artifacts

- Use isolated checkouts/workspaces for parallel implementation and validation.
  Verification should run against the commit or tree under review, not against a
  moving builder workspace.
- Campaign output directories, generated harness binaries, and shared build
  artifacts are single-writer resources while a campaign is running. Rebuilding
  or deleting them mid-run can poison otherwise deterministic evidence.
- Before updating canonical outputs or hashes, verify them from a clean build and
  on every platform the claim covers.
- Concurrent builders on one machine share more than they think: session-shared
  scratch directories are not per-agent (another agent can truncate your log),
  and pattern kills like `pkill -f "mise run check"` match every workspace's
  run, not just yours. Write battery logs to per-workspace paths and kill only
  by the PID of processes you started.
- Wall-clock timings taken while several batteries run concurrently are
  contention-inflated. Label them as such; only quote uncontended runs as
  representative durations.

## Cross-platform and campaign lessons

- Cross-platform trace identity is not a Patina contract. Different operating
  systems expose different libc and synchronization surfaces, so trace hashes are
  platform-local unless a specific test proves otherwise.
- Cross-platform outcome identity must be designed at the application layer:
  hash stable, payload-determined facts and normalize away incidental completion
  order; include ordering or schedule-sensitive counters only when that behavior
  is under test.
- Inert knobs are bugs. Fault, schedule, coverage, and buggify controls need
  reports that show whether they affected the run; vacuous clean passes should be
  warnings or classified failures when the tier depends on them.
- A knob that several execution families each plumb through their own
  hand-maintained list will eventually be carried by some families and dropped by
  the rest, and a dropped knob looks exactly like a clean run. Derive every
  family's plumbing from ONE table keyed to the flag registry, and gate that
  table against the registry with a test. Two silent-inertness bugs of this shape
  were found and structurally removed while unifying the fault knobs.
- Failure classifiers must be deterministic and self-tested. A new class should
  have a fixture that fires it, and a clean run should not hide unclassified or
  infrastructure failures.
- Sparse or paced workloads can manufacture non-liveness that looks like a bug
  (leader-election churn under loss, retry-driven log bloat decelerating
  commits). Before treating slow convergence as a finding, run a workload-shape
  discriminator — the same faults with an unpaced or zero-window control — and
  give workload artifacts their own outcome class instead of counting them as
  failures or silently tolerating them.

## Native/shim-specific operating rules

- Read `crates/patina-native-shim/AGENTS.md` before changing the native shim.
- The host-alias doctrine is structural: shim internals reach real host
  primitives through private resolved aliases, never by calling public symbols
  that guest code can import.
- Default-deny audit/run parity is load-bearing. Do not fix a missed native
  effect by adding an allowance; add or harden the detector and then model,
  interpose, or deny-trap the effect.
- The `cargo-patina` binary embeds native C shim sources at build time. After
  changing the C layer, rebuild `cargo-patina` before trusting native validation.
- Guest builds link the shim through injected link args, which cargo does not
  treat as a fingerprint input: after a shim or runtime change, `cargo patina
  build` can report "Finished" instantly and hand back a guest binary still
  linked against the old shim. Deleting the guest's local `target/` does not
  help when a global `build.build-dir` redirects the real build directory.
  Until the staleness bug is fixed, force a relink (e.g. touch the guest's
  sources) and confirm the fresh binary actually contains the change before
  trusting "the fix didn't work" evidence.

## Local maintainer notes

If `AGENTS.local.md` exists, read it after this file for local maintainer
recipes. It is intentionally gitignored and may contain machine-specific paths,
VM names, sandbox snapshot IDs, model choices, and VCS-tool workflows. Do not
copy those details into tracked docs unless they become portable project policy.
