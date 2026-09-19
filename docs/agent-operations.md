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
- `mise run check:fast` is an inner-loop tier, not landing evidence. It includes
  fmt, both clippy passes, all workspace tests except the `cargo-patina`
  `end_to_end` binary and the five native execution targets, fast conformance, cheap selftests, flag drift, MSRV cargo
  check, WASI, and cross-target smoke. `mise run check` is the default local
  landing gate; CI/final gates add the full `mise run msrv` suite and audit
  corpus breadth. For runtime/shim/trace/target changes, the native acceptance
  targets (`native_abi`, `native_containment`, `native_raw`, `native_trace`,
  `native_workloads`) and WASI/cross-target checks are part of the evidence, not optional
  cleanup.
- A green gate is only evidence if it can fail. Selftests and planted fixtures
  should prove classifiers, drift detectors, default-deny audits, and vacuity
  checks actually bite.
- A finding from a harness or oracle is a hypothesis, not a conclusion. Before
  reporting a bug in a system under test, reproduce it independently — the
  smallest faithful standalone repro, or a differential against a reference
  implementation — and adjudicate suspicious verdicts against ground truth (the
  trace, the actual on-disk state) rather than the oracle's word. False positives
  come from harness/oracle bugs far more often than from the tool under it, and an
  approximate repro that fails to reproduce proves nothing.
- For docs-only changes that mention CLI flags, run `scripts/check-flag-drift.sh`
  at minimum. If a doc or script mentions a Patina flag, it must come from the
  generated CLI registry rather than memory.
- Keep commits targeted and linear, but avoid wasting CI with rapid-fire pushes
  for commits that are ready back-to-back. If a batch is ready together, push it
  once; if the next commit will not be ready soon, push the current one and watch
  it.

### Publishing

- `scripts/publish.sh` is the release path. Its default is a dry run: it prints
  every publishable crate's packaged file list, asserts each package carries
  both license texts (the root `LICENSE-MIT`/`LICENSE-APACHE` reach a package
  through per-crate symlinks, so a new crate needs both), and runs
  `cargo publish --workspace --dry-run`. Nothing is uploaded.
- `scripts/publish.sh --execute` uploads, and refuses — naming everything that
  is missing — unless the working tree is clean and the commit carries the git
  tag `v<workspace version>`. Tag deliberately (`git tag -a v0.1.0`) before
  publishing; the script never creates the tag. Published names are
  `patina-dst-*` plus `cargo-patina`; `patina-dst-bench` is `publish = false`.
- `cargo package --workspace` is a cheap rung of the full check tier. It catches
  manifest, readme, and include/exclude breakage, not a missing license symlink;
  the dry run does.

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
- Tests must locate Cargo artifacts through `cargo metadata` (or compiler
  artifact messages), not assume a fixture's `target/` directory. Target-dir
  redirection also makes independent fixture packages share output names: keep
  those test builds single-writer, and use a serial test run when the build
  environment redirects them into one target directory.
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
- Any harness or testbed that takes a binary path (a `--patina PATH`-style
  option) can silently measure a STALE binary after a source change and
  reproduce the pre-change numbers exactly. Rebuild before measuring, and
  prefer a cheap behavioral discriminator that would differ across the change
  (for the guided scheduler, the exploit-ancestor distribution) over trusting
  that the rebuild happened.

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
- New C code in the native shim is linked into EVERY guest, so one added libc
  call becomes an uninterposed import that the pre-run default-deny gate refuses
  for every native program — not just for guests using the new feature. Prefer a
  few lines of hand-rolled parsing over a libc helper there, and treat a gate
  refusal naming an unexpected symbol as a real finding rather than an
  over-strict allowlist. (Found on Linux, where glibc resolved `strtol` to
  `__isoc23_strtol`; macOS did not surface it. The audit now normalizes glibc's
  `__isocNN_` generation aliases onto their base symbol, so that particular
  spelling no longer refuses — but the "one libc call, every guest" rule stands
  for any symbol that is not already interposed or known-safe.)
- Syncing a source tree to a verification host with `rsync -a` preserves source
  mtimes, so a build cache on the target can look NEWER than the freshly synced
  sources and the toolchain skips the rebuild — the tests then run against stale
  code and "pass". Tell the sync tool not to preserve times, or touch the tree
  after syncing, and be suspicious of a cross-host run that compiles
  suspiciously fast.
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
- A control run only exonerates a suspect if the control tree excludes the
  suspect change. "Main also fails" proves nothing when main already contains
  the commit under suspicion — a durability regression was once misattributed
  as a platform quirk because the control included it. Bisect to a first-bad
  commit and confirm its parent green before attributing anything.
- Restore binaries with `cp`, never `mv`: `mv` preserves the source mtime, so
  cargo sees an up-to-date artifact, skips the rebuild, and every subsequent
  run silently exercises the stale binary. Phantom failures from this cost a
  debugging round; when a result is surprising, confirm the artifact's mtime is
  newer than the sources before forming any theory.

## Native/shim-specific operating rules

- Read `crates/patina-native-shim/AGENTS.md` before changing the native shim.
- The host-alias doctrine is structural: shim internals reach real host
  primitives through private resolved aliases, never by calling public symbols
  that guest code can import.
- Under a shim the runtime's own `std::env` reads route through the *interposed*
  `getenv`, so once the environment is scrubbed every late lookup returns "not
  set" — indistinguishable from a default, and therefore silent. Resolve each
  knob once, at configuration time, from the family's control plane; a
  configuration value consulted at finalization is a bug even when the code
  reads correctly. Enforce it cheaply with a source lint that fails on the
  forbidden read shape, paired with a table gate so a newly declared variable
  cannot skip the mechanism. Found when eight documented report suppressors
  turned out to be inert across the whole native family — half from this, half
  from the supervisor forwarding only one of them into the cleared child
  environment.
- Default-deny audit/run parity is load-bearing. Do not fix a missed native
  effect by adding an allowance; add or harden the detector and then model,
  interpose, or deny-trap the effect.
- The `cargo-patina` binary embeds native C shim sources at build time. After
  changing the C layer, rebuild `cargo-patina` before trusting native validation.
- After a source-mutation detector restores an older embedded shim bundle,
  verify the linked artifact, not just the restored checkout. Distinct bundles
  share a toolchain-keyed shim target directory; Cargo can report it fresh while
  its staticlib still contains the planted mutation. If observed, clean that
  package's release artifacts using Cargo with the actual bundled manifest and
  shim target directory, then rerun the detector GREEN. Cleaning the checkout's
  target does not clean this separate artifact. This cache-invalidation class
  needs a dedicated build-layer detector; filesystem conformance caught it in
  the fs-fixup battery.
- A native build has two halves — the shim staticlib, built in the unpacked shim
  workspace, and the guest, built in the caller's working directory — and a build
  tool that resolves its compiler per directory (rustup's `rustc` proxy reads the
  rust-toolchain file above wherever it runs) can give them different toolchains.
  Two libstds in one link is a loud `duplicate symbol` failure on one platform
  and a silent success on another, so the agreement is checked at the single
  point where the shim is built rather than trusted. When a mechanism depends on
  ambient per-directory resolution, verify what the tool actually does before
  writing the diagnostic: an absolute toolchain `cargo` still invokes the `PATH`
  `rustc` proxy, so the working directory — not the cargo binary — picks the
  compiler.
- Guest binaries relink automatically when the shim or the runtime beneath it
  changes: the injected build flags carry a hash of the link inputs' bytes, so
  Cargo's own fingerprint invalidates. No source-touching or `target/` deletion
  is needed to pick up a shim change — and a guest that still shows old shim
  behavior is a real finding, not a stale build.

## Local maintainer notes

If `AGENTS.local.md` exists, read it after this file for local maintainer
recipes. It is intentionally gitignored and may contain machine-specific paths,
VM names, sandbox snapshot IDs, model choices, and VCS-tool workflows. Do not
copy those details into tracked docs unless they become portable project policy.
