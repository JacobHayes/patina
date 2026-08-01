# Testbed agent guidance

Read the root `AGENTS.md`, `docs/agent-operations.md`, and this file before
changing any testbed.

## Purpose

Testbeds are dogfooding guests, not demos tailored to current implementation
comfort. They should exercise production-shaped behavior and drive Patina to
support the surfaces that real Rust programs use.

## Rules

- Keep each testbed independently meaningful. Do not weaken a workload just
  because Patina lacks support for a surface; either model the surface, document
  the open limitation, or remove the no-op run from the testbed.
- Every classifier needs a selftest that proves the class can fire. A campaign
  that cannot classify its own planted failures is not evidence.
- Non-vacuity is part of success. Fault, schedule, coverage, and buggify tiers
  should report whether the intended plane was exercised, and clean-but-inert
  runs should be warnings or failures according to the tier's contract.
- Build/run preludes must fail loudly. Guard against stale binaries: if a build
  fails, the next leg must not run yesterday's artifact and report success.
- Canonical outcome hashes must be stable facts, not schedule artifacts. Before
  pinning a value, verify it from a clean build and across every platform the
  README claims.
- Trace hashes are platform-local unless a test explicitly proves otherwise.
  Outcome hashes should describe the final application result, not incidental
  completion order; include ordering only when ordering is the behavior under
  test.
- Campaign output directories and generated binaries are single-writer resources
  while a sweep is live. Do not delete, rebuild, or reuse them from a second
  process without explicit coordination.
- Testbed scripts should carry `--help`; scripts with classifiers should carry a
  `--selftest` or an equivalent planted-fixture proof.
