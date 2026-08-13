# Arc: structured outcome channel — verdict ABI, envelope classification, guest-agnostic core

Status: design approved 2026-08-12 (all five decisions user-settled, see §2);
implementation not started. Lands as `docs/arcs/outcome-channel.md`.

## 1. Problem

Campaign outcome classification is stdout archaeology. The classifier
(`crates/cargo-patina/src/campaign.rs`, `classify(exit_code, stdout, stderr)`)
substring-matches both captured streams against hardcoded marker lists. That
design has three concrete failures:

1. **Guest-specific strings live in core patina.** `VIOLATION_MARKERS` contains
   `WORKQ_VIOLATION` and `BUG_CAUGHT` — our own testbeds' private conventions,
   baked into the product. This now violates project doctrine ("Core patina is
   guest-agnostic", AGENTS.md) and scales to zero guests beyond ours.
2. **Level-1 guests are nearly invisible.** An unmodified guest that detects its
   own corruption, prints `ERROR: checksum mismatch`, and exits 0 classifies
   `OK`. One that exits 1 for corruption and 1 for a bad flag is one
   undifferentiated `UNCLASSIFIED`.
3. **SIGABRT is misattributed.** Any exit 134 with no violation marker is
   assumed to be a *patina* fail-closed refusal — a guest that deliberately
   `abort()`s on its own invariant failure (Rust `panic = "abort"`, `assert!`)
   is filed as patina's fault, and the finding is hidden inside an
   infra-looking bucket.

Magic strings are also fragile (a guest that happens to echo a marker forges a
classification), undiscoverable (nothing in `--help` or the registry names
them), and unversioned.

## 2. Settled decisions (user, 2026-08-12)

| # | Decision | Choice |
|---|---|---|
| 1 | Verdict ABI shape | **Single verb** — one shim symbol; kinds are data, not symbols (Antithesis-validated, §3) |
| 2 | Classifier input | **Envelope is the only input** — full migration, marker lists deleted, workq/pubsub migrated in the same arc (no dual path) |
| 3 | Level-1 fallback | **Spec-declared per-guest patterns** + exit-code mapping; grep survives only as explicit per-guest config, never baked in |
| 4 | Pre-main sequencing | Out of scope here — the init-prologue probe is a separate green-lit track |
| 5 | Guest deliberate abort | **Own campaign class `GUEST_ABORT`** — patina refusals become envelope-attributed, so an unattributed SIGABRT is the guest's own doing |

Doctrine adopted alongside: **core patina is guest-agnostic** (AGENTS.md,
Project doctrine). This arc removes the existing debt.

## 3. Prior art: Antithesis

Verified against their docs (2026-08-12): the entire Antithesis SDK — every
assertion type (`always`, `sometimes`, `reachable`, `unreachable`,
comparison/composition variants) *and* lifecycle events (`setup_complete`) —
funnels through **one** shared-library symbol, `fuzz_json_data(ptr, len)`,
carrying structured JSON payloads. When the native lib is absent, the same
JSON goes to a JSONL file (`$ANTITHESIS_OUTPUT_DIR/sdk.jsonl`) and is ingested
identically. Assertion identity aggregates by `message` (label); `details` is
an optional key-value payload for triage. Their SDKs are sugar over that one
entry point — exactly the shim-ABI-first, SDK-sugar-second shape patina
already uses for `patina_buggify`.

## 4. Design

### 4.1 The verdict ABI (one verb)

The shim exports one C symbol; the WASI host adds the matching import to the
`patina_sdk` module:

```c
void patina_verdict(uint32_t kind,
                    const uint8_t *label, size_t label_len,
                    const uint8_t *detail, size_t detail_len);
```

- `kind` is a small closed enum owned by the runtime (initial set:
  `VIOLATION`, `PASS`, `ABORT_INTENT`); new kinds are new enum values walked by
  the compiler to every consumer (the `FaultKnob` pattern), never new symbols.
- `label` aggregates verdicts the way Antithesis aggregates by `message` and
  the way `sometimes!` labels already key `sites.json`.
- `detail` is optional UTF-8 (JSON by convention), recorded verbatim.

Each call is recorded as a **trace event** (deterministic; replay reproduces it
byte-identically — the standard evidence shape applies) and surfaced in the
result envelope. The SDK's existing surfaces lower to it: `always!` failure
stops printing `PATINA_ALWAYS_VIOLATION` to stderr and calls
`patina_verdict(VIOLATION, label, detail)` instead. A guest that intends to
abort calls `patina_verdict(ABORT_INTENT, …)` first, so its SIGABRT is
attributed (§4.4).

What this deliberately does not do: conjure calls from a level-1 guest. An
unmodified binary never reaches this ABI — that is what §4.3 is for.

### 4.2 The envelope is the classifier's only input

`patina.result/v1` gains structured outcome fields, populated by the runtime
with **zero guest changes** for everything patina itself already knows:

- `verdicts[]` — every `patina_verdict` call: kind, label, detail, sequence.
- `runtime_findings[]` — runtime-detected violations with a `source`
  attribution: liveness/converge watchdog, schedule diagnostics.
- `fault_reports{}` — the per-plane accounting (fs/dns/net/entropy/clock/swarm)
  as structured objects including the `vacuous` bit, replacing consumers'
  parsing of `PATINA_*_FAULT_REPORT` lines. The printed lines may remain as
  human diagnostics, but nothing in patina classifies from them.
- `refusal` — when patina itself fails closed: the refusal class and message.
  This is what makes an *unattributed* SIGABRT meaningful (§4.4).
- `guest_exit` — exit code / terminating signal.

`classify` becomes a pure function of the envelope (plus the spec's declared
patterns, §4.3). The marker lists (`VIOLATION_MARKERS`, `FAIL_CLOSED_MARKERS`,
`INFRA_MARKERS`, the per-plane `vacuous=1` line scans) are **deleted**, not
deprecated — no dual path. Every campaign class must be re-proven fireable
through the envelope by the selftest in the same change (a check that cannot
fail is a bug).

### 4.3 Level-1 fallback: spec-declared patterns + exit codes

For guests that never call the ABI, the campaign spec (`.patina/config.toml` /
campaign configuration) may declare per-guest classification rules:

```toml
[classify.patterns]
violation = ["CORRUPTION", "checksum mismatch"]   # output line substrings
[classify.exit_codes]
violation = [3]
```

- Declared patterns are matched against the captured streams by the classifier
  — the grep mechanism survives, but as **explicit per-guest configuration**,
  discoverable and versioned with the guest, never a string in patina source.
- Defaults without declarations: exit 0 → `OK`, unattributed SIGABRT →
  `GUEST_ABORT` (§4.4), any other nonzero → `UNCLASSIFIED` (loud, as today).
- Envelope facts always take precedence over declared patterns; patterns can
  only *add* findings, never downgrade one.

### 4.4 `GUEST_ABORT` is its own class

With patina's own refusals envelope-attributed (`refusal` field), the SIGABRT
inference inverts: exit 134 **with** a refusal record is `FAIL_CLOSED_ABORT`;
exit 134 **without** one is the guest's own doing and classifies
`GUEST_ABORT` — a finding bucket, not infra noise. A preceding
`ABORT_INTENT`/`VIOLATION` verdict enriches it (label/detail in the report),
but is not required for the class to fire.

### 4.5 The recognition primitive — one mechanism, two consumers

Campaign classification and `minimize` both need to recognize a failure from a
run's output, and today they do it with two unrelated oracles: the campaign
greps hardcoded markers in `classify()`, while `minimize` makes the operator
hand-write a shell oracle that re-greps the same thing (the campaign already
knew the generation was a violation, then discards that and asks the user to
re-encode it). The envelope closes this incoherence without conflating the two
questions, which are genuinely different:

- **Campaign** asks a multi-way, open question — *which class did this
  generation land in?* (discovery; the whole `classify()` taxonomy).
- **Minimize** asks a binary, targeted question — *does this candidate still
  exhibit the same failure the seed generation had?* (a fixed target).

Extract one primitive, `recognize_verdicts(envelope) -> Set<Verdict>`. Campaign
classifies *from* it; `minimize` captures the seed generation's verdict set as
its **target** and its oracle becomes "does this candidate's replay envelope
still contain that verdict (kind + label)?" — auto-derived, so
`minimize --generation N` needs no hand-written `--marker`. It reuses only the
recognition primitive, never the whole classifier (the vacuity/infra classes
are meaningless for a fixed target), and the external-command/`--marker` oracle
stays as the level-1 escape hatch, structurally identical to §4.3's
spec-declared patterns. The built-in replay oracle already shipped for
`minimize` (marker present AND clean replay) is the stepping-stone; this makes
the target auto-derived once verdicts are structured. Feeds the
`custom-ops` arc's boundary discussion (`docs/arcs/custom-ops.md`).

## 5. Waves

- **Wave A — ABI + envelope.** `patina_verdict` in the shim (host-alias
  doctrine applies) and the WASI `patina_sdk` import; trace event kind;
  `patina.result/v1` outcome fields; SDK macros lower to the ABI. Runtime
  emits `fault_reports{}`/`refusal`/`runtime_findings[]` structurally.
- **Wave B — classifier migration.** `classify(envelope, spec_rules)`;
  `GUEST_ABORT` class; spec-declared patterns; delete every marker list and
  the testbed strings from core; campaign selftest re-proves all classes
  (including the new one) fireable through the new channel, red-before/
  green-after. **Landed.** Campaign generations run with `--format json`;
  `built_in_class` takes a text-free `RunFacts`, so guest output structurally
  cannot decide a built-in class. Two Wave A corrections fell out of it: an
  incomplete recorded trace is a *consequence* of a guest dying mid-record, not
  a `refusal` (attributing it made `GUEST_ABORT` unreachable), and the
  embedders' legacy `PATINA_ALWAYS_VIOLATION` print is gone — the verdict line
  is the only announcement. Known residue for Wave C: a WASI guest's trap (an
  `always!` violation among them) surfaces as a CLI error rather than a run
  envelope, so such a generation classifies `INFRA`; giving `execute_wasi_run`
  an envelope for a guest-side trap closes it.
- **Wave C — testbed + docs migration.** workq/pubsub emit verdicts via the
  SDK instead of `WORKQ_VIOLATION`/`BUG_CAUGHT` prints; their run-patina/
  acceptance/fuzz-sweep scripts read the JSON envelope instead of grepping;
  ARCHITECTURE/VALIDATION/TUTORIAL/llms.txt/skill updated; help registry rows
  for any new flags; flag-drift gate stays green.

Wave ordering is strict (B needs A's envelope; C needs B's classifier), but
each wave lands green on the full check ladder independently.

## 6. Acceptance

The arc is done when, demonstrated by a repeatable script:

1. `campaign --selftest` proves every class — including `GUEST_ABORT` —
   fireable with the envelope as the only classifier input.
2. `rg -n 'WORKQ_VIOLATION|BUG_CAUGHT' crates/` is empty, and no core source
   contains guest-specific classification strings (doctrine gate).
3. The workq acceptance battery (`testbeds/workq/acceptance.sh`) passes
   end-to-end with verdict-ABI reporting: planted bug caught, minimized,
   replayed flag-free byte-identically — verdict events included in the
   replay-identity check.
4. A deliberately aborting guest classifies `GUEST_ABORT` (not
   `FAIL_CLOSED_ABORT`); a patina refusal still classifies `FAIL_CLOSED_ABORT`
   via envelope attribution (red-before/green-after for the split).
5. A level-1 guest with a spec-declared pattern classifies `VIOLATION` from
   output it already prints, with zero guest modification.

## 7. Cross-references

- **sometimes-gate / invariant-visibility**: verdict labels share the label
  namespace and aggregation semantics of `sites.json`; the duplicate-label
  gate applies.
- **unified-fault-knobs**: `fault_reports{}` in the envelope structurally
  carries what the `PATINA_*_FAULT_REPORT` lines carry today; the vacuity
  classes keep their per-plane separation.
- **init-prologue track** (separate, probe green-lit 2026-08-12): unrelated
  mechanically, but both arcs shrink the "unmodified guest" gap from opposite
  ends (observability here, pre-main determinism there).
