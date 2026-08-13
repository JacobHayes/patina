# Arc: guest extensibility — SDK custom operations

Status: design approved 2026-08-12 (shape chosen: SDK custom-op API first;
declarative symbol models as the documented escalation; raw shim-extension ABI
explicitly not chosen). **Wave A landed** — record/replay custom operations
across all three families (ARCHITECTURE.md, "The custom-operation ABI";
IMPLEMENTATION.md item 16). **Wave B landed** — seeded custom-op faults
(`--custom-op-fail-permille`) as a first-class `FaultKnob`, the compiler-walked
knob consolidation described in `docs/arcs/unified-fault-knobs.md`. Wave C
(docs/skill) is open.

## 1. Problem

When a guest performs an effect Patina does not model, the run refuses (or,
with `--allow`, the operator waives the refusal and accepts that the effect is
un-interposed). Either way the guest author is **blocked on upstream Patina
support** for that effect. The `--allow` hatch does not unblock them — it only
converts a loud refusal into an un-modeled hole, which is the opposite of what
determinism testing wants.

The question this arc answers: can a guest author extend the set of interposed
operations *themselves* — declare a new named operation, give it a recorded or
seeded-fault behavior — without waiting for a Patina release and without
punching a hole in the fail-closed guarantee?

## 2. The decision (user, 2026-08-12)

Three shapes were considered; they differ in **which side of the determinism
boundary the extension code runs on**.

| Shape | Extension runs as | Reach | Trust surface | Verdict |
|---|---|---|---|---|
| **SDK custom-op API** | guest code (level 2+) | any effect the guest can wrap at a boundary it controls | none new — recorded like a built-in op | **chosen, first** |
| Declarative symbol models | Patina-generated interposer from a config declaration | binary-only deps, no guest changes | restricted to declarable ABI shapes; Patina authors the executing code | documented escalation |
| Raw shim-extension ABI | user-shipped interposer linked into the shim | symbols inside binary-only deps, no guest changes | maximal — user code runs *inside* the determinism boundary | **not chosen** |

Rationale for starting with the SDK custom-op API: the extension is guest code,
so determinism is by construction (record real result → replay returns recorded
bytes), the op is named and visible in traces and audits, it works across all
three families including WASI, and the failure mode is contained — if the guest
forgets to wrap an effect, the existing interposition and audit still catch the
raw effect and fail closed. Its limit is that it needs a boundary the guest
controls (source access, level 2+); it cannot reach inside a binary-only
dependency. That limit is what the declarative-models escalation exists for, if
demand appears.

Why the raw shim-extension ABI is not chosen: user code linked into the shim
becomes *silent nondeterminism* on any bug — the one failure class Patina
exists to eliminate. The host-alias doctrine
([[shim-host-alias-doctrine]]) cannot be statically enforced on external code,
so an extension calling a public interposable symbol can recurse or escape; and
the audit would have to trust the extension's own claims about what it models,
hollowing out the fail-closed guarantee. Power is real, but it trades away the
property the whole system is built to provide.

## 3. Design — SDK custom operations

A custom operation is a guest-declared, named effect that Patina records on the
record pass and reproduces on replay, exactly like a built-in `Operation`. The
guest wraps an effect it would otherwise perform directly; Patina mediates it.

### 3.1 The SDK surface (sugar over the shim ABI)

Following the SDK-is-sugar contract ([[patina-project-state]]): the SDK macro
lowers to a shim ABI verb; the shim provides the mechanism. Shape (names
illustrative, to be pinned in help.rs at build time):

```rust
// The guest wraps an effect. On record, `perform` runs and its result bytes
// are captured into the trace under `label`. On replay, `perform` is NOT run;
// the recorded bytes are returned. Determinism is by construction.
let bytes = patina_dst::custom_op("s3.get_object", &request_key, || {
    // the real effect — a network fetch, a syscall Patina doesn't model, a
    // read from a device the guest owns. Returns Vec<u8> (or a typed value
    // the SDK serializes).
    real_s3_client.get(&request_key)
})?;
```

- `label` names the op class (aggregates in traces/reports like `sometimes!`
  labels and verdict labels — one label namespace, the duplicate-label gate
  applies).
- `key` is the operation's logical input; recorded alongside the result so
  replay can assert the guest asked the *same* question (mismatch refuses —
  same contract as native `--env` reconcile).
- `perform` is the real effect, run only on record.

### 3.2 Seeded faults, like a built-in knob

The point of Patina is fault injection, not just record/replay. A custom op is
injectable on the same rate-based, domain-separated PRF path as the built-in
fault knobs: a guest can declare that `s3.get_object` may fail with a seeded
probability, and the campaign's fault vector carries it. The op declares its
failure shape (an error value the guest handles), and the reducer/campaign treat
it as one more knob — which is what makes it first-class rather than a bolt-on.

**The declaration is one bit on the ABI, and the failure value never crosses
it.** `custom_op_begin` gained a `fault_eligible` argument and a third answer
(`2` = "a fault fired"); the guest's `on_fault` closure supplies the value.
That split is the narrowest change that works, and it is not only narrow but
correct: only the guest's own types know a value its call site can return, so
Patina decides *whether* the operation fails and the guest decides *what that
means*. Carrying the failure payload over the ABI instead would have pinned the
guest's encoding into the boundary — the very coupling §6 exists to avoid.

The fired fault is recorded as the operation's `Outcome::Error`, not as bytes
that happen to spell a failure, so replay reproduces it without re-drawing and
`cargo patina trace` can tell an injected fault from an upstream one the guest
really saw. Replay never re-consults eligibility — the trace is authoritative —
but a call site that has since dropped its declaration is refused by name rather
than handed a value it cannot return.

Each label draws from its own child stream (`fault_domain::CUSTOM_OP_FAULT`
keyed by the label hash), so arming a fault on one operation class never shifts
another's decisions.

**Vacuity is stricter here than on any other plane.** Elsewhere zero
opportunities simply means there was nothing to fault: a run that did no
filesystem I/O had no filesystem. But a fault-eligible custom op exists only
because the guest declared one, so an armed knob that reached none is a coverage
claim with nothing behind it — `PATINA_CUSTOMOP_FAULT_REPORT` reports
`vacuous=1` for it, and a campaign generation files it under
`VACUOUS_CUSTOM_OP_FAULT`. That is also why the campaign band is opt-in
(`campaign --custom-op-faults`, alongside `--faults`): banding it over a guest
that declares nothing would put a provably inert knob, and its vacuity class,
into every generation — the same reasoning that makes the DNS band ride on
`--dns-entry`.

### 3.3 What it is NOT allowed to do

- It cannot make a level-1 (unmodified binary) guest extensible — it needs the
  guest to call the API. That is a stated limit, not a bug; the declarative
  escalation covers binary-only cases.
- It cannot be used to launder an un-modeled effect past the audit: the
  `perform` closure still executes real host effects **on the record pass**, so
  a custom op wrapping a raw network call is honest about performing that call
  when recording. Recording is not the determinism-guaranteed mode; replay is.
  The audit surface must name custom-op record-pass effects for what they are.
- The recorded bytes are the authority on replay; a `perform` that is itself
  nondeterministic across record runs produces different traces across seeds —
  detectable by the standard byte-identical-repeat evidence, not hidden.

## 4. Relationship to the outcome-channel arc

Both arcs shrink the "blocked on upstream" gap from the guest's side and both
lower to the same shim-ABI-first, SDK-sugar-second contract. The verdict ABI
(`docs/arcs/outcome-channel.md`) and the custom-op ABI are siblings: one lets a
guest report *what it concluded*, the other lets a guest wrap *what it did*.
They share the label namespace and the trace-event recording discipline. Build
the outcome channel first (it is the smaller, higher-leverage surface and it
also unifies the campaign/minimize oracles — see that arc's §"recognition
primitive"); the custom-op ABI reuses its trace-event and label machinery.

## 5. Waves (sketch, to be detailed on go)

- **Wave A — record/replay custom op. LANDED.** Shim ABI verbs + WASI imports;
  SDK sugar (`custom_op_bytes` untyped, `custom_op` typed behind the `custom-ops`
  feature); `Operation::CustomOp { label, key }` carrying the result as
  `Outcome::Bytes`; replay reconcile (a changed label or key refuses by name);
  audit unchanged, so a record-pass effect is named for what it is. Acceptance
  met: a guest custom op records and replays byte-identically, replay never runs
  `perform`, and a key mismatch on replay refuses. One design decision beyond the
  sketch: the ABI is three verbs (one per phase) rather than one with a phase
  argument, because the phases carry different argument shapes and directions —
  the op class stays data (the `label`), which is what the verdict doctrine
  protects. One enforcement beyond the sketch: a `perform` that performs a
  *modeled* boundary operation is refused at record time, since replay skips
  `perform` and could never reproduce those events.
- **Wave B — seeded custom-op faults. LANDED.** `--custom-op-fail-permille` as a
  `FaultKnob` variant, so the compiler walked it to every consumer: registry row,
  control-plane forwarding, trace record and replay reconcile, swarm class
  (`custom_op_fail`), campaign band (generation byte 30) and vacuity class
  (`VACUOUS_CUSTOM_OP_FAULT`), plus the `PATINA_CUSTOMOP_FAULT_REPORT` line and
  its `custom_op` facts plane. The SDK grew `custom_op_bytes_faultable` and (with
  the `custom-ops` feature) `custom_op_faultable`; `Context::custom_op_faultable`
  is the cargo-family mirror. Acceptance met: a guest whose retry policy
  mishandles its own declared failure only under a two-in-a-row fault pattern is
  found by an ordinary `campaign --faults --custom-op-faults` and classified
  through its own verdict, while the same campaign without the band is clean.
  Two design decisions beyond the sketch: the failure VALUE stays guest-side
  (§3.2), and zero eligible operations counts as vacuous, which no other plane
  does. Not in scope, and deferred deliberately: minimization of a custom-op
  fault vector — the knob is one per-mille rate, so the existing generic
  reducer already shrinks it, but that has not been demonstrated end to end.
- **Wave C — docs/skill.** The guest-patterns skill gains a custom-op section;
  ARCHITECTURE/VALIDATION/llms.txt updated; help registry rows.

## 6. Value typing (decided 2026-08-12, user go 2026-08-13)

**Typed at the SDK, raw bytes at the ABI.** The user wants typed ergonomics;
the limitation typing would impose lives entirely at the ABI layer — pinning a
serialization wire format into the shim ABI and the trace contract forever,
and coupling non-Rust/level-1-adjacent consumers to a Rust-side format. So the
split: the shim ABI verb and the trace event carry opaque bytes (narrow,
family-agnostic, forward-compatible), while the SDK's `custom_op` surface is
typed from day one — `custom_op<T: Serialize + DeserializeOwned>` with
SDK-owned encoding to those bytes. The encoding the SDK uses is part of the
guest's build (recorded traces replay against the same guest binary, which is
already the fingerprint contract), not part of the ABI. A guest that wants raw
bytes uses the `Vec<u8>` instantiation; nothing extra to build.
