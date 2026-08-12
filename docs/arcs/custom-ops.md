# Arc: guest extensibility — SDK custom operations

Status: design approved 2026-08-12 (shape chosen: SDK custom-op API first;
declarative symbol models as the documented escalation; raw shim-extension ABI
explicitly not chosen). Implementation not started. Lands as
`docs/arcs/custom-ops.md`.

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
[[patina-yield-points]]/fault knobs: a guest can declare that `s3.get_object`
may fail with a seeded probability, and the campaign's fault vector can carry
it. The op declares its failure shape (an error value the guest handles), and
the reducer/campaign treat it as one more knob — which is what makes it
first-class rather than a bolt-on. The custom-op fault plane reports vacuity
like every other plane (a declared custom fault that never fired is a coverage
gap, surfaced loudly).

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

- **Wave A — record/replay custom op.** Shim ABI verb + WASI import; SDK macro;
  trace event kind carrying label/key/result; replay reconcile (key mismatch
  refuses); audit names record-pass effects. Acceptance: a guest custom op
  records and replays byte-identically, and a key mismatch on replay refuses.
- **Wave B — seeded custom-op faults.** Declared failure shape on the
  domain-separated PRF path; campaign fault-vector row; per-plane vacuity
  report; band-or-waiver gate. Acceptance: a planted custom-op fault is
  campaign-fireable, non-vacuous, and caught+minimized like a built-in knob.
- **Wave C — docs/skill.** The guest-patterns skill gains a custom-op section;
  ARCHITECTURE/VALIDATION/llms.txt updated; help registry rows.

## 6. Open question for the go decision

Whether custom-op *values* should be typed through the SDK (serde-style,
SDK-owned serialization) or stay raw `Vec<u8>` with the guest owning
encode/decode. Raw bytes are simpler and family-agnostic; typed values are
friendlier but pull a serialization contract into the ABI. Recommendation: ship
Wave A raw-bytes, add a typed sugar layer in the SDK only if usage shows the
raw form is a common footgun — keep the ABI narrow.
