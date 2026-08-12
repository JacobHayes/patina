# Unified Fault-Knob System — Design

Status: design approved 2026-07-30; Wave A (`domain_seed`/`fault_domain` registry, nested
`FaultConfig`, FaultNet permille migration, swarm coverage gate), Wave B (`FaultFs` errors +
short I/O), Wave C (fs latency, `--net-latency-nanos` in the shared fault group, TCP base
latency, `--budget`/`test`-buggify parity, the crash-placement campaign band) and and Wave D
(SimNet + shim wildcard-bind routing, `Operation::DnsResolve` + `Context::dns_resolve`,
the `getaddrinfo`/`freeaddrinfo` interposer, `--dns-entry`/`Kind::DnsEntry` + both fault knobs +
`DnsConfigRecord` + reconcile, the WASI family exception, the harness `dns_entry`/`dns_service`
builders, and the campaign DNS band + `VACUOUS_DNS_FAULT` class) implemented 2026-08-06; Wave E
(network faults: duplication, connect-refuse, reset, `--net-partition`, TCP buffer sizing) and the
F+ planes in scope (entropy `--entropy-fail-permille`, clock `--epoch-jump-nanos`) implemented
2026-08-07, consolidated on the `FaultKnob` enum + one metadata table so a new knob is walked by
the compiler and the band-or-waiver / vacuity / forwarding gates. **Acceptance met 2026-08-07**
(repeatable: `testbeds/workq/acceptance.sh`): a `--faults --swarm` campaign over workq shows fs and
dns generations firing non-vacuously, the planted ignored-short-write bug caught, minimized with
the violation preserved, and replayed flag-free byte-identically. Clock skew and spawn faults are
deferred to a scheduler/monotonic-API wave; allocator faults are out of scope (no interposition
exists). The §0 file:line references are as verified at design
time (post-e135c94) and have since moved.

## 0. Verified current state (what this builds on, with the gaps found)

- Config: flat `FaultConfig` (patina-runtime/src/lib.rs:426-438: `crash_at`, `torn_granularity`,
  `sleep_jitter_nanos`, `net_jitter_nanos`, `net_drop_permille`); `net_latency_nanos` is a separate
  `RuntimeConfig` field (:516). `BuggifyConfig` is a separate engine with proper PRF domain
  separation (`buggify_domain`, :2202).
- Net faults live inside `SimNet` (decide_drop :210, draw_jitter :221, TCP retransmit+jitter
  :246), driven by `fault_seed`. Fs has only the point crash: `CrashFs` + Context-side
  `crash_at`/`crash_counts`/`maybe_inject_crash` (:3374-3390). No rate-based fs errors, no short
  I/O, no fs latency.
- Both families share the same choke points: WASI host and native shim both build drivers via
  `with_default_drivers` (wasi-host:4071, native-shim:1767) and route every fs op through
  `Context::fs_*` (runtime :2948+). Family parity for anything wired there is automatic.
- Trace: `FaultConfigRecord` (patina-trace:93) round-trips knobs; replay is trace-authoritative
  with fail-closed reconciliation (`reconcile_replay_faults` :4528); the CLI native-replay parser
  additionally rejects re-supplied semantic flags outright (cargo-patina/src/lib.rs:3103).
  Fault knobs fold NO fingerprint component (only `+buggify/+pct/+starve/+swarm/+yieldpoints`
  do); that is the established pattern.
- Vacuity: `NetFaultReport::is_vacuous` (driver-api:194-213), emitted at finalization
  (runtime:3989). Fs has no counterpart.
- Swarm: `apply_swarm_mask` (:4713) is a hand-maintained per-class table
  (crash/sleep_jitter/net_jitter/net_drop/net_latency/buggify) with domain-separated per-class
  coins.
- DNS today: the native shim interposes `getaddrinfo` but hard-fails it with `EAI_FAIL`
  (patina_posix.c:2983, "IPv6 and DNS are out of scope"); `gethostbyname`/`getnameinfo` are
  classified network symbols in the audit surface (patina-target:1936). SimNet addresses are
  exact `ip:port` strings (`format_addr`, native-shim:5457) with **no wildcard-bind routing** —
  a `bind(0.0.0.0:P)` listener is keyed literally and unreachable via any other IP.

Defects found while verifying, which the unified design fixes rather than papering over:

1. **Substream aliasing.** `SeededEntropy::new(root_seed)` and `SimNet::fault_seed(root_seed)`
   (runtime :1583, :1593) both run `SplitMix64::new(root_seed)`: the guest's entropy bytes and
   the net fault decisions are the SAME u64 sequence consumed at different offsets. Sleep jitter
   uses an ad-hoc XOR constant (:1653), swarm another (:4722), buggify a real PRF. There is no
   shared derivation rule, so "adding a knob never perturbs another domain" is currently luck.
2. **TCP base latency is not applied.** `SimNet::tcp_send` explicitly skips `base_latency_nanos`
   ("deferred to wrapper-level", net-sim:556), and the wrapper that would add it (`LatencyNet`)
   is never installed by `with_default_drivers`. In managed runs `--net-latency-nanos` affects
   UDP only. This is the user-reported "non-zero TCP latency" gap. FIXED in Wave A (the segment
   path adds the base latency); Wave C closed the loop end to end from the CLI and corrected the
   "zero-latency TCP" claim in README/VALIDATION/IMPLEMENTATION.
3. **No I/O-fault errnos exist.** `ErrorCode` (patina-abi:262) has no EIO/ENOSPC/EINTR
   equivalents, so fs error injection needs new ABI vocabulary, not just a wrapper.
4. **Code-only fault surface.** `SimNet::partition()` (net-sim:69) — a first-class DST fault —
   and several CrashFs model knobs are reachable only from code, violating the
   experiments-are-externally-controlled principle (full audit in §7).

## 1. Unifying abstraction

**The shared shape is: one per-domain config struct + one seed-derivation rule + one decision-point
law + one vacuity report per domain + one swarm-class row per knob + one trace-record field per
knob.** A new knob is "cheap and consistent" when it is exactly one row in each of those six
places, and a test enforces that the rows exist.

### 1.1 Config: `FaultConfig` becomes per-domain sub-structs

```rust
pub struct FaultConfig {
    pub fs: FsFaultConfig,       // crash_at, torn_granularity, error_permille, short_permille, latency_nanos
    pub net: NetFaultConfig,     // latency_nanos (moved from RuntimeConfig), jitter_nanos, drop_permille
    pub clock: ClockFaultConfig, // sleep_jitter_nanos (future: skew, realtime jumps)
    pub dns: DnsFaultConfig,     // fail_permille, latency_nanos (§3)
}
```

Hard migration, no aliases (no-cruft doctrine): `net_latency_nanos` moves out of `RuntimeConfig`
into `faults.net.latency_nanos` and every caller is migrated in the same change. Rationale for
nesting: `apply_swarm_mask`, `fault_record`, and the vacuity emitters then iterate domains
instead of accreting a flat field list, and a new domain is a new struct rather than five more
loose fields. Every field stays inert-at-default (a knob-free run is byte-identical).

### 1.2 Seed derivation: one PRF, one registry of domain labels

```rust
/// The ONLY way any fault/decision stream derives its seed from the root seed.
pub fn domain_seed(root_seed: u64, domain: &'static str) -> u64 {
    splitmix_hash(&[root_seed, splitmix_hash_str(domain)])
}
```

(Implementation: promote the existing `splitmix_hash_str` + a multi-word finalizer, same family
as `buggify_prf` — no new dependency.) Domain labels are string constants collected in one module
(`fault_domain::{FS_ERROR, FS_SHORT, FS_LATENCY, NET_FAULT, DNS_FAULT, SLEEP_JITTER, ENTROPY, ...}`).
Because each domain's stream is keyed by its label and nothing else, adding a knob (a new label)
can never perturb another domain's stream — the property the current XOR-constant zoo does not
guarantee. Migrate the existing streams onto it: `SimNet::fault_seed(domain_seed(root, NET_FAULT))`,
sleep jitter, `SeededEntropy` (fixing defect 1), and the swarm per-class coins. This changes
same-seed outcomes for seeded runs (acceptable pre-users; no behavioral compat promised) and
makes OLD fault-knob traces fail replay loudly at the first reconcile mismatch (fail-closed, not
silent; acceptable pre-users — note it in the commit message).

### 1.3 The decision-point law

Stated once in driver-api docs and enforced per-knob by test: **a fault decision draws from its
domain stream if and only if the decision is live** (knob non-default AND the op is
fault-eligible), and decision-free configurations draw nothing. `SimNet` already obeys this
("Decision-free configs draw nothing", net-sim:244); FaultFs and every future domain must too.
This is what makes "knob off" byte-identical and keeps streams a pure function of
seed + domain + op sequence.

### 1.4 Where a knob lives: wrapper driver vs Context

Two placements, chosen by one criterion — **does the effect need virtual time/scheduling?**

- **No (alter an op's result): wrapper driver** around the driver-api trait, following the
  FaultNet/LatencyNet template, installed at the `with_default_drivers` choke point so both
  families inherit it. Fs error injection and short I/O go here.
- **Yes (delay/park/reschedule): Context**, at the `fs_*`/sleep choke points, because only the
  Context owns the clock and scheduler. Sleep jitter is already there; fs latency and DNS
  resolution latency join it.

### 1.5 Buggify and swarm

Buggify stays a fully orthogonal engine: it is cooperative (site-based, guest-labeled), not an
environmental rate knob, and already has its own PRF, record, reconcile, and fingerprint suffix.
The only shared surface is swarm: **every new knob registers a swarm class token**
(`fs_error`, `fs_short`, `fs_latency`, `dns_fail`, `dns_latency`, later `net_connect_refuse`, ...)
in `apply_swarm_mask`'s table, so `--swarm` subset-selection extends over new domains
automatically. To keep the table honest, add a unit test asserting the class list covers every
non-default-able `FaultConfig` field (a knob added without a swarm row fails the test — the
drift gate for §1's "six places").

### 1.6 Rate/unit grammar

Probabilities are **permille** (`u16`, 0..=1000); latencies are **inclusive `MIN..MAX` nanos
ranges** (a fixed latency is `N..N`). The explicit-API `FaultNet` wrapper's `drop_one_in`/
`duplicate_one_in` is off-grammar; migrate it to `drop_permille`/`duplicate_permille` on a
`domain_seed` substream in the foundation wave (its callers are in-repo only). CrashFs's `f64`
probability builder knobs migrate to permille in the wave that exposes them (§7).

## 2. First concrete domain: FaultFs

### 2.1 New ABI vocabulary

Add `ErrorCode::{Io, NoSpace, Interrupted}` (patina-abi). Mapping arms: wasi-host → `WASI_ERRNO_IO
/ NOSPC / INTR` (lib.rs:2883 match), native shim → `EIO / ENOSPC / EINTR` (lib.rs:1256 match).
Both matches are exhaustive, so the compiler forces both families — parity is compile-enforced.

### 2.2 The wrapper: `FaultFs<D: FsDriver>` in patina-wrapper-fault

The crate is already "deterministic fault injection around data-plane drivers"; FaultFs joins
FaultNet there. Installed by `with_default_drivers` as `FaultFs<CrashFs>` (runtime :1571):
**FaultFs wraps CrashFs**, i.e. injection sits ABOVE the crash journal. Rationale: an injected
error models the kernel refusing the op before it reaches storage — a failed write must not be
journaled as pending data, and a passed-through op journals and crash-tears exactly as today.
`crash()` and every other op forward, so `--fs-crash-at` composes unchanged and the wrappers
stack with no CrashFs edits.

### 2.3 Knobs and their errno sets

Three knobs, three swarm classes, three vacuity rows:

- **`--fs-error-permille N`** — per eligible op, one seeded draw decides fire/no-fire; on fire, a
  second draw picks uniformly from the op's eligible errno set:
  - `Io` (EIO): every eligible op — the universal media/transport failure, and the one errno
    every storage engine must tolerate (fsyncgate class when it lands on `sync`).
  - `NoSpace` (ENOSPC): the allocating ops — `write`, `write_at`, `set_len`, creating `open`,
    `create_directory`, `rename`, `link`, `symlink` — the second-most-common real-world fs
    failure and the classic silent-corruption trigger.
  - `Interrupted` (EINTR): the blocking-capable ops — `read`, `write`, `read_at`, `write_at`,
    `sync` — the retry-loop discipline check (std retries it; C-style and direct-syscall guests
    often don't).
  - **Eligible ops** = every `FsDriver` op except `close`, `dup`, `seek`, and `crash`. `seek`/
    `dup` are pure bookkeeping in a virtual fs (no real-world analogue worth modeling); `close`
    is excluded in v1 because an injected close error tends to find harness fd-leak bugs, not
    guest bugs — revisit with evidence.
- **`--fs-short-permille N`** — partial I/O, not an error: on fire, a cursor/positional `read`'s
  `max_len` or a `write`'s buffer is truncated to a seeded fraction, clamped to ≥1 byte so a
  looping caller always terminates. This is its own knob (not an errno) because the buggy guest
  pattern it catches — ignoring the return count — is disjoint from error handling.
- **`--fs-latency-nanos MIN..MAX`** — per eligible op, seeded extra latency applied in
  `Context::fs_*` (the §1.4 "needs time" placement) as an internal
  `sleep_until(Monotonic, now + draw)` BEFORE executing the op, mirroring `apply_sleep_jitter`.
  Latency-before-op means it composes with error injection (the op is slow, then fails) and,
  in multi-task guests, parks the caller so other tasks interleave mid-I/O — the actual
  bug-finding value (I/O completing "later than expected" reorders against timers and peers).

Deliberately NOT in v1: per-op scoping (`--fs-error-permille write:50`) — one rate over the
eligible set keeps the grammar flat, and seeds + swarm already vary exposure; add scoping only
when a real campaign shows the need. Also not in v1: a capacity model (sticky ENOSPC from a
`--fs-disk-bytes` budget) — roadmap.

### 2.4 `FsFaultReport` and per-knob vacuity

New in driver-api, mirroring `NetFaultReport` but **per-class**, because "knob set but nothing
fired" must be caught per knob (the net report's merged counters can hide one inert knob behind
another firing one — noted as a follow-up refinement for net):

```rust
pub struct FsFaultReport {
    pub eligible_ops: u64,          // fault-eligible fs ops observed
    pub error_vacuity_diagnosable: bool, pub errors_injected: u64,
    pub short_vacuity_diagnosable: bool, pub shorts_applied: u64,
    pub latency_vacuity_diagnosable: bool, pub latency_applied: u64,   // filled by Context
}
// is_vacuous(): any class that was diagnosable yet applied == 0
```

A class is `*_vacuity_diagnosable` only once its rate over the opportunities it
actually saw expected at least `VACUITY_MIN_EXPECTED_FIRES` (5) firings. A rate
knob drawing a handful of times at a low rate produces zero fires as its
ORDINARY outcome; diagnosing those runs would fire the warning — and the
campaign class built on it — on healthy runs. Since `P(zero) <= e^-expected`,
five expected firings holds a spurious verdict under 1%. Correspondingly, a
short I/O counts as `shorts_applied` only when the truncation actually BOUND the
result: truncating a read below a length the file never reached perturbs nothing
the guest can observe, and counting it would let a knob that is inert on the
exercised I/O path report itself as working.

`FsDriver::fault_report(&self) -> Option<FsFaultReport>` (default `None`, wrappers forward —
same contract as `NetDriver::fault_report`). At finalization the runtime merges the driver
report with the Context's latency counters and emits one machine-readable line,
`PATINA_FS_FAULT_REPORT eligible_ops=... errors_injected=... errors_by_op=... shorts_applied=...
shorts_by_op=... latency_applied=... vacuous=...`, plus a loud `PATINA WARNING` on vacuity —
suppressed only by a false-y `PATINA_FS_FAULT_REPORT` env, exactly like the net report (:4892).
The `*_by_op` fields name the operation kinds a class's effects landed on
(`open:1,read:2`, or `-` for none), so a non-vacuous knob that only ever fired on one corner of
the driver surface is visible as the partial coverage it is.

### 2.5 RED-provability (detection before fixes)

Each knob lands with its detector proven RED first:

1. **Efficacy (fault → guest observation)**: per knob, a test at rate 1000 asserts the GUEST sees
   it — a wasi + native testbed pair (extend the buggify-wasi testbed pattern) whose guest exits
   distinctly on: `read` returning EIO, `write` returning ENOSPC, a short read count, and a
   virtual-clock delta across an fs op ≥ MIN. Run under both families; identical outcomes.
2. **Vacuity detector RED**: a selftest class (fuzz-sweep/campaign selftest, joining
   VACUOUS_SCHEDULE at selftest 35's pattern) that constructs the vacuous condition — knob set,
   fs traffic present, zero applications (e.g. a run wired with the bare `CrashFs` and no
   `FaultFs`) — and asserts the WARNING fires. The detector must fail RED before the knob's
   plumbing is trusted.
3. **Determinism**: same seed twice → byte-identical injected-fault sequence; adjacent domains
   (entropy bytes, net decisions, schedule) byte-identical with the fs knobs on vs off
   (the §1.2/§1.3 guarantee, asserted directly).

## 3. Second concrete domain: DNS (decided in scope)

Decided defaults: `localhost`/`127.0.0.1` resolve out of the box; every other name is NXDOMAIN
unless defined via a repeatable `--dns-entry NAME=ADDR`; defined names additionally get seeded
fault knobs. DNS is a full §1 domain, not a bare static table.

### 3.1 Resolver semantics and the host table

- The table is runtime config: `BTreeMap<String, Ipv4Addr>` from repeated `--dns-entry
  NAME=ADDR` (ADDR an IPv4 literal — SimNet's address space is `ip:port` strings over u32 IPs,
  native-shim:5457; IPv6 stays out of scope with the existing fail-closed behavior).
- Built-in resolutions, table-independent and fault-exempt: numeric literals (getaddrinfo with a
  numeric node parses locally, as libc does), `localhost` → `127.0.0.1`, and a null node
  (service-only lookup) → `127.0.0.1`.
- Undefined name → NXDOMAIN (`EAI_NONAME`). That is semantics, not a fault: it fires at rate
  1.0, deterministically, knob-free. Defined names are where the fault knobs act.

### 3.2 Resolution is a recorded boundary op

`Context::dns_resolve(name) -> Result<Ipv4Addr>` becomes a new recorded operation
(`Operation::DnsResolve { name }`, string-outcome decode path like `fs_read_link`). This makes
replay authoritative for free (the recorded outcome replays op-by-op), gives the trace renderer
a visible resolution event, and gives the fault knobs their op sequence. The fault draws follow
the §1.3 law on the `DNS_FAULT` substream.

Knobs (two swarm classes, two vacuity rows in a `DnsFaultReport` emitted as
`PATINA_DNS_FAULT_REPORT`, same shape as §2.4):

- **`--dns-fail-permille N`** — on fire against a DEFINED name, a second draw picks
  NXDOMAIN (`EAI_NONAME` — models stale/deleted records) or timeout (`EAI_AGAIN` — models a
  slow/unreachable resolver; the transient-failure retry-discipline check).
- **`--dns-latency-nanos MIN..MAX`** — seeded resolution latency, applied Context-side before
  the lookup (the §1.4 "needs time" placement). Resolution latency is a classic distributed-
  systems reorderer (services racing on startup name lookups).

### 3.3 Interposer surface

Replace the `EAI_FAIL` stub (patina_posix.c:2983): `getaddrinfo` routes through a new ABI call
into `Context::dns_resolve` and returns a single A-record `addrinfo` (heap-allocated;
`freeaddrinfo` becomes a real free instead of today's no-op). `gethostbyname` and `getnameinfo`
STAY fail-closed (they remain classified/deny-trapped in patina-target:1936) — no modern Rust or
libc-backed path uses them for forward lookup, and no-cruft says don't build vocabulary nothing
consumes; the pre-run gate keeps refusals loud if a guest ever links them. The cargo/explicit
family gets `Context::dns_resolve` directly; the harness gets `HarnessBuilder::dns_entry(name,
addr)` as a config overlay. **WASI: no DNS surface exists in wasip1 (no getaddrinfo, no
sock_addr_resolve), so DNS is a documented family exception** (the first with allocator, §9) —
the WASI supervisor rejects `--dns-*` flags rather than silently accepting them.

### 3.4 Producer side: how a name reaches a listening service

The question: resolved addresses live in SimNet's virtual address space — what does the
listening service do? Answer in two parts:

1. **Wildcard-bind routing rule in SimNet (the enabler).** Today `bind`/`connect` match exact
   `ip:port` strings, so nothing but an address-literal rendezvous works. Add one routing rule:
   a listener bound to `0.0.0.0:P` receives any connect/send addressed to `*:P` that has no
   exact-match binding (exact match stays preferred). With that, **the producer does nothing
   special**: ordinary server code binds `INADDR_ANY` as it would in production, and any client
   that resolves `db.internal` → `10.0.0.5` and connects to `10.0.0.5:P` reaches it. DNS
   entries are pure client-side routing config; no service-side registration is required.
2. **Harness-registered named services (the ergonomic layer).** Yes — the harness can derive DNS
   from topology: `HarnessBuilder::dns_service(name)` allocates a deterministic virtual IP
   (`10.0.0.N` in registration order), inserts the DNS entry, and the service body just binds
   `0.0.0.0:P`. This is a deliberate, small extension of the harness v1 scope statement
   ("network topology out of scope", patina-harness docs) — it is one map entry per name, not a
   topology model. Multi-process topologies stay future work; today's guests are single-process
   with in-process service threads, which this covers fully.

## 4. CLI surface

**Grammar: `--<domain>-<effect>-<unit>`.** New rows in the shared `FAULT_FLAGS` group
(help.rs:258), plus DNS config:

| Flag | Kind | Doc (one line) |
|---|---|---|
| `--fs-error-permille N` | Permille | Fail eligible fs ops at N per-mille with a seeded errno (EIO/ENOSPC/EINTR per op). |
| `--fs-short-permille N` | Permille | Truncate fs reads/writes at N per-mille (short I/O, ≥1 byte). |
| `--fs-latency-nanos MIN..MAX` | NanosRange | Add seeded latency drawn from [MIN, MAX] to every fs op. |
| `--net-latency-nanos N` | U64 | (moved) Base per-datagram/segment delivery latency. |
| `--dns-entry NAME=ADDR` | DnsEntry (new Kind) | Define NAME to resolve to IPv4 ADDR (repeatable); undefined names are NXDOMAIN. |
| `--dns-fail-permille N` | Permille | Fail lookups of defined names at N per-mille (seeded NXDOMAIN or timeout). |
| `--dns-latency-nanos MIN..MAX` | NanosRange | Add seeded latency drawn from [MIN, MAX] to every name resolution. |

`Kind::DnsEntry` (non-empty NAME `=` IPv4 literal) is the only new Kind; the value-grammar
property test gets its valid/invalid samples. `--dns-entry` is semantic config (like `--arg`),
not a fault knob, but lives beside the `--dns-*` fault flags in a "DNS options" group.

**Resolving the `--net-latency-nanos` asymmetry: move it from the native-run-only group
(help.rs:614) into `FAULT_FLAGS`.** It is a deterministic environment knob like jitter/drop, the
runtime env plumbing (`ENV_NET_LATENCY` via `apply_fault_env`) is already family-neutral, and it
already round-trips inside `FaultConfigRecord` — only the CLI placement is wrong. Keep it a
single `U64` base (not a range): net already decomposes base+jitter as two knobs and that maps
1:1 onto SimNet; fs/dns use one range because they have no base/jitter split worth exposing.

Verbs: `FAULT_FLAGS` already flows to `run` (all three families — the cargo/wasi/native parsers
share the `apply_fault_flag` path, lib.rs:2750) and `test`; new knobs inherit that for free
(`--dns-*` on WASI: rejected with the family-exception message, §3.3). `replay` gets them added
to the reject-with-explanation list (lib.rs:3103) — the trace is authoritative, no re-supply.
`campaign --faults` extends its per-generation derivation (campaign.rs:971) with seeded bands:
fs error [0, 100]‰, fs short [0, 200]‰, fs latency [0, hash-byte × 10µs], dns fail [0, 100]‰,
net latency [0, 2.55ms] — measured-then-tuned like the existing drop/jitter bands. The registry
drift gates (`registry_covers_every_parsed_flag`, `registry_value_grammars_match_the_parsers`)
force registration and grammar agreement.

## 5. Trace / replay / fingerprint

- **`FaultConfigRecord`**: add flat optional fields `fs_error_permille`, `fs_short_permille`,
  `fs_latency_nanos`, `dns_fail_permille`, `dns_latency_nanos` with the existing
  skip-at-default serde attributes. A knob-free run's serialized record stays byte-identical, so
  all existing knob-free traces replay unchanged. `deny_unknown_fields` makes an older runtime
  reject a newer fault trace loudly — fail-closed, correct.
- **DNS table**: a new `RunMetadata` field (`dns: Option<DnsConfigRecord { entries }>`,
  skip-if-empty) records the host table so replay is flag-free and reconciled exactly like
  faults/buggify (`reconcile_replay_dns`, same shape as :4528). Resolution outcomes are ALSO
  recorded ops (§3.2), so the table record is for self-description + conflict detection, not
  correctness.
- **Replay parity with no flag re-supply**: automatic through the two existing mechanisms —
  (a) the recorded op stream is authoritative (`reconcile` compares driver outcomes op-by-op,
  and injected errors/shorts/NXDOMAINs are ordinary recorded outcomes; fs/dns-latency sleeps
  are ordinary recorded clock/scheduler ops), and (b) `fault_config_from_record` rebuilds the
  same `FaultConfig`, so replay-side drivers reconstruct identical decision streams.
  `reconcile_replay_faults` compares whole `FaultConfig` structs, so it extends with zero code.
- **Fingerprints: unchanged.** Rate fault knobs are metadata-reconciled, never fingerprint
  components — the established split (fingerprint = "can these two builds/configs possibly
  produce the same op stream"; fault knobs = "which op stream, recorded and reconciled"). New
  knobs follow it. The §1.2 substream migration changes no fingerprint either; its only compat
  effect is old fault-knob traces failing reconcile loudly (accepted, pre-users).

## 6. Coverage matrix: finders vs reproducers, per domain and family

Definitions: a **finder** is a rate-based seeded knob that explores (fires at seed-chosen
points); a **reproducer** is deterministic point placement — a point-injection knob and/or
flag-free trace replay — that pins one failure for debugging/minimization. Trace replay is a
universal reproducer for anything recorded, so the reproducer column asks: *once found, can this
fault be replayed flag-free, and is there standalone point injection?*

| Domain | Cargo (explicit/test) | WASI | Native | Notes / gaps |
|---|---|---|---|---|
| fs durability (crash, torn writes) | finder: ✓ (Wave C) · repro: ✓ `--fs-crash-at` + replay | same | same | Closed in Wave C by seed-drawn crash placement: `campaign --faults` draws the op class and a low ordinal from the generation hash (and tears at byte granularity half the time), so successive generations crash at different points in the guest's I/O sequence. No new runtime knob was needed. |
| fs I/O errors / short I/O / latency | finder: ✗ → §2 · repro: replay after §2 | same | same | Point injection (`--fs-error-at op:N`) deliberately deferred; seed+replay covers reproduction. |
| net delivery (drop/jitter/latency) | finder: ✓ · repro: replay ✓ | same | finder: ✓ full · repro: ✓ | Latency CLI family gap fixed in Wave C (`--net-latency-nanos` moved into the shared `FAULT_FLAGS`); TCP base latency (defect 2) applies on the stream path. No point injection ("drop packet N") — replay suffices. |
| net partition | finder: ✗ · repro: ✗ | ✗ | ✗ | **Code-only** (`SimNet::partition`, §7). Fix: `--net-partition A,B` (static) + seeded timed partitions with heal windows tied to the liveness converge arm (§8 #1). |
| TCP connect/reset | ✗ | ✗ | ✗ | §8 #1. |
| DNS | finder: ✓ · repro: replay ✓ | N/A (no wasip1 surface) | finder: ✓ · repro: ✓ | Closed in Wave D. The finder is `--dns-fail-permille`/`--dns-latency-nanos` over a `--dns-entry` host table, banded per generation by `campaign --faults` (which takes `--dns-entry` as campaign shape). Family exception documented. |
| clock (sleep jitter) | finder: ✓ · repro: replay ✓ | ✓ · ✓ | ✓ · ✓ | Skew/jumps: §8 #2. |
| schedule (PCT/starve/yield-points) | finder: ✗ (env-only, no CLI) · repro: replay ✓ | N/A (single-threaded) | finder: ✓ · repro: replay + minimize ✓ | Cargo-family CLI gap noted in §7. |
| entropy | finder: ✗ · repro: replay ✓ (stream recorded) | same | same | Fault knob: §8 #3. |
| buggify (cooperative) | finder: env-only, no `test` CLI flags · repro: sites recorded ✓ | finder: ✓ · repro: ✓ | ✓ · ✓ | Cargo `test` CLI gap noted in §7. |
| spawn / allocator | ✗ | ✗ / N/A | ✗ | §8 #4/#5. |

Reading the matrix: reproduction is structurally solved (trace replay + reconcile covers every
recorded domain); the systematic weakness is **finders** — fs had none at all (this design's
core), crash placement has no rate mode, and partition/connect-level net faults aren't reachable
from the CLI. That matches the user's diagnosis that point injection alone "is pretty hard to
use for actually finding bugs."

## 7. Audit: run-shaping config not externally controllable

Principle: every knob that shapes an experiment is externally controlled (CLI-flagged, recorded,
reconciled). Sweep method: `RuntimeConfig` fields + default-driver builder knobs + wrapper knobs
vs the help.rs registry. Findings, with dispositions:

| Code surface | CLI today | Disposition |
|---|---|---|
| `SimNet::partition(left, right)` (net-sim:69) | none | **Flag it** (Wave E): repeatable `--net-partition A,B`; seeded/timed partitions as the finder variant. Highest-value gap in the audit. |
| `SimNetBuilder::tcp_buffer_bytes` (net-sim:38) | none | **Flag it** (`--net-tcp-buffer-bytes N`, Usize): buffer pressure changes would-block behavior — a legitimate experiment axis. Low priority, Wave E. |
| `CrashFsBuilder::torn_write_probability` (f64, fs-crash:209) | none | **Flag + permille migration** (`--fs-torn-permille`); f64 probabilities are off-grammar (§1.6). |
| `CrashFsBuilder::torn_write_granularity(bytes)` (fs-crash:203) | only `block\|byte` enum | **Delete the arbitrary-bytes code path** unless a use appears — no-cruft says don't carry a hidden third mode the CLI can't spell. |
| `CrashFsBuilder::model_rename_atomicity` / `model_directory_durability` / `directory_loss_probability` (fs-crash:222-234) | none | **Flag them** in a later fs-durability wave (`--fs-rename-atomic`, `--fs-dir-loss-permille`); until then defaults-only — acceptable since nothing in-tree varies them, but tracked here so the gap is explicit. |
| `FaultNet::drop_one_in/duplicate_one_in`, `LatencyNet` knobs | none (explicit-API wrappers) | FaultNet migrates to permille (Wave A). Duplication becomes a managed knob (`--net-duplicate-permille`, Wave E). LatencyNet stays an explicit-API composition tool, exempt: it duplicates managed knobs rather than adding new ones. |
| `RuntimeConfig::step_budget` | `--budget` on every family (Wave C) | DONE: `--budget` is registered for the Cargo, WASI, native and native-harness families; wasi's `--fuel` remains the separate wasm-execution budget. |
| Buggify knobs on cargo `test` | `BUGGIFY_FLAGS` on `run`/`test` (Wave C) | DONE: the Cargo family parses the buggify flags and forwards them over the same `PATINA_BUGGIFY*` control plane it forwards fault knobs on, scrubbing the ambient environment first. |
| Schedule policy on cargo family | env-only (`PATINA_SCHED_*`) | Defer with a decision note: the explicit-API family owns its scheduler in code; revisit when a cargo-family exploration campaign exists. |
| `HarnessBuilder` overlay (harness crate) | by design | Exempt: the code-side twin of the CLI control plane — flows through the same `RuntimeConfig` and reconciles identically. Documented, not a violation. |

Ongoing enforcement: everything inside `FaultConfig` is covered by the §1.5 swarm-coverage
drift test (all NEW knobs must pass through it); driver-builder knobs outside `FaultConfig` are
not mechanically enumerable, so this table is the tracked list and each wave's review checks it.

## 8. Domain roadmap after fs and DNS (ordered)

1. **TCP connect/reset + partition CLI + duplication** (FaultNet:120 declines connection faults
   today). Choke point: `SimNet::tcp_connect` / established-endpoint state. Knobs:
   `--net-connect-refuse-permille` (seeded `ConnectionRefused` at connect),
   `--net-reset-permille` (seeded async reset: subsequent `tcp_send`/`tcp_recv` return
   `ConnectionReset`), `--net-partition A,B` (+ seeded timed partitions, heal windows tied to
   the liveness converge arm), `--net-duplicate-permille` for datagrams. Joins `NetFaultReport`
   as per-class rows (adopting §2.4's per-class shape for net). Pairs naturally after DNS:
   refused connects against resolved names is the realistic startup-race scenario.
2. **Clock skew / realtime jumps.** Choke point: `VirtualClock` via a `ClockDriver` wrapper +
   Context conversion (:3519). Knobs: `--clock-skew-ppm N` (steady realtime-vs-monotonic drift),
   `--clock-jump-nanos MIN..MAX` + a permille (seeded realtime step jumps at op boundaries).
   Law: monotonic stays monotonic — only Realtime skews/jumps; the runtime's timer registry is
   monotonic-keyed, so invariants hold by construction.
3. **Entropy faults.** Choke point: `EntropyDriver::fill` wrapper. Knob:
   `--entropy-fail-permille` (`Io`/`Interrupted` on getrandom-class reads). Small, cheap once
   the template exists; low standalone value (few guests handle it), so it rides mostly as a
   template-completeness proof.
4. **Spawn EAGAIN.** Choke point: `Context`/`SchedulerDriver::spawn` (both families' thread
   creation funnels there). Knob: `--spawn-fail-permille` → new `ErrorCode::Again` → EAGAIN from
   `pthread_create`/wasi-threads. Needs the buggify-style `after_setup` gate consideration:
   failing the guest's first worker spawn mostly finds startup aborts, not bugs.
5. **Allocator failure.** Native-only (malloc interpose in the shim; no WASI analogue — a
   documented family-parity exception like DNS). `--alloc-fail-permille`, gated `after_setup`
   by default; blast radius is huge and most Rust guests abort on OOM, so this is last and
   ships only with campaign evidence it classifies cleanly.

## 9. Family parity

Automatic (by construction, because both families share `with_default_drivers` + `Context`):
driver-wrapper knobs, Context-level fs/dns latency, env plumbing, trace round-trip.

Not automatic — each gets an explicit guard:

- **Errno mapping**: two per-family match arms (wasi-host:2883, native-shim:1256). Exhaustive
  matches make omission a compile error.
- **Context-bypass precedent**: sleep jitter is applied at TWO sites (Context :2944 AND "the
  native embedder jitters at its own sleep entry"). Fs and DNS latency must have exactly ONE
  site each (Context); the shim must not grow its own. Guard: the §2.5 dual-family efficacy
  test asserts identical virtual-time deltas for the same seed across families.
- **CLI parsers are per-family, hand-rolled**: covered by the shared `FAULT_FLAGS` name-list +
  `apply_fault_flag` path and the registry drift tests.
- **Documented family exceptions**: DNS (wasip1 has no resolution surface — WASI rejects
  `--dns-*` loudly) and, later, the allocator knob (native-only). Exceptions are named in help
  text and rejected, never silently ignored.

## 10. Staged implementation plan

No implementation before doc review (alignment-first flow). Waves are separable commits;
runtime-touching waves take the full battery including the 3 validation scripts, plus the mise
check ladder; Linux 8-gate at wave boundaries.

- **Wave A — foundation (runtime-touching, full battery).** `domain_seed` + `fault_domain`
  label registry; migrate net-fault/sleep-jitter/entropy/swarm streams onto it (fixes defect 1);
  restructure `FaultConfig` into per-domain sub-structs and fold `net_latency_nanos` in,
  migrating all callers; FaultNet permille migration; swarm-table coverage test (the six-places
  drift gate). No new knobs — behavior-per-seed changes, replay/fingerprint machinery untouched.
- **Wave B — FaultFs errors + shorts (runtime-touching, full battery).** RED first: efficacy
  testbeds + VACUOUS_FS_FAULT selftest class proven failing. Then: `ErrorCode` variants + both
  errno maps; `FaultFs<D>` wrapper + install as `FaultFs<CrashFs>`; `FsFaultReport` + trait
  method + finalization emission; `FaultConfigRecord` fields; CLI flags + replay reject-list +
  campaign bands + registry rows.
- **Wave C — latency unification + parity fixes (runtime-touching, full battery). DONE.**
  Context fs latency (`--fs-latency-nanos`) with its efficacy/vacuity legs; `--net-latency-nanos`
  moved into `FAULT_FLAGS` (all families); SimNet TCP base latency verified end to end from the
  CLI (defect 2, fixed in Wave A) and the stale "zero-latency TCP" docs corrected; the §7
  `--budget` and `test`-buggify family-parity fixes; the seed-drawn crash-placement campaign
  band (§6 fs-durability finder gap). Two parity bugs found while unifying the plumbing and
  fixed in the same change: the native libtest harness parsed `--fs-error-permille`/
  `--fs-short-permille` but never re-emitted them to its child `run` (silently inert), and the
  Cargo family forwarded a bare optional-value flag's value to Cargo (so `--buggify 500` meant
  "buggify at the default rate, and 500 is a test filter"). Both are now structurally prevented:
  every family's fault plumbing enumerates ONE knob table gated against the flag registry, and a
  plain token after a bare optional-value flag is a loud parse error.
- **Wave D — DNS (runtime-touching, full battery). DONE.**
  Delivered: the wildcard-bind routing rule — shared by SimNet AND the native shim, because each
  resolves addresses independently and a rule in only one of them delivers traffic that nothing
  wakes for (red-proven in both directions); `Operation::DnsResolve` + `Context::dns_resolve`
  with the host table, the built-ins, and NXDOMAIN-as-semantics; the `getaddrinfo` interposer
  returning one heap A record with a real `freeaddrinfo`; `--dns-entry` (`Kind::DnsEntry`),
  `--dns-fail-permille`, `--dns-latency-nanos`, `DnsConfigRecord` + reconcile, swarm rows, and
  the WASI family exception (declared by the owning group, so the refusal is registry-driven);
  `PATINA_DNS_FAULT_REPORT` with per-class vacuity; runtime and native end-to-end efficacy legs.
  Then completed: `HarnessBuilder::dns_entry`/`dns_service` (§3.4 part 2, allocating `10.0.0.N`
  in registration order and skipping addresses an explicit entry claims); the campaign `--faults`
  DNS band plus the `VACUOUS_DNS_FAULT` outcome class (RED-proven: four selftest fixtures failing
  before the classify rule, including per-plane attribution so a vacuous DNS run is not filed
  under the fs class); and TUTORIAL §9, every command executed.

  One addition beyond the original wave list, made because the band would otherwise have been
  inert by construction: `campaign --dns-entry NAME=ADDR`. A campaign had no way to define a host
  table — a generation with no defined names resolves everything to NXDOMAIN by SEMANTICS, so a
  banded `--dns-fail-permille` could never fire and the fault report would stay silent. The flag
  is campaign SHAPE (recorded in the out-dir spec, refused on `--extend`/`--resume` like every
  other spec flag, refused outright for a WASI artifact), and the band is emitted only when the
  table is non-empty. This is the arc's own acceptance criterion — "a campaign … shows fs/dns-fault
  generations firing" — made reachable rather than a new axis.

  One design note against §3.4: the accepted socket's local address stays the LISTENER's
  (`0.0.0.0:PORT`) rather than the address the client dialed, so `getsockname` on an accepted
  wildcard socket reports the wildcard. Reporting the dialed address would mean adding a field
  to the recorded `TcpAccepted` outcome, i.e. a trace-format decision; the stream endpoints are
  instead paired by the client's ephemeral address, which both sides already hold and which
  needs no format change.

  The future fix, should the dialed address ever be wanted (a guest asserting on `getsockname`,
  or a multi-homed model where the IP a client reached is meaningful): add a `local` field to
  `TcpAccepted` and bump the trace format with a migration — a DELIBERATE format decision taken
  on its own terms rather than folded into a domain wave. The endpoint pairing would no longer
  NEED the client's address at that point, though there is no reason to change it back.
- **Wave E — TCP connect/reset, partition CLI, duplication, tcp-buffer flag, net per-class
  vacuity (roadmap #1 + §7 rows).**
- **Waves F+ — clock, entropy, spawn, allocator (roadmap #2-#5)**, each a small commit stamped
  from the same six-places template, each shipping RED detectors first.

Acceptance for the arc: a campaign over a storage+network testbed with `--faults --swarm` shows
fs/dns-fault generations firing (non-vacuous reports), at least one planted-bug class (ignored
short write, unhandled ENOSPC, unretried DNS timeout) caught and minimized, and flag-free
replay of a failing generation.
