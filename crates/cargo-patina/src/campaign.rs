//! `cargo patina campaign` — a config-driven, deterministic fault-and-schedule
//! sweep that generalizes the battle-tested shell campaign machinery
//! (`testbeds/workq/fuzz-sweep.sh`, `testbeds/buggify-campaign.sh`) into a
//! first-class product surface.
//!
//! A campaign runs `generations` independent child `cargo patina run` processes
//! over one artifact. Everything is a pure function of the generation number, so a
//! re-run with the same spec reproduces the same seeds, the same per-generation
//! knobs, the same outcomes, and the same failure signatures — the determinism the
//! `--selftest` and the deterministic-re-run test prove.
//!
//! Per generation:
//!   * the run seed and every randomized knob derive from `SHA-256("patina-campaign
//!     -<seed_base>-<generation>")` (no wall clock, no `$RANDOM`), exactly the fuzz-sweep
//!     scheme;
//!   * the child streams a generalized result contract — `PATINA_RESULT <k=v…>`
//!     and `PATINA_VIOLATION <class> <detail>` (harness-agnostic generalizations of
//!     the existing per-testbed result/violation and `PATINA_SDK_REPORT`
//!     conventions), plus the runtime's own `PATINA_VIOLATION liveness` /
//!     `PATINA_SCHEDULE_POLICY` diagnostics;
//!   * the [`classify`] pure classifier assigns one of eight outcome classes with
//!     the same strictness discipline as fuzz-sweep (an explicit finding is never
//!     downgraded, a nonzero exit is never silently OK, and an unrecognized outcome
//!     lands loudly in `UNCLASSIFIED`);
//!   * a per-failure [`Signature`] (class + normalized violation-detail shape +
//!     policy/bug-depth annotation) is accumulated into a signature store in the
//!     output directory: repeats are deduped, the first occurrence of a novel
//!     signature is flagged and its trace saved with a `cargo patina replay`/re-run
//!     reproduce command.
//!
//! Output is a summary-first human report or a `patina.campaign/v2` JSON envelope
//! (the `patina.result/v1` envelope family extended for a campaign). Both are
//! progressive-disclosure: the envelope carries class counts, deduped signatures,
//! and per-run detail ONLY for novel/failing generations, with pointers to the
//! full on-disk artifacts (the signature store, saved traces, reports); the human
//! stream prints novel/failing generations plus a periodic progress heartbeat
//! rather than one line per generation.

mod classify;
mod driver;
mod generation;
mod observe;
mod parse;
mod report;
mod repro;
mod selftest;
mod spec;
mod state;

pub use classify::{
    CampaignClass, ClassifyRules, FindingFacts, GenerationFacts, RunFacts, VerdictFacts, classify,
    recognize_verdicts, signature,
};
pub(crate) use generation::{GenerationRun, run_envelope};
pub use parse::{CampaignInvocation, parse};
pub(crate) use repro::{GenerationRepro, generation_repro, run_reduced_generation};
pub(crate) use spec::DEFAULT_OUT_DIR;
pub use spec::{AllowUnmetSometimes, CampaignSpec};

use crate::CliError;
use driver::run_campaign;
use patina_dst_runtime::FaultKnob;
use selftest::selftest;
use sha2::{Digest, Sha256};

/// The `--fault-scale-permille` value that leaves every seed-drawn fault band
/// exactly as it was before the flag existed: 1000 per-mille = 1.0 = full
/// intensity. Also the upper bound — the flag DAMPENS the tuned bands, it never
/// amplifies them past ceilings that were chosen against the child `run` knobs'
/// own limits.
const FAULT_SCALE_FULL: u64 = 1000;

/// The `--starve-scale-permille` value that leaves the starvation sweep exactly
/// as it was before the flag existed: 1000 per-mille = 1.0 = full intensity.
/// Also the upper bound, for the reason [`FAULT_SCALE_FULL`] is one — the dial
/// DAMPENS a tuned band, it never amplifies it past a ceiling chosen against the
/// child `run` knobs' own limits.
///
/// The same grammar and the same identity as the fault dial, so an operator who
/// has met one has met the other, but its own name: the two govern different
/// planes, and a report that says "scale 10" has to be unambiguous about which.
const STARVE_SCALE_FULL: u64 = FAULT_SCALE_FULL;

/// Route the `campaign` verb.
pub fn execute(invocation: CampaignInvocation) -> Result<i32, CliError> {
    if invocation.selftest {
        return selftest();
    }
    run_campaign(invocation)
}

/// A per-failure signature: the outcome class plus a normalized shape of the
/// primary finding line (digits/hex collapsed so run-specific values do not
/// fragment a signature) plus any policy/bug-depth annotation. Two failures with
/// the same signature are "the same bug"; a never-before-seen signature is NOVEL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub class: CampaignClass,
    pub shape: String,
    pub policy: String,
}

impl Signature {
    /// The stable dedup key.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.class.as_str(), self.shape, self.policy)
    }
}

/// A typed value for a child `run` flag, rendered to the exact canonical syntax
/// the run parser accepts. Campaign builds every child-flag value through this so
/// it can never emit a value shape the run parser rejects — the general fix for
/// the value-syntax drift class (e.g. `--sleep-jitter-nanos 0:N` vs `0..N`). The
/// generic property test (`registry_value_grammars_match_the_parsers`) proves
/// each rendering is a run-parser-accepted form of its registry [`help::Kind`].
enum RunValue {
    /// A decimal integer (per-mille, count, or nanosecond scalar).
    Int(u64),
    /// An inclusive `lo..hi` nanosecond range (`help::Kind::NanosRange`).
    NanosRange { lo: u64, hi: u64 },
    /// A valueless switch (`help::Kind`-less, `Value::None`).
    Switch,
    /// A value with its own grammar (a crash spec, an enum member).
    Text(String),
}

impl RunValue {
    fn render(&self) -> String {
        match self {
            RunValue::Int(value) => value.to_string(),
            RunValue::NanosRange { lo, hi } => format!("{lo}..{hi}"),
            RunValue::Switch => String::new(),
            RunValue::Text(value) => value.clone(),
        }
    }
}

/// Push a child `run` flag onto `flags`, rendering the exact CLI syntax the run
/// parser accepts: the run registry decides the value form — an optional-value
/// flag inlines (`--flag=VALUE`), a required-value flag uses the space form
/// (`--flag VALUE`), a switch takes no value — and [`RunValue`] renders the value
/// in its canonical grammar. Routing every child flag through here (rather than
/// hand-formatting strings) makes it structurally impossible for a campaign to
/// emit syntax the child `run` rejects.
fn push_run_flag(flags: &mut Vec<String>, name: &str, value: RunValue) {
    match crate::help::flag_arity("run", name) {
        Some(crate::help::Value::Optional(..)) => flags.push(format!("{name}={}", value.render())),
        Some(crate::help::Value::Required(..)) => {
            flags.push(name.to_string());
            flags.push(value.render());
        }
        // A valueless switch (`--swarm`), or an unregistered name (a programming
        // error the registry drift gate catches): emit the bare flag.
        Some(crate::help::Value::None) | None => flags.push(name.to_string()),
    }
}

/// The width of a generation's band material: the 32-byte generation hash plus
/// the 32-byte extension block [`generation_bands`] appends after it.
const GEN_BAND_BYTES: usize = 64;

/// Which byte of the generation's band material each seed-derived band draws
/// from.
///
/// Every band must claim a byte here and read it through the claim, never by
/// writing a literal index. Two bands sharing a byte would silently *correlate*
/// their knobs — the campaign would never explore that pair independently, so a
/// bug reachable only at some combination of the two could be unreachable at
/// every generation — and nothing about the run would look wrong. One table makes
/// a collision a testable fact instead of a reviewer's job:
/// [`generation_byte_claims_are_disjoint`] rejects a duplicate or out-of-range
/// claim, and [`every_generation_hash_read_goes_through_a_claim`] rejects a raw
/// literal index that bypassed the table.
///
/// Every byte of the 32-byte generation hash is claimed, so the namespace GREW,
/// exactly as this comment used to prescribe: [`generation_bands`] appends a
/// second, domain-separated SHA-256 after byte 31. Bytes 0..32 are the
/// generation hash itself and are byte-for-byte what they always were — every
/// campaign recorded before the extension existed still derives the same flags —
/// and bytes 32..64 are the new draws. A band claims an index in either half and
/// reads it the same way. Indices 33..64 are unclaimed and are where the next
/// band should draw from; a band that belongs to an existing policy's
/// configuration should still be bit-sliced out of that policy's byte instead
/// (see [`gen_byte::SCHED_STARVE`]).
mod gen_byte {
    use std::ops::Range;

    /// The child run's `--seed`, little-endian. A slice, not a single byte, so it
    /// claims eight of them.
    pub(super) const SEED: Range<usize> = 0..8;

    pub(super) const BUGGIFY_ACTIVATION: usize = 8;
    pub(super) const BUGGIFY_FIRE: usize = 9;
    pub(super) const SCHED_PCT_DEPTH: usize = 11;
    pub(super) const NET_DROP: usize = 12;
    pub(super) const SLEEP_JITTER_HI: usize = 13;
    pub(super) const FS_ERROR: usize = 14;
    pub(super) const FS_SHORT: usize = 15;
    pub(super) const FS_LATENCY_HI: usize = 16;
    pub(super) const NET_LATENCY: usize = 20;
    pub(super) const DNS_FAIL: usize = 21;
    pub(super) const DNS_LATENCY_HI: usize = 22;
    pub(super) const NET_JITTER_HI: usize = 23;
    pub(super) const NET_DUPLICATE: usize = 24;
    pub(super) const NET_CONNECT_REFUSE: usize = 25;
    pub(super) const NET_RESET: usize = 26;
    pub(super) const NET_TCP_BUFFER: usize = 27;
    pub(super) const ENTROPY_FAIL: usize = 28;
    pub(super) const EPOCH_JUMP: usize = 29;
    pub(super) const CUSTOM_OP_FAIL: usize = 30;
    /// The whole starvation policy configuration — interval count, start window,
    /// and maximum interval length — bit-sliced out of ONE byte.
    ///
    /// The three sub-knobs are deliberately correlated with each other and with
    /// nothing else. They are not three independent faults; they are one policy's
    /// shape ("how many holds, how deep, how long"), and the campaign's
    /// disjointness rule exists to stop two UNRELATED knobs from sweeping a
    /// diagonal of their joint space. Slicing one byte gives 256 distinct
    /// starvation configurations — every generation of a thousand-generation
    /// sweep sees several — while leaving every other band's draw untouched.
    pub(super) const SCHED_STARVE: usize = 31;

    /// Whether this generation starves at all. The first claim in the extension
    /// block (see [`super::generation_bands`]), and it had to be: the three
    /// starvation sub-knobs consume all eight bits of [`SCHED_STARVE`], and a
    /// gate sliced out of that same byte would decide "does this generation
    /// starve" from the very bits that decide "how", so a dampened campaign
    /// would starve only at one corner of the policy space instead of rarely
    /// across all of it.
    ///
    /// Only ever consulted below full `--starve-scale-permille`: at full scale
    /// the gate is unconditionally open, which is what keeps the default sweep
    /// unchanged.
    pub(super) const STARVE_FIRE: usize = 32;

    /// The bands no fault knob owns, for the disjointness gate. The fault knobs'
    /// own claims come from [`super::campaign_band`], so this list is only the
    /// exploration bands — a `FaultKnob` cannot be missing from it, because it
    /// was never in it. The raw-index scan is the other half of the pairing:
    /// between them, a band is either claimed here or through the knob table, or
    /// it fails a gate.
    #[cfg(test)]
    pub(super) const EXPLORATION_CLAIMS: &[(&str, usize)] = &[
        ("buggify activation", BUGGIFY_ACTIVATION),
        ("buggify fire", BUGGIFY_FIRE),
        ("sched-pct depth", SCHED_PCT_DEPTH),
        ("starvation policy", SCHED_STARVE),
        ("starvation fire", STARVE_FIRE),
    ];
}

/// The generation-hash bytes a knob's campaign band draws from, or `None` for a
/// knob the campaign does not band.
///
/// The campaign owns the generation-hash layout, so this facet of the knob table
/// lives here rather than in the runtime — but it is keyed by the same
/// [`FaultKnob`], so the exhaustive match still walks a new knob to the decision.
/// A `None` is a knob that is INERT in every campaign generation: it can be set
/// by hand on a `run`, but no campaign will ever explore it. That is a real gap,
/// not an oversight, and writing it out is what makes it visible.
///
/// `generation_byte_claims_are_disjoint` reads this to prove no two bands share a
/// byte, and `every_generation_hash_read_goes_through_a_claim` proves no band
/// bypassed the table with a literal index.
fn campaign_band(knob: FaultKnob) -> Option<&'static [usize]> {
    match knob {
        // Not drawn: crash placement is native-only (WASI/Cargo refuse
        // --fs-crash-at by name), and a native crash band still needs a
        // reachable crash point, classifier awareness of the named crash
        // errors, and `minimize` on two-incarnation traces
        // (docs/DECISIONS.md row 12).
        FaultKnob::FsCrashAt | FaultKnob::FsTornGranularity => None,
        FaultKnob::FsErrorPermille => Some(&[gen_byte::FS_ERROR]),
        FaultKnob::FsShortPermille => Some(&[gen_byte::FS_SHORT]),
        FaultKnob::FsLatencyNanos => Some(&[gen_byte::FS_LATENCY_HI]),
        FaultKnob::SleepJitterNanos => Some(&[gen_byte::SLEEP_JITTER_HI]),
        FaultKnob::NetDropPermille => Some(&[gen_byte::NET_DROP]),
        FaultKnob::NetLatencyNanos => Some(&[gen_byte::NET_LATENCY]),
        FaultKnob::DnsFailPermille => Some(&[gen_byte::DNS_FAIL]),
        FaultKnob::DnsLatencyNanos => Some(&[gen_byte::DNS_LATENCY_HI]),
        FaultKnob::NetJitterNanos => Some(&[gen_byte::NET_JITTER_HI]),
        FaultKnob::NetDuplicatePermille => Some(&[gen_byte::NET_DUPLICATE]),
        FaultKnob::NetConnectRefusePermille => Some(&[gen_byte::NET_CONNECT_REFUSE]),
        FaultKnob::NetResetPermille => Some(&[gen_byte::NET_RESET]),
        FaultKnob::NetTcpBufferBytes => Some(&[gen_byte::NET_TCP_BUFFER]),
        FaultKnob::EntropyFailPermille => Some(&[gen_byte::ENTROPY_FAIL]),
        FaultKnob::EpochJumpNanos => Some(&[gen_byte::EPOCH_JUMP]),
        // Banded, but emitted only for a spec that declares `--custom-op-faults`
        // — the same shape as the DNS knobs riding on `--dns-entry`. A guest
        // whose custom operations declare no failure shape has nothing this knob
        // could fail, so banding it unconditionally would put a provably inert
        // knob, and its vacuity class, into every campaign generation.
        FaultKnob::CustomOpFailPermille => Some(&[gen_byte::CUSTOM_OP_FAIL]),
        // WAIVED (see `BAND_WAIVERS`) — a partition names virtual ADDRESSES the
        // guest actually uses, which the campaign has no generic pool for (unlike
        // `--dns-entry`, there is no `spec.net_partitions` list of candidate
        // endpoints). Synthesizing addresses the guest never dials would be a
        // band that provably never fires, which is worse than an honest gap.
        FaultKnob::NetPartition => None,
        // Not a drawn band by design: the host table is the campaign's SHAPE, not
        // a per-generation draw, and is passed through from the spec (see the
        // DNS block in `derive_flags`).
        FaultKnob::DnsEntry => None,
    }
}

/// Every [`FaultKnob`] [`campaign_band`] leaves `None` MUST have a waiver here —
/// a one-line reason the gap is a decision, not an oversight. `every_unbanded_knob_is_waived`
/// makes a new knob with neither a band nor a waiver a loud compile-adjacent
/// failure instead of a silent gap `the_campaign_bands_exactly_the_knobs_it_claims_to`
/// would only catch if someone remembered to update its list by hand.
#[cfg(test)]
const BAND_WAIVERS: &[(FaultKnob, &str)] = &[
    (
        FaultKnob::FsCrashAt,
        concat!(
            "not drawn: crash restart is native-only (WASI/Cargo refuse ",
            "--fs-crash-at by name), and a native crash band still needs a ",
            "reachable crash point, classifier awareness of the named crash ",
            "errors, and minimize on two-incarnation traces ",
            "(docs/DECISIONS.md row 12)"
        ),
    ),
    (
        FaultKnob::FsTornGranularity,
        concat!(
            "paired with --fs-crash-at: torn granularity has no effect without ",
            "the crash selector, so it stays suspended with crash generation"
        ),
    ),
    (
        FaultKnob::NetPartition,
        "topology-shaped: a partition names virtual addresses the guest actually \
         dials, and the campaign spec carries no generic pool of candidate \
         endpoints to draw from (unlike --dns-entry's spec.dns_entries)",
    ),
    (
        FaultKnob::DnsEntry,
        "table-plane: the host table is the campaign's SHAPE (passed through from \
         the spec), not a per-generation draw",
    ),
];

/// The band material a generation draws every knob from: its 32-byte generation
/// hash, followed by a domain-separated 32-byte extension block.
///
/// The namespace grew because byte 31 was the last free one and the starvation
/// fire gate still needed a draw INDEPENDENT of the policy it gates. Appending
/// rather than re-hashing is the whole point: bytes 0..32 are the generation
/// hash unchanged, so every band that existed before the extension derives
/// byte-for-byte what it always did and every recorded campaign still
/// reproduces.
///
/// Keyed on the HASH rather than on `(seed_base, generation)` so it composes
/// with `--guided`: a guided generation runs a MUTATED hash, and deriving the
/// extension from that hash keeps [`derive_flags`] a pure function of the hash
/// alone — a second keying would have handed a mutated generation the unmutated
/// generation's extension draws.
fn generation_bands(hash: &[u8; 32]) -> [u8; GEN_BAND_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"patina-campaign-bands/v1");
    hasher.update(hash);
    let extension: [u8; 32] = hasher.finalize().into();
    let mut bands = [0u8; GEN_BAND_BYTES];
    bands[..32].copy_from_slice(hash);
    bands[32..].copy_from_slice(&extension);
    bands
}

/// One band's `nth` claimed byte of the generation's band material.
///
/// Reading through the claim is what makes [`campaign_band`] the single source
/// rather than a parallel description: a band cannot draw from a byte the table
/// did not give it, and a knob the table bands `None` cannot draw at all.
fn band_byte(hash: &[u8; GEN_BAND_BYTES], knob: FaultKnob, nth: usize) -> u8 {
    let band = campaign_band(knob)
        .unwrap_or_else(|| panic!("{knob:?} draws a band the knob table does not claim"));
    hash[band[nth]]
}

/// The outcome class a knob's vacuity — its fault plane reporting that a rate
/// which should have fired repeatedly applied zero effects — is filed under, or
/// `None` for a knob whose inertness no class names.
///
/// Like [`campaign_band`], this facet belongs to the campaign rather than the
/// runtime, and like it, the exhaustive match turns a missing class into a
/// decision instead of an omission.
#[cfg(test)]
fn vacuity_class(knob: FaultKnob) -> Option<CampaignClass> {
    match knob {
        FaultKnob::FsErrorPermille | FaultKnob::FsShortPermille | FaultKnob::FsLatencyNanos => {
            Some(CampaignClass::VacuousFsFault)
        }
        FaultKnob::DnsFailPermille | FaultKnob::DnsLatencyNanos => {
            Some(CampaignClass::VacuousDnsFault)
        }
        FaultKnob::EntropyFailPermille => Some(CampaignClass::VacuousEntropyFault),
        FaultKnob::EpochJumpNanos => Some(CampaignClass::VacuousClockFault),
        FaultKnob::CustomOpFailPermille => Some(CampaignClass::VacuousCustomOpFault),
        // `NetFaultReport` carries one combined `vacuous=` bit over all seven of
        // these classes (drop/jitter/latency/duplicate/connect-refuse/reset/
        // partition all share one report line), so they share the one
        // `VacuousNetFault` class rather than each naming its own — the report
        // itself cannot tell them apart.
        FaultKnob::NetJitterNanos
        | FaultKnob::NetDropPermille
        | FaultKnob::NetLatencyNanos
        | FaultKnob::NetDuplicatePermille
        | FaultKnob::NetConnectRefusePermille
        | FaultKnob::NetResetPermille
        | FaultKnob::NetPartition => Some(CampaignClass::VacuousNetFault),
        // No rate to judge inert: a crash fires at a chosen boundary op, a
        // torn-write granularity is a model rather than a rate, a buffer size is
        // a capacity, a delayed sleep is indistinguishable from a longer one, and
        // the host table is workload. Each of these reports nothing, which
        // `vacuity_classes_match_the_classifier` pins against the knob table.
        FaultKnob::FsCrashAt
        | FaultKnob::FsTornGranularity
        | FaultKnob::SleepJitterNanos
        | FaultKnob::NetTcpBufferBytes
        | FaultKnob::DnsEntry => None,
    }
}

/// The first native-only invocation flag this spec carries, if any — the name a
/// non-native campaign's refusal quotes.
fn non_native_invocation_flag(spec: &CampaignSpec) -> Option<&'static str> {
    if spec.compute_watchdog_ms.is_some() {
        return Some("--compute-watchdog-ms");
    }
    if spec.harness {
        return Some("--harness");
    }
    if !spec.allow_symbols.is_empty() {
        return Some("--allow");
    }
    if spec.allow_unsupported_symbols.is_some() {
        return Some("--allow-unsupported-symbols");
    }
    None
}

/// The child-run flags that are pure INVOCATION SHAPE rather than a seed-derived
/// draw: `--harness` and the pre-run gate surface (`--allow`,
/// `--allow-unsupported-symbols`). Every generation gets them verbatim.
///
/// Their own function because the reproduce commands need exactly this set and
/// nothing else. Native replay restores every semantic input from the trace, but
/// these controls (including the host-time compute bound) are host/build facts a trace cannot carry (see
/// `parse_native_replay`), so a `cargo patina replay` line that dropped them would
/// hand the operator a command that fails closed on the guest the campaign just
/// swept.
///
/// Native-only: `--harness` names a native harness binary and the pre-run gate is
/// the native supervisor's. A non-native campaign carrying one is refused by name
/// upstream (`run_campaign`), so the family check here is belt and braces —
/// mirroring the DNS band.
fn invocation_flags(spec: &CampaignSpec, family: &'static str) -> Vec<String> {
    let mut flags = Vec::new();
    if family != "native" {
        return flags;
    }
    if let Some(bound) = spec.compute_watchdog_ms {
        push_run_flag(&mut flags, "--compute-watchdog-ms", RunValue::Int(bound));
    }
    if spec.harness {
        push_run_flag(&mut flags, "--harness", RunValue::Switch);
    }
    for symbol in &spec.allow_symbols {
        push_run_flag(&mut flags, "--allow", RunValue::Text(symbol.clone()));
    }
    if let Some(policy) = &spec.allow_unsupported_symbols {
        push_run_flag(
            &mut flags,
            "--allow-unsupported-symbols",
            RunValue::Text(policy.clone()),
        );
    }
    flags
}

/// Dampen one band's drawn INTENSITY by a per-mille scale.
///
/// Shared by both dials — `--fault-scale-permille` over the fault bands and
/// `--starve-scale-permille` over the starvation policy's count and hold length
/// — because they are one arithmetic with one identity ([`FAULT_SCALE_FULL`] and
/// [`STARVE_SCALE_FULL`] are the same 1000), and two copies of it would be two
/// chances to round differently.
///
/// Applied to the value the band ALREADY drew rather than to the band's ceiling,
/// which is what makes `FAULT_SCALE_FULL` the exact identity — `(v * 1000 + 500)
/// / 1000 == v` for every `v` — and therefore what keeps the default sweep byte
/// for byte the sweep it always was. Scaling the ceiling first would round
/// differently and silently rewrite every historical generation.
///
/// Rounds to NEAREST, not down. The child `run` knobs are per-mille-granular, so
/// 1 per-mille is the finest non-zero rate that exists; truncating would turn
/// every draw the scale pushes under that floor into a hard zero, disarming the
/// plane entirely and (over a busy guest) reporting it as vacuous. Rounding to
/// nearest instead spreads the same expected intensity over FEWER generations: at
/// scale 10, a band that drew 50 per-mille yields 1 per-mille and one that drew 20
/// yields 0, so roughly half the generations carry a real, rare fault rate and the
/// mean rate is a hundredfold lower — which is the regime the operator asked for.
fn scale_intensity(value: u64, scale_permille: u64) -> u64 {
    (value * scale_permille + FAULT_SCALE_FULL / 2) / FAULT_SCALE_FULL
}

/// Whether this generation runs a starvation policy at all.
///
/// The dominant lever of `--starve-scale-permille`. Dampening the policy's
/// fields alone would still hand every generation a hold: the guest's exposure
/// to the one exploration policy that
/// can WEDGE it would stay at 100% of the sweep under a flag that says the
/// opposite. Gating the whole policy is what makes a dampened campaign spend its
/// budget on runs that finish, and it is not a loss of exploration — an
/// unstarved generation still samples the guest under buggify, swarm, PCT and
/// every fault band the campaign enabled.
///
/// At `STARVE_SCALE_FULL` the comparison is `byte * 1000 < 256_000`, true for
/// all 256 byte values, so the gate is unconditionally open and the default
/// sweep is byte-for-byte the sweep it always was. Its own claimed band byte, so
/// the decision is independent of the policy's own shape rather than correlated
/// with it.
fn starve_band_fires(hash: &[u8; GEN_BAND_BYTES], scale_permille: u64) -> bool {
    u64::from(hash[gen_byte::STARVE_FIRE]) * STARVE_SCALE_FULL < scale_permille * 256
}

/// Derive the per-generation `run` flags from the generation hash. Native-only
/// exploration knobs (`--swarm`, `--sched-pct`) are skipped for a WASI module
/// (single-threaded; the WASI `run` does not accept them). Every draw indexes
/// through a [`gen_byte`] claim so no two bands can share a byte unnoticed.
fn derive_flags(spec: &CampaignSpec, hash: &[u8; 32], family: &'static str) -> Vec<String> {
    // From here down `hash` is the generation's full BAND MATERIAL: the hash
    // itself in bytes 0..32, then the extension block. Shadowing rather than a
    // new name on purpose — every band read below stays spelled `hash[...]`,
    // which is the one form `every_generation_hash_read_goes_through_a_claim`
    // scans for, so widening the namespace did not quietly narrow the gate.
    let hash = &generation_bands(hash);
    let native = family == "native";
    let mut flags = invocation_flags(spec, family);
    // One binding for the whole band section: every INTENSITY draw below passes
    // through `scale_intensity` with it, so a band that forgets to is a visible
    // omission rather than an invisible one.
    let scale = spec.fault_scale_permille;

    if spec.buggify {
        // Activation in [300, 900] permille, fire in [300, 900] permille — a wide
        // seed-varying band that both activates and fires cooperative-SUT sites
        // often enough to exercise a planted bug across a modest campaign, while
        // still leaving clean generations (neither always nor never firing).
        let activation = 300 + (u32::from(hash[gen_byte::BUGGIFY_ACTIVATION]) * 600 / 255);
        let fire = 300 + (u32::from(hash[gen_byte::BUGGIFY_FIRE]) * 600 / 255);
        push_run_flag(&mut flags, "--buggify", RunValue::Int(u64::from(fire)));
        push_run_flag(
            &mut flags,
            "--buggify-activation-permille",
            RunValue::Int(u64::from(activation)),
        );
    }
    if spec.faults {
        let fs_error = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::FsErrorPermille, 0)) * 100 / 255, // [0, 100] permille
            scale,
        );
        push_run_flag(&mut flags, "--fs-error-permille", RunValue::Int(fs_error));
        let fs_short = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::FsShortPermille, 0)) * 200 / 255, // [0, 200] permille
            scale,
        );
        push_run_flag(&mut flags, "--fs-short-permille", RunValue::Int(fs_short));
        let fs_latency_hi = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::FsLatencyNanos, 0)) * 10_000, // up to 2.55 ms
            scale,
        );
        push_run_flag(
            &mut flags,
            "--fs-latency-nanos",
            RunValue::NanosRange {
                lo: 0,
                hi: fs_latency_hi,
            },
        );
        // Crash-restart placement is not drawn (see `campaign_band`); explicit
        // native crash coverage lives in the e2e suite.
        let drop = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::NetDropPermille, 0)) * 200 / 255, // [0, 200] permille
            scale,
        );
        push_run_flag(&mut flags, "--net-drop-permille", RunValue::Int(drop));
        let net_latency = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::NetLatencyNanos, 0)) * 10_000, // up to 2.55 ms
            scale,
        );
        push_run_flag(
            &mut flags,
            "--net-latency-nanos",
            RunValue::Int(net_latency),
        );
        let net_jitter_hi = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::NetJitterNanos, 0)) * 10_000, // up to 2.55 ms
            scale,
        );
        push_run_flag(
            &mut flags,
            "--net-jitter-nanos",
            RunValue::NanosRange {
                lo: 0,
                hi: net_jitter_hi,
            },
        );
        let net_duplicate = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::NetDuplicatePermille, 0)) * 200 / 255, // [0, 200] permille
            scale,
        );
        push_run_flag(
            &mut flags,
            "--net-duplicate-permille",
            RunValue::Int(net_duplicate),
        );
        let net_connect_refuse = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::NetConnectRefusePermille, 0)) * 200 / 255, // [0, 200] permille
            scale,
        );
        push_run_flag(
            &mut flags,
            "--net-connect-refuse-permille",
            RunValue::Int(net_connect_refuse),
        );
        let net_reset = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::NetResetPermille, 0)) * 200 / 255, // [0, 200] permille
            scale,
        );
        push_run_flag(&mut flags, "--net-reset-permille", RunValue::Int(net_reset));
        // [64, 4096] bytes: small enough to make would-block/partial-send paths
        // reachable (the flag's own purpose) while staying well clear of 0, which
        // `SimNet::builder().build()` refuses outright.
        let net_tcp_buffer =
            64 + u64::from(band_byte(hash, FaultKnob::NetTcpBufferBytes, 0)) * (4096 - 64) / 255;
        push_run_flag(
            &mut flags,
            "--net-tcp-buffer-bytes",
            RunValue::Int(net_tcp_buffer),
        );
        let jitter_hi = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::SleepJitterNanos, 0)) * 10_000, // up to 2.55 ms
            scale,
        );
        push_run_flag(
            &mut flags,
            "--sleep-jitter-nanos",
            RunValue::NanosRange {
                lo: 0,
                hi: jitter_hi,
            },
        );
        // Runtime-level like the fs/net bands above, and available to every
        // family (WASI guests draw entropy too, unlike DNS resolution): no
        // host-table-shaped gate needed.
        let entropy_fail = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::EntropyFailPermille, 0)) * 200 / 255, // [0, 200] permille
            scale,
        );
        push_run_flag(
            &mut flags,
            "--entropy-fail-permille",
            RunValue::Int(entropy_fail),
        );
        // [0, 255e9] ns: up to ~4.25 minutes each direction. Deliberately
        // seconds-scale rather than the ms-scale fs/net latency bands above —
        // wall-jump bugs (cert-expiry checks, timestamp-ordering) live at the
        // seconds-to-minutes scale a real clock step or NTP correction moves,
        // not the microsecond jitter that exercises reordering against timers.
        let epoch_jump_hi = scale_intensity(
            u64::from(band_byte(hash, FaultKnob::EpochJumpNanos, 0)) * 1_000_000_000,
            scale,
        );
        push_run_flag(
            &mut flags,
            "--epoch-jump-nanos",
            RunValue::Int(epoch_jump_hi),
        );
        // Opt-in, on the same reasoning as the DNS band below: whether a custom
        // operation is fault-eligible is the GUEST's declaration, and over a
        // guest that declares none the knob provably cannot fire. Every
        // generation would then report a vacuous custom-op plane — a true
        // statement about a band that should never have been emitted. Once
        // declared it is family-agnostic: a custom op is guest code, so all
        // three families have them.
        if spec.custom_op_faults {
            let custom_op_fail = scale_intensity(
                u64::from(band_byte(hash, FaultKnob::CustomOpFailPermille, 0)) * 200 / 255, // [0, 200] permille
                scale,
            );
            push_run_flag(
                &mut flags,
                "--custom-op-fail-permille",
                RunValue::Int(custom_op_fail),
            );
        }
        // The DNS band rides on the host table, which is spec config rather than a
        // per-generation draw: with no defined name every lookup is NXDOMAIN by
        // SEMANTICS and no DNS fault is ever eligible, so banding the knobs there
        // would ship a knob that provably cannot fire. WASI never gets them —
        // wasip1 has no resolution surface (the artifact is refused outright
        // upstream of this, so this is belt and braces).
        if !spec.dns_entries.is_empty() && family != "wasi" {
            for entry in &spec.dns_entries {
                push_run_flag(&mut flags, "--dns-entry", RunValue::Text(entry.clone()));
            }
            let dns_fail = scale_intensity(
                u64::from(band_byte(hash, FaultKnob::DnsFailPermille, 0)) * 100 / 255, // [0, 100] permille
                scale,
            );
            push_run_flag(&mut flags, "--dns-fail-permille", RunValue::Int(dns_fail));
            let dns_latency_hi = scale_intensity(
                u64::from(band_byte(hash, FaultKnob::DnsLatencyNanos, 0)) * 10_000, // up to 2.55 ms
                scale,
            );
            push_run_flag(
                &mut flags,
                "--dns-latency-nanos",
                RunValue::NanosRange {
                    lo: 0,
                    hi: dns_latency_hi,
                },
            );
        }
    }
    if spec.swarm && native {
        push_run_flag(&mut flags, "--swarm", RunValue::Switch);
    }
    if spec.pct && native {
        let depth = 1 + u32::from(hash[gen_byte::SCHED_PCT_DEPTH] % 5); // [1, 5]
        push_run_flag(&mut flags, "--sched-pct", RunValue::Int(u64::from(depth)));
    }
    if spec.starve && native {
        // One byte, three fields. The low three bits pick the interval count; the
        // next three pick the START WINDOW as a power of two; the top two pick the
        // maximum interval length, also as a power of two.
        //
        // WHY POWERS OF TWO, AND WHY THIS WIDE. The window is measured in
        // SCHEDULING DECISIONS, and a real guest's schedule length spans orders of
        // magnitude — a toy two-thread probe takes a handful of decisions, an
        // instrumented database stress run takes tens of thousands. A linear sweep
        // over any single range would place every interval in the first fraction
        // of a percent of the long runs (which is exactly what the fixed
        // `--starve-window` default does) or would never reach the short ones. A
        // log sweep from 512 to 65536 puts intervals both near startup and deep
        // into a long schedule across a campaign.
        //
        // The maximum length is deliberately much smaller (16..128 decisions):
        // it is also the scheduler's AGING CAP, so it bounds how long any task can
        // be held off before liveness forces it to run. A narrow hold is what the
        // lost-wakeup / missed-notify bug shapes need; a long one just stalls.
        //
        // The whole policy is gated by `--starve-scale-permille`
        // (`starve_band_fires`): at full scale every generation starves, as it
        // always has; below it, proportionally fewer do, and a generation that
        // does not starve is still a full sample under the campaign's other
        // knobs. Two of the three fields are then dampened and the third is
        // deliberately left alone — see `CampaignSpec::starve_scale_permille`
        // for which way each axis points and why.
        let starve_scale = spec.starve_scale_permille;
        if starve_band_fires(hash, starve_scale) {
            let policy = hash[gen_byte::SCHED_STARVE];
            // Dampened around the [1, 8] band's FLOOR, not its raw value: a
            // gated generation starves, so it has at least one interval, and
            // scaling `count - 1` makes 1000 the exact arithmetic identity.
            let intervals = 1 + scale_intensity(u64::from(policy & 0b111), starve_scale); // [1, 8]
            // NOT scaled: placement, not intensity, and WHICH END IS HARSH is a
            // property of the guest rather than of the dial. Measured on
            // `turso_stress`, 512 puts every hold in the startup prefix, where
            // the policy defers nothing at all (`starve_events=0`) and the run
            // completes; 65536 puts the same-shaped holds in the concurrent
            // phase, where the run never finishes. For a SHORT guest the
            // relationship inverts — a large window places starts past the end of
            // the schedule, so nothing fires. There is no direction a uniform
            // multiply could move this that is right for both, so it keeps its
            // full log sweep at every scale.
            let window = 1u64 << (9 + u32::from((policy >> 3) & 0b111)); // 512..65536
            // Dampened, floored at one decision: `--starve-max-len` is a
            // positive integer, and a zero-length hold is not a gentler hold but
            // no hold at all — which the gate above already expresses honestly.
            let max_len =
                scale_intensity(1u64 << (4 + u32::from((policy >> 6) & 0b11)), starve_scale).max(1); // 16..128
            push_run_flag(&mut flags, "--starve", RunValue::Int(intervals));
            push_run_flag(&mut flags, "--starve-window", RunValue::Int(window));
            push_run_flag(&mut flags, "--starve-max-len", RunValue::Int(max_len));
        }
    }
    if let Some(nanos) = spec.watchdog_nanos {
        push_run_flag(&mut flags, "--liveness-watchdog", RunValue::Int(nanos));
    }
    if let Some(nanos) = spec.converge_nanos {
        push_run_flag(&mut flags, "--converge-within", RunValue::Int(nanos));
        if let Some(heal) = spec.heal_after_nanos {
            push_run_flag(&mut flags, "--heal-after", RunValue::Int(heal));
        }
    }
    flags
}

/// `SHA-256("patina-campaign-<seed_base>-<generation>")` — the deterministic per-generation
/// derivation, mirroring the fuzz-sweep scheme (no wall clock / `$RANDOM`).
fn generation_hash(seed_base: u64, generation: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("patina-campaign-{seed_base}-{generation}").as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
#[path = "campaign/tests.rs"]
mod derivation_tests;

#[cfg(test)]
mod tests {

    // The other half of the pairing: a band that writes `hash[15]` directly would
    // satisfy the disjointness test above (it never appears in the table) while
    // still colliding. Scanning the source for a literal index is what makes the
    // table load-bearing rather than advisory.
    #[test]
    fn every_generation_hash_read_goes_through_a_claim() {
        // Only the non-test half is scanned: this module's own diagnostics spell
        // the pattern out, and a gate that trips on its own error messages is
        // useless. The bound is the test MODULE header, not a bare `#[cfg(test)]`
        // — `gen_byte::EXPLORATION_CLAIMS` carries one of those too, and cutting
        // there would stop the scan above `derive_flags` and silently cover none
        // of the bands. The original files also name anchors that must fall
        // inside the scanned region, so a future edit that moves the bound fails
        // loudly instead of quietly shrinking the gate to nothing. Additional
        // campaign modules are discovered at test time and scanned up to their
        // own test-module marker, or through the whole file when it has none.
        const TEST_MARKER: &str = "#[cfg(test)]\nmod tests {";
        let needle = format!("hash{}", '[');
        for (file, source) in crate::test_source::rust_sources("src") {
            if file != "campaign.rs" && file != "guided.rs" && !file.starts_with("campaign/") {
                continue;
            }
            if file.rsplit('/').next() == Some("tests.rs") {
                continue;
            }
            let anchor = match file.as_str() {
                "campaign.rs" => Some("fn derive_flags"),
                "guided.rs" => Some("fn base_generation_hash"),
                _ => None,
            };
            let end = source.find(TEST_MARKER).unwrap_or_else(|| {
                if anchor.is_some() {
                    panic!("{file} has no `{TEST_MARKER}`; the scan bound is stale")
                }
                source.len()
            });
            let scanned = &source[..end];
            if let Some(anchor) = anchor {
                assert!(
                    scanned.contains(anchor),
                    "the scan of {file} stops before `{anchor}`, so it does not cover the derivation \
                     it is meant to gate"
                );
                assert!(
                    scanned.contains(&needle),
                    "the scan of {file} found no generation-hash reads at all, so it proves nothing"
                );
            }
            for (offset, line) in scanned.lines().enumerate() {
                let mut from = 0;
                while let Some(at) = line[from..].find(&needle) {
                    let after = from + at + needle.len();
                    if line[after..].starts_with(|c: char| c.is_ascii_digit()) {
                        panic!(
                            "{file}:{} reads the generation hash by literal index:\n  {}\nClaim a \
                             byte in `gen_byte` and index through the claim, so a collision with \
                             another band fails `generation_byte_claims_are_disjoint`.",
                            offset + 1,
                            line.trim()
                        );
                    }
                    from = after;
                }
            }
        }
    }
}
